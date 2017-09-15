(ns hbase-packet-inspector.core
  (:require [cemerick.url :refer [query->map]]
            [clojure.core.async :as async]
            [clojure.core.match :refer [match]]
            [clojure.string :as str]
            [clojure.tools.cli :as cli]
            [clojure.tools.logging :as log]
            [hbase-packet-inspector.hbase :as hbase]
            [hbase-packet-inspector.pool :as pool]
            [hbase-packet-inspector.pcap :as pcap]
            [hbase-packet-inspector.sink.db :as db]
            [hbase-packet-inspector.sink.kafka :as kafka])
  (:import (com.google.common.io ByteStreams)
           (com.google.protobuf InvalidProtocolBufferException)
           (java.io ByteArrayInputStream ByteArrayOutputStream DataInputStream
                    EOFException SequenceInputStream)
           (java.sql Timestamp)
           (java.util.concurrent CancellationException)
           (org.pcap4j.core PcapHandle))
  (:gen-class))

(def tty?
  "True if stdin is a tty device"
  (some? (System/console)))

(def usage
  "hbase-packet-inspector

Usage:
  hbase-packet-inspector [OPTIONS] [-i INTERFACE]
  hbase-packet-inspector [OPTIONS] FILES...

Options:
  -h --help                 Show this message
  -i --interface=INTERFACE  Network interface to monitor
  -p --port=PORT            Port to monitor (default: 16020 and 60020)
  -c --count=COUNT          Maximum number of packets to process
  -d --duration=DURATION    Number of seconds to capture packets
  -k --kafka=SERVERS/TOPIC  Kafka bootstrap servers and the name of the topic
                              TOPIC:
                                T      Both requests and responses to T
                                T1/T2  Requests to T1, responses to T2
                                T/     Requests to T, responses are ignored
                                /T     Requests are ignored, responses to T
  -v --verbose              Verbose output")

(def cli-options
  [["-p" "--port=PORT"
    :parse-fn #(Integer/parseInt %)
    :validate [#(< 0 % 0x10000) "Must be a number between 0 and 65536"]]
   ["-c" "--count=COUNT"
    :parse-fn #(Integer/parseInt %)
    :validate [pos? "Must be a positive integer"]]
   ["-d" "--duration=DURATION"
    :parse-fn #(Integer/parseInt %)
    :validate [pos? "Must be a positive integer"]]
   ["-i" "--interface=INTERFACE"
    :validate [seq "Must be a non-empty string"]]
   ["-k" "--kafka=SERVERS/TOPIC"
    :validate [seq "Must be a non-empty string"]]
   ["-h" "--help"]
   ["-v" "--verbose"
    :default false]])

(def hbase-ports
  "Default set of ports relevant to HBase region server"
  #{16020 60020})

(def state-expiration-ms
  "Any state object that stayed over this period will be expired. The default
  is 2 minutes."
  120000)

(def report-interval
  "Progress report interval"
  {:count 10000
   :ms    2000})

(defn parse-stream
  "Processes the byte stream and returns the map representation of request or
  response"
  [inbound? ^ByteArrayInputStream bais total-size request-finder]
  (assoc (hbase/parse-stream inbound? bais request-finder)
         :size total-size))

(defn valid-length?
  "Checks if the length of the request is valid.

  A request to region server should be prefixed by a 4-byte integer denoting
  the total length of the request. Since MTU of Ethernet is limited to 1500
  bytes, a single request can be split into multiple packets and it is possible
  that we encounter an intermediate packet that does not start with a valid
  integer without seeing the first slice of the request. And in that case, it
  is very likely that the integer representation of the first 4 bytes of the
  packet is an absurd value. This function is a simple heuristic to filter out
  such intermediate packets we can't process. Of course the approach is not
  fail-safe and we may run into an exception later when we try to parse the
  packet."
  [len]
  (and (pos? len) (< len (* 256 1024 1024))))

(defn process-scan-state
  "Manages state transition during Scan lifecycle. Returns the pair of new
  state map and the augmented parsed info."
  [state client-key parsed]
  (let [{:keys [method inbound? call-id scanner ts]} parsed
        prefix (conj client-key call-id)
        scanner-state (state scanner)
        region-info (select-keys scanner-state [:table :region])]
    (match [method inbound?]

      ;; 1. Remember Scan request for call-id
      [(:or :open-scanner :small-scan) true]
      [(assoc! state (conj prefix :scanner) parsed) parsed]

      ;; 2. Find Scan request for call-id and map it to the scanner-id
      [:open-scanner false]
      (let [key     (conj prefix :scanner)
            request (get state key)
            state   (dissoc! state key)
            state   (assoc! state scanner request)]
        [state parsed])

      ;; 3. Attach region info from the Scan request for the scanner-id
      ;;    and update timestamp of the scanner state
      [:next-rows _]
      [(assoc! state scanner (assoc scanner-state :ts ts))
       (merge parsed region-info)]

      ;; 4. Discard Scan request from the state
      [:close-scanner true]
      [(dissoc! state scanner) (merge parsed region-info)]

      ;; State transition is simpler for small scans
      [:small-scan false]
      (let [key (conj prefix :scanner)]
        [(dissoc! state key) parsed])

      [_ _] [state parsed])))

(defn sub-ts
  "Returns the difference of two Timestamps in milliseconds"
  [^Timestamp ts2 ^Timestamp ts1]
  (- (.getTime ts2) (.getTime ts1)))

(defn read-int4
  "Reads 4-byte integer from the input stream"
  [^ByteArrayInputStream bais]
  (try (.. (DataInputStream. bais) readInt)
       (catch EOFException _ 0)))

(defn process-hbase-packet
  "Executes proc-fn with with the map parsed from a packet. Returns the new
  state for the next iteration. state map can have the following types of
  states.

  [addr port]                  => ByteArrayOutputStream
  [addr port call-id]          => Request
  [addr port call-id :scanner] => ScanRequest
  scanner-id                   => ScanRequest

  (call-id is not globally unique)

  The protocol is inherently stateful, and the packets from and to a client
  should be processed in the exact order. However, since we are not
  a participant of the communication, some events are not visible to us. For
  example, if a client sends a connection preamble with an invalid version
  number, the server will simply close the connection, the client will know,
  but we won't. A client can go missing before sending the full request, or it
  can disappear without properly closing the open scanner. And we'll inevitably
  end up with dangling state objects which will be periodically cleaned up by
  trim-state.

  In short, it's not possible to reproduce the exact state between the server
  and the clients and that's not our goal here. We will not try to keep track
  of the states that are not essential to the workload, such as initial
  connetion handshake."

  [packet-map ports timestamp state proc-fn]
  {:pre [(set? ports)]}
  (let [{:keys [data length]} packet-map
        inbound?      (some? (ports (-> packet-map :dst :port)))
        server        (packet-map (if inbound? :dst :src))
        client        (packet-map (if inbound? :src :dst))
        client-key    ((juxt :addr :port) client)
        client-state  (state client-key)
        base-map      {:ts       timestamp
                       :inbound? inbound?
                       :server   (:addr server)
                       :client   (:addr client)
                       :port     (:port client)}
        expects-more  (fn [state ^ByteArrayInputStream bais size expects]
                        (assoc! state client-key
                                {:ts timestamp :ins [bais] :size size :expects expects}))
        next-state    (fn [state parsed]
                        ;; Only responses for known requests have previous :ts
                        (let [prev-ts (:ts parsed)
                              parsed (if prev-ts
                                       (assoc parsed :elapsed (sub-ts timestamp prev-ts))
                                       parsed)
                              [state info] (process-scan-state state client-key (merge parsed base-map))
                              state-key (conj client-key (:call-id parsed))]
                          (proc-fn info)
                          (dissoc! (if inbound?
                                     (assoc! state state-key info)
                                     (dissoc! state state-key))
                                   client-key)))
        advance-state (fn [state bais size remains]
                        ;; A single packet may have multiple messages
                        ;;   e.g. Nagle's algorithm, Asynchbase
                        (let [request-finder (when-not inbound? #(state (conj client-key %)))
                              parsed         (parse-stream inbound? bais size request-finder)
                              state          (next-state state parsed)
                              size           (if (pos? remains) (read-int4 bais) 0)
                              remains        (- remains size 4)]
                          (if (valid-length? size)
                            (if (neg? remains)
                              (expects-more state bais size (- remains))
                              (recur state bais size remains))
                            state)))]
    (if-not (and data (some ports [(-> packet-map :src :port)
                                   (-> packet-map :dst :port)]))
      state
      (try
        (if-not client-state
          ;; Initial encounter
          (let [bais    (ByteArrayInputStream. data)
                size    (read-int4 bais)
                remains (- length size 4)]

            (if-not (valid-length? size)
              ;; Uncovered packets (e.g. Preamble ("HBas" = 1212309875),
              ;; SASL handshake, ConnectionHeader) or fragmented payload whose
              ;; header we missed
              state
              (if (neg? remains)
                ;; Not ready. We need more data.
                (expects-more state bais size (- size (- (count data) 4)))
                ;; Data is now ready. We may have more data after the first
                ;; message (remains > 0).
                (advance-state state bais size remains))))

          ;; Continued fragment -> append new bytes to ByteArrayOutputStream
          (let [{:keys  [ins size expects]} client-state
                bais    (ByteArrayInputStream. data)
                ins     (conj ins bais)
                expects (- expects (count data))]
            (if (pos? expects)
              ;; Still needs more
              (assoc! state client-key
                      (assoc client-state
                             :ins ins :ts timestamp :expects expects))
              ;; Finally ready to advance state
              (advance-state state (SequenceInputStream. (java.util.Collections/enumeration ins)) size (- expects)))))
        (catch Exception e
          (when-not (instance? InvalidProtocolBufferException e)
            (log/warn e))
          ;; Discard byte stream for the client
          (dissoc! state client-key))))))

(defn send!
  "Sends request/response information into sink (H2 database or Kafka)"
  [sink verbose info]
  (let [{:keys [inbound? actions results client port call-id cells]} info
        batch  (count actions)
        multi? (> batch 1)
        info   (merge info (when (= batch 1) (first actions)))
        info   (assoc (dissoc info :actions :results)
                      :batch batch
                      :cells (or cells
                                 (reduce + (remove nil? (map :cells actions)))))
        info  (if multi?
                (assoc info
                       (if inbound? :actions :results)
                       (for [elem (if inbound? actions results)]
                         (assoc elem
                                :client  client
                                :port    port
                                :call-id call-id)))
                info)]
    (when verbose
      (log/info info))
    (sink info)))

(defn trim-state-expired
  "Removes state objects that are not handled correctly within the period"
  [state latest-ts]
  (let [new-state (reduce-kv (fn [s k v]
                               (if (<= (sub-ts latest-ts (:ts v))
                                       state-expiration-ms)
                                 (assoc s k v) s))
                             {} state)
        xcount    (- (count state) (count new-state))]
    (when (pos? xcount)
      (log/infof "Expired %d state object(s)" xcount))
    new-state))

(defn expected-memory-usage
  "Memory needed to parse the object"
  ^long [[_ state-props]]
  (let [{:keys [out remains] :or {remains 0}} state-props]
    (+ remains (if out
                 (.size ^ByteArrayOutputStream out)
                 0))))

(defn fmt-bytes
  [bytes]
  (cond
    (< bytes (Math/pow 1024 1)) (str bytes " B")
    (< bytes (Math/pow 1024 2)) (format "%.02f KiB" (/ bytes (Math/pow 1024 1)))
    (< bytes (Math/pow 1024 3)) (format "%.02f MiB" (/ bytes (Math/pow 1024 2)))
    :else                       (format "%.02f GiB" (/ bytes (Math/pow 1024 3)))))

(defn max-memory
  "Returns the maximum amount of memory that can be used by this process"
  []
  (.. Runtime getRuntime maxMemory))

(defn trim-state-by-memory
  "Makes sure that the state objects do not occupy more than 50% of the total
  available memory."
  [state]
  (let [memory-max   (max-memory)
        memory-used  (reduce + (map expected-memory-usage state))
        memory-limit (quot memory-max 2)]
    (if (< memory-used memory-limit)
      state
      (loop [entries   []
             remaining (sort-by expected-memory-usage state)
             num-bytes 0]
        (let [[entry & remaining] remaining
              num-bytes+ (+ num-bytes (expected-memory-usage entry))]
          (if (and (seq remaining) (< num-bytes+ memory-limit))
            (recur (conj entries entry) remaining num-bytes+)
            (let [dropped (- (count state) (count entries))]
              (when (pos? dropped)
                (log/infof "%d object(s) dropped due to memory limit: %s -> %s"
                           dropped
                           (fmt-bytes memory-used)
                           (fmt-bytes num-bytes)))
              (into {} entries))))))))

(def trim-state (comp trim-state-by-memory trim-state-expired))

(defn logger
  [count stats]
  (let [stats-str
        (when (seq stats)
          (str " (" (str/join ", " (for [[k v] stats]
                                     (str (name k) ": " v))) ")"))]
    (log/infof (str "Processed %d packets" stats-str) count)))

(defn start-handler
  "Starts a background thread for parsing and interpreting HBase requests and
  responses"
  [chan close-chan sink stats-fn {:keys [port verbose count duration]}]
  {:pre [(or (nil? count) (pos? count))]}
  (let [pool (pool/create-batch-pool (partial send! sink verbose))]
    (async/thread
      (let [submit   (fn [info] (.submit pool info))
            duration (some-> duration (* 1000))
            ports    (if port (hash-set port) hbase-ports)]
        (loop [state    (transient {})
               first-ts nil
               seen     0
               prev     {:seen 0 :ts (System/currentTimeMillis)}]
          (let [[latest-ts packet-map] (async/<!! chan)]
            (if (nil? latest-ts)
              (async/>!! close-chan seen)
              (let [first-ts  (or first-ts latest-ts)
                    new-state (process-hbase-packet
                               packet-map ports latest-ts state submit)
                    now       (System/currentTimeMillis)
                    seen      (inc seen)
                    tdiff     (- now  (:ts   prev))
                    diff      (- seen (:seen prev))
                    print?    (or (>= tdiff (:ms report-interval))
                                  (>= diff  (:count report-interval)))]
                (when print?
                  (logger seen (stats-fn)))
                (if (and (or (nil? count) (< seen count))
                         (or (nil? duration) (< (sub-ts latest-ts first-ts) duration)))
                  (if print?
                    (recur (transient (trim-state (persistent! new-state) latest-ts))
                           first-ts seen {:seen seen :ts now})
                    (recur new-state first-ts seen prev))
                  (do (async/close! chan) ;; No more puts
                      (async/alts!! [chan (async/timeout 100)])
                      (async/>!! close-chan seen)))))))))
    (fn [] (.close pool))))

(defn read-handle
  "Reads packets from the handle and passes each packet to handler thread"
  [^PcapHandle handle sink stats-fn & [options]]
  (let [chan (async/chan 10000)
        close-chan (async/chan)
        closer (start-handler chan close-chan sink stats-fn options)]
    (loop []
      (let [packet-map (pcap/parse-next-packet handle)]
        (case packet-map
          ::pcap/interrupt
          (do (async/>!! chan [])
              (log/infof "Finished processing %d packets"
                         (async/<!! close-chan)))

          ::pcap/ignore
          (recur)

          (when (async/>!! chan [(.getTimestamp handle) packet-map])
            (recur)))))
    (closer)))

(defn read-pcap-file
  "Loads pcap file into in-memory h2 database"
  [file-name sink options]
  (with-open [handle (pcap/file-handle file-name)]
    (read-handle handle sink (constantly {}) options)))

(defn read-net-interface
  "Captures packets from the interface and loads into the database"
  [interface sink options]
  (with-open [handle (pcap/live-handle interface hbase-ports)]
    (let [stats-fn #(let [stats (.getStats handle)]
                      {:received (.getNumPacketsReceived stats)
                       :dropped  (.getNumPacketsDropped stats)})
          f (future (read-handle handle sink stats-fn options))]
      (if-let [duration (:duration options)]
        (Thread/sleep (* 1000 duration))
        (if tty?
          (do
            (log/info "Press enter key to stop capturing")
            (read-line))
          (deref f)))
      (log/info "Closing the handle")
      (future-cancel f)
      (try @f (catch CancellationException _)))

    (let [stats (.getStats handle)]
      (log/infof "%d packets received, %d dropped"
                 (.getNumPacketsReceived stats)
                 (.getNumPacketsDropped stats)))))

(defn select-nif
  "Interactive network interface selector. Returns nil if user enters 'q'."
  []
  (when-not tty?
    (throw (IllegalArgumentException.
            "Cannot select device as stdin is not tty. Use --interface option.")))
  (pcap/select-interface))

(defn print-usage!
  "Prints usage and terminates the program"
  ([status extra]
   (println extra)
   (print-usage! status))
  ([status]
   (println usage)
   (System/exit status)))

(defn parse-kafka-spec
  "Parses --kafka option"
  [kafka-spec]
  (let [[_ servers topic1 topic2 query]
        (re-matches #"^([^/]+)/([^/]*?)(?:/([^/]*?))?(?:\?(.*))?$" kafka-spec)
        extra-pairs (query->map query)]
    (when (or (nil? servers) (every? nil? (map seq [topic1 topic2])))
      (throw (IllegalArgumentException. "Invalid Kafka spec")))
    {:servers servers
     :topic1 topic1
     :topic2 (or topic2 topic1)
     :extra-pairs (query->map query)}))

(defn with-kafka*
  "Executes process function with Kafka sink"
  [kafka-spec process]
  (let [{:keys [servers topic1 topic2 extra-pairs]} (parse-kafka-spec kafka-spec)]
    (log/info "Creating Kafka producer")
    (let [[send close] (kafka/send-and-close-fn servers topic1 topic2 extra-pairs)]
      (process send)
      (log/info "Closing Kafka producer")
      (close))))

(defn with-db*
  "Executes process function with in-memory DB sink"
  [process]
  (let [connection (db/connect)]
    (log/info "Creating database schema")
    (db/create connection)
    (let [load (db/load-fn connection)]
      (process load)
      (let [{:keys [server url]} (db/start-web-server connection)]
        (log/info "Started web server:" url)
        (db/start-shell connection)
        (.stop ^org.h2.tools.Server server)))))

(defn parse-opts!
  "Parses arguments and terminates the program when an error is found"
  [args]
  (let [{:keys [options arguments errors] :as parse-result} (cli/parse-opts args cli-options)
        {:keys [count duration interface kafka help]} options]
    (cond
      help   (print-usage! 0)
      errors (print-usage! 1 (first errors))
      (and interface (seq arguments)) (print-usage! 1)

      (every? not [kafka tty? count duration])
      (print-usage! 1 "Cannot load data into in-memory database indefinitely"))
    parse-result))

(defn -main
  [& args]
  (let [{:keys [options arguments errors]} (parse-opts! args)
        {:keys [port verbose count duration interface kafka help]} options]
    (let [with-sink* (if kafka (partial with-kafka* kafka) with-db*)]
      (try
        (with-sink*
          (fn [sink]
            (if (seq arguments)
              ;; From files
              (doseq [file arguments]
                (log/info "Loading" file)
                (read-pcap-file file sink options))
              ;; From a live capture
              (read-net-interface
               (or interface (select-nif) (System/exit 1))
               sink
               options))))
        (catch Exception e
          (log/error e))))

    (shutdown-agents)))
