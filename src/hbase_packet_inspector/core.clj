(ns hbase-packet-inspector.core
  (:require [cemerick.url :refer [query->map]]
            [clojure.core.match :refer [match]]
            [clojure.string :as str]
            [clojure.tools.cli :as cli]
            [clojure.tools.logging :as log]
            [hbase-packet-inspector.hbase :as hbase]
            [hbase-packet-inspector.pcap :as pcap]
            [hbase-packet-inspector.sink.db :as db]
            [hbase-packet-inspector.sink.kafka :as kafka])
  (:import (com.google.common.io ByteStreams)
           (com.google.protobuf InvalidProtocolBufferException)
           (java.io ByteArrayInputStream ByteArrayOutputStream DataInputStream
                    EOFException)
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
  [state client parsed]
  (let [{:keys [method inbound? call-id scanner ts]} parsed
        region-info (select-keys (state [:scanner scanner]) [:table :region])]
    (match [method inbound?]

      ;;; 1. Remember Scan request for call-id
      [(:or :open-scanner :small-scan) true]
      [(assoc state [:scanner-for client call-id] parsed) parsed]

      ;;; 2. Find Scan request for call-id and map it to the scanner-id
      [:open-scanner false]
      (let [key     [:scanner-for client call-id]
            request (get state key)
            state   (dissoc state key)
            state   (assoc state [:scanner scanner] request)]
        [state parsed])

      ;;; 3. Attach region info from the Scan request for the scanner-id
      ;;;    and update timestamp of the scanner state
      [:next-rows _]
      [(update state [:scanner scanner] assoc :ts ts)
       (merge parsed region-info)]

      ;;; 4. Discard Scan request from the state
      [:close-scanner true]
      [(dissoc state [:scanner scanner]) (merge parsed region-info)]

      ;;; State transition is simpler for small scans
      [:small-scan false]
      (let [key [:scanner-for client call-id]]
        [(dissoc state key) parsed])

      [_ _] [state parsed])))

(defn sub-ts
  "Returns the difference of two Timestamps in milliseconds"
  [^Timestamp ts2 ^Timestamp ts1]
  (- (.getTime ts2) (.getTime ts1)))

(defn process-hbase-packet
  "Executes proc-fn with with the map parsed from a packet. Returns the new
  state for the next iteration. state map can have the following types of
  states.

  [:client client]              => ByteArrayOutputStream
  [:call client call-id]        => Request
  [:scanner-for client call-id] => ScanRequest
  [:scanner scanner-id]         => ScanRequest

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
  (let [{:keys         [data length]} packet-map
        inbound?       (some? (ports (-> packet-map :dst :port)))
        server         (packet-map (if inbound? :dst :src))
        client         (packet-map (if inbound? :src :dst))
        client-state   (state [:client client])
        request-finder (fn [call-id] (state [:call client call-id]))
        base-map       {:ts       timestamp
                        :inbound? inbound?
                        :server   (:addr server)
                        :client   (:addr client)
                        :port     (:port client)}
        next-state     (fn [parsed]
                         (let [info (merge parsed base-map) ; mind the order
                               {:keys [call-id]} info
                               info (or (some->
                                         (when-not inbound? (request-finder call-id))
                                         :ts
                                         (some->> (sub-ts timestamp)
                                                  (assoc info :elapsed)))
                                        info)
                               [state info] (process-scan-state state client info)]
                           (proc-fn info)
                           (dissoc (if inbound?
                                     (assoc state [:call client call-id] info)
                                     (dissoc state [:call client call-id]))
                                   [:client client])))]
    (if-not (and data (some ports [(-> packet-map :src :port)
                                   (-> packet-map :dst :port)]))
      state
      (try
        (if-not client-state
          ;;; Initial encounter
          (let [bais  (ByteArrayInputStream. data)
                total (try (.. (DataInputStream. bais) readInt)
                           (catch EOFException _ 0))]

            (if-not (valid-length? total)
              ;;; Uncovered packets (e.g. Preamble, SASL handshake,
              ;;; ConnectionHeader) or fragmented payload whose header we
              ;;; missed
              state
              (if (> total (- length 4))
                (let [baos   (ByteArrayOutputStream.)
                      copied (ByteStreams/copy bais baos)]
                  (assoc state [:client client]
                         {:ts timestamp :out baos :total total :remains (- total copied)}))
                (next-state (parse-stream inbound? bais total request-finder)))))

          ;;; Continued fragment
          (let [{:keys  [out total remains]} client-state
                bais    (ByteArrayInputStream. data)
                copied  (ByteStreams/copy bais ^ByteArrayOutputStream out)
                remains (- remains copied)]
            (if (pos? remains)
              (assoc state [:client client]
                     (assoc client-state :ts timestamp :remains remains))
              (let [ba   (.toByteArray ^ByteArrayOutputStream out)
                    bais (ByteArrayInputStream. ba)]
                (next-state (parse-stream inbound? bais total request-finder))))))
        (catch Exception e
          (when-not (instance? InvalidProtocolBufferException e)
            (log/warn e))
          ;;; Discard byte stream for the client
          (dissoc state [:client client]))))))

(defn send!
  "Sends request/response information into sink (H2 database or Kafka)"
  [sink info verbose]
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
  (let [new-state (->> state
                       (remove (fn [[_ v]]
                                 (> (sub-ts latest-ts (:ts v))
                                    state-expiration-ms)))
                       (into {}))
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

(defn read-handle
  "Reads packets from the handle"
  [^PcapHandle handle sink & [{:keys [port verbose count duration]}]]
  {:pre [(or (nil? count) (pos? count))]}
  (let [logger   #(log/infof "Processed %d packet(s)" %)
        duration (some-> duration (* 1000))
        ports    (if port (hash-set port) hbase-ports)]
    (loop [state    {}
           first-ts nil
           seen     0
           prev     {:seen 0 :ts (System/currentTimeMillis)}]
      (let [packet-map (pcap/parse-next-packet handle)]
        (case packet-map
          ::pcap/interrupt (logger seen)
          ::pcap/ignore (recur state first-ts seen prev)
          (let [latest-ts (.getTimestamp handle)
                first-ts  (or first-ts latest-ts)
                new-state (process-hbase-packet
                           packet-map ports latest-ts state #(send! sink % verbose))
                now       (System/currentTimeMillis)
                seen      (inc seen)
                tdiff     (- now  (:ts   prev))
                diff      (- seen (:seen prev))
                print?    (or (>= tdiff (:ms report-interval))
                              (>= diff  (:count report-interval)))]
            (when print?
              (logger seen))
            (if (and (or (nil? count) (< seen count))
                     (or (nil? duration) (< (sub-ts latest-ts first-ts) duration)))
              (if print?
                (recur (trim-state new-state latest-ts) first-ts seen {:seen seen :ts now})
                (recur new-state first-ts seen prev))
              (logger seen))))))))

(defn read-pcap-file
  "Loads pcap file into in-memory h2 database"
  [file-name sink options]
  (with-open [handle (pcap/file-handle file-name)]
    (read-handle handle sink options)))

(defn read-net-interface
  "Captures packets from the interface and loads into the database"
  [interface sink options]
  (with-open [handle (pcap/live-handle interface hbase-ports)]
    (let [f (future (read-handle handle sink options))]
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
      (log/infof "%d packet(s) received, %d dropped"
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
        (re-matches #"^([^/]+)/([^/]*)(?:/([^/]*?))?(?:\?(.*))?$" kafka-spec)
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
    (process (db/sink-fn connection))
    (let [{:keys [server url]} (db/start-web-server connection)]
      (log/info "Started web server:" url)
      (db/start-shell connection)
      (.stop ^org.h2.tools.Server server))))

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
    (let [with-sink* (if kafka with-kafka* with-db*)]
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
