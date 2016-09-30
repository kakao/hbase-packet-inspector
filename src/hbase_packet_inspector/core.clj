(ns hbase-packet-inspector.core
  (:require [clojure.core.match :refer [match]]
            [clojure.java.jdbc :as jdbc]
            [clojure.string :as str]
            [clojure.tools.cli :refer [parse-opts]]
            [clojure.tools.logging :as log])
  (:import (com.google.common.io ByteStreams)
           (com.google.protobuf InvalidProtocolBufferException
                                LiteralByteString)
           (java.io ByteArrayInputStream ByteArrayOutputStream DataInputStream
                    EOFException)
           (java.sql PreparedStatement Statement Timestamp)
           (java.util.concurrent CancellationException TimeoutException)
           (org.apache.hadoop.hbase HRegionInfo)
           (org.apache.hadoop.hbase.protobuf.generated ClientProtos$Action
                                                       ClientProtos$GetRequest
                                                       ClientProtos$GetResponse
                                                       ClientProtos$MultiRequest
                                                       ClientProtos$MultiResponse
                                                       ClientProtos$MutateRequest
                                                       ClientProtos$MutationProto
                                                       ClientProtos$RegionAction
                                                       ClientProtos$RegionActionResult
                                                       ClientProtos$Result
                                                       ClientProtos$ResultOrException
                                                       ClientProtos$ScanRequest
                                                       ClientProtos$ScanResponse
                                                       RPCProtos$RequestHeader
                                                       RPCProtos$ResponseHeader)
           (org.apache.hadoop.hbase.util Bytes)
           (org.h2.server.web WebServer)
           (org.h2.tools Server Shell)
           (org.pcap4j.core BpfProgram$BpfCompileMode PcapHandle
                            PcapHandle$Builder
                            PcapNetworkInterface$PromiscuousMode Pcaps)
           (org.pcap4j.packet IpV4Packet Packet TcpPacket)
           (org.pcap4j.util NifSelector))
  (:gen-class))

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
   ["-h" "--help"]
   ["-v" "--verbose"
    :default false]])

(def hbase-ports
  "Default set of ports relevant to HBase region server"
  #{16020 60020})

(def state-expiration-ms
  "Any state object that stayed over this period will be expired"
  12000)

(def report-interval
  "Progress report interval"
  {:count 10000
   :ms    2000})

(defonce ^{:doc "In-memory h2 database"} db-connection
  (jdbc/get-connection
    {:classname   "org.h2.Driver"
     :subprotocol "h2:mem"
     :subname     "hbase;DB_CLOSE_DELAY=-1;LOG=0;UNDO_LOG=0;LOCK_MODE=0"}))

(def schema
  "Database schema"
  (let [schema {:requests [[:ts         "timestamp"]
                           [:client     "varchar(15)"]
                           [:port       "int"]
                           [:call_id    "int"]
                           [:server     "varchar(15)"]
                           [:type       "varchar(30)"]
                           [:size       "int"]
                           [:batch      "int"]
                           [:table      "varchar(100)"]
                           [:region     "varchar(200)"]
                           [:row        "varchar(500)"]
                           [:stoprow    "varchar(500)"]
                           [:cells      "int"]
                           [:durability "varchar(20)"]]
                :actions  [[:client     "varchar(15)"]
                           [:port       "int"]
                           [:call_id    "int"]
                           [:type       "varchar(30)"]
                           [:table      "varchar(100)"]
                           [:region     "varchar(200)"]
                           [:row        "varchar(500)"]
                           [:cells      "int"]
                           [:durability "varchar(20)"]]}]
    (assoc schema
           :responses
           (conj (:requests schema) [:error "varchar(300)"] [:elapsed "int"])
           :results
           (conj (:actions schema)  [:error "varchar(300)"]))))

(defn db-execute!
  "Executes SQL with the database"
  [sql]
  (with-open [^Statement stmt (-> db-connection .createStatement)]
    (.execute stmt sql)))

(let [fields (into {} (for [[table specs] schema]
                        [table (mapv #(-> % first name
                                          (str/replace "_" "-")
                                          (str/replace "type" "method")
                                          keyword) specs)]))
      fields-with-index (into {} (for [[table columns] fields]
                                   [table (map vector (iterate inc 1) columns)]))]
  (defn create-db
    "Recreates database tables"
    []
    (doseq [[table spec] schema]
      (db-execute! (str "drop table if exists " (name table)))
      (db-execute! (jdbc/create-table-ddl table spec))))

  ;;; PreparedStatements can be made only when the tables already exist
  (create-db)

  (let [pstmts
        (into {} (for [[table columns] fields]
                   [table
                    (jdbc/prepare-statement
                      db-connection
                      (format "insert into %s values(%s)"
                              (name table)
                              (str/join ", " (repeat (count columns) "?"))))]))]
    (defn db-insert-pstmt!
      "Inserts a row into the table using PreparedStatement"
      [table values]
      (let [pstmt ^PreparedStatement (pstmts table)]
        (doseq [[idx col] (fields-with-index table)
                :let [val (col values)]]
          (cond
            (nil? val)     (.setNull   pstmt idx java.sql.Types/NULL)
            (keyword? val) (.setObject pstmt idx (name val))
            :else          (.setObject pstmt idx val)))
        (.execute pstmt)))))

(defn packet->map
  "Returns essential information from the given packet as a map"
  [^Packet packet]
  (let [^IpV4Packet ipv4 (.get packet IpV4Packet)
        ^TcpPacket  tcp  (.get packet TcpPacket)
        ^Packet     data (.getPayload tcp)]
    (let [ipv4-header (.getHeader ipv4)
          tcp-header  (.getHeader tcp)]
      {:src {:addr (.. ipv4-header getSrcAddr getHostAddress)
             :port (.. tcp-header  getSrcPort valueAsInt)}
       :dst {:addr (.. ipv4-header getDstAddr getHostAddress)
             :port (.. tcp-header  getDstPort valueAsInt)}
       :length (and data (.. data length))
       :data   (and data (.. data getRawData))})))

(defn ^PcapHandle live-handle
  "Opens PcapHandle for the interface"
  [interface ports]
  (let [handle (.. (PcapHandle$Builder. interface)
                   (snaplen (* 1024 64))
                   (promiscuousMode PcapNetworkInterface$PromiscuousMode/NONPROMISCUOUS)
                   (timeoutMillis 1000)
                   build)]
    (.setFilter handle
                (str/join " or " (map (partial format "port %d") ports))
                BpfProgram$BpfCompileMode/OPTIMIZE)
    handle))

(defn ^PcapHandle file-handle
  "Opens PcapHandle from the existing file or from STDIN if path is -"
  [path]
  (Pcaps/openOffline path))

(defn ->string-binary
  "Returns a printable representation of a LiteralByteString.

  Bytes/toStringBinary used to be slow, but it's fast since hbase-client 1.2.2.
  See: https://issues.apache.org/jira/browse/HBASE-15569"
  [^LiteralByteString bytes]
  (Bytes/toStringBinary (.. bytes asReadOnlyByteBuffer)))

(defn ->keyword
  "Converts CamelCase string to lower-case keyword"
  [s]
  (-> s
      (str/replace #"([a-z])([A-Z])"
                   (fn [[_ a b]] (str a "-" (str/lower-case b))))
      str/lower-case
      keyword))

(defn parse-region-name
  "Extracts table name and encoded name from region name"
  [^LiteralByteString name]
  (let [as-bytes (-> name .asReadOnlyByteBuffer Bytes/getBytes)
        table    (Bytes/toStringBinary ^bytes (first (HRegionInfo/parseRegionName as-bytes)))
        encoded  (HRegionInfo/encodeRegionName as-bytes)]
    {:table  table
     :region encoded}))

(defn parse-get-request
  "Parses GetRequest"
  [^ClientProtos$GetRequest request]
  (assoc (parse-region-name (.. request getRegion getValue))
         :row (->string-binary (.. request getGet getRow))))

(defn parse-scan-request
  "Parses ScanRequest. :method in the returned map can be one of the followings:
     :open-scanner [*]
     :next-rows
     :close-scanner
     :small-scan [*]

     [*]: has parameters"
  [^ClientProtos$ScanRequest request]
  (let [scan   (.. request getScan)
        open?  (not (.. request hasScannerId))
        close? (.. request getCloseScanner)
        method (cond
                 (and open? close?) :small-scan
                 open?              :open-scanner
                 close?             :close-scanner
                 :else              :next-rows)]
    (merge {:method  method
            :scanner (.. request getScannerId)}
           (when (#{:open-scanner :small-scan} method)
             (merge (parse-region-name (.. request getRegion getValue))
                    {:caching (.. scan getCaching)
                     :row     (->string-binary (.. scan getStartRow))
                     :stoprow (->string-binary (.. scan getStopRow))})))))

(defn parse-mutation
  "Parses MutationProto"
  [^ClientProtos$MutationProto mutation]
  {:method     (->keyword (.. mutation getMutateType name))
   :row        (->string-binary (.. mutation getRow))
   :cells      (+ (.. mutation getAssociatedCellCount)
                  (.. mutation getColumnValueList size))
   :durability (.. mutation getDurability name toLowerCase)})

(defn parse-mutate-request
  "Parses MutateRequest"
  [^ClientProtos$MutateRequest request]
  (let [base   (parse-mutation (.. request getMutation))
        method (:method base)
        method (if (.. request hasCondition)
                 (keyword (str "check-and-" (name method)))
                 method)]
    (merge base
           {:method method}
           (parse-region-name (.. request getRegion getValue)))))

(defn parse-multi-request
  "Parses MultiRequest and returns the list of actions"
  [^ClientProtos$MultiRequest multi-request]
  (let [region-actions (.. multi-request getRegionActionList)]
    (for [^ClientProtos$RegionAction region-action region-actions
          ^ClientProtos$Action action (.. region-action getActionList)
          :let [region (parse-region-name (.. region-action getRegion getValue))]]
      (merge
        (if (.hasGet action)
          {:method :get
           :row    (->string-binary (.. action getGet getRow))}
          (parse-mutation (.. action getMutation)))
        region))))

(defn parse-request
  "Processes request from client"
  [^RPCProtos$RequestHeader header bais]
  (let [method  (.getMethodName header)
        method  (if (re-matches #"[a-zA-Z]+" method)
                  (->keyword method)
                  (throw (InvalidProtocolBufferException. "Invalid method name")))
        call-id (.getCallId header)
        params? (and (.hasRequestParam header)
                     (.getRequestParam header))
        base    {:method method :call-id call-id}]
    (merge
      base
      (when params?
        (case method
          :get
          (let [request (ClientProtos$GetRequest/parseDelimitedFrom bais)]
            (parse-get-request request))

          :scan
          (let [request (ClientProtos$ScanRequest/parseDelimitedFrom bais)]
            (parse-scan-request request))

          :mutate
          (let [request (ClientProtos$MutateRequest/parseDelimitedFrom bais)]
            (parse-mutate-request request))

          :multi
          (let [request (ClientProtos$MultiRequest/parseDelimitedFrom bais)
                actions (parse-multi-request request)
                table   (some-> (filter :table actions) first :table)]
            {:table   table
             :actions actions})
          {})))))

(defn parse-scan-response
  "Parses ScanResponses to extract the total number of cells"
  [^ClientProtos$ScanResponse response]
  {:scanner (.. response getScannerId)
   :cells   (reduce + (.. response getCellsPerResultList))})

(defn parse-get-response
  "Parses GetResponse to extract the number of cells"
  [^ClientProtos$GetResponse response]
  {:cells (+ (.. response getResult getAssociatedCellCount)
             (.. response getResult getCellList size))})

(defn parse-multi-response
  "Parses MultiResponse to extract the number of cells"
  [^ClientProtos$MultiResponse response actions]
  (let [results (for [^ClientProtos$RegionActionResult region-response     (.getRegionActionResultList response)
                      ^ClientProtos$ResultOrException  result-or-exception (.getResultOrExceptionList region-response)
                      :let  [result?    (.hasResult    result-or-exception)
                             exception? (.hasException result-or-exception)
                             result     (.getResult result-or-exception)]]
                  {:cells     (when result? (+ (.. result getAssociatedCellCount)
                                               (.. result getCellList size)))
                   :exception (when exception?
                                (some-> result-or-exception .getException .getName))})]
    {:cells   (reduce + (filter some? (map :cells results)))
     :actions (map merge actions results)}))

(defn parse-response
  "Processes response to client. Uses request-fn to find the request map for
  the call-id."
  [^RPCProtos$ResponseHeader header bais request-fn]
  (let [call-id (.. header getCallId)
        error?  (.. header hasException)
        request (request-fn call-id)
        method  (if request (:method request) :unknown)
        base    (conj {:method  method
                       :call-id call-id}
                      (when error?
                        [:error (.. header getException getExceptionClassName)]))]
    (merge
      request ; can be nil, but it's okay
      base
      (match [method]
        [(:or :open-scanner :next-rows :close-scanner)]
        (let [response (ClientProtos$ScanResponse/parseDelimitedFrom bais)]
          (parse-scan-response response))

        [:get]
        (let [response (ClientProtos$GetResponse/parseDelimitedFrom bais)]
          (parse-get-response response))

        [:multi]
        (let [response (ClientProtos$MultiResponse/parseDelimitedFrom bais)]
          (parse-multi-response response (:actions request)))

        [_] nil))))

(defn parse-stream
  "Processes the byte stream and returns the map representation of request or
  response"
  [inbound? ^ByteArrayInputStream bais total-size request-fn]
  (let [as-map (if inbound?
                 (let [header (RPCProtos$RequestHeader/parseDelimitedFrom bais)]
                   (parse-request header bais))
                 (let [header (RPCProtos$ResponseHeader/parseDelimitedFrom bais)]
                   (parse-response header bais request-fn)))]
    (assoc as-map :size total-size)))

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
  (and (pos? len) (< len (* 1024 1024 1024))))

(defn process-scan-state
  "Manages state transition during Scan lifecycle"
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
        [state (merge request parsed)])

      ;;; 3. Attach region info from the Scan request for the scanner-id
      ;;;    and update timestamp of the scanner state
      [:next-rows _]
      [(update state [:scanner scanner] assoc :ts ts)
       (merge parsed region-info)]

      ;;; 4. Discard Scan request from the state
      [:close-scanner true]
      [(dissoc state [:scanner scanner]) parsed]

      ;;; State transition is simpler for small scans
      [:small-scan false]
      (let [key [:scanner-for client call-id]]
        [(dissoc state key) (merge parsed region-info)])

      [_ _] [state parsed])))

(defn sub-ts
  "Returns the difference of two Timestamps in milliseconds"
  [^Timestamp ts2 ^Timestamp ts1]
  (- (.getTime ts2) (.getTime ts1)))

(defn process-hbase-packet
  "Parses the raw packet into a map and executes proc-fn with it.
  Returns the new state for the next iteration. state map can have the
  following types of states.

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
  can disappear without properly closing the open scanner.

  In short, it's not possible to reproduce the exact state between the server
  and the clients and that's not our goal here. We will not try to keep track
  of the states that are not essential to the workload, e.g. initial connetion
  handshake.

  However, we'll inevitably end up with dangling state objects that has to be
  cleaned up if we're going to run this program as a long-running process."

  [^Packet packet ports timestamp state proc-fn]
  {:pre [(set? ports)]}
  (let [raw          (packet->map packet)
        {:keys       [data length]} raw
        inbound?     (some? (ports (-> raw :dst :port)))
        server       (raw (if inbound? :dst :src))
        client       (raw (if inbound? :src :dst))
        client-state (state [:client client])
        request-fn   (fn [call-id] (state [:call client call-id]))
        base-map     {:ts       timestamp
                      :inbound? inbound?
                      :server   (:addr server)
                      :client   (:addr client)
                      :port     (:port client)}
        next-state   (fn [parsed]
                       (let [info (merge parsed base-map) ; mind the order
                             {:keys [call-id]} info
                             info (or (some->
                                        (when-not inbound? (request-fn call-id))
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
    (if-not (and data (some ports [(-> raw :src :port)
                                   (-> raw :dst :port)]))
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
                (next-state (parse-stream inbound? bais total request-fn)))))

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
                (next-state (parse-stream inbound? bais total request-fn))))))
        (catch Exception e
          (when-not (instance? InvalidProtocolBufferException e)
            (log/warn (.getMessage e)))
          ;;; Discard byte stream for the client
          (dissoc state [:client client]))))))

(defn db-insert!
  "Inserts request/response information into h2 database tables"
  [info verbose]
  (let [{:keys [inbound? actions client port call-id cells]} info
        batch  (count actions)
        multi? (> batch 1)
        info   (merge info (when (= batch 1) (first actions)))
        table  (if inbound? :requests :responses)
        info   (assoc info
                      :batch batch
                      :cells (or cells
                               (reduce + (remove nil? (map :cells actions)))))]
    (when verbose
      (log/info info))
    (when multi?
      (doseq [action actions]
        (db-insert-pstmt! (if inbound? :actions :results)
                          (assoc action
                                 :client  client
                                 :port    port
                                 :call-id call-id))))
    (db-insert-pstmt! table info)))

(defn get-next-packet
  "Retrieves the next packet from the handle. getNextPacketEx can throw
  TimeoutException if there is no new packet for the interface or when the
  packet is buffered by OS. This function retries in that case."
  [^PcapHandle handle]
  (loop []
    (let [result (try
                   (.getNextPacketEx handle)
                   (catch TimeoutException _
                     (Thread/sleep 100) ; needed for future-cancel
                     ::retry)
                   (catch java.io.EOFException _ nil))]
      (if (= result ::retry)
        (recur)
        result))))

(defn trim-state
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

(defn read-handle
  "Reads packets from the handle"
  [^PcapHandle handle port verbose count duration]
  {:pre [(or (nil? count) (pos? count))]}
  (let [logger   #(log/infof "Processed %d packet(s)" %)
        duration (some-> duration (* 1000))
        ports    (if port (hash-set port) hbase-ports)]
    (loop [state    {}
           first-ts nil
           seen     0
           prev     {:seen 0 :ts (System/currentTimeMillis)}]
      (if-let [packet (try (get-next-packet handle)
                           (catch InterruptedException _ nil))]
        (let [latest-ts (.getTimestamp handle)
              first-ts  (or first-ts latest-ts)
              new-state (process-hbase-packet
                          packet ports latest-ts state #(db-insert! % verbose))
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
            (logger seen)))
        (logger seen)))))

(defn read-pcap-file
  "Loads pcap file into in-memory h2 database"
  [file-name & {:keys [port verbose count duration]}]
  (with-open [handle (file-handle file-name)]
    (read-handle handle port verbose count duration)))

(defn read-net-interface
  "Captures packets from the interface and loads into the database"
  [interface & {:keys [port verbose count duration]}]
  (with-open [handle (live-handle interface hbase-ports)]
    (log/info "Press enter key to stop capturing")
    (let [f (future (read-handle handle port verbose count duration))]
      (if duration
        (Thread/sleep (* 1000 duration))
        (read-line))
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
  (some-> (NifSelector.) .selectNetworkInterface .getName))

(defn start-shell
  "Starts interactive command-line SQL client"
  []
  (.runTool (Shell.) db-connection (make-array String 0)))

(defn start-web-server
  "Starts web server for h2 database"
  []
  (let [ws (WebServer.)
        s  (doto (Server. ws (into-array String ["-webPort" "0" "-webAllowOthers"]))
             .start)
        url (.addSession ws db-connection)]
    {:server s :url url}))

(defn- print-usage!
  ([status extra]
   (println extra)
   (print-usage! status))
  ([status]
   (println usage)
   (System/exit status)))

(defn -main
  [& args]
  (let [{:keys [options arguments errors]} (parse-opts args cli-options)
        {:keys [port verbose count duration interface help]} options]
    (cond
      help   (print-usage! 0)
      errors (print-usage! 1 (first errors))
      (and interface (seq arguments)) (print-usage! 1))

    (log/info "Creating database schema")
    (create-db)

    (if (seq arguments)
      ;;; From files
      (doseq [file arguments]
        (log/info "Loading" file)
        (read-pcap-file file :port port :verbose verbose :count count :duration duration))
      ;;; From a live capture
      (read-net-interface (or interface (select-nif) (System/exit 1))
                          :port port :verbose verbose :count count :duration duration))

    (let [{:keys [server url]} (start-web-server)]
      (log/info "Started web server:" url)
      (start-shell)
      (.stop server)
      (shutdown-agents))))
