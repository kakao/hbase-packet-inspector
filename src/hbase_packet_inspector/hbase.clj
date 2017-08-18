(ns hbase-packet-inspector.hbase
  (:require [clojure.core.match :refer [match]]
            [clojure.string :as str])
  (:import (com.google.protobuf InvalidProtocolBufferException
                                LiteralByteString)
           (java.io ByteArrayInputStream)
           (org.apache.hadoop.hbase HRegionInfo)
           (org.apache.hadoop.hbase.protobuf.generated ClientProtos$Action
                                                       ClientProtos$BulkLoadHFileRequest
                                                       ClientProtos$Column
                                                       ClientProtos$GetRequest
                                                       ClientProtos$GetResponse
                                                       ClientProtos$MultiRequest
                                                       ClientProtos$MultiResponse
                                                       ClientProtos$MutateRequest
                                                       ClientProtos$MutationProto
                                                       ClientProtos$MutationProto$ColumnValue
                                                       ClientProtos$RegionAction
                                                       ClientProtos$RegionActionResult
                                                       ClientProtos$ResultOrException
                                                       ClientProtos$ScanRequest
                                                       ClientProtos$ScanResponse
                                                       RPCProtos$RequestHeader
                                                       RPCProtos$ResponseHeader)
           (org.apache.hadoop.hbase.util Bytes)))

(defn ->string-binary
  "Returns a printable representation of a LiteralByteString.

  Bytes/toStringBinary used to be slow, but it's fast since hbase-client 1.2.2.
  See: https://issues.apache.org/jira/browse/HBASE-15569"
  [^LiteralByteString bytes]
  (Bytes/toStringBinary (.. bytes asReadOnlyByteBuffer)))

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
                  {:cells     (when result?
                                (+ (.. result getAssociatedCellCount)
                                   (.. result getCellList size)))
                   :exception (when exception?
                                (some-> result-or-exception .getException .getName))})]
    {:cells   (reduce + (filter some? (map :cells results)))
     :actions (map merge actions results)}))

(defn parse-response
  "Processes response to client. Uses request-finder to find the request map for
  the call-id."
  [^RPCProtos$ResponseHeader header bais request-finder]
  (let [call-id (.. header getCallId)
        error?  (.. header hasException)
        request (request-finder call-id)
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
  (let [get (.. request getGet)
        families (.. get getColumnList)
        all-qualifiers (reduce + (for [^ClientProtos$Column family families]
                                   (.. family getQualifierCount)))]
    (assoc (parse-region-name (.. request getRegion getValue))
           :row (->string-binary (.. get getRow))
           :cells all-qualifiers)))

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

(defn ->keyword
  "Converts CamelCase string to lower-case keyword"
  [s]
  (-> s
      (str/replace #"([a-z])([A-Z])"
                   (fn [[_ a b]] (str a "-" (str/lower-case b))))
      str/lower-case
      keyword))

(defn parse-mutation
  "Parses MutationProto"
  [^ClientProtos$MutationProto mutation]
  {:method     (->keyword (.. mutation getMutateType name))
   :row        (->string-binary (.. mutation getRow))
   :cells      (+ (.. mutation getAssociatedCellCount)
                  (count (mapcat #(.getQualifierValueList ^ClientProtos$MutationProto$ColumnValue %)
                                 (.. mutation getColumnValueList))))
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

(defn parse-bulk-load-hfile-request
  "Parses BulkLoadHFileRequest"
  [^ClientProtos$BulkLoadHFileRequest request]
  (parse-region-name (.. request getRegion getValue)))

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

         :bulk-load-hfile
         (let [request (ClientProtos$BulkLoadHFileRequest/parseDelimitedFrom bais)]
           (parse-bulk-load-hfile-request request))
         {})))))

(defn parse-stream
  "Processes the byte stream and returns the map representation of request or
  response. request-finder is used to find the corresponding request for the
  call ID."
  [inbound? ^ByteArrayInputStream bais request-finder]
  (if inbound?
    (let [header (RPCProtos$RequestHeader/parseDelimitedFrom bais)]
      (parse-request header bais))
    (let [header (RPCProtos$ResponseHeader/parseDelimitedFrom bais)]
      (parse-response header bais request-finder))))
