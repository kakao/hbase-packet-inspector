(ns hbase-packet-inspector.hbase-test
  (:require [clojure.test :refer :all]
            [hbase-packet-inspector.core :as core]
            [hbase-packet-inspector.hbase :as hbase])
  (:import (com.google.protobuf ByteString MessageLite InvalidProtocolBufferException)
           (java.io ByteArrayInputStream ByteArrayOutputStream)
           (org.apache.hadoop.hbase HRegionInfo)
           (org.apache.hadoop.hbase.protobuf.generated
            HBaseProtos$CompareType
            HBaseProtos$NameBytesPair
            HBaseProtos$RegionSpecifier
            HBaseProtos$RegionSpecifier$RegionSpecifierType
            RPCProtos$RequestHeader
            RPCProtos$ResponseHeader
            RPCProtos$ExceptionResponse
            ComparatorProtos$Comparator
            CellProtos$Cell
            ClientProtos$Action
            ClientProtos$RegionAction
            ClientProtos$Column
            ClientProtos$Condition
            ClientProtos$Get
            ClientProtos$GetRequest
            ClientProtos$GetResponse
            ClientProtos$MultiRequest
            ClientProtos$MultiResponse
            ClientProtos$MutationProto
            ClientProtos$MutationProto$ColumnValue
            ClientProtos$MutationProto$ColumnValue$QualifierValue
            ClientProtos$MutationProto$MutationType
            ClientProtos$MutateRequest
            ClientProtos$BulkLoadHFileRequest
            ClientProtos$Result
            ClientProtos$ResultOrException
            ClientProtos$RegionActionResult
            ClientProtos$Scan
            ClientProtos$ScanRequest
            ClientProtos$ScanResponse)))

(deftest test->string-binary
  (is (= "[\\x5C]^_`abcdefghijklmnopqrstuvwxyz{|}~\\x7F\\x80\\x81"
         (hbase/->string-binary
          (ByteString/copyFrom (byte-array (range 91 130)))))))

(deftest test-parse-region-name
  (is (= {:table "tablename" :region "<...encoded-name-in-32-bytes...>"}
         (hbase/parse-region-name
          (ByteString/copyFromUtf8
           "tablename,startkey,timestamp.<...encoded-name-in-32-bytes...>.")))))

(deftest test->keyword
  (is (= :get (hbase/->keyword "Get")))
  (is (= :get (hbase/->keyword "GET")))
  (is (= :get-online-regions (hbase/->keyword "GetOnlineRegions"))))

(defn make-result
  ^ClientProtos$Result [assoc-cells cells]
  (let [builder (.. (ClientProtos$Result/newBuilder)
                    (setAssociatedCellCount assoc-cells))]
    (dotimes [_ cells]
      (.addCell builder (CellProtos$Cell/newBuilder)))
    (.build builder)))

(defn make-exception
  ^HBaseProtos$NameBytesPair [name value]
  (.. (HBaseProtos$NameBytesPair/newBuilder)
      (setName name)
      (setValue (ByteString/copyFromUtf8 value))
      build))

(defn make-scan-response
  ^ClientProtos$ScanResponse [scanner-id]
  (.. (ClientProtos$ScanResponse/newBuilder)
      (setScannerId scanner-id)
      (addCellsPerResult 1)
      (addCellsPerResult 2)
      build))

(defn make-get-response
  ^ClientProtos$GetResponse [assoc-cells cells]
  (.. (ClientProtos$GetResponse/newBuilder)
      (setResult (make-result assoc-cells cells))
      build))

(defn make-multi-response
  ^ClientProtos$MultiResponse []
  (.. (ClientProtos$MultiResponse/newBuilder)
      (addRegionActionResult
       (.. (ClientProtos$RegionActionResult/newBuilder)
           (addResultOrException
            (.. (ClientProtos$ResultOrException/newBuilder)
                (setResult (make-result 10 2))))
           (addResultOrException
            (.. (ClientProtos$ResultOrException/newBuilder)
                (setException (make-exception "foo" "bar"))))))
      build))

(defn ->bais
  [& msgs]
  (let [baos (ByteArrayOutputStream.)]
    (doseq [^MessageLite msg msgs]
      (.writeDelimitedTo msg baos))
    (ByteArrayInputStream. (.toByteArray baos))))

(defn make-response-header
  ^RPCProtos$ResponseHeader [call-id]
  (.. (RPCProtos$ResponseHeader/newBuilder)
      (setCallId call-id)
      (setException (.. (RPCProtos$ExceptionResponse/newBuilder)
                        (setExceptionClassName "error-class")))
      build))

(defn parse-response
  [call-id ^MessageLite response request]
  (hbase/parse-response (make-response-header call-id)
                        (->bais response)
                        {call-id request}))

(deftest test-parse-response
  (testing "multi"
    (is (= {:method  :multi
            :actions [{:foo :bar} {:FOO :BAR}]
            :results [{:foo :bar, :cells 12, :exception nil}
                      {:FOO :BAR, :cells nil, :exception "foo"}]
            :call-id 100
            :error   "error-class"
            :cells   12}
           (parse-response 100
                           (make-multi-response)
                           {:method :multi
                            :actions [{:foo :bar} {:FOO :BAR}]}))))
  (testing "get"
    (is (= {:method  :get
            :call-id 100
            :error   "error-class"
            :cells   12}
           (parse-response 100 (make-get-response 10 2) {:method :get}))))

  (testing "scan"
    (is (= {:method  :open-scanner
            :call-id 100
            :error   "error-class"
            :scanner 200
            :cells   3}
           (parse-response 100 (make-scan-response 200) {:method :open-scanner}))))

  (testing "unknown"
    (is (= {:method :unknown :call-id 1}
           (hbase/parse-response
            (.. (RPCProtos$ResponseHeader/newBuilder)
                (setCallId 1)
                build)
            (ByteArrayInputStream. (byte-array 0))
            {1 {:method :unknown}})))))

(def ^String table-name "<tablename>")
(def ^String region-name "<tablename>,<startkey>,<regionId>.<encodedName>")
(def ^String encoded-name (HRegionInfo/encodeRegionName (.getBytes region-name)))

(def ^HBaseProtos$RegionSpecifier region
  (.. (HBaseProtos$RegionSpecifier/newBuilder)
      (setType HBaseProtos$RegionSpecifier$RegionSpecifierType/ENCODED_REGION_NAME)
      (setValue (ByteString/copyFromUtf8 region-name))
      build))

(defn make-get
  ^ClientProtos$Get []
  (.. (ClientProtos$Get/newBuilder)
      (setRow (ByteString/copyFromUtf8 "rowkey"))
      (addColumn (.. (ClientProtos$Column/newBuilder)
                     (setFamily (ByteString/copyFromUtf8 "cf1"))
                     (addQualifier (ByteString/copyFromUtf8 "cq1"))
                     (addQualifier (ByteString/copyFromUtf8 "cq2"))
                     (addQualifier (ByteString/copyFromUtf8 "cq3"))))
      (addColumn (.. (ClientProtos$Column/newBuilder)
                     (setFamily (ByteString/copyFromUtf8 "cf2"))
                     (addQualifier (ByteString/copyFromUtf8 "cq1"))
                     (addQualifier (ByteString/copyFromUtf8 "cq2"))
                     (addQualifier (ByteString/copyFromUtf8 "cq3"))))
      build))

(defn make-get-request
  ^ClientProtos$GetRequest []
  (.. (ClientProtos$GetRequest/newBuilder)
      (setRegion region)
      (setGet (make-get))
      build))

(defn make-scan-request
  ^ClientProtos$ScanRequest [scanner-id close? caching]
  (let [builder (.. (ClientProtos$ScanRequest/newBuilder)
                    (setRegion region))]
    (when scanner-id
      (.setScannerId builder scanner-id))
    (when close?
      (.setCloseScanner builder true))
    (.setScan builder
              (.. (ClientProtos$Scan/newBuilder)
                  (setCaching caching)
                  (setStartRow (ByteString/copyFromUtf8 "start"))
                  (setStopRow (ByteString/copyFromUtf8 "stop"))))
    (.build builder)))

(defn make-request-header
  ^RPCProtos$RequestHeader [method-name call-id]
  (.. (RPCProtos$RequestHeader/newBuilder)
      (setCallId call-id)
      (setMethodName method-name)
      (setRequestParam true)
      build))

(defn make-mutation
  ^ClientProtos$MutationProto [^String mutate-type]
  (.. (ClientProtos$MutationProto/newBuilder)
      (setMutateType
       (ClientProtos$MutationProto$MutationType/valueOf
        mutate-type))
      (setRow (ByteString/copyFromUtf8 "rowkey"))
      (setAssociatedCellCount 10)
      (addColumnValue (.. (ClientProtos$MutationProto$ColumnValue/newBuilder)
                          (setFamily (ByteString/copyFromUtf8 "cf1"))
                          (addQualifierValue (ClientProtos$MutationProto$ColumnValue$QualifierValue/newBuilder))))
      (addColumnValue (.. (ClientProtos$MutationProto$ColumnValue/newBuilder)
                          (setFamily (ByteString/copyFromUtf8 "cf2"))
                          (addQualifierValue (ClientProtos$MutationProto$ColumnValue$QualifierValue/newBuilder))
                          (addQualifierValue (ClientProtos$MutationProto$ColumnValue$QualifierValue/newBuilder))))
      build))

(defn make-mutate-request
  ^ClientProtos$MutateRequest [^String mutate-type has-condition]
  (let [builder (.. (ClientProtos$MutateRequest/newBuilder)
                    (setRegion region)
                    (setMutation (make-mutation mutate-type)))]
    (when has-condition
      ;; row, family, qualifier, compare_type, comparator
      (.setCondition builder (.. (ClientProtos$Condition/newBuilder)
                                 (setRow (ByteString/copyFromUtf8 "rowkey"))
                                 (setFamily (ByteString/copyFromUtf8 "cf"))
                                 (setQualifier (ByteString/copyFromUtf8 "cq"))
                                 (setCompareType HBaseProtos$CompareType/EQUAL)
                                 (setComparator (.. (ComparatorProtos$Comparator/newBuilder)
                                                    (setName "cmp")
                                                    build)))))
    (.build builder)))

(defn make-multi-request
  ^ClientProtos$MultiRequest []
  (.. (ClientProtos$MultiRequest/newBuilder)
      (addRegionAction (.. (ClientProtos$RegionAction/newBuilder)
                           (setRegion region)
                           (addAction
                            (.. (ClientProtos$Action/newBuilder)
                                (setGet (make-get))))
                           (addAction
                            (.. (ClientProtos$Action/newBuilder)
                                (setMutation (make-mutation "PUT"))))
                           (addAction
                            (.. (ClientProtos$Action/newBuilder)
                                (setMutation (make-mutation "DELETE"))))
                           build))
      build))

(defn parse-request
  [method-name call-id request]
  (hbase/parse-request (make-request-header method-name call-id)
                       (->bais request)))

(deftest test-parse-request
  (testing "get"
    (is (= {:method  :get
            :call-id 100
            :table   table-name
            :region  encoded-name
            :row     "rowkey"
            :cells   6}
           (parse-request "GET" 100 (make-get-request)))))

  (testing "open-scanner"
    (is (= {:method  :open-scanner
            :call-id 100
            :scanner 0
            :table   table-name
            :region  encoded-name
            :caching 1000
            :row     "start"
            :stoprow "stop"}
           (parse-request "SCAN" 100 (make-scan-request nil false 1000)))))

  (testing "close-scanner"
    (is (= {:method  :close-scanner
            :call-id 100
            :scanner 1}
           (parse-request "SCAN" 100 (make-scan-request 1 true 1000)))))

  (testing "small-scan"
    (is (= {:method  :small-scan
            :call-id 100
            :scanner 0
            :table   table-name
            :region  encoded-name
            :caching 1000
            :row     "start"
            :stoprow "stop"}
           (parse-request "SCAN" 100 (make-scan-request nil true 1000)))))

  (testing "next-rows"
    (is (= {:method  :next-rows
            :call-id 100
            :scanner 2}
           (parse-request "SCAN" 100 (make-scan-request 2 false 1000)))))

  (testing "put"
    (is (= {:method :put
            :call-id 100
            :row "rowkey"
            :cells 13
            :durability :use_default
            :table   table-name
            :region  encoded-name}
           (parse-request "MUTATE" 100 (make-mutate-request "PUT" false)))))

  (testing "check-and-delete"
    (is (= {:method :check-and-delete
            :call-id 100
            :row "rowkey"
            :cells 13
            :durability :use_default
            :table   table-name
            :region  encoded-name}
           (parse-request "MUTATE" 100 (make-mutate-request "DELETE" true)))))

  (testing "multi"
    (is (= {:method :multi
            :call-id 100
            :table "<tablename>"
            :actions [{:method :get
                       :row "rowkey"
                       :table "<tablename>"
                       :region "1505983556"}
                      {:method :put
                       :row "rowkey"
                       :cells 13
                       :durability :use_default
                       :table "<tablename>"
                       :region "1505983556"}
                      {:method :delete
                       :row "rowkey"
                       :cells 13
                       :durability :use_default
                       :table "<tablename>"
                       :region "1505983556"}]}
           (parse-request "MULTI" 100 (make-multi-request)))))

  (testing "bulk-load-hfile"
    (is (= {:method :bulk-load-hfile
            :call-id 100
            :table   table-name
            :region  encoded-name}
           (parse-request "BulkLoadHfile" 100
                          (.. (ClientProtos$BulkLoadHFileRequest/newBuilder)
                              (setRegion region)
                              build)))))
  (testing "unknown"
    (is (= {:method :unknown :call-id 100}
           (parse-request "unknown" 100 (make-get-request)))))

  (testing "invalid"
    (is (thrown? InvalidProtocolBufferException
                 (parse-request "1234" 100 (make-get-request))))))

(deftest test-parse-stream
  (testing "hbase/parse-stream"
    (is (= {:method :get
            :call-id 100
            :table table-name
            :region encoded-name
            :row "rowkey"
            :cells 6}
           (hbase/parse-stream true (->bais (make-request-header "GET" 100)
                                            (make-get-request)) nil)))
    (is (= {:method :get
            :extra :data
            :call-id 100
            :error "error-class"
            :cells 12}
           (hbase/parse-stream false (->bais (make-response-header 100)
                                             (make-get-response 10 2))
                               {100 {:method :get :extra :data}}))))

  (testing "core/parse-stream"
    ;; Basically does the same, but takes additional total-size argument
    (is (= {:method :get
            :call-id 100
            :table table-name
            :region encoded-name
            :row "rowkey"
            :cells 6
            :size 9999}
           (core/parse-stream true (->bais (make-request-header "GET" 100)
                                           (make-get-request)) 9999 nil)))))
