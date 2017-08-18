(ns hbase-packet-inspector.hbase-test
  (:require [clojure.test :refer :all]
            [hbase-packet-inspector.hbase :refer :all :as hbase])
  (:import (com.google.protobuf ByteString MessageLite)
           (java.io ByteArrayInputStream ByteArrayOutputStream)
           (org.apache.hadoop.hbase.protobuf.generated
            HBaseProtos$NameBytesPair
            RPCProtos$ResponseHeader
            RPCProtos$ExceptionResponse
            CellProtos$Cell
            ClientProtos$GetResponse
            ClientProtos$MultiResponse
            ClientProtos$Result
            ClientProtos$ResultOrException
            ClientProtos$RegionActionResult
            ClientProtos$ScanResponse)))

(deftest test->string-binary
  (is (= "[\\x5C]^_`abcdefghijklmnopqrstuvwxyz{|}~\\x7F\\x80\\x81"
         (->string-binary
          (ByteString/copyFrom (byte-array (range 91 130)))))))

(deftest test-parse-region-name
  (is (= {:table "tablename" :region "<...encoded-name-in-32-bytes...>"}
         (parse-region-name
          (ByteString/copyFromUtf8
           "tablename,startkey,timestamp.<...encoded-name-in-32-bytes...>.")))))

(deftest test->keyword
  (is (= :get (->keyword "Get")))
  (is (= :get (->keyword "GET")))
  (is (= :get-online-regions (->keyword "GetOnlineRegions"))))

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
  [^MessageLite msg]
  (let [baos (ByteArrayOutputStream.)]
    (.writeDelimitedTo msg baos)
    (ByteArrayInputStream. (.toByteArray baos))))

(deftest test-parse-scan-response
  (is (= {:scanner 100 :cells 3}
         (hbase/parse-scan-response (make-scan-response 100)))))

(deftest test-parse-get-response
  (is (= {:cells 12}
         (hbase/parse-get-response
          (make-get-response 10 2)))))

(deftest test-parse-multi-response
  (is (= {:cells 12
          :actions [{:foo :bar :cells 12 :exception nil}
                    {:FOO :BAR :cells 0 :exception "foo"}]}
         (hbase/parse-multi-response (make-multi-response)
                                     [{:foo :bar}
                                      {:FOO :BAR}]))))

(deftest test-parse-response
  (testing "multi"
    (is (= {:method :multi
            :actions [{:foo :bar, :cells 12, :exception nil}
                      {:FOO :BAR, :cells 0, :exception "foo"}]
            :call-id 1
            :error "error-class"
            :cells 12}
           (hbase/parse-response
            (.. (RPCProtos$ResponseHeader/newBuilder)
                (setCallId 1)
                (setException (.. (RPCProtos$ExceptionResponse/newBuilder)
                                  (setExceptionClassName "error-class")))
                build)
            (->bais (make-multi-response))
            {1 {:method :multi
                :actions [{:foo :bar}
                          {:FOO :BAR}]}}))))
  (testing "get"
    (is (= {:method :get
            :call-id 1
            :error "error-class"
            :cells 12}
           (hbase/parse-response
            (.. (RPCProtos$ResponseHeader/newBuilder)
                (setCallId 1)
                (setException (.. (RPCProtos$ExceptionResponse/newBuilder)
                                  (setExceptionClassName "error-class")))
                build)
            (->bais (make-get-response 10 2))
            {1 {:method :get}}))))

  (testing "scan"
    (is (= {:method :open-scanner
            :call-id 1
            :scanner 200
            :cells 3}
           (hbase/parse-response
            (.. (RPCProtos$ResponseHeader/newBuilder)
                (setCallId 1)
                build)
            (->bais (make-scan-response 200))
            {1 {:method :open-scanner}}))))

  (testing "unknown"
    (is (= {:method :unknown :call-id 1}
           (hbase/parse-response
            (.. (RPCProtos$ResponseHeader/newBuilder)
                (setCallId 1)
                build)
            (ByteArrayInputStream. (byte-array 0))
            {1 {:method :unknown}})))))
