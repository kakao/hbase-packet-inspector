(ns hbase-packet-inspector.hbase-test
  (:require [clojure.test :refer :all]
            [hbase-packet-inspector.hbase :refer :all])
  (:import (com.google.protobuf ByteString)))

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
