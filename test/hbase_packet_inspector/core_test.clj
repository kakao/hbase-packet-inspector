(ns hbase-packet-inspector.core-test
  (:require [clojure.test :refer :all]
            [clojure.string :as str]
            [clojure.tools.cli :refer [parse-opts]]
            [hbase-packet-inspector.core :refer :all])
  (:import (com.google.protobuf ByteString
                                LiteralByteString)
           (java.sql Timestamp)))

(deftest test-cli-options
  (testing "Combo"
    (let [{:keys [arguments options errors] :as result}
          (parse-opts ["-i" "eth0" "-c" "100" "-p0" "hello" "world"] cli-options)
          {:keys [interface port count verbose]} options]
      (is (= "eth0" interface))
      (is (= 100 count))
      (is (= false verbose))
      (is (not (contains? options :port)))
      (is (str/includes? (first errors) "Must be a number between 0 and 65536"))
      (is (= ["hello" "world"] arguments))))
  (testing "Empty interface"
    (let [{:keys [errors]} (parse-opts ["-i" ""] cli-options)]
      (is (str/includes? (first errors) "Must be a non-empty string")))))

(deftest test->string-binary
  (is (= "[\\x5C]^_`abcdefghijklmnopqrstuvwxyz{|}~\\x7F\\x80\\x81"
         (->string-binary
          (ByteString/copyFrom (byte-array (range 91 130)))))))

(deftest test->keyword
  (is (= :get (->keyword "Get")))
  (is (= :get (->keyword "GET")))
  (is (= :get-online-regions (->keyword "GetOnlineRegions"))))

(deftest test-parse-region-name
  (is (= {:table "tablename" :region "<...encoded-name-in-32-bytes...>"}
         (parse-region-name
          (ByteString/copyFromUtf8
           "tablename,startkey,timestamp.<...encoded-name-in-32-bytes...>.")))))

(deftest test-process-scan-state
  (let [client :alice
        state0 {}

        open-req {:method   :open-scanner
                  :inbound? true
                  :call-id  100
                  :ts       2016
                  :table    "foo"
                  :region   "bar"}
        [state1  _] (process-scan-state state0 client open-req)

        open-res {:method   :open-scanner
                  :inbound? false
                  :call-id  100
                  :scanner  1000}
        [state2 open-res*] (process-scan-state state1 client open-res)

        next-req {:method   :next-rows
                  :inbound? true
                  :ts       2017
                  :scanner  1000}
        [state3 next-req*] (process-scan-state state2 client next-req)

        next-res {:method   :next-rows
                  :inbound? false
                  :ts       2018
                  :scanner  1000}
        [state4 next-res*] (process-scan-state state3 client next-res)

        close-req {:method :close-scanner
                   :inbound? true
                   :scanner 1000}
        [state5 close-req] (process-scan-state state3 client close-req)]
    ;;; The call ID of open-scanner request is mapped to the request
    (is (contains? state1 [:scanner-for :alice 100]))
    (is (not (contains? state1 [:scanner 1000])))
    (is (= open-req (state1 [:scanner-for :alice 100])))

    ;;; Scanner ID only becomes known on open-scanner response
    ;;; We map scanner ID to the initial open-scanner request
    (is (not (contains? state2 [:scanner-for :alice 100])))
    (is (contains? state2 [:scanner 1000]))
    (is (= open-req (state2 [:scanner 1000])))
    (is (every? open-res* [:region :table]))

    ;;; The response and request are augmented with the initial open-scanner
    ;;; request.
    (is (every? next-req* [:region :table]))
    (is (every? next-res* [:region :table]))

    ;;; next-rows only updates :ts
    (is (= 2016 (-> state2 first val :ts)))
    (is (= 2017 (-> state3 first val :ts)))
    (is (= 2018 (-> state4 first val :ts)))
    (is (apply = (map #(map (fn [[k v]] [k (dissoc v :ts)]) %)
                      [state4 state3 state2])))

    ;;; close-scanner will remove scanner entry from the state
    (is (empty? state5))))

(deftest test-trim-state
  (let [now-ms (System/currentTimeMillis)
        state {:new {:ts (Timestamp. now-ms)}
               :old {:ts (Timestamp. (- now-ms state-expiration-ms))}}]
    (is (= 2 (count (trim-state state (Timestamp. (dec now-ms))))))
    (is (= 1 (count (trim-state state (Timestamp. (inc now-ms))))))))
