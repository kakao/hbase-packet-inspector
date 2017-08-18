(ns hbase-packet-inspector.core-test
  (:require [clojure.string :as str]
            [clojure.test :refer :all]
            [clojure.tools.cli :refer [parse-opts]]
            [hbase-packet-inspector.core :refer :all])
  (:import (java.sql Timestamp)))

(deftest test-cli-options
  (testing "Combo"
    (let [{:keys [arguments options errors] :as result}
          (parse-opts ["-i" "eth0" "-c" "100" "-p0" "--duration=123" "hello" "world"] cli-options)
          {:keys [interface port duration count verbose]} options]
      (is (= "eth0" interface))
      (is (= 100 count))
      (is (= 123 duration))
      (is (= false verbose))
      (is (not (contains? options :port)))
      (is (str/includes? (first errors) "Must be a number between 0 and 65536"))
      (is (= ["hello" "world"] arguments))))
  (testing "Empty interface"
    (let [{:keys [errors]} (parse-opts ["-i" ""] cli-options)]
      (is (str/includes? (first errors) "Must be a non-empty string")))))

(deftest test-valid-length?
  (is (not (valid-length? -1)))
  (is (not (valid-length? 0)))
  (is (not (valid-length? (Math/pow 1024 3))))
  (is (valid-length? 1024)))

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
        [state2 _] (process-scan-state state1 client open-res)

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
        [state5 close-req] (process-scan-state state4 client close-req)

        small-scan-req {:method   :small-scan
                        :call-id  200
                        :table    "foo"
                        :region   "bar"
                        :inbound? true}
        [state6 small-scan-req*] (process-scan-state state5 client small-scan-req)

        small-scan-res {:method   :small-scan
                        :call-id  200
                        :inbound? false}
        [state7 _] (process-scan-state state6 client small-scan-res)
        [state8 unknown] (process-scan-state state7 client {:method :unknown})]
    ;;; The call ID of open-scanner request is mapped to the request
    (is (contains? state1 [:scanner-for :alice 100]))
    (is (not (contains? state1 [:scanner 1000])))
    (is (= open-req (state1 [:scanner-for :alice 100])))

    ;;; Scanner ID only becomes known on open-scanner response
    ;;; We map scanner ID to the initial open-scanner request
    (is (not (contains? state2 [:scanner-for :alice 100])))
    (is (contains? state2 [:scanner 1000]))
    (is (= open-req (state2 [:scanner 1000])))

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
    (is (empty? state5))

    ;;; Small scan state
    (is (= 1 (count state6)))
    (is (contains? state6 [:scanner-for :alice 200]))
    (is (= "foo" (-> state6 vals first :table)))
    (is (= "bar" (-> state6 vals first :region)))

    ;;; state is cleaned up after small-scan response
    (is (empty? state7))

    ;;; Unknown method shouldn't affect state
    (is (= {:method :unknown} unknown))
    (is (empty? state8))))

(deftest test-trim-state
  (let [now-ms (System/currentTimeMillis)
        state {:new {:ts (Timestamp. now-ms)}
               :old {:ts (Timestamp. (- now-ms state-expiration-ms))}}]
    (is (= 2 (count (trim-state state (Timestamp. (dec now-ms))))))
    (is (= 1 (count (trim-state state (Timestamp. (inc now-ms))))))))

(deftest test-fmt-bytes
  (is (= "100 B" (fmt-bytes 100)))
  (is (= "1.00 KiB" (fmt-bytes 1024)))
  (is (= "1.00 MiB" (fmt-bytes (Math/pow 1024 2))))
  (is (= "1.00 GiB" (fmt-bytes (Math/pow 1024 3))))
  (is (= "1024.00 GiB" (fmt-bytes (Math/pow 1024 4)))))

(deftest test-parse-kafka-spec
  (is (thrown? IllegalArgumentException (parse-kafka-spec "foo,bar")))
  (is (thrown? IllegalArgumentException (parse-kafka-spec "/t")))
  (is (thrown? IllegalArgumentException (parse-kafka-spec "foo,bar//")))
  (is (= {:servers "foo,bar" :topic1 "t" :topic2 "t" :extra-pairs nil}
         (parse-kafka-spec "foo,bar/t")))
  (is (= {:servers "foo,bar" :topic1 "t" :topic2 "" :extra-pairs nil}
         (parse-kafka-spec "foo,bar/t/")))
  (is (= {:servers "foo,bar" :topic1 "" :topic2 "t" :extra-pairs nil}
         (parse-kafka-spec "foo,bar//t")))
  (is (= {:servers "foo,bar" :topic1 "t1" :topic2 "t2" :extra-pairs nil}
         (parse-kafka-spec "foo,bar/t1/t2")))
  (is (= {:servers "foo,bar" :topic1 "t1" :topic2 "t2" :extra-pairs {"a" "b" "c" "d"}}
         (parse-kafka-spec "foo,bar/t1/t2?a=b&c=d"))))
