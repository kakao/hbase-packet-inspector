(ns hbase-packet-inspector.core-test
  (:require [clojure.string :as str]
            [clojure.java.io :as io]
            [clojure.test :refer :all]
            [clojure.tools.logging :as log]
            [clojure.tools.cli :refer [parse-opts]]
            [hbase-packet-inspector.core :refer :all :as core]
            [hbase-packet-inspector.sink.kafka :as kafka]
            [hbase-packet-inspector.kafka-test :as kt])
  (:import (java.sql Timestamp)
           (java.io ByteArrayInputStream ByteArrayOutputStream)
           (com.google.common.io ByteStreams)))

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
    ;; The call ID of open-scanner request is mapped to the request
    (is (contains? state1 [:scanner-for :alice 100]))
    (is (not (contains? state1 [:scanner 1000])))
    (is (= open-req (state1 [:scanner-for :alice 100])))

    ;; Scanner ID only becomes known on open-scanner response
    ;; We map scanner ID to the initial open-scanner request
    (is (not (contains? state2 [:scanner-for :alice 100])))
    (is (contains? state2 [:scanner 1000]))
    (is (= open-req (state2 [:scanner 1000])))

    ;; The response and request are augmented with the initial open-scanner
    ;; request.
    (is (every? next-req* [:region :table]))
    (is (every? next-res* [:region :table]))

    ;; next-rows only updates :ts
    (is (= 2016 (-> state2 first val :ts)))
    (is (= 2017 (-> state3 first val :ts)))
    (is (= 2018 (-> state4 first val :ts)))
    (is (apply = (map #(map (fn [[k v]] [k (dissoc v :ts)]) %)
                      [state4 state3 state2])))

    ;; close-scanner will remove scanner entry from the state
    (is (empty? state5))

    ;; Small scan state
    (is (= 1 (count state6)))
    (is (contains? state6 [:scanner-for :alice 200]))
    (is (= "foo" (-> state6 vals first :table)))
    (is (= "bar" (-> state6 vals first :region)))

    ;; state is cleaned up after small-scan response
    (is (empty? state7))

    ;; Unknown method shouldn't affect state
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
  (is (= {:servers "foo,bar" :topic1 "t" :topic2 "t" :extra-pairs {"a" "b" "c" "d"}}
         (parse-kafka-spec "foo,bar/t?a=b&c=d")))
  (is (= {:servers "foo,bar" :topic1 "t" :topic2 "" :extra-pairs nil}
         (parse-kafka-spec "foo,bar/t/")))
  (is (= {:servers "foo,bar" :topic1 "" :topic2 "t" :extra-pairs nil}
         (parse-kafka-spec "foo,bar//t")))
  (is (= {:servers "foo,bar" :topic1 "t1" :topic2 "t2" :extra-pairs nil}
         (parse-kafka-spec "foo,bar/t1/t2")))
  (is (= {:servers "foo,bar" :topic1 "t1" :topic2 "t2" :extra-pairs {"a" "b" "c" "d"}}
         (parse-kafka-spec "foo,bar/t1/t2?a=b&c=d"))))

(deftest test-parse-opts!
  (let [exit    (atom nil)
        message (atom nil)
        parse!  (fn [args]
                  (reset! exit nil)
                  (reset! message nil)
                  (core/parse-opts! args))]
    (with-redefs [core/print-usage!
                  (fn
                    ([status]
                     (core/print-usage! status nil))
                    ([status error]
                     (reset! exit status)
                     (reset! message error)))]
      (testing "Basic options"
        (parse! ["--help"])
        (is (= 0 @exit))
        (is (= nil @message))

        (parse! ["--kakao"])
        (is (= 1 @exit))
        (is (= "Unknown option: \"--kakao\"" @message))

        (parse! ["-i" "eth0" "file1" "file2"])
        (is (= 1 @exit))
        (is (= nil @message)))

      (testing "Non-interactive mode is allowed if any of --kafka, --duration,
               and --count are specified"
        (with-redefs [core/tty? true] (parse! [])
                     (is (nil? @exit))
                     (is (nil? @message)))

        (with-redefs [core/tty? false]
          (parse! [])
          (is (= 1 @exit))
          (is (= "Cannot load data into in-memory database indefinitely" @message)))

        (with-redefs [core/tty? false]
          (doseq [option ["--kafka=host/topic" "--count=10" "--duration=10"]]
            (parse! [option])
            (is (nil? @exit))))))))

(deftest test-unable-to-select-nif
  (is (thrown-with-msg?
       IllegalArgumentException
       #"Use --interface"
       (with-redefs [core/tty? false]
         (core/select-nif)))))

(deftest test-state
  (testing "expected-memory-usage"
    (is (= 0 (core/expected-memory-usage [:a {}])))
    (is (= 100 (core/expected-memory-usage [:a {:remains 100}])))
    (let [baos (ByteArrayOutputStream.)]
      (ByteStreams/copy (ByteArrayInputStream. (byte-array 200)) baos)
      (is (= (+ 100 200) (core/expected-memory-usage [:a {:remains 100 :out baos}])))))

  (testing "trim-state-by-memory"
    (is (= #{1 2 3}
           (set (keys (with-redefs [core/max-memory (constantly 140)]
                        (core/trim-state-by-memory
                         {1 {:remains 10}
                          2 {:remains 20}
                          3 {:remains 30}
                          4 {:remains 40}})))))))

  (testing "trim-state; first by the expiration date, then by the memory limit"
    (is (= #{2 3}
           (set (keys (with-redefs [core/max-memory (constantly 140)]
                        (core/trim-state {1 {:remains 10 :ts (java.sql.Timestamp. 0)}
                                          2 {:remains 20 :ts (java.sql.Timestamp. 20)}
                                          3 {:remains 30 :ts (java.sql.Timestamp. 20)}
                                          4 {:remains 40 :ts (java.sql.Timestamp. 20)}}
                                         (java.sql.Timestamp.
                                          (+ 10 core/state-expiration-ms))))))))))

;;; Fixture files are generated in pseudo-distributed mode, where the port
;;; numbers of regionservers are automatically assigned from 16201.
(defn read-fixture
  [file-name & [options]]
  (let [result (atom [])]
    (core/read-pcap-file
     (.getPath (io/resource (str (name file-name) ".pcap")))
     #(swap! result conj %) (merge {:port 16201} options))
    @result))

(comment
  (doseq [info (read-fixture :checkAndMutate)
          :when (= test-table (:table info))]
    (println info)))

(def test-table "TestTable")
(def record-count 100)
(def record-size 1000)
(def batch-get-size 20)
(def caching-size 20)

(deftest test-read-pcap-file
  (testing "sequentialWrite"
    (let [infos (read-fixture :sequentialWrite)
          multi (first (filter (every-pred :inbound? #(-> % :method (= :multi))) infos))
          multi-call-id (:call-id multi)
          {:keys [table batch size actions]} multi]
      (is (= test-table table))
      (is (> size (* record-size record-count)))
      (is (= record-count batch))
      (doseq [action actions
              :let [{:keys [method call-id cells]} action]]
        (is (= :put method))
        (is (= multi-call-id call-id))
        (is (= 1 cells)))))

  (testing "randomRead"
    (let [infos (read-fixture :randomRead)
          multis (filter (every-pred (complement :inbound?)
                                     #(-> % :method (= :multi))) infos)]
      (is (= (quot record-count batch-get-size) (count multis)))
      (doseq [multi multis
              :let [{:keys [method size batch results cells]} multi]]
        (is (= :multi method))
        (is (= batch-get-size batch))
        (is (= batch-get-size cells))
        (is (= batch-get-size (count results)))
        (is (> size (* record-size batch)))
        (doseq [result results
                :let [{:keys [method row region table cells]} result]]
          (is (= :get method))
          (is (= 1 cells))
          (is (every? identity [row region table]))))))

  (testing "scan"
    (let [infos (read-fixture :scan)
          nexts (filter (every-pred (complement :inbound?)
                                    #(-> % :table (= test-table))
                                    #(-> % :method (= :next-rows))) infos)]
      (is (= (quot record-count caching-size) (count nexts)))
      (apply = (map :scanner nexts))
      (doseq [next nexts
              :let [{:keys [size cells]} next]]
        (is (> size (* record-size caching-size)))
        (is (= caching-size cells)))))

  (testing "Multi-message packets"
    (let [infos (read-fixture :deferredFlush)]
      (is (= 2000 (count (filter #(-> % :method (= :increment)) infos))))))

  (testing "Small-scan"
    (let [infos (read-fixture :smallScan)]
      (is (= 200
             (->> infos
                  (filter #(-> % ((juxt :table :method)) (= ["t" :small-scan])))
                  (remove :inbound?)
                  (map :cells)
                  (reduce +))))))

  (testing "CAS"
    (doseq [[file method] {:increment      :increment
                           :append         :append
                           :checkAndPut    :check-and-put
                           :checkAndMutate :check-and-put
                           :checkAndDelete :check-and-delete}]
      (let [infos (read-fixture file)
            grouped (group-by (juxt :method :inbound?) infos)
            grouped (into {} (for [[group vals] grouped]
                               [group (count vals)]))]
        (is (= record-count (grouped [method true])))
        (is (= record-count (grouped [method false])))))))

(let [all-count (count (read-fixture :increment))]
  (deftest read-pcap-file-with-options
    (testing "Port"
      (is (zero? (count (read-fixture :increment {:port 100})))))

    (testing "Count"
      (is (> 100 (count (read-fixture :increment {:count 100})))))

    ;; Note that these assertions may not hold if fixtures are regenerated
    (testing "Duration"
      (is (> all-count
             (count (read-fixture :increment {:duration 0.1}))))
      (is (> (count (read-fixture :increment {:duration 0.1}))
             (count (read-fixture :increment {:duration 0.01})))))

    (testing "Verbose"
      (let [observed (atom 0)]
        (with-redefs [core/report-interval {:count 1 :ms 2000}
                      log/log* (fn [& _] (swap! observed inc))]
          (read-fixture :increment {:verbose true})
          ;; 2 logs for each entry + completion log
          (is (> @observed (+ (* 2 all-count) 1)))))))

  (deftest test-with-kafka*
    (let [history (atom [])]
      (with-redefs [kafka/create-sender (fn [_servers] (kt/->TestSender history))]
        (core/with-kafka*
          "servers/topic1/topic2"
          (fn [sink]
            (doseq [info (read-fixture :increment)]
              (sink info)))))
      (is (= (inc all-count) (count @history)))
      (is (= :close (last @history))))))
