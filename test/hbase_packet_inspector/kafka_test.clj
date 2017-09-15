(ns hbase-packet-inspector.kafka-test
  (:require [clojure.test :refer :all]
            [clojure.string :as str]
            [cheshire.core :as json]
            [hbase-packet-inspector.sink.kafka :as kafka])
  (:import org.apache.kafka.clients.producer.ProducerRecord
           org.apache.kafka.clients.producer.KafkaProducer))

(deftest test-producer-config
  (let [servers "foo,bar"
        props (kafka/map->props (kafka/producer-config servers))]
    (is (instance? java.util.Properties props))
    (is (= servers (.getProperty props "bootstrap.servers")))))

(deftest test-make-record
  (let [record (kafka/make-record "topic" {:foo :bar})]
    (is (instance? ProducerRecord record))
    (is (= "topic" (.topic record)))
    (is (= "{\"foo\":\"bar\"}" (.value record)))))

(deftype TestSender [history]
  hbase_packet_inspector.sink.kafka.ISender
  (send  [this record] (swap! history conj record))
  (close [this]        (swap! history conj :close)))

(deftest test-send-fn
  (let [history (atom [])
        sender  (TestSender. history)
        extra   {:foo :bar}
        send    (kafka/send-fn sender extra)
        topic   "t1"
        record  {:a :b :ts (java.sql.Timestamp. 100)}]
    (send topic record)
    (.close sender)
    (is (= 2 (count @history)))
    (is (= "t1" (.topic ^ProducerRecord (first @history))))
    (is (= "{\"a\":\"b\",\"ts\":100,\"foo\":\"bar\"}"
           (.value ^ProducerRecord (first @history))))
    (is (= :close (last @history)))))

(deftest test-send-and-close-fn
  (let [servers  (atom "my-servers")
        topic1   "t1"
        topic2   "t2"
        extra    {:foo :bar}
        hostname (kafka/hostname)
        history  (atom [])]
    (with-redefs [kafka/create-sender
                  (fn [s]
                    (swap! servers = s)
                    (TestSender. history))]
      (let [[send close] (kafka/send-and-close-fn @servers topic1 topic2 extra)]
        (is @servers)
        ;; :inbound? and :ts are required
        (is (thrown? AssertionError (send {:inbound? true})))
        (is (thrown? AssertionError (send {:ts 0})))
        (send {:inbound? true :ts (java.sql.Timestamp. 0)})
        (send {:inbound? false :ts (java.sql.Timestamp. 100)})
        (close)

        (let [[^ProducerRecord req
               ^ProducerRecord res] (take 2 @history)
              req-map (json/parse-string (.value req))
              res-map (json/parse-string (.value res))]
          (is (= "t1" (.topic req)))
          (is (= "t2" (.topic res)))
          (is (= 0 (req-map "ts")))
          (is (= 100 (res-map "ts")))
          (doseq [m [req-map res-map]]
            (is (= hostname (m "hostname")))
            (is (= "bar" (m "foo")))))
        (is (= :close (last @history)))
        (is (= 3 (count @history)))))))
