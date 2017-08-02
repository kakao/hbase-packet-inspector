(ns hbase-packet-inspector.sink.kafka
  (:require [cheshire.core :as json]
            [grouper.core :as grouper])
  (:import (java.util Properties)
           (org.apache.kafka.clients.producer KafkaProducer ProducerConfig
                                              ProducerRecord)))

(defn producer-config
  "Returns map describing producer config"
  [bootstrap-servers]
  {ProducerConfig/BOOTSTRAP_SERVERS_CONFIG
   bootstrap-servers
   ProducerConfig/COMPRESSION_TYPE_CONFIG
   "gzip"
   ProducerConfig/KEY_SERIALIZER_CLASS_CONFIG
   "org.apache.kafka.common.serialization.StringSerializer"
   ProducerConfig/VALUE_SERIALIZER_CLASS_CONFIG
   "org.apache.kafka.common.serialization.StringSerializer"})

(defn map->props
  "Creates Properties from Clojure map"
  ^Properties [opts]
  (let [props (Properties.)]
    (doseq [[k v] opts]
      (.setProperty props k (str v)))
    props))

(defn create-producer
  "Creates a new Producer"
  ^KafkaProducer [bootstrap-servers]
  (KafkaProducer.
   (map->props (producer-config bootstrap-servers))))

(defn make-record
  "Makes ProducerRecord to send"
  ^ProducerRecord [topic record]
  (ProducerRecord.
   topic
   (json/generate-string record)))

(defn send-and-close-fn
  "Returns two functions; one for sending records to Kafka as flat json format
  records, and another for closing the batch pool and Kafka producer."
  [bootstrap-servers topic & [extra-pairs]]
  (let [producer   (create-producer bootstrap-servers)
        hostname   (.. java.net.InetAddress getLocalHost getHostName)
        batch-pool (grouper/start!
                    (fn [items]
                      (doseq [item items]
                        (.send producer
                               (make-record
                                topic
                                (merge (assoc item
                                              :hostname hostname
                                              :ts (.getTime ^java.sql.Timestamp (:ts item)))
                                       extra-pairs)))))
                    :capacity 1000
                    :interval 200
                    :pool 2)]
    [(fn [table record]
       (when (= table :responses)
         (grouper/submit! batch-pool record)))
     (fn []
       (.close batch-pool)
       (.flush producer)
       (.close producer))]))
