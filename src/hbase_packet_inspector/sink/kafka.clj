(ns hbase-packet-inspector.sink.kafka
  (:require [cheshire.core :as json])
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

(definterface ISender
  (send  [record])
  (close []))

(deftype KafkaSender [^KafkaProducer producer]
  ISender
  (send [this record] (.send producer record))
  (close [this]
    (.flush producer)
    (.close producer)))

(defn create-sender
  "Creates ISender based on Kafka Producer"
  ^ISender [bootstrap-servers]
  (KafkaSender.
   (KafkaProducer.
    (map->props (producer-config bootstrap-servers)))))

(defn hostname
  "Returns the host name"
  []
  (.. java.net.InetAddress getLocalHost getHostName))

(defn make-record
  "Makes ProducerRecord to send"
  ^ProducerRecord [topic record]
  (ProducerRecord. topic (json/generate-string record)))

(defn send-fn
  "Returns send function for sending formatted record to the specified sender"
  [^ISender sender extra-pairs]
  (fn [topic record]
    (let [ts     (.getTime ^java.sql.Timestamp (:ts record))
          record (merge (assoc record :ts ts) extra-pairs)]
      (.send sender (make-record topic record)))))

(defn send-and-close-fn
  "Returns two functions; one for sending records to Kafka as json format
  records, and another for closing the Kafka producer."
  [bootstrap-servers topic1 topic2 & [extra-pairs]]
  (let [sender     (create-sender bootstrap-servers)
        send       (send-fn sender (merge {:hostname (hostname)} extra-pairs))]
    [(fn [record]
       {:pre [(contains? record :inbound?)
              (contains? record :ts)]}
       (let [topic (if (:inbound? record) topic1 topic2)]
         (when (seq topic)
           (send topic record))))
     (fn []
       (.close sender))]))
