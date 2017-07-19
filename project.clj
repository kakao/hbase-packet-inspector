(defproject hbase-packet-inspector "0.2.0"
  :description "Analyzes HBase region server packets"
  :url "http://github.com/kakao"
  :license {:name "Apache License 2.0"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.clojure/core.match "0.3.0-alpha4"]
                 [org.clojure/tools.cli "0.3.5"]
                 [org.clojure/tools.logging "0.4.0"]
                 [org.clojure/java.jdbc "0.7.0"]
                 [org.slf4j/slf4j-api "1.7.25"]
                 [org.slf4j/slf4j-log4j12 "1.7.25"]
                 [org.apache.hbase/hbase-client "1.2.3"]
                 [org.pcap4j/pcap4j-core "1.6.6"]
                 [org.pcap4j/pcap4j-packetfactory-static "1.6.6"]
                 [com.google.guava/guava "19.0"]
                 [com.google.protobuf/protobuf-java "2.5.0"]
                 [com.h2database/h2 "1.4.196"]
                 [org.apache.kafka/kafka-clients "0.11.0.0"]
                 [cheshire "5.7.1"]
                 [junegunn/grouper "0.1.0"]]
  :plugins [[lein-bin "0.3.5"]]
  :bin {:bin-path "target"}
  :main hbase-packet-inspector.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
