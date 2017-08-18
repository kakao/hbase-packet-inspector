(ns hbase-packet-inspector.pcap-test
  (:require [clojure.test :refer :all]
            [hbase-packet-inspector.pcap :as pcap :refer :all])
  (:import (java.net InetAddress)
           (org.pcap4j.packet AbstractPacket IpV4Packet$Builder IpV4Rfc1349Tos
                              TcpPacket$Builder UnknownPacket$Builder)
           (org.pcap4j.packet.namednumber IpNumber IpVersion TcpPort)))

(deftest test-packet->map
  (let [src-addr "0.0.0.0"
        dst-addr "0.0.0.1"
        src-port 12345
        dst-port 16020
        data "foobar"
        ipv4-packet (.. (IpV4Packet$Builder.)
                        (srcAddr (InetAddress/getByName src-addr))
                        (dstAddr (InetAddress/getByName dst-addr))
                        (protocol (IpNumber/TCP))
                        (version (IpVersion/IPV4))
                        (tos (IpV4Rfc1349Tos/newInstance 0))
                        build)
        unknown-builder (.. (UnknownPacket$Builder.)
                            (rawData (into-array Byte/TYPE (seq data))))
        tcp-packet (.. (TcpPacket$Builder.)
                       (srcPort (TcpPort/getInstance (short src-port)))
                       (dstPort (TcpPort/getInstance (short dst-port)))
                       (payloadBuilder unknown-builder)
                       build)
        packet (proxy [AbstractPacket] []
                 (iterator [] (.iterator [ipv4-packet tcp-packet])))
        packet-map (packet->map packet)]
    (is (= src-addr (get-in packet-map [:src :addr])))
    (is (= dst-addr (get-in packet-map [:dst :addr])))
    (is (= src-port (get-in packet-map [:src :port])))
    (is (= dst-port (get-in packet-map [:dst :port])))
    (is (= (count data) (:length packet-map)))
    (is (= data (apply str (map char (:data packet-map)))))))

(deftest test-packet->map-may-return-nil
  (let [empty-packet (proxy [AbstractPacket] []
                       (iterator [] (.iterator [])))]
    (is (= nil (packet->map empty-packet)))))

(deftest test-parse-next-packet
  (with-redefs [get-next-packet (constantly nil)]
    (is (= ::pcap/interrupt (parse-next-packet nil))))
  (with-redefs [get-next-packet #(throw (InterruptedException. %))]
    (is (= ::pcap/interrupt (parse-next-packet "interrupted"))))
  (with-redefs [get-next-packet (constantly :foo)
                packet->map (constantly nil)]
    (is (= ::pcap/ignore (parse-next-packet nil))))
  (with-redefs [get-next-packet (constantly :foo)
                packet->map (constantly :bar)]
    (is (= :bar (parse-next-packet nil)))))
