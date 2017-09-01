(ns hbase-packet-inspector.pcap
  (:require [clojure.string :as str]
            [clojure.tools.logging :as log])
  (:import (java.util.concurrent TimeoutException)
           (org.pcap4j.core BpfProgram$BpfCompileMode PcapHandle
                            PcapHandle$Builder
                            PcapNetworkInterface$PromiscuousMode Pcaps)
           (org.pcap4j.packet IpV4Packet Packet TcpPacket)
           (org.pcap4j.util NifSelector)))

(defn select-interface
  "Interactive network interface selector. Returns nil if user enters 'q'."
  []
  (some-> (NifSelector.) .selectNetworkInterface .getName))

(defn live-handle
  "Opens PcapHandle for the interface. Requires root permission."
  ^PcapHandle [interface ports]
  (let [handle (.. (PcapHandle$Builder. interface)
                   (snaplen    (* 64 1024))
                   (bufferSize (* 128 1024 1024))
                   (promiscuousMode PcapNetworkInterface$PromiscuousMode/NONPROMISCUOUS)
                   (timeoutMillis 1000)
                   build)]
    (.setFilter handle
                (str/join " or " (map (partial format "port %d") ports))
                BpfProgram$BpfCompileMode/OPTIMIZE)
    handle))

(defn file-handle
  "Opens PcapHandle from the existing file or from STDIN if path is -"
  ^PcapHandle [path]
  (Pcaps/openOffline path))

(defn packet->map
  "Returns essential information parsed from the given packet as a map.
  Returns nil if necessary information is not found."
  [^Packet packet]
  (let [^IpV4Packet ipv4 (.get packet IpV4Packet)
        ^TcpPacket  tcp  (.get packet TcpPacket)
        data        (when tcp (.getPayload tcp))
        ipv4-header (when ipv4 (.getHeader ipv4))
        tcp-header  (when tcp (.getHeader tcp))]
    (when (every? some? [data ipv4-header tcp-header])
      {:src {:addr (.. ipv4-header getSrcAddr getHostAddress)
             :port (.. tcp-header  getSrcPort valueAsInt)}
       :dst {:addr (.. ipv4-header getDstAddr getHostAddress)
             :port (.. tcp-header  getDstPort valueAsInt)}
       :length (.. data length)
       :data   (.. data getRawData)})))

(defn get-next-packet
  "Retrieves the next packet from the handle. getNextPacketEx can throw
  TimeoutException if there is no new packet for the interface or when the
  packet is buffered by OS. This function retries in that case."
  [^PcapHandle handle]
  (loop []
    (let [result (try
                   (.getNextPacketEx handle)
                   (catch TimeoutException _
                     (Thread/sleep 100) ; needed for future-cancel
                     ::retry)
                   (catch java.io.EOFException _ nil))]
      (if (= result ::retry)
        (recur)
        result))))

(defn parse-next-packet
  "Retrieves the next packet from the handle and parses it using packet->map
  function. ::interrupt is returned if interrupted or the end of file handle is
  reached. ::ignore can be returned while reading a live handle."
  [^PcapHandle handle]
  (let [packet (try (get-next-packet handle)
                    (catch InterruptedException e
                      (log/warn (.getMessage e))
                      nil))
        packet-map (when packet (packet->map packet))]
    (cond
      (nil? packet) ::interrupt
      (nil? packet-map) ::ignore
      :else packet-map)))
