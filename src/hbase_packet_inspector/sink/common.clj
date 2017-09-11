(ns hbase-packet-inspector.sink.common
  (:require [clojure.tools.logging :as log]
            [grouper.core :as grouper]))

(definterface IBatchPool
  (^void submit [item])
  (^void close []))

(deftype BatchPool [grouper]
  IBatchPool
  (submit [this item]
    (grouper/submit! grouper item))
  (close [this]
    (grouper/shutdown! grouper)))

(deftype NoPool [f]
  IBatchPool
  (submit [this item]
    (f item))
  (close [this]))

(defn num-cores
  "Returns the number of system cores"
  []
  (.. Runtime getRuntime availableProcessors))

(defn create-batch-pool
  "Creates a thread pool for asynchronous processing depending on the number of
  system cores. The number of threads does not exceed either 2 or 25% of the
  total number of cores. If the system has less than 4 cores, an instance of
  NoPool is returned which simply executes the function with the given item,
  instead of passing it to another thread."
  ^IBatchPool [f]
  ;; Do not occupy more than 25% of the total cores
  (let [threads (min (quot (num-cores) 4) 2)]
    (if (zero? threads)
      (NoPool. f)
      (let [grouper (grouper/start!
                     #(try (doseq [item %] (f item))
                           (catch Exception e (log/error e)))
                     :capacity 1000
                     :interval 200
                     :pool threads)]
        (log/infof "Allocated %d extra thread(s)" threads)
        (BatchPool. grouper)))))
