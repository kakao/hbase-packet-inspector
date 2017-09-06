(ns load-generator.core
  (:import
   org.apache.hadoop.hbase.TableName
   [org.apache.hadoop.hbase.client ConnectionFactory Connection Put Scan]
   [org.hbase.async HBaseClient AtomicIncrementRequest])
  (:gen-class))

(def ^String table-name "t")
(def ^String cf "d")

(defn asynchbase-batch-increment
  []
  (let [async (HBaseClient. "localhost")]
    (.setFlushInterval async 100)
    (doseq [f (doall
               (for [_ (range 10)]
                 (future
                   (dotimes [i 100]
                     (.atomicIncrement
                      async
                      (AtomicIncrementRequest. table-name (str i) cf "foo" 1))))))]
      (deref f))
    (.. async shutdown join)))

(defn small-scan
  []
  (with-open [connection (ConnectionFactory/createConnection)
              table      (.getTable connection (TableName/valueOf table-name))]
    (dotimes [i 100]
      (let [cf    (.getBytes cf)
            value (.getBytes "value")
            put   (.. (Put. (.getBytes (str i)))
                      (addColumn cf (.getBytes "foo") value)
                      (addColumn cf (.getBytes "bar") value))]
        (.put table put)))
    (with-open [scanner (.getScanner table (.. (Scan.) (setSmall true)))]
      (doseq [_ (seq scanner)]))))

(defn -main
  [& args]
  (case (first args)
    "asynchbase"
    (asynchbase-batch-increment)

    "small-scan"
    (small-scan)))
