(ns asynchbase-client.core
  (:import [org.hbase.async HBaseClient
                            AtomicIncrementRequest])
  (:gen-class))

(defn -main
  [& args]
  (let [async (HBaseClient. "localhost")]
    (.setFlushInterval async 100)
    (doseq [f (doall
                (for [_ (range 10)]
                  (future
                    (dotimes [i 100]
                      (.atomicIncrement
                        async
                        (AtomicIncrementRequest. "t" (str i) "d" "foo" 1))))))]
      (deref f))
    (.. async shutdown join)))
