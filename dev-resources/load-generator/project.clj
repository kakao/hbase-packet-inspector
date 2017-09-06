(defproject load-generator "0.1.0-SNAPSHOT"
  :dependencies [[org.clojure/clojure           "1.8.0"]
                 [io.netty/netty                "3.9.4.Final"]
                 [org.apache.hbase/hbase-client "1.2.3"]
                 [org.slf4j/slf4j-api           "1.7.21"]
                 [org.slf4j/slf4j-log4j12       "1.7.21"]
                 [org.hbase/asynchbase          "1.7.2"
                  :exclusions [org.jboss.netty/netty
                               org.slf4j/slf4j-api
                               org.slf4j/log4j-over-slf4j]]]
  :main ^:skip-aot load-generator.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
