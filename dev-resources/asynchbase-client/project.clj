(defproject asynchbase-client "0.1.0-SNAPSHOT"
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [io.netty/netty "3.9.4.Final"]
                 [org.hbase/asynchbase "1.7.2" :exclusions [org.jboss.netty/netty]]]
  :main ^:skip-aot asynchbase-client.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
