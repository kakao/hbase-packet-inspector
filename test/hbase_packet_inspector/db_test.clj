(ns hbase-packet-inspector.db-test
  (:require [clojure.test :refer :all]
            [clojure.string :as str]
            [clojure.java.jdbc :as jdbc]
            [hbase-packet-inspector.sink.db :as db]))

(deftest test-db-connection
  (let [connection (db/connect)
        tables [:requests :actions :responses :results]
        q (fn [sql] (jdbc/query {:connection connection} sql))]
    (is (instance? java.sql.Connection connection))
    (is (re-find #"h2:mem" (str connection)))

    (db/create connection)
    (is (= (set tables)
           (set (map (comp keyword str/lower-case :table_name)
                     (q "show tables")))))
    (doseq [table tables]
      (is (empty? (q (str "select * from " (name table))))))

    (let [sink (db/sink-fn connection)]
      (sink {:client :foo
             :port 1000
             :row nil
             :inbound? true
             :actions [{:client :bar} {:client :baz}]})
      (sink {:client :FOO
             :port 2000
             :row "row"
             :inbound? false
             :results [{:client :BAR} {:client :BAZ}]})
      (is (thrown? AssertionError (sink {:client :foo}))))

    (let [rows (into {} (for [table tables]
                          [table (q (str "select * from " (name table)))]))]
      (is (= #{"foo"}       (set (map :client (:requests rows)))))
      (is (= #{1000}        (set (map :port (:requests rows)))))
      (is (= #{nil}         (set (map :row (:requests rows)))))
      (is (= #{"bar" "baz"} (set (map :client (:actions rows)))))
      (is (= #{"FOO"}       (set (map :client (:responses rows)))))
      (is (= #{2000}        (set (map :port (:responses rows)))))
      (is (= #{"row"}       (set (map :row (:responses rows)))))
      (is (= #{"BAR" "BAZ"} (set (map :client (:results rows))))))))
