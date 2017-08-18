(ns hbase-packet-inspector.sink.db
  (:require [clojure.java.jdbc :as jdbc]
            [clojure.string :as str]
            [clojure.tools.logging :as log])
  (:import (java.sql Connection PreparedStatement Statement)
           (org.h2.server.web WebServer)
           (org.h2.tools Server Shell)))

(def schema
  "Database schema"
  (let [schema {:requests [[:ts         "timestamp"]
                           [:client     "varchar"]
                           [:port       "int"]
                           [:call_id    "int"]
                           [:server     "varchar"]
                           [:type       "varchar"]
                           [:size       "int"]
                           [:batch      "int"]
                           [:table      "varchar"]
                           [:region     "varchar"]
                           [:row        "varchar"]
                           [:stoprow    "varchar"]
                           [:cells      "int"]
                           [:durability "varchar"]]
                :actions  [[:client     "varchar"]
                           [:port       "int"]
                           [:call_id    "int"]
                           [:type       "varchar"]
                           [:table      "varchar"]
                           [:region     "varchar"]
                           [:row        "varchar"]
                           [:cells      "int"]
                           [:durability "varchar"]]}]
    (assoc schema
           :responses
           (conj (:requests schema) [:error "varchar"] [:elapsed "int"])
           :results
           (conj (:actions schema)  [:error "varchar"]))))

(defn connect
  "Connects to the in-memory database"
  ^Connection []
  (jdbc/get-connection
   {:classname   "org.h2.Driver"
    :subprotocol "h2:mem"
    :subname     "hbase;DB_CLOSE_DELAY=-1;LOG=0;UNDO_LOG=0;LOCK_MODE=0"}))

(defn execute!
  "Executes SQL with the database"
  [^Connection connection sql]
  (with-open [^Statement stmt (-> connection .createStatement)]
    (.execute stmt sql)))

(let [fields (into {} (for [[table specs] schema]
                        [table (mapv #(-> % first name
                                          (str/replace "_" "-")
                                          (str/replace "type" "method")
                                          keyword) specs)]))
      fields-with-index (into {} (for [[table columns] fields]
                                   [table (map vector (iterate inc 1) columns)]))]
  (defn create
    "Recreates database tables"
    [^Connection connection]
    (doseq [[table spec] schema :let [table (name table)]]
      (execute! connection (str "drop table if exists " table))
      (execute! connection (jdbc/create-table-ddl table spec))
      (execute! connection (format "create index %s_idx on %s (client, port, call_id)"
                                   table table))))

  (defn prepared-insert-fn
    "Returns function for inserting records into in-memory database tables
    using prepared statements"
    [^Connection connection]
    (let [pstmts (into {} (for [[table columns] fields]
                            [table
                             (jdbc/prepare-statement
                              connection
                              (format "insert into %s values(%s)"
                                      (name table)
                                      (str/join ", " (repeat (count columns) "?"))))]))]
      (fn [table values]
        (let [pstmt ^PreparedStatement (pstmts table)]
          (doseq [[idx col] (fields-with-index table)
                  :let [val (col values)]]
            (cond
              (nil? val)     (.setNull   pstmt idx java.sql.Types/NULL)
              (keyword? val) (.setObject pstmt idx (name val))
              :else          (.setObject pstmt idx val)))
          (.execute pstmt))))))

(defn sink-fn
  [^Connection connection]
  (let [inserter (prepared-insert-fn connection)]
    (fn [values]
      {:pre [(contains? values :inbound?)]}
      (let [table   (if (:inbound? values) :requests :responses)
            actions (:actions values)
            results (:results values)]
        (inserter table (dissoc values :actions :results))
        (doseq [action actions] (inserter :actions action))
        (doseq [result results] (inserter :results result))))))

(defn start-shell
  "Starts interactive command-line SQL client"
  [^Connection connection]
  (.runTool (Shell.) connection (make-array String 0)))

(defn start-web-server
  "Starts web server for h2 database"
  [^Connection connection]
  (let [ws (WebServer.)
        s  (doto (Server. ws (into-array String ["-webPort" "0" "-webAllowOthers"]))
             .start)
        url (.addSession ws connection)]
    {:server s :url url}))
