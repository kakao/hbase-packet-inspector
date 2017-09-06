#!/bin/bash
# docker run -v $(PWD)/test/fixtures:/data -p 16010:16010 -it hpi-test-env

set -e

service ssh restart

cd hbase-1.2.6

cat > conf/hbase-site.xml << EOF
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="configuration.xsl"?>
<configuration>
  <property>
    <name>hbase.cluster.distributed</name>
    <value>true</value>
  </property>
  <property>
    <name>hbase.zookeeper.quorum</name>
    <value>$(hostname --ip-address)</value>
  </property>
</configuration>
EOF

mkdir -p ~/.ssh
echo 'StrictHostKeyChecking no' > ~/.ssh/config
ssh-keygen -f ~/.ssh/id_rsa -N ''
cat ~/.ssh/id_rsa.pub > ~/.ssh/authorized_keys
echo 'export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64' >> ~/.bashrc

bin/start-hbase.sh

dump() {
  nohup tcpdump -s 0 -i lo -U -w "/data/$1.pcap" port 16201 > /dev/null 2>&1 &
  echo $! > tcpdump.pid
  sleep 2
  case "$1" in
    sequentialWrite)
      bin/hbase pe --nomapred --rows=100 --valueSize=1000 sequentialWrite 1
      ;;
    randomRead)
      bin/hbase pe --nomapred --rows=100 --multiGet=20 randomRead 1
      ;;
    scan)
      bin/hbase pe --nomapred --rows=100 --caching=20 scan 1
      ;;
    increment)
      bin/hbase pe --nomapred --rows=100 increment 1
      ;;
    append)
      bin/hbase pe --nomapred --rows=100 append 1
      ;;
    checkAndPut)
      bin/hbase pe --nomapred --rows=100 checkAndPut 1
      ;;
    checkAndMutate)
      bin/hbase pe --nomapred --rows=100 checkAndMutate 1
      ;;
    checkAndDelete)
      bin/hbase pe --nomapred --rows=100 checkAndDelete 1
      ;;
    deferredFlush)
      echo "create 't', 'd' unless list.include?('t')" | bin/hbase shell
      java -jar /data/load-generator/target/uberjar/load-generator-0.1.0-SNAPSHOT-standalone.jar asynchbase
      ;;
    smallScan)
      echo "create 't', 'd' unless list.include?('t')" | bin/hbase shell
      java -jar /data/load-generator/target/uberjar/load-generator-0.1.0-SNAPSHOT-standalone.jar small-scan
      ;;
  esac
  sleep 2
  kill -2 "$(cat tcpdump.pid)"
}

dump sequentialWrite
dump randomRead
dump scan
dump increment
dump append
dump checkAndPut
dump checkAndMutate
dump checkAndDelete
dump deferredFlush
dump smallScan
