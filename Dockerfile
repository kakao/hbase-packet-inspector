FROM openjdk:8
RUN apt-get update -y && apt-get install -y tcpdump net-tools openssh-server
ADD http://apache.mirror.cdnetworks.com/hbase/1.2.6/hbase-1.2.6-bin.tar.gz .
