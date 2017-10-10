Name:		hbase-packet-inspector
Version:	0.2.0
Release:	1%{?dist}
Summary:	hbase-packet-inspector monitors HBase packets

Group:		Development/Tools
License:	Apache 2
URL:		https://github.com/kakao/hbase-packet-inspector
Source0:	%{name}-%{version}.tar.gz

Requires:	libpcap >= 1.4.0

%define __jar_repack 0

%description
hbase-packet-inspector is a command-line tool for analyzing network traffic of
HBase RegionServers.


%prep
# Without -n, it expects %{name}-%{version} after extracting the tarball

%setup -q -n %{name}

%build
# Nothing to do


%install
install -m 0755 -d %{buildroot}/etc/init.d
install -m 0755 -d %{buildroot}/usr/lib/%{name}
install -m 0755 -d %{buildroot}/usr/lib/%{name}/lib
install -m 0755 -d %{buildroot}/usr/lib/%{name}/conf
install -m 0755 lib/%{name}.jar %{buildroot}/usr/lib/%{name}/lib/%{name}.jar
install -m 0755 init.d/%{name} %{buildroot}/etc/init.d/%{name}
install -m 0644 conf/log4j.properties %{buildroot}/usr/lib/%{name}/conf/log4j.properties
install -m 0644 conf/%{name}.properties %{buildroot}/usr/lib/%{name}/conf/%{name}.properties


%files
/etc/init.d/hbase-packet-inspector
%dir /usr/lib/%{name}
%dir /usr/lib/%{name}/lib
/usr/lib/%{name}/lib/%{name}.jar
%dir /usr/lib/%{name}/conf
/usr/lib/%{name}/conf/log4j.properties
/usr/lib/%{name}/conf/%{name}.properties
