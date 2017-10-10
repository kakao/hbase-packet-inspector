NAME := hbase-packet-inspector
VERSION := 0.2.0
UBERJAR := target/$(NAME)-$(VERSION).jar

RPM6 := rpmbuild/RPMS/x86_64/$(NAME)-$(VERSION)-1.el6.x86_64.rpm
RPM7 := rpmbuild/RPMS/x86_64/$(NAME)-$(VERSION)-1.el7.centos.x86_64.rpm

TARBALL := rpmbuild/SOURCES/$(NAME)-$(VERSION).tar.gz

build: $(UBERJAR)

$(UBERJAR): $(shell find src/ -name "*.clj")
	lein uberjar

$(TARBALL): $(UBERJAR)
	mkdir -p rpmbuild/{BUILD,BUILDROOT,RPMS,SRPMS}
	mkdir -p rpmbuild/SOURCES/$(NAME)/lib
	cp -f $(UBERJAR) rpmbuild/SOURCES/$(NAME)/lib/$(NAME).jar
	cd rpmbuild/SOURCES && tar -cvzf $(NAME)-$(VERSION).tar.gz $(NAME)

$(RPM6): $(TARBALL)
	make centos6
	docker run -v $(CURDIR)/rpmbuild:/root/rpmbuild -t hpi-centos6 rpmbuild -ba rpmbuild/SPECS/hbase-packet-inspector.spec

$(RPM7): $(TARBALL)
	make centos7
	docker run -v $(CURDIR)/rpmbuild:/root/rpmbuild -t hpi-centos7 rpmbuild -ba rpmbuild/SPECS/hbase-packet-inspector.spec

rpm6: $(RPM6)
rpm7: $(RPM7)
rpm: $(RPM6) $(RPM7)

yum:
	rm -rf yum
	mkdir -p yum/{6,7}
	cp -f rpmbuild/RPMS/x86_64/hbase-packet-inspector-0.2.0-1.el6.x86_64.rpm yum/6
	cp -f rpmbuild/RPMS/x86_64/hbase-packet-inspector-0.2.0-1.el7.centos.x86_64.rpm yum/7
	docker run -v $(CURDIR)/rpmbuild:/root/rpmbuild -v $(CURDIR)/yum:/root/yum -it hpi-centos6 createrepo /root/yum/6
	docker run -v $(CURDIR)/rpmbuild:/root/rpmbuild -v $(CURDIR)/yum:/root/yum -it hpi-centos7 createrepo /root/yum/7

yum-server:
	cd yum && python -m SimpleHTTPServer 8080

%: Dockerfile.%
	docker build -t hpi-$@ - < Dockerfile.$@
	# docker run -v $(CURDIR)/rpmbuild:/root/rpmbuild -it hpi-$@

clean:
	rm -rf rpmbuild/{BUILD,BUILDROOT,RPMS,SRPMS} \
		rpmbuild/SOURCES/$(NAME)-$(VERSION).tar.gz \
		rpmbuild/SOURCES/$(NAME)/lib yum

.PHONY: all build rpm rpm6 rpm7 yum yum-server clean
