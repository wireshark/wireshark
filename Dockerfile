FROM quay.io/pypa/manylinux2014_x86_64

RUN yum install -y epel-release centos-release-scl

COPY redhat/rpms.txt /tmp/

RUN xargs --arg-file /tmp/rpms.txt yum install -y && yum clean all && rm -rf /var/yum/cache

ENV CC=/opt/rh/devtoolset-9/root/usr/bin/gcc

COPY . /marine

WORKDIR /build

RUN cmake3 -DCMAKE_INSTALL_PREFIX=/usr -GNinja /marine && ninja marine
