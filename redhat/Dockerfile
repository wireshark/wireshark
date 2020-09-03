FROM centos:7

RUN yum install -y epel-release centos-release-scl

COPY ./rpms.txt /tmp/

RUN xargs --arg-file /tmp/rpms.txt yum install -y

ENV CC=/opt/rh/devtoolset-9/root/usr/bin/gcc

RUN git config --global user.name "Tom Legkov" && git config --global user.email "tom.legkov@outlook.com"

WORKDIR /build

VOLUME /build

VOLUME /marine

ENV PREFIX=/usr

CMD cmake3 -GNinja /marine && ninja marine && ninja rpm-package
