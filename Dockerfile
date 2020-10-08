FROM ubuntu:latest

RUN apt update

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -y install tzdata

RUN apt install -y build-essential cmake ninja-build libpcap-dev libglib2.0-dev libgcrypt20-dev libc-ares-dev bison flex liblz4-dev libsmi2-dev libgnutls28-dev libminizip-dev libbrotli-dev libsnappy-dev libzstd-dev libnghttp2-dev lua5.1 luajit libspandsp-dev libxml2-dev liblua5.1-dev libluajit-5.1-dev libkrb5-dev python3-pip python3-setuptools

COPY . /marine

WORKDIR /marine

RUN mkdir -p build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr -GNinja ..

RUN ninja -C build marine

RUN cd build && ninja install
