#!/bin/bash
set -e
docker build -t marine-build:centos7 .
mkdir -p build
docker run -i --rm -v $(pwd)/build:/build -v $(pwd)/..:/marine marine-build:centos7
