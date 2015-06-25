#!/bin/bash
set -e

mkdir -p build
cd build
cmake /wireshark/
make -j2
