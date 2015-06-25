#!/bin/bash
set -e

apt-get update
apt-get build-dep -y wireshark
apt-get install -y cmake valgrind qt5-default \
    libqt5multimedia5 libqt5multimediawidgets5 qtmultimedia5-dev \
    qttools5-dev qttools5-dev-tools
