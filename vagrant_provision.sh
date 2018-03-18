#!/bin/bash
#
# Copyright 2015 Evan Huus <eapache@gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

set -e

apt-get update
apt-get build-dep -y wireshark
apt-get install -y git cmake valgrind qt5-default \
    libqt5multimedia5 qtmultimedia5-dev \
    libqt5svg5-dev qttools5-dev qttools5-dev-tools
