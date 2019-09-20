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

grep -q WIRESHARK_RUN_FROM_BUILD_DIRECTORY ~/.profile || echo "export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1" >> ~/.profile
grep -q WIRESHARK_BIN_DIR ~/.profile || echo "export WIRESHARK_BIN_DIR=~/build/run" >> ~/.profile
mkdir -p build
cd build
cmake -DENABLE_CCACHE=ON ../wireshark
make -j4
make test-programs
make test
