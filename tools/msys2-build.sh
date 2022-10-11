#!/bin/bash
# Build script for MSYS2
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

mkdir build
cd build

cmake -G Ninja -DENABLE_WERROR=No .. || exit 1

ninja || exit 1

ninja test-programs || exit 1

pytest
