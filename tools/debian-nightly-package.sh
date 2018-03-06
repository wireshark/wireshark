#!/bin/bash
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

set -e

if test -z $1; then
    echo "Usage:"
    echo " $0 <distribution>"
    echo " e.g: $0 xenial"
    exit 1
fi

DIST=$1
VERSION=$(git describe --tags | sed 's/v//;s/-/~/g;s/rc/~rc/')
rm debian/changelog || true
EDITOR=touch dch -p --package wireshark --create --force-distribution -v${VERSION}~${DIST}1 -D $DIST
sed -i 's/\* Initial release.*/* Nightly build for '${DIST^}'/' debian/changelog
dpkg-buildpackage -S -d
