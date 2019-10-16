#!/bin/sh
#
# Compare ABIs of two Wireshark working copies
#
# Copyright 2017 Balint Reczey <balint.reczey@canonical.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Set shared library package names and library versions in Debian packaging
# matching the new major release's so versions

set -e

for i in codecs wireshark wiretap wsutil; do
    NEW_VERSION=$(grep SOVERSION "$(grep -l lib${i} ./*/CMakeLists.txt)" | sed 's/.*SOVERSION \([0-9]*\).*/\1/')
    rename "s/0\\./${NEW_VERSION}./" debian/lib${i}0.*
    grep -l -R "lib${i}0" debian/ | xargs sed -i "s/lib${i}0/lib${i}${NEW_VERSION}/"
    grep -l -R "lib${i}\\.so\\.0" debian/ | xargs sed -i "s/lib${i}\\.so\\.0/lib${i}.so.${NEW_VERSION}/"
done
