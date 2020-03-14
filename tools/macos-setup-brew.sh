#!/bin/sh
# Copyright 2014, Evan Huus (See AUTHORS file)
#
# Enhance (2016) by Alexis La Goutte (For use with Travis CI)
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Update to last brew release
brew update

# install some libs needed by Wireshark
brew install c-ares glib libgcrypt gnutls lua@5.1 cmake python nghttp2 snappy lz4 libxml2 ninja libmaxminddb \
	libsmi spandsp brotli minizip zstd libssh libilbc speexdsp gettext qt5 "$@"

# Uncomment to enable automatic updates using Sparkle
# brew cask install sparkle

exit 0
#
#  Editor modelines
#
#  Local Variables:
#  c-basic-offset: 4
#  tab-width: 8
#  indent-tabs-mode: nil
#  End:
#
#  ex: set shiftwidth=4 tabstop=8 expandtab:
#  :indentSize=4:tabSize=8:noTabs=true:
#
