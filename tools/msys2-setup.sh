#!/bin/bash
# Setup development environment on MSYS2
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# We drag in tools that might not be needed by all users; it's easier
# that way.
#

function print_usage() {
	printf "\\nUtility to setup an MSYS2 MinGW-w64 system for Wireshark development.\\n"
	printf "The basic usage installs the needed software\\n\\n"
	printf "Usage: %s [--install-optional] [...other options...]\\n" "$0"
	printf "\\t--install-optional: install optional software as well\\n"
	printf "\\t--install-test-deps: install packages required to run all tests\\n"
	printf "\\t--install-all: install everything\\n"
	printf "\\t[other]: other options are passed as-is to pacman\\n"
	printf "\\tPass --noconfirm to bypass any \"are you sure?\" messages.\\n"
}

ADDITIONAL=0
TESTDEPS=0
LUA=0
OPTIONS=
for arg; do
	case $arg in
		--help)
			print_usage
			exit 0
			;;
		--install-optional)
			ADDITIONAL=1
			;;
		--install-test-deps)
			TESTDEPS=1
			;;
		--install-all)
			ADDITIONAL=1
			TESTDEPS=1
			LUA=1
			;;
		*)
			OPTIONS="$OPTIONS $arg"
			;;
	esac
done

#
# Lua is kind of a mess. Lua 5.2 is not available. Some packages depend
# on LuaJIT and it conflicts with Lua 5.1. This will probably have to
# be fixed by the MSYS2 maintainers. Take a hands off approach for now.
#
BASIC_LIST="base-devel \
	mingw-w64-x86_64-brotli \
	mingw-w64-x86_64-c-ares \
	mingw-w64-x86_64-cmake \
	mingw-w64-x86_64-glib2 \
	mingw-w64-x86_64-gnutls \
	mingw-w64-x86_64-libgcrypt \
	mingw-w64-x86_64-libilbc \
	mingw-w64-x86_64-libmaxminddb \
	mingw-w64-x86_64-nghttp2 \
	mingw-w64-x86_64-libpcap \
	mingw-w64-x86_64-libssh \
	mingw-w64-x86_64-libxml2 \
	mingw-w64-x86_64-lz4 \
	mingw-w64-x86_64-minizip \
	mingw-w64-x86_64-ninja \
	mingw-w64-x86_64-opus \
	mingw-w64-x86_64-pcre2 \
	mingw-w64-x86_64-python \
	mingw-w64-x86_64-qt6-base \
	mingw-w64-x86_64-qt6-multimedia \
	mingw-w64-x86_64-qt6-tools \
	mingw-w64-x86_64-qt6-5compat \
	mingw-w64-x86_64-snappy \
	mingw-w64-x86_64-spandsp \
	mingw-w64-x86_64-speexdsp \
	mingw-w64-x86_64-toolchain \
	mingw-w64-x86_64-winsparkle \
	mingw-w64-x86_64-zlib \
	mingw-w64-x86_64-zstd"

ADDITIONAL_LIST="mingw-w64-x86_64-asciidoctor \
	mingw-w64-x86_64-ccache \
	mingw-w64-x86_64-doxygen \
	mingw-w64-x86_64-perl \
	mingw-w64-x86_64-libxslt"

TESTDEPS_LIST="mingw-w64-x86_64-python-pytest \
	mingw-w64-x86_64-python-pytest-xdist"

ACTUAL_LIST=$BASIC_LIST

if [ $ADDITIONAL -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $ADDITIONAL_LIST"
fi

if [ $TESTDEPS -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $TESTDEPS_LIST"
fi

# Partial upgrades are unsupported.
pacman --sync --refresh --sysupgrade --needed $ACTUAL_LIST $OPTIONS || exit 2

if [ $ADDITIONAL -eq 0 ]
then
	printf "\n*** Optional packages not installed. Rerun with --install-optional to have them.\n"
fi

if [ $TESTDEPS -eq 0 ]
then
	printf "\n*** Test deps not installed. Rerun with --install-test-deps to have them.\n"
fi

if [ $LUA -ne 0 ]
then
	printf "\n*** Lua 5.1 can be installed with: pacman -S mingw-w64-x86_64-lua51\n"
fi
