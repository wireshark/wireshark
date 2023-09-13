#!/bin/bash
# Setup development environment on Fedora Linux for MinGW-w64
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
	printf "\\nUtility to setup a Fedora MinGW-w64 system for Wireshark development.\\n"
	printf "The basic usage installs the needed software\\n\\n"
	printf "Usage: %s [...other options...]\\n" "$0"
	printf "\\t--install-all: install everything\\n"
	printf "\\t[other]: other options are passed as-is to pacman\\n"
	printf "\\tPass --noconfirm to bypass any \"are you sure?\" messages.\\n"
}

OPTIONS=
for arg; do
	case $arg in
		--help)
			print_usage
			exit 0
			;;
		--install-all)
			;;
		*)
			OPTIONS="$OPTIONS $arg"
			;;
	esac
done

BASIC_LIST="mingw64-gcc \
	mingw64-gcc-c++ \
	mingw64-glib2 \
	mingw64-libgcrypt \
	mingw64-c-ares \
	mingw64-qt6-qtbase \
	mingw64-qt6-qt5compat \
	mingw64-qt6-qtmultimedia \
	mingw64-qt6-qttools \
	mingw64-speexdsp \
	mingw32-nsis \
	mingw64-nsis \
	mingw64-gnutls \
	mingw64-brotli \
	mingw64-minizip \
	mingw64-opus \
	mingw64-wpcap \
	mingw64-libxml2 \
	ninja-build \
	flex \
	lemon \
	asciidoctor \
	libxslt \
	docbook-style-xsl \
	ccache \
	git \
	patch \
	cmake
	cmake-rpm-macros"

ACTUAL_LIST=$BASIC_LIST

dnf install $ACTUAL_LIST $OPTIONS
