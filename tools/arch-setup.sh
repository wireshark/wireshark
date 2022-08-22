#!/bin/bash
# Setup development environment on Arch Linux
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

set -e -u -o pipefail

function print_usage() {
	printf "\\nUtility to setup a pacman-based system for Wireshark development.\\n"
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
AUR=0
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
			AUR=1
			;;
		*)
			OPTIONS="$OPTIONS $arg"
			;;
	esac
done

# Check if the user is root
if [ "$(id -u)" -ne 0 ]
then
	echo "You must be root."
	exit 1
fi

BASIC_LIST="base-devel \
	bcg729 \
	brotli \
	c-ares \
	cmake \
	git \
	glib2 \
	gnutls \
	krb5 \
	libcap \
	libgcrypt \
	libilbc \
	libmaxminddb \
	libnghttp2 \
	libnl \
	libpcap \
	libssh \
	libxml2 \
	lua52 \
	lz4 \
	minizip \
	ninja \
	pcre2 \
	python \
	qt6-base \
	qt6-multimedia \
	qt6-tools \
	qt6-5compat \
	sbc \
	snappy \
	spandsp \
	speexdsp \
	zlib \
	zstd"

ADDITIONAL_LIST="asciidoctor \
	ccache \
	docbook-xml \
	docbook-xsl \
	doxygen \
	libxslt \
	perl"

TESTDEPS_LIST="python-pytest \
	python-pytest-xdist"

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

if [ $AUR -ne 0 ]
then
	printf "\n*** These and other packages may also be found in the AUR: libsmi.\n"
fi
