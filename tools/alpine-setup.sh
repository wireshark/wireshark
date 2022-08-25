#!/bin/bash
# Setup development environment on alpine systems
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
	printf "\\nUtility to setup a alpine system for Wireshark Development.\\n"
	printf "The basic usage installs the needed software\\n\\n"
	printf "Usage: %s [--install-optional] [--install-deb-deps] [...other options...]\\n" "$0"
	printf "\\t--install-optional: install optional software as well\\n"
	printf "\\t--install-all: install everything\\n"
	printf "\\t[other]: other options are passed as-is to apt\\n"
}

ADDITIONAL=0
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
		--install-all)
			ADDITIONAL=1
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

BASIC_LIST="cmake \
	ninja \
	gcc \
	g++ \
	glib-dev \
	libgcrypt-dev \
	flex \
	tiff-dev \
	c-ares-dev \
	pcre2-dev \
	qt5-qtbase-dev \
	qt5-qttools-dev \
	qt5-qtmultimedia-dev \
	qt5-qtsvg-dev"

ADDITIONAL_LIST="
	git \
	asciidoctor \
	libssh-dev \
	spandsp-dev \
	libcap-dev \
	libpcap-dev \
	libxml2-dev \
	libmaxminddb-dev \
	krb5-dev \
	lz4-dev \
	gnutls-dev \
	snappy-dev \
	nghttp2-dev \
	lua5.2-dev \
	libnl3-dev \
	sbc-dev \
	minizip-dev \
	speexdsp-dev \
	brotli-dev \
	perl \
	"

# Uncomment to add PNG compression utilities used by compress-pngs:
# ADDITIONAL_LIST="$ADDITIONAL_LIST \
#	advancecomp \
#	optipng \
#	oxipng \
#	pngcrush"

# Adds package $2 to list variable $1 if the package is found.
# If $3 is given, then this version requirement must be satisfied.
add_package() {
	local list="$1" pkgname="$2"

	# fail if the package is not known
	apk list $pkgname &> /dev/null || return 1

	# package is found, append it to list
	eval "${list}=\"\${${list}} \${pkgname}\""
}

ACTUAL_LIST=$BASIC_LIST

# Now arrange for optional support libraries
if [ $ADDITIONAL -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $ADDITIONAL_LIST"
fi

apk update || exit 2
apk add $ACTUAL_LIST $OPTIONS || exit 2

if [ $ADDITIONAL -eq 0 ]
then
	printf "\n*** Optional packages not installed. Rerun with --install-optional to have them.\n"
fi
