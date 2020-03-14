#!/usr/bin/env bash
# Setup development environment on BSD-like platforms.
#
# Tested on: FreeBSD, OpenBSD, NetBSD.
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

if [ "$1" = "--help" ]
then
	echo "\nUtility to setup a bsd-based system for Wireshark Development.\n"
	echo "The basic usage installs the needed software\n\n"
	echo "Usage: $0 [--install-optional] [...other options...]\n"
	echo "\t--install-optional: install optional software as well"
	echo "\t[other]: other options are passed as-is to pkg manager.\n"
	exit 1
fi

# Check if the user is root
if [ $(id -u) -ne 0 ]
then
	echo "You must be root."
	exit 1
fi

for op
do
	if [ "$op" = "--install-optional" ]
	then
		ADDITIONAL=1
	else
		OPTIONS="$OPTIONS $op"
	fi
done

BASIC_LIST="\
	cmake \
	qt5 \
	git"

ADDITIONAL_LIST="\
	gettext-tools \
	snappy \
	bcg729 \
	libssh \
	libmaxminddb \
	libsmi \
	brotli \
	speexdsp \
	zstd \
	lua52 \
	"

# Guess which package manager we will use
PM=`which pkgin 2> /dev/null || which pkg 2> /dev/null || which pkg_add 2> /dev/null`

case $PM in
	*/pkgin)
		PM_OPTIONS="install"
		PM_SEARCH="pkgin search"
		PM_MUST_GLOB=no
		;;
	*/pkg)
		PM_OPTIONS="install"
		PM_SEARCH="pkg search"
		PM_MUST_GLOB=yes
		;;
	*/pkg_add)
		PM_OPTIONS=""
		PM_SEARCH="pkg_info"
		PM_MUST_GLOB=no
		;;
esac


echo "Using $PM ($PM_SEARCH)"

# Adds package $2 to list variable $1 if the package is found
add_package() {
	local list="$1" pkgname="$2"

	# fail if the package is not known
	if [ "$PM_MUST_GLOB" = yes ]
	then
		#
		# We need to do a glob search, with a "*" at the
		# end, so we only find packages that *begin* with
		# the name; otherwise, searching for pkg-config
		# could find packages that *don't* begin with
		# pkg-config, but have it later in the name
		# (FreeBSD 11 has one such package), so when
		# we then try to install it, that fails.  Doing
		# an *exact* search fails, as that requires that
		# the package name include the version number.
		#
		$PM_SEARCH -g "$pkgname*" > /dev/null 2>&1 || return 1
	else
		$PM_SEARCH "$pkgname" > /dev/null 2>&1 || return 1
	fi

	# package is found, append it to list
	eval "${list}=\"\${${list}} \${pkgname}\""
}

# pkg-config: NetBSD
# pkgconf: FreeBSD
add_package BASIC_LIST pkg-config ||
add_package BASIC_LIST pkgconf ||
echo "pkg-config is unavailable"

# c-ares: FreeBSD
# libcares: OpenBSD
add_package BASIC_LIST c-ares ||
add_package BASIC_LIST libcares ||
echo "c-ares is unavailable"

# rubygem-asciidoctor: FreeBSD
add_package ADDITIONAL_LIST rubygem-asciidoctor ||
echo "asciidoctor is unavailable"

# liblz4: FreeBSD
# lz4: NetBSD
add_package ADDITIONAL_LIST liblz4 ||
add_package ADDITIONAL_LIST lz4 ||
echo "lz4 is unavailable"

# nghttp2: NetBSD
add_package ADDITIONAL_LIST nghttp2 ||
echo "nghttp2 is unavailable"

# spandsp: NetBSD
add_package ADDITIONAL_LIST spandsp ||
echo "spandsp is unavailable"

# ninja: FreeBSD, OpenBSD
# ninja-build: NetBSD
add_package ADDITIONAL_LIST ninja-build ||
add_package ADDITIONAL_LIST ninja ||
echo "ninja is unavailable"

# libilbc: FreeBSD
add_package ADDITIONAL_LIST libilbc ||
echo "libilbc is unavailable"

# Add OS-specific required/optional packages
# Those not listed don't require additions.
case `uname` in
	OpenBSD)
		add_package ADDITIONAL_LIST bison || echo "bison is unavailable"
		;;
	NetBSD)
		add_package ADDITIONAL_LIST libgcrypt || echo "libgcrypt is unavailable"
		;;
esac

ACTUAL_LIST=$BASIC_LIST

# Now arrange for optional support libraries
if [ "$ADDITIONAL" != "" ]
then
	ACTUAL_LIST="$ACTUAL_LIST $ADDITIONAL_LIST"
fi

$PM $PM_OPTIONS $ACTUAL_LIST $OPTIONS
if [ ! $? ]
then
	exit 2
fi

if [ "$ADDITIONAL" == "" ]
then
	echo -e "\n*** Optional packages not installed. Rerun with --install-optional to have them.\n"
fi
