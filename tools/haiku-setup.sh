#!/bin/bash
# Setup development environment on Haiku
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
	printf "\\nUtility to setup a Haiku system for Wireshark development.\\n"
	printf "The basic usage installs the needed software\\n\\n"
	printf "Usage: %s [--install-optional] [--install-deb-deps] [...other options...]\\n" "$0"
	printf "\\t--install-optional: install optional software as well\\n"
	printf "\\t--install-test-deps: install packages required to run all tests\\n"
	printf "\\t--install-qt5-deps: force installation of packages required to use Qt5 (not recommended)\\n"
	printf "\\t--install-qt6-deps: force installation of packages required to use Qt6\\n"
	printf "\\t--install-all: install everything\\n"
	printf "\\t[other]: other options are passed as-is to apt\\n"
}

# Adds package $2 to list variable $1 if the package is found.
# If $3 is given, then this version requirement must be satisfied.
function add_package() {
	local list="$1" pkgname="$2" versionreq="${3:-}" version

	version=$(apt-cache show "$pkgname" 2>/dev/null |
		awk '/^Version:/{ print $2; exit}')
	# fail if the package is not known
	if [ -z "$version" ]; then
		return 1
	elif [ -n "$versionreq" ]; then
		# Require minimum version or fail.
		# shellcheck disable=SC2086
		dpkg --compare-versions $version ge $versionreq || return 1
	fi

	# package is found, append it to list
	eval "${list}=\"\${${list}} \${pkgname}\""
}

ADDITIONAL=0
TESTDEPS=0
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

BASIC_LIST="
	cmake
	flex
	gcc
	gcc_syslibs_devel
	c_ares_devel
	libgcrypt_devel
	glib2_devel
	libpcap_devel
	libpcre2_devel
	speexdsp_devel
	libxml2_devel
	libxml2
	qt6_base_devel
	qt6_5compat_devel
	qt6_multimedia_devel
	qt6_svg_devel
	qt6_tools_devel  
	make
	python3.14
	"

ADDITIONAL_LIST="
	ccache
	doxygen
	git
	brotli_devel
	gnutls_devel
	krb5_devel
	lz4_devel
	maxminddb_devel
	minizip_devel
	nghttp2_devel
	opus_devel
	parse_yapp
	ibsbc_devel
	snappy_devel
	xxhash_devel
	zstd_devel
	ninja
	perl
	"

# PNG compression utilities used by compress-pngs:
ADDITIONAL_LIST="
	$ADDITIONAL_LIST
	advancecomp
	optipng
	pngcrush
	"

# libssh-gcrypt-dev: Debian < trixie, Ubuntu < 25.04
# libssh-dev: All releases, but trixie and 25.04 has relicensed OpenSSH
# See: https://bugs.debian.org/1074337
add_package ADDITIONAL_LIST libssh-dev 0.11.1-1 ||
ADDITIONAL_LIST="$ADDITIONAL_LIST libssh-gcrypt-dev"

# Lua 5.5: Debian >= forky, Ubuntu >= 26.04 (resolute)
# Lua 5.4: Debian >= bullseye, Ubuntu >= 22.04 (jammy)
# Lua 5.3: Debian >= buster, Ubuntu >= 20.04 (focal)
add_package ADDITIONAL_LIST liblua5.5-dev ||
add_package ADDITIONAL_LIST liblua5.4-dev ||
ADDITIONAL_LIST="$ADDITIONAL_LIST liblua5.3-dev"

# Debian >= bookworm, Ubuntu >= 22.04
add_package ADDITIONAL_LIST nghttp3_devel ||
echo "nghttp3_devel is unavailable" >&2

# ilbc library from http://www.deb-multimedia.org
#add_package ADDITIONAL_LIST libilbc-dev ||
#echo "libilbc-dev is unavailable"

# Debian >= bullseye, Ubuntu >= 22.04 (jammy)
# bcg729 library libbcg729-dev
#add_package ADDITIONAL_LIST libbcg729-dev ||
#    echo "libbcg729-dev is unavailable"

# Debian >= bullseye, Ubuntu >= 22.04 (jammy)
#add_package ADDITIONAL_LIST libcpuinfo-dev ||
#    echo "libcpuinfo-dev is unavailable"

ACTUAL_LIST=$BASIC_LIST

# Now arrange for optional support libraries
if [ $ADDITIONAL -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $ADDITIONAL_LIST"
fi

if [ $TESTDEPS -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $TESTDEPS_LIST"
fi

# shellcheck disable=SC2086
pkgman install $ACTUAL_LIST $OPTIONS || exit 2

if [ $ADDITIONAL -eq 0 ]
then
	printf "\n*** Optional packages not installed. Rerun with --install-optional to have them.\n"
fi

if [ $TESTDEPS -eq 0 ]
then
	printf "\n*** Test deps not installed. Rerun with --install-test-deps to have them.\n"
fi
