#!/bin/bash
# Setup development environment on Debian and derivatives such as Ubuntu
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
	printf "\\nUtility to setup a debian-based system for Wireshark Development.\\n"
	printf "The basic usage installs the needed software\\n\\n"
	printf "Usage: %s [--install-optional] [--install-deb-deps] [...other options...]\\n" "$0"
	printf "\\t--install-optional: install optional software as well\\n"
	printf "\\t--install-deb-deps: install packages required to build the .deb file\\n"
	printf "\\t--install-test-deps: install packages required to run all tests\\n"
	printf "\\t--install-qt5-deps: force installation of packages required to use Qt5\\n"
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
		dpkg --compare-versions $version $versionreq || return 1
	fi

	# package is found, append it to list
	eval "${list}=\"\${${list}} \${pkgname}\""
}

ADDITIONAL=0
DEBDEPS=0
TESTDEPS=0
ADD_QT5=0
ADD_QT6=0
HAVE_ADD_QT=0
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
		--install-deb-deps)
			DEBDEPS=1
			;;
		--install-test-deps)
			TESTDEPS=1
			;;
		--install-qt5-deps)
			ADD_QT5=1
			;;
		--install-qt6-deps)
			ADD_QT6=1
			;;
		--install-all)
			ADDITIONAL=1
			DEBDEPS=1
			TESTDEPS=1
			ADD_QT5=1
			ADD_QT6=1
			HAVE_ADD_QT=1
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
	g++
	gcc
	libc-ares-dev
	libgcrypt-dev
	libglib2.0-dev
	libpcap-dev
	libpcre2-dev
	libspeexdsp-dev
	make
	python3
	"

QT5_LIST="
	libqt5svg5-dev
	qt5-qmake
	qtbase5-dev
	qtbase5-dev-tools
	qtchooser
	qtmultimedia5-dev
	qttools5-dev
	qttools5-dev-tools
	"

QT6_LIST="
	freeglut3-dev
	libqt6svg6-dev
	libvulkan-dev
	libxkbcommon-dev
	qt6-base-dev
	qt6-l10n-tools
	qt6-multimedia-dev
	qt6-tools-dev
	qt6-tools-dev-tools
	"

# qt6-5compat-dev: Debian >= bookworm, Ubuntu >= 23.04
# libqt6core5compat6-dev: Ubuntu 22.04
add_package QT6_LIST qt6-5compat-dev ||
QT6_LIST="$QT6_LIST libqt6core5compat6-dev"

if [ $ADD_QT5 -ne 0 ]
then
	BASIC_LIST="$BASIC_LIST $QT5_LIST"
	HAVE_ADD_QT=1
fi

if [ $ADD_QT6 -ne 0 ]
then
	BASIC_LIST="$BASIC_LIST $QT6_LIST"
	HAVE_ADD_QT=1
fi

if [ $HAVE_ADD_QT -eq 0 ]
then
	# Try to select Qt version from distro
	test -e /etc/os-release && os_release='/etc/os-release' || os_release='/usr/lib/os-release'
	# shellcheck disable=SC1090
	. "${os_release}"

	# Ubuntu 22.04 (jammy) / Debian 12 (bookworm) or later
	MAJOR=$(echo "$VERSION_ID" | cut -f1 -d.)
	if [ "${ID:-linux}" = "ubuntu" ] && [ "${MAJOR:-0}" -ge "22" ]; then
		echo "Installing Qt6."
		BASIC_LIST="$BASIC_LIST $QT6_LIST"
	elif [ "${ID:-linux}" = "debian" ] && [ "${MAJOR:-0}" -ge "12" ]; then
		echo "Installing Qt6."
		BASIC_LIST="$BASIC_LIST $QT6_LIST"
	else
		echo "Installing Qt5."
		BASIC_LIST="$BASIC_LIST $QT5_LIST"
	fi
fi

ADDITIONAL_LIST="
	ccache
	doxygen
	git
	libbrotli-dev
	libcap-dev
	libgnutls28-dev
	libkrb5-dev
	liblz4-dev
	libmaxminddb-dev
	libminizip-dev
	libnghttp2-dev
	libnl-3-dev
	libnl-cli-3-dev
	libopencore-amrnb-dev
	libopus-dev
	libparse-yapp-perl
	libsbc-dev
	libssh-gcrypt-dev
	libsmi2-dev
	libsnappy-dev
	libspandsp-dev
	libsystemd-dev
	libxml2-dev
	libzstd-dev
	ninja-build
	perl
	xsltproc
	"

# Uncomment to add PNG compression utilities used by compress-pngs:
# ADDITIONAL_LIST="
#	$ADDITIONAL_LIST
#	advancecomp
#	optipng
#	pngcrush
#	"

DEBDEPS_LIST="
	asciidoctor
	debhelper
	dh-python
	docbook-xml
	docbook-xsl
	libxml2-utils
	lintian
	lsb-release
	po-debconf
	python3-ply
	quilt
	"

TESTDEPS_LIST="
	gdb
	python3-pytest
	python3-pytest-xdist
	softhsm2
	"

# apt-get update must be called before calling add_package
# otherwise available packages appear as unavailable
apt-get update || exit 2

# Lua 5.4: Debian >= bullseye, Ubuntu >= 22.04 (jammy)
# Lua 5.3: Debian >= buster, Ubuntu >= 20.04 (focal)
add_package ADDITIONAL_LIST liblua5.4-dev ||
ADDITIONAL_LIST="$ADDITIONAL_LIST liblua5.3-dev"

# Debian >= bookworm, Ubuntu >= 22.04
add_package ADDITIONAL_LIST libnghttp3-dev ||
echo "libnghttp3-dev is unavailable" >&2

# ilbc library from http://www.deb-multimedia.org
add_package ADDITIONAL_LIST libilbc-dev ||
echo "libilbc-dev is unavailable"

# Debian >= bullseye, Ubuntu >= 22.04 (jammy)
# bcg729 library libbcg729-dev
add_package ADDITIONAL_LIST libbcg729-dev ||
    echo "libbcg729-dev is unavailable"

ACTUAL_LIST=$BASIC_LIST

# Now arrange for optional support libraries
if [ $ADDITIONAL -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $ADDITIONAL_LIST"
fi

if [ $DEBDEPS -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $DEBDEPS_LIST"
fi

if [ $TESTDEPS -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $TESTDEPS_LIST"
fi

# shellcheck disable=SC2086
apt-get install $ACTUAL_LIST $OPTIONS || exit 2

if [ $ADDITIONAL -eq 0 ]
then
	printf "\n*** Optional packages not installed. Rerun with --install-optional to have them.\n"
fi

if [ $DEBDEPS -eq 0 ]
then
	printf "\n*** Debian packages build deps not installed. Rerun with --install-deb-deps to have them.\n"
fi

if [ $TESTDEPS -eq 0 ]
then
	printf "\n*** Test deps not installed. Rerun with --install-test-deps to have them.\n"
fi
