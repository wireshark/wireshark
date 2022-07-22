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
	printf "\\t[other]: other options are passed as-is to apt\\n"
}

ADDITIONAL=0
DEBDEPS=0
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
		--install-deb-deps)
			DEBDEPS=1
			;;
		--install-test-deps)
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

BASIC_LIST="gcc \
	g++\
	libglib2.0-dev \
	qttools5-dev \
	qttools5-dev-tools \
	libqt5svg5-dev \
	qtmultimedia5-dev \
	qtbase5-dev \
	qtchooser \
	qt5-qmake \
	qtbase5-dev-tools \
	libc-ares-dev \
	libpcap-dev \
	libpcre2-dev \
	flex \
	make \
	python3 \
	libgcrypt-dev"

ADDITIONAL_LIST="libnl-3-dev \
	libkrb5-dev \
	libsmi2-dev \
	libsbc-dev \
	liblua5.2-dev \
	libnl-cli-3-dev \
	libparse-yapp-perl \
	libcap-dev \
	liblz4-dev \
	libsnappy-dev \
	libzstd-dev \
	libspandsp-dev \
	libxml2-dev \
	libminizip-dev \
	git \
	ninja-build \
	perl \
	xsltproc \
	ccache \
	libspeexdsp-dev"

# Uncomment to add PNG compression utilities used by compress-pngs:
# ADDITIONAL_LIST="$ADDITIONAL_LIST \
#	advancecomp \
#	optipng \
#	pngcrush"

DEBDEPS_LIST="debhelper \
	dh-python \
	asciidoctor \
	docbook-xml \
	docbook-xsl \
	libxml2-utils \
	lintian \
	lsb-release \
	po-debconf \
	python3-ply \
	quilt"

TESTDEPS_LIST="python3-pytest \
	python3-pytest-xdist"

# Adds package $2 to list variable $1 if the package is found.
# If $3 is given, then this version requirement must be satisfied.
add_package() {
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

# apt-get update must be called before calling add_package
# otherwise available packages appear as unavailable
apt-get update || exit 2

# cmake3 3.5.1: Ubuntu 14.04
# cmake >= 3.5: Debian >= jessie-backports, Ubuntu >= 16.04
add_package BASIC_LIST cmake3 ||
BASIC_LIST="$BASIC_LIST cmake"

# Debian >= wheezy-backports, Ubuntu >= 16.04
add_package ADDITIONAL_LIST libnghttp2-dev ||
echo "libnghttp2-dev is unavailable" >&2

# libssh-gcrypt-dev: Debian >= jessie, Ubuntu >= 16.04
# libssh-dev (>= 0.6): Debian >= jessie, Ubuntu >= 14.04
add_package ADDITIONAL_LIST libssh-gcrypt-dev ||
add_package ADDITIONAL_LIST libssh-dev ||
echo "libssh-gcrypt-dev and libssh-dev are unavailable" >&2

# libgnutls28-dev: Debian >= wheezy-backports, Ubuntu >= 12.04
add_package ADDITIONAL_LIST libgnutls28-dev ||
echo "libgnutls28-dev is unavailable" >&2

# Debian >= jessie-backports, Ubuntu >= 16.04
add_package ADDITIONAL_LIST libmaxminddb-dev ||
echo "libmaxminddb-dev is unavailable" >&2

# Debian >= stretch-backports, Ubuntu >= 16.04
add_package ADDITIONAL_LIST libbrotli-dev ||
echo "libbrotli-dev is unavailable" >&2

# libsystemd-journal-dev: Ubuntu 14.04
# libsystemd-dev: Ubuntu >= 16.04
add_package ADDITIONAL_LIST libsystemd-dev ||
add_package ADDITIONAL_LIST libsystemd-journal-dev ||
echo "libsystemd-dev is unavailable"

# ilbc library from http://www.deb-multimedia.org
add_package ADDITIONAL_LIST libilbc-dev ||
echo "libilbc-dev is unavailable"

# opus library libopus-dev
add_package ADDITIONAL_LIST libopus-dev ||
    echo "libopus-dev is unavailable"

# softhsm2 2.0.0: Ubuntu 16.04
# softhsm2 2.2.0: Debian >= jessie-backports, Ubuntu 18.04
# softhsm2 >= 2.4.0: Debian >= buster, Ubuntu >= 18.10
if ! add_package TESTDEPS_LIST softhsm2 '>= 2.3.0'; then
	if add_package TESTDEPS_LIST softhsm2; then
		# If SoftHSM 2.3.0 is unavailble, install p11tool.
		TESTDEPS_LIST="$TESTDEPS_LIST gnutls-bin"
	else
		echo "softhsm2 is unavailable" >&2
	fi
fi

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
