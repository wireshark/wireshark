#!/bin/sh
# Setup development environment on Debian and derivatives such as Ubuntu
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# We drag in tools that might not be needed by all users; it's easier
# that way.
#

if [ "$1" = "--help" ]
then
	echo "\nUtility to setup a debian-based system for Wireshark Development.\n"
	echo "The basic usage installs the needed software\n\n"
	echo "Usage: $0 [--install-optional] [...other options...]\n"
	echo "\t--install-optional: install optional software as well"
	echo "\t[other]: other options are passed as-is to apt\n"
	exit 1
fi

# Check if the user is root
if [ $(id -u) -ne 0 ]
then
	echo "You must be root."
	exit 1
fi

for op in $@
do
	if [ "$op" = "--install-optional" ]
	then
		ADDITIONAL=1
	else
		OPTIONS="$OPTIONS $op"
	fi
done

BASIC_LIST="libgtk2.0-dev libpcap-dev bison flex make automake \
	libtool python perl libgcrypt-dev"

ADDITIONAL_LIST="libnl-3-dev qttools5-dev qttools5-dev-tools libgtk-3-dev \
		libc-ares-dev libkrb5-dev libqt5svg5-dev lynx libsmi2-dev \
		portaudio19-dev asciidoc libsbc-dev libgeoip-dev \
		qtmultimedia5-dev liblua5.2-dev libnl-cli-3-dev \
		libparse-yapp-perl qt5-default cmake libcap-dev \
		liblz4-dev libsnappy-dev libspandsp-dev libxml2-dev"

# Adds package $2 to list variable $1 if the package is found
add_package() {
	local list="$1" pkgname="$2"

	# fail if the package is not known
	[ -n "$(apt-cache show "$pkgname" 2>/dev/null)" ] || return 1

	# package is found, append it to list
	eval "${list}=\"\${${list}} \${pkgname}\""
}

# only needed for newer distro versions where "libtool" binary is separated.
# Debian >= jessie, Ubuntu >= 16.04
add_package BASIC_LIST libtool-bin

# Debian >= wheezy-backports, Ubuntu >= 16.04
add_package ADDITIONAL_LIST libnghttp2-dev ||
echo "libnghttp2-dev is unavailable" >&2

# libssh-gcrypt-dev: Debian >= jessie, Ubuntu >= 16.04
# libssh-dev (>= 0.6): Debian >= jessie, Ubuntu >= 14.04
add_package ADDITIONAL_LIST libssh-gcrypt-dev ||
add_package ADDITIONAL_LIST libssh-dev ||
echo "libssh-gcrypt-dev and libssh-dev are unavailable" >&2

# libgnutls-dev: Debian <= jessie, Ubuntu <= 16.04
# libgnutls28-dev: Debian >= wheezy-backports, Ubuntu >= 12.04
add_package ADDITIONAL_LIST libgnutls28-dev ||
add_package ADDITIONAL_LIST libgnutls-dev ||
echo "libgnutls28-dev and libgnutls-dev are unavailable" >&2

ACTUAL_LIST=$BASIC_LIST

# Now arrange for optional support libraries
if [ $ADDITIONAL ]
then
	ACTUAL_LIST="$ACTUAL_LIST $ADDITIONAL_LIST"
fi

apt-get install $ACTUAL_LIST $OPTIONS
if [ $? != 0 ]
then
	exit 2
fi

if [ ! $ADDITIONAL ]
then
	echo "\n*** Optional packages not installed. Rerun with --install-optional to have them.\n"
fi
