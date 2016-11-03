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
	libtool python perl"

ADDITIONAL_LIST="libnl-3-dev qttools5-dev qttools5-dev-tools libgtk-3-dev \
		libc-ares-dev libssh-dev libkrb5-dev libqt5svg5-dev lynx libsmi2-dev \
		portaudio19-dev asciidoc libgcrypt-dev libsbc-dev libgeoip-dev \
		libgnutls-dev qtmultimedia5-dev liblua5.2-dev libnl-cli-3-dev \
		libparse-yapp-perl qt5-default cmake libcap-dev \
		liblz4-dev libsnappy-dev"

# Check for lsb_release command in $PATH
if ! which lsb_release > /dev/null; then
	echo "ERROR: lsb_release not found in \$PATH" >&2
	exit 1;
fi

rel=$(lsb_release --codename --short)

case $rel in
trusty)
	# Add trusty specific steps
	# i.e. there is no libtool-bin package in trusty and other distros.
	# Avoid install it on those platforms.
	;;
*)
	BASIC_LIST="$BASIC_LIST libtool-bin"
	ADDITIONAL_LIST="$ADDITIONAL_LIST libnghttp2-dev libssh-gcrypt-dev"
	;;
esac

# Install basic packages
apt-get install $BASIC_LIST $OPTIONS

# Now arrange for optional support libraries
if [ ! $ADDITIONAL ]
then
	echo "\n*** Optional packages not installed. Rerun with --install-optional to have them.\n"
else
	apt-get install $ADDITIONAL_LIST $OPTIONS
fi
