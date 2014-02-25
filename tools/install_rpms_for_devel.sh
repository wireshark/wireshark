#!/bin/bash

# A little shell script to install all the packages necesary to do Wireshark
# development.  Both the development and runtime packages are installed
# although the latter aren't strictly necessary.
#
# Ideally this could automatically pull the packages out of
# packaging/rpm/SPECS/wireshark.spec.in but given the variance in package names
# between distributions, this seems painful...
#
# Copyright 2013 Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
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

if [ -r /etc/SuSE-release ]
then
	INSTALL_CMD=zypper
	GTK2="gtk2-devel libgtk-2_0-0"
	GTK3="gtk3-devel libgtk-3-0"
	QT="libqt4-devel gcc-c++"
	GLIB2="glib2-devel libglib-2_0-0"
	PCAP="libpcap-devel libpcap1"
	ZLIB="zlib-devel libz1"
	CARES="libcares-devel libcares2"
else
	if [ ! -r /etc/redhat-release ]
	then
		echo "* * Unknown distro! Assuming Redhat-like. * *"
		echo
	fi

	INSTALL_CMD=yum
	GTK2="gtk2-devel gtk2"
	GTK3="gtk3-devel gtk3"
	QT="qt-devel gcc-c++"
	GLIB2="glib2-devel glib2"
	PCAP="libpcap-devel libpcap"
	ZLIB="zlib-devel zlib"
	CARES="c-ares-devel c-ares"
fi

PKGS="autoconf automake libtool gcc flex bison python perl $GLIB2
$PCAP $ZLIB lua-devel lua $CARES $GTK2 desktop-file-utils $QT fop asciidoc
git git-review perl-podlators"

echo "Run this command (as root):"
echo
echo $INSTALL_CMD install -y $PKGS

