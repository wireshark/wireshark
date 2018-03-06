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
# SPDX-License-Identifier: GPL-2.0-or-later

if [ -r /etc/SuSE-release ]
then
	INSTALL_CMD=zypper
	GTK2="gtk2-devel libgtk-2_0-0"
	GTK3="gtk3-devel libgtk-3-0"
	QT="libqt4-devel gcc-c++"
	GLIB2="glib2-devel libglib-2_0-0"
	PCAP="libpcap-devel libpcap1"
	ZLIB="zlib-devel libz1"
	SNAPPY="snappy-devel libsnappy1"
	# The runtime package name changes with the version.  Just pull it
	# in through the -devel package.
	LZ4="liblz4-devel"
	CARES="libcares-devel libcares2"
	NGHTTP2="nghttp2"
	# SUSE doesn't split the pod2* commands into a separate package like RH
	PERLPODS=""
	GNUTLS="libgnutls-devel"
	GETTEXT="gettext-tools"
	QT5="libqt5-linguist-devel libqt5-qtsvg-devel libqt5-qtmultimedia-devel
		libQt5PrintSupport-devel"
	CAP_PROGS="libcap-progs"
else
	if [ ! -r /etc/redhat-release ]
	then
		echo "* * Unknown distro! Assuming Redhat-like. * *"
		echo
	fi

	if type -p dnf > /dev/null
	then
		INSTALL_CMD=dnf
		POD2HTML="perl-Pod-Html"
	else
		INSTALL_CMD=yum
	fi
	GTK2="gtk2-devel gtk2"
	GTK3="gtk3-devel gtk3"
	QT="qt-devel gcc-c++ qt5-qtbase-devel qt5-qtmultimedia-devel"
	GLIB2="glib2-devel glib2"
	PCAP="libpcap-devel libpcap"
	ZLIB="zlib-devel zlib"
	SNAPPY="snappy-devel snappy"
	LZ4="lz4 lz4-devel" # May need to enable EPEL
	CARES="c-ares-devel c-ares"
	NGHTTP2="libnghttp2"
	PERLPODS="perl-podlators"
	GNUTLS="gnutls-devel"
	GETTEXT="gettext-devel"
	QT5="qt5-linguist qt5-qtsvg-devel"
        # mmdbresolve
	MAXMINDDB="libmaxminddb-devel"
fi

PKGS="autoconf automake libtool gcc flex bison python perl $GLIB2
$PCAP $ZLIB lua-devel lua $CARES $GTK3 $GTK2 desktop-file-utils $QT fop
asciidoc git git-review $PERLPODS"

PKGS_OPT="libnl3-devel libnghttp2-devel $NGHTTP2 $SNAPPY $LZ4 libcap $CAP_PROGS
libcap-devel $MAXMINDDB libgcrypt-devel $GNUTLS $GETTEXT libssh-devel
krb5-devel perl-Parse-Yapp sbc-devel libsmi-devel $POD2HTML $QT5 asciidoctor"

echo "Run this command (as root):"
echo
echo $INSTALL_CMD install $PKGS
echo
echo "To install optional packages:"
echo
echo $INSTALL_CMD install $PKGS_OPT
echo
echo "This tool has been obsoleted by tools/rpm-setup.sh"
