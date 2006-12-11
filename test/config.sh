#!/bin/bash
#
# Configuration of the command line tests
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2005 Ulf Lamping
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

# Set WS_SYSTEM to our system type, e.g. Windows, Linux, Darwin
# http://support.microsoft.com/kb/100843
if [ -n "${OS#Windows}" ] ; then
	WS_SYSTEM="Windows"
else
	WS_SYSTEM=`uname -s`
fi

# path to the Wireshark binaries, only used for the settings below
if [ "$WS_SYSTEM" = "Windows" ] ; then
	WS_BIN_PATH=../wireshark-gtk2
else
	WS_BIN_PATH=..
fi

# Tweak the following to your liking.
WIRESHARK=$WS_BIN_PATH/wireshark
TSHARK=$WS_BIN_PATH/tshark
CAPINFOS=$WS_BIN_PATH/capinfos
DUMPCAP=$WS_BIN_PATH/dumpcap

# interface with at least a few packets/sec traffic on it
# (e.g. start a web radio to generate some traffic :-)
# an interfaces index (1 based) should do well for recent devbuilds
TRAFFIC_CAPTURE_IFACE=${TRAFFIC_CAPTURE_IFACE:-3}

# time to capture some traffic (in seconds)
# (you may increase this if you get errors caused by very low traffic)
TRAFFIC_CAPTURE_DURATION=20

# the default is to not capture in promiscuous mode
# (this makes known trouble with some Windows WLAN adapters)
# if you need promiscuous mode, comment this line out
TRAFFIC_CAPTURE_PROMISC=-p

# Windows (even cygwin) don't provide the mkfifo used here
# if you have mkfifo, you may uncomment this line
#TEST_FIFO
