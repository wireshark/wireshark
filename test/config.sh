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

# path to the Wireshark binaries, only used for the settings below
ETH_BIN_PATH=../Debug_GTK2

# Tweak the following to your liking.
WIRESHARK=$ETH_BIN_PATH/wireshark
TSHARK=$ETH_BIN_PATH/tshark
CAPINFOS=$ETH_BIN_PATH/capinfos
DUMPCAP=$ETH_BIN_PATH/dumpcap

# interface with at least a few packets/sec traffic on it
# (e.g. start a web radio to generate some traffic :-)
# an interfaces index (1 based) should do well for recent devbuilds
TRAFFIC_CAPTURE_IFACE=2

# time to capture some traffic (in seconds)
# (you may increase this if you get errors caused by very low traffic)
TRAFFIC_CAPTURE_DURATION=3
