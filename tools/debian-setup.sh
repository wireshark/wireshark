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

#
# Install the packages required for Wireshark development.
# (This includes GUI packages; making that optional, with a command-line
# flag, is left as an exercise to the reader.)
#
# We drag in tools that might not be needed by all users; it's easier
# that way.
#
apt-get install libgtk2.0-dev libpcap0.8-dev bison flex make automake \
	libtool python perl

#
# Now arrange for optional support libraries - or just pull them all in?
#
