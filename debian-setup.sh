#!/bin/sh
# Setup development environment on Debian and derivatives such as Ubuntu
#
# $Id$
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
