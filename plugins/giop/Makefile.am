# Makefile.am
# Automake file for Ethereal/GIOP subdissectors 
#
# $Id$
#
# Copyright 2001, Ericsson Inc.
# Frank Singleton <frank.singleton@ericsson.com>
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

INCLUDES = -I$(top_srcdir)

plugindir = @plugindir@

plugin_LTLIBRARIES = cosnaming.la coseventcomm.la tango.la parlay.la
cosnaming_la_SOURCES = packet-cosnaming.c moduleinfo.h
cosnaming_la_LDFLAGS = -module -avoid-version
cosnaming_la_LIBADD = @PLUGIN_LIBS@

coseventcomm_la_SOURCES = packet-coseventcomm.c moduleinfo.h
coseventcomm_la_LDFLAGS = -module -avoid-version
coseventcomm_la_LIBADD = @PLUGIN_LIBS@

tango_la_SOURCES = packet-tango.c moduleinfo.h
tango_la_LDFLAGS = -module -avoid-version
tango_la_LIBADD = @PLUGIN_LIBS@

parlay_la_SOURCES = packet-parlay.c moduleinfo.h
parlay_la_LDFLAGS = -module -avoid-version
parlay_la_LIBADD = @PLUGIN_LIBS@

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

CLEANFILES = \
	cosnaming \
	coseventcomm \
	tango \
	parlay \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	Makefile.nmake
