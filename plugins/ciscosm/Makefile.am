# Makefile.am
# Automake file for Cisco SS7 Session Management dissector
# Copyright 2004, Duncan Sargeant <dunc-ethereal@rcpt.to>
#
# $Id$
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
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

plugin_LTLIBRARIES = ciscosm.la
ciscosm_la_SOURCES = packet-sm.c moduleinfo.h
ciscosm_la_LDFLAGS = -module -avoid-version
ciscosm_la_LIBADD = @PLUGIN_LIBS@

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

CLEANFILES = \
	ciscosm \
	*~

EXTRA_DIST = \
	Makefile.nmake
