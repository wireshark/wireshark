# Makefile.am
# Automake file for Megaco Ethereal plugin
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

plugin_LTLIBRARIES = v5ua.la
v5ua_la_SOURCES = packet-v5ua.c moduleinfo.h
v5ua_la_LDFLAGS = -module -avoid-version

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

v5ua_la_DEPENDENCIES = packet-v5ua-static.o

packet-v5ua-static.o:	packet-v5ua.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-v5ua-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-v5ua.c 

CLEANFILES = \
	v5ua \
	*~

EXTRA_DIST = \
	Makefile.nmake
