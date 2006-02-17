# Makefile.am
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

plugin_LTLIBRARIES = lua.la

lua_la_SOURCES = \
	lua_tvb.c \
	lua_proto.c \
	lua_tree.c \
	lua_pinfo.c \
	lua_tap.c \
	lua_gui.c \
	lua_dumper.c \
	packet-lua.c \
	packet-lua.h \
	plugin.c

lua_la_LDFLAGS = -module -avoid-version
lua_la_LIBADD = @PLUGIN_LIBS@ @LUA_LIBS@


# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =


CLEANFILES = \
	*~

DISTCLEANFILES = \
	dummy

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	dummy

dummy:
	touch dummy

