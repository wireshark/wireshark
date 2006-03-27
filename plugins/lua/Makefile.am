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

INCLUDES = -I$(top_srcdir) @LUA_INCLUDES@

plugindir = @plugindir@

plugin_LTLIBRARIES = lua.la

lua_modules = 	\
	elua_tvb.c \
	elua_proto.c \
	elua_tree.c \
	elua_pinfo.c \
	elua_tap.c \
	elua_gui.c \
	elua_util.c \
	elua_field.c \
	elua_dumper.c

lua_la_SOURCES = \
	$(lua_modules) \
	elua.c \
	elua.h \
	elua_plugin.c

lua_la_LDFLAGS = -module -avoid-version
lua_la_LIBADD = @PLUGIN_LIBS@ @LUA_LIBS@

pkgdata_DATA = init.lua

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

CLEANFILES = \
	*~

DISTCLEANFILES = \
	dummy

MAINTAINERCLEANFILES = \
	doc/*.pod	\
	Makefile.in	\
	elua_register.h \
	init.lua

EXTRA_DIST = \
	elua_register.h \
	elua_makereg.pl \
	template-init.lua \
	make-init-lua.pl \
	Makefile.nmake

elua.h: elua_register.h

# do not do not unnecessarilly modify the old file in order avoid recompiling every module every time 
elua_register.h: elua_makereg.pl $(lua_modules)
	$(PERL) elua_makereg.pl $(lua_modules) > elua_register.h.new
	if diff elua_register.h.new elua_register.h >/dev/null; then rm elua_register.h.new; else mv elua_register.h.new elua_register.h; fi

doc: $(lua_modules)
	$(PERL) elua_makedoc.pl $^

dummy:
	touch dummy

init.lua: template-init.lua make-init-lua.pl ../../epan/ftypes/ftypes.h ../../wiretap/wtap.h  ../../epan/proto.h
	$(PERL) make-init-lua.pl template-init.lua > init.lua
