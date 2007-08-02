# Makefile.am
#
# $Id$
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
#

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

INCLUDES = -I$(top_srcdir) @LUA_INCLUDES@

noinst_LTLIBRARIES = libwslua.la

libwslua_la_SOURCES = \
	$(MODULES) \
	taps_wslua.c \
	register_wslua.c \
	init_wslua.c \
	wslua.h

libwslua_la_LIBADD = @LUA_LIBS@

BUILT_SOURCES = \
	taps_wslua.c \
	register_wslua.c \
	declare_wslua.h

dist_pkgdata_DATA = \
	init.lua \
	console.lua \
	dtd_gen.lua

CLEANFILES = \
	*~

DISTCLEANFILES = \
	$(BUILT_SOURCES) \
	taps.txt \
	wslua_register.h

MAINTAINERCLEANFILES = \
	Makefile.in	\
	register_wslua.c \
	declare_wslua.h \
	init.lua

EXTRA_DIST = \
	declare_wslua.h \
	register_wslua.c \
	taps \
	make-reg.pl \
	template-init.lua \
	make-init-lua.pl \
	make-taps.pl \
	Makefile.common \
	Makefile.nmake

taps_used = \
	../dissectors/packet-http.h \
	../dissectors/packet-ip.h \
	../dissectors/packet-udp.h \
	../dissectors/packet-h225.h

taps: $(taps_used)
	touch taps

taps_wslua.c: make-taps.pl taps
	$(PERL) $(srcdir)/make-taps.pl taps taps_wslua.c taps.txt

taps.txt: taps_wslua.c
	
wslua.h: declare_wslua.h

register_wslua.c: declare_wslua.h

declare_wslua.h: make-reg.pl $(wslua_modules) taps_wslua.c
	$(PERL) $(srcdir)/make-reg.pl $(wslua_modules);

dummy:
	touch dummy

init.lua: template-init.lua make-init-lua.pl ../ftypes/ftypes.h ../../wiretap/wtap.h  ../proto.h ../../stat_menu.h
	$(PERL) $(srcdir)/make-init-lua.pl template-init.lua > init.lua
