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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

INCLUDES = -I$(top_srcdir) @LUA_INCLUDES@

noinst_LTLIBRARIES = libwslua.la

wslua_modules = 	\
	wslua_tvb.c \
	wslua_proto.c \
	wslua_tree.c \
	wslua_pinfo.c \
	wslua_listener.c \
	wslua_gui.c \
	wslua_util.c \
	wslua_field.c \
	wslua_dumper.c

libwslua_la_SOURCES = \
	$(wslua_modules) \
	taps_wslua.c \
	register_wslua.c \
	init_wslua.c \
	wslua.h

libwslua_la_LIBADD = @LUA_LIBS@

BUILT_SOURCES = \
	taps_wslua.c \
	register_wslua.c \
	declare_wslua.h

pkgdata_DATA = \
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
	doc/*.pod	\
	init.lua

EXTRA_DIST = \
	declare_wslua.h \
	register_wslua.c \
	taps \
	make-reg.pl \
	make-doc.pl \
	template-init.lua \
	make-init-lua.pl \
	make-taps.pl \
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

doc: make-doc.pl $(wslua_modules) template-wsluarm.xml
	$(PERL) $(srcdir)/make-doc.pl $(wslua_modules)

dummy:
	touch dummy

init.lua: template-init.lua make-init-lua.pl ../ftypes/ftypes.h ../../wiretap/wtap.h  ../proto.h
	$(PERL) $(srcdir)/make-init-lua.pl template-init.lua > init.lua
