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
	init_wslua.c \
	wslua.h

libwslua_la_LIBADD = @LUA_LIBS@

BUILT_SOURCES = \
	taps.c-inc \
	wslua_register.h

pkgdata_DATA = init.lua

CLEANFILES = \
	*~

DISTCLEANFILES = \
	taps.c-inc \
	taps.txt \
	wslua_register.h

MAINTAINERCLEANFILES = \
	Makefile.in	\
	doc/*.pod	\
	init.lua

EXTRA_DIST = \
	wslua_register.h \
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

taps.c-inc: make-taps.pl taps
	$(PERL) $(srcdir)/make-taps.pl taps taps.c-inc taps.txt

taps.txt: taps.c-inc
	
wslua.h: wslua_register.h

# do not do not unnecessarilly modify the old file in order avoid recompiling every module every time 
wslua_register.h: make-reg.pl $(lua_modules) taps.c-inc
	$(PERL) $(srcdir)/make-reg.pl \
		wslua_tvb.c \
		wslua_proto.c \
		wslua_tree.c \
		wslua_pinfo.c \
		wslua_listener.c \
		wslua_gui.c \
		wslua_util.c \
		wslua_field.c \
		wslua_dumper.c > wslua_register.h.new ;\
	if diff wslua_register.h.new wslua_register.h >/dev/null; then rm wslua_register.h.new; else mv wslua_register.h.new wslua_register.h; fi

doc: make-doc.pl $(lua_modules)
	$(PERL) $(srcdir)/make-doc.pl \
		wslua_tvb.c \
		wslua_proto.c \
		wslua_tree.c \
		wslua_pinfo.c \
		wslua_listener.c \
		wslua_gui.c \
		wslua_util.c \
		wslua_field.c \
		wslua_dumper.c

dummy:
	touch dummy

init.lua: template-init.lua make-init-lua.pl ../ftypes/ftypes.h ../../wiretap/wtap.h  ../proto.h
	$(PERL) $(srcdir)/make-init-lua.pl template-init.lua > init.lua
