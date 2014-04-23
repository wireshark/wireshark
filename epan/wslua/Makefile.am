# Makefile.am
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

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

AM_CPPFLAGS = -I$(top_srcdir) @LUA_INCLUDES@

noinst_LTLIBRARIES = libwslua.la

wslua_modules = 	\
	$(srcdir)/lua_bitop.c \
	$(srcdir)/lrexlib.c \
	$(srcdir)/lrexlib_glib.c \
	$(srcdir)/lrexlib_glib_f.c \
	$(srcdir)/wslua_tvb.c \
	$(srcdir)/wslua_proto.c \
	$(srcdir)/wslua_int64.c \
	$(srcdir)/wslua_tree.c \
	$(srcdir)/wslua_pinfo.c \
	$(srcdir)/wslua_listener.c \
	$(srcdir)/wslua_gui.c \
	$(srcdir)/wslua_dir.c \
	$(srcdir)/wslua_util.c \
	$(srcdir)/wslua_field.c \
	$(srcdir)/wslua_file.c \
	$(srcdir)/wslua_struct.c \
	$(srcdir)/wslua_dumper.c \
	$(srcdir)/wslua_internals.c

libwslua_la_SOURCES = \
	$(wslua_modules) \
	taps_wslua.c \
	register_wslua.c \
	init_wslua.c \
	init_wslua.h \
	wslua.h

libwslua_la_LIBADD = @LUA_LIBS@

BUILT_SOURCES = \
	taps_wslua.c \
	register_wslua.c \
	declare_wslua.h

dist_pkgdata_DATA = \
	console.lua \
	dtd_gen.lua

nodist_pkgdata_DATA = \
	init.lua

CLEANFILES = \
	*~

DISTCLEANFILES = \
	$(BUILT_SOURCES) \
	taps.txt \
	wslua_register.h \
	init.lua

MAINTAINERCLEANFILES = \
	Makefile.in	\
	register_wslua.c \
	declare_wslua.h

EXTRA_DIST = \
	declare_wslua.h		\
	lua_bitop.h		\
	lrexlib.h 			\
	lrexlib_algo.h 		\
	register_wslua.c	\
	taps			\
	make-reg.pl		\
	template-init.lua	\
	make-init-lua.pl	\
	make-taps.pl		\
	Makefile.nmake		\
	CMakeLists.txt

taps_used = \
	../dissectors/packet-http.h \
	../dissectors/packet-ip.h \
	../dissectors/packet-udp.h \
	../dissectors/packet-h225.h \
	../dissectors/packet-ieee80211.h

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
	$(PERL) $(srcdir)/make-init-lua.pl $(top_srcdir) $(srcdir)/template-init.lua > init.lua

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	init_wslua.c \
	register_wslua.c \
	taps_wslua.c \
	lrexlib_glib.c \
	lrexlib_glib_f.c \
	wslua_dumper.c \
	wslua_field.c \
	wslua_file.c \
	wslua_gui.c \
	wslua_int64.c \
	wslua_pinfo.c \
	wslua_proto.c \
	wslua_struct.c \
	wslua_tree.c \
	wslua_tree.c \
	wslua_tvb.c \
	wslua_dir.c \
	wslua_util.c
