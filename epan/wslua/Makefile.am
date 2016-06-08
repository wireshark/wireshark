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

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(LUA_CFLAGS) \
	$(GLIB_CFLAGS)

noinst_LTLIBRARIES = libwslua.la

wslua_modules = 		\
	lrexlib.c		\
	lrexlib_glib.c		\
	lrexlib_glib_f.c	\
	lua_bitop.c		\
	wslua_address.c		\
	wslua_byte_array.c	\
	wslua_capture_info.c	\
	wslua_column.c		\
	wslua_dir.c		\
	wslua_dissector.c	\
	wslua_dumper.c		\
	wslua_field.c		\
	wslua_file.c		\
	wslua_file_common.c	\
	wslua_file_handler.c	\
	wslua_frame_info.c	\
	wslua_gui.c		\
	wslua_int64.c		\
	wslua_internals.c	\
	wslua_listener.c	\
	wslua_nstime.c		\
	wslua_pinfo.c		\
	wslua_pref.c		\
	wslua_proto.c		\
	wslua_proto_expert.c	\
	wslua_proto_field.c	\
	wslua_struct.c		\
	wslua_tree.c		\
	wslua_tvb.c		\
	wslua_util.c

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
	.editorconfig		\
	declare_wslua.h		\
	lua_bitop.h		\
	lrexlib.h 		\
	lrexlib_algo.h 		\
	wslua_file_common.h 	\
	wslua_pinfo_common.h 	\
	lrexlib_algo.h 		\
	register_wslua.c	\
	taps			\
	make-reg.pl		\
	template-init.lua	\
	make-init-lua.pl	\
	make-taps.pl		\
	CMakeLists.txt

taps_used = \
	$(top_srcdir)/epan/dissectors/packet-http.h \
	$(top_srcdir)/epan/dissectors/packet-ip.h \
	$(top_srcdir)/epan/dissectors/packet-udp.h \
	$(top_srcdir)/epan/dissectors/packet-h225.h \
	$(top_srcdir)/epan/dissectors/packet-ieee80211.h

taps_wslua.c: make-taps.pl $(srcdir)/taps $(taps_used)
	$(AM_V_PERL)$(PERL) $(srcdir)/make-taps.pl $(srcdir)/taps taps_wslua.c taps.txt $(srcdir)

taps.txt: taps_wslua.c

wslua.h: declare_wslua.h

register_wslua.c: declare_wslua.h

declare_wslua.h: make-reg.pl $(wslua_modules) taps_wslua.c
	$(AM_V_PERL)$(PERL) $(srcdir)/make-reg.pl -d $(srcdir) $(wslua_modules)

init.lua: template-init.lua make-init-lua.pl $(top_srcdir)/epan/ftypes/ftypes.h $(top_srcdir)/wiretap/wtap.h  $(top_srcdir)/epan/proto.h $(top_srcdir)/epan/stat_groups.h
	$(AM_V_PERL)$(PERL) $(srcdir)/make-init-lua.pl $(top_srcdir) $(srcdir)/template-init.lua > init.lua

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
