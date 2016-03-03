# Makefile.am
# Automake file for MATE Wireshark plugin
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

include Makefile.common
include $(top_srcdir)/Makefile.am.inc
include ../Makefile.am.inc

#
# XXX - how to make this apply only to clean files?
#
#if HAVE_WARNINGS_AS_ERRORS
#AM_CFLAGS += -Werror
#endif

plugin_LTLIBRARIES = mate.la

mate_la_SOURCES = \
	plugin.c	\
	moduleinfo.h	\
	$(SRC_FILES)	\
	$(HEADER_FILES)

nodist_mate_la_SOURCES = \
	$(NODIST_SRC_FILES) \
	$(NODIST_HEADER_FILES)

mate_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

mate_la_CFLAGS = $(GENERATED_CFLAGS) $(PLUGIN_CFLAGS)

mate_la_LDFLAGS = $(PLUGIN_LDFLAGS)

BUILT_SOURCES = \
	$(LEMON_GENERATED_HEADER_FILES)

CLEANFILES = \
	mate \
	*~

DISTCLEANFILES = \
	mate_grammar.out \
	$(NODIST_SRC_FILES) \
	$(NODIST_HEADER_FILES)

MAINTAINERCLEANFILES = \
	Makefile.in \
	$(GENERATED_SRC_FILES) \
	$(GENERATED_HEADER_FILES) \
	plugin.c

EXTRA_DIST = \
	mate_grammar.lemon	\
	mate_parser.l		\
	Makefile.common		\
	Makefile.nmake		\
	moduleinfo.nmake	\
	plugin.rc.in		\
	CMakeLists.txt		\
	examples/call.mate	\
	examples/mms.mate	\
	examples/pasv_ftp.mate	\
	examples/tcp.mate	\
	examples/web.mate	\
	matelib/dns.mate	\
	matelib/h225_ras.mate	\
	matelib/isup.mate	\
	matelib/megaco.mate	\
	matelib/q931.mate	\
	matelib/radius.mate	\
	matelib/rtsp.mate	\
	matelib/sip.mate

mate_parser_lex.h : mate_parser.c

mate_grammar.h : mate_grammar.c
mate_grammar.c : mate_grammar.lemon mate.h mate_util.h $(LEMON)
	$(AM_V_LEMON)$(LEMON) T=$(lemon_srcdir)/lempar.c $(srcdir)/mate_grammar.lemon || \
		(rm -f grammar.c grammar.h ; false)
