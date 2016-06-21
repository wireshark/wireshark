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
include ../Makefile.am.inc

plugin_LTLIBRARIES = tpg.la

tpg_la_SOURCES = \
	moduleinfo.h	\
	http-parser.c \
	http-parser.h \
	packet-http.c

tpg_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

tpg_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

tpg_la_LDFLAGS = $(PLUGIN_LDFLAGS)

CLEANFILES = \
	tpg \
	*~

DISTCLEANFILES = \
	http-parser.c \
	http-parser.h

MAINTAINERCLEANFILES = \
	Makefile.in	\
	http-parser.c	\
	http-parser.h 	\
	plugin.c

EXTRA_DIST = \
	http.tpg	\
	CMakeLists.txt

TPG = $(top_builddir)/tools/tpg

http-parser.h: http-parser.c

$(TPG)/TPG.pm: $(TPG)/TPG.yp
	cd $(TPG) && make

http-parser.c: http.tpg $(TPG)/tpg.pl $(TPG)/TPG.pm
	$(PERL) -I$(TPG) $(TPG)/tpg.pl http.tpg

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(DISSECTOR_SRC) $(DISSECTOR_INCLUDES)
