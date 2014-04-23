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

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

AM_CPPFLAGS = -I$(top_srcdir)

plugindir = @plugindir@

plugin_LTLIBRARIES = tpg.la

tpg_la_SOURCES = \
	moduleinfo.h	\
	http-parser.c \
	http-parser.h \
	packet-http.c

tpg_la_LDFLAGS = -module -avoid-version
tpg_la_LIBADD = @PLUGIN_LIBS@

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

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
	Makefile.nmake	\
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
