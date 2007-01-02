# Makefile.am
# Automake file for MATE Wireshark plugin
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

INCLUDES = -I$(top_srcdir)

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
	http.tpg \
	Makefile.nmake

TPG = ../../tools/tpg

http-parser.h: http-parser.c

$(TPG)/TPG.pm: $(TPG)/TPG.yp
	cd $(TPG) && make

http-parser.c: http.tpg $(TPG)/tpg.pl $(TPG)/TPG.pm
	$(PERL) -I$(TPG) $(TPG)/tpg.pl http.tpg

