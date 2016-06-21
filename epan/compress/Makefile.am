# Makefile.am
# Automake file for the compress for Wireshark
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

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS)

noinst_LTLIBRARIES = liblzxpress.la

liblzxpress_la_SOURCES = \
	lzxpress.c	\
	lzxpress.h

EXTRA_DIST =

CLEANFILES = \
	liblzxpress.a	\
	liblzxpress.la	\
	*~

DISTCLEANFILES =

MAINTAINERCLEANFILES = \
	Makefile.in

checkapi:
	$(PERL) ../../tools/checkAPIs.pl -g termoutput -build \
	$(liblzxpress_la_SOURCES)
