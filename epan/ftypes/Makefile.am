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

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) -I$(top_srcdir)/epan $(WS_CPPFLAGS) \
	$(GLIB_CFLAGS) $(LIBGNUTLS_CFLAGS) $(LIBGCRYPT_CFLAGS)

noinst_LTLIBRARIES = libftypes.la

libftypes_la_SOURCES = \
	ftypes.c	\
	ftype-bytes.c	\
	ftype-double.c	\
	ftype-ieee-11073-float.c	\
	ftype-integer.c	\
	ftype-ipv4.c	\
	ftype-ipv6.c	\
	ftype-guid.c	\
	ftype-none.c	\
	ftype-pcre.c	\
	ftype-protocol.c	\
	ftype-string.c	\
	ftype-time.c	\
	ftypes.h	\
	ftypes-int.h

EXTRA_DIST = \
	.editorconfig		\
	CMakeLists.txt

CLEANFILES = \
	libftypes.a	\
	libftypes.la	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(libftypes_la_SOURCES)
