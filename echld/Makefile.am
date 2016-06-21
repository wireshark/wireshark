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

AM_CPPFLAGS = -DWS_BUILD_DLL $(INCLUDEDIRS) $(WS_CPPFLAGS) \
	$(GLIB_CFLAGS)

lib_LTLIBRARIES = libechld.la

libechld_la_SOURCES = \
	echld-util.c	\
	dispatcher.c	\
	child.c		\
	parent.c	\
	common.c	\
	echld-int.h	\
	echld-util.h	\
	echld.h

libechld_la_LDFLAGS = -version-info 0:0:0 @LDFLAGS_SHAREDLIB@

libechld_la_LIBADD =			\
	../caputils/libcaputils.a	\
	../epan/libwireshark.la		\
	../wsutil/libwsutil.la		\
	../wiretap/libwiretap.la	\
	@GLIB_LIBS@

libechld_la_DEPENDENCIES = \
	../caputils/libcaputils.a	\
	../epan/libwireshark.la		\
	../wiretap/libwiretap.la	\
	../wsutil/libwsutil.la

EXTRA_DIST = \
	CMakeLists.txt

CLEANFILES = \
	libechld.a	\
	libechld.la	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

