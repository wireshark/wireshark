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

include Makefile.common
include $(top_srcdir)/Makefile.am.inc

ACLOCAL_AMFLAGS = `../aclocal-flags`

AM_CPPFLAGS = -DWS_BUILD_DLL $(INCLUDEDIRS) $(WS_CPPFLAGS) \
	$(GLIB_CFLAGS)

# Optional objects that I know how to build. These will be
# linked into libechld.
echld_optional_objects = $(LIBECHLD_SRC)

lib_LTLIBRARIES = libechld.la

libechld_la_LDFLAGS = -version-info 0:0:0 @LDFLAGS_SHAREDLIB@

libechld_la_SOURCES = \
	$(LIBECHLD_SRC)		\
	$(LIBECHLD_INCLUDES)

libechld_la_DEPENDENCIES = \
	../caputils/libcaputils.a	\
	../epan/libwireshark.la		\
	../wiretap/libwiretap.la	\
	../wsutil/libwsutil.la


libechld_la_LIBADD =			\
	../caputils/libcaputils.a	\
	../epan/libwireshark.la		\
	../wsutil/libwsutil.la		\
	../wiretap/libwiretap.la	\
	@GLIB_LIBS@

EXTRA_DIST = \
	CMakeLists.txt	\
	Makefile.common	\
	Makefile.nmake

CLEANFILES = \
	libechld.a	\
	libechld.la	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

