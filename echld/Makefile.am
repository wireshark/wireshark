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

include ../Makefile.am.inc

ACLOCAL_AMFLAGS = `../aclocal-flags`

include Makefile.common

# Optional objects that I know how to build. These will be
# linked into libechld.
echld_optional_objects = $(LIBECHLD_SRC)


lib_LTLIBRARIES = libechld.la

libechld_la_LDFLAGS = -version-info 0:0:0 @LDFLAGS_SHAREDLIB@



AM_CFLAGS =-DWS_BUILD_DLL

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS += -Werror
endif

AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../wiretap

libechld_la_SOURCES = \
	$(LIBECHLD_SRC)		\
	$(LIBECHLD_INCLUDES)	\
	$(LIBECHLD_MORE_SRC)


libechld_la_DEPENDENCIES = \
	../epan/libwireshark.la		\
	../wiretap/libwiretap.la	\
	../wsutil/libwsutil.la


libechld_la_LIBADD =			\
	../epan/libwireshark.la		\
	../wsutil/libwsutil.la		\
	../wiretap/libwiretap.la	\
	@GLIB_LIBS@

EXTRA_DIST = \
	CMakeLists.txt	\
	Makefile.common

CLEANFILES = \
	libechld.a	\
	libechld.la	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

