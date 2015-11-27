# Makefile.am
# Automake file for the libwscodec library for Wireshark
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

AM_CPPFLAGS += -I$(top_srcdir)/wiretap -DWS_BUILD_DLL

CLEANFILES = \
	libwscodec.la	\
	*~

MAINTAINERCLEANFILES =	\
	Makefile.in

lib_LTLIBRARIES = libwscodecs.la
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libwscodecs_la_LDFLAGS = -version-info 0:0:0 @LDFLAGS_SHAREDLIB@

# All sources that should be put in the source distribution tarball
libwscodecs_la_SOURCES = \
	$(LIBWSCODECS_SRC) \
	$(noinst_HEADERS)

libwscodecs_la_DEPENDENCIES = ${top_builddir}/wsutil/libwsutil.la

libwscodecs_la_LIBADD = ${top_builddir}/wsutil/libwsutil.la

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(LIBWSCODECS_SRC)

EXTRA_DIST = \
	CMakeLists.txt			\
	Makefile.common			\
	Makefile.nmake
