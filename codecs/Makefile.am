# Makefile.am
# Automake file for the libcodec library for Wireshark
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
include ../Makefile.am.inc

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

noinst_LIBRARIES = libcodec.a

CLEANFILES = \
	libcodec.a	\
	*~

MAINTAINERCLEANFILES =	\
	Makefile.in

# All sources that should be put in the source distribution tarball
libcodec_a_SOURCES = \
	$(LIBCODEC_SRC) \
	$(noinst_HEADERS)

libcodec_a_DEPENDENCIES = 

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(LIBCODEC_SRC)

EXTRA_DIST = \
	CMakeLists.txt			\
	Makefile.common			\
	Makefile.nmake
