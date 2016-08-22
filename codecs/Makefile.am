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

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = -DWS_BUILD_DLL $(INCLUDEDIRS) $(WS_CPPFLAGS) \
	$(GLIB_CFLAGS) $(SBC_CFLAGS)

lib_LTLIBRARIES = libwscodecs.la

# All sources that should be put in the source distribution tarball
libwscodecs_la_SOURCES = \
	codecs.c		\
	G711a/G711adecode.c	\
	G711u/G711udecode.c	\
	G722/G722decode.c	\
	G726/G726decode.c

if HAVE_SBC
libwscodecs_la_SOURCES += sbc/sbc.c
endif

if !HAVE_SPEEXDSP
libwscodecs_la_SOURCES += speex/resample.c
endif

# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libwscodecs_la_LDFLAGS = -version-info 1:0:0 @LDFLAGS_SHAREDLIB@

libwscodecs_la_LIBADD = $(top_builddir)/wsutil/libwsutil.la $(GLIB_LIBS) $(SBC_LIBS)

libwscodecs_la_DEPENDENCIES = $(top_builddir)/wsutil/libwsutil.la

noinst_HEADERS = \
	codecs.h \
	G711a/G711adecode.h \
	G711a/G711atable.h \
	G711u/G711udecode.h \
	G711u/G711utable.h \
	G722/G722decode.h \
	G726/G726decode.h \
	sbc/sbc_private.h \
	speex/arch.h \
	speex/speex_resampler.h \
	speex/stack_alloc.h

EXTRA_DIST = \
	CMakeLists.txt			\
	speex/README.txt

CLEANFILES = \
	libwscodec.la	\
	*~

MAINTAINERCLEANFILES =	\
	Makefile.in

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(libwscodecs_la_SOURCES)
