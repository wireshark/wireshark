# Makefile.am
#
# $Id: Makefile.am 48716 2013-04-03 07:38:44Z guy $
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

ACLOCAL_AMFLAGS = `../aclocal-flags`

# Optional objects that I know how to build. These will be
# linked into libechld.
echld_optional_objects =

include ../Makefile.am.inc

include Makefile.common

AM_CFLAGS =-DWS_BUILD_DLL

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS += -Werror
endif


lib_LTLIBRARIES = libechld.la
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libechld_la_LDFLAGS = -version-info 0:0:0 @LDFLAGS_SHAREDLIB@

AM_CPPFLAGS = -I$(srcdir)/..

libechld_la_SOURCES =		\
	$(LIBECHLD_SRC)	\
	$(LIBECHLD_INCLUDES)

EXTRA_libechld_la_SOURCES=	

libechld_la_DEPENDENCIES=	

libechld_la_LIBADD =		\
	@GLIB_LIBS@

EXTRA_DIST =		\
	CMakeLists.txt	\
	Makefile.common	\
	Makefile.nmake

CLEANFILES = \
	libechld.a	\
	libechld.la	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

bin_PROGRAMS =
	@echld_test_bin@

EXTRA_PROGRAMS = echld_test

echld_test_LDADD = \
	echld/libechld.la \
	@GLIB_LIBS@

echld_test_CFLAGS = $(AM_CLEAN_CFLAGS)

# ABI compliance checker can be obtained from
# http://ispras.linux-foundation.org/index.php/ABI_compliance_checker
# Checked using version 1.21.12
#dumpabi-libechld: all abi-descriptor.xml
#	rm -rf abi-check-headers abi_dumps .libs/*.abi.tar.gz
#	mkdir abi-check-headers
#	cp ../config.h ../ws_symbol_export.h *.h abi-check-headers/
#	abi-compliance-checker -l libechld -v1 `readlink .libs/libechld.so | sed 's/.*\.so\.//'` \
#		-relpath $(abs_srcdir) -dump-abi abi-descriptor.xml || \
#		cat logs/libechld/[0-9]*/log.txt
#	cp -f abi_dumps/libechld/libechld_* .libs/
#	cd .libs && ln -sf libechld_*.abi.tar.gz libechld.abi.tar.gz
#
#checkapi:
#	$(PERL) ../tools/checkAPIs.pl -g abort -g termoutput \
#	$(PERL) ../tools/checkAPIs.pl -g termoutput -build \
#	$(LIBWSUTIL_SRC)
#	file_util.c unicode-utils.c
