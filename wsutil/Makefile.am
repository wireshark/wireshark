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

SUBDIRS = nghttp2

DIST_SUBDIRS = $(SUBDIRS)

ACLOCAL_AMFLAGS = `../aclocal-flags`

# Optional objects that I know how to build. These will be
# linked into libwsutil.
wsutil_optional_objects =

if NEED_GETOPT_LO
wsutil_optional_objects += @GETOPT_LO@
endif

if NEED_INET_ATON_LO
wsutil_optional_objects += @INET_ATON_LO@
endif

if NEED_INET_NTOP_LO
wsutil_optional_objects += @INET_NTOP_LO@
endif

if NEED_INET_PTON_LO
wsutil_optional_objects += @INET_PTON_LO@
endif

if NEED_STRNCASECMP_LO
wsutil_optional_objects += @STRNCASECMP_LO@
endif

if NEED_STRPTIME_LO
wsutil_optional_objects += @STRPTIME_LO@
endif

if SSE42_SUPPORTED
wsutil_optional_objects += libwsutil_sse42.la
endif

include ../Makefile.am.inc

include Makefile.common

AM_CFLAGS =-DWS_BUILD_DLL

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS += -Werror
endif

noinst_LTLIBRARIES = libwsutil_sse42.la

lib_LTLIBRARIES = libwsutil.la
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libwsutil_la_LDFLAGS = -version-info 0:0:0 @LDFLAGS_SHAREDLIB@

AM_CPPFLAGS = -I$(srcdir)/.. \
	$(LIBGCRYPT_CFLAGS) \
	-DTOP_SRCDIR=\"$(abs_top_srcdir)\"

libwsutil_la_SOURCES =		\
	$(LIBWSUTIL_SRC)	\
	$(LIBWSUTIL_INCLUDES)

libwsutil_sse42_la_SOURCES = \
	ws_mempbrk_sse42.c

libwsutil_sse42_la_CFLAGS = $(AM_CFLAGS) @CFLAGS_SSE42@

EXTRA_libwsutil_la_SOURCES=	\
	inet_aton.c		\
	inet_aton.h		\
	inet_ntop.c		\
	inet_pton.c		\
	inet_v6defs.h		\
	strncasecmp.c		\
	strptime.c		\
	strptime.h		\
	wsgetopt.c		\
	wsgetopt.h		\
	wsgetopt_int.h

libwsutil_la_DEPENDENCIES=	\
	nghttp2/libnghttp2.la	\
	$(wsutil_optional_objects)

libwsutil_la_LIBADD =		\
	@COREFOUNDATION_FRAMEWORKS@	\
	@GLIB_LIBS@		\
	@LIBGCRYPT_LIBS@	\
	nghttp2/libnghttp2.la	\
	$(wsutil_optional_objects)

EXTRA_DIST =		\
	CMakeLists.txt	\
	Makefile.common	\
	Makefile.nmake	\
	file_util.c	\
	file_util.h	\
	wsgcrypt.h

CLEANFILES = \
	libwsutil.a	\
	libwsutil.la	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

# ABI compliance checker can be obtained from
# http://ispras.linux-foundation.org/index.php/ABI_compliance_checker
# Checked using version 1.21.12
dumpabi-libwsutil: all abi-descriptor.xml
	rm -rf abi-check-headers abi_dumps .libs/*.abi.tar.gz
	mkdir abi-check-headers
	cp ../config.h ../ws_symbol_export.h *.h abi-check-headers/
	abi-compliance-checker -l libwsutil -v1 `readlink .libs/libwsutil.so | sed 's/.*\.so\.//'` \
		-relpath $(abs_srcdir) -dump-abi abi-descriptor.xml || \
		cat logs/libwsutil/[0-9]*/log.txt
	cp -f abi_dumps/libwsutil/libwsutil_* .libs/
	cd .libs && ln -sf libwsutil_*.abi.tar.gz libwsutil.abi.tar.gz

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(LIBWSUTIL_SRC)

#	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput \
#	-sourcedir=$(srcdir) \
#	file_util.c unicode-utils.c

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
