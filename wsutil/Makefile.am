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

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) -DWS_BUILD_DLL \
	-DTOP_SRCDIR=\"$(abs_top_srcdir)\" 	\
	-DDATAFILE_DIR=\"$(pkgdatadir)\" 	\
	-DEXTCAP_DIR=\"$(extcapdir)\" 		\
	-DPLUGIN_INSTALL_DIR=\"$(plugindir)\"	\
	$(GLIB_CFLAGS) $(LIBGCRYPT_CFLAGS)

# Optional headers for ABI checking
wsutil_optional_abi_includes =

if HAVE_OS_X_FRAMEWORKS
wsutil_optional_abi_includes += cfutils.h
endif

# Header files for functions in libwsutil's ABI on this platform.
libwsutil_abi_INCLUDES = 	\
	$(libwsutil_nonrepl_INCLUDES)	\
	$(wsutil_optional_abi_includes)

# Optional objects that I know how to build. These will be
# linked into libwsutil if necessary.
wsutil_optional_objects = \
	@FLOORL_LO@		\
	@GETOPT_LO@		\
	@INET_ATON_LO@		\
	@INET_NTOP_LO@		\
	@INET_PTON_LO@		\
	@POPCOUNT_LO@		\
	@STRPTIME_LO@

if SSE42_SUPPORTED
wsutil_optional_objects += libwsutil_sse42.la
endif

noinst_LTLIBRARIES = libwsutil_sse42.la

lib_LTLIBRARIES = libwsutil.la
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libwsutil_la_LDFLAGS = -version-info 0:0:0 @LDFLAGS_SHAREDLIB@

LIBWSUTIL_SRC = $(LIBWSUTIL_COMMON_SRC)
LIBWSUTIL_INCLUDES = $(LIBWSUTIL_COMMON_INCLUDES)

if HAVE_OS_X_FRAMEWORKS
LIBWSUTIL_SRC += cfutils.c
LIBWSUTIL_INCLUDES += cfutils.h
endif

libwsutil_la_SOURCES = \
	$(LIBWSUTIL_SRC)	\
	$(LIBWSUTIL_INCLUDES)

libwsutil_sse42_la_SOURCES = \
	ws_mempbrk_sse42.c

libwsutil_sse42_la_CFLAGS = $(AM_CFLAGS) $(CFLAGS_SSE42)

EXTRA_libwsutil_la_SOURCES = \
	floorl.c		\
	floorl.h		\
	inet_aton.c		\
	inet_aton.h		\
	inet_ntop.c		\
	inet_pton.c		\
	inet_addr-int.h		\
	popcount.c		\
	popcount.h		\
	strptime.c		\
	strptime.h		\
	wsgetopt.c		\
	wsgetopt.h		\
	wsgetopt_int.h

libwsutil_la_DEPENDENCIES = \
	$(wsutil_optional_objects)

libwsutil_la_LIBADD = \
	@COREFOUNDATION_FRAMEWORKS@	\
	@GLIB_LIBS@		\
	@LIBGCRYPT_LIBS@	\
	$(wsutil_optional_objects)

EXTRA_DIST = \
	cfutils.c	\
	cfutils.h	\
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
	cp ../config.h ../ws_symbol_export.h $(libwsutil_abi_INCLUDES) abi-check-headers/
	abi-compliance-checker -log-path abi_logs/log.txt -l libwsutil -v1 `readlink .libs/libwsutil.so | sed 's/.*\.so\.//'` \
		-relpath $(abs_srcdir) -dump-abi abi-descriptor.xml || \
		cat logs/libwsutil/[0-9]*/log.txt
	cp -f abi_dumps/libwsutil/libwsutil_* .libs/
	cd .libs && ln -sf libwsutil_*.abi.tar.gz libwsutil.abi.tar.gz

maintainer-clean-local: clean-dumpabi-libwsutil

.PHONY: clean-dumpabi-libwsutil

clean-dumpabi-libwsutil:
	rm -rf abi-check-headers abi_dumps .libs/*.abi.tar.gz abi_logs abi-descriptor.xml

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(LIBWSUTIL_SRC)

#	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput \
#	-sourcedir=$(srcdir) \
#	file_util.c unicode-utils.c

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
