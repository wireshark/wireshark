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

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) -DWS_BUILD_DLL \
	-DTOP_SRCDIR=\"$(abs_top_srcdir)\" 	\
	-DDATAFILE_DIR=\"$(pkgdatadir)\" 	\
	-DEXTCAP_DIR=\"$(extcapdir)\" 		\
	-DPLUGIN_DIR=\"$(pkglibdir)/plugins\"	\
	-DJSMN_STRICT				\
	$(GLIB_CFLAGS)				\
	$(PCAP_CFLAGS)				\
	$(LIBGCRYPT_CFLAGS)			\
	$(LIBGNUTLS_CFLAGS)

WSUTIL_PUBLIC_INCLUDES = \
	adler32.h		\
	base32.h		\
	base64.h		\
	bits_count_ones.h	\
	bits_ctz.h		\
	bitswap.h		\
	buffer.h		\
	clopts_common.h		\
	cmdarg_err.h		\
	color.h			\
	copyright_info.h	\
	cpu_info.h		\
	crash_info.h		\
	crc6.h			\
	crc7.h			\
	crc8.h			\
	crc10.h			\
	crc11.h			\
	crc16.h			\
	crc16-plain.h		\
	crc32.h			\
	eax.h			\
	filesystem.h		\
	frequency-utils.h	\
	g711.h			\
	glib-compat.h		\
	inet_addr.h		\
	inet_ipv4.h		\
	inet_ipv6.h		\
	interface.h		\
	jsmn.h			\
	mpeg-audio.h		\
	nstime.h		\
	os_version_info.h	\
	pint.h			\
	plugins.h		\
	privileges.h		\
	processes.h		\
	report_message.h	\
	rsa.h			\
	sign_ext.h		\
	sober128.h		\
	socket.h		\
	str_util.h		\
	strnatcmp.h		\
	strtoi.h		\
	tempfile.h		\
	time_util.h		\
	type_util.h		\
	unicode-utils.h 	\
	utf8_entities.h		\
	ws_cpuid.h		\
	ws_mempbrk.h		\
	ws_mempbrk_int.h	\
	ws_printf.h		\
	wsjsmn.h		\
	wsgcrypt.h		\
	wsgetopt.h		\
	wspcap.h		\
	xtea.h

WSUTIL_PRIVATE_INCLUDES =

subpkgincludedir = $(pkgincludedir)/wsutil

subpkginclude_HEADERS = \
	$(WSUTIL_PUBLIC_INCLUDES)

noinst_HEADERS = \
	$(WSUTIL_PRIVATE_INCLUDES)

# Optional objects that I know how to build. These will be
# linked into libwsutil if necessary.
wsutil_optional_objects =

if SSE42_SUPPORTED
wsutil_optional_objects += libwsutil_sse42.la
endif

noinst_LTLIBRARIES = libwsutil_sse42.la

lib_LTLIBRARIES = libwsutil.la

libwsutil_sse42_la_SOURCES = \
	ws_mempbrk_sse42.c

libwsutil_sse42_la_CFLAGS = $(AM_CFLAGS) $(CFLAGS_SSE42)

libwsutil_la_SOURCES = \
	adler32.c		\
	airpdcap_wep.c		\
	base32.c		\
	base64.c		\
	bitswap.c		\
	buffer.c		\
	clopts_common.c		\
	cmdarg_err.c		\
	copyright_info.c	\
	cpu_info.c		\
	crash_info.c		\
	crc6.c			\
	crc7.c			\
	crc8.c			\
	crc10.c			\
	crc11.c			\
	crc16.c			\
	crc16-plain.c		\
	crc32.c			\
	eax.c			\
	filesystem.c		\
	frequency-utils.c	\
	g711.c			\
	glib-compat.c		\
	inet_addr.c		\
	interface.c		\
	jsmn.c			\
	mpeg-audio.c		\
	nstime.c		\
	os_version_info.c	\
	plugins.c		\
	privileges.c		\
	report_message.c	\
	rsa.c			\
	sober128.c		\
	str_util.c		\
	strtoi.c		\
	strnatcmp.c		\
	tempfile.c		\
	time_util.c		\
	type_util.c		\
	unicode-utils.c		\
	ws_mempbrk.c		\
	wsgcrypt.c		\
	wsjsmn.c		\
	xtea.c

# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libwsutil_la_LDFLAGS = -version-info 0:0:0 @LDFLAGS_SHAREDLIB@

libwsutil_la_LIBADD = \
	$(LTLIBOBJS)			\
	$(GLIB_LIBS)			\
	$(LIBGCRYPT_LIBS)		\
	$(LIBGNUTLS_LIBS)		\
	$(wsutil_optional_objects)

EXTRA_libwsutil_la_DEPENDENCIES = \
	$(wsutil_optional_objects)

# Only source code files that may be built via LTLIBOBJS (besides files not
# built at all) must be added to EXTRA_DIST
EXTRA_DIST = \
	.editorconfig		\
	cfutils.c		\
	cfutils.h		\
	CMakeLists.txt		\
	file_util.c		\
	file_util.h		\
	getopt_long.c		\
	getopt_long.h		\
	popcount.c		\
	popcount.h		\
	strptime.c		\
	strptime.h		\
	win32-utils.c		\
	win32-utils.h

CLEANFILES = \
	libwsutil.a	\
	libwsutil.la	\
	*~

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(libwsutil_la_SOURCES)

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
