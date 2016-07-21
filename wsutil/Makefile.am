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
	-DPLUGIN_INSTALL_DIR=\"$(plugindir)\"	\
	$(GLIB_CFLAGS) $(LIBGCRYPT_CFLAGS)

# Optional headers for ABI checking
wsutil_optional_abi_includes =

if HAVE_OS_X_FRAMEWORKS
wsutil_optional_abi_includes += cfutils.h
endif

# Header files that don't declare replacement functions for functions
# present in the APIs/ABIs of some, but not all, targets.
libwsutil_nonrepl_INCLUDES = \
	adler32.h		\
	aes.h			\
	base64.h		\
	bits_count_ones.h	\
	bits_ctz.h		\
	bitswap.h		\
	buffer.h		\
	clopts_common.h		\
	cmdarg_err.h		\
	copyright_info.h	\
	crash_info.h		\
	crc6.h			\
	crc7.h			\
	crc8.h			\
	crc10.h			\
	crc11.h			\
	crc16.h			\
	crc16-plain.h		\
	crc32.h			\
	des.h			\
	eax.h			\
	filesystem.h		\
	frequency-utils.h	\
	g711.h			\
	inet_addr.h		\
	inet_ipv6.h		\
	interface.h		\
	jsmn.h			\
	md4.h			\
	md5.h			\
	mpeg-audio.h		\
	nstime.h		\
	os_version_info.h	\
	pint.h			\
	plugins.h		\
	privileges.h		\
	processes.h		\
	rc4.h			\
	report_err.h		\
	sha1.h			\
	sha2.h			\
	sign_ext.h		\
	sober128.h		\
	str_util.h		\
	strnatcmp.h		\
	tempfile.h		\
	time_util.h		\
	type_util.h		\
	unicode-utils.h 	\
	utf8_entities.h		\
	ws_cpuid.h		\
	ws_mempbrk.h		\
	ws_mempbrk_int.h	\
	ws_printf.h

# Header files for functions in libwsutil's ABI on this platform.
libwsutil_abi_INCLUDES = \
	$(libwsutil_nonrepl_INCLUDES)	\
	$(wsutil_optional_abi_includes)

# Optional objects that I know how to build. These will be
# linked into libwsutil if necessary.
wsutil_optional_objects =

if SSE42_SUPPORTED
wsutil_optional_objects += libwsutil_sse42.la
endif

noinst_LTLIBRARIES = libwsutil_sse42.la

lib_LTLIBRARIES = libwsutil.la

libwsutil_la_SOURCES = \
	$(libwsutil_nonrepl_INCLUDES)	\
	adler32.c		\
	aes.c			\
	airpdcap_wep.c		\
	base64.c		\
	bitswap.c		\
	buffer.c		\
	clopts_common.c		\
	cmdarg_err.c		\
	copyright_info.c	\
	crash_info.c		\
	crc6.c			\
	crc7.c			\
	crc8.c			\
	crc10.c			\
	crc11.c			\
	crc16.c			\
	crc16-plain.c		\
	crc32.c			\
	des.c			\
	eax.c			\
	filesystem.c		\
	frequency-utils.c	\
	g711.c			\
	inet_addr.c		\
	interface.c		\
	jsmn.c			\
	md4.c			\
	md5.c			\
	mpeg-audio.c		\
	nstime.c		\
	os_version_info.c	\
	plugins.c		\
	privileges.c		\
	rc4.c			\
	report_err.c		\
	sha1.c			\
	sha2.c			\
	sober128.c		\
	str_util.c		\
	strnatcmp.c		\
	tempfile.c		\
	time_util.c		\
	type_util.c		\
	unicode-utils.c		\
	ws_mempbrk.c

if HAVE_OS_X_FRAMEWORKS
libwsutil_la_SOURCES += cfutils.c cfutils.h
endif

libwsutil_sse42_la_SOURCES = \
	ws_mempbrk_sse42.c

libwsutil_sse42_la_CFLAGS = $(AM_CFLAGS) $(CFLAGS_SSE42)

# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libwsutil_la_LDFLAGS = -version-info 7:0:0 @LDFLAGS_SHAREDLIB@

libwsutil_la_LIBADD = \
	$(LTLIBOBJS)			\
	@COREFOUNDATION_FRAMEWORKS@	\
	@GLIB_LIBS@			\
	@LIBGCRYPT_LIBS@		\
	$(wsutil_optional_objects)

EXTRA_libwsutil_la_DEPENDENCIES = \
	$(wsutil_optional_objects)

EXTRA_DIST = \
	.editorconfig		\
	cfutils.c		\
	cfutils.h		\
	CMakeLists.txt		\
	file_util.c		\
	file_util.h		\
	getopt_long.c		\
	getopt_long.h		\
	inet_addr-int.h		\
	inet_aton.c		\
	inet_aton.h		\
	inet_ntop.c		\
	inet_pton.c		\
	popcount.c		\
	popcount.h		\
	strptime.c		\
	strptime.h		\
	win32-utils.c		\
	win32-utils.h		\
	ws_mempbrk_sse42.c	\
	wsgcrypt.h		\
	wsgetopt.h

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
