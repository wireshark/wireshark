# Makefile.am
# Automake file for Filetap
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

lib_LTLIBRARIES = libfiletap.la
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libfiletap_la_LDFLAGS = -version-info 0:0:0 @LDFLAGS_SHAREDLIB@

AM_NON_GENERATED_CFLAGS =-DWS_BUILD_DLL

if HAVE_WARNINGS_AS_ERRORS
AM_NON_GENERATED_CFLAGS += -Werror
endif

AM_CPPFLAGS = -I$(srcdir)/..

CLEANFILES = \
	libfiletap.a		\
	libfiletap.la		\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

libfiletap_la_SOURCES = \
	$(NONGENERATED_C_FILES)	\
	$(NONGENERATED_HEADER_FILES)
libfiletap_la_CFLAGS = $(AM_NON_GENERATED_CFLAGS)

EXTRA_DIST = \
	Makefile.common		\
	Makefile.nmake

libfiletap_la_LIBADD = ${top_builddir}/wsutil/libwsutil.la $(GLIB_LIBS)
libfiletap_la_DEPENDENCIES = ${top_builddir}/wsutil/libwsutil.la

# ABI compliance checker can be obtained from
# http://ispras.linux-foundation.org/index.php/ABI_compliance_checker
# Checked using version 1.21.12
dumpabi-libfiletap: all abi-descriptor.xml
	rm -rf abi-check-headers abi_dumps .libs/*.abi.tar.gz
	mkdir abi-check-headers
	cp *.h ../ws_symbol_export.h abi-check-headers/
	abi-compliance-checker -l libfiletap -v1 `readlink .libs/libfiletap.so | sed 's/.*\.so\.//'` \
		-relpath $(abs_srcdir) -dump-abi abi-descriptor.xml || \
		cat logs/libfiletap/[0-9]*/log.txt
	cp -f abi_dumps/libfiletap/libfiletap_* .libs/
	cd .libs && ln -sf libfiletap_*.abi.tar.gz libfiletap.abi.tar.gz

checkapi:
## 'abort' checking disabled for now pending resolution of existing use of g_assert & g_error
##	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput \
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(NONGENERATED_C_FILES)
