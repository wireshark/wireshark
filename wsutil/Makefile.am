# Makefile.am
#
# $Id$
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

ACLOCAL_AMFLAGS = `../aclocal-flags`

# Optional objects that I know how to build. These will be
# linked into libwsutil.
wsutil_optional_objects =

# filters for symbols to be omitted from libwsutil.sym
# symbols defined only on windows
def_sym_filter_symbols = /^getenv_utf8/ || /^ws_stdio/ || /^ws_init_dll_search_path/ || /^ws_load_library/ || /^ws_module_open/ || /^utf_[168]*to[168]/ || /^arg_list_utf_16to8/ || /^npf_sys_is_running/

if NEED_GETOPT_LO
wsutil_optional_objects += @GETOPT_LO@
else
def_sym_filter_symbols += || /^getopt/ || /^optarg/ || /^optind/ || /^opterr/ || /^optopt/
endif
 
if NEED_INET_ATON_LO
wsutil_optional_objects += @INET_ATON_LO@
else
def_sym_filter_symbols += || /^inet_aton/
endif
 
if NEED_INET_NTOP_LO
wsutil_optional_objects += @INET_NTOP_LO@
else
def_sym_filter_symbols += || /^ws_inet_ntop/
endif
 
if NEED_INET_PTON_LO
wsutil_optional_objects += @INET_PTON_LO@
else
def_sym_filter_symbols += || /^ws_inet_pton/
endif

if NEED_STRNCASECMP_LO
wsutil_optional_objects += @STRNCASECMP_LO@
else
def_sym_filter_symbols += || /^strncasecmp/
endif

if NEED_STRPTIME_LO
wsutil_optional_objects += @STRPTIME_LO@
else
def_sym_filter_symbols += || /^strptime/
endif

def_sym_filter_symbols += {next;};

include ../Makefile.am.inc

include Makefile.common

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

lib_LTLIBRARIES = libwsutil.la
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libwsutil_la_LDFLAGS = -version-info 0:0:0 -export-symbols libwsutil.sym @LDFLAGS_SHAREDLIB@

INCLUDES = -I$(srcdir)/..

libwsutil_la_SOURCES =		\
	$(LIBWSUTIL_SRC)	\
	$(LIBWSUTIL_INCLUDES)

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
	wsgetopt.h

libwsutil_la_DEPENDENCIES=	\
	$(wsutil_optional_objects) \
	libwsutil.sym

libwsutil_la_LIBADD =		\
	@GLIB_LIBS@		\
	$(wsutil_optional_objects)

EXTRA_DIST =		\
	Makefile.common	\
	Makefile.nmake	\
	file_util.c	\
	file_util.h 	\
	libwsutil.def	\
	unicode-utils.c	\
	unicode-utils.h

CLEANFILES = \
	libwsutil.a	\
	libwsutil.la	\
	libwsutil.sym	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

# ABI compliance checker can be obtained from
# http://ispras.linux-foundation.org/index.php/ABI_compliance_checker
# Checked using version 1.21.12
dumpabi: all abi-descriptor.xml
	rm -rf abi-check-headers abi_dumps .libs/*.abi.tar.gz; \
	mkdir abi-check-headers; cp *.h abi-check-headers/; \
	abi-compliance-checker -l libwsutil -v1 `ls  .libs/libwsutil.so.?.?.?|sed 's/.*\.so\.//'` \
		-relpath $(abs_srcdir) -dump-abi abi-descriptor.xml && \
	cp -f abi_dumps/libwsutil/libwsutil_* .libs/; \
	cd .libs; ln -sf libwsutil_*.abi.tar.gz libwsutil.abi.tar.gz

checkapi:
	$(PERL) ../tools/checkAPIs.pl -g abort -g termoutput \
	$(LIBWSUTIL_SRC)
#	file_util.c unicode-utils.c
