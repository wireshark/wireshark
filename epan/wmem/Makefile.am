# Makefile.am
# Automake file for Wireshark Memory Manager
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

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(LIBWMEM_CFLAGS) \
	$(GLIB_CFLAGS)

noinst_LTLIBRARIES = libwmem.la

EXTRA_PROGRAMS = wmem_test

libwmem_la_SOURCES = \
	wmem_array.c			\
	wmem_core.c			\
	wmem_allocator_block.c		\
	wmem_allocator_block_fast.c	\
	wmem_allocator_simple.c		\
	wmem_allocator_strict.c		\
	wmem_list.c			\
	wmem_map.c			\
	wmem_miscutl.c			\
	wmem_scopes.c			\
	wmem_stack.c			\
	wmem_strbuf.c			\
	wmem_strutl.c			\
	wmem_tree.c			\
	wmem_interval_tree.c		\
	wmem_user_cb.c			\
	wmem.h				\
	wmem_array.h			\
	wmem_core.h			\
	wmem_allocator.h		\
	wmem_allocator_block.h		\
	wmem_allocator_block_fast.h    	\
	wmem_allocator_simple.h		\
	wmem_allocator_strict.h		\
	wmem_list.h			\
	wmem_map.h			\
	wmem_map_int.h			\
	wmem_miscutl.h			\
	wmem_queue.h			\
	wmem_scopes.h			\
	wmem_stack.h			\
	wmem_strbuf.h			\
	wmem_strutl.h			\
	wmem_tree.h			\
	wmem_tree-int.h			\
	wmem_interval_tree.h		\
	wmem_user_cb.h			\
	wmem_user_cb_int.h

wmem_test_SOURCES = wmem_test.c

wmem_test_LDADD = \
	libwmem.la \
	$(GLIB_LIBS) \
	../../wsutil/libwsutil.la

test-programs: wmem_test

CLEANFILES = \
	libwmem.a	\
	libwmem.la	\
	*~

DISTCLEANFILES =

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	CMakeLists.txt

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(libwmem_la_SOURCES)

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
