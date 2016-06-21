# Makefile.am
# Automake file for libnghttp2 library
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

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(LIBNGHTTP2_CFLAGS) \
	$(GLIB_CFLAGS)

noinst_LTLIBRARIES = libnghttp2.la

libnghttp2_la_SOURCES =	\
	nghttp2_buf.c			\
	nghttp2_hd.c			\
	nghttp2_hd_huffman.c		\
	nghttp2_hd_huffman_data.c	\
	nghttp2_helper.c		\
	nghttp2_mem.c			\
	nghttp2_rcbuf.c			\
	nghttp2_buf.h			\
	nghttp2_hd.h			\
	nghttp2_hd_huffman.h		\
	nghttp2_helper.h		\
	nghttp2_int.h			\
	nghttp2_mem.h			\
	nghttp2_rcbuf.h			\
	nghttp2.h			\
	nghttp2ver.h

EXTRA_DIST = \
	.editorconfig	\
	README.nghttp2	\
	CMakeLists.txt

CLEANFILES = \
	libnghttp2.a	\
	libnghttp2.la	\
	*~

DISTCLEANFILES =

MAINTAINERCLEANFILES =	\
	Makefile.in

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
