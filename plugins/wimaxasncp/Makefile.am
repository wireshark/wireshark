# Makefile.am
# Automake file for wimaxasncp plugin
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
#

include Makefile.common
include $(top_srcdir)/Makefile.am.inc
include ../Makefile.am.inc

noinst_LTLIBRARIES = wimaxasncp-generated.la

plugin_LTLIBRARIES = wimaxasncp.la

wimaxasncp_generated_la_SOURCES = \
	$(FLEX_GENERATED_C_FILES)	\
	$(FLEX_GENERATED_HEADER_FILES)

wimaxasncp_generated_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

wimaxasncp_generated_la_CFLAGS = $(GENERATED_CFLAGS) $(PLUGIN_CFLAGS)

wimaxasncp_generated_la_LDFLAGS = $(PLUGIN_LDFLAGS)

wimaxasncp_la_SOURCES = \
	plugin.c	\
	moduleinfo.h	\
	$(CLEAN_SRC_FILES)	\
	$(CLEAN_HEADER_FILES)

wimaxasncp_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

wimaxasncp_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

wimaxasncp_la_LDFLAGS = $(PLUGIN_LDFLAGS)

wimaxasncp_la_DEPENDENCIES = wimaxasncp-generated.la

CLEANFILES = \
	wimaxasncp \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in	      \
	$(GENERATED_SRC_FILES) \
	$(GENERATED_HEADER_FILES) \
	plugin.c

EXTRA_DIST = \
	Makefile.common		\
	Makefile.nmake		\
	moduleinfo.nmake	\
	plugin.rc.in		\
	wimaxasncp_dict.l	\
	CMakeLists.txt

wimaxasncp_dict_lex.h:	wimaxasncp_dict.c

wimaxasncp_dict.c:	wimaxasncp_dict.h

#
# Install the wimaxasncp DTD and XML files in the "wimaxasncp"
# subdirectory of $(pkgdatadir)
#
wimaxasncpdir = $(pkgdatadir)/wimaxasncp
