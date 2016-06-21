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
include ../Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = stats_tree

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES) \
	stats_tree_plugin.c	\
	pinfo_stats_tree.c

# Headers.
CLEAN_HEADER_FILES = \
	pinfo_stats_tree.h

HEADER_FILES = \
	$(CLEAN_HEADER_FILES)

plugin_LTLIBRARIES = stats_tree.la

stats_tree_la_SOURCES = \
	$(SRC_FILES)	\
	$(HEADER_FILES)

stats_tree_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

stats_tree_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

stats_tree_la_LDFLAGS = $(PLUGIN_LDFLAGS)

CLEANFILES = \
	stats_tree \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	plugin.rc.in		\
	CMakeLists.txt
