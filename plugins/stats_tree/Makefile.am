# Makefile.am
# Automake file for stats_tree Wireshark plugin
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

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = -I$(top_srcdir)

include Makefile.common

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

plugindir = @plugindir@

plugin_LTLIBRARIES = stats_tree.la

stats_tree_la_SOURCES = \
	$(SRC_FILES)	\
	$(HEADER_FILES)

stats_tree_la_LDFLAGS = -module -avoid-version
stats_tree_la_LIBADD = @PLUGIN_LIBS@

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

CLEANFILES = \
	stats_tree \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	Makefile.common		\
	Makefile.nmake		\
	moduleinfo.nmake	\
	plugin.rc.in		\
	CMakeLists.txt

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(CLEAN_SRC_FILES) $(CLEAN_HEADER_FILES)
