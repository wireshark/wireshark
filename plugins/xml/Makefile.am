# Makefile.am
# Automake file for XML Ethereal plugin
#
# $Id$
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
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
#

INCLUDES = -I$(top_srcdir)

plugindir = @plugindir@

plugin_LTLIBRARIES = xml.la
xml_la_SOURCES = moduleinfo.h \
	packet-xml.h \
	xml_lexer.l \
	packet-xml.c \
	xml_plugin.c
	
#	dtd.h dtd.c dtd_lexer.l dtd_prep.l dtd_parser.c dtd_parser.h

xml_la_LDFLAGS = -module -avoid-version
xml_la_LIBADD = @PLUGIN_LIBS@

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

CLEANFILES = \
	xml \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	Makefile.nmake \
	xml_lexer.l

#	dtd_parser.lemon dtd_prep.l \
#
#LEMON=../../tools/lemon
#
#dtd_parser.h : dtd_parser.c
#dtd_parser.c : dtd_parser.lemon
#	$(LEMON)/lemon t=$(srcdir)/$(lemon) $(srcdir)/dtd_parser.lemon || (rm -f dtd_parser.c dtd_parser.h false)
#
