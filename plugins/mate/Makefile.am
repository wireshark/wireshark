# Makefile.am
# Automake file for MATE Ethereal plugin
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
#

INCLUDES = -I$(top_srcdir)

plugindir = @plugindir@

plugin_LTLIBRARIES = mate.la

mate_la_SOURCES = \
	mate.h		\
	mate_grammar.c	\
	mate_grammar.h	\
	mate_parser.c	\
	mate_plugin.c	\
	mate_runtime.c	\
	mate_setup.c	\
	mate_util.c	\
	mate_util.h	\
	moduleinfo.h	\
	packet-mate.c

mate_la_LDFLAGS = -module -avoid-version
mate_la_LIBADD = @PLUGIN_LIBS@

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

CLEANFILES = \
	mate \
	*~

DISTCLEANFILES = \
	mate_grammar.out	\
	mate_grammar.c		\
	mate_grammar.h

MAINTAINERCLEANFILES = \
	Makefile.in		\
	mate_grammar.c		\
	mate_grammar.h		\
	mate_grammar.out	\
	mate_parser.c

EXTRA_DIST = \
	mate_grammar.lemon \
	mate_parser.l \
	Makefile.nmake

mate_parser.c : mate_parser.l
	$(LEX) -Pdf_ -omate_parser.c $(srcdir)/mate_parser.l

LEMON = ../../tools/lemon

mate_grammar.h : mate_grammar.c
mate_grammar.c : mate_grammar.lemon mate.h mate_util.h $(LEMON)/lemon
	$(LEMON)/lemon t=$(srcdir)/$(LEMON)/lempar.c $(srcdir)/mate_grammar.lemon || \
		(rm -f grammar.c grammar.h ; false)

