# Makefile.am
# Automake file for Ethereal
#
# $Id: Makefile.am,v 1.29 2004/01/25 18:52:33 gerald Exp $
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

SUBDIRS = acn asn1 artnet docsis enttec giop gryphon irda lwres megaco mgcp pcli rdm rtnet v5ua

plugindir = @plugindir@

ADDRESS_EXPORT_FILES = \
	Xass-list	\
	Xplugin_api.c	\
	Xplugin_api.h	\
	Xplugin_api_decls.h	\
	Xplugin_table.h

$(ADDRESS_EXPORT_FILES): xyzzy plugin_gen.py plugin_api.c plugin_api_list.c
	$(PYTHON) $(srcdir)/plugin_gen.py xyzzy

xyzzy: plugin_api_list.c
	gcc -aux-info xyzzy -DHAVE_CONFIG_H $(GLIB_CFLAGS) -I$(top_srcdir) -I$(top_builddir) -c $(srcdir)/plugin_api_list.c

EXTRA_DIST = \
	plugin_api.c	\
	plugin_api.h	\
	plugin_api_decls.h	\
	plugin_api_defs.h	\
	plugin_api_list.c	\
	plugin_gen.py	\
	plugin_table.h	\
	Makefile.nmake	\
	README.interface	\
	Xass-list	\
	Xplugin_api.c	\
	Xplugin_api.h	\
	Xplugin_api_decls.h	\
	Xplugin_table.h

DISTCLEANFILES = \
	Xass-list	\
	Xplugin_api.c	\
	Xplugin_api.h	\
	Xplugin_api_decls.h	\
	Xplugin_table.h	\
	xyzzy

CLEANFILES = \
	plugin_api_list.o
