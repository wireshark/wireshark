# Makefile.am
#
# $Id: $
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

INCLUDES = -I$(top_srcdir) -I./lua-5.0.2/include

plugindir = @plugindir@

plugin_LTLIBRARIES = work.la

work_la_SOURCES = \
    packet-lua.c \
	plugin.c

work_la_LDFLAGS = -module -avoid-version
work_la_LIBADD = @PLUGIN_LIBS@


# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS = -L./lua-5.0.2/lib -llua -llualib


CLEANFILES = \
	*~

DISTCLEANFILES = \
	dummy

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	dummy

dummy:
	touch dummy
    
