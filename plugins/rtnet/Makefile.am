# Makefile.am
# Automake file for Ethereal/RTNET
#
# $Id: Makefile.am,v 1.1 2003/06/11 09:17:03 guy Exp $
#
# Ethereal - Network traffic analyzer
# By Steve Limkemann <stevelim@dgtech.com>
# Copyright 1998 Steve Limkemann
#
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

plugin_LTLIBRARIES = rtnet.la
rtnet_la_SOURCES = packet-rtnet.c moduleinfo.h
rtnet_la_LDFLAGS = -module -avoid-version

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

rtnet_la_DEPENDENCIES = packet-rtnet-static.o

packet-rtnet-static.o:	packet-rtnet.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-rtnet-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-rtnet.c 

CLEANFILES = \
	rtnet \
	*~

EXTRA_DIST = \
	Makefile.nmake
