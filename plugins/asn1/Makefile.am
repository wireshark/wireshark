# Makefile.am
# Automake file for Ethereal/asn1
#
# $Id: Makefile.am,v 1.1 2003/10/28 07:02:38 guy Exp $
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

plugin_LTLIBRARIES = asn1.la
asn1_la_SOURCES = packet-asn1.c moduleinfo.h
asn1_la_LDFLAGS = -module -avoid-version

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

packet-asn1-static.o:	packet-asn1.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-asn1-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-asn1.c 

CLEANFILES = asn1 *~

EXTRA_DIST = Makefile.nmake
