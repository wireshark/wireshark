# Makefile.am
# Automake file for Ethereal/docsis subdissectors
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

INCLUDES = -I$(top_srcdir) -I$(includedir)

plugindir = @plugindir@

plugin_LTLIBRARIES = docsis.la
docsis_la_SOURCES = packet-intrngreq.c packet-type29ucd.c packet-docsis.c packet-bpkmattr.c packet-dsarsp.c packet-macmgmt.c packet-rngrsp.c packet-bpkmreq.c packet-dscack.c packet-map.c packet-tlv.c packet-bpkmrsp.c packet-dscreq.c packet-regack.c packet-uccreq.c packet-dscrsp.c packet-regreq.c packet-uccrsp.c packet-dsaack.c packet-dsdreq.c packet-regrsp.c packet-ucd.c packet-dsareq.c packet-dsdrsp.c packet-rngreq.c packet-vendor.c packet-docsis.h packet-tlv.h moduleinfo.h packet-dccack.c packet-dccreq.c  packet-dccrsp.c  packet-dcd.c
docsis_la_LDFLAGS = -module -avoid-version
docsis_la_LIBADD = @PLUGIN_LIBS@

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

CLEANFILES = \
	docsis \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	Makefile.nmake \
	README
