# Makefile.am
# Automake file for Ethereal/docsis
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

INCLUDES = -I$(top_srcdir) -I$(includedir)

plugindir = @plugindir@

plugin_LTLIBRARIES = docsis.la
docsis_la_SOURCES = packet-docsis.c packet-bpkmattr.c packet-dsarsp.c packet-macmgmt.c packet-rngrsp.c packet-bpkmreq.c packet-dscack.c packet-map.c packet-tlv.c packet-bpkmrsp.c packet-dscreq.c packet-regack.c packet-uccreq.c packet-dscrsp.c packet-regreq.c packet-uccrsp.c packet-dsaack.c packet-dsdreq.c packet-regrsp.c packet-ucd.c packet-dsareq.c packet-dsdrsp.c packet-rngreq.c packet-vendor.c packet-docsis.h packet-tlv.h moduleinfo.h
docsis_la_LDFLAGS = -module -avoid-version

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

docsis_la_DEPENDENCIES = packet-docsis-static.o packet-bpkmattr-static.o packet-dsarsp-static.o packet-macmgmt-static.o packet-rngrsp-static.o packet-bpkmreq-static.o packet-dscack-static.o packet-map-static.o packet-tlv-static.o packet-bpkmrsp-static.o packet-dscreq-static.o packet-regack-static.o packet-uccreq-static.o packet-dscrsp-static.o packet-regreq-static.o packet-uccrsp-static.o packet-dsaack-static.o packet-dsdreq-static.o packet-regrsp-static.o packet-ucd-static.o packet-dsareq-static.o packet-dsdrsp-static.o packet-rngreq-static.o packet-vendor-static.o

packet-docsis-static.o:	packet-docsis.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-docsis-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-docsis.c 


packet-bpkmattr-static.o: packet-bpkmattr.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-bpkmattr-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-bpkmattr.c

packet-dsarsp-static.o:	packet-dsarsp.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-dsarsp-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-dsarsp.c

packet-macmgmt-static.o:	packet-macmgmt.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-macmgmt-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-macmgmt.c

packet-rngrsp-static.o:	packet-rngrsp.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-rngrsp-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-rngrsp.c

packet-bpkmreq-static.o:	packet-bpkmreq.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-bpkmreq-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-bpkmreq.c

packet-dscack-static.o:	packet-dscack.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-dscack-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-dscack.c

packet-map-static.o:	packet-map.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-map-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-map.c

packet-tlv-static.o:	packet-tlv.c packet-tlv.h moduleinfo.h
	$(LTCOMPILE) -c -o packet-tlv-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-tlv.c

packet-bpkmrsp-static.o:	packet-bpkmrsp.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-bpkmrsp-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-bpkmrsp.c

packet-dscreq-static.o:	packet-dscreq.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-dscreq-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-dscreq.c

packet-regack-static.o:	packet-regack.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-regack-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-regack.c

packet-uccreq-static.o:	packet-uccreq.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-uccreq-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-uccreq.c

packet-dscrsp-static.o:	packet-dscrsp.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-dscrsp-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-dscrsp.c

packet-regreq-static.o:	packet-regreq.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-regreq-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-regreq.c

packet-uccrsp-static.o:	packet-uccrsp.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-uccrsp-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-uccrsp.c

packet-dsaack-static.o:	packet-dsaack.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-dsaack-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-dsaack.c

packet-dsdreq-static.o:	packet-dsdreq.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-dsdreq-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-dsdreq.c

packet-regrsp-static.o:	packet-regrsp.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-regrsp-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-regrsp.c

packet-ucd-static.o:	packet-ucd.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-ucd-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-ucd.c

packet-dsareq-static.o:	packet-dsareq.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-dsareq-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-dsareq.c

packet-dsdrsp-static.o:	packet-dsdrsp.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-dsdrsp-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-dsdrsp.c

packet-rngreq-static.o:	packet-rngreq.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-rngreq-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-rngreq.c

packet-vendor-static.o:	packet-vendor.c moduleinfo.h
	$(LTCOMPILE) -c -o packet-vendor-static.o -D__ETHEREAL_STATIC__ $(srcdir)/packet-vendor.c

CLEANFILES = \
	docsis \
	*~

EXTRA_DIST = \
	Makefile.nmake \
	README
