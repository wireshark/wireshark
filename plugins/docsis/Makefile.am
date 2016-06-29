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
PLUGIN_NAME = docsis

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	packet-bintrngreq.c \
	packet-bpkmattr.c \
	packet-bpkmreq.c \
	packet-bpkmrsp.c \
	packet-cmctrlreq.c \
	packet-cmctrlrsp.c \
	packet-cmstatus.c \
	packet-intrngreq.c \
	packet-dbcreq.c \
	packet-dbcrsp.c \
	packet-dbcack.c \
	packet-dccack.c \
	packet-dccreq.c \
	packet-dccrsp.c \
	packet-dcd.c \
	packet-dpd.c \
	packet-dpvreq.c \
	packet-dpvrsp.c \
	packet-docsis.c \
	packet-dsaack.c \
	packet-dsareq.c \
	packet-dsarsp.c \
	packet-dscack.c \
	packet-dscreq.c \
	packet-dscrsp.c \
	packet-dsdreq.c \
	packet-dsdrsp.c \
	packet-macmgmt.c \
	packet-map.c \
	packet-mdd.c \
	packet-ocd.c \
	packet-regack.c \
	packet-regreq.c \
	packet-regreqmp.c \
	packet-regrsp.c \
	packet-regrspmp.c \
	packet-rngreq.c \
	packet-rngrsp.c \
	packet-sync.c \
	packet-tlv.c \
	packet-tlv-cmctrl.c \
	packet-type29ucd.c \
	packet-type35ucd.c \
	packet-uccreq.c \
	packet-uccrsp.c \
	packet-ucd.c \
	packet-vendor.c

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES)

# Headers.
CLEAN_HEADER_FILES =	\
	packet-tlv.h

HEADER_FILES = \
	$(FLEX_GENERATED_HEADER_FILES) \
	$(CLEAN_HEADER_FILES)

plugin_LTLIBRARIES = docsis.la

docsis_la_SOURCES = \
	plugin.c \
	moduleinfo.h \
	$(SRC_FILES)	\
	$(HEADER_FILES)

docsis_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

docsis_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

docsis_la_LDFLAGS = $(PLUGIN_LDFLAGS)

CLEANFILES = \
	docsis \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in \
	plugin.c

EXTRA_DIST = \
	plugin.rc.in		\
	README			\
	CMakeLists.txt
