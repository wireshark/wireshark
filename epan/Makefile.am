# Makefile.am
# Automake file for the EPAN library
# (Ethereal Protocol ANalyzer Library)
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

SUBDIRS = ftypes dfilter dissectors

# EPAN will eventually be a shared library. While I move source code around,
# however, it is an archive library.

ACLOCAL_AMFLAGS = `../aclocal-flags`

lib_LTLIBRARIES = libethereal.la
libethereal_la_LDFLAGS = -version-info 0:1:0

include Makefile.common

INCLUDES = -I$(srcdir)/..

libethereal_la_SOURCES = \
	addr_and_mask.c		\
	addr_and_mask.h		\
	address.h		\
	atalk-utils.c		\
	atalk-utils.h		\
	bitswap.c		\
	bitswap.h		\
	circuit.c		\
	circuit.h		\
	column_info.h		\
	conversation.c		\
	conversation.h		\
	column-utils.c		\
	column-utils.h		\
	epan.c			\
	epan.h			\
	epan_dissect.h		\
	except.c		\
	except.h		\
	exceptions.h		\
	filesystem.c		\
	filesystem.h		\
	frame_data.c		\
	frame_data.h		\
	gdebug.h		\
	int-64bit.c		\
	int-64bit.h		\
	ipv4.c			\
	ipv4.h			\
	ipv6-utils.h		\
	nstime.h		\
	osi-utils.c		\
	osi-utils.h		\
	packet.c		\
	packet.h		\
	packet_info.h		\
	pint.h			\
	plugins.c		\
	plugins.h		\
	proto.c			\
	proto.h			\
	resolv.c		\
	resolv.h		\
	report_err.h		\
	slab.h			\
	sna-utils.c		\
	sna-utils.h		\
	strutil.c		\
	strutil.h		\
	timestamp.c		\
	timestamp.h    		\
	to_str.c		\
	to_str.h		\
	tvbuff.c		\
	tvbuff.h		\
	value_string.c		\
	value_string.h		\
	$(DISSECTOR_SRC)        \
	$(DISSECTOR_SUPPORT_SRC)

EXTRA_libethereal_la_SOURCES =	\
        inet_aton.c		\
	inet_pton.c		\
	inet_ntop.c		\
	inet_aton.h		\
	inet_v6defs.h

EXTRA_DIST = \
	libethereal.def	\
	Makefile.common	\
	Makefile.nmake	\
	tvbtest.c	\
	doxygen.cfg.in

CLEANFILES = \
	libethereal.a		\
	libethereal.la		\
	*~

MAINTAINERCLEANFILES =	\
	register.c	\
	../packet-ncp2222.c

#
# Add the object files for missing routines, if any.
#
libethereal_la_LIBADD = @INET_ATON_O@ @INET_PTON_O@ @INET_NTOP_O@ dfilter/libdfilter.la ftypes/libftypes.la dissectors/libdissectors.la
libethereal_la_DEPENDENCIES = @INET_ATON_O@ @INET_PTON_O@ @INET_NTOP_O@ dfilter/libdfilter.la ftypes/libftypes.la dissectors/libdissectors.la

tvbtest: tvbtest.o tvbuff.o except.o strutil.o
	$(LINK) -o tvbtest tvbtest.o tvbuff.o except.o strutil.o `glib-config --libs`


if HAVE_PLUGINS

if ENABLE_STATIC

plugin_src = \
	../plugins/acn/packet-acn.c \
	../plugins/artnet/packet-artnet.c \
	../plugins/asn1/packet-asn1.c \
	../plugins/docsis/packet-bpkmattr.c \
	../plugins/docsis/packet-bpkmreq.c \
	../plugins/docsis/packet-bpkmrsp.c \
	../plugins/docsis/packet-docsis.c \
	../plugins/docsis/packet-dsaack.c \
	../plugins/docsis/packet-dsareq.c \
	../plugins/docsis/packet-dsarsp.c \
	../plugins/docsis/packet-dscack.c \
	../plugins/docsis/packet-dscreq.c \
	../plugins/docsis/packet-dscrsp.c \
	../plugins/docsis/packet-dsdreq.c \
	../plugins/docsis/packet-dsdrsp.c \
	../plugins/docsis/packet-intrngreq.c \
	../plugins/docsis/packet-macmgmt.c \
	../plugins/docsis/packet-map.c \
	../plugins/docsis/packet-regack.c \
	../plugins/docsis/packet-regreq.c \
	../plugins/docsis/packet-regrsp.c \
	../plugins/docsis/packet-rngreq.c \
	../plugins/docsis/packet-rngrsp.c \
	../plugins/docsis/packet-tlv.c \
	../plugins/docsis/packet-type29ucd.c \
	../plugins/docsis/packet-uccreq.c \
	../plugins/docsis/packet-uccrsp.c \
	../plugins/docsis/packet-ucd.c \
	../plugins/enttec/packet-enttec.c \
	../plugins/giop/packet-cosnaming.c \
	../plugins/giop/packet-coseventcomm.c \
	../plugins/gryphon/packet-gryphon.c \
	../plugins/irda/packet-irda.c \
	../plugins/lwres/packet-lwres.c \
	../plugins/megaco/packet-megaco.c \
	../plugins/mgcp/packet-mgcp.c \
	../plugins/pcli/packet-pcli.c \
	../plugins/rdm/packet-rdm.c \
	../plugins/rtnet/packet-rtnet.c \
	../plugins/v5ua/packet-v5ua.c

else		# ENABLE_STATIC

plugin_src =

endif		# ENABLE_STATIC

else		# HAVE_PLUGINS
plugin_src =

endif		# HAVE_PLUGINS

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

