# Makefile.am
# Automake file for the EPAN library
# (Ethereal Protocol ANalyzer Library)
#
# $Id: Makefile.am,v 1.35 2004/03/03 00:07:01 jmayer Exp $
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

SUBDIRS = ftypes dfilter

# EPAN will eventually be a shared library. While I move source code around,
# however, it is an archive library.

ACLOCAL_AMFLAGS = `../aclocal-flags`

noinst_LIBRARIES = libethereal.a

include Makefile.common

INCLUDES = -I$(srcdir)/..

libethereal_a_SOURCES = \
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
	epan_dissect.h	\
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
	slab.h			\
	sna-utils.c		\
	sna-utils.h		\
	strutil.c		\
	strutil.h		\
	timestamp.h    		\
	to_str.c		\
	to_str.h		\
	tvbuff.c		\
	tvbuff.h		\
	value_string.c		\
	value_string.h		\
	$(DISSECTOR_SRC)        \
	$(DISSECTOR_SUPPORT_SRC)

EXTRA_libethereal_a_SOURCES =	\
        inet_aton.c		\
	inet_pton.c		\
	inet_ntop.c		\
	inet_aton.h		\
	inet_v6defs.h

EXTRA_DIST = \
	config.h.win32		\
	Makefile.nmake		\
	tvbtest.c

CLEANFILES = \
	libethereal.a	\
	*~

MAINTAINERCLEANFILES =	\
	register.c

#
# Add the object files for missing routines, if any.
#
libethereal_a_LIBADD = @INET_ATON_O@ @INET_PTON_O@ @INET_NTOP_O@
libethereal_a_DEPENDENCIES = @INET_ATON_O@ @INET_PTON_O@ @INET_NTOP_O@

../packet-ncp2222.c : $(srcdir)/../ncp2222.py
	$(PYTHON) $(srcdir)/../ncp2222.py -o $@

tvbtest: tvbtest.o tvbuff.o except.o strutil.o
	$(LINK) -o tvbtest tvbtest.o tvbuff.o except.o strutil.o `glib-config --libs`

#
# Build "register.c", which contains a function "register_all_protocols()"
# that calls the register routines for all protocols.
#
# We do this by grepping through sources.  If that turns out to be too slow,
# maybe we could just require every .o file to have an register routine
# of a given name (packet-aarp.o -> proto_register_aarp, etc.).
#
# Formatting conventions:  The name of the proto_register_* routines must
# start in column zero, or must be preceded only by "void " starting in
# column zero, and must not be inside #if.
#
# We assume that all dissector routines are in "packet-XXX.c" files.
#
# For some unknown reason, having a big "for" loop in the Makefile
# to scan all the "packet-XXX.c" files doesn't work with some "make"s;
# they seem to pass only the first few names in the list to the shell,
# for some reason.
#
# Therefore, we have a script to generate the "register.c" file.
#
# The first argument is the name of the file to write.
# The second argument is the directory in which the source files live.
# All subsequent arguments are the files to scan.
#
register.c: $(plugin_src) $(DISSECTOR_SRC) $(srcdir)/../make-reg-dotc
	@if test -n $(PYTHON); then \
		echo Making register.c with python ; \
		$(PYTHON) $(srcdir)/../make-reg-dotc.py $(srcdir) $(DISSECTOR_SRC) ; \
	else \
		echo Making register.c with shell script ; \
		$(srcdir)/../make-reg-dotc register.c $(srcdir) \
			$(plugin_src) $(DISSECTOR_SRC) ; \
	fi

#
# Currently register.c can be included in the distribution because
# we always build all protocol dissectors. We used to have to check
# whether or not to build the snmp dissector. If we again need to
# variably build something, making register.c non-portable, uncomment
# the dist-hook line below.
#
# Oh, yuk.  We don't want to include "register.c" in the distribution, as
# its contents depend on the configuration, and therefore we want it
# to be built when the first "make" is done; however, Automake insists
# on putting *all* source into the distribution.
#
# We work around this by having a "dist-hook" rule that deletes
# "register.c", so that "dist" won't pick it up.
#
#dist-hook:
#	@rm -f $(distdir)/register.c

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
	../plugins/docsis/packet-macmgmt.c \
	../plugins/docsis/packet-map.c \
	../plugins/docsis/packet-regack.c \
	../plugins/docsis/packet-regreq.c \
	../plugins/docsis/packet-regrsp.c \
	../plugins/docsis/packet-rngreq.c \
	../plugins/docsis/packet-rngrsp.c \
	../plugins/docsis/packet-tlv.c \
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

