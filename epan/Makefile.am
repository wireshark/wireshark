# Makefile.am
# Automake file for the EPAN library
# (Ethereal Protocol ANalyzer Library)
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


if HAVE_LIBLUA
wslua_lib = wslua/libwslua.la
wslua_dir = wslua
wslua_dist_dir = 
else            # HAVE_LIBLUA
wslua_lib =
wslua_dir =
wslua_dist_dir = wslua
endif           # HAVE_LIBLUA


SUBDIRS = ftypes dfilter dissectors $(wslua_dir)

DIST_SUBDIRS = $(SUBDIRS) $(wslua_dist_dir)

# EPAN will eventually be a shared library. While I move source code around,
# however, it is an archive library.

ACLOCAL_AMFLAGS = `../aclocal-flags`

lib_LTLIBRARIES = libwireshark.la
libwireshark_la_LDFLAGS = -version-info 0:1:0

include Makefile.common

INCLUDES = -I$(srcdir)/.. -I$(srcdir)/$(LEMON) @LUA_INCLUDES@ \
	$(LIBGNUTLS_CFLAGS) $(LIBGCRYPT_CFLAGS)

libwireshark_la_SOURCES = \
	$(LIBWIRESHARK_SRC)	\
	$(LIBWIRESHARK_INCLUDES)

EXTRA_libwireshark_la_SOURCES =	\
	g_ascii_strtoull.c	\
	g_ascii_strtoull.h	\
	inet_aton.c		\
	inet_pton.c		\
	inet_ntop.c		\
	inet_aton.h		\
	inet_v6defs.h

EXTRA_DIST = \
	dtd_grammar.lemon \
	dtd_parse.l \
	dtd_preparse.l \
	enterprise-numbers  \
	libwireshark.def	\
	Makefile.common	\
	Makefile.nmake	\
	make-sminmpec.pl \
	radius_dict.l   \
	tvbtest.c	\
	exntest.c	\
	doxygen.cfg.in

CLEANFILES = \
	libwireshark.a		\
	libwireshark.la		\
	*~

DISTCLEANFILES = \
	dtd_grammar.out		\
	dtd_grammar.c		\
	dtd_grammar.h		\
	dtd_parse.c		\
	dtd_preparse.c		\
	radius_dict.c
	

MAINTAINERCLEANFILES = \
	Makefile.in		\
	sminmpec.c


#
# Add the object files for missing routines, if any.
#
libwireshark_la_LIBADD = @G_ASCII_STRTOULL_LO@ @INET_ATON_LO@ @INET_PTON_LO@ @INET_NTOP_LO@ dfilter/libdfilter.la ftypes/libftypes.la dissectors/libdissectors.la $(wslua_lib) @ADNS_LIBS@ @LIBGNUTLS_LIBS@ @LIBICONV@ @KRB5_LIBS@ @SNMP_LIBS@ @SSL_LIBS@ -lm
libwireshark_la_DEPENDENCIES = @G_ASCII_STRTOULL_LO@ @INET_ATON_LO@ @INET_PTON_LO@ @INET_NTOP_LO@ dfilter/libdfilter.la ftypes/libftypes.la dissectors/libdissectors.la $(wslua_lib)

tvbtest: tvbtest.o tvbuff.o except.o strutil.o
	$(LINK) $^ $(GLIB_LIBS) -lz

exntest: exntest.o except.o
	$(LINK) $^ $(GLIB_LIBS)

radius_dict.c: radius_dict.l
	$(LEX) $^
	
dtd_parse.c : dtd_parse.l
	$(LEX) -odtd_parse.c $(srcdir)/dtd_parse.l

dtd_preparse.c : dtd_preparse.l
	$(LEX) -odtd_preparse.c $(srcdir)/dtd_preparse.l

dtd_grammar.h: dtd_grammar.c

LEMON=../tools/lemon

dtd_grammar.c: dtd_grammar.lemon $(LEMON)/lemon$(EXEEXT)
	$(LEMON)/lemon$(EXEEXT) t=$(srcdir)/$(LEMON)/lempar.c $(srcdir)/dtd_grammar.lemon
	
tvbtest.o exntest.o: exceptions.h

sminmpec.c: enterprise-numbers make-sminmpec.pl
	$(PERL) $(srcdir)/make-sminmpec.pl $(srcdir)/enterprise-numbers sminmpec.c

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

