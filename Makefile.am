# Makefile.am
# Automake file for Ethereal
#
# $Id: Makefile.am,v 1.705 2004/02/01 04:34:53 gerald Exp $
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

ACLOCAL_AMFLAGS = `./aclocal-flags`

#
# This is a hideous hack.
#
# Automake needs to know into which sections to install various man
# pages; if the names in "man_MANS" have suffixes, it can infer the
# sections from the name (e.g., "hello.1" goes in section 1), but if
# they don't have suffixes, it can't tell what sections to put them, and
# it just gives up and doesn't create any rules to install them (and it
# gives up silently, so you have no clue what's wrong).
#
# Therefore, we can't just set "man_MANS" to a list of variables to be
# filled in by the configure script, as those variables don't have man
# page section numbers.
#
# It turns out (although this is not documented anywhere I could find
# in the automake Info file) that if you define, instead, variables with
# names like "man{section}_MANS", automake will infer that the names in
# those variables are the names of man pages to be installed in section
# "{section}".
#
# So, as all our man pages go in section 1, we define "man1_MANS" to
# contain all the man page.
#
# *However*, if "man_MANS" isn't defined at all, automake concludes that
# there are no man pages, the fact that, say, "man1_MANS" is defined
# nonwithstanding!  (I suspect this is the result of a mistaken attempt
# to get people to fix their automake files not to use "MANS"; if "MANS"
# is defined, it prints a warning and sets the exit status, but doesn't
# exit, and then it just gives up if "man_MANS" isn't defined,
# presumably on the theory that the only reason it wouldn't be defined
# is because the automake file uses the obsolete "MANS" variable instead
# of the shiny new "man_MANS" variable.)
#
# So we also define "man_MANS", but don't define it as anything;
# automake will arrange that the Makefile define it as the union of all
# the "man{section}_MANS" variables.
#
bin_PROGRAMS = @ethereal_bin@ @editcap_bin@ @mergecap_bin@ @tethereal_bin@ @dftest_bin@ @randpkt_bin@ @text2pcap_bin@
bin_SCRIPTS = @idl2eth_bin@
man1_MANS = @ethereal_man@ @editcap_man@ @mergecap_man@ @tethereal_man@ @text2pcap_man@ @idl2eth_man@
man4_MANS = @etherealfilter_man@
man_MANS =

EXTRA_PROGRAMS = ethereal tethereal editcap mergecap dftest text2pcap
EXTRA_SCRIPTS = idl2eth

#
# Ethereal configuration files are put in $(pkgdatadir).  It currently
# contains the "manuf" file and a "diameter" directory.
#
pkgdata_DATA = manuf

#
# Install the Diameter DTD and XML files in the "diameter" subdirectory
# of that directory.
#
diameterdir = $(pkgdatadir)/diameter
diameter_DATA = dictionary.dtd dictionary.xml mobileipv4.xml \
	nasreq.xml sunping.xml

include Makefile.common

if HAVE_PLUGINS
plugin_libs = \
	plugins/acn/acn.la \
	plugins/artnet/artnet.la \
	plugins/asn1/asn1.la \
	plugins/docsis/docsis.la \
	plugins/enttec/enttec.la \
	plugins/giop/cosnaming.la \
	plugins/giop/coseventcomm.la \
	plugins/gryphon/gryphon.la \
	plugins/irda/irda.la \
	plugins/lwres/lwres.la \
	plugins/megaco/megaco.la \
	plugins/mgcp/mgcp.la \
	plugins/pcli/pcli.la \
	plugins/rdm/rdm.la \
	plugins/rtnet/rtnet.la \
	plugins/v5ua/v5ua.la

if ENABLE_STATIC
plugin_ldadd = \
	plugins/acn/packet-acn.o \
	plugins/artnet/packet-artnet.o \
	plugins/asn1/packet-asn1.o \
	plugins/docsis/packet-bpkmattr.o \
	plugins/docsis/packet-bpkmreq.o \
	plugins/docsis/packet-bpkmrsp.o \
	plugins/docsis/packet-docsis.o \
	plugins/docsis/packet-dsaack.o \
	plugins/docsis/packet-dsareq.o \
	plugins/docsis/packet-dsarsp.o \
	plugins/docsis/packet-dscack.o \
	plugins/docsis/packet-dscreq.o \
	plugins/docsis/packet-dscrsp.o \
	plugins/docsis/packet-dsdreq.o \
	plugins/docsis/packet-dsdrsp.o \
	plugins/docsis/packet-macmgmt.o \
	plugins/docsis/packet-map.o \
	plugins/docsis/packet-regack.o \
	plugins/docsis/packet-regreq.o \
	plugins/docsis/packet-regrsp.o \
	plugins/docsis/packet-rngreq.o \
	plugins/docsis/packet-rngrsp.o \
	plugins/docsis/packet-tlv.o \
	plugins/docsis/packet-uccreq.o \
	plugins/docsis/packet-uccrsp.o \
	plugins/docsis/packet-ucd.o \
	plugins/enttec/packet-enttec.o \
	plugins/giop/packet-cosnaming.o \
	plugins/giop/packet-coseventcomm.o \
	plugins/gryphon/packet-gryphon.o \
	plugins/irda/packet-irda.o \
	plugins/lwres/packet-lwres.o \
	plugins/megaco/packet-megaco.o \
	plugins/mgcp/packet-mgcp.o \
	plugins/pcli/packet-pcli.o \
	plugins/rdm/packet-rdm.o \
	plugins/rtnet/packet-rtnet.o \
	plugins/v5ua/packet-v5ua.o

plugin_src = \
	plugins/acn/packet-acn.c \
	plugins/artnet/packet-artnet.c \
	plugins/asn1/packet-asn1.c \
	plugins/docsis/packet-bpkmattr.c \
	plugins/docsis/packet-bpkmreq.c \
	plugins/docsis/packet-bpkmrsp.c \
	plugins/docsis/packet-docsis.c \
	plugins/docsis/packet-dsaack.c \
	plugins/docsis/packet-dsareq.c \
	plugins/docsis/packet-dsarsp.c \
	plugins/docsis/packet-dscack.c \
	plugins/docsis/packet-dscreq.c \
	plugins/docsis/packet-dscrsp.c \
	plugins/docsis/packet-dsdreq.c \
	plugins/docsis/packet-dsdrsp.c \
	plugins/docsis/packet-macmgmt.c \
	plugins/docsis/packet-map.c \
	plugins/docsis/packet-regack.c \
	plugins/docsis/packet-regreq.c \
	plugins/docsis/packet-regrsp.c \
	plugins/docsis/packet-rngreq.c \
	plugins/docsis/packet-rngrsp.c \
	plugins/docsis/packet-tlv.c \
	plugins/docsis/packet-uccreq.c \
	plugins/docsis/packet-uccrsp.c \
	plugins/docsis/packet-ucd.c \
	plugins/enttec/packet-enttec.c \
	plugins/giop/packet-cosnaming.c \
	plugins/giop/packet-coseventcomm.c \
	plugins/gryphon/packet-gryphon.c \
	plugins/irda/packet-irda.c \
	plugins/lwres/packet-lwres.c \
	plugins/megaco/packet-megaco.c \
	plugins/mgcp/packet-mgcp.c \
	plugins/pcli/packet-pcli.c \
	plugins/rdm/packet-rdm.c \
	plugins/rtnet/packet-rtnet.c \
	plugins/v5ua/packet-v5ua.c

else		# ENABLE_STATIC
plugin_ldadd = \
	"-dlopen" self	\
	"-dlopen" plugins/acn/acn.la \
	"-dlopen" plugins/artnet/artnet.la \
	"-dlopen" plugins/asn1/asn1.la \
	"-dlopen" plugins/docsis/docsis.la \
	"-dlopen" plugins/enttec/enttec.la \
	"-dlopen" plugins/giop/cosnaming.la \
	"-dlopen" plugins/giop/coseventcomm.la \
	"-dlopen" plugins/gryphon/gryphon.la \
	"-dlopen" plugins/irda/irda.la \
	"-dlopen" plugins/lwres/lwres.la \
	"-dlopen" plugins/megaco/megaco.la \
	"-dlopen" plugins/mgcp/mgcp.la \
	"-dlopen" plugins/pcli/pcli.la \
	"-dlopen" plugins/rdm/rdm.la \
	"-dlopen" plugins/rtnet/rtnet.la \
	"-dlopen" plugins/v5ua/v5ua.la

plugin_src =

endif		# ENABLE_STATIC

else		# HAVE_PLUGINS
plugin_src =

plugin_libs =

plugin_ldadd =
endif		# HAVE_PLUGINS

noinst_HEADERS = \
	packet-acse.h  \
	packet-afp.h   \
	packet-afs-defs.h \
	packet-afs-macros.h \
	packet-afs-register-info.h \
	packet-afs.h   \
	packet-ansi_a.h \
	packet-ansi_map.h \
	packet-arcnet.h \
	packet-arp.h   \
	packet-atalk.h \
	packet-atm.h   \
	packet-bgp.h   \
	packet-bootparams.h \
	packet-bssap.h \
	packet-chdlc.h \
	packet-clearcase.h  \
	packet-clip.h  \
	packet-data.h \
	packet-dccp.h \
	packet-dcerpc-atsvc.h \
	packet-dcerpc-browser.h \
	packet-dcerpc-dce122.h \
	packet-dcerpc-dcom.h \
	packet-dcerpc-dfs.h \
	packet-dcerpc-dnsserver.h \
	packet-dcerpc-drsuapi.h \
	packet-dcerpc-initshutdown.h \
	packet-dcerpc-lsa.h \
	packet-dcerpc-mapi.h \
	packet-dcerpc-netlogon.h \
	packet-dcerpc-nt.h \
	packet-dcerpc-reg.h \
	packet-dcerpc-samr.h \
	packet-dcerpc-spoolss.h \
	packet-dcerpc-srvsvc.h \
	packet-dcerpc-svcctl.h \
	packet-dcerpc-tapi.h \
	packet-dcerpc-wkssvc.h \
	packet-dcerpc.h \
	packet-ddtp.h  \
	packet-diameter-defs.h \
	packet-diffserv-mpls-common.h \
	packet-dns.h   \
	packet-dvmrp.h \
	packet-edonkey.h \
	packet-esis.h  \
	packet-eth.h   \
	packet-fc.h \
	packet-fcbls.h \
	packet-fcct.h \
	packet-fcdns.h \
	packet-fcels.h \
	packet-fcfcs.h \
	packet-fcfzs.h \
	packet-fclctl.h \
	packet-fcp.h \
	packet-fcsb3.h \
	packet-fcsp.h \
	packet-fcswils.h \
	packet-fddi.h  \
	packet-frame.h  \
	packet-giop.h  \
	packet-gnutella.h \
	packet-gsm_a.h  \
	packet-gssapi.h \
	packet-gtp.h    \
	packet-h225.h    \
	packet-h245.h    \
	packet-hclnfsd.h  \
	packet-hpext.h	\
	packet-http.h  \
	packet-iax2.h  \
	packet-ieee80211.h \
	packet-ieee8023.h \
	packet-igap.h  \
	packet-igmp.h  \
	packet-ip.h    \
	packet-ipfc.h  \
	packet-ipsec.h \
	packet-ipv6.h  \
	packet-ipx.h   \
	packet-isis-clv.h \
	packet-isis-hello.h \
	packet-isis-lsp.h \
	packet-isis-snp.h \
	packet-isis.h  \
	packet-isl.h   \
	packet-isup.h   \
	packet-kerberos.h \
	packet-klm.h   \
	packet-ldap.h  \
	packet-llc.h   \
	packet-mip6.h  \
	packet-mount.h \
	packet-mrdisc.h \
	packet-msnip.h \
	packet-mtp3.h  \
	packet-ncp-int.h \
	packet-ndps.h    \
	packet-netbios.h \
	packet-nfs.h   \
	packet-nisplus.h \
	packet-nlm.h   \
	packet-ntp.h  \
	packet-null.h  \
	packet-osi-options.h \
	packet-osi.h   \
	packet-pcnfsd.h \
	packet-per.h   \
	packet-pflog.h \
	packet-pim.h   \
	packet-portmap.h   \
	packet-ppp.h   \
	packet-pres.h  \
	packet-prism.h \
	packet-q931.h  \
	packet-radiotap.h \
	packet-raw.h   \
	packet-ripng.h \
	packet-rmi.h   \
	packet-rpc.h   \
	packet-rquota.h \
	packet-rsvp.h  \
	packet-rtcp.h  \
	packet-rtp.h   \
	packet-rtp-events.h \
	packet-rwall.h  \
	packet-rx.h  \
	packet-scsi.h  \
	packet-ses.h   \
	packet-sll.h   \
	packet-smb-browse.h \
	packet-smb-common.h \
	packet-smb-mailslot.h \
	packet-smb-pipe.h \
	packet-smb-sidsnooping.h \
	packet-sna.h   \
	packet-snmp.h	\
	packet-spray.h \
	packet-stat-notify.h \
	packet-stat.h   \
	packet-tacacs.h \
	packet-tcap.h  \
	packet-tcp.h   \
	packet-tns.h \
	packet-tpkt.h  \
	packet-tr.h    \
	packet-udp.h   \
	packet-vines.h \
	packet-vlan.h \
	packet-wap.h \
	packet-wccp.h \
	packet-wlancap.h \
	packet-wsp.h \
	packet-wtls.h \
	packet-wtp.h \
	packet-x11-keysym.h	\
	packet-x11-keysymdef.h	\
	packet-ypbind.h \
	packet-yppasswd.h \
	packet-ypserv.h \
	packet-ypxfr.h

DISSECTOR_SUPPORT_SRC = \
	adler32.c      \
	adler32.h      \
	afn.c          \
	afn.h          \
	aftypes.h      \
	arcnet_pids.h  \
	asn1.c         \
	asn1.h         \
	bridged_pids.h \
	chdlctypes.h   \
	column.c       \
	column.h       \
	crc32.c        \
	crc32.h        \
	crypt-des.c    \
	crypt-des.h    \
	crypt-md4.c    \
	crypt-md4.h    \
	crypt-md5.c    \
	crypt-md5.h    \
	crypt-rc4.c    \
	crypt-rc4.h    \
	etypes.h       \
	follow.c       \
	follow.h       \
	format-oid.h   \
	g711.c		\
	g711.h		\
	greproto.h     \
	h225-persistentdata.c \
	h225-persistentdata.h \
	in_cksum.c     \
	in_cksum.h     \
	ip_opts.h      \
	ipproto.c      \
	ipproto.h      \
	lapd_sapi.h    \
	llcsaps.h      \
	nlpid.h        \
	oui.h          \
	packet-dcerpc-nt.c \
	ppptypes.h     \
	prefs-int.h    \
	prefs.c        \
	prefs.h        \
	ptvcursor.c	\
	ptvcursor.h	\
	reassemble.c   \
	reassemble.h   \
	req_resp_hdrs.c \
	req_resp_hdrs.h \
	rpc_defrag.h   \
	rtp_pt.h       \
	sctpppids.h    \
	smb.h          \
	t35.c		\
	t35.h		\
	tap.c		\
	tap.h		\
	util.c         \
	util.h         \
	x264_prt_id.h  \
	xdlc.c         \
	xdlc.h         \
	xmlstub.c      \
	xmlstub.h

BUILT_SOURCES = \
	cvsversion.h	\
	x11-declarations.h \
	x11-register-info.h

ETHEREAL_COMMON_SRC = \
	$(DISSECTOR_SUPPORT_SRC) \
	$(BUILT_SOURCES) \
	capture_stop_conditions.c   \
	capture_stop_conditions.h   \
	cfile.c         \
	cfile.h         \
	color.h        \
	conditions.c   \
	conditions.h   \
	disabled_protos.c      \
	disabled_protos.h      \
	file.h         \
	pcap-util.c    \
	pcap-util.h    \
	pcap-util-int.h \
	pcap-util-unix.c \
	print.c        \
	print.h        \
	ps.c           \
	ps.h           \
	range.c		\
	range.h		\
	register.h     \
	ringbuffer.c   \
	ringbuffer.h   \
	timestats.c	\
	timestats.h	\
	version_info.c	\
	version_info.h

ethereal_SOURCES = \
	$(DISSECTOR_SRC) \
	$(ETHEREAL_COMMON_SRC) \
	register.c     \
	capture.c      \
	capture.h      \
	file.c         \
	filters.c      \
	filters.h      \
	globals.h      \
	menu.h         \
	progress_dlg.h \
	proto_hier_stats.h	\
	proto_hier_stats.c	\
	simple_dialog.h \
	statusbar.h    \
	summary.c      \
	summary.h      \
	tap_dfilter_dlg.h \
	ui_util.h

EXTRA_ethereal_SOURCES = \
	snprintf.c	\
	snprintf.h	\
	snprintf-imp.h	\
	strerror.c	\
	strerror.h	\
	strcasecmp.c	\
	strncasecmp.c	\
	mkstemp.c	\
	mkstemp.h	\
	strptime.c	\
	strptime.h

# Optional objects that I know how to build. These will be
# linked into the ethereal executable.
# They will also be linked into the tethereal executable; if this
# list ever grows to include something that can't be linked with
# tethereal, or if tethereal needs something that ethereal doesn't,
# we should probably split this into stuff needed both
# by ethereal and tethereal and stuff needed only by one or the
# other.
ethereal_optional_objects = @SNPRINTF_O@ @STRERROR_O@ \
	@STRCASECMP_O@ @STRNCASECMP_O@ @MKSTEMP_O@ @STRPTIME_O@

# Additional libs that I know how to build. These will be
# linked into the ethereal executable.
ethereal_additional_libs = \
	wiretap/libwiretap.a	\
	gtk/libui.a		\
	epan/libethereal.a	\
	epan/ftypes/libftypes.a \
	epan/dfilter/libdfilter.a

# This is the automake dependency variable for the executable
ethereal_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs)	\
	$(plugin_libs)

# This automake variable adds to the link-line for the executable.
#
# Note that Ethereal doesn't have to be linked with @GLIB_LIBS@, as
# they are included in @GTK_LIBS@, and doesn't have to be linked with
# @SOCKET_LIBS@ or @NSL_LIBS@, as those should also be included in
# @GTK_LIBS@ (as those are also needed for X applications, and GTK+
# applications are X applications).

if ENABLE_STATIC
ethereal_LDFLAGS = -Wl,-static -all-static
else
ethereal_LDFLAGS = -export-dynamic
endif

ethereal_LDADD = \
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@ 		\
	$(plugin_ldadd)			\
	@PCRE_LIBS@ \
	@PCAP_LIBS@ @GTK_LIBS@ @ADNS_LIBS@

TETHEREAL_TAP_SRC = \
	tap-ansi_astat.c	\
	tap-bootpstat.c		\
	tap-dcerpcstat.c	\
	tap-gsm_astat.c		\
	tap-h225counter.c	\
	tap-h225rassrt.c	\
	tap-httpstat.c		\
	tap-iostat.c		\
	tap-iousers.c		\
	tap-mgcpstat.c		\
	tap-protocolinfo.c	\
	tap-protohierstat.c	\
	tap-rpcstat.c		\
	tap-rpcprogs.c		\
	tap-smbsids.c		\
	tap-smbstat.c		\
	tap-wspstat.c

tethereal_SOURCES = \
	$(DISSECTOR_SRC) \
	$(ETHEREAL_COMMON_SRC) \
	$(TETHEREAL_TAP_SRC) \
	tethereal-tap-register.c \
	register.c     \
	tethereal.c

# Additional libs that I know how to build. These will be
# linked into the tethereal executable.
tethereal_additional_libs =		\
	wiretap/libwiretap.a		\
	epan/libethereal.a		\
	epan/ftypes/libftypes.a		\
	epan/dfilter/libdfilter.a

# This is the automake dependency variable for the executable
tethereal_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(tethereal_additional_libs)	\
	$(plugin_libs)

# This automake variable adds to the link-line for the executable
tethereal_LDADD = \
	$(ethereal_optional_objects)	\
	$(tethereal_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@		\
	$(plugin_ldadd)			\
	@PCRE_LIBS@ \
	@GLIB_LIBS@ -lm			\
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@ @ADNS_LIBS@

if ENABLE_STATIC
tethereal_LDFLAGS = -Wl,-static -all-static
else
tethereal_LDFLAGS = -export-dynamic
endif

# Optional objects that I know how to build, and that are needed by
# text2pcap.
text2pcap_optional_objects = @STRERROR_O@ @STRPTIME_O@

text2pcap_SOURCES = text2pcap.c text2pcap-scanner.l
text2pcap_DEPENDENCIES = text2pcap.h

# This automake variable adds to the link-line for the executable
text2pcap_LDADD = $(text2pcap_optional_objects) \
	@GLIB_LIBS@ -lm

mergecap_SOURCES = mergecap.c cvsversion.h
mergecap_DEPENDENCIES = wiretap/libwiretap.a

editcap_SOURCES = editcap.c

# This is the automake dependency variable for the executable
editcap_DEPENDENCIES = wiretap/libwiretap.a

# This automake variable adds to the link-line for the executable
editcap_LDADD = wiretap/libwiretap.a @GLIB_LIBS@
mergecap_LDADD = wiretap/libwiretap.a @GLIB_LIBS@

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap

#
# Build the version string
#
cvsversion.h:
	$(PERL) $(srcdir)/make-version.pl

#
# Build various header files for the X11 dissector.
#
x11-declarations.h x11-register-info.h: x11-fields process-x11-fields.pl
	$(PERL) $(srcdir)/process-x11-fields.pl <$(srcdir)/x11-fields

#
# Build shell scripts by doing variable substitution.
# Taken from autoconf 2.13.
#
editsh = sed -e 's,@''SHELL''@,$(SHELL),g'

SUFFIXES = .sh
.sh:
	rm -f $@ $@.tmp
	$(editsh) $< > $@.tmp && chmod +x $@.tmp && mv $@.tmp $@

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
register.c: $(plugin_src) $(DISSECTOR_SRC) $(srcdir)/make-reg-dotc
	@if test -n $(PYTHON); then \
		echo Making register.c with python ; \
		$(PYTHON) $(srcdir)/make-reg-dotc.py $(srcdir) $(DISSECTOR_SRC) ; \
	else \
		echo Making register.c with shell script ; \
		$(srcdir)/make-reg-dotc register.c $(srcdir) \
			$(plugin_src) $(DISSECTOR_SRC) ; \
	fi

#
# Build "tethereal-tap-register.c", which contains a function 
# "register_all_tap_listeners()"
# that calls the register routines for all tehtereal tap listeners.
#
# We do this by grepping through sources.
#
# Formatting conventions:  The name of the tap_listener_register_* 
# routines must start in column zero, or must be preceded only by 
# "void " starting in column zero, and must not be inside #if.
#
# The first argument is the directory in which the source files live.
# All subsequent arguments are the files to scan.
#
tethereal-tap-register.c: $(TETHEREAL_TAP_SRC) $(srcdir)/make-tapreg-dotc
	@echo Making tethereal-tap-register.c
	@$(srcdir)/make-tapreg-dotc tethereal-tap-register.c $(srcdir) $(TETHEREAL_TAP_SRC)

ps.c: print.ps rdps
	./rdps $(srcdir)/print.ps ps.c

rdps: rdps.c
	$(CC) $(CFLAGS) -o rdps $(srcdir)/rdps.c

randpkt.o: randpkt.c
	$(CC) -DHAVE_CONFIG_H -I. `glib-config --cflags` -c $(srcdir)/randpkt.c

randpkt: randpkt.o wiretap/libwiretap.a
	$(LINK) -o randpkt randpkt.o wiretap/libwiretap.a `glib-config --libs` -lz


dftest_SOURCES = \
	$(DISSECTOR_SRC) \
	$(DISSECTOR_SUPPORT_SRC) \
	$(BUILT_SOURCES) \
	register.c     \
	dftest.c

dftest_additional_libs =		\
	wiretap/libwiretap.a		\
	epan/libethereal.a		\
	epan/ftypes/libftypes.a		\
	epan/dfilter/libdfilter.a

dftest_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(dftest_additional_libs)	\
	$(plugin_libs)

# This automake variable adds to the link-line for the executable
dftest_LDADD = \
	$(ethereal_optional_objects)	\
	$(dftest_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@		\
	$(plugin_ldadd)			\
	@PCRE_LIBS@ \
	@GLIB_LIBS@ -lm \
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@ @ADNS_LIBS@

dftest_LDFLAGS = -export-dynamic

CLEANFILES =	\
	@rdps_bin@ \
	idl2eth

DISTCLEANFILES = \
	aclocal-missing/*.m4 \
	ps.c \
	*~

MAINTAINERCLEANFILES =		\
	register.c		\
	ps.c

EXTRA_DIST = \
	Ethereal.desktop	\
	FAQ			\
	INSTALL.configure       \
	Makefile.common		\
	Makefile.nmake		\
	README.aix		\
	README.bsd		\
	README.hpux		\
	README.irix		\
	README.linux		\
	README.tru64		\
	README.vmware		\
	README.win32		\
	TODO			\
	aclocal-fallback/glib-2.0.m4 \
	aclocal-fallback/glib.m4 \
	aclocal-fallback/gtk-2.0.m4 \
	aclocal-fallback/gtk.m4 \
	aclocal-flags		\
	aclocal-missing/dummy	\
	autogen.sh		\
	capture-wpcap.c		\
	capture-wpcap.h		\
	cleanbld.bat		\
	config.h.win32		\
	config.nmake		\
	debian/README.debian	\
	debian/changelog	\
	debian/control		\
	debian/copyright	\
	debian/dirs		\
	debian/docs		\
	debian/menu		\
	debian/postinst		\
	debian/prerm		\
	debian/rules		\
	dictionary.dtd		\
	dictionary.xml		\
	doc/Makefile.am         \
	doc/Makefile.nmake      \
	doc/README.capture      \
	doc/README.design       \
	doc/README.developer    \
	doc/README.idl2eth      \
	doc/README.plugins      \
	doc/README.regression   \
	doc/README.tapping	\
	doc/README.tvbuff	\
	doc/README.xml-output	\
	doc/dfilter2pod.pl	\
	doc/editcap.pod		\
	doc/ethereal-filter.pod.template \
	doc/ethereal.pod	\
	doc/idl2eth.pod		\
	doc/mergecap.pod	\
	doc/randpkt.txt		\
	doc/tethereal.pod	\
	doc/text2pcap.pod	\
	editcap.c		\
	ethereal_be.py		\
	ethereal_gen.py		\
	getopt.c		\
	getopt.h		\
	idl2eth.sh		\
	image/Ethereal.icns	\
	image/Makefile.nmake	\
	image/README.image	\
	image/clist_ascend.xpm	\
	image/clist_descend.xpm	\
	image/dn_arrow.xpm	\
	image/editcap.rc.in	\
	image/eexcl3d64.xpm	\
	image/eicon3d16.xpm	\
	image/eicon3d32.xpm	\
	image/eicon3d48.xpm	\
	image/eicon3d64.xpm	\
	image/elogo3d48x48.png	\
	image/ethereal.ico	\
	image/ethereal.rc.in	\
	image/ethereal48x48-trans.png  \
	image/ethereal48x48.png \
	image/hi16-app-ethereal.png	\
	image/hi32-app-ethereal.png	\
	image/hi48-app-ethereal.png	\
	image/icon-ethereal.xpm	\
	image/icon-excl.xpm	\
	image/lo16-app-ethereal.png	\
	image/lo32-app-ethereal.png	\
	image/lo48-app-ethereal.png	\
	image/mergecap.rc.in	\
	image/nsis-checked.bmp	\
	image/nsis-unchecked.bmp	\
	image/stock_dialog_error_48.xpm	\
	image/stock_dialog_warning_48.xpm	\
	image/stock_dialog_question_48.xpm	\
	image/stock_dialog_info_48.xpm	\
	image/tethereal.rc.in	\
	image/text2pcap.rc.in	\
	image/toolbar/capture_24.xpm	\
	image/toolbar/cfilter_24.xpm	\
	image/toolbar/dfilter_24.xpm	\
	image/toolbar/stock_close_24.xpm	\
	image/toolbar/stock_colorselector_24.xpm	\
	image/toolbar/stock_help_24.xpm	\
	image/toolbar/stock_jump_to_24.xpm	\
	image/toolbar/stock_open_24.xpm	\
	image/toolbar/stock_preferences_24.xpm	\
	image/toolbar/stock_print_24.xpm	\
	image/toolbar/stock_refresh_24.xpm	\
	image/toolbar/stock_right_arrow_24.xpm	\
	image/toolbar/stock_save_24.xpm	\
	image/toolbar/stock_search_24.xpm	\
	image/toolbar/stock_stop_24.xpm	\
	image/up_arrow.xpm	\
	make-manuf		\
	make-reg-dotc		\
	make-reg-dotc.py	\
	make-tapreg-dotc	\
	manuf                   \
	manuf.tmpl		\
	mergecap.c		\
	mobileipv4.xml		\
	nasreq.xml		\
	ncp2222.py              \
	packet-ncp2222.inc	\
	print.ps                \
	process-x11-fields.pl	\
	randpkt.c		\
	rdps.c			\
	sunping.xml		\
	text2pcap-scanner.l     \
	text2pcap.c             \
	text2pcap.h             \
	wka.tmpl		\
	x11-fields

if SETUID_INSTALL
install-exec-hook:
	-chmod +s $(DESTDIR)$(bindir)/ethereal
	-chmod +s $(DESTDIR)$(bindir)/tethereal
else
install-exec-hook:
endif

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

DIST_SUBDIRS = tools wiretap doc epan plugins packaging gtk help

if HAVE_PLUGINS
SUBDIRS = tools wiretap doc epan plugins packaging help @ethereal_SUBDIRS@
else
SUBDIRS = tools wiretap doc epan packaging help @ethereal_SUBDIRS@
endif

ethereal.1: ethereal doc/ethereal.pod
	(cd doc ; \
	$(MAKE) ../ethereal.1 )

tethereal.1: tethereal doc/tethereal.pod
	(cd doc ; \
	$(MAKE) ../tethereal.1 )

ethereal-filter.4: tethereal doc/ethereal-filter.pod.template
	(cd doc ; \
	$(MAKE) ../ethereal-filter.4 )

editcap.1: doc/editcap.pod
	(cd doc ; \
	$(MAKE) ../editcap.1 )

idl2eth.1: doc/idl2eth.pod
	(cd doc ; \
	$(MAKE) ../idl2eth.1 )

mergecap.1: doc/mergecap.pod
	(cd doc ; \
	$(MAKE) ../mergecap.1 )

text2pcap.1: doc/text2pcap.pod
	(cd doc ; \
	$(MAKE) ../text2pcap.1 )

packet-ncp2222.c : ncp2222.py
	$(PYTHON) $(srcdir)/ncp2222.py -o $@

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

# We load top_stagedir with an explicit path so that libtool doesn't freak.
top_stagedir=`cd $(top_srcdir) && pwd`/packaging/svr4.stage
stagedir=$(top_stagedir)/$(PACKAGE).stage
host_cpu=@host_cpu@
host_os=@host_os@

svr4-package: $(bin_SCRIPTS) $(lib_LTLIBRARIES)
	@if test x$(HAVE_SVR4_PACKAGING) = xyes ; then \
		rm -rf $(stagedir) ; \
		$(MAKE) DESTDIR=$(stagedir) install; \
		$(srcdir)/packaging/svr4/mkpkg \
			$(PACKAGE) \
			$(PACKAGE)-$(VERSION)-$(host_os)-$(host_cpu)-local \
			$(prefix) \
			$(top_stagedir) ; \
	else \
		echo "Error: SVR4 packaging tools not found." ; \
		echo "Package build abandoned." ; \
	fi

solaris-package: svr4-package

rpm_topdir=`cd $(top_srcdir) && pwd`/packaging/rpm
rpm-package: dist
	if test x$(HAVE_RPM) = xyes ; then \
		cd $(rpm_topdir) ; \
		mkdir -p BUILD RPMS SOURCES ; \
		cd SOURCES ; \
		ln -s ../../../$(distdir).tar.gz ; \
		cd .. ; \
		rpm --define "_topdir `cd . && pwd`" -bb SPECS/ethereal.spec && \
			echo "Package successfully built in `pwd`/RPMS." ; \
	else \
		echo "Error: RPM executable and/or source directory not found." ; \
	fi
srpm-package: dist
	if test x$(HAVE_RPM) = xyes ; then \
		cd $(rpm_topdir) ; \
		mkdir -p BUILD SRPMS SOURCES ; \
		cd SOURCES ; \
		ln -s ../../../$(distdir).tar.gz ; \
		cd .. ; \
		rpm --define "_topdir `cd . && pwd`" -bs SPECS/ethereal.spec && \
			echo "Package successfully built in `pwd`/SRPMS." ; \
	else \
		echo "Error: RPM executable and/or source directory not found." ; \
	fi

debian-package: debian/rules
	dpkg-buildpackage -rfakeroot -us -uc

clean-local:
	rm -rf $(top_stagedir)

test-splint: $(ethereal_SOURCES)
	splint \
		-gnu-extensions	-D_U_=""	\
		-I. `glib-config --cflags` \
		-I./epan \
		-I./tools/lemon \
		-I./wiretap	\
		$(ethereal_SOURCES)
