# Makefile.am
# Automake file for Ethereal
#
# $Id: Makefile.am,v 1.344 2001/07/08 21:51:31 hagbard Exp $
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
bin_PROGRAMS = @ethereal_bin@ @editcap_bin@ @tethereal_bin@ @dftest_bin@ @randpkt_bin@ @text2pcap_bin@
man1_MANS = @ethereal_man@ @editcap_man@ @tethereal_man@ @text2pcap_man@
man_MANS = 

EXTRA_PROGRAMS = ethereal ethereal_static tethereal tethereal_static editcap dftest text2pcap

sysconf_DATA = manuf

DISSECTOR_SRC = \
	packet-aarp.c  \
	packet-afs.c   \
	packet-aim.c   \
	packet-arp.c   \
	packet-ascend.c\
	packet-atalk.c \
	packet-atm.c   \
	packet-auto_rp.c   \
	packet-bacapp.c   \
	packet-bacnet.c   \
	packet-bgp.c   \
	packet-bootp.c \
	packet-bootparams.c \
	packet-bpdu.c  \
	packet-bvlc.c \
	packet-bxxp.c \
	packet-cdp.c   \
	packet-cgmp.c  \
	packet-chdlc.c  \
	packet-clip.c  \
	packet-clnp.c  \
	packet-cops.c  \
	packet-cups.c  \
	packet-data.c  \
	packet-dcerpc.c  \
	packet-ddtp.c  \
	packet-dec-bpdu.c \
	packet-diameter.c \
	packet-dns.c   \
	packet-dsi.c   \
	packet-dvmrp.c \
	packet-eigrp.c \
	packet-esis.c  \
	packet-eth.c   \
	packet-ethertype.c   \
	packet-fddi.c  \
	packet-fr.c    \
	packet-frame.c  \
	packet-ftp.c   \
	packet-giop.c  \
	packet-gnutella.c \
	packet-gre.c   \
	packet-gtp.c   \
	packet-gvrp.c  \
	packet-h1.c    \
	packet-h261.c  \
	packet-hclnfsd.c  \
	packet-hsrp.c  \
	packet-http.c  \
	packet-icmpv6.c\
	packet-icp.c   \
	packet-icq.c   \
	packet-ieee80211.c \
	packet-ieee8023.c \
	packet-igmp.c  \
	packet-igrp.c  \
	packet-imap.c   \
	packet-ip.c    \
	packet-ipp.c   \
	packet-ipsec.c \
	packet-ipv6.c  \
	packet-ipx.c   \
	packet-irc.c   \
	packet-isakmp.c\
	packet-iscsi.c \
	packet-isis.c  \
	packet-isis-clv.c \
	packet-isis-hello.c \
	packet-isis-lsp.c \
	packet-isis-snp.c \
	packet-isl.c   \
	packet-isup.c  \
	packet-iua.c   \
	packet-kerberos.c \
	packet-klm.c   \
	packet-l2tp.c  \
	packet-lapb.c  \
	packet-lapbether.c \
	packet-lapd.c  \
	packet-ldap.c  \
	packet-ldp.c   \
	packet-llc.c   \
	packet-lmi.c   \
	packet-lpd.c   \
	packet-m2pa.c  \
	packet-m3ua.c  \
	packet-mapi.c  \
	packet-mbtcp.c \
	packet-mip.c  \
	packet-mount.c \
	packet-mpeg1.c  \
	packet-mpls.c \
	packet-mrdisc.c \
	packet-msnip.c \
	packet-msproxy.c \
	packet-mtp3.c \
	packet-nbipx.c \
	packet-nbns.c  \
	packet-ncp.c   \
	packet-ncp2222.c   \
	packet-netbios.c \
	packet-nfs.c   \
	packet-nisplus.c \
	packet-nlm.c   \
	packet-nntp.c  \
	packet-ntp.c  \
	packet-null.c  \
	packet-osi.c   \
	packet-osi-options.c \
	packet-ospf.c  \
	packet-pim.c   \
	packet-pop.c   \
	packet-portmap.c   \
	packet-ppp.c   \
	packet-pppoe.c \
	packet-pptp.c  \
	packet-q2931.c \
	packet-q931.c  \
	packet-quake.c \
	packet-quakeworld.c \
	packet-quake2.c \
	packet-radius.c\
	packet-ranap.c \
	packet-raw.c   \
	packet-rip.c   \
	packet-ripng.c \
	packet-rlogin.c \
	packet-rpc.c   \
	packet-rquota.c \
	packet-rsh.c   \
	packet-rsvp.c  \
	packet-rtcp.c  \
	packet-rtp.c   \
	packet-rtsp.c  \
	packet-rwall.c \
	packet-rx.c  \
	packet-sap.c   \
	packet-sctp.c   \
	packet-sdp.c   \
	packet-sip.c   \
	packet-sll.c   \
	packet-smb.c   \
	packet-smb-browse.c \
	packet-smb-common.c \
	packet-smb-logon.c \
	packet-smb-mailslot.c \
	packet-smb-pipe.c \
	packet-smtp.c \
	packet-sna.c   \
	packet-snmp.c	\
	packet-socks.c \
	packet-spray.c \
	packet-srvloc.c \
	packet-sscop.c \
	packet-stat.c   \
	packet-stat-notify.c \
	packet-sual.c   \
	packet-syslog.c \
	packet-tacacs.c \
	packet-tcp.c   \
	packet-telnet.c\
	packet-tftp.c  \
	packet-time.c  \
	packet-tns.c \
	packet-tpkt.c  \
	packet-tr.c    \
	packet-trmac.c \
	packet-udp.c   \
	packet-v120.c \
	packet-vines.c \
	packet-vlan.c \
	packet-vrrp.c \
	packet-vtp.c  \
	packet-wccp.c \
	packet-wcp.c \
	packet-who.c  \
	packet-wap.c \
	packet-wtls.c \
	packet-wsp.c \
	packet-wtp.c \
	packet-x11.c   \
	packet-x25.c   \
	packet-xot.c   \
	packet-yhoo.c  \
	packet-ypbind.c \
	packet-yppasswd.c \
	packet-ypserv.c \
	packet-ypxfr.c \
	packet-zebra.c

PLUGIN_SRC = \
	plugins/mgcp/packet-mgcp.c	\
	plugins/gryphon/packet-gryphon.c 

noinst_HEADERS = \
	packet-afs.h   \
	packet-afs-macros.h \
	packet-afs-register-info.h \
	packet-afs-defs.h \
	packet-arp.h   \
	packet-atalk.h \
	packet-bgp.h   \
	packet-bootparams.h \
	packet-chdlc.h \
	packet-clip.h  \
	packet-dcerpc.h \
	packet-ddtp.h  \
	packet-diameter-defs.h \
	packet-dns.h   \
	packet-dvmrp.h \
	packet-esis.h  \
	packet-eth.h   \
	packet-fddi.h  \
	packet-fr.h    \
	packet-frame.h  \
	packet-giop.h  \
	packet-gnutella.h \
	packet-hclnfsd.h  \
	packet-http.h  \
	packet-ieee80211.h \
	packet-ieee8023.h \
	packet-ip.h    \
	packet-ipsec.h \
	packet-ipv6.h  \
	packet-ipx.h   \
	packet-isis.h  \
	packet-isis-clv.h \
	packet-isis-hello.h \
	packet-isis-lsp.h \
	packet-isis-snp.h \
	packet-isl.h   \
	packet-klm.h   \
	packet-ldap.h  \
	packet-llc.h   \
	packet-mount.h \
	packet-ncp-int.h \
	packet-netbios.h \
	packet-nfs.h   \
	packet-nisplus.h \
	packet-nlm.h   \
	packet-ntp.h  \
	packet-null.h  \
	packet-osi.h   \
	packet-osi-options.h \
	packet-pim.h   \
	packet-portmap.h   \
	packet-ppp.h   \
	packet-q931.h  \
	packet-raw.h   \
	packet-ripng.h \
	packet-rpc.h   \
	packet-rquota.h \
	packet-rtcp.h  \
	packet-rtp.h   \
	packet-rwall.h  \
	packet-rx.h  \
	packet-sll.h   \
	packet-smb.h   \
	packet-smb-browse.h \
	packet-smb-common.h \
	packet-smb-logon.h \
	packet-smb-mailslot.h \
	packet-smb-pipe.h \
	packet-sna.h   \
	packet-snmp.h	\
	packet-spray.h \
	packet-stat.h   \
	packet-stat-notify.h \
	packet-tcp.h   \
	packet-tns.h \
	packet-tpkt.h  \
	packet-tr.h    \
	packet-udp.h   \
	packet-vines.h \
	packet-vlan.h \
	packet-wccp.h \
	packet-wap.h \
	packet-wtls.h \
	packet-wtp.h \
	packet-wsp.h \
	packet-x11-keysym.h	\
	packet-yhoo.h  \
	packet-ypbind.h \
	packet-yppasswd.h \
	packet-ypserv.h \
	packet-ypxfr.h 

ETHEREAL_COMMON_SRC = \
	aftypes.h      \
	alignment.h    \
	asn1.c         \
	asn1.h         \
	bridged_pids.h \
	column.c       \
	column.h       \
	color.h        \
	etypes.h       \
	follow.c       \
	follow.h       \
	greproto.h     \
	in_cksum.c     \
	in_cksum.h     \
	ipproto.c      \
	ipproto.h      \
	llcsaps.h      \
	nlpid.h        \
	oui.h          \
	ppptypes.h     \
	prefs.c        \
	prefs.h        \
	prefs-int.h    \
	print.c        \
	print.h        \
	ps.c           \
	ps.h           \
	ptvcursor.c	\
	ptvcursor.h	\
	reassemble.c   \
	reassemble.h   \
	register.h     \
	smb.h          \
	util.c         \
	util.h         \
	x11-declarations.h \
	x11-register-info.h \
	xdlc.c         \
	xdlc.h

BUILT_SOURCES = \
	x11-declarations.h \
	x11-register-info.h

ethereal_SOURCES = \
	$(DISSECTOR_SRC) \
	$(ETHEREAL_COMMON_SRC) \
	register.c     \
	capture.c      \
	capture.h      \
	file.c         \
	file.h         \
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
	ui_util.h

ethereal_static_SOURCES = \
	$(DISSECTOR_SRC) \
	$(ETHEREAL_COMMON_SRC) \
	register-static.c     \
	capture.c      \
	capture.h      \
	file.c         \
	file.h         \
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
	plugins/gryphon/gryphon.la \
	plugins/mgcp/mgcp.la

ethereal_static_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs)

# This automake variable adds to the link-line for the executable.
#
# Note that Ethereal doesn't have to be linked with @GLIB_LIBS@, as
# they are included in @GTK_LIBS@, and doesn't have to be linked with
# @SOCKET_LIBS@ or @NSL_LIBS@, as those should also be included in
# @GTK_LIBS@ (as those are also needed for X applications, and GTK+
# applications are X applications).
ethereal_LDADD = \
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@ 		\
	"-dlopen" self	\
	"-dlopen" plugins/gryphon/gryphon.la @PCAP_LIBS@ @GTK_LIBS@ \
	"-dlopen" plugins/mgcp/mgcp.la @PCAP_LIBS@ @GTK_LIBS@

ethereal_static_LDADD = \
	"-all-static" 			\
	plugins/mgcp/packet-mgcp-static.o		\
	plugins/gryphon/packet-gryphon-static.o		\
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@		\
	@PCAP_LIBS@ @GTK_LIBS@		

ethereal_LDFLAGS = -export-dynamic
ethereal_static_LDFLAGS = -Wl,-static

tethereal_SOURCES = \
	$(DISSECTOR_SRC) \
	$(ETHEREAL_COMMON_SRC) \
	register.c     \
	tethereal.c

tethereal_static_SOURCES = \
	$(DISSECTOR_SRC) \
	$(ETHEREAL_COMMON_SRC) \
	register-static.c     \
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
	plugins/gryphon/gryphon.la	\
	plugins/mgcp/mgcp.la

tethereal_static_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(tethereal_additional_libs)	

# This automake variable adds to the link-line for the executable
tethereal_LDADD = wiretap/libwiretap.a	\
	$(ethereal_optional_objects)	\
	$(tethereal_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@		\
	"-dlopen" self	\
	"-dlopen" plugins/gryphon/gryphon.la @GLIB_LIBS@ -lm \
	"-dlopen" plugins/mgcp/mgcp.la @GLIB_LIBS@ -lm \
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@

tethereal_static_LDADD = \
	"-all-static"		\
	plugins/mgcp/packet-mgcp-static.o		\
	plugins/gryphon/packet-gryphon-static.o		\
	wiretap/libwiretap.a	\
	$(ethereal_optional_objects)	\
	$(tethereal_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@		\
	@GLIB_LIBS@ -lm \
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@

tethereal_LDFLAGS = -export-dynamic
tethereal_static_LDFLAGS = -Wl,-static

text2pcap_SOURCES = text2pcap.c text2pcap-scanner.l
text2pcap_DEPENDENCIES = text2pcap.h

editcap_SOURCES = editcap.c

# This is the automake dependency variable for the executable
editcap_DEPENDENCIES = wiretap/libwiretap.a

# This automake variable adds to the link-line for the executable
editcap_LDADD = wiretap/libwiretap.a @GLIB_LIBS@

#
# Build various header files for the X11 dissector.
#
x11-declarations.h x11-register-info.h: x11-fields process-x11-fields.pl
	$(PERL) $(srcdir)/process-x11-fields.pl <$(srcdir)/x11-fields

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
# The first argument is the directory in which the source files live.
# All subsequent arguments are the files to scan.
#
register.c: $(DISSECTOR_SRC) $(srcdir)/make-reg-dotc
	@echo Making register.c
	@$(srcdir)/make-reg-dotc register.c $(srcdir) $(DISSECTOR_SRC)

register-static.c: $(PLUGIN_SRC) $(DISSECTOR_SRC) $(srcdir)/make-reg-dotc
	@echo Making register-static.c
	@$(srcdir)/make-reg-dotc register-static.c $(srcdir) $(PLUGIN_SRC) $(DISSECTOR_SRC)

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
	$(ETHEREAL_COMMON_SRC) \
	register.c     \
	dftest.c

dftest_additional_libs =		\
	epan/libethereal.a		\
	epan/ftypes/libftypes.a		\
	epan/dfilter/libdfilter.a

dftest_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(dftest_additional_libs)	\
	plugins/gryphon/gryphon.la \
	plugins/mgcp/mgcp.la

# This automake variable adds to the link-line for the executable
dftest_LDADD = \
	$(ethereal_optional_objects)	\
	$(dftest_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@		\
	"-dlopen" self	\
	"-dlopen" plugins/gryphon/gryphon.la @GLIB_LIBS@ -lm \
	"-dlopen" plugins/mgcp/mgcp.la @GLIB_LIBS@ -lm \
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@

dftest_LDFLAGS = -export-dynamic

DISTCLEANFILES =	\
	register.c	\
	register-static.c \
	rdps		\
	ps.c		\
	*~

EXTRA_DIST = \
	aclocal-flags		\
	capture-wpcap.c		\
	capture-wpcap.h		\
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
	doc/Makefile.in         \
	doc/Makefile.am         \
	doc/README.developer    \
	doc/README.idl2eth      \
	doc/README.regression   \
	doc/README.tvbuff	\
	doc/dfilter2pod.pl	\
	doc/editcap.pod		\
	doc/ethereal.pod.template \
	doc/randpkt.txt		\
	doc/tethereal.pod.template \
	doc/text2pcap.pod	\
	editcap.c		\
	ethereal_be.py		\
	ethereal_gen.py		\
	text2pcap.c             \
	text2pcap.h             \
	text2pcap-scanner.l     \
	getopt.c		\
	getopt.h		\
	idl2eth			\
	ieee-float.h		\
	image/Makefile.nmake	\
	image/editcap.rc.in	\
	image/elogo3d48x48.png	\
	image/ethereal48x48-trans.png  \
	image/ethereal48x48.png \
	image/ethereal.ico	\
	image/ethereal.rc.in	\
	image/icon-excl.xpm     \
	image/icon-ethereal.xpm \
	image/tethereal.rc.in	\
	image/text2pcap.rc.in	\
	INSTALL.configure       \
	Makefile.nmake		\
	make-reg-dotc		\
	make-reg-dotc.py	\
	manuf                   \
	ncp2222.py              \
	packet-ncp2222.inc	\
	print.ps                \
	process-x11-fields.pl	\
	README.aix		\
	README.bsd		\
	README.hpux		\
	README.irix		\
	README.linux		\
	README.tru64		\
	README.vmware		\
	README.win32		\
	randpkt.c		\
	rdps.c			\
	TODO			\
	x11-fields

if SETUID_INSTALL
install-exec-hook:
	-chmod +s $(DESTDIR)$(bindir)/ethereal
	-chmod +s $(DESTDIR)$(bindir)/tethereal
	-chmod +s $(DESTDIR)$(bindir)/ethereal_static
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

SUBDIRS = tools wiretap epan plugins packaging @ethereal_SUBDIRS@

ethereal.1: ethereal doc/ethereal.pod.template
	(cd doc ; \
	$(MAKE) ../ethereal.1 )

tethereal.1: tethereal doc/tethereal.pod.template
	(cd doc ; \
	$(MAKE) ../tethereal.1 )

editcap.1: doc/editcap.pod
	(cd doc ; \
	$(MAKE) ../editcap.1 )

text2pcap.1: doc/text2pcap.pod
	(cd doc ; \
	$(MAKE) ../text2pcap.1 )

packet-ncp2222.c : ncp2222.py
	$(PYTHON) $(srcdir)/ncp2222.py > $@

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

# We load top_stagedir with an explicit path so that libtool doesn't freak.
top_stagedir=`cd $(top_srcdir) && pwd`/packaging/svr4.stage
stagedir=$(top_stagedir)/$(PACKAGE).stage
host_cpu=@host_cpu@
host_os=@host_os@

svr4-package: $(bin_SCRIPTS) $(lib_LTLIBRARIES)
	if test x$(HAVE_SVR4_PACKAGING) = xyes ; then \
		rm -rf $(stagedir) ; \
		$(MAKE) DESTDIR=$(stagedir) install-strip; \
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

specfile=$(top_srcdir)/packaging/rpm/ethereal.spec

rpm-package: dist
	if test x$(HAVE_RPM_PACKAGING) = xyes ; then \
		cp $(top_srcdir)/$(distdir).tar.gz $(RPM_SOURCEDIR) ; \
		rpm -bb --clean --rmsource $(specfile) ; \
	else \
		echo "Error: RPM executable and/or source directory not found." ; \
		echo "Package build abandoned." ; \
	fi

srpm-package: dist
	if test x$(HAVE_RPM_PACKAGING) = xyes ; then \
		cp $(top_srcdir)/$(distdir).tar.gz $(RPM_SOURCEDIR) ; \
		rpm -bs --clean --rmsource $(specfile) ; \
	else \
		echo "Error: RPM executable and/or source directory not found." ; \
		echo "Package build abandoned." ; \
	fi

debian-package: debian/rules
	dpkg-buildpackage -rfakeroot -us -uc

clean-local:
	rm -rf $(top_stagedir)
