# Makefile.am
# Automake file for Ethereal
#
# $Id: Makefile.am,v 1.175 2000/03/09 18:31:49 ashokn Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@zing.org>
# Copyright 1998 Gerald Combs
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

EXTRA_PROGRAMS = ethereal_static
bin_PROGRAMS = ethereal editcap tethereal

man_MANS = ethereal.1 editcap.1 tethereal.1

sysconf_DATA = manuf

# Any POSIX-compatible YACC should honor the -p flag
YFLAGS=-d -p dfilter_

DISSECTOR_SOURCES = \
	packet-aarp.c  \
	packet-aarp.h  \
	packet-afs.c   \
	packet-afs.h   \
	packet-arp.c   \
	packet-arp.h   \
	packet-ascend.c\
	packet-ascend.h\
	packet-atalk.c \
	packet-atalk.h \
	packet-atm.c   \
	packet-atm.h   \
	packet-auto_rp.c   \
	packet-auto_rp.h   \
	packet-bgp.c   \
	packet-bgp.h   \
	packet-bootp.c \
	packet-bootp.h \
	packet-bootparams.c \
	packet-bootparams.h \
	packet-bpdu.c  \
	packet-bpdu.h  \
	packet-cdp.c   \
	packet-cdp.h   \
	packet-cgmp.c  \
	packet-cgmp.h  \
	packet-clip.c  \
	packet-clip.h  \
	packet-data.c  \
	packet-dhis.c  \
	packet-dhis.h  \
	packet-dns.c   \
	packet-dns.h   \
	packet-eth.c   \
	packet-eth.h   \
	packet-fddi.c  \
	packet-fddi.h  \
	packet-ftp.c   \
	packet-ftp.h   \
	packet-giop.c  \
	packet-giop.h  \
	packet-gre.c   \
	packet-gre.h   \
	packet-h1.c    \
	packet-h1.h    \
	packet-hsrp.c  \
	packet-hsrp.h  \
	packet-http.c  \
	packet-http.h  \
	packet-icmpv6.c\
	packet-icmpv6.h\
	packet-icp.c   \
	packet-icp.h   \
	packet-icq.c   \
	packet-icq.h   \
	packet-imap.c   \
	packet-imap.h   \
	packet-ip.c    \
	packet-ip.h    \
	packet-ipp.c   \
	packet-ipp.h   \
	packet-ipsec.c \
	packet-ipsec.h \
	packet-ipv6.c  \
	packet-ipv6.h  \
	packet-ipx.c   \
	packet-ipx.h   \
	packet-irc.c   \
	packet-irc.h   \
	packet-isakmp.c\
	packet-isakmp.h\
	packet-isis.h  \
	packet-isis.c  \
	packet-isis-clv.h \
	packet-isis-clv.c \
	packet-isis-hello.h \
	packet-isis-hello.c \
	packet-isis-lsp.h \
	packet-isis-lsp.c \
	packet-isis-snp.h \
	packet-isis-snp.c \
	packet-isl.c   \
	packet-isl.h   \
	packet-l2tp.c  \
	packet-l2tp.h  \
	packet-lapb.c  \
	packet-lapb.h  \
	packet-lapd.c  \
	packet-lapd.h  \
	packet-ldap.c  \
	packet-ldap.h  \
	packet-llc.c   \
	packet-llc.h   \
	packet-lpd.c   \
	packet-lpd.h   \
	packet-mapi.c  \
	packet-mapi.h  \
	packet-mount.c \
	packet-mount.h \
	packet-mpls.c \
	packet-mpls.h \
	packet-nbipx.c \
	packet-nbipx.h \
	packet-nbns.c  \
	packet-nbns.h  \
	packet-ncp.c   \
	packet-ncp.h   \
	packet-netbios.c \
	packet-netbios.h \
	packet-nfs.c   \
	packet-nfs.h   \
	packet-nlm.c   \
	packet-nlm.h   \
	packet-nntp.c  \
	packet-nntp.h  \
	packet-ntp.c  \
	packet-ntp.h  \
	packet-null.c  \
	packet-null.h  \
	packet-osi.c   \
	packet-osi.h   \
	packet-ospf.c  \
	packet-ospf.h  \
	packet-pim.c   \
	packet-pim.h   \
	packet-pop.c   \
	packet-pop.h   \
	packet-portmap.c   \
	packet-portmap.h   \
	packet-ppp.c   \
	packet-ppp.h   \
	packet-pppoe.c \
	packet-pppoe.h \
	packet-pptp.c  \
	packet-pptp.h  \
	packet-q2931.c \
	packet-q2931.h \
	packet-q931.c  \
	packet-q931.h  \
	packet-radius.c\
	packet-radius.h\
	packet-raw.c   \
	packet-raw.h   \
	packet-rip.c   \
	packet-rip.h   \
	packet-ripng.c \
	packet-ripng.h \
	packet-rpc.c   \
	packet-rpc.h   \
	packet-rsvp.c  \
	packet-rsvp.h  \
	packet-rtsp.c  \
	packet-rtsp.h  \
	packet-rx.c  \
	packet-rx.h  \
	packet-sap.c   \
	packet-sap.h   \
	packet-sdp.c   \
	packet-sdp.h   \
	packet-smb.c   \
	packet-smb.h   \
	packet-smb-browse.c \
	packet-smb-common.c \
	packet-smb-common.h \
	packet-smb-logon.c \
	packet-smb-mailslot.c \
	packet-smb-pipe.c \
	packet-sna.c   \
	packet-sna.h   \
	packet-snmp.c	\
	packet-snmp.h	\
	packet-srvloc.c \
	packet-srvloc.h \
	packet-sscop.c \
	packet-sscop.h \
	packet-stat.c   \
	packet-stat.h   \
	packet-tacacs.c \
	packet-tacacs.h \
	packet-tcp.c   \
	packet-tcp.h   \
	packet-telnet.c\
	packet-telnet.h\
	packet-tftp.c  \
	packet-tftp.h  \
	packet-time.c  \
	packet-time.h  \
	packet-tns.c \
	packet-tns.h \
	packet-tr.c    \
	packet-tr.h    \
	packet-trmac.c \
	packet-trmac.h \
	packet-udp.c   \
	packet-udp.h   \
	packet-v120.c \
	packet-v120.h \
	packet-vines.c \
	packet-vines.h \
	packet-vlan.c \
	packet-vlan.h \
	packet-vrrp.c \
	packet-vrrp.h \
	packet-vtp.c  \
	packet-vtp.h  \
	packet-wccp.c\
	packet-wccp.h\
	packet-who.c\
	packet-who.h\
	packet-x25.c   \
	packet-x25.h   \
	packet-yhoo.c  \
	packet-yhoo.h  \
	packet-ypbind.c \
	packet-ypbind.h \
	packet-ypserv.c \
	packet-ypserv.h \
	packet-ypxfr.c \
	packet-ypxfr.h 

ETHEREAL_COMMON_SOURCES = \
	alignment.h    \
	asn1.c         \
	asn1.h         \
	column.c       \
	column.h       \
	conversation.c \
	conversation.h \
	dfilter-int.h  \
	dfilter-grammar.y \
	dfilter-scanner.l \
	dfilter.c      \
	dfilter.h      \
	ethertype.c    \
	etypes.h       \
	follow.c       \
	follow.h       \
	inet_v6defs.h  \
	ipproto.c      \
	ipv4.c         \
	ipv4.h         \
	nlpid.h        \
	oui.h          \
	packet.c       \
	packet.h       \
	plugins.c      \
	plugins.h      \
	prefs.c        \
	prefs.h        \
	print.c        \
	print.h        \
	proto.c        \
	proto.h        \
	ps.c           \
	ps.h           \
	register.c     \
	register.h     \
	resolv.c       \
	resolv.h       \
	smb.h          \
	timestamp.h    \
	util.c         \
	util.h         \
	xdlc.c         \
	xdlc.h

ethereal_SOURCES = \
	$(DISSECTOR_SOURCES) \
	$(ETHEREAL_COMMON_SOURCES) \
	capture.c      \
	capture.h      \
	file.c         \
	file.h         \
	globals.h      \
	menu.h         \
	simple_dialog.h \
	summary.c      \
	summary.h      \
	ui_util.h

ethereal_static_SOURCES = \
	$(ethereal_SOURCES)

EXTRA_ethereal_SOURCES = \
	dfilter-grammar.c \
	dfilter-grammar.h \
	dfilter-scanner.c \
	snprintf.c	\
	snprintf.h	\
	snprintf-imp.h	\
	strerror.c	\
	strerror.h	\
	strncasecmp.c	\
	mkstemp.c	\
	mkstemp.h	\
	inet_aton.c     \
	inet_pton.c     \
	inet_ntop.c

# Optional objects that I know how to build. These will be
# linked into the ethereal executable.
# They will also be linked into the tethereal executable; if this
# list ever grows to include something that can't be linked with
# tethereal, or if tethereal needs something that ethereal doesn't,
# we should probably split this into stuff needed both
# by ethereal and tethereal and stuff needed only by one or the
# other.
ethereal_optional_objects = @SNPRINTF_O@ @STRERROR_O@ \
	@STRNCASECMP_O@ @MKSTEMP_O@ \
	@INET_ATON_O@ @INET_PTON_O@ @INET_NTOP_O@ 

# Additional libs that I know how to build. These will be
# linked into the ethereal executable.
ethereal_additional_libs = wiretap/libwiretap.a gtk/libui.a

# This is the automake dependency variable for the executable
ethereal_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs)	\
	plugins/gryphon/gryphon.la

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
	@SNMP_LIBS@			\
	"-dlopen" self	\
	"-dlopen" plugins/gryphon/gryphon.la @PCAP_LIBS@ @GTK_LIBS@

ethereal_static_LDADD = \
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs) \
	@SNMP_LIBS@			\
	@PCAP_LIBS@ @GTK_LIBS@

ethereal_LDFLAGS = -export-dynamic
ethereal_static_LDFLAGS = -Wl,-static

tethereal_SOURCES = \
	$(DISSECTOR_SOURCES) \
	$(ETHEREAL_COMMON_SOURCES) \
	tethereal.c

# Additional libs that I know how to build. These will be
# linked into the tethereal executable.
tethereal_additional_libs = wiretap/libwiretap.a

# This is the automake dependency variable for the executable
tethereal_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(tethereal_additional_libs)	\
	plugins/gryphon/gryphon.la

# This automake variable adds to the link-line for the executable
tethereal_LDADD = wiretap/libwiretap.a	\
	$(ethereal_optional_objects)	\
	$(tethereal_additional_libs)	\
	@SNMP_LIBS@			\
	"-dlopen" self	\
	"-dlopen" plugins/gryphon/gryphon.la @GLIB_LIBS@ -lm \
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@

tethereal_LDFLAGS = -export-dynamic

editcap_SOURCES = editcap.c

# This is the automake dependency variable for the executable
editcap_DEPENDENCIES = wiretap/libwiretap.a

# This automake variable adds to the link-line for the executable
editcap_LDADD = wiretap/libwiretap.a @GLIB_LIBS@

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
# We assume that all dissector routines are in "packet-XXX.c" files,
# or in "packet.c".
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
register.c: packet.c $(DISSECTOR_SOURCES)
	@echo Making register.c
	@$(srcdir)/make-reg-dotc $(srcdir) packet.c $(DISSECTOR_SOURCES)

ps.c: print.ps rdps
	./rdps $(srcdir)/print.ps ps.c

rdps: rdps.c
	$(CC) $(CFLAGS) -o rdps $(srcdir)/rdps.c

randpkt.o: randpkt.c
	$(CC) -DHAVE_CONFIG_H -I. `glib-config --cflags` -c $(srcdir)/randpkt.c

randpkt: randpkt.o wiretap/libwiretap.a
	$(LINK) -o randpkt randpkt.o wiretap/libwiretap.a `glib-config --libs` -lz

DISTCLEANFILES =	\
	register.c	\
	rdps		\
	ps.c		\
	*~

EXTRA_DIST = \
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
	doc/README.developer    \
	doc/Makefile.in         \
	doc/Makefile.am         \
	doc/dfilter2pod.in      \
	doc/editcap.pod		\
	doc/ethereal.pod.template \
	doc/proto_tree		\
	doc/randpkt.txt		\
	doc/tethereal.pod.template \
	editcap.c		\
	ethereal.spec.in         \
	image/ethereal48x48-trans.png  \
	image/ethereal48x48.png \
	image/icon-excl.xpm     \
	image/icon-ethereal.xpm \
	INSTALL.configure       \
	Makefile.nmake		\
	make-reg-dotc		\
	manuf                   \
	print.ps                \
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
	TODO

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

SUBDIRS = wiretap gtk plugins @ethereal_SUBDIRS@

ethereal.1: ethereal doc/ethereal.pod.template
	(cd doc ; \
	$(MAKE) ../ethereal.1 )

tethereal.1: tethereal doc/tethereal.pod.template
	(cd doc ; \
	$(MAKE) ../tethereal.1 )

editcap.1: doc/editcap.pod
	(cd doc ; \
	$(MAKE) ../editcap.1 )

dfilter-scanner.c : dfilter-scanner.l
	$(LEX) -Pdfilter_ -t $(srcdir)/dfilter-scanner.l > dfilter-scanner.c

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
