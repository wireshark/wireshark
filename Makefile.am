# Makefile.am
# Automake file for Ethereal
#
# $Id: Makefile.am,v 1.116 1999/11/23 17:09:56 gram Exp $
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

bin_PROGRAMS = ethereal

man_MANS = ethereal.1

sysconf_DATA = manuf

# Any POSIX-compatible YACC should honor the -p flag
YFLAGS=-d -p dfilter_

DISSECTOR_SOURCES = \
	packet-aarp.c  \
	packet-afs.c   \
	packet-afs.h   \
	packet-arp.c   \
	packet-ascend.c\
	packet-atalk.c \
	packet-atalk.h \
	packet-atm.c   \
	packet-auto_rp.c   \
	packet-bgp.c   \
	packet-bgp.h   \
	packet-bootp.c \
	packet-bootparams.c \
	packet-bootparams.h \
	packet-bpdu.c  \
	packet-cdp.c   \
	packet-clip.c  \
	packet-data.c  \
	packet-dns.c   \
	packet-dns.h   \
	packet-eth.c   \
	packet-fddi.c  \
	packet-ftp.c   \
	packet-giop.c  \
	packet-gre.c   \
	packet-hsrp.c  \
	packet-http.c  \
	packet-icmpv6.c\
	packet-icp.c   \
	packet-icq.c   \
	packet-imap.c   \
	packet-ip.c    \
	packet-ip.h    \
	packet-ipp.c   \
	packet-ipsec.c \
	packet-ipv6.c  \
	packet-ipv6.h  \
	packet-ipx.c   \
	packet-ipx.h   \
	packet-isakmp.c\
	packet-lapb.c  \
	packet-lapd.c  \
	packet-llc.c   \
	packet-lpd.c   \
	packet-mapi.c  \
	packet-mount.c \
	packet-mount.h \
	packet-nbipx.c \
	packet-nbns.c  \
	packet-ncp.c   \
	packet-ncp.h   \
	packet-netbios.c \
	packet-netbios.h \
	packet-nfs.c   \
	packet-nfs.h   \
	packet-nlm.c   \
	packet-nlm.h   \
	packet-nntp.c  \
	packet-ntp.c  \
	packet-ntp.h  \
	packet-null.c  \
	packet-osi.c   \
	packet-ospf.c  \
	packet-ospf.h  \
	packet-pim.c   \
	packet-pop.c   \
	packet-portmap.c   \
	packet-portmap.h   \
	packet-ppp.c   \
	packet-pppoe.c \
	packet-pptp.c  \
	packet-q2931.c \
	packet-q931.c  \
	packet-radius.c\
	packet-raw.c   \
	packet-rip.c   \
	packet-rip.h   \
	packet-ripng.c \
	packet-ripng.h \
	packet-rpc.c   \
	packet-rpc.h   \
	packet-rsvp.c  \
	packet-rsvp.h  \
	packet-rtsp.c  \
	packet-rx.c  \
	packet-rx.h  \
	packet-sap.c   \
	packet-sdp.c   \
	packet-smb.c   \
	packet-sna.c   \
	packet-sna.h   \
	packet-sscop.c \
	packet-stat.c   \
	packet-stat.h   \
	packet-tcp.c   \
	packet-telnet.c\
	packet-tftp.c  \
	packet-tr.c    \
	packet-trmac.c \
	packet-udp.c   \
	packet-vines.c \
	packet-vines.h \
	packet-vlan.c \
	packet-vrrp.c \
	packet-x25.c   \
	packet-yhoo.c  \
	packet-yhoo.h  \
	packet-ypbind.c \
	packet-ypbind.h \
	packet-ypserv.c \
	packet-ypserv.h \
	packet-ypxfr.c \
	packet-ypxfr.h 

ethereal_SOURCES = \
	alignment.h    \
	capture.c      \
	capture.h      \
	colors.c       \
	colors.h       \
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
	file.c         \
	file.h         \
	follow.c       \
	follow.h       \
	globals.h      \
	inet_v6defs.h  \
	ipproto.c      \
	ipv4.c         \
	ipv4.h         \
	packet.c       \
	packet.h       \
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
	summary.c      \
	summary.h      \
	timestamp.h    \
	util.c         \
	util.h         \
	xdlc.c         \
	xdlc.h         \
	$(DISSECTOR_SOURCES)

EXTRA_ethereal_SOURCES = \
	dfilter-grammar.c \
	dfilter-grammar.h \
	dfilter-scanner.c \
	packet-snmp.c	\
	packet-snmp.h	\
	snprintf.c	\
	snprintf.h	\
	snprintf-imp.h	\
	strerror.c	\
	strerror.h	\
	strncasecmp.c	\
	mkstemp.c	\
	inet_aton.c     \
	inet_pton.c     \
	inet_ntop.c

ethereal_DEPENDENCIES = @SNMP_O@ @SNPRINTF_O@ @STRERROR_O@ \
@STRNCASECMP_O@ @MKSTEMP_O@ @INET_ATON_O@ @INET_PTON_O@ @INET_NTOP_O@\
wiretap/libwiretap.a gtk/libui.a
ethereal_LDADD = @SNMP_O@ @SNPRINTF_O@ @STRERROR_O@ \
@STRNCASECMP_O@ @MKSTEMP_O@ @INET_ATON_O@ @INET_PTON_O@ @INET_NTOP_O@\
wiretap/libwiretap.a gtk/libui.a \
@SNMP_A@

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
register.c: packet.c $(DISSECTOR_SOURCES) @SNMP_C@
	@echo Making register.c
	@$(srcdir)/make-reg-dotc $(srcdir) packet.c $(DISSECTOR_SOURCES) @SNMP_C@

ps.c: print.ps rdps
	./rdps $(srcdir)/print.ps ps.c

rdps: rdps.c
	$(CC) -o rdps $(srcdir)/rdps.c

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
	doc/Makefile.in         \
	doc/Makefile.am         \
	doc/dfilter2pod.in      \
	doc/ethereal.pod.template \
	doc/randpkt.txt		\
	ethereal.spec.in         \
	image/icon-excl.xpm     \
	image/icon-ethereal.xpm \
	Makefile.nmake		\
	make-reg-dotc		\
	manuf                   \
	print.ps                \
	README.irix		\
	README.linux		\
	README.tru64		\
	README.win32		\
	randpkt.c		\
	rdps.c

#
# Oh, yuk.  We don't want to include "register.c" in the distribution, as
# its contents depend on the configuration, and therefore we want it
# to be built when the first "make" is done; however, Automake insists
# on putting *all* source into the distribution.
#
# We work around this by having a "disk-hook" rule that deletes
# "register.c", so that "dist" won't pick it up.
#
dist-hook:
	@rm -f $(distdir)/register.c

SUBDIRS = wiretap gtk @ethereal_SUBDIRS@

ethereal.1: ethereal doc/ethereal.pod.template
	(cd doc ; \
	$(MAKE) ../ethereal.1 )

dfilter-scanner.c : dfilter-scanner.l
	$(LEX) -Pdfilter_ -t $(srcdir)/dfilter-scanner.l > dfilter-scanner.c
