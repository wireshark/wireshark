# Makefile.am
# Automake file for Ethereal
#
# $Id: Makefile.am,v 1.86 1999/10/14 05:41:28 itojun Exp $
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

ethereal_SOURCES = \
	alignment.h    \
	capture.c      \
	capture.h      \
	colors.c       \
	colors.h       \
	column.c       \
	column.h       \
	dfilter-int.h  \
	dfilter-grammar.y \
	dfilter-scanner.l \
	dfilter.c      \
	dfilter.h      \
	display.c      \
	display.h      \
	ethertype.c    \
	etypes.h       \
	file.c         \
	file.h         \
	follow.c       \
	follow.h       \
	globals.h      \
	ipproto.c      \
	packet-aarp.c  \
	packet-arp.c   \
	packet-ascend.c\
	packet-atalk.c \
	packet-atm.c   \
	packet-bootp.c \
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
	packet-http.c  \
	packet-icmpv6.c\
	packet-icp.c   \
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
	packet-llc.c   \
	packet-lpd.c   \
	packet-nbipx.c \
	packet-nbns.c  \
	packet-ncp.c   \
	packet-ncp.h   \
	packet-netbios.c \
	packet-netbios.h \
	packet-nntp.c  \
	packet-ntp.c  \
	packet-ntp.h  \
	packet-null.c  \
	packet-osi.c   \
	packet-ospf.c  \
	packet-ospf.h  \
	packet-pim.c   \
	packet-pop.c   \
	packet-ppp.c   \
	packet-pppoe.c \
	packet-pptp.c  \
	packet-radius.c\
	packet-raw.c   \
	packet-rip.c   \
	packet-rip.h   \
	packet-ripng.c \
	packet-ripng.h \
	packet-rsvp.c  \
	packet-rsvp.h  \
	packet-rtsp.c  \
	packet-sdp.c   \
	packet-smb.c   \
	packet-sna.c   \
	packet-tcp.c   \
	packet-telnet.c\
	packet-tftp.c  \
	packet-tr.c    \
	packet-trmac.c \
	packet-udp.c   \
	packet-vines.c \
	packet-vines.h \
	packet-x25.c   \
	packet-yhoo.c  \
	packet-yhoo.h  \
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
	resolv.c       \
	resolv.h       \
	smb.h          \
	summary.c      \
	summary.h      \
	timestamp.h    \
	util.c         \
	util.h         \
	xdlc.c         \
	xdlc.h

EXTRA_ethereal_SOURCES = \
	dfilter-grammar.c \
	dfilter-grammar.h \
	dfilter-scanner.c \
	packet-snmp.c	\
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
@STRNCASECMP_O@ @MKSTEMP_O@ @INET_ATON_O@ @INET_ATON_O@ @INET_NTOP_O@\
wiretap/libwiretap.a gtk/libui.a \
@SNMP_A@

ps.c: print.ps rdps
	./rdps $(srcdir)/print.ps ps.c

rdps: rdps.c
	$(CC) -o rdps $(srcdir)/rdps.c

randpkt.o: randpkt.c
	$(CC) -DHAVE_CONFIG_H -I. `glib-config --cflags` -c $(srcdir)/randpkt.c

randpkt: randpkt.o wiretap/libwiretap.a
	$(LINK) -o randpkt randpkt.o wiretap/libwiretap.a `glib-config --libs` -lz

DISTCLEANFILES =	\
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
	manuf                   \
	print.ps                \
	README.irix		\
	README.linux		\
	README.tru64		\
	README.win32		\
	randpkt.c		\
	rdps.c

SUBDIRS = wiretap gtk @ethereal_SUBDIRS@

ethereal.1: ethereal doc/ethereal.pod.template
	(cd doc ; \
	$(MAKE) ../ethereal.1 )

dfilter-scanner.c : dfilter-scanner.l
	$(LEX) -Pdfilter_ -t $(srcdir)/dfilter-scanner.l > dfilter-scanner.c
