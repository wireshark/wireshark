bin_PROGRAMS = ethereal

man_MANS = ethereal.1

sysconf_DATA = manuf

YFLAGS=-d

ethereal_SOURCES = \
	alignment.h    \
	capture.c      \
	capture.h      \
	column.c       \
	column.h       \
	dfilter-grammar.y \
	dfilter-scanner.l \
	dfilter.c      \
	dfilter.h      \
	display.c      \
	display.h      \
	ethereal.c     \
	ethereal.h     \
	ethertype.c    \
	etypes.h       \
	file.c         \
	file.h         \
	filter.c       \
	filter.h       \
	follow.c       \
	follow.h       \
	gtkpacket.c    \
	gtkpacket.h    \
	menu.c         \
	menu.h         \
	packet-aarp.c  \
	packet-arp.c   \
	packet-atalk.c \
	packet-bootp.c \
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
	packet-ip.c    \
	packet-ip.h    \
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
	packet-nntp.c  \
	packet-null.c  \
	packet-osi.c   \
	packet-ospf.c  \
	packet-ospf.h  \
	packet-pop.c   \
	packet-ppp.c   \
	packet-pppoe.c \
	packet-pptp.c  \
	packet-radius.c\
	packet-raw.c   \
	packet-rip.c   \
	packet-rip.h   \
	packet-rsvp.c  \
	packet-rsvp.h  \
	packet-rtsp.c  \
	packet-sdp.c   \
	packet-smb.c   \
	packet-tcp.c   \
	packet-telnet.c\
	packet-tftp.c  \
	packet-tr.c    \
	packet-trmac.c \
	packet-udp.c   \
	packet-vines.c \
	packet-vines.h \
	packet-x25.c   \
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
	timestamp.h    \
	util.c         \
        summary.c      \
        summary.h      \
	util.h

EXTRA_ethereal_SOURCES = \
	dfilter-grammar.c \
	dfilter-grammar.h \
	dfilter-scanner.c \
	packet-snmp.c	\
	snprintf.c	\
	snprintf.h	\
	snprintf-imp.h	\
	strerror.c	\
	strerror.h

ethereal_DEPENDENCIES = @SNMP_O@ @SNPRINTF_O@ @STRERROR_O@ wiretap/libwiretap.a
ethereal_LDADD = @SNMP_O@ @SNPRINTF_O@ @STRERROR_O@ wiretap/libwiretap.a @SNMP_A@

ps.c: print.ps rdps
	./rdps print.ps ps.c

rdps: rdps.c
	$(CC) -o rdps rdps.c

DISTCLEANFILES =	\
	rdps		\
	ps.c		\
	*~

EXTRA_DIST = \
	config.h.win32		\
	doc/Makefile            \
	doc/configure           \
	doc/configure.in        \
	doc/dfilter2pod.in      \
	doc/ethereal.pod        \
	doc/ethereal.pod.template \
	ethereal.1              \
	ethereal.spec           \
	image/icon-excl.xpm     \
	image/icon-ethereal.xpm \
	Makefile.nmake		\
	manuf                   \
	print.ps                \
	README.tru64		\
	README.win32		\
	rdps.c			\
	VERSION

SUBDIRS = wiretap @SUBDIRS@

ethereal.1: ethereal doc/ethereal.pod.template VERSION
	(cd doc ; \
	make ../ethereal.1 )
