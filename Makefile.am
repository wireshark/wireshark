bin_PROGRAMS = ethereal

man_MANS = ethereal.1

sysconf_DATA = manuf

ethereal_SOURCES = \
	alignment.h    \
	capture.c      \
	capture.h      \
	column.c       \
	column.h       \
	config.h       \
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
	packet.c       \
	packet.h       \
	prefs.c        \
	prefs.h        \
	print.c        \
	print.h        \
	ps.c           \
	ps.h           \
	resolv.c       \
	resolv.h       \
	smb.h          \
        summary.h      \
        summary.c      \
	timestamp.h    \
	util.c         \
	util.h

EXTRA_ethereal_SOURCES = \
	packet-snmp.c	\
	snprintf.c	\
	snprintf.h	\
	snprintf-imp.h	\
	strerror.c	\
	strerror.h

ethereal_DEPENDENCIES = @SNMP_O@ @SNPRINTF_O@ @STRERROR_O@ @LIBWIRETAP_A@
ethereal_LDADD = @SNMP_O@ @SNPRINTF_O@ @STRERROR_O@ @LIBWIRETAP_A@ @SNMP_A@

ps.c: print.ps rdps
	./rdps print.ps ps.c

rdps: rdps.c
	$(CC) -o rdps rdps.c

DISTCLEANFILES =	\
	rdps		\
	ps.c		\
	*~

EXTRA_DIST =                \
	doc/Makefile            \
	doc/ethereal.pod        \
	ethereal.1              \
	ethereal.spec           \
	image/icon-excl.xpm     \
	image/icon-ethereal.xpm \
	manuf                   \
	print.ps                \
	README.tru64		\
	rdps.c			\
	ylwrap			\
	VERSION

SUBDIRS = @SUBDIRS@

ethereal.1: doc/ethereal.pod VERSION
	(cd doc ; \
	pod2man ethereal.pod                \
	--center="The Ethereal Network Analyzer" \
	--release=`cat ../VERSION`                  \
	> ../ethereal.1 )
