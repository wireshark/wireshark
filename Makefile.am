bin_PROGRAMS = ethereal

man_MANS = ethereal.1

sysconf_DATA = manuf

ethereal_SOURCES = \
	capture.c      \
	column.c       \
	ethereal.c     \
	ethertype.c    \
	file.c         \
	filter.c       \
	follow.c       \
	gtkpacket.c    \
	menu.c         \
	packet.c       \
	packet-aarp.c  \
	packet-arp.c   \
	packet-atalk.c \
	packet-bootp.c \
	packet-cdp.c   \
	packet-data.c  \
	packet-dns.c   \
	packet-eth.c   \
	packet-ftp.c   \
	packet-fddi.c  \
	packet-giop.c  \
	packet-http.c  \
	packet-ip.c    \
	packet-icmpv6.c \
	packet-ipsec.c \
	packet-ipv6.c  \
	packet-ipx.c   \
	packet-llc.c   \
	packet-lpd.c   \
	packet-nbipx.c \
	packet-nbns.c  \
	packet-ncp.c   \
	packet-nntp.c  \
	packet-null.c  \
	packet-osi.c   \
	packet-ospf.c  \
	packet-pop.c   \
	packet-ppp.c   \
	packet-raw.c   \
	packet-rip.c   \
	packet-tcp.c   \
	packet-telnet.c \
	packet-tftp.c  \
	packet-tr.c    \
	packet-trmac.c \
	packet-udp.c   \
	packet-vines.c \
	prefs.c        \
	print.c        \
	ps.c           \
	resolv.c       \
	util.c         \
	capture.h      \
	column.h       \
	config.h       \
	ethereal.h     \
	etypes.h       \
	file.h         \
	filter.h       \
	follow.h       \
	gtkpacket.h    \
	menu.h         \
	packet.h       \
	packet-dns.h   \
	packet-ip.h    \
	packet-ipv6.h  \
	packet-ipx.h   \
	packet-ncp.h   \
	packet-ospf.h  \
	packet-rip.h   \
	packet-vines.h \
	prefs.h        \
	print.h        \
	ps.h           \
	resolv.h       \
	util.h

EXTRA_ethereal_SOURCES = \
	snprintf.c           \
	snprintf.h           \
	snprintf-imp.h

ethereal_DEPENDENCIES = @SNPRINTF_O@ @LIBWIRETAP_A@
ethereal_LDADD = @SNPRINTF_O@ @LIBWIRETAP_A@

ps.c: print.ps rdps
	./rdps print.ps ps.c

rdps: rdps.c
	$(CC) -o rdps rdps.c

DISTCLEANFILES =			\
	rdps 					\
	ps.c 					\
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
	ylwrap

SUBDIRS = @SUBDIRS@
