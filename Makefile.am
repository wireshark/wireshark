bin_PROGRAMS = ethereal

man_MANS = ethereal.1

ethereal_SOURCES = \
	capture.c      \
	ethereal.c     \
	ethertype.c    \
	file.c         \
	filter.c       \
	menu.c         \
	packet.c       \
	packet-arp.c   \
	packet-bootp.c \
	packet-data.c  \
	packet-dns.c   \
	packet-eth.c   \
	packet-llc.c   \
	packet-lpd.c   \
	packet-ip.c    \
	packet-ipv6.c  \
	packet-ipx.c   \
	packet-osi.c   \
	packet-ospf.c  \
	packet-ppp.c   \
	packet-raw.c   \
	packet-rip.c   \
	packet-tcp.c   \
	packet-tr.c    \
	packet-trmac.c \
	packet-udp.c   \
	packet-vines.c \
	print.c        \
	ps.c           \
	resolv.c       \
	util.c         \
	capture.h      \
	config.h       \
	ethereal.h     \
	etypes.h       \
	file.h         \
	filter.h       \
	menu.h         \
	packet.h       \
	packet-ipv6.h  \
	packet-ospf.h  \
	packet-rip.h   \
	packet-vines.h \
	print.h        \
	ps.h           \
	resolv.h       \
	snprintf.h     \
	util.h

ps.c: print.ps rdps
	./rdps print.ps ps.c

rdps: rdps.c
	$(CC) -o rdps rdps.c

EXTRA_ethereal_SOURCES = @SNPRINTF_C@
ethereal_DEPENDENCIES = @SNPRINTF_O@
LDADD = @SNPRINTF_O@

EXTRA_DIST =            \
	ethereal.1          \
	snprintf.c          \
	rdps.c              \
	print.ps            \
	image/icon-excl.xpm \
	doc/Makefile        \
	doc/ethereal.pod
