# Makefile.am
# Automake file for extcap tools
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0+

include ../Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS) $(PCAP_CFLAGS)

EXTRA_DIST = \
	.editorconfig

extcap_PROGRAMS = \
	@androiddump_bin@	\
	@randpktdump_bin@	\
	@sshdump_bin@		\
	@ciscodump_bin@		\
	@udpdump_bin@

EXTRA_PROGRAMS = androiddump randpktdump sshdump ciscodump udpdump

androiddump_SOURCES = \
	androiddump.c	\
	extcap-base.c

# Libraries and plugin flags with which to link androiddump.
androiddump_LDADD = \
	../ui/libui.a			\
	../wiretap/libwiretap.la	\
	../wsutil/libwsutil.la		\
	@GLIB_LIBS@

randpktdump_SOURCES = \
	randpktdump.c	\
	extcap-base.c

# Libraries and plugin flags with which to link randpktdump.
randpktdump_LDADD = \
	../randpkt_core/librandpkt_core.a	\
	../ui/libui.a			\
	../wiretap/libwiretap.la	\
	../wsutil/libwsutil.la		\
	@GLIB_LIBS@

sshdump_SOURCES = \
	sshdump.c	\
	extcap-base.c	\
	ssh-base.c

# Libraries and plugin flags with which to link sshdump.
sshdump_LDADD = \
	../wiretap/libwiretap.la	\
	../wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@LIBSSH_LIBS@

ciscodump_SOURCES = \
	ciscodump.c	\
	extcap-base.c	\
	ssh-base.c

# Libraries and plugin flags with which to link ciscodump.
ciscodump_LDADD = \
	../writecap/libwritecap.a	\
	../wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@LIBSSH_LIBS@

udpdump_SOURCES = \
	udpdump.c \
	extcap-base.c

# Libraries and plugin flags with which to link udpdump.
udpdump_LDADD = \
	../writecap/libwritecap.a	\
	../wsutil/libwsutil.la		\
	@GLIB_LIBS@

noinst_HEADERS = \
	extcap-base.h	\
	ssh-base.h
