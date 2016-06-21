# Makefile.am
# Automake file for extcap tools
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include ../Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS)

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	.editorconfig

extcap_PROGRAMS = \
	@androiddump_bin@	\
	@randpktdump_bin@	\
	@sshdump_bin@		\
	@ciscodump_bin@

EXTRA_PROGRAMS = androiddump randpktdump sshdump ciscodump

androiddump_SOURCES = \
	androiddump.c	\
	extcap-base.c

if ENABLE_STATIC
androiddump_LDFLAGS = -Wl,-static -all-static
else
androiddump_LDFLAGS = -export-dynamic
endif

# Libraries and plugin flags with which to link androiddump.
androiddump_LDADD = \
	../wiretap/libwiretap.la	\
	../wsutil/libwsutil.la		\
	@GLIB_LIBS@

randpktdump_SOURCES = \
	randpktdump.c	\
	extcap-base.c

if ENABLE_STATIC
	randpktdump_LDFLAGS = -Wl,-static -all-static
else
	randpktdump_LDFLAGS = -export-dynamic
endif

# Libraries and plugin flags with which to link randpktdump.
randpktdump_LDADD = \
	../randpkt_core/librandpkt_core.a	\
	../wiretap/libwiretap.la	\
	../wsutil/libwsutil.la		\
	@GLIB_LIBS@

sshdump_SOURCES = \
	sshdump.c	\
	extcap-base.c	\
	ssh-base.c

if ENABLE_STATIC
	sshdump_LDFLAGS = -Wl,-static -all-static
else
	sshdump_LDFLAGS = -export-dynamic
endif

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

if ENABLE_STATIC
	ciscodump_LDFLAGS = -Wl,-static -all-static
else
	ciscodump_LDFLAGS = -export-dynamic
endif

# Libraries and plugin flags with which to link ciscodump.
ciscodump_LDADD = \
	../writecap/libwritecap.a	\
	../wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@LIBSSH_LIBS@

noinst_HEADERS = \
	extcap-base.h	\
	ssh-base.h
