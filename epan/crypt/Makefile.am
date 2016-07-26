# Makefile.am
# Automake file for the airpdcap for Wireshark
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

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS)

noinst_LTLIBRARIES = libairpdcap.la

include Custom.common

libairpdcap_la_SOURCES =	\
	airpdcap.c		\
	airpdcap_ccmp.c		\
	airpdcap_rijndael.c	\
	airpdcap_tkip.c		\
	airpdcap_debug.h	\
	airpdcap_interop.h	\
	airpdcap_int.h		\
	airpdcap_rijndael.h	\
	airpdcap_system.h	\
	airpdcap_user.h		\
	airpdcap_ws.h		\
	kasumi.h		\
	wep-wpadefs.h		\
	$(CUSTOM_CRYPTO_SRC)

EXTRA_DIST = \
	Custom.common \
	CMakeLists.txt	\
	CMakeListsCustom.txt.example

CLEANFILES = \
	libairpdcap.a	\
	libairpdcap.la	\
	*~

DISTCLEANFILES =

MAINTAINERCLEANFILES =	\
	Makefile.in

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(libairpdcap_la_SOURCES)
