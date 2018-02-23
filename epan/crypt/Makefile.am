# Makefile.am
# Automake file for 802.11 decryption for Wireshark
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

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS) $(LIBGCRYPT_CFLAGS)

noinst_LTLIBRARIES = libdot11decrypt.la

include Custom.common

CRYPT_SOURCES =			\
	dot11decrypt.c		\
	dot11decrypt_ccmp.c		\
	dot11decrypt_rijndael.c	\
	dot11decrypt_tkip.c

CRYPT_INCLUDES = 		\
	dot11decrypt_debug.h	\
	dot11decrypt_interop.h	\
	dot11decrypt_int.h		\
	dot11decrypt_rijndael.h	\
	dot11decrypt_system.h	\
	dot11decrypt_user.h		\
	dot11decrypt_ws.h		\
	kasumi.h		\
	wep-wpadefs.h

libdot11decrypt_la_SOURCES =	\
	$(CRYPT_SOURCES)	\
	$(CRYPT_INCLUDES)	\
	$(CUSTOM_CRYPTO_SRC)

EXTRA_DIST = \
	Custom.common \
	CMakeLists.txt	\
	CMakeListsCustom.txt.example

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(CRYPT_SOURCES)
