# Makefile.am
# Automake file for the GTK interface routines for Wireshark
#
# $Id$
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

include Makefile.common

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

noinst_LIBRARIES = libui.a

CLEANFILES = \
	libui.a		\
	*~

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

wireshark-tap-register.c: $(WIRESHARK_TAP_SRC) $(top_srcdir)/tools/make-tapreg-dotc
	@echo Making wireshark-tap-register.c
	@$(top_srcdir)/tools/make-tapreg-dotc wireshark-tap-register.c $(srcdir) $(WIRESHARK_TAP_SRC)

libui_a_SOURCES = \
	$(WIRESHARK_GTK_SRC) \
	$(GENERATED_C_FILES) \
	$(noinst_HEADERS) \
	$(WIRESHARK_TAP_SRC)

libui_a_DEPENDENCIES = 

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap $(LIBGCRYPT_CFLAGS) $(LIBGNUTLS_CFLAGS) $(PORTAUDIO_INCLUDES)


doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

checkapi:
	$(PERL) ../tools/checkAPIs.pl \
	$(WIRESHARK_GTK_SRC) \
	$(WIRESHARK_TAP_SRC) \
	capture_if_details_dlg_win32.c	\
	file_dlg_win32.c \
	print_win32.c
