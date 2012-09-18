# Makefile.am
# Automake file for the TShark taps
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include Makefile.common
include ../../Makefile.am.inc

if HAVE_WARNINGS_AS_ERRORS
AM_CLEAN_CFLAGS = -Werror
endif

noinst_LIBRARIES = libcliui.a

CLEANFILES = \
	libcliui.a			\
	tshark-tap-register.c-tmp	\
	tshark-tap-register-cache.pkl	\
	*~

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

#
# Build "tshark-tap-register.c", which contains a function
# "register_all_tap_listeners()"
# that calls the register routines for all tshark tap listeners.
#
# We do this by grepping through sources.
#
# Formatting conventions:  The name of the tap_listener_register_*
# routines must start in column zero, or must be preceded only by
# "void " starting in column zero, and must not be inside #if.
#
# The first argument is the directory in which the source files live.
# All subsequent arguments are the files to scan.
#
tshark-tap-register.c: $(TSHARK_TAP_SRC) $(top_srcdir)/tools/make-tapreg-dotc $(top_srcdir)/tools/make-tap-reg.py
	@if test -n "$(PYTHON)"; then \
		echo Making tshark-tap-register.c with python; \
		$(PYTHON) $(top_srcdir)/tools/make-tap-reg.py $(srcdir) tshark-taps $(TSHARK_TAP_SRC); \
	else \
		echo Making tshark-tap-register.c; \
		$(top_srcdir)/tools/make-tapreg-dotc tshark-tap-register.c $(srcdir) $(TSHARK_TAP_SRC); \
	fi

# All sources that should be put in the source distribution tarball
libcliui_a_SOURCES = \
	$(TSHARK_TAP_SRC) \
	$(noinst_HEADERS) \
	$(GENERATED_HEADER_FILES) \
	$(GENERATED_C_FILES)

libcliui_a_CFLAGS = $(AM_CLEAN_CFLAGS)

libcliui_a_DEPENDENCIES =

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap $(LIBGCRYPT_CFLAGS) $(LIBGNUTLS_CFLAGS) $(PORTAUDIO_INCLUDES)


doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) ../../tools/checkAPIs.pl -g deprecated-gtk -build \
	$(TSHARK_TAP_SRC)

checkapi-todo:
	$(PERL) ../../tools/checkAPIs.pl -M -g deprecated-gtk-todo -build \
	$(TSHARK_TAP_SRC)

EXTRA_DIST = \
	$(GENERATOR_FILES)	\
	Makefile.common			\
	Makefile.nmake
