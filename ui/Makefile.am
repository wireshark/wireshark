# Makefile.am
# Automake file for the common-to-all-toolkits user interface routines
# for Wireshark
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
include ../Makefile.am.inc

if HAVE_WARNINGS_AS_ERRORS
AM_CLEAN_CFLAGS = -Werror
endif

noinst_LIBRARIES = libui.a libui_dirty.a

CLEANFILES = \
	libui.a		\
	libui_dirty.a	\
	*~

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

RUNLEX=$(top_srcdir)/tools/runlex.sh

text_import_scanner_lex.h: text_import_scanner.c

# All sources that should be put in the source distribution tarball
libui_a_SOURCES = \
	$(WIRESHARK_UI_SRC) \
	$(noinst_HEADERS) \
	$(GENERATED_HEADER_FILES) \
	$(GENERATED_C_FILES)

libui_a_CFLAGS = $(AM_CLEAN_CFLAGS)

libui_a_DEPENDENCIES =

libui_dirty_a_SOURCES = \
	$(DIRTY_GENERATED_C_FILES)

libui_dirty_a_DEPENDENCIES =

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap $(LIBGCRYPT_CFLAGS) $(LIBGNUTLS_CFLAGS) $(PORTAUDIO_INCLUDES)


doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) ../tools/checkAPIs.pl -g deprecated-gtk -build \
	$(WIRESHARK_UI_SRC)

checkapi-todo:
	$(PERL) ../tools/checkAPIs.pl -M -g deprecated-gtk-todo -build \
	$(WIRESHARK_UI_SRC)

EXTRA_DIST = \
	$(GENERATOR_FILES)		\
	CMakeLists.txt			\
	doxygen.cfg.in			\
	Makefile.common			\
	Makefile.nmake
