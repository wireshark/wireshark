# Makefile.am
# Automake file for the common-to-all-toolkits user interface routines
# for Wireshark
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
	doxygen-ui.tag	\
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

wsar_html: doxygen.cfg ../doxygen_global.cfg
if HAVE_DOXYGEN
	(umask 022 ; $(DOXYGEN) doxygen.cfg)
endif

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g deprecated-gtk -build \
	-sourcedir=$(srcdir) \
	$(WIRESHARK_UI_SRC)

checkapi-todo:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -M -g deprecated-gtk-todo -build \
	-sourcedir=$(srcdir) \
	$(WIRESHARK_UI_SRC)

EXTRA_DIST = \
	$(GENERATOR_FILES)		\
	CMakeLists.txt			\
	doxygen.cfg.in			\
	Makefile.common			\
	Makefile.nmake
