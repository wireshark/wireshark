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
include ../../Makefile.am.inc

if HAVE_WARNINGS_AS_ERRORS
AM_CLEAN_CFLAGS = -Werror
endif

noinst_LIBRARIES = libgtkui.a libgtkui_dirty.a

CLEANFILES = \
	libgtkui.a		\
	libgtkui_dirty.a	\
	*~

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

RUNLEX=$(top_srcdir)/tools/runlex.sh

text_import_scanner_lex.h: text_import_scanner.c

#
# Build "wireshark-tap-register.c", which contains a function
# "register_all_tap_listeners()"
# that calls the register routines for all wireshark tap listeners.
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
wireshark-tap-register.c: $(WIRESHARK_TAP_SRC) $(top_srcdir)/tools/make-tapreg-dotc
	@echo Making wireshark-tap-register.c
	@$(top_srcdir)/tools/make-tapreg-dotc wireshark-tap-register.c $(srcdir) $(WIRESHARK_TAP_SRC)

WIRESHARK_CLEAN_LIBGTKUI_SRC = \
 	$(WIRESHARK_GTK_SRC) \
	$(WIRESHARK_TAP_SRC) \
 	$(GENERATED_C_FILES)

libgtkui_a_SOURCES = \
	$(WIRESHARK_CLEAN_LIBGTKUI_SRC) \
	$(noinst_HEADERS) \
	$(GENERATED_HEADER_FILES)

libgtkui_a_CFLAGS = $(AM_CLEAN_CFLAGS)

libgtkui_a_DEPENDENCIES =

libgtkui_dirty_a_SOURCES = \
	$(DIRTY_GENERATED_C_FILES)

libgtkui_dirty_a_DEPENDENCIES =

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap $(LIBGCRYPT_CFLAGS) $(LIBGNUTLS_CFLAGS) $(PORTAUDIO_INCLUDES)


doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) ../../tools/checkAPIs.pl -g deprecated-gtk \
	$(WIRESHARK_CLEAN_LIBGTKUI_SRC) \
	capture_if_details_dlg_win32.c

checkapi-todo:
	$(PERL) ../../tools/checkAPIs.pl -M -g deprecated-gtk-todo \
	$(WIRESHARK_GTK_SRC) \
	$(WIRESHARK_TAP_SRC) \
	capture_if_details_dlg_win32.c

expert_indicators.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for elevel in chat error none note warn ; do \
		gdk-pixbuf-csource --raw --name=expert_$${elevel}_pb_data ../../image/expert_$${elevel}.png >> $@ ;\
	done

network_icons.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for icon in bluetooth usb wired wireless ; do \
		gdk-pixbuf-csource --raw --name=network_$${icon}_pb_data ../../image/toolbar/network_$${icon}_16.png >> $@ ;\
	done

remote_icons.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for icon in arrow globe sat ; do \
		gdk-pixbuf-csource --raw --name=remote_$${icon}_pb_data ../../image/toolbar/remote_$${icon}_16.png >> $@ ;\
	done

pipe_icon.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	gdk-pixbuf-csource --raw --name=pipe_pb_data ../../image/toolbar/pipe_16.png >> $@

EXTRA_DIST = \
	$(GENERATOR_FILES)		\
	airpcap_dlg.c			\
	airpcap_gui_utils.c		\
	capture_if_details_dlg_win32.c	\
	capture_if_details_dlg_win32.h	\
	doxygen.cfg.in			\
	libgtkui.vcproj			\
	main_airpcap_toolbar.c		\
	Makefile.common			\
	Makefile.nmake			\
	CMakeLists.txt			\
	Makefile_custom.common
