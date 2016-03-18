# Makefile.am
# Automake file for the GTK interface routines for Wireshark
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
include $(top_srcdir)/Makefile.am.inc

if HAVE_GRESOURCE_PIXBUF
NODIST_GENERATED_FILES += \
	wireshark-gresources.h	\
	wireshark-gresources.c
else
BUILD_PIXBUF_CSOURCE = \
	pixbuf-csource.h
	pixbuf-csource.c
endif

if HAVE_EXTCAP
WIRESHARK_COMMON_GTK_SRC += extcap_gtk.c
WIRESHARK_COMMON_GTK_HDRS += extcap_gtk.h
endif

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GTK_CFLAGS) \
	$(PORTAUDIO_INCLUDES)

CLEANFILES = \
	libgtkui.a				\
	wireshark-tap-register.c-tmp		\
	wireshark-tap-register-cache.pkl	\
	*~

DISTCLEANFILES = \
	$(NODIST_GENERATED_FILES)

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

EXTRA_DIST = \
	.editorconfig			\
	$(GENERATOR_FILES)		\
	airpcap_dlg.c			\
	airpcap_dlg.h			\
	airpcap_gui_utils.c		\
	airpcap_gui_utils.h		\
	capture_if_details_dlg_win32.c	\
	capture_if_details_dlg_win32.h	\
	CMakeLists.txt			\
	doxygen.cfg.in			\
	main_airpcap_toolbar.c		\
	main_airpcap_toolbar.h		\
	Makefile.common			\
	Makefile.nmake			\
	Makefile_custom.common		\
	pixbuf-csource.c		\
	pixbuf-csource.h

BUILT_SOURCES = \
	$(GENERATED_FILES)	\
	$(NODIST_GENERATED_FILES)

noinst_LIBRARIES = libgtkui.a

libgtkui_a_SOURCES = \
	$(WIRESHARK_COMMON_GTK_SRC)	\
	$(WIRESHARK_COMMON_GTK_HDRS)	\
	$(WIRESHARK_TAP_SRC)		\
	$(GENERATED_FILES)

nodist_libgtkui_a_SOURCES = \
	$(NODIST_GENERATED_FILES)	\
	$(BUILD_PIXBUF_CSOURCE)

libgtkui_a_DEPENDENCIES =

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
wireshark-tap-register.c:  $(WIRESHARK_TAP_SRC) Makefile.common Makefile_custom.common $(top_srcdir)/tools/make-tap-reg.py
	@echo Making wireshark-tap-register.c
	@$(PYTHON) $(top_srcdir)/tools/make-tap-reg.py $(srcdir) taps $(WIRESHARK_TAP_SRC)

wireshark-gresources.c: main.gresources.xml $(shell glib-compile-resources --sourcedir=$(top_srcdir) --generate-dependencies $(srcdir)/main.gresources.xml)
	@echo Making $@
	@glib-compile-resources --sourcedir=$(top_srcdir) --target=$@ --generate --manual-register $<

wireshark-gresources.h: main.gresources.xml
	@echo Making $@
	@glib-compile-resources --sourcedir=$(top_srcdir) --target=$@ --generate --manual-register $<

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g deprecated-gtk -build \
	-sourcedir=$(srcdir)		\
	$(WIRESHARK_CLEAN_LIBGTKUI_SRC)	\
	capture_if_details_dlg_win32.c

checkapi-todo:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -M -g deprecated-gtk-todo -build \
	-sourcedir=$(srcdir)	\
	$(WIRESHARK_GTK_SRC)	\
	$(WIRESHARK_TAP_SRC)	\
	capture_if_details_dlg_win32.c
