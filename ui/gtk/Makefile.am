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
include ../../Makefile.am.inc

if HAVE_WARNINGS_AS_ERRORS
AM_CLEAN_CFLAGS = -Werror
endif

noinst_LIBRARIES = libgtkui.a

CLEANFILES = \
	libgtkui.a				\
	wireshark-tap-register.c-tmp		\
	wireshark-tap-register-cache.pkl	\
	*~

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

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
wireshark-tap-register.c: $(WIRESHARK_TAP_SRC) $(top_srcdir)/tools/make-tapreg-dotc $(top_srcdir)/tools/make-tap-reg.py
	@if test -n "$(PYTHON)"; then \
		echo Making wireshark-tap-register.c with python ; \
		$(PYTHON) $(top_srcdir)/tools/make-tap-reg.py $(srcdir) taps $(WIRESHARK_TAP_SRC); \
	else \
		echo Making wireshark-tap-register.c; \
		$(top_srcdir)/tools/make-tapreg-dotc wireshark-tap-register.c $(srcdir) $(WIRESHARK_TAP_SRC); \
	fi

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

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap $(PORTAUDIO_INCLUDES)


doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g deprecated-gtk -build \
	-sourcedir=$(srcdir) \
	$(WIRESHARK_CLEAN_LIBGTKUI_SRC) \
	capture_if_details_dlg_win32.c

checkapi-todo:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -M -g deprecated-gtk-todo -build \
	-sourcedir=$(srcdir) \
	$(WIRESHARK_GTK_SRC) \
	$(WIRESHARK_TAP_SRC) \
	capture_if_details_dlg_win32.c

expert_indicators.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for elevel in chat error none note warn ok ; do \
		gdk-pixbuf-csource --raw --name=expert_$${elevel}_pb_data $(top_srcdir)/image/expert_$${elevel}.png >> $@ ;\
	done

capture_comment_icons.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for caction in add update disabled ; do \
		gdk-pixbuf-csource --raw --name=capture_comment_$${caction}_pb_data $(top_srcdir)/image/capture_comment_$${caction}.png >> $@ ;\
	done

network_icons.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for icon in bluetooth usb wired wireless ; do \
		gdk-pixbuf-csource --raw --name=network_$${icon}_pb_data $(top_srcdir)/image/toolbar/network_$${icon}_16.png >> $@ ;\
	done

remote_icons.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for icon in arrow globe sat ; do \
		gdk-pixbuf-csource --raw --name=remote_$${icon}_pb_data $(top_srcdir)/image/toolbar/remote_$${icon}_16.png >> $@ ;\
	done

pipe_icon.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	gdk-pixbuf-csource --raw --name=pipe_pb_data $(top_srcdir)/image/toolbar/pipe_16.png >> $@

TOOLBAR_COMMON_ICONS = \
	capture_interfaces \
	capture_options_alt1 \
	capture_restart \
	capture_start \
	capture_stop \
	gnome_emblem_web \
	toolbar_wireshark_file

toolbar_icons.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for icon16 in $(TOOLBAR_COMMON_ICONS) ; do \
		gdk-pixbuf-csource --raw --name=$${icon16}_16_pb_data $(top_srcdir)/image/toolbar/$${icon16}_16.png >> $@ ;\
	done
	for icon24 in $(TOOLBAR_COMMON_ICONS) ; do \
		gdk-pixbuf-csource --raw --name=$${icon24}_24_pb_data $(top_srcdir)/image/toolbar/$${icon24}_24.png >> $@ ;\
	done

layouts.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for layout_num in 1 2 3 4 5 6 ; do \
		gdk-pixbuf-csource --raw --name=layout_$${layout_num}_pb_data $(top_srcdir)/image/layout_$${layout_num}.png >> $@ ;\
	done

wsicon.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for layout_num in 16 24 32 48 64 ; do \
		gdk-pixbuf-csource --raw --name=wsicon_$${layout_num}_pb_data $(top_srcdir)/image/wsicon$${layout_num}.png >> $@ ;\
	done

wsiconcap.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	for layout_num in 16 24 32 48 64 ; do \
		gdk-pixbuf-csource --raw --name=wsiconcap_$${layout_num}_pb_data $(top_srcdir)/image/wsiconcap$${layout_num}.png >> $@ ;\
	done

wssplash.h:
	echo "/* This file was automatically generated. DO NOT EDIT. */" > $@
	echo >> $@
	gdk-pixbuf-csource --raw --name=wssplash_pb_data $(top_srcdir)/image/wssplash_dev.png >> $@

clean-pixbufs:
	rm expert_indicators.h capture_comment_icons.h network_icons.h remote_icons.h pipe_icon.h \
		toolbar_icons.h layouts.h wsicon.h wsiconcap.h wssplash.h

EXTRA_DIST = \
	$(GENERATOR_FILES)		\
	airpcap_dlg.c			\
	airpcap_gui_utils.c		\
	capture_if_details_dlg_win32.c	\
	capture_if_details_dlg_win32.h	\
	CMakeLists.txt			\
	doxygen.cfg.in			\
	main_airpcap_toolbar.c		\
	Makefile.common			\
	Makefile.nmake			\
	Makefile_custom.common
