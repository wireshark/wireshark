# Makefile.am
# Automake file for the Qt interface routines for Wireshark
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

noinst_LIBRARIES = libqtui.a

CLEANFILES = \
	libqtui.a		\
	*~

DISTCLEANFILES = \
	$(GENERATED_NODIST_FILES)

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)		\
	$(GENERATED_NODIST_FILES)	\
	Makefile.in

RUNLEX=$(top_srcdir)/tools/runlex.sh

libqtui_a_SOURCES = \
	$(WIRESHARK_QT_SRC) \
	$(WIRESHARK_TAP_SRC) \
	$(GENERATED_C_FILES) \
	$(GENERATED_CPP_FILES) \
	$(noinst_HEADERS) \
	$(GENERATED_HEADER_FILES)

nodist_libqtui_a_SOURCES = \
	$(GENERATED_NODIST_C_FILES) \
	$(GENERATED_NODIST_CPP_FILES) \
	$(GENERATED_NODIST_HEADER_FILES)

libqtui_a_CFLAGS = $(AM_CLEAN_CFLAGS)

libqtui_a_DEPENDENCIES =

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap $(LIBGCRYPT_CFLAGS) $(LIBGNUTLS_CFLAGS) $(PORTAUDIO_INCLUDES)

#
# For building .moc.cpp files from .h files by running moc
# and building .rcc.cpp files from .qrc files by running rcc
#
SUFFIXES = .moc.cpp .qrc .rcc.cpp

.h.moc.cpp:
	moc -I.. -I../.. -o $@ $<

.qrc.rcc.cpp:
	rcc -name `basename $< .qrc` -o $@ $<

ui_%.h: %.ui
	uic $< -o $@

# The Qt toolchain uses the naming convention moc_FOO.cpp. Should we do the same?
#moc_%.cpp: %.h
#	moc $< -o $@

export_object_dialog.cpp export_object_dialog.h: ui_export_object_dialog.h

file_set_dialog.cpp file_set_dialog.h: ui_file_set_dialog.h

import_text_dialog.cpp import_text_dialog.h: ui_import_text_dialog.h

layout_preferences_frame.cpp layout_preferences_frame.h: ui_layout_preferences_frame.h

main_welcome.cpp main_welcome.h: ui_main_welcome.h

main_window.cpp main_window.h: ui_main_window.h

main_window_preferences_frame.cpp main_window_preferences_frame.h: ui_main_window_preferences_frame.h

packet_comment_dialog.cpp packet_comment_dialog.h: ui_packet_comment_dialog.h

packet_format_group_box.cpp packet_format_group_box.h: ui_packet_format_group_box.h

packet_range_group_box.cpp packet_range_group_box.h: ui_packet_range_group_box.h

preferences_dialog.cpp preferences_dialog.h: ui_preferences_dialog.h

print_dialog.cpp print_dialog.h: ui_print_dialog.h

profile_dialog.cpp profile_dialog.h: ui_profile_dialog.h

search_frame.cpp search_frame.h: ui_search_frame.h

splash_overlay.cpp splash_overlay.h: ui_splash_overlay.h

time_shift_dialog.cpp time_shift_dialog.h: ui_time_shift_dialog.h

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) ../tools/checkAPIs.pl -g deprecated-gtk -build \
	$(WIRESHARK_GTK_SRC) \
	$(WIRESHARK_TAP_SRC) \
	capture_if_details_dlg_win32.c

checkapi-todo:
	$(PERL) ../tools/checkAPIs.pl -M -g deprecated-gtk-todo -build \
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

# XXX to be created
#	libqtui.vcproj
#	Makefile.nmake
EXTRA_DIST = \
	$(GENERATOR_FILES)		\
	$(QRC_FILES)			\
	$(TS_FILES)			\
	$(QM_FILES)			\
	CMakeLists.txt			\
	doxygen.cfg.in			\
	export_object_dialog.ui		\
	file_set_dialog.ui		\
	import_text_dialog.ui		\
	layout_preferences_frame.ui	\
	main.cpp			\
	Makefile.common			\
	Makefile_custom.common		\
	main_welcome.ui			\
	main_window.ui			\
	main_window_preferences_frame.ui	\
	packet_format_group_box.ui	\
	packet_range_group_box.ui	\
	packet_comment_dialog.ui	\
	preferences_dialog.ui		\
	print_dialog.ui			\
	profile_dialog.ui		\
	QtShark.pro			\
	search_frame.ui			\
	splash_overlay.ui		\
	time_shift_dialog.ui		\
	display_filter_16.svg		\
	gpl-template.txt
