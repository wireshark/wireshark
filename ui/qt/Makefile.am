# Makefile.am
# Automake file for the Qt interface routines for Wireshark
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
	libqtui.a \
	wireshark-tap-register.c-tmp \
	wireshark-tap-register-cache.pkl \
	*.moc.cpp \
	*.rrc.cpp \
	ui_*.h
	*~

DISTCLEANFILES = \
	$(NODIST_GENERATED_FILES)

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)		\
	$(NODIST_GENERATED_FILES)	\
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
wireshark-tap-register.c: $(WIRESHARK_QT_TAP_SRC) $(top_srcdir)/tools/make-tapreg-dotc $(top_srcdir)/tools/make-tap-reg.py
	@if test -n "$(PYTHON)"; then \
		echo Making wireshark-tap-register.c with python ; \
		$(PYTHON) $(top_srcdir)/tools/make-tap-reg.py $(srcdir) taps $(WIRESHARK_QT_TAP_SRC); \
	else \
		echo Making wireshark-tap-register.c; \
		$(top_srcdir)/tools/make-tapreg-dotc wireshark-tap-register.c $(srcdir) $(WIRESHARK_QT_TAP_SRC); \
	fi

RUNLEX=$(top_srcdir)/tools/runlex.sh

libqtui_a_SOURCES = \
	$(WIRESHARK_QT_SRC) \
	$(WIRESHARK_TAP_SRC) \
	$(GENERATED_C_FILES) \
	$(GENERATED_CPP_FILES) \
	$(noinst_HEADERS) \
	$(GENERATED_HEADER_FILES)

nodist_libqtui_a_SOURCES = \
	$(NODIST_GENERATED_C_FILES) \
	$(NODIST_GENERATED_CPP_FILES) \
	$(NODIST_GENERATED_HEADER_FILES)

libqtui_a_CFLAGS = $(AM_CLEAN_CFLAGS)

libqtui_a_DEPENDENCIES =

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap $(LIBGCRYPT_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) $(PIE_CFLAGS)

AM_CXXFLAGS = $(AM_CLEAN_CFLAGS)

AM_V_MOC = $(am__v_MOC_@AM_V@)
am__v_MOC_ = $(am__v_MOC_@AM_DEFAULT_V@)
am__v_MOC_0 = @echo "  MOC     " $@;

AM_V_RCC = $(am__v_RCC_@AM_V@)
am__v_RCC_ = $(am__v_RCC_@AM_DEFAULT_V@)
am__v_RCC_0 = @echo "  RCC     " $@;

AM_V_UIC = $(am__v_UIC_@AM_V@)
am__v_UIC_ = $(am__v_UIC_@AM_DEFAULT_V@)
am__v_UIC_0 = @echo "  UIC     " $@;

#
# For building .moc.cpp files from .h files by running moc
# and building .rcc.cpp files from .qrc files by running rcc
#
SUFFIXES = .moc.cpp .qrc .rcc.cpp

.h.moc.cpp:
	$(AM_V_MOC)$(MOC) -I.. -I../.. -o $@ $<

.qrc.rcc.cpp:
	$(MKDIR_P) $(@D)
	$(AM_V_RCC)rcc -name `basename $< .qrc` -o $@ $<

ui_%.h: %.ui
	$(AM_V_UIC)$(UIC) $< -o $@

# The Qt toolchain uses the naming convention moc_FOO.cpp. Should we do the same?
#moc_%.cpp: %.h
#	$(MOC) $< -o $@

about_dialog.cpp about_dialog.h: ui_about_dialog.h

capture_interfaces_dialog.cpp capture_interfaces_dialog.h: ui_capture_interfaces_dialog.h

capture_preferences_frame.cpp capture_preferences_frame.h: ui_capture_preferences_frame.h

column_preferences_frame.cpp column_preferences_frame.h: ui_column_preferences_frame.h

compiled_filter_output.cpp compiled_filter_output.h: ui_compiled_filter_output.h

decode_as_dialog.cpp decode_as_dialog.h: ui_decode_as_dialog.h

export_object_dialog.cpp export_object_dialog.h: ui_export_object_dialog.h

export_pdu_dialog.cpp export_pdu_dialog.h: ui_export_pdu_dialog.h

file_set_dialog.cpp file_set_dialog.h: ui_file_set_dialog.h

filter_expressions_preferences_frame.cpp filter_expressions_preferences_frame.h: ui_filter_expressions_preferences_frame.h

follow_stream_dialog.cpp: ui_follow_stream_dialog.h

font_color_preferences_frame.cpp font_color_preferences_frame.h: ui_font_color_preferences_frame.h

import_text_dialog.cpp import_text_dialog.h: ui_import_text_dialog.h

io_graph_dialog.cpp io_graph_dialog.h: ui_io_graph_dialog.h

layout_preferences_frame.cpp layout_preferences_frame.h: ui_layout_preferences_frame.h

lbm_lbtrm_transport_dialog.cpp lbm_lbtrm_transport_dialog.h: ui_lbm_lbtrm_transport_dialog.h

lbm_lbtru_transport_dialog.cpp lbm_lbtru_transport_dialog.h: ui_lbm_lbtru_transport_dialog.h

lbm_stream_dialog.cpp lbm_stream_dialog.h: ui_lbm_stream_dialog.h

lbm_uimflow_dialog.cpp lbm_uimflow_dialog.h: ui_lbm_uimflow_dialog.h

main_welcome.cpp main_welcome.h: ui_main_welcome.h

main_window.cpp main_window_slots.cpp main_window.h: ui_main_window.h

main_window_preferences_frame.cpp main_window_preferences_frame.h: ui_main_window_preferences_frame.h

module_preferences_scroll_area.cpp module_preferences_scroll_area.h: ui_module_preferences_scroll_area.h

packet_comment_dialog.cpp packet_comment_dialog.h: ui_packet_comment_dialog.h

packet_format_group_box.cpp packet_format_group_box.h: ui_packet_format_group_box.h

packet_range_group_box.cpp packet_range_group_box.h: ui_packet_range_group_box.h

preferences_dialog.cpp preferences_dialog.h: ui_preferences_dialog.h

print_dialog.cpp print_dialog.h: ui_print_dialog.h

profile_dialog.cpp profile_dialog.h: ui_profile_dialog.h

search_frame.cpp search_frame.h: ui_search_frame.h

sequence_dialog.cpp sequence_dialog.h: ui_sequence_dialog.h

sctp_all_assocs_dialog.cpp sctp_all_assocs_dialog.h: ui_sctp_all_assocs_dialog.h

sctp_assoc_analyse_dialog.cpp sctp_assoc_analyse_dialog.h: ui_sctp_assoc_analyse_dialog.h

sctp_chunk_statistics_dialog.cpp sctp_chunk_statistics_dialog.h: ui_sctp_chunk_statistics_dialog.h

sctp_graph_dialog.cpp sctp_graph_dialog.h: ui_sctp_graph_dialog.h

sctp_graph_arwnd_dialog.cpp sctp_graph_arwnd_dialog.h: ui_sctp_graph_arwnd_dialog.h

sctp_graph_byte_dialog.cpp sctp_graph_byte_dialog.h: ui_sctp_graph_byte_dialog.h

splash_overlay.cpp splash_overlay.h: ui_splash_overlay.h

stats_tree_dialog.cpp stats_tree_dialog.h: ui_stats_tree_dialog.h

summary_dialog.cpp summary_dialog.h: ui_summary_dialog.h

tcp_stream_dialog.cpp: ui_tcp_stream_dialog.h

time_shift_dialog.cpp time_shift_dialog.h: ui_time_shift_dialog.h

uat_dialog.cpp uat_dialog.h: ui_uat_dialog.h

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g deprecated-gtk -build \
	-sourcedir=$(srcdir) \
	$(WIRESHARK_GTK_SRC) \
	$(WIRESHARK_TAP_SRC) \
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
#	Makefile.nmake
EXTRA_DIST = \
	$(GENERATOR_FILES)		\
	$(UI_FILES)			\
	$(QRC_FILES)			\
	$(TS_FILES)			\
	$(QM_FILES)			\
	CMakeLists.txt			\
	doxygen.cfg.in			\
	main.cpp			\
	Makefile.common			\
	Makefile_custom.common		\
	QtShark.pro			\
	display_filter_16.svg		\
	gpl-template.txt
