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
include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS) $(Qt_CFLAGS)

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
wireshark-tap-register.c: $(WIRESHARK_QT_TAP_SRC) $(top_srcdir)/tools/make-tap-reg.py
	@echo Making wireshark-tap-register.c
	@$(PYTHON) $(top_srcdir)/tools/make-tap-reg.py $(srcdir) taps $(WIRESHARK_QT_TAP_SRC)

libqtui_a_SOURCES = \
	$(WIRESHARK_QT_SRC) \
	$(WIRESHARK_QT_TAP_SRC) \
	$(GENERATED_C_FILES) \
	$(GENERATED_CPP_FILES) \
	$(noinst_HEADERS) \
	$(GENERATED_HEADER_FILES)

nodist_libqtui_a_SOURCES = \
	$(NODIST_GENERATED_C_FILES) \
	$(NODIST_GENERATED_CPP_FILES) \
	$(NODIST_GENERATED_HEADER_FILES)

libqtui_a_DEPENDENCIES =

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
# For building .moc.cpp files from .h files by running moc,
# building .rcc.cpp files from .qrc files by running rcc,
# and building ui_XXX.h files from .ui files by running uic.
#
SUFFIXES = .moc.cpp .qrc .rcc.cpp

.h.moc.cpp:
	$(AM_V_MOC)$(MOC) $(MOC_OPTIONS) -I.. -I../.. -o $@ $<

.qrc.rcc.cpp:
	$(MKDIR_P) $(@D)
	$(AM_V_RCC)$(RCC) -name `basename $< .qrc` -o $@ $<

ui_%.h: %.ui
	$(AM_V_UIC)$(UIC) $< -o $@

# The Qt toolchain uses the naming convention moc_FOO.cpp. Should we do the same?
#moc_%.cpp: %.h
#	$(MOC) $< -o $@

#
# Explicit dependencies to force the ui_ headers to be built.
# See "Recording Dependencies manually" in the "Built Sources"
# section of the automake documentation:
#
#    https://www.gnu.org/software/automake/manual/automake.html#Sources
#
about_dialog.$(OBJEXT): ui_about_dialog.h

address_editor_frame.$(OBJEXT): ui_address_editor_frame.h

bluetooth_att_server_attributes_dialog.$(OBJEXT): ui_bluetooth_att_server_attributes_dialog.h

bluetooth_devices_dialog.$(OBJEXT): ui_bluetooth_devices_dialog.h

bluetooth_hci_summary_dialog.$(OBJEXT): ui_bluetooth_hci_summary_dialog.h

capture_file_properties_dialog.$(OBJEXT): ui_capture_file_properties_dialog.h

capture_interfaces_dialog.$(OBJEXT): ui_capture_interfaces_dialog.h

capture_preferences_frame.$(OBJEXT): ui_capture_preferences_frame.h

coloring_rules_dialog.$(OBJEXT): ui_coloring_rules_dialog.h

column_editor_frame.$(OBJEXT): ui_column_editor_frame.h

column_preferences_frame.$(OBJEXT): ui_column_preferences_frame.h

compiled_filter_output.$(OBJEXT): ui_compiled_filter_output.h

conversation_hash_tables_dialog.$(OBJEXT): ui_conversation_hash_tables_dialog.h

decode_as_dialog.$(OBJEXT): ui_decode_as_dialog.h

display_filter_expression_dialog.$(OBJEXT): ui_display_filter_expression_dialog.h

dissector_tables_dialog.$(OBJEXT): ui_dissector_tables_dialog.h

enabled_protocols_dialog.$(OBJEXT): ui_enabled_protocols_dialog.h

expert_info_dialog.$(OBJEXT): ui_expert_info_dialog.h

export_object_dialog.$(OBJEXT): ui_export_object_dialog.h

export_pdu_dialog.$(OBJEXT): ui_export_pdu_dialog.h

extcap_options_dialog.$(OBJEXT): ui_extcap_options_dialog.h

file_set_dialog.$(OBJEXT): ui_file_set_dialog.h

filter_dialog.$(OBJEXT): ui_filter_dialog.h

filter_expression_frame.$(OBJEXT): ui_filter_expression_frame.h

filter_expressions_preferences_frame.$(OBJEXT): ui_filter_expressions_preferences_frame.h

follow_stream_dialog.$(OBJEXT): ui_follow_stream_dialog.h

font_color_preferences_frame.$(OBJEXT): ui_font_color_preferences_frame.h

funnel_string_dialog.$(OBJEXT): ui_funnel_string_dialog.h

funnel_text_dialog.$(OBJEXT): ui_funnel_text_dialog.h

gsm_map_summary_dialog.$(OBJEXT): ui_gsm_map_summary_dialog.h

iax2_analysis_dialog.$(OBJEXT): ui_iax2_analysis_dialog.h

import_text_dialog.$(OBJEXT): ui_import_text_dialog.h

io_graph_dialog.$(OBJEXT): ui_io_graph_dialog.h

layout_preferences_frame.$(OBJEXT): ui_layout_preferences_frame.h

lbm_lbtrm_transport_dialog.$(OBJEXT): ui_lbm_lbtrm_transport_dialog.h

lbm_lbtru_transport_dialog.$(OBJEXT): ui_lbm_lbtru_transport_dialog.h

lbm_stream_dialog.$(OBJEXT): ui_lbm_stream_dialog.h

lbm_uimflow_dialog.$(OBJEXT): ui_lbm_uimflow_dialog.h

lte_rlc_graph_dialog.$(OBJEXT): ui_lte_rlc_graph_dialog.h

main_welcome.$(OBJEXT): ui_main_welcome.h

main_window.$(OBJEXT): ui_main_window.h

main_window_preferences_frame.$(OBJEXT): ui_main_window_preferences_frame.h

main_window_slots.$(OBJEXT): ui_main_window.h

manage_interfaces_dialog.$(OBJEXT): ui_manage_interfaces_dialog.h

module_preferences_scroll_area.$(OBJEXT): ui_module_preferences_scroll_area.h

mtp3_summary_dialog.$(OBJEXT): ui_mtp3_summary_dialog.h

packet_comment_dialog.$(OBJEXT): ui_packet_comment_dialog.h

packet_dialog.$(OBJEXT): ui_packet_dialog.h

packet_format_group_box.$(OBJEXT): ui_packet_format_group_box.h

packet_range_group_box.$(OBJEXT): ui_packet_range_group_box.h

preference_editor_frame.$(OBJEXT): ui_preference_editor_frame.h

preferences_dialog.$(OBJEXT): ui_preferences_dialog.h

print_dialog.$(OBJEXT): ui_print_dialog.h

progress_frame.$(OBJEXT): ui_progress_frame.h

profile_dialog.$(OBJEXT): ui_profile_dialog.h

protocol_hierarchy_dialog.$(OBJEXT): ui_protocol_hierarchy_dialog.h

remote_capture_dialog.$(OBJEXT): ui_remote_capture_dialog.h

remote_settings_dialog.$(OBJEXT): ui_remote_settings_dialog.h

resolved_addresses_dialog.$(OBJEXT): ui_resolved_addresses_dialog.h

rtp_analysis_dialog.$(OBJEXT): ui_rtp_analysis_dialog.h

rtp_player_dialog.$(OBJEXT): ui_rtp_player_dialog.h

rtp_stream_dialog.$(OBJEXT): ui_rtp_stream_dialog.h

search_frame.$(OBJEXT): ui_search_frame.h

sequence_dialog.$(OBJEXT): ui_sequence_dialog.h

sctp_all_assocs_dialog.$(OBJEXT): ui_sctp_all_assocs_dialog.h

sctp_assoc_analyse_dialog.$(OBJEXT): ui_sctp_assoc_analyse_dialog.h

sctp_chunk_statistics_dialog.$(OBJEXT): ui_sctp_chunk_statistics_dialog.h

sctp_graph_dialog.$(OBJEXT): ui_sctp_graph_dialog.h

sctp_graph_arwnd_dialog.$(OBJEXT): ui_sctp_graph_arwnd_dialog.h

sctp_graph_byte_dialog.$(OBJEXT): ui_sctp_graph_byte_dialog.h

show_packet_bytes_dialog.$(OBJEXT): ui_show_packet_bytes_dialog.h

splash_overlay.$(OBJEXT): ui_splash_overlay.h

supported_protocols_dialog.$(OBJEXT): ui_supported_protocols_dialog.h

tap_parameter_dialog.$(OBJEXT): ui_tap_parameter_dialog.h

tcp_stream_dialog.$(OBJEXT): ui_tcp_stream_dialog.h

time_shift_dialog.$(OBJEXT): ui_time_shift_dialog.h

traffic_table_dialog.$(OBJEXT): ui_traffic_table_dialog.h

uat_dialog.$(OBJEXT): ui_uat_dialog.h

voip_calls_dialog.$(OBJEXT): ui_voip_calls_dialog.h

wireless_frame.$(OBJEXT): ui_wireless_frame.h

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

#checkapi: checkapi-base checkapi-todo

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
	Makefile.common			\
	Makefile_custom.common		\
	Wireshark.pro			\
	gpl-template.txt
