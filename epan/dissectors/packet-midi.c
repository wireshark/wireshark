/* packet-midi.c
 * MIDI dissector
 *
 * Copyright (c) 2006-2012, Tobias Erichsen <t.erichsen@gmx.de>
 * Copyright (c) 2026 by Matt Morris <mattm.dev.1[AT]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * NOTES:
 * The handling of SysEx messages (start/end) is tailored to their slightly
 * non-standard use in RTP-MIDI. Should still work elsewhere, but might accept some
 * extra messages. (also consider using the dedicated midi-sysex dissector)
 *
 * The dissector does not currently handle system real-time messages that are interleaved
 * within other regular messages.
 * (Most network/usb protocols forbid this so it doesn't matter too much)
 *
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include "data-midi-sysex-id.h"
#include "packet-midi.h"

/* protocols and header fields */
static int proto_midi;
static dissector_handle_t midi_handle;
static dissector_handle_t midi_sysex_handle;

static dissector_handle_t midi_sysex_common_rt_handle;
static dissector_handle_t midi_sysex_common_nrt_handle;
static dissector_handle_t midi_sysex_common_edu_handle;
static dissector_table_t sysex_manufacturer_dissector_table;

static int ett_midi;
static int ett_midi1_command;
static int ett_midi_ump;
static int ett_midi_ump_flex_chord;
static int ett_midi_ump_stream_request;
static int ett_midi_ump_stream_fb_disc;

static int ett_midi2_attr_data;
static int ett_midi2_program_options;
static int ett_midi2_note_manage;

static int ett_midi_sysex_data;
static int ett_midi_sysex_edu;
static int ett_midi_sysex_manu;
static int ett_midi_sysex_common_rt;
static int ett_midi_sysex_common_nrt;
static int ett_midi_sysex_common_tune_note;
static int ett_midi_sysex_ci_proc_supported_features;
static int ett_midi_sysex_ci_proc_requested_system_messages;
static int ett_midi_sysex_ci_proc_requested_channel_messages;
static int ett_midi_sysex_ci_proc_requested_note_messages;
static int ett_midi_sysex_ci_supported_categories;

static int hf_midi1_command;

static int hf_midi1_channel_status;
static int hf_midi_channel;
static int hf_midi_note;
static int hf_midi1_velocity;
static int hf_midi1_pressure;
static int hf_midi1_controller;
static int hf_midi1_controller_value;
static int hf_midi1_program;
static int hf_midi1_channel_pressure;
static int hf_midi1_pitch_bend;

static int hf_midi_common_status;
static int hf_midi_quarter_frame_type;
static int hf_midi_quarter_frame_value;
static int hf_midi_spp;
static int hf_midi_song_select;
static int hf_midi_unknown_data;

static int hf_midi_ump;
static int hf_midi_ump_mt;
static int hf_midi_ump_group;
static int hf_midi_ump_reserved;
static int hf_midi_ump_utility_status;
static int hf_midi_ump_utility_jr;
static int hf_midi_ump_utility_dc_tpq;
static int hf_midi_ump_utility_dc;
static int hf_midi_ump_data64_status;
static int hf_midi_ump_data64_length;
static int hf_midi_ump_data64_data;
static int hf_midi_ump_data64_pad;
static int hf_midi_ump_data128_status;
static int hf_midi_ump_data128_length;
static int hf_midi_ump_data128_stream_id;
static int hf_midi_ump_data128_data;
static int hf_midi_ump_data128_mds_chunk_len;
static int hf_midi_ump_data128_mds_chunk_count;
static int hf_midi_ump_data128_mds_chunk_num;
static int hf_midi_ump_data128_mds_payload;

static int hf_midi_ump_flex_format;
static int hf_midi_ump_flex_address;
static int hf_midi_ump_flex_channel;
static int hf_midi_ump_flex_status_bank;
static int hf_midi_ump_flex_status_00;
static int hf_midi_ump_flex_status_01;
static int hf_midi_ump_flex_status_02;
static int hf_midi_ump_flex_status;
static int hf_midi_ump_flex_data;
static int hf_midi_ump_flex_data_text;
static int hf_midi_ump_flex_data_tempo;
static int hf_midi_ump_flex_data_ts_num;
static int hf_midi_ump_flex_data_ts_den;
static int hf_midi_ump_flex_data_ts_notes;
static int hf_midi_ump_flex_data_met_clocks;
static int hf_midi_ump_flex_data_met_bar_1;
static int hf_midi_ump_flex_data_met_bar_2;
static int hf_midi_ump_flex_data_met_bar_3;
static int hf_midi_ump_flex_data_met_sub_1;
static int hf_midi_ump_flex_data_met_sub_2;
static int hf_midi_ump_flex_data_sig_sharps;
static int hf_midi_ump_flex_data_sig_tonic;
static int hf_midi_ump_flex_data_chord_tonic;
static int hf_midi_ump_flex_data_chord_bass;
static int hf_midi_ump_flex_data_chord_sharps;
static int hf_midi_ump_flex_data_chord_note;
static int hf_midi_ump_flex_data_chord_type;
static int hf_midi_ump_flex_data_chord_alt_type;
static int hf_midi_ump_flex_data_chord_alt_deg;

static int hf_midi_ump_stream_form;
static int hf_midi_ump_stream_status;
static int hf_midi_ump_stream_ver_major;
static int hf_midi_ump_stream_ver_minor;
static int hf_midi_ump_stream_request;
static int hf_midi_ump_stream_request_e;
static int hf_midi_ump_stream_request_d;
static int hf_midi_ump_stream_request_n;
static int hf_midi_ump_stream_request_i;
static int hf_midi_ump_stream_request_s;
static int hf_midi_ump_stream_ep_info_s;
static int hf_midi_ump_stream_ep_info_fbs;
static int hf_midi_ump_stream_ep_info_m2;
static int hf_midi_ump_stream_ep_info_m1;
static int hf_midi_ump_stream_rx_jr;
static int hf_midi_ump_stream_tx_jr;
static int hf_midi_ump_stream_ep_name;
static int hf_midi_ump_stream_prod_id;
static int hf_midi_ump_stream_protocol;
static int hf_midi_ump_stream_fb_num;
static int hf_midi_ump_stream_fb_disc;
static int hf_midi_ump_stream_fb_disc_info;
static int hf_midi_ump_stream_fb_disc_name;
static int hf_midi_ump_stream_fb_active;
static int hf_midi_ump_stream_fb_ui_hint;
static int hf_midi_ump_stream_fb_midi_1;
static int hf_midi_ump_stream_fb_dir;
static int hf_midi_ump_stream_fb_group;
static int hf_midi_ump_stream_fb_group_span;
static int hf_midi_ump_stream_fb_ci_version;
static int hf_midi_ump_stream_fb_sysex8_count;
static int hf_midi_ump_stream_fb_name;

static int hf_midi2_channel_status;
static int hf_midi2_attribute_type;
static int hf_midi2_velocity;
static int hf_midi2_attr_data;
static int hf_midi2_attr_data_pitch_semitones;
static int hf_midi2_attr_data_pitch_fract;
static int hf_midi2_pressure;
static int hf_midi2_controller_value;
static int hf_midi2_program_options;
static int hf_midi2_program_options_bank_valid;
static int hf_midi2_program_bank_msb;
static int hf_midi2_program_bank_lsb;
static int hf_midi2_channel_pressure;
static int hf_midi2_pitch_bend;
static int hf_midi2_per_note_controller;
static int hf_midi2_per_note_controller_value;
static int hf_midi2_param_bank;
static int hf_midi2_param_index;
static int hf_midi2_param_value;
static int hf_midi2_param_delta;
static int hf_midi2_note_manage;
static int hf_midi2_note_manage_detach;
static int hf_midi2_note_manage_reset;
static int hf_midi2_per_note_pitch_bend;

static int hf_midi_sysex8_manu;
static int hf_midi_sysex8_device_id;
static int hf_midi_sysex8_sub_id_1;
static int hf_midi_sysex8_sub_id_2;


static int hf_midi_sysex_manu_short;
static int hf_midi_sysex_manu_long;
static int hf_midi_sysex_edu_data;

static int hf_midi_sysex_common_device_id;
static int hf_midi_sysex_common_non_realtime;
static int hf_midi_sysex_common_realtime;

static int hf_midi_sysex_dump_packet_number;
static int hf_midi_sysex_sample_dump_sample_number;
static int hf_midi_sysex_sample_dump_sample_format;
static int hf_midi_sysex_sample_dump_sample_period;
static int hf_midi_sysex_sample_dump_sample_length;
static int hf_midi_sysex_sample_dump_loop_start;
static int hf_midi_sysex_sample_dump_loop_end;
static int hf_midi_sysex_sample_dump_loop_type;
static int hf_midi_sysex_sample_dump_packet_count;
static int hf_midi_sysex_sample_dump_packet_check;
static int hf_midi_sysex_sample_dump_packet_data;
static int hf_midi_sysex_sample_dump_ext_msg_type;
static int hf_midi_sysex_sample_dump_ext_loop_number;

static int hf_midi_sysex_mtc_type;
static int hf_midi_sysex_mtc_hour;
static int hf_midi_sysex_mtc_min;
static int hf_midi_sysex_mtc_sec;
static int hf_midi_sysex_mtc_frame;
static int hf_midi_sysex_mtc_fract_frame;
static int hf_midi_sysex_mtc_rt_msg_type;
static int hf_midi_sysex_mtc_ub_u1;
static int hf_midi_sysex_mtc_ub_u2;
static int hf_midi_sysex_mtc_ub_u3;
static int hf_midi_sysex_mtc_ub_u4;
static int hf_midi_sysex_mtc_ub_u5;
static int hf_midi_sysex_mtc_ub_u6;
static int hf_midi_sysex_mtc_ub_u7;
static int hf_midi_sysex_mtc_ub_u8;
static int hf_midi_sysex_mtc_ub_u9;
static int hf_midi_sysex_mtc_cue_rt_command;
static int hf_midi_sysex_mtc_cue_nrt_command;
static int hf_midi_sysex_mtc_cue_event_num;
static int hf_midi_sysex_mtc_cue_add_info;

static int hf_midi_sysex_gen_info_msg_type;
static int hf_midi_sysex_gen_info_device_family;
static int hf_midi_sysex_gen_info_family_member;
static int hf_midi_sysex_gen_info_software_rev;

static int hf_midi_sysex_file_dump_msg_type;
static int hf_midi_sysex_file_dump_device_id;
static int hf_midi_sysex_file_dump_file_type;
static int hf_midi_sysex_file_dump_file_name;
static int hf_midi_sysex_file_dump_file_length;
static int hf_midi_sysex_file_dump_packet_num;
static int hf_midi_sysex_file_dump_byte_count;
static int hf_midi_sysex_file_dump_packet_data;
static int hf_midi_sysex_file_dump_checksum;

static int hf_midi_sysex_tuning_msg_type;
static int hf_midi_sysex_tuning_program;
static int hf_midi_sysex_tuning_name;
static int hf_midi_sysex_tuning_freq;
static int hf_midi_sysex_tuning_checksum;
static int hf_midi_sysex_tuning_change_count;
static int hf_midi_sysex_common_tune_note;

static int hf_midi_sysex_gen_midi_on_off;

static int hf_midi_sysex_msc_command_format;
static int hf_midi_sysex_msc_command;
static int hf_midi_sysex_msc_q_number;
static int hf_midi_sysex_msc_q_list;
static int hf_midi_sysex_msc_q_path;
static int hf_midi_sysex_msc_q_delimiter;
static int hf_midi_sysex_msc_tc_type;
static int hf_midi_sysex_msc_tc_hour;
static int hf_midi_sysex_msc_tc_colour;
static int hf_midi_sysex_msc_tc_min;
static int hf_midi_sysex_msc_tc_sec;
static int hf_midi_sysex_msc_tc_sign;
static int hf_midi_sysex_msc_tc_final_byte;
static int hf_midi_sysex_msc_tc_frame;
static int hf_midi_sysex_msc_tc_stat_est;
static int hf_midi_sysex_msc_tc_stat_valid;
static int hf_midi_sysex_msc_tc_stat_video;
static int hf_midi_sysex_msc_tc_fract_frame;
static int hf_midi_sysex_msc_generic_controller_number;
static int hf_midi_sysex_msc_generic_controller_value;
static int hf_midi_sysex_msc_macro_number;
static int hf_midi_sysex_msc_checksum;
static int hf_midi_sysex_msc_seq_number;
static int hf_midi_sysex_msc_d1;
static int hf_midi_sysex_msc_d2;
static int hf_midi_sysex_msc_d3;
static int hf_midi_sysex_msc_d4;
static int hf_midi_sysex_msc_status_code_lighting;
static int hf_midi_sysex_msc_status_code_sound;
static int hf_midi_sysex_msc_status_code_machinery;
static int hf_midi_sysex_msc_status_code_video;
static int hf_midi_sysex_msc_status_code_projection;
static int hf_midi_sysex_msc_status_code_process_control;
static int hf_midi_sysex_msc_status_code_pyrotechnics;

static int hf_midi_sysex_note_info_msg_type;
static int hf_midi_sysex_note_info_bar_num;
static int hf_midi_sysex_note_info_bytes;
static int hf_midi_sysex_note_info_numerator;
static int hf_midi_sysex_note_info_denominator;
static int hf_midi_sysex_note_info_midi_clocks;
static int hf_midi_sysex_note_info_32nds;

static int hf_midi_sysex_dev_ctrl_msg_type;
static int hf_midi_sysex_dev_ctrl_volume;
static int hf_midi_sysex_dev_ctrl_balance;

static int hf_midi_sysex_mmc_command;
static int hf_midi_sysex_mmc_response;
static int hf_midi_sysex_mmc_count;
static int hf_midi_sysex_mmc_data;

static int hf_midi_sysex_downloadable_sounds_msg_type;

static int hf_midi_sysex_ci_msg_type;
static int hf_midi_sysex_ci_major_version;
static int hf_midi_sysex_ci_minor_version;
static int hf_midi_sysex_ci_src_muid;
static int hf_midi_sysex_ci_dst_muid;
static int hf_midi_sysex_ci_reserved;

static int hf_midi_sysex_ci_prof_id;
static int hf_midi_sysex_ci_prof_count_enabled;
static int hf_midi_sysex_ci_prof_count_disabled;
static int hf_midi_sysex_ci_prof_chans;
static int hf_midi_sysex_ci_prof_inquiry_target;
static int hf_midi_sysex_ci_prof_inquiry_target_data_len;
static int hf_midi_sysex_ci_prof_inquiry_target_data;
static int hf_midi_sysex_ci_prof_data_len;
static int hf_midi_sysex_ci_prof_data;
static int hf_midi_sysex_ci_prop_sim_supported;
static int hf_midi_sysex_ci_prop_ver_major;
static int hf_midi_sysex_ci_prop_ver_minor;
static int hf_midi_sysex_ci_prop_request_id;
static int hf_midi_sysex_ci_prop_header_len;
static int hf_midi_sysex_ci_prop_header;
static int hf_midi_sysex_ci_prop_chunk_count;
static int hf_midi_sysex_ci_prop_chunk_num;
static int hf_midi_sysex_ci_prop_data_len;
static int hf_midi_sysex_ci_prop_data;
static int hf_midi_sysex_ci_proc_supported_features;
static int hf_midi_sysex_ci_proc_supported_features_msg_report;
static int hf_midi_sysex_ci_proc_message_data_control;
static int hf_midi_sysex_ci_proc_requested_system_messages;
static int hf_midi_sysex_ci_proc_requested_system_messages_mtc_qf;
static int hf_midi_sysex_ci_proc_requested_system_messages_song_pos;
static int hf_midi_sysex_ci_proc_requested_system_messages_song_sel;
static int hf_midi_sysex_ci_proc_requested_channel_messages;
static int hf_midi_sysex_ci_proc_requested_channel_messages_pitch_bend;
static int hf_midi_sysex_ci_proc_requested_channel_messages_cc;
static int hf_midi_sysex_ci_proc_requested_channel_messages_rpn;
static int hf_midi_sysex_ci_proc_requested_channel_messages_nrpn;
static int hf_midi_sysex_ci_proc_requested_channel_messages_pc;
static int hf_midi_sysex_ci_proc_requested_channel_messages_pressure;
static int hf_midi_sysex_ci_proc_requested_note_messages;
static int hf_midi_sysex_ci_proc_requested_note_messages_notes;
static int hf_midi_sysex_ci_proc_requested_note_messages_pressure;
static int hf_midi_sysex_ci_proc_requested_note_messages_pitch_bend;
static int hf_midi_sysex_ci_proc_requested_note_messages_registered_per_note;
static int hf_midi_sysex_ci_proc_requested_note_messages_assigned_per_note;
static int hf_midi_sysex_ci_device_manu_short;
static int hf_midi_sysex_ci_device_manu_long;
static int hf_midi_sysex_ci_supported_categories;
static int hf_midi_sysex_ci_supported_categories_0;
static int hf_midi_sysex_ci_supported_categories_1;
static int hf_midi_sysex_ci_supported_categories_2;
static int hf_midi_sysex_ci_supported_categories_3;
static int hf_midi_sysex_ci_supported_categories_4;
static int hf_midi_sysex_ci_supported_categories_5;
static int hf_midi_sysex_ci_supported_categories_6;
static int hf_midi_sysex_ci_max_sysex;
static int hf_midi_sysex_ci_output_path_id;
static int hf_midi_sysex_ci_function_block;
static int hf_midi_sysex_ci_ep_info_status;
static int hf_midi_sysex_ci_ep_info_len;
static int hf_midi_sysex_ci_ep_info_data;
static int hf_midi_product_instance_id;
static int hf_midi_sysex_ci_ack_original_id;
static int hf_midi_sysex_ci_ack_status_code;
static int hf_midi_sysex_ci_ack_status_data;
static int hf_midi_sysex_ci_ack_details;
static int hf_midi_sysex_ci_ack_msg_len;
static int hf_midi_sysex_ci_ack_message;
static int hf_midi_sysex_ci_invalid_muid;
static int hf_midi_sysex_ci_nak_original_id;
static int hf_midi_sysex_ci_nak_status_code;
static int hf_midi_sysex_ci_nak_status_data;
static int hf_midi_sysex_ci_nak_details;
static int hf_midi_sysex_ci_nak_msg_len;
static int hf_midi_sysex_ci_nak_message;


static int ett_midi_ump_data64_msg_fragment;
static int ett_midi_ump_data64_msg_fragments;
static int hf_midi_ump_data64_msg_fragments;
static int hf_midi_ump_data64_msg_fragment;
static int hf_midi_ump_data64_msg_fragment_overlap;
static int hf_midi_ump_data64_msg_fragment_overlap_conflicts;
static int hf_midi_ump_data64_msg_fragment_multiple_tails;
static int hf_midi_ump_data64_msg_fragment_too_long_fragment;
static int hf_midi_ump_data64_msg_fragment_error;
static int hf_midi_ump_data64_msg_fragment_count;
static int hf_midi_ump_data64_msg_reassembled_in;
static int hf_midi_ump_data64_msg_reassembled_length;
static int hf_midi_ump_data64_msg_reassembled_data;

static reassembly_table midi_ump_data64_reassembly_table;

static const fragment_items midi_ump_data64_msg_frag_items = {
    /* Fragment subtrees */
    &ett_midi_ump_data64_msg_fragment,
    &ett_midi_ump_data64_msg_fragments,
    /* Fragment fields */
    &hf_midi_ump_data64_msg_fragments,
    &hf_midi_ump_data64_msg_fragment,
    &hf_midi_ump_data64_msg_fragment_overlap,
    &hf_midi_ump_data64_msg_fragment_overlap_conflicts,
    &hf_midi_ump_data64_msg_fragment_multiple_tails,
    &hf_midi_ump_data64_msg_fragment_too_long_fragment,
    &hf_midi_ump_data64_msg_fragment_error,
    &hf_midi_ump_data64_msg_fragment_count,
    /* Reassembled in field */
    &hf_midi_ump_data64_msg_reassembled_in,
    /* Reassembled length field */
    &hf_midi_ump_data64_msg_reassembled_length,
    &hf_midi_ump_data64_msg_reassembled_data,
    /* Tag */
    "Message fragments"
};


static const value_string midi_note_values[] = {
    { 0,   "C-1" },
    { 1,   "C#-1" },
    { 2,   "D-1" },
    { 3,   "D#-1" },
    { 4,   "E-1" },
    { 5,   "F-1" },
    { 6,   "F#-1" },
    { 7,   "G-1" },
    { 8,   "G#-1" },
    { 9,   "A-1" },
    { 10,  "A#-1" },
    { 11,  "B-1" },
    { 12,  "C0" },
    { 13,  "C#0" },
    { 14,  "D0" },
    { 15,  "D#0" },
    { 16,  "E0" },
    { 17,  "F0" },
    { 18,  "F#0" },
    { 19,  "G0" },
    { 20,  "G#0" },
    { 21,  "A0" },
    { 22,  "A#0" },
    { 23,  "B0" },
    { 24,  "C1" },
    { 25,  "C#1" },
    { 26,  "D1" },
    { 27,  "D#1" },
    { 28,  "E1" },
    { 29,  "F1" },
    { 30,  "F#1" },
    { 31,  "G1" },
    { 32,  "G#1" },
    { 33,  "A1" },
    { 34,  "A#1" },
    { 35,  "B1" },
    { 36,  "C2" },
    { 37,  "C#2" },
    { 38,  "D2" },
    { 39,  "D#2" },
    { 40,  "E2" },
    { 41,  "F2" },
    { 42,  "F#2" },
    { 43,  "G2" },
    { 44,  "G#2" },
    { 45,  "A2" },
    { 46,  "A#2" },
    { 47,  "B2" },
    { 48,  "C3" },
    { 49,  "C#3" },
    { 50,  "D3" },
    { 51,  "D#3" },
    { 52,  "E3" },
    { 53,  "F3" },
    { 54,  "F#3" },
    { 55,  "G3" },
    { 56,  "G#3" },
    { 57,  "A3" },
    { 58,  "A#3" },
    { 59,  "B3" },
    { 60,  "C4" },
    { 61,  "C#4" },
    { 62,  "D4" },
    { 63,  "D#4" },
    { 64,  "E4" },
    { 65,  "F4" },
    { 66,  "F#4" },
    { 67,  "G4" },
    { 68,  "G#4" },
    { 69,  "A4" },
    { 70,  "A#4" },
    { 71,  "B4" },
    { 72,  "C5" },
    { 73,  "C#5" },
    { 74,  "D5" },
    { 75,  "D#5" },
    { 76,  "E5" },
    { 77,  "F5" },
    { 78,  "F#5" },
    { 79,  "G5" },
    { 80,  "G#5" },
    { 81,  "A5" },
    { 82,  "A#5" },
    { 83,  "B5" },
    { 84,  "C6" },
    { 85,  "C#6" },
    { 86,  "D6" },
    { 87,  "D#6" },
    { 88,  "E6" },
    { 89,  "F6" },
    { 90,  "F#6" },
    { 91,  "G6" },
    { 92,  "G#6" },
    { 93,  "A6" },
    { 94,  "A#6" },
    { 95,  "B6" },
    { 96,  "C7" },
    { 97,  "C#7" },
    { 98,  "D7" },
    { 99,  "D#7" },
    { 100, "E7" },
    { 101, "F7" },
    { 102, "F#7" },
    { 103, "G7" },
    { 104, "G#7" },
    { 105, "A7" },
    { 106, "A#7" },
    { 107, "B7" },
    { 108, "C8" },
    { 109, "C#8" },
    { 110, "D8" },
    { 111, "D#8" },
    { 112, "E8" },
    { 113, "F8" },
    { 114, "F#8" },
    { 115, "G8" },
    { 116, "G#8" },
    { 117, "A8" },
    { 118, "A#8" },
    { 119, "B8" },
    { 120, "C9" },
    { 121, "C#9" },
    { 122, "D9" },
    { 123, "D#9" },
    { 124, "E9" },
    { 125, "F9" },
    { 126, "F#9" },
    { 127, "G9" },
    { 0,   NULL }
};
value_string_ext midi_note_values_ext = VALUE_STRING_EXT_INIT(midi_note_values);

static const value_string midi_controller_values[] = {
    { 0,   "Bank Select (msb)" },
    { 1,   "Modulation Wheel Or Lever (msb)" },
    { 2,   "Breath Controller (msb)" },
    /* 3 */
    { 4,   "Foot Controller (msb)" },
    { 5,   "Portamento Time (msb)" },
    { 6,   "Data Entry (msb)" },
    { 7,   "Channel Volume (msb)" },
    { 8,   "Balance (msb)" },
    /* 9 */
    { 10,  "Pan (msb)" },
    { 11,  "Expression Controller (msb)" },
    { 12,  "Effect Control 1 (msb)" },
    { 13,  "Effect Control 2 (msb)" },
    /* 14, 15 */
    { 16,  "General Purpose Controller 1 (msb)" },
    { 17,  "General Purpose Controller 2 (msb)" },
    { 18,  "General Purpose Controller 3 (msb)" },
    { 19,  "General Purpose Controller 4 (msb)" },
    /* 20-31 */
    { 32,  "Bank Select (lsb)" },
    { 33,  "Modulation Wheel Or Lever (lsb)" },
    { 34,  "Breath Controller (lsb)" },
    /* 35 */
    { 36,  "Foot Controller (lsb)" },
    { 37,  "Portamento Time (lsb)" },
    { 38,  "Data Entry (lsb)" },
    { 39,  "Volume (lsb)" },
    { 40,  "Balance (lsb)" },
    /* 41 */
    { 42,  "Pan (lsb)" },
    { 43,  "Expression Controller (lsb)" },
    { 44,  "Effect Control 1 (lsb)" },
    { 45,  "Effect Control 2 (lsb)" },
    /* 46, 47 */
    { 48,  "General Purpose Controller 1 (lsb)" },
    { 49,  "General Purpose Controller 2 (lsb)" },
    { 50,  "General Purpose Controller 3 (lsb)" },
    { 51,  "General Purpose Controller 4 (lsb)" },
    /* 48-51: General Purpose Controller 1-4 */
    /* 52-63 */
    { 64,  "Damper Pedal" },
    { 65,  "Portamento On/Off" },
    { 66,  "Sustenuto" },
    { 67,  "Soft Pedal" },
    { 68,  "Legato Footswitch" },
    { 69,  "Hold 2" },
    { 70,  "Sound Controller 1 (default: Sound Variation)" },
    { 71,  "Sound Controller 2 (default: Timbre/Harmonic Intensity)" },
    { 72,  "Sound Controller 3 (default: Release Time)" },
    { 73,  "Sound Controller 4 (default: Attack Time)" },
    { 74,  "Sound Controller 5 (default: Brightness)" },
    { 75,  "Sound Controller 6" },
    { 76,  "Sound Controller 7" },
    { 77,  "Sound Controller 8" },
    { 78,  "Sound Controller 9" },
    { 79,  "Sound Controller 10" },
    { 80,  "General Purpose Controller 5" },
    { 81,  "General Purpose Controller 6" },
    { 82,  "General Purpose Controller 7" },
    { 83,  "General Purpose Controller 8" },
    { 84,  "Portamento Control" },
    /* 85-90 */
    { 91,  "Effects 1 Depth (formerly: External Effects Depth)" },
    { 92,  "Effects 2 Depth (formerly: Tremolo Depth)" },
    { 93,  "Effects 3 Depth (formerly: Chorus Depth)" },
    { 94,  "Effects 4 Depth (formerly: Celeste (Detune) Depth)" },
    { 95,  "Effects 5 Depth (formerly: Phaser Depth)" },
    { 96,  "Data Increment" },
    { 97,  "Data Decrement" },
    { 98,  "Non-Registered Parameter (lsb)" },
    { 99,  "Non-Registered Parameter (msb)" },
    { 100, "Registered Parameter (lsb)" },
    { 101, "Registered Parameter (msb)" },
    /* 102-119 */
    { 120, "All Sound Off" },
    { 121, "Reset All Controllers" },
    { 122, "Local Control" },
    { 123, "All Notes Off" },
    { 124, "Omni Mode Off" },
    { 125, "Omni Mode On" },
    { 126, "Mono Mode On" },
    { 127, "Poly Mode On" },
    { 0,   NULL }
};
value_string_ext midi_controller_values_ext = VALUE_STRING_EXT_INIT(midi_controller_values);

const value_string midi_channels[] = {
    { 0,  "Channel 1" },
    { 1,  "Channel 2" },
    { 2,  "Channel 3" },
    { 3,  "Channel 4" },
    { 4,  "Channel 5" },
    { 5,  "Channel 6" },
    { 6,  "Channel 7" },
    { 7,  "Channel 8" },
    { 8,  "Channel 9" },
    { 9,  "Channel 10" },
    { 10, "Channel 11" },
    { 11, "Channel 12" },
    { 12, "Channel 13" },
    { 13, "Channel 14" },
    { 14, "Channel 15" },
    { 15, "Channel 16" },
    { 0,  NULL }
};


#define MIDI_STATUS_CHAN_NOTE_OFF         0x08
#define MIDI_STATUS_CHAN_NOTE_ON          0x09
#define MIDI_STATUS_CHAN_POLY_PRESSURE    0x0a
#define MIDI_STATUS_CHAN_CONTROL_CHANGE   0x0b
#define MIDI_STATUS_CHAN_PROGRAM_CHANGE   0x0c
#define MIDI_STATUS_CHAN_CHANNEL_PRESSURE 0x0d
#define MIDI_STATUS_CHAN_PITCH_BEND       0x0e
static const value_string midi_channel_status[] = {
    { MIDI_STATUS_CHAN_NOTE_OFF,         "Note Off" },
    { MIDI_STATUS_CHAN_NOTE_ON,          "Note On" },
    { MIDI_STATUS_CHAN_POLY_PRESSURE,    "Polyphonic Key Pressure" },
    { MIDI_STATUS_CHAN_CONTROL_CHANGE,   "Control Change" },
    { MIDI_STATUS_CHAN_PROGRAM_CHANGE,   "Program Change" },
    { MIDI_STATUS_CHAN_CHANNEL_PRESSURE, "Channel Pressure" },
    { MIDI_STATUS_CHAN_PITCH_BEND,       "Pitch Bend Change" },
    { 0,                                 NULL }
};
static const char* midi_channel_status_special_off = "Note Off*";

#define MIDI_STATUS_COMMON_SYSEX_START             0xf0
#define MIDI_STATUS_COMMON_MTC_QUARTER_FRAME       0xf1
#define MIDI_STATUS_COMMON_SONG_POSITION_POINTER   0xf2
#define MIDI_STATUS_COMMON_SONG_SELECT             0xf3
#define MIDI_STATUS_COMMON_UNDEFINED_F4            0xf4
#define MIDI_STATUS_COMMON_UNDEFINED_F5            0xf5
#define MIDI_STATUS_COMMON_TUNE_REQUEST            0xf6
#define MIDI_STATUS_COMMON_SYSEX_END               0xf7
#define MIDI_STATUS_COMMON_REALTIME_TIMING_CLOCK   0xf8
#define MIDI_STATUS_COMMON_REALTIME_MIDI_TICK      0xf9 /* Spec says undefined */
#define MIDI_STATUS_COMMON_REALTIME_START          0xfa
#define MIDI_STATUS_COMMON_REALTIME_CONTINUE       0xfb
#define MIDI_STATUS_COMMON_REALTIME_STOP           0xfc
#define MIDI_STATUS_COMMON_REALTIME_UNDEFINED_FD   0xfd
#define MIDI_STATUS_COMMON_REALTIME_ACTIVE_SENSING 0xfe
#define MIDI_STATUS_COMMON_REALTIME_SYSTEM_RESET   0xff
static const value_string midi_common_status[] = {
    /* Common 0xf0 - 0xf7 */
    { MIDI_STATUS_COMMON_SYSEX_START,           "SOX: Start Of System-Exclusive / End of System-Exclusive Segment" },
    { MIDI_STATUS_COMMON_MTC_QUARTER_FRAME,     "MTC Quarter Frame" },
    { MIDI_STATUS_COMMON_SONG_POSITION_POINTER, "Song Position Pointer" },
    { MIDI_STATUS_COMMON_SONG_SELECT,           "Song Select" },
    { MIDI_STATUS_COMMON_UNDEFINED_F4,          "Systems Exclusive Cancel" }, /* not defined, special use in RTP-MIDI */
    { MIDI_STATUS_COMMON_UNDEFINED_F5,          "Undefined 0xf5" },           /* not defined */
    { MIDI_STATUS_COMMON_TUNE_REQUEST,          "Tune Request" },
    { MIDI_STATUS_COMMON_SYSEX_END,             "EOX: Start of System-Exclusive Segment / End of System-Exclusive" },
    /* Realtime 0xf8 - 0xff */
    { MIDI_STATUS_COMMON_REALTIME_TIMING_CLOCK,   "RT: Timing Clock" },
    { MIDI_STATUS_COMMON_REALTIME_MIDI_TICK,      "RT: Midi Tick" },            /* undefined ??? */
    { MIDI_STATUS_COMMON_REALTIME_START,          "RT: Start" },
    { MIDI_STATUS_COMMON_REALTIME_CONTINUE,       "RT: Continue" },
    { MIDI_STATUS_COMMON_REALTIME_STOP,           "RT: Stop" },
    { MIDI_STATUS_COMMON_REALTIME_UNDEFINED_FD,   "RT: Undefined 0xfd" },
    { MIDI_STATUS_COMMON_REALTIME_ACTIVE_SENSING, "RT: Active sensing" },
    { MIDI_STATUS_COMMON_REALTIME_SYSTEM_RESET,   "RT: Systems reset" },
    { 0, NULL }
};
static const char rtp_midi_common_status_sysex_segment_end[]      = "End of Sysex-Segment";
static const char rtp_midi_common_status_sysex_segment_start[]    = "Start of Sysex-Segment";
static const char rtp_midi_common_status_sysex_segment[]          = "Middle Sysex-Segment";
static const char rtp_midi_common_status_sysex_segment_complete[] = "Full Sysex-Command";
static const char rtp_midi_common_status_sysex_cancel[]           = "Sysex-Cancel";




#define MIDI_UMP_MT_UTILITY   0x0
#define MIDI_UMP_MT_SYSTEM    0x1
#define MIDI_UMP_MT_MIDI_1    0x2
#define MIDI_UMP_MT_DATA_64   0x3
#define MIDI_UMP_MT_MIDI_2    0x4
#define MIDI_UMP_MT_DATA_128  0x5
#define MIDI_UMP_MT_FLEX_DATA 0xD
#define MIDI_UMP_MT_STREAM    0xF
static const value_string midi_ump_mt_name[] = {
    { MIDI_UMP_MT_UTILITY,   "Utility" },
    { MIDI_UMP_MT_SYSTEM,    "System RealTime/Common" },
    { MIDI_UMP_MT_MIDI_1,    "MIDI 1.0 Channel Voice" },
    { MIDI_UMP_MT_DATA_64,   "8-Byte Data Messages (SysEx)" },
    { MIDI_UMP_MT_MIDI_2,    "MIDI 2.0 Channel Voice" },
    { MIDI_UMP_MT_DATA_128,  "16-Byte Data Messages" },
    { MIDI_UMP_MT_FLEX_DATA, "Flex Data Messages" },
    { MIDI_UMP_MT_STREAM,    "UMP Stream Messages" },
    { 0, NULL }
};
static const value_string midi_ump_mt_name_short[] = {
    { MIDI_UMP_MT_UTILITY,   "Utility" },
    { MIDI_UMP_MT_SYSTEM,    "System" },
    { MIDI_UMP_MT_MIDI_1,    "MIDI 1.0" },
    { MIDI_UMP_MT_DATA_64,   "SysEx" },
    { MIDI_UMP_MT_MIDI_2,    "MIDI 2.0" },
    { MIDI_UMP_MT_DATA_128,  "SysEx8" },
    { MIDI_UMP_MT_FLEX_DATA, "Flex Data" },
    { MIDI_UMP_MT_STREAM,    "Stream" },
    { 0, NULL }
};
static const unsigned int midi_ump_message_size[] = {
    /* 0x0 */ 4,  /* MIDI_UMP_MT_UTILITY */
    /* 0x1 */ 4,  /* MIDI_UMP_MT_SYSTEM */
    /* 0x2 */ 4,  /* MIDI_UMP_MT_MIDI_1 */
    /* 0x3 */ 8,  /* MIDI_UMP_MT_DATA_64 */
    /* 0x4 */ 8,  /* MIDI_UMP_MT_MIDI_2 */
    /* 0x5 */ 16, /* MIDI_UMP_MT_DATA_128 */
    /* 0x6 */ 4,
    /* 0x7 */ 4,
    /* 0x8 */ 8,
    /* 0x9 */ 8,
    /* 0xA */ 8,
    /* 0xB */ 12,
    /* 0xC */ 12,
    /* 0xD */ 16,
    /* 0xE */ 16,
    /* 0xF */ 16
};


#define MIDI_UMP_UTILITY_STATUS_NOOP     0x0
#define MIDI_UMP_UTILITY_STATUS_JR_CLOCK 0x1
#define MIDI_UMP_UTILITY_STATUS_JR_TIME  0x2
#define MIDI_UMP_UTILITY_STATUS_DC_TPQ   0x3
#define MIDI_UMP_UTILITY_STATUS_DC       0x4
static const value_string midi_ump_utility_status_name[] = {
    { MIDI_UMP_UTILITY_STATUS_NOOP,     "NOOP" },
    { MIDI_UMP_UTILITY_STATUS_JR_CLOCK, "JR Clock" },
    { MIDI_UMP_UTILITY_STATUS_JR_TIME,  "JR Timestamp" },
    { MIDI_UMP_UTILITY_STATUS_DC_TPQ,   "DC Ticks Per Quarter Note" },
    { MIDI_UMP_UTILITY_STATUS_DC,       "DC Ticks Since Last Event" },
    { 0, NULL }
};

#define MIDI_UMP_DATA64_STATUS_SINGLE   0x0
#define MIDI_UMP_DATA64_STATUS_START    0x1
#define MIDI_UMP_DATA64_STATUS_CONTINUE 0x2
#define MIDI_UMP_DATA64_STATUS_END      0x3
static const value_string midi_ump_data64_status_name[] = {
    { MIDI_UMP_DATA64_STATUS_SINGLE,   "SysEx in 1 UMP" },
    { MIDI_UMP_DATA64_STATUS_START,    "SysEx Start" },
    { MIDI_UMP_DATA64_STATUS_CONTINUE, "SysEx Continue" },
    { MIDI_UMP_DATA64_STATUS_END,      "SysEx End" },
    { 0, NULL }
};

#define MIDI_UMP_MIDI2_REGISTERED_PER_NOTE 0x0
#define MIDI_UMP_MIDI2_ASSIGNABLE_PER_NOTE 0x1
#define MIDI_UMP_MIDI2_REGISTERED_CONTROL  0x2
#define MIDI_UMP_MIDI2_ASSIGNABLE_CONTROL  0x3
#define MIDI_UMP_MIDI2_REL_REG_CONTROL     0x4
#define MIDI_UMP_MIDI2_REL_ASS_CONTROL     0x5
#define MIDI_UMP_MIDI2_PER_NOTE_PITCH_BEND 0x6
#define MIDI_UMP_MIDI2_PER_NOTE_MANAGEMENT 0xF
static const value_string midi_ump_midi2_status_name[] = {
    { MIDI_STATUS_CHAN_NOTE_OFF,          "Note Off" },
    { MIDI_STATUS_CHAN_NOTE_ON,           "Note On" },
    { MIDI_STATUS_CHAN_POLY_PRESSURE,     "Poly Pressure" },
    { MIDI_STATUS_CHAN_CONTROL_CHANGE,    "Control Change" },
    { MIDI_STATUS_CHAN_PROGRAM_CHANGE,    "Program Change" },
    { MIDI_STATUS_CHAN_CHANNEL_PRESSURE,  "Channel Pressure" },
    { MIDI_STATUS_CHAN_PITCH_BEND,        "Pitch Bend" },
    { MIDI_UMP_MIDI2_REGISTERED_PER_NOTE, "Registered Per-Note Ctrl." },
    { MIDI_UMP_MIDI2_ASSIGNABLE_PER_NOTE, "Assignable Per-Note Ctrl." },
    { MIDI_UMP_MIDI2_REGISTERED_CONTROL,  "Registered Ctrl. (RPN)" },
    { MIDI_UMP_MIDI2_ASSIGNABLE_CONTROL,  "Assignable Ctrl. (NRPN)" },
    { MIDI_UMP_MIDI2_REL_REG_CONTROL,     "Relative Registered Ctrl." },
    { MIDI_UMP_MIDI2_REL_ASS_CONTROL,     "Relative Assignable Ctrl." },
    { MIDI_UMP_MIDI2_PER_NOTE_PITCH_BEND, "Per-Note Pitch Bend" },
    { MIDI_UMP_MIDI2_PER_NOTE_MANAGEMENT, "Per-Note Management" },
    { 0, NULL }
};

#define MIDI_UMP_MIDI2_ATTR_TYPE_PITCH79 0x03
static const value_string midi2_attribute_type[] = {
    { 0x00, "No Attribute Data" },
    { 0x01, "Manufacturer Specific" },
    { 0x02, "Profile Specific" },
    { 0x03, "Pitch 7.9" },
    { 0, NULL }
};

#define MIDI_UMP_DATA128_STATUS_SINGLE      0x0
#define MIDI_UMP_DATA128_STATUS_START       0x1
#define MIDI_UMP_DATA128_STATUS_CONTINUE    0x2
#define MIDI_UMP_DATA128_STATUS_END         0x3
#define MIDI_UMP_DATA128_STATUS_MDS_HEADER  0x8
#define MIDI_UMP_DATA128_STATUS_MDS_PAYLOAD 0x9
static const value_string midi_ump_data128_status_name[] = {
    { MIDI_UMP_DATA128_STATUS_SINGLE,      "SysEx8 in 1 UMP" },
    { MIDI_UMP_DATA128_STATUS_START,       "SysEx8 Start" },
    { MIDI_UMP_DATA128_STATUS_CONTINUE,    "SysEx8 Continue" },
    { MIDI_UMP_DATA128_STATUS_END,         "SysEx8 End" },
    { MIDI_UMP_DATA128_STATUS_MDS_HEADER,  "Mixed Data Set Header" },
    { MIDI_UMP_DATA128_STATUS_MDS_PAYLOAD, "Mixed Data Set Payload" },
    { 0, NULL }
};

static const value_string midi_ump_data128_stream_id_specials[] = {
    { 0x1, "Unexpected EndOfData Valid" },
    { 0xF, "Unexpected EndOfData Incomplete" },
    { 0, NULL }
};

static const value_string midi_ump_flex_format[] = {
    { 0, "Complete Flex Data Message" },
    { 1, "Flex Data Start" },
    { 2, "Flex Data Continue" },
    { 3, "Flex Data End" },
    { 0, NULL }
};
static const value_string midi_ump_flex_address[] = {
    { 0, "Channel" },
    { 1, "Group" },
    { 0, NULL }
};
static const value_string midi_ump_flex_status_bank[] = {
    { 0, "Setup & Performance" },
    { 1, "Metadata Text" },
    { 2, "Performance Text" },
    { 0, NULL }
};

#define MIDI_UMP_FLEX_DATA_STATUS_SET_TEMPO      0x00
#define MIDI_UMP_FLEX_DATA_STATUS_SET_TIME_SIG   0x01
#define MIDI_UMP_FLEX_DATA_STATUS_SET_METRONOME  0x02
#define MIDI_UMP_FLEX_DATA_STATUS_SET_KEY_SIG    0x05
#define MIDI_UMP_FLEX_DATA_STATUS_SET_CHORD_NAME 0x06
static const value_string midi_ump_flex_data_bank_00_status_name[] = {
    { MIDI_UMP_FLEX_DATA_STATUS_SET_TEMPO,      "SysEx8 in 1 UMP" },
    { MIDI_UMP_FLEX_DATA_STATUS_SET_TIME_SIG,   "SysEx8 Start" },
    { MIDI_UMP_FLEX_DATA_STATUS_SET_METRONOME,  "SysEx8 Continue" },
    { MIDI_UMP_FLEX_DATA_STATUS_SET_KEY_SIG,    "SysEx8 End" },
    { MIDI_UMP_FLEX_DATA_STATUS_SET_CHORD_NAME, "Mixed Data Set Header" },
    { 0, NULL }
};
static const value_string midi_ump_flex_data_bank_01_status_name[] = {
    { 0x00, "Unknown Metadata Text Event" },
    { 0x01, "Project Name" },
    { 0x02, "Composition (Song) Name" },
    { 0x03, "MIDI Clip Name" },
    { 0x04, "Copyright Notice" },
    { 0x05, "Composer Name" },
    { 0x06, "Lyricist Name" },
    { 0x07, "Arranger Name" },
    { 0x08, "Publisher Name" },
    { 0x09, "Primary Performer Name" },
    { 0x0A, "Accompanying Performer Name" },
    { 0x0B, "Recording/Concert Date" },
    { 0x0C, "Recording/Concert Location" },
    { 0, NULL }
};
static const value_string midi_ump_flex_data_bank_02_status_name[] = {
    { 0x00, "Unknown Performance Text Events" },
    { 0x01, "Lyrics" },
    { 0x02, "Lyrics Language" },
    { 0x03, "Ruby" },
    { 0x04, "Ruby Language" },
    { 0, NULL }
};

static const value_string midi_ump_flex_data_note[] = {
    { 0x0, "unknown or non-standard" },
    { 0x1, "A" },
    { 0x2, "B" },
    { 0x3, "C" },
    { 0x4, "D" },
    { 0x5, "E" },
    { 0x6, "F" },
    { 0x7, "G" },
    { 0, NULL }
};
static const value_string midi_ump_flex_data_chord_type[] = {
    { 0x00, "Clear Chord - No Chord" },
    { 0x01, "Major" },
    { 0x02, "Major 6th" },
    { 0x03, "Major 7th" },
    { 0x04, "Major 9th" },
    { 0x05, "Major 11th" },
    { 0x06, "Major 13th" },
    { 0x07, "Minor" },
    { 0x08, "Minor 6th" },
    { 0x09, "Minor 7th" },
    { 0x0A, "Minor 9th" },
    { 0x0B, "Minor 11th" },
    { 0x0C, "Minor 13th" },
    { 0x0D, "Dominant" },
    { 0x0E, "Dominant ninth" },
    { 0x0F, "Dominant 11th" },
    { 0x10, "Dominant 13th" },
    { 0x11, "Augmented" },
    { 0x12, "Augmented seventh" },
    { 0x13, "Diminished" },
    { 0x14, "Diminished seventh" },
    { 0x15, "Half diminished" },
    { 0x16, "Major-minor or Minor-major" },
    { 0x17, "Pedal" },
    { 0x18, "Power" },
    { 0x19, "Suspended 2nd" },
    { 0x1A, "Suspended 4th" },
    { 0x1B, "7 Suspended 4th" },
    { 0, NULL }
};
static const value_string midi_ump_flex_data_chord_alt_type[] = {
    { 0, "No alteration" },
    { 1, "Add degree" },
    { 2, "Subtract degree" },
    { 3, "Raise degree" },
    { 4, "Lower degree" },
    { 0, NULL }
};

#define MIDI_UMP_STREAM_STATUS_ENDPOINT_DISCOVERY       0x00
#define MIDI_UMP_STREAM_STATUS_ENDPOINT_INFO            0x01
#define MIDI_UMP_STREAM_STATUS_DEVICE_IDENTITY          0x02
#define MIDI_UMP_STREAM_STATUS_ENDPOINT_NAME            0x03
#define MIDI_UMP_STREAM_STATUS_PRODUCT_INSTANCE_ID      0x04
#define MIDI_UMP_STREAM_STATUS_STREAM_CONFIGURATION_REQ 0x05
#define MIDI_UMP_STREAM_STATUS_STREAM_CONFIGURATION     0x06
#define MIDI_UMP_STREAM_STATUS_FUNCTION_BLOCK_DISCOVERY 0x10
#define MIDI_UMP_STREAM_STATUS_FUNCTION_BLOCK_INFO      0x11
#define MIDI_UMP_STREAM_STATUS_FUNCTION_BLOCK_NAME      0x12
#define MIDI_UMP_STREAM_STATUS_START_OF_CLIP            0x20
#define MIDI_UMP_STREAM_STATUS_END_OF_CLIP              0x21
static const value_string midi_ump_stream_data_status_name[] = {
    { MIDI_UMP_STREAM_STATUS_ENDPOINT_DISCOVERY,       "Endpoint Discovery" },
    { MIDI_UMP_STREAM_STATUS_ENDPOINT_INFO,            "Endpoint Info" },
    { MIDI_UMP_STREAM_STATUS_DEVICE_IDENTITY,          "Device Identity" },
    { MIDI_UMP_STREAM_STATUS_ENDPOINT_NAME,            "Endpoint Name" },
    { MIDI_UMP_STREAM_STATUS_PRODUCT_INSTANCE_ID,      "Product Instance ID" },
    { MIDI_UMP_STREAM_STATUS_STREAM_CONFIGURATION_REQ, "Stream Configuration Request" },
    { MIDI_UMP_STREAM_STATUS_STREAM_CONFIGURATION,     "Stream Configuration" },
    { MIDI_UMP_STREAM_STATUS_FUNCTION_BLOCK_DISCOVERY, "Function Block Discovery" },
    { MIDI_UMP_STREAM_STATUS_FUNCTION_BLOCK_INFO,      "Function Block Info" },
    { MIDI_UMP_STREAM_STATUS_FUNCTION_BLOCK_NAME,      "Function Block name" },
    { MIDI_UMP_STREAM_STATUS_START_OF_CLIP,            "Start Of Clip" },
    { MIDI_UMP_STREAM_STATUS_END_OF_CLIP,              "End of Clip" },
    { 0, NULL }
};

static const value_string midi_ump_stream_format[] = {
    { 0, "Complete Message" },
    { 1, "Start of Message" },
    { 2, "Continuation of Message" },
    { 3, "End of Message" },
    { 0, NULL }
};
static const value_string midi_ump_stream_protocol[] = {
    { 1, "MIDI 1.0 Protocol" },
    { 2, "MIDI 2.0 Protocol" },
    { 0, NULL }
};
static const value_string midi_ump_stream_fb_ui_hint[] = {
    { 0, "unknown or undeclared" },
    { 1, "primarily Receiver" },
    { 2, "primarily Sender" },
    { 3, "Sender and Receiver" },
    { 0, NULL }
};
static const value_string midi_ump_stream_fb_midi_1[] = {
    { 0, "Not MIDI 1.0" },
    { 1, "MIDI 1.0: Don't restrict Bandwidth" },
    { 2, "MIDI 1.0: Restrict Bandwidth to 31.25Kbps" },
    { 0, NULL }
};
static const value_string midi_ump_stream_fb_dir[] = {
    { 1, "Input, Receive only" },
    { 2, "Output, Transmits only" },
    { 3, "Bidirectional Connection" },
    { 0, NULL }
};
static const value_string midi_ump_stream_fb_sysex8_count[] = {
    { 0, "SysEx8 Not Supported"},
    { 0, NULL }
};

static int* const midi2_program_options[] = {
    &hf_midi2_program_options_bank_valid,
    NULL
};
static int* const midi2_note_manage_fields[] = {
    &hf_midi2_note_manage_detach,
    &hf_midi2_note_manage_reset,
    NULL
};

static int* const midi_ump_stream_request_fields[] = {
    &hf_midi_ump_stream_request_e,
    &hf_midi_ump_stream_request_d,
    &hf_midi_ump_stream_request_n,
    &hf_midi_ump_stream_request_i,
    &hf_midi_ump_stream_request_s,
    NULL
};
static int* const midi_ump_stream_fb_disc_fields[] = {
    &hf_midi_ump_stream_fb_disc_info,
    &hf_midi_ump_stream_fb_disc_name,
    NULL
};



/* MIDI Universal Non-Realtime System Exclusive Messages (sysex-manu-id=0x7e) */
#define MIDI_SYSEX_NRT_SAMPLE_DUMP_HEADER     0x01
#define MIDI_SYSEX_NRT_SAMPLE_DATA_PACKET     0x02
#define MIDI_SYSEX_NRT_SAMPLE_DUMP_REQUEST    0x03
#define MIDI_SYSEX_NRT_MTC                    0x04
#define MIDI_SYSEX_NRT_SAMPLE_DUMP_EXTENSIONS 0x05
#define MIDI_SYSEX_NRT_GENERAL_INFORMATION    0x06
#define MIDI_SYSEX_NRT_FILE_DUMP              0x07
#define MIDI_SYSEX_NRT_MIDI_TUNING_STANDARD   0x08
#define MIDI_SYSEX_NRT_GENERAL_MIDI           0x09
#define MIDI_SYSEX_NRT_DOWNLOADABLE_SOUNDS    0x0a
#define MIDI_SYSEX_NRT_CAPABILITY_INQUIRY     0x0d
#define MIDI_SYSEX_NRT_END_OF_FILE            0x7b
#define MIDI_SYSEX_NRT_WAIT                   0x7c
#define MIDI_SYSEX_NRT_CANCEL                 0x7d
#define MIDI_SYSEX_NRT_NAK                    0x7e
#define MIDI_SYSEX_NRT_ACK                    0x7f
static const value_string midi_sysex_common_nrt[] = {
    { MIDI_SYSEX_NRT_SAMPLE_DUMP_HEADER,     "Sample Dump Header" },
    { MIDI_SYSEX_NRT_SAMPLE_DATA_PACKET,     "Sample Data Packet" },
    { MIDI_SYSEX_NRT_SAMPLE_DUMP_REQUEST,    "Sample Dump Request" },
    { MIDI_SYSEX_NRT_MTC,                    "MIDI Time Code (MTC)" },
    { MIDI_SYSEX_NRT_SAMPLE_DUMP_EXTENSIONS, "Sample Dump Extensions" },
    { MIDI_SYSEX_NRT_GENERAL_INFORMATION,    "General Information" },
    { MIDI_SYSEX_NRT_FILE_DUMP,              "File Dump" },
    { MIDI_SYSEX_NRT_MIDI_TUNING_STANDARD,   "Midi Tuning Standard" },
    { MIDI_SYSEX_NRT_GENERAL_MIDI,           "General MIDI (GM)" },
    { MIDI_SYSEX_NRT_DOWNLOADABLE_SOUNDS,    "Downloadable Sounds (DLS)" },
    { MIDI_SYSEX_NRT_CAPABILITY_INQUIRY,     "Capability Inquiry (MIDI-CI)" },
    { MIDI_SYSEX_NRT_END_OF_FILE,            "End Of File" },
    { MIDI_SYSEX_NRT_WAIT,                   "Wait" },
    { MIDI_SYSEX_NRT_CANCEL,                 "Cancel" },
    { MIDI_SYSEX_NRT_NAK,                    "NAK" },
    { MIDI_SYSEX_NRT_ACK,                    "ACK" },
    { 0, NULL }
};

/* MIDI Universal Realtime System Exclusive Messages (sysex-manu-id=0x7F) */
#define MIDI_SYSEX_RT_MIDI_TIME_CODE                0x01
#define MIDI_SYSEX_RT_MIDI_SHOW_CONTROL             0x02
#define MIDI_SYSEX_RT_NOTATION_INFORMATION          0x03
#define MIDI_SYSEX_RT_DEVICE_CONTROL                0x04
#define MIDI_SYSEX_RT_MTC_CUEING                    0x05
#define MIDI_SYSEX_RT_MIDI_MACHINE_CONTROL_COMMAND  0x06
#define MIDI_SYSEX_RT_MIDI_MACHINE_CONTROL_RESPONSE 0x07
#define MIDI_SYSEX_RT_MIDI_TUNING_STANDARD          0x08
static const value_string midi_sysex_common_rt[] = {
    { MIDI_SYSEX_RT_MIDI_TIME_CODE,                "MIDI Time Code (MTC)" },
    { MIDI_SYSEX_RT_MIDI_SHOW_CONTROL,             "MIDI Show Control" },
    { MIDI_SYSEX_RT_NOTATION_INFORMATION,          "Notation Information" },
    { MIDI_SYSEX_RT_DEVICE_CONTROL,                "Device Control" },
    { MIDI_SYSEX_RT_MTC_CUEING,                    "Real Time MTC Cueing" },
    { MIDI_SYSEX_RT_MIDI_MACHINE_CONTROL_COMMAND,  "MIDI Machine Control Command" },
    { MIDI_SYSEX_RT_MIDI_MACHINE_CONTROL_RESPONSE, "MIDI Machine Control Response" },
    { MIDI_SYSEX_RT_MIDI_TUNING_STANDARD,          "MIDI Tuning Standard" },
    { 0, NULL }
};

/* MIDI Time-Code Non-Realtime */
static const value_string midi_mtc_sysex_cue_nrt[] = {
    { 0x00, "Special" },
    { 0x01, "Punch In Points" },
    { 0x02, "Punch Out Points" },
    { 0x03, "Delete Punch In Points" },
    { 0x04, "Delete Punch Out Points" },
    { 0x05, "Event Start Point" },
    { 0x06, "Event Stop Point" },
    { 0x07, "Event Start Point with additional Info" },
    { 0x08, "Event Stop Point with additional Info" },
    { 0x09, "Delete Event Start Point" },
    { 0x0a, "Delete Event Stop Point" },
    { 0x0b, "Cue Points" },
    { 0x0c, "Cue Points with additional Info" },
    { 0x0d, "Delete Cue Point" },
    { 0x0e, "Event Name in additional Info" },
    { 0,                                NULL }
};

/* MIDI Time-Code Realtime */
static const value_string midi_mtc_sysex_cue_rt[] = {
    { 0x00, "Special" },
    { 0x01, "Punch In Points" },
    { 0x02, "Punch Out Points" },
    { 0x03, "(Reserved 0x03)" },
    { 0x04, "(Reserved 0x04)" },
    { 0x05, "Event Start Points" },
    { 0x06, "Event Stop Points" },
    { 0x07, "Event Start Points with additional Info" },
    { 0x08, "Event Stop Points with additional Info" },
    { 0x09, "(Reserved 0x09)" },
    { 0x0a, "(Reserved 0x0a)" },
    { 0x0b, "Cue Points" },
    { 0x0c, "Cue Points with additional Info" },
    { 0x0d, "(Reserved 0x0d)" },
    { 0x0e, "Event Name in additional Info" },
    { 0, NULL }
};

static const value_string midi_mtc_fm_type_values[] = {
    { 0, "24 Frames/Second" },
    { 1, "25 Frames/Second" },
    { 2, "30 Frames/Second (drop frame)" },
    { 3, "30 Frames/Second (non-drop frame)" },
    { 0, NULL }
};

static const value_string midi_mtc_qft_values[] = {
    { 0, "Frame count LS nibble" },
    { 1, "Frame count MS nibble" },
    { 2, "Seconds count LS nibble" },
    { 3, "Seconds count MS nibble" },
    { 4, "Minutes count LS nibble" },
    { 5, "Minutes count MS nibble" },
    { 6, "Hours count LS nibble" },
    { 7, "Hours count MS nibble" },
    { 0, NULL }
};

#define MIDI_SYSEX_COMMON_NRT_SD_EXT_LOOP_POINT_TRANSMISSION 0x01
#define MIDI_SYSEX_COMMON_NRT_SD_EXT_LOOP_POINTS_REQUEST     0x02
static const value_string midi_sysex_common_nrt_sd_ext[] = {
    { MIDI_SYSEX_COMMON_NRT_SD_EXT_LOOP_POINT_TRANSMISSION,    "Loop Point Transmission" },
    { MIDI_SYSEX_COMMON_NRT_SD_EXT_LOOP_POINTS_REQUEST,        "Loop Points Request" },
    { 0, NULL }
};

static const value_string midi_sysex_common_nrt_sd_loop_number[] = {
    { 0x7f7f, "Delete All Loops" },
    { 0, NULL }
};

static const value_string midi_sysex_common_nrt_sample_dump_loop_type[] = {
    { 0x00, "Forwards only (unidirectional)" },
    { 0x01, "Backwards/Forwards (bi-directional)" },
    { 0x7f, "Off" },
    { 0, NULL }
};

#define MIDI_SYSEX_COMMON_NRT_GI_IDENTITY_REQUEST 0x01
#define MIDI_SYSEX_COMMON_NRT_GI_IDENTITY_REPLY   0x02
static const value_string midi_sysex_common_nrt_gi[] = {
    { MIDI_SYSEX_COMMON_NRT_GI_IDENTITY_REQUEST, "Identity Request" },
    { MIDI_SYSEX_COMMON_NRT_GI_IDENTITY_REPLY,   "Identity Reply" },
    { 0, NULL }
};

#define MIDI_SYSEX_COMMON_NRT_FD_HEADER      0x01
#define MIDI_SYSEX_COMMON_NRT_FD_DATA_PACKET 0x02
#define MIDI_SYSEX_COMMON_NRT_FD_REQUEST     0x03
static const value_string midi_sysex_common_nrt_fd[] = {
    { MIDI_SYSEX_COMMON_NRT_FD_HEADER,      "Header" },
    { MIDI_SYSEX_COMMON_NRT_FD_DATA_PACKET, "Data Packet" },
    { MIDI_SYSEX_COMMON_NRT_FD_REQUEST,     "Request" },
    { 0, NULL }
};

#define MIDI_SYSEX_COMMON_TUNING_BULK_DUMP_REQUEST 0x00
#define MIDI_SYSEX_COMMON_TUNING_BULK_DUMP_REPLY   0x01
#define MIDI_SYSEX_COMMON_TUNING_NOTE_CHANGE       0x02
static const value_string midi_sysex_common_tuning[] = {
    { MIDI_SYSEX_COMMON_TUNING_BULK_DUMP_REQUEST, "Bulk Dump Request" },
    { MIDI_SYSEX_COMMON_TUNING_BULK_DUMP_REPLY,   "Bulk Dump Reply" },
    { MIDI_SYSEX_COMMON_TUNING_NOTE_CHANGE,       "Note Change" },
    { 0, NULL }
};

static const value_string midi_sysex_common_nrt_gm[] = {
    { 1, "General MIDI System On" },
    { 2, "General MIDI System Off" },
    { 0, NULL }
};

static const value_string midi_sysex_common_nrt_dls[] = {
    { 1, "DLS Level 1 On" },
    { 2, "DLS Level 1 Off" },
    { 3, "DLS Level 1 Voice Allocation Off" },
    { 4, "DLS Level 1 Voice Allocation On" },
    { 0, NULL }
};

#define MIDI_SYSEX_CI_PROF_INQ          0x20
#define MIDI_SYSEX_CI_PROF_INQ_REP      0x21
#define MIDI_SYSEX_CI_PROF_ON            0x22
#define MIDI_SYSEX_CI_PROF_OFF           0x23
#define MIDI_SYSEX_CI_PROF_ENABLED       0x24
#define MIDI_SYSEX_CI_PROF_DISABLED      0x25
#define MIDI_SYSEX_CI_PROF_ADDED         0x26
#define MIDI_SYSEX_CI_PROF_REMOVED       0x27
#define MIDI_SYSEX_CI_PROF_DETAILS       0x28
#define MIDI_SYSEX_CI_PROF_DETAILS_REP   0x29
#define MIDI_SYSEX_CI_PROF_SPECIFIC_DATA 0x2F
#define MIDI_SYSEX_CI_PROP_CAPABILITY     0x30
#define MIDI_SYSEX_CI_PROP_CAPABILITY_REP 0x31
#define MIDI_SYSEX_CI_PROP_HAS_DATA       0x32
#define MIDI_SYSEX_CI_PROP_HAS_DATA_REP   0x33
#define MIDI_SYSEX_CI_PROP_GET_DATA       0x34
#define MIDI_SYSEX_CI_PROP_GET_DATA_REP   0x35
#define MIDI_SYSEX_CI_PROP_SET_DATA       0x36
#define MIDI_SYSEX_CI_PROP_SET_DATA_REP   0x37
#define MIDI_SYSEX_CI_PROP_SUB            0x38
#define MIDI_SYSEX_CI_PROP_SUB_REP        0x39
#define MIDI_SYSEX_CI_PROP_NOTIFY         0x3F
#define MIDI_SYSEX_CI_PROC_CAPABILITIES       0x40
#define MIDI_SYSEX_CI_PROC_CAPABILITIES_REP   0x41
#define MIDI_SYSEX_CI_PROC_MESSAGE_REPORT     0x42
#define MIDI_SYSEX_CI_PROC_MESSAGE_REPORT_REP 0x43
#define MIDI_SYSEX_CI_PROC_MESSAGE_REPORT_END 0x44
#define MIDI_SYSEX_CI_DISC            0x70
#define MIDI_SYSEX_CI_DISC_REP        0x71
#define MIDI_SYSEX_CI_EP_INFO         0x72
#define MIDI_SYSEX_CI_EP_INFO_REP     0x73
#define MIDI_SYSEX_CI_ACK             0x7D
#define MIDI_SYSEX_CI_MUID_INVALIDATE 0x7E
#define MIDI_SYSEX_CI_NAK            0x7F
static const value_string midi_sysex_common_nrt_ci[] = {
    { 0x10, "DEPRECATED: Initiate Protocol Negotiation" },
    { 0x11, "DEPRECATED: Reply to Initiate Protocol Negotiation" },
    { 0x12, "DEPRECATED: Set New Selected Protocol" },
    { 0x13, "DEPRECATED: Test New Protocol Initiator to Responder" },
    { 0x14, "DEPRECATED: Test New Protocol Responder to Initiator" },
    { 0x15, "DEPRECATED: Confirmation Protocol Established" },

    { 0x20, "Profile Inquiry Initiator" },
    { 0x21, "Reply to Profile Inquiry Responder" },
    { 0x22, "Set Profile On Initiator" },
    { 0x23, "Set Profile Off Initiator" },
    { 0x24, "Profile Enabled Report Initiator or Responder" },
    { 0x25, "Profile Disabled Report Initiator or Responder" },
    { 0x26, "Profile Added Report Responder" },
    { 0x27, "Profile Removed Report Responder" },
    { 0x28, "Profile Details Inquiry Initiator" },
    { 0x29, "Reply to Profile Details Inquiry Responder" },
    { 0x2F, "Profile Specific Data Initiator or Responder" },

    { 0x30, "Inquiry: Property Exchange Capabilities Initiator" },
    { 0x31, "Reply to Property Exchange Capabilities Responder" },
    { 0x32, "Inquiry: Has Property Data (Reserved)" },
    { 0x33, "Reply to Has Property Data (Reserved)" },
    { 0x34, "Inquiry: Get Property Data Initiator" },
    { 0x35, "Reply to Get Property Data Responder" },
    { 0x36, "Inquiry: Set Property Data Initiator" },
    { 0x37, "Reply to Set Property Data Responder" },
    { 0x38, "Subscription Initiator or Responder" },
    { 0x39, "Reply to Subscription Initiator or Responder" },
    { 0x3F, "Notify Initiator or Responder" },

    { 0x40, "Inquiry: Process Inquiry Capabilities Initiator" },
    { 0x41, "Reply to Process Inquiry Capabilities Responder" },
    { 0x42, "Inquiry: MIDI Message Report Initiator" },
    { 0x43, "Reply to MIDI Message Report Responder" },
    { 0x44, "End of MIDI Message Report Responder" },

    { 0x70, "Discovery Initiator" },
    { 0x71, "Reply to Discovery Responder" },
    { 0x72, "Inquiry: Endpoint Information Initiator" },
    { 0x73, "Reply to Endpoint Information Responder" },
    { 0x7D, "MIDI-CI ACK Initiator or Responder" },
    { 0x7E, "Invalidate MUID Initiator or Responder" },
    { 0x7F, "MIDI-CI NAK" },
    { 0, NULL }
};

static const value_string midi_sysex_ci_muid[] = {
    { 0x0FFFFFFF, "Broadcast" },
    { 0, NULL }
};

static const value_string midi_sysex_ci_proc_message_data_control[] = {
    { 0x00, "No Data, Query capabilities" },
    { 0x01, "Non-Default Controllers" },
    { 0x7F, "Full Report" },
    { 0, NULL }
};
static const value_string midi_sysex_ci_ep_info_status[] = {
    { 0x00, "Product Instance ID" },
    { 0, NULL }
};
static const value_string midi_sysex_ci_ack_status_code[] = {
    { 0x00, "ACK" },
    { 0x10, "Timeout Wait" },
    { 0, NULL }
};
static const value_string midi_sysex_ci_nak_status_code[] = {
    { 0x00, "NAK" },
    { 0x01, "MIDI-CI message not supported" },
    { 0x02, "MIDI-CI version not supported" },
    { 0x03, "Channel/Group/Function Block Not in use" },
    { 0x04, "Profile not supported" },
    { 0x20, "Terminate Inquiry" },
    { 0x21, "Property Exchange Chunks out of sequence" },
    { 0x40, "Error occurred, please retry" },
    { 0x41, "Message was malformed" },
    { 0x42, "Timeout has occurred" },
    { 0x43, "Busy, try again" },
    { 0, NULL }
};

static int* const midi_sysex_ci_proc_supported_features[] = {
    &hf_midi_sysex_ci_proc_supported_features_msg_report,
    NULL
};
static int* const midi_sysex_ci_proc_requested_system_messages[] = {
    &hf_midi_sysex_ci_proc_requested_system_messages_mtc_qf,
    &hf_midi_sysex_ci_proc_requested_system_messages_song_pos,
    &hf_midi_sysex_ci_proc_requested_system_messages_song_sel,
    NULL
};
static int* const midi_sysex_ci_proc_requested_channel_messages[] = {
    &hf_midi_sysex_ci_proc_requested_channel_messages_pitch_bend,
    &hf_midi_sysex_ci_proc_requested_channel_messages_cc,
    &hf_midi_sysex_ci_proc_requested_channel_messages_rpn,
    &hf_midi_sysex_ci_proc_requested_channel_messages_nrpn,
    &hf_midi_sysex_ci_proc_requested_channel_messages_pc,
    &hf_midi_sysex_ci_proc_requested_channel_messages_pressure,
    NULL
};
static int* const midi_sysex_ci_proc_requested_note_messages[] = {
    &hf_midi_sysex_ci_proc_requested_note_messages_notes,
    &hf_midi_sysex_ci_proc_requested_note_messages_pressure,
    &hf_midi_sysex_ci_proc_requested_note_messages_pitch_bend,
    &hf_midi_sysex_ci_proc_requested_note_messages_registered_per_note,
    &hf_midi_sysex_ci_proc_requested_note_messages_assigned_per_note,
    NULL
};

static int* const midi_sysex_ci_supported_categories[] = {
    &hf_midi_sysex_ci_supported_categories_0,
    &hf_midi_sysex_ci_supported_categories_1,
    &hf_midi_sysex_ci_supported_categories_2,
    &hf_midi_sysex_ci_supported_categories_3,
    &hf_midi_sysex_ci_supported_categories_4,
    &hf_midi_sysex_ci_supported_categories_5,
    &hf_midi_sysex_ci_supported_categories_6,
    NULL
};

#define MIDI_SYSEX_COMMON_RT_MTC_FULL_MESSAGE 0x01
#define MIDI_SYSEX_COMMON_RT_MTC_USER_BITS    0x02
static const value_string midi_sysex_common_rt_mtc[] = {
    { MIDI_SYSEX_COMMON_RT_MTC_FULL_MESSAGE, "Full Message" },
    { MIDI_SYSEX_COMMON_RT_MTC_USER_BITS,    "User Bits" },
    { 0, NULL }
};

static const value_string midi_sysex_msc_command_format[] = {
    { 0x00, "Extensions" },
    { 0x01, "Lighting (General Category)" },
    { 0x02, "Moving Lights" },
    { 0x03, "Color Changers" },
    { 0x04, "Strobes" },
    { 0x05, "Lasers" },
    { 0x06, "Chasers" },
    { 0x10, "Sound (General Category)" },
    { 0x11, "Music" },
    { 0x12, "CD Players" },
    { 0x13, "EPROM Playback" },
    { 0x14, "Audio Tape Machine" },
    { 0x15, "Intercoms" },
    { 0x16, "Amplifiers" },
    { 0x17, "Audio Effects Devices" },
    { 0x18, "Equalizers" },
    { 0x20, "Machinery (General Category" },
    { 0x21, "Rigging" },
    { 0x22, "Flys" },
    { 0x23, "Lifts" },
    { 0x24, "Turntables" },
    { 0x25, "Trusses" },
    { 0x26, "Robots" },
    { 0x27, "Animation" },
    { 0x28, "Floats" },
    { 0x29, "Breakaways" },
    { 0x2a, "Barges" },
    { 0x30, "Video (General Category" },
    { 0x31, "Video Tape Machines" },
    { 0x32, "Video Cassette Machines" },
    { 0x33, "Video Disc Players" },
    { 0x34, "Video Switchers" },
    { 0x35, "Video Effects" },
    { 0x36, "Video Character Generators" },
    { 0x37, "Video Still Stores" },
    { 0x38, "Video Monitors" },
    { 0x40, "Projections (General)" },
    { 0x41, "Film Projectors" },
    { 0x42, "Slide Projectors" },
    { 0x43, "Video Projectors" },
    { 0x44, "Dissolvers" },
    { 0x45, "Shutter Controls" },
    { 0x50, "Process Control (General)" },
    { 0x51, "Hydraulic Oil" },
    { 0x52, "H2O" },
    { 0x53, "CO2" },
    { 0x54, "Compressed Air" },
    { 0x55, "Natural Gas" },
    { 0x56, "Fog" },
    { 0x57, "Smoke" },
    { 0x58, "Cracked Haze" },
    { 0x60, "Pyro (General Category)" },
    { 0x61, "Fireworks" },
    { 0x62, "Explosions" },
    { 0x63, "Flame" },
    { 0x64, "Smoke Pots" },
    { 0x7f, "All Types" },
    { 0,    NULL }
};
static value_string_ext midi_sysex_msc_command_format_ext =
    VALUE_STRING_EXT_INIT(midi_sysex_msc_command_format);

#define MIDI_SYSEX_MSC_COMMAND_EXTENSIONS     0x00
#define MIDI_SYSEX_MSC_COMMAND_GO             0x01
#define MIDI_SYSEX_MSC_COMMAND_STOP           0x02
#define MIDI_SYSEX_MSC_COMMAND_RESUME         0x03
#define MIDI_SYSEX_MSC_COMMAND_TIMED_GO       0x04
#define MIDI_SYSEX_MSC_COMMAND_LOAD           0x05
#define MIDI_SYSEX_MSC_COMMAND_SET            0x06
#define MIDI_SYSEX_MSC_COMMAND_FIRE           0x07
#define MIDI_SYSEX_MSC_COMMAND_ALL_OFF        0x08
#define MIDI_SYSEX_MSC_COMMAND_RESTORE        0x09
#define MIDI_SYSEX_MSC_COMMAND_RESET          0x0A
#define MIDI_SYSEX_MSC_COMMAND_GO_OFF         0x0B
#define MIDI_SYSEX_MSC_COMMAND_GO_JAM_CLOCK   0x10
#define MIDI_SYSEX_MSC_COMMAND_STANDBY_PLUS   0x11
#define MIDI_SYSEX_MSC_COMMAND_STANDBY_MINUS  0x12
#define MIDI_SYSEX_MSC_COMMAND_SEQUENCE_PLUS  0x13
#define MIDI_SYSEX_MSC_COMMAND_SEQUENCE_MINUS 0x14
#define MIDI_SYSEX_MSC_COMMAND_START_CLOCK    0x15
#define MIDI_SYSEX_MSC_COMMAND_STOP_CLOCK     0x16
#define MIDI_SYSEX_MSC_COMMAND_ZERO_CLOCK     0x17
#define MIDI_SYSEX_MSC_COMMAND_SET_CLOCK      0x18
#define MIDI_SYSEX_MSC_COMMAND_MTC_CHASE_ON   0x19
#define MIDI_SYSEX_MSC_COMMAND_MTC_CHASE_OFF  0x1A
#define MIDI_SYSEX_MSC_COMMAND_OPEN_CUE_LIST  0x1B
#define MIDI_SYSEX_MSC_COMMAND_CLOSE_CUE_LIST 0x1C
#define MIDI_SYSEX_MSC_COMMAND_OPEN_CUE_PATH  0x1D
#define MIDI_SYSEX_MSC_COMMAND_CLOSE_CUE_PATH 0x1E
#define MIDI_SYSEX_MSC_COMMAND_STANDBY        0x20
#define MIDI_SYSEX_MSC_COMMAND_STANDING_BY    0x21
#define MIDI_SYSEX_MSC_COMMAND_GO_2PC         0x22
#define MIDI_SYSEX_MSC_COMMAND_COMPLETE       0x23
#define MIDI_SYSEX_MSC_COMMAND_CANCEL         0x24
#define MIDI_SYSEX_MSC_COMMAND_CANCELLED      0x25
#define MIDI_SYSEX_MSC_COMMAND_ABORT          0x26
static const value_string midi_sysex_msc_command[] = {
    { MIDI_SYSEX_MSC_COMMAND_EXTENSIONS,     "Extensions" },
    { MIDI_SYSEX_MSC_COMMAND_GO,             "GO" },
    { MIDI_SYSEX_MSC_COMMAND_STOP,           "STOP" },
    { MIDI_SYSEX_MSC_COMMAND_RESUME,         "RESUME" },
    { MIDI_SYSEX_MSC_COMMAND_TIMED_GO,       "TIMED_GO" },
    { MIDI_SYSEX_MSC_COMMAND_LOAD,           "LOAD" },
    { MIDI_SYSEX_MSC_COMMAND_SET,            "SET" },
    { MIDI_SYSEX_MSC_COMMAND_FIRE,           "FIRE" },
    { MIDI_SYSEX_MSC_COMMAND_ALL_OFF,        "ALL_OFF" },
    { MIDI_SYSEX_MSC_COMMAND_RESTORE,        "RESTORE" },
    { MIDI_SYSEX_MSC_COMMAND_RESET,          "RESET" },
    { MIDI_SYSEX_MSC_COMMAND_GO_OFF,         "GO_OFF" },
    { MIDI_SYSEX_MSC_COMMAND_GO_JAM_CLOCK,   "GO/JAM_CLOCK" },
    { MIDI_SYSEX_MSC_COMMAND_STANDBY_PLUS,   "STANDBY_+" },
    { MIDI_SYSEX_MSC_COMMAND_STANDBY_MINUS,  "STANDBY_-" },
    { MIDI_SYSEX_MSC_COMMAND_SEQUENCE_PLUS,  "SEQUENCE_+" },
    { MIDI_SYSEX_MSC_COMMAND_SEQUENCE_MINUS, "SEQUENCE_-" },
    { MIDI_SYSEX_MSC_COMMAND_START_CLOCK,    "START_CLOCK" },
    { MIDI_SYSEX_MSC_COMMAND_STOP_CLOCK,     "STOP_CLOCK" },
    { MIDI_SYSEX_MSC_COMMAND_ZERO_CLOCK,     "ZERO_CLOCK" },
    { MIDI_SYSEX_MSC_COMMAND_SET_CLOCK,      "SET_CLOCK" },
    { MIDI_SYSEX_MSC_COMMAND_MTC_CHASE_ON,   "MTC_CHASE_ON" },
    { MIDI_SYSEX_MSC_COMMAND_MTC_CHASE_OFF,  "MTC_CHASE_OFF" },
    { MIDI_SYSEX_MSC_COMMAND_OPEN_CUE_LIST,  "OPEN_CUE_LIST" },
    { MIDI_SYSEX_MSC_COMMAND_CLOSE_CUE_LIST, "CLOSE_CUE_LIST" },
    { MIDI_SYSEX_MSC_COMMAND_OPEN_CUE_PATH,  "OPEN_CUE_PATH" },
    { MIDI_SYSEX_MSC_COMMAND_CLOSE_CUE_PATH, "CLOSE_CUE_PATH" },
    { MIDI_SYSEX_MSC_COMMAND_STANDBY,        "STANDBY" },
    { MIDI_SYSEX_MSC_COMMAND_STANDING_BY,    "STANDING_BY" },
    { MIDI_SYSEX_MSC_COMMAND_GO_2PC,         "GO_2PC" },
    { MIDI_SYSEX_MSC_COMMAND_COMPLETE,       "COMPLETE" },
    { MIDI_SYSEX_MSC_COMMAND_CANCEL,         "CANCEL" },
    { MIDI_SYSEX_MSC_COMMAND_CANCELLED,      "CANCELLED" },
    { MIDI_SYSEX_MSC_COMMAND_ABORT,          "ABORT" },
    { 0, NULL }
};

static const range_string midi_sysex_msc_generic_controllers[] = {
    { 0,   127, "Sub master" },
    { 128, 191, "Playback master" },
    { 192, 223, "Playback speed controller" },
    { 224, 255, "Chase sequence master" },
    { 256, 287, "Chase sequence speed master" },
    { 510, 510, "Grand Master fader" },
    { 511, 511, "General speed controller" },
    { 512, 1023, "Individual channel level" },
    { 0, 0, NULL }
};

/* NB: manual override commands are kinda wrong because they are the
 * only ones that differ between cancel and abort messages, and I don't
 * want to handle that difference
 */
#define MIDI_SYSEX_MSC_STATUS_CODES_DEFAULT \
    { 0x0000, "unknown/undefined error" }, \
    { 0x8000, "checksum error" }, \
    { 0x8004, "completing" }, \
    { 0x8008, "paused" }, \
    { 0x800C, "terminated" }, \
    { 0x8010, "reversed" }, \
    { 0x8020, "timeout" }, \
    { 0x8024, "not standing by" }, \
    { 0x8028, "manual override initiated" }, \
    { 0x8030, "manual override in progress" }, \
    { 0x8040, "deadman interlock not established" }, \
    { 0x8044, "required safety interlock not established" }, \
    { 0x8050, "unknown <Q_number>" }, \
    { 0x8054, "unknown <Q_list>" }, \
    { 0x8058, "unknown <Q_path>" }, \
    { 0x805C, "too many cues active" }, \
    { 0x8060, "cue out of sequence" }, \
    { 0x8064, "invalid d1 cue data value" }, \
    { 0x8068, "invalid d2 cue data value" }, \
    { 0x806C, "invalid d3 cue data value" }, \
    { 0x8070, "invalid d4 cue data value" }, \
    { 0x8090, "manual cueing of playback medium required" }, \
    { 0x80A0, "power failure in controlled device subsystem" }, \
    { 0x80B0, "reading new show cues from disk" },
static const value_string midi_sysex_msc_status_codes_lighting[] = {
    MIDI_SYSEX_MSC_STATUS_CODES_DEFAULT
    { 0x1004, "position motor failure" },
    { 0x1008, "scroller motor failure" },
    { 0x100C, "strobe not charged" },
    { 0x1010, "laser safety interlock not established" },
    { 0, NULL }
};
static const value_string midi_sysex_msc_status_codes_sound[] = {
    MIDI_SYSEX_MSC_STATUS_CODES_DEFAULT
    { 0x1004, "amplifier failure" },
    { 0x1008, "amplifier overload" },
    { 0, NULL }
};
static const value_string midi_sysex_msc_status_codes_machinery[] = {
    MIDI_SYSEX_MSC_STATUS_CODES_DEFAULT
    { 0x1004, "motor failure" },
    { 0x1008, "limit switch inhibiting movement" },
    { 0x100C, "unequal movement in multiple section system" },
    { 0x1010, "servo failure" },
    { 0, NULL }
};
static const value_string midi_sysex_msc_status_codes_video[] = {
    MIDI_SYSEX_MSC_STATUS_CODES_DEFAULT
    { 0x1004, "sync lost" },
    { 0x1008, "time code lost" },
    { 0, NULL }
};
static const value_string midi_sysex_msc_status_codes_projection[] = {
    MIDI_SYSEX_MSC_STATUS_CODES_DEFAULT
    { 0x1004, "film tension lost" },
    { 0x1008, "lamp failure" },
    { 0, NULL }
};
static const value_string midi_sysex_msc_status_codes_process_control[] = {
    MIDI_SYSEX_MSC_STATUS_CODES_DEFAULT
    { 0x1004, "hydraulic oil low" },
    { 0x1008, "water low" },
    { 0x100C, "carbon dioxide low" },
    { 0x1010, "excess gas detected" },
    { 0x1014, "gas pilot out" },
    { 0x1018, "improper gas ignition conditions (windy)" },
    { 0x101C, "smoke/fog fluid low" },
    { 0x1104, "invalid switch number" },
    { 0x1108, "latch setting system inoperative" },
    { 0x1204, "burned out cue light" },
    { 0, NULL }
};
static const value_string midi_sysex_msc_status_codes_pyrotechnics[] = {
    MIDI_SYSEX_MSC_STATUS_CODES_DEFAULT
    { 0x1004, "charge not loaded" },
    { 0x1008, "atmospheric conditions prohibit discharge" },
    { 0, NULL }
};

static const true_false_string tfs_midi_sysex_msc_tc_colour = {"colour framed code", "non colour frame"};
static const true_false_string tfs_midi_sysex_msc_tc_sign = {"negative", "positive"};
static const true_false_string tfs_midi_sysex_msc_tc_final_byte = {"status", "subframes"};
static const true_false_string tfs_midi_sysex_msc_tc_stat_est = {"tach or control track updated code", "normal time code"};
static const true_false_string tfs_midi_sysex_msc_tc_stat_video = {"first frame in 4 or 8 field video sequence", "no field information in this frame"};

#define MIDI_SYSEX_COMMON_RT_NT_BAR_NUMBER                0x01
#define MIDI_SYSEX_COMMON_RT_NT_TIME_SIGNATURE_IMMEDIATE  0x02
#define MIDI_SYSEX_COMMON_RT_NT_TIME_SIGNATURE_DELAYED    0x42
static const value_string midi_sysex_common_rt_notations[] = {
    { MIDI_SYSEX_COMMON_RT_NT_BAR_NUMBER,               "Bar Number" },
    { MIDI_SYSEX_COMMON_RT_NT_TIME_SIGNATURE_IMMEDIATE, "Time Signature (Immediate)" },
    { MIDI_SYSEX_COMMON_RT_NT_TIME_SIGNATURE_DELAYED,   "Time Signature (Delayed)" },
    { 0, NULL }
};

#define MIDI_SYSEX_COMMON_RT_DC_MASTER_VOLUME  0x01
#define MIDI_SYSEX_COMMON_RT_DC_MASTER_BALANCE 0x02
static const value_string midi_sysex_common_rt_device_control[] = {
    { MIDI_SYSEX_COMMON_RT_DC_MASTER_VOLUME,  "Master Volume" },
    { MIDI_SYSEX_COMMON_RT_DC_MASTER_BALANCE, "Master Balance" },
    { 0, NULL }
};

static const value_string midi_sysex_common_rt_mmc_commands[] = {
    { 0x00, "reserved for extensions" },
    { 0x01, "STOP" },
    { 0x02, "PLAY" },
    { 0x03, "DEFERRED PLAY" },
    { 0x04, "FAST FORWARD" },
    { 0x05, "REWIND" },
    { 0x06, "RECORD STROBE" },
    { 0x07, "RECORD EXIT" },
    { 0x08, "RECORD PAUSE" },
    { 0x09, "PAUSE" },
    { 0x0A, "EJECT" },
    { 0x0B, "CHASE" },
    { 0x0C, "COMMAND ERROR RESET" },
    { 0x0D, "MMC RESET" },

    { 0x40, "WRITE" },
    { 0x41, "MASKED WRITE" },
    { 0x42, "READ" },
    { 0x43, "UPDATE" },
    { 0x44, "LOCATE" },
    { 0x45, "VARIABLE PLAY" },
    { 0x46, "SEARCH" },
    { 0x47, "SHUTTLE" },
    { 0x48, "STEP" },
    { 0x49, "ASSIGN SYSTEM MASTER" },
    { 0x4A, "GENERATOR COMMAND" },
    { 0x4B, "MIDI TIME CODE COMMAND" },
    { 0x4C, "MOVE" },
    { 0x4D, "ADD" },
    { 0x4E, "SUBTRACT" },
    { 0x4F, "DROP FRAME ADJUST" },
    { 0x50, "PROCEDURE" },
    { 0x51, "EVENT" },
    { 0x52, "GROUP" },
    { 0x53, "COMMAND SEGMENT" },
    { 0x54, "DEFERRED VARIABLE PLAY" },
    { 0x55, "RECORD STROBE VARIABLE" },

    { 0x7C, "WAIT" },
    { 0x7F, "RESUME" },
    { 0,    NULL }
};

static const value_string midi_sysex_common_rt_mmc_responses[] = {
    { 0x00, "reserved for extensions" },
    { 0x01, "SELECTED TIME CODE" },
    { 0x02, "SELECTED MASTER CODE" },
    { 0x03, "REQUESTED OFFSET" },
    { 0x04, "ACTUAL OFFSET" },
    { 0x05, "LOCK DEVIATION" },
    { 0x06, "GENERATOR TIME CODE" },
    { 0x07, "MIDI TIME CODE INPUT" },
    { 0x08, "GP0/LOCATE POINT" },
    { 0x09, "GP1" },
    { 0x0A, "GP2" },
    { 0x0B, "GP3" },
    { 0x0C, "GP4" },
    { 0x0D, "GP5" },
    { 0x0E, "GP6" },
    { 0x0F, "GP7" },

    { 0x21, "Short SELECTED TIME CODE" },
    { 0x22, "Short SELECTED MASTER CODE" },
    { 0x23, "Short REQUESTED OFFSET" },
    { 0x24, "Short ACTUAL OFFSET" },
    { 0x25, "Short LOCK DEVIATION" },
    { 0x26, "Short GENERATOR TIME CODE" },
    { 0x27, "Short MIDI TIME CODE INPUT" },
    { 0x28, "Short GP0/LOCATE POINT" },
    { 0x29, "Short GP1" },
    { 0x2A, "Short GP2" },
    { 0x2B, "Short GP3" },
    { 0x2C, "Short GP4" },
    { 0x2D, "Short GP5" },
    { 0x2E, "Short GP6" },
    { 0x2F, "Short GP7" },

    { 0x40, "SIGNATURE" },
    { 0x41, "UPDATE RATE" },
    { 0x42, "RESPONSE ERROR" },
    { 0x43, "COMMAND ERROR" },
    { 0x44, "COMMAND ERROR LEVEL" },
    { 0x45, "TIME STANDARD" },
    { 0x46, "SELECTED TIME CODE SOURCE" },
    { 0x47, "SELECTED TIME CODE USERBITS" },
    { 0x48, "MOTION CONTROL TALLY" },
    { 0x49, "VELOCITY TALLY" },
    { 0x4A, "STOP MODE" },
    { 0x4B, "FAST MODE" },
    { 0x4C, "RECORD MODE" },
    { 0x4D, "RECORD STATUS" },
    { 0x4E, "TRACK RECORD STATUS" },
    { 0x4F, "TRACK RECORD READY" },
    { 0x50, "GLOBAL MONITOR" },
    { 0x51, "RECORD MONITOR" },
    { 0x52, "TRACK SYNC MONITOR" },
    { 0x53, "TRACK INPUT MONITOR" },
    { 0x54, "STEP LENGTH" },
    { 0x55, "PLAY SPEED REFERENCE" },
    { 0x56, "FIXED SPEED" },
    { 0x57, "LIFTER DEFEAT" },
    { 0x58, "CONTROL DISABLE" },
    { 0x59, "RESOLVED PLAY MODE" },
    { 0x5A, "CHASE MODE" },
    { 0x5B, "GENERATOR COMMAND TALLY" },
    { 0x5C, "GENERATOR SETUP" },
    { 0x5D, "GENERATOR USERBITS" },
    { 0x5E, "MIDI TIME CODE COMMAND TALLY" },
    { 0x5F, "MIDI TIME CODE SETUP" },
    { 0x60, "PROCEDURE RESPONSE" },
    { 0x61, "EVENT RESPONSE" },
    { 0x62, "TRACK MUTE" },
    { 0x63, "VITC INSERT ENABLE" },
    { 0x64, "RESPONSE SEGMENT" },
    { 0x65, "FAILURE" },

    { 0x7C, "WAIT" },
    { 0x7F, "RESUME" },
    { 0,    NULL }
};




static proto_item *
proto_tree_midi_14bit(proto_tree *tree, int hfindex, tvbuff_t *tvb, const unsigned start, uint16_t* retval) {
    /* MIDI fields are all LSB first */
    uint16_t v = tvb_get_uint16(tvb, start, ENC_LITTLE_ENDIAN);
    /* Do the shuffle */
    v = (v&0x7F) | ((v&0x7F00) >> 1);
    proto_item* pi = proto_tree_add_uint(tree, hfindex, tvb, start, 2, v);

    if (retval != NULL) {
        *retval = v;
    }

    return pi;
}

static proto_item *
proto_tree_midi_21bit(proto_tree *tree, int hfindex, tvbuff_t *tvb, const unsigned start, uint32_t* retval) {
    /* MIDI fields are all LSB first */
    uint32_t v = tvb_get_uint24(tvb, start, ENC_LITTLE_ENDIAN);
    /* Do the shuffle */
    v = (v&0x7F) | ((v&0x7F00) >> 1) | ((v&0x7F0000) >> 2);
    proto_item* pi = proto_tree_add_uint(tree, hfindex, tvb, start, 3, v);

    if (retval != NULL) {
        *retval = v;
    }

    return pi;
}

static proto_item *
proto_tree_midi_28bit(proto_tree *tree, int hfindex, tvbuff_t *tvb, const unsigned start, uint32_t* retval) {
    /* MIDI fields are all LSB first */
    uint32_t v = tvb_get_uint32(tvb, start, ENC_LITTLE_ENDIAN);
    /* Do the shuffle */
    v = (v&0x7F) | ((v&0x7F00) >> 1) | ((v&0x7F0000) >> 2) | ((v&0x7F000000) >> 3);
    proto_item* pi = proto_tree_add_uint(tree, hfindex, tvb, start, 4, v);

    if (retval != NULL) {
        *retval = v;
    }

    return pi;
}


/* SysEx-Common Non-Realtime Sample Dump Header */
static unsigned int
dissect_sysex7_common_nrt_sample_dump_hdr(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    proto_tree_midi_14bit(tree, hf_midi_sysex_sample_dump_sample_number, tvb, offset, NULL);
    offset += 2;
    proto_tree_add_item(tree, hf_midi_sysex_sample_dump_sample_format, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_midi_21bit(tree, hf_midi_sysex_sample_dump_sample_period, tvb, offset, NULL);
    offset += 3;
    proto_tree_midi_21bit(tree, hf_midi_sysex_sample_dump_sample_length, tvb, offset, NULL);
    offset += 3;
    proto_tree_midi_21bit(tree, hf_midi_sysex_sample_dump_loop_start, tvb, offset, NULL);
    offset += 3;
    proto_tree_midi_21bit(tree, hf_midi_sysex_sample_dump_loop_end, tvb, offset, NULL);
    offset += 3;
    proto_tree_add_item(tree, hf_midi_sysex_sample_dump_loop_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

/* SysEx-Common Non-Realtime Sample Dump Data Packet */
static unsigned int
dissect_sysex7_common_nrt_sample_dump_data(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, unsigned int offset) {
    proto_tree_add_item(tree, hf_midi_sysex_sample_dump_packet_count, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_midi_sysex_sample_dump_packet_data, tvb, offset, 120, ENC_NA);
    offset += 120;
    proto_tree_add_checksum(tree, tvb, offset, hf_midi_sysex_sample_dump_packet_check, -1, NULL, pinfo, 0, ENC_NA, PROTO_CHECKSUM_NO_FLAGS);
    offset++;

    return offset;
}

/* SysEx-Common Non-Realtime Sample Dump Request */
static unsigned int
dissect_sysex7_common_nrt_sample_dump_req(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    proto_tree_midi_14bit(tree, hf_midi_sysex_sample_dump_sample_number, tvb, offset, NULL);
    offset += 2;
    return offset;
}

/* SysEx-Common Non-Realtime Sample Dump Extension */
static unsigned int
dissect_sysex7_common_nrt_sample_dump_ext(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    uint8_t sub_id;
    proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_sample_dump_ext_msg_type, tvb, offset, 1, ENC_NA, &sub_id);
    offset += 1;

    if (sub_id == MIDI_SYSEX_COMMON_NRT_SD_EXT_LOOP_POINT_TRANSMISSION) {
        proto_tree_midi_14bit(tree, hf_midi_sysex_sample_dump_sample_number, tvb, offset, NULL);
        offset += 2;
        proto_tree_midi_14bit(tree, hf_midi_sysex_sample_dump_ext_loop_number, tvb, offset, NULL);
        offset += 2;
        proto_tree_add_item(tree, hf_midi_sysex_sample_dump_loop_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_midi_21bit(tree, hf_midi_sysex_sample_dump_loop_start, tvb, offset, NULL);
        offset += 3;
        proto_tree_midi_21bit(tree, hf_midi_sysex_sample_dump_loop_end, tvb, offset, NULL);
        offset += 3;
    } else if (sub_id == MIDI_SYSEX_COMMON_NRT_SD_EXT_LOOP_POINTS_REQUEST) {
        proto_tree_midi_14bit(tree, hf_midi_sysex_sample_dump_sample_number, tvb, offset, NULL);
        offset += 2;
        proto_tree_midi_14bit(tree, hf_midi_sysex_sample_dump_ext_loop_number, tvb, offset, NULL);
        offset += 2;
    }

    return offset;
}

/* SysEx-Common Non-Realtime General Information */
static unsigned int
dissect_sysex7_common_nrt_gen_info(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    uint8_t sub_id;
    proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_gen_info_msg_type, tvb, offset, 1, ENC_NA, &sub_id);
    offset++;

    if (sub_id == MIDI_SYSEX_COMMON_NRT_GI_IDENTITY_REQUEST) {
        /* nothing more to do... */
    } else if (sub_id == MIDI_SYSEX_COMMON_NRT_GI_IDENTITY_REPLY) {
        uint8_t manu_short;

        proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_manu_short, tvb, offset, 1, ENC_NA, &manu_short);
        offset++;
        if (manu_short == 0) {
            proto_tree_midi_14bit(tree, hf_midi_sysex_manu_long, tvb, offset, NULL);
            offset += 2;
        }

        proto_tree_midi_14bit(tree, hf_midi_sysex_gen_info_device_family, tvb, offset, NULL);
        offset += 2;
        proto_tree_midi_14bit(tree, hf_midi_sysex_gen_info_family_member, tvb, offset, NULL);
        offset += 2;
        proto_tree_midi_28bit(tree, hf_midi_sysex_gen_info_software_rev, tvb, offset, NULL);
        offset += 4;
    }

    return offset;
}

/* SysEx-Common Non-Realtime File Dump */
static unsigned int
dissect_sysex7_common_nrt_file_dump(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, unsigned int offset) {
    uint8_t sub_id;
    proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_file_dump_msg_type, tvb, offset, 1, ENC_NA, &sub_id);
    offset++;

    if (sub_id == MIDI_SYSEX_COMMON_NRT_FD_REQUEST) {
        proto_tree_add_item(tree, hf_midi_sysex_file_dump_device_id, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_file_dump_file_type, tvb, offset, 4, ENC_ASCII);
        offset += 4;
        if (tvb_reported_length_remaining(tvb, offset)) {
            unsigned int len;
            proto_tree_add_item_ret_length(tree, hf_midi_sysex_file_dump_file_name, tvb, offset, -1, ENC_ASCII, &len);
            offset += len;
        }
    } else if (sub_id == MIDI_SYSEX_COMMON_NRT_FD_HEADER) {
        proto_tree_add_item(tree, hf_midi_sysex_file_dump_device_id, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_file_dump_file_type, tvb, offset, 4, ENC_ASCII);
        offset += 4;
        proto_tree_midi_28bit(tree, hf_midi_sysex_file_dump_file_length, tvb, offset, NULL);
        offset += 4;
        if (tvb_reported_length_remaining(tvb, offset)) {
            unsigned int len;
            proto_tree_add_item_ret_length(tree, hf_midi_sysex_file_dump_file_name, tvb, offset, -1, ENC_ASCII, &len);
            offset += len;
        }
    } else if (sub_id == MIDI_SYSEX_COMMON_NRT_FD_DATA_PACKET) {
        proto_tree_add_item(tree, hf_midi_sysex_file_dump_packet_num, tvb, offset, 1, ENC_NA);
        offset++;
        /* This is the number of bytes actually transmitted on the wire
         * There is a rather complex encoding scheme, but we don't need to worry about that.
         */
        uint8_t byte_count;
        proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_file_dump_byte_count, tvb, offset, 1, ENC_NA, &byte_count);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_file_dump_packet_data, tvb, offset, byte_count + 1, ENC_NA);
        offset += byte_count + 1;
        proto_tree_add_checksum(tree, tvb, offset, hf_midi_sysex_file_dump_checksum, -1, NULL, pinfo, 0, ENC_NA, PROTO_CHECKSUM_NO_FLAGS);
        offset++;
    }

    return offset;
}

/* SysEx-Common (Non-)Realtime MIDI Tuning Standard
 * As the code-points do not overlap, both RT and NRT are decoded here.
 */
static unsigned int
dissect_sysex7_common_tuning(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned int offset) {
    const char* note_str;
    proto_tree* note_tree;

    uint8_t sub_id;
    proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_tuning_msg_type, tvb, offset, 1, ENC_NA, &sub_id);
    offset++;

    if (sub_id == MIDI_SYSEX_COMMON_TUNING_BULK_DUMP_REQUEST) {
        proto_tree_add_item(tree, hf_midi_sysex_tuning_program, tvb, offset, 1, ENC_NA);
        offset++;
    } else if (sub_id == MIDI_SYSEX_COMMON_TUNING_BULK_DUMP_REPLY) {
        proto_tree_add_item(tree, hf_midi_sysex_tuning_program, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_tuning_name, tvb, offset, 16, ENC_ASCII);
        offset += 16;
        for (int i = 0; i < 128; i++) {
            note_str = val_to_str_ext_const(i, &midi_note_values_ext, "");
            note_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3, ett_midi_sysex_common_tune_note, NULL, "Note: %s", note_str);
            proto_tree_midi_21bit(note_tree, hf_midi_sysex_tuning_freq, tvb, offset, NULL);
            offset += 3;
        }

        proto_tree_add_checksum(tree, tvb, offset, hf_midi_sysex_tuning_checksum, -1, NULL, pinfo, 0, ENC_NA, PROTO_CHECKSUM_NO_FLAGS);
        offset++;
    } else if (sub_id == MIDI_SYSEX_COMMON_TUNING_NOTE_CHANGE) {
        proto_tree_add_item(tree, hf_midi_sysex_tuning_program, tvb, offset, 1, ENC_NA);
        offset++;

        uint8_t changes;
        proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_tuning_change_count, tvb, offset, 1, ENC_NA, &changes);
        offset++;

        for (int i = 0; i < changes; i++) {
            uint8_t note = tvb_get_uint8(tvb, offset) & 0x7F;
            note_str = val_to_str_ext_const(note, &midi_note_values_ext, "");
            note_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3, ett_midi_sysex_common_tune_note, NULL, "Note: %s", note_str);

            proto_tree_add_item(note_tree, hf_midi_sysex_common_tune_note, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_midi_21bit(note_tree, hf_midi_sysex_tuning_freq, tvb, offset, NULL);
            offset += 3;
        }
    }

    return offset;
}

/* SysEx-Common Non-Realtime General MIDI */
static unsigned int
dissect_sysex7_common_nrt_gen_midi(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    proto_tree_add_item(tree, hf_midi_sysex_gen_midi_on_off, tvb, offset, 1, ENC_NA);
    offset += 1;
    return offset;
}

/* SysEx-Common Non-Realtime Downloadable Sounds */
static unsigned int
dissect_sysex7_common_nrt_dls(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    proto_tree_add_item(tree, hf_midi_sysex_downloadable_sounds_msg_type, tvb, offset, 1, ENC_NA);
    offset++;
    return offset;
}


static unsigned int
dissect_sysex7_common_nrt_ci_prof(tvbuff_t *tvb, proto_tree *tree, unsigned int offset, uint8_t msg_type) {
    uint16_t len;
    switch (msg_type) {
        case MIDI_SYSEX_CI_PROF_INQ:
            break;
        case MIDI_SYSEX_CI_PROF_INQ_REP:
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_prof_count_enabled, tvb, offset, &len);
            offset += 2;
            for (int i = 0; i < len; i++) {
                proto_tree_add_item(tree, hf_midi_sysex_ci_prof_id, tvb, offset, 5, ENC_NA);
                offset += 5;
            }
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_prof_count_disabled, tvb, offset, &len);
            offset += 2;
            for (int i = 0; i < len; i++) {
                proto_tree_add_item(tree, hf_midi_sysex_ci_prof_id, tvb, offset, 5, ENC_NA);
                offset += 5;
            }
            break;
        case MIDI_SYSEX_CI_PROF_ON:
        case MIDI_SYSEX_CI_PROF_ENABLED:
        case MIDI_SYSEX_CI_PROF_DISABLED:
            proto_tree_add_item(tree, hf_midi_sysex_ci_prof_id, tvb, offset, 5, ENC_NA);
            offset += 5;
            if (tvb_reported_length_remaining(tvb, offset)) {
                proto_tree_midi_14bit(tree, hf_midi_sysex_ci_prof_chans, tvb, offset, NULL);
                offset += 2;
            }
            break;
        case MIDI_SYSEX_CI_PROF_OFF:
            proto_tree_add_item(tree, hf_midi_sysex_ci_prof_id, tvb, offset, 5, ENC_NA);
            offset += 5;
            if (tvb_reported_length_remaining(tvb, offset)) {
                proto_tree_add_item(tree, hf_midi_sysex_ci_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;
            }
            break;
        case MIDI_SYSEX_CI_PROF_ADDED:
        case MIDI_SYSEX_CI_PROF_REMOVED:
            proto_tree_add_item(tree, hf_midi_sysex_ci_prof_id, tvb, offset, 5, ENC_NA);
            offset += 5;
            break;
        case MIDI_SYSEX_CI_PROF_DETAILS:
        case MIDI_SYSEX_CI_PROF_DETAILS_REP:
            proto_tree_add_item(tree, hf_midi_sysex_ci_prof_id, tvb, offset, 5, ENC_NA);
            offset += 5;
            proto_tree_add_item(tree, hf_midi_sysex_ci_prof_inquiry_target, tvb, offset, 1, ENC_NA);
            offset += 1;
            if (msg_type == MIDI_SYSEX_CI_PROF_DETAILS_REP) {
                proto_tree_midi_14bit(tree, hf_midi_sysex_ci_prof_inquiry_target_data_len, tvb, offset, &len);
                offset += 2;
                proto_tree_add_item(tree, hf_midi_sysex_ci_prof_inquiry_target_data, tvb, offset, len, ENC_NA);
                offset += len;
            }
            break;
        case MIDI_SYSEX_CI_PROF_SPECIFIC_DATA:
            proto_tree_add_item(tree, hf_midi_sysex_ci_prof_id, tvb, offset, 5, ENC_NA);
            offset += 5;
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_prof_data_len, tvb, offset, &len);
            offset += 2;
            proto_tree_add_item(tree, hf_midi_sysex_ci_prof_data, tvb, offset, len, ENC_NA);
            offset += len;
            break;
    }
    return offset;
}
static unsigned int
dissect_sysex7_common_nrt_ci_prop(tvbuff_t *tvb, proto_tree *tree, unsigned int offset, uint8_t msg_type) {
    uint16_t len;
    switch (msg_type) {
        case MIDI_SYSEX_CI_PROP_CAPABILITY:
        case MIDI_SYSEX_CI_PROP_CAPABILITY_REP:
            proto_tree_add_item(tree, hf_midi_sysex_ci_prop_sim_supported, tvb, offset, 1, ENC_NA);
            offset += 1;
            if (tvb_reported_length_remaining(tvb, offset)) {
                proto_tree_add_item(tree, hf_midi_sysex_ci_prop_ver_major, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(tree, hf_midi_sysex_ci_prop_ver_minor, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case MIDI_SYSEX_CI_PROP_GET_DATA:
        case MIDI_SYSEX_CI_PROP_GET_DATA_REP:
        case MIDI_SYSEX_CI_PROP_SET_DATA:
        case MIDI_SYSEX_CI_PROP_SET_DATA_REP:
        case MIDI_SYSEX_CI_PROP_SUB:
        case MIDI_SYSEX_CI_PROP_SUB_REP:
        case MIDI_SYSEX_CI_PROP_NOTIFY:
            proto_tree_add_item(tree, hf_midi_sysex_ci_prop_request_id, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_prop_header_len, tvb, offset, &len);
            offset += 2;
            proto_tree_add_item(tree, hf_midi_sysex_ci_prop_header, tvb, offset, len, ENC_NA);
            offset += len;
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_prop_chunk_count, tvb, offset, NULL);
            offset += 2;
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_prop_chunk_num, tvb, offset, NULL);
            offset += 2;
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_prop_data_len, tvb, offset, &len);
            offset += 2;
            proto_tree_add_item(tree, hf_midi_sysex_ci_prop_data, tvb, offset, len, ENC_NA);
            offset += len;
            break;
    }
    return offset;
}
static unsigned int
dissect_sysex7_common_nrt_ci_proc(tvbuff_t *tvb, proto_tree *tree, unsigned int offset, uint8_t msg_type) {
    switch (msg_type) {
        case MIDI_SYSEX_CI_PROC_CAPABILITIES:
            break;
        case MIDI_SYSEX_CI_PROC_CAPABILITIES_REP:
            proto_tree_add_bitmask(tree, tvb, offset, hf_midi_sysex_ci_proc_supported_features,
                ett_midi_sysex_ci_proc_supported_features, midi_sysex_ci_proc_supported_features, ENC_NA);
            offset += 1;
            break;
        case MIDI_SYSEX_CI_PROC_MESSAGE_REPORT:
        case MIDI_SYSEX_CI_PROC_MESSAGE_REPORT_REP:
            proto_tree_add_item(tree, hf_midi_sysex_ci_proc_message_data_control, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_bitmask(tree, tvb, offset, hf_midi_sysex_ci_proc_requested_system_messages,
                ett_midi_sysex_ci_proc_requested_system_messages, midi_sysex_ci_proc_requested_system_messages, ENC_NA);
            offset += 1;
            proto_tree_add_item(tree, hf_midi_sysex_ci_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_bitmask(tree, tvb, offset, hf_midi_sysex_ci_proc_requested_channel_messages,
                ett_midi_sysex_ci_proc_requested_channel_messages, midi_sysex_ci_proc_requested_channel_messages, ENC_NA);
            offset += 1;
            proto_tree_add_bitmask(tree, tvb, offset, hf_midi_sysex_ci_proc_requested_note_messages,
                ett_midi_sysex_ci_proc_requested_note_messages, midi_sysex_ci_proc_requested_note_messages, ENC_NA);
            offset += 1;
            break;
        case MIDI_SYSEX_CI_PROC_MESSAGE_REPORT_END:
            break;
    }
    return offset;
}
static unsigned int
dissect_sysex7_common_nrt_ci_management(tvbuff_t *tvb, proto_tree *tree, unsigned int offset, uint8_t msg_type) {
    uint16_t len;
    switch (msg_type) {
        case MIDI_SYSEX_CI_DISC:
        case MIDI_SYSEX_CI_DISC_REP:
            proto_tree_add_item(tree, hf_midi_sysex_ci_device_manu_short, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_device_manu_long, tvb, offset, NULL);
            offset += 2;
            proto_tree_midi_14bit(tree, hf_midi_sysex_gen_info_device_family, tvb, offset, NULL);
            offset += 2;
            proto_tree_midi_14bit(tree, hf_midi_sysex_gen_info_family_member, tvb, offset, NULL);
            offset += 2;
            proto_tree_midi_28bit(tree, hf_midi_sysex_gen_info_software_rev, tvb, offset, NULL);
            offset += 4;
            proto_tree_add_bitmask(tree, tvb, offset, hf_midi_sysex_ci_supported_categories,
                ett_midi_sysex_ci_supported_categories, midi_sysex_ci_supported_categories, ENC_NA);
            offset += 1;
            proto_tree_midi_28bit(tree, hf_midi_sysex_ci_max_sysex, tvb, offset, NULL);
            offset += 4;
            if (tvb_reported_length_remaining(tvb, offset)) {
                proto_tree_add_item(tree, hf_midi_sysex_ci_output_path_id, tvb, offset, 1, ENC_NA);
                offset += 1;
                if (msg_type == MIDI_SYSEX_CI_DISC_REP) {
                    proto_tree_add_item(tree, hf_midi_sysex_ci_function_block, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
            }
            break;
        case MIDI_SYSEX_CI_EP_INFO:
            proto_tree_add_item(tree, hf_midi_sysex_ci_ep_info_status, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case MIDI_SYSEX_CI_EP_INFO_REP: {
            uint8_t status;
            proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_ci_ep_info_status, tvb, offset, 1, ENC_NA, &status);
            offset += 1;
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_ep_info_len, tvb, offset, &len);
            offset += 2;
            proto_tree_add_item(tree, hf_midi_sysex_ci_ep_info_data, tvb, offset, len, ENC_NA);
            if (status == 0)
                proto_tree_add_item(tree, hf_midi_product_instance_id, tvb, offset, len, ENC_ASCII);
            offset += len;
            break;
        }
        case MIDI_SYSEX_CI_ACK:
            proto_tree_add_item(tree, hf_midi_sysex_ci_ack_original_id, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(tree, hf_midi_sysex_ci_ack_status_code, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(tree, hf_midi_sysex_ci_ack_status_data, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(tree, hf_midi_sysex_ci_ack_details, tvb, offset, 5, ENC_NA);
            offset += 5;
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_ack_msg_len, tvb, offset, &len);
            offset += 2;
            proto_tree_add_item(tree, hf_midi_sysex_ci_ack_message, tvb, offset, len, ENC_NA);
            offset += len;
            break;
        case MIDI_SYSEX_CI_MUID_INVALIDATE:
            proto_tree_midi_28bit(tree, hf_midi_sysex_ci_invalid_muid, tvb, offset, NULL);
            offset += 4;
            break;
        case MIDI_SYSEX_CI_NAK:
            if (tvb_reported_length_remaining(tvb, offset) == 0) break;
            proto_tree_add_item(tree, hf_midi_sysex_ci_nak_original_id, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(tree, hf_midi_sysex_ci_nak_status_code, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(tree, hf_midi_sysex_ci_nak_status_data, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(tree, hf_midi_sysex_ci_nak_details, tvb, offset, 5, ENC_NA);
            offset += 5;
            proto_tree_midi_14bit(tree, hf_midi_sysex_ci_nak_msg_len, tvb, offset, &len);
            offset += 2;
            proto_tree_add_item(tree, hf_midi_sysex_ci_nak_message, tvb, offset, len, ENC_NA);
            offset += len;
            break;
    }
    return offset;
}

/* SysEx-Common Non-Realtime Capability Inquiry */
static unsigned int
dissect_sysex7_common_nrt_ci(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    uint8_t msg_typ;
    proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_ci_msg_type, tvb, offset, 1, ENC_NA, &msg_typ);
    offset++;
    proto_tree_add_item(tree, hf_midi_sysex_ci_major_version, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_midi_sysex_ci_minor_version, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_midi_28bit(tree, hf_midi_sysex_ci_src_muid, tvb, offset, NULL);
    offset += 4;
    proto_tree_midi_28bit(tree, hf_midi_sysex_ci_dst_muid, tvb, offset, NULL);
    offset += 4;

    if ((msg_typ & 0xF0) == 0x20) {
        offset = dissect_sysex7_common_nrt_ci_prof(tvb, tree, offset, msg_typ);
    } else if ((msg_typ & 0xF0) == 0x30) {
        offset = dissect_sysex7_common_nrt_ci_prop(tvb, tree, offset, msg_typ);
    } else if ((msg_typ & 0xF0) == 0x40) {
        offset = dissect_sysex7_common_nrt_ci_proc(tvb, tree, offset, msg_typ);
    } else if ((msg_typ & 0xF0) == 0x70) {
        offset = dissect_sysex7_common_nrt_ci_management(tvb, tree, offset, msg_typ);
    }
    return offset;
}

/* SysEx-common Non-Realtime MIDI Time Code Cueing */
static unsigned int
dissect_sysex7_common_nrt_mtc_cue(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    proto_tree_add_item(tree, hf_midi_sysex_mtc_cue_nrt_command, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_midi_sysex_mtc_type, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_midi_sysex_mtc_hour, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_midi_sysex_mtc_min, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_midi_sysex_mtc_sec, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_midi_sysex_mtc_frame, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_midi_sysex_mtc_fract_frame, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_midi_14bit(tree, hf_midi_sysex_mtc_cue_event_num, tvb, offset, NULL);
    offset += 2;

    if (tvb_reported_length_remaining(tvb, offset)) {
        unsigned int len;
        proto_tree_add_item_ret_length(tree, hf_midi_sysex_mtc_cue_add_info, tvb, offset, -1, ENC_NA, &len);
        offset += len;
    }

    return offset;
}

/* SysEx-Common Realtime MIDI Time Code Cueing */
static unsigned int
dissect_sysex7_common_rt_mtc_cue(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    proto_tree_add_item(tree, hf_midi_sysex_mtc_cue_rt_command, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_midi_14bit(tree, hf_midi_sysex_mtc_cue_event_num, tvb, offset, NULL);
    offset += 2;

    if (tvb_reported_length_remaining(tvb, offset)) {
        unsigned int len;
        proto_tree_add_item_ret_length(tree, hf_midi_sysex_mtc_cue_add_info, tvb, offset, -1, ENC_NA, &len);
        offset += len;
    }

    return offset;
}

/* SysEx-Common Realtime MIDI Time Code */
static unsigned int
dissect_sysex7_common_rt_mtc(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    uint8_t sub_id;
    proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_mtc_rt_msg_type, tvb, offset, 1, ENC_NA, &sub_id);
    offset++;

    if (sub_id == MIDI_SYSEX_COMMON_RT_MTC_FULL_MESSAGE) {
        /* type and hours */
        proto_tree_add_item(tree, hf_midi_sysex_mtc_type, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_midi_sysex_mtc_hour, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_min, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_sec, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_frame, tvb, offset, 1, ENC_NA);
        offset++;
    } else if (sub_id == MIDI_SYSEX_COMMON_RT_MTC_USER_BITS) {
        proto_tree_add_item(tree, hf_midi_sysex_mtc_ub_u1, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_ub_u2, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_ub_u3, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_ub_u4, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_ub_u5, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_ub_u6, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_ub_u7, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_ub_u8, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_mtc_ub_u9, tvb, offset, 1, ENC_NA);
        offset++;
    }

    return offset;
}

static void
decode_sysex7_msc_q_str(proto_tree* tree, int hfindex, tvbuff_t* tvb, unsigned int* offset, bool required) {
    /* Handle optional string */
    if (tvb_reported_length_remaining(tvb, *offset) == 0) {
        if (!required)
            return;
        /* Deliberate error: missing */
        proto_tree_add_item(tree, hfindex, tvb, *offset, 1, ENC_ASCII);
        return;
    }

    int str_len = tvb_strnlen(tvb, *offset, -1);
    unsigned int actual_len;
    proto_tree_add_item_ret_length(tree, hfindex, tvb, *offset, str_len, ENC_ASCII, &actual_len);
    *offset += actual_len;
}
static unsigned int
decode_sysex7_msc_q_number(proto_tree* tree, tvbuff_t* tvb, unsigned int offset, bool required) {
    unsigned int len = tvb_reported_length(tvb);
    /* Handle optional string */
    if (!required && offset >= len)
        return offset;

    decode_sysex7_msc_q_str(tree, hf_midi_sysex_msc_q_number, tvb, &offset, true);

    /* eat delimiters */
    while (offset<len && tvb_get_uint8(tvb, offset)==0) {
        proto_tree_add_item(tree, hf_midi_sysex_msc_q_delimiter, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    if (offset >= len)
        return offset;
    decode_sysex7_msc_q_str(tree, hf_midi_sysex_msc_q_list, tvb, &offset, false);

    while (offset<len && tvb_get_uint8(tvb, offset)==0) {
        proto_tree_add_item(tree, hf_midi_sysex_msc_q_delimiter, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    if (offset >= len)
        return offset;
    decode_sysex7_msc_q_str(tree, hf_midi_sysex_msc_q_path, tvb, &offset, false);

    return offset;
}
static void
decode_sysex7_msc_standard_time(proto_tree* tree, tvbuff_t* tvb, unsigned int* off) {
    unsigned int offset = *off;
    bool final_byte_status;
    proto_tree_add_item(tree, hf_midi_sysex_msc_tc_type, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_midi_sysex_msc_tc_hour, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_midi_sysex_msc_tc_colour, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_midi_sysex_msc_tc_min, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_midi_sysex_msc_tc_sec, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_midi_sysex_msc_tc_sign, tvb, offset, 1, ENC_NA);
    proto_tree_add_item_ret_boolean(tree, hf_midi_sysex_msc_tc_final_byte, tvb, offset, 1, ENC_NA, &final_byte_status);
    proto_tree_add_item(tree, hf_midi_sysex_msc_tc_frame, tvb, offset, 1, ENC_NA);
    offset++;
    if (final_byte_status) {
        proto_tree_add_item(tree, hf_midi_sysex_msc_tc_stat_est, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_midi_sysex_msc_tc_stat_valid, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_midi_sysex_msc_tc_stat_video, tvb, offset, 1, ENC_NA);
    } else {
        proto_tree_add_item(tree, hf_midi_sysex_msc_tc_fract_frame, tvb, offset, 1, ENC_NA);
    }
    offset++;
    *off = offset;
}

/* SysEx-Common Realtime MIDI Show Control */
static unsigned int
decode_sysex_common_rt_sc(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    uint8_t command_format, command;

    proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_msc_command_format, tvb, offset, 1, ENC_NA, &command_format);
    offset++;
    proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_msc_command, tvb, offset, 1, ENC_NA, &command);
    offset++;

    switch (command) {
        case MIDI_SYSEX_MSC_COMMAND_GO:
        case MIDI_SYSEX_MSC_COMMAND_STOP:
        case MIDI_SYSEX_MSC_COMMAND_RESUME:
            offset = decode_sysex7_msc_q_number(tree, tvb, offset, false);
            break;
        case MIDI_SYSEX_MSC_COMMAND_TIMED_GO:
            decode_sysex7_msc_standard_time(tree, tvb, &offset);
            offset = decode_sysex7_msc_q_number(tree, tvb, offset, false);
            break;
        case MIDI_SYSEX_MSC_COMMAND_LOAD:
            offset = decode_sysex7_msc_q_number(tree, tvb, offset, true);
            break;
        case MIDI_SYSEX_MSC_COMMAND_SET:
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_generic_controller_number, tvb, offset, NULL);
            offset += 2;
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_generic_controller_value, tvb, offset, NULL);
            offset += 2;
            if (tvb_reported_length_remaining(tvb, offset) > 0)
                decode_sysex7_msc_standard_time(tree, tvb, &offset);
            break;
        case MIDI_SYSEX_MSC_COMMAND_FIRE:
            proto_tree_add_item(tree, hf_midi_sysex_msc_macro_number, tvb, offset, 1, ENC_NA);
            offset++;
            break;
        case MIDI_SYSEX_MSC_COMMAND_ALL_OFF:
        case MIDI_SYSEX_MSC_COMMAND_RESTORE:
        case MIDI_SYSEX_MSC_COMMAND_RESET:
            break;
        case MIDI_SYSEX_MSC_COMMAND_GO_OFF:
        case MIDI_SYSEX_MSC_COMMAND_GO_JAM_CLOCK:
            offset = decode_sysex7_msc_q_number(tree, tvb, offset, false);
            break;
        case MIDI_SYSEX_MSC_COMMAND_STANDBY_PLUS:
        case MIDI_SYSEX_MSC_COMMAND_STANDBY_MINUS:
        case MIDI_SYSEX_MSC_COMMAND_SEQUENCE_PLUS:
        case MIDI_SYSEX_MSC_COMMAND_SEQUENCE_MINUS:
        case MIDI_SYSEX_MSC_COMMAND_START_CLOCK:
        case MIDI_SYSEX_MSC_COMMAND_STOP_CLOCK:
        case MIDI_SYSEX_MSC_COMMAND_ZERO_CLOCK:
            decode_sysex7_msc_q_str(tree, hf_midi_sysex_msc_q_list, tvb, &offset, false);
            break;
        case MIDI_SYSEX_MSC_COMMAND_SET_CLOCK:
            decode_sysex7_msc_standard_time(tree, tvb, &offset);
            decode_sysex7_msc_q_str(tree, hf_midi_sysex_msc_q_list, tvb, &offset, false);
            break;
        case MIDI_SYSEX_MSC_COMMAND_MTC_CHASE_ON:
        case MIDI_SYSEX_MSC_COMMAND_MTC_CHASE_OFF:
            decode_sysex7_msc_q_str(tree, hf_midi_sysex_msc_q_list, tvb, &offset, false);
            break;
        case MIDI_SYSEX_MSC_COMMAND_OPEN_CUE_LIST:
        case MIDI_SYSEX_MSC_COMMAND_CLOSE_CUE_LIST:
            decode_sysex7_msc_q_str(tree, hf_midi_sysex_msc_q_list, tvb, &offset, true);
            break;
        case MIDI_SYSEX_MSC_COMMAND_OPEN_CUE_PATH:
        case MIDI_SYSEX_MSC_COMMAND_CLOSE_CUE_PATH:
            decode_sysex7_msc_q_str(tree, hf_midi_sysex_msc_q_path, tvb, &offset, true);
            break;
        case MIDI_SYSEX_MSC_COMMAND_STANDBY:
        case MIDI_SYSEX_MSC_COMMAND_GO_2PC:
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_checksum, tvb, offset, NULL);
            offset += 2;
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_seq_number, tvb, offset, NULL);
            offset += 2;
            proto_tree_add_item(tree, hf_midi_sysex_msc_d1, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_midi_sysex_msc_d2, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_midi_sysex_msc_d3, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_midi_sysex_msc_d4, tvb, offset, 1, ENC_NA);
            offset++;
            offset = decode_sysex7_msc_q_number(tree, tvb, offset, true);
            break;
        case MIDI_SYSEX_MSC_COMMAND_STANDING_BY:
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_checksum, tvb, offset, NULL);
            offset += 2;
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_seq_number, tvb, offset, NULL);
            offset += 2;
            decode_sysex7_msc_standard_time(tree, tvb, &offset);
            offset = decode_sysex7_msc_q_number(tree, tvb, offset, false);
            break;
        case MIDI_SYSEX_MSC_COMMAND_COMPLETE:
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_checksum, tvb, offset, NULL);
            offset += 2;
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_seq_number, tvb, offset, NULL);
            offset += 2;
            offset = decode_sysex7_msc_q_number(tree, tvb, offset, false);
            break;
        case MIDI_SYSEX_MSC_COMMAND_CANCEL:
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_checksum, tvb, offset, NULL);
            offset += 2;
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_seq_number, tvb, offset, NULL);
            offset += 2;
            offset = decode_sysex7_msc_q_number(tree, tvb, offset, true);
            break;
        case MIDI_SYSEX_MSC_COMMAND_CANCELLED:
        case MIDI_SYSEX_MSC_COMMAND_ABORT: {
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_checksum, tvb, offset, NULL);
            offset += 2;
            int hf_status;
            if (command_format < 0x10) {
                hf_status = hf_midi_sysex_msc_status_code_lighting;
            } else if (command_format < 0x20) {
                hf_status = hf_midi_sysex_msc_status_code_sound;
            } else if (command_format < 0x30) {
                hf_status = hf_midi_sysex_msc_status_code_machinery;
            } else if (command_format < 0x40) {
                hf_status = hf_midi_sysex_msc_status_code_video;
            } else if (command_format < 0x50) {
                hf_status = hf_midi_sysex_msc_status_code_projection;
            } else if (command_format < 0x60) {
                hf_status = hf_midi_sysex_msc_status_code_process_control;
            } else if (command_format < 0x70) {
                hf_status = hf_midi_sysex_msc_status_code_pyrotechnics;
            } else {
                hf_status = hf_midi_sysex_msc_status_code_lighting;
            }
            uint8_t s1 = tvb_get_uint8(tvb, offset);
            uint8_t s2 = tvb_get_uint8(tvb, offset+1);
            uint16_t status = (s1*4) + (s2*512);
            proto_tree_add_uint(tree, hf_status, tvb, offset, 2, status);
            offset += 2;
            proto_tree_midi_14bit(tree, hf_midi_sysex_msc_seq_number, tvb, offset, NULL);
            offset += 2;
            break;
        }
    }

    return offset;
}

/* SysEx-Common Realtime Notation Information */
static unsigned int
dissect_sysex7_common_rt_note_info(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    uint8_t sub_id;
    proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_note_info_msg_type, tvb, offset, 1, ENC_NA, &sub_id);
    offset++;

    if (sub_id == MIDI_SYSEX_COMMON_RT_NT_BAR_NUMBER) {
        proto_tree_midi_14bit(tree, hf_midi_sysex_note_info_bar_num, tvb, offset, NULL);
        offset += 2;
    } else if ((sub_id == MIDI_SYSEX_COMMON_RT_NT_TIME_SIGNATURE_IMMEDIATE) || (sub_id == MIDI_SYSEX_COMMON_RT_NT_TIME_SIGNATURE_DELAYED)) {
        uint8_t bytes;
        proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_note_info_bytes, tvb, offset, 1, ENC_NA, &bytes);
        offset++;

        /* time sig numerator+denominator */
        proto_tree_add_item(tree, hf_midi_sysex_note_info_numerator, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_note_info_denominator, tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(tree, hf_midi_sysex_note_info_midi_clocks, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_midi_sysex_note_info_32nds, tvb, offset, 1, ENC_NA);
        offset++;

        while (bytes > 4) {
            /* time sig numerator+denominator */
            proto_tree_add_item(tree, hf_midi_sysex_note_info_numerator, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_midi_sysex_note_info_denominator, tvb, offset, 1, ENC_NA);
            offset++;
            bytes -= 2;
        }
    }

    return offset;
}

/* SysEx-Common Realtime Device Control */
static unsigned int
dissect_sysex7_common_rt_dev_ctrl(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    uint8_t sub_id;
    proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_dev_ctrl_msg_type, tvb, offset, 1, ENC_NA, &sub_id);
    offset++;

    if (sub_id == MIDI_SYSEX_COMMON_RT_DC_MASTER_VOLUME) {
        proto_tree_midi_14bit(tree, hf_midi_sysex_dev_ctrl_volume, tvb, offset, NULL);
        offset += 2;
    } else if (sub_id == MIDI_SYSEX_COMMON_RT_DC_MASTER_BALANCE) {
        proto_tree_midi_14bit(tree, hf_midi_sysex_dev_ctrl_balance, tvb, offset, NULL);
        offset += 2;
    }

    return offset;
}

/* SysEx-Common Realtime MIDI Machine Control Command */
static unsigned int
dissect_sysex7_common_rt_mmc_command(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    /* Actually a list of commands */
    while (tvb_reported_length_remaining(tvb, offset)) {
        uint8_t command;
        proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_mmc_command, tvb, offset, 1, ENC_NA, &command);
        offset++;

        /* Skip commands with no data */
        if (command < 0x40 || command > 0x77)
            continue;

        uint8_t count;
        proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_mmc_count, tvb, offset, 1, ENC_NA, &count);
        offset++;

        proto_tree_add_item(tree, hf_midi_sysex_mmc_data, tvb, offset, count, ENC_NA);
        offset += count;

        /* TODO: further MMC dissection */
    }

    return offset;
}

/* SysEx-Common Realtime MIDI Machine Control Response */
static unsigned int
dissect_sysex7_common_rt_mmc_response(tvbuff_t *tvb, proto_tree *tree, unsigned int offset) {
    while (tvb_reported_length_remaining(tvb, offset)) {
        uint8_t response;
        proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_mmc_response, tvb, offset, 1, ENC_NA, &response);
        offset++;

        if (0x01 <= response && response <= 0x1f) {
            /* Standard time code fields (5 bytes) */
            proto_tree_add_item(tree, hf_midi_sysex_mmc_data, tvb, offset, 5, ENC_NA);
            offset += 5;
            continue;
        } else if (0x20 <= response && response <= 0x3F) {
            /* Short time code fields (2 bytes) */
            proto_tree_add_item(tree, hf_midi_sysex_mmc_data, tvb, offset, 2, ENC_NA);
            offset += 2;
            continue;
        }
        if (response < 0x40 || response > 0x77)
            continue;

        uint8_t count;
        proto_tree_add_item_ret_uint8(tree, hf_midi_sysex_mmc_count, tvb, offset, 1, ENC_NA, &count);
        offset++;

        proto_tree_add_item(tree, hf_midi_sysex_mmc_data, tvb, offset, count, ENC_NA);
        offset += count;

        /* TODO: further MMC dissection */
    }

    return offset;
}


/* SysEx-Common Non-Realtime: 0x7E */
static int
dissect_sysex7_common_nrt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
    uint8_t common_nrt;
    const char* nrt_str;
    proto_tree* command_tree;
    unsigned int offset = 0;

    proto_tree_add_item(parent_tree, hf_midi_sysex_common_device_id, tvb, offset, 1, ENC_NA);
    offset++;

    common_nrt = tvb_get_uint8(tvb, offset);
    nrt_str = val_to_str(pinfo->pool, common_nrt, midi_sysex_common_nrt, "Unknown 0x%02x");

    command_tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, -1, ett_midi_sysex_common_nrt, NULL, "Common NRT: %s", nrt_str);
    proto_tree_add_item(command_tree, hf_midi_sysex_common_non_realtime, tvb, offset, 1, ENC_NA);
    offset++;

    switch (common_nrt) {
        case MIDI_SYSEX_NRT_SAMPLE_DUMP_HEADER:
            offset = dissect_sysex7_common_nrt_sample_dump_hdr(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_SAMPLE_DATA_PACKET:
            offset = dissect_sysex7_common_nrt_sample_dump_data(tvb, pinfo, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_SAMPLE_DUMP_REQUEST:
            offset = dissect_sysex7_common_nrt_sample_dump_req(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_MTC:
            offset = dissect_sysex7_common_nrt_mtc_cue(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_SAMPLE_DUMP_EXTENSIONS:
            offset = dissect_sysex7_common_nrt_sample_dump_ext(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_GENERAL_INFORMATION:
            offset = dissect_sysex7_common_nrt_gen_info(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_FILE_DUMP:
            offset = dissect_sysex7_common_nrt_file_dump(tvb, pinfo, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_MIDI_TUNING_STANDARD:
            offset = dissect_sysex7_common_tuning(tvb, pinfo, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_GENERAL_MIDI:
            offset = dissect_sysex7_common_nrt_gen_midi(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_DOWNLOADABLE_SOUNDS:
            offset = dissect_sysex7_common_nrt_dls(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_CAPABILITY_INQUIRY:
            offset = dissect_sysex7_common_nrt_ci(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_NRT_END_OF_FILE:
        case MIDI_SYSEX_NRT_WAIT:
        case MIDI_SYSEX_NRT_CANCEL:
        case MIDI_SYSEX_NRT_NAK:
        case MIDI_SYSEX_NRT_ACK:
            /* we only have a packet-number */
            proto_tree_add_item(command_tree, hf_midi_sysex_dump_packet_number, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
    }

    if (tvb_reported_length_remaining(tvb, offset)) {
        unsigned int len;
        proto_tree_add_item_ret_length(command_tree, hf_midi_unknown_data, tvb, offset, -1, ENC_NA, &len);
        offset += len;
    }

    return offset;
}

/* SysEx-Common Realtime: 0x7F */
static int
dissect_sysex7_common_rt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
    uint8_t common_rt;
    const char* rt_str;
    proto_tree* command_tree;
    unsigned int offset = 0;

    proto_tree_add_item(parent_tree, hf_midi_sysex_common_device_id, tvb, offset, 1, ENC_NA);
    offset++;

    common_rt = tvb_get_uint8(tvb, offset);
    rt_str = val_to_str(pinfo->pool, common_rt, midi_sysex_common_rt, "Unknown 0x%02x");

    command_tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, -1, ett_midi_sysex_common_rt, NULL, "Common RT: %s", rt_str);
    proto_tree_add_item(command_tree, hf_midi_sysex_common_realtime, tvb, offset, 1, ENC_NA);
    offset++;

    switch (common_rt) {
        case MIDI_SYSEX_RT_MIDI_TIME_CODE:
            offset = dissect_sysex7_common_rt_mtc(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_RT_MIDI_SHOW_CONTROL:
            offset = decode_sysex_common_rt_sc(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_RT_NOTATION_INFORMATION:
            offset = dissect_sysex7_common_rt_note_info(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_RT_DEVICE_CONTROL:
            offset = dissect_sysex7_common_rt_dev_ctrl(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_RT_MTC_CUEING:
            offset = dissect_sysex7_common_rt_mtc_cue(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_RT_MIDI_MACHINE_CONTROL_COMMAND:
            offset = dissect_sysex7_common_rt_mmc_command(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_RT_MIDI_MACHINE_CONTROL_RESPONSE:
            offset = dissect_sysex7_common_rt_mmc_response(tvb, command_tree, offset);
            break;
        case MIDI_SYSEX_RT_MIDI_TUNING_STANDARD:
            offset = dissect_sysex7_common_tuning(tvb, pinfo, command_tree, offset);
            break;
    }

    if (tvb_reported_length_remaining(tvb, offset)) {
        unsigned int len;
        proto_tree_add_item_ret_length(command_tree, hf_midi_unknown_data, tvb, offset, -1, ENC_NA, &len);
        offset += len;
    }

    return offset;
}

/* SysEx-Common Educational: 0x7D */
static int
dissect_sysex7_common_educational(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void* data _U_) {
    /* No real meaning to this, we just take all the data and return */
    proto_tree_add_item(parent_tree, hf_midi_sysex_edu_data, tvb, 0, -1, ENC_NA);
    return tvb_reported_length(tvb);
}



/* Helpers to allow parsing variable endianness UMP packets
 * Network MIDI 2.0 uses big endian, and USB MIDI 2.0 uses little endian.
 * So both are actually required.
 */
#define UMP_ENCODING be ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN

#define UMP_WORD_BYTE_1 be ? offset : offset+3, 1
#define UMP_WORD_BYTE_2 be ? offset+1 : offset+2, 1
#define UMP_WORD_BYTE_3 be ? offset+2 : offset+1, 1
#define UMP_WORD_BYTE_4 be ? offset+3 : offset, 1

#define UMP_WORD_BYTES_1_2 be ? offset : offset+2, 2
#define UMP_WORD_BYTES_3_4 be ? offset+2 : offset, 2

#define UMP_WORD_BYTES_1_3 be ? offset : offset+1, 3
#define UMP_WORD_BYTES_2_4 be ? offset+1 : offset, 3

/* MIDI UMP Message type 0x0: Utility */
static void
dissect_midi_ump_utility(tvbuff_t* tvb, proto_tree* tree, unsigned int offset, bool be) {
    uint8_t status;
    proto_tree_add_item_ret_uint8(tree, hf_midi_ump_utility_status, tvb, UMP_WORD_BYTE_2, ENC_NA, &status);

    switch (status) {
        case MIDI_UMP_UTILITY_STATUS_NOOP:
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
            break;
        case MIDI_UMP_UTILITY_STATUS_JR_CLOCK:
        case MIDI_UMP_UTILITY_STATUS_JR_TIME:
            proto_tree_add_item(tree, hf_midi_ump_utility_jr, tvb, UMP_WORD_BYTES_3_4, UMP_ENCODING);
            break;
        case MIDI_UMP_UTILITY_STATUS_DC_TPQ:
            proto_tree_add_item(tree, hf_midi_ump_utility_dc_tpq, tvb, UMP_WORD_BYTES_3_4, UMP_ENCODING);
            break;
        case MIDI_UMP_UTILITY_STATUS_DC:
            proto_tree_add_item(tree, hf_midi_ump_utility_dc, tvb, UMP_WORD_BYTES_2_4, UMP_ENCODING);
            break;
        default:
            proto_tree_add_item(tree, hf_midi_unknown_data, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
            break;
    }
}

/* MIDI UMP Message type 0x1: System Common & System Real Time */
static void
dissect_midi_ump_system(tvbuff_t* tvb, proto_tree* tree, unsigned int offset, bool be) {
    uint8_t status;
    proto_tree_add_item_ret_uint8(tree, hf_midi_common_status, tvb, UMP_WORD_BYTE_2, ENC_NA, &status);

    switch (status) {
        case MIDI_STATUS_COMMON_MTC_QUARTER_FRAME:
            proto_tree_add_item(tree, hf_midi_quarter_frame_type, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_item(tree, hf_midi_quarter_frame_value, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_4, ENC_NA);
            break;
        case MIDI_STATUS_COMMON_SONG_POSITION_POINTER: {
            /* Special Handling: byte 3 is lsb. byte 4 is msb */
            uint16_t v = tvb_get_uint16(tvb, be ? offset+2 : offset, be ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
            v = ((v&0x7F00) >> 1) | (v&0x7F);
            proto_tree_add_uint(tree, hf_midi_spp, tvb, UMP_WORD_BYTES_3_4, v);
            break;
        }
        case MIDI_STATUS_COMMON_SONG_SELECT:
            proto_tree_add_item(tree, hf_midi_song_select, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_4, ENC_NA);
            break;
        case MIDI_STATUS_COMMON_TUNE_REQUEST:
        case MIDI_STATUS_COMMON_REALTIME_TIMING_CLOCK:
        case MIDI_STATUS_COMMON_REALTIME_START:
        case MIDI_STATUS_COMMON_REALTIME_CONTINUE:
        case MIDI_STATUS_COMMON_REALTIME_STOP:
        case MIDI_STATUS_COMMON_REALTIME_ACTIVE_SENSING:
        case MIDI_STATUS_COMMON_REALTIME_SYSTEM_RESET:
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
            break;
        default:
            proto_tree_add_item(tree, hf_midi_unknown_data, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
            break;
    }
}

/* MIDI UMP Message type 0x2: MIDI 1.0 Channel Voice Messages */
static void
dissect_midi_ump_midi1(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned int offset, bool be, proto_item* parent) {
    uint8_t status, chan;
    proto_tree_add_item_ret_uint8(tree, hf_midi1_channel_status, tvb, UMP_WORD_BYTE_2, ENC_NA, &status);
    proto_tree_add_item_ret_uint8(tree, hf_midi_channel, tvb, UMP_WORD_BYTE_2, ENC_NA, &chan);
    chan += 1;
    const char* status_str = val_to_str_const(status, midi_channel_status, "");
    const char* note_str;

    uint8_t a, b;
    switch (status) {
        case MIDI_STATUS_CHAN_NOTE_OFF:
        case MIDI_STATUS_CHAN_NOTE_ON:
            proto_tree_add_item_ret_uint8(tree, hf_midi_note, tvb, UMP_WORD_BYTE_3, ENC_NA, &a);
            proto_tree_add_item_ret_uint8(tree, hf_midi1_velocity, tvb, UMP_WORD_BYTE_4, ENC_NA, &b);
            if (status == MIDI_STATUS_CHAN_NOTE_ON && b == 0)
                status_str = midi_channel_status_special_off;
            note_str = val_to_str_ext_const(a, &midi_note_values_ext, "");
            proto_item_append_text(parent, " %s (c=%d, n=%s, v=%d)", status_str, chan, note_str, b);
            break;
        case MIDI_STATUS_CHAN_POLY_PRESSURE:
            proto_tree_add_item_ret_uint8(tree, hf_midi_note, tvb, UMP_WORD_BYTE_3, ENC_NA, &a);
            proto_tree_add_item_ret_uint8(tree, hf_midi1_pressure, tvb, UMP_WORD_BYTE_4, ENC_NA, &b);
            note_str = val_to_str_ext_const(a, &midi_note_values_ext, "");
            proto_item_append_text(parent, " %s (c=%d, n=%s, p=%d)", status_str, chan, note_str, b);
            break;
        case MIDI_STATUS_CHAN_CONTROL_CHANGE:
            proto_tree_add_item_ret_uint8(tree, hf_midi1_controller, tvb, UMP_WORD_BYTE_3, ENC_NA, &a);
            proto_tree_add_item_ret_uint8(tree, hf_midi1_controller_value, tvb, UMP_WORD_BYTE_4, ENC_NA, &b);
            note_str = val_to_str_ext(pinfo->pool, a, &midi_controller_values_ext, "%d");
            proto_item_append_text(parent, " %s (c=%d, ctrl=%s, p=%d)", status_str, chan, note_str, b);
            break;
        case MIDI_STATUS_CHAN_PROGRAM_CHANGE:
            proto_tree_add_item_ret_uint8(tree, hf_midi1_program, tvb, UMP_WORD_BYTE_3, ENC_NA, &a);
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_4, ENC_NA);
            proto_item_append_text(parent, " %s (c=%d, p=%d)", status_str, chan, a);
            break;
        case MIDI_STATUS_CHAN_CHANNEL_PRESSURE:
            proto_tree_add_item_ret_uint8(tree, hf_midi1_channel_pressure, tvb, UMP_WORD_BYTE_3, ENC_NA, &a);
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_4, ENC_NA);
            proto_item_append_text(parent, " %s (c=%d, p=%d)", status_str, chan, a);
            break;
        case MIDI_STATUS_CHAN_PITCH_BEND: {
            uint16_t v = tvb_get_uint16(tvb, be ? offset+2 : offset, be ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
            v = ((v&0x7F00) >> 1) | (v&0x7F);
            proto_tree_add_uint(tree, hf_midi1_pitch_bend, tvb, UMP_WORD_BYTES_3_4, v);
            proto_item_append_text(parent, " %s (c=%d, pb=%d)", status_str, chan, v);
            break;
        }
        default:
            proto_tree_add_item(tree, hf_midi_unknown_data, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
            break;
    }
}

/* MIDI UMP Message type 0x3: 8-Byte Data Messages */
static void
dissect_midi_ump_data64(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned int offset, bool be, uint8_t group_num) {
    uint8_t status, len;
    proto_item* data = NULL;
    proto_tree_add_item_ret_uint8(tree, hf_midi_ump_data64_status, tvb, UMP_WORD_BYTE_2, ENC_NA, &status);
    proto_tree_add_item_ret_uint8(tree, hf_midi_ump_data64_length, tvb, UMP_WORD_BYTE_2, ENC_NA, &len);
    len = len > 6 ? 6 : len;

    // can do data here, is common to all message types
    if (be) {
        if (len) {
            data = proto_tree_add_item(tree, hf_midi_ump_data64_data, tvb, offset+2, len, ENC_NA);
        }
        if (len < 6) {
            proto_tree_add_item(tree, hf_midi_ump_data64_pad, tvb, offset+2+len, 6-len, ENC_NA);
        }
    } else {
        /* The data bytes could be broken up into multiple different sections */
        proto_tree_add_item(tree, hf_midi_ump_data64_data, tvb, offset, 2, ENC_NA);
        proto_tree_add_item(tree, hf_midi_ump_data64_data, tvb, offset+4, 4, ENC_NA);
    }
    if (data == NULL)
        return;

    /* fits in a single message, so we can dissect it (maybe) */
    if (status == MIDI_UMP_DATA64_STATUS_SINGLE) {
        tvbuff_t* single_tvb = tvb_new_subset_length(tvb, offset+2, len);
        bool save_writable = col_get_writable(pinfo->cinfo, COL_INFO);
        col_set_writable(pinfo->cinfo, COL_INFO, false);
        call_dissector(midi_sysex_handle, single_tvb, pinfo, tree);
        col_set_writable(pinfo->cinfo, COL_INFO, save_writable);
        return;
    }

    bool save_fragmented = pinfo->fragmented;
    fragment_head* frag_sysex_msg = fragment_add_seq_next(
        &midi_ump_data64_reassembly_table,
        tvb, offset+2,
        pinfo,
        group_num,
        NULL,
        len,
        status != MIDI_UMP_DATA64_STATUS_END
    );
    if (frag_sysex_msg == NULL) {
        pinfo->fragmented = save_fragmented;
        return;
    }
    tvbuff_t* assemble_tvb = process_reassembled_data(
        tvb, offset+1, pinfo, "Reassembled SysEx",
        frag_sysex_msg, &midi_ump_data64_msg_frag_items,
        NULL, tree
    );
    pinfo->fragmented = save_fragmented;
    if (assemble_tvb == NULL)
        return;

    bool save_writable = col_get_writable(pinfo->cinfo, COL_INFO);
    col_set_writable(pinfo->cinfo, COL_INFO, false);
    call_dissector(midi_sysex_handle, assemble_tvb, pinfo, tree);
    col_set_writable(pinfo->cinfo, COL_INFO, save_writable);
}

/* MIDI UMP Message type 0x4: MIDI 2.0 Channel Voice Messages */
static void
dissect_midi_ump_midi2(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned int offset, bool be, proto_item* parent) {
    uint8_t status, chan;
    proto_tree_add_item_ret_uint8(tree, hf_midi2_channel_status, tvb, UMP_WORD_BYTE_2, ENC_NA, &status);
    proto_tree_add_item_ret_uint8(tree, hf_midi_channel, tvb, UMP_WORD_BYTE_2, ENC_NA, &chan);
    chan += 1;
    const char* status_str = val_to_str_const(status, midi_ump_midi2_status_name, "");
    const char* note_str;

    uint8_t v8_0, v8_1, v8_2;
    uint16_t v16_0;
    uint32_t v32_0;
    int32_t v32_1;

    switch (status) {
        case MIDI_STATUS_CHAN_NOTE_OFF:
        case MIDI_STATUS_CHAN_NOTE_ON: {
            proto_tree_add_item_ret_uint8(tree, hf_midi_note, tvb, UMP_WORD_BYTE_3, ENC_NA, &v8_0);
            proto_tree_add_item_ret_uint8(tree, hf_midi2_attribute_type, tvb, UMP_WORD_BYTE_4, ENC_NA, &v8_1);
            offset += 4;
            proto_tree_add_item_ret_uint16(tree, hf_midi2_velocity, tvb, UMP_WORD_BYTES_1_2, UMP_ENCODING, &v16_0);
            proto_item* pi = proto_tree_add_item(tree, hf_midi2_attr_data, tvb, UMP_WORD_BYTES_3_4, UMP_ENCODING);
            if (v8_1 == MIDI_UMP_MIDI2_ATTR_TYPE_PITCH79) {
                proto_tree* t = proto_item_add_subtree(pi, ett_midi2_attr_data);
                uint8_t n = tvb_get_uint8(tvb, be ? offset+2 : offset+1) >> 1;
                proto_tree_add_uint(t, hf_midi2_attr_data_pitch_semitones, tvb, UMP_WORD_BYTE_3, n);
                proto_tree_add_item(t, hf_midi2_attr_data_pitch_fract, tvb, UMP_WORD_BYTES_3_4, UMP_ENCODING);
            }

            if (status == MIDI_STATUS_CHAN_NOTE_ON && v16_0 == 0)
                status_str = midi_channel_status_special_off;
            note_str = val_to_str_ext_const(v8_0, &midi_note_values_ext, "");
            proto_item_append_text(parent, " %s (c=%d, n=%s, v=%d)", status_str, chan, note_str, v16_0);
            break;
        }
        case MIDI_STATUS_CHAN_POLY_PRESSURE:
            proto_tree_add_item_ret_uint8(tree, hf_midi_note, tvb, UMP_WORD_BYTE_3, ENC_NA, &v8_0);
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_4, ENC_NA);
            offset += 4;
            proto_tree_add_item_ret_uint32(tree, hf_midi2_pressure, tvb, offset, 4, UMP_ENCODING, &v32_0);

            note_str = val_to_str_ext_const(v8_0, &midi_note_values_ext, "");
            proto_item_append_text(parent, " %s (c=%d, n=%s, p=%u)", status_str, chan, note_str, v32_0);
            break;
        case MIDI_STATUS_CHAN_CONTROL_CHANGE:
            proto_tree_add_item_ret_uint8(tree, hf_midi1_controller, tvb, UMP_WORD_BYTE_3, ENC_NA, &v8_0);
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_4, ENC_NA);
            offset += 4;
            proto_tree_add_item_ret_uint32(tree, hf_midi2_controller_value, tvb, offset, 4, UMP_ENCODING, &v32_0);

            note_str = val_to_str_ext(pinfo->pool, v8_0, &midi_controller_values_ext, "%d");
            proto_item_append_text(parent, " %s (c=%d, ctrl=%s, p=%u)", status_str, chan, note_str, v32_0);
            break;
        case MIDI_STATUS_CHAN_PROGRAM_CHANGE:
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_bitmask(tree, tvb, be?offset+3:offset, hf_midi2_program_options,
                ett_midi2_program_options, midi2_program_options, ENC_NA);
            offset += 4;
            proto_tree_add_item_ret_uint8(tree, hf_midi1_program, tvb, UMP_WORD_BYTE_1, ENC_NA, &v8_0);
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_2, ENC_NA);
            proto_tree_add_item_ret_uint8(tree, hf_midi2_program_bank_msb, tvb, UMP_WORD_BYTE_3, ENC_NA, &v8_1);
            proto_tree_add_item_ret_uint8(tree, hf_midi2_program_bank_lsb, tvb, UMP_WORD_BYTE_4, ENC_NA, &v8_2);

            proto_item_append_text(parent, " %s (c=%d, p=%d, b=0x%02x 0x%02x)", status_str, chan, v8_0, v8_1, v8_2);
            break;
        case MIDI_STATUS_CHAN_CHANNEL_PRESSURE:
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
            offset += 4;
            proto_tree_add_item_ret_uint32(tree, hf_midi2_channel_pressure, tvb, offset, 4, UMP_ENCODING, &v32_0);

            proto_item_append_text(parent, " %s (c=%d, p=%u)", status_str, chan, v32_0);
            break;
        case MIDI_STATUS_CHAN_PITCH_BEND:
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
            offset += 4;
            proto_tree_add_item_ret_uint32(tree, hf_midi2_pitch_bend, tvb, offset, 4, UMP_ENCODING, &v32_0);

            proto_item_append_text(parent, " %s (c=%d, pb=%u)", status_str, chan, v32_0);
            break;
        case MIDI_UMP_MIDI2_REGISTERED_PER_NOTE:
        case MIDI_UMP_MIDI2_ASSIGNABLE_PER_NOTE:
            proto_tree_add_item_ret_uint8(tree, hf_midi_note, tvb, UMP_WORD_BYTE_3, ENC_NA, &v8_0);
            proto_tree_add_item_ret_uint8(tree, hf_midi2_per_note_controller, tvb, UMP_WORD_BYTE_4, ENC_NA, &v8_1);
            offset += 4;
            proto_tree_add_item_ret_uint32(tree, hf_midi2_per_note_controller_value, tvb, offset, 4, UMP_ENCODING, &v32_0);

            note_str = val_to_str_ext_const(v8_0, &midi_note_values_ext, "");
            proto_item_append_text(parent, " %s (c=%d, n=%s, ctrl=0x%02x, v=%u)", status_str, chan, note_str, v8_1, v32_0);
            break;
        case MIDI_UMP_MIDI2_REGISTERED_CONTROL:
        case MIDI_UMP_MIDI2_ASSIGNABLE_CONTROL:
            proto_tree_add_item_ret_uint8(tree, hf_midi2_param_bank, tvb, UMP_WORD_BYTE_3, ENC_NA, &v8_0);
            proto_tree_add_item_ret_uint8(tree, hf_midi2_param_index, tvb, UMP_WORD_BYTE_4, ENC_NA, &v8_1);
            offset += 4;
            proto_tree_add_item_ret_uint32(tree, hf_midi2_param_value, tvb, offset, 4, UMP_ENCODING, &v32_0);

            proto_item_append_text(parent, " %s (c=%d, ctrl=0x%02x 0x%02x, v=%u)", status_str, chan, v8_0, v8_1, v32_0);
            break;
        case MIDI_UMP_MIDI2_REL_REG_CONTROL:
        case MIDI_UMP_MIDI2_REL_ASS_CONTROL:
            proto_tree_add_item_ret_uint8(tree, hf_midi2_param_bank, tvb, UMP_WORD_BYTE_3, ENC_NA, &v8_0);
            proto_tree_add_item_ret_uint8(tree, hf_midi2_param_index, tvb, UMP_WORD_BYTE_4, ENC_NA, &v8_1);
            offset += 4;
            proto_tree_add_item_ret_int(tree, hf_midi2_param_delta, tvb, offset, 4, UMP_ENCODING, &v32_1);

            proto_item_append_text(parent, " %s (c=%d, ctrl=0x%02x 0x%02x, d=%d)", status_str, chan, v8_0, v8_1, v32_1);
            break;
        case MIDI_UMP_MIDI2_PER_NOTE_PITCH_BEND:
            proto_tree_add_item_ret_uint8(tree, hf_midi_note, tvb, UMP_WORD_BYTE_3, ENC_NA, &v8_0);
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_4, ENC_NA);
            offset += 4;
            proto_tree_add_item_ret_uint32(tree, hf_midi2_per_note_pitch_bend, tvb, offset, 4, UMP_ENCODING, &v32_0);

            note_str = val_to_str_ext_const(v8_0, &midi_note_values_ext, "");
            proto_item_append_text(parent, " %s (c=%d, n=%s, pb=%u)", status_str, chan, note_str, v32_0);
            break;
        case MIDI_UMP_MIDI2_PER_NOTE_MANAGEMENT:
            proto_tree_add_item_ret_uint8(tree, hf_midi_note, tvb, UMP_WORD_BYTE_3, ENC_NA, &v8_0);
            v8_1 = tvb_get_uint8(tvb, be ? offset+3:offset);
            proto_tree_add_bitmask(tree, tvb, be ? offset+3:offset, hf_midi2_note_manage,
                ett_midi2_note_manage, midi2_note_manage_fields, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 4, ENC_NA);

            note_str = val_to_str_ext_const(v8_0, &midi_note_values_ext, "");
            proto_item_append_text(parent, " %s (c=%d, n=%s, f=0x%02x%s%s)", status_str, chan, note_str,
                v8_1, v8_1&2?" d":"", v8_1?" s":""
            );
            break;
        default:
            if (be)
                proto_tree_add_item(tree, hf_midi_unknown_data, tvb, offset+2, 6, ENC_NA);
            else {
                proto_tree_add_item(tree, hf_midi_unknown_data, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
                proto_tree_add_item(tree, hf_midi_unknown_data, tvb, offset+4, 4, ENC_NA);
            }
            break;
    }
}

/* MIDI UMP Message type 0x5: 16-Byte Data Messages */
static void
dissect_midi_ump_data128(tvbuff_t* tvb, proto_tree* tree, unsigned int offset, bool be) {
    uint8_t status;
    proto_tree_add_item_ret_uint8(tree, hf_midi_ump_data128_status, tvb, UMP_WORD_BYTE_2, ENC_NA, &status);

    if (status <= MIDI_UMP_DATA128_STATUS_END) {
        uint8_t len;
        proto_tree_add_item_ret_uint8(tree, hf_midi_ump_data128_length, tvb, UMP_WORD_BYTE_2, ENC_NA, &len);

        proto_tree_add_item(tree, hf_midi_ump_data128_stream_id, tvb, UMP_WORD_BYTE_3, ENC_NA);

        /* Should probably do the dissector things here, but we don't have any yet */
        if (be && len > 0) {
            proto_tree_add_item(tree, hf_midi_ump_data128_data, tvb, offset+3, len-1, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset+3+(len-1), 13-(len-1), ENC_NA);
            if (len >= 2 && (status == MIDI_UMP_DATA128_STATUS_SINGLE || status == MIDI_UMP_DATA128_STATUS_START))
                proto_tree_add_item(tree, hf_midi_sysex8_manu, tvb, offset+3, 2, UMP_ENCODING);
        } else {
            proto_tree_add_item(tree, hf_midi_ump_data128_data, tvb, UMP_WORD_BYTE_4, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_data128_data, tvb, offset, 12, ENC_NA);
        }
    } else if (status == MIDI_UMP_DATA128_STATUS_MDS_HEADER) {
        proto_tree_add_item(tree, hf_midi_ump_data128_mds_chunk_len, tvb, UMP_WORD_BYTES_3_4, UMP_ENCODING);
        offset += 4;
        proto_tree_add_item(tree, hf_midi_ump_data128_mds_chunk_count, tvb, UMP_WORD_BYTES_1_2, UMP_ENCODING);
        proto_tree_add_item(tree, hf_midi_ump_data128_mds_chunk_num, tvb, UMP_WORD_BYTES_3_4, UMP_ENCODING);
        offset += 4;
        proto_tree_add_item(tree, hf_midi_sysex8_manu, tvb, UMP_WORD_BYTES_1_2, UMP_ENCODING);
        proto_tree_add_item(tree, hf_midi_sysex8_device_id, tvb, UMP_WORD_BYTES_3_4, UMP_ENCODING);
        offset += 4;
        proto_tree_add_item(tree, hf_midi_sysex8_sub_id_1, tvb, UMP_WORD_BYTES_1_2, UMP_ENCODING);
        proto_tree_add_item(tree, hf_midi_sysex8_sub_id_2, tvb, UMP_WORD_BYTES_3_4, UMP_ENCODING);
    } else if (status == MIDI_UMP_DATA128_STATUS_MDS_PAYLOAD) {
        proto_tree_add_item(tree, hf_midi_ump_data128_mds_payload, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
        offset += 4;
        proto_tree_add_item(tree, hf_midi_ump_data128_mds_payload, tvb, offset, 12, ENC_NA);
    } else {
        proto_tree_add_item(tree, hf_midi_unknown_data, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
        offset += 4;
        proto_tree_add_item(tree, hf_midi_unknown_data, tvb, offset, 12, ENC_NA);
    }
}

/* MIDI UMP Message type 0xD: Flex Data Messages */
static void
dissect_midi_ump_flex_data(tvbuff_t* tvb, proto_tree* tree, unsigned int offset, bool be) {
    uint8_t format, bank, status;
    proto_tree_add_item_ret_uint8(tree, hf_midi_ump_flex_format, tvb, UMP_WORD_BYTE_2, ENC_NA, &format);
    proto_tree_add_item(tree, hf_midi_ump_flex_address, tvb, UMP_WORD_BYTE_2, ENC_NA);
    proto_tree_add_item(tree, hf_midi_ump_flex_channel, tvb, UMP_WORD_BYTE_2, ENC_NA);

    proto_tree_add_item_ret_uint8(tree, hf_midi_ump_flex_status_bank, tvb, UMP_WORD_BYTE_3, ENC_NA, &bank);
    if (bank == 0x00)
        proto_tree_add_item_ret_uint8(tree, hf_midi_ump_flex_status_00, tvb, UMP_WORD_BYTE_4, ENC_NA, &status);
    else if (bank == 0x01)
        proto_tree_add_item_ret_uint8(tree, hf_midi_ump_flex_status_01, tvb, UMP_WORD_BYTE_4, ENC_NA, &status);
    else if (bank == 0x02)
        proto_tree_add_item_ret_uint8(tree, hf_midi_ump_flex_status_02, tvb, UMP_WORD_BYTE_4, ENC_NA, &status);
    else
        proto_tree_add_item_ret_uint8(tree, hf_midi_ump_flex_status, tvb, UMP_WORD_BYTE_4, ENC_NA, &status);
    offset += 4;

    if (format != 0) {
        proto_tree_add_item(tree, hf_midi_ump_flex_data, tvb, offset, 12, ENC_NA);
        return;
    }
    /* Now we have a complete message so we can do things with it */

    if (bank == 0) {
        /* some known messages */
        switch (status) {
            case MIDI_UMP_FLEX_DATA_STATUS_SET_TEMPO:
                proto_tree_add_item(tree, hf_midi_ump_flex_data_tempo, tvb, offset, 4, UMP_ENCODING);
                offset += 4;
                proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 8, ENC_NA);
                break;
            case MIDI_UMP_FLEX_DATA_STATUS_SET_TIME_SIG:
                proto_tree_add_item(tree, hf_midi_ump_flex_data_ts_num, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(tree, hf_midi_ump_flex_data_ts_den, tvb, UMP_WORD_BYTE_2, ENC_NA);
                proto_tree_add_item(tree, hf_midi_ump_flex_data_ts_notes, tvb, UMP_WORD_BYTE_3, ENC_NA);
                proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_4, ENC_NA);
                offset += 4;
                proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 8, ENC_NA);
                break;
            case MIDI_UMP_FLEX_DATA_STATUS_SET_METRONOME:
                proto_tree_add_item(tree, hf_midi_ump_flex_data_met_clocks, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(tree, hf_midi_ump_flex_data_met_bar_1, tvb, UMP_WORD_BYTE_2, ENC_NA);
                proto_tree_add_item(tree, hf_midi_ump_flex_data_met_bar_2, tvb, UMP_WORD_BYTE_3, ENC_NA);
                proto_tree_add_item(tree, hf_midi_ump_flex_data_met_bar_3, tvb, UMP_WORD_BYTE_4, ENC_NA);
                offset += 4;
                proto_tree_add_item(tree, hf_midi_ump_flex_data_met_sub_1, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(tree, hf_midi_ump_flex_data_met_sub_2, tvb, UMP_WORD_BYTE_2, ENC_NA);
                proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
                offset += 4;
                proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 4, ENC_NA);
                break;
            case MIDI_UMP_FLEX_DATA_STATUS_SET_KEY_SIG:
                proto_tree_add_item(tree, hf_midi_ump_flex_data_sig_sharps, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(tree, hf_midi_ump_flex_data_sig_tonic, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTES_2_4, ENC_NA);
                offset += 4;
                proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 8, ENC_NA);
                break;
            case MIDI_UMP_FLEX_DATA_STATUS_SET_CHORD_NAME: {
                proto_item* tonic_ti = proto_tree_add_item(tree, hf_midi_ump_flex_data_chord_tonic, tvb, offset, 8, ENC_NA);
                proto_tree* tonic = proto_item_add_subtree(tonic_ti, ett_midi_ump_flex_chord);
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_sharps, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_note, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_type, tvb, UMP_WORD_BYTE_2, ENC_NA);
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_alt_type, tvb, UMP_WORD_BYTE_3, ENC_NA);
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_alt_deg, tvb, UMP_WORD_BYTE_3, ENC_NA);
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_alt_type, tvb, UMP_WORD_BYTE_4, ENC_NA);
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_alt_deg, tvb, UMP_WORD_BYTE_4, ENC_NA);
                offset += 4;
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_alt_type, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_alt_deg, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_alt_type, tvb, UMP_WORD_BYTE_2, ENC_NA);
                proto_tree_add_item(tonic, hf_midi_ump_flex_data_chord_alt_deg, tvb, UMP_WORD_BYTE_2, ENC_NA);
                proto_tree_add_item(tonic, hf_midi_ump_reserved, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
                offset += 4;
                proto_item* bass_ti = proto_tree_add_item(tree, hf_midi_ump_flex_data_chord_bass, tvb, offset, 4, ENC_NA);
                proto_tree* bass = proto_item_add_subtree(bass_ti, ett_midi_ump_flex_chord);
                proto_tree_add_item(bass, hf_midi_ump_flex_data_chord_sharps, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(bass, hf_midi_ump_flex_data_chord_note, tvb, UMP_WORD_BYTE_1, ENC_NA);
                proto_tree_add_item(bass, hf_midi_ump_flex_data_chord_type, tvb, UMP_WORD_BYTE_2, ENC_NA);
                proto_tree_add_item(bass, hf_midi_ump_flex_data_chord_alt_type, tvb, UMP_WORD_BYTE_3, ENC_NA);
                proto_tree_add_item(bass, hf_midi_ump_flex_data_chord_alt_deg, tvb, UMP_WORD_BYTE_3, ENC_NA);
                proto_tree_add_item(bass, hf_midi_ump_flex_data_chord_alt_type, tvb, UMP_WORD_BYTE_4, ENC_NA);
                proto_tree_add_item(bass, hf_midi_ump_flex_data_chord_alt_deg, tvb, UMP_WORD_BYTE_4, ENC_NA);
                break;
            }
            default:
                proto_tree_add_item(tree, hf_midi_ump_flex_data, tvb, offset, 12, ENC_NA);
                break;
        }
    } else if (be && (bank == 1 || bank == 2)) {
        /* Can decode as text */
        proto_tree_add_item(tree, hf_midi_ump_flex_data_text, tvb, offset, 12, ENC_UTF_8);
    } else {
        /* still unknown */
        proto_tree_add_item(tree, hf_midi_ump_flex_data, tvb, offset, 12, ENC_NA);
    }
}

/* MIDI UMP Message type 0xF: UMP Stream Messages */
static void
dissect_midi_ump_stream(tvbuff_t* tvb, proto_tree* tree, unsigned int offset, bool be) {
    uint8_t form;
    uint16_t status;
    proto_tree_add_item_ret_uint8(tree, hf_midi_ump_stream_form, tvb, UMP_WORD_BYTE_1, ENC_NA, &form);
    proto_tree_add_item_ret_uint16(tree, hf_midi_ump_stream_status, tvb, UMP_WORD_BYTES_1_2, UMP_ENCODING, &status);

    switch (status) {
        case MIDI_UMP_STREAM_STATUS_ENDPOINT_DISCOVERY:
            proto_tree_add_item(tree, hf_midi_ump_stream_ver_major, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_ver_minor, tvb, UMP_WORD_BYTE_4, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTES_1_3, ENC_NA);
            proto_tree_add_bitmask(tree, tvb, be ? offset+3:offset, hf_midi_ump_stream_request,
                ett_midi_ump_stream_request, midi_ump_stream_request_fields, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 8, ENC_NA);
            break;
        case MIDI_UMP_STREAM_STATUS_ENDPOINT_INFO:
            proto_tree_add_item(tree, hf_midi_ump_stream_ver_major, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_ver_minor, tvb, UMP_WORD_BYTE_4, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_stream_ep_info_s, tvb, UMP_WORD_BYTE_1, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_ep_info_fbs, tvb, UMP_WORD_BYTE_1, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_ep_info_m2, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_ep_info_m1, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_rx_jr, tvb, UMP_WORD_BYTE_4, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_tx_jr, tvb, UMP_WORD_BYTE_4, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 8, ENC_NA);
            break;
        case MIDI_UMP_STREAM_STATUS_DEVICE_IDENTITY:
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTE_1, ENC_NA);
            /* NOTE: I think the endianness might be wrong here */
            proto_tree_add_item(tree, hf_midi_sysex_manu_short, tvb, UMP_WORD_BYTE_2, ENC_NA);
            proto_tree_midi_14bit(tree, hf_midi_sysex_manu_long, tvb, be ? offset+2 : offset, NULL);
            offset += 4;
            proto_tree_midi_14bit(tree, hf_midi_sysex_gen_info_device_family, tvb, be ? offset : offset+2, NULL);
            proto_tree_midi_14bit(tree, hf_midi_sysex_gen_info_family_member, tvb, be ? offset+2 : offset, NULL);
            offset += 4;
            proto_tree_midi_28bit(tree, hf_midi_sysex_gen_info_software_rev, tvb, offset, NULL);
            break;
        case MIDI_UMP_STREAM_STATUS_ENDPOINT_NAME:
            if (be) {
                proto_tree_add_item(tree, hf_midi_ump_stream_ep_name, tvb, offset+2, 14, ENC_UTF_8);
            } else {
                proto_tree_add_item(tree, hf_midi_ump_stream_ep_name, tvb, UMP_WORD_BYTES_3_4, ENC_UTF_8);
                offset += 4;
                proto_tree_add_item(tree, hf_midi_ump_stream_ep_name, tvb, offset, 12, ENC_UTF_8);
            }
            break;
        case MIDI_UMP_STREAM_STATUS_PRODUCT_INSTANCE_ID:
            if (be) {
                proto_tree_add_item(tree, hf_midi_ump_stream_prod_id, tvb, offset+2, 14, ENC_UTF_8);
            } else {
                proto_tree_add_item(tree, hf_midi_ump_stream_prod_id, tvb, UMP_WORD_BYTES_3_4, ENC_UTF_8);
                offset += 4;
                proto_tree_add_item(tree, hf_midi_ump_stream_prod_id, tvb, offset, 12, ENC_UTF_8);
            }
            break;
        case MIDI_UMP_STREAM_STATUS_STREAM_CONFIGURATION_REQ:
        case MIDI_UMP_STREAM_STATUS_STREAM_CONFIGURATION:
            proto_tree_add_item(tree, hf_midi_ump_stream_protocol, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_rx_jr, tvb, UMP_WORD_BYTE_4, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_tx_jr, tvb, UMP_WORD_BYTE_4, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 12, ENC_NA);
            break;
        case MIDI_UMP_STREAM_STATUS_FUNCTION_BLOCK_DISCOVERY:
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_num, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_bitmask(tree, tvb, be ? offset+3:offset, hf_midi_ump_stream_fb_disc,
                ett_midi_ump_stream_fb_disc, midi_ump_stream_fb_disc_fields, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 12, ENC_NA);
            break;
        case MIDI_UMP_STREAM_STATUS_FUNCTION_BLOCK_INFO:
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_active, tvb, UMP_WORD_BYTE_2, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_num, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_ui_hint, tvb, UMP_WORD_BYTE_4, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_midi_1, tvb, UMP_WORD_BYTE_4, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_dir, tvb, UMP_WORD_BYTE_4, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_group, tvb, UMP_WORD_BYTE_1, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_group_span, tvb, UMP_WORD_BYTE_2, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_ci_version, tvb, UMP_WORD_BYTE_3, ENC_NA);
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_sysex8_count, tvb, UMP_WORD_BYTE_4, ENC_NA);
            offset += 4;
            proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 8, ENC_NA);
            break;
        case MIDI_UMP_STREAM_STATUS_FUNCTION_BLOCK_NAME:
            proto_tree_add_item(tree, hf_midi_ump_stream_fb_num, tvb, UMP_WORD_BYTE_3, ENC_NA);
            if (be) {
                proto_tree_add_item(tree, hf_midi_ump_stream_fb_name, tvb, offset+3, 13, ENC_NA);
            } else {
                proto_tree_add_item(tree, hf_midi_ump_stream_fb_name, tvb, UMP_WORD_BYTE_4, ENC_UTF_8);
                offset += 4;
                proto_tree_add_item(tree, hf_midi_ump_stream_fb_name, tvb, offset, 12, ENC_NA);
            }
            break;
        case MIDI_UMP_STREAM_STATUS_START_OF_CLIP:
        case MIDI_UMP_STREAM_STATUS_END_OF_CLIP:
            if (be) {
                proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 14, ENC_NA);
            } else {
                proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
                offset += 4;
                proto_tree_add_item(tree, hf_midi_ump_reserved, tvb, offset, 12, ENC_NA);
            }
            break;
        default:
            break;
    }

}

unsigned int
dissect_midi_ump_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, unsigned int offset, const unsigned int encoding) {
    uint8_t message_type, group=0;
    bool be = encoding == ENC_BIG_ENDIAN;

    proto_item* pi = proto_tree_add_item(parent_tree, hf_midi_ump, tvb, offset, 4, ENC_NA);
    proto_tree* tree = proto_item_add_subtree(pi, ett_midi_ump);

    proto_tree_add_item_ret_uint8(tree, hf_midi_ump_mt, tvb, UMP_WORD_BYTE_1, ENC_NA, &message_type);

    unsigned int message_len = midi_ump_message_size[message_type];
    proto_item_set_len(pi, message_len);

    if (message_type != MIDI_UMP_MT_UTILITY && message_type != MIDI_UMP_MT_STREAM) {
        proto_tree_add_item_ret_uint8(tree, hf_midi_ump_group, tvb, UMP_WORD_BYTE_1, ENC_NA, &group);
        proto_item_append_text(pi, ", Group %d", group);
    }

    proto_item_append_text(pi, ", %s", val_to_str(pinfo-> pool, message_type, midi_ump_mt_name_short, "mt=%d"));

    switch (message_type) {
        case MIDI_UMP_MT_UTILITY:
            dissect_midi_ump_utility(tvb, tree, offset, be);
            break;
        case MIDI_UMP_MT_SYSTEM:
            dissect_midi_ump_system(tvb, tree, offset, be);
            break;
        case MIDI_UMP_MT_MIDI_1:
            dissect_midi_ump_midi1(tvb, pinfo, tree, offset, be, pi);
            break;
        case MIDI_UMP_MT_DATA_64:
            dissect_midi_ump_data64(tvb, pinfo, tree, offset, be, group);
            break;
        case MIDI_UMP_MT_MIDI_2:
            dissect_midi_ump_midi2(tvb, pinfo, tree, offset, be, pi);
            break;
        case MIDI_UMP_MT_DATA_128:
            dissect_midi_ump_data128(tvb, tree, offset, be);
            break;
        case MIDI_UMP_MT_FLEX_DATA:
            dissect_midi_ump_flex_data(tvb, tree, offset, be);
            break;
        case MIDI_UMP_MT_STREAM:
            dissect_midi_ump_stream(tvb, tree, offset, be);
            break;
        default:
            if (be) {
                proto_tree_add_item(tree, hf_midi_unknown_data, tvb, offset+2, message_len-2, ENC_NA);
            } else {
                proto_tree_add_item(tree, hf_midi_unknown_data, tvb, UMP_WORD_BYTES_3_4, ENC_NA);
                if (message_len > 4) {
                    proto_tree_add_item(tree, hf_midi_unknown_data, tvb, offset+4, message_len-4, ENC_NA);
                }
            }
            break;
    }

    offset += message_len;
    return offset;
}



/* SysEx-Start command */
static unsigned int
dissect_midi1_sysex_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned int offset, bool first_command) {
    const char* status_str;
    proto_tree* command_tree;
    int data_len = 0;

    status_str = val_to_str_const(MIDI_STATUS_COMMON_SYSEX_END, midi_common_status, "");

    /* we need to parse "away" data until the next command */
    while (true) {
        uint8_t octet = tvb_get_uint8(tvb, 1 + offset + data_len);

        /* lets check if we have a "normal" end - if so,
        * the last status-byte is consumed as it belongs to the message
        */
        if (octet == MIDI_STATUS_COMMON_SYSEX_END) {
            status_str = rtp_midi_common_status_sysex_segment_complete;
        } else if (octet == MIDI_STATUS_COMMON_SYSEX_START) {
            status_str = rtp_midi_common_status_sysex_segment_start;
        } else if (octet == MIDI_STATUS_COMMON_UNDEFINED_F4) {
            status_str = rtp_midi_common_status_sysex_cancel;
        }

        /* Is this command through? */
        if (octet & 0x80) {
            break;
        }
        data_len++;
    }

    command_tree = proto_tree_add_subtree(tree, tvb, offset, data_len + 2, ett_midi1_command, NULL, status_str);
    proto_tree_add_item(command_tree, hf_midi_common_status, tvb, offset, 1, ENC_NA);
    offset++;

    uint8_t manu_short;
    proto_tree_add_item_ret_uint8(command_tree, hf_midi_sysex_manu_short, tvb, offset, 1, ENC_NA, &manu_short);
    offset++;
    data_len--;

    uint32_t manufacturer;
    if (manu_short == 0) {
        /* The wireshark table of manufacturer IDs is stored in a 7-bit mode,
         * so we load this in a compatible way
         */
        uint16_t manu_long;
        proto_tree_add_item_ret_uint16(command_tree, hf_midi_sysex_manu_long, tvb, offset, 2, ENC_BIG_ENDIAN, &manu_long);
        offset += 2;
        data_len-=2;
        manufacturer = manu_long;
    } else {
        manufacturer = manu_short << 16;
    }

    tvbuff_t* sysex_tvb = tvb_new_subset_length(tvb, offset, data_len);
    dissector_try_uint(
        sysex_manufacturer_dissector_table,
        manufacturer,
        sysex_tvb,
        pinfo,
        command_tree
    );
    offset += data_len;

    proto_tree_add_item(command_tree, hf_midi_common_status, tvb, offset, 1, ENC_NA);
    offset++;

    if (!first_command) {
        col_append_fstr(pinfo->cinfo, COL_INFO,", %s", status_str);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, status_str);
    }

    return offset;
}

/* SysEx-End command
 * - in RTP-MIDI this has a special semantic, it either starts a segmented SysEx-frame or a SysEx-Cancel
 */
static int
dissect_midi1_sysex_end(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned int offset, bool first_command) {
    const char *status_str;
    proto_tree *command_tree;
    int data_len = 0;

    status_str = val_to_str_const(MIDI_STATUS_COMMON_SYSEX_END, midi_common_status, "");

    /* we need to parse "away" data until the next command */
    while (true) {
        uint8_t octet = tvb_get_uint8(tvb, 1 + offset + data_len);

        /* lets check if we have a "normal" end - if so,
         * the last status-byte is consumed as it belongs to the message
         */
        if (octet == MIDI_STATUS_COMMON_SYSEX_END) {
            status_str = rtp_midi_common_status_sysex_segment_end;
        } else if (octet == MIDI_STATUS_COMMON_SYSEX_START) {
            status_str = rtp_midi_common_status_sysex_segment;
        } else if (octet == MIDI_STATUS_COMMON_UNDEFINED_F4) {
            status_str = rtp_midi_common_status_sysex_cancel;
        }

        /* Is this command through? */
        if (octet & 0x80) {
            break;
        }
        data_len++;
    }

    command_tree = proto_tree_add_subtree(tree, tvb, offset, data_len + 2, ett_midi1_command, NULL, status_str);
    proto_tree_add_item(command_tree, hf_midi_common_status, tvb, offset, 1, ENC_NA);
    offset++;
    if (data_len > 0) {
        proto_tree_add_item(command_tree, hf_midi_unknown_data, tvb, offset, data_len, ENC_NA);
        offset += data_len;
    }
    proto_tree_add_item(command_tree, hf_midi_common_status, tvb, offset, 1, ENC_NA);
    offset++;

    if (!first_command) {
        col_append_fstr(pinfo->cinfo, COL_INFO,", %s", status_str);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, status_str);
    }

    return offset;
}

int
dissect_midi1_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset, uint8_t *runningstatus, bool first_command)
{
    uint8_t octet;
    bool using_rs = false;

    proto_item* command;
    proto_tree* command_tree;
    const char* status_str;

    /* for extracting from fields and using as display */
    uint8_t a, b;
    uint16_t c;

    octet = tvb_get_uint8(tvb, offset);

    /* Decode running status */
    if ((octet & 0x80) == 0) {
        /* Not provided */
        if (runningstatus == NULL)
            return -1;
        octet = *runningstatus;
        /* Not yet initialised / reset */
        if ((octet & 0x80) == 0)
            return -1;
        using_rs = true;
    } else if (runningstatus != NULL) {
        /* Channel command: replace current status */
        if (octet < 0xf0) {
            *runningstatus = octet;
        } else {
            /* System command
             * Realtime (0xF8-0xFF) keep the current running-status
             * other system-commands clear it */
            if (octet < 0xF8) {
                *runningstatus = 0;
            }
        }
    }

    /* MIDI channel commands */
    if (octet < 0xF0) {
        unsigned int init_offset = offset;
        command = proto_tree_add_item(tree, hf_midi1_command, tvb, offset, 1, ENC_NA);
        command_tree = proto_item_add_subtree(command, ett_midi1_command);

        /* dissect the first byte of the message here */
        if (using_rs) {
            proto_item* pi = proto_tree_add_uint(command_tree, hf_midi1_channel_status, tvb, offset, 0, octet);
            proto_item_set_generated(pi);
            pi = proto_tree_add_uint(command_tree, hf_midi_channel, tvb, offset, 0, octet);
            proto_item_set_generated(pi);
        } else {
            proto_tree_add_item(command_tree, hf_midi1_channel_status, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(command_tree, hf_midi_channel, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        /* And add its info to the info column.
            (Could get wonky here if we have a packet error, but I think the simplicity is worth it)
            (note the octet is always >=0x80 and <0xF0, so we never use the const value)
         */
        status_str = val_to_str_const(octet >> 4, midi_channel_status, "");
        if (!first_command) {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
        }
        uint8_t chan = (octet & 0x0F) + 1;

        const char* note_str;
        switch (octet >> 4) {
            case MIDI_STATUS_CHAN_NOTE_OFF:
                proto_tree_add_item_ret_uint8(command_tree, hf_midi_note, tvb, offset, 1, ENC_NA, &a);
                offset += 1;
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_velocity, tvb, offset, 1, ENC_NA, &b);
                offset += 1;
                note_str = val_to_str_ext_const(a, &midi_note_values_ext, "");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s (c=%d, n=%s, v=%d)", status_str, chan, note_str, b);
                proto_item_append_text(command, " %s (c=%d, n=%s, v=%d)", status_str, chan, note_str, b);
                break;
            case MIDI_STATUS_CHAN_NOTE_ON:
                proto_tree_add_item_ret_uint8(command_tree, hf_midi_note, tvb, offset, 1, ENC_NA, &a);
                offset += 1;
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_velocity, tvb, offset, 1, ENC_NA, &b);
                offset += 1;
                if (b == 0) {
                    status_str = midi_channel_status_special_off;
                }
                note_str = val_to_str_ext_const(a, &midi_note_values_ext, "");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s (c=%d, n=%s, v=%d)", status_str, chan, note_str, b);
                proto_item_append_text(command, " %s (c=%d, n=%s, v=%d)", status_str, chan, note_str, b);
                break;
            case MIDI_STATUS_CHAN_POLY_PRESSURE:
                proto_tree_add_item_ret_uint8(command_tree, hf_midi_note, tvb, offset, 1, ENC_NA, &a);
                offset += 1;
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_pressure, tvb, offset, 1, ENC_NA, &b);
                offset += 1;
                note_str = val_to_str_ext_const(a, &midi_note_values_ext, "");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s (c=%d, n=%s, p=%d)", status_str, chan, note_str, b);
                proto_item_append_text(command, " %s (c=%d, n=%s, p=%d)", status_str, chan, note_str, b);
                break;
            case MIDI_STATUS_CHAN_CONTROL_CHANGE:
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_controller, tvb, offset, 1, ENC_NA, &a);
                offset += 1;
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_controller_value, tvb, offset, 1, ENC_NA, &b);
                offset += 1;
                note_str = val_to_str_ext(pinfo->pool, a, &midi_controller_values_ext, "%d");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s (c=%d, ctrl=%s, p=%d)", status_str, chan, note_str, b);
                proto_item_append_text(command, " %s (c=%d, ctrl=%s, p=%d)", status_str, chan, note_str, b);
                break;
            case MIDI_STATUS_CHAN_PROGRAM_CHANGE:
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_program, tvb, offset, 1, ENC_NA, &a);
                offset += 1;
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s (c=%d, p=%d)", status_str, chan, a);
                proto_item_append_text(command, " %s (c=%d, p=%d)", status_str, chan, a);
                break;
            case MIDI_STATUS_CHAN_CHANNEL_PRESSURE:
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_channel_pressure, tvb, offset, 1, ENC_NA, &a);
                offset += 1;
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s (c=%d, p=%d)", status_str, chan, a);
                proto_item_append_text(command, " %s (c=%d, p=%d)", status_str, chan, a);
                break;
            case MIDI_STATUS_CHAN_PITCH_BEND:
                proto_tree_midi_14bit(command_tree, hf_midi1_pitch_bend, tvb, offset, &c);
                offset += 2;
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s (c=%d, pb=%d)", status_str, chan, c);
                proto_item_append_text(command, " %s (c=%d, pb=%d)", status_str, chan, c);
                break;
        }

        proto_item_set_len(command, offset - init_offset);
        return offset;
    }


    /* System commands (0xF0-0xFF) */
    if (octet == MIDI_STATUS_COMMON_SYSEX_START) {
        return dissect_midi1_sysex_start(tvb, pinfo, tree, offset, first_command);
    } else if (octet == MIDI_STATUS_COMMON_SYSEX_END) {
        return dissect_midi1_sysex_end(tvb, pinfo, tree, offset, first_command);
    }

    unsigned int init_offset = offset;
    command = proto_tree_add_item(tree, hf_midi1_command, tvb, offset, 1, ENC_NA);
    command_tree = proto_item_add_subtree(command, ett_midi1_command);
    proto_tree_add_item(command_tree, hf_midi_common_status, tvb, offset, 1, ENC_NA);
    offset += 1;

    status_str = val_to_str_const(octet, midi_common_status, "");
    proto_item_append_text(command, " %s", status_str);
    if (!first_command) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", status_str);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, status_str);
    }

    /* Switch for command. Realtime commands (0xF8-0xFF) skip this as they have no data */
    switch (octet) {
        case MIDI_STATUS_COMMON_MTC_QUARTER_FRAME:
            proto_tree_add_item(command_tree, hf_midi_quarter_frame_type, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(command_tree, hf_midi_quarter_frame_value, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case MIDI_STATUS_COMMON_SONG_POSITION_POINTER:
            proto_tree_midi_14bit(command_tree, hf_midi_spp, tvb, offset, &c);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (p=%d)", c);
            proto_item_append_text(command, " (p=%d)", c);
            break;
        case MIDI_STATUS_COMMON_SONG_SELECT:
            proto_tree_add_item_ret_uint8(command_tree, hf_midi_song_select, tvb, offset, 1, ENC_NA, &a);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (s=%d)", a);
            proto_item_append_text(command, " (s=%d)", a);
            break;
        case MIDI_STATUS_COMMON_UNDEFINED_F4:
        case MIDI_STATUS_COMMON_UNDEFINED_F5: {
            unsigned int count = 0;
            while (tvb_reported_length_remaining(tvb, offset+count)) {
                uint8_t v = tvb_get_uint8(tvb, offset + count);
                if (v & 0x80) {
                    break;
                }
                count++;
            }
            proto_tree_add_item(command_tree, hf_midi_unknown_data, tvb, offset, count, ENC_NA);
            offset += count;
            proto_tree_add_item(command_tree, hf_midi_common_status, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        }
        case MIDI_STATUS_COMMON_TUNE_REQUEST:
            /* Do nothing here: no data */
            break;
    }

    proto_item_set_len(command, offset-init_offset);
    return offset;
}

static int
dissect_midi1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    unsigned offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MIDI");
    col_set_str(pinfo->cinfo, COL_INFO, "MIDI: ");

    proto_item *ti = proto_tree_add_protocol_format(parent_tree, proto_midi, tvb, 0, -1, "MIDI");
    proto_tree *tree = proto_item_add_subtree(ti, ett_midi);

    uint8_t runningstatus = 0;
    bool first_message = false;
    unsigned prev_offset = offset;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_midi1_message(
            tvb,
            pinfo,
            tree,
            offset,
            &runningstatus,
            first_message
        );
        first_message = false;
        if (offset <= prev_offset)
            break;
        prev_offset = offset;

    }

    return offset;
}

void
proto_register_midi(void) {
    static hf_register_info hf[] = {
        { &hf_midi1_command,
            { "Command", "midi.command",
            FT_NONE, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_midi1_channel_status,
            { "Channel Status", "midi.channel_status",
            FT_UINT8, BASE_HEX,
            VALS(midi_channel_status), 0xf0,
            NULL, HFILL }
        },
        { &hf_midi_channel,
            { "Channel", "midi.channel",
            FT_UINT8, BASE_HEX,
            VALS(midi_channels), 0x0f,
            NULL, HFILL }
        },
        { &hf_midi_note,
            { "Note", "midi.note",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
            &midi_note_values_ext, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi1_velocity,
            { "Velocity", "midi.velocity",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi1_pressure,
            { "Pressure", "midi.pressure",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi1_controller,
            { "Controller", "midi.controller",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
            &midi_controller_values_ext, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi1_controller_value,
            { "Value", "midi.controller_value",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi1_program,
            { "Program", "midi.program",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi1_channel_pressure,
            { "Pressure", "midi.channel_pressure",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi1_pitch_bend,
            { "Pitch Bend", "midi.pitch_bend",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f7f,
            NULL, HFILL }
        },

        { &hf_midi_common_status,
            { "Common Status", "midi.common_status",
            FT_UINT8, BASE_HEX,
            VALS(midi_common_status), 0x0,
            NULL, HFILL }
        },
        { &hf_midi_quarter_frame_type,
            { "MTC-quarter-frame-type", "midi.mtc.quarter_frame.type",
            FT_UINT8, BASE_HEX,
            VALS(midi_mtc_qft_values), 0x70,
            NULL, HFILL }
        },
        { &hf_midi_quarter_frame_value,
            { "MTC-quarter-frame-value", "midi.mtc.quarter_frame.value",
            FT_UINT8, BASE_HEX,
            NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_midi_spp,
            { "Song Position Pointer", "midi.song_position_pointer",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_song_select,
            { "Song Select", "midi.song_select",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_unknown_data,
            { "Unknown Data", "midi.unknown_data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },

        { &hf_midi_ump,
            { "UMP", "midi.ump",
            FT_NONE, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_mt,
            { "Message Type", "midi.ump.mt",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_mt_name), 0xF0,
            NULL, HFILL }
        },
        { &hf_midi_ump_group,
            { "Group", "midi.ump.group",
            FT_UINT8, BASE_DEC,
            NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_midi_ump_reserved,
            { "Reserved", "midi.ump.reserved",
            FT_NONE, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_utility_status,
            { "Status", "midi.ump.utility.status",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_utility_status_name), 0xF0,
            NULL, HFILL }
        },
        { &hf_midi_ump_utility_jr,
            { "JR Timestamp", "midi.ump.utility.jr_time",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_utility_dc_tpq,
            { "Ticks Per 1/4 Note", "midi.ump.utility.dc_tpq",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_utility_dc,
            { "Ticks Since Last Event", "midi.ump.utility.dc",
            FT_UINT24, BASE_DEC,
            NULL, 0x0FFFFF,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_status,
            { "Status", "midi.ump.data64.status",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_data64_status_name), 0xF0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_length,
            { "Data Length", "midi.ump.data64.len",
            FT_UINT8, BASE_DEC,
            NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_data,
            { "Data", "midi.ump.data64.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_pad,
            { "Padding", "midi.ump.data64.pad",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data128_status,
            { "Status", "midi.ump.data128.status",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_data128_status_name), 0xF0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data128_length,
            { "Length", "midi.ump.data128.length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_midi_ump_data128_stream_id,
            { "Stream Id", "midi.ump.data128.stream_id",
            FT_UINT8, BASE_DEC | BASE_SPECIAL_VALS,
            VALS(midi_ump_data128_stream_id_specials), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data128_data,
            { "Data", "midi.ump.data128.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data128_mds_chunk_len,
            { "Chunk Len", "midi.ump.data128.mds.chunk_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data128_mds_chunk_count,
            { "Chunk Count", "midi.ump.data128.mds.chunk_count",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data128_mds_chunk_num,
            { "Chunk Num", "midi.ump.data128.mds.chunk_num",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data128_mds_payload,
            { "Payload", "midi.ump.data128.mds.payload",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_midi_ump_flex_format,
            { "Flex Data Format", "midi.ump.flex.format",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_flex_format), 0x60,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_address,
            { "Flex Data Address", "midi.ump.flex.address",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_flex_address), 0x30,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_channel,
            { "Channel", "midi.ump.flex.channel",
            FT_UINT8, BASE_DEC,
            NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_status_bank,
            { "Flex Data Status Bank", "midi.ump.flex.status_bank",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_flex_status_bank), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_status,
            { "Flex Data Status", "midi.ump.flex.status",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_status_00,
            { "Flex Data Status", "midi.ump.flex.status",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_flex_data_bank_00_status_name), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_status_01,
            { "Flex Data Status", "midi.ump.flex.status",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_flex_data_bank_01_status_name), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_status_02,
            { "Flex Data Status", "midi.ump.flex.status",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_flex_data_bank_02_status_name), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data,
            { "Flex Data", "midi.ump.flex.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_text,
            { "Text Content", "midi.ump.flex.data.text",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_tempo,
            { "Tempo (10ns / quarter note)", "midi.ump.flex.data.tempo",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_ts_num,
            { "TimeSig Numerator", "midi.ump.flex.data.ts.num",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_ts_den,
            { "TimeSig Denominator", "midi.ump.flex.data.ts.den",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_ts_notes,
            { "TimeSig 1/32 notes", "midi.ump.flex.data.ts.notes",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_met_clocks,
            { "Metronome Clocks per Tick", "midi.ump.flex.data.met.clocks",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_met_bar_1,
            { "Bar Accent 1", "midi.ump.flex.data.met.bar_1",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_met_bar_2,
            { "Bar Accent 2", "midi.ump.flex.data.met.bar_2",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_met_bar_3,
            { "Bar Accent 3", "midi.ump.flex.data.met.bar_3",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_met_sub_1,
            { "Subdivision Clicks 1", "midi.ump.flex.data.met.sub_1",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_met_sub_2,
            { "Subdivision Clicks 2", "midi.ump.flex.data.met.sub_2",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_sig_sharps,
            { "KeySig Sharps", "midi.ump.flex.data.sig.sharps",
            FT_UINT8, BASE_DEC,
            NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_sig_tonic,
            { "KeySig Tonic Note", "midi.ump.flex.data.sig.tonic",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_flex_data_note), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_chord_tonic,
            { "Chord Tonic Note", "midi.ump.flex.data.chord.tonic",
            FT_NONE, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_chord_bass,
            { "Chord Bass Note", "midi.ump.flex.data.chord.bass",
            FT_NONE, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_chord_sharps,
            { "Sharps/Flats", "midi.ump.flex.data.chord.sharps",
            FT_UINT8, BASE_DEC,
            NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_chord_note,
            { "Note", "midi.ump.flex.data.chord.note",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_flex_data_note), 0x0F,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_chord_type,
            { "Chord Type", "midi.ump.flex.data.chord.type",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_flex_data_chord_type), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_chord_alt_type,
            { "Alteration Type", "midi.ump.flex.data.chord.alt_type",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_flex_data_chord_alt_type), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_flex_data_chord_alt_deg,
            { "Alteration Degree", "midi.ump.flex.data.chord.alt_deg",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_midi_ump_stream_form,
            { "Stream Format", "midi.ump.stream.format",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_stream_format), 0x0C,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_status,
            { "Stream Status", "midi.ump.stream.status",
            FT_UINT16, BASE_HEX,
            VALS(midi_ump_stream_data_status_name), 0x03FF,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_ver_major,
            { "UMP Version Major", "midi.ump.stream.ver_major",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_ver_minor,
            { "UMP Version Minor", "midi.ump.stream.ver_minor",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_request,
            { "Request Bitmap", "midi.ump.stream.request",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_request_e,
            { "Endpoint Info", "midi.ump.stream.request.e",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_request_d,
            { "Device Identity", "midi.ump.stream.request.d",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_request_n,
            { "Endpoint Name", "midi.ump.stream.request.n",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_request_i,
            { "Product Instance Id", "midi.ump.stream.request.i",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_request_s,
            { "Stream Configuration", "midi.ump.stream.request.s",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_ep_info_s,
            { "Static Function Blocks", "midi.ump.stream.ep_info.s",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_ep_info_fbs,
            { "Function Block Count", "midi.ump.stream.ep_info.fbs",
            FT_UINT8, BASE_DEC,
            NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_ep_info_m2,
            { "MIDI 2.0 Supported", "midi.ump.stream.ep_info.m2",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_ep_info_m1,
            { "MIDI 1.0 Supported", "midi.ump.stream.ep_info.m1",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_rx_jr,
            { "Receive JR Supported", "midi.ump.stream.rx_jr",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_tx_jr,
            { "Transmit JR Supported", "midi.ump.stream.tx_jr",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_ep_name,
            { "Endpoint Name", "midi.ump.stream.ep_name",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_prod_id,
            { "Product Instance Id", "midi.ump.stream.prod_id",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_protocol,
            { "MIDI Protocol", "midi.ump.stream.protocol",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_stream_protocol), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_num,
            { "Function Block Number", "midi.ump.stream.fb.num",
            FT_UINT8, BASE_DEC,
            NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_disc,
            { "asdf", "midi.ump.stream.fb.disc",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_disc_info,
            { "Request Function Block Info", "midi.ump.stream.fb.disc.info",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_disc_name,
            { "Request Function Block Name", "midi.ump.stream.fb.disc.name",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_active,
            { "Active", "midi.ump.stream.fb.active",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_ui_hint,
            { "UI Hint", "midi.ump.stream.fb.ui_hint",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_stream_fb_ui_hint), 0x30,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_midi_1,
            { "MIDI 1.0 Support", "midi.ump.stream.fb.midi_1",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_stream_fb_midi_1), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_dir,
            { "Direction", "midi.ump.stream.fb.dir",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_stream_fb_dir), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_group,
            { "First Group", "midi.ump.stream.fb.group",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_group_span,
            { "Group Span", "midi.ump.stream.fb.group_span",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_ci_version,
            { "MIDI-CI Version", "midi.ump.stream.fb.ci_version",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_sysex8_count,
            { "Max SysEx8 Streams", "midi.ump.stream.fb.sysex8_count",
            FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS,
            VALS(midi_ump_stream_fb_sysex8_count), 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_stream_fb_name,
            { "Function Block Name", "midi.ump.stream.fb.name",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_midi2_channel_status,
            { "Channel Status", "midi.channel_status",
            FT_UINT8, BASE_HEX,
            VALS(midi_ump_midi2_status_name), 0xF0,
            NULL, HFILL }
        },
        { &hf_midi2_attribute_type,
            { "Attribute Type", "midi.attribute_type",
            FT_UINT8, BASE_HEX,
            VALS(midi2_attribute_type), 0,
            NULL, HFILL }
        },
        { &hf_midi2_velocity,
            { "Velocity", "midi.velocity",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_attr_data,
            { "Attribute Data", "midi.attr_data",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_attr_data_pitch_semitones,
            { "Semitone", "midi.attr_data.semitone",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
            &midi_note_values_ext, 0xFE,
            NULL, HFILL }
        },
        { &hf_midi2_attr_data_pitch_fract,
            { "Fraction of Semitone", "midi.attr_data.frac_semitone",
            FT_UINT16, BASE_DEC,
            NULL, 0x01FF,
            NULL, HFILL }
        },
        { &hf_midi2_pressure,
            { "Pressure", "midi.pressure",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_controller_value,
            { "Value", "midi.controller_value",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_program_options,
            { "Options", "midi.program_options",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_program_options_bank_valid,
            { "Bank Valid", "midi.program_options.bank_valid",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi2_program_bank_msb,
            { "Bank MSB", "midi.program_bank_msb",
            FT_UINT8, BASE_DEC,
            NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_midi2_program_bank_lsb,
            { "Bank LSB", "midi.program_bank_lsb",
            FT_UINT8, BASE_DEC,
            NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_midi2_channel_pressure,
            { "Pressure", "midi.channel_pressure",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_pitch_bend,
            { "Pitch Bend", "midi.pitch_bend",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_per_note_controller,
            { "Per-Note Controller", "midi.per_note_controller",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_per_note_controller_value,
            { "Value", "midi.per_note_controller_value",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_param_bank,
            { "Parameter Bank", "midi.param_bank",
            FT_UINT8, BASE_HEX,
            NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_midi2_param_index,
            { "Parameter Index", "midi.param_index",
            FT_UINT8, BASE_HEX,
            NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_midi2_param_value,
            { "Value", "midi.param_value",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_param_delta,
            { "Delta", "midi.param_delta",
            FT_INT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_note_manage,
            { "Options", "midi.note_manage",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi2_note_manage_detach,
            { "Detach Per-Note Controllers", "midi.note_manage.detach",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi2_note_manage_reset,
            { "Reset Per-Note Controllers", "midi.note_manage.reset",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_midi2_per_note_pitch_bend,
            { "Pitch Bend", "midi.per_note_pitch_bend",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_midi_sysex8_manu,
            { "Manufacturer", "midi.sysex8.manu",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex8_device_id,
            { "Device Id", "midi.sysex8.device_id",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex8_sub_id_1,
            { "Sub Id #1", "midi.sysex8.sub_id_1",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex8_sub_id_2,
            { "Sub Id #2", "midi.sysex8.sub_id_2",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_midi_sysex_manu_short,
            { "Manufacturer (short)", "midi.sysex.manufacturer_short",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING,
            &midi_sysex_id_vals_ext, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_manu_long,
            { "Manufacturer (long)", "midi.sysex.manufacturer_long",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING,
            &midi_sysex_extended_id_vals_ext, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_edu_data,
            { "Educational command data", "midi.sysex.edu_data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },

        { &hf_midi_sysex_common_device_id,
            { "Device ID", "midi.sysex.common.device_id",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_common_realtime,
            { "Realtime Type", "midi.sysex.common.realtime",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_rt), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_common_non_realtime,
            { "Non-Realtime Type", "midi.sysex.common.non_realtime",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_nrt), 0x7f,
            NULL, HFILL }
        },

        { &hf_midi_sysex_dump_packet_number,
            { "Packet Number", "midi.sysex.dump.packet_number",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_sample_number,
            { "Sample Number", "midi.sysex.sample_dump.sample_number",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_sample_format,
            { "Sample Format", "midi.sysex.sample_dump.sample_format",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_sample_period,
            { "Sample Period", "midi.sysex.sample_dump.sample_period",
            FT_UINT24, BASE_DEC,
            NULL, 0x7f7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_sample_length,
            { "Sample Length", "midi.sysex.sample_dump.sample_length",
            FT_UINT24, BASE_DEC,
            NULL, 0x7f7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_loop_start,
            { "Sustain Loop Start", "midi.sysex.sample_dump.loop_start",
            FT_UINT24, BASE_DEC,
            NULL, 0x7f7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_loop_end,
            { "Sustain Loop End", "midi.sysex.sample_dump.loop_end",
            FT_UINT24, BASE_DEC,
            NULL, 0x7f7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_loop_type,
            { "Loop Type", "midi.sysex.sample_dump.loop_type",
            FT_UINT8, BASE_DEC,
            VALS(midi_sysex_common_nrt_sample_dump_loop_type), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_packet_count,
            { "Running Packet Count", "midi.sysex.sample_dump.packet_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_packet_check,
            { "Packet Checksum", "midi.sysex.sample_dump.checksum",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_packet_data,
            { "Sample Data", "midi.sysex.sample_dump.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_ext_msg_type,
            { "Sample Dump Extension Message Type", "midi.sysex.sample_dump.ext_msg_type",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_nrt_sd_ext), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_sample_dump_ext_loop_number,
            { "Loop Number", "midi.sysex.sample_dump.loop_number",
            FT_UINT16, BASE_DEC|BASE_SPECIAL_VALS,
            VALS(midi_sysex_common_nrt_sd_loop_number), 0x7f7f,
            NULL, HFILL }
        },

        { &hf_midi_sysex_mtc_type,
            { "MTC Type", "midi.mtc.type",
            FT_UINT8, BASE_HEX,
            VALS(midi_mtc_fm_type_values), 0x60,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_hour,
            { "MTC Hour", "midi.mtc.hour",
            FT_UINT8, BASE_DEC,
            NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_min,
            { "MTC Minute", "midi.mtc.minute",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_sec,
            { "MTC Second", "midi.mtc.second",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_frame,
            { "MTC Frame", "midi.mtc.frame",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_fract_frame,
            { "MTC Fractional Frame", "midi.mtc.fract_frame",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_rt_msg_type,
            { "MTC Realtime Message Type", "midi.mtc.rt_msg_type",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_rt_mtc), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_ub_u1,
            { "MTC User Bits U1", "midi.mtc.user_bits.u1",
            FT_UINT8, BASE_HEX,
            NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_ub_u2,
            { "MTC User Bits U2", "midi.mtc.user_bits.u2",
            FT_UINT8, BASE_HEX,
            NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_ub_u3,
            { "MTC User Bits U3", "midi.mtc.user_bits.u3",
            FT_UINT8, BASE_HEX,
            NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_ub_u4,
            { "MTC User Bits U4", "midi.mtc.user_bits.u4",
            FT_UINT8, BASE_HEX,
            NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_ub_u5,
            { "MTC User Bits U5", "midi.mtc.user_bits.u5",
            FT_UINT8, BASE_HEX,
            NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_ub_u6,
            { "MTC User Bits U6", "midi.mtc.user_bits.u6",
            FT_UINT8, BASE_HEX,
            NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_ub_u7,
            { "MTC User Bits U7", "midi.mtc.user_bits.u7",
            FT_UINT8, BASE_HEX,
            NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_ub_u8,
            { "MTC User Bits U8", "midi.mtc.user_bits.u8",
            FT_UINT8, BASE_HEX,
            NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_ub_u9,
            { "MTC User Bits U9", "midi.mtc.user_bits.u9",
            FT_UINT8, BASE_HEX,
            NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_cue_rt_command,
            { "MTC Cueing RealTime Command", "midi.mtc.cue.rt_command",
            FT_UINT8, BASE_HEX,
            VALS(midi_mtc_sysex_cue_rt), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_cue_nrt_command,
            { "MTC Cueing Non-Realtime Command", "midi.mtc.cue.nrt_command",
            FT_UINT8, BASE_HEX,
            VALS(midi_mtc_sysex_cue_nrt), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_cue_event_num,
            { "MTC Event Number", "midi.mtc.event_num",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mtc_cue_add_info,
            { "MTC Additional Info", "midi.mtc.add_info",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_midi_sysex_gen_info_msg_type,
            { "General Information Message Type", "midi.general_info.msg_type",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_nrt_gi), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_gen_info_device_family,
            { "Device Family", "midi.sysex.general_info.device_family",
            FT_UINT16, BASE_HEX,
            NULL, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_gen_info_family_member,
            { "Device Family Member", "midi.sysex.general_info.device_family_member",
            FT_UINT16, BASE_HEX,
            NULL, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_gen_info_software_rev,
            { "Software Revision", "midi.sysex.general_info.software_revision",
            FT_UINT32, BASE_HEX,
            NULL, 0x7f7f7f7f,
            NULL, HFILL }
        },

        { &hf_midi_sysex_file_dump_msg_type,
            { "File Dump Message Type", "midi.sysex.file_dump.msg_type",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_nrt_fd), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_file_dump_device_id,
            { "File Dump Device ID", "midi.sysex.file_dump.device_id",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_file_dump_file_type,
            { "File Type", "midi.sysex.file_dump.file_type",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_file_dump_file_name,
            { "File Name", "midi.sysex.file_dump.file_name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_file_dump_file_length,
            { "File Length", "midi.sysex.file_dump.file_length",
            FT_UINT32, BASE_DEC,
            NULL, 0x7f7f7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_file_dump_packet_num,
            { "Packet Number", "midi.sysex.file_dump.packet_num",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_file_dump_byte_count,
            { "Packet Byte Count", "midi.sysex.file_dump.byte_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_file_dump_packet_data,
            { "Packet Data", "midi.sysex.file_dump.packet_data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_file_dump_checksum,
            { "Packet Checksum", "midi.sysex.file_dump.checksum",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL }
        },

        { &hf_midi_sysex_tuning_msg_type,
            { "Tuning Message Type", "midi.sysex.tuning.msg_type",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_tuning), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_tuning_program,
            { "Tuning Program", "midi.sysex.tuning.program",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_tuning_name,
            { "Tuning Name", "midi.sysex.tuning.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_tuning_freq,
            { "Frequency", "midi.sysex.tuning.freq",
            FT_UINT24, BASE_HEX,
            NULL, 0x7f7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_tuning_checksum,
            { "Tuning Checksum", "midi.sysex.tuning.checksum",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_tuning_change_count,
            { "Change Count", "midi.sysex.tuning.change_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_common_tune_note,
            { "Note", "midi.sysex.tuning.note",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
            &midi_note_values_ext, 0x7f,
            NULL, HFILL }
        },

        { &hf_midi_sysex_gen_midi_on_off,
            { "General MIDI (GM)", "midi.sysex.general_midi",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_nrt_gm), 0x7f,
            NULL, HFILL }
        },

        { &hf_midi_sysex_msc_command_format,
            { "MSC Command Format", "midi.sysex.msc.command_format",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING,
            &midi_sysex_msc_command_format_ext, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_command,
            { "MSC Command", "midi.sysex.msc.command",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_msc_command), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_q_number,
            { "Q number", "midi.sysex.msc.q_number",
            FT_STRING, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_q_list,
            { "Q list", "midi.sysex.msc.q_list",
            FT_STRING, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_q_path,
            { "Q path", "midi.sysex.msc.q_path",
            FT_STRING, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_q_delimiter,
            { "Delimiter", "midi.sysex.msc.q_delim",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_type,
            { "TC Type", "midi.msc.tc.type",
            FT_UINT8, BASE_HEX,
            VALS(midi_mtc_fm_type_values), 0x60,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_hour,
            { "TC Hour", "midi.msc.tc.hour",
            FT_UINT8, BASE_DEC,
            NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_colour,
            { "TC Colour Frame", "midi.msc.tc.colour",
            FT_BOOLEAN, 8,
            TFS(&tfs_midi_sysex_msc_tc_colour), 0x40,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_min,
            { "TC Minute", "midi.msc.tc.minute",
            FT_UINT8, BASE_DEC,
            NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_sec,
            { "TC Second", "midi.msc.tc.second",
            FT_UINT8, BASE_DEC,
            NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_sign,
            { "TC Sign", "midi.msc.tc.sign",
            FT_BOOLEAN, 8,
            TFS(&tfs_midi_sysex_msc_tc_sign), 0x40,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_final_byte,
            { "TC Final Byte", "midi.msc.tc.final_byte",
            FT_BOOLEAN, 8,
            TFS(&tfs_midi_sysex_msc_tc_final_byte), 0x20,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_frame,
            { "TC Frame", "midi.msc.tc.frame",
            FT_UINT8, BASE_DEC,
            NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_fract_frame,
            { "TC Fractional Frame", "midi.msc.tc.fract_frame",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_stat_est,
            { "TC Estimated", "midi.msc.tc.estimated",
            FT_BOOLEAN, 8,
            TFS(&tfs_midi_sysex_msc_tc_stat_est), 0x40,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_stat_valid,
            { "TC Valid", "midi.msc.tc.valid",
            FT_BOOLEAN, 8,
            TFS(&tfs_invalid_valid), 0x20,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_tc_stat_video,
            { "TC Video", "midi.msc.tc.video",
            FT_BOOLEAN, 8,
            TFS(&tfs_midi_sysex_msc_tc_stat_video), 0x10,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_generic_controller_number,
            { "Controller Number", "midi.sysex.msc.generic_controller_number",
            FT_UINT16, BASE_DEC|BASE_RANGE_STRING|BASE_SPECIAL_VALS,
            RVALS(midi_sysex_msc_generic_controllers), 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_generic_controller_value,
            { "Controller Value", "midi.sysex.msc.generic_controller_value",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_macro_number,
            { "Macro Number", "midi.sysex.msc.macro_number",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_checksum,
            { "Checksum", "midi.sysex.msc.checksum",
            FT_UINT16, BASE_HEX,
            NULL, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_seq_number,
            { "Sequence Number", "midi.sysex.msc.seq_number",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_d1,
            { "d1", "midi.sysex.msc.d1",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_d2,
            { "d2", "midi.sysex.msc.d2",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_d3,
            { "d3", "midi.sysex.msc.d3",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_d4,
            { "d4", "midi.sysex.msc.d4",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_status_code_lighting,
            { "Status Code", "midi.sysex.msc.status_code",
            FT_UINT16, BASE_HEX,
            VALS(midi_sysex_msc_status_codes_lighting), 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_status_code_sound,
            { "Status Code", "midi.sysex.msc.status_code",
            FT_UINT16, BASE_HEX,
            VALS(midi_sysex_msc_status_codes_sound), 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_status_code_machinery,
            { "Status Code", "midi.sysex.msc.status_code",
            FT_UINT16, BASE_HEX,
            VALS(midi_sysex_msc_status_codes_machinery), 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_status_code_video,
            { "Status Code", "midi.sysex.msc.status_code",
            FT_UINT16, BASE_HEX,
            VALS(midi_sysex_msc_status_codes_video), 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_status_code_projection,
            { "Status Code", "midi.sysex.msc.status_code",
            FT_UINT16, BASE_HEX,
            VALS(midi_sysex_msc_status_codes_projection), 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_status_code_process_control,
            { "Status Code", "midi.sysex.msc.status_code",
            FT_UINT16, BASE_HEX,
            VALS(midi_sysex_msc_status_codes_process_control), 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_msc_status_code_pyrotechnics,
            { "Status Code", "midi.sysex.msc.status_code",
            FT_UINT16, BASE_HEX,
            VALS(midi_sysex_msc_status_codes_pyrotechnics), 0x7f7f,
            NULL, HFILL }
        },

        { &hf_midi_sysex_note_info_msg_type,
            { "Notation Information Message Type", "midi.sysex.note_info.msg_type",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_rt_notations), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_note_info_bar_num,
            { "Bar Number", "midi.sysex.note_info.barnum",
            FT_UINT16, BASE_HEX,
            NULL, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_note_info_bytes,
            { "Bytes", "midi.sysex.note_info.bytes",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_note_info_numerator,
            { "Time Signature Numerator", "midi.sysex.note_info.numerator",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_note_info_denominator,
            { "Time Signature Denominator", "midi.sysex.note_info.denominator",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_note_info_midi_clocks,
            { "MIDI clocks in click", "midi.sysex.note_info.midiclock",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_note_info_32nds,
            { "32nd notes in MIDI quarter note", "midi.sysex.note_info.32nds",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },

        { &hf_midi_sysex_dev_ctrl_msg_type,
            { "Device Control Message Type", "midi.sysex.dev_ctrl.msg_type",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_rt_device_control), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_dev_ctrl_volume,
            { "Volume", "midi.sysex.dev_ctrl.volume",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_dev_ctrl_balance,
            { "Balance", "midi.sysex.dev_ctrl.balance",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f7f,
            NULL, HFILL }
        },

        { &hf_midi_sysex_mmc_command,
            { "MIDI Machine Control Command", "midi.sysex.mmc.command",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_rt_mmc_commands), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mmc_response,
            { "MIDI Machine Control Response", "midi.sysex.mmc.response",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_rt_mmc_responses), 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mmc_count,
            { "Data Count", "midi.sysex.mmc.count",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_midi_sysex_mmc_data,
            { "Data", "midi.sysex.mmc.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_midi_sysex_downloadable_sounds_msg_type,
            { "Downloadable Sounds Message", "midi.sysex.dls",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_nrt_dls), 0x7f,
            NULL, HFILL }
        },

        { &hf_midi_sysex_ci_msg_type,
            { "Message Type", "midi.sysex.ci.msg_type",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_nrt_ci), 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_major_version,
            { "Major Version", "midi.sysex.ci.major_version",
            FT_UINT8, BASE_DEC,
            NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_minor_version,
            { "Minor Version", "midi.sysex.ci.minor_version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_src_muid,
            { "Source MUID", "midi.sysex.ci.src_muid",
            FT_UINT32, BASE_HEX|BASE_SPECIAL_VALS,
            VALS(midi_sysex_ci_muid), 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_dst_muid,
            { "Destination MUID", "midi.sysex.ci.dst_muid",
            FT_UINT32, BASE_HEX|BASE_SPECIAL_VALS,
            VALS(midi_sysex_ci_muid), 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_reserved,
            { "Reserved", "midi.sysex.ci.reserved",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prof_id,
            { "Profile Id", "midi.sysex.ci.prof.id",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prof_count_enabled,
            { "Enabled Profile Count", "midi.sysex.ci.prof.count_enabled",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prof_count_disabled,
            { "Disabled Profile Count", "midi.sysex.ci.prof.count_disabled",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prof_chans,
            { "Profile Channel Count", "midi.sysex.ci.prof.chans",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prof_inquiry_target,
            { "Inquiry Target", "midi.sysex.ci.prof.inquiry_target",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prof_inquiry_target_data_len,
            { "Inquiry Target Data Len", "midi.sysex.ci.prof.inquiry_target.data_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prof_inquiry_target_data,
            { "Inquiry Target Data", "midi.sysex.ci.prof.inquiry_target.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prof_data_len,
            { "Profile Specific Data Len", "midi.sysex.ci.prof.data_len",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prof_data,
            { "Profile Specific Data", "midi.sysex.ci.prof.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prop_sim_supported,
            { "Simultaneous Requests Supported", "midi.sysex.ci.prop.sim_supported",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prop_ver_major,
            { "Property Exchange Major Version", "midi.sysex.ci.prop.ver_major",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prop_ver_minor,
            { "Property Exchange Minor Version", "midi.sysex.ci.prop.ver_minor",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prop_request_id,
            { "Request Id", "midi.sysex.ci.prop.request_id",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prop_header_len,
            { "Header Length", "midi.sysex.ci.prop.header_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prop_header,
            { "Header Data", "midi.sysex.ci.prop.header",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prop_chunk_count,
            { "Chunk Count", "midi.sysex.ci.prop.chunk_count",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prop_chunk_num,
            { "Chunk Number", "midi.sysex.ci.prop.chunk_num",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prop_data_len,
            { "Property Data Len", "midi.sysex.ci.prop.data_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_prop_data,
            { "Property Data", "midi.sysex.ci.prop.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_supported_features,
            { "Process Inquiry Supported Features", "midi.sysex.ci.proc.supported_features",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_supported_features_msg_report,
            { "MIDI Message Report", "midi.sysex.ci.proc.supported_features.msg_report",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_message_data_control,
            { "Message Data Control", "midi.sysex.ci.proc.message_data_control",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_ci_proc_message_data_control), 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_system_messages,
            { "Requested System Messages", "midi.sysex.ci.proc.requested_system_messages",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_system_messages_mtc_qf,
            { "MTC Quarter Frame", "midi.sysex.ci.proc.requested_system_messages.mtc_qf",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_system_messages_song_pos,
            { "Song Position", "midi.sysex.ci.proc.requested_system_messages.song_pos",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_system_messages_song_sel,
            { "Song Select", "midi.sysex.ci.proc.requested_system_messages.song_sel",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_channel_messages,
            { "Requested Channel Messages", "midi.sysex.ci.proc.requested_channel_messages",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_channel_messages_pitch_bend,
            { "Pitch Bend", "midi.sysex.ci.proc.requested_channel_messages.pitch_bend",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_channel_messages_cc,
            { "Control Change", "midi.sysex.ci.proc.requested_channel_messages.cc",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_channel_messages_rpn,
            { "RPN", "midi.sysex.ci.proc.requested_channel_messages.rpn",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_channel_messages_nrpn,
            { "NRPN", "midi.sysex.ci.proc.requested_channel_messages.nrpn",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_channel_messages_pc,
            { "Program Change", "midi.sysex.ci.proc.requested_channel_messages.pc",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_channel_messages_pressure,
            { "Channel Pressure", "midi.sysex.ci.proc.requested_channel_messages.pressure",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_note_messages,
            { "Requested Note Messages", "midi.sysex.ci.proc.requested_note_messages",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_note_messages_notes,
            { "Notes", "midi.sysex.ci.proc.requested_note_messages.notes",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_note_messages_pressure,
            { "Poly Pressure", "midi.sysex.ci.proc.requested_note_messages.pressure",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_note_messages_pitch_bend,
            { "Per-Note Pitch Bend", "midi.sysex.ci.proc.requested_note_messages.pitch_bend",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_note_messages_registered_per_note,
            { "Registered Per-Note Controller", "midi.sysex.ci.proc.requested_note_messages.registered_per_note",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_proc_requested_note_messages_assigned_per_note,
            { "Assignable Per-Note Controller", "midi.sysex.ci.proc.requested_note_messages.assigned_per_note",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_device_manu_short,
            { "Device Manufacturer (Short)", "midi.sysex.ci.device_manu_short",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING,
            &midi_sysex_id_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_device_manu_long,
            { "Device Manufacturer (Long)", "midi.sysex.ci.device_manu_long",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING,
            &midi_sysex_extended_id_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_supported_categories,
            { "Supported Ci Categories", "midi.sysex.ci.supported_categories",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_supported_categories_0,
            { "0x00-0x0F Reserved", "midi.sysex.ci.supported_categories.0",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_supported_categories_1,
            { "0x10-0x1F Protocol Negotiation (Deprecated)", "midi.sysex.ci.supported_categories.1",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_supported_categories_2,
            { "0x20-0x2F Profile Configuration", "midi.sysex.ci.supported_categories.2",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_supported_categories_3,
            { "0x30-0x3F Property Exchange", "midi.sysex.ci.supported_categories.3",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_supported_categories_4,
            { "0x40-0x4F Process Inquiry", "midi.sysex.ci.supported_categories.4",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_supported_categories_5,
            { "0x50-0x5F Reserved", "midi.sysex.ci.supported_categories.5",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_supported_categories_6,
            { "0x60-0x6F Reserved", "midi.sysex.ci.supported_categories.6",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_max_sysex,
            { "Maximum SysEx Size", "midi.sysex.ci.max_sysex",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_output_path_id,
            { "Output Path Id", "midi.sysex.ci.output_path_id",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_function_block,
            { "Function Block Number", "midi.sysex.ci.function_block",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_ep_info_status,
            { "Ep Info Status", "midi.sysex.ci.ep_info.status",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_ci_ep_info_status), 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_ep_info_len,
            { "EP Info Data Length", "midi.sysex.ci.ep_info.len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_ep_info_data,
            { "EP Info Data", "midi.sysex.ci.ep_info.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_product_instance_id,
            { "Product Instance Id", "midi.sysex.ci.product_instance_id",
            FT_STRING, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_ack_original_id,
            { "Original Transaction Sub-Id", "midi.sysex.ci.ack.original_id",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_nrt_ci), 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_ack_status_code,
            { "ACK Status Code", "midi.sysex.ci.ack.status_code",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_ci_ack_status_code), 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_ack_status_data,
            { "ACK Status Data", "midi.sysex.ci.ack.status_data",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_ack_details,
            { "ACK Details", "midi.sysex.ci.ack.details",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_ack_msg_len,
            { "Message Len", "midi.sysex.ci.ack.msg_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_ack_message,
            { "Message", "midi.sysex.ci.ack.message",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_invalid_muid,
            { "Target MUID", "midi.sysex.ci.invalid_muid",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_nak_original_id,
            { "Original Transaction Sub-Id", "midi.sysex.ci.nak.original_id",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_common_nrt_ci), 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_nak_status_code,
            { "NAK Status Code", "midi.sysex.ci.nak.status_code",
            FT_UINT8, BASE_HEX,
            VALS(midi_sysex_ci_nak_status_code), 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_nak_status_data,
            { "NAK Status Data", "midi.sysex.ci.nak.status_data",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_nak_details,
            { "NAK Details", "midi.sysex.ci.nak.details",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_nak_msg_len,
            { "Message Len", "midi.sysex.ci.nak.msg_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_sysex_ci_nak_message,
            { "Message", "midi.sysex.ci.nak.message",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_midi_ump_data64_msg_fragments,
            { "Message fragments", "midi.ump.data64.fragments",
            FT_NONE, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_msg_fragment,
            { "Message fragment", "midi.ump.data64.fragment",
            FT_FRAMENUM, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_msg_fragment_overlap,
            { "Message fragment overlap", "midi.ump.data64.fragment.overlap",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_msg_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data",
              "midi.ump.data64.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_msg_fragment_multiple_tails,
            { "Message has multiple tail fragments",
              "midi.ump.data64.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_msg_fragment_too_long_fragment,
            { "Message fragment too long", "midi.ump.data64.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_msg_fragment_error,
            { "Message defragmentation error", "midi.ump.data64.fragment.error",
            FT_FRAMENUM, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_msg_fragment_count,
            { "Message fragment count", "midi.ump.data64.fragment.count",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_msg_reassembled_in,
            { "Reassembled in", "midi.ump.data64.reassembled.in",
            FT_FRAMENUM, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_msg_reassembled_length,
            { "Reassembled length", "midi.ump.data64.reassembled.length",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_midi_ump_data64_msg_reassembled_data,
            { "Reassembled data", "midi.ump.data64.reassembled.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_midi,
        &ett_midi1_command,
        &ett_midi_ump,
        &ett_midi_ump_flex_chord,
        &ett_midi_ump_stream_request,
        &ett_midi_ump_stream_fb_disc,
        &ett_midi2_attr_data,
        &ett_midi2_program_options,
        &ett_midi2_note_manage,
        &ett_midi_sysex_data,
        &ett_midi_sysex_edu,
        &ett_midi_sysex_manu,
        &ett_midi_sysex_common_rt,
        &ett_midi_sysex_common_nrt,
        &ett_midi_sysex_common_tune_note,
        &ett_midi_sysex_ci_proc_supported_features,
        &ett_midi_sysex_ci_proc_requested_system_messages,
        &ett_midi_sysex_ci_proc_requested_channel_messages,
        &ett_midi_sysex_ci_proc_requested_note_messages,
        &ett_midi_sysex_ci_supported_categories,
        &ett_midi_ump_data64_msg_fragment,
        &ett_midi_ump_data64_msg_fragments,
    };


    proto_midi = proto_register_protocol("MIDI", "MIDI", "midi");
    proto_register_field_array(proto_midi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    midi_handle = register_dissector_with_description (
        "midi1",        /* dissector name           */
        "MIDI 1.0",     /* dissector description    */
        dissect_midi1,  /* dissector function       */
        proto_midi       /* protocol being dissected */
    );

    midi_sysex_common_rt_handle = register_dissector("midi_sysex_rt", dissect_sysex7_common_rt, proto_midi);
    midi_sysex_common_nrt_handle = register_dissector("midi_sysex_nrt", dissect_sysex7_common_nrt, proto_midi);
    midi_sysex_common_edu_handle = register_dissector("midi_sysex_edu", dissect_sysex7_common_educational, proto_midi);

    reassembly_table_register(&midi_ump_data64_reassembly_table, &addresses_reassembly_table_functions);

    /* sysex8_dissector_table = register_dissector_table("midi.sysex8.manufacturer",
        "MIDI SysEx8 manufacturer", proto_midi_sysex8, FT_UINT24, BASE_HEX); */
}

void
proto_reg_handoff_midi(void) {
    dissector_add_for_decode_as_with_preference("udp.port", midi_handle);

    sysex_manufacturer_dissector_table = find_dissector_table("midi.sysex.manufacturer");
    dissector_add_uint(
        "midi.sysex.manufacturer",
        MIDI_SYSEX_ID_NON_REAL_TIME_UNIVERSAL_SYSTEM_EXCLUSIVE << 16,
        midi_sysex_common_nrt_handle
    );
    dissector_add_uint(
        "midi.sysex.manufacturer",
        MIDI_SYSEX_ID_REAL_TIME_UNIVERSAL_SYSTEM_EXCLUSIVE << 16,
        midi_sysex_common_rt_handle
    );
    dissector_add_uint(
        "midi.sysex.manufacturer",
        MIDI_SYSEX_ID_EDUCATIONAL_NON_COMMERCIAL_USE << 16,
        midi_sysex_common_edu_handle
    );

    midi_sysex_handle = find_dissector_add_dependency("midi_sysex_inner", proto_midi);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
