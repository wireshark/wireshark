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
#include "data-midi-sysex-id.h"
#include "packet-midi.h"

/* protocols and header fields */
static int proto_midi;
static dissector_handle_t midi_handle;

static dissector_handle_t midi_sysex_common_rt_handle;
static dissector_handle_t midi_sysex_common_nrt_handle;
static dissector_handle_t midi_sysex_common_edu_handle;
static dissector_table_t sysex_manufacturer_dissector_table;

static int ett_midi;
static int ett_midi1_command;

static int ett_midi_sysex_data;
static int ett_midi_sysex_edu;
static int ett_midi_sysex_manu;
static int ett_midi_sysex_common_rt;
static int ett_midi_sysex_common_nrt;
static int ett_midi_sysex_common_tune_note;

static int hf_midi1_command;

static int hf_midi_channel_status;
static int hf_midi_channel;
static int hf_midi1_note;
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


static int hf_midi_sysex_manu_short;
static int hf_midi_sysex_manu_long;
static int hf_midi_sysex_manu_data;
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

/*
 * MIDI Universal Non-Realtime System Exclusive Messages (sysex-manu-id=0x7e)
 */
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
    { MIDI_SYSEX_NRT_END_OF_FILE,            "End Of File" },
    { MIDI_SYSEX_NRT_WAIT,                   "Wait" },
    { MIDI_SYSEX_NRT_CANCEL,                 "Cancel" },
    { MIDI_SYSEX_NRT_NAK,                    "NAK" },
    { MIDI_SYSEX_NRT_ACK,                    "ACK" },
    { 0, NULL }
};

/*
 * MIDI Universal Realtime System Exclusive Messages (sysex-manu-id=0x7F)
 */
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



/* SysEx-Common Non-Realtime */
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

/* SysEx-Common Realtime */
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

/* SysEx-Common Educational */
static int
dissect_sysex7_common_educational(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void* data _U_) {
    /* No real meaning to this, we just take all the data and return */
    proto_tree_add_item(parent_tree, hf_midi_sysex_edu_data, tvb, 0, -1, ENC_NA);
    return tvb_reported_length(tvb);
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
            proto_item* pi = proto_tree_add_uint(command_tree, hf_midi_channel_status, tvb, offset, 0, octet);
            proto_item_set_generated(pi);
            pi = proto_tree_add_uint(command_tree, hf_midi_channel, tvb, offset, 0, octet);
            proto_item_set_generated(pi);
        } else {
            proto_tree_add_item(command_tree, hf_midi_channel_status, tvb, offset, 1, ENC_NA);
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
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_note, tvb, offset, 1, ENC_NA, &a);
                offset += 1;
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_velocity, tvb, offset, 1, ENC_NA, &b);
                offset += 1;
                note_str = val_to_str_ext_const(a, &midi_note_values_ext, "");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s (c=%d, n=%s, v=%d)", status_str, chan, note_str, b);
                proto_item_append_text(command, " %s (c=%d, n=%s, v=%d)", status_str, chan, note_str, b);
                break;
            case MIDI_STATUS_CHAN_NOTE_ON:
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_note, tvb, offset, 1, ENC_NA, &a);
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
                proto_tree_add_item_ret_uint8(command_tree, hf_midi1_note, tvb, offset, 1, ENC_NA, &a);
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

        { &hf_midi_channel_status,
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
        { &hf_midi1_note,
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
        { &hf_midi_sysex_manu_data,
            { "Manufacturer specific data", "midi.sysex.manu_data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
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
            { "MTC Cueing Non-Realtime Commmand", "midi.mtc.cue.nrt_command",
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
    };

    static int *ett[] = {
        &ett_midi,
        &ett_midi1_command,
        &ett_midi_sysex_data,
        &ett_midi_sysex_edu,
        &ett_midi_sysex_manu,
        &ett_midi_sysex_common_rt,
        &ett_midi_sysex_common_nrt,
        &ett_midi_sysex_common_tune_note,
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
