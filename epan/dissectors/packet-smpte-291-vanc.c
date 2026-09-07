/* packet-smpte-291-vanc.c
 * SMPTE ST 291 ancillary-data parsing and built-in VANC application dissectors.
 *
 * Built-in application payloads implemented in this source file:
 *   SMPTE ST 12-2, SMPTE ST 2010, SMPTE ST 2016-3, SMPTE ST 2031,
 *   SMPTE ST 334-2, and Free TV Australia OP-47 / SMPTE RDD 8.
 *
 * Copyright (c) 2026, Devin Heitmueller <dheitmueller@ltnglobal.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <wsutil/bitswap.h>

#include "packet-smpte-291-vanc.h"

/* Protocol, field, subtree, expert, and dissector declarations */

/* SMPTE ST 291 common declarations */
static int proto_st291;
static int hf_st291_did;
static int hf_st291_sdid;
static int hf_st291_dbn;
static dissector_table_t st291_did_sdid_table;

/* SMPTE ST 12-2 declarations */
static int proto_st12_2;
static int hf_st12_2_timecode;
static int hf_st12_2_frame_units;
static int hf_st12_2_frame_tens;
static int hf_st12_2_second_units;
static int hf_st12_2_second_tens;
static int hf_st12_2_minute_units;
static int hf_st12_2_minute_tens;
static int hf_st12_2_hour_units;
static int hf_st12_2_hour_tens;
static int hf_st12_2_binary_group_1;
static int hf_st12_2_binary_group_2;
static int hf_st12_2_binary_group_3;
static int hf_st12_2_binary_group_4;
static int hf_st12_2_binary_group_5;
static int hf_st12_2_binary_group_6;
static int hf_st12_2_binary_group_7;
static int hf_st12_2_binary_group_8;
static int hf_st12_2_flag_bit_10;
static int hf_st12_2_flag_bit_11;
static int hf_st12_2_flag_bit_27;
static int hf_st12_2_flag_bit_43;
static int hf_st12_2_flag_bit_58;
static int hf_st12_2_flag_bit_59;
static int hf_st12_2_payload_type;
static int hf_st12_2_vitc;
static int hf_st12_2_vitc_line_sel;
static int hf_st12_2_vitc_line_dup;
static int hf_st12_2_vitc_validity;
static int hf_st12_2_vitc_process;
static int ett_st12_2;
static int ett_st12_2_timecode;
static int ett_st12_2_vitc;
static expert_field ei_st12_2_bad_length = EI_INIT;
static dissector_handle_t st12_2_handle;

/* SMPTE ST 2010 declarations */
static int proto_st2010;
static int hf_st2010_payload_descriptor;
static int hf_st2010_reserved;
static int hf_st2010_version;
static int hf_st2010_continued_pkt;
static int hf_st2010_following_pkt;
static int hf_st2010_duplicate_msg;
static int hf_st2010_payload;
static int hf_st2010_fragments;
static int hf_st2010_fragment;
static int hf_st2010_fragment_overlap;
static int hf_st2010_fragment_overlap_conflict;
static int hf_st2010_fragment_multiple_tails;
static int hf_st2010_fragment_too_long_fragment;
static int hf_st2010_fragment_error;
static int hf_st2010_fragment_count;
static int hf_st2010_reassembled_in;
static int hf_st2010_reassembled_length;
static int hf_st2010_reassembled_data;
static int ett_st2010;
static int ett_st2010_fragment;
static int ett_st2010_fragments;
static expert_field ei_st2010_bad_version = EI_INIT;
static expert_field ei_st2010_reserved_bits = EI_INIT;
static expert_field ei_st2010_orphan_fragment = EI_INIT;
static expert_field ei_st2010_overlapping_message = EI_INIT;
static expert_field ei_st2010_empty_payload = EI_INIT;
static dissector_handle_t st2010_handle;
static dissector_table_t st2010_payload_table;
static reassembly_table st2010_reassembly_table;

/* SMPTE ST 2016-3 declarations */
static int proto_st2016_3;
static int hf_st2016_3_afd_byte;
static int hf_st2016_3_afd_code;
static int hf_st2016_3_afd_ar;
static int hf_st2016_3_afd_reserved;
static int hf_st2016_3_reserved_1;
static int hf_st2016_3_reserved_2;
static int hf_st2016_3_bar_flags;
static int hf_st2016_3_bar_top;
static int hf_st2016_3_bar_bottom;
static int hf_st2016_3_bar_left;
static int hf_st2016_3_bar_right;
static int hf_st2016_3_bar_reserved;
static int hf_st2016_3_bar_value_1;
static int hf_st2016_3_bar_value_1_marker;
static int hf_st2016_3_bar_value_1_data;
static int hf_st2016_3_bar_value_2;
static int hf_st2016_3_bar_value_2_marker;
static int hf_st2016_3_bar_value_2_data;
static int hf_st2016_3_bar_value_1_meaning;
static int hf_st2016_3_bar_value_2_meaning;
static int ett_st2016_3;
static int ett_st2016_3_afd;
static int ett_st2016_3_bar_flags;
static int ett_st2016_3_bar_value_1;
static int ett_st2016_3_bar_value_2;
static expert_field ei_st2016_3_bad_length;
static expert_field ei_st2016_3_afd_reserved;
static expert_field ei_st2016_3_reserved_udw;
static expert_field ei_st2016_3_bar_reserved;
static expert_field ei_st2016_3_bar_flags_invalid;
static expert_field ei_st2016_3_bar_marker;
static dissector_handle_t st2016_3_handle;

/* SMPTE ST 334-2 declarations */
static int proto_st334_2;
static int hf_st334_2_cdp_identifier;
static int hf_st334_2_cdp_length;
static int hf_st334_2_frame_rate;
static int hf_st334_2_header_reserved;
static int hf_st334_2_time_code_present;
static int hf_st334_2_ccdata_present;
static int hf_st334_2_svcinfo_present;
static int hf_st334_2_svc_info_start;
static int hf_st334_2_svc_info_change;
static int hf_st334_2_svc_info_complete;
static int hf_st334_2_caption_service_active;
static int hf_st334_2_header_reserved_bit;
static int hf_st334_2_header_sequence_counter;
static int hf_st334_2_section_id;
static int hf_st334_2_timecode;
static int hf_st334_2_tc_field_flag;
static int hf_st334_2_drop_frame_flag;
static int hf_st334_2_cc_count;
static int hf_st334_2_cc_marker_bits;
static int hf_st334_2_cc_valid;
static int hf_st334_2_cc_type;
static int hf_st334_2_cc_data_1;
static int hf_st334_2_cc_data_2;
static int hf_st334_2_dtvcc_data;
static int hf_st334_2_svc_reserved;
static int hf_st334_2_svc_info_start_section;
static int hf_st334_2_svc_info_change_section;
static int hf_st334_2_svc_info_complete_section;
static int hf_st334_2_svc_count;
static int hf_st334_2_csn_reserved;
static int hf_st334_2_csn_size;
static int hf_st334_2_csn_reserved_2;
static int hf_st334_2_caption_service_number;
static int hf_st334_2_service_data;
static int hf_st334_2_service_language;
static int hf_st334_2_service_digital_cc;
static int hf_st334_2_service_digital_reserved;
static int hf_st334_2_service_line21_reserved;
static int hf_st334_2_service_line21_field;
static int hf_st334_2_service_descriptor_number;
static int hf_st334_2_service_easy_reader;
static int hf_st334_2_service_wide_aspect_ratio;
static int hf_st334_2_service_reserved_14;
static int hf_st334_2_future_length;
static int hf_st334_2_future_data;
static int hf_st334_2_footer_sequence_counter;
static int hf_st334_2_packet_checksum;
static int hf_st334_2_checksum_calculated;
static int ett_st334_2;
static int ett_st334_2_header;
static int ett_st334_2_timecode;
static int ett_st334_2_ccdata;
static int ett_st334_2_cc_construct;
static int ett_st334_2_svcinfo;
static int ett_st334_2_service;
static int ett_st334_2_service_data;
static int ett_st334_2_future;
static int ett_st334_2_footer;
static expert_field ei_st334_2_bad_identifier;
static expert_field ei_st334_2_bad_length;
static expert_field ei_st334_2_bad_reserved;
static expert_field ei_st334_2_bad_section_order;
static expert_field ei_st334_2_duplicate_section;
static expert_field ei_st334_2_missing_section;
static expert_field ei_st334_2_cc_count;
static expert_field ei_st334_2_bad_marker;
static expert_field ei_st334_2_sequence_mismatch;
static expert_field ei_st334_2_bad_checksum;
static expert_field ei_st334_2_truncated;
static dissector_handle_t st334_2_handle;

/* SMPTE ST 2031 declarations */
static int proto_st2031;
static int hf_st2031_data_identifier;
static int hf_st2031_data_unit_id;
static int hf_st2031_data_unit_length;
static int hf_st2031_field_parity;
static int hf_st2031_line_offset;
static int hf_st2031_framing_code;
static int hf_st2031_magazine_hamming;
static int hf_st2031_magazine;
static int hf_st2031_packet_number_hamming;
static int hf_st2031_packet_number;
static int hf_st2031_page_units_hamming;
static int hf_st2031_page_units;
static int hf_st2031_page_tens_hamming;
static int hf_st2031_page_tens;
static int hf_st2031_data_string;
static int hf_st2031_textdata_array;
static int hf_st2031_erase_page;
static int hf_st2031_newsflash;
static int hf_st2031_subtitle;
static int hf_st2031_suppress_header;
static int hf_st2031_update_indicator;
static int hf_st2031_interrupted_sequence;
static int hf_st2031_inhibit_display;
static int hf_st2031_magazine_serial;
static int hf_st2031_character_set;
static int hf_st2031_tt_control;
static int ett_st2031;
static dissector_handle_t st2031_handle;

/* OP-47 / SMPTE RDD 8 declarations */
static int proto_op47;
static int hf_op47_sdp_identifier;
static int hf_op47_sdp_length;
static int hf_op47_sdp_format_code;
static int hf_op47_sdp_adaption_header;
static int hf_op47_sdp_pkt_desc_b;
static int hf_op47_clock_runin;
static int hf_op47_framing_code;
static int hf_op47_magazine_hamming;
static int hf_op47_magazine;
static int hf_op47_packet_number_hamming;
static int hf_op47_packet_number;
static int hf_op47_page_units_hamming;
static int hf_op47_page_units;
static int hf_op47_page_tens_hamming;
static int hf_op47_page_tens;
static int hf_op47_data_string;
static int hf_op47_textdata_array;
static int hf_op47_erase_page;
static int hf_op47_newsflash;
static int hf_op47_subtitle;
static int hf_op47_suppress_header;
static int hf_op47_update_indicator;
static int hf_op47_interrupted_sequence;
static int hf_op47_inhibit_display;
static int hf_op47_magazine_serial;
static int hf_op47_character_set;
static int hf_op47_tt_control;
static int ett_op47;
static int ett_op47_wst;
static dissector_handle_t op47_handle;

/* ST 291 Type 2 DID/SDID keys used by the built-in VANC dissectors. */
#define ST12_2_DID_SDID_KEY   0x6060
#define ST2010_DID_SDID_KEY   0x4107
#define ST2016_3_DID_SDID_KEY 0x4105
#define ST334_2_DID_SDID_KEY  0x6101
#define ST334_2_CDP_IDENTIFIER 0x9669
#define ST2031_DID_SDID_KEY   0x4108
#define OP47_DID_SDID_KEY     0x4302

#define ST2010_PAYLOAD_SCTE104 0
/*
 * SMPTE ST 291-1 ancillary-data core and DID/SDID dispatch
 */


/*
 * Registered SMPTE ST 291 DID/SDID assignments.
 *
 * SMPTE ST 291-1:2011, Sec. 4 assigns DID values through the SMPTE
 * Registration Authority; Sec. 5.1 defines Type 1 versus Type 2 packets.
 *
 * Source: SMPTE Registration Authority, "Data Identification Word
 * Assignments for Registered DIDs", downloaded from:
 * https://www.smpte-ra.org/smpte-ancillary-data-smpte-st-291
 *
 * The register contained 81 assignments when reviewed on 2026-09-05.
 * Keep this table synchronized with the SMPTE RA register rather than with
 * transport-specific dissectors such as ST 2110-40 or ST 2038.
 */
typedef struct {
    uint8_t did;
    uint8_t sdid;
    const char *description;
} st291_did_sdid_entry_t;

typedef struct {
    uint8_t did;
    const char *description;
} st291_did_entry_t;

/* Type 2 identities: SMPTE ST 291-1:2011, Sec. 5.1 uses DID + SDID. */
static const st291_did_sdid_entry_t st291_did_sdid_assignments[] = {
    { 0x08, 0x08, "SMPTE ST 353: MPEG recoding data, VANC space" },
    { 0x08, 0x0c, "SMPTE ST 353: MPEG recoding data, HANC space" },
    { 0x40, 0x01, "SMPTE ST 305: SDTI transport in active frame space" },
    { 0x40, 0x02, "SMPTE ST 348: HD-SDTI transport in active frame space" },
    { 0x40, 0x04, "SMPTE ST 427: Link Encryption Message 1" },
    { 0x40, 0x05, "SMPTE ST 427: Link Encryption Message 2" },
    { 0x40, 0x06, "SMPTE ST 427: Link Encryption Metadata" },
    { 0x41, 0x01, "SMPTE ST 352: Payload Identification, HANC space" },
    { 0x41, 0x05, "SMPTE ST 2016-3: AFD and Bar Data" },
    { 0x41, 0x06, "SMPTE ST 2016-4: Pan-Scan Data" },
    { 0x41, 0x07, "SMPTE ST 2010: ANSI/SCTE 104 messages" },
    { 0x41, 0x08, "SMPTE ST 2031: DVB/SCTE VBI data" },
    { 0x41, 0x09, "SMPTE ST 2056: MPEG TS packets in VANC" },
    { 0x41, 0x0a, "SMPTE ST 2068: Stereoscopic 3D Frame Compatible Packing and Signaling" },
    { 0x41, 0x0b, "SMPTE ST 2064-2: Lip Sync data as specified by ST 2064-1" },
    { 0x41, 0x0c, "SMPTE ST 2108-1: Extended HDR/WCG for SDI" },
    { 0x41, 0x0d, "SMPTE ST 2108-2: Vertical Ancillary Data Mapping of KLV Formatted HDR/WCG Metadata" },
    { 0x43, 0x01, "ITU-R BT.1685: Structure of inter-station control data conveyed by ancillary data packets" },
    { 0x43, 0x02, "SMPTE RDD 8: Subtitling Distribution packet (SDP)" },
    { 0x43, 0x03, "SMPTE RDD 8: Transport of ANC packet in an ANC Multipacket" },
    { 0x43, 0x04, "ARIB TR-B29: Metadata to monitor errors of audio and video signals on a broadcasting chain" },
    { 0x43, 0x05, "SMPTE RDD 18: Acquisition Metadata Sets for Video Camera Parameters" },
    { 0x44, 0x04, "SMPTE RP 214: KLV Metadata transport in VANC space" },
    { 0x44, 0x14, "SMPTE RP 214: KLV Metadata transport in HANC space" },
    { 0x44, 0x44, "SMPTE RP 223: Packing UMID and Program Identification Label Data into ST 291 ancillary data packets" },
    { 0x45, 0x01, "SMPTE ST 2020-1: Compressed Audio Metadata" },
    { 0x45, 0x02, "SMPTE ST 2020-1: Compressed Audio Metadata" },
    { 0x45, 0x03, "SMPTE ST 2020-1: Compressed Audio Metadata" },
    { 0x45, 0x04, "SMPTE ST 2020-1: Compressed Audio Metadata" },
    { 0x45, 0x05, "SMPTE ST 2020-1: Compressed Audio Metadata" },
    { 0x45, 0x06, "SMPTE ST 2020-1: Compressed Audio Metadata" },
    { 0x45, 0x07, "SMPTE ST 2020-1: Compressed Audio Metadata" },
    { 0x45, 0x08, "SMPTE ST 2020-1: Compressed Audio Metadata" },
    { 0x45, 0x09, "SMPTE ST 2020-1: Compressed Audio Metadata" },
    { 0x46, 0x01, "SMPTE ST 2051: Two Frame Marker in HANC" },
    { 0x50, 0x01, "SMPTE RDD 8: WSS data" },
    { 0x51, 0x01, "SMPTE RP 215: Film Codes in VANC space" },
    { 0x60, 0x60, "SMPTE ST 12-2: Ancillary Time Code" },
    { 0x60, 0x61, "SMPTE ST 12-3: Time Code for High Frame Rate Signals" },
    { 0x60, 0x62, "SMPTE ST 2103: Generic Time Label" },
    { 0x61, 0x01, "SMPTE ST 334-1: EIA 708B Data mapping into VANC space" },
    { 0x61, 0x02, "SMPTE ST 334-1: EIA 608 Data mapping into VANC space" },
    { 0x62, 0x01, "SMPTE RP 207: Program Description in VANC space" },
    { 0x62, 0x02, "SMPTE ST 334-1: Data broadcast (DTV) in VANC space" },
    { 0x62, 0x03, "SMPTE RP 208: VBI Data in VANC space" },
    { 0x64, 0x64, "SMPTE RP 196 (withdrawn): Time Code in HANC space" },
    { 0x64, 0x7f, "SMPTE RP 196 (withdrawn): VITC in HANC space" },
};

/* Type 1 identities: SMPTE ST 291-1:2011, Sec. 5.1 uses DID + DBN. */
static const st291_did_entry_t st291_did_assignments[] = {
    { 0x00, "SMPTE ST 291: Undefined data deleted (deprecated)" },
    { 0x80, "SMPTE ST 291: Packet marked for deletion" },
    { 0x84, "SMPTE ST 291: End packet deleted (deprecated)" },
    { 0x88, "SMPTE ST 291: Start packet deleted (deprecated)" },
    { 0xa0, "SMPTE ST 299-2: Audio data in HANC space (3G), Group 8 Control packet" },
    { 0xa1, "SMPTE ST 299-2: Audio data in HANC space (3G), Group 7 Control packet" },
    { 0xa2, "SMPTE ST 299-2: Audio data in HANC space (3G), Group 6 Control packet" },
    { 0xa3, "SMPTE ST 299-2: Audio data in HANC space (3G), Group 5 Control packet" },
    { 0xa4, "SMPTE ST 299-2: Audio data in HANC space (3G), Group 8" },
    { 0xa5, "SMPTE ST 299-2: Audio data in HANC space (3G), Group 7" },
    { 0xa6, "SMPTE ST 299-2: Audio data in HANC space (3G), Group 6" },
    { 0xa7, "SMPTE ST 299-2: Audio data in HANC space (3G), Group 5" },
    { 0xe0, "SMPTE ST 299-1: Audio data in HANC space (HDTV)" },
    { 0xe1, "SMPTE ST 299-1: Audio data in HANC space (HDTV)" },
    { 0xe2, "SMPTE ST 299-1: Audio data in HANC space (HDTV)" },
    { 0xe3, "SMPTE ST 299-1: Audio data in HANC space (HDTV)" },
    { 0xe4, "SMPTE ST 299-1: Audio data in HANC space (HDTV)" },
    { 0xe5, "SMPTE ST 299-1: Audio data in HANC space (HDTV)" },
    { 0xe6, "SMPTE ST 299-1: Audio data in HANC space (HDTV)" },
    { 0xe7, "SMPTE ST 299-1: Audio data in HANC space (HDTV)" },
    { 0xec, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xed, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xee, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xef, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xf0, "SMPTE ST 315: Camera position (HANC or VANC space)" },
    { 0xf4, "SMPTE RP 165: Error Detection and Handling (HANC space)" },
    { 0xf8, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xf9, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xfa, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xfb, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xfc, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xfd, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xfe, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
    { 0xff, "SMPTE ST 272: Audio data in HANC space (SDTV)" },
};

static const char *
st291_lookup_did(uint8_t did)
{
    unsigned i;

    for (i = 0; i < array_length(st291_did_assignments); i++) {
        if (st291_did_assignments[i].did == did)
            return st291_did_assignments[i].description;
    }
    return NULL;
}

static const char *
st291_lookup_did_sdid(uint8_t did, uint8_t sdid)
{
    unsigned i;

    for (i = 0; i < array_length(st291_did_sdid_assignments); i++) {
        if (st291_did_sdid_assignments[i].did == did &&
            st291_did_sdid_assignments[i].sdid == sdid)
            return st291_did_sdid_assignments[i].description;
    }
    return NULL;
}

dissector_table_t
st291_get_did_sdid_table(void)
{
    return st291_did_sdid_table;
}

/* SMPTE ST 291-1:2011, Secs. 5.1-5.2 -- DID/SDID/DBN on-wire identity fields. */
proto_item *
st291_tree_add_did(proto_tree *tree, tvbuff_t *tvb,
                   int offset, int length, uint8_t did)
{
    return proto_tree_add_uint(tree, hf_st291_did, tvb, offset, length, did);
}

proto_item *
st291_tree_add_sdid(proto_tree *tree, tvbuff_t *tvb,
                    int offset, int length, uint8_t did _U_, uint8_t sdid)
{
    return proto_tree_add_uint(tree, hf_st291_sdid, tvb, offset, length, sdid);
}

/* SMPTE ST 291-1:2011, Sec. 5.1: bit b7 of the DID distinguishes the
 * Type 1 (DBN) and Type 2 (SDID) identity forms used for the lookup. */
void
st291_append_packet_description(proto_item *item, uint8_t did, uint8_t sdid_or_dbn)
{
    const char *description;

    if ((did & 0x80U) != 0)
        description = st291_lookup_did(did);
    else
        description = st291_lookup_did_sdid(did, sdid_or_dbn);

    if (description != NULL)
        proto_item_append_text(item, ": %s", description);
}

proto_item *
st291_tree_add_dbn(proto_tree *tree, tvbuff_t *tvb,
                   int offset, int length, uint8_t dbn)
{
    return proto_tree_add_uint(tree, hf_st291_dbn, tvb, offset, length, dbn);
}

/* SMPTE ST 291-1:2011, Secs. 5.1-5.2 define DID, SDID and DBN.
 * The st291.did_sdid table below is Wireshark-only dispatch metadata. */
void
proto_register_st291(void)
{
    static hf_register_info hf[] = {
        { &hf_st291_did,
          { "Data ID", "st291.did", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
        { &hf_st291_sdid,
          { "Secondary Data ID", "st291.sdid", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
        { &hf_st291_dbn,
          { "Data Block Number", "st291.dbn", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    };

    proto_st291 = proto_register_protocol(
        "SMPTE ST 291 Ancillary Data", "ST 291", "st291");

    proto_register_field_array(proto_st291, hf, array_length(hf));

    /*
     * Public extension point for ST 291 application payload dissectors.
     * Native and Lua dissectors can register DID/SDID keys here for
     * additional VANC payload formats.
     */
    st291_did_sdid_table = register_dissector_table(
        "st291.did_sdid", "SMPTE ST 291 DID/SDID",
        proto_st291, FT_UINT16, BASE_HEX);
}

/*
 * SMPTE ST 12-2 time code in ancillary data
 */


/* SMPTE ST 12-2:2014, Sec. 6.2.1, Table 2 -- DBB1 payload type. */
static const value_string st12_2_payload_type_vals[] = {
    { 0x00, "Linear time code (ATC_LTC)" },
    { 0x01, "Vertical interval time code #1 (ATC_VITC1)" },
    { 0x02, "Vertical interval time code #2 (ATC_VITC2)" },
    { 0x03, "User defined" },
    { 0x04, "User defined" },
    { 0x05, "User defined" },
    { 0x06, "Film data block (transferred from reader)" },
    { 0x07, "Production data block (transferred from reader)" },
    { 0x7D, "Video tape data block (locally generated)" },
    { 0x7E, "Film data block (locally generated)" },
    { 0x7F, "Production data block (locally generated)" },
    { 0, NULL }
};

/* SMPTE ST 12-2:2014, Sec. 6.2.2, Tables 3 and 5 -- DBB2 validity/process bits. */
static const value_string st12_2_vitc_validity_vals[] = {
    { 0, "No time code error received or locally generated time code address" },
    { 1, "Transmitted time code interpolated from previous time code (received a time code error)" },
    { 0, NULL }
};

static const value_string st12_2_vitc_process_vals[] = {
    { 0, "Binary groups in time code data stream are processed to compensate for latency" },
    { 1, "Binary groups in time code data stream are only retransmitted (no delay compensation)" },
    { 0, NULL }
};


/*
 * SMPTE ST 12-2:2014, Sec. 6.3, Table 6 maps the 64 information bits
 * defined by SMPTE ST 12-1 into UDW 1 through UDW 16.  The time address
 * is BCD; the intervening nibbles are the eight binary groups.  The six
 * remaining positions are ST 12-1 flag bits whose meaning depends on the
 * television system/frame rate (ST 12-1:2014, Sec. 8.3 and Tables 1-3).
 */
static int
dissect_st12_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const st291_vanc_dissector_data_t *st291_data =
        (const st291_vanc_dissector_data_t *)data;
    proto_tree *top_tree =
        st291_data && st291_data->top_tree ? st291_data->top_tree : tree;
    proto_item *ti;
    proto_tree *st12_tree;
    proto_tree *time_tree;
    proto_tree *vitc_tree;
    uint8_t dbb1 = 0;
    uint8_t dbb2 = 0;
    uint8_t frame_units;
    uint8_t frame_tens;
    uint8_t second_units;
    uint8_t second_tens;
    uint8_t minute_units;
    uint8_t minute_tens;
    uint8_t hour_units;
    uint8_t hour_tens;
    uint8_t frames;
    uint8_t seconds;
    uint8_t minutes;
    uint8_t hours;
    bool drop_frame;
    char time_str[16];
    unsigned x;

    ti = proto_tree_add_item(top_tree, proto_st12_2, tvb, 0,
                             tvb_captured_length(tvb), ENC_NA);
    st12_tree = proto_item_add_subtree(ti, ett_st12_2);

    if (tvb_captured_length(tvb) < 16) {
        expert_add_info_format(pinfo, ti, &ei_st12_2_bad_length,
                               "ST 12-2 requires at least 16 UDW bytes; packet contains %u",
                               tvb_captured_length(tvb));
        return tvb_captured_length(tvb);
    }

    /*
     * SMPTE ST 12-2:2014, Sec. 6.3, Table 6 maps the 64 information
     * bits defined by SMPTE ST 12-1 into UDW 1 through UDW 16.
     *
     * The time-address digits are BCD:
     *   UDW 1/3   -- frame units/tens
     *   UDW 5/7   -- second units/tens
     *   UDW 9/11  -- minute units/tens
     *   UDW 13/15 -- hour units/tens
     *
     * ST 12-2 Sec. 6.1.2 defines b4 as the least-significant bit of
     * each four-bit information group.
     */
    frame_units  = (tvb_get_uint8(tvb, 0)  >> 4) & 0x0f;
    frame_tens   = (tvb_get_uint8(tvb, 2)  >> 4) & 0x03;
    second_units = (tvb_get_uint8(tvb, 4)  >> 4) & 0x0f;
    second_tens  = (tvb_get_uint8(tvb, 6)  >> 4) & 0x07;
    minute_units = (tvb_get_uint8(tvb, 8)  >> 4) & 0x0f;
    minute_tens  = (tvb_get_uint8(tvb, 10) >> 4) & 0x07;
    hour_units   = (tvb_get_uint8(tvb, 12) >> 4) & 0x0f;
    hour_tens    = (tvb_get_uint8(tvb, 14) >> 4) & 0x03;

    frames  = frame_tens * 10 + frame_units;
    seconds = second_tens * 10 + second_units;
    minutes = minute_tens * 10 + minute_units;
    hours   = hour_tens * 10 + hour_units;

    /*
     * SMPTE ST 12-2:2014, Sec. 6.3, Table 6 maps ST 12-1 bit 10 to
     * UDW 3 b6.  SMPTE ST 12-1:2014, Table 3 identifies bit 10 as
     * the drop-frame flag for the applicable 30-frame systems.
     */
    drop_frame = (tvb_get_uint8(tvb, 2) & 0x40) != 0;

    snprintf(time_str, sizeof(time_str), "%02u:%02u:%02u%c%02u",
             hours, minutes, seconds, drop_frame ? ';' : ':', frames);

    /*
     * This row is a human-readable representation of the 64 information
     * bits below.  It spans the actual UDW bytes rather than being marked
     * generated, so selecting it highlights the complete ATC data block.
     */
    ti = proto_tree_add_string(st12_tree, hf_st12_2_timecode, tvb, 0, 16, time_str);
    time_tree = proto_item_add_subtree(ti, ett_st12_2_timecode);

    /*
     * The BCD digit fields below are the actual on-wire nibbles from
     * ST 12-2:2014, Sec. 6.3, Table 6.  Their hf masks select the
     * corresponding b4-b7 positions in each UDW byte.
     */
    /*
     * SMPTE ST 12-2:2014, Sec. 6.3, Table 6.  Present the fields in
     * UDW order so the protocol tree follows the packet layout directly.
     */
    /* UDW 1: units of frames */
    proto_tree_add_item(time_tree, hf_st12_2_frame_units, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* UDW 2: binary group 1 */
    proto_tree_add_item(time_tree, hf_st12_2_binary_group_1, tvb, 1, 1, ENC_BIG_ENDIAN);

    /* UDW 3: tens of frames, ST 12-1 flag bits 10 and 11 */
    proto_tree_add_item(time_tree, hf_st12_2_frame_tens, tvb, 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(time_tree, hf_st12_2_flag_bit_10, tvb, 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(time_tree, hf_st12_2_flag_bit_11, tvb, 2, 1, ENC_BIG_ENDIAN);

    /* UDW 4: binary group 2 */
    proto_tree_add_item(time_tree, hf_st12_2_binary_group_2, tvb, 3, 1, ENC_BIG_ENDIAN);

    /* UDW 5: units of seconds */
    proto_tree_add_item(time_tree, hf_st12_2_second_units, tvb, 4, 1, ENC_BIG_ENDIAN);

    /* UDW 6: binary group 3 */
    proto_tree_add_item(time_tree, hf_st12_2_binary_group_3, tvb, 5, 1, ENC_BIG_ENDIAN);

    /* UDW 7: tens of seconds, ST 12-1 flag bit 27 */
    proto_tree_add_item(time_tree, hf_st12_2_second_tens, tvb, 6, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(time_tree, hf_st12_2_flag_bit_27, tvb, 6, 1, ENC_BIG_ENDIAN);

    /* UDW 8: binary group 4 */
    proto_tree_add_item(time_tree, hf_st12_2_binary_group_4, tvb, 7, 1, ENC_BIG_ENDIAN);

    /* UDW 9: units of minutes */
    proto_tree_add_item(time_tree, hf_st12_2_minute_units, tvb, 8, 1, ENC_BIG_ENDIAN);

    /* UDW 10: binary group 5 */
    proto_tree_add_item(time_tree, hf_st12_2_binary_group_5, tvb, 9, 1, ENC_BIG_ENDIAN);

    /* UDW 11: tens of minutes, ST 12-1 flag bit 43 */
    proto_tree_add_item(time_tree, hf_st12_2_minute_tens, tvb, 10, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(time_tree, hf_st12_2_flag_bit_43, tvb, 10, 1, ENC_BIG_ENDIAN);

    /* UDW 12: binary group 6 */
    proto_tree_add_item(time_tree, hf_st12_2_binary_group_6, tvb, 11, 1, ENC_BIG_ENDIAN);

    /* UDW 13: units of hours */
    proto_tree_add_item(time_tree, hf_st12_2_hour_units, tvb, 12, 1, ENC_BIG_ENDIAN);

    /* UDW 14: binary group 7 */
    proto_tree_add_item(time_tree, hf_st12_2_binary_group_7, tvb, 13, 1, ENC_BIG_ENDIAN);

    /* UDW 15: tens of hours, ST 12-1 flag bits 58 and 59 */
    proto_tree_add_item(time_tree, hf_st12_2_hour_tens, tvb, 14, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(time_tree, hf_st12_2_flag_bit_58, tvb, 14, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(time_tree, hf_st12_2_flag_bit_59, tvb, 14, 1, ENC_BIG_ENDIAN);

    /* UDW 16: binary group 8 */
    proto_tree_add_item(time_tree, hf_st12_2_binary_group_8, tvb, 15, 1, ENC_BIG_ENDIAN);

    /*
     * SMPTE ST 12-2:2014, Secs. 6.2.1-6.2.2, Tables 2-3.
     * DBB1 is assembled from b4 of UDW 1-8; DBB2 from b4 of UDW 9-16.
     * These bytes are logical fields spread across multiple UDWs, so they
     * are shown as generated aggregate values.
     */
    for (x = 0; x < 8; x++) {
        dbb1 |= tvb_get_bits8(tvb, (x) * 8 + 4, 1) << x;
        dbb2 |= tvb_get_bits8(tvb, (8 + x) * 8 + 4, 1) << x;
    }

    ti = proto_tree_add_uint(st12_tree, hf_st12_2_payload_type, tvb, 0, 0, dbb1);
    proto_item_set_generated(ti);

    ti = proto_tree_add_uint(st12_tree, hf_st12_2_vitc, tvb, 0, 0, dbb2);
    proto_item_set_generated(ti);

    if (dbb1 == 0x01 || dbb1 == 0x02) {
        vitc_tree = proto_item_add_subtree(ti, ett_st12_2_vitc);

        ti = proto_tree_add_uint(vitc_tree, hf_st12_2_vitc_line_sel, tvb, 0, 0, dbb2);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(vitc_tree, hf_st12_2_vitc_line_dup, tvb, 0, 0, dbb2);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(vitc_tree, hf_st12_2_vitc_validity, tvb, 0, 0, dbb2);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(vitc_tree, hf_st12_2_vitc_process, tvb, 0, 0, dbb2);
        proto_item_set_generated(ti);
    }

    proto_item_append_text(proto_tree_get_parent(st12_tree), ": %s", time_str);

    return tvb_captured_length(tvb);
}

void
proto_register_st12_2(void)
{
    static hf_register_info hf[] = {
        { &hf_st12_2_timecode,
          { "Time Code", "st12_2.timecode", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* SMPTE ST 12-2:2014, Sec. 6.3, Table 6. */
        { &hf_st12_2_frame_units,
          { "Frame Units", "st12_2.time.frames.units", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_frame_tens,
          { "Frame Tens", "st12_2.time.frames.tens", FT_UINT8, BASE_DEC, NULL, 0x30, NULL,
            HFILL } },
        { &hf_st12_2_second_units,
          { "Second Units", "st12_2.time.seconds.units", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_second_tens,
          { "Second Tens", "st12_2.time.seconds.tens", FT_UINT8, BASE_DEC, NULL, 0x70, NULL,
            HFILL } },
        { &hf_st12_2_minute_units,
          { "Minute Units", "st12_2.time.minutes.units", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_minute_tens,
          { "Minute Tens", "st12_2.time.minutes.tens", FT_UINT8, BASE_DEC, NULL, 0x70, NULL,
            HFILL } },
        { &hf_st12_2_hour_units,
          { "Hour Units", "st12_2.time.hours.units", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_hour_tens,
          { "Hour Tens", "st12_2.time.hours.tens", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL } },

        /*
         * SMPTE ST 12-2:2014, Sec. 6.3, Table 6;
         * SMPTE ST 12-1:2014, Table 3.
         */
        { &hf_st12_2_flag_bit_10,
          { "ST 12-1 Flag Bit 10 (Drop Frame in 30-frame systems)", "st12_2.flag.bit10",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL } },
        { &hf_st12_2_flag_bit_11,
          { "ST 12-1 Flag Bit 11 (Color Frame in 30/25-frame systems)", "st12_2.flag.bit11",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL } },
        { &hf_st12_2_flag_bit_27,
          { "ST 12-1 Flag Bit 27", "st12_2.flag.bit27", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL } },
        { &hf_st12_2_flag_bit_43,
          { "ST 12-1 Flag Bit 43", "st12_2.flag.bit43", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL } },
        { &hf_st12_2_flag_bit_58,
          { "ST 12-1 Flag Bit 58", "st12_2.flag.bit58", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL } },
        { &hf_st12_2_flag_bit_59,
          { "ST 12-1 Flag Bit 59", "st12_2.flag.bit59", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL } },

        /* SMPTE ST 12-2:2014, Sec. 6.3, Table 6; ST 12-1 Secs. 8.4-8.5. */
        { &hf_st12_2_binary_group_1,
          { "Binary Group 1", "st12_2.binary_group.1", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_binary_group_2,
          { "Binary Group 2", "st12_2.binary_group.2", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_binary_group_3,
          { "Binary Group 3", "st12_2.binary_group.3", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_binary_group_4,
          { "Binary Group 4", "st12_2.binary_group.4", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_binary_group_5,
          { "Binary Group 5", "st12_2.binary_group.5", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_binary_group_6,
          { "Binary Group 6", "st12_2.binary_group.6", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_binary_group_7,
          { "Binary Group 7", "st12_2.binary_group.7", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL,
            HFILL } },
        { &hf_st12_2_binary_group_8,
          { "Binary Group 8", "st12_2.binary_group.8", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL,
            HFILL } },

        /* SMPTE ST 12-2:2014, Sec. 6.2.1, Table 2. */
        { &hf_st12_2_payload_type,
          { "Payload Type", "st12_2.payload_type", FT_UINT8, BASE_HEX,
            VALS(st12_2_payload_type_vals), 0x0, NULL, HFILL } },

        /* SMPTE ST 12-2:2014, Sec. 6.2.2, Tables 3-5. */
        { &hf_st12_2_vitc,
          { "VITC Data", "st12_2.vitc", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_st12_2_vitc_line_sel,
          { "Line Select", "st12_2.vitc.line_sel", FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL } },
        { &hf_st12_2_vitc_line_dup,
          { "Duplication", "st12_2.vitc.line_dup", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL } },
        { &hf_st12_2_vitc_validity,
          { "TC Validity", "st12_2.vitc.validity", FT_UINT8, BASE_DEC,
            VALS(st12_2_vitc_validity_vals), 0x40, NULL, HFILL } },
        { &hf_st12_2_vitc_process,
          { "Process Bit", "st12_2.vitc.process", FT_UINT8, BASE_DEC,
            VALS(st12_2_vitc_process_vals), 0x80, NULL, HFILL } },
    };
    static int *ett[] = {
        &ett_st12_2,
        &ett_st12_2_timecode,
        &ett_st12_2_vitc,
    };
    static ei_register_info ei[] = {
        { &ei_st12_2_bad_length,
          { "st12_2.length.bad", PI_MALFORMED, PI_WARN,
            "ST 12-2 payload contains fewer than 16 UDW bytes", EXPFILL } },
    };
    expert_module_t *expert_st12_2;

    proto_st12_2 = proto_register_protocol(
        "SMPTE ST 12-2 Ancillary Time Code", "ST 12-2", "st12_2");
    proto_register_field_array(proto_st12_2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_st12_2 = expert_register_protocol(proto_st12_2);
    expert_register_field_array(expert_st12_2, ei, array_length(ei));

    st12_2_handle = register_dissector("st12_2", dissect_st12_2, proto_st12_2);
}

void
proto_reg_handoff_st12_2(void)
{
    dissector_add_uint("st291.did_sdid", ST12_2_DID_SDID_KEY, st12_2_handle);
}

/*
 * SMPTE ST 2010 SCTE-104 mapping
 */

static const fragment_items st2010_frag_items = {
    &ett_st2010_fragment,
    &ett_st2010_fragments,
    &hf_st2010_fragments,
    &hf_st2010_fragment,
    &hf_st2010_fragment_overlap,
    &hf_st2010_fragment_overlap_conflict,
    &hf_st2010_fragment_multiple_tails,
    &hf_st2010_fragment_too_long_fragment,
    &hf_st2010_fragment_error,
    &hf_st2010_fragment_count,
    &hf_st2010_reassembled_in,
    &hf_st2010_reassembled_length,
    &hf_st2010_reassembled_data,
    "ST 2010 message fragments"
};

static void
call_st2010_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if (!dissector_try_uint(st2010_payload_table, ST2010_PAYLOAD_SCTE104,
                            tvb, pinfo, tree)) {
        call_data_dissector(tvb, pinfo, tree);
    }
}

/* SMPTE 2010-2008, Sec. 5.2, Tables 1-3; Sec. 5.4 for multi-packet reassembly. */
static int
dissect_st2010(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const st291_vanc_dissector_data_t *st291_data =
        (const st291_vanc_dissector_data_t *)data;
    proto_tree *payload_tree =
        st291_data && st291_data->top_tree ? st291_data->top_tree : tree;
    const unsigned len = tvb_captured_length(tvb);
    uint8_t desc;
    unsigned version;
    bool continued_pkt;
    bool following_pkt;
    bool duplicate_msg;
    proto_item *ti;
    proto_tree *st2010_tree;
    fragment_head *fd_head;
    tvbuff_t *reassembled_tvb;
    bool save_fragmented;

    if (len < 1)
        return 0;

    desc = tvb_get_uint8(tvb, 0);
    version = (desc & 0x18) >> 3;
    continued_pkt = (desc & 0x04) != 0;
    following_pkt = (desc & 0x02) != 0;
    duplicate_msg = (desc & 0x01) != 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ST2010");

    ti = proto_tree_add_item(tree, proto_st2010, tvb, 0, -1, ENC_NA);
    st2010_tree = proto_item_add_subtree(ti, ett_st2010);

    proto_tree_add_item(st2010_tree, hf_st2010_payload_descriptor, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(st2010_tree, hf_st2010_reserved, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(st2010_tree, hf_st2010_version, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(st2010_tree, hf_st2010_continued_pkt, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(st2010_tree, hf_st2010_following_pkt, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(st2010_tree, hf_st2010_duplicate_msg, tvb, 0, 1, ENC_BIG_ENDIAN);

    if ((desc & 0xE0) != 0)
        expert_add_info(pinfo, ti, &ei_st2010_reserved_bits);
    if (version != 1)
        expert_add_info(pinfo, ti, &ei_st2010_bad_version);

    proto_item_append_text(ti, ": version %u%s%s%s",
                           version,
                           continued_pkt ? ", continued" : "",
                           following_pkt ? ", following" : "",
                           duplicate_msg ? ", duplicate" : "");

    if (len <= 1) {
        expert_add_info(pinfo, ti, &ei_st2010_empty_payload);
        return len;
    }

    proto_tree_add_item(st2010_tree, hf_st2010_payload, tvb, 1, -1, ENC_NA);

    /* Single-packet SCTE-104 message. */
    if (!continued_pkt && !following_pkt) {
        tvbuff_t *msg_tvb = tvb_new_subset_remaining(tvb, 1);
        call_st2010_payload(msg_tvb, pinfo, payload_tree);
        return len;
    }

    /*
     * Fragmented ST 2010 message.  ST 2010 supplies no fragment number or
     * message identifier, so fragments are appended in capture order.  The
     * reassembly key is the enclosing flow (addresses + ports) plus ID 0.
     * ST 2010 permits only one complete SCTE-104 message per video frame,
     * so overlapping in-progress messages on one flow are malformed.
     */
    if (!PINFO_FD_VISITED(pinfo)) {
        fragment_head *active = fragment_get(&st2010_reassembly_table, pinfo, 0, NULL);

        if (!following_pkt) {
            if (active != NULL) {
                expert_add_info(pinfo, ti, &ei_st2010_overlapping_message);
                return len;
            }
        } else if (active == NULL) {
            expert_add_info(pinfo, ti, &ei_st2010_orphan_fragment);
            return len;
        }
    }

    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = true;
    fd_head = fragment_add_seq_next(&st2010_reassembly_table,
                                    tvb, 1, pinfo, 0, NULL,
                                    len - 1, continued_pkt);

    reassembled_tvb = process_reassembled_data(tvb, 1, pinfo,
                                                "Reassembled SCTE-104 Message",
                                                fd_head, &st2010_frag_items,
                                                NULL, st2010_tree);
    pinfo->fragmented = save_fragmented;

    if (reassembled_tvb != NULL)
        call_st2010_payload(reassembled_tvb, pinfo, payload_tree);

    return len;
}

void
proto_register_st2010(void)
{
    static hf_register_info hf[] = {
        { &hf_st2010_payload_descriptor,
          { "Payload Descriptor", "st2010.payload_descriptor", FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL } },
        { &hf_st2010_reserved,
          { "Reserved", "st2010.reserved", FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL } },
        { &hf_st2010_version,
          { "Mapping Version", "st2010.version", FT_UINT8, BASE_DEC, NULL, 0x18, NULL, HFILL } },
        { &hf_st2010_continued_pkt,
          { "Continued Packet", "st2010.continued_pkt", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_st2010_following_pkt,
          { "Following Packet", "st2010.following_pkt", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_st2010_duplicate_msg,
          { "Duplicate Message", "st2010.duplicate_msg", FT_BOOLEAN, 8, NULL, 0x01, NULL,
            HFILL } },
        { &hf_st2010_payload,
          { "SCTE-104 Message Bytes", "st2010.payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL,
            HFILL } },

        { &hf_st2010_fragments,

          { "Reassembled ST 2010 fragments", "st2010.fragments", FT_NONE, BASE_NONE, NULL,

            0x00, NULL, HFILL } },
        { &hf_st2010_fragment,
          { "ST 2010 fragment", "st2010.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL,
            HFILL } },
        { &hf_st2010_fragment_overlap,
          { "ST 2010 fragment overlap", "st2010.fragment.overlap", FT_BOOLEAN, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },
        { &hf_st2010_fragment_overlap_conflict,
          { "ST 2010 fragment overlap conflict", "st2010.fragment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_st2010_fragment_multiple_tails,
          { "ST 2010 multiple tail fragments", "st2010.fragment.multiple_tails", FT_BOOLEAN,
            BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_st2010_fragment_too_long_fragment,
          { "ST 2010 fragment too long", "st2010.fragment.too_long_fragment", FT_BOOLEAN,
            BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_st2010_fragment_error,
          { "ST 2010 reassembly error in frame", "st2010.fragment.error", FT_FRAMENUM,
            BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_st2010_fragment_count,
          { "ST 2010 fragment count", "st2010.fragment.count", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },
        { &hf_st2010_reassembled_in,
          { "Reassembled in", "st2010.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL } },
        { &hf_st2010_reassembled_length,
          { "Reassembled length", "st2010.reassembled.length", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },
        { &hf_st2010_reassembled_data,
          { "Reassembled SCTE-104 data", "st2010.reassembled.data", FT_BYTES, BASE_NONE, NULL,
            0x00, NULL, HFILL } },
    };

    static int *ett[] = {
        &ett_st2010,
        &ett_st2010_fragment,
        &ett_st2010_fragments,
    };

    static ei_register_info ei[] = {
        { &ei_st2010_bad_version,
          { "st2010.version.invalid", PI_PROTOCOL, PI_WARN,
            "ST 2010 mapping version is not Version 1", EXPFILL } },
        { &ei_st2010_reserved_bits,
          { "st2010.reserved.nonzero", PI_PROTOCOL, PI_WARN,
            "Reserved Payload Descriptor bits are non-zero", EXPFILL } },
        { &ei_st2010_orphan_fragment,
          { "st2010.fragment.orphan", PI_REASSEMBLE, PI_WARN,
            "Following ST 2010 fragment seen without a preceding first fragment", EXPFILL } },
        { &ei_st2010_overlapping_message,
          { "st2010.fragment.overlap_message", PI_REASSEMBLE, PI_WARN,
            "New ST 2010 message started while another message is still being reassembled",
            EXPFILL } },
        { &ei_st2010_empty_payload,
          { "st2010.payload.empty", PI_MALFORMED, PI_WARN,
            "ST 2010 packet contains a Payload Descriptor but no SCTE-104 bytes", EXPFILL } },
    };

    expert_module_t *expert;

    proto_st2010 = proto_register_protocol("SMPTE ST 2010", "ST 2010", "st2010");
    proto_register_field_array(proto_st2010, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert = expert_register_protocol(proto_st2010);
    expert_register_field_array(expert, ei, array_length(ei));

    reassembly_table_register(&st2010_reassembly_table,
                              &addresses_ports_reassembly_table_functions);

    /*
     * Public payload table. Key 0 is the complete SCTE-104 message. A Lua
     * dissector can register here after all compiled dissectors initialize.
     */
    st2010_payload_table = register_dissector_table(
        "st2010.payload_type", "ST 2010 Payload Type", proto_st2010, FT_UINT8, BASE_DEC);

    st2010_handle = register_dissector("st2010", dissect_st2010, proto_st2010);
}

void
proto_reg_handoff_st2010(void)
{
    dissector_add_uint("st291.did_sdid", ST2010_DID_SDID_KEY, st2010_handle);
}

/*
 * SMPTE ST 2016-3 active format description and bar data
 */

static const struct true_false_string st2016_3_tfs_afd_ar = {
    "16:9 coded frame",
    "4:3 coded frame"
};

/* SMPTE ST 2016-1:2009, Sec. 5, Table 1 -- AFD code meaning depends on coded-frame AR. */
static const char *
st2016_3_afd_description(uint8_t afd, bool ar_16_9)
{
    static const char *const afd_4_3[16] = {
        "Undefined",
        "Reserved",
        "Letterbox 16:9 image, at top of coded frame",
        "Letterbox 14:9 image, at top of coded frame",
        "Letterbox image with aspect ratio greater than 16:9, vertically centered",
        "Reserved",
        "Reserved",
        "Reserved",
        "Full frame 4:3 image, same as coded frame",
        "Full frame 4:3 image, same as coded frame",
        "Letterbox 16:9 image, vertically centered, all image areas protected",
        "Letterbox 14:9 image, vertically centered",
        "Reserved",
        "Full frame 4:3 image, with alternative 14:9 center",
        "Letterbox 16:9 image, with alternative 14:9 center",
        "Letterbox 16:9 image, with alternative 4:3 center"
    };
    static const char *const afd_16_9[16] = {
        "Undefined",
        "Reserved",
        "Full frame 16:9 image, same as coded frame",
        "Pillarbox 14:9 image, horizontally centered",
        "Letterbox image with aspect ratio greater than 16:9, vertically centered",
        "Reserved",
        "Reserved",
        "Reserved",
        "Full frame 16:9 image, same as coded frame",
        "Pillarbox 4:3 image, horizontally centered",
        "Full frame 16:9 image, all image areas protected",
        "Pillarbox 14:9 image, horizontally centered",
        "Reserved",
        "Pillarbox 4:3 image, with alternative 14:9 center",
        "Full frame 16:9 image, with alternative 14:9 center",
        "Full frame 16:9 image, with alternative 4:3 center"
    };

    return ar_16_9 ? afd_16_9[afd & 0x0f] : afd_4_3[afd & 0x0f];
}

/* SMPTE ST 2016-1:2009, Secs. 6, 9.2.1-9.2.2, Tables 3, 5 and 6. */
static const char *
st2016_3_bar_value_meaning(unsigned value_index, bool top, bool bottom, bool left, bool right)
{
    if (value_index == 1) {
        if (top)
            return "Line number: end of top bar";
        if (bottom)
            return "Line number: start of bottom bar";
        if (left)
            return "Pixel number: end of left bar";
        if (right)
            return "Pixel number: start of right bar";
    } else {
        if (top && bottom)
            return "Line number: start of bottom bar";
        if (left && right)
            return "Pixel number: start of right bar";
    }

    return "No valid Bar Data value";
}

static int
dissect_st2016_3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const st291_vanc_dissector_data_t *st291_data =
        (const st291_vanc_dissector_data_t *)data;
    proto_tree *top_tree =
        st291_data && st291_data->top_tree ? st291_data->top_tree : tree;
    proto_item *ti;
    proto_item *root_ti;
    proto_tree *st2016_tree;
    proto_tree *afd_tree;
    proto_tree *flags_tree;
    proto_tree *value_tree;
    unsigned len = tvb_captured_length(tvb);
    uint8_t afd_byte;
    uint8_t afd;
    bool ar_16_9;
    uint8_t flags;
    bool top;
    bool bottom;
    bool left;
    bool right;
    uint16_t value1;
    uint16_t value2;
    const char *meaning1;
    const char *meaning2;

    root_ti = proto_tree_add_item(top_tree, proto_st2016_3, tvb, 0, len, ENC_NA);
    st2016_tree = proto_item_add_subtree(root_ti, ett_st2016_3);

    if (len != 8) {
        expert_add_info_format(pinfo, root_ti, &ei_st2016_3_bad_length,
                               "ST 2016-3 requires 8 UDW bytes; packet contains %u",
                               len);
        return len;
    }

    /* SMPTE ST 2016-3:2009, Sec. 4.1, Table 1 maps UDW1 to the
     * ST 2016-1 AFD byte; ST 2016-1:2009, Sec. 9.1, Table 4 defines
     * reserved bits, active_format and coded_frame_aspect_ratio. */
    afd_byte = tvb_get_uint8(tvb, 0);
    afd = (afd_byte >> 3) & 0x0f;
    ar_16_9 = (afd_byte & 0x04) != 0;

    ti = proto_tree_add_item(st2016_tree, hf_st2016_3_afd_byte, tvb, 0, 1, ENC_BIG_ENDIAN);
    afd_tree = proto_item_add_subtree(ti, ett_st2016_3_afd);
    proto_tree_add_item(afd_tree, hf_st2016_3_afd_reserved, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format_value(afd_tree, hf_st2016_3_afd_code, tvb, 0, 1, afd,
                                     "%u (%s)", afd,
                                     st2016_3_afd_description(afd, ar_16_9));
    proto_tree_add_item(afd_tree, hf_st2016_3_afd_ar, tvb, 0, 1, ENC_BIG_ENDIAN);

    if ((afd_byte & 0x83) != 0)
        expert_add_info(pinfo, ti, &ei_st2016_3_afd_reserved);

    /* SMPTE ST 2016-3:2009, Sec. 4.1, Table 1 -- UDW2 and UDW3 are reserved. */
    ti = proto_tree_add_item(st2016_tree, hf_st2016_3_reserved_1, tvb, 1, 1, ENC_BIG_ENDIAN);
    if (tvb_get_uint8(tvb, 1) != 0)
        expert_add_info(pinfo, ti, &ei_st2016_3_reserved_udw);

    ti = proto_tree_add_item(st2016_tree, hf_st2016_3_reserved_2, tvb, 2, 1, ENC_BIG_ENDIAN);
    if (tvb_get_uint8(tvb, 2) != 0)
        expert_add_info(pinfo, ti, &ei_st2016_3_reserved_udw);

    /* SMPTE ST 2016-3:2009, Sec. 4.1, Table 1 maps UDW4 to Bar Data flags;
     * SMPTE ST 2016-1:2009, Sec. 9.2.1, Table 5 defines top/bottom/left/right. */
    flags = tvb_get_uint8(tvb, 3);
    top = (flags & 0x80) != 0;
    bottom = (flags & 0x40) != 0;
    left = (flags & 0x20) != 0;
    right = (flags & 0x10) != 0;

    ti = proto_tree_add_item(st2016_tree, hf_st2016_3_bar_flags, tvb, 3, 1, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti, ett_st2016_3_bar_flags);
    proto_tree_add_item(flags_tree, hf_st2016_3_bar_top, tvb, 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_st2016_3_bar_bottom, tvb, 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_st2016_3_bar_left, tvb, 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_st2016_3_bar_right, tvb, 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_st2016_3_bar_reserved, tvb, 3, 1, ENC_BIG_ENDIAN);

    if ((flags & 0x0f) != 0)
        expert_add_info(pinfo, ti, &ei_st2016_3_bar_reserved);

    if ((top != bottom) || (left != right) || ((top || bottom) && (left || right)))
        expert_add_info(pinfo, ti, &ei_st2016_3_bar_flags_invalid);

    /* SMPTE ST 2016-3:2009, Sec. 4.1, Table 1 maps UDW5-UDW8 to
     * Bar Data Value 1/2; ST 2016-1:2009, Sec. 9.2.2, Table 6 defines
     * marker bits and the 14-bit line/pixel values. */
    value1 = tvb_get_ntohs(tvb, 4);
    value2 = tvb_get_ntohs(tvb, 6);
    meaning1 = st2016_3_bar_value_meaning(1, top, bottom, left, right);
    meaning2 = st2016_3_bar_value_meaning(2, top, bottom, left, right);

    ti = proto_tree_add_item(st2016_tree, hf_st2016_3_bar_value_1, tvb, 4, 2, ENC_BIG_ENDIAN);
    value_tree = proto_item_add_subtree(ti, ett_st2016_3_bar_value_1);
    proto_tree_add_item(value_tree, hf_st2016_3_bar_value_1_marker, tvb, 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(value_tree, hf_st2016_3_bar_value_1_data, tvb, 4, 2, ENC_BIG_ENDIAN);
    ti = proto_tree_add_string(value_tree, hf_st2016_3_bar_value_1_meaning, tvb, 4, 0,
                               meaning1);
    proto_item_set_generated(ti);

    ti = proto_tree_add_item(st2016_tree, hf_st2016_3_bar_value_2, tvb, 6, 2, ENC_BIG_ENDIAN);
    value_tree = proto_item_add_subtree(ti, ett_st2016_3_bar_value_2);
    proto_tree_add_item(value_tree, hf_st2016_3_bar_value_2_marker, tvb, 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(value_tree, hf_st2016_3_bar_value_2_data, tvb, 6, 2, ENC_BIG_ENDIAN);
    ti = proto_tree_add_string(value_tree, hf_st2016_3_bar_value_2_meaning, tvb, 6, 0,
                               meaning2);
    proto_item_set_generated(ti);

    if (top || bottom || left || right) {
        if ((value1 & 0xc000) != 0xc000)
            expert_add_info(pinfo, ti, &ei_st2016_3_bar_marker);
        if ((top && bottom) || (left && right)) {
            if ((value2 & 0xc000) != 0xc000)
                expert_add_info(pinfo, ti, &ei_st2016_3_bar_marker);
        }
    }

    proto_item_append_text(root_ti, ": AFD: %s in %s mode",
                           st2016_3_afd_description(afd, ar_16_9),
                           ar_16_9 ? "16:9" : "4:3");

    return len;
}

void
proto_register_st2016_3(void)
{
    static hf_register_info hf[] = {
        { &hf_st2016_3_afd_byte,
          { "AFD Information", "st2016_3.afd", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_st2016_3_afd_code,
          { "AFD Code", "st2016_3.afd.code", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_st2016_3_afd_ar,
          { "Coded Frame Aspect Ratio", "st2016_3.afd.ar", FT_BOOLEAN, 8,
            TFS(&st2016_3_tfs_afd_ar), 0x04, NULL, HFILL } },
        { &hf_st2016_3_afd_reserved,
          { "Reserved", "st2016_3.afd.reserved", FT_UINT8, BASE_HEX, NULL, 0x83, NULL, HFILL } },
        { &hf_st2016_3_reserved_1,
          { "Reserved UDW 2", "st2016_3.reserved1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_st2016_3_reserved_2,
          { "Reserved UDW 3", "st2016_3.reserved2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_st2016_3_bar_flags,
          { "Bar Data Flags", "st2016_3.bar.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_st2016_3_bar_top,
          { "Top Bar Present", "st2016_3.bar.top", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL } },
        { &hf_st2016_3_bar_bottom,
          { "Bottom Bar Present", "st2016_3.bar.bottom", FT_BOOLEAN, 8, NULL, 0x40, NULL,
            HFILL } },
        { &hf_st2016_3_bar_left,
          { "Left Bar Present", "st2016_3.bar.left", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL } },
        { &hf_st2016_3_bar_right,
          { "Right Bar Present", "st2016_3.bar.right", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
        { &hf_st2016_3_bar_reserved,
          { "Reserved", "st2016_3.bar.reserved", FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL } },
        { &hf_st2016_3_bar_value_1,
          { "Bar Data Value 1", "st2016_3.bar.value1", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_st2016_3_bar_value_1_marker,
          { "Marker Bits", "st2016_3.bar.value1.marker", FT_UINT16, BASE_HEX, NULL, 0xc000,
            NULL, HFILL } },
        { &hf_st2016_3_bar_value_1_data,
          { "Line/Pixel Number", "st2016_3.bar.value1.data", FT_UINT16, BASE_DEC, NULL,
            0x3fff, NULL, HFILL } },
        { &hf_st2016_3_bar_value_2,
          { "Bar Data Value 2", "st2016_3.bar.value2", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_st2016_3_bar_value_2_marker,
          { "Marker Bits", "st2016_3.bar.value2.marker", FT_UINT16, BASE_HEX, NULL, 0xc000,
            NULL, HFILL } },
        { &hf_st2016_3_bar_value_2_data,
          { "Line/Pixel Number", "st2016_3.bar.value2.data", FT_UINT16, BASE_DEC, NULL,
            0x3fff, NULL, HFILL } },
        { &hf_st2016_3_bar_value_1_meaning,
          { "Meaning", "st2016_3.bar.value1.meaning", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
        { &hf_st2016_3_bar_value_2_meaning,
          { "Meaning", "st2016_3.bar.value2.meaning", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
    };

    static int *ett[] = {
        &ett_st2016_3,
        &ett_st2016_3_afd,
        &ett_st2016_3_bar_flags,
        &ett_st2016_3_bar_value_1,
        &ett_st2016_3_bar_value_2,
    };

    static ei_register_info ei[] = {
        { &ei_st2016_3_bad_length,
          { "st2016_3.length.bad", PI_MALFORMED, PI_WARN,
            "ST 2016-3 payload length is not 8 bytes", EXPFILL } },
        { &ei_st2016_3_afd_reserved,
          { "st2016_3.afd.reserved.bad", PI_PROTOCOL, PI_WARN,
            "Reserved AFD bits are not zero", EXPFILL } },
        { &ei_st2016_3_reserved_udw,
          { "st2016_3.reserved_udw.bad", PI_PROTOCOL, PI_WARN,
            "Reserved ST 2016-3 UDW is not zero", EXPFILL } },
        { &ei_st2016_3_bar_reserved,
          { "st2016_3.bar.reserved.bad", PI_PROTOCOL, PI_WARN,
            "Reserved Bar Data flag bits are not zero", EXPFILL } },
        { &ei_st2016_3_bar_flags_invalid,
          { "st2016_3.bar.flags.invalid", PI_PROTOCOL, PI_WARN,
            "Bar Data flags must specify Top+Bottom, Left+Right, or no bars", EXPFILL } },
        { &ei_st2016_3_bar_marker,
          { "st2016_3.bar.marker.bad", PI_PROTOCOL, PI_WARN,
            "Bar Data value marker bits are not binary '11'", EXPFILL } },
    };

    expert_module_t *expert_st2016_3;

    proto_st2016_3 = proto_register_protocol(
        "SMPTE ST 2016-3 AFD and Bar Data", "ST 2016-3", "st2016_3");

    proto_register_field_array(proto_st2016_3, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_st2016_3 = expert_register_protocol(proto_st2016_3);
    expert_register_field_array(expert_st2016_3, ei, array_length(ei));

    st2016_3_handle =
        register_dissector("st2016_3", dissect_st2016_3, proto_st2016_3);
}

void
proto_reg_handoff_st2016_3(void)
{
    dissector_add_uint("st291.did_sdid", ST2016_3_DID_SDID_KEY, st2016_3_handle);
}

/*
 * SMPTE ST 334-2 Caption Distribution Packet
 */


/* SMPTE ST 334-2:2015, Sec. 5.2, Table 3 -- cdp_frame_rate values. */
static const value_string st334_2_frame_rate_vals[] = {
    { 0x0, "Forbidden" },
    { 0x1, "24000/1001 (~23.976 fps)" },
    { 0x2, "24 fps" },
    { 0x3, "25 fps" },
    { 0x4, "30000/1001 (~29.97 fps)" },
    { 0x5, "30 fps" },
    { 0x6, "50 fps" },
    { 0x7, "60000/1001 (~59.94 fps)" },
    { 0x8, "60 fps" },
    { 0, NULL }
};

/* SMPTE ST 334-2:2015, Sec. 5.1, Table 1; Secs. 5.3-5.7 -- CDP section IDs. */
static const value_string st334_2_section_id_vals[] = {
    { 0x71, "Time Code Section" },
    { 0x72, "CC Data Section" },
    { 0x73, "CC Service Information Section" },
    { 0x74, "CDP Footer" },
    { 0, NULL }
};

/* SMPTE ST 334-2:2015, Sec. 5.4, Table 5; cc_type semantics are inherited from CEA-708. */
static const value_string st334_2_cc_type_vals[] = {
    { 0x0, "NTSC line 21 field 1 closed captions (CEA-608)" },
    { 0x1, "NTSC line 21 field 2 closed captions (CEA-608)" },
    { 0x2, "DTVCC channel packet data" },
    { 0x3, "DTVCC channel packet start" },
    { 0, NULL }
};

static const struct true_false_string st334_2_tfs_present = {
    "Present", "Not present"
};

static const struct true_false_string st334_2_tfs_valid = {
    "Valid", "Invalid"
};

/* SMPTE ST 334-2:2015, Sec. 5.4, Table 5 -- required cc_count for each cdp_frame_rate. */
static unsigned
st334_2_expected_cc_count(uint8_t frame_rate)
{
    switch (frame_rate) {
    case 0x1:
    case 0x2:
        return 25;
    case 0x3:
        return 24;
    case 0x4:
    case 0x5:
        return 20;
    case 0x6:
        return 12;
    case 0x7:
    case 0x8:
        return 10;
    default:
        return 0;
    }
}

/* SMPTE ST 334-2:2015, Sec. 5.6, Table 7 -- CDP checksum makes the modulo-256 packet sum zero. */
static uint8_t
st334_2_cdp_checksum(tvbuff_t *tvb, unsigned length)
{
    unsigned i;
    uint8_t sum = 0;

    for (i = 0; i < length; i++)
        sum = (uint8_t)(sum + tvb_get_uint8(tvb, i));

    return sum;
}

/* SMPTE ST 334-2:2015, Sec. 5.1, Table 1 -- required CDP section ordering. */
static unsigned
st334_2_section_rank(uint8_t id)
{
    switch (id) {
    case 0x71: return 1;
    case 0x72: return 2;
    case 0x73: return 3;
    case 0x74: return 5;
    default:
        if (id >= 0x75 && id <= 0xef)
            return 4;
        return 0;
    }
}

/* SMPTE ST 334-2:2015, Sec. 5, Tables 1-8 -- complete CDP syntax. */
static int
dissect_st334_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const st291_vanc_dissector_data_t *st291_data =
        (const st291_vanc_dissector_data_t *)data;
    proto_tree *top_tree = st291_data && st291_data->top_tree ?
        st291_data->top_tree : tree;
    proto_item *ti;
    proto_item *root_ti;
    proto_tree *cdp_tree;
    proto_tree *header_tree;
    unsigned captured_len = tvb_captured_length(tvb);
    unsigned parse_len;
    unsigned offset;
    unsigned previous_rank = 0;
    uint16_t identifier;
    uint8_t declared_len;
    uint8_t frame_rate;
    uint8_t flags;
    uint16_t header_sequence;
    bool time_present;
    bool cc_present;
    bool svc_present;
    bool seen_time = false;
    bool seen_cc = false;
    bool seen_svc = false;
    bool seen_footer = false;

    ti = proto_tree_add_item(top_tree, proto_st334_2, tvb, 0, -1, ENC_NA);
    cdp_tree = proto_item_add_subtree(ti, ett_st334_2);

    if (captured_len < 7) {
        expert_add_info_format(pinfo, ti, &ei_st334_2_bad_length,
                               "ST 334-2 requires at least 7 UDW bytes; packet contains %u",
                               captured_len);
        return captured_len;
    }

    identifier = tvb_get_ntohs(tvb, 0);
    declared_len = tvb_get_uint8(tvb, 2);
    frame_rate = (tvb_get_uint8(tvb, 3) >> 4) & 0x0f;
    flags = tvb_get_uint8(tvb, 4);
    header_sequence = tvb_get_ntohs(tvb, 5);

    if (declared_len < 7 || declared_len > captured_len)
        parse_len = captured_len;
    else
        parse_len = declared_len;

    root_ti = ti;
    proto_item_set_len(ti, parse_len);
    proto_item_append_text(ti, ", sequence %u", header_sequence);

    /* SMPTE ST 334-2:2015, Sec. 5.2, Tables 2-3 -- cdp_header(). */
    header_tree = proto_tree_add_subtree(cdp_tree, tvb, 0, 7,
                                         ett_st334_2_header, NULL, "CDP Header");

    ti = proto_tree_add_item(header_tree, hf_st334_2_cdp_identifier, tvb, 0, 2, ENC_BIG_ENDIAN);
    if (identifier != ST334_2_CDP_IDENTIFIER)
        expert_add_info_format(pinfo, ti, &ei_st334_2_bad_identifier,
                               "CDP identifier is 0x%04x; expected 0x%04x",
                               identifier, ST334_2_CDP_IDENTIFIER);

    ti = proto_tree_add_item(header_tree, hf_st334_2_cdp_length, tvb, 2, 1, ENC_BIG_ENDIAN);
    if (declared_len != captured_len)
        expert_add_info_format(pinfo, ti, &ei_st334_2_bad_length,
                               "CDP length is %u bytes, but ST 291 UDW payload contains %u bytes",
                               declared_len, captured_len);

    proto_tree_add_item(header_tree, hf_st334_2_frame_rate, tvb, 3, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(header_tree, hf_st334_2_header_reserved, tvb, 3, 1, ENC_BIG_ENDIAN);
    if ((tvb_get_uint8(tvb, 3) & 0x0f) != 0x0f)
        expert_add_info(pinfo, ti, &ei_st334_2_bad_reserved);

    proto_tree_add_item(header_tree, hf_st334_2_time_code_present, tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(header_tree, hf_st334_2_ccdata_present, tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(header_tree, hf_st334_2_svcinfo_present, tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(header_tree, hf_st334_2_svc_info_start, tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(header_tree, hf_st334_2_svc_info_change, tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(header_tree, hf_st334_2_svc_info_complete, tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(header_tree, hf_st334_2_caption_service_active, tvb, 4, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(header_tree, hf_st334_2_header_reserved_bit, tvb, 4, 1, ENC_BIG_ENDIAN);
    if ((flags & 0x01) == 0)
        expert_add_info(pinfo, ti, &ei_st334_2_bad_reserved);

    proto_tree_add_item(header_tree, hf_st334_2_header_sequence_counter, tvb, 5, 2, ENC_BIG_ENDIAN);

    time_present = (flags & 0x80) != 0;
    cc_present = (flags & 0x40) != 0;
    svc_present = (flags & 0x20) != 0;

    offset = 7;
    while (offset < parse_len) {
        uint8_t id;
        unsigned rank;
        unsigned section_len = 0;

        if (!tvb_bytes_exist(tvb, offset, 1))
            break;

        id = tvb_get_uint8(tvb, offset);
        rank = st334_2_section_rank(id);

        if (rank != 0 && rank < previous_rank) {
            ti = proto_tree_add_item(cdp_tree, hf_st334_2_section_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            expert_add_info(pinfo, ti, &ei_st334_2_bad_section_order);
        }
        if (rank != 0 && rank > previous_rank)
            previous_rank = rank;

        /* SMPTE ST 334-2:2015, Sec. 5.3, Table 4 -- time_code_section(). */
        if (id == 0x71) {
            proto_tree *section_tree;
            uint8_t b1, b2, b3, b4;
            unsigned hours, minutes, seconds, frames;
            char time_str[48];

            if (!tvb_bytes_exist(tvb, offset, 5) || offset + 5 > parse_len) {
                expert_add_info_format(pinfo, root_ti, &ei_st334_2_truncated,
                                       "Truncated CDP time code section");
                break;
            }
            section_len = 5;
            section_tree = proto_tree_add_subtree(cdp_tree, tvb, offset, section_len,
                                                  ett_st334_2_timecode, NULL, "Time Code Section");
            ti = proto_tree_add_item(section_tree, hf_st334_2_section_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (seen_time)
                expert_add_info(pinfo, ti, &ei_st334_2_duplicate_section);
            seen_time = true;

            b1 = tvb_get_uint8(tvb, offset + 1);
            b2 = tvb_get_uint8(tvb, offset + 2);
            b3 = tvb_get_uint8(tvb, offset + 3);
            b4 = tvb_get_uint8(tvb, offset + 4);

            hours = ((b1 >> 4) & 0x03) * 10 + (b1 & 0x0f);
            minutes = ((b2 >> 4) & 0x07) * 10 + (b2 & 0x0f);
            seconds = ((b3 >> 4) & 0x07) * 10 + (b3 & 0x0f);
            frames = ((b4 >> 4) & 0x03) * 10 + (b4 & 0x0f);
            snprintf(time_str, sizeof(time_str), "%02u:%02u:%02u:%02u",
                       hours, minutes, seconds, frames);
            ti = proto_tree_add_string(section_tree, hf_st334_2_timecode, tvb, offset + 1, 4, time_str);
            proto_item_set_generated(ti);
            proto_tree_add_item(section_tree, hf_st334_2_tc_field_flag, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(section_tree, hf_st334_2_drop_frame_flag, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        } else if (id == 0x72) {
            /* SMPTE ST 334-2:2015, Sec. 5.4, Table 5 -- ccdata_section(). */
            proto_tree *section_tree;
            unsigned count;
            unsigned expected;
            unsigned i;
            unsigned dtvcc_len = 0;
            uint8_t *dtvcc_data;

            if (!tvb_bytes_exist(tvb, offset, 2) || offset + 2 > parse_len) {
                expert_add_info_format(pinfo, root_ti, &ei_st334_2_truncated,
                                       "Truncated CDP CC data section header");
                break;
            }
            count = tvb_get_uint8(tvb, offset + 1) & 0x1f;
            section_len = 2 + 3 * count;
            if (!tvb_bytes_exist(tvb, offset, section_len) || offset + section_len > parse_len) {
                expert_add_info_format(pinfo, root_ti, &ei_st334_2_truncated,
                                       "CC data section requires %u bytes but packet ends early",
                                       section_len);
                break;
            }

            section_tree = proto_tree_add_subtree(cdp_tree, tvb, offset, section_len,
                                                  ett_st334_2_ccdata, NULL, "CC Data Section");
            ti = proto_tree_add_item(section_tree, hf_st334_2_section_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (seen_cc)
                expert_add_info(pinfo, ti, &ei_st334_2_duplicate_section);
            seen_cc = true;

            ti = proto_tree_add_item(section_tree, hf_st334_2_cc_count, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            if ((tvb_get_uint8(tvb, offset + 1) & 0xe0) != 0xe0)
                expert_add_info(pinfo, ti, &ei_st334_2_bad_marker);

            expected = st334_2_expected_cc_count(frame_rate);
            if (expected != 0 && count != expected)
                expert_add_info_format(pinfo, ti, &ei_st334_2_cc_count,
                                       "cc_count is %u; frame-rate code 0x%x requires %u",
                                       count, frame_rate, expected);

            dtvcc_data = wmem_alloc(pinfo->pool, MAX(1U, count * 2));
            for (i = 0; i < count; i++) {
                unsigned c_off = offset + 2 + i * 3;
                uint8_t type_byte = tvb_get_uint8(tvb, c_off);
                uint8_t cc_type = type_byte & 0x03;
                proto_tree *construct_tree;

                construct_tree = proto_tree_add_subtree_format(
                    section_tree, tvb, c_off, 3, ett_st334_2_cc_construct, NULL,
                    "CC Construct %u: %s", i + 1,
                    val_to_str_const(cc_type, st334_2_cc_type_vals, "Unknown"));
                ti = proto_tree_add_item(construct_tree, hf_st334_2_cc_marker_bits, tvb, c_off, 1, ENC_BIG_ENDIAN);
                if ((type_byte & 0xf8) != 0xf8)
                    expert_add_info(pinfo, ti, &ei_st334_2_bad_marker);
                proto_tree_add_item(construct_tree, hf_st334_2_cc_valid, tvb, c_off, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(construct_tree, hf_st334_2_cc_type, tvb, c_off, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(construct_tree, hf_st334_2_cc_data_1, tvb, c_off + 1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(construct_tree, hf_st334_2_cc_data_2, tvb, c_off + 2, 1, ENC_BIG_ENDIAN);

                if ((type_byte & 0x04) != 0 && (cc_type == 2 || cc_type == 3)) {
                    dtvcc_data[dtvcc_len++] = tvb_get_uint8(tvb, c_off + 1);
                    dtvcc_data[dtvcc_len++] = tvb_get_uint8(tvb, c_off + 2);
                }
            }
            if (dtvcc_len != 0) {
                tvbuff_t *dtvcc_tvb;

                dtvcc_tvb = tvb_new_child_real_data(tvb, dtvcc_data,
                                                     dtvcc_len, dtvcc_len);
                /* ST 334-2:2015, Sec. 5.4, Table 5: concatenate valid cc_type 2/3 constructs for CEA-708 decoding. */
                add_new_data_source(pinfo, dtvcc_tvb, "CEA-708 DTVCC Data");
                ti = proto_tree_add_item(section_tree, hf_st334_2_dtvcc_data,
                                         dtvcc_tvb, 0, dtvcc_len, ENC_NA);
                proto_item_set_generated(ti);
            }
        } else if (id == 0x73) {
            /* SMPTE ST 334-2:2015, Sec. 5.5, Table 6 -- ccsvcinfo_section(). */
            proto_tree *section_tree;
            uint8_t svc_flags;
            unsigned count;
            unsigned i;

            if (!tvb_bytes_exist(tvb, offset, 2) || offset + 2 > parse_len) {
                expert_add_info_format(pinfo, root_ti, &ei_st334_2_truncated,
                                       "Truncated CDP service information section header");
                break;
            }
            svc_flags = tvb_get_uint8(tvb, offset + 1);
            count = svc_flags & 0x0f;
            section_len = 2 + 7 * count;
            if (!tvb_bytes_exist(tvb, offset, section_len) || offset + section_len > parse_len) {
                expert_add_info_format(pinfo, root_ti, &ei_st334_2_truncated,
                                       "Service information section requires %u bytes but packet ends early",
                                       section_len);
                break;
            }

            section_tree = proto_tree_add_subtree(cdp_tree, tvb, offset, section_len,
                                                  ett_st334_2_svcinfo, NULL,
                                                  "CC Service Information Section");
            ti = proto_tree_add_item(section_tree, hf_st334_2_section_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (seen_svc)
                expert_add_info(pinfo, ti, &ei_st334_2_duplicate_section);
            seen_svc = true;

            ti = proto_tree_add_item(section_tree, hf_st334_2_svc_reserved, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            if ((svc_flags & 0x80) == 0)
                expert_add_info(pinfo, ti, &ei_st334_2_bad_reserved);
            proto_tree_add_item(section_tree, hf_st334_2_svc_info_start_section, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(section_tree, hf_st334_2_svc_info_change_section, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(section_tree, hf_st334_2_svc_info_complete_section, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(section_tree, hf_st334_2_svc_count, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

            if (((flags >> 2) & 0x07) != ((svc_flags >> 4) & 0x07)) {
                expert_add_info_format(pinfo, ti, &ei_st334_2_bad_reserved,
                                       "Service-info start/change/complete flags do not match CDP header");
            }

            for (i = 0; i < count; i++) {
                unsigned s_off = offset + 2 + i * 7;
                uint8_t first = tvb_get_uint8(tvb, s_off);
                unsigned service_number;
                uint8_t type_byte;
                bool digital_cc;
                proto_tree *service_tree;
                proto_tree *data_tree;

                service_tree = proto_tree_add_subtree_format(
                    section_tree, tvb, s_off, 7, ett_st334_2_service, NULL,
                    "Caption Service %u", i + 1);
                ti = proto_tree_add_item(service_tree, hf_st334_2_csn_reserved, tvb, s_off, 1, ENC_BIG_ENDIAN);
                if ((first & 0x80) == 0)
                    expert_add_info(pinfo, ti, &ei_st334_2_bad_reserved);
                proto_tree_add_item(service_tree, hf_st334_2_csn_size, tvb, s_off, 1, ENC_BIG_ENDIAN);
                if ((first & 0x40) != 0) {
                    ti = proto_tree_add_item(service_tree, hf_st334_2_csn_reserved_2, tvb, s_off, 1, ENC_BIG_ENDIAN);
                    if ((first & 0x20) == 0)
                        expert_add_info(pinfo, ti, &ei_st334_2_bad_reserved);
                    service_number = first & 0x1f;
                } else {
                    service_number = first & 0x3f;
                }
                ti = proto_tree_add_uint(service_tree, hf_st334_2_caption_service_number,
                                         tvb, s_off, 1, service_number);

                /*
                 * SMPTE ST 334-2:2015, Sec. 5.5, Table 6 defines
                 * svc_data_byte_1 through svc_data_byte_6 as one service
                 * entry encoded according to the caption service descriptor
                 * loop in ATSC A/65:2013, Sec. 6.9.2, Table 6.26.
                 */
                type_byte = tvb_get_uint8(tvb, s_off + 4);
                digital_cc = (type_byte & 0x80) != 0;

                data_tree = proto_tree_add_subtree(
                    service_tree, tvb, s_off + 1, 6,
                    ett_st334_2_service_data, NULL, "Service Data");

                proto_tree_add_item(data_tree, hf_st334_2_service_language,
                                    tvb, s_off + 1, 3, ENC_ASCII);
                proto_tree_add_item(data_tree, hf_st334_2_service_digital_cc,
                                    tvb, s_off + 4, 1, ENC_BIG_ENDIAN);

                if (digital_cc) {
                    proto_tree_add_item(data_tree, hf_st334_2_service_digital_reserved,
                                        tvb, s_off + 4, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(data_tree, hf_st334_2_service_descriptor_number,
                                        tvb, s_off + 4, 1, ENC_BIG_ENDIAN);
                } else {
                    proto_tree_add_item(data_tree, hf_st334_2_service_line21_reserved,
                                        tvb, s_off + 4, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(data_tree, hf_st334_2_service_line21_field,
                                        tvb, s_off + 4, 1, ENC_BIG_ENDIAN);
                }

                proto_tree_add_item(data_tree, hf_st334_2_service_easy_reader,
                                    tvb, s_off + 5, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(data_tree, hf_st334_2_service_wide_aspect_ratio,
                                    tvb, s_off + 5, 1, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(data_tree, hf_st334_2_service_reserved_14,
                                         tvb, s_off + 5, 2, ENC_BIG_ENDIAN);
                if ((tvb_get_ntohs(tvb, s_off + 5) & 0x3fff) != 0x3fff)
                    expert_add_info(pinfo, ti, &ei_st334_2_bad_reserved);
            }
        } else if (id == 0x74) {
            /* SMPTE ST 334-2:2015, Sec. 5.6, Table 7 -- cdp_footer(). */
            proto_tree *section_tree;
            uint16_t footer_sequence;
            uint8_t sum;
            proto_item *checksum_item;

            section_len = 4;
            if (!tvb_bytes_exist(tvb, offset, section_len) || offset + section_len > parse_len) {
                expert_add_info_format(pinfo, root_ti, &ei_st334_2_truncated,
                                       "Truncated CDP footer");
                break;
            }

            section_tree = proto_tree_add_subtree(cdp_tree, tvb, offset, section_len,
                                                  ett_st334_2_footer, NULL, "CDP Footer");
            ti = proto_tree_add_item(section_tree, hf_st334_2_section_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (seen_footer)
                expert_add_info(pinfo, ti, &ei_st334_2_duplicate_section);
            seen_footer = true;

            footer_sequence = tvb_get_ntohs(tvb, offset + 1);
            ti = proto_tree_add_item(section_tree, hf_st334_2_footer_sequence_counter,
                                     tvb, offset + 1, 2, ENC_BIG_ENDIAN);
            if (footer_sequence != header_sequence)
                expert_add_info_format(pinfo, ti, &ei_st334_2_sequence_mismatch,
                                       "Footer sequence %u does not match header sequence %u",
                                       footer_sequence, header_sequence);

            checksum_item = proto_tree_add_item(section_tree, hf_st334_2_packet_checksum,
                                                tvb, offset + 3, 1, ENC_BIG_ENDIAN);
            if (parse_len == declared_len && offset + 4 == parse_len) {
                sum = st334_2_cdp_checksum(tvb, parse_len);
                ti = proto_tree_add_uint(section_tree, hf_st334_2_checksum_calculated,
                                         tvb, 0, 0,
                                         (uint8_t)(tvb_get_uint8(tvb, offset + 3) - sum));
                proto_item_set_generated(ti);
                if (sum != 0)
                    expert_add_info_format(pinfo, checksum_item, &ei_st334_2_bad_checksum,
                                           "CDP checksum does not make packet sum modulo 256 equal zero (sum 0x%02x)",
                                           sum);
            }
            offset += section_len;
            break;
        } else if (id >= 0x75 && id <= 0xef) {
            /* SMPTE ST 334-2:2015, Sec. 5.7, Table 8 -- future_section(). */
            proto_tree *section_tree;
            unsigned future_len;

            if (!tvb_bytes_exist(tvb, offset, 2) || offset + 2 > parse_len) {
                expert_add_info_format(pinfo, root_ti, &ei_st334_2_truncated,
                                       "Truncated future CDP section header");
                break;
            }
            future_len = tvb_get_uint8(tvb, offset + 1);
            section_len = 2 + future_len;
            if (!tvb_bytes_exist(tvb, offset, section_len) || offset + section_len > parse_len) {
                expert_add_info_format(pinfo, root_ti, &ei_st334_2_truncated,
                                       "Future CDP section requires %u bytes but packet ends early",
                                       section_len);
                break;
            }
            section_tree = proto_tree_add_subtree_format(
                cdp_tree, tvb, offset, section_len, ett_st334_2_future, NULL,
                "Unknown/Future CDP Section 0x%02x", id);
            proto_tree_add_item(section_tree, hf_st334_2_section_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(section_tree, hf_st334_2_future_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            if (future_len != 0)
                proto_tree_add_item(section_tree, hf_st334_2_future_data, tvb, offset + 2,
                                    future_len, ENC_NA);
        } else {
            ti = proto_tree_add_item(cdp_tree, hf_st334_2_section_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            expert_add_info_format(pinfo, ti, &ei_st334_2_bad_section_order,
                                   "Unknown CDP section identifier 0x%02x cannot be safely skipped",
                                   id);
            break;
        }

        offset += section_len;
    }

    if (time_present != seen_time)
        expert_add_info_format(pinfo, root_ti, &ei_st334_2_missing_section,
                               "CDP header time_code_present=%u but time-code section %s",
                               time_present, seen_time ? "is present" : "is absent");
    if (cc_present != seen_cc)
        expert_add_info_format(pinfo, root_ti, &ei_st334_2_missing_section,
                               "CDP header ccdata_present=%u but CC-data section %s",
                               cc_present, seen_cc ? "is present" : "is absent");
    if (svc_present != seen_svc)
        expert_add_info_format(pinfo, root_ti, &ei_st334_2_missing_section,
                               "CDP header svcinfo_present=%u but service-info section %s",
                               svc_present, seen_svc ? "is present" : "is absent");
    if (!seen_footer)
        expert_add_info_format(pinfo, root_ti, &ei_st334_2_missing_section,
                               "Required CDP footer is absent");

    return captured_len;
}

void
proto_register_st334_2(void)
{
    static hf_register_info hf[] = {
        { &hf_st334_2_cdp_identifier,
          { "CDP Identifier", "st334_2.cdp.identifier", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_st334_2_cdp_length,
          { "CDP Length", "st334_2.cdp.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_st334_2_frame_rate,
          { "CDP Frame Rate", "st334_2.cdp.frame_rate", FT_UINT8, BASE_HEX,
            VALS(st334_2_frame_rate_vals), 0xf0, NULL, HFILL } },
        { &hf_st334_2_header_reserved,
          { "Reserved", "st334_2.cdp.header.reserved", FT_UINT8, BASE_HEX, NULL, 0x0f, NULL,
            HFILL } },
        { &hf_st334_2_time_code_present,
          { "Time Code", "st334_2.cdp.time_code_present", FT_BOOLEAN, 8,
            TFS(&st334_2_tfs_present), 0x80, NULL, HFILL } },
        { &hf_st334_2_ccdata_present,
          { "CC Data", "st334_2.cdp.ccdata_present", FT_BOOLEAN, 8, TFS(&st334_2_tfs_present),
            0x40, NULL, HFILL } },
        { &hf_st334_2_svcinfo_present,
          { "Service Information", "st334_2.cdp.svcinfo_present", FT_BOOLEAN, 8,
            TFS(&st334_2_tfs_present), 0x20, NULL, HFILL } },
        { &hf_st334_2_svc_info_start,
          { "Service Info Start", "st334_2.cdp.svc_info_start", FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL } },
        { &hf_st334_2_svc_info_change,
          { "Service Info Change", "st334_2.cdp.svc_info_change", FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL } },
        { &hf_st334_2_svc_info_complete,
          { "Service Info Complete", "st334_2.cdp.svc_info_complete", FT_BOOLEAN, 8, NULL,
            0x04, NULL, HFILL } },
        { &hf_st334_2_caption_service_active,
          { "Caption Service Active", "st334_2.cdp.caption_service_active", FT_BOOLEAN, 8,
            NULL, 0x02, NULL, HFILL } },
        { &hf_st334_2_header_reserved_bit,
          { "Reserved", "st334_2.cdp.header.reserved_bit", FT_BOOLEAN, 8, NULL, 0x01, NULL,
            HFILL } },
        { &hf_st334_2_header_sequence_counter,
          { "Header Sequence Counter", "st334_2.cdp.header_sequence", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_st334_2_section_id,
          { "Section ID", "st334_2.section.id", FT_UINT8, BASE_HEX,
            VALS(st334_2_section_id_vals), 0x0, NULL, HFILL } },
        { &hf_st334_2_timecode,
          { "Time Code", "st334_2.timecode", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_st334_2_tc_field_flag,
          { "Field Flag", "st334_2.timecode.field_flag", FT_BOOLEAN, 8, NULL, 0x80, NULL,
            HFILL } },
        { &hf_st334_2_drop_frame_flag,
          { "Drop Frame", "st334_2.timecode.drop_frame", FT_BOOLEAN, 8, NULL, 0x80, NULL,
            HFILL } },
        { &hf_st334_2_cc_count,
          { "CC Count", "st334_2.ccdata.count", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL } },
        { &hf_st334_2_cc_marker_bits,
          { "Marker Bits", "st334_2.ccdata.marker", FT_UINT8, BASE_HEX, NULL, 0xf8, NULL,
            HFILL } },
        { &hf_st334_2_cc_valid,
          { "CC Valid", "st334_2.ccdata.valid", FT_BOOLEAN, 8, TFS(&st334_2_tfs_valid), 0x04,
            NULL, HFILL } },
        { &hf_st334_2_cc_type,
          { "CC Type", "st334_2.ccdata.type", FT_UINT8, BASE_DEC, VALS(st334_2_cc_type_vals),
            0x03, NULL, HFILL } },
        { &hf_st334_2_cc_data_1,
          { "CC Data 1", "st334_2.ccdata.data1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_st334_2_cc_data_2,
          { "CC Data 2", "st334_2.ccdata.data2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_st334_2_dtvcc_data,
          { "DTVCC Data", "st334_2.ccdata.dtvcc", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_st334_2_svc_reserved,
          { "Reserved", "st334_2.svcinfo.reserved", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL } },
        { &hf_st334_2_svc_info_start_section,
          { "Service Info Start", "st334_2.svcinfo.start", FT_BOOLEAN, 8, NULL, 0x40, NULL,
            HFILL } },
        { &hf_st334_2_svc_info_change_section,
          { "Service Info Change", "st334_2.svcinfo.change", FT_BOOLEAN, 8, NULL, 0x20, NULL,
            HFILL } },
        { &hf_st334_2_svc_info_complete_section,
          { "Service Info Complete", "st334_2.svcinfo.complete", FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL } },
        { &hf_st334_2_svc_count,
          { "Service Count", "st334_2.svcinfo.count", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL,
            HFILL } },
        { &hf_st334_2_csn_reserved,
          { "Reserved", "st334_2.svcinfo.service.reserved", FT_BOOLEAN, 8, NULL, 0x80, NULL,
            HFILL } },
        { &hf_st334_2_csn_size,
          { "Caption Service Number Size", "st334_2.svcinfo.service.csn_size", FT_BOOLEAN, 8,
            NULL, 0x40, NULL, HFILL } },
        { &hf_st334_2_csn_reserved_2,
          { "Reserved", "st334_2.svcinfo.service.reserved_2", FT_BOOLEAN, 8, NULL, 0x20, NULL,
            HFILL } },
        { &hf_st334_2_caption_service_number,
          { "Caption Service Number", "st334_2.svcinfo.service.number", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },

        /*
         * SMPTE ST 334-2:2015, Sec. 5.5, Table 6;
         * ATSC A/65:2013, Sec. 6.9.2, Table 6.26.
         */
        { &hf_st334_2_service_data,
          { "Service Data", "st334_2.svcinfo.service.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_st334_2_service_language,
          { "Language", "st334_2.svcinfo.service.language", FT_STRING, BASE_NONE, NULL, 0x0,
            "ISO 639.2/B language code", HFILL } },
        { &hf_st334_2_service_digital_cc,
          { "Digital CC", "st334_2.svcinfo.service.digital_cc", FT_BOOLEAN, 8,
            TFS(&tfs_yes_no), 0x80, "1 = CEA-708 digital captions; 0 = CEA-608/line 21", HFILL } },
        { &hf_st334_2_service_digital_reserved,
          { "Reserved", "st334_2.svcinfo.service.digital_reserved", FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL } },
        { &hf_st334_2_service_line21_reserved,
          { "Reserved", "st334_2.svcinfo.service.line21_reserved", FT_UINT8, BASE_HEX, NULL,
            0x7e, NULL, HFILL } },
        { &hf_st334_2_service_line21_field,
          { "Line 21 Field", "st334_2.svcinfo.service.line21_field", FT_BOOLEAN, 8, NULL,
            0x01, "0 = field 1; 1 = field 2", HFILL } },
        { &hf_st334_2_service_descriptor_number,
          { "Caption Service Number", "st334_2.svcinfo.service.descriptor_number", FT_UINT8,
            BASE_DEC, NULL, 0x3f, NULL, HFILL } },
        { &hf_st334_2_service_easy_reader,
          { "Easy Reader", "st334_2.svcinfo.service.easy_reader", FT_BOOLEAN, 8,
            TFS(&tfs_yes_no), 0x80, NULL, HFILL } },
        { &hf_st334_2_service_wide_aspect_ratio,
          { "Wide Aspect Ratio", "st334_2.svcinfo.service.wide_aspect_ratio", FT_BOOLEAN, 8,
            TFS(&tfs_yes_no), 0x40, "1 = 16:9; 0 = 4:3", HFILL } },
        { &hf_st334_2_service_reserved_14,
          { "Reserved", "st334_2.svcinfo.service.reserved_14", FT_UINT16, BASE_HEX, NULL,
            0x3fff, NULL, HFILL } },
        { &hf_st334_2_future_length,
          { "Length", "st334_2.future.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_st334_2_future_data,
          { "Data", "st334_2.future.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_st334_2_footer_sequence_counter,
          { "Footer Sequence Counter", "st334_2.cdp.footer_sequence", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_st334_2_packet_checksum,
          { "Packet Checksum", "st334_2.cdp.checksum", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_st334_2_checksum_calculated,
          { "Calculated Checksum", "st334_2.cdp.checksum_calculated", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
    };
    static int *ett[] = {
        &ett_st334_2,
        &ett_st334_2_header,
        &ett_st334_2_timecode,
        &ett_st334_2_ccdata,
        &ett_st334_2_cc_construct,
        &ett_st334_2_svcinfo,
        &ett_st334_2_service,
        &ett_st334_2_service_data,
        &ett_st334_2_future,
        &ett_st334_2_footer,
    };
    static ei_register_info ei[] = {
        { &ei_st334_2_bad_identifier, { "st334_2.bad_identifier", PI_PROTOCOL, PI_WARN, "Invalid CDP identifier", EXPFILL } },
        { &ei_st334_2_bad_length, { "st334_2.bad_length", PI_MALFORMED, PI_WARN, "CDP length mismatch", EXPFILL } },
        { &ei_st334_2_bad_reserved, { "st334_2.bad_reserved", PI_PROTOCOL, PI_WARN, "Invalid reserved bits or duplicated flags", EXPFILL } },
        { &ei_st334_2_bad_section_order, { "st334_2.bad_section_order", PI_PROTOCOL, PI_WARN, "Invalid or unknown CDP section ordering", EXPFILL } },
        { &ei_st334_2_duplicate_section, { "st334_2.duplicate_section", PI_PROTOCOL, PI_WARN, "Duplicate CDP section", EXPFILL } },
        { &ei_st334_2_missing_section, { "st334_2.missing_section", PI_PROTOCOL, PI_WARN, "CDP section presence mismatch", EXPFILL } },
        { &ei_st334_2_cc_count, { "st334_2.bad_cc_count", PI_PROTOCOL, PI_WARN, "CC count does not match frame rate", EXPFILL } },
        { &ei_st334_2_bad_marker, { "st334_2.bad_marker", PI_PROTOCOL, PI_WARN, "Invalid CEA-708 marker bits", EXPFILL } },
        { &ei_st334_2_sequence_mismatch, { "st334_2.sequence_mismatch", PI_SEQUENCE, PI_WARN, "CDP header/footer sequence mismatch", EXPFILL } },
        { &ei_st334_2_bad_checksum, { "st334_2.bad_checksum", PI_CHECKSUM, PI_WARN, "Invalid CDP checksum", EXPFILL } },
        { &ei_st334_2_truncated, { "st334_2.truncated", PI_MALFORMED, PI_ERROR, "Truncated CDP section", EXPFILL } },
    };
    expert_module_t *expert_st334_2;

    proto_st334_2 = proto_register_protocol(
        "SMPTE ST 334-2 Caption Distribution Packet", "ST 334-2", "st334_2");
    proto_register_field_array(proto_st334_2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_st334_2 = expert_register_protocol(proto_st334_2);
    expert_register_field_array(expert_st334_2, ei, array_length(ei));

    st334_2_handle = register_dissector("st334_2", dissect_st334_2, proto_st334_2);
}

void
proto_reg_handoff_st334_2(void)
{
    dissector_add_uint("st291.did_sdid", ST334_2_DID_SDID_KEY, st334_2_handle);
}

/*
 * Common System B World System Teletext decoding used by ST 2031 and
 * RDD 8 / OP-47. The protocols retain separate display-filter fields; this
 * structure supplies the appropriate field IDs to the common parser.
 */
typedef struct {
    int *magazine_hamming;
    int *magazine;
    int *packet_number_hamming;
    int *packet_number;
    int *page_units_hamming;
    int *page_units;
    int *page_tens_hamming;
    int *page_tens;
    int *data_string;
    int *textdata_array;
    int *erase_page;
    int *newsflash;
    int *subtitle;
    int *suppress_header;
    int *update_indicator;
    int *interrupted_sequence;
    int *inhibit_display;
    int *magazine_serial;
    int *character_set;
    int *tt_control;
} st291_wst_fields_t;

/* Rec. ITU-R BT.653-3, System B national-option character subsets. */
static const value_string st291_wst_national_subset_vals[] = {
    { 0x00, "English" },
    { 0x01, "German" },
    { 0x04, "Swedish/Finnish/Hungarian" },
    { 0x05, "Italian" },
    { 0x10, "French" },
    { 0x11, "Portuguese/Spanish" },
    { 0x14, "Czech/Slovak" },
    { 0, NULL }
};

static void
st291_process_wst_packet(tvbuff_t *tvb, proto_tree *tree, const st291_wst_fields_t *fields)
{
    uint8_t text_data[40];
    char data_string[41];
    unsigned magazine, packet_number;
    unsigned data_start_offset = 0, number_of_data_bytes = 0;
    proto_item *ti;
    unsigned i;

    if (tvb_captured_length(tvb) < 42)
        return;

    proto_tree_add_item(tree, *fields->magazine_hamming, tvb, 0, 2, ENC_BIG_ENDIAN);
    magazine = tvb_get_bits8(tvb, 1, 1)
             + 2 * tvb_get_bits8(tvb, 3, 1)
             + 4 * tvb_get_bits8(tvb, 5, 1);
    if (magazine == 0)
        magazine = 8;
    ti = proto_tree_add_uint(tree, *fields->magazine, tvb, 0, 0, magazine);
    proto_item_set_generated(ti);

    proto_tree_add_item(tree, *fields->packet_number_hamming, tvb, 0, 2, ENC_BIG_ENDIAN);
    packet_number = tvb_get_bits8(tvb, 7, 1)
                  + 2 * tvb_get_bits8(tvb, 9, 1)
                  + 4 * tvb_get_bits8(tvb, 11, 1)
                  + 8 * tvb_get_bits8(tvb, 13, 1)
                  + 16 * tvb_get_bits8(tvb, 15, 1);
    ti = proto_tree_add_uint(tree, *fields->packet_number, tvb, 0, 0, packet_number);
    proto_item_set_generated(ti);

    if (packet_number == 0) {
        unsigned page_units, page_tens, tt_page;

        data_start_offset = 10;
        number_of_data_bytes = 32;

        page_units = tvb_get_bits8(tvb, 2 * 8 + 1, 1)
                   + 2 * tvb_get_bits8(tvb, 2 * 8 + 3, 1)
                   + 4 * tvb_get_bits8(tvb, 2 * 8 + 5, 1)
                   + 8 * tvb_get_bits8(tvb, 2 * 8 + 7, 1);
        page_tens = tvb_get_bits8(tvb, 3 * 8 + 1, 1)
                  + 2 * tvb_get_bits8(tvb, 3 * 8 + 3, 1)
                  + 4 * tvb_get_bits8(tvb, 3 * 8 + 5, 1)
                  + 8 * tvb_get_bits8(tvb, 3 * 8 + 7, 1);

        proto_tree_add_item(tree, *fields->page_units_hamming, tvb, 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, *fields->page_tens_hamming, tvb, 3, 1, ENC_BIG_ENDIAN);
        ti = proto_tree_add_uint(tree, *fields->page_units, tvb, 0, 0, page_units);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(tree, *fields->page_tens, tvb, 0, 0, page_tens);
        proto_item_set_generated(ti);

        tt_page = (magazine << 8) | (page_tens << 4) | page_units;
        proto_tree_add_none_format(tree, *fields->tt_control, tvb, 0, 0,
                                   "Control bits for TT Page 0x%x:", tt_page);

        proto_tree_add_item(tree, *fields->erase_page, tvb, 5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, *fields->newsflash, tvb, 7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, *fields->subtitle, tvb, 7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, *fields->suppress_header, tvb, 8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, *fields->update_indicator, tvb, 8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, *fields->interrupted_sequence, tvb, 8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, *fields->inhibit_display, tvb, 8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, *fields->magazine_serial, tvb, 9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, *fields->character_set, tvb, 9, 1, ENC_BIG_ENDIAN);
    } else if (packet_number >= 1 && packet_number <= 25) {
        data_start_offset = 2;
        number_of_data_bytes = 40;
    }

    if (number_of_data_bytes == 0)
        return;

    for (i = 0; i < number_of_data_bytes; i++) {
        uint8_t c = tvb_get_bits8(tvb, (data_start_offset + i) * 8, 7);
        text_data[i] = c;
        data_string[i] = (char)c;
    }
    data_string[number_of_data_bytes] = '\0';

    ti = proto_tree_add_string(tree, *fields->data_string, tvb, 0, 0, data_string);
    proto_item_set_generated(ti);
    ti = proto_tree_add_bytes(tree, *fields->textdata_array, tvb, 0, 0, text_data);
    proto_item_set_generated(ti);
}

/*
 * SMPTE ST 2031 DVB/SCTE VBI data in VANC
 */

static const struct true_false_string st2031_tfs_field_parity = {
    "First field of a frame", "Second field of a frame"
};


static const st291_wst_fields_t st2031_wst_fields = {
    &hf_st2031_magazine_hamming,
    &hf_st2031_magazine,
    &hf_st2031_packet_number_hamming,
    &hf_st2031_packet_number,
    &hf_st2031_page_units_hamming,
    &hf_st2031_page_units,
    &hf_st2031_page_tens_hamming,
    &hf_st2031_page_tens,
    &hf_st2031_data_string,
    &hf_st2031_textdata_array,
    &hf_st2031_erase_page,
    &hf_st2031_newsflash,
    &hf_st2031_subtitle,
    &hf_st2031_suppress_header,
    &hf_st2031_update_indicator,
    &hf_st2031_interrupted_sequence,
    &hf_st2031_inhibit_display,
    &hf_st2031_magazine_serial,
    &hf_st2031_character_set,
    &hf_st2031_tt_control,
};

/* Rec. ITU-R BT.653-3, System B national-option character subsets used by Teletext data units. */
/* SMPTE ST 2031:2015, Sec. 6, Table 2; values originate in ETSI EN 301 775, Sec. 4.4. */
static const range_string st2031_data_identifier_vals[] = {
    { 0x10, 0x1F, "EBU Teletext/VPS/WSS/CC/VBI sample data" },
    { 0x80, 0x98, "User defined" },
    { 0x99, 0x9B, "EBU Teletext/VPS/WSS/CC/VBI sample data" },
    { 0x9C, 0xFF, "User defined" },
    { 0x00, 0xFF, "Reserved for future use" },
    { 0, 0, NULL }
};

/* SMPTE ST 2031:2015, Sec. 6, Table 2; data_unit_id values originate in ETSI EN 301 775, Sec. 4.5. */
static const range_string st2031_data_unit_id_vals[] = {
    { 0x00, 0x01, "DVB reserved" },
    { 0x02, 0x02, "EBU Teletext non-subtitle data" },
    { 0x03, 0x03, "EBU Teletext subtitle data" },
    { 0x04, 0x7F, "DVB reserved" },
    { 0x80, 0xBF, "User defined" },
    { 0xC0, 0xC0, "Inverted Teletext" },
    { 0xC1, 0xC2, "DVB reserved" },
    { 0xC3, 0xC3, "VPS" },
    { 0xC4, 0xC4, "WSS" },
    { 0xC5, 0xC5, "CEA-608 Closed Captioning" },
    { 0xC6, 0xC6, "monochrome 4:2:2 samples" },
    { 0xC7, 0xCF, "User defined" },
    { 0xD0, 0xD0, "AMOL48" },
    { 0xD1, 0xD1, "AMOL96" },
    { 0xDA, 0xE5, "SCTE reserved" },
    { 0xE6, 0xFE, "SCTE user defined" },
    { 0xFF, 0xFF, "MPEG stuffing" },
    { 0x00, 0xFF, "Reserved or user defined" },
    { 0, 0, NULL }
};

/* ETSI EN 301 775, Sec. 4.5.2 carries a 42-byte Teletext data block;
 * packet addressing, page/control bits and character data follow Rec. ITU-R BT.653-3 System B. */
/* SMPTE ST 2031:2015, Secs. 5-6, Tables 1-2; ETSI EN 301 775 Sec. 4.5 for Teletext fields. */
static int
dissect_st2031(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    const st291_vanc_dissector_data_t *st291_data = (const st291_vanc_dissector_data_t *)data;
    proto_tree *top_tree = st291_data && st291_data->top_tree ? st291_data->top_tree : tree;
    proto_item *ti;
    proto_tree *st2031_tree;
    uint8_t unit_id;
    tvbuff_t *wst_tvb;

    if (tvb_captured_length(tvb) < 2)
        return 0;

    ti = proto_tree_add_item(top_tree, proto_st2031, tvb, 0, -1, ENC_NA);
    st2031_tree = proto_item_add_subtree(ti, ett_st2031);

    /* SMPTE ST 2031:2015, Sec. 6, Table 2 -- data_identifier,
     * data_unit_id and data_unit_length. */
    proto_tree_add_item(st2031_tree, hf_st2031_data_identifier, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(st2031_tree, hf_st2031_data_unit_id, tvb, 1, 1, ENC_BIG_ENDIAN);
    unit_id = tvb_get_uint8(tvb, 1);

    if ((unit_id == 0x02 || unit_id == 0x03) && tvb_captured_length(tvb) >= 47) {
        proto_tree_add_item(st2031_tree, hf_st2031_data_unit_length, tvb, 2, 1, ENC_BIG_ENDIAN);
        /* ETSI EN 301 775, Secs. 4.5.1-4.5.2, Tables 4-5 --
         * field_parity, line_offset, framing_code and Teletext data block. */
        proto_tree_add_item(st2031_tree, hf_st2031_field_parity, tvb, 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(st2031_tree, hf_st2031_line_offset, tvb, 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(st2031_tree, hf_st2031_framing_code, tvb, 4, 1, ENC_BIG_ENDIAN);
        wst_tvb = tvb_new_subset_length(tvb, 5, 42);
        st291_process_wst_packet(wst_tvb, st2031_tree, &st2031_wst_fields);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_st2031(void)
{
    static hf_register_info hf[] = {
        { &hf_st2031_data_identifier,
          { "Data Identifier", "st2031.data_identifier", FT_UINT8,
            BASE_HEX | BASE_RANGE_STRING, RVALS(st2031_data_identifier_vals), 0x0, NULL, HFILL } },
        { &hf_st2031_data_unit_id,
          { "Data Unit ID", "st2031.data_unit_id", FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(st2031_data_unit_id_vals), 0x0, NULL, HFILL } },
        { &hf_st2031_data_unit_length,
          { "Data Unit Length", "st2031.data_unit_length", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_st2031_field_parity,
          { "Field Parity", "st2031.field_parity", FT_BOOLEAN, 8,
            TFS(&st2031_tfs_field_parity), 0x20, NULL, HFILL } },
        { &hf_st2031_line_offset,
          { "Line Offset", "st2031.line_offset", FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL } },
        { &hf_st2031_framing_code,
          { "Framing Code", "st2031.framing_code", FT_UINT8, BASE_HEX, NULL, 0xFF, NULL, HFILL } },
        { &hf_st2031_magazine_hamming,
          { "Magazine (Hamming 8/4)", "st2031.teletext.magazine_hamming", FT_UINT16, BASE_DEC,
            NULL, 0xFC00, NULL, HFILL } },
        { &hf_st2031_magazine,
          { "Magazine", "st2031.teletext.magazine", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_st2031_packet_number_hamming,
          { "Packet Number (Hamming 8/4)", "st2031.teletext.packet_number_hamming", FT_UINT16,
            BASE_DEC, NULL, 0x03FF, NULL, HFILL } },
        { &hf_st2031_packet_number,
          { "Packet Number", "st2031.teletext.packet_number", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_st2031_page_units_hamming,
          { "Page Units (Hamming 8/4)", "st2031.teletext.page_units_hamming", FT_UINT8,
            BASE_HEX, NULL, 0xFF, NULL, HFILL } },
        { &hf_st2031_page_units,
          { "Page Units", "st2031.teletext.page_units", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_st2031_page_tens_hamming,
          { "Page Tens (Hamming 8/4)", "st2031.teletext.page_tens_hamming", FT_UINT8,
            BASE_HEX, NULL, 0xFF, NULL, HFILL } },
        { &hf_st2031_page_tens,
          { "Page Tens", "st2031.teletext.page_tens", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_st2031_data_string,
          { "Data String", "st2031.teletext.data_string", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_st2031_textdata_array,
          { "Text Data", "st2031.teletext.text_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
        { &hf_st2031_erase_page,
          { "Erase Page", "st2031.teletext.erase_page", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_st2031_newsflash,
          { "Newsflash", "st2031.teletext.newsflash", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_st2031_subtitle,
          { "Subtitle", "st2031.teletext.subtitle", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_st2031_suppress_header,
          { "Suppress Header", "st2031.teletext.suppress_header", FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL } },
        { &hf_st2031_update_indicator,
          { "Update Indicator", "st2031.teletext.update_indicator", FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL } },
        { &hf_st2031_interrupted_sequence,
          { "Interrupted Sequence", "st2031.teletext.interrupted_sequence", FT_BOOLEAN, 8,
            NULL, 0x04, NULL, HFILL } },
        { &hf_st2031_inhibit_display,
          { "Inhibit Display", "st2031.teletext.inhibit_display", FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL } },
        { &hf_st2031_magazine_serial,
          { "Magazine Serial", "st2031.teletext.magazine_serial", FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL } },
        { &hf_st2031_character_set,
          { "Character Subset", "st2031.teletext.character_set", FT_UINT8, BASE_DEC,
            VALS(st291_wst_national_subset_vals), 0x15, NULL, HFILL } },
        { &hf_st2031_tt_control,
          { "Teletext Control", "st2031.teletext.control", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
    };
    static int *ett[] = { &ett_st2031 };

    proto_st2031 = proto_register_protocol(
        "SMPTE ST 2031 VBI Data", "ST 2031", "st2031");
    proto_register_field_array(proto_st2031, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    st2031_handle = register_dissector("st2031", dissect_st2031, proto_st2031);
}

void
proto_reg_handoff_st2031(void)
{
    dissector_add_uint("st291.did_sdid", ST2031_DID_SDID_KEY, st2031_handle);
}

/*
 * Free TV Australia OP-47 / SMPTE RDD 8 teletext
 */

static const st291_wst_fields_t op47_wst_fields = {
    &hf_op47_magazine_hamming,
    &hf_op47_magazine,
    &hf_op47_packet_number_hamming,
    &hf_op47_packet_number,
    &hf_op47_page_units_hamming,
    &hf_op47_page_units,
    &hf_op47_page_tens_hamming,
    &hf_op47_page_tens,
    &hf_op47_data_string,
    &hf_op47_textdata_array,
    &hf_op47_erase_page,
    &hf_op47_newsflash,
    &hf_op47_subtitle,
    &hf_op47_suppress_header,
    &hf_op47_update_indicator,
    &hf_op47_interrupted_sequence,
    &hf_op47_inhibit_display,
    &hf_op47_magazine_serial,
    &hf_op47_character_set,
    &hf_op47_tt_control,
};

/* Rec. ITU-R BT.653-3, System B national-option character subsets used by OP-47 WST data. */
/* OP-47 Issue 6, Sec. 5.5.2 carries a System B WST packet; magazine,
 * packet number, page address, control bits and text follow Rec. ITU-R BT.653-3. */
/* Free TV Australia OP-47 Issue 6, Secs. 5.1, 5.4 and 5.5, Fig. 2. */
static int
dissect_op47(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const st291_vanc_dissector_data_t *st291_data = (const st291_vanc_dissector_data_t *)data;
    proto_tree *top_tree = st291_data && st291_data->top_tree ? st291_data->top_tree : tree;
    proto_item *ti;
    proto_tree *op47_tree;
    unsigned len = tvb_captured_length(tvb);
    uint8_t format_code;
    unsigned offset_a = 4, offset_b = 9, i;

    if (len < 4)
        return 0;

    ti = proto_tree_add_item(top_tree, proto_op47, tvb, 0, -1, ENC_NA);
    op47_tree = proto_item_add_subtree(ti, ett_op47);

    /* OP-47 Issue 6, Sec. 5.1 and Fig. 2 -- SDP identifier, length and format code. */
    proto_tree_add_item(op47_tree, hf_op47_sdp_identifier, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(op47_tree, hf_op47_sdp_length, tvb, 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(op47_tree, hf_op47_sdp_format_code, tvb, 3, 1, ENC_BIG_ENDIAN);
    format_code = tvb_get_uint8(tvb, 3);
    if (format_code != 0x02 || len < 9)
        return len;

    /* OP-47 Issue 6, Sec. 5.4 -- Packet Descriptor Structure A / adaptation header. */
    ti = proto_tree_add_item(op47_tree, hf_op47_sdp_adaption_header, tvb, 4, 5, ENC_NA);
    proto_item_set_generated(ti);

    for (i = 0; i < 5; i++) {
        uint8_t pkt_desc_a;
        uint8_t *flipped;
        tvbuff_t *wst_tvb;
        proto_tree *wst_tree;

        if (offset_a >= len)
            break;
        pkt_desc_a = tvb_get_uint8(tvb, offset_a);
        if (pkt_desc_a == 0)
            break;
        if (offset_b + 45 > len)
            break;

        /* OP-47 Issue 6, Sec. 5.5 -- Packet Descriptor Structure B;
         * Secs. 5.5.1-5.5.2 define clock run-in, framing code and WST data. */
        ti = proto_tree_add_item(op47_tree, hf_op47_sdp_pkt_desc_b, tvb, offset_b, 45, ENC_NA);
        proto_item_set_generated(ti);
        wst_tree = proto_item_add_subtree(ti, ett_op47_wst);

        ti = proto_tree_add_item(wst_tree, hf_op47_clock_runin, tvb, offset_b, 2, ENC_BIG_ENDIAN);
        proto_item_set_generated(ti);
        ti = proto_tree_add_item(wst_tree, hf_op47_framing_code, tvb, offset_b + 2, 1, ENC_BIG_ENDIAN);
        proto_item_set_generated(ti);

        flipped = wmem_alloc(pinfo->pool, 42);
        tvb_memcpy(tvb, flipped, offset_b + 3, 42);
        bitswap_buf_inplace(flipped, 42);

        wst_tvb = tvb_new_child_real_data(tvb, flipped, 42, 42);
        add_new_data_source(pinfo, wst_tvb, "OP-47 WST data (bit reversed)");
        st291_process_wst_packet(wst_tvb, wst_tree, &op47_wst_fields);

        offset_a++;
        offset_b += 45;
    }

    return len;
}

void
proto_register_op47(void)
{
    static hf_register_info hf[] = {
        { &hf_op47_sdp_identifier,
          { "Identifier", "op47.sdp.identifier", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_op47_sdp_length,
          { "Length", "op47.sdp.length", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_op47_sdp_format_code,
          { "Format Code", "op47.sdp.format_code", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_op47_sdp_adaption_header,
          { "Adaption Header", "op47.sdp.adaption_header", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_op47_sdp_pkt_desc_b,
          { "Packet Descriptor B", "op47.sdp.packet_descriptor_b", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL } },
        { &hf_op47_clock_runin,
          { "Clock Run-In", "op47.wst.clock_runin", FT_UINT16, BASE_HEX, NULL, 0xFFFF, NULL,
            HFILL } },
        { &hf_op47_framing_code,
          { "Framing Code", "op47.wst.framing_code", FT_UINT8, BASE_HEX, NULL, 0xFF, NULL,
            HFILL } },
        { &hf_op47_magazine_hamming,
          { "Magazine (Hamming 8/4)", "op47.wst.magazine_hamming", FT_UINT16, BASE_DEC, NULL,
            0xFC00, NULL, HFILL } },
        { &hf_op47_magazine,
          { "Magazine", "op47.wst.magazine", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_op47_packet_number_hamming,
          { "Packet Number (Hamming 8/4)", "op47.wst.packet_number_hamming", FT_UINT16,
            BASE_DEC, NULL, 0x03FF, NULL, HFILL } },
        { &hf_op47_packet_number,
          { "Packet Number", "op47.wst.packet_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
            HFILL } },
        { &hf_op47_page_units_hamming,
          { "Page Units (Hamming 8/4)", "op47.wst.page_units_hamming", FT_UINT8, BASE_HEX,
            NULL, 0xFF, NULL, HFILL } },
        { &hf_op47_page_units,
          { "Page Units", "op47.wst.page_units", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_op47_page_tens_hamming,
          { "Page Tens (Hamming 8/4)", "op47.wst.page_tens_hamming", FT_UINT8, BASE_HEX, NULL,
            0xFF, NULL, HFILL } },
        { &hf_op47_page_tens,
          { "Page Tens", "op47.wst.page_tens", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_op47_data_string,
          { "Data String", "op47.wst.data_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
        { &hf_op47_textdata_array,
          { "Text Data", "op47.wst.text_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_op47_erase_page,
          { "Erase Page", "op47.wst.erase_page", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_op47_newsflash,
          { "Newsflash", "op47.wst.newsflash", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_op47_subtitle,
          { "Subtitle", "op47.wst.subtitle", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_op47_suppress_header,
          { "Suppress Header", "op47.wst.suppress_header", FT_BOOLEAN, 8, NULL, 0x40, NULL,
            HFILL } },
        { &hf_op47_update_indicator,
          { "Update Indicator", "op47.wst.update_indicator", FT_BOOLEAN, 8, NULL, 0x10, NULL,
            HFILL } },
        { &hf_op47_interrupted_sequence,
          { "Interrupted Sequence", "op47.wst.interrupted_sequence", FT_BOOLEAN, 8, NULL,
            0x04, NULL, HFILL } },
        { &hf_op47_inhibit_display,
          { "Inhibit Display", "op47.wst.inhibit_display", FT_BOOLEAN, 8, NULL, 0x01, NULL,
            HFILL } },
        { &hf_op47_magazine_serial,
          { "Magazine Serial", "op47.wst.magazine_serial", FT_BOOLEAN, 8, NULL, 0x40, NULL,
            HFILL } },
        { &hf_op47_character_set,
          { "Character Subset", "op47.wst.character_set", FT_UINT8, BASE_DEC,
            VALS(st291_wst_national_subset_vals), 0x15, NULL, HFILL } },
        { &hf_op47_tt_control,
          { "Teletext Control", "op47.wst.control", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };
    static int *ett[] = {
        &ett_op47,
        &ett_op47_wst,
    };

    proto_op47 = proto_register_protocol(
        "RDD 8 / OP-47 Subtitle Distribution Packet", "OP-47", "op47");
    proto_register_field_array(proto_op47, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    op47_handle = register_dissector("op47", dissect_op47, proto_op47);
}

void
proto_reg_handoff_op47(void)
{
    dissector_add_uint("st291.did_sdid", OP47_DID_SDID_KEY, op47_handle);
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
