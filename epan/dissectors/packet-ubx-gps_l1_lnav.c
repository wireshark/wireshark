/* packet-ubx-gps_l1_lnav.c
 * Dissection of Global Positioning System (GPS) L1 C/A LNAV navigation messages
 * (as provided by UBX-RXM-SFRBX).
 *
 * By Timo Warns <timo.warns@gmail.com>
 * Copyright 2023 Timo Warns
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <wsutil/utf8_entities.h>
#include <proto.h>

#include "packet-ubx.h"
#include "packet-ubx-galileo_e1b_inav.h"

/*
 * Dissects GPS L1 C/A LNAV navigation messages as encoded by UBX (in
 * UBX-RXM-SFRBX messages).
 *
 * UBX encodes the 30 bit words of GPS subframes as 32 bit words in little-endian.
 *
 * The two most significant bits of the 32 bit word can be ignored.
 *
 * UBX takes care of the word parity checks. So, parity checks do not have to be
 * repeated for dissection. UBX inverts the bits of a word if the least
 * significant parity bit (D30) of the previous word is 1 (i.e. UBX undoes the
 * bit inverting of GPS removing the need to do so for dissection).
 */

/*
 * mapping from L2 channel code ID to description
 * see IS-GPS-200N, Section 20.3.3.3.1.2
 */
static const value_string L2_CHANNEL_CODE[] = {
    {0x0, "invalid"},
    {0x1, "P-code ON"},
    {0x2, "C/A-code ON"},
    {0x3, "invalid"},
    {0, NULL},
};

/*
 * mapping from URA index to URA
 * see IS-GPS-200N, Section 20.3.3.3.1.3
 */
static const value_string URA_INDEX[] = {
    { 0,    "0.00 < URA <= 2.40"},
    { 1,    "2.40 < URA <= 3.40"},
    { 2,    "3.40 < URA <= 4.85"},
    { 3,    "4.85 < URA <= 6.85"},
    { 4,    "6.85 < URA <= 9.65"},
    { 5,    "9.65 < URA <= 13.65"},
    { 6,   "13.65 < URA <= 24.00"},
    { 7,   "24.00 < URA <= 48.00"},
    { 8,   "48.00 < URA <= 96.00"},
    { 9,   "96.00 < URA <= 192.00"},
    {10,  "192.00 < URA <= 384.00"},
    {11,  "384.00 < URA <= 768.00"},
    {12,  "768.00 < URA <= 1536.00"},
    {13, "1536.00 < URA <= 3072.00"},
    {14, "3072.00 < URA <= 6144.00"},
    {15, "6144.00 < URA"},
    {0, NULL},
};

/*
 * mapping for SV health summary
 * see IS-GPS-200N, Section 20.3.3.3.1.4
 */
static const value_string SV_HEALTH_SUMMARY[] = {
    {0, "all LNAV data are OK"},
    {1, "some or all LNAV data are bad"},
    {0, NULL},
};

/*
 * mapping for codes for health of SV signal components
 * see IS-GPS-200N, Section 20.3.3.5.1.3
 */
static const value_string SV_HEALTH_CODE[] = {
    {0,  "All Signals OK"},
    {1,  "All Signals Weak"},
    {2,  "All Signals Dead"},
    {3,  "All Signals Have No Data Modulation"},
    {4,  "L1 P Signal Weak"},
    {5,  "L1 P Signal Dead"},
    {6,  "L1 P Signal Has No Data Modulation"},
    {7,  "L2 P Signal Weak"},
    {8,  "L2 P Signal Dead"},
    {9,  "L2 P Signal Has No Data Modulation"},
    {10, "L1C Signal Weak"},
    {11, "L1C Signal Dead"},
    {12, "L1C Signal Has No Data Modulation"},
    {13, "L2C Signal Weak"},
    {14, "L2C Signal Dead"},
    {15, "L2C Signal Has No Data Modulation"},
    {16, "L1 & L2 P Signal Weak"},
    {17, "L1 & L2 P Signal Dead"},
    {18, "L1 & L2 P Signal Has No Data Modulation"},
    {19, "L1 & L2C Signal Weak"},
    {20, "L1 & L2C Signal Dead"},
    {21, "L1 & L2C Signal Has No Data Modulation"},
    {22, "L1 Signal Weak"},
    {23, "L1 Signal Dead"},
    {24, "L1 Signal Has No Data Modulation"},
    {25, "L2 Signal Weak"},
    {26, "L2 Signal Dead"},
    {27, "L2 Signal Has No Data Modulation"},
    {28, "SV Is Temporarily Out (Do not use this SV during current pass)"},
    {29, "SV Will Be Temporarily Out (Use with caution)"},
    {30, "One Or More Signals Are Deformed, However The Relevant URA Parameters Are Valid"},
    {31, "More Than One Combination Would Be Required To Describe Anomalies"},
    {0, NULL},
};

/*
 * mapping for codes for fit interval flag
 * see IS-GPS-200N, Section 20.3.3.4.3.1
 */
static const value_string FIT_INTERVAL_FLAG[] = {
    {0, "4 hours"},
    {1, "greater than 4 hours"},
    {0, NULL},
};

/*
 * Format meters (with 2^-5 scale factor) for
 * amplitude of orbit correction terms
 */
static void fmt_orbit_correction(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-5 m", c);
}

/* Format reference time ephemeris */
static void fmt_t_oe(char *label, uint32_t c) {
    c = c << 4;
    snprintf(label, ITEM_LABEL_LENGTH, "%d s", c);
}

/* Format age of data offset */
static void fmt_aodo(char *label, uint32_t c) {
    c = c * 900;
    snprintf(label, ITEM_LABEL_LENGTH, "%d s", c);
}

// Initialize the protocol and registered fields
static int proto_ubx_gps_l1;

// Telemetry Word (see IS-GPS-200N, Section 20.3.3.1)
static int hf_ubx_gps_l1_tlm_preamble;
static int hf_ubx_gps_l1_tlm_message;
static int hf_ubx_gps_l1_tlm_integrity;
static int hf_ubx_gps_l1_tlm_reserved;
static int hf_ubx_gps_l1_tlm_parity;

// Handover Word (see IS-GPS-200N, Section 20.3.3.2)
static int hf_ubx_gps_l1_how_tow_count;
static int hf_ubx_gps_l1_how_alert;
static int hf_ubx_gps_l1_how_anti_spoof;
static int hf_ubx_gps_l1_how_subframe_id;
static int hf_ubx_gps_l1_how_parity_sol;
static int hf_ubx_gps_l1_how_parity;

// Subframe 1 (see IS-GPS-200N, Section 20.3.3.3)
static int hf_ubx_gps_l1_sf1_w3_week_no;
static int hf_ubx_gps_l1_sf1_w3_l2_channel_code;
static int hf_ubx_gps_l1_sf1_w3_ura_index;
static int hf_ubx_gps_l1_sf1_w3_sv_health_summary;
static int hf_ubx_gps_l1_sf1_w3_sv_health;
static int hf_ubx_gps_l1_sf1_w3_iodc_msbs;
static int hf_ubx_gps_l1_sf1_w3_parity;
static int hf_ubx_gps_l1_sf1_w4_l2_p_data_flag;
static int hf_ubx_gps_l1_sf1_w4_reserved;
static int hf_ubx_gps_l1_sf1_w4_parity;
static int hf_ubx_gps_l1_sf1_w5_reserved;
static int hf_ubx_gps_l1_sf1_w5_parity;
static int hf_ubx_gps_l1_sf1_w6_reserved;
static int hf_ubx_gps_l1_sf1_w6_parity;
static int hf_ubx_gps_l1_sf1_w7_reserved;
static int hf_ubx_gps_l1_sf1_w7_tgd;
static int hf_ubx_gps_l1_sf1_w7_parity;
static int hf_ubx_gps_l1_sf1_w8_iodc_lsbs;
static int hf_ubx_gps_l1_sf1_w8_toc;
static int hf_ubx_gps_l1_sf1_w8_parity;
static int hf_ubx_gps_l1_sf1_w9_af2;
static int hf_ubx_gps_l1_sf1_w9_af1;
static int hf_ubx_gps_l1_sf1_w9_parity;
static int hf_ubx_gps_l1_sf1_w10_af0;
static int hf_ubx_gps_l1_sf1_w10_t;
static int hf_ubx_gps_l1_sf1_w10_parity;

// Subframe 2 (see IS-GPS-200N, Section 20.3.3.4)
static int hf_ubx_gps_l1_sf2_w3_iode;
static int hf_ubx_gps_l1_sf2_w3_c_rs;
static int hf_ubx_gps_l1_sf2_w3_parity;
static int hf_ubx_gps_l1_sf2_w4_delta_n;
static int hf_ubx_gps_l1_sf2_w4_m0_msbs;
static int hf_ubx_gps_l1_sf2_w4_parity;
static int hf_ubx_gps_l1_sf2_w5_m0_lsbs;
static int hf_ubx_gps_l1_sf2_w5_parity;
static int hf_ubx_gps_l1_sf2_w6_c_uc;
static int hf_ubx_gps_l1_sf2_w6_e_msbs;
static int hf_ubx_gps_l1_sf2_w6_parity;
static int hf_ubx_gps_l1_sf2_w7_e_lsbs;
static int hf_ubx_gps_l1_sf2_w7_parity;
static int hf_ubx_gps_l1_sf2_w8_c_us;
static int hf_ubx_gps_l1_sf2_w8_sqrt_a_msbs;
static int hf_ubx_gps_l1_sf2_w8_parity;
static int hf_ubx_gps_l1_sf2_w9_sqrt_a_lsbs;
static int hf_ubx_gps_l1_sf2_w9_parity;
static int hf_ubx_gps_l1_sf2_w10_t_oe;
static int hf_ubx_gps_l1_sf2_w10_fif;
static int hf_ubx_gps_l1_sf2_w10_aodo;
static int hf_ubx_gps_l1_sf2_w10_t;
static int hf_ubx_gps_l1_sf2_w10_parity;

static dissector_table_t ubx_gps_l1_sf_dissector_table;

static expert_field ei_ubx_gps_l1_tlm_preamble;
static expert_field ei_ubx_gps_l1_how_tow_count;
static expert_field ei_ubx_gps_l1_how_subframe_id;

static int ett_ubx_gps_l1;
static int ett_ubx_gps_l1_tlm;
static int ett_ubx_gps_l1_how;
static int ett_ubx_gps_l1_sf1_w3;
static int ett_ubx_gps_l1_sf1_w4;
static int ett_ubx_gps_l1_sf1_w5;
static int ett_ubx_gps_l1_sf1_w6;
static int ett_ubx_gps_l1_sf1_w7;
static int ett_ubx_gps_l1_sf1_w8;
static int ett_ubx_gps_l1_sf1_w9;
static int ett_ubx_gps_l1_sf1_w10;
static int ett_ubx_gps_l1_sf2_w3;
static int ett_ubx_gps_l1_sf2_w4;
static int ett_ubx_gps_l1_sf2_w5;
static int ett_ubx_gps_l1_sf2_w6;
static int ett_ubx_gps_l1_sf2_w7;
static int ett_ubx_gps_l1_sf2_w8;
static int ett_ubx_gps_l1_sf2_w9;
static int ett_ubx_gps_l1_sf2_w10;

/* Format TOW count */
static void fmt_tow_count(char *label, int32_t c) {
    unsigned tow = c << 2;
    snprintf(label, ITEM_LABEL_LENGTH, "%d (TOW: %.1fs)", c, tow * 1.5);
}

/* Format Clock Data Reference Time t_OC */
static void fmt_t_oc(char *label, int32_t i) {
    unsigned t_oc = i << 4;
    snprintf(label, ITEM_LABEL_LENGTH, "%ds", t_oc);
}

/* Dissect GPS L1 C/A LNAV navigation message */
static int dissect_ubx_gps_l1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint32_t subframe_id = (tvb_get_uint32(tvb, 4, ENC_LITTLE_ENDIAN) & 0x00000700) >> 8;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GPS L1 LNAV");
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Subframe %i", subframe_id);

    proto_tree *gps_l1_tree = proto_tree_add_subtree_format(tree, tvb, 0, 40, ett_ubx_gps_l1, NULL, "GPS L1 LNAV (Subframe %i)", subframe_id);

    // send the subframe to the next dissector
    if (!dissector_try_uint(ubx_gps_l1_sf_dissector_table, subframe_id, tvb, pinfo, gps_l1_tree)) {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

// Dissect the telemetry (TLM) word
static void dissect_ubx_gps_l1_tlm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    proto_tree *tlm_tree = proto_tree_add_subtree_format(tree, tvb, 0, 4, ett_ubx_gps_l1_tlm, NULL, "Word 1: Telemetry");

    uint32_t tlm_preamble;
    proto_item* pi_tlm_preamble = proto_tree_add_item_ret_uint(tlm_tree, hf_ubx_gps_l1_tlm_preamble, tvb, 0, 4, ENC_LITTLE_ENDIAN, &tlm_preamble);
    if (tlm_preamble != 0x8b) {
        expert_add_info(pinfo, pi_tlm_preamble, &ei_ubx_gps_l1_tlm_preamble);
    }

    proto_tree_add_item(tlm_tree, hf_ubx_gps_l1_tlm_message,   tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tlm_tree, hf_ubx_gps_l1_tlm_integrity, tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tlm_tree, hf_ubx_gps_l1_tlm_reserved,  tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tlm_tree, hf_ubx_gps_l1_tlm_parity,    tvb, 0, 4, ENC_LITTLE_ENDIAN);
}

// Dissect the handover word (HOW)
static void dissect_ubx_gps_l1_how(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    uint32_t subframe_id;

    proto_tree *how_tree = proto_tree_add_subtree_format(tree, tvb, 4, 4, ett_ubx_gps_l1_how, NULL, "Word 2: Handover");

    uint32_t tow_count;
    proto_item* pi_how_tow_count = proto_tree_add_item_ret_uint(how_tree, hf_ubx_gps_l1_how_tow_count, tvb, 4, 4, ENC_LITTLE_ENDIAN, &tow_count);
    if (tow_count > 100799) {
        expert_add_info(pinfo, pi_how_tow_count, &ei_ubx_gps_l1_how_tow_count);
    }

    proto_tree_add_item(how_tree, hf_ubx_gps_l1_how_alert,      tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(how_tree, hf_ubx_gps_l1_how_anti_spoof, tvb, 4, 4, ENC_LITTLE_ENDIAN);

    proto_item* pi_how_sf_id = proto_tree_add_item_ret_uint(how_tree, hf_ubx_gps_l1_how_subframe_id, tvb, 4, 4, ENC_LITTLE_ENDIAN, &subframe_id);
    if (subframe_id > 5) {
        expert_add_info(pinfo, pi_how_sf_id, &ei_ubx_gps_l1_how_subframe_id);
    }

    proto_tree_add_item(how_tree, hf_ubx_gps_l1_how_parity_sol, tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(how_tree, hf_ubx_gps_l1_how_parity,     tvb, 4, 4, ENC_LITTLE_ENDIAN);
}

/* Dissect subframe 1 */
static int dissect_ubx_gps_l1_sf1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    dissect_ubx_gps_l1_tlm(tvb, pinfo, tree, data);
    dissect_ubx_gps_l1_how(tvb, pinfo, tree, data);

    // subframe 1, word 3
    proto_tree *w3_tree = proto_tree_add_subtree_format(tree,            tvb, 8, 4, ett_ubx_gps_l1_sf1_w3, NULL, "Word 3");
    proto_tree_add_item(w3_tree, hf_ubx_gps_l1_sf1_w3_week_no,           tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w3_tree, hf_ubx_gps_l1_sf1_w3_l2_channel_code,   tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w3_tree, hf_ubx_gps_l1_sf1_w3_ura_index,         tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w3_tree, hf_ubx_gps_l1_sf1_w3_sv_health_summary, tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w3_tree, hf_ubx_gps_l1_sf1_w3_sv_health,         tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w3_tree, hf_ubx_gps_l1_sf1_w3_iodc_msbs,         tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w3_tree, hf_ubx_gps_l1_sf1_w3_parity,            tvb, 8, 4, ENC_LITTLE_ENDIAN);

    // subframe 1, word 4
    proto_tree *w4_tree = proto_tree_add_subtree_format(tree,         tvb, 12, 4, ett_ubx_gps_l1_sf1_w4, NULL, "Word 4");
    proto_tree_add_item(w4_tree, hf_ubx_gps_l1_sf1_w4_l2_p_data_flag, tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w4_tree, hf_ubx_gps_l1_sf1_w4_reserved,       tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w4_tree, hf_ubx_gps_l1_sf1_w4_parity,         tvb, 12, 4, ENC_LITTLE_ENDIAN);


    // subframe 1, word 5
    proto_tree *w5_tree = proto_tree_add_subtree_format(tree,   tvb, 16, 4, ett_ubx_gps_l1_sf1_w5, NULL, "Word 5");
    proto_tree_add_item(w5_tree, hf_ubx_gps_l1_sf1_w5_reserved, tvb, 16, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w5_tree, hf_ubx_gps_l1_sf1_w5_parity,   tvb, 16, 4, ENC_LITTLE_ENDIAN);

    // subframe 1, word 6
    proto_tree *w6_tree = proto_tree_add_subtree_format(tree,   tvb, 20, 4, ett_ubx_gps_l1_sf1_w6, NULL, "Word 6");
    proto_tree_add_item(w6_tree, hf_ubx_gps_l1_sf1_w6_reserved, tvb, 20, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w6_tree, hf_ubx_gps_l1_sf1_w6_parity,   tvb, 20, 4, ENC_LITTLE_ENDIAN);

    // subframe 1, word 7
    proto_tree *w7_tree = proto_tree_add_subtree_format(tree,   tvb, 24, 4, ett_ubx_gps_l1_sf1_w7, NULL, "Word 7");
    proto_tree_add_item(w7_tree, hf_ubx_gps_l1_sf1_w7_reserved, tvb, 24, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w7_tree, hf_ubx_gps_l1_sf1_w7_tgd,      tvb, 24, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w7_tree, hf_ubx_gps_l1_sf1_w7_parity,   tvb, 24, 4, ENC_LITTLE_ENDIAN);

    // subframe 1, word 8
    proto_tree *w8_tree = proto_tree_add_subtree_format(tree,     tvb, 28, 4, ett_ubx_gps_l1_sf1_w8, NULL, "Word 8");
    proto_tree_add_item(w8_tree, hf_ubx_gps_l1_sf1_w8_iodc_lsbs,  tvb, 28, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w8_tree, hf_ubx_gps_l1_sf1_w8_toc,        tvb, 28, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w8_tree, hf_ubx_gps_l1_sf1_w8_parity,     tvb, 28, 4, ENC_LITTLE_ENDIAN);

    // subframe 1, word 9
    proto_tree *w9_tree = proto_tree_add_subtree_format(tree, tvb, 32, 4, ett_ubx_gps_l1_sf1_w9, NULL, "Word 9");
    proto_tree_add_item(w9_tree, hf_ubx_gps_l1_sf1_w9_af2,    tvb, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w9_tree, hf_ubx_gps_l1_sf1_w9_af1,    tvb, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w9_tree, hf_ubx_gps_l1_sf1_w9_parity, tvb, 32, 4, ENC_LITTLE_ENDIAN);

    // subframe 1, word 10
    proto_tree *w10_tree = proto_tree_add_subtree_format(tree,  tvb, 36, 4, ett_ubx_gps_l1_sf1_w10, NULL, "Word 10");
    proto_tree_add_item(w10_tree, hf_ubx_gps_l1_sf1_w10_af0,    tvb, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w10_tree, hf_ubx_gps_l1_sf1_w10_t,      tvb, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w10_tree, hf_ubx_gps_l1_sf1_w10_parity, tvb, 36, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect subframe 2 */
static int dissect_ubx_gps_l1_sf2(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {

    dissect_ubx_gps_l1_tlm(tvb, pinfo, tree, data);
    dissect_ubx_gps_l1_how(tvb, pinfo, tree, data);

    // subframe 2, word 3
    proto_tree *w3_tree = proto_tree_add_subtree_format(tree, tvb, 8, 4, ett_ubx_gps_l1_sf2_w3, NULL, "Word 3");
    proto_tree_add_item(w3_tree, hf_ubx_gps_l1_sf2_w3_iode,   tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w3_tree, hf_ubx_gps_l1_sf2_w3_c_rs,   tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w3_tree, hf_ubx_gps_l1_sf2_w3_parity, tvb, 8, 4, ENC_LITTLE_ENDIAN);

    // subframe 2, word 4
    proto_tree *w4_tree = proto_tree_add_subtree_format(tree,  tvb, 12, 4, ett_ubx_gps_l1_sf2_w4, NULL, "Word 4");
    proto_tree_add_item(w4_tree, hf_ubx_gps_l1_sf2_w4_delta_n, tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w4_tree, hf_ubx_gps_l1_sf2_w4_m0_msbs, tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w4_tree, hf_ubx_gps_l1_sf2_w4_parity,  tvb, 12, 4, ENC_LITTLE_ENDIAN);

    // subframe 2, word 5
    proto_tree *w5_tree = proto_tree_add_subtree_format(tree,  tvb, 16, 4, ett_ubx_gps_l1_sf2_w5, NULL, "Word 5");
    proto_tree_add_item(w5_tree, hf_ubx_gps_l1_sf2_w5_m0_lsbs, tvb, 16, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w5_tree, hf_ubx_gps_l1_sf2_w5_parity,  tvb, 16, 4, ENC_LITTLE_ENDIAN);

    // subframe 2, word 6
    proto_tree *w6_tree = proto_tree_add_subtree_format(tree, tvb, 20, 4, ett_ubx_gps_l1_sf2_w6, NULL, "Word 6");
    proto_tree_add_item(w6_tree, hf_ubx_gps_l1_sf2_w6_c_uc,   tvb, 20, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w6_tree, hf_ubx_gps_l1_sf2_w6_e_msbs, tvb, 20, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w6_tree, hf_ubx_gps_l1_sf2_w6_parity, tvb, 20, 4, ENC_LITTLE_ENDIAN);

    // subframe 2, word 7
    proto_tree *w7_tree = proto_tree_add_subtree_format(tree, tvb, 24, 4, ett_ubx_gps_l1_sf2_w7, NULL, "Word 7");
    proto_tree_add_item(w7_tree, hf_ubx_gps_l1_sf2_w7_e_lsbs, tvb, 24, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w7_tree, hf_ubx_gps_l1_sf2_w7_parity, tvb, 24, 4, ENC_LITTLE_ENDIAN);

    // subframe 2, word 8
    proto_tree *w8_tree = proto_tree_add_subtree_format(tree,      tvb, 28, 4, ett_ubx_gps_l1_sf2_w8, NULL, "Word 8");
    proto_tree_add_item(w8_tree, hf_ubx_gps_l1_sf2_w8_c_us,        tvb, 28, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w8_tree, hf_ubx_gps_l1_sf2_w8_sqrt_a_msbs, tvb, 28, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w8_tree, hf_ubx_gps_l1_sf2_w8_parity,      tvb, 28, 4, ENC_LITTLE_ENDIAN);

    // subframe 2, word 9
    proto_tree *w9_tree = proto_tree_add_subtree_format(tree,      tvb, 32, 4, ett_ubx_gps_l1_sf2_w9, NULL, "Word 9");
    proto_tree_add_item(w9_tree, hf_ubx_gps_l1_sf2_w9_sqrt_a_lsbs, tvb, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w9_tree, hf_ubx_gps_l1_sf2_w9_parity,      tvb, 32, 4, ENC_LITTLE_ENDIAN);

    // subframe 2, word 10
    proto_tree *w10_tree = proto_tree_add_subtree_format(tree,  tvb, 36, 4, ett_ubx_gps_l1_sf2_w10, NULL, "Word 10");
    proto_tree_add_item(w10_tree, hf_ubx_gps_l1_sf2_w10_t_oe,   tvb, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w10_tree, hf_ubx_gps_l1_sf2_w10_fif,    tvb, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w10_tree, hf_ubx_gps_l1_sf2_w10_aodo,   tvb, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w10_tree, hf_ubx_gps_l1_sf2_w10_t,      tvb, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(w10_tree, hf_ubx_gps_l1_sf2_w10_parity, tvb, 36, 4, ENC_LITTLE_ENDIAN);

    // TODO: reassemble and dissect fields whose MSBs and LSBs are split across words

    return tvb_captured_length(tvb);
}

void proto_register_ubx_gps_l1(void) {

    static hf_register_info hf[] = {
        // All subframes - Word 1 (TLM)
        {&hf_ubx_gps_l1_tlm_preamble,  {"Preamble",                    "gps_l1.tlm.preamble",  FT_UINT32,  BASE_HEX,  NULL, 0x3fc00000, NULL, HFILL}},
        {&hf_ubx_gps_l1_tlm_message,   {"Message",                     "gps_l1.tlm.message",   FT_UINT32,  BASE_HEX,  NULL, 0x003fff00, NULL, HFILL}},
        {&hf_ubx_gps_l1_tlm_integrity, {"Integrity Status Flag (ISF)", "gps_l1.tlm.integrity", FT_BOOLEAN, 32,        NULL, 0x00000080, NULL, HFILL}},
        {&hf_ubx_gps_l1_tlm_reserved,  {"Reserved",                    "gps_l1.tlm.reserved",  FT_UINT32,  BASE_HEX,  NULL, 0x00000040, NULL, HFILL}},
        {&hf_ubx_gps_l1_tlm_parity,    {"Parity",                      "gps_l1.tlm.parity",    FT_UINT32,  BASE_HEX,  NULL, 0x0000003f, NULL, HFILL}},

        // All subframes - Word 2 (HOW)
        {&hf_ubx_gps_l1_how_tow_count,   {"Time-of-Week (TOW) Count",    "gps_l1.how.tow_count",   FT_UINT32,  BASE_CUSTOM, CF_FUNC(&fmt_tow_count), 0x3fffe000, NULL, HFILL}},
        {&hf_ubx_gps_l1_how_alert,       {"Alert",                       "gps_l1.how.alert",       FT_BOOLEAN, 32,        NULL, 0x00001000, NULL, HFILL}},
        {&hf_ubx_gps_l1_how_anti_spoof,  {"Anti-Spoof (A-S)",            "gps_l1.how.anti_spoof",  FT_BOOLEAN, 32,        NULL, 0x00000800, NULL, HFILL}},
        {&hf_ubx_gps_l1_how_subframe_id, {"Subframe ID",                 "gps_l1.how.subframe_id", FT_UINT32,  BASE_DEC,  NULL, 0x00000700, NULL, HFILL}},
        {&hf_ubx_gps_l1_how_parity_sol,  {"Solved for parity zero bits", "gps_l1.how.parity_sol",  FT_UINT32,  BASE_HEX,  NULL, 0x000000c0, NULL, HFILL}},
        {&hf_ubx_gps_l1_how_parity,      {"Parity",                      "gps_l1.how.parity",      FT_UINT32,  BASE_DEC,  NULL, 0x0000003f, NULL, HFILL}},


        // Subframe 1 - Word 3
        {&hf_ubx_gps_l1_sf1_w3_week_no,           {"Week Number",                         "gps_l1.sf1.w3.week_number",       FT_UINT32,  BASE_DEC,  NULL, 0x3ff00000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w3_l2_channel_code,   {"L2 Channel Code",                     "gps_l1.sf1.w3.l2_channel_code",   FT_UINT32,  BASE_HEX,  VALS(L2_CHANNEL_CODE), 0x000c0000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w3_ura_index,         {"URA Index",                           "gps_l1.sf1.w3.ura_index",         FT_UINT32,  BASE_HEX,  VALS(URA_INDEX), 0x0003c000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w3_sv_health_summary, {"SV Health Summary",                   "gps_l1.sf1.w3.sv_health_summary", FT_UINT32,  BASE_HEX,  VALS(SV_HEALTH_SUMMARY), 0x00002000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w3_sv_health,         {"SV's Signal Component Health Status", "gps_l1.sf1.w3.sv_health",         FT_UINT32,  BASE_HEX,  VALS(SV_HEALTH_CODE), 0x00001f00, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w3_iodc_msbs,         {"Issue of Data Clock (IODC) MSBs",     "gps_l1.sf1.w3.iodc_msbs",         FT_UINT32,  BASE_HEX,  NULL, 0x000000c0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w3_parity,            {"Parity",                              "gps_l1.sf1.w3.parity",         FT_UINT32,  BASE_HEX,  NULL, 0x0000003f, NULL, HFILL}},

        // Subframe 1 - Word 4
        {&hf_ubx_gps_l1_sf1_w4_l2_p_data_flag, {"L2 P Data Flag", "gps_l1.sf1.w4.l2_p_data_flag", FT_BOOLEAN, 32,       NULL, 0x20000000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w4_reserved,       {"Reserved",       "gps_l1.sf1.w4.reserved",       FT_UINT32,  BASE_HEX, NULL, 0x1fffffc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w4_parity,         {"Parity",         "gps_l1.sf1.w4.parity",         FT_UINT32,  BASE_HEX, NULL, 0x0000003f, NULL, HFILL}},

        // Subframe 1 - Word 5
        {&hf_ubx_gps_l1_sf1_w5_reserved, {"Reserved", "gps_l1.sf1.w5.reserved", FT_UINT32, BASE_HEX, NULL, 0x3fffffc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w5_parity,   {"Parity",   "gps_l1.sf1.w5.parity",   FT_UINT32, BASE_HEX, NULL, 0x0000003f, NULL, HFILL}},

        // Subframe 1 - Word 6
        {&hf_ubx_gps_l1_sf1_w6_reserved, {"Reserved", "gps_l1.sf1.w6.reserved", FT_UINT32, BASE_HEX, NULL, 0x3fffffc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w6_parity,   {"Parity",   "gps_l1.sf1.w6.parity",   FT_UINT32, BASE_HEX, NULL, 0x0000003f, NULL, HFILL}},

        // Subframe 1 - Word 7
        {&hf_ubx_gps_l1_sf1_w7_reserved, {"Reserved",                                "gps_l1.sf1.w7.reserved", FT_UINT32, BASE_HEX, NULL, 0x3fffc000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w7_tgd,      {"Estimated Group Delay Differential T_GD", "gps_l1.sf1.w7.tgd",      FT_INT32,  BASE_DEC, NULL, 0x00003fc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w7_parity,   {"Parity",                                  "gps_l1.sf1.w7.parity",   FT_UINT32, BASE_HEX, NULL, 0x0000003f, NULL, HFILL}},

        // Subframe 1 - Word 8
        {&hf_ubx_gps_l1_sf1_w8_iodc_lsbs, {"Issue of Data Clock (IODC) LSBs", "gps_l1.sf1.w8.iodc_lsbs", FT_UINT32, BASE_HEX,  NULL, 0x3fc00000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w8_toc,       {"Clock Data Reference Time t_OC",  "gps_l1.sf1.w8.toc",       FT_UINT32, BASE_CUSTOM, CF_FUNC(&fmt_t_oc), 0x003fffc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w8_parity,    {"Parity",                          "gps_l1.sf1.w8.parity",    FT_UINT32, BASE_HEX,  NULL, 0x0000003f, NULL, HFILL}},

        // Subframe 1 - Word 9
        {&hf_ubx_gps_l1_sf1_w9_af2,    {"Drift Rate Correction Coefficient a_f2",     "gps_l1.sf1.w9.af2",    FT_INT32,  BASE_DEC, NULL, 0x3fc00000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w9_af1,    {"SV Clock Drift Correction Coefficient a_f1", "gps_l1.sf1.w9.af1",    FT_INT32,  BASE_DEC, NULL, 0x003fffc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w9_parity, {"Parity",                                     "gps_l1.sf1.w9.parity", FT_UINT32, BASE_HEX, NULL, 0x0000003f, NULL, HFILL}},

        // Subframe 1 - Word 10
        {&hf_ubx_gps_l1_sf1_w10_af0,    {"SV Clock Bias Correction Coefficient a_f0", "gps_l1.sf1.w10.af0",    FT_INT32,  BASE_DEC, NULL, 0x3fffff00, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w10_t,      {"t",                                         "gps_l1.sf1.w10.t",      FT_UINT32, BASE_HEX, NULL, 0x000000c0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf1_w10_parity, {"Parity",                                    "gps_l1.sf1.w10.parity", FT_UINT32, BASE_HEX, NULL, 0x0000003f, NULL, HFILL}},


        // Subframe 2 - Word 3
        {&hf_ubx_gps_l1_sf2_w3_iode,   {"Issue of Data, Ephemeris (IODE)",                                           "gps_l1.sf2.w3.iode",    FT_UINT32, BASE_DEC,    NULL,                           0x3fc00000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w3_c_rs,   {"Amplitude of the sine harmonic correction term to the orbit radius (C_RS)", "gps_l1.sf2.w3.c_rs",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_orbit_correction), 0x003fffc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w3_parity, {"Parity",                                                                    "gps_l1.sf2.w3.parity",  FT_UINT32, BASE_HEX,    NULL,                           0x0000003f, NULL, HFILL}},

        // Subframe 2 - Word 4
        {&hf_ubx_gps_l1_sf2_w4_delta_n, {"Mean Motion Difference From Computed Value (" UTF8_CAPITAL_DELTA "n)", "gps_l1.sf2.w4.delta_n", FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_semi_circles_rate), 0x3fffc000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w4_m0_msbs, {"Mean Anomaly at Reference Time (M_0) MSBs",                            "gps_l1.sf2.w4.m0_msbs", FT_UINT32, BASE_HEX,    NULL,                            0x00003fc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w4_parity,  {"Parity",                                                               "gps_l1.sf2.w4.parity",  FT_UINT32, BASE_HEX,    NULL,                            0x0000003f, NULL, HFILL}},

        // Subframe 2 - Word 5
        {&hf_ubx_gps_l1_sf2_w5_m0_lsbs, {"Mean Anomaly at Reference Time (M_0) LSBs", "gps_l1.sf2.w5.m0_lsbs", FT_UINT32, BASE_HEX, NULL, 0x3fffffc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w5_parity,  {"Parity",                                    "gps_l1.sf2.w5.parity",  FT_UINT32, BASE_HEX, NULL, 0x0000003f, NULL, HFILL}},

        // Subframe 2 - Word 6
        {&hf_ubx_gps_l1_sf2_w6_c_uc,   {"Amplitude of the Cosine Harmonic Correction Term to the Argument of Latitude (C_uc)", "gps_l1.sf2.w6.c_uc",   FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_lat_correction), 0x3fffc000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w6_e_msbs, {"Eccentricity (e) MSBs",                                                               "gps_l1.sf2.w6.e_msbs", FT_UINT32, BASE_HEX,    NULL,                         0x00003fc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w6_parity, {"Parity",                                                                              "gps_l1.sf2.w6.parity", FT_UINT32, BASE_HEX,    NULL,                         0x0000003f, NULL, HFILL}},

        // Subframe 2 - Word 7
        {&hf_ubx_gps_l1_sf2_w7_e_lsbs, {"Eccentricity (e) LSBs", "gps_l1.sf2.w7.e_lsbs", FT_UINT32, BASE_HEX, NULL, 0x3fffffc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w7_parity, {"Parity",                "gps_l1.sf2.w7.parity", FT_UINT32, BASE_HEX, NULL, 0x0000003f, NULL, HFILL}},

        // Subframe 2 - Word 8
        {&hf_ubx_gps_l1_sf2_w8_c_us,        {"Amplitude of the Sine Harmonic Correction Term to the Argument of Latitude (C_us)", "gps_l1.sf2.w8.c_us",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_lat_correction), 0x3fffc000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w8_sqrt_a_msbs, {"Square Root of the Semi-Major Axis (" UTF8_SQUARE_ROOT "A) MSBs",                   "gps_l1.sf2.w8.sqrt_a_msbs", FT_UINT32, BASE_HEX,    NULL,                         0x00003fc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w8_parity,      {"Parity",                                                                            "gps_l1.sf2.w8.parity",      FT_UINT32, BASE_HEX,    NULL,                         0x0000003f, NULL, HFILL}},

        // Subframe 2 - Word 9
        {&hf_ubx_gps_l1_sf2_w9_sqrt_a_lsbs, {"Square Root of the Semi-Major Axis (" UTF8_SQUARE_ROOT "A) LSBs", "gps_l1.sf2.w9.sqrt_a_lsbs", FT_UINT32, BASE_HEX, NULL, 0x3fffffc0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w9_parity,      {"Parity",                                                          "gps_l1.sf2.w9.parity",      FT_UINT32, BASE_HEX, NULL, 0x0000003f, NULL, HFILL}},

        // Subframe 2 - Word 10
        {&hf_ubx_gps_l1_sf2_w10_t_oe,    {"Reference Time Ephemeris (t_oe)", "gps_l1.sf2.w10.t_oe",   FT_UINT32, BASE_CUSTOM, CF_FUNC(&fmt_t_oe),      0x3fffc000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w10_fif,     {"Fit Interval Flag",               "gps_l1.sf2.w10.fif",    FT_UINT32, BASE_HEX,    VALS(FIT_INTERVAL_FLAG), 0x00002000, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w10_aodo,    {"Age of Data Offset (AODO)",       "gps_l1.sf2.w10.aodo",   FT_UINT32, BASE_CUSTOM, CF_FUNC(&fmt_aodo),      0x00001f00, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w10_t,       {"t",                               "gps_l1.sf2.w10.t",      FT_UINT32, BASE_HEX,    NULL,                    0x000000c0, NULL, HFILL}},
        {&hf_ubx_gps_l1_sf2_w10_parity,  {"Parity",                          "gps_l1.sf2.w10.parity", FT_UINT32, BASE_HEX,    NULL,                    0x0000003f, NULL, HFILL}},
    };

    expert_module_t *expert_ubx_gps_l1;

    static ei_register_info ei[] = {
        {&ei_ubx_gps_l1_tlm_preamble,    {"gps_l1.tlm.preamble.invalid",    PI_PROTOCOL, PI_WARN, "Invalid preamble",    EXPFILL}},
        {&ei_ubx_gps_l1_how_tow_count,   {"gps_l1.how.tow_count.invalid",   PI_PROTOCOL, PI_WARN, "Invalid TOW count",   EXPFILL}},
        {&ei_ubx_gps_l1_how_subframe_id, {"gps_l1.how.subframe_id.invalid", PI_PROTOCOL, PI_WARN, "Invalid subframe ID", EXPFILL}},
    };

    static int *ett[] = {
        &ett_ubx_gps_l1,
        &ett_ubx_gps_l1_tlm,
        &ett_ubx_gps_l1_how,
        &ett_ubx_gps_l1_sf1_w3,
        &ett_ubx_gps_l1_sf1_w4,
        &ett_ubx_gps_l1_sf1_w5,
        &ett_ubx_gps_l1_sf1_w6,
        &ett_ubx_gps_l1_sf1_w7,
        &ett_ubx_gps_l1_sf1_w8,
        &ett_ubx_gps_l1_sf1_w9,
        &ett_ubx_gps_l1_sf1_w10,
        &ett_ubx_gps_l1_sf2_w3,
        &ett_ubx_gps_l1_sf2_w4,
        &ett_ubx_gps_l1_sf2_w5,
        &ett_ubx_gps_l1_sf2_w6,
        &ett_ubx_gps_l1_sf2_w7,
        &ett_ubx_gps_l1_sf2_w8,
        &ett_ubx_gps_l1_sf2_w9,
        &ett_ubx_gps_l1_sf2_w10,
    };

    proto_ubx_gps_l1 = proto_register_protocol("GPS L1 Navigation Message", "GPS L1", "gps_l1");

    register_dissector("ubx_gps_l1", dissect_ubx_gps_l1, proto_ubx_gps_l1);

    proto_register_field_array(proto_ubx_gps_l1, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_ubx_gps_l1 = expert_register_protocol(proto_ubx_gps_l1);
    expert_register_field_array(expert_ubx_gps_l1, ei, array_length(ei));

    ubx_gps_l1_sf_dissector_table = register_dissector_table("ubx.rxm.sfrbx.gps_l1.sf",
            "GPS L1 LNAV Subframe", proto_ubx_gps_l1, FT_UINT8, BASE_DEC);
}

void proto_reg_handoff_ubx_gps_l1(void) {
    dissector_add_uint("ubx.rxm.sfrbx.gnssid", GNSS_ID_GPS,
            create_dissector_handle(dissect_ubx_gps_l1, proto_ubx_gps_l1));

    dissector_add_uint("ubx.rxm.sfrbx.gps_l1.sf", 1,
            create_dissector_handle(dissect_ubx_gps_l1_sf1, proto_ubx_gps_l1));
    dissector_add_uint("ubx.rxm.sfrbx.gps_l1.sf", 2,
            create_dissector_handle(dissect_ubx_gps_l1_sf2, proto_ubx_gps_l1));
}
