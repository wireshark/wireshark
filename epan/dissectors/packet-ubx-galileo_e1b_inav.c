/* packet-ubx-galileo_e1b_inav.c
 * Dissection of Galileo E1-B I/NAV navigation messages
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

#include <epan/packet.h>
#include <wsutil/pint.h>
#include <wsutil/utf8_entities.h>

#include "packet-ubx.h"

/*
 * Dissects Galileo E1-B I/NAV navigation messages
 * as encoded by UBX (in UBX-RXM-SFRBX messages).
 * Based on Galileo OS SIS ICD Issue 2.1
 */

// Initialize the protocol and registered fields
static int proto_ubx_gal_inav;

static int hf_ubx_gal_inav_even_odd;
static int hf_ubx_gal_inav_page_type;
static int hf_ubx_gal_inav_type;
static int hf_ubx_gal_inav_data_122_67;
static int hf_ubx_gal_inav_data_66_17;
static int hf_ubx_gal_inav_data_16_1;
static int hf_ubx_gal_inav_osnma;
static int hf_ubx_gal_inav_sar_start_bit;
static int hf_ubx_gal_inav_sar_long_rlm;
static int hf_ubx_gal_inav_sar_beacon_1;
static int hf_ubx_gal_inav_sar_rlm_data;
static int hf_ubx_gal_inav_spare;
static int hf_ubx_gal_inav_ssp;
static int hf_ubx_gal_inav_crc;
static int hf_ubx_gal_inav_tail;
static int hf_ubx_gal_inav_pad;
static int hf_ubx_gal_inav_reserved_1;

static int hf_ubx_gal_inav_word0;
static int hf_ubx_gal_inav_word0_type;
static int hf_ubx_gal_inav_word0_time;
static int hf_ubx_gal_inav_word0_spare;
static int hf_ubx_gal_inav_word0_wn;
static int hf_ubx_gal_inav_word0_tow;

static int hf_ubx_gal_inav_word1;
static int hf_ubx_gal_inav_word1_type;
static int hf_ubx_gal_inav_word1_iodnav;
static int hf_ubx_gal_inav_word1_t0e;
static int hf_ubx_gal_inav_word1_m0;
static int hf_ubx_gal_inav_word1_e;
static int hf_ubx_gal_inav_word1_sqrta;
static int hf_ubx_gal_inav_word1_reserved;

static dissector_table_t ubx_gal_inav_word_dissector_table;

static int ett_ubx_gal_inav;
static int ett_ubx_gal_inav_word0;
static int ett_ubx_gal_inav_word1;
static int ett_ubx_gal_inav_sar;

static const value_string GAL_PAGE_TYPE[] = {
    {0, "nominal"},
    {1, "alert"},
    {0, NULL},
};

static const value_string GAL_SSP[] = {
    {0x04, "SSP 1"},
    {0x2b, "SSP 2"},
    {0x2f, "SSP 3"},
    {0, NULL},
};

/* Format mean anomaly at reference time */
static void fmt_m0(char *label, int64_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%" PRId64 " * 2^-31 semi-circles", c);
}

/* Format eccentricity */
static void fmt_e(char *label, uint64_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%" PRIu64 " * 2^-33", c);
}

/* Format square root of the semi-major axis */
static void fmt_sqrt_a(char *label, uint64_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%" PRIu64 " * 2^-19 " UTF8_SQUARE_ROOT "m", c);
}

/* Format ephemeris reference time */
static void fmt_t0e(char *label, uint32_t c) {
    c = c * 60;
    snprintf(label, ITEM_LABEL_LENGTH, "%ds", c);
}

/* Dissect Galileo E1-B I/NAV navigation message */
static int dissect_ubx_gal_inav(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tvbuff_t *next_tvb;

    bool sar_start, sar_long_rlm;
    uint32_t inav_type, page_type;
    uint64_t data_122_67, data_66_17, data_16_1;
    uint8_t *word;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Galileo E1-B I/NAV");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_tree *gal_inav_tree = proto_tree_add_subtree(tree, tvb, 0, 32, ett_ubx_gal_inav, NULL, "Galileo E1-B I/NAV");

    // even page
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_even_odd, tvb, 0, 1, ENC_NA);
    proto_tree_add_item_ret_uint(gal_inav_tree, hf_ubx_gal_inav_page_type, tvb, 0, 1, ENC_NA, &page_type);

    if (page_type == 1) { // alert page
        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_reserved_1,  tvb, 0, 15, ENC_NA);
    }
    else { // nominal page
        proto_tree_add_item_ret_uint(gal_inav_tree,   hf_ubx_gal_inav_type,        tvb, 0,  1, ENC_NA,         &inav_type);
        proto_tree_add_item_ret_uint64(gal_inav_tree, hf_ubx_gal_inav_data_122_67, tvb, 0,  8, ENC_BIG_ENDIAN, &data_122_67);
        proto_tree_add_item_ret_uint64(gal_inav_tree, hf_ubx_gal_inav_data_66_17,  tvb, 8,  8, ENC_BIG_ENDIAN, &data_66_17);
    }

    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_tail,            tvb, 14, 1, ENC_NA);
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_pad,             tvb, 15, 1, ENC_NA);


    // odd page
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_even_odd, tvb, 16, 1, ENC_NA);
    proto_tree_add_item_ret_uint(gal_inav_tree, hf_ubx_gal_inav_page_type, tvb, 16, 1, ENC_NA, &page_type);

    if (page_type == 1) { // alert page
        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_reserved_1,  tvb, 16, 11, ENC_NA);
    }
    else { // nominal page
        proto_tree_add_item_ret_uint64(gal_inav_tree, hf_ubx_gal_inav_data_16_1,   tvb, 16, 8, ENC_BIG_ENDIAN, &data_16_1);
        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_osnma,       tvb, 16, 8, ENC_BIG_ENDIAN);

        proto_tree *sar_tree = proto_tree_add_subtree(gal_inav_tree, tvb, 23, 4, ett_ubx_gal_inav_sar, NULL, "SAR");
        proto_tree_add_item_ret_boolean(sar_tree, hf_ubx_gal_inav_sar_start_bit, tvb, 23, 4, ENC_BIG_ENDIAN, &sar_start);
        proto_tree_add_item_ret_boolean(sar_tree, hf_ubx_gal_inav_sar_long_rlm,  tvb, 23, 4, ENC_BIG_ENDIAN, &sar_long_rlm);
        if (sar_start) {
            proto_tree_add_item(sar_tree, hf_ubx_gal_inav_sar_beacon_1, tvb, 23, 4, ENC_BIG_ENDIAN);
        }
        else {
            // TODO: add more elaborate dissection for subsequent RLM data (requiring state tracking)
            proto_tree_add_item(sar_tree, hf_ubx_gal_inav_sar_rlm_data, tvb, 23, 4, ENC_BIG_ENDIAN);
        }

        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_spare,       tvb, 26, 1, ENC_NA);
    }

    // TODO: check CRC
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_crc,           tvb, 26, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_ssp,           tvb, 28, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_tail,          tvb, 30, 1, ENC_NA);
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_pad,           tvb, 31, 1, ENC_NA);

    // handoff the data word of a nominal page
    if (page_type == 0) {
        // create new tvb with the data word
        word = wmem_alloc(pinfo->pool, 16);
        phton16(word + 14, data_16_1);
        phton64(word + 6, data_66_17);
        phton64(word, (((uint64_t) inav_type) << 58) | (data_122_67 << 2) | (data_66_17 >> 48));

        next_tvb = tvb_new_child_real_data(tvb, (uint8_t *)word, 16, 16);
        add_new_data_source(pinfo, next_tvb, "Galileo I/NAV Word");

        // handoff to appropriate dissector
        if (!dissector_try_uint(ubx_gal_inav_word_dissector_table, inav_type, next_tvb, pinfo, tree)) {
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }

    return tvb_captured_length(tvb);
}

/* Dissect word 0 - I/NAV Spare Word */
static int dissect_ubx_gal_inav_word0(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    col_append_fstr(pinfo->cinfo, COL_INFO, "Word 0 (Spare Word)");

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_gal_inav_word0, tvb, 0, 16, ENC_NA);
    proto_tree *word_tree = proto_item_add_subtree(ti, ett_ubx_gal_inav_word0);

    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word0_type,  tvb,  0,  1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word0_time,  tvb,  0,  1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word0_spare, tvb,  1, 11, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word0_wn,    tvb, 12,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word0_tow,   tvb, 12,  4, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect word 1 - Ephemeris (1/4) */
static int dissect_ubx_gal_inav_word1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    col_append_fstr(pinfo->cinfo, COL_INFO, "Word 1 (Ephemeris (1/4))");

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_gal_inav_word1, tvb, 0, 16, ENC_NA);
    proto_tree *word_tree = proto_item_add_subtree(ti, ett_ubx_gal_inav_word1);

    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_type,     tvb,  0, 1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_iodnav,   tvb,  0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_t0e,      tvb,  2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_m0,       tvb,  3, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_e,        tvb,  7, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_sqrta,    tvb,  8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_reserved, tvb, 15, 1, ENC_NA);

    return tvb_captured_length(tvb);
}

void proto_register_ubx_gal_inav(void) {

    static hf_register_info hf[] = {
        {&hf_ubx_gal_inav_even_odd,      {"Even/Odd",      "gal_inav.even_odd",      FT_BOOLEAN, 8,         TFS(&tfs_odd_even),  0x80,               NULL, HFILL}},
        {&hf_ubx_gal_inav_page_type,     {"Page Type",     "gal_inav.page_type",     FT_UINT8,   BASE_DEC,  VALS(GAL_PAGE_TYPE), 0x40,               NULL, HFILL}},
        {&hf_ubx_gal_inav_type,          {"Type",          "gal_inav.type",          FT_UINT8,   BASE_DEC,  NULL,                0x3f,               NULL, HFILL}},
        {&hf_ubx_gal_inav_data_122_67,   {"Data (122-67)", "gal_inav.data_122_67",   FT_UINT64,  BASE_HEX,  NULL,                0x00ffffffffffffff, NULL, HFILL}},
        {&hf_ubx_gal_inav_data_66_17,    {"Data (66-17)",  "gal_inav.data_66_17",    FT_UINT64,  BASE_HEX,  NULL,                0xffffffffffffc000, NULL, HFILL}},
        {&hf_ubx_gal_inav_data_16_1,     {"Data (16-1)",   "gal_inav.data_16_1",     FT_UINT64,  BASE_HEX,  NULL,                0x3fffc00000000000, NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma,         {"OSNMA",         "gal_inav.osnma",         FT_UINT64,  BASE_HEX,  NULL,                0x00003fffffffffc0, NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_start_bit, {"Start bit",     "gal_inav.sar.start_bit", FT_BOOLEAN, 32,        NULL,                0x20000000,         NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_long_rlm,  {"Long RLM",      "gal_inav.sar.long_rlm",  FT_BOOLEAN, 32,        NULL,                0x10000000,         NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_beacon_1,  {"Beacon (1/3)",  "gal_inav.sar.beacon_1",  FT_UINT32,  BASE_HEX,  NULL,                0x0fffff00,         NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_rlm_data,  {"RLM data",      "gal_inav.sar.rlm_data",  FT_UINT32,  BASE_HEX,  NULL,                0x0fffff00,         NULL, HFILL}},
        {&hf_ubx_gal_inav_spare,         {"Spare",         "gal_inav.spare",         FT_UINT8,   BASE_HEX,  NULL,                0xc0,               NULL, HFILL}},
        {&hf_ubx_gal_inav_reserved_1,    {"Reserved 1",    "gal_inav.reserved_1",    FT_NONE,    BASE_NONE, NULL,                0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_crc,           {"CRC",           "gal_inav.crc",           FT_UINT32,  BASE_HEX,  NULL,                0x3fffffc0,         NULL, HFILL}},
        {&hf_ubx_gal_inav_ssp,           {"SSP",           "gal_inav.ssp",           FT_UINT32,  BASE_HEX,  VALS(GAL_SSP),       0x003fc000,         NULL, HFILL}},
        {&hf_ubx_gal_inav_tail,          {"Tail",          "gal_inav.tail",          FT_UINT8,   BASE_HEX,  NULL,                0x3f,               NULL, HFILL}},
        {&hf_ubx_gal_inav_pad,           {"Pad",           "gal_inav.pad",           FT_UINT8,   BASE_HEX,  NULL,                0x0,                NULL, HFILL}},

        // Word 0
        {&hf_ubx_gal_inav_word0,         {"Word 0 (Spare Word)", "gal_inav.word0",         FT_NONE,       BASE_NONE, NULL, 0x0,  NULL, HFILL}},
        {&hf_ubx_gal_inav_word0_type,    {"Type",                "gal_inav.word0.type",    FT_UINT8,      BASE_HEX,  NULL, 0xfc, NULL, HFILL}},
        {&hf_ubx_gal_inav_word0_time,    {"Time",                "gal_inav.word0.time",    FT_UINT8,      BASE_HEX,  NULL, 0x03, NULL, HFILL}},
        {&hf_ubx_gal_inav_word0_spare,   {"Spare",               "gal_inav.word0.spare",   FT_BYTES,      BASE_NONE|SEP_SPACE, NULL, 0x0,  NULL, HFILL}},
        {&hf_ubx_gal_inav_word0_wn,      {"Week Number",         "gal_inav.word0.wn",      FT_UINT32,     BASE_DEC,  NULL, 0xfff00000,  NULL, HFILL}},
        {&hf_ubx_gal_inav_word0_tow,     {"Time of Week",        "gal_inav.word0.tow",     FT_UINT32,     BASE_DEC,  NULL, 0x000fffff,  NULL, HFILL}},

        // Word 1
        {&hf_ubx_gal_inav_word1,         {"Word 1 (Ephemeris (1/4))",                 "gal_inav.word1",          FT_NONE,   BASE_NONE, NULL, 0x0,    NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_type,    {"Type",                                     "gal_inav.word1.type",     FT_UINT8,  BASE_HEX,  NULL, 0xfc,   NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_iodnav,  {"IOD_nav",                                  "gal_inav.word1.iod_nav",  FT_UINT16, BASE_DEC,  NULL, 0x03ff, NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_t0e,     {"Ephemeris reference time (t_0e)",          "gal_inav.word1.t_0e",     FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_t0e), 0xfffc, NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_m0,      {"Mean anomaly at reference time (M_0)",     "gal_inav.word1.m_0",      FT_INT64,  BASE_CUSTOM, CF_FUNC(&fmt_m0),     0x03fffffffc000000, NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_e,       {"Eccentricity (e)",                         "gal_inav.word1.e",        FT_UINT64, BASE_CUSTOM, CF_FUNC(&fmt_e),      0x03fffffffc000000, NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_sqrta,   {"Square root of the semi-major axis (" UTF8_SQUARE_ROOT "a)", "gal_inav.word1.sqrt_a",   FT_UINT64, BASE_CUSTOM, CF_FUNC(&fmt_sqrt_a), 0x00000003fffffffc, NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_reserved,{"Reserved",                                 "gal_inav.word1.reserved", FT_UINT8,  BASE_HEX, NULL, 0x03, NULL, HFILL}},
    };

    static int *ett[] = {
        &ett_ubx_gal_inav,
        &ett_ubx_gal_inav_sar,
    };

    proto_ubx_gal_inav = proto_register_protocol("Galileo E1-B I/NAV Navigation Message", "Galileo I/NAV", "gal_inav");

    proto_register_field_array(proto_ubx_gal_inav, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("ubx_gal_inav", dissect_ubx_gal_inav, proto_ubx_gal_inav);

    ubx_gal_inav_word_dissector_table = register_dissector_table("ubx.rxm.sfrbx.gal_inav.word",
            "Galileo I/NAV Word", proto_ubx_gal_inav, FT_UINT8, BASE_DEC);
}

void proto_reg_handoff_ubx_gal_inav(void) {
    dissector_add_uint("ubx.rxm.sfrbx.gnssid", GNSS_ID_GALILEO, create_dissector_handle(dissect_ubx_gal_inav, proto_ubx_gal_inav));

    dissector_add_uint("ubx.rxm.sfrbx.gal_inav.word", 0, create_dissector_handle(dissect_ubx_gal_inav_word0, proto_ubx_gal_inav));
    dissector_add_uint("ubx.rxm.sfrbx.gal_inav.word", 1, create_dissector_handle(dissect_ubx_gal_inav_word1, proto_ubx_gal_inav));
}
