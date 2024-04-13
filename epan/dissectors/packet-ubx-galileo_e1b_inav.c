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

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tfs.h>

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

static int ett_ubx_gal_inav;
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

/* Dissect Galileo E1-B I/NAV navigation message */
static int dissect_ubx_gal_inav(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    bool sar_start, sar_long_rlm;
    guint32 page_type;

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
        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_type,        tvb, 0,  1, ENC_NA);
        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_data_122_67, tvb, 0,  8, ENC_BIG_ENDIAN);
        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_data_66_17,  tvb, 8,  8, ENC_BIG_ENDIAN);
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
        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_data_16_1,   tvb, 16, 8, ENC_BIG_ENDIAN);
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
    };

    static gint *ett[] = {
        &ett_ubx_gal_inav,
        &ett_ubx_gal_inav_sar,
    };

    proto_ubx_gal_inav = proto_register_protocol("Galileo E1-B I/NAV Navigation Message", "Galileo I/NAV", "gal_inav");

    proto_register_field_array(proto_ubx_gal_inav, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("ubx_gal_inav", dissect_ubx_gal_inav, proto_ubx_gal_inav);
}

void proto_reg_handoff_ubx_gal_inav(void) {
    dissector_add_uint("ubx.rxm.sfrbx.gnssid", GNSS_ID_GALILEO, create_dissector_handle(dissect_ubx_gal_inav, proto_ubx_gal_inav));
}
