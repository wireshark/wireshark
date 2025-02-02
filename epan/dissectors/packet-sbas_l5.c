/* packet-sbas_l5.c
 * SBAS L5 protocol dissection.
 *
 * By Timo Warns <timo.warns@gmail.com>
 * Copyright 2025 Timo Warns
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
#include <epan/unit_strings.h>

#include <wsutil/array.h>
#include <wsutil/utf8_entities.h>

#include "packet-sbas_l1.h"

/*
 * Dissects navigation messages of the Satellite Based Augmentation System
 * (SBAS) sent on L5 frequency as defined by ICAO Annex 10, Vol I, 8th edition.
 */

// SBAS L5 preamble values
#define SBAS_L5_PREAMBLE_1 0x05
#define SBAS_L5_PREAMBLE_2 0x0c
#define SBAS_L5_PREAMBLE_3 0x06
#define SBAS_L5_PREAMBLE_4 0x09
#define SBAS_L5_PREAMBLE_5 0x03
#define SBAS_L5_PREAMBLE_6 0x0a

static const char *EMS_L5_SVC_FLAG = "L5";

/* Initialize the protocol and registered fields */
static int proto_sbas_l5;

// see ICAO Annex 10, Vol I, 8th edition, Appendix B, Section 3.5.10
static int hf_sbas_l5_preamble;
static int hf_sbas_l5_mt;
static int hf_sbas_l5_checksum;

// see ICAO Annex 10, Vol I, 8th edition, Appendix B, Table B-106
static int hf_sbas_l5_mt0;
static int hf_sbas_l5_mt0_reserved_1;
static int hf_sbas_l5_mt0_reserved_2;
static int hf_sbas_l5_mt0_reserved_3;

// see ICAO Annex 10, Vol I, 8th edition, Appendix B, Table B-107
static int hf_sbas_l5_mt31;
static int hf_sbas_l5_mt31_gps_mask;
static int hf_sbas_l5_mt31_glonass_mask;
static int hf_sbas_l5_mt31_galileo_mask;
static int hf_sbas_l5_mt31_spare_112_119;
static int hf_sbas_l5_mt31_sbas_mask;
static int hf_sbas_l5_mt31_bds_mask;
static int hf_sbas_l5_mt31_reserved;
static int hf_sbas_l5_mt31_spare_208_214;
static int hf_sbas_l5_mt31_iodm;

// see ICAO Annex 10, Vol I, 8th edition, Appendix B, Table B-118
static int hf_sbas_l5_mt63;
static int hf_sbas_l5_mt63_reserved_1;
static int hf_sbas_l5_mt63_reserved_2;
static int hf_sbas_l5_mt63_reserved_3;

static dissector_table_t sbas_l5_mt_dissector_table;

static expert_field ei_sbas_l5_preamble;
static expert_field ei_sbas_l5_mt0;
static expert_field ei_sbas_l5_crc;

static int ett_sbas_l5;
static int ett_sbas_l5_mt0;
static int ett_sbas_l5_mt31;
static int ett_sbas_l5_mt63;


/* Dissect SBAS L5 message */
static int dissect_sbas_l5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tvbuff_t *next_tvb;
    uint32_t preamble, mt, cmp_crc;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L5");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_sbas_l5, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l5_tree = proto_item_add_subtree(ti, ett_sbas_l5);

    // preamble
    proto_item* pi_preamble = proto_tree_add_item_ret_uint(
            sbas_l5_tree, hf_sbas_l5_preamble,
            tvb, 0, 1, ENC_NA,
            &preamble);
    if (preamble != SBAS_L5_PREAMBLE_1 &&
            preamble != SBAS_L5_PREAMBLE_2 &&
            preamble != SBAS_L5_PREAMBLE_3 &&
            preamble != SBAS_L5_PREAMBLE_4 &&
            preamble != SBAS_L5_PREAMBLE_5 &&
            preamble != SBAS_L5_PREAMBLE_6) {
        expert_add_info_format(pinfo, pi_preamble, &ei_sbas_l5_preamble,
                "Erroneous preamble");
    }

    // message type
    proto_item* pi_mt = proto_tree_add_item_ret_uint(
            sbas_l5_tree, hf_sbas_l5_mt,
            tvb, 0, 2, ENC_BIG_ENDIAN,
            &mt);
    if (mt == 0) { // flag "Do Not Use" MT0 messages
        expert_add_info(pinfo, pi_mt, &ei_sbas_l5_mt0);
    }

    // checksum
    cmp_crc = sbas_crc24q((uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, 29));
    proto_tree_add_checksum(sbas_l5_tree, tvb, 28, hf_sbas_l5_checksum, -1,
            &ei_sbas_l5_crc, NULL, cmp_crc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

    // try to dissect MT data
    next_tvb = tvb_new_subset_length(tvb, 1, 28);
    if (!dissector_try_uint(sbas_l5_mt_dissector_table, mt, next_tvb, pinfo, tree)) {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L5 MT 0 */
static int dissect_sbas_l5_mt0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT0");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l5_mt0, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l5_mt0_tree = proto_item_add_subtree(ti, ett_sbas_l5_mt0);

    proto_tree_add_item(sbas_l5_mt0_tree, hf_sbas_l5_mt0_reserved_1, tvb,  0,  1, ENC_NA);
    proto_tree_add_item(sbas_l5_mt0_tree, hf_sbas_l5_mt0_reserved_2, tvb,  1, 26, ENC_NA);
    proto_tree_add_item(sbas_l5_mt0_tree, hf_sbas_l5_mt0_reserved_3, tvb, 27,  1, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L5 MT 31 */
static int dissect_sbas_l5_mt31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT31");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l5_mt31, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l5_mt31_tree = proto_item_add_subtree(ti, ett_sbas_l5_mt31);

    proto_tree_add_item(sbas_l5_mt31_tree, hf_sbas_l5_mt31_gps_mask,      tvb,  0,  8, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l5_mt31_tree, hf_sbas_l5_mt31_glonass_mask,  tvb,  4,  8, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l5_mt31_tree, hf_sbas_l5_mt31_galileo_mask,  tvb,  9,  8, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l5_mt31_tree, hf_sbas_l5_mt31_spare_112_119, tvb, 14,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l5_mt31_tree, hf_sbas_l5_mt31_sbas_mask,     tvb, 15,  8, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l5_mt31_tree, hf_sbas_l5_mt31_bds_mask,      tvb, 20,  8, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l5_mt31_tree, hf_sbas_l5_mt31_reserved,      tvb, 24,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l5_mt31_tree, hf_sbas_l5_mt31_spare_208_214, tvb, 26,  1, ENC_NA);
    proto_tree_add_item(sbas_l5_mt31_tree, hf_sbas_l5_mt31_iodm,          tvb, 27,  1, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L5 MT 63 */
static int dissect_sbas_l5_mt63(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L5 MT63");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l5_mt63, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt63_tree = proto_item_add_subtree(ti, ett_sbas_l5_mt63);

    proto_tree_add_item(sbas_l1_mt63_tree, hf_sbas_l5_mt63_reserved_1, tvb,  0,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt63_tree, hf_sbas_l5_mt63_reserved_2, tvb,  1, 26, ENC_NA);
    proto_tree_add_item(sbas_l1_mt63_tree, hf_sbas_l5_mt63_reserved_3, tvb, 27,  1, ENC_NA);

    return tvb_captured_length(tvb);
}

void proto_register_sbas_l5(void) {

    static hf_register_info hf[] = {
        {&hf_sbas_l5_preamble, {"Preamble",     "sbas_l5.preamble", FT_UINT8,  BASE_HEX, NULL, 0xf0,       NULL, HFILL}},
        {&hf_sbas_l5_mt,       {"Message Type", "sbas_l5.mt"      , FT_UINT16, BASE_DEC, NULL, 0x0fc0,     NULL, HFILL}},
        {&hf_sbas_l5_checksum, {"Checksum",     "sbas_l5.checksum", FT_UINT32, BASE_HEX, NULL, 0x3fffffc0, NULL, HFILL}},

        // MT0
        {&hf_sbas_l5_mt0,            {"MT0",        "sbas_l5.mt0",            FT_NONE,  BASE_NONE, NULL, 0x00, NULL, HFILL}},
        {&hf_sbas_l5_mt0_reserved_1, {"Reserved 1", "sbas_l5.mt0.reserved_1", FT_UINT8, BASE_HEX,  NULL, 0x3f, NULL, HFILL}},
        {&hf_sbas_l5_mt0_reserved_2, {"Reserved 2", "sbas_l5.mt0.reserved_2", FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL}},
        {&hf_sbas_l5_mt0_reserved_3, {"Reserved 3", "sbas_l5.mt0.reserved_3", FT_UINT8, BASE_HEX,  NULL, 0xc0, NULL, HFILL}},

        // MT31
        {&hf_sbas_l5_mt31,               {"MT31",                        "sbas_l5.mt31",               FT_NONE,   BASE_NONE, NULL, 0x00,                         NULL, HFILL}},
        {&hf_sbas_l5_mt31_gps_mask,      {"GPS Mask",                    "sbas_l5.mt31.gps_mask",      FT_UINT64, BASE_HEX,  NULL, UINT64_C(0x3ffffffffe000000), NULL, HFILL}},
        {&hf_sbas_l5_mt31_glonass_mask,  {"GLONASS Mask",                "sbas_l5.mt31.glonass_mask",  FT_UINT64, BASE_HEX,  NULL, UINT64_C(0x01fffffffff00000), NULL, HFILL}},
        {&hf_sbas_l5_mt31_galileo_mask,  {"Galileo Mask",                "sbas_l5.mt31.galileo_mask",  FT_UINT64, BASE_HEX,  NULL, UINT64_C(0x0fffffffff800000), NULL, HFILL}},
        {&hf_sbas_l5_mt31_spare_112_119, {"Spare",                       "sbas_l5.mt31.spare_112_119", FT_UINT16, BASE_HEX,  NULL, 0x7f80,                       NULL, HFILL}},
        {&hf_sbas_l5_mt31_sbas_mask,     {"SBAS Mask",                   "sbas_l5.mt31.sbas_mask",     FT_UINT64, BASE_HEX,  NULL, UINT64_C(0x7fffffffff000000), NULL, HFILL}},
        {&hf_sbas_l5_mt31_bds_mask,      {"BDS Mask",                    "sbas_l5.mt31.bds_mask",      FT_UINT64, BASE_HEX,  NULL, UINT64_C(0xfffffffff8000000), NULL, HFILL}},
        {&hf_sbas_l5_mt31_reserved,      {"Reserved",                    "sbas_l5.mt31.reserved",      FT_UINT32, BASE_HEX,  NULL, 0x07ff8000,                   NULL, HFILL}},
        {&hf_sbas_l5_mt31_spare_208_214, {"Spare",                       "sbas_l5.mt31.spare_208_214", FT_UINT8,  BASE_HEX,  NULL, 0x7f,                         NULL, HFILL}},
        {&hf_sbas_l5_mt31_iodm,          {"Issue of Data - Mask (IODM)", "sbas_l5.mt31.iodm",          FT_UINT8,  BASE_DEC,  NULL, 0xc0,                         NULL, HFILL}},

        // MT63
        {&hf_sbas_l5_mt63,            {"MT63",       "sbas_l5.mt63",            FT_NONE,  BASE_NONE, NULL, 0x00, NULL, HFILL}},
        {&hf_sbas_l5_mt63_reserved_1, {"Reserved 1", "sbas_l5.mt63.reserved_1", FT_UINT8, BASE_HEX,  NULL, 0x3f, NULL, HFILL}},
        {&hf_sbas_l5_mt63_reserved_2, {"Reserved 2", "sbas_l5.mt63.reserved_2", FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL}},
        {&hf_sbas_l5_mt63_reserved_3, {"Reserved 3", "sbas_l5.mt63.reserved_3", FT_UINT8, BASE_HEX,  NULL, 0xc0, NULL, HFILL}},
    };

    expert_module_t *expert_sbas_l5;

    static ei_register_info ei[] = {
        {&ei_sbas_l5_preamble,          {"sbas_l5.illegal_preamble",          PI_PROTOCOL, PI_WARN, "Illegal preamble", EXPFILL}},
        {&ei_sbas_l5_mt0,               {"sbas_l5.mt0",                       PI_PROTOCOL, PI_WARN, "MT is 0", EXPFILL}},
        {&ei_sbas_l5_crc,               {"sbas_l5.crc",                       PI_CHECKSUM, PI_WARN, "CRC", EXPFILL}},
    };

    static int *ett[] = {
        &ett_sbas_l5,
        &ett_sbas_l5_mt0,
        &ett_sbas_l5_mt31,
        &ett_sbas_l5_mt63,
    };

    proto_sbas_l5 = proto_register_protocol("SBAS L5 Navigation Message", "SBAS L5", "sbas_l5");

    proto_register_field_array(proto_sbas_l5, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_sbas_l5 = expert_register_protocol(proto_sbas_l5);
    expert_register_field_array(expert_sbas_l5, ei, array_length(ei));

    register_dissector("sbas_l5", dissect_sbas_l5, proto_sbas_l5);

    sbas_l5_mt_dissector_table = register_dissector_table("sbas_l5.mt",
            "SBAS L5 MT", proto_sbas_l5, FT_UINT8, BASE_DEC);
}


void proto_reg_handoff_sbas_l5(void) {
    dissector_handle_t sbas_l5_dissector_handle = create_dissector_handle(dissect_sbas_l5, proto_sbas_l5);
    dissector_add_string("ems.svc_flag", EMS_L5_SVC_FLAG, sbas_l5_dissector_handle);

    dissector_add_uint("sbas_l5.mt", 0,  create_dissector_handle(dissect_sbas_l5_mt0,  proto_sbas_l5));
    dissector_add_uint("sbas_l5.mt", 31, create_dissector_handle(dissect_sbas_l5_mt31, proto_sbas_l5));
    dissector_add_uint("sbas_l5.mt", 63, create_dissector_handle(dissect_sbas_l5_mt63, proto_sbas_l5));
}
