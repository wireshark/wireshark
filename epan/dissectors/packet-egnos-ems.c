/* packet-ems.c
 * EGNOS Message Server file format dissection.
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
#include <wiretap/wtap.h>

/*
 * Dissects PCAPs mapped from the EMS file format as defined by the "EGNOS
 * Messager Server User Interface Document" (E-RD-SYS-E31-011-ESA, Issue 2)
 */

/* Initialize the protocol and registered fields */
static int proto_ems;

static int hf_ems_prn;
static int hf_ems_year;
static int hf_ems_month;
static int hf_ems_day;
static int hf_ems_hour;
static int hf_ems_minute;
static int hf_ems_second;
static int hf_ems_mt;

static int ett_ems;

static dissector_handle_t  ems_handle;

/* Dissect EMS data record */
static int dissect_ems(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tvbuff_t *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EMS");
    col_clear(pinfo->cinfo, COL_INFO);

    uint8_t prn, year, month, day, hour, minute, second, mt;
    prn    = tvb_get_uint8(tvb, 0);
    year   = tvb_get_uint8(tvb, 1);
    month  = tvb_get_uint8(tvb, 2);
    day    = tvb_get_uint8(tvb, 3);
    hour   = tvb_get_uint8(tvb, 4);
    minute = tvb_get_uint8(tvb, 5);
    second = tvb_get_uint8(tvb, 6);
    mt     = tvb_get_uint8(tvb, 7);

    proto_tree *ems_tree = proto_tree_add_subtree_format(tree, tvb, 0, 40,
            ett_ems, NULL, "EMS (%04d-%02d-%02d %02d:%02d:%02d PRN%d MT%d)",
            2000 + year, month, day, hour, minute, second, prn, mt);

    proto_tree_add_item(ems_tree, hf_ems_prn,    tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ems_tree, hf_ems_year,   tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ems_tree, hf_ems_month,  tvb, 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ems_tree, hf_ems_day,    tvb, 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ems_tree, hf_ems_hour,   tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ems_tree, hf_ems_minute, tvb, 5, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ems_tree, hf_ems_second, tvb, 6, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ems_tree, hf_ems_mt,     tvb, 7, 1, ENC_BIG_ENDIAN);

    next_tvb = tvb_new_subset_remaining(tvb, 8);

    dissector_handle_t sbas_l1_dissector_handle = find_dissector("sbas_l1");
    if (sbas_l1_dissector_handle) {
        call_dissector(sbas_l1_dissector_handle, next_tvb, pinfo, tree);
    }
    else {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

void proto_register_ems(void) {

    static hf_register_info hf[] = {
        {&hf_ems_prn,    {"PRN",          "ems.prn",    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_year,   {"Year",         "ems.year",   FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_month,  {"Month",        "ems.month",  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_day,    {"Day",          "ems.day",    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_hour,   {"Hour",         "ems.hour",   FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_minute, {"Minute",       "ems.minute", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_second, {"Second",       "ems.second", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_mt,     {"Message Type", "ems.mt",     FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_ems,
    };

    proto_ems = proto_register_protocol("EGNOS Message Server file", "EMS", "ems");
    ems_handle = register_dissector("ems", dissect_ems, proto_ems);

    proto_register_field_array(proto_ems, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_ems(void) {
    static bool initialized = false;

    if (!initialized) {
        dissector_add_uint("wtap_encap", WTAP_ENCAP_EMS, ems_handle);
    }
}
