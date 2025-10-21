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
#include <errno.h>
#include <glib.h>
#include <proto.h>
#include <strutil.h>
#include <tvbuff.h>
#include <wiretap/wtap.h>

#include "packet-sbas_l1.h"

/*
 * Dissects EMS files with format as defined by the
 * "Multi-Band EGNOS File Format Description Document" (ESA-EGN-EPO-ICD-0031, Issue 1.4)
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
static int hf_ems_svc_flag;
static int hf_ems_nof_bits;
static int hf_ems_nof;
static int hf_ems_mt;

static dissector_table_t ems_msg_dissector_table;

static int ett_ems;

static dissector_handle_t  ems_handle;

/* Dissect EMS data record */
static int dissect_ems(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    GByteArray *bytes = g_byte_array_new();

    const uint8_t *nof_bits_hex_str;
    int nof_bits_hex_str_len;
    int nof_bits;
    int nof_hex_chars_len;

    const char *svc_flag;

    tvbuff_t *next_tvb = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EMS");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_tree *ems_tree = proto_tree_add_subtree_format(tree, tvb, 0, 40, ett_ems, NULL, "EMS");

    proto_tree_add_item(ems_tree, hf_ems_prn,    tvb,  0, 3, ENC_ASCII);
    proto_tree_add_item(ems_tree, hf_ems_year,   tvb,  4, 2, ENC_ASCII);
    proto_tree_add_item(ems_tree, hf_ems_month,  tvb,  7, 2, ENC_ASCII);
    proto_tree_add_item(ems_tree, hf_ems_day,    tvb, 10, 2, ENC_ASCII);
    proto_tree_add_item(ems_tree, hf_ems_hour,   tvb, 13, 2, ENC_ASCII);
    proto_tree_add_item(ems_tree, hf_ems_minute, tvb, 16, 2, ENC_ASCII);

    gboolean is_l1 = tvb_get_uint8(tvb, 21) == ' ';
    if (is_l1) {

        svc_flag = EMS_L1_SVC_FLAG;

        // L1 message are always encoded as 64 hex chars
        nof_hex_chars_len = 64;

        proto_tree_add_item(ems_tree, hf_ems_second, tvb, 19, 2, ENC_ASCII);

        // Single digit MT?
        if (tvb_get_uint8(tvb, 23) == ' ') {
            proto_tree_add_item(ems_tree, hf_ems_mt, tvb, 22, 1, ENC_ASCII);
            proto_tree_add_bytes_item(ems_tree, hf_ems_nof, tvb, 24, nof_hex_chars_len, ENC_ASCII | ENC_STR_HEX | ENC_SEP_NONE, bytes, NULL, NULL);
        }
        else {
            proto_tree_add_item(ems_tree, hf_ems_mt, tvb, 22, 2, ENC_ASCII);
            proto_tree_add_bytes_item(ems_tree, hf_ems_nof, tvb, 25, nof_hex_chars_len, ENC_ASCII | ENC_STR_HEX | ENC_SEP_NONE, bytes, NULL, NULL);
        }
    }
    else { // L5 or non-standard message encoding
        proto_tree_add_item(ems_tree, hf_ems_second, tvb, 19, 9, ENC_ASCII);
        proto_tree_add_item_ret_string(ems_tree, hf_ems_svc_flag, tvb, 29, 2, ENC_ASCII, pinfo->pool, (const uint8_t **) &svc_flag);
        proto_tree_add_item_ret_string_and_length(ems_tree, hf_ems_nof_bits, tvb, 32, 4, ENC_ASCII, pinfo->pool, &nof_bits_hex_str, &nof_bits_hex_str_len);
        proto_tree_add_item(ems_tree, hf_ems_mt, tvb, 37, 2, ENC_ASCII);

        // dissect NOF with a number of bits given by NOF bits
        if (nof_bits_hex_str && nof_bits_hex_str_len > 0) {
            errno = 0;
            nof_bits = (int) strtol(nof_bits_hex_str, NULL, 16);

            if (!errno) {
                nof_hex_chars_len = 2 * ((nof_bits / 8) + ((nof_bits % 8) ? 1 : 0));
                proto_tree_add_bytes_item(ems_tree, hf_ems_nof, tvb, 40, nof_hex_chars_len, ENC_ASCII | ENC_STR_HEX | ENC_SEP_NONE, bytes, NULL, NULL);
            }
        }
    }

    next_tvb = tvb_new_child_real_data(tvb, (uint8_t *)wmem_memdup(pinfo->pool, bytes->data, bytes->len), bytes->len, bytes->len);
    add_new_data_source(pinfo, next_tvb, "SBAS message");

    if (!dissector_try_string_with_data(ems_msg_dissector_table, svc_flag, next_tvb, pinfo, tree, true, NULL)) {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    g_byte_array_free(bytes, true);

    return tvb_captured_length(tvb);
}

void proto_register_ems(void) {

    static hf_register_info hf[] = {
        {&hf_ems_prn,      {"PRN",             "ems.prn",      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_year,     {"Year",            "ems.year",     FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_month,    {"Month",           "ems.month",    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_day,      {"Day",             "ems.day",      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_hour,     {"Hour",            "ems.hour",     FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_minute,   {"Minute",          "ems.minute",   FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_second,   {"Second",          "ems.second",   FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_svc_flag, {"Service Flag",    "ems.svc_flag", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_nof_bits, {"NOF Bits Number", "ems.nof_bits", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_mt,       {"Message Type",    "ems.mt",       FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ems_nof,      {"NOF",             "ems.nof",      FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_ems,
    };

    proto_ems = proto_register_protocol("EGNOS Message Server file", "EMS", "ems");
    ems_handle = register_dissector("ems", dissect_ems, proto_ems);

    proto_register_field_array(proto_ems, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ems_msg_dissector_table = register_dissector_table("ems.svc_flag", "EMS Service Flag", proto_ems, FT_STRING, STRING_CASE_SENSITIVE);
}

void proto_reg_handoff_ems(void) {
    static bool initialized = false;

    if (!initialized) {
        dissector_add_uint("wtap_encap", WTAP_ENCAP_EMS, ems_handle);
    }
}
