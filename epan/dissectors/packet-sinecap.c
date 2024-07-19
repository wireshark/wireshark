/* packet-sinecap.c
 *
 * Author:      Nikolas Koesling, 2023 (nikolas@koesling.info)
 * Description: Wireshark dissector for the SINEC AP protocol according to
 *      https://cache.industry.siemens.com/dl/files/274/22090274/att_83836/v1/447_840_840C_880_Computer_Link_General_Description.pdf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>

#define PROTO_TAG_AP "SINEC-AP"

/* Min. telegram length for heuristic check */
#define TXP_MIN_TELEGRAM_LENGTH 22

/* Wireshark ID of the AP1 protocol */
static int proto_ap;

static int hf_ap_protoid;
static int hf_ap_mpxadr;
static int hf_ap_comcls;
static int hf_ap_comcod;
static int hf_ap_modfr1;
static int hf_ap_modfr2;
static int hf_ap_errcls;
static int hf_ap_errcod;
static int hf_ap_rosctr;
static int hf_ap_sgsqnr;
static int hf_ap_tactid;
static int hf_ap_tasqnr;
static int hf_ap_spare;
static int hf_ap_pduref;
static int hf_ap_pduid;
static int hf_ap_pdulg;
static int hf_ap_parlg;
static int hf_ap_datlg;

static int ett_ap;

static heur_dissector_list_t ap_heur_subdissector_list;

static const value_string vs_comcls[] = {
        {0x0, "ACK without data"},
        {0x4, "Serial transfer"},
        {0, NULL}
};

static const value_string vs_protid[] = {
        {0x0, "SINEC AP 1.0"},
        {0, NULL}
};

static bool
dissect_ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    /*----------------- Heuristic Checks - Begin */
    /* 1) check for minimum length */
    if (tvb_captured_length(tvb) < TXP_MIN_TELEGRAM_LENGTH)
        return false;

    /* 2) protocol id == 0 */
    if (tvb_get_uint8(tvb, 0) != 0)
        return false;
    /*----------------- Heuristic Checks - End */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_AP);
    col_clear(pinfo->cinfo, COL_INFO);

    uint8_t comcls = tvb_get_uint8(tvb, 2);

    int offset = 16;
    uint16_t pdulg = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;

    uint16_t datlg = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    offset += 2;

    ws_assert(offset == 22);

    /* check pdu and data length */
    if (pdulg != tvb_captured_length(tvb))
        return false;
    if (datlg != tvb_captured_length(tvb) - 22)
        return false;

    switch (comcls) {
        case 0x0: {
            // ack without data
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "ACK without data");
            break;
        }
        case 0x4: {
            // serial transfer
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Serial transfer");
            break;
        }
        default:
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "UNKNOWN command class");
    }

    proto_item *ap_item = proto_tree_add_item(tree, proto_ap, tvb, 0, -1, ENC_NA);
    proto_tree *ap_tree = proto_item_add_subtree(ap_item, ett_ap);

    offset = 0;
    proto_tree_add_item(ap_tree, hf_ap_protoid, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ap_tree, hf_ap_mpxadr, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ap_tree, hf_ap_comcls, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ap_tree, hf_ap_comcod, tvb, offset++, 1, ENC_BIG_ENDIAN);

    switch (comcls) {
        case 0x0: {
            // ack without data
            proto_tree_add_item(ap_tree, hf_ap_errcls, tvb, offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ap_tree, hf_ap_errcod, tvb, offset++, 1, ENC_BIG_ENDIAN);
            break;
        }
        case 0x4: {
            // serial transfer
            proto_tree_add_item(ap_tree, hf_ap_modfr1, tvb, offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ap_tree, hf_ap_modfr2, tvb, offset++, 1, ENC_BIG_ENDIAN);
            break;
        }
        default:
            proto_tree_add_item(ap_tree, hf_ap_modfr1, tvb, offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ap_tree, hf_ap_modfr2, tvb, offset++, 1, ENC_BIG_ENDIAN);
    }

    proto_tree_add_item(ap_tree, hf_ap_rosctr, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ap_tree, hf_ap_sgsqnr, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ap_tree, hf_ap_tactid, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ap_tree, hf_ap_tasqnr, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ap_tree, hf_ap_spare, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ap_tree, hf_ap_pduref, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ap_tree, hf_ap_pduid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ap_tree, hf_ap_pdulg, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ap_tree, hf_ap_parlg, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ap_tree, hf_ap_datlg, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    ws_assert(offset == 22);

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        struct tvbuff *next_tvb = tvb_new_subset_remaining(tvb,  offset);
        heur_dtbl_entry_t *hdtbl_entry;
        if (!dissector_try_heuristic(ap_heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }

    return true;
}

void
proto_register_ap(void)
{
    static hf_register_info hf[] = {
            {&hf_ap_protoid, {"PROTID", "sinecap.protid", FT_UINT8, BASE_HEX, VALS(vs_protid), 0x0, "Protocol version", HFILL}},
            {&hf_ap_mpxadr, {"MPXADR", "sinecap.mpxadr", FT_UINT8, BASE_HEX, NULL, 0x0, "Multiplex address", HFILL}},
            {&hf_ap_comcls, {"COMCLS", "sinecap.comcls", FT_UINT8, BASE_HEX, VALS(vs_comcls), 0x0, "Command class", HFILL}},
            {&hf_ap_comcod, {"COMCOD", "sinecap.comcod", FT_UINT8, BASE_HEX, NULL, 0x0, "Command code", HFILL}},
            {&hf_ap_modfr1, {"MODFR1", "sinecap.modfr1", FT_UINT8, BASE_HEX, NULL, 0x0, "Modifier 1", HFILL}},
            {&hf_ap_errcls, {"ERRCLS", "sinecap.errcls", FT_UINT8, BASE_HEX, NULL, 0x0, "Error class", HFILL}},
            {&hf_ap_modfr2, {"MODFR2", "sinecap.modfr2", FT_UINT8, BASE_HEX, NULL, 0x0, "Modifier 2", HFILL}},
            {&hf_ap_errcod, {"ERRCOD", "sinecap.errcod", FT_UINT8, BASE_HEX, NULL, 0x0, "Error code", HFILL}},
            {&hf_ap_rosctr, {"ROSCTR", "sinecap.rosctr", FT_UINT8, BASE_HEX, NULL, 0x0, "Remote operating service", HFILL}},
            {&hf_ap_sgsqnr, {"SGSQNR", "sinecap.sgsqnr", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "Segment sequence number", HFILL}},
            {&hf_ap_tactid, {"TACTID", "sinecap.tactid", FT_UINT8, BASE_HEX, NULL, 0x0, "Transaction identifier", HFILL}},
            {&hf_ap_tasqnr, {"TASQNR", "sinecap.tasqnr", FT_UINT8, BASE_HEX, NULL, 0x0, "Transaction sequence number", HFILL}},
            {&hf_ap_spare, {"SPARE", "sinecap.spare", FT_UINT16, BASE_HEX, NULL, 0x0, "Free space", HFILL}},
            {&hf_ap_pduref, {"PDUREF", "sinecap.pduref", FT_UINT16, BASE_HEX, NULL, 0x0, "Protocol Data Unit reference", HFILL}},
            {&hf_ap_pduid, {"PDUID", "sinecap.pduid", FT_UINT16, BASE_HEX, NULL, 0x0, "Protocol Data Unit identifier", HFILL}},
            {&hf_ap_pdulg, {"PDULG", "sinecap.pdulg", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "Protocol Data Unit length", HFILL}},
            {&hf_ap_parlg, {"PARLG", "sinecap.parlg", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "Parameter length", HFILL}},
            {&hf_ap_datlg, {"DATLG", "sinecap.datlg", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "Data length", HFILL}},
    };

    proto_ap = proto_register_protocol (
            "SINEC AP Telegram",    /* name        */
            "SINEC AP",             /* short name  */
            "sinecap"               /* filter_name */
    );

    static int *ett[] = {
            &ett_ap,
    };

    proto_register_field_array(proto_ap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length (ett));
    ap_heur_subdissector_list = register_heur_dissector_list_with_description("sinecap", "SINEC AP data", proto_ap);
}

void
proto_reg_handoff_ap(void)
{
    heur_dissector_add("cotp", dissect_ap, "SINEC AP Telegram over COTP", "sinecap", proto_ap, HEURISTIC_ENABLE);
    heur_dissector_add("cotp_is", dissect_ap, "SINEC AP Telegram over COTP", "sinecap_is", proto_ap, HEURISTIC_ENABLE);
}
