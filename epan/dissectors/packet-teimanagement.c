/* packet-teimanagement.c
 * Routines for LAPD TEI Management frame disassembly
 * Rolf Fiedler <rolf.fiedler@innoventif.com>
 * based on code by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/lapd_sapi.h>

/* ISDN/LAPD references:
 *
 * http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/isdn.htm
 * http://www.ece.wpi.edu/courses/ee535/hwk11cd95/agrebe/agrebe.html
 * http://www.acacia-net.com/Clarinet/Protocol/q9213o84.htm
 */

void proto_reg_handoff_teimanagement(void);
void proto_register_teimanagement(void);

static dissector_handle_t teimanagement_handle;

static int proto_tei;

static int hf_tei_management_entity_id;
static int hf_tei_management_reference;
static int hf_tei_management_message;
static int hf_tei_management_action;
static int hf_tei_management_extend;

static int ett_tei_management_subtree;

#define TEI_ID_REQUEST    0x01
#define TEI_ID_ASSIGNED   0x02
#define TEI_ID_DENIED     0x03
#define TEI_ID_CHECK_REQ  0x04
#define TEI_ID_CHECK_RESP 0x05
#define TEI_ID_REMOVE     0x06
#define TEI_ID_VERIFY     0x07

static const value_string tei_msg_vals[]={
    { TEI_ID_REQUEST,    "Identity Request"},
    { TEI_ID_ASSIGNED,   "Identity Assigned"},
    { TEI_ID_DENIED,     "Identity Denied"},
    { TEI_ID_CHECK_REQ,  "Identity Check Request"},
    { TEI_ID_CHECK_RESP, "Identity Check Response"},
    { TEI_ID_REMOVE,     "Identity Remove"},
    { TEI_ID_VERIFY,     "Identity Verify"},
    { 0, NULL}
};

static int
dissect_teimanagement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *tei_tree = NULL;
    proto_item *tei_ti;
    uint8_t message;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TEI");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        tei_ti = proto_tree_add_item(tree, proto_tei, tvb, 0, 5, ENC_NA);
        tei_tree = proto_item_add_subtree(tei_ti, ett_tei_management_subtree);

        proto_tree_add_item(tei_tree, hf_tei_management_entity_id, tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tei_tree, hf_tei_management_reference,  tvb, 1, 2, ENC_BIG_ENDIAN);
    }

    message = tvb_get_uint8(tvb, 3);
        col_add_str(pinfo->cinfo, COL_INFO,
            val_to_str(message, tei_msg_vals, "Unknown message type (0x%04x)"));
    if (tree) {
        proto_tree_add_uint(tei_tree, hf_tei_management_message, tvb, 3, 1, message);
        proto_tree_add_item(tei_tree, hf_tei_management_action, tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tei_tree, hf_tei_management_extend, tvb, 4, 1, ENC_BIG_ENDIAN);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_teimanagement(void)
{
    static int *subtree[]={
        &ett_tei_management_subtree
    };

    static hf_register_info hf[] = {
        { &hf_tei_management_entity_id,
          { "Entity", "tei_management.entity", FT_UINT8, BASE_HEX, NULL, 0x0,
                "Layer Management Entity Identifier", HFILL }},

        { &hf_tei_management_reference,
          { "Reference", "tei_management.reference", FT_UINT16, BASE_DEC, NULL, 0x0,
                "Reference Number", HFILL }},

        { &hf_tei_management_message,
          { "Msg", "tei_management.msg", FT_UINT8, BASE_DEC, VALS(tei_msg_vals), 0x0,
                "Message Type", HFILL }},

        { &hf_tei_management_action,
          { "Action", "tei_management.action", FT_UINT8, BASE_DEC, NULL, 0xfe,
                "Action Indicator", HFILL }},

        { &hf_tei_management_extend,
          { "Extend", "tei_management.extend", FT_UINT8, BASE_DEC, NULL, 0x01,
                "Extension Indicator", HFILL }}
    };

    proto_tei = proto_register_protocol("TEI Management Procedure, Channel D (LAPD)",
                                         "TEI_MANAGEMENT", "tei_management");
    proto_register_field_array (proto_tei, hf, array_length(hf));
    proto_register_subtree_array(subtree, array_length(subtree));

    teimanagement_handle = register_dissector("tei_management", dissect_teimanagement, proto_tei);
}

void
proto_reg_handoff_teimanagement(void)
{
    dissector_add_uint("lapd.sapi", LAPD_SAPI_L2, teimanagement_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
