/* packet-marker.c
 * Routines for Link Aggregation Marker protocol dissection.
 * IEEE Std 802.1AX-2014 Section 6.5
 *
 * Copyright 2002 Steve Housley <steve_housley@3com.com>
 * Copyright 2005 Dominique Bastien <dbastien@accedian.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <epan/slow_protocol_subtypes.h>

/* General declarations */
void proto_register_marker(void);
void proto_reg_handoff_marker(void);

/* MARKER TLVs subtype */
#define MARKER_TERMINATOR               0x0
#define MARKERPDU_MARKER_INFO           0x1
#define MARKERPDU_MARKER_RESPONSE       0x2

static const value_string marker_vals[] = {
    { MARKER_TERMINATOR,         "Marker Terminator" },
    { MARKERPDU_MARKER_INFO,     "Marker Information" },
    { MARKERPDU_MARKER_RESPONSE, "Marker Response Information" },
    { 0, NULL }
};

/* Initialise the protocol and registered fields */
static int proto_marker = -1;

static int hf_marker_version_number = -1;
static int hf_marker_tlv_type = -1;
static int hf_marker_tlv_length = -1;
static int hf_marker_req_port = -1;
static int hf_marker_req_system = -1;
static int hf_marker_req_trans_id = -1;
static int hf_marker_req_pad = -1;
static int hf_marker_reserved = -1;

/* Expert Items */
static expert_field ei_marker_wrong_tlv_type = EI_INIT;
static expert_field ei_marker_wrong_tlv_length = EI_INIT;
static expert_field ei_marker_wrong_pad_value = EI_INIT;

/* Initialise the subtree pointers */
static gint ett_marker = -1;

static int
dissect_marker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int           offset = 0;
    guint         tlv_type, tlv_length;
    guint         port, transactionid, pad;
    const gchar  *sysidstr;

    proto_tree *marker_tree;
    proto_item *marker_item, *tlv_type_item, *tlv_length_item, *pad_item;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Marker");
    col_set_str(pinfo->cinfo, COL_INFO, "Marker Protocol");

    marker_item = proto_tree_add_protocol_format(tree, proto_marker, tvb,
        0, -1, "Marker Protocol");
    marker_tree = proto_item_add_subtree(marker_item, ett_marker);

    proto_tree_add_item(marker_tree, hf_marker_version_number, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    tlv_type_item = proto_tree_add_item_ret_uint(marker_tree, hf_marker_tlv_type, tvb,
        offset, 1, ENC_BIG_ENDIAN, &tlv_type);
    offset += 1;

    tlv_length_item = proto_tree_add_item_ret_uint(marker_tree, hf_marker_tlv_length, tvb,
        offset, 1, ENC_BIG_ENDIAN, &tlv_length);
    offset += 1;

    if (tlv_type == MARKERPDU_MARKER_INFO) {
        col_set_str(pinfo->cinfo, COL_INFO, "Information");
    } else if (tlv_type == MARKERPDU_MARKER_RESPONSE) {
        col_set_str(pinfo->cinfo, COL_INFO, "Response");
    } else {
        expert_add_info(pinfo, tlv_type_item, &ei_marker_wrong_tlv_type);
    }
    if (tlv_length != 16) {
        expert_add_info(pinfo, tlv_length_item, &ei_marker_wrong_tlv_length);
    }
    proto_tree_add_item_ret_uint(marker_tree, hf_marker_req_port, tvb,
        offset, 2, ENC_BIG_ENDIAN, &port);
    offset += 2;

    proto_tree_add_item(marker_tree, hf_marker_req_system, tvb,
        offset, 6, ENC_NA);
    sysidstr = tvb_ether_to_str(tvb, offset);
    offset += 6;

    proto_tree_add_item_ret_uint(marker_tree, hf_marker_req_trans_id, tvb,
        offset, 4, ENC_BIG_ENDIAN, &transactionid);
    offset += 4;

    col_append_fstr(pinfo->cinfo, COL_INFO, " SysId=%s, P=%d, TId=%d",
        sysidstr, port, transactionid);

    pad_item = proto_tree_add_item_ret_uint(marker_tree, hf_marker_req_pad, tvb,
        offset, 2, ENC_BIG_ENDIAN, &pad);
    if (pad != 0) {
        expert_add_info(pinfo, pad_item, &ei_marker_wrong_pad_value);
    }
    offset += 2;

    proto_tree_add_item_ret_uint(marker_tree, hf_marker_tlv_type, tvb,
        offset, 1, ENC_BIG_ENDIAN, &tlv_type);
    offset += 1;

    proto_tree_add_item_ret_uint(marker_tree, hf_marker_tlv_length, tvb,
        offset, 1, ENC_BIG_ENDIAN, &tlv_length);
    offset += 1;

    if (tlv_type == MARKER_TERMINATOR) {
        if (tlv_length != 0) {
            expert_add_info(pinfo, tlv_type_item, &ei_marker_wrong_tlv_length);
        }
    } else {
        expert_add_info(pinfo, tlv_type_item, &ei_marker_wrong_tlv_type);
    }

    proto_tree_add_item(marker_tree, hf_marker_reserved, tvb,
        offset, 90, ENC_NA);
    offset += 90;
    return offset;
}

/* Register the protocol with Wireshark */
void
proto_register_marker(void)
{
/* Setup list of header fields */

    static hf_register_info hf[] = {
        { &hf_marker_version_number,
          { "Version Number",    "marker.version",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "Marker protocol version", HFILL }},

        { &hf_marker_tlv_type,
          { "TLV Type",    "marker.tlvType",
            FT_UINT8,    BASE_HEX,    VALS(marker_vals),    0x0,
            NULL, HFILL }},

        { &hf_marker_tlv_length,
          { "TLV Length",            "marker.tlvLen",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "Length of the Actor TLV", HFILL }},

        { &hf_marker_req_port,
          { "Requester Port",  "marker.requesterPort",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_marker_req_system,
          { "Requester System",  "marker.requesterSystem",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            "Requester System ID encoded as a MAC address", HFILL }},

        { &hf_marker_req_trans_id,
          { "Requester Transaction ID",  "marker.requesterTransId",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_marker_req_pad,
          { "Requester Pad",  "marker.requesterPad",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_marker_reserved,
          { "Reserved",  "marker.reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},
    };

    /* Setup protocol subtree array */

    static gint *ett[] = {
        &ett_marker,
    };

    static ei_register_info ei[] = {
    { &ei_marker_wrong_tlv_type,   { "marker.wrong_tlv_type",   PI_MALFORMED, PI_ERROR, "TLV is not expected type",   EXPFILL }},
    { &ei_marker_wrong_tlv_length, { "marker.wrong_tlv_length", PI_MALFORMED, PI_ERROR, "TLV is not expected length", EXPFILL }},
    { &ei_marker_wrong_pad_value,  { "marker.wrong_pad_value",  PI_PROTOCOL,  PI_WARN,  "pad value is not 0",         EXPFILL }},
    };

    expert_module_t* expert_marker;



    /* Register the protocol name and description */

    proto_marker = proto_register_protocol("Marker", "Link Aggregation Marker Protocol", "marker");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_marker, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_marker = expert_register_protocol(proto_marker);
    expert_register_field_array(expert_marker, ei, array_length(ei));

}

void
proto_reg_handoff_marker(void)
{
    dissector_handle_t marker_handle;

    marker_handle = create_dissector_handle(dissect_marker, proto_marker);
    dissector_add_uint("slow.subtype", MARKER_SUBTYPE, marker_handle);
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
