/* packet-marker.c
 * Routines for Link Aggregation Marker protocol dissection.
 * IEEE Std 802.1AX
 *
 * Copyright 2002 Steve Housley <steve_housley@3com.com>
 * Copyright 2005 Dominique Bastien <dbastien@accedian.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/slow_protocol_subtypes.h>

/* General declarations */
void proto_register_marker(void);
void proto_reg_handoff_marker(void);

/* MARKER TLVs subtype */
#define MARKERPDU_END_MARKER            0x0
#define MARKERPDU_MARKER_INFO           0x1
#define MARKERPDU_MARKER_RESPONSE       0x2

static const value_string marker_vals[] = {
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

/* Initialise the subtree pointers */

static gint ett_marker = -1;

/*
 * Name: dissect_marker
 *
 * Description:
 *    This function is used to dissect the Link Aggregation Marker Protocol
 *    slow protocols defined in IEEE802.3 clause 43.5 (The PDUs are defined
 *    in section 43.5.3.2). The TLV types are 0x01 for a marker TLV and 0x02
 *    for a marker response. A value of 0x00 indicates an end of message.
 *
 * Input Arguments:
 *    tvb:   buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo: structure associated with the rcv packet (see packet_info.h).
 *    tree:  the protocol tree associated with the rcv packet (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for MARKER and MARKER Response PDUs.
 */
static int
dissect_marker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int     offset = 0;
    guint8  raw_octet;

    proto_tree *marker_tree;
    proto_item *marker_item;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Marker");
    col_set_str(pinfo->cinfo, COL_INFO, "Marker Protocol");

    if (tree)
    {
        marker_item = proto_tree_add_protocol_format(tree, proto_marker, tvb,
                            0, -1, "Marker Protocol");
        marker_tree = proto_item_add_subtree(marker_item, ett_marker);

        /* Version Number */
        proto_tree_add_item(marker_tree, hf_marker_version_number, tvb,
                offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        while (1)
        {
            /* TLV Type */
            raw_octet = tvb_get_guint8(tvb, offset);

            if (raw_octet == MARKERPDU_END_MARKER)
                break;

            proto_tree_add_uint(marker_tree, hf_marker_tlv_type, tvb,
                    offset, 1, raw_octet);
            offset += 1;

            /* TLV Length */
            proto_tree_add_item(marker_tree, hf_marker_tlv_length, tvb,
                    offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            /* Requester Port */
            proto_tree_add_item(marker_tree, hf_marker_req_port, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Requester System */
            proto_tree_add_item(marker_tree, hf_marker_req_system, tvb,
                    offset, 6, ENC_NA);
            offset += 6;

            /* Requester Transaction ID */
            proto_tree_add_item(marker_tree, hf_marker_req_trans_id, tvb,
                    offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Pad to align */
            offset += 2;
        }
    }
    return tvb_captured_length(tvb);
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
    };

    /* Setup protocol subtree array */

    static gint *ett[] = {
        &ett_marker,
    };

    /* Register the protocol name and description */

    proto_marker = proto_register_protocol("Marker", "Link Aggregation Marker Protocol", "marker");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_marker, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_marker(void)
{
    dissector_handle_t marker_handle;

    marker_handle = create_dissector_handle(dissect_marker, proto_marker);
    dissector_add_uint("slow.subtype", MARKER_SUBTYPE, marker_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
