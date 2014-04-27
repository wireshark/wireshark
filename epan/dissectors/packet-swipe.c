/* packet-swipe.c
 * swIPe IP Security Protocol
 *
 * http://www.crypto.com/papers/swipe.id.txt
 *
 * Copyright 2014 by Michael Mann
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
#include <epan/ipproto.h>

void proto_register_swipe(void);
void proto_reg_handoff_swipe(void);

/* Routing Header Types */
static const value_string swipe_packet_type_vals[] = {
    { 0, "Plain encapsulation" },
    { 1, "Packet is authenticated but not encrypted" },
    { 2, "Packet is encrypted" },
    { 3, "Packet is both authenticated and encrypted" },
    { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_swipe             = -1;

static int hf_swipe_packet_type    = -1;
static int hf_swipe_len            = -1;
static int hf_swipe_policy_id      = -1;
static int hf_swipe_packet_seq     = -1;
static int hf_swipe_authenticator  = -1;

/* Initialize the subtree pointers */
static gint ett_swipe              = -1;

static dissector_handle_t ipv6_handle;

static int
dissect_swipe(tvbuff_t *tvb, packet_info * pinfo, proto_tree *tree, void* data _U_)
{
    int             header_len, offset = 0;
    proto_tree      *swipe_tree;
    proto_item      *ti;
    tvbuff_t        *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "swIPe");
    col_clear(pinfo->cinfo, COL_INFO);

    header_len = tvb_get_guint8(tvb, offset + 1);
    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_swipe, tvb, offset, header_len, ENC_NA);
        swipe_tree = proto_item_add_subtree(ti, ett_swipe);

        /* Packet Type */
        proto_tree_add_item(swipe_tree, hf_swipe_packet_type, tvb, offset, 1, ENC_NA);

        /* Header Length */
        proto_tree_add_item(swipe_tree, hf_swipe_len, tvb, offset + 1, 1, ENC_NA);

        /* Policy ID */
        proto_tree_add_item(swipe_tree, hf_swipe_policy_id, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

        /* Packet Sequence Number */
        proto_tree_add_item(swipe_tree, hf_swipe_packet_seq, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

        if (header_len > 8)
            proto_tree_add_item(swipe_tree, hf_swipe_authenticator, tvb, offset + 8, header_len - 8, ENC_NA);
    }

    next_tvb = tvb_new_subset_remaining(tvb, header_len);
    call_dissector(ipv6_handle, next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_swipe(void)
{

    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_swipe_packet_type,      { "Packet type",      "swipe.packet_type",      FT_UINT8, BASE_DEC, VALS(swipe_packet_type_vals), 0x0, NULL, HFILL } },
        { &hf_swipe_len,     { "Header Length",     "swipe.len",     FT_UINT8,  BASE_DEC, NULL,                      0x0, NULL, HFILL } },
        { &hf_swipe_policy_id,    { "Policy identifier",    "swipe.policy_id",    FT_UINT16, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
        { &hf_swipe_packet_seq,     { "Packet sequence number",     "swipe.packet_seq",     FT_UINT32, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
        { &hf_swipe_authenticator,   { "Authenticator",   "swipe.authenticator",   FT_BYTES, BASE_NONE, NULL,                      0x0, NULL, HFILL } },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_swipe
    };

    /* Register the protocol name and description */
    proto_swipe = proto_register_protocol("swIPe IP Security Protocol", "swIPe", "swipe");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_swipe, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_swipe(void)
{
    dissector_handle_t swipe_handle;

    swipe_handle = new_create_dissector_handle(dissect_swipe, proto_swipe );
    dissector_add_uint("ip.proto", IP_PROTO_SWIPE, swipe_handle);

    ipv6_handle = find_dissector("ipv6");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
