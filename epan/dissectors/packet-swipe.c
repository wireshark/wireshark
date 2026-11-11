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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/iana-info.h>

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
static int proto_swipe;

static int hf_swipe_packet_type;
static int hf_swipe_len;
static int hf_swipe_policy_id;
static int hf_swipe_packet_seq;
static int hf_swipe_authenticator;

/* Initialize the subtree pointers */
static int ett_swipe;

static expert_field ei_swipe_nested_too_deeply;

#define SWIPE_MAX_NESTING 4

static dissector_handle_t swipe_handle;
static dissector_handle_t ipv6_handle;

static int
dissect_swipe(tvbuff_t *tvb, packet_info * pinfo, proto_tree *tree, void* data _U_)
{
    int             header_len, offset = 0;
    proto_tree      *swipe_tree;
    proto_item      *ti;
    tvbuff_t        *next_tvb;
    unsigned        nesting;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "swIPe");
    col_clear(pinfo->cinfo, COL_INFO);

    header_len = tvb_get_uint8(tvb, offset + 1);
    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_swipe, tvb, offset, header_len, ENC_NA);
        swipe_tree = proto_item_add_subtree(ti, ett_swipe);

        /* Packet Type */
        proto_tree_add_item(swipe_tree, hf_swipe_packet_type, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Header Length */
        proto_tree_add_item(swipe_tree, hf_swipe_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

        /* Policy ID */
        proto_tree_add_item(swipe_tree, hf_swipe_policy_id, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

        /* Packet Sequence Number */
        proto_tree_add_item(swipe_tree, hf_swipe_packet_seq, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

        if (header_len > 8)
            proto_tree_add_item(swipe_tree, hf_swipe_authenticator, tvb, offset + 8, header_len - 8, ENC_NA);
    }

    next_tvb = tvb_new_subset_remaining(tvb, header_len);
    nesting = p_get_proto_depth(pinfo, proto_swipe);
    if (nesting >= SWIPE_MAX_NESTING) {
        proto_tree_add_expert_remaining(tree, pinfo, &ei_swipe_nested_too_deeply, tvb, header_len);
        return tvb_captured_length(tvb);
    }
    p_set_proto_depth(pinfo, proto_swipe, nesting + 1);
    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    p_set_proto_depth(pinfo, proto_swipe, nesting);

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
    static int *ett[] = {
        &ett_swipe
    };

    static ei_register_info ei[] = {
        { &ei_swipe_nested_too_deeply, { "swipe.nested_too_deeply", PI_PROTOCOL, PI_WARN, "swIPe nested too deeply", EXPFILL }},
    };
    expert_module_t *expert_swipe;

    /* Register the protocol name and description */
    proto_swipe = proto_register_protocol("swIPe IP Security Protocol", "swIPe", "swipe");

    /* Register the dissector handle */
    swipe_handle = register_dissector("swipe", dissect_swipe, proto_swipe);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_swipe, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_swipe = expert_register_protocol(proto_swipe);
    expert_register_field_array(expert_swipe, ei, array_length(ei));
}

void
proto_reg_handoff_swipe(void)
{
    dissector_add_uint("ip.proto", IP_PROTO_SWIPE_DEPRECATED, swipe_handle);

    ipv6_handle = find_dissector_add_dependency("ipv6", proto_swipe );
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
