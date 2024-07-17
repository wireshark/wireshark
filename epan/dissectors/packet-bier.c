/* @file
 * Routines for Bit Index Explicit Replication (BIER) dissection
 *
 * Copyright 2024, John Thacker <johnthacker@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RFC 8296: https://www.rfc-editor.org/rfc/rfc8296.html
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_bier(void);
void proto_reg_handoff_bier(void);

static int proto_bier;

static int hf_bier_nibble;
static int hf_bier_ver;
static int hf_bier_bsl;
static int hf_bier_entropy;
static int hf_bier_oam;
static int hf_bier_rsv;
static int hf_bier_dscp;
static int hf_bier_proto;
static int hf_bier_bfir_id;
static int hf_bier_bitstring;

static int ett_bier;

static dissector_table_t bier_subdissector_table;

static dissector_handle_t bier_handle;

static const value_string bier_bsl_vals[] = {
    { 1, "64 bits" },
    { 2, "128 bits" },
    { 3, "256 bits" },
    { 4, "512 bits" },
    { 5, "1024 bits" },
    { 6, "2048 bits" },
    { 7, "4096 bits" },
    { 0, NULL }
};

// https://www.iana.org/assignments/bier/bier.xhtml#bier-next-protocol-identifiers
static const value_string bier_proto_vals[] = {
    { 0, "Reserved" },
    { 1, "MPLS packet with downstream-assigned label at top of stack" },
    { 2, "MPLS packet with upstream-assigned label at top of stack" },
    { 3, "Ethernet frame" },
    { 4, "IPv4 packet" },
    { 5, "OAM packet" },
    { 6, "IPv6 packet" },
    { 7, "Payload is VXLAN encapsulated (no IP/UDP header)" },
    { 8, "Payload is NVGRE encapsulated (no IP header)" },
    { 9, "Payload is GENEVE encapsulated (no IP/UDP header)" },
    { 63, "Reserved" },
    { 0, NULL }
};

static int
dissect_bier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *bier_tree;

    unsigned offset = 0;
    uint32_t proto;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < 16) {
        return 0;
    }

    if (tvb_captured_length(tvb) < 2) {
        return 0;
    }

    /* This nibble is ignored in non-MPLS */
    if (((tvb_get_uint8(tvb, 0) >> 4) & 0xF) != 0x5) {
        return 0;
    }

    uint8_t bsl = (tvb_get_uint8(tvb, 1) >> 4) & 0xF;
    if (bsl == 0 || bsl > 7) {
        return 0;
    }

    int bitstring_length = 1 << (bsl + 2);

    if (tvb_reported_length_remaining(tvb, 8) < bitstring_length) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BIER");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_bier, tvb, offset, 8 + bitstring_length, ENC_NA);

    bier_tree = proto_item_add_subtree(ti, ett_bier);

    proto_tree_add_item(bier_tree, hf_bier_nibble, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(bier_tree, hf_bier_ver, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(bier_tree, hf_bier_bsl, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(bier_tree, hf_bier_entropy, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(bier_tree, hf_bier_oam, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(bier_tree, hf_bier_rsv, tvb, offset, 1, ENC_NA);
    /* DSCP field unused in MPLS; may be as IP DSCP in non-MPLS. */
    proto_tree_add_item(bier_tree, hf_bier_dscp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item_ret_uint(bier_tree, hf_bier_proto, tvb, offset, 1, ENC_NA, &proto);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str_wmem(pinfo->pool, proto, bier_proto_vals, "Unknown (0x%02x)"));
    offset += 1;

    proto_tree_add_item(bier_tree, hf_bier_bfir_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(bier_tree, hf_bier_bitstring, tvb, offset, bitstring_length, ENC_NA);
    offset += bitstring_length;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (!dissector_try_uint(bier_subdissector_table, proto, next_tvb, pinfo, tree)) {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_bier(void)
{
    static hf_register_info hf[] = {
        {
            &hf_bier_nibble,
            {
                "Nibble", "bier.nibble", FT_UINT8,
                BASE_HEX, NULL, 0xF0, NULL, HFILL
            }
        },
        {
            &hf_bier_ver,
            {
                "Version", "bier.ver", FT_UINT8,
                BASE_DEC, NULL, 0x0F, NULL, HFILL
            }
        },
        {
            &hf_bier_bsl,
            {
                "BitString Length", "bier.bsl", FT_UINT8,
                BASE_DEC, VALS(bier_bsl_vals), 0xF0, NULL, HFILL
            }
        },
        {
            &hf_bier_entropy,
            {
                "Entropy", "bier.entropy", FT_UINT24,
                BASE_HEX, NULL, 0x0FFFFF, NULL, HFILL
            }
        },
        {
            &hf_bier_oam,
            {
                "OAM", "bier.oam", FT_UINT8,
                BASE_HEX, NULL, 0xC0, NULL, HFILL
            }
        },
        {
            &hf_bier_rsv,
            {
                "Rsv", "bier.rsv", FT_UINT8,
                BASE_HEX, NULL, 0x30, NULL, HFILL
            }
        },
        {
            &hf_bier_dscp,
            {
                "DSCP", "bier.dscp", FT_UINT16,
                BASE_HEX, NULL, 0x0FC0, NULL, HFILL
            }
        },
        {
            &hf_bier_proto,
            {
                "Next Protocol", "bier.proto", FT_UINT8,
                BASE_HEX, VALS(bier_proto_vals), 0x3F, NULL, HFILL
            }
        },
        {
            &hf_bier_bfir_id,
            {
                "BFIR-id", "bier.bfir-id", FT_UINT16,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_bier_bitstring,
            {
                "BitString", "bier.bitstring", FT_BYTES,
                BASE_NONE, NULL, 0x0, NULL, HFILL
            }
        },
    };

    static int *ett[] = {
        &ett_bier
    };

    proto_bier =
        proto_register_protocol("Bit Index Explicit Replication", "BIER", "bier");

    proto_register_field_array(proto_bier, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    bier_handle = register_dissector_with_description("bier.mpls", "BIER encapsulated in MPLS", dissect_bier, proto_bier);

    bier_subdissector_table = register_dissector_table("bier.proto",
        "BIER Next Protocol", proto_bier, FT_UINT8, BASE_DEC);
}

void
proto_reg_handoff_bier(void)
{
    dissector_handle_t mpls_handle = find_dissector_add_dependency("mpls", proto_bier);

    dissector_add_for_decode_as("mpls.label", bier_handle);

    dissector_add_uint("mpls.pfn", 5, bier_handle);

    dissector_add_uint("bier.proto", 1, mpls_handle);
    dissector_add_uint("bier.proto", 2, mpls_handle);
    dissector_add_uint("bier.proto", 3, find_dissector_add_dependency("eth_maybefcs", proto_bier));
    dissector_add_uint("bier.proto", 4, find_dissector_add_dependency("ip", proto_bier));
    /* 5 is BIER OAM - https://datatracker.ietf.org/doc/draft-ietf-bier-ping/ */
    dissector_add_uint("bier.proto", 6, find_dissector_add_dependency("ipv6", proto_bier));
    dissector_add_uint("bier.proto", 7, find_dissector_add_dependency("vxlan", proto_bier));
    dissector_add_uint("bier.proto", 8, find_dissector_add_dependency("gre", proto_bier));
    dissector_add_uint("bier.proto", 9, find_dissector_add_dependency("geneve", proto_bier));
}
