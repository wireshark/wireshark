/* packet-carp.c
 * Routines for the Common Address Redundancy Protocol (CARP)
 * Copyright 2013, Uli Heilmeier <uh@heilmeier.eu>
 * Based on packet-vrrp.c by Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/expert.h>
#include <epan/in_cksum.h>

void proto_register_carp(void);
void proto_reg_handoff_carp(void);

static dissector_handle_t carp_handle;

static int proto_carp;
static int ett_carp;
static int ett_carp_ver_type;

static int hf_carp_ver_type;
static int hf_carp_version;
static int hf_carp_type;
static int hf_carp_vhid;
static int hf_carp_advskew;
static int hf_carp_authlen;
static int hf_carp_demotion;
static int hf_carp_advbase;
static int hf_carp_counter;
static int hf_carp_hmac;
static int hf_carp_checksum;
static int hf_carp_checksum_status;

static expert_field ei_carp_checksum;

#define CARP_VERSION_MASK 0xf0
#define CARP_TYPE_MASK 0x0f

#define CARP_TYPE_ADVERTISEMENT 1
static const value_string carp_type_vals[] = {
    {CARP_TYPE_ADVERTISEMENT, "Advertisement"},
    {0, NULL}
};

static bool
test_carp_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    uint8_t ver_type, version, auth_length;

    /* First some simple check if the data is
       really CARP */
    if (tvb_captured_length(tvb) < 36)
        return false;

    /* Version must be 1 or 2, type must be in carp_type_vals */
    ver_type = tvb_get_uint8(tvb, 0);
    version = hi_nibble(ver_type);
    if ((version == 0) || (version > 2) ||
        (try_val_to_str(lo_nibble(ver_type), carp_type_vals) == NULL))
        return false;

    auth_length = tvb_get_uint8(tvb, 3);
    if ( auth_length != 7 )
        return false;

    return true;
}

static int
dissect_carp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset = 0;
    unsigned carp_len;
    uint8_t vhid;
    vec_t cksum_vec[4];
    proto_item *ti, *tv;
    proto_tree *carp_tree, *ver_type_tree;
    uint8_t ver_type;

    /* Make sure it's a CARP packet */
    if (!test_carp_packet(tvb, pinfo, tree, data))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CARP");
    col_clear(pinfo->cinfo, COL_INFO);

    vhid = tvb_get_uint8(tvb, 1);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s (Virtual Host ID: %u)",
                 "Announcement", vhid);

    ti = proto_tree_add_item(tree, proto_carp, tvb, 0, -1, ENC_NA);
    carp_tree = proto_item_add_subtree(ti, ett_carp);

    ver_type = tvb_get_uint8(tvb, 0);
    tv = proto_tree_add_uint_format(carp_tree, hf_carp_ver_type,
                    tvb, offset, 1, ver_type,
                    "Version %u, Packet type %u (%s)",
                    hi_nibble(ver_type), lo_nibble(ver_type),
                    val_to_str_const(lo_nibble(ver_type), carp_type_vals, "Unknown"));
    ver_type_tree = proto_item_add_subtree(tv, ett_carp_ver_type);
    proto_tree_add_uint(ver_type_tree, hf_carp_version, tvb, offset, 1, ver_type);
    proto_tree_add_uint(ver_type_tree, hf_carp_type, tvb, offset, 1, ver_type);
    offset++;

    proto_tree_add_item(carp_tree, hf_carp_vhid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(carp_tree, hf_carp_advskew, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(carp_tree, hf_carp_authlen, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(carp_tree, hf_carp_demotion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(carp_tree, hf_carp_advbase, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    carp_len = tvb_reported_length(tvb);
    if (!pinfo->fragmented && tvb_captured_length(tvb) >= carp_len) {
        /* The packet isn't part of a fragmented datagram
           and isn't truncated, so we can checksum it. */
        SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, 0, carp_len);
        proto_tree_add_checksum(carp_tree, tvb, offset, hf_carp_checksum, hf_carp_checksum_status, &ei_carp_checksum, pinfo, in_cksum(&cksum_vec[0], 1),
                                ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
    } else {
        proto_tree_add_checksum(carp_tree, tvb, offset, hf_carp_checksum, hf_carp_checksum_status, &ei_carp_checksum, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    }

    offset+=2;

    /* Counter */
    proto_tree_add_item(carp_tree, hf_carp_counter, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    proto_tree_add_item(carp_tree, hf_carp_hmac, tvb, offset, 20, ENC_NA);
    offset+=20;

    return offset;
}

/* heuristic dissector */
static bool
dissect_carp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!test_carp_packet(tvb, pinfo, tree, data))
        return false;

    dissect_carp(tvb, pinfo, tree, data);
    return true;
}

void proto_register_carp(void)
{
    static hf_register_info hf[] = {
        { &hf_carp_ver_type,
          {"CARP message version and type", "carp.typever",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},

        { &hf_carp_version,
          {"CARP protocol version", "carp.version",
           FT_UINT8, BASE_DEC, NULL, CARP_VERSION_MASK,
           NULL, HFILL }},

        { &hf_carp_type,
          {"CARP packet type", "carp.type",
           FT_UINT8, BASE_DEC, VALS(carp_type_vals), CARP_TYPE_MASK,
           NULL, HFILL }},

        { &hf_carp_vhid,
          {"Virtual Host ID", "carp.vhid",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},

        { &hf_carp_advskew,
          {"Advertisement Skew", "carp.advskew",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},

        { &hf_carp_authlen,
          {"Auth Len", "carp.authlen",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           "Size of counter+hash in 32bit chunks", HFILL }},

        { &hf_carp_demotion,
          {"Demotion indicator", "carp.demotion",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},

        { &hf_carp_advbase,
          {"Adver Int", "carp.adver_int",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           "Time interval (in seconds) between ADVERTISEMENTS", HFILL }},

        { &hf_carp_counter, {"Counter", "carp.counter",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},

        { &hf_carp_hmac,
          {"HMAC", "carp.hmac",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           "SHA-1 HMAC", HFILL }},

        { &hf_carp_checksum,
          {"Checksum", "carp.checksum",
           FT_UINT16, BASE_HEX, NULL, 0x0,
           NULL, HFILL }},

        { &hf_carp_checksum_status,
          {"Checksum Status", "carp.checksum.status",
           FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
           NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_carp,
        &ett_carp_ver_type
    };

    static ei_register_info ei[] = {
        { &ei_carp_checksum, { "carp.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    };

    expert_module_t* expert_carp;

    proto_carp = proto_register_protocol("Common Address Redundancy Protocol", "CARP", "carp");
    carp_handle = register_dissector("carp", dissect_carp, proto_carp);
    proto_register_field_array(proto_carp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_carp = expert_register_protocol(proto_carp);
    expert_register_field_array(expert_carp, ei, array_length(ei));
}

void
proto_reg_handoff_carp(void)
{
    dissector_add_uint("ip.proto", IP_PROTO_VRRP, carp_handle);
    heur_dissector_add( "ip", dissect_carp_heur, "CARP over IP", "carp_ip", proto_carp, HEURISTIC_ENABLE);
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
