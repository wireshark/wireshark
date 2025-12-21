/* packet-trueconf.c
 * Routines for TrueConf packet dissection
 * Copyright 2025, Sergey Rudakov <rudakov.private.bsf@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <wireshark.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include "packet-tcp.h"


#define TRUECONF_PORT 4307
#define TRUECONF_MAGIC "_VS_TRANSPORT_"
#define TRUECONF_MAGIC_LEN 14

static int proto_trueconf;
static int ett_trueconf;

static int hf_trueconf_magic;
static int hf_trueconf_zero2;
static int hf_trueconf_conn_id;
static int hf_trueconf_flags;
static int hf_trueconf_cap;
static int hf_trueconf_unk1;
static int hf_trueconf_ver_major;
static int hf_trueconf_ver_minor;
static int hf_trueconf_name_len;
static int hf_trueconf_host;
static int hf_trueconf_sep0;
static int hf_trueconf_token_len;
static int hf_trueconf_token;
static int hf_trueconf_msg_type;
static int hf_trueconf_len_a;
static int hf_trueconf_len_b;
static int hf_trueconf_seed16;
static int hf_trueconf_payload;
static int hf_trueconf_trailer1;
static int hf_trueconf_trailer2;
static int hf_trueconf_trailer3;
static int hf_trueconf_trailer4;

static int find_magic_offset(tvbuff_t *tvb, int offset)
{
    if (tvb_memeql(tvb, offset, (const uint8_t*)TRUECONF_MAGIC, TRUECONF_MAGIC_LEN) == 0)
        return offset;

    return -1;
}


static unsigned
get_trueconf_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    int magic_off = find_magic_offset(tvb, offset);
    if (magic_off < 0)
        return 0;

    unsigned headers = 2 + 3 + 1 + 2 + 1 + 1 + 1 + 1;
    if (tvb_captured_length_remaining(tvb, magic_off) < TRUECONF_MAGIC_LEN + headers)
        return 0;

    unsigned pos = magic_off + TRUECONF_MAGIC_LEN + headers;
    unsigned name_len = tvb_get_uint8(tvb, pos - 1);
    unsigned caplen = tvb_captured_length(tvb);
    if (name_len > 0 && caplen - pos == 0 )  // if the name length is not 0 and the name is missing,
        return caplen; // it means that there will be no new data

    pos += name_len;

    if (pos + 2 > caplen)
        return 0; //  token_len

    unsigned token_len = tvb_get_ntohs(tvb, pos);
    pos += 2 + token_len;
    if (pos + 2 + 4 + 4 + 16 > caplen)
        return 0; // msg_type + len_a + len_b + seed16

    unsigned len_a = tvb_get_letohl(tvb, pos + 2);
    unsigned len_b = tvb_get_letohl(tvb, pos + 6);
    unsigned payload_len = len_a < len_b ? len_a : len_b;
    unsigned full_len = pos + 2 + 4 + 4 + 16 + payload_len - magic_off - headers;
    return full_len;
}


static int dissect_trueconf_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int off = find_magic_offset(tvb, 0);
    if (off < 0)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRUECONF");

    proto_item *ti = proto_tree_add_item(tree, proto_trueconf, tvb, off, -1, ENC_NA);
    proto_tree *trueconf_tree = proto_item_add_subtree(ti, ett_trueconf);

    proto_tree_add_item(trueconf_tree, hf_trueconf_magic, tvb, off, 14, ENC_ASCII);
    off += 14;
    proto_tree_add_item(trueconf_tree, hf_trueconf_zero2, tvb, off, 2, ENC_NA);
    off += 2;
    proto_tree_add_item(trueconf_tree, hf_trueconf_conn_id, tvb, off, 3, ENC_NA);
    off += 3;
    proto_tree_add_item(trueconf_tree, hf_trueconf_flags, tvb, off, 1, ENC_BIG_ENDIAN);
    off += 1;
    proto_tree_add_item(trueconf_tree, hf_trueconf_cap, tvb, off, 2, ENC_BIG_ENDIAN);
    off += 2;
    proto_tree_add_item(trueconf_tree, hf_trueconf_unk1, tvb, off, 1, ENC_BIG_ENDIAN);
    off += 1;
    proto_tree_add_item(trueconf_tree, hf_trueconf_ver_major, tvb, off, 1, ENC_BIG_ENDIAN);
    off += 1;
    proto_tree_add_item(trueconf_tree, hf_trueconf_ver_minor, tvb, off, 1, ENC_BIG_ENDIAN);
    off += 1;

    uint32_t name_len;
    proto_tree_add_item_ret_uint(trueconf_tree, hf_trueconf_name_len, tvb, off, 1, ENC_BIG_ENDIAN, &name_len);
    off += 1;

    if (name_len > 0) {
        proto_tree_add_item(trueconf_tree, hf_trueconf_host, tvb, off, name_len, ENC_ASCII);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Handshake host=%s", tvb_format_text(pinfo->pool, tvb, off, name_len));
        off += name_len;
    }

    if (tvb_reported_length_remaining(tvb, off) > 0 && tvb_get_uint8(tvb, off) == 0x00) {
        proto_tree_add_item(trueconf_tree, hf_trueconf_sep0, tvb, off, 1, ENC_BIG_ENDIAN);
        off += 1;
    }

    uint32_t token_len;
    proto_tree_add_item_ret_uint(trueconf_tree, hf_trueconf_token_len, tvb, off, 1, ENC_BIG_ENDIAN, &token_len);
    off += 1;
    if (token_len > 0) {
        proto_tree_add_item(trueconf_tree, hf_trueconf_token, tvb, off, token_len, ENC_ASCII);
        off += token_len;
    }

    proto_tree_add_item(trueconf_tree, hf_trueconf_msg_type, tvb, off, 2, ENC_BIG_ENDIAN);
    off += 2;
    proto_tree_add_item(trueconf_tree, hf_trueconf_len_a, tvb, off, 4, ENC_LITTLE_ENDIAN);
    off += 4;
    proto_tree_add_item(trueconf_tree, hf_trueconf_len_b, tvb, off, 4, ENC_LITTLE_ENDIAN);
    off += 4;
    proto_tree_add_item(trueconf_tree, hf_trueconf_seed16, tvb, off, 16, ENC_NA);
    off += 16;

    int remain = tvb_reported_length_remaining(tvb, off);
    if (remain > 0) {
        proto_item *payload_ti = proto_tree_add_item(trueconf_tree, hf_trueconf_payload, tvb, off, remain, ENC_NA);
        if (remain >= 16) {
            int tail = off + remain - 16;
            proto_tree *tr = proto_item_add_subtree(payload_ti, ett_trueconf);
            proto_tree_add_item(tr, hf_trueconf_trailer1, tvb, tail, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tr, hf_trueconf_trailer2, tvb, tail + 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tr, hf_trueconf_trailer3, tvb, tail + 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tr, hf_trueconf_trailer4, tvb, tail + 12, 4, ENC_LITTLE_ENDIAN);
        }
    }

    return tvb_captured_length(tvb);
}

static int dissect_trueconf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, TRUECONF_MAGIC_LEN, get_trueconf_pdu_len, dissect_trueconf_pdu, data);
    return tvb_captured_length(tvb);
}


void proto_register_trueconf(void)
{
    static hf_register_info hf[] = {
        { &hf_trueconf_magic,      { "Magic",          "trueconf.magic",     FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_trueconf_zero2,      { "Reserved(2)",    "trueconf.zero2",     FT_BYTES,  BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_trueconf_conn_id,    { "ConnID(3)",      "trueconf.conn_id",   FT_BYTES,  BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_trueconf_flags,      { "Flags",          "trueconf.flags",     FT_UINT8,  BASE_HEX,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_cap,        { "Capabilities",   "trueconf.cap",       FT_UINT16, BASE_HEX,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_unk1,       { "Unknown1",       "trueconf.unk1",      FT_UINT8,  BASE_HEX,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_ver_major,  { "Version Major",  "trueconf.ver.major", FT_UINT8,  BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_ver_minor,  { "Version Minor",  "trueconf.ver.minor", FT_UINT8,  BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_name_len,   { "Name Length",    "trueconf.name_len",  FT_UINT8,  BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_host,       { "Server Name",    "trueconf.host",      FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_trueconf_sep0,       { "Separator(0x00)","trueconf.sep0",      FT_UINT8,  BASE_HEX,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_token_len,  { "Token Length",   "trueconf.token_len", FT_UINT16, BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_token,      { "Token/ID",       "trueconf.token",     FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_trueconf_msg_type,   { "Message Type",   "trueconf.msg_type",  FT_UINT16, BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_len_a,      { "Length A (LE)",  "trueconf.len_a",     FT_UINT32, BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_len_b,      { "Length B (LE)",  "trueconf.len_b",     FT_UINT32, BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_seed16,     { "Seed/Salt (16)", "trueconf.seed16",    FT_BYTES,  BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_trueconf_payload,    { "Opaque Payload", "trueconf.payload",   FT_BYTES,  BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_trueconf_trailer1,   { "Trailer1 (LE)",  "trueconf.trailer1",  FT_UINT32, BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_trailer2,   { "Trailer2 (LE)",  "trueconf.trailer2",  FT_UINT32, BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_trailer3,   { "Trailer3 (LE)",  "trueconf.trailer3",  FT_UINT32, BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_trueconf_trailer4,   { "Trailer4 (LE)",  "trueconf.trailer4",  FT_UINT32, BASE_DEC,  NULL, 0, NULL, HFILL }},
    };

    static int *ett[] = { &ett_trueconf };

    proto_trueconf = proto_register_protocol("TrueConf Protocol", "TrueConf", "trueconf");

    proto_register_field_array(proto_trueconf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_trueconf(void)
{
    dissector_handle_t trueconf_handle;
    trueconf_handle = create_dissector_handle(dissect_trueconf, proto_trueconf);
    dissector_add_uint_with_preference("tcp.port", TRUECONF_PORT, trueconf_handle);
}
