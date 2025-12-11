/* packet-ple.c
 * Routines for Private Line Emulation (PLE) dissection
 *
 * Copyright 2025, AimValley B.V.
 * Jaap Keuter <jaap.keuter@aimvalley.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Relevant IETF documentation:
 * - RFC 9801
 * - RFC 4385
 * - RFC 9790
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-mpls.h"
#include "packet-rtp.h"
#include "packet-iana-data.h"

void proto_register_ple(void);
void proto_reg_handoff_ple(void);

static dissector_handle_t ple_handle;

static int proto_ple;

static int hf_ple_cw;
static int hf_ple_cw_pfn;
static int hf_ple_cw_l;
static int hf_ple_cw_r;
static int hf_ple_cw_rsv;
static int hf_ple_cw_frg;
static int hf_ple_cw_len;
static int hf_ple_cw_seq;
static int hf_ple_seq;

static int ett_ple;
static int ett_ple_cw;

static expert_field ei_ple_reserved;
static expert_field ei_ple_fragmentation;
static expert_field ei_ple_length;
static expert_field ei_ple_rtp;
static expert_field ei_ple_seq;

static const true_false_string tfs_l_bit = { "Attachment circuit fault", "Ok" };
static const true_false_string tfs_r_bit = { "Packet loss or Backward Fault", "Ok" };

static const value_string cw_frg_names[] =
{
    { 0, "No fragmentation" },
    { 1, "First fragment" },
    { 2, "Last fragment" },
    { 3, "Intermediate fragment" },
    { 0, NULL }
};

/* Preferences */
#define PREF_SEQ_SIZE_AUTO  0
#define PREF_SEQ_SIZE_16    1
#define PREF_SEQ_SIZE_32    2

static const enum_val_t pref_seq_size_types[] = {
    { "auto",   "Automatic", PREF_SEQ_SIZE_AUTO },
    { "standard", "Standard (16 bit)", PREF_SEQ_SIZE_16 },
    { "extended", "Extended (32 bit)", PREF_SEQ_SIZE_32 },
    { NULL, NULL, 0 }
};

static int pref_seq_size = PREF_SEQ_SIZE_AUTO;


static int
dissect_ple(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree  *ple_tree;
    proto_item  *ple_ti;
    proto_item  *ple_cw_ti;
    proto_tree  *ple_cw_tree;
    proto_item  *ti;
    int         offset = 0;
    bool        l_bit, r_bit;
    uint32_t    cw_rsv;
    uint32_t    cw_frg;
    uint32_t    cw_len;
    uint32_t    cw_seq;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PLE");
    col_clear(pinfo->cinfo, COL_INFO);

    ple_ti = proto_tree_add_item(tree, proto_ple, tvb, 0, -1, ENC_NA);
    ple_tree = proto_item_add_subtree(ple_ti, ett_ple);

    /* PLE Control Word, as per RFC 9801, section 5.2.1 */
    ple_cw_ti = proto_tree_add_item(ple_tree, hf_ple_cw, tvb, offset, 4, ENC_BIG_ENDIAN);
    ple_cw_tree = proto_item_add_subtree(ple_cw_ti, ett_ple_cw);

    proto_tree_add_item(ple_cw_tree, hf_ple_cw_pfn, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_boolean(ple_cw_tree, hf_ple_cw_l, tvb, offset, 4, ENC_BIG_ENDIAN, &l_bit);
    proto_tree_add_item_ret_boolean(ple_cw_tree, hf_ple_cw_r, tvb, offset, 4, ENC_BIG_ENDIAN, &r_bit);
    ti = proto_tree_add_item_ret_uint(ple_cw_tree, hf_ple_cw_rsv, tvb, offset, 4, ENC_BIG_ENDIAN, &cw_rsv);
    if (cw_rsv)
    {
        expert_add_info(pinfo, ti, &ei_ple_reserved);
    }

    ti = proto_tree_add_item_ret_uint(ple_cw_tree, hf_ple_cw_frg, tvb, offset, 4, ENC_BIG_ENDIAN, &cw_frg);
    if (cw_frg)
    {
        expert_add_info(pinfo, ti, &ei_ple_fragmentation);
    }

    ti = proto_tree_add_item_ret_uint(ple_cw_tree, hf_ple_cw_len, tvb, offset, 4, ENC_BIG_ENDIAN, &cw_len);
    if (cw_len)
    {
        expert_add_info(pinfo, ti, &ei_ple_length);
    }

    proto_tree_add_item_ret_uint(ple_cw_tree, hf_ple_cw_seq, tvb, offset, 4, ENC_BIG_ENDIAN, &cw_seq);

    col_append_fstr(pinfo->cinfo, COL_INFO, "CW: 0x%08x", tvb_get_ntohl(tvb, offset));

    if (l_bit)
    {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "L-bit set");
    }
    if (r_bit)
    {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "R-bit set");
    }

    offset += 4;

    /* RTP Header, as per RFC 9801, section 5.2.2 */
    struct _rtp_info rtp_info;

    int rtp_header_len = dissect_rtp_shim_header(tvb, offset, pinfo, ple_tree, &rtp_info);

    if (rtp_header_len == 0)
    {
        proto_tree_add_expert(ple_tree, pinfo, &ei_ple_rtp, tvb, offset, 0);
        col_append_sep_str(pinfo->cinfo, COL_INFO, "; ", "RTP header missing");
    }
    else
    {
        unsigned ple_seq = cw_seq;

        if (((pref_seq_size == PREF_SEQ_SIZE_AUTO) && (cw_seq != rtp_info.info_seq_num)) ||
            (pref_seq_size == PREF_SEQ_SIZE_32))
        {
            /* The PLE sequence number is an extended sequence number, i.e.,
             * the concatenation of RTP seq and PLE CW seq.
             */
            ple_seq |= rtp_info.info_seq_num << 16;
        }

        ti = proto_tree_add_uint(ple_tree, hf_ple_seq, tvb, 0, 0, ple_seq);
        proto_item_set_generated(ti);

        if (pref_seq_size == PREF_SEQ_SIZE_16)
        {
            /* The PLE sequence number is a standard sequence number, i.e.,
             * the RTP seq and PLE CW seq, which are (supposed to be) equal.
             */
            if (rtp_info.info_seq_num != cw_seq)
            {
                expert_add_info_format(pinfo, ti, &ei_ple_seq,
                                       "PLE CW seq (0x%04x) and RTP seq (0x%04x) must be equal",
                                       cw_seq, rtp_info.info_seq_num
                                       );
            }
        }

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "; ", "RTP PT: %u, SSRC: 0x%X, Seq: %u, Time=%u",
                            rtp_info.info_payload_type,
                            rtp_info.info_sync_src,
                            rtp_info.info_seq_num,
                            rtp_info.info_timestamp
                            );

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "; ", "PLE Seq: %u", ple_seq);
    }

    tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset + rtp_header_len);

    call_data_dissector(next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

void
proto_register_ple(void)
{
    static hf_register_info hf[] = {
        { &hf_ple_cw,
            { "Control word", "ple.cw", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ple_cw_pfn,
            { "Post-stack First Nibble", "ple.cw.pfn", FT_UINT32, BASE_HEX,
            NULL, 0xF0000000, NULL, HFILL }},
        { &hf_ple_cw_l,
            { "L-bit", "ple.cw.l", FT_BOOLEAN, 32,
            TFS(&tfs_l_bit), 0x08000000, "Payload invalid due to attachment circuit fault", HFILL }},
        { &hf_ple_cw_r,
            { "R-bit", "ple.cw.r", FT_BOOLEAN, 32,
            TFS(&tfs_r_bit), 0x04000000, "Remote packet loss or backward fault indication", HFILL }},
        { &hf_ple_cw_rsv,
            { "RSV", "ple.cw.rsv", FT_UINT32, BASE_HEX,
            NULL, 0x03000000, "Reserved", HFILL }},
        { &hf_ple_cw_frg,
            { "FRG", "ple.cw.cw_frg", FT_UINT32, BASE_HEX,
            VALS(cw_frg_names), 0x00C00000, "Fragmentation bits", HFILL }},
        { &hf_ple_cw_len,
            { "LEN", "ple.cw.len", FT_UINT32, BASE_DEC,
            NULL, 0x003F0000, "Length", HFILL }},
        { &hf_ple_cw_seq,
            { "Sequence number", "ple.cw.seq", FT_UINT32, BASE_DEC,
            NULL, 0x0000FFFF, NULL, HFILL }},

        { &hf_ple_seq,
            { "Sequence number", "ple.seq", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_ple,
        &ett_ple_cw
    };

    static ei_register_info ei[] = {
        { &ei_ple_reserved,
            { "ple.reserved", PI_PROTOCOL, PI_WARN,
              "RSV must be zero", EXPFILL }},
        { &ei_ple_fragmentation,
            { "ple.fragmentation", PI_PROTOCOL, PI_WARN,
              "FRG must be zero", EXPFILL }},
        { &ei_ple_length,
            { "ple.length", PI_PROTOCOL, PI_WARN,
              "Length must be zero", EXPFILL }},
        { &ei_ple_rtp,
            { "ple.rtp", PI_PROTOCOL, PI_ERROR,
              "RTP header missing", EXPFILL }},
        { &ei_ple_seq,
            { "ple.sequence", PI_PROTOCOL, PI_WARN,
              "PLE CW and RTP sequence numbers are unequal", EXPFILL }}
    };

    module_t *ple_module;
    expert_module_t* expert_ple;

    proto_ple = proto_register_protocol("Private Line Emulation", "PLE", "ple");
    proto_register_field_array(proto_ple, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ple = expert_register_protocol(proto_ple);
    expert_register_field_array(expert_ple, ei, array_length(ei));

    ple_module = prefs_register_protocol(proto_ple, NULL);

    prefs_register_enum_preference(ple_module, "seq_num_size",
        "Sequence number size", "Sequence numbers (CW and RTP) are the same or concatenated", &pref_seq_size,
        pref_seq_size_types, false);

    ple_handle = register_dissector("ple", dissect_ple, proto_ple);
}

void
proto_reg_handoff_ple(void)
{
    dissector_add_for_decode_as("mpls.label", ple_handle);
    dissector_add_for_decode_as("mpls.pfn", ple_handle);
    dissector_add_for_decode_as("ethertype", ple_handle);
    dissector_add_for_decode_as("udp.port", ple_handle);

    dissector_add_uint("ip.proto", IP_PROTO_BIT_EMU, ple_handle);
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
