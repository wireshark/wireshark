/* packet-cesoeth.c
 * Dissection of Circuit Emulation Service over Ethernet (MEF 8)
 * www.mef.net
 *
 * Copyright 2018, AimValley B.V.
 * Jaap Keuter <jkeuter@aimvalley.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/etypes.h>
#include "packet-rtp.h"

void proto_register_cesoeth(void);
void proto_reg_handoff_cesoeth(void);

static dissector_handle_t cesoeth_handle;

static int proto_cesoeth;
static int hf_cesoeth_pw_ecid;
static int hf_cesoeth_pw_res;
static int hf_cesoeth_cw;
static int hf_cesoeth_cw_reserved1;
static int hf_cesoeth_cw_l;
static int hf_cesoeth_cw_r;
static int hf_cesoeth_cw_l0_m;
static int hf_cesoeth_cw_l1_m;
static int hf_cesoeth_cw_frg;
static int hf_cesoeth_cw_len;
static int hf_cesoeth_cw_seq;
static int hf_cesoeth_padding;

static int ett_cesoeth;
static int ett_cesoeth_cw;

static expert_field ei_cesoeth_reserved;
static expert_field ei_cesoeth_length;

static int* const cesoeth_l0_cw[] =
{
    &hf_cesoeth_cw_reserved1,
    &hf_cesoeth_cw_l,
    &hf_cesoeth_cw_r,
    &hf_cesoeth_cw_l0_m,
    &hf_cesoeth_cw_frg,
    &hf_cesoeth_cw_len,
    &hf_cesoeth_cw_seq,
    NULL
};

static int* const cesoeth_l1_cw[] =
{
    &hf_cesoeth_cw_reserved1,
    &hf_cesoeth_cw_l,
    &hf_cesoeth_cw_r,
    &hf_cesoeth_cw_l1_m,
    &hf_cesoeth_cw_frg,
    &hf_cesoeth_cw_len,
    &hf_cesoeth_cw_seq,
    NULL
};

static const value_string frg_names[] =
{
    { 0, "No fragmentation" },
    { 1, "First fragment" },
    { 2, "Last fragment" },
    { 3, "Intermediate fragment" },
    { 0, NULL }
};

static const value_string l0_m_names[] =
{
    { 0, "No local TDM defect" },
    { 1, "Reserved" },
    { 2, "RDI on TDM input" },
    { 3, "Non-TDM data" },
    { 0, NULL }
};

static const value_string l1_m_names[] =
{
    { 0, "TDM defect" },
    { 1, "Reserved" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { 0, NULL }
};

/* Preferences */
static bool has_rtp_header;
static bool heuristic_rtp_header = true;


static int
dissect_cesoeth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree  *cesoeth_tree;
    proto_item  *cesoeth_ti;
    proto_item  *bitmask_ti;
    int         offset = 0;
    uint32_t    ecid, reserved;
    bool        l_bit, r_bit;
    uint8_t     m_bits, frg;
    int         cw_len, padding_len, tail_len, payload_len;
    uint16_t    sn;
    tvbuff_t    *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CESoETH");
    col_clear(pinfo->cinfo, COL_INFO);

    cesoeth_ti = proto_tree_add_item(tree, proto_cesoeth, tvb, 0, -1, ENC_NA);
    cesoeth_tree = proto_item_add_subtree(cesoeth_ti, ett_cesoeth);

    proto_tree_add_item_ret_uint(cesoeth_tree, hf_cesoeth_pw_ecid, tvb, offset, 4, ENC_BIG_ENDIAN, &ecid);
    col_append_fstr(pinfo->cinfo, COL_INFO, "ECID: 0x%05x", ecid);
    bitmask_ti = proto_tree_add_item_ret_uint(cesoeth_tree, hf_cesoeth_pw_res, tvb, offset, 4, ENC_BIG_ENDIAN, &reserved);
    if (reserved != 0x102)
        expert_add_info_format(pinfo, bitmask_ti, &ei_cesoeth_reserved, "Reserved field must be 0x102");
    offset += 4;

    /*
     * CES header control word
     *
     * bits  name       description
     * 31-28 reserved   set to 0
     *  27   L-bit      set to 1 to indicate local TDM failure
     *  26   R-bit      set to 1 to indicate remote loss of frame
     * 25-24 M-bits     modifier bits
     * 23-22 FRG bits   fragmentation bits
     * 21-16 length     length (0 if no padding applied)
     * 15-0  sequence   sequence number
     */

    l_bit  = (tvb_get_uint8(tvb, offset) & 0x08) ? true : false;
    r_bit  = (tvb_get_uint8(tvb, offset) & 0x04) ? true : false;
    m_bits = (tvb_get_uint8(tvb, offset) & 0x03);
    frg    = tvb_get_bits8(tvb, 40, 2);
    cw_len = tvb_get_bits8(tvb, 42, 6);
    sn     = tvb_get_ntohs(tvb, offset + 2);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", SN: %u", sn);

    if (l_bit)
    {
        bitmask_ti = proto_tree_add_bitmask(cesoeth_tree, tvb, offset, hf_cesoeth_cw, ett_cesoeth_cw, cesoeth_l1_cw, ENC_NA);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_const(m_bits, l1_m_names, "Unknown"));
    } else {
        bitmask_ti = proto_tree_add_bitmask(cesoeth_tree, tvb, offset, hf_cesoeth_cw, ett_cesoeth_cw, cesoeth_l0_cw, ENC_NA);
        if (m_bits)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_const(m_bits, l0_m_names, "Unknown"));
    }

    if (cw_len >= 42)
    {
        /*
         * Now we have to go spelunking in the bitmask tree for the length item
         * in order to add an expert item to it.
         */
        proto_tree *bm_tree = proto_item_get_subtree(bitmask_ti);
        if (bm_tree) {
            proto_item *pi;

            for (pi = tree->first_child; pi; pi = pi->next)
            {
                field_info *fi;
                fi = PITEM_FINFO(pi);
                if (fi && (fi->hfinfo->id == hf_cesoeth_cw_len))
                    break;
            }

            expert_add_info_format(pinfo, pi, &ei_cesoeth_length, "Length can not be 42 or larger");
        }

        cw_len = 0; /* Put a stop to this madness */
    }

    if (r_bit)
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Remote loss of frame");

    if (frg)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_const(frg, frg_names, "Unknown"));

    offset += 4;

    /*
     * When L is set the TDM payload MAY be missing.
     * But also when snap value is used on capture.
     * Will the optional RTP header be there when the TDM payload is missing? I guess so.
     * Length includes the size of the CW (being 4), the optional RTP header (being 12) and
     * the TDM payload, as long as it doesn't exceed 42 octets. Length > 0 indicates padding,
     * which must NOT be passed to the RTP dissector, it's not RTP padding.
     */

    padding_len = (cw_len > 0) ? (42 - cw_len) : 0;
    tail_len = tvb_reported_length_remaining(tvb, offset);
    payload_len = tail_len - padding_len;

    if (payload_len > 0)
    {
        next_tvb = tvb_new_subset_length(tvb, offset, payload_len);

        if ((has_rtp_header) ||
            ((heuristic_rtp_header) &&
                /* Check for RTP version 2, the other fields must be zero */
                (tvb_get_uint8(tvb, offset) == 0x80) &&
                /* Check the marker is zero. Unfortunately PT is not always from the dynamic range */
                ((tvb_get_uint8(tvb, offset + 1) & 0x80) == 0) &&
                /* The sequence numbers from cw and RTP header must match */
                (tvb_get_ntohs(tvb, offset + 2) == sn)))
        {
            struct _rtp_info rtp_info;

            int rtp_header_len = dissect_rtp_shim_header(tvb, offset, pinfo, cesoeth_tree, &rtp_info);

            col_set_str(pinfo->cinfo, COL_PROTOCOL, "CESoETH (w RTP)");
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "RTP PT: %u, SSRC: 0x%X, Seq: %u, Time=%u",
                                rtp_info.info_payload_type,
                                rtp_info.info_sync_src,
                                rtp_info.info_seq_num,
                                rtp_info.info_timestamp
                               );

            next_tvb = tvb_new_subset_length(tvb, offset + rtp_header_len, payload_len - rtp_header_len);
        }

        call_data_dissector(next_tvb, pinfo, tree);

        offset += payload_len;
    }

    if (padding_len > 0)
    {
        proto_tree_add_item(cesoeth_tree, hf_cesoeth_padding, tvb, offset, padding_len, ENC_NA);

        offset += padding_len;
    }

    return offset;
}

void
proto_register_cesoeth(void)
{
    static hf_register_info hf[] = {
        { &hf_cesoeth_pw_ecid,
            { "ECID", "cesoeth.ecid", FT_UINT32, BASE_HEX,
            NULL, 0xFFFFF000, NULL, HFILL }},
        { &hf_cesoeth_pw_res,
            { "Reserved", "cesoeth.res", FT_UINT32, BASE_HEX,
            NULL, 0x00000FFF, "Reserved (0x102)", HFILL }},

        { &hf_cesoeth_cw,
            { "Control word", "cesoeth.cw", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_cesoeth_cw_reserved1,
            { "Reserved", "cesoeth.cw.reserved", FT_UINT32, BASE_HEX,
            NULL, 0xF0000000, NULL, HFILL }},
        { &hf_cesoeth_cw_l,
            { "L-bit", "cesoeth.cw.l", FT_BOOLEAN, 32,
            NULL, 0x08000000, "Local TDM failure", HFILL }},
        { &hf_cesoeth_cw_r,
            { "R-bit", "cesoeth.cw.r", FT_BOOLEAN, 32,
            NULL, 0x04000000, "Remote Loss of Frames indication", HFILL }},
        { &hf_cesoeth_cw_l0_m,
            { "M-bits", "cesoeth.cw.m", FT_UINT32, BASE_HEX,
            VALS(l0_m_names), 0x03000000, "Modifier bits", HFILL }},
        { &hf_cesoeth_cw_l1_m,
            { "M-bits", "cesoeth.cw.m", FT_UINT32, BASE_HEX,
            VALS(l1_m_names), 0x03000000, "Modifier bits", HFILL }},
        { &hf_cesoeth_cw_frg,
            { "Frg", "cesoeth.cw.frg", FT_UINT32, BASE_HEX,
            VALS(frg_names), 0x00C00000, "Fragmentation bits", HFILL }},
        { &hf_cesoeth_cw_len,
            { "Len", "cesoeth.cw.len", FT_UINT32, BASE_DEC,
            NULL, 0x003F0000, "Length", HFILL }},
        { &hf_cesoeth_cw_seq,
            { "SN", "cesoeth.cw.sn", FT_UINT32, BASE_DEC,
            NULL, 0x0000FFFF, "Sequence number", HFILL }},

        { &hf_cesoeth_padding,
            { "Padding", "cesoeth.padding", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }}
    };

    static int *ett[] = {
        &ett_cesoeth,
        &ett_cesoeth_cw
    };

    static ei_register_info ei[] = {
        { &ei_cesoeth_reserved,
            { "cesoeth.reserved", PI_PROTOCOL, PI_WARN,
              "Reserved field", EXPFILL }},
        { &ei_cesoeth_length,
            { "cesoeth.length", PI_PROTOCOL, PI_WARN,
              "Length field", EXPFILL }}
    };

    module_t *cesoeth_module;
    expert_module_t* expert_cesoeth;

    proto_cesoeth = proto_register_protocol("Circuit Emulation Service over Ethernet", "CESoETH", "cesoeth");
    proto_register_field_array(proto_cesoeth, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_cesoeth = expert_register_protocol(proto_cesoeth);
    expert_register_field_array(expert_cesoeth, ei, array_length(ei));

    cesoeth_module = prefs_register_protocol(proto_cesoeth, NULL);

    prefs_register_bool_preference(cesoeth_module, "rtp_header", "RTP header in CES payload",
                                   "Whether or not the RTP header is present in the CES payload.", &has_rtp_header);

    prefs_register_bool_preference(cesoeth_module, "rtp_header_heuristic", "Try to find RTP header in CES payload",
                                   "Heuristically determine if an RTP header is present in the CES payload.", &heuristic_rtp_header);


    cesoeth_handle = register_dissector("cesoeth", dissect_cesoeth, proto_cesoeth);
}

void
proto_reg_handoff_cesoeth(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_CESOETH, cesoeth_handle);
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
