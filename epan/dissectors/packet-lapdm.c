/* packet-lapdm.c
 * Routines for LAPDm frame disassembly
 * Duncan Salerno <duncan.salerno@googlemail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* LAPDm references:
 *
 * Mobile Station - Base Stations System (MS - BSS) Interface Data Link (DL) Layer Specification
 * Base Station Controller - Base Transceiver Station (BSC - BTS) interface; Layer 2 specification
 * http://www.3gpp.org/ftp/Specs/html-info/44006.htm
 *
 * From 3GPP TS 44.006:
 *
 * LAPDm is used for information sent on the control channels BCCH, AGCH, NCH,
 * PCH, FACCH, SACCH and SDCCH as defined in 3GPP TS 44.003.
 *
 * AGCH, NCH and PCH are sometimes referred to by the collective name CCCH.
 * FACCH, SACCH and SDCCH are, similarly, referred to by the collective name DCCH.
 *
 * Format A is used on DCCHs for frames where there is no information field.
 * Formats B, Bter and B4 are used on DCCHs for frames containing an information field:
 * Format Bter is used on request of higher layers if and only if short L2 header type 1 is
 * supported and a UI command is to be transmitted on SAPI 0;
 * Format B4 is used for UI frames transmitted by the network on SACCH;
 * Format B is applied in all other cases.
 * Format Bbis is used only on BCCH, PCH, NCH, and AGCH.
 * In addition there is a Format C for transmission of random access signals.
 *
 * This module currently supports A, B, B4
 * In the future will support Bter
 * Bbis and C should be supported elsewhere
 */

#include "config.h"
#include "packet-lapdm.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/xdlc.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>

void proto_register_lapdm(void);

static dissector_handle_t b4_info_handle;

static int proto_lapdm;
static int hf_lapdm_address;
static int hf_lapdm_ea;
static int hf_lapdm_cr;
static int hf_lapdm_sapi;
static int hf_lapdm_lpd;

static int hf_lapdm_control;
static int hf_lapdm_n_r;
static int hf_lapdm_n_s;
static int hf_lapdm_p;
static int hf_lapdm_f;
static int hf_lapdm_s_ftype;
static int hf_lapdm_u_modifier_cmd;
static int hf_lapdm_u_modifier_resp;
static int hf_lapdm_ftype_i;
static int hf_lapdm_ftype_s_u;

static int hf_lapdm_length;
static int hf_lapdm_el;
static int hf_lapdm_m;
static int hf_lapdm_len;

/*
 * LAPDm fragment handling
 */
static int hf_lapdm_fragment_data;
static int hf_lapdm_fragments;
static int hf_lapdm_fragment;
static int hf_lapdm_fragment_overlap;
static int hf_lapdm_fragment_overlap_conflicts;
static int hf_lapdm_fragment_multiple_tails;
static int hf_lapdm_fragment_too_long_fragment;
static int hf_lapdm_fragment_error;
static int hf_lapdm_fragment_count;
static int hf_lapdm_reassembled_in;
static int hf_lapdm_reassembled_length;

static int ett_lapdm;
static int ett_lapdm_address;
static int ett_lapdm_control;
static int ett_lapdm_length;
static int ett_lapdm_fragment;
static int ett_lapdm_fragments;

static reassembly_table lapdm_reassembly_table;

static wmem_map_t *lapdm_last_n_s_map;

static dissector_table_t lapdm_sapi_dissector_table;

static bool reassemble_lapdm = true;

/*
 * Bits in the address field.
 */
#define LAPDM_SAPI              0x1c    /* Service Access Point Identifier */
#define LAPDM_SAPI_SHIFT        2
#define LAPDM_CR                0x02    /* Command/Response bit */
#define LAPDM_EA                0x01    /* First Address Extension bit */
#define LAPDM_LPD               0x60    /* Link Protocol Discriminator */

/*
 * Bits in the length field.
 */
#define LAPDM_EL                0x01    /* Extended Length = 1 */
#define LAPDM_M                 0x02    /* More fragments */
#define LAPDM_M_SHIFT           1
#define LAPDM_LEN               0xfc    /* Length */
#define LAPDM_LEN_SHIFT         2

#define LAPDM_HEADER_LEN 3
#define LAPDM_HEADER_LEN_B4 2

#define LAPDM_SAPI_RR_CC_MM     0
#define LAPDM_SAPI_SMS          3

/* Used only for U frames */
static const xdlc_cf_items lapdm_cf_items = {
    &hf_lapdm_n_r,
    &hf_lapdm_n_s,
    &hf_lapdm_p,
    &hf_lapdm_f,
    &hf_lapdm_s_ftype,
    &hf_lapdm_u_modifier_cmd,
    &hf_lapdm_u_modifier_resp,
    &hf_lapdm_ftype_i,
    &hf_lapdm_ftype_s_u
};

static const value_string lapdm_ea_vals[] = {
    { 0,                "More octets" },
    { 1,                "Final octet" },
    { 0,                NULL }
};

static const value_string lapdm_sapi_vals[] = {
    { LAPDM_SAPI_RR_CC_MM,      "RR/MM/CC" },
    { LAPDM_SAPI_SMS,           "SMS/SS" },
    { 0,                        NULL }
};

static const value_string lapdm_lpd_vals[] = {
    { 0,                "Normal GSM" },
    { 1,                "Cell broadcast service" },
    { 0,                NULL }
};

static const value_string lapdm_m_vals[] = {
    { 0,                "Last segment" },
    { 1,                "More segments" },
    { 0,                NULL }
};

static const value_string lapdm_el_vals[] = {
    { 0,                "More octets" },
    { 1,                "Final octet" },
    { 0,                NULL }
};


static const fragment_items lapdm_frag_items = {
    /* Fragment subtrees */
    &ett_lapdm_fragment,
    &ett_lapdm_fragments,
    /* Fragment fields */
    &hf_lapdm_fragments,
    &hf_lapdm_fragment,
    &hf_lapdm_fragment_overlap,
    &hf_lapdm_fragment_overlap_conflicts,
    &hf_lapdm_fragment_multiple_tails,
    &hf_lapdm_fragment_too_long_fragment,
    &hf_lapdm_fragment_error,
    &hf_lapdm_fragment_count,
    /* Reassembled in field */
    &hf_lapdm_reassembled_in,
    /* Reassembled length field */
    &hf_lapdm_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "fragments"
};

static bool hdr_has_length(enum lapdm_hdr_type hdr_type)
{
    switch (hdr_type) {
    case LAPDM_HDR_FMT_A:
    case LAPDM_HDR_FMT_B:
        return true;
    default:
        return false;
    }
}


static int
dissect_lapdm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree *lapdm_tree, *addr_tree, *length_tree;
    proto_item *lapdm_ti, *addr_ti, *length_ti;
    uint8_t addr, length, header_len, cr, sapi, len, n_s;
    int control;
    bool m;
    tvbuff_t *payload;
    int available_length;
    bool is_response = false;
    enum lapdm_hdr_type hdr_type = LAPDM_HDR_FMT_B;
    bool is_acch = false, is_ui_frame = false;

    if (data) {
        lapdm_data_t *ld = (lapdm_data_t *) data;
        is_acch = ld->is_acch;
    }

    /* Check that there's enough data */
    if (tvb_captured_length(tvb) < LAPDM_HEADER_LEN_B4)
        return 0;

    control = tvb_get_uint8(tvb, 1);
    is_ui_frame = (control & XDLC_S_U_MASK) == XDLC_U && (control & XDLC_U_MODIFIER_MASK) == XDLC_UI;

    /* only downlink UI SACCH frames use B4 header format */
    if (is_acch && is_ui_frame && pinfo->p2p_dir == P2P_DIR_RECV) {
        hdr_type = LAPDM_HDR_FMT_B4;
        header_len = LAPDM_HEADER_LEN_B4;
        length = 0;
    } else {
        header_len = LAPDM_HEADER_LEN;

        /* Check that there's enough data */
        if (tvb_captured_length(tvb) < header_len)
            return 0;

        length = tvb_get_uint8(tvb, 2);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LAPDm");

    addr = tvb_get_uint8(tvb, 0);

    cr = addr & LAPDM_CR;
    if (pinfo->p2p_dir == P2P_DIR_RECV) {
        is_response = cr ? false : true;
    }
    else if (pinfo->p2p_dir == P2P_DIR_SENT) {
        is_response = cr ? true : false;
    }

    if (tree) {
        lapdm_ti = proto_tree_add_item(tree, proto_lapdm, tvb, 0, header_len, ENC_NA);
        lapdm_tree = proto_item_add_subtree(lapdm_ti, ett_lapdm);

        addr_ti = proto_tree_add_uint(lapdm_tree, hf_lapdm_address, tvb, 0, 1, addr);
        addr_tree = proto_item_add_subtree(addr_ti, ett_lapdm_address);

        proto_tree_add_uint(addr_tree, hf_lapdm_lpd, tvb, 0, 1, addr);
        proto_tree_add_uint(addr_tree, hf_lapdm_sapi, tvb, 0, 1, addr);
        proto_tree_add_uint(addr_tree, hf_lapdm_cr, tvb, 0, 1, addr);
        proto_tree_add_uint(addr_tree, hf_lapdm_ea, tvb, 0, 1, addr);
    }
    else {
        lapdm_ti = NULL;
        lapdm_tree = NULL;
    }

    control = dissect_xdlc_control(tvb, 1, pinfo, lapdm_tree, hf_lapdm_control,
                                   ett_lapdm_control, &lapdm_cf_items, NULL /* LAPDm doesn't support extended */, NULL, NULL,
                                   is_response, false, false);

    /* dissect length field (if present) */
    if (tree && hdr_has_length(hdr_type)) {
        length_ti = proto_tree_add_uint(lapdm_tree, hf_lapdm_length, tvb,
                                        2, 1, length);
        length_tree = proto_item_add_subtree(length_ti, ett_lapdm_length);

        proto_tree_add_uint(length_tree, hf_lapdm_len, tvb, 2, 1, length);
        proto_tree_add_uint(length_tree, hf_lapdm_m, tvb, 2, 1, length);
        proto_tree_add_uint(length_tree, hf_lapdm_el, tvb, 2, 1, length);
    }

    if (hdr_has_length(hdr_type)) {
        len = (length & LAPDM_LEN) >> LAPDM_LEN_SHIFT;
        m = (length & LAPDM_M) >> LAPDM_M_SHIFT;
    } else {
        len = tvb_captured_length(tvb) - header_len;
        m = 0;
    }

    sapi = (addr & LAPDM_SAPI) >> LAPDM_SAPI_SHIFT;
    n_s = (control & XDLC_N_S_MASK) >> XDLC_N_S_SHIFT;
    available_length = tvb_captured_length(tvb) - header_len;

    /* No point in doing anything if no payload
     */
    if( !MIN(len, available_length) )
        return 2;

    payload = tvb_new_subset_length_caplen(tvb, header_len, MIN(len,available_length), len);

    /* Potentially segmented I frame
     */
    if( (control & XDLC_I_MASK) == XDLC_I && reassemble_lapdm && !pinfo->flags.in_error_pkt )
    {
        fragment_head *fd_m = NULL;
        tvbuff_t *reassembled = NULL;
        uint32_t fragment_id;
        bool save_fragmented = pinfo->fragmented, add_frag;

        pinfo->fragmented = m;

        /* Rely on caller to provide a way to group fragments */
        fragment_id =  (conversation_get_id_from_elements(pinfo, CONVERSATION_GSMTAP, USE_LAST_ENDPOINT) << 4) | (sapi << 1) | pinfo->p2p_dir;

        if (!PINFO_FD_VISITED(pinfo)) {
            /* Check if new N(S) is equal to previous N(S) (to avoid adding retransmissions in reassembly table)
               As GUINT_TO_POINTER macro does not allow to differentiate NULL from 0, use 1-8 range instead of 0-7 */
            unsigned *p_last_n_s = (unsigned*)wmem_map_lookup(lapdm_last_n_s_map, GUINT_TO_POINTER(fragment_id));
            if (GPOINTER_TO_UINT(p_last_n_s) == (unsigned)(n_s+1)) {
                add_frag = false;
            } else {
                add_frag = true;
                wmem_map_insert(lapdm_last_n_s_map, GUINT_TO_POINTER(fragment_id), GUINT_TO_POINTER(n_s+1));
            }
        } else {
            add_frag = true;
        }

        if (add_frag) {
            /* This doesn't seem the best way of doing it as doesn't
            take N(S) into account, but N(S) isn't always 0 for
            the first fragment!
            */
            fd_m = fragment_add_seq_next (&lapdm_reassembly_table, payload, 0,
                                        pinfo,
                                        fragment_id, /* uint32_t ID for fragments belonging together */
                                        NULL,
                                        /*n_s uint32_t fragment sequence number */
                                        len, /* uint32_t fragment length */
                                        m); /* More fragments? */

            reassembled = process_reassembled_data(payload, 0, pinfo,
                                                "Reassembled LAPDm", fd_m, &lapdm_frag_items,
                                                NULL, lapdm_tree);

            /* Reassembled into this packet
            */
            if (fd_m && pinfo->num == fd_m->reassembled_in) {
                if (!dissector_try_uint(lapdm_sapi_dissector_table, sapi,
                                        reassembled, pinfo, tree))
                    call_data_dissector(reassembled, pinfo, tree);

                if (!PINFO_FD_VISITED(pinfo)) {
                    /* If reassembling is done, allow fragment_id reuse */
                    wmem_map_remove(lapdm_last_n_s_map, GUINT_TO_POINTER(fragment_id));
                }
            }
            else {
                col_append_str(pinfo->cinfo, COL_INFO, " (Fragment)");
                proto_tree_add_item(lapdm_tree, hf_lapdm_fragment_data, payload, 0, -1, ENC_NA);
            }
        }

        /* Now reset fragmentation information in pinfo
         */
        pinfo->fragmented = save_fragmented;
    }
    else if (hdr_type == LAPDM_HDR_FMT_B4)
    {
        /* B4 frames have no length octet at L2 level, but instead a L2 pseudo length octet
         * at L3.  We must call the proper dissector for decoding them */
        call_dissector(b4_info_handle, payload, pinfo, tree);
    }
    else
    {
        if (!PINFO_FD_VISITED(pinfo) && ((control & XDLC_S_U_MASK) == XDLC_U) && ((control & XDLC_U_MODIFIER_MASK) == XDLC_SABM)) {
            /* SABM frame; reset the last N(S) to an invalid value */
            uint32_t fragment_id = (conversation_get_id_from_elements(pinfo, CONVERSATION_GSMTAP, USE_LAST_ENDPOINT) << 4) | (sapi << 1) | pinfo->p2p_dir;
            wmem_map_insert(lapdm_last_n_s_map, GUINT_TO_POINTER(fragment_id), GUINT_TO_POINTER(0));
        }

        /* Whole packet
           If we have some data, try and dissect it (only happens for UI, SABM, UA or I frames)
        */
        if (!dissector_try_uint(lapdm_sapi_dissector_table, sapi,
                                payload, pinfo, tree))
            call_data_dissector(payload, pinfo, tree);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_lapdm(void)
{
    static hf_register_info hf[] = {

        { &hf_lapdm_address,
          { "Address Field", "lapdm.address_field", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_lapdm_ea,
          { "EA", "lapdm.ea", FT_UINT8, BASE_DEC, VALS(lapdm_ea_vals), LAPDM_EA,
            "Address field extension bit", HFILL }},

        { &hf_lapdm_cr,
          { "C/R", "lapdm.cr", FT_UINT8, BASE_DEC, NULL, LAPDM_CR,
            "Command/response field bit", HFILL }},

        { &hf_lapdm_lpd,
          { "LPD", "lapdm.lpd", FT_UINT8, BASE_DEC, VALS(lapdm_lpd_vals), LAPDM_LPD,
            "Link Protocol Discriminator", HFILL }},

        { &hf_lapdm_sapi,
          { "SAPI", "lapdm.sapi", FT_UINT8, BASE_DEC, VALS(lapdm_sapi_vals), LAPDM_SAPI,
            "Service access point identifier", HFILL }},

        { &hf_lapdm_control,
          { "Control Field", "lapdm.control_field", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_lapdm_n_r,
          { "N(R)", "lapdm.control.n_r", FT_UINT8, BASE_DEC,
            NULL, XDLC_N_R_MASK, NULL, HFILL }},

        { &hf_lapdm_n_s,
          { "N(S)", "lapdm.control.n_s", FT_UINT8, BASE_DEC,
            NULL, XDLC_N_S_MASK, NULL, HFILL }},

        { &hf_lapdm_p,
          { "Poll", "lapdm.control.p", FT_BOOLEAN, 8,
            NULL, XDLC_P_F, NULL, HFILL }},

        { &hf_lapdm_f,
          { "Final", "lapdm.control.f", FT_BOOLEAN, 8,
            NULL, XDLC_P_F, NULL, HFILL }},

        { &hf_lapdm_s_ftype,
          { "Supervisory frame type", "lapdm.control.s_ftype", FT_UINT8, BASE_HEX,
            VALS(stype_vals), XDLC_S_FTYPE_MASK, NULL, HFILL }},

        { &hf_lapdm_u_modifier_cmd,
          { "Command", "lapdm.control.u_modifier_cmd", FT_UINT8, BASE_HEX,
            VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK, NULL, HFILL }},

        { &hf_lapdm_u_modifier_resp,
          { "Response", "lapdm.control.u_modifier_resp", FT_UINT8, BASE_HEX,
            VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK, NULL, HFILL }},

        { &hf_lapdm_ftype_i,
          { "Frame type", "lapdm.control.ftype", FT_UINT8, BASE_HEX,
            VALS(ftype_vals), XDLC_I_MASK, NULL, HFILL }},

        { &hf_lapdm_ftype_s_u,
          { "Frame type", "lapdm.control.ftype", FT_UINT8, BASE_HEX,
            VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL }},

        { &hf_lapdm_length,
          { "Length Field", "lapdm.length_field", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_lapdm_el,
          { "EL", "lapdm.el", FT_UINT8, BASE_DEC,
            VALS(lapdm_el_vals), LAPDM_EL, "Length indicator field extension bit", HFILL }},

        { &hf_lapdm_m,
          { "M", "lapdm.m", FT_UINT8, BASE_DEC,
            VALS(lapdm_m_vals), LAPDM_M, "More data bit", HFILL }},

        { &hf_lapdm_len,
          { "Length", "lapdm.length", FT_UINT8, BASE_DEC,
            NULL, LAPDM_LEN, "Length indicator", HFILL }},

        /* Fragment reassembly
         */
        { &hf_lapdm_fragment_data,
          { "Fragment Data", "lapdm.fragment_data", FT_NONE, BASE_NONE,
            NULL, 0x00, NULL, HFILL }},

        { &hf_lapdm_fragments,
          { "Message fragments", "lapdm.fragments", FT_NONE, BASE_NONE,
            NULL, 0x00, "LAPDm Message fragments", HFILL }},

        { &hf_lapdm_fragment,
          { "Message fragment", "lapdm.fragment", FT_FRAMENUM, BASE_NONE,
            NULL, 0x00, "LAPDm Message fragment", HFILL }},

        { &hf_lapdm_fragment_overlap,
          { "Message fragment overlap", "lapdm.fragment.overlap", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "LAPDm Message fragment overlaps with other fragment(s)", HFILL }},

        { &hf_lapdm_fragment_overlap_conflicts,
          { "Message fragment overlapping with conflicting data", "lapdm.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "LAPDm Message fragment overlaps with conflicting data", HFILL }},

        { &hf_lapdm_fragment_multiple_tails,
          { "Message has multiple tail fragments", "lapdm.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "LAPDm Message fragment has multiple tail fragments", HFILL }},

        { &hf_lapdm_fragment_too_long_fragment,
          { "Message fragment too long", "lapdm.fragment.too_long_fragment", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "LAPDm Message fragment data goes beyond the packet end", HFILL }},

        { &hf_lapdm_fragment_error,
          { "Message defragmentation error", "lapdm.fragment.error", FT_FRAMENUM, BASE_NONE,
            NULL, 0x00, "LAPDm Message defragmentation error due to illegal fragments", HFILL }},

        { &hf_lapdm_fragment_count,
          { "Message fragment count", "lapdm.fragment.count", FT_UINT32, BASE_DEC,
            NULL, 0x00, NULL, HFILL }},

        { &hf_lapdm_reassembled_in,
          { "Reassembled in", "lapdm.reassembled.in", FT_FRAMENUM, BASE_NONE,
            NULL, 0x00, "LAPDm Message has been reassembled in this packet.", HFILL }},

        { &hf_lapdm_reassembled_length,
          { "Reassembled LAPDm length", "lapdm.reassembled.length", FT_UINT32, BASE_DEC,
            NULL, 0x00, "The total length of the reassembled payload", HFILL }}

    };
    static int *ett[] = {
        &ett_lapdm,
        &ett_lapdm_address,
        &ett_lapdm_control,
        &ett_lapdm_length,
        &ett_lapdm_fragment,
        &ett_lapdm_fragments
    };

    module_t *lapdm_module;

    proto_lapdm = proto_register_protocol("Link Access Procedure, Channel Dm (LAPDm)", "LAPDm", "lapdm");
    proto_register_field_array (proto_lapdm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("lapdm", dissect_lapdm, proto_lapdm);

    lapdm_sapi_dissector_table = register_dissector_table("lapdm.sapi", "LAPDm SAPI", proto_lapdm, FT_UINT8, BASE_DEC);

    lapdm_module = prefs_register_protocol(proto_lapdm, NULL);
    prefs_register_bool_preference(lapdm_module, "reassemble",
                                   "Reassemble fragmented LAPDm packets",
                                   "Whether the dissector should defragment LAPDm messages spanning multiple packets.",
                                   &reassemble_lapdm);

    lapdm_last_n_s_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);

    reassembly_table_register(&lapdm_reassembly_table,
                           &addresses_reassembly_table_functions);

    /* B4 frames have no length octet at L2 level, but instead a L2 pseudo length octet
     * at L3.  We must call the proper dissector for decoding them, and gsm_a_ccch supports
     * L2 pseudo length */
    b4_info_handle = find_dissector_add_dependency("gsm_a_ccch", proto_lapdm);
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
