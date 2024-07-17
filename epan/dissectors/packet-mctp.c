/* packet-mctp.c
 * Routines for Management Component Transport Protocol (MCTP) packet
 * disassembly
 * Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * MCTP is a datagram-based protocol for intra-platform communication,
 * typically between a management controller and system devices.
 *
 * MCTP is defined by DMTF standard DSP0236: https://www.dmtf.org/dsp/DSP0236
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/to_str.h>
#include "packet-mctp.h"
#include "packet-sll.h"

#define MCTP_MIN_LENGTH 5       /* 4-byte header, plus message type */

void proto_register_mctp(void);
void proto_reg_handoff_mctp(void);

static int proto_mctp;

static int hf_mctp_ver;
static int hf_mctp_dst;
static int hf_mctp_src;
static int hf_mctp_flags;
static int hf_mctp_flags_som;
static int hf_mctp_flags_eom;
static int hf_mctp_seq;
static int hf_mctp_tag;
static int hf_mctp_tag_to;
static int hf_mctp_tag_value;
static int hf_mctp_msg_ic;
static int hf_mctp_msg_type;

static int ett_mctp;
static int ett_mctp_fst;
static int ett_mctp_flags;
static int ett_mctp_tag;
static int ett_mctp_type;

static const true_false_string tfs_tag_to = { "Sender", "Receiver" };

static int hf_mctp_fragments;
static int hf_mctp_fragment;
static int hf_mctp_fragment_overlap;
static int hf_mctp_fragment_overlap_conflicts;
static int hf_mctp_fragment_multiple_tails;
static int hf_mctp_fragment_too_long_fragment;
static int hf_mctp_fragment_error;
static int hf_mctp_fragment_count;
static int hf_mctp_reassembled_in;
static int hf_mctp_reassembled_length;
static int hf_mctp_reassembled_data;

static int ett_mctp_fragment;
static int ett_mctp_fragments;

static const fragment_items mctp_frag_items = {
    /* Fragment subtrees */
    &ett_mctp_fragment,
    &ett_mctp_fragments,
    /* Fragment fields */
    &hf_mctp_fragments,
    &hf_mctp_fragment,
    &hf_mctp_fragment_overlap,
    &hf_mctp_fragment_overlap_conflicts,
    &hf_mctp_fragment_multiple_tails,
    &hf_mctp_fragment_too_long_fragment,
    &hf_mctp_fragment_error,
    &hf_mctp_fragment_count,
    /* "Reassembled in" field */
    &hf_mctp_reassembled_in,
    /* Reassembled length field */
    &hf_mctp_reassembled_length,
    &hf_mctp_reassembled_data,
    /* Tag */
    "Message fragments"
};

static const value_string flag_vals[] = {
    { 0x00, "none" },
    { 0x01, "EOM" },
    { 0x02, "SOM" },
    { 0x03, "SOM|EOM" },
    { 0x00, NULL },
};

static const value_string type_vals[] = {
    { MCTP_TYPE_CONTROL, "MCTP Control Protocol" },
    { MCTP_TYPE_PLDM, "PLDM" },
    { MCTP_TYPE_NCSI, "NC-SI" },
    { MCTP_TYPE_ETHERNET, "Ethernet" },
    { MCTP_TYPE_NVME, "NVMe-MI" },
    { 0, NULL },
};

static dissector_table_t mctp_dissector_table;
static dissector_table_t mctp_encap_dissector_table;
static reassembly_table mctp_reassembly_table;

static int
dissect_mctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_tree *mctp_tree, *fst_tree;
    unsigned len, ver, type, seq, fst;
    bool save_fragmented;
    proto_item *ti, *tti;
    tvbuff_t *next_tvb;
    uint8_t tag;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCTP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Check that the packet is long enough for it to belong to us. */
    len = tvb_reported_length(tvb);

    if (len < MCTP_MIN_LENGTH) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus length %u, minimum %u",
                     len, MCTP_MIN_LENGTH);
        return tvb_captured_length(tvb);
    }

    ver = tvb_get_bits8(tvb, 4, 4);
    if (ver != 1) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid version %u", ver);
        return tvb_captured_length(tvb);
    }

    /* Top-level protocol item & tree */
    ti = proto_tree_add_item(tree, proto_mctp, tvb, 0, 4, ENC_NA);
    mctp_tree = proto_item_add_subtree(ti, ett_mctp);

    set_address_tvb(&pinfo->dl_dst, AT_MCTP, 1, tvb, 1);
    set_address_tvb(&pinfo->dl_src, AT_MCTP, 1, tvb, 2);
    copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
    copy_address_shallow(&pinfo->src, &pinfo->dl_src);

    proto_item_append_text(ti, " Dst: %s, Src %s",
            address_to_str(pinfo->pool, &pinfo->dst),
            address_to_str(pinfo->pool, &pinfo->src));

    /* Standard header fields */
    proto_tree_add_item(mctp_tree, hf_mctp_ver, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(mctp_tree, hf_mctp_dst, tvb, 1, 1, ENC_NA);
    proto_tree_add_item(mctp_tree, hf_mctp_src, tvb, 2, 1, ENC_NA);

    static int * const mctp_flags[] = {
        &hf_mctp_flags_som,
        &hf_mctp_flags_eom,
        NULL
    };

    static int * const mctp_tag[] = {
        &hf_mctp_tag_to,
        &hf_mctp_tag_value,
        NULL,
    };

    fst = tvb_get_uint8(tvb, 3);
    tag = fst & 0x0f;
    fst_tree = proto_tree_add_subtree_format(mctp_tree, tvb, 3, 1, ett_mctp_fst,
                                      &tti, "Flags %s, seq %d, tag %s%d",
                                      val_to_str_const(fst >> 6, flag_vals, ""),
                                      fst >> 4 & 0x3,
                                      fst & 0x08 ? "TO:" : "",
                                      fst & 0x7);
    proto_tree_add_bitmask(fst_tree, tvb, 3, hf_mctp_flags,
                           ett_mctp_flags, mctp_flags, ENC_NA);
    proto_tree_add_item_ret_uint(fst_tree, hf_mctp_seq, tvb, 3, 1, ENC_NA, &seq);
    proto_tree_add_bitmask_with_flags(fst_tree, tvb, 3, hf_mctp_tag,
                           ett_mctp_tag, mctp_tag, ENC_NA, BMT_NO_FLAGS);

    /* use the tags as our port numbers */
    pinfo->ptype = PT_MCTP;
    pinfo->srcport = tag;
    pinfo->destport = tag ^ 0x08; /* flip tag-owner bit */

    save_fragmented = pinfo->fragmented;

    col_set_str(pinfo->cinfo, COL_INFO, "MCTP message");

    /* if we're not both the start and end of a message, handle as a
     * fragment */
    if ((fst & 0xc0) != 0xc0) {
        fragment_head *frag_msg = NULL;
        tvbuff_t *new_tvb = NULL;

        pinfo->fragmented = true;
        frag_msg = fragment_add_seq_next(&mctp_reassembly_table,
                                         tvb, 4, pinfo,
                                         fst & 0x7, NULL,
                                         tvb_captured_length_remaining(tvb, 4),
                                         !(fst & 0x40));

        new_tvb = process_reassembled_data(tvb, 4, pinfo,
                                           "reassembled Message",
                                           frag_msg, &mctp_frag_items,
                                           NULL, mctp_tree);

        if (fst & 0x40)
            col_append_str(pinfo->cinfo, COL_INFO, " reassembled");
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, " frag %u", seq);

        next_tvb = new_tvb;
    } else {
        next_tvb = tvb_new_subset_remaining(tvb, 4);
    }

    if (next_tvb) {
        proto_tree *type_tree;
        int rc;

        type = tvb_get_uint8(next_tvb, 0);
        type_tree = proto_tree_add_subtree_format(mctp_tree, next_tvb, 0, 1,
                                                  ett_mctp_type,
                                                  &tti, "Type: %s (0x%x)%s",
                                                  val_to_str_const(type & 0x7f,
                                                                   type_vals,
                                                                   "unknown"),
                                                  type & 0x7f,
                                                  type & 0x80 ? " + IC" : "");

        proto_tree_add_item(type_tree, hf_mctp_msg_type, next_tvb, 0, 1,
                            ENC_NA);
        proto_tree_add_item(type_tree, hf_mctp_msg_ic, next_tvb, 0, 1,
                            ENC_NA);

        rc = dissector_try_uint_new(mctp_dissector_table, type & 0x7f,
                                    next_tvb, pinfo, tree, true, NULL);

        if (!rc && !(type & 0x80)) {
            tvbuff_t *encap_tvb = tvb_new_subset_remaining(next_tvb, 1);
            dissector_try_uint_new(mctp_encap_dissector_table, type,
                                   encap_tvb, pinfo, tree, true, NULL);
        }
    }

    pinfo->fragmented = save_fragmented;

    return tvb_captured_length(tvb);
}

void
proto_register_mctp(void)
{
    /* *INDENT-OFF* */
    /* Field definitions */
    static hf_register_info hf[] = {
        { &hf_mctp_ver,
          { "Version", "mctp.version",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL },
        },
        { &hf_mctp_dst,
          { "Destination", "mctp.dst",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL },
        },
        { &hf_mctp_src,
          { "Source", "mctp.src",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL },
        },
        { &hf_mctp_flags,
          { "Flags", "mctp.flags",
            FT_UINT8, BASE_HEX, NULL, 0xc0,
            NULL, HFILL },
        },
        { &hf_mctp_flags_som,
          { "Start of message", "mctp.flags.som",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
            NULL, HFILL },
        },
        { &hf_mctp_flags_eom,
          { "End of message", "mctp.flags.eom",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            NULL, HFILL },
        },
        { &hf_mctp_seq,
          { "Sequence", "mctp.seq",
            FT_UINT8, BASE_HEX, NULL, 0x30,
            NULL, HFILL },
        },
        { &hf_mctp_tag,
          { "Tag", "mctp.tag",
            FT_UINT8, BASE_HEX, NULL, 0x0f,
            NULL, HFILL },
        },
        { &hf_mctp_tag_to,
          { "Tag owner", "mctp.tag.to",
            FT_BOOLEAN, 8, TFS(&tfs_tag_to), 0x08,
            NULL, HFILL },
        },
        { &hf_mctp_tag_value,
          { "Tag value", "mctp.tag.value",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL },
        },

        /* message header */
        { &hf_mctp_msg_ic,
          { "Integrity check", "mctp.msg.ic",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x80,
            NULL, HFILL },
        },
        { &hf_mctp_msg_type,
          { "Message type", "mctp.msg.type",
            FT_UINT8, BASE_HEX, VALS(type_vals), 0x7f,
            NULL, HFILL },
        },

        /* generic fragmentation */
        {&hf_mctp_fragments,
            {"Message fragments", "mctp.fragments",
                FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment,
            {"Message fragment", "mctp.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_overlap,
            {"Message fragment overlap", "mctp.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_overlap_conflicts,
            {"Message fragment overlapping with conflicting data",
                "mctp.fragment.overlap.conflicts",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_multiple_tails,
            {"Message has multiple tail fragments",
                "mctp.fragment.multiple_tails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_too_long_fragment,
            {"Message fragment too long", "mctp.fragment.too_long_fragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_error,
            {"Message defragmentation error", "mctp.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_count,
            {"Message fragment count", "mctp.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_reassembled_in,
            {"Reassembled in", "mctp.reassembled.in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_reassembled_length,
            {"Reassembled length", "mctp.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_reassembled_data,
            {"Reassembled data", "mctp.reassembled.data",
                FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL } },
    };

    /* protocol subtree */
    static int *ett[] = {
        &ett_mctp,
        &ett_mctp_flags,
        &ett_mctp_fst,
        &ett_mctp_tag,
        &ett_mctp_type,
        &ett_mctp_fragment,
        &ett_mctp_fragments,
    };

    /* Register the protocol name and description */
    proto_mctp = proto_register_protocol("MCTP", "MCTP", "mctp");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_mctp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* We have two dissector tables here, both keyed off the type byte, but
     * with different decode semantics:
     *
     * mctp.type: for protocols that are "MCTP-aware" - they perform their
     *    own decoding of the type byte, including the IC bit, and possibly the
     *    message integrity check (which is type-specific!). For example,
     *    NVMe-MI, which includes the type byte in packet specifications
     *
     * mctp.encap-type: for procotols that are trivially encapsulated in a
     *    MCTP message, and do not handle the type byte themselves. For
     *    example, NC-SI over MCTP, which just wraps a NC-SI packet within
     *    a MCTP message.
     *
     * it doesn't make sense to allow encap-type decoders to also have the IC
     * bit set, as there is no specification for what format the message
     * integrity check is in. So, we disallow the IC bit in the type field
     * for those dissectors.
     */
    mctp_dissector_table = register_dissector_table("mctp.type", "MCTP type",
                                                    proto_mctp, FT_UINT8,
                                                    BASE_HEX);
    mctp_encap_dissector_table = register_dissector_table("mctp.encap-type",
                                                          "MCTP encapsulated type",
                                                          proto_mctp, FT_UINT8,
                                                          BASE_HEX);

    reassembly_table_register(&mctp_reassembly_table,
                              &addresses_reassembly_table_functions);
}

void
proto_reg_handoff_mctp(void)
{
    dissector_handle_t mctp_handle;
    mctp_handle = create_dissector_handle(dissect_mctp, proto_mctp);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_MCTP, mctp_handle);
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
