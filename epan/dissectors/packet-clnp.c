/* packet-clnp.c
 * Routines for ISO/OSI network protocol packet disassembly
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 * Ralf Schneider <Ralf.Schneider@t-online.de>
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
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/nlpid.h>

#include "packet-osi.h"
#include "packet-osi-options.h"

void proto_register_clnp(void);
void proto_reg_handoff_clnp(void);

/* protocols and fields */

static int  proto_clnp;
static int ett_clnp;
static int ett_clnp_type;
static int ett_clnp_segments;
static int ett_clnp_segment;
static int ett_clnp_disc_pdu;

static int hf_clnp_id;
static int hf_clnp_length;
static int hf_clnp_version;
static int hf_clnp_ttl;
static int hf_clnp_type;
static int hf_clnp_cnf_segmentation;
static int hf_clnp_cnf_more_segments;
static int hf_clnp_cnf_report_error;
static int hf_clnp_cnf_type;
static int hf_clnp_pdu_length;
static int hf_clnp_data_unit_identifier;
static int hf_clnp_segment_offset;
static int hf_clnp_total_length;
static int hf_clnp_checksum;
static int hf_clnp_checksum_status;
static int hf_clnp_dest_length;
static int hf_clnp_dest;
static int hf_clnp_src_length;
static int hf_clnp_src;
static int hf_clnp_segments;
static int hf_clnp_segment;
static int hf_clnp_segment_overlap;
static int hf_clnp_segment_overlap_conflict;
static int hf_clnp_segment_multiple_tails;
static int hf_clnp_segment_too_long_segment;
static int hf_clnp_segment_error;
static int hf_clnp_segment_count;
static int hf_clnp_reassembled_in;
static int hf_clnp_reassembled_length;

static const fragment_items clnp_frag_items = {
    &ett_clnp_segment,
    &ett_clnp_segments,
    &hf_clnp_segments,
    &hf_clnp_segment,
    &hf_clnp_segment_overlap,
    &hf_clnp_segment_overlap_conflict,
    &hf_clnp_segment_multiple_tails,
    &hf_clnp_segment_too_long_segment,
    &hf_clnp_segment_error,
    &hf_clnp_segment_count,
    &hf_clnp_reassembled_in,
    &hf_clnp_reassembled_length,
    /* Reassembled data field */
    NULL,
    "segments"
};

static expert_field ei_clnp_length;
static expert_field ei_clnp_checksum;

static dissector_handle_t clnp_handle;
static dissector_handle_t ositp_handle;
static dissector_handle_t ositp_inactive_handle;
static dissector_handle_t idrp_handle;

/*
 * ISO 8473 OSI CLNP definition (see RFC994)
 *
 *            _________________________________
 *           |           Fixed Part            |
 *           |_________________________________|
 *           |          Address Part           |
 *           |_________________________________|
 *           |   Segmentation Part (optional)  |
 *           |_________________________________|
 *           |     Options Part (optional)     |
 *           |_________________________________|
 *           |         Data (optional)         |
 *           |_________________________________|
 */

#define ISO8473_V1  0x01    /* CLNP version 1 */

/* Fixed part */

/* Length of fixed part */
#define FIXED_PART_LEN          9

#define CNF_TYPE                0x1f
#define CNF_ERR_OK              0x20
#define CNF_MORE_SEGS           0x40
#define CNF_SEG_OK              0x80

#define DT_NPDU                 0x1C
#define MD_NPDU                 0x1D
#define ER_NPDU                 0x01
#define ERQ_NPDU                0x1E
#define ERP_NPDU                0x1F

static const value_string npdu_type_abbrev_vals[] = {
    { DT_NPDU,    "DT" },
    { MD_NPDU,    "MD" },
    { ER_NPDU,    "ER" },
    { ERQ_NPDU,   "ERQ" },
    { ERP_NPDU,   "ERP" },
    { 0,          NULL }
};

static const value_string npdu_type_vals[] = {
    { DT_NPDU,    "Data" },
    { MD_NPDU,    "Multicast Data" },
    { ER_NPDU,    "Error Report" },
    { ERQ_NPDU,   "Echo Request" },
    { ERP_NPDU,   "Echo Response" },
    { 0,          NULL }
};

/* field position */

#define P_CLNP_PROTO_ID         0
#define P_CLNP_HDR_LEN          1
#define P_CLNP_VERS             2
#define P_CLNP_TTL              3
#define P_CLNP_TYPE             4
#define P_CLNP_SEGLEN           5
#define P_CLNP_CKSUM            7
#define P_CLNP_ADDRESS_PART     9

/* Segmentation part */

#define SEGMENTATION_PART_LEN   6

struct clnp_segment {
    gushort       cng_id;         /* data unit identifier */
    gushort       cng_off;        /* segment offset */
    gushort       cng_tot_len;    /* total length */
};

/* NSAP selector */

#define NSEL_NET                0x00
#define NSEL_NP                 0x20
#define NSEL_TP                 0x21

/* global variables */

/* List of dissectors to call for CLNP packets */
static heur_dissector_list_t clnp_heur_subdissector_list;

/*
 * Reassembly of CLNP.
 */
static reassembly_table clnp_reassembly_table;

/* options */
static unsigned tp_nsap_selector = NSEL_TP;
static bool always_decode_transport;
static bool clnp_reassemble = true;

/* function definitions */

/*
 *  CLNP part / main entry point
*/

static int
dissect_clnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree     *clnp_tree;
    proto_item     *ti, *ti_len = NULL, *ti_pdu_len = NULL, *ti_tot_len = NULL;
    uint8_t         cnf_proto_id;
    uint8_t         cnf_hdr_len;
    uint8_t         cnf_vers;
    uint8_t         cnf_ttl;
    uint8_t         cnf_type;
    char            flag_string[6+1];
    const char     *pdu_type_string;
    proto_tree     *type_tree;
    uint16_t        segment_length;
    uint16_t        du_id = 0;
    uint16_t        segment_offset = 0;
    uint16_t        total_length;
    uint16_t        cnf_cksum;
    bool            cksum_valid = true;
    int             offset;
    unsigned char   src_len, dst_len, nsel, opt_len = 0;
    unsigned        next_length;
    proto_tree     *discpdu_tree;
    bool            save_in_error_pkt;
    fragment_head  *fd_head;
    tvbuff_t       *next_tvb;
    bool            update_col_info = true;
    bool            save_fragmented;
    heur_dtbl_entry_t *hdtbl_entry;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CLNP");
    col_clear(pinfo->cinfo, COL_INFO);

    cnf_proto_id = tvb_get_uint8(tvb, P_CLNP_PROTO_ID);
    if (cnf_proto_id == NLPID_NULL) {
        col_set_str(pinfo->cinfo, COL_INFO, "Inactive subset");
        ti = proto_tree_add_item(tree, proto_clnp, tvb, P_CLNP_PROTO_ID, 1, ENC_NA);
        clnp_tree = proto_item_add_subtree(ti, ett_clnp);
        proto_tree_add_uint_format(clnp_tree, hf_clnp_id, tvb, P_CLNP_PROTO_ID, 1,
                cnf_proto_id, "Inactive subset");
        next_tvb = tvb_new_subset_remaining(tvb, 1);
        call_dissector(ositp_inactive_handle, next_tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    /* return if version not known */
    cnf_vers = tvb_get_uint8(tvb, P_CLNP_VERS);
    if (cnf_vers != ISO8473_V1) {
        call_data_dissector(tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    /* fixed part decoding */
    cnf_hdr_len = tvb_get_uint8(tvb, P_CLNP_HDR_LEN);

    ti = proto_tree_add_item(tree, proto_clnp, tvb, 0, cnf_hdr_len, ENC_NA);
    clnp_tree = proto_item_add_subtree(ti, ett_clnp);
    proto_tree_add_uint(clnp_tree, hf_clnp_id, tvb, P_CLNP_PROTO_ID, 1,
            cnf_proto_id);
    ti_len = proto_tree_add_uint(clnp_tree, hf_clnp_length, tvb, P_CLNP_HDR_LEN, 1,
            cnf_hdr_len);
    if (cnf_hdr_len < FIXED_PART_LEN) {
        /* Header length is less than the length of the fixed part of
           the header. */
        expert_add_info_format(pinfo, ti_len, &ei_clnp_length,
                "Header length value < minimum length %u",
                FIXED_PART_LEN);
        return 2;
    }
    proto_tree_add_uint(clnp_tree, hf_clnp_version, tvb, P_CLNP_VERS, 1,
                cnf_vers);
    cnf_ttl = tvb_get_uint8(tvb, P_CLNP_TTL);
    proto_tree_add_uint_format(clnp_tree, hf_clnp_ttl, tvb, P_CLNP_TTL, 1,
            cnf_ttl,
            "Holding Time : %u (%u.%u secs)",
            cnf_ttl, cnf_ttl / 2, (cnf_ttl % 2) * 5);
    cnf_type = tvb_get_uint8(tvb, P_CLNP_TYPE);
    pdu_type_string = val_to_str(cnf_type & CNF_TYPE, npdu_type_abbrev_vals,
            "Unknown (0x%02x)");
    flag_string[0] = '\0';
    if (cnf_type & CNF_SEG_OK)
        (void) g_strlcat(flag_string, "S ", 7);
    if (cnf_type & CNF_MORE_SEGS)
        (void) g_strlcat(flag_string, "M ", 7);
    if (cnf_type & CNF_ERR_OK)
        (void) g_strlcat(flag_string, "E ", 7);
    ti = proto_tree_add_uint_format(clnp_tree, hf_clnp_type, tvb, P_CLNP_TYPE, 1,
            cnf_type,
            "PDU Type     : 0x%02x (%s%s)",
            cnf_type,
            flag_string,
            pdu_type_string);
    type_tree = proto_item_add_subtree(ti, ett_clnp_type);
    proto_tree_add_item(type_tree, hf_clnp_cnf_segmentation, tvb, P_CLNP_TYPE, 1, ENC_NA);
    proto_tree_add_item(type_tree, hf_clnp_cnf_more_segments, tvb, P_CLNP_TYPE, 1, ENC_NA);
    proto_tree_add_item(type_tree, hf_clnp_cnf_report_error, tvb, P_CLNP_TYPE, 1, ENC_NA);
    proto_tree_add_item(type_tree, hf_clnp_cnf_type, tvb, P_CLNP_TYPE, 1, ENC_BIG_ENDIAN);

    /* If we don't have the full header - i.e., not enough to see the
       segmentation part and determine whether this datagram is segmented
       or not - set the Info column now; we'll get an exception before
       we set it otherwise. */

    if (tvb_reported_length(tvb) < cnf_hdr_len) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
    }

    segment_length = tvb_get_ntohs(tvb, P_CLNP_SEGLEN);
    ti_pdu_len = proto_tree_add_uint(clnp_tree, hf_clnp_pdu_length, tvb, P_CLNP_SEGLEN, 2,
            segment_length);
    if (segment_length < cnf_hdr_len) {
        /* Segment length is less than the header length. */
        expert_add_info_format(pinfo, ti_pdu_len, &ei_clnp_length,
                "PDU length < header length %u", cnf_hdr_len);
        return 7;
    }
    cnf_cksum = tvb_get_ntohs(tvb, P_CLNP_CKSUM);
    if (cnf_cksum == 0) {
        /* No checksum present */
        proto_tree_add_checksum(clnp_tree, tvb, P_CLNP_CKSUM, hf_clnp_checksum, hf_clnp_checksum_status, &ei_clnp_checksum, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NOT_PRESENT);
    } else {
        uint32_t c0 = 0, c1 = 0;

        if (osi_calc_checksum(tvb, 0, cnf_hdr_len, &c0, &c1)) {
            /* Successfully processed checksum, verify it */
            proto_tree_add_checksum(clnp_tree, tvb, P_CLNP_CKSUM, hf_clnp_checksum, hf_clnp_checksum_status, &ei_clnp_checksum, pinfo, c0 | c1, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_ZERO);
            cksum_valid = (c0 | c1) ? false : true;
        } else {
            proto_tree_add_checksum(clnp_tree, tvb, P_CLNP_CKSUM, hf_clnp_checksum, hf_clnp_checksum_status, &ei_clnp_checksum, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
        }
    }

    opt_len = cnf_hdr_len;
    opt_len -= FIXED_PART_LEN; /* Fixed part of Header */

    /* address part */

    offset = P_CLNP_ADDRESS_PART;
    if (opt_len < 1) {
        /* Header length is less than the minimum value in CLNP,
           including the destination address length. */
        expert_add_info_format(pinfo, ti_len, &ei_clnp_length,
                "Header length value < %u",
                FIXED_PART_LEN + 1);
        return offset;
    }
    dst_len  = tvb_get_uint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(clnp_tree, hf_clnp_dest_length, tvb, offset, 1,
                dst_len);
    }
    offset += 1;
    opt_len -= 1;

    if (opt_len < dst_len) {
        /* Header length is less than the minimum value,
           including the destination address length and the
           destination address. */
        expert_add_info_format(pinfo, ti_len, &ei_clnp_length,
                "Header length value < %u",
                FIXED_PART_LEN + 1 + dst_len);
        return offset;
    }
    nsel     = tvb_get_uint8(tvb, offset + dst_len - 1);
    set_address_tvb(&pinfo->net_dst, get_osi_address_type(), dst_len, tvb, offset);
    copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
    proto_tree_add_bytes_format_value(clnp_tree, hf_clnp_dest, tvb, offset, dst_len,
            NULL,
            "%s",
            print_nsap_net(pinfo->pool, tvb, offset, dst_len));
    offset += dst_len;
    opt_len -= dst_len;

    if (opt_len < 1) {
        /* Header length is less than the minimum value,
           including the destination address length, the
           destination address, and the source address length. */
        expert_add_info_format(pinfo, ti_len, &ei_clnp_length,
                "Header length value < %u",
                FIXED_PART_LEN + 1 + dst_len + 1);
        return offset;
    }
    src_len  = tvb_get_uint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(clnp_tree, hf_clnp_src_length, tvb,
                offset, 1, src_len);
    }
    offset += 1;
    opt_len -= 1;

    if (opt_len < src_len) {
        /* Header length is less than the minimum value,
           including the destination address length, the
           destination address, the source address length,
           and the source address. */
        expert_add_info_format(pinfo, ti_len, &ei_clnp_length,
                "Header length value < %u",
                FIXED_PART_LEN + 1 + dst_len + 1 + src_len);
        return offset;
    }
    set_address_tvb(&pinfo->net_src, get_osi_address_type(), src_len, tvb, offset);
    copy_address_shallow(&pinfo->src, &pinfo->net_src);
    proto_tree_add_bytes_format_value(clnp_tree, hf_clnp_src, tvb, offset, src_len,
            NULL,
            "%s",
            print_nsap_net(pinfo->pool, tvb, offset, src_len));
    offset += src_len;
    opt_len -= src_len;

    /* Segmentation Part */

    if (cnf_type & CNF_SEG_OK) {
        if (opt_len < SEGMENTATION_PART_LEN) {
            /* Header length is less than the minimum value,
               including the destination address length, the
               destination address, the source address length,
               the source address, and the segmentation part. */
            expert_add_info_format(pinfo, ti_len, &ei_clnp_length,
                    "Header length value < %u",
                    FIXED_PART_LEN + 1 + dst_len + 1 + SEGMENTATION_PART_LEN);
            return offset;
        }

        du_id = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(clnp_tree, hf_clnp_data_unit_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
        segment_offset = tvb_get_ntohs(tvb, offset + 2);
        proto_tree_add_item(clnp_tree, hf_clnp_segment_offset, tvb, offset + 2 , 2, ENC_BIG_ENDIAN);
        total_length = tvb_get_ntohs(tvb, offset + 4);
        ti_tot_len = proto_tree_add_item(clnp_tree, hf_clnp_total_length, tvb, offset + 4 , 2, ENC_BIG_ENDIAN);
        if (total_length < segment_length) {
            /* Reassembled length is less than the length of this segment. */
            expert_add_info_format(pinfo, ti_tot_len, &ei_clnp_length,
                    "Total length < segment length %u", segment_length);
            return offset;
        }
        offset  += SEGMENTATION_PART_LEN;
        opt_len -= SEGMENTATION_PART_LEN;
    }

    dissect_osi_options(opt_len, tvb, offset, clnp_tree, pinfo);

    offset += opt_len;

    /* If clnp_reassemble is on, this is a segment, we have all the
     * data in the segment, and the checksum is valid, then just add the
     * segment to the hashtable.
     */
    save_fragmented = pinfo->fragmented;
    if (clnp_reassemble && (cnf_type & CNF_SEG_OK) &&
            ((cnf_type & CNF_MORE_SEGS) || segment_offset != 0) &&
            tvb_bytes_exist(tvb, offset, segment_length - cnf_hdr_len) &&
            segment_length > cnf_hdr_len &&
            cksum_valid != false) {
        fd_head = fragment_add_check(&clnp_reassembly_table,
                tvb, offset, pinfo, du_id, NULL,
                segment_offset, segment_length - cnf_hdr_len,
                cnf_type & CNF_MORE_SEGS);

        next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled CLNP",
                fd_head, &clnp_frag_items, &update_col_info, clnp_tree);
    } else {
        /* If this is the first segment, dissect its contents, otherwise
           just show it as a segment.

           XXX - if we eventually don't save the reassembled contents of all
           segmented datagrams, we may want to always reassemble. */
        if ((cnf_type & CNF_SEG_OK) && segment_offset != 0) {
            /* Not the first segment - don't dissect it. */
            next_tvb = NULL;
        } else {
            /* First segment, or not segmented.  Dissect what we have here. */

            /* Get a tvbuff for the payload.  Set its length to the segment
               length, and flag it as a fragment, so going past the end
               reports FragmentBoundsError, i.e. "there's data missing
               because this isn't reassembled", not ReportedBoundsError,
               i.e. "the dissector ran past the end of the packet, so the
               packet must not have been constructed properly". */
            next_tvb = tvb_new_subset_length(tvb, offset, segment_length - cnf_hdr_len);
            tvb_set_fragment(next_tvb);

            /*
             * If this is the first segment, but not the only segment,
             * tell the next protocol that.
             */
            if ((cnf_type & (CNF_SEG_OK|CNF_MORE_SEGS)) == (CNF_SEG_OK|CNF_MORE_SEGS))
                pinfo->fragmented = true;
            else
                pinfo->fragmented = false;
        }
    }

    if (next_tvb == NULL) {
        /* Just show this as a segment. */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Fragmented %s NPDU %s(off=%u)",
                pdu_type_string, flag_string, segment_offset);

        /* As we haven't reassembled anything, we haven't changed "pi", so
           we don't have to restore it. */
        call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
        pinfo->fragmented = save_fragmented;
        return tvb_captured_length(tvb);
    }

    if (tvb_offset_exists(tvb, offset)) {
        switch (cnf_type & CNF_TYPE) {

            case DT_NPDU:
            case MD_NPDU:
                /* Continue with COTP if any data.
                   XXX - if this isn't the first Derived PDU of a segmented Initial
                   PDU, skip that? */

                if (nsel==NSEL_NET && tvb_get_uint8(next_tvb, 0)==NLPID_ISO10747_IDRP) {
                    if(call_dissector(idrp_handle, next_tvb, pinfo, tree) != 0) {
                        pinfo->fragmented = save_fragmented;
                        return tvb_captured_length(tvb);
                    }
                }
                if (nsel == (unsigned char)tp_nsap_selector || always_decode_transport) {
                    if (call_dissector(ositp_handle, next_tvb, pinfo, tree) != 0) {
                        pinfo->fragmented = save_fragmented;
                        return tvb_captured_length(tvb);       /* yes, it appears to be COTP or CLTP */
                    }
                }
                if (dissector_try_heuristic(clnp_heur_subdissector_list, next_tvb,
                            pinfo, tree, &hdtbl_entry, NULL)) {
                    pinfo->fragmented = save_fragmented;
                    return tvb_captured_length(tvb);       /* yes, it appears to be one of the protocols in the heuristic list */
                }

                break;

            case ER_NPDU:
                /* The payload is the header and "none, some, or all of the data
                   part of the discarded PDU", i.e. it's like an ICMP error;
                   dissect it as a CLNP PDU. */

                col_add_fstr(pinfo->cinfo, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
                next_length = tvb_reported_length_remaining(tvb, offset);
                if (next_length != 0) {
                    /* We have payload; dissect it. */
                    discpdu_tree = proto_tree_add_subtree(clnp_tree, tvb, offset, next_length,
                            ett_clnp_disc_pdu, NULL, "Discarded PDU");

                    /* Save the current value of the "we're inside an error packet"
                       flag, and set that flag; subdissectors may treat packets
                       that are the payload of error packets differently from
                       "real" packets. */
                    save_in_error_pkt = pinfo->flags.in_error_pkt;
                    pinfo->flags.in_error_pkt = true;

                    call_dissector(clnp_handle, next_tvb, pinfo, discpdu_tree);

                    /* Restore the "we're inside an error packet" flag. */
                    pinfo->flags.in_error_pkt = save_in_error_pkt;
                }
                pinfo->fragmented = save_fragmented;
                return tvb_captured_length(tvb);   /* we're done with this PDU */

            case ERQ_NPDU:
            case ERP_NPDU:
                /* XXX - dissect this */
                break;
        }
    }
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
    call_data_dissector(next_tvb, pinfo, tree);
    pinfo->fragmented = save_fragmented;
    return tvb_captured_length(tvb);
} /* dissect_clnp */

void
proto_register_clnp(void)
{
    static hf_register_info hf[] = {
        { &hf_clnp_id,
            { "Network Layer Protocol Identifier", "clnp.nlpi", FT_UINT8, BASE_HEX,
                VALS(nlpid_vals), 0x0, NULL, HFILL }},

        { &hf_clnp_length,
            { "HDR Length", "clnp.len",          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_version,
            { "Version", "clnp.version",  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_ttl,
            { "Holding Time", "clnp.ttl",        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_type,
            { "PDU Type", "clnp.type",     FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_cnf_segmentation,
            { "Segmentation permitted", "clnp.cnf.segmentation", FT_BOOLEAN, 8, TFS(&tfs_yes_no), CNF_SEG_OK, NULL, HFILL }},

        { &hf_clnp_cnf_more_segments,
            { "More segments", "clnp.cnf.more_segments", FT_BOOLEAN, 8, TFS(&tfs_yes_no), CNF_MORE_SEGS, NULL, HFILL }},

        { &hf_clnp_cnf_report_error,
            { "Report error if PDU discarded", "clnp.cnf.report_error", FT_BOOLEAN, 8, TFS(&tfs_yes_no), CNF_ERR_OK, NULL, HFILL }},

        { &hf_clnp_cnf_type,
            { "Type", "clnp.cnf.type", FT_UINT8, BASE_DEC, VALS(npdu_type_vals), CNF_TYPE, NULL, HFILL }},

        { &hf_clnp_pdu_length,
            { "PDU length", "clnp.pdu.len",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_data_unit_identifier,
            { "Data unit identifier", "clnp.data_unit_identifier",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_segment_offset,
            { "Segment offset", "clnp.segment_offset",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_total_length,
            { "Total length", "clnp.total_length",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_checksum,
            { "Checksum", "clnp.checksum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_checksum_status,
            { "Checksum Status", "clnp.checksum.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL }},

        { &hf_clnp_dest_length,
            { "DAL", "clnp.dsap.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_dest,
            { "DA", "clnp.dsap",     FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_src_length,
            { "SAL", "clnp.ssap.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_src,
            { "SA", "clnp.ssap",     FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_clnp_segment_overlap,
            { "Segment overlap", "clnp.segment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Segment overlaps with other segments", HFILL }},

        { &hf_clnp_segment_overlap_conflict,
            { "Conflicting data in segment overlap", "clnp.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping segments contained conflicting data", HFILL }},

        { &hf_clnp_segment_multiple_tails,
            { "Multiple tail segments found", "clnp.segment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when reassembling the packet", HFILL }},

        { &hf_clnp_segment_too_long_segment,
            { "Segment too long", "clnp.segment.toolongsegment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Segment contained data past end of packet", HFILL }},

        { &hf_clnp_segment_error,
            { "Reassembly error", "clnp.segment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Reassembly error due to illegal segments", HFILL }},

        { &hf_clnp_segment_count,
            { "Segment count", "clnp.segment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_clnp_segment,
            { "CLNP Segment", "clnp.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_clnp_segments,
            { "CLNP Segments", "clnp.segments", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_clnp_reassembled_in,
            { "Reassembled CLNP in frame", "clnp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "This CLNP packet is reassembled in this frame", HFILL }},

        { &hf_clnp_reassembled_length,
            { "Reassembled CLNP length", "clnp.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }}
    };
    static int *ett[] = {
        &ett_clnp,
        &ett_clnp_type,
        &ett_clnp_segments,
        &ett_clnp_segment,
        &ett_clnp_disc_pdu,
    };

    static ei_register_info ei[] = {
        { &ei_clnp_length, { "clnp.len.bad", PI_MALFORMED, PI_ERROR, "Header length value bad", EXPFILL }},
        { &ei_clnp_checksum, { "clnp.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    };

    module_t *clnp_module;
    expert_module_t* expert_clnp;

    proto_clnp = proto_register_protocol(PROTO_STRING_CLNP, "CLNP", "clnp");
    proto_register_field_array(proto_clnp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_clnp = expert_register_protocol(proto_clnp);
    expert_register_field_array(expert_clnp, ei, array_length(ei));
    clnp_handle = register_dissector("clnp", dissect_clnp, proto_clnp);
    clnp_heur_subdissector_list = register_heur_dissector_list_with_description("clnp", "CLNP DT/MD payload", proto_clnp);

    reassembly_table_register(&clnp_reassembly_table,
            &addresses_reassembly_table_functions);

    register_osi_address_type();

    clnp_module = prefs_register_protocol(proto_clnp, NULL);
    prefs_register_uint_preference(clnp_module, "tp_nsap_selector",
            "NSAP selector for Transport Protocol (last byte in hex)",
            "NSAP selector for Transport Protocol (last byte in hex)",
            16, &tp_nsap_selector);
    prefs_register_bool_preference(clnp_module, "always_decode_transport",
            "Always try to decode NSDU as transport PDUs",
            "Always try to decode NSDU as transport PDUs",
            &always_decode_transport);
    prefs_register_bool_preference(clnp_module, "reassemble",
            "Reassemble segmented CLNP datagrams",
            "Whether segmented CLNP datagrams should be reassembled",
            &clnp_reassemble);
    /* XXX - catch this and tweak the decode_as settings? */
    prefs_register_obsolete_preference(clnp_module, "decode_atn_options");
}

void
proto_reg_handoff_clnp(void)
{
    ositp_handle = find_dissector_add_dependency("ositp", proto_clnp);
    ositp_inactive_handle = find_dissector_add_dependency("ositp_inactive", proto_clnp);
    idrp_handle = find_dissector_add_dependency("idrp", proto_clnp);

    dissector_add_uint("osinl.incl", NLPID_ISO8473_CLNP, clnp_handle);
    dissector_add_uint("osinl.incl", NLPID_NULL, clnp_handle); /* Inactive subset */
    dissector_add_uint("x.25.spi", NLPID_ISO8473_CLNP, clnp_handle);
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
