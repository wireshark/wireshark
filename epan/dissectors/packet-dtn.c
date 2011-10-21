/*
 * Copyright 2006-2007 The MITRE Corporation.
 * All Rights Reserved.
 * Approved for Public Release; Distribution Unlimited.
 * Tracking Number 07-0090.
 *
 * The US Government will not be charged any license fee and/or royalties
 * related to this software. Neither name of The MITRE Corporation; nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Specification reference:
 * Ref http://www.ietf.org/rfc/rfc5050.txt?number=5050
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include "packet-dtn.h"

void proto_reg_handoff_bundle(void);
static int dissect_primary_header(packet_info *pinfo, proto_tree *primary_tree, tvbuff_t *tvb);
static int dissect_admin_record(proto_tree *primary_tree, tvbuff_t *tvb, int offset);
static int dissect_payload_header(proto_tree *tree, tvbuff_t *tvb, int bundle_offset, gboolean *lastheader);
static int display_metadata_block(proto_tree *tree, tvbuff_t *tvb, int bundle_offset, gboolean *lastheader);
static int dissect_contact_header(tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *conv_tree, proto_item *conv_item);
static int dissect_tcp_convergence_data_header(tvbuff_t *tvb, proto_tree *tree);
static int dissect_version_4_primary_header(packet_info *pinfo,
                                            proto_tree *primary_tree, tvbuff_t *tvb);
static int dissect_version_5_and_6_primary_header(packet_info *pinfo,
                                            proto_tree *primary_tree, tvbuff_t *tvb);
static int add_sdnv_to_tree(proto_tree *tree, tvbuff_t *tvb, int offset, const char *field_id);
static int add_dtn_time_to_tree(proto_tree *tree, tvbuff_t *tvb, int offset, const char *field_id);
static int add_sdnv_time_to_tree(proto_tree *tree, tvbuff_t *tvb, int offset, const char *field_id);

/* For Reassembling TCP Convergence Layer segments */
static GHashTable *msg_fragment_table = NULL;
static GHashTable *msg_reassembled_table = NULL;

static char magic[] = {'d', 't', 'n', '!'};

static int proto_bundle = -1;
static int proto_tcp_conv = -1;
static int hf_bundle_pdu_version = -1;

/* TCP Convergence Header Variables */
static int hf_contact_hdr_version = -1;
static int hf_contact_hdr_flags = -1;
static int hf_contact_hdr_keep_alive = -1;
static int hf_contact_hdr_flags_ack_req = -1;
static int hf_contact_hdr_flags_frag_enable = -1;
static int hf_contact_hdr_flags_nak = -1;

/* TCP Convergence Data Header Variables */
static int hf_tcp_convergence_data_procflags = -1;
static int hf_tcp_convergence_data_procflags_start = -1;
static int hf_tcp_convergence_data_procflags_end = -1;

/* TCP Convergence Shutdown Header Variables */
static int hf_tcp_convergence_shutdown_flags = -1;
static int hf_tcp_convergence_shutdown_flags_reason = -1;
static int hf_tcp_convergence_shutdown_flags_delay = -1;
static int hf_tcp_convergence_shutdown_reason = -1;
static int hf_tcp_convergence_shutdown_delay = -1;

/*TCP Convergence Layer Reassembly boilerplate*/
static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;

/* Primary Header Processing Flag Variables */
static guint8 pri_hdr_procflags; /*This is global to allow processing Payload Header*/

static int hf_bundle_procflags = -1;
static int hf_bundle_procflags_fragment = -1;
static int hf_bundle_procflags_admin = -1;
static int hf_bundle_procflags_dont_fragment = -1;
static int hf_bundle_procflags_cust_xfer_req = -1;
static int hf_bundle_procflags_dest_singleton = -1;
static int hf_bundle_procflags_application_ack = -1;

/* Additions for Version 5 */
static int hf_bundle_control_flags = -1;
static int hf_bundle_procflags_general = -1;
static int hf_bundle_procflags_cos = -1;
static int hf_bundle_procflags_status = -1;

/* Primary Header COS Flag Variables */
static int hf_bundle_cosflags = -1;
static int hf_bundle_cosflags_priority = -1;

/* Primary Header Status Report Request Flag Variables */
static int hf_bundle_srrflags = -1;
static int hf_bundle_srrflags_report_receipt = -1;
static int hf_bundle_srrflags_report_cust_accept = -1;
static int hf_bundle_srrflags_report_forward = -1;
static int hf_bundle_srrflags_report_delivery = -1;
static int hf_bundle_srrflags_report_deletion = -1;
static int hf_bundle_srrflags_report_ack = -1;

/* Primary Header Length Fields*/
static int hf_bundle_primary_header_len = -1;
static int hf_bundle_dest_scheme_offset = -1;
static int hf_bundle_dest_ssp_offset = -1;
static int hf_bundle_source_scheme_offset = -1;
static int hf_bundle_source_ssp_offset = -1;
static int hf_bundle_report_scheme_offset = -1;
static int hf_bundle_report_ssp_offset = -1;
static int hf_bundle_cust_scheme_offset = -1;
static int hf_bundle_cust_ssp_offset = -1;

/* Dictionary EIDs */
static int hf_bundle_dest_scheme = -1;
static int hf_bundle_dest_ssp = -1;
static int hf_bundle_source_scheme = -1;
static int hf_bundle_source_ssp = -1;
static int hf_bundle_report_scheme = -1;
static int hf_bundle_report_ssp = -1;
static int hf_bundle_custodian_scheme = -1;
static int hf_bundle_custodian_ssp = -1;

/* Remaining Primary Header Fields */
static int hf_bundle_creation_timestamp = -1;
static int hf_bundle_lifetime = -1;

/* Secondary Header Processing Flag Variables */
static int hf_bundle_payload_flags = -1;
static int hf_bundle_payload_flags_replicate_hdr = -1;
static int hf_bundle_payload_flags_xmit_report = -1;
static int hf_bundle_payload_flags_discard_on_fail = -1;
static int hf_bundle_payload_flags_last_header = -1;

/* Block Processing Control Flag Variables (Version 5) */
static int hf_block_control_flags = -1;
static int hf_block_control_replicate = -1;
static int hf_block_control_transmit_status = -1;
static int hf_block_control_delete_bundle = -1;
static int hf_block_control_last_block = -1;
static int hf_block_control_discard_block = -1;
static int hf_block_control_not_processed = -1;
static int hf_block_control_eid_reference = -1;

/* Administrative Record Variables */
static int hf_bundle_admin_statflags = -1;
static int hf_bundle_admin_rcvd = -1;
static int hf_bundle_admin_accepted = -1;
static int hf_bundle_admin_forwarded = -1;
static int hf_bundle_admin_delivered = -1;
static int hf_bundle_admin_deleted = -1;
static int hf_bundle_admin_acked = -1;
static int hf_bundle_admin_receipt_time = -1;
static int hf_bundle_admin_accept_time = -1;
static int hf_bundle_admin_forward_time = -1;
static int hf_bundle_admin_delivery_time = -1;
static int hf_bundle_admin_delete_time = -1;
static int hf_bundle_admin_ack_time = -1;
static int hf_bundle_admin_timestamp_copy = -1;
static int hf_bundle_admin_signal_time = -1;

/* Tree Node Variables */
static gint ett_bundle = -1;
static gint ett_tcp_conv = -1;
static gint ett_tcp_conv_hdr = -1;
static gint ett_conv_flags = -1;
static gint ett_shutdown_flags = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;
static gint ett_bundle_hdr = -1;
static gint ett_primary_hdr = -1;
static gint ett_proc_flags = -1;
static gint ett_gen_flags = -1;
static gint ett_cos_flags = -1;
static gint ett_srr_flags = -1;
static gint ett_dictionary = -1;
static gint ett_payload_hdr = -1;
static gint ett_payload_flags = -1;
static gint ett_block_flags = -1;
static gint ett_contact_hdr_flags = -1;
static gint ett_admin_record = -1;
static gint ett_admin_rec_status = -1;
static gint ett_metadata_hdr = -1;

static guint bundle_tcp_port = 4556;
static guint bundle_udp_port = 4556;

static const value_string custody_signal_reason_codes[] = {
    {0x3, "Redundant Reception"},
    {0x4, "Depleted Storage"},
    {0x5, "Destination Endpoint ID Unintelligible"},
    {0x6, "No Known Route to Destination"},
    {0x7, "No Timely Contact with Next Node on Route"},
    {0x8, "Header Unintelligible"},
    {0, NULL}
};

static const value_string status_report_reason_codes[] = {
    {0x1, "Lifetime Expired"},
    {0x2, "Forwarded over Unidirectional Link"},
    {0x3, "Transmission Cancelled"},
    {0x4, "Depleted Storage"},
    {0x5, "Destination Endpoint ID Unintelligible"},
    {0x6, "No Known Route to Destination"},
    {0x7, "No Timely Contact with Next Node on Route"},
    {0x8, "Header Unintelligible"},
    {0, NULL}
};

static const fragment_items msg_frag_items = {
    /*Fragment subtrees*/
    &ett_msg_fragment,
    &ett_msg_fragments,
    /*Fragment Fields*/
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    /*Reassembled in field*/
    &hf_msg_reassembled_in,
    /*Reassembled length field*/
    &hf_msg_reassembled_length,
    /*Tag*/
    "Message fragments"
};

static void
dissect_tcp_bundle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    int buffer_size;    /*Number of bytes in buffer that can be processed*/
    int frame_offset;   /*To handle the case of > 1 bundle in an Ethernet Frame*/
    proto_tree *conv_proto_tree = NULL;

    buffer_size = tvb_reported_length(tvb);
    frame_offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bundle");
    col_clear(pinfo->cinfo,COL_INFO); /* Clear out stuff in the info column */

    while(frame_offset < buffer_size) {
        guint8         conv_hdr;

        conv_hdr = tvb_get_guint8(tvb, frame_offset);
        if((conv_hdr & TCP_CONVERGENCE_TYPE_MASK) == TCP_CONVERGENCE_DATA_SEGMENT) {
            fragment_data *frag_msg;
            tvbuff_t      *new_tvb;
            proto_tree    *bundle_tree;
            proto_tree    *conv_proto_tree;
            proto_item    *ci;
            int            segment_length;
            gboolean       more_frags;
            int            sdnv_length;
            int            convergence_hdr_size;
            int            fixed;

            /* Only Start and End flags (bits 0 & 1) are valid in Data Segment */
            if((conv_hdr & ~(TCP_CONVERGENCE_TYPE_MASK | TCP_CONVERGENCE_DATA_FLAGS)) != 0) {
                col_set_str(pinfo->cinfo, COL_INFO, "Invalid TCP CL Data Segment Flags");
                return;
            }
            fixed = 1;
            segment_length = evaluate_sdnv(tvb, fixed + frame_offset, &sdnv_length);
            if(segment_length < 0) {
                col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error (Length)");
                return;
            }
            convergence_hdr_size = sdnv_length + fixed;
            if((buffer_size - frame_offset - convergence_hdr_size) < segment_length) {
                /*Segment not complete -- wait for the rest of it*/
                pinfo->desegment_len =
                            segment_length - (buffer_size - frame_offset
                                                        - convergence_hdr_size);
                pinfo->desegment_offset = frame_offset;
                return;
            }

            /*
             * 1/11/2006 - If I got here, I should have a complete convergence layer
             * "segment" beginning at frame_offset. However that might not be a
             * complete bundle. Or there might be a complete bundle plus one or more
             * additional convergence layer headers.
             */

            bundle_tree = NULL;
            new_tvb     = NULL;
            if((conv_hdr & TCP_CONVERGENCE_DATA_END_FLAG) == TCP_CONVERGENCE_DATA_END_FLAG) {
                more_frags = FALSE;
            }
            else {
                more_frags = TRUE;
            }
            ci = proto_tree_add_item(tree, proto_tcp_conv, tvb,
                                                        frame_offset, -1, ENC_NA);
            conv_proto_tree = proto_item_add_subtree(ci, ett_tcp_conv);
            dissect_tcp_convergence_data_header(tvb, conv_proto_tree);

            /*
             * Note: The reassembled bundle will only include the first
             * Convergence layer header.
             */

            frag_msg = fragment_add_seq_next(tvb, frame_offset + convergence_hdr_size,
                                           pinfo, 0, msg_fragment_table,
                                           msg_reassembled_table, segment_length,
                                           more_frags);
            if(frag_msg && !more_frags) {
                proto_item *ti;

                ti = proto_tree_add_item(tree, proto_bundle, tvb,
                                                        frame_offset, -1, ENC_NA);
                bundle_tree = proto_item_add_subtree(ti, ett_bundle);
                new_tvb = process_reassembled_data(tvb,
                                                   frame_offset + convergence_hdr_size,
                                                   pinfo, "Reassembled DTN", frag_msg,
                                                   &msg_frag_items, NULL, bundle_tree);
            }
            if(new_tvb) {
                int bundle_size;
                bundle_size = dissect_complete_bundle(new_tvb, pinfo, bundle_tree);
                if(bundle_size == 0) {  /*Couldn't parse bundle*/
                    col_set_str(pinfo->cinfo, COL_INFO, "Dissection Failed");
                    return;                     /*Give up*/
                }
            }
            else {

                /*
                 * If there are 2 segments, the second of which is very short, this
                 * gets displayed instead of the usual Source EID/Destination EID in
                 * the Bundle Dissection frame. If these statements are left out entirely,
                 * nothing is displayed, i.e., there seems to be no way to get the
                 * Source/Destination in the 2-segment case. I'll leave it in because I
                 * think it is informative in the multi-segment case although confusing in the
                 * 2-segment case.
                 */

                col_set_str(pinfo->cinfo, COL_INFO, "[Reassembled Segment of a Bundle]");
            }

            /*
             * If we could be sure that the current tvb buffer ended with the CL segment,
             * we could return here. But the buffer could contain multiple complete segments
             * or bundles or a bundle plus other CL messages. In order to process whatever
             * follow the current segment, we have to continue through the buffer until
             * frame_offset indicates everything in the buffer has been processed.
             */

            frame_offset += (segment_length + convergence_hdr_size);
        }
        else {  /*Else this is not a Data Segment*/

            proto_item *conv_item;
            proto_tree *conv_tree;
            proto_item *ci;
            char       *sptr;

            if(frame_offset == 0) {
                ci = proto_tree_add_item(tree, proto_tcp_conv, tvb,
                                                        frame_offset, -1, ENC_NA);
                conv_proto_tree = proto_item_add_subtree(ci, ett_tcp_conv);
            }

            /*
             * Other Convergence Layer messages are short; assume they won't need
             * reassembly. Start with the Convergence Layer Tree.
             */

            conv_item = proto_tree_add_text(conv_proto_tree, tvb, frame_offset, -1,
                                                                "TCP Convergence Header");
            conv_tree = proto_item_add_subtree(conv_item, ett_tcp_conv_hdr);

            if(conv_hdr == (guint8)magic[0]) {
                sptr = (char *) tvb_get_ephemeral_string(tvb, frame_offset, 4);
                if(!memcmp(sptr, magic, 4)){
                    dissect_contact_header(tvb, pinfo, conv_tree, conv_item);
                    return;     /*Assumes Contact Header is alone in segment*/
                }
            }
            if(conv_hdr == TCP_CONVERGENCE_ACK_SEGMENT) {       /*No valid flags in Ack*/
                int         ack_length;
                int         sdnv_length;
                int         fixed;

                proto_tree_add_text(conv_tree, tvb, frame_offset, 1, "Pkt Type: Ack");
                fixed = 1;
                ack_length = evaluate_sdnv(tvb, frame_offset + fixed, &sdnv_length);
                if(ack_length < 0) {
                    proto_tree_add_text(conv_tree, tvb, frame_offset + fixed, sdnv_length,
                                        "Ack Length: Error");
                    return;
                }
                proto_tree_add_text(conv_tree, tvb, frame_offset + fixed, sdnv_length,
                                    "Ack Length: %d", ack_length);

                /*return (sdnv_length + fixed);*/
                frame_offset += (sdnv_length + fixed);
                proto_item_set_len(conv_item, sdnv_length + fixed);
            }
            else if(conv_hdr == TCP_CONVERGENCE_KEEP_ALIVE) { /*No valid flags in Keep Alive*/
                proto_item_set_len(conv_item, 1);
                proto_tree_add_text(conv_tree, tvb, frame_offset, 1, "Pkt Type: Keep Alive");
                frame_offset += 1;
            }
            else if((conv_hdr & TCP_CONVERGENCE_TYPE_MASK) == TCP_CONVERGENCE_SHUTDOWN) {
                proto_item *shutdown_flag_item;
                proto_tree *shutdown_flag_tree;
                guint8 shutdown_flags;
                int field_length;

                if((conv_hdr &
                        ~(TCP_CONVERGENCE_TYPE_MASK | TCP_CONVERGENCE_SHUTDOWN_FLAGS)) != 0) {
                    proto_tree_add_text(conv_tree, tvb, frame_offset,
                                                -1, "Invalid Convergence Layer Shutdown Packet");
                    return;
                }
                proto_item_set_len(conv_item, 1);
                proto_tree_add_text(conv_tree, tvb, 0, 1, "Pkt Type: Shutdown");

                /* Add tree for Shutdown Flags */
                shutdown_flags = conv_hdr;
                shutdown_flag_item = proto_tree_add_item(conv_tree,
                                                hf_tcp_convergence_shutdown_flags, tvb,
                                                frame_offset, 1, ENC_BIG_ENDIAN);
                shutdown_flag_tree = proto_item_add_subtree(shutdown_flag_item,
                                                                        ett_shutdown_flags);
                proto_tree_add_boolean(shutdown_flag_tree,
                                                hf_tcp_convergence_shutdown_flags_reason,
                                                tvb, frame_offset, 1, shutdown_flags);
                proto_tree_add_boolean(shutdown_flag_tree,
                                                hf_tcp_convergence_shutdown_flags_delay,
                                                tvb, frame_offset, 1, shutdown_flags);

                frame_offset += 1;
                field_length = 1;
                if(conv_hdr & TCP_CONVERGENCE_SHUTDOWN_REASON) {
                    proto_tree_add_item(conv_tree,
                                                hf_tcp_convergence_shutdown_reason, tvb,
                                                frame_offset, 1, ENC_BIG_ENDIAN);
                    frame_offset += 1;
                    field_length += 1;
                }
                if(conv_hdr & TCP_CONVERGENCE_SHUTDOWN_DELAY) {
                    proto_tree_add_item(conv_tree,
                                                hf_tcp_convergence_shutdown_delay, tvb,
                                                frame_offset, 2, ENC_BIG_ENDIAN);
                    frame_offset += 2;
                    field_length += 2;
                }
                proto_item_set_len(conv_item, field_length);
            }
            else if(conv_hdr == TCP_CONVERGENCE_REFUSE_BUNDLE) { /*No valid flags*/
                proto_item_set_len(conv_item, 1);
                proto_tree_add_text(conv_tree, tvb, frame_offset,
                                                        1, "Pkt Type: Refuse Bundle");
                frame_offset += 1;
            }
            else {
                proto_tree_add_text(conv_tree, tvb, frame_offset,
                                                -1, "Invalid/Partial Convergence Layer Packet");
                return;
            }
        }
    }           /*end while()*/
    return;
}

static void
dissect_udp_bundle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    int         buffer_size;    /*Number of bytes in buffer that can be processed*/
    int         hdr_offset;
    int         lasthdrflag;
    guint8      next_header_type;
    proto_item *ti;
    proto_tree *bundle_tree;
    proto_item *primary_item;
    proto_tree *primary_tree;

    buffer_size = tvb_reported_length_remaining(tvb, 0);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bundle");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    ti = proto_tree_add_item(tree, proto_bundle, tvb, 0, -1, ENC_NA);
    bundle_tree = proto_item_add_subtree(ti, ett_bundle);

    primary_item = proto_tree_add_text(bundle_tree, tvb, 0, -1,
                                                "Primary Bundle Header");
    primary_tree = proto_item_add_subtree(primary_item, ett_primary_hdr);
    hdr_offset = dissect_primary_header(pinfo, primary_tree, tvb);
    if(hdr_offset == 0) {
        col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
        return;
    }
    proto_item_set_len(primary_item, hdr_offset);

    /*
     * Done with primary header; decode the remaining headers
     */

    lasthdrflag = 0;
    while((hdr_offset > 0) && (buffer_size > hdr_offset)) {
        gint payload_size;

        next_header_type = tvb_get_guint8(tvb, hdr_offset);
        if(next_header_type == PAYLOAD_HEADER_TYPE) {
            payload_size =
                dissect_payload_header(bundle_tree, tvb, hdr_offset, &lasthdrflag);
        }
        else {  /*Assume anything else is a Metadata Block*/
            payload_size = display_metadata_block(bundle_tree, tvb,
                                                 hdr_offset, &lasthdrflag);
        }
        if(payload_size == 0) {
            col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
            return;
        }
        hdr_offset += payload_size;
        if(lasthdrflag) {
            return;
        }
    }
    return;
}

static int
dissect_tcp_convergence_data_header(tvbuff_t *tvb, proto_tree *tree)
{
    proto_item *conv_item;
    proto_tree *conv_tree;
    int         buflen;
    int         sdnv_length;
    int         segment_length;
    proto_item *conv_flag_item;
    proto_tree *conv_flag_tree;
    guint8      tcp_convergence_hdr_procflags;

    buflen    = tvb_length(tvb);
    conv_item = proto_tree_add_text(tree, tvb, 0, -1, "TCP Convergence Header");
    conv_tree = proto_item_add_subtree(conv_item, ett_tcp_conv_hdr);
    proto_tree_add_text(conv_tree, tvb, 0, 1, "Pkt Type: Data");

    /* Add tree for Start/End bits */
    tcp_convergence_hdr_procflags = tvb_get_guint8(tvb, 0);
    conv_flag_item = proto_tree_add_item(conv_tree, hf_tcp_convergence_data_procflags, tvb,
                                                0, 1, ENC_BIG_ENDIAN);
    conv_flag_tree = proto_item_add_subtree(conv_flag_item, ett_conv_flags);
    proto_tree_add_boolean(conv_flag_tree, hf_tcp_convergence_data_procflags_start,
                                                tvb, 0, 1, tcp_convergence_hdr_procflags);
    proto_tree_add_boolean(conv_flag_tree, hf_tcp_convergence_data_procflags_end,
                                                tvb, 0, 1, tcp_convergence_hdr_procflags);

    segment_length = evaluate_sdnv(tvb, 1, &sdnv_length);
    proto_tree_add_text(conv_tree, tvb, 1, sdnv_length, "Segment Length: %d", segment_length);
    proto_item_set_len(conv_item, sdnv_length + 1);
    return buflen;
}

/*
 * Dissect a complete bundle starting at offset 0 in tvb. Return 0 on failure,
 * otherwise the length of the bundle.
 */

int
dissect_complete_bundle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *primary_item;
    proto_tree *primary_tree;
    int         primary_header_size;
    gboolean    lastheader = FALSE;
    int         offset;

    primary_item = proto_tree_add_text(tree, tvb, 0, -1,
                                                "Primary Bundle Header");
    primary_tree = proto_item_add_subtree(primary_item, ett_primary_hdr);
    primary_header_size = dissect_primary_header(pinfo, primary_tree, tvb);
    if(primary_header_size == 0) {      /*Couldn't parse primary header*/
        col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
        return(0);      /*Give up*/
    }
    proto_item_set_len(primary_item, primary_header_size);
    offset = primary_header_size;

    /*
     * Done with primary header; decode the remaining headers
     */

    while(lastheader == FALSE) {
        guint8 next_header_type;
        int payload_size;

        next_header_type = tvb_get_guint8(tvb, offset);
        if(next_header_type == PAYLOAD_HEADER_TYPE) {

            /*
             * Returns payload size or 0 if can't parse payload
             */
            payload_size = dissect_payload_header(tree, tvb, offset, &lastheader);
        }
        else {  /*Assume anything else is a Metadata Block*/
            payload_size = display_metadata_block(tree, tvb, offset, &lastheader);
        }
        if(payload_size == 0) { /*Payload header parse failed*/
            col_set_str(pinfo->cinfo, COL_INFO, "Dissection Failed");
            return (0);
        }
        offset += payload_size;
    }
    return(offset);
}

/*
 * This routine returns 0 if header decoding fails, otherwise the length of the primary
 * header. The bundle starts right at the beginning of the tvbuff.
 */

static int
dissect_primary_header(packet_info *pinfo, proto_tree *primary_tree, tvbuff_t *tvb)
{
    gint   offset;
    guint8 version;

    offset = 0;

    version = tvb_get_guint8(tvb, 0);  /* Primary Header Version */

    if((version != 4) && (version != 5) && (version != 6)) {
        proto_tree_add_text(primary_tree, tvb, offset, 1, "Invalid Version Number");
        return 0;
    }

    proto_tree_add_item(primary_tree, hf_bundle_pdu_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (version == 4) {
        return dissect_version_4_primary_header(pinfo, primary_tree, tvb);
    }
    else {
        return dissect_version_5_and_6_primary_header(pinfo, primary_tree, tvb);
    }
}

/* XXX: Consider common functions for use by dissect_version_4_primary_header() and
        dissect_version_5_and_6_primary_header() since there's much identical code
        between the two.
*/

static int
dissect_version_4_primary_header(packet_info *pinfo, proto_tree *primary_tree, tvbuff_t *tvb)
{
    guint8        cosflags;
    const guint8 *dict_ptr;
    int           bundle_header_length;
    int           bundle_header_dict_length;
    int           offset;     /*Total offset into frame (frame_offset + convergence layer size)*/
    int           sdnv_length;
    int           dest_scheme_offset, dest_ssp_offset, source_scheme_offset, source_ssp_offset;
    int           report_scheme_offset, report_ssp_offset, cust_scheme_offset, cust_ssp_offset;
    int           fragment_offset, total_adu_length;
    int           dst_scheme_pos, src_scheme_pos, rpt_scheme_pos, cust_scheme_pos;
    int           dst_scheme_len, src_scheme_len, rpt_scheme_len, cust_scheme_len;
    int           dst_ssp_len, src_ssp_len, rpt_ssp_len, cust_ssp_len;
    const gchar  *src_node;
    const gchar  *dst_node;

    guint8        srrflags;
    proto_item   *srr_flag_item;
    proto_tree   *srr_flag_tree;

    proto_item   *proc_flag_item;
    proto_tree   *proc_flag_tree;
    proto_item   *cos_flag_item;
    proto_tree   *cos_flag_tree;
    proto_item   *dict_item;
    proto_tree   *dict_tree;

    offset = 1;         /* Version Number already displayed*/

    /* Primary Header Processing Flags */
    pri_hdr_procflags = tvb_get_guint8(tvb, offset);
    proc_flag_item = proto_tree_add_item(primary_tree, hf_bundle_procflags, tvb,
                                                offset, 1, ENC_BIG_ENDIAN);
    proc_flag_tree = proto_item_add_subtree(proc_flag_item, ett_proc_flags);
    proto_tree_add_boolean(proc_flag_tree, hf_bundle_procflags_fragment,
                                                tvb, offset, 1, pri_hdr_procflags);
    proto_tree_add_boolean(proc_flag_tree, hf_bundle_procflags_admin,
                                                tvb, offset, 1, pri_hdr_procflags);
    proto_tree_add_boolean(proc_flag_tree, hf_bundle_procflags_dont_fragment,
                                                tvb, offset, 1, pri_hdr_procflags);
    proto_tree_add_boolean(proc_flag_tree, hf_bundle_procflags_cust_xfer_req,
                                                tvb, offset, 1, pri_hdr_procflags);
    proto_tree_add_boolean(proc_flag_tree, hf_bundle_procflags_dest_singleton,
                                                tvb, offset, 1, pri_hdr_procflags);

    /* Primary Header COS Flags */
    ++offset;
    cosflags = tvb_get_guint8(tvb, offset);
    cos_flag_item = proto_tree_add_item(primary_tree, hf_bundle_cosflags, tvb,
                                                offset, 1, ENC_BIG_ENDIAN);
    cos_flag_tree = proto_item_add_subtree(cos_flag_item, ett_cos_flags);
    proto_tree_add_uint(cos_flag_tree, hf_bundle_cosflags_priority,
                                                tvb, offset, 1, cosflags);
    /* Status Report Request Flags */
    ++offset;
    srrflags = tvb_get_guint8(tvb, offset);
    srr_flag_item = proto_tree_add_item(primary_tree, hf_bundle_srrflags, tvb,
                                                offset, 1, ENC_BIG_ENDIAN);
    srr_flag_tree = proto_item_add_subtree(srr_flag_item, ett_srr_flags);

    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_receipt,
                                                tvb, offset, 1, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_cust_accept,
                                                tvb, offset, 1, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_forward,
                                                tvb, offset, 1, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_delivery,
                                                tvb, offset, 1, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_deletion,
                                                tvb, offset, 1, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_ack,
                                                tvb, offset, 1, srrflags);
    ++offset;

    bundle_header_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(bundle_header_length < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length, "Bundle Header Length: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Bundle Header Length: %d", bundle_header_length);

    tvb_ensure_bytes_exist(tvb, offset + sdnv_length, bundle_header_length);
    offset += sdnv_length;

    /*
     * Pick up offsets into dictionary (8 of them)
     */

    dest_scheme_offset = tvb_get_ntohs(tvb, offset);
    dst_scheme_pos = offset;
    dst_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_dest_scheme_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dest_ssp_offset = tvb_get_ntohs(tvb, offset);
    dst_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_dest_ssp_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    source_scheme_offset = tvb_get_ntohs(tvb, offset);
    src_scheme_pos = offset;
    src_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_source_scheme_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    source_ssp_offset = tvb_get_ntohs(tvb, offset);
    src_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_source_ssp_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    report_scheme_offset = tvb_get_ntohs(tvb, offset);
    rpt_scheme_pos = offset;
    rpt_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_report_scheme_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    report_ssp_offset = tvb_get_ntohs(tvb, offset);
    rpt_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_report_ssp_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    cust_scheme_offset = tvb_get_ntohs(tvb, offset);
    cust_scheme_pos = offset;
    cust_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_cust_scheme_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    cust_ssp_offset = tvb_get_ntohs(tvb, offset);
    cust_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_cust_ssp_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(primary_tree, hf_bundle_creation_timestamp,
                                                        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(primary_tree, hf_bundle_lifetime, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    bundle_header_dict_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(bundle_header_dict_length < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length, "Dictionary Length: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Dictionary Length: %d", bundle_header_dict_length);
    offset += sdnv_length;

    /*
     * Pull out stuff from the dictionary
     */

    tvb_ensure_bytes_exist(tvb, offset, bundle_header_dict_length);

    dict_item = proto_tree_add_text(primary_tree, tvb, offset, bundle_header_dict_length, "Dictionary");
    dict_tree = proto_item_add_subtree(dict_item, ett_dictionary);

    /*
     * If the dictionary length is 0, then the CBHE block compression method is applied.
     * So the scheme offset is the node number and the ssp offset is the service number.
     * If destination scheme offset is 2 and destination ssp offset is 1, then the EID is
     * ipn:2.1
     */
    if(bundle_header_dict_length == 0)
    {
        /*
         * Destination info
         */
        proto_tree_add_text(dict_tree, tvb, 0,
                                0, "Destination Scheme: %s",IPN_SCHEME_STR);
        if(dest_scheme_offset == 0 && dest_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb, dst_scheme_pos,
                                dst_scheme_len + dst_ssp_len, "Destination: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb, dst_scheme_pos,
                                dst_scheme_len + dst_ssp_len,
                                "Destination: %d.%d",dest_scheme_offset,dest_ssp_offset);
        }

        /*
         * Source info
         */
        proto_tree_add_text(dict_tree, tvb, 0,
                                        0, "Source Scheme: %s",IPN_SCHEME_STR);
        if(source_scheme_offset == 0 && source_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb, src_scheme_pos,
                                src_scheme_len + src_ssp_len, "Source: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb, src_scheme_pos,
                                src_scheme_len + src_ssp_len,
                                "Source: %d.%d",source_scheme_offset,source_ssp_offset);
        }

        /*
         * Report to info
         */
        proto_tree_add_text(dict_tree, tvb, 0,
                                        0, "Report Scheme: %s",IPN_SCHEME_STR);
        if(report_scheme_offset == 0 && report_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb, rpt_scheme_pos,
                                rpt_scheme_len + rpt_ssp_len, "Report: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb, rpt_scheme_pos,
                                rpt_scheme_len + rpt_ssp_len,
                                "Report: %d.%d",report_scheme_offset,report_ssp_offset);
        }

        /*
         * Custodian info
         */
        proto_tree_add_text(dict_tree, tvb, 0,
                                        0, "Custodian Scheme: %s",IPN_SCHEME_STR);
        if(cust_scheme_offset == 0 && cust_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb, cust_scheme_pos,
                                cust_scheme_len + cust_ssp_len, "Custodian: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb, cust_scheme_pos,
                                cust_scheme_len + cust_ssp_len,
                                "Custodian: %d.%d",cust_scheme_offset,cust_ssp_offset);
        }

        if(source_scheme_offset == 0 && source_ssp_offset == 0)
        {
                src_node = "Null";
        }
        else
        {
                src_node = ep_strdup_printf("%s:%d.%d",IPN_SCHEME_STR, source_scheme_offset, source_ssp_offset);
        }
        if(dest_scheme_offset == 0 && dest_ssp_offset == 0)
        {
                dst_node = "Null";
        }
        else
        {
                dst_node = ep_strdup_printf("%s:%d.%d",IPN_SCHEME_STR, dest_scheme_offset, dest_ssp_offset);
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s > %s", src_node,dst_node);
    }

    /*
     * This pointer can be made to address outside the packet boundaries so we
     * need to check for improperly formatted strings (no null termination).
     */

    else
    {
        /*
         * Destination info
         */

        proto_tree_add_item(dict_tree, hf_bundle_dest_scheme, tvb, offset + dest_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_dest_ssp, tvb, offset + dest_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Source info
         */

        proto_tree_add_item(dict_tree, hf_bundle_source_scheme, tvb, offset + source_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_source_ssp, tvb, offset + source_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Report to info
         */

        proto_tree_add_item(dict_tree, hf_bundle_report_scheme, tvb, offset + report_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_report_ssp, tvb, offset + report_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Custodian info
         */

        proto_tree_add_item(dict_tree, hf_bundle_custodian_scheme, tvb, offset + cust_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_custodian_ssp, tvb, offset + cust_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Add Source/Destination to INFO Field
         */

        /* Note: If we get this far, the offsets (and the strings) are at least within the TVB */
        dict_ptr = tvb_get_ptr(tvb, offset, bundle_header_dict_length);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s:%s > %s:%s",
                     dict_ptr + source_scheme_offset, dict_ptr + source_ssp_offset,
                     dict_ptr + dest_scheme_offset, dict_ptr + dest_ssp_offset);

    }
    offset += bundle_header_dict_length;        /*Skip over dictionary*/
    /*
     * Do this only if Fragment Flag is set
     */

    if(pri_hdr_procflags & BUNDLE_PROCFLAGS_FRAG_MASK) {
        fragment_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(fragment_offset < 0) {
            return 0;
        }
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                                        "Fragment Offset: %d", fragment_offset);
        offset += sdnv_length;

        total_adu_length = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(total_adu_length < 0) {
            return 0;
        }
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Total Application Data Unit Length: %d", fragment_offset);
        offset += sdnv_length;
    }
    return (offset);
}


/*
 * This routine returns 0 if header decoding fails, otherwise the length of the primary
 * header. The bundle starts right at the beginning of the tvbuff.
 */

static int
dissect_version_5_and_6_primary_header(packet_info *pinfo,
                                        proto_tree *primary_tree, tvbuff_t *tvb)
{
    guint64 bundle_processing_control_flags;
    guint8 cosflags;
    const guint8 *dict_ptr;
    int bundle_header_length;
    int bundle_header_dict_length;
    int offset;         /*Total offset into frame (frame_offset + convergence layer size)*/
    int sdnv_length;
    int dest_scheme_offset, dest_ssp_offset, source_scheme_offset, source_ssp_offset;
    int report_scheme_offset, report_ssp_offset, cust_scheme_offset, cust_ssp_offset;
    int dest_scheme_pos, source_scheme_pos, report_scheme_pos, cust_scheme_pos;
    int dest_scheme_len, source_scheme_len, report_scheme_len, cust_scheme_len;
    int dest_ssp_len, source_ssp_len, report_ssp_len, cust_ssp_len;
    int fragment_offset, total_adu_length;
    int timestamp;
    time_t time_since_2000;
    int timestamp_sequence;
    int lifetime;
    char *time_string;
    const gchar *src_node;
    const gchar *dst_node;
    guint8 srrflags;
    proto_item *srr_flag_item;
    proto_tree *srr_flag_tree;
    proto_item *gen_flag_item;
    proto_tree *gen_flag_tree;

    proto_item *proc_flag_item;
    proto_tree *proc_flag_tree;
    proto_item *cos_flag_item;
    proto_tree *cos_flag_tree;
    proto_item *dict_item;
    proto_tree *dict_tree;


    offset = 1;         /* Version Number already displayed */
    bundle_processing_control_flags = evaluate_sdnv_64(tvb, offset, &sdnv_length);

    /* Primary Header Processing Flags */
    pri_hdr_procflags = (guint8) (bundle_processing_control_flags & 0x7f);

    if (sdnv_length < 1) {
        expert_add_info_format(pinfo, primary_tree, PI_UNDECODED, PI_WARN,
                               "Wrong bundle control flag length: %d", sdnv_length);
        return 0;
    }
    proc_flag_item = proto_tree_add_item(primary_tree, hf_bundle_control_flags, tvb,
                                                offset, sdnv_length, ENC_BIG_ENDIAN);
    proc_flag_tree = proto_item_add_subtree(proc_flag_item, ett_proc_flags);

    gen_flag_item = proto_tree_add_text(proc_flag_tree, tvb, offset,
                                        sdnv_length, "General Flags");
    gen_flag_tree = proto_item_add_subtree(gen_flag_item, ett_gen_flags);

    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_fragment,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);
    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_admin,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);
    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_dont_fragment,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);
    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_cust_xfer_req,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);
    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_dest_singleton,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);
    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_application_ack,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);

    /* Primary Header COS Flags */
    cosflags = (guint8) ((bundle_processing_control_flags >> 7) & 0x7f);
    cos_flag_item = proto_tree_add_text(proc_flag_tree, tvb, offset,
                                        sdnv_length, "Class of Service Flags");
    cos_flag_tree = proto_item_add_subtree(cos_flag_item, ett_cos_flags);
    if((cosflags & BUNDLE_COSFLAGS_PRIORITY_MASK) == BUNDLE_COSFLAGS_PRIORITY_BULK) {
        proto_tree_add_text(cos_flag_tree, tvb, offset,
                                        sdnv_length, "00 -- Priority = Bulk");
    }
    else if((cosflags & BUNDLE_COSFLAGS_PRIORITY_MASK) ==
                                        BUNDLE_COSFLAGS_PRIORITY_NORMAL) {
        proto_tree_add_text(cos_flag_tree, tvb, offset,
                                        sdnv_length, "01 -- Priority = Normal");
    }
    else if((cosflags & BUNDLE_COSFLAGS_PRIORITY_MASK) ==
                                        BUNDLE_COSFLAGS_PRIORITY_EXP) {
        proto_tree_add_text(cos_flag_tree, tvb, offset,
                                        sdnv_length, "10 -- Priority = Expedited");
    }
    else {
        proto_tree_add_text(cos_flag_tree, tvb, offset,
                                        sdnv_length, "11 -- Invalid (Reserved)");
        return 0;
    }

    /* Status Report Request Flags */
    srrflags = (guint8) ((bundle_processing_control_flags >> 14) & 0x7f);
    srr_flag_item = proto_tree_add_text(proc_flag_tree, tvb, offset,
                                        sdnv_length, "Status Report Request Flags");
    srr_flag_tree = proto_item_add_subtree(srr_flag_item, ett_srr_flags);

    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_receipt,
                                                tvb, offset, sdnv_length, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_cust_accept,
                                                tvb, offset, sdnv_length, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_forward,
                                                tvb, offset, sdnv_length, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_delivery,
                                                tvb, offset, sdnv_length, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_deletion,
                                                tvb, offset, sdnv_length, srrflags);
    offset += sdnv_length;

    /* -- hdr_length -- */
    bundle_header_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(bundle_header_length < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Bundle Header Length: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Bundle Header Length: %d", bundle_header_length);
    tvb_ensure_bytes_exist(tvb, offset + sdnv_length, bundle_header_length);
    offset += sdnv_length;

    /*
     * Pick up offsets into dictionary (8 of them). Do rough sanity check that SDNV
     * hasn't told us to access way past the Primary Header.
     */

    /* -- dest_scheme -- */
    dest_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dest_scheme_pos = offset;
    dest_scheme_len = sdnv_length;

    if((dest_scheme_offset < 0) || (dest_scheme_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Destination Scheme Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Destination Scheme Offset: %d", dest_scheme_offset);
    offset += sdnv_length;

    /* -- dest_ssp -- */
    dest_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dest_ssp_len = sdnv_length;

    if((dest_ssp_offset < 0) || (dest_ssp_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Destination SSP Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Destination SSP Offset: %d", dest_ssp_offset);
    offset += sdnv_length;


    /* -- source_scheme -- */
    source_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    source_scheme_pos = offset;
    source_scheme_len = sdnv_length;

    if((source_scheme_offset < 0) || (source_scheme_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Source Scheme Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Source Scheme Offset: %d", source_scheme_offset);
    offset += sdnv_length;

    /* -- source_ssp -- */
    source_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    source_ssp_len = sdnv_length;

    if((source_ssp_offset < 0) || (source_ssp_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Source SSP Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Source SSP Offset: %d", source_ssp_offset);
    offset += sdnv_length;


    /* -- report_scheme -- */
    report_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    report_scheme_pos = offset;
    report_scheme_len = sdnv_length;

    if((report_scheme_offset < 0) || (report_scheme_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Report Scheme Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Report Scheme Offset: %d", report_scheme_offset);
    offset += sdnv_length;

    /* -- report_ssp -- */
    report_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    report_ssp_len = sdnv_length;

    if((report_ssp_offset < 0) || (report_ssp_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Report SSP Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Report SSP Offset: %d", report_ssp_offset);
    offset += sdnv_length;


    /* -- cust_scheme -- */
    cust_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    cust_scheme_pos = offset;
    cust_scheme_len = sdnv_length;

    if((cust_scheme_offset < 0) || (cust_scheme_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Custodian Scheme Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Custodian Scheme Offset: %d", cust_scheme_offset);
    offset += sdnv_length;

    /* -- cust_ssp -- */
    cust_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    cust_ssp_len = sdnv_length;

    if((cust_ssp_offset < 0) || (cust_ssp_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Custodian SSP Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Custodian SSP Offset: %d", cust_ssp_offset);
    offset += sdnv_length;


    /* -- timestamp -- */
    timestamp = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(timestamp < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Timestamp: Error");
        return 0;
    }
    time_since_2000 = (time_t) (timestamp + 946684800);
    time_string = abs_time_secs_to_str(time_since_2000, ABSOLUTE_TIME_LOCAL, TRUE);
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Timestamp: 0x%x [%s]", timestamp, time_string);
    offset += sdnv_length;

    /* -- timestamp_sequence -- */
    timestamp_sequence = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(timestamp_sequence < 0) {
        gint64 ts_seq;

        if((ts_seq = evaluate_sdnv_64(tvb, offset, &sdnv_length)) < 0) {
            proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                                "Timestamp Sequence Number: Error");
            return 0;
        }
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Timestamp Sequence Number: 0x%" G_GINT64_MODIFIER "x", ts_seq);
    }
    else {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Timestamp Sequence Number: %d", timestamp_sequence);
    }
    offset += sdnv_length;

    /* -- lifetime -- */
    lifetime = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(lifetime < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Lifetime: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Lifetime: %d", lifetime);
    offset += sdnv_length;

    /* -- dict_length -- */
    bundle_header_dict_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(bundle_header_dict_length < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Dictionary Length: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Dictionary Length: %d",bundle_header_dict_length);
    offset += sdnv_length;

    /*
     * Pull out stuff from the dictionary
     */

    tvb_ensure_bytes_exist(tvb, offset, bundle_header_dict_length);

    dict_item = proto_tree_add_text(primary_tree, tvb, offset, bundle_header_dict_length,
                                    "Dictionary");
    dict_tree = proto_item_add_subtree(dict_item, ett_dictionary);

    if(bundle_header_dict_length == 0)
    {
        /*
         * Destination info
         */
        proto_tree_add_text(dict_tree, tvb,
                            0, 0,
                            "Destination Scheme: %s",IPN_SCHEME_STR);
        if(dest_scheme_offset == 0 && dest_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb,
                                    dest_scheme_pos, dest_scheme_len + dest_ssp_len,
                                    "Destination: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb,
                                    dest_scheme_pos, dest_scheme_len + dest_ssp_len,
                                    "Destination: %d.%d",dest_scheme_offset,dest_ssp_offset);
        }

        /*
         * Source info
         */
        proto_tree_add_text(dict_tree, tvb,
                            0, 0,
                            "Source Scheme: %s",IPN_SCHEME_STR);
        if(source_scheme_offset == 0 && source_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb,
                                    source_scheme_pos, source_scheme_len + source_ssp_len,
                                    "Source: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb,
                                    source_scheme_pos, source_scheme_len + source_ssp_len,
                                    "Source: %d.%d",source_scheme_offset,source_ssp_offset);
        }

        /*
         * Report to info
         */
        proto_tree_add_text(dict_tree, tvb,
                            0, 0,
                            "Report Scheme: %s",IPN_SCHEME_STR);
        if((report_scheme_offset == 0) && (report_ssp_offset == 0))
        {
                proto_tree_add_text(dict_tree, tvb,
                                    report_scheme_pos, report_scheme_len + report_ssp_len,
                                    "Report: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb,
                                    report_scheme_pos, report_scheme_len + report_ssp_len,
                                    "Report: %d.%d",report_scheme_offset,report_ssp_offset);
        }

        /*
         * Custodian info
         */
        proto_tree_add_text(dict_tree, tvb, 0,
                                        0, "Custodian Scheme: %s",IPN_SCHEME_STR);
        if(cust_scheme_offset == 0 && cust_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb,
                                    cust_scheme_pos, cust_scheme_len + cust_ssp_len,
                                    "Custodian: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb, cust_scheme_pos,
                                cust_scheme_len + cust_ssp_len,
                                "Custodian: %d.%d",cust_scheme_offset,cust_ssp_offset);
        }

        if(source_scheme_offset == 0 && source_ssp_offset == 0)
        {
                src_node = "Null";
        }
        else
        {
                src_node = ep_strdup_printf("%s:%d.%d",IPN_SCHEME_STR, source_scheme_offset, source_ssp_offset);
        }
        if(dest_scheme_offset == 0 && dest_ssp_offset == 0)
        {
                dst_node = "Null";
        }
        else
        {
                dst_node = ep_strdup_printf("%s:%d.%d",IPN_SCHEME_STR, dest_scheme_offset, dest_ssp_offset);
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s > %s", src_node, dst_node);
    }
    else
    {
        /*
         * Note that the various "offset" pointers may address outside the packet boundaries.
         * proto_tree_add_item() will throw a "bounds exception" for invalid "offset" values.
         */

        /*
         * Destination info
         */

        proto_tree_add_item(dict_tree, hf_bundle_dest_scheme, tvb, offset + dest_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_dest_ssp, tvb, offset + dest_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Source info
         */

        proto_tree_add_item(dict_tree, hf_bundle_source_scheme, tvb, offset + source_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_source_ssp, tvb, offset + source_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Report to info
         */

        proto_tree_add_item(dict_tree, hf_bundle_report_scheme, tvb, offset + report_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_report_ssp, tvb, offset + report_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Custodian info
         */

        proto_tree_add_item(dict_tree, hf_bundle_custodian_scheme, tvb, offset + cust_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_custodian_ssp, tvb, offset + cust_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Add Source/Destination to INFO Field
         */

        /* Note: If we get this far, the offsets (and the strings) are at least within the TVB */
        dict_ptr = tvb_get_ptr(tvb, offset, bundle_header_dict_length);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s:%s > %s:%s",
                     dict_ptr + source_scheme_offset, dict_ptr + source_ssp_offset,
                     dict_ptr + dest_scheme_offset, dict_ptr + dest_ssp_offset);
    }
    offset += bundle_header_dict_length;        /*Skip over dictionary*/

    /*
     * Do this only if Fragment Flag is set
     */

    if(pri_hdr_procflags & BUNDLE_PROCFLAGS_FRAG_MASK) {
        fragment_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(fragment_offset < 0) {
            return 0;
        }
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                                        "Fragment Offset: %d", fragment_offset);
        offset += sdnv_length;

        total_adu_length = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(total_adu_length < 0) {
            return 0;
        }
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Total Application Data Unit Length: %d", fragment_offset);
        offset += sdnv_length;
    }
    return (offset);
}

/*
 * bundle_offset is offset into this bundle where header starts.
 * Return size of payload (including payload header) or 0 on failure.
 */

static int
dissect_payload_header(proto_tree *tree, tvbuff_t *tvb, int offset, gboolean *lastheader)
{
    proto_item *payload_item;
    proto_tree *payload_tree;
    int         sdnv_length;
    int         header_start;
    int         payload_length;

    header_start = offset;      /*Used to compute total payload length*/
    payload_item = proto_tree_add_text(tree, tvb, offset, -1, "Payload Header");
    payload_tree = proto_item_add_subtree(payload_item, ett_payload_hdr);

    proto_tree_add_text(payload_tree, tvb, offset, 1, "Header Type: 1");
    ++offset;

    /* Add tree for processing flags */
    /* This is really a SDNV but there are only 7 bits defined so leave it this way*/

    if(hf_bundle_pdu_version == 4) {
        proto_item *proc_flag_item;
        proto_tree *proc_flag_tree;
        guint8      procflags;

        procflags = tvb_get_guint8(tvb, offset);
        if(procflags & HEADER_PROCFLAGS_LAST_HEADER) {
            *lastheader = TRUE;
        }
        else {
            *lastheader = FALSE;
        }
        proc_flag_item = proto_tree_add_item(payload_tree, hf_bundle_payload_flags, tvb,
                                                offset, 1, ENC_BIG_ENDIAN);
        proc_flag_tree = proto_item_add_subtree(proc_flag_item, ett_payload_flags);
        proto_tree_add_boolean(proc_flag_tree, hf_bundle_payload_flags_replicate_hdr,
                                                tvb, offset, 1, procflags);
        proto_tree_add_boolean(proc_flag_tree, hf_bundle_payload_flags_xmit_report,
                                                tvb, offset, 1, procflags);
        proto_tree_add_boolean(proc_flag_tree, hf_bundle_payload_flags_discard_on_fail,
                                                tvb, offset, 1, procflags);
        proto_tree_add_boolean(proc_flag_tree, hf_bundle_payload_flags_last_header,
                                                tvb, offset, 1, procflags);
        ++offset;
    }
    else {      /*Bundle Protocol Version 5*/
        int control_flags;
        proto_item *block_flag_item;
        proto_tree *block_flag_tree;

        control_flags = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(control_flags & BLOCK_CONTROL_LAST_BLOCK) {
            *lastheader = TRUE;
        }
        else {
            *lastheader = FALSE;
        }
        block_flag_item = proto_tree_add_item(payload_tree, hf_block_control_flags, tvb,
                                                offset, sdnv_length, ENC_BIG_ENDIAN);
        block_flag_tree = proto_item_add_subtree(block_flag_item, ett_block_flags);

        proto_tree_add_boolean(block_flag_tree, hf_block_control_replicate,
                                        tvb, offset, sdnv_length, control_flags);
        proto_tree_add_boolean(block_flag_tree, hf_block_control_transmit_status,
                                        tvb, offset, sdnv_length, control_flags);
        proto_tree_add_boolean(block_flag_tree, hf_block_control_delete_bundle,
                                        tvb, offset, sdnv_length, control_flags);
        proto_tree_add_boolean(block_flag_tree, hf_block_control_last_block,
                                        tvb, offset, sdnv_length, control_flags);
        proto_tree_add_boolean(block_flag_tree, hf_block_control_discard_block,
                                        tvb, offset, sdnv_length, control_flags);
        proto_tree_add_boolean(block_flag_tree, hf_block_control_not_processed,
                                        tvb, offset, sdnv_length, control_flags);
        proto_tree_add_boolean(block_flag_tree, hf_block_control_eid_reference,
                                        tvb, offset, sdnv_length, control_flags);
        offset += sdnv_length;
    }

    payload_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    proto_item_set_len(payload_item, 2 + sdnv_length);

    if(payload_length < 0) {
        proto_tree_add_text(payload_tree, tvb, offset, sdnv_length, "Payload Length: Error");
        return 0;
    }
    proto_tree_add_text(payload_tree, tvb, offset, sdnv_length, "Payload Length: %d", payload_length);

    offset += sdnv_length;
    if(pri_hdr_procflags & BUNDLE_PROCFLAGS_ADMIN_MASK) {
        int admin_size;

        /*
         * XXXX - Have not allowed for admin record spanning multiple segments!
         */

        admin_size = dissect_admin_record(payload_tree, tvb, offset);
        if(admin_size == 0) {
            return 0;
        }
    }
    return (payload_length + (offset - header_start));
}

/*
 * Return the length of the Administrative Record or 0 if analysis fails.
 */

static int
dissect_admin_record(proto_tree *primary_tree, tvbuff_t *tvb, int offset)
{
    proto_item *admin_record_item;
    proto_tree *admin_record_tree;
    proto_item *timestamp_sequence_item;
    guint8 record_type;
    guint8 status;
    guint8 reason;
    int record_size = 0;
    int sdnv_length;
    int timestamp_sequence;
    int endpoint_length;
    guint8 *string_ptr;

    admin_record_item = proto_tree_add_text(primary_tree, tvb, offset, -1,
                                                        "Administrative Record");
    admin_record_tree = proto_item_add_subtree(admin_record_item, ett_admin_record);
    record_type = tvb_get_guint8(tvb, offset);

    if(record_type == (0x05 << 4)) {
        proto_tree_add_text(admin_record_tree, tvb, offset, 1, "Announce Record (Contact)");
        return 1;       /*Special case for poxy TCP Convergence Layer Announce Bundle*/
    }
    if(record_type & ADMIN_REC_FLAGS_FRAGMENT) {
        proto_tree_add_text(admin_record_tree, tvb, offset, 1, "Record is for a Fragment");
    }
    else {
        proto_tree_add_text(admin_record_tree,
                                tvb, offset, 1, "Record is not for a Fragment");
    }

    switch((record_type >> 4) & 0xf)
    {

    case ADMIN_REC_TYPE_STATUS_REPORT:
    {
        proto_item *status_flag_item;
        proto_tree *status_flag_tree;

        proto_tree_add_text(admin_record_tree, tvb, offset, 1,
                                "Administrative Record Type: Bundle Status Report");
        ++record_size; ++offset;

        /* Decode Bundle Status Report Flags */
        status = tvb_get_guint8(tvb, offset);
        status_flag_item = proto_tree_add_item(admin_record_tree,
                                hf_bundle_admin_statflags, tvb, offset, 1, ENC_BIG_ENDIAN);
        status_flag_tree = proto_item_add_subtree(status_flag_item,
                                                        ett_admin_rec_status);
        proto_tree_add_boolean(status_flag_tree, hf_bundle_admin_rcvd,
                                                tvb, offset, 1, status);
        proto_tree_add_boolean(status_flag_tree, hf_bundle_admin_accepted,
                                                tvb, offset, 1, status);
        proto_tree_add_boolean(status_flag_tree, hf_bundle_admin_forwarded,
                                                tvb, offset, 1, status);
        proto_tree_add_boolean(status_flag_tree, hf_bundle_admin_delivered,
                                                tvb, offset, 1, status);
        proto_tree_add_boolean(status_flag_tree, hf_bundle_admin_deleted,
                                                tvb, offset, 1, status);
        proto_tree_add_boolean(status_flag_tree, hf_bundle_admin_acked,
                                                tvb, offset, 1, status);
        ++record_size; ++offset;

        reason = tvb_get_guint8(tvb, offset);
        if(reason == 0) {
            proto_tree_add_text(admin_record_tree, tvb, offset, 1,
                                "Reason Code: 0 (No Additional Information)");
        }
        else {
            proto_tree_add_text(admin_record_tree, tvb, offset, 1,
                                        "Reason Code: 0x%x (%s)", reason,
                                        val_to_str(reason, status_report_reason_codes,
                                                        "Invalid"));
        }
        ++record_size; ++offset;
        if(record_type & ADMIN_REC_FLAGS_FRAGMENT) {
            sdnv_length = add_sdnv_to_tree(admin_record_tree, tvb, offset,
                                                        "Fragment Offset");
            if(sdnv_length <= 0) {
                return 0;
            }
            offset += sdnv_length; record_size += sdnv_length;
            sdnv_length = add_sdnv_to_tree(admin_record_tree, tvb, offset,
                                                        "Fragment Length");
            if(sdnv_length <= 0) {
                return 0;
            }
            offset += sdnv_length; record_size += sdnv_length;
        }
        if(status & ADMIN_STATUS_FLAGS_RECEIVED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset,
                                                        "Bundle Received Time");
            if(sdnv_length <= 0) {
                return 0;
            }
            offset += sdnv_length; record_size += sdnv_length;
        }
        if(status & ADMIN_STATUS_FLAGS_ACCEPTED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset,
                                                        "Bundle Accepted Time");
            if(sdnv_length <= 0) {
                return 0;
            }
            offset += sdnv_length; record_size += sdnv_length;
        }
        if(status & ADMIN_STATUS_FLAGS_FORWARDED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset,
                                                        "Bundle Forwarded Time");
            if(sdnv_length <= 0) {
                return 0;
            }
            offset += sdnv_length; record_size += sdnv_length;
        }
        if(status & ADMIN_STATUS_FLAGS_DELIVERED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset,
                                                        "Bundle Delivered Time");
            if(sdnv_length <= 0) {
                return 0;
            }
            offset += sdnv_length; record_size += sdnv_length;
        }
        if(status & ADMIN_STATUS_FLAGS_DELETED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset,
                                                        "Bundle Deleted Time");
            if(sdnv_length <= 0) {
                return 0;
            }
            offset += sdnv_length; record_size += sdnv_length;
        }
        if(status & ADMIN_STATUS_FLAGS_ACKNOWLEDGED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset,
                                                        "Bundle Acknowledged Time");
            if(sdnv_length <= 0) {
                return 0;
            }
            offset += sdnv_length; record_size += sdnv_length;
        }

        /* Get 2 SDNVs for Creation Timestamp */
        sdnv_length = add_sdnv_time_to_tree(admin_record_tree, tvb, offset,
                                        "Bundle Creation Timestamp");
        if(sdnv_length <= 0) {
            return 0;
        }
        offset += sdnv_length; record_size += sdnv_length;

        timestamp_sequence = evaluate_sdnv(tvb, offset, &sdnv_length);
        timestamp_sequence_item = proto_tree_add_text(admin_record_tree, tvb, offset, sdnv_length, " ");

        if(timestamp_sequence < 0) {
            gint64 ts_seq;

            if((ts_seq = evaluate_sdnv_64(tvb, offset, &sdnv_length)) < 0) {
               proto_item_set_text(timestamp_sequence_item, "Timestamp Sequence Number: Error");
               return 0;
            }

            proto_item_set_text(timestamp_sequence_item,
                "Timestamp Sequence Number: 0x%" G_GINT64_MODIFIER "x", ts_seq);
        }
        else {
            proto_item_set_text(timestamp_sequence_item,
				"Timestamp Sequence Number: %d", timestamp_sequence);
        }
        offset += sdnv_length; record_size += sdnv_length;

        endpoint_length = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(endpoint_length < 0) {
            return 0;
        }
        proto_tree_add_text(admin_record_tree, tvb, offset, sdnv_length,
                                        "Endpoint Length: %d", endpoint_length);
        offset += sdnv_length; record_size += sdnv_length;

        /*
         * Endpoint name may not be null terminated. This routine is supposed
         * to add the null at the end of the string buffer.
         */
        string_ptr = tvb_get_ephemeral_string(tvb, offset, endpoint_length);
        proto_tree_add_text(admin_record_tree, tvb, offset, endpoint_length,
                                                "Bundle Endpoint ID: %s", string_ptr);
        offset += endpoint_length; record_size += endpoint_length;

        return record_size;
    }
    case ADMIN_REC_TYPE_CUSTODY_SIGNAL:
        proto_tree_add_text(admin_record_tree, tvb, offset, 1,
                                "Administrative Record Type: Custody Signal");
        ++record_size; ++offset;

        status = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(admin_record_tree, tvb, offset, 1,
                        "Custody Transfer Succeeded Flag: %d", (status >> 7) & 0x01);
        if((status & ADMIN_REC_CUSTODY_REASON_MASK) == 0) {
            proto_tree_add_text(admin_record_tree, tvb, offset, 1,
                                        "Reason Code: 0 (No Additional Information)");
        }
        else {
            proto_tree_add_text(admin_record_tree, tvb, offset, 1,
                                "Reason Code: 0x%x (%s)",
                                status & ADMIN_REC_CUSTODY_REASON_MASK,
                                val_to_str(status & ADMIN_REC_CUSTODY_REASON_MASK,
                                                custody_signal_reason_codes, "Invalid"));
        }
        ++record_size; ++offset;
        if(record_type & ADMIN_REC_FLAGS_FRAGMENT) {
            sdnv_length = add_sdnv_to_tree(admin_record_tree, tvb, offset,
                                                        "Fragment Offset");
            if(sdnv_length <= 0) {
                return 0;
            }
            offset += sdnv_length; record_size += sdnv_length;
            sdnv_length = add_sdnv_to_tree(admin_record_tree, tvb, offset,
                                                        "Fragment Length");
            if(sdnv_length <= 0) {
                return 0;
            }
            offset += sdnv_length; record_size += sdnv_length;
        }

        /* Signal Time */
        sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset,
                                                        "Bundle Signal Time");
        if(sdnv_length <= 0) {
            return 0;
        }
        offset += sdnv_length; record_size += sdnv_length;

        /* Timestamp copy */
        sdnv_length = add_sdnv_time_to_tree(admin_record_tree, tvb, offset,
                                                        "Bundle Creation Timestamp");
        if(sdnv_length <= 0) {
            return 0;
        }
        offset += sdnv_length; record_size += sdnv_length;

        timestamp_sequence = evaluate_sdnv(tvb, offset, &sdnv_length);
        timestamp_sequence_item = proto_tree_add_text(admin_record_tree, tvb, offset, sdnv_length, " ");

        if(timestamp_sequence < 0) {
            gint64 ts_seq;

            if((ts_seq = evaluate_sdnv_64(tvb, offset, &sdnv_length)) < 0) {
               proto_item_set_text(timestamp_sequence_item, "Timestamp Sequence Number: Error");
               return 0;
            }

            proto_item_set_text(timestamp_sequence_item,
               "Timestamp Sequence Number: 0x%" G_GINT64_MODIFIER "x", ts_seq);
        }
        else {
            proto_item_set_text(timestamp_sequence_item,
               "Timestamp Sequence Number: %d", timestamp_sequence);
        }

        offset += sdnv_length; record_size += sdnv_length;

        endpoint_length = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(endpoint_length < 0) {
            return 0;
        }
        proto_tree_add_text(admin_record_tree, tvb, offset, sdnv_length,
                                        "Endpoint Length: %d", endpoint_length);
        offset += sdnv_length; record_size += sdnv_length;
        string_ptr = tvb_get_ephemeral_string(tvb, offset, endpoint_length);
        proto_tree_add_text(admin_record_tree, tvb, offset, endpoint_length,
                                                "Bundle Endpoint ID: %s", string_ptr);
        offset += endpoint_length; record_size += endpoint_length;
        return record_size;

    }   /* End Switch */

    proto_tree_add_text(admin_record_tree, tvb, offset, 1,
                                "Administrative Record Type: Unknown");
    return 0;
}

/*
 * Return length of contact header or 0 on failure
 */

static int
dissect_contact_header(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *conv_tree, proto_item *conv_item)
{
    guint8 contact_hdr_flags;
    proto_item *contact_hdr_flag_item;
    proto_tree *contact_hdr_flag_tree;
    int eid_length;
    int sdnv_length;
    char *sptr;

    /*
     * I'm going to assume that if this is a contact header, the buffer
     * contains the complete header and that there are no other packets
     * in the buffer.
     */

    proto_tree_add_text(conv_tree, tvb, 0, 4, "Pkt Type: Contact Header");
    proto_tree_add_item(conv_tree, hf_contact_hdr_version, tvb, 4, 1, ENC_BIG_ENDIAN);

    /* Subtree to expand the bits in the Contact Header Flags */
    contact_hdr_flags = tvb_get_guint8(tvb, 5);
    contact_hdr_flag_item =
                proto_tree_add_item(conv_tree, hf_contact_hdr_flags, tvb, 5, 1, ENC_BIG_ENDIAN);
    contact_hdr_flag_tree =
                proto_item_add_subtree(contact_hdr_flag_item, ett_contact_hdr_flags);
    proto_tree_add_boolean(contact_hdr_flag_tree, hf_contact_hdr_flags_ack_req,
                                                tvb, 5, 1, contact_hdr_flags);
    proto_tree_add_boolean(contact_hdr_flag_tree, hf_contact_hdr_flags_frag_enable,
                                tvb, 5, 1, contact_hdr_flags);
    proto_tree_add_boolean(contact_hdr_flag_tree, hf_contact_hdr_flags_nak,
                                tvb, 5, 1, contact_hdr_flags);
    proto_tree_add_item(conv_tree, hf_contact_hdr_keep_alive, tvb, 6, 2, ENC_BIG_ENDIAN);

    /*
     * New format Contact header has length field followed by Bundle Header.
     */

    eid_length = evaluate_sdnv(tvb, 8, &sdnv_length);
    if(eid_length < 0) {
        col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error (Local EID Length)");
        return 0;
    }
    proto_tree_add_text(conv_tree, tvb, 8, sdnv_length,
                                "Local EID Length: %d", eid_length);
    proto_item_set_len(conv_item, sdnv_length + eid_length + 8);

    sptr = (char *) tvb_get_ephemeral_string(tvb, sdnv_length + 8, eid_length);
    proto_tree_add_text(conv_tree, tvb, sdnv_length + 8, eid_length, "Local EID: %s", sptr);

    return(sdnv_length + eid_length + 8);
}

static int
display_metadata_block(proto_tree *tree, tvbuff_t *tvb, int offset, gboolean *lastheader)
{
    proto_item *block_item;
    proto_tree *block_tree;
    int sdnv_length;
    int header_start;
    int block_length;
    guint8 type;
    int control_flags;
    proto_tree *block_flag_tree = NULL;
    int num_eid_ref = 0;
    int i = 0, ref_scheme = 0, ref_ssp = 0;

    type = tvb_get_guint8(tvb, offset);
    header_start = offset;      /*Used to compute total payload length*/
    offset = 0;
    block_item = proto_tree_add_text(tree, tvb, header_start + offset, -1, "Metadata Block");
    block_tree = proto_item_add_subtree(block_item, ett_metadata_hdr);

    proto_tree_add_text(block_tree, tvb, header_start + offset, 1, "Block Type: %d", type);
    ++offset;

    control_flags = evaluate_sdnv(tvb, header_start + offset, &sdnv_length);
    if(control_flags & BLOCK_CONTROL_LAST_BLOCK) {
        *lastheader = TRUE;
    } else {
        *lastheader = FALSE;
    }
    proto_tree_add_text(block_tree, tvb, header_start + offset, 1, "Block Flags: 0x%x", control_flags);
    offset += sdnv_length;

    block_flag_tree = proto_item_add_subtree(block_item, ett_block_flags);

    proto_tree_add_boolean(block_flag_tree, hf_block_control_replicate,
			   tvb, offset, sdnv_length, control_flags);
    proto_tree_add_boolean(block_flag_tree, hf_block_control_transmit_status,
			   tvb, offset, sdnv_length, control_flags);
    proto_tree_add_boolean(block_flag_tree, hf_block_control_delete_bundle,
			   tvb, offset, sdnv_length, control_flags);
    proto_tree_add_boolean(block_flag_tree, hf_block_control_last_block,
			   tvb, offset, sdnv_length, control_flags);
    proto_tree_add_boolean(block_flag_tree, hf_block_control_discard_block,
			   tvb, offset, sdnv_length, control_flags);
    proto_tree_add_boolean(block_flag_tree, hf_block_control_not_processed,
			   tvb, offset, sdnv_length, control_flags);
    proto_tree_add_boolean(block_flag_tree, hf_block_control_eid_reference,
			   tvb, offset, sdnv_length, control_flags);

    if (control_flags & BLOCK_CONTROL_EID_REFERENCE) {
    	num_eid_ref = evaluate_sdnv(tvb, header_start + offset, &sdnv_length);
    	offset += sdnv_length;

    	for (i = 0; i < num_eid_ref; i++)
    	{
    		ref_scheme = evaluate_sdnv(tvb, header_start + offset, &sdnv_length);
    		offset += sdnv_length;

    		ref_ssp = evaluate_sdnv(tvb, header_start + offset, &sdnv_length);
    		offset += sdnv_length;
    	}
    }

    block_length = evaluate_sdnv(tvb, header_start + offset, &sdnv_length);
    proto_item_set_len(block_item, offset + sdnv_length + block_length);
    if(block_length < 0) {
        proto_tree_add_text(block_tree, tvb, header_start + offset, sdnv_length, "Metadata Block Length: Error");
        return 0;
    }
    proto_tree_add_text(block_tree, tvb, header_start + offset, sdnv_length, "Block Length: %d", block_length);
    offset += (sdnv_length + block_length);

    return offset;
}

/*
 * SDNV has a zero in high-order bit position of last byte. The high-order
 * bit of all preceding bytes is set to one. This returns the numeric value
 * in an integer and sets the value of the second argument to the number of
 * bytes used to code the SDNV. A -1 is returned if the evaluation fails
 * (value exceeds maximum for signed integer). 0 is an acceptable value.
 */

#define SDNV_MASK       0x7f

/*3rd arg is number of bytes in field (returned)*/
int
evaluate_sdnv(tvbuff_t *tvb, int offset, int *bytecount)
{
    int value = 0;
    guint8 curbyte;

    *bytecount = 0;

    /*
     * Get 1st byte and continue to get them while high-order bit is 1
     */

    while((curbyte = tvb_get_guint8(tvb, offset)) & ~SDNV_MASK) {
        if(*bytecount >= (int) sizeof(int)) {
            *bytecount = 0;
            return -1;
        }
        value = value << 7;
        value |= (curbyte & SDNV_MASK);
        ++offset;
        ++*bytecount;
    }

    /*
     * Add in the byte whose high-order bit is 0 (last one)
     */

    value = value << 7;
    value |= (curbyte & SDNV_MASK);
    ++*bytecount;
    return value;
}

/* Special Function to evaluate 64 bit SDNVs */
gint64
evaluate_sdnv_64(tvbuff_t *tvb, int offset, int *bytecount)
{
    gint64 value = 0;
    guint8 curbyte;

    *bytecount = 0;

    /*
     * Get 1st byte and continue to get them while high-order bit is 1
     */

    while((curbyte = tvb_get_guint8(tvb, offset)) & ~SDNV_MASK) {
        if(*bytecount >= (int) sizeof(gint64)) {
            *bytecount = 0;
            return -1;
        }
        value = value << 7;
        value |= (curbyte & SDNV_MASK);
        ++offset;
        ++*bytecount;
    }

    /*
     * Add in the byte whose high-order bit is 0 (last one)
     */

    value = value << 7;
    value |= (curbyte & SDNV_MASK);
    ++*bytecount;
    return value;
}

static int
add_sdnv_to_tree(proto_tree *tree, tvbuff_t *tvb, int offset, const char *field_id)
{
    int sdnv_length;
    int sdnv_value;

    sdnv_value = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(sdnv_value < 0) {
        return 0;
    }
    proto_tree_add_text(tree, tvb, offset, sdnv_length, "%s: %d", field_id, sdnv_value);
    return sdnv_length;
}

/*
 * Adds the result of 2 SDNVs to tree: First SDNV is seconds, next is nanoseconds.
 * Returns bytes in both SDNVs or 0 if something goes wrong.
 */
static int
add_dtn_time_to_tree(proto_tree *tree, tvbuff_t *tvb, int offset, const char *field_id)
{
    int sdnv_length, sdnv2_length;
    int sdnv_value;
    time_t time_since_2000;
    char *time_string;

    sdnv_value = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(sdnv_value < 0) {
        return 0;
    }
    time_since_2000 = (time_t) (sdnv_value + 946684800);
    time_string = abs_time_secs_to_str(time_since_2000, ABSOLUTE_TIME_LOCAL, TRUE);
    proto_tree_add_text(tree, tvb, offset, sdnv_length,
                        "%s (sec): %d [%s]", field_id, sdnv_value, time_string);
    offset += sdnv_length;

    sdnv_value = evaluate_sdnv(tvb, offset, &sdnv2_length);
    if(sdnv_value < 0) {
        return 0;
    }
    proto_tree_add_text(tree, tvb, offset, sdnv2_length,
                                "%s (ns): %d", field_id, sdnv_value);
    return (sdnv_length + sdnv2_length);
}

/*
 * Adds the result of SDNV which is a time since 2000 to tree.
 * Returns bytes in SDNV or 0 if something goes wrong.
 */
static int
add_sdnv_time_to_tree(proto_tree *tree, tvbuff_t *tvb, int offset, const char *field_id)
{
    int sdnv_length;
    int sdnv_value;
    time_t time_since_2000;
    char *time_string;

    sdnv_value = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(sdnv_value < 0) {
        return 0;
    }
    time_since_2000 = (time_t) (sdnv_value + 946684800);
    time_string = abs_time_secs_to_str(time_since_2000, ABSOLUTE_TIME_LOCAL, TRUE);
    proto_tree_add_text(tree, tvb, offset, sdnv_length,
                        "%s: %d [%s]", field_id, sdnv_value, time_string);
    return sdnv_length;
}

static void
bundle_defragment_init(void) {
    fragment_table_init(&msg_fragment_table);
    reassembled_table_init(&msg_reassembled_table);
}

void
proto_register_bundle(void)
{

  static hf_register_info hf[] = {
    {&hf_bundle_pdu_version,
        {"Bundle Version", "bundle.version",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_contact_hdr_version,
        {"Version", "bundle.tcp_conv.contact_hdr.version",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_contact_hdr_flags,
        {"Flags", "bundle.tcp_conv.contact_hdr.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_contact_hdr_flags_ack_req,
        {"Bundle Acks Requested", "bundle.tcp_conv.contact_hdr.flags.ackreq",
                FT_BOOLEAN, 8, NULL, TCP_CONV_BUNDLE_ACK_FLAG, NULL, HFILL}
    },
    {&hf_contact_hdr_flags_frag_enable,
        {"Reactive Fragmentation Enabled", "bundle.tcp_conv.contact_hdr.flags.fragen",
                FT_BOOLEAN, 8, NULL, TCP_CONV_REACTIVE_FRAG_FLAG, NULL, HFILL}
    },
    {&hf_contact_hdr_flags_nak,
        {"Support Negative Acknowledgements", "bundle.tcp_conv.contact_hdr.flags.nak",
                FT_BOOLEAN, 8, NULL, TCP_CONV_CONNECTOR_RCVR_FLAG, NULL, HFILL}
    },
    {&hf_contact_hdr_keep_alive,
        {"Keep Alive", "bundle.tcp_conv.contact_hdr.keep_alive",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_tcp_convergence_data_procflags,
        {"TCP Convergence Data Flags", "bundle.tcp_conv.data.proc.flag",
                FT_UINT8, BASE_HEX, NULL, TCP_CONVERGENCE_DATA_FLAGS, NULL, HFILL}
    },
    {&hf_tcp_convergence_data_procflags_start,
        {"Segment contains start of bundle", "bundle.tcp_conv.data.proc.start",
                FT_BOOLEAN, 8, NULL, TCP_CONVERGENCE_DATA_START_FLAG, NULL, HFILL}
    },
    {&hf_tcp_convergence_data_procflags_end,
        {"Segment contains end of Bundle", "bundle.tcp_conv.data.proc.end",
                FT_BOOLEAN, 8, NULL, TCP_CONVERGENCE_DATA_END_FLAG, NULL, HFILL}
    },
    {&hf_tcp_convergence_shutdown_flags,
        {"TCP Convergence Shutdown Flags", "bundle.tcp_conv.shutdown.flags",
                FT_UINT8, BASE_HEX, NULL, TCP_CONVERGENCE_SHUTDOWN_FLAGS, NULL, HFILL}
    },
    {&hf_tcp_convergence_shutdown_flags_reason,
        {"Shutdown includes Reason Code", "bundle.tcp_conv.shutdown.reason.flag",
                FT_BOOLEAN, 8, NULL, TCP_CONVERGENCE_SHUTDOWN_REASON, NULL, HFILL}
    },
    {&hf_tcp_convergence_shutdown_flags_delay,
        {"Shutdown includes Reconnection Delay", "bundle.tcp_conv.shutdown.delay.flag",
                FT_BOOLEAN, 8, NULL, TCP_CONVERGENCE_SHUTDOWN_DELAY, NULL, HFILL}
    },
    {&hf_tcp_convergence_shutdown_reason,
        {"Shutdown Reason Code", "bundle.tcp_conv.shutdown.reason",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_tcp_convergence_shutdown_delay,
        {"Shutdown Reconnection Delay", "bundle.tcp_conv.shutdown.delay",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },

    {&hf_msg_fragments,
        {"Message Fragments", "bundle.msg.fragments",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_msg_fragment,
        {"Message Fragment", "bundle.msg.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_msg_fragment_overlap,
        {"Message fragment overlap", "bundle.msg.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_msg_fragment_overlap_conflicts,
        {"Message fragment overlapping with conflicting data",
         "bundle.msg.fragment.overlap.conflicts",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_msg_fragment_multiple_tails,
        {"Message has multiple tails", "bundle.msg.fragment.multiple_tails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_msg_fragment_too_long_fragment,
        {"Message fragment too long", "bundle.msg.fragment.too_long_fragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_msg_fragment_error,
        {"Message defragmentation error", "bundle.msg.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_msg_fragment_count,
        {"Message fragment count", "bundle.msg.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_msg_reassembled_in,
        {"Reassembled in", "bundle.msg.reassembled.in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_msg_reassembled_length,
        {"Reassembled DTN length", "bundle.msg.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_procflags,
        {"Primary Header Processing Flags", "bundle.primary.proc.flag",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_procflags_fragment,
        {"Bundle is a Fragment", "bundle.primary.proc.frag",
                FT_BOOLEAN, 8, NULL, BUNDLE_PROCFLAGS_FRAG_MASK, NULL, HFILL}
    },
    {&hf_bundle_procflags_admin,
        {"Administrative Record", "bundle.primary.proc.admin",
                FT_BOOLEAN, 8, NULL, BUNDLE_PROCFLAGS_ADMIN_MASK, NULL, HFILL}
    },
    {&hf_bundle_procflags_dont_fragment,
        {"Do Not Fragment Bundle", "bundle.primary.proc.dontfrag",
                FT_BOOLEAN, 8, NULL, BUNDLE_PROCFLAGS_DONTFRAG_MASK, NULL, HFILL}
    },
    {&hf_bundle_procflags_cust_xfer_req,
        {"Request Custody Transfer", "bundle.primary.proc.xferreq",
                FT_BOOLEAN, 8, NULL, BUNDLE_PROCFLAGS_XFERREQ_MASK, NULL, HFILL}
    },
    {&hf_bundle_procflags_dest_singleton,
        {"Destination is Singleton", "bundle.primary.proc.single",
                FT_BOOLEAN, 8, NULL, BUNDLE_PROCFLAGS_SINGLETON_MASK, NULL, HFILL}
    },
    {&hf_bundle_procflags_application_ack,
        {"Request Acknowledgement by Application", "bundle.primary.proc.ack",
                FT_BOOLEAN, 8, NULL, BUNDLE_PROCFLAGS_APP_ACK_MASK, NULL, HFILL}
    },
    {&hf_bundle_control_flags,
        {"Bundle Processing Control Flags", "bundle.primary.proc.flag",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_procflags_general,
        {"General Flags", "bundle.primary.proc.gen",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_procflags_cos,
        {"Cloass of Service Flags", "bundle.primary.proc.cos",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_procflags_status,
        {"Status Report Flags", "bundle.primary.proc.status",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_cosflags,
        {"Primary Header COS Flags", "bundle.primary.cos.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_cosflags_priority,
        {"Priority", "bundle.primary.cos.priority",
                FT_UINT8, BASE_DEC, NULL, BUNDLE_COSFLAGS_PRIORITY_MASK, NULL, HFILL}
    },
    {&hf_bundle_srrflags,
        {"Primary Header Report Request Flags", "bundle.primary.srr.flag",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_srrflags_report_receipt,
        {"Request Reception Report", "bundle.primary.srr.report",
                FT_BOOLEAN, 8, NULL, BUNDLE_SRRFLAGS_REPORT_MASK, NULL, HFILL}
    },
    {&hf_bundle_srrflags_report_cust_accept,
        {"Request Report of Custody Acceptance", "bundle.primary.srr.custaccept",
                FT_BOOLEAN, 8, NULL, BUNDLE_SRRFLAGS_CUSTODY_MASK, NULL, HFILL}
    },
    {&hf_bundle_srrflags_report_forward,
        {"Request Report of Bundle Forwarding", "bundle.primary.srr.forward",
                FT_BOOLEAN, 8, NULL, BUNDLE_SRRFLAGS_FORWARD_MASK, NULL, HFILL}
    },
    {&hf_bundle_srrflags_report_delivery,
        {"Request Report of Bundle Delivery", "bundle.primary.srr.delivery",
                FT_BOOLEAN, 8, NULL, BUNDLE_SRRFLAGS_DELIVERY_MASK, NULL, HFILL}
    },
    {&hf_bundle_srrflags_report_deletion,
        {"Request Report of Bundle Deletion", "bundle.primary.srr.delete",
                FT_BOOLEAN, 8, NULL, BUNDLE_SRRFLAGS_DELETION_MASK, NULL, HFILL}
    },
    {&hf_bundle_srrflags_report_ack,
        {"Request Report of Application Ack", "bundle.primary.srr.ack",
                FT_BOOLEAN, 8, NULL, BUNDLE_SRRFLAGS_ACK_MASK, NULL, HFILL}
    },
    {&hf_bundle_primary_header_len,
        {"Bundle Header Length", "bundle.primary.len",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_dest_scheme_offset,
        {"Destination Scheme Offset", "bundle.primary.destschemeoff",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_dest_ssp_offset,
        {"Destination SSP Offset", "bundle.primary.destssspoff",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_source_scheme_offset,
        {"Source Scheme Offset", "bundle.primary.srcschemeoff",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_source_ssp_offset,
        {"Source SSP Offset", "bundle.primary.srcsspoff",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_report_scheme_offset,
        {"Report Scheme Offset", "bundle.primary.rptschemeoff",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_report_ssp_offset,
        {"Report SSP Offset", "bundle.primary.rptsspoff",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_cust_scheme_offset,
        {"Custodian Scheme Offset", "bundle.primary.custschemeoff",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_cust_ssp_offset,
        {"Custodian SSP Offset", "bundle.primary.custsspoff",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_dest_scheme,
        {"Destination Scheme", "bundle.primary.destination_scheme",
                FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_dest_ssp,
        {"Destination", "bundle.primary.destination",
                FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_source_scheme,
        {"Source Scheme", "bundle.primary.source_scheme",
                FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_source_ssp,
        {"Source", "bundle.primary.source",
                FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_report_scheme,
        {"Report Scheme", "bundle.primary.report_scheme",
                FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_report_ssp,
        {"Report", "bundle.primary.report",
                FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_custodian_scheme,
        {"Custodian Scheme", "bundle.primary.custodian_scheme",
                FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_custodian_ssp,
        {"Custodian", "bundle.primary.custodian",
                FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_creation_timestamp,
        {"Creation Timestamp", "bundle.primary.timestamp",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_lifetime,
        {"Lifetime", "bundle.primary.lifetime",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_payload_flags,
        {"Payload Header Processing Flags", "bundle.payload.proc.flag",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_payload_flags_replicate_hdr,
        {"Replicate Header in Every Fragment", "bundle.payload.proc.replicate",
                FT_BOOLEAN, 8, NULL, PAYLOAD_PROCFLAGS_REPLICATE_MASK, NULL, HFILL}
    },
    {&hf_bundle_payload_flags_xmit_report,
        {"Report if Can't Process Header", "bundle.payload.proc.report",
                FT_BOOLEAN, 8, NULL, PAYLOAD_PROCFLAGS_XMIT_STATUS, NULL, HFILL}
    },
    {&hf_bundle_payload_flags_discard_on_fail,
        {"Discard if Can't Process Header", "bundle.payload.proc.discard",
                FT_BOOLEAN, 8, NULL, PAYLOAD_PROCFLAGS_DISCARD_FAILURE, NULL, HFILL}
    },
    {&hf_bundle_payload_flags_last_header,
        {"Last Header", "bundle.payload.proc.lastheader",
                FT_BOOLEAN, 8, NULL, PAYLOAD_PROCFLAGS_LAST_HEADER, NULL, HFILL}
    },
    {&hf_bundle_admin_statflags,
        {"Administrative Record Status Flags", "bundle.admin.status.flag",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_admin_rcvd,
        {"Reporting Node Received Bundle", "bundle.admin.status.rcvd",
                FT_BOOLEAN, 8, NULL, ADMIN_STATUS_FLAGS_RECEIVED, NULL, HFILL}
    },
    {&hf_bundle_admin_accepted,
        {"Reporting Node Accepted Custody", "bundle.admin.status.accept",
                FT_BOOLEAN, 8, NULL, ADMIN_STATUS_FLAGS_ACCEPTED, NULL, HFILL}
    },
    {&hf_bundle_admin_forwarded,
        {"Reporting Node Forwarded Bundle", "bundle.admin.status.forward",
                FT_BOOLEAN, 8, NULL, ADMIN_STATUS_FLAGS_FORWARDED, NULL, HFILL}
    },
    {&hf_bundle_admin_delivered,
        {"Reporting Node Delivered Bundle", "bundle.admin.status.delivered",
                FT_BOOLEAN, 8, NULL, ADMIN_STATUS_FLAGS_DELIVERED, NULL, HFILL}
    },
    {&hf_bundle_admin_deleted,
        {"Reporting Node Deleted Bundle", "bundle.admin.status.delete",
                FT_BOOLEAN, 8, NULL, ADMIN_STATUS_FLAGS_DELETED, NULL, HFILL}
    },
    {&hf_bundle_admin_acked,
        {"Acknowledged by Application", "bundle.admin.status.ack",
                FT_BOOLEAN, 8, NULL, ADMIN_STATUS_FLAGS_ACKNOWLEDGED, NULL, HFILL}
    },
    {&hf_bundle_admin_receipt_time,
        {"Time of Receipt", "bundle.admin.status.receipttime",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_admin_accept_time,
        {"Time of Custody Acceptance", "bundle.admin.status.accepttime",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_admin_forward_time,
        {"Time of Forwarding", "bundle.admin.status.forwardtime",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_admin_delivery_time,
        {"Time of Delivery", "bundle.admin.status.deliverytime",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_admin_delete_time,
        {"Time of Deletion", "bundle.admin.status.deletetime",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_admin_ack_time,
        {"Time of Acknowledgement", "bundle.admin.status.acktime",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_admin_timestamp_copy,
        {"Copy of Creation Timestamp", "bundle.admin.status.timecopy",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_bundle_admin_signal_time,
        {"Time of Signal", "bundle.admin.signal.time",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_block_control_flags,
        {"Block Processing Control Flags", "bundle.block.control.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_block_control_replicate,
        {"Replicate Block in Every Fragment", "bundle.block.control.replicate",
                FT_BOOLEAN, 8, NULL, BLOCK_CONTROL_REPLICATE, NULL, HFILL}
    },
    {&hf_block_control_transmit_status,
        {"Transmit Status if Block Can't be Processeed", "bundle.block.control.status",
                FT_BOOLEAN, 8, NULL, BLOCK_CONTROL_TRANSMIT_STATUS, NULL, HFILL}
    },
    {&hf_block_control_delete_bundle,
        {"Delete Bundle if Block Can't be Processeed", "bundle.block.control.delete",
                FT_BOOLEAN, 8, NULL, BLOCK_CONTROL_DELETE_BUNDLE, NULL, HFILL}
    },
    {&hf_block_control_last_block,
        {"Last Block", "bundle.block.control.last",
                FT_BOOLEAN, 8, NULL, BLOCK_CONTROL_LAST_BLOCK, NULL, HFILL}
    },
    {&hf_block_control_discard_block,
        {"Discard Block If Can't Process", "bundle.block.control.discard",
                FT_BOOLEAN, 8, NULL, BLOCK_CONTROL_DISCARD_BLOCK, NULL, HFILL}
    },
    {&hf_block_control_not_processed,
        {"Block Was Forwarded Without Processing", "bundle.block.control.process",
                FT_BOOLEAN, 8, NULL, BLOCK_CONTROL_NOT_PROCESSED, NULL, HFILL}
    },
    {&hf_block_control_eid_reference,
        {"Block Contains an EID-reference Field", "bundle.block.control.eid",
                FT_BOOLEAN, 8, NULL, BLOCK_CONTROL_EID_REFERENCE, NULL, HFILL}
    }
  };

  static gint *ett[] = {
    &ett_bundle,
    &ett_tcp_conv,
    &ett_tcp_conv_hdr,
    &ett_msg_fragment,
    &ett_msg_fragments,
    &ett_bundle_hdr,
    &ett_primary_hdr,
    &ett_proc_flags,
    &ett_gen_flags,
    &ett_cos_flags,
    &ett_srr_flags,
    &ett_dictionary,
    &ett_payload_hdr,
    &ett_payload_flags,
    &ett_block_flags,
    &ett_contact_hdr_flags,
    &ett_conv_flags,
    &ett_shutdown_flags,
    &ett_admin_record,
    &ett_admin_rec_status,
    &ett_metadata_hdr
  };

  module_t *bundle_module;

  proto_bundle = proto_register_protocol (
                        "Bundle Protocol",
                        "Bundle",
                        "bundle"
                   );
  bundle_module = prefs_register_protocol(proto_bundle, proto_reg_handoff_bundle);

  proto_tcp_conv = proto_register_protocol (
                        "DTN TCP Convergence Layer Protocol",
                        "TCPCL",
                        "tcpcl"
                );

  prefs_register_uint_preference(bundle_module, "tcp.port",
                                        "Bundle Protocol TCP Port",
                                        "TCP Port to Accept Bundle Protocol Connections",
                                        10,
                                        &bundle_tcp_port);

  prefs_register_uint_preference(bundle_module, "udp.port",
                                        "Bundle Protocol UDP Port",
                                        "UDP Port to Accept Bundle Protocol Connections",
                                        10,
                                        &bundle_udp_port);

  proto_register_field_array(proto_bundle, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(bundle_defragment_init);
}

void
proto_reg_handoff_bundle(void)
{
    static dissector_handle_t tcp_bundle_handle;
    static dissector_handle_t udp_bundle_handle;
    static guint tcp_port;
    static guint udp_port;

    static int Initialized = FALSE;

    if (!Initialized) {
        tcp_bundle_handle = create_dissector_handle(dissect_tcp_bundle, proto_bundle);
        udp_bundle_handle = create_dissector_handle(dissect_udp_bundle, proto_bundle);
        Initialized = TRUE;
    }
    else {
        dissector_delete_uint("tcp.port", tcp_port, tcp_bundle_handle);
        dissector_delete_uint("udp.port", udp_port, udp_bundle_handle);
    }
    tcp_port = bundle_tcp_port;
    udp_port = bundle_udp_port;
    dissector_add_uint("tcp.port", tcp_port, tcp_bundle_handle);
    dissector_add_uint("udp.port", udp_port, udp_bundle_handle);
}
