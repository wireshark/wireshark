/* packet-dtn.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Specification reference:
 * RFC 5050
 * http://tools.ietf.org/html/rfc5050
 */

/*
 *    Modifications were made to this file under designation MFS-33289-1 and
 *    are Copyright 2015 United States Government as represented by NASA
 *       Marshall Space Flight Center. All Rights Reserved.
 *
 *    Released under the GNU GPL with NASA legal approval granted 2016-06-10.
 *
 *    The subject software is provided "AS IS" WITHOUT ANY WARRANTY of any kind,
 *    either expressed, implied or statutory and this agreement does not,
 *    in any manner, constitute an endorsement by government agency of any
 *    results, designs or products resulting from use of the subject software.
 *    See the Agreement for the specific language governing permissions and
 *    limitations.
 */

#include "config.h"

#include <stdio.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include "packet-dtn.h"
#include "packet-tcp.h"

static int dissect_admin_record(proto_tree *primary_tree, tvbuff_t *tvb, packet_info *pinfo,
                                int offset, int payload_length, gboolean* success);

/* For Reassembling TCP Convergence Layer segments */
static reassembly_table msg_reassembly_table;

static const char magic[] = {'d', 't', 'n', '!'};

static int proto_bundle = -1;
static int proto_tcp_conv = -1;
static int hf_bundle_pdu_version = -1;

/* TCP Convergence Header Variables */
static int hf_tcp_convergence_pkt_type = -1;

static int hf_contact_hdr_version = -1;
static int hf_contact_hdr_flags = -1;
static int hf_contact_hdr_keep_alive = -1;
static int hf_contact_hdr_flags_ack_req = -1;
static int hf_contact_hdr_flags_frag_enable = -1;
static int hf_contact_hdr_flags_nak = -1;
static int hf_contact_hdr_magic = -1;
static int hf_contact_hdr_local_eid_length = -1;
static int hf_contact_hdr_local_eid = -1;

/* TCP Convergence Data Header Variables */
static int hf_tcp_convergence_data_procflags = -1;
static int hf_tcp_convergence_data_procflags_start = -1;
static int hf_tcp_convergence_data_procflags_end = -1;
static int hf_tcp_convergence_data_segment_length = -1;

/* TCP Convergence Ack Variables */
static int hf_tcp_convergence_ack_length = -1;

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

/* Primary Header Fields*/
static int hf_bundle_primary_header_len = -1;
static int hf_bundle_primary_dictionary_len = -1;
static int hf_bundle_primary_timestamp = -1;
static int hf_bundle_primary_fragment_offset = -1;
static int hf_bundle_primary_total_adu_len = -1;
static int hf_bundle_primary_timestamp_seq_num64 = -1;
static int hf_bundle_primary_timestamp_seq_num32 = -1;

static int hf_bundle_dest_scheme_offset_u16 = -1;
static int hf_bundle_dest_scheme_offset_i32 = -1;
static int hf_bundle_dest_ssp_offset_u16 = -1;
static int hf_bundle_dest_ssp_offset_i32 = -1;
static int hf_bundle_source_scheme_offset_u16 = -1;
static int hf_bundle_source_scheme_offset_i32 = -1;
static int hf_bundle_source_ssp_offset_u16 = -1;
static int hf_bundle_source_ssp_offset_i32 = -1;
static int hf_bundle_report_scheme_offset_u16 = -1;
static int hf_bundle_report_scheme_offset_i32 = -1;
static int hf_bundle_report_ssp_offset_u16 = -1;
static int hf_bundle_report_ssp_offset_i32 = -1;
static int hf_bundle_cust_scheme_offset_u16 = -1;
static int hf_bundle_cust_scheme_offset_i32 = -1;
static int hf_bundle_cust_ssp_offset_u16 = -1;
static int hf_bundle_cust_ssp_offset_i32 = -1;

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
static int hf_bundle_lifetime_sdnv = -1;

/* Secondary Header Processing Flag Variables */
static int hf_bundle_payload_length = -1;
static int hf_bundle_payload_header_type = -1;
static int hf_bundle_payload_data = -1;
static int hf_bundle_payload_flags = -1;
static int hf_bundle_payload_flags_replicate_hdr = -1;
static int hf_bundle_payload_flags_xmit_report = -1;
static int hf_bundle_payload_flags_discard_on_fail = -1;
static int hf_bundle_payload_flags_last_header = -1;

/* Block Processing Control Flag Variables (Version 5) */
static int hf_block_control_flags = -1;
static int hf_block_control_flags_sdnv = -1;
static int hf_block_control_replicate = -1;
static int hf_block_control_transmit_status = -1;
static int hf_block_control_delete_bundle = -1;
static int hf_block_control_last_block = -1;
static int hf_block_control_discard_block = -1;
static int hf_block_control_not_processed = -1;
static int hf_block_control_eid_reference = -1;
static int hf_block_control_block_length = -1;
static int hf_block_control_block_cteb_custody_id = -1;
static int hf_block_control_block_cteb_creator_custodian_eid = -1;

/* Non-Primary Block Type Code Variable */
static int hf_bundle_block_type_code = -1;
static int hf_bundle_unprocessed_block_data = -1;

/* ECOS Flag Variables */
static int hf_ecos_flags = -1;
static int hf_ecos_flags_critical = -1;
static int hf_ecos_flags_streaming = -1;
static int hf_ecos_flags_flowlabel = -1;
static int hf_ecos_flags_reliable = -1;
static int hf_ecos_flow_label = -1;

static int hf_ecos_ordinal = -1;

/* Administrative Record Variables */
static int hf_bundle_admin_record_type = -1;
static int hf_bundle_admin_record_fragment = -1;
static int hf_bundle_admin_statflags = -1;
static int hf_bundle_admin_rcvd = -1;
static int hf_bundle_admin_accepted = -1;
static int hf_bundle_admin_forwarded = -1;
static int hf_bundle_admin_delivered = -1;
static int hf_bundle_admin_deleted = -1;
static int hf_bundle_admin_acked = -1;
static int hf_bundle_admin_fragment_offset = -1;
static int hf_bundle_admin_fragment_length = -1;
static int hf_bundle_admin_timestamp_seq_num64 = -1;
static int hf_bundle_admin_timestamp_seq_num32 = -1;
static int hf_bundle_admin_endpoint_length = -1;
static int hf_bundle_admin_endpoint_id = -1;

static int hf_bundle_admin_receipt_time = -1;
static int hf_bundle_admin_accept_time = -1;
static int hf_bundle_admin_forward_time = -1;
static int hf_bundle_admin_delivery_time = -1;
static int hf_bundle_admin_delete_time = -1;
static int hf_bundle_admin_ack_time = -1;
static int hf_bundle_admin_timestamp_copy = -1;
static int hf_bundle_admin_signal_time = -1;
static int hf_bundle_status_report_reason_code = -1;
static int hf_bundle_custody_trf_succ_flg = -1;
static int hf_bundle_custody_signal_reason = -1;
static int hf_bundle_custody_id_range_start = -1;
static int hf_bundle_custody_id_range_end = -1;

/* Tree Node Variables */
static gint ett_bundle = -1;
static gint ett_conv_flags = -1;
static gint ett_shutdown_flags = -1;
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

static gint ett_tcp_conv = -1;
static gint ett_tcp_conv_hdr = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;


static expert_field ei_bundle_payload_length = EI_INIT;
static expert_field ei_bundle_control_flags_length = EI_INIT;
static expert_field ei_bundle_block_control_flags = EI_INIT;
static expert_field ei_bundle_sdnv_length = EI_INIT;
static expert_field ei_bundle_timestamp_seq_num = EI_INIT;
static expert_field ei_bundle_offset_error = EI_INIT;
static expert_field ei_block_control_block_cteb_invalid = EI_INIT;
static expert_field ei_block_control_block_cteb_valid = EI_INIT;

static expert_field ei_tcp_convergence_data_flags = EI_INIT;
static expert_field ei_tcp_convergence_segment_length = EI_INIT;
static expert_field ei_tcp_convergence_ack_length = EI_INIT;


static dissector_handle_t bundle_handle;

static guint bundle_tcp_port = 4556;
static guint bundle_udp_port = 4556;

typedef struct dictionary_data {
    int bundle_header_dict_length;

    int dest_scheme_offset;
    int dst_scheme_pos;
    int dst_scheme_len;
    int source_scheme_offset;
    int src_scheme_pos;
    int src_scheme_len;
    int report_scheme_offset;
    int rpt_scheme_pos;
    int rpt_scheme_len;
    int cust_scheme_offset;
    int cust_scheme_pos;
    int cust_scheme_len;
    int dest_ssp_offset;
    int dst_ssp_len;
    int source_ssp_offset;
    int src_ssp_len;
    int report_ssp_offset;
    int rpt_ssp_len;
    int cust_ssp_offset;
    int cust_ssp_len;

} dictionary_data_t;


static const value_string packet_type_vals[] = {
    {((TCP_CONVERGENCE_DATA_SEGMENT>>4)  & 0x0F), "Data"},
    {((TCP_CONVERGENCE_ACK_SEGMENT>>4)   & 0x0F), "Ack"},
    {((TCP_CONVERGENCE_REFUSE_BUNDLE>>4) & 0x0F), "Refuse Bundle"},
    {((TCP_CONVERGENCE_KEEP_ALIVE>>4)    & 0x0F), "Keep Alive"},
    {((TCP_CONVERGENCE_SHUTDOWN>>4)      & 0x0F), "Shutdown"},
    {0, NULL}
};

static const value_string admin_record_type_vals[] = {
    {ADMIN_REC_TYPE_STATUS_REPORT, "Bundle Status Report"},
    {ADMIN_REC_TYPE_CUSTODY_SIGNAL, "Custody Signal"},
    {ADMIN_REC_TYPE_AGGREGATE_CUSTODY_SIGNAL, "Aggregate Custody Signal"},
    {ADMIN_REC_TYPE_ANNOUNCE_BUNDLE, "Announce Record (Contact)"},
    {0, NULL}
};

static const value_string custody_signal_reason_codes[] = {
    {0x0, "No Additional Information"},
    {0x3, "Redundant Reception"},
    {0x4, "Depleted Storage"},
    {0x5, "Destination Endpoint ID Unintelligible"},
    {0x6, "No Known Route to Destination"},
    {0x7, "No Timely Contact with Next Node on Route"},
    {0x8, "Header Unintelligible"},
    {0, NULL}
};

static const value_string status_report_reason_codes[] = {
    {0x0, "No Additional Information"},
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

static const value_string bundle_block_type_codes[] = {
    {0x01, "Bundle Payload Block"},
    {0x02, "Bundle Authentication Block"},
    {0x03, "Payload Integrity Block"},
    {0x04, "Payload Confidentiality Block"},
    {0x05, "Previous-Hop Insertion Block"},
    {0x08, "Metadata Extension Block"},
    {0x09, "Extension Security Block"},
    {0x0a, "Custody Transfer Enhancement Block"},
    {0x13, "Extended Class of Service Block"},
    {0, NULL}
};

static const value_string cosflags_priority_vals[] = {
    {0x00, "Bulk"},
    {0x01, "Normal"},
    {0x02, "Expedited"},
    {0x03, "Invalid (Reserved)"},
    {0, NULL}
};

/*
 * SDNV has a zero in high-order bit position of last byte. The high-order
 * bit of all preceding bytes is set to one. This returns the numeric value
 * in an integer and sets the value of the second argument to the number of
 * bytes used to code the SDNV. A -1 is returned if the evaluation fails
 * (value exceeds maximum for signed integer). 0 is an acceptable value.
 */

#define SDNV_MASK       0x7f

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
    /* Reassembled data field */
    NULL,
    /*Tag*/
    "Message fragments"
};

/*
 * Adds the result of 2 SDNVs to tree: First SDNV is seconds, next is nanoseconds.
 * Returns bytes in both SDNVs or 0 if something goes wrong.
 */
static int
add_dtn_time_to_tree(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_dtn_time)
{
    nstime_t dtn_time;
    int      sdnv_length, sdnv2_length;
    int      sdnv_value;
    int      orig_offset;

    orig_offset = offset;

    sdnv_value = evaluate_sdnv(tvb, offset, &sdnv_length);
    if (sdnv_value < 0) {
        return 0;
    }

    dtn_time.secs = (time_t)(sdnv_value + 946684800);
    offset += sdnv_length;

    dtn_time.nsecs = evaluate_sdnv(tvb, offset, &sdnv2_length);
    if (dtn_time.nsecs < 0) {
        return 0;
    }

    proto_tree_add_time(tree, hf_dtn_time, tvb, orig_offset, sdnv_length + sdnv2_length, &dtn_time);

    return (sdnv_length + sdnv2_length);
}

/*
 * Adds the result of SDNV which is a time since 2000 to tree.
 * Returns bytes in SDNV or 0 if something goes wrong.
 */
static int
add_sdnv_time_to_tree(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_sdnv_time)
{
    nstime_t dtn_time;
    int      sdnv_length;
    int      sdnv_value;

    sdnv_value = evaluate_sdnv(tvb, offset, &sdnv_length);
    if (sdnv_value < 0) {
        return 0;
    }

    dtn_time.secs = (time_t)(sdnv_value + 946684800);
    dtn_time.nsecs = 0;
    proto_tree_add_time(tree, hf_sdnv_time, tvb, offset, sdnv_length, &dtn_time);

    return sdnv_length;
}

static int
add_sdnv_to_tree(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, int offset, int hf_sdnv)
{
    proto_item *ti;
    int         sdnv_length;
    int         sdnv_value;

    sdnv_value = evaluate_sdnv(tvb, offset, &sdnv_length);
    ti = proto_tree_add_int(tree, hf_sdnv, tvb, offset, sdnv_length, sdnv_value);
    if (sdnv_value < 0) {
        expert_add_info(pinfo, ti, &ei_bundle_sdnv_length);
        return 0;
    }
    return sdnv_length;
}

/*
 * Pull out stuff from the dictionary
 */
static int
dissect_dictionary(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, dictionary_data_t* dict_data,
                    guint8 pri_hdr_procflags, gchar **bundle_custodian, int creation_timestamp, int timestamp_sequence)
{
    proto_tree  *dict_tree;
    const gchar* col_text;

    col_text = col_get_text(pinfo->cinfo, COL_INFO);

    dict_tree = proto_tree_add_subtree(tree, tvb, offset, dict_data->bundle_header_dict_length, ett_dictionary, NULL, "Dictionary");

    /*
     * If the dictionary length is 0, then the CBHE block compression method is applied. (RFC6260)
     * So the scheme offset is the node number and the ssp offset is the service number.
     * If destination scheme offset is 2 and destination ssp offset is 1, then the EID is
     * ipn:2.1
     */
    if (dict_data->bundle_header_dict_length == 0)
    {
        const gchar *src_node, *dst_node;

        /*
         * Destination info
         */
        if (dict_data->dest_scheme_offset == 0 && dict_data->dest_ssp_offset == 0)
        {
            proto_tree_add_string(dict_tree, hf_bundle_dest_scheme, tvb, 0, 0, DTN_SCHEME_STR);
            proto_tree_add_string(dict_tree, hf_bundle_dest_ssp, tvb, dict_data->dst_scheme_pos,
                            dict_data->dst_scheme_len + dict_data->dst_ssp_len, "none");

            dst_node = "dtn:none";
        }
        else
        {
            proto_tree_add_string(dict_tree, hf_bundle_dest_scheme, tvb, 0, 0, IPN_SCHEME_STR);
            proto_tree_add_string(dict_tree, hf_bundle_dest_ssp, tvb, dict_data->dst_scheme_pos,
                            dict_data->dst_scheme_len + dict_data->dst_ssp_len,
                            wmem_strdup_printf(wmem_packet_scope(), "%d.%d",dict_data->dest_scheme_offset,dict_data->dest_ssp_offset));

            dst_node = wmem_strdup_printf(wmem_packet_scope(), "%s:%d.%d", IPN_SCHEME_STR,
                                          dict_data->dest_scheme_offset, dict_data->dest_ssp_offset);
        }

        /*
         * Source info
         */
        if (dict_data->source_scheme_offset == 0 && dict_data->source_ssp_offset == 0)
        {
            proto_tree_add_string(dict_tree, hf_bundle_source_scheme, tvb, 0, 0, DTN_SCHEME_STR);
            proto_tree_add_string(dict_tree, hf_bundle_source_ssp, tvb, dict_data->src_scheme_pos,
                            dict_data->src_scheme_len + dict_data->src_ssp_len, "none");

            src_node = "dtn:none";
        }
        else
        {
            proto_tree_add_string(dict_tree, hf_bundle_source_scheme, tvb, 0, 0, IPN_SCHEME_STR);
            proto_tree_add_string(dict_tree, hf_bundle_source_ssp, tvb, dict_data->src_scheme_pos,
                            dict_data->src_scheme_len + dict_data->src_ssp_len,
                            wmem_strdup_printf(wmem_packet_scope(), "%d.%d", dict_data->source_scheme_offset, dict_data->source_ssp_offset));

            src_node = wmem_strdup_printf(wmem_packet_scope(), "%s:%d.%d", IPN_SCHEME_STR,
                                          dict_data->source_scheme_offset, dict_data->source_ssp_offset);
        }

        /*
         * Report to info
         */
        if (dict_data->report_scheme_offset == 0 && dict_data->report_ssp_offset == 0)
        {
            proto_tree_add_string(dict_tree, hf_bundle_report_scheme, tvb, 0, 0, DTN_SCHEME_STR);
            proto_tree_add_string(dict_tree, hf_bundle_report_ssp, tvb, dict_data->rpt_scheme_pos,
                            dict_data->rpt_scheme_len + dict_data->rpt_ssp_len, "none");
        }
        else
        {
            proto_tree_add_string(dict_tree, hf_bundle_report_scheme, tvb, 0, 0, IPN_SCHEME_STR);
            proto_tree_add_string(dict_tree, hf_bundle_report_ssp, tvb, dict_data->rpt_scheme_pos,
                            dict_data->rpt_scheme_len + dict_data->rpt_ssp_len,
                            wmem_strdup_printf(wmem_packet_scope(), "%d.%d", dict_data->report_scheme_offset, dict_data->report_ssp_offset));
        }

        /*
         * Custodian info
         */
        if (dict_data->cust_scheme_offset == 0 && dict_data->cust_ssp_offset == 0)
        {
            proto_tree_add_string(dict_tree, hf_bundle_custodian_scheme, tvb, 0, 0, DTN_SCHEME_STR);
            proto_tree_add_string(dict_tree, hf_bundle_custodian_ssp, tvb, dict_data->cust_scheme_pos,
                            dict_data->cust_scheme_len + dict_data->cust_ssp_len, "none");
        }
        else
        {
            proto_tree_add_string(dict_tree, hf_bundle_custodian_scheme, tvb, 0, 0, IPN_SCHEME_STR);
            proto_tree_add_string(dict_tree, hf_bundle_custodian_ssp, tvb, dict_data->cust_scheme_pos,
                            dict_data->cust_scheme_len + dict_data->cust_ssp_len,
                            wmem_strdup_printf(wmem_packet_scope(), "%d.%d", dict_data->cust_scheme_offset, dict_data->cust_ssp_offset));
        }

        /* remember custodian, for use in checking cteb validity */
        col_set_writable(pinfo->cinfo, COL_INFO, TRUE);
        col_clear_fence(pinfo->cinfo, COL_INFO);
        if (col_text && strstr(col_text, " > ")) {
            if (! strstr(col_text, "[multiple]")) {
                col_append_str(pinfo->cinfo, COL_INFO, ", [multiple]");
            }
        } else {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s > %s %d.%d", src_node, dst_node, creation_timestamp, timestamp_sequence);
        }
        col_set_fence(pinfo->cinfo, COL_INFO);

        *bundle_custodian = wmem_strdup_printf(wmem_packet_scope(), "%s:%d.%d", IPN_SCHEME_STR,
                                               dict_data->cust_scheme_offset, dict_data->cust_ssp_offset);
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

        proto_tree_add_item(dict_tree, hf_bundle_dest_scheme,
                            tvb, offset + dict_data->dest_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_dest_ssp,
                            tvb, offset + dict_data->dest_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Source info
         */

        proto_tree_add_item(dict_tree, hf_bundle_source_scheme,
                            tvb, offset + dict_data->source_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_source_ssp,
                            tvb, offset + dict_data->source_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Report to info
         */

        proto_tree_add_item(dict_tree, hf_bundle_report_scheme,
                            tvb, offset + dict_data->report_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_report_ssp,
                            tvb, offset + dict_data->report_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Custodian info
         */

        proto_tree_add_item(dict_tree, hf_bundle_custodian_scheme, tvb, offset + dict_data->cust_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_custodian_ssp, tvb, offset + dict_data->cust_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Add Source/Destination to INFO Field
         */

        col_set_writable(pinfo->cinfo, COL_INFO, TRUE);
        col_clear_fence(pinfo->cinfo, COL_INFO);
        if (col_text && strstr(col_text, " > "))
            col_append_str(pinfo->cinfo, COL_INFO, ", [multiple]");
        else {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s:%s > %s:%s %d.%d",
                         tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset + dict_data->source_scheme_offset, NULL, ENC_ASCII),
                         tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset + dict_data->source_ssp_offset, NULL, ENC_ASCII),
                         tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset + dict_data->dest_scheme_offset, NULL, ENC_ASCII),
                         tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset + dict_data->dest_ssp_offset, NULL, ENC_ASCII),
                         creation_timestamp, timestamp_sequence);
        }
        col_set_fence(pinfo->cinfo, COL_INFO);


        /* remember custodian, for use in checking cteb validity */
        *bundle_custodian = wmem_strdup_printf(wmem_packet_scope(),
                                               "%s:%s",
                                               tvb_get_stringz_enc(wmem_packet_scope(),
                                                               tvb, offset + dict_data->cust_scheme_offset,
                                                               NULL, ENC_ASCII),
                                               tvb_get_stringz_enc(wmem_packet_scope(),
                                                               tvb, offset + dict_data->cust_ssp_offset,
                                                               NULL, ENC_ASCII));
    }
    offset += dict_data->bundle_header_dict_length;        /*Skip over dictionary*/

    /*
     * Do this only if Fragment Flag is set
     */

    if (pri_hdr_procflags & BUNDLE_PROCFLAGS_FRAG_MASK) {
        int sdnv_length;
        sdnv_length = add_sdnv_to_tree(tree, tvb, pinfo, offset, hf_bundle_primary_fragment_offset);
        if (sdnv_length < 0) {
            return 0;
        }
        offset += sdnv_length;

        sdnv_length = add_sdnv_to_tree(tree, tvb, pinfo, offset, hf_bundle_primary_total_adu_len);
        if (sdnv_length < 0) {
            return 0;
        }
        offset += sdnv_length;
    }

    return offset;
}

/*
 * This routine returns 0 if header decoding fails, otherwise the length of the primary
 * header, starting right after version number.
 */
static int
dissect_version_4_primary_header(packet_info *pinfo, proto_tree *primary_tree, tvbuff_t *tvb,
                                 guint8* pri_hdr_procflags, gchar **bundle_custodian)
{
    int bundle_header_length;
    int offset = 1;             /* Version Number already displayed */
    int sdnv_length;
    dictionary_data_t dict_data;

    proto_item *ti;
    proto_tree *srr_flag_tree, *proc_flag_tree, *cos_flag_tree;

    /* Primary Header Processing Flags */
    *pri_hdr_procflags = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_item(primary_tree, hf_bundle_procflags, tvb,
                                                offset, 1, ENC_BIG_ENDIAN);
    proc_flag_tree = proto_item_add_subtree(ti, ett_proc_flags);
    proto_tree_add_item(proc_flag_tree, hf_bundle_procflags_fragment,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(proc_flag_tree, hf_bundle_procflags_admin,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(proc_flag_tree, hf_bundle_procflags_dont_fragment,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(proc_flag_tree, hf_bundle_procflags_cust_xfer_req,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(proc_flag_tree, hf_bundle_procflags_dest_singleton,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Primary Header COS Flags */
    ++offset;
    ti = proto_tree_add_item(primary_tree, hf_bundle_cosflags, tvb,
                                                offset, 1, ENC_BIG_ENDIAN);
    cos_flag_tree = proto_item_add_subtree(ti, ett_cos_flags);
    proto_tree_add_item(cos_flag_tree, hf_bundle_cosflags_priority,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Status Report Request Flags */
    ++offset;
    ti = proto_tree_add_item(primary_tree, hf_bundle_srrflags, tvb,
                                                offset, 1, ENC_BIG_ENDIAN);
    srr_flag_tree = proto_item_add_subtree(ti, ett_srr_flags);

    proto_tree_add_item(srr_flag_tree, hf_bundle_srrflags_report_receipt,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(srr_flag_tree, hf_bundle_srrflags_report_cust_accept,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(srr_flag_tree, hf_bundle_srrflags_report_forward,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(srr_flag_tree, hf_bundle_srrflags_report_delivery,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(srr_flag_tree, hf_bundle_srrflags_report_deletion,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(srr_flag_tree, hf_bundle_srrflags_report_ack,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
    ++offset;

    bundle_header_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    ti = proto_tree_add_int(primary_tree, hf_bundle_primary_header_len, tvb, offset, sdnv_length,
                            bundle_header_length);
    if (bundle_header_length < 0) {
        expert_add_info_format(pinfo, ti, &ei_bundle_sdnv_length, "Bundle Header Length Error");
        return 0;
    }

    offset += sdnv_length;

    /* Ensure all fields have been initialized */
    memset(&dict_data, 0, sizeof(dict_data));

    /*
     * Pick up offsets into dictionary (8 of them)
     */

    dict_data.dest_scheme_offset = tvb_get_ntohs(tvb, offset);
    dict_data.dst_scheme_pos = offset;
    dict_data.dst_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_dest_scheme_offset_u16,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dict_data.dest_ssp_offset = tvb_get_ntohs(tvb, offset);
    dict_data.dst_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_dest_ssp_offset_u16,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dict_data.source_scheme_offset = tvb_get_ntohs(tvb, offset);
    dict_data.src_scheme_pos = offset;
    dict_data.src_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_source_scheme_offset_u16,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dict_data.source_ssp_offset = tvb_get_ntohs(tvb, offset);
    dict_data.src_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_source_ssp_offset_u16,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dict_data.report_scheme_offset = tvb_get_ntohs(tvb, offset);
    dict_data.rpt_scheme_pos = offset;
    dict_data.rpt_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_report_scheme_offset_u16,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dict_data.report_ssp_offset = tvb_get_ntohs(tvb, offset);
    dict_data.rpt_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_report_ssp_offset_u16,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dict_data.cust_scheme_offset = tvb_get_ntohs(tvb, offset);
    dict_data.cust_scheme_pos = offset;
    dict_data.cust_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_cust_scheme_offset_u16,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dict_data.cust_ssp_offset = tvb_get_ntohs(tvb, offset);
    dict_data.cust_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_cust_ssp_offset_u16,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(primary_tree, hf_bundle_creation_timestamp,
                                                        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(primary_tree, hf_bundle_lifetime, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    dict_data.bundle_header_dict_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    ti = proto_tree_add_int(primary_tree, hf_bundle_primary_dictionary_len, tvb, offset, sdnv_length,
                            dict_data.bundle_header_dict_length);
    if (dict_data.bundle_header_dict_length < 0) {
        expert_add_info_format(pinfo, ti, &ei_bundle_sdnv_length, "Dictionary Header Length Error");
        return 0;
    }
    offset += sdnv_length;

    offset = dissect_dictionary(pinfo, primary_tree, tvb, offset, &dict_data, *pri_hdr_procflags, bundle_custodian, 0, 0);
    return offset;
}


/*
 * This routine returns 0 if header decoding fails, otherwise the length of the primary
 * header, starting right after version number.
 */

static int
dissect_version_5_and_6_primary_header(packet_info *pinfo,
                                       proto_tree *primary_tree, tvbuff_t *tvb,
                                       guint8* pri_hdr_procflags, gchar **bundle_custodian)
{
    guint64            bundle_processing_control_flags;
    guint8             cosflags;
    int                bundle_header_length;
    int                offset = 1; /* Version Number already displayed */
    int                sdnv_length;
    dictionary_data_t  dict_data;
    int                timestamp_sequence;
    int                creation_timestamp;
    guint8             srrflags;
    proto_item        *ti;
    proto_item        *ti_dst_scheme_offset, *ti_dst_ssp_offset;
    proto_item        *ti_src_scheme_offset, *ti_src_ssp_offset;
    proto_item        *ti_cust_scheme_offset, *ti_cust_ssp_offset;
    proto_item        *ti_rprt_scheme_offset, *ti_rprt_ssp_offset;
    proto_tree        *gen_flag_tree, *srr_flag_tree, *proc_flag_tree, *cos_flag_tree;
    static const int * pri_flags[] = {
        &hf_bundle_procflags_fragment,
        &hf_bundle_procflags_admin,
        &hf_bundle_procflags_dont_fragment,
        &hf_bundle_procflags_cust_xfer_req,
        &hf_bundle_procflags_dest_singleton,
        &hf_bundle_procflags_application_ack,
        NULL
    };

    static const int * srr_flags[] = {
        &hf_bundle_srrflags_report_receipt,
        &hf_bundle_srrflags_report_cust_accept,
        &hf_bundle_srrflags_report_forward,
        &hf_bundle_srrflags_report_delivery,
        &hf_bundle_srrflags_report_deletion,
        NULL
    };

    bundle_processing_control_flags = evaluate_sdnv_64(tvb, offset, &sdnv_length);

    /* Primary Header Processing Flags */
    *pri_hdr_procflags = (guint8) (bundle_processing_control_flags & 0x7f);

    if (sdnv_length < 1 || sdnv_length > 8) {
        expert_add_info_format(pinfo, primary_tree, &ei_bundle_control_flags_length,
                               "Wrong bundle control flag length: %d", sdnv_length);
        return 0;
    }
    ti = proto_tree_add_item(primary_tree, hf_bundle_control_flags, tvb,
                                                offset, sdnv_length, ENC_BIG_ENDIAN);
    proc_flag_tree = proto_item_add_subtree(ti, ett_proc_flags);

    ti = proto_tree_add_uint(proc_flag_tree, hf_bundle_procflags_general, tvb, offset,
                                        sdnv_length, *pri_hdr_procflags);
    gen_flag_tree = proto_item_add_subtree(ti, ett_gen_flags);

    /* With the variability of sdnv_length, proto_tree_add_bitmask_value
       can't be used */

    proto_tree_add_bitmask_list_value(gen_flag_tree, tvb, offset, sdnv_length, pri_flags, *pri_hdr_procflags);

    /* Primary Header COS Flags */
    cosflags = (guint8) ((bundle_processing_control_flags >> 7) & 0x7f);
    ti = proto_tree_add_uint(proc_flag_tree, hf_bundle_procflags_cos, tvb, offset,
                                        sdnv_length, cosflags);
    cos_flag_tree = proto_item_add_subtree(ti, ett_cos_flags);
    proto_tree_add_uint(cos_flag_tree, hf_bundle_cosflags_priority, tvb, offset,
                                    sdnv_length, cosflags);

    /* Status Report Request Flags */
    srrflags = (guint8) ((bundle_processing_control_flags >> 14) & 0x7f);
    ti = proto_tree_add_uint(proc_flag_tree, hf_bundle_procflags_status, tvb, offset,
                                        sdnv_length, srrflags);
    srr_flag_tree = proto_item_add_subtree(ti, ett_srr_flags);

    proto_tree_add_bitmask_list_value(srr_flag_tree, tvb, offset, sdnv_length, srr_flags, srrflags);
    offset += sdnv_length;

    /* -- hdr_length -- */
    bundle_header_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    ti = proto_tree_add_int(primary_tree, hf_bundle_primary_header_len, tvb, offset, sdnv_length,
                            bundle_header_length);
    if (bundle_header_length < 0) {
        expert_add_info_format(pinfo, ti, &ei_bundle_sdnv_length, "Bundle Header Length Error");
        return 0;
    }

    offset += sdnv_length;

    /*
     * Pick up offsets into dictionary (8 of them). Do rough sanity check that SDNV
     * hasn't told us to access way past the Primary Header.
     */

    /* Ensure all fields have been initialized */
    memset(&dict_data, 0, sizeof(dict_data));

    /* -- dest_scheme -- */
    dict_data.dest_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dict_data.dst_scheme_pos = offset;
    dict_data.dst_scheme_len = sdnv_length;

    ti_dst_scheme_offset = proto_tree_add_int(primary_tree, hf_bundle_dest_scheme_offset_i32, tvb, offset, sdnv_length,
                            dict_data.dest_scheme_offset);
    offset += sdnv_length;

    /* -- dest_ssp -- */
    dict_data.dest_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dict_data.dst_ssp_len = sdnv_length;

    ti_dst_ssp_offset = proto_tree_add_int(primary_tree, hf_bundle_dest_ssp_offset_i32, tvb, offset, sdnv_length,
                            dict_data.dest_ssp_offset);
    offset += sdnv_length;

    /* -- source_scheme -- */
    dict_data.source_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dict_data.src_scheme_pos = offset;
    dict_data.src_scheme_len = sdnv_length;

    ti_src_scheme_offset = proto_tree_add_int(primary_tree, hf_bundle_source_scheme_offset_i32, tvb, offset, sdnv_length,
                            dict_data.source_scheme_offset);
    offset += sdnv_length;

    /* -- source_ssp -- */
    dict_data.source_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dict_data.src_ssp_len = sdnv_length;

    ti_src_ssp_offset = proto_tree_add_int(primary_tree, hf_bundle_source_ssp_offset_i32, tvb, offset, sdnv_length,
                            dict_data.source_ssp_offset);
    offset += sdnv_length;

    /* -- report_scheme -- */
    dict_data.report_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dict_data.rpt_scheme_pos = offset;
    dict_data.rpt_scheme_len = sdnv_length;

    ti_rprt_scheme_offset = proto_tree_add_int(primary_tree, hf_bundle_report_scheme_offset_i32, tvb, offset,
                            sdnv_length, dict_data.report_scheme_offset);
    offset += sdnv_length;

    /* -- report_ssp -- */
    dict_data.report_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dict_data.rpt_ssp_len = sdnv_length;

    ti_rprt_ssp_offset = proto_tree_add_int(primary_tree, hf_bundle_report_ssp_offset_i32, tvb, offset, sdnv_length,
                            dict_data.report_ssp_offset);
    offset += sdnv_length;


    /* -- cust_scheme -- */
    dict_data.cust_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dict_data.cust_scheme_pos = offset;
    dict_data.cust_scheme_len = sdnv_length;

    ti_cust_scheme_offset = proto_tree_add_int(primary_tree, hf_bundle_cust_scheme_offset_i32, tvb, offset, sdnv_length,
                            dict_data.cust_scheme_offset);
    offset += sdnv_length;

    /* -- cust_ssp -- */
    dict_data.cust_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dict_data.cust_ssp_len = sdnv_length;

    ti_cust_ssp_offset = proto_tree_add_int(primary_tree, hf_bundle_cust_ssp_offset_i32, tvb, offset, sdnv_length,
                            dict_data.cust_ssp_offset);
    offset += sdnv_length;


    creation_timestamp = evaluate_sdnv(tvb, offset, &sdnv_length);
    sdnv_length = add_sdnv_time_to_tree(primary_tree, tvb, offset, hf_bundle_primary_timestamp);
    if (sdnv_length == 0)
        return 0;

    offset += sdnv_length;

    /* -- timestamp_sequence -- */
    timestamp_sequence = evaluate_sdnv(tvb, offset, &sdnv_length);
    if (timestamp_sequence < 0) {
        gint64 ts_seq = evaluate_sdnv_64(tvb, offset, &sdnv_length);

        ti = proto_tree_add_int64(primary_tree, hf_bundle_primary_timestamp_seq_num64,
                                                        tvb, offset, sdnv_length, ts_seq);
        if (ts_seq < 0) {
            expert_add_info(pinfo, ti, &ei_bundle_timestamp_seq_num);
        }
    }
    else {
        proto_tree_add_int(primary_tree, hf_bundle_primary_timestamp_seq_num32,
                                                        tvb, offset, sdnv_length, timestamp_sequence);
    }
    offset += sdnv_length;

    /* -- lifetime -- */
    sdnv_length = add_sdnv_to_tree(primary_tree, tvb, pinfo, offset, hf_bundle_lifetime_sdnv);
    offset += sdnv_length;

    /* -- dict_length -- */
    dict_data.bundle_header_dict_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    ti = proto_tree_add_int(primary_tree, hf_bundle_primary_dictionary_len, tvb, offset, sdnv_length,
                            dict_data.bundle_header_dict_length);
    if (dict_data.bundle_header_dict_length < 0) {
        expert_add_info_format(pinfo, ti, &ei_bundle_sdnv_length, "Dictionary Header Length Error");
        return 0;
    }
    offset += sdnv_length;

    if ((dict_data.dest_scheme_offset < 0) ||
        (dict_data.bundle_header_dict_length > 0 && (dict_data.dest_scheme_offset > bundle_header_length))) {
        expert_add_info_format(pinfo, ti_dst_scheme_offset, &ei_bundle_offset_error, "Destination Scheme Offset Error");
    }
    if ((dict_data.dest_ssp_offset < 0) ||
        (dict_data.bundle_header_dict_length > 0 && (dict_data.dest_ssp_offset > bundle_header_length))) {
        expert_add_info_format(pinfo, ti_dst_ssp_offset, &ei_bundle_offset_error, "Destination SSP Offset Error");
    }
    if ((dict_data.source_scheme_offset < 0) ||
        (dict_data.bundle_header_dict_length > 0 && (dict_data.source_scheme_offset > bundle_header_length))) {
        expert_add_info_format(pinfo, ti_src_scheme_offset, &ei_bundle_offset_error, "Source Scheme Offset Error");
    }
    if ((dict_data.source_ssp_offset < 0) ||
        (dict_data.bundle_header_dict_length > 0 && (dict_data.source_ssp_offset > bundle_header_length))) {
        expert_add_info_format(pinfo, ti_src_ssp_offset, &ei_bundle_offset_error, "Source SSP Offset Error");
    }
    if ((dict_data.report_scheme_offset < 0) ||
        (dict_data.bundle_header_dict_length > 0 && (dict_data.report_scheme_offset > bundle_header_length))) {
        expert_add_info_format(pinfo, ti_rprt_scheme_offset, &ei_bundle_offset_error, "Report Scheme Offset Error");
    }
    if ((dict_data.report_ssp_offset < 0) ||
        (dict_data.bundle_header_dict_length > 0 && (dict_data.report_ssp_offset > bundle_header_length))) {
        expert_add_info_format(pinfo, ti_rprt_ssp_offset, &ei_bundle_offset_error, "Report SSP Offset Error");
    }
    if ((dict_data.cust_scheme_offset < 0) ||
        (dict_data.bundle_header_dict_length > 0 && (dict_data.cust_scheme_offset > bundle_header_length))) {
        expert_add_info_format(pinfo, ti_cust_scheme_offset, &ei_bundle_offset_error, "Custodian Scheme Offset Error");
    }
    if ((dict_data.cust_ssp_offset < 0) ||
        (dict_data.bundle_header_dict_length > 0 && (dict_data.cust_ssp_offset > bundle_header_length))) {
        expert_add_info_format(pinfo, ti_cust_ssp_offset, &ei_bundle_offset_error, "Custodian SSP Offset Error");
    }

    offset = dissect_dictionary(pinfo, primary_tree, tvb, offset, &dict_data, *pri_hdr_procflags, bundle_custodian,
                                creation_timestamp, timestamp_sequence);
    return offset;
}

/*
 * offset is where the header starts.
 * Return new offset, and set lastheader if failure.
 */
static int
dissect_payload_header(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, guint8 version,
                       guint8 pri_hdr_procflags, gboolean *lastheader)
{
    proto_item *payload_block, *payload_item, *ti;
    proto_tree *payload_block_tree, *payload_tree;
    int         sdnv_length, payload_length;

    payload_block_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_payload_hdr, &payload_block, "Payload Block");

    payload_tree = proto_tree_add_subtree(payload_block_tree, tvb, offset, -1, ett_payload_hdr, &payload_item, "Payload Header");

    proto_tree_add_uint(payload_tree, hf_bundle_payload_header_type, tvb, offset, 1, 1);
    ++offset;

    /* Add tree for processing flags */
    /* This is really a SDNV but there are only 7 bits defined so leave it this way*/

    if (version == 4) {
        static const gint *flags[] = {
            &hf_bundle_payload_flags_replicate_hdr,
            &hf_bundle_payload_flags_xmit_report,
            &hf_bundle_payload_flags_discard_on_fail,
            &hf_bundle_payload_flags_last_header,
            NULL
        };
        guint8      procflags;

        procflags = tvb_get_guint8(tvb, offset);
        if (procflags & HEADER_PROCFLAGS_LAST_HEADER) {
            *lastheader = TRUE;
        }
        else {
            *lastheader = FALSE;
        }
        proto_tree_add_bitmask(payload_tree, tvb, offset, hf_bundle_payload_flags,
                               ett_payload_flags, flags, ENC_BIG_ENDIAN);
        ++offset;
    }
    else {      /*Bundle Protocol Version 5*/
        int control_flags;
        proto_item *block_flag_item;
        proto_tree *block_flag_tree;

        control_flags = evaluate_sdnv(tvb, offset, &sdnv_length);
        if (control_flags & BLOCK_CONTROL_LAST_BLOCK) {
            *lastheader = TRUE;
        }
        else {
            *lastheader = FALSE;
        }
        block_flag_item = proto_tree_add_item(payload_tree, hf_block_control_flags, tvb,
                                                offset, sdnv_length, ENC_BIG_ENDIAN);
        block_flag_tree = proto_item_add_subtree(block_flag_item, ett_block_flags);

        proto_tree_add_item(block_flag_tree, hf_block_control_replicate,
                                        tvb, offset, sdnv_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(block_flag_tree, hf_block_control_transmit_status,
                                        tvb, offset, sdnv_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(block_flag_tree, hf_block_control_delete_bundle,
                                        tvb, offset, sdnv_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(block_flag_tree, hf_block_control_last_block,
                                        tvb, offset, sdnv_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(block_flag_tree, hf_block_control_discard_block,
                                        tvb, offset, sdnv_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(block_flag_tree, hf_block_control_not_processed,
                                        tvb, offset, sdnv_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(block_flag_tree, hf_block_control_eid_reference,
                                        tvb, offset, sdnv_length, ENC_BIG_ENDIAN);
        offset += sdnv_length;
    }

    payload_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    ti = proto_tree_add_int(payload_tree, hf_bundle_payload_length, tvb, offset, sdnv_length, payload_length);
    if (payload_length < 0) {
        expert_add_info(pinfo, ti, &ei_bundle_payload_length);
        /* Force quiting */
        *lastheader = TRUE;
        return offset;
    }

    proto_item_set_len(payload_item, 2 + sdnv_length);
    proto_item_set_len(payload_block, 2 + sdnv_length + payload_length);

    offset += sdnv_length;
    if (pri_hdr_procflags & BUNDLE_PROCFLAGS_ADMIN_MASK) {
        gboolean success = FALSE;

        /*
         * XXXX - Have not allowed for admin record spanning multiple segments!
         */

        offset = dissect_admin_record(payload_block_tree, tvb, pinfo, offset, payload_length, &success);
        if (!success) {
            /* Force quiting */
            *lastheader = TRUE;
            return offset;
        }
    } else {
        proto_tree_add_string(payload_block_tree, hf_bundle_payload_data, tvb, offset, payload_length,
                              wmem_strdup_printf(wmem_packet_scope(), "<%d bytes>",payload_length));
        offset += payload_length;
    }

    return offset;
}

/*
 * Return the offset after the Administrative Record or set success = FALSE if analysis fails.
 */
static int
dissect_admin_record(proto_tree *primary_tree, tvbuff_t *tvb, packet_info *pinfo,
                     int offset, int payload_length, gboolean* success)
{
    proto_item *admin_record_item;
    proto_tree *admin_record_tree;
    proto_item *timestamp_sequence_item;
    guint8      record_type;
    guint8      status;
    int         start_offset = offset;
    int         sdnv_length;
    int         timestamp_sequence;
    int         endpoint_length;

    *success = FALSE;
    admin_record_tree = proto_tree_add_subtree(primary_tree, tvb, offset, -1,
                        ett_admin_record, &admin_record_item, "Administrative Record");
    record_type = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(admin_record_tree, hf_bundle_admin_record_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    switch ((record_type >> 4) & 0xf)
    {
    case ADMIN_REC_TYPE_STATUS_REPORT:
    {
        proto_item *status_flag_item;
        proto_tree *status_flag_tree;

        proto_tree_add_item(admin_record_tree, hf_bundle_admin_record_fragment, tvb, offset, 1, ENC_NA);
        ++offset;

        /* Decode Bundle Status Report Flags */
        status = tvb_get_guint8(tvb, offset);
        status_flag_item = proto_tree_add_item(admin_record_tree,
                                hf_bundle_admin_statflags, tvb, offset, 1, ENC_BIG_ENDIAN);
        status_flag_tree = proto_item_add_subtree(status_flag_item,
                                                        ett_admin_rec_status);
        proto_tree_add_item(status_flag_tree, hf_bundle_admin_rcvd,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(status_flag_tree, hf_bundle_admin_accepted,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(status_flag_tree, hf_bundle_admin_forwarded,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(status_flag_tree, hf_bundle_admin_delivered,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(status_flag_tree, hf_bundle_admin_deleted,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(status_flag_tree, hf_bundle_admin_acked,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
        ++offset;

        proto_tree_add_item(admin_record_tree, hf_bundle_status_report_reason_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        ++offset;

        if (record_type & ADMIN_REC_FLAGS_FRAGMENT) {
            sdnv_length = add_sdnv_to_tree(admin_record_tree, tvb, pinfo, offset, hf_bundle_admin_fragment_offset);
            if (sdnv_length <= 0) {
                return offset;
            }
            offset += sdnv_length;
            sdnv_length = add_sdnv_to_tree(admin_record_tree, tvb, pinfo, offset, hf_bundle_admin_fragment_length);
            if (sdnv_length <= 0) {
                return offset;
            }
            offset += sdnv_length;
        }
        if (status & ADMIN_STATUS_FLAGS_RECEIVED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset, hf_bundle_admin_receipt_time);
            if (sdnv_length <= 0) {
                return offset;
            }
            offset += sdnv_length;
        }
        if (status & ADMIN_STATUS_FLAGS_ACCEPTED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset, hf_bundle_admin_accept_time);
            if (sdnv_length <= 0) {
                return offset;
            }
            offset += sdnv_length;
        }
        if (status & ADMIN_STATUS_FLAGS_FORWARDED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset, hf_bundle_admin_forward_time);
            if (sdnv_length <= 0) {
                return offset;
            }
            offset += sdnv_length;
        }
        if (status & ADMIN_STATUS_FLAGS_DELIVERED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset, hf_bundle_admin_delivery_time);
            if (sdnv_length <= 0) {
                return offset;
            }
            offset += sdnv_length;
        }
        if (status & ADMIN_STATUS_FLAGS_DELETED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset, hf_bundle_admin_delete_time);
            if (sdnv_length <= 0) {
                return offset;
            }
            offset += sdnv_length;
        }
        if (status & ADMIN_STATUS_FLAGS_ACKNOWLEDGED) {
            sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset, hf_bundle_admin_ack_time);
            if (sdnv_length <= 0) {
                return offset;
            }
            offset += sdnv_length;
        }

        /* Get 2 SDNVs for Creation Timestamp */
        sdnv_length = add_sdnv_time_to_tree(admin_record_tree, tvb, offset, hf_bundle_admin_timestamp_copy);
        if (sdnv_length <= 0) {
            return offset;
        }
        offset += sdnv_length;

        timestamp_sequence = evaluate_sdnv(tvb, offset, &sdnv_length);
        if (timestamp_sequence < 0) {
            gint64 ts_seq = evaluate_sdnv_64(tvb, offset, &sdnv_length);

            timestamp_sequence_item = proto_tree_add_int64(admin_record_tree, hf_bundle_admin_timestamp_seq_num64,
                                                            tvb, offset, sdnv_length, ts_seq);
            if (ts_seq < 0) {
                expert_add_info(pinfo, timestamp_sequence_item, &ei_bundle_timestamp_seq_num);
               return offset;
            }
        }
        else {
            proto_tree_add_int(admin_record_tree, hf_bundle_admin_timestamp_seq_num32,
                                                            tvb, offset, sdnv_length, timestamp_sequence);
        }
        offset += sdnv_length;

        endpoint_length = evaluate_sdnv(tvb, offset, &sdnv_length);
        if (endpoint_length < 0) {
            return offset;
        }
        proto_tree_add_int(admin_record_tree, hf_bundle_admin_endpoint_length, tvb, offset, sdnv_length, endpoint_length);
        offset += sdnv_length;

        /*
         * Endpoint name may not be null terminated. This routine is supposed
         * to add the null at the end of the string buffer.
         */
        proto_tree_add_item(admin_record_tree, hf_bundle_admin_endpoint_id, tvb, offset, endpoint_length, ENC_NA|ENC_ASCII);
        offset += endpoint_length;

        break;
    } /* case ADMIN_REC_TYPE_STATUS_REPORT */
    case ADMIN_REC_TYPE_CUSTODY_SIGNAL:
    {
        proto_tree_add_item(admin_record_tree, hf_bundle_admin_record_fragment, tvb, offset, 1, ENC_NA);
        ++offset;

        proto_tree_add_item(admin_record_tree, hf_bundle_custody_trf_succ_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(admin_record_tree, hf_bundle_custody_signal_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
        ++offset;

        if (record_type & ADMIN_REC_FLAGS_FRAGMENT) {
            sdnv_length = add_sdnv_to_tree(admin_record_tree, tvb, pinfo, offset, hf_bundle_admin_fragment_offset);
            if (sdnv_length <= 0) {
                return offset;
            }
            offset += sdnv_length;
            sdnv_length = add_sdnv_to_tree(admin_record_tree, tvb, pinfo, offset, hf_bundle_admin_fragment_length);
            if (sdnv_length <= 0) {
                return offset;
            }
            offset += sdnv_length;
        }

        /* Signal Time */
        sdnv_length = add_dtn_time_to_tree(admin_record_tree, tvb, offset, hf_bundle_admin_signal_time);
        if (sdnv_length <= 0) {
            return offset;
        }
        offset += sdnv_length;

        /* Timestamp copy */
        sdnv_length = add_sdnv_time_to_tree(admin_record_tree, tvb, offset, hf_bundle_admin_timestamp_copy);
        if (sdnv_length <= 0) {
            return offset;
        }
        offset += sdnv_length;

        timestamp_sequence = evaluate_sdnv(tvb, offset, &sdnv_length);
        if (timestamp_sequence < 0) {
            gint64 ts_seq = evaluate_sdnv_64(tvb, offset, &sdnv_length);

            timestamp_sequence_item = proto_tree_add_int64(admin_record_tree, hf_bundle_admin_timestamp_seq_num64,
                                                            tvb, offset, sdnv_length, ts_seq);
            if (ts_seq < 0) {
                expert_add_info(pinfo, timestamp_sequence_item, &ei_bundle_timestamp_seq_num);
               return offset;
            }
        }
        else {
            proto_tree_add_int(admin_record_tree, hf_bundle_admin_timestamp_seq_num32,
                                                            tvb, offset, sdnv_length, timestamp_sequence);
        }
        offset += sdnv_length;

        endpoint_length = evaluate_sdnv(tvb, offset, &sdnv_length);
        if (endpoint_length < 0) {
            return 0;
        }
        proto_tree_add_int(admin_record_tree, hf_bundle_admin_endpoint_length, tvb, offset, sdnv_length, endpoint_length);
        offset += sdnv_length;
        proto_tree_add_item(admin_record_tree, hf_bundle_admin_endpoint_id, tvb, offset, endpoint_length, ENC_NA|ENC_ASCII);
        offset += endpoint_length;
        break;
    } /* case ADMIN_REC_TYPE_CUSTODY_SIGNAL */
    case ADMIN_REC_TYPE_AGGREGATE_CUSTODY_SIGNAL:
    {
        proto_item *ti;
        int payload_bytes_processed = 0;
        int right_edge = -1;
        int fill_start;
        int fill_length = -1;
        int sdnv_length_start = -1;
        int sdnv_length_gap = -1;
        int sdnv_length_length = -1;

        proto_tree_add_item(admin_record_tree, hf_bundle_admin_record_fragment, tvb, offset, 1, ENC_NA);
        ++offset;
        ++payload_bytes_processed;

        proto_tree_add_item(admin_record_tree, hf_bundle_custody_trf_succ_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(admin_record_tree, hf_bundle_custody_signal_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
        ++offset;
        ++payload_bytes_processed;

        /* process the first fill */
        fill_start = evaluate_sdnv(tvb, offset, &sdnv_length_start);
        ti = proto_tree_add_int(admin_record_tree, hf_bundle_custody_id_range_start, tvb, offset, sdnv_length_start, fill_start);
        if (fill_start < 0 || sdnv_length_start < 0) {
            expert_add_info_format(pinfo, ti, &ei_bundle_sdnv_length, "ACS: Unable to process CTEB Custody ID Range start SDNV");
            return offset;
        }
        fill_length = evaluate_sdnv(tvb, offset + sdnv_length_start, &sdnv_length_length);
        ti = proto_tree_add_int(admin_record_tree, hf_bundle_custody_id_range_end, tvb, offset,
                                sdnv_length_start + sdnv_length_length, fill_start + fill_length - 1);
        if (fill_length < 0 || sdnv_length_length < 0) {
            expert_add_info_format(pinfo, ti, &ei_bundle_sdnv_length, "ACS: Unable to process CTEB Custody ID Range length SDNV");
            return offset;
        }

        right_edge = fill_start + fill_length;
        offset += sdnv_length_start + sdnv_length_length;
        payload_bytes_processed += sdnv_length_start + sdnv_length_length;

        /* now attempt to consume all the rest of the data in the
         * payload as additional fills */
        while (payload_bytes_processed < payload_length) {
            int fill_gap;
            fill_gap = evaluate_sdnv(tvb, offset, &sdnv_length_gap);
            ti = proto_tree_add_int(admin_record_tree, hf_bundle_custody_id_range_start, tvb, offset, sdnv_length_gap, fill_gap);
            if (fill_gap < 0 || sdnv_length_gap < 0) {
                expert_add_info_format(pinfo, ti, &ei_bundle_sdnv_length, "ACS: Unable to process CTEB Custody ID Range gap SDNV");
                return offset;
            }
            fill_length = evaluate_sdnv(tvb, offset + sdnv_length_gap, &sdnv_length_length);
            ti = proto_tree_add_int(admin_record_tree, hf_bundle_custody_id_range_end, tvb, offset,
                                    sdnv_length_gap + sdnv_length_length, right_edge + fill_gap + fill_length - 1);
            if (fill_length < 0 || sdnv_length_length < 0) {
                expert_add_info_format(pinfo, ti, &ei_bundle_sdnv_length, "ACS: Unable to process CTEB Custody ID Range length SDNV");
                return offset;
            }

            right_edge += fill_gap + fill_length;
            offset += sdnv_length_gap + sdnv_length_length;
            payload_bytes_processed += sdnv_length_gap + sdnv_length_length;
        }

        if (payload_bytes_processed > payload_length) {
            expert_add_info_format(pinfo, ti, &ei_bundle_offset_error, "ACS: CTEB Custody ID Range data extends past payload length");
            return offset;
        }

        break;
    } /* case ADMIN_REC_TYPE_AGGREGATE_CUSTODY_SIGNAL */
    case ADMIN_REC_TYPE_ANNOUNCE_BUNDLE:
    default:
        offset++;
        break;
    }   /* End Switch */

    proto_item_set_len(admin_record_item, offset - start_offset);
    *success = TRUE;
    return offset;
}

static int
display_extension_block(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, gchar *bundle_custodian, gboolean *lastheader)
{
    proto_item   *block_item, *ti, *block_flag_replicate_item, *block_flag_eid_reference_item;
    proto_tree   *block_tree;
    int           sdnv_length;
    int           block_length;
    int           block_overhead;
    guint8        type;
    unsigned int  control_flags;
    proto_tree   *block_flag_tree;
    proto_item   *block_flag_item;

    type = tvb_get_guint8(tvb, offset);
    block_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_metadata_hdr, &block_item, "Extension Block");

    proto_tree_add_item(block_tree, hf_bundle_block_type_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    ++offset;
    block_overhead = 1;

    control_flags = (unsigned int)evaluate_sdnv(tvb, offset, &sdnv_length);
    if (control_flags & BLOCK_CONTROL_LAST_BLOCK) {
        *lastheader = TRUE;
    } else {
        *lastheader = FALSE;
    }
    block_flag_item = proto_tree_add_uint(block_tree, hf_block_control_flags_sdnv, tvb,
                                            offset, sdnv_length, control_flags);
    block_flag_tree = proto_item_add_subtree(block_flag_item, ett_block_flags);
    block_flag_replicate_item = proto_tree_add_boolean(block_flag_tree, hf_block_control_replicate,
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
    block_flag_eid_reference_item = proto_tree_add_boolean(block_flag_tree, hf_block_control_eid_reference,
                           tvb, offset, sdnv_length, control_flags);
    offset += sdnv_length;
    block_overhead += sdnv_length;

    /* TODO: if this block has EID references, add them to display tree */
    if (control_flags & BLOCK_CONTROL_EID_REFERENCE) {
        int i;
        int num_eid_ref;

        num_eid_ref = evaluate_sdnv(tvb, offset, &sdnv_length);
        offset += sdnv_length;
        block_overhead += sdnv_length;

        for (i = 0; i < num_eid_ref; i++)
        {
            if (evaluate_sdnv(tvb, offset, &sdnv_length) < 0)
                break;
            offset += sdnv_length;
            block_overhead += sdnv_length;

            if (evaluate_sdnv(tvb, offset, &sdnv_length) < 0)
                break;
            offset += sdnv_length;
            block_overhead += sdnv_length;
        }
    }

    block_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    ti = proto_tree_add_int(block_tree, hf_block_control_block_length, tvb, offset, sdnv_length, block_length);
    if (block_length < 0) {
        expert_add_info_format(pinfo, ti, &ei_bundle_offset_error, "Metadata Block Length Error");
        /* Force quitting */
        *lastheader = TRUE;
        return offset;
    }
    offset += sdnv_length;
    block_overhead += sdnv_length;

    /* now we have enough info to know total length of metadata block */
    proto_item_set_len(block_item, block_overhead + block_length);

    switch (type)
    {
    case BUNDLE_BLOCK_TYPE_AUTHENTICATION:
    case BUNDLE_BLOCK_TYPE_INTEGRITY:
    case BUNDLE_BLOCK_TYPE_CONFIDENTIALITY:
    case BUNDLE_BLOCK_TYPE_PREVIOUS_HOP_INSERT:
    case BUNDLE_BLOCK_TYPE_METADATA_EXTENSION:
    case BUNDLE_BLOCK_TYPE_EXTENSION_SECURITY:
    {
        proto_tree_add_string(block_tree, hf_bundle_unprocessed_block_data, tvb, offset, block_length, "Block data");
        /* not yet dissected, skip past data */
        offset += block_length;
        break;
    }
    case BUNDLE_BLOCK_TYPE_CUSTODY_TRANSFER:
    {
        int custody_id;
        const guint8 *cteb_creator_custodian_eid;
        int cteb_creator_custodian_eid_length;

        /* check requirements for Block Processing Control Flags */
        if ((control_flags & BLOCK_CONTROL_REPLICATE) != 0) {
            expert_add_info_format(pinfo, block_flag_replicate_item, &ei_bundle_block_control_flags, "ERROR: Replicate must be clear for CTEB");
        }
        if ((control_flags & BLOCK_CONTROL_EID_REFERENCE) != 0) {
            expert_add_info_format(pinfo, block_flag_eid_reference_item, &ei_bundle_block_control_flags, "ERROR: EID-Reference must be clear for CTEB");
        }

        /* there are two elements in a CTEB, first is the custody ID */
        custody_id = evaluate_sdnv(tvb, offset, &sdnv_length);
        proto_tree_add_int(block_tree, hf_block_control_block_cteb_custody_id, tvb, offset, sdnv_length, custody_id);
        offset += sdnv_length;

        /* and second is the creator custodian EID */
        cteb_creator_custodian_eid_length = block_length - sdnv_length;
        ti = proto_tree_add_item_ret_string(block_tree, hf_block_control_block_cteb_creator_custodian_eid, tvb, offset,
                                cteb_creator_custodian_eid_length, ENC_ASCII, wmem_packet_scope(), &cteb_creator_custodian_eid);

        /* also check if CTEB is valid, i.e. custodians match */
        if (bundle_custodian == NULL) {
            expert_add_info_format(pinfo, ti, &ei_block_control_block_cteb_invalid,
                                "CTEB Is NOT Valid (Bundle Custodian NULL)");
        }
        else if (strlen(cteb_creator_custodian_eid) != strlen(bundle_custodian)) {
            expert_add_info_format(pinfo, ti, &ei_block_control_block_cteb_invalid,
                                "CTEB Is NOT Valid (Bundle Custodian [%s] != CTEB Custodian [%s])",
                                bundle_custodian, cteb_creator_custodian_eid);
        }
        else if (memcmp(cteb_creator_custodian_eid, bundle_custodian, strlen(bundle_custodian)) != 0) {
            expert_add_info_format(pinfo, ti, &ei_block_control_block_cteb_invalid,
                                "CTEB Is NOT Valid (Bundle Custodian [%s] != CTEB Custodian [%s])",
                                bundle_custodian, cteb_creator_custodian_eid);
        }
        else {
            expert_add_info(pinfo, ti, &ei_block_control_block_cteb_valid);
        }
        offset += cteb_creator_custodian_eid_length;

        break;
    }
    case BUNDLE_BLOCK_TYPE_EXTENDED_COS:
    {
        int flags;
        static const int * ecos_flags_fields[] = {
            &hf_ecos_flags_critical,
            &hf_ecos_flags_streaming,
            &hf_ecos_flags_flowlabel,
            &hf_ecos_flags_reliable,
            NULL
        };

        /* check requirements for Block Processing Control Flags */
        if ((control_flags & BLOCK_CONTROL_REPLICATE) == 0) {
            expert_add_info_format(pinfo, block_flag_replicate_item, &ei_bundle_block_control_flags, "ERROR: Replicate must be set for ECOS");
        }
        if ((control_flags & BLOCK_CONTROL_EID_REFERENCE) != 0) {
            expert_add_info_format(pinfo, block_flag_eid_reference_item, &ei_bundle_block_control_flags, "ERROR: EID-Reference must be clear for ECOS");
        }

        /* flags byte */
        flags = (int)tvb_get_guint8(tvb, offset);
        proto_tree_add_bitmask(block_tree, tvb, offset, hf_ecos_flags, ett_block_flags, ecos_flags_fields, ENC_BIG_ENDIAN);
        offset += 1;

        /* ordinal byte */
        proto_tree_add_item(block_tree, hf_ecos_ordinal, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* optional flow label sdnv */
        if ((flags & ECOS_FLAGS_FLOWLABEL) != 0) {
            int flow_label;
            flow_label = evaluate_sdnv(tvb, offset, &sdnv_length);
            ti = proto_tree_add_int(block_tree, hf_ecos_flow_label, tvb, offset, sdnv_length, flow_label);
            if (flow_label < 0) {
                expert_add_info_format(pinfo, ti, &ei_bundle_sdnv_length, "ECOS Flow Label Error");
                /* Force quitting */
                *lastheader = TRUE;
                return offset;
            }
            offset += sdnv_length;
        }

        break;
    }
    default:
    {
        proto_tree_add_string(block_tree, hf_bundle_unprocessed_block_data, tvb, offset, block_length, "Block data");
        /* unknown bundle type, skip past data */
        offset += block_length;
        break;
    }
    }

    return offset;
}

/*3rd arg is number of bytes in field (returned)*/
int
evaluate_sdnv(tvbuff_t *tvb, int offset, int *bytecount)
{
    int    value = 0;
    guint8 curbyte;

    *bytecount = 0;

    if (!tvb_bytes_exist(tvb, offset, 1)) {
        return -1;
    }

    /*
     * Get 1st byte and continue to get them while high-order bit is 1
     */

    while ((curbyte = tvb_get_guint8(tvb, offset)) & ~SDNV_MASK) {
        if (*bytecount >= (int) sizeof(int)) {
            *bytecount = 0;
            return -1;
        }
        value = value << 7;
        value |= (curbyte & SDNV_MASK);
        ++offset;
        ++*bytecount;

        if (!tvb_bytes_exist(tvb, offset, 1)) {
            return -1;
        }
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
/*3rd arg is number of bytes in field (returned)*/
gint64
evaluate_sdnv_64(tvbuff_t *tvb, int offset, int *bytecount)
{
    gint64 value = 0;
    guint8 curbyte;

    *bytecount = 0;

    if (!tvb_bytes_exist(tvb, offset, 1)) {
        return -1;
    }

    /*
     * Get 1st byte and continue to get them while high-order bit is 1
     */

    while ((curbyte = tvb_get_guint8(tvb, offset)) & ~SDNV_MASK) {
        if (*bytecount >= (int) sizeof(gint64)) {
            *bytecount = 0;
            return -1;
        }
        value = value << 7;
        value |= (curbyte & SDNV_MASK);
        ++offset;
        ++*bytecount;

        if (!tvb_bytes_exist(tvb, offset, 1)) {
            return -1;
        }
    }

    /*
     * Add in the byte whose high-order bit is 0 (last one)
     */

    value = value << 7;
    value |= (curbyte & SDNV_MASK);
    ++*bytecount;
    return value;
}

/* Special Function to evaluate 32 bit unsigned SDNVs with error indication
 *    bytecount returns the number bytes consumed
 *    value returns the actual value
 *
 *    result is TRUE (1) on success else FALSE (0)
 */
int
evaluate_sdnv32(tvbuff_t *tvb, int offset, int *bytecount, guint32 *value)
{
    int result;
    int num_bits_in_value;
    guint8 curbyte;
    guint8 high_bit;

    *value = 0;
    *bytecount = 0;

    result = FALSE;
    num_bits_in_value = 0;

    if (tvb_bytes_exist(tvb, offset, 1)) {
        /*
         * Get 1st byte and continue to get them while high-order bit is 1
         */
        result = TRUE;

        /* Determine number of non-zero bits in first SDNV byte */
        /* technically 0x80 0x80 ... 0x81 is a valid inefficient representation of "1" */
        while ((0 == num_bits_in_value) && ((curbyte = tvb_get_guint8(tvb, offset)) & ~SDNV_MASK)) {
            if (!tvb_bytes_exist(tvb, offset, 1)) {
                result = FALSE;
                break;
            } else {
                num_bits_in_value = 7;
                high_bit = 0x40;
                while ((num_bits_in_value > 0) && (!(curbyte & high_bit))) {
                    --num_bits_in_value;
                    high_bit = high_bit >> 1;
                }

                *value |= (curbyte & SDNV_MASK);
                ++offset;
                ++*bytecount;
            }
        }


        /* Process additional bytes that have the high order bit set */
        while (result && ((curbyte = tvb_get_guint8(tvb, offset)) & ~SDNV_MASK)) {
            /* Since the high order bit is set there must be 7 low order bits after this byte */
            if (!tvb_bytes_exist(tvb, offset, 1) || ((num_bits_in_value + 7) > (32 - 7))) {
                result = FALSE;
            } else {
                *value = *value << 7;
                *value |= (curbyte & SDNV_MASK);
                ++offset;
                ++*bytecount;
            }
        }

        if (result) {
            /*
             * Add in the byte whose high-order bit is 0 (last one)
             */
            *value = *value << 7;
            *value |= (curbyte & SDNV_MASK);
            ++*bytecount;
        } else {
            *bytecount = 0;
        }
    }

    return result;
}


/* Special Function to evaluate 64 bit unsigned SDNVs with error indication
 *    bytecount returns the number bytes consumed or zero on error
 *    value returns the actual value
 *
 *    result is TRUE (1) on success else FALSE (0)
 */
int
evaluate_sdnv64(tvbuff_t *tvb, int offset, int *bytecount, guint64 *value)
{
    int result;
    int num_bits_in_value;
    guint8 curbyte;
    guint8 high_bit;

    *value = 0;
    *bytecount = 0;

    result = FALSE;
    num_bits_in_value = 0;

    if (tvb_bytes_exist(tvb, offset, 1)) {
        /*
         * Get 1st byte and continue to get them while high-order bit is 1
         */
        result = TRUE;

        /* Determine number of non-zero bits in first SDNV byte */
        /* technically 0x80 0x80 ... 0x81 is a valid inefficient representation of "1" */
        while ((0 == num_bits_in_value) && ((curbyte = tvb_get_guint8(tvb, offset)) & ~SDNV_MASK)) {
            if (!tvb_bytes_exist(tvb, offset, 1)) {
                result = FALSE;
                break;
            } else {
                num_bits_in_value = 7;
                high_bit = 0x40;
                while ((num_bits_in_value > 0) && (!(curbyte & high_bit))) {
                    --num_bits_in_value;
                    high_bit = high_bit >> 1;
                }

                *value |= (curbyte & SDNV_MASK);
                ++offset;
                ++*bytecount;
            }
        }


        /* Process additional bytes that have the high order bit set */
        while (result && ((curbyte = tvb_get_guint8(tvb, offset)) & ~SDNV_MASK)) {
            /* Since the high order bit is set there must be 7 low order bits after this byte */
            if (!tvb_bytes_exist(tvb, offset, 1) || ((num_bits_in_value + 7) > (64 - 7))) {
                result = FALSE;
            } else {
                *value = *value << 7;
                *value |= (curbyte & SDNV_MASK);
                ++offset;
                ++*bytecount;
            }
        }

        if (result) {
            /*
             * Add in the byte whose high-order bit is 0 (last one)
             */
            *value = *value << 7;
            *value |= (curbyte & SDNV_MASK);
            ++*bytecount;
        } else {
            *bytecount = 0;
        }
    }

    return result;
}


static guint
get_dtn_contact_header_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                           int offset, void *data _U_)
{
    int len, bytecount;

    /* get length from sdnv */
    len = evaluate_sdnv(tvb, offset+8, &bytecount);
    if (len < 0)
        return 0;

    return len+bytecount+8;
}

static int
dissect_dtn_contact_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *conv_proto_tree, *conv_tree, *conv_flag_tree;
    int         eid_length, sdnv_length;
    int         offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCPCL");
    col_clear(pinfo->cinfo,COL_INFO); /* Clear out stuff in the info column */
    col_add_str(pinfo->cinfo, COL_INFO, "Contact Header");

    ti = proto_tree_add_item(tree, proto_tcp_conv, tvb, offset, -1, ENC_NA);
    conv_proto_tree = proto_item_add_subtree(ti, ett_tcp_conv);

    conv_tree = proto_tree_add_subtree(conv_proto_tree, tvb, offset, -1, ett_tcp_conv, NULL, "Contact Header");

    proto_tree_add_item(conv_tree, hf_contact_hdr_magic, tvb, offset, 4, ENC_NA|ENC_ASCII);
    offset += 4;
    proto_tree_add_item(conv_tree, hf_contact_hdr_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Subtree to expand the bits in the Contact Header Flags */
    ti = proto_tree_add_item(conv_tree, hf_contact_hdr_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    conv_flag_tree = proto_item_add_subtree(ti, ett_contact_hdr_flags);
    proto_tree_add_item(conv_flag_tree, hf_contact_hdr_flags_ack_req, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(conv_flag_tree, hf_contact_hdr_flags_frag_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(conv_flag_tree, hf_contact_hdr_flags_nak, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(conv_tree, hf_contact_hdr_keep_alive, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*
     * New format Contact header has length field followed by Bundle Header.
     */
    eid_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    ti = proto_tree_add_int(tree, hf_contact_hdr_local_eid_length, tvb, offset, sdnv_length, eid_length);
    if (eid_length < 0) {
        expert_add_info(pinfo, ti, &ei_bundle_sdnv_length);
        return offset;
    }

    proto_tree_add_item(conv_tree, hf_contact_hdr_local_eid, tvb, sdnv_length + offset, eid_length, ENC_NA|ENC_ASCII);
    return tvb_captured_length(tvb);
}

static guint
get_tcpcl_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    int    len, bytecount;
    guint8 conv_hdr = tvb_get_guint8(tvb, offset);

    switch (conv_hdr & TCP_CONVERGENCE_TYPE_MASK)
    {
    case TCP_CONVERGENCE_DATA_SEGMENT:
        /* get length from sdnv */
        len = evaluate_sdnv(tvb, offset+1, &bytecount);
        if (len < 0)
            return 0;

        return len+bytecount+1;

    case TCP_CONVERGENCE_ACK_SEGMENT:
        /* get length from sdnv */
        len = evaluate_sdnv(tvb, offset+1, &bytecount);
        if (len < 0)
            return 0;

        return bytecount+1;

    case TCP_CONVERGENCE_KEEP_ALIVE:
    case TCP_CONVERGENCE_REFUSE_BUNDLE:
        /* always 1 byte */
        return 1;
    case TCP_CONVERGENCE_SHUTDOWN:
        len = 1;

        if (conv_hdr & TCP_CONVERGENCE_SHUTDOWN_REASON) {
            len += 1;
        }
        if (conv_hdr & TCP_CONVERGENCE_SHUTDOWN_DELAY) {
            len += 2;
        }

        return len;
    }

    /* This probably isn't a TCPCL/Bundle packet, so just stop dissection */
    return -1;
}

static int
dissect_tcpcl_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    guint8         conv_hdr;
    int            offset = 0;
    int            sdnv_length, segment_length, convergence_hdr_size;
    proto_item    *ci, *sub_item;
    proto_tree    *conv_proto_tree, *conv_tree, *sub_tree;
    fragment_head *frag_msg;
    tvbuff_t      *new_tvb;
    gboolean       more_frags;
    int            processed_length = 0;
    const gchar*   col_text;
    gboolean       bundle_in_col_info;

    static guint32 frag_id = 0;
    static guint32 last_frame = 0;
    static int last_raw_offset = 0;

    if (last_frame != pinfo->fd->num || tvb_raw_offset(tvb) < last_raw_offset)
        frag_id = 0;
    last_frame = pinfo->fd->num;
    last_raw_offset = tvb_raw_offset(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCPCL");
    col_clear(pinfo->cinfo,COL_INFO); /* Clear out stuff in the info column */

    col_text = col_get_text(pinfo->cinfo, COL_INFO);
    bundle_in_col_info = (col_text && strstr(col_text, " > "));

    ci = proto_tree_add_item(tree, proto_tcp_conv, tvb, offset, -1, ENC_NA);
    conv_proto_tree = proto_item_add_subtree(ci, ett_tcp_conv);

    conv_tree = proto_tree_add_subtree(conv_proto_tree, tvb, 0, -1, ett_tcp_conv_hdr, NULL, "TCP Convergence Header");

    conv_hdr = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(conv_tree, hf_tcp_convergence_pkt_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const((conv_hdr>>4)&0xF, packet_type_vals, "Unknown"));

    switch (conv_hdr & TCP_CONVERGENCE_TYPE_MASK)
    {
    case TCP_CONVERGENCE_DATA_SEGMENT:
        sub_item = proto_tree_add_item(conv_tree, hf_tcp_convergence_data_procflags, tvb,
                                                    offset, 1, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_conv_flags);
        proto_tree_add_item(sub_tree, hf_tcp_convergence_data_procflags_start,
                                                    tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_tcp_convergence_data_procflags_end,
                                                    tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Only Start and End flags (bits 0 & 1) are valid in Data Segment */
        if ((conv_hdr & ~(TCP_CONVERGENCE_TYPE_MASK | TCP_CONVERGENCE_DATA_FLAGS)) != 0) {
            expert_add_info(pinfo, sub_item, &ei_tcp_convergence_data_flags);
        }

        segment_length = evaluate_sdnv(tvb, 1, &sdnv_length);
        sub_item = proto_tree_add_int(conv_tree, hf_tcp_convergence_data_segment_length, tvb, 1, sdnv_length, segment_length);
        if (segment_length < 0) {
            expert_add_info(pinfo, sub_item, &ei_tcp_convergence_segment_length);
            return 1;
        }

        convergence_hdr_size = sdnv_length + 1;

        /*
            * 1/11/2006 - If I got here, I should have a complete convergence layer
            * "segment" beginning at frame_offset. However that might not be a
            * complete bundle. Or there might be a complete bundle plus one or more
            * additional convergence layer headers.
            */

        new_tvb  = NULL;
        sub_tree = NULL;
        if ((conv_hdr & TCP_CONVERGENCE_DATA_END_FLAG) == TCP_CONVERGENCE_DATA_END_FLAG) {
            more_frags = FALSE;
        }
        else {
            more_frags = TRUE;
        }

        frag_msg = fragment_add_seq_next(&msg_reassembly_table,
                                         tvb, offset + convergence_hdr_size,
                                         pinfo, frag_id, data,
                                         segment_length, more_frags);

        if (!more_frags) ++frag_id;

        processed_length = convergence_hdr_size + segment_length;

        if (frag_msg && !more_frags) {

            int save_fd_head_layer = frag_msg->reas_in_layer_num;
            frag_msg->reas_in_layer_num = pinfo->curr_layer_num;

            sub_item = proto_tree_add_item(tree, proto_bundle, tvb, offset, -1, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_bundle);

            new_tvb = process_reassembled_data(tvb, offset + convergence_hdr_size,
                                                pinfo, "Reassembled DTN", frag_msg,
                                                &msg_frag_items, NULL, sub_tree);

            frag_msg->reas_in_layer_num = save_fd_head_layer;
        }

        if (new_tvb) {
            if (0 == call_dissector_with_data(bundle_handle, new_tvb, pinfo, sub_tree, data)) {
                /*Couldn't parse bundle, treat as raw data */
                call_data_dissector(new_tvb, pinfo, sub_tree);
                return tvb_captured_length(tvb);
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
            col_add_str(pinfo->cinfo, COL_INFO, "[Bundle TCPCL Segment]");
        }
        break;
    case TCP_CONVERGENCE_ACK_SEGMENT:
        if (bundle_in_col_info) {
            if (!strstr(col_text, ", TCPL ACK")) {
                col_add_str(pinfo->cinfo, COL_INFO, ", TCPL ACK Segment(s)");
            }
        } else {
            col_set_str(pinfo->cinfo, COL_INFO, "TCPL ACK Segment(s)");
        }
        segment_length = evaluate_sdnv(tvb, offset+1, &sdnv_length);
        sub_item = proto_tree_add_int(conv_tree, hf_tcp_convergence_ack_length, tvb, offset+1, sdnv_length, segment_length);
        if (segment_length < 0) {
            expert_add_info(pinfo, sub_item, &ei_tcp_convergence_ack_length);
            processed_length = tvb_captured_length(tvb);
        } else {
            processed_length = sdnv_length + 1;
        }
        break;
    case TCP_CONVERGENCE_KEEP_ALIVE:
        if (bundle_in_col_info) {
            if (!strstr(col_text, ", TCPL KEEPALIVE")) {
                col_add_str(pinfo->cinfo, COL_INFO, ", TCPL KEEPALIVE Segment");
            }
        } else {
            col_set_str(pinfo->cinfo, COL_INFO, "TCPL KEEPALIVE Sgement");
        }
        /*No valid flags in Keep Alive*/
        processed_length = 1;
        break;

    case TCP_CONVERGENCE_SHUTDOWN:
        if (bundle_in_col_info) {
            if (!strstr(col_text, ", TCPL SHUTDOWN")) {
                col_add_str(pinfo->cinfo, COL_INFO, ", TCPL SHUTDOWN Segment");
            }
        } else {
            col_set_str(pinfo->cinfo, COL_INFO, "TCPL SHUTDOWN Sgement");
        }
        /* Add tree for Shutdown Flags */
        sub_item = proto_tree_add_item(conv_tree, hf_tcp_convergence_shutdown_flags, tvb,
                                        offset, 1, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_shutdown_flags);

        proto_tree_add_item(sub_tree, hf_tcp_convergence_shutdown_flags_reason,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_tcp_convergence_shutdown_flags_delay,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);

        offset += 1;
        if (conv_hdr & TCP_CONVERGENCE_SHUTDOWN_REASON) {
            proto_tree_add_item(conv_tree,
                                        hf_tcp_convergence_shutdown_reason, tvb,
                                        offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
        if (conv_hdr & TCP_CONVERGENCE_SHUTDOWN_DELAY) {
            proto_tree_add_item(conv_tree,
                                        hf_tcp_convergence_shutdown_delay, tvb,
                                        offset, 2, ENC_BIG_ENDIAN);
        }
        break;
    case TCP_CONVERGENCE_REFUSE_BUNDLE:
        if (bundle_in_col_info) {
            if (!strstr(col_text, ", TCPL REFUSE")) {
                col_add_str(pinfo->cinfo, COL_INFO, ", TCPL REFUSE_BUNDLE Segment");
            }
        } else {
            col_set_str(pinfo->cinfo, COL_INFO, "TCPL REFUSE_BUNDLE Sgement");
        }
        /*No valid flags*/
        processed_length = tvb_captured_length(tvb);
        break;
    }

    return processed_length;
}

static int
dissect_tcpcl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint8  conv_hdr;
    int     offset, bytecount;
    int processed_length;

    /* Make sure we have a convergence header byte */
    if (!tvb_bytes_exist(tvb, 0, 1))
        return 0;

    conv_hdr = tvb_get_guint8(tvb, 0);
    switch (conv_hdr & TCP_CONVERGENCE_TYPE_MASK)
    {
    case TCP_CONVERGENCE_DATA_SEGMENT:
    case TCP_CONVERGENCE_ACK_SEGMENT:
        /* ensure sdnv */
        offset = 1;
        bytecount = 1;

        if (!tvb_bytes_exist(tvb, offset, 1)) {
            pinfo->desegment_offset = 0;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return 0;
        }

        while (tvb_get_guint8(tvb, offset) & ~SDNV_MASK) {
            if (bytecount > (int)sizeof(int)) {
                /* invalid length field */
                return 0;
            }

            bytecount++;
            offset++;

            if (!tvb_bytes_exist(tvb, offset, 1)) {
                pinfo->desegment_offset = 0;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return 0;
            }
        }
        break;
    case TCP_CONVERGENCE_KEEP_ALIVE:
    case TCP_CONVERGENCE_REFUSE_BUNDLE:
        /* always 1 byte */
        break;
    case TCP_CONVERGENCE_SHUTDOWN:
        if ((conv_hdr &
                ~(TCP_CONVERGENCE_TYPE_MASK | TCP_CONVERGENCE_SHUTDOWN_FLAGS)) != 0) {
            /* Not for us */
            return 0;
        }
        break;
    default:
        if (conv_hdr == (guint8)magic[0]) {
            if (!tvb_bytes_exist(tvb, 0, 4) || tvb_memeql(tvb, 0, magic, 4)) {
                /* Not for us */
                return 0;
            }

            tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 8, get_dtn_contact_header_len, dissect_dtn_contact_header, data);
            return tvb_captured_length(tvb);
        }

        /* Not for us */
        return 0;
    };

    processed_length = get_tcpcl_pdu_len(pinfo, tvb, 0, data);

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 1, get_tcpcl_pdu_len, dissect_tcpcl_pdu, data);

    return processed_length;
}

static int
dissect_bundle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *ti_bundle_protocol;
    proto_tree *bundle_tree, *primary_tree;
    int         primary_header_size;
    gboolean    lastheader = FALSE;
    int         offset = 0;
    guint8      version, pri_hdr_procflags;
    /* Custodian from Primary Block, used to validate CTEB */
    gchar      *bundle_custodian = NULL;


    version = tvb_get_guint8(tvb, offset);  /* Primary Header Version */
    if ((version != 4) && (version != 5) && (version != 6)) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bundle");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    ti_bundle_protocol = proto_tree_add_item(tree, proto_bundle, tvb, offset, -1, ENC_NA);
    bundle_tree = proto_item_add_subtree(ti_bundle_protocol, ett_bundle);

    primary_tree = proto_tree_add_subtree(bundle_tree, tvb, offset, -1, ett_primary_hdr, &ti, "Primary Bundle Header");

    proto_tree_add_item(primary_tree, hf_bundle_pdu_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (version == 4) {
        primary_header_size = dissect_version_4_primary_header(pinfo, primary_tree, tvb,
                                &pri_hdr_procflags, &bundle_custodian);
    }
    else {
        primary_header_size = dissect_version_5_and_6_primary_header(pinfo, primary_tree, tvb,
                                &pri_hdr_procflags, &bundle_custodian);
    }

    if (primary_header_size == 0) {      /*Couldn't parse primary header*/
        col_add_str(pinfo->cinfo, COL_INFO, "Protocol Error");
        return(0);      /*Give up*/
    }

    proto_item_set_len(ti, primary_header_size);
    offset = primary_header_size;

    /*
     * Done with primary header; decode the remaining headers
     */

    while (lastheader == FALSE) {
        guint8 next_header_type;

        next_header_type = tvb_get_guint8(tvb, offset);
        if (next_header_type == BUNDLE_BLOCK_TYPE_PAYLOAD) {

            /*
             * Returns payload size or 0 if can't parse payload
             */
            offset = dissect_payload_header(bundle_tree, tvb, pinfo, offset, version, pri_hdr_procflags, &lastheader);
        }
        else {  /*Assume anything else is a Metadata Block*/
            offset = display_extension_block(bundle_tree, tvb, pinfo, offset, bundle_custodian, &lastheader);
        }
    }

    proto_item_set_len(ti_bundle_protocol, offset);

    return(offset);
}

static void
bundle_defragment_init(void) {
    reassembly_table_init(&msg_reassembly_table,
                          &addresses_reassembly_table_functions);
}

static void
bundle_defragment_cleanup(void) {
    reassembly_table_destroy(&msg_reassembly_table);
}


void proto_reg_handoff_bundle(void);
void proto_register_bundle(void);

void
proto_register_bundle(void)
{

    static hf_register_info hf[] = {
        {&hf_bundle_pdu_version,
         {"Bundle Version", "bundle.version",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
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
         {"Class of Service Flags", "bundle.primary.proc.cos",
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
          FT_UINT8, BASE_DEC, VALS(cosflags_priority_vals), BUNDLE_COSFLAGS_PRIORITY_MASK, NULL, HFILL}
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
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_primary_dictionary_len,
         {"Dictionary Length", "bundle.primary.dictionary_len",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_primary_fragment_offset,
         {"Fragment Offset", "bundle.primary.fragment_offset",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_primary_total_adu_len,
         {"Total Application Data Unit Length", "bundle.primary.total_adu_len",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_primary_timestamp_seq_num64,
         {"Timestamp Sequence Number", "bundle.primary.timestamp_seq_num",
          FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_primary_timestamp_seq_num32,
         {"Timestamp Sequence Number", "bundle.primary.timestamp_seq_num",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_primary_timestamp,
         {"Timestamp", "bundle.primary.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_dest_scheme_offset_u16,
         {"Destination Scheme Offset", "bundle.primary.destschemeoff",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_dest_scheme_offset_i32,
         {"Destination Scheme Offset", "bundle.primary.destschemeoff",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_dest_ssp_offset_u16,
         {"Destination SSP Offset", "bundle.primary.destssspoff",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_dest_ssp_offset_i32,
         {"Destination SSP Offset", "bundle.primary.destssspoff",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_source_scheme_offset_u16,
         {"Source Scheme Offset", "bundle.primary.srcschemeoff",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_source_scheme_offset_i32,
         {"Source Scheme Offset", "bundle.primary.srcschemeoff",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_source_ssp_offset_u16,
         {"Source SSP Offset", "bundle.primary.srcsspoff",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_source_ssp_offset_i32,
         {"Source SSP Offset", "bundle.primary.srcsspoff",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_report_scheme_offset_u16,
         {"Report Scheme Offset", "bundle.primary.rptschemeoff",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_report_scheme_offset_i32,
         {"Report Scheme Offset", "bundle.primary.rptschemeoff",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_report_ssp_offset_u16,
         {"Report SSP Offset", "bundle.primary.rptsspoff",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_report_ssp_offset_i32,
         {"Report SSP Offset", "bundle.primary.rptsspoff",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_cust_scheme_offset_u16,
         {"Custodian Scheme Offset", "bundle.primary.custschemeoff",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_cust_scheme_offset_i32,
         {"Custodian Scheme Offset", "bundle.primary.custschemeoff",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_cust_ssp_offset_u16,
         {"Custodian SSP Offset", "bundle.primary.custsspoff",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_cust_ssp_offset_i32,
         {"Custodian SSP Offset", "bundle.primary.custsspoff",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
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
         {"Creation Timestamp", "bundle.primary.creation_timestamp",
          FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_lifetime,
         {"Lifetime", "bundle.primary.lifetime",
          FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_lifetime_sdnv,
         {"Lifetime", "bundle.primary.lifetime",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_payload_length,
         {"Payload Length", "bundle.payload.length",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_payload_flags,
         {"Payload Header Processing Flags", "bundle.payload.proc.flag",
          FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_payload_header_type,
         {"Header Type", "bundle.payload.proc.header_type",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_payload_data,
         {"Payload Data", "bundle.payload.data",
          FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
        {&hf_bundle_admin_record_type,
         {"Administrative Record Type", "bundle.admin.record_type",
          FT_UINT8, BASE_DEC, VALS(admin_record_type_vals), 0xF0, NULL, HFILL}
        },
        {&hf_bundle_admin_record_fragment,
         {"Administrative Record for Fragment", "bundle.admin.record_fragment",
          FT_BOOLEAN, 8, TFS(&tfs_yes_no), ADMIN_REC_FLAGS_FRAGMENT, NULL, HFILL}
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
        {&hf_bundle_admin_fragment_offset,
         {"Fragment Offset", "bundle.admin.fragment_offset",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_fragment_length,
         {"Fragment Length", "bundle.admin.fragment_length",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_timestamp_seq_num64,
         {"Timestamp Sequence Number", "bundle.admin.timestamp_seq_num",
          FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_timestamp_seq_num32,
         {"Timestamp Sequence Number", "bundle.admin.timestamp_seq_num",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_endpoint_length,
         {"Endpoint Length", "bundle.admin.endpoint_length",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_endpoint_id,
         {"Bundle Endpoint ID", "bundle.admin.endpoint_id",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_receipt_time,
         {"Bundle Received Time", "bundle.admin.status.receipttime",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_accept_time,
         {"Bundle Accepted Time", "bundle.admin.status.accepttime",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_forward_time,
         {"Bundle Forwarded Time", "bundle.admin.status.forwardtime",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_delivery_time,
         {"Bundle Delivered Time", "bundle.admin.status.deliverytime",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_delete_time,
         {"Bundle Deleted Time", "bundle.admin.status.deletetime",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_ack_time,
         {"Bundle Acknowledged Time", "bundle.admin.status.acktime",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_timestamp_copy,
         {"Bundle Creation Timestamp", "bundle.admin.status.timecopy",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_admin_signal_time,
         {"Bundle Signal Time", "bundle.admin.signal.time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_block_control_flags,
         {"Block Processing Control Flags", "bundle.block.control.flags",
          FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_block_control_flags_sdnv,
         {"Block Processing Control Flags", "bundle.block.control.flags",
          FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_block_control_block_length,
         {"Block Length", "bundle.block.length",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_block_control_block_cteb_custody_id,
         {"CTEB Custody ID", "bundle.block.cteb_custody_id",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_block_control_block_cteb_creator_custodian_eid,
         {"CTEB Creator Custodian EID", "bundle.block.cteb_creator_custodian_eid",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
        },
        {&hf_bundle_status_report_reason_code,
         {"Status Report Reason Code", "bundle.status_report_reason_code",
          FT_UINT8, BASE_DEC, VALS(status_report_reason_codes), 0x0, NULL, HFILL}
        },
        {&hf_bundle_custody_trf_succ_flg,
         {"Custody Transfer Succeeded Flag", "bundle.custody_trf_succ_flg",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        {&hf_bundle_custody_signal_reason,
         {"Custody Signal Reason Code", "bundle.custody_signal_reason_code",
          FT_UINT8, BASE_DEC, VALS(custody_signal_reason_codes), ADMIN_REC_CUSTODY_REASON_MASK, NULL, HFILL}
        },
        {&hf_bundle_custody_id_range_start,
         {"CTEB Custody ID Range Start", "bundle.custody_id_range_start",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_custody_id_range_end,
         {"CTEB Custody ID Range End", "bundle.custody_id_range_end",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_bundle_block_type_code,
         {"Block Type Code", "bundle.block_type_code",
          FT_UINT8, BASE_DEC, VALS(bundle_block_type_codes), 0x0, NULL, HFILL}
        },
        {&hf_bundle_unprocessed_block_data,
         {"Block Data", "bundle.block_data",
          FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ecos_flags,
         {"ECOS Flags", "bundle.block.ecos.flags",
          FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ecos_flags_critical,
         {"Critical", "bundle.block.ecos.flags.critical",
          FT_BOOLEAN, 8, NULL, ECOS_FLAGS_CRITICAL, NULL, HFILL}
        },
        {&hf_ecos_flags_streaming,
         {"Streaming", "bundle.block.ecos.flags.streaming",
          FT_BOOLEAN, 8, NULL, ECOS_FLAGS_STREAMING, NULL, HFILL}
        },
        {&hf_ecos_flags_flowlabel,
         {"Flow Label", "bundle.block.ecos.flags.flowlabel",
          FT_BOOLEAN, 8, NULL, ECOS_FLAGS_FLOWLABEL, NULL, HFILL}
        },
        {&hf_ecos_flags_reliable,
         {"Reliable", "bundle.block.ecos.flags.reliable",
          FT_BOOLEAN, 8, NULL, ECOS_FLAGS_RELIABLE, NULL, HFILL}
        },
        {&hf_ecos_flow_label,
         {"ECOS Flow Label", "bundle.block.ecos.flow_label",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ecos_ordinal,
         {"ECOS Ordinal", "bundle.block.ecos.ordinal",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
    };

    static hf_register_info hf_tcpcl[] = {
        {&hf_tcp_convergence_pkt_type,
         {"Pkt Type", "tcpcl.pkt_type",
          FT_UINT8, BASE_DEC, VALS(packet_type_vals), 0xF0, NULL, HFILL}
        },
        {&hf_tcp_convergence_data_procflags,
         {"TCP Convergence Data Flags", "tcpcl.data.proc.flag",
          FT_UINT8, BASE_HEX, NULL, TCP_CONVERGENCE_DATA_FLAGS, NULL, HFILL}
        },
        {&hf_tcp_convergence_data_procflags_start,
         {"Segment contains start of bundle", "tcpcl.data.proc.start",
          FT_BOOLEAN, 8, NULL, TCP_CONVERGENCE_DATA_START_FLAG, NULL, HFILL}
        },
        {&hf_tcp_convergence_data_procflags_end,
         {"Segment contains end of Bundle", "tcpcl.data.proc.end",
          FT_BOOLEAN, 8, NULL, TCP_CONVERGENCE_DATA_END_FLAG, NULL, HFILL}
        },
        {&hf_tcp_convergence_data_segment_length,
         {"Segment Length", "tcpcl.data.length",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_tcp_convergence_shutdown_flags,
         {"TCP Convergence Shutdown Flags", "tcpcl.shutdown.flags",
          FT_UINT8, BASE_HEX, NULL, TCP_CONVERGENCE_SHUTDOWN_FLAGS, NULL, HFILL}
        },
        {&hf_tcp_convergence_shutdown_flags_reason,
         {"Shutdown includes Reason Code", "tcpcl.shutdown.reason.flag",
          FT_BOOLEAN, 8, NULL, TCP_CONVERGENCE_SHUTDOWN_REASON, NULL, HFILL}
        },
        {&hf_tcp_convergence_shutdown_flags_delay,
         {"Shutdown includes Reconnection Delay", "tcpcl.shutdown.delay.flag",
          FT_BOOLEAN, 8, NULL, TCP_CONVERGENCE_SHUTDOWN_DELAY, NULL, HFILL}
        },
        {&hf_tcp_convergence_shutdown_reason,
         {"Shutdown Reason Code", "tcpcl.shutdown.reason",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_tcp_convergence_shutdown_delay,
         {"Shutdown Reconnection Delay", "tcpcl.shutdown.delay",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_tcp_convergence_ack_length,
         {"Ack Length", "tcpcl.ack.length",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_contact_hdr_version,
         {"Version", "tcpcl.contact_hdr.version",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_contact_hdr_flags,
         {"Flags", "tcpcl.contact_hdr.flags",
          FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_contact_hdr_flags_ack_req,
         {"Bundle Acks Requested", "tcpcl.contact_hdr.flags.ackreq",
          FT_BOOLEAN, 8, NULL, TCP_CONV_BUNDLE_ACK_FLAG, NULL, HFILL}
        },
        {&hf_contact_hdr_flags_frag_enable,
         {"Reactive Fragmentation Enabled", "tcpcl.contact_hdr.flags.fragen",
          FT_BOOLEAN, 8, NULL, TCP_CONV_REACTIVE_FRAG_FLAG, NULL, HFILL}
        },
        {&hf_contact_hdr_flags_nak,
         {"Support Negative Acknowledgements", "tcpcl.contact_hdr.flags.nak",
          FT_BOOLEAN, 8, NULL, TCP_CONV_CONNECTOR_RCVR_FLAG, NULL, HFILL}
        },
        {&hf_contact_hdr_keep_alive,
         {"Keep Alive", "tcpcl.contact_hdr.keep_alive",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_contact_hdr_magic,
         {"Magic", "tcpcl.contact_hdr.magic",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_contact_hdr_local_eid,
         {"Local EID", "tcpcl.contact_hdr.local_eid",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_contact_hdr_local_eid_length,
         {"Local EID Length", "tcpcl.contact_hdr.local_eid_length",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
    };

    static gint *ett[] = {
        &ett_bundle,
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

    static gint *ett_tcpcl[] = {
        &ett_tcp_conv,
        &ett_tcp_conv_hdr,
        &ett_msg_fragment,
        &ett_msg_fragments,
    };

    static ei_register_info ei[] = {
        { &ei_bundle_control_flags_length,
          { "bundle.block.control.flags.length", PI_UNDECODED, PI_WARN, "Wrong bundle control flag length", EXPFILL }
        },
        { &ei_bundle_payload_length,
          { "bundle.payload.length.invalid", PI_PROTOCOL, PI_ERROR, "Payload length error", EXPFILL }
        },
        { &ei_bundle_sdnv_length,
          { "bundle.sdnv_length_invalid", PI_PROTOCOL, PI_ERROR, "SDNV length error", EXPFILL }
        },
        { &ei_bundle_timestamp_seq_num,
          { "bundle.timestamp_seq_num_invalid", PI_PROTOCOL, PI_ERROR, "Timestamp Sequence Number error", EXPFILL }
        },
        { &ei_bundle_offset_error,
          { "bundle.offset_error", PI_PROTOCOL, PI_WARN, "Offset field error", EXPFILL }
        },
        { &ei_bundle_block_control_flags,
          { "bundle.block.control.flags.error", PI_PROTOCOL, PI_WARN, "Control flag error", EXPFILL }
        },
        { &ei_block_control_block_cteb_invalid,
          { "bundle.block.control.cteb_invalid", PI_PROTOCOL, PI_WARN, "CTEB Is Invalid", EXPFILL }
        },
        { &ei_block_control_block_cteb_valid,
          { "bundle.block.control.cteb_valid", PI_PROTOCOL, PI_NOTE, "CTEB Is Valid", EXPFILL }
        },
    };

    static ei_register_info ei_tcpcl[] = {
        { &ei_tcp_convergence_data_flags,
          { "tcpcl.data.flags.invalid", PI_PROTOCOL, PI_WARN, "Invalid TCP CL Data Segment Flags", EXPFILL }
        },
        { &ei_tcp_convergence_segment_length,
          { "tcpcl.data.length.invalid", PI_PROTOCOL, PI_ERROR, "Invalid Data Length", EXPFILL }
        },
        { &ei_tcp_convergence_ack_length,
          { "tcpcl.ack.length.error", PI_PROTOCOL, PI_WARN, "Ack Length: Error", EXPFILL }
        },
    };

    module_t *bundle_module;
    expert_module_t *expert_bundle, *expert_tcpcl;

    proto_bundle  = proto_register_protocol("Bundle Protocol", "Bundle", "bundle");
    bundle_handle = register_dissector("bundle", dissect_bundle, proto_bundle);
    bundle_module = prefs_register_protocol(proto_bundle, proto_reg_handoff_bundle);

    proto_tcp_conv = proto_register_protocol ("DTN TCP Convergence Layer Protocol", "TCPCL", "tcpcl");

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
    expert_bundle = expert_register_protocol(proto_bundle);
    expert_register_field_array(expert_bundle, ei, array_length(ei));

    proto_register_field_array(proto_tcp_conv, hf_tcpcl, array_length(hf_tcpcl));
    proto_register_subtree_array(ett_tcpcl, array_length(ett_tcpcl));
    expert_tcpcl = expert_register_protocol(proto_tcp_conv);
    expert_register_field_array(expert_tcpcl, ei_tcpcl, array_length(ei_tcpcl));

    register_init_routine(bundle_defragment_init);
    register_cleanup_routine(bundle_defragment_cleanup);
}

void
proto_reg_handoff_bundle(void)
{
    static dissector_handle_t tcpcl_handle;
    static guint tcp_port;
    static guint udp_port;

    static int Initialized = FALSE;

    if (!Initialized) {
        tcpcl_handle = create_dissector_handle(dissect_tcpcl, proto_bundle);
        Initialized  = TRUE;
    }
    else {
        dissector_delete_uint("tcp.port", tcp_port, tcpcl_handle);
        dissector_delete_uint("udp.port", udp_port, bundle_handle);
    }
    tcp_port = bundle_tcp_port;
    udp_port = bundle_udp_port;
    dissector_add_uint("tcp.port", tcp_port, tcpcl_handle);
    dissector_add_uint("udp.port", udp_port, bundle_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
