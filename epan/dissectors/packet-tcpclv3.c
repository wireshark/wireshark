/* packet-tcpclv3.c
 * References:
 *     RFC 7242: https://tools.ietf.org/html/rfc7242
 *
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
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Specification reference:
 * RFC 5050
 * https://tools.ietf.org/html/rfc5050
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
#include <epan/reassemble.h>
#include <epan/expert.h>
#include "packet-tcpclv3.h"
#include "packet-bpv6.h"
#include "packet-tcp.h"

/* For Reassembling TCP Convergence Layer segments */
static reassembly_table msg_reassembly_table;

static const char magic[] = {'d', 't', 'n', '!'};

static int proto_tcp_conv = -1;

/* TCP Convergence Header Variables */
static int hf_tcp_convergence_pkt_type = -1;

/* Refuse-Bundle reason code */
static int hf_dtn_refuse_bundle_reason_code = -1;

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

/* Tree Node Variables */
static gint ett_conv_flags = -1;
static gint ett_shutdown_flags = -1;
static gint ett_contact_hdr_flags = -1;
static gint ett_tcp_conv = -1;
static gint ett_tcp_conv_hdr = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static expert_field ei_tcp_convergence_data_flags = EI_INIT;
static expert_field ei_tcp_convergence_segment_length = EI_INIT;
static expert_field ei_tcp_convergence_ack_length = EI_INIT;


static dissector_handle_t bundle_handle;

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
    {((TCP_CONVERGENCE_LENGTH>>4)      & 0x0F), "Length"},
    {0, NULL}
};

/* Refuse-Bundle Reason-Code Flags as per RFC-7242: Section-5.4 */
static const value_string refuse_bundle_reason_code[] = {
    {TCP_REFUSE_BUNDLE_REASON_UNKNOWN,       "Reason for refusal is unknown"},
    {TCP_REFUSE_BUNDLE_REASON_RX_COMPLETE,   "Complete Bundle Received"},
    {TCP_REFUSE_BUNDLE_REASON_RX_EXHAUSTED,  "Receiver's resources exhausted"},
    {TCP_REFUSE_BUNDLE_REASON_RX_RETRANSMIT, "Receiver expects re-transmission of bundle"},
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
    /* Reassembled data field */
    NULL,
    /*Tag*/
    "Message fragments"
};

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

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCPCLv3");
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
    expert_field *ei_bundle_sdnv_length;
    eid_length = evaluate_sdnv_ei(tvb, offset, &sdnv_length, &ei_bundle_sdnv_length);
    ti = proto_tree_add_int(tree, hf_contact_hdr_local_eid_length, tvb, offset, sdnv_length, eid_length);
    if (ei_bundle_sdnv_length) {
        expert_add_info(pinfo, ti, ei_bundle_sdnv_length);
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

    case TCP_CONVERGENCE_LENGTH:
        /* get length from sdnv */
        len = evaluate_sdnv(tvb, offset+1, &bytecount);
        if (len < 0)
            return 0;
        return bytecount+1;

    }

    /* This probably isn't a TCPCL/Bundle packet, so just stop dissection */
    return -1;
}

static int
dissect_tcpcl_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    guint8         conv_hdr;
    guint8         refuse_bundle_hdr;
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

            new_tvb = process_reassembled_data(tvb, offset + convergence_hdr_size,
                                                pinfo, "Reassembled DTN", frag_msg,
                                                &msg_frag_items, NULL,
                                                proto_tree_get_parent_tree(tree)
            );

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
            col_set_str(pinfo->cinfo, COL_INFO, "TCPL KEEPALIVE Segment");
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
            col_set_str(pinfo->cinfo, COL_INFO, "TCPL SHUTDOWN Segment");
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
            col_set_str(pinfo->cinfo, COL_INFO, "TCPL REFUSE_BUNDLE Segment");
        }

        refuse_bundle_hdr = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(conv_tree, hf_dtn_refuse_bundle_reason_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const((refuse_bundle_hdr>>4)&0xF, refuse_bundle_reason_code, "Unknown"));

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


void
proto_register_tcpclv3(void)
{

    static hf_register_info hf_tcpcl[] = {
        {&hf_tcp_convergence_pkt_type,
         {"Pkt Type", "tcpcl.pkt_type",
          FT_UINT8, BASE_DEC, VALS(packet_type_vals), 0xF0, NULL, HFILL}
        },
        {&hf_dtn_refuse_bundle_reason_code,
         {"Reason-Code", "tcpcl.refuse.reason_code",
          FT_UINT8, BASE_DEC, VALS(refuse_bundle_reason_code), 0x0F, NULL, HFILL}
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

        {&hf_msg_fragments,
         {"Message Fragments", "tcpcl.msg.fragments",
          FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_msg_fragment,
         {"Message Fragment", "tcpcl.msg.fragment",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_msg_fragment_overlap,
         {"Message fragment overlap", "tcpcl.msg.fragment.overlap",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_msg_fragment_overlap_conflicts,
         {"Message fragment overlapping with conflicting data",
          "tcpcl.msg.fragment.overlap.conflicts",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_msg_fragment_multiple_tails,
         {"Message has multiple tails", "tcpcl.msg.fragment.multiple_tails",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_msg_fragment_too_long_fragment,
         {"Message fragment too long", "tcpcl.msg.fragment.too_long_fragment",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_msg_fragment_error,
         {"Message defragmentation error", "tcpcl.msg.fragment.error",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_msg_fragment_count,
         {"Message fragment count", "tcpcl.msg.fragment.count",
          FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_msg_reassembled_in,
         {"Reassembled in", "tcpcl.msg.reassembled.in",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_msg_reassembled_length,
         {"Reassembled DTN length", "tcpcl.msg.reassembled.length",
          FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
    };

    static gint *ett_tcpcl[] = {
        &ett_tcp_conv,
        &ett_tcp_conv_hdr,
        &ett_conv_flags,
        &ett_contact_hdr_flags,
        &ett_shutdown_flags,
        &ett_msg_fragment,
        &ett_msg_fragments,
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

    expert_module_t *expert_tcpcl;

    proto_tcp_conv = proto_register_protocol ("DTN TCP Convergence Layer Protocol", "TCPCL", "tcpcl");

    proto_register_field_array(proto_tcp_conv, hf_tcpcl, array_length(hf_tcpcl));
    proto_register_subtree_array(ett_tcpcl, array_length(ett_tcpcl));
    expert_tcpcl = expert_register_protocol(proto_tcp_conv);
    expert_register_field_array(expert_tcpcl, ei_tcpcl, array_length(ei_tcpcl));

    reassembly_table_register(&msg_reassembly_table,
                          &addresses_reassembly_table_functions);

}

void
proto_reg_handoff_tcpclv3(void)
{
    dissector_handle_t tcpcl_handle;

    bundle_handle = find_dissector("bundle");

    tcpcl_handle = create_dissector_handle(dissect_tcpcl, proto_tcp_conv);
    dissector_add_uint_with_preference("tcp.port", BUNDLE_PORT, tcpcl_handle);
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
