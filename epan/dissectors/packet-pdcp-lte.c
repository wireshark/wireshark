/* Routines for LTE PDCP/ROHC
 *
 * Martin Mathieson
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>

#include "packet-pdcp-lte.h"

/* Described in:
 * 3GPP TS 36.323 Evolved Universal Terrestrial Radio Access (E-UTRA)
 *                Packet Data Convergence Protocol (PDCP) specification
 *
 * RFC 3095       RObust Header Compression (ROHC):
 *                Framework and four profiles: RTP, UDP, ESP, and uncompressed
 */


/* TODO:
   - Update to latest version of 36.323
   - Complete ROHC support for RTP and extend to other profiles (including ROHCv2)
   - Support for decryption
   - Verify MAC authentication bytes
   - Call LTE RRC dissector for uncompressed, signalling payloads
*/


/* Initialize the protocol and registered fields. */
int proto_pdcp_lte = -1;

static int hf_pdcp_lte_configuration = -1;

static int hf_pdcp_lte_rohc = -1;
static int hf_pdcp_lte_rohc_compression = -1;
static int hf_pdcp_lte_rohc_mode = -1;
static int hf_pdcp_lte_rohc_rnd = -1;
static int hf_pdcp_lte_rohc_udp_checksum_present = -1;
static int hf_pdcp_lte_rohc_profile = -1;
static int hf_pdcp_lte_no_header_pdu = -1;
static int hf_pdcp_lte_plane = -1;
static int hf_pdcp_lte_seqnum_length = -1;

static int hf_pdcp_lte_cid_inclusion_info = -1;
static int hf_pdcp_lte_large_cid_present = -1;

static int hf_pdcp_lte_seq_num_5 = -1;
static int hf_pdcp_lte_seq_num_7 = -1;
static int hf_pdcp_lte_reserved3 = -1;
static int hf_pdcp_lte_seq_num_12 = -1;
static int hf_pdcp_lte_signalling_data = -1;
static int hf_pdcp_lte_mac = -1;
static int hf_pdcp_lte_data_control = -1;
static int hf_pdcp_lte_user_plane_data = -1;
static int hf_pdcp_lte_control_pdu_type = -1;
static int hf_pdcp_lte_lis = -1;
static int hf_pdcp_lte_bitmap = -1;
static int hf_pdcp_lte_bitmap_not_received = -1;

static int hf_pdcp_lte_rohc_padding = -1;
static int hf_pdcp_lte_rohc_r_0_crc = -1;
static int hf_pdcp_lte_rohc_feedback = -1;

static int hf_pdcp_lte_rohc_type0_t = -1;
static int hf_pdcp_lte_rohc_type1_t = -1;
static int hf_pdcp_lte_rohc_type2_t = -1;

static int hf_pdcp_lte_rohc_d = -1;
static int hf_pdcp_lte_rohc_ir_crc = -1;

static int hf_pdcp_lte_rohc_static_ipv4 = -1;
static int hf_pdcp_lte_rohc_ip_version = -1;
static int hf_pdcp_lte_rohc_ip_protocol = -1;
static int hf_pdcp_lte_rohc_ip_src = -1;
static int hf_pdcp_lte_rohc_ip_dst = -1;

static int hf_pdcp_lte_rohc_static_udp = -1;
static int hf_pdcp_lte_rohc_static_udp_src_port = -1;
static int hf_pdcp_lte_rohc_static_udp_dst_port = -1;

static int hf_pdcp_lte_rohc_static_rtp = -1;
static int hf_pdcp_lte_rohc_static_rtp_ssrc = -1;

static int hf_pdcp_lte_rohc_dynamic_ipv4 = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_tos = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_ttl = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_id = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_df = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_rnd = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_nbo = -1;

static int hf_pdcp_lte_rohc_dynamic_udp = -1;
static int hf_pdcp_lte_rohc_dynamic_udp_checksum = -1;
static int hf_pdcp_lte_rohc_dynamic_udp_seqnum = -1;

static int hf_pdcp_lte_rohc_dynamic_rtp = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_rx = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_cc = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_seqnum = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_timestamp = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_reserved3 = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_x = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_mode = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_tis = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_tss = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_ts_stride = -1;

static int hf_pdcp_lte_rohc_ts = -1;
static int hf_pdcp_lte_rohc_m = -1;

static int hf_pdcp_lte_add_cid = -1;
static int hf_pdcp_lte_large_cid = -1;

static int hf_pdcp_lte_uo0_sn = -1;

static int hf_pdcp_lte_r0_sn = -1;
static int hf_pdcp_lte_r0_crc_sn = -1;
static int hf_pdcp_lte_r0_crc_crc = -1;

static int hf_pdcp_lte_feedback_code = -1;
static int hf_pdcp_lte_feedback_size = -1;
static int hf_pdcp_lte_feedback_feedback1 = -1;
static int hf_pdcp_lte_feedback_feedback2 = -1;
static int hf_pdcp_lte_feedback_ack_type = -1;
static int hf_pdcp_lte_feedback_mode = -1;
static int hf_pdcp_lte_feedback_sn = -1;
static int hf_pdcp_lte_feedback_option = -1;
static int hf_pdcp_lte_feedback_length = -1;
static int hf_pdcp_lte_feedback_crc = -1;
static int hf_pdcp_lte_feedback_option_sn = -1;
static int hf_pdcp_lte_feedback_option_clock = -1;

static int hf_pdcp_lte_ip_id = -1;
static int hf_pdcp_lte_udp_checksum = -1;
static int hf_pdcp_lte_payload = -1;


/* Protocol subtree. */
static int ett_pdcp = -1;
static int ett_pdcp_configuration = -1;
static int ett_pdcp_packet = -1;
static int ett_pdcp_rohc = -1;
static int ett_pdcp_rohc_static_ipv4 = -1;
static int ett_pdcp_rohc_static_udp = -1;
static int ett_pdcp_rohc_static_rtp = -1;
static int ett_pdcp_rohc_dynamic_ipv4 = -1;
static int ett_pdcp_rohc_dynamic_udp = -1;
static int ett_pdcp_rohc_dynamic_rtp = -1;


static const value_string pdcp_plane_vals[] = {
    { SIGNALING_PLANE,    "Signalling" },
    { USER_PLANE,         "User" },
    { 0,   NULL }
};


static const value_string rohc_mode_vals[] = {
    { UNIDIRECTIONAL,            "Unidirectional" },
    { OPTIMISTIC_BIDIRECTIONAL,  "Optimistic Bidirectional" },
    { RELIABLE_BIDIRECTIONAL,    "Reliable Bidirectional" },
    { 0,   NULL }
};


/* TODO: add more */
static const value_string rohc_profile_vals[] = {
    { 0,   "Uncompressed" },
    { 1,   "RTP" },
    { 2,   "UDP" },
    { 3,   "ESP/IP" },
    { 0,   NULL }
};

static const value_string pdu_type_vals[] = {
    { 0,   "Control PDU" },
    { 1,   "Data PDU" },
    { 0,   NULL }
};

static const value_string feedback_ack_vals[] = {
    { 0,   "ACK" },
    { 1,   "NACK" },
    { 2,   "STATIC-NACK" },
    { 0,   NULL }
};

static const value_string feedback_option_vals[] = {
    { 1,   "CRC" },
    { 2,   "REJECT" },
    { 3,   "SN-Not-Valid" },
    { 4,   "SN" },
    { 5,   "Clock" },
    { 6,   "Jitter" },
    { 7,   "Loss" },
    { 0,   NULL }
};

static const value_string control_pdu_type_vals[] = {
    { 0,   "PDCP Status report" },
    { 1,   "Header Compression Feedback Information" },
    { 0,   NULL }
};

static const value_string t_vals[] = {
    { 0,   "ID message format" },
    { 1,   "TS message format" },
    { 0,   NULL }
};

static const value_string ip_protocol_vals[] = {
    { 6,   "TCP" },
    { 17,  "UDP" },
    { 0,   NULL }
};


dissector_handle_t ip_handle = 0;


/* Preference variables */
static gboolean global_pdcp_show_feedback_option_tag_length = FALSE;
static gboolean global_pdcp_dissect_user_plane_as_ip = FALSE;
static gboolean global_pdcp_dissect_signalling_plane_as_rrc = FALSE;  /* Not currently used */
static gboolean global_pdcp_dissect_rohc = FALSE;

/* Dissect a Large-CID field.
   Return following offset */
static int dissect_large_cid(proto_tree *tree,
                             tvbuff_t *tvb,
                             int offset)
{
    guint8 first_octet = tvb_get_guint8(tvb, offset);

    if ((first_octet & 0x80) == 0) {
        /* One byte */
        proto_tree_add_uint(tree, hf_pdcp_lte_large_cid, tvb, offset, 1,
                            first_octet);
        return offset+1;
    }
    else {
        /* Two bytes */
        guint16 bytes = tvb_get_ntohs(tvb, offset) & 0x7fff;
        proto_tree_add_uint(tree, hf_pdcp_lte_large_cid, tvb, offset, 2,
                            bytes);
        return offset+2;
    }

}

static int dissect_pdcp_dynamic_chain(proto_tree *tree,
                                      proto_item *root_item _U_,
                                      tvbuff_t *tvb,
                                      int offset,
                                      struct pdcp_lte_info *p_pdcp_info,
                                      packet_info *pinfo)
{
    /* IPv4 dynamic */
    if (p_pdcp_info->rohc_ip_version == 4) {
        proto_tree *dynamic_ipv4_tree;
        proto_item *root_ti;
        int tree_start_offset = offset;
        guint8 tos, ttl, id, rnd, nbo;

        /* Create dynamic IPv4 subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_dynamic_ipv4, tvb, offset, -1, FALSE);
        dynamic_ipv4_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_dynamic_ipv4);

        /* ToS */
        tos = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_tos, tvb, offset, 1, FALSE);
        offset++;

        /* TTL */
        ttl = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_ttl, tvb, offset, 1, FALSE);
        offset++;

        /* IP-ID */
        id = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_id, tvb, offset, 1, FALSE);
        offset++;

        /* IP flags */
        rnd = (tvb_get_guint8(tvb, offset) & 0x40) >> 6;
        nbo = (tvb_get_guint8(tvb, offset) & 0x20) >> 5;
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_df, tvb, offset, 1, FALSE);
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_rnd, tvb, offset, 1, FALSE);
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_nbo, tvb, offset, 1, FALSE);

        /* TODO: general extension header list... */
        offset += 3;

        /* Set proper length for subtree */
        proto_item_set_len(root_ti, offset-tree_start_offset);

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (ToS=%u, TTL=%u, ID=%u, RND=%u, NBO=%u)",
                               tos, ttl, id, rnd, nbo);
    }

    /* UDP dynamic */
    if ((p_pdcp_info->profile == 1) ||
        (p_pdcp_info->profile == 2)) {

        proto_tree *dynamic_udp_tree;
        proto_item *root_ti;
        unsigned short checksum;

        /* Create dynamic UDP subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_dynamic_udp, tvb, offset, 2, FALSE);
        dynamic_udp_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_dynamic_udp);

        /* 16-bit checksum */
        checksum = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(dynamic_udp_tree, hf_pdcp_lte_rohc_dynamic_udp_checksum, tvb, offset, 2, FALSE);
        offset +=2;

        if (p_pdcp_info->profile == 2) {
            guint16 seqnum;

            seqnum = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(dynamic_udp_tree, hf_pdcp_lte_rohc_dynamic_udp_seqnum, tvb, offset, 2, FALSE);
            offset +=2;

            /* Add summary to root item */
            proto_item_append_text(root_ti, " (checksum = %04x, seqnum = %u)", checksum, seqnum);
        }
        else {
            /* Add summary to root item */
            proto_item_append_text(root_ti, " (checksum = %04x)", checksum);
        }
    }

    /* RTP dynamic */
    if (p_pdcp_info->profile == 1) {
        proto_tree *dynamic_rtp_tree;
        proto_item *root_ti;
        int tree_start_offset = offset;
        guint8     rx;
        guint8     contributing_csrcs;
        guint16    sequence_number;
        guint32    timestamp;
        guint8     tis=0, tss=0;
        guint64    ts_stride=0;

        /* Create dynamic RTP subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_dynamic_rtp, tvb, offset, -1, FALSE);
        dynamic_rtp_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_dynamic_rtp);

        /* TODO: */
        /* V | P | RX | CC */
        rx = tvb_get_guint8(tvb, offset) & 0x10;
        proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_rx, tvb, offset, 1, FALSE);
        contributing_csrcs = tvb_get_guint8(tvb, offset) & 0x0f;
        proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_cc, tvb, offset, 1, FALSE);
        offset += 1;

        /* TODO: */
        /* M | PT */
        offset += 1;

        /* Sequence number */
        sequence_number = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_seqnum, tvb, offset, 2, FALSE);
        offset += 2;

        /* Timestamp (4 octets) */
        timestamp = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_timestamp, tvb, offset, 4, FALSE);
        offset += 4;

        /* TODO: CSRC list */
        /*offset += (4 * contributing_csrcs); */
        offset++;

        /* TODO: Reserved | X | Mode | TIS | TIS */
        if (rx) {
            guint8 this_byte = tvb_get_guint8(tvb, offset);
            proto_item *reserved_ti = proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_reserved3,
                                                          tvb, offset, 1, FALSE);

            /* Check reserved bits are 0 */
            if ((this_byte & 0xe0) != 0) {
                expert_add_info_format(pinfo, reserved_ti, PI_MALFORMED, PI_ERROR,
                                       "Reserved bits have value 0x%x - should be 0x0",
                                       (this_byte & 0xe0));
            }
            proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_x, tvb, offset, 1, FALSE);
            proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_mode, tvb, offset, 1, FALSE);
            tss = (this_byte & 0x02);
            proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_tss, tvb, offset, 1, FALSE);
            tis = (this_byte & 0x01);
            proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_tis, tvb, offset, 1, FALSE);
            offset++;
        }

        /* TODO: the length of these fields can be learned by looked at the leading bits, see
           RFC 3095, "4.5.6.  Self-describing variable-length values" */
        /* TODO: TS-Stride (1-4 bytes) */
        if (tis) {
            /* Assume encoded in two bytes for now... */
            proto_tree_add_bits_ret_val(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_ts_stride,
                                        tvb, offset*8 + 2, 14, &ts_stride, FALSE);
            offset += 2;
        }

        /* TODO: Time-stride (1-4 bytes) */
        if (tss) {
        }

        /* Set proper length for subtree */
        proto_item_set_len(root_ti, offset-tree_start_offset);

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (seqnum = %u, timestamp = %u)",
                               sequence_number, timestamp);
    }

    return offset;
}



static int dissect_pdcp_irdyn_packet(proto_tree *tree _U_,
                                     proto_item *root_item,
                                     tvbuff_t *tvb _U_,
                                     int offset,
                                     struct pdcp_lte_info *p_pdcp_info _U_,
                                     packet_info *pinfo)
{
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, " IRDYN");
    }
    proto_item_append_text(root_item, " (IRDYN)");

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Profile */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_profile, tvb, offset, 1, FALSE);
    offset++;

    /* 8-bit CRC */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_ir_crc, tvb, offset, 1, FALSE);
    offset++;

    /* Dissect dynamic chain */
    offset = dissect_pdcp_dynamic_chain(tree,
                                        root_item,
                                        tvb,
                                        offset,
                                        p_pdcp_info,
                                        pinfo);
    return offset;
}


static int dissect_pdcp_ir_packet(proto_tree *tree,
                                  proto_item *root_item,
                                  tvbuff_t *tvb,
                                  int offset,
                                  struct pdcp_lte_info *p_pdcp_info,
                                  packet_info *pinfo)
{
    unsigned char dynamic_chain_present;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, " IR");
    }
    proto_item_append_text(root_item, " (IR)");

    /* Is dynamic chain present? */
    dynamic_chain_present = tvb_get_guint8(tvb, offset) & 0x1;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_d, tvb, offset, 1, FALSE);
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Profile */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_profile, tvb, offset, 1, FALSE);
    offset++;

    /* 8-bit CRC */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_ir_crc, tvb, offset, 1, FALSE);
    offset++;

    /* IPv4 static part */
    if (p_pdcp_info->rohc_ip_version == 4) {
        proto_tree *static_ipv4_tree;
        proto_item *root_ti;
        int tree_start_offset = offset;
        guint8  protocol;
        guint32 source, dest;

        /* Create static IPv4 subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_static_ipv4, tvb, offset, -1, FALSE);
        static_ipv4_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_static_ipv4);

        /* IP version (must be 4) */
        proto_tree_add_item(static_ipv4_tree, hf_pdcp_lte_rohc_ip_version, tvb, offset, 1, FALSE);
        offset++;

        /* Protocol */
        protocol = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(static_ipv4_tree, hf_pdcp_lte_rohc_ip_protocol, tvb, offset, 1, FALSE);
        offset++;

        /* Source address */
        source = tvb_get_ipv4(tvb, offset);
        proto_tree_add_item(static_ipv4_tree, hf_pdcp_lte_rohc_ip_src, tvb, offset, 4, FALSE);
        offset += 4;

        /* Dest address */
        dest = tvb_get_ipv4(tvb, offset);
        proto_tree_add_item(static_ipv4_tree, hf_pdcp_lte_rohc_ip_dst, tvb, offset, 4, FALSE);
        offset += 4;

        /* Set proper length for subtree */
        proto_item_set_len(root_ti, offset-tree_start_offset);

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (prot=%s: %s -> %s)",
                               val_to_str(protocol, ip_protocol_vals, "Unknown"),
                               (char*)get_hostname(source),
                               (char*)get_hostname(dest));
    }

    /* UDP static part. TODO: also check protocol from last part!? */
    if ((p_pdcp_info->profile == 1) ||
        (p_pdcp_info->profile == 2)) {

        proto_tree *static_udp_tree;
        proto_item *root_ti;
        int tree_start_offset = offset;
        unsigned short source_port, dest_port;

        /* Create static UDP subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_static_udp, tvb, offset, -1, FALSE);
        static_udp_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_static_udp);

        /* Source port */
        source_port = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(static_udp_tree, hf_pdcp_lte_rohc_static_udp_src_port, tvb, offset, 2, FALSE);
        offset += 2;

        /* Dest port */
        dest_port = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(static_udp_tree, hf_pdcp_lte_rohc_static_udp_src_port, tvb, offset, 2, FALSE);
        offset += 2;

        /* Set proper length for subtree */
        proto_item_set_len(root_ti, offset-tree_start_offset);

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (%u -> %u)", source_port, dest_port);
    }

    /* RTP static */
    if (p_pdcp_info->profile == 1) {
        proto_tree *static_rtp_tree;
        proto_item *root_ti;
        guint32    ssrc;

        /* Create static RTP subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_static_rtp, tvb, offset, 4, FALSE);
        static_rtp_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_static_rtp);

        /* SSRC */
        ssrc = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(static_rtp_tree, hf_pdcp_lte_rohc_static_rtp_ssrc, tvb, offset, 4, FALSE);
        offset += 4;

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (SSRC=%u)", ssrc);
    }


    /* Dynamic chain */
    if (dynamic_chain_present) {
        offset = dissect_pdcp_dynamic_chain(tree,
                                            root_item,
                                            tvb,
                                            offset,
                                            p_pdcp_info,
                                            pinfo);
    }

    return offset;
}



static int dissect_pdcp_feedback_feedback1(proto_tree *tree,
                                           tvbuff_t *tvb,
                                           int offset,
                                           struct pdcp_lte_info *p_pdcp_info _U_,
                                           packet_info *pinfo _U_)
{
    guint8 sn;

    /* TODO: profile-specific */
    sn = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_pdcp_lte_feedback_feedback1, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);
    }

    return offset;
}

/* Includes Large-CID, if present */
static int dissect_pdcp_feedback_feedback2(proto_tree *tree,
                                           tvbuff_t *tvb,
                                           int offset,
                                           int size,
                                           struct pdcp_lte_info *p_pdcp_info _U_,
                                           packet_info *pinfo _U_)
{
    guint8  ack_type;
    guint8  mode;
    guint8  first_octet;
    guint16 sn;
    const char * full_mode_name;
    int size_remaining;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Feeback-2 root.  TODO: add as tree root */
    proto_tree_add_item(tree, hf_pdcp_lte_feedback_feedback2, tvb, offset, -1, FALSE);

    /* Ack-type */
    first_octet = tvb_get_guint8(tvb, offset);
    ack_type = (first_octet & 0xc0) >> 6;
    proto_tree_add_item(tree, hf_pdcp_lte_feedback_ack_type, tvb, offset, 1, FALSE);

    /* TODO: expert info on NACK? */

    /* Mode */
    mode = (first_octet & 0x30) >> 4;
    proto_tree_add_item(tree, hf_pdcp_lte_feedback_mode, tvb, offset, 1, FALSE);

    /* Show ACK-TYPE(Mode) in info column */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        full_mode_name = val_to_str(mode, rohc_mode_vals, "Error");

        col_append_fstr(pinfo->cinfo, COL_INFO, " %s(%c)",
                        val_to_str(ack_type, feedback_ack_vals, "Unknown"),
                        full_mode_name[0]);
    }

    /* 11 bits of SN */
    proto_tree_add_item(tree, hf_pdcp_lte_feedback_sn, tvb, offset, 2, FALSE);
    sn = tvb_get_ntohs(tvb, offset) & 0x7ff;
    offset += 2;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);
    }

    /* Loop over any remaining feedback options */
    size_remaining = size - 2;

    while (tvb_length_remaining(tvb, offset) > 0) {
        guint8 option = (tvb_get_guint8(tvb, offset) & 0xf0) >> 4;
        guint8 length = tvb_get_guint8(tvb, offset) & 0x0f;

        /* Preference setting controls showing option and lengths */
        if (global_pdcp_show_feedback_option_tag_length) {
            proto_tree_add_item(tree, hf_pdcp_lte_feedback_option, tvb, offset, 1, FALSE);
            proto_tree_add_item(tree, hf_pdcp_lte_feedback_length, tvb, offset, 1, FALSE);
        }
        offset++;
        size_remaining--;

        /* TODO: switch including missing option types */
        switch (option) {
            case 1:
                /* CRC */
                proto_tree_add_item(tree, hf_pdcp_lte_feedback_crc, tvb, offset, 1, FALSE);
                break;
            case 2:
                /* REJECT: TODO */
                break;
            case 3:
                /* SN-Not-Valid: TODO */
                break;
            case 4:
                /* SN */
                proto_tree_add_item(tree, hf_pdcp_lte_feedback_option_sn, tvb, offset, 1, FALSE);
                break;
            case 5:
                /* Clock */
                proto_tree_add_item(tree, hf_pdcp_lte_feedback_option_clock, tvb, offset, 1, FALSE);
                break;
            case 6:
                /* Jitter: TODO */
                break;
            case 7:
                /* Loss: TODO */
                break;

            default:
                /* TODO: unhandled option */
                break;
        }

        /* Skip length */
        offset += length;
        size_remaining -= length;
    }

    return offset;
}


/* Dissect a feedback packet.
   Return following offset */
static int dissect_pdcp_feedback_packet(proto_tree *tree,
                                        proto_item *root_item,
                                        tvbuff_t *tvb,
                                        int offset,
                                        struct pdcp_lte_info *p_pdcp_info,
                                        packet_info *pinfo)
{
    guint8 code;
    guint8 size;
    proto_item *ti;
    proto_item *root_ti;
    proto_tree *feedback_tree;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, " Feedback");
    }
    proto_item_append_text(root_item, " (Feedback)");

    /* Create feedback tree root */
    root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback, tvb, offset, -1, FALSE);
    feedback_tree = proto_item_add_subtree(root_ti, ett_pdcp_packet);

    /* Code */
    code = tvb_get_guint8(tvb, offset) & 0x07;
    ti = proto_tree_add_item(feedback_tree, hf_pdcp_lte_feedback_code, tvb, offset, 1, FALSE);
    offset++;

    /* Optional length field */
    if (code != 0) {
        proto_item_append_text(ti, " (length of feedback data)");
        size = code;
    }
    else {
        proto_tree_add_item(feedback_tree, hf_pdcp_lte_feedback_size, tvb, offset, 1, FALSE);
        size = tvb_get_guint8(tvb, offset);
        offset++;
    }

    /* Work out feedback type */
    if ((p_pdcp_info->cid_inclusion_info == CID_IN_ROHC_PACKET) &&
         !p_pdcp_info->large_cid_present) {

        /* Small CID */
        if (size == 1) {
            offset = dissect_pdcp_feedback_feedback1(feedback_tree, tvb, offset, p_pdcp_info, pinfo);
        }
        else if ((size > 1) && ((tvb_get_guint8(tvb, offset) & 0xc0) == 0xc0)) {
            /* Add-CID here! */
            proto_tree_add_item(feedback_tree, hf_pdcp_lte_add_cid, tvb, offset, 1, FALSE);
            offset++;

            if (size == 2) {
                offset = dissect_pdcp_feedback_feedback1(feedback_tree, tvb, offset, p_pdcp_info, pinfo);
            }
            else {
                offset = dissect_pdcp_feedback_feedback2(feedback_tree, tvb, offset, size, p_pdcp_info, pinfo);
            }
        }
        else {
            offset = dissect_pdcp_feedback_feedback2(feedback_tree, tvb, offset, size, p_pdcp_info, pinfo);
        }
    }
    else {
        offset = dissect_pdcp_feedback_feedback2(feedback_tree, tvb, offset, size, p_pdcp_info, pinfo);
    }

    return offset;
}


/* Dissect R-0 packet.
   Return following offset */
static int dissect_pdcp_r_0_packet(proto_tree *tree,
                                   proto_item *root_item,
                                   tvbuff_t *tvb,
                                   int offset,
                                   struct pdcp_lte_info *p_pdcp_info _U_,
                                   packet_info *pinfo)
{
    guint8 sn;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, " R-0");
    }
    proto_item_append_text(root_item, " (R-0)");

    /* 6 bits of sn */
    sn = tvb_get_guint8(tvb, offset) & 0x3f;
    proto_tree_add_item(tree, hf_pdcp_lte_r0_sn, tvb, offset, 1, FALSE);
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);
    }

    return offset;
}


/* Dissect R-0-CRC packet.
   Return following offset */
static int dissect_pdcp_r_0_crc_packet(proto_tree *tree,
                                       proto_item *root_item,
                                       tvbuff_t *tvb,
                                       int offset,
                                       struct pdcp_lte_info *p_pdcp_info,
                                       packet_info *pinfo)
{
    guint8 sn;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, " R-0-CRC");
    }
    proto_item_append_text(root_item, " (R-0-CRC)");

    proto_tree_add_item(tree, hf_pdcp_lte_rohc_r_0_crc, tvb, offset, -1, FALSE);

    /* 7 bits of sn */
    /* TODO: wrong!  Large-cid may be in-between!!!! */
    sn = tvb_get_guint8(tvb, offset) & 0x3f;
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Conclude SN */
    sn = (sn << 1) + ((tvb_get_guint8(tvb, offset) & 0x80) >> 7);
    proto_tree_add_uint(tree, hf_pdcp_lte_r0_crc_sn, tvb, offset, 1, sn);

    /* 7 bit CRC */
    proto_tree_add_item(tree, hf_pdcp_lte_r0_crc_crc, tvb, offset, 1, FALSE);
    offset++;

    /* Show SN in info column */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);
    }

    return offset;
}


/* Dissect UO-0-CRC packet.
   Return following offset */
static int dissect_pdcp_uo_0_packet(proto_tree *tree,
                                    proto_item *root_item,
                                    tvbuff_t *tvb,
                                    int offset,
                                    struct pdcp_lte_info *p_pdcp_info,
                                    packet_info *pinfo)
{
    guint8 sn;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, " U0-0");
    }
    proto_item_append_text(root_item, " (UO-0)");

    /* SN */
    sn = (tvb_get_guint8(tvb, offset) & 0x78) >> 3;
    proto_tree_add_item(tree, hf_pdcp_lte_uo0_sn, tvb, offset, 1, FALSE);

    /* TODO: CRC... */

    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Show SN in info column */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);
    }

    return offset;
}


/* Dissect R-1 packet.
   Return following offset */
static int  dissect_pdcp_r_1_packet(proto_tree *tree,
                                    proto_item *root_item,
                                    tvbuff_t *tvb,
                                    int offset,
                                    struct pdcp_lte_info *p_pdcp_info,
                                    packet_info *pinfo)
{
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, " R-1");
    }
    proto_item_append_text(root_item, " (R-1)");

    /* TODO: octet before large-cid */
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    if (p_pdcp_info->profile == 1) {
        /* TODO: */
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
    }

    return offset;
}


/* Dissect R-1-TS or R-1-ID packet.
   Return following offset */
static int  dissect_pdcp_r_1_ts_or_id_packet(proto_tree *tree,
                                             proto_item *root_item,
                                             tvbuff_t *tvb,
                                             int offset,
                                             struct pdcp_lte_info *p_pdcp_info,
                                             packet_info *pinfo)
{
    unsigned char T;

    /* TODO: octet before large-cid */
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* T determines frame type */
    T = tvb_get_guint8(tvb, ++offset) >> 7;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_type1_t, tvb, offset, 1, FALSE);
    if (T) {
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_str(pinfo->cinfo, COL_INFO, " R-1-TS");
        }
        proto_item_append_text(root_item, " (R-1-TS)");
    }
    else {
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_str(pinfo->cinfo, COL_INFO, " R-1-ID");
        }
        proto_item_append_text(root_item, " (R-1-ID)");
    }

    if (p_pdcp_info->profile == 1) {
        /* TODO: */
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
    }

    return offset;
}


/* Dissect UO-1 packet.
   Return following offset */
static int  dissect_pdcp_uo_1_packet(proto_tree *tree,
                                     proto_item *root_item,
                                     tvbuff_t *tvb,
                                     int offset,
                                     struct pdcp_lte_info *p_pdcp_info,
                                     packet_info *pinfo)
{
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, " UO-1");
    }
    proto_item_append_text(root_item, " (UO-1)");

    /* TODO: octet before large-cid */
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    if (p_pdcp_info->profile == 1) {
        /* TODO: */
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
    }

    return offset;
}


/* Dissect UO-1-TS or UO-1-ID packet.
   Return following offset */
static int  dissect_pdcp_uo_1_ts_or_id_packet(proto_tree *tree,
                                              proto_item *root_item,
                                              tvbuff_t *tvb,
                                              int offset,
                                              struct pdcp_lte_info *p_pdcp_info,
                                              packet_info *pinfo)
{
    unsigned char T;

    /* TODO: octet before large-cid */
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* T determines frame type */
    T = tvb_get_guint8(tvb, ++offset) >> 5;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_type0_t, tvb, offset, 1, FALSE);
    if (T) {
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_str(pinfo->cinfo, COL_INFO, " UO-1-TS");
        }
        proto_item_append_text(root_item, " (UO-1-TS)");
    }
    else {
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_str(pinfo->cinfo, COL_INFO, " UO-1-ID");
        }
        proto_item_append_text(root_item, " (UO-1-ID)");
    }

    if (p_pdcp_info->profile == 1) {
        /* TODO: */
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
    }

    return offset;
}





/* Dissect UOR-2 packet.
   Return following offset */
static int  dissect_pdcp_uor_2_packet(proto_tree *tree,
                                      proto_item *root_item,
                                      tvbuff_t *tvb,
                                      int offset,
                                      struct pdcp_lte_info *p_pdcp_info,
                                      packet_info *pinfo)
{
    guint8 ts;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, " U0R-2");
    }
    proto_item_append_text(root_item, " (UOR-2)");

    /* TS straddles CID */
    ts = tvb_get_guint8(tvb, offset) & 0x1f;
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Last bit of TS is here */
    ts = (ts << 1) & (tvb_get_guint8(tvb, offset) >> 7);
    proto_tree_add_uint(tree, hf_pdcp_lte_rohc_ts, tvb, offset, 1, ts);



    if (p_pdcp_info->profile == 1) {
        /* TODO: */
        offset++;
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
        offset += 2;
    }

    return offset;
}


/* Dissect UOR-2-TS or UOR-2-ID packet.
   Return following offset */
static int  dissect_pdcp_uor_2_ts_or_id_packet(proto_tree *tree,
                                               proto_item *root_item,
                                               tvbuff_t *tvb,
                                               int offset,
                                               struct pdcp_lte_info *p_pdcp_info,
                                               packet_info *pinfo)
{
    unsigned char T;

    /* TODO: octet before large-cid.
       TODO: can't decode this until we know what T is,
             but T is after large-cid... */
    offset++;

    /* T determines frame type */
    T = tvb_get_guint8(tvb, offset) >> 7;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_type2_t, tvb, offset, 1, FALSE);

    if (T) {
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_str(pinfo->cinfo, COL_INFO, " U0R-2-TS");
        }
        proto_item_append_text(root_item, " (UOR-2-TS)");
    }
    else {
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_str(pinfo->cinfo, COL_INFO, " U0R-2-ID");
        }
        proto_item_append_text(root_item, " (UOR-2-ID)");
    }


    if (T) {
        /* UOR-2-TS format */

        /* TS */
        guint8 ts = tvb_get_guint8(tvb, offset) & 0x1f;
        proto_tree_add_uint(tree, hf_pdcp_lte_rohc_ts, tvb, offset, 1, ts);
        offset++;

        /* Large CID */
        if (p_pdcp_info->large_cid_present) {
            offset = dissect_large_cid(tree, tvb, offset);
        }

        /* m */
        proto_tree_add_item(tree, hf_pdcp_lte_rohc_m, tvb, offset, 1, ts);

        /* TODO: */
    }
    else {
        /* TODO: UOR-2-ID format */

        /* IP-ID */

        /* Large CID */
        if (p_pdcp_info->large_cid_present) {
            offset = dissect_large_cid(tree, tvb, offset);
        }

        /* TODO: */
    }

    if (p_pdcp_info->profile == 1) {
        /* TODO: */
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
    }

    return offset;
}




/* Show in the tree the config info attached to this frame, as generated fields */
static void show_pdcp_config(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                             pdcp_lte_info *p_pdcp_info)
{
    proto_item *ti;
    proto_tree *configuration_tree;
    proto_item *configuration_ti = proto_tree_add_item(tree,
                                                       hf_pdcp_lte_configuration,
                                                       tvb, 0, 0, FALSE);
    configuration_tree = proto_item_add_subtree(configuration_ti, ett_pdcp_configuration);

    /* Plane */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_plane, tvb, 0, 0,
                             p_pdcp_info->plane);
    PROTO_ITEM_SET_GENERATED(ti);

    /* User-plane-specific fields */
    if (p_pdcp_info->plane == USER_PLANE) {

        /* No Header PDU */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_no_header_pdu, tvb, 0, 0,
                                 p_pdcp_info->no_header_pdu);
        PROTO_ITEM_SET_GENERATED(ti);

        if (!p_pdcp_info->no_header_pdu) {

            /* Seqnum length */
            ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_seqnum_length, tvb, 0, 0,
                                     p_pdcp_info->seqnum_length);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    /* ROHC compression */
    ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_lte_rohc_compression, tvb, 0, 0,
                                p_pdcp_info->rohc_compression);
    PROTO_ITEM_SET_GENERATED(ti);

    /* ROHC-specific settings */
    if (p_pdcp_info->rohc_compression) {

        /* Show ROHC mode */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_mode, tvb, 0, 0,
                                 p_pdcp_info->mode);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Show RND */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_rnd, tvb, 0, 0,
                                 p_pdcp_info->rnd);
        PROTO_ITEM_SET_GENERATED(ti);

        /* UDP Checksum */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_udp_checksum_present, tvb, 0, 0,
                                 p_pdcp_info->udp_checkum_present);
        PROTO_ITEM_SET_GENERATED(ti);

        /* ROHC profile */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_profile, tvb, 0, 0,
                                 p_pdcp_info->profile);
        PROTO_ITEM_SET_GENERATED(ti);

        /* CID Inclusion Info */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_cid_inclusion_info, tvb, 0, 0,
                                 p_pdcp_info->cid_inclusion_info);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Large CID */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_large_cid_present, tvb, 0, 0,
                                 p_pdcp_info->large_cid_present);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Append summary to configuration root */
    proto_item_append_text(configuration_ti, "(plane=%s",
                           val_to_str(p_pdcp_info->plane, pdcp_plane_vals, "Unknown"));

    if (p_pdcp_info->rohc_compression) {
        const char *mode = val_to_str(p_pdcp_info->mode, rohc_mode_vals, "Error");
        proto_item_append_text(configuration_ti, ", mode=%c, profile=%s",
                               mode[0],
                               val_to_str(p_pdcp_info->profile, rohc_profile_vals, "Unknown"));
    }
    proto_item_append_text(configuration_ti, ")");
    PROTO_ITEM_SET_GENERATED(configuration_ti);

    /* Show plane in info column */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s: ",
                        val_to_str(p_pdcp_info->plane, pdcp_plane_vals, "Unknown"));
    }

}


/******************************/
/* Main dissection function.  */
static void dissect_pdcp_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    const char         *mode;
    proto_tree         *pdcp_tree = NULL;
    proto_item         *root_ti = NULL;
    proto_tree         *rohc_tree = NULL;
    proto_item         *rohc_ti = NULL;
    gint               offset = 0;
    gint               rohc_offset;
    struct pdcp_lte_info  *p_pdcp_info;
    guint8             base_header_byte;
    guint8             udp_checksum_needed = TRUE;

    /* Append this protocol name rather than replace. */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_add_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-LTE");

    /* Create pdcp tree. */
    if (tree) {
        root_ti = proto_tree_add_item(tree, proto_pdcp_lte, tvb, offset, -1, FALSE);
        pdcp_tree = proto_item_add_subtree(root_ti, ett_pdcp);
    }


    /* Look for attached packet info! */
    p_pdcp_info = p_get_proto_data(pinfo->fd, proto_pdcp_lte);
    /* Can't dissect anything without it... */
    if (p_pdcp_info == NULL) {
        return;
    }


    /* Set mode string */
    mode = val_to_str(p_pdcp_info->mode, rohc_mode_vals, "Error");

    /* Show configuration (attached packet) info in tree */
    if (pdcp_tree) {
        show_pdcp_config(pinfo, tvb, pdcp_tree, p_pdcp_info);
    }

    /* Show ROHC mode */
    if (p_pdcp_info->rohc_compression &&
        check_col(pinfo->cinfo, COL_INFO)) {

        col_append_fstr(pinfo->cinfo, COL_INFO, " (mode=%c)", mode[0]);
    }


    /* Handle PDCP header (if present) */
    if (!p_pdcp_info->no_header_pdu) {

        /*****************************/
        /* Signalling plane messages */
        if (p_pdcp_info->plane == SIGNALING_PLANE) {
            guint32 mac;
            guint32 data_length;

            /* 5-bit sequence number */
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_5, tvb, offset, 1, FALSE);
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " sn=%u",
                                tvb_get_guint8(tvb, offset) & 0x1f);
            }
            offset++;


            /* RRC data is all but last 4 bytes.
               TODO: use lte-rrc dissector when available
                     (according to direction and channel type) */
            if (global_pdcp_dissect_signalling_plane_as_rrc) {
                /*
                tvbuff_t *payload_tvb = tvb_new_subset(tvb, offset, offset,
                                                       tvb_length_remaining(tvb, offset) - 4);
                */
            }
            else {
                /* Just show as unparsed data */
                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, tvb, offset,
                                    tvb_length_remaining(tvb, offset) - 4, FALSE);
            }

            data_length = tvb_length_remaining(tvb, offset) - 4;
            offset += data_length;

            /* Last 4 bytes are MAC */
            mac = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_mac, tvb, offset, 4, FALSE);
            offset += 4;

            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " MAC=0x%08x (%u bytes data)",
                                mac, data_length);
            }

            return;
        }
        else if (p_pdcp_info->plane == USER_PLANE) {

            /**********************************/
            /* User-plane messages            */
            guint16 seqnum;
            gboolean pdu_type = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;

            /* Data/Control flag */
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_data_control, tvb, offset, 1, FALSE);

            if (pdu_type == 1) {
                /*****************************/
                /* Use-plane Data            */

                /* Number of sequence number bits depends upon config */
                if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_7_BITS) {
                    seqnum = tvb_get_guint8(tvb, offset) & 0x7f;
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_7, tvb, offset, 1, FALSE);
                    offset++;
                }
                else if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_12_BITS) {
                    proto_item *ti;
                    guint8 reserved_value;

                    /* 3 reserved bits */
                    ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_reserved3, tvb, offset, 1, FALSE);
                    reserved_value = (tvb_get_guint8(tvb, offset) & 0x70) >> 4;

                    /* Complain if not 0 */
                    if (reserved_value != 0) {
                        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                               "Reserved bits have value 0x%x - should be 0x0",
                                               reserved_value);
                    }

                    /* 12-bit sequence number */
                    seqnum = tvb_get_ntohs(tvb, offset) & 0x0fff;
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_12, tvb, offset, 2, FALSE);
                    offset += 2;
                }
                else {
                    /* Not a recognised data format!!!!! */
                    return;
                }

                if (check_col(pinfo->cinfo, COL_INFO)) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " sn=%u", seqnum);
                }
            }
            else {
                /*******************************/
                /* User-plane Control messages */
                guint8 control_pdu_type = (tvb_get_guint8(tvb, offset) & 0x70) >> 4;
                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_control_pdu_type, tvb, offset, 1, FALSE);

                switch (control_pdu_type) {
                    case 0:    /* PDCP status report */
                        {
                            guint16 lis;
                            guint   not_received = 0;
                            guint   sn;

                            /* Last-in-sequence SN */
                            lis = tvb_get_ntohs(tvb, offset) & 0x0fff;
                            sn = lis;
                            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_lis, tvb,
                                                offset, 2, FALSE);
                            offset += 2;

                            /* Bitmap */
                            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_bitmap, tvb,
                                                offset, -1, FALSE);

                            /* For each byte... */
                            for ( ; tvb_length_remaining(tvb, offset); offset++) {
                                guint bit_offset = 0;
                                /* .. look for error (0) in each bit */
                                for ( ; bit_offset < 8; bit_offset++) {
                                    if ((tvb_get_guint8(tvb, offset) >> (7-bit_offset) & 0x1) == 0) {
                                        proto_tree_add_boolean_format_value(pdcp_tree, hf_pdcp_lte_bitmap_not_received, tvb, offset, 1, TRUE,
                                                                            " (SN=%u)", sn);
                                        not_received++;
                                    }
                                    sn = (sn + 1) % 4096;
                                }
                            }

                            if (check_col(pinfo->cinfo, COL_INFO)) {
                                col_append_fstr(pinfo->cinfo, COL_INFO,
                                               " Status Report (lis=%u) not-received=%u",
                                               lis, not_received);
                            }
                        }
                        return;

                    case 1:     /* ROHC Feedback */
                        offset++;
                        break;  /* Drop-through to dissect feedback */

                    default:    /* Reserved */
                        return;
                }
            }
        }
        else {
            /* Invalid plane setting...! */
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " - INVALID PLANE (%u)",
                                p_pdcp_info->plane);
            }
            return;
        }
    }
    else {
        /* Show that its a no-header PDU */
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_str(pinfo->cinfo, COL_INFO, " No-Header");
        }
    }


    /* If not compressed with ROHC, show as user-plane data */
    if (!p_pdcp_info->rohc_compression) {

        if (global_pdcp_dissect_user_plane_as_ip && (ip_handle != 0)) {
            tvbuff_t *payload_tvb = tvb_new_subset(tvb, offset, -1, -1);
            call_dissector_only(ip_handle, payload_tvb, pinfo, pdcp_tree);
        }
        else {
            if (tvb_length_remaining(tvb, offset) > 0) {
                if (p_pdcp_info->plane == USER_PLANE) {
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_user_plane_data, tvb, offset, -1, FALSE);
                }
                else {
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, tvb, offset, -1, FALSE);
                }

                if (check_col(pinfo->cinfo, COL_INFO)) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " (%u bytes data)",
                                    tvb_length_remaining(tvb, offset));
                }
            }
        }
        return;
    }


    /***************************/
    /* ROHC packets            */
    /***************************/

    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_append_fstr(pinfo->cinfo, COL_PROTOCOL, "|ROHC(%s)",
                        val_to_str(p_pdcp_info->profile, rohc_profile_vals, "Unkown"));
    }

    /* Only attempt ROHC if configured to */
    if (!global_pdcp_dissect_rohc) {
        return;
    }
    
    /* Create pdcp tree. */
    if (pdcp_tree) {
        rohc_ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_rohc, tvb, offset, -1, FALSE);
        rohc_tree = proto_item_add_subtree(rohc_ti, ett_pdcp_rohc);
    }

    rohc_offset = offset;

    /* Skip any leading padding octets (11100000) */
    while (tvb_get_guint8(tvb, offset) == 0xe0) {
        offset++;
    }
    if (offset > rohc_offset) {
        proto_tree_add_item(rohc_tree, hf_pdcp_lte_rohc_padding, tvb, rohc_offset,
                            offset-rohc_offset, FALSE);
    }

    /* Add-CID octet */
    if ((p_pdcp_info->cid_inclusion_info == CID_IN_ROHC_PACKET) &&
        !p_pdcp_info->large_cid_present)
    {
        if (((tvb_get_guint8(tvb, offset) >> 4) & 0x0f) == 0x0e) {
            proto_tree_add_item(rohc_tree, hf_pdcp_lte_add_cid, tvb, offset, 1, FALSE);
            offset++;
        }
        else {
            /* Assume CID value of 0 if field absent */
            proto_item *ti = proto_tree_add_uint(rohc_tree, hf_pdcp_lte_add_cid, tvb, offset, 0, 0);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    /* Now look at first octet of base header and identify packet type */
    base_header_byte = tvb_get_guint8(tvb, offset);

    /* IR (1111110) */
    if ((base_header_byte & 0xfe) == 0xfc) {
        offset = dissect_pdcp_ir_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
    }

    /* IRDYN (11111000) */
    else if (base_header_byte == 0xf8) {
        offset = dissect_pdcp_irdyn_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        udp_checksum_needed = FALSE;
    }

    /* Feedback (begins with 11110) */
    else if (((base_header_byte & 0xf8) >> 3) == 0x1e) {
        offset = dissect_pdcp_feedback_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        return;
    }

    /* Packet type 0 (0) */
    else if ((base_header_byte & 0x80) == 0) {

        /* TODO: decide type based upon:
           - mode
           - 2nd bit
           - length remaining (taking into account large-cid) */

        /* R-0 begins with 00 */
        if (((base_header_byte & 0xc0) == 0) &&
             (p_pdcp_info->mode == RELIABLE_BIDIRECTIONAL)) {

            offset = dissect_pdcp_r_0_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        }

        /* R-0-CRC begins with 01 */
        else if ((((base_header_byte & 0x40) >> 6) == 1) &&
                  (p_pdcp_info->mode == RELIABLE_BIDIRECTIONAL)) {

            offset = dissect_pdcp_r_0_crc_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        }

        else {
            offset = dissect_pdcp_uo_0_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        }
    }

    /* Packet type 1 (10) */
    else if (((base_header_byte & 0xc0) >> 6) == 2) {

        switch (p_pdcp_info->mode) {

            case RELIABLE_BIDIRECTIONAL:
                 /* R-1 if !(ipv4 && rand) */
                 if (!((p_pdcp_info->rohc_ip_version == 4) &&
                      (!p_pdcp_info->rnd))) {
                    offset = dissect_pdcp_r_1_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
                    return;
                 }
                else {
                    /* Whether its R-1-ID or R-1-TS depends upon T bit */
                    dissect_pdcp_r_1_ts_or_id_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
                    return;
                }
                break;

            case UNIDIRECTIONAL:
            case OPTIMISTIC_BIDIRECTIONAL:
                 /* UO-1 if !(ipv4 && rand) */
                 if (!((p_pdcp_info->rohc_ip_version == 4) &&
                      (!p_pdcp_info->rnd))) {
                    offset = dissect_pdcp_uo_1_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
                    return;
                 }
                else {
                    /* Whether its UO-1-ID or UO-1-TS depends upon T bit */
                    dissect_pdcp_uo_1_ts_or_id_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
                    return;
                }

                return; 

        }
    }

    /* Packet type 2 (110) */
    else if (((base_header_byte & 0xe0) >> 5) == 6) {

        /* UOR-2 if !(ipv4 && rand) */
        if (!((p_pdcp_info->rohc_ip_version == 4) &&
              (!p_pdcp_info->rnd))) {

            offset = dissect_pdcp_uor_2_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        }
        else {
            /* Whether its UOR-2-ID or UOR-2-TS depends upon T bit */
            dissect_pdcp_uor_2_ts_or_id_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
            return;
        }
    }

    /* Segment (1111111) */
    else if ((base_header_byte & 0xfe) == 0xfe) {
        /* TODO: */
        return;
    }


    /* Fields beyond base header */

    /* IP-ID */
    if (p_pdcp_info->rnd) {
        proto_tree_add_item(rohc_tree, hf_pdcp_lte_ip_id, tvb, offset, 2, FALSE);
        offset += 2;
    }

    /* UDP Checksum */
    if (p_pdcp_info->udp_checkum_present && udp_checksum_needed) {
        proto_tree_add_item(rohc_tree, hf_pdcp_lte_udp_checksum, tvb, offset, 2, FALSE);
        offset += 2;
    }

    /* Payload */
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(rohc_tree, hf_pdcp_lte_payload, tvb, offset, -1, FALSE);
    }
}

void proto_register_pdcp(void)
{
    static hf_register_info hf[] =
    {
        { &hf_pdcp_lte_configuration,
            { "Configuration",
              "pdcp_configuration", FT_STRING, BASE_NONE, NULL, 0x0,
              "Configuation info passed into dissector", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_compression,
            { "ROHC Compression",
              "pdcp.rohc", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "ROHC Mode", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_mode,
            { "ROHC mode",
              "pdcp.rohc.mode", FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x0,
              "ROHC Mode", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_rnd,
            { "RND",  /* TODO: true/false vals? */
              "pdcp.rohc.rnd", FT_UINT8, BASE_DEC, NULL, 0x0,
              "RND of outer ip header", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_udp_checksum_present,
            { "UDP Checksum",  /* TODO: true/false vals? */
              "pdcp.rohc.checksum-present", FT_UINT8, BASE_DEC, NULL, 0x0,
              "UDP Checksum_present", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_profile,
            { "ROHC profile",
              "pdcp.rohc.profile", FT_UINT8, BASE_DEC, VALS(rohc_profile_vals), 0x0,
              "ROHC Mode", HFILL
            }
        },
        { &hf_pdcp_lte_no_header_pdu,
            { "No Header PDU",
              "pdcp.no-header_pdu", FT_UINT8, BASE_DEC, NULL, 0x0,
              "No Header PDU", HFILL
            }
        },
        { &hf_pdcp_lte_plane,
            { "Plane",
              "pdcp.plane", FT_UINT8, BASE_DEC, VALS(pdcp_plane_vals), 0x0,
              "No Header PDU", HFILL
            }
        },
        { &hf_pdcp_lte_seqnum_length,
            { "Seqnum length",
              "pdcp.seqnum_length", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Sequence Number Length", HFILL
            }
        },


        { &hf_pdcp_lte_cid_inclusion_info,
            { "CID Inclusion Info",
              "pdcp.cid-inclusion-info", FT_UINT8, BASE_DEC, NULL, 0x0,
              "CID Inclusion Info", HFILL
            }
        },
        { &hf_pdcp_lte_large_cid_present,
            { "Large CID Present",
              "pdcp.large-cid-present", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Large CID Present", HFILL
            }
        },

        { &hf_pdcp_lte_seq_num_5,
            { "Seq Num",
              "pdcp.seq-num", FT_UINT8, BASE_DEC, NULL, 0x1f,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_7,
            { "Seq Num",
              "pdcp.seq-num", FT_UINT8, BASE_DEC, NULL, 0x7f,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_reserved3,
            { "Reserved",
              "pdcp.reserved3", FT_UINT8, BASE_HEX, NULL, 0x70,
              "3 reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_12,
            { "Seq Num",
              "pdcp.seq-num", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_signalling_data,
            { "Signalling Data",
              "pdcp.signalling-data", FT_BYTES, BASE_HEX, NULL, 0x0,
              "Signalling Data", HFILL
            }
        },
        { &hf_pdcp_lte_mac,
            { "MAC",
              "pdcp.mac", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
              "MAC", HFILL
            }
        },
        { &hf_pdcp_lte_data_control,
            { "PDU Type",
              "pdcp.pdu-type", FT_UINT8, BASE_HEX, VALS(pdu_type_vals), 0x80,
              "PDU type", HFILL
            }
        },
        { &hf_pdcp_lte_user_plane_data,
            { "User-Plane Data",
              "pdcp.user-data", FT_BYTES, BASE_HEX, NULL, 0x0,
              "User-Plane Data", HFILL
            }
        },
        { &hf_pdcp_lte_control_pdu_type,
            { "Control PDU Type",
              "pdcp.control-pdu-type", FT_UINT8, BASE_HEX, VALS(control_pdu_type_vals), 0x70,
              "Control PDU type", HFILL
            }
        },
        { &hf_pdcp_lte_lis,
            { "Last in sequence SN",
              "pdcp.lis", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "Last in sequence PDCP Sequence Number", HFILL
            }
        },
        { &hf_pdcp_lte_bitmap,
            { "Bitmap",
              "pdcp.bitmap", FT_NONE, BASE_NONE, NULL, 0x0,
              "Status report bitmap (0=error, 1=OK)", HFILL
            }
        },
        { &hf_pdcp_lte_bitmap_not_received,
            { "Not Received",
              "pdcp.bitmap.error", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "Status report PDU error", HFILL
            }
        },

        { &hf_pdcp_lte_rohc,
            { "ROHC Message",
              "pdcp.rohc", FT_NONE, BASE_NONE, NULL, 0,
              "ROHC Message", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_padding,
            { "Padding",
              "pdcp.rohc.padding", FT_NONE, BASE_NONE, NULL, 0,
              "ROHC Padding", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_r_0_crc,
            { "R-0-CRC Packet",
              "pdcp.r-0-crc", FT_NONE, BASE_NONE, NULL, 0,
              "R-0-CRC Packet", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback,
            { "Feedback",
              "pdcp.rohc.feedback", FT_NONE, BASE_NONE, NULL, 0,
              "Feedback Packet", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_type0_t,
            { "T",
              "pdcp.rohc.t0.t", FT_UINT8, BASE_HEX, VALS(t_vals), 0x20,
              "Indicates whether frame type is TS (1) or ID (0)", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_type1_t,
            { "T",
              "pdcp.rohc.t1.t", FT_UINT8, BASE_HEX, VALS(t_vals), 0x80,
              "Indicates whether frame type is TS (1) or ID (0)", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_type2_t,
            { "T",
              "pdcp.rohc.t2.t", FT_UINT8, BASE_HEX, VALS(t_vals), 0x80,
              "Indicates whether frame type is TS (1) or ID (0)", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_d,
            { "D",
              "pdcp.rohc.t2.t", FT_UINT8, BASE_HEX, NULL, 0x01,
              "Indicates whether Dynamic chain is present", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_ir_crc,
            { "CRC",
              "pdcp.rohc.ir.crc", FT_UINT8, BASE_HEX, NULL, 0x0,
              "8-bit CRC", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_static_ipv4,
            { "Static IPv4 chain",
              "pdcp.rohc.static.ipv4", FT_NONE, BASE_NONE, NULL, 0x0,
              "Static IPv4 chain", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_ip_version,
            { "IP Version",
              "pdcp.rohc.ip-version", FT_UINT8, BASE_HEX, NULL, 0xf0,
              "IP Version", HFILL
            }
        },
        /* TODO: create/use value_string */
        { &hf_pdcp_lte_rohc_ip_protocol,
            { "IP Protocol",
              "pdcp.rohc.ip-protocol", FT_UINT8, BASE_DEC, VALS(ip_protocol_vals), 0x0,
              "IP Protocol", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_ip_src,
            { "IP Source address",
              "pdcp.rohc.ip-src", FT_IPv4, BASE_DEC, NULL, 0x0,
              "IP Source address", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_ip_dst,
            { "IP Destination address",
              "pdcp.rohc.ip-dst", FT_IPv4, BASE_DEC, NULL, 0x0,
              "IP Destination address", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_static_udp,
            { "Static UDP chain",
              "pdcp.rohc.static.udp", FT_NONE, BASE_NONE, NULL, 0x0,
              "Static UDP chain", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_static_udp_src_port,
            { "Static UDP source port",
              "pdcp.rohc.static.udp.src-port", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Static UDP source port", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_static_udp_dst_port,
            { "Static UDP destination port",
              "pdcp.rohc.static.udp.dst-port", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Static UDP destination port", HFILL
            }
        },


        { &hf_pdcp_lte_rohc_static_rtp,
            { "Static RTP chain",
              "pdcp.rohc.static.rtp", FT_NONE, BASE_NONE, NULL, 0x0,
              "Static RTP chain", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_static_rtp_ssrc,
            { "SSRC",
              "pdcp.rohc.static.rtp.ssrc", FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              "Static RTP chain SSRC", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_dynamic_ipv4,
            { "Dynamic IPv4 chain",
              "pdcp.rohc.dynamic.ipv4", FT_NONE, BASE_NONE, NULL, 0x0,
              "Dynamic IPv4 chain", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_tos,
            { "ToS",
              "pdcp.rohc.ip.tos", FT_UINT8, BASE_HEX, NULL, 0x0,
              "IP Type of Service", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_ttl,
            { "TTL",
              "pdcp.rohc.ip.ttl", FT_UINT8, BASE_HEX, NULL, 0x0,
              "IP Time To Live", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_id,
            { "IP-ID",
              "pdcp.rohc.ip.id", FT_UINT8, BASE_HEX, NULL, 0x0,
              "IP ID", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_df,
            { "Don't Fragment",
              "pdcp.rohc.ip.df", FT_UINT8, BASE_HEX, NULL, 0x80,
              "IP Don't Fragment flag", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_rnd,
            { "Random IP-ID field",
              "pdcp.rohc.ip.rnd", FT_UINT8, BASE_HEX, NULL, 0x40,
              "Random IP-ID field", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_nbo,
            { "Network Byte Order IP-ID field",
              "pdcp.rohc.ip.nbo", FT_UINT8, BASE_HEX, NULL, 0x20,
              "Network Byte Order IP-ID field", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_dynamic_udp,
            { "Dynamic UDP chain",
              "pdcp.rohc.dynamic.udp", FT_NONE, BASE_NONE, NULL, 0x0,
              "Dynamic UDP chain", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_udp_checksum,
            { "UDP Checksum",
              "pdcp.rohc.dynamic.udp.checksum", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              "UDP Checksum", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_udp_seqnum,
            { "UDP Sequence Number",
              "pdcp.rohc.dynamic.udp.seqnum", FT_UINT16, BASE_HEX, NULL, 0x0,
              "UDP Sequence Number", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_dynamic_rtp,
            { "Dynamic RTP chain",
              "pdcp.rohc.dynamic.rtp", FT_NONE, BASE_NONE, NULL, 0x0,
              "Dynamic RTP chain", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_rx,
            { "RX",
              "pdcp.rohc.dynamic.rtp.rx", FT_UINT8, BASE_DEC, NULL, 0x10,
              "RX", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_cc,
            { "Contributing CSRCs",
              "pdcp.rohc.dynamic.rtp.cc", FT_UINT8, BASE_DEC, NULL, 0x0f,
              "Dynamic RTP chain CCs", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_seqnum,
            { "RTP Sequence Number",
              "pdcp.rohc.dynamic.rtp.seqnum", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Dynamic RTP chain Sequence Number", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_timestamp,
            { "RTP Timestamp",
              "pdcp.rohc.dynamic.rtp.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0,
              "Dynamic RTP chain Timestamp", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_dynamic_rtp_reserved3,
            { "Reserved",
              "pdcp.rohc.dynamic.rtp.reserved3", FT_UINT8, BASE_HEX, NULL, 0xc0,
              "Reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_x,
            { "X",
              "pdcp.rohc.dynamic.rtp.x", FT_UINT8, BASE_DEC, NULL, 0x10,
              "X", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_mode,
            { "Mode",
              "pdcp.rohc.dynamic.rtp.mode", FT_UINT8, BASE_HEX, VALS(rohc_mode_vals), 0x0c,
              "Mode", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_tis,
            { "TIS",
              "pdcp.rohc.dynamic.rtp.tis", FT_UINT8, BASE_HEX, NULL, 0x02,
              "Dynamic RTP chain TIS (indicates time_stride present)", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_tss,
            { "TSS",
              "pdcp.rohc.dynamic.rtp.tss", FT_UINT8, BASE_HEX, NULL, 0x01,
              "Dynamic RTP chain TSS (indicates TS_stride present)", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_ts_stride,
            { "TS Stride",
              "pdcp.rohc.dynamic.rtp.ts-stride", FT_UINT32, BASE_DEC, NULL, 0x0,
              "Dynamic RTP chain TS Stride", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_ts,
            { "TS",
              "pdcp.rohc.ts", FT_UINT8, BASE_DEC, NULL, 0x0,
              "TS", HFILL
            }
        },

        { &hf_pdcp_lte_add_cid,
            { "Add-CID",
              "pdcp.add-cid", FT_UINT8, BASE_DEC, NULL, 0x0f,
              "Add-CID", HFILL
            }
        },
        { &hf_pdcp_lte_large_cid,
            { "Large-CID",
              "pdcp.large-cid", FT_UINT16, BASE_DEC, NULL, 0x07ff,
              "Large-CID", HFILL
            }
        },
        { &hf_pdcp_lte_uo0_sn,
            { "SN",
              "pdcp.rohc.uo0.sn", FT_UINT8, BASE_DEC, NULL, 0x78,
              "SN", HFILL
            }
        },
        { &hf_pdcp_lte_r0_sn,
            { "SN",
              "pdcp.rohc.r0.sn", FT_UINT8, BASE_DEC, NULL, 0x3f,
              "SN", HFILL
            }
        },
        { &hf_pdcp_lte_r0_crc_sn,
            { "SN",
              "pdcp.rohc.r0-crc.sn", FT_UINT16, BASE_DEC, NULL, 0x0,
              "SN", HFILL
            }
        },
        { &hf_pdcp_lte_r0_crc_crc,
            { "CRC7",
              "pdcp.rohc.r0-crc.crc", FT_UINT8, BASE_DEC, NULL, 0x7f,
              "CRC 7", HFILL
            }
        },

        { &hf_pdcp_lte_feedback_code,
            { "Code",
              "pdcp.feedback-code", FT_UINT8, BASE_DEC, NULL, 0x07,
              "Feedback options length (if > 0)", HFILL
            }
        },
        { &hf_pdcp_lte_feedback_size,
            { "Size",
              "pdcp.feedback-size", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Feedback options length", HFILL
            }
        },
        { &hf_pdcp_lte_feedback_feedback1,
            { "FEEDBACK-1 (SN)",
              "pdcp.feedback.feedback1", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Feedback-1", HFILL
            }
        },
        { &hf_pdcp_lte_feedback_feedback2,
            { "FEEDBACK-2",
              "pdcp.feedback.feedback2", FT_NONE, BASE_NONE, NULL, 0x0,
              "Feedback-2", HFILL
            }
        },

        { &hf_pdcp_lte_feedback_ack_type,
            { "Acktype",
              "pdcp.feedback-acktype", FT_UINT8, BASE_DEC, VALS(feedback_ack_vals), 0xc0,
              "Feedback-2 ack type", HFILL
            }
        },
        { &hf_pdcp_lte_feedback_mode,
            { "mode",
              "pdcp.feedback-mode", FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x30,
              "Feedback mode", HFILL
            }
        },
        { &hf_pdcp_lte_feedback_sn,
            { "SN",
              "pdcp.feedback-sn", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "Feedback mode", HFILL
            }
        },

        { &hf_pdcp_lte_feedback_option,
            { "Option",
              "pdcp.feedback-option", FT_UINT8, BASE_DEC, VALS(feedback_option_vals), 0xf0,
              "Feedback mode", HFILL
            }
        },
        { &hf_pdcp_lte_feedback_length,
            { "Length",
              "pdcp.feedback-length", FT_UINT8, BASE_DEC, NULL, 0x0f,
              "Feedback length", HFILL
            }
        },
        { &hf_pdcp_lte_feedback_crc,
            { "CRC",
              "pdcp.feedback-crc", FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
              "Feedback CRC", HFILL
            }
        },
        { &hf_pdcp_lte_feedback_option_sn,
            { "SN",
              "pdcp.feedback-option-sn", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Feedback Option SN", HFILL
            }
        },
        { &hf_pdcp_lte_feedback_option_clock,
            { "Clock",
              "pdcp.feedback-option-clock", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Feedback Option Clock", HFILL
            }
        },

        { &hf_pdcp_lte_ip_id,
            { "IP-ID",
              "pdcp.ip-id", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              "IP-ID", HFILL
            }
        },
        { &hf_pdcp_lte_udp_checksum,
            { "UDP Checksum",
              "pdcp.udp-checksum", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              "UDP Checksum", HFILL
            }
        },
        { &hf_pdcp_lte_payload,
            { "Payload",
              "pdcp.payload", FT_BYTES, BASE_HEX, NULL, 0x0,
              "Payload", HFILL
            }
        },

    };

    static gint *ett[] =
    {
        &ett_pdcp,
        &ett_pdcp_configuration,
        &ett_pdcp_packet,
        &ett_pdcp_rohc,
        &ett_pdcp_rohc_static_ipv4,
        &ett_pdcp_rohc_static_udp,
        &ett_pdcp_rohc_static_rtp,
        &ett_pdcp_rohc_dynamic_ipv4,
        &ett_pdcp_rohc_dynamic_udp,
        &ett_pdcp_rohc_dynamic_rtp
    };

    module_t *pdcp_lte_module;

    /* Register protocol. */
    proto_pdcp_lte = proto_register_protocol("PDCP-LTE", "PDCP-LTE", "pdcp-lte");
    proto_register_field_array(proto_pdcp_lte, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    register_dissector("pdcp-lte", dissect_pdcp_lte, proto_pdcp_lte);

    pdcp_lte_module = prefs_register_protocol(proto_pdcp_lte, NULL);

    /* Dissect uncompressed user-plane data as IP */
    prefs_register_bool_preference(pdcp_lte_module, "show_user_plane_as_ip",
        "Show uncompressed User-Plane data as IP",
        "Show uncompressed User-Plane data as IP",
        &global_pdcp_dissect_user_plane_as_ip);

#if 0
    /* Dissect unciphered signalling data as RRC */
    prefs_register_bool_preference(pdcp_lte_module, "show_signalling_plane_as_rrc",
        "Show unciphered Signalling-Plane data as RRC",
        "Show unciphered Signalling-Plane data as RRC",
        &global_pdcp_dissect_signalling_plane_as_rrc);
#endif

    /* Attempt to dissect ROHC headers */
    prefs_register_bool_preference(pdcp_lte_module, "dissect_rohc",
        "Attempt to decode ROHC data",
        "Attempt to decode ROHC data",
        &global_pdcp_dissect_rohc);

    prefs_register_bool_preference(pdcp_lte_module, "show_feedback_option_tag_length",
        "Show ROHC feedback option tag & length",
        "Show ROHC feedback option tag & length",
        &global_pdcp_show_feedback_option_tag_length);
}

void proto_reg_handoff_pdcp_lte(void)
{
    ip_handle = find_dissector("ip");
}

