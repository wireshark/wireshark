/* packet-rdt.c
 *
 * Routines for RDT dissection
 * RDT = Real Data Transport
 *
 * Copyright 2005
 * Written by Martin Mathieson and Tom Marshall
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

/* Information sources:
 * helixcommunity.org sources, in particular
 * server/protocol/transport/rdt/pub/tngpkt.pm
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/strutil.h>

#include "packet-rdt.h"

static dissector_handle_t rdt_handle;

static gint    proto_rdt                        = -1;

/* Packet fields */
static gint    hf_rdt_packet                    = -1;

/* flags1: shared */
static gint    hf_rdt_len_included              = -1;

/* flags1: data packet */
static gint    hf_rdt_data_flags1               = -1;
static gint    hf_rdt_data_need_reliable        = -1;
static gint    hf_rdt_data_stream_id            = -1;
static gint    hf_rdt_data_is_reliable          = -1;

/* flags2: data packet */
static gint    hf_rdt_data_flags2               = -1;
static gint    hf_rdt_data_backtoback           = -1;
static gint    hf_rdt_data_slowdata             = -1;
static gint    hf_rdt_data_asmrule              = -1;

/* flags1: asm action packet */
static gint    hf_rdt_aact_flags                = -1;
static gint    hf_rdt_aact_stream_id            = -1;

/* flags1: ack packet */
static gint    hf_rdt_ack_flags                 = -1;
static gint    hf_rdt_ack_lost_high             = -1;

/* flags1: latency report packet */
static gint    hf_rdt_latency_report_flags      = -1;

/* flags1: bandwidth report packet */
static gint    hf_rdt_bandwidth_report_flags    = -1;

/* flags1: stream end packet */
static gint    hf_rdt_stre_flags                = -1;
static gint    hf_rdt_stre_need_reliable        = -1;
static gint    hf_rdt_stre_stream_id            = -1;
static gint    hf_rdt_stre_packet_sent          = -1;
static gint    hf_rdt_stre_ext_flag             = -1;

static gint    hf_rdt_rtt_request_flags         = -1;
static gint    hf_rdt_rtt_response_flags        = -1;
static gint    hf_rdt_congestion_flags          = -1;
static gint    hf_rdt_report_flags              = -1;
static gint    hf_rdt_tirq_flags                = -1;
static gint    hf_rdt_tirp_flags                = -1;
static gint    hf_rdt_bw_probing_flags          = -1;

/* Octets 1-2: sequence number or packet type */
static gint    hf_rdt_sequence_number           = -1;
static gint    hf_rdt_packet_type               = -1;

/* Only present if length_included */
static gint    hf_rdt_packet_length             = -1;

/* General shared fields */
static gint    hf_rdt_timestamp                 = -1;
static gint    hf_rdt_stream_id_ex              = -1;
static gint    hf_rdt_asmrule_ex                = -1;
static gint    hf_rdt_total_reliable            = -1;
static gint    hf_rdt_data                      = -1;

/* Special use fields */
static gint    hf_rdt_aact_reliable_seqno       = -1;
static gint    hf_rdt_brpt_interval             = -1;
static gint    hf_rdt_brpt_bandwidth            = -1;
static gint    hf_rdt_brpt_sequence             = -1;
static gint    hf_rdt_rtrp_ts_sec               = -1;
static gint    hf_rdt_rtrp_ts_usec              = -1;
static gint    hf_rdt_cong_xmit_mult            = -1;
static gint    hf_rdt_cong_recv_mult            = -1;
static gint    hf_rdt_stre_seqno                = -1;
static gint    hf_rdt_stre_dummy_flags1         = -1;
static gint    hf_rdt_stre_dummy_type           = -1;
static gint    hf_rdt_stre_reason_code          = -1;
static gint    hf_rdt_lrpt_server_out_time      = -1;
static gint    hf_rdt_tirq_request_rtt_info     = -1;
static gint    hf_rdt_tirq_request_buffer_info  = -1;
static gint    hf_rdt_tirq_request_time_msec    = -1;
static gint    hf_rdt_tirp_has_rtt_info         = -1;
static gint    hf_rdt_tirp_is_delayed           = -1;
static gint    hf_rdt_tirp_has_buffer_info      = -1;
static gint    hf_rdt_tirp_request_time_msec    = -1;
static gint    hf_rdt_tirp_response_time_msec   = -1;
static gint    hf_rdt_tirp_buffer_info          = -1;
static gint    hf_rdt_tirp_buffer_info_count    = -1;
static gint    hf_rdt_tirp_buffer_info_stream_id         = -1;
static gint    hf_rdt_tirp_buffer_info_lowest_timestamp  = -1;
static gint    hf_rdt_tirp_buffer_info_highest_timestamp = -1;
static gint    hf_rdt_tirp_buffer_info_bytes_buffered    = -1;
static gint    hf_rdt_bwpp_seqno                = -1;
static gint    hf_rdt_unk_flags1                = -1;

/* RDT setup fields */
static gint    hf_rdt_setup                     = -1;
static gint    hf_rdt_setup_frame               = -1;
static gint    hf_rdt_setup_method              = -1;
static gint    hf_rdt_feature_level             = -1;

/* RDT fields defining a sub tree */
static gint    ett_rdt                          = -1;
static gint    ett_rdt_packet                   = -1;
static gint    ett_rdt_setup                    = -1;
static gint    ett_rdt_data_flags1              = -1;
static gint    ett_rdt_data_flags2              = -1;
static gint    ett_rdt_aact_flags               = -1;
static gint    ett_rdt_ack_flags                = -1;
static gint    ett_rdt_latency_report_flags     = -1;
static gint    ett_rdt_bandwidth_report_flags   = -1;
static gint    ett_rdt_stre_flags               = -1;
static gint    ett_rdt_rtt_request_flags        = -1;
static gint    ett_rdt_rtt_response_flags       = -1;
static gint    ett_rdt_congestion_flags         = -1;
static gint    ett_rdt_report_flags             = -1;
static gint    ett_rdt_tirq_flags               = -1;
static gint    ett_rdt_tirp_flags               = -1;
static gint    ett_rdt_tirp_buffer_info         = -1;
static gint    ett_rdt_bw_probing_flags         = -1;

/* Port preference settings */
static gboolean global_rdt_register_udp_port = FALSE;
static guint    global_rdt_udp_port = 6970;

void proto_register_rdt(void);
void proto_reg_handoff_rdt(void);

/* Main dissection function */
static void dissect_rdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Parse individual packet types */
static guint dissect_rdt_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_asm_action_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_bandwidth_report_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_ack_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_rtt_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_rtt_response_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_congestion_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_stream_end_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_report_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_latency_report_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_transport_info_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_transport_info_response_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_bw_probing_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint dissect_rdt_unknown_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Preferences bool to control whether or not setup info should be shown */
static gboolean global_rdt_show_setup_info = TRUE;

/* Packet types */
#define RDT_ASMACTIION_PACKET               0xff00
#define RDT_BANDWIDTHREPORT_PACKET          0xff01
#define RDT_ACK_PACKET                      0xff02
#define RDT_RTTREQUEST_PACKET               0xff03
#define RDT_RTTRESPONSE_PACKET              0xff04
#define RDT_CONGESTION_PACKET               0xff05
#define RDT_STREAMEND_PACKET                0xff06
#define RDT_REPORT_PACKET                   0xff07
#define RDT_LATENCYREPORT_PACKET            0xff08
#define RDT_TRANSPORTINFO_PACKET            0xff09
#define RDT_TRANSPORTINFORESPONSE_PACKET    0xff0a
#define RDT_BWPROBING_PACKET                0xff0b

static const value_string packet_type_vals[] =
{
    { RDT_ASMACTIION_PACKET,             "Asm action"  },
    { RDT_BANDWIDTHREPORT_PACKET,        "Bandwidth report"  },
    { RDT_ACK_PACKET,                    "Ack"  },
    { RDT_RTTREQUEST_PACKET,             "RTT request"  },
    { RDT_RTTRESPONSE_PACKET,            "RTT response"  },
    { RDT_CONGESTION_PACKET,             "Congestion"  },
    { RDT_STREAMEND_PACKET,              "Stream end" },
    { RDT_REPORT_PACKET,                 "Report" },
    { RDT_LATENCYREPORT_PACKET,          "Latency report" },
    { RDT_TRANSPORTINFO_PACKET,          "Transport info" },
    { RDT_TRANSPORTINFORESPONSE_PACKET,  "Transport info response" },
    { RDT_BWPROBING_PACKET,              "BW probing" },
    { 0, NULL }
};


/* Set up an RDT conversation */
void rdt_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method,
                     gint  rdt_feature_level)
{
    address null_addr;
    conversation_t* p_conv;
    struct _rdt_conversation_info *p_conv_data;

    /* If this isn't the first time this packet has been processed,
       we've already done this work, so we don't need to do it
      again. */
    if (pinfo->fd->flags.visited)
    {
        return;
    }

    SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

    /* Check if the ip address and port combination is not already registered
       as a conversation. */
    p_conv = find_conversation(pinfo->fd->num, addr, &null_addr, PT_UDP, port, other_port,
                               NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

    /* If not, create a new conversation. */
    if ( !p_conv || p_conv->setup_frame != pinfo->fd->num)
    {
        p_conv = conversation_new(pinfo->fd->num, addr, &null_addr, PT_UDP,
                                  (guint32)port, (guint32)other_port,
                                  NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
    }

    /* Set dissector */
    conversation_set_dissector(p_conv, rdt_handle);

    /* Check if the conversation has data associated with it. */
    p_conv_data = conversation_get_proto_data(p_conv, proto_rdt);

    /* If not, add a new data item. */
    if (!p_conv_data)
    {
        /* Create conversation data */
        p_conv_data = se_alloc(sizeof(struct _rdt_conversation_info));
        conversation_add_proto_data(p_conv, proto_rdt, p_conv_data);
    }

    /* Update the conversation data. */
    g_strlcpy(p_conv_data->method, setup_method, MAX_RDT_SETUP_METHOD_SIZE);
    p_conv_data->frame_number = pinfo->fd->num;
    p_conv_data->feature_level = rdt_feature_level;
}



/****************************************************************************/
/* Main dissection function                                                 */
/****************************************************************************/
static void dissect_rdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       previous_offset = 0;
    gint        offset = 0;
    proto_item  *ti;
    proto_tree  *rdt_tree = NULL;
    proto_tree  *rdt_packet_tree;
    guint16     packet_type;

    /* Set/clear columns */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDT");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Create RDT protocol tree */
    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_rdt, tvb, offset, -1, FALSE);
        rdt_tree = proto_item_add_subtree(ti, ett_rdt);
    }

    /* Conversation setup info */
    if (global_rdt_show_setup_info)
    {
        show_setup_info(tvb, pinfo, rdt_tree);
    }

    /* Parse all RDT packets found in the frame */
    while (offset != -1 && tvb_length_remaining(tvb, offset))
    {
        /* Every packet type should have at least 3 bytes */
        tvb_ensure_bytes_exist(tvb, offset, 3);

        /* 2nd & 3rd bytes determine packet type */
        packet_type = tvb_get_ntohs(tvb, offset+1);

        /* Add a tree for the next individual packet */
        ti =  proto_tree_add_string_format(rdt_tree, hf_rdt_packet, tvb, offset, -1,
                                           "",
                                           "RDT packet (%s)",
                                           packet_type < 0xff00 ? "Data" :
                                               val_to_str(packet_type, packet_type_vals, "Unknown"));
        rdt_packet_tree = proto_item_add_subtree(ti, ett_rdt_packet);

        /* Dissect the details of the next packet in this frame */
        if (packet_type < 0xff00)
        {
            offset = dissect_rdt_data_packet(tvb, pinfo, rdt_packet_tree, offset);
        }
        else
        {
            switch (packet_type)
            {
            case RDT_ASMACTIION_PACKET:
                offset = dissect_rdt_asm_action_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_BANDWIDTHREPORT_PACKET:
                offset = dissect_rdt_bandwidth_report_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_ACK_PACKET:
                offset = dissect_rdt_ack_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_RTTREQUEST_PACKET:
                offset = dissect_rdt_rtt_request_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_RTTRESPONSE_PACKET:
                offset = dissect_rdt_rtt_response_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_CONGESTION_PACKET:
                offset = dissect_rdt_congestion_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_STREAMEND_PACKET:
                offset = dissect_rdt_stream_end_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_REPORT_PACKET:
                offset = dissect_rdt_report_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_LATENCYREPORT_PACKET:
                offset = dissect_rdt_latency_report_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_TRANSPORTINFO_PACKET:
                offset = dissect_rdt_transport_info_request_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_TRANSPORTINFORESPONSE_PACKET:
                offset = dissect_rdt_transport_info_response_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;
            case RDT_BWPROBING_PACKET:
                offset = dissect_rdt_bw_probing_packet(tvb, pinfo, rdt_packet_tree, offset);
                break;

            default:
                /* Unknown control packet */
                offset = dissect_rdt_unknown_control(tvb, pinfo, rdt_packet_tree, offset);
                break;
            }
        }

        /* Select correct number of bytes for the tree showing this packet */
        if (offset != -1)
        {
            proto_item_set_len(rdt_packet_tree, offset-previous_offset);
        }
        previous_offset = offset;
    }
}



/************************************************/
/* Functions to dissect individual packet types */
/************************************************/

/* Dissect a data packet */
guint dissect_rdt_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       start_offset = offset;
    guint16     packet_length;
    guint8      flags1;
    guint8      length_included_flag;
    guint8      need_reliable_flag;
    guint16     stream_id;
    guint16     sequence_number;
    guint8      is_reliable_flag;
    guint8      flags2;
    guint32     timestamp;
    guint16     asm_rule_number;
    guint8      back_to_back;
    guint8      slow_data;
    proto_tree  *flags_tree1;
    proto_tree  *flags_tree2;
    proto_item  *ti;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = (flags1 & 0x80) >> 7;
    need_reliable_flag = (flags1 & 0x40) >> 6;
    stream_id = (flags1 & 0x3e) >> 1;
    is_reliable_flag = flags1 & 0x01;

    /* Create subtree for flags1 fields */
    if (tree)
    {
        ti =  proto_tree_add_string_format(tree, hf_rdt_data_flags1, tvb, offset, 1,
                                           "",
                                           "Length-included=%u, need-reliable=%u, stream-id=%u, is-reliable=%u",
                                           length_included_flag,
                                           need_reliable_flag,
                                           stream_id,
                                           is_reliable_flag);
        flags_tree1 = proto_item_add_subtree(ti, ett_rdt_data_flags1);

        proto_tree_add_item(flags_tree1, hf_rdt_len_included, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree1, hf_rdt_data_need_reliable, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree1, hf_rdt_data_stream_id, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree1, hf_rdt_data_is_reliable, tvb, offset, 1, FALSE);
    }

    offset++;

    /* Sequence number */
    sequence_number = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_rdt_sequence_number, tvb, offset, 2, FALSE);
    offset += 2;

    /* Length field is optional */
    if (length_included_flag)
    {
        packet_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_packet_length, tvb, offset, 2, FALSE);
        offset += 2;

        /* Check that there are as many bytes as reported */
        tvb_ensure_bytes_exist(tvb, start_offset, packet_length);
    }
    else
    {
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    /* More flags */
    flags2 = tvb_get_guint8(tvb, offset);
    back_to_back = (flags2 & 0x80) >> 7;
    slow_data = (flags2 & 0x40) >> 6;
    asm_rule_number = flags2 & 0x3f;


    /* Create subtree for flags2 fields */
    if (tree)
    {
        ti =  proto_tree_add_string_format(tree, hf_rdt_data_flags2, tvb, offset, 1,
                                           "",
                                           "Back-to-back=%u, slow-data=%u, asm-rule=%u",
                                           back_to_back,
                                           slow_data,
                                           asm_rule_number);

        /* Create subtree for flags and add fields */
        flags_tree2 = proto_item_add_subtree(ti, ett_rdt_data_flags2);

        proto_tree_add_item(flags_tree2, hf_rdt_data_backtoback, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree2, hf_rdt_data_slowdata, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree2, hf_rdt_data_asmrule, tvb, offset, 1, FALSE);
    }
    offset++;

    /* Timestamp */
    timestamp = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_rdt_timestamp, tvb, offset, 4, FALSE);
    offset += 4;

    /* Stream ID expansion */
    if (stream_id == 31)
    {
        stream_id = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_stream_id_ex, tvb, offset, 2, FALSE);
        offset += 2;
    }

    /* Total reliable */
    if (need_reliable_flag)
    {
        proto_tree_add_item(tree, hf_rdt_total_reliable, tvb, offset, 2, FALSE);
        offset += 2;
    }

    /* Asm rule number */
    if (asm_rule_number == 63)
    {
        asm_rule_number = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_asmrule_ex, tvb, offset, 2, FALSE);
        offset += 2;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    "DATA: stream-id=%02u asm-rule=%02u seq=%05u ts=%05u  ",
                    stream_id, asm_rule_number, sequence_number, timestamp);

    /* The remaining data is unparsed. */
    proto_tree_add_item(tree, hf_rdt_data, tvb, offset, -1, ENC_NA);
    offset += tvb_length_remaining(tvb, offset);

    if (packet_length < (offset - start_offset) ||
        packet_length > tvb_length_remaining(tvb, start_offset))
    {
        proto_tree_add_text(tree, tvb, 0, 0, "Packet length invalid");
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    return start_offset + packet_length;
}

/* Dissect an asm-action packet */
guint dissect_rdt_asm_action_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       start_offset = offset;
    guint16     packet_length;
    guint8      flags1;
    guint8      length_included_flag;
    guint16     stream_id;
    guint16     rel_seqno;
    proto_tree  *flags_tree;
    proto_item  *ti;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = (flags1 & 0x80) >> 7;
    stream_id = (flags1 & 0x7c) >> 2;

    /* Create subtree for flags fields */
    if (tree)
    {
        proto_tree_add_item(tree, proto_rdt, tvb, offset, -1, FALSE);
        ti =  proto_tree_add_string_format(tree, hf_rdt_aact_flags, tvb, offset, 1,
                                           "",
                                           "Length-included=%u, stream_id=%u",
                                           length_included_flag,
                                           stream_id);
        flags_tree = proto_item_add_subtree(ti, ett_rdt_aact_flags);

        proto_tree_add_item(flags_tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_rdt_aact_stream_id, tvb, offset, 1, FALSE);
    }
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    rel_seqno = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_rdt_aact_reliable_seqno, tvb, offset, 2, FALSE);
    offset += 2;

    /* Length field is optional */
    if (length_included_flag)
    {
        packet_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_packet_length, tvb, offset, 2, FALSE);
        offset += 2;

        /* Check that there are as many bytes as reported */
        tvb_ensure_bytes_exist(tvb, start_offset, packet_length);
    }
    else
    {
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    /* Stream ID expansion */
    if (stream_id == 31)
    {
        stream_id = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_stream_id_ex, tvb, offset, 2, FALSE);
        offset += 2;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    "ASM-ACTION: stream-id=%02u rel-seqno=%05u  ",
                    stream_id, rel_seqno);

    /* The remaining data is unparsed. */
    proto_tree_add_item(tree, hf_rdt_data, tvb, offset, -1, ENC_NA);

    if (packet_length < (offset - start_offset) ||
        packet_length > tvb_length_remaining(tvb, start_offset))
    {
        proto_tree_add_text(tree, tvb, 0, 0, "Packet length invalid");
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    return start_offset + packet_length;
}

/* Dissect an bandwidth-report packet */
guint dissect_rdt_bandwidth_report_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       start_offset = offset;
    guint16     packet_length;
    guint8      flags1;
    guint8      length_included_flag;
    proto_tree  *flags_tree;
    proto_item  *ti;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = (flags1 & 0x80) >> 7;

    /* Create subtree for flags fields */
    if (tree)
    {
        ti =  proto_tree_add_string_format(tree, hf_rdt_bandwidth_report_flags, tvb, offset, 1,
                                           "",
                                           "Length-included=%u",
                                           length_included_flag);
        flags_tree = proto_item_add_subtree(ti, ett_rdt_bandwidth_report_flags);

        proto_tree_add_item(flags_tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
    }
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    /* Length field is optional */
    if (length_included_flag)
    {
        packet_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_packet_length, tvb, offset, 2, FALSE);
        offset += 2;

        /* Check that there are as many bytes as reported */
        tvb_ensure_bytes_exist(tvb, start_offset, packet_length);
    }
    else
    {
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    proto_tree_add_item(tree, hf_rdt_brpt_interval, tvb, offset, 2, FALSE);
    offset += 2;
    proto_tree_add_item(tree, hf_rdt_brpt_bandwidth, tvb, offset, 4, FALSE);
    offset += 4;
    proto_tree_add_item(tree, hf_rdt_brpt_sequence, tvb, offset, 1, FALSE);
    offset += 1;

    col_append_str(pinfo->cinfo, COL_INFO, "BANDWIDTH-REPORT:  ");

    if (packet_length < (offset - start_offset) ||
        packet_length > tvb_length_remaining(tvb, start_offset))
    {
        proto_tree_add_text(tree, tvb, 0, 0, "Packet length invalid");
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    return start_offset + packet_length;
}

/* Dissect an ack packet */
guint dissect_rdt_ack_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       start_offset = offset;
    guint16     packet_length;
    guint8      flags1;
    guint8      length_included_flag;
    guint8      lost_high_flag;
    proto_tree  *flags_tree;
    proto_item  *ti;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = (flags1 & 0x80) >> 7;
    lost_high_flag = (flags1 & 0x40) >> 6;

    /* Create subtree for flags fields */
    if (tree)
    {
        ti =  proto_tree_add_string_format(tree, hf_rdt_ack_flags, tvb, offset, 1,
                                           "",
                                           "Length-included=%u, lost-high=%u",
                                           length_included_flag,
                                           lost_high_flag);
        flags_tree = proto_item_add_subtree(ti, ett_rdt_ack_flags);

        proto_tree_add_item(flags_tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_rdt_ack_lost_high, tvb, offset, 1, FALSE);
    }
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    /* Length field is optional */
    if (length_included_flag)
    {
        packet_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_packet_length, tvb, offset, 2, FALSE);
        offset += 2;

        /* Check that there are as many bytes as reported */
        tvb_ensure_bytes_exist(tvb, start_offset, packet_length);
    }
    else
    {
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    /* XXX: The remaining data is unparsed. */
    proto_tree_add_item(tree, hf_rdt_data, tvb, offset, -1, ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, "ACK: lh=%u  ", lost_high_flag);

    if (packet_length < (offset - start_offset) ||
        packet_length > tvb_length_remaining(tvb, start_offset))
    {
        proto_tree_add_text(tree, tvb, 0, 0, "Packet length invalid");
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    return start_offset + packet_length;
}

/* Dissect an att-request packet */
guint dissect_rdt_rtt_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    /* Flags in first byte */
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    col_append_str(pinfo->cinfo, COL_INFO, "RTT-REQUEST:  ");

    return offset;
}

/* Dissect an att-response packet */
guint dissect_rdt_rtt_response_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    /* Flags in first byte */
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    proto_tree_add_item(tree, hf_rdt_rtrp_ts_sec, tvb, offset, 4, FALSE);
    offset += 4;
    proto_tree_add_item(tree, hf_rdt_rtrp_ts_usec, tvb, offset, 4, FALSE);
    offset += 4;

    col_append_str(pinfo->cinfo, COL_INFO, "RTT-RESPONSE:  ");

    return offset;
}

/* Dissect an congestion packet */
guint dissect_rdt_congestion_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    /* Flags in first byte */
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    proto_tree_add_item(tree, hf_rdt_cong_xmit_mult, tvb, offset, 4, FALSE);
    offset += 4;
    proto_tree_add_item(tree, hf_rdt_cong_recv_mult, tvb, offset, 4, FALSE);
    offset += 4;

    col_append_str(pinfo->cinfo, COL_INFO, "CONGESTION:  ");

    return offset;
}

/* Dissect an stream-end packet */
guint dissect_rdt_stream_end_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8      flags1;
    guint8      need_reliable;
    guint16     stream_id;
    guint8      packet_sent;
    guint8      ext_flag;
    proto_tree  *flags_tree;
    proto_item  *ti;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    need_reliable = (flags1 & 0x80) >> 7;
    stream_id = (flags1 & 0x7c) >> 2;
    packet_sent = (flags1 & 0x2) >> 1;
    ext_flag = flags1 & 0x1;

    /* Create subtree for flags fields */
    if (tree)
    {
        ti =  proto_tree_add_string_format(tree, hf_rdt_stre_flags, tvb, offset, 1,
                                           "",
                                           "Need-reliable=%u, stream-id=%u, packet-sent=%u, ext-flag=%u",
                                           need_reliable,
                                           stream_id,
                                           packet_sent,
                                           ext_flag);
        flags_tree = proto_item_add_subtree(ti, ett_rdt_stre_flags);

        proto_tree_add_item(flags_tree, hf_rdt_stre_need_reliable, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_rdt_stre_stream_id, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_rdt_stre_packet_sent, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_rdt_stre_ext_flag, tvb, offset, 1, FALSE);
    }
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    proto_tree_add_item(tree, hf_rdt_stre_seqno, tvb, offset, 2, FALSE);
    offset += 2;
    proto_tree_add_item(tree, hf_rdt_timestamp, tvb, offset, 4, FALSE);
    offset += 4;

    /* Stream ID expansion */
    if (stream_id == 31)
    {
        stream_id = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_stream_id_ex, tvb, offset, 2, FALSE);
        offset += 2;
    }

    /* Total reliable */
    if (need_reliable)
    {
        proto_tree_add_item(tree, hf_rdt_total_reliable, tvb, offset, 2, FALSE);
        offset += 2;
    }

    if (ext_flag)
    {
        proto_tree_add_item(tree, hf_rdt_stre_dummy_flags1, tvb, offset, 1, FALSE);
        offset += 1;
        proto_tree_add_item(tree, hf_rdt_stre_dummy_type, tvb, offset, 2, FALSE);
        offset += 2;
        proto_tree_add_item(tree, hf_rdt_stre_reason_code, tvb, offset, 4, FALSE);
        offset += 4;
        /* XXX: Remainder is reason_text */
        offset += tvb_length_remaining(tvb, offset);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "STREAM-END: stream-id=%02u  ", stream_id);

    return offset;
}

/* Dissect an report packet */
guint dissect_rdt_report_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       start_offset = offset;
    guint16     packet_length;
    guint8      flags1;
    guint8      length_included_flag;
    proto_tree  *flags_tree;
    proto_item  *ti;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = (flags1 & 0x80) >> 7;

    /* Create subtree for flags fields */
    if (tree)
    {
        ti =  proto_tree_add_string_format(tree, hf_rdt_report_flags, tvb, offset, 1,
                                           "",
                                           "Length-included=%u",
                                           length_included_flag);
        flags_tree = proto_item_add_subtree(ti, ett_rdt_report_flags);

        proto_tree_add_item(flags_tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
    }
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    /* Length field is optional */
    if (length_included_flag)
    {
        packet_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_packet_length, tvb, offset, 2, FALSE);
        offset += 2;

        /* Check that there are as many bytes as reported */
        tvb_ensure_bytes_exist(tvb, start_offset, packet_length);
    }
    else
    {
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    col_append_str(pinfo->cinfo, COL_INFO, "REPORT:  ");

    /* The remaining data is unparsed. */
    proto_tree_add_item(tree, hf_rdt_data, tvb, offset, -1, ENC_NA);

    if (packet_length < (offset - start_offset) ||
        packet_length > tvb_length_remaining(tvb, start_offset))
    {
        proto_tree_add_text(tree, tvb, 0, 0, "Packet length invalid");
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    return start_offset + packet_length;
}

/* Dissect an latency-report packet */
guint dissect_rdt_latency_report_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       start_offset = offset;
    guint16     packet_length;
    guint8      flags1;
    guint8      length_included_flag;
    guint32     server_out_time;
    proto_tree  *flags_tree;
    proto_item  *ti;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = (flags1 & 0x80) >> 7;

    /* Create subtree for flags fields */
    if (tree)
    {
        ti =  proto_tree_add_string_format(tree, hf_rdt_latency_report_flags, tvb, offset, 1,
                                           "",
                                           "Length-included=%u",
                                           length_included_flag);
        flags_tree = proto_item_add_subtree(ti, ett_rdt_latency_report_flags);

        proto_tree_add_item(flags_tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
    }
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    /* Length field is optional */
    if (length_included_flag)
    {
        packet_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_packet_length, tvb, offset, 2, FALSE);
        offset += 2;

        /* Check that there are as many bytes as reported */
        tvb_ensure_bytes_exist(tvb, start_offset, packet_length);
    }
    else
    {
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    server_out_time = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_rdt_lrpt_server_out_time, tvb, offset, 4, FALSE);
    offset += 4;

    col_append_fstr(pinfo->cinfo, COL_INFO, "LATENCY-REPORT: t=%u  ", server_out_time);

    if (packet_length < (offset - start_offset) ||
        packet_length > tvb_length_remaining(tvb, start_offset))
    {
        proto_tree_add_text(tree, tvb, 0, 0, "Packet length invalid");
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    return start_offset + packet_length;
}

/* Dissect a transport-info packet */
guint dissect_rdt_transport_info_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8      flags1;
    guint8      request_rtt_info_flag;
    guint8      request_buffer_info_flag;
    proto_tree  *flags_tree;
    proto_item  *ti;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    request_rtt_info_flag = (flags1 & 0x2) >> 1;
    request_buffer_info_flag = (flags1 & 0x01);

    /* Create subtree for flags fields */
    if (tree)
    {
        ti =  proto_tree_add_string_format(tree, hf_rdt_ack_flags, tvb, offset, 1,
                                           "",
                                           "Request-rtt-info=%u, request-buffer-info=%u",
                                           request_rtt_info_flag,
                                           request_buffer_info_flag);
        flags_tree = proto_item_add_subtree(ti, ett_rdt_tirq_flags);

        proto_tree_add_item(flags_tree, hf_rdt_tirq_request_rtt_info, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_rdt_tirq_request_buffer_info, tvb, offset, 1, FALSE);
    }
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    if (request_rtt_info_flag)
    {
        proto_tree_add_item(tree, hf_rdt_tirq_request_time_msec, tvb, offset, 4, FALSE);
        offset += 4;
    }

    col_append_str(pinfo->cinfo, COL_INFO, "TRANSPORT-INFO-REQUEST:  ");

    return offset;
}

/* Dissect an transport-info-response packet */
guint dissect_rdt_transport_info_response_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8      flags1;
    guint8      has_rtt_info;
    guint8      is_delayed;
    guint8      has_buffer_info;
    proto_tree  *flags_tree;
    proto_item  *ti;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    has_rtt_info = (flags1 & 0x4) >> 2;
    is_delayed = (flags1 & 0x2) >> 1;
    has_buffer_info = (flags1 & 0x1);

    /* Create subtree for flags fields */
    if (tree)
    {
        ti =  proto_tree_add_string_format(tree, hf_rdt_tirp_flags, tvb, offset, 1,
                                           "",
                                           "Has-rtt-info=%u, is-delayed=%u, has-buffer-info=%u",
                                           has_rtt_info,
                                           is_delayed,
                                           has_buffer_info);
        flags_tree = proto_item_add_subtree(ti, ett_rdt_tirp_flags);

        proto_tree_add_item(flags_tree, hf_rdt_tirp_has_rtt_info, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_rdt_tirp_is_delayed, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_rdt_tirp_has_buffer_info, tvb, offset, 1, FALSE);
    }
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    /* RTT info */
    if (has_rtt_info)
    {
        proto_tree_add_item(tree, hf_rdt_tirp_request_time_msec, tvb, offset, 4, FALSE);
        offset += 4;

        if (is_delayed)
        {
            proto_tree_add_item(tree, hf_rdt_tirp_response_time_msec, tvb, offset, 4, FALSE);
            offset += 4;
        }
    }

    /* Buffer info */
    if (has_buffer_info)
    {
        guint16 n;

        /* Read number of buffers */
        guint16 buffer_info_count = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_tirp_buffer_info_count, tvb, offset, 2, FALSE);
        offset += 2;

        for (n=0; n < buffer_info_count; n++)
        {
            proto_tree  *buffer_info_tree;
            proto_item  *ti2;

            /* Each buffer info in a new subtree */
            ti2 =  proto_tree_add_string_format(tree, hf_rdt_tirp_buffer_info, tvb, offset, 14,
                                               "",
                                               "Buffer info %u",
                                               n+1);
            buffer_info_tree = proto_item_add_subtree(ti2, ett_rdt_tirp_buffer_info);

            /* Read individual buffer info */
            proto_tree_add_item(buffer_info_tree, hf_rdt_tirp_buffer_info_stream_id, tvb, offset, 2, FALSE);
            offset += 2;
            proto_tree_add_item(buffer_info_tree, hf_rdt_tirp_buffer_info_lowest_timestamp, tvb, offset, 4, FALSE);
            offset += 4;
            proto_tree_add_item(buffer_info_tree, hf_rdt_tirp_buffer_info_highest_timestamp, tvb, offset, 4, FALSE);
            offset += 4;
            proto_tree_add_item(buffer_info_tree, hf_rdt_tirp_buffer_info_bytes_buffered, tvb, offset, 4, FALSE);
            offset += 4;
        }
    }

    /* Report what is left */
    offset += tvb_length_remaining(tvb, offset);

    col_append_str(pinfo->cinfo, COL_INFO, "RESPONSE:  ");

    return offset;
}

/* Dissect a bw-probing packet */
guint dissect_rdt_bw_probing_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       start_offset = offset;
    guint16     packet_length;
    guint8      flags1;
    guint8      length_included_flag;
    proto_tree  *flags_tree;
    proto_item  *ti;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = (flags1 & 0x80) >> 7;

    /* Create subtree for flags fields */
    if (tree)
    {
        ti =  proto_tree_add_string_format(tree, hf_rdt_bw_probing_flags, tvb, offset, 1,
                                           "",
                                           "Length-included=%u",
                                           length_included_flag);
        flags_tree = proto_item_add_subtree(ti, ett_rdt_bw_probing_flags);

        proto_tree_add_item(flags_tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
    }
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    /* Length field is optional */
    if (length_included_flag)
    {
        packet_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_packet_length, tvb, offset, 2, FALSE);
        offset += 2;

        /* Check that there are as many bytes as reported */
        tvb_ensure_bytes_exist(tvb, start_offset, packet_length);
    }
    else
    {
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    proto_tree_add_item(tree, hf_rdt_bwpp_seqno, tvb, offset, 1, FALSE);
    offset += 1;
    proto_tree_add_item(tree, hf_rdt_timestamp, tvb, offset, 1, FALSE);
    offset += 4;

    col_append_str(pinfo->cinfo, COL_INFO, "BW-PROBING:  ");

    if (packet_length < (offset - start_offset) ||
        packet_length > tvb_length_remaining(tvb, start_offset))
    {
        proto_tree_add_text(tree, tvb, 0, 0, "Packet length invalid");
        packet_length = tvb_length_remaining(tvb, start_offset);
    }

    return start_offset + packet_length;
}

/* Dissect an unknown control packet */
guint dissect_rdt_unknown_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    /* Flags in first byte */
    proto_tree_add_item(tree, hf_rdt_unk_flags1, tvb, offset, 1, FALSE);
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    /* The remaining data is unparsed. */
    proto_tree_add_item(tree, hf_rdt_data, tvb, offset, -1, ENC_NA);
    offset += tvb_length_remaining(tvb, offset);

    col_append_str(pinfo->cinfo, COL_INFO, "UNKNOWN-CTL:  ");

    return offset;
}

/* Look for conversation info and display any setup info found */
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Conversation and current data */
    conversation_t *p_conv;
    struct _rdt_conversation_info *p_conv_data;

    /* Use existing packet info if available */
    p_conv_data = p_get_proto_data(pinfo->fd, proto_rdt);

    if (!p_conv_data)
    {
        /* First time, get info from conversation */
        p_conv = find_conversation(pinfo->fd->num, &pinfo->net_dst, &pinfo->net_src,
                                   pinfo->ptype,
                                   pinfo->destport, pinfo->srcport, NO_ADDR_B);
        if (p_conv)
        {
            /* Create space for conversation info */
            struct _rdt_conversation_info *p_conv_packet_data;
            p_conv_data = conversation_get_proto_data(p_conv, proto_rdt);

            if (p_conv_data)
            {
                /* Save this conversation info into packet info */
                p_conv_packet_data = se_alloc(sizeof(struct _rdt_conversation_info));
                g_strlcpy(p_conv_packet_data->method, p_conv_data->method, MAX_RDT_SETUP_METHOD_SIZE);
                p_conv_packet_data->frame_number = p_conv_data->frame_number;
                p_conv_packet_data->feature_level = p_conv_data->feature_level;
                p_add_proto_data(pinfo->fd, proto_rdt, p_conv_packet_data);
            }
        }
    }

    /* Create setup info subtree with summary info. */
    if (p_conv_data)
    {
        proto_tree *rdt_setup_tree;
        proto_item *ti =  proto_tree_add_string_format(tree, hf_rdt_setup, tvb, 0, 0,
                                                       "",
                                                       "Stream setup by %s (frame %u), feature level %d",
                                                       p_conv_data->method,
                                                       p_conv_data->frame_number,
                                                       p_conv_data->feature_level);
        PROTO_ITEM_SET_GENERATED(ti);
        rdt_setup_tree = proto_item_add_subtree(ti, ett_rdt_setup);
        if (rdt_setup_tree)
        {
            /* Add details into subtree */
            proto_item* item = proto_tree_add_uint(rdt_setup_tree, hf_rdt_setup_frame,
                                                   tvb, 0, 0, p_conv_data->frame_number);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_string(rdt_setup_tree, hf_rdt_setup_method,
                                         tvb, 0, 0, p_conv_data->method);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_int(rdt_setup_tree, hf_rdt_feature_level,
                                      tvb, 0, 0, p_conv_data->feature_level);
            PROTO_ITEM_SET_GENERATED(item);
        }
    }
}


void proto_register_rdt(void)
{
    static hf_register_info hf[] =
    {
        {
            &hf_rdt_packet,
            {
                "RDT packet",
                "rdt.packet",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_data_flags1,
            {
                "RDT data flags 1",
                "rdt.data-flags1",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_len_included,
            {
                "Length included",
                "rdt.length-included",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_data_need_reliable,
            {
                "Need reliable",
                "rdt.need-reliable",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_data_stream_id,
            {
                "Stream ID",
                "rdt.stream-id",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x3e,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_data_is_reliable,
            {
                "Is reliable",
                "rdt.is-reliable",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_data_flags2,
            {
                "RDT data flags 2",
                "rdt.data-flags2",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "RDT data flags2", HFILL
            }
        },
        {
            &hf_rdt_data_backtoback,
            {
                "Back-to-back",
                "rdt.back-to-back",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_data_slowdata,
            {
                "Slow data",
                "rdt.slow-data",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_data_asmrule,
            {
                "asm rule",
                "rdt.asm-rule",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x3f,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_aact_flags,
            {
                "RDT asm-action flags 1",
                "rdt.aact-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "RDT aact flags", HFILL
            }
        },
        {
            &hf_rdt_aact_stream_id,
            {
                "Stream ID",
                "rdt.stream-id",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7c,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_sequence_number,
            {
                "Sequence number",
                "rdt.sequence-number",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_packet_type,
            {
                "Packet type",
                "rdt.packet-type",
                FT_UINT16,
                BASE_HEX,
                VALS(packet_type_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_ack_flags,
            {
                "RDT ack flags",
                "rdt.ack-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_ack_lost_high,
            {
                "Lost high",
                "rdt.lost-high",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_latency_report_flags,
            {
                "RDT latency report flags",
                "rdt.latency-report-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_bandwidth_report_flags,
            {
                "RDT bandwidth report flags",
                "rdt.bandwidth-report-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_stre_flags,
            {
                "RDT stream end flags",
                "rdt.stream-end-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_rtt_request_flags,
            {
                "RDT rtt request flags",
                "rdt.rtt-request-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_rtt_response_flags,
            {
                "RDT rtt response flags",
                "rdt.rtt-response-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_congestion_flags,
            {
                "RDT congestion flags",
                "rdt.congestion-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_report_flags,
            {
                "RDT report flags",
                "rdt.report-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirq_flags,
            {
                "RDT transport info request flags",
                "rdt.transport-info-request-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_flags,
            {
                "RDT transport info response flags",
                "rdt.transport-info-response-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_bw_probing_flags,
            {
                "RDT bw probing flags",
                "rdt.bw-probing-flags",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_packet_length,
            {
                "Packet length",
                "rdt.packet-length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_timestamp,
            {
                "Timestamp",
                "rdt.timestamp",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_stream_id_ex,
            {
                "Stream-id expansion",
                "rdt.stream-id-expansion",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_asmrule_ex,
            {
                "Asm rule expansion",
                "rdt.asm-rule-expansion",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_total_reliable,
            {
                "Total reliable",
                "rdt.total-reliable",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_data,
            {
                "Data",
                "rdt.data",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
               NULL, HFILL
            }
        },
        {
            &hf_rdt_aact_reliable_seqno,
            {
                "Reliable sequence number",
                "rdt.reliable-seq-no",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_brpt_interval,
            {
                "Bandwidth report interval",
                "rdt.bwid-report-interval",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_brpt_bandwidth,
            {
                "Bandwidth report bandwidth",
                "rdt.bwid-report-bandwidth",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_brpt_sequence,
            {
                "Bandwidth report sequence",
                "rdt.bwid-report-sequence",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_rtrp_ts_sec,
            {
                "Round trip response timestamp seconds",
                "rdt.rtrp-ts-sec",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_rtrp_ts_usec,
            {
                "Round trip response timestamp microseconds",
                "rdt.rtrp-ts-usec",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_cong_xmit_mult,
            {
                "Congestion transmit multiplier",
                "rdt.cong-xmit-mult",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_cong_recv_mult,
            {
                "Congestion receive multiplier",
                "rdt.cong-recv-mult",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_stre_need_reliable,
            {
                "Need reliable",
                "rdt.stre-need-reliable",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_stre_stream_id,
            {
                "Stream id",
                "rdt.stre-stream-id",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7c,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_stre_packet_sent,
            {
                "Packet sent",
                "rdt.stre-packet-sent",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_stre_ext_flag,
            {
                "Ext flag",
                "rdt.stre-ext-flag",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x01,
                NULL, HFILL
            }
        },

        {
            &hf_rdt_stre_seqno,
            {
                "Stream end sequence number",
                "rdt.stre-seqno",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_stre_dummy_flags1,
            {
                "Stream end reason dummy flags1",
                "rdt.stre-reason-dummy-flags1",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_stre_dummy_type,
            {
                "Stream end reason dummy type",
                "rdt.stre-reason-dummy-type",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_stre_reason_code,
            {
                "Stream end reason code",
                "rdt.stre-reason-code",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_lrpt_server_out_time,
            {
                "Latency report server out time",
                "rdt.lrpt-server-out-time",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirq_request_rtt_info,
            {
                "Transport info request rtt info flag",
                "rdt.tirq-request-rtt-info",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x2,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirq_request_buffer_info,
            {
                "Transport info request buffer info flag",
                "rdt.tirq-request-buffer-info",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x1,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirq_request_time_msec,
            {
                "Transport info request time msec",
                "rdt.tirq-request-time-msec",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_has_rtt_info,
            {
                "Transport info response has rtt info flag",
                "rdt.tirp-has-rtt-info",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x4,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_is_delayed,
            {
                "Transport info response is delayed",
                "rdt.tirp-is-delayed",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x2,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_has_buffer_info,
            {
                "Transport info response has buffer info",
                "rdt.tirp-has-buffer-info",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x1,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_request_time_msec,
            {
                "Transport info request time msec",
                "rdt.tirp-request-time-msec",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_response_time_msec,
            {
                "Transport info response time msec",
                "rdt.tirp-response-time-msec",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_buffer_info_count,
            {
                "Transport info buffer into count",
                "rdt.tirp-buffer-info-count",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_buffer_info,
            {
                "RDT buffer info",
                "rdt.tirp-buffer-info",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_buffer_info_stream_id,
            {
                "Buffer info stream-id",
                "rdt.tirp-buffer-info-stream-id",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_buffer_info_lowest_timestamp,
            {
                "Lowest timestamp",
                "rdt.tirp-buffer-info-lowest-timestamp",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_buffer_info_highest_timestamp,
            {
                "Highest timestamp",
                "rdt.tirp-buffer-info-highest-timestamp",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_tirp_buffer_info_bytes_buffered,
            {
                "Bytes buffered",
                "rdt.tirp-buffer-info-bytes-buffered",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_bwpp_seqno,
            {
                "Bandwidth probing packet seqno",
                "rdt.bwpp-seqno",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_unk_flags1,
            {
                "Unknown packet flags",
                "rdt.unk-flags1",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rdt_setup,
            {
                "Stream setup",
                "rdt.setup",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Stream setup, method and frame number", HFILL
            }
        },
        {
            &hf_rdt_setup_frame,
            {
                "Setup frame",
                "rdt.setup-frame",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                "Frame that set up this stream", HFILL
            }
        },
        {
            &hf_rdt_setup_method,
            {
                "Setup Method",
                "rdt.setup-method",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Method used to set up this stream", HFILL
            }
        },
        {
            &hf_rdt_feature_level,
            {
                "RDT feature level",
                "rdt.feature-level",
                FT_INT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    };

    static gint *ett[] =
    {
        &ett_rdt,
        &ett_rdt_packet,
        &ett_rdt_setup,
        &ett_rdt_data_flags1,
        &ett_rdt_data_flags2,
        &ett_rdt_aact_flags,
        &ett_rdt_ack_flags,
        &ett_rdt_latency_report_flags,
        &ett_rdt_bandwidth_report_flags,
        &ett_rdt_stre_flags,
        &ett_rdt_rtt_request_flags,
        &ett_rdt_rtt_response_flags,
        &ett_rdt_congestion_flags,
        &ett_rdt_report_flags,
        &ett_rdt_tirq_flags,
        &ett_rdt_tirp_flags,
        &ett_rdt_tirp_buffer_info,
        &ett_rdt_bw_probing_flags
    };

    module_t *rdt_module;

    /* Register protocol and fields */
    proto_rdt = proto_register_protocol("Real Data Transport", "RDT", "rdt");
    proto_register_field_array(proto_rdt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("rdt", dissect_rdt, proto_rdt);

    /* Preference settings */
    rdt_module = prefs_register_protocol(proto_rdt, proto_reg_handoff_rdt);
    prefs_register_bool_preference(rdt_module, "show_setup_info",
                                   "Show stream setup information",
                                   "Where available, show which protocol and frame caused "
                                   "this RDT stream to be created",
                                   &global_rdt_show_setup_info);

    prefs_register_bool_preference(rdt_module, "register_udp_port",
                                   "Register default UDP client port",
                                   "Register a client UDP port for RDT traffic",
                                   &global_rdt_register_udp_port);

    /* TODO: better to specify a range of ports instead? */
    prefs_register_uint_preference(rdt_module, "default_udp_port",
                                   "Default UDP client port",
                                   "Set the UDP port for clients",
                                   10, &global_rdt_udp_port);

}

void proto_reg_handoff_rdt(void)
{
    static gboolean rdt_prefs_initialized = FALSE;
    /* Also store this so can delete registered setting properly */
    static gboolean  rdt_register_udp_port;
    static guint     rdt_udp_port;

    if (!rdt_prefs_initialized)
    {
        /* Register this dissector as one that can be selected by a
           UDP port number. */
        rdt_handle = find_dissector("rdt");
        dissector_add_handle("udp.port", rdt_handle);
        rdt_prefs_initialized = TRUE;
    }
    else
    {
        /* Undo any current port registrations */
        if (rdt_register_udp_port)
        {
            dissector_delete_uint("udp.port", rdt_udp_port, rdt_handle);
        }
    }

    /* Remember whether a port is set for next time */
    rdt_register_udp_port = global_rdt_register_udp_port;

    /* Add any new port registration */
    if (global_rdt_register_udp_port)
    {
        /* Set our port number for future use */
        rdt_udp_port = global_rdt_udp_port;

        /* And register with this port */
        dissector_add_uint("udp.port", global_rdt_udp_port, rdt_handle);
    }
}

