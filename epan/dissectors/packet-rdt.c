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
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <stdio.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>

#include "packet-rdt.h"

static dissector_handle_t rdt_handle;

static gint    proto_rdt                        = -1;

/* Packet fields */
static gint    hf_rdt_packet                    = -1;

/* flags1: shared */
static gint    hf_rdt_len_included              = -1;

/* flags1: data packet */
static gint    hf_rdt_data_need_reliable        = -1;
static gint    hf_rdt_data_stream_id            = -1;
static gint    hf_rdt_data_is_reliable          = -1;
static gint    hf_rdt_data_backtoback           = -1;
static gint    hf_rdt_data_slowdata             = -1;
static gint    hf_rdt_data_asmrule              = -1;

/* flags1: asm action packet */
static gint    hf_rdt_aact_stream_id            = -1;

/* Octets 1-2: sequence number or packet type */
static gint    hf_rdt_sequence_number           = -1;
static gint    hf_rdt_packet_type               = -1;

static gint    hf_rdt_ack_lost_high             = -1;

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
static gint    hf_rdt_bwpp_seqno                = -1;
static gint    hf_rdt_unk_flags1                = -1;

/* RDT setup fields */
static gint    hf_rdt_setup                     = -1;
static gint    hf_rdt_setup_frame               = -1;
static gint    hf_rdt_setup_method              = -1;

/* RDT fields defining a sub tree */
static gint    ett_rdt                          = -1;
static gint    ett_rdt_packet                   = -1;
static gint    ett_rdt_setup                    = -1;


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

/* Memory chunk for storing conversation and per-packet info */
static GMemChunk *rdt_conversations = NULL;


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
    { RDT_BANDWIDTHREPORT_PACKET,        "Bandwith report"  },
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
                     gchar *setup_method, guint32 setup_frame_number)
{
    address null_addr;
    conversation_t* p_conv;
    struct _rdt_conversation_info *p_conv_data = NULL;

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
    p_conv = find_conversation(setup_frame_number, addr, &null_addr, PT_UDP, port, other_port,
                               NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

    /* If not, create a new conversation. */
    if ( !p_conv || p_conv->setup_frame != setup_frame_number)
    {
        p_conv = conversation_new(setup_frame_number, addr, &null_addr, PT_UDP,
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
        p_conv_data = g_mem_chunk_alloc(rdt_conversations);

        conversation_add_proto_data(p_conv, proto_rdt, p_conv_data);
    }

    /* Update the conversation data. */
    strncpy(p_conv_data->method, setup_method, MAX_RDT_SETUP_METHOD_SIZE);
    p_conv_data->method[MAX_RDT_SETUP_METHOD_SIZE] = '\0';
    p_conv_data->frame_number = setup_frame_number;
}

/* Initialise dissector-global storage */
static void rdt_init(void)
{
    /* (Re)allocate mem chunk for conversations */
    if (rdt_conversations)
    {
        g_mem_chunk_destroy(rdt_conversations);
    }

    rdt_conversations = g_mem_chunk_new("rdt_conversations",
                                        sizeof(struct _rdt_conversation_info),
                                        20 * sizeof(struct _rdt_conversation_info),
                                        G_ALLOC_ONLY);
}



/****************************************************************************/
/* Main dissection function                                                 */
/****************************************************************************/
static void dissect_rdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       previous_offset = 0;
    gint        offset = 0;
    proto_item  *ti = NULL;
    proto_tree  *rdt_tree = NULL;
    proto_tree  *rdt_packet_tree = NULL;
    guint16     packet_type;

    /* Set columns */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDT");
    }
    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_set_str(pinfo->cinfo, COL_INFO, "RealPlayer:");
    }

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
        /* Every packet type should have at least 5 bytes */
        tvb_ensure_bytes_exist(tvb, offset, 5);

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
    guint8      flags2;
    guint32     timestamp;
    guint16     asm_rule_number;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = flags1 & 0x80;
    need_reliable_flag = flags1 & 0x40;
    stream_id = (flags1 & 0x3e) >> 1;
    proto_tree_add_item(tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_rdt_data_need_reliable, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_rdt_data_stream_id, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_rdt_data_is_reliable, tvb, offset, 1, FALSE);
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

    /* More bit fields */
    flags2 = tvb_get_guint8(tvb, offset);
    asm_rule_number = flags2 & 0x3f;
    proto_tree_add_item(tree, hf_rdt_data_backtoback, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_rdt_data_slowdata, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_rdt_data_asmrule, tvb, offset, 1, FALSE);
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

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        "  DATA: stream-id=%02d seq=%05d ts=%d",
                        stream_id, sequence_number, timestamp);
    }

    /* The remaining data is unparsed. */
    proto_tree_add_item(tree, hf_rdt_data, tvb, offset, -1, FALSE);
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

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = flags1 & 0x80;
    stream_id = (flags1 & 0x7c) >> 2;
    proto_tree_add_item(tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_rdt_aact_stream_id, tvb, offset, 1, FALSE);
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

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        "  ASM-ACTION: stream-id=%02d rs=%05d",
                        stream_id, rel_seqno);
    }

    /* The remaining data is unparsed. */
    proto_tree_add_item(tree, hf_rdt_data, tvb, offset, -1, FALSE);

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

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = flags1 & 0x80;
    proto_tree_add_item(tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
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

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_add_str(pinfo->cinfo, COL_INFO, "  BANDWIDTH-REPORT: ");
    }

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
    guint8      lost_high;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = flags1 & 0x80;
    lost_high = flags1 & 0x40;
    proto_tree_add_item(tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_rdt_ack_lost_high, tvb, offset, 1, FALSE);
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
    proto_tree_add_item(tree, hf_rdt_data, tvb, offset, -1, FALSE);

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "  ACK: ");
    }

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
    guint8      flags1;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_add_str(pinfo->cinfo, COL_INFO, "  RTT-REQUEST: ");
    }

    return offset;
}

/* Dissect an att-response packet */
guint dissect_rdt_rtt_response_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8      flags1;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    proto_tree_add_item(tree, hf_rdt_rtrp_ts_sec, tvb, offset, 4, FALSE);
    offset += 4;
    proto_tree_add_item(tree, hf_rdt_rtrp_ts_usec, tvb, offset, 4, FALSE);
    offset += 4;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "  RTT-RESPONSE: ");
    }

    return offset;
}

/* Dissect an congestion packet */
guint dissect_rdt_congestion_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8      flags1;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    proto_tree_add_item(tree, hf_rdt_cong_xmit_mult, tvb, offset, 4, FALSE);
    offset += 4;
    proto_tree_add_item(tree, hf_rdt_cong_recv_mult, tvb, offset, 4, FALSE);
    offset += 4;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "  CONGESTION: ");
    }

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

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    need_reliable = flags1 & 0x80;
    stream_id = (flags1 & 0x7c) >> 2;
    packet_sent = flags1 & 0x2;
    ext_flag = flags1 & 0x1;
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

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "  STREAM-END: ");
    }

    return offset;
}

/* Dissect an report packet */
guint dissect_rdt_report_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       start_offset = offset;
    guint16     packet_length;
    guint8      flags1;
    guint8      length_included_flag;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = flags1 & 0x80;
    proto_tree_add_item(tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
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

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "  REPORT: ");
    }

    /* The remaining data is unparsed. */
    proto_tree_add_item(tree, hf_rdt_data, tvb, offset, -1, FALSE);

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

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = flags1 & 0x80;
    proto_tree_add_item(tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
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

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        "  LATENCY-REPORT: t=%d",
                        server_out_time);
    }

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
    guint8      request_rtt_info;
    guint32     request_time_msec;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    request_rtt_info = flags1 & 0x2;
    proto_tree_add_item(tree, hf_rdt_tirq_request_rtt_info, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_rdt_tirq_request_buffer_info, tvb, offset, 1, FALSE);
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    if (request_rtt_info)
    {
        request_time_msec = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(tree, hf_rdt_tirq_request_time_msec, tvb, offset, 4, FALSE);
        offset += 4;
    }

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "  TRANSPORT-INFO-REQUEST: ");
    }

    return offset;
}

/* Dissect an transport-info-response packet */
guint dissect_rdt_transport_info_response_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8      flags1;
    guint8      has_rtt_info;
    guint8      is_delayed;
    guint8      has_buffer_info;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    has_rtt_info = flags1 & 0x4;
    is_delayed = flags1 & 0x2;
    has_buffer_info = flags1 & 0x1;
    proto_tree_add_item(tree, hf_rdt_tirp_has_rtt_info, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_rdt_tirp_is_delayed, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_rdt_tirp_has_buffer_info, tvb, offset, 1, FALSE);
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    /* TODO: parse rtt_info, buffer_info */
    offset += tvb_length_remaining(tvb, offset);

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "  RESPONSE: ");
    }

    return offset;
}

/* Dissect a bw-probing packet */
guint dissect_rdt_bw_probing_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       start_offset = offset;
    guint16     packet_length;
    guint8      flags1;
    guint8      length_included_flag;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    length_included_flag = flags1 & 0x80;
    proto_tree_add_item(tree, hf_rdt_len_included, tvb, offset, 1, FALSE);
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

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "  BW-PROBING: ");
    }

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
    guint8      flags1;

    /* Flags in first byte */
    flags1 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_rdt_unk_flags1, tvb, offset, 1, FALSE);
    offset++;

    /* Packet type */
    proto_tree_add_item(tree, hf_rdt_packet_type, tvb, offset, 2, FALSE);
    offset += 2;

    /* The remaining data is unparsed. */
    proto_tree_add_item(tree, hf_rdt_data, tvb, offset, -1, FALSE);
    offset += tvb_length_remaining(tvb, offset);

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "  UNKNOWN-CTL: ");
    }

    return offset;
}

/* Look for conversation info and display any setup info found */
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Conversation and current data */
    conversation_t *p_conv = NULL;
    struct _rdt_conversation_info *p_conv_data = NULL;

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
                p_conv_packet_data = g_mem_chunk_alloc(rdt_conversations);
                strcpy(p_conv_packet_data->method, p_conv_data->method);
                p_conv_packet_data->frame_number = p_conv_data->frame_number;
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
                                                       "Stream setup by %s (frame %d)",
                                                       p_conv_data->method,
                                                       p_conv_data->frame_number);
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
                "RDT packet", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "Packet type", HFILL
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
                "Lost high", HFILL
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
                "", HFILL
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
                "Timestamp", HFILL
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
                "Stream-id expansion", HFILL
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
                "Asm rule expansion", HFILL
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
                "Total reliable", HFILL
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
               "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
                "", HFILL
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
        }
    };

    static gint *ett[] =
    {
        &ett_rdt,
        &ett_rdt_packet,
        &ett_rdt_setup
    };

    module_t *rdt_module;

    /* Register protocol and fields */
    proto_rdt = proto_register_protocol("Real Data Transport", "RDT", "rdt");
    proto_register_field_array(proto_rdt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("rdt", dissect_rdt, proto_rdt);

    /* Preference settings */
    rdt_module = prefs_register_protocol(proto_rdt, NULL);
    prefs_register_bool_preference(rdt_module, "show_setup_info",
                                   "Show stream setup information",
                                   "Where available, show which protocol and frame caused "
                                   "this RDT stream to be created",
                                   &global_rdt_show_setup_info);

    register_init_routine(&rdt_init);
}

void proto_reg_handoff_rdt(void)
{
    rdt_handle = find_dissector("rdt");
}

