/* packet-rpcordma.c
 * Routines for RPC over RDMA dissection (RFC 5666)
 * Copyright 2014-2015, Mellanox Technologies Ltd.
 * Code by Yan Burman.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>

#include "packet-infiniband.h"

#define MIN_RPCRDMA_HDR_SZ  16
#define MIN_RPCRDMA_MSG_SZ  (MIN_RPCRDMA_HDR_SZ + 12)
#define MIN_RPCRDMA_MSGP_SZ (MIN_RPCRDMA_MSG_SZ +  8)

#define SID_ULP_MASK   0x00000000FF000000
#define SID_PROTO_MASK 0x0000000000FF0000
#define SID_PORT_MASK  0x000000000000FFFF

#define SID_ULP         0x01
#define SID_PROTO_TCP   0x06
#define TCP_PORT_RPCRDMA_RANGE    "20049,2050"

#define SID_MASK    (SID_ULP_MASK | SID_PROTO_MASK)
#define SID_ULP_TCP ((SID_ULP << 3 * 8) | (SID_PROTO_TCP << 2 * 8))

void proto_reg_handoff_rpcordma(void);
void proto_register_rpcordma(void);

static int proto_rpcordma = -1;
static dissector_handle_t ib_handler;
static dissector_handle_t rpc_handler;
static dissector_handle_t rpcordma_handler;
static int proto_ib = -1;

/* RPCoRDMA Header */
static int hf_rpcordma_xid = -1;
static int hf_rpcordma_vers = -1;
static int hf_rpcordma_flow_control = -1;
static int hf_rpcordma_message_type = -1;

/* chunks */
static int hf_rpcordma_reads_count = -1;
static int hf_rpcordma_writes_count = -1;
static int hf_rpcordma_reply_count = -1;

static int hf_rpcordma_position = -1;

/* rdma_segment */
static int hf_rpcordma_rdma_handle = -1;
static int hf_rpcordma_rdma_length = -1;
static int hf_rpcordma_rdma_offset = -1;

static int hf_rpcordma_rdma_align = -1;
static int hf_rpcordma_rdma_thresh = -1;

static int hf_rpcordma_errcode = -1;
static int hf_rpcordma_vers_high = -1;
static int hf_rpcordma_vers_low = -1;

/* Initialize the subtree pointers */
static gint ett_rpcordma = -1;
static gint ett_rpcordma_chunk = -1;
static gint ett_rpcordma_read_list = -1;
static gint ett_rpcordma_read_chunk = -1;
static gint ett_rpcordma_write_list = -1;
static gint ett_rpcordma_write_chunk = -1;
static gint ett_rpcordma_reply_chunk = -1;
static gint ett_rpcordma_segment = -1;

/* global preferences */
static gboolean gPREF_MAN_EN    = FALSE;
static gint gPREF_TYPE[2]       = {0};
static const char *gPREF_ID[2]  = {NULL};
static guint gPREF_QP[2]        = {0};
static range_t *gPORT_RANGE;

/* source/destination addresses from preferences menu (parsed from gPREF_TYPE[?], gPREF_ID[?]) */
static address manual_addr[2];
static void *manual_addr_data[2];

static const enum_val_t pref_address_types[] = {
    {"lid", "LID", 0},
    {"gid", "GID", 1},
    {NULL, NULL, -1}
};

enum MSG_TYPE {
    RDMA_MSG,
    RDMA_NOMSG,
    RDMA_MSGP,
    RDMA_DONE,
    RDMA_ERROR
};

static const value_string rpcordma_message_type[] = {
    {RDMA_MSG,   "RDMA_MSG"},
    {RDMA_NOMSG, "RDMA_NOMSG"},
    {RDMA_MSGP,  "RDMA_MSGP"},
    {RDMA_DONE,  "RDMA_DONE"},
    {RDMA_ERROR, "RDMA_ERROR"},
    {0, NULL}
};

#define ERR_VERS  1
#define ERR_CHUNK 2

static const value_string rpcordma_err[] = {
    {ERR_VERS,  "ERR_VERS"},
    {ERR_CHUNK, "ERR_CHUNK"},
    {0, NULL}
};

static guint get_read_list_size(tvbuff_t *tvb, guint max_offset, guint offset)
{
    guint32 value_follows;
    guint start = offset;

    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (offset > max_offset)
            return 0;
        if (!value_follows)
            break;

        offset += 20;
        if (offset > max_offset)
            return 0;
    }

    return offset - start;
}

static guint get_read_list_chunk_count(tvbuff_t *tvb, guint offset)
{
    guint32 value_follows;
    guint num_chunks;

    num_chunks = 0;
    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (!value_follows)
            break;

        num_chunks++;
        offset += 20;
    }
    return num_chunks;
}

static guint get_write_chunk_size(tvbuff_t *tvb, guint offset)
{
    guint segment_count;

    segment_count = tvb_get_ntohl(tvb, offset);
    return 4 + (segment_count * 16);
}

static guint get_write_list_size(tvbuff_t *tvb, guint max_offset, guint offset)
{
    guint32 value_follows;
    guint start = offset;

    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (offset > max_offset)
            return 0;
        if (!value_follows)
            break;

        offset += get_write_chunk_size(tvb, offset);
        if (offset > max_offset)
            return 0;
    }

    return offset - start;
}

static guint get_write_list_chunk_count(tvbuff_t *tvb, guint offset)
{
    guint32 value_follows;
    guint num_chunks;

    num_chunks = 0;
    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (!value_follows)
            break;

        num_chunks++;
        offset += get_write_chunk_size(tvb, offset);
    }

   return num_chunks;
}

static guint get_reply_chunk_size(tvbuff_t *tvb, guint max_offset, guint offset)
{
    guint32 value_follows;
    guint start = offset;

    value_follows = tvb_get_ntohl(tvb, offset);
    offset += 4;
    if (offset > max_offset)
        return 0;

    if (value_follows) {
        offset += get_write_chunk_size(tvb, offset);
        if (offset > max_offset)
            return 0;
    }

    return offset - start;
}

static guint get_reply_chunk_count(tvbuff_t *tvb, guint offset)
{
    guint32 value_follows;

    value_follows = tvb_get_ntohl(tvb, offset);
    return value_follows ? 1 : 0;
}

static guint dissect_rpcrdma_read_chunk(proto_tree *read_list,
        tvbuff_t *tvb, guint offset)
{
    proto_tree *read_chunk;
    guint32 position;

    position = tvb_get_ntohl(tvb, offset);
    read_chunk = proto_tree_add_subtree_format(read_list, tvb,
                        offset, 20, ett_rpcordma_read_chunk, NULL,
                        "Read chunk: (position %u)", position);

    proto_tree_add_item(read_chunk, hf_rpcordma_position, tvb,
                offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(read_chunk, hf_rpcordma_rdma_handle, tvb,
                offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(read_chunk, hf_rpcordma_rdma_length, tvb,
                offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(read_chunk, hf_rpcordma_rdma_offset, tvb,
                offset, 8, ENC_BIG_ENDIAN);
    return offset + 8;
}

static guint dissect_rpcrdma_read_list(tvbuff_t *tvb, guint offset,
        proto_tree *tree)
{
    guint reported_length = tvb_reported_length(tvb);
    guint selection_size, chunk_count;
    proto_tree *read_list;
    guint32 value_follows;
    proto_item *item;

    selection_size = get_read_list_size(tvb, reported_length, offset);
    chunk_count = get_read_list_chunk_count(tvb, offset);
    item = proto_tree_add_uint_format(tree, hf_rpcordma_reads_count,
                        tvb, offset, selection_size, chunk_count,
                        "Read list (count: %u)", chunk_count);

    read_list = proto_item_add_subtree(item, ett_rpcordma_read_list);

    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (!value_follows)
            break;

        offset = dissect_rpcrdma_read_chunk(read_list, tvb, offset);
    }

    return offset;
}

static guint dissect_rpcrdma_segment(proto_tree *write_chunk, tvbuff_t *tvb,
        guint offset, guint32 i)
{
    proto_tree *segment;

    segment = proto_tree_add_subtree_format(write_chunk, tvb,
                    offset, 16, ett_rpcordma_segment, NULL,
                    "RDMA segment %u", i);

    proto_tree_add_item(segment, hf_rpcordma_rdma_handle, tvb,
                offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(segment, hf_rpcordma_rdma_length, tvb,
                offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(segment, hf_rpcordma_rdma_offset, tvb,
                offset, 8, ENC_BIG_ENDIAN);
    return offset + 8;
}

static guint dissect_rpcrdma_write_chunk(proto_tree *write_list,
        tvbuff_t *tvb, guint offset)
{
    guint32 i, segment_count;
    proto_tree *write_chunk;
    guint selection_size;

    selection_size = get_write_chunk_size(tvb, offset);
    segment_count = tvb_get_ntohl(tvb, offset);
    write_chunk = proto_tree_add_subtree_format(write_list, tvb,
                        offset, selection_size,
                        ett_rpcordma_write_chunk, NULL,
                        "Write chunk (%u segment%s)", segment_count,
                        segment_count == 1 ? "" : "s");
    offset += 4;

    for (i = 0; i < segment_count; ++i)
        offset = dissect_rpcrdma_segment(write_chunk, tvb, offset, i);

    return offset;
}

static guint dissect_rpcrdma_write_list(tvbuff_t *tvb, guint offset,
        proto_tree *tree)
{
    guint reported_length = tvb_reported_length(tvb);
    guint selection_size, chunk_count;
    proto_tree *write_list;
    guint32 value_follows;
    proto_item *item;

    selection_size = get_write_list_size(tvb, reported_length, offset);
    chunk_count = get_write_list_chunk_count(tvb, offset);
    item = proto_tree_add_uint_format(tree, hf_rpcordma_writes_count,
                        tvb, offset, selection_size, chunk_count,
                        "Write list (count: %u)", chunk_count);

    write_list = proto_item_add_subtree(item, ett_rpcordma_write_list);

    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (!value_follows)
            break;

        offset = dissect_rpcrdma_write_chunk(write_list, tvb, offset);
    }

    return offset;
}

static guint dissect_rpcrdma_reply_chunk(tvbuff_t *tvb, guint offset,
        proto_tree *tree)
{
    guint reported_length = tvb_reported_length(tvb);
    guint32 selection_size, chunk_count;
    proto_tree *reply_chunk;
    guint32 value_follows;
    proto_item *item;

    selection_size = get_reply_chunk_size(tvb, reported_length, offset);
    chunk_count = get_reply_chunk_count(tvb, offset);
    item = proto_tree_add_uint_format(tree, hf_rpcordma_reply_count,
                tvb, offset, selection_size, chunk_count,
                "Reply chunk (count: %u)", chunk_count);

    reply_chunk = proto_item_add_subtree(item, ett_rpcordma_reply_chunk);

    value_follows = tvb_get_ntohl(tvb, offset);
    offset += 4;
    if (!value_follows)
        return offset;

    return dissect_rpcrdma_write_chunk(reply_chunk, tvb, offset);
}

static guint parse_rdma_header(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    offset = dissect_rpcrdma_read_list(tvb, offset, tree);
    offset = dissect_rpcrdma_write_list(tvb, offset, tree);
    return dissect_rpcrdma_reply_chunk(tvb, offset, tree);
}

static guint get_chunk_lists_size(tvbuff_t *tvb, guint max_offset, guint offset)
{
    guint size, start = offset;

    size = get_read_list_size(tvb, max_offset, offset);
    if (!size)
        return 0;
    offset += size;

    size = get_write_list_size(tvb, max_offset, offset);
    if (!size)
        return 0;
    offset += size;

    size = get_reply_chunk_size(tvb, max_offset, offset);
    if (!size)
        return 0;
    offset += size;

    return offset - start;
}

/*
 * We need to differentiate between RPC messages inside RDMA and regular send messages.
 * In order to do that (as well as extra validation) we want to verify that for RDMA_MSG
 * and RDMA_MSGP types, RPC call or RPC reply header follows. We can do this by comparing
 * XID in RPC and RPCoRDMA headers.
 */
/* msg_type has already been validated */
static gboolean
packet_is_rpcordma(tvbuff_t *tvb)
{
    guint size, len = tvb_reported_length(tvb);
    guint32 xid_rpc;
    guint32 xid = tvb_get_ntohl(tvb, 0);
    guint32 msg_type = tvb_get_ntohl(tvb, 12);
    guint offset;

    switch (msg_type) {
    case RDMA_MSG:
        if (len < MIN_RPCRDMA_MSG_SZ)
            return FALSE;
        offset = MIN_RPCRDMA_HDR_SZ;
        size = get_chunk_lists_size(tvb, len, offset);
        if (!size)
            return FALSE;
        offset += size;

        if (offset + 4 > len)
            return FALSE;
        xid_rpc = tvb_get_ntohl(tvb, offset);
        if (xid != xid_rpc)
            return FALSE;
        break;

    case RDMA_MSGP:
        if (len < MIN_RPCRDMA_MSGP_SZ)
            return FALSE;
        offset = MIN_RPCRDMA_HDR_SZ + 8;
        size = get_chunk_lists_size(tvb, len, offset);
        if (!size)
            return FALSE;
        offset += size;

        if (offset + 4 > len)
            return FALSE;
        xid_rpc = tvb_get_ntohl(tvb, offset);
        if (xid != xid_rpc)
            return FALSE;
        break;

    default:
        break;
    }

    return TRUE;
}

static int
dissect_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *next_tvb;
    proto_item *ti;
    proto_tree *rpcordma_tree;
    guint offset = 0;
    guint32 xid;
    guint32 msg_type;
    guint32 val;

    if (tvb_reported_length(tvb) < MIN_RPCRDMA_HDR_SZ)
        return 0;

    if (tvb_get_ntohl(tvb, 4) != 1)  /* vers */
        return 0;

    msg_type = tvb_get_ntohl(tvb, 12);
    if (msg_type > RDMA_ERROR)
        return 0;

    if (!packet_is_rpcordma(tvb))
        return 0;

    xid = tvb_get_ntohl(tvb, 0);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RPCoRDMA");
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s XID 0x%x",
        val_to_str(msg_type, rpcordma_message_type, "Unknown (%d)"), xid);

    ti = proto_tree_add_item(tree, proto_rpcordma, tvb, 0, MIN_RPCRDMA_HDR_SZ, ENC_NA);

    rpcordma_tree = proto_item_add_subtree(ti, ett_rpcordma);

    proto_tree_add_item(rpcordma_tree, hf_rpcordma_xid, tvb,
                offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(rpcordma_tree, hf_rpcordma_vers, tvb,
                offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(rpcordma_tree, hf_rpcordma_flow_control, tvb,
                offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(rpcordma_tree, hf_rpcordma_message_type, tvb,
                offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    switch (msg_type) {
    case RDMA_MSG:
        /* Parse rpc_rdma_header */
        offset = parse_rdma_header(tvb, offset, rpcordma_tree);

        next_tvb = tvb_new_subset_remaining(tvb, offset);
        return call_dissector(rpc_handler, next_tvb, pinfo, tree);

    case RDMA_NOMSG:
        /* Parse rpc_rdma_header_nomsg */
        offset = parse_rdma_header(tvb, offset, rpcordma_tree);
        break;

    case RDMA_MSGP:
        /* Parse rpc_rdma_header_padded */
        proto_tree_add_item(rpcordma_tree, hf_rpcordma_rdma_align, tvb,
                    offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(rpcordma_tree, hf_rpcordma_rdma_thresh, tvb,
                    offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        offset = parse_rdma_header(tvb, offset, rpcordma_tree);

        next_tvb = tvb_new_subset_remaining(tvb, offset);
        return call_dissector(rpc_handler, next_tvb, pinfo, tree);

    case RDMA_DONE:
        break;

    case RDMA_ERROR:
        /* rpc_rdma_errcode */
        val = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(rpcordma_tree, hf_rpcordma_errcode, tvb,
                    offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        switch (val) {
        case ERR_VERS:
            proto_tree_add_item(rpcordma_tree, hf_rpcordma_vers_low, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(rpcordma_tree, hf_rpcordma_vers_high, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;

        case ERR_CHUNK:
            break;

        default:
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            return call_data_dissector(next_tvb, pinfo, tree);
        }
        break;
    }

    return offset;
}

static int
dissect_rpcordma(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    return dissect_packet(tvb, pinfo, tree);
}

static gboolean
dissect_rpcordma_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    conversation_t *conv;
    conversation_infiniband_data *convo_data = NULL;

    if (gPREF_MAN_EN) {
        /* If the manual settings are enabled see if this fits - in which case we can skip
           the following checks entirely and go straight to dissecting */
        if (    (addresses_equal(&pinfo->src, &manual_addr[0]) &&
                 addresses_equal(&pinfo->dst, &manual_addr[1]) &&
                 (pinfo->srcport == 0xffffffff /* is unknown */ || pinfo->srcport == gPREF_QP[0]) &&
                 (pinfo->destport == 0xffffffff /* is unknown */ || pinfo->destport == gPREF_QP[1]))    ||
                (addresses_equal(&pinfo->src, &manual_addr[1]) &&
                 addresses_equal(&pinfo->dst, &manual_addr[0]) &&
                 (pinfo->srcport == 0xffffffff /* is unknown */ || pinfo->srcport == gPREF_QP[1]) &&
                 (pinfo->destport == 0xffffffff /* is unknown */ || pinfo->destport == gPREF_QP[0]))    )
            return (dissect_packet(tvb, pinfo, tree) != 0);
    }

    /* first try to find a conversation between the two current hosts. in most cases this
       will not work since we do not have the source QP. this WILL succeed when we're still
       in the process of CM negotiations */
    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                             PT_IBQP, pinfo->srcport, pinfo->destport, 0);

    if (!conv) {
        /* if not, try to find an established RC channel. recall Infiniband conversations are
           registered with one side of the channel. since the packet is only guaranteed to
           contain the qpn of the destination, we'll use this */
        conv = find_conversation(pinfo->num, &pinfo->dst, &pinfo->dst,
                                 PT_IBQP, pinfo->destport, pinfo->destport, NO_ADDR_B|NO_PORT_B);

        if (!conv)
            return FALSE;   /* nothing to do with no conversation context */
    }

    convo_data = (conversation_infiniband_data *)conversation_get_proto_data(conv, proto_ib);

    if (!convo_data)
        return FALSE;

    if ((convo_data->service_id & SID_MASK) != SID_ULP_TCP)
        return FALSE;   /* the service id doesn't match that of TCP ULP - nothing for us to do here */

    if (!(value_is_in_range(gPORT_RANGE, (guint32)(convo_data->service_id & SID_PORT_MASK))))
        return FALSE;   /* the port doesn't match that of RPCoRDMA - nothing for us to do here */

    conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, rpcordma_handler);

    return (dissect_packet(tvb, pinfo, tree) != 0);
}

void
proto_register_rpcordma(void)
{
    module_t *rpcordma_module;
    static hf_register_info hf[] = {
        { &hf_rpcordma_xid,
          { "XID", "rpcordma.xid",
            FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL}
        },
        { &hf_rpcordma_vers,
          { "Version", "rpcordma.version",
            FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL}
        },
        { &hf_rpcordma_flow_control,
          { "Flow Control", "rpcordma.flow_control",
            FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL}
        },
        { &hf_rpcordma_message_type,
          { "Message Type", "rpcordma.msg_type",
            FT_UINT32, BASE_HEX,
            VALS(rpcordma_message_type), 0x0, NULL, HFILL}
        },
        { &hf_rpcordma_reads_count,
          { "Read list", "rpcordma.reads_count",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_writes_count,
          { "Write list", "rpcordma.writes_count",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_reply_count,
          { "Reply list", "rpcordma.reply_count",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_rdma_handle,
          { "RDMA handle", "rpcordma.rdma_handle",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_rdma_length,
          { "RDMA length", "rpcordma.rdma_length",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_rdma_offset,
          { "RDMA offset", "rpcordma.rdma_offset",
            FT_UINT64, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_position,
          { "Postion in XDR", "rpcordma.position",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_rdma_align,
          { "RDMA align", "rpcordma.rdma_align",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_rdma_thresh,
          { "RDMA threshold", "rpcordma.rdma_thresh",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_errcode,
          { "Error code", "rpcordma.errcode",
            FT_UINT32, BASE_HEX,
            VALS(rpcordma_err), 0, NULL, HFILL }
        },
        { &hf_rpcordma_vers_low,
          { "Version low", "rpcordma.vers_low",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_vers_high,
          { "Version high", "rpcordma.vers_high",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_rpcordma,
        &ett_rpcordma_chunk,
        &ett_rpcordma_read_list,
        &ett_rpcordma_read_chunk,
        &ett_rpcordma_write_list,
        &ett_rpcordma_write_chunk,
        &ett_rpcordma_reply_chunk,
        &ett_rpcordma_segment,
    };

    proto_rpcordma = proto_register_protocol (
        "RPC over RDMA", /* name       */
        "RPCoRDMA",      /* short name */
        "rpcordma"       /* abbrev     */
        );

    proto_register_field_array(proto_rpcordma, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    rpcordma_module = prefs_register_protocol(proto_rpcordma, proto_reg_handoff_rpcordma);

    prefs_register_bool_preference(rpcordma_module, "manual_en", "Enable manual settings",
        "Check to treat all traffic between the configured source/destination as RPCoRDMA",
        &gPREF_MAN_EN);

    prefs_register_static_text_preference(rpcordma_module, "addr_a", "Address A",
        "Side A of the manually-configured connection");
    prefs_register_enum_preference(rpcordma_module, "addr_a_type", "Address Type",
        "Type of address specified", &gPREF_TYPE[0], pref_address_types, FALSE);
    prefs_register_string_preference(rpcordma_module, "addr_a_id", "ID",
        "LID/GID of address A", &gPREF_ID[0]);
    prefs_register_uint_preference(rpcordma_module, "addr_a_qp", "QP Number",
        "QP Number for address A", 10, &gPREF_QP[0]);

    prefs_register_static_text_preference(rpcordma_module, "addr_b", "Address B",
        "Side B of the manually-configured connection");
    prefs_register_enum_preference(rpcordma_module, "addr_b_type", "Address Type",
        "Type of address specified", &gPREF_TYPE[1], pref_address_types, FALSE);
    prefs_register_string_preference(rpcordma_module, "addr_b_id", "ID",
        "LID/GID of address B", &gPREF_ID[1]);
    prefs_register_uint_preference(rpcordma_module, "addr_b_qp", "QP Number",
        "QP Number for address B", 10, &gPREF_QP[1]);

    range_convert_str(&gPORT_RANGE, TCP_PORT_RPCRDMA_RANGE, MAX_TCP_PORT);
    prefs_register_range_preference(rpcordma_module,
                                    "target_ports",
                                    "Target Ports Range",
                                    "Range of RPCoRDMA server ports"
                                    "(default " TCP_PORT_RPCRDMA_RANGE ")",
                                    &gPORT_RANGE, MAX_TCP_PORT);
}

void
proto_reg_handoff_rpcordma(void)
{
    static gboolean initialized = FALSE;

    if (!initialized) {
        rpcordma_handler = create_dissector_handle(dissect_rpcordma, proto_rpcordma);
        heur_dissector_add("infiniband.payload", dissect_rpcordma_heur, "Infiniband RPC over RDMA", "rpcordma_infiniband", proto_rpcordma, HEURISTIC_ENABLE);
        heur_dissector_add("infiniband.mad.cm.private", dissect_rpcordma_heur, "RPC over RDMA in PrivateData of CM packets", "rpcordma_ib_private", proto_rpcordma, HEURISTIC_ENABLE);

        /* allocate enough space in the addresses to store the largest address (a GID) */
        manual_addr_data[0] = wmem_alloc(wmem_epan_scope(), GID_SIZE);
        manual_addr_data[1] = wmem_alloc(wmem_epan_scope(), GID_SIZE);

        rpc_handler = find_dissector_add_dependency("rpc", proto_rpcordma);
        ib_handler = find_dissector_add_dependency("infiniband", proto_rpcordma);
        proto_ib = dissector_handle_get_protocol_index(ib_handler);

        initialized = TRUE;
    }

    if (gPREF_MAN_EN) {
        /* the manual setting is enabled, so parse the settings into the address type */
        gboolean error_occured = FALSE;
        char *not_parsed;
        int i;

        for (i = 0; i < 2; i++) {
            if (gPREF_TYPE[i] == 0) {   /* LID */
                errno = 0;  /* reset any previous error indicators */
                *((guint16*)manual_addr_data[i]) = (guint16)strtoul(gPREF_ID[i], &not_parsed, 0);
                if (errno || *not_parsed != '\0') {
                    error_occured = TRUE;
                } else {
                    set_address(&manual_addr[i], AT_IB, sizeof(guint16), manual_addr_data[i]);
                }
            } else {    /* GID */
                if (!str_to_ip6(gPREF_ID[i], manual_addr_data[i]) ) {
                    error_occured = TRUE;
                } else {
                    set_address(&manual_addr[i], AT_IB, GID_SIZE, manual_addr_data[i]);
                }
            }

            if (error_occured) {
                /* an invalid id was specified - disable manual settings until it's fixed */
                gPREF_MAN_EN = FALSE;
                break;
            }
        }
    }
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
