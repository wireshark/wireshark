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
#include "packet-iwarp-ddp-rdmap.h"

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
static dissector_handle_t rpc_handler;

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
static int hf_rpcordma_segment_count = -1;

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
    guint chunk_size, start = offset;

    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (offset > max_offset)
            return 0;
        if (!value_follows)
            break;

        chunk_size = get_write_chunk_size(tvb, offset);
        if ((offset + chunk_size) < offset ||
            (offset + chunk_size) > max_offset)
            return 0;
        offset += chunk_size;
    }

    return offset - start;
}

static guint get_write_list_chunk_count(tvbuff_t *tvb, guint offset)
{
    guint32 value_follows;
    guint num_chunks, chunk_size;

    num_chunks = 0;
    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (!value_follows)
            break;

        num_chunks++;
        chunk_size = get_write_chunk_size(tvb, offset);
        if ((offset + chunk_size) < offset)
            break;
        offset += chunk_size;
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
    guint chunk_count, start = offset;
    proto_tree *read_list;
    guint32 value_follows;
    proto_item *item;

    chunk_count = get_read_list_chunk_count(tvb, offset);
    item = proto_tree_add_uint_format(tree, hf_rpcordma_reads_count,
                        tvb, offset, 0, chunk_count,
                        "Read list (count: %u)", chunk_count);

    read_list = proto_item_add_subtree(item, ett_rpcordma_read_list);

    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (!value_follows)
            break;

        offset = dissect_rpcrdma_read_chunk(read_list, tvb, offset);
    }

    proto_item_set_len(item, offset - start);
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
    proto_tree_add_item(write_chunk, hf_rpcordma_segment_count,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    for (i = 0; i < segment_count; ++i)
        offset = dissect_rpcrdma_segment(write_chunk, tvb, offset, i);

    return offset;
}

static guint dissect_rpcrdma_write_list(tvbuff_t *tvb, guint offset,
        proto_tree *tree)
{
    guint chunk_count, start = offset;
    proto_tree *write_list;
    guint32 value_follows;
    proto_item *item;

    chunk_count = get_write_list_chunk_count(tvb, offset);
    item = proto_tree_add_uint_format(tree, hf_rpcordma_writes_count,
                        tvb, offset, 0, chunk_count,
                        "Write list (count: %u)", chunk_count);

    write_list = proto_item_add_subtree(item, ett_rpcordma_write_list);

    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (!value_follows)
            break;

        offset = dissect_rpcrdma_write_chunk(write_list, tvb, offset);
    }

    proto_item_set_len(item, offset - start);
    return offset;
}

static guint dissect_rpcrdma_reply_chunk(tvbuff_t *tvb, guint offset,
        proto_tree *tree)
{
    guint32 chunk_count, start = offset;
    proto_tree *reply_chunk;
    guint32 value_follows;
    proto_item *item;

    chunk_count = get_reply_chunk_count(tvb, offset);
    item = proto_tree_add_uint_format(tree, hf_rpcordma_reply_count,
                tvb, offset, 4, chunk_count,
                "Reply chunk (count: %u)", chunk_count);

    reply_chunk = proto_item_add_subtree(item, ett_rpcordma_reply_chunk);

    value_follows = tvb_get_ntohl(tvb, offset);
    offset += 4;
    if (!value_follows)
        return offset;

    offset = dissect_rpcrdma_write_chunk(reply_chunk, tvb, offset);
    proto_item_set_len(item, offset - start);
    return offset;
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
static gboolean
packet_is_rpcordma(tvbuff_t *tvb)
{
    guint size, len = tvb_reported_length(tvb);
    guint32 xid_rpc;
    guint32 xid = tvb_get_ntohl(tvb, 0);
    guint32 msg_type = tvb_get_ntohl(tvb, 12);
    guint offset;

    if (len < MIN_RPCRDMA_HDR_SZ)
        return 0;

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

    case RDMA_NOMSG:
    case RDMA_DONE:
    case RDMA_ERROR:
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

static int
dissect_rpcrdma(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t *next_tvb;
    proto_item *ti;
    proto_tree *rpcordma_tree;
    guint offset = 0;
    guint32 msg_type = tvb_get_ntohl(tvb, 12);
    guint32 xid;
    guint32 val;

    if (tvb_get_ntohl(tvb, 4) != 1)  /* vers */
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

        proto_item_set_len(ti, offset);
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

        proto_item_set_len(ti, offset);
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
            proto_item_set_len(ti, offset);
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            return call_data_dissector(next_tvb, pinfo, tree);
        }
        break;
    }

    proto_item_set_len(ti, offset);
    return offset;
}

static gboolean
dissect_rpcrdma_ib_heur(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    struct infinibandinfo *info = (struct infinibandinfo *)data;

    if (!info)
        return FALSE;

    switch (info->opCode) {
    case RC_SEND_FIRST:
    case RC_SEND_MIDDLE:
    case RC_SEND_LAST:
    case RC_SEND_ONLY:
    case RC_SEND_LAST_INVAL:
    case RC_SEND_ONLY_INVAL:
        break;
    default:
        return FALSE;
    }

    if (!packet_is_rpcordma(tvb))
        return FALSE;
    dissect_rpcrdma(tvb, pinfo, tree, NULL);
    return TRUE;
}

static gboolean
dissect_rpcrdma_iwarp_heur(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    struct rdmapinfo *info = (struct rdmapinfo *)data;

    if (!info)
        return FALSE;

    switch (info->opcode) {
    case RDMA_SEND:
    case RDMA_SEND_INVALIDATE:
        break;
    default:
        return FALSE;
    }

    if (!packet_is_rpcordma(tvb))
        return FALSE;

    dissect_rpcrdma(tvb, pinfo, tree, NULL);
    return TRUE;
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
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL}
        },
        { &hf_rpcordma_flow_control,
          { "Flow Control", "rpcordma.flow_control",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL}
        },
        { &hf_rpcordma_message_type,
          { "Message Type", "rpcordma.msg_type",
            FT_UINT32, BASE_DEC,
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
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_rdma_offset,
          { "RDMA offset", "rpcordma.rdma_offset",
            FT_UINT64, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_position,
          { "Position in XDR", "rpcordma.position",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_segment_count,
          { "Write chunk segment count", "rpcordma.segment_count",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_rdma_align,
          { "RDMA align", "rpcordma.rdma_align",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_rdma_thresh,
          { "RDMA threshold", "rpcordma.rdma_thresh",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_errcode,
          { "Error code", "rpcordma.errcode",
            FT_UINT32, BASE_DEC,
            VALS(rpcordma_err), 0, NULL, HFILL }
        },
        { &hf_rpcordma_vers_low,
          { "Version low", "rpcordma.vers_low",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_rpcordma_vers_high,
          { "Version high", "rpcordma.vers_high",
            FT_UINT32, BASE_DEC,
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

    prefs_register_obsolete_preference(rpcordma_module, "manual_en");
    prefs_register_obsolete_preference(rpcordma_module, "addr_a");
    prefs_register_obsolete_preference(rpcordma_module, "addr_a_type");
    prefs_register_obsolete_preference(rpcordma_module, "addr_a_id");
    prefs_register_obsolete_preference(rpcordma_module, "addr_a_qp");
    prefs_register_obsolete_preference(rpcordma_module, "addr_b");
    prefs_register_obsolete_preference(rpcordma_module, "addr_b_type");
    prefs_register_obsolete_preference(rpcordma_module, "addr_b_id");
    prefs_register_obsolete_preference(rpcordma_module, "addr_b_qp");
    prefs_register_obsolete_preference(rpcordma_module, "target_ports");
}

void
proto_reg_handoff_rpcordma(void)
{
    heur_dissector_add("infiniband.payload", dissect_rpcrdma_ib_heur, "RPC-over-RDMA on Infiniband",
                        "rpcrdma_infiniband", proto_rpcordma, HEURISTIC_ENABLE);
    dissector_add_for_decode_as("infiniband", create_dissector_handle( dissect_rpcrdma, proto_rpcordma ) );

    heur_dissector_add("iwarp_ddp_rdmap", dissect_rpcrdma_iwarp_heur, "RPC-over-RDMA on iWARP",
                        "rpcrdma_iwarp", proto_rpcordma, HEURISTIC_ENABLE);

    rpc_handler = find_dissector_add_dependency("rpc", proto_rpcordma);
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
