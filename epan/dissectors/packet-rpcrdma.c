/* packet-rpcordma.c
 * Routines for RPC over RDMA dissection (RFC 5666)
 * Copyright 2014-2015, Mellanox Technologies Ltd.
 * Code by Yan Burman.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/exceptions.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>

#include "packet-rpcrdma.h"
#include "packet-frame.h"
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

static int proto_rpcordma;
static dissector_handle_t rpcordma_handle;
static dissector_handle_t rpc_handler;

/* RPCoRDMA Header */
static int hf_rpcordma_xid;
static int hf_rpcordma_vers;
static int hf_rpcordma_flow_control;
static int hf_rpcordma_message_type;

/* chunks */
static int hf_rpcordma_reads_count;
static int hf_rpcordma_writes_count;
static int hf_rpcordma_reply_count;

static int hf_rpcordma_position;
static int hf_rpcordma_segment_count;

/* rdma_segment */
static int hf_rpcordma_rdma_handle;
static int hf_rpcordma_rdma_length;
static int hf_rpcordma_rdma_offset;

static int hf_rpcordma_rdma_align;
static int hf_rpcordma_rdma_thresh;

static int hf_rpcordma_errcode;
static int hf_rpcordma_vers_high;
static int hf_rpcordma_vers_low;

/* Initialize the subtree pointers */
static int ett_rpcordma;
static int ett_rpcordma_chunk;
static int ett_rpcordma_read_list;
static int ett_rpcordma_read_chunk;
static int ett_rpcordma_write_list;
static int ett_rpcordma_write_chunk;
static int ett_rpcordma_reply_chunk;
static int ett_rpcordma_segment;

/* Fragmentation */
static int hf_rpcordma_fragments;
static int hf_rpcordma_fragment;
static int hf_rpcordma_fragment_overlap;
static int hf_rpcordma_fragment_overlap_conflicts;
static int hf_rpcordma_fragment_multiple_tails;
static int hf_rpcordma_fragment_too_long_fragment;
static int hf_rpcordma_fragment_error;
static int hf_rpcordma_fragment_count;
static int hf_rpcordma_reassembled_in;
static int hf_rpcordma_reassembled_length;
static int hf_rpcordma_reassembled_data;

static int ett_rpcordma_fragment;
static int ett_rpcordma_fragments;

static const fragment_items rpcordma_frag_items = {
    /* Fragment subtrees */
    &ett_rpcordma_fragment,
    &ett_rpcordma_fragments,
    /* Fragment fields */
    &hf_rpcordma_fragments,
    &hf_rpcordma_fragment,
    &hf_rpcordma_fragment_overlap,
    &hf_rpcordma_fragment_overlap_conflicts,
    &hf_rpcordma_fragment_multiple_tails,
    &hf_rpcordma_fragment_too_long_fragment,
    &hf_rpcordma_fragment_error,
    &hf_rpcordma_fragment_count,
    /* Reassembled in field */
    &hf_rpcordma_reassembled_in,
    /* Reassembled length field */
    &hf_rpcordma_reassembled_length,
    /* Reassembled data field */
    &hf_rpcordma_reassembled_data,
    /* Tag */
    "RPCoRDMA fragments"
};

/* Reassembly table */
static reassembly_table rpcordma_reassembly_table;

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

/* RDMA chunk type */
typedef enum {
    RDMA_READ_CHUNK,
    RDMA_WRITE_CHUNK,
    RDMA_REPLY_CHUNK
} chunk_type_t;

/* RDMA segment */
typedef struct {
    uint32_t xdrpos;  /* Position in XDR stream -- RDMA read only */
    uint32_t handle;  /* Registered memory handle */
    uint32_t length;  /* Length of segment in bytes */
    uint64_t offset;  /* Segment virtual address or offset */
} rdma_segment_t;

/* RDMA chunk */
typedef struct {
    chunk_type_t  type;      /* Chunk type */
    uint32_t      length;    /* Length of chunk in bytes */
    wmem_array_t *segments;  /* List of segments for chunk */
} rdma_chunk_t;

/* RPC-over-RDMA lists */
typedef struct {
    wmem_array_t *p_read_list;   /* List of RDMA read chunks */
    wmem_array_t *p_write_list;  /* List of RDMA write chunks */
    wmem_array_t *p_reply_list;  /* List of RDMA reply chunks */
} rdma_lists_t;

/*
 * Segment information for RDMA I/O
 * All segments belonging to the same chunk list have the same message ID
 * A segment could have multiple I/O requests
 */
typedef struct {
    uint32_t      handle;   /* Handle or remote key of segment */
    uint64_t      offset;   /* Segment virtual address or offset */
    uint32_t      msgid;    /* ID for fragments belonging together */
    uint32_t      msgno;    /* Message number base so fragments are
                               consecutive within segment requests */
    chunk_type_t  type;     /* Chunk type for segment */
    uint32_t      xdrpos;   /* Position in XDR stream -- RDMA read only */
    uint32_t      length;   /* Length of segment in bytes */
    uint32_t      rbytes;   /* Number of bytes added to reassembly table */
} segment_info_t;

typedef struct {
    uint32_t        psn;     /* First PSN for request */
    uint32_t        length;  /* Request length */
    uint64_t        offset;  /* Request offset */
    segment_info_t *segment; /* Segment info for RDMA I/O */
} ib_request_t;

/* Send reassembly info structure */
typedef struct {
    uint32_t msgid;  /* ID for fragments belonging together */
    uint32_t msgno;  /* Message number base */
    uint32_t rsize;  /* Number of bytes added to reassembly table */
} send_info_t;

/* State structure per conversation */
typedef struct {
    wmem_tree_t    *segment_list; /* Binary tree of segments searched by handle */
    wmem_tree_t    *psn_list;     /* Binary tree of IB requests searched by PSN */
    wmem_tree_t    *msgid_list;   /* Binary tree of segments with same message id */
    wmem_tree_t    *request_list; /* Binary tree of iWarp read requests for mapping sink -> source */
    wmem_tree_t    *send_list;    /* Binary tree for mapping PSN -> msgid (IB) */
    wmem_tree_t    *msn_list;     /* Binary tree for mapping MSN -> msgid (iWarp) */
    segment_info_t *segment_info; /* Current READ/WRITE/REPLY segment info */
    uint32_t        iosize;       /* Maximum size of data transferred in a
                                     single packet */
} rdma_conv_info_t;

/* Proto data keys */
enum {
    RPCRDMA_MSG_ID,
    RPCRDMA_FRAG_HEAD,
    RPCRDMA_WRITE_SIZE,
};

/* Return the number of fragments of size 'b' in 'a' */
#define NFRAGS(a,b) ((a)/(b) + ((a)%(b) ? 1: 0))

/*
 * Global variable set for every InfiniBand packet. This is used because
 * the arguments in dissect_rpcrdma are fixed and cannot be changed to pass
 * an extra argument to differentiate between InfiniBand and iWarp.
 * Reassembly is only supported for InfiniBand packets.
 */
static struct infinibandinfo *gp_infiniband_info;

/* Global variable set for every iWarp packet */
static rdmap_info_t *gp_rdmap_info;

/* Call process_reassembled_data just once per frame */
static bool g_needs_reassembly;

/* Array of offsets for reduced data in write chunks */
static wmem_array_t *gp_rdma_write_offsets;

/* Signal upper layer(s) the current frame's data has been reduced by DDP */
static bool g_rpcrdma_reduced;

/*
 * Signal upper layer(s) the current frame's data has been reduced by DDP
 * (direct data placement) in which large data chunks have been removed from
 * the XDR data so these data chunks could be transferred using RDMA writes.
 * This is only used on RDMA write chunks because there is no way to know
 * where each write chunk must be inserted into the XDR data.
 * Read chunks have the xdrpos because the client needs to notify the server
 * how to reassemble the reduced message and their chunks. On the other hand,
 * write chunks do not have this information because the client knows exactly
 * how to reassemble the reply with the use of the virtual address in the chunk,
 * but this virtual address is internal to the client -- there is no way to
 * map the virtual address to an offset within the XDR data.
 */
bool rpcrdma_is_reduced(void)
{
    return g_rpcrdma_reduced;
}

/*
 * Insert offset in the reduced data write chunk array.
 * Offset is relative to the reduced message from the end of the reported
 * buffer because the upper layer is dealing with the reduced XDR message
 * so it is easier to report this offset back and calculate the correct XDR
 * position in this layer before reassembly starts for a reduced message
 */
void rpcrdma_insert_offset(int offset)
{
    wmem_array_append_one(gp_rdma_write_offsets, offset);
}

/*
 * Reset the array of write offsets at the end of the frame. These
 * are packet scoped, so they don't need to be freed, but we want
 * to ensure that the global doesn't point to no longer allocated
 * memory in a later packet.
 */
static void
reset_write_offsets(void)
{
    gp_rdma_write_offsets = NULL;
}

/* Get conversation state, it is created if it does not exist */
static rdma_conv_info_t *get_rdma_conv_info(packet_info *pinfo)
{
    conversation_t *p_conversation;
    rdma_conv_info_t *p_rdma_conv_info;

    /* Find or create conversation info */
    p_conversation = find_or_create_conversation(pinfo);

    /* Get state structure for this conversation */
    p_rdma_conv_info = (rdma_conv_info_t *)conversation_get_proto_data(p_conversation, proto_rpcordma);
    if (p_rdma_conv_info == NULL) {
        /* Add state structure for this conversation */
        p_rdma_conv_info = wmem_new(wmem_file_scope(), rdma_conv_info_t);
        p_rdma_conv_info->segment_list = wmem_tree_new(wmem_file_scope());
        p_rdma_conv_info->psn_list     = wmem_tree_new(wmem_file_scope());
        p_rdma_conv_info->msgid_list   = wmem_tree_new(wmem_file_scope());
        p_rdma_conv_info->send_list    = wmem_tree_new(wmem_file_scope());
        p_rdma_conv_info->msn_list     = wmem_tree_new(wmem_file_scope());
        p_rdma_conv_info->request_list = wmem_tree_new(wmem_file_scope());
        p_rdma_conv_info->segment_info = NULL;
        p_rdma_conv_info->iosize = 1;
        conversation_add_proto_data(p_conversation, proto_rpcordma, p_rdma_conv_info);
    }
    return p_rdma_conv_info;
}

/* Set RDMA maximum I/O size for conversation */
static void set_max_iosize(rdma_conv_info_t *p_rdma_conv_info, unsigned size)
{
    p_rdma_conv_info->iosize = MAX(p_rdma_conv_info->iosize, size);
}

/* Return a unique non-zero message ID */
static uint32_t get_msg_id(void)
{
    static uint32_t msg_id = 0;
    if (++msg_id == 0) {
        /* Message ID has wrapped around so increment again */
        ++msg_id;
    }
    return msg_id;
}

/* Find segment info for the given handle and offset */
static segment_info_t *find_segment_info(rdma_conv_info_t *p_rdma_conv_info, uint32_t handle, uint64_t offset)
{
    segment_info_t *p_segment_info;

    p_segment_info = (segment_info_t *)wmem_tree_lookup32(p_rdma_conv_info->segment_list, handle);
    if (p_segment_info && offset >= p_segment_info->offset && \
        offset < p_segment_info->offset + p_segment_info->length)
        return p_segment_info;
    return NULL;
}

/* Add Infiniband request info for the correct segment */
static void add_request_info(rdma_conv_info_t *p_rdma_conv_info, packet_info *pinfo)
{
    segment_info_t *p_segment_info;
    ib_request_t   *p_ib_request;

    if (!pinfo->fd->visited) {
        p_segment_info = find_segment_info(p_rdma_conv_info, gp_infiniband_info->reth_remote_key, gp_infiniband_info->reth_remote_address);
        if (p_segment_info) {
            /* Add request to list */
            p_ib_request = wmem_new(wmem_file_scope(), ib_request_t);
            p_ib_request->psn     = gp_infiniband_info->packet_seq_num;
            p_ib_request->offset  = gp_infiniband_info->reth_remote_address;
            p_ib_request->length  = gp_infiniband_info->reth_dma_length;
            p_ib_request->segment = p_segment_info;
            wmem_tree_insert32(p_rdma_conv_info->psn_list, gp_infiniband_info->packet_seq_num, p_ib_request);
        }
    }
}

/*
 * Return if reassembly is done by checking all bytes in each segment have
 * been added to the reassembly table. It could be more than requested
 * because of padding bytes.
 */
static bool is_reassembly_done(rdma_conv_info_t *p_rdma_conv_info, uint32_t msgid)
{
    uint32_t message_size = 0;
    uint32_t reassembled_size = 0;
    wmem_list_frame_t *item;
    wmem_list_t    *msgid_segments;
    segment_info_t *p_segment_info;
    bool ret = false; /* Make sure there is at least one segment */
    int segment_type = -1;

    /* Get all segments for the given msgid */
    msgid_segments = wmem_tree_lookup32(p_rdma_conv_info->msgid_list, msgid);
    if (msgid_segments) {
        for (item = wmem_list_head(msgid_segments); item != NULL; item = wmem_list_frame_next(item)) {
            p_segment_info = wmem_list_frame_data(item);
            segment_type = p_segment_info->type;
            if (p_segment_info->rbytes < p_segment_info->length) {
                /* Not all bytes have been received for this request */
                return false;
            }
            /* At least one segment is done, check the rest */
            ret = true;
            message_size     += p_segment_info->length;
            reassembled_size += p_segment_info->rbytes;
        }
    }
    if (ret && segment_type == RDMA_READ_CHUNK) {
        /*
         * Make sure all bytes are added to the reassembly table. Since the
         * reassembly is done on the READ_RESPONSE_LAST, a read request could
         * happen after the last read response for the previous request, in
         * this case this will give a false positive so check the total size
         * of all chunks (all segments required for the message)
         */
        return (reassembled_size >= message_size);
    }
    return ret;
}

/*
 * Get the fragment head from the cache
 * Returns NULL if still missing fragments
 */
static fragment_head *get_fragment_head(packet_info *pinfo)
{
    return (fragment_head *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rpcordma, RPCRDMA_FRAG_HEAD);
}

/* Save the fragment head on the proto data cache */
static void set_fragment_head(fragment_head *fd_head, packet_info *pinfo)
{
    if (fd_head && fd_head != get_fragment_head(pinfo)) {
        /* Add the fragment head to the packet cache */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_rpcordma, RPCRDMA_FRAG_HEAD, fd_head);
    }
}

/*
 * Get the fragment head for the current frame
 * Returns non-NULL if this frame is a fragment
 */
static fragment_head *get_reassembled_id(packet_info *pinfo)
{
    uint32_t *p_msgid;
    p_msgid = (uint32_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rpcordma, RPCRDMA_MSG_ID);
    if (p_msgid) {
        return fragment_get_reassembled_id(&rpcordma_reassembly_table, pinfo, *p_msgid);
    }
    return NULL;
}

/* Get the reassembled data, returns NULL if still missing fragments */
static tvbuff_t *get_reassembled_data(tvbuff_t *tvb, unsigned offset,
        packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *new_tvb = NULL;
    fragment_head *fd_head;

    if (g_needs_reassembly) {
        /* Get fragment head for fragment to display "Reassembled in" message */
        fd_head = get_reassembled_id(pinfo);
        if (!fd_head) {
            /* Get fragment head on frame where reassembly has been completed */
            fd_head = get_fragment_head(pinfo);
        }
        if (fd_head) {
            new_tvb = process_reassembled_data(tvb, offset, pinfo,
                "Reassembled RPCoRDMA Message", fd_head, &rpcordma_frag_items,
                NULL, tree);
            /* Call process_reassembled_data just once per frame */
            g_needs_reassembly = false;
        }
    }
    return new_tvb;
}

/*
 * Complete reassembly:
 * 1. If p_rdma_conv_info is NULL then complete reassembly.
 * 2. If p_rdma_conv_info is non-NULL then complete reassembly only if
 *    reassembly is really done by making sure all data has been received.
 */
static fragment_head *end_reassembly(uint32_t msgid,
        rdma_conv_info_t *p_rdma_conv_info, packet_info *pinfo)
{
    fragment_head *fd_head = NULL;

    /* Check if reassembly is really done only if p_rdma_conv_info is non-NULL */
    if (!p_rdma_conv_info || is_reassembly_done(p_rdma_conv_info, msgid)) {
        /* Complete the reassembly */
        fd_head = fragment_end_seq_next(&rpcordma_reassembly_table, pinfo, msgid, NULL);
        set_fragment_head(fd_head, pinfo);
    }
    return fd_head;
}

/*
 * Add a fragment to the reassembly table and return the reassembled data
 * if all fragments have been added
 */
static tvbuff_t *add_fragment(tvbuff_t *tvb, int offset, uint32_t msgid,
        int32_t msg_num, bool more_frags, rdma_conv_info_t *p_rdma_conv_info,
        packet_info *pinfo, proto_tree *tree)
{
    uint8_t pad_count = 0;
    uint32_t nbytes, frag_size;
    tvbuff_t *new_tvb = NULL;
    fragment_head *fd_head = NULL;
    uint32_t *p_msgid;

    if (gp_infiniband_info) {
        pad_count = gp_infiniband_info->pad_count;
    }

    /* Get fragment head if reassembly has been completed */
    fd_head = get_fragment_head(pinfo);
    if (fd_head == NULL) {
        /* Reassembly has not been completed yet */
        if (msg_num >= 0) {
            nbytes = tvb_captured_length_remaining(tvb, offset);
            if (nbytes > 0 || more_frags) {
                /* Add message fragment to reassembly table */
                if (pad_count > 0 && p_rdma_conv_info && \
                    p_rdma_conv_info->segment_info != NULL && \
                    p_rdma_conv_info->segment_info->type == RDMA_READ_CHUNK && \
                    p_rdma_conv_info->segment_info->xdrpos == 0) {
                    /* Do not include any padding bytes inserted by Infiniband
                     * layer if this is a PZRC (Position-Zero Read Chunk) since
                     * payload stream already has any necessary padding bytes */
                    frag_size = tvb_reported_length_remaining(tvb, offset) - pad_count;
                    if (frag_size < nbytes) {
                        nbytes = frag_size;
                    }
                }
                fd_head = fragment_add_seq_check(&rpcordma_reassembly_table,
                                                 tvb, offset, pinfo,
                                                 msgid, NULL, (uint32_t)msg_num,
                                                 nbytes, more_frags);
                /* Save the msgid in the proto data cache */
                p_msgid = wmem_new(wmem_file_scope(), uint32_t);
                *p_msgid = msgid;
                p_add_proto_data(wmem_file_scope(), pinfo, proto_rpcordma, RPCRDMA_MSG_ID, p_msgid);
            } else if (p_rdma_conv_info) {
                /* No data in this frame, so just complete the reassembly
                 * if reassembly is really done */
                fd_head = end_reassembly(msgid, p_rdma_conv_info, pinfo);
            }
            /* Add the fragment head to the packet cache */
            set_fragment_head(fd_head, pinfo);
        }
    }

    /* Get reassembled data */
    new_tvb = get_reassembled_data(tvb, 0, pinfo, tree);

    return new_tvb;
}

/*
 * Add an Infiniband fragment to the reassembly table and return the
 * reassembled data if all fragments have been added
 */
static tvbuff_t *add_ib_fragment(tvbuff_t *tvb,
        rdma_conv_info_t *p_rdma_conv_info, bool only_frag,
        packet_info *pinfo, proto_tree *tree)
{
    uint32_t msgid, msg_num, msg_off;
    uint32_t nfrags, psndelta = 0;
    tvbuff_t *new_tvb = NULL;
    ib_request_t   *p_ib_request;
    segment_info_t *p_segment_info = NULL;
    uint32_t iosize = p_rdma_conv_info->iosize;
    uint64_t va_offset;

    if (pinfo->fd->visited) {
        return get_reassembled_data(tvb, 0, pinfo, tree);
    } else if (only_frag) {
        /* Write Only: no request so use segment info */
        p_segment_info = find_segment_info(p_rdma_conv_info, gp_infiniband_info->reth_remote_key, gp_infiniband_info->reth_remote_address);
        va_offset = gp_infiniband_info->reth_remote_address;
    } else {
        p_rdma_conv_info->segment_info = NULL;
        /* Get correct request */
        p_ib_request = (ib_request_t *)wmem_tree_lookup32_le(p_rdma_conv_info->psn_list, gp_infiniband_info->packet_seq_num);
        if (p_ib_request) {
            psndelta = gp_infiniband_info->packet_seq_num - p_ib_request->psn;
            nfrags = NFRAGS((p_ib_request->length), iosize);
            if (psndelta < nfrags) {
                /* This is the correct request */
                p_segment_info = p_ib_request->segment;
                /* Make message number relative to request */
                va_offset = p_ib_request->offset;
            }
        }
    }
    if (p_segment_info) {
        p_rdma_conv_info->segment_info = p_segment_info;
        p_segment_info->rbytes += tvb_reported_length(tvb);
        /* Make message number relative to request or segment(write only) */
        msg_off = (uint32_t)NFRAGS((va_offset - p_segment_info->offset), iosize) + psndelta;
        msgid   = p_segment_info->msgid;
        msg_num = p_segment_info->msgno + 1 + msg_off;
        new_tvb = add_fragment(tvb, 0, msgid, msg_num, true, p_rdma_conv_info, pinfo, tree);
    }
    return new_tvb;
}

/*
 * Add padding bytes as a separate fragment when last fragment's data is not
 * on a four-byte boundary. The MPA layer removes the padding bytes from all
 * iWarp Reads/Writes. The iWarp Send messages are padded correctly.
 */
static void add_iwarp_padding(tvbuff_t *tvb, int offset,
        uint32_t msgid, uint32_t msgno, packet_info *pinfo)
{
    char *pbuf;
    tvbuff_t *pad_tvb;
    /* Size of payload data for current iWarp Read/Write */
    uint32_t bsize = tvb_reported_length_remaining(tvb, offset);
    /* Number of padding bytes needed */
    uint32_t padding = (4 - (bsize%4)) % 4;

    if (padding > 0) {
        /* Allocate buffer for the number of padding bytes that will be added */
        pbuf = (char *)wmem_alloc(pinfo->pool, padding);
        memset(pbuf, 0, padding);
        /* Create tvb buffer */
        pad_tvb = tvb_new_real_data(pbuf, padding, padding);
        /* Add padding fragment to the reassembly table */
        fragment_add_seq_check(&rpcordma_reassembly_table, pad_tvb, 0,
                pinfo, msgid, NULL, msgno, padding, true);
    }
}

/*
 * Add an iWarp fragment to the reassembly table and return the
 * reassembled data if all fragments have been added
 */
static tvbuff_t *add_iwarp_fragment(tvbuff_t *tvb,
        rdma_conv_info_t *p_rdma_conv_info, packet_info *pinfo,
        proto_tree *tree)
{
    uint32_t sbytes = 0; /* Total bytes for all segments in current reassembly */
    uint32_t rbytes = 0; /* Total bytes received so far */
    uint32_t msgno;      /* Message number for this fragment */
    uint32_t steering_tag;
    uint64_t tagged_offset;
    bool more_frags = true;
    wmem_list_t *msgid_segments;
    wmem_list_frame_t *item;
    segment_info_t *p_seginfo;
    segment_info_t *p_segment_info;
    rdmap_request_t *p_read_request = NULL;
    tvbuff_t *new_tvb = NULL;

    if (pinfo->fd->visited) {
        return get_reassembled_data(tvb, 0, pinfo, tree);
    } else if (gp_rdmap_info->opcode == RDMA_READ_RESPONSE) {
        /* Read fragment: map sink -> source using the request info */
        p_read_request = wmem_tree_lookup32(p_rdma_conv_info->request_list, gp_rdmap_info->steering_tag);
        if (p_read_request) {
            /* Map Read Response STag to segment STag */
            steering_tag = p_read_request->source_stag;
            /* Map Read Response offset to segment offset */
            tagged_offset = gp_rdmap_info->tagged_offset - p_read_request->sink_toffset + p_read_request->source_toffset;
        } else {
            return NULL;
        }
    } else {
        /* Write fragment: no need for mapping, use steering tag and offset */
        steering_tag  = gp_rdmap_info->steering_tag;
        tagged_offset = gp_rdmap_info->tagged_offset;
    }

    p_rdma_conv_info->segment_info = NULL;
    p_segment_info = find_segment_info(p_rdma_conv_info, steering_tag, tagged_offset);
    if (p_segment_info) {
        /* Message number is relative with respect to chunk, adding
         * one since msgno = 0 is reserved for the reduced message */
        msgno = (uint32_t)(tagged_offset - p_segment_info->offset) + p_segment_info->msgno + 1;
        p_rdma_conv_info->segment_info = p_segment_info;

        /* Include this fragment's data */
        p_segment_info->rbytes += tvb_captured_length_remaining(tvb, 0);

        if (gp_rdmap_info->last_flag) {
            /* This is a last fragment so go through all segments
             * to calculate sbytes and rbytes */
            msgid_segments = wmem_tree_lookup32(p_rdma_conv_info->msgid_list, p_segment_info->msgid);
            if (msgid_segments) {
                for (item = wmem_list_head(msgid_segments); item != NULL; item = wmem_list_frame_next(item)) {
                    p_seginfo = wmem_list_frame_data(item);
                    sbytes += p_seginfo->length;
                    rbytes += p_seginfo->rbytes;
                }
            }
            if (p_read_request && rbytes == sbytes) {
                /* Complete read chunk reassembly since all fragments
                 * have been received */
                more_frags = false;
            }
        }
        new_tvb = add_fragment(tvb, 0, p_segment_info->msgid, msgno, true, p_rdma_conv_info, pinfo, tree);
        if ((!new_tvb && !more_frags) || (gp_rdmap_info->last_flag && !p_read_request && rbytes == sbytes)) {
            /* This is the very last fragment, include any padding if needed */
            add_iwarp_padding(tvb, 0, p_segment_info->msgid, msgno+1, pinfo);
        }
        if (!new_tvb && !more_frags) {
            /* Complete reassembly */
            end_reassembly(p_segment_info->msgid, p_rdma_conv_info, pinfo);
            new_tvb = get_reassembled_data(tvb, 0, pinfo, tree);
        }
    }
    return new_tvb;
}

static unsigned get_read_list_size(tvbuff_t *tvb, unsigned max_offset, unsigned offset)
{
    uint32_t value_follows;
    unsigned start = offset;

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

static unsigned get_read_list_chunk_count(tvbuff_t *tvb, unsigned offset)
{
    uint32_t value_follows;
    unsigned num_chunks;

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

static unsigned get_write_chunk_size(tvbuff_t *tvb, unsigned offset)
{
    unsigned segment_count;
    unsigned max_count = (unsigned)tvb_reported_length_remaining(tvb, offset + 4) / 16;

    segment_count = tvb_get_ntohl(tvb, offset);
    if (segment_count > max_count) {
        /* XXX We should throw an exception here. */
        segment_count = max_count;
    }
    return 4 + (segment_count * 16);
}

static unsigned get_write_list_size(tvbuff_t *tvb, unsigned max_offset, unsigned offset)
{
    uint32_t value_follows;
    unsigned chunk_size, start = offset;

    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (offset > max_offset)
            return 0;
        if (!value_follows)
            break;

        chunk_size = get_write_chunk_size(tvb, offset);
        if (max_offset - offset < chunk_size)
            return 0;
        offset += chunk_size;
    }

    return offset - start;
}

static unsigned get_write_list_chunk_count(tvbuff_t *tvb, unsigned offset)
{
    uint32_t value_follows;
    unsigned num_chunks, chunk_size;

    num_chunks = 0;
    while (1) {
        value_follows = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (!value_follows)
            break;

        num_chunks++;
        chunk_size = get_write_chunk_size(tvb, offset);
        if (chunk_size == 0)
            break;
        offset += chunk_size;
    }

   return num_chunks;
}

static unsigned get_reply_chunk_size(tvbuff_t *tvb, unsigned max_offset, unsigned offset)
{
    uint32_t value_follows;
    unsigned start = offset;

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

static unsigned get_reply_chunk_count(tvbuff_t *tvb, unsigned offset)
{
    uint32_t value_follows;

    value_follows = tvb_get_ntohl(tvb, offset);
    return value_follows ? 1 : 0;
}

/*
 * The RDMA read list is given as a list of read segments in the protocol.
 * In order to create a list of chunks, all segments having the same XDR
 * position will be part of an RDMA read chunk.
 */
static void add_rdma_read_segment(wmem_array_t *p_read_list,
        rdma_segment_t *p_rdma_segment)
{
    unsigned i;
    rdma_segment_t *p_segment;
    rdma_chunk_t *p_rdma_chunk = NULL;

    /* Look for correct chunk where to insert the segment */
    for (i=0; i<wmem_array_get_count(p_read_list); i++) {
        p_rdma_chunk = (rdma_chunk_t *)wmem_array_index(p_read_list, i);
        p_segment = (rdma_segment_t *)wmem_array_index(p_rdma_chunk->segments, 0);
        if (p_segment->xdrpos == p_rdma_segment->xdrpos) {
            /* Found correct read chunk */
            break;
        } else {
            p_rdma_chunk = NULL;
        }
    }

    if (p_rdma_chunk == NULL) {
        /* No read chunk was found so initialize a new chunk */
        p_rdma_chunk = wmem_new(wmem_packet_scope(), rdma_chunk_t);
        p_rdma_chunk->type = RDMA_READ_CHUNK;
        p_rdma_chunk->segments = wmem_array_new(wmem_packet_scope(), sizeof(rdma_segment_t));
        /* Add read chunk to the RDMA read list */
        wmem_array_append(p_read_list, p_rdma_chunk, 1);
    }

    /* Add segment to the read chunk */
    wmem_array_append(p_rdma_chunk->segments, p_rdma_segment, 1);
}

static unsigned dissect_rpcrdma_read_chunk(proto_tree *read_list,
        tvbuff_t *tvb, unsigned offset, wmem_array_t *p_read_list)
{
    proto_tree *read_chunk;
    uint32_t position;
    rdma_segment_t *p_rdma_segment;

    /* Initialize read segment */
    p_rdma_segment = wmem_new(wmem_packet_scope(), rdma_segment_t);

    position = tvb_get_ntohl(tvb, offset);
    p_rdma_segment->xdrpos = position;
    read_chunk = proto_tree_add_subtree_format(read_list, tvb,
                        offset, 20, ett_rpcordma_read_chunk, NULL,
                        "Read chunk: (position %u)", position);

    proto_tree_add_item(read_chunk, hf_rpcordma_position, tvb,
                offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(read_chunk, hf_rpcordma_rdma_handle, tvb,
                offset, 4, ENC_BIG_ENDIAN, &p_rdma_segment->handle);
    offset += 4;
    proto_tree_add_item_ret_uint(read_chunk, hf_rpcordma_rdma_length, tvb,
                offset, 4, ENC_BIG_ENDIAN, &p_rdma_segment->length);
    offset += 4;
    proto_tree_add_item_ret_uint64(read_chunk, hf_rpcordma_rdma_offset, tvb,
                offset, 8, ENC_BIG_ENDIAN, &p_rdma_segment->offset);

    add_rdma_read_segment(p_read_list, p_rdma_segment);
    return offset + 8;
}

static unsigned dissect_rpcrdma_read_list(tvbuff_t *tvb, unsigned offset,
        proto_tree *tree, rdma_lists_t *rdma_lists)
{
    unsigned chunk_count, start = offset;
    proto_tree *read_list;
    uint32_t value_follows;
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

        if (rdma_lists->p_read_list == NULL) {
            /* Initialize RDMA read list */
            rdma_lists->p_read_list = wmem_array_new(wmem_packet_scope(), sizeof(rdma_chunk_t));
        }
        offset = dissect_rpcrdma_read_chunk(read_list, tvb, offset, rdma_lists->p_read_list);
    }

    proto_item_set_len(item, offset - start);
    return offset;
}

static unsigned dissect_rpcrdma_segment(proto_tree *write_chunk, tvbuff_t *tvb,
        unsigned offset, uint32_t i, wmem_array_t *p_segments)
{
    proto_tree *segment;
    rdma_segment_t *p_rdma_segment;

    /* Initialize write segment */
    p_rdma_segment = wmem_new(wmem_packet_scope(), rdma_segment_t);
    p_rdma_segment->xdrpos = 0; /* Not used in write segments */

    segment = proto_tree_add_subtree_format(write_chunk, tvb,
                    offset, 16, ett_rpcordma_segment, NULL,
                    "RDMA segment %u", i);

    proto_tree_add_item_ret_uint(segment, hf_rpcordma_rdma_handle, tvb,
                offset, 4, ENC_BIG_ENDIAN, &p_rdma_segment->handle);
    offset += 4;
    proto_tree_add_item_ret_uint(segment, hf_rpcordma_rdma_length, tvb,
                offset, 4, ENC_BIG_ENDIAN, &p_rdma_segment->length);
    offset += 4;
    proto_tree_add_item_ret_uint64(segment, hf_rpcordma_rdma_offset, tvb,
                offset, 8, ENC_BIG_ENDIAN, &p_rdma_segment->offset);

    /* Add segment to the write chunk */
    wmem_array_append(p_segments, p_rdma_segment, 1);
    return offset + 8;
}

static unsigned dissect_rpcrdma_write_chunk(proto_tree *write_list, tvbuff_t *tvb,
        unsigned offset, chunk_type_t chunk_type, wmem_array_t *p_rdma_list)
{
    uint32_t i, segment_count;
    proto_tree *write_chunk;
    unsigned selection_size;
    rdma_chunk_t *p_rdma_chunk;

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

    /* Initialize write chunk */
    p_rdma_chunk = wmem_new(wmem_packet_scope(), rdma_chunk_t);
    p_rdma_chunk->type = chunk_type;
    p_rdma_chunk->segments = wmem_array_new(wmem_packet_scope(), sizeof(rdma_segment_t));

    /* Add chunk to the write/reply list */
    wmem_array_append(p_rdma_list, p_rdma_chunk, 1);

    for (i = 0; i < segment_count; ++i)
        offset = dissect_rpcrdma_segment(write_chunk, tvb, offset, i, p_rdma_chunk->segments);

    return offset;
}

static unsigned dissect_rpcrdma_write_list(tvbuff_t *tvb, unsigned offset,
        proto_tree *tree, rdma_lists_t *rdma_lists)
{
    unsigned chunk_count, start = offset;
    proto_tree *write_list;
    uint32_t value_follows;
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

        if (rdma_lists->p_write_list == NULL) {
            /* Initialize RDMA write list */
            rdma_lists->p_write_list = wmem_array_new(wmem_packet_scope(), sizeof(rdma_chunk_t));
        }
        offset = dissect_rpcrdma_write_chunk(write_list, tvb, offset, RDMA_WRITE_CHUNK, rdma_lists->p_write_list);
    }

    proto_item_set_len(item, offset - start);
    return offset;
}

static unsigned dissect_rpcrdma_reply_chunk(tvbuff_t *tvb, unsigned offset,
        proto_tree *tree, rdma_lists_t *rdma_lists)
{
    uint32_t chunk_count, start = offset;
    proto_tree *reply_chunk;
    uint32_t value_follows;
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

    /* Initialize RDMA reply list */
    rdma_lists->p_reply_list = wmem_array_new(wmem_packet_scope(), sizeof(rdma_chunk_t));

    offset = dissect_rpcrdma_write_chunk(reply_chunk, tvb, offset, RDMA_REPLY_CHUNK, rdma_lists->p_reply_list);
    proto_item_set_len(item, offset - start);
    return offset;
}

static unsigned parse_rdma_header(tvbuff_t *tvb, unsigned offset, proto_tree *tree,
        rdma_lists_t *rdma_lists)
{
    offset = dissect_rpcrdma_read_list(tvb, offset, tree, rdma_lists);
    offset = dissect_rpcrdma_write_list(tvb, offset, tree, rdma_lists);
    return dissect_rpcrdma_reply_chunk(tvb, offset, tree, rdma_lists);
}

static unsigned get_chunk_lists_size(tvbuff_t *tvb, unsigned max_offset, unsigned offset)
{
    unsigned size, start = offset;

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
 * Return the total number of bytes for the given RDMA chunk list
 * Returns 0 when called on an RPC call message because that is where the
 * segments are set up. On an RPC reply message the total number of bytes
 * added to the reassembly table is returned. This is only valid for RDMA
 * writes since there is no RPC-over-RDMA layer for RDMA reads on an RPC reply.
 */
static unsigned
get_rdma_list_size(wmem_array_t *p_list, packet_info *pinfo)
{
    unsigned i, j, size = 0;
    uint32_t *p_size;
    rdma_chunk_t *p_rdma_chunk;
    rdma_segment_t *p_rdma_segment;
    segment_info_t *p_segment_info;
    rdma_conv_info_t *p_rdma_conv_info;

    if (p_list) {
        /* Get size from cache */
        p_size = (uint32_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rpcordma, RPCRDMA_WRITE_SIZE);
        if (p_size) {
            return *p_size;
        }
        /* Get conversation state */
        p_rdma_conv_info = get_rdma_conv_info(pinfo);
        for (i=0; i<wmem_array_get_count(p_list); i++) {
            p_rdma_chunk = (rdma_chunk_t *)wmem_array_index(p_list, i);
            for (j=0; j<wmem_array_get_count(p_rdma_chunk->segments); j++) {
                p_rdma_segment = (rdma_segment_t *)wmem_array_index(p_rdma_chunk->segments, j);
                p_segment_info = find_segment_info(p_rdma_conv_info, p_rdma_segment->handle, p_rdma_segment->offset);
                if (p_segment_info) {
                    size += p_segment_info->rbytes;
                }
            }
        }
    }
    if (size > 0) {
        /* Save size on the proto data cache */
        p_size = wmem_new(wmem_file_scope(), uint32_t);
        *p_size = size;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_rpcordma, RPCRDMA_WRITE_SIZE, p_size);
    }
    return size;
}

/* Process an RDMA chunk list (read, write or reply) */
static tvbuff_t *
process_rdma_list(tvbuff_t *tvb, unsigned offset, wmem_array_t *p_list,
        packet_info *pinfo, proto_tree *tree)
{
    unsigned i, j, size;
    uint32_t msgid   = 0;
    uint32_t xdrpos  = 0;
    uint32_t xdrprev = 0;
    uint32_t lenprev = 0;
    uint32_t msg_num = 0;
    uint32_t msg_off = 0;
    unsigned *p_offset = NULL;
    tvbuff_t *tmp_tvb;
    tvbuff_t *new_tvb = NULL;
    fragment_head *fd_head;
    rdma_segment_t *p_rdma_segment;
    rdma_chunk_t *p_rdma_chunk = NULL;
    segment_info_t *p_segment_info = NULL;
    bool setup = false;
    wmem_list_t *msgid_segments = NULL;
    rdma_conv_info_t *p_rdma_conv_info;

    if (p_list) {
        /* Get conversation state */
        p_rdma_conv_info = get_rdma_conv_info(pinfo);

        for (i=0; i<wmem_array_get_count(p_list); i++) {
            p_rdma_chunk = (rdma_chunk_t *)wmem_array_index(p_list, i);
            p_rdma_chunk->length = 0;
            p_offset = NULL;

            if (p_rdma_chunk->type == RDMA_WRITE_CHUNK) {
                /* Process any write chunk offsets from reduced message */
                if (gp_rdma_write_offsets && wmem_array_get_count(gp_rdma_write_offsets) == wmem_array_get_count(p_list)) {
                    p_offset = (unsigned *)wmem_array_index(gp_rdma_write_offsets, i);
                    /* Convert reduced offset to xdr position */
                    xdrpos = tvb_reported_length_remaining(tvb, offset) - *p_offset + msg_off;
                }
            }

            for (j=0; j<wmem_array_get_count(p_rdma_chunk->segments); j++) {
                p_rdma_segment = (rdma_segment_t *)wmem_array_index(p_rdma_chunk->segments, j);
                if (p_rdma_chunk->type == RDMA_READ_CHUNK) {
                    xdrpos = p_rdma_segment->xdrpos;
                }
                p_segment_info = find_segment_info(p_rdma_conv_info, p_rdma_segment->handle, p_rdma_segment->offset);
                if (p_segment_info) {
                    /* This must be the reply, change segment size */
                    p_segment_info->length = p_rdma_segment->length;
                } else {
                    if (msgid == 0) {
                        /* Create new message ID */
                        msgid = get_msg_id();
                        msgid_segments = wmem_list_new(wmem_file_scope());
                        wmem_tree_insert32(p_rdma_conv_info->msgid_list, msgid, msgid_segments);
                    }
                    /* Create new segment info */
                    p_segment_info = wmem_new(wmem_file_scope(), segment_info_t);
                    p_segment_info->handle = p_rdma_segment->handle;
                    p_segment_info->length = p_rdma_segment->length;
                    p_segment_info->offset = p_rdma_segment->offset;
                    p_segment_info->msgid  = msgid;
                    p_segment_info->msgno  = p_rdma_chunk->length;
                    p_segment_info->type   = p_rdma_chunk->type;
                    p_segment_info->xdrpos = xdrpos;
                    p_segment_info->rbytes = 0;
                    /* Add segment to the list of segments */
                    wmem_tree_insert32(p_rdma_conv_info->segment_list, p_rdma_segment->handle, p_segment_info);
                    wmem_list_append(msgid_segments, p_segment_info);
                    setup = true;
                }
                /* Calculate the number of bytes for the whole chunk */
                p_rdma_chunk->length += p_rdma_segment->length;
            }

            /* Add chunk length to correctly calculate xdrpos */
            msg_off += p_rdma_chunk->length;

            /*
             * Add reduced data before each chunk data for either the
             * read chunk or write chunk (p_offset != NULL)
             */
            if (p_rdma_chunk->type == RDMA_READ_CHUNK || p_offset) {
                /*
                 * Payload data in this frame (e.g., two chunks)
                 * where chunk data is sent separately using RDMA:
                 * +----------------+----------------+----------------+
                 * |    xdrdata1    |    xdrdata2    |    xdrdata3    |
                 * +----------------+----------------+----------------+
                 *    chunk data1 --^  chunk data2 --^
                 *
                 * Reassembled message should look like the following in which
                 * the xdrpos specifies where the chunk data must be inserted.
                 * The xdrpos is relative to the reassembled message and NOT
                 * relative to the reduced data (data in this frame):
                 * +----------+-------------+----------+-------------+----------+
                 * | xdrdata1 | chunk data1 | xdrdata2 | chunk data2 | xdrdata3 |
                 * +----------+-------------+----------+-------------+----------+
                 * xdrpos1 ---^              xdrpos2 --^
                 */

                /* Add data before the xdr position */
                size = xdrpos - xdrprev - lenprev;
                if (size > 0 && tvb_captured_length_remaining(tvb, offset) > 0 && p_segment_info) {
                    tmp_tvb = tvb_new_subset_length(tvb, offset, size);
                    add_fragment(tmp_tvb, 0, p_segment_info->msgid, msg_num, true, p_rdma_conv_info, pinfo, tree);
                    /* Message number for fragment after read/write chunk */
                    msg_num += p_rdma_chunk->length;
                    /* Save rest of data for next fragment */
                    tvb = tvb_new_subset_remaining(tvb, offset+size);
                    offset = 0;
                }

                xdrprev = xdrpos;
                lenprev = p_rdma_chunk->length;
            }
        }

        fd_head = get_fragment_head(pinfo);
        if (fd_head == NULL) {
            if (p_segment_info == NULL) {
                return NULL;
            } else if (p_rdma_chunk->type == RDMA_REPLY_CHUNK && !setup &&
                    !pinfo->fd->visited && p_rdma_chunk->length > 0) {
                /* Only reassemble if reply chunk size is non-zero to avoid
                 * reassembly of a single fragment. The RPC-over-RDMA reply
                 * has no data when the reply chunk size is non-zero but it
                 * needs to reassemble all fragments (more_frags = false)
                 * in this frame. On the other hand when the reply chunk
                 * size is zero, the whole message is given in this frame
                 * therefore there is no need to reassemble. */
                new_tvb = add_fragment(tvb, offset, p_segment_info->msgid, 0, false, p_rdma_conv_info, pinfo, tree);
            } else if (p_rdma_chunk->type == RDMA_READ_CHUNK && tvb_captured_length_remaining(tvb, offset) > 0) {
                /* Add data after the last read chunk */
                add_fragment(tvb, offset, p_segment_info->msgid, msg_num, true, p_rdma_conv_info, pinfo, tree);
            } else if (p_offset && tvb_reported_length_remaining(tvb, offset) > 0) {
                /* Add data after the last write chunk */
                new_tvb = add_fragment(tvb, offset, p_segment_info->msgid, msg_num, true, p_rdma_conv_info, pinfo, tree);
            }
        }
    }

    return new_tvb;
}

/* Process all RDMA chunk lists (read, write and reply) */
static tvbuff_t *
process_rdma_lists(tvbuff_t *tvb, unsigned offset, rdma_lists_t *rdma_lists,
        packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *new_tvb;
    tvbuff_t *ret_tvb;

    new_tvb = get_reassembled_data(tvb, offset, pinfo, tree);
    if (new_tvb) {
        /* Reassembled message has already been cached */
        return new_tvb;
    }

    /*
     * Reassembly is not done here, process the rdma list to set up the
     * expected read chunks and their respective segments
     * Reassembly is done on the last read response
     * - Used for a large RPC call which has at least one large opaque,
     *   e.g., NFS WRITE
     * - The RPC call packet is used only to set up the RDMA read chunk list.
     *   It also has the reduced message data which includes the first fragment
     *   (XDR data up to and including the opaque length), but it could also
     *   have fragments between each read chunk and the last fragment after
     *   the last read chunk data. The reduced message is then broken down
     *   into fragments and inserted into the reassembly table.
     * - The opaque data is transferred via RDMA reads, once all fragments are
     *   accounted for they are reassembled and the whole RPC call is dissected
     *   in the last read response -- there is no RPCoRDMA layer
     *
     * - Packet sent order, the reduced RPC call is sent first, then the RDMA
     *   reads, e.g., showing only for a single chunk:
     *   +----------------+-------------+-----------+-----------+-----+-----------+
     *   | WRITE call XDR | opaque size |  GETATTR  | RDMA read | ... | RDMA read |
     *   +----------------+-------------+-----------+-----------+-----+-----------+
     *   |<-------------- First frame ------------->|<-------- chunk data ------->|
     *   Each RDMA read could be a single RDMA_READ_RESPONSE_ONLY or a series of
     *   RDMA_READ_RESPONSE_FIRST, RDMA_READ_RESPONSE_MIDDLE, ...,
     *   RDMA_READ_RESPONSE_LAST
     *
     * - NFS WRITE call, this is how it should be reassembled:
     *   +----------------+-------------+-----------+-----+-----------+-----------+
     *   | WRITE call XDR | opaque size | RDMA read | ... | RDMA read |  GETATTR  |
     *   +----------------+-------------+-----------+-----+-----------+-----------+
     *                                  |<--- opaque (chunk) data --->|
     */
    process_rdma_list(tvb, offset, rdma_lists->p_read_list, pinfo, tree);

    /*
     * Reassembly is done on the reply message (RDMA_NOMSG)
     * Process the rdma list on the call message to set up the reply
     * chunk and its respective segments expected by the reply
     * - Used for a large RPC reply which does not fit into a single SEND
     *   operation and does not have a single large opaque, e.g., NFS READDIR
     * - The RPC call packet is used only to set up the RDMA reply chunk list
     * - The whole RPC reply is transferred via RDMA writes
     * - The RPC reply packet has no data (RDMA_NOMSG) but fragments are
     *   reassembled and the whole RPC reply is dissected
     *
     * - Packet sent order, this is the whole XDR data for the RPC reply:
     *   +--------------------------+------------------+--------------------------+
     *   |        RDMA write        |       ...        |        RDMA write        |
     *   +--------------------------+------------------+--------------------------+
     *   Each RDMA write could be a single RDMA_WRITE_ONLY or a series of
     *   RDMA_WRITE_FIRST, RDMA_WRITE_MIDDLE, ..., RDMA_WRITE_LAST
     */
    new_tvb = process_rdma_list(tvb, offset, rdma_lists->p_reply_list, pinfo, tree);

    /*
     * Reassembly is done on the reply message (RDMA_MSG)
     * Process the rdma list on the call message to set up the write
     * chunks and their respective segments expected by the reply
     * - Used for a large RPC reply which has at least one large opaque,
     *   e.g., NFS READ
     * - The RPC call packet is used only to set up the RDMA write chunk list
     * - The opaque data is transferred via RDMA writes
     * - The RPC reply packet has the reduced message data which includes the
     *   first fragment (XDR data up to and including the opaque length), but
     *   it could also have fragments between each write chunk and the last
     *   fragment after the last write chunk data. The reduced message is
     *   then broken down into fragments and inserted into the reassembly table.
     *   Fragments are then reassembled and the whole RPC reply is dissected
     * - Packet sent order, the RDMA writes are sent first, then the reduced RPC
     *   reply, e.g., showing only for a single chunk:
     *   +------------+-----+------------+----------------+-------------+---------+
     *   | RDMA write | ... | RDMA write | READ reply XDR | opaque size | GETATTR |
     *   +------------+-----+------------+----------------+-------------+---------+
     *   |<-------- write chunk -------->|<------------- Last frame ------------->|
     *   Each RDMA write could be a single RDMA_WRITE_ONLY or a series of
     *   RDMA_WRITE_FIRST, RDMA_WRITE_MIDDLE, ..., RDMA_WRITE_LAST
     *
     * - NFS READ reply, this is how it should be reassembled:
     *   +----------------+-------------+------------+-----+------------+---------+
     *   | READ reply XDR | opaque size | RDMA write | ... | RDMA write | GETATTR |
     *   +----------------+-------------+------------+-----+------------+---------+
     *                                  |<---- opaque (chunk) data ---->|
     */
    ret_tvb = process_rdma_list(tvb, offset, rdma_lists->p_write_list, pinfo, tree);

    /*
     * Either the reply chunk or the write chunks should be reassembled here
     * but not both
     */
    new_tvb = (new_tvb && ret_tvb) ? NULL : (ret_tvb ? ret_tvb : new_tvb);

    return new_tvb;
}

/*
 * Add a fragment to the SEND reassembly table and return the reassembled data
 * if all fragments have been added
 */
static tvbuff_t *add_send_fragment(rdma_conv_info_t *p_rdma_conv_info,
        tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    uint32_t msgid = 0;
    int32_t msgno = -1;
    tvbuff_t *new_tvb = NULL;
    bool first_frag  = false;
    bool middle_frag = false;
    bool last_frag   = false;
    send_info_t *p_send_info = NULL;

    if (gp_infiniband_info) {
        first_frag  =  gp_infiniband_info->opCode == RC_SEND_FIRST;
        middle_frag =  gp_infiniband_info->opCode == RC_SEND_MIDDLE;
        last_frag   = (gp_infiniband_info->opCode == RC_SEND_LAST || \
                       gp_infiniband_info->opCode == RC_SEND_LAST_INVAL);
    } else if (gp_rdmap_info) {
        first_frag  = !gp_rdmap_info->last_flag && gp_rdmap_info->message_offset == 0;
        middle_frag = !gp_rdmap_info->last_flag && gp_rdmap_info->message_offset > 0;
        last_frag   =  gp_rdmap_info->last_flag && gp_rdmap_info->message_offset > 0;
    }

    if (!first_frag && !middle_frag && !last_frag) {
        /* Only one SEND fragment, no need to reassemble */
        return tvb;
    } else if (pinfo->fd->visited) {
        return get_reassembled_data(tvb, 0, pinfo, tree);
    } else if (first_frag) {
        /* Start of multi-SEND message */
        p_send_info = wmem_new(wmem_file_scope(), send_info_t);
        p_send_info->msgid = get_msg_id();
        p_send_info->rsize = 0;

        if (gp_infiniband_info) {
            /* Message numbers are relative with respect to current PSN */
            p_send_info->msgno = gp_infiniband_info->packet_seq_num;
            wmem_tree_insert32(p_rdma_conv_info->send_list, gp_infiniband_info->packet_seq_num, p_send_info);
        } else if (gp_rdmap_info) {
            /* Message numbers are given by the RDMAP offset -- msgno is not used */
            p_send_info->msgno = 0;
            wmem_tree_insert32(p_rdma_conv_info->msn_list, gp_rdmap_info->message_seq_num, p_send_info);
        }
    } else {
        /* SEND fragment, get the send reassembly info structure */
        if (gp_infiniband_info) {
            p_send_info = wmem_tree_lookup32_le(p_rdma_conv_info->send_list, gp_infiniband_info->packet_seq_num);
        } else if (gp_rdmap_info) {
            p_send_info = wmem_tree_lookup32(p_rdma_conv_info->msn_list, gp_rdmap_info->message_seq_num);
        }
    }
    if (p_send_info) {
        p_send_info->rsize += tvb_reported_length(tvb);
        msgid = p_send_info->msgid;
        if (gp_infiniband_info) {
            /* Message numbers are consecutive starting at zero */
            msgno = gp_infiniband_info->packet_seq_num - p_send_info->msgno;
        } else if (gp_rdmap_info) {
            /* Message numbers are given by the RDMAP offset */
            msgno = gp_rdmap_info->message_offset;
        }
    }
    if (msgid > 0 && msgno >= 0) {
        new_tvb = add_fragment(tvb, 0, msgid, msgno, !last_frag, p_rdma_conv_info, pinfo, tree);
        if (last_frag && !new_tvb && gp_rdmap_info) {
            /* Since message numbers are not consecutive for iWarp,
             * verify there are no missing fragments */
            if (p_send_info->rsize == msgno + tvb_reported_length(tvb)) {
                end_reassembly(msgid, NULL, pinfo);
                new_tvb = get_reassembled_data(tvb, 0, pinfo, tree);
            }
        }
    }
    if (new_tvb) {
        /* This is the last fragment, data has been reassembled
         * and ready to be dissected */
        return new_tvb;
    }
    return tvb;
}

/*
 * We need to differentiate between RPC messages inside RDMA and regular send messages.
 * In order to do that (as well as extra validation) we want to verify that for RDMA_MSG
 * and RDMA_MSGP types, RPC call or RPC reply header follows. We can do this by comparing
 * XID in RPC and RPCoRDMA headers.
 */
static bool
packet_is_rpcordma(tvbuff_t *tvb)
{
    unsigned size, len = tvb_reported_length(tvb);
    uint32_t xid_rpc;
    uint32_t xid = tvb_get_ntohl(tvb, 0);
    uint32_t msg_type = tvb_get_ntohl(tvb, 12);
    unsigned offset;

    if (len < MIN_RPCRDMA_HDR_SZ)
        return 0;

    switch (msg_type) {
    case RDMA_MSG:
        if (len < MIN_RPCRDMA_MSG_SZ)
            return false;
        offset = MIN_RPCRDMA_HDR_SZ;
        size = get_chunk_lists_size(tvb, len, offset);
        if (!size)
            return false;
        offset += size;

        if (offset + 4 > len)
            return false;
        xid_rpc = tvb_get_ntohl(tvb, offset);
        if (xid != xid_rpc)
            return false;
        break;

    case RDMA_MSGP:
        if (len < MIN_RPCRDMA_MSGP_SZ)
            return false;
        offset = MIN_RPCRDMA_HDR_SZ + 8;
        size = get_chunk_lists_size(tvb, len, offset);
        if (!size)
            return false;
        offset += size;

        if (offset + 4 > len)
            return false;
        xid_rpc = tvb_get_ntohl(tvb, offset);
        if (xid != xid_rpc)
            return false;
        break;

    case RDMA_NOMSG:
    case RDMA_DONE:
    case RDMA_ERROR:
        break;

    default:
        return false;
    }

    return true;
}

static int
dissect_rpcrdma(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t *volatile next_tvb;
    tvbuff_t *frag_tvb;
    proto_item *ti;
    proto_tree *rpcordma_tree;
    unsigned offset;
    uint32_t msg_type;
    uint32_t xid;
    uint32_t val;
    uint32_t *p_msgid;
    unsigned write_size;
    int save_visited;
    rdma_lists_t rdma_lists = { NULL, NULL, NULL };

    /* tvb_get_ntohl() should not throw an exception while checking if
       this is an rpcrdma packet */
    if (tvb_captured_length(tvb) < MIN_RPCRDMA_HDR_SZ)
        return 0;

    if (tvb_get_ntohl(tvb, 4) != 1)  /* vers */
        return 0;

    xid = tvb_get_ntohl(tvb, 0);
    msg_type = tvb_get_ntohl(tvb, 12);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RPCoRDMA");
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s XID 0x%x",
        val_to_str(msg_type, rpcordma_message_type, "Unknown (%d)"), xid);

    ti = proto_tree_add_item(tree, proto_rpcordma, tvb, 0, MIN_RPCRDMA_HDR_SZ, ENC_NA);

    rpcordma_tree = proto_item_add_subtree(ti, ett_rpcordma);

    offset = 0;
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
        offset = parse_rdma_header(tvb, offset, rpcordma_tree, &rdma_lists);

        proto_item_set_len(ti, offset);

        frag_tvb = get_reassembled_data(tvb, offset, pinfo, tree);
        if (frag_tvb) {
            /* Reassembled message has already been cached -- call upper dissector */
            return call_dissector(rpc_handler, frag_tvb, pinfo, tree);
        } else if (pinfo->fd->visited && !g_needs_reassembly && rdma_lists.p_read_list) {
            /* This frame has already been added as a read fragment */
            return 0;
        } else {
            next_tvb = tvb_new_subset_remaining(tvb, offset);

            /*
             * Get the total number of bytes for the write chunk list.
             * It returns 0 if there is no write chunk list, or this is an
             * RPC call (list has just been set up) or it is an RPC reply but
             * there is an error so the reply message has not been reduced.
             */
            write_size = get_rdma_list_size(rdma_lists.p_write_list, pinfo);

            if (write_size > 0 && !pinfo->fd->visited) {
                /* Initialize array of write chunk offsets */
                gp_rdma_write_offsets = wmem_array_new(wmem_packet_scope(), sizeof(int));
                register_frame_end_routine(pinfo, reset_write_offsets);
                TRY {
                    /*
                     * Call the upper layer dissector to get a list of offsets
                     * where message has been reduced.
                     * This is done on the first pass (visited = 0)
                     */
                    g_rpcrdma_reduced = true;
                    call_dissector(rpc_handler, next_tvb, pinfo, tree);
                }
                FINALLY {
                    /* Make sure to disable reduced data processing */
                    g_rpcrdma_reduced = false;
                }
                ENDTRY;
            } else if (write_size > 0 && pinfo->fd->visited) {
                /*
                 * Reassembly is done on the second pass (visited = 1)
                 * This is done because dissecting the upper layer(s) again
                 * causes the upper layer(s) to be displayed twice if it is
                 * done on the same pass.
                 */
                p_msgid = (uint32_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rpcordma, RPCRDMA_MSG_ID);
                if (p_msgid) {
                    /*
                     * All fragments were added during the first pass,
                     * reassembly just needs to be completed here
                     */
                    save_visited = pinfo->fd->visited;
                    pinfo->fd->visited = 0;
                    end_reassembly(*p_msgid, NULL, pinfo);
                    pinfo->fd->visited = save_visited;
                }
            }

            /*
             * If there is a write chunk list, process_rdma_lists will convert
             * the offsets returned by the upper layer into xdr positions
             * and break the current reduced message into separate fragments
             * and insert them into the reassembly table in the first pass.
             * On the second pass, the reassembly has just been done so
             * process_rdma_lists should only call process_reassembled_data
             * to get the reassembled data and call the dissector for the
             * upper layer with the reassembled message.
             */
            frag_tvb = process_rdma_lists(next_tvb, 0, &rdma_lists, pinfo, tree);
            gp_rdma_write_offsets = NULL;
            if (rdma_lists.p_read_list) {
                /*
                 * If there is a read chunk list, do not dissect upper layer
                 * just label rest of packet as "Data" since the reassembly
                 * will be done on the last read response.
                 */
                call_data_dissector(next_tvb, pinfo, tree);
                break;
            } else if (frag_tvb) {
                /* Replace current frame data with the reassembled data */
                next_tvb = frag_tvb;
            }
        }
        return call_dissector(rpc_handler, next_tvb, pinfo, tree);

    case RDMA_NOMSG:
        /* Parse rpc_rdma_header_nomsg */
        offset = parse_rdma_header(tvb, offset, rpcordma_tree, &rdma_lists);
        if (pinfo->fd->visited) {
            /* Reassembly was done on the first pass, so just get the reassembled data */
            next_tvb = get_reassembled_data(tvb, offset, pinfo, tree);
        } else {
            next_tvb = process_rdma_lists(tvb, offset, &rdma_lists, pinfo, tree);
        }
        if (next_tvb) {
            /*
             * Even though there is no data in this frame, reassembly for
             * the reply chunk is done in this frame so dissect upper layer
             */
            call_dissector(rpc_handler, next_tvb, pinfo, tree);
        }
        break;

    case RDMA_MSGP:
        /* Parse rpc_rdma_header_padded */
        proto_tree_add_item(rpcordma_tree, hf_rpcordma_rdma_align, tvb,
                    offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(rpcordma_tree, hf_rpcordma_rdma_thresh, tvb,
                    offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        offset = parse_rdma_header(tvb, offset, rpcordma_tree, &rdma_lists);

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

static bool
dissect_rpcrdma_ib_heur(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    tvbuff_t *new_tvb = NULL;
    bool more_frags = false;
    rdma_conv_info_t *p_rdma_conv_info;

    /* Initialize global variables for InfiniBand reassembly */
    g_rpcrdma_reduced  = false;
    g_needs_reassembly = true;
    gp_rdmap_info      = NULL;
    gp_infiniband_info = (struct infinibandinfo *)data;

    if (!gp_infiniband_info)
        return false;

    /* Get conversation state */
    p_rdma_conv_info = get_rdma_conv_info(pinfo);

    switch (gp_infiniband_info->opCode) {
    case RC_SEND_ONLY:
    case RC_SEND_ONLY_INVAL:
        break;
    case RC_SEND_FIRST:
    case RC_SEND_MIDDLE:
        add_send_fragment(p_rdma_conv_info, tvb, pinfo, tree);
        return false;
    case RC_SEND_LAST:
    case RC_SEND_LAST_INVAL:
        tvb = add_send_fragment(p_rdma_conv_info, tvb, pinfo, tree);
        break;
    case RC_RDMA_WRITE_ONLY:
    case RC_RDMA_WRITE_ONLY_IMM:
        set_max_iosize(p_rdma_conv_info, tvb_reported_length(tvb));
        add_ib_fragment(tvb, p_rdma_conv_info, true, pinfo, tree);
        return false;
    case RC_RDMA_WRITE_FIRST:
        set_max_iosize(p_rdma_conv_info, tvb_reported_length(tvb));
        add_request_info(p_rdma_conv_info, pinfo);
        /* fall through */
    case RC_RDMA_WRITE_MIDDLE:
    case RC_RDMA_WRITE_LAST:
    case RC_RDMA_WRITE_LAST_IMM:
        /* Add fragment to the reassembly table */
        add_ib_fragment(tvb, p_rdma_conv_info, false, pinfo, tree);
        /* Do not dissect here, dissection is done on RDMA_MSG or RDMA_NOMSG */
        return false;
    case RC_RDMA_READ_REQUEST:
        add_request_info(p_rdma_conv_info, pinfo);
        return false;
    case RC_RDMA_READ_RESPONSE_FIRST:
        set_max_iosize(p_rdma_conv_info, tvb_reported_length(tvb));
        /* fall through */
    case RC_RDMA_READ_RESPONSE_MIDDLE:
        more_frags = true;
        /* fall through */
    case RC_RDMA_READ_RESPONSE_LAST:
    case RC_RDMA_READ_RESPONSE_ONLY:
        /* Add fragment to the reassembly table */
        new_tvb = add_ib_fragment(tvb, p_rdma_conv_info, false, pinfo, tree);
        if (!new_tvb && !more_frags && p_rdma_conv_info->segment_info) {
            /*
             * Reassembled data has not been cached (new_tvb==NULL) yet,
             * so make sure reassembly is really done if more_frags==false,
             * (for the READ_RESPONSE_LAST or ONLY case).
             * Do not add any more data, just complete the reassembly
             */
            end_reassembly(p_rdma_conv_info->segment_info->msgid, p_rdma_conv_info, pinfo);
            new_tvb = get_reassembled_data(tvb, 0, pinfo, tree);
        }
        if (new_tvb) {
            /* This is the last fragment, data has been reassembled and ready to dissect */
            return call_dissector(rpc_handler, new_tvb, pinfo, tree);
        }
        return false;
    default:
        return false;
    }

    if (!packet_is_rpcordma(tvb))
        return false;
    dissect_rpcrdma(tvb, pinfo, tree, NULL);
    return true;
}

static bool
dissect_rpcrdma_iwarp_heur(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    tvbuff_t *new_tvb;
    rdma_conv_info_t *p_rdma_conv_info;
    rdmap_request_t  *p_read_request;

    /* Initialize global variables for iWarp reassembly */
    g_rpcrdma_reduced  = false;
    g_needs_reassembly = true;
    gp_infiniband_info = NULL;
    gp_rdmap_info = (rdmap_info_t *)data;

    if (!gp_rdmap_info)
        return false;

    /* Get conversation state */
    p_rdma_conv_info = get_rdma_conv_info(pinfo);

    switch (gp_rdmap_info->opcode) {
    case RDMA_SEND:
    case RDMA_SEND_INVALIDATE:
        tvb = add_send_fragment(p_rdma_conv_info, tvb, pinfo, tree);
        if (!gp_rdmap_info->last_flag) {
            /* This is a SEND fragment, do not dissect yet */
            return false;
        }
        break;
    case RDMA_WRITE:
        add_iwarp_fragment(tvb, p_rdma_conv_info, pinfo, tree);
        /* Do not dissect here, dissection is done on RDMA_MSG or RDMA_NOMSG */
        return false;
    case RDMA_READ_REQUEST:
        if (!pinfo->fd->visited && gp_rdmap_info->read_request) {
            p_read_request = wmem_new(wmem_file_scope(), rdmap_request_t);
            memcpy(p_read_request, gp_rdmap_info->read_request, sizeof(rdmap_request_t));
            wmem_tree_insert32(p_rdma_conv_info->request_list, gp_rdmap_info->read_request->sink_stag, p_read_request);
        }
        return false;
    case RDMA_READ_RESPONSE:
        new_tvb = add_iwarp_fragment(tvb, p_rdma_conv_info, pinfo, tree);
        if (new_tvb) {
            /* This is the last fragment, data has been reassembled and ready to dissect */
            return call_dissector(rpc_handler, new_tvb, pinfo, tree);
        }
        return false;
    default:
        return false;
    }

    if (!packet_is_rpcordma(tvb))
        return false;

    dissect_rpcrdma(tvb, pinfo, tree, NULL);
    return true;
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
        /* Fragment entries */
        { &hf_rpcordma_fragments,
          { "Reassembled RPCoRDMA fragments", "rpcordma.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        { &hf_rpcordma_fragment,
          { "RPCoRDMA fragment", "rpcordma.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        { &hf_rpcordma_fragment_overlap,
          { "Fragment overlap", "rpcordma.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        { &hf_rpcordma_fragment_overlap_conflicts,
          { "Fragment overlapping with conflicting data", "rpcordma.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        { &hf_rpcordma_fragment_multiple_tails,
          { "Multiple tail fragments found", "rpcordma.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        { &hf_rpcordma_fragment_too_long_fragment,
          { "Fragment too long", "rpcordma.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        { &hf_rpcordma_fragment_error,
          { "Defragmentation error", "rpcordma.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        { &hf_rpcordma_fragment_count,
          { "Fragment count", "rpcordma.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
        },
        { &hf_rpcordma_reassembled_in,
          { "Reassembled PDU in frame", "rpcordma.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        { &hf_rpcordma_reassembled_length,
          { "Reassembled RPCoRDMA length", "rpcordma.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
        },
        { &hf_rpcordma_reassembled_data,
          { "Reassembled RPCoRDMA data", "rpcordma.reassembled.data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_rpcordma,
        &ett_rpcordma_chunk,
        &ett_rpcordma_read_list,
        &ett_rpcordma_read_chunk,
        &ett_rpcordma_write_list,
        &ett_rpcordma_write_chunk,
        &ett_rpcordma_reply_chunk,
        &ett_rpcordma_segment,
        &ett_rpcordma_fragment,
        &ett_rpcordma_fragments,
    };

    proto_rpcordma = proto_register_protocol (
        "RPC over RDMA", /* name       */
        "RPCoRDMA",      /* short name */
        "rpcordma"       /* abbrev     */
        );

    proto_register_field_array(proto_rpcordma, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    reassembly_table_register(&rpcordma_reassembly_table, &addresses_ports_reassembly_table_functions);

    /* Register dissector handle */
    rpcordma_handle = register_dissector("rpcordma", dissect_rpcrdma, proto_rpcordma);

    /* Register preferences */
    rpcordma_module = prefs_register_protocol_obsolete(proto_rpcordma);

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
    dissector_add_for_decode_as("infiniband", rpcordma_handle);

    heur_dissector_add("iwarp_ddp_rdmap", dissect_rpcrdma_iwarp_heur, "RPC-over-RDMA on iWARP",
                        "rpcrdma_iwarp", proto_rpcordma, HEURISTIC_ENABLE);

    rpc_handler = find_dissector_add_dependency("rpc", proto_rpcordma);
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
