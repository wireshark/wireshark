/* packet-lnet.c
 * Routines for lnet dissection
 * Copyright (c) 2012, 2013, 2017 Intel Corporation.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * LNet - Lustre Networking
 *
 * A network abstraction layer for passing data at near wire-speed.
 * Supports RDMA where available and run across a variety of network hosts.
 *
 * http://doc.lustre.org/lustre_manual.xhtml#understandinglustrenetworking
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/proto_data.h>


#include "packet-tcp.h"
#include "packet-lnet.h"
VALUE_STRING_ARRAY2(portal_index);

void proto_reg_handoff_lnet(void);
void proto_register_lnet(void);


/* Initialize the protocol and registered fields */
static int proto_lnet = -1;

static int hf_lnet_ksm_type = -1;
static int hf_lnet_ksm_csum = -1;
static int hf_lnet_ksm_zc_req_cookie = -1;
static int hf_lnet_ksm_zc_ack_cookie = -1;

static int hf_lnet_ib_magic = -1;
static int hf_lnet_ib_version = -1;
static int hf_lnet_ib_type = -1;
static int hf_lnet_ib_credits = -1;
static int hf_lnet_ib_nob = -1;
static int hf_lnet_ib_csum = -1;
static int hf_lnet_ib_srcstamp = -1;
static int hf_lnet_ib_dststamp = -1;

static int hf_lnet_src_nid = -1;
static int hf_lnet_dest_nid = -1;

static int hf_lnet_nid_addr = -1;
static int hf_lnet_nid_lnet_type = -1;
static int hf_lnet_nid_interface = -1;

static int hf_lnet_dest_pid = -1;
static int hf_lnet_src_pid = -1;

static int hf_lnet_msg_type = -1;
static int hf_lnet_payload_length = -1;
static int hf_lnet_payload = -1;
static int hf_lnet_msg_filler = -1;

static int hf_dst_wmd_interface = -1;
static int hf_dst_wmd_object = -1;

static int hf_match_bits = -1;
static int hf_mlength = -1;

static int hf_hdr_data = -1;
static int hf_ptl_index = -1;
static int hf_offset = -1;

static int hf_src_offset = -1;
static int hf_sink_length = -1;

static int hf_hello_incarnation = -1;
static int hf_hello_type = -1;

static int hf_lnet_o2ib_connparam = -1;
static int hf_lnet_o2ib_connparam_qdepth = -1;
static int hf_lnet_o2ib_connparam_max_frags = -1;
static int hf_lnet_o2ib_connparam_max_size = -1;
static int hf_lnet_o2ib_cookie = -1;
static int hf_lnet_o2ib_src_cookie = -1;
static int hf_lnet_o2ib_dest_cookie = -1;
static int hf_lnet_o2ib_status = -1;

static int hf_lnet_rdma_desc = -1;
static int hf_lnet_rdma_desc_key = -1;
static int hf_lnet_rdma_desc_nfrags = -1;

static int hf_lnet_rdma_frag_size = -1;
static int hf_lnet_rdma_frag_addr = -1;

/* Initialize the subtree pointers */
static gint ett_lnet = -1;
static gint ett_lnet_nid = -1;
static gint ett_lnet_o2ib_connparams = -1;
static gint ett_lnet_rdma_desc = -1;
static gint ett_lnet_rdma_frag = -1;

static expert_field ei_lnet_buflen = EI_INIT;
static expert_field ei_lnet_type = EI_INIT;

#define LNET_TCP_PORT 988   /* Not IANA registered */

#define LNET_HEADER_LEN 52
#define LNET_PTL_INDEX_OFFSET_PUT (88 + extra_bytes)

#define EXTRA_IB_HEADER_SIZE 24

static dissector_table_t subdissector_table;

/********************************************************************\
 *
 * LNet Definitions
 *
 * NID : Network IDentifiyer
 * IP@PORT#
 * e.g. 192.168.1.1@tcp0 or 10.10.10.1@o2ib4
 *
\********************************************************************/

#define lndnames_VALUE_STRING_LIST(XXX) \
    XXX(QSWLND,         1)              \
    XXX(SOCKLND,        2)              \
    XXX(GMLND,          3)              \
    XXX(PTLLND,         4)              \
    XXX(O2IBLND,        5)              \
    XXX(CIBLND,         6)              \
    XXX(OPENIBLND,      7)              \
    XXX(IIBLND,         8)              \
    XXX(LOLND,          9)              \
    XXX(RALND,          10)             \
    XXX(VIBLND,         11)             \
    XXX(MXLND,          12)             \
    XXX(GNILND,         13)             \
    XXX(GNIIPLND,       14)             \
    XXX(PTL4LND,        15)

VALUE_STRING_ENUM2(lndnames);
VALUE_STRING_ARRAY2(lndnames);

/* These are the NID protocol names */
static const value_string lndprotos[] = {
    { QSWLND,         "elan" }, /* removed v2_7_50 */
    { SOCKLND,        "tcp" },
    { GMLND,          "gm" },   /* removed v2_0_0-rc1a-16-gc660aac */
    { PTLLND,         "ptl" },  /* removed v2_7_50 */
    { O2IBLND,        "o2ib" },
    { CIBLND,         "cib" },  /* removed v2_0_0-rc1a-175-gd2b8a0e */
    { OPENIBLND,      "openib" }, /* removed v2_0_0-rc1a-175-gd2b8a0e */
    { IIBLND,         "iib" },  /* removed v2_0_0-rc1a-175-gd2b8a0e */
    { LOLND,          "lo" },
    { RALND,          "ra" },   /* removed v2_7_50_0-34-g8be9e41 */
    { VIBLND,         "vib" },  /* removed v2_0_0-rc1a-175-gd2b8a0e */
    { MXLND,          "mx" },   /* removed v2_7_50_0-34-g8be9e41 */
    { GNILND,         "gni" },
    { GNIIPLND,       "gip" },
    { PTL4LND,        "ptlf" },
    { 0, NULL}
};

enum MSG_type {
    LNET_MSG_ACK = 0,
    LNET_MSG_PUT,
    LNET_MSG_GET,
    LNET_MSG_REPLY,
    LNET_MSG_HELLO,
};

static const value_string lnet_msg_type[] = {
    { LNET_MSG_ACK  , "ACK"},
    { LNET_MSG_PUT  , "PUT"},
    { LNET_MSG_GET  , "GET"},
    { LNET_MSG_REPLY, "REPLY"},
    { LNET_MSG_HELLO, "HELLO"},
    { 0, NULL}
};

/* PROTO MAGIC for LNDs */
#define LNET_PROTO_IB_MAGIC		0x0be91b91
#define LNET_PROTO_MAGIC		0x45726963 /* ! */
#define LNET_PROTO_PING_MAGIC		0x70696E67 /* 'ping' */
#define LNET_PROTO_ACCEPTOR_MAGIC	0xacce7100
#define LNET_PROTO_GNI_MAGIC		0xb00fbabe /* ask Kim */
#define LNET_PROTO_TCP_MAGIC		0xeebc0ded

static const value_string lnet_magic[] = {
    { LNET_PROTO_IB_MAGIC,              "IB_MAGIC" },
    { LNET_PROTO_MAGIC,                 "LNET_MAGIC" }, /* place holder */
    { LNET_PROTO_PING_MAGIC,            "PING_MAGIC" },
    { LNET_PROTO_ACCEPTOR_MAGIC,        "ACCEPTOR_MAGIC" },
    { LNET_PROTO_GNI_MAGIC,             "GNI_MAGIC" },
    { LNET_PROTO_TCP_MAGIC,             "TCP_MAGIC" },
    { 0, NULL }
};

/* SOCKLND constants. */
#define ksm_type_VALUE_STRING_LIST(XXX)         \
    XXX(KSOCK_MSG_NOOP, 0xc0)                   \
    XXX(KSOCK_MSG_LNET, 0xc1)

VALUE_STRING_ENUM2(ksm_type);
VALUE_STRING_ARRAY2(ksm_type);

static const value_string ib_version_t[] = {
    {0x11, "1"},
    {0x12, "2"},
    {0, NULL}
};

#define lnet_ib_type_VALUE_STRING_LIST(XXX)         \
    XXX(IBLND_MSG_CONNREQ,      0xc0)               \
    XXX(IBLND_MSG_CONNACK,      0xc1)               \
    XXX(IBLND_MSG_NOOP,         0xd0)               \
    XXX(IBLND_MSG_IMMEDIATE,    0xd1)               \
    XXX(IBLND_MSG_PUT_REQ,      0xd2)               \
    XXX(IBLND_MSG_PUT_NAK,      0xd3)               \
    XXX(IBLND_MSG_PUT_ACK,      0xd4)               \
    XXX(IBLND_MSG_PUT_DONE,     0xd5)               \
    XXX(IBLND_MSG_GET_REQ,      0xd6)               \
    XXX(IBLND_MSG_GET_DONE,     0xd7)

VALUE_STRING_ENUM2(lnet_ib_type);
VALUE_STRING_ARRAY2(lnet_ib_type);

/********************************************************************\
 *
 * LNet Conversation
 *
\********************************************************************/

typedef struct _lnet_conv_info_t {
    wmem_map_t *pdus;
} lnet_conv_info_t;

static struct lnet_trans_info *
get_lnet_conv(packet_info *pinfo, guint64 match_bits) {
    conversation_t *conversation;

    struct lnet_trans_info *info;

    lnet_conv_info_t *conv_info;

    // Ignore ports because this is kernel level and there can only be one Lustre instance per server
    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype),
                                     0, 0, 0);
    if (conversation == NULL)
        conversation = conversation_new(pinfo->num, &pinfo->src,
                                        &pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype), 0, 0, 0);

    conv_info = (lnet_conv_info_t *)conversation_get_proto_data(conversation, proto_lnet);
    if (!conv_info) {
        conv_info = wmem_new0(wmem_file_scope(), lnet_conv_info_t);
        conv_info->pdus = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

        conversation_add_proto_data(conversation, proto_lnet, conv_info);
    }

    info = (struct lnet_trans_info *)wmem_map_lookup(conv_info->pdus, GUINT_TO_POINTER(match_bits));
    if (info == NULL) {
        info = wmem_new0(wmem_file_scope(), struct lnet_trans_info);
        info->match_bits = match_bits;
        wmem_map_insert(conv_info->pdus, GUINT_TO_POINTER(info->match_bits), info);
    }

    return info;
}

/********************************************************************\
 *
 * LND:O2IB Structures
 *
\********************************************************************/

static int
dissect_struct_o2ib_connparam(tvbuff_t *tvb, proto_tree *parent_tree, int offset)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_lnet_o2ib_connparam, tvb, offset, 8, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lnet_o2ib_connparams);

    proto_tree_add_item(tree, hf_lnet_o2ib_connparam_qdepth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;
    proto_tree_add_item(tree, hf_lnet_o2ib_connparam_max_frags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;
    proto_tree_add_item(tree, hf_lnet_o2ib_connparam_max_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    return offset;
}

/* kib_rdma_desc_t */
/* { */
/*         __u32             rd_key;               /\* local/remote key *\/ */
/*         __u32             rd_nfrags;            /\* # fragments *\/ */
/*         kib_rdma_frag_t   rd_frags[0];          /\* buffer frags *\/ */
/* }
 * kib_rdma_frag_t */
/* { */
/*     __u32             rf_nob;               /\* # bytes this frag *\/ */
/*     __u64             rf_addr;              /\* CAVEAT EMPTOR: misaligned!! *\/ */
/* } */
static int
dissect_struct_rdma_desc(tvbuff_t *tvb, proto_tree *parent_tree, int offset)
{
    proto_tree *tree, *ftree;
    int old_offset;
    guint32 frags, i;

    proto_item *item;

    old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_lnet_rdma_desc, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lnet_rdma_desc);

    /* @@ SAVE KEY and use to intercept infiniband payload */
    proto_tree_add_item(tree, hf_lnet_rdma_desc_key, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lnet_rdma_desc_nfrags, tvb, offset, 4, ENC_LITTLE_ENDIAN, &frags);
    offset += 4;

    for (i=0; i < frags; ++i) {
        ftree = proto_tree_add_subtree_format(tree, tvb, offset, 12, ett_lnet_rdma_frag, NULL, "RDMA Fragment [%d]", i);
        proto_tree_add_item(ftree, hf_lnet_rdma_frag_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(ftree, hf_lnet_rdma_frag_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    proto_item_set_len(item, offset-old_offset);
    return offset;
}


/********************************************************************\
 *
 * NID Dissection & Healper Function
 *
\********************************************************************/

// EXPORTED
int
lnet_dissect_struct_nid(tvbuff_t * tvb, proto_tree *parent_tree, int offset, int hf_index)
{
    proto_tree *tree;
    proto_item *item;
    guint32 ip, interface, proto;

    item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 8, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lnet_nid);

    ip = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_lnet_nid_addr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    proto_tree_add_item_ret_uint(tree, hf_lnet_nid_interface, tvb, offset, 2, ENC_LITTLE_ENDIAN, &interface);
    offset+=2;
    proto_tree_add_item_ret_uint(tree, hf_lnet_nid_lnet_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &proto);
    offset+=2;

    if (ip != 0) {
        address addr;
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(item, ": %s@%s%d", address_to_name(&addr), val_to_str(proto, lndprotos, "E(%d)"), interface);
    }

    return offset;
}

/********************************************************************\
 *
 * Other Dissection
 *
\********************************************************************/

static int
dissect_csum(tvbuff_t * tvb, packet_info *pinfo, proto_tree *tree, int offset, guint lnd_type)
{
    guint32 csum;
    proto_item *ti;

    csum = tvb_get_letohl(tvb, offset);
    // @@ convert this to proto_tree_add_checksum()
    switch (lnd_type) {
    case SOCKLND:
        ti = proto_tree_add_item(tree, hf_lnet_ib_csum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        break;

    case O2IBLND:
        ti = proto_tree_add_item(tree, hf_lnet_ksm_csum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        break;

    default:
        ti = proto_tree_add_expert_format(tree, pinfo, &ei_lnet_type, tvb, offset, 4,
                                          "Checksum for unprocessed type: %s",
                                          val_to_str(lnd_type, lndnames, "Unknown(%d)"));
        break;
    }

    if (csum == 0)
        proto_item_append_text(ti, " (DISABLED)");

    return offset + 4;
}

/********************************************************************\
 *
 * Message Type Dissection
 *
\********************************************************************/

static int
dissect_lnet_put(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint64 *match)
{
    /* typedef struct lnet_put {
       lnet_handle_wire_t  ack_wmd;
       __u64               match_bits;
       __u64               hdr_data;
       __u32               ptl_index;
       __u32               offset;
       } WIRE_ATTR lnet_put_t; */
    const char *port;
    guint32 ptl_index;

    proto_tree_add_item(tree, hf_dst_wmd_interface, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_dst_wmd_object, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item_ret_uint64(tree, hf_match_bits, tvb, offset, 8, ENC_LITTLE_ENDIAN, match);
    offset += 8;
    proto_tree_add_item(tree, hf_hdr_data, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* print ptl_index */
    proto_tree_add_item_ret_uint(tree, hf_ptl_index, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ptl_index);
    offset += 4;

    port = val_to_str(ptl_index, portal_index, "Unknown(%d)");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", port);
    proto_item_append_text(tree, ", %s" , port);

    proto_tree_add_item(tree, hf_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    return offset;
}

static int
dissect_lnet_get(tvbuff_t * tvb, packet_info *pinfo, proto_tree *tree, int offset, guint64 *match)
{
    /* typedef struct lnet_get {
       lnet_handle_wire_t  return_wmd;
       __u64               match_bits;
       __u32               ptl_index;
       __u32               src_offset;
       __u32               sink_length;
       } WIRE_ATTR lnet_get_t;
    */
    const char *port;
    guint32 ptl_index;

    proto_tree_add_item(tree, hf_dst_wmd_interface, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_dst_wmd_object, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item_ret_uint64(tree, hf_match_bits, tvb, offset, 8, ENC_LITTLE_ENDIAN, match);
    offset += 8;

    proto_tree_add_item_ret_uint(tree, hf_ptl_index, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ptl_index);
    offset += 4;

    port = val_to_str(ptl_index, portal_index, "Unknown (%d)");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", port);
    proto_item_append_text(tree, ", %s", port);

    proto_tree_add_item(tree, hf_src_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_sink_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    return offset;
}

static int
dissect_lnet_reply(tvbuff_t * tvb, proto_tree *tree, int offset)
{
    /* typedef struct lnet_reply {
       lnet_handle_wire_t  dst_wmd;
       } WIRE_ATTR lnet_reply_t; */

    proto_tree_add_item(tree, hf_dst_wmd_interface, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset+=8;
    proto_tree_add_item(tree, hf_dst_wmd_object, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset+=8;

    return offset;
}


static int
dissect_lnet_hello(tvbuff_t * tvb, proto_tree *tree, int offset)
{
    /* typedef struct lnet_hello {
       __u64              incarnation;
       __u32              type;
       } WIRE_ATTR lnet_hello_t; */

    proto_tree_add_item(tree, hf_hello_incarnation, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset+=8;
    proto_tree_add_item(tree, hf_hello_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    return offset;
}

static int
dissect_lnet_ack(tvbuff_t * tvb, proto_tree *tree, int offset, guint64 *match)
{
    /* typedef struct lnet_ack {
       lnet_handle_wire_t  dst_wmd;
       __u64               match_bits;
       __u32               mlength;
       } WIRE_ATTR lnet_ack_t; */

    proto_tree_add_item(tree, hf_dst_wmd_interface, tvb, offset, 8, ENC_NA);
    offset+=8;
    proto_tree_add_item(tree, hf_dst_wmd_object, tvb, offset, 8, ENC_NA);
    offset+=8;
    proto_tree_add_item_ret_uint64(tree, hf_match_bits, tvb, offset, 8, ENC_LITTLE_ENDIAN, match);
    offset+=8;
    proto_tree_add_item(tree, hf_mlength, tvb, offset,4, ENC_LITTLE_ENDIAN);
    offset+=4;
    return offset;
}

/********************************************************************\
 *
 * Dissect Header Functions
 *
\********************************************************************/

static int
dissect_ksock_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *ti;
    guint64 val;

    proto_tree_add_item(tree, hf_lnet_ksm_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    offset = dissect_csum(tvb, pinfo, tree, offset, SOCKLND);
    ti = proto_tree_add_item_ret_uint64(tree, hf_lnet_ksm_zc_req_cookie, tvb, offset, 8, ENC_LITTLE_ENDIAN, &val);
    if (val == 0)
        proto_item_append_text(ti, " (NO ACK REQUIRED)");
    offset += 8;
    ti = proto_tree_add_item_ret_uint64(tree, hf_lnet_ksm_zc_ack_cookie, tvb, offset, 8, ENC_LITTLE_ENDIAN, &val);
    if (val == 0)
        proto_item_append_text(ti, " (NOT ACK)");
    offset += 8;
    return offset;
}
static int
dissect_ksock_msg_noop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_ksock_msg(tvb, pinfo, tree, 0);
}

static int
dissect_ib_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint32 *msg_type, guint32 *msg_length)
{
    /* typedef struct
     * {
     *    __u32             ibm_magic;            * I'm an ibnal message *
     *    __u16             ibm_version;          * this is my version *

     *    __u8              ibm_type;             * msg type *
     *    __u8              ibm_credits;          * returned credits *
     *    __u32             ibm_nob;              * # bytes in message *
     *    __u32             ibm_cksum;            * checksum (0 == no
     *                                                checksum) *
     *    __u64             ibm_srcnid;           * sender's NID *
     *    __u64             ibm_srcstamp;         * sender's incarnation *
     *    __u64             ibm_dstnid;           * destination's NID *
     *    __u64             ibm_dststamp;         * destination's
     *                                                incarnation *

     *    union {
     *        kib_connparams_t      connparams;
     *        kib_immediate_msg_t   immediate;
     *        kib_putreq_msg_t      putreq;
     *        kib_putack_msg_t      putack;
     *        kib_get_msg_t         get;
     *        kib_completion_msg_t  completion;
     *    } WIRE_ATTR ibm_u;
     *} WIRE_ATTR kib_msg_t;   */

    proto_tree_add_item(tree, hf_lnet_ib_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lnet_ib_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_lnet_ib_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, msg_type);
    offset += 1;
    proto_tree_add_item(tree, hf_lnet_ib_credits, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_lnet_ib_nob, tvb, offset, 4, ENC_LITTLE_ENDIAN, msg_length);
    offset += 4;
    offset = dissect_csum(tvb, pinfo, tree, offset, O2IBLND);

    offset = lnet_dissect_struct_nid(tvb, tree, offset, hf_lnet_src_nid);

    proto_tree_add_item(tree, hf_lnet_ib_srcstamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    offset = lnet_dissect_struct_nid(tvb, tree, offset, hf_lnet_dest_nid);

    proto_tree_add_item(tree, hf_lnet_ib_dststamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* LNet payloads only exist when the LND msg type is IMMEDIATE.
       Return a zero offset for all other types. */
    return offset;
}

/********************************************************************\
 *
 * Main Packet Dissection
 *
\********************************************************************/
static int
dissect_lnet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;

    proto_tree *lnet_tree;
    /* Other misc. local variables. */
    guint offset = 0;
    guint32 msg_length = 0;
    guint32 payload_length = 0;
    gint32 msg_filler_length = 0;

    guint64 match;
    guint32 msg_type = 0;
    guint32 ib_msg_type = 0;
    guint extra_bytes = GPOINTER_TO_UINT(data);
    gboolean ib_msg_payload = FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LNET");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_lnet, tvb, 0, -1, ENC_NA);
    lnet_tree = proto_item_add_subtree(ti, ett_lnet);

    if (extra_bytes) {
        offset = dissect_ib_msg(tvb, pinfo, lnet_tree, offset, &ib_msg_type, &msg_length);

        switch (ib_msg_type) {
        case IBLND_MSG_CONNREQ:
        case IBLND_MSG_CONNACK:
            // kib_connparams_t;
            col_add_fstr(pinfo->cinfo, COL_INFO, "LNET %s",
                        val_to_str(ib_msg_type, lnet_ib_type, "Unknown(%d)"));
            offset = dissect_struct_o2ib_connparam(tvb, lnet_tree, offset);
            msg_filler_length = tvb_reported_length_remaining(tvb, offset);
            ib_msg_payload = TRUE;
            break;

        case IBLND_MSG_NOOP:
            // No further data
            col_add_fstr(pinfo->cinfo, COL_INFO, "LNET %s",
                        val_to_str(ib_msg_type, lnet_ib_type, "Unknown(%d)"));
            ib_msg_payload = TRUE;
            break;

        case IBLND_MSG_IMMEDIATE:
            // Normal LNET Message
            break;

        case IBLND_MSG_PUT_REQ:
            // kib_putreq_msg_t
            // lnet_hdr + cookie
            break;

        case IBLND_MSG_PUT_ACK:
            // kib_putack_msg_t;
            // src cookie + dest cookie + rdma_desc_t
            col_add_fstr(pinfo->cinfo, COL_INFO, "LNET %s",
                        val_to_str(ib_msg_type, lnet_ib_type, "Unknown(%d)"));
            proto_tree_add_item(lnet_tree, hf_lnet_o2ib_src_cookie, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset+=8;
            proto_tree_add_item(lnet_tree, hf_lnet_o2ib_dest_cookie, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset+=8;
            offset = dissect_struct_rdma_desc(tvb, lnet_tree, offset);
            ib_msg_payload = TRUE;
            break;

        case IBLND_MSG_GET_REQ:
            // kib_get_msg_t
            // lnet_hdr + cookie + rdma_desc_t
            break;

        case IBLND_MSG_PUT_NAK:
        case IBLND_MSG_PUT_DONE:
        case IBLND_MSG_GET_DONE:
            // kib_completion_msg_t;
            col_add_fstr(pinfo->cinfo, COL_INFO, "LNET %s",
                        val_to_str(ib_msg_type, lnet_ib_type, "Unknown(%d)"));

            proto_tree_add_item(lnet_tree, hf_lnet_o2ib_cookie, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset+=8;
            proto_tree_add_item(lnet_tree, hf_lnet_o2ib_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            ib_msg_payload = TRUE;
            break;
        }

    } else {
        /* dissect the first 24 bytes (ksock_msg_t in
         * lnet/socklnd.h
         */
        offset = dissect_ksock_msg(tvb, pinfo, lnet_tree, offset);
    }

    if (!ib_msg_payload) {
        /* LNET HEADER */
        offset = lnet_dissect_struct_nid(tvb, lnet_tree, offset, hf_lnet_dest_nid);
        offset = lnet_dissect_struct_nid(tvb, lnet_tree, offset, hf_lnet_src_nid);

        /* pid */
        proto_tree_add_item(lnet_tree, hf_lnet_src_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(lnet_tree, hf_lnet_dest_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* put some nice info on lnet line */
        proto_tree_add_item_ret_uint(lnet_tree, hf_lnet_msg_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &msg_type);
        proto_item_append_text(ti, " %s", val_to_str(msg_type, lnet_msg_type, "Unknown(%d)"));
        col_add_fstr(pinfo->cinfo, COL_INFO, "LNET_%s", val_to_str(msg_type, lnet_msg_type, "Unknown(%d)"));
        offset += 4;

        /* payload data (to follow) length :*/
        proto_tree_add_item_ret_uint(lnet_tree, hf_lnet_payload_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &payload_length);
        offset += 4;

        match = 0;
        switch (msg_type) {
        case LNET_MSG_ACK:
            offset = dissect_lnet_ack(tvb, lnet_tree, offset, &match);
            break;
        case LNET_MSG_PUT:
            offset = dissect_lnet_put(tvb, pinfo, lnet_tree, offset, &match);
            break;
        case LNET_MSG_GET:
            offset = dissect_lnet_get(tvb, pinfo, lnet_tree, offset, &match);
            break;
        case LNET_MSG_REPLY:
            offset = dissect_lnet_reply(tvb, lnet_tree, offset);
            break;
        case LNET_MSG_HELLO:
            offset = dissect_lnet_hello(tvb, lnet_tree, offset);
            break;
        default:
            break;
        }

        switch (ib_msg_type) {
        case 0: // not actually an ib_msg
            break;
        case IBLND_MSG_PUT_REQ:
            proto_tree_add_item(lnet_tree, hf_lnet_o2ib_cookie, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            /*@@ SAVE payload_length with O2IB cookie for IBLND_MSG_PUT_ACK */
            payload_length = 0;
            break;
        case IBLND_MSG_GET_REQ:
            proto_tree_add_item(lnet_tree, hf_lnet_o2ib_cookie, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            offset = dissect_struct_rdma_desc(tvb, lnet_tree, offset);
            break;
        }

        /* padding */
        msg_filler_length = 72 - offset + 24 + extra_bytes;
        /*
        if (msg_filler_length > 72)
            goto out;
        */
        /*  +24 : ksock_message take 24bytes, and allready in offset  */
    }

    if (msg_filler_length > 0) {
        proto_tree_add_item(lnet_tree, hf_lnet_msg_filler, tvb, offset, msg_filler_length, ENC_NA);
        offset += msg_filler_length;
    }

    if (payload_length > 0) {
        tvbuff_t *next_tvb;
        struct lnet_trans_info *conv;

        next_tvb = tvb_new_subset_length(tvb, offset, payload_length);
        switch (msg_type) {
        case LNET_MSG_PUT:
            conv = get_lnet_conv(pinfo, match);

            offset += dissector_try_uint_new(subdissector_table, tvb_get_letohl(tvb, LNET_PTL_INDEX_OFFSET_PUT),
                                             next_tvb, pinfo, tree, TRUE, conv);
            break;
        default:
            /* display of payload */
            proto_tree_add_item(lnet_tree, hf_lnet_payload, tvb, offset, payload_length, ENC_NA);
            offset += payload_length;
            break;
        }
    }

    if (tvb_captured_length(tvb) != offset) {
        expert_add_info_format(pinfo, ti, &ei_lnet_buflen,
                               "Capture:%d offset:%d (length:%d) msg_type:%d ib_type:%02x",
                               tvb_captured_length(tvb), offset, msg_length, msg_type, ib_msg_type);
    }
    return offset;
}

/********************************************************************\
 *
 * Length Functions (these are SOCK LND only)
 *
\********************************************************************/
#if 0
static guint
get_lnet_ib_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint32 plen;

    /* Ensure this is an LNET IB segment */
    if (tvb_get_letohl(tvb, 0) != LNET_PROTO_IB_MAGIC)
        return 0;

    /* Get the IB message length (see dissect_ib_msg() for .ibm_nob)
     */
    plen = tvb_get_letohl(tvb, offset + 8);

    return plen;
}
#endif

static guint
get_lnet_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint32 plen;
    guint extra_bytes = GPOINTER_TO_UINT(data);

    /* Get the payload length:
     * 24 = ksm header,
     * 28 = the rest of the headers
     */
    plen = tvb_get_letohl(tvb, offset + 28 + 24 + extra_bytes);

    /* That length doesn't include the header; add that in.
     * +24 == ksock msg header.. :D
     */
    return plen + 72 + 24 + extra_bytes;
}

static guint
get_noop_message_len(packet_info *pinfo _U_, tvbuff_t *tvb _U_,
                     int offset _U_, void *data _U_)
{
    return 24;
}

/********************************************************************   \
 *
 * Core Functions
 *
\********************************************************************/

static int
dissect_lnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    switch (tvb_get_letohl(tvb, 0)) {
    case KSOCK_MSG_NOOP:
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
                         get_noop_message_len,
                         dissect_ksock_msg_noop, GUINT_TO_POINTER(0));
        break;
    case KSOCK_MSG_LNET:
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, LNET_HEADER_LEN,
                         get_lnet_message_len,
                         dissect_lnet_message, GUINT_TO_POINTER(0));
        break;
    }
    return tvb_captured_length(tvb);
}

static gboolean
dissect_lnet_ib_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* We can tell if this is an LNet payload by looking at the first
     * 32-bit word for our magic number. */
    if (tvb_captured_length(tvb) < 4 || tvb_get_letohl(tvb, 0) != LNET_PROTO_IB_MAGIC)
        /* Not an LNet payload. */
        return FALSE;

    dissect_lnet_message(tvb, pinfo, tree, GUINT_TO_POINTER(EXTRA_IB_HEADER_SIZE));
    return TRUE;
}

void
proto_register_lnet(void)
{
    static hf_register_info hf[] = {
        { &hf_lnet_ksm_type,
          { "Type of socklnd message", "lnet.ksm_type", FT_UINT32, BASE_HEX, VALS(ksm_type), 0x0, NULL, HFILL }},
        { &hf_lnet_ksm_csum,
          { "Checksum", "lnet.ksm_csum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_ksm_zc_req_cookie,
          { "Ack required", "lnet.ksm_zc_req_cookie", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_ksm_zc_ack_cookie,
          { "Ack", "lnet.ksm_zc_ack_cookie", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /* Infiniband Fields */
        { &hf_lnet_ib_magic,
          { "Magic of IB message", "lnet.ib.magic", FT_UINT32, BASE_HEX, VALS(lnet_magic), 0x0, NULL, HFILL} },
        { &hf_lnet_ib_version,
          { "Version", "lnet.ib.version", FT_UINT16, BASE_HEX, VALS(ib_version_t), 0x0, NULL, HFILL} },
        { &hf_lnet_ib_type,
          { "Type of IB message", "lnet.ib.type", FT_UINT8, BASE_HEX, VALS(lnet_ib_type), 0x0, NULL, HFILL} },
        { &hf_lnet_ib_credits,
          { "Returned Credits", "lnet.ib.credits", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL} },
        { &hf_lnet_ib_nob,
          { "Number of Bytes", "lnet.ib.nob", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL} },
        { &hf_lnet_ib_csum,
          { "Checksum", "lnet.ib_csum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL} },
        { &hf_lnet_ib_srcstamp,
          { "Sender Timestamp", "lnet.ib.srcstamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_ib_dststamp,
          { "Destination Timestamp", "lnet.ib.dststamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},

        { &hf_lnet_src_nid,
          { "Src nid", "lnet.src_nid", FT_NONE, BASE_NONE, NULL, 0x0, "Source NID", HFILL }},
        { &hf_lnet_dest_nid,
          { "Dest nid", "lnet.dest_nid", FT_NONE, BASE_NONE, NULL, 0x0, "Destination NID", HFILL }},

        { &hf_lnet_nid_addr,
          { "lnd address", "lnet.nid.addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_nid_lnet_type,
          { "lnd network type", "lnet.nid.type", FT_UINT16, BASE_DEC, VALS(lndnames), 0x0, NULL, HFILL }},
        { &hf_lnet_nid_interface,
          { "lnd network interface", "lnet.nid.net_interface", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_lnet_dest_pid,
          { "Dest pid", "lnet.dest_pid", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "Destination pid", HFILL }},
        { &hf_lnet_src_pid,
          { "Src pid", "lnet.src_pid", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "Source nid", HFILL }},

        { &hf_lnet_msg_type,
          { "Message type", "lnet.msg_type", FT_UINT32, BASE_DEC, VALS(lnet_msg_type), 0x0, NULL, HFILL }},
        { &hf_lnet_payload_length,
          { "Payload length", "lnet.payload_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_payload,
          { "Payload", "lnet.payload", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dst_wmd_interface,
          { "DST MD index interface", "lnet.msg_dst_interface_cookie", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dst_wmd_object,
          { "DST MD index object", "lnet.msg_dst_object_cookie", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_match_bits,
          { "Match bits", "lnet.msg_dst_match_bits", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_mlength,
          { "Message length", "lnet.msg_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        /* Put */
        { &hf_hdr_data,
          { "hdr data", "lnet.msg_hdr_data", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_ptl_index,
          { "ptl index", "lnet.ptl_index", FT_UINT32, BASE_DEC, VALS(portal_index), 0x0, NULL, HFILL}},
        { &hf_offset,
          { "offset", "lnet.offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        /* Get*/
        { &hf_src_offset,
          { "src offset", "lnet.src_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_sink_length,
          { "sink length", "lnet.sink_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        /* Hello */
        { &hf_hello_incarnation,
          { "hello incarnation", "lnet.hello_incarnation", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_hello_type,
          { "hello type", "lnet.hello_type", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_lnet_msg_filler,
          { "msg filler (padding)", "lnet.ptl_filler", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        /* O2IB Specific */
        { &hf_lnet_o2ib_connparam,
          { "O2IB ConnParam", "lnet.connparam", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_o2ib_connparam_qdepth,
          { "Queue Depth", "lnet.connparam.qdepth", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_o2ib_connparam_max_frags,
          { "Max Fragments", "lnet.connparam.max_frags", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_o2ib_connparam_max_size,
          { "Max Msg Size", "lnet.connparam.max_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_lnet_o2ib_cookie,
          { "O2IB Cookie", "lnet.o2ib.cookie", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_o2ib_src_cookie,
          { "O2IB Source Cookie", "lnet.o2ib.src_cookie", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_o2ib_dest_cookie,
          { "O2IB Dest Cookie", "lnet.o2ib.dest_cookie", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_o2ib_status,
          { "O2IB Status", "lnet.o2ib.status", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_lnet_rdma_desc,
          { "RDMA Description", "lnet.rdma", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_rdma_desc_key,
          { "RDMA Key", "lnet.rdma.key", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_rdma_desc_nfrags,
          { "RDMA # of Fragments", "lnet.rdma.nfrags", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_lnet_rdma_frag_size,
          { "RDMA Frag Size (bytes)", "lnet.rdma_frag.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lnet_rdma_frag_addr,
          { "RDMA Frag Address", "lnet.rdma_frag.addr", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_lnet,
        &ett_lnet_nid,
        &ett_lnet_o2ib_connparams,
        &ett_lnet_rdma_desc,
        &ett_lnet_rdma_frag,
    };

    expert_module_t *expert_lnet;
    static ei_register_info ei[] = {
        { &ei_lnet_buflen,
          { "lnet.bad_buflen", PI_MALFORMED, PI_ERROR, "Buffer length mis-match", EXPFILL } },
        { &ei_lnet_type,
          { "lnet.bad_type", PI_PROTOCOL, PI_ERROR, "LNET Type mis-match", EXPFILL } }
    };

    proto_lnet = proto_register_protocol("Lustre Network", "LNet", "lnet");

    proto_register_field_array(proto_lnet, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_lnet = expert_register_protocol(proto_lnet);
    expert_register_field_array(expert_lnet, ei, array_length(ei));

    subdissector_table = register_dissector_table("lnet.ptl_index", "lnet portal index",
                                                  proto_lnet,
                                                  FT_UINT32 , BASE_DEC);
}

void
proto_reg_handoff_lnet(void)
{
    dissector_handle_t lnet_handle;

    heur_dissector_add("infiniband.payload", dissect_lnet_ib_heur, "LNet over IB",
                        "lnet_ib", proto_lnet, HEURISTIC_ENABLE);
    heur_dissector_add("infiniband.mad.cm.private", dissect_lnet_ib_heur, "LNet over IB CM",
                        "lnet_ib_cm_private",  proto_lnet, HEURISTIC_ENABLE);
    lnet_handle = create_dissector_handle(dissect_lnet, proto_lnet);
    dissector_add_for_decode_as("infiniband", lnet_handle);
    dissector_add_uint_with_preference("tcp.port", LNET_TCP_PORT, lnet_handle);
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
