/* packet-irdma.c
 *
 * Routines for IBM i RDMA dissection
 * Copyright 2018, 2024 IBM Corporation
 * Brian Jongekryg (bej@us.ibm.com, bej@arbin.net)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Dissector for IBM i base RDMA frame traffic
 * captured via TRCCNN TYPE(*RDMA) command
 *
 * Subdissectors for IBM i RDMA endoint traffic can be registered
 * by calling
 *   dissector_add_uint("irdma.ep.port", port, handle);
 */

#include <config.h>

#include <string.h>

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <wsutil/utf8_entities.h>

#include <packet-irdma.h>

/* irdmaep conversation and packet analysis data                     */
typedef struct irdmaep_buffer
{
    /* Size of buffer */
    uint32_t size;

    /* Offset of first byte available for use */
    uint32_t offset;

    /* Last data sequence number in buffer */
    uint32_t  seq_num;

    /* Contents of buffer unknown */
    bool     indeterminate;

} irdmaep_buffer_t;

#define IRDMAEP_MAX_DATA_BUFID   2
typedef struct irdmaep_flow
{
    /* Last sent DATA sequence */
    bool        data_seq_valid;
    uint32_t    data_seq;

    /* Last sent USER_RDMA data (RECVACK) ID, offset */
    bool        recvack_valid;
    uint32_t    recvack_id;
    uint32_t    recvack_offset;

    /* Receive buffer status */
    /* Number of receive buffers */
    uint32_t    recv_buffer_count;

    /* Most recent buffer used by sender */
    uint32_t    recv_mrb;

    /* Calculated buffer size estimate */
    uint32_t    recv_min_size;

    /* Track up to two remote receive buffers */
    irdmaep_buffer_t  recv_buffer[IRDMAEP_MAX_DATA_BUFID];

} irdmaep_flow_t;

typedef struct irdmaep_analysis
{
    /* Trace status for both directions of the flow.
       Info for sends with smaller src port is recorded in flow1,
       larger src port in flow2. */
    irdmaep_flow_t flow1;
    irdmaep_flow_t flow2;

    /* Forward or reverse flow info based on current packet ports */
    irdmaep_flow_t *fwd_flow, *rev_flow;

    /* Server port number from CONNREQ or CONNACK to help determine
       which payload dissector to call. */
    uint32_t server_port;

    /* Keep track of RDMA endpoint stream numbers */
    uint32_t stream;

    /* Track whether conversation was closed, so we know to start
       new conversation if CONNREQ/ACK seen. */
    bool     closed;

    /* Current link sequence number */
    uint32_t link;

    /* Link switch timestamps */
    nstime_t movereq_time;

    /* Conversation timestamps */
    nstime_t ts_first;
    nstime_t ts_prev;

} irdmaep_analysis_t;

typedef struct irdmaep_packet_analysis
{
    /* Retransmitted packet? */
    bool     retransmission;

    /* Out-of-order sequence (should never occur) */
    bool     out_of_order;

    /* Bytes remaining available for sending/receiving */
    uint32_t rbuf_available;

    /* Bytes remaining in current/active receive buffer */
    uint32_t rbuf_cur;

    /* Max bytes available for next send */
    uint32_t rbuf_max;

    /* Is rbuf_available estimated or true value */
    bool     rbuf_estimated;

    /* Does packet sequence indicate this is stale (prior link) */
    bool     seq_stale;

    /* First packet on new link */
    bool     linkswt;

    /* Time to move link */
    nstime_t movelink_time;

    /* Delta time from previous packet */
    nstime_t delta_time;

} irdmaep_packet_analysis_t;

/* Prototypes */
void proto_reg_handoff_irdma(void);
void proto_register_irdma(void);

static int dissect_irdma(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_irdmaqp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_irdmalink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_irdmaep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static void dissect_data_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void irdmaep_add_rbuf_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                  irdmaep_packet_analysis_t *eppd);
static void dissect_reuse_msg(tvbuff_t *tvb, packet_info *pinfo,
                              irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void dissect_user_recv_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                  irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void dissect_user_send_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                  irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void dissect_connect_msg(tvbuff_t *tvb, packet_info *pinfo,
                                irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void dissect_close_msg(tvbuff_t *tvb, packet_info *pinfo,
                              irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void dissect_buffer_msg_mkeyaddr(tvbuff_t *tvb, packet_info *pinfo,
                                        irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void dissect_buffer_msg(tvbuff_t *tvb, packet_info *pinfo,
                               irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void dissect_move_link_msg(tvbuff_t *tvb, packet_info *pinfo,
                                  irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void dissect_move_link_ack_msg(tvbuff_t *tvb, packet_info *pinfo,
                                      irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void dissect_move_link_cmp_msg(tvbuff_t *tvb, packet_info *pinfo,
                                      irdmaep_analysis_t *epd, proto_tree *ep_tree);
static void dissect_irdmaep_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                 irdmaep_pdata_t *data);
static irdmaep_analysis_t *init_irdmaep_conversation_data(packet_info *pinfo);
static void analyze_irdmaep_rbuffer(irdmaep_flow_t *flow,
                                    irdmaep_packet_analysis_t *eppd);
static void *add_eppd(packet_info *pinfo);
static void *get_eppd(packet_info *pinfo);
static void *get_or_add_eppd(packet_info *pinfo);

/* Initialize the protocol and registered fields */
static int proto_irdma;
static int proto_irdmaqp;
static int proto_irdmalink;
static int proto_irdmaep;

static int hf_irdma_hwdst;
static int hf_irdma_hwsrc;
static int hf_irdma_qpindex;
static int hf_irdma_ip6src;
static int hf_irdma_ip6dst;
static int hf_irdma_ip4src;
static int hf_irdma_ip4dst;
static int hf_irdma_hwaddr;
static int hf_irdma_ip6addr;
static int hf_irdma_ip4addr;

static int hf_irdmaqp_type;
static int hf_irdmaqp_id;

static int hf_irdmalink_type;
static int hf_irdmalink_groups;

static int hf_irdmaep_type;
static int hf_irdmaep_len;
static int hf_irdmaep_grpid;
static int hf_irdmaep_grpid_ctr;
static int hf_irdmaep_grpid_time;
static int hf_irdmaep_grpid_hwaddr;
static int hf_irdmaep_srcport;
static int hf_irdmaep_dstport;
static int hf_irdmaep_port;
static int hf_irdmaep_stream;
static int hf_irdmaep_linkseq;
static int hf_irdmaep_sndbufsize;
static int hf_irdmaep_usrblksize;
static int hf_irdmaep_reason;
static int hf_irdmaep_rbuf;
static int hf_irdmaep_rkey;
static int hf_irdmaep_raddr;
static int hf_irdmaep_flags;
static int hf_irdmaep_flag_buf0_free;
static int hf_irdmaep_flag_buf1_free;
static int hf_irdmaep_rcvbufsize;
static int hf_irdmaep_sendseq;
static int hf_irdmaep_recvseq0;
static int hf_irdmaep_recvseq1;
static int hf_irdmaep_usndsent;
static int hf_irdmaep_usndid;
static int hf_irdmaep_urcvid;
static int hf_irdmaep_seqnum;
static int hf_irdmaep_bufid;
static int hf_irdmaep_offset;
static int hf_irdmaep_datalen;
static int hf_irdmaep_ulength;
static int hf_irdmaep_blength;
static int hf_irdmaep_recvid;
static int hf_irdmaep_rbufavail;
static int hf_irdmaep_rbufactive;
static int hf_irdmaep_rbufmax;
static int hf_irdmaep_move1;
static int hf_irdmaep_move2;
static int hf_irdmaep_ts_relative;
static int hf_irdmaep_ts_delta;

static expert_field ei_irdmaep_analysis_stale;
static expert_field ei_irdmaep_analysis_dup;
static expert_field ei_irdmaep_analysis_oos;
static expert_field ei_irdmaep_connection_req;
static expert_field ei_irdmaep_connection_ack;
static expert_field ei_irdmaep_connection_lswt;

/* Initialize the subtree pointers */
static int ett_irdma;
static int ett_irdmaqp;
static int ett_irdmalink;
static int ett_irdmaep;
static int ett_irdmaep_grpid;
static int ett_irdmaep_rbuf;
static int ett_irdmaep_bufflags;
static int ett_irdmaep_rcvbuf_analyze;
static int ett_irdmaep_timestamps;

static dissector_table_t irdmaep_dissector_table = NULL;

static dissector_handle_t irdmaqp_handle;
static dissector_handle_t irdmalink_handle;
static dissector_handle_t irdmaep_handle;

static uint32_t irdmaep_stream_count;

/* Data passed from iRDMA dissector to QP, Link, Endpoint dissectors */
typedef struct
{
    uint32_t  qpindex;
} irdma_data_t;

/* Miscellaneous utility functions */
static inline bool
seq16_lt(uint16_t a, uint16_t b)
{
    return (int16_t) (a - b) < 0;
}

static inline bool
seq16_gt(uint16_t a, uint16_t b)
{
    return (int16_t) (a - b) > 0;
}

static inline bool
is_v4mapped(ws_in6_addr *addr)
{
    static uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    return memcmp(addr, mapped, 12) == 0;
}

static inline bool
is_v4compat(ws_in6_addr *addr)
{
    static uint8_t zeroes[12] = {0};
    return memcmp(addr, zeroes, 12) == 0
        && memcmp(&addr->bytes[12], zeroes, 4) != 0;
}

static const value_string irdma_serv_names[] = {
    {930, "mrdb-engine"},
    {931, "mrdb-objrep"},
    {932, "mrdb-objrepr"},
    {940, "ifs-mfs"},
    {946, "drda-ddm"},
    {0, NULL}};

static inline const char *
irdma_serv_name_lookup(unsigned port)
{
    return try_val_to_str(port, irdma_serv_names);
}

static inline void
irdma_col_snprint_port(char *buf, unsigned long buf_siz, uint16_t val)
{
    const char *str;

    if (gbl_resolv_flags.transport_name &&
        (str = irdma_serv_name_lookup(val)) != NULL) {
        snprintf(buf, buf_siz, "%s(%" PRIu16 ")", str, val);
    } else {
        snprintf(buf, buf_siz, "%" PRIu16, val);
    }
}

static void
irdma_col_append_ports(column_info *cinfo, const int col, uint16_t src, uint16_t dst)
{
    char buf_src[32], buf_dst[32];

    irdma_col_snprint_port(buf_src, 32, src);
    irdma_col_snprint_port(buf_dst, 32, dst);
    col_append_lstr(cinfo, col, buf_src, " " UTF8_RIGHTWARDS_ARROW " ", buf_dst, COL_ADD_LSTR_TERMINATOR);
}

static void
irdma_custom_format_port(char *str, uint32_t port)
{
    irdma_col_snprint_port(str, ITEM_LABEL_LENGTH, port);
}

static void
irdma_custom_format_rbufsize(char *str, uint32_t bufsize)
{
    bufsize &= 0xFFF;
    uint32_t kb_bufsize = bufsize * 4;
    snprintf(str, ITEM_LABEL_LENGTH, "%" PRIu32 " (%" PRIu32 " KB)", bufsize, kb_bufsize);
}

static void
irdma_init(void)
{
    irdmaep_stream_count = 0;
}

/*********************************************************************/
/*********************************************************************/
/* RDMA pseudo-header data and functions                             */
/*********************************************************************/
/*********************************************************************/

/* IBM i RDMA pseudo-header from TRCCNN offsets                      */
#define IRDMA_HDR_DST         0
#define IRDMA_HDR_SRC         6
#define IRDMA_HDR_QPINDEX    12
#define IRDMA_HDR_SRCIP      14
#define IRDMA_HDR_SRCIP4     26
#define IRDMA_HDR_DSTIP      30
#define IRDMA_HDR_DSTIP4     42
#define IRDMA_HDR_LENGTH     46

/* Payload types for IBM i RDMA frames                               */
#define IRDMA_PROTO_ENDPOINT  0     /* 0b   */
#define IRDMA_PROTO_QP        4     /* 100b */
#define IRDMA_PROTO_LINK      5     /* 101b */

/* Dissect IBM i RDMA pseudo-header */
static int
dissect_irdma(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_item *irdma_item;
    proto_tree *irdma_tree;
    /* Other misc. local variables. */
    ws_in6_addr ipsrc;
    bool        ipv4 = false;
    char *src_str, *dst_str;
    irdma_data_t irdma_data = {0};
    dissector_handle_t subdissector_handle = NULL;

    /*** HEURISTICS ***/

    /* First, if at all possible, do some heuristics to check if the packet
     * cannot possibly belong to your protocol.  This is especially important
     * for protocols directly on top of TCP or UDP where port collisions are
     * common place (e.g., even though your protocol uses a well known port,
     * someone else may set up, for example, a web server on that port which,
     * if someone analyzed that web server's traffic in Wireshark, would result
     * in Wireshark handing an HTTP packet to your dissector).
     *
     * For example:
     */

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < IRDMA_HDR_LENGTH)
        return 0;

    /* Check that the packet has a recognizable frame type. This probably
       won't eliminate many bad packets. */
    uint8_t ftype = tvb_get_bits8(tvb, IRDMA_HDR_LENGTH * 8, 3);
    if (ftype > 5)
        return 0;

    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string 'irdma',
     * and the 'Info' column which can be much wider and contain misc. summary
     * information (for example, the port number for TCP packets).
     *
     * If you are setting the column to a constant string, use "col_set_str()",
     * as it's more efficient than the other "col_set_XXX()" calls.
     *
     * If
     * - you may be appending to the column later OR
     * - you have constructed the string locally OR
     * - the string was returned from a call to val_to_str()
     * then use "col_add_str()" instead, as that takes a copy of the string.
     *
     * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
     * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
     * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
     * more efficient than "col_add_fstr()".
     *
     * For full details see section 1.4 of README.dissector.
     */

    /* Set the Protocol column to the constant string of irdma */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDMA");

    /* Use first 3 bits beyond header to determine what type of frame this is
       (QP management, Link Management, Endpoint)  */
    if (ftype == IRDMA_PROTO_QP)
        {
        col_set_str(pinfo->cinfo, COL_INFO, "QP Management");
        subdissector_handle = irdmaqp_handle;
        }
    else
    if (ftype == IRDMA_PROTO_LINK)
        {
        col_set_str(pinfo->cinfo, COL_INFO, "Link Management");
        subdissector_handle = irdmalink_handle;
        }
    else
        {
        col_set_str(pinfo->cinfo, COL_INFO, "RDMA Endpoint");
        subdissector_handle = irdmaep_handle;
        }

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    /* create display subtree for the protocol */
    irdma_item = proto_tree_add_item(tree, proto_irdma, tvb, 0, IRDMA_HDR_LENGTH, ENC_NA);
    irdma_tree = proto_item_add_subtree(irdma_item, ett_irdma);

    set_address_tvb(&pinfo->dl_dst, AT_ETHER, 6, tvb, IRDMA_HDR_DST);
    set_address_tvb(&pinfo->dl_src, AT_ETHER, 6, tvb, IRDMA_HDR_SRC);

    proto_tree_add_item(irdma_tree, hf_irdma_hwdst, tvb, IRDMA_HDR_DST, 6, ENC_NA);
    ti = proto_tree_add_item(irdma_tree, hf_irdma_hwaddr, tvb, IRDMA_HDR_DST, 6, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(ti);

    proto_tree_add_item(irdma_tree, hf_irdma_hwsrc, tvb, IRDMA_HDR_SRC, 6, ENC_NA);
    ti = proto_tree_add_item(irdma_tree, hf_irdma_hwaddr, tvb, IRDMA_HDR_SRC, 6, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(ti);

    proto_tree_add_item_ret_uint(irdma_tree, hf_irdma_qpindex, tvb,
                                 IRDMA_HDR_QPINDEX, 2, ENC_BIG_ENDIAN,
                                 &irdma_data.qpindex);

    /* Get source IP address and determine if we've got an IPv4 or IPv6 address */
    tvb_get_ipv6(tvb, IRDMA_HDR_SRCIP, &ipsrc);
    ipv4 = is_v4mapped(&ipsrc) || is_v4compat(&ipsrc);

    if (ipv4)
        {
        set_address_tvb(&pinfo->net_dst, AT_IPv4, 4, tvb, IRDMA_HDR_DSTIP4);
        copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

        set_address_tvb(&pinfo->net_src, AT_IPv4, 4, tvb, IRDMA_HDR_SRCIP4);
        copy_address_shallow(&pinfo->src, &pinfo->net_src);

        src_str = tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_IPv4, IRDMA_HDR_SRCIP4);
        dst_str = tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_IPv4, IRDMA_HDR_DSTIP4);

        proto_tree_add_item(irdma_tree, hf_irdma_ip4src, tvb, IRDMA_HDR_SRCIP4, 4, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(irdma_tree, hf_irdma_ip4addr, tvb, IRDMA_HDR_SRCIP4, 4, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_HIDDEN(ti);

        proto_tree_add_item(irdma_tree, hf_irdma_ip4dst, tvb, IRDMA_HDR_DSTIP4, 4, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(irdma_tree, hf_irdma_ip4addr, tvb, IRDMA_HDR_DSTIP4, 4, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_HIDDEN(ti);
        }
    else
        {
        set_address_tvb(&pinfo->net_dst, AT_IPv6, 16, tvb, IRDMA_HDR_DSTIP);
        copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

        set_address_tvb(&pinfo->net_src, AT_IPv6, 16, tvb, IRDMA_HDR_SRCIP);
        copy_address_shallow(&pinfo->src, &pinfo->net_src);

        src_str = tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_IPv6, IRDMA_HDR_SRCIP);
        dst_str = tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_IPv6, IRDMA_HDR_DSTIP);

        proto_tree_add_item(irdma_tree, hf_irdma_ip6src, tvb, IRDMA_HDR_SRCIP, 16, ENC_NA);
        ti = proto_tree_add_item(irdma_tree, hf_irdma_ip6addr, tvb, IRDMA_HDR_SRCIP, 16, ENC_NA);
        PROTO_ITEM_SET_HIDDEN(ti);

        proto_tree_add_item(irdma_tree, hf_irdma_ip6dst, tvb, IRDMA_HDR_DSTIP, 16, ENC_NA);
        ti = proto_tree_add_item(irdma_tree, hf_irdma_ip6addr, tvb, IRDMA_HDR_DSTIP, 16, ENC_NA);
        PROTO_ITEM_SET_HIDDEN(ti);
        }

    proto_item_append_text(irdma_item, ", Src: %s", src_str);
    proto_item_append_text(irdma_item, ", Dst: %s", dst_str);

    call_dissector_with_data(subdissector_handle,
                             tvb_new_subset_remaining(tvb, IRDMA_HDR_LENGTH),
                             pinfo, tree, &irdma_data);

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

/*********************************************************************/
/*********************************************************************/
/* RDMA QP data and functions                                        */
/*********************************************************************/
/*********************************************************************/
/* IBM i RDMA QP message types                                       */
#define IRDMA_QP_ECHOREQ      0x8000
#define IRDMA_QP_ECHORSP      0x8001

/* IBM i RDMA QP message offsets                                     */
#define IRDMA_QP_TYPE         0     /* 16-bit message type */
#define IRDMA_QP_ECHO_ID      2     /* 16-bit Echo req/rsp ID */

static const value_string irdmaqp_type_str[] = {
    {IRDMA_QP_ECHOREQ,   "Echo request"},
    {IRDMA_QP_ECHORSP,   "Echo response"},
    {0, NULL}};

/* Dissect RDMA QP packets */
static int
dissect_irdmaqp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *qp_tree;

    irdma_data_t *irdma_data = (irdma_data_t *) data;

    if (tvb_reported_length(tvb) < 2)
        return 0;

    /* Set the Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDMA-QP");

    uint16_t msg_type = tvb_get_ntohs(tvb, IRDMA_QP_TYPE);
    const char *msg_type_str = val_to_str(msg_type, irdmaqp_type_str,
                                          "Unknown message (0x%04X)");

    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "%-16s qp=%2" PRIu32, msg_type_str, irdma_data->qpindex);

    /* Create display subtree for the QP message */
    ti = proto_tree_add_item(tree, proto_irdmaqp, tvb, 0, -1, ENC_NA);
    qp_tree = proto_item_add_subtree(ti, ett_irdmaqp);

    proto_tree_add_item(qp_tree, hf_irdmaqp_type, tvb, IRDMA_QP_TYPE, 2,
                        ENC_BIG_ENDIAN);

    switch (msg_type)
        {
        case IRDMA_QP_ECHOREQ:
        case IRDMA_QP_ECHORSP:
            {
            uint32_t echo_id;
            proto_tree_add_item_ret_uint(qp_tree, hf_irdmaqp_id, tvb,
                                         IRDMA_QP_ECHO_ID, 2,
                                         ENC_BIG_ENDIAN, &echo_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", id=%" PRIu32, echo_id);
            break;
            }
        }

    return tvb_captured_length(tvb);
}

/*********************************************************************/
/*********************************************************************/
/* RDMA Link data and functions                                      */
/*********************************************************************/
/*********************************************************************/
/* IBM i RDMA Link message types                                     */
#define IRDMA_LINK_STATUS     0xA000

/* IBM i RDMA Link message offsets                                   */
#define IRDMA_LINK_TYPE          0  /* 16-bit message type */
#define IRDMA_LINK_STATUS_GROUPS 2  /* 16-bit count of active groups */

static const value_string irdmalink_type_str[] = {
    {IRDMA_LINK_STATUS,   "Link Status"},
    {0, NULL}};

/* Dissect RDMA Link packets */
static int
dissect_irdmalink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *link_tree;

    if (tvb_reported_length(tvb) < 2)
        return 0;

    /* Set the Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDMA-Link");

    uint16_t msg_type = tvb_get_ntohs(tvb, IRDMA_LINK_TYPE);
    const char *msg_type_str = val_to_str(msg_type, irdmalink_type_str,
                                          "Unknown message (0x%04X)");

    col_add_str(pinfo->cinfo, COL_INFO, msg_type_str);

    /* Create display subtree for the Link message */
    ti = proto_tree_add_item(tree, proto_irdmalink, tvb, 0, -1, ENC_NA);
    link_tree = proto_item_add_subtree(ti, ett_irdmalink);

    proto_tree_add_item(link_tree, hf_irdmalink_type, tvb, IRDMA_LINK_TYPE, 2,
                        ENC_BIG_ENDIAN);

    switch (msg_type)
        {
        case IRDMA_LINK_STATUS:
            {
            uint32_t groups;
            proto_tree_add_item_ret_uint(link_tree, hf_irdmalink_groups, tvb,
                                         IRDMA_LINK_STATUS_GROUPS, 2,
                                         ENC_BIG_ENDIAN, &groups);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", groups=%" PRIu32, groups);
            break;
            }
        }

    return tvb_captured_length(tvb);
}

/*********************************************************************/
/*********************************************************************/
/* RDMA Endpoint data and functions                                  */
/*********************************************************************/
/*********************************************************************/
/* IBM i RDMA Endpoint preferences                                   */
static bool irdmaep_calculate_ts = true;
static bool irdmaep_no_subdissector_on_error = true;

/* IBM i RDMA Endpoint message types                                 */
#define IRDMA_EP_CONNREQ      0x01
#define IRDMA_EP_CONNACK      0x02
#define IRDMA_EP_CONNBUF      0x03
#define IRDMA_EP_RNEGREQ      0x04
#define IRDMA_EP_RNEGACK      0x05
#define IRDMA_EP_CLOSE        0x06
#define IRDMA_EP_RESET        0x09
#define IRDMA_EP_MOVEREQ      0x11
#define IRDMA_EP_MOVEACK      0x12
#define IRDMA_EP_MOVECMP      0x13
#define IRDMA_EP_DATA         0x21
#define IRDMA_EP_REUSEBUF     0x22
#define IRDMA_EP_RECVREQ      0x23
#define IRDMA_EP_RECVACK      0x24
#define IRDMA_EP_RECVNAK      0x25

/* IBM i RDMA Endpoint message offsets                               */
#define IRDMA_EP_TYPE         0     /* ( 1) Message type */
#define IRDMA_EP_LEN          1     /* ( 1) Message length */
#define IRDMA_EP_GRPID        2     /* (12) Group ID */
#define IRDMA_EP_GRPID_CTR    2     /*      ( 1) Uniqueness counter */
#define IRDMA_EP_GRPID_TIME   3     /*      ( 5) Bits 4-43 of TOD */
#define IRDMA_EP_GRPID_MAC    8     /*      ( 6) MAC address */
#define IRDMA_EP_SPORT       14     /* ( 2) Source port */
#define IRDMA_EP_DPORT       16     /* ( 2) Destination port */
#define IRDMA_EP_LINKSEQ     18     /* ( 2) Link sequence number */
#define IRDMA_EP_MIN_LENGTH  20

#define IRDMA_EP_CONNECT_BUFSIZE    20 /* ( 2) Send buffer size (* 4KB) */
#define IRDMA_EP_CONNECT_USRBLKSIZE 22 /* ( 2) USER_RDMA receive block size (* 4KB) */
#define IRDMA_EP_CONNECT_MIN_LENGTH 24

#define IRDMA_EP_CLOSE_REASON       20 /* ( 4) Close reason */
#define IRDMA_EP_CLOSE_MIN_LENGTH   24

#define IRDMA_EP_BUFFER_RKEY        20 /* ( 4) x2 Receive buffer MKeys */
#define IRDMA_EP_BUFFER_RADDR       28 /* ( 8) x2 Receive buffer addresses */
#define IRDMA_EP_BUFFER_FLAGS       44 /* ( 4 bits) Flags */
#define IRDMA_EP_BUFFER_RBUFSIZE    44 /* (12 bits) Size of each receive buffer (* 4KB) */
#define IRDMA_EP_MOVELINK_SENDSEQ   46 /* ( 2) Last sent sequence number */
#define IRDMA_EP_MOVELINK_RBUFSEQ   48 /* ( 2) x2 Last received sequence number */
#define IRDMA_EP_MOVELINK_USNDSENT  52 /* ( 4) Number of bytes sent from current USER_RDMA */
#define IRDMA_EP_MOVELINK_USNDID    56 /* ( 2) Current USER_RDMA recv ID being sent */
#define IRDMA_EP_MOVELINKACK_URCVID 58 /* ( 2) Last USER_RDMA recv ID complete */

#define IRDMA_EP_MOVELINKCMP_URCVID 20 /* ( 2) Last USER_RDMA recv ID complete */

#define IRDMA_EP_DATA_SEQNUM        20 /* ( 2) Sequence number */
#define IRDMA_EP_DATA_BUFID         22 /* ( 2) Buffer index */
#define IRDMA_EP_DATA_OFFSET        24 /* ( 4) Buffer offset */
#define IRDMA_EP_DATA_DATALEN       28 /* ( 4) Data length */
#define IRDMA_EP_DATA_MSG_LEN       32

#define IRDMA_EP_REUSE_SEQNUM       20 /* ( 2) Sequence number */
#define IRDMA_EP_REUSE_BUFID        22 /* ( 2) Buffer index */

#define IRDMA_EP_USERRECV_ULENGTH   20 /* ( 4) Total user receive length */
#define IRDMA_EP_USERRECV_OFFSET    24 /* ( 4) Offset within full buffer */
#define IRDMA_EP_USERRECV_RLENGTH   28 /* ( 4) Buffer length */
#define IRDMA_EP_USERRECV_RECVID    32 /* ( 2) Receive identifier */
#define IRDMA_EP_USERRECV_RKEY      34 /* ( 4) Buffer MKey */
#define IRDMA_EP_USERRECV_RADDR     38 /* ( 8) Buffer address */
#define IRDMA_EP_USERRECV_MSG_LEN   46

#define IRDMA_EP_USERSEND_ULENGTH   20 /* ( 4) Total user send length */
#define IRDMA_EP_USERSEND_OFFSET    24 /* ( 4) Offset within full buffer */
#define IRDMA_EP_USERSEND_SLENGTH   28 /* ( 4) Length sent */
#define IRDMA_EP_USERSEND_RECVID    32 /* ( 2) Receive identifier */
#define IRDMA_EP_USERSEND_MSG_LEN   34

static const value_string irdmaep_type_str[] = {
    {IRDMA_EP_CONNREQ,   "CONNREQ"},
    {IRDMA_EP_CONNACK,   "CONNACK"},
    {IRDMA_EP_CONNBUF,   "CONNBUF"},
    {IRDMA_EP_RNEGREQ,   "RNEGREQ"},
    {IRDMA_EP_RNEGACK,   "RNEGACK"},
    {IRDMA_EP_CLOSE,     "CLOSE"},
    {IRDMA_EP_RESET,     "RESET"},
    {IRDMA_EP_MOVEREQ,   "MOVEREQ"},
    {IRDMA_EP_MOVEACK,   "MOVEACK"},
    {IRDMA_EP_MOVECMP,   "MOVECMP"},
    {IRDMA_EP_DATA,      "DATA"},
    {IRDMA_EP_REUSEBUF,  "REUSEBUF"},
    {IRDMA_EP_RECVREQ,   "RECVREQ"},
    {IRDMA_EP_RECVACK,   "RECVACK"},
    {IRDMA_EP_RECVNAK,   "RECVNAK"},
    {0, NULL}};

static const value_string vals_free_inuse[] = {
    {0,   "In-use"},
    {1,   "Free"},
    {0,   NULL}};

/* Dissect RDMA Endpoint packets */
static int
dissect_irdmaep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *ti_seq, *ti_type;
    proto_tree *ep_tree, *ts_tree;
    proto_tree *grpid_tree;
    address group_addr;
    conversation_t *conv = NULL;
    irdmaep_analysis_t *epd = NULL;
    irdmaep_packet_analysis_t *eppd = NULL;
    uint32_t linkseq;
    nstime_t ts;

    if (tvb_reported_length(tvb) < IRDMA_EP_MIN_LENGTH)
        return 0;

    /* Set the Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDMA-EP");

    col_clear(pinfo->cinfo, COL_INFO);

    pinfo->srcport = tvb_get_ntohs(tvb, IRDMA_EP_SPORT);
    pinfo->destport = tvb_get_ntohs(tvb, IRDMA_EP_DPORT);
    pinfo->ptype = PT_TCP; /* Not really TCP, but nothing else better */
    irdma_col_append_ports(pinfo->cinfo, COL_INFO,
                           pinfo->srcport, pinfo->destport);

    set_address(&group_addr, AT_STRINGZ, 25,
                tvb_bytes_to_str(wmem_packet_scope(), tvb, IRDMA_EP_GRPID, 12));

    uint8_t msg_type = tvb_get_uint8(tvb, IRDMA_EP_TYPE);
    uint8_t msg_length = tvb_get_uint8(tvb, IRDMA_EP_LEN);
    const char *msg_type_str = val_to_str(msg_type, irdmaep_type_str,
                                          "UNKNOWN (0x%02X)");
    col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", msg_type_str);

    /* Find or create conversation for this packet */
    conv = find_conversation(pinfo->num, &group_addr, &group_addr,
                             CONVERSATION_NONE, pinfo->srcport, pinfo->destport, 0);

    /* If first time through the packets and conversation exists but message
       is a CONNREQ, check if we really should be starting a new conversation
       instead */
    if (!PINFO_FD_VISITED(pinfo)
        && conv
        && msg_type == IRDMA_EP_CONNREQ)
        {
        epd = (irdmaep_analysis_t *) conversation_get_proto_data(conv, proto_irdmaep);
        if (epd && epd->closed)
            conv = NULL;
        }

    /* If this is a new conversation, allocate conversation data */
    if (!conv)
        {
        conv = conversation_new(pinfo->num, &group_addr, &group_addr,
                                CONVERSATION_NONE, pinfo->srcport, pinfo->destport, 0);
        epd = init_irdmaep_conversation_data(pinfo);
        conversation_add_proto_data(conv, proto_irdmaep, epd);
        }
    else
        epd = (irdmaep_analysis_t *) conversation_get_proto_data(conv, proto_irdmaep);

    if (pinfo->num > conv->last_frame)
        conv->last_frame = pinfo->num;

    epd->fwd_flow = &epd->flow1;
    epd->rev_flow = &epd->flow2;
    if (pinfo->srcport < pinfo->destport)
        {
        epd->fwd_flow = &epd->flow2;
        epd->rev_flow = &epd->flow1;
        }

    /* Create display subtree for the Endpoint message */
    ti = proto_tree_add_item(tree, proto_irdmaep, tvb, 0, msg_length, ENC_NA);
    ep_tree = proto_item_add_subtree(ti, ett_irdmaep);

    ti_type = proto_tree_add_item(ep_tree, hf_irdmaep_type, tvb,
                                  IRDMA_EP_TYPE, 1, ENC_NA);
    proto_tree_add_item(ep_tree, hf_irdmaep_len, tvb,
                        IRDMA_EP_LEN, 1, ENC_NA);

    ti = proto_tree_add_item(ep_tree, hf_irdmaep_grpid, tvb,
                             IRDMA_EP_GRPID, 12, ENC_NA);
    grpid_tree = proto_item_add_subtree(ti, ett_irdmaep_grpid);

    proto_tree_add_item(grpid_tree, hf_irdmaep_grpid_ctr, tvb,
                        IRDMA_EP_GRPID_CTR, 1, ENC_NA);
    proto_tree_add_item(grpid_tree, hf_irdmaep_grpid_time, tvb,
                        IRDMA_EP_GRPID_TIME, 5, ENC_BIG_ENDIAN);
    proto_tree_add_item(grpid_tree, hf_irdmaep_grpid_hwaddr, tvb,
                        IRDMA_EP_GRPID_MAC, 6, ENC_NA);


    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_srcport, tvb,
                                 IRDMA_EP_SPORT, 2, ENC_BIG_ENDIAN,
                                 &pinfo->srcport);
    ti = proto_tree_add_item(ep_tree, hf_irdmaep_port, tvb,
                             IRDMA_EP_SPORT, 2, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(ti);

    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_dstport, tvb,
                                 IRDMA_EP_DPORT, 2, ENC_BIG_ENDIAN,
                                 &pinfo->destport);
    ti = proto_tree_add_item(ep_tree, hf_irdmaep_port, tvb,
                             IRDMA_EP_DPORT, 2, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(ti);
    ti = proto_tree_add_uint(ep_tree, hf_irdmaep_stream, tvb, 0, 0,
                             epd->stream);
    PROTO_ITEM_SET_GENERATED(ti);
    ti_seq = proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_linkseq, tvb,
                                          IRDMA_EP_LINKSEQ, 2, ENC_BIG_ENDIAN,
                                          &linkseq);

    /* Record conversation info that should only be done on first pass
       (when packets are seen in order) */
    if (!PINFO_FD_VISITED(pinfo))
        {
        if (irdmaep_calculate_ts)
            {
            if (!eppd)
                eppd = (irdmaep_packet_analysis_t *) get_or_add_eppd(pinfo);
            nstime_delta(&eppd->delta_time, &pinfo->abs_ts, &epd->ts_prev);

            nstime_copy(&epd->ts_prev, &pinfo->abs_ts);
            }

        /* If this is a CLOSE or RESET request, remember so that if we see a
           later CONNREQ with the same ports, we'll create a new conversation. */
        if (msg_type == IRDMA_EP_CLOSE
            || msg_type == IRDMA_EP_RESET)
            epd->closed = 1;

         /* If link seq not yet known, save current link seq */
         if (epd->link == 0xFFFFFFFF)
             epd->link = linkseq;

         /* Update current link seq if it has increased */
         if (seq16_gt(linkseq, epd->link))
             {
             epd->link = linkseq;
             if (!eppd)
                 eppd = (irdmaep_packet_analysis_t *) get_or_add_eppd(pinfo);
             eppd->linkswt = 1;
             }

         /* If packet is from prior link, set stale flag */
         if (seq16_lt(linkseq, epd->link))
             {
             if (!eppd)
                 eppd = (irdmaep_packet_analysis_t *) get_or_add_eppd(pinfo);
             eppd->seq_stale = 1;
             }
         }
    else
        eppd = (irdmaep_packet_analysis_t *) get_eppd(pinfo);

    if (eppd)
        {
        if (eppd->linkswt)
            expert_add_info(pinfo, ti_seq, &ei_irdmaep_connection_lswt);

        if (eppd->seq_stale)
            expert_add_info(pinfo, ti_seq, &ei_irdmaep_analysis_stale);
        }

    switch (msg_type)
        {
        case IRDMA_EP_DATA:
            dissect_data_msg(tvb, pinfo, tree, epd, ep_tree);
            break;

        case IRDMA_EP_REUSEBUF:
            dissect_reuse_msg(tvb, pinfo, epd, ep_tree);
            break;

        case IRDMA_EP_RECVREQ:
            dissect_user_recv_msg(tvb, pinfo, tree, epd, ep_tree);
            break;

        case IRDMA_EP_RECVACK:
        case IRDMA_EP_RECVNAK:
            dissect_user_send_msg(tvb, pinfo, tree, epd, ep_tree);
            break;

        case IRDMA_EP_CONNREQ:
            expert_add_info_format(pinfo, ti_type, &ei_irdmaep_connection_req,
                                   "Connection request (CONNREQ): server port %u",
                                   pinfo->destport);
            dissect_connect_msg(tvb, pinfo, epd, ep_tree);
            break;

        case IRDMA_EP_CONNACK:
            expert_add_info_format(pinfo, ti_type, &ei_irdmaep_connection_ack,
                                   "Connection acknowledgement (CONNACK): server port %u",
                                   pinfo->srcport);
            dissect_connect_msg(tvb, pinfo, epd, ep_tree);
            break;

        case IRDMA_EP_RNEGREQ:
            dissect_connect_msg(tvb, pinfo, epd, ep_tree);
            break;

        case IRDMA_EP_CLOSE:
            dissect_close_msg(tvb, pinfo, epd, ep_tree);
            break;

        case IRDMA_EP_CONNBUF:
        case IRDMA_EP_RNEGACK:
            dissect_buffer_msg(tvb, pinfo, epd, ep_tree);
            break;

        case IRDMA_EP_MOVEREQ:
            if (!PINFO_FD_VISITED(pinfo))
                {
                /* Save time of MOVEREQ so we can report link switch delay */
                epd->movereq_time = pinfo->abs_ts;
                }

            dissect_move_link_msg(tvb, pinfo, epd, ep_tree);
            break;

        case IRDMA_EP_MOVEACK:
            dissect_move_link_ack_msg(tvb, pinfo, epd, ep_tree);
            break;

        case IRDMA_EP_MOVECMP:
            dissect_move_link_cmp_msg(tvb, pinfo, epd, ep_tree);
            break;
        }

    ts_tree = proto_tree_add_subtree(ep_tree, tvb, 0, 0, ett_irdmaep_timestamps,
                                     &ti, "Timestamps");
    PROTO_ITEM_SET_GENERATED(ti);
    nstime_delta(&ts, &pinfo->abs_ts, &epd->ts_first);
    ti = proto_tree_add_time(ts_tree, hf_irdmaep_ts_relative, tvb, 0, 0, &ts);
    PROTO_ITEM_SET_GENERATED(ti);
    if (eppd && !nstime_is_unset(&eppd->delta_time))
        {
        ti = proto_tree_add_time(ts_tree, hf_irdmaep_ts_delta, tvb, 0, 0,
                                 &eppd->delta_time);
        PROTO_ITEM_SET_GENERATED(ti);
        }

    return tvb_captured_length(tvb);
}

static void
dissect_data_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 irdmaep_analysis_t *epd, proto_tree *ep_tree)
{
    proto_item *ti_seq;
    irdmaep_packet_analysis_t *eppd = NULL;
    irdmaep_pdata_t pdata = {IRDMAEP_DATA_TYPE};
    uint32_t bufid, seqnum, offset, datalen;

    ti_seq = proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_seqnum, tvb,
                                          IRDMA_EP_DATA_SEQNUM, 2, ENC_BIG_ENDIAN,
                                          &seqnum);
    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_bufid, tvb,
                                 IRDMA_EP_DATA_BUFID, 2, ENC_BIG_ENDIAN,
                                 &bufid);
    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_offset, tvb,
                                 IRDMA_EP_DATA_OFFSET, 4, ENC_BIG_ENDIAN,
                                 &offset);
    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_datalen, tvb,
                                 IRDMA_EP_DATA_DATALEN, 4, ENC_BIG_ENDIAN,
                                 &datalen);

    /* Update flow analysis only on first (in-order) pass */
    if (!PINFO_FD_VISITED(pinfo)
        && bufid < IRDMAEP_MAX_DATA_BUFID)
        {
        /* Only validate sequence number if we know previous seq# */
        if (epd->fwd_flow->data_seq_valid)
            {
            uint16_t expected = epd->fwd_flow->data_seq + 1;
            if (seqnum != expected)
                {
                /* Unexpected sequence number -- update packet data */
                eppd = (irdmaep_packet_analysis_t *) get_or_add_eppd(pinfo);
                if (seq16_lt(seqnum, expected))
                    eppd->retransmission = 1;
                else
                    eppd->out_of_order = 1; /* Should never occur! */
                }
            }

        epd->fwd_flow->data_seq_valid = 1;
        epd->fwd_flow->data_seq = seqnum;

        /* Update remote receive buffer status */
        /* First, if this gives info on receive buffer we didn't yet know about,
           bump buffer count but set those buffers to indeterminate state */
        for (; epd->fwd_flow->recv_buffer_count <= bufid; ++epd->fwd_flow->recv_buffer_count)
            epd->fwd_flow->recv_buffer[epd->fwd_flow->recv_buffer_count].indeterminate = 1;

        epd->fwd_flow->recv_mrb = bufid;
        epd->fwd_flow->recv_buffer[bufid].seq_num = seqnum;
        epd->fwd_flow->recv_buffer[bufid].offset = (offset + datalen + 0xF) & ~0xF;
        epd->fwd_flow->recv_buffer[bufid].indeterminate = 0;

        /* Adjust discovered size of buffer (in case initial buffer info msg
           wasn't captured for this flow) */
        if (epd->fwd_flow->recv_buffer[bufid].offset > epd->fwd_flow->recv_min_size)
            epd->fwd_flow->recv_min_size = (epd->fwd_flow->recv_buffer[bufid].offset + 0xFFF) & ~0xFFF;

        if (!eppd)
            eppd = (irdmaep_packet_analysis_t *) get_or_add_eppd(pinfo);
        analyze_irdmaep_rbuffer(epd->fwd_flow, eppd);
        }
    else
        eppd = (irdmaep_packet_analysis_t *) get_eppd(pinfo);

    if (eppd)
        {
        if (eppd->retransmission)
            {
            col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Retransmission] ");
            expert_add_info(pinfo, ti_seq, &ei_irdmaep_analysis_dup);
            }

        if (eppd->out_of_order)
            {
            col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Out-of-order] ");
            expert_add_info(pinfo, ti_seq, &ei_irdmaep_analysis_oos);
            }

        irdmaep_add_rbuf_tree(tvb, pinfo, ep_tree, eppd);
        }

    dissect_irdmaep_data(tvb_new_subset_remaining(tvb, IRDMA_EP_DATA_MSG_LEN),
                         pinfo, tree, &pdata);
}

static void
irdmaep_add_rbuf_tree(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                      irdmaep_packet_analysis_t *eppd)
{
    proto_item *ti;
    proto_tree *rcvbuf_tree;

    ti = proto_tree_add_uint(tree, hf_irdmaep_rbufavail, tvb, 0, 0,
                             eppd->rbuf_available);
    if (eppd->rbuf_estimated)
        proto_item_append_text(ti, " (min)");
    PROTO_ITEM_SET_GENERATED(ti);

    rcvbuf_tree = proto_item_add_subtree(ti, ett_irdmaep_rcvbuf_analyze);

    ti = proto_tree_add_uint(rcvbuf_tree, hf_irdmaep_rbufactive, tvb, 0, 0,
                             eppd->rbuf_cur);
    if (eppd->rbuf_estimated)
        proto_item_append_text(ti, " (min)");
    PROTO_ITEM_SET_GENERATED(ti);

    ti = proto_tree_add_uint(rcvbuf_tree, hf_irdmaep_rbufmax, tvb, 0, 0,
                             eppd->rbuf_max);
    if (eppd->rbuf_estimated)
        proto_item_append_text(ti, " (min)");
    PROTO_ITEM_SET_GENERATED(ti);
}

static void
dissect_reuse_msg(tvbuff_t *tvb, packet_info *pinfo,
                  irdmaep_analysis_t *epd, proto_tree *ep_tree)
{
    irdmaep_packet_analysis_t *eppd = NULL;
    uint32_t bufid, seqnum;

    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_seqnum, tvb,
                                 IRDMA_EP_REUSE_SEQNUM, 2, ENC_BIG_ENDIAN,
                                 &seqnum);
    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_bufid, tvb,
                                 IRDMA_EP_REUSE_BUFID, 2, ENC_BIG_ENDIAN,
                                 &bufid);

    /* Update receive buffer analysis only on first (in-order) pass */
    if (!PINFO_FD_VISITED(pinfo)
        && bufid < IRDMAEP_MAX_DATA_BUFID)
        {
        /* Reuse msg reflects local receive buffer status, so update lcl_rbuf */

        /* First, if this gives info on receive buffer we didn't yet know about,
           bump buffer count but set those buffers to indeterminate state */
        for (; epd->rev_flow->recv_buffer_count <= bufid; ++epd->rev_flow->recv_buffer_count)
            epd->rev_flow->recv_buffer[epd->rev_flow->recv_buffer_count].indeterminate = 1;

        if (epd->rev_flow->recv_buffer_count > 1
            || epd->rev_flow->recv_buffer[bufid].seq_num == seqnum
            || epd->rev_flow->recv_buffer[bufid].indeterminate)
            {
            epd->rev_flow->recv_buffer[bufid].offset = 0;
            epd->rev_flow->recv_buffer[bufid].indeterminate = 0;
            }

        eppd = (irdmaep_packet_analysis_t *) add_eppd(pinfo);
        analyze_irdmaep_rbuffer(epd->rev_flow, eppd);
        }
    else
        eppd = (irdmaep_packet_analysis_t *) get_eppd(pinfo);

    if (eppd)
        irdmaep_add_rbuf_tree(tvb, pinfo, ep_tree, eppd);
}

static void
dissect_user_recv_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      irdmaep_analysis_t *epd _U_, proto_tree *ep_tree)
{
    proto_item *ti;
    proto_tree *rbuf_tree;

    irdmaep_pdata_t pdata = {IRDMAEP_USERRDMA_TYPE, 0};

    proto_tree_add_item(ep_tree, hf_irdmaep_ulength, tvb,
                        IRDMA_EP_USERRECV_ULENGTH, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_offset, tvb,
                                 IRDMA_EP_USERRECV_OFFSET, 4, ENC_BIG_ENDIAN,
                                 &pdata.userrdma_offset);
    proto_tree_add_item(ep_tree, hf_irdmaep_blength, tvb,
                        IRDMA_EP_USERRECV_RLENGTH, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ep_tree, hf_irdmaep_recvid, tvb,
                        IRDMA_EP_USERRECV_RECVID, 2, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(ep_tree, hf_irdmaep_rbuf, tvb,
                             IRDMA_EP_USERRECV_RKEY, 12, ENC_NA);
    rbuf_tree = proto_item_add_subtree(ti, ett_irdmaep_rbuf);
    proto_tree_add_item(rbuf_tree, hf_irdmaep_rkey, tvb,
                        IRDMA_EP_USERRECV_RKEY, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(rbuf_tree, hf_irdmaep_raddr, tvb,
                        IRDMA_EP_USERRECV_RADDR, 8, ENC_BIG_ENDIAN);

    dissect_irdmaep_data(tvb_new_subset_remaining(tvb, IRDMA_EP_USERRECV_MSG_LEN),
                         pinfo, tree, &pdata);
}

static void
dissect_user_send_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      irdmaep_analysis_t *epd, proto_tree *ep_tree)
{
    proto_item *ti_ofs;
    irdmaep_packet_analysis_t *eppd = NULL;
    uint32_t recvid, offset, block_length, total_length;

    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_ulength, tvb,
                                 IRDMA_EP_USERSEND_ULENGTH, 4, ENC_BIG_ENDIAN,
                                 &total_length);
    ti_ofs = proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_offset, tvb,
                                          IRDMA_EP_USERSEND_OFFSET, 4, ENC_BIG_ENDIAN,
                                          &offset);
    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_blength, tvb,
                                 IRDMA_EP_USERSEND_SLENGTH, 4, ENC_BIG_ENDIAN,
                                 &block_length);
    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_recvid, tvb,
                                 IRDMA_EP_USERSEND_RECVID, 2, ENC_BIG_ENDIAN,
                                 &recvid);

    /* Update flow analysis only on first (in-order) pass */
    if (!PINFO_FD_VISITED(pinfo))
        {
        if (epd->fwd_flow->recvack_valid)
            {
            uint16_t nextid = epd->fwd_flow->recvack_id + 1;

            if ((recvid == epd->fwd_flow->recvack_id && offset == epd->fwd_flow->recvack_offset)
                || (recvid == nextid && offset == 0))
                {
                /* Expected ID, offset */
                }
            else
                {
                /* Unexpected offset */
                eppd = (irdmaep_packet_analysis_t *) get_or_add_eppd(pinfo);
                if (recvid == epd->fwd_flow->recvack_id
                    && offset < epd->fwd_flow->recvack_offset)
                    eppd->retransmission = 1;
                else
                    eppd->out_of_order = 1; /* Should never occur! */
                }
            }

        epd->fwd_flow->recvack_valid = 1;
        epd->fwd_flow->recvack_id = recvid;
        epd->fwd_flow->recvack_offset = offset + block_length;
        }
    else
        eppd = (irdmaep_packet_analysis_t *) get_eppd(pinfo);

    if (eppd)
        {
        if (eppd->retransmission)
            {
            col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Retransmission] ");
            expert_add_info(pinfo, ti_ofs, &ei_irdmaep_analysis_dup);
            }

        if (eppd->out_of_order)
            {
            col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Out-of-order] ");
            expert_add_info(pinfo, ti_ofs, &ei_irdmaep_analysis_oos);
            }
        }

    irdmaep_pdata_t pdata = {IRDMAEP_USERRDMA_TYPE, offset};
    dissect_irdmaep_data(tvb_new_subset_remaining(tvb, IRDMA_EP_USERSEND_MSG_LEN),
                         pinfo, tree, &pdata);
}

static void
dissect_connect_msg(tvbuff_t *tvb, packet_info *pinfo _U_,
                    irdmaep_analysis_t *epd _U_, proto_tree *ep_tree)
{
    proto_item *ti;
    uint32_t bufsize;

    ti = proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_sndbufsize, tvb,
                                      IRDMA_EP_CONNECT_BUFSIZE, 2,
                                      ENC_BIG_ENDIAN, &bufsize);
    proto_item_append_text(ti, " (%u KB)", bufsize * 4);

    uint8_t msg_type = tvb_get_uint8(tvb, IRDMA_EP_TYPE);
    if (msg_type == IRDMA_EP_CONNREQ
        || msg_type == IRDMA_EP_CONNACK)
        {
        ti = proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_usrblksize, tvb,
                                          IRDMA_EP_CONNECT_USRBLKSIZE, 2,
                                          ENC_BIG_ENDIAN, &bufsize);
        proto_item_append_text(ti, " (%u KB)", bufsize * 4);
        }
}

static void
dissect_close_msg(tvbuff_t *tvb, packet_info *pinfo _U_,
                  irdmaep_analysis_t *epd _U_, proto_tree *ep_tree)
{
    proto_tree_add_item(ep_tree, hf_irdmaep_reason, tvb,
                        IRDMA_EP_CLOSE_REASON, 4, ENC_BIG_ENDIAN);
}

static void
dissect_buffer_msg_mkeyaddr(tvbuff_t *tvb, packet_info *pinfo _U_,
                            irdmaep_analysis_t *epd _U_, proto_tree *ep_tree)
{
    proto_item *ti;
    proto_tree *rbuf_tree;

    ti = proto_tree_add_item(ep_tree, hf_irdmaep_rbuf, tvb,
                             IRDMA_EP_BUFFER_RKEY, 24, ENC_NA);
    rbuf_tree = proto_item_add_subtree(ti, ett_irdmaep_rbuf);
    proto_tree_add_item(rbuf_tree, hf_irdmaep_rkey, tvb,
                        IRDMA_EP_BUFFER_RKEY, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(rbuf_tree, hf_irdmaep_raddr, tvb,
                        IRDMA_EP_BUFFER_RADDR, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(rbuf_tree, hf_irdmaep_rkey, tvb,
                        IRDMA_EP_BUFFER_RKEY + 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(rbuf_tree, hf_irdmaep_raddr, tvb,
                        IRDMA_EP_BUFFER_RADDR + 8, 8, ENC_BIG_ENDIAN);
}

static void
dissect_buffer_msg(tvbuff_t *tvb, packet_info *pinfo,
                   irdmaep_analysis_t *epd, proto_tree *ep_tree)
{
    uint32_t rbufsize;

    dissect_buffer_msg_mkeyaddr(tvb, pinfo, epd, ep_tree);

    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_rcvbufsize, tvb,
                                 IRDMA_EP_BUFFER_RBUFSIZE, 2, ENC_BIG_ENDIAN,
                                 &rbufsize);
    rbufsize *= 4096;

    /* Update receive buffer analysis only on first (in-order) pass */
    if (!PINFO_FD_VISITED(pinfo))
        {
        if (tvb_get_uint32(tvb, IRDMA_EP_BUFFER_RKEY, ENC_BIG_ENDIAN))
            {
            memset(&epd->rev_flow->recv_buffer[0], 0,
                   sizeof epd->rev_flow->recv_buffer[0]);
            epd->rev_flow->recv_buffer[0].size = rbufsize;
            if (epd->rev_flow->recv_buffer_count < 1)
                epd->rev_flow->recv_buffer_count = 1;
            }

        if (tvb_get_uint32(tvb, IRDMA_EP_BUFFER_RKEY + 4, ENC_BIG_ENDIAN))
            {
            memset(&epd->rev_flow->recv_buffer[1], 0,
                   sizeof epd->rev_flow->recv_buffer[1]);
            epd->rev_flow->recv_buffer[1].size = rbufsize;
            if (epd->rev_flow->recv_buffer_count < 2)
                epd->rev_flow->recv_buffer_count = 2;
            }
        }
}

static void
dissect_move_link_msg(tvbuff_t *tvb, packet_info *pinfo,
                      irdmaep_analysis_t *epd, proto_tree *ep_tree)
{
    dissect_buffer_msg_mkeyaddr(tvb, pinfo, epd, ep_tree);

    proto_item *ti;
    proto_tree *flags_tree;
    uint32_t rbufsize;

    ti = proto_tree_add_item(ep_tree, hf_irdmaep_flags, tvb,
                             IRDMA_EP_BUFFER_FLAGS, 1, ENC_NA);
    flags_tree = proto_item_add_subtree(ti, ett_irdmaep_bufflags);
    proto_tree_add_item(flags_tree, hf_irdmaep_flag_buf0_free, tvb,
                        IRDMA_EP_BUFFER_FLAGS, 1, ENC_NA);
    proto_tree_add_item(flags_tree, hf_irdmaep_flag_buf1_free, tvb,
                        IRDMA_EP_BUFFER_FLAGS, 1, ENC_NA);
    proto_tree_add_item_ret_uint(ep_tree, hf_irdmaep_rcvbufsize, tvb,
                                 IRDMA_EP_BUFFER_RBUFSIZE, 2, ENC_BIG_ENDIAN,
                                 &rbufsize);

    proto_tree_add_item(ep_tree, hf_irdmaep_sendseq, tvb,
                        IRDMA_EP_MOVELINK_SENDSEQ, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ep_tree, hf_irdmaep_recvseq0, tvb,
                        IRDMA_EP_MOVELINK_RBUFSEQ, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ep_tree, hf_irdmaep_recvseq1, tvb,
                        IRDMA_EP_MOVELINK_RBUFSEQ + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ep_tree, hf_irdmaep_usndsent, tvb,
                        IRDMA_EP_MOVELINK_USNDSENT, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ep_tree, hf_irdmaep_usndid, tvb,
                        IRDMA_EP_MOVELINK_USNDID, 2, ENC_BIG_ENDIAN);

    /* Update receive buffer analysis only on first (in-order) pass */
    if (!PINFO_FD_VISITED(pinfo))
        {
        if (tvb_get_uint32(tvb, IRDMA_EP_BUFFER_RKEY, ENC_BIG_ENDIAN)
            && (rbufsize & 0x8000))
            {
            memset(&epd->rev_flow->recv_buffer[0], 0,
                   sizeof epd->rev_flow->recv_buffer[0]);
            epd->rev_flow->recv_buffer[0].size = (rbufsize & 0xFFF) * 4096;
            }

        if (tvb_get_uint32(tvb, IRDMA_EP_BUFFER_RKEY + 4, ENC_BIG_ENDIAN)
            && (rbufsize & 0x4000))
            {
            memset(&epd->rev_flow->recv_buffer[1], 0,
                   sizeof epd->rev_flow->recv_buffer[1]);
            epd->rev_flow->recv_buffer[1].size = (rbufsize & 0xFFF) * 4096;
            }
        }
}

static void
dissect_move_link_ack_msg(tvbuff_t *tvb, packet_info *pinfo,
                          irdmaep_analysis_t *epd, proto_tree *ep_tree)
{
    proto_item *ti;
    irdmaep_packet_analysis_t *eppd = NULL;

    if (!PINFO_FD_VISITED(pinfo))
        {
        eppd = (irdmaep_packet_analysis_t *) get_or_add_eppd(pinfo);

        nstime_delta(&eppd->movelink_time, &pinfo->abs_ts, &epd->movereq_time);
        }
    else
        eppd = (irdmaep_packet_analysis_t *) get_eppd(pinfo);

    dissect_move_link_msg(tvb, pinfo, epd, ep_tree);

    proto_tree_add_item(ep_tree, hf_irdmaep_urcvid, tvb,
                        IRDMA_EP_MOVELINKACK_URCVID, 2, ENC_BIG_ENDIAN);

    ti = proto_tree_add_time(ep_tree, hf_irdmaep_move1, tvb,
                             IRDMA_EP_TYPE, 0, &eppd->movelink_time);
    PROTO_ITEM_SET_GENERATED(ti);
}

static void
dissect_move_link_cmp_msg(tvbuff_t *tvb, packet_info *pinfo,
                          irdmaep_analysis_t *epd, proto_tree *ep_tree)
{
    proto_item *ti;
    irdmaep_packet_analysis_t *eppd = NULL;

    if (!PINFO_FD_VISITED(pinfo))
        {
        eppd = (irdmaep_packet_analysis_t *) get_or_add_eppd(pinfo);

        nstime_delta(&eppd->movelink_time, &pinfo->abs_ts, &epd->movereq_time);
        }
    else
        eppd = (irdmaep_packet_analysis_t *) get_eppd(pinfo);

    proto_tree_add_item(ep_tree, hf_irdmaep_urcvid, tvb,
                        IRDMA_EP_MOVELINKCMP_URCVID, 2, ENC_BIG_ENDIAN);

    ti = proto_tree_add_time(ep_tree, hf_irdmaep_move2, tvb,
                             IRDMA_EP_TYPE, 0, &eppd->movelink_time);
    PROTO_ITEM_SET_GENERATED(ti);
}

static void
dissect_irdmaep_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     irdmaep_pdata_t *pdata)
{
    irdmaep_packet_analysis_t *eppd = NULL;

    /* Should we try to call subdissector based on port? */
    if (!irdmaep_no_subdissector_on_error
        || !(eppd = (irdmaep_packet_analysis_t *) get_eppd(pinfo))
        || !eppd->retransmission)
        {
        uint32_t low_port, high_port;

        if (pinfo->srcport < pinfo->destport)
            {
            low_port = pinfo->srcport;
            high_port = pinfo->destport;
            }
        else
            {
            low_port = pinfo->destport;
            high_port = pinfo->srcport;
            }

        if (dissector_try_uint_new(irdmaep_dissector_table, low_port,
                                   tvb, pinfo, tree, true, pdata))
            return;

        if (dissector_try_uint_new(irdmaep_dissector_table, high_port,
                                   tvb, pinfo, tree, true, pdata))
            return;
        }

    /* If no subdissector (or error and skipped calling), just dissect as data */
    call_data_dissector(tvb, pinfo, tree);
}

static irdmaep_analysis_t *
init_irdmaep_conversation_data(packet_info *pinfo)
{
    irdmaep_analysis_t *epd
        = wmem_new0(wmem_file_scope(), irdmaep_analysis_t);

    epd->stream = irdmaep_stream_count++;
    epd->link = -1;

    nstime_copy(&epd->ts_first, &pinfo->abs_ts);
    nstime_copy(&epd->ts_prev, &pinfo->abs_ts);

    return epd;
}

static void *
get_eppd(packet_info *pinfo)
{
    return p_get_proto_data(wmem_file_scope(), pinfo, proto_irdmaep,
                            pinfo->curr_layer_num);
}

static void *
add_eppd(packet_info *pinfo)
{
    irdmaep_packet_analysis_t *eppd
        = wmem_new0(wmem_file_scope(), irdmaep_packet_analysis_t);
    p_add_proto_data(wmem_file_scope(), pinfo, proto_irdmaep,
                     pinfo->curr_layer_num, eppd);

    nstime_set_unset(&eppd->delta_time);
    return eppd;
}

static void *
get_or_add_eppd(packet_info *pinfo)
{
    irdmaep_packet_analysis_t *eppd = (irdmaep_packet_analysis_t *) get_eppd(pinfo);
    if (!eppd)
        eppd = (irdmaep_packet_analysis_t *) add_eppd(pinfo);

    return eppd;
}

static void
analyze_irdmaep_rbuffer(irdmaep_flow_t *flow,
                        irdmaep_packet_analysis_t *eppd)
{
    uint32_t bufid = flow->recv_mrb;

    /* Start by getting available space in the current receive
       buffer */
    if (flow->recv_buffer[bufid].size)
        eppd->rbuf_available
            = eppd->rbuf_cur
            = eppd->rbuf_max
            = flow->recv_buffer[bufid].size
                - flow->recv_buffer[bufid].offset;
    else
        {
        eppd->rbuf_available
            = eppd->rbuf_cur
            = eppd->rbuf_max
            = flow->recv_min_size
                - flow->recv_buffer[bufid].offset;
        eppd->rbuf_estimated = 1;
        }

    /* If there's a second receive buffer and it's empty, include
       it in receive buffer analysis */
    if (++bufid == IRDMAEP_MAX_DATA_BUFID)
        bufid = 0;
    if (flow->recv_buffer_count > 1
        && !flow->recv_buffer[bufid].indeterminate
        && flow->recv_buffer[bufid].offset == 0)
        {
        uint32_t size = flow->recv_buffer[bufid].size
                        ? flow->recv_buffer[bufid].size
                        : flow->recv_min_size;
        eppd->rbuf_available += size;
        if (size > eppd->rbuf_max)
            eppd->rbuf_max = size;
        }
}

/*********************************************************************/
/*********************************************************************/
/* Dissector registration functions                                  */
/*********************************************************************/
/*********************************************************************/

/* Register the protocol with Wireshark                              */
void
proto_register_irdma(void)
{
    module_t        *irdmaep_module;
    expert_module_t *expert_irdmaep;

    /*****************************************************************/
    /* RDMA pseudo-header field definitions                          */
    /*****************************************************************/
    static hf_register_info hf[] = {
        { &hf_irdma_hwdst,
          { "Destination", "irdma.dst",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Destination Hardware Address", HFILL }},
        { &hf_irdma_hwsrc,
           { "Source", "irdma.src",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              "Source Hardware Address", HFILL }},
        { &hf_irdma_qpindex,
           { "QP#", "irdma.qpidx",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "QP Index", HFILL}},
        { &hf_irdma_ip6src,
           { "Source IP", "irdma.ipv6.src",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              "Source IP Address", HFILL }},
        { &hf_irdma_ip6dst,
           { "Destination IP", "irdma.ipv6.dst",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              "Destination IP Address", HFILL }},
        { &hf_irdma_ip4src,
           { "Source IP", "irdma.ipv4.src",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              "Source IP Address", HFILL }},
        { &hf_irdma_ip4dst,
           { "Destination IP", "irdma.ipv4.dst",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              "Destination IP Address", HFILL }},
        { &hf_irdma_hwaddr,
           { "Address", "irdma.addr",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              "Source or Destination Hardware Address", HFILL}},
        { &hf_irdma_ip6addr,
           { "IP Address", "irdma.ipv6.addr",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              "Source or Destination IPv6 Address", HFILL}},
        { &hf_irdma_ip4addr,
           { "IP Address", "irdma.ipv4.addr",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              "Source or Destination IPv4 Address", HFILL}}
    };

    /*****************************************************************/
    /* RDMA QP field definitions                                     */
    /*****************************************************************/
    static hf_register_info hfqp[] = {
       { &hf_irdmaqp_type,
         { "Type", "irdma.qp.type",
           FT_UINT16, BASE_HEX, VALS(irdmaqp_type_str), 0x0,
           "RDMA QP Message Type", HFILL }},
       { &hf_irdmaqp_id,
          { "Identifier", "irdma.qp.echo.id",
             FT_UINT16, BASE_DEC, NULL, 0x0,
             "RDMA QP Echo Identifier", HFILL }}
    };

    /*****************************************************************/
    /* RDMA Link field definitions                                   */
    /*****************************************************************/
    static hf_register_info hflink[] = {
       { &hf_irdmalink_type,
           { "Type", "irdma.link.type",
             FT_UINT16, BASE_HEX, VALS(irdmalink_type_str), 0x0,
             "RDMA Link Message Type", HFILL }},
       { &hf_irdmalink_groups,
           { "Groups", "irdma.link.status.groups",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "RDMA Link Status Active Group Count", HFILL }}
    };

    /*****************************************************************/
    /* RDMA Endpoint field definitions                               */
    /*****************************************************************/
    static hf_register_info hfep[] = {
        { &hf_irdmaep_type,
            { "Type", "irdma.ep.type",
              FT_UINT8, BASE_DEC_HEX, VALS(irdmaep_type_str), 0x0,
              "RDMA Endpoint Message Type", HFILL }},
        { &hf_irdmaep_len,
            { "Length", "irdma.ep.len",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               "RDMA Endpoint Message Length", HFILL }},
        { &hf_irdmaep_grpid,
            { "Group ID", "irdma.ep.grpid",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               "RDMA Endpoint Group Identifier", HFILL }},
        { &hf_irdmaep_grpid_ctr,
            { "Counter", "irdma.ep.grpid.counter",
               FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
               "RDMA Endpoint Group Identifier Uniqueness Counter", HFILL }},
        { &hf_irdmaep_grpid_time,
            { "Time Generated", "irdma.ep.grpid.time",
               FT_UINT48, BASE_HEX_DEC, NULL, 0x0,
               "RDMA Endpoint Group Identifier Timestamp", HFILL }},
        { &hf_irdmaep_grpid_hwaddr,
            { "Hardware Address", "irdma.ep.grpid.hwaddr",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               "RDMA Endpoint Group Identifier Hardware Address", HFILL }},
        { &hf_irdmaep_srcport,
            { "Source Port", "irdma.ep.srcport",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(irdma_custom_format_port), 0x0,
               "RDMA Endpoint Source Port", HFILL }},
        { &hf_irdmaep_dstport,
            { "Destination Port", "irdma.ep.dstport",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(irdma_custom_format_port), 0x0,
               "RDMA Endpoint Destination Port", HFILL }},
        { &hf_irdmaep_port,
            { "Source or Destination Port", "irdma.ep.port",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               "RDMA Endpoint Source or Destination Port", HFILL }},
        { &hf_irdmaep_stream,
            { "Stream index", "irdma.ep.stream",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               "RDMA Endpoint Stream Index", HFILL }},
        { &hf_irdmaep_linkseq,
            { "Link Sequence", "irdma.ep.linkseq",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               "RDMA Endpoint Link Switch Sequence", HFILL }},
        { &hf_irdmaep_sndbufsize,
            { "Send Buffer Size", "irdma.ep.sndbufsize",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               "RDMA Endpoint Send Buffer Size", HFILL }},
        { &hf_irdmaep_usrblksize,
            { "User Block Size", "irdma.ep.usrblksize",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               "RDMA Endpoint USER_RDMA Block Size", HFILL }},
        { &hf_irdmaep_reason,
            { "Reason", "irdma.ep.reason",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,    /* TODO - Add Strings for reason? */
               "RDMA Endpoint Close Reason", HFILL }},
        { &hf_irdmaep_rbuf,
            { "Remote Memory", "irdma.ep.rbuf",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               "RDMA Endpoint Remote Memory Key/Address", HFILL }},
        { &hf_irdmaep_rkey,
            { "Remote Memory Key", "irdma.ep.rbuf.key",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               "RDMA Endpoint Remote Memory Key", HFILL }},
        { &hf_irdmaep_raddr,
            { "Remote Memory Address", "irdma.ep.rbuf.addr",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               "RDMA Endpoint Remote Memory Address", HFILL }},
        { &hf_irdmaep_flags,
            { "Flags", "irdma.ep.buffer.flags",
               FT_UINT8, BASE_HEX, NULL, 0xF0,
               "RDMA Endpoint Buffer Flags", HFILL }},
        { &hf_irdmaep_flag_buf0_free,
            { "Buffer #0", "irdma.ep.buffer.flags.buf0",
               FT_UINT8, 1, VALS(vals_free_inuse), 0x80,
               "RDMA Endpoint Buffer 0 Free Flag", HFILL }},
        { &hf_irdmaep_flag_buf1_free,
            { "Buffer #1", "irdma.ep.buffer.flags.buf1",
               FT_UINT8, 1, VALS(vals_free_inuse), 0x40,
               "RDMA Endpoint Buffer 1 Free Flag", HFILL }},
        { &hf_irdmaep_rcvbufsize,
            { "Receive Buffer Size", "irdma.ep.rcvbufsize",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(irdma_custom_format_rbufsize), 0x0,
               "RDMA Endpoint Receive Buffer Size", HFILL }},
        { &hf_irdmaep_sendseq,
            { "Last Send Sequence", "irdma.ep.sendseq",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint Last Successful Data Sequence Number", HFILL }},
        { &hf_irdmaep_recvseq0,
            { "Last Received Sequence (Buffer #0)", "irdma.ep.recvseq0",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint Last Received Data Sequence Number", HFILL }},
        { &hf_irdmaep_recvseq1,
            { "Last Received Sequence (Buffer #1)", "irdma.ep.recvseq1",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint Last Received Data Sequence Number", HFILL }},
        { &hf_irdmaep_usndsent,
            { "USER_RDMA Bytes Sent", "irdma.ep.usndsent",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint Bytes Sent From Current USER_RDMA Transfer", HFILL }},
        { &hf_irdmaep_usndid,
            { "USER_RDMA Send Identifier", "irdma.ep.usndid",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint Current USER_RDMA Send Identifier", HFILL }},
        { &hf_irdmaep_urcvid,
            { "USER_RDMA Receive Identifier Complete", "irdma.ep.urcvid",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint Last USER_RDMA Receive Identifier Completed", HFILL }},
        { &hf_irdmaep_seqnum,
            { "Send Sequence", "irdma.ep.seqnum",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint Data Sequence Number", HFILL }},
        { &hf_irdmaep_bufid,
            { "Buffer Identifier", "irdma.ep.bufid",
               FT_UINT16, BASE_DEC, NULL, 0x0,
              "RDMA Endpoint Buffer Identifier", HFILL }},
        { &hf_irdmaep_offset,
            { "Buffer Offset", "irdma.ep.offset",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              "RDMA Endpoint Buffer Offset", HFILL }},
        { &hf_irdmaep_datalen,
            { "Length", "irdma.ep.length",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint Data Length", HFILL }},
        { &hf_irdmaep_ulength,
            { "USER_RDMA Length", "irdma.ep.ulength",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint USER_RDMA Total Length", HFILL }},
        { &hf_irdmaep_blength,
            { "USER_RDMA Block Length", "irdma.ep.blength",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint USER_RDMA Block Length", HFILL }},
        { &hf_irdmaep_recvid,
            { "USER_RDMA Receive Identifier", "irdma.ep.recvid",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Endpoint USER_RDMA Receive Identifier", HFILL }},
        { &hf_irdmaep_rbufavail,
            { "Receive Buffer Available", "irdma.ep.analysis.rcvbuf",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Receive Buffer Bytes Available", HFILL }},
        { &hf_irdmaep_rbufactive,
            { "Active Receive Buffer Available", "irdma.ep.analysis.rcvbuf.active",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Active Receive Buffer Bytes Available", HFILL }},
        { &hf_irdmaep_rbufmax,
            { "Maximum Receive Buffer Available", "irdma.ep.analysis.rcvbuf.max",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
               "RDMA Maximum Receive Buffer Bytes Available", HFILL }},
        { &hf_irdmaep_move1,
            { "Server link switch time", "irdma.ep.analysis.linkswt.server",
               FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
               "RDMA server link switch time", HFILL }},
        { &hf_irdmaep_move2,
            { "Link switch time", "irdma.ep.analysis.linkswt",
               FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
               "RDMA link switch time", HFILL }},
        { &hf_irdmaep_ts_relative,
            { "Time since first frame in this RDMA stream", "irdma.ep.time_relative",
               FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
               "Time relative to first frame in this RDMA stream", HFILL }},
        { &hf_irdmaep_ts_delta,
            { "Time since previous frame in this RDMA stream", "irdma.ep.time_delta",
               FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
               "Time delta from previous frame in this RDMA stream", HFILL }}
    };

    /*****************************************************************/
    /* Protocol subtree array                                        */
    /*****************************************************************/
    static int *ett[] = {
        &ett_irdma,
        &ett_irdmaqp,
        &ett_irdmalink,
        &ett_irdmaep,
        &ett_irdmaep_grpid,
        &ett_irdmaep_rbuf,
        &ett_irdmaep_bufflags,
        &ett_irdmaep_rcvbuf_analyze,
        &ett_irdmaep_timestamps
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_irdmaep_analysis_stale,
            { "irdma.ep.analysis.stale", PI_SEQUENCE, PI_NOTE,
               "Packet received from prior link", EXPFILL }},
        { &ei_irdmaep_analysis_dup,
            { "irdma.ep.analysis.dup", PI_SEQUENCE, PI_CHAT,
               "Duplicate data packet (retransmission)", EXPFILL }},
        { &ei_irdmaep_analysis_oos,
            { "irdma.ep.analysis.oos", PI_SEQUENCE, PI_ERROR,
               "Out of order data packet", EXPFILL }},
        { &ei_irdmaep_connection_req,
            { "irdma.ep.connection.req", PI_SEQUENCE, PI_CHAT,
               "Connection request (CONNREQ)", EXPFILL }},
        { &ei_irdmaep_connection_ack,
            { "irdma.ep.connection.ack", PI_SEQUENCE, PI_CHAT,
               "Connection acknowledgement (CONNACK)", EXPFILL }},
        { &ei_irdmaep_connection_lswt,
            { "irdma.ep.connection.linkswt", PI_SEQUENCE, PI_NOTE,
               "Link switch", EXPFILL }}
    };

    /*****************************************************************/
    /* Register the protocols                                        */
    /*****************************************************************/
    proto_irdma = proto_register_protocol("IBM i RDMA", "iRDMA", "irdma");
    proto_irdmaqp = proto_register_protocol("IBM i RDMA QP", "iRDMA-QP", "irdma.qp");
    proto_irdmalink = proto_register_protocol("IBM i RDMA Link", "iRDMA-Link", "irdma.link");
    proto_irdmaep = proto_register_protocol("IBM i RDMA Endpoint", "iRDMA-EP", "irdma.ep");

    register_init_routine(irdma_init);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_irdma, hf, array_length(hf));
    proto_register_field_array(proto_irdmaqp, hfqp, array_length(hfqp));
    proto_register_field_array(proto_irdmalink, hflink, array_length(hflink));
    proto_register_field_array(proto_irdmaep, hfep, array_length(hfep));

    proto_register_subtree_array(ett, array_length(ett));

    // Register a dissector table to allow sub-dissectors to register based on EP port
    irdmaep_dissector_table
        = register_dissector_table("irdma.ep.port", "RDMA EP Port", proto_irdmaep, FT_UINT16, BASE_DEC);

    /* Required function calls to register expert items */
    expert_irdmaep = expert_register_protocol(proto_irdmaep);
    expert_register_field_array(expert_irdmaep, ei, array_length(ei));

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_irdma in the following.
     */
    prefs_register_protocol(proto_irdma, proto_reg_handoff_irdma);
    irdmaep_module = prefs_register_protocol(proto_irdmaep, NULL);
    prefs_register_bool_preference(irdmaep_module, "calculate_timestamps",
        "Calculate conversation timestamps",
        "Calculate timestamps relative to the first frame and the previous frame in the RDMA conversation",
        &irdmaep_calculate_ts);
    prefs_register_bool_preference(irdmaep_module, "no_subdissector_on_error",
        "Do not call subdissectors for error packets",
        "Do not call any subdissectors for retransmitted segments",
        &irdmaep_no_subdissector_on_error);

    register_dissector("irdma", dissect_irdma, proto_irdma);
}

/* Simpler form of proto_reg_handoff_irdma which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_irdma(void)
{
    /* Use create_dissector_handle() to get the handles to IBM i RDMA
     * subdissectors.
     */
    irdmaqp_handle = create_dissector_handle(dissect_irdmaqp, proto_irdmaqp);
    irdmalink_handle = create_dissector_handle(dissect_irdmalink, proto_irdmalink);
    irdmaep_handle = create_dissector_handle(dissect_irdmaep, proto_irdmaep);
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
