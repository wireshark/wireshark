/* packet-vj.c
 * Routines for Van Jacobson header decompression.  (See RFC 1144.)
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 *
 * This file created by Irfan Khan <ikhan@qualcomm.com>
 * Copyright (c) 2001  by QUALCOMM, Incorporated.
 * All Rights reserved.
 *
 * Routines to compress and uncompress TCP packets (for transmission
 * over low speed serial lines).
 *
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *      Van Jacobson (van@helios.ee.lbl.gov), Dec 31, 1989:
 *      - Initial distribution.
 *
 *
 * modified for KA9Q Internet Software Package by
 * Katie Stevens (dkstevens@ucdavis.edu)
 * University of California, Davis
 * Computing Services
 *      - 01-31-90      initial adaptation (from 1.19)
 *      PPP.05  02-15-90 [ks]
 *      PPP.08  05-02-90 [ks]   use PPP protocol field to signal compression
 *      PPP.15  09-90    [ks]   improve mbuf handling
 *      PPP.16  11-02    [karn] substantially rewritten to use NOS facilities
 *
 *      - Feb 1991      Bill_Simpson@um.cc.umich.edu
 *                      variable number of conversation slots
 *                      allow zero or one slots
 *                      separate routines
 *                      status display
 *      - Jul 1994      Dmitry Gorodchanin
 *                      Fixes for memory leaks.
 *      - Oct 1994      Dmitry Gorodchanin
 *                      Modularization.
 *      - Jan 1995      Bjorn Ekwall
 *                      Use ip_fast_csum from ip.h
 *      - July 1995     Christos A. Polyzols
 *                      Spotted bug in tcp option checking
 *      - Sep 2001      Irfan Khan
 *                      Rewrite to make the code work for ethereal.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-ppp.h"
#include <epan/ppptypes.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/emem.h>

/* Define relevant IP/TCP parameters */
#define IP_FIELD_TOT_LEN      2 /* Total length field in IP hdr           */
#define IP_FIELD_PROTOCOL     9 /* Protocol field byte in IP hdr          */
#define IP_ADDR_SIZE          4 /* Size in bytes of IPv4 address          */
#define IP_FIELD_SRC         12 /* Byte 12 in IP hdr - src address        */
#define IP_FIELD_DST         16 /* Byte 16 in IP hdr - dst address        */
#define IP_HDR_LEN           20 /* Minimum IP header length               */
#define IP_HDR_LEN_MASK    0x0f /* Mask for header length field           */
#define IP_MAX_OPT_LEN       44 /* Max length of IP options               */
#define TCP_FIELD_HDR_LEN    12 /* Data offset field in TCP hdr           */
#define TCP_HDR_LEN          20 /* Minimum TCP header length              */
#define TCP_MAX_OPT_LEN      44 /* Max length of TCP options              */
#define TCP_SIMUL_CONV_MAX  256 /* Max number of simul. TCP conversations */
#define TCP_PUSH_BIT       0x08 /* TCP push bit                           */
#define TCP_URG_BIT        0x20 /* TCP urgent bit                         */

/* Bits in first octet of compressed packet */
/* flag bits for what changed in a packet */
#define NEW_C           0x40 /* Connection number changed               */
#define NEW_I           0x20 /* IP sequence number change by value != 1 */
#define CHANGE_PUSH_BIT 0x10 /* TCP push bit set                        */
#define NEW_S           0x08 /* Sequence number changed                 */
#define NEW_A           0x04 /* Ack sequence number changed             */
#define NEW_W           0x02 /* Window changed                          */
#define NEW_U           0x01 /* Urgent pointer present                  */

/* reserved, special-case values of above */
#define SPECIAL_I     (NEW_S|NEW_W|NEW_U)    /* echoed interactive traffic */
#define SPECIAL_D     (NEW_S|NEW_A|NEW_W|NEW_U)/* unidirectional data */
#define SPECIALS_MASK (NEW_S|NEW_A|NEW_W|NEW_U)

/* Function return values */
#define VJ_OK           0
#define VJ_ERROR       -1

/* Define for 0 */
#define ZERO            0

/* VJ Mem Chunk defines */
#define VJ_DATA_SIZE  128 /* Max IP hdr(64)+Max TCP hdr(64) */

/* IP and TCP header types */
typedef struct {
  guint8  ihl_version;
  guint8  tos;
  guint16 tot_len;
  guint16 id;
  guint16 frag_off;
  guint8  ttl;
  guint8  proto;
  guint16 cksum;
  guint32 src;
  guint32 dst;
} iphdr_type;

typedef struct {
  guint16 srcport;
  guint16 dstport;
  guint32 seq;
  guint32 ack_seq;
  guint8  off_x2;
  guint8  flags;
  guint16 window;
  guint16 cksum;
  guint16 urg_ptr;
} tcphdr_type;

#define TCP_OFFSET(th)  (((th)->off_x2 & 0xf0) >> 4)

/* State per active tcp conversation */
typedef struct cstate {
  iphdr_type cs_ip;
  tcphdr_type cs_tcp;
  guint8 cs_ipopt[IP_MAX_OPT_LEN];
  guint8 cs_tcpopt[TCP_MAX_OPT_LEN];
  guint32 flags;
#define SLF_TOSS  0x00000001    /* tossing rcvd frames until id received */
} cstate;

/* All the state data for one serial line */
typedef struct {
  cstate rstate[TCP_SIMUL_CONV_MAX]; /* receive connection states (array) */
  guint8 recv_current;               /* most recent rcvd id */
} slcompress;

/* Initialize the protocol and registered fields */
static int proto_vj = -1;

static int hf_vj_change_mask = -1;
static int hf_vj_change_mask_c = -1;
static int hf_vj_change_mask_i = -1;
static int hf_vj_change_mask_p = -1;
static int hf_vj_change_mask_s = -1;
static int hf_vj_change_mask_a = -1;
static int hf_vj_change_mask_w = -1;
static int hf_vj_change_mask_u = -1;
static int hf_vj_connection_number = -1;
static int hf_vj_tcp_cksum = -1;
static int hf_vj_urp = -1;
static int hf_vj_win_delta = -1;
static int hf_vj_ack_delta = -1;
static int hf_vj_seq_delta = -1;
static int hf_vj_ip_id_delta = -1;

static gint ett_vj = -1;
static gint ett_vj_changes = -1;

/* Protocol handles */
static dissector_handle_t ip_handle;
static dissector_handle_t data_handle;

/* State repository (Full Duplex) */
#define RX_TX_STATE_COUNT 2
static slcompress *rx_tx_state[RX_TX_STATE_COUNT] = {NULL, NULL};

/* Mem Chunks for storing decompressed headers */
typedef struct {
	int	offset;			/* uppermost bit is "can't dissect" flag */
	guint8	data[VJ_DATA_SIZE];
} vj_header_t;

/* Function prototypes */
static int get_unsigned_delta(tvbuff_t *tvb, int *offsetp, int hf,
                        proto_tree *tree);
static int get_signed_delta(tvbuff_t *tvb, int *offsetp, int hf,
                        proto_tree *tree);
static guint16 ip_csum(const guint8 *ptr, guint32 len);
static slcompress *slhc_init(void);
static void vj_init(void);
static gint vjc_process(tvbuff_t *src_tvb, packet_info *pinfo, proto_tree *tree,
                      slcompress *comp);
static gint vjc_tvb_setup(tvbuff_t *src_tvb, tvbuff_t **dst_tvb,
                          packet_info *pinfo);

/* Dissector for VJ Uncompressed packets */
static void
dissect_vjuc(tvbuff_t *tvb, packet_info *pinfo, proto_tree * tree)
{
  proto_item *ti;
  proto_tree *vj_tree     = NULL;
  slcompress *comp;
  int         i;
  gint        conn_index;
  cstate     *cs          = NULL;
  guint8      ihl;
  guint8      thl;
  guint8     *buffer;
  tvbuff_t   *next_tvb;
  gint        isize       = tvb_length(tvb);
  gint        ipsize;

  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_INFO, "PPP VJ");

  if(tree != NULL) {
    ti = proto_tree_add_protocol_format(tree, proto_vj, tvb, 0, -1,
                                        "PPP VJ Compression: Uncompressed data");
    vj_tree = proto_item_add_subtree(ti, ett_vj);
  }

  if(pinfo->p2p_dir == P2P_DIR_UNKNOWN) {
    /* Direction of the traffic unknown - can't update state */
    comp = NULL;
  } else {
    /* Get state for that direction */
    comp = rx_tx_state[pinfo->p2p_dir];
  }

  /*
   * Check to make sure we can fetch the connection index.
   */
  if(!tvb_bytes_exist(tvb, IP_FIELD_PROTOCOL, 1)) {
    /*
     * We don't.  We can't even mark a connection as non-decompressable,
     * as we don't know which connection this is.  Mark them all as
     * non-decompressable.
     */
    if(check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "VJ uncompressed TCP (not enough data available)");
    if(tree != NULL)
      call_dissector(data_handle, tvb, pinfo, tree);
    if(comp != NULL) {
      for(i = 0; i < TCP_SIMUL_CONV_MAX; i++)
        comp->rstate[i].flags |= SLF_TOSS;
    }
    return;
  }

  /* Get connection index */
  conn_index = tvb_get_guint8(tvb, IP_FIELD_PROTOCOL);
  if(tree != NULL)
    proto_tree_add_uint(vj_tree, hf_vj_connection_number, tvb,
                        IP_FIELD_PROTOCOL, 1, conn_index);

  /*
   * Update the current connection, and get a pointer to its state.
   */
  if(comp != NULL) {
    comp->recv_current = conn_index;
    cs = &comp->rstate[conn_index];
  }

  /* Get the IP header length */
  ihl = tvb_get_guint8(tvb, 0) & IP_HDR_LEN_MASK;
  ihl <<= 2;

  /* Check IP header length */
  if(ihl < IP_HDR_LEN) {
    if(check_col(pinfo->cinfo, COL_INFO)) {
      col_add_fstr(pinfo->cinfo, COL_INFO, "VJ uncompressed TCP (IP header length (%u) < %u)",
                   ihl, IP_HDR_LEN);
    }
    if(cs != NULL)
      cs->flags |= SLF_TOSS;
    return;
  }

  /* Make sure we have the full IP header */
  if(isize < ihl) {
    if(check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "VJ uncompressed TCP (not enough data available)");
    if(tree != NULL)
      call_dissector(data_handle, tvb, pinfo, tree);
    if(cs != NULL)
      cs->flags |= SLF_TOSS;
    return;
  }

  if(check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "VJ uncompressed TCP");

  /*
   * Copy packet data to a buffer, and replace the connection index with
   * the protocol type (which is always TCP), to give the actual IP header.
   */
  buffer = tvb_memdup(tvb, 0, isize);
  buffer[IP_FIELD_PROTOCOL] = IP_PROTO_TCP;

  /* Check IP checksum */
  if(ip_csum(buffer, ihl) != ZERO) {
    /*
     * Checksum invalid - don't update state, and don't decompress
     * any subsequent compressed packets in this direction.
     */
    if(cs != NULL)
      cs->flags |= SLF_TOSS;
    cs = NULL;  /* disable state updates */
  } else {
    /* Do we have the TCP header length in the tvbuff? */
    if(!tvb_bytes_exist(tvb, ihl + TCP_FIELD_HDR_LEN, 1)) {
      /* We don't, so we can't provide enough data for decompression */
      if(check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "VJ uncompressed TCP (not enough data available)");
      if(cs != NULL)
        cs->flags |= SLF_TOSS;
      cs = NULL;  /* disable state updates */
    } else {
      /* Get the TCP header length */
      thl = tvb_get_guint8(tvb, ihl + TCP_FIELD_HDR_LEN);
      thl = ((thl & 0xf0) >> 4) * 4;

      /* Check TCP header length */
      if(thl < TCP_HDR_LEN) {
        if(check_col(pinfo->cinfo, COL_INFO)) {
          col_add_fstr(pinfo->cinfo, COL_INFO, "VJ uncompressed TCP (TCP header length (%u) < %u)",
                       thl, TCP_HDR_LEN);
        }
        if(cs != NULL)
          cs->flags |= SLF_TOSS;
        cs = NULL;  /* disable state updates */
      } else {
        /* Make sure we have the full TCP header */
        if(isize < thl) {
          if(check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "VJ uncompressed TCP (not enough data available)");
          if(cs != NULL)
            cs->flags |= SLF_TOSS;
          cs = NULL;  /* disable state updates */
        }
      }
    }
  }

  /*
   * If packet seen for first time, update state if we have state and can
   * update it.
   */
  if(!pinfo->fd->flags.visited) {
    if(cs != NULL) {
      cs->flags &= ~SLF_TOSS;
      memcpy(&cs->cs_ip, &buffer[0], IP_HDR_LEN);
      memcpy(&cs->cs_tcp, &buffer[ihl], TCP_HDR_LEN);
      if(ihl > IP_HDR_LEN)
        memcpy(cs->cs_ipopt, &buffer[sizeof(iphdr_type)], ihl - IP_HDR_LEN);
      if(TCP_OFFSET(&(cs->cs_tcp)) > 5)
        memcpy(cs->cs_tcpopt, &buffer[ihl + sizeof(tcphdr_type)],
                   (TCP_OFFSET(&(cs->cs_tcp)) - 5) * 4);
    }
  }

  /*
   * Set up tvbuff containing packet with protocol type.
   * Neither header checksum is recalculated.
   *
   * Use the length field from the IP header as the reported length;
   * use the minimum of that and the number of bytes we got from
   * the tvbuff as the actual length, just in case the tvbuff we were
   * handed includes part or all of the FCS (because the FCS preference
   * for the PPP dissector doesn't match the FCS size in this session).
   */
  ipsize = pntohs(&buffer[IP_FIELD_TOT_LEN]);
  if (ipsize < isize)
    isize = ipsize;
  next_tvb = tvb_new_real_data(buffer, isize, ipsize);
  tvb_set_child_real_data_tvbuff(tvb, next_tvb);
  add_new_data_source(pinfo, next_tvb, "VJ Uncompressed");

  /*
   * Call IP dissector.
   */
  call_dissector(ip_handle, next_tvb, pinfo, tree);
}

/* Dissector for VJ Compressed packets */
static void
dissect_vjc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *vj_tree     = NULL;
  tvbuff_t   *next_tvb = NULL;
  slcompress *comp     = NULL;
  gint        err      = VJ_ERROR;

  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_INFO, "PPP VJ");

  if(tree != NULL) {
    ti = proto_tree_add_protocol_format(tree, proto_vj, tvb, 0, -1,
                                        "PPP VJ Compression: Compressed data");
    vj_tree = proto_item_add_subtree(ti, ett_vj);
  }

  if(!ppp_vj_decomp || pinfo->p2p_dir == P2P_DIR_UNKNOWN) {
    /*
     * VJ decompression turned off, so we shouldn't decompress, or
     * direction of the traffic unknown, so we can't decompress.
     */
    comp = NULL;
  } else {
    /* Get state for that direction */
    comp = rx_tx_state[pinfo->p2p_dir];
  }

  /* Process the compressed data header */
  if(vjc_process(tvb, pinfo, vj_tree, comp) == VJ_ERROR)
    return;

  /* Decompression possible - set up tvb containing decompressed packet */
  err = vjc_tvb_setup(tvb, &next_tvb, pinfo);
  if(err == VJ_ERROR) {
    if(tree != NULL)
      call_dissector(data_handle, tvb, pinfo, vj_tree);
    return;
  }

  /* No errors, so call IP dissector */
  call_dissector(ip_handle, next_tvb, pinfo, tree);
}

/* Registration functions for dissectors */
void
proto_register_vj(void)
{
  static hf_register_info hf[] = {
    { &hf_vj_change_mask,
      { "Change mask",	"vj.change_mask",	FT_UINT8, BASE_HEX,
        NULL, 0x0, "", HFILL }},
    { &hf_vj_change_mask_c,
      { "Connection changed",		"vj.change_mask_c",	FT_BOOLEAN, 8,
        NULL, NEW_C, "Connection number changed", HFILL }},
    { &hf_vj_change_mask_i,
      { "IP ID change != 1",		"vj.change_mask_i",	FT_BOOLEAN, 8,
        NULL, NEW_I, "IP ID changed by a value other than 1", HFILL }},
    { &hf_vj_change_mask_p,
      { "Push bit set",			"vj.change_mask_p",	FT_BOOLEAN, 8,
        NULL, CHANGE_PUSH_BIT, "TCP PSH flag set", HFILL }},
    { &hf_vj_change_mask_s,
      { "Sequence number changed",	"vj.change_mask_s",	FT_BOOLEAN, 8,
        NULL, NEW_S, "Sequence number changed", HFILL }},
    { &hf_vj_change_mask_a,
      { "Ack number changed",		"vj.change_mask_a",	FT_BOOLEAN, 8,
        NULL, NEW_A, "Acknowledgement sequence number changed", HFILL }},
    { &hf_vj_change_mask_w,
      { "Window changed",		"vj.change_mask_w",	FT_BOOLEAN, 8,
        NULL, NEW_W, "TCP window changed", HFILL }},
    { &hf_vj_change_mask_u,
      { "Urgent pointer set",		"vj.change_mask_u",	FT_BOOLEAN, 8,
        NULL, NEW_U, "Urgent pointer set", HFILL }},
    { &hf_vj_connection_number,
      { "Connection number",	"vj.connection_number",	FT_UINT8, BASE_DEC,
        NULL, 0x0, "Connection number", HFILL }},
    { &hf_vj_tcp_cksum,
      { "TCP checksum",			"vj.tcp_cksum",	FT_UINT16, BASE_HEX,
        NULL, 0x0, "TCP checksum", HFILL }},
    { &hf_vj_urp,
      { "Urgent pointer",		"vj.urp",	FT_UINT16, BASE_DEC,
        NULL, 0x0, "Urgent pointer", HFILL }},
    { &hf_vj_win_delta,
      { "Window delta",			"vj.win_delta",	FT_INT16, BASE_DEC,
        NULL, 0x0, "Delta for window", HFILL }},
    { &hf_vj_ack_delta,
      { "Ack delta",			"vj.ack_delta",	FT_UINT16, BASE_DEC,
        NULL, 0x0, "Delta for acknowledgment sequence number", HFILL }},
    { &hf_vj_seq_delta,
      { "Sequence delta",		"vj.seq_delta",	FT_UINT16, BASE_DEC,
        NULL, 0x0, "Delta for sequence number", HFILL }},
    { &hf_vj_ip_id_delta,
      { "IP ID delta",			"vj.ip_id_delta",	FT_UINT16, BASE_DEC,
        NULL, 0x0, "Delta for IP ID", HFILL }},
  };
  static gint *ett[] = {
    &ett_vj,
    &ett_vj_changes,
  };

  proto_vj = proto_register_protocol("PPP VJ Compression", "PPP VJ", "vj");
  proto_register_field_array(proto_vj, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&vj_init);
}

void
proto_reg_handoff_vj(void)
{
  dissector_handle_t vjc_handle;
  dissector_handle_t vjuc_handle;

  vjc_handle = create_dissector_handle(dissect_vjc, proto_vj);
  dissector_add("ppp.protocol", PPP_VJC_COMP, vjc_handle);

  vjuc_handle = create_dissector_handle(dissect_vjuc, proto_vj);
  dissector_add("ppp.protocol", PPP_VJC_UNCOMP, vjuc_handle);

  ip_handle = find_dissector("ip");
  data_handle = find_dissector("data");
}

/* Initialization function */
static void
vj_init(void)
{
  gint i           = ZERO;

  for(i = 0; i < RX_TX_STATE_COUNT; i++) {
    rx_tx_state[i] = slhc_init();
  }
  return;
}

/* Initialization routine for VJ decompression */
static slcompress *
slhc_init(void)
{
  slcompress *comp = se_alloc(sizeof(slcompress));
  int         i;

  memset(comp, ZERO, sizeof(slcompress));

  /*
   * Initialize the state; there is no current connection, and
   * we have no header data for any of the connections, as we
   * haven't yet seen an uncompressed frame.
   */
  comp->recv_current = TCP_SIMUL_CONV_MAX - 1;
  for (i = 0; i < TCP_SIMUL_CONV_MAX; i++)
    comp->rstate[i].flags |= SLF_TOSS;
  return comp;
}

/* Setup the decompressed packet tvb for VJ compressed packets */
static gint
vjc_tvb_setup(tvbuff_t *src_tvb,
              tvbuff_t **dst_tvb,
              packet_info *pinfo)
{
  vj_header_t *hdr_buf;
  guint8       offset;
  guint8      *data_ptr;
  iphdr_type  *ip;
  tcphdr_type *thp;
  gint         hdr_len;
  gint         buf_len;
  guint8      *pbuf;

  DISSECTOR_ASSERT(src_tvb);

  /* Get decompressed header stored in fd protocol area */
  hdr_buf = p_get_proto_data(pinfo->fd, proto_vj);
  if(hdr_buf == NULL) {
    if(check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "VJ compressed TCP (previous data bad or missing)");
    return VJ_ERROR;
  }

  if(check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "VJ compressed TCP");

  /* Get the data offset in the tvbuff */
  offset  = hdr_buf->offset;

  /* Copy header and form tvb */
  data_ptr = hdr_buf->data;
  ip = (iphdr_type *)data_ptr;
  hdr_len  = lo_nibble(ip->ihl_version) * 4;
  thp = (tcphdr_type *)(data_ptr + hdr_len);
  hdr_len += TCP_OFFSET(thp) * 4;
  buf_len  = tvb_length(src_tvb) + hdr_len - offset;
  pbuf     = g_malloc(buf_len);
  memcpy(pbuf, data_ptr, hdr_len);
  tvb_memcpy(src_tvb, pbuf + hdr_len, offset, buf_len - hdr_len);
  *dst_tvb = tvb_new_real_data(pbuf, buf_len, g_ntohs(ip->tot_len));
  tvb_set_child_real_data_tvbuff(src_tvb, *dst_tvb);
  add_new_data_source(pinfo, *dst_tvb, "VJ Decompressed");
  return VJ_OK;
}

/*
 * For VJ compressed packet:
 *
 *	check if it is malformed;
 *	dissect the relevant fields;
 *	update the decompressor state on the first pass.
 */
static gint
vjc_process(tvbuff_t *src_tvb, packet_info *pinfo, proto_tree *tree,
            slcompress *comp)
{
  int            offset     = ZERO;
  int            i;
  gint           changes;
  proto_item    *ti;
  proto_tree    *changes_tree;
  guint8         conn_index;
  cstate        *cs         = NULL;
  iphdr_type    *ip         = NULL;
  tcphdr_type   *thp        = NULL;
  guint16        tcp_cksum;
  gint           hdrlen     = ZERO;
  guint16        word;
  int            delta;
  gint           len;
  vj_header_t   *buf_hdr;
  guint8        *data_ptr;

  if(tvb_length(src_tvb) < 3){
    /*
     * We don't even have enough data for the change byte, so we can't
     * determine which connection this is; mark all connections as
     * non-decompressible.
     */
    if(check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "VJ compressed TCP (not enough data available)");
    if(tree != NULL)
      call_dissector(data_handle, src_tvb, pinfo, tree);
    if(comp != NULL) {
      for(i = 0; i < TCP_SIMUL_CONV_MAX; i++)
        comp->rstate[i].flags |= SLF_TOSS;
    }
    return VJ_ERROR;
  }

  /* Read the change byte */
  changes = tvb_get_guint8(src_tvb, offset);
  if(tree != NULL) {
    switch (changes & SPECIALS_MASK) {

    case SPECIAL_I:
      ti = proto_tree_add_uint_format(tree, hf_vj_change_mask, src_tvb,
                                      offset, 1, changes,
                                      "Change mask: 0x%02x (echoed interactive traffic)",
                                      changes);
      break;

    case SPECIAL_D:
      ti = proto_tree_add_uint_format(tree, hf_vj_change_mask, src_tvb,
                                      offset, 1, changes,
                                      "Change mask: 0x%02x (unidirectional data)",
                                      changes);
      break;

    default:
      /*
       * XXX - summarize bits?
       */
      ti = proto_tree_add_uint_format(tree, hf_vj_change_mask, src_tvb,
                                      offset, 1, changes,
                                      "Change mask: 0x%02x", changes);
      break;
    }
    changes_tree = proto_item_add_subtree(ti, ett_vj_changes);
    proto_tree_add_boolean(changes_tree, hf_vj_change_mask_c, src_tvb,
                           offset, 1, changes);
    proto_tree_add_boolean(changes_tree, hf_vj_change_mask_i, src_tvb,
                           offset, 1, changes);
    proto_tree_add_boolean(changes_tree, hf_vj_change_mask_p, src_tvb,
                           offset, 1, changes);
    proto_tree_add_boolean(changes_tree, hf_vj_change_mask_s, src_tvb,
                           offset, 1, changes);
    proto_tree_add_boolean(changes_tree, hf_vj_change_mask_a, src_tvb,
                           offset, 1, changes);
    proto_tree_add_boolean(changes_tree, hf_vj_change_mask_w, src_tvb,
                           offset, 1, changes);
    proto_tree_add_boolean(changes_tree, hf_vj_change_mask_u, src_tvb,
                           offset, 1, changes);
  }
  offset++;

  if(changes & NEW_C){    /* Read conn index */
    conn_index = tvb_get_guint8(src_tvb, offset);
    if(tree != NULL)
      proto_tree_add_uint(tree, hf_vj_connection_number, src_tvb, offset, 1,
                          conn_index);
    offset++;
    if(comp != NULL)
      comp->recv_current = conn_index;
  }

  if(!pinfo->fd->flags.visited) {
    /*
     * This is the first time this frame has been seen, so we need
     * state information to decompress it.  If that information isn't
     * available, don't use the state information, and don't update it,
     * either.
     */
    if(comp != NULL && !(comp->rstate[comp->recv_current].flags & SLF_TOSS)) {
      cs = &comp->rstate[comp->recv_current];
      thp = &cs->cs_tcp;
      ip = &cs->cs_ip;
    }
  }

  /* Build TCP and IP headers */
  tcp_cksum = tvb_get_ntohs(src_tvb, offset);
  if(tree != NULL)
    proto_tree_add_uint(tree, hf_vj_tcp_cksum, src_tvb, offset, 2, tcp_cksum);
  if(cs != NULL) {
    hdrlen = lo_nibble(ip->ihl_version) * 4 + TCP_OFFSET(thp) * 4;
    thp->cksum = g_htons(tcp_cksum);
  }
  offset += 2;
  if(cs != NULL) {
    if(changes & CHANGE_PUSH_BIT)
      thp->flags |= TCP_PUSH_BIT;
    else
      thp->flags &= ~TCP_PUSH_BIT;
  }

  /* Deal with special cases and normal deltas */
  switch(changes & SPECIALS_MASK){
    case SPECIAL_I:                   /* Echoed terminal traffic */
      if(cs != NULL) {
        word = g_ntohs(ip->tot_len) - hdrlen;
        thp->ack_seq = g_htonl(g_ntohl(thp->ack_seq) + word);
        thp->seq = g_htonl(g_ntohl(thp->seq) + word);
      }
      break;
    case SPECIAL_D:                   /* Unidirectional data */
      if(cs != NULL)
        thp->seq = g_htonl(g_ntohl(thp->seq) + g_ntohs(ip->tot_len) - hdrlen);
      break;
    default:
      if(changes & NEW_U){
        delta = get_unsigned_delta(src_tvb, &offset, hf_vj_urp, tree);
        if(cs != NULL) {
          thp->urg_ptr = delta;
          thp->flags |= TCP_URG_BIT;
        }
      } else {
        if(cs != NULL)
          thp->flags &= ~TCP_URG_BIT;
      }
      if(changes & NEW_W) {
        delta = get_signed_delta(src_tvb, &offset, hf_vj_win_delta, tree);
        if(cs != NULL)
          thp->window = g_htons(g_ntohs(thp->window) + delta);
      }
      if(changes & NEW_A) {
        delta = get_unsigned_delta(src_tvb, &offset, hf_vj_ack_delta, tree);
        if(cs != NULL)
          thp->ack_seq = g_htonl(g_ntohl(thp->ack_seq) + delta);
      }
      if(changes & NEW_S) {
      	delta = get_unsigned_delta(src_tvb, &offset, hf_vj_seq_delta, tree);
        if(cs != NULL)
          thp->seq = g_htonl(g_ntohl(thp->seq) + delta);
      }
      break;
  }
  if(changes & NEW_I)
    delta = get_unsigned_delta(src_tvb, &offset, hf_vj_ip_id_delta, tree);
  else
    delta = 1;
  if(cs != NULL)
    ip->id = g_htons(g_ntohs(ip->id) + delta);

  /* Compute IP packet length and the buffer length needed */
  len = tvb_reported_length_remaining(src_tvb, offset);
  if(len < ZERO) {
    /*
     * This shouldn't happen, as we *were* able to fetch stuff right before
     * offset.
     */
    if(check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "VJ compressed TCP (not enough data available)");
    if(cs != NULL)
      cs->flags |= SLF_TOSS;
    return VJ_ERROR;
  }

  /* Show the TCP payload */
  if(tree != NULL && tvb_offset_exists(src_tvb, offset))
    proto_tree_add_text(tree, src_tvb, offset, -1, "TCP payload");

  /* Nothing more to do if we don't have any compression state */
  if(comp == NULL) {
    /* Direction of the traffic unknown - can't decompress */
    if(check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "VJ compressed TCP (direction unknown)");
    return VJ_ERROR;
  }

  if((cs != NULL) && (!pinfo->fd->flags.visited)) {
    len += hdrlen;
    ip->tot_len = g_htons(len);
    /* Compute IP check sum */
    ip->cksum = ZERO;
    ip->cksum = ip_csum((guint8 *)ip, lo_nibble(ip->ihl_version) * 4);

    /* Store the reconstructed header in frame data area */
    buf_hdr = se_alloc(sizeof (vj_header_t));
    buf_hdr->offset = offset;  /* Offset in tvbuff is also stored */
    data_ptr = buf_hdr->data;
    memcpy(data_ptr, ip, IP_HDR_LEN);
    data_ptr += IP_HDR_LEN;
    if(lo_nibble(ip->ihl_version) > 5) {
      memcpy(data_ptr, cs->cs_ipopt, (lo_nibble(ip->ihl_version) - 5) * 4);
      data_ptr += (lo_nibble(ip->ihl_version) - 5) * 4;
    }
    memcpy(data_ptr, thp, TCP_HDR_LEN);
    data_ptr += TCP_HDR_LEN;
    if(TCP_OFFSET(thp) > 5)
      memcpy(data_ptr, cs->cs_tcpopt, (TCP_OFFSET(thp) - 5) * 4);
    p_add_proto_data(pinfo->fd, proto_vj, buf_hdr);
  }

  return VJ_OK;
}

/*
 * Get an unsigned delta for a field, and put it into the protocol tree if
 * we're building a protocol tree.
 */
static int
get_unsigned_delta(tvbuff_t *tvb, int *offsetp, int hf, proto_tree *tree)
{
  int offset = *offsetp;
  int len;
  guint16 del;

  len = 1;
  del = tvb_get_guint8(tvb, offset++);
  if(del == ZERO){
    del = tvb_get_ntohs(tvb, offset);
    offset += 2;
    len += 2;
  }
  if(tree != NULL)
    proto_tree_add_uint(tree, hf, tvb, *offsetp, len, del);
  *offsetp = offset;
  return del;
}

/*
 * Get a signed delta for a field, and put it into the protocol tree if
 * we're building a protocol tree.
 */
static int
get_signed_delta(tvbuff_t *tvb, int *offsetp, int hf, proto_tree *tree)
{
  int offset = *offsetp;
  int len;
  gint16 del;

  len = 1;
  del = tvb_get_guint8(tvb, offset++);
  if(del == ZERO){
    del = tvb_get_ntohs(tvb, offset);
    offset += 2;
    len += 2;
  }
  if(tree != NULL)
    proto_tree_add_int(tree, hf, tvb, *offsetp, len, del);
  *offsetp = offset;
  return del;
}

/* Wrapper for in_cksum function */
static guint16
ip_csum(const guint8 * ptr, guint32 len)
{
  vec_t cksum_vec[1];

  cksum_vec[0].ptr = ptr;
  cksum_vec[0].len = len;
  return in_cksum(&cksum_vec[0], 1);
}
