/* packet-vj.c
 * Routines for Van Jacobson header decompression. 
 *
 * $Id: packet-vj.c,v 1.2 2001/12/19 22:39:59 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 *
 * This file created by Irfan Khan <ikhan@qualcomm.com>
 * Copyright (c) 2001  by QUALCOMM, Incorporated.
 * All Rights reserved.
 * 
 * Routines to compress and uncompress tcp packets (for transmission
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include <string.h>
#include "packet.h"
#include "packet-ppp.h"
#include "ppptypes.h"
#include "in_cksum.h"
#include "epan/tvbuff.h"

/* Define relevant IP/TCP parameters */
#define IP_FIELD_SRC         12 /* Byte 12 in IP hdr - src address        */
#define IP_FIELD_DST         16 /* Byte 16 in IP hdr - dst address        */
#define IP_ADDR_SIZE          4 /* Size in bytes of IPv4 address          */
#define IP_FIELD_PROTOCOL     9 /* Protocol field byte in IP hdr          */
#define IP_PROTOCOL_TCP    0x06 /* Protocol field value for TCP           */
#define IP_HDR_LEN           20 /* Minimum IP header length               */
#define IP_HDR_LEN_MASK    0x0f /* Mask for header length field           */
#define IP_MAX_OPT_LEN       44 /* Max length of IP options               */
#define TCP_HDR_LEN          20 /* Minimum TCP header length              */
#define TCP_PUSH_BIT       0x10 /* TCP push bit                           */
#define TCP_MAX_OPT_LEN      44 /* Max length of TCP options               */
#define TCP_SIMUL_CONV      256 /* Number of simul. TCP conversations     */
#define TCP_SIMUL_CONV_MAX  256 /* Max number of simul. TCP conversations */

/* Bits in first octet of compressed packet */
/* flag bits for what changed in a packet */
#define NEW_C   0x40    
#define NEW_I   0x20
#define NEW_S   0x08
#define NEW_A   0x04
#define NEW_W   0x02
#define NEW_U   0x01

/* reserved, special-case values of above */
#define SPECIAL_I     (NEW_S|NEW_W|NEW_U)    /* echoed interactive traffic */
#define SPECIAL_D     (NEW_S|NEW_A|NEW_W|NEW_U)/* unidirectional data */
#define SPECIALS_MASK (NEW_S|NEW_A|NEW_W|NEW_U)

/* Function return values */
#define VJ_OK           0
#define VJ_ERROR       -1

/* Define for 0 */
#define ZERO            0

/* Two byte CRC */
#define CRC_LEN         sizeof(guint16) 

/* VJ Mem Chunk defines */
#define VJ_DATA_SIZE  128 /* Max IP hdr(64)+Max TCP hdr(64) */
#define VJ_ATOM_COUNT 250 /* Number of Atoms per block      */ 

/* IP and TCP header types */
typedef struct {
#if BYTE_ORDER == LITTLE_ENDIAN 
  guint8  ihl:4,
          version:4;
#else 
  guint8  version:4,
          ihl:4;
#endif
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
#if BYTE_ORDER == LITTLE_ENDIAN
  guint16 res1:4,
          doff:4,
          fin:1,
          syn:1,
          rst:1,
          psh:1,
          ack:1,
          urg:1,
          ece:1,
          cwr:1;
#else 
  guint16 doff:4,
          res1:4,
          cwr:1,
          ece:1,
          urg:1,
          ack:1,
          psh:1,
          rst:1,
          syn:1,
          fin:1;
#endif
  guint16 window;
  guint16 cksum;
  guint16 urg_ptr;
} tcphdr_type;


/* State per active tcp conversation */
typedef struct cstate {
  struct cstate *next;   /* next in ring (xmit) */
  iphdr_type cs_ip; 
  tcphdr_type cs_tcp;
  guint8 cs_ipopt[IP_MAX_OPT_LEN];
  guint8 cs_tcpopt[TCP_MAX_OPT_LEN];
} cstate;

/* All the state data for one serial line */
typedef struct {
  cstate *rstate;  /* receive connection states (array)*/
  guint8 rslot_limit;     /* highest receive slot id */
  guint8 recv_current;    /* most recent rcvd id */
  guint8 flags;
#define SLF_TOSS  0x01    /* tossing rcvd frames until id received */
} slcompress;

/* Initialize the protocol and registered fields */
static int proto_vj = -1;

/* Protocol handles */
static dissector_handle_t vjc_handle;
static dissector_handle_t vjuc_handle;
static dissector_handle_t data_handle;

/* State repository (Full Duplex) */
#define RX_TX_STATE_COUNT 2
static slcompress *rx_tx_state[RX_TX_STATE_COUNT] = {NULL, NULL};
 
/* Mem Chunks for storing decompressed headers */
static GMemChunk *vj_header_memchunk = NULL;
typedef struct {
	guint32	offset;
	guint8	data[VJ_DATA_SIZE];
} vj_header_t;
	
/* Function prototypes */
static void decodes(tvbuff_t *tvb, guint32 *offset, gint16 *val);
static void decodel(tvbuff_t *tvb, guint32 *offset, gint32 *val);
static guint16 ip_csum(const guint8 *ptr, guint32 len);
static slcompress *slhc_init(gint rslots);
static void vj_init(void);
static void vj_display_pkt(tvbuff_t *parent_tvb, tvbuff_t *child_tvb, 
                           packet_info *pinfo, proto_tree *tree);
static gint vjuc_check(tvbuff_t *tvb, slcompress *comp);
static void vjuc_update_state(tvbuff_t *tvb, slcompress *comp, guint8 index);
static gint vjuc_tvb_setup(tvbuff_t *tvb, tvbuff_t **dst_tvb, 
                           slcompress *comp);
static gint vjc_check(tvbuff_t *src_tvb, slcompress *comp);
static gint vjc_update_state(tvbuff_t *src_tvb, slcompress *comp, 
                             frame_data *fd);
static gint vjc_tvb_setup(tvbuff_t *src_tvb, tvbuff_t **dst_tvb, 
                          frame_data *fd);

/* Dissector for VJ Uncompressed packets */
static void
dissect_vjuc(tvbuff_t *tvb, packet_info *pinfo, proto_tree * tree)
{
  tvbuff_t   *next_tvb    = NULL;
  tvbuff_t   *data_tvb    = NULL;
  slcompress *comp        = NULL;
  gint        conn_index  = ZERO;
  gint        err         = VJ_OK;

  /* Return if VJ is off or direction is not known */
  if(ppp_vj_decomp == FALSE || pinfo->p2p_dir == P2P_DIR_UNKNOWN) 
    err = VJ_ERROR;

  if((comp = rx_tx_state[pinfo->p2p_dir]) == NULL)
    err = VJ_ERROR;

  /* Check if packet malformed. */
  if(err == VJ_OK)
    err = conn_index = vjuc_check(tvb, comp); 

  /* Set up tvb containing decompressed packet */
  if(err != VJ_ERROR)
    err = vjuc_tvb_setup(tvb, &next_tvb, comp); 

  /* If packet seen for first time update state */
  if(pinfo->fd->flags.visited != 1 && err == VJ_OK) 
    vjuc_update_state(next_tvb, comp, conn_index);

  /* If no errors call IP dissector else dissect as data. */
  if(err == VJ_OK)
    vj_display_pkt(tvb, next_tvb, pinfo, tree);
  else {
    data_tvb = tvb_new_subset(tvb, 0, -1, -1);
    call_dissector(data_handle, data_tvb, pinfo, tree);
  }
}

/* Dissector for VJ Compressed packets */
static void
dissect_vjc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t   *next_tvb = NULL;
  tvbuff_t   *data_tvb = NULL;
  slcompress *comp     = NULL;
  gint        err      = VJ_OK;
  
  /* Return if VJ is off or direction is not known */
  if(ppp_vj_decomp == FALSE || pinfo->p2p_dir == P2P_DIR_UNKNOWN) 
    err = VJ_ERROR;
  
  if((comp = rx_tx_state[pinfo->p2p_dir]) == NULL)
    err = VJ_ERROR;

  /* Check if packet malformed. */
  if(err != VJ_ERROR)
    err = vjc_check(tvb, comp);

  /* If packet seen for first time update state */
  if(pinfo->fd->flags.visited != 1 && err == VJ_OK) {
    err = vjc_update_state(tvb, comp, pinfo->fd); 
  }

  /* Set up tvb containing decompressed packet */
  if(err == VJ_OK)
    err = vjc_tvb_setup(tvb, &next_tvb, pinfo->fd); 

  /* If no errors call IP dissector else dissect as data */
  if(err == VJ_OK)
    vj_display_pkt(tvb, next_tvb, pinfo, tree);
  else {
    data_tvb = tvb_new_subset(tvb, 0, -1, -1);
    call_dissector(data_handle, data_tvb, pinfo, tree);
  }
}

/* Registeration functions for dissectors */
void
proto_register_vj(void)
{
  proto_vj = proto_register_protocol("PPP VJ Compression", "PPP VJ", "vj");
  register_init_routine(&vj_init);

  vjc_handle = create_dissector_handle(dissect_vjc, proto_vj);
  vjuc_handle = create_dissector_handle(dissect_vjuc, proto_vj);

}

void
proto_reg_handoff_vj(void)
{
  dissector_add("ppp.protocol", PPP_VJC_COMP, vjc_handle);
  dissector_add("ppp.protocol", PPP_VJC_UNCOMP, vjuc_handle);

  data_handle = find_dissector("data");
}

/* Function to setup decompressed packet display */
static void 
vj_display_pkt(tvbuff_t *parent_tvb, 
               tvbuff_t *child_tvb, 
               packet_info *pinfo, 
               proto_tree *tree)
{
  dissector_handle_t ip_handle = find_dissector("ip");
  frame_data *fd               = pinfo->fd;
  tvbuff_t   *data_tvb         = NULL;
  
  g_assert(parent_tvb);
  g_assert(child_tvb);
  g_assert(fd);

  if (ip_handle == NULL) {
    data_tvb = tvb_new_subset(child_tvb, 0, -1, -1);
    call_dissector(data_handle, data_tvb, pinfo, tree);
  }
  else {
    tvb_set_child_real_data_tvbuff(parent_tvb, child_tvb);
    fd->data_src = g_slist_append(fd->data_src, child_tvb);
    SET_ADDRESS(&pinfo->net_src, 
                AT_IPv4, 
                IP_ADDR_SIZE, 
                tvb_get_ptr(child_tvb, IP_FIELD_SRC, IP_ADDR_SIZE));
    SET_ADDRESS(&pinfo->src,     
                AT_IPv4, 
                IP_ADDR_SIZE, 
                tvb_get_ptr(child_tvb, IP_FIELD_SRC, IP_ADDR_SIZE));
    SET_ADDRESS(&pinfo->net_dst, 
                AT_IPv4, 
                IP_ADDR_SIZE, 
                tvb_get_ptr(child_tvb, IP_FIELD_DST, IP_ADDR_SIZE));
    SET_ADDRESS(&pinfo->dst,     
                AT_IPv4, 
                IP_ADDR_SIZE, 
                tvb_get_ptr(child_tvb, IP_FIELD_DST, IP_ADDR_SIZE));
    call_dissector(ip_handle, child_tvb, pinfo, tree);
  }
  return;
}

/* Initialization function */
static void 
vj_init(void)
{
  gint i           = ZERO;
  slcompress *pslc = NULL;
  cstate *pstate   = NULL;

  if(vj_header_memchunk != NULL)
    g_mem_chunk_destroy(vj_header_memchunk);
  vj_header_memchunk = g_mem_chunk_new("vj header store", sizeof (vj_header_t), 
                                       sizeof (vj_header_t) * VJ_ATOM_COUNT,
                                       G_ALLOC_ONLY);
  for(i=0; i< RX_TX_STATE_COUNT; i++){
    if((pslc = rx_tx_state[i]) != NULL){
      if((pstate = pslc->rstate) != NULL)
        g_free(pstate);
      g_free(pslc);
    }
    rx_tx_state[i] = slhc_init(TCP_SIMUL_CONV);
  }
  return;
}

/* Initialization routine for VJ decompression */
static slcompress *
slhc_init(gint rslots)
{
  size_t rsize     = rslots * sizeof(cstate);
  slcompress *comp = g_malloc(sizeof(slcompress));

  if(rslots < ZERO || rslots > TCP_SIMUL_CONV_MAX)
    return NULL;

  if (comp != NULL) {
    memset(comp, ZERO, sizeof(slcompress));
    if ((comp->rstate = g_malloc(rsize)) == NULL) {
      g_free(comp);
      comp = NULL;
    }
    else {
      memset(comp->rstate, ZERO, rsize);
      comp->rslot_limit = rslots - 1;
      comp->recv_current = TCP_SIMUL_CONV_MAX - 1;
      comp->flags |= SLF_TOSS;
    }
  }
  return comp;
} 

/* Setup the decompressed packet tvb for VJ compressed packets */
static gint 
vjc_tvb_setup(tvbuff_t *src_tvb, 
              tvbuff_t **dst_tvb, 
	      frame_data * fd)
{
  tvbuff_t    *orig_tvb    = NULL;
  vj_header_t *hdr_buf;
  guint8      *data_ptr;
  guint8      *pbuf        = NULL;
  gint         hdr_len     = ZERO;
  gint         buf_len     = ZERO;
  guint8       offset      = ZERO;

  g_assert(src_tvb);

  /* Get decompressed header stored in fd protocol area */
  hdr_buf = p_get_proto_data(fd, proto_vj);
  if(hdr_buf == NULL) 
    return VJ_ERROR;

  /* Get the data offset in the tvbuff */
  offset  = hdr_buf->offset;

  /* Copy header and form tvb */
  data_ptr = hdr_buf->data;
  hdr_len  = ((iphdr_type *)data_ptr)->ihl * 4;
  hdr_len += ((tcphdr_type *)(data_ptr + hdr_len))->doff * 4;
  buf_len  = tvb_length(src_tvb) + hdr_len - offset;
  pbuf     = g_malloc(buf_len); 
  memcpy(pbuf, data_ptr, hdr_len);
  tvb_memcpy(src_tvb, pbuf + hdr_len, offset, buf_len - hdr_len);
  *dst_tvb = tvb_new_real_data(pbuf, buf_len, buf_len, "VJ Decompressed");
  return VJ_OK;
} 

/* For VJ compressed packets update the decompressor state */
static gint 
vjc_update_state(tvbuff_t *src_tvb,  slcompress *comp, frame_data *fd)
{
  vj_header_t   *buf_hdr;
  guint8        *data_ptr;
  cstate        *cs      = &comp->rstate[comp->recv_current];
  tcphdr_type   *thp     = &cs->cs_tcp;
  iphdr_type    *ip      = &cs->cs_ip;
  gint           changes = ZERO;
  gint           len     = ZERO;
  gint           hdrlen  = ZERO;
  guint32        offset  = ZERO;
  guint16        word    = ZERO;

  g_assert(src_tvb);
  g_assert(comp);
  g_assert(fd);

  /* Read the change byte */
  changes = tvb_get_guint8(src_tvb, offset++);
  if(changes & NEW_C)
   offset++;

  /* Build TCP and IP headers */
  hdrlen = ip->ihl * 4 + thp->doff * 4;
  thp->cksum = htons((tvb_get_guint8(src_tvb, offset++) << 8) | 
                      tvb_get_guint8(src_tvb, offset++));
  thp->psh = (changes & TCP_PUSH_BIT) ? 1 : 0;

  /* Deal with special cases and normal deltas */
  switch(changes & SPECIALS_MASK){
    case SPECIAL_I:                   /* Echoed terminal traffic */
      word = ntohs(ip->tot_len) - hdrlen;
      thp->ack_seq = htonl( ntohl(thp->ack_seq) + word);
      thp->seq = htonl( ntohl(thp->seq) + word);
    break;
    case SPECIAL_D:                   /* Unidirectional data */
      thp->seq = htonl( ntohl(thp->seq) + ntohs(ip->tot_len) - hdrlen);
    break;
    default:
      if(changes & NEW_U){
        thp->urg_ptr = ZERO;
        decodes(src_tvb, &offset, &thp->urg_ptr);  
        thp->urg = 1;
      } 
      else
        thp->urg = 0;
      if(changes & NEW_W)
        decodes(src_tvb, &offset, &thp->window); 
      if(changes & NEW_A)
        decodel(src_tvb, &offset, &thp->ack_seq); 
      if(changes & NEW_S)
        decodel(src_tvb, &offset, &thp->seq); 
    break;
  }
  if(changes & NEW_I)
    decodes(src_tvb, &offset, &ip->id); 
  else
    ip->id = htons (ntohs (ip->id) + 1);

  /* Compute ip packet length and the buffer length needed */
  if((len = tvb_length(src_tvb) - offset - CRC_LEN) < ZERO) {
    comp->flags |= SLF_TOSS;
    return VJ_ERROR;
  }
  len += hdrlen;
  ip->tot_len = htons(len);
  /* Compute IP check sum */
  ip->cksum = ZERO;
  ip->cksum = ip_csum((guint8 *)ip, ip->ihl * 4);

  /* Store the reconstructed header in frame data area */
  buf_hdr = g_mem_chunk_alloc(vj_header_memchunk);
  buf_hdr->offset = offset;  /* Offset in tvbuff is also stored */
  data_ptr = buf_hdr->data;
  memcpy(data_ptr, ip, IP_HDR_LEN);
  data_ptr += IP_HDR_LEN;
  if(ip->ihl > 5) {
    memcpy(data_ptr, cs->cs_ipopt, (ip->ihl - 5) * 4);
    data_ptr += (ip->ihl - 5) * 4;
  }
  memcpy(data_ptr, thp, TCP_HDR_LEN);
  data_ptr += TCP_HDR_LEN;
  if(thp->doff > 5)
    memcpy(data_ptr, cs->cs_tcpopt, (thp->doff - 5) * 4);
  p_add_proto_data(fd, proto_vj, buf_hdr);

  return VJ_OK;
} 

/* For VJ compressed packet check if it is malformed */
static gint 
vjc_check(tvbuff_t *src_tvb, slcompress *comp)
{
  guint8 conn_index = ZERO;
  guint8 offset     = ZERO;
  gint   changes    = ZERO;

  g_assert(src_tvb);
  g_assert(comp);

  if(tvb_length(src_tvb) < 3){
    comp->flags |= SLF_TOSS;
    return VJ_ERROR;
  }

  /* Read the change byte */
  changes = tvb_get_guint8(src_tvb, offset++);

  if(changes & NEW_C){    /* Read conn index */
    conn_index = tvb_get_guint8(src_tvb, offset++);
    if(conn_index > comp->rslot_limit) {
      comp->flags |= SLF_TOSS;
      return VJ_ERROR;
    }
    comp->flags &= ~SLF_TOSS;
    comp->recv_current = conn_index;
  } 
  else {
   if(comp->flags & SLF_TOSS)
     return VJ_ERROR;
  }
  
  return VJ_OK;
} 

/* Decode the delta of a 32 bit header field */
static void 
decodel(tvbuff_t *tvb, guint32* offset, gint32 *val)
{
  gint del = tvb_get_guint8(tvb, (*offset)++);
  if(del == ZERO){
    del = tvb_get_ntohs(tvb, *offset);
    *offset= *offset + 2;
  }
  *val = htonl(ntohl(*val) + del);
  return;
}

/* Decode the delta of a 16 bit header field */
static void 
decodes(tvbuff_t *tvb, guint32* offset, gint16 *val)
{
  gint del = tvb_get_guint8(tvb, (*offset)++);
  if(del == ZERO){
    del = tvb_get_ntohs(tvb, *offset);
    *offset= *offset + 2;
  }
  *val = htons(ntohs(*val) + del);
  return;
}

/* For VJ uncompressed packet check if it is malformed */
static gint 
vjuc_check(tvbuff_t *tvb, slcompress *comp)
{
  guint8 ihl   = ZERO;
  gint   index = ZERO;

  g_assert(comp);
  g_assert(tvb);

  if(tvb_length(tvb) < IP_HDR_LEN) {
    comp->flags |= SLF_TOSS;
    index = VJ_ERROR;
  }
  else {
    /* Get the IP header length */
    ihl = tvb_get_guint8(tvb, 0) & IP_HDR_LEN_MASK;
    ihl <<= 2;

    /* Get connection index */
    index = tvb_get_guint8(tvb, IP_FIELD_PROTOCOL);

    /* Check connection number and IP header length field */
    if(ihl < IP_HDR_LEN || index > comp->rslot_limit) {
      comp->flags |= SLF_TOSS;
      index = VJ_ERROR;
    }
  }

  return index;
} 

/* Setup the decompressed packet tvb for VJ uncompressed packets */
static gint 
vjuc_tvb_setup(tvbuff_t *tvb, 
               tvbuff_t **dst_tvb, 
               slcompress *comp)
{
  guint8     ihl         = ZERO;
  guint8     index       = ZERO;
  gint       isize       = tvb_length(tvb);
  guint8    *buffer      = NULL;
  tvbuff_t  *orig_tvb    = NULL;
  gint       orig_offset = 0;

  g_assert(comp);
  g_assert(tvb);

  /* Get the IP header length */
  ihl = tvb_get_guint8(tvb, 0) & IP_HDR_LEN_MASK;
  ihl <<= 2;
  
  /* Copy packet data to a buffer */
  buffer   = g_malloc(isize);
  tvb_memcpy(tvb, buffer, 0, isize);
  buffer[IP_FIELD_PROTOCOL] = IP_PROTOCOL_TCP;

  /* Compute checksum */
  if (ip_csum(buffer, ihl) != ZERO) {
    g_free(buffer);
    comp->flags |= SLF_TOSS;
    return VJ_ERROR;
  }

  /* 
   * Form the new tvbuff. 
   * Neither header checksum is recalculated
   */
  *dst_tvb = tvb_new_real_data(buffer, isize, isize, "VJ Uncompressed");
  return VJ_OK;
} 

/* For VJ uncompressed packets update the decompressor state */
static void 
vjuc_update_state(tvbuff_t *tvb, slcompress *comp, guint8 index)
{
  cstate  *cs    = NULL;
  guint8   ihl   = ZERO;
  gint     isize = tvb_length(tvb);

  g_assert(comp);
  g_assert(tvb);

  /* Get the IP header length */
  ihl = tvb_get_guint8(tvb, 0) & IP_HDR_LEN_MASK;
  ihl <<= 2;
  
  /* Update local state */
  cs = &comp->rstate[comp->recv_current = index];
  comp->flags &= ~SLF_TOSS;
  tvb_memcpy(tvb, (guint8 *)&cs->cs_ip, 0, IP_HDR_LEN);
  tvb_memcpy(tvb, (guint8 *)&cs->cs_tcp, ihl, TCP_HDR_LEN);
  if (ihl > IP_HDR_LEN)
    tvb_memcpy(tvb, cs->cs_ipopt, sizeof(iphdr_type), ihl - IP_HDR_LEN);
  if (cs->cs_tcp.doff > 5)
    tvb_memcpy(tvb, cs->cs_tcpopt, ihl + sizeof(tcphdr_type), 
               (cs->cs_tcp.doff - 5) * 4);
  return;
} 

/* Wraper for in_cksum function */
static guint16 
ip_csum(const guint8 * ptr, guint32 len)
{
        vec_t cksum_vec[1];

        cksum_vec[0].ptr = ptr;
        cksum_vec[0].len = len;
        return in_cksum(&cksum_vec[0], 1);
}
