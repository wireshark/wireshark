/* packet-juniper.c
 * Routines for Juniper Networks, Inc. packet disassembly
 * Copyright 2005 Hannes Gredler <hannes@juniper.net>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "etypes.h"
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include "ppptypes.h"
#include "packet-ppp.h"
#include "packet-ip.h"
#include "nlpid.h"

#define JUNIPER_FLAG_PKT_OUT        0x00     /* Outgoing packet */
#define JUNIPER_FLAG_PKT_IN         0x01     /* Incoming packet */
#define JUNIPER_FLAG_NO_L2          0x02     /* L2 header stripped */
#define JUNIPER_FLAG_EXT            0x80     /* extensions present */
#define JUNIPER_ATM2_PKT_TYPE_MASK  0x70
#define JUNIPER_ATM2_GAP_COUNT_MASK 0x3F
#define JUNIPER_PCAP_MAGIC          0x4d4743

#define JUNIPER_PIC_ATM1   1
#define JUNIPER_PIC_ATM2   2
#define JUNIPER_PIC_MLPPP  3
#define JUNIPER_PIC_MLFR   4

#define JUNIPER_HDR_SNAP   0xaaaa03
#define JUNIPER_HDR_NLPID  0xfefe03
#define JUNIPER_HDR_LLC_UI 0x03
#define JUNIPER_HDR_PPP    0xff03

#define ML_PIC_COOKIE_LEN 2
#define LS_PIC_COOKIE_LEN 4
#define AS_PIC_COOKIE_LEN 8

#define GSP_SVC_REQ_APOLLO 0x40
#define GSP_SVC_REQ_LSQ    0x47

#define LSQ_COOKIE_RE         0x2
#define LSQ_COOKIE_DIR        0x1
#define LSQ_L3_PROTO_SHIFT     4
#define LSQ_L3_PROTO_MASK     0xf0
#define LSQ_L3_PROTO_IPV4     (0 << LSQ_L3_PROTO_SHIFT)
#define LSQ_L3_PROTO_IPV6     (1 << LSQ_L3_PROTO_SHIFT)
#define LSQ_L3_PROTO_MPLS     (2 << LSQ_L3_PROTO_SHIFT)
#define LSQ_L3_PROTO_ISO      (3 << LSQ_L3_PROTO_SHIFT)

static const value_string juniper_direction_vals[] = {
    {JUNIPER_FLAG_PKT_OUT, "Out"},
    {JUNIPER_FLAG_PKT_IN,  "In"},
    {0,                    NULL}
};

static const value_string juniper_l2hdr_presence_vals[] = {
    { 0, "Present"},
    { 2, "none"},
    {0,                    NULL}
};

static int proto_juniper = -1;

static int hf_juniper_magic = -1;
static int hf_juniper_direction = -1;
static int hf_juniper_l2hdr_presence = -1;
static int hf_juniper_ext_len = -1;
static int hf_juniper_atm1_cookie = -1;
static int hf_juniper_atm2_cookie = -1;
static int hf_juniper_mlpic_cookie = -1;
static int hf_juniper_lspic_cookie = -1;
static int hf_juniper_aspic_cookie = -1;

static gint ett_juniper = -1;

static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t mpls_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t eth_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t q933_handle;
static dissector_handle_t frelay_handle;
static dissector_handle_t data_handle;

static dissector_table_t osinl_subdissector_table;
static dissector_table_t osinl_excl_subdissector_table;

int dissect_juniper_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti, guint8 *flags);
int dissect_juniper_payload_proto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,proto_item *ti, guint proto, guint offset);
static void dissect_juniper_atm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 atm_pictype);
static gboolean ppp_heuristic_guess(guint16 proto);
static guint ip_heuristic_guess(guint8 ip_header_byte);
static guint juniper_svc_cookie_len (guint64 cookie);
static guint juniper_svc_cookie_proto (guint64 cookie, guint16 pictype, guint8 flags);

/* values < 200 are JUNOS internal proto values
 * found in frames containing no link-layer header */
enum {
    PROTO_UNKNOWN = 0,
    PROTO_IP = 2,
    PROTO_MPLS_IP = 3,
    PROTO_IP_MPLS = 4,
    PROTO_MPLS = 5,
    PROTO_IP6 = 6,
    PROTO_MPLS_IP6 = 7,
    PROTO_IP6_MPLS = 8,
    PROTO_CLNP = 10,
    PROTO_CLNP_MPLS = 32,
    PROTO_MPLS_CLNP = 33,
    PROTO_PPP = 200,
    PROTO_ISO = 201,
    PROTO_LLC = 202,
    PROTO_LLC_SNAP = 203,
    PROTO_ETHER = 204,
    PROTO_OAM = 205,
    PROTO_Q933 = 206,
    PROTO_FRELAY = 207
};

static const value_string juniper_proto_vals[] = {
    {PROTO_IP, "IPv4"},
    {PROTO_MPLS_IP, "MPLS->IPv4"},
    {PROTO_IP_MPLS, "IPv4->MPLS"},
    {PROTO_IP6, "IPv6"},
    {PROTO_MPLS_IP6, "MPLS->IPv6"},
    {PROTO_IP6_MPLS, "IPv6->MPLS"},
    {PROTO_PPP, "PPP"},
    {PROTO_CLNP, "CLNP"},
    {PROTO_MPLS_CLNP, "MPLS->CLNP"},
    {PROTO_CLNP_MPLS, "CLNP->MPLS"},
    {PROTO_ISO, "OSI"},
    {PROTO_MPLS, "MPLS"},
    {PROTO_LLC, "LLC"},
    {PROTO_LLC_SNAP, "LLC/SNAP"},
    {PROTO_ETHER, "Ethernet"},
    {PROTO_OAM, "ATM OAM Cell"},
    {PROTO_Q933, "Q.933"},
    {PROTO_FRELAY, "Frame-Relay"},
    {0,                    NULL}
};

/* the first subtree is accessed by several routines */
static proto_tree *juniper_subtree = NULL;

/* generic juniper header dissector  */
int
dissect_juniper_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti, guint8 *flags)
{
  proto_item *tisub;
  guint8     direction,l2hdr_presence,proto;
  guint16    ext_len,hdr_len;
  guint32    magic_number;

  tvbuff_t   *next_tvb;
  proto_tree *juniper_ext_subtree = NULL;

  magic_number = tvb_get_ntoh24(tvb, 0);
  *flags = tvb_get_guint8(tvb, 3);
  direction = *flags & JUNIPER_FLAG_PKT_IN;
  l2hdr_presence = *flags & JUNIPER_FLAG_NO_L2;

  juniper_subtree = proto_item_add_subtree(ti, ett_juniper);          
  tisub = proto_tree_add_text (juniper_subtree, tvb, 0, 3,
                            "Magic-Number: 0x%06x (%scorrect)", 
                            magic_number,
                            (magic_number == JUNIPER_PCAP_MAGIC) ?  "" : "in" );
    
  if (magic_number != JUNIPER_PCAP_MAGIC)
     return -1;
  
  tisub = proto_tree_add_uint_format (juniper_subtree, hf_juniper_direction, tvb, 3, 1,
                            direction, "Direction: %s",
                            val_to_str(direction,juniper_direction_vals,"Unknown"));
  
  tisub = proto_tree_add_uint_format (juniper_subtree, hf_juniper_l2hdr_presence, tvb, 3, 1,
                            l2hdr_presence, "L2-header: %s",
                            val_to_str(l2hdr_presence,juniper_l2hdr_presence_vals,"Unknown"));

  /* calculate hdr_len before cookie, payload */

  /* meta-info extensions (JUNOS >= 7.5) ? */
  if ((*flags & JUNIPER_FLAG_EXT) == JUNIPER_FLAG_EXT) {
      ext_len = tvb_get_ntohs(tvb,4);
      hdr_len = 6 + ext_len; /* MGC,flags,ext_len */

      tisub = proto_tree_add_uint (juniper_subtree, hf_juniper_ext_len, tvb, 4, 2, ext_len);
      juniper_ext_subtree = proto_item_add_subtree(tisub, ett_juniper);          

      /* FIXME add TLV parser for extensions */
      tisub = proto_tree_add_text (juniper_ext_subtree, tvb, 6, ext_len, "unparsed Extensions");

  } else
      hdr_len = 4; /* MGC,flags */

  if ((*flags & JUNIPER_FLAG_NO_L2) == JUNIPER_FLAG_NO_L2) { /* no link header present ? */
      proto = tvb_get_letohl(tvb,hdr_len); /* proto is stored in host-order */
      next_tvb = tvb_new_subset(tvb, hdr_len + 4, -1, -1);
      dissect_juniper_payload_proto(tvb, pinfo, tree, ti, proto, hdr_len + 4);
      return -1;
  }

  return hdr_len; /* bytes parsed */

}

/* print the payload protocol  */
int
dissect_juniper_payload_proto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              proto_item *ti, guint proto, guint offset)
{

    tvbuff_t   *next_tvb;
    guint8     nlpid; 

    ti = proto_tree_add_text (juniper_subtree, tvb, offset, 0, "[Payload Type: %s]",
                            val_to_str(proto,juniper_proto_vals,"Unknown"));

    next_tvb = tvb_new_subset(tvb, offset, -1, -1);  
  
    switch (proto) {
    case PROTO_IP:
    case PROTO_MPLS_IP:
        call_dissector(ipv4_handle, next_tvb, pinfo, tree);
        break;
    case PROTO_IP6:
    case PROTO_MPLS_IP6:
        call_dissector(ipv6_handle, next_tvb, pinfo, tree);  
        break;
    case PROTO_MPLS:
    case PROTO_IP_MPLS:
    case PROTO_IP6_MPLS:
    case PROTO_CLNP_MPLS:
        call_dissector(mpls_handle, next_tvb, pinfo, tree);
        break;
    case PROTO_PPP:
        call_dissector(ppp_handle, next_tvb, pinfo, tree);
        break;
    case PROTO_ETHER:
        call_dissector(eth_handle, next_tvb, pinfo, tree);
        break;
    case PROTO_LLC:
    case PROTO_LLC_SNAP:
        call_dissector(llc_handle, next_tvb, pinfo, tree);
        break;
    case PROTO_ISO:
    case PROTO_CLNP:
    case PROTO_MPLS_CLNP:
        nlpid = tvb_get_guint8(tvb, offset);
        if(dissector_try_port(osinl_subdissector_table, nlpid, next_tvb, pinfo, tree))
            return 0;
        next_tvb = tvb_new_subset(tvb, offset+1, -1, -1);
        if(dissector_try_port(osinl_excl_subdissector_table, nlpid, next_tvb, pinfo, tree))
            return 0;
        break;
    case PROTO_Q933:
        call_dissector(q933_handle, next_tvb, pinfo, tree);
        break;
    case PROTO_FRELAY:
        call_dissector(frelay_handle, next_tvb, pinfo, tree);
        break;
    case PROTO_OAM: /* FIXME call OAM disector without leading HEC byte */
    default:
        call_dissector(data_handle, next_tvb, pinfo, tree);  
        break;
    }

    return 0;
}

/* MLFR dissector */
static void
dissect_juniper_mlfr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint      offset;
  int        bytes_processed;
  guint8     flags;
  guint64    aspic_cookie;
  guint32    lspic_cookie;
  guint16    mlpic_cookie;
  guint      proto,cookie_len;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper MLFR");
  if (check_col(pinfo->cinfo, COL_INFO))
      col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper Multi-Link Frame-Relay (FRF.15)");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
      return;
  else
      offset+=bytes_processed;

  aspic_cookie = tvb_get_ntoh64(tvb,offset);
  proto = juniper_svc_cookie_proto(aspic_cookie, JUNIPER_PIC_MLFR, flags);
  cookie_len = juniper_svc_cookie_len(aspic_cookie);

  if (cookie_len == AS_PIC_COOKIE_LEN)
      ti = proto_tree_add_uint64(juniper_subtree, hf_juniper_aspic_cookie,
                                 tvb, offset, AS_PIC_COOKIE_LEN, aspic_cookie);
  if (cookie_len == LS_PIC_COOKIE_LEN) {
      lspic_cookie = tvb_get_ntohl(tvb,offset);
      ti = proto_tree_add_uint(juniper_subtree, hf_juniper_lspic_cookie,
                               tvb, offset, LS_PIC_COOKIE_LEN, lspic_cookie);
  }

  offset += cookie_len;

  mlpic_cookie = tvb_get_ntohs(tvb, offset);

  /* AS-PIC IS-IS */
  if (cookie_len == AS_PIC_COOKIE_LEN &&
      proto == PROTO_UNKNOWN &&
      tvb_get_guint8(tvb,offset) == JUNIPER_HDR_LLC_UI) {
      offset += 1;
      proto = PROTO_ISO;
  }

  /* LS-PIC IS-IS */
  if (cookie_len == LS_PIC_COOKIE_LEN) {
      if ( tvb_get_ntohs(tvb,offset) == JUNIPER_HDR_LLC_UI ||
           tvb_get_ntohs(tvb,offset) == (JUNIPER_HDR_LLC_UI<<8)) {
          offset += 2;
      }
  }

  /* LS-PIC ? */
  if (cookie_len == LS_PIC_COOKIE_LEN && tvb_get_guint8(tvb,offset) == JUNIPER_HDR_LLC_UI) {
      offset += 1;
  }

  /* child link of an LS-PIC bundle ? */
  if (cookie_len == 0 && tvb_get_ntohs(tvb,offset+ML_PIC_COOKIE_LEN) == 
      (JUNIPER_HDR_LLC_UI<<8 | NLPID_Q_933)) {
      cookie_len = ML_PIC_COOKIE_LEN;
      ti = proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                               tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
      offset += 3;
      proto = PROTO_Q933;
  }

  /* child link of an ML-, LS-, AS-PIC bundle / ML-PIC bundle ? */
  if (cookie_len == 0) {
      if (tvb_get_ntohs(tvb,offset+ML_PIC_COOKIE_LEN) == JUNIPER_HDR_LLC_UI ||
          tvb_get_ntohs(tvb,offset+ML_PIC_COOKIE_LEN) == (JUNIPER_HDR_LLC_UI<<8)) {
          cookie_len = ML_PIC_COOKIE_LEN;
          ti = proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                               tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
          offset += 4;
          proto = PROTO_ISO;
  }
  }

  /* ML-PIC bundle ? */
  if (cookie_len == 0 && tvb_get_guint8(tvb,offset+ML_PIC_COOKIE_LEN) == JUNIPER_HDR_LLC_UI) {
      cookie_len = ML_PIC_COOKIE_LEN;
      ti = proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                               tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
      offset += 3;
      proto = PROTO_ISO;
  }

  ti = proto_tree_add_text (juniper_subtree, tvb, offset, 0, "[Cookie length: %u]",cookie_len);
  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, proto, offset);
      
}



/* MLPPP dissector */
static void
dissect_juniper_mlppp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint      offset;
  int        bytes_processed;
  guint8     flags;
  guint64    aspic_cookie;
  guint32    lspic_cookie;
  guint16    mlpic_cookie;
  guint      proto,cookie_len;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper MLPPP");
  if (check_col(pinfo->cinfo, COL_INFO))
      col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper MLPPP");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
      return;
  else
      offset+=bytes_processed;

  aspic_cookie = tvb_get_ntoh64(tvb,offset);
  proto = juniper_svc_cookie_proto(aspic_cookie, JUNIPER_PIC_MLPPP, flags);
  cookie_len = juniper_svc_cookie_len(aspic_cookie);

  if (cookie_len == AS_PIC_COOKIE_LEN)
      ti = proto_tree_add_uint64(juniper_subtree, hf_juniper_aspic_cookie,
                                 tvb, offset, AS_PIC_COOKIE_LEN, aspic_cookie);
  if (cookie_len == LS_PIC_COOKIE_LEN) {
      lspic_cookie = tvb_get_ntohl(tvb,offset);
      ti = proto_tree_add_uint(juniper_subtree, hf_juniper_lspic_cookie,
                               tvb, offset, LS_PIC_COOKIE_LEN, lspic_cookie);
  }

  /* no cookie pattern identified - lets guess from now on */

  /* child link of an LS-PIC bundle ? */
  if (cookie_len == 0 && tvb_get_ntohs(tvb, offset) == JUNIPER_HDR_PPP) {
      proto = PROTO_PPP;
      offset += 2;
  }

  /* ML-PIC ? */
  if (cookie_len == 0 && ppp_heuristic_guess(tvb_get_ntohs(tvb, offset+2))) {
      proto = PROTO_PPP;
      cookie_len = 2;
      mlpic_cookie = tvb_get_ntohs(tvb, offset);
      ti = proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                               tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
  }

  /* child link of an ML-PIC bundle ? */
  if (cookie_len == 0 && ppp_heuristic_guess(tvb_get_ntohs(tvb, offset))) {
      proto = PROTO_PPP;
  }

  ti = proto_tree_add_text (juniper_subtree, tvb, offset, 0, "[Cookie length: %u]",cookie_len);
  offset += cookie_len;

  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, proto, offset);
      
}


/* PPPoE dissector */
static void
dissect_juniper_pppoe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint      offset;
  int        bytes_processed;
  guint8     flags;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper PPPoE");
  if (check_col(pinfo->cinfo, COL_INFO))
      col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper PPPoE PIC");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
      return;
  else
      offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_ETHER, offset);

}


/* wrapper for passing the PIC type to the generic ATM dissector */
static void
dissect_juniper_atm1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{ 
    dissect_juniper_atm(tvb,pinfo,tree, JUNIPER_PIC_ATM1);
}

/* wrapper for passing the PIC type to the generic ATM dissector */
static void
dissect_juniper_atm2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{ 
    dissect_juniper_atm(tvb,pinfo,tree, JUNIPER_PIC_ATM2);
}

/* generic ATM dissector */
static void
dissect_juniper_atm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 atm_pictype)
{
  proto_item *ti,*tisub;
  guint8     next_proto = PROTO_UNKNOWN,atm1_header_len,atm2_header_len,flags;
  guint32    cookie1, proto;
  guint64    cookie2;
  guint      offset = 0;
  int        bytes_processed;
  tvbuff_t   *next_tvb;

  switch (atm_pictype) {
  case JUNIPER_PIC_ATM1:
      if (check_col(pinfo->cinfo, COL_PROTOCOL))
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper ATM1");
      break;
  case JUNIPER_PIC_ATM2:
      if (check_col(pinfo->cinfo, COL_PROTOCOL))
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper ATM2");
      break;
  default: /* should not happen */
      if (check_col(pinfo->cinfo, COL_PROTOCOL))
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper ATM unknown");
      return;

  }

  if (check_col(pinfo->cinfo, COL_INFO))
      col_clear(pinfo->cinfo, COL_INFO);

  switch (atm_pictype) {
  case JUNIPER_PIC_ATM1:
      ti = proto_tree_add_text (tree, tvb, 0, 4 , "Juniper ATM1 PIC");
      break;
  case JUNIPER_PIC_ATM2:
      ti = proto_tree_add_text (tree, tvb, 0, 4 , "Juniper ATM2 PIC");
      break;
  default: /* should not happen */
      ti = proto_tree_add_text (tree, tvb, 0, 0 , "Juniper unknown ATM PIC");
      return;
  }

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);
  if(bytes_processed == -1)
      return;
  else
      offset+=bytes_processed;

  if ((flags & JUNIPER_FLAG_NO_L2) == JUNIPER_FLAG_NO_L2) {
      atm1_header_len = 4;
      atm2_header_len = 4;
  }
  else {
      atm1_header_len = 4;
      atm2_header_len = 8;
  }

  cookie1 = tvb_get_ntohl(tvb,4);
  cookie2 = tvb_get_ntoh64(tvb,4);

  switch (atm_pictype) {
  case JUNIPER_PIC_ATM1:
      tisub = proto_tree_add_uint(juniper_subtree, hf_juniper_atm1_cookie, tvb, 4, 4, cookie1);
      offset += atm1_header_len;
      if (cookie1 & 0x80000000) /* OAM cell ? */
          next_proto = PROTO_OAM;
      break;
  case JUNIPER_PIC_ATM2:
      tisub = proto_tree_add_uint64(juniper_subtree, hf_juniper_atm2_cookie, tvb, 4, 8, cookie2);
      offset += atm2_header_len;
      if (cookie2 & 0x7000) /* OAM cell ? */
          next_proto = PROTO_OAM;
      break;
  default: /* should not happen */
      return;  
  }

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);  

  if (next_proto == PROTO_OAM) {
      dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_OAM, offset);
      return;
  }

  proto = tvb_get_ntoh24(tvb, offset); /* first try: 24-Bit guess */

  if (proto == JUNIPER_HDR_NLPID) {
      /*
       * This begins with something that appears to be an LLC header for
       * OSI; is this LLC-multiplexed traffic?
       */
      dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_LLC, offset);
      return;
  }

  if (proto == JUNIPER_HDR_SNAP) {
      /*
       * This begins with something that appears to be an LLC header for
       * SNAP; is this LLC-multiplexed traffic?
       */
      dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_LLC_SNAP, offset);
      return;
  }

  if ((flags & JUNIPER_FLAG_PKT_IN) != JUNIPER_FLAG_PKT_IN && /* ether-over-1483 encaps ? */
      (cookie1 & JUNIPER_ATM2_GAP_COUNT_MASK) &&
      atm_pictype != JUNIPER_PIC_ATM1) {
      dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_ETHER, offset);
      return;
  }

  proto = tvb_get_ntohs(tvb, offset); /* second try: 16-Bit guess */

  if ( ppp_heuristic_guess( (guint16) proto) && 
       atm_pictype != JUNIPER_PIC_ATM1) {
      /*
       * This begins with something that appears to be a PPP protocol
       * type; is this VC-multiplexed PPPoA?
       * That's not supported on ATM1 PICs.
       */
      ti = proto_tree_add_text (juniper_subtree, tvb, offset, 0, "Encapsulation Type: VC-MUX");
      dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_PPP , offset);
      return;
  }

  proto = tvb_get_guint8(tvb, offset); /* third try: 8-Bit guess */

  if ( proto == JUNIPER_HDR_LLC_UI ) {
      /*
       * Cisco style NLPID encaps?
       * Is the 0x03 an LLC UI control field?
       */
      ti = proto_tree_add_text (juniper_subtree, tvb, offset, 1, "Encapsulation Type: Cisco NLPID");
      dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_ISO , offset+1);
      return;
  }

  next_proto = ip_heuristic_guess( (guint8) proto);
  if (next_proto != PROTO_UNKNOWN) { /* last resort: VC-MUX encaps ? */
      /*
       * This begins with something that might be the first byte of
       * an IPv4 or IPv6 packet; is this VC-multiplexed IP?
       */
      ti = proto_tree_add_text (juniper_subtree, tvb, offset, 0, "Encapsulation Type: VC-MUX");
      dissect_juniper_payload_proto(tvb, pinfo, tree, ti, next_proto , offset);
      return;
  }

  /* could not figure what it is */
  ti = proto_tree_add_text (juniper_subtree, tvb, offset, -1, "Payload Type: unknown");
  call_dissector(data_handle, next_tvb, pinfo, tree);  
}

/* list of Juniper supported PPP proto IDs */
static gboolean
ppp_heuristic_guess(guint16 proto) {

    switch(proto) {
    case PPP_IP :
    case PPP_OSI :
    case PPP_MPLS_UNI :
    case PPP_MPLS_MULTI :
    case PPP_IPCP :
    case PPP_OSICP :
    case PPP_MPLSCP :
    case PPP_LCP :
    case PPP_PAP :
    case PPP_CHAP :
    case PPP_MP :
    case PPP_IPV6 :
    case PPP_IPV6CP :
        return TRUE;
        break;

    default:
        return FALSE; /* did not find a ppp header */
        break;
    }
}

/*
 * return the IP version number based on the first byte of the IP header
 * returns 0 if it does not match a valid first IPv4/IPv6 header byte
 */
static guint
ip_heuristic_guess(guint8 ip_header_byte) {

    switch(ip_header_byte) {
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
    case 0x4c:
    case 0x4d:
    case 0x4e:
    case 0x4f:
        return PROTO_IP;
        break;
    case 0x60:
    case 0x61:
    case 0x62:
    case 0x63:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
    case 0x68:
    case 0x69:
    case 0x6a:
    case 0x6b:
    case 0x6c:
    case 0x6d:
    case 0x6e:
    case 0x6f:
        return PROTO_IP6;
        break;
    default:
        return PROTO_UNKNOWN; /* did not find a ip header */
    }
}

/* return cookie length dep. on cookie SVC id */
static
guint juniper_svc_cookie_len (guint64 cookie) {

    guint8 svc_cookie_id;
    svc_cookie_id = (guint8)(cookie >> 56) & 0xff;

    switch(svc_cookie_id) {
    case 0x54:
        return LS_PIC_COOKIE_LEN;
    case GSP_SVC_REQ_APOLLO:
    case GSP_SVC_REQ_LSQ:
        return AS_PIC_COOKIE_LEN;
    default:
        return 0;
    }
}

/* return the next-level protocol based on cookie input */
static guint
juniper_svc_cookie_proto (guint64 cookie, guint16 pictype, guint8 flags) {

    guint8 svc_cookie_id;
    guint16 lsq_proto;
    guint8 lsq_dir;

    svc_cookie_id = (guint8)(cookie >> 56) & 0xff;
    lsq_proto = (guint16)((cookie >> 16) & LSQ_L3_PROTO_MASK);
    lsq_dir = (guint8)(cookie >> 24) & 0x3;


    switch (svc_cookie_id) {
    case 0x54:
        switch (pictype) {
        case JUNIPER_PIC_MLPPP:
            return PROTO_PPP;
        case JUNIPER_PIC_MLFR:
            return PROTO_ISO;
        default:
            return PROTO_UNKNOWN;
        }
    case GSP_SVC_REQ_APOLLO:
    case GSP_SVC_REQ_LSQ:
        switch(lsq_proto) {
        case LSQ_L3_PROTO_IPV4:
            switch(pictype) {
            case JUNIPER_PIC_MLPPP:
                /* incoming traffic would have the direction bits set
                 * -> this must be IS-IS over PPP
                 */
                if ((flags & JUNIPER_FLAG_PKT_IN) == JUNIPER_FLAG_PKT_IN &&
                    lsq_dir != (LSQ_COOKIE_RE|LSQ_COOKIE_DIR))
                    return PROTO_PPP;
                else
                    return PROTO_IP;
            case JUNIPER_PIC_MLFR:
                if (lsq_dir == (LSQ_COOKIE_RE|LSQ_COOKIE_DIR))
                    return PROTO_UNKNOWN;
                else
                    return PROTO_IP;
            default:
                return PROTO_UNKNOWN;
            }
        case LSQ_L3_PROTO_IPV6:
            return PROTO_IP6;
        case LSQ_L3_PROTO_MPLS:
            return PROTO_MPLS;
        case LSQ_L3_PROTO_ISO:
            return PROTO_ISO;
        default:
            return PROTO_UNKNOWN;
        }
    default:
        return PROTO_UNKNOWN;
    }
}


void
proto_register_juniper(void)
{
  static hf_register_info hf[] = {
    { &hf_juniper_magic,
      { "Magic Number", "juniper.magic-number", FT_UINT24, BASE_HEX,
        NULL, 0x0, "", HFILL }},
    { &hf_juniper_direction,
      { "Direction", "juniper.direction", FT_UINT8, BASE_HEX,
        VALS(juniper_direction_vals), 0x0, "", HFILL }},
    { &hf_juniper_l2hdr_presence,
      { "L2 header presence", "juniper.l2hdr", FT_UINT8, BASE_HEX,
        VALS(juniper_l2hdr_presence_vals), 0x0, "", HFILL }},
    { &hf_juniper_ext_len,
      { "Extension length", "juniper.ext_len", FT_UINT16, BASE_DEC,
        NULL, 0x0, "", HFILL }},
    { &hf_juniper_atm2_cookie,
      { "Cookie", "juniper.atm2.cookie", FT_UINT64, BASE_HEX,
        NULL, 0x0, "", HFILL }},
    { &hf_juniper_atm1_cookie,
      { "Cookie", "juniper.atm1.cookie", FT_UINT32, BASE_HEX,
        NULL, 0x0, "", HFILL }},
    { &hf_juniper_mlpic_cookie,
    { "Cookie", "juniper.mlpic.cookie", FT_UINT16, BASE_HEX,
        NULL, 0x0, "", HFILL }},
    { &hf_juniper_lspic_cookie,
    { "Cookie", "juniper.lspic.cookie", FT_UINT32, BASE_HEX,
        NULL, 0x0, "", HFILL }},
    { &hf_juniper_aspic_cookie,
    { "Cookie", "juniper.aspic.cookie", FT_UINT64, BASE_HEX,
        NULL, 0x0, "", HFILL }},
  };

  static gint *ett[] = {
    &ett_juniper,
  };

  proto_juniper = proto_register_protocol("Juniper", "Juniper", "juniper");
  proto_register_field_array(proto_juniper, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_juniper(void)
{
  dissector_handle_t juniper_atm1_handle;
  dissector_handle_t juniper_atm2_handle;
  dissector_handle_t juniper_pppoe_handle;
  dissector_handle_t juniper_mlppp_handle;
  dissector_handle_t juniper_mlfr_handle;

  osinl_subdissector_table = find_dissector_table("osinl");
  osinl_excl_subdissector_table = find_dissector_table("osinl.excl");
  eth_handle = find_dissector("eth_withoutfcs");
  ppp_handle = find_dissector("ppp");
  llc_handle = find_dissector("llc");
  ipv4_handle = find_dissector("ip");
  ipv6_handle = find_dissector("ipv6");
  mpls_handle = find_dissector("mpls");
  q933_handle = find_dissector("q933");
  frelay_handle = find_dissector("fr");
  data_handle = find_dissector("data");

  juniper_atm2_handle = create_dissector_handle(dissect_juniper_atm2, proto_juniper);
  juniper_atm1_handle = create_dissector_handle(dissect_juniper_atm1, proto_juniper);
  juniper_pppoe_handle = create_dissector_handle(dissect_juniper_pppoe, proto_juniper);
  juniper_mlppp_handle = create_dissector_handle(dissect_juniper_mlppp, proto_juniper);
  juniper_mlfr_handle = create_dissector_handle(dissect_juniper_mlfr, proto_juniper);
  dissector_add("wtap_encap", WTAP_ENCAP_JUNIPER_ATM2, juniper_atm2_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_JUNIPER_ATM1, juniper_atm1_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_JUNIPER_PPPOE, juniper_pppoe_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_JUNIPER_MLPPP, juniper_mlppp_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_JUNIPER_MLFR, juniper_mlfr_handle);
}

