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

#define JUNIPER_FLAG_PKT_OUT        0x00     /* Outgoing packet */
#define JUNIPER_FLAG_PKT_IN         0x01     /* Incoming packet */
#define JUNIPER_FLAG_NO_L2          0x02     /* L2 header stripped */
#define JUNIPER_ATM2_PKT_TYPE_MASK  0x70
#define JUNIPER_ATM2_GAP_COUNT_MASK 0x3F
#define JUNIPER_PCAP_MAGIC          0x4d4743

#define JUNIPER_ATM1   1
#define JUNIPER_ATM2   2

#define JUNIPER_HDR_SNAP   0xaaaa03
#define JUNIPER_HDR_NLPID  0xfefe03
#define JUNIPER_HDR_CNLPID 0x03

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
static int hf_juniper_atm1_cookie = -1;
static int hf_juniper_atm2_cookie = -1;

static gint ett_juniper = -1;

static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t eth_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t data_handle;

static dissector_table_t osinl_subdissector_table;
static dissector_table_t osinl_excl_subdissector_table;

static void dissect_juniper_atm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 atm_pictype);
static gboolean ppp_heuristic_guess(guint16 proto);
static guint ip_heuristic_guess(guint8 ip_header_byte);

/* wrapper for passing the PIC type to the generic ATM dissector */
static void
dissect_juniper_atm1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{ 
    dissect_juniper_atm(tvb,pinfo,tree, JUNIPER_ATM1);
}

/* wrapper for passing the PIC type to the generic ATM dissector */
static void
dissect_juniper_atm2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{ 
    dissect_juniper_atm(tvb,pinfo,tree, JUNIPER_ATM2);
}

/* generic ATM dissector */
static void
dissect_juniper_atm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 atm_pictype)
{
  proto_item *ti,*tisub;
  proto_tree *subtree = NULL;
  guint8     direction,l2hdr_presence,flags,ipvers,atm1_header_len,atm2_header_len;
  guint32    magic_number, cookie1, proto;
  guint64    cookie2;
  guint      offset;

  tvbuff_t   *next_tvb;

  switch (atm_pictype) {
  case JUNIPER_ATM1:
      if (check_col(pinfo->cinfo, COL_PROTOCOL))
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper ATM1");
      break;
  case JUNIPER_ATM2:
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

  offset = 0;
  magic_number = tvb_get_ntoh24(tvb, 0);
  flags = tvb_get_guint8(tvb, 3);
  direction = flags & JUNIPER_FLAG_PKT_IN;
  l2hdr_presence = flags & JUNIPER_FLAG_NO_L2;

  if ((flags & JUNIPER_FLAG_NO_L2) == JUNIPER_FLAG_NO_L2) {
      atm1_header_len = 8;
      atm2_header_len = 8;
  }
  else {
      atm1_header_len = 8;
      atm2_header_len = 12;
  }

  switch (atm_pictype) {
  case JUNIPER_ATM1:
      ti = proto_tree_add_text (tree, tvb, 0, atm1_header_len, "Juniper ATM1 PIC");
      break;
  case JUNIPER_ATM2:
      ti = proto_tree_add_text (tree, tvb, 0, atm2_header_len, "Juniper ATM2 PIC");
      break;
  default: /* should not happen */
      ti = proto_tree_add_text (tree, tvb, 0, 0 , "Juniper unknown ATM PIC");
      return;
  }

  subtree = proto_item_add_subtree(ti, ett_juniper);  
        
  tisub = proto_tree_add_text (subtree, tvb, 0, 3,
                            "Magic-Number: 0x%06x (%scorrect)", 
                            magic_number,
                            (magic_number == JUNIPER_PCAP_MAGIC) ?  "" : "in" );
    
  if (magic_number != JUNIPER_PCAP_MAGIC)
     return;
  
  tisub = proto_tree_add_uint_format (subtree, hf_juniper_direction, tvb, 3, 1,
                            direction, "Direction: %s",
                            val_to_str(direction,juniper_direction_vals,"Unknown"));
  
  tisub = proto_tree_add_uint_format (subtree, hf_juniper_l2hdr_presence, tvb, 3, 1,
                            l2hdr_presence, "L2-header: %s",
                            val_to_str(l2hdr_presence,juniper_l2hdr_presence_vals,"Unknown"));


  switch (atm_pictype) {
  case JUNIPER_ATM1:
      offset += atm1_header_len;
      break;
  case JUNIPER_ATM2:
      offset += atm2_header_len;
      break;
  default: /* should not happen */
      return;  
  }

  if ((flags & JUNIPER_FLAG_NO_L2) == JUNIPER_FLAG_NO_L2) { /* no link header present ? */
      next_tvb = tvb_new_subset(tvb, offset, -1, -1);
      ipvers = ip_heuristic_guess(tvb_get_guint8(tvb, offset)); /* try IP */
      if (ipvers != 0) {
          ti = proto_tree_add_text (subtree, tvb, offset, 0,
                                    "Payload Type: Null encapsulation IPv%u",
                                    ipvers);
          switch (ipvers) {
          case 6:
              call_dissector(ipv6_handle, next_tvb, pinfo, tree);
              break;
          case 4:
              call_dissector(ipv4_handle, next_tvb, pinfo, tree);  
              break;
          }
      }
      return;
  }

  cookie1 = tvb_get_ntohl(tvb,4);
  cookie2 = tvb_get_ntoh64(tvb,4);

  switch (atm_pictype) {
  case JUNIPER_ATM1:
      tisub = proto_tree_add_uint(subtree, hf_juniper_atm1_cookie, tvb, 4, 4, cookie1);
      break;
  case JUNIPER_ATM2:
      tisub = proto_tree_add_uint64(subtree, hf_juniper_atm2_cookie, tvb, 4, 8, cookie2);
      break;
  default: /* should not happen */
      return;  
  }

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);  

  /* FIXME OAM cells */
    
  proto = tvb_get_ntoh24(tvb, offset); /* first try: 24-Bit guess */

  if (proto == JUNIPER_HDR_NLPID) {
      /*
       * This begins with something that appears to be an LLC header for
       * OSI; is this LLC-multiplexed traffic?
       */
      ti = proto_tree_add_text (subtree, tvb, offset, 0, "Payload Type: LLC/NLPID ");
      call_dissector(llc_handle, next_tvb, pinfo, tree);
      return;
  }

  if (proto == JUNIPER_HDR_SNAP) {
      /*
       * This begins with something that appears to be an LLC header for
       * SNAP; is this LLC-multiplexed traffic?
       */
      ti = proto_tree_add_text (subtree, tvb, offset, 0, "Payload Type: LLC/SNAP ");
      call_dissector(llc_handle, next_tvb, pinfo, tree);
      return;
  }

  if (direction != JUNIPER_FLAG_PKT_IN && /* ether-over-1483 encaps ? */
      (cookie1 & JUNIPER_ATM2_GAP_COUNT_MASK) &&
      atm_pictype != JUNIPER_ATM1) {
      ti = proto_tree_add_text (subtree, tvb, offset, 0, "Payload Type: Ethernet");
      call_dissector(eth_handle, next_tvb, pinfo, tree);
      return;
  }

  proto = tvb_get_ntohs(tvb, offset); /* second try: 16-Bit guess */

  if ( ppp_heuristic_guess(proto) && 
       atm_pictype != JUNIPER_ATM1) {
      /*
       * This begins with something that appears to be a PPP protocol
       * type; is this VC-multiplexed PPPoA?
       * That's not supported on ATM1 PICs.
       */
      ti = proto_tree_add_text (subtree, tvb, offset, 0, "Payload Type: VC-MUX PPP");
      call_dissector(ppp_handle, next_tvb, pinfo, tree);
      return;
  }

  proto = tvb_get_guint8(tvb, offset); /* third try: 8-Bit guess */

  if ( proto == JUNIPER_HDR_CNLPID ) {
      /*
       * Cisco style NLPID encaps?
       * Is the 0x03 an LLC UI control field?
       */
      ti = proto_tree_add_text (subtree, tvb, offset, 1, "Payload Type: Cisco NLPID");
      proto = tvb_get_guint8(tvb, offset+1);
      if(dissector_try_port(osinl_subdissector_table, proto, next_tvb, pinfo, tree))
          return;
      next_tvb = tvb_new_subset(tvb, offset+2, -1, -1);
      if(dissector_try_port(osinl_excl_subdissector_table, proto, next_tvb, pinfo, tree))
          return;
  }

  ipvers = ip_heuristic_guess(proto);
  if (ipvers != 0) { /* last resort: VC-MUX encaps ? */
      /*
       * This begins with something that might be the first byte of
       * an IPv4 or IPv6 packet; is this VC-multiplexed IP?
       */
      ti = proto_tree_add_text (subtree, tvb, offset, 0,
                                "Payload Type: VC-MUX IPv%u",
                                ipvers);
      switch (ipvers) {
      case 6:
          call_dissector(ipv6_handle, next_tvb, pinfo, tree);
          break;
      case 4:
          call_dissector(ipv4_handle, next_tvb, pinfo, tree);  
          break;
      }
      return;
  }

  /* could not figure what it is */
  ti = proto_tree_add_text (subtree, tvb, offset, -1, "Payload Type: unknown");
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
        return 4;
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
        return 6;
        break;
    default:
        return 0; /* did not find a ip header */
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
    { &hf_juniper_atm2_cookie,
      { "Cookie", "juniper.atm2.cookie", FT_UINT64, BASE_HEX,
        NULL, 0x0, "", HFILL }},
    { &hf_juniper_atm1_cookie,
      { "Cookie", "juniper.atm1.cookie", FT_UINT32, BASE_HEX,
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

  osinl_subdissector_table = find_dissector_table("osinl");
  osinl_excl_subdissector_table = find_dissector_table("osinl.excl");
  eth_handle = find_dissector("eth_withoutfcs");
  ppp_handle = find_dissector("ppp");
  llc_handle = find_dissector("llc");
  ipv4_handle = find_dissector("ip");
  ipv6_handle = find_dissector("ipv6");
  data_handle = find_dissector("data");

  juniper_atm2_handle = create_dissector_handle(dissect_juniper_atm2, proto_juniper);
  juniper_atm1_handle = create_dissector_handle(dissect_juniper_atm1, proto_juniper);
  dissector_add("wtap_encap", WTAP_ENCAP_JUNIPER_ATM2, juniper_atm2_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_JUNIPER_ATM1, juniper_atm1_handle);
}

