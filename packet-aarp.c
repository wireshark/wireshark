/* packet-aarp.c
 * Routines for Appletalk ARP packet disassembly
 *
 * $Id: packet-aarp.c,v 1.25 2000/11/19 08:53:54 guy Exp $
 *
 * Simon Wilkinson <sxw@dcs.ed.ac.uk>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <glib.h>
#include "packet.h"
#include "strutil.h"
#include "etypes.h"

static int proto_aarp = -1;
static int hf_aarp_hard_type = -1;
static int hf_aarp_proto_type = -1;
static int hf_aarp_hard_size = -1;
static int hf_aarp_proto_size = -1;
static int hf_aarp_opcode = -1;
static int hf_aarp_src_ether = -1;
static int hf_aarp_src_id = -1;
static int hf_aarp_dst_ether = -1;
static int hf_aarp_dst_id = -1;

static gint ett_aarp = -1;

#ifndef AARP_REQUEST
#define AARP_REQUEST 	0x0001
#endif
#ifndef AARP_REPLY
#define AARP_REPLY	0x0002
#endif
#ifndef AARP_PROBE	
#define AARP_PROBE	0x0003
#endif

/* The following is screwed up shit to deal with the fact that
   the linux kernel edits the packet inline. */
#define AARP_REQUEST_SWAPPED    0x0100
#define AARP_REPLY_SWAPPED  0x0200
#define AARP_PROBE_SWAPPED  0x0300

static const value_string op_vals[] = {
  {AARP_REQUEST,  "request" },
  {AARP_REPLY,    "reply"   },
  {AARP_PROBE,    "probe"   },
  {AARP_REQUEST_SWAPPED,  "request" },
  {AARP_REPLY_SWAPPED,    "reply"   },
  {AARP_PROBE_SWAPPED,    "probe"   },
  {0,             NULL           } };

/* AARP protocol HARDWARE identifiers. */
#define AARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/
#define	AARPHRD_TR	2		/* Token Ring			*/

static const value_string hrd_vals[] = {
  {AARPHRD_ETHER,   "Ethernet"       },
  {AARPHRD_TR,      "Token Ring"     },
  {0,               NULL             } };

static gchar *
atalkid_to_str(const guint8 *ad) {
  gint node;
  static gchar  str[3][16];
  static gchar *cur;
  
  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  
  node=ad[1]<<8|ad[2];
  sprintf(cur, "%d.%d",node,ad[3]);
  return cur;
}

static gchar *
aarphrdaddr_to_str(guint8 *ad, int ad_len, guint16 type) {
  if ((type == AARPHRD_ETHER || type == AARPHRD_TR) && ad_len == 6) {
    /* Ethernet address (or Token Ring address, which is the same type
       of address). */
    return ether_to_str(ad);
  }
  return bytes_to_str(ad, ad_len);
}

static gchar *
aarpproaddr_to_str(guint8 *ad, int ad_len, guint16 type) {
  if (type == ETHERTYPE_ATALK && ad_len == 4) {
    /* IP address.  */
    return atalkid_to_str(ad);
  }
  return bytes_to_str(ad, ad_len);
}
    
/* Offsets of fields within an AARP packet. */
#define	AR_HRD		0
#define	AR_PRO		2
#define	AR_HLN		4
#define	AR_PLN		5
#define	AR_OP		6
#define MIN_AARP_HEADER_SIZE	8

void
dissect_aarp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  guint16     ar_hrd;
  guint16     ar_pro;
  guint8      ar_hln;
  guint8      ar_pln;
  guint16     ar_op;
  proto_tree  *aarp_tree;
  proto_item  *ti;
  gchar       *op_str;
  int         sha_offset, spa_offset, tha_offset, tpa_offset;
  guint8      *sha_val, *spa_val, *tha_val, *tpa_val;
  gchar       *sha_str, *spa_str, *tha_str, *tpa_str;

  CHECK_DISPLAY_AS_DATA(proto_aarp, tvb, pinfo, tree);

  pinfo->current_proto = "AARP";

  ar_hrd = tvb_get_ntohs(tvb, AR_HRD);
  ar_pro = tvb_get_ntohs(tvb, AR_PRO);
  ar_hln = tvb_get_guint8(tvb, AR_HLN);
  ar_pln = tvb_get_guint8(tvb, AR_PLN);
  ar_op  = tvb_get_ntohs(tvb, AR_OP);

  /* Extract the addresses.  */
  sha_offset = MIN_AARP_HEADER_SIZE;
  sha_val = tvb_get_ptr(tvb, sha_offset, ar_hln);
  sha_str = aarphrdaddr_to_str(sha_val, ar_hln, ar_hrd);

  spa_offset = sha_offset + ar_hln;
  spa_val = tvb_get_ptr(tvb, spa_offset, ar_pln);
  spa_str = aarpproaddr_to_str(spa_val, ar_pln, ar_pro);

  tha_offset = spa_offset + ar_pln;
  tha_val = tvb_get_ptr(tvb, tha_offset, ar_hln);
  tha_str = aarphrdaddr_to_str(tha_val, ar_hln, ar_hrd);

  tpa_offset = tha_offset + ar_hln;
  tpa_val = tvb_get_ptr(tvb, tpa_offset, ar_pln);
  tpa_str = aarpproaddr_to_str(tpa_val, ar_pln, ar_pro);
  
  if(check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "AARP");

  if (check_col(pinfo->fd, COL_INFO)) {
    switch (ar_op) {
      case AARP_REQUEST:
      case AARP_REQUEST_SWAPPED:
        col_add_fstr(pinfo->fd, COL_INFO, "Who has %s?  Tell %s", tpa_str, spa_str);
        break;
      case AARP_REPLY:
      case AARP_REPLY_SWAPPED:
        col_add_fstr(pinfo->fd, COL_INFO, "%s is at %s", spa_str, sha_str);
        break;
      case AARP_PROBE:
      case AARP_PROBE_SWAPPED:
        col_add_fstr(pinfo->fd, COL_INFO, "Is there a %s", tpa_str);
        break;
      default:
        col_add_fstr(pinfo->fd, COL_INFO, "Unknown AARP opcode 0x%04x", ar_op);
        break;
    }
  }

  if (tree) {
    if ((op_str = match_strval(ar_op, op_vals)))
      ti = proto_tree_add_protocol_format(tree, proto_aarp, tvb, 0,
				      MIN_AARP_HEADER_SIZE + 2*ar_hln + 
				      2*ar_pln, "AppleTalk Address Resolution Protocol (%s)", op_str);
    else
      ti = proto_tree_add_protocol_format(tree, proto_aarp, tvb, 0,
				      MIN_AARP_HEADER_SIZE + 2*ar_hln + 
				      2*ar_pln,
				      "AppleTalk Address Resolution Protocol (opcode 0x%04x)", ar_op);
    aarp_tree = proto_item_add_subtree(ti, ett_aarp);
    proto_tree_add_uint(aarp_tree, hf_aarp_hard_type, tvb, AR_HRD, 2,
			       ar_hrd);
    proto_tree_add_uint(aarp_tree, hf_aarp_proto_type, tvb, AR_PRO, 2, 
			       ar_pro);
    proto_tree_add_uint(aarp_tree, hf_aarp_hard_size, tvb, AR_HLN, 1,
			       ar_hln);
    proto_tree_add_uint(aarp_tree, hf_aarp_proto_size, tvb, AR_PLN, 1,
			       ar_pln);
    proto_tree_add_uint(aarp_tree, hf_aarp_opcode, tvb, AR_OP, 2,
			       ar_op);
    proto_tree_add_bytes_format(aarp_tree, hf_aarp_src_ether, tvb, sha_offset, ar_hln,
			       sha_val,
			       "Sender hardware address: %s", sha_str);
    proto_tree_add_bytes_format(aarp_tree, hf_aarp_src_id, tvb, spa_offset, ar_pln,
			       spa_val,
			       "Sender ID: %s", spa_str);
    proto_tree_add_bytes_format(aarp_tree, hf_aarp_dst_ether, tvb, tha_offset, ar_hln,
			       tha_val,
			       "Target hardware address: %s", tha_str);
    proto_tree_add_bytes_format(aarp_tree, hf_aarp_dst_id, tvb, tpa_offset, ar_pln,
			       tpa_val,
			       "Target ID: %s", tpa_str);
  }
}

void
proto_register_aarp(void)
{
  static hf_register_info hf[] = {
    { &hf_aarp_hard_type,
      { "Hardware type",	"aarp.hard.type",	
	FT_UINT16,	BASE_HEX,	VALS(hrd_vals),	0x0,
      	"" }},

    { &hf_aarp_proto_type,
      { "Protocol type",	"aarp.proto.type",	
	FT_UINT16,	BASE_HEX, 	VALS(etype_vals),	0x0,
      	"" }},    

    { &hf_aarp_hard_size,
      { "Hardware size",	"aarp.hard.size",	
	FT_UINT8,	BASE_DEC, 	NULL,	0x0,
      	"" }},

    { &hf_aarp_proto_size,
      { "Protocol size",	"aarp.proto.size",	
	FT_UINT8,	BASE_DEC, 	NULL,	0x0,
      	"" }},

    { &hf_aarp_opcode,
      { "Opcode",		"aarp.opcode",
	FT_UINT16,	BASE_DEC,	VALS(op_vals),	0x0,
      	"" }},

    { &hf_aarp_src_ether,
      { "Sender ether",		"aarp.src.ether",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_aarp_src_id,
      { "Sender ID",		"aarp.src.id",
	FT_BYTES,	BASE_HEX,	NULL,	0x0,
      	"" }},

    { &hf_aarp_dst_ether,
      { "Target ether",		"aarp.dst.ether",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_aarp_dst_id,
      { "Target ID",		"aarp.dst.id",		
	FT_BYTES,	BASE_HEX,	NULL,	0x0,
      	"" }},
  };
  static gint *ett[] = {
    &ett_aarp,
  };

  proto_aarp = proto_register_protocol("Appletalk Address Resolution Protocol",
				       "aarp");
  proto_register_field_array(proto_aarp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aarp(void)
{
  dissector_add("ethertype", ETHERTYPE_AARP, dissect_aarp);
}
