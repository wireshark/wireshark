/* packet-aarp.c
 * Routines for Appletalk ARP packet disassembly
 *
 * $Id: packet-aarp.c,v 1.14 1999/11/16 11:42:23 guy Exp $
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

static const value_string op_vals[] = {
  {AARP_REQUEST,  "AARP request" },
  {AARP_REPLY,    "AARP reply"   },
  {AARP_PROBE,    "AARP probe"   },
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
dissect_aarp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  guint16     ar_hrd;
  guint16     ar_pro;
  guint8      ar_hln;
  guint8      ar_pln;
  guint16     ar_op;
  proto_tree  *aarp_tree;
  proto_item  *ti;
  gchar       *op_str;
  int         sha_offset, spa_offset, tha_offset, tpa_offset;
  gchar       *sha_str, *spa_str, *tha_str, *tpa_str;

  if (!BYTES_ARE_IN_FRAME(offset, MIN_AARP_HEADER_SIZE)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  ar_hrd = pntohs(&pd[offset + AR_HRD]);
  ar_pro = pntohs(&pd[offset + AR_PRO]);
  ar_hln = (guint8) pd[offset + AR_HLN];
  ar_pln = (guint8) pd[offset + AR_PLN];
  ar_op  = pntohs(&pd[offset + AR_OP]);

  if (!BYTES_ARE_IN_FRAME(offset, 
			  MIN_AARP_HEADER_SIZE + ar_hln*2 + ar_pln*2)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }
  
  /* Extract the addresses.  */
  sha_offset = offset + MIN_AARP_HEADER_SIZE;
  sha_str = aarphrdaddr_to_str((guint8 *) &pd[sha_offset], ar_hln, ar_hrd);
  spa_offset = sha_offset + ar_hln;
  spa_str = aarpproaddr_to_str((guint8 *) &pd[spa_offset], ar_pln, ar_pro);
  tha_offset = spa_offset + ar_pln;
  tha_str = aarphrdaddr_to_str((guint8 *) &pd[tha_offset], ar_hln, ar_hrd);
  tpa_offset = tha_offset + ar_hln;
  tpa_str = aarpproaddr_to_str((guint8 *) &pd[tpa_offset], ar_pln, ar_pro);
  
  if(check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "AARP");

  if (check_col(fd, COL_INFO)) {
    switch (ar_op) {
      case AARP_REQUEST:
        col_add_fstr(fd, COL_INFO, "Who has %s?  Tell %s", tpa_str, spa_str);
        break;
      case AARP_REPLY:
        col_add_fstr(fd, COL_INFO, "%s is at %s", spa_str, sha_str);
        break;
      case AARP_PROBE:
        col_add_fstr(fd, COL_INFO, "Is there a %s", tpa_str);
        break;
      default:
        col_add_fstr(fd, COL_INFO, "Unknown AARP opcode 0x%04x", ar_op);
        break;
    }
  }

  if (tree) {
    if ((op_str = match_strval(ar_op, op_vals)))
      ti = proto_tree_add_item_format(tree, proto_aarp, offset,
				      MIN_AARP_HEADER_SIZE + 2*ar_hln + 
				      2*ar_pln, NULL, op_str);
    else
      ti = proto_tree_add_item_format(tree, proto_aarp, offset,
				      MIN_AARP_HEADER_SIZE + 2*ar_hln + 
				      2*ar_pln, NULL,
				      "Unknown AARP (opcode 0x%04x)", ar_op);
    aarp_tree = proto_item_add_subtree(ti, ett_aarp);
    proto_tree_add_item(aarp_tree, hf_aarp_hard_type, offset + AR_HRD, 2,
			       ar_hrd);
    proto_tree_add_item(aarp_tree, hf_aarp_proto_type, offset + AR_PRO, 2, 
			       ar_pro);
    proto_tree_add_item(aarp_tree, hf_aarp_hard_size, offset + AR_HLN, 1,
			       ar_hln);
    proto_tree_add_item(aarp_tree, hf_aarp_proto_size, offset + AR_PLN, 1,
			       ar_pln);
    proto_tree_add_item(aarp_tree, hf_aarp_opcode, offset + AR_OP, 2,
			       ar_op);
    proto_tree_add_item_format(aarp_tree, hf_aarp_src_ether, sha_offset, ar_hln,
			       &pd[sha_offset],
			       "Sender hardware address: %s", sha_str);
    proto_tree_add_item_format(aarp_tree, hf_aarp_src_id, spa_offset, ar_pln,
			       &pd[spa_offset],
			       "Sender ID: %s", spa_str);
    proto_tree_add_item_format(aarp_tree, hf_aarp_dst_ether, tha_offset, ar_hln,
			       &pd[tha_offset],
			       "Target hardware address: %s", tha_str);
    proto_tree_add_item_format(aarp_tree, hf_aarp_dst_id, tpa_offset, ar_pln,
			       &pd[tpa_offset],
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
