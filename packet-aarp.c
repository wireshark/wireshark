/* packet-aarp.c
 * Routines for Appletalk ARP packet disassembly
 *
 * $Id: packet-aarp.c,v 1.11 1999/10/12 06:20:00 gram Exp $
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

typedef struct _e_ether_aarp {
        guint16 htype, ptype;
        guint8  halen, palen;
        guint16 op;
        guint8  hsaddr[6];
        guint8  psaddr[4];
        guint8  hdaddr[6];
        guint8  pdaddr[4];
} e_ether_aarp;

#ifndef AARP_REQUEST
#define AARP_REQUEST 	0x0001
#endif
#ifndef AARP_REPLY
#define AARP_REPLY	0x0002
#endif
#ifndef AARP_PROBE	
#define AARP_PROBE	0x0003
#endif

gchar *
atalkid_to_str(guint8 *ad) {
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
    
void
dissect_aarp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  e_ether_aarp  ea;
  proto_tree	*aarp_tree;
  proto_item	*ti;
  gchar			*op_str;
  value_string op_vals[] = { {AARP_REQUEST,  "AARP request" },
                             {AARP_REPLY,    "AARP reply"   },
                             {AARP_PROBE,    "AARP probe"   },
                             {0,             NULL           } };

  if (!BYTES_ARE_IN_FRAME(offset, sizeof(e_ether_aarp))) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  ea.htype = pntohs(&pd[offset]);
  ea.ptype = pntohs(&pd[offset + 2]);
  ea.halen = (guint8) pd[offset + 4];
  ea.palen = (guint8) pd[offset + 5];
  ea.op  = pntohs(&pd[offset + 6]);
  memcpy(&ea.hsaddr, &pd[offset +  8], 6);
  memcpy(&ea.psaddr, &pd[offset + 14], 4);
  memcpy(&ea.hdaddr, &pd[offset + 18], 6);
  memcpy(&ea.pdaddr, &pd[offset + 24], 4);
  
  if(check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "AARP");
  
  if (tree) {
    if ((op_str = match_strval(ea.op, op_vals)))
      ti = proto_tree_add_item_format(tree, proto_aarp, offset, 28, NULL, op_str);
    else
      ti = proto_tree_add_item_format(tree, proto_aarp, offset, 28, NULL,
        "Unknown AARP (opcode 0x%04x)", ea.op);
    aarp_tree = proto_item_add_subtree(ti, ETT_AARP);
    proto_tree_add_item_format(aarp_tree, hf_aarp_hard_type, offset,      2,
			       ea.htype,
			       "Hardware type: 0x%04x", 
			       ea.htype);
    proto_tree_add_item_format(aarp_tree, hf_aarp_proto_type, offset +  2, 2,
			       ea.ptype,
			       "Protocol type: 0x%04x",
			       ea.ptype);
    proto_tree_add_item_format(aarp_tree, hf_aarp_hard_size, offset +  4, 1,
			       ea.halen,
			       "Hardware size: 0x%02x", 
			       ea.halen);
    proto_tree_add_item_format(aarp_tree, hf_aarp_proto_size, offset +  5, 1,
			       ea.palen,
			       "Protocol size: 0x%02x", 
			       ea.palen);
    proto_tree_add_item_format(aarp_tree, hf_aarp_opcode, offset +  6, 2,
			       ea.op,
			       "Opcode: 0x%04x (%s)",
			       ea.op, op_str ? op_str : "Unknown");
    proto_tree_add_item(aarp_tree, hf_aarp_src_ether, offset +  8, 6,
			ea.hsaddr);
    proto_tree_add_item_format(aarp_tree, hf_aarp_src_id, offset + 14, 4,
			       ea.psaddr,
			       "Sender ID: %s", 
			       atalkid_to_str((guint8 *) ea.psaddr));
    proto_tree_add_item(aarp_tree, hf_aarp_dst_ether, offset + 18, 6,
			ea.hdaddr);
    proto_tree_add_item_format(aarp_tree, hf_aarp_dst_id, offset + 24, 4,
			       ea.pdaddr,
			       "Target ID: %s", 
			       atalkid_to_str((guint8 *) ea.pdaddr));
  }

  if (ea.ptype != ETHERTYPE_AARP && ea.ptype != ETHERTYPE_ATALK && 
      check_col(fd, COL_INFO)) {
    col_add_fstr(fd, COL_INFO, "h/w %d (%d) prot %d (%d) op 0x%04x",
      ea.htype, ea.halen, ea.ptype, ea.palen, ea.op);
    return;
  }
  if (check_col(fd, COL_INFO)) {
    switch (ea.op) {
      case AARP_REQUEST:
        col_add_fstr(fd, COL_INFO, "Who has %s?  Tell %s",
          atalkid_to_str((guint8 *) ea.pdaddr), atalkid_to_str((guint8 *) ea.psaddr));
        break;
      case AARP_REPLY:
        col_add_fstr(fd, COL_INFO, "%s is at %s",
          atalkid_to_str((guint8 *) ea.psaddr),
          ether_to_str((guint8 *) ea.hsaddr));
        break;
      case AARP_PROBE:
        col_add_fstr(fd, COL_INFO, "Is there a %s",
          atalkid_to_str((guint8 *) ea.pdaddr));
        break;
    }
  }
}

void
proto_register_aarp(void)
{
  static hf_register_info hf[] = {
    { &hf_aarp_hard_type,
      { "Hardware type", "aarp.hard.type",	FT_UINT16, BASE_HEX, 	NULL, 0x0,
      	"" }},

    { &hf_aarp_proto_type,
      { "Protocol type", "aarp.proto.type",	FT_UINT16, BASE_HEX, 	NULL, 0x0,
      	"" }},    

    { &hf_aarp_hard_size,
      { "Hardware size", "aarp.hard.size",	FT_UINT8, BASE_DEC, 	NULL, 0x0,
      	"" }},

    { &hf_aarp_proto_size,
      { "Protocol size", "aarp.proto.size",	FT_UINT8, BASE_DEC, 	NULL, 0x0,
      	"" }},

    { &hf_aarp_opcode,
      { "Opcode",	 "aarp.opcode",		FT_UINT16, BASE_DEC,	NULL, 0x0,
      	"" }},

    { &hf_aarp_src_ether,
      { "Sender ether",	 "aarp.src.ether",	FT_ETHER, BASE_NONE,	NULL, 0x0,
      	"" }},

    { &hf_aarp_src_id,
      { "Sender ID",	 "aarp.src.id",		FT_UINT32, BASE_HEX,	NULL, 0x0,
      	"" }},

    { &hf_aarp_dst_ether,
      { "Target ether",	 "aarp.dst.ether",	FT_ETHER, BASE_NONE,	NULL, 0x0,
      	"" }},

    { &hf_aarp_dst_id,
      { "Target ID",	 "aarp.dst.id",		FT_UINT32, BASE_HEX,	NULL, 0x0,
      	"" }},
  };

  proto_aarp = proto_register_protocol("Appletalk Address Resolution Protocol",
				       "aarp");
  proto_register_field_array(proto_aarp, hf, array_length(hf));
}
