/* packet-dec-bpdu.c
 * Routines for DEC BPDU (DEC Spanning Tree Protocol) disassembly
 *
 * $Id: packet-dec-bpdu.c,v 1.6 2001/01/25 06:14:14 guy Exp $
 *
 * Copyright 2001 Paul Ionescu <paul@acorp.ro>
 * 
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "packet.h"
#include "resolv.h"
#include "etypes.h"
#include "ppptypes.h"

/* Offsets of fields within a BPDU */

#define BPDU_DEC_CODE            0
#define BPDU_TYPE                1
#define BPDU_VERSION		 2
#define BPDU_FLAGS               3
#define BPDU_ROOT_PRI            4
#define BPDU_ROOT_MAC            6
#define BPDU_ROOT_PATH_COST     12
#define BPDU_BRIDGE_PRI         14
#define BPDU_BRIDGE_MAC         16
#define BPDU_PORT_IDENTIFIER    22
#define BPDU_MESSAGE_AGE        23
#define BPDU_HELLO_TIME         24
#define BPDU_MAX_AGE            25
#define BPDU_FORWARD_DELAY      26

#define DEC_BPDU_SIZE		27


static int proto_dec_bpdu = -1;

static gint ett_dec_bpdu = -1;

static void
dissect_dec_bpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
      guint8  protocol_identifier;
      guint8  protocol_version;
      guint8  bpdu_type;
      guint8  flags;
      proto_tree *bpdu_tree;
      proto_item *ti;

      if (check_col(pinfo->fd, COL_PROTOCOL)) {
	    col_set_str(pinfo->fd, COL_PROTOCOL, "DEC_STP");
      }
      if (check_col(pinfo->fd, COL_INFO)) {
	    col_clear(pinfo->fd, COL_INFO);
      }

      bpdu_type = tvb_get_guint8(tvb, BPDU_TYPE);
      flags=tvb_get_guint8(tvb,BPDU_FLAGS);
      
      if (check_col(pinfo->fd, COL_INFO)) {
	    if (bpdu_type == 25)
		  col_add_fstr(pinfo->fd, COL_INFO, "Hello Packet");
	    else if (bpdu_type == 0x02)
		  col_add_fstr(pinfo->fd, COL_INFO, "Topology Change Notification");
      }
      
      tvb_set_reported_length(tvb, DEC_BPDU_SIZE);

      if (tree) {
	    protocol_identifier = tvb_get_guint8(tvb, BPDU_DEC_CODE);

	    protocol_version = tvb_get_guint8(tvb, BPDU_VERSION);

	    ti = proto_tree_add_protocol_format(tree, proto_dec_bpdu, tvb, 0, DEC_BPDU_SIZE,
			    	"DEC Spanning Tree Protocol");
	    bpdu_tree = proto_item_add_subtree(ti, ett_dec_bpdu);

	    proto_tree_add_text(bpdu_tree, tvb, BPDU_DEC_CODE, 1, "Protocol ID: 0x%02x (%s)",
	         protocol_identifier,
	         protocol_identifier==0xe1?"DEC Spanning Tree Protocol":
	         "Unknown protocol, the dissection may be wrong");

	    proto_tree_add_text(bpdu_tree, tvb, BPDU_TYPE,1, "BPDU Type: %u (%s)", bpdu_type,
	    	(bpdu_type==25?"Hello Packet":(bpdu_type==2?"Topology change notice":"Unknown")));

	    proto_tree_add_text(bpdu_tree, tvb, BPDU_VERSION,1, "BPDU Version: %u (%s)",
	    	protocol_version,protocol_version==1?"DEC STP Version 1":"Unknown Version");

	    proto_tree_add_text(bpdu_tree, tvb, BPDU_FLAGS,1, "Flags: 0x%02x",flags);

	    if (flags & 0x80)
		  proto_tree_add_text(bpdu_tree, tvb, BPDU_FLAGS, 1, "      1... ....  Use short timers");
	    if (flags & 0x02)
		  proto_tree_add_text(bpdu_tree, tvb, BPDU_FLAGS, 1, "      .... ..1.  Topology Change Acknowledgment");
	    if (flags & 0x01)
		  proto_tree_add_text(bpdu_tree, tvb, BPDU_FLAGS, 1, "      .... ...1  Topology Change");
	    
	    proto_tree_add_text(bpdu_tree, tvb, BPDU_ROOT_PRI,2, "Root priority: %u",
	    	tvb_get_ntohs(tvb,BPDU_ROOT_PRI));
	    proto_tree_add_text(bpdu_tree, tvb, BPDU_ROOT_MAC,6, "Root MAC: %s",
	    	ether_to_str(tvb_get_ptr(tvb,BPDU_ROOT_MAC,6)));
	    proto_tree_add_text(bpdu_tree, tvb, BPDU_ROOT_PATH_COST,2, "Root path cost: %u",
	    	tvb_get_ntohs(tvb,BPDU_ROOT_PATH_COST));
	    proto_tree_add_text(bpdu_tree, tvb, BPDU_BRIDGE_PRI,2, "Root priority: %u",
	    	tvb_get_ntohs(tvb,BPDU_BRIDGE_PRI));
	    proto_tree_add_text(bpdu_tree, tvb, BPDU_BRIDGE_MAC,6, "Root MAC: %s",
	    	ether_to_str(tvb_get_ptr(tvb,BPDU_BRIDGE_MAC,6)));
	    proto_tree_add_text(bpdu_tree, tvb, BPDU_PORT_IDENTIFIER,1, "Port identifier: %u",
	    	tvb_get_guint8(tvb,BPDU_PORT_IDENTIFIER));
	    proto_tree_add_text(bpdu_tree, tvb, BPDU_MESSAGE_AGE,1, "Age: %u",
	    	tvb_get_guint8(tvb,BPDU_MESSAGE_AGE));
	    proto_tree_add_text(bpdu_tree, tvb, BPDU_HELLO_TIME,1, "Hello time: %u",
	    	tvb_get_guint8(tvb,BPDU_HELLO_TIME));
	    proto_tree_add_text(bpdu_tree, tvb, BPDU_MAX_AGE,1, "Max Age: %u",
	    	tvb_get_guint8(tvb,BPDU_MAX_AGE));
	    proto_tree_add_text(bpdu_tree, tvb, BPDU_FORWARD_DELAY,1, "Forward Delay: %u",
	    	tvb_get_guint8(tvb,BPDU_FORWARD_DELAY));

      }
}

void
proto_register_dec_bpdu(void)
{
  static gint *ett[] = {
    &ett_dec_bpdu,
  };

  proto_dec_bpdu = proto_register_protocol("DEC Spanning Tree Protocol",
					   "DEC_STP", "dec_stp");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dec_bpdu(void)
{
  dissector_add("ethertype", ETHERTYPE_DEC_LB, dissect_dec_bpdu,
		proto_dec_bpdu); 
  dissector_add("ppp.protocol", PPP_DEC_LB, dissect_dec_bpdu,
		proto_dec_bpdu); 
}
