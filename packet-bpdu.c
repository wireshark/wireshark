/* packet-bpdu.c
 * Routines for BPDU (Spanning Tree Protocol) disassembly
 *
 * $Id: packet-bpdu.c,v 1.18 2001/01/03 06:55:27 guy Exp $
 *
 * Copyright 1999 Christophe Tronche <ch.tronche@computer.org>
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
#include "llcsaps.h"
#include "resolv.h"

/* Include this for GVRP dissector */
#include "packet-gvrp.h"

/* Offsets of fields within a BPDU */

#define BPDU_IDENTIFIER          0
#define BPDU_VERSION_IDENTIFIER  2
#define BPDU_TYPE                3
#define BPDU_FLAGS               4
#define BPDU_ROOT_IDENTIFIER     5
#define BPDU_ROOT_PATH_COST     13
#define BPDU_BRIDGE_IDENTIFIER  17
#define BPDU_PORT_IDENTIFIER    25
#define BPDU_MESSAGE_AGE        27
#define BPDU_MAX_AGE            29
#define BPDU_HELLO_TIME         31
#define BPDU_FORWARD_DELAY      33

static int proto_bpdu = -1;
static int hf_bpdu_proto_id = -1;
static int hf_bpdu_version_id = -1;
static int hf_bpdu_type = -1;
static int hf_bpdu_flags = -1;
static int hf_bpdu_root_mac = -1;
static int hf_bpdu_root_cost = -1;
static int hf_bpdu_bridge_mac = -1;
static int hf_bpdu_port_id = -1;
static int hf_bpdu_msg_age = -1;
static int hf_bpdu_max_age = -1;
static int hf_bpdu_hello_time = -1;
static int hf_bpdu_forward_delay = -1;

static gint ett_bpdu = -1;

static void
dissect_bpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
      guint16 protocol_identifier;
      guint8  protocol_version_identifier;
      guint8  bpdu_type;
      guint8  flags;
      guint16 root_identifier_bridge_priority;
      guint8  *root_identifier_mac;
      gchar   *root_identifier_mac_str;
      guint32 root_path_cost;
      guint16 bridge_identifier_bridge_priority;
      guint8  *bridge_identifier_mac;
      gchar   *bridge_identifier_mac_str;
      guint16 port_identifier;
      double message_age;
      double max_age;
      double hello_time;
      double forward_delay;
      
      proto_tree *bpdu_tree;
      proto_item *ti;

      CHECK_DISPLAY_AS_DATA(proto_bpdu, tvb, pinfo, tree);

      /* GARP application frames require special interpretation of the
         destination address field; otherwise, they will be mistaken as
         BPDU frames.  
         Fortunately, they can be recognized by checking the first 6 octets
         of the destination address, which are in the range from
         01-80-C2-00-00-20 to 01-80-C2-00-00-2F.

	 Yes - we *do* need to check the destination address type;
	 on Linux cooked captures, there *is* no destination address,
	 so it's AT_NONE. */
      if (pinfo->dl_dst.type == AT_ETHER &&
	  pinfo->dl_dst.data[0] == 0x01 && pinfo->dl_dst.data[1] == 0x80 &&
	  pinfo->dl_dst.data[2] == 0xC2 && pinfo->dl_dst.data[3] == 0x00 &&
	  pinfo->dl_dst.data[4] == 0x00 && ((pinfo->dl_dst.data[5] & 0x20) == 0x20)) {

	    protocol_identifier = tvb_get_ntohs(tvb, BPDU_IDENTIFIER);

	    switch (pinfo->dl_dst.data[5]) {

	    case 0x20:
		  /* Future expansion for GMRP */
		  break;

	    case 0x21:
		  /* for GVRP */
		  dissect_gvrp(tvb, pinfo, tree);
		  return;
	    }

	    pinfo->current_proto = "GARP";

	    if (check_col(pinfo->fd, COL_PROTOCOL)) {
		    col_set_str(pinfo->fd, COL_PROTOCOL, "GARP");
		    /* Generic Attribute Registration Protocol */
	    }

	    if (check_col(pinfo->fd, COL_INFO)) {
		    col_add_fstr(pinfo->fd, COL_INFO,
		        "Unknown GARP application (0x%02X)",
			pinfo->dl_dst.data[5]);
            }

	    return;
      }

      pinfo->current_proto = "STP";

      bpdu_type = tvb_get_guint8(tvb, BPDU_TYPE);
      flags = tvb_get_guint8(tvb, BPDU_FLAGS);
      root_identifier_bridge_priority = tvb_get_ntohs(tvb, BPDU_ROOT_IDENTIFIER);
      root_identifier_mac = tvb_get_ptr(tvb, BPDU_ROOT_IDENTIFIER + 2, 6);
      root_identifier_mac_str = ether_to_str(root_identifier_mac);
      root_path_cost = tvb_get_ntohl(tvb, BPDU_ROOT_PATH_COST);
      port_identifier = tvb_get_ntohs(tvb, BPDU_PORT_IDENTIFIER);

      if (check_col(pinfo->fd, COL_PROTOCOL)) {
	    col_set_str(pinfo->fd, COL_PROTOCOL, "STP"); /* Spanning Tree Protocol */
      }

      if (check_col(pinfo->fd, COL_INFO)) {
	    if (bpdu_type == 0)
		  col_add_fstr(pinfo->fd, COL_INFO, "Conf. %sRoot = %d/%s  Cost = %d  Port = 0x%04x", 
			       flags & 0x1 ? "TC + " : "",
			       root_identifier_bridge_priority, root_identifier_mac_str, root_path_cost,
			       port_identifier);
	    else if (bpdu_type == 0x80)
		  col_add_fstr(pinfo->fd, COL_INFO, "Topology Change Notification");
      }

      if (tree) {
	    protocol_identifier = tvb_get_ntohs(tvb, BPDU_IDENTIFIER);
	    protocol_version_identifier = tvb_get_guint8(tvb, BPDU_VERSION_IDENTIFIER);

	    ti = proto_tree_add_protocol_format(tree, proto_bpdu, tvb, 0, 35,
			    	"Spanning Tree Protocol");
	    bpdu_tree = proto_item_add_subtree(ti, ett_bpdu);
	    proto_tree_add_uint_format(bpdu_tree, hf_bpdu_proto_id, tvb,
				       BPDU_IDENTIFIER, 2, 
				       protocol_identifier,
				       "Protocol Identifier: 0x%04x (%s)", 
				       protocol_identifier,
				       protocol_identifier == 0 ? 
				       "Spanning Tree" : "Unknown Protocol");

	    proto_tree_add_uint(bpdu_tree, hf_bpdu_version_id, tvb, 
				BPDU_VERSION_IDENTIFIER, 1, 
				protocol_version_identifier);
	    if (protocol_version_identifier != 0)
		  proto_tree_add_text(bpdu_tree, tvb, BPDU_VERSION_IDENTIFIER, 1,
		  "   (Warning: this version of Ethereal only knows about version = 0)");
	    proto_tree_add_uint_format(bpdu_tree, hf_bpdu_type, tvb,
				       BPDU_TYPE, 1, 
				       bpdu_type,
				       "BPDU Type: 0x%02x (%s)", 
				       bpdu_type,
				       bpdu_type == 0 ? "Configuration" :
				       bpdu_type == 0x80 ? "Topology Change Notification" : "Unknown");

	    if (bpdu_type != 0) {
	      dissect_data(tvb, BPDU_TYPE + 1, pinfo, tree);
	      return;
	    }

	    bridge_identifier_bridge_priority = tvb_get_ntohs(tvb, BPDU_BRIDGE_IDENTIFIER);
	    bridge_identifier_mac = tvb_get_ptr(tvb, BPDU_BRIDGE_IDENTIFIER + 2, 6);
	    bridge_identifier_mac_str = ether_to_str(bridge_identifier_mac);
	    message_age = tvb_get_ntohs(tvb, BPDU_MESSAGE_AGE) / 256.0;
	    max_age = tvb_get_ntohs(tvb, BPDU_MAX_AGE) / 256.0;
	    hello_time = tvb_get_ntohs(tvb, BPDU_HELLO_TIME) / 256.0;
	    forward_delay = tvb_get_ntohs(tvb, BPDU_FORWARD_DELAY) / 256.0;

	    proto_tree_add_uint(bpdu_tree, hf_bpdu_flags, tvb, 
				BPDU_FLAGS, 1, flags);
	    if (flags & 0x80)
		  proto_tree_add_text(bpdu_tree, tvb, BPDU_FLAGS, 1, "   1... ....  Topology Change Acknowledgment");
	    if (flags & 0x01)
		  proto_tree_add_text(bpdu_tree, tvb, BPDU_FLAGS, 1, "   .... ...1  Topology Change");

	    proto_tree_add_ether_hidden(bpdu_tree, hf_bpdu_root_mac, tvb,
				       BPDU_ROOT_IDENTIFIER + 2, 6,
				       root_identifier_mac);
	    proto_tree_add_text(bpdu_tree, tvb, 
				BPDU_ROOT_IDENTIFIER, 8, 
				"Root Identifier: %d / %s", 
				root_identifier_bridge_priority, 
				root_identifier_mac_str);
	    proto_tree_add_uint(bpdu_tree, hf_bpdu_root_cost, tvb, 
				BPDU_ROOT_PATH_COST, 4, 
				root_path_cost);
	    proto_tree_add_text(bpdu_tree, tvb, 
				BPDU_BRIDGE_IDENTIFIER, 8, 
				"Bridge Identifier: %d / %s", 
				bridge_identifier_bridge_priority, 
				bridge_identifier_mac_str);
	    proto_tree_add_ether_hidden(bpdu_tree, hf_bpdu_bridge_mac, tvb,
				       BPDU_BRIDGE_IDENTIFIER + 2, 6,
				       bridge_identifier_mac);
	    proto_tree_add_uint(bpdu_tree, hf_bpdu_port_id, tvb,
				BPDU_PORT_IDENTIFIER, 2, 
				port_identifier);
	    proto_tree_add_double(bpdu_tree, hf_bpdu_msg_age, tvb,
				BPDU_MESSAGE_AGE, 2, 
				message_age);
	    proto_tree_add_double(bpdu_tree, hf_bpdu_max_age, tvb,
				BPDU_MAX_AGE, 2, 
				max_age);
	    proto_tree_add_double(bpdu_tree, hf_bpdu_hello_time, tvb,
				BPDU_HELLO_TIME, 2, 
				hello_time);
	    proto_tree_add_double(bpdu_tree, hf_bpdu_forward_delay, tvb,
				BPDU_FORWARD_DELAY, 2, 
				forward_delay);
      }
}

void
proto_register_bpdu(void)
{

  static hf_register_info hf[] = {
    { &hf_bpdu_proto_id,
      { "Protocol Identifier",		"stp.protocol",
	FT_UINT16,	BASE_HEX,	NULL,	0x0,
      	"" }},
    { &hf_bpdu_version_id,
      { "Protocol Version Identifier",	"stp.version",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"" }},
    { &hf_bpdu_type,
      { "BPDU type",			"stp.type",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"" }},
    { &hf_bpdu_flags,
      { "BPDU flags",			"stp.flags",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"" }},
    { &hf_bpdu_root_mac,
      { "Root Identifier",		"stp.root.hw",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	"" }},
    { &hf_bpdu_root_cost,
      { "Root Path Cost",		"stp.root.cost",
	FT_UINT32,	BASE_DEC,	NULL,	0x0,
      	"" }},
    { &hf_bpdu_bridge_mac,
      { "Bridge Identifier",		"stp.bridge.hw",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	""}},
    { &hf_bpdu_port_id,
      { "Port identifier",		"stp.port",
	FT_UINT16,	BASE_HEX,	NULL,	0x0,
      	""}},
    { &hf_bpdu_msg_age,
      { "Message Age",			"stp.msg_age",
	FT_DOUBLE,	BASE_NONE,	NULL,	0x0,
      	"" }},
    { &hf_bpdu_max_age,
      { "Max Age",			"stp.max_age",
	FT_DOUBLE,	BASE_NONE,	NULL,	0x0,
      	"" }},
    { &hf_bpdu_hello_time,
      { "Hello Time",			"stp.hello",
	FT_DOUBLE,	BASE_NONE,	NULL,	0x0,
      	"" }},
    { &hf_bpdu_forward_delay,
      { "Forward Delay",		"stp.forward",
	FT_DOUBLE,	BASE_NONE,	NULL,	0x0,
      	"" }},
  };
  static gint *ett[] = {
    &ett_bpdu,
  };

  proto_bpdu = proto_register_protocol("Spanning Tree Protocol", "STP", "stp");
  proto_register_field_array(proto_bpdu, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("bpdu", dissect_bpdu);
}

void
proto_reg_handoff_bpdu(void)
{
  dissector_add("llc.dsap", SAP_BPDU, dissect_bpdu);
}
