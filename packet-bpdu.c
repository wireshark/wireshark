/* packet-bpdu.c
 * Routines for BPDU (Spanning Tree Protocol) disassembly
 *
 * $Id: packet-bpdu.c,v 1.2 1999/10/08 21:20:23 guy Exp $
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
#include "resolv.h"
#include "util.h"

/*  #ifndef __PACKET_IP_H__ */
/*  #include "packet-ip.h" */
/*  #endif */

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

void dissect_bpdu(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
      guint16 protocol_identifier;
      guint8  protocol_version_identifier;
      guint8  bpdu_type;
      guint8  flags;
      guint16 root_identifier_bridge_priority;
      gchar   *root_identifier_mac;
      guint32 root_path_cost;
      guint16 bridge_identifier_bridge_priority;
      gchar   *bridge_identifier_mac;
      guint16 port_identifier;
      double message_age;
      double max_age;
      double hello_time;
      double forward_delay;
      
      proto_tree *bpdu_tree;
      proto_item *ti;
      const u_char *bpdu;

      bpdu = pd + offset;
      bpdu_type = (guint8) bpdu[BPDU_TYPE];
      flags = (guint8) bpdu[BPDU_FLAGS];
      root_identifier_bridge_priority = pntohs(bpdu + BPDU_ROOT_IDENTIFIER);
      root_identifier_mac = ether_to_str(bpdu + BPDU_ROOT_IDENTIFIER + 2);
      root_path_cost = pntohl(bpdu + BPDU_ROOT_PATH_COST);
      port_identifier = pntohs(bpdu + BPDU_PORT_IDENTIFIER);

      if (check_col(fd, COL_PROTOCOL)) {
	    col_add_str(fd, COL_PROTOCOL, "STP"); /* Spanning Tree Protocol */
      }

      if (check_col(fd, COL_INFO)) {
	    if (bpdu_type == 0)
		  col_add_fstr(fd, COL_INFO, "Conf. %sRoot = %d/%s  Cost = %d  Port = 0x%04x", 
			       flags & 0x1 ? "TC + " : "",
			       root_identifier_bridge_priority, root_identifier_mac, root_path_cost,
			       port_identifier);
	    else if (bpdu_type == 0x80)
		  col_add_fstr(fd, COL_INFO, "Topology Change Notification");
      }

      if (tree) {
	    protocol_identifier = pntohs(bpdu + BPDU_IDENTIFIER);
	    protocol_version_identifier = (guint8) bpdu[BPDU_VERSION_IDENTIFIER];

	    ti = proto_tree_add_item_format(tree, proto_bpdu, offset, 35, NULL, "Spanning Tree Protocol");
	    bpdu_tree = proto_item_add_subtree(ti, ETT_BPDU);
	    proto_tree_add_text(bpdu_tree, offset + BPDU_IDENTIFIER, 2, "Protocol Identifier: 0x%04x (%s)", 
				protocol_identifier,
				protocol_identifier == 0 ? "Spanning Tree" : "Unknown Protocol");

	    proto_tree_add_text(bpdu_tree, offset + BPDU_VERSION_IDENTIFIER, 1, "Protocol Version Identifier: %d", protocol_version_identifier);
	    if (protocol_version_identifier != 0)
		  proto_tree_add_text(bpdu_tree, offset + BPDU_VERSION_IDENTIFIER, 1, "   (Warning: this version of packet-bpdu only knows about version = 0)");
	    proto_tree_add_text(bpdu_tree, offset + BPDU_TYPE, 1, "BPDU Type: 0x%02x (%s)", 
				bpdu_type,
				bpdu_type == 0 ? "Configuration" :
				bpdu_type == 0x80 ? "Topology Change Notification" : "Unknown");

	    if (bpdu_type != 0) return;

	    bridge_identifier_bridge_priority = pntohs(bpdu + BPDU_BRIDGE_IDENTIFIER);
	    bridge_identifier_mac = ether_to_str(bpdu + BPDU_BRIDGE_IDENTIFIER + 2);
	    message_age = pntohs(bpdu + BPDU_MESSAGE_AGE) / 256.0;
	    max_age = pntohs(bpdu + BPDU_MAX_AGE) / 256.0;
	    hello_time = pntohs(bpdu + BPDU_HELLO_TIME) / 256.0;
	    forward_delay = pntohs(bpdu + BPDU_FORWARD_DELAY) / 256.0;

	    proto_tree_add_text(bpdu_tree, offset + BPDU_FLAGS, 1, "Flags: 0x%02x", flags);
	    if (flags & 0x80)
		  proto_tree_add_text(bpdu_tree, offset + BPDU_FLAGS, 1, "   1... ....  Topology Change Acknowledgment");
	    if (flags & 0x01)
		  proto_tree_add_text(bpdu_tree, offset + BPDU_FLAGS, 1, "   .... ...1  Topology Change");

	    proto_tree_add_text(bpdu_tree, offset + BPDU_ROOT_IDENTIFIER, 8, "Root Identifier: %d / %s", root_identifier_bridge_priority, root_identifier_mac);
	    proto_tree_add_text(bpdu_tree, offset + BPDU_ROOT_PATH_COST, 4, "Root Path Cost: %d", root_path_cost);
	    proto_tree_add_text(bpdu_tree, offset + BPDU_BRIDGE_IDENTIFIER, 8, "Bridge Identifier: %d / %s", 
				bridge_identifier_bridge_priority, 
				bridge_identifier_mac);
	    proto_tree_add_text(bpdu_tree, offset + BPDU_PORT_IDENTIFIER, 2, "Port identifier: 0x%04x", port_identifier);
	    proto_tree_add_text(bpdu_tree, offset + BPDU_MESSAGE_AGE, 2, "Message Age: %f", message_age);
	    proto_tree_add_text(bpdu_tree, offset + BPDU_MAX_AGE, 2, "Max Age: %f", max_age);
	    proto_tree_add_text(bpdu_tree, offset + BPDU_HELLO_TIME, 2, "Hello Time: %f", hello_time);
	    proto_tree_add_text(bpdu_tree, offset + BPDU_FORWARD_DELAY, 2, "Forward Delay: %f", forward_delay);
      }
}

void
proto_register_bpdu(void)
{
        proto_bpdu = proto_register_protocol("Spanning Tree Protocol", "stp");
}
