/* packet-bpdu.c
 * Routines for BPDU (Spanning Tree Protocol) disassembly
 *
 * $Id: packet-bpdu.c,v 1.34 2002/03/19 09:17:54 guy Exp $
 *
 * Copyright 1999 Christophe Tronche <ch.tronche@computer.org>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "llcsaps.h"
#include "ppptypes.h"
#include <epan/resolv.h>

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
#define BPDU_VERSION_1_LENGTH	35

#define CONF_BPDU_SIZE		35
#define TC_BPDU_SIZE		4
#define RST_BPDU_SIZE		36

/* Flag bits */

#define BPDU_FLAGS_TCACK		0x80
#define BPDU_FLAGS_AGREEMENT		0x40
#define BPDU_FLAGS_FORWARDING		0x20
#define BPDU_FLAGS_LEARNING		0x10
#define BPDU_FLAGS_PORT_ROLE_MASK	0x0C
#define BPDU_FLAGS_PORT_ROLE_SHIFT	2
#define BPDU_FLAGS_PROPOSAL		0x02
#define BPDU_FLAGS_TC			0x01

static int proto_bpdu = -1;
static int hf_bpdu_proto_id = -1;
static int hf_bpdu_version_id = -1;
static int hf_bpdu_type = -1;
static int hf_bpdu_flags = -1;
static int hf_bpdu_flags_tcack = -1;
static int hf_bpdu_flags_agreement = -1;
static int hf_bpdu_flags_forwarding = -1;
static int hf_bpdu_flags_learning = -1;
static int hf_bpdu_flags_port_role = -1;
static int hf_bpdu_flags_proposal = -1;
static int hf_bpdu_flags_tc = -1;
static int hf_bpdu_root_mac = -1;
static int hf_bpdu_root_cost = -1;
static int hf_bpdu_bridge_mac = -1;
static int hf_bpdu_port_id = -1;
static int hf_bpdu_msg_age = -1;
static int hf_bpdu_max_age = -1;
static int hf_bpdu_hello_time = -1;
static int hf_bpdu_forward_delay = -1;
static int hf_bpdu_version_1_length = -1;

static gint ett_bpdu = -1;
static gint ett_bpdu_flags = -1;

static dissector_handle_t gvrp_handle;
static dissector_handle_t gmrp_handle;
static dissector_handle_t data_handle;

static const value_string protocol_id_vals[] = {
	{ 0, "Spanning Tree Protocol" },
	{ 0, NULL }
};

#define BPDU_TYPE_CONF			0x00
#define BPDU_TYPE_RST			0x02
#define BPDU_TYPE_TOPOLOGY_CHANGE	0x80

static const value_string bpdu_type_vals[] = {
	{ BPDU_TYPE_CONF,            "Configuration" },
	{ BPDU_TYPE_RST,             "Rapid Spanning Tree" },
	{ BPDU_TYPE_TOPOLOGY_CHANGE, "Topology Change Notification" },
	{ 0,                         NULL }
};

static const value_string role_vals[] = {
	{ 1, "Alternate or Backup" },
	{ 2, "Root" },
	{ 3, "Designated" },
	{ 0, NULL }
};

static const char initial_sep[] = " (";
static const char cont_sep[] = ", ";

#define APPEND_BOOLEAN_FLAG(flag, item, string) \
	if(flag){							\
		if(item)						\
			proto_item_append_text(item, string, sep);	\
		sep = cont_sep;						\
	}

static void
dissect_bpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
      guint16 protocol_identifier;
      guint8  protocol_version_identifier;
      guint8  bpdu_type;
      int bpdu_size;
      guint8  flags;
      guint16 root_identifier_bridge_priority;
      const guint8  *root_identifier_mac;
      gchar   *root_identifier_mac_str;
      guint32 root_path_cost;
      guint16 bridge_identifier_bridge_priority;
      const guint8  *bridge_identifier_mac;
      gchar   *bridge_identifier_mac_str;
      guint16 port_identifier;
      double message_age;
      double max_age;
      double hello_time;
      double forward_delay;
      
      proto_tree *bpdu_tree;
      proto_item *bpdu_item;
      proto_tree *flags_tree;
      proto_item *flags_item;
      guint8	rstp_bpdu;
      const char *sep;

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
		   /* for GMRP */
		  call_dissector(gmrp_handle, tvb, pinfo, tree);
		  return;

	    case 0x21:
		  /* for GVRP */
		  call_dissector(gvrp_handle, tvb, pinfo, tree);
		  return;
	    }

	    pinfo->current_proto = "GARP";

	    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GARP");
		    /* Generic Attribute Registration Protocol */
	    }

	    if (check_col(pinfo->cinfo, COL_INFO)) {
		    col_add_fstr(pinfo->cinfo, COL_INFO,
		        "Unknown GARP application (0x%02X)",
			pinfo->dl_dst.data[5]);
            }

	    return;
      }

      if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
	    col_set_str(pinfo->cinfo, COL_PROTOCOL, "STP"); /* Spanning Tree Protocol */
      }
      if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_clear(pinfo->cinfo, COL_INFO);
      }

      bpdu_type = tvb_get_guint8(tvb, BPDU_TYPE);
      switch (bpdu_type) {

      case BPDU_TYPE_CONF:
      case BPDU_TYPE_RST:
	    flags = tvb_get_guint8(tvb, BPDU_FLAGS);
	    root_identifier_bridge_priority = tvb_get_ntohs(tvb,
	        BPDU_ROOT_IDENTIFIER);
	    root_identifier_mac = tvb_get_ptr(tvb, BPDU_ROOT_IDENTIFIER + 2, 6);
	    root_identifier_mac_str = ether_to_str(root_identifier_mac);
	    root_path_cost = tvb_get_ntohl(tvb, BPDU_ROOT_PATH_COST);
	    port_identifier = tvb_get_ntohs(tvb, BPDU_PORT_IDENTIFIER);
	    break;

      default:
	    /* Squelch GCC complaints. */
	    flags = 0;
	    root_identifier_bridge_priority = 0;
	    root_identifier_mac = NULL;
	    root_identifier_mac_str = NULL;
	    root_path_cost = 0;
	    port_identifier = 0;
	    break;
      }

      if (check_col(pinfo->cinfo, COL_INFO)) {
	    switch (bpdu_type) {

	    case BPDU_TYPE_CONF:
		  col_add_fstr(pinfo->cinfo, COL_INFO, "Conf. %sRoot = %d/%s  Cost = %d  Port = 0x%04x", 
			       flags & 0x1 ? "TC + " : "",
			       root_identifier_bridge_priority, root_identifier_mac_str, root_path_cost,
			       port_identifier);
		  break;

	    case BPDU_TYPE_TOPOLOGY_CHANGE:
		  col_add_fstr(pinfo->cinfo, COL_INFO, "Topology Change Notification");
		  break;

	    case BPDU_TYPE_RST:
		  col_add_fstr(pinfo->cinfo, COL_INFO, "RST. %sRoot = %d/%s  Cost = %d  Port = 0x%04x", 
			       flags & 0x1 ? "TC + " : "",
			       root_identifier_bridge_priority, root_identifier_mac_str, root_path_cost,
			       port_identifier);
		  break;

	    default:
		  col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown BPDU type (%u)",
			       bpdu_type);
                  break;
            }
      }

      switch (bpdu_type) {

      case BPDU_TYPE_CONF:
        set_actual_length(tvb, CONF_BPDU_SIZE);
        break;

      case BPDU_TYPE_TOPOLOGY_CHANGE:
        set_actual_length(tvb, TC_BPDU_SIZE);
        break;

      case BPDU_TYPE_RST:
        set_actual_length(tvb, RST_BPDU_SIZE);
        break;
      }

      if (tree) {
	    bpdu_item = proto_tree_add_protocol_format(tree, proto_bpdu, tvb,
				0, -1, "Spanning Tree Protocol");
	    bpdu_tree = proto_item_add_subtree(bpdu_item, ett_bpdu);

	    protocol_identifier = tvb_get_ntohs(tvb, BPDU_IDENTIFIER);
	    proto_tree_add_uint(bpdu_tree, hf_bpdu_proto_id, tvb,
				BPDU_IDENTIFIER, 2, protocol_identifier);

	    protocol_version_identifier = tvb_get_guint8(tvb, BPDU_VERSION_IDENTIFIER);
	    proto_tree_add_uint(bpdu_tree, hf_bpdu_version_id, tvb, 
				BPDU_VERSION_IDENTIFIER, 1, 
				protocol_version_identifier);
            switch (protocol_version_identifier) {
              case 0:
                break;
              case 2:
                break;
              default:
		  proto_tree_add_text(bpdu_tree, tvb, BPDU_VERSION_IDENTIFIER, 1,
		  "   (Warning: this version of Ethereal only knows about versions 0 & 2)");
                break;
            }
	    proto_tree_add_uint(bpdu_tree, hf_bpdu_type, tvb,
				       BPDU_TYPE, 1, 
				       bpdu_type);

	    if (bpdu_type != BPDU_TYPE_CONF && bpdu_type != BPDU_TYPE_RST) {
	      call_dissector(data_handle,tvb_new_subset(tvb, BPDU_TYPE + 1,-1,tvb_reported_length_remaining(tvb,BPDU_TYPE + 1)), pinfo, tree);
	      return;
	    }

            rstp_bpdu = (bpdu_type == BPDU_TYPE_RST);
	    bridge_identifier_bridge_priority = tvb_get_ntohs(tvb, BPDU_BRIDGE_IDENTIFIER);
	    bridge_identifier_mac = tvb_get_ptr(tvb, BPDU_BRIDGE_IDENTIFIER + 2, 6);
	    bridge_identifier_mac_str = ether_to_str(bridge_identifier_mac);

	    flags_item = proto_tree_add_uint(bpdu_tree, hf_bpdu_flags, tvb, 
				BPDU_FLAGS, 1, flags);
	    flags_tree = proto_item_add_subtree(flags_item, ett_bpdu_flags);
	    sep = initial_sep;
	    APPEND_BOOLEAN_FLAG(flags & BPDU_FLAGS_TCACK, flags_item,
				"%sTopology Change Acknowledgment");
	    proto_tree_add_boolean(flags_tree, hf_bpdu_flags_tcack, tvb,
				BPDU_FLAGS, 1, flags);
            if (rstp_bpdu) {
	      APPEND_BOOLEAN_FLAG(flags & BPDU_FLAGS_AGREEMENT, flags_item,
				  "%sAgreement");
	      proto_tree_add_boolean(flags_tree, hf_bpdu_flags_agreement, tvb,
				  BPDU_FLAGS, 1, flags);
	      APPEND_BOOLEAN_FLAG(flags & BPDU_FLAGS_FORWARDING, flags_item,
				  "%sForwarding");
	      proto_tree_add_boolean(flags_tree, hf_bpdu_flags_forwarding, tvb,
				  BPDU_FLAGS, 1, flags);
	      APPEND_BOOLEAN_FLAG(flags & BPDU_FLAGS_LEARNING, flags_item,
				  "%sLearning");
	      proto_tree_add_boolean(flags_tree, hf_bpdu_flags_learning, tvb,
				  BPDU_FLAGS, 1, flags);
	      if (flags_item) {
		guint8 port_role;

		port_role = (flags & BPDU_FLAGS_PORT_ROLE_MASK) >> BPDU_FLAGS_PORT_ROLE_SHIFT;
		proto_item_append_text(flags_item, "%sPort Role: %s", sep,
				       val_to_str(port_role, role_vals,
						  "Unknown (%u)"));
	      }
	      sep = cont_sep;
	      proto_tree_add_uint(flags_tree, hf_bpdu_flags_port_role, tvb,
				  BPDU_FLAGS, 1, flags);
	      APPEND_BOOLEAN_FLAG(flags & BPDU_FLAGS_PROPOSAL, flags_item,
				  "%sProposal");
	      proto_tree_add_boolean(flags_tree, hf_bpdu_flags_proposal, tvb,
				  BPDU_FLAGS, 1, flags);
            }
	    APPEND_BOOLEAN_FLAG(flags & BPDU_FLAGS_TC, flags_item,
				"%sTopology Change");
	    proto_tree_add_boolean(flags_tree, hf_bpdu_flags_tc, tvb,
				BPDU_FLAGS, 1, flags);
	    if (sep != initial_sep) {
	      /* We put something in; put in the terminating ")" */
	      proto_item_append_text(flags_item, ")");
	    }

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
	    message_age = tvb_get_ntohs(tvb, BPDU_MESSAGE_AGE) / 256.0;
	    proto_tree_add_double(bpdu_tree, hf_bpdu_msg_age, tvb,
				BPDU_MESSAGE_AGE, 2, 
				message_age);
	    max_age = tvb_get_ntohs(tvb, BPDU_MAX_AGE) / 256.0;
	    proto_tree_add_double(bpdu_tree, hf_bpdu_max_age, tvb,
				BPDU_MAX_AGE, 2, 
				max_age);
	    hello_time = tvb_get_ntohs(tvb, BPDU_HELLO_TIME) / 256.0;
	    proto_tree_add_double(bpdu_tree, hf_bpdu_hello_time, tvb,
				BPDU_HELLO_TIME, 2, 
				hello_time);
	    forward_delay = tvb_get_ntohs(tvb, BPDU_FORWARD_DELAY) / 256.0;
	    proto_tree_add_double(bpdu_tree, hf_bpdu_forward_delay, tvb,
				BPDU_FORWARD_DELAY, 2, 
				forward_delay);
            if (rstp_bpdu) {
	      proto_tree_add_item(bpdu_tree, hf_bpdu_version_1_length, tvb,
				BPDU_VERSION_1_LENGTH, 1, FALSE);
	    }
      }
}

static const true_false_string yesno = {  
	"Yes",
	"No"
};

void
proto_register_bpdu(void)
{

  static hf_register_info hf[] = {
    { &hf_bpdu_proto_id,
      { "Protocol Identifier",		"stp.protocol",
	FT_UINT16,	BASE_HEX,	VALS(&protocol_id_vals), 0x0,
      	"", HFILL }},
    { &hf_bpdu_version_id,
      { "Protocol Version Identifier",	"stp.version",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"", HFILL }},
    { &hf_bpdu_type,
      { "BPDU Type",			"stp.type",
	FT_UINT8,	BASE_HEX,	VALS(&bpdu_type_vals),	0x0,
      	"", HFILL }},
    { &hf_bpdu_flags,
      { "BPDU flags",			"stp.flags",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"", HFILL }},
    { &hf_bpdu_flags_tcack,
      { "Topology Change Acknowledgment",  "stp.flags.tcack",
	FT_BOOLEAN,	8,		TFS(&yesno),	BPDU_FLAGS_TCACK,
      	"", HFILL }},
    { &hf_bpdu_flags_agreement,
      { "Agreement",			"stp.flags.agreement",
	FT_BOOLEAN,	8,		TFS(&yesno),	BPDU_FLAGS_AGREEMENT,
      	"", HFILL }},
    { &hf_bpdu_flags_forwarding,
      { "Forwarding",			"stp.flags.forwarding",
	FT_BOOLEAN,	8,		TFS(&yesno),	BPDU_FLAGS_FORWARDING,
      	"", HFILL }},
    { &hf_bpdu_flags_learning,
      { "Learning",			"stp.flags.learning",
	FT_BOOLEAN,	8,		TFS(&yesno),	BPDU_FLAGS_LEARNING,
      	"", HFILL }},
    { &hf_bpdu_flags_port_role,
      { "Port Role",			"stp.flags.port_role",
	FT_UINT8,	BASE_DEC,	VALS(role_vals),	BPDU_FLAGS_PORT_ROLE_MASK,
      	"", HFILL }},
    { &hf_bpdu_flags_proposal,
      { "Proposal",			"stp.flags.proposal",
	FT_BOOLEAN,	8,		TFS(&yesno),	BPDU_FLAGS_PROPOSAL,
      	"", HFILL }},
    { &hf_bpdu_flags_tc,
      { "Topology Change",		"stp.flags.tc",
	FT_BOOLEAN,	8,		TFS(&yesno),	BPDU_FLAGS_TC,
      	"", HFILL }},
    { &hf_bpdu_root_mac,
      { "Root Identifier",		"stp.root.hw",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},
    { &hf_bpdu_root_cost,
      { "Root Path Cost",		"stp.root.cost",
	FT_UINT32,	BASE_DEC,	NULL,	0x0,
      	"", HFILL }},
    { &hf_bpdu_bridge_mac,
      { "Bridge Identifier",		"stp.bridge.hw",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},
    { &hf_bpdu_port_id,
      { "Port identifier",		"stp.port",
	FT_UINT16,	BASE_HEX,	NULL,	0x0,
      	"", HFILL }},
    { &hf_bpdu_msg_age,
      { "Message Age",			"stp.msg_age",
	FT_DOUBLE,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},
    { &hf_bpdu_max_age,
      { "Max Age",			"stp.max_age",
	FT_DOUBLE,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},
    { &hf_bpdu_hello_time,
      { "Hello Time",			"stp.hello",
	FT_DOUBLE,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},
    { &hf_bpdu_forward_delay,
      { "Forward Delay",		"stp.forward",
	FT_DOUBLE,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},
    { &hf_bpdu_version_1_length,
      { "Version 1 Length",		"stp.version_1_length",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"", HFILL }},
  };
  static gint *ett[] = {
    &ett_bpdu,
    &ett_bpdu_flags,
  };

  proto_bpdu = proto_register_protocol("Spanning Tree Protocol", "STP", "stp");
  proto_register_field_array(proto_bpdu, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("bpdu", dissect_bpdu, proto_bpdu);
}

void
proto_reg_handoff_bpdu(void)
{
  dissector_handle_t bpdu_handle;

  /*
   * Get handle for the GVRP dissector.
   */
  gvrp_handle = find_dissector("gvrp");
  
  /*
   * Get handle for the GMRP dissector.
   */
  gmrp_handle = find_dissector("gmrp");
  data_handle = find_dissector("data");

  bpdu_handle = find_dissector("bpdu");
  dissector_add("llc.dsap", SAP_BPDU, bpdu_handle);
  dissector_add("ppp.protocol", PPP_BPDU, bpdu_handle);
}
