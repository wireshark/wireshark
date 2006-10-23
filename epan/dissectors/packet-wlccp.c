/* packet-wlccp.c
 * Routines for Cisco Wireless LAN Context Control Protocol dissection
 *
 * Copyright 2005, Joerg Mayer (see AUTHORS file)
 * Copyright 2006, Stephen Fisher <stephentfisher@yahoo.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * The CISCOWL dissector was merged into this one.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/* Version 0x00 was reverse engineered */
/* Version 0xC1 Protocol reference: US Patent Application 0050220054 */

/* More clues to version 0x00 of the protocol:
 *
 * Header (Eth V2 or SNAP)
 * Length (2 bytes)
 * Type (2 bytes)
 *	0202: Unknown, Length 36 (14 + 20 + 2)
 *	4001: Unknown, Length 48 (14 + 32 + 2)
 *	4601: Unknown, Length 34 (14 + 18 + 2)
 *	4081 on Eth V2: Name, Version Length 84 (14 + 48 + 20 + 2)
 *	4081 on 802.3: Name Length 72 (14 + 56 + 2)
 * Dst MAC (6 bytes)
 * Src MAC (6 bytes)
 * Unknown1 (2 bytes)  Unknown19 + Unknown2 may be a MAC address on type 0202
 * Unknown2 (4 bytes)	see Unknown19
 * 0 (17 bytes)
 * Device IP (4 bytes)
 * 0 (2 bytes)
 * Device name (8 bytes)
 * 0 (20 bytes)
 * Unknown3 (2 bytes)
 * Unknown4 (4 bytes)
 * Version string (10 bytes)
 * 0 (4 bytes)
 * 0 (2 bytes)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/oui.h>
#include "packet-llc.h"

static const value_string wlccp_sap_vs[] = {
	{ 0, "Context Management"        },
	{ 2, "Radio Resource Management" },
	{ 0, NULL                        }
};

static const value_string wlccp_subtype_vs[] = {
	{ 0, "Request" },
	{ 1, "Reply"   },
	{ 2, "Confirm" },
	{ 3, "Ack"     },
	{ 0, NULL      }
};

static const value_string wlccp_node_type_vs[] = {
	{ 0, "None"                         },
	{ 1, "Access Point (AP)"            },
	{ 2, "Subnet Context Manager (SCM)" },
	{ 4, "Local Context Manager (LCM)"  },
	{ 8, "Campus Context Manager (CCM)" },
	{ 0x10, "Infrastructure (ICN)"      },
	{ 0x40, "Client"                    },
	{ 0, NULL                           }
};

static const value_string cisco_pid_vals[] = {
        { 0x0000, "WLCCP" },
        { 0, NULL         }
};

/* Bit fields in message type */
#define MT_SUBTYPE         (0xC0)
#define MT_BASE_MSG_TYPE   (0x3F)

/* Bit fields in flags */
#define F_RETRY            (1<<15)
#define F_RESPONSE_REQUEST (1<<14)
#define F_TLV              (1<<13)
#define F_INBOUND          (1<<12)
#define F_OUTBOUND         (1<<11)
#define F_HOPWISE_ROUTING  (1<<10)
#define F_ROOT_CM          (1<<9)
#define F_RELAY            (1<<8)
#define F_MIC              (1<<7)

#define WLCCP_UDP_PORT 2887
/* WLCCP also uses an LLC OUI type and an ethertype */

/* Forward declaration we need below */
void proto_reg_handoff_wlccp(void);

/* Initialize the protocol and registered fields */
static int proto_wlccp = -1;

static int hf_llc_wlccp_pid = -1;

static int hf_wlccp_version = -1;

static int hf_wlccp_dstmac = -1;
static int hf_wlccp_srcmac = -1;
static int hf_wlccp_hostname = -1;

static int hf_wlccp_sap = -1;
static int hf_wlccp_destination_node_type = -1;
static int hf_wlccp_length = -1;
static int hf_wlccp_type = -1;
static int hf_wlccp_subtype = -1;
static int hf_wlccp_base_message_type = -1;
static int hf_wlccp_hops = -1;
static int hf_wlccp_msg_id = -1;
static int hf_wlccp_flags = -1;
static int hf_wlccp_retry_flag = -1;
static int hf_wlccp_response_request_flag = -1;
static int hf_wlccp_tlv_flag = -1;
static int hf_wlccp_inbound_flag = -1;
static int hf_wlccp_outbound_flag = -1;
static int hf_wlccp_hopwise_routing_flag = -1;
static int hf_wlccp_root_cm_flag = -1;
static int hf_wlccp_relay_flag = -1;
static int hf_wlccp_mic_flag = -1;
static int hf_wlccp_originator_node_type = -1;
static int hf_wlccp_originator = -1;
static int hf_wlccp_responder_node_type = -1;
static int hf_wlccp_responder = -1;
static int hf_wlccp_relay_node_type = -1;
static int hf_wlccp_relay_node_id = -1;
static int hf_wlccp_priority = -1;
static int hf_wlccp_age = -1;
static int hf_wlccp_period = -1;
static int hf_wlccp_ipv4_address = -1;


/* Initialize the subtree pointers */
static gint ett_wlccp = -1;
static gint ett_wlccp_type = -1;
static gint ett_wlccp_flags = -1;

/* Code to actually dissect the packets */
static void
dissect_wlccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wlccp_tree, *wlccp_type_tree, *wlccp_flags_tree;
	gboolean relay_flag;
	guint8 version;
	guint16 type, flags;
	guint offset = 0;

	/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "WLCCP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		if(tvb_get_guint8(tvb, 0) == 0xC1) { /* Get the version number */
			col_add_fstr(pinfo->cinfo, COL_INFO, "Message subtype: %s",
				     match_strval((tvb_get_guint8(tvb, 6)>>6) & 3,
						  wlccp_subtype_vs));
		} else {
			col_add_str(pinfo->cinfo, COL_INFO, "WLCCP frame");
		}
	}

	if (tree) {
		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_wlccp, tvb, 0, -1, FALSE);
		wlccp_tree = proto_item_add_subtree(ti, ett_wlccp);

		proto_tree_add_item(wlccp_tree, hf_wlccp_version,
				    tvb, offset, 1, FALSE);
		version = tvb_get_guint8(tvb, 0);
		offset += 1;

		if(version == 0x0) {
			proto_tree_add_item(wlccp_tree, hf_wlccp_length,
					    tvb, 1, 1, FALSE);

			proto_tree_add_item(wlccp_tree, hf_wlccp_type,
					    tvb, 2, 2, FALSE);
			type = tvb_get_ntohs(tvb, 2);
		
			proto_tree_add_item(wlccp_tree, hf_wlccp_dstmac,
					    tvb, 4, 6, FALSE);

			proto_tree_add_item(wlccp_tree, hf_wlccp_srcmac,
					    tvb, 10, 6, FALSE);

			if(type == 0x4081) {
				proto_tree_add_item(wlccp_tree, hf_wlccp_ipv4_address,
						    tvb, 38, 4, FALSE);

				proto_tree_add_item(wlccp_tree, hf_wlccp_hostname,
						    tvb, 44, 28, FALSE);
			}
		}

		if(version == 0xC1) {
			proto_tree_add_item(wlccp_tree, hf_wlccp_sap,
					    tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(wlccp_tree, hf_wlccp_destination_node_type,
					    tvb, offset, 2, FALSE);
			offset += 2;
			
			proto_tree_add_item(wlccp_tree, hf_wlccp_length,
					    tvb, offset, 2, FALSE);
			offset += 2;
			
			ti = proto_tree_add_item(wlccp_tree, hf_wlccp_type,
						 tvb, offset, 1, FALSE);
			wlccp_type_tree = proto_item_add_subtree(ti, ett_wlccp_type);

			proto_tree_add_item(wlccp_type_tree, hf_wlccp_subtype,
					    tvb, offset, 1, FALSE);
			proto_tree_add_item(wlccp_type_tree, hf_wlccp_base_message_type,
					    tvb, offset, 1, FALSE);
			offset += 1;
			
			proto_tree_add_item(wlccp_tree, hf_wlccp_hops,
					    tvb, offset, 1, FALSE);
			offset += 1;
			
			proto_tree_add_item(wlccp_tree, hf_wlccp_msg_id,
					    tvb, offset, 2, FALSE);
			offset += 2;
			
			ti = proto_tree_add_item(wlccp_tree, hf_wlccp_flags,
						 tvb, offset, 2, FALSE);
			flags = tvb_get_ntohs(tvb, offset);
			wlccp_flags_tree = proto_item_add_subtree(ti, ett_wlccp_flags);

			proto_tree_add_item(wlccp_flags_tree, hf_wlccp_retry_flag,
					    tvb, offset, 2, FALSE);
			
			proto_tree_add_item(wlccp_flags_tree,
					    hf_wlccp_response_request_flag,
					    tvb, offset, 2, FALSE);

			proto_tree_add_item(wlccp_flags_tree,
					    hf_wlccp_tlv_flag,
					    tvb, offset, 2, FALSE);
			
			proto_tree_add_item(wlccp_flags_tree,
					    hf_wlccp_inbound_flag,
					    tvb, offset, 2, FALSE);
			
			proto_tree_add_item(wlccp_flags_tree,
					    hf_wlccp_outbound_flag,
					    tvb, offset, 2, FALSE);
			
			proto_tree_add_item(wlccp_flags_tree,
					    hf_wlccp_hopwise_routing_flag,
					    tvb, offset, 2, FALSE);
			
			proto_tree_add_item(wlccp_flags_tree,
					    hf_wlccp_root_cm_flag,
					    tvb, offset, 2, FALSE);
			
			proto_tree_add_item(wlccp_flags_tree,
					    hf_wlccp_relay_flag,
					    tvb, offset, 2, FALSE);
			relay_flag = (tvb_get_ntohs(tvb, offset)>>8) & 1;
			
			proto_tree_add_item(wlccp_flags_tree,
					    hf_wlccp_mic_flag,
					    tvb, offset, 2, FALSE);
			offset += 2;
			
			proto_tree_add_item(wlccp_tree, hf_wlccp_originator_node_type,
					    tvb, offset, 2, FALSE);
			offset += 2;
			
			proto_tree_add_item(wlccp_tree, hf_wlccp_originator,
					    tvb, offset, 6, FALSE);
			offset += 6;
			
			proto_tree_add_item(wlccp_tree, hf_wlccp_responder_node_type,
					    tvb, offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(wlccp_tree, hf_wlccp_responder,
					    tvb, offset, 6, FALSE);
			offset += 6;

			offset += 6; /* Skip over MAC address of sender again */
			
			if(relay_flag) {
				proto_tree_add_item(wlccp_tree, hf_wlccp_relay_node_type,
						    tvb, offset, 2, FALSE);
				offset += 2;

				proto_tree_add_item(wlccp_tree, hf_wlccp_relay_node_id,
						    tvb, offset, 6, FALSE);
				offset += 6;
			}

			if(flags == 0x2800) { /* We have extra information at the end of the frame */
				proto_tree_add_item(wlccp_tree, hf_wlccp_priority,
						    tvb, 38, 1, FALSE);

				proto_tree_add_item(wlccp_tree, hf_wlccp_age,
						    tvb, 48, 4, FALSE);

				proto_tree_add_item(wlccp_tree, hf_wlccp_period,
						    tvb, 55, 1, FALSE);

				proto_tree_add_item(wlccp_tree, hf_wlccp_ipv4_address,
						    tvb, 76, 4, FALSE);
				
			}
		}
	}
}


/* Register the protocol with Wireshark */
void
proto_register_wlccp(void)
{                 
	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_wlccp_version,
		  { "Version", "wlccp.version",
		    FT_UINT8, BASE_HEX, NULL,
		    0x0, "Protocol ID/Version", HFILL }
		},

		{ &hf_wlccp_srcmac,
		  { "Src MAC", "wlccp.srcmac",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Source MAC address", HFILL }
		},

		{ &hf_wlccp_dstmac,
		  { "Dst MAC", "wlccp.dstmac",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Destination MAC address", HFILL }
		},

		{ &hf_wlccp_hostname,
		  { "Hostname", "wlccp.hostname",
		    FT_STRING, BASE_NONE, NULL,
		    0x0, "Hostname of device", HFILL }
		},

		{ &hf_wlccp_sap,
		  { "SAP", "wlccp.sap",
		    FT_UINT8, BASE_DEC, VALS(wlccp_sap_vs),
		    0x0, "Service Access Point ID", HFILL }
		},

		{ &hf_wlccp_destination_node_type,
		  { "Destination node type", "wlccp.destination_node_type",
		    FT_UINT8, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, "Node type of the hop destination", HFILL }
		},

		{ &hf_wlccp_length,
		  { "Length", "wlccp.length",
		    FT_UINT16, BASE_DEC, NULL,
		    0x0, "Length of WLCCP payload (bytes)", HFILL }
		},


		{ &hf_wlccp_type,
		  { "Message Type", "wlccp.type",
		    FT_UINT8, BASE_HEX, NULL,
		    0x0, "Message Type", HFILL }
		},

		{ &hf_wlccp_subtype,
		  { "Subtype", "wlccp.subtype",
		    FT_UINT8, BASE_DEC, VALS(wlccp_subtype_vs),
		    MT_SUBTYPE, "Message Subtype", HFILL }
		},

		{ &hf_wlccp_base_message_type,
		  { "Base message type", "wlccp.base_message_type",
		    FT_UINT8, BASE_HEX_DEC, NULL,
		    MT_BASE_MSG_TYPE, "Base message type", HFILL }
		},


		{ &hf_wlccp_hops,
		  { "Hops", "wlccp.hops",
		    FT_UINT8, BASE_DEC, NULL,
		    0x0, "Number of WLCCP hops", HFILL }
		},

		{ &hf_wlccp_msg_id,
		  { "Message ID", "wlccp.msg_id",
		    FT_UINT16, BASE_DEC, NULL,
		    0x0, "Sequence number used to match request/reply pairs",
		    HFILL }
		},


		{ &hf_wlccp_flags,
		  { "Flags", "wlccp.flags",
		    FT_UINT16, BASE_HEX, NULL,
		    0x0, "Flags", HFILL }
		},

		{ &hf_wlccp_retry_flag,
		  { "Retry flag", "wlccp.retry_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_RETRY, "Set on for retransmissions", HFILL }
		},

		{ &hf_wlccp_response_request_flag,
		  { "Response request flag", "wlccp.response_request_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_RESPONSE_REQUEST, "Set on to request a reply", HFILL }
		},

		{ &hf_wlccp_tlv_flag,
		  { "TLV flag", "wlccp.tlv_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_TLV, "Set to indicate that optional TLVs follow the fixed fields", HFILL }
		},

		{ &hf_wlccp_inbound_flag,
		  { "Inbound flag", "wlccp.inbound_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_INBOUND, "Message is inbound to the top of the topology tree", HFILL }
		},

		{ &hf_wlccp_outbound_flag,
		  { "Outbound flag", "wlccp.outbound_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_OUTBOUND, "Message is outbound from the top of the topology tree", HFILL }
		},

		{ &hf_wlccp_hopwise_routing_flag,
		  { "Hopwise-routing flag", "wlccp.hopwise_routing_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_HOPWISE_ROUTING, "On to force intermediate access points to process the message also", HFILL }
		},

		{ &hf_wlccp_root_cm_flag,
		  { "Root context manager flag", "wlccp.root_cm_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_ROOT_CM, "Set to on to send message to the root context manager of the topology tree", HFILL }
		},

		{ &hf_wlccp_relay_flag,
		  { "Relay flag", "wlccp.relay_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_RELAY, "Signifies that this header is immediately followed by a relay node field", HFILL }
		},

		{ &hf_wlccp_mic_flag,
		  { "MIC flag", "wlccp.mic_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_MIC, "On in a message that must be authenticated and has an authentication TLV", HFILL }
		},

		{ &hf_wlccp_originator_node_type,
		  { "Originator node type", "wlccp.originator_node_type",
		    FT_UINT8, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, "Originating device's node type", HFILL }
		},

		{ &hf_wlccp_originator,
		  { "Originator", "wlccp.originator",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Originating device's MAC address", HFILL }
		},

		{ &hf_wlccp_responder_node_type,
		  { "Responder node type", "wlccp.responder_node_type",
		    FT_UINT8, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, "Responding device's node type", HFILL }
		},

		{ &hf_wlccp_responder,
		  { "Responder", "wlccp.responder",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Responding device's MAC address", HFILL }
		},

		{ &hf_wlccp_relay_node_type,
		  { "Relay node type", "wlccp.relay_node_type",
		    FT_UINT8, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, "Type of node which relayed this message", HFILL }
		},

		{ &hf_wlccp_relay_node_id,
		  { "Relay node ID", "wlccp.relay_node_id",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Node which relayed this message", HFILL }
		},

		{ &hf_wlccp_priority,
		  { "WDS priority", "wlccp.priority",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "WDS priority of this access point", HFILL }
		},

		{ &hf_wlccp_age,
		  { "Age", "wlccp.age",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Time since AP became a WDS master", HFILL }
		},

		{ &hf_wlccp_period,
		  { "Period", "wlccp.period",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Interval between announcements (seconds)", HFILL }
		},

		{ &hf_wlccp_ipv4_address,
		  { "IPv4 Address", "wlccp.ipv4_address",
		    FT_IPv4, BASE_NONE, NULL, 0,
		    "IPv4 address of this access point", HFILL }
		}

	};
	
	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_wlccp,
		&ett_wlccp_type,
		&ett_wlccp_flags
	};

	/* Register the protocol name and description */
	proto_wlccp = proto_register_protocol("Cisco Wireless LAN Context Control Protocol", "WLCCP", "wlccp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_wlccp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
        

}


void
proto_reg_handoff_wlccp(void)
{
        static gboolean inited = FALSE;
        
        if( !inited ) {

		dissector_handle_t wlccp_handle;

		wlccp_handle = create_dissector_handle(dissect_wlccp,
						       proto_wlccp);

		dissector_add("ethertype", ETHERTYPE_WLCCP, wlccp_handle);
		dissector_add("udp.port", WLCCP_UDP_PORT, wlccp_handle);
		dissector_add("llc.wlccp_pid", 0x0000, wlccp_handle);

		inited = TRUE;
	}
}


void
proto_register_wlccp_oui(void)
{
	static hf_register_info hf[] = {
		{ &hf_llc_wlccp_pid,
		  { "PID", "llc.wlccp_pid",
		    FT_UINT16, BASE_HEX, VALS(cisco_pid_vals),
		    0x0, "", HFILL }
		}
	};
	
	llc_add_oui(OUI_CISCOWL, "llc.wlccp_pid", "Cisco WLCCP OUI PID", hf);
}
