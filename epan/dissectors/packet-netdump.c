/* packet-netdump.c
 * Routines for Netdump dissection
 * Copyright 2009, Neil Horman <nhorman@tuxdriver.com> 
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

/* forward reference */
void proto_reg_handoff_netdump(void);

/* Initialize the protocol and registered fields */
static int proto_netdump = -1;
static int hf_netdump_magic_number = -1;
static int hf_netdump_seq_nr = -1;
static int hf_netdump_command = -1;
static int hf_netdump_from = -1;
static int hf_netdump_to = -1;
static int hf_netdump_payload = -1;
static int hf_netdump_code = -1;
static int hf_netdump_info = -1;
static int hf_netdump_version = -1;

/* Global sample port pref */
static guint gPORT_PREF = 0;

/* Initialize the subtree pointers */
static gint ett_netdump = -1;

static const value_string command_names[] = {
	{ 0, "COMM_NONE" },
	{ 1, "COMM_SEND_MEM" },
	{ 2, "COMM_EXIT" },
	{ 3, "COMM_REBOOT" },
	{ 4, "COMM_HELLO" },
	{ 5, "COMM_GET_NR_PAGES" },
	{ 6, "COMM_GET_PAGE_SIZE" },
	{ 7, "COMM_START_NETDUMP_ACK" },
	{ 8, "COMM_GET_REGS" },
	{ 9, "COMM_SHOW_STATE" },
	{ 0, NULL }
};

static const value_string reply_code_names[] = {
	{ 0, "REPLY_NONE" },
	{ 1, "REPLY_ERROR" },
	{ 2, "REPLY_LOG" },
	{ 3, "REPLY_MEM" },
	{ 4, "REPLY_RESERVED" },
	{ 5, "REPLY_HELLO" },
	{ 6, "REPLY_NR_PAGES" },
	{ 7, "REPLY_PAGE_SIZE" },
	{ 8, "REPLY_START_NETDUMP" },
	{ 9, "REPLY_END_NETDUMP" },
	{ 10, "REPLY_REGS" },
	{ 11, "REPLY_MAGIC" },
	{ 12, "REPLY_SHOW_STATE" },
	{ 0, NULL }
};


/* Code to actually dissect the packets */
static void
dissect_netdump(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	/* Check that there's enough data */
	if (tvb_reported_length(tvb) == 0)
		return;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netdump");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *netdump_tree = NULL;
		ti = proto_tree_add_item(tree, proto_netdump, tvb, 0, -1, FALSE);
		netdump_tree = proto_item_add_subtree(ti, ett_netdump);
		if (tvb_reported_length(tvb) == 24) {
			/* Its a request format packet */
			proto_tree_add_item(netdump_tree, hf_netdump_magic_number, tvb, 0, 8, FALSE);
			proto_tree_add_item(netdump_tree, hf_netdump_seq_nr, tvb, 8, 4, FALSE);
			proto_tree_add_item(netdump_tree, hf_netdump_command, tvb, 12, 4, FALSE);
			proto_tree_add_item(netdump_tree, hf_netdump_from, tvb, 16, 4, FALSE);
			proto_tree_add_item(netdump_tree, hf_netdump_to, tvb, 20, 4, FALSE);
		} else {
			/* Its a reply packet */
			proto_tree_add_item(netdump_tree, hf_netdump_version, tvb, 0, 1, FALSE);
			proto_tree_add_item(netdump_tree, hf_netdump_seq_nr, tvb, 1, 4, FALSE);
			proto_tree_add_item(netdump_tree, hf_netdump_code, tvb, 5, 4, FALSE);
			proto_tree_add_item(netdump_tree, hf_netdump_info, tvb, 9, 4, TRUE);
			proto_tree_add_item(netdump_tree, hf_netdump_payload, tvb, 13, -1, ENC_NA);
		}
	}
}

void proto_register_netdump(void)
{
	module_t *netdump_module;

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_netdump
	};

	static hf_register_info hf[] = {
		{ &hf_netdump_magic_number,
			{ "Netdump Magic Number", "netdump.magic",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_netdump_seq_nr,
			{"Netdump seq number", "netdump.seq_nr",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_netdump_command,
			{"Netdump command", "netdump.command",
			FT_UINT32, BASE_DEC,
			VALS(command_names), 0x0,
			NULL, HFILL}
		},
		{ &hf_netdump_from,
			{"Netdump from val", "netdump.from",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_netdump_to,
			{"Netdump to val", "netdump.to",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_netdump_code,
			{"Netdump code", "netdump.code",
			FT_UINT32, BASE_DEC,
			VALS(reply_code_names), 0x0,
			NULL, HFILL}
		},
		{ &hf_netdump_info,
			{"Netdump info", "netdump.info",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_netdump_payload,
			{"Netdump payload", "netdump.payload",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_netdump_version,
			{"Netdump version", "netdump.version",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		}
	};

	proto_netdump = proto_register_protocol (
		"Netdump Protocol",	/* name */
		"Netdump",		/* short name */
		"netdump"		/* abbrev */
		);
	proto_register_field_array(proto_netdump, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netdump_module = prefs_register_protocol(proto_netdump,
		proto_reg_handoff_netdump);

	/* Register a sample port preference   */
	prefs_register_uint_preference(netdump_module, "udp.port",
		"Netdump UDP port",
		"port if other than the default",
		10, &gPORT_PREF);
}

void proto_reg_handoff_netdump(void)
{
	static gboolean initalized = FALSE;
	static dissector_handle_t netdump_handle;
	static int CurrentPort;

	if (!initalized) {
		netdump_handle = create_dissector_handle(dissect_netdump,
				proto_netdump);

		dissector_add_handle("udp.port", netdump_handle); /* For Decode As */
		initalized = TRUE;
	} else {
		if (CurrentPort != 0)
			dissector_delete_uint("udp.port", CurrentPort, netdump_handle);
	}

	CurrentPort = gPORT_PREF;

	if (CurrentPort != 0)
		dissector_add_uint("udp.port", CurrentPort, netdump_handle);
}

