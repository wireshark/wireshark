/* packet-lge_monitor.c
 * Routines for LGE Monitor packet dissection
 * Copyright 2006, Anders Broman <anders.broman[at]ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * LGE Monitor is a trace tool from Nortel.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>


/* Initialize the protocol and registered fields */
static int proto_lge_monitor		= -1;

static int hf_lge_monitor_dir = -1;
static int hf_lge_monitor_prot = -1;
static int hf_lge_monitor_length = -1;

/* Initialize the subtree pointers */
static int ett_lge_monitor = -1;


static guint LGEMonitorUDPPort = 0;
static dissector_handle_t mtp3_handle, m3ua_handle, sccp_handle, sctp_handle;

static const value_string lge_monitor_dir_vals[] = {
	{ 0x00,	"TX(Transmit Message Signaling Unit)" },
	{ 0x01,	"RX(Receive Message Signaling Unit)" },
	{ 0,	NULL }
};

static const value_string lge_monitor_prot_vals[] = {
	{ 0x00,	"MTP-3(Message Transfer Part 3)" },
	{ 0x01, "SCCP(Signaling Connection Control Part)"},
	{ 0x02, "SCTP(Stream Control Transmission Protocol)"},
	{ 0x03, "M3UA(MTP-3 User Adaptation)"},
	{ 0,	NULL }
};

#define LGEMON_PROTO_HEADER_LENGTH 12

/* Code to actually dissect the packets */
static void
dissect_lge_monitor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint32 lge_monitor_proto_id;
	tvbuff_t* next_tvb = NULL;

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *lge_monitor_tree;

/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LGE Monitor");

	ti = proto_tree_add_item(tree, proto_lge_monitor, tvb, 0, LGEMON_PROTO_HEADER_LENGTH, FALSE);
	lge_monitor_tree = proto_item_add_subtree(ti, ett_lge_monitor);

	proto_tree_add_text(lge_monitor_tree, tvb, offset, LGEMON_PROTO_HEADER_LENGTH, "LGE Monitor PDU");
	proto_tree_add_item(lge_monitor_tree, hf_lge_monitor_dir, tvb, offset, 4, FALSE);
	offset = offset +4;
	lge_monitor_proto_id = tvb_get_ntohl(tvb,offset);
	proto_tree_add_item(lge_monitor_tree, hf_lge_monitor_prot, tvb, offset, 4, FALSE);
	offset = offset +4;
	proto_tree_add_item(lge_monitor_tree, hf_lge_monitor_length, tvb, offset, 4, FALSE);
	offset = offset +4;

	next_tvb = tvb_new_subset_remaining(tvb, offset);

	switch (lge_monitor_proto_id){
	case 0: /* MTP3 */
		call_dissector(mtp3_handle, next_tvb, pinfo, tree);
		break;
	case 1: /* SCCP */
		call_dissector(sccp_handle, next_tvb, pinfo, tree);
		break;
	case 2: /* SCTP */
		call_dissector(sctp_handle, next_tvb, pinfo, tree);
		return;
	case 3: /* M3UA */
		call_dissector(m3ua_handle, next_tvb, pinfo, tree);
		return;
	default:
		proto_tree_add_text(lge_monitor_tree, tvb, offset, -1, "LGE Monitor data");
		break;
	}
	return;
}


void
proto_reg_handoff_lge_monitor(void)
{
	static dissector_handle_t lge_monitor_handle;
	static guint saved_udp_port;
	static gboolean lge_monitor_prefs_initialized = FALSE;

	if (!lge_monitor_prefs_initialized) {
		lge_monitor_handle = create_dissector_handle(dissect_lge_monitor, proto_lge_monitor);
		dissector_add_handle("udp.port", lge_monitor_handle);  /* for 'decode-as' */
		mtp3_handle  = find_dissector("mtp3");
		m3ua_handle  = find_dissector("m3ua");
		sccp_handle  = find_dissector("sccp");
		sctp_handle  = find_dissector("sctp");
		lge_monitor_prefs_initialized = TRUE;
	  }
	else {
		if (saved_udp_port != 0) {
			dissector_delete_uint("udp.port", saved_udp_port, lge_monitor_handle);
		}
	}

	if (LGEMonitorUDPPort != 0) {
		dissector_add_uint("udp.port", LGEMonitorUDPPort, lge_monitor_handle);
	}
	saved_udp_port = LGEMonitorUDPPort;
}

void
proto_register_lge_monitor(void)
{

	module_t *lge_monitor_module;

/* Setup list of header fields  */
	static hf_register_info hf[] = {
		{ &hf_lge_monitor_dir,
			{ "Direction",           "lge_monitor.dir",
			FT_UINT32, BASE_DEC, VALS(lge_monitor_dir_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_lge_monitor_prot,
			{ "Protocol Identifier",           "lge_monitor.prot",
			FT_UINT32, BASE_DEC, VALS(lge_monitor_prot_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_lge_monitor_length,
			{ "Payload Length",           "lge_monitor.length",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_lge_monitor,
	};

/* Register the protocol name and description */
	proto_lge_monitor = proto_register_protocol("LGE Monitor","LGE_Monitor", "lge_monitor");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_lge_monitor, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	/* Register a configuration option for port */


	lge_monitor_module = prefs_register_protocol(proto_lge_monitor, proto_reg_handoff_lge_monitor);

	prefs_register_uint_preference(lge_monitor_module, "udp.port",
								   "LGE Monitor UDP Port",
								   "Set UDP port for LGE Monitor messages",
								   10,
								   &LGEMonitorUDPPort);

}


