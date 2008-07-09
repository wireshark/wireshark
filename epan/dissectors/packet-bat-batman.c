/* packet-bat-batman.c
 * Routines for B.A.T.M.A.N. Layer 3 dissection
 * Copyright 2008, Sven Eckelmann <sven.eckelmann@gmx.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "packet-bat.h"
#include <epan/addr_resolv.h>

static gint ett_bat_batman = -1;
static gint ett_bat_batman_flags = -1;
static gint ett_bat_batman_gwflags = -1;
static gint ett_bat_batman_hna = -1;

static dissector_handle_t data_handle;

static int hf_bat_batman_version = -1;
static int hf_bat_batman_flags = -1;
static int hf_bat_batman_ttl = -1;
static int hf_bat_batman_gwflags = -1;
static int hf_bat_batman_seqno = -1;
static int hf_bat_batman_gwport = -1;
static int hf_bat_batman_orig = -1;
static int hf_bat_batman_old_orig = -1;
static int hf_bat_batman_tq = -1;
static int hf_bat_batman_hna_len = -1;
static int hf_bat_batman_hna_network = -1;
static int hf_bat_batman_hna_netmask = -1;

/* flags */
static int hf_bat_batman_flags_unidirectional = -1;
static int hf_bat_batman_flags_directlink = -1;

/* gwflags */
/* unknown */

static guint global_bat_batman_udp_port = BAT_BATMAN_PORT;
static guint udp_port = 0;

static void dissect_bat_batman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_bat_hna(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* supported packet dissectors */
static void dissect_bat_batman_v5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void register_bat_batman(void)
{
	static hf_register_info hf[] = {
		{ &hf_bat_batman_version,
		  { "Version", "bat.batman.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_flags,
		  { "Flags", "bat.batman.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_ttl,
		  { "Time to Live", "bat.batman.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_gwflags,
		  { "Gateway Flags", "bat.batman.gwflags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_seqno,
		  { "Sequence number", "bat.batman.seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_gwport,
		  { "Gateway Port", "bat.batman.gwport",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_orig,
		  { "Originator", "bat.batman.orig",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_old_orig,
		  { "Received from", "bat.batman.old_orig",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_tq,
		  { "Transmission Quality", "bat.batman.tq",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_hna_len,
		  { "Number of HNAs", "bat.batman.hna_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_flags_unidirectional,
		  { "Unidirectional", "bat.batman.flags.unidirectional",
		    FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x80,
		    "", HFILL }
		},
		{ &hf_bat_batman_flags_directlink,
		  { "DirectLink", "bat.batman.flags.directlink",
		    FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x40,
		    "", HFILL }
		},
		{ &hf_bat_batman_hna_network,
		  { "HNA Network", "bat.batman.hna_network",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_batman_hna_netmask,
		  { "HNA Netmask", "bat.batman.hna_netmask",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_bat_batman,
		&ett_bat_batman_flags,
		&ett_bat_batman_gwflags,
		&ett_bat_batman_hna
	};

	proto_register_field_array(proto_bat_plugin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	prefs_register_uint_preference(bat_module, "batman.bat.port", "BAT UDP Port",
	                               "Set the port for B.A.T.M.A.N. BAT "
	                               "messages (if other than the default of 4305)",
	                               10, &global_bat_batman_udp_port);
}

void reg_handoff_bat_batman(void)
{
	static gboolean inited = FALSE;
	static dissector_handle_t batman_handle;

	if (!inited) {
		batman_handle = create_dissector_handle(dissect_bat_batman, proto_bat_plugin);
		data_handle = find_dissector("data");

		inited = TRUE;
	} else {
		dissector_delete("udp.port", udp_port, batman_handle);
	}

	udp_port = global_bat_batman_udp_port;
	dissector_add("udp.port", udp_port, batman_handle);
}

static void dissect_bat_batman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_BATMAN");
	}

	version = tvb_get_guint8(tvb, 0);
	switch (version) {
	case 5:
		dissect_bat_batman_v5(tvb, pinfo, tree);
		break;
	default:
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_clear(pinfo->cinfo, COL_INFO);
			col_append_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		}
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_bat_gwflags(tvbuff_t *tvb, guint8 gwflags, int offset, proto_item *tgw)
{
	proto_tree *gwflags_tree;
	guint8 s = (gwflags & 0x80) >> 7;
	guint8 downbits = (gwflags & 0x7C) >> 3;
	guint8 upbits = (gwflags & 0x07);
	guint down, up;

	down = 32 * (s + 2) * (1 << downbits);
	up = ((upbits + 1) * down) / 8;

	gwflags_tree =  proto_item_add_subtree(tgw, ett_bat_batman_gwflags);
	proto_tree_add_text(gwflags_tree, tvb, offset, 1, "Download Speed: %dkbit", down);
	proto_tree_add_text(gwflags_tree, tvb, offset, 1, "Upload Speed: %dkbit", up);

}

static void dissect_bat_batman_v5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct batman_packet_v5 *batman_packeth;
	const guint8  *old_orig_addr, *orig_addr;
	guint32 old_orig, orig;
	gint i;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v5));

	batman_packeth->version = tvb_get_guint8(tvb, 0);
	batman_packeth->flags = tvb_get_guint8(tvb, 1);
	batman_packeth->ttl = tvb_get_guint8(tvb, 2);
	batman_packeth->gwflags = tvb_get_guint8(tvb, 3);
	batman_packeth->seqno = tvb_get_ntohs(tvb, 4);
	batman_packeth->gwport = tvb_get_ntohs(tvb, 6);
	orig_addr = tvb_get_ptr(tvb, 8, 4);
	orig = tvb_get_ipv4(tvb, 8);
	SET_ADDRESS(&batman_packeth->orig, AT_IPv4, 4, orig_addr);
	old_orig_addr = tvb_get_ptr(tvb, 12, 4);
	old_orig = tvb_get_ipv4(tvb, 12);
	SET_ADDRESS(&batman_packeth->old_orig, AT_IPv4, 4, old_orig_addr);
	batman_packeth->tq = tvb_get_guint8(tvb, 16);
	batman_packeth->hna_len = tvb_get_guint8(tvb, 17);

	/* Set info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_append_fstr(pinfo->cinfo, COL_INFO, "Seq=%u",
		                batman_packeth->seqno);
	}

	/* Set tree info */
	if (tree) {
		proto_item *ti = NULL, *tf, *tgw;
		proto_tree *bat_batman_tree = NULL, *flag_tree = NULL;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, BATMAN_PACKET_V5_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_hostname(orig), ip_to_str(batman_packeth->orig.data));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, BATMAN_PACKET_V5_SIZE, FALSE);
		}
		bat_batman_tree = proto_item_add_subtree(ti, ett_bat_batman);

		/* items */
		proto_tree_add_item(bat_batman_tree, hf_bat_batman_version, tvb, offset, 1, FALSE);
		offset += 1;

		tf = proto_tree_add_item(bat_batman_tree, hf_bat_batman_flags, tvb, offset, 1, FALSE);
		/* <flags> */
		flag_tree =  proto_item_add_subtree(tf, ett_bat_batman_flags);
		proto_tree_add_boolean(flag_tree, hf_bat_batman_flags_unidirectional, tvb, offset, 1, batman_packeth->flags);
		proto_tree_add_boolean(flag_tree, hf_bat_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
		/* </flags> */
		offset += 1;

		proto_tree_add_item(bat_batman_tree, hf_bat_batman_ttl, tvb, offset, 1, FALSE);
		offset += 1;

		tgw = proto_tree_add_item(bat_batman_tree, hf_bat_batman_gwflags, tvb, offset, 1, FALSE);
		dissect_bat_gwflags(tvb, batman_packeth->gwflags, offset, tgw);
		offset += 1;

		proto_tree_add_item(bat_batman_tree, hf_bat_batman_seqno, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(bat_batman_tree, hf_bat_batman_gwport, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_ipv4(bat_batman_tree, hf_bat_batman_orig, tvb, offset, 4, orig);
		offset += 4;

		proto_tree_add_ipv4(bat_batman_tree, hf_bat_batman_old_orig, tvb, offset, 4,  old_orig);
		offset += 4;

		proto_tree_add_item(bat_batman_tree, hf_bat_batman_tq, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(bat_batman_tree, hf_bat_batman_hna_len, tvb, offset, 1, FALSE);
		offset += 1;
	}

	tap_queue_packet(bat_tap, pinfo, batman_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	for (i = 0; i < batman_packeth->hna_len; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 5, 5);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		dissect_bat_hna(next_tvb, pinfo, tree);
		offset += 5;
	}

	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, length_remaining);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_bat_hna(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	const guint8  *hna_addr;
	guint32 hna;
	guint8 hna_netmask;

	hna_addr = tvb_get_ptr(tvb, 0, 4);
	hna = tvb_get_ipv4(tvb, 0);
	hna_netmask = tvb_get_guint8(tvb, 4);


	/* Set tree info */
	if (tree) {
		proto_item *ti = NULL;
		proto_tree *bat_batman_hna_tree = NULL;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 5,
			                                    "B.A.T.M.A.N. HNA: %s/%d",
			                                    ip_to_str(hna_addr), hna_netmask);
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, 5, FALSE);
		}
		bat_batman_hna_tree = proto_item_add_subtree(ti, ett_bat_batman_hna);

		proto_tree_add_ipv4(bat_batman_hna_tree, hf_bat_batman_hna_network, tvb, 0, 4, hna);
		proto_tree_add_item(bat_batman_hna_tree, hf_bat_batman_hna_netmask, tvb, 4, 1, FALSE);
	}
}
