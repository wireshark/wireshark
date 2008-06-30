/* packet-bat-vis.c
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

static gint ett_bat_vis = -1;
static gint ett_bat_vis_entry = -1;

static dissector_handle_t data_handle;

static int hf_bat_vis_vis_orig = -1;
static int hf_bat_vis_version = -1;
static int hf_bat_vis_gwflags = -1;
static int hf_bat_max_tq_v22 = -1;
static int hf_bat_max_tq_v23 = -1;
static int hf_bat_vis_data_type = -1;
static int hf_bat_vis_netmask = -1;
static int hf_bat_vis_tq_v22 = -1;
static int hf_bat_vis_tq_v23 = -1;
static int hf_bat_vis_data_ip = -1;

static guint global_bat_vis_udp_port = BAT_VIS_PORT;
static guint udp_port = 0;

static void dissect_vis_entry_v22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_bat_vis_v22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_vis_entry_v23(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_bat_vis_v23(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_bat_vis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static const value_string packettypenames[] = {
	{ DATA_TYPE_NEIGH, "NEIGH" },
	{ DATA_TYPE_SEC_IF, "SEC_IF" },
	{ DATA_TYPE_HNA, "HNA" },
	{ 0, NULL }
};

void register_bat_vis(void)
{
	static hf_register_info hf[] = {
		{ &hf_bat_vis_vis_orig,
		  { "Originator", "bat.vis.sender_ip",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_vis_version,
		  { "Version", "bat.vis.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_vis_gwflags,
		  { "Gateway Flags", "bat.vis.gwflags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_max_tq_v22,
		  { "Maximum Transmission Quality", "bat.vis.tq_max",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_max_tq_v23,
		  { "Maximum Transmission Quality", "bat.vis.tq_max",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_bat_vis_data_type,
		  { "Type", "bat.vis.data_type",
		    FT_UINT8, BASE_DEC, VALS(packettypenames), 0x0,
		    "", HFILL }
		},
		{ &hf_bat_vis_tq_v22,
		  { "Transmission Quality", "bat.vis.tq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL}
		},
		{ &hf_bat_vis_tq_v23,
		  { "Transmission Quality", "bat.vis.tq",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "", HFILL}
		},
		{ &hf_bat_vis_netmask,
		  { "Netmask", "bat.vis.netmask",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "", HFILL}
		},
		{ &hf_bat_vis_data_ip,
		  { "IP", "bat.vis.data_ip",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_bat_vis,
		&ett_bat_vis_entry
	};

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_bat_plugin, hf, array_length(hf));

	prefs_register_uint_preference(bat_module, "batman.vis.port", "VIS UDP Port",
	                               "Set the port for B.A.T.M.A.N. VIS "
	                               "messages (if other than the default of 4307)",
	                               10, &global_bat_vis_udp_port);
}

void reg_handoff_bat_vis(void)
{
	static gboolean inited = FALSE;
	static dissector_handle_t vis_handle;

	if (!inited) {
		vis_handle = create_dissector_handle(dissect_bat_vis, proto_bat_plugin);
		data_handle = find_dissector("data");
	} else {
		dissector_delete("udp.port", udp_port, vis_handle);
	}

	udp_port = global_bat_vis_udp_port;
	dissector_add("udp.port", udp_port, vis_handle);
}

static void dissect_bat_vis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_VIS");
	}

	version = tvb_get_guint8(tvb, 4);
	switch (version) {
	case 22:
		dissect_bat_vis_v22(tvb, pinfo, tree);
		break;
	case 23:
		dissect_bat_vis_v23(tvb, pinfo, tree);
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

static void dissect_bat_vis_v22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v22 *vis_packeth;
	const guint8  *sender_ip_addr;
	guint32 sender_ip;
	proto_tree *bat_vis_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining, i;
	int offset = 0;

	vis_packeth = ep_alloc(sizeof(struct vis_packet_v22));

	sender_ip_addr = tvb_get_ptr(tvb, 0, 4);
	sender_ip = tvb_get_ipv4(tvb, 0);
	SET_ADDRESS(&vis_packeth->sender_ip, AT_IPv4, 4, sender_ip_addr);
	vis_packeth->version = tvb_get_guint8(tvb, 4);
	vis_packeth->gw_class = tvb_get_guint8(tvb, 5);
	vis_packeth->tq_max = tvb_get_ntohs(tvb, 6);

	/* set protocol name */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_VIS");
	}

	/* Set info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_append_fstr(pinfo->cinfo, COL_INFO, "Src: %s (%s)",
		                get_hostname(sender_ip), ip_to_str(vis_packeth->sender_ip.data));
	}

	/* Set tree info */
	if (tree) {
		proto_item *ti = NULL;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, VIS_PACKET_V22_SIZE,
			                                    "B.A.T.M.A.N. Vis, Src: %s (%s)",
			                                    get_hostname(sender_ip), ip_to_str(vis_packeth->sender_ip.data));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, VIS_PACKET_V22_SIZE, FALSE);
		}
		bat_vis_tree = proto_item_add_subtree(ti, ett_bat_vis);

		/* items */
		proto_tree_add_ipv4(bat_vis_tree, hf_bat_vis_vis_orig, tvb, offset, 4, sender_ip);
		offset += 4;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_version, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_gwflags, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_max_tq_v22, tvb, offset, 2, FALSE);
		offset += 2;
	}

	tap_queue_packet(bat_tap, pinfo, vis_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	for (i = 0; i < length_remaining; i += VIS_PACKET_V22_DATA_SIZE) {
		next_tvb = tvb_new_subset(tvb, offset, VIS_PACKET_V22_DATA_SIZE, VIS_PACKET_V22_DATA_SIZE);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		if (bat_vis_tree != NULL) {
			dissect_vis_entry_v22(next_tvb, pinfo, tree);
		}

		offset += VIS_PACKET_V22_DATA_SIZE;
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

static void dissect_vis_entry_v22(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	struct vis_data_v22 *vis_datah;
	const guint8  *ip_addr;
	guint32 ip;

	vis_datah = ep_alloc(sizeof(struct vis_data_v22));
	vis_datah->type = tvb_get_guint8(tvb, 0);
	vis_datah->data = tvb_get_ntohs(tvb, 1);
	ip_addr = tvb_get_ptr(tvb, 3, 4);
	ip = tvb_get_ipv4(tvb, 3);
	SET_ADDRESS(&vis_datah->ip, AT_IPv4, 4, ip_addr);


	/* Set tree info */
	if (tree) {
		proto_item *ti = NULL;
		proto_tree *bat_vis_entry_tree = NULL;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 7,
			                                    "VIS Entry: [%s] %s (%s)",
			                                    val_to_str(vis_datah->type, packettypenames, "Unknown (0x%02x)"),
			                                    get_hostname(ip), ip_to_str(vis_datah->ip.data));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, 7, FALSE);
		}
		bat_vis_entry_tree = proto_item_add_subtree(ti, ett_bat_vis_entry);

		proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_data_type, tvb, 0, 1, FALSE);

		switch (vis_datah->type) {
		case DATA_TYPE_NEIGH:
			proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_tq_v22, tvb, 1, 2, FALSE);
			break;
		case DATA_TYPE_HNA:
			proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_netmask, tvb, 1, 1, FALSE);
			break;
		case DATA_TYPE_SEC_IF:
		default:
			break;
		}
		proto_tree_add_ipv4(bat_vis_entry_tree, hf_bat_vis_data_ip, tvb, 3, 4,  ip);
	}
}

static void dissect_bat_vis_v23(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v23 *vis_packeth;
	const guint8  *sender_ip_addr;
	guint32 sender_ip;
	proto_tree *bat_vis_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining, i;
	int offset = 0;

	vis_packeth = ep_alloc(sizeof(struct vis_packet_v23));

	sender_ip_addr = tvb_get_ptr(tvb, 0, 4);
	sender_ip = tvb_get_ipv4(tvb, 0);
	SET_ADDRESS(&vis_packeth->sender_ip, AT_IPv4, 4, sender_ip_addr);
	vis_packeth->version = tvb_get_guint8(tvb, 4);
	vis_packeth->gw_class = tvb_get_guint8(tvb, 5);
	vis_packeth->tq_max = tvb_get_guint8(tvb, 6);

	/* set protocol name */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_VIS");
	}

	/* Set info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_append_fstr(pinfo->cinfo, COL_INFO, "Src: %s (%s)",
		                get_hostname(sender_ip), ip_to_str(vis_packeth->sender_ip.data));
	}

	/* Set tree info */
	if (tree) {
		proto_item *ti = NULL;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, VIS_PACKET_V23_SIZE,
			                                    "B.A.T.M.A.N. Vis, Src: %s (%s)",
			                                    get_hostname(sender_ip), ip_to_str(vis_packeth->sender_ip.data));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, VIS_PACKET_V23_SIZE, FALSE);
		}
		bat_vis_tree = proto_item_add_subtree(ti, ett_bat_vis);

		/* items */
		proto_tree_add_ipv4(bat_vis_tree, hf_bat_vis_vis_orig, tvb, offset, 4, sender_ip);
		offset += 4;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_version, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_gwflags, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_max_tq_v23, tvb, offset, 1, FALSE);
		offset += 1;
	}

	tap_queue_packet(bat_tap, pinfo, vis_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	for (i = 0; i < length_remaining; i += VIS_PACKET_V23_DATA_SIZE) {
		next_tvb = tvb_new_subset(tvb, offset, VIS_PACKET_V23_DATA_SIZE, VIS_PACKET_V23_DATA_SIZE);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		if (bat_vis_tree != NULL) {
			dissect_vis_entry_v23(next_tvb, pinfo, tree);
		}

		offset += VIS_PACKET_V23_DATA_SIZE;
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

static void dissect_vis_entry_v23(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	struct vis_data_v23 *vis_datah;
	const guint8  *ip_addr;
	guint32 ip;

	vis_datah = ep_alloc(sizeof(struct vis_data_v23));
	vis_datah->type = tvb_get_guint8(tvb, 0);
	vis_datah->data = tvb_get_guint8(tvb, 1);
	ip_addr = tvb_get_ptr(tvb, 2, 4);
	ip = tvb_get_ipv4(tvb, 2);
	SET_ADDRESS(&vis_datah->ip, AT_IPv4, 4, ip_addr);


	/* Set tree info */
	if (tree) {
		proto_item *ti = NULL;
		proto_tree *bat_vis_entry_tree = NULL;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 7,
			                                    "VIS Entry: [%s] %s (%s)",
			                                    val_to_str(vis_datah->type, packettypenames, "Unknown (0x%02x)"),
			                                    get_hostname(ip), ip_to_str(vis_datah->ip.data));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, 7, FALSE);
		}
		bat_vis_entry_tree = proto_item_add_subtree(ti, ett_bat_vis_entry);

		proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_data_type, tvb, 0, 1, FALSE);

		switch (vis_datah->type) {
		case DATA_TYPE_NEIGH:
			proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_tq_v23, tvb, 1, 1, FALSE);
			break;
		case DATA_TYPE_HNA:
			proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_netmask, tvb, 1, 1, FALSE);
			break;
		case DATA_TYPE_SEC_IF:
		default:
			break;
		}
		proto_tree_add_ipv4(bat_vis_entry_tree, hf_bat_vis_data_ip, tvb, 2, 4,  ip);
	}
}
