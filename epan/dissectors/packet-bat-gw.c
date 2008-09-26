/* packet-bat-gw.c
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

static gint ett_bat_gw = -1;

static dissector_handle_t ip_handle;
static dissector_handle_t data_handle;

static int hf_bat_gw_type = -1;
static int hf_bat_gw_ip = -1;

static guint global_bat_gw_udp_port = BAT_GW_PORT;

static void dissect_bat_gw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static const value_string packettypenames[] = {
	{ TUNNEL_DATA, "DATA" },
	{ TUNNEL_IP_REQUEST, "IP_REQUEST" },
	{ TUNNEL_IP_INVALID, "IP_INVALID" },
	{ TUNNEL_KEEPALIVE_REQUEST, "KEEPALIVE_REQUEST" },
	{ TUNNEL_KEEPALIVE_REPLY, "KEEPALIVE_REPLY" },
	{ 0, NULL }
};

void register_bat_gw()
{
	static hf_register_info hf[] = {
		{ &hf_bat_gw_type,
		  { "Type", "bat.gw.type",
		    FT_UINT8, BASE_DEC, VALS(packettypenames), 0x0,
		    "", HFILL }
		},
		{ &hf_bat_gw_ip,
		  { "IP", "bat.gw.ip",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_bat_gw
	};

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_bat_plugin, hf, array_length(hf));

	prefs_register_uint_preference(bat_module, "batman.gw.port", "GW UDP Port",
	                               "Set the port for B.A.T.M.A.N. Gateway "
	                               "messages (if other than the default of 4306)",
	                               10, &global_bat_gw_udp_port);
}

void reg_handoff_bat_gw(void)
{
	static gboolean inited = FALSE;
	static dissector_handle_t gw_handle;
	static guint udp_port;

	if (!inited) {
		gw_handle = create_dissector_handle(dissect_bat_gw, proto_bat_plugin);
		ip_handle = find_dissector("ip");
		data_handle = find_dissector("data");

		inited = TRUE;
	} else {
		dissector_delete("udp.port", udp_port, gw_handle);
	}

	udp_port = global_bat_gw_udp_port;
	dissector_add("udp.port", udp_port, gw_handle);
}

static void dissect_bat_gw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct gw_packet *gw_packeth;
	const guint8  *ip_addr;
	guint32 ip;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	gw_packeth = ep_alloc(sizeof(struct gw_packet));
	gw_packeth->type = tvb_get_guint8(tvb, 0);
	ip = tvb_get_ipv4(tvb, 1);
	ip_addr = tvb_get_ptr(tvb, 1, 4);

	/* set protocol name */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_GW");
	}

	/* Set info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_append_fstr(pinfo->cinfo, COL_INFO, "Type=%s",
		                val_to_str(gw_packeth->type, packettypenames, "Unknown (0x%02x)"));
		if (ip != 0) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " IP: %s (%s)",
			                get_hostname(ip), ip_to_str(ip_addr));
		}
	}


	/* Set tree info */
	if (tree) {
		proto_item *ti = NULL;
		proto_tree *bat_gw_entry_tree = NULL;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 1,
			                                    "B.A.T.M.A.N. GW [%s]",
			                                    val_to_str(gw_packeth->type, packettypenames, "Unknown (0x%02x)"));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, 1, FALSE);
		}
		bat_gw_entry_tree = proto_item_add_subtree(ti, ett_bat_gw);

		proto_tree_add_item(bat_gw_entry_tree, hf_bat_gw_type, tvb, offset, 1, FALSE);
		offset += 1;

		if (ip != 0) {
			proto_tree_add_ipv4(bat_gw_entry_tree, hf_bat_gw_ip, tvb, offset, 4, ip);
			offset += 4;
		}
	}

	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, length_remaining);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		if (gw_packeth->type == TUNNEL_DATA) {
			call_dissector(ip_handle, next_tvb, pinfo, tree);
		} else {
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}
	}
}
