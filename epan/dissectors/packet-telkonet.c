/* packet-telkonet.c
 * Routines for ethertype 0x88A1 tunneling dissection
 *
 * $Id$
 *
 * Copyright 2006 Joerg Mayer (see AUTHORS file)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* 2do:
 * - find out more about the real meaning of the 8 bytes
 *   and possible other packet types
 * - Telkonet (www.telkonet.com) has registered other ethertypes
 *   as well: find out what they do
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>

static int proto_telkonet = -1;
static int hf_telkonet_type = -1;

static gint ett_telkonet = -1;

static dissector_handle_t eth_withoutfcs_handle;

typedef enum {
	TELKONET_TYPE_TUNNEL = 0x78
} telkonet_type_t;

static const value_string telkonet_type_vals[] = {
	{ TELKONET_TYPE_TUNNEL,	"tunnel" },

	{ 0x00,	NULL }
};

static void
dissect_telkonet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *ti, *telkonet_tree;
	int offset = 0;
	telkonet_type_t type;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TELKONET");
	col_clear(pinfo->cinfo, COL_INFO);

	type = tvb_get_guint8(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
	  col_add_fstr(pinfo->cinfo, COL_INFO, "Telkonet type: %s",
		val_to_str(type, telkonet_type_vals, "Unknown (0x%02x)"));
	}

	telkonet_tree = NULL;

	ti = proto_tree_add_item(tree, proto_telkonet, tvb, 0, 8, ENC_NA);
	telkonet_tree = proto_item_add_subtree(ti, ett_telkonet);

	proto_tree_add_item(telkonet_tree, hf_telkonet_type, tvb, 0, 8, ENC_NA);
	offset += 8;

	if (type == TELKONET_TYPE_TUNNEL)
		call_dissector(eth_withoutfcs_handle, tvb_new_subset_remaining(tvb, offset),
			pinfo, tree);
}

void
proto_register_telkonet(void)
{
	static hf_register_info hf[] = {
		{ &hf_telkonet_type,
		{ "Type", "telkonet.type", FT_BYTES, BASE_NONE, NULL,
			0x0, "TELKONET type", HFILL }},
	};
	static gint *ett[] = {
		&ett_telkonet,
	};

	proto_telkonet = proto_register_protocol("Telkonet powerline", "TELKONET", "telkonet");
	proto_register_field_array(proto_telkonet, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_telkonet(void)
{
	dissector_handle_t telkonet_handle;

	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");

	telkonet_handle = create_dissector_handle(dissect_telkonet, proto_telkonet);
	dissector_add_uint("ethertype", ETHERTYPE_TELKONET, telkonet_handle);
}
