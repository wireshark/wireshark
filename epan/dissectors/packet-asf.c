/* packet-asf.c
 * Routines for ASF packet dissection
 *
 * Duncan Laurie <duncan@sun.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-rmcp.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 
 * 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

/*
 * See
 *
 *	http://www.dmtf.org/standards/standard_alert.php
 */

#define RMCP_CLASS_ASF 0x06

static int proto_asf = -1;
static int hf_asf_iana = -1;
static int hf_asf_type = -1;
static int hf_asf_tag = -1;
static int hf_asf_len = -1;

static dissector_handle_t data_handle;
static gint ett_asf = -1;

static const value_string asf_type_vals[] = {
	{ 0x10, "Reset" },
	{ 0x11, "Power-up" },
	{ 0x12, "Unconditional Power-down" },
	{ 0x13, "Power Cycle" },
	{ 0x40, "Presence Pong" },
	{ 0x41, "Capabilities Response" },
	{ 0x42, "System State Response" },
	{ 0x80, "Presence Ping" },
	{ 0x81, "Capabilities Request" },
	{ 0x82, "System State Request" },
	{ 0x00, NULL }
};

static void
dissect_asf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*asf_tree = NULL;
	proto_item	*ti;
	guint8		type;
	guint8		len;
	tvbuff_t	*next_tvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ASF");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	type = tvb_get_guint8(tvb, 4);
	len = tvb_get_guint8(tvb, 7);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
		     val_to_str(type, asf_type_vals, "Unknown (0x%02x)"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_asf, tvb, 0, 8, FALSE);
		asf_tree = proto_item_add_subtree(ti, ett_asf);
		proto_tree_add_item(asf_tree, hf_asf_iana, tvb, 0, 4, FALSE);
		proto_tree_add_item(asf_tree, hf_asf_type, tvb, 4, 1, FALSE);
		proto_tree_add_item(asf_tree, hf_asf_tag, tvb, 5, 1, FALSE);
		proto_tree_add_item(asf_tree, hf_asf_len, tvb, 7, 1, FALSE);
	}

	if (len) {
		next_tvb = tvb_new_subset(tvb, 8, -1, len);
		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

void
proto_register_asf(void)
{
	static hf_register_info hf[] = {
		{ &hf_asf_iana, {
			"IANA Enterprise Number", "asf.iana",
			FT_UINT32, BASE_HEX, NULL, 0,
			"ASF IANA Enterprise Number", HFILL }},
		{ &hf_asf_type, {
			"Message Type", "asf.type",
			FT_UINT8, BASE_HEX, VALS(asf_type_vals), 0,
			"ASF Message Type", HFILL }},
		{ &hf_asf_tag, {
			"Message Tag", "asf.tag",
			FT_UINT8, BASE_HEX, NULL, 0,
			"ASF Message Tag", HFILL }},
		{ &hf_asf_len, {
			"Data Length", "asf.len",
			FT_UINT8, BASE_DEC, NULL, 0,
			"ASF Data Length", HFILL }},
	};
	static gint *ett[] = {
		&ett_asf,
	};

	proto_asf = proto_register_protocol(
		"Alert Standard Forum", "ASF", "asf");

	proto_register_field_array(proto_asf, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_asf(void)
{
	dissector_handle_t asf_handle;

	data_handle = find_dissector("data");

	asf_handle = create_dissector_handle(dissect_asf, proto_asf);
	dissector_add("rmcp.class", RMCP_CLASS_ASF, asf_handle);
}
