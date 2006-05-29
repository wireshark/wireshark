/* packet-rmcp.c
 * Routines for RMCP packet dissection
 *
 * Duncan Laurie <duncan@sun.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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
 *
 * (the ASF specification includes RMCP)
 */

static int proto_rmcp = -1;
static int hf_rmcp_version = -1;
static int hf_rmcp_sequence = -1;
static int hf_rmcp_class = -1;
static int hf_rmcp_type = -1;

static gint ett_rmcp = -1;
static gint ett_rmcp_typeclass = -1;

static dissector_handle_t data_handle;
static dissector_table_t rmcp_dissector_table;

#define UDP_PORT_RMCP		623
#define UDP_PORT_RMCP_SECURE	664

#define RMCP_TYPE_MASK		0x80
#define RMCP_TYPE_NORM		0x00
#define RMCP_TYPE_ACK		0x01

static const value_string rmcp_type_vals[] = {
	{ RMCP_TYPE_NORM,	"Normal RMCP" },
	{ RMCP_TYPE_ACK,	"RMCP ACK" },
	{ 0,			NULL }
};

#define RMCP_CLASS_MASK		0x1f
#define RMCP_CLASS_ASF		0x06
#define RMCP_CLASS_IPMI		0x07
#define RMCP_CLASS_OEM		0x08

static const value_string rmcp_class_vals[] = {
	{ RMCP_CLASS_ASF,	"ASF" },
	{ RMCP_CLASS_IPMI,	"IPMI" },
	{ RMCP_CLASS_OEM,	"OEM" },
	{ 0,			NULL }
};

static int
dissect_rmcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*rmcp_tree = NULL, *field_tree;
	proto_item	*ti, *tf;
	tvbuff_t	*next_tvb;
	guint8		class;
	const gchar	*class_str;
	guint8		type;

	/*
	 * Check whether it's a known class value; if not, assume it's
	 * not RMCP.
	 */
	if (!tvb_bytes_exist(tvb, 3, 1))
		return 0;	/* class value byte not present */
	class = tvb_get_guint8(tvb, 3);

	/* Get the normal/ack bit from the RMCP class */
	type = (class & RMCP_TYPE_MASK) >> 7;
	class &= RMCP_CLASS_MASK;

	class_str = match_strval(class, rmcp_class_vals);
	if (class_str == NULL)
		return 0;	/* unknown class value */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RMCP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s, Class: %s",
		     val_to_str(type, rmcp_type_vals, "Unknown (0x%02x)"),
		     class_str);

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_rmcp, tvb, 0, 4,
			 "Remote Management Control Protocol, Class: %s",
			 class_str);
		rmcp_tree = proto_item_add_subtree(ti, ett_rmcp);

		proto_tree_add_item(rmcp_tree, hf_rmcp_version, tvb, 0, 1, TRUE);
		proto_tree_add_item(rmcp_tree, hf_rmcp_sequence, tvb, 2, 1, TRUE);

		tf = proto_tree_add_text(rmcp_tree, tvb, 3, 1, "Type: %s, Class: %s",
			 val_to_str(type, rmcp_type_vals, "Unknown (0x%02x)"),
			 class_str);

		field_tree = proto_item_add_subtree(tf, ett_rmcp_typeclass);

		proto_tree_add_item(field_tree, hf_rmcp_class, tvb, 3, 1, TRUE);
		proto_tree_add_item(field_tree, hf_rmcp_type, tvb, 3, 1, TRUE);
	}

	if (!type){ /* do not expect a data block for an ACK */

		next_tvb = tvb_new_subset(tvb, 4, -1, -1);

		if (!dissector_try_port(rmcp_dissector_table, class, next_tvb, pinfo,
			tree))
			call_dissector(data_handle, next_tvb, pinfo, tree);
	}

	return tvb_length(tvb);
}

void
proto_register_rmcp(void)
{
	static hf_register_info hf[] = {
		{ &hf_rmcp_version, {
			"Version", "rmcp.version",
			FT_UINT8, BASE_HEX, NULL, 0,
			"RMCP Version", HFILL }},
		{ &hf_rmcp_sequence, {
			"Sequence", "rmcp.sequence",
			FT_UINT8, BASE_HEX, NULL, 0,
			"RMCP Sequence", HFILL }},
		{ &hf_rmcp_class, {
			"Class", "rmcp.class",
			FT_UINT8, BASE_HEX,
			VALS(rmcp_class_vals), RMCP_CLASS_MASK,
			"RMCP Class", HFILL }},
		{ &hf_rmcp_type, {
			"Message Type", "rmcp.type",
			FT_UINT8, BASE_HEX,
			VALS(rmcp_type_vals), RMCP_TYPE_MASK,
			"RMCP Message Type", HFILL }},
	};
	static gint *ett[] = {
		&ett_rmcp,
		&ett_rmcp_typeclass,
	};

	proto_rmcp = proto_register_protocol(
		"Remote Management Control Protocol", "RMCP", "rmcp");

	proto_register_field_array(proto_rmcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	rmcp_dissector_table = register_dissector_table(
		"rmcp.class", "RMCP Class", FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_rmcp(void)
{
	dissector_handle_t rmcp_handle;

	data_handle = find_dissector("data");

	rmcp_handle = new_create_dissector_handle(dissect_rmcp, proto_rmcp);
	dissector_add("udp.port", UDP_PORT_RMCP, rmcp_handle);
	dissector_add("udp.port", UDP_PORT_RMCP_SECURE, rmcp_handle);
}
