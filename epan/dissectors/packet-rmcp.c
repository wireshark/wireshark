/* packet-rmcp.c
 * Routines for RMCP packet dissection
 *
 * Duncan Laurie <duncan@sun.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_rmcp(void);
void proto_register_rsp(void);
void proto_reg_handoff_rmcp(void);
void proto_reg_handoff_rsp(void);

/*
 * See
 *	http://www.dmtf.org/standards/standard_alert.php
 *      http://www.dmtf.org/standards/documents/ASF/DSP0136.pdf
 * (the ASF specification includes RMCP)
 */

static int proto_rmcp = -1;
static int hf_rmcp_version = -1;
static int hf_rmcp_reserved = -1;
static int hf_rmcp_sequence = -1;
static int hf_rmcp_class = -1;
static int hf_rmcp_type = -1;
static int hf_rmcp_trailer = -1;

static int proto_rsp = -1;
static int hf_rsp_session_id = -1;
static int hf_rsp_sequence = -1;

static gint ett_rmcp = -1;
static gint ett_rmcp_typeclass = -1;

static gint ett_rsp = -1;

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
dissect_rmcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree	*rmcp_tree = NULL, *field_tree;
	proto_item	*ti;
	tvbuff_t	*next_tvb;
	guint8		rmcp_class;
	const gchar	*class_str;
	guint8		type;
	guint		len;

	/*
	 * Check whether it's a known class value; if not, assume it's
	 * not RMCP.
	 */
	if (!tvb_bytes_exist(tvb, 3, 1))
		return 0;	/* class value byte not present */
	rmcp_class = tvb_get_guint8(tvb, 3);

	/* Get the normal/ack bit from the RMCP class */
	type = (rmcp_class & RMCP_TYPE_MASK) >> 7;
	rmcp_class &= RMCP_CLASS_MASK;

	class_str = try_val_to_str(rmcp_class, rmcp_class_vals);
	if (class_str == NULL)
		return 0;	/* unknown class value */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RMCP");
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s, Class: %s",
		     val_to_str(type, rmcp_type_vals, "Unknown (0x%02x)"),
		     class_str);

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_rmcp, tvb, 0, 4,
			 "Remote Management Control Protocol, Class: %s",
			 class_str);
		rmcp_tree = proto_item_add_subtree(ti, ett_rmcp);

		proto_tree_add_item(rmcp_tree, hf_rmcp_version, tvb, 0, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(rmcp_tree, hf_rmcp_reserved, tvb, 1, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(rmcp_tree, hf_rmcp_sequence, tvb, 2, 1, ENC_LITTLE_ENDIAN);

		field_tree = proto_tree_add_subtree_format(rmcp_tree, tvb, 3, 1,
			 ett_rmcp_typeclass, NULL, "Type: %s, Class: %s",
			 val_to_str(type, rmcp_type_vals, "Unknown (0x%02x)"),
			 class_str);

		proto_tree_add_item(field_tree, hf_rmcp_class, tvb, 3, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(field_tree, hf_rmcp_type, tvb, 3, 1, ENC_LITTLE_ENDIAN);
	}

	if (!type){ /* do not expect a data block for an ACK */

		next_tvb = tvb_new_subset_remaining(tvb, 4);

		if (!dissector_try_uint(rmcp_dissector_table, rmcp_class, next_tvb, pinfo,
			tree)) {
			len = call_data_dissector(next_tvb, pinfo, tree);
			if (len < tvb_reported_length(next_tvb)) {
				proto_tree_add_item(tree, hf_rmcp_trailer, tvb, 4 + len, -1, ENC_NA);
			}
		}
	}

	return tvb_captured_length(tvb);
}

static int
dissect_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree	*rsp_tree = NULL/*, *field_tree*/;
	proto_item	*ti/*, *tf*/;
	tvbuff_t	*next_tvb;
	int 		offset = 0;

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_rsp, tvb, offset, 8,
			 "RMCP Security-extension Protocol");
		rsp_tree = proto_item_add_subtree(ti, ett_rsp);

		proto_tree_add_item(rsp_tree, hf_rsp_session_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(rsp_tree, hf_rsp_sequence, tvb, offset, 4, ENC_BIG_ENDIAN);
		/*offset += 4;*/
	}

	/* XXX determination of RCMP message length needs to
	 * be done according to 3.2.3.3.3 of the specification.
	 * This is only valid for session ID equals 0
	 */
	next_tvb = tvb_new_subset_remaining(tvb, 8);
	dissect_rmcp(next_tvb, pinfo, tree, NULL);

	return tvb_captured_length(tvb);
}

void
proto_register_rmcp(void)
{
	static hf_register_info hf[] = {
		{ &hf_rmcp_version, {
			"Version", "rmcp.version",
			FT_UINT8, BASE_HEX, NULL, 0,
			"RMCP Version", HFILL }},
		{ &hf_rmcp_reserved, {
			"Reserved", "rmcp.version",
			FT_UINT8, BASE_HEX, NULL, 0,
			"RMCP Reserved", HFILL }},
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
		{ &hf_rmcp_trailer, {
			"RSP Trailer", "rmcp.trailer",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_rmcp,
		&ett_rmcp_typeclass
	};

	proto_rmcp = proto_register_protocol(
		"Remote Management Control Protocol", "RMCP", "rmcp");

	proto_register_field_array(proto_rmcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	rmcp_dissector_table = register_dissector_table(
		"rmcp.class", "RMCP Class", proto_rmcp, FT_UINT8, BASE_HEX);
}

void
proto_register_rsp(void)
{
	static hf_register_info hf[] = {
		{ &hf_rsp_session_id, {
			"Session ID", "rsp.session_id",
			FT_UINT32, BASE_HEX, NULL, 0,
			"RSP session ID", HFILL }},
		{ &hf_rsp_sequence, {
			"Sequence", "rsp.sequence",
			FT_UINT32, BASE_HEX, NULL, 0,
			"RSP sequence", HFILL }},
	};
	static gint *ett[] = {
		&ett_rsp
	};

	proto_rsp = proto_register_protocol(
		"RMCP Security-extensions Protocol", "RSP", "rsp");
	proto_register_field_array(proto_rsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rmcp(void)
{
	dissector_handle_t rmcp_handle;

	rmcp_handle = create_dissector_handle(dissect_rmcp, proto_rmcp);
	dissector_add_uint("udp.port", UDP_PORT_RMCP, rmcp_handle);
}

void
proto_reg_handoff_rsp(void)
{
	dissector_handle_t rsp_handle;

	rsp_handle = create_dissector_handle(dissect_rsp, proto_rsp);
	dissector_add_uint("udp.port", UDP_PORT_RMCP_SECURE, rsp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
