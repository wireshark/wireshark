/* packet-interlink.c
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_interlink(void);
void proto_reg_handoff_interlink(void);

/*
 * No public information available.
 */

static int proto_interlink = -1;

static int hf_interlink_id = -1;
static int hf_interlink_version = -1;
static int hf_interlink_cmd = -1;
static int hf_interlink_seq = -1;
static int hf_interlink_flags = -1;
static int hf_interlink_flags_req_ack = -1;
static int hf_interlink_flags_inc_ack_port = -1;
static int hf_interlink_block_type = -1;
static int hf_interlink_block_version = -1;
static int hf_interlink_block_length = -1;

static gint ett_interlink = -1;
static gint ett_interlink_header = -1;
static gint ett_interlink_flags = -1;
static gint ett_interlink_block = -1;

static dissector_handle_t data_handle;
static dissector_table_t subdissector_table;

static const true_false_string flags_set_notset = {
	"Set", "Not set"
};

static const value_string names_cmd[] = {
	{ 1, "Data" },
	{ 2, "Ack" },
	{ 0, NULL }
};


static int
dissect_interlink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int		offset = 0;
	proto_tree	*il_tree;
	proto_item	*il_item;
	proto_tree	*ilh_tree = NULL;
	proto_tree	*ilb_tree = NULL;
	guint8		ilb_type;
	guint8		ilb_version;
	guint16		type_version = 0;
	dissector_handle_t	handle;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "INTERLINK");
	col_clear(pinfo->cinfo, COL_INFO);

	il_item = proto_tree_add_item(tree, proto_interlink,
							tvb, 0, 16, ENC_NA);
	il_tree = proto_item_add_subtree(il_item, ett_interlink);

	ilh_tree = proto_tree_add_subtree(il_tree, tvb, 0, 12, ett_interlink_header, NULL, "Interlink Header");

	if (ilh_tree) {
		proto_tree_add_item(ilh_tree, hf_interlink_id, tvb, offset, 4, ENC_ASCII|ENC_NA);
		offset += 4;
		proto_tree_add_item(ilh_tree, hf_interlink_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(ilh_tree, hf_interlink_cmd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(ilh_tree, hf_interlink_seq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	} else {
		offset += 10;
	}

	if (ilh_tree) {
		static const int * flags[] = {
			&hf_interlink_flags_req_ack,
			&hf_interlink_flags_inc_ack_port,
			NULL
		};

		proto_tree_add_bitmask(ilh_tree, tvb, offset, hf_interlink_flags, ett_interlink_flags, flags, ENC_LITTLE_ENDIAN);

	}
	offset += 2;

	ilb_tree = proto_tree_add_subtree(il_tree, tvb, offset, 4, ett_interlink_block, NULL, "Block Header");

	ilb_type = tvb_get_guint8(tvb, offset);
	ilb_version = tvb_get_guint8(tvb, offset + 1);
	type_version = ilb_type << 8 | ilb_version;
	col_append_fstr(pinfo->cinfo, COL_INFO, "Type: %d, Version: %d",
		ilb_type, ilb_version);

	if (ilb_tree) {
		proto_tree_add_item(ilb_tree, hf_interlink_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(ilb_tree, hf_interlink_block_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(ilb_tree, hf_interlink_block_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	} else {
		offset += 4;
	}

	/* Generate a new tvb for the rest. */
	next_tvb = tvb_new_subset_remaining(tvb, offset);

	/* Probably a sub-dissector exists for this type/version combination. */
	handle = dissector_get_uint_handle(subdissector_table, type_version);

	/* Without a proper sub-dissector, we use "data". */
	if (handle == NULL) handle = data_handle;

	/* Call the sub-dissector. */
	call_dissector(handle, next_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}


static gboolean
dissect_interlink_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if (!tvb_bytes_exist(tvb, 0, 4)) {
		return FALSE;
	}
	if (
		tvb_get_guint8(tvb,0) != 'I' ||
		tvb_get_guint8(tvb,1) != 'L' ||
		tvb_get_guint8(tvb,2) != 'N' ||
		tvb_get_guint8(tvb,3) != 'K'
	)
		return FALSE;

	dissect_interlink(tvb, pinfo, tree, data);
	return TRUE;
}


void
proto_register_interlink(void)
{
	static hf_register_info hf[] = {
		{ &hf_interlink_id, {
			"Magic ID", "interlink.id", FT_STRING,
			BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_interlink_version, {
			"Version", "interlink.version", FT_UINT16,
			BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_interlink_cmd, {
			"Command", "interlink.cmd", FT_UINT16,
			BASE_DEC, VALS(names_cmd), 0, NULL, HFILL }},
		{ &hf_interlink_seq, {
			"Sequence", "interlink.seq", FT_UINT16,
			BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_interlink_flags, {
			"Flags", "interlink.flags", FT_UINT16,
			BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_interlink_flags_req_ack, {
			"REQ_ACK", "interlink.flags.req_ack", FT_BOOLEAN,
			16, TFS(&flags_set_notset), 0x01, NULL, HFILL }},
		{ &hf_interlink_flags_inc_ack_port, {
			"INC_ACK_PORT", "interlink.flags.inc_ack_port", FT_BOOLEAN,
			16, TFS(&flags_set_notset), 0x02, NULL, HFILL }},
		{ &hf_interlink_block_type, {
			"Type", "interlink.type", FT_UINT8,
			BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_interlink_block_version, {
			"Version", "interlink.block_version", FT_UINT8,
			BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_interlink_block_length, {
			"Length", "interlink.length", FT_UINT16,
			BASE_DEC, NULL, 0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_interlink,
		&ett_interlink_header,
		&ett_interlink_flags,
		&ett_interlink_block,
	};

	proto_interlink = proto_register_protocol("Interlink Protocol",
							"Interlink",
							"interlink");
	proto_register_field_array(proto_interlink, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("interlink", dissect_interlink, proto_interlink);

	/* Probably someone will write sub-dissectors. You can never know. */
	subdissector_table = register_dissector_table("interlink.type_version",
		"Interlink type_version", proto_interlink, FT_UINT16, BASE_HEX);
}


void
proto_reg_handoff_interlink(void)
{
	dissector_handle_t interlink_handle;
	interlink_handle = find_dissector("interlink");

	/* Allow "Decode As" with any UDP packet. */
	dissector_add_for_decode_as("udp.port", interlink_handle);

	/* Add our heuristic packet finder. */
	heur_dissector_add("udp", dissect_interlink_heur, "Interlink over UDP", "interlink_udp", proto_interlink, HEURISTIC_ENABLE);

	data_handle = find_dissector("data");
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
