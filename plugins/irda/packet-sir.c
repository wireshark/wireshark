/** Decode IrDA Serial Infrared (SIR) wrapped packets.
 * @author Shaun Jackman <sjackman@debian.org>
 * @copyright Copyright 2004 Shaun Jackman
 * @license GPL
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/crc16-tvb.h>

/** Serial infrared port. */
#define TCP_PORT_SIR 6417


/** Beginning of frame. */
#define SIR_BOF 0xc0

/** End of frame. */
#define SIR_EOF 0xc1

/** Control escape. */
#define SIR_CE 0x7d

/** Escapes this character. */
#define SIR_ESCAPE(x) ((x)^0x20)

void proto_reg_handoff_irsir(void);
void proto_register_irsir(void);

/** Protocol handles. */
static dissector_handle_t irda_handle;

/** Protocol fields. */
static int proto_sir = -1;
static int ett_sir = -1;
static int hf_sir_bof = -1;
/* static int hf_sir_ce = -1; */
static int hf_sir_eof = -1;
static int hf_sir_fcs = -1;
static int hf_sir_fcs_status = -1;
static int hf_sir_length = -1;
static int hf_sir_preamble = -1;

/* Copied and renamed from proto.c because global value_strings don't work for plugins */
static const value_string plugin_proto_checksum_vals[] = {
	{ PROTO_CHECKSUM_E_BAD,        "Bad"  },
	{ PROTO_CHECKSUM_E_GOOD,       "Good" },
	{ PROTO_CHECKSUM_E_UNVERIFIED, "Unverified" },
	{ PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },

	{ 0,        NULL }
};


/** Unescapes the data. */
static tvbuff_t *
unescape_data(tvbuff_t *tvb, packet_info *pinfo)
{
	if (tvb_find_guint8(tvb, 0, -1, SIR_CE) == -1) {
		return tvb;
	} else {
		guint length = tvb_captured_length(tvb);
		guint offset;
		guint8 *data = (guint8 *)g_malloc(length);
		guint8 *dst = data;
		tvbuff_t *next_tvb;

		for (offset = 0; offset < length; )
		{
			guint8 c = tvb_get_guint8(tvb, offset++);
			if ((c == SIR_CE) && (offset < length))
				c = SIR_ESCAPE(tvb_get_guint8(tvb, offset++));
			*dst++ = c;
		}

		next_tvb = tvb_new_child_real_data(tvb, data, (guint) (dst-data), (guint) (dst-data));
		tvb_set_free_cb(next_tvb, g_free);
		add_new_data_source(pinfo, next_tvb, "Unescaped SIR");
		return next_tvb;
	}
}


/** Checksums the data. */
static tvbuff_t *
checksum_data(tvbuff_t *tvb, proto_tree *tree)
{
	int len = tvb_reported_length(tvb) - 2;
	if (len < 0)
		return tvb;

	proto_tree_add_checksum(tree, tvb, len, hf_sir_fcs, hf_sir_fcs_status, NULL, NULL, crc16_ccitt_tvb(tvb, len),
								ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);

	return tvb_new_subset_length(tvb, 0, len);
}


/** Dissects an SIR packet. */
static int
dissect_sir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root, void* data _U_)
{
	gint offset = 0;
	gint bof_offset;
	gint eof_offset;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		bof_offset = tvb_find_guint8(tvb, offset, -1, SIR_BOF);
		eof_offset = (bof_offset == -1) ? -1 :
			tvb_find_guint8(tvb, bof_offset, -1, SIR_EOF);

		if (bof_offset == -1 || eof_offset == -1) {
			if (pinfo->can_desegment) {
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = 1;
			}
			return tvb_captured_length(tvb);
		} else {
			guint preamble_len = bof_offset - offset;
			gint data_offset = bof_offset + 1;
			tvbuff_t* next_tvb = tvb_new_subset(tvb,
				data_offset, eof_offset - data_offset, -1);
			next_tvb = unescape_data(next_tvb, pinfo);
			if (root) {
				guint data_len = tvb_reported_length(next_tvb) < 2 ? 0 :
					tvb_reported_length(next_tvb) - 2;
				proto_tree* ti = proto_tree_add_protocol_format(root,
						proto_sir, tvb, offset, eof_offset - offset + 1,
						"Serial Infrared, Len: %d", data_len);
				proto_tree* tree = proto_item_add_subtree(ti, ett_sir);
				if (preamble_len > 0)
					proto_tree_add_item(tree, hf_sir_preamble, tvb,
							offset, preamble_len, ENC_NA);
				proto_tree_add_item(tree, hf_sir_bof, tvb,
						bof_offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_uint(tree, hf_sir_length,
						next_tvb, 0, data_len, data_len);
				next_tvb = checksum_data(next_tvb, tree);
				proto_tree_add_item(tree, hf_sir_eof, tvb,
						eof_offset, 1, ENC_BIG_ENDIAN);
			} else {
				next_tvb = checksum_data(next_tvb, NULL);
			}
			call_dissector(irda_handle, next_tvb, pinfo, root);
		}
		offset = eof_offset + 1;
	}
    return tvb_captured_length(tvb);
}


/** Registers this dissector with the parent dissector. */
void
proto_reg_handoff_irsir(void)
{
	dissector_add_uint("tcp.port", TCP_PORT_SIR, find_dissector("sir"));

	irda_handle = find_dissector("irda");
}


/** Initializes this protocol. */
void
proto_register_irsir(void)
{
	static gint* ett[] = { &ett_sir };

	static hf_register_info hf_sir[] = {
		{ &hf_sir_bof,
			{ "Beginning of frame", "sir.bof",
				FT_UINT8, BASE_HEX, NULL, 0,
				NULL, HFILL }},
#if 0
		{ &hf_sir_ce,
			{ "Command escape", "sir.ce",
				FT_UINT8, BASE_HEX, NULL, 0,
				NULL, HFILL }},
#endif
		{ &hf_sir_eof,
			{ "End of frame", "sir.eof",
				FT_UINT8, BASE_HEX, NULL, 0,
				NULL, HFILL }},
		{ &hf_sir_fcs,
			{ "Frame check sequence", "sir.fcs",
				FT_UINT16, BASE_HEX, NULL, 0,
				NULL, HFILL }},
		{ &hf_sir_fcs_status,
			{ "Frame check sequence Status", "sir.fcs.status",
				FT_UINT8, BASE_NONE, VALS(plugin_proto_checksum_vals), 0x0,
				NULL, HFILL }},
		{ &hf_sir_length,
			{ "Length", "sir.length",
				FT_UINT16, BASE_DEC, NULL, 0,
				NULL, HFILL }},
		{ &hf_sir_preamble,
			{ "Preamble", "sir.preamble",
				FT_BYTES, BASE_NONE, NULL, 0,
				NULL, HFILL }}
	};

	proto_sir = proto_register_protocol(
			"Serial Infrared", "SIR", "sir");
	register_dissector("sir", dissect_sir, proto_sir);
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(
			proto_sir, hf_sir, array_length(hf_sir));
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
