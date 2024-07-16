/** Decode IrDA Serial Infrared (SIR) wrapped packets.
 * @author Shaun Jackman <sjackman@debian.org>
 * @copyright Copyright 2004 Shaun Jackman
 * @license GPL
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/crc16-tvb.h>

/** Serial infrared port. */
#define TCP_PORT_SIR 6417 /* Not IANA registered */


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
static dissector_handle_t sir_handle;

/** Protocol fields. */
static int proto_sir;
static int ett_sir;
static int hf_sir_bof;
/* static int hf_sir_ce; */
static int hf_sir_eof;
static int hf_sir_fcs;
static int hf_sir_fcs_status;
static int hf_sir_length;
static int hf_sir_preamble;

static expert_field ei_sir_fcs;

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
		unsigned length = tvb_captured_length(tvb);
		unsigned offset;
		uint8_t *data = (uint8_t *)wmem_alloc(pinfo->pool, length);
		uint8_t *dst = data;
		tvbuff_t *next_tvb;

		for (offset = 0; offset < length; )
		{
			uint8_t c = tvb_get_uint8(tvb, offset++);
			if ((c == SIR_CE) && (offset < length))
				c = SIR_ESCAPE(tvb_get_uint8(tvb, offset++));
			*dst++ = c;
		}

		next_tvb = tvb_new_child_real_data(tvb, data, (unsigned) (dst-data), (unsigned) (dst-data));
		add_new_data_source(pinfo, next_tvb, "Unescaped SIR");
		return next_tvb;
	}
}


/** Checksums the data. */
static tvbuff_t *
checksum_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int len = tvb_reported_length(tvb) - 2;
	if (len < 0)
		return tvb;

	proto_tree_add_checksum(tree, tvb, len, hf_sir_fcs, hf_sir_fcs_status, &ei_sir_fcs, pinfo, crc16_ccitt_tvb(tvb, len),
								ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);

	return tvb_new_subset_length(tvb, 0, len);
}


/** Dissects an SIR packet. */
static int
dissect_sir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root, void* data _U_)
{
	int offset = 0;
	int bof_offset;
	int eof_offset;

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
			unsigned preamble_len = bof_offset - offset;
			int data_offset = bof_offset + 1;
			tvbuff_t* next_tvb = tvb_new_subset_length_caplen(tvb,
				data_offset, eof_offset - data_offset, -1);
			next_tvb = unescape_data(next_tvb, pinfo);
			if (root) {
				unsigned data_len = tvb_reported_length(next_tvb) < 2 ? 0 :
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
				next_tvb = checksum_data(next_tvb, pinfo, tree);
				proto_tree_add_item(tree, hf_sir_eof, tvb,
						eof_offset, 1, ENC_BIG_ENDIAN);
			} else {
				next_tvb = checksum_data(next_tvb, pinfo, NULL);
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
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_SIR, sir_handle);

	irda_handle = find_dissector("irda");
}


/** Initializes this protocol. */
void
proto_register_irsir(void)
{
	static int* ett[] = { &ett_sir };

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

	static ei_register_info ei[] = {
		{ &ei_sir_fcs, { "sir.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
	};

	expert_module_t* expert_sir;

	proto_sir = proto_register_protocol("Serial Infrared", "SIR", "sir");
	sir_handle = register_dissector("sir", dissect_sir, proto_sir);
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array( proto_sir, hf_sir, array_length(hf_sir));
	expert_sir = expert_register_protocol(proto_sir);
	expert_register_field_array(expert_sir, ei, array_length(ei));
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
