/* packet-chargen.c
 * Routines for chargen packet dissection
 * Copyright 2014, Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Chargen specs taken from RFC 864
 * https://tools.ietf.org/html/rfc864
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#define CHARGEN_PORT_UDP 19
#define CHARGEN_PORT_TCP 19

void proto_register_chargen(void);
void proto_reg_handoff_chargen(void);

static dissector_handle_t chargen_handle;

static int proto_chargen;

static int hf_chargen_data;

static int ett_chargen;

/* dissect_chargen - dissects chargen packet data
 * tvb - tvbuff for packet data (IN)
 * pinfo - packet info
 * proto_tree - resolved protocol tree
 */
static int
dissect_chargen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* dissector_data _U_)
{
	proto_tree* chargen_tree;
	proto_item* ti;
	uint8_t* data;
	uint32_t len;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Chargen");
	col_set_str(pinfo->cinfo, COL_INFO, "Chargen");

	ti = proto_tree_add_item(tree, proto_chargen, tvb, 0, -1, ENC_NA);
	chargen_tree = proto_item_add_subtree(ti, ett_chargen);

	len = tvb_reported_length(tvb);
	data = tvb_get_string_enc(pinfo->pool, tvb, 0, len, ENC_ASCII);

	proto_tree_add_string_format(chargen_tree, hf_chargen_data, tvb, 0,
		len, "Data", "Data (%u): %s", len, data);

/*	proto_tree_add_item(chargen_tree, hf_chargen_data, tvb, 0, -1, ENC_ASCII); */
	return tvb_captured_length(tvb);
}

void
proto_register_chargen(void)
{
	static hf_register_info hf[] = {
		{ &hf_chargen_data, {
			"Data", "chargen.data", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }}
		};

	static int *ett[] = {
		&ett_chargen,
	};

	proto_chargen = proto_register_protocol("Character Generator Protocol", "Chargen",
	    "chargen");
	proto_register_field_array(proto_chargen, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	chargen_handle = register_dissector("chargen", dissect_chargen, proto_chargen);
}

void
proto_reg_handoff_chargen(void)
{
	dissector_add_uint_with_preference("udp.port", CHARGEN_PORT_UDP, chargen_handle);
	dissector_add_uint_with_preference("tcp.port", CHARGEN_PORT_TCP, chargen_handle);
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
