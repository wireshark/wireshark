/* packet-g723.c
 * Routines for G.723 dissection
 * Copyright 2005, Anders Broman <anders.broman[at]ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/rtp_pt.h>

void proto_reg_handoff_g723(void);
void proto_register_g723(void);

static dissector_handle_t g723_handle;

/* Initialize the protocol and registered fields */
static int proto_g723;
static int hf_g723_frame_size_and_codec;
static int hf_g723_lpc_B5_B0;

/* Initialize the subtree pointers */
static int ett_g723;


/*		 RFC 3551
	The least significant two bits of the first
	octet in the frame determine the frame size and codec type:
	 bits  content                      octets/frame
	 00    high-rate speech (6.3 kb/s)            24
	 01    low-rate speech  (5.3 kb/s)            20
	 10    SID frame                               4
	 11    reserved

 */
static const value_string g723_frame_size_and_codec_type_value[] = {
	{0,			"High-rate speech (6.3 kb/s)"},
	{1,			"Low-rate speech  (5.3 kb/s)"}, /* Not coded */
	{2,			"SID frame"},
	{3,			"Reserved"},
	{ 0,	NULL }
};


/* Dissection */
static int
dissect_g723(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	unsigned octet;

	proto_item *ti;
	proto_tree *g723_tree;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "G.723.1");
	if (tree) {
		ti = proto_tree_add_item(tree, proto_g723, tvb, 0, -1, ENC_NA);

		g723_tree = proto_item_add_subtree(ti, ett_g723);

		octet = tvb_get_guint8(tvb,offset);
		proto_tree_add_item(g723_tree, hf_g723_frame_size_and_codec, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(g723_tree, hf_g723_lpc_B5_B0, tvb, offset, 1, ENC_BIG_ENDIAN);

		if ((octet & 0x1) == 1 ) /* Low rate */
			return tvb_captured_length(tvb);
	}/* if tree */

	return tvb_captured_length(tvb);
}

void
proto_reg_handoff_g723(void)
{
	dissector_add_uint("rtp.pt", PT_G723, g723_handle);

}

void
proto_register_g723(void)
{


	static hf_register_info hf[] = {
		{ &hf_g723_frame_size_and_codec,
			{ "Frame size and codec type", "g723.frame_size_and_codec",
			FT_UINT8, BASE_HEX, VALS(g723_frame_size_and_codec_type_value), 0x03,
			"RATEFLAG_B0", HFILL }
		},
		{ &hf_g723_lpc_B5_B0,
			{ "LPC_B5...LPC_B0",           "g723.lpc.b5b0",
			FT_UINT8, BASE_HEX, NULL, 0xfc,
			NULL, HFILL }
		},

	};

	static int *ett[] = {
		&ett_g723,
	};

	proto_g723 = proto_register_protocol("G.723","G.723", "g723");

	proto_register_field_array(proto_g723, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	g723_handle = register_dissector("g723", dissect_g723, proto_g723);
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
