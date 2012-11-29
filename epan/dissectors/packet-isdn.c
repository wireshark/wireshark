/* packet-isdn.c
 * Routines for ISDN packet disassembly
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/circuit.h>

static int proto_isdn = -1;
static int hf_isdn_channel = -1;

static gint ett_isdn = -1;

/*
 * Protocol used on the D channel.
 */
#define DCHANNEL_LAPD	0	/* LAPD */
#define DCHANNEL_DPNSS	1	/* DPNSS link layer */

static const enum_val_t dchannel_protocol_options[] = {
    { "lapd", "LAPD", DCHANNEL_LAPD },
    { "DPNSS", "DPNSS", DCHANNEL_DPNSS },
    { NULL, NULL, 0 }
};

static int dchannel_protocol = DCHANNEL_LAPD;

static dissector_handle_t lapd_handle;
static dissector_handle_t dpnss_link_handle;
static dissector_handle_t ppp_hdlc_handle;
static dissector_handle_t v120_handle;
static dissector_handle_t data_handle;

static const value_string channel_vals[] = {
	{ 0,	"D" },
	{ 1,	"B1" },
	{ 2,	"B2" },
	{ 3,	"B3" },
	{ 4,	"B4" },
	{ 5,	"B5" },
	{ 6,	"B6" },
	{ 7,	"B7" },
	{ 8,	"B8" },
	{ 9,	"B9" },
	{ 10,	"B10" },
	{ 11,	"B11" },
	{ 12,	"B12" },
	{ 13,	"B13" },
	{ 14,	"B14" },
	{ 15,	"B15" },
	{ 16,	"B16" },
	{ 17,	"B17" },
	{ 18,	"B19" },
	{ 19,	"B19" },
	{ 20,	"B20" },
	{ 21,	"B21" },
	{ 22,	"B22" },
	{ 23,	"B23" },
	{ 24,	"B24" },
	{ 25,	"B25" },
	{ 26,	"B26" },
	{ 27,	"B27" },
	{ 28,	"B29" },
	{ 29,	"B29" },
	{ 30,	"B30" },
	{ 0,	NULL }
};

static void
dissect_isdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *isdn_tree;
	proto_item *ti;
	static const guint8 v120_sabme[3] = { 0x08, 0x01, 0x7F };
	static const guint8 ppp[2] = { 0xFF, 0x03 };
	circuit_t *circuit;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISDN");

	if (pinfo->pseudo_header->isdn.uton) {
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, "Network");
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "User");
	} else {
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, "User");
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "Network");
	}

	pinfo->ctype = CT_ISDN;
	pinfo->circuit_id = pinfo->pseudo_header->isdn.channel;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_isdn, tvb, 0, 0, ENC_NA);
		isdn_tree = proto_item_add_subtree(ti, ett_isdn);

		proto_tree_add_uint(isdn_tree, hf_isdn_channel, tvb, 0, 0,
		    pinfo->pseudo_header->isdn.channel);
	}

	/*
	 * Set up a circuit for this channel, and assign it a dissector.
	 */
	circuit = find_circuit(pinfo->ctype, pinfo->circuit_id, pinfo->fd->num);
	if (circuit == NULL)
		circuit = circuit_new(pinfo->ctype, pinfo->circuit_id,
		    pinfo->fd->num);

	if (circuit_get_dissector(circuit) == NULL) {
		/*
		 * We don't yet know the type of traffic on the circuit.
		 */
		switch (pinfo->pseudo_header->isdn.channel) {

		case 0:
			/*
			 * D-channel.  Dissect it with whatever protocol
			 * the user specified, or the default of LAPD if
			 * they didn't specify one.
			 */
			switch (dchannel_protocol) {

			case DCHANNEL_LAPD:
				circuit_set_dissector(circuit, lapd_handle);
				break;

			case DCHANNEL_DPNSS:
				circuit_set_dissector(circuit,
				    dpnss_link_handle);
				break;
			}
			break;

		default:
			/*
			 * B-channel.
			 *
			 * We don't know yet whether the datastream is
			 * V.120 or not; this heuristic tries to figure
			 * that out.
			 *
			 * We cannot glean this from the Q.931 SETUP message,
			 * because no commercial V.120 implementation I've
			 * seen actually sets the V.120 protocol discriminator
			 * (that, or I'm misreading the spec badly).
			 *
			 * TODO: close the circuit after a close on the B
			 * channel is detected.
			 *
			 *	-Bert Driehuis (from the i4btrace reader;
			 *	 this heuristic was moved from there to
			 *	 here)
			 *
			 * XXX - I don't know that one can guarantee that
			 * the SABME will appear in the first frame on
			 * the channels, so we probably can't just say
			 * "it must be PPP" if we don't immediately see
			 * the V.120 SABME frame, so we do so only if
			 * we see the 0xFF 0x03.  Unfortunately, that
			 * won't do the right thing if the PPP-over-HDLC
			 * headers aren't being used....
			 */
			if (tvb_memeql(tvb, 0, v120_sabme, 3) == 0) {
				/*
				 * We assume this is V.120.
				 */
				circuit_set_dissector(circuit, v120_handle);
			} else if (tvb_memeql(tvb, 0, ppp, 2) == 0) {
				/*
				 * We assume this is PPP.
				 */
				circuit_set_dissector(circuit, ppp_hdlc_handle);
			}
			break;
		}
	}

	if (!try_circuit_dissector(pinfo->ctype, pinfo->circuit_id,
	    pinfo->fd->num, tvb, pinfo, tree))
		call_dissector(data_handle, tvb, pinfo, tree);
}

void
proto_register_isdn(void)
{
	static hf_register_info hf[] = {
		{ &hf_isdn_channel,
		{ "Channel",	"isdn.channel", FT_UINT8, BASE_DEC,
		  VALS(channel_vals), 0x0, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_isdn,
	};
	module_t *isdn_module;

	proto_isdn = proto_register_protocol("ISDN", "ISDN", "isdn");
	proto_register_field_array(proto_isdn, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	isdn_module = prefs_register_protocol(proto_isdn, NULL);

	prefs_register_enum_preference(isdn_module, "dchannel_protocol",
	    "D-channel protocol",
	    "The protocol running on the D channel",
	    &dchannel_protocol, dchannel_protocol_options, FALSE);
}

void
proto_reg_handoff_isdn(void)
{
	dissector_handle_t isdn_handle;

	/*
	 * Get handles for the LAPD, DPNSS link-layer, PPP, and V.120
	 * dissectors.
	 */
	lapd_handle = find_dissector("lapd");
	dpnss_link_handle = find_dissector("dpnss_link");
	ppp_hdlc_handle = find_dissector("ppp_hdlc");
	v120_handle = find_dissector("v120");
	data_handle = find_dissector("data");

	isdn_handle = create_dissector_handle(dissect_isdn, proto_isdn);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_ISDN, isdn_handle);
}
