/* packet-isdn.c
 * Routines for ISDN packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <epan/conversation.h>

void proto_register_isdn(void);
void proto_reg_handoff_isdn(void);

static int proto_isdn = -1;
static int hf_isdn_direction = -1;
static int hf_isdn_channel = -1;

static gint ett_isdn = -1;

static dissector_handle_t isdn_handle;

/*
 * Protocol used on the D channel.
 */
#define DCHANNEL_LAPD	0	/* LAPD */
#define DCHANNEL_DPNSS	1	/* DPNSS link layer */

static const enum_val_t dchannel_protocol_options[] = {
	{ "lapd",  "LAPD",  DCHANNEL_LAPD },
	{ "DPNSS", "DPNSS", DCHANNEL_DPNSS },
	{ NULL, NULL, 0 }
};

static int dchannel_protocol = DCHANNEL_LAPD;

static dissector_handle_t lapd_phdr_handle;
static dissector_handle_t dpnss_link_handle;
static dissector_handle_t ppp_hdlc_handle;
static dissector_handle_t v120_handle;

static const true_false_string isdn_direction_tfs = {
	"User->Network",
	"Network->User"
};

static const value_string channel_vals[] = {
	{  0,	"D" },
	{  1,	"B1" },
	{  2,	"B2" },
	{  3,	"B3" },
	{  4,	"B4" },
	{  5,	"B5" },
	{  6,	"B6" },
	{  7,	"B7" },
	{  8,	"B8" },
	{  9,	"B9" },
	{ 10,	"B10" },
	{ 11,	"B11" },
	{ 12,	"B12" },
	{ 13,	"B13" },
	{ 14,	"B14" },
	{ 15,	"B15" },
	{ 16,	"B16" },
	{ 17,	"B17" },
	{ 18,	"B18" },
	{ 19,	"B19" },
	{ 20,	"B20" },
	{ 21,	"B21" },
	{ 22,	"B22" },
	{ 23,	"B23" },
	{ 24,	"B24" },
	{ 25,	"B25" },
	{ 26,	"B26" },
	{ 27,	"B27" },
	{ 28,	"B28" },
	{ 29,	"B29" },
	{ 30,	"B30" },
	{ 0,	NULL }
};

static int
dissect_isdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct isdn_phdr *isdn = (struct isdn_phdr *)data;
	proto_tree *isdn_tree;
	proto_item *ti;
	static const guint8 v120_sabme[3] = { 0x08, 0x01, 0x7F };
	static const guint8 ppp[2] = { 0xFF, 0x03 };
	conversation_t *conv;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISDN");

	if (isdn->uton) {
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, "Network");
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "User");
		pinfo->p2p_dir = P2P_DIR_SENT;
	} else {
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, "User");
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "Network");
		pinfo->p2p_dir = P2P_DIR_RECV;
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_isdn, tvb, 0, 0, ENC_NA);
		isdn_tree = proto_item_add_subtree(ti, ett_isdn);

		proto_tree_add_boolean(isdn_tree, hf_isdn_direction, tvb, 0, 0,
		     isdn->uton);

		proto_tree_add_uint(isdn_tree, hf_isdn_channel, tvb, 0, 0,
		    isdn->channel);
	}

	/*
	 * Set up a circuit for this channel, and assign it a dissector.
	 */
	conv = find_or_create_conversation_by_id(pinfo, CONVERSATION_ISDN,
	    isdn->channel);

	if (conversation_get_dissector(conv, 0) == NULL) {
		/*
		 * We don't yet know the type of traffic on the circuit.
		 */
		switch (isdn->channel) {

		case 0:
			/*
			 * D-channel.  Dissect it with whatever protocol
			 * the user specified, or the default of LAPD if
			 * they didn't specify one.
			 */
			switch (dchannel_protocol) {

			case DCHANNEL_LAPD:
				conversation_set_dissector(conv, lapd_phdr_handle);
				break;

			case DCHANNEL_DPNSS:
				conversation_set_dissector(conv,
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
				conversation_set_dissector(conv, v120_handle);
			} else if (tvb_memeql(tvb, 0, ppp, 2) == 0) {
				/*
				 * We assume this is PPP.
				 */
				conversation_set_dissector(conv, ppp_hdlc_handle);
			}
			break;
		}
	}

	if (!try_conversation_dissector_by_id(CONVERSATION_ISDN, isdn->channel,
		tvb, pinfo, tree, data))
		call_data_dissector(tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

void
proto_register_isdn(void)
{
	static hf_register_info hf[] = {
		{ &hf_isdn_direction,
		{ "Direction", "isdn.direction", FT_BOOLEAN, BASE_NONE,
		  TFS(&isdn_direction_tfs), 0x0, NULL, HFILL }},

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

	isdn_handle = register_dissector("isdn", dissect_isdn, proto_isdn);
}

void
proto_reg_handoff_isdn(void)
{
	/*
	 * Get handles for the LAPD-with-pseudoheader, DPNSS link-layer,
	 * PPP, and V.120 dissectors.
	 */
	lapd_phdr_handle = find_dissector("lapd-phdr");
	dpnss_link_handle = find_dissector("dpnss_link");
	ppp_hdlc_handle = find_dissector("ppp_hdlc");
	v120_handle = find_dissector("v120");

	dissector_add_uint("wtap_encap", WTAP_ENCAP_ISDN, isdn_handle);
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
