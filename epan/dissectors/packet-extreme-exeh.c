/* packet-extreme-internal-eth.c
 * Routines for the disassembly of Extreme Networks internal
 * Ethernet capture headers
 *
 * Copyright 2021 Joerg Mayer (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * It is possible to create internal capture in EXOS with
 * debug packet capture ...
 *
 * List of interfaces on all VRs:
 * run script shell.py cat /proc/net/dev
 * on older software the following should work as well:
 * debug packet capture on cmd-args "-D -1"
 *
 * See:
 *	https://extremeportal.force.com/ExtrArticleDetail?an=000079573
 *	https://extremeportal.force.com/ExtrArticleDetail?an=000082238
 *	https://extremeportal.force.com/ExtrArticleDetail?an=000079220
 *
 * This capture begins with an internal header (maybe containing some HiGig variant?),
 * followed by the "original" Ethernet frame.
 */

/*
 * TODO
 * 00 - 01: Unknown
 *          always zero for incoming(?)
 *          often non-zero for outgoing
 * 10 - 23: Unknown (traffic properties?)
 * 28 - 29: Unknown
 *          always zero(?)
 * 32 - 33: Unknown
 *          always zero(?)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>

void proto_register_exeh(void);
void proto_reg_handoff_exeh(void);

static dissector_handle_t exeh_handle;

static dissector_handle_t ethnofcs_handle;

static int proto_exeh;
/* EXEH data */
static int hf_exeh_unknown_00_01;
static int hf_exeh_module1;
static int hf_exeh_port1;
static int hf_exeh_module2; /* m2 + p2 always zero for outgoing(?) */
static int hf_exeh_port2;
static int hf_exeh_unknown_10_16;
static int hf_exeh_unknown_17_0xfd;
static int hf_exeh_unknown_17_0x02;
static int hf_exeh_unknown_18_21;
static int hf_exeh_unknown_22_23;
static int hf_exeh_incoming_framesource;
static int hf_exeh_outgoing_framesource;
static int hf_exeh_vlan;
static int hf_exeh_unknown_28_29;
static int hf_exeh_dir;
static int hf_exeh_unknown_32_33;
static int hf_exeh_etype;
static int hf_exeh_etypelen;
static int hf_exeh_etypedata;

static expert_field ei_exeh_unexpected_value;
static expert_field ei_exeh_unequal_ports;
static expert_field ei_exeh_incoming_framesource;
static expert_field ei_exeh_outgoing_framesource;

static int ett_exeh;

#define PROTO_SHORT_NAME "EXEH"
#define PROTO_LONG_NAME "EXtreme extra Eth Header"

static const value_string exeh_direction_vals[] = {
	{0x07, "Incoming"},
	{0xff, "Outgoing"},

	{0, NULL},
};

static const value_string exeh_outgoing_vlanid_vals[] = {
	{0x0000, "No tag or VLAN ID = 0"},
	{0x000f, "Has VLAN ID"},

	{0, NULL},
};

static const value_string exeh_incoming_framesource_vals[] = {
	{0x0000, "N/A"},

	{0, NULL},
};

static const value_string exeh_outgoing_framesource_vals[] = {
	{0x0000, "CPU"},
	{0x4248, "Broadcom Hardware"},

	{0, NULL},
};


static int
dissect_exeh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *exeh_tree;
	uint32_t offset = 0;
	uint32_t etype, module1, port1, module2, port2, direction, framesource;
	int32_t databytes;
	tvbuff_t *frame_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME ":");

	ti = proto_tree_add_item(tree, proto_exeh, tvb, offset, -1,
				 ENC_NA);
	exeh_tree = proto_item_add_subtree(ti, ett_exeh);

	direction = tvb_get_ntohs(tvb, 30);
	proto_tree_add_item(exeh_tree, hf_exeh_unknown_00_01, tvb, offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item_ret_uint(exeh_tree, hf_exeh_module1, tvb, offset, 2, ENC_BIG_ENDIAN, &module1);
	offset += 2;
	proto_tree_add_item_ret_uint(exeh_tree, hf_exeh_port1, tvb, offset, 2, ENC_BIG_ENDIAN, &port1);
	offset += 2;
	proto_tree_add_item_ret_uint(exeh_tree, hf_exeh_module2, tvb, offset, 2, ENC_BIG_ENDIAN, &module2);
	offset += 2;
	ti = proto_tree_add_item_ret_uint(exeh_tree, hf_exeh_port2, tvb, offset, 2, ENC_BIG_ENDIAN, &port2);
	if ( !(direction == 255 && module2 == 0) && (module1 != module2 || port1 != port2) )
			expert_add_info(pinfo, ti, &ei_exeh_unequal_ports);
	offset += 2;
	proto_tree_add_item(exeh_tree, hf_exeh_unknown_10_16, tvb, offset, 7, ENC_NA);
	offset += 7;
	proto_tree_add_item(exeh_tree, hf_exeh_unknown_17_0xfd, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(exeh_tree, hf_exeh_unknown_17_0x02, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(exeh_tree, hf_exeh_unknown_18_21, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(exeh_tree, hf_exeh_unknown_22_23, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	if ( direction == 7 ) {
		ti = proto_tree_add_item_ret_uint(exeh_tree, hf_exeh_incoming_framesource, tvb, offset, 2, ENC_BIG_ENDIAN, &framesource);
		if ( framesource != 0 )
			expert_add_info(pinfo, ti, &ei_exeh_incoming_framesource);
	} else { /* Direction == 255 */
		ti = proto_tree_add_item_ret_uint(exeh_tree, hf_exeh_outgoing_framesource, tvb, offset, 2, ENC_BIG_ENDIAN, &framesource);
		if ( framesource != 0 && framesource != 0x4248 )
			expert_add_info(pinfo, ti, &ei_exeh_outgoing_framesource);
	}
	offset += 2;
	proto_tree_add_item(exeh_tree, hf_exeh_vlan, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(exeh_tree, hf_exeh_unknown_28_29, tvb, offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item(exeh_tree, hf_exeh_dir, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(exeh_tree, hf_exeh_unknown_32_33, tvb, offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item_ret_uint(exeh_tree, hf_exeh_etype, tvb, offset, 2, ENC_BIG_ENDIAN, &etype);
	switch (etype) {
	case 0x8100: /* VLAN/VMAN Tag */
		ti = proto_tree_add_item_ret_int(exeh_tree, hf_exeh_etypelen, tvb, offset+2, 2, ENC_BIG_ENDIAN, &databytes);
		if (tvb_reported_length_remaining(tvb, offset) != databytes)
			expert_add_info(pinfo, ti, &ei_exeh_unexpected_value);
		break;
	default:
		proto_tree_add_item(exeh_tree, hf_exeh_etypedata, tvb, offset+2, 2, ENC_BIG_ENDIAN);
	}
	offset += 4;

	frame_tvb = tvb_new_subset_remaining(tvb, offset);
	call_dissector(ethnofcs_handle, frame_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

void
proto_register_exeh(void)
{
	static hf_register_info hf[] = {

	/* EXEH data */
		{ &hf_exeh_unknown_00_01,
		{ "Unknown_00",	"exeh.unknown00", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_module1,
		{ "Module",	"exeh.module1", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_port1,
		{ "Port",	"exeh.port1", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_module2,
		{ "Module",	"exeh.module2", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_port2,
		{ "Port",	"exeh.port2", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_unknown_10_16,
		{ "Unknown_10 (incoming specific?)",	"exeh.unknown10", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_unknown_17_0xfd,
		{ "Unknown_17",	"exeh.unknown17", FT_UINT8, BASE_HEX, NULL,
			0xfd, NULL, HFILL }},

		{ &hf_exeh_unknown_17_0x02,
		{ "Unknown_17 (Add dot1Q?)",	"exeh.unknown17.dot1q", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
			0x02, NULL, HFILL }},

		{ &hf_exeh_unknown_18_21,
		{ "Unknown_18 (outgoing specific?)",	"exeh.unknown18", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_unknown_22_23,
		{ "Add VLAN ID?",	"exeh.unknown22", FT_UINT16, BASE_NONE, VALS(exeh_outgoing_vlanid_vals),
			0x0, NULL, HFILL }},

		{ &hf_exeh_incoming_framesource,
		{ "Frame source",	"exeh.framesource", FT_UINT16, BASE_HEX, VALS(exeh_incoming_framesource_vals),
			0x0, NULL, HFILL }},

		{ &hf_exeh_outgoing_framesource,
		{ "Frame source",	"exeh.framesource", FT_UINT16, BASE_HEX, VALS(exeh_outgoing_framesource_vals),
			0x0, NULL, HFILL }},

		{ &hf_exeh_vlan,
		{ "Transport VLAN",	"exeh.vlan", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_unknown_28_29,
		{ "Unknown_28",	"exeh.unknown28", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_dir,
		{ "Direction",	"exeh.direction", FT_UINT16, BASE_HEX, VALS(exeh_direction_vals),
			0x0, NULL, HFILL }},

		{ &hf_exeh_unknown_32_33,
		{ "Unknown_32",	"exeh.unknown32", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_etype,
		{ "Etype",	"exeh.etype", FT_UINT16, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_etypedata,
		{ "Etype data",	"exeh.etypedata", FT_UINT16, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_exeh_etypelen,
		{ "Length",	"exeh.etypelen", FT_INT16, BASE_DEC, NULL,
			0x0, "Bytes from 8100 to end of frame", HFILL }},
	};


	static int *ett[] = {
		&ett_exeh,
	};

	static ei_register_info ei[] = {
		{ &ei_exeh_unexpected_value, { "exeh.unexpected_value", PI_PROTOCOL, PI_WARN, "Unexpected length", EXPFILL }},
		{ &ei_exeh_unequal_ports, { "exeh.unequal_ports", PI_PROTOCOL, PI_WARN, "Unequal ports", EXPFILL }},
		{ &ei_exeh_incoming_framesource, { "exeh.incoming_framesource", PI_PROTOCOL, PI_WARN, "Incoming framesource non-zero", EXPFILL }},
		{ &ei_exeh_outgoing_framesource, { "exeh.outgoing_framesource", PI_PROTOCOL, PI_WARN, "Outgoing framesource unknown magic", EXPFILL }},
	};

	expert_module_t* expert_exeh;

	proto_exeh = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "exeh");
	proto_register_field_array(proto_exeh, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_exeh = expert_register_protocol(proto_exeh);
	expert_register_field_array(expert_exeh, ei, array_length(ei));

	exeh_handle = register_dissector("exeh", dissect_exeh, proto_exeh);
}

void
proto_reg_handoff_exeh(void)
{
	ethnofcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_exeh);

	dissector_add_uint("ethertype", ETHERTYPE_EXEH, exeh_handle);
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
