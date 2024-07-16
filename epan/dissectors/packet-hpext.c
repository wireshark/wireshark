/* packet-hpext.c
 * Routines for HP extended IEEE 802.2 LLC layer
 * Jochen Friedrich <jochen@scram.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/llcsaps.h>
#include "packet-hpext.h"

void proto_register_hpext(void);
void proto_reg_handoff_hpext(void);

static dissector_handle_t hpext_handle;

static dissector_table_t subdissector_table;

static const value_string xsap_vals[] = {
	{ HPEXT_DXSAP,  "RBOOT Destination Service Access Point" },
	{ HPEXT_SXSAP,  "RBOOT Source Service Access Point" },
	{ HPEXT_HPSW,   "HP Switch Protocol" },
	{ HPEXT_SNMP,   "SNMP" },
	{ 0x00,         NULL }
};

static int proto_hpext;

static int hf_hpext_dxsap;
static int hf_hpext_reserved;
static int hf_hpext_sxsap;

static int ett_hpext;

static int
dissect_hpext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*hpext_tree = NULL;
	proto_item	*ti = NULL;
	uint16_t		dxsap, sxsap;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HPEXT");

	dxsap = tvb_get_ntohs(tvb, 3);
	sxsap = tvb_get_ntohs(tvb, 5);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_hpext, tvb, 0, 7, ENC_NA);
		hpext_tree = proto_item_add_subtree(ti, ett_hpext);
		proto_tree_add_item(hpext_tree, hf_hpext_reserved, tvb, 0, 3, ENC_NA);
		proto_tree_add_uint(hpext_tree, hf_hpext_dxsap, tvb, 3,
			2, dxsap);
		proto_tree_add_uint(hpext_tree, hf_hpext_sxsap, tvb, 5,
			2, sxsap);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO,
		    "; HPEXT; DXSAP %s, SXSAP %s",
		    val_to_str(dxsap, xsap_vals, "%04x"),
		    val_to_str(sxsap, xsap_vals, "%04x"));

	if (tvb_reported_length_remaining(tvb, 7) > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, 7);
		if (!dissector_try_uint(subdissector_table,
		    dxsap, next_tvb, pinfo, tree)) {
			call_data_dissector(next_tvb, pinfo, tree);
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_register_hpext(void)
{
	static hf_register_info hf[] = {
		{ &hf_hpext_dxsap,
			{ "DXSAP", "hpext.dxsap",
			  FT_UINT16, BASE_HEX, VALS(xsap_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_hpext_sxsap,
			{ "SXSAP", "hpext.sxsap",
			  FT_UINT16, BASE_HEX, VALS(xsap_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_hpext_reserved,
			{ "Reserved", "hpext.reserved",
			  FT_UINT24, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_hpext
	};

	proto_hpext = proto_register_protocol("HP Extended Local-Link Control", "HPEXT", "hpext");
	proto_register_field_array(proto_hpext, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
	subdissector_table = register_dissector_table("hpext.dxsap",
	  "HPEXT XSAP", proto_hpext, FT_UINT16, BASE_HEX);

	hpext_handle = register_dissector("hpext", dissect_hpext, proto_hpext);
}

void
proto_reg_handoff_hpext(void)
{
	dissector_add_uint("llc.dsap", SAP_HPEXT, hpext_handle);
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
