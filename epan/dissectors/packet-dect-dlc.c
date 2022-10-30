/* packet-dect-dlc.c
 *
 * Dissector for the DECT (Digital Enhanced Cordless Telecommunications)
 * DLC protocol layer as described in ETSI EN 300 175-4 V2.7.1 (2017-11)
 *
 * DLC is sometimes also called LAPC, which is a derivative of LAPDm (GSM),
 * which is a derivative of LAPD (ISDN).
 *
 * Copyright 2018 by Harald Welte <laforge@gnumonks.org>
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
#include <epan/xdlc.h>

static int proto_dect_dlc = -1;

static gint hf_dlc_address = -1;
static gint hf_dlc_nlf = -1;
static gint hf_dlc_lln = -1;
static gint hf_dlc_sapi = -1;
static gint hf_dlc_cr = -1;

static int hf_dlc_control = -1;
static int hf_dlc_n_r = -1;
static int hf_dlc_n_s = -1;
static int hf_dlc_p = -1;
static int hf_dlc_f = -1;
static int hf_dlc_s_ftype = -1;
static int hf_dlc_u_modifier_cmd = -1;
static int hf_dlc_u_modifier_resp = -1;
static int hf_dlc_ftype_i = -1;
static int hf_dlc_ftype_s_u = -1;

static int hf_dlc_length = -1;
static int hf_dlc_el = -1;
static int hf_dlc_m = -1;
static int hf_dlc_len = -1;

static gint ett_dect_dlc = -1;
static gint ett_dect_dlc_address = -1;
static gint ett_dect_dlc_control = -1;
static gint ett_dect_dlc_length = -1;

static dissector_handle_t data_handle;

static dissector_table_t dlc_sapi_dissector_table;


static const xdlc_cf_items dlc_cf_items = {
	&hf_dlc_n_r,
	&hf_dlc_n_s,
	&hf_dlc_p,
	&hf_dlc_f,
	&hf_dlc_s_ftype,
	&hf_dlc_u_modifier_cmd,
	&hf_dlc_u_modifier_resp,
	&hf_dlc_ftype_i,
	&hf_dlc_ftype_s_u
};

static const value_string dlc_sapi_vals[] = {
	{ 0, "Connection oriented signalling" },
	{ 3, "Connectionless signalling" },
	{ 0, NULL }
};

static const value_string dlc_lln_vals[] = {
	{ 0, "U0" },
	{ 1, "A1" },
	{ 2, "B2" },
	{ 3, "B3" },
	{ 4, "B4" },
	{ 5, "B5" },
	{ 6, "B6" },
	{ 7, "unassigned" },
	{ 0, NULL }
};

static const value_string dlc_m_vals[] = {
	{ 0, "Last segment" },
	{ 1, "More segments" },
	{ 0, NULL }
};

static const value_string dlc_el_vals[] = {
	{ 0, "More octets" },
	{ 1, "Final octet" },
	{ 0, NULL }
};


static int dissect_dect_dlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree *dlc_tree, *addr_tree, *length_tree;
	proto_item *dlc_ti, *addr_ti, *length_ti;
	gboolean is_response = FALSE;
	int available_length;
	tvbuff_t *payload;
	guint8 cr, sapi, length, len;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DECT-DLC");

	cr = tvb_get_guint8(tvb, 0) & 0x02;
	if (pinfo->p2p_dir == P2P_DIR_RECV)
		is_response = cr ? FALSE : TRUE;
	else if (pinfo->p2p_dir == P2P_DIR_SENT)
		is_response = cr ? TRUE : FALSE;

	dlc_ti = proto_tree_add_item(tree, proto_dect_dlc, tvb, 0, 3, ENC_NA);
	dlc_tree = proto_item_add_subtree(dlc_ti, ett_dect_dlc);

	addr_ti = proto_tree_add_item(dlc_tree, hf_dlc_address, tvb, 0, 1, ENC_NA);
	addr_tree = proto_item_add_subtree(addr_ti, ett_dect_dlc_address);

	sapi = (tvb_get_guint8(tvb, 0) & 0x0C) >> 2;
	proto_tree_add_item(addr_tree, hf_dlc_nlf, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(addr_tree, hf_dlc_lln, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(addr_tree, hf_dlc_sapi, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(addr_tree, hf_dlc_cr, tvb, 0, 1, ENC_NA);

	dissect_xdlc_control(tvb, 1, pinfo, dlc_tree, hf_dlc_control,
				ett_dect_dlc_control, &dlc_cf_items, NULL, NULL, NULL,
				is_response, FALSE, FALSE);

	length_ti = proto_tree_add_item(dlc_tree, hf_dlc_length, tvb, 2, 1, ENC_NA);
	length_tree = proto_item_add_subtree(length_ti, ett_dect_dlc_length);
	length = tvb_get_guint8(tvb, 2);
	proto_tree_add_uint(length_tree, hf_dlc_len, tvb, 2, 1, length);
	proto_tree_add_uint(length_tree, hf_dlc_m, tvb, 2, 1, length);
	proto_tree_add_uint(length_tree, hf_dlc_el, tvb, 2, 1, length);
	len = length >> 2;

	available_length = tvb_captured_length(tvb) - 3;
	if (available_length > 0) {
		payload = tvb_new_subset_length_caplen(tvb, 3, MIN(len, available_length), len);

		/* FIXME: fragment reassembly like in packet-lapdm.c */

		if (!dissector_try_uint(dlc_sapi_dissector_table, sapi, payload, pinfo, tree))
			call_data_dissector(payload, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

void proto_register_dect_dlc(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_dlc_address,
			{ "Address Field", "dect_dlc.address_field", FT_UINT8, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dlc_nlf,
			{ "NLF", "dect_dlc.nlf", FT_UINT8, BASE_DEC,
				NULL, 0x80, "New Link Flag", HFILL
			}
		},
		{ &hf_dlc_lln,
			{ "LLN", "dect_dlc.lln", FT_UINT8, BASE_DEC,
				VALS(dlc_lln_vals), 0x70, "Logical Link Number", HFILL
			}
		},
		{ &hf_dlc_sapi,
			{ "SAPI", "dect_dlc.sapi", FT_UINT8, BASE_DEC,
				VALS(dlc_sapi_vals), 0x0C, "Service Access Point Identifier", HFILL
			}
		},
		{ &hf_dlc_cr,
			{ "C/R", "dect_dlc.cr", FT_UINT8, BASE_DEC,
				NULL, 0x02, "Command/Response field bit", HFILL
			}
		},
		{ &hf_dlc_control,
			{ "Control Field", "dect_dlc.control_field", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dlc_n_r,
			{ "N(R)", "dect_dlc.control.n_r", FT_UINT8, BASE_DEC,
				NULL, 0xE0, NULL, HFILL
			}
		},
		{ &hf_dlc_n_s,
			{ "N(S)", "dect_dlc.control.n_s", FT_UINT8, BASE_DEC,
				NULL, 0x0E, NULL, HFILL
			}
		},
		{ &hf_dlc_p,
			{ "Poll", "dect_dlc.control.p", FT_BOOLEAN, 8,
				TFS(&tfs_true_false), 0x10, NULL, HFILL
			}
		},
		{ &hf_dlc_f,
			{ "Final", "dect_dlc.control.f", FT_BOOLEAN, 8,
				TFS(&tfs_true_false), 0x10, NULL, HFILL
			}
		},
		{ &hf_dlc_s_ftype,
			{ "Supervisory frame type", "dect_dlc.control.s_ftype", FT_UINT8, BASE_HEX,
				VALS(stype_vals), XDLC_S_FTYPE_MASK, NULL, HFILL
			}
		},
		{ &hf_dlc_u_modifier_cmd,
			{ "Command", "dect_dlc.control.u_modifier_cmd", FT_UINT8, BASE_HEX,
				VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK, NULL, HFILL
			}
		},
		{ &hf_dlc_u_modifier_resp,
			{ "Response", "dect_dlc.control.u_modifier_resp", FT_UINT8, BASE_HEX,
				VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK, NULL, HFILL
			}
		},
		{ &hf_dlc_ftype_i,
			{ "Frame type", "dect_dlc.control.ftype", FT_UINT8, BASE_HEX,
				VALS(ftype_vals), XDLC_I_MASK, NULL, HFILL
			}
		},
		{ &hf_dlc_ftype_s_u,
			{ "Frame type", "dect_dlc.control.ftype", FT_UINT8, BASE_HEX,
				VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL
			}
		},
		{ &hf_dlc_length,
			{ "Length Field", "dect_dlc.length_field", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dlc_el,
			{ "EL", "dect_dlc.el", FT_UINT8, BASE_DEC,
				VALS(dlc_el_vals), 0x01, "Length indicator field extension bit", HFILL
			}
		},
		{ &hf_dlc_m,
			{ "M", "dect_dlc.m", FT_UINT8, BASE_DEC,
				VALS(dlc_m_vals), 0x02, "More data bit", HFILL
			}
		},
		{ &hf_dlc_len,
			{ "Length", "dect_dlc.length", FT_UINT8, BASE_DEC,
				NULL, 0xFC, "LEngth indicator", HFILL
			}
		},

	};

	static gint *ett[] = {
		&ett_dect_dlc,
		&ett_dect_dlc_address,
		&ett_dect_dlc_control,
		&ett_dect_dlc_length,
	};

	/* Register protocol */
	proto_dect_dlc = proto_register_protocol("DECT DLC (LAPC)", "DECT-DLC", "dect_dlc");

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_dect_dlc, hf, array_length(hf));

	register_dissector("dect_dlc", dissect_dect_dlc, proto_dect_dlc);

	dlc_sapi_dissector_table = register_dissector_table("dect_dlc.sapi", "DECT DLC SAPI", proto_dect_dlc, FT_UINT8, BASE_DEC);

	data_handle = find_dissector("data");
}

#if 0
//void proto_reg_handoff_dect_aastra(void)
//{
//	dissector_handle_t dlc_handle  = create_dissector_handle(dissect_aamide_xdlc, proto_dect_dlc);
//}
#endif

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
