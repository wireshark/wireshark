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
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/xdlc.h>

void proto_register_dect_dlc(void);

static int proto_dect_dlc;

static int hf_dect_dlc_address;
static int hf_dect_dlc_nlf;
static int hf_dect_dlc_lln;
static int hf_dect_dlc_sapi;
static int hf_dect_dlc_cr;

static int hf_dect_dlc_control;
static int hf_dect_dlc_n_r;
static int hf_dect_dlc_n_s;
static int hf_dect_dlc_p;
static int hf_dect_dlc_f;
static int hf_dect_dlc_s_ftype;
static int hf_dect_dlc_u_modifier_cmd;
static int hf_dect_dlc_u_modifier_resp;
static int hf_dect_dlc_ftype_i;
static int hf_dect_dlc_ftype_s_u;

static int hf_dect_dlc_length;
static int hf_dect_dlc_el;
static int hf_dect_dlc_m;
static int hf_dect_dlc_len;

static int ett_dect_dlc;
static int ett_dect_dlc_address;
static int ett_dect_dlc_control;
static int ett_dect_dlc_length;

static dissector_handle_t data_handle;

static dissector_table_t dlc_sapi_dissector_table;

static reassembly_table dect_dlc_reassembly_table;

static int hf_dect_dlc_fragment_data;
static int hf_dect_dlc_fragment;
static int hf_dect_dlc_fragments;
static int hf_dect_dlc_fragment_overlap;
static int hf_dect_dlc_fragment_overlap_conflicts;
static int hf_dect_dlc_fragment_multiple_tails;
static int hf_dect_dlc_fragment_too_long_fragment;
static int hf_dect_dlc_fragment_error;
static int hf_dect_dlc_fragment_count;
static int hf_dect_dlc_reassembled_in;
static int hf_dect_dlc_reassembled_length;

static int ett_dect_dlc_fragment;
static int ett_dect_dlc_fragments;

static const fragment_items dect_dlc_frag_items = {
    /* Fragment subtrees */
    &ett_dect_dlc_fragment,
    &ett_dect_dlc_fragments,
    /* Fragment fields */
    &hf_dect_dlc_fragments,
    &hf_dect_dlc_fragment,
    &hf_dect_dlc_fragment_overlap,
    &hf_dect_dlc_fragment_overlap_conflicts,
    &hf_dect_dlc_fragment_multiple_tails,
    &hf_dect_dlc_fragment_too_long_fragment,
    &hf_dect_dlc_fragment_error,
    &hf_dect_dlc_fragment_count,
    /* Reassembled in field */
    &hf_dect_dlc_reassembled_in,
    /* Reassembled length field */
    &hf_dect_dlc_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "fragments"
};

static wmem_map_t *dect_dlc_last_n_s_map;

#define DECT_DLC_M          0x02
#define DECT_DLC_M_SHIFT    1

static bool reassemble_dect_dlc = true;

static const xdlc_cf_items dect_dlc_cf_items = {
	&hf_dect_dlc_n_r,
	&hf_dect_dlc_n_s,
	&hf_dect_dlc_p,
	&hf_dect_dlc_f,
	&hf_dect_dlc_s_ftype,
	&hf_dect_dlc_u_modifier_cmd,
	&hf_dect_dlc_u_modifier_resp,
	&hf_dect_dlc_ftype_i,
	&hf_dect_dlc_ftype_s_u
};

static const value_string dect_dlc_sapi_vals[] = {
	{ 0, "Connection oriented signalling" },
	{ 3, "Connectionless signalling" },
	{ 0, NULL }
};

static const value_string dect_dlc_lln_vals[] = {
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

static const value_string dect_dlc_m_vals[] = {
	{ 0, "Last segment" },
	{ 1, "More segments" },
	{ 0, NULL }
};

static const value_string dect_dlc_el_vals[] = {
	{ 0, "More octets" },
	{ 1, "Final octet" },
	{ 0, NULL }
};


static int dissect_dect_dlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree *dlc_tree, *addr_tree, *length_tree;
	proto_item *dlc_ti, *addr_ti, *length_ti;
	bool is_response = false;
	bool m;
	int available_length;
	int control;
	tvbuff_t *payload;
	uint8_t cr, sapi, length, len, n_s;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DECT-DLC");

	cr = tvb_get_uint8(tvb, 0) & 0x02;
	if (pinfo->p2p_dir == P2P_DIR_RECV)
		is_response = cr ? false : true;
	else if (pinfo->p2p_dir == P2P_DIR_SENT)
		is_response = cr ? true : false;

	dlc_ti = proto_tree_add_item(tree, proto_dect_dlc, tvb, 0, 3, ENC_NA);
	dlc_tree = proto_item_add_subtree(dlc_ti, ett_dect_dlc);

	addr_ti = proto_tree_add_item(dlc_tree, hf_dect_dlc_address, tvb, 0, 1, ENC_NA);
	addr_tree = proto_item_add_subtree(addr_ti, ett_dect_dlc_address);

	sapi = (tvb_get_uint8(tvb, 0) & 0x0C) >> 2;
	proto_tree_add_item(addr_tree, hf_dect_dlc_nlf, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(addr_tree, hf_dect_dlc_lln, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(addr_tree, hf_dect_dlc_sapi, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(addr_tree, hf_dect_dlc_cr, tvb, 0, 1, ENC_NA);

	control = dissect_xdlc_control(tvb, 1, pinfo, dlc_tree, hf_dect_dlc_control,
				ett_dect_dlc_control, &dect_dlc_cf_items, NULL, NULL, NULL,
				is_response, false, false);
	n_s = (control & XDLC_N_S_MASK) >> XDLC_N_S_SHIFT;

	length_ti = proto_tree_add_item(dlc_tree, hf_dect_dlc_length, tvb, 2, 1, ENC_NA);
	length_tree = proto_item_add_subtree(length_ti, ett_dect_dlc_length);
	length = tvb_get_uint8(tvb, 2);
	proto_tree_add_uint(length_tree, hf_dect_dlc_len, tvb, 2, 1, length);
	proto_tree_add_uint(length_tree, hf_dect_dlc_m, tvb, 2, 1, length);
	proto_tree_add_uint(length_tree, hf_dect_dlc_el, tvb, 2, 1, length);
	len = length >> 2;

	available_length = tvb_captured_length(tvb) - 3;
	if (available_length > 0) {
		payload = tvb_new_subset_length_caplen(tvb, 3, MIN(len, available_length), len);

		/* Potentially segmented I frame */
		if( (control & XDLC_I_MASK) == XDLC_I && reassemble_dect_dlc && !pinfo->flags.in_error_pkt )
		{
			fragment_head *fd_m = NULL;
			tvbuff_t *reassembled = NULL;
			uint32_t fragment_id;
			bool save_fragmented = pinfo->fragmented, add_frag;

			m = (length & DECT_DLC_M) >> DECT_DLC_M_SHIFT;
			pinfo->fragmented = m;

			fragment_id = (conversation_get_id_from_elements(pinfo, CONVERSATION_NONE, USE_LAST_ENDPOINT) << 3) | ( sapi << 1) | pinfo->p2p_dir;

			if (!PINFO_FD_VISITED(pinfo)) {
				/* Check if new N(S) is equal to previous N(S) (to avoid adding retransmissions in reassembly table)
				As GUINT_TO_POINTER macro does not allow to differentiate NULL from 0, use 1-8 range instead of 0-7 */
				unsigned *p_last_n_s = (unsigned*)wmem_map_lookup(dect_dlc_last_n_s_map, GUINT_TO_POINTER(fragment_id));
				if (GPOINTER_TO_UINT(p_last_n_s) == (unsigned)(n_s+1)) {
					add_frag = false;
				} else {
					add_frag = true;
					wmem_map_insert(dect_dlc_last_n_s_map, GUINT_TO_POINTER(fragment_id), GUINT_TO_POINTER(n_s+1));
				}
			} else {
				add_frag = true;
			}

			if (add_frag) {
				/* This doesn't seem the best way of doing it as doesn't
				take N(S) into account, but N(S) isn't always 0 for
				the first fragment!	*/
				fd_m = fragment_add_seq_next (&dect_dlc_reassembly_table, payload, 0,
											pinfo,
											fragment_id, /* uint32_t ID for fragments belonging together */
											NULL,
											/*n_s uint32_t fragment sequence number */
											len, /* uint32_t fragment length */
											m); /* More fragments? */

				reassembled = process_reassembled_data(payload, 0, pinfo,
													"Reassembled DLC", fd_m, &dect_dlc_frag_items,
													NULL, dlc_tree);

				/* Reassembled into this packet	*/
				if (fd_m && pinfo->num == fd_m->reassembled_in) {
					if (!dissector_try_uint(dlc_sapi_dissector_table, sapi,
											reassembled, pinfo, tree))
						call_data_dissector(reassembled, pinfo, tree);
				}
				else {
					col_append_str(pinfo->cinfo, COL_INFO, " (Fragment)");
					proto_tree_add_item(dlc_tree, hf_dect_dlc_fragment_data, payload, 0, -1, ENC_NA);
				}
			}

			/* Now reset fragmentation information in pinfo	*/
			pinfo->fragmented = save_fragmented;
		}
		else
		{
			if (!PINFO_FD_VISITED(pinfo) && ((control & XDLC_S_U_MASK) == XDLC_U) && ((control & XDLC_U_MODIFIER_MASK) == XDLC_SABM)) {
				/* SABM frame; reset the last N(S) to an invalid value */
				uint32_t fragment_id = (conversation_get_id_from_elements(pinfo, CONVERSATION_GSMTAP, USE_LAST_ENDPOINT) << 3) | (sapi << 1) | pinfo->p2p_dir;
				wmem_map_insert(dect_dlc_last_n_s_map, GUINT_TO_POINTER(fragment_id), GUINT_TO_POINTER(0));
			}
			if (!dissector_try_uint(dlc_sapi_dissector_table, sapi, payload, pinfo, tree))
				call_data_dissector(payload, pinfo, tree);
		}
	}

	return tvb_captured_length(tvb);
}

void proto_register_dect_dlc(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_dect_dlc_address,
			{ "Address Field", "dect_dlc.address_field", FT_UINT8, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_nlf,
			{ "NLF", "dect_dlc.nlf", FT_UINT8, BASE_DEC,
				NULL, 0x80, "New Link Flag", HFILL
			}
		},
		{ &hf_dect_dlc_lln,
			{ "LLN", "dect_dlc.lln", FT_UINT8, BASE_DEC,
				VALS(dect_dlc_lln_vals), 0x70, "Logical Link Number", HFILL
			}
		},
		{ &hf_dect_dlc_sapi,
			{ "SAPI", "dect_dlc.sapi", FT_UINT8, BASE_DEC,
				VALS(dect_dlc_sapi_vals), 0x0C, "Service Access Point Identifier", HFILL
			}
		},
		{ &hf_dect_dlc_cr,
			{ "C/R", "dect_dlc.cr", FT_UINT8, BASE_DEC,
				NULL, 0x02, "Command/Response field bit", HFILL
			}
		},
		{ &hf_dect_dlc_control,
			{ "Control Field", "dect_dlc.control_field", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_n_r,
			{ "N(R)", "dect_dlc.control.n_r", FT_UINT8, BASE_DEC,
				NULL, 0xE0, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_n_s,
			{ "N(S)", "dect_dlc.control.n_s", FT_UINT8, BASE_DEC,
				NULL, 0x0E, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_p,
			{ "Poll", "dect_dlc.control.p", FT_BOOLEAN, 8,
				NULL, 0x10, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_f,
			{ "Final", "dect_dlc.control.f", FT_BOOLEAN, 8,
				NULL, 0x10, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_s_ftype,
			{ "Supervisory frame type", "dect_dlc.control.s_ftype", FT_UINT8, BASE_HEX,
				VALS(stype_vals), XDLC_S_FTYPE_MASK, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_u_modifier_cmd,
			{ "Command", "dect_dlc.control.u_modifier_cmd", FT_UINT8, BASE_HEX,
				VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_u_modifier_resp,
			{ "Response", "dect_dlc.control.u_modifier_resp", FT_UINT8, BASE_HEX,
				VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_ftype_i,
			{ "Frame type", "dect_dlc.control.ftype", FT_UINT8, BASE_HEX,
				VALS(ftype_vals), XDLC_I_MASK, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_ftype_s_u,
			{ "Frame type", "dect_dlc.control.ftype", FT_UINT8, BASE_HEX,
				VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_length,
			{ "Length Field", "dect_dlc.length_field", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_el,
			{ "EL", "dect_dlc.el", FT_UINT8, BASE_DEC,
				VALS(dect_dlc_el_vals), 0x01, "Length indicator field extension bit", HFILL
			}
		},
		{ &hf_dect_dlc_m,
			{ "M", "dect_dlc.m", FT_UINT8, BASE_DEC,
				VALS(dect_dlc_m_vals), 0x02, "More data bit", HFILL
			}
		},
		{ &hf_dect_dlc_len,
			{ "Length", "dect_dlc.length", FT_UINT8, BASE_DEC,
				NULL, 0xFC, "Length indicator", HFILL
			}
		},

		/* Fragment reassembly */
		{ &hf_dect_dlc_fragment_data,
			{ "Fragment Data", "dect_dlc.fragment_data", FT_NONE, BASE_NONE,
				NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_fragments,
			{ "Message fragments", "dect_dlc.fragments",
				FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_fragment,
			{ "Message fragment", "dect_dlc.fragment",
				FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_fragment_overlap,
			{ "Message fragment overlap", "dect_dlc.fragment.overlap",
				FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_fragment_overlap_conflicts,
			{ "Message fragment overlapping with conflicting data",
				"dect_dlc.fragment.overlap.conflicts",
				FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_fragment_multiple_tails,
			{ "Message has multiple tail fragments",
				"dect_dlc.fragment.multiple_tails",
				FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_fragment_too_long_fragment,
			{ "Message fragment too long", "dect_dlc.fragment.too_long_fragment",
				FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_fragment_error,
			{ "Message defragmentation error", "dect_dlc.fragment.error",
				FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_fragment_count,
			{ "Message fragment count", "dect_dlc.fragment.count",
				FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_reassembled_in,
			{ "Reassembled in", "dect_dlc.reassembled.in",
				FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_dect_dlc_reassembled_length,
			{ "Reassembled length", "dect_dlc.reassembled.length",
				FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
	};

	static int *ett[] = {
		&ett_dect_dlc,
		&ett_dect_dlc_address,
		&ett_dect_dlc_control,
		&ett_dect_dlc_length,
		&ett_dect_dlc_fragment,
		&ett_dect_dlc_fragments,
	};

	/* Register protocol */
	proto_dect_dlc = proto_register_protocol("DECT DLC (LAPC)", "DECT-DLC", "dect_dlc");

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_dect_dlc, hf, array_length(hf));

	register_dissector("dect_dlc", dissect_dect_dlc, proto_dect_dlc);

	dlc_sapi_dissector_table = register_dissector_table("dect_dlc.sapi", "DECT DLC SAPI", proto_dect_dlc, FT_UINT8, BASE_DEC);

	data_handle = find_dissector("data");

	reassembly_table_register(&dect_dlc_reassembly_table,
                           &addresses_reassembly_table_functions);
	dect_dlc_last_n_s_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
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
