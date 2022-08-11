/* packet-ehdlc.c
 * Routines for packet dissection of Ericsson HDLC as used in A-bis over IP
 * Copyright 2010-2012, 2016 by Harald Welte <laforge@gnumonks.org>
 *
 * This code is based on pure educational guesses while looking at protocol
 * traces, as there is no publicly available protocol description by Ericsson.
 * Even the name is a guess, since it looks quite a bit like HDLC and is used
 * by Ericsson, I called it EHDLC.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/xdlc.h>
#include "packet-l2tp.h"

void proto_register_ehdlc(void);
void proto_reg_handoff_ehdlc(void);

/* Initialize the protocol and registered fields */
static int proto_ehdlc = -1;

static int hf_ehdlc_data_len = -1;
static int hf_ehdlc_csapi = -1;
static int hf_ehdlc_ctei = -1;

static int hf_ehdlc_sapi = -1;
static int hf_ehdlc_tei = -1;
static int hf_ehdlc_c_r = -1;

static int hf_ehdlc_xid_payload = -1;
static int hf_ehdlc_xid_win_tx = -1;
static int hf_ehdlc_xid_win_rx = -1;
static int hf_ehdlc_xid_ack_tmr_ms = -1;
static int hf_ehdlc_xid_format_id = -1;
static int hf_ehdlc_xid_group_id = -1;
static int hf_ehdlc_xid_len = -1;
static int hf_ehdlc_control = -1;

static int hf_ehdlc_p = -1;
static int hf_ehdlc_f = -1;
static int hf_ehdlc_u_modifier_cmd = -1;
static int hf_ehdlc_u_modifier_resp = -1;
static int hf_ehdlc_ftype_s_u = -1;

static int hf_ehdlc_n_r = -1;
static int hf_ehdlc_n_s = -1;
static int hf_ehdlc_p_ext = -1;
static int hf_ehdlc_f_ext = -1;
static int hf_ehdlc_s_ftype = -1;
static int hf_ehdlc_ftype_i = -1;
static int hf_ehdlc_ftype_s_u_ext = -1;

static dissector_handle_t ehdlc_handle;

/* Used only for U frames */
static const xdlc_cf_items ehdlc_cf_items = {
	NULL,
	NULL,
	&hf_ehdlc_p,
	&hf_ehdlc_f,
	NULL,
	&hf_ehdlc_u_modifier_cmd,
	&hf_ehdlc_u_modifier_resp,
	NULL,
	&hf_ehdlc_ftype_s_u
};

/* Used only for I and S frames */
static const xdlc_cf_items ehdlc_cf_items_ext = {
	&hf_ehdlc_n_r,
	&hf_ehdlc_n_s,
	&hf_ehdlc_p_ext,
	&hf_ehdlc_f_ext,
	&hf_ehdlc_s_ftype,
	NULL,
	NULL,
	&hf_ehdlc_ftype_i,
	&hf_ehdlc_ftype_s_u_ext,
};

/* Initialize the subtree pointers */
static gint ett_ehdlc = -1;
static gint ett_ehdlc_xid = -1;
static gint ett_ehdlc_control = -1;

enum {
	SUB_RSL,
	SUB_OML,
	SUB_TFP,
	SUB_PGSL,
	SUB_DATA,

	SUB_MAX
};

/* Determine TEI from Compressed TEI */
static guint8 tei_from_ctei(guint8 ctei)
{
	if (ctei < 12)
		return ctei;
	else
		return 60 + (ctei - 12);
}

static guint8 c_r_from_csapi(guint8 csapi)
{
	switch (csapi) {
	case 1:
	case 6:
		return 1;
	default:
		return 0;
	}
}

static guint8 sapi_from_csapi(guint8 csapi)
{
	switch (csapi) {
	case 0:
	case 1: /* RSL */
		return 0;
	case 2: /* TFP */
		return 10;
	case 3: /* TFP */
		return 11;
	case 4: /* P-GSL */
		return 12;
	case 5:
	case 6: /* OML */
		return 62;
	case 7:
	default:
		/* error! */
		return 0;
	}
}

static dissector_handle_t sub_handles[SUB_MAX];

static int
dissect_ehdlc_xid(proto_tree *tree, tvbuff_t *tvb, guint base_offset, guint len)
{
	guint offset = base_offset;
	proto_item *ti;
	proto_tree *xid_tree;

	/* XID is formatted like ISO 8885, typically we see
	 * something like
	 * 82		format identifier
	 * 80		group identifier
	 * 00 09 	length
	 * 07 01 05 	Window Size Tx
	 * 09 01 04	Ack Timer (msec)
	 * 08 01 05	Window Size Rx */
	ti = proto_tree_add_item(tree, hf_ehdlc_xid_payload,
				 tvb, offset, len, ENC_NA);
	xid_tree = proto_item_add_subtree(ti, ett_ehdlc_xid);

	proto_tree_add_item(xid_tree, hf_ehdlc_xid_format_id, tvb, offset++, 1, ENC_NA);
	proto_tree_add_item(xid_tree, hf_ehdlc_xid_group_id, tvb, offset++, 1, ENC_NA);
	proto_tree_add_item(xid_tree, hf_ehdlc_xid_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	while (tvb_reported_length_remaining(tvb, offset) >= 2) {
		guint8 iei = tvb_get_guint8(tvb, offset++);
		guint8 ie_len = tvb_get_guint8(tvb, offset++);

		switch (iei) {
		case 0x07:
			proto_tree_add_item(xid_tree, hf_ehdlc_xid_win_tx, tvb,
					offset, ie_len, ENC_NA);
			break;
		case 0x08:
			proto_tree_add_item(xid_tree, hf_ehdlc_xid_win_rx, tvb,
					offset, ie_len, ENC_NA);
			break;
		case 0x09:
			proto_tree_add_item(xid_tree, hf_ehdlc_xid_ack_tmr_ms, tvb,
					offset, ie_len, ENC_NA);
			break;
		}
		offset += ie_len;
	}

	return offset - base_offset;
}

/* Code to actually dissect the packets */
static int
dissect_ehdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int  offset = 4;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EHDLC");
	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_item *ti            = NULL;
		proto_tree *ehdlc_tree    = NULL;
		guint16     len, hdr2;
		guint8      csapi, ctei, sapi, tei, c_r;
		tvbuff_t   *next_tvb;
		guint16     control;
		gboolean    is_response   = FALSE, is_extended = TRUE;
		gint        header_length = 2; /* Address + Length field */

		hdr2 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
		len = hdr2 & 0x1FF;
		csapi = hdr2 >> 13;
		sapi = sapi_from_csapi(csapi);
		c_r = c_r_from_csapi(csapi);
		ctei = (hdr2 >> 9) & 0xF;
		tei = tei_from_ctei(ctei);

		/* Add TEI to INFO column */
		col_append_fstr(pinfo->cinfo, COL_INFO, " | TEI:%02u | ", tei);
		col_set_fence(pinfo->cinfo, COL_INFO);

		if (tree) {
			/* Use MIN(...,...) in the following to prevent a premature */
			/* exception before we try to dissect whatever is available. */
			ti = proto_tree_add_protocol_format(tree, proto_ehdlc,
					tvb, offset, MIN(len, tvb_captured_length_remaining(tvb,offset)),
					"Ericsson HDLC protocol");
			ehdlc_tree = proto_item_add_subtree(ti, ett_ehdlc);

			proto_tree_add_item(ehdlc_tree, hf_ehdlc_csapi,
					    tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(ehdlc_tree, hf_ehdlc_ctei,
					    tvb, offset, 1, ENC_BIG_ENDIAN);
			ti = proto_tree_add_uint(ehdlc_tree, hf_ehdlc_c_r,
							 tvb, offset, 1, c_r);
			proto_item_set_generated(ti);
			ti = proto_tree_add_uint(ehdlc_tree, hf_ehdlc_sapi,
							 tvb, offset, 1, sapi);
			proto_item_set_generated(ti);
			ti = proto_tree_add_uint(ehdlc_tree, hf_ehdlc_tei,
							 tvb, offset, 1, tei);
			proto_item_set_generated(ti);
			proto_tree_add_item(ehdlc_tree, hf_ehdlc_data_len,
					    tvb, offset, 2, ENC_BIG_ENDIAN);
		}

		if (sapi == 10 || sapi == 11) {
			/* Voice TRAU */
			next_tvb = tvb_new_subset_length(tvb, offset+2, len-2);
			call_dissector(sub_handles[SUB_TFP], next_tvb, pinfo, tree);
			offset += len;
			continue;
		} else if (sapi == 12) {
			/* GPRS TRAU */
			next_tvb = tvb_new_subset_length(tvb, offset+2, len-2);
			call_dissector(sub_handles[SUB_PGSL], next_tvb, pinfo, tree);
			offset += len;
			continue;
		}

		control = dissect_xdlc_control(tvb, offset+2, pinfo, ehdlc_tree, hf_ehdlc_control,
					       ett_ehdlc_control, &ehdlc_cf_items, &ehdlc_cf_items_ext,
					       NULL, NULL, is_response, is_extended, FALSE);
		header_length += XDLC_CONTROL_LEN(control, is_extended);

		if (XDLC_IS_INFORMATION(control)) {
			next_tvb = tvb_new_subset_length(tvb, offset+header_length,
						  len-header_length);

			switch (sapi) {
			case 0:
				/* len == 4 seems to be some kind of ACK */
				if (len <= 4)
					break;
				call_dissector(sub_handles[SUB_RSL], next_tvb, pinfo, tree);
				break;
			case 62:
				/* len == 4 seems to be some kind of ACK */
				if (len <= 4)
					break;
				call_dissector(sub_handles[SUB_OML], next_tvb, pinfo, tree);
				break;
			default:
				call_dissector(sub_handles[SUB_DATA], next_tvb, pinfo, tree);
				break;
			}
		} else if (control == (XDLC_U | XDLC_XID)) {
			dissect_ehdlc_xid(ehdlc_tree, tvb, offset+header_length,
					  len-header_length);
		}

		if (len == 0)
			len = 1;
		offset += len;
	}
	return tvb_captured_length(tvb);
}

void
proto_register_ehdlc(void)
{
	static hf_register_info hf[] = {
		{ &hf_ehdlc_data_len,
		  { "DataLen", "ehdlc.data_len",
		    FT_UINT16, BASE_DEC, NULL, 0x1FF,
		    "The length of the data (in bytes)", HFILL }
		},
		{ &hf_ehdlc_csapi,
		  { "Compressed SAPI", "ehdlc.csapi",
		    FT_UINT8, BASE_DEC, NULL, 0xE0,
		    NULL, HFILL}
		},
		{ &hf_ehdlc_ctei,
		  { "Compressed TEI", "ehdlc.ctei",
		    FT_UINT8, BASE_DEC, NULL, 0x1E,
		    NULL, HFILL}
		},
		{ &hf_ehdlc_sapi,
		  { "SAPI", "ehdlc.sapi",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_tei,
		  { "TEI", "ehdlc.tei",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_c_r,
		  { "C/R", "ehdlc.c_r",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_ehdlc_xid_payload,
		  { "XID Payload", "ehdlc.xid_payload",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_xid_win_tx,
		  { "Transmit Window", "ehdlc.xid.win_tx",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_xid_win_rx,
		  { "Receive Window", "ehdlc.xid.win_rx",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_xid_ack_tmr_ms,
		  { "Timer (ms)", "ehdlc.xid.ack_tmr_ms",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_xid_format_id,
		  { "Format Identifier", "ehdlc.xid.format_id",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_xid_group_id,
		  { "Group Identifier", "ehdlc.xid.group_id",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_xid_len,
		  { "XID Length", "ehdlc.xid.len",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_control,
		  { "Control Field", "ehdlc.control",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_n_r,
		  { "N(R)", "ehdlc.control.n_r",
		    FT_UINT16, BASE_DEC, NULL, XDLC_N_R_EXT_MASK,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_n_s,
		  { "N(S)", "ehdlc.control.n_s",
		    FT_UINT16, BASE_DEC, NULL, XDLC_N_S_EXT_MASK,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_p,
		  { "Poll", "ehdlc.control.p",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), XDLC_P_F,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_p_ext,
		  { "Poll", "ehdlc.control.p",
		    FT_BOOLEAN, 16, TFS(&tfs_set_notset), XDLC_P_F_EXT,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_f,
		  { "Final", "ehdlc.control.f",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), XDLC_P_F,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_f_ext,
		  { "Final", "ehdlc.control.f",
		    FT_BOOLEAN, 16, TFS(&tfs_set_notset), XDLC_P_F_EXT,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_s_ftype,
		  { "Supervisory frame type", "ehdlc.control.s_ftype",
		    FT_UINT16, BASE_HEX, VALS(stype_vals), XDLC_S_FTYPE_MASK,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_u_modifier_cmd,
		  { "Command", "ehdlc.control.u_modifier_cmd",
		    FT_UINT8, BASE_HEX, VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_u_modifier_resp,
		  { "Response", "ehdlc.control.u_modifier_resp",
		    FT_UINT8, BASE_HEX, VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_ftype_i,
		  { "Frame Type", "ehdlc.control.ftype",
		    FT_UINT16, BASE_HEX, VALS(ftype_vals), XDLC_I_MASK,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_ftype_s_u,
		  { "Frame Type", "ehdlc.control.ftype",
		    FT_UINT8, BASE_HEX, VALS(ftype_vals), XDLC_S_U_MASK,
		    NULL, HFILL }
		},
		{ &hf_ehdlc_ftype_s_u_ext,
		  { "Frame Type", "ehdlc.control.ftype",
		    FT_UINT16, BASE_HEX, VALS(ftype_vals), XDLC_S_U_MASK,
		    NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_ehdlc,
		&ett_ehdlc_xid,
		&ett_ehdlc_control,
	};

	proto_ehdlc =
	    proto_register_protocol("Ericsson HDLC",
				    "Ericsson HDLC as used in A-bis over IP", "ehdlc");

	proto_register_field_array(proto_ehdlc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ehdlc_handle = register_dissector("ehdlc", dissect_ehdlc, proto_ehdlc);
}

void
proto_reg_handoff_ehdlc(void)
{
	sub_handles[SUB_RSL]  = find_dissector_add_dependency("gsm_abis_rsl", proto_ehdlc);
	sub_handles[SUB_OML]  = find_dissector_add_dependency("gsm_abis_oml", proto_ehdlc);
	sub_handles[SUB_TFP]  = find_dissector_add_dependency("gsm_abis_tfp", proto_ehdlc);
	sub_handles[SUB_PGSL]  = find_dissector_add_dependency("gsm_abis_pgsl", proto_ehdlc);
	sub_handles[SUB_DATA] = find_dissector("data");

	dissector_add_for_decode_as("l2tp.pw_type", ehdlc_handle);
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
