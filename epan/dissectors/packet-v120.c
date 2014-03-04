/* packet-v120.c
 * Routines for v120 frame disassembly
 * Bert Driehuis <driehuis@playbeing.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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
#include <epan/xdlc.h>

void proto_register_v120(void);
void proto_reg_handoff_v120(void);

static int proto_v120 = -1;
static int hf_v120_address = -1;
static int hf_v120_rc = -1;
static int hf_v120_lli = -1;
static int hf_v120_ea0 = -1;
static int hf_v120_ea1 = -1;
static int hf_v120_control = -1;
static int hf_v120_n_r = -1;
static int hf_v120_n_s = -1;
static int hf_v120_p = -1;
static int hf_v120_p_ext = -1;
static int hf_v120_f = -1;
static int hf_v120_f_ext = -1;
static int hf_v120_s_ftype = -1;
static int hf_v120_u_modifier_cmd = -1;
static int hf_v120_u_modifier_resp = -1;
static int hf_v120_ftype_i = -1;
static int hf_v120_ftype_s_u = -1;
static int hf_v120_ftype_s_u_ext = -1;
static int hf_v120_header8 = -1;
static int hf_v120_header_ext8 = -1;
static int hf_v120_header_break8 = -1;
static int hf_v120_header_error_control8 = -1;
static int hf_v120_header_segb8 = -1;
static int hf_v120_header_segf8 = -1;
static int hf_v120_header16 = -1;
static int hf_v120_header_ext16 = -1;
static int hf_v120_header_break16 = -1;
static int hf_v120_header_error_control16 = -1;
static int hf_v120_header_segb16 = -1;
static int hf_v120_header_segf16 = -1;
static int hf_v120_header_e = -1;
static int hf_v120_header_dr = -1;
static int hf_v120_header_sr = -1;
static int hf_v120_header_rr = -1;

static gint ett_v120 = -1;
static gint ett_v120_address = -1;
static gint ett_v120_control = -1;
static gint ett_v120_header = -1;

static dissector_handle_t data_handle;

static const true_false_string tfs_response_command = { "Response", "Command"  };
static const true_false_string tfs_segmentation_no_segmentation = { "Segmentation", "No segmentation" };

static int dissect_v120_header(tvbuff_t *tvb, int offset, proto_tree *tree);

/* Used only for U frames */
static const xdlc_cf_items v120_cf_items = {
	NULL,
	NULL,
	&hf_v120_p,
	&hf_v120_f,
	NULL,
	&hf_v120_u_modifier_cmd,
	&hf_v120_u_modifier_resp,
	NULL,
	&hf_v120_ftype_s_u
};

/* Used only for I and S frames */
static const xdlc_cf_items v120_cf_items_ext = {
	&hf_v120_n_r,
	&hf_v120_n_s,
	&hf_v120_p_ext,
	&hf_v120_f_ext,
	&hf_v120_s_ftype,
	NULL,
	NULL,
	&hf_v120_ftype_i,
	&hf_v120_ftype_s_u_ext
};

static void
dissect_v120(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*v120_tree, *address_tree;
	proto_item	*ti, *tc;
	int		is_response;
	int		v120len;
	guint8	byte0, byte1;
	guint16	control;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "V.120");
	col_clear(pinfo->cinfo, COL_INFO);

	byte0 = tvb_get_guint8(tvb, 0);

	col_add_fstr(pinfo->cinfo, COL_RES_DL_SRC, "0x%02X", byte0);

	byte1 = tvb_get_guint8(tvb, 1);

	if ( ((byte0 & 0x01) != 0x00) && ((byte1 & 0x01) != 0x01) )
	{
		col_set_str(pinfo->cinfo, COL_INFO, "Invalid V.120 frame");
		if (tree)
			proto_tree_add_protocol_format(tree, proto_v120, tvb, 0, -1,
									"Invalid V.120 frame");
		return;
	}

	if (pinfo->p2p_dir == P2P_DIR_SENT) {
		is_response = (byte0 & 0x02) ? FALSE: TRUE;
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DCE");
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DTE");
	} else {
		/* XXX - what if the direction is unknown? */
		is_response = (byte0 & 0x02) ? TRUE : FALSE;
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DTE");
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DCE");
	}

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_v120, tvb, 0, -1, "V.120");
		v120_tree = proto_item_add_subtree(ti, ett_v120);
		tc = proto_tree_add_item(v120_tree, hf_v120_address, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_item_append_text(tc, "LLI: %d C/R: %s",
				((byte0 & 0xfc) << 5) | ((byte1 & 0xfe) >> 1),
				byte0 & 0x02 ? "R" : "C");
		address_tree = proto_item_add_subtree(tc, ett_v120_address);

		proto_tree_add_item(address_tree, hf_v120_rc, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(address_tree, hf_v120_lli, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(address_tree, hf_v120_ea0, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(address_tree, hf_v120_ea1, tvb, 0, 2, ENC_BIG_ENDIAN);
	}
	else {
		v120_tree = NULL;
		ti = NULL;
	}
	control = dissect_xdlc_control(tvb, 2, pinfo, v120_tree, hf_v120_control,
		ett_v120_control, &v120_cf_items, &v120_cf_items_ext,
		NULL, NULL, is_response, TRUE, FALSE);
	if (tree) {
		v120len = 2 + XDLC_CONTROL_LEN(control, TRUE);

		if (tvb_bytes_exist(tvb, v120len, 1))
			v120len += dissect_v120_header(tvb, v120len, v120_tree);
		proto_item_set_len(ti, v120len);
		next_tvb = tvb_new_subset_remaining(tvb, v120len);
		call_dissector(data_handle,next_tvb, pinfo, v120_tree);
	}
}

static int
dissect_v120_header(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	int header_len;
	guint8 byte0;
	proto_tree *h_tree;
	proto_item *tc;

	byte0 = tvb_get_guint8(tvb, offset);
	if (byte0 & 0x80) {
		header_len = 1;
		tc = proto_tree_add_item(tree, hf_v120_header8, tvb, 0, 1, ENC_NA);

		h_tree = proto_item_add_subtree(tc, ett_v120_header);
		proto_tree_add_item(h_tree, hf_v120_header_ext8, tvb, 0, 1, ENC_NA);
		proto_tree_add_item(h_tree, hf_v120_header_break8, tvb, 0, 1, ENC_NA);
		proto_tree_add_item(h_tree, hf_v120_header_error_control8, tvb, 0, 1, ENC_NA);
		proto_tree_add_item(h_tree, hf_v120_header_segb8, tvb, 0, 1, ENC_NA);
		proto_tree_add_item(h_tree, hf_v120_header_segf8, tvb, 0, 1, ENC_NA);
	} else {
		header_len = 2;
		tc = proto_tree_add_item(tree, hf_v120_header16, tvb, 0, 2, ENC_BIG_ENDIAN);
		h_tree = proto_item_add_subtree(tc, ett_v120_header);
		proto_tree_add_item(h_tree, hf_v120_header_ext16, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(h_tree, hf_v120_header_break16, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(h_tree, hf_v120_header_error_control16, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(h_tree, hf_v120_header_segb16, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(h_tree, hf_v120_header_segf16, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(h_tree, hf_v120_header_e, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(h_tree, hf_v120_header_dr, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(h_tree, hf_v120_header_sr, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(h_tree, hf_v120_header_rr, tvb, 0, 2, ENC_BIG_ENDIAN);
	}

	proto_item_append_text(tc, " B: %d F: %d",
			byte0 & 0x02 ? 1:0, byte0 & 0x01 ? 1:0);

	return header_len;
}

void
proto_register_v120(void)
{
    static hf_register_info hf[] = {
	{ &hf_v120_address,
	  { "Link Address", "v120.address", FT_UINT16, BASE_HEX, NULL,
		  0x0, NULL, HFILL }},
	{ &hf_v120_rc,
	  { "R/C", "v120.rc", FT_BOOLEAN, 16, TFS(&tfs_response_command),
		  0x0002, NULL, HFILL }},
	{ &hf_v120_lli,
	  { "LLI", "v120.lli", FT_UINT16, BASE_HEX, NULL,
		  0xfefc, NULL, HFILL }},
	{ &hf_v120_ea0,
	  { "EA0", "v120.ea0", FT_BOOLEAN, 16, TFS(&tfs_error_ok),
		  0x0001, NULL, HFILL }},
	{ &hf_v120_ea1,
	  { "EA1", "v120.ea1", FT_BOOLEAN, 16, TFS(&tfs_ok_error),
		  0x0100, NULL, HFILL }},
	{ &hf_v120_control,
	  { "Control Field", "v120.control", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	NULL, HFILL }},
	{ &hf_v120_n_r,
	    { "N(R)", "v120.control.n_r", FT_UINT16, BASE_DEC,
		NULL, XDLC_N_R_EXT_MASK, NULL, HFILL }},
	{ &hf_v120_n_s,
	    { "N(S)", "v120.control.n_s", FT_UINT16, BASE_DEC,
		NULL, XDLC_N_S_EXT_MASK, NULL, HFILL }},
	{ &hf_v120_p,
	    { "Poll", "v120.control.p", FT_BOOLEAN, 8,
		TFS(&tfs_set_notset), XDLC_P_F, NULL, HFILL }},
	{ &hf_v120_p_ext,
	    { "Poll", "v120.control.p", FT_BOOLEAN, 16,
		TFS(&tfs_set_notset), XDLC_P_F_EXT, NULL, HFILL }},
	{ &hf_v120_f,
	    { "Final", "v120.control.f", FT_BOOLEAN, 8,
		TFS(&tfs_set_notset), XDLC_P_F, NULL, HFILL }},
	{ &hf_v120_f_ext,
	    { "Final", "v120.control.f", FT_BOOLEAN, 16,
		TFS(&tfs_set_notset), XDLC_P_F_EXT, NULL, HFILL }},
	{ &hf_v120_s_ftype,
	    { "Supervisory frame type", "v120.control.s_ftype", FT_UINT16, BASE_HEX,
		VALS(stype_vals), XDLC_S_FTYPE_MASK, NULL, HFILL }},
	{ &hf_v120_u_modifier_cmd,
	    { "Command", "v120.control.u_modifier_cmd", FT_UINT8, BASE_HEX,
		VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK, NULL, HFILL }},
	{ &hf_v120_u_modifier_resp,
	    { "Response", "v120.control.u_modifier_resp", FT_UINT8, BASE_HEX,
		VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK, NULL, HFILL }},
	{ &hf_v120_ftype_i,
	    { "Frame type", "v120.control.ftype", FT_UINT16, BASE_HEX,
		VALS(ftype_vals), XDLC_I_MASK, NULL, HFILL }},
	{ &hf_v120_ftype_s_u,
	    { "Frame type", "v120.control.ftype", FT_UINT8, BASE_HEX,
		VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL }},
	{ &hf_v120_ftype_s_u_ext,
	    { "Frame type", "v120.control.ftype", FT_UINT16, BASE_HEX,
		VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL }},
	{ &hf_v120_header8,
	  { "Header", "v120.header", FT_UINT8, BASE_HEX, NULL, 0x0,
	  	NULL, HFILL }},
	{ &hf_v120_header_ext8,
	  { "Extension octet", "v120.header.ext", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
	  	NULL, HFILL }},
	{ &hf_v120_header_break8,
	  { "Break condition", "v120.header.break", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
	  	NULL, HFILL }},
	{ &hf_v120_header_error_control8,
	  { "Error control C1/C2", "v120.error_control", FT_UINT8, BASE_HEX, NULL, 0x0C,
	  	NULL, HFILL }},
	{ &hf_v120_header_segb8,
	  { "Bit B", "v120.header.segb", FT_BOOLEAN, 8, TFS(&tfs_segmentation_no_segmentation), 0x02,
	  	NULL, HFILL }},
	{ &hf_v120_header_segf8,
	  { "Bit F", "v120.header.segf", FT_BOOLEAN, 8, TFS(&tfs_segmentation_no_segmentation), 0x01,
	  	NULL, HFILL }},
	{ &hf_v120_header16,
	  { "Header", "v120.header", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	NULL, HFILL }},
	{ &hf_v120_header_ext16,
	  { "Extension octet", "v120.header.ext", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x80,
	  	NULL, HFILL }},
	{ &hf_v120_header_break16,
	  { "Break condition", "v120.header.break", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x40,
	  	NULL, HFILL }},
	{ &hf_v120_header_error_control16,
	  { "Error control C1/C2", "v120.error_control", FT_UINT16, BASE_HEX, NULL, 0x0C,
	  	NULL, HFILL }},
	{ &hf_v120_header_segb16,
	  { "Bit B", "v120.header.segb", FT_BOOLEAN, 16, TFS(&tfs_segmentation_no_segmentation), 0x02,
	  	NULL, HFILL }},
	{ &hf_v120_header_segf16,
	  { "Bit F", "v120.header.segf", FT_BOOLEAN, 16, TFS(&tfs_segmentation_no_segmentation), 0x01,
	  	NULL, HFILL }},
	{ &hf_v120_header_e,
	  { "E", "v120.header.e", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
	  	NULL, HFILL }},
	{ &hf_v120_header_dr,
	  { "DR", "v120.header.dr", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x4000,
	  	NULL, HFILL }},
	{ &hf_v120_header_sr,
	  { "SR", "v120.header.sr", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x2000,
	  	NULL, HFILL }},
	{ &hf_v120_header_rr,
	  { "RR", "v120.header.rr", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x1000,
	  	NULL, HFILL }},
    };
    static gint *ett[] = {
        &ett_v120,
        &ett_v120_address,
        &ett_v120_control,
        &ett_v120_header,
    };

    proto_v120 = proto_register_protocol("Async data over ISDN (V.120)",
					 "V.120", "v120");
    proto_register_field_array (proto_v120, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("v120", dissect_v120, proto_v120);
}

void
proto_reg_handoff_v120(void)
{
    data_handle = find_dissector("data");
}
