/* packet-lapd.c
 * Routines for LAPD frame disassembly
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/xdlc.h>

#include <epan/lapd_sapi.h>

/* ISDN/LAPD references:
 *
 * http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/isdn.htm
 * http://www.ece.wpi.edu/courses/ee535/hwk11cd95/agrebe/agrebe.html
 * http://www.acacia-net.com/Clarinet/Protocol/q9213o84.htm
 */

static int proto_lapd = -1;
static int hf_lapd_address = -1;
static int hf_lapd_sapi = -1;
static int hf_lapd_cr = -1;
static int hf_lapd_ea1 = -1;
static int hf_lapd_tei = -1;
static int hf_lapd_ea2 = -1;
static int hf_lapd_control = -1;
static int hf_lapd_n_r = -1;
static int hf_lapd_n_s = -1;
static int hf_lapd_p = -1;
static int hf_lapd_p_ext = -1;
static int hf_lapd_f = -1;
static int hf_lapd_f_ext = -1;
static int hf_lapd_s_ftype = -1;
static int hf_lapd_u_modifier_cmd = -1;
static int hf_lapd_u_modifier_resp = -1;
static int hf_lapd_ftype_i = -1;
static int hf_lapd_ftype_s_u = -1;
static int hf_lapd_ftype_s_u_ext = -1;

static gint ett_lapd = -1;
static gint ett_lapd_address = -1;
static gint ett_lapd_control = -1;

static dissector_table_t lapd_sapi_dissector_table;

static dissector_handle_t data_handle;
static dissector_handle_t tei_handle;

/*
 * Bits in the address field.
 */
#define	LAPD_SAPI	0xfc00	/* Service Access Point Identifier */
#define	LAPD_SAPI_SHIFT	10
#define	LAPD_CR		0x0200	/* Command/Response bit */
#define	LAPD_EA1	0x0100	/* First Address Extension bit */
#define	LAPD_TEI	0x00fe	/* Terminal Endpoint Identifier */
#define LAPD_TEI_SHIFT	1
#define	LAPD_EA2	0x0001	/* Second Address Extension bit */

static const value_string lapd_sapi_vals[] = {
	{ LAPD_SAPI_Q931,	"Q.931 Call control procedure" },
	{ LAPD_SAPI_PM_Q931,	"Packet mode Q.931 Call control procedure" },
	{ LAPD_SAPI_X25,	"X.25 Level 3 procedures" },
	{ LAPD_SAPI_L2,		"Layer 2 management procedures" },
	{ 0,			NULL }
};

/* Used only for U frames */
static const xdlc_cf_items lapd_cf_items = {
	NULL,
	NULL,
	&hf_lapd_p,
	&hf_lapd_f,
	NULL,
	&hf_lapd_u_modifier_cmd,
	&hf_lapd_u_modifier_resp,
	NULL,
	&hf_lapd_ftype_s_u
};

/* Used only for I and S frames */
static const xdlc_cf_items lapd_cf_items_ext = {
	&hf_lapd_n_r,
	&hf_lapd_n_s,
	&hf_lapd_p_ext,
	&hf_lapd_f_ext,
	&hf_lapd_s_ftype,
	NULL,
	NULL,
	&hf_lapd_ftype_i,
	&hf_lapd_ftype_s_u_ext
};

static void
dissect_lapd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*lapd_tree, *addr_tree;
	proto_item	*lapd_ti, *addr_ti;
	guint16		control;
	int		lapd_header_len;
	guint16		address, cr, sapi, tei;
	gboolean	is_response = 0;
	tvbuff_t	*next_tvb;
	char		*srcname = "?";
	char		*dstname = "?";

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "LAPD");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	address = tvb_get_ntohs(tvb, 0);
	cr = address & LAPD_CR;
	tei = (address & LAPD_TEI) >> LAPD_TEI_SHIFT;
	sapi = (address & LAPD_SAPI) >> LAPD_SAPI_SHIFT;
	lapd_header_len = 2;	/* address */

	if (check_col(pinfo->cinfo, COL_TEI))
		col_add_fstr(pinfo->cinfo, COL_TEI, "%u", tei);

	if (pinfo->fd->lnk_t == WTAP_ENCAP_LINUX_LAPD) {
		/* frame is captured via libpcap */
		if (pinfo->pseudo_header->lapd.pkttype == 4 /*PACKET_OUTGOING*/) {
			if (pinfo->pseudo_header->lapd.we_network) {
				is_response = cr ? FALSE : TRUE;
				srcname = "Local Network";
				dstname = "Remote User";
			} else {
				srcname = "Local User";
				dstname = "Remote Network";
			}
		}
		else if (pinfo->pseudo_header->lapd.pkttype == 3 /*PACKET_OTHERHOST*/) {
			// We must be a TE, sniffing what other TE transmit

			is_response = cr ? TRUE : FALSE;
			srcname = "Remote User";
			dstname = "Remote Network";
		}
		else {
			// The frame is incoming
			if (pinfo->pseudo_header->lapd.we_network) {
				is_response = cr ? TRUE : FALSE;
				srcname = "Remote User";
				dstname = "Local Network";
			} else {
				is_response = cr ? FALSE : TRUE;
				srcname = "Remote Network";
				dstname = "Local User";
			}
		}
	}
	else if (pinfo->p2p_dir == P2P_DIR_SENT) {
		is_response = cr ? FALSE : TRUE;
		srcname = "Network";
		dstname = "User";
	}
	else if (pinfo->p2p_dir == P2P_DIR_RECV) {
		is_response = cr ? TRUE : FALSE;
		srcname = "User";
		dstname = "Network";
	}

	if(check_col(pinfo->cinfo, COL_RES_DL_SRC))
	    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, srcname);
	if(check_col(pinfo->cinfo, COL_RES_DL_DST))
	    col_set_str(pinfo->cinfo, COL_RES_DL_DST, dstname);

	if (tree) {
		lapd_ti = proto_tree_add_item(tree, proto_lapd, tvb, 0, -1,
		    FALSE);
		lapd_tree = proto_item_add_subtree(lapd_ti, ett_lapd);

		addr_ti = proto_tree_add_uint(lapd_tree, hf_lapd_address, tvb,
		    0, 2, address);
		addr_tree = proto_item_add_subtree(addr_ti, ett_lapd_address);

		proto_tree_add_uint(addr_tree, hf_lapd_sapi,tvb, 0, 1, address);
		proto_tree_add_uint(addr_tree, hf_lapd_cr,  tvb, 0, 1, address);
		proto_tree_add_uint(addr_tree, hf_lapd_ea1, tvb, 0, 1, address);
		proto_tree_add_uint(addr_tree, hf_lapd_tei, tvb, 1, 1, address);
		proto_tree_add_uint(addr_tree, hf_lapd_ea2, tvb, 1, 1, address);
	}
	else {
		lapd_ti = NULL;
		lapd_tree = NULL;
	}

	control = dissect_xdlc_control(tvb, 2, pinfo, lapd_tree, hf_lapd_control,
	    ett_lapd_control, &lapd_cf_items, &lapd_cf_items_ext, NULL, NULL,
	    is_response, TRUE, FALSE);
	lapd_header_len += XDLC_CONTROL_LEN(control, TRUE);

	if (tree)
		proto_item_set_len(lapd_ti, lapd_header_len);

	next_tvb = tvb_new_subset(tvb, lapd_header_len, -1, -1);
	if (XDLC_IS_INFORMATION(control)) {
		/* call next protocol */
		if (!dissector_try_port(lapd_sapi_dissector_table, sapi,
		    next_tvb, pinfo, tree))
			call_dissector(data_handle,next_tvb, pinfo, tree);
	} else
		call_dissector(data_handle,next_tvb, pinfo, tree);
}

void
proto_register_lapd(void)
{
    static hf_register_info hf[] = {
	{ &hf_lapd_address,
	  { "Address Field", "lapd.address", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	"Address", HFILL }},

	{ &hf_lapd_sapi,
	  { "SAPI", "lapd.sapi", FT_UINT16, BASE_DEC, VALS(lapd_sapi_vals), LAPD_SAPI,
	  	"Service Access Point Identifier", HFILL }},

	{ &hf_lapd_cr,
	  { "C/R", "lapd.cr", FT_UINT16, BASE_DEC, NULL, LAPD_CR,
	  	"Command/Response bit", HFILL }},

	{ &hf_lapd_ea1,
	  { "EA1", "lapd.ea1", FT_UINT16, BASE_DEC, NULL, LAPD_EA1,
	  	"First Address Extension bit", HFILL }},

	{ &hf_lapd_tei,
	  { "TEI", "lapd.tei", FT_UINT16, BASE_DEC, NULL, LAPD_TEI,
	  	"Terminal Endpoint Identifier", HFILL }},

	{ &hf_lapd_ea2,
	  { "EA2", "lapd.ea2", FT_UINT16, BASE_DEC, NULL, LAPD_EA2,
	  	"Second Address Extension bit", HFILL }},

	{ &hf_lapd_control,
	  { "Control Field", "lapd.control", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	"Control field", HFILL }},

	{ &hf_lapd_n_r,
	    { "N(R)", "lapd.control.n_r", FT_UINT16, BASE_DEC,
		NULL, XDLC_N_R_EXT_MASK, "", HFILL }},

	{ &hf_lapd_n_s,
	    { "N(S)", "lapd.control.n_s", FT_UINT16, BASE_DEC,
		NULL, XDLC_N_S_EXT_MASK, "", HFILL }},

	{ &hf_lapd_p,
	    { "Poll", "lapd.control.p", FT_BOOLEAN, 8,
		TFS(&flags_set_truth), XDLC_P_F, "", HFILL }},

	{ &hf_lapd_p_ext,
	    { "Poll", "lapd.control.p", FT_BOOLEAN, 16,
		TFS(&flags_set_truth), XDLC_P_F_EXT, "", HFILL }},

	{ &hf_lapd_f,
	    { "Final", "lapd.control.f", FT_BOOLEAN, 8,
		TFS(&flags_set_truth), XDLC_P_F, "", HFILL }},

	{ &hf_lapd_f_ext,
	    { "Final", "lapd.control.f", FT_BOOLEAN, 16,
		TFS(&flags_set_truth), XDLC_P_F_EXT, "", HFILL }},

	{ &hf_lapd_s_ftype,
	    { "Supervisory frame type", "lapd.control.s_ftype", FT_UINT16, BASE_HEX,
		VALS(stype_vals), XDLC_S_FTYPE_MASK, "", HFILL }},

	{ &hf_lapd_u_modifier_cmd,
	    { "Command", "lapd.control.u_modifier_cmd", FT_UINT8, BASE_HEX,
		VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK, "", HFILL }},

	{ &hf_lapd_u_modifier_resp,
	    { "Response", "lapd.control.u_modifier_resp", FT_UINT8, BASE_HEX,
		VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK, "", HFILL }},

	{ &hf_lapd_ftype_i,
	    { "Frame type", "lapd.control.ftype", FT_UINT16, BASE_HEX,
		VALS(ftype_vals), XDLC_I_MASK, "", HFILL }},

	{ &hf_lapd_ftype_s_u,
	    { "Frame type", "lapd.control.ftype", FT_UINT8, BASE_HEX,
		VALS(ftype_vals), XDLC_S_U_MASK, "", HFILL }},

	{ &hf_lapd_ftype_s_u_ext,
	    { "Frame type", "lapd.control.ftype", FT_UINT16, BASE_HEX,
		VALS(ftype_vals), XDLC_S_U_MASK, "", HFILL }},
    };
    static gint *ett[] = {
        &ett_lapd,
        &ett_lapd_address,
        &ett_lapd_control,
    };

    proto_lapd = proto_register_protocol("Link Access Procedure, Channel D (LAPD)",
					 "LAPD", "lapd");
    proto_register_field_array (proto_lapd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("lapd", dissect_lapd, proto_lapd);

    lapd_sapi_dissector_table = register_dissector_table("lapd.sapi",
	    "LAPD SAPI", FT_UINT16, BASE_DEC);
}

void
proto_reg_handoff_lapd(void)
{
	dissector_handle_t lapd_handle;

	data_handle = find_dissector("data");
	tei_handle = find_dissector("tei");


	lapd_handle = create_dissector_handle(dissect_lapd, proto_lapd);
	dissector_add("wtap_encap", WTAP_ENCAP_LINUX_LAPD, lapd_handle);
}
