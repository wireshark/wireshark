/* packet-v5dl.c
 * Routines for V5 data link frame disassembly
 * Rolf Fiedler <rolf.fiedler@innoventif.de> using the LAPD code of
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id$
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
/*
 * V5 Data Link Layer
 *
 * V5 references:
 * ETS 300 324-1
 * ETS 300 347-1
 *
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/xdlc.h>
#include <epan/crc16-tvb.h>

static int proto_v5dl = -1;
static int hf_v5dl_direction = -1;
static int hf_v5dl_address = -1;
static int hf_v5dl_ef = -1;
static int hf_v5dl_eah = -1;
static int hf_v5dl_cr = -1;
static int hf_v5dl_ea1 = -1;
static int hf_v5dl_eal = -1;
static int hf_v5dl_ea2 = -1;
static int hf_v5dl_control = -1;
static int hf_v5dl_n_r = -1;
static int hf_v5dl_n_s = -1;
static int hf_v5dl_p = -1;
static int hf_v5dl_p_ext = -1;
static int hf_v5dl_f = -1;
static int hf_v5dl_f_ext = -1;
static int hf_v5dl_s_ftype = -1;
static int hf_v5dl_u_modifier_cmd = -1;
static int hf_v5dl_u_modifier_resp = -1;
static int hf_v5dl_ftype_i = -1;
static int hf_v5dl_ftype_s_u = -1;
static int hf_v5dl_ftype_s_u_ext = -1;
static int hf_v5dl_checksum = -1;
static int hf_v5dl_checksum_good = -1;
static int hf_v5dl_checksum_bad = -1;

static gint ett_v5dl = -1;
static gint ett_v5dl_address = -1;
static gint ett_v5dl_control = -1;
static gint ett_v5dl_checksum = -1;

static dissector_handle_t v52_handle;

/*
 * Bits in the address field.
 */
#define	V5DL_EAH		0xfc00	/* Service Access Point Identifier */
#define	V5DL_EAH_SHIFT		10
#define	V5DL_CR			0x0200	/* Command/Response bit */
#define	V5DL_EA1		0x0100	/* First Address Extension bit */
#define	V5DL_EAL		0x00fe	/* Terminal Endpoint Identifier */
#define	V5DL_EAL_SHIFT		1
#define	V5DL_EA2		0x0001	/* Second Address Extension bit */

static const value_string v5dl_direction_vals[] = {
	{ P2P_DIR_RECV,		"Network->User"},
	{ P2P_DIR_SENT,		"User->Network"},
	{ 0,			NULL }
};

static const value_string v5dl_addr_vals[] = {
	{ 8175, "ISDN Protocol" },
	{ 8176, "PSTN Protocol" },
	{ 8177, "CONTROL Protocol" },
	{ 8178, "BCC Protocol" },
	{ 8179, "PROT Protocol" },
	{ 8180, "Link Control Protocol" },
	{ 8191, "VALUE RESERVED" },
	{ 0,	NULL } };

/* Used only for U frames */
static const xdlc_cf_items v5dl_cf_items = {
	NULL,
	NULL,
	&hf_v5dl_p,
	&hf_v5dl_f,
	NULL,
	&hf_v5dl_u_modifier_cmd,
	&hf_v5dl_u_modifier_resp,
	NULL,
	&hf_v5dl_ftype_s_u
};

/* Used only for I and S frames */
static const xdlc_cf_items v5dl_cf_items_ext = {
	&hf_v5dl_n_r,
	&hf_v5dl_n_s,
	&hf_v5dl_p_ext,
	&hf_v5dl_f_ext,
	&hf_v5dl_s_ftype,
	NULL,
	NULL,
	&hf_v5dl_ftype_i,
	&hf_v5dl_ftype_s_u_ext
};


#define MAX_V5DL_PACKET_LEN 1024

static void
dissect_v5dl(tvbuff_t*, packet_info*, proto_tree*);

static void
dissect_v5dl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*v5dl_tree, *addr_tree;
	proto_item	*v5dl_ti, *addr_ti;
	int		direction;
	guint		v5dl_header_len;
	guint16		control;
#if 0
	proto_tree	*checksum_tree;
	proto_item	*checksum_ti;
	guint16		checksum, checksum_calculated;
	guint		checksum_offset;
#endif
	guint16		addr, cr, eah, eal, v5addr;
	gboolean	is_response = 0;
#if 0
	guint		length, reported_length;
#endif
	tvbuff_t	*next_tvb;
	const char	*srcname = "?";
	const char	*dstname = "?";

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "V5DL");
	col_clear(pinfo->cinfo, COL_INFO);

	addr = tvb_get_ntohs(tvb, 0);
	cr = addr & V5DL_CR;
	eal = (addr & V5DL_EAL) >> V5DL_EAL_SHIFT;
	eah = (addr & V5DL_EAH) >> V5DL_EAH_SHIFT;
	v5addr = (eah << 7) + eal;
	v5dl_header_len = 2;	/* addr */

	direction = pinfo->p2p_dir;
	if (pinfo->p2p_dir == P2P_DIR_RECV) {
	    is_response = cr ? FALSE : TRUE;
	    srcname = "Network";
	    dstname = "User";
	}
	else if (pinfo->p2p_dir == P2P_DIR_SENT) {
	    is_response = cr ? TRUE : FALSE;
	    srcname = "User";
	    dstname = "Network";
	}

	col_set_str(pinfo->cinfo, COL_RES_DL_SRC, srcname);
	col_set_str(pinfo->cinfo, COL_RES_DL_DST, dstname);

	if (tree) {
		proto_item *direction_ti;

		v5dl_ti = proto_tree_add_item(tree, proto_v5dl, tvb, 0, -1,
		    ENC_NA);
		v5dl_tree = proto_item_add_subtree(v5dl_ti, ett_v5dl);

		/*
		 * Don't show the direction if we don't know it.
		 */
		if (direction != P2P_DIR_UNKNOWN) {
			direction_ti = proto_tree_add_uint(v5dl_tree, hf_v5dl_direction,
			                                   tvb, 0, 0, pinfo->p2p_dir);
			PROTO_ITEM_SET_GENERATED(direction_ti);
		}

		addr_ti = proto_tree_add_uint(v5dl_tree, hf_v5dl_ef, tvb,
		    0, 2, v5addr);
		addr_tree = proto_item_add_subtree(addr_ti, ett_v5dl_address);
		proto_tree_add_uint(addr_tree, hf_v5dl_eah, tvb, 0, 1, addr);
		proto_tree_add_uint(addr_tree, hf_v5dl_cr,  tvb, 0, 1, addr);
		proto_tree_add_uint(addr_tree, hf_v5dl_ea1, tvb, 0, 1, addr);
		proto_tree_add_uint(addr_tree, hf_v5dl_eal, tvb, 1, 1, addr);
		proto_tree_add_uint(addr_tree, hf_v5dl_ea2, tvb, 1, 1, addr);
	}
	else {
		v5dl_ti = NULL;
		v5dl_tree = NULL;
	}

	control = dissect_xdlc_control(tvb, 2, pinfo, v5dl_tree, hf_v5dl_control,
	    ett_v5dl_control, &v5dl_cf_items, &v5dl_cf_items_ext, NULL, NULL,
	    is_response, TRUE, FALSE);
	v5dl_header_len += XDLC_CONTROL_LEN(control, TRUE);

	if (tree)
		proto_item_set_len(v5dl_ti, v5dl_header_len);

	/*
	 * XXX - the sample capture supplied with bug 7027 does not
	 * appear to include checksums in the packets.
	 */
#if 0
	/*
	 * Check the checksum, if available.
	 * The checksum is a CCITT CRC-16 at the end of the packet, so
	 * if we don't have the entire packet in the capture - i.e., if
	 * tvb_length(tvb) != tvb_reported_length(tvb) we can't check it.
	 */
	length = tvb_length(tvb);
	reported_length = tvb_reported_length(tvb);

	/*
	 * If the reported length isn't big enough for the V5DL header
	 * and 2 bytes of checksum, the packet is malformed, as the
	 * checksum overlaps the header.
	 */
	if (reported_length < v5dl_header_len + 2)
		THROW(ReportedBoundsError);

	if (length == reported_length) {
		/*
		 * There's no snapshot length cutting off any of the
		 * packet.
		 */
		checksum_offset = reported_length - 2;
		checksum = tvb_get_ntohs(tvb, checksum_offset);
		checksum_calculated = crc16_ccitt_tvb(tvb, checksum_offset);
		checksum_calculated = g_htons(checksum_calculated);  /* Note: g_htons() macro may eval arg multiple times */

		if (checksum == checksum_calculated) {
			checksum_ti = proto_tree_add_uint_format(v5dl_tree, hf_v5dl_checksum, tvb, checksum_offset,
								 2, 0,
								 "Checksum: 0x%04x [correct]",
								 checksum);
			checksum_tree = proto_item_add_subtree(checksum_ti, ett_v5dl_checksum);
			proto_tree_add_boolean(checksum_tree, hf_v5dl_checksum_good, tvb, checksum_offset, 2, TRUE);
			proto_tree_add_boolean(checksum_tree, hf_v5dl_checksum_bad, tvb, checksum_offset, 2, FALSE);
		} else {
			checksum_ti = proto_tree_add_uint_format(v5dl_tree, hf_v5dl_checksum, tvb, checksum_offset,
								 2, 0,
								 "Checksum: 0x%04x [incorrect, should be 0x%04x]",
								 checksum, checksum_calculated);
			checksum_tree = proto_item_add_subtree(checksum_ti, ett_v5dl_checksum);
			proto_tree_add_boolean(checksum_tree, hf_v5dl_checksum_good, tvb, checksum_offset, 2, FALSE);
			proto_tree_add_boolean(checksum_tree, hf_v5dl_checksum_bad, tvb, checksum_offset, 2, TRUE);
		}

		/*
		 * Remove the V5DL header *and* the checksum.
		 */
		next_tvb = tvb_new_subset(tvb, v5dl_header_len,
		    tvb_length_remaining(tvb, v5dl_header_len) - 2,
		    tvb_reported_length_remaining(tvb, v5dl_header_len) - 2);
	} else {
		/*
		 * Some or all of the packet is cut off by a snapshot
		 * length.
		 */
		if (length == reported_length - 1) {
			/*
			 * One byte is cut off, so there's only one
			 * byte of checksum in the captured data.
			 * Remove that byte from the captured length
			 * and both bytes from the reported length.
			 */
			next_tvb = tvb_new_subset(tvb, v5dl_header_len,
			    tvb_length_remaining(tvb, v5dl_header_len) - 1,
			    tvb_reported_length_remaining(tvb, v5dl_header_len) - 2);
		} else {
			/*
			 * Two or more bytes are cut off, so there are
			 * no bytes of checksum in the captured data.
			 * Just remove the checksum from the reported
			 * length.
			 */
			next_tvb = tvb_new_subset(tvb, v5dl_header_len,
			    tvb_length_remaining(tvb, v5dl_header_len),
			    tvb_reported_length_remaining(tvb, v5dl_header_len) - 2);
		}
	}
#else
	next_tvb = tvb_new_subset_remaining(tvb, v5dl_header_len);
#endif

	if (XDLC_IS_INFORMATION(control)) {
		/* call V5.2 dissector */
	        call_dissector(v52_handle, next_tvb, pinfo, tree);
	}
}

void
proto_reg_handoff_v5dl(void);

void
proto_register_v5dl(void)
{
	static hf_register_info hf[] = {

	{ &hf_v5dl_direction,
	  { "Direction", "v5dl.direction", FT_UINT8, BASE_DEC, VALS(v5dl_direction_vals), 0x0,
	  	NULL, HFILL }},

	{ &hf_v5dl_address,
	  { "Address Field", "v5dl.address", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	"Address", HFILL }},

	{ &hf_v5dl_ef,
	  { "EF", "v5dl.ef", FT_UINT16, BASE_DEC, VALS(v5dl_addr_vals), 0x0,
	  	"Envelope Function Address", HFILL }},

	{ &hf_v5dl_eah,
	  { "EAH", "v5dl.eah", FT_UINT16, BASE_DEC, NULL, V5DL_EAH,
	  	"Envelope Address High", HFILL }},

	{ &hf_v5dl_cr,
	  { "C/R", "v5dl.cr", FT_UINT16, BASE_DEC, NULL, V5DL_CR,
	  	"Command/Response bit", HFILL }},

	{ &hf_v5dl_ea1,
	  { "EA1", "v5dl.ea1", FT_UINT16, BASE_DEC, NULL, V5DL_EA1,
	  	"First Address Extension bit", HFILL }},

	{ &hf_v5dl_eal,
	  { "EAL", "v5dl.eal", FT_UINT16, BASE_DEC, NULL, V5DL_EAL,
	  	"Envelope Address Low", HFILL }},

	{ &hf_v5dl_ea2,
	  { "EA2", "v5dl.ea2", FT_UINT16, BASE_DEC, NULL, V5DL_EA2,
	  	"Second Address Extension bit", HFILL }},

	{ &hf_v5dl_control,
	  { "Control Field", "v5dl.control", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	NULL, HFILL }},

	{ &hf_v5dl_n_r,
	  { "N(R)", "v5dl.control.n_r", FT_UINT16, BASE_DEC,
		NULL, XDLC_N_R_EXT_MASK, NULL, HFILL }},

	{ &hf_v5dl_n_s,
	  { "N(S)", "v5dl.control.n_s", FT_UINT16, BASE_DEC,
		NULL, XDLC_N_S_EXT_MASK, NULL, HFILL }},

	{ &hf_v5dl_p,
	  { "Poll", "v5dl.control.p", FT_BOOLEAN, 8,
		TFS(&tfs_set_notset), XDLC_P_F, NULL, HFILL }},

	{ &hf_v5dl_p_ext,
	  { "Poll", "v5dl.control.p", FT_BOOLEAN, 16,
		TFS(&tfs_set_notset), XDLC_P_F_EXT, NULL, HFILL }},

	{ &hf_v5dl_f,
	  { "Final", "v5dl.control.f", FT_BOOLEAN, 8,
		TFS(&tfs_set_notset), XDLC_P_F, NULL, HFILL }},

	{ &hf_v5dl_f_ext,
	  { "Final", "v5dl.control.f", FT_BOOLEAN, 16,
		TFS(&tfs_set_notset), XDLC_P_F_EXT, NULL, HFILL }},

	{ &hf_v5dl_s_ftype,
	  { "Supervisory frame type", "v5dl.control.s_ftype", FT_UINT16, BASE_HEX,
		VALS(stype_vals), XDLC_S_FTYPE_MASK, NULL, HFILL }},

	{ &hf_v5dl_u_modifier_cmd,
	  { "Command", "v5dl.control.u_modifier_cmd", FT_UINT8, BASE_HEX,
		VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK, NULL, HFILL }},

	{ &hf_v5dl_u_modifier_resp,
	  { "Response", "v5dl.control.u_modifier_resp", FT_UINT8, BASE_HEX,
		VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK, NULL, HFILL }},

	{ &hf_v5dl_ftype_i,
	  { "Frame type", "v5dl.control.ftype", FT_UINT16, BASE_HEX,
		VALS(ftype_vals), XDLC_I_MASK, NULL, HFILL }},

	{ &hf_v5dl_ftype_s_u,
	  { "Frame type", "v5dl.control.ftype", FT_UINT8, BASE_HEX,
		VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL }},

	{ &hf_v5dl_ftype_s_u_ext,
	  { "Frame type", "v5dl.control.ftype", FT_UINT16, BASE_HEX,
		VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL }},

	{ &hf_v5dl_checksum,
	  { "Checksum", "v5dl.checksum", FT_UINT16, BASE_HEX,
		NULL, 0x0, "Details at: http://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }},

	{ &hf_v5dl_checksum_good,
	  { "Good Checksum", "v5dl.checksum_good", FT_BOOLEAN, BASE_NONE,
		NULL, 0x0, "True: checksum matches packet content; False: doesn't match content or not checked", HFILL }},

	{ &hf_v5dl_checksum_bad,
	  { "Bad Checksum", "v5dl.checksum_bad", FT_BOOLEAN, BASE_NONE,
		NULL, 0x0, "True: checksum doesn't match packet content; False: matches content or not checked", HFILL }}
	};

	static gint *ett[] = {
		&ett_v5dl,
		&ett_v5dl_address,
		&ett_v5dl_control,
		&ett_v5dl_checksum
	};

	proto_v5dl = proto_register_protocol("V5 Data Link Layer",
					     "V5DL", "v5dl");
	proto_register_field_array (proto_v5dl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("v5dl", dissect_v5dl, proto_v5dl);
}

void
proto_reg_handoff_v5dl(void)
{
	v52_handle = find_dissector("v52");
}
