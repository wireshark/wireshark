/* packet-v120.c
 * Routines for v120 frame disassembly
 * Bert Driehuis <driehuis@playbeing.org>
 *
 * $Id: packet-v120.c,v 1.24 2002/01/21 07:36:44 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include "xdlc.h"

#define FROM_DCE	0x80

static int proto_v120 = -1;
static int hf_v120_address = -1;
static int hf_v120_control = -1;
static int hf_v120_header = -1;

static gint ett_v120 = -1;
static gint ett_v120_address = -1;
static gint ett_v120_control = -1;
static gint ett_v120_header = -1;

static dissector_handle_t data_handle;

static int dissect_v120_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static void
dissect_v120(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree	*v120_tree, *tc, *address_tree;
    proto_item	*ti;
    int		is_response;
    int		addr;
    char	info[80];
    int		v120len;
    guint8	byte0, byte1;
    guint16	control;
    tvbuff_t	*next_tvb;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "V.120");
    if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

    byte0 = tvb_get_guint8(tvb, 0);

    if(check_col(pinfo->cinfo, COL_RES_DL_SRC))
	col_add_fstr(pinfo->cinfo, COL_RES_DL_SRC, "0x%02X", byte0);

    byte1 = tvb_get_guint8(tvb, 1);

    if ((byte0 & 0x01) != 0x00 && (byte1 && 0x01) != 0x01)
    {
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_set_str(pinfo->cinfo, COL_INFO, "Invalid V.120 frame");
	if (tree)
	    ti = proto_tree_add_protocol_format(tree, proto_v120, tvb, 0, -1,
			                    "Invalid V.120 frame");
	return;
    }

    if (pinfo->pseudo_header->x25.flags & FROM_DCE) {
	if(check_col(pinfo->cinfo, COL_RES_DL_DST))
	    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DTE");
	if(check_col(pinfo->cinfo, COL_RES_DL_SRC))
	    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DCE");
    }
    else {
	if(check_col(pinfo->cinfo, COL_RES_DL_DST))
	    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DCE");
	if(check_col(pinfo->cinfo, COL_RES_DL_SRC))
	    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DTE");
    }

    if (((pinfo->pseudo_header->x25.flags & FROM_DCE) && byte0 & 0x02) ||
       (!(pinfo->pseudo_header->x25.flags & FROM_DCE) && !(byte0 & 0x02)))
	is_response = TRUE;
    else
	is_response = FALSE;

    if (tree) {
	ti = proto_tree_add_protocol_format(tree, proto_v120, tvb, 0, -1, "V.120");
	v120_tree = proto_item_add_subtree(ti, ett_v120);
	addr = byte1 << 8 | byte0;
	sprintf(info, "LLI: %d C/R: %s",
			((byte0 & 0xfc) << 5) | ((byte1 & 0xfe) >> 1),
			byte0 & 0x02 ? "R" : "C");
	tc = proto_tree_add_text(v120_tree, tvb,
			0, 2,
			"Address field: %s", info);
	address_tree = proto_item_add_subtree(tc, ett_v120_address);
	proto_tree_add_text(address_tree, tvb, 0, 2,
		    decode_boolean_bitfield(addr, 0x0002, 2*8,
			"Response", "Command"), NULL);
	sprintf(info, "LLI: %d", ((byte0 & 0xfc) << 5) | ((byte1 & 0xfe) >> 1));
	proto_tree_add_text(address_tree, tvb, 0, 2,
		    decode_numeric_bitfield(addr, 0xfefc, 2*8, info));
	proto_tree_add_text(address_tree, tvb, 0, 2,
		    decode_boolean_bitfield(addr, 0x0001, 2*8,
			"EA0 = 1 (Error)", "EA0 = 0"), NULL);
	proto_tree_add_text(address_tree, tvb, 0, 2,
		    decode_boolean_bitfield(addr, 0x0100, 2*8,
			"EA1 = 1", "EA1 = 0 (Error)"), NULL);
    }
    else {
	v120_tree = NULL;
	ti = NULL;
    }
    control = dissect_xdlc_control(tvb, 2, pinfo, v120_tree, hf_v120_control,
	    ett_v120_control, is_response, TRUE);
    if (tree) {
	v120len = 2 + XDLC_CONTROL_LEN(control, TRUE);
	if (tvb_bytes_exist(tvb, v120len, 1))
		v120len += dissect_v120_header(tvb, v120len, pinfo, v120_tree);
	proto_item_set_len(ti, v120len);
	next_tvb = tvb_new_subset(tvb, v120len, -1, -1);
	call_dissector(data_handle,next_tvb, pinfo, v120_tree);
    }
}

static int
dissect_v120_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	char info[80];
	int header_len, nbits;
	int header;
	proto_tree *h_tree, *tc;
	guint8	byte0;

	byte0 = tvb_get_guint8(tvb, offset);

	if (byte0 & 0x80) {
		header_len = 1;
		header = byte0;
	} else {
		header_len = 2;
		header = byte0 | tvb_get_guint8(tvb, offset + 1) << 8;
	}
	nbits = header_len * 8;
	sprintf(info, "Header: B: %d F: %d", byte0 & 0x02 ? 1:0,
			byte0 & 0x01 ? 1:0);
	tc = proto_tree_add_text(tree, tvb,
			offset, header_len,
			"Header octet: %s (0x%02X)", info, byte0);
	h_tree = proto_item_add_subtree(tc, ett_v120_header);
	proto_tree_add_text(h_tree, tvb, offset, header_len,
		    decode_boolean_bitfield(header, 0x80, nbits,
			"No extension octet", "Extension octet follows"), NULL);
	proto_tree_add_text(h_tree, tvb, offset, header_len,
		    decode_boolean_bitfield(header, 0x40, nbits,
			"Break condition", "No break condition"), NULL);
	sprintf(info, "Error control C1/C2: %d", (header & 0x0c) >> 2);
	proto_tree_add_text(h_tree, tvb, offset, header_len,
		    decode_numeric_bitfield(header, 0x0c, nbits, info));
	proto_tree_add_text(h_tree, tvb, offset, header_len,
		    decode_boolean_bitfield(header, 0x02, nbits,
			"Segmentation bit B", "No segmentation bit B"), NULL);
	proto_tree_add_text(h_tree, tvb, offset, header_len,
		    decode_boolean_bitfield(header, 0x01, nbits,
			"Segmentation bit F", "No segmentation bit F"), NULL);
	if (header_len == 2) {
		proto_tree_add_text(h_tree, tvb, offset, header_len,
		    decode_boolean_bitfield(header, 0x8000, nbits,
			"E", "E bit not set (Error)"), NULL);
		proto_tree_add_text(h_tree, tvb, offset, header_len,
		    decode_boolean_bitfield(header, 0x4000, nbits,
			"DR", "No DR"), NULL);
		proto_tree_add_text(h_tree, tvb, offset, header_len,
		    decode_boolean_bitfield(header, 0x2000, nbits,
			"SR", "No SR"), NULL);
		proto_tree_add_text(h_tree, tvb, offset, header_len,
		    decode_boolean_bitfield(header, 0x1000, nbits,
			"RR", "No RR"), NULL);
	}
	return header_len;
}

void
proto_register_v120(void)
{
    static hf_register_info hf[] = {
	{ &hf_v120_address,
	  { "Link Address", "v120.address", FT_UINT16, BASE_HEX, NULL,
		  0x0, "", HFILL }},
	{ &hf_v120_control,
	  { "Control Field", "v120.control", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	"", HFILL }},
	{ &hf_v120_header,
	  { "Header Field", "v120.header", FT_STRING, BASE_NONE, NULL, 0x0,
	  	"", HFILL }},
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
}

void
proto_reg_handoff_v120(void)
{
    dissector_handle_t v120_handle;

    data_handle = find_dissector("data");
    v120_handle = create_dissector_handle(dissect_v120, proto_v120);
    dissector_add("wtap_encap", WTAP_ENCAP_V120, v120_handle);
}
