/* packet-v120.c
 * Routines for v120 frame disassembly
 * Bert Driehuis <driehuis@playbeing.org>
 *
 * $Id: packet-v120.c,v 1.8 2000/05/19 23:06:09 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998
 *
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
#include "packet.h"
#include "packet-v120.h"
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

static int dissect_v120_header(const u_char *pd, int offset, frame_data *fd, proto_tree *tree);

void
dissect_v120(const union wtap_pseudo_header *pseudo_header, const u_char *pd,
		frame_data *fd, proto_tree *tree)
{
    proto_tree *v120_tree, *ti, *tc, *address_tree;
    int is_response;
    int addr;
    char info[80];
    int v120len;
    guint16 control;

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "V.120");

    if(check_col(fd, COL_RES_DL_SRC))
	col_add_fstr(fd, COL_RES_DL_SRC, "0x%02X", pd[0]);
    if ((pd[0] & 0x01) != 0x00 && (pd[1] && 0x01) != 0x01)
    {
	if (check_col(fd, COL_INFO))
	    col_add_str(fd, COL_INFO, "Invalid V.120 frame");
	if (tree)
	    ti = proto_tree_add_protocol_format(tree, proto_v120, NullTVB, 0, fd->cap_len,
			                    "Invalid V.120 frame");
	return;
    }

    if (pseudo_header->x25.flags & FROM_DCE) {
	if(check_col(fd, COL_RES_DL_DST))
	    col_add_str(fd, COL_RES_DL_DST, "DTE");
	if(check_col(fd, COL_RES_DL_SRC))
	    col_add_str(fd, COL_RES_DL_SRC, "DCE");
    }
    else {
	if(check_col(fd, COL_RES_DL_DST))
	    col_add_str(fd, COL_RES_DL_DST, "DCE");
	if(check_col(fd, COL_RES_DL_SRC))
	    col_add_str(fd, COL_RES_DL_SRC, "DTE");
    }

    if (((pseudo_header->x25.flags & FROM_DCE) && pd[0] & 0x02) ||
       (!(pseudo_header->x25.flags & FROM_DCE) && !(pd[0] & 0x02)))
	is_response = TRUE;
    else
	is_response = FALSE;

    if (tree) {
	ti = proto_tree_add_protocol_format(tree, proto_v120, NullTVB, 0, 0,
					    "V.120");
	v120_tree = proto_item_add_subtree(ti, ett_v120);
	addr = pd[1] << 8 | pd[0];
	sprintf(info, "LLI: %d C/R: %s",
			((pd[0] & 0xfc) << 5) | ((pd[1] & 0xfe) >> 1),
			pd[0] & 0x02 ? "R" : "C");
	tc = proto_tree_add_text(v120_tree, NullTVB,
			0, 2,
			"Address field: %s", info);
	address_tree = proto_item_add_subtree(tc, ett_v120_address);
	proto_tree_add_text(address_tree, NullTVB, 0, 2,
		    decode_boolean_bitfield(addr, 0x0002, 2*8,
			"Response", "Command"), NULL);
	sprintf(info, "LLI: %d", ((pd[0] & 0xfc) << 5) | ((pd[1] & 0xfe) >> 1));
	proto_tree_add_text(address_tree, NullTVB, 0, 2,
		    decode_numeric_bitfield(addr, 0xfefc, 2*8, info));
	proto_tree_add_text(address_tree, NullTVB, 0, 2,
		    decode_boolean_bitfield(addr, 0x0001, 2*8,
			"EA0 = 1 (Error)", "EA0 = 0"), NULL);
	proto_tree_add_text(address_tree, NullTVB, 0, 2,
		    decode_boolean_bitfield(addr, 0x0100, 2*8,
			"EA1 = 1", "EA1 = 0 (Error)"), NULL);
    }
    else {
	v120_tree = NULL;
	ti = NULL;
    }
    control = dissect_xdlc_control(pd, 2, fd, v120_tree, hf_v120_control,
	    ett_v120_control, is_response, TRUE);
    if (tree) {
	v120len = 2 + XDLC_CONTROL_LEN(control, TRUE);
	if (BYTES_ARE_IN_FRAME(v120len, 1))
		v120len += dissect_v120_header(pd, v120len, fd, v120_tree);
	proto_item_set_len(ti, v120len);
	if (IS_DATA_IN_FRAME(v120len))
		dissect_data(&pd[v120len], v120len, fd, v120_tree);
    }
}

static int
dissect_v120_header(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	char info[80];
	int header_len, nbits;
	int header;
	proto_tree *h_tree, *tc;

	if (pd[offset] & 0x80) {
		header_len = 1;
		header = pd[offset];
	} else {
		header_len = 2;
		header = pd[offset] | pd[offset + 1] << 8;
	}
	nbits = header_len * 8;
	sprintf(info, "Header: B: %d F: %d", pd[offset] & 0x02 ? 1:0,
			pd[offset] & 0x01 ? 1:0);
	tc = proto_tree_add_text(tree, NullTVB,
			offset, header_len,
			"Header octet: %s (0x%02X)", info, pd[offset]);
	h_tree = proto_item_add_subtree(tc, ett_v120_header);
	proto_tree_add_text(h_tree, NullTVB, offset, header_len,
		    decode_boolean_bitfield(header, 0x80, nbits,
			"No extension octet", "Extension octet follows"), NULL);
	proto_tree_add_text(h_tree, NullTVB, offset, header_len,
		    decode_boolean_bitfield(header, 0x40, nbits,
			"Break condition", "No break condition"), NULL);
	sprintf(info, "Error control C1/C2: %d", (header & 0x0c) >> 2);
	proto_tree_add_text(h_tree, NullTVB, offset, header_len,
		    decode_numeric_bitfield(header, 0x0c, nbits, info));
	proto_tree_add_text(h_tree, NullTVB, offset, header_len,
		    decode_boolean_bitfield(header, 0x02, nbits,
			"Segmentation bit B", "No segmentation bit B"), NULL);
	proto_tree_add_text(h_tree, NullTVB, offset, header_len,
		    decode_boolean_bitfield(header, 0x01, nbits,
			"Segmentation bit F", "No segmentation bit F"), NULL);
	if (header_len == 2) {
		proto_tree_add_text(h_tree, NullTVB, offset, header_len,
		    decode_boolean_bitfield(header, 0x8000, nbits,
			"E", "E bit not set (Error)"), NULL);
		proto_tree_add_text(h_tree, NullTVB, offset, header_len,
		    decode_boolean_bitfield(header, 0x4000, nbits,
			"DR", "No DR"), NULL);
		proto_tree_add_text(h_tree, NullTVB, offset, header_len,
		    decode_boolean_bitfield(header, 0x2000, nbits,
			"SR", "No SR"), NULL);
		proto_tree_add_text(h_tree, NullTVB, offset, header_len,
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
		  0x0, "" }},
	{ &hf_v120_control,
	  { "Control Field", "v120.control", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	"" }},
	{ &hf_v120_header,
	  { "Header Field", "v120.header", FT_STRING, BASE_NONE, NULL, 0x0,
	  	"" }},
    };
    static gint *ett[] = {
        &ett_v120,
        &ett_v120_address,
        &ett_v120_control,
        &ett_v120_header,
    };

    proto_v120 = proto_register_protocol ("Async data over ISDN (V.120)", "v120");
    proto_register_field_array (proto_v120, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
