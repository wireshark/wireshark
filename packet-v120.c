/* packet-v120.c
 * Routines for v120 frame disassembly
 * Bert Driehuis <driehuis@playbeing.org>
 *
 * $Id: packet-v120.c,v 1.1 1999/12/12 22:39:29 gram Exp $
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
#include "xdlc.h"

#define FROM_DCE	0x80

static int proto_v120 = -1;
static int hf_v120_address = -1;
static int hf_v120_control = -1;

static gint ett_v120 = -1;
static gint ett_v120_address = -1;
static gint ett_v120_control = -1;

void
dissect_v120(const u_char *pd, frame_data *fd, proto_tree *tree)
{
    proto_tree *v120_tree, *ti, *tc, *address_tree;
    int is_response;
    int addr;
    char info[80];
    int v120len;

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "V.120");

    if(check_col(fd, COL_RES_DL_SRC))
	col_add_fstr(fd, COL_RES_DL_SRC, "0x%02X", pd[0]);
    if ((pd[0] & 0x01) != 0x00 && (pd[1] && 0x01) != 0x01)
    {
	if (check_col(fd, COL_INFO))
	    col_add_str(fd, COL_INFO, "Invalid V.120 frame");
	if (tree)
	    ti = proto_tree_add_item_format(tree, proto_v120, 0, fd->cap_len,
			                    NULL, "Invalid V.120 frame");
	return;
    }

    if (fd->pseudo_header.x25.flags & FROM_DCE) {
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

    if (((fd->pseudo_header.x25.flags & FROM_DCE) && pd[0] & 0x02) ||
       (!(fd->pseudo_header.x25.flags & FROM_DCE) && !(pd[0] & 0x02)))
	is_response = TRUE;
    else
	is_response = FALSE;

    if (tree) {
	if (fd->pkt_len <= 5)
		v120len = fd->pkt_len;
	else
		v120len = 5;
	ti = proto_tree_add_item_format(tree, proto_v120, 0, v120len, NULL,
					    "V.120");
	v120_tree = proto_item_add_subtree(ti, ett_v120);
	addr = pd[0] << 8 | pd[1];
	sprintf(info, "LLI: %d C/R: %s",
			((pd[0] & 0xfc) << 5) | ((pd[1] & 0xfe) >> 1),
			pd[0] & 0x02 ? "R" : "C");
	tc = proto_tree_add_item_format(v120_tree, ett_v120_address,
			0, 2,
			"Address field: %s (0x%02X)", info, addr);
	address_tree = proto_item_add_subtree(tc, ett_v120_address);
	proto_tree_add_text(address_tree, 0, 2,
		    decode_boolean_bitfield(addr, 0x0200, 2*8,
			"Response", "Command"), NULL);
	sprintf(info, "LLI: %d", ((pd[0] & 0xfc) << 5) | ((pd[1] & 0xfe) >> 1));
	proto_tree_add_text(address_tree, 0, 2,
		    decode_numeric_bitfield(addr, 0xfcfe, 2*8, info));
	proto_tree_add_text(address_tree, 0, 2,
		    decode_boolean_bitfield(addr, 0x0100, 2*8,
			"EA0 = 1 (Error)", "EA0 = 0"), NULL);
	proto_tree_add_text(address_tree, 0, 2,
		    decode_boolean_bitfield(addr, 0x01, 2*8,
			"EA1 = 1", "EA1 = 0 (Error)"), NULL);
	/* TODO: parse octets 4 & 5. Not that they're used in
	   practice, but it looks so professional. */
    }
    else
        v120_tree = NULL;
    dissect_xdlc_control(pd, 2, fd, v120_tree, hf_v120_control,
	    ett_v120_control, is_response, v120len == 3 ? FALSE : TRUE);

    /* not end of frame ==> X.25 */
}

void
proto_register_v120(void)
{
    static hf_register_info hf[] = {
	{ &hf_v120_address,
	  { "Link Address", "v120.address", FT_UINT16, BASE_HEX, NULL,
		  0x0, "" }},
	{ &hf_v120_control,
	  { "Control Field", "v120.control", FT_STRING, BASE_NONE, NULL, 0x0,
	  	"" }},
    };
    static gint *ett[] = {
        &ett_v120,
        &ett_v120_address,
        &ett_v120_control,
    };

    proto_v120 = proto_register_protocol ("Async data over ISDN (V.120)", "v120");
    proto_register_field_array (proto_v120, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
