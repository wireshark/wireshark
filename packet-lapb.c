/* packet-lapb.c
 * Routines for lapb frame disassembly
 * Olivier Abad <abad@daba.dhis.org>
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

int proto_lapb = -1;
int hf_lapb_address = -1;
int hf_lapb_control = -1;

void
dissect_lapb(const u_char *pd, frame_data *fd, proto_tree *tree)
{
    proto_tree *lapb_tree, *ti;
    int is_response;

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "LAPB");

    if(check_col(fd, COL_RES_DL_SRC))
	col_add_fstr(fd, COL_RES_DL_SRC, "0x%02X", pd[0]);
    if (fd->flags & FROM_DCE) {
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

    if (((fd->flags & FROM_DCE) && pd[0] == 0x01) ||
       (!(fd->flags & FROM_DCE) && pd[0] == 0x03))
	is_response = TRUE;
    else
	is_response = FALSE;

    if (tree) {
	ti = proto_tree_add_item_format(tree, proto_lapb, 0, 2, NULL,
					    "LAPB");
	lapb_tree = proto_item_add_subtree(ti, ETT_LAPB);
	proto_tree_add_item_format(lapb_tree, hf_lapb_address, 0, 1, pd[0],
				       "Address: 0x%02X", pd[0]);
    }
    else
        lapb_tree = NULL;
    dissect_xdlc_control(pd, 1, fd, lapb_tree, hf_lapb_control,
	    is_response, FALSE);

    /* not end of frame ==> X.25 */
    if (fd->cap_len > 2) dissect_x25(pd, 2, fd, tree);
}

void
proto_register_lapb(void)
{
    static hf_register_info hf[] = {
	{ &hf_lapb_address,
	  { "Address Field", "lapb.address", FT_UINT8, NULL} },
	{ &hf_lapb_control,
	  { "Control Field", "lapb.control", FT_STRING, NULL} },
    };

    proto_lapb = proto_register_protocol ("LAPB", "lapb");
    proto_register_field_array (proto_lapb, hf, array_length(hf));
}
