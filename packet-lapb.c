/* packet-lapb.c
 * Routines for lapb frame disassembly
 * Olivier Abad <oabad@cybercable.fr>
 *
 * $Id: packet-lapb.c,v 1.20 2000/05/28 17:04:10 oabad Exp $
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
#include "packet-lapb.h"
#include "packet-x25.h"
#include "xdlc.h"

#define FROM_DCE	0x80

static int proto_lapb = -1;
static int hf_lapb_address = -1;
static int hf_lapb_control = -1;

static gint ett_lapb = -1;
static gint ett_lapb_control = -1;

void
dissect_lapb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree		*lapb_tree, *ti;
    int			is_response;
    guint8		byte0;
    const guint8	*this_pd;
    int			this_offset;
    tvbuff_t		*next_tvb;

    pinfo->current_proto = "LAPB";

    if (check_col(pinfo->fd, COL_PROTOCOL))
	col_add_str(pinfo->fd, COL_PROTOCOL, "LAPB");

    if (pinfo->pseudo_header->x25.flags & FROM_DCE) {
	if(check_col(pinfo->fd, COL_RES_DL_DST))
	    col_add_str(pinfo->fd, COL_RES_DL_DST, "DTE");
	if(check_col(pinfo->fd, COL_RES_DL_SRC))
	    col_add_str(pinfo->fd, COL_RES_DL_SRC, "DCE");
    }
    else {
	if(check_col(pinfo->fd, COL_RES_DL_DST))
	    col_add_str(pinfo->fd, COL_RES_DL_DST, "DCE");
	if(check_col(pinfo->fd, COL_RES_DL_SRC))
	    col_add_str(pinfo->fd, COL_RES_DL_SRC, "DTE");
    }

    byte0 = tvb_get_guint8(tvb, 0);

    if (byte0 != 0x01 && byte0 != 0x03) /* invalid LAPB frame */
    {
	if (check_col(pinfo->fd, COL_INFO))
	    col_add_str(pinfo->fd, COL_INFO, "Invalid LAPB frame");
	if (tree)
	    ti = proto_tree_add_protocol_format(tree, proto_lapb, tvb, 0,
			    tvb_length(tvb), "Invalid LAPB frame");
	return;
    }

    if (((pinfo->pseudo_header->x25.flags & FROM_DCE) && byte0 == 0x01) ||
       (!(pinfo->pseudo_header->x25.flags & FROM_DCE) && byte0 == 0x03))
	is_response = TRUE;
    else
	is_response = FALSE;

    if (tree) {
	ti = proto_tree_add_protocol_format(tree, proto_lapb, tvb, 0, 2,
					    "LAPB");
	lapb_tree = proto_item_add_subtree(ti, ett_lapb);
	proto_tree_add_uint_format(lapb_tree, hf_lapb_address, tvb, 0, 1, byte0,
				       "Address: 0x%02X", byte0);
    }
    else
        lapb_tree = NULL;

    tvb_compat(tvb, &this_pd, &this_offset);
    dissect_xdlc_control(this_pd, this_offset+1, pinfo->fd, lapb_tree, hf_lapb_control,
	    ett_lapb_control, is_response, FALSE);

    /* not end of frame ==> X.25 */
    if (tvb_length(tvb) > 2) {
	    next_tvb = tvb_new_subset(tvb, 2, -1, -1);
	    dissect_x25(next_tvb, pinfo, tree);
    }
}

void
proto_register_lapb(void)
{
    static hf_register_info hf[] = {
	{ &hf_lapb_address,
	  { "Address Field", "lapb.address", FT_UINT8, BASE_HEX, NULL, 0x0, 
	  	"" }},

	{ &hf_lapb_control,
	  { "Control Field", "lapb.control", FT_UINT8, BASE_HEX, NULL, 0x0,
	  	"" }},
    };
    static gint *ett[] = {
        &ett_lapb,
        &ett_lapb_control,
    };

    proto_lapb = proto_register_protocol ("Link Access Procedure Balanced (LAPB)", "lapb");
    proto_register_field_array (proto_lapb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
