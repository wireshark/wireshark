/* packet-bofl.c
 * Routines for Wellfleet BOFL dissection
 * Author: Endoh Akira (endoh@netmarks.co.jp)
 *
 * $Id: packet-bofl.c,v 1.1 2003/02/27 02:45:42 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>

#define ETHER_TYPE_BOFL 0x8102
#define BOFL_MIN_LEN    8

/* Initialize the protocol and registered fields */
static int proto_bofl       = -1;
static int hf_bofl_pdu      = -1;
static int hf_bofl_sequence = -1;

/* Initialize the subtree pointers */
static gint ett_bofl = -1;

/* Code to actually dissect the packets */
void
dissect_bofl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *bofl_tree;
    const guint len = tvb_length(tvb);
    guint32     pdu, sequence;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BOFL");

    if (len < BOFL_MIN_LEN) {
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_set_str(pinfo->cinfo, COL_INFO, "(packet too short)");
	    proto_tree_add_text(tree, tvb, 0, len,
		"Wellfleet Breath of Life (packet too short)");
	    return;
    }

    pdu = tvb_get_ntohl(tvb, 0);
    sequence = tvb_get_ntohl(tvb, 4);
    if (check_col(pinfo->cinfo, COL_INFO)) {
	col_clear(pinfo->cinfo, COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO,
	    "PDU: 0x%x  Sequence: %d", pdu, sequence);
    }
    if (tree) {
	ti = proto_tree_add_item(tree, proto_bofl, tvb, 0, len, FALSE);
	bofl_tree = proto_item_add_subtree(ti, ett_bofl);
	proto_tree_add_uint(bofl_tree, hf_bofl_pdu, tvb, 0, 4, pdu);
	proto_tree_add_uint(bofl_tree, hf_bofl_sequence, tvb, 4, 4, sequence);
	if (len > 8)
	    proto_tree_add_text(bofl_tree, tvb, 8, len-8,
		"Padding (%d byte)", len-8);
    }
}


void
proto_register_bofl(void)
{
    static hf_register_info hf[] = {
	{ &hf_bofl_pdu,
	  { "PDU", "bofl.pdu",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "PDU; normally equals 0x01010000 or 0x01011111", HFILL }
	},
	{ &hf_bofl_sequence,
	  { "Sequence", "bofl.sequence",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "incremental counter", HFILL }
	}
    };

    static gint *ett[] = {
	&ett_bofl,
    };

    proto_bofl = proto_register_protocol("Wellfleet Breath of Life",
	"BOFL", "bofl");
    proto_register_field_array(proto_bofl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_bofl(void)
{
    dissector_handle_t bofl_handle;

    bofl_handle = create_dissector_handle(dissect_bofl, proto_bofl);
    dissector_add("ethertype", ETHER_TYPE_BOFL, bofl_handle);
}
