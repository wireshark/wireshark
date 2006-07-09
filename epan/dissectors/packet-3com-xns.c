/* packet-xns-llc.c
 * Routines for 3Com's encapsulation of XNS over 802.2 LLC
 * (and other protocols using DSAP 80)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>

static int proto_3com_xns = -1;

static int hf_3com_xns_type_ethertype = -1;
static int hf_3com_xns_type_retix_bpdu = -1;

static gint ett_3com_xns = -1;

static const value_string retix_bpdu_type_vals[] = {
	{ 0x0004, "Retix Spanning Tree" },
	{ 0, NULL }
};

static dissector_handle_t retix_bpdu_handle;

/*
 * Apparently 3Com had some scheme for encapsulating XNS in 802.2 LLC,
 * using a DSAP and SSAP of 0x80, and putting a 2-byte field that appeared
 * to contain, at least for IPP, the Ethertype value for IPP.
 *
 * We assume that the value there is an Ethertype value, except for
 * the Retix spanning tree protocol, which also uses a DSAP and SSAP
 * of 0x80 but has, at least in one capture, 0x0004 as the type
 * field.  We handle that specially.
 *
 * XXX - I've also seen packets on 802.11 with a DSAP and SSAP of 0x80,
 * but with random stuff that appears neither to be XNS nor Retix
 * spanning tree.
 */
static void
dissect_3com_xns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *subtree = NULL;
	proto_tree *ti;
	guint16 type;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "3Com XNS");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_3com_xns, tvb, 0, 4, FALSE);
		subtree = proto_item_add_subtree(ti, ett_3com_xns);
	}

	type = tvb_get_ntohs(tvb, 0);
	if (type == 0x0004) {
		proto_tree_add_uint(subtree, hf_3com_xns_type_retix_bpdu,
		    tvb, 0, 2, type);
		call_dissector(retix_bpdu_handle,
		    tvb_new_subset(tvb, 2, -1, -1), pinfo, tree);
	} else {
		ethertype(type, tvb, 2, pinfo, tree, subtree,
		    hf_3com_xns_type_ethertype, -1, 0);
	}
}

void proto_register_3com_xns(void);

void
proto_register_3com_xns(void)
{
	static hf_register_info hf[] = {
		/* registered here but handled in ethertype.c */
		{ &hf_3com_xns_type_ethertype,
		{ "Type", "xnsllc.type", FT_UINT16, BASE_HEX,
			VALS(etype_vals), 0x0, "", HFILL }},

		{ &hf_3com_xns_type_retix_bpdu,
		{ "Type", "xnsllc.type", FT_UINT16, BASE_HEX,
			VALS(retix_bpdu_type_vals), 0x0, "", HFILL }},
	};

	static gint *ett[] ={
		&ett_3com_xns,
	};

	proto_3com_xns = proto_register_protocol("3Com XNS Encapsulation", "3COMXNS", "3comxns");
	proto_register_field_array(proto_3com_xns, hf, array_length(hf)); 
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_3com_xns(void);

void
proto_reg_handoff_3com_xns(void)
{
	dissector_handle_t our_xns_handle;

	retix_bpdu_handle = find_dissector("rbpdu");

	our_xns_handle = create_dissector_handle(dissect_3com_xns,
	    proto_3com_xns);
	dissector_add("llc.dsap", 0x80, our_xns_handle);
}
