/* packet-xns-llc.c
 * Routines for 3Com's encapsulation of XNS over 802.2 LLC
 * (and other protocols using DSAP 80)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

/* Forward declarations */
void proto_register_3com_xns(void);
void proto_reg_handoff_3com_xns(void);

static int proto_3com_xns = -1;

static int hf_3com_xns_type_ethertype = -1;
static int hf_3com_xns_type_retix_bpdu = -1;

static gint ett_3com_xns = -1;

static const value_string retix_bpdu_type_vals[] = {
	{ 0x0004, "Retix Spanning Tree" },
	{ 0, NULL }
};

static dissector_table_t ethertype_subdissector_table;

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
static int
dissect_3com_xns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *subtree;
	proto_tree *ti;
	guint16 type;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "3Com XNS");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_3com_xns, tvb, 0, 4, ENC_NA);
	subtree = proto_item_add_subtree(ti, ett_3com_xns);

	type = tvb_get_ntohs(tvb, 0);
	next_tvb = tvb_new_subset_remaining(tvb, 2);
	if (type == 0x0004) {
		proto_tree_add_uint(subtree, hf_3com_xns_type_retix_bpdu,
		    tvb, 0, 2, type);
		call_dissector(retix_bpdu_handle, next_tvb, pinfo, tree);
	} else {
		proto_tree_add_uint(subtree, hf_3com_xns_type_ethertype,
		    tvb, 0, 2, type);
		if (!dissector_try_uint(ethertype_subdissector_table,
		    type, next_tvb, pinfo, tree))
			call_data_dissector(next_tvb, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

void
proto_register_3com_xns(void)
{
	static hf_register_info hf[] = {
		/* registered here but handled in ethertype.c */
		{ &hf_3com_xns_type_ethertype,
		{ "Type", "3comxns.type", FT_UINT16, BASE_HEX,
			VALS(etype_vals), 0x0, NULL, HFILL }},

		{ &hf_3com_xns_type_retix_bpdu,
		{ "Type", "3comxns.type", FT_UINT16, BASE_HEX,
			VALS(retix_bpdu_type_vals), 0x0, NULL, HFILL }},
	};

	static gint *ett[] ={
		&ett_3com_xns,
	};

	proto_3com_xns = proto_register_protocol("3Com XNS Encapsulation", "3COMXNS", "3comxns");
	proto_register_field_array(proto_3com_xns, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_3com_xns(void)
{
	dissector_handle_t our_xns_handle;

	retix_bpdu_handle = find_dissector_add_dependency("rbpdu", proto_3com_xns);

	ethertype_subdissector_table = find_dissector_table("ethertype");

	our_xns_handle = create_dissector_handle(dissect_3com_xns, proto_3com_xns);
	dissector_add_uint("llc.dsap", 0x80, our_xns_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
