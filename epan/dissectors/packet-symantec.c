/* packet-symantec.c
 * Routines for dissection of packets from the Axent Raptor firewall/
 * Symantec Enterprise Firewall
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

static dissector_table_t ethertype_dissector_table;

/* protocols and header fields */
static int proto_symantec = -1;
static int hf_symantec_if = -1;
static int hf_symantec_etype = -1;

static gint ett_symantec = -1;

static void
dissect_symantec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *symantec_tree = NULL;
	guint16 etype;
	tvbuff_t *next_tvb;

	/*
	 * The first 4 bytes are the IPv4 address of the interface that
	 * captured the data, followed by 2 bytes of 0, then an Ethernet
	 * type, followed by 36 bytes of 0.
	 */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_add_str(pinfo->cinfo, COL_PROTOCOL, "Symantec");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "Symantec Enterprise Firewall");
	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_symantec, tvb,
		    0, 44, "Symantec firewall");
		symantec_tree = proto_item_add_subtree(ti, ett_symantec);
	}
	etype = tvb_get_ntohs(tvb, 6);
	if (tree) {
		proto_tree_add_item(symantec_tree, hf_symantec_if, tvb,
		    0, 4, FALSE);
		proto_tree_add_uint(symantec_tree, hf_symantec_etype, tvb,
		    6, 2, etype);
	}
	next_tvb = tvb_new_subset(tvb, 44, -1, -1);
	dissector_try_port(ethertype_dissector_table, etype, next_tvb, pinfo,
	    tree);
}

void
proto_register_symantec(void)
{
	static hf_register_info hf[] = {
		{ &hf_symantec_if,
		    { "Interface",      "symantec.if", FT_IPv4, BASE_NONE, NULL, 0x0,
			"Interface", HFILL }},
		{ &hf_symantec_etype,
		    { "Type",	"symantec.type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
			"", HFILL }},
	};
	static gint *ett[] = {
		&ett_symantec,
	};

	proto_symantec = proto_register_protocol("Symantec Enterprise Firewall",
	    "Symantec", "symantec");
	proto_register_field_array(proto_symantec, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_symantec(void)
{
	dissector_handle_t symantec_handle;

	ethertype_dissector_table = find_dissector_table("ethertype");

	symantec_handle = create_dissector_handle(dissect_symantec,
	    proto_symantec);
	dissector_add("wtap_encap", WTAP_ENCAP_SYMANTEC, symantec_handle);
}
