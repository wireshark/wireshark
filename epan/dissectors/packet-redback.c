/* packet-redback.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * Start of RedBack SmartEdge 400/800 tcpdump trace disassembly
 * Copyright 2005-2008 Florian Lohoff <flo@rfc822.org>
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
#include "packet-ip.h"

static int proto_redback = -1;
static gint ett_redback = -1;

static dissector_table_t osinl_subdissector_table;
static dissector_table_t osinl_excl_subdissector_table;

static dissector_handle_t ipv4_handle;
static dissector_handle_t ethnofcs_handle;
static dissector_handle_t clnp_handle;
static dissector_handle_t arp_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t ppphdlc_handle;
static dissector_handle_t data_handle;

static int hf_redback_context = -1;
static int hf_redback_flags = -1;
static int hf_redback_circuit = -1;
static int hf_redback_length = -1;
static int hf_redback_protocol = -1;
static int hf_redback_l3offset = -1;
static int hf_redback_dataoffset = -1;
static int hf_redback_padding = -1;
static int hf_redback_unknown = -1;

static void
dissect_redback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint16		l3off, dataoff, proto;
	proto_item	*ti;
	proto_tree	*rbtree = NULL;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo,COL_PROTOCOL,"RBN");

	dataoff = tvb_get_ntohs(tvb, 20);
	l3off = tvb_get_ntohs(tvb, 22);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_redback, tvb, 0, -1, FALSE);
		rbtree = proto_item_add_subtree(ti, ett_redback);

		proto_tree_add_item(rbtree, hf_redback_context, tvb, 0, 4, FALSE);
		proto_tree_add_item(rbtree, hf_redback_flags, tvb, 4, 4, FALSE);
		proto_tree_add_item(rbtree, hf_redback_circuit, tvb, 8, 8, FALSE);
		proto_tree_add_item(rbtree, hf_redback_length, tvb, 16, 2, FALSE);
		proto_tree_add_item(rbtree, hf_redback_protocol, tvb, 18, 2, FALSE);
		proto_tree_add_item(rbtree, hf_redback_dataoffset, tvb, 20, 2, FALSE);
		proto_tree_add_item(rbtree, hf_redback_l3offset, tvb, 22, 2, FALSE);

		if (dataoff > 24) {
			proto_tree_add_item(rbtree, hf_redback_padding, tvb, 24, dataoff-24, FALSE);
		}
	}

	proto = tvb_get_ntohs(tvb, 18);
	switch(proto) {
		case 0x01:
			/*
			 * IP on Ethernet - Incoming data points to an ethernet header
			 * outgoing we have a pure IPv4 Packet
			 */
			next_tvb = tvb_new_subset_remaining(tvb, dataoff);
			if (dataoff == l3off)
				call_dissector(ipv4_handle, next_tvb, pinfo, tree);
			else if (dataoff+2 == l3off)
				call_dissector(ppp_handle, next_tvb, pinfo, tree);
			else if (dataoff+4 == l3off)
				call_dissector(ppphdlc_handle, next_tvb, pinfo, tree);
			else
				call_dissector(ethnofcs_handle, next_tvb, pinfo, tree);
			break;
		case 0x02:
			/*
			 * This is ISIS - Either incoming with ethernet FCS
			 * and CLNP - passed to the eth dissector or in case 
			 * of outgoing its pure ISIS and the linecard attaches
			 * the ethernet and CLNP headers ...
			 *
			 */
			next_tvb = tvb_new_subset_remaining(tvb, dataoff);
			if (l3off > dataoff) {
				call_dissector(ethnofcs_handle, next_tvb, pinfo, tree);
			} else {
				guint8 nlpid = tvb_get_guint8(tvb, dataoff);
				if(dissector_try_uint(osinl_subdissector_table, nlpid, next_tvb, pinfo, tree))
					break;
				next_tvb = tvb_new_subset_remaining(tvb, dataoff+1);
				if(dissector_try_uint(osinl_excl_subdissector_table, nlpid, next_tvb, pinfo, tree))
					break;
				next_tvb = tvb_new_subset_remaining(tvb, dataoff);
				call_dissector(data_handle, next_tvb, pinfo, tree);
			}
			break;
		case 0x06: {
			/*
			 * PPP Messages e.g. LCP, IPCP etc - possibly on ethernet in case of PPPoE.
			 * PPPoE messages are Protocol 8 ...
			 */
			guint32		flags;
			flags = tvb_get_ntohl(tvb, 4);

			if (flags & 0x00400000) {
				next_tvb = tvb_new_subset_remaining(tvb, dataoff);
			} else {
				if (tree)
					proto_tree_add_item(rbtree, hf_redback_unknown, tvb, dataoff, 4, FALSE);
				next_tvb = tvb_new_subset_remaining(tvb, dataoff+4);
			}

			if (l3off == dataoff) {
				call_dissector(ppp_handle, next_tvb, pinfo, tree);
			} else {
				call_dissector(ethnofcs_handle, next_tvb, pinfo, tree);
			}
			break;
		}
		case 0x03: /* Unicast Ethernet tx - Seen with PPPoE PADO */
		case 0x04: /* Unicast Ethernet rx - Seen with ARP  */
		case 0x08: /* Broadcast Ethernet rx - Seen with PPPoE PADI */
			next_tvb = tvb_new_subset_remaining(tvb, dataoff);
			call_dissector(ethnofcs_handle, next_tvb, pinfo, tree);
			break;
		default:
			if (tree)
				proto_tree_add_text (rbtree, tvb, 24, -1, "Unknown Protocol Data %u", proto);
			break;
	}
	return;
}

void
proto_register_redback(void)
{
	static hf_register_info hf[] = {
		{ &hf_redback_context,
			{ "Context", "redback.context", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redback_flags,
			{ "Flags", "redback.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redback_circuit,
			{ "Circuit", "redback.circuit", FT_UINT64, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redback_length,
			{ "Length", "redback.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redback_protocol,
			{ "Protocol", "redback.protocol", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redback_l3offset,
			{ "Layer 3 Offset", "redback.l3offset", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redback_dataoffset,
			{ "Data Offset", "redback.dataoffset", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redback_padding,
			{ "Padding", "redback.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redback_unknown,
			{ "Unknown", "redback.unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_redback
	};

	proto_redback = proto_register_protocol("Redback", "Redback", "redback");
	proto_register_field_array(proto_redback, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_redback(void)
{
	dissector_handle_t redback_handle;

	osinl_subdissector_table = find_dissector_table("osinl");
	osinl_excl_subdissector_table = find_dissector_table("osinl.excl");

	ipv4_handle = find_dissector("ip");
	data_handle = find_dissector("data");
	ethnofcs_handle = find_dissector("eth_withoutfcs");
	clnp_handle = find_dissector("clnp");
	arp_handle = find_dissector("arp");
	ppp_handle = find_dissector("ppp");
	ppphdlc_handle = find_dissector("ppp_hdlc");

	redback_handle = create_dissector_handle(dissect_redback, proto_redback);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_REDBACK, redback_handle);
}


