/* packet-redback.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * Ericsson SmartEdge tcpdump trace disassembly
 * Copyright 2005-2014 Florian Lohoff <f@zz.de>
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

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>


void proto_register_redback(void);
void proto_reg_handoff_redback(void);

static dissector_handle_t redback_handle;

static gint ett_redback = -1;

static dissector_table_t osinl_incl_subdissector_table;
static dissector_table_t osinl_excl_subdissector_table;

static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t ethnofcs_handle;
static dissector_handle_t clnp_handle;
static dissector_handle_t arp_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t ppphdlc_handle;

static header_field_info *hfi_redback = NULL;

#define REDBACK_HFI_INIT HFI_INIT(proto_redback)

static header_field_info hfi_redback_context REDBACK_HFI_INIT =
	{ "Context", "redback.context", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_redback_flags REDBACK_HFI_INIT =
	{ "Flags", "redback.flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_redback_circuit REDBACK_HFI_INIT =
	{ "Circuit", "redback.circuit", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_redback_length REDBACK_HFI_INIT =
	{ "Length", "redback.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_redback_protocol REDBACK_HFI_INIT =
	{ "Protocol", "redback.protocol", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_redback_l3offset REDBACK_HFI_INIT =
	{ "Layer 3 Offset", "redback.l3offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_redback_dataoffset REDBACK_HFI_INIT =
	{ "Data Offset", "redback.dataoffset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_redback_padding REDBACK_HFI_INIT =
	{ "Padding", "redback.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_redback_unknown REDBACK_HFI_INIT =
	{ "Unknown", "redback.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static expert_field ei_redback_protocol = EI_INIT;

static int
dissect_redback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint16		l3off, dataoff, proto;
	proto_item	*ti, *protocol_item;
	proto_tree	*rbtree = NULL;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo,COL_PROTOCOL,"RBN");

	dataoff = tvb_get_ntohs(tvb, 20);
	l3off = tvb_get_ntohs(tvb, 22);

	ti = proto_tree_add_item(tree, hfi_redback, tvb, 0, -1, ENC_NA);
	rbtree = proto_item_add_subtree(ti, ett_redback);

	proto_tree_add_item(rbtree, &hfi_redback_context, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(rbtree, &hfi_redback_flags, tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(rbtree, &hfi_redback_circuit, tvb, 8, 8, ENC_BIG_ENDIAN);
	proto_tree_add_item(rbtree, &hfi_redback_length, tvb, 16, 2, ENC_BIG_ENDIAN);
	protocol_item = proto_tree_add_item(rbtree, &hfi_redback_protocol, tvb, 18, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(rbtree, &hfi_redback_dataoffset, tvb, 20, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(rbtree, &hfi_redback_l3offset, tvb, 22, 2, ENC_BIG_ENDIAN);

	if (dataoff > 24) {
		proto_tree_add_item(rbtree, &hfi_redback_padding, tvb, 24, dataoff-24, ENC_NA);
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
			 * of outgoing it's pure ISIS and the linecard attaches
			 * the ethernet and CLNP headers ...
			 *
			 */
			next_tvb = tvb_new_subset_remaining(tvb, dataoff);
			if (l3off > dataoff) {
				call_dissector(ethnofcs_handle, next_tvb, pinfo, tree);
			} else {
				guint8 nlpid = tvb_get_guint8(tvb, dataoff);
				if(dissector_try_uint(osinl_incl_subdissector_table, nlpid, next_tvb, pinfo, tree))
					break;
				next_tvb = tvb_new_subset_remaining(tvb, dataoff+1);
				if(dissector_try_uint(osinl_excl_subdissector_table, nlpid, next_tvb, pinfo, tree))
					break;
				next_tvb = tvb_new_subset_remaining(tvb, dataoff);
				call_data_dissector(next_tvb, pinfo, tree);
			}
			break;
		case 0x06: {
			/*
			 * PPP Messages e.g. LCP, IPCP etc - possibly on ethernet in case of PPPoE.
			 * PPPoE messages are Protocol 8 ...
			 */
			guint32		flags;
			flags = tvb_get_ntohl(tvb, 4);

			if (flags & 0x04000000) {
				next_tvb = tvb_new_subset_remaining(tvb, dataoff);
			} else {
				if (tree)
					proto_tree_add_item(rbtree, &hfi_redback_unknown, tvb, dataoff, 4, ENC_NA);
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
		case 0x09: /* IPv6 either encapsulated as ethernet or native ip */
			next_tvb = tvb_new_subset_remaining(tvb, dataoff);
			if (dataoff == l3off)
				call_dissector(ipv6_handle, next_tvb, pinfo, tree);
			else
				call_dissector(ethnofcs_handle, next_tvb, pinfo, tree);
			break;
		default:
			expert_add_info(pinfo, protocol_item, &ei_redback_protocol);
			break;
	}
	return tvb_captured_length(tvb);
}

void
proto_register_redback(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_redback_context,
		&hfi_redback_flags,
		&hfi_redback_circuit,
		&hfi_redback_length,
		&hfi_redback_protocol,
		&hfi_redback_l3offset,
		&hfi_redback_dataoffset,
		&hfi_redback_padding,
		&hfi_redback_unknown,
	};
#endif

	static gint *ett[] = {
		&ett_redback
	};

	static ei_register_info ei[] = {
		{ &ei_redback_protocol, { "redback.protocol.unknown", PI_PROTOCOL, PI_WARN, "Unknown Protocol Data", EXPFILL }},
	};

	expert_module_t* expert_redback;
	int proto_redback;

	proto_redback = proto_register_protocol("Redback", "Redback", "redback");
	hfi_redback   = proto_registrar_get_nth(proto_redback);
	redback_handle = register_dissector("redback", dissect_redback, proto_redback);

	proto_register_fields(proto_redback, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));
	expert_redback = expert_register_protocol(proto_redback);
	expert_register_field_array(expert_redback, ei, array_length(ei));
}

void
proto_reg_handoff_redback(void)
{
	osinl_incl_subdissector_table = find_dissector_table("osinl.incl");
	osinl_excl_subdissector_table = find_dissector_table("osinl.excl");

	ipv4_handle = find_dissector_add_dependency("ip", hfi_redback->id);
	ipv6_handle = find_dissector_add_dependency("ipv6", hfi_redback->id);
	ethnofcs_handle = find_dissector_add_dependency("eth_withoutfcs", hfi_redback->id);
	clnp_handle = find_dissector_add_dependency("clnp", hfi_redback->id);
	arp_handle = find_dissector_add_dependency("arp", hfi_redback->id);
	ppp_handle = find_dissector_add_dependency("ppp", hfi_redback->id);
	ppphdlc_handle = find_dissector_add_dependency("ppp_hdlc", hfi_redback->id);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_REDBACK, redback_handle);
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
