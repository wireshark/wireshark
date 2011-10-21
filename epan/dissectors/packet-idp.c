/* packet-idp.c
 * Routines for XNS IDP
 * Based on the Netware IPX dissector by Gilbert Ramirez <gram@alumni.rice.edu>
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
#include "packet-idp.h"
#include <epan/etypes.h>

static int proto_idp = -1;
static int hf_idp_checksum = -1;
static int hf_idp_len = -1;
static int hf_idp_src = -1;
static int hf_idp_dst = -1;
static int hf_idp_hops = -1;
static int hf_idp_packet_type = -1;
static int hf_idp_dnet = -1;
static int hf_idp_dnode = -1;
static int hf_idp_dsocket = -1;
static int hf_idp_snet = -1;
static int hf_idp_snode = -1;
static int hf_idp_ssocket = -1;

static gint ett_idp = -1;

static dissector_handle_t data_handle;

static dissector_table_t idp_type_dissector_table;

/*
 * See
 *
 *	"Internet Transport Protocols", XSIS 028112, December 1981
 *
 * if you can find it; this is based on the headers in the BSD XNS
 * implementation.
 */

#define IDP_HEADER_LEN	30		/* It's *always* 30 bytes */

static const value_string idp_packet_type_vals[] = {
	{ IDP_PACKET_TYPE_RIP,		"RIP" },
	{ IDP_PACKET_TYPE_ECHO,		"Echo" },
	{ IDP_PACKET_TYPE_ERROR,	"Error" },
	{ IDP_PACKET_TYPE_PEP,		"PEP" },
	{ IDP_PACKET_TYPE_SPP,		"SPP" },
	{ 0,				NULL }
};

static const value_string idp_socket_vals[] = {
	{ IDP_SOCKET_SMB,		"SMB" },
	{ 0,				NULL }
};

static void
dissect_idp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*idp_tree = NULL;
	proto_item	*ti = NULL;
	guint16		length;
	guint8		type;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IDP");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_idp, tvb, 0, IDP_HEADER_LEN, ENC_NA);
		idp_tree = proto_item_add_subtree(ti, ett_idp);
	}

	proto_tree_add_item(idp_tree, hf_idp_checksum, tvb, 0, 2, ENC_BIG_ENDIAN);
	length = tvb_get_ntohs(tvb, 2);
	proto_tree_add_uint_format(idp_tree, hf_idp_len, tvb, 2, 2, length,
		"Length: %u bytes", length);
	/* Adjust the tvbuff length to include only the IDP datagram. */
	set_actual_length(tvb, length);
	proto_tree_add_item(idp_tree, hf_idp_hops, tvb, 4, 1, ENC_BIG_ENDIAN);
	type = tvb_get_guint8(tvb, 5);
	proto_tree_add_uint(idp_tree, hf_idp_packet_type, tvb, 5, 1, type);

	pinfo->ptype = PT_IDP;

	/* Destination */
	proto_tree_add_item(idp_tree, hf_idp_dnet, tvb, 6, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(idp_tree, hf_idp_dnode, tvb, 10, 6, ENC_NA);
	pinfo->destport = tvb_get_ntohs(tvb, 16);
	proto_tree_add_uint(idp_tree, hf_idp_dsocket, tvb, 16, 2,
	    pinfo->destport);

	/* Source */
	proto_tree_add_item(idp_tree, hf_idp_snet, tvb, 18, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(idp_tree, hf_idp_snode, tvb, 22, 6, ENC_NA);
	pinfo->srcport = tvb_get_ntohs(tvb, 28);
	proto_tree_add_uint(idp_tree, hf_idp_ssocket, tvb, 28, 2,
	    pinfo->srcport);

	/* Make the next tvbuff */
	next_tvb = tvb_new_subset_remaining(tvb, IDP_HEADER_LEN);

	/*
	 * Hand off to the dissector for the packet type.
	 */
	if (dissector_try_uint(idp_type_dissector_table, type, next_tvb,
	    pinfo, tree))
		return;

	call_dissector(data_handle, next_tvb, pinfo, tree);
}

void
proto_register_idp(void)
{
	static hf_register_info hf_idp[] = {
		{ &hf_idp_checksum,
		    { "Checksum",	"idp.checksum", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_idp_src,
		    { "Source Address",	"idp.src", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_idp_dst,
		    { "Destination Address",	"idp.dst", FT_STRING, BASE_NONE,
			NULL, 0x0,  NULL, HFILL }},

		{ &hf_idp_len,
		    { "Length",		"idp.len", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		/* XXX - does this have separate hop count and time subfields? */
		{ &hf_idp_hops,
		    { "Transport Control (Hops)", "idp.hops", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_idp_packet_type,
		    { "Packet Type",	"idp.packet_type", FT_UINT8, BASE_DEC,
			VALS(idp_packet_type_vals), 0x0, NULL, HFILL }},

		{ &hf_idp_dnet,
		    { "Destination Network","idp.dst.net", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_idp_dnode,
		    { "Destination Node",	"idp.dst.node", FT_ETHER, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_idp_dsocket,
		    { "Destination Socket",	"idp.dst.socket", FT_UINT16, BASE_HEX,
			VALS(idp_socket_vals), 0x0, NULL, HFILL }},

		{ &hf_idp_snet,
		    { "Source Network","idp.src.net", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_idp_snode,
		    { "Source Node",	"idp.src.node", FT_ETHER, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_idp_ssocket,
		    { "Source Socket",	"idp.src.socket", FT_UINT16, BASE_HEX,
			VALS(idp_socket_vals), 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_idp,
	};

	proto_idp = proto_register_protocol("Internetwork Datagram Protocol",
	    "IDP", "idp");
	proto_register_field_array(proto_idp, hf_idp, array_length(hf_idp));
	proto_register_subtree_array(ett, array_length(ett));

	idp_type_dissector_table = register_dissector_table("idp.packet_type",
	    "IDP packet type", FT_UINT8, BASE_DEC);
}

void
proto_reg_handoff_idp(void)
{
	dissector_handle_t idp_handle;

	idp_handle = create_dissector_handle(dissect_idp, proto_idp);
	dissector_add_uint("ethertype", ETHERTYPE_XNS_IDP, idp_handle);
	dissector_add_uint("chdlctype", ETHERTYPE_XNS_IDP, idp_handle);

	data_handle = find_dissector("data");
}
