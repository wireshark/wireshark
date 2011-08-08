/* packet-paltalk.c
 * Routines for Paltalk dissection
 * Copyright 2005, Tim Hentenaar < tim at hentenaar dot com >
 * Copyright 2008, Mohammad Ebrahim Mohammadi Panah < mebrahim at gmail dot com >
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>

#include "packet-tcp.h"

#define INET_IPV4_ADDRESS_FROM_BYTES(a,b,c,d) g_htonl(((a)<<24) | ((b)<<16) | ((c)<<8) | (d)) /* *network* order */

#define PALTALK_SERVERS_ADDRESS INET_IPV4_ADDRESS_FROM_BYTES(199,106,0,0)      /* 199.106.0.0 in *network* order */
#define PALTALK_SERVERS_NETMASK INET_IPV4_ADDRESS_FROM_BYTES(0xFF, 0xFE, 0x00, 0x00)  /* /15  in *network* order */

#define PALTALK_HEADER_LENGTH 6

/* forward reference */
static guint dissect_paltalk_get_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset);
static void dissect_paltalk_desegmented(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int proto_paltalk = -1;

static int hf_paltalk_pdu_type = -1;
static int hf_paltalk_version = -1;
static int hf_paltalk_length = -1;
static int hf_paltalk_content = -1;

static gint ett_paltalk = -1;

static gboolean
dissect_paltalk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 src32, dst32;

	/* Detect if this TCP session is a Paltalk one */
	/* TODO: Optimize detection logic if possible */

	if ((pinfo->net_src.type != AT_IPv4) 
	    || (pinfo->net_dst.type != AT_IPv4)
	    || (pinfo->net_src.len != 4)
	    || (pinfo->net_dst.len != 4)
	    || !pinfo->net_src.data 
	    || !pinfo->net_dst.data)
		return FALSE;

	memcpy((guint8 *)&src32, pinfo->net_src.data, 4); /* *Network* order */
	memcpy((guint8 *)&dst32, pinfo->net_dst.data, 4); /* *Network* order */

	if ( ((src32 & PALTALK_SERVERS_NETMASK) != PALTALK_SERVERS_ADDRESS) 
	     &&
	     ((dst32 & PALTALK_SERVERS_NETMASK) != PALTALK_SERVERS_ADDRESS))
		return FALSE;

	/* Dissect result of desegmented TCP data */
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, PALTALK_HEADER_LENGTH
			, dissect_paltalk_get_len, dissect_paltalk_desegmented);
	return TRUE;
}

static guint
dissect_paltalk_get_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	return tvb_get_ntohs(tvb, offset + 4) + PALTALK_HEADER_LENGTH;
}

static void
dissect_paltalk_desegmented(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti = NULL;
	proto_tree *pt_tree = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Paltalk");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree)		/* we are being asked for details */
	{
		ti = proto_tree_add_item(tree, proto_paltalk, tvb, 0, -1, FALSE);
		pt_tree = proto_item_add_subtree(ti, ett_paltalk);
		proto_tree_add_item(pt_tree, hf_paltalk_pdu_type, tvb, 0, 2, FALSE);
		proto_tree_add_item(pt_tree, hf_paltalk_version, tvb, 2, 2, FALSE);
		proto_tree_add_item(pt_tree, hf_paltalk_length, tvb, 4, 2, FALSE);
		proto_tree_add_item(pt_tree, hf_paltalk_content, tvb, 6, tvb_get_ntohs(tvb, 4), FALSE);
	}
}

void
proto_register_paltalk(void)
{
	static hf_register_info hf[] = {
		{ &hf_paltalk_pdu_type, { "Packet Type", "paltalk.type", 
					  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }},
		{ &hf_paltalk_version,  { "Protocol Version", "paltalk.version",
					  FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_paltalk_length,   { "Payload Length", "paltalk.length",
					  FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_paltalk_content,  { "Payload Content", "paltalk.content",
					  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }}
	};

	static gint *ett[] = { &ett_paltalk };

	proto_paltalk = proto_register_protocol("Paltalk Messenger Protocol", "Paltalk", "paltalk");
	proto_register_field_array(proto_paltalk, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_paltalk(void)
{
	heur_dissector_add("tcp", dissect_paltalk, proto_paltalk);
}

