/* packet-ipvs-syncd.c   2001 Ronnie Sahlberg <See AUTHORS for email>
 * Routines for IGMP packet disassembly
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
#include <epan/ipproto.h>
#include <epan/in_cksum.h>

static int proto_ipvs_syncd = -1;
static int hf_conn_count = -1;
static int hf_syncid = -1;
static int hf_size = -1;
static int hf_resv8 = -1;
static int hf_proto = -1;
static int hf_cport = -1;
static int hf_vport = -1;
static int hf_dport = -1;
static int hf_caddr = -1;
static int hf_vaddr = -1;
static int hf_daddr = -1;
static int hf_flags = -1;
static int hf_state = -1;
static int hf_in_seq_init = -1;
static int hf_in_seq_delta = -1;
static int hf_in_seq_pdelta = -1;
static int hf_out_seq_init = -1;
static int hf_out_seq_delta = -1;
static int hf_out_seq_pdelta = -1;

static int ett_ipvs_syncd = -1;
static int ett_conn = -1;
static int ett_flags = -1;

#define IPVS_SYNCD_MC_GROUP "224.0.0.18"
#define IPVS_SYNCD_PORT 8848

static const value_string proto_strings[] = {
	{0x06, "TCP"},
	{0x11, "UDP"},
	{0x00, NULL},
};

static const value_string state_strings[] = {
	{0x00, "Input"},
	{0x04, "Output"},
	{0x08, "Input Only"},
	{0x00, NULL},
};

/*
 *  IPVS Connection Flags
 *  Pulled from include/net/ip_vs.h in linux kernel source
 */
#define IP_VS_CONN_F_FWD_MASK         0x0007    /* mask for the fwd methods */
#define IP_VS_CONN_F_MASQ             0x0000    /* masquerading */
#define IP_VS_CONN_F_LOCALNODE        0x0001    /* local node */
#define IP_VS_CONN_F_TUNNEL           0x0002    /* tunneling */
#define IP_VS_CONN_F_DROUTE           0x0003    /* direct routing */
#define IP_VS_CONN_F_BYPASS           0x0004    /* cache bypass */
#define IP_VS_CONN_F_HASHED           0x0040    /* hashed entry */
#define IP_VS_CONN_F_NOOUTPUT         0x0080    /* no output packets */
#define IP_VS_CONN_F_INACTIVE         0x0100    /* not established */
#define IP_VS_CONN_F_OUT_SEQ          0x0200    /* must do output seq adjust */
#define IP_VS_CONN_F_IN_SEQ           0x0400    /* must do input seq adjust */
#define IP_VS_CONN_F_SEQ_MASK         0x0600    /* in/out sequence mask */
#define IP_VS_CONN_F_NO_CPORT         0x0800    /* no client port set yet */


static void
dissect_ipvs_syncd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_tree *tree;
	proto_item *item;
	int offset = 0;
	guint8 cnt = 0;
	int conn = 0;

	item = proto_tree_add_item(parent_tree, proto_ipvs_syncd, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_ipvs_syncd);


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPVS");
	col_clear(pinfo->cinfo, COL_INFO);

	cnt = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_conn_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_syncid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_size, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	for (conn = 0; conn < cnt; conn++)
	{
		proto_tree *ctree, *ti;
		proto_tree *ftree, *fi;
		guint16 flags;

		ti = proto_tree_add_text(tree, tvb, offset, 24, "Connection #%d", conn+1);
		ctree = proto_item_add_subtree(ti, ett_conn);

		proto_tree_add_item(ctree, hf_resv8, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(ctree, hf_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(ctree, hf_cport, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(ctree, hf_vport, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(ctree, hf_dport, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(ctree, hf_caddr, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(ctree, hf_vaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(ctree, hf_daddr, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		flags = tvb_get_ntohs(tvb, offset);
		fi = proto_tree_add_item(ctree, hf_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
		ftree = proto_item_add_subtree(fi, ett_flags);

		if ( (flags & 0x0F) == IP_VS_CONN_F_MASQ )
		{
			proto_tree_add_text(ftree, tvb, offset+1, 1, "Connection Type: Masquerade");
		}
		else if ( (flags & 0x0F) == IP_VS_CONN_F_LOCALNODE )
		{
			proto_tree_add_text(ftree, tvb, offset+1, 1, "Connection Type: Local Node");
		}
		else if ( (flags & 0x0F) == IP_VS_CONN_F_TUNNEL )
		{
			proto_tree_add_text(ftree, tvb, offset+1, 1, "Connection Type: Tunnel");
		}
		else if ( (flags & 0x0F) == IP_VS_CONN_F_DROUTE )
		{
			proto_tree_add_text(ftree, tvb, offset+1, 1, "Connection Type: Direct Routing");
		}
		else
		{
			proto_tree_add_text(ftree, tvb, offset+1, 1, "Connection Type: Unknown (%d)",
				flags & IP_VS_CONN_F_FWD_MASK);
		}

		if ( flags & IP_VS_CONN_F_HASHED )
		{
			proto_tree_add_text(ftree, tvb, offset+1, 1, "Hashed Entry");
		}

		if ( flags & IP_VS_CONN_F_NOOUTPUT )
		{
			proto_tree_add_text(ftree, tvb, offset+1, 1, "No Output Packets");
		}

		if ( flags & IP_VS_CONN_F_INACTIVE )
		{
			proto_tree_add_text(ftree, tvb, offset, 1, "Connection Not Established");
		}

		if ( flags & IP_VS_CONN_F_OUT_SEQ )
		{
			proto_tree_add_text(ftree, tvb, offset, 1, "Adjust Output Sequence");
		}

		if ( flags & IP_VS_CONN_F_IN_SEQ )
		{
			proto_tree_add_text(ftree, tvb, offset, 1, "Adjust Input Sequence");
		}

		if ( flags & IP_VS_CONN_F_NO_CPORT )
		{
			proto_tree_add_text(ftree, tvb, offset, 1, "No Client Port Set");
		}

		offset += 2;

		proto_tree_add_item(ctree, hf_state, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* we have full connection info */
		if ( flags & IP_VS_CONN_F_SEQ_MASK )
		{
			proto_tree_add_item(ctree, hf_in_seq_init, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(ctree, hf_in_seq_delta, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(ctree, hf_in_seq_pdelta, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(ctree, hf_out_seq_init, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(ctree, hf_out_seq_delta, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(ctree, hf_out_seq_pdelta, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}

	}
}

void
proto_register_ipvs_syncd(void)
{
	static hf_register_info hf[] = {
		{ &hf_conn_count,
			{ "Connection Count", "ipvs.conncount", FT_UINT8, BASE_DEC,
			  NULL, 0, NULL, HFILL }},

		{ &hf_syncid,
			{ "Synchronization ID", "ipvs.syncid", FT_UINT8, BASE_DEC,
			  NULL, 0, NULL, HFILL }},

		{ &hf_size,
			{ "Size", "ipvs.size", FT_UINT16, BASE_DEC,
			  NULL, 0, NULL, HFILL }},

		{ &hf_resv8,
			{ "Reserved", "ipvs.resv8", FT_UINT8, BASE_HEX,
			  NULL, 0, NULL, HFILL }},

		{ &hf_proto,
			{ "Protocol", "ipvs.proto", FT_UINT8, BASE_HEX,
			  VALS(proto_strings), 0, NULL, HFILL }},

		{ &hf_cport,
			{ "Client Port", "ipvs.cport", FT_UINT16, BASE_DEC,
			  NULL, 0, NULL, HFILL }},

		{ &hf_vport,
			{ "Virtual Port", "ipvs.vport", FT_UINT16, BASE_DEC,
			  NULL, 0, NULL, HFILL }},

		{ &hf_dport,
			{ "Destination Port", "ipvs.dport", FT_UINT16, BASE_DEC,
			  NULL, 0, NULL, HFILL }},

		{ &hf_caddr,
			{ "Client Address", "ipvs.caddr", FT_IPv4, BASE_NONE,
			  NULL, 0, NULL, HFILL }},

		{ &hf_vaddr,
			{ "Virtual Address", "ipvs.vaddr", FT_IPv4, BASE_NONE,
			  NULL, 0, NULL, HFILL }},

		{ &hf_daddr,
			{ "Destination Address", "ipvs.daddr", FT_IPv4, BASE_NONE,
			  NULL, 0, NULL, HFILL }},

		{ &hf_flags,
			{ "Flags", "ipvs.flags", FT_UINT16, BASE_HEX,
			  NULL, 0, NULL, HFILL }},

		{ &hf_state,
			{ "State", "ipvs.state", FT_UINT16, BASE_HEX,
			  VALS(state_strings), 0, NULL, HFILL }},

		{ &hf_in_seq_init,
			{ "Input Sequence (Initial)", "ipvs.in_seq.initial", FT_UINT32,
				BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_in_seq_delta,
			{ "Input Sequence (Delta)", "ipvs.in_seq.delta", FT_UINT32,
				BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_in_seq_pdelta,
			{ "Input Sequence (Previous Delta)", "ipvs.in_seq.pdelta", FT_UINT32,
				BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_out_seq_init,
			{ "Output Sequence (Initial)", "ipvs.out_seq.initial", FT_UINT32,
				BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_out_seq_delta,
			{ "Output Sequence (Delta)", "ipvs.out_seq.delta", FT_UINT32,
				BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_out_seq_pdelta,
			{ "Output Sequence (Previous Delta)", "ipvs.out_seq.pdelta", FT_UINT32,
				BASE_HEX, NULL, 0, NULL, HFILL }},




	};
	static gint *ett[] = {
		&ett_ipvs_syncd,
		&ett_conn,
		&ett_flags,
	};

	proto_ipvs_syncd = proto_register_protocol("IP Virtual Services Sync Daemon",
	    "IPVS", "ipvs");
	proto_register_field_array(proto_ipvs_syncd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipvs_syncd(void)
{
	dissector_handle_t ipvs_syncd_handle;

	ipvs_syncd_handle = create_dissector_handle(dissect_ipvs_syncd, proto_ipvs_syncd);
	dissector_add_uint("udp.port", IPVS_SYNCD_PORT, ipvs_syncd_handle);
}
