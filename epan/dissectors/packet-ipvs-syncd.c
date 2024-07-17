/* packet-ipvs-syncd.c   2001 Ronnie Sahlberg <See AUTHORS for email>
 * Routines for IGMP packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_ipvs_syncd(void);
void proto_reg_handoff_ipvs_syncd(void);

static dissector_handle_t ipvs_syncd_handle;

static int proto_ipvs_syncd;
static int hf_conn_count;
static int hf_syncid;
static int hf_size;
static int hf_resv;
static int hf_version;
static int hf_proto;
static int hf_cport;
static int hf_vport;
static int hf_dport;
static int hf_caddr;
static int hf_vaddr;
static int hf_daddr;
static int hf_flags;
static int hf_flags_conn_type;
static int hf_flags_hashed_entry;
static int hf_flags_no_output_packets;
static int hf_flags_conn_not_established;
static int hf_flags_adjust_output_seq;
static int hf_flags_adjust_input_seq;
static int hf_flags_no_client_port_set;
static int hf_state;
static int hf_in_seq_init;
static int hf_in_seq_delta;
static int hf_in_seq_pdelta;
static int hf_out_seq_init;
static int hf_out_seq_delta;
static int hf_out_seq_pdelta;

/* Payload v1 */
static int hf_type;
static int hf_ver;
static int hf_size_v1;
static int hf_flags_v1;
static int hf_fwmark;
static int hf_timeout;
static int hf_caddr6;
static int hf_vaddr6;
static int hf_daddr6;

static int ett_ipvs_syncd;
static int ett_conn;
static int ett_flags;

#define IPVS_SYNCD_MC_GROUP "224.0.0.18"
#define IPVS_SYNCD_PORT 8848 /* Not IANA registered */

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

static const value_string type_strings[] = {
	{0x0, "IPv4"},
	{0x2, "IPv6"},
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

static const value_string connection_type_strings[] = {
	{IP_VS_CONN_F_MASQ,	 "Masquerade"},
	{IP_VS_CONN_F_LOCALNODE, "Local Node"},
	{IP_VS_CONN_F_TUNNEL,	 "Tunnel"},
	{IP_VS_CONN_F_DROUTE,	 "Direct Routing"},
	{0x00, NULL},
};


static int
dissect_ipvs_syncd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_tree *tree;
	proto_item *item;
	int         offset = 0;
	uint8_t     cnt    = 0;
	uint8_t     version = 0;
	int         conn   = 0;

	item = proto_tree_add_item(parent_tree, proto_ipvs_syncd, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_ipvs_syncd);


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPVS");
	col_clear(pinfo->cinfo, COL_INFO);

	cnt = tvb_get_uint8(tvb, offset);
	if(cnt == 0) { //Version 1 (or after...) first byte is reserved
		proto_tree_add_item(tree, hf_resv, tvb, offset, 1, ENC_NA);
		col_set_str(pinfo->cinfo, COL_INFO, "v1");
	} else {
		proto_tree_add_item(tree, hf_conn_count, tvb, offset, 1, ENC_BIG_ENDIAN);
		col_set_str(pinfo->cinfo, COL_INFO, "v0");
	}
	offset += 1;

	proto_tree_add_item(tree, hf_syncid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_size, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	if(cnt == 0) { //Version 1 (or after...)
		cnt = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_conn_count, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		version = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(tree, hf_resv, tvb, offset, 2, ENC_NA);
		offset += 2;
	}
	col_append_fstr(pinfo->cinfo, COL_INFO, " %u Connection(s)", cnt);

	for (conn = 0; conn < cnt; conn++)
	{
		if(version) {

			proto_tree *ctree;
			uint8_t type;
			uint16_t size;

			ctree = proto_tree_add_subtree_format(tree, tvb, offset, 36, ett_conn, NULL,
							      "Connection #%d", conn+1);

			type = tvb_get_uint8(tvb, offset);
			proto_tree_add_item(ctree, hf_type, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(ctree, hf_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			size = (tvb_get_ntohs(tvb, offset) & 0x1FFF);
			proto_item_set_len(ctree, size);
			proto_tree_add_item(ctree, hf_ver, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ctree, hf_size_v1, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(ctree, hf_flags_v1, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(ctree, hf_state, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(ctree, hf_cport, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(ctree, hf_vport, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(ctree, hf_dport, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(ctree, hf_fwmark, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(ctree, hf_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			if(type == 0){ /* IPv4 */

				proto_tree_add_item(ctree, hf_caddr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(ctree, hf_vaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(ctree, hf_daddr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else { /* IPv6 */

				proto_tree_add_item(ctree, hf_caddr6, tvb, offset, 16, ENC_NA);
				offset += 16;

				proto_tree_add_item(ctree, hf_vaddr6, tvb, offset, 16, ENC_NA);
				offset += 16;

				proto_tree_add_item(ctree, hf_daddr6, tvb, offset, 16, ENC_NA);
				offset += 16;
			}

		} else {

			proto_tree *ctree;
			proto_tree *ftree, *fi;
			uint16_t flags;

			ctree = proto_tree_add_subtree_format(tree, tvb, offset, 24, ett_conn, NULL,
							      "Connection #%d", conn+1);

			proto_tree_add_item(ctree, hf_resv, tvb, offset, 1, ENC_NA);
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
			proto_tree_add_item(ftree, hf_flags_conn_type, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ftree, hf_flags_hashed_entry, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ftree, hf_flags_no_output_packets, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ftree, hf_flags_conn_not_established, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ftree, hf_flags_adjust_output_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ftree, hf_flags_adjust_input_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ftree, hf_flags_no_client_port_set, tvb, offset, 2, ENC_BIG_ENDIAN);

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

	return tvb_captured_length(tvb);
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

		{ &hf_resv,
			{ "Reserved", "ipvs.resv", FT_BYTES, BASE_NONE,
			  NULL, 0, NULL, HFILL }},

		{ &hf_version,
			{ "Version", "ipvs.version", FT_UINT8, BASE_DEC,
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

		{ &hf_flags_conn_type,
			{ "Connection Type", "ipvs.flags.conn_type", FT_UINT16, BASE_HEX,
			  VALS(connection_type_strings), 0x0F, NULL, HFILL }},

		{ &hf_flags_hashed_entry,
			{ "Hashed Entry", "ipvs.flags.hashed_entry", FT_BOOLEAN, 16,
			  NULL, IP_VS_CONN_F_HASHED, NULL, HFILL }},

		{ &hf_flags_no_output_packets,
			{ "No Output Packets", "ipvs.flags.no_output_packets", FT_BOOLEAN, 16,
			  NULL, IP_VS_CONN_F_NOOUTPUT, NULL, HFILL }},

		{ &hf_flags_conn_not_established,
			{ "Connection Not Established", "ipvs.flags.conn_not_established", FT_BOOLEAN, 16,
			  NULL, IP_VS_CONN_F_INACTIVE, NULL, HFILL }},

		{ &hf_flags_adjust_output_seq,
			{ "Adjust Output Sequence", "ipvs.flags.adjust_output_seq", FT_BOOLEAN, 16,
			  NULL, IP_VS_CONN_F_OUT_SEQ, NULL, HFILL }},

		{ &hf_flags_adjust_input_seq,
			{ "Adjust Input Sequence", "ipvs.flags.adjust_input_seq", FT_BOOLEAN, 16,
			  NULL, IP_VS_CONN_F_IN_SEQ, NULL, HFILL }},

		{ &hf_flags_no_client_port_set,
			{ "No Client Port Set", "ipvs.flags.no_client_port_set", FT_BOOLEAN, 16,
			  NULL, IP_VS_CONN_F_NO_CPORT, NULL, HFILL }},

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

		/* v1 payload */

		{ &hf_type,
			{ "Type", "ipvs.type", FT_UINT8, BASE_DEC,
			  VALS(type_strings), 0, NULL, HFILL }},

		{ &hf_ver,
			{ "Version", "ipvs.ver", FT_UINT16, BASE_DEC,
			  NULL, 0xE000, NULL, HFILL }},

		{ &hf_size_v1,
			{ "Size", "ipvs.size.v1", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }},

		{ &hf_flags_v1,
			{ "Flags", "ipvs.flags.v1", FT_UINT32, BASE_HEX,
			  NULL, 0, NULL, HFILL }},

		{ &hf_fwmark,
			{ "FWmark", "ipvs.fwmark", FT_UINT32, BASE_HEX,
			  NULL, 0, NULL, HFILL }},

		{ &hf_timeout,
			{ "Timeout", "ipvs.timeout", FT_UINT32, BASE_DEC,
			  NULL, 0, NULL, HFILL }},

		{ &hf_caddr6,
			{ "Client Address", "ipvs.caddr6", FT_IPv6, BASE_NONE,
			  NULL, 0, NULL, HFILL }},

		{ &hf_vaddr6,
			{ "Virtual Address", "ipvs.vaddr6", FT_IPv6, BASE_NONE,
			  NULL, 0, NULL, HFILL }},

		{ &hf_daddr6,
			{ "Destination Address", "ipvs.daddr6", FT_IPv6, BASE_NONE,
			  NULL, 0, NULL, HFILL }},

	};
	static int *ett[] = {
		&ett_ipvs_syncd,
		&ett_conn,
		&ett_flags,
	};

	proto_ipvs_syncd = proto_register_protocol("IP Virtual Services Sync Daemon", "IPVS", "ipvs");
	proto_register_field_array(proto_ipvs_syncd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ipvs_syncd_handle = register_dissector("ipvs", dissect_ipvs_syncd, proto_ipvs_syncd);
}

void
proto_reg_handoff_ipvs_syncd(void)
{
	dissector_add_uint_with_preference("udp.port", IPVS_SYNCD_PORT, ipvs_syncd_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
