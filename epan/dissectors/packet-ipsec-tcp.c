/*
 * Routines for the disassembly of the proprietary Cisco IPSEC in
 * TCP encapsulation protocol
 *
 * Copyright 2007 Joerg Mayer (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* TODO:
 * - Find out the meaning of the (unknown) trailer
 * - UDP checksum is wrong
 * - Currently doesn't handle AH (lack of sample trace)
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-ndmp.h"

void proto_register_tcpencap(void);
void proto_reg_handoff_tcpencap(void);

static dissector_handle_t tcpencap_handle;

static int hf_tcpencap_unknown;
static int hf_tcpencap_zero;
static int hf_tcpencap_seq;
static int hf_tcpencap_ike_direction;
static int hf_tcpencap_esp_zero;
static int hf_tcpencap_magic;
static int hf_tcpencap_proto;
static int hf_tcpencap_magic2;

static int proto_tcpencap;
static int ett_tcpencap;
static int ett_tcpencap_unknown;

static const value_string tcpencap_ikedir_vals[] = {
	{ 0x0000,	"Server to client" },
	{ 0x4000,	"Client to server" },

	{ 0,	NULL }
};

static const value_string tcpencap_proto_vals[] = {
	{ 0x11,	"ISAKMP" },
	{ 0x32,	"ESP" },

	{ 0,	NULL }
};

#define TRAILERLENGTH 16
#define TCP_CISCO_IPSEC 10000

static dissector_handle_t esp_handle;
static dissector_handle_t udp_handle;

#define TCP_ENCAP_P_ESP 1
#define TCP_ENCAP_P_UDP 2


static int
packet_is_tcpencap(tvbuff_t *tvb, packet_info *pinfo, uint32_t offset)
{
	if (	/* Must be zero */
		tvb_get_ntohl(tvb, offset + 0) != 0 ||
		/* Lower 12 bits must be zero */
		(tvb_get_ntohs(tvb, offset + 6) & 0xfff) != 0 ||
		/* Protocol must be UDP or ESP */
		(tvb_get_uint8(tvb, offset + 13) != 17 &&
		 tvb_get_uint8(tvb, offset + 13) != 50)
	) {
		return false;
	}

	if(check_if_ndmp(tvb, pinfo)){
		return false;
	}

	return true;
}

/*
 * TCP Encapsulation of IPsec Packets
 * as supported by the cisco vpn3000 concentrator series
 */
static int
dissect_tcpencap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree *tcpencap_tree = NULL;
	proto_tree *tcpencap_unknown_tree = NULL;

	proto_item *tree_item = NULL;
	proto_item *unknown_item = NULL;
	tvbuff_t *next_tvb;
	uint32_t reported_length = tvb_reported_length(tvb);
	uint32_t offset;
	uint8_t protocol;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCPENCAP");
	col_clear(pinfo->cinfo, COL_INFO);

	/* If the first 4 bytes are 0x01f401f4 (udp src and dst port = 500)
	   we most likely have UDP (isakmp) traffic */

	if (tvb_get_ntohl(tvb, 0) == 0x01f401f4) { /* UDP means ISAKMP */
		protocol = TCP_ENCAP_P_UDP;
	} else { /* Hopefully ESP */
		protocol = TCP_ENCAP_P_ESP;
	}

	if (tree) {
		tree_item = proto_tree_add_item(tree, proto_tcpencap, tvb, 0, -1, ENC_NA);
		tcpencap_tree = proto_item_add_subtree(tree_item, ett_tcpencap);

		/* Dissect the trailer following the encapsulated IPSEC/ISAKMP packet */
		offset = reported_length - TRAILERLENGTH;
		unknown_item = proto_tree_add_item(tcpencap_tree, hf_tcpencap_unknown, tvb,
			offset, TRAILERLENGTH, ENC_NA);
		/* Try to guess the contents of the trailer */
		tcpencap_unknown_tree = proto_item_add_subtree(unknown_item, ett_tcpencap_unknown);
		proto_tree_add_item(tcpencap_unknown_tree, hf_tcpencap_zero, tvb, offset + 0, 4, ENC_NA);
		proto_tree_add_item(tcpencap_unknown_tree, hf_tcpencap_seq, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
		if (protocol == TCP_ENCAP_P_UDP) {
			proto_tree_add_item(tcpencap_unknown_tree, hf_tcpencap_ike_direction, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(tcpencap_unknown_tree, hf_tcpencap_esp_zero, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
		}
		proto_tree_add_item(tcpencap_unknown_tree, hf_tcpencap_magic, tvb, offset + 8, 5, ENC_NA);
		proto_tree_add_item(tcpencap_unknown_tree, hf_tcpencap_proto, tvb, offset + 13, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tcpencap_unknown_tree, hf_tcpencap_magic2, tvb, offset + 14, 2, ENC_NA);
	}

	/* Create the tvbuffer for the next dissector */
	next_tvb = tvb_new_subset_length_caplen(tvb, 0, reported_length - TRAILERLENGTH , -1);
	if (protocol == TCP_ENCAP_P_UDP) {
		call_dissector(udp_handle, next_tvb, pinfo, tree);
	} else { /* Hopefully ESP */
		call_dissector(esp_handle, next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static bool
dissect_tcpencap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	uint32_t reported_length = tvb_reported_length(tvb);
	uint32_t captured_length = tvb_captured_length(tvb);

	if (reported_length <= TRAILERLENGTH + 8 ||
		/* Ensure we have enough bytes for packet_is_tcpencap analysis */
		(reported_length - captured_length) > (TRAILERLENGTH - 13) ||
		!packet_is_tcpencap(tvb, pinfo, reported_length - TRAILERLENGTH) ) {
		return false;
	}

	dissect_tcpencap(tvb, pinfo, tree, data);
	return true;
}

void
proto_register_tcpencap(void)
{
	static hf_register_info hf[] = {

		{ &hf_tcpencap_unknown,
		{ "Unknown trailer",      "tcpencap.unknown", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_tcpencap_zero,
		{ "All zero",      "tcpencap.zero", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_tcpencap_seq,
		{ "Sequence number",      "tcpencap.seq", FT_UINT16, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_tcpencap_esp_zero,
		{ "ESP zero",      "tcpencap.espzero", FT_UINT16, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_tcpencap_ike_direction,
		{ "ISAKMP traffic direction",      "tcpencap.ikedirection", FT_UINT16, BASE_HEX, VALS(tcpencap_ikedir_vals),
			0x0, NULL, HFILL }},

		{ &hf_tcpencap_magic,
		{ "Magic number",      "tcpencap.magic", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_tcpencap_proto,
		{ "Protocol",      "tcpencap.proto", FT_UINT8, BASE_HEX, VALS(tcpencap_proto_vals),
			0x0, NULL, HFILL }},

		{ &hf_tcpencap_magic2,
		{ "Magic 2",      "tcpencap.magic2", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	};

	static int *ett[] = {
		&ett_tcpencap,
		&ett_tcpencap_unknown,
	};

	proto_tcpencap = proto_register_protocol("TCP Encapsulation of IPsec Packets", "TCPENCAP", "tcpencap");

	proto_register_field_array(proto_tcpencap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	tcpencap_handle = register_dissector("tcpencap", dissect_tcpencap, proto_tcpencap);
}

void
proto_reg_handoff_tcpencap(void)
{
	esp_handle = find_dissector_add_dependency("esp", proto_tcpencap);
	udp_handle = find_dissector_add_dependency("udp", proto_tcpencap);

	heur_dissector_add("tcp", dissect_tcpencap_heur, "TCP Encapsulation of IPsec Packets", "ipsec_tcp", proto_tcpencap, HEURISTIC_ENABLE);

	/* Register TCP port for dissection */
	dissector_add_for_decode_as_with_preference("tcp.port", tcpencap_handle);
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
