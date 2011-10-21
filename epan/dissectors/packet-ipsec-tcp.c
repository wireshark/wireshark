/*
 * Routines for the disassembly of the proprietary Cisco IPSEC in
 * TCP encapsulation protocol
 *
 * $Id$
 *
 * Copyright 2007 Joerg Mayer (see AUTHORS file)
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

/* TODO:
 * - Find out the meaning of the (unknown) trailer
 * - UDP checksum is wrong
 * - Currently doesn't handle AH (lack of sample trace)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-ndmp.h"

static int hf_tcpencap_unknown = -1;
static int hf_tcpencap_zero = -1;
static int hf_tcpencap_seq = -1;
static int hf_tcpencap_ike_direction = -1;
static int hf_tcpencap_esp_zero = -1;
static int hf_tcpencap_magic = -1;
static int hf_tcpencap_proto = -1;
static int hf_tcpencap_magic2 = -1;

static int proto_tcpencap = -1;
static gint ett_tcpencap = -1;
static gint ett_tcpencap_unknown = -1;

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
static guint global_tcpencap_tcp_port = TCP_CISCO_IPSEC;

static dissector_handle_t esp_handle;
static dissector_handle_t udp_handle;

#define TCP_ENCAP_P_ESP 1
#define TCP_ENCAP_P_UDP 2


/* Another case of several companies creating protocols and
   choosing an easy-to-remember port. Playing tonight: Cisco vs NDMP.
*/
static int
packet_is_tcpencap(tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
	if (	/* Must be zero */
		tvb_get_ntohl(tvb, offset + 0) != 0 ||
		/* Lower 12 bits must be zero */
		(tvb_get_ntohs(tvb, offset + 6) & 0xfff) != 0 ||
		/* Protocol must be UDP or ESP */
		(tvb_get_guint8(tvb, offset + 13) != 17 &&
		 tvb_get_guint8(tvb, offset + 13) != 50)
	) {
		return FALSE;
	}

	if(check_if_ndmp(tvb, pinfo)){
		return FALSE;
	}

	return TRUE;
}

/*
 * TCP Encapsulation of IPsec Packets
 * as supported by the cisco vpn3000 concentrator series
 */
static int
dissect_tcpencap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *tcpencap_tree = NULL;
	proto_tree *tcpencap_unknown_tree = NULL;

	proto_item *tree_item = NULL;
	proto_item *unknown_item = NULL;
	tvbuff_t *next_tvb;
	guint32 reported_length = tvb_reported_length(tvb);
	guint32 offset;
	guint8  protocol;

	/* verify that this looks like a tcpencap packet */
	if (reported_length <= TRAILERLENGTH + 8 ||
	   !packet_is_tcpencap(tvb, pinfo, reported_length - TRAILERLENGTH) ) {
		return 0;
	}

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
	next_tvb = tvb_new_subset(tvb, 0, reported_length - TRAILERLENGTH , -1);
	if (protocol == TCP_ENCAP_P_UDP) {
		call_dissector(udp_handle, next_tvb, pinfo, tree);
	} else { /* Hopefully ESP */
		call_dissector(esp_handle, next_tvb, pinfo, tree);
	}

	return tvb_length(tvb);
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

	static gint *ett[] = {
		&ett_tcpencap,
		&ett_tcpencap_unknown,
	};

	module_t *tcpencap_module;

	void proto_reg_handoff_tcpencap(void);

	proto_tcpencap = proto_register_protocol(
		"TCP Encapsulation of IPsec Packets", "TCPENCAP", "tcpencap");
	proto_register_field_array(proto_tcpencap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	tcpencap_module = prefs_register_protocol(proto_tcpencap, proto_reg_handoff_tcpencap);
	prefs_register_uint_preference(tcpencap_module, "tcp.port", "IPSEC TCP Port",
		"Set the port for IPSEC/ISAKMP messages"
		"If other than the default of 10000)",
		10, &global_tcpencap_tcp_port);
}

void
proto_reg_handoff_tcpencap(void)
{
	static dissector_handle_t tcpencap_handle;
	static gboolean initialized = FALSE;
	static guint tcpencap_tcp_port;

	if (!initialized) {
		tcpencap_handle = new_create_dissector_handle(dissect_tcpencap, proto_tcpencap);
		esp_handle = find_dissector("esp");
		udp_handle = find_dissector("udp");
		initialized = TRUE;
	} else {
		dissector_delete_uint("tcp.port", tcpencap_tcp_port, tcpencap_handle);
	}

	tcpencap_tcp_port = global_tcpencap_tcp_port;
	dissector_add_uint("tcp.port", global_tcpencap_tcp_port, tcpencap_handle);
}

