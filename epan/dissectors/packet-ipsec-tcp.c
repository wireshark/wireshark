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

static int hf_tcpencap_unknown = -1;

static int proto_tcpencap = -1;
static gint ett_tcpencap = -1;

#define TCP_CISCO_IPSEC 10000
static guint global_tcpencap_tcp_port = TCP_CISCO_IPSEC;

static dissector_handle_t esp_handle;
static dissector_handle_t udp_handle;

/*
 * TCP Encapsulation of IPsec Packets	
 * as supported by the cisco vpn3000 concentrator series
 */
static void
dissect_tcpencap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *tcpencap_tree = NULL;
	proto_item *ti = NULL;
	tvbuff_t *next_tvb;
	guint32 reported_length = tvb_reported_length(tvb);

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCPENCAP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_tcpencap, tvb, 0, -1, FALSE);
		tcpencap_tree = proto_item_add_subtree(ti, ett_tcpencap);
	}

	/* Dissect the trailer following the encapsulated IPSEC/ISAKMP packet */
	proto_tree_add_item(tcpencap_tree, hf_tcpencap_unknown, tvb,
		reported_length - 16, 16, FALSE);

	/* If the first 4 bytes are 0x01f401f4 (udp src and dst port = 500)
	   we most likely have UDP (isakmp) traffic */
	
	/* Create the tvbuffer for the next dissector */
	next_tvb = tvb_new_subset(tvb, 0, reported_length - 16 , -1);
	if (tvb_get_ntohl(tvb, 0) == 0x01f401f4) {
		call_dissector(udp_handle, next_tvb, pinfo, tree);
	} else { /* Hopefully ESP */
		call_dissector(esp_handle, next_tvb, pinfo, tree);
	}
}

void
proto_reg_handoff_tcpencap(void)
{
	dissector_handle_t tcpencap_handle;

	esp_handle = find_dissector("esp");
	udp_handle = find_dissector("udp");

	tcpencap_handle = create_dissector_handle(dissect_tcpencap, proto_tcpencap);
	dissector_add("tcp.port", global_tcpencap_tcp_port, tcpencap_handle);
}

void
proto_register_tcpencap(void)
{
	static hf_register_info hf[] = {

		{ &hf_tcpencap_unknown,
		{ "Unknown Trailer",      "tcpencap.unknown", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},
	};

	static gint *ett[] = {
		&ett_tcpencap,
	};

	module_t *tcpencap_module;

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

