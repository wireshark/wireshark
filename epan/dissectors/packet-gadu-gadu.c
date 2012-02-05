/* packet-gadu-gadu.c
 * Routines for Gadu-Gadu dissection
 * Copyright 2011, Jekub Zawadzki <darkjames@darkjames.ath.cx>
 *
 * $Id$
 *
 * Protocol documentation available at http://toxygen.net/libgadu/protocol/
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include <epan/dissectors/packet-tcp.h>

#define TCP_PORT_GADU_GADU 8074	/* assigned by IANA */

/* desegmentation of Gadu-Gadu over TCP */
static gboolean gadu_gadu_desegment = TRUE;

static gint proto_gadu_gadu = -1;

static gint ett_gadu_gadu = -1;

static gint hf_gadu_gadu_header_type_recv = -1;
static gint hf_gadu_gadu_header_type_send = -1;
static gint hf_gadu_gadu_header_length = -1;
static gint hf_gadu_gadu_data = -1;

/* original (GG_*) names likes in documentation (http://toxygen.net/libgadu/protocol/#ch1.16) */
static const value_string gadu_gadu_packets_type_recv[] = {
	{ 0x01, "GG_WELCOME" },
	{ 0x05, "GG_SEND_MSG_ACK" },
	{ 0x09, "GG_LOGIN_FAILED" },
	{ 0x0b, "GG_DISCONNECTING" },
	{ 0x0d, "GG_DISCONNECT_ACK" },
	{ 0x0e, "GG_PUBDIR50_REPLY" },
	{ 0x14, "GG_NEED_EMAIL" },
	{ 0x1f, "GG_DCC7_INFO" },
	{ 0x20, "GG_DCC7_NEW" },
	{ 0x21, "GG_DCC7_ACCEPT" },
	{ 0x22, "GG_DCC7_REJECT" },
	{ 0x23, "GG_DCC7_ID_REPLY" },
	{ 0x25, "GG_DCC7_ABORTED" },
	{ 0x27, "GG_XML_EVENT" },
	{ 0x2c, "GG_XML_ACTION" },
	{ 0x2e, "GG_RECV_MSG80" },
	{ 0x35, "GG_LOGIN_OK80" },
	{ 0x36, "GG_STATUS80" },
	{ 0x37, "GG_NOTIFY_REPLY80" },
	{ 0x41, "GG_USERLIST_REPLY100" },
	{ 0x44, "GG_USER_DATA" },
	{ 0x59, "GG_TYPING_NOTIFY" },
	{ 0x5a, "GG_OWN_MESSAGE" },
	{ 0x5b, "GG_OWN_RESOURCE_INFO" },
	{ 0, NULL }
};

static const value_string gadu_gadu_packets_type_send[] = {
	{ 0x08, "GG_PING" },
	{ 0x0d, "GG_ADD_NOTIFY" },
	{ 0x0e, "GG_REMOVE_NOTIFY" },
	{ 0x0f, "GG_NOTIFY_FIRST" },
	{ 0x10, "GG_NOTIFY_LAST" },
	{ 0x12, "GG_LIST_EMPTY" },
	{ 0x14, "GG_PUBDIR50_REQUEST" },
	{ 0x1f, "GG_DCC7_INFO" },
	{ 0x20, "GG_DCC7_NEW" },
	{ 0x21, "GG_DCC7_ACCEPT" },
	{ 0x22, "GG_DCC7_REJECT" },
	{ 0x23, "GG_DCC7_ID_REQUEST" },
	{ 0x25, "GG_DCC7_ABORT" },
	{ 0x2d, "GG_SEND_MSG80" },
	{ 0x31, "GG_LOGIN80" },
	{ 0x38, "GG_NEW_STATUS80" },
	{ 0x40, "GG_USERLIST_REQUEST100" },
	{ 0x46, "GG_RECV_MSG_ACK" },
	{ 0x59, "GG_TYPING_NOTIFY" },
	{ 0x62, "GG_OWN_DISCONNECT" },
	{ 0, NULL }
};

static guint
get_gadu_gadu_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint32 len = tvb_get_letohl(tvb, offset + 4);

	return len + 8;
}

static void
dissect_gadu_gadu_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *gadu_gadu_tree = NULL;
	proto_item *ti;
	int offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Gadu-Gadu");

	if (pinfo->srcport == TCP_PORT_GADU_GADU && pinfo->destport == TCP_PORT_GADU_GADU)
		pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	else if (pinfo->srcport == TCP_PORT_GADU_GADU)
		pinfo->p2p_dir = P2P_DIR_RECV;
	else if (pinfo->destport == TCP_PORT_GADU_GADU)
		pinfo->p2p_dir = P2P_DIR_SENT;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_gadu_gadu, tvb, 0, -1, ENC_NA);
		gadu_gadu_tree = proto_item_add_subtree(ti, ett_gadu_gadu);

		proto_tree_add_item(gadu_gadu_tree, (pinfo->p2p_dir == P2P_DIR_RECV) ? hf_gadu_gadu_header_type_recv : hf_gadu_gadu_header_type_send, tvb, 0, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(gadu_gadu_tree, hf_gadu_gadu_header_length, tvb, 4, 4, ENC_LITTLE_ENDIAN);
	}

	offset = 8;

	/* for now display rest of data as FT_BYTES. */
	if (tvb_length_remaining(tvb, offset) > 0) {
		proto_tree_add_item(gadu_gadu_tree, hf_gadu_gadu_data, tvb, offset, -1, ENC_NA);
	}
}

static int
dissect_gadu_gadu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, gadu_gadu_desegment, 8, get_gadu_gadu_pdu_len, dissect_gadu_gadu_pdu);
	return tvb_length(tvb);
}

void
proto_register_gadu_gadu(void)
{
	static hf_register_info hf[] = {
	/* header */
		{ &hf_gadu_gadu_header_type_recv,
			{ "Packet Type", "gadu-gadu.recv", FT_UINT32, BASE_HEX, VALS(gadu_gadu_packets_type_recv), 0x0, "Packet Type (recv)", HFILL }
		},
		{ &hf_gadu_gadu_header_type_send,
			{ "Packet Type", "gadu-gadu.send", FT_UINT32, BASE_HEX, VALS(gadu_gadu_packets_type_send), 0x0, "Packet Type (send)", HFILL }
		},
		{ &hf_gadu_gadu_header_length,
			{ "Packet Length", "gadu-gadu.len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
	/* data */
		{ &hf_gadu_gadu_data,
			{ "Packet Data", "gadu-gadu.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_gadu_gadu
	};

	module_t *gadu_gadu_module;

	proto_gadu_gadu = proto_register_protocol("Gadu-Gadu Protocol", "Gadu-Gadu", "gadu-gadu");

	gadu_gadu_module = prefs_register_protocol(proto_gadu_gadu, NULL);
	prefs_register_bool_preference(gadu_gadu_module, "desegment",
			"Reassemble Gadu-Gadu messages spanning multiple TCP segments",
			"Whether the Gadu-Gadu dissector should reassemble messages spanning multiple TCP segments."
			"To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
			&gadu_gadu_desegment);

	proto_register_field_array(proto_gadu_gadu, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gadu_gadu(void)
{
	dissector_handle_t gadu_gadu_handle = new_create_dissector_handle(dissect_gadu_gadu, proto_gadu_gadu);

	dissector_add_uint("tcp.port", TCP_PORT_GADU_GADU, gadu_gadu_handle);
}

