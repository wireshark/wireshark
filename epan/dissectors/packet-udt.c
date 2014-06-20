/* packet-udt.c
 *
 * Routines for UDT packet dissection
 *
 * Copyright 2013 (c) chas williams <chas@cmf.nrl.navy.mil>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>

/*
 * based on http://tools.ietf.org/html/draft-gg-udt-03
 */

#define UDT_TYPE_DATA			0
#define UDT_TYPE_CONTROL		1

#define UDT_PACKET_TYPE_HANDSHAKE	0x0000
#define UDT_PACKET_TYPE_KEEPALIVE	0x0001
#define UDT_PACKET_TYPE_ACK		0x0002
#define UDT_PACKET_TYPE_NAK		0x0003
#define UDT_PACKET_TYPE_SHUTDOWN	0x0005
#define UDT_PACKET_TYPE_ACK2		0x0006

#define UDT_HANDSHAKE_TYPE_STREAM	0
#define UDT_HANDSHAKE_TYPE_DGRAM	1

void proto_register_udt(void);
void proto_reg_handoff_udt(void);

static const value_string udt_packet_types[] = {
	{UDT_PACKET_TYPE_HANDSHAKE, "handshake"},
	{UDT_PACKET_TYPE_KEEPALIVE, "keepalive"},
	{UDT_PACKET_TYPE_ACK,       "ack"},
	{UDT_PACKET_TYPE_NAK,       "nak"},
	{UDT_PACKET_TYPE_SHUTDOWN,  "shutdown"},
	{UDT_PACKET_TYPE_ACK2,      "ack2"},
	{0, NULL},
};

static const value_string udt_handshake_types[] = {
	{UDT_HANDSHAKE_TYPE_STREAM, "STREAM"},
	{UDT_HANDSHAKE_TYPE_DGRAM,  "DGRAM"},
	{0, NULL},
};

static const value_string udt_types[] = {
	{UDT_TYPE_DATA,    "DATA"},
	{UDT_TYPE_CONTROL, "CONTROL"},
	{0, NULL},
};

static int proto_udt = -1;
static int hf_udt_iscontrol = -1;
static int hf_udt_type = -1;
static int hf_udt_seqno = -1;
static int hf_udt_ack_seqno = -1;
static int hf_udt_ackno = -1;
static int hf_udt_msgno = -1;
static int hf_udt_msgno_first = -1;
static int hf_udt_msgno_last = -1;
static int hf_udt_msgno_inorder = -1;
static int hf_udt_timestamp = -1;
static int hf_udt_id = -1;
static int hf_udt_addinfo = -1;
static int hf_udt_rtt = -1;
static int hf_udt_rttvar = -1;
static int hf_udt_bufavail = -1;
static int hf_udt_rate = -1;
static int hf_udt_linkcap = -1;
static int hf_udt_handshake_version = -1;
static int hf_udt_handshake_type = -1;
static int hf_udt_handshake_isn = -1;
static int hf_udt_handshake_mtu = -1;
static int hf_udt_handshake_flow_window = -1;
static int hf_udt_handshake_reqtype = -1;
static int hf_udt_handshake_id = -1;
static int hf_udt_handshake_cookie = -1;
static int hf_udt_handshake_peerip = -1;

static gint ett_udt = -1;

static expert_field ei_udt_nak_seqno = EI_INIT;

static dissector_handle_t udt_handle;
static dissector_handle_t data_handle;

static int
dissect_udt(tvbuff_t *tvb, packet_info* pinfo, proto_tree *parent_tree,
	    void *data _U_)
{
	proto_tree *tree;
	proto_item *udt_item;
	int         is_control, type;
	guint       i;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDT");
	col_clear(pinfo->cinfo, COL_INFO);

	is_control = tvb_get_ntohl(tvb, 0) & 0x80000000;
	type = (tvb_get_ntohl(tvb, 0) >> 16) & 0x7fff;

	if (is_control)
		col_add_fstr(pinfo->cinfo, COL_INFO, "UDT type: %s  id: %x",
			     val_to_str(type, udt_packet_types,
					"Unknown Control Type (%x)"),
			     tvb_get_ntohl(tvb, 12));
	else
		col_add_fstr(pinfo->cinfo, COL_INFO,
			     "UDT type: data  seqno: %u  msgno: %u  id: %x",
			     tvb_get_ntohl(tvb, 0) & 0x7fffffff,
			     tvb_get_ntohl(tvb, 4) & 0x1fffffff,
			     tvb_get_ntohl(tvb, 12));

	udt_item = proto_tree_add_item(parent_tree, proto_udt, tvb,
					      0, -1, ENC_NA);
	tree = proto_item_add_subtree(udt_item, ett_udt);

	proto_tree_add_item(tree, hf_udt_iscontrol, tvb, 0, 4, ENC_BIG_ENDIAN);
	if (is_control) {
		if (tree) {
			proto_tree_add_item(tree, hf_udt_type, tvb, 0, 2,
					    ENC_BIG_ENDIAN);
			switch (type) {
			case UDT_PACKET_TYPE_ACK:
				proto_tree_add_item(tree, hf_udt_ackno, tvb, 4, 4,
						    ENC_BIG_ENDIAN);
				break;
			case UDT_PACKET_TYPE_ACK2:
				proto_tree_add_item(tree, hf_udt_ackno, tvb, 4, 4,
						    ENC_BIG_ENDIAN);
				break;
			default:
				proto_tree_add_item(tree, hf_udt_addinfo, tvb, 4, 4,
						    ENC_BIG_ENDIAN);
			}
			proto_tree_add_item(tree, hf_udt_timestamp, tvb, 8, 4,
					    ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_udt_id, tvb, 12, 4,
					    ENC_BIG_ENDIAN);
		}

		switch (type) {
		case UDT_PACKET_TYPE_HANDSHAKE:
			if (tree) {
				proto_tree_add_item(tree, hf_udt_handshake_version, tvb,
						    16,  4, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_handshake_type, tvb,
						    20,  4, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_handshake_isn, tvb,
						    24,  4, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_handshake_mtu, tvb,
						    28,  4, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_handshake_flow_window, tvb,
						    32,  4, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_handshake_reqtype, tvb,
						    36,  4, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_handshake_id, tvb,
						    40,  4, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_handshake_cookie, tvb,
						    44,  4, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_handshake_peerip, tvb,
						    48, 16, ENC_NA);
				proto_item_set_len(udt_item, 64);
			}
			break;
		case UDT_PACKET_TYPE_ACK:
			if (tree) {
				proto_tree_add_item(tree, hf_udt_ack_seqno, tvb, 16, 4,
						    ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_rtt,      tvb, 20, 4,
						    ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_rttvar,   tvb, 24, 4,
						    ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_udt_bufavail, tvb, 28, 4,
						    ENC_BIG_ENDIAN);
				/* if not a light ack, decode the rate and link capacity */
				if (tvb_reported_length(tvb) == 40) {
					proto_tree_add_item(tree, hf_udt_rate, tvb,
							    32, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_udt_linkcap, tvb,
							    36, 4, ENC_BIG_ENDIAN);
					proto_item_set_len(udt_item, 40);
				}
				else
				{
					proto_item_set_len(udt_item, 32);
				}
			}
			break;
		case UDT_PACKET_TYPE_NAK:
			for (i = 16; i < tvb_reported_length(tvb); i = i + 4) {
				guint32 start, finish;
				int     is_range;

				is_range = tvb_get_ntohl(tvb, i) & 0x80000000;
				start = tvb_get_ntohl(tvb, i) & 0x7fffffff;

				if (is_range) {
					finish = tvb_get_ntohl(tvb, i + 4) & 0x7fffffff;

					proto_tree_add_expert_format(tree, pinfo, &ei_udt_nak_seqno,
									tvb, i, 8, "Missing Sequence Number(s): %u-%u",
								    start, finish);
					i = i + 4;
				} else {
					proto_tree_add_expert_format(tree, pinfo, &ei_udt_nak_seqno,
								    tvb, i, 4, "Missing Sequence Number: %u",
								    start);
				}
			}

			proto_item_set_len(udt_item, tvb_reported_length(tvb));
			break;
		}
	} else {
		/* otherwise, a data packet */
		tvbuff_t *next_tvb;

		if (tree) {
			proto_tree_add_item(tree, hf_udt_seqno,		tvb,  0, 4,
					    ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_udt_msgno_first,	tvb,  4, 4,
					    ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_udt_msgno_last,	tvb,  4, 4,
					    ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_udt_msgno_inorder, tvb,  4, 4,
					    ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_udt_msgno,		tvb,  4, 4,
					    ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_udt_timestamp,	tvb,  8, 4,
					    ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_udt_id,		tvb, 12, 4,
					    ENC_BIG_ENDIAN);

		}
		next_tvb = tvb_new_subset_remaining(tvb, 16);
		call_dissector(data_handle, next_tvb, pinfo, tree);
	}

	return tvb_reported_length(tvb);
}

static gboolean
dissect_udt_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	conversation_t *conv;

	/* Must have at least 24 captured bytes for heuristic check */
	if (tvb_captured_length(tvb) < 24)
		return FALSE;

	/* detect handshake control packet */
	if (tvb_get_ntohl(tvb, 0) != (0x80000000 | UDT_PACKET_TYPE_HANDSHAKE))
		return FALSE;

	/* must be version 4 */
	if ((tvb_get_ntohl(tvb, 16) != 4))
		return FALSE;

	/* must be datagram or stream */
	if ((tvb_get_ntohl(tvb, 20) != UDT_HANDSHAKE_TYPE_DGRAM)
	    && (tvb_get_ntohl(tvb, 20) != UDT_HANDSHAKE_TYPE_STREAM))
		return FALSE;

	conv = find_or_create_conversation(pinfo);
	conversation_set_dissector(conv, udt_handle);
	dissect_udt(tvb, pinfo, tree, data);

	return TRUE;
}

void proto_register_udt(void)
{
	expert_module_t *expert_udt;

	static hf_register_info hf[] = {
		{&hf_udt_iscontrol, {
				"Type", "udt.iscontrol",
				 FT_UINT32, BASE_DEC,
				VALS(udt_types), 0x80000000, NULL, HFILL}},

		{&hf_udt_type, {
				"Type", "udt.type",
				FT_UINT16, BASE_HEX,
				VALS(udt_packet_types), 0x7fff, NULL, HFILL}},

		{&hf_udt_seqno, {
				"Sequence Number", "udt.seqno",
				FT_UINT32, BASE_DEC,
				NULL, 0x7fffffff, NULL, HFILL}},

		{&hf_udt_addinfo, {
				"Additional Info", "udt.addinfo",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_msgno, {
				"Message Number", "udt.msgno",
				FT_UINT32, BASE_DEC,
				NULL, 0x1fffffff, NULL, HFILL}},

		{&hf_udt_msgno_first, {
				"First Indicator", "udt.msg.first",
				FT_UINT32, BASE_DEC,
				NULL, 0x80000000, NULL, HFILL}},

		{&hf_udt_msgno_last, {
				"Last Indicator", "udt.msg.last",
				FT_UINT32, BASE_DEC,
				NULL, 0x40000000, NULL, HFILL}},

		{&hf_udt_msgno_inorder, {
				"In-Order Indicator", "udt.msg.order",
				FT_UINT32, BASE_DEC,
				NULL, 0x20000000, NULL, HFILL}},

		{&hf_udt_timestamp, {
				"Timestamp", "udt.timestamp",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_id, {
				"ID", "udt.id",
				FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_ack_seqno, {
				"Ack Sequence Number", "udt.ack_seqno",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_ackno, {
				"Ack Number", "udt.ackno",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_rtt, {
				"RTT (microseconds)", "udt.rtt",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_rttvar, {
				"RTT Variance (microseconds)", "udt.rttvar",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_bufavail, {
				"Buffer Available (packets)", "udt.rttvar",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_rate, {
				"Rate (packets/second)", "udt.rate",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_linkcap, {
				"Link Capacity (packets/second)", "udt.linkcap",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_handshake_version, {
				"Version", "udt.hs.version",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_handshake_type, {
				"Type", "udt.hs.type",
				FT_UINT32, BASE_DEC,
				VALS(udt_handshake_types), 0, NULL,
				HFILL}},

		{&hf_udt_handshake_isn, {
				"Initial Sequence Number", "udt.hs.isn",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_handshake_mtu, {
				"MTU", "udt.hs.mtu",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_handshake_flow_window, {
				"Flow Window", "udt.hs.flow_window",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_handshake_reqtype, {
				"Requested Type", "udt.hs.reqtype",
				FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_handshake_id, {
				"ID", "udt.hs.id",
				FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_handshake_cookie, {
				"SYN Cookie", "udt.hs.cookie",
				FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL}},

		{&hf_udt_handshake_peerip, {
				"Peer IP Address", "udt.hs.peerip",
				FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL}},
	};

	static gint *ett[] = {
		&ett_udt,
	};

	static ei_register_info ei[] = {
		{ &ei_udt_nak_seqno,
		  { "udt.nak_seqno", PI_SEQUENCE, PI_NOTE,
		    "Missing Sequence Number(s)", EXPFILL }},
	};

	proto_udt = proto_register_protocol("UDT Protocol", "UDT", "udt");
	proto_register_field_array(proto_udt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_udt = expert_register_protocol(proto_udt);
	expert_register_field_array(expert_udt, ei, array_length(ei));
}

void proto_reg_handoff_udt(void)
{
	data_handle = find_dissector("data");
	udt_handle  = new_create_dissector_handle(dissect_udt, proto_udt);

	heur_dissector_add("udp", dissect_udt_heur, proto_udt);
	dissector_add_for_decode_as("udp.port", udt_handle);
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
