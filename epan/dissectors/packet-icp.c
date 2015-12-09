/* packet-icp.c
 * Routines for ICP (internet cache protocol) packet disassembly
 * RFC 2186 && RFC 2187
 * By Peter Torvals
 * Copyright 1999 Peter Torvals
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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

#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_icp(void);
void proto_reg_handoff_icp(void);

static int proto_icp = -1;
static int hf_icp_length = -1;
static int hf_icp_opcode = -1;
static int hf_icp_version = -1;
static int hf_icp_request_nr = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_icp_url = -1;
static int hf_icp_rtt = -1;
static int hf_icp_object_data = -1;
static int hf_icp_requester_host_address = -1;
static int hf_icp_sender_host_ip_address = -1;
static int hf_icp_option_src_rtt = -1;
static int hf_icp_object_length = -1;
static int hf_icp_option_hit_obj = -1;

static gint ett_icp = -1;
static gint ett_icp_payload = -1;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_icp_fragmented_packet = EI_INIT;

#define UDP_PORT_ICP    3130

#define CODE_ICP_OP_QUERY 1
#define CODE_ICP_OP_INVALID 0
#define CODE_ICP_OP_HIT 2
#define CODE_ICP_OP_MISS 3
#define CODE_ICP_OP_ERR 4
#define CODE_ICP_OP_SEND 5
#define CODE_ICP_OP_SENDA 6
#define CODE_ICP_OP_DATABEG 7
#define CODE_ICP_OP_DATA 8
#define CODE_ICP_OP_DATAEND 9
#define CODE_ICP_OP_SECHO 10
#define CODE_ICP_OP_DECHO 11
#define CODE_ICP_OP_MISS_NOFETCH 21
#define CODE_ICP_OP_DENIED 22
#define CODE_ICP_OP_HIT_OBJ 23

static const value_string opcode_vals[] = {
{ CODE_ICP_OP_INVALID ,      "ICP_INVALID" },
{ CODE_ICP_OP_QUERY ,        "ICP_QUERY" },
{ CODE_ICP_OP_HIT ,          "ICP_HIT" },
{ CODE_ICP_OP_MISS ,         "ICP_MISS" },
{ CODE_ICP_OP_ERR ,          "ICP_ERR" },
{ CODE_ICP_OP_SEND,          "ICP_SEND" },
{ CODE_ICP_OP_SENDA,         "ICP_SENDA"},
{ CODE_ICP_OP_DATABEG,       "ICP_DATABEG"},
{ CODE_ICP_OP_DATA,          "ICP_DATA"},
{ CODE_ICP_OP_DATAEND,       "ICP_DATA_END"},
{ CODE_ICP_OP_SECHO ,        "ICP_SECHO"},
{ CODE_ICP_OP_DECHO ,        "ICP_DECHO"},
{ CODE_ICP_OP_MISS_NOFETCH , "ICP_MISS_NOFETCH"},
{ CODE_ICP_OP_DENIED ,       "ICP_DENIED"},
{ CODE_ICP_OP_HIT_OBJ ,      "ICP_HIT_OBJ"},
{ 0,     NULL}
};

static void dissect_icp_payload(tvbuff_t *tvb, packet_info *pinfo, int offset,
				proto_tree *pload_tree, guint8 opcode)
{
	gint stringlength;
	guint16 objectlength;
	proto_item* object_item;

	switch(opcode)
	{
	case CODE_ICP_OP_QUERY:
	 	/* 4 byte requester host address */
		proto_tree_add_item(pload_tree, hf_icp_requester_host_address, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		/* null terminated URL */
		stringlength = tvb_strsize(tvb, offset);
		proto_tree_add_item(pload_tree, hf_icp_url, tvb, offset, stringlength, ENC_ASCII|ENC_NA);
		break;

	case CODE_ICP_OP_SECHO:
	case CODE_ICP_OP_DECHO:
	case CODE_ICP_OP_HIT:
	case CODE_ICP_OP_MISS:
	case CODE_ICP_OP_ERR:
	case CODE_ICP_OP_MISS_NOFETCH:
	case CODE_ICP_OP_DENIED:
		stringlength = tvb_strsize(tvb, offset);
		proto_tree_add_item(pload_tree, hf_icp_url, tvb, offset, stringlength, ENC_ASCII|ENC_NA);
		break;

	case CODE_ICP_OP_HIT_OBJ:
		/* null terminated URL */
		stringlength = tvb_strsize(tvb, offset);
		proto_tree_add_item(pload_tree, hf_icp_url, tvb, offset, stringlength, ENC_ASCII|ENC_NA);
		offset += stringlength;

		/* 2 byte object size */
		/* object data not recommended by standard*/
		objectlength=tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(pload_tree, hf_icp_object_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* object data not recommended by standard*/
		object_item = proto_tree_add_item(pload_tree, hf_icp_object_data, tvb, offset, objectlength, ENC_NA);
		if (objectlength > tvb_reported_length_remaining(tvb, offset))
		{
			expert_add_info(pinfo, object_item, &ei_icp_fragmented_packet);
		}
		break;
	default:
		break;
	}
}

static int dissect_icp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *icp_tree , *payload_tree;
	proto_item *ti;
	guint8 opcode;
	guint16 message_length;
	guint32 request_number;
	guint32 options;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICP");
	col_clear(pinfo->cinfo, COL_INFO);

	opcode=tvb_get_guint8(tvb, 0);
	message_length=tvb_get_ntohs(tvb, 2);
	request_number=tvb_get_ntohl(tvb, 4);

	col_add_fstr(pinfo->cinfo,COL_INFO,"Opcode: %s (%u), Req Nr: %u",
		     val_to_str_const(opcode, opcode_vals, "Unknown"), opcode,
		     request_number);

	ti = proto_tree_add_item(tree,proto_icp, tvb, 0, message_length, ENC_NA);
	icp_tree = proto_item_add_subtree(ti, ett_icp);

	if (tree)
	{
		proto_tree_add_uint(icp_tree,hf_icp_opcode, tvb, 0, 1, opcode);

		proto_tree_add_item(icp_tree,hf_icp_version, tvb, 1, 1, ENC_BIG_ENDIAN);

		proto_tree_add_uint(icp_tree,hf_icp_length, tvb, 2, 2, message_length);

		proto_tree_add_uint(icp_tree,hf_icp_request_nr, tvb, 4, 4,
				    request_number);

		options=tvb_get_ntohl(tvb, 8);
		if ( (opcode == CODE_ICP_OP_QUERY) && ((options & 0x80000000 ) != 0) )
		{
			proto_tree_add_item(icp_tree, hf_icp_option_hit_obj, tvb, 8, 4, ENC_NA);
		}
		if ( (opcode == CODE_ICP_OP_QUERY)&& ((options & 0x40000000 ) != 0) )
		{
			proto_tree_add_item(icp_tree, hf_icp_option_src_rtt, tvb, 8, 4, ENC_NA);
		}
		if ((opcode != CODE_ICP_OP_QUERY)&& ((options & 0x40000000 ) != 0))
		{
			proto_tree_add_item(icp_tree, hf_icp_option_src_rtt, tvb, 8, 4, ENC_NA);
            proto_tree_add_item(icp_tree, hf_icp_rtt, tvb, 12, 4, ENC_BIG_ENDIAN);
		}

		proto_tree_add_item(icp_tree, hf_icp_sender_host_ip_address, tvb, 16, 4, ENC_BIG_ENDIAN);
	}

	payload_tree = proto_tree_add_subtree(icp_tree, tvb,
						      20, message_length - 20,
						      ett_icp_payload, NULL, "Payload");
	dissect_icp_payload(tvb, pinfo, 20, payload_tree, opcode);

	return tvb_captured_length(tvb);
}

void
proto_register_icp(void)
{
	static hf_register_info hf[] = {
		{ &hf_icp_opcode,
		  { "Opcode", "icp.opcode", FT_UINT8, BASE_HEX, VALS(opcode_vals),
		    0x0, NULL, HFILL }},

		{ &hf_icp_version,
		  { "Version", "icp.version", FT_UINT8, BASE_DEC, NULL,
		    0x0, NULL, HFILL }},

		{ &hf_icp_length,
		  { "Length", "icp.length", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL }},

		{ &hf_icp_request_nr,
		  { "Request Number", "icp.nr", FT_UINT32, BASE_DEC, NULL,
		    0x0, NULL, HFILL }},

      { &hf_icp_requester_host_address, { "Requester Host Address", "icp.requester_host_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_icp_url, { "URL", "icp.url", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_icp_object_length, { "Object length", "icp.object_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_icp_object_data, { "Object data", "icp.object_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_icp_option_hit_obj, { "Option: ICP_FLAG_HIT_OBJ", "icp.option.hit_obj", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_icp_option_src_rtt, { "Option: ICP_FLAG_SRC_RTT", "icp.option.src_rtt", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_icp_rtt, { "RTT", "icp.rtt", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_icp_sender_host_ip_address, { "Sender Host IP address", "icp.sender_host_ip_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_icp,
		&ett_icp_payload,
	};

	static ei_register_info ei[] = {
		{ &ei_icp_fragmented_packet, { "icp.fragmented_packet", PI_PROTOCOL, PI_WARN, "Packet is fragmented", EXPFILL }},
	};

	expert_module_t* expert_icp;

	proto_icp = proto_register_protocol("Internet Cache Protocol", "ICP", "icp");

	proto_register_field_array(proto_icp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_icp = expert_register_protocol(proto_icp);
	expert_register_field_array(expert_icp, ei, array_length(ei));
}

void
proto_reg_handoff_icp(void)
{
	dissector_handle_t icp_handle;

	icp_handle = create_dissector_handle(dissect_icp, proto_icp);
	dissector_add_uint("udp.port", UDP_PORT_ICP, icp_handle);
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
