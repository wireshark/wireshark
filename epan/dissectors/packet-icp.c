/* packet-icp.c
 * Routines for ICP (internet cache protocol) packet disassembly
 * RFC 2186 && RFC 2187
 * By Peter Torvals
 * Copyright 1999 Peter Torvals
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define MAX_TEXTBUF_LENGTH 600
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>

static int proto_icp=-1;
static int hf_icp_length=-1;
static int hf_icp_opcode=-1;
static int hf_icp_version=-1;
static int hf_icp_request_nr=-1;

static gint ett_icp = -1;
static gint ett_icp_payload = -1;

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
{ CODE_ICP_OP_INVALID ,    "ICP_INVALID" },
{ CODE_ICP_OP_QUERY ,    "ICP_QUERY" },
{ CODE_ICP_OP_HIT ,    "ICP_HIT" },
{ CODE_ICP_OP_MISS ,    "ICP_MISS" },
{ CODE_ICP_OP_ERR ,    "ICP_ERR" },
{ CODE_ICP_OP_SEND,    "ICP_SEND" },
{ CODE_ICP_OP_SENDA, "ICP_SENDA"},
{ CODE_ICP_OP_DATABEG, "ICP_DATABEG"},
{ CODE_ICP_OP_DATA,    "ICP_DATA"},
{ CODE_ICP_OP_DATAEND, "ICP_DATA_END"},
{ CODE_ICP_OP_SECHO ,    "ICP_SECHO"},
{ CODE_ICP_OP_DECHO ,    "ICP_DECHO"},
{ CODE_ICP_OP_MISS_NOFETCH ,    "ICP_MISS_NOFETCH"},
{ CODE_ICP_OP_DENIED ,    "ICP_DENIED"},
{ CODE_ICP_OP_HIT_OBJ ,    "ICP_HIT_OBJ"},
{ 0,     NULL}
};

static void dissect_icp_payload(tvbuff_t *tvb, int offset,
        proto_tree *pload_tree, guint8 opcode)
{
  gint stringlength;
  guint16 objectlength;

  switch(opcode)
  {
	case CODE_ICP_OP_QUERY:
	 	/* 4 byte requester host address */
		proto_tree_add_text(pload_tree, tvb,offset,4,
			"Requester Host Address %s",
			tvb_ip_to_str(tvb, offset));
		offset += 4;

		/* null terminated URL */
		stringlength = tvb_strsize(tvb, offset);
		proto_tree_add_text(pload_tree, tvb, offset, stringlength,
			"URL: %s", tvb_get_ephemeral_string(tvb, offset, stringlength));
		break;

	case CODE_ICP_OP_SECHO:
	case CODE_ICP_OP_DECHO:
	case CODE_ICP_OP_HIT:
	case CODE_ICP_OP_MISS:
	case CODE_ICP_OP_ERR:
	case CODE_ICP_OP_MISS_NOFETCH:
	case CODE_ICP_OP_DENIED:
		stringlength = tvb_strsize(tvb, offset);
		proto_tree_add_text(pload_tree, tvb, offset, stringlength,
			"URL: %s", tvb_get_ephemeral_string(tvb, offset, stringlength));
		break;

	case CODE_ICP_OP_HIT_OBJ:
		/* null terminated URL */
		stringlength = tvb_strsize(tvb, offset);
		proto_tree_add_text(pload_tree, tvb, offset, stringlength,
			"URL: %s", tvb_get_ephemeral_string(tvb, offset, stringlength));
		offset += stringlength;

		/* 2 byte object size */
		/* object data not recommended by standard*/
		objectlength=tvb_get_ntohs(tvb, offset);
		proto_tree_add_text(pload_tree, tvb,offset,2,"Object length: %u", objectlength);
		offset += 2;

		/* object data not recommended by standard*/
		proto_tree_add_text(pload_tree, tvb,offset,objectlength,"Object data");
		if (objectlength > tvb_reported_length_remaining(tvb, offset))
		{
			proto_tree_add_text(pload_tree, tvb,offset,0,
				"Packet is fragmented, rest of object is in next udp packet");
		}
		break;
	default:
		break;
  }
}

static void dissect_icp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *icp_tree , *payload_tree;
  proto_item *ti , *payloadtf;
  guint8 opcode;
  guint16 message_length;
  guint32 request_number;
  guint32 options;
  guint32 option_data;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICP");
  col_clear(pinfo->cinfo, COL_INFO);

  opcode=tvb_get_guint8(tvb, 0);
  message_length=tvb_get_ntohs(tvb, 2);
  request_number=tvb_get_ntohl(tvb, 4);

  if (check_col(pinfo->cinfo, COL_INFO))
  {
        col_add_fstr(pinfo->cinfo,COL_INFO,"Opcode: %s (%u), Req Nr: %u",
		val_to_str(opcode, opcode_vals, "Unknown"), opcode,
		request_number);
  }

  if (tree)
  {

        ti = proto_tree_add_item(tree,proto_icp, tvb, 0, message_length, ENC_NA);
        icp_tree = proto_item_add_subtree(ti, ett_icp);

        proto_tree_add_uint(icp_tree,hf_icp_opcode, tvb, 0, 1, opcode);

        proto_tree_add_item(icp_tree,hf_icp_version, tvb, 1, 1, ENC_BIG_ENDIAN);

        proto_tree_add_uint(icp_tree,hf_icp_length, tvb, 2, 2, message_length);

        proto_tree_add_uint(icp_tree,hf_icp_request_nr, tvb, 4, 4,
                request_number);

	options=tvb_get_ntohl(tvb, 8);
	if ( (opcode == CODE_ICP_OP_QUERY) && ((options & 0x80000000 ) != 0) )
	{
		proto_tree_add_text(icp_tree, tvb,8,4,
			"option: ICP_FLAG_HIT_OBJ");
  	}
	if ( (opcode == CODE_ICP_OP_QUERY)&& ((options & 0x40000000 ) != 0) )
	{
		proto_tree_add_text(icp_tree, tvb,8,4,
			"option:ICP_FLAG_SRC_RTT");
  	}
	if ((opcode != CODE_ICP_OP_QUERY)&& ((options & 0x40000000 ) != 0))
	{
		option_data=tvb_get_ntohl(tvb, 12);
		proto_tree_add_text(icp_tree, tvb,8,8,
			"option: ICP_FLAG_SCR_RTT RTT=%u",
			option_data & 0x0000ffff);
	}

	proto_tree_add_text(icp_tree, tvb, 16, 4,
			"Sender Host IP address %s",
			tvb_ip_to_str(tvb, 16));

        payloadtf = proto_tree_add_text(icp_tree, tvb,
                        20, message_length - 20,
                        "Payload");
        payload_tree = proto_item_add_subtree(payloadtf, ett_icp_payload);
        dissect_icp_payload(tvb, 20, payload_tree, opcode);
  }
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
	};
	static gint *ett[] = {
		&ett_icp,
		&ett_icp_payload,
	};

	proto_icp = proto_register_protocol("Internet Cache Protocol",
	    "ICP", "icp");
	proto_register_field_array(proto_icp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_icp(void)
{
	dissector_handle_t icp_handle;

	icp_handle = create_dissector_handle(dissect_icp, proto_icp);
	dissector_add_uint("udp.port", UDP_PORT_ICP, icp_handle);
}
