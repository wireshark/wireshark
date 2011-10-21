/* packet-sm.c
 * Routines for Cisco Session Management Protocol dissection
 * Copyright 2004, Duncan Sargeant <dunc-ethereal@rcpt.to>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * This is basically a glue dissector for the Cisco SM protocol.  It sits
 * between the RUDP and MTP3 layers in conversations on port 7000 between
 * SLTs and MGCs.  A link to an overview of the technology :
 *
 * http://www.cisco.com/en/US/products/sw/netmgtsw/ps4883/products_installation_and_configuration_guide_chapter09186a008010950a.html
 *
 * Link showing debugs of the protocol:
 * http://www.cisco.com/univercd/cc/td/doc/product/access/sc/rel7/omts/omts_apb.htm#30052
 *
 * I'm unable to get local debugs of this protocol, as the SLT's are
 * slow cpu cisco 2600's, and they tend to drop the signalling links
 * if you turn any debugging on!  But there's not much interesting
 * here, its just glue to get the ISUP/MTP3 data nicely.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <epan/packet.h>

#define MESSAGE_TYPE_START				0
#define MESSAGE_TYPE_STOP				1
#define MESSAGE_TYPE_ACTIVE				2
#define MESSAGE_TYPE_STANDBY			3
#define MESSAGE_TYPE_Q_HOLD_INVOKE		4
#define MESSAGE_TYPE_Q_HOLD_RESPONSE	5
#define MESSAGE_TYPE_Q_RESUME_INVOKE	6
#define MESSAGE_TYPE_Q_RESUME_RESPONSE	7
#define MESSAGE_TYPE_Q_RESET_INVOKE		8
#define MESSAGE_TYPE_Q_RESET_RESPONSE	9
#define MESSAGE_TYPE_PDU				0x8000

static const value_string sm_message_type_value[] = {
	{ MESSAGE_TYPE_START,			"Start Message" },
	{ MESSAGE_TYPE_STOP,			"Stop Message" },
	{ MESSAGE_TYPE_ACTIVE,			"Active Message" },
	{ MESSAGE_TYPE_STANDBY,			"Standby Message" },
	{ MESSAGE_TYPE_Q_HOLD_INVOKE,  		"Q_HOLD Invoke Message" },
	{ MESSAGE_TYPE_Q_HOLD_RESPONSE,  	"Q_HOLD Response Message" },
	{ MESSAGE_TYPE_Q_RESUME_INVOKE,  	"Q_RESUME Invoke Message" },
	{ MESSAGE_TYPE_Q_RESUME_RESPONSE,	"Q_RESUME Response Message" },
	{ MESSAGE_TYPE_Q_RESET_INVOKE,    	"Q_RESET Invoke Message" },
	{ MESSAGE_TYPE_Q_RESET_RESPONSE,  	"Q_RESET Response Message" },
	{ MESSAGE_TYPE_PDU,                	"PDU Message" },
  	{ 0,                                  	NULL }
};

static const value_string sm_message_type_value_info[] = {
        { MESSAGE_TYPE_START,                   "Start" },
        { MESSAGE_TYPE_STOP,                    "Stop" },
        { MESSAGE_TYPE_ACTIVE,                  "Active" },
        { MESSAGE_TYPE_STANDBY,                 "Standby" },
        { MESSAGE_TYPE_Q_HOLD_INVOKE,           "Q_HOLD Invoke" },
        { MESSAGE_TYPE_Q_HOLD_RESPONSE,         "Q_HOLD Response" },
        { MESSAGE_TYPE_Q_RESUME_INVOKE,         "Q_RESUME Invoke" },
        { MESSAGE_TYPE_Q_RESUME_RESPONSE,       "Q_RESUME Response" },
        { MESSAGE_TYPE_Q_RESET_INVOKE,          "Q_RESET Invoke" },
        { MESSAGE_TYPE_Q_RESET_RESPONSE,        "Q_RESET Response" },
        { MESSAGE_TYPE_PDU,                     "PDU" },
        { 0,                                    NULL }
};


#define PDU_MTP3_TO_SLT			0x10
#define PDU_MTP3_FROM_SLT		0x11

#define PDU_SET_STATE			0x44
#define PDU_RETURN_STATE		0x45

static const value_string sm_pdu_type_value[] = {
	{ PDU_MTP3_TO_SLT,		"mtp3 to SLT"},
	{ PDU_MTP3_FROM_SLT, 		"mtp3 from SLT"},
	{ PDU_SET_STATE, 		"set session state"},
	{ PDU_RETURN_STATE,		"return session state"},
        { 0,                    NULL }
};

/* TODO: Change to useful name once known */
#define SM_PROTOCOL_X100 0x0100
#define SM_PROTOCOL_X101 0x0101
#define SM_PROTOCOL_X114 0x0114
#define SM_PROTOCOL_X122 0x0122


/* Initialize the protocol and registered fields */
static int proto_sm = -1;

static int hf_sm_sm_msg_type = -1;
static int hf_sm_protocol = -1;
static int hf_sm_msg_id = -1;
static int hf_sm_msg_type = -1;
static int hf_sm_channel = -1;
static int hf_sm_bearer = -1;
static int hf_sm_len = -1;
static int hf_sm_ip_addr = -1;
static int hf_sm_context = -1;
static int hf_sm_eisup_msg_id = -1;
static int hf_sm_tag = -1;

/* Initialize the subtree pointers */
static gint ett_sm = -1;

static dissector_handle_t sdp_handle;
static dissector_handle_t mtp3_handle;
static dissector_handle_t data_handle;

/* Code to actually dissect the packets */
static void
dissect_sm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *sm_tree;
	tvbuff_t *next_tvb = NULL;
	guint32 sm_message_type;
	guint16 protocol;
	guint16 msg_type = 0;
	guint16 length;
	guint16 tag;
	int     offset = 0;

	sm_message_type = tvb_get_ntohl(tvb,offset);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SM");

	col_add_fstr(pinfo->cinfo, COL_INFO, "Cisco SM Packet (%s)",
		val_to_str(sm_message_type, sm_message_type_value_info,"reserved"));

	ti = proto_tree_add_item(tree, proto_sm, tvb, offset, 0, ENC_NA);
	sm_tree = proto_item_add_subtree(ti, ett_sm);

	proto_tree_add_uint_format(sm_tree, hf_sm_sm_msg_type, tvb, offset, 4, sm_message_type,
		"SM Message type: %s (0x%0x)", val_to_str(sm_message_type, sm_message_type_value, "reserved"), sm_message_type);

	offset = offset + 4;
	if (sm_message_type ==  MESSAGE_TYPE_PDU) {
		proto_tree_add_item(sm_tree, hf_sm_protocol, tvb, offset, 2, ENC_BIG_ENDIAN);
		protocol = tvb_get_ntohs(tvb,offset);
		offset = offset + 2;
		switch(protocol){
		case SM_PROTOCOL_X100:
		case SM_PROTOCOL_X122:
			if (!tree)
				return;
			/* Protocol 0x100/0x122 only contains a length and then an EISUP packet */
			proto_tree_add_item(sm_tree, hf_sm_len, tvb, offset, 2, ENC_BIG_ENDIAN);
			length = tvb_get_ntohs(tvb,offset);
			offset = offset + 2;
			proto_item_set_len(ti, 8);

			/* This should be the EISUP dissector but we havent got one
			 * right now - so decode it as data for now ... */
			next_tvb = tvb_new_subset(tvb, offset, length, length);
			call_dissector(data_handle, next_tvb, pinfo, sm_tree);

			break;
		case SM_PROTOCOL_X101:
			if (!tree)
				return;
			/* XXX Reveres enginered so this may not be correct!!!
			 * EISUP - used between Cisco HSI and Cisco PGW devices,
			 * uses RUDP with default port number 8003.
			 * Protocol stack is RUDP->Cisco SM->SDP.
			 * This implementation is PROPRIETARY
			 */
			proto_tree_add_item(sm_tree, hf_sm_len, tvb, offset, 2, ENC_BIG_ENDIAN);
			length = tvb_get_ntohs(tvb,offset);
			offset = offset + 2;
			proto_item_set_len(ti, length + offset);
			/* The next stuff seems to be IP addr */
			proto_tree_add_item(sm_tree, hf_sm_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset = offset + 4;
			/* This part looks to be the same per session */
			proto_tree_add_item(sm_tree, hf_sm_context, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset = offset +4;
			/* Some sort of message type? */
			proto_tree_add_item(sm_tree, hf_sm_eisup_msg_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset = offset + 1;
			/* XXX Problem are tags 1 or two bytes???*/
			proto_tree_add_item(sm_tree, hf_sm_tag, tvb, offset, 2, ENC_BIG_ENDIAN);

			tag = tvb_get_ntohs(tvb,offset);
			offset = offset +2;
			if (tag== 0x01ac) {
				proto_tree_add_item(sm_tree, hf_sm_len, tvb, offset, 2, ENC_BIG_ENDIAN);
				length = tvb_get_ntohs(tvb,offset);
				offset = offset +2;
				next_tvb = tvb_new_subset(tvb, offset, length, length);
				call_dissector(sdp_handle, next_tvb, pinfo, sm_tree);
				offset = offset+length;

			}
			/*return;*/
			break;
		case SM_PROTOCOL_X114:
			if (!tree)
				return;
			/* XXX Reveres enginered so this may not be correct!!! */
			proto_tree_add_item(sm_tree, hf_sm_len, tvb, offset, 2, ENC_BIG_ENDIAN);
			length = tvb_get_ntohs(tvb,offset);
			offset = offset + 2;
			proto_item_set_len(ti, length + offset);
			/* The next stuff seems to be IP addr */
			proto_tree_add_item(sm_tree, hf_sm_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset = offset + 4;
			proto_tree_add_item(sm_tree, hf_sm_context, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset = offset +4;
			/* Some sort of message type? */
			proto_tree_add_item(sm_tree, hf_sm_eisup_msg_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset = offset + 1;
			/* XXX Problem are tags 1 or two bytes???*/
			proto_tree_add_item(sm_tree, hf_sm_tag, tvb, offset, 2, ENC_BIG_ENDIAN);

			tag = tvb_get_ntohs(tvb,offset);
			offset = offset +2;
			if (tag== 0x01ac) {
				proto_tree_add_item(sm_tree, hf_sm_len, tvb, offset, 2, ENC_BIG_ENDIAN);
				length = tvb_get_ntohs(tvb,offset);
				offset = offset +2;
				next_tvb = tvb_new_subset(tvb, offset, length, length);
				call_dissector(sdp_handle, next_tvb, pinfo, sm_tree);
				offset = offset+length;

			}
			break;
		default:
			proto_tree_add_item(sm_tree, hf_sm_msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset = offset +2;
			msg_type = tvb_get_ntohs(tvb,offset);
			proto_tree_add_uint_format(sm_tree, hf_sm_msg_type, tvb, offset, 2, msg_type,
				"Message type: %s (0x%0x)", val_to_str(msg_type, sm_pdu_type_value, "reserved"),
				msg_type);
			msg_type = tvb_get_ntohs(tvb,offset);
			offset = offset + 2;
			proto_tree_add_item(sm_tree, hf_sm_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset = offset + 2;
			proto_tree_add_item(sm_tree, hf_sm_bearer, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset = offset +2;
			proto_tree_add_item(sm_tree, hf_sm_len, tvb, offset, 2, ENC_BIG_ENDIAN);
			length = tvb_get_ntohs(tvb,offset);
			offset = offset +2;
			proto_item_set_len(ti, 16);

			if (length > 0) {
				next_tvb = tvb_new_subset(tvb, offset, length, length);

				if ((msg_type == PDU_MTP3_TO_SLT || msg_type == PDU_MTP3_FROM_SLT)) {
					call_dissector(mtp3_handle, next_tvb, pinfo, tree);
				} else {
					call_dissector(data_handle, next_tvb, pinfo, tree);
				}
			}
		}
	}

}

void
proto_register_sm(void)
{
	static hf_register_info hf[] = {
		{ &hf_sm_sm_msg_type,
			{ "SM Message Type",           "sm.sm_msg_type",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_protocol,
			{ "Protocol Type",           "sm.protocol",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_msg_id,
			{ "Message ID",           "sm.msgid",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_msg_type,
			{ "Message Type",           "sm.msg_type",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_channel,
			{ "Channel ID",           "sm.channel",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_bearer,
			{ "Bearer ID",           "sm.bearer",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_len,
			{ "Length",           "sm.len",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_ip_addr,
			{ "IPv4 address","sm.ip_addr",
			FT_IPv4,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_context,
			{ "Context","sm.context",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Context(guesswork!)", HFILL }
		},
		{ &hf_sm_eisup_msg_id,
			{ "Message id","sm.eisup_message_id",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Message id(guesswork!)", HFILL }
		},
		{ &hf_sm_tag,
			{ "Tag","sm.tag",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Tag(guesswork!)", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sm,
	};

/* Register the protocol name and description */
	proto_sm = proto_register_protocol("Cisco Session Management",
	    "SM", "sm");

	register_dissector("sm", dissect_sm, proto_sm);

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_sm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_sm(void)
{
	sdp_handle  = find_dissector("sdp");
	mtp3_handle = find_dissector("mtp3");
	data_handle = find_dissector("data");
}

