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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This is basically a glue dissector for the Cisco SM protocol.  It sits
 * between the RUDP and MTP3 layers between SLTs and MGCs.
 *
 * A link to an overview of the technology :
 * http://www.cisco.com/en/US/products/sw/netmgtsw/ps4883/products_installation_and_configuration_guide_chapter09186a008010950a.html
 * Link showing debugs of the protocol:
 * http://www.cisco.com/univercd/cc/td/doc/product/access/sc/rel7/omts/omts_apb.htm#30052
 * Scroll down to Backhaul Debug Event/Cause/Reason Codes:
 * http://www.cisco.com/en/US/docs/ios-xml/ios/debug/command/s1/db-s2.html#GUID-83B6671D-B86F-4B41-819C-85D14F4AACAE
 * Free/Opensource implementation:
 * http://yate.null.ro/websvn/filedetails.php?repname=yate&path=%2Ftrunk%2Fmodules%2Fserver%2Fciscosm.cpp
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#define MESSAGE_TYPE_START              0
#define MESSAGE_TYPE_STOP               1
#define MESSAGE_TYPE_ACTIVE             2
#define MESSAGE_TYPE_STANDBY            3
#define MESSAGE_TYPE_Q_HOLD_INVOKE      4
#define MESSAGE_TYPE_Q_HOLD_RESPONSE    5
#define MESSAGE_TYPE_Q_RESUME_INVOKE    6
#define MESSAGE_TYPE_Q_RESUME_RESPONSE  7
#define MESSAGE_TYPE_Q_RESET_INVOKE     8
#define MESSAGE_TYPE_Q_RESET_RESPONSE   9
#define MESSAGE_TYPE_PDU                0x8000

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

static const value_string sm_alignment_type[] = {
	{ 0x00, "Unknown (probably linkset was already up)"},
	{ 0x03, "Emergency alignment"},
	{ 0x04, "Normal alignment"},
	{ 0x05, "Power On MTP2"},
	{ 0x06, "Start MTP2"},
	{ 0, NULL}
};

static const value_string sm_backhaul_reason_code[] = {
	{ 0x00, "Layer management request"},
	{ 0x01, "SUERM (Signal Unit Error Monitor) failure"},
	{ 0x02, "Excessively long alignment period"},
	{ 0x03, "T7 timer expired"}, 
	{ 0x04, "Physical interface failure"},
	{ 0x05, "Two or three invalid BSNs"},
	{ 0x06, "Two or three invalid FIBs"},
	{ 0x07, "LSSU (Link Status Signal Unit) condition"},
	{ 0x13, "SIOs (Service Information Octets) received "
	        "in Link State Control (LSC)"},
	{ 0x14, "Timer T2 expired waiting for SIO"},
	{ 0x15, "Timer T3 expired waiting for SIE/SIN "},
	{ 0x16, "SIO received in initial alignment control (IAC)"},
	{ 0x17, "Proving period failure"},
	{ 0x18, "Timer T1 expired waiting for FISU (Fill-In Signal Unit)"},
	{ 0x19, "SIN received in the in-service state"},
	{ 0x20, "CTS lost"}, 
	{ 0x25, "No resources"},
	{    0, NULL}
};

static const value_string sm_backhaul_event_code[] = {
	{ 0x00, "Local processor outage"},
	{ 0x01, "Local processor outage recovered"},
	{ 0x02, "Entered a congested state"},
	{ 0x03, "Exited a congested state"},
	{ 0x04, "Physical layer up"},
	{ 0x05, "Physical layer down"},
	{ 0x06, "Protocol error"},
	{ 0x07, "Link is aligned"},
	{ 0x08, "Link alignment lost"},
	{ 0x09, "Retransmit buffer full"},
	{ 0x0a, "Retransmit buffer no longer full"},
	{ 0x0b, "Negative acknowledgment"},
	{ 0x0c, "Remote entered congestion"},
	{ 0x0d, "Remote exited congestion"},
	{ 0x0e, "Remote entered processor outage"},
	{ 0x0f, "Remote exited processor outage"},
	{    0, NULL}
};

static const value_string sm_backhaul_cause_code[] = {
	{ 0x00, "Unknown (default)"},
	{ 0x01, "Management initiated"},
	{ 0x02, "Abnormal BSN (backward sequence number)"},
	{ 0x03, "Abnormal FIB (Forward Indicator Bit)"},
	{ 0x04, "Congestion discard"},
	{    0, NULL}
};

static const value_string sm_linkdown_cause_code[] = {
	{ 0x00, "Unknown (default)"},
	{ 0x01, "Management initiated"},
	{ 0x03, "Congestion ended"},
	{    0, NULL}
};

static const value_string sm_retrieval_type[] = {
	{ 0x01, "Request for BSN"},
	{ 0x02, "Request for MSUs"},
	{ 0x03, "Request to drop MSUs"},
	{    0, NULL}
};

static const value_string sm_lsc_state_type[] = {
	{ 0x00, "Set LPO"},
	{ 0x01, "Clear LPO"},
	{ 0x02, "Set Emergency"},
	{ 0x03, "Clear Emergency"},
	{ 0x04, "Clear Buffers"},
	{ 0x05, "Clear Transmit Buffer"},
	{ 0x06, "Clear ReTransmission Buffer"},
	{ 0x07, "Clear Receive Buffer"},
	{ 0x08, "Continue"},
	{ 0x09, "Power On"},
	{ 0x0a, "Start"},
	{ 0x0b, "Stop"},
	{    0, NULL}
};

static const value_string sm_stat_request_type[] = {
	{ 0x00, "Reset"},
	{ 0x01, "Send & Reset"},
	{ 0x02, "Send"},
	{    0, NULL}
};

#define PDU_CONNECT_REQUEST             0x06
#define PDU_CONNECT_CONFIRM             0x07
#define PDU_DISCONNECT_CONFIRM          0x0b
#define PDU_DISCONNECT_INDICATION       0x0c
#define PDU_MTP3_TO_SLT			0x10
#define PDU_MTP3_FROM_SLT		0x11
#define PDU_RETRIEVAL_REQUEST           0x12
#define PDU_RETRIEVAL_CONFIRM           0x13
#define PDU_LSC_REQUEST                 0x20
#define PDU_LSC_CONFIRM                 0x21
#define PDU_LSC_INDICATION              0x22
#define PDU_STAT_REQUEST                0x44

static const value_string sm_pdu_type_value[] = {
	{ PDU_CONNECT_REQUEST,		"Connect Request"},
	{ PDU_CONNECT_CONFIRM,		"Connect Confirm"},
	{ 0x0a,                           "Disconnect Request"},
	{ PDU_DISCONNECT_CONFIRM,		"Disconnect Confirm"},
	{ PDU_DISCONNECT_INDICATION,	"Disconnect Indication Message"},
	{ PDU_MTP3_TO_SLT,		"MSU Request (message to MTP2 link)"},
	{ PDU_MTP3_FROM_SLT, 		"MSU Indication (message from MTP2 link)"},
	{ PDU_RETRIEVAL_REQUEST,          "Retrieval Request"},
	{ PDU_RETRIEVAL_CONFIRM,          "Retrieval Confirm"},
	{ 0x14,                           "Retrieval Indication"},
	{ 0x15,                           "Retrieval Message"},
	{ PDU_LSC_REQUEST,                "Link State Controller Request"},
	{ PDU_LSC_CONFIRM,                "Link State Controller Confirm"},
	{ PDU_LSC_INDICATION,             "Link State Controller Indication"},
	{ 0x40,                           "Configuration Request"},
	{ 0x41,                           "Configuration Confirm"},
	{ 0x42,                           "Status Request"},
	{ 0x43,                           "Status Confirm"},
	{ PDU_STAT_REQUEST,               "Statistic Request"},
	{ 0x45,                           "Statistic Confirm"},
	{ 0x46,                           "Control Request"},
	{ 0x47,                           "Control Confirm"},
	{ 0x50,                           "Flow Control Request"},
	{ 0x51,                           "Flow Control Indication"},
	{ 0,                    NULL }
};

/* TODO: Change to useful name once known */
#define SM_PROTOCOL_X004 0x0004 /* https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7188 */
/* RUDP/SM stack called BSM V1 (version 1 versus Version 0 used for SS7). */
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
static int hf_sm_alignment_type = -1;
static int hf_sm_backhaul_reason_code = -1;
static int hf_sm_backhaul_event_code = -1;
static int hf_sm_backhaul_cause_code = -1;
static int hf_sm_linkdown_cause_code = -1;
static int hf_sm_retrieval_type = -1;
static int hf_sm_lsc_state_type = -1;
static int hf_sm_stat_request_type = -1;
static int hf_sm_bsn_num = -1;

/* Initialize the subtree pointers */
static gint ett_sm = -1;

static dissector_handle_t sdp_handle;
static dissector_handle_t mtp3_handle;
static dissector_handle_t q931_handle;
static dissector_handle_t data_handle;

/* Code to actually dissect the packets */
static void
dissect_sm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *sm_tree;
	tvbuff_t *next_tvb = NULL;
	guint32 sm_message_type;
	guint32 bsn_num = 0;
	guint32 bh_event_code = 0;
	guint16 protocol;
	guint16 msg_type = 0;
	guint16 length;
	guint16 tag;
	int     offset = 0;

	sm_message_type = tvb_get_ntohl(tvb,offset);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SM");

	col_add_fstr(pinfo->cinfo, COL_INFO, "Cisco SM Packet (%s)",
		val_to_str_const(sm_message_type, sm_message_type_value_info,"reserved"));

	ti = proto_tree_add_item(tree, proto_sm, tvb, offset, 0, ENC_NA);
	sm_tree = proto_item_add_subtree(ti, ett_sm);

	proto_tree_add_uint_format(sm_tree, hf_sm_sm_msg_type, tvb, offset, 4, sm_message_type,
		"SM Message type: %s (0x%0x)", val_to_str_const(sm_message_type, sm_message_type_value, "reserved"), sm_message_type);

	offset = offset + 4;
	if (sm_message_type ==  MESSAGE_TYPE_PDU) {
		proto_tree_add_item(sm_tree, hf_sm_protocol, tvb, offset, 2, ENC_BIG_ENDIAN);
		protocol = tvb_get_ntohs(tvb,offset);
		offset = offset + 2;
		switch(protocol){
		/* start case RUDP BSM v.1  ---------------------------------------------------------- */
		case SM_PROTOCOL_X004:
			if (!tree)
				return;

			proto_tree_add_item(sm_tree, hf_sm_msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset = offset +2;
			msg_type = tvb_get_ntohs(tvb,offset);
			proto_tree_add_uint_format(sm_tree, hf_sm_msg_type, tvb, offset, 2, msg_type,
				"Message type: %s (0x%0x)", val_to_str_const(msg_type, sm_pdu_type_value, "reserved"),
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
					call_dissector(q931_handle, next_tvb, pinfo, tree);
				} else {
					call_dissector(data_handle, next_tvb, pinfo, tree);
				}
			}

			break;
			/* end case RUDP BSM v.1 ---------------------------------------------------------- */

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
			/* XXX Reverse enginered so this may not be correct!!!
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
			/* XXX Reverse enginered so this may not be correct!!! */
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
				"Message type: %s (0x%0x)", val_to_str_const(msg_type, sm_pdu_type_value, "reserved"),
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

				switch (msg_type) {
				case PDU_MTP3_TO_SLT:
				case PDU_MTP3_FROM_SLT:
					call_dissector(mtp3_handle, next_tvb, pinfo, tree);
					break;
				case PDU_CONNECT_REQUEST:
				case PDU_CONNECT_CONFIRM:
					proto_tree_add_item(sm_tree, hf_sm_alignment_type, tvb, offset, 4, ENC_BIG_ENDIAN);
					break;
				case PDU_DISCONNECT_CONFIRM:
				case PDU_DISCONNECT_INDICATION:
					proto_tree_add_item(sm_tree, hf_sm_backhaul_reason_code, tvb, offset, 4, ENC_BIG_ENDIAN);
					break;
				case PDU_RETRIEVAL_REQUEST:
				case PDU_RETRIEVAL_CONFIRM:
					proto_tree_add_item(sm_tree, hf_sm_retrieval_type, tvb, offset, 4, ENC_BIG_ENDIAN);
					if (msg_type == PDU_RETRIEVAL_CONFIRM && tvb_get_ntohl(tvb,offset) == 0x01) {
						offset += 4;
						bsn_num = tvb_get_ntohl(tvb,offset);
						proto_tree_add_uint_format(sm_tree, hf_sm_bsn_num, tvb, offset, 4,
												   bsn_num, "BSN: %d", bsn_num);
					}
					break;
				case PDU_LSC_REQUEST:
				case PDU_LSC_CONFIRM:
					proto_tree_add_item(sm_tree, hf_sm_lsc_state_type, tvb, offset, 4, ENC_BIG_ENDIAN);
					break;
				case PDU_LSC_INDICATION:
					proto_tree_add_item(sm_tree, hf_sm_backhaul_event_code, tvb, offset, 4, ENC_BIG_ENDIAN);
					bh_event_code = tvb_get_ntohl(tvb,offset);
					if (bh_event_code == 0x02 || bh_event_code == 0x04) {
						offset += 4;
						proto_tree_add_item(sm_tree, hf_sm_linkdown_cause_code, tvb, offset, 4, ENC_BIG_ENDIAN);
					} else if (bh_event_code == 0x06) {
						offset += 4;
						proto_tree_add_item(sm_tree, hf_sm_backhaul_cause_code, tvb, offset, 4, ENC_BIG_ENDIAN);
					}
					break;
				case PDU_STAT_REQUEST:
					proto_tree_add_item(sm_tree, hf_sm_stat_request_type, tvb, offset, 4, ENC_BIG_ENDIAN);
					break;
				default:
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
		{ &hf_sm_alignment_type,
		  { "Alignment type","sm.connect_type",
		    FT_UINT32, BASE_HEX, VALS(sm_alignment_type), 0x0,
		    NULL, HFILL }
		},
		{ &hf_sm_backhaul_reason_code,
		  { "Backhaul reason code","sm.backhaul_reason",
			FT_UINT32, BASE_HEX, VALS(sm_backhaul_reason_code), 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_backhaul_event_code,
		  { "Backhaul event code","sm.backhaul_event",
			FT_UINT32, BASE_HEX, VALS(sm_backhaul_event_code), 0x0,
						NULL, HFILL }
		},
		{ &hf_sm_backhaul_cause_code,
		  { "Backhaul cause code","sm.backhaul_cause",
			FT_UINT32, BASE_HEX, VALS(sm_backhaul_cause_code), 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_linkdown_cause_code,
		  { "Link down cause","sm.linkdown_reason",
			FT_UINT32, BASE_HEX, VALS(sm_linkdown_cause_code), 0x0,
			NULL, HFILL }
		},
		
		{ &hf_sm_retrieval_type,
		  { "Retrieval type","sm.retrieval_type",
			FT_UINT32, BASE_HEX, VALS(sm_retrieval_type), 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_lsc_state_type,
		  { "LSC Request type","sm.lsc_state_type",
			FT_UINT32, BASE_HEX, VALS(sm_lsc_state_type), 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_stat_request_type,
		  { "Statistic request type","sm.stat_request_type",
			FT_UINT32, BASE_HEX, VALS(sm_stat_request_type), 0x0,
			NULL, HFILL }
		},
		{ &hf_sm_bsn_num,
		  { "BSN Number","sm.bsn_num",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
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
	q931_handle = find_dissector("q931");
	data_handle = find_dissector("data");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
