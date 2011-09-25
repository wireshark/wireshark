/* packet-classicstun.c
 * Routines for Simple Traversal of UDP Through NAT dissection
 * Copyright 2003, Shiang-Ming Huang <smhuang@pcs.csie.nctu.edu.tw>
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
 *
 * Please refer to RFC 3489 for protocol detail.
 * (supports extra message attributes described in draft-ietf-behave-rfc3489bis-00)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>

/* Initialize the protocol and registered fields */
static int proto_classicstun = -1;

static int hf_classicstun_type = -1;		/* CLASSIC-STUN message header */
static int hf_classicstun_length = -1;
static int hf_classicstun_id = -1;
static int hf_classicstun_att = -1;
static int hf_classicstun_response_in = -1;
static int hf_classicstun_response_to = -1;
static int hf_classicstun_time = -1;


static int classicstun_att_type = -1;		/* CLASSIC-STUN attribute fields */
static int classicstun_att_length = -1;
static int classicstun_att_value = -1;
static int classicstun_att_family = -1;
static int classicstun_att_ipv4 = -1;
static int classicstun_att_ipv6 = -1;
static int classicstun_att_port = -1;
static int classicstun_att_change_ip = -1;
static int classicstun_att_change_port = -1;
static int classicstun_att_unknown = -1;
static int classicstun_att_error_class = -1;
static int classicstun_att_error_number = -1;
static int classicstun_att_error_reason = -1;
static int classicstun_att_server_string = -1;
static int classicstun_att_xor_ipv4 = -1;
static int classicstun_att_xor_ipv6 = -1;
static int classicstun_att_xor_port = -1;
static int classicstun_att_lifetime = -1;
static int classicstun_att_magic_cookie = -1;
static int classicstun_att_bandwidth = -1;
static int classicstun_att_data = -1;
static int classicstun_att_connection_request_binding = -1;

/* Structure containing transaction specific information */
typedef struct _classicstun_transaction_t {
	guint32 req_frame;
	guint32 rep_frame;
	nstime_t req_time;
} classicstun_transaction_t;

/* Structure containing conversation specific information */
typedef struct _classicstun_conv_info_t {
	emem_tree_t *pdus;
} classicstun_conv_info_t;


/* Message Types */
#define BINDING_REQUEST			0x0001
#define BINDING_RESPONSE		0x0101
#define BINDING_ERROR_RESPONSE		0x0111
#define SHARED_SECRET_REQUEST		0x0002
#define SHARED_SECRET_RESPONSE		0x0102
#define SHARED_SECRET_ERROR_RESPONSE	0x1112
#define ALLOCATE_REQUEST		0x0003
#define ALLOCATE_RESPONSE		0x0103
#define ALLOCATE_ERROR_RESPONSE		0x0113
#define SEND_REQUEST			0x0004
#define SEND_RESPONSE			0x0104
#define SEND_ERROR_RESPONSE		0x0114
#define DATA_INDICATION			0x0115
#define SET_ACTIVE_DESTINATION_REQUEST	0x0006
#define SET_ACTIVE_DESTINATION_RESPONSE	0x0106
#define SET_ACTIVE_DESTINATION_ERROR_RESPONSE	0x0116


/* Message classes */
#define CLASS_MASK	0xC110
#define REQUEST		0x0000
#define INDICATION	0x0001
#define RESPONSE	0x0010
#define ERROR_RESPONSE	0x0011

/* Attribute Types */
#define MAPPED_ADDRESS		0x0001
#define RESPONSE_ADDRESS	0x0002
#define CHANGE_REQUEST		0x0003
#define SOURCE_ADDRESS		0x0004
#define CHANGED_ADDRESS		0x0005
#define USERNAME		0x0006
#define PASSWORD		0x0007
#define MESSAGE_INTEGRITY	0x0008
#define ERROR_CODE		0x0009
#define UNKNOWN_ATTRIBUTES	0x000a
#define REFLECTED_FROM		0x000b
#define LIFETIME		0x000d
#define ALTERNATE_SERVER	0x000e
#define MAGIC_COOKIE		0x000f
#define BANDWIDTH		0x0010
#define DESTINATION_ADDRESS	0x0011
#define REMOTE_ADDRESS		0x0012
#define DATA			0x0013
#define NONCE			0x0014
#define REALM			0x0015
#define REQUESTED_ADDRESS_TYPE	0x0016
#define XOR_MAPPED_ADDRESS	0x8020
#define XOR_ONLY		0x0021
#define SERVER			0x8022
#define CONNECTION_REQUEST_BINDING      0xc001
#define BINDING_CHANGE                  0xc002



/* Initialize the subtree pointers */
static gint ett_classicstun = -1;
static gint ett_classicstun_att_type = -1;
static gint ett_classicstun_att = -1;


#define UDP_PORT_STUN 	3478
#define TCP_PORT_STUN	3478


#define CLASSICSTUN_HDR_LEN	((guint)20)	/* CLASSIC-STUN message header length */
#define ATTR_HDR_LEN	4	/* CLASSIC-STUN attribute header length */


static const value_string messages[] = {
	{BINDING_REQUEST, "Binding Request"},
	{BINDING_RESPONSE, "Binding Response"},
	{BINDING_ERROR_RESPONSE, "Binding Error Response"},
	{SHARED_SECRET_REQUEST, "Shared Secret Request"},
	{SHARED_SECRET_RESPONSE, "Shared Secret Response"},
	{SHARED_SECRET_ERROR_RESPONSE, "Shared Secret Error Response"},
	{ALLOCATE_REQUEST, "Allocate Request"},
	{ALLOCATE_RESPONSE, "Allocate Response"},
	{ALLOCATE_ERROR_RESPONSE, "Allocate Error Response"},
	{SEND_REQUEST, "Send Request"},
	{SEND_RESPONSE, "Send Response"},
	{SEND_ERROR_RESPONSE, "Send Error Response"},
	{DATA_INDICATION, "Data Indication"},
	{SET_ACTIVE_DESTINATION_REQUEST, "Set Active Destination Request"},
	{SET_ACTIVE_DESTINATION_RESPONSE, "Set Active Destination Response"},
	{SET_ACTIVE_DESTINATION_ERROR_RESPONSE, "Set Active Destination Error Response"},
	{0x00, NULL}
};

static const value_string attributes[] = {
	{MAPPED_ADDRESS, "MAPPED-ADDRESS"},
	{RESPONSE_ADDRESS, "RESPONSE-ADDRESS"},
	{CHANGE_REQUEST, "CHANGE-REQUEST"},
	{SOURCE_ADDRESS, "SOURCE-ADDRESS"},
	{CHANGED_ADDRESS, "CHANGED-ADDRESS"},
	{USERNAME, "USERNAME"},
	{PASSWORD, "PASSWORD"},
	{MESSAGE_INTEGRITY, "MESSAGE-INTEGRITY"},
	{ERROR_CODE, "ERROR-CODE"},
	{REFLECTED_FROM, "REFLECTED-FROM"},
	{LIFETIME, "LIFETIME"},
	{ALTERNATE_SERVER, "ALTERNATE_SERVER"},
	{MAGIC_COOKIE, "MAGIC_COOKIE"},
	{BANDWIDTH, "BANDWIDTH"},
	{DESTINATION_ADDRESS, "DESTINATION_ADDRESS"},
	{REMOTE_ADDRESS, "REMOTE_ADDRESS"},
	{DATA, "DATA"},
	{NONCE, "NONCE"},
	{REALM, "REALM"},
	{REQUESTED_ADDRESS_TYPE, "REQUESTED_ADDRESS_TYPE"},
	{XOR_MAPPED_ADDRESS, "XOR_MAPPED_ADDRESS"},
	{XOR_ONLY, "XOR_ONLY"},
	{SERVER, "SERVER"},
	{CONNECTION_REQUEST_BINDING, "CONNECTION-REQUEST-BINDING"},
	{BINDING_CHANGE, "BINDING-CHANGE"},
	{0x00, NULL}
};

static const value_string attributes_family[] = {
	{0x0001, "IPv4"},
	{0x0002, "IPv6"},
	{0x00, NULL}
};

static int
dissect_classicstun(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	proto_item *ti;
	proto_item *ta;
	proto_tree *classicstun_tree;
	proto_tree *att_type_tree;
	proto_tree *att_tree;
	guint16 msg_type;
	guint16 msg_length;
	const char *msg_type_str;
	guint16 att_type;
	guint16 att_length;
	guint16 offset;
	guint   len;
	guint i;
	conversation_t *conversation;
	classicstun_conv_info_t *classicstun_info;
	classicstun_transaction_t * classicstun_trans;
	emem_tree_key_t transaction_id_key[2];
	guint32 transaction_id[4];


	/*
	 * First check if the frame is really meant for us.
	 */
	len = tvb_length(tvb);
	/* First, make sure we have enough data to do the check. */
	if (len < CLASSICSTUN_HDR_LEN)
		return 0;

	msg_type = tvb_get_ntohs(tvb, 0);

	if (msg_type & 0xC000 || tvb_get_ntohl(tvb, 4) == 0x2112a442 /* New STUN */
	    || tvb_get_ntohl(tvb, 4) == 0x7f5a9bc7) /* XMCP */
		return 0;

	/* check if message type is correct */
	msg_type_str = match_strval(msg_type, messages);
	if (msg_type_str == NULL)
		return 0;

	msg_length = tvb_get_ntohs(tvb, 2);

	/* check if payload enough */
	if (len != CLASSICSTUN_HDR_LEN+msg_length)
		return 0;

	/* The message seems to be a valid CLASSIC-STUN message! */

	/* Create the transaction key which may be used
	   to track the conversation */
	transaction_id[0] = tvb_get_ntohl(tvb, 4);
	transaction_id[1] = tvb_get_ntohl(tvb, 8);
	transaction_id[2] = tvb_get_ntohl(tvb, 12);
	transaction_id[3] = tvb_get_ntohl(tvb, 16);

	transaction_id_key[0].length = 4;
	transaction_id_key[0].key =  transaction_id;
	transaction_id_key[1].length = 0;
	transaction_id_key[1].key =  NULL;

	/*
	 * Do we have a conversation for this connection?
	 */
	conversation = find_or_create_conversation(pinfo);

	/*
	 * Do we already have a state structure for this conv
	 */
	classicstun_info = conversation_get_proto_data(conversation, proto_classicstun);
	if (!classicstun_info) {
		/* No.  Attach that information to the conversation, and add
		 * it to the list of information structures.
		 */
		classicstun_info = se_alloc(sizeof(classicstun_conv_info_t));
		classicstun_info->pdus=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "classicstun_pdus");
		conversation_add_proto_data(conversation, proto_classicstun, classicstun_info);
	}

	if(!pinfo->fd->flags.visited){
		if (((msg_type & CLASS_MASK) >> 4) == REQUEST) {
			/* This is a request */
			classicstun_trans=se_alloc(sizeof(classicstun_transaction_t));
			classicstun_trans->req_frame=pinfo->fd->num;
			classicstun_trans->rep_frame=0;
			classicstun_trans->req_time=pinfo->fd->abs_ts;
			se_tree_insert32_array(classicstun_info->pdus, transaction_id_key,
					       (void *)classicstun_trans);
		} else {
			classicstun_trans=se_tree_lookup32_array(classicstun_info->pdus,
								 transaction_id_key);
			if(classicstun_trans){
				classicstun_trans->rep_frame=pinfo->fd->num;
			}
		}
	} else {
		classicstun_trans=se_tree_lookup32_array(classicstun_info->pdus, transaction_id_key);
	}
	if(!classicstun_trans){
		/* create a "fake" pana_trans structure */
		classicstun_trans=ep_alloc(sizeof(classicstun_transaction_t));
		classicstun_trans->req_frame=0;
		classicstun_trans->rep_frame=0;
		classicstun_trans->req_time=pinfo->fd->abs_ts;
	}



	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CLASSIC-STUN");

	col_add_fstr(pinfo->cinfo, COL_INFO, "Message: %s",
		     msg_type_str);

	if (tree) {
		guint transaction_id_first_word;

		ti = proto_tree_add_item(tree, proto_classicstun, tvb, 0, -1, FALSE);

		classicstun_tree = proto_item_add_subtree(ti, ett_classicstun);

		if (((msg_type & CLASS_MASK) >> 4) == REQUEST) {
			if (classicstun_trans->rep_frame) {
				proto_item *it;
				it=proto_tree_add_uint(classicstun_tree, hf_classicstun_response_in,
						       tvb, 0, 0,
						       classicstun_trans->rep_frame);
				PROTO_ITEM_SET_GENERATED(it);
			}
		}
		else if ((((msg_type & CLASS_MASK) >> 4) == RESPONSE) ||
			 (((msg_type & CLASS_MASK) >> 4) == ERROR_RESPONSE)) {
			/* This is a response */
			if(classicstun_trans->req_frame){
				proto_item *it;
				nstime_t ns;

				it=proto_tree_add_uint(classicstun_tree, hf_classicstun_response_to, tvb, 0, 0, classicstun_trans->req_frame);
				PROTO_ITEM_SET_GENERATED(it);

				nstime_delta(&ns, &pinfo->fd->abs_ts, &classicstun_trans->req_time);
				it=proto_tree_add_time(classicstun_tree, hf_classicstun_time, tvb, 0, 0, &ns);
				PROTO_ITEM_SET_GENERATED(it);
			}

		}

		proto_tree_add_uint(classicstun_tree, hf_classicstun_type, tvb, 0, 2, msg_type);
		proto_tree_add_uint(classicstun_tree, hf_classicstun_length, tvb, 2, 2, msg_length);
		proto_tree_add_item(classicstun_tree, hf_classicstun_id, tvb, 4, 16, FALSE);

		/* Remember this (in host order) so we can show clear xor'd addresses */
		transaction_id_first_word = tvb_get_ntohl(tvb, 4);

		if (msg_length > 0) {
			ta = proto_tree_add_item(classicstun_tree, hf_classicstun_att, tvb, CLASSICSTUN_HDR_LEN, msg_length, FALSE);
			att_type_tree = proto_item_add_subtree(ta, ett_classicstun_att_type);

			offset = CLASSICSTUN_HDR_LEN;

			while( msg_length > 0) {
				att_type = tvb_get_ntohs(tvb, offset); /* Type field in attribute header */
				att_length = tvb_get_ntohs(tvb, offset+2); /* Length field in attribute header */

				ta = proto_tree_add_text(att_type_tree, tvb, offset,
							 ATTR_HDR_LEN+att_length,
							 "Attribute: %s",
							 val_to_str(att_type, attributes, "Unknown (0x%04x)"));
				att_tree = proto_item_add_subtree(ta, ett_classicstun_att);

				proto_tree_add_uint(att_tree, classicstun_att_type, tvb,
						    offset, 2, att_type);
				offset += 2;
				if (ATTR_HDR_LEN+att_length > msg_length) {
					proto_tree_add_uint_format(att_tree,
								   classicstun_att_length, tvb, offset, 2,
								   att_length,
								   "Attribute Length: %u (bogus, goes past the end of the message)",
								   att_length);
					break;
				}
				proto_tree_add_uint(att_tree, classicstun_att_length, tvb,
						    offset, 2, att_length);
				offset += 2;
				switch( att_type ){
					case MAPPED_ADDRESS:
					case RESPONSE_ADDRESS:
					case SOURCE_ADDRESS:
					case CHANGED_ADDRESS:
					case REFLECTED_FROM:
					case ALTERNATE_SERVER:
					case DESTINATION_ADDRESS:
					case REMOTE_ADDRESS:
						if (att_length < 2)
							break;
						proto_tree_add_item(att_tree, classicstun_att_family, tvb, offset+1, 1, FALSE);
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, classicstun_att_port, tvb, offset+2, 2, FALSE);
						switch( tvb_get_guint8(tvb, offset+1) ){
							case 1:
								if (att_length < 8)
									break;
								proto_tree_add_item(att_tree, classicstun_att_ipv4, tvb, offset+4, 4, FALSE);
								break;

							case 2:
								if (att_length < 20)
									break;
								proto_tree_add_item(att_tree, classicstun_att_ipv6, tvb, offset+4, 16, FALSE);
								break;
						}
						break;

					case CHANGE_REQUEST:
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, classicstun_att_change_ip, tvb, offset, 4, FALSE);
						proto_tree_add_item(att_tree, classicstun_att_change_port, tvb, offset, 4, FALSE);
						break;

					case USERNAME:
					case PASSWORD:
					case MESSAGE_INTEGRITY:
					case NONCE:
					case REALM:
						if (att_length < 1)
							break;
						proto_tree_add_item(att_tree, classicstun_att_value, tvb, offset, att_length, FALSE);
						break;

					case ERROR_CODE:
						if (att_length < 3)
							break;
						proto_tree_add_item(att_tree, classicstun_att_error_class, tvb, offset+2, 1, FALSE);
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, classicstun_att_error_number, tvb, offset+3, 1, FALSE);
						if (att_length < 5)
							break;
						proto_tree_add_item(att_tree, classicstun_att_error_reason, tvb, offset+4, (att_length-4), FALSE);
						break;

					case LIFETIME:
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, classicstun_att_lifetime, tvb, offset, 4, FALSE);
						break;

					case MAGIC_COOKIE:
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, classicstun_att_magic_cookie, tvb, offset, 4, FALSE);
						break;

					case BANDWIDTH:
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, classicstun_att_bandwidth, tvb, offset, 4, FALSE);
						break;

					case DATA:
						proto_tree_add_item(att_tree, classicstun_att_data, tvb, offset, att_length, FALSE);
						break;

					case UNKNOWN_ATTRIBUTES:
						for (i = 0; i < att_length; i += 4) {
							proto_tree_add_item(att_tree, classicstun_att_unknown, tvb, offset+i, 2, FALSE);
							proto_tree_add_item(att_tree, classicstun_att_unknown, tvb, offset+i+2, 2, FALSE);
						}
						break;

					case SERVER:
						proto_tree_add_item(att_tree, classicstun_att_server_string, tvb, offset, att_length, FALSE);
						break;

					case XOR_MAPPED_ADDRESS:
						if (att_length < 2)
							break;
						proto_tree_add_item(att_tree, classicstun_att_family, tvb, offset+1, 1, FALSE);
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, classicstun_att_xor_port, tvb, offset+2, 2, FALSE);

						/* Show the port 'in the clear'
						   XOR (host order) transid with (host order) xor-port.
						   Add host-order port into tree. */
						ti = proto_tree_add_uint(att_tree, classicstun_att_port, tvb, offset+2, 2,
									 tvb_get_ntohs(tvb, offset+2) ^
									 (transaction_id_first_word >> 16));
						PROTO_ITEM_SET_GENERATED(ti);

						if (att_length < 8)
							break;
						switch( tvb_get_guint8(tvb, offset+1) ){
							case 1:
								if (att_length < 8)
									break;
								proto_tree_add_item(att_tree, classicstun_att_xor_ipv4, tvb, offset+4, 4, FALSE);

								/* Show the address 'in the clear'.
								   XOR (host order) transid with (host order) xor-address.
								   Add in network order tree. */
								ti = proto_tree_add_ipv4(att_tree, classicstun_att_ipv4, tvb, offset+4, 4,
											 g_htonl(tvb_get_ntohl(tvb, offset+4) ^
												 transaction_id_first_word));
								PROTO_ITEM_SET_GENERATED(ti);
								break;

							case 2:
								if (att_length < 20)
									break;
								proto_tree_add_item(att_tree, classicstun_att_xor_ipv6, tvb, offset+4, 16, FALSE);
								break;
						}
						break;

					case REQUESTED_ADDRESS_TYPE:
						if (att_length < 2)
							break;
						proto_tree_add_item(att_tree, classicstun_att_family, tvb, offset+1, 1, FALSE);
						break;

					case CONNECTION_REQUEST_BINDING:
						proto_tree_add_item(att_tree, classicstun_att_connection_request_binding, tvb, offset, att_length, FALSE);
						break;

					default:
						break;
				}
				offset += att_length;
				msg_length -= ATTR_HDR_LEN+att_length;
			}
		}
	}
	return tvb_length(tvb);
}


static gboolean
dissect_classicstun_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (dissect_classicstun(tvb, pinfo, tree) == 0)
		return FALSE;

	return TRUE;
}




void
proto_register_classicstun(void)
{
	static hf_register_info hf[] = {
		{ &hf_classicstun_type,
			{ "Message Type",	"classicstun.type", 	FT_UINT16,
			BASE_HEX, 	VALS(messages),	0x0, 	NULL, 	HFILL }
		},
		{ &hf_classicstun_length,
			{ "Message Length",	"classicstun.length",	FT_UINT16,
			BASE_HEX,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &hf_classicstun_id,
			{ "Message Transaction ID",	"classicstun.id",	FT_BYTES,
			BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &hf_classicstun_att,
			{ "Attributes",		"classicstun.att",	FT_NONE,
			BASE_NONE, 		NULL, 	0x0, 	NULL,	HFILL }
		},
		{ &hf_classicstun_response_in,
			{ "Response In", "classicstun.response_in",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"The response to this CLASSICSTUN query is in this frame", HFILL }},
		{ &hf_classicstun_response_to,
			{ "Request In", "classicstun.response_to",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This is a response to the CLASSICSTUN Request in this frame", HFILL }},
		{ &hf_classicstun_time,
			{ "Time", "classicstun.time",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
			"The time between the Request and the Response", HFILL }},

		/* ////////////////////////////////////// */
		{ &classicstun_att_type,
			{ "Attribute Type",	"classicstun.att.type",	FT_UINT16,
			BASE_HEX,	VALS(attributes),	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_length,
			{ "Attribute Length",	"classicstun.att.length",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_value,
			{ "Value",	"classicstun.att.value",	FT_BYTES,
			BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_family,
			{ "Protocol Family",	"classicstun.att.family",	FT_UINT16,
			BASE_HEX,	VALS(attributes_family),	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_ipv4,
			{ "IP",		"classicstun.att.ipv4",	FT_IPv4,
			BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_ipv6,
			{ "IP",		"classicstun.att.ipv6",	FT_IPv6,
			BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_port,
			{ "Port",	"classicstun.att.port",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_change_ip,
			{ "Change IP","classicstun.att.change.ip",	FT_BOOLEAN,
			16, 	TFS(&tfs_set_notset),	0x0004,	NULL,	HFILL}
		},
		{ &classicstun_att_change_port,
			{ "Change Port","classicstun.att.change.port",	FT_BOOLEAN,
			16, 	TFS(&tfs_set_notset),	0x0002,	NULL,	HFILL}
		},
		{ &classicstun_att_unknown,
			{ "Unknown Attribute","classicstun.att.unknown",	FT_UINT16,
			BASE_HEX, 	NULL,	0x0,	NULL,	HFILL}
		},
		{ &classicstun_att_error_class,
			{ "Error Class","classicstun.att.error.class",	FT_UINT8,
			BASE_DEC, 	NULL,	0x07,	NULL,	HFILL}
		},
		{ &classicstun_att_error_number,
			{ "Error Code","classicstun.att.error",	FT_UINT8,
			BASE_DEC, 	NULL,	0x0,	NULL,	HFILL}
		},
		{ &classicstun_att_error_reason,
			{ "Error Reason Phase","classicstun.att.error.reason",	FT_STRING,
			BASE_NONE, 	NULL,	0x0,	NULL,	HFILL}
		},
		{ &classicstun_att_xor_ipv4,
			{ "IP (XOR-d)",		"classicstun.att.ipv4-xord",	FT_IPv4,
			BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_xor_ipv6,
			{ "IP (XOR-d)",		"classicstun.att.ipv6-xord",	FT_IPv6,
			BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_xor_port,
			{ "Port (XOR-d)",	"classicstun.att.port-xord",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_server_string,
			{ "Server version","classicstun.att.server",	FT_STRING,
			BASE_NONE, 	NULL,	0x0,	NULL,	HFILL}
 		},
		{ &classicstun_att_lifetime,
			{ "Lifetime",	"classicstun.att.lifetime",	FT_UINT32,
			BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_magic_cookie,
			{ "Magic Cookie",	"classicstun.att.magic.cookie",	FT_UINT32,
			BASE_HEX,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_bandwidth,
			{ "Bandwidth",	"classicstun.att.bandwidth",	FT_UINT32,
			BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_data,
			{ "Data",	"classicstun.att.data",	FT_BYTES,
			BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &classicstun_att_connection_request_binding,
			{ "Connection Request Binding", "classicstun.att.connection_request_binding", FT_STRING,
			BASE_NONE,	NULL, 0x0,	NULL,	HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_classicstun,
		&ett_classicstun_att_type,
		&ett_classicstun_att,
	};

/* Register the protocol name and description */
	proto_classicstun = proto_register_protocol("Simple Traversal of UDP Through NAT",
						    "CLASSICSTUN", "classicstun");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_classicstun, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	new_register_dissector("classicstun", dissect_classicstun, proto_classicstun);
	new_register_dissector("classicstun-heur", dissect_classicstun_heur, proto_classicstun);
}


void
proto_reg_handoff_classicstun(void)
{
#if 0 /* The stun dissector registers on these ports */
	dissector_handle_t classicstun_handle;

	classicstun_handle = find_dissector("classicstun");

	dissector_add_uint("tcp.port", TCP_PORT_STUN, classicstun_handle);
	dissector_add_uint("udp.port", UDP_PORT_STUN, classicstun_handle);
#endif
	heur_dissector_add("udp", dissect_classicstun_heur, proto_classicstun);
	heur_dissector_add("tcp", dissect_classicstun_heur, proto_classicstun);
}
