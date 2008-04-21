/* packet-stun2.c
 * Routines for Session Traversal Utilities for NAT (STUN) dissection
 * Copyright 2003, Shiang-Ming Huang <smhuang@pcs.csie.nctu.edu.tw>
 * Copyright 2006, Marc Petit-Huguenin <marc@petit-huguenin.org>
 * Copyright 2007, 8x8 Inc. <petithug@8x8.com>
 * Copyright 2008, Gael Breard <gael@breard.org>
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
 * Please refer to draft-ietf-behave-rfc3489bis-15
 * and draft-ietf-behave-turn-07 for protocol detail.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <packet-tcp.h>
#include <packet-udp.h>

/* Initialize the protocol and registered fields */
static int proto_stun2 = -1;

static int hf_stun2_channel = -1;

static int hf_stun2_class = -1;
static int hf_stun2_method = -1;
static int hf_stun2_length = -1;
static int hf_stun2_cookie = -1;
static int hf_stun2_id = -1;
static int hf_stun2_att = -1;

static int stun2_att_type = -1;		/* STUN2 attribute fields */
static int stun2_att_length = -1;
static int stun2_att_family = -1;
static int stun2_att_ipv4 = -1;
static int stun2_att_ipv6 = -1;
static int stun2_att_port = -1;
static int stun2_att_username = -1;
static int stun2_att_padding = -1;
static int stun2_att_hmac = -1;
static int stun2_att_crc32 = -1;
static int stun2_att_error_class = -1;
static int stun2_att_error_number = -1;
static int stun2_att_error_reason = -1;
static int stun2_att_realm = -1;
static int stun2_att_nonce = -1;
static int stun2_att_unknown = -1;
static int stun2_att_xor_ipv4 = -1;
static int stun2_att_xor_ipv6 = -1;
static int stun2_att_xor_port = -1;
static int stun2_att_server = -1;
static int stun2_att_value = -1;
static int stun2_att_channelnum = -1;

static int stun2_att_transp = -1;
static int stun2_att_bandwidth = -1;
static int stun2_att_lifetime = -1;

static int stun2_att_reserved = -1;

/* Message classes */
#define CLASS_MASK	0xC110
#define REQUEST		0x0000
#define INDICATION	0x0001
#define RESPONSE	0x0010
#define ERROR_RESPONSE	0x0011

/* Request/Response Transactions */
#define METHOD_MASK		0xCEEF
#define BINDING			0x0001  /* draft-ietf-behave-rfc3489bis-07 */
#define ALLOCATE		0x0003  /*draft-ietf-behave-turn-07*/
#define REFRESH			0x0004  /*draft-ietf-behave-turn-07*/
#define CHANNELBIND		0x0009  /*draft-ietf-behave-turn-07*/
/* Indications */
#define SEND			0x0006  /*draft-ietf-behave-turn-07*/
#define DATA_IND		0x0007  /*draft-ietf-behave-turn-07*/


/* Attribute Types */
/* Comprehension-required range (0x0000-0x7FFF) */
#define MAPPED_ADDRESS				0x0001 /* rfc3489bis-15 */
#define RESPONSE_ADDRESS			0x0002 /* HISTORIC */
#define CHANGE_REQUEST				0x0003 /* nat-behavior-discovery-03 */
#define SOURCE_ADDRESS				0x0004 /* HISTORIC */
#define CHANGED_ADDRESS				0x0005 /* HISTORIC */
#define USERNAME					0x0006 /* rfc3489bis-15 */
#define PASSWORD					0x0007 /* HISTORIC - RESERVED */
#define MESSAGE_INTEGRITY			0x0008 /* rfc3489bis-15 */
#define ERROR_CODE					0x0009 /* rfc3489bis-15 */
#define UNKNOWN_ATTRIBUTES			0x000A /* rfc3489bis-15 */
#define REFLECTED_FROM				0x000B /* HISTORIC */
#define CHANNEL_NUMBER				0x000C /* turn-07 */
#define LIFETIME					0x000D /* turn-07 */
#define BANDWIDTH					0x0010 /* turn-07 */
#define PEER_ADDRESS				0x0012 /* turn-07 */
#define DATA						0x0013 /* turn-07 */
#define REALM						0x0014 /* rfc3489bis-15 */
#define NONCE						0x0015 /* rfc3489bis-15 */
#define RELAY_ADDRESS				0x0016 /* turn-07 */
#define REQUESTED_ADDRESS_TYPE		0x0017 /* turn-ipv6-04 */
#define REQUESTED_PROPS				0x0018 /* turn-07 */
#define REQUESTED_TRANSPORT			0x0019 /* turn-07 */
#define XOR_MAPPED_ADDRESS			0x0020 /* rfc3489bis-15 */
#define RESERVATION_TOKEN			0x0022 /* turn-07 */
#define PADDING						0x0026 /* nat-behavior-discovery-03 */
#define XOR_RESPONSE_TARGET			0x0027 /* nat-behavior-discovery-03 */
#define XOR_REFLECTED_FROM			0x0028 /* nat-behavior-discovery-03 */

/* Comprehension-optional range (0x8000-0xFFFF) */
#define SERVER						0x8022 /* rfc3489bis-15 */
#define ALTERNATE_SERVER			0x8023 /* rfc3489bis-15 */
#define CACHE_TIMEOUT				0x8027 /* nat-behavior-discovery-03 */
#define FINGERPRINT					0x8028 /* rfc3489bis-15 */
#define RESPONSE_ORIGIN				0x802b /* nat-behavior-discovery-03 */
#define OTHER_ADDRESS				0x802c /* nat-behavior-discovery-03 */

/* divers */
#define PROTO_NUM_UDP	17
#define PROTO_NUM_TCP	6
#define PROTO_NUM_ERR	255

#define TURN_REQUESTED_PROPS_EVEN_PORT		0x01
#define TURN_REQUESTED_PROPS_PAIR_OF_PORTS	0x02

#define TURN_CHANNEL_NUMBER_MIN				0x4000
#define TURN_CHANNEL_NUMBER_MAX				0xFFFE






/* Initialize the subtree pointers */
static gint ett_stun2 = -1;
static gint ett_stun2_att_type = -1;
static gint ett_stun2_att = -1;

#define UDP_PORT_STUN2 	3478
#define TCP_PORT_STUN2	3478

#define STUN2_HDR_LEN				((guint)20)	/* STUN2 message header length */
#define ATTR_HDR_LEN				4			/* STUN2 attribute header length */
#define CHANNEL_DATA_HDR_LEN		4			/* TURN CHANNEL-DATA Message hdr length */
#define MIN_HDR_LEN					4

static const value_string transportnames[] = {
	{ 17, "UDP" },
	{ 6, "TCP" },
	{ 0, NULL }
};

static const value_string classes[] = {
	{REQUEST, "Request"},
	{INDICATION, "Indication"},
	{RESPONSE, "Success Response"},
	{ERROR_RESPONSE, "Error Response"},
	{0x00, NULL}
};

static const value_string methods[] = {
	{BINDING, "Binding"},
	{ALLOCATE, "Allocate"},
	{REFRESH, "Refresh"},
	{CHANNELBIND, "Channel-Bind"},
	{SEND, "Send"},
	{DATA_IND, "Data"},
	{0x00, NULL}
};



static const value_string attributes[] = {
	{MAPPED_ADDRESS, "MAPPED-ADDRESS"},
	{USERNAME, "USERNAME"},
	{MESSAGE_INTEGRITY, "MESSAGE-INTEGRITY"},
	{ERROR_CODE, "ERROR-CODE"},
	{UNKNOWN_ATTRIBUTES, "UNKNOWN-ATTRIBUTES"},
	{REALM, "REALM"},
	{NONCE, "NONCE"},
	{XOR_MAPPED_ADDRESS, "XOR-MAPPED-ADDRESS"},
	{SERVER, "SERVER"},
	{ALTERNATE_SERVER, "ALTERNATE-SERVER"},
	{FINGERPRINT, "FINGERPRINT"},
	{PEER_ADDRESS, "PEER-ADDRESS"},
	{RELAY_ADDRESS, "RELAY-ADDRESS"},
	{DATA, "DATA"},
	{REQUESTED_TRANSPORT, "REQUESTED-TRANSPORT"},
	{BANDWIDTH, "BANDWIDTH"},
	{LIFETIME, "LIFETIME"},
	{CHANNEL_NUMBER, "CHANNEL-NUMBER"},
	{0x00, NULL}
};

static const value_string error_code[] = {
	{300, "Try Alternate"},/* rfc3489bis-15 */
	{400, "Bad Request"},/* rfc3489bis-15 */
	{401, "Unauthorized"},/* rfc3489bis-15 */
	{420, "Unknown Attribute"},/* rfc3489bis-15 */
	{437, "Allocation Mismatch"},/* turn-07 */
	{438, "Stale Nonce"},/* rfc3489bis-15 */
	{439, "Wrong Credentials"}, /* turn-07 - collision 38=>39 */
	{442, "Unsupported Transport Protocol"},/* turn-07 */
	{440, "Address Family not Supported"}, /* turn-ipv6-04 */
	{481, "Connection does not exist"}, /* nat-behavior-discovery-03 */
	{486, "Allocation Quota Reached"},/* turn-07 */
	{500, "Server Error"},/* rfc3489bis-15 */
	{503, "Service Unavailable"}, /* nat-behavior-discovery-03 */
	{507, "Insufficient Bandwidth Capacity"},/* turn-07 */
	{508, "Insufficient Port Capacity"},/* turn-07 */
	{600, "Global Failure"},
	{0x00, NULL}
};


static const value_string attributes_family[] = {
	{0x0001, "IPv4"},
	{0x0002, "IPv6"},
	{0x00, NULL}
};

static guint
get_stun2_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint16 type = tvb_get_ntohs(tvb, offset);
	guint16 length = tvb_get_ntohs(tvb, offset+2);
	guint res = 0;

	if (type & 0xC000)
	{
		/* two first bits not NULL => should be a channel-data message */
		res = (guint) ((length + CHANNEL_DATA_HDR_LEN +3) & -4);
	}
	else
	{
		/* Normal STUN message */
		res = (guint) length + STUN2_HDR_LEN;
	}
	return res;
}

static int
dissect_stun2_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_item *ta;
	proto_tree *stun2_tree;
	proto_tree *att_type_tree;
	proto_tree *att_tree;
	guint16 msg_type;
	guint16 msg_length;
	const char *msg_class_str;
	const char *msg_method_str;
	guint16 att_type;
	guint16 att_length;
	guint16 offset;
	guint i;
	guint transaction_id_first_word;
	guint len;
	guint msg_total_len;

	/*
	 * First check if the frame is really meant for us.
	 */

	offset = 0;
	len = tvb_length(tvb);



	/* First, make sure we have enough data to do the check. */
	if (len < MIN_HDR_LEN)
		return FALSE;

	msg_type = tvb_get_ntohs(tvb, 0);
	msg_length = tvb_get_ntohs(tvb, 2);


	if (msg_type & 0xC000)
	{
		/* two first bits not NULL => should be a channel-data message */
		if (msg_type == 0xFFFF)
			return FALSE;
		msg_total_len = (guint) ((msg_length + CHANNEL_DATA_HDR_LEN +3) & -4) ;
	}
	else 
	{
		/* Normal STUN message */
		msg_total_len = (guint) msg_length + STUN2_HDR_LEN;
		if (len < STUN2_HDR_LEN)
			return FALSE;
		/* Check if it is really a STUN2 message */
		if ( tvb_get_ntohl(tvb, 4) != 0x2112a442)
			return FALSE;
	}

	/* check if payload enough */
	if (len != msg_total_len)
		return FALSE;


	/* The message seems to be a valid STUN2 message! */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "STUN2");

	/* BEGIN of CHANNEL-DATA specific section */
	if (msg_type & 0xC000)
	{
		/* two first bits not NULL => should be a channel-data message*/

		/* Clear out stuff in the info column */
		if (check_col(pinfo->cinfo,COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "ChannelData TURN Message");
		}
		if (!tree) return TRUE;
		ti = proto_tree_add_item(
			tree, proto_stun2, tvb, 0, 
			CHANNEL_DATA_HDR_LEN, 
			FALSE);
		proto_item_append_text(ti, ", TURN ChannelData Message");
		stun2_tree = proto_item_add_subtree(ti, ett_stun2);
		proto_tree_add_item(stun2_tree, hf_stun2_channel, tvb, offset, 2, FALSE); offset += 2;
		proto_tree_add_item(stun2_tree, hf_stun2_length,  tvb, offset, 2, FALSE); offset += 2;

		decode_udp_ports(tvb, offset, pinfo, tree, 0, 0, (int) offset + msg_length);
		/* TODO ports : get src and dst ports from context */
		return TRUE;
	}
	/* END of CHANNEL-DATA specific section */

	msg_class_str = match_strval((msg_type & CLASS_MASK) >> 4, classes);
	msg_method_str = match_strval(msg_type & METHOD_MASK, methods);
	if (msg_method_str == NULL)
		msg_method_str = "Unknown";

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			msg_method_str, msg_class_str);

	if (!tree)
		return TRUE;

	ti = proto_tree_add_item(tree, proto_stun2, tvb, 0, -1, FALSE);

	stun2_tree = proto_item_add_subtree(ti, ett_stun2);

	proto_tree_add_uint(stun2_tree, hf_stun2_class, tvb, 0, 2, msg_type);
	proto_tree_add_uint(stun2_tree, hf_stun2_method, tvb, 0, 2, msg_type);
	proto_tree_add_uint(stun2_tree, hf_stun2_length, tvb, 2, 2, msg_length);
	proto_tree_add_item(stun2_tree, hf_stun2_cookie, tvb, 4, 4, FALSE);
	proto_tree_add_item(stun2_tree, hf_stun2_id, tvb, 8, 12, FALSE);

	/* Remember this (in host order) so we can show clear xor'd addresses */
	/* TODO IPv6 support */
	transaction_id_first_word = tvb_get_ntohl(tvb, 4);

	if (msg_length > 0) {
		ta = proto_tree_add_item(stun2_tree, hf_stun2_att, tvb, STUN2_HDR_LEN, msg_length, FALSE);
		att_type_tree = proto_item_add_subtree(ta, ett_stun2_att_type);

		offset = STUN2_HDR_LEN;

		while (msg_length > 0) {
			att_type = tvb_get_ntohs(tvb, offset); /* Type field in attribute header */
			att_length = tvb_get_ntohs(tvb, offset+2); /* Length field in attribute header */

			ta = proto_tree_add_text(att_type_tree, tvb, offset,
				ATTR_HDR_LEN+att_length,
				"Attribute: %s",
				val_to_str(att_type, attributes, att_type & 0x8000 ?
					"Unknown (0x%4x) - Comprehension-optional" :
					"Unknown (0x%04x)- Comprehension-required"));
			att_tree = proto_item_add_subtree(ta, ett_stun2_att);

			proto_tree_add_uint(att_tree, stun2_att_type, tvb,
				offset, 2, att_type);
			offset += 2;
			if (ATTR_HDR_LEN+att_length > msg_length) {
				proto_tree_add_uint_format(att_tree,
					stun2_att_length, tvb, offset, 2,
					att_length,
					"Attribute Length: %u (bogus, goes past the end of the message)",
					att_length);
				break;
			}
			proto_tree_add_uint(att_tree, stun2_att_length, tvb,
				offset, 2, att_length);
			offset += 2;
			switch (att_type) {
			case MAPPED_ADDRESS:
			case ALTERNATE_SERVER:
				if (att_length < 2)
					break;
				proto_tree_add_item(att_tree, stun2_att_family, tvb, offset+1, 1, FALSE);
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun2_att_port, tvb, offset+2, 2, FALSE);
				switch (tvb_get_guint8(tvb, offset+1)) {
				case 1:
					if (att_length < 8)
						break;
					proto_tree_add_item(att_tree, stun2_att_ipv4, tvb, offset+4, 4, FALSE);
					{
						gchar *ipstr;
						guint32 ip;
						ip = tvb_get_ipv4(tvb,offset+4);
						ipstr = ip_to_str((guint8*)&ip);
						proto_item_append_text(att_tree, ": %s:%d", ipstr,tvb_get_ntohs(tvb,offset+2));
						if (check_col(pinfo->cinfo, COL_INFO)) {
							col_append_fstr(
								pinfo->cinfo, COL_INFO,
								" %s: %s:%d",
								val_to_str(att_type, attributes, "Unknown"),
								ipstr,
								tvb_get_ntohs(tvb,offset+2)
								);
						}
					}
					break;

				case 2:
					if (att_length < 20)
						break;
					proto_tree_add_item(att_tree, stun2_att_ipv6, tvb, offset+4, 16, FALSE);
					break;
				}
				break;

			case USERNAME:
				proto_tree_add_item(att_tree, stun2_att_username, tvb, offset, att_length, FALSE);
				proto_item_append_text(att_tree, ": %s", tvb_get_ephemeral_string(tvb, offset, att_length));
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" user: %s",
						tvb_get_ephemeral_string(tvb,offset, att_length)
						);
				}
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case MESSAGE_INTEGRITY:
				if (att_length < 20)
					break;
				proto_tree_add_item(att_tree, stun2_att_hmac, tvb, offset, att_length, FALSE);
				break;

			case ERROR_CODE:
				if (att_length < 3)
					break;
				proto_tree_add_item(att_tree, stun2_att_error_class, tvb, offset+2, 1, FALSE);
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun2_att_error_number, tvb, offset+3, 1, FALSE);
				{
					int human_error_num = tvb_get_guint8(tvb, offset+2) * 100 + tvb_get_guint8(tvb, offset+3);
					proto_item_append_text(
						att_tree,
						" %d (%s)",
						human_error_num, /* human readable error code */
						val_to_str(human_error_num, error_code, "*Unknown error code*")
						);
					if (check_col(pinfo->cinfo, COL_INFO)) {
						col_append_fstr(
							pinfo->cinfo, COL_INFO,
							" error-code: %d (%s)",
							human_error_num,
							val_to_str(human_error_num, error_code, "*Unknown error code*")
							);
					}
				}
				if (att_length < 5)
					break;
				proto_tree_add_item(att_tree, stun2_att_error_reason, tvb, offset+4, att_length-4, FALSE);

				proto_item_append_text(att_tree, ": %s", tvb_get_ephemeral_string(tvb, offset+4, att_length-4));
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" %s",
						tvb_get_ephemeral_string(tvb, offset+4, att_length-4)
						);
				}

				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case UNKNOWN_ATTRIBUTES:
				for (i = 0; i < att_length; i += 2)
					proto_tree_add_item(att_tree, stun2_att_unknown, tvb, offset+i, 2, FALSE);
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case REALM:
				proto_tree_add_item(att_tree, stun2_att_realm, tvb, offset, att_length, FALSE);
				proto_item_append_text(att_tree, ": %s", tvb_get_ephemeral_string(tvb, offset, att_length));
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" realm: %s",
						tvb_get_ephemeral_string(tvb,offset, att_length)
						);
				}
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case NONCE:
				proto_tree_add_item(att_tree, stun2_att_nonce, tvb, offset, att_length, FALSE);
				proto_item_append_text(att_tree, ": %s", tvb_get_ephemeral_string(tvb, offset, att_length));
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" with nonce"
						);
				}
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case XOR_MAPPED_ADDRESS:
			case PEER_ADDRESS:
			case RELAY_ADDRESS:
				if (att_length < 2)
					break;
				proto_tree_add_item(att_tree, stun2_att_family, tvb, offset+1, 1, FALSE);
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun2_att_xor_port, tvb, offset+2, 2, FALSE);

				/* Show the port 'in the clear'
				XOR (host order) transid with (host order) xor-port.
				Add host-order port into tree. */
				ti = proto_tree_add_uint(att_tree, stun2_att_port, tvb, offset+2, 2,
					tvb_get_ntohs(tvb, offset+2) ^
					(transaction_id_first_word >> 16));
				PROTO_ITEM_SET_GENERATED(ti);

				if (att_length < 8)
					break;
				switch (tvb_get_guint8(tvb, offset+1)) {
					case 1:
					if (att_length < 8)
						break;
					proto_tree_add_item(att_tree, stun2_att_xor_ipv4, tvb, offset+4, 4, FALSE);

					/* Show the address 'in the clear'.
					XOR (host order) transid with (host order) xor-address.
					Add in network order tree. */
					ti = proto_tree_add_ipv4(att_tree, stun2_att_ipv4, tvb, offset+4, 4,
						g_htonl(tvb_get_ntohl(tvb, offset+4) ^
						transaction_id_first_word));
					PROTO_ITEM_SET_GENERATED(ti);

					{
						gchar *ipstr;
						guint32 ip;
						guint16 port;
						ip = g_htonl(tvb_get_ntohl(tvb, offset+4) ^ transaction_id_first_word);
						ipstr = ip_to_str((guint8*)&ip);
						port = tvb_get_ntohs(tvb, offset+2) ^ (transaction_id_first_word >> 16);
						proto_item_append_text(att_tree, ": %s:%d", ipstr, port);
						if (check_col(pinfo->cinfo, COL_INFO)) {
							col_append_fstr(
								pinfo->cinfo, COL_INFO,
								" %s: %s:%d",
								val_to_str(att_type, attributes, "Unknown"),
								ipstr,
								port
								);
						}
					}
					break;

				case 2:
					if (att_length < 20)
						break;
					/* TODO add IPv6 */
					proto_tree_add_item(att_tree, stun2_att_xor_ipv6, tvb, offset+4, 16, FALSE);
					break;
				}
				break;

			case SERVER:
				proto_tree_add_item(att_tree, stun2_att_server, tvb, offset, att_length, FALSE);
				proto_item_append_text(att_tree, ": %s", tvb_get_ephemeral_string(tvb, offset, att_length));
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" server: %s",
						tvb_get_ephemeral_string(tvb,offset, att_length)
						);
				}
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case FINGERPRINT:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun2_att_crc32, tvb, offset, att_length, FALSE);
				break;

			case DATA:
				if (att_length > 0) {
					proto_tree_add_item(att_tree, stun2_att_value, tvb, offset, att_length, FALSE);
					if (att_length % 4 != 0) {
						proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
					}
					decode_udp_ports(tvb, offset, pinfo, tree, 0, 0, (int) offset + att_length);
					/* TODO ports */
				}
				break;

			case REQUESTED_TRANSPORT:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun2_att_transp, tvb, offset, 1, FALSE);
				{
					guint8  protoCode = tvb_get_guint8(tvb, offset);
					proto_item_append_text(att_tree, ": %s", val_to_str(protoCode, transportnames, "Unknown (0x%8x)"));
					if (check_col(pinfo->cinfo, COL_INFO)) {
						col_append_fstr(
							pinfo->cinfo, COL_INFO,
							" %s",
							val_to_str(protoCode, transportnames, "Unknown (0x%8x)")
							);
					}
				}
				proto_tree_add_uint(att_tree, stun2_att_reserved, tvb, offset+1, 3, 3);
				break;

			case CHANNEL_NUMBER:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun2_att_channelnum, tvb, offset, 2, FALSE);
				{
					guint16 chan = tvb_get_ntohs(tvb, offset);
					proto_item_append_text(att_tree, ": 0x%x", chan);
					if (check_col(pinfo->cinfo, COL_INFO)) {
						col_append_fstr(
							pinfo->cinfo, COL_INFO,
							" ChannelNumber=0x%x",
							chan
							);
					}
				}
				proto_tree_add_uint(att_tree, stun2_att_reserved, tvb, offset+2, 2, 2);
				break;

			case BANDWIDTH:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun2_att_bandwidth, tvb, offset, 4, FALSE);
				proto_item_append_text(att_tree, " %d", tvb_get_ntohl(tvb, offset));
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" bandwidth: %d",
						tvb_get_ntohl(tvb, offset)
						);
				}
				break;
			case LIFETIME:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun2_att_lifetime, tvb, offset, 4, FALSE);
				proto_item_append_text(att_tree, " %d", tvb_get_ntohl(tvb, offset));
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" lifetime: %d",
						tvb_get_ntohl(tvb, offset)
						);
				}
				break;

			default:
				if (att_length > 0)
					proto_tree_add_item(att_tree, stun2_att_value, tvb, offset, att_length, FALSE);
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;
			}
			offset += (att_length+3) & -4;
			msg_length -= (ATTR_HDR_LEN+att_length+3) & -4;
		}
	}

	return TRUE;
}

static int
dissect_stun2_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_stun2_message(tvb, pinfo, tree);
}

static void
dissect_stun2_message_no_return(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_stun2_message(tvb, pinfo, tree);
}

static void
dissect_stun2_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MIN_HDR_LEN,
		get_stun2_message_len, dissect_stun2_message_no_return);
}

static gboolean
dissect_stun2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint16 msg_type;
	guint16 msg_length;
	guint msg_total_len;
	guint len;

	/* First, make sure we have enough data to do the check. */
	len = tvb_length(tvb);
	if (len < MIN_HDR_LEN)
		return FALSE;

	msg_type = tvb_get_ntohs(tvb, 0);
	msg_length = tvb_get_ntohs(tvb, 2);

	if (msg_type & 0xC000)
	{
		/* two first bits not NULL => should be a channel-data message */
		if (msg_type == 0xFFFF)
			return FALSE;
		msg_total_len = (guint) ((msg_length + CHANNEL_DATA_HDR_LEN +3) & -4);
	}
	else
	{
		/* Normal STUN message */
		msg_total_len = (guint) msg_length + STUN2_HDR_LEN;
		if (len < STUN2_HDR_LEN)
			return FALSE;
		/* Check if it is really a STUN2 message */
		if (tvb_get_ntohl(tvb, 4) != 0x2112a442)
			return FALSE;
	}

	/* check if payload enough */
	if (len != msg_total_len)
		return FALSE;

	dissect_stun2_message(tvb, pinfo, tree);
	return TRUE;
}

void
proto_register_stun2(void)
{
	static hf_register_info hf[] = {

		{ &hf_stun2_channel,
		{ "Channel Number",	"stun2.channel",	FT_UINT16,
		BASE_HEX, 	NULL, 	0x0, 	"",	HFILL }
		},

		/* ////////////////////////////////////// */
		{ &hf_stun2_class,
		{ "Message Class",	"stun2.class", 	FT_UINT16,
		BASE_HEX, 	VALS(classes),	0x0110, 	"", 	HFILL }
		},
		{ &hf_stun2_method,
		{ "Message Method",	"stun2.method", 	FT_UINT16,
		BASE_HEX, 	VALS(methods),	0x3EEF, 	"", 	HFILL }
		},
		{ &hf_stun2_length,
		{ "Message Length",	"stun2.length",	FT_UINT16,
		BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &hf_stun2_cookie,
		{ "Message Cookie",	"stun2.cookie",	FT_BYTES,
		BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &hf_stun2_id,
		{ "Message Transaction ID",	"stun2.id",	FT_BYTES,
		BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &hf_stun2_att,
		{ "Attributes",		"stun2.att",	FT_NONE,
		BASE_NONE,	NULL, 	0x0, 	"",	HFILL }
		},
		/* ////////////////////////////////////// */
		{ &stun2_att_type,
		{ "Attribute Type",	"stun2.att.type",	FT_UINT16,
		BASE_HEX,	VALS(attributes),	0x0, 	"",	HFILL }
		},
		{ &stun2_att_length,
		{ "Attribute Length",	"stun2.att.length",	FT_UINT16,
		BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_family,
		{ "Protocol Family",	"stun2.att.family",	FT_UINT16,
		BASE_HEX,	VALS(attributes_family),	0x0, 	"",	HFILL }
		},
		{ &stun2_att_ipv4,
		{ "IP",		"stun2.att.ipv4",	FT_IPv4,
		BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_ipv6,
		{ "IP",		"stun2.att.ipv6",	FT_IPv6,
		BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_port,
		{ "Port",	"stun2.att.port",	FT_UINT16,
		BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_username,
		{ "Username",	"stun2.att.username",	FT_STRING,
		BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_padding,
		{ "Padding",	"stun2.att.padding",	FT_UINT16,
		BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_hmac,
		{ "HMAC-SHA1",	"stun2.att.hmac",	FT_BYTES,
		BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_crc32,
		{ "CRC-32",	"stun2.att.crc32",	FT_UINT32,
		BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_error_class,
		{ "Error Class","stun2.att.error.class",	FT_UINT8,
		BASE_DEC, 	NULL,	0x07,	"",	HFILL}
		},
		{ &stun2_att_error_number,
		{ "Error Code","stun2.att.error",	FT_UINT8,
		BASE_DEC, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun2_att_error_reason,
		{ "Error Reason Phrase","stun2.att.error.reason",	FT_STRING,
		BASE_NONE, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun2_att_realm,
		{ "Realm",	"stun2.att.realm",	FT_STRING,
		BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_nonce,
		{ "Nonce",	"stun2.att.nonce",	FT_STRING,
		BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_unknown,
		{ "Unknown Attribute","stun2.att.unknown",	FT_UINT16,
		BASE_HEX, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun2_att_xor_ipv4,
		{ "IP (XOR-d)",		"stun2.att.ipv4-xord",	FT_IPv4,
		BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_xor_ipv6,
		{ "IP (XOR-d)",		"stun2.att.ipv6-xord",	FT_IPv6,
		BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_xor_port,
		{ "Port (XOR-d)",	"stun2.att.port-xord",	FT_UINT16,
		BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_server,
		{ "Server software","stun2.att.server",	FT_STRING,
		BASE_NONE, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun2_att_value,
		{ "Value",	"stun2.value",	FT_BYTES,
		BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_reserved,
		{ "Reserved",	"stun2.att.reserved",	FT_UINT16,
		BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_transp,
		{ "Transport",	"stun2.att.transp",	FT_UINT8,
		BASE_HEX,	VALS(transportnames),	0x0, 	"",	HFILL }
		},
		{ &stun2_att_channelnum,
		{ "Channel-Number",	"stun2.att.channelnum",	FT_UINT16,
		BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_bandwidth,
		{ "Bandwidth",	"stun2.port.bandwidth", 	FT_UINT32,
		BASE_DEC, 	NULL,	0x0, 	"", HFILL }
		},
		{ &stun2_att_lifetime,
		{ "Lifetime",	"stun2.port.lifetime", 	FT_UINT32,
		BASE_DEC, 	NULL,	0x0, 	"", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_stun2,
		&ett_stun2_att_type,
		&ett_stun2_att
	};

	/* Register the protocol name and description */
	proto_stun2 = proto_register_protocol("Session Traversal Utilities for NAT",
		"STUN2", "stun2");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_stun2, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_stun2(void)
{
	dissector_handle_t stun2_tcp_handle;
	dissector_handle_t stun2_udp_handle;

	stun2_tcp_handle = create_dissector_handle(dissect_stun2_tcp, proto_stun2);
	stun2_udp_handle = new_create_dissector_handle(dissect_stun2_udp, proto_stun2);

	dissector_add("tcp.port", TCP_PORT_STUN2, stun2_tcp_handle);
	dissector_add("udp.port", UDP_PORT_STUN2, stun2_udp_handle);

	heur_dissector_add("udp", dissect_stun2_heur, proto_stun2);
	heur_dissector_add("tcp", dissect_stun2_heur, proto_stun2);
}

