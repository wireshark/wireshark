/* packet-stun.c
 * Routines for Session Traversal Utilities for NAT (STUN) dissection
 * Copyright 2003, Shiang-Ming Huang <smhuang@pcs.csie.nctu.edu.tw>
 * Copyright 2006, Marc Petit-Huguenin <marc@petit-huguenin.org>
 * Copyright 2007-2008, 8x8 Inc. <petithug@8x8.com>
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
 * Please refer to the following specs for protocol detail:
 * - RFC 5389, formerly draft-ietf-behave-rfc3489bis-18
 * - RFC 5245, formerly draft-ietf-mmusic-ice-19
 * - RFC 5780, formerly draft-ietf-behave-nat-behavior-discovery-08
 * - RFC 5766, formerly draft-ietf-behave-turn-16
 * - draft-ietf-behave-turn-ipv6-11
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/ipproto.h>
#include <packet-tcp.h>
#include <packet-udp.h>

/* heuristic subdissectors */
static heur_dissector_list_t heur_subdissector_list;

/* data dissector handle */
static dissector_handle_t data_handle;

/* Initialize the protocol and registered fields */
static int proto_stun = -1;

static int hf_stun_channel = -1;

static int hf_stun_type = -1;
static int hf_stun_type_class = -1;
static int hf_stun_type_method = -1;
static int hf_stun_type_method_assignment = -1;
static int hf_stun_length = -1;
static int hf_stun_cookie = -1;
static int hf_stun_id = -1;
static int hf_stun_attributes = -1;
static int hf_stun_response_in = -1;
static int hf_stun_response_to = -1;
static int hf_stun_time = -1;
static int hf_stun_duplicate = -1;
static int hf_stun_attr = -1;

static int stun_att_type = -1;		/* STUN attribute fields */
static int stun_att_length = -1;
static int stun_att_family = -1;
static int stun_att_type_comprehension = -1;
static int stun_att_type_assignment = -1;
static int stun_att_ipv4 = -1;
static int stun_att_ipv6 = -1;
static int stun_att_port = -1;
static int stun_att_username = -1;
static int stun_att_padding = -1;
static int stun_att_hmac = -1;
static int stun_att_crc32 = -1;
static int stun_att_error_class = -1;
static int stun_att_error_number = -1;
static int stun_att_error_reason = -1;
static int stun_att_realm = -1;
static int stun_att_nonce = -1;
static int stun_att_unknown = -1;
static int stun_att_xor_ipv4 = -1;
static int stun_att_xor_ipv6 = -1;
static int stun_att_xor_port = -1;
static int stun_att_icmp_type = -1;
static int stun_att_icmp_code = -1;
static int stun_att_software = -1;
static int stun_att_priority = -1;
static int stun_att_tie_breaker = -1;
static int stun_att_change_ip = -1;
static int stun_att_change_port = -1;
static int stun_att_cache_timeout = -1;
static int stun_att_token = -1;
static int stun_att_reserve_next = -1;
static int stun_att_reserved = -1;
static int stun_att_value = -1;
static int stun_att_transp = -1;
static int stun_att_bandwidth = -1;
static int stun_att_lifetime = -1;
static int stun_att_channelnum = -1;


/* Structure containing transaction specific information */
typedef struct _stun_transaction_t {
	guint32 req_frame;
	guint32 rep_frame;
	nstime_t req_time;
} stun_transaction_t;

/* Structure containing conversation specific information */
typedef struct _stun_conv_info_t {
	emem_tree_t *transaction_pdus;
} stun_conv_info_t;


/* Message classes */
#define REQUEST		0x0000
#define INDICATION	0x0001
#define RESPONSE	0x0002
#define ERROR_RESPONSE	0x0003


/* Methods */
#define BINDING			0x0001	/* draft-ietf-behave-rfc3489bis-17 */
#define ALLOCATE		0x0003  /* draft-ietf-behave-turn-10*/
#define REFRESH			0x0004  /* draft-ietf-behave-turn-10*/
#define CHANNELBIND		0x0009  /* draft-ietf-behave-turn-10*/
#define CREATE_PERMISSION	0x0008	/* draft-ietf-behave-turn-10 */
/* Indications */
#define SEND			0x0006  /* draft-ietf-behave-turn-10*/
#define DATA_IND		0x0007  /* draft-ietf-behave-turn-10*/


/* Attribute Types */
/* Comprehension-required range (0x0000-0x7FFF) */
#define MAPPED_ADDRESS		0x0001	/* draft-ietf-behave-rfc3489bis-17 */
#define CHANGE_REQUEST		0x0003	/* draft-ietf-behave-nat-behavior-discovery-03 */
#define USERNAME		0x0006	/* draft-ietf-behave-rfc3489bis-17 */
#define MESSAGE_INTEGRITY	0x0008	/* draft-ietf-behave-rfc3489bis-17 */
#define ERROR_CODE		0x0009	/* draft-ietf-behave-rfc3489bis-17 */
#define UNKNOWN_ATTRIBUTES	0x000a	/* draft-ietf-behave-rfc3489bis-17 */
#define CHANNEL_NUMBER		0x000c	/* draft-ietf-behave-turn-10 */
#define LIFETIME		0x000d	/* draft-ietf-behave-turn-10 */
#define BANDWIDTH		0x0010 /* turn-07 */
#define XOR_PEER_ADDRESS	0x0012	/* draft-ietf-behave-turn-10 */
#define DATA			0x0013	/* draft-ietf-behave-turn-10 */
#define REALM			0x0014	/* draft-ietf-behave-rfc3489bis-17 */
#define NONCE			0x0015	/* draft-ietf-behave-rfc3489bis-17 */
#define XOR_RELAYED_ADDRESS	0x0016	/* draft-ietf-behave-turn-10 */
#define REQUESTED_ADDRESS_TYPE	0x0017	/* draft-ietf-behave-turn-ipv6-03 */
#define EVEN_PORT		0x0018	/* draft-ietf-behave-turn-10 */
#define REQUESTED_TRANSPORT	0x0019	/* draft-ietf-behave-turn-10 */
#define DONT_FRAGMENT		0x001a	/* draft-ietf-behave-turn-10 */
#define XOR_MAPPED_ADDRESS	0x0020	/* draft-ietf-behave-rfc3489bis-17 */
#define RESERVATION_TOKEN	0x0022	/* draft-ietf-behave-turn-10 */
#define PRIORITY		0x0024	/* draft-ietf-mmusic-ice-19 */
#define USE_CANDIDATE		0x0025	/* draft-ietf-mmusic-ice-19 */
#define PADDING			0x0026	/* draft-ietf-behave-nat-behavior-discovery-03 */
#define XOR_RESPONSE_TARGET	0x0027	/* draft-ietf-behave-nat-behavior-discovery-03 */
#define XOR_REFLECTED_FROM	0x0028	/* draft-ietf-behave-nat-behavior-discovery-03 */
#define ICMP			0x0030	/* Moved from TURN to a future I-D */
/* Comprehension-optional range (0x8000-0xFFFF) */
#define SOFTWARE		0x8022	/* draft-ietf-behave-rfc3489bis-17 */
#define ALTERNATE_SERVER	0x8023	/* draft-ietf-behave-rfc3489bis-17 */
#define CACHE_TIMEOUT		0x8027	/* draft-ietf-behave-nat-behavior-discovery-03 */
#define FINGERPRINT		0x8028	/* draft-ietf-behave-rfc3489bis-17 */
#define ICE_CONTROLLED		0x8029	/* draft-ietf-mmusic-ice-19 */
#define ICE_CONTROLLING		0x802a	/* draft-ietf-mmusic-ice-19 */
#define RESPONSE_ORIGIN		0x802b	/* draft-ietf-behave-nat-behavior-discovery-03 */
#define OTHER_ADDRESS		0x802c	/* draft-ietf-behave-nat-behavior-discovery-03 */

/* divers */
#define PROTO_NUM_UDP	17
#define PROTO_NUM_TCP	6
#define PROTO_NUM_ERR	255

#define TURN_REQUESTED_PROPS_EVEN_PORT		0x01
#define TURN_REQUESTED_PROPS_PAIR_OF_PORTS	0x02

#define TURN_CHANNEL_NUMBER_MIN			0x4000
#define TURN_CHANNEL_NUMBER_MAX			0xFFFE







/* Initialize the subtree pointers */
static gint ett_stun = -1;
static gint ett_stun_type = -1;
static gint ett_stun_att_all= -1;
static gint ett_stun_att = -1;
static gint ett_stun_att_type = -1;

#define UDP_PORT_STUN 	3478
#define TCP_PORT_STUN	3478

#define STUN_HDR_LEN		((guint)20)	/* STUN message header length */
#define ATTR_HDR_LEN			4	/* STUN attribute header length */
#define CHANNEL_DATA_HDR_LEN		4	/* TURN CHANNEL-DATA Message hdr length */
#define MIN_HDR_LEN			4

static const value_string transportnames[] = {
	{ 17, "UDP" },
	{  6, "TCP" },
	{  0, NULL }
};

static const value_string classes[] = {
	{REQUEST       , "Request"},
	{INDICATION    , "Indication"},
	{RESPONSE      , "Success Response"},
	{ERROR_RESPONSE, "Error Response"},
	{0x00          , NULL}
};

static const value_string methods[] = {
	{BINDING	  , "Binding"},
	{ALLOCATE	  , "Allocate"},
	{REFRESH	  , "Refresh"},
	{CHANNELBIND	  , "Channel-Bind"},
	{SEND		  , "Send"},
	{DATA_IND	  , "Data"},
	{CREATE_PERMISSION, "CreatePermission"},
	{0x00		  , NULL}
};



static const value_string attributes[] = {
	{MAPPED_ADDRESS        , "MAPPED-ADDRESS"},
	{CHANGE_REQUEST        , "CHANGE_REQUEST"},
	{USERNAME              , "USERNAME"},
	{MESSAGE_INTEGRITY     , "MESSAGE-INTEGRITY"},
	{ERROR_CODE            , "ERROR-CODE"},
	{UNKNOWN_ATTRIBUTES    , "UNKNOWN-ATTRIBUTES"},
	{CHANNEL_NUMBER        , "CHANNEL-NUMBER"},
	{LIFETIME              , "LIFETIME"},
	{BANDWIDTH             , "BANDWIDTH"},
	{XOR_PEER_ADDRESS      , "XOR-PEER-ADDRESS"},
	{DATA                  , "DATA"},
	{REALM                 , "REALM"},
	{NONCE                 , "NONCE"},
	{XOR_RELAYED_ADDRESS   , "XOR-RELAYED-ADDRESS"},
	{REQUESTED_ADDRESS_TYPE, "REQUESTED-ADDRESS-TYPE"},
	{EVEN_PORT             , "EVEN-PORT"},
	{REQUESTED_TRANSPORT   , "REQUESTED-TRANSPORT"},
	{DONT_FRAGMENT         , "DONT-FRAGMENT"},
	{XOR_MAPPED_ADDRESS    , "XOR-MAPPED-ADDRESS"},
	{RESERVATION_TOKEN     , "RESERVATION-TOKEN"},
	{PRIORITY              , "PRIORITY"},
	{USE_CANDIDATE         , "USE-CANDIDATE"},
	{PADDING               , "PADDING"},
	{XOR_RESPONSE_TARGET   , "XOR-RESPONSE-TARGET"},
	{XOR_REFLECTED_FROM    , "XOR-REFELECTED-FROM"},
	{ICMP                  , "ICMP"},
	{SOFTWARE              , "SOFTWARE"},
	{ALTERNATE_SERVER      , "ALTERNATE-SERVER"},
	{CACHE_TIMEOUT         , "CACHE-TIMEOUT"},
	{FINGERPRINT           , "FINGERPRINT"},
	{ICE_CONTROLLED        , "ICE-CONTROLLED"},
	{ICE_CONTROLLING       , "ICE-CONTROLLING"},
	{RESPONSE_ORIGIN       , "RESPONSE-ORIGIN"},
	{OTHER_ADDRESS         , "OTHER-ADDRESS"},
	{0x00                  , NULL}
};

static const value_string assignments[] = {
	{0x0000, "IETF Review"},
	{0x0001, "Designated Expert"},
	{0x00, NULL}
};

static const value_string comprehensions[] = {
	{0x0000, "Required"},
	{0x0001, "Optional"},
	{0x00  , NULL}
};

static const value_string attributes_reserve_next[] = {
	{0, "No reservation"},
	{1, "Reserve next port number"},
	{0x00, NULL}
};

static const value_string attributes_properties_p[] = {
	{0, "All allocation"},
	{1, "Preserving allocation"},
	{0x00, NULL}
};

static const value_string attributes_family[] = {
	{0x0001, "IPv4"},
	{0x0002, "IPv6"},
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


static guint
get_stun_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint16 type = tvb_get_ntohs(tvb, offset);
	guint16 length = tvb_get_ntohs(tvb, offset+2);
	guint res;

	if (type & 0xC000)
	{
		/* two first bits not NULL => should be a channel-data message */
		res = (guint) ((length + CHANNEL_DATA_HDR_LEN +3) & -4);
	}
	else
	{
		/* Normal STUN message */
		res = (guint) length + STUN_HDR_LEN;
	}
	return res;
}

static int
dissect_stun_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *stun_tree;
	proto_tree *stun_type_tree;
	proto_tree *att_all_tree;
	proto_tree *att_type_tree;
	proto_tree *att_tree;
	guint16 msg_type;
	guint16 msg_length;
	guint16 msg_type_method;
	guint16 msg_type_class;
	const char *msg_class_str;
	const char *msg_method_str;
	guint16 att_type;
	guint16 att_length;
	guint16 offset;
	guint i;
	guint magic_cookie_first_word;
	guint len;
	guint msg_total_len;
	conversation_t *conversation=NULL;
	stun_conv_info_t *stun_info;
	stun_transaction_t * stun_trans;
	emem_tree_key_t transaction_id_key[2];
	guint32 transaction_id[3];

	/*
	 * First check if the frame is really meant for us.
	 */

	offset = 0;
	len = tvb_length(tvb);



	/* First, make sure we have enough data to do the check. */
	if (len < MIN_HDR_LEN)
		return 0;

	msg_type = tvb_get_ntohs(tvb, 0);
	msg_length = tvb_get_ntohs(tvb, 2);

	if (msg_type & 0xC000)
	{
		/* two first bits not NULL => should be a channel-data message */
		if (msg_type == 0xFFFF)
			return 0;
		/* note that padding is only mandatory over streaming
		   protocols */
		msg_total_len = (guint) ((msg_length + CHANNEL_DATA_HDR_LEN +3) & -4) ;

		/* check if payload enough */
		if (len != msg_total_len) {
			if (pinfo->ipproto != IP_PROTO_UDP) {
				return 0;
			}
			/* recalculate the total length without padding */
			msg_total_len = (guint) msg_length + CHANNEL_DATA_HDR_LEN;
			if (len != msg_total_len)
				return 0;
		}
	}
	else
	{
		/* Normal STUN message */
		msg_total_len = (guint) msg_length + STUN_HDR_LEN;
		if (len < STUN_HDR_LEN)
			return 0;
		/* Check if it is really a STUN message */
		if ( tvb_get_ntohl(tvb, 4) != 0x2112a442)
			return 0;

		/* check if payload enough */
		if (len != msg_total_len)
			return 0;
	}

	/* The message seems to be a valid STUN message! */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "STUN");

	/* BEGIN of CHANNEL-DATA specific section */
	if (msg_type & 0xC000)
	{
		guint data_length;
		tvbuff_t *next_tvb;
		guint reported_len, new_len;
		/* two first bits not NULL => should be a channel-data message*/

		/* Clear out stuff in the info column */
		col_set_str(pinfo->cinfo, COL_INFO, "ChannelData TURN Message");

		if (!tree)
			return tvb_length(tvb);
		ti = proto_tree_add_item(
			tree, proto_stun, tvb, 0,
			CHANNEL_DATA_HDR_LEN,
			FALSE);
		proto_item_append_text(ti, ", TURN ChannelData Message");
		stun_tree = proto_item_add_subtree(ti, ett_stun);
		proto_tree_add_item(stun_tree, hf_stun_channel, tvb, offset, 2, FALSE); offset += 2;
		data_length = tvb_get_ntohs(tvb, 2);
		proto_tree_add_item(stun_tree, hf_stun_length,  tvb, offset, 2, FALSE); offset += 2;


		new_len = tvb_length_remaining(tvb, CHANNEL_DATA_HDR_LEN);
		reported_len = tvb_reported_length_remaining(tvb,
							     CHANNEL_DATA_HDR_LEN);
		if (data_length < reported_len) {
			reported_len = data_length;
		}
		next_tvb = tvb_new_subset(tvb, CHANNEL_DATA_HDR_LEN, new_len,
					  reported_len);


		if (!dissector_try_heuristic(heur_subdissector_list,
					     next_tvb, pinfo, tree)) {
			call_dissector_only(data_handle,next_tvb, pinfo, tree);
		}

		return tvb_length(tvb);
	}
	/* END of CHANNEL-DATA specific section */

	/* At this stage, we know this is a standard stun message */

	/* Create the transaction key which may be used
	   to track the conversation */
	transaction_id[0] = tvb_get_ntohl(tvb, 8);
	transaction_id[1] = tvb_get_ntohl(tvb, 12);
	transaction_id[2] = tvb_get_ntohl(tvb, 16);

	transaction_id_key[0].length = 3;
	transaction_id_key[0].key =  transaction_id;
	transaction_id_key[1].length = 0;
	transaction_id_key[1].key = NULL;

	msg_type_class = ((msg_type & 0x0010) >> 4) | ((msg_type & 0x0100) >> 7) ;
	msg_type_method = (msg_type & 0x000F) | ((msg_type & 0x00E0) >> 1) | ((msg_type & 0x3E00) >> 2);

	conversation = find_or_create_conversation(pinfo);

	/*
	 * Do we already have a state structure for this conv
	 */
	stun_info = conversation_get_proto_data(conversation, proto_stun);
	if (!stun_info) {
		/* No.  Attach that information to the conversation, and add
		 * it to the list of information structures.
		 */
		stun_info = se_alloc(sizeof(stun_conv_info_t));
		stun_info->transaction_pdus=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "stun_transaction_pdus");
		conversation_add_proto_data(conversation, proto_stun, stun_info);
	}

	if (!pinfo->fd->flags.visited) {
		if ((stun_trans =
		     se_tree_lookup32_array(stun_info->transaction_pdus,
					    transaction_id_key)) == NULL) {
			stun_trans=se_alloc(sizeof(stun_transaction_t));
			stun_trans->req_frame=0;
			stun_trans->rep_frame=0;
			stun_trans->req_time=pinfo->fd->abs_ts;
			se_tree_insert32_array(stun_info->transaction_pdus,
					       transaction_id_key,
					       (void *)stun_trans);
		}

		if (msg_type_class == REQUEST) {
			/* This is a request */
			if (stun_trans->req_frame == 0) {
				stun_trans->req_frame=pinfo->fd->num;
			}

		} else {
			/* This is a catch-all for all non-request messages */
			if (stun_trans->rep_frame == 0) {
				stun_trans->rep_frame=pinfo->fd->num;
			}

		}
	} else {
		stun_trans=se_tree_lookup32_array(stun_info->transaction_pdus,
						  transaction_id_key);
	}

	if (!stun_trans) {
		/* create a "fake" pana_trans structure */
		stun_trans=ep_alloc(sizeof(stun_transaction_t));
		stun_trans->req_frame=0;
		stun_trans->rep_frame=0;
		stun_trans->req_time=pinfo->fd->abs_ts;
	}


	msg_class_str = val_to_str_const(msg_type_class, classes, "Unknown");
	msg_method_str = val_to_str_const(msg_type_method, methods, "Unknown");

	if(check_col(pinfo->cinfo,COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			     msg_method_str, msg_class_str);
	}

	ti = proto_tree_add_item(tree, proto_stun, tvb, 0, -1, FALSE);

	stun_tree = proto_item_add_subtree(ti, ett_stun);


	if (msg_type_class == REQUEST) {
		if (stun_trans->req_frame != pinfo->fd->num) {
			proto_item *it;
			it=proto_tree_add_uint(stun_tree, hf_stun_duplicate,
					       tvb, 0, 0,
					       stun_trans->req_frame);
			PROTO_ITEM_SET_GENERATED(it);
		}
		if (stun_trans->rep_frame) {
			proto_item *it;
			it=proto_tree_add_uint(stun_tree, hf_stun_response_in,
					       tvb, 0, 0,
					       stun_trans->rep_frame);
			PROTO_ITEM_SET_GENERATED(it);
		}
	}
	else {
		/* Retransmission control */
		if (stun_trans->rep_frame != pinfo->fd->num) {
			proto_item *it;
			it=proto_tree_add_uint(stun_tree, hf_stun_duplicate,
					       tvb, 0, 0,
					       stun_trans->rep_frame);
			PROTO_ITEM_SET_GENERATED(it);
		}
		if (msg_type_class == RESPONSE || msg_type_class == ERROR_RESPONSE) {
			/* This is a response */
			if (stun_trans->req_frame) {
				proto_item *it;
				nstime_t ns;

				it=proto_tree_add_uint(stun_tree, hf_stun_response_to, tvb, 0, 0,
						       stun_trans->req_frame);
				PROTO_ITEM_SET_GENERATED(it);

				nstime_delta(&ns, &pinfo->fd->abs_ts, &stun_trans->req_time);
				it=proto_tree_add_time(stun_tree, hf_stun_time, tvb, 0, 0, &ns);
				PROTO_ITEM_SET_GENERATED(it);
			}

		}
	}

	ti = proto_tree_add_uint_format(stun_tree, hf_stun_type, tvb, 0, 2,
					msg_type, "Message Type: 0x%04x (%s %s)", msg_type, msg_method_str, msg_class_str);
	stun_type_tree = proto_item_add_subtree(ti, ett_stun_type);
	proto_tree_add_uint(stun_type_tree, hf_stun_type_class, tvb, 0, 2, msg_type);
	ti = proto_tree_add_text(stun_type_tree, tvb, 0, 2, "%s (%d)", msg_class_str, msg_type_class);
	PROTO_ITEM_SET_GENERATED(ti);
	proto_tree_add_uint(stun_type_tree, hf_stun_type_method, tvb, 0, 2, msg_type);
	ti = proto_tree_add_text(stun_type_tree, tvb, 0, 2, "%s (0x%03x)", msg_method_str, msg_type_method);
	PROTO_ITEM_SET_GENERATED(ti);
	proto_tree_add_uint(stun_type_tree, hf_stun_type_method_assignment, tvb, 0, 2, msg_type);
	ti = proto_tree_add_text(stun_type_tree, tvb, 0, 2, "%s (%d)", val_to_str((msg_type & 0x2000) >> 13, assignments, "Unknown: 0x%x"), (msg_type & 0x2000) >> 13);
	PROTO_ITEM_SET_GENERATED(ti);

	proto_tree_add_uint(stun_tree, hf_stun_length, tvb, 2, 2, msg_length);
	proto_tree_add_item(stun_tree, hf_stun_cookie, tvb, 4, 4, FALSE);
	proto_tree_add_item(stun_tree, hf_stun_id, tvb, 8, 12, FALSE);

	/* Remember this (in host order) so we can show clear xor'd addresses */
	magic_cookie_first_word = tvb_get_ntohl(tvb, 4);

	if (msg_length > 0) {
		ti = proto_tree_add_item(stun_tree, hf_stun_attributes, tvb, STUN_HDR_LEN, msg_length, FALSE);
		att_all_tree = proto_item_add_subtree(ti, ett_stun_att_all);

		offset = STUN_HDR_LEN;

		while (msg_length > 0) {
			att_type = tvb_get_ntohs(tvb, offset); /* Type field in attribute header */
			att_length = tvb_get_ntohs(tvb, offset+2); /* Length field in attribute header */
			ti = proto_tree_add_uint_format(att_all_tree, hf_stun_attr,
							tvb, offset, ATTR_HDR_LEN+att_length,
							att_type, "%s", val_to_str(att_type, attributes, "Unknown"));
			att_tree = proto_item_add_subtree(ti, ett_stun_att);
			ti = proto_tree_add_uint(att_tree, stun_att_type, tvb,
						 offset, 2, att_type);
			att_type_tree = proto_item_add_subtree(ti, ett_stun_att_type);
			proto_tree_add_uint(att_type_tree, stun_att_type_comprehension, tvb, offset, 2, att_type);
			ti = proto_tree_add_text(att_type_tree, tvb, offset, 2,
						 "%s (%d)",
						 val_to_str((att_type & 0x8000) >> 15, comprehensions, "Unknown: %d"),
						 (att_type & 0x8000) >> 15);
			PROTO_ITEM_SET_GENERATED(ti);
			proto_tree_add_uint(att_type_tree, stun_att_type_assignment, tvb, offset, 2, att_type);
			ti = proto_tree_add_text(att_type_tree, tvb, offset, 2,
						 "%s (%d)",
						 val_to_str((att_type & 0x4000) >> 14, assignments, "Unknown: %d"),
						 (att_type & 0x4000) >> 14);
			PROTO_ITEM_SET_GENERATED(ti);

			offset += 2;
			if (ATTR_HDR_LEN+att_length > msg_length) {
				proto_tree_add_uint_format(att_tree,
							   stun_att_length, tvb, offset, 2,
							   att_length,
							   "Attribute Length: %u (bogus, goes past the end of the message)",
							   att_length);
				break;
			}
			proto_tree_add_uint(att_tree, stun_att_length, tvb,
					    offset, 2, att_length);
			offset += 2;
			switch (att_type) {
			case MAPPED_ADDRESS:
			case ALTERNATE_SERVER:
			case RESPONSE_ORIGIN:
			case OTHER_ADDRESS:
				if (att_length < 1)
					break;
				proto_tree_add_uint(att_tree, stun_att_reserved, tvb, offset, 1, 1);
				if (att_length < 2)
					break;
				proto_tree_add_item(att_tree, stun_att_family, tvb, offset+1, 1, FALSE);
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun_att_port, tvb, offset+2, 2, FALSE);
				switch (tvb_get_guint8(tvb, offset+1)) {
				case 1:
					if (att_length < 8)
						break;
					proto_tree_add_item(att_tree, stun_att_ipv4, tvb, offset+4, 4, FALSE);
					{
						const gchar *ipstr;
						guint32 ip;
						ip = tvb_get_ipv4(tvb,offset+4);
						ipstr = ip_to_str((guint8*)&ip);
						proto_item_append_text(att_tree, ": %s:%d", ipstr,tvb_get_ntohs(tvb,offset+2));
						if(check_col(pinfo->cinfo,COL_INFO)) {
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
					proto_tree_add_item(att_tree, stun_att_ipv6, tvb, offset+4, 16, FALSE);
					break;
				}
				break;

			case CHANGE_REQUEST:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun_att_change_ip, tvb, offset, 4, FALSE);
				proto_tree_add_item(att_tree, stun_att_change_port, tvb, offset, 4, FALSE);
				break;

			case USERNAME:
				proto_tree_add_item(att_tree, stun_att_username, tvb, offset, att_length, FALSE);
				proto_item_append_text(att_tree, ": %s", tvb_get_ephemeral_string(tvb, offset, att_length));
				if(check_col(pinfo->cinfo,COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" user: %s",
						tvb_get_ephemeral_string(tvb,offset, att_length)
						);
				}
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun_att_padding,
							    tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case MESSAGE_INTEGRITY:
				if (att_length < 20)
					break;
				proto_tree_add_item(att_tree, stun_att_hmac, tvb, offset, att_length, FALSE);
				break;

			case ERROR_CODE:
				if (att_length < 2)
					break;
				proto_tree_add_uint(att_tree, stun_att_reserved, tvb, offset, 2, 2);
				if (att_length < 3)
					break;
				proto_tree_add_item(att_tree, stun_att_error_class, tvb, offset+2, 1, FALSE);
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun_att_error_number, tvb, offset+3, 1, FALSE);
				{
					int human_error_num = tvb_get_guint8(tvb, offset+2) * 100 + tvb_get_guint8(tvb, offset+3);
					proto_item_append_text(
						att_tree,
						" %d (%s)",
						human_error_num, /* human readable error code */
						val_to_str(human_error_num, error_code, "*Unknown error code*")
						);
					if(check_col(pinfo->cinfo,COL_INFO)) {
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
				proto_tree_add_item(att_tree, stun_att_error_reason, tvb, offset+4, att_length-4, FALSE);

				proto_item_append_text(att_tree, ": %s", tvb_get_ephemeral_string(tvb, offset+4, att_length-4));
				if(check_col(pinfo->cinfo,COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" %s",
						tvb_get_ephemeral_string(tvb, offset+4, att_length-4)
						);
				}

				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case UNKNOWN_ATTRIBUTES:
				for (i = 0; i < att_length; i += 2)
					proto_tree_add_item(att_tree, stun_att_unknown, tvb, offset+i, 2, FALSE);
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case REALM:
				proto_tree_add_item(att_tree, stun_att_realm, tvb, offset, att_length, FALSE);
				proto_item_append_text(att_tree, ": %s", tvb_get_ephemeral_string(tvb, offset, att_length));
				if(check_col(pinfo->cinfo,COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" realm: %s",
						tvb_get_ephemeral_string(tvb,offset, att_length)
						);
				}
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case NONCE:
				proto_tree_add_item(att_tree, stun_att_nonce, tvb, offset, att_length, FALSE);
				proto_item_append_text(att_tree, ": %s", tvb_get_ephemeral_string(tvb, offset, att_length));
				if(check_col(pinfo->cinfo,COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" with nonce"
						);
				}
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case XOR_MAPPED_ADDRESS:
			case XOR_PEER_ADDRESS:
			case XOR_RELAYED_ADDRESS:
			case XOR_RESPONSE_TARGET:
			case XOR_REFLECTED_FROM:
				if (att_length < 1)
					break;
				    	proto_tree_add_uint(att_tree, stun_att_reserved, tvb, offset, 1, 1);
				if (att_length < 2)
					break;
				proto_tree_add_item(att_tree, stun_att_family, tvb, offset+1, 1, FALSE);
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun_att_xor_port, tvb, offset+2, 2, FALSE);

				/* Show the port 'in the clear'
				XOR (host order) transid with (host order) xor-port.
				Add host-order port into tree. */
				ti = proto_tree_add_uint(att_tree, stun_att_port, tvb, offset+2, 2,
					tvb_get_ntohs(tvb, offset+2) ^
					(magic_cookie_first_word >> 16));
				PROTO_ITEM_SET_GENERATED(ti);

				if (att_length < 8)
					break;
				switch (tvb_get_guint8(tvb, offset+1)) {
					case 1:
					proto_tree_add_item(att_tree, stun_att_xor_ipv4, tvb, offset+4, 4, FALSE);

					/* Show the address 'in the clear'.
					XOR (host order) transid with (host order) xor-address.
					Add in network order tree. */
					ti = proto_tree_add_ipv4(att_tree, stun_att_ipv4, tvb, offset+4, 4,
						g_htonl(tvb_get_ntohl(tvb, offset+4) ^
						magic_cookie_first_word));
					PROTO_ITEM_SET_GENERATED(ti);

					{
						const gchar *ipstr;
						guint32 ip;
						guint16 port;
						ip = g_htonl(tvb_get_ntohl(tvb, offset+4) ^ magic_cookie_first_word);
						ipstr = ip_to_str((guint8*)&ip);
						port = tvb_get_ntohs(tvb, offset+2) ^ (magic_cookie_first_word >> 16);
						proto_item_append_text(att_tree, ": %s:%d", ipstr, port);
						if(check_col(pinfo->cinfo,COL_INFO)) {
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
					proto_tree_add_item(att_tree, stun_att_xor_ipv6, tvb, offset+4, 16, FALSE);
					{
						guint32 IPv6[4];
						IPv6[0] = g_htonl(tvb_get_ntohl(tvb, offset+4) ^ magic_cookie_first_word);
						IPv6[1] = g_htonl(tvb_get_ntohl(tvb, offset+8) ^ transaction_id[0]);
						IPv6[2] = g_htonl(tvb_get_ntohl(tvb, offset+12) ^ transaction_id[1]);
						IPv6[3] = g_htonl(tvb_get_ntohl(tvb, offset+16) ^ transaction_id[2]);
						ti = proto_tree_add_ipv6(att_tree, stun_att_ipv6, tvb, offset+4, 16,
									 (const guint8 *)IPv6);
						PROTO_ITEM_SET_GENERATED(ti);
					}

					break;
				}
				break;

			case REQUESTED_ADDRESS_TYPE:
				if (att_length < 1)
					break;
				proto_tree_add_item(att_tree, stun_att_family, tvb, offset, 1, FALSE);
				if (att_length < 4)
					break;
				proto_tree_add_uint(att_tree, stun_att_reserved, tvb, offset+1, 3, 3);
				break;
case EVEN_PORT:
  				if (att_length < 1)
					break;
				proto_tree_add_item(att_tree, stun_att_reserve_next, tvb, offset, 1, FALSE);
				break;

			case RESERVATION_TOKEN:
				if (att_length < 8)
					break;
				proto_tree_add_item(att_tree, stun_att_token, tvb, offset, 8, FALSE);
				break;

			case PRIORITY:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun_att_priority, tvb, offset, 4, FALSE);
				break;

			case PADDING:
				proto_tree_add_uint(att_tree, stun_att_padding, tvb, offset, att_length, att_length);
				break;

			case ICMP:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun_att_icmp_type, tvb, offset, 1, FALSE);
				proto_tree_add_item(att_tree, stun_att_icmp_code, tvb, offset+1, 1, FALSE);
				break;

			case SOFTWARE:
				proto_tree_add_item(att_tree, stun_att_software, tvb, offset, att_length, FALSE);
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;

			case CACHE_TIMEOUT:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun_att_cache_timeout, tvb, offset, 4, FALSE);
				break;

			case FINGERPRINT:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun_att_crc32, tvb, offset, att_length, FALSE);
				break;

			case ICE_CONTROLLED:
			case ICE_CONTROLLING:
				if (att_length < 8)
					break;
				proto_tree_add_item(att_tree, stun_att_tie_breaker, tvb, offset, 8, FALSE);
				break;

			case DATA:
				if (att_length > 0) {
					tvbuff_t *next_tvb;
					guint reported_len, pad=0;
					proto_tree_add_item(att_tree, stun_att_value, tvb, offset, att_length, FALSE);
					if (att_length % 4 != 0) {
						pad = 4-(att_length % 4);
						proto_tree_add_uint(att_tree, stun_att_padding, tvb, offset+att_length, pad, pad);
					}
					reported_len = att_length;


					next_tvb =
						tvb_new_subset(tvb, offset,
							       reported_len,
							       reported_len);

					if (!dissector_try_heuristic(heur_subdissector_list,
								     next_tvb, pinfo, att_tree)) {
						call_dissector_only(data_handle,next_tvb, pinfo, att_tree);
					}

				}
				break;

			case REQUESTED_TRANSPORT:
				if (att_length < 1)
					break;
				proto_tree_add_item(att_tree, stun_att_transp, tvb, offset, 1, FALSE);
				if (att_length < 4)
					break;

				{
					guint8  protoCode = tvb_get_guint8(tvb, offset);
					proto_item_append_text(att_tree, ": %s", val_to_str(protoCode, transportnames, "Unknown (0x%8x)"));
					if(check_col(pinfo->cinfo,COL_INFO)) {
						col_append_fstr(
							pinfo->cinfo, COL_INFO,
							" %s",
							val_to_str(protoCode, transportnames, "Unknown (0x%8x)")
							);
					}
				}
				proto_tree_add_uint(att_tree, stun_att_reserved, tvb, offset+1, 3, 3);
				break;

			case CHANNEL_NUMBER:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun_att_channelnum, tvb, offset, 2, FALSE);
				{
					guint16 chan = tvb_get_ntohs(tvb, offset);
					proto_item_append_text(att_tree, ": 0x%x", chan);
					if(check_col(pinfo->cinfo,COL_INFO)) {
						col_append_fstr(
							pinfo->cinfo, COL_INFO,
							" ChannelNumber=0x%x",
							chan
							);
					}
				}
				proto_tree_add_uint(att_tree, stun_att_reserved, tvb, offset+2, 2, 2);
				break;

			case BANDWIDTH:
				if (att_length < 4)
					break;
				proto_tree_add_item(att_tree, stun_att_bandwidth, tvb, offset, 4, FALSE);
				proto_item_append_text(att_tree, " %d", tvb_get_ntohl(tvb, offset));
				if(check_col(pinfo->cinfo,COL_INFO)) {
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
				proto_tree_add_item(att_tree, stun_att_lifetime, tvb, offset, 4, FALSE);
				proto_item_append_text(att_tree, " %d", tvb_get_ntohl(tvb, offset));
				if(check_col(pinfo->cinfo,COL_INFO)) {
					col_append_fstr(
						pinfo->cinfo, COL_INFO,
						" lifetime: %d",
						tvb_get_ntohl(tvb, offset)
						);
				}
				break;

			default:
				if (att_length > 0)
					proto_tree_add_item(att_tree, stun_att_value, tvb, offset, att_length, FALSE);
				if (att_length % 4 != 0)
					proto_tree_add_uint(att_tree, stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
				break;
			}
			offset += (att_length+3) & -4;
			msg_length -= (ATTR_HDR_LEN+att_length+3) & -4;
		}
	}

	return tvb_length(tvb);
}

static int
dissect_stun_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_stun_message(tvb, pinfo, tree);
}

static void
dissect_stun_message_no_return(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_stun_message(tvb, pinfo, tree);
}

static void
dissect_stun_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MIN_HDR_LEN,
		get_stun_message_len, dissect_stun_message_no_return);
}

static gboolean
dissect_stun_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (dissect_stun_message(tvb, pinfo, tree) == 0) {
		/*
		 * It wasn't a valid STUN message, and wasn't
		 * dissected as such.
		 */
		return FALSE;
	}
	return TRUE;
}

void
proto_register_stun(void)
{
	static hf_register_info hf[] = {

		{ &hf_stun_channel,
		  { "Channel Number",	"stun.channel",	FT_UINT16,
		    BASE_HEX, 	NULL, 	0x0, 	NULL,	HFILL }
		},

		/* ////////////////////////////////////// */
		{ &hf_stun_type,
		  { "Message Type",	"stun.type", 	FT_UINT16,
		    BASE_HEX, 	NULL,	0, 	NULL, 	HFILL }
		},
		{ &hf_stun_type_class,
		  { "Message Class",	"stun.type.class", 	FT_UINT16,
		    BASE_HEX, 	NULL,	0x0110, 	NULL, 	HFILL }
		},
		{ &hf_stun_type_method,
		  { "Message Method",	"stun.type.method", 	FT_UINT16,
		    BASE_HEX, 	NULL,	0x3EEF, 	NULL, 	HFILL }
		},
		{ &hf_stun_type_method_assignment,
		  { "Message Method Assignment",	"stun.type.method-assignment", 	FT_UINT16,
		    BASE_HEX, 	NULL,	0x2000, 	NULL, 	HFILL }
		},
		{ &hf_stun_length,
		  { "Message Length",	"stun.length",	FT_UINT16,
		    BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &hf_stun_cookie,
		  { "Message Cookie",	"stun.cookie",	FT_BYTES,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &hf_stun_id,
		  { "Message Transaction ID",	"stun.id",	FT_BYTES,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &hf_stun_attributes,
		  { "Attributes",		"stun.attributes",	FT_NONE,
		    BASE_NONE,	NULL, 	0x0, 	NULL,	HFILL }
		},
		{ &hf_stun_attr,
		  { "Attribute Type",	"stun.attribute", 	FT_UINT16,
		    BASE_HEX, 	NULL,	0, 	NULL, 	HFILL }
		},
		{ &hf_stun_response_in,
		  { "Response In",	"stun.response-in", FT_FRAMENUM,
		    BASE_NONE, NULL, 0x0, "The response to this STUN query is in this frame", HFILL }
		},
		{ &hf_stun_response_to,
		  { "Request In", "stun.response-to", FT_FRAMENUM,
		    BASE_NONE, NULL, 0x0, "This is a response to the STUN Request in this frame", HFILL }
		},
		{ &hf_stun_time,
		  { "Time", "stun.time", FT_RELATIVE_TIME,
		    BASE_NONE, NULL, 0x0, "The time between the Request and the Response", HFILL }
		},
		{ &hf_stun_duplicate,
		  { "Duplicated original message in", "stun.reqduplicate", FT_FRAMENUM,
		    BASE_NONE, NULL, 0x0, "This is a duplicate of STUN message in this frame", HFILL }
		},
		/* ////////////////////////////////////// */
		{ &stun_att_type,
		  { "Attribute Type",	"stun.att.type",	FT_UINT16,
		    BASE_HEX,	VALS(attributes),	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_type_comprehension,
		  { "Attribute Type Comprehension",	"stun.att.type.comprehension",	FT_UINT16,
		    BASE_HEX,	NULL,	0x8000, 	NULL,	HFILL }
		},
		{ &stun_att_type_assignment,
		  { "Attribute Type Assignment",	"stun.att.type.assignment",	FT_UINT16,
		    BASE_HEX,	NULL,	0x4000, 	NULL,	HFILL }
		},
		{ &stun_att_length,
		  { "Attribute Length",	"stun.att.length",	FT_UINT16,
		    BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_family,
		  { "Protocol Family",	"stun.att.family",	FT_UINT8,
		    BASE_HEX,	VALS(attributes_family),	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_ipv4,
		  { "IP",		"stun.att.ipv4",	FT_IPv4,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_ipv6,
		  { "IP",		"stun.att.ipv6",	FT_IPv6,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_port,
		  { "Port",	"stun.att.port",	FT_UINT16,
		    BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_username,
		  { "Username",	"stun.att.username",	FT_STRING,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_padding,
		  { "Padding",	"stun.att.padding",	FT_UINT16,
		    BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_hmac,
		  { "HMAC-SHA1",	"stun.att.hmac",	FT_BYTES,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_crc32,
		  { "CRC-32",	"stun.att.crc32",	FT_UINT32,
		    BASE_HEX,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_error_class,
		  { "Error Class","stun.att.error.class",	FT_UINT8,
		    BASE_DEC, 	NULL,	0x07,	NULL,	HFILL}
		},
		{ &stun_att_error_number,
		  { "Error Code","stun.att.error",	FT_UINT8,
		    BASE_DEC, 	NULL,	0x0,	NULL,	HFILL}
		},
		{ &stun_att_error_reason,
		  { "Error Reason Phrase","stun.att.error.reason",	FT_STRING,
		    BASE_NONE, 	NULL,	0x0,	NULL,	HFILL}
		},
		{ &stun_att_realm,
		  { "Realm",	"stun.att.realm",	FT_STRING,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_nonce,
		  { "Nonce",	"stun.att.nonce",	FT_STRING,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_unknown,
		  { "Unknown Attribute","stun.att.unknown",	FT_UINT16,
		    BASE_HEX, 	NULL,	0x0,	NULL,	HFILL}
		},
		{ &stun_att_xor_ipv4,
		  { "IP (XOR-d)",		"stun.att.ipv4-xord",	FT_BYTES,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_xor_ipv6,
		  { "IP (XOR-d)",		"stun.att.ipv6-xord",	FT_BYTES,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_xor_port,
		  { "Port (XOR-d)",	"stun.att.port-xord",	FT_BYTES,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_icmp_type,
		  { "ICMP type",		"stun.att.icmp.type",	FT_UINT8,
		    BASE_DEC, 	NULL,	0x0,	NULL,	HFILL}
 		},
		{ &stun_att_icmp_code,
		  { "ICMP code",		"stun.att.icmp.code",	FT_UINT8,
		    BASE_DEC, 	NULL,	0x0,	NULL,	HFILL}
 		},
		{ &stun_att_software,
		  { "Software","stun.att.software",	FT_STRING,
		    BASE_NONE, 	NULL,	0x0,	NULL,	HFILL}
		},
		{ &stun_att_priority,
		  { "Priority",		"stun.att.priority",	FT_UINT32,
		    BASE_DEC, 	NULL,	0x0,	NULL,	HFILL}
 		},
		{ &stun_att_tie_breaker,
		  { "Tie breaker",	"stun.att.tie-breaker",	FT_BYTES,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_lifetime,
		  { "Lifetime",		"stun.att.lifetime",	FT_UINT32,
		    BASE_DEC, 	NULL,	0x0,	NULL,	HFILL}
 		},
		{ &stun_att_change_ip,
		  { "Change IP","stun.att.change-ip",	FT_BOOLEAN,
		    16, 	TFS(&tfs_set_notset),	0x0004,	NULL,	HFILL}
		},
		{ &stun_att_change_port,
		  { "Change Port","stun.att.change-port",	FT_BOOLEAN,
		    16, 	TFS(&tfs_set_notset),	0x0002,	NULL,	HFILL}
		},
		{ &stun_att_reserve_next,
		  { "Reserve next","stun.att.even-port.reserve-next",	FT_UINT8,
		    BASE_DEC, 	VALS(attributes_reserve_next),	0x80,	NULL,	HFILL}
		},
		{ &stun_att_cache_timeout,
		  { "Cache timeout",		"stun.att.cache-timeout",	FT_UINT32,
		    BASE_DEC, 	NULL,	0x0,	NULL,	HFILL}
 		},
		{ &stun_att_token,
		  { "Token",	"stun.att.token",	FT_BYTES,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_value,
		  { "Value",	"stun.value",	FT_BYTES,
		    BASE_NONE,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_reserved,
		  { "Reserved",	"stun.att.reserved",	FT_UINT16,
		    BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_transp,
		  { "Transport",	"stun.att.transp",	FT_UINT8,
		    BASE_HEX,	VALS(transportnames),	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_channelnum,
		  { "Channel-Number",	"stun.att.channelnum",	FT_UINT16,
		    BASE_HEX,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &stun_att_bandwidth,
		  { "Bandwidth",	"stun.port.bandwidth", 	FT_UINT32,
		    BASE_DEC, 	NULL,	0x0, 	NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_stun,
		&ett_stun_type,
		&ett_stun_att_all,
		&ett_stun_att,
		&ett_stun_att_type,
	};

	/* Register the protocol name and description */
	proto_stun = proto_register_protocol("Session Traversal Utilities for NAT", "STUN", "stun");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_stun, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* heuristic subdissectors (used for the DATA field) */
	register_heur_dissector_list("stun", &heur_subdissector_list);
}

void
proto_reg_handoff_stun(void)
{
	dissector_handle_t stun_tcp_handle;
	dissector_handle_t stun_udp_handle;

	stun_tcp_handle = create_dissector_handle(dissect_stun_tcp, proto_stun);
	stun_udp_handle = new_create_dissector_handle(dissect_stun_udp, proto_stun);

	dissector_add_uint("tcp.port", TCP_PORT_STUN, stun_tcp_handle);
	dissector_add_uint("udp.port", UDP_PORT_STUN, stun_udp_handle);

	heur_dissector_add("udp", dissect_stun_heur, proto_stun);
	heur_dissector_add("tcp", dissect_stun_heur, proto_stun);
	heur_dissector_add("stun", dissect_stun_heur, proto_stun);

	data_handle = find_dissector("data");
}

