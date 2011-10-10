/* packet-msproxy.c
 * Routines for Microsoft Proxy packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * This was derived from the dante socks implementation source code.
 * Most of the information came from common.h and msproxy_clientprotocol.c
 *
 * See http://www.inet.no/dante for more information
 */

/************************************************************************
 *									*
 *  Notes: These are possible command values. User input is welcome 	*
 *									*
 *  Command = 0x040a - Remote host closed connection (maybe ?? )	*
 *  Command = 0x0411 - Remote host closed connection			*
 *  Command = 0x0413 - Local host closed connection or SYN worked	*
 *									*
 ************************************************************************/




#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#include "packet-tcp.h"
#include "packet-udp.h"

extern void udp_hash_add(guint16 proto,
        void (*dissect)(const guchar *, int, frame_data *, proto_tree *));


static int proto_msproxy = -1;

static int ett_msproxy = -1;
static int ett_msproxy_name = -1;

static int hf_msproxy_cmd = -1;
static int hf_msproxy_clntport = -1;

static int hf_msproxy_dstaddr = -1;

static int hf_msproxy_srcport = -1;
static int hf_msproxy_dstport = -1;
static int hf_msproxy_serverport = -1;
static int hf_msproxy_serveraddr = -1;
static int hf_msproxy_bindport = -1;
static int hf_msproxy_bindaddr = -1;
static int hf_msproxy_boundport = -1;
static int hf_msproxy_bind_id = -1;
static int hf_msproxy_resolvaddr = -1;

static int hf_msproxy_server_int_addr = -1;
static int hf_msproxy_server_int_port = -1;
static int hf_msproxy_server_ext_addr = -1;
static int hf_msproxy_server_ext_port = -1;

static dissector_handle_t msproxy_sub_handle;


#define UDP_PORT_MSPROXY 1745

#define N_MSPROXY_HELLO			0x05	/* packet 1 from client */
#define N_MSPROXY_ACK			0x10	/* packet 1 from server */
#define N_MSPROXY_USERINFO_ACK		0x04	/* packet 2 from server */
#define N_MSPROXY_AUTH			0x47	/* packet 3 from client */
#define N_MSPROXY_RESOLVE		0x07	/* Resolve request	*/


/*$$$ 0x0500 was dante value, I see 0x05ff and 0x0500 */

#define MSPROXY_HELLO			0x0500
#define MSPROXY_HELLO_2			0x05ff

#define MSPROXY_HELLO_ACK		0x1000

#define MSPROXY_USERINFO		0x1000
#define MSPROXY_USERINFO_ACK		0x0400

#define MSPROXY_AUTH			0x4700
#define MSPROXY_AUTH_1_ACK		0x4714
#define MSPROXY_AUTH_2			0x4701
#define MSPROXY_AUTH_2_ACK		0x4715
#define MSPROXY_AUTH_2_ACK2		0x4716

#define MSPROXY_RESOLVE			0x070d
#define MSPROXY_RESOLVE_ACK		0x070f

#define MSPROXY_BIND			0x0704
#define MSPROXY_BIND_ACK		0x0706

#define MSPROXY_TCP_BIND		0x0707
#define MSPROXY_TCP_BIND_ACK		0x0708

#define MSPROXY_LISTEN			0x0406

#define MSPROXY_BINDINFO		0x0709

#define MSPROXY_BINDINFO_ACK		0x070a

#define MSPROXY_CONNECT			0x071e
#define MSPROXY_CONNECT_ACK		0x0703

#define MSPROXY_UDPASSOCIATE		0x0705
#define MSPROXY_UDPASSOCIATE_ACK	0x0706

#define MSPROXY_UDP_BIND_REQ		0x070b

#define MSPROXY_CONNECTED		0x042c
#define MSPROXY_SESSIONEND		0x251e

#define MSPROXY_BIND_AUTHFAILED		0x0804
#define MSPROXY_CONNECT_AUTHFAILED	0x081e
#define MSPROXY_CONNREFUSED		0x4		/* low 12 bits seem to vary.	*/

#define FROM_SERVER 1			/* direction of packet data for get_msproxy_cmd_name */
#define FROM_CLIENT 0




/*$$$ should this be the same as redirect_entry_t ?? */
/*  then the add_conversation could just copy the structure */
/* using the same allocation (instance  for you object guys)	*/
/* wouldn't work because there may be multiple child conversations */
/* from the same MSProxy conversation */

typedef struct {
	guint32	dst_addr;
	guint32	clnt_port;
	guint32	dst_port;
	guint32	server_int_port;
	int	proto;
}hash_entry_t;


/************** conversation hash stuff ***************/

typedef struct {
	guint32	remote_addr;
	guint32	clnt_port;
	guint32	server_int_port;
	guint32	remote_port;
	int	proto;
}redirect_entry_t;


/************** negotiated conversation hash stuff ***************/


static guint32 last_row= 0;	/* used to see if packet is new */

static void msproxy_sub_dissector( tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *tree) {

/* Conversation dissector called from TCP or UDP dissector. Decode and	*/
/* display the msproxy header, the pass the rest of the data to the tcp	*/
/* or udp port decode routine to  handle the payload.			*/

	guint32 *ptr;
	redirect_entry_t *redirect_info;
	conversation_t *conversation;
	proto_tree      *msp_tree;
	proto_item      *ti;

	conversation = find_conversation( pinfo->fd->num, &pinfo->src, &pinfo->dst,
		pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

	DISSECTOR_ASSERT( conversation);	/* should always find a conversation */

	redirect_info = conversation_get_proto_data(conversation,
		proto_msproxy);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MS Proxy");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO,
			(( redirect_info->proto == PT_TCP) ? "TCP stream" :
			 "UDP packets"));

	if ( tree) {
    		ti = proto_tree_add_item( tree, proto_msproxy, tvb, 0, 0,
    			FALSE );

		msp_tree = proto_item_add_subtree(ti, ett_msproxy);

		proto_tree_add_uint( msp_tree, hf_msproxy_dstport, tvb, 0, 0,
			redirect_info->remote_port);

		proto_tree_add_ipv4( msp_tree, hf_msproxy_dstaddr, tvb, 0, 0,
			redirect_info->remote_addr);

	}

/* set pinfo->{src/dst port} and call the UDP sub-dissector lookup */

	if ( pinfo->srcport == redirect_info->clnt_port)
       		ptr = &pinfo->destport;
   	else
    		ptr = &pinfo->srcport;

        *ptr = redirect_info->remote_port;

	if ( redirect_info->proto == PT_TCP)
		decode_tcp_ports( tvb, 0, pinfo, tree, pinfo->srcport,
			pinfo->destport, NULL);
	else
		decode_udp_ports( tvb, 0, pinfo, tree, pinfo->srcport,
			pinfo->destport, -1);

        *ptr = redirect_info->server_int_port;
}



static void add_msproxy_conversation( packet_info *pinfo,
	hash_entry_t *hash_info){

/* check to see if a conversation already exists, if it does assume 	*/
/* it's our conversation and quit. Otherwise create a new conversation.	*/
/* Load the conversation dissector to our  dissector and load the	*/
/* conversation data structure with the info needed to call the TCP or 	*/
/* UDP port decoder.							*/

/* NOTE: Currently this assume that the conversation will be created 	*/
/* 	during a packet from the server.  If that changes, pinfo->src	*/
/*	and pinfo->dst will not be correct and this routine will have	*/
/*	to change.							*/

	conversation_t *conversation;
	redirect_entry_t *new_conv_info;

	if (pinfo->fd->flags.visited) {
		/*
		 * We've already processed this frame once, so we
		 * should already have done this.
		 */
		return;
	}

	conversation = find_conversation( pinfo->fd->num, &pinfo->src,
		&pinfo->dst, hash_info->proto, hash_info->server_int_port,
		hash_info->clnt_port, 0);

	if ( !conversation) {
		conversation = conversation_new( pinfo->fd->num, &pinfo->src, &pinfo->dst,
			hash_info->proto, hash_info->server_int_port,
			hash_info->clnt_port, 0);
	}
	conversation_set_dissector(conversation, msproxy_sub_handle);

	new_conv_info = se_alloc(sizeof(redirect_entry_t));

	new_conv_info->remote_addr = hash_info->dst_addr;
	new_conv_info->clnt_port = hash_info->clnt_port;
	new_conv_info->remote_port = hash_info->dst_port;
	new_conv_info->server_int_port = hash_info->server_int_port;
	new_conv_info->proto = hash_info->proto;

	conversation_add_proto_data(conversation, proto_msproxy,
		new_conv_info);
}



static int display_application_name(tvbuff_t *tvb, int offset,
	proto_tree *tree) {

/* display the application name in the proto tree.   			*/

/* NOTE: this routine assumes that the tree pointer is valid (not NULL) */

	int length;

	length = tvb_strnlen( tvb, offset, 255);
	proto_tree_add_text( tree, tvb, offset, length, "Application: %.*s",
		length, tvb_get_ephemeral_string( tvb, offset, length));

	return length;
}


static const char *get_msproxy_cmd_name( int cmd, int direction) {

/* return the command name string for cmd */

	switch (cmd){
		case MSPROXY_HELLO_2:
		case MSPROXY_HELLO: 		return "Hello";

/* MSPROXY_HELLO_ACK & MSPROXY_USERINFO have the same value (0x1000).	*/
/* So use the direction flag to determine which to use.			*/

		case MSPROXY_USERINFO:
			if ( direction == FROM_SERVER)
				return "Hello Acknowledge";
			else
				return "User Info";
		case MSPROXY_USERINFO_ACK: 	return "User Info Acknowledge";
		case MSPROXY_AUTH: 		return "Authentication";
		case MSPROXY_AUTH_1_ACK: 	return "Authentication Acknowledge";
		case MSPROXY_AUTH_2: 		return "Authentication 2";
		case MSPROXY_AUTH_2_ACK: 	return "Authentication 2 Acknowledge";
		case MSPROXY_RESOLVE: 		return "Resolve";
		case MSPROXY_RESOLVE_ACK: 	return "Resolve Acknowledge";
		case MSPROXY_BIND: 		return "Bind";
		case MSPROXY_TCP_BIND: 		return "TCP Bind";
		case MSPROXY_TCP_BIND_ACK: 	return "TCP Bind Acknowledge";
		case MSPROXY_LISTEN: 		return "Listen";
		case MSPROXY_BINDINFO: 		return "Bind Info";
		case MSPROXY_BINDINFO_ACK: 	return "Bind Info Acknowledge";
		case MSPROXY_CONNECT: 		return "Connect";
		case MSPROXY_CONNECT_ACK: 	return "Connect Acknowledge";
		case MSPROXY_UDPASSOCIATE: 	return "UDP Associate";
		case MSPROXY_UDP_BIND_REQ: 	return "UDP Bind";
		case MSPROXY_UDPASSOCIATE_ACK:	return "Bind or Associate Acknowledge";
		case MSPROXY_CONNECTED: 	return "Connected";
		case MSPROXY_SESSIONEND:	return "Session End";

		default:			return "Unknown";
	}
}



static void dissect_user_info_2(tvbuff_t *tvb, int offset,
	proto_tree *tree) {

/* decode the user, application, computer name  */


	int length;

	if ( tree) {
		length = tvb_strnlen( tvb, offset, 255);
		if (length == -1)
			return;
		proto_tree_add_text( tree, tvb, offset, length + 1,
			"User name: %.*s", length,
			tvb_get_ephemeral_string( tvb, offset, length));
		offset += length + 2;

		length = tvb_strnlen( tvb, offset, 255);
		if (length == -1)
			return;
		proto_tree_add_text( tree, tvb, offset, length + 1,
			"Application name: %.*s", length,
			tvb_get_ephemeral_string( tvb, offset, length));
		offset += length + 1;

		length = tvb_strnlen( tvb, offset, 255);
		if (length == -1)
			return;
		proto_tree_add_text( tree, tvb, offset, length + 1,
			"Client computer name: %.*s", length,
			tvb_get_ephemeral_string( tvb, offset, length));
	}
}



static void dissect_msproxy_request_1(tvbuff_t *tvb, int offset,
	proto_tree *tree) {

/* decode the request _1 structure  */


	offset += 182;

	dissect_user_info_2( tvb, offset, tree);

}



static void dissect_bind(tvbuff_t *tvb, int offset,
	 proto_tree *tree, hash_entry_t *conv_info) {

/* decode the bind request   */

	offset += 18;

	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_bindaddr, tvb, offset, 4,
			ENC_BIG_ENDIAN);
	offset += 4;

	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_bindport, tvb, offset, 2,
			 ENC_BIG_ENDIAN);
	offset += 6;

	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_clntport, tvb, offset, 2,
			 ENC_BIG_ENDIAN);
	offset += 2;

	conv_info->clnt_port = tvb_get_ntohs( tvb, offset);
	offset += 6;

	if ( tree){
		proto_tree_add_item( tree, hf_msproxy_boundport, tvb, offset, 2,
			ENC_BIG_ENDIAN);

		offset += 82;
		display_application_name( tvb, offset, tree);
	}
}



static void dissect_auth(tvbuff_t *tvb, int offset,
	proto_tree *tree) {

/* decode the authorization request  */

	if ( tree) {
		offset += 134;

		proto_tree_add_text( tree, tvb, offset, 7, "NTLMSSP signature: %.7s",
			tvb_get_ephemeral_string( tvb, offset, 7));
		offset += 7;
	}
}



static void dissect_tcp_bind(tvbuff_t *tvb, int offset,
	proto_tree *tree, hash_entry_t *conv_info) {

/* decode the bind packet. Set the protocol type in the conversation 	*/
/* information so the bind_info can use it to create the payload	*/
/* dissector.								*/


	conv_info->proto = PT_TCP;

	if ( tree) {
		offset += 6;

		proto_tree_add_item( tree, hf_msproxy_bind_id, tvb, offset, 4,
			ENC_BIG_ENDIAN);
		offset += 16;

		proto_tree_add_item( tree, hf_msproxy_boundport, tvb, offset, 2,
			ENC_BIG_ENDIAN);

		offset += 96;
		display_application_name( tvb, offset, tree);
	}
}


static void dissect_request_connect(tvbuff_t *tvb, int offset,
	proto_tree *tree, hash_entry_t *conv_info) {

/* decode the connect request, display  */

	conv_info->proto = PT_TCP;

	offset += 20;

	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_dstport, tvb, offset, 2,
			ENC_BIG_ENDIAN);

	conv_info->dst_port = tvb_get_ntohs( tvb, offset);
	offset += 2;

	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_dstaddr, tvb, offset, 4,
			ENC_BIG_ENDIAN);

	conv_info->dst_addr = tvb_get_ipv4( tvb, offset);

	offset += 12;

	conv_info->clnt_port = tvb_get_ntohs( tvb, offset);

	if ( tree){
		proto_tree_add_uint( tree, hf_msproxy_clntport, tvb, offset, 2,
			conv_info->clnt_port);

		offset += 84;

		display_application_name( tvb, offset, tree);
	}
}


static void dissect_bind_info_ack(tvbuff_t *tvb, int offset, proto_tree *tree) {

/* decode the client bind info ack  */


	if ( tree){
		offset += 6;

		proto_tree_add_item( tree, hf_msproxy_bind_id, tvb, offset, 4,
			ENC_BIG_ENDIAN);
		offset += 14;

		proto_tree_add_item( tree, hf_msproxy_dstport, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item( tree, hf_msproxy_dstaddr, tvb, offset, 4,
			ENC_BIG_ENDIAN);
		offset += 12;

		proto_tree_add_item( tree, hf_msproxy_server_int_port, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item( tree, hf_msproxy_server_ext_port, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item( tree, hf_msproxy_server_ext_addr, tvb,
			offset, 4, ENC_BIG_ENDIAN);

		offset += 78;
		display_application_name( tvb, offset, tree);
	}
}


static void dissect_request_resolve(tvbuff_t *tvb, int offset,
	proto_tree *tree) {

/* dissect the request resolve structure */
/* display a string with a length, characters encoding */
/* they are displayed under a tree with the name in Label variable */
/* return the length of the string and the length byte */

	proto_tree      *name_tree;
	proto_item      *ti;

	int length = tvb_get_guint8( tvb, offset);

	if ( tree){
  	 	ti = proto_tree_add_text(tree, tvb, offset, length + 1,
   		 	"Host Name: %.*s", length,
   		 	tvb_get_ephemeral_string( tvb, offset + 18, length));

		name_tree = proto_item_add_subtree(ti, ett_msproxy_name);

		proto_tree_add_text( name_tree, tvb, offset, 1, "Length: %d",
			length);

		++offset;
		offset += 17;

		proto_tree_add_text( name_tree, tvb, offset, length, "String: %s",
   		 	tvb_get_ephemeral_string( tvb, offset, length));
	}
}



static void dissect_udp_bind(tvbuff_t *tvb, int offset,
	proto_tree *tree, hash_entry_t *conv_info) {

/* Dissect the udp bind request.  Load the protocol id (PT_UDP) and the	*/
/* remote address so bind_info can use it to create conversation 	*/
/* dissector. 								*/

	conv_info->proto = PT_UDP;


	offset += 8;

	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_bind_id, tvb, offset, 4,
			ENC_BIG_ENDIAN);
	offset += 12;


	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_dstport, tvb, offset, 2,
			ENC_BIG_ENDIAN);
	offset += 2;

	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_dstaddr, tvb, offset, 4,
			ENC_BIG_ENDIAN);

	offset += 96;

	if ( tree)
		display_application_name( tvb, offset, tree);
}


static void dissect_udp_assoc(tvbuff_t *tvb, int offset,
	proto_tree *tree, hash_entry_t *conv_info) {

/* dissect the udp associate request. And load client port into 	*/
/* conversation data structure for later.				*/


	offset += 28;

	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_clntport, tvb, offset, 2,
			ENC_BIG_ENDIAN);

	conv_info->clnt_port = tvb_get_ntohs( tvb, offset);

	offset += 90;

	if ( tree)
		display_application_name( tvb, offset, tree);
}


static void dissect_msproxy_request(tvbuff_t *tvb,
	proto_tree *tree, hash_entry_t *conv_info) {

	int offset = 0;
	int cmd;

	if ( tree) {
		proto_tree_add_text( tree, tvb, offset, 4, "Client id: 0x%0x",
			tvb_get_letohl( tvb, offset));
		offset += 4;

		proto_tree_add_text( tree, tvb, offset, 4, "Version: 0x%04x",
			tvb_get_letohl( tvb, offset));
		offset += 4;

		proto_tree_add_text( tree, tvb, offset, 4, "Server id: 0x%0x",
			tvb_get_letohl( tvb, offset));
		offset += 4;

		proto_tree_add_text( tree, tvb, offset, 1, "Server ack: %u",
			tvb_get_guint8( tvb, offset));
		offset += 4;

		proto_tree_add_text( tree, tvb, offset, 1, "Sequence Number: %u",
			tvb_get_guint8( tvb, offset));
		offset += 8;

		proto_tree_add_text( tree, tvb, offset, 4, "RWSP signature: %.4s",
			tvb_get_ephemeral_string( tvb, offset, 4));
		offset += 12;
	}
	else 			/* no tree */
		offset += 36;

	cmd = tvb_get_ntohs( tvb, offset);

	if ( tree)
		proto_tree_add_uint_format( tree, hf_msproxy_cmd, tvb, offset, 2,
			cmd, "Command: 0x%02x (%s)", cmd,
			get_msproxy_cmd_name( cmd, FROM_CLIENT));

	offset += 2;

	switch (cmd){
		case MSPROXY_AUTH:
			dissect_auth( tvb, offset, tree);
			break;

		case MSPROXY_BIND:
			dissect_bind( tvb, offset, tree, conv_info);
			break;

		case MSPROXY_UDP_BIND_REQ:
			dissect_udp_bind( tvb, offset, tree, conv_info);
			break;

		case MSPROXY_AUTH_2:	/*$$ this is probably wrong place for this */
		case MSPROXY_TCP_BIND:
			dissect_tcp_bind( tvb, offset, tree, conv_info);
			break;

		case MSPROXY_RESOLVE:
			dissect_request_resolve( tvb, offset, tree);
			break;

		case MSPROXY_CONNECT:
		case MSPROXY_LISTEN:
			dissect_request_connect( tvb, offset, tree,
				conv_info);
			break;

		case MSPROXY_BINDINFO_ACK:
			dissect_bind_info_ack( tvb, offset, tree);
			break;

		case MSPROXY_HELLO:
		case MSPROXY_HELLO_2:
			dissect_msproxy_request_1( tvb, offset, tree);
			break;

		case  MSPROXY_UDPASSOCIATE:
			dissect_udp_assoc( tvb, offset, tree, conv_info);
			break;
		default:
			if ( tree)
				proto_tree_add_text( tree, tvb, offset, 0,
					"Unhandled request command (report this, please)");
	}
}



static void dissect_hello_ack(tvbuff_t *tvb, int offset, proto_tree *tree) {

/* decode the hello acknowledge packet  */

	offset += 60;

	if ( tree) {
		proto_tree_add_item( tree, hf_msproxy_serverport, tvb, offset, 2,
			 ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item( tree, hf_msproxy_serveraddr, tvb, offset, 4,
			ENC_BIG_ENDIAN);
		offset += 4;
	}
}



/* XXX - implement me */
static void dissect_user_info_ack(tvbuff_t *tvb _U_, int offset,
	proto_tree *tree _U_) {

/* decode the  response _2 structure  */

	offset += 18;

	offset += 2;

}



static void dissect_udpassociate_ack(tvbuff_t *tvb, int offset,
	proto_tree *tree) {

	offset += 6;

	if ( tree) {
		proto_tree_add_item( tree, hf_msproxy_bind_id, tvb, offset, 4,
			ENC_BIG_ENDIAN);
		offset += 14;

		proto_tree_add_item( tree, hf_msproxy_server_ext_port, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item( tree, hf_msproxy_server_ext_addr, tvb,
			offset, 4, ENC_BIG_ENDIAN);

		offset += 96;
		display_application_name( tvb, offset, tree);
	}
}



static void dissect_auth_1_ack(tvbuff_t *tvb, int offset,
	proto_tree *tree) {

	offset += 134;
	if ( tree) {
		proto_tree_add_text( tree, tvb, offset, 7, "NTLMSSP signature: %.7s",
			tvb_get_ephemeral_string( tvb, offset, 7));
		offset += 48;

		/* XXX - always 255? */
		proto_tree_add_text( tree, tvb, offset, 255, "NT domain: %.255s",
			tvb_get_ephemeral_string( tvb, offset, 255));
	}
}



/* XXX - implement me */
static void dissect_msproxy_response_4( tvbuff_t *tvb _U_, int offset,
	proto_tree *tree _U_) {

/* decode the response _4 structure  */

	offset += 134;
}



static void dissect_connect_ack( tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, hash_entry_t *conv_info) {

/* decode the connect ack packet  */
	offset += 20;

	if ( tree)
 		proto_tree_add_item( tree, hf_msproxy_server_int_port, tvb,
 			offset, 2, ENC_BIG_ENDIAN);


	conv_info->proto = PT_TCP;
	conv_info->server_int_port = tvb_get_ntohs( tvb, offset);
	offset += 2;

	if ( tree){
		proto_tree_add_item( tree, hf_msproxy_server_int_addr, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset += 14;

 		proto_tree_add_item( tree, hf_msproxy_server_ext_port, tvb,
 			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item( tree, hf_msproxy_server_ext_addr, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset += 80;

		display_application_name( tvb, offset, tree);
	}

	add_msproxy_conversation( pinfo, conv_info);
}



static void dissect_tcp_bind_ack( tvbuff_t *tvb, int offset, proto_tree *tree) {

/* decode the tcp bind */

	if ( tree) {
		offset += 6;

		proto_tree_add_item( tree, hf_msproxy_bind_id, tvb, offset, 4,
			ENC_BIG_ENDIAN);
		offset += 16;

 		proto_tree_add_uint( tree, hf_msproxy_server_int_port, tvb,
 			offset, 2, FALSE);
		offset += 6;

 		proto_tree_add_item( tree, hf_msproxy_server_ext_port, tvb,
 			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item( tree, hf_msproxy_server_ext_addr, tvb,
			offset, 4, ENC_BIG_ENDIAN);

		offset += 88;

		display_application_name( tvb, offset, tree);
	}
}



static void dissect_bind_info( tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, hash_entry_t *conv_info) {

/* decode the Bind info response from server */

	offset += 6;

	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_bind_id, tvb, offset, 4,
			ENC_BIG_ENDIAN);
	offset += 14;


	conv_info->dst_port = tvb_get_ntohs( tvb, offset);
	if ( tree)
 		proto_tree_add_uint( tree, hf_msproxy_dstport, tvb, offset, 2,
 			conv_info->dst_port);
	offset += 2;

	conv_info->dst_addr = tvb_get_ipv4( tvb, offset);
	if ( tree)
		proto_tree_add_item( tree, hf_msproxy_dstaddr, tvb, offset, 4,
			ENC_BIG_ENDIAN);
	offset += 12;

	conv_info->server_int_port = tvb_get_ntohs( tvb, offset);
	if ( tree)
 		proto_tree_add_uint( tree, hf_msproxy_server_int_port, tvb,
 			offset, 2, conv_info->server_int_port);
	offset += 4;

	if ( tree) {
 		proto_tree_add_item( tree, hf_msproxy_server_ext_port, tvb,
 			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item( tree, hf_msproxy_server_ext_addr, tvb,
			offset, 4, ENC_BIG_ENDIAN);

		offset += 78;
		display_application_name( tvb, offset, tree);

	}

	add_msproxy_conversation( pinfo, conv_info);
}



static void dissect_resolve(tvbuff_t *tvb, int offset, proto_tree *tree) {

/* dissect the  response resolve structure */
/* display a string with a length, characters encoding */
/* they are displayed under a tree with the name in Label variable */
/* return the length of the string and the length byte */

	if ( tree) {
		int addr_offset;

		addr_offset = tvb_get_guint8( tvb, offset);

		proto_tree_add_text( tree, tvb, offset, 1, "Address offset: %d",
			addr_offset);

		++offset;

		offset += 13;

		offset += addr_offset;

		proto_tree_add_item( tree, hf_msproxy_resolvaddr, tvb, offset, 4,
			ENC_BIG_ENDIAN);
	}
}



static void dissect_msproxy_response(tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *tree, hash_entry_t *conv_info) {

	int offset = 0;
	int cmd;

	if ( tree) {
		proto_tree_add_text( tree, tvb, offset, 4, "Client id: 0x%0x",
			tvb_get_letohl( tvb, offset));
		offset += 4;

		proto_tree_add_text( tree, tvb, offset, 4, "Version: 0x%04x",
			tvb_get_letohl( tvb, offset));
		offset += 4;

		proto_tree_add_text( tree, tvb, offset, 4, "Server id: 0x%04x",
			tvb_get_letohl( tvb, offset));
		offset += 4;

		proto_tree_add_text( tree, tvb, offset, 1, "Client ack: 0x%02x",
			tvb_get_guint8( tvb, offset));
		offset += 4;

		proto_tree_add_text( tree, tvb, offset, 1, "Sequence Number: 0x%02x",
			tvb_get_guint8( tvb, offset));

		offset += 8;

		proto_tree_add_text( tree, tvb, offset, 4, "RWSP signature: %.4s",
			tvb_get_ephemeral_string( tvb, offset, 4));

		offset += 12;
	}
	else
		offset += 36;

	cmd = tvb_get_ntohs( tvb, offset);

	if ( tree)
		proto_tree_add_uint_format( tree, hf_msproxy_cmd, tvb, offset, 2,
			cmd, "Command: 0x%02x (%s)", cmd,
			get_msproxy_cmd_name( cmd, FROM_SERVER));
	offset += 2;

	switch (cmd) {
		case MSPROXY_HELLO_ACK:
			dissect_hello_ack( tvb, offset, tree);
			break;

		case MSPROXY_USERINFO_ACK:
			dissect_user_info_ack( tvb, offset, tree);
			break;

		case MSPROXY_AUTH_1_ACK:
			dissect_auth_1_ack( tvb, offset, tree);
			break;

/* this also handle the MSPROXY_BIND_ACK ??? check this */

		case MSPROXY_UDPASSOCIATE_ACK:
			dissect_udpassociate_ack( tvb, offset, tree);
			break;

		case MSPROXY_AUTH_2_ACK:
		case MSPROXY_AUTH_2_ACK2:
			dissect_msproxy_response_4( tvb, offset, tree);
			break;

		case MSPROXY_TCP_BIND_ACK:
			dissect_tcp_bind_ack( tvb, offset, tree);
			break;

		case MSPROXY_CONNECT_ACK:
			dissect_connect_ack( tvb, offset, pinfo, tree,
				conv_info);
			break;

		case MSPROXY_BINDINFO:
			dissect_bind_info( tvb, offset, pinfo, tree, conv_info);
			break;

		case MSPROXY_RESOLVE_ACK:
			dissect_resolve( tvb, offset, tree);
			break;

		case MSPROXY_CONNECT_AUTHFAILED:
		case MSPROXY_BIND_AUTHFAILED:
			proto_tree_add_text( tree, tvb, offset, 0, "No know information (help wanted)");
			break;

		default:

			if (tree &&
			   (((cmd >> 8) ==  MSPROXY_CONNREFUSED) ||
			    ((cmd >> 12) ==  MSPROXY_CONNREFUSED)))
				proto_tree_add_text( tree, tvb, offset, 0,
					"No know information (help wanted)");

			else if ( tree)
				proto_tree_add_text( tree, tvb, offset, 0,
					"Unhandled response command (report this, please)");
	}


}



static void dissect_msproxy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {


	proto_tree      *msproxy_tree = NULL;
	proto_item      *ti;
	unsigned int	cmd;


	hash_entry_t *hash_info;
	conversation_t *conversation;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MSproxy");
	col_clear(pinfo->cinfo, COL_INFO);

	conversation = find_or_create_conversation(pinfo);

	hash_info = conversation_get_proto_data(conversation, proto_msproxy);
	if ( !hash_info) {
    		hash_info = se_alloc(sizeof(hash_entry_t));
		conversation_add_proto_data(conversation, proto_msproxy,
			hash_info);
	}

	if (check_col(pinfo->cinfo, COL_INFO)){

		cmd = tvb_get_ntohs( tvb, 36);

		if ( pinfo->srcport == UDP_PORT_MSPROXY)
			col_add_fstr( pinfo->cinfo, COL_INFO, "Server message: %s",
				get_msproxy_cmd_name( cmd, FROM_SERVER));
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "Client message: %s",
				get_msproxy_cmd_name( cmd, FROM_CLIENT));

	}

	if (tree) {				/* if proto tree, decode data */
    		ti = proto_tree_add_item( tree, proto_msproxy, tvb, 0, -1,
    				FALSE );

		msproxy_tree = proto_item_add_subtree(ti, ett_msproxy);
	}

	if ( pinfo->srcport == UDP_PORT_MSPROXY)
		dissect_msproxy_response( tvb, pinfo, msproxy_tree, hash_info);
	else
		dissect_msproxy_request( tvb, msproxy_tree, hash_info);
}



static void msproxy_reinit( void){

/* Do the cleanup work when a new pass through the packet list is	*/
/* performed. Reset the highest row seen counter			*/

	last_row = 0;
}



void
proto_register_msproxy( void){

/* Prep the msproxy protocol, for now, just register it	*/

	static gint *ett[] = {
		&ett_msproxy,
		&ett_msproxy_name
	};
  	static hf_register_info hf[] = {

                { &hf_msproxy_cmd,
                	{ "Command", "msproxy.command", FT_UINT16, BASE_DEC,
                		 NULL, 0x0, NULL, HFILL
                	}
		},

 		{ &hf_msproxy_dstaddr,
			{ "Destination Address", "msproxy.dstaddr", FT_IPv4, BASE_NONE, NULL,
			 	0x0, NULL, HFILL
			}
		},

		{ &hf_msproxy_srcport,
			{ "Source Port", "msproxy.srcport", FT_UINT16,
				BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_msproxy_dstport,
			{ "Destination Port", "msproxy.dstport", FT_UINT16,
				BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_msproxy_clntport,
			{ "Client Port",	"msproxy.clntport", FT_UINT16,
				BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
 		{ &hf_msproxy_server_ext_addr,
			{ "Server External Address", "msproxy.server_ext_addr", FT_IPv4, BASE_NONE, NULL,
			 	0x0, NULL, HFILL
			}
		},

		{ &hf_msproxy_server_ext_port,
			{ "Server External Port",	"msproxy.server_ext_port", FT_UINT16,
				BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},

 		{ &hf_msproxy_server_int_addr,
			{ "Server Internal Address", "msproxy.server_int_addr", FT_IPv4, BASE_NONE, NULL,
			 	0x0, NULL, HFILL
			}
		},

		{ &hf_msproxy_server_int_port,
			{ "Server Internal Port",	"msproxy.server_int_port", FT_UINT16,
				BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_msproxy_serverport,
			{ "Server Port",	"msproxy.serverport", FT_UINT16,
				BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_msproxy_bindport,
			{ "Bind Port",	"msproxy.bindport", FT_UINT16,
				BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_msproxy_boundport,
			{ "Bound Port",	"msproxy.boundport", FT_UINT16,
				BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
 		{ &hf_msproxy_serveraddr,
			{ "Server Address", "msproxy.serveraddr", FT_IPv4, BASE_NONE, NULL,
			 	0x0, NULL, HFILL
			}
		},
 		{ &hf_msproxy_bindaddr,
			{ "Destination", "msproxy.bindaddr", FT_IPv4, BASE_NONE, NULL,
			 	0x0, NULL, HFILL
			}
		},
		{ &hf_msproxy_bind_id,
			{ "Bound Port Id",	"msproxy.bindid", FT_UINT32,
				BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
 		{ &hf_msproxy_resolvaddr,
			{ "Address", "msproxy.resolvaddr", FT_IPv4, BASE_NONE, NULL,
			 	0x0, NULL, HFILL
			}
		}

	};

   	proto_msproxy = proto_register_protocol( "MS Proxy Protocol",
	    "MS Proxy", "msproxy");

	proto_register_field_array(proto_msproxy, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_init_routine( &msproxy_reinit);	/* register re-init routine */

	msproxy_sub_handle = create_dissector_handle(msproxy_sub_dissector,
	    proto_msproxy);
}


void
proto_reg_handoff_msproxy(void) {

	/* dissector install routine */

	dissector_handle_t msproxy_handle;

	msproxy_handle = create_dissector_handle(dissect_msproxy,
	    proto_msproxy);
	dissector_add_uint("udp.port", UDP_PORT_MSPROXY, msproxy_handle);
}
