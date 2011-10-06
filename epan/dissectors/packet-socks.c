/* packet-socks.c
 * Routines for socks versions 4 &5  packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 * Copyright 2008, Jelmer Vernooij <jelmer@samba.org>
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
 *
 * The Version 4 decode is based on SOCKS4.protocol and SOCKS4A.protocol.
 * The Version 5 decoder is based upon rfc-1928
 * The Version 5 User/Password authentication is based on rfc-1929.
 *
 * See
 *
 *	http://www.socks.permeo.com/TechnicalResources/ProtocolDocuments.asp
 *
 * for these and other documents.  See
 *
 *	http://www.socks.nec.com/protocol/socks4a.protocol
 *
 * for information on SOCKS version 4a.
 *
 * Revisions:
 *
 * 2003-09-18 JCFoster Fixed problem with socks tunnel in socks tunnel
 *			causing heap overflow because of an infinite loop
 *			where the socks dissect was call over and over.
 *
 *			Also remove some old code marked with __JUNK__
 *
 * 2001-01-08 JCFoster Fixed problem with NULL pointer for hash data.
 *			Now test and exit if hash_info is null.
 */

/* Possible enhancements -
 *
 * Add GSS-API authentication per rfc-1961
 * Add CHAP authentication
 * Decode FLAG bits per
 * 	http://archive.socks.permeo.com/draft/draft-ietf-aft-socks-pro-v5-04.txt
 * In call_next_dissector, could load the destination address into
 * 	pinfo->src or pinfo->dst structure before calling next dissector.
 * remove display_string or at least make it use protocol identifiers
 * socks_hash_entry_t needs to handle V5 address type and domain names
*/




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
#include <epan/strutil.h>


#define compare_packet(X) (X == (pinfo->fd->num))
#define get_packet_ptr	(pinfo->fd->num)
#define row_pointer_type guint32

#define TCP_PORT_SOCKS 1080


/**************** Socks commands ******************/

#define CONNECT_COMMAND		1
#define BIND_COMMAND		2
#define UDP_ASSOCIATE_COMMAND	3
#define PING_COMMAND		0x80
#define TRACERT_COMMAND		0x81


/********** V5 Authentication methods *************/

#define NO_AUTHENTICATION 	0
#define GSS_API_AUTHENTICATION 	1
#define USER_NAME_AUTHENTICATION 	2
#define CHAP_AUTHENTICATION 	3
#define AUTHENTICATION_FAILED 	0xff

/* 2003-09-18 JCFoster Fixed problem with socks tunnel in socks tunnel */

static int in_socks_dissector_flag = 0;		/* set to 1 to avoid recursive overflow */

/*********** Header field identifiers *************/

static int proto_socks = -1;

static int ett_socks = -1;
static int ett_socks_auth = -1;
static int ett_socks_name = -1;

static int hf_socks_ver = -1;
static int hf_socks_ip_dst = -1;
static int hf_socks_ip6_dst = -1;
static int hf_user_name = -1;
static int hf_gssapi_payload = -1;
static int hf_gssapi_command = -1;
static int hf_gssapi_length = -1;
static int hf_v4a_dns_name = -1;
static int hf_socks_dstport = -1;
static int hf_socks_cmd = -1;
static int hf_socks_results = -1;
static int hf_socks_results_4 = -1;
static int hf_socks_results_5 = -1;


/************* Dissector handles ***********/

static dissector_handle_t socks_handle;
static dissector_handle_t socks_udp_handle;

/************* State Machine names ***********/

enum SockState {
	None = 0,
	Connecting,
	V4UserNameWait,
	V4NameWait,
	V5Command,
	V5Reply,
	V5BindReply,
	UserNameAuth,
	UserNameAuthReply,
	GssApiAuth,
	GssApiAuthReply,
	Done
};



typedef struct {
	int		state;
	int		version;
	int		command;
	int		grant;
	guint32 	port;
	guint32 	udp_port;
	guint32 	udp_remote_port;

	int		connect_offset;
	row_pointer_type 	v4_name_row;
	row_pointer_type	v4_user_name_row;
	row_pointer_type	connect_row;
	row_pointer_type	cmd_reply_row;
	row_pointer_type	bind_reply_row;
	row_pointer_type	command_row;
	row_pointer_type 	auth_method_row;
	row_pointer_type	user_name_auth_row;
	row_pointer_type	auth_version;
	row_pointer_type	gssapi_auth_row;
	row_pointer_type	gssapi_auth_reply_row;
	row_pointer_type	gssapi_auth_failure_row;
	guint32 start_done_row;

	guint32	dst_addr;	/* this needs to handle IPv6 */
}socks_hash_entry_t;




static const char *address_type_table[] = {
	"Unknown",
	"IPv4",
	"Unknown",
	"Domain Name",
	"IPv6",
	"Unknown"
};


/* String table for the V4 reply status messages */

static const value_string reply_table_v4[] = {
	{90, "Granted"},
	{91, "Rejected or Failed"},
	{92, "Rejected because SOCKS server cannot connect to identd on the client"},
	{93, "Rejected because the client program and identd report different user-ids"},
	{0, NULL}
};

/* String table for the V5 reply status messages */

static const value_string reply_table_v5[] = {
	{0, "Succeeded"},
	{1, "General SOCKS server failure"},
	{2, "Connection not allowed by ruleset"},
	{3, "Network unreachable"},
	{4, "Host unreachable"},
	{5, "Connection refused"},
	{6, "TTL expired"},
	{7, "Command not supported"},
	{8, "Address type not supported"},
	{0, NULL},
};

static const value_string cmd_strings[] = {
	{0, "Unknown"},
	{1, "Connect"},
	{2, "Bind"},
	{3, "UdpAssociate"},
	{0x80, "Ping"},
	{0x81, "Traceroute"},
	{0, NULL}
};

static const value_string gssapi_command_table[] = {
	{ 1, "Authentication" },
	{ 0xFF, "Failure" },
	{ 0, NULL }
};


/************************* Support routines ***************************/


static int display_string(tvbuff_t *tvb, int offset,
	proto_tree *tree, const char *label){

/* display a string with a length, characters encoding */
/* they are displayed under a tree with the name in Label variable */
/* return the length of the string and the length byte */


	proto_tree      *name_tree;
	proto_item      *ti;

	char temp[ 256];
	int length = tvb_get_guint8(tvb, offset);

	tvb_memcpy(tvb, (guint8 *)temp, offset+1, length);
	temp[ length ] = '\0';

   	ti = proto_tree_add_text(tree, tvb, offset, length + 1,
   		"%s: %s" , label, temp);


	name_tree = proto_item_add_subtree(ti, ett_socks_name);

	proto_tree_add_text( name_tree, tvb, offset, 1, "Length: %u", length);

	++offset;

	proto_tree_add_text( name_tree, tvb, offset, length, "String: %s", temp);

	return length + 1;
}



static const char *get_auth_method_name( guint Number){

/* return the name of the authenication method */

	if ( Number == 0) return "No authentication";
	if ( Number == 1) return "GSSAPI";
	if ( Number == 2) return "Username/Password";
	if ( Number == 3) return "Chap";
	if (( Number >= 4) && ( Number <= 0x7f))return "IANA assigned";
	if (( Number >= 0x80) && ( Number <= 0xfe)) return "private method";
	if ( Number == 0xff) return "no acceptable method";

	/* shouldn't reach here */

	return "Bad method number (not 0-0xff)";
}


static const char *get_command_name( guint Number){

/* return the name of the command as a string */

	if ( Number == 0) return "Unknown";
	if ( Number == 1) return "Connect";
	if ( Number == 2) return "Bind";
	if ( Number == 3) return "UdpAssociate";
	if ( Number == 0x80) return "Ping";
	if ( Number == 0x81) return "Traceroute";
	return "Unknown";
}


static int display_address(tvbuff_t *tvb, int offset, proto_tree *tree) {

/* decode and display the v5 address, return offset of next byte */

	int a_type = tvb_get_guint8(tvb, offset);

	proto_tree_add_text( tree, tvb, offset, 1,
			"Address Type: %d (%s)", a_type,
			address_type_table[ MIN( (guint) a_type,
				array_length( address_type_table)-1) ]);

	++offset;

	if ( a_type == 1){		/* IPv4 address */
		proto_tree_add_item( tree, hf_socks_ip_dst, tvb, offset,
					4, FALSE);
		offset += 4;
	}
	else if ( a_type == 3){	/* domain name address */

		offset += display_string(tvb, offset, tree,
			"Remote name");
	}
	else if ( a_type == 4){	/* IPv6 address */
		proto_tree_add_item( tree, hf_socks_ip6_dst, tvb, offset,
				16, FALSE);
		offset += 16;
	}

	return offset;
}


static int get_address_v5(tvbuff_t *tvb, int offset,
	socks_hash_entry_t *hash_info) {

/* decode the v5 address and return offset of next byte */
/*XXX this needs to handle IPV6 and domain name addresses */


	int a_type = tvb_get_guint8(tvb, offset++);

	if ( a_type == 1){ 		/* IPv4 address */

	   	if ( hash_info)
	   		hash_info->dst_addr = tvb_get_ipv4(tvb, offset);
		offset += 4;
	}

	else if ( a_type == 4) 		/* IPv6 address */
		offset += 16;

	else if ( a_type == 3)	/* domain name address */
		offset += tvb_get_guint8(tvb, offset) + 1;
	return offset;
}


/********************* V5 UDP Associate handlers ***********************/

static void
socks_udp_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

/* Conversation dissector called from UDP dissector. Decode and display */
/* the socks header, the pass the rest of the data to the udp port 	*/
/* decode routine to  handle the payload.				*/

	int offset = 0;
	guint32 *ptr;
	socks_hash_entry_t *hash_info;
	conversation_t *conversation;
	proto_tree      *socks_tree;
	proto_item      *ti;

	conversation = find_conversation( pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0);

	DISSECTOR_ASSERT( conversation);	/* should always find a conversation */

	hash_info = conversation_get_proto_data(conversation, proto_socks);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Socks");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Version: 5, UDP Associated packet");

	if ( tree) {
    		ti = proto_tree_add_protocol_format( tree, proto_socks, tvb,
    			offset, -1, "Socks" );

		socks_tree = proto_item_add_subtree(ti, ett_socks);

       		proto_tree_add_text( socks_tree, tvb, offset, 2, "Reserved");
		offset += 2;

       		proto_tree_add_text( socks_tree, tvb, offset, 1, "Fragment Number: %u", tvb_get_guint8(tvb, offset));
		++offset;


		offset = display_address( tvb, offset, socks_tree);
		hash_info->udp_remote_port = tvb_get_ntohs(tvb, offset);

		proto_tree_add_uint( socks_tree, hf_socks_dstport, tvb,
			offset, 2, hash_info->udp_remote_port);

		offset += 2;
	}
	else { 		/* no tree, skip past the socks header */
		offset += 3;
		offset = get_address_v5( tvb, offset, 0) + 2;
	}


/* set pi src/dst port and call the udp sub-dissector lookup */

	if ( pinfo->srcport == hash_info->port)
       		ptr = &pinfo->destport;
   	else
    		ptr = &pinfo->srcport;

        *ptr = hash_info->udp_remote_port;

	decode_udp_ports( tvb, offset, pinfo, tree, pinfo->srcport, pinfo->destport, -1);

        *ptr = hash_info->udp_port;

}


static void
new_udp_conversation( socks_hash_entry_t *hash_info, packet_info *pinfo){

	conversation_t *conversation = conversation_new( pinfo->fd->num, &pinfo->src, &pinfo->dst,  PT_UDP,
			hash_info->udp_port, hash_info->port, 0);

	DISSECTOR_ASSERT( conversation);

	conversation_add_proto_data(conversation, proto_socks, hash_info);
	conversation_set_dissector(conversation, socks_udp_handle);
}




/**************** Protocol Tree Display routines  ******************/

static void
display_socks_v4(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, socks_hash_entry_t *hash_info) {


/* Display the protocol tree for the V4 version. This routine uses the	*/
/* stored conversation information to decide what to do with the row.	*/
/* Per packet information would have been better to do this, but we	*/
/* didn't have that when I wrote this. And I didn't expect this to get	*/
/* so messy.								*/


	proto_item *hidden_item;
	guint command;
	unsigned char ipaddr[4];
	guint username_len, domainname_len;

					/* Display command from client */
	if (compare_packet( hash_info->connect_row)){

		proto_tree_add_text( tree, tvb, offset, 1,
				"Version: %u", hash_info->version);
		++offset;
		command = tvb_get_guint8(tvb, offset);

		proto_tree_add_text( tree, tvb, offset, 1,
			"Command: %u (%s)", command,
				get_command_name( command));
		++offset;

						/* Do remote port	*/
		proto_tree_add_item( tree, hf_socks_dstport, tvb, offset, 2,
				ENC_BIG_ENDIAN);
		offset += 2;

						/* Do destination address */
		tvb_memcpy(tvb, ipaddr, offset, 4);
		proto_tree_add_item( tree, hf_socks_ip_dst, tvb, offset,
				4, FALSE);

		offset += 4;

/*XXX check this, needs to do length checking	 */
/* Should perhaps do TCP reassembly as well */
		if ( tvb_offset_exists(tvb, offset)) {
						/* display user name 	*/
			username_len = tvb_strsize(tvb, offset);
			proto_tree_add_item( tree, hf_user_name, tvb, offset,
				username_len, FALSE);
			offset += username_len;
			if ( ipaddr[0] == 0 && ipaddr[1] == 0 &&
			     ipaddr[2] == 0 && ipaddr[3] != 0) {
			     	/* 0.0.0.x , where x!=0 means v4a support */
			     	domainname_len = tvb_strsize(tvb, offset);
				proto_tree_add_item( tree, hf_v4a_dns_name,
					tvb, offset, domainname_len,
					FALSE);
			}
		}

	}
				/*Display command response from server*/

	else if ( compare_packet( hash_info->cmd_reply_row)){

		proto_tree_add_item( tree, hf_socks_ver, tvb, offset, 1,
				ENC_BIG_ENDIAN);
		++offset;
						/* Do results code	*/
		proto_tree_add_item( tree, hf_socks_results_4, tvb, offset, 1, ENC_BIG_ENDIAN);
		hidden_item = proto_tree_add_item(tree, hf_socks_results, tvb, offset, 1, ENC_BIG_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(hidden_item);

		++offset;

						/* Do remote port	*/
		proto_tree_add_item( tree, hf_socks_dstport, tvb, offset, 2,
				ENC_BIG_ENDIAN);
		offset += 2;
						/* Do remote address	*/
		proto_tree_add_item( tree, hf_socks_ip_dst, tvb, offset, 4,
			FALSE);
	}

	else if ( compare_packet( hash_info->v4_user_name_row)){

/*XXX check this, needs to do length checking	 */
/* Should perhaps do TCP reassembly as well */
		if ( tvb_offset_exists(tvb, offset)) {
			proto_tree_add_text( tree, tvb, offset,
				tvb_strsize(tvb, offset),
				"User Name: %s", tvb_get_ephemeral_string(tvb, offset, -1));
		}
	}
}


static void
display_socks_v5(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, socks_hash_entry_t *hash_info) {

/* Display the protocol tree for the version. This routine uses the	*/
/* stored conversation information to decide what to do with the row.	*/
/* Per packet information would have been better to do this, but we	*/
/* didn't have that when I wrote this. And I didn't expect this to get	*/
/* so messy.								*/

	unsigned int i, command;
	guint temp;
	const char *AuthMethodStr;
	guint8 auth_status;

	proto_tree_add_item( tree, hf_socks_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
	++offset;

	if (compare_packet( hash_info->connect_row)){

		proto_tree      *AuthTree;
		proto_item      *ti;

		temp = tvb_get_guint8(tvb, offset);	/* Get Auth method count */
							/* build auth tree */
		ti = proto_tree_add_text( tree, tvb, offset, -1,
				"Client Authentication Methods");

		AuthTree = proto_item_add_subtree(ti, ett_socks_auth);

		proto_tree_add_text( AuthTree, tvb, offset, 1,
				"Count: %u", temp);
		++offset;

		for( i = 0; i  < temp; ++i) {

			AuthMethodStr = get_auth_method_name(
				tvb_get_guint8( tvb, offset));
			proto_tree_add_text( AuthTree, tvb, offset, 1,
				"Method[%u]: %u (%s)", i,
				tvb_get_guint8( tvb, offset), AuthMethodStr);
			++offset;
		}
		proto_item_set_end( ti, tvb, offset);
		return;
	}					/* Get accepted auth method */
	else if (compare_packet( hash_info->auth_method_row)) {

		proto_tree_add_text( tree, tvb, offset, 1,
			"Accepted Auth Method: 0x%0x (%s)", tvb_get_guint8( tvb, offset),
				get_auth_method_name( tvb_get_guint8( tvb, offset)));

		return;
	}					/* handle user/password auth */
	else if (compare_packet( hash_info->user_name_auth_row)) {

						/* process user name	*/
		offset += display_string( tvb, offset, tree,
				"User name");
						/* process password	*/
		offset += display_string( tvb, offset, tree,
				"Password");
	}
					/* command to the server */
					/* command response from server */
	else if (compare_packet( hash_info->auth_version)) {
		auth_status = tvb_get_guint8(tvb, offset);
		if(auth_status != 0)
			proto_tree_add_text( tree, tvb, offset, 1, "Status: %u (failure)", auth_status);
		else
			proto_tree_add_text( tree, tvb, offset, 1, "Status: success");
		offset ++;
	}
	else if (compare_packet( hash_info->gssapi_auth_row)) {
		guint16 len;
		proto_tree_add_item( tree, hf_gssapi_command, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item( tree, hf_gssapi_length, tvb, offset+1, 2, ENC_BIG_ENDIAN);
		len = tvb_get_ntohs(tvb, offset+1);
		if (len > 0)
			proto_tree_add_item( tree, hf_gssapi_payload, tvb, offset+3, len, ENC_NA);
	}
	else if (compare_packet( hash_info->gssapi_auth_failure_row)) {
		proto_tree_add_item( tree, hf_gssapi_command, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	else if (compare_packet( hash_info->gssapi_auth_reply_row)) {
		guint16 len;
		proto_tree_add_item( tree, hf_gssapi_command, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item( tree, hf_gssapi_length, tvb, offset+1, 2, ENC_BIG_ENDIAN);
		len = tvb_get_ntohs(tvb, offset+1);
		if (len > 0)
			proto_tree_add_item( tree, hf_gssapi_payload, tvb, offset+3, len, ENC_NA);
	}
	else if ((compare_packet( hash_info->command_row)) ||
	         (compare_packet( hash_info->cmd_reply_row)) ||
	         (compare_packet( hash_info->bind_reply_row))){

		command = tvb_get_guint8(tvb, offset);

		if (compare_packet( hash_info->command_row))
			proto_tree_add_uint( tree, hf_socks_cmd, tvb, offset, 1,
			    command);

		else {
			proto_item *hidden_item;
			proto_tree_add_item( tree, hf_socks_results_5, tvb, offset, 1, ENC_BIG_ENDIAN);
			hidden_item = proto_tree_add_item(tree, hf_socks_results, tvb, offset, 1, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
		}

		++offset;

		proto_tree_add_text( tree, tvb, offset, 1,
			"Reserved: 0x%0x (should = 0x00)", tvb_get_guint8(tvb, offset));
		++offset;

		offset = display_address(tvb, offset, tree);
/*XXX Add remote port for search somehow */
						/* Do remote port	*/
		proto_tree_add_text( tree, tvb, offset, 2,
				"%sPort: %u",
				(compare_packet( hash_info->bind_reply_row) ?
					"Remote Host " : ""),
				 tvb_get_ntohs(tvb, offset));
	}
}



/**************** Decoder State Machines ******************/


static guint
state_machine_v4( socks_hash_entry_t *hash_info, tvbuff_t *tvb,
	int offset, packet_info *pinfo) {

/* Decode V4 protocol.  This is done on the first pass through the 	*/
/* list.  Based upon the current state, decode the packet and determine	*/
/* what the next state should be.  If we had per packet information, 	*/
/* this would be the place to load them up.				*/

	if ( hash_info->state == None) {		/* new connection */

		col_append_str(pinfo->cinfo, COL_INFO, " Connect to server request");

		hash_info->state = Connecting;	/* change state		*/

		hash_info->command = tvb_get_guint8(tvb, offset + 1);
						/* get remote port	*/
		if ( hash_info->command == CONNECT_COMMAND)
			hash_info->port =  tvb_get_ntohs(tvb, offset + 2);
						/* get remote address	*/

		hash_info->dst_addr = tvb_get_ipv4(tvb, offset + 4);

						/* save the packet pointer */
		hash_info->connect_row = get_packet_ptr;

						/* skip past this stuff	*/
		hash_info->connect_offset = offset + 8;

		offset += 8;

		if ( !tvb_offset_exists(tvb, offset)) {	/* if no user name */
							/* change state */
			hash_info->state = V4UserNameWait;
			/*
			 * XXX - add 1, or leave it alone?
			 * We were adding "strlen(...) + 1".
			 */
			hash_info->connect_offset += 1;
		} else {
			/*
			 * Add in the length of the user name.
			 * XXX - what if the user name is split between
			 * TCP segments?
			 */
			hash_info->connect_offset += tvb_strsize(tvb, offset);
		}

		if ( !hash_info->dst_addr){ 		/* if no dest address */
							/* if more data */
			if ( tvb_offset_exists(tvb, hash_info->connect_offset)) {
/*XXX copy remote name here ??? */
				hash_info->state = Connecting;
			}
			else
				hash_info->state = V4NameWait;
						}
						/* waiting for V4 user name */
	}else if ( hash_info->state == V4UserNameWait){

		col_append_str(pinfo->cinfo, COL_INFO, " Connect Request (User name)");

		hash_info->v4_user_name_row = get_packet_ptr;
/*XXX may need to check for domain name here */
		hash_info->state = Connecting;
	}
					/* waiting for V4 domain name	*/
	else if ( hash_info->state == V4NameWait){

		hash_info->v4_name_row = get_packet_ptr;
		hash_info->state = Connecting;

	}
	else if ( hash_info->state == Connecting){

		col_append_str(pinfo->cinfo, COL_INFO, " Connect Response");

						/* save packet pointer 	*/
		hash_info->cmd_reply_row = get_packet_ptr;
		hash_info->state = Done;		/* change state		*/
		offset = offset + 8;
	}

	return offset;
}



static void
state_machine_v5( socks_hash_entry_t *hash_info, tvbuff_t *tvb,
	int offset, packet_info *pinfo) {

/* Decode V5 protocol.  This is done on the first pass through the 	*/
/* list.  Based upon the current state, decode the packet and determine	*/
/* what the next state should be.  If we had per packet information, 	*/
/* this would be the place to load them up.				*/


	int temp;

	if ( hash_info->state == None) {

		col_append_str(pinfo->cinfo, COL_INFO, " Connect to server request");

		hash_info->state = Connecting;	/* change state		*/
		hash_info->connect_row = get_packet_ptr;

		temp = tvb_get_guint8(tvb, offset + 1);
						/* skip past auth methods */
		offset = hash_info->connect_offset = offset + 1 + temp;
	}
	else if ( hash_info->state == Connecting){

		guint AuthMethod = tvb_get_guint8(tvb, offset + 1);

		col_append_str(pinfo->cinfo, COL_INFO, " Connect to server response");

		hash_info->auth_method_row = get_packet_ptr;

		if ( AuthMethod == NO_AUTHENTICATION)
			hash_info->state = V5Command;

		else if ( AuthMethod == USER_NAME_AUTHENTICATION)
			hash_info->state = UserNameAuth;

		else if ( AuthMethod == GSS_API_AUTHENTICATION)
			hash_info->state = GssApiAuth;

		else	hash_info->state = Done;	/*Auth failed or error*/

	}

	else if ( hash_info->state == V5Command) {	/* Handle V5 Command */

		/** ?? guint temp; **/

		hash_info->command = tvb_get_guint8(tvb, offset + 1); /* get command */

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " Command Request - %s",
				get_command_name(hash_info->command));

		hash_info->state = V5Reply;
		hash_info->command_row = get_packet_ptr;

		offset += 3;			/* skip to address type */

		offset = get_address_v5(tvb, offset, hash_info);

		/** temp = tvb_get_guint8(tvb, offset);  XX: what was this for ? **/

		if (( hash_info->command == CONNECT_COMMAND) ||
		    ( hash_info->command == UDP_ASSOCIATE_COMMAND))
						/* get remote port	*/
			hash_info->port =  tvb_get_ntohs(tvb, offset);
	}

	else if ( hash_info->state == V5Reply) {	/* V5 Command Reply */


		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " Command Response - %s",
				get_command_name(hash_info->command));

		hash_info->cmd_reply_row = get_packet_ptr;

		if (( hash_info->command == CONNECT_COMMAND) ||
		    (hash_info->command == PING_COMMAND) ||
		    (hash_info->command == TRACERT_COMMAND))
			hash_info->state = Done;

		else if ( hash_info->command == BIND_COMMAND)
			hash_info->state = V5BindReply;

		else if ( hash_info->command == UDP_ASSOCIATE_COMMAND){
			offset += 3;		/* skip to address type */
			offset = get_address_v5(tvb, offset, hash_info);

	/* save server udp port and create udp conversation */
			hash_info->udp_port =  tvb_get_ntohs(tvb, offset);

			if (!pinfo->fd->flags.visited)
				new_udp_conversation( hash_info, pinfo);

/*XXX may need else statement to handle unknowns and generate error message */

		}
	}
	else if ( hash_info->state == V5BindReply) {	/* V5 Bind Second Reply */

		col_append_str(pinfo->cinfo, COL_INFO, " Command Response: Bind remote host info");

		hash_info->bind_reply_row = get_packet_ptr;
		hash_info->state = Done;
	}
	else if ( hash_info->state == UserNameAuth) {	/* Handle V5 User Auth*/
		col_append_str(pinfo->cinfo, COL_INFO,
				" User authentication request");

		hash_info->user_name_auth_row = get_packet_ptr;
		hash_info->state = UserNameAuthReply;

	}
	else if ( hash_info->state == GssApiAuth) {
		col_append_str(pinfo->cinfo, COL_INFO,
						   " GSSAPI Authentication request");
		hash_info->gssapi_auth_row = get_packet_ptr;
		hash_info->state = GssApiAuthReply;
	}
	else if ( hash_info->state == GssApiAuthReply) {
		if (tvb_get_guint8(tvb, offset+1) == 0xFF) {
			col_append_str(pinfo->cinfo, COL_INFO,
							   " GSSAPI Authentication failure");
			hash_info->gssapi_auth_failure_row = get_packet_ptr;
		} else {
			col_append_str(pinfo->cinfo, COL_INFO,
							   " GSSAPI Authentication reply");
			if (tvb_get_ntohs(tvb, offset+2) == 0)
				hash_info->state = V5Command;
			else
				hash_info->state = GssApiAuth;
			hash_info->gssapi_auth_reply_row = get_packet_ptr;
		}
	}
	else if ( hash_info->state == UserNameAuthReply){	/* V5 User Auth reply */
		hash_info->auth_version = get_packet_ptr;
		col_append_str(pinfo->cinfo, COL_INFO, " User authentication reply");
		hash_info->state = V5Command;
	}
}



static void
display_ping_and_tracert(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, socks_hash_entry_t *hash_info) {

/* Display the ping/trace_route conversation */


       	const guchar    *data, *dataend;
       	const guchar   *lineend, *eol;
       	int             linelen;

					/* handle the end command */
       	if ( pinfo->destport == TCP_PORT_SOCKS){
		col_append_str(pinfo->cinfo, COL_INFO, ", Terminate Request");

		if ( tree)
  			proto_tree_add_text(tree, tvb, offset, 1,
   				(hash_info->command  == PING_COMMAND) ?
				"Ping: End command" :
	   			"Traceroute: End command");
	}
       	else{ 		/* display the PING or Traceroute results */
		col_append_str(pinfo->cinfo, COL_INFO, ", Results");

		if ( tree){
			proto_tree_add_text(tree, tvb, offset, -1,
   				(hash_info->command  == PING_COMMAND) ?
   				"Ping Results:" :
   				"Traceroute Results");

  	      		data = tvb_get_ptr(tvb, offset, -1);
        		dataend = data + tvb_length_remaining(tvb, offset);

       	        	while (data < dataend) {

              			lineend = find_line_end(data, dataend, &eol);
                		linelen = (int)(lineend - data);

       		                proto_tree_add_text( tree, tvb, offset, linelen,
       		                	"%s", format_text(data, linelen));
               		        offset += linelen;
                       		data = lineend;
                       	}
		}
	}
}



static void clear_in_socks_dissector_flag(void *dummy _U_)
{
	in_socks_dissector_flag = 0; /* avoid recursive overflow */
}

static void call_next_dissector(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, proto_tree *socks_tree,
	socks_hash_entry_t *hash_info)
{

/* Display the results for PING and TRACERT extensions or		*/
/* Call TCP dissector for the port that was passed during the	    	*/
/* connect process  						     	*/
/* Load pointer to pinfo->XXXport depending upon the direction,		*/
/* change pinfo port to the remote port, call next dissecotr to decode	*/
/* the payload, and restore the pinfo port after that is done.		*/

	guint32 *ptr;
	struct tcpinfo *tcpinfo = pinfo->private_data;
	guint16 save_can_desegment;
	struct tcp_analysis *tcpd=NULL;

	tcpd=get_tcp_conversation_data(NULL,pinfo);

 	if (( hash_info->command  == PING_COMMAND) ||
 	    ( hash_info->command  == TRACERT_COMMAND))

		display_ping_and_tracert(tvb, offset, pinfo, tree, hash_info);

   	else {		/* call the tcp port decoder to handle the payload */

/*XXX may want to load dest address here */

 		if ( pinfo->destport  == TCP_PORT_SOCKS)
        		ptr = &pinfo->destport;
	   	else
        		ptr = &pinfo->srcport;

	        *ptr = hash_info->port;

/* 2003-09-18 JCFoster Fixed problem with socks tunnel in socks tunnel */

		in_socks_dissector_flag = 1; /* avoid recursive overflow */
		CLEANUP_PUSH(clear_in_socks_dissector_flag, NULL);

		save_can_desegment = pinfo->can_desegment;
		pinfo->can_desegment = pinfo->saved_can_desegment;
		dissect_tcp_payload(tvb, pinfo, offset, tcpinfo->seq,
		    tcpinfo->nxtseq, pinfo->srcport, pinfo->destport,
		    tree, socks_tree, tcpd);
		pinfo->can_desegment = save_can_desegment;

		CLEANUP_CALL_AND_POP;

	        *ptr = TCP_PORT_SOCKS;
	}
}



static void
dissect_socks(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	int 		offset = 0;
	proto_tree      *socks_tree = NULL;
	proto_item      *ti;
	socks_hash_entry_t *hash_info;
	conversation_t *conversation;

/* 2003-09-18 JCFoster Fixed problem with socks tunnel in socks tunnel */

	/* avoid recursive overflow */

	if ( in_socks_dissector_flag) {
		return;
	}

	conversation = find_or_create_conversation(pinfo);
	hash_info = conversation_get_proto_data(conversation,proto_socks);
	if ( !hash_info){
    		hash_info = se_alloc(sizeof(socks_hash_entry_t));
		hash_info->start_done_row = G_MAXINT;
    		hash_info->state = None;
		hash_info->port = 0;
		hash_info->version = tvb_get_guint8(tvb, offset); /* get version*/

		if (( hash_info->version != 4) && 	/* error test version */
		   ( hash_info->version != 5))
    			hash_info->state = Done;

		conversation_add_proto_data(conversation, proto_socks,
			hash_info);

						/* set dissector for now */
		conversation_set_dissector(conversation, socks_handle);
	}

/* display summary window information  */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Socks");

	if (check_col(pinfo->cinfo, COL_INFO)){
		if (( hash_info->version == 4) || ( hash_info->version == 5)){
			col_add_fstr(pinfo->cinfo, COL_INFO, "Version: %d",
				hash_info->version);
		}
		else			/* unknown version display error */
			col_set_str(pinfo->cinfo, COL_INFO, "Unknown");


		if ( hash_info->command == PING_COMMAND)
			col_append_str(pinfo->cinfo, COL_INFO, ", Ping Req");
		if ( hash_info->command == TRACERT_COMMAND)
			col_append_str(pinfo->cinfo, COL_INFO, ", Traceroute Req");

/*XXX		if ( hash_info->port != -1) */
		if ( hash_info->port != 0)
			col_append_fstr(pinfo->cinfo, COL_INFO, ", Remote Port: %u",
				hash_info->port);
	}


/* run state machine if needed */

	if ((hash_info->state != Done) && ( !pinfo->fd->flags.visited)){

		if ( hash_info->version == 4)
			state_machine_v4( hash_info, tvb, offset, pinfo);

		else if ( hash_info->version == 5)
			state_machine_v5( hash_info, tvb, offset, pinfo);

		if (hash_info->state == Done) { 	/* if done now 	*/
			hash_info->start_done_row = pinfo->fd->num;
		}
	}

/* if proto tree, decode and display */

	if (tree) {
    		ti = proto_tree_add_item( tree, proto_socks, tvb, offset, -1,
    			FALSE );

		socks_tree = proto_item_add_subtree(ti, ett_socks);

		if ( hash_info->version == 4)
			display_socks_v4(tvb, offset, pinfo, socks_tree,
				hash_info);

		else if ( hash_info->version == 5)
			display_socks_v5(tvb, offset, pinfo, socks_tree,
				hash_info);

				/* if past startup, add the faked stuff */
		if ( pinfo->fd->num >  hash_info->start_done_row){
						/*  add info to tree */
        		proto_tree_add_text( socks_tree, tvb, offset, 0,
        			"Command: %d (%s)", hash_info->command,
				get_command_name(hash_info->command));

			proto_tree_add_ipv4( socks_tree, hf_socks_ip_dst, tvb,
					offset, 0, hash_info->dst_addr);

				/* no fake address for ping & traceroute */

			if (( hash_info->command != PING_COMMAND) &&
			    ( hash_info->command != TRACERT_COMMAND)){
				proto_tree_add_uint( socks_tree, hf_socks_dstport, tvb,
					offset, 0, hash_info->port);
			}
		}

	}


/* call next dissector if ready */

	if ( pinfo->fd->num > hash_info->start_done_row){
		call_next_dissector(tvb, offset, pinfo, tree, socks_tree,
		    hash_info);
	}
}



void
proto_register_socks( void){

/*** Prep the socks protocol, register it and a initialization routine  */
/*	to clear the hash stuff.					*/


	static gint *ett[] = {
		&ett_socks,
		&ett_socks_auth,
		&ett_socks_name

	};

  	static hf_register_info hf[] = {


		{ &hf_socks_ver,
			{ "Version", "socks.version", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL
			}
		},
		{ &hf_socks_ip_dst,
			{ "Remote Address", "socks.dst", FT_IPv4, BASE_NONE, NULL,
				0x0, NULL, HFILL
			}
		},
		{ &hf_socks_ip6_dst,
			{ "Remote Address(ipv6)", "socks.dstV6", FT_IPv6, BASE_NONE, NULL,
				0x0, NULL, HFILL
			}
		},
		{ &hf_user_name,
			{ "User Name", "socks.username", FT_STRINGZ, BASE_NONE, NULL,
				0x0, NULL, HFILL
			}
		},
		{ &hf_gssapi_payload,
			{ "GSSAPI data", "socks.gssapi.data", FT_BYTES, BASE_NONE, NULL,
				0x0, NULL, HFILL
			}
		},
		{ &hf_gssapi_command,
			{ "SOCKS/GSSAPI command", "socks.gssapi.command", FT_UINT8, BASE_DEC,
				VALS(gssapi_command_table), 0x0, NULL, HFILL
			}
		},
		{ &hf_gssapi_length,
			{ "SOCKS/GSSAPI data length", "socks.gssapi.length", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL
			}
		},
		{ &hf_v4a_dns_name,
			{ "SOCKS v4a Remote Domain Name", "socks.v4a_dns_name", FT_STRINGZ, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_socks_dstport,
			{ "Remote Port", "socks.dstport", FT_UINT16,
				BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_socks_cmd,
			{ "Command", "socks.command", FT_UINT8,
				BASE_DEC,  VALS(cmd_strings), 0x0, NULL, HFILL
			}
		},
		{ &hf_socks_results_4,
			{ "Results(V4)", "socks.results_v4", FT_UINT8,
				BASE_DEC, VALS(reply_table_v4), 0x0, NULL, HFILL
			}
		},
		{ &hf_socks_results_5,
			{ "Results(V5)", "socks.results_v5", FT_UINT8,
				BASE_DEC, VALS(reply_table_v5), 0x0, NULL, HFILL
			}
		},
		{ &hf_socks_results,
			{ "Results(V5)", "socks.results", FT_UINT8,
				BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		}

	};


   	proto_socks = proto_register_protocol (
   		"Socks Protocol", "Socks", "socks");

	proto_register_field_array(proto_socks, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_socks(void) {

	/* dissector install routine */
	socks_udp_handle = create_dissector_handle(socks_udp_dissector, proto_socks);
	socks_handle = create_dissector_handle(dissect_socks, proto_socks);

 	dissector_add_uint("tcp.port", TCP_PORT_SOCKS, socks_handle);
}
