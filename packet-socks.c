/* packet-socks.c
 * Routines for socks versions 4 &5  packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-socks.c,v 1.9 2000/08/11 13:34:59 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 * See http://www.socks.nec.com/socksprot.html for these and other documents
 *
 */

/* Possible enhancements -
 *
 * Add GSS-API authentication per rfc-1961
 * Add CHAP authentication
 * Decode FLAG bits per
 * 	 http://www.socks.nec.com/draft/draft-ietf-aft-socks-pro-v-04.txt 
 * In call_next_dissector, could load the destination address into the 
 * 	pi structure before calling next dissector.
 * remove display_string or at least make it use protocol identifiers
 * socks_hash_entry_t needs to handle V5 address type and domain names
*/




#ifdef HAVE_CONFIG_H
# include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "resolv.h"
#include "globals.h"
#include "alignment.h"
#include "conversation.h"

#include "packet-tcp.h"
#include "packet-udp.h"


#define CHECK_PACKET_LENGTH(X) if (!BYTES_ARE_IN_FRAME(offset, X)){  \
        proto_tree_add_text(tree, NullTVB, offset, 0, "*** FRAME TOO SHORT ***"); \
        return; }

#define compare_packet(X) (X == (fd->num))
#define get_packet_ptr	(fd->num)
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


/*********** Header field identifiers *************/

static int proto_socks = -1;

static int ett_socks = -1;
static int ett_socks_auth = -1;
static int ett_socks_name = -1;

static int hf_socks_ver = -1;
static int hf_socks_ip_dst = -1;
static int hf_socks_ip6_dst = -1;
static int hf_user_name = -1;
static int hf_socks_dstport = -1;
static int hf_socks_command = -1;


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
	GssApiAuth,
	AuthReply,
	Done
};



typedef struct {
	int	state;
	int 	version;
	int 	command;
	int 	grant;
	gint32 	port;
	gint32 	udp_port;
	gint32 	udp_remote_port;
	
	int	connect_offset;
	row_pointer_type 	v4_name_row;
	row_pointer_type	v4_user_name_row;
	row_pointer_type	connect_row;
	row_pointer_type	cmd_reply_row;
	row_pointer_type	bind_reply_row;
	row_pointer_type	command_row;
	row_pointer_type 	auth_method_row;
	row_pointer_type	user_name_auth_row;
	guint32 start_done_row;
	
	guint32	dst_addr;	/* this needs to handle IPv6 */
}socks_hash_entry_t;




static char *address_type_table[] = {
	"Unknown",
	"IPv4",
	"Unknown",
	"Domain Name",
	"IPv6",
	"Unknown"
};


/* String table for the V4 reply status messages */

static char *reply_table_v4[] = {
	"Granted",
	"Rejected or Failed",
	"Rejected because SOCKS server cannot connect to identd on the client",
	"Rejected because the client program and identd report different user-ids",
	"Unknown"
};


/* String table for the V5 reply status messages */

static char *reply_table_v5[] = {
	"Succeeded",
	"General SOCKS server failure",
	"Connection not allowed by ruleset",
	"Network unreachable",
	"Host unreachable",
	"Connection refused",
	"TTL expired",
	"Command not supported",
	"Address type not supported",
	"Unknown"
};


#define socks_hash_init_count 20
#define socks_hash_val_length (sizeof(socks_hash_entry_t))

static GMemChunk *socks_vals = NULL;


/************************* Support routines ***************************/


static int display_string( const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *label){

/* display a string with a length, characters encoding */
/* they are displayed under a tree with the name in Label variable */
/* return the length of the string and the length byte */


	proto_tree      *name_tree;
	proto_item      *ti;


	char temp[ 256];
	int length = GBYTE( pd, offset);

	if (!BYTES_ARE_IN_FRAME(offset, 8)){  
       		proto_tree_add_text(tree, NullTVB, offset, 0, "*** FRAME TOO SHORT ***");
	        return 0;
	}

	strncpy( temp, &pd[ offset + 1], length);
	temp[ length ] = 0;
  
   	ti = proto_tree_add_text(tree, NullTVB, offset, length + 1,
   	 	"%s: %s" , label, temp);


	name_tree = proto_item_add_subtree(ti, ett_socks_name);

	proto_tree_add_text( name_tree, NullTVB, offset, 1, "Length: %d", length);

	++offset;

	proto_tree_add_text( name_tree, NullTVB, offset, length, "String: %s", temp);

	return length + 1;
}	
 


static char *get_auth_method_name( guint Number){

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


static char *get_command_name( guint Number){

/* return the name of the command as a string */

	if ( Number == 0) return "Unknow";
	if ( Number == 1) return "Connect";
	if ( Number == 2) return "Bind";
	if ( Number == 3) return "UdpAssociate";
	if ( Number == 0x80) return "Ping";
	if ( Number == 0x81) return "Traceroute";
	return "Unknown";
}


static int display_address( const u_char *pd, int offset,
		frame_data *fd, proto_tree *tree) {

/* decode and display the v5 address, return offset of next byte */

	int a_type = GBYTE( pd, offset);

	proto_tree_add_text( tree, NullTVB, offset, 1,
			"Address Type: %d (%s)", a_type, 
			address_type_table[ MAX( 0, MIN( a_type,
				array_length( address_type_table)-1))]);

	++offset;

	if ( a_type == 1){		/* IPv4 address */
	   	if (!BYTES_ARE_IN_FRAME(offset, 4)) 
       			proto_tree_add_text(tree, NullTVB, offset, 0, "*** FRAME TOO SHORT ***");

		proto_tree_add_ipv4( tree, hf_socks_ip_dst, NullTVB, offset,
					4, GWORD( pd, offset));
		offset += 4;
	}	
	else if ( a_type == 3){	/* domain name address */

		offset += display_string( pd, offset, fd, tree,
			"Remote name");
	}
	else if ( a_type == 4){	/* IPv6 address */
		if (!BYTES_ARE_IN_FRAME(offset, 16)) 
       			proto_tree_add_text(tree, NullTVB, offset, 0, "*** FRAME TOO SHORT ***");

		proto_tree_add_ipv6( tree, hf_socks_ip6_dst, NullTVB, offset,
				4, &pd[offset]);
		offset += 16;
	}

	return offset;
}


static int get_address_v5( const u_char *pd, int offset, 
	socks_hash_entry_t *hash_info) {

/* decode the v5 address and return offset of next byte */
/*$$$ this needs to handle IPV6 and domain name addresses */
 

	int a_type = GBYTE( pd, offset++);

	if ( a_type == 1){ 		/* IPv4 address */
	   
	   	if ( hash_info)
			hash_info->dst_addr = GWORD( pd, offset);
		offset += 4;
	}
		
	else if ( a_type == 4) 		/* IPv6 address */
		offset += 16;
	
	else if ( a_type == 3)	/* domain name address */
		offset += GBYTE( pd, offset) + 1;
	
	return offset;
}	


/********************* V5 UDP Associate handlers ***********************/

static void socks_udp_dissector( const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree) {

/* Conversation dissector called from UDP dissector. Decode and display */
/* the socks header, the pass the rest of the data to the udp port 	*/
/* decode routine to  handle the payload.				*/

	guint32 *ptr;
	socks_hash_entry_t *hash_info;
	conversation_t *conversation;
	proto_tree      *socks_tree;
	proto_item      *ti;
	
	conversation = find_conversation( &pi.src, &pi.dst, pi.ptype,
		pi.srcport, pi.destport);

	g_assert( conversation);	/* should always find a conversation */

	hash_info = (socks_hash_entry_t*)conversation->data;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "Socks");

	if (check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO, "Version: 5, UDP Associated packet");
			
	if ( tree) {
    		ti = proto_tree_add_protocol_format( tree, proto_socks, NullTVB, offset,
    			END_OF_FRAME, "Socks" );

		socks_tree = proto_item_add_subtree(ti, ett_socks);

		CHECK_PACKET_LENGTH( 3);

       		proto_tree_add_text( socks_tree, NullTVB, offset, 2, "Reserved");
		offset += 2;
		
       		proto_tree_add_text( socks_tree, NullTVB, offset, 1, "Fragment Number: %d", GBYTE( pd,offset));
		++offset;
	

		offset = display_address( pd, offset, fd, socks_tree);
		hash_info->udp_remote_port = pntohs( &pd[ offset]);
		
		CHECK_PACKET_LENGTH( 2);
		proto_tree_add_uint( socks_tree, hf_socks_dstport, NullTVB,
			offset, 2, hash_info->udp_remote_port);
			
		offset += 2;
	}
	else { 		/* no tree, skip past the socks header */
		CHECK_PACKET_LENGTH( 3);
		offset += 3;
		offset = get_address_v5( pd,offset, 0) + 2;
	}	


/* set pi src/dst port and call the udp sub-dissector lookup */

	if ( pi.srcport == hash_info->port) 		
       		ptr = &pi.destport;
   	else
    		ptr = &pi.srcport;

        *ptr = hash_info->udp_remote_port;
   	
	decode_udp_ports( pd, offset, fd, tree, pi.srcport, pi.destport);
 
        *ptr = hash_info->udp_port;

}

			
void new_udp_conversation( socks_hash_entry_t *hash_info){

	conversation_t *conversation = conversation_new( &pi.src, &pi.dst,  PT_UDP,
			hash_info->udp_port, hash_info->port, hash_info);
			
	g_assert( conversation);
	
	conversation->is_old_dissector = TRUE;
	conversation->dissector.old = socks_udp_dissector;
}




/**************** Protocol Tree Display routines  ******************/


void display_socks_v4( const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, socks_hash_entry_t *hash_info) {


/* Display the protocol tree for the V5 version. This routine uses the	*/
/* stored conversation information to decide what to do with the row.	*/
/* Per packet information would have been better to do this, but we	*/
/* didn't have that when I wrote this. And I didn't expect this to get	*/
/* so messy.								*/


	int command;

					/* Display command from client */
	if (compare_packet( hash_info->connect_row)){

		CHECK_PACKET_LENGTH( 8);
		proto_tree_add_text( tree, NullTVB, offset, 1,
				"Version: %u ", hash_info->version);
		++offset;
		command = GBYTE( pd, offset);

		proto_tree_add_text( tree, NullTVB, offset, 1,
			"Command: %u (%s)", command, 
				get_command_name( command));
		++offset;

						/* Do remote port	*/
		proto_tree_add_uint( tree, hf_socks_dstport, NullTVB, offset, 2,
				pntohs( &pd[ offset]));
		offset += 2;

						/* Do destination address */
		proto_tree_add_ipv4( tree, hf_socks_ip_dst, NullTVB, offset,
				4, GWORD( pd, offset));

		offset += 4;

/*$$ check this, needs to do length checking	 */		
						/* display user name 	*/
			proto_tree_add_string( tree, hf_user_name, NullTVB, offset, 
				strlen( &pd[offset]) + 1,
				&pd[offset]);

	}
				/*Display command response from server*/
	
	else if ( compare_packet( hash_info->cmd_reply_row)){
				 
		CHECK_PACKET_LENGTH( 8);
		proto_tree_add_text( tree, NullTVB, offset, 1,
			"Version: %u (should be 0) ", GBYTE( pd, offset));
		++offset;
						/* Do results code	*/
		proto_tree_add_text( tree, NullTVB, offset, 1,
			"Result Code: %u (%s)", GBYTE( pd, offset) ,
			reply_table_v4[ MAX(0, MIN( GBYTE( pd, offset) - 90, 4))]);
		++offset;

						/* Do remote port	*/
		proto_tree_add_uint( tree, hf_socks_dstport, NullTVB, offset, 2,
				pntohs( &pd[ offset]));
		offset += 2;;
						/* Do remote address	*/
		proto_tree_add_ipv4( tree, hf_socks_ip_dst, NullTVB, offset, 4,
			GWORD( pd, offset));
	}
	
	else if ( compare_packet( hash_info->v4_user_name_row)){
			 
/*$$ check this, needs to do length checking	 */		
		proto_tree_add_text( tree, NullTVB, offset, strlen( &pd[offset]),
				"User Name: %s", &pd[offset]);
	}
}			



void display_socks_v5( const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, socks_hash_entry_t *hash_info) {
	
/* Display the protocol tree for the version. This routine uses the	*/
/* stored conversation information to decide what to do with the row.	*/
/* Per packet information would have been better to do this, but we	*/
/* didn't have that when I wrote this. And I didn't expect this to get	*/
/* so messy.								*/

	int i, command;
	guint temp;
	char *AuthMethodStr;


	if (compare_packet( hash_info->connect_row)){

		proto_tree      *AuthTree;
		proto_item      *ti;

		CHECK_PACKET_LENGTH( 2);
						/* Do version 	*/
		proto_tree_add_uint( tree, hf_socks_ver, NullTVB, offset, 1,
				hash_info->version);
		++offset;

		temp = GBYTE( pd, offset);	/* Get Auth method count */
							/* build auth tree */
		ti = proto_tree_add_text( tree, NullTVB, offset, 1,
				"Client Authentication Methods");
				
		AuthTree = proto_item_add_subtree(ti, ett_socks_auth);

		proto_tree_add_text( AuthTree, NullTVB, offset, 1,
				"Count: %u ", temp);
		++offset;

		CHECK_PACKET_LENGTH( temp);

		for( i = 0; i  < temp; ++i) {

			AuthMethodStr = get_auth_method_name(
				GBYTE( pd, offset + i));
			proto_tree_add_text( AuthTree, NullTVB, offset + i, 1,
				"Method[%d]: %u (%s)", i,
				GBYTE( pd, offset + i), AuthMethodStr); 
		}
		return;
	}					/* Get accepted auth method */
	else if (compare_packet( hash_info->auth_method_row)) {

		++offset;
		CHECK_PACKET_LENGTH( 1);

		proto_tree_add_text( tree, NullTVB, offset, 1,
			"Accepted Auth Method: 0x%0x (%s)", GBYTE( pd, offset),
				get_auth_method_name( GBYTE( pd, offset)));

		return;
	}					/* handle user/password auth */
	else if (compare_packet( hash_info->user_name_auth_row)) {

		proto_tree_add_text( tree, NullTVB, offset, 1,
				"Version: %u ", hash_info->version);
		++offset;
						/* process user name	*/
		offset += display_string( pd, offset, fd, tree,
				"User name");
						/* process password	*/
		offset += display_string( pd, offset, fd, tree,
				"Password");
	}					
					/* command to the server */	
					/* command response from server */
	else if ((compare_packet( hash_info->command_row)) || 
	         (compare_packet( hash_info->cmd_reply_row)) ||
	         (compare_packet( hash_info->bind_reply_row))){

		proto_tree_add_text( tree, NullTVB, offset, 1,
			"Version: %u ", hash_info->version);

		CHECK_PACKET_LENGTH( 1);

		++offset;

		command = GBYTE( pd, offset);
		
		if (compare_packet( hash_info->command_row))
			proto_tree_add_text( tree, NullTVB, offset, 1, "Command: %u (%s)",
				command,  get_command_name( command));
		else
			proto_tree_add_text( tree, NullTVB, offset, 1, "Status: %d (%s)",
				GBYTE( pd, offset), reply_table_v5[ MAX( 0,
				MIN(GBYTE( pd, offset) - 90, 9))]);
		++offset;

		proto_tree_add_text( tree, NullTVB, offset, 1,
			"Reserved: 0x%0x (should = 0x00)", GBYTE( pd, offset)); 
		++offset;

		offset = display_address( pd, offset, fd, tree);

		CHECK_PACKET_LENGTH( 2);
						/* Do remote port	*/
		proto_tree_add_text( tree, NullTVB, offset, 2,
				"%sPort: %d",
				(compare_packet( hash_info->bind_reply_row) ?
					"Remote Host " : ""),
				 pntohs( &pd[ offset]));
	}
}


	
/**************** Decoder State Machines ******************/


static guint state_machine_v4( socks_hash_entry_t *hash_info, const u_char *pd,
	int offset, frame_data *fd) {

/* Decode V4 protocol.  This is done on the first pass through the 	*/
/* list.  Based upon the current state, decode the packet and determine	*/
/* what the next state should be.  If we had per packet information, 	*/
/* this would be the place to load them up.				*/

	if ( hash_info->state == None) {		/* new connection */

		if (check_col(fd, COL_INFO))
	 		col_append_str(fd, COL_INFO, " Connect to server request");

		hash_info->state = Connecting;	/* change state		*/

		hash_info->command = GBYTE( pd, offset + 1);
						/* get remote port	*/
		if ( hash_info->command == CONNECT_COMMAND)						
			hash_info->port =  pntohs( &pd[ offset + 2]);
						/* get remote address	*/
		hash_info->dst_addr = GWORD( pd, offset + 4);
		
						/* save the packet pointer */
		hash_info->connect_row = get_packet_ptr;

						/* skip past this stuff	*/
		hash_info->connect_offset = offset + 8;

		offset += 8;
		
		if ( offset == pi.len) 		/* if no user name 	*/
						/* change state 	*/
			hash_info->state = V4UserNameWait;
		
			
		hash_info->connect_offset += strlen( &pd[ offset]) + 1;
		
		if ( !hash_info->dst_addr){ 		/* if no dest address */
							/* if more data */
			if ( hash_info->connect_offset < pi.len ) {
/*$$$ copy remote name here ??? */
				hash_info->state = Connecting;
			}
			else
				hash_info->state = V4NameWait;	
						}
						/* waiting for V4 user name */
	}else if ( hash_info->state == V4UserNameWait){	

		if (check_col(fd, COL_INFO))
	 		col_append_str(fd, COL_INFO, " Connect Request (User name)");

		hash_info->v4_user_name_row = get_packet_ptr;
/*$$$ may need to check for domain name here */
		hash_info->state = Connecting;
	}
					/* waiting for V4 domain name	*/
	else if ( hash_info->state == V4NameWait){

		hash_info->v4_name_row = get_packet_ptr;
		hash_info->state = Connecting;

	}
	else if ( hash_info->state == Connecting){

		if (check_col(fd, COL_INFO))
	 		col_append_str(fd, COL_INFO, " Connect Response");

						/* save packet pointer 	*/
		hash_info->cmd_reply_row = get_packet_ptr;
		hash_info->state = Done;		/* change state		*/
		offset = offset + 8;
	}

	return offset;
}



static void state_machine_v5( socks_hash_entry_t *hash_info, const u_char *pd, 
	int offset, frame_data *fd) {

/* Decode V5 protocol.  This is done on the first pass through the 	*/
/* list.  Based upon the current state, decode the packet and determine	*/
/* what the next state should be.  If we had per packet information, 	*/
/* this would be the place to load them up.				*/


	int temp;

	if ( hash_info->state == None) {

		if (check_col(fd, COL_INFO))
			col_append_str(fd, COL_INFO, " Connect to server request");

		hash_info->state = Connecting;	/* change state		*/
		hash_info->connect_row = get_packet_ptr;	

		if (!BYTES_ARE_IN_FRAME(offset, 1)){ 
			hash_info->state = Done;	/* change state		*/
	        	return; 
	        }

		temp = GBYTE( pd, offset + 1);
						/* skip past auth methods */
		offset = hash_info->connect_offset = offset + 1 + temp;
	}
	else if ( hash_info->state == Connecting){

		guint AuthMethod = GBYTE( pd, offset + 1);

		if (check_col(fd, COL_INFO))
	 		col_append_str(fd, COL_INFO, " Connect to server response");

		hash_info->auth_method_row = get_packet_ptr;

		if ( AuthMethod == NO_AUTHENTICATION)
			hash_info->state = V5Command;
			
		else if ( AuthMethod == USER_NAME_AUTHENTICATION)
			hash_info->state = UserNameAuth;
			
		else if ( AuthMethod == GSS_API_AUTHENTICATION)
/*$$$ should be this 		hash_info->state = GssApiAuth; */
			hash_info->state = Done;	
			
		else	hash_info->state = Done;	/*Auth failed or error*/

	}
	
	else if ( hash_info->state == V5Command) {	/* Handle V5 Command */

		guint temp;

		if (!BYTES_ARE_IN_FRAME(offset, 1)){ 
			hash_info->state = Done;	/* change state		*/
	        	return; 
	        }

		hash_info->command = GBYTE( pd, offset + 1); /* get command */

		if (check_col(fd, COL_INFO))
	 		col_append_fstr(fd, COL_INFO, " Command Request - %s",
	 			get_command_name(hash_info->command));

		hash_info->state = V5Reply;
		hash_info->command_row = get_packet_ptr;

		offset += 3;			/* skip to address type */

		offset = get_address_v5( pd, offset, hash_info);

		if (!BYTES_ARE_IN_FRAME(offset, 1)){ 
			hash_info->state = Done;
	        	return; 
	        }
		temp = GBYTE( pd, offset);

		if (( hash_info->command == CONNECT_COMMAND) || 
		    ( hash_info->command == UDP_ASSOCIATE_COMMAND))
						/* get remote port	*/
			hash_info->port =  pntohs( &pd[ offset]);
	}

	else if ( hash_info->state == V5Reply) {	/* V5 Command Reply */


		if (check_col(fd, COL_INFO))
	 		col_append_fstr(fd, COL_INFO, " Command Response - %s",
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
			offset = get_address_v5( pd, offset, hash_info);

	/* save server udp port and create upd conversation */
			if (!BYTES_ARE_IN_FRAME(offset, 2)){ 
				hash_info->state = Done;
		        	return; 
		        }
			hash_info->udp_port =  pntohs( &pd[ offset]);
			
			new_udp_conversation( hash_info);

/*$$ may need else statement to handle unknows and generate error message */
			
		}		
	}
	else if ( hash_info->state == V5BindReply) {	/* V5 Bind Second Reply */

		if (check_col(fd, COL_INFO))
	 		col_append_str(fd, COL_INFO, " Command Response: Bind remote host info");

		hash_info->bind_reply_row = get_packet_ptr;
		hash_info->state = Done;
	}
	else if ( hash_info->state == UserNameAuth) {	/* Handle V5 User Auth*/
		if (check_col(fd, COL_INFO))
	 		col_append_str(fd, COL_INFO,
	 			" User authentication response");

		hash_info->user_name_auth_row = get_packet_ptr;
		hash_info->state = AuthReply;

	}
	else if ( hash_info->state == AuthReply){	/* V5 User Auth reply */
		hash_info->cmd_reply_row = get_packet_ptr;
		if (check_col(fd, COL_INFO))
	 		col_append_str(fd, COL_INFO, " User authentication reply");
		hash_info->state = V5Command;
	}
}



static void display_ping_and_tracert( const u_char *pd, int offset,
	frame_data *fd,	proto_tree *tree, socks_hash_entry_t *hash_info) {

/* Display the ping/trace_route conversation */


       	const u_char    *data, *dataend;
       	const u_char   *lineend, *eol;
       	int             linelen;

					/* handle the end command */
       	if ( pi.destport == TCP_PORT_SOCKS){
		if (check_col(fd, COL_INFO))
			col_append_str(fd, COL_INFO, ", Terminate Request");
        	
		if ( tree)
  			proto_tree_add_text(tree, NullTVB, offset, 1,
   				(hash_info->command  == PING_COMMAND) ?
	 			"Ping: End command" :
	   	 		"Traceroute: End command");
	}
       	else{ 		/* display the PING or Traceroute results */
		if (check_col(fd, COL_INFO))
			col_append_str(fd, COL_INFO, ", Results");

		if ( tree){
			proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME,
   		 		(hash_info->command  == PING_COMMAND) ?
   		 		"Ping Results:" :
   	 			"Traceroute Results");

  	      		data = &pd[offset];
        		dataend = data + END_OF_FRAME;
        	
       	        	while (data < dataend) {
	
              			lineend = find_line_end(data, dataend, &eol);
                		linelen = lineend - data;

       		                proto_tree_add_text( tree, NullTVB, offset, linelen,
       		                	format_text(data, linelen));
               		        offset += linelen;
                       		data = lineend;
                       	}
		}
	}
}



static void call_next_dissector( const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, socks_hash_entry_t *hash_info) {

/* Display the results for PING and TRACERT extensions or		*/
/* Call TCP  dissector for the port that was passed during the	    	*/
/* connect process  						     	*/
/* Load pointer to pi.XXXport depending upon the direction, change   	*/
/* pi port to the remote port, call next dissecotr to decode the     	*/
/* payload, and restore the pi port after that is done.		     	*/

	guint32 *ptr;
 
 	if (( hash_info->command  == PING_COMMAND) ||
 	    ( hash_info->command  == TRACERT_COMMAND))
 	         
		display_ping_and_tracert( pd, offset, fd, tree, hash_info);

   	else {		/* call the tcp port decoder to handle the payload */
   	
/*$$$ may want to load dest address here */

 		if ( pi.destport  == TCP_PORT_SOCKS)
        		ptr = &pi.destport;
	   	else
        		ptr = &pi.srcport;

	        *ptr = hash_info->port;
		decode_tcp_ports( pd, offset, fd, tree, pi.srcport, pi.destport);
	        *ptr = TCP_PORT_SOCKS;
	}
}                



static void
dissect_socks(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree      *socks_tree;
	proto_item      *ti;
	socks_hash_entry_t *hash_info;
	conversation_t *conversation;
	

	conversation = find_conversation( &pi.src, &pi.dst, pi.ptype,
		pi.srcport, pi.destport);

	if ( conversation)			/* conversation found */
		hash_info = conversation->data;

			/* new conversation create local data structure */
	else {				
    		hash_info = g_mem_chunk_alloc(socks_vals);
		hash_info->start_done_row = G_MAXINT;
    		hash_info->state = None;
		hash_info->port = -1;
		hash_info->version = GBYTE( pd, offset); /* get version*/

		if (( hash_info->version != 4) && 	/* error test version */
		   ( hash_info->version != 5))
    			hash_info->state = Done;

		conversation_new( &pi.src, &pi.dst, pi.ptype,
			pi.srcport, pi.destport, hash_info);
	}

/* display summary window information  */

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "Socks");

	if (check_col(fd, COL_INFO)){
		if (( hash_info->version == 4) || ( hash_info->version == 5)){
			col_add_fstr(fd, COL_INFO, "Version: %d",
				hash_info->version);
		}		
		else			/* unknown version display error */
			col_add_str(fd, COL_INFO, "Unknown");
		

		if ( hash_info->command == PING_COMMAND)
			col_append_str(fd, COL_INFO, ", Ping Req");
		if ( hash_info->command == TRACERT_COMMAND)
			col_append_str(fd, COL_INFO, ", Traceroute Req");
		
		if ( hash_info->port != -1)
			col_append_fstr(fd, COL_INFO, ", Remote Port: %d",
				hash_info->port);
	}


/* run state machine if needed */

	if ((hash_info->state != Done) && ( !fd->flags.visited)){

		if ( hash_info->version == 4)
			state_machine_v4( hash_info, pd, offset, fd);

		else if ( hash_info->version == 5)
			state_machine_v5( hash_info, pd, offset, fd);

		if (hash_info->state == Done) { 	/* if done now 	*/
			hash_info->start_done_row = fd->num;
		}
	}
	
/* if proto tree, decode and display */

	if (tree) {			
    		ti = proto_tree_add_item( tree, proto_socks, NullTVB, offset,
    			END_OF_FRAME, FALSE );

		socks_tree = proto_item_add_subtree(ti, ett_socks);

		if ( hash_info->version == 4)
			display_socks_v4( pd, offset, fd, tree, socks_tree,
				hash_info);
			
		else if ( hash_info->version == 5)
			display_socks_v5( pd, offset, fd, tree, socks_tree,
				hash_info);

				/* if past startup, add the faked stuff */
		if ( fd->num >  hash_info->start_done_row){
						/*  add info to tree */
        		proto_tree_add_text( socks_tree, NullTVB, offset, 0,
        			"Command: %d (%s)", hash_info->command,
				get_command_name(hash_info->command));

			proto_tree_add_ipv4( socks_tree, hf_socks_ip_dst, NullTVB,
					offset, 0, hash_info->dst_addr);

				/* no fake address for ping & traceroute */
				
			if (( hash_info->command != PING_COMMAND) &&
			    ( hash_info->command != TRACERT_COMMAND)){
				proto_tree_add_uint( socks_tree, hf_socks_dstport, NullTVB,
					offset, 0, hash_info->port);
			}
		}

	}


/* call next dissector if ready */

	if ( fd->num > hash_info->start_done_row){
		call_next_dissector( pd, offset, fd, tree, hash_info);
	}
}



static void socks_reinit( void){

/* Do the cleanup work when a new pass through the packet list is	*/
/* performed. Reset the highest row seen counter and re-initialize the	*/
/* conversation memory chunks.						*/

  	if (socks_vals)
    		g_mem_chunk_destroy(socks_vals);

  	socks_vals = g_mem_chunk_new("socks_vals", socks_hash_val_length,
		socks_hash_init_count * socks_hash_val_length,
		G_ALLOC_AND_FREE);
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
			{ "Version", "socks.ver", FT_UINT8, BASE_NONE, NULL,
			 	0x0, ""
			}
		},
		{ &hf_socks_ip_dst,
			{ "Remote Address", "socks.dst", FT_IPv4, BASE_NONE, NULL,
			 	0x0, ""
			}
		},
		{ &hf_socks_ip6_dst,
			{ "Remote Address", "socks.dstV6", FT_IPv6, BASE_NONE, NULL,
			 	0x0, ""
			}
		},

                { &hf_user_name,
                	{ "User Name", "socks.username", FT_STRING, BASE_NONE,
                		 NULL, 0x0, ""
                	}
                },
		{ &hf_socks_dstport,
			{ "Remote Port", "socks.dstport", FT_UINT16,
				BASE_DEC, NULL, 0x0, ""
			}
		},
		{ &hf_socks_command,
			{ "Command", "socks.command", FT_UINT16,
				BASE_DEC, NULL, 0x0, ""
			}
		}

	};


   	proto_socks = proto_register_protocol (
   		"Socks Protocol", "socks");           

	proto_register_field_array(proto_socks, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));  

	register_init_routine( &socks_reinit);	/* register re-init routine */
}


void
proto_reg_handoff_socks(void) {

	/* dissector install routine */ 
 
 	old_dissector_add("tcp.port", TCP_PORT_SOCKS, dissect_socks);
}
