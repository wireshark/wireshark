/* packet-rlogin.c
 * Routines for unix rlogin packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-rlogin.c,v 1.10 2000/10/21 05:52:21 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * Based upon RFC-1282 - BSD Rlogin
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


#define CHECK_PACKET_LENGTH(X) if (!BYTES_ARE_IN_FRAME(offset, X)){  \
        proto_tree_add_text(tree, NullTVB, offset, 0, "*** FRAME TOO SHORT ***"); \
        return; }


#define TCP_PORT_RLOGIN 513

static int proto_rlogin = -1;

static int ett_rlogin = -1;
static int ett_rlogin_window = -1;
static int ett_rlogin_user_info = -1;
static int ett_rlogin_window_rows = -1;
static int ett_rlogin_window_cols = -1;
static int ett_rlogin_window_x_pixels = -1;
static int ett_rlogin_window_y_pixels = -1;


static int hf_user_info = -1;
static int hf_window_info = -1;
static int hf_window_info_rows = -1;
static int hf_window_info_cols = -1;
static int hf_window_info_x_pixels = -1;
static int hf_window_info_y_pixels = -1;


#define RLOGIN_PORT 513

#define NAME_LEN 32

typedef struct {
	int	state;
	int	info_framenum;
	char  	name[ NAME_LEN];
	
}rlogin_hash_entry_t;


#define NONE 0
#define USER_INFO_WAIT 1
#define DONE 2
#define BAD 2


static GMemChunk *rlogin_vals = NULL;

#define rlogin_hash_init_count 20

static guint32 last_abs_sec = 0;
static guint32 last_abs_usec= 0;

/* Find the length of a '\0'-terminated string, *INCLUDING* the terminating
   '\0', but don't run past the end of the packet doing so. */
static int
string_len(const char *str, int maxlen)
{
	const char *str_end;

	str_end = memchr(str, '\0', maxlen);
	if (str_end == NULL) {
		/* No '\0' found - return the length as of when we stopped,
		   plus one to force the length to be too long and and
		   CHECK_PACKET_LENGTH to fail. */
		return maxlen + 1;
	}
	return str_end - str + 1;
}

static void
rlogin_init( void){

/* Routine to initialize rlogin protocol before each capture or filter pass. */
/* Release any memory if needed.  Then setup the memory chunks.		*/

	last_abs_sec = 0;
	last_abs_usec= 0;

  	if (rlogin_vals)
   		g_mem_chunk_destroy(rlogin_vals);

  	rlogin_vals = g_mem_chunk_new("rlogin_vals",
  		sizeof( rlogin_hash_entry_t),
		rlogin_hash_init_count * sizeof( rlogin_hash_entry_t),
		G_ALLOC_AND_FREE);
}


/**************** Decoder State Machine ******************/

static void  
rlogin_state_machine( rlogin_hash_entry_t *hash_info, const u_char *pd,
	int offset, frame_data *fd) {

/* rlogin stream decoder */
/* Just watched for second packet from client with the user name and 	*/
/* terminal type information.						*/


	if ( pi.destport != RLOGIN_PORT)   /* not from client */
		return;
						/* exit if not needed */
	if (( hash_info->state == DONE) || (  hash_info->state == BAD))
		return;
		
						/* test timestamp */
	if (( last_abs_sec > fd->abs_secs) || 
	    (( last_abs_sec == fd->abs_secs) && ( last_abs_usec >= fd->abs_usecs)))
	    	return;

	last_abs_sec = fd->abs_secs;			/* save timestamp */
	last_abs_usec = fd->abs_usecs;

	if ( !IS_DATA_IN_FRAME(offset))		/* exit if no data */
		return;   

	if ( hash_info->state == NONE){      		/* new connection*/

		if ( GBYTE( pd, offset + 1)) {		/* expect a NULL */
			hash_info->state = DONE;		/* quit, no NULL */
			return;
		}
		else {
			if (( END_OF_FRAME) <= 1)	/* if no data	*/
				hash_info->state = USER_INFO_WAIT;
			else {
				hash_info->state = DONE;	
				hash_info->info_framenum = fd->num;
			}	
		}
	}					/* expect user data here */
/*$$$ may need to do more checking here */	
	else if ( hash_info->state == USER_INFO_WAIT) {
		hash_info->state = DONE;	
		hash_info->info_framenum = fd->num;
							/* save name for later*/
		strncpy( hash_info->name, &pd[ offset], NAME_LEN);

		hash_info->name[ NAME_LEN] = 0;
		
		if (check_col(fd, COL_INFO))	/* update summary 	*/
			col_append_str( fd, COL_INFO, ", User information");
		
	}		
}


static void rlogin_display( rlogin_hash_entry_t *hash_info, const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree) {

/* Display the proto tree */

	proto_tree      *rlogin_tree, *user_info_tree, *window_tree;
	proto_item      *ti;
	guint8 *Ptr;
	const char *str;
	int str_len;
	proto_item      *user_info_item,  *window_info_item;

 	ti = proto_tree_add_item( tree, proto_rlogin, NullTVB, offset,
    			END_OF_FRAME, FALSE);

	rlogin_tree = proto_item_add_subtree(ti, ett_rlogin);

	if ( !IS_DATA_IN_FRAME(offset))		/* exit if no data */
		return;

	if ( tcp_urgent_pointer &&		/* if control message */
 	     BYTES_ARE_IN_FRAME(offset + tcp_urgent_pointer - 1, 1)) {

		int i = offset + tcp_urgent_pointer - 1;
		guint16 Temp = GBYTE( pd, i);
		
		if ( i < offset)		/* check for data in front */
			proto_tree_add_text( rlogin_tree, NullTVB, offset, i - offset,
				"Data");
		
   		proto_tree_add_text( rlogin_tree, NullTVB, i, 1, "Control byte: %u (%s)",
   				Temp,
				(Temp == 2) ? "Clear buffer" :
				(Temp == 0x10) ? "Raw mode" :
				(Temp == 0x20) ? "Cooked mode" :
				(Temp == 0x80) ? "Window size request" :
				"Unknown");
		offset = i;			/* adjust offset */
		}
		
	else if ( !GBYTE( pd, offset)){		        	  /* startup */
		if ( pi.srcport== RLOGIN_PORT)   /* from server */
	   		proto_tree_add_text(rlogin_tree, NullTVB, offset, 1,
					"Startup info received flag (0x00)");
					
		else 
	   		proto_tree_add_text(rlogin_tree, NullTVB, offset, 1,
					"Client Startup Flag (0x00)");
		++offset;
	}
		
        if (!IS_DATA_IN_FRAME(offset))
        	return;	/* No more data to check */

	if ( hash_info->info_framenum == fd->num){		/* user info ?*/
		user_info_item = proto_tree_add_item( rlogin_tree, hf_user_info, NullTVB,
			offset, END_OF_FRAME, FALSE);

		str = &pd[ offset];		/* do server user name */
		str_len = string_len( str, END_OF_FRAME);
		CHECK_PACKET_LENGTH( str_len);
		user_info_tree = proto_item_add_subtree( user_info_item,
			ett_rlogin_user_info);
		proto_tree_add_text(  user_info_tree, NullTVB, offset, str_len,
				"Server User Name:  %.*s", str_len, str);
		offset += str_len;

	        if (!IS_DATA_IN_FRAME(offset))
	        	return;	/* No more data to check */
		str = &pd[ offset];		/* do client user name */
		str_len = string_len( str, END_OF_FRAME);
		CHECK_PACKET_LENGTH( str_len);
		proto_tree_add_text(  user_info_tree, NullTVB, offset, str_len,
				"Client User Name:  %.*s", str_len, str);
		offset += str_len;
		
	        if (!IS_DATA_IN_FRAME(offset))
	        	return;	/* No more data to check */
		str = &pd[ offset];		/* do terminal type/speed */
		str_len = string_len( str, END_OF_FRAME);
		CHECK_PACKET_LENGTH( str_len);
		proto_tree_add_text(  user_info_tree, NullTVB, offset, str_len,
				"Terminal Type/Speed:  %.*s", str_len, str);
		offset += str_len;
   	}
  
        if (!IS_DATA_IN_FRAME(offset))
        	return;	/* No more data to check */

/* test for terminal information, the data will have 2 0xff bytes */
  
  						/* look for first 0xff byte */
  	Ptr = (guint8*)memchr( &pd[ offset], 0xff, END_OF_FRAME);
  		
	if (( Ptr) && (*(Ptr + 1) == 0xff)) {	/* found terminal info */

		int ti_offset = Ptr - pd;		/* get offset 	*/

		if ( ti_offset < offset){	/*if data before terminal info*/
	                proto_tree_add_text( rlogin_tree, NullTVB, offset,
	                	(ti_offset - offset), "Data");
	                offset = ti_offset;
	        }
		        	
		CHECK_PACKET_LENGTH( 12);
		window_info_item = proto_tree_add_item( rlogin_tree,
				hf_window_info, NullTVB, offset, 12, FALSE );
    			
		window_tree = proto_item_add_subtree( window_info_item,
			                 ett_rlogin_window);

		CHECK_PACKET_LENGTH( 2);
	        proto_tree_add_text( window_tree, NullTVB, offset, 2, 
			"Magic Cookie:  (0xff, 0xff)");
		offset += 2;
					
		CHECK_PACKET_LENGTH( 2);
	      	proto_tree_add_text( window_tree, NullTVB, offset, 2, 
			"Window size marker:  'ss'");
		offset += 2;

		CHECK_PACKET_LENGTH( 2);
	 	proto_tree_add_uint( window_tree, hf_window_info_rows, NullTVB, offset,
		    	2, pntohs( &pd[offset]));
		offset += 2;

		CHECK_PACKET_LENGTH( 2);
 		proto_tree_add_uint( window_tree, hf_window_info_cols, NullTVB, offset,
		    	2, pntohs( &pd[offset]) );
		offset += 2;

		CHECK_PACKET_LENGTH( 2);
 		proto_tree_add_uint( window_tree, hf_window_info_x_pixels, NullTVB,
 			offset, 2, pntohs( &pd[offset]));
		offset += 2;

		CHECK_PACKET_LENGTH( 2);
		proto_tree_add_uint( window_tree, hf_window_info_y_pixels, NullTVB,
			offset, 2, pntohs( &pd[offset]) );
		offset += 2;
	}
			
	if ( END_OF_FRAME != 0) 			/* if more data */
		proto_tree_add_text(rlogin_tree, NullTVB, offset, END_OF_FRAME, "Data");

}	



static void
dissect_rlogin(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {


	guint8 *Ptr;
	rlogin_hash_entry_t *hash_info = 0;
	conversation_t *conversation;

	OLD_CHECK_DISPLAY_AS_DATA(proto_rlogin, pd, offset, fd, tree);

						/* Lookup this connection*/
	conversation = find_conversation( &pi.src, &pi.dst, pi.ptype,
		pi.srcport, pi.destport, 0);

	if ( conversation)			/* conversation found */
		hash_info = conversation->data;

			/* new conversation create local data structure */
	else {				
    		hash_info = g_mem_chunk_alloc(rlogin_vals);
    		hash_info->state = NONE;
    		hash_info->info_framenum = -1;
		hash_info->name[ 0] = 0;

		conversation_new( &pi.src, &pi.dst, pi.ptype,
			pi.srcport, pi.destport, hash_info, 0);
	}
	
	if (check_col(fd, COL_PROTOCOL))		/* update protocol  */
		col_add_str(fd, COL_PROTOCOL, "Rlogin");

	if (check_col(fd, COL_INFO)){			/* display packet info*/

		char temp[1000];
		
		if ( hash_info->name[0]) {
			strcpy( temp, "User name: ");
			strcat( temp, hash_info->name);
			strcat( temp, ", ");
		}
		else 
			temp[0] = 0;
			 
		if ( !GBYTE(pd, offset))
			strcat( temp, "Start Handshake"); 
		else if ( tcp_urgent_pointer)
			strcat( temp, "Control Message"); 

		else {				/* check for terminal info */
		 	Ptr = (guint8*)memchr( &pd[ offset], 0xff, END_OF_FRAME);
		
			if (( Ptr) && (*(Ptr + 1) == 0xff))
				strcat( temp, "Terminal Info");
			else {
				int i;
				strcat( temp, "Data:"); 
				i = strlen( temp);
				strncat( temp, &pd[ offset], 128); 
				temp[ i + MIN( 128, END_OF_FRAME)] = 0;
			}
		}		

		col_add_str(fd, COL_INFO, temp);
	}

	rlogin_state_machine( hash_info, pd, offset, fd);

	if ( tree) 				/* if proto tree, decode data */
 		rlogin_display( hash_info, pd, offset, fd, tree);
}


void
proto_register_rlogin( void){

/* Prep the rlogin protocol, for now, just register it	*/

	static gint *ett[] = {
		&ett_rlogin,
		&ett_rlogin_window,
		&ett_rlogin_window_rows,
		&ett_rlogin_window_cols,
		&ett_rlogin_window_x_pixels,
		&ett_rlogin_window_y_pixels,
		&ett_rlogin_user_info
	};
	
  	static hf_register_info hf[] = {
    
                { &hf_user_info,
                	{ "User Info", "rlogin.user_info", FT_NONE, BASE_NONE,
                		 NULL, 0x0, ""
                	}
		},
                { &hf_window_info,
                	{ "Window Info", "rlogin.window_size", FT_NONE, BASE_NONE,
                		 NULL, 0x0, ""
                	}
		},
                { &hf_window_info_rows,
                	{ "Rows", "rlogin.window_size.rows", FT_UINT16, BASE_DEC,
                		 NULL, 0x0, ""
                	}
		},
                { &hf_window_info_cols,
                	{ "Columns", "rlogin.window_size.cols", FT_UINT16, BASE_DEC,
                		 NULL, 0x0, ""
                	}
		},
                { &hf_window_info_x_pixels,
                	{ "X Pixels", "rlogin.window_size.x_pixels", FT_UINT16, BASE_DEC,
                		 NULL, 0x0, ""
                	}
		},
                { &hf_window_info_y_pixels,
                	{ "Y Pixels", "rlogin.window_size.y_pixels", FT_UINT16, BASE_DEC,
                		 NULL, 0x0, ""
                	}
		}
	};
	

   	proto_rlogin = proto_register_protocol (
   		"Rlogin Protocol", "rlogin");           

	proto_register_field_array(proto_rlogin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));  

	register_init_routine( &rlogin_init);	/* register re-init routine */


}

void
proto_reg_handoff_rlogin(void) {

	/* dissector install routine */ 
 
	old_dissector_add("tcp.port", TCP_PORT_RLOGIN, dissect_rlogin);
}
