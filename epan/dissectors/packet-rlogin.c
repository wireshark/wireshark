/* packet-rlogin.c
 * Routines for unix rlogin packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Based upon RFC-1282 - BSD Rlogin
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#include "packet-tcp.h"

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
	guint32	info_framenum;
	char  	name[ NAME_LEN];

} rlogin_hash_entry_t;

#define NONE		0
#define USER_INFO_WAIT	1
#define DONE		2
#define BAD		2

static guint32 last_abs_sec = 0;
static guint32 last_abs_usec= 0;

static void
rlogin_init(void)
{

/* Routine to initialize rlogin protocol before each capture or filter pass. */

	last_abs_sec = 0;
	last_abs_usec= 0;

}


/**************** Decoder State Machine ******************/

static void
rlogin_state_machine( rlogin_hash_entry_t *hash_info, tvbuff_t *tvb,
	packet_info *pinfo)
{
	guint length;
	gint stringlen;

/* rlogin stream decoder */
/* Just watched for second packet from client with the user name and 	*/
/* terminal type information.						*/


	if ( pinfo->destport != RLOGIN_PORT)   /* not from client */
		return;
						/* exit if not needed */
	if (( hash_info->state == DONE) || (  hash_info->state == BAD))
		return;

						/* test timestamp */
	if (( last_abs_sec > pinfo->fd->abs_secs) ||
	    (( last_abs_sec == pinfo->fd->abs_secs) &&
	     ( last_abs_usec >= pinfo->fd->abs_usecs)))
	    	return;

	last_abs_sec = pinfo->fd->abs_secs;		/* save timestamp */
	last_abs_usec = pinfo->fd->abs_usecs;

	length = tvb_length(tvb);
	if ( length == 0)				/* exit if no data */
		return;

	if ( hash_info->state == NONE){      		/* new connection*/
		if (tvb_get_guint8(tvb, 0) != '\0') {
			/*
			 * We expected a NUL, but didn't get one; quit.
			 */
			hash_info->state = DONE;
			return;
		}
		else {
			if (length <= 1)		/* if no data	*/
				hash_info->state = USER_INFO_WAIT;
			else {
				hash_info->state = DONE;
				hash_info->info_framenum = pinfo->fd->num;
			}
		}
	}					/* expect user data here */
/*$$$ may need to do more checking here */
	else if ( hash_info->state == USER_INFO_WAIT) {
		hash_info->state = DONE;
		hash_info->info_framenum = pinfo->fd->num;
							/* save name for later*/
		stringlen = tvb_strnlen(tvb, 0, NAME_LEN);
		if (stringlen == -1)
			stringlen = NAME_LEN - 1;	/* no '\0' found */
		else if (stringlen > NAME_LEN - 1)
			stringlen = NAME_LEN - 1;	/* name too long */
		tvb_memcpy(tvb, (guint8 *)hash_info->name, 0, stringlen);
		hash_info->name[stringlen] = '\0';

		if (check_col(pinfo->cinfo, COL_INFO))	/* update summary */
			col_append_str(pinfo->cinfo, COL_INFO,
			    ", User information");
	}
}

static void rlogin_display( rlogin_hash_entry_t *hash_info, tvbuff_t *tvb,
	packet_info *pinfo, proto_tree *tree, struct tcpinfo *tcpinfo)
{
/* Display the proto tree */
	int             offset = 0;
	proto_tree      *rlogin_tree, *user_info_tree, *window_tree;
	proto_item      *ti;
	guint           length;
	int		str_len;
	gint		ti_offset;
	proto_item      *user_info_item,  *window_info_item;

 	ti = proto_tree_add_item( tree, proto_rlogin, tvb, 0, -1, FALSE);

	rlogin_tree = proto_item_add_subtree(ti, ett_rlogin);

	length = tvb_length(tvb);
	if ( length == 0)			/* exit if no captured data */
		return;

	/*
	 * XXX - this works only if the urgent pointer points to something
	 * in this segment; to make it work if the urgent pointer points
	 * to something past this segment, we'd have to remember the urgent
	 * pointer setting for this conversation.
	 */
	if ( tcpinfo->urgent &&			/* if urgent pointer set */
	     length >= tcpinfo->urgent_pointer) {	/* and it's in this frame */

		int urgent_offset = tcpinfo->urgent_pointer - 1;
		guint8 Temp = tvb_get_guint8(tvb, urgent_offset);

		if (urgent_offset > offset)	/* check for data in front */
			proto_tree_add_text( rlogin_tree, tvb, offset,
			    urgent_offset, "Data");

		proto_tree_add_text( rlogin_tree, tvb, urgent_offset, 1,
				"Control byte: %u (%s)",
				Temp,
				(Temp == 0x02) ? "Clear buffer" :
				(Temp == 0x10) ? "Raw mode" :
				(Temp == 0x20) ? "Cooked mode" :
				(Temp == 0x80) ? "Window size request" :
				"Unknown");
		offset = urgent_offset + 1;	/* adjust offset */
	}
	else if ( tvb_get_guint8(tvb, offset) == '\0'){   /* startup */
		if ( pinfo->srcport== RLOGIN_PORT)   /* from server */
	   		proto_tree_add_text(rlogin_tree, tvb, offset, 1,
					"Startup info received flag (0x00)");

		else
	   		proto_tree_add_text(rlogin_tree, tvb, offset, 1,
					"Client Startup Flag (0x00)");
		++offset;
	}

	if (!tvb_offset_exists(tvb, offset))
		return;	/* No more data to check */

	if ( hash_info->info_framenum == pinfo->fd->num){
		/*
		 * First frame of conversation, hence user info?
		 */
		user_info_item = proto_tree_add_item( rlogin_tree, hf_user_info, tvb,
			offset, -1, FALSE);

		/*
		 * Do server user name.
		 */
		str_len = tvb_strsize(tvb, offset);
		user_info_tree = proto_item_add_subtree( user_info_item,
			ett_rlogin_user_info);
		proto_tree_add_text(user_info_tree, tvb, offset, str_len,
				"Server User Name: %.*s", str_len - 1,
				tvb_get_ptr(tvb, offset, str_len - 1));
		offset += str_len;

		/*
		 * Do client user name.
		 */
		str_len = tvb_strsize(tvb, offset);
		proto_tree_add_text(user_info_tree, tvb, offset, str_len,
				"Client User Name: %.*s", str_len - 1,
				tvb_get_ptr(tvb, offset, str_len - 1));
		offset += str_len;

		/*
		 * Do terminal type/speed.
		 */
		str_len = tvb_strsize(tvb, offset);
		proto_tree_add_text(user_info_tree, tvb, offset, str_len,
				"Terminal Type/Speed: %.*s", str_len - 1,
				tvb_get_ptr(tvb, offset, str_len - 1));
		offset += str_len;
	}

	if (!tvb_offset_exists(tvb, offset))
		return;	/* No more data to check */

/* test for terminal information, the data will have 2 0xff bytes */

						/* look for first 0xff byte */
	ti_offset = tvb_find_guint8(tvb, offset, -1, 0xff);

	if (ti_offset != -1 &&
	    tvb_bytes_exist(tvb, ti_offset + 1, 1) &&
	    tvb_get_guint8(tvb, ti_offset + 1) == 0xff) {
	        /*
		 * Found terminal info.
		 */
		if (ti_offset > offset) {
			/*
			 * There's data before the terminal info.
			 */
	                proto_tree_add_text( rlogin_tree, tvb, offset,
	                	(ti_offset - offset), "Data");
	                offset = ti_offset;
	        }

		window_info_item = proto_tree_add_item(rlogin_tree,
				hf_window_info, tvb, offset, 12, FALSE );

		window_tree = proto_item_add_subtree(window_info_item,
			                 ett_rlogin_window);

	        proto_tree_add_text(window_tree, tvb, offset, 2,
			"Magic Cookie: (0xff, 0xff)");
		offset += 2;

	      	proto_tree_add_text(window_tree, tvb, offset, 2,
			"Window size marker: 'ss'");
		offset += 2;

	 	proto_tree_add_item(window_tree, hf_window_info_rows, tvb,
	 		offset, 2, FALSE);
		offset += 2;

 		proto_tree_add_item(window_tree, hf_window_info_cols, tvb,
 			offset, 2, FALSE);
		offset += 2;

 		proto_tree_add_item(window_tree, hf_window_info_x_pixels, tvb,
 			offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(window_tree, hf_window_info_y_pixels, tvb,
			offset, 2, FALSE);
		offset += 2;
	}

	if (tvb_offset_exists(tvb, offset)) {
		/*
		 * There's more data in the frame.
		 */
		proto_tree_add_text(rlogin_tree, tvb, offset, -1, "Data");
	}
}

static void
dissect_rlogin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct tcpinfo *tcpinfo = pinfo->private_data;
	conversation_t *conversation;
	rlogin_hash_entry_t *hash_info;
	guint length;
	gint ti_offset;

						/* Lookup this connection*/
	conversation = find_conversation( pinfo->fd->num, &pinfo->src, &pinfo->dst,
		pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

	if ( !conversation) {
		conversation = conversation_new( pinfo->fd->num, &pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}
	hash_info = conversation_get_proto_data(conversation, proto_rlogin);
	if ( !hash_info) {
		hash_info = se_alloc(sizeof( rlogin_hash_entry_t));
		hash_info->state = NONE;
		hash_info->info_framenum = 0;	/* no frame has the number 0 */
		hash_info->name[ 0] = 0;
		conversation_add_proto_data(conversation, proto_rlogin,
			hash_info);
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))		/* update protocol  */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Rlogin");

	if (check_col(pinfo->cinfo, COL_INFO)){		/* display packet info*/
		if ( hash_info->name[0]) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "User name: %s, ", hash_info->name);
		}
		else
			col_clear(pinfo->cinfo, COL_INFO);

		length = tvb_length(tvb);
		if (length != 0) {
			if ( tvb_get_guint8(tvb, 0) == '\0') {
				col_append_str(pinfo->cinfo, COL_INFO,
				    "Start Handshake");
			}
			else if ( tcpinfo->urgent &&
				  length >= tcpinfo->urgent_pointer ) {
				col_append_str(pinfo->cinfo, COL_INFO,
				    "Control Message");
			}
			else {			/* check for terminal info */
				ti_offset = tvb_find_guint8(tvb, 0, -1, 0xff);
				if (ti_offset != -1 &&
				    tvb_bytes_exist(tvb, ti_offset + 1, 1) &&
				    tvb_get_guint8(tvb, ti_offset + 1) == 0xff) {
					col_append_str(pinfo->cinfo, COL_INFO,
					    "Terminal Info");
				}
				else {
					int bytes_to_copy;

					bytes_to_copy = tvb_length(tvb);
					if (bytes_to_copy > 128)
						bytes_to_copy = 128;
					col_append_fstr(pinfo->cinfo, COL_INFO,
					    "Data: %s",
					    tvb_format_text(tvb, 0, bytes_to_copy));
				}
			}
		}
	}

	rlogin_state_machine( hash_info, tvb, pinfo);

	if ( tree) 				/* if proto tree, decode data */
 		rlogin_display( hash_info, tvb, pinfo, tree, tcpinfo);
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
				 NULL, 0x0, "", HFILL
			}
		},
		{ &hf_window_info,
			{ "Window Info", "rlogin.window_size", FT_NONE, BASE_NONE,
				 NULL, 0x0, "", HFILL
			}
		},
		{ &hf_window_info_rows,
			{ "Rows", "rlogin.window_size.rows", FT_UINT16, BASE_DEC,
				 NULL, 0x0, "", HFILL
			}
		},
		{ &hf_window_info_cols,
			{ "Columns", "rlogin.window_size.cols", FT_UINT16, BASE_DEC,
				 NULL, 0x0, "", HFILL
			}
		},
		{ &hf_window_info_x_pixels,
			{ "X Pixels", "rlogin.window_size.x_pixels", FT_UINT16, BASE_DEC,
				 NULL, 0x0, "", HFILL
			}
		},
		{ &hf_window_info_y_pixels,
			{ "Y Pixels", "rlogin.window_size.y_pixels", FT_UINT16, BASE_DEC,
				 NULL, 0x0, "", HFILL
			}
		}
	};

	proto_rlogin = proto_register_protocol (
		"Rlogin Protocol", "Rlogin", "rlogin");

	proto_register_field_array(proto_rlogin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_init_routine( &rlogin_init);	/* register re-init routine */
}

void
proto_reg_handoff_rlogin(void) {

	/* dissector install routine */

	dissector_handle_t rlogin_handle;

	rlogin_handle = create_dissector_handle(dissect_rlogin, proto_rlogin);
	dissector_add("tcp.port", TCP_PORT_RLOGIN, rlogin_handle);
}
