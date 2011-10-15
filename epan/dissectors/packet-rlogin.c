/* packet-rlogin.c
 * Routines for unix rlogin packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste[AT]woodward.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#include "packet-tcp.h"

#define RLOGIN_PORT 513

static int proto_rlogin = -1;

static int ett_rlogin = -1;
static int ett_rlogin_window = -1;
static int ett_rlogin_user_info = -1;
static int ett_rlogin_window_rows = -1;
static int ett_rlogin_window_cols = -1;
static int ett_rlogin_window_x_pixels = -1;
static int ett_rlogin_window_y_pixels = -1;

static int hf_user_info = -1;
static int hf_client_startup_flag = -1;
static int hf_startup_info_received_flag = -1;
static int hf_user_info_client_user_name = -1;
static int hf_user_info_server_user_name = -1;
static int hf_user_info_terminal_type = -1;
static int hf_user_info_terminal_speed = -1;
static int hf_control_message = -1;
static int hf_window_info = -1;
static int hf_window_info_ss = -1;
static int hf_window_info_rows = -1;
static int hf_window_info_cols = -1;
static int hf_window_info_x_pixels = -1;
static int hf_window_info_y_pixels = -1;
static int hf_data = -1;

static const value_string control_message_vals[] =
{
    { 0x02,     "Clear buffer"        },
    { 0x10,     "Raw mode"            },
    { 0x20,     "Cooked mode"         },
    { 0x80,     "Window size request" },
    { 0, NULL }
};


typedef enum  {
	NONE=0,
	USER_INFO_WAIT=1,
	DONE=2
} session_state_t;

#define NAME_LEN 32
typedef struct {
	session_state_t  state;
	guint32          info_framenum;
	char             user_name[NAME_LEN];
} rlogin_hash_entry_t;



/* Decoder State Machine.  Currently only used to snoop on
   client-user-name as sent by the client up connection establishment.
*/
static void
rlogin_state_machine(rlogin_hash_entry_t *hash_info, tvbuff_t *tvb, packet_info *pinfo)
{
	guint length;
	gint stringlen;

	/* Won't change state if already seen this packet */
	if (pinfo->fd->flags.visited)
	{
		return;
	}

	/* rlogin stream decoder */
	/* Just watch for the second packet from client with the user name and */
	/* terminal type information. */

	if (pinfo->destport != RLOGIN_PORT)
	{
		return;
	}

	/* exit if already passed username in conversation */
	if (hash_info->state == DONE)
	{
		return;
	}

	/* exit if no data */
	length = tvb_length(tvb);
	if (length == 0)
	{
		return;
	}

	if (hash_info->state == NONE)
	{
		/* new connection*/
		if (tvb_get_guint8(tvb, 0) != '\0')
		{
			/* We expected a null, but didn't get one; quit. */
			hash_info->state = DONE;
			return;
		}
		else
		{
			if (length <= 1)
			{
				/* Still waiting for data */
				hash_info->state = USER_INFO_WAIT;
			}
			else
			{
				/* Have info, store frame number */
				hash_info->state = DONE;
				hash_info->info_framenum = pinfo->fd->num;
			}
		}
	}
	/* expect user data here */
	/* TODO: may need to do more checking here? */
	else
	if (hash_info->state == USER_INFO_WAIT)
	{
		/* Store frame number here */
		hash_info->state = DONE;
		hash_info->info_framenum = pinfo->fd->num;

		/* Work out length of string to copy */
		stringlen = tvb_strnlen(tvb, 0, NAME_LEN);
		if (stringlen == -1)
			stringlen = NAME_LEN - 1;   /* no '\0' found */
		else if (stringlen > NAME_LEN - 1)
			stringlen = NAME_LEN - 1;   /* name too long */

		/* Copy and terminate string into hash name */
		tvb_memcpy(tvb, (guint8 *)hash_info->user_name, 0, stringlen);
		hash_info->user_name[stringlen] = '\0';

		col_append_str(pinfo->cinfo, COL_INFO, ", (User information)");
	}
}

/* Dissect details of packet */
static void rlogin_display(rlogin_hash_entry_t *hash_info,
                           tvbuff_t *tvb,
                           packet_info *pinfo,
                           proto_tree *tree,
                           struct tcpinfo *tcpinfo)
{
	/* Display the proto tree */
	int             offset = 0;
	proto_tree      *rlogin_tree, *user_info_tree, *window_tree;
	proto_item      *ti;
	guint           length;
	int             str_len;
	gint            ti_offset;
	proto_item      *user_info_item, *window_info_item;

	/* Create rlogin subtree */
	ti = proto_tree_add_item(tree, proto_rlogin, tvb, 0, -1, FALSE);
	rlogin_tree = proto_item_add_subtree(ti, ett_rlogin);

	/* Return if data empty */
	length = tvb_length(tvb);
	if (length == 0)
	{
		return;
	}

	/*
	 * XXX - this works only if the urgent pointer points to something
	 * in this segment; to make it work if the urgent pointer points
	 * to something past this segment, we'd have to remember the urgent
	 * pointer setting for this conversation.
	 */
	if (tcpinfo->urgent &&                 /* if urgent pointer set */
	    length >= tcpinfo->urgent_pointer) /* and it's in this frame */
	{
		/* Get urgent byte into Temp */
		int urgent_offset = tcpinfo->urgent_pointer - 1;
		guint8 control_byte;

		/* Check for text data in front */
		if (urgent_offset > offset)
		{
			proto_tree_add_item(rlogin_tree, hf_data, tvb, offset, urgent_offset, ENC_ASCII|ENC_NA);
		}

		/* Show control byte */
		proto_tree_add_item(rlogin_tree, hf_control_message, tvb,
		                    urgent_offset, 1, ENC_BIG_ENDIAN);
		control_byte = tvb_get_guint8(tvb, urgent_offset);
		if (check_col(pinfo->cinfo, COL_INFO))
		{
			col_append_fstr(pinfo->cinfo, COL_INFO,
			               " (%s)", val_to_str(control_byte, control_message_vals, "Unknown"));
		}

		offset = urgent_offset + 1; /* adjust offset */
	}
	else
	if (tvb_get_guint8(tvb, offset) == '\0')
	{
		/* Startup */
		if (pinfo->srcport == RLOGIN_PORT)   /* from server */
		{
			proto_tree_add_item(rlogin_tree, hf_startup_info_received_flag,
			                    tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		else
		{
			proto_tree_add_item(rlogin_tree, hf_client_startup_flag,
			                    tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		++offset;
	}

	if (!tvb_offset_exists(tvb, offset))
	{
		/* No more data to check */
		return;
	}

	if (hash_info->info_framenum == pinfo->fd->num)
	{
		gint info_len;
		gint slash_offset;

		/* First frame of conversation, assume user info... */

		info_len = tvb_length_remaining(tvb, offset);

		/* User info tree */
		user_info_item = proto_tree_add_string_format(rlogin_tree, hf_user_info, tvb,
		                                              offset, info_len, FALSE,
		                                              "User info (%s)",
		                                              tvb_format_text(tvb, offset, info_len));
		user_info_tree = proto_item_add_subtree(user_info_item,
		                                        ett_rlogin_user_info);

		/* Client user name. */
		str_len = tvb_strsize(tvb, offset);
		proto_tree_add_item(user_info_tree, hf_user_info_client_user_name,
		                    tvb, offset, str_len, ENC_ASCII|ENC_NA);
		offset += str_len;

		/* Server user name. */
		str_len = tvb_strsize(tvb, offset);
		proto_tree_add_item(user_info_tree, hf_user_info_server_user_name,
		                    tvb, offset, str_len, ENC_ASCII|ENC_NA);
		offset += str_len;

		/* Terminal type/speed. */
		slash_offset = tvb_find_guint8(tvb, offset, -1, '/');
		if (slash_offset != -1)
		{
			/* Terminal type */
			proto_tree_add_item(user_info_tree, hf_user_info_terminal_type,
			                    tvb, offset, slash_offset-offset, ENC_ASCII|ENC_NA);
			offset = slash_offset + 1;

			/* Terminal speed */
			str_len = tvb_strsize(tvb, offset);
			proto_tree_add_uint(user_info_tree, hf_user_info_terminal_speed,
			                    tvb, offset, str_len,
			                    atoi(tvb_format_text(tvb, offset, str_len)));
			offset += str_len;
		}
	}

	if (!tvb_offset_exists(tvb, offset))
	{
		/* No more data to check */
		return;
	}

	/* Test for terminal information, the data will have 2 0xff bytes */
	/* look for first 0xff byte */
	ti_offset = tvb_find_guint8(tvb, offset, -1, 0xff);

	/* Next byte must also be 0xff */
	if (ti_offset != -1 &&
	    tvb_bytes_exist(tvb, ti_offset + 1, 1) &&
	    tvb_get_guint8(tvb, ti_offset + 1) == 0xff)
	{
		guint16 rows, columns;

		/* Have found terminal info. */
		if (ti_offset > offset)
		{
			/* There's data before the terminal info. */
			proto_tree_add_item(rlogin_tree, hf_data, tvb,
			                    offset, ti_offset - offset, ENC_ASCII|ENC_NA);
		}

		/* Create window info tree */
		window_info_item =
			proto_tree_add_item(rlogin_tree, hf_window_info, tvb, offset, 12, ENC_NA);
		window_tree = proto_item_add_subtree(window_info_item, ett_rlogin_window);

		/* Cookie */
		proto_tree_add_text(window_tree, tvb, offset, 2, "Magic Cookie: (0xff, 0xff)");
		offset += 2;

		/* These bytes should be "ss" */
		proto_tree_add_item(window_tree, hf_window_info_ss, tvb, offset, 2, ENC_ASCII|ENC_NA);
		offset += 2;

		/* Character rows */
		rows = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(window_tree, hf_window_info_rows, tvb,
		                    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* Characters per row */
		columns = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(window_tree, hf_window_info_cols, tvb,
		                    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* x pixels */
		proto_tree_add_item(window_tree, hf_window_info_x_pixels, tvb,
		                    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* y pixels */
		proto_tree_add_item(window_tree, hf_window_info_y_pixels, tvb,
		                    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* Show setting highlights in info column */
		if (check_col(pinfo->cinfo, COL_INFO))
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, " (rows=%u, cols=%u)",
			                rows, columns);
		}
	}

	if (tvb_offset_exists(tvb, offset))
	{
		/* There's more data in the frame. */
		proto_tree_add_item(rlogin_tree, hf_data, tvb, offset, -1, ENC_ASCII|ENC_NA);
	}
}


/****************************************************************
 * Main dissection function
 ****************************************************************/
static void
dissect_rlogin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct tcpinfo *tcpinfo = pinfo->private_data;
	conversation_t *conversation;
	rlogin_hash_entry_t *hash_info;
	guint length;
	gint ti_offset;

	/* Get or create conversation */
	conversation = find_or_create_conversation(pinfo);

	/* Get or create data associated with this conversation */
	hash_info = conversation_get_proto_data(conversation, proto_rlogin);
	if (!hash_info)
	{
		/* Populate new data struct... */
		hash_info = se_alloc(sizeof(rlogin_hash_entry_t));
		hash_info->state = NONE;
		hash_info->info_framenum = 0;  /* no frame has the number 0 */
		hash_info->user_name[0] = '\0';

		/* ... and store in conversation */
		conversation_add_proto_data(conversation, proto_rlogin, hash_info);
	}

	/* Set protocol column text */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Rlogin");

	/* Set info column */
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		/* Show user-name if available */
		if (hash_info->user_name[0])
		{
			col_add_fstr(pinfo->cinfo, COL_INFO,
			              "User name: %s, ", hash_info->user_name);
		}
		else
		{
			col_clear(pinfo->cinfo, COL_INFO);
		}

		/* Work out packet content summary for display */
		length = tvb_length(tvb);
		if (length != 0)
		{
			/* Initial NULL byte represents part of connection handshake */
			if (tvb_get_guint8(tvb, 0) == '\0')
			{
				col_append_str(pinfo->cinfo, COL_INFO,
				               (pinfo->destport == RLOGIN_PORT) ?
				                   "Start Handshake" :
				                   "Startup info received");
			}
			else
			if (tcpinfo->urgent && length >= tcpinfo->urgent_pointer)
			{
				/* Urgent pointer inside current data represents a control message */
				col_append_str(pinfo->cinfo, COL_INFO, "Control Message");
			}
			else
			{
				/* Search for 2 consecutive ff bytes
				  (signifies window change control message) */
				ti_offset = tvb_find_guint8(tvb, 0, -1, 0xff);
				if (ti_offset != -1 &&
				    tvb_bytes_exist(tvb, ti_offset + 1, 1) &&
				    tvb_get_guint8(tvb, ti_offset + 1) == 0xff)
				{
					col_append_str(pinfo->cinfo, COL_INFO, "Terminal Info");
				}
				else
				{
					/* Show any text data in the frame */
					int bytes_to_copy = tvb_length(tvb);
					if (bytes_to_copy > 128)
					{
						/* Truncate to 128 bytes for display */
						bytes_to_copy = 128;
					}

					/* Add data into info column */
					col_append_fstr(pinfo->cinfo, COL_INFO,
					                "Data: %s",
					                 tvb_format_text(tvb, 0, bytes_to_copy));
				}
			}
		}
	}

	/* See if conversation state needs to be updated */
	rlogin_state_machine(hash_info, tvb, pinfo);

	/* Dissect in detail */
	rlogin_display(hash_info, tvb, pinfo, tree, tcpinfo);
}


void proto_register_rlogin(void)
{
	static gint *ett[] = {
		&ett_rlogin,
		&ett_rlogin_window,
		&ett_rlogin_window_rows,
		&ett_rlogin_window_cols,
		&ett_rlogin_window_x_pixels,
		&ett_rlogin_window_y_pixels,
		&ett_rlogin_user_info
	};

	static hf_register_info hf[] =
	{
		{ &hf_user_info,
			{ "User Info", "rlogin.user_info", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_client_startup_flag,
			{ "Client startup flag", "rlogin.client_startup_flag", FT_UINT8, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_startup_info_received_flag,
			{ "Startup info received flag", "rlogin.startup_info_received_flag", FT_UINT8, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_user_info_client_user_name,
			{ "Client-user-name", "rlogin.client_user_name", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_user_info_server_user_name,
			{ "Server-user-name", "rlogin.server_user_name", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_user_info_terminal_type,
			{ "Terminal-type", "rlogin.terminal_type", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_user_info_terminal_speed,
			{ "Terminal-speed", "rlogin.terminal_speed", FT_UINT32, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_control_message,
			{ "Control message", "rlogin.control_message", FT_UINT8, BASE_HEX,
				 VALS(control_message_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info,
			{ "Window Info", "rlogin.window_size", FT_NONE, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info_ss,
			{ "Window size marker", "rlogin.window_size.ss", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info_rows,
			{ "Rows", "rlogin.window_size.rows", FT_UINT16, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info_cols,
			{ "Columns", "rlogin.window_size.cols", FT_UINT16, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info_x_pixels,
			{ "X Pixels", "rlogin.window_size.x_pixels", FT_UINT16, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info_y_pixels,
			{ "Y Pixels", "rlogin.window_size.y_pixels", FT_UINT16, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_data,
			{ "Data", "rlogin.data", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		}
	};

	proto_rlogin = proto_register_protocol("Rlogin Protocol", "Rlogin", "rlogin");

	proto_register_field_array(proto_rlogin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_rlogin(void)
{
	/* Dissector install routine */
	dissector_handle_t rlogin_handle = create_dissector_handle(dissect_rlogin,proto_rlogin);
	dissector_add_uint("tcp.port", RLOGIN_PORT, rlogin_handle);
}
