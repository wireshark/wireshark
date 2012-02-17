/* packet-rsh.c
 * Routines for rsh (Remote Shell) dissection
 * Copyright 2012, Stephen Fisher (see AUTHORS file)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This dissector is a modified copy of packet-exec.c due to
 * protocol similarities and replaces the original rsh dissector
 * by Robert Tsai <rtsai@netapp.com>.  It is further based on BSD's
 * rshd code and man page.
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/str_util.h>

/* The rsh protocol uses TCP port 512 per its IANA assignment */
#define RSH_PORT 514

/* Variables for our preferences */
static gboolean preference_info_show_client_username = FALSE;
static gboolean preference_info_show_server_username = TRUE;
static gboolean preference_info_show_command = FALSE;

/* Initialize the protocol and registered fields */
static int proto_rsh = -1;

static int hf_rsh_stderr_port     = -1;
static int hf_rsh_client_username = -1;
static int hf_rsh_server_username = -1;
static int hf_rsh_command         = -1;

/* Initialize the subtree pointers */
static gint ett_rsh = -1;

#define RSH_STDERR_PORT_LEN 5
#define RSH_CLIENT_USERNAME_LEN 16
#define RSH_SERVER_USERNAME_LEN 16
#define RSH_COMMAND_LEN 256 /* Based on the size of the system's argument list */

/* Initialize the structure that will be tied to each conversation.
 * This is used to display the username and/or command in the INFO column of
 * each packet of the conversation. */

typedef enum {
	NONE,
	WAIT_FOR_STDERR_PORT,
	WAIT_FOR_CLIENT_USERNAME,
	WAIT_FOR_SERVER_USERNAME,
	WAIT_FOR_COMMAND,
	WAIT_FOR_DATA
} rsh_session_state_t;


typedef struct {
	/* Packet number within the conversation */
	guint first_packet_number, second_packet_number;
	guint third_packet_number, fourth_packet_number;

	/* The following variables are given values from session_state_t
	 * above to keep track of where we are in the beginning of the session
	 * (when the username and other fields show up).  This is necessary for
	 * when the user clicks randomly through the initial packets instead of
	 * going in order.
	 */

	/* Track where we are in the conversation */
	rsh_session_state_t state;
	rsh_session_state_t first_packet_state, second_packet_state;
	rsh_session_state_t third_packet_state, fourth_packet_state;

	gchar *client_username;
	gchar *server_username;
	gchar *command;
} rsh_hash_entry_t;


static void
dissect_rsh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *rsh_tree=NULL;

	/* Variables for extracting and displaying data from the packet */
	guchar *field_stringz; /* Temporary storage for each field we extract */

	gint length;
	guint offset = 0;
	conversation_t *conversation;
	rsh_hash_entry_t *hash_info;

	conversation = find_or_create_conversation(pinfo);

	/* Retrieve information from conversation
	 * or add it if it isn't there yet
	 */
	hash_info = conversation_get_proto_data(conversation, proto_rsh);
	if(!hash_info){
		hash_info = se_alloc(sizeof(rsh_hash_entry_t));

		hash_info->first_packet_number = pinfo->fd->num;
		hash_info->second_packet_number = 0;
		hash_info->third_packet_number  = 0;
		hash_info->fourth_packet_number  = 0;

		hash_info->state = WAIT_FOR_STDERR_PORT; /* The first field we'll see */

		/* Start with empty username and command strings */
		hash_info->client_username=NULL;
		hash_info->server_username=NULL;
		hash_info->command=NULL;

		/* These will be set on the first pass by the first
		 * four packets of the conversation
		 */
		hash_info->first_packet_state  = NONE;
		hash_info->second_packet_state = NONE;
		hash_info->third_packet_state  = NONE;
		hash_info->fourth_packet_state  = NONE;

		conversation_add_proto_data(conversation, proto_rsh, hash_info);
	}

	/* Store the number of the first three packets of this conversation
	 * as we reach them the first time */

	if(!hash_info->second_packet_number
	&& pinfo->fd->num > hash_info->first_packet_number){
		/* We're on the second packet of the conversation */
		hash_info->second_packet_number = pinfo->fd->num;
	} else if(hash_info->second_packet_number
	 && !hash_info->third_packet_number
	 && pinfo->fd->num > hash_info->second_packet_number) {
		/* We're on the third packet of the conversation */
		hash_info->third_packet_number = pinfo->fd->num;
	} else if(hash_info->third_packet_number
	 && !hash_info->fourth_packet_number
	 && pinfo->fd->num > hash_info->third_packet_number) {
		/* We're on the fourth packet of the conversation */
		hash_info->fourth_packet_number = pinfo->fd->num;
	}

	/* Save this packet's state so we can retrieve it if this packet
	 * is selected again later.  If the packet's state was already stored,
	 * then retrieve it */
	if(pinfo->fd->num == hash_info->first_packet_number){
		if(hash_info->first_packet_state == NONE){
			hash_info->first_packet_state = hash_info->state;
		} else {
			hash_info->state = hash_info->first_packet_state;
		}
	}

	if(pinfo->fd->num == hash_info->second_packet_number){
		if(hash_info->second_packet_state == NONE){
			hash_info->second_packet_state = hash_info->state;
		} else {
			hash_info->state = hash_info->second_packet_state;
		}
	}

	if(pinfo->fd->num == hash_info->third_packet_number){
		if(hash_info->third_packet_state == NONE){
			hash_info->third_packet_state = hash_info->state;
		} else {
			hash_info->state = hash_info->third_packet_state;
		}
	}

	if(pinfo->fd->num == hash_info->fourth_packet_number){
		if(hash_info->fourth_packet_state == NONE){
			hash_info->fourth_packet_state = hash_info->state;
		} else {
			hash_info->state = hash_info->fourth_packet_state;
		}
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSH");

	if(check_col(pinfo->cinfo, COL_INFO)){
		/* First, clear the info column */
		col_clear(pinfo->cinfo, COL_INFO);

		/* Client username */
		if(hash_info->client_username && preference_info_show_client_username == TRUE){
			col_append_fstr(pinfo->cinfo, COL_INFO, "Client username:%s ", hash_info->client_username);
		}

		/* Server username */
		if(hash_info->server_username && preference_info_show_server_username == TRUE){
			col_append_fstr(pinfo->cinfo, COL_INFO, "Server username:%s ", hash_info->server_username);
		}

		/* Command */
		if(hash_info->command && preference_info_show_command == TRUE){
			col_append_fstr(pinfo->cinfo, COL_INFO, "Command:%s ", hash_info->command);
		}
	}

	/* create display subtree for the protocol */
	ti = proto_tree_add_item(tree, proto_rsh, tvb, 0, -1, ENC_NA);
	rsh_tree = proto_item_add_subtree(ti, ett_rsh);

	/* If this packet doesn't end with a null terminated string,
	 * then it must be session data only and we can skip looking
	 * for the other fields.
	 */
	if(tvb_find_guint8(tvb, tvb_length(tvb)-1, 1, '\0') == -1){
		hash_info->state = WAIT_FOR_DATA;
	}

	if(hash_info->state == WAIT_FOR_STDERR_PORT
	&& tvb_length_remaining(tvb, offset)){
		field_stringz = tvb_get_ephemeral_stringz(tvb, offset, &length);

		/* Check if this looks like the stderr_port field.
		 * It is optional, so it may only be 1 character long
		 * (the NULL)
		 */
		if(length == 1 || (isdigit_string(field_stringz)
		&& length <= RSH_STDERR_PORT_LEN)){
			proto_tree_add_string(rsh_tree, hf_rsh_stderr_port, tvb, offset, length, (gchar*)field_stringz);
			 /* Next field we need */
			hash_info->state = WAIT_FOR_CLIENT_USERNAME;
		} else {
			/* Since the data doesn't match this field, it must be data only */
			hash_info->state = WAIT_FOR_DATA;
		}

		/* Used if the next field is in the same packet */
		offset += length;
	}


	if(hash_info->state == WAIT_FOR_CLIENT_USERNAME
	&& tvb_length_remaining(tvb, offset)){
		field_stringz = tvb_get_ephemeral_stringz(tvb, offset, &length);

		/* Check if this looks like the username field */
		if(length != 1 && length <= RSH_CLIENT_USERNAME_LEN
		&& isprint_string(field_stringz)){
			proto_tree_add_string(rsh_tree, hf_rsh_client_username, tvb, offset, length, (gchar*)field_stringz);

			/* Store the client username so we can display it in the
			 * info column of the entire conversation
			 */
			if(!hash_info->client_username){
				hash_info->client_username=se_strdup((gchar*)field_stringz);
			}

			 /* Next field we need */
			hash_info->state = WAIT_FOR_SERVER_USERNAME;
		} else {
			/* Since the data doesn't match this field, it must be data only */
			hash_info->state = WAIT_FOR_DATA;
		}

		/* Used if the next field is in the same packet */
		offset += length;
	}


	if(hash_info->state == WAIT_FOR_SERVER_USERNAME
	&& tvb_length_remaining(tvb, offset)){
		field_stringz = tvb_get_ephemeral_stringz(tvb, offset, &length);

		/* Check if this looks like the password field */
		if(length != 1 && length <= RSH_SERVER_USERNAME_LEN
		&& isprint_string(field_stringz)){
			proto_tree_add_string(rsh_tree, hf_rsh_server_username, tvb, offset, length, (gchar*)field_stringz);

			/* Store the server username so we can display it in the
			 * info column of the entire conversation
			 */
			if(!hash_info->server_username){
				hash_info->server_username=se_strdup((gchar*)field_stringz);
			}

			/* Next field we need */
			hash_info->state = WAIT_FOR_COMMAND;
		} else {
			/* Since the data doesn't match this field, it must be data only */
			hash_info->state = WAIT_FOR_DATA;
		}

		/* Used if the next field is in the same packet */
		offset += length;
		 /* Next field we are looking for */
		hash_info->state = WAIT_FOR_COMMAND;
	}


	if(hash_info->state == WAIT_FOR_COMMAND
	&& tvb_length_remaining(tvb, offset)){
		field_stringz = tvb_get_ephemeral_stringz(tvb, offset, &length);

		/* Check if this looks like the command field */
		if(length != 1 && length <= RSH_COMMAND_LEN
		&& isprint_string(field_stringz)){
			proto_tree_add_string(rsh_tree, hf_rsh_command, tvb, offset, length, (gchar*)field_stringz);

			/* Store the command so we can display it in the
			 * info column of the entire conversation
			 */
			if(!hash_info->command){
				hash_info->command=se_strdup((gchar*)field_stringz);
			}

		} else {
			/* Since the data doesn't match this field, it must be data only */
			hash_info->state = WAIT_FOR_DATA;
		}
	}


	if(hash_info->state == WAIT_FOR_DATA
	&& tvb_length_remaining(tvb, offset)){
		if(pinfo->destport == RSH_PORT){
			/* Packet going to the server */
			/* offset = 0 since the whole packet is data */
			proto_tree_add_text(rsh_tree, tvb, 0, -1, "Client -> Server Data");

			col_append_str(pinfo->cinfo, COL_INFO, "Client -> Server data");
		} else {
			/* This packet must be going back to the client */
			/* offset = 0 since the whole packet is data */
			proto_tree_add_text(rsh_tree, tvb, 0, -1, "Server -> Client Data");

			col_append_str(pinfo->cinfo, COL_INFO, "Server -> Client Data");
		}
	}

	/* We haven't seen all of the fields yet */
	if(hash_info->state < WAIT_FOR_DATA){
		col_set_str(pinfo->cinfo, COL_INFO, "Session Establishment");
	}
}

void
proto_register_rsh(void)
{
	static hf_register_info hf[] =
	{
	{ &hf_rsh_stderr_port, { "Stderr port (optional)", "rsh.stderr_port",
		FT_STRINGZ, BASE_NONE, NULL, 0,
		"Client port that is listening for stderr stream from server", HFILL } },

	{ &hf_rsh_client_username, { "Client username", "rsh.client_username",
		FT_STRINGZ, BASE_NONE, NULL, 0,
		"User's identity on the client machine", HFILL } },

	{ &hf_rsh_server_username, { "Server username", "rsh.server_username",
		FT_STRINGZ, BASE_NONE, NULL, 0,
		"User's identity on the server machine", HFILL } },

	{ &hf_rsh_command, { "Command to execute", "rsh.command",
		FT_STRINGZ, BASE_NONE, NULL, 0,
		"Command client is requesting the server to run", HFILL } }

	};

	static gint *ett[] =
	{
		&ett_rsh
	};

	module_t *rsh_module;

	/* Register the protocol name and description */
	proto_rsh = proto_register_protocol("Remote Shell", "RSH", "rsh");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_rsh, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register preferences module */
	rsh_module = prefs_register_protocol(proto_rsh, NULL);

	/* Register our preferences */
	prefs_register_bool_preference(rsh_module, "info_show_client_username",
		 "Show client username in info column",
		 "Controls the display of the session's client username in the info column.  This is only displayed if the packet containing it was seen during this capture session.", &preference_info_show_client_username);

	prefs_register_bool_preference(rsh_module, "info_show_server_username",
		 "Show server username in info column",
		 "Controls the display of the session's server username in the info column.  This is only displayed if the packet containing it was seen during this capture session.", &preference_info_show_server_username);

	prefs_register_bool_preference(rsh_module, "info_show_command",
		 "Show command in info column",
		 "Controls the display of the command being run on the server by this session in the info column.  This is only displayed if the packet containing it was seen during this capture session.", &preference_info_show_command);
}


/* Entry function */
void
proto_reg_handoff_rsh(void)
{
	dissector_handle_t rsh_handle;

	rsh_handle = create_dissector_handle(dissect_rsh, proto_rsh);
	dissector_add_uint("tcp.port", RSH_PORT, rsh_handle);
}
