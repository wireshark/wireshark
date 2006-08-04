/* packet-exec.c
 * Routines for exec (rexec) dissection
 * Copyright 2006, Stephen Fisher <stephentfisher@yahoo.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Based on BSD rexecd code/man page and parts of packet-rlogin.c
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
#include <string.h>
#include <ctype.h>

#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/prefs.h>

/* The exec protocol uses TCP port 512 per its IANA assignment */
#define EXEC_PORT 512

/* Forward declaration we need below */
void proto_reg_handoff_exec(void);
gboolean exec_isprint_string(gchar *string);
gboolean exec_isdigit_string(gchar *string);

/* Variables for our preferences */
static gboolean preference_info_show_username = TRUE;
static gboolean preference_info_show_command = FALSE;

/* Initialize the protocol and registered fields */
static int proto_exec = -1;

static int hf_exec_stderr_port = -1;
static int hf_exec_username    = -1;
static int hf_exec_password    = -1;
static int hf_exec_command     = -1;

/* Initialize the subtree pointers */
static gint ett_exec = -1;

#define EXEC_STDERR_PORT_LEN 5
#define EXEC_USERNAME_LEN 16
#define EXEC_PASSWORD_LEN 16
#define EXEC_COMMAND_LEN 256 /* Longer depending on server operating system? */

/* Initialize the structure that will be tied to each conversation.
 * This is used to display the username and/or command in the INFO column of
 * each packet of the conversation. */

typedef enum {
	NONE                 = 0,
	WAIT_FOR_STDERR_PORT = 1,
	WAIT_FOR_USERNAME    = 2,
	WAIT_FOR_PASSWORD    = 3,
	WAIT_FOR_COMMAND     = 4,
	WAIT_FOR_DATA        = 5
} exec_session_state_t;
    

typedef struct {
	/* Packet number within the conversation */
	guint first_packet_number, second_packet_number;
	guint third_packet_number, forth_packet_number;

	/* The following variables are given values from session_state_t
	 * above to keep track of where we are in the beginning of the session
	 * (when the username and other fields show up).  This is necessary for
	 * when the user clicks randomly through the initial packets instead of
	 * going in order.
	 */

	/* Track where we are in the conversation */
	exec_session_state_t state;
	exec_session_state_t first_packet_state, second_packet_state;
	exec_session_state_t third_packet_state, forth_packet_state;

	gchar *username;
	gchar *command;
} exec_hash_entry_t;


static void
dissect_exec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *exec_tree=NULL;

	/* Variables for extracting and displaying data from the packet */
	gchar *field_stringz; /* Temporary storage for each field we extract */

	gint length;
	guint offset = 0;
	conversation_t *conversation;
	exec_hash_entry_t *hash_info;

	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

	if(!conversation){  /* Conversation does not exist yet - create it */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}


	/* Retrieve information from conversation 
	 * or add it if it isn't there yet
	 */
	hash_info = conversation_get_proto_data(conversation, proto_exec);
	if(!hash_info){
		hash_info = se_alloc(sizeof(exec_hash_entry_t));
      
		hash_info->first_packet_number = pinfo->fd->num;
		hash_info->second_packet_number = 0;
		hash_info->third_packet_number  = 0;
		hash_info->forth_packet_number  = 0;

		hash_info->state = WAIT_FOR_STDERR_PORT; /* The first field we'll see */

		/* Start with empty username and command strings */
		hash_info->username=NULL;
		hash_info->command=NULL;

		/* These will be set on the first pass by the first 
		 * four packets of the conversation
		 */
		hash_info->first_packet_state  = NONE;
		hash_info->second_packet_state = NONE;
		hash_info->third_packet_state  = NONE;
		hash_info->forth_packet_state  = NONE;

		conversation_add_proto_data(conversation, proto_exec, hash_info);
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
	 && !hash_info->forth_packet_number
	 && pinfo->fd->num > hash_info->third_packet_number) {
		/* We're on the forth packet of the conversation */
		hash_info->forth_packet_number = pinfo->fd->num;
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
      
	if(pinfo->fd->num == hash_info->forth_packet_number){
		if(hash_info->forth_packet_state == NONE){
			hash_info->forth_packet_state = hash_info->state;
		} else {
			hash_info->state = hash_info->forth_packet_state;
		}
	}

	if(check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "EXEC");

	if(check_col(pinfo->cinfo, COL_INFO)){
		/* First, clear the info column */
		col_clear(pinfo->cinfo, COL_INFO);

		/*username */
		if(hash_info->username && preference_info_show_username == TRUE){
			col_append_fstr(pinfo->cinfo, COL_INFO, "Username:%s ", hash_info->username);
		}
      
		/* Command */
		if(hash_info->command && preference_info_show_command == TRUE){
			col_append_fstr(pinfo->cinfo, COL_INFO, "Command:%s ", hash_info->command);
		}
	}
  
	/* create display subtree for the protocol */
	ti = proto_tree_add_item(tree, proto_exec, tvb, 0, -1, FALSE);
	exec_tree = proto_item_add_subtree(ti, ett_exec);

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
		if(length == 1 || (exec_isdigit_string(field_stringz)
		&& length <= EXEC_STDERR_PORT_LEN)){
			proto_tree_add_string(exec_tree, hf_exec_stderr_port, tvb, offset, length, field_stringz);
			 /* Next field we need */
			hash_info->state = WAIT_FOR_USERNAME;
		} else { 
			/* Since the data doesn't match this field, it must be data only */
			hash_info->state = WAIT_FOR_DATA;
		}
       
		/* Used if the next field is in the same packet */
		offset += length;
	}
  
 
	if(hash_info->state == WAIT_FOR_USERNAME
	&& tvb_length_remaining(tvb, offset)){
		field_stringz = tvb_get_ephemeral_stringz(tvb, offset, &length);
	  
		/* Check if this looks like the username field */
		if(length != 1 && length <= EXEC_USERNAME_LEN
		&& exec_isprint_string(field_stringz)){
			proto_tree_add_string(exec_tree, hf_exec_username, tvb, offset, length, field_stringz);

			/* Store the username so we can display it in the 
			 * info column of the entire conversation
			 */
			if(!hash_info->username){
				hash_info->username=se_strdup(field_stringz);
			}

			 /* Next field we need */
			hash_info->state = WAIT_FOR_PASSWORD;
		} else { 
			/* Since the data doesn't match this field, it must be data only */
			hash_info->state = WAIT_FOR_DATA;
		}
 
		/* Used if the next field is in the same packet */
		offset += length;
	}
      

	if(hash_info->state == WAIT_FOR_PASSWORD
	&& tvb_length_remaining(tvb, offset)){
		field_stringz = tvb_get_ephemeral_stringz(tvb, offset, &length);
	  
		/* Check if this looks like the password field */
		if(length != 1 && length <= EXEC_PASSWORD_LEN
		&& exec_isprint_string(field_stringz)){
			proto_tree_add_string(exec_tree, hf_exec_password, tvb, offset, length, field_stringz);

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
		if(length != 1 && length <= EXEC_COMMAND_LEN
		&& exec_isprint_string(field_stringz)){
			proto_tree_add_string(exec_tree, hf_exec_command, tvb, offset, length, field_stringz);
	      
			/* Store the username so we can display it in the 
			 * info column of the entire conversation
			 */
			if(!hash_info->command){
				hash_info->command=se_strdup(field_stringz);
			}

		} else {
			/* Since the data doesn't match this field, it must be data only */
			hash_info->state = WAIT_FOR_DATA;
		}
	}

  
	if(hash_info->state == WAIT_FOR_DATA
	&& tvb_length_remaining(tvb, offset)){
		if(pinfo->destport == EXEC_PORT){
			/* Packet going to the server */
			/* offset = 0 since the whole packet is data */
			proto_tree_add_text(exec_tree, tvb, 0, -1, "Client -> Server Data");
	  
			if(check_col(pinfo->cinfo, COL_INFO))
				col_append_str(pinfo->cinfo, COL_INFO, "Client -> Server data");
		} else {
			/* This packet must be going back to the client */
			/* offset = 0 since the whole packet is data */
			proto_tree_add_text(exec_tree, tvb, 0, -1, "Server -> Client Data");
	  
			if(check_col(pinfo->cinfo, COL_INFO))
				col_append_str(pinfo->cinfo, COL_INFO, "Server -> Client Data");
		}
	}

	/* We haven't seen all of the fields yet */
	if(hash_info->state < WAIT_FOR_DATA){
		if(check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Session Establishment");
	}
}

void
proto_register_exec(void)
{
	static hf_register_info hf[] =
	{
	{ &hf_exec_stderr_port, { "Stderr port (optional)", "exec.stderr_port",
		FT_STRINGZ, BASE_NONE, NULL, 0,
		"Client port that is listening for stderr stream from server", HFILL } },
      
	{ &hf_exec_username, { "Client username", "exec.username",
		FT_STRINGZ, BASE_NONE, NULL, 0,
		"Username client uses to log in to the server.", HFILL } },
      
	{ &hf_exec_password, { "Client password", "exec.password",
		FT_STRINGZ, BASE_NONE, NULL, 0,
		"Password client uses to log in to the server.", HFILL } },
      
	{ &hf_exec_command, { "Command to execute", "exec.command",
		FT_STRINGZ, BASE_NONE, NULL, 0,
		"Command client is requesting the server to run.", HFILL } }

	};

	static gint *ett[] = 
	{ 
		&ett_exec 
	};

	module_t *exec_module;

	/* Register the protocol name and description */
	proto_exec = proto_register_protocol("Remote Process Execution", "EXEC", "exec");
  
	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_exec, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register preferences module */
	exec_module = prefs_register_protocol(proto_exec, proto_reg_handoff_exec);

	/* Register our preferences */
	prefs_register_bool_preference(exec_module, "info_show_username",
		 "Show username in info column?",
		 "Controls the display of the session's username in the info column.  This is only displayed if the packet containing it was seen during this capture session.", &preference_info_show_username);

	prefs_register_bool_preference(exec_module, "info_show_command",
		 "Show command in info column?",
		 "Controls the display of the command being run on the server by this session in the info column.  This is only displayed if the packet containing it was seen during this capture session.", &preference_info_show_command);

}


/* Entry function */
void
proto_reg_handoff_exec(void)
{
	dissector_handle_t exec_handle;

	exec_handle = create_dissector_handle(dissect_exec, proto_exec);
	dissector_add("tcp.port", EXEC_PORT, exec_handle);
}

/* Custom function to check if an entire string is printable. */
gboolean
exec_isprint_string(gchar *string)
{
	guint position;

	/* Loop until we reach the end of the string (a null) */
	for(position = 0; string[position] != '\0'; position++){
		if(!isprint(string[position])){
			/* The string contains a non-printable character */
			return FALSE;
		}
	}

	/* The string contains only printable characters */
	return TRUE;
}

/* Custom function to check if an entire string is digits. */
gboolean
exec_isdigit_string(gchar *string)
{
	guint position;

	/* Loop until we reach the end of the string (a null) */
	for(position = 0; string[position] != '\0'; position++){
		if(!isdigit(string[position])){
			/* The string contains a non-digit character */
			return FALSE;
		}
	}

	/* The string contains only digits */
	return TRUE;
}
