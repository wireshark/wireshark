/* packet-quakeworld.c
 * Routines for QuakeWorld packet dissection
 *
 * Uwe Girlich <uwe@planetquake.com>
 *	http://www.idsoftware.com/q1source/q1source.zip
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-quake.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include <wsutil/strtoi.h>

void proto_register_quakeworld(void);
void proto_reg_handoff_quakeworld(void);

static int proto_quakeworld = -1;

static int hf_quakeworld_s2c = -1;
static int hf_quakeworld_c2s = -1;
static int hf_quakeworld_connectionless = -1;
static int hf_quakeworld_game = -1;
static int hf_quakeworld_connectionless_marker = -1;
static int hf_quakeworld_connectionless_text = -1;
static int hf_quakeworld_connectionless_command = -1;
static int hf_quakeworld_connectionless_arguments = -1;
static int hf_quakeworld_connectionless_connect_version = -1;
static int hf_quakeworld_connectionless_connect_qport = -1;
static int hf_quakeworld_connectionless_connect_challenge = -1;
static int hf_quakeworld_connectionless_connect_infostring = -1;
static int hf_quakeworld_connectionless_connect_infostring_key_value = -1;
static int hf_quakeworld_connectionless_connect_infostring_key = -1;
static int hf_quakeworld_connectionless_connect_infostring_value = -1;
static int hf_quakeworld_connectionless_rcon_password = -1;
static int hf_quakeworld_connectionless_rcon_command = -1;
static int hf_quakeworld_game_seq1 = -1;
static int hf_quakeworld_game_rel1 = -1;
static int hf_quakeworld_game_seq2 = -1;
static int hf_quakeworld_game_rel2 = -1;
static int hf_quakeworld_game_qport = -1;

static gint ett_quakeworld = -1;
static gint ett_quakeworld_connectionless = -1;
static gint ett_quakeworld_connectionless_text = -1;
static gint ett_quakeworld_connectionless_arguments = -1;
static gint ett_quakeworld_connectionless_connect_infostring = -1;
static gint ett_quakeworld_connectionless_connect_infostring_key_value = -1;
static gint ett_quakeworld_game = -1;
static gint ett_quakeworld_game_seq1 = -1;
static gint ett_quakeworld_game_seq2 = -1;
static gint ett_quakeworld_game_clc = -1;
static gint ett_quakeworld_game_svc = -1;

static expert_field ei_quakeworld_connectionless_command_invalid = EI_INIT;

/*
	helper functions, they may ave to go somewhere else
	they are mostly copied without change from
	  quakeworldsource/client/cmd.c
	  quakeworldsource/client/common.c
*/

#define MAX_TEXT_SIZE	2048

static const char *
COM_Parse (const char *data, int data_len, int* token_start, int* token_len)
{
	int c;
	char* com_token = (char*)wmem_alloc(wmem_packet_scope(), data_len+1);

	com_token[0] = '\0';
	*token_start = 0;
	*token_len = 0;

	if (data == NULL)
		return NULL;

	/* skip whitespace */
skipwhite:
	while (TRUE) {
		c = *data;
		if (c == '\0')
			return NULL;	/* end of file; */
		if ((c != ' ') && (!g_ascii_iscntrl(c)))
		    break;
		data++;
		(*token_start)++;
	}

	/* skip // comments */
	if ((c=='/') && (data[1]=='/')) {
		while (*data && *data != '\n'){
			data++;
			(*token_start)++;
		}
		goto skipwhite;
	}

	/* handle quoted strings specially */
	if (c == '\"') {
		data++;
		(*token_start)++;
		while (*token_len < data_len) {
			c = *data++;
			if ((c=='\"') || (c=='\0')) {
				com_token[*token_len] = '\0';
				return data;
			}
			com_token[*token_len] = c;
			(*token_len)++;
		}
	}

	if (*token_len == data_len) {
		com_token[*token_len] = '\0';
		return data;
	}

	/* parse a regular word */
	do {
		com_token[*token_len] = c;
		data++;
		(*token_len)++;
		c = *data;
	} while (( c != ' ') && (!g_ascii_iscntrl(c)) && (*token_len < data_len));

	com_token[*token_len] = '\0';
	return data;
}


#define			MAX_ARGS 80
static	int		cmd_argc = 0;
static	const char	*cmd_argv[MAX_ARGS];
static	const char	*cmd_null_string = "";
static	int		cmd_argv_start[MAX_ARGS];
static	int		cmd_argv_length[MAX_ARGS];



static int
Cmd_Argc(void)
{
	return cmd_argc;
}


static const char*
Cmd_Argv(int arg)
{
	if ( arg >= cmd_argc )
		return cmd_null_string;
	return cmd_argv[arg];
}


static int
Cmd_Argv_start(int arg)
{
	if ( arg >= cmd_argc )
		return 0;
	return cmd_argv_start[arg];
}


static int
Cmd_Argv_length(int arg)
{
	if ( arg >= cmd_argc )
		return 0;
	return cmd_argv_length[arg];
}


static void
Cmd_TokenizeString(const char* text, int text_len)
{
	int start;
	int com_token_start;
	int com_token_length;
	cmd_argc = 0;

	start = 0;
	while (start < text_len) {

		/* skip whitespace up to a \n */
		while (*text && *text <= ' ' && *text != '\n' && start < text_len) {
			text++;
			start++;
		}

		if (*text == '\n') {
			/* a newline separates commands in the buffer */
			text++;
			break;
		}

		if ((!*text) || (start == text_len))
			return;

		text = COM_Parse (text, text_len-start, &com_token_start, &com_token_length);
		if (!text)
			return;

		if (cmd_argc < MAX_ARGS) {
			cmd_argv[cmd_argc] = (char*)text;
			cmd_argv_start[cmd_argc] = start + com_token_start;
			cmd_argv_length[cmd_argc] = com_token_length;
			cmd_argc++;
		}

		start += com_token_start + com_token_length;
	}
}


static void
dissect_id_infostring(tvbuff_t *tvb, proto_tree* tree,
	int offset, char* infostring,
	gint ett_key_value, int hf_key_value, int hf_key, int hf_value)
{
	char     *newpos     = infostring;
	gboolean end_of_info = FALSE;

	/* to look at all the key/value pairs, we destroy infostring */
	while(!end_of_info) {
		char* keypos;
		char* valuepos;
		int   keylength;
		char* keyvaluesep;
		int   valuelength;
		char* valueend;

		keypos = newpos;
		if (*keypos == '\0') break;
		if (*keypos == '\\') keypos++;

		for (keylength = 0
			;
			*(keypos + keylength) != '\\' &&
			*(keypos + keylength) != '\0'
			;
			keylength++)
		;
		keyvaluesep = keypos + keylength;
		if (*keyvaluesep == '\0') break;
		valuepos = keyvaluesep+1;
		for (valuelength = 0
			;
			*(valuepos + valuelength) != '\\' &&
			*(valuepos + valuelength) != '\0'
			;
			valuelength++)
		;
		valueend = valuepos + valuelength;
		if (*valueend == '\0') {
			end_of_info = TRUE;
		}
		*(keyvaluesep) = '=';
		*(valueend) = '\0';

		if (tree) {
			proto_item* sub_item;
			proto_tree* sub_tree;

			sub_item = proto_tree_add_string(tree,
				hf_key_value,
				tvb,
				offset + (gint)(keypos-infostring),
				keylength + 1 + valuelength, keypos);
			sub_tree = proto_item_add_subtree(
				sub_item,
				ett_key_value);
			*(keyvaluesep) = '\0';
			proto_tree_add_string(sub_tree,
					      hf_key,
					      tvb,
					      offset + (gint)(keypos-infostring),
					      keylength, keypos);
			proto_tree_add_string(sub_tree,
					      hf_value,
					      tvb,
					      offset + (gint)(valuepos-infostring),
					      valuelength, valuepos);
		}
		newpos = valueend + 1;
	}
}


static const value_string names_direction[] = {
#define DIR_C2S 0
	{ DIR_C2S, "Client to Server" },
#define DIR_S2C 1
	{ DIR_S2C, "Server to Client" },
	{ 0, NULL }
};


/* I took this name and value directly out of the QW source. */
#define PORT_MASTER 27500 /* Not IANA registered */
static range_t *gbl_quakeworldServerPorts = NULL;

/* out of band message id bytes (taken out of quakeworldsource/client/protocol.h */

/* M = master, S = server, C = client, A = any */
/* the second character will allways be \n if the message isn't a single */
/* byte long (?? not true anymore?) */

#define S2C_CHALLENGE		'c'
#define S2C_CONNECTION		'j'
#define A2A_PING		'k'	/* respond with an A2A_ACK */
#define A2A_ACK			'l'	/* general acknowledgement without info */
#define A2A_NACK		'm'	/* [+ comment] general failure */
#define A2A_ECHO		'e'	/* for echoing */
#define A2C_PRINT		'n'	/* print a message on client */

#define S2M_HEARTBEAT		'a'	/* + serverinfo + userlist + fraglist */
#define A2C_CLIENT_COMMAND	'B'	/* + command line */
#define S2M_SHUTDOWN		'C'


static void
dissect_quakeworld_ConnectionlessPacket(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int direction)
{
	proto_tree	*cl_tree;
	proto_tree	*text_tree = NULL;
	proto_item	*pi = NULL;
	guint8		*text;
	int		len;
	int		offset;
	guint32		marker;
	int		command_len;
	const char	*command = "";
	gboolean	command_finished = FALSE;

	marker = tvb_get_ntohl(tvb, 0);
	cl_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_quakeworld_connectionless, NULL, "Connectionless");

	proto_tree_add_uint(cl_tree, hf_quakeworld_connectionless_marker,
				tvb, 0, 4, marker);

	/* all the rest of the packet is just text */
	offset = 4;

	text = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII|ENC_NA);
	/* actually, we should look for a eol char and stop already there */

	if (cl_tree) {
		proto_item *text_item;
		text_item = proto_tree_add_string(cl_tree, hf_quakeworld_connectionless_text,
						  tvb, offset, len, text);
		text_tree = proto_item_add_subtree(text_item, ett_quakeworld_connectionless_text);
	}

	if (direction == DIR_C2S) {
		/* client to server commands */
		const char *c;

		Cmd_TokenizeString(text, len);
		c = Cmd_Argv(0);

		/* client to sever commands */
		if (strcmp(c,"ping") == 0) {
			command = "Ping";
			command_len = 4;
		} else if (strcmp(c,"status") == 0) {
			command = "Status";
			command_len = 6;
		} else if (strcmp(c,"log") == 0) {
			command = "Log";
			command_len = 3;
		} else if (strcmp(c,"connect") == 0) {
			guint32 version = 0;
			guint16 qport = 0;
			guint32 challenge = 0;
			gboolean version_valid = TRUE;
			gboolean qport_valid = TRUE;
			gboolean challenge_valid = TRUE;
			const char *infostring;
			proto_tree *argument_tree = NULL;
			command = "Connect";
			command_len = Cmd_Argv_length(0);
			if (text_tree) {
				proto_item *argument_item;
				pi = proto_tree_add_string(text_tree, hf_quakeworld_connectionless_command,
					tvb, offset, command_len, command);
				argument_item = proto_tree_add_string(text_tree,
					hf_quakeworld_connectionless_arguments,
					tvb, offset + Cmd_Argv_start(1), len + 1 - Cmd_Argv_start(1),
					text + Cmd_Argv_start(1));
				argument_tree = proto_item_add_subtree(argument_item,
								       ett_quakeworld_connectionless_arguments);
				command_finished=TRUE;
			}
			version_valid = ws_strtou32(Cmd_Argv(1), NULL, &version);
			qport_valid = ws_strtou16(Cmd_Argv(2), NULL, &qport);
			challenge_valid = ws_strtou32(Cmd_Argv(3), NULL, &challenge);
			infostring = Cmd_Argv(4);

			if (text_tree && (!version_valid || !qport_valid || !challenge_valid))
				expert_add_info(pinfo, pi, &ei_quakeworld_connectionless_command_invalid);

			if (argument_tree) {
				proto_item *info_item;
				proto_tree *info_tree;
				proto_tree_add_uint(argument_tree,
					hf_quakeworld_connectionless_connect_version,
					tvb,
					offset + Cmd_Argv_start(1),
					Cmd_Argv_length(1), version);
				proto_tree_add_uint(argument_tree,
					hf_quakeworld_connectionless_connect_qport,
					tvb,
					offset + Cmd_Argv_start(2),
					Cmd_Argv_length(2), qport);
				proto_tree_add_int(argument_tree,
					hf_quakeworld_connectionless_connect_challenge,
					tvb,
					offset + Cmd_Argv_start(3),
					Cmd_Argv_length(3), challenge);
				info_item = proto_tree_add_string(argument_tree,
					hf_quakeworld_connectionless_connect_infostring,
					tvb,
					offset + Cmd_Argv_start(4),
					Cmd_Argv_length(4), infostring);
				info_tree = proto_item_add_subtree(
					info_item, ett_quakeworld_connectionless_connect_infostring);
				dissect_id_infostring(tvb, info_tree, offset + Cmd_Argv_start(4),
					wmem_strdup(wmem_packet_scope(), infostring),
					ett_quakeworld_connectionless_connect_infostring_key_value,
					hf_quakeworld_connectionless_connect_infostring_key_value,
					hf_quakeworld_connectionless_connect_infostring_key,
					hf_quakeworld_connectionless_connect_infostring_value);
			}
		} else if (strcmp(c,"getchallenge") == 0) {
			command = "Get Challenge";
			command_len = Cmd_Argv_length(0);
		} else if (strcmp(c,"rcon") == 0) {
			const char* password;
			int i;
			char remaining[MAX_TEXT_SIZE+1];
			proto_tree *argument_tree = NULL;
			command = "Remote Command";
			command_len = Cmd_Argv_length(0);
			if (text_tree) {
				proto_item *argument_item;
				proto_tree_add_string(text_tree, hf_quakeworld_connectionless_command,
					tvb, offset, command_len, command);
				argument_item = proto_tree_add_string(text_tree,
					hf_quakeworld_connectionless_arguments,
					tvb, offset + Cmd_Argv_start(1), len - Cmd_Argv_start(1),
					text + Cmd_Argv_start(1));
				argument_tree =	proto_item_add_subtree(argument_item,
								       ett_quakeworld_connectionless_arguments);
				command_finished=TRUE;
			}
			password = Cmd_Argv(1);
			if (argument_tree) {
				proto_tree_add_string(argument_tree,
					hf_quakeworld_connectionless_rcon_password,
					tvb,
					offset + Cmd_Argv_start(1),
					Cmd_Argv_length(1), password);
			}
			remaining[0] = '\0';
			for (i=2; i<Cmd_Argc() ; i++) {
				(void) g_strlcat (remaining, Cmd_Argv(i), MAX_TEXT_SIZE+1);
				(void) g_strlcat (remaining, " ", MAX_TEXT_SIZE+1);
			}
			if (text_tree) {
				proto_tree_add_string(argument_tree,
					hf_quakeworld_connectionless_rcon_command,
					tvb, offset + Cmd_Argv_start(2),
					Cmd_Argv_start(Cmd_Argc()-1) + Cmd_Argv_length(Cmd_Argc()-1) -
					Cmd_Argv_start(2),
					remaining);
			}
		} else if (c[0]==A2A_PING && ( c[1]=='\0' || c[1]=='\n')) {
			command = "Ping";
			command_len = 1;
		} else if (c[0]==A2A_ACK && ( c[1]=='\0' || c[1]=='\n')) {
			command = "Ack";
			command_len = 1;
		} else {
			command = "Unknown";
			command_len = len - 1;
		}
	}
	else {
		/* server to client commands */
		if (text[0] == S2C_CONNECTION) {
			command = "Connected";
			command_len = 1;
		} else if (text[0] == A2C_CLIENT_COMMAND) {
			command = "Client Command";
			command_len = 1;
			/* stringz (command), stringz (localid) */
		} else if (text[0] == A2C_PRINT) {
			command = "Print";
			command_len = 1;
			/* string */
		} else if (text[0] == A2A_PING) {
			command = "Ping";
			command_len = 1;
		} else if (text[0] == S2C_CHALLENGE) {
			command = "Challenge";
			command_len = 1;
			/* string, conversion */
		} else {
			command = "Unknown";
			command_len = len - 1;
		}
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", command);

	if (!command_finished) {
		proto_tree_add_string(text_tree, hf_quakeworld_connectionless_command,
			tvb, offset, command_len, command);
	}
	/*offset += len;*/
}


static void
dissect_quakeworld_client_commands(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree)
{
	/* If I have too much time at hand, I'll fill it with all
	   the information from my QWD specs:
		http://www.planetquake.com/demospecs/qwd/
	*/
	call_data_dissector(tvb, pinfo, tree);
}


static void
dissect_quakeworld_server_commands(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree)
{
	/* If I have too much time at hand, I'll fill it with all
	   the information from my QWD specs:
		http://www.planetquake.com/demospecs/qwd/
	*/
	call_data_dissector(tvb, pinfo, tree);
}


static const value_string names_reliable[] = {
	{ 0, "Non Reliable" },
	{ 1, "Reliable" },
	{ 0, NULL }
};


static void
dissect_quakeworld_GamePacket(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int direction)
{
	proto_tree	*game_tree = NULL;
	guint32		seq1;
	guint32		seq2;
	int		rel1;
	int		rel2;
	int		offset;
	guint		rest_length;

	direction = value_is_in_range(gbl_quakeworldServerPorts, pinfo->destport) ?
			DIR_C2S : DIR_S2C;

	game_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_quakeworld_game, NULL, "Game");

	offset = 0;

	seq1 = tvb_get_letohl(tvb, offset);
	rel1 = seq1 & 0x80000000 ? 1 : 0;
	seq1 &= ~0x80000000;
	if (game_tree) {
		proto_tree *seq1_tree = proto_tree_add_subtree_format(game_tree,
							    tvb, offset, 4, ett_quakeworld_game_seq1, NULL, "Current Sequence: %u (%s)",
							    seq1, val_to_str(rel1,names_reliable,"%u"));
		proto_tree_add_uint(seq1_tree, hf_quakeworld_game_seq1,
				    tvb, offset, 4, seq1);
		proto_tree_add_boolean(seq1_tree, hf_quakeworld_game_rel1,
				       tvb, offset+3, 1, rel1);
	}
	offset += 4;

	seq2 = tvb_get_letohl(tvb, offset);
	rel2 = seq2 & 0x80000000 ? 1 : 0;
	seq2 &= ~0x80000000;
	if (game_tree) {
		proto_tree *seq2_tree = proto_tree_add_subtree_format(game_tree,
							    tvb, offset, 4, ett_quakeworld_game_seq2, NULL, "Acknowledge Sequence: %u (%s)",
							    seq2, val_to_str(rel2,names_reliable,"%u"));
		proto_tree_add_uint(seq2_tree, hf_quakeworld_game_seq2, tvb, offset, 4, seq2);
		proto_tree_add_boolean(seq2_tree, hf_quakeworld_game_rel2, tvb, offset+3, 1, rel2);
	}
	offset += 4;

	if (direction == DIR_C2S) {
		/* client to server */
		guint16 qport = tvb_get_letohs(tvb, offset);
		if (game_tree) {
			proto_tree_add_uint(game_tree, hf_quakeworld_game_qport, tvb, offset, 2, qport);
		}
		offset +=2;
	}

	/* all the rest is pure game data */
	rest_length = tvb_reported_length(tvb) - offset;
	if (rest_length) {
		tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
		proto_tree *c_tree;

		if (direction == DIR_C2S) {
			c_tree = proto_tree_add_subtree(game_tree, next_tvb,
							     0, -1, ett_quakeworld_game_clc, NULL, "Client Commands");
			dissect_quakeworld_client_commands(next_tvb, pinfo, c_tree);
		}
		else {
			c_tree = proto_tree_add_subtree(game_tree, next_tvb,
							     0, -1, ett_quakeworld_game_svc, NULL, "Server Commands");

			dissect_quakeworld_server_commands(next_tvb, pinfo, c_tree);
		}
	}
}


static int
dissect_quakeworld(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*quakeworld_tree = NULL;
	int		direction;

	direction = value_is_in_range(gbl_quakeworldServerPorts, pinfo->destport) ?
			DIR_C2S : DIR_S2C;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUAKEWORLD");
	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(direction,
			names_direction, "%u"));

	if (tree) {
		proto_item	*quakeworld_item;
		quakeworld_item = proto_tree_add_item(tree, proto_quakeworld,
				tvb, 0, -1, ENC_NA);
		quakeworld_tree = proto_item_add_subtree(quakeworld_item, ett_quakeworld);
		proto_tree_add_uint_format(quakeworld_tree,
					   direction == DIR_S2C ?
					   hf_quakeworld_s2c :
					   hf_quakeworld_c2s,
					   tvb, 0, 0, 1,
					   "Direction: %s", val_to_str(direction, names_direction, "%u"));
	}

	if (tvb_get_ntohl(tvb, 0) == 0xffffffff) {
		col_append_str(pinfo->cinfo, COL_INFO, " Connectionless");
		proto_tree_add_uint_format(quakeworld_tree,
				hf_quakeworld_connectionless,
				tvb, 0, 0, 1,
				"Type: Connectionless");
		dissect_quakeworld_ConnectionlessPacket(
			tvb, pinfo, quakeworld_tree, direction);
	}
	else {
		col_append_str(pinfo->cinfo, COL_INFO, " Game");
		proto_tree_add_uint_format(quakeworld_tree,
				hf_quakeworld_game,
				tvb, 0, 0, 1,
				"Type: Game");
		dissect_quakeworld_GamePacket(
			tvb, pinfo, quakeworld_tree, direction);
	}
	return tvb_captured_length(tvb);
}

static void
apply_quakeworld_prefs(void)
{
    /* Port preference used to determine client/server */
    gbl_quakeworldServerPorts = prefs_get_range_value("quakeworld", "udp.port");
}

void
proto_register_quakeworld(void)
{
	expert_module_t* expert_quakeworld;

	static hf_register_info hf[] = {
		{ &hf_quakeworld_c2s,
			{ "Client to Server", "quakeworld.c2s",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quakeworld_s2c,
			{ "Server to Client", "quakeworld.s2c",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quakeworld_connectionless,
			{ "Connectionless", "quakeworld.connectionless",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quakeworld_game,
			{ "Game", "quakeworld.game",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quakeworld_connectionless_marker,
			{ "Marker", "quakeworld.connectionless.marker",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quakeworld_connectionless_text,
			{ "Text", "quakeworld.connectionless.text",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quakeworld_connectionless_command,
			{ "Command", "quakeworld.connectionless.command",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quakeworld_connectionless_arguments,
			{ "Arguments", "quakeworld.connectionless.arguments",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quakeworld_connectionless_connect_version,
			{ "Version", "quakeworld.connectionless.connect.version",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Protocol Version", HFILL }},
		{ &hf_quakeworld_connectionless_connect_qport,
			{ "QPort", "quakeworld.connectionless.connect.qport",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"QPort of the client", HFILL }},
		{ &hf_quakeworld_connectionless_connect_challenge,
			{ "Challenge", "quakeworld.connectionless.connect.challenge",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"Challenge from the server", HFILL }},
		{ &hf_quakeworld_connectionless_connect_infostring,
			{ "Infostring", "quakeworld.connectionless.connect.infostring",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Infostring with additional variables", HFILL }},
		{ &hf_quakeworld_connectionless_connect_infostring_key_value,
			{ "Key/Value", "quakeworld.connectionless.connect.infostring.key_value",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Key and Value", HFILL }},
		{ &hf_quakeworld_connectionless_connect_infostring_key,
			{ "Key", "quakeworld.connectionless.connect.infostring.key",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Infostring Key", HFILL }},
		{ &hf_quakeworld_connectionless_connect_infostring_value,
			{ "Value", "quakeworld.connectionless.connect.infostring.value",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Infostring Value", HFILL }},
		{ &hf_quakeworld_connectionless_rcon_password,
			{ "Password", "quakeworld.connectionless.rcon.password",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Rcon Password", HFILL }},
		{ &hf_quakeworld_connectionless_rcon_command,
			{ "Command", "quakeworld.connectionless.rcon.command",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quakeworld_game_seq1,
			{ "Sequence Number", "quakeworld.game.seq1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Sequence number of the current packet", HFILL }},
		{ &hf_quakeworld_game_rel1,
			{ "Reliable", "quakeworld.game.rel1",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Packet is reliable and may be retransmitted", HFILL }},
		{ &hf_quakeworld_game_seq2,
			{ "Sequence Number", "quakeworld.game.seq2",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Sequence number of the last received packet", HFILL }},
		{ &hf_quakeworld_game_rel2,
			{ "Reliable", "quakeworld.game.rel2",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Packet was reliable and may be retransmitted", HFILL }},
		{ &hf_quakeworld_game_qport,
			{ "QPort", "quakeworld.game.qport",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"QuakeWorld Client Port", HFILL }}
	};
	static gint *ett[] = {
		&ett_quakeworld,
		&ett_quakeworld_connectionless,
		&ett_quakeworld_connectionless_text,
		&ett_quakeworld_connectionless_arguments,
		&ett_quakeworld_connectionless_connect_infostring,
		&ett_quakeworld_connectionless_connect_infostring_key_value,
		&ett_quakeworld_game,
		&ett_quakeworld_game_seq1,
		&ett_quakeworld_game_seq2,
		&ett_quakeworld_game_clc,
		&ett_quakeworld_game_svc
	};

	static ei_register_info ei[] = {
		{ &ei_quakeworld_connectionless_command_invalid, { "quakeworld.connectionless.command.invalid",
			PI_MALFORMED, PI_ERROR, "Invalid connectionless command", EXPFILL }}
	};

	proto_quakeworld = proto_register_protocol("QuakeWorld Network Protocol", "QUAKEWORLD", "quakeworld");
	proto_register_field_array(proto_quakeworld, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
	prefs_register_protocol(proto_quakeworld, apply_quakeworld_prefs);

	expert_quakeworld = expert_register_protocol(proto_quakeworld);
	expert_register_field_array(expert_quakeworld, ei, array_length(ei));
}


void
proto_reg_handoff_quakeworld(void)
{
	dissector_handle_t quakeworld_handle;

	quakeworld_handle = create_dissector_handle(dissect_quakeworld, proto_quakeworld);
	dissector_add_uint_with_preference("udp.port", PORT_MASTER, quakeworld_handle);
        apply_quakeworld_prefs();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
