/* packet-quake.c
 * Routines for quake packet dissection
 *
 * Uwe Girlich <uwe@planetquake.com>
 *	http://www.idsoftware.com/q1source/q1source.zip
 *
 * $Id: packet-quake.c,v 1.10 2000/12/02 08:41:08 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"
#include "conversation.h"

static int proto_quake = -1;
static int hf_quake_header_flags = -1; 
static int hf_quake_header_length = -1; 
static int hf_quake_header_sequence = -1; 
static int hf_quake_control_command = -1;

static int hf_quake_CCREQ_CONNECT_game = -1;
static int hf_quake_CCREQ_CONNECT_version = -1;
static int hf_quake_CCREQ_SERVER_INFO_game = -1;
static int hf_quake_CCREQ_SERVER_INFO_version = -1;
static int hf_quake_CCREQ_PLAYER_INFO_player = -1;
static int hf_quake_CCREQ_RULE_INFO_lastrule = -1;

static int hf_quake_CCREP_ACCEPT_port = -1;
static int hf_quake_CCREP_REJECT_reason = -1;
static int hf_quake_CCREP_SERVER_INFO_address = -1;
static int hf_quake_CCREP_SERVER_INFO_server = -1;
static int hf_quake_CCREP_SERVER_INFO_map = -1;
static int hf_quake_CCREP_SERVER_INFO_num_player = -1;
static int hf_quake_CCREP_SERVER_INFO_max_player = -1;
static int hf_quake_CCREP_PLAYER_INFO_name = -1;
static int hf_quake_CCREP_PLAYER_INFO_colors = -1;
static int hf_quake_CCREP_PLAYER_INFO_colors_shirt = -1;
static int hf_quake_CCREP_PLAYER_INFO_colors_pants = -1;
static int hf_quake_CCREP_PLAYER_INFO_frags = -1;
static int hf_quake_CCREP_PLAYER_INFO_connect_time = -1;
static int hf_quake_CCREP_PLAYER_INFO_address = -1;
static int hf_quake_CCREP_RULE_INFO_rule = -1;
static int hf_quake_CCREP_RULE_INFO_value = -1;


static gint ett_quake = -1;
static gint ett_quake_control = -1;
static gint ett_quake_control_colors = -1;
static gint ett_quake_flags = -1;


/* I took these names directly out of the Q1 source. */
#define NETFLAG_LENGTH_MASK 0x0000ffff
#define NET_HEADERSIZE 8
#define DEFAULTnet_hostport 26000

#define NETFLAG_LENGTH_MASK     0x0000ffff
#define NETFLAG_DATA            0x00010000
#define NETFLAG_ACK                     0x00020000
#define NETFLAG_NAK                     0x00040000
#define NETFLAG_EOM                     0x00080000
#define NETFLAG_UNRELIABLE      0x00100000
#define NETFLAG_CTL                     0x80000000                              


#define CCREQ_CONNECT           0x01
#define CCREQ_SERVER_INFO       0x02
#define CCREQ_PLAYER_INFO       0x03
#define CCREQ_RULE_INFO         0x04
 
#define CCREP_ACCEPT            0x81
#define CCREP_REJECT            0x82
#define CCREP_SERVER_INFO       0x83
#define CCREP_PLAYER_INFO       0x84
#define CCREP_RULE_INFO         0x85

static const value_string names_control_command[] = {
	{	CCREQ_CONNECT, "connect" },
	{	CCREQ_SERVER_INFO, "server_info" },
	{	CCREQ_PLAYER_INFO, "player_info" },
	{	CCREQ_RULE_INFO, "rule_info" },
	{	CCREP_ACCEPT, "accept" },
	{	CCREP_REJECT, "reject" },
	{	CCREP_SERVER_INFO, "server_info" },
	{	CCREP_PLAYER_INFO, "player_info" },
	{	CCREP_RULE_INFO, "rule_info" },
	{ 0, NULL }
};

#define CCREQ 0x00
#define CCREP 0x80

#define QUAKE_MAXSTRING 0x800

static const value_string names_control_direction[] = {
        { CCREQ, "Request" },
        { CCREP, "Reply" },
        { 0, NULL }
};


static const value_string names_colors[] = {
	{  0, "White" },
	{  1, "Brown" },
	{  2, "Lavender" },
	{  3, "Khaki" },
	{  4, "Red" },
	{  5, "Lt Brown" },
	{  6, "Peach" },
	{  7, "Lt Peach" },
	{  8, "Purple" },
	{  9, "Dk Purple" },
	{ 10, "Tan" },
	{ 11, "Green" },
	{ 12, "Yellow" },
	{ 13, "Blue" },
	{ 14, "Blue" },
	{ 15, "Blue" },
	{  0, NULL }
};


static void dissect_quake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);



static void
dissect_quake_CCREQ_CONNECT
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint maxbufsize;
	char game[QUAKE_MAXSTRING];
	guint8 version;
	gint len;

	maxbufsize = MIN(sizeof(game), tvb_length(tvb));
	len = tvb_get_nstringz0(tvb, 0, maxbufsize, game);
	version = tvb_get_guint8(tvb, len + 1);

	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREQ_CONNECT_game,
			tvb, 0, len + 1, game);
		proto_tree_add_uint(tree, hf_quake_CCREQ_CONNECT_version,
			tvb, len + 1, 1, version);
	}
}


static void
dissect_quake_CCREQ_SERVER_INFO
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint maxbufsize;
	char game[QUAKE_MAXSTRING];
	guint8 version;
	gint len;

	maxbufsize = MIN(sizeof(game), tvb_length(tvb));
	len = tvb_get_nstringz0(tvb, 0, maxbufsize, game);
	version = tvb_get_guint8(tvb, len + 1);

	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREQ_SERVER_INFO_game,
			tvb, 0, len + 1, game);
		proto_tree_add_uint(tree, hf_quake_CCREQ_SERVER_INFO_version,
			tvb, len + 1, 1, version);
	}
}


static void
dissect_quake_CCREQ_PLAYER_INFO
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 player;

	player = tvb_get_guint8(tvb, 0);
	if (tree) {
		 proto_tree_add_uint(tree, hf_quake_CCREQ_PLAYER_INFO_player,
			tvb, 0, 1, player);
	}
}


static void
dissect_quake_CCREQ_RULE_INFO
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	char rule[QUAKE_MAXSTRING];
	gint maxbufsize;
	gint len;

	maxbufsize = MIN(sizeof(rule), tvb_length(tvb));
	len = tvb_get_nstringz0(tvb, 0, maxbufsize, rule);
	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREQ_RULE_INFO_lastrule,
			tvb, 0, len + 1, rule);
	}
}


static void
dissect_quake_CCREP_ACCEPT
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 port;
	conversation_t *c;

	port = tvb_get_letohl(tvb, 0);
	c = conversation_new( &pi.src, &pi.dst, PT_UDP, port, pi.destport,
	    NULL, 0);
	if (c) {
		conversation_set_dissector(c, dissect_quake);
	}
	if (tree) {
		proto_tree_add_uint(tree, hf_quake_CCREP_ACCEPT_port,
			tvb, 0, 4, port);
	}
}


static void
dissect_quake_CCREP_REJECT
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint maxbufsize;
	char reason[QUAKE_MAXSTRING];
	gint len;

	maxbufsize = MIN(sizeof(reason), tvb_length(tvb));
	len = tvb_get_nstringz0(tvb, 0, maxbufsize, reason);

	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREP_REJECT_reason,
			tvb, 0, len + 1, reason);
	}
}


static void
dissect_quake_CCREP_SERVER_INFO
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset;
	gint len;
	gint maxbufsize;
	char address[QUAKE_MAXSTRING];
	char server[QUAKE_MAXSTRING];
	char map[QUAKE_MAXSTRING];

	guint8 num_player;
	guint8 max_player;
	guint8 version;

	offset = 0;

	maxbufsize = MIN(sizeof(address), tvb_length_remaining(tvb, offset));
	len = tvb_get_nstringz0(tvb, offset, maxbufsize, address);
	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREP_SERVER_INFO_address,
			tvb, offset, len + 1, address);
	}
	offset += len + 1;

	maxbufsize = MIN(sizeof(server), tvb_length_remaining(tvb, offset));
	len = tvb_get_nstringz0(tvb, offset, maxbufsize, server);
	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREP_SERVER_INFO_server,
			tvb, offset, len + 1, server);
	}
	offset += len + 1;
	
	maxbufsize = MIN(sizeof(map), tvb_length_remaining(tvb, offset));
	len = tvb_get_nstringz0(tvb, offset, maxbufsize, map);
	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREP_SERVER_INFO_map,
			tvb, offset, len + 1, map);
	}
	offset += len + 1;

	num_player = tvb_get_guint8(tvb, offset + 0);
	max_player = tvb_get_guint8(tvb, offset + 1);
	version    = tvb_get_guint8(tvb, offset + 2);

	if (tree) {
		proto_tree_add_uint(tree, hf_quake_CCREP_SERVER_INFO_num_player,
			tvb, offset + 0, 1, num_player);
		proto_tree_add_uint(tree, hf_quake_CCREP_SERVER_INFO_max_player,
			tvb, offset + 1, 1, max_player);
		proto_tree_add_uint(tree, hf_quake_CCREQ_SERVER_INFO_version,
			tvb, offset + 2, 1, version);
	}
}


static void
dissect_quake_CCREP_PLAYER_INFO
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset;
	guint8 player;
	gint len;
	gint maxbufsize;
	char name[QUAKE_MAXSTRING];
	guint32 colors;
	guint32 color_shirt;
	guint32 color_pants;
	guint32 frags;
	guint32 connect_time;
	char address[QUAKE_MAXSTRING];

	offset = 0;

	player = tvb_get_guint8(tvb, offset);
	if (tree) {
		proto_tree_add_uint(tree, hf_quake_CCREQ_PLAYER_INFO_player,
			tvb, offset, 1, player);
	}
	offset += 1;
	
	maxbufsize = MIN(sizeof(name), tvb_length_remaining(tvb, offset));
	len = tvb_get_nstringz0(tvb, offset, maxbufsize, name);
	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREP_PLAYER_INFO_name,
			tvb, offset, len + 1, name);
	}
	offset += len + 1;

	colors       = tvb_get_letohl(tvb, offset + 0);
	color_shirt = (colors >> 4) & 0x0f;
	color_pants = (colors     ) & 0x0f;
	frags        = tvb_get_letohl(tvb, offset + 4);
	connect_time = tvb_get_letohl(tvb, offset + 8);
	if (tree) {
		proto_item *colors_item;
		proto_tree *colors_tree;

		colors_item = proto_tree_add_uint(tree,
			hf_quake_CCREP_PLAYER_INFO_colors,
			tvb, offset + 0, 4, colors);
		if (colors_item) {
			colors_tree = proto_item_add_subtree(colors_item,
					ett_quake_control_colors);
			proto_tree_add_uint(colors_tree,
				hf_quake_CCREP_PLAYER_INFO_colors_shirt,
				tvb, offset + 0, 1, color_shirt);
			proto_tree_add_uint(colors_tree,
				hf_quake_CCREP_PLAYER_INFO_colors_pants,
				tvb, offset + 0, 1, color_pants);
		}
		proto_tree_add_uint(tree, hf_quake_CCREP_PLAYER_INFO_frags,
			tvb, offset + 4, 4, frags);
		proto_tree_add_uint(tree, hf_quake_CCREP_PLAYER_INFO_connect_time,
			tvb, offset + 8, 4, connect_time);
	}
	offset += 3*4;

	maxbufsize = MIN(sizeof(address), tvb_length_remaining(tvb, offset));
	len = tvb_get_nstringz0(tvb, offset, maxbufsize, address);
	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREP_PLAYER_INFO_address,
			tvb, offset, len + 1, address);
	}
	offset += len + 1;
}


static void
dissect_quake_CCREP_RULE_INFO
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	char rule[QUAKE_MAXSTRING];
	char value[QUAKE_MAXSTRING];
	gint maxbufsize;
	gint len;
	gint offset;

	if (tvb_length(tvb) == 0) return;

	offset = 0;

	maxbufsize = MIN(sizeof(rule), tvb_length_remaining(tvb, offset));
	len = tvb_get_nstringz0(tvb, offset, maxbufsize, rule);
	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREP_RULE_INFO_rule,
			tvb, offset, len + 1, rule);
	}
	offset += len + 1;

	maxbufsize = MIN(sizeof(value), tvb_length_remaining(tvb, offset));
	len = tvb_get_nstringz0(tvb, offset, maxbufsize, value);
	if (tree) {
		proto_tree_add_string(tree, hf_quake_CCREP_RULE_INFO_value,
			tvb, offset, len + 1, value);
	}
	offset += len + 1;
}


static void
dissect_quake_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8		command;
	int		direction;
	proto_item	*control_item = NULL;
	proto_tree	*control_tree = NULL;
	guint		rest_length;
	tvbuff_t	*next_tvb;
	
	command = tvb_get_guint8(tvb, 0);
	direction = (command & 0x80) ? CCREP : CCREQ;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_add_fstr(pinfo->fd, COL_INFO, "%s %s",
			val_to_str(command,names_control_command, "%u"),
			val_to_str(direction,names_control_direction,"%u"));
	}

	if (tree) {
		control_item = proto_tree_add_text(tree, tvb,
				0, tvb_length(tvb), "Control %s: %s",
				val_to_str(direction, names_control_direction, "%u"),
				val_to_str(command, names_control_command, "%u"));
		if (control_item)
			control_tree = proto_item_add_subtree(control_item,
						ett_quake_control);
		proto_tree_add_uint(control_tree, hf_quake_control_command,
					tvb, 0, 1, command);
	}

	rest_length = tvb_reported_length(tvb) - 1;
	next_tvb = tvb_new_subset(tvb, 1, rest_length , rest_length);
	switch (command) {
		case CCREQ_CONNECT:
			dissect_quake_CCREQ_CONNECT
			(next_tvb, pinfo, control_tree);
		break;
		case CCREQ_SERVER_INFO:
			dissect_quake_CCREQ_SERVER_INFO
			(next_tvb, pinfo, control_tree);
		break;
		case CCREQ_PLAYER_INFO:
			dissect_quake_CCREQ_PLAYER_INFO
			(next_tvb, pinfo, control_tree);
		break;
		case CCREQ_RULE_INFO:
			dissect_quake_CCREQ_RULE_INFO
			(next_tvb, pinfo, control_tree);
		break;
		case CCREP_ACCEPT:
			dissect_quake_CCREP_ACCEPT
			(next_tvb, pinfo, control_tree);
		break;
		case CCREP_REJECT:
			dissect_quake_CCREP_REJECT
			(next_tvb, pinfo, control_tree);
		break;
		case CCREP_SERVER_INFO:
			dissect_quake_CCREP_SERVER_INFO
			(next_tvb, pinfo, control_tree);
		break;
		case CCREP_PLAYER_INFO:
			dissect_quake_CCREP_PLAYER_INFO
			(next_tvb, pinfo, control_tree);
		break;
		case CCREP_RULE_INFO:
			dissect_quake_CCREP_RULE_INFO
			(next_tvb, pinfo, control_tree);
		break;
		default:
			dissect_data(next_tvb, 0, pinfo, control_tree);
		break;
	}
}


static void
dissect_quake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*quake_tree = NULL;
	proto_item	*quake_item = NULL;
	guint32		length;
	guint32		flags;
	guint32		sequence = 0;
	guint		rest_length;
	tvbuff_t	*next_tvb;

	CHECK_DISPLAY_AS_DATA(proto_quake, tvb, pinfo, tree);

	pinfo->current_proto = "QUAKE";

	if (!tvb_bytes_exist(tvb, 0, 4)) return;

	length = tvb_get_ntohl(tvb, 0);
	flags = length & (~NETFLAG_LENGTH_MASK);
	length &= NETFLAG_LENGTH_MASK;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "QUAKE");

	if (tree) {
		quake_item = proto_tree_add_item(tree, proto_quake,
				tvb, 0, tvb_length(tvb), FALSE);
		if (quake_item)
			quake_tree = proto_item_add_subtree(quake_item, ett_quake);
	}

	if (quake_tree) {
		proto_item* flags_item = NULL;
		proto_tree* flags_tree = NULL;

		flags_item = proto_tree_add_uint(quake_tree, hf_quake_header_flags,
			tvb, 0, 2, flags);
		if (flags_item) {
			flags_tree = proto_item_add_subtree(flags_item, ett_quake_flags);
		}

		if (flags_tree) {
			proto_tree_add_text(flags_tree, tvb, 0, 2,
				decode_boolean_bitfield(flags, NETFLAG_DATA, 32,
				"Data","-"));
			proto_tree_add_text(flags_tree, tvb, 0, 2,
				decode_boolean_bitfield(flags, NETFLAG_ACK, 32,
				"Acknowledgment","-"));
			proto_tree_add_text(flags_tree, tvb, 0, 2,
				decode_boolean_bitfield(flags, NETFLAG_NAK, 32,
				"No Acknowledgment","-"));
			proto_tree_add_text(flags_tree, tvb, 0, 2,
				decode_boolean_bitfield(flags, NETFLAG_EOM, 32,
				"End Of Message","-"));
			proto_tree_add_text(flags_tree, tvb, 0, 2,
				decode_boolean_bitfield(flags, NETFLAG_UNRELIABLE, 32,
				"Unreliable","-"));
			proto_tree_add_text(flags_tree, tvb, 0, 2,
				decode_boolean_bitfield(flags, NETFLAG_CTL, 32,
				"Control","-"));
		}
		proto_tree_add_uint(quake_tree, hf_quake_header_length,
			tvb, 2, 2, length);
	}

	if (flags == NETFLAG_CTL) {
		rest_length = tvb_reported_length(tvb) - 4;
		next_tvb = tvb_new_subset(tvb, 4, rest_length , rest_length);
		dissect_quake_control(next_tvb, pinfo, quake_tree);
		return;
	}

	sequence = tvb_get_ntohl(tvb, 4);
	if (check_col(pinfo->fd, COL_INFO)) {
		col_add_fstr(pinfo->fd, COL_INFO, "seq 0x%x", sequence);
	}
	if (quake_tree) {
		proto_tree_add_uint(quake_tree, hf_quake_header_sequence,
			tvb, 4, 4, sequence);
	}

	rest_length = tvb_reported_length(tvb) - 8;
	next_tvb = tvb_new_subset(tvb, 8, rest_length , rest_length);
	dissect_data(next_tvb, 0, pinfo, quake_tree);
}

void
proto_register_quake(void)
{

  static hf_register_info hf[] = {
    { &hf_quake_header_flags,
      { "Flags", "quake.header.flags",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"Flags" }},
    { &hf_quake_header_length,
      { "Length", "quake.header.length",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"full data length" }},
    { &hf_quake_header_sequence,
      { "Sequence", "quake.header.sequence",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"Sequence Number" }},
    { &hf_quake_control_command,
      { "Command", "quake.control.command",
	FT_UINT8, BASE_HEX, VALS(names_control_command), 0x0,
	"Control Command" }},
    { &hf_quake_CCREQ_CONNECT_game,
      { "Game", "quake.control.connect.game",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Game Name" }},
    { &hf_quake_CCREQ_CONNECT_version,
      { "Version", "quake.control.connect.version",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Game Protocol Version Number" }},
    { &hf_quake_CCREQ_SERVER_INFO_game,
      { "Game", "quake.control.server_info.game",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Game Name" }},
    { &hf_quake_CCREQ_SERVER_INFO_version,
      { "Version", "quake.control.server_info.version",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Game Protocol Version Number" }},
    { &hf_quake_CCREQ_PLAYER_INFO_player,
      { "Player", "quake.control.player_info.player",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Player" }},
    { &hf_quake_CCREQ_RULE_INFO_lastrule,
      { "Last Rule", "quake.control.rule_info.lastrule",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Last Rule Name" }},
    { &hf_quake_CCREP_ACCEPT_port,
      { "Port", "quake.control.accept.port",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Game Data Port" }},
    { &hf_quake_CCREP_REJECT_reason,
      { "Reason", "quake.control.reject.reason",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Reject Reason" }},
    { &hf_quake_CCREP_SERVER_INFO_address,
      { "Address", "quake.control.server_info.address",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Server Address" }},
    { &hf_quake_CCREP_SERVER_INFO_server,
      { "Server", "quake.control.server_info.server",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Server Name" }},
    { &hf_quake_CCREP_SERVER_INFO_map,
      { "Map", "quake.control.server_info.map",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Map Name" }},
    { &hf_quake_CCREP_SERVER_INFO_num_player,
      { "Number of Players", "quake.control.server_info.num_player",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Current Number of Players" }},
    { &hf_quake_CCREP_SERVER_INFO_max_player,
      { "Maximal Number of Players", "quake.control.server_info.max_player",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Maximal Number of Players" }},
    { &hf_quake_CCREP_PLAYER_INFO_name,
      { "Name", "quake.control.player_info.name",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Player Name" }},
    { &hf_quake_CCREP_PLAYER_INFO_colors,
      { "Colors", "quake.control.player_info.colors",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"Player Colors" }},
    { &hf_quake_CCREP_PLAYER_INFO_colors_shirt,
      { "Shirt", "quake.control.player_info.colors.shirt",
	FT_UINT8, BASE_DEC, VALS(names_colors), 0x0,
	"Shirt Color" }},
    { &hf_quake_CCREP_PLAYER_INFO_colors_pants,
      { "Pants", "quake.control.player_info.colors.pants",
	FT_UINT8, BASE_DEC, VALS(names_colors), 0x0,
	"Pants Color" }},
    { &hf_quake_CCREP_PLAYER_INFO_frags,
      { "Frags", "quake.control.player_info.frags",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Player Frags" }},
    { &hf_quake_CCREP_PLAYER_INFO_connect_time,
      { "Connect Time", "quake.control.player_info.connect_time",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Player Connect Time" }},
    { &hf_quake_CCREP_PLAYER_INFO_address,
      { "Address", "quake.control.player_info.address",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Player Address" }},
    { &hf_quake_CCREP_RULE_INFO_rule,
      { "Rule", "quake.control.rule_info.rule",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Rule Name" }},
    { &hf_quake_CCREP_RULE_INFO_value,
      { "Value", "quake.control.rule_info.value",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Rule Value" }},
  };
  static gint *ett[] = {
    &ett_quake,
    &ett_quake_control,
    &ett_quake_control_colors,
    &ett_quake_flags,
  };

  proto_quake = proto_register_protocol("Quake Network Protocol", "quake");
  proto_register_field_array(proto_quake, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_quake(void)
{
	dissector_add("udp.port", DEFAULTnet_hostport, dissect_quake);
}
