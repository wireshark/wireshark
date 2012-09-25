/* packet-quake.c
 * Routines for Quake packet dissection
 *
 * Uwe Girlich <uwe@planetquake.com>
 *	http://www.idsoftware.com/q1source/q1source.zip
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>

static int proto_quake = -1;
static int hf_quake_header_flags = -1;
static int hf_quake_header_flags_data = -1;
static int hf_quake_header_flags_ack = -1;
static int hf_quake_header_flags_no_ack = -1;
static int hf_quake_header_flags_endmsg = -1;
static int hf_quake_header_flags_unreliable = -1;
static int hf_quake_header_flags_control = -1;
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

static dissector_handle_t quake_handle;
static dissector_handle_t data_handle;

/* I took these names directly out of the Q1 source. */
#define NET_HEADERSIZE 8
#define DEFAULTnet_hostport 26000
static guint gbl_quakeServerPort=DEFAULTnet_hostport;

#define NETFLAG_DATA            0x0001
#define NETFLAG_ACK             0x0002
#define NETFLAG_NAK             0x0004
#define NETFLAG_EOM             0x0008
#define NETFLAG_UNRELIABLE      0x0010
#define NETFLAG_CTL             0x8000


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
(tvbuff_t *tvb, proto_tree *tree)
{
	gint offset;
	proto_item *ti;

	offset = 0;

	if (tree) {
		ti = proto_tree_add_item(tree, hf_quake_CCREQ_CONNECT_game,
			tvb, offset, -1, ENC_ASCII|ENC_NA);
		offset += proto_item_get_len(ti);

		proto_tree_add_item(tree, hf_quake_CCREQ_CONNECT_version,
			tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
}


static void
dissect_quake_CCREQ_SERVER_INFO
(tvbuff_t *tvb, proto_tree *tree)
{
	gint offset;
	proto_item *ti;

	offset = 0;

	if (tree) {
		ti = proto_tree_add_item(tree, hf_quake_CCREQ_SERVER_INFO_game,
			tvb, offset, -1, ENC_ASCII|ENC_NA);
		offset += proto_item_get_len(ti);
		proto_tree_add_item(tree, hf_quake_CCREQ_SERVER_INFO_version,
			tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
}


static void
dissect_quake_CCREQ_PLAYER_INFO
(tvbuff_t *tvb, proto_tree *tree)
{
	if (tree) {
		 proto_tree_add_item(tree, hf_quake_CCREQ_PLAYER_INFO_player,
			tvb, 0, 1, ENC_LITTLE_ENDIAN);
	}
}


static void
dissect_quake_CCREQ_RULE_INFO
(tvbuff_t *tvb, proto_tree *tree)
{
	if (tree) {
		proto_tree_add_item(tree, hf_quake_CCREQ_RULE_INFO_lastrule,
			tvb, 0, -1, ENC_ASCII|ENC_NA);
	}
}


static void
dissect_quake_CCREP_ACCEPT
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 port;
	conversation_t *c;

	port = tvb_get_letohl(tvb, 0);
	c = find_or_create_conversation(pinfo);
	conversation_set_dissector(c, quake_handle);

	if (tree) {
		proto_tree_add_uint(tree, hf_quake_CCREP_ACCEPT_port,
			tvb, 0, 4, port);
	}
}


static void
dissect_quake_CCREP_REJECT
(tvbuff_t *tvb, proto_tree *tree)
{
	if (tree) {
		proto_tree_add_item(tree, hf_quake_CCREP_REJECT_reason,
			tvb, 0, -1, ENC_ASCII|ENC_NA);
	}
}


static void
dissect_quake_CCREP_SERVER_INFO
(tvbuff_t *tvb, proto_tree *tree)
{
	gint offset;
	proto_item *ti;

	offset = 0;

	if (tree) {
		ti = proto_tree_add_item(tree,
			hf_quake_CCREP_SERVER_INFO_address, tvb, offset, -1,
			ENC_ASCII|ENC_NA);
		offset += proto_item_get_len(ti);

		ti = proto_tree_add_item(tree,
			hf_quake_CCREP_SERVER_INFO_server, tvb, offset, -1,
			ENC_ASCII|ENC_NA);
		offset += proto_item_get_len(ti);

		ti = proto_tree_add_item(tree, hf_quake_CCREP_SERVER_INFO_map,
			tvb, offset, -1, ENC_ASCII|ENC_NA);
		offset += proto_item_get_len(ti);

		proto_tree_add_item(tree, hf_quake_CCREP_SERVER_INFO_num_player,
			tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_quake_CCREP_SERVER_INFO_max_player,
			tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_quake_CCREQ_SERVER_INFO_version,
			tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
}


static void
dissect_quake_CCREP_PLAYER_INFO
(tvbuff_t *tvb, proto_tree *tree)
{
	gint offset;
	proto_item *ti;
	guint32 colors;
	guint32 color_shirt;
	guint32 color_pants;
	proto_item *colors_item;
	proto_tree *colors_tree;

	offset = 0;

	if (tree) {
		proto_tree_add_item(tree, hf_quake_CCREQ_PLAYER_INFO_player,
			tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		ti = proto_tree_add_item(tree, hf_quake_CCREP_PLAYER_INFO_name,
			tvb, offset, -1, ENC_ASCII|ENC_NA);
		offset += proto_item_get_len(ti);

		colors       = tvb_get_letohl(tvb, offset + 0);
		color_shirt = (colors >> 4) & 0x0f;
		color_pants = (colors     ) & 0x0f;

		colors_item = proto_tree_add_uint(tree,
			hf_quake_CCREP_PLAYER_INFO_colors,
			tvb, offset, 4, colors);
		colors_tree = proto_item_add_subtree(colors_item,
				ett_quake_control_colors);
		proto_tree_add_uint(colors_tree,
			hf_quake_CCREP_PLAYER_INFO_colors_shirt,
			tvb, offset, 1, color_shirt);
		proto_tree_add_uint(colors_tree,
			hf_quake_CCREP_PLAYER_INFO_colors_pants,
			tvb, offset, 1, color_pants);
		offset += 4;
		proto_tree_add_item(tree, hf_quake_CCREP_PLAYER_INFO_frags,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_quake_CCREP_PLAYER_INFO_connect_time,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_quake_CCREP_PLAYER_INFO_address,
			tvb, offset, -1, ENC_ASCII|ENC_NA);
	}
}


static void
dissect_quake_CCREP_RULE_INFO
(tvbuff_t *tvb, proto_tree *tree)
{
	gint offset;
	proto_item *ti;

	if (tvb_reported_length(tvb) == 0) return;

	offset = 0;

	if (tree) {
		ti = proto_tree_add_item(tree, hf_quake_CCREP_RULE_INFO_rule,
			tvb, offset, -1, ENC_ASCII|ENC_NA);
		offset += proto_item_get_len(ti);

		proto_tree_add_item(tree, hf_quake_CCREP_RULE_INFO_value,
			tvb, offset, -1, ENC_ASCII|ENC_NA);
	}
}


static void
dissect_quake_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8		command;
	int		direction;
	proto_tree	*control_tree = NULL;
	guint		rest_length;
	tvbuff_t	*next_tvb;

	command = tvb_get_guint8(tvb, 0);
	direction = (command & 0x80) ? CCREP : CCREQ;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			val_to_str(command,names_control_command, "%u"),
			val_to_str(direction,names_control_direction,"%u"));
	}

	if (tree) {
		proto_item *control_item;
		control_item = proto_tree_add_text(tree, tvb,
				0, -1, "Control %s: %s",
				val_to_str(direction, names_control_direction, "%u"),
				val_to_str(command, names_control_command, "%u"));
		control_tree = proto_item_add_subtree(control_item, ett_quake_control);
		proto_tree_add_uint(control_tree, hf_quake_control_command,
					tvb, 0, 1, command);
	}

	rest_length = tvb_reported_length(tvb) - 1;
	next_tvb = tvb_new_subset(tvb, 1, rest_length , rest_length);
	switch (command) {
		case CCREQ_CONNECT:
			dissect_quake_CCREQ_CONNECT
				(next_tvb, control_tree);
		break;
		case CCREQ_SERVER_INFO:
			dissect_quake_CCREQ_SERVER_INFO
				(next_tvb, control_tree);
		break;
		case CCREQ_PLAYER_INFO:
			dissect_quake_CCREQ_PLAYER_INFO
				(next_tvb, control_tree);
		break;
		case CCREQ_RULE_INFO:
			dissect_quake_CCREQ_RULE_INFO
				(next_tvb, control_tree);
		break;
		case CCREP_ACCEPT:
			dissect_quake_CCREP_ACCEPT
				(next_tvb, pinfo, control_tree);
		break;
		case CCREP_REJECT:
			dissect_quake_CCREP_REJECT
				(next_tvb, control_tree);
		break;
		case CCREP_SERVER_INFO:
			dissect_quake_CCREP_SERVER_INFO
				(next_tvb, control_tree);
		break;
		case CCREP_PLAYER_INFO:
			dissect_quake_CCREP_PLAYER_INFO
				(next_tvb, control_tree);
		break;
		case CCREP_RULE_INFO:
			dissect_quake_CCREP_RULE_INFO
				(next_tvb, control_tree);
		break;
		default:
			call_dissector(data_handle,next_tvb, pinfo, control_tree);
		break;
	}
}


static void
dissect_quake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*quake_tree = NULL;
	guint16		flags;
	guint32		sequence = 0;
	guint		rest_length;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUAKE");
	col_clear(pinfo->cinfo, COL_INFO);

	flags = tvb_get_ntohs(tvb, 2);

	if (tree) {
		proto_item *quake_item;
		quake_item = proto_tree_add_item(tree, proto_quake,
				tvb, 0, -1, ENC_NA);
		quake_tree = proto_item_add_subtree(quake_item, ett_quake);
	}

	if (quake_tree) {
		proto_item* flags_item;
		proto_tree* flags_tree;

		flags_item = proto_tree_add_item(quake_tree, hf_quake_header_flags,
			tvb, 2, 2, ENC_BIG_ENDIAN);
		flags_tree = proto_item_add_subtree(flags_item, ett_quake_flags);
		proto_tree_add_item(flags_tree, hf_quake_header_flags_data, tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(flags_tree, hf_quake_header_flags_ack, tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(flags_tree, hf_quake_header_flags_no_ack, tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(flags_tree, hf_quake_header_flags_endmsg, tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(flags_tree, hf_quake_header_flags_unreliable, tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(flags_tree, hf_quake_header_flags_control, tvb, 2, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(quake_tree, hf_quake_header_length,
			tvb, 0, 2, ENC_BIG_ENDIAN);
	}

	if (flags == NETFLAG_CTL) {
		rest_length = tvb_reported_length(tvb) - 4;
		next_tvb = tvb_new_subset(tvb, 4, rest_length , rest_length);
		dissect_quake_control(next_tvb, pinfo, quake_tree);
		return;
	}

	sequence = tvb_get_ntohl(tvb, 4);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "seq 0x%x", sequence);
	}
	if (quake_tree) {
		proto_tree_add_uint(quake_tree, hf_quake_header_sequence,
			tvb, 4, 4, sequence);
	}

	rest_length = tvb_reported_length(tvb) - 8;
	next_tvb = tvb_new_subset(tvb, 8, rest_length , rest_length);
	call_dissector(data_handle,next_tvb, pinfo, quake_tree);
}


void proto_reg_handoff_quake(void);

void
proto_register_quake(void)
{
  static hf_register_info hf[] = {
    { &hf_quake_header_flags,
      { "Flags", "quake.header.flags",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	NULL, HFILL }},
    { &hf_quake_header_flags_data,
      { "Data", "quake.header.flags.data",
	FT_BOOLEAN, 16, TFS(&tfs_set_notset), NETFLAG_DATA,
	NULL, HFILL }},
    { &hf_quake_header_flags_ack,
      { "Acknowledgment", "quake.header.flags.ack",
	FT_BOOLEAN, 16, TFS(&tfs_set_notset), NETFLAG_ACK,
	NULL, HFILL }},
    { &hf_quake_header_flags_no_ack,
      { "No Acknowledgment", "quake.header.flags.no_ack",
	FT_BOOLEAN, 16, TFS(&tfs_set_notset), NETFLAG_NAK,
	NULL, HFILL }},
    { &hf_quake_header_flags_endmsg,
      { "End Of Message", "quake.header.flags.endmsg",
	FT_BOOLEAN, 16, TFS(&tfs_set_notset), NETFLAG_EOM,
	NULL, HFILL }},
    { &hf_quake_header_flags_unreliable,
      { "Unreliable", "quake.header.flags.unreliable",
	FT_BOOLEAN, 16, TFS(&tfs_set_notset), NETFLAG_UNRELIABLE,
	NULL, HFILL }},
    { &hf_quake_header_flags_control,
      { "Control", "quake.header.flags.control",
	FT_BOOLEAN, 16, TFS(&tfs_set_notset), NETFLAG_CTL,
	NULL, HFILL }},
    { &hf_quake_header_length,
      { "Length", "quake.header.length",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"full data length", HFILL }},
    { &hf_quake_header_sequence,
      { "Sequence", "quake.header.sequence",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"Sequence Number", HFILL }},
    { &hf_quake_control_command,
      { "Command", "quake.control.command",
	FT_UINT8, BASE_HEX, VALS(names_control_command), 0x0,
	"Control Command", HFILL }},
    { &hf_quake_CCREQ_CONNECT_game,
      { "Game", "quake.control.connect.game",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Game Name", HFILL }},
    { &hf_quake_CCREQ_CONNECT_version,
      { "Version", "quake.control.connect.version",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Game Protocol Version Number", HFILL }},
    { &hf_quake_CCREQ_SERVER_INFO_game,
      { "Game", "quake.control.server_info.game",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Game Name", HFILL }},
    { &hf_quake_CCREQ_SERVER_INFO_version,
      { "Version", "quake.control.server_info.version",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Game Protocol Version Number", HFILL }},
    { &hf_quake_CCREQ_PLAYER_INFO_player,
      { "Player", "quake.control.player_info.player",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }},
    { &hf_quake_CCREQ_RULE_INFO_lastrule,
      { "Last Rule", "quake.control.rule_info.lastrule",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Last Rule Name", HFILL }},
    { &hf_quake_CCREP_ACCEPT_port,
      { "Port", "quake.control.accept.port",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Game Data Port", HFILL }},
    { &hf_quake_CCREP_REJECT_reason,
      { "Reason", "quake.control.reject.reason",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Reject Reason", HFILL }},
    { &hf_quake_CCREP_SERVER_INFO_address,
      { "Address", "quake.control.server_info.address",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Server Address", HFILL }},
    { &hf_quake_CCREP_SERVER_INFO_server,
      { "Server", "quake.control.server_info.server",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Server Name", HFILL }},
    { &hf_quake_CCREP_SERVER_INFO_map,
      { "Map", "quake.control.server_info.map",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Map Name", HFILL }},
    { &hf_quake_CCREP_SERVER_INFO_num_player,
      { "Number of Players", "quake.control.server_info.num_player",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Current Number of Players", HFILL }},
    { &hf_quake_CCREP_SERVER_INFO_max_player,
      { "Maximal Number of Players", "quake.control.server_info.max_player",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }},
    { &hf_quake_CCREP_PLAYER_INFO_name,
      { "Name", "quake.control.player_info.name",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Player Name", HFILL }},
    { &hf_quake_CCREP_PLAYER_INFO_colors,
      { "Colors", "quake.control.player_info.colors",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"Player Colors", HFILL }},
    { &hf_quake_CCREP_PLAYER_INFO_colors_shirt,
      { "Shirt", "quake.control.player_info.colors.shirt",
	FT_UINT8, BASE_DEC, VALS(names_colors), 0x0,
	"Shirt Color", HFILL }},
    { &hf_quake_CCREP_PLAYER_INFO_colors_pants,
      { "Pants", "quake.control.player_info.colors.pants",
	FT_UINT8, BASE_DEC, VALS(names_colors), 0x0,
	"Pants Color", HFILL }},
    { &hf_quake_CCREP_PLAYER_INFO_frags,
      { "Frags", "quake.control.player_info.frags",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Player Frags", HFILL }},
    { &hf_quake_CCREP_PLAYER_INFO_connect_time,
      { "Connect Time", "quake.control.player_info.connect_time",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Player Connect Time", HFILL }},
    { &hf_quake_CCREP_PLAYER_INFO_address,
      { "Address", "quake.control.player_info.address",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Player Address", HFILL }},
    { &hf_quake_CCREP_RULE_INFO_rule,
      { "Rule", "quake.control.rule_info.rule",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Rule Name", HFILL }},
    { &hf_quake_CCREP_RULE_INFO_value,
      { "Value", "quake.control.rule_info.value",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
	"Rule Value", HFILL }},
  };
	static gint *ett[] = {
		&ett_quake,
		&ett_quake_control,
		&ett_quake_control_colors,
		&ett_quake_flags,
	};
	module_t *quake_module;

	proto_quake = proto_register_protocol("Quake Network Protocol",
					"QUAKE", "quake");
	proto_register_field_array(proto_quake, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
	quake_module = prefs_register_protocol(proto_quake,
		proto_reg_handoff_quake);
	prefs_register_uint_preference(quake_module, "udp.port",
					"Quake Server UDP Port",
					"Set the UDP port for the Quake Server",
					10, &gbl_quakeServerPort);
}


void
proto_reg_handoff_quake(void)
{
	static gboolean Initialized=FALSE;
	static guint ServerPort;

	if (!Initialized) {
		quake_handle = create_dissector_handle(dissect_quake, proto_quake);
		data_handle = find_dissector("data");
		Initialized=TRUE;
	} else {
		dissector_delete_uint("udp.port", ServerPort, quake_handle);
	}

	/* set port for future deletes */
	ServerPort=gbl_quakeServerPort;

	dissector_add_uint("udp.port", gbl_quakeServerPort, quake_handle);
}


