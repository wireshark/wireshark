/* packet-quake2.c
 * Routines for Quake II packet dissection
 *
 * Uwe Girlich <uwe@planetquake.com>
 *	http://www.idsoftware.com/q1source/q1source.zip
 *	http://www.planetquake.com/demospecs/dm2
 *	http://www.dgs.monash.edu.au/~timf/bottim/
 *	http://www.opt-sci.Arizona.EDU/Pandora/default.asp
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-quakeworld.c
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>

static int proto_quake2 = -1;

static int hf_quake2_s2c = -1;
static int hf_quake2_c2s = -1;
static int hf_quake2_connectionless = -1;
static int hf_quake2_game = -1;
static int hf_quake2_connectionless_marker = -1;
static int hf_quake2_connectionless_text = -1;
static int hf_quake2_game_seq1 = -1;
static int hf_quake2_game_rel1 = -1;
static int hf_quake2_game_seq2 = -1;
static int hf_quake2_game_rel2 = -1;
static int hf_quake2_game_qport = -1;
static int hf_quake2_game_client_command = -1;
static int hf_quake2_game_server_command = -1;
static int hf_quake2_game_client_command_move = -1;
static int hf_quake2_game_client_command_move_chksum = -1;
static int hf_quake2_game_client_command_move_lframe = -1;
static int hf_quake2_game_client_command_move_bitfield_angles1 = -1;
static int hf_quake2_game_client_command_move_bitfield_angles2 = -1;
static int hf_quake2_game_client_command_move_bitfield_angles3 = -1;
static int hf_quake2_game_client_command_move_bitfield_movement_fwd = -1;
static int hf_quake2_game_client_command_move_bitfield_movement_side = -1;
static int hf_quake2_game_client_command_move_bitfield_movement_up = -1;
static int hf_quake2_game_client_command_move_bitfield_buttons = -1;
static int hf_quake2_game_client_command_move_bitfield_impulse = -1;
static int hf_quake2_game_client_command_move_msec = -1;
static int hf_quake2_game_client_command_move_lightlevel = -1;

static gint ett_quake2 = -1;
static gint ett_quake2_connectionless = -1;
static gint ett_quake2_game = -1;
static gint ett_quake2_game_seq1 = -1;
static gint ett_quake2_game_seq2 = -1;
static gint ett_quake2_game_clc = -1;
static gint ett_quake2_game_svc = -1;
static gint ett_quake2_game_clc_cmd = -1;
static gint ett_quake2_game_svc_cmd = -1;
static gint ett_quake2_game_clc_cmd_move_bitfield = -1;
static gint ett_quake2_game_clc_cmd_move_moves = -1;


static dissector_handle_t data_handle;

#define PORT_MASTER 27910
static guint gbl_quake2ServerPort=PORT_MASTER;


static void
dissect_quake2_ConnectionlessPacket(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree, int direction _U_)
{
	proto_tree	*cl_tree = NULL;
	guint8		*text;
	int		len;
	int		offset;

	guint32 marker;

	marker = tvb_get_ntohl(tvb, 0);
	if (tree) {
		proto_item *cl_item = NULL;
		cl_item = proto_tree_add_text(tree, tvb,
				0, -1, "Connectionless");
		cl_tree = proto_item_add_subtree(cl_item, ett_quake2_connectionless);
		proto_tree_add_uint(cl_tree, hf_quake2_connectionless_marker,
				tvb, 0, 4, marker);
	}

	/* all the rest of the packet is just text */
        offset = 4;

        len = tvb_length_remaining(tvb, offset);
        if (cl_tree) {
                text = tvb_get_ephemeral_string(tvb, offset, len);
                proto_tree_add_string(cl_tree, hf_quake2_connectionless_text,
                        tvb, offset, len, text);
        }
        offset += len;

	/* we should analyse the result 'text' a bit further */
	/* for this we need the direction parameter */
}

static const value_string hf_quake2_game_client_command_move_vals[] = {
	{ 0x00,  	"-"   },
	{ 0x01,  	"set" },
	{ 0, NULL }
};

static int
dissect_quake2_client_commands_move(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree)
{
	#define MOVES 3		/* 3 updates per command */

	/* taken from qcommon.h */
	#define CM_ANGLE1   (1<<0)
	#define CM_ANGLE2   (1<<1)
	#define CM_ANGLE3   (1<<2)
	#define CM_FORWARD  (1<<3)
	#define CM_SIDE     (1<<4)
	#define CM_UP       (1<<5)
	#define CM_BUTTONS  (1<<6)
	#define CM_IMPULSE  (1<<7)
	/* qshared.h */
	#define	BUTTON_ATTACK 	1
	#define BUTTON_USE	2
	#define BUTTON_ANY	128

	guint8 	chksum;
	guint32 lastframe;
	int i, offset = 0;
	enum { Q_OFFSET, Q_VALUE, Q_SIZE };
	struct movement {
		guint8 bits[Q_SIZE];
		guint16 angles[3][Q_SIZE];
		gint16 movement[3][Q_SIZE];
		guint8 buttons[Q_SIZE];
		guint8 lightlevel[Q_SIZE];
		guint8 msec[Q_SIZE];
		guint8 impulse[Q_SIZE];
	} move[MOVES+1];

	chksum = tvb_get_guint8(tvb, offset);
	offset++;
	lastframe = tvb_get_letohl(tvb, offset);
	offset += 4;

	for (i=0; i < MOVES; i++) {
		move[i].bits[Q_VALUE] = tvb_get_guint8(tvb, offset);
		move[i].bits[Q_OFFSET] = offset;
		offset++;
		if (move[i].bits[Q_VALUE] & CM_ANGLE1) {
			move[i].angles[0][Q_VALUE] = tvb_get_letohs(tvb, offset);
			move[i].angles[0][Q_OFFSET] = offset;
			offset += 2;
		}
		if (move[i].bits[Q_VALUE] & CM_ANGLE2) {
			move[i].angles[1][Q_VALUE] = tvb_get_letohs(tvb, offset);
			move[i].angles[1][Q_OFFSET] = offset;
			offset += 2;
		}
		if (move[i].bits[Q_VALUE] & CM_ANGLE3) {
			move[i].angles[2][Q_VALUE] = tvb_get_letohs(tvb, offset);
			move[i].angles[2][Q_OFFSET] = offset;
			offset += 2;
		}
		if (move[i].bits[Q_VALUE] & CM_FORWARD) {
			move[i].movement[0][Q_VALUE] = tvb_get_letohs(tvb, offset);
			move[i].movement[0][Q_OFFSET] = offset;
			offset += 2;
		}
		if (move[i].bits[Q_VALUE] & CM_SIDE) {
			move[i].movement[1][Q_VALUE] = tvb_get_letohs(tvb, offset);
			move[i].movement[1][Q_OFFSET] = offset;
			offset += 2;
		}
		if (move[i].bits[Q_VALUE] & CM_UP) {
			move[i].movement[2][Q_VALUE] = tvb_get_letohs(tvb, offset);
			move[i].movement[2][Q_OFFSET] = offset;
			offset += 2;
		}
		if (move[i].bits[Q_VALUE] & CM_BUTTONS) {
			move[i].buttons[Q_VALUE] = tvb_get_guint8(tvb, offset);
			move[i].buttons[Q_OFFSET] = offset;
			offset++;
		}
		if (move[i].bits[Q_VALUE] & CM_IMPULSE) {
			move[i].impulse[Q_VALUE] = tvb_get_guint8(tvb, offset);
			move[i].impulse[Q_OFFSET] = offset;
			offset++;
		}

		move[i].msec[Q_VALUE] = tvb_get_guint8(tvb, offset);
		move[i].msec[Q_OFFSET] = offset;
		offset++;
		move[i].lightlevel[Q_VALUE] = tvb_get_guint8(tvb, offset);
		move[i].lightlevel[Q_OFFSET] = offset;
		offset++;
	}

	if (!tree)
		return offset;

	proto_tree_add_uint(tree, hf_quake2_game_client_command_move_chksum, tvb,
		0, 1, chksum);
	proto_tree_add_uint(tree, hf_quake2_game_client_command_move_lframe, tvb,
		1, 4, lastframe);

	move[MOVES].bits[Q_OFFSET] = offset;
	for (i=0; i < MOVES; i++) {
		proto_item *move_item, *movebits_item, *bit_item;
		proto_item *sub_tree, *field_tree;
		#define SHORT2ANGLE(x) ((float)x/65536.0*360.0)

		move_item = proto_tree_add_text(tree,
				tvb,
				move[i].bits[Q_OFFSET],
				move[i+1].bits[Q_OFFSET]-move[i].bits[Q_OFFSET],
				"Move %u", i+1);
		sub_tree = proto_item_add_subtree(move_item,
				ett_quake2_game_clc_cmd_move_moves);

		movebits_item =
			proto_tree_add_uint(sub_tree, hf_quake2_game_client_command_move,
					tvb,
					move[i].bits[Q_OFFSET],
					1,
					move[i].bits[Q_VALUE]);

		proto_tree_add_uint(sub_tree,
				hf_quake2_game_client_command_move_msec,
				tvb, move[i].msec[Q_OFFSET], 1, move[i].msec[Q_VALUE]);
		proto_tree_add_uint(sub_tree,
				hf_quake2_game_client_command_move_lightlevel,
				tvb, move[i].lightlevel[Q_OFFSET], 1, move[i].lightlevel[Q_VALUE]);

		if (move[i].bits[Q_VALUE] == 0) {
			proto_item_append_text(movebits_item, " (no moves)");
			continue;
		}

		field_tree = proto_item_add_subtree(movebits_item,
				ett_quake2_game_clc_cmd_move_bitfield);

		if (move[i].bits[Q_VALUE] & CM_ANGLE1) {
			bit_item = proto_tree_add_uint(field_tree,
				hf_quake2_game_client_command_move_bitfield_angles1, tvb,
				move[i].angles[0][Q_OFFSET], 2, move[i].bits[Q_VALUE]);
			proto_item_append_text(bit_item, " (%d", move[i].angles[0][Q_VALUE]);
			proto_item_append_text(bit_item, " = %.2f deg)",
					SHORT2ANGLE(move[i].angles[0][Q_VALUE]));
		}

		if (move[i].bits[Q_VALUE] & CM_ANGLE2) {
			bit_item = proto_tree_add_uint(field_tree,
				hf_quake2_game_client_command_move_bitfield_angles2, tvb,
				move[i].angles[1][Q_OFFSET], 2, move[i].bits[Q_VALUE]);
			proto_item_append_text(bit_item, " (%d", move[i].angles[1][Q_VALUE]);
			proto_item_append_text(bit_item, " = %.2f deg)",
					SHORT2ANGLE(move[i].angles[1][Q_VALUE]));
		}
		if (move[i].bits[Q_VALUE] & CM_ANGLE3) {
			bit_item = proto_tree_add_uint(field_tree,
				hf_quake2_game_client_command_move_bitfield_angles3, tvb,
				move[i].angles[2][Q_OFFSET], 2, move[i].bits[Q_VALUE]);
			proto_item_append_text(bit_item, " (%d", move[i].angles[2][Q_VALUE]);
			proto_item_append_text(bit_item, " = %.2f deg)",
					SHORT2ANGLE(move[i].angles[2][Q_VALUE]));
		}
		if (move[i].bits[Q_VALUE] & CM_FORWARD) {
			bit_item = proto_tree_add_uint(field_tree,
				hf_quake2_game_client_command_move_bitfield_movement_fwd, tvb,
				move[i].movement[0][Q_OFFSET], 2, move[i].bits[Q_VALUE]);
			proto_item_append_text(bit_item, " (%hd)",
					move[i].movement[0][Q_VALUE]);
		}
		if (move[i].bits[Q_VALUE] & CM_SIDE) {
			bit_item = proto_tree_add_uint(field_tree,
				hf_quake2_game_client_command_move_bitfield_movement_side, tvb,
				move[i].movement[1][Q_OFFSET], 2, move[i].bits[Q_VALUE]);
			proto_item_append_text(bit_item, " (%hd)",
					move[i].movement[1][Q_VALUE]);
		}
		if (move[i].bits[Q_VALUE] & CM_UP) {
			bit_item = proto_tree_add_uint(field_tree,
				hf_quake2_game_client_command_move_bitfield_movement_up, tvb,
				move[i].movement[2][Q_OFFSET], 2, move[i].bits[Q_VALUE]);
			proto_item_append_text(bit_item, " (%hd)",
					move[i].movement[2][Q_VALUE]);
		}
		if (move[i].bits[Q_VALUE] & CM_BUTTONS) {
			bit_item = proto_tree_add_uint(field_tree,
				hf_quake2_game_client_command_move_bitfield_buttons, tvb,
				move[i].buttons[Q_OFFSET], 1, move[i].bits[Q_VALUE]);
			proto_item_append_text(bit_item, " (%d)",
					move[i].buttons[Q_VALUE]);
			if (move[i].buttons[Q_VALUE] & BUTTON_ATTACK)
				proto_item_append_text(bit_item, " (Attack)");
			if (move[i].buttons[Q_VALUE] & BUTTON_USE)
				proto_item_append_text(bit_item, " (Use)");
			if (move[i].buttons[Q_VALUE] & BUTTON_ANY)
				proto_item_append_text(bit_item, " (Any)");
		}
		if (move[i].bits[Q_VALUE] & CM_IMPULSE) {
			bit_item = proto_tree_add_uint(field_tree,
				hf_quake2_game_client_command_move_bitfield_impulse, tvb,
				move[i].impulse[Q_OFFSET], 1, move[i].bits[Q_VALUE]);
			proto_item_append_text(bit_item, " (%d)",
				move[i].impulse[Q_VALUE]);
		}

	}

	return offset;
}

static int
dissect_quake2_client_commands_uinfo(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint len;

	len = tvb_strsize(tvb, 0);

	if (tree) {
		proto_tree_add_text(tree, tvb, 0, len, "Userinfo: %s",
				    tvb_get_ephemeral_string(tvb, 0, len));
	}

	return len;
}

static int
dissect_quake2_client_commands_stringcmd(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint len;

	len = tvb_strsize(tvb, 0);

	if (tree) {
		proto_tree_add_text(tree, tvb, 0, len, "Command: %s",
				    tvb_get_ephemeral_string(tvb, 0, len));
	}

	return len;
}

static const value_string names_client_cmd[] = {
	/* qcommon.h */
#define CLC_BAD 0
	{ CLC_BAD, "clc_bad" },
#define CLC_NOP 1
	{ CLC_NOP, "clc_nop" },
#define CLC_MOVE 2
	{ CLC_MOVE, "clc_move" },
#define CLC_USERINFO 3
	{ CLC_USERINFO, "clc_userinfo" },
#define CLC_STRINGCMD 4
	{ CLC_STRINGCMD, "clc_stringcmd" },
	{ 0, NULL }
};

static void
dissect_quake2_client_commands(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree)
{
	proto_tree *clc_tree = NULL;
	tvbuff_t *next_tvb   = NULL;
	guint8 client_cmd_type;
	guint rest_length = 0;
	int   offset      = 0;

	do {
		client_cmd_type = tvb_get_guint8(tvb, offset);

		if (tree) {
			proto_item *cmd_type_item = proto_tree_add_uint(tree,
					hf_quake2_game_client_command, tvb, offset, 1,
					client_cmd_type);

			proto_item_append_text(cmd_type_item, " (%s)",
					       val_to_str(client_cmd_type, names_client_cmd, "%u"));
			clc_tree = proto_item_add_subtree(cmd_type_item, ett_quake2_game_clc_cmd);
		}

		offset++;
		rest_length = tvb_reported_length(tvb) - offset;
		if (rest_length)
			next_tvb = tvb_new_subset(tvb, offset,
					rest_length, rest_length);
		else
			return;

		rest_length = 0;
		switch (client_cmd_type) {
			case CLC_BAD:
				break;
			case CLC_NOP:
				break;
			case CLC_MOVE:
				rest_length =
					dissect_quake2_client_commands_move(next_tvb,
							pinfo, clc_tree);
				break;
			case CLC_USERINFO:
				rest_length =
					dissect_quake2_client_commands_uinfo(next_tvb,
							pinfo, clc_tree);
				break;
			case CLC_STRINGCMD:
				rest_length =
					dissect_quake2_client_commands_stringcmd(next_tvb,
							pinfo, clc_tree);
				break;
			default:
				break;
		}
		offset += rest_length;
	} while (tvb_reported_length(tvb) - offset > 0);
}

static const value_string names_server_cmd[] = {
	/* qcommon.h */
#define SVC_BAD 0
	{ SVC_BAD, "svc_bad" },
#define SVC_MUZZLEFLASH 1
	{ SVC_MUZZLEFLASH, "svc_muzzleflash" },
#define SVC_MUZZLEFLASH2 2
	{ SVC_MUZZLEFLASH2, "svc_muzzleflash2" },
#define SVC_TEMP_ENTITY 3
	{ SVC_TEMP_ENTITY, "svc_temp_entity" },
#define SVC_LAYOUT 4
	{ SVC_LAYOUT, "svc_layout" },
#define SVC_INVENTORY 5
	{ SVC_INVENTORY, "svc_inventory" },
#define SVC_NOP 6
	{ SVC_NOP, "svc_nop" },
#define SVC_DISCONNECT 7
	{ SVC_DISCONNECT, "svc_disconnect" },
#define SVC_RECONNECT 8
	{ SVC_RECONNECT, "svc_reconnect" },
#define SVC_SOUND 9
	{ SVC_SOUND, "svc_sound" },
#define SVC_PRINT 10
	{ SVC_PRINT, "svc_print" },
#define SVC_STUFFTEXT 11
	{ SVC_STUFFTEXT, "svc_stufftext" },
#define SVC_SERVERDATA 12
	{ SVC_SERVERDATA, "svc_serverdata" },
#define  SVC_CONFIGSTRING 13
	{ SVC_CONFIGSTRING, "svc_configstring" },
#define SVC_SPAWNBASELINE 14
	{ SVC_SPAWNBASELINE, "svc_spawnbaseline" },
#define SVC_CENTERPRINT 15
	{ SVC_CENTERPRINT, "svc_centerprint" },
#define SVC_DOWNLOAD 16
	{ SVC_DOWNLOAD, "svc_download" },
#define SVC_PLAYERINFO 17
	{ SVC_PLAYERINFO, "svc_playerinfo" },
#define SVC_PACKETENTITIES 18
	{ SVC_PACKETENTITIES, "svc_packetentities" },
#define SVC_DELTAPACKETENTITIES 19
	{ SVC_DELTAPACKETENTITIES, "svc_deltapacketentities" },
#define SVC_FRAME 20
	{ SVC_FRAME, "svc_frame" },
	{ 0, NULL }
};

static void
dissect_quake2_server_commands(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree)
{
	tvbuff_t *next_tvb = NULL;
	guint8 server_cmd_type;
	guint rest_length = 0;
	int offset = 0;

	server_cmd_type = tvb_get_guint8(tvb, offset);

	if (tree) {
		proto_item *cmd_type_item;
		cmd_type_item = proto_tree_add_uint(tree,
				hf_quake2_game_server_command, tvb, offset, 1, server_cmd_type);

		proto_item_append_text(cmd_type_item, " (%s)",
				       val_to_str(server_cmd_type, names_server_cmd, "%u"));
	}

	offset++;
	rest_length = tvb_reported_length(tvb) - offset;
	if (rest_length)
		next_tvb = tvb_new_subset(tvb, offset, rest_length, rest_length);
	else
		return;


	switch (server_cmd_type) {
		case SVC_BAD:
			break;
		case SVC_MUZZLEFLASH:
			break;
		case SVC_MUZZLEFLASH2:
			break;
		case SVC_TEMP_ENTITY:
			break;
		case SVC_LAYOUT:
			break;
		case SVC_NOP:
			break;
		case SVC_DISCONNECT:
			break;
		case SVC_RECONNECT:
			break;
		case SVC_SOUND:
			break;
		case SVC_PRINT:
			break;
		case SVC_STUFFTEXT:
			break;
		case SVC_SERVERDATA:
			break;
		case SVC_CONFIGSTRING:
			break;
		case SVC_SPAWNBASELINE:
			break;
		case SVC_CENTERPRINT:
			break;
		case SVC_DOWNLOAD:
			break;
		case SVC_PLAYERINFO:
			break;
		case SVC_PACKETENTITIES:
			break;
		case SVC_DELTAPACKETENTITIES:
			break;
		case SVC_FRAME:
			break;

		default:
			break;
	}
	call_dissector(data_handle, next_tvb, pinfo, tree);
}


static const value_string names_reliable[] = {
        { 0, "Non Reliable" },
        { 1, "Reliable" },
        { 0, NULL }
};

static const value_string names_direction[] = {
#define DIR_C2S 0
	{ DIR_C2S, "Client to Server" },
#define DIR_S2C 1
	{ DIR_S2C, "Server to Client" },
	{ 0, NULL }
};


static void
dissect_quake2_GamePacket(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int direction)
{
	proto_tree *game_tree = NULL;
	guint32    seq1;
	guint32    seq2;
	int        rel1;
	int        rel2;
	int        offset;
	guint      rest_length;

	direction = (pinfo->destport == gbl_quake2ServerPort) ?
			DIR_C2S : DIR_S2C;

	if (tree) {
		proto_item *game_item;
		game_item = proto_tree_add_text(tree, tvb,
				0, -1, "Game");
		game_tree = proto_item_add_subtree(game_item, ett_quake2_game);
	}

	offset = 0;

	seq1 = tvb_get_letohl(tvb, offset);
	rel1 = seq1 & 0x80000000 ? 1 : 0;
	seq1 &= ~0x80000000;
	if (game_tree) {
		proto_item *seq1_item = proto_tree_add_text(game_tree,
			tvb, offset, 4, "Current Sequence: %u (%s)",
			seq1, val_to_str(rel1,names_reliable,"%u"));
		proto_tree *seq1_tree = proto_item_add_subtree(
			seq1_item, ett_quake2_game_seq1);
		proto_tree_add_uint(seq1_tree, hf_quake2_game_seq1,
				    tvb, offset, 4, seq1);
		proto_tree_add_boolean(seq1_tree, hf_quake2_game_rel1,
				       tvb, offset+3, 1, rel1);
	}
	offset += 4;

	seq2 = tvb_get_letohl(tvb, offset);
	rel2 = seq2 & 0x80000000 ? 1 : 0;
	seq2 &= ~0x80000000;
	if (game_tree) {
		proto_item *seq2_item = proto_tree_add_text(game_tree,
			tvb, offset, 4, "Acknowledge Sequence: %u (%s)",
			seq2, val_to_str(rel2,names_reliable,"%u"));
		proto_tree *seq2_tree = proto_item_add_subtree(
			seq2_item, ett_quake2_game_seq2);
		proto_tree_add_uint(seq2_tree, hf_quake2_game_seq2,
				    tvb, offset, 4, seq2);
		proto_tree_add_boolean(seq2_tree, hf_quake2_game_rel2,
				       tvb, offset+3, 1, rel2);
	}
	offset += 4;

	if (direction == DIR_C2S) {
		/* client to server */
		guint16 qport = tvb_get_letohs(tvb, offset);
		if (game_tree) {
			proto_tree_add_uint(game_tree, hf_quake2_game_qport,
				tvb, offset, 2, qport);
		}
		offset +=2;
	}

	/* all the rest is pure game data */
	rest_length = tvb_reported_length(tvb) - offset;
	if (rest_length) {
		tvbuff_t *next_tvb =
		tvb_new_subset(tvb, offset, rest_length , rest_length);

		if (direction == DIR_C2S) {
			proto_tree *c_tree = NULL;
			if (tree) {
				proto_item *c_item;
				c_item = proto_tree_add_text(game_tree, next_tvb,
							     0, -1, "Client Commands");
				c_tree = proto_item_add_subtree(c_item, ett_quake2_game_clc);
			}
			dissect_quake2_client_commands(next_tvb, pinfo, c_tree);
		}
		else {
			proto_tree *c_tree = NULL;
			if (tree) {
				proto_item *c_item;
				c_item = proto_tree_add_text(game_tree, next_tvb,
							     0, -1, "Server Commands");
				c_tree = proto_item_add_subtree(c_item, ett_quake2_game_svc);
			}
			dissect_quake2_server_commands(next_tvb, pinfo, c_tree);
		}
	}
}


static void
dissect_quake2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*quake2_tree = NULL;
	int		direction;

	direction = (pinfo->destport == gbl_quake2ServerPort) ?
			DIR_C2S : DIR_S2C;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUAKE2");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(direction,
			names_direction, "%u"));

	if (tree) {
		proto_item *quake2_item;
		quake2_item = proto_tree_add_item(tree, proto_quake2,
						  tvb, 0, -1, FALSE);
		quake2_tree = proto_item_add_subtree(quake2_item, ett_quake2);
		proto_tree_add_uint_format(quake2_tree,
					   direction == DIR_S2C ?
					   hf_quake2_s2c :
					   hf_quake2_c2s,
					   tvb, 0, 0, 1,
					   "Direction: %s", val_to_str(direction, names_direction, "%u"));
	}

	if (tvb_get_ntohl(tvb, 0) == 0xffffffff) {
		col_append_str(pinfo->cinfo, COL_INFO, " Connectionless");
		if (quake2_tree)
			proto_tree_add_uint_format(quake2_tree,
				hf_quake2_connectionless,
				tvb, 0, 0, 1,
				"Type: Connectionless");
		dissect_quake2_ConnectionlessPacket(
			tvb, pinfo, quake2_tree, direction);
	}
	else {
		col_append_str(pinfo->cinfo, COL_INFO, " Game");
		if (quake2_tree)
			proto_tree_add_uint_format(quake2_tree,
				hf_quake2_game,
				tvb, 0, 0, 1,
				"Type: Game");
		dissect_quake2_GamePacket(
			tvb, pinfo, quake2_tree, direction);
	}
}


void proto_reg_handoff_quake2(void);

void
proto_register_quake2(void)
{
	static hf_register_info hf[] = {
		{ &hf_quake2_c2s,
			{ "Client to Server", "quake2.c2s",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quake2_s2c,
			{ "Server to Client", "quake2.s2c",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quake2_connectionless,
			{ "Connectionless", "quake2.connectionless",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quake2_game,
			{ "Game", "quake2.game",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quake2_connectionless_marker,
			{ "Marker", "quake2.connectionless.marker",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quake2_connectionless_text,
			{ "Text", "quake2.connectionless.text",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_quake2_game_seq1,
			{ "Sequence Number", "quake2.game.seq1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Sequence number of the current packet", HFILL }},
		{ &hf_quake2_game_rel1,
			{ "Reliable", "quake2.game.rel1",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Packet is reliable and may be retransmitted", HFILL }},
		{ &hf_quake2_game_seq2,
			{ "Sequence Number", "quake2.game.seq2",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Sequence number of the last received packet", HFILL }},
		{ &hf_quake2_game_rel2,
			{ "Reliable", "quake2.game.rel2",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Packet was reliable and may be retransmitted", HFILL }},
		{ &hf_quake2_game_qport,
			{ "QPort", "quake2.game.qport",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Quake II Client Port", HFILL }},
		{ &hf_quake2_game_client_command,
			{ "Client Command Type", "quake2.game.client.command",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Quake II Client Command", HFILL }},
		{ &hf_quake2_game_server_command,
			{ "Server Command", "quake2.game.server.command",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Quake II Server Command", HFILL }},
		{ &hf_quake2_game_client_command_move_chksum,
			{ "Checksum", "quake2.game.client.command.move.chksum",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Quake II Client Command Move", HFILL }},
		{ &hf_quake2_game_client_command_move_lframe,
			{ "Last Frame", "quake2.game.client.command.move.lframe",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Quake II Client Command Move", HFILL }},
		{ &hf_quake2_game_client_command_move,
			{ "Bitfield", "quake2.game.client.command.move",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Quake II Client Command Move", HFILL }},
		{ &hf_quake2_game_client_command_move_bitfield_angles1,
			{ "Angles (pitch)", "quake2.game.client.command.move.angles",
			FT_UINT8, BASE_HEX,
			VALS(hf_quake2_game_client_command_move_vals),
			CM_ANGLE1, NULL, HFILL }},
		{ &hf_quake2_game_client_command_move_bitfield_angles2,
			{ "Angles (yaw)", "quake2.game.client.command.move.angles",
			FT_UINT8, BASE_HEX,
			VALS(hf_quake2_game_client_command_move_vals),
			CM_ANGLE2, NULL, HFILL }},
		{ &hf_quake2_game_client_command_move_bitfield_angles3,
			{ "Angles (roll)", "quake2.game.client.command.move.angles",
			FT_UINT8, BASE_HEX,
			VALS(hf_quake2_game_client_command_move_vals),
			CM_ANGLE3, NULL, HFILL }},
		{ &hf_quake2_game_client_command_move_bitfield_movement_fwd,
			{ "Movement (fwd)", "quake2.game.client.command.move.movement",
			FT_UINT8, BASE_HEX,
			VALS(hf_quake2_game_client_command_move_vals),
			CM_FORWARD, NULL, HFILL }},
		{ &hf_quake2_game_client_command_move_bitfield_movement_side,
			{ "Movement (side)", "quake2.game.client.command.move.movement",
			FT_UINT8, BASE_HEX,
			VALS(hf_quake2_game_client_command_move_vals),
			CM_SIDE, NULL, HFILL }},
		{ &hf_quake2_game_client_command_move_bitfield_movement_up,
			{ "Movement (up)", "quake2.game.client.command.move.movement",
			FT_UINT8, BASE_HEX,
			VALS(hf_quake2_game_client_command_move_vals),
			CM_UP, NULL, HFILL }},
		{ &hf_quake2_game_client_command_move_bitfield_buttons,
			{ "Buttons", "quake2.game.client.command.move.buttons",
			FT_UINT8, BASE_HEX,
			VALS(hf_quake2_game_client_command_move_vals),
			CM_BUTTONS, NULL, HFILL }},
		{ &hf_quake2_game_client_command_move_bitfield_impulse,
			{ "Impulse", "quake2.game.client.command.move.impulse",
			FT_UINT8, BASE_HEX,
			VALS(hf_quake2_game_client_command_move_vals),
			CM_IMPULSE, NULL, HFILL }},
		{ &hf_quake2_game_client_command_move_msec,
			{ "Msec", "quake2.game.client.command.move.msec",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Quake II Client Command Move", HFILL }},
		{ &hf_quake2_game_client_command_move_lightlevel,
			{ "Lightlevel", "quake2.game.client.command.move.lightlevel",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Quake II Client Command Move", HFILL }}
	};
	static gint *ett[] = {
		&ett_quake2,
		&ett_quake2_connectionless,
		&ett_quake2_game,
		&ett_quake2_game_seq1,
		&ett_quake2_game_seq2,
		&ett_quake2_game_clc,
		&ett_quake2_game_svc,
		&ett_quake2_game_clc_cmd,
		&ett_quake2_game_svc_cmd,
		&ett_quake2_game_clc_cmd_move_moves,
		&ett_quake2_game_clc_cmd_move_bitfield
	};
	module_t *quake2_module;

	proto_quake2 = proto_register_protocol("Quake II Network Protocol",
						"QUAKE2", "quake2");
	proto_register_field_array(proto_quake2, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
	quake2_module = prefs_register_protocol(proto_quake2,
		proto_reg_handoff_quake2);
	prefs_register_uint_preference(quake2_module, "udp.port",
					"Quake II Server UDP Port",
					"Set the UDP port for the Quake II Server",
					10, &gbl_quake2ServerPort);
}


void
proto_reg_handoff_quake2(void)
{
	static gboolean Initialized=FALSE;
	static dissector_handle_t quake2_handle;
	static guint ServerPort;

	if (!Initialized) {
		quake2_handle = create_dissector_handle(dissect_quake2,
				proto_quake2);
		data_handle = find_dissector("data");
		Initialized=TRUE;
	} else {
		dissector_delete_uint("udp.port", ServerPort, quake2_handle);
	}

        /* set port for future deletes */
        ServerPort=gbl_quake2ServerPort;

	dissector_add_uint("udp.port", gbl_quake2ServerPort, quake2_handle);
}


