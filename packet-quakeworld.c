/* packet-quakeworld.c
 * Routines for QuakeWorld packet dissection
 *
 * Uwe Girlich <uwe@planetquake.com>
 *	http://www.idsoftware.com/q1source/q1source.zip
 *
 * $Id: packet-quakeworld.c,v 1.1 2001/06/21 15:15:02 girlich Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-quake.c
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

#include <glib.h>
#include "packet.h"
#include "prefs.h"

static int proto_quakeworld = -1;

static int hf_quakeworld_s2c = -1;
static int hf_quakeworld_c2s = -1;
static int hf_quakeworld_connectionless = -1;
static int hf_quakeworld_game = -1;
static int hf_quakeworld_connectionless_marker = -1;
static int hf_quakeworld_connectionless_text = -1;
static int hf_quakeworld_game_seq1 = -1;
static int hf_quakeworld_game_rel1 = -1;
static int hf_quakeworld_game_seq2 = -1;
static int hf_quakeworld_game_rel2 = -1;
static int hf_quakeworld_game_qport = -1;

static gint ett_quakeworld = -1;
static gint ett_quakeworld_connectionless = -1;
static gint ett_quakeworld_game = -1;
static gint ett_quakeworld_game_seq1 = -1;
static gint ett_quakeworld_game_seq2 = -1;
static gint ett_quakeworld_game_clc = -1;
static gint ett_quakeworld_game_svc = -1;


/* I took this name and value directly out of the QW source. */
#define PORT_MASTER 27500
static unsigned int gbl_quakeworldServerPort=PORT_MASTER;


static void
dissect_quakeworld_ConnectionlessPacket(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int direction)
{
	proto_tree	*cl_tree = NULL;
	proto_item	*cl_item = NULL;
	guint8		text[2048];
	int		maxbufsize = 0;
	int		len;
	int		offset;

	guint32 marker;

	marker = tvb_get_ntohl(tvb, 0);
	if (tree) {
		cl_item = proto_tree_add_text(tree, tvb,
				0, tvb_length(tvb), "Connectionless");
		if (cl_item)
			cl_tree = proto_item_add_subtree(
				cl_item, ett_quakeworld_connectionless);
	}

	if (cl_tree) {
		proto_tree_add_uint(cl_tree, hf_quakeworld_connectionless_marker,
				tvb, 0, 4, marker);
	}

	/* all the rest of the packet is just text */
        offset = 4;

        maxbufsize = MIN((gint)sizeof(text), tvb_length_remaining(tvb, offset));
        len = tvb_get_nstringz0(tvb, offset, maxbufsize, text);
        if (tree) {
                proto_tree_add_string(cl_tree, hf_quakeworld_connectionless_text,
                        tvb, offset, len + 1, text);
        }
        offset += len + 1;

	/* we should analyse the result 'text' a bit further */
	/* for this we need the direction parameter */
}


static void
dissect_quakeworld_client_commands(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree)
{
	/* If I have too much time at hand, I'll fill it with all
	   the information from my QWD specs:
		http://www.planetquake.com/demospecs/qwd/
	*/
	dissect_data(tvb, 0, pinfo, tree);
}


static void
dissect_quakeworld_server_commands(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree)
{
	/* If I have too much time at hand, I'll fill it with all
	   the information from my QWD specs:
		http://www.planetquake.com/demospecs/qwd/
	*/
	dissect_data(tvb, 0, pinfo, tree);
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
dissect_quakeworld_GamePacket(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int direction)
{
	proto_tree	*game_tree = NULL;
	proto_item	*game_item = NULL;
	guint32 seq1;
	guint32 seq2;
	int rel1;
	int rel2;
	int offset;
	guint		rest_length;

	direction = (pinfo->destport == gbl_quakeworldServerPort) ?
			DIR_C2S : DIR_S2C;

	if (tree) {
		game_item = proto_tree_add_text(tree, tvb,
				0, tvb_length(tvb), "Game");
		if (game_item)
			game_tree = proto_item_add_subtree(
				game_item, ett_quakeworld_game);
	}

	offset = 0;

	seq1 = tvb_get_letohl(tvb, offset);
	rel1 = seq1 & 0x80000000 ? 1 : 0;
	seq1 &= ~0x80000000;
	if (game_tree) {
		proto_item *seq1_item = proto_tree_add_text(game_tree,
			tvb, offset, 4, "Current Sequence: %u (%s)",
			seq1, val_to_str(rel1,names_reliable,"%u"));
		if (seq1_item) {
			proto_tree *seq1_tree = proto_item_add_subtree(
				seq1_item, ett_quakeworld_game_seq1);
			proto_tree_add_uint(seq1_tree, hf_quakeworld_game_seq1,
					tvb, offset, 4, seq1);
			proto_tree_add_boolean(seq1_tree, hf_quakeworld_game_rel1,
					tvb, offset+3, 1, rel1);
		}
	}
	offset += 4;

	seq2 = tvb_get_letohl(tvb, offset);
	rel2 = seq2 & 0x80000000 ? 1 : 0;
	seq2 &= ~0x80000000;
	if (game_tree) {
		proto_item *seq2_item = proto_tree_add_text(game_tree,
			tvb, offset, 4, "Acknowledge Sequence: %u (%s)",
			seq2, val_to_str(rel2,names_reliable,"%u"));;
		if (seq2_item) {
			proto_tree *seq2_tree = proto_item_add_subtree(
				seq2_item, ett_quakeworld_game_seq2);
			proto_tree_add_uint(seq2_tree, hf_quakeworld_game_seq2,
					tvb, offset, 4, seq2);
			proto_tree_add_boolean(seq2_tree, hf_quakeworld_game_rel2,
					tvb, offset+3, 1, rel2);
		}
	}
	offset += 4;

	if (direction == DIR_C2S) {
		/* client to server */
		guint16 qport = tvb_get_letohs(tvb, offset);
		if (game_tree) {
			proto_tree_add_uint(game_tree, hf_quakeworld_game_qport, 
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
			proto_item *c_item = NULL;
			proto_tree *c_tree = NULL;
			if (tree) {
				c_item = proto_tree_add_text(game_tree, next_tvb,
				0, tvb_length(next_tvb),
				"Client Commands");
				if (c_item) {
					c_tree = proto_item_add_subtree(
						c_item, ett_quakeworld_game_clc);
				}
			}
			dissect_quakeworld_client_commands(next_tvb, pinfo, c_tree);
		}
		else {
			proto_item *c_item = NULL;
			proto_tree *c_tree = NULL;
			if (tree) {
				c_item = proto_tree_add_text(game_tree, next_tvb,
				0, tvb_length(next_tvb),
				"Server Commands");
				if (c_item) {
					c_tree = proto_item_add_subtree(
					c_item, ett_quakeworld_game_svc);
				}
			}
			dissect_quakeworld_server_commands(next_tvb, pinfo, c_tree);
		}
	}
}


static void
dissect_quakeworld(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*quakeworld_tree = NULL;
	proto_item	*quakeworld_item = NULL;
	int		direction;

	/*
	 * XXX - this is a conversation dissector, and the code to
	 * call a conversation dissector doesn't check for disabled
	 * protocols or set "pinfo->current_proto".
	 */
	CHECK_DISPLAY_AS_DATA(proto_quakeworld, tvb, pinfo, tree);

	direction = (pinfo->destport == gbl_quakeworldServerPort) ?
			DIR_C2S : DIR_S2C;

	pinfo->current_proto = "QUAKEWORLD";

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "QUAKEWORLD");
	if (check_col(pinfo->fd, COL_INFO))
		col_set_str(pinfo->fd, COL_INFO, val_to_str(direction,
			names_direction, "%u"));

	if (tree) {
		quakeworld_item = proto_tree_add_item(tree, proto_quakeworld,
				tvb, 0, tvb_length(tvb), FALSE);
		if (quakeworld_item)
			quakeworld_tree = proto_item_add_subtree(
				quakeworld_item, ett_quakeworld);
			if (quakeworld_tree) {
				proto_tree_add_uint_format(quakeworld_tree,
					direction == DIR_S2C ?
					hf_quakeworld_s2c :
					hf_quakeworld_c2s,
					tvb, 0, 0, 1,
					"Direction: %s", val_to_str(direction, names_direction, "%u"));
			}
	}

	if (tvb_get_ntohl(tvb, 0) == 0xffffffff) {
		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_str(pinfo->fd, COL_INFO, " Connectionless");
		}
		if (quakeworld_tree)
			proto_tree_add_uint_format(quakeworld_tree,
				hf_quakeworld_connectionless,
				tvb, 0, 0, 1,
				"Type: Connectionless");
		dissect_quakeworld_ConnectionlessPacket(
			tvb, pinfo, quakeworld_tree, direction);
	}
	else {
		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_str(pinfo->fd, COL_INFO, " Game");
		}
		if (quakeworld_tree)
			proto_tree_add_uint_format(quakeworld_tree,
				hf_quakeworld_game,
				tvb, 0, 0, 1,
				"Type: Game");
		dissect_quakeworld_GamePacket(
			tvb, pinfo, quakeworld_tree, direction);
	}
}


void
proto_reg_handoff_quakeworld(void)
{
	static int Initialized=FALSE;
	static int ServerPort=0;
 
	if (Initialized) {
		dissector_delete("udp.port", ServerPort, dissect_quakeworld);
	} else {
		Initialized=TRUE;
	}
 
        /* set port for future deletes */
        ServerPort=gbl_quakeworldServerPort;
 
	dissector_add("udp.port", gbl_quakeworldServerPort,
			dissect_quakeworld, proto_quakeworld);
}


void
proto_register_quakeworld(void)
{
	static hf_register_info hf[] = {
		{ &hf_quakeworld_c2s,
			{ "Client to Server", "quakeworld.c2s",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Client to Server", HFILL }},
		{ &hf_quakeworld_s2c,
			{ "Server to Client", "quakeworld.s2c",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Server to Client", HFILL }},
		{ &hf_quakeworld_connectionless,
			{ "Connectionless", "quakeworld.connectionless",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Connectionless", HFILL }},
		{ &hf_quakeworld_game,
			{ "Game", "quakeworld.game",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Game", HFILL }},
		{ &hf_quakeworld_connectionless_marker,
			{ "Marker", "quakeworld.connectionless.marker",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Marker", HFILL }},
		{ &hf_quakeworld_connectionless_text,
			{ "Text", "quakeworld.connectionless.text",
			FT_STRING, BASE_DEC, NULL, 0x0,
			"Text", HFILL }},
		{ &hf_quakeworld_game_seq1,
			{ "Sequence Number", "quakeworld.game.seq1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Sequence number of the current packet", HFILL }},
		{ &hf_quakeworld_game_rel1,
			{ "Reliable", "quakeworld.game.rel1",
			FT_BOOLEAN, BASE_DEC, NULL, 0x0,
			"Packet is reliable and may be retransmitted", HFILL }},
		{ &hf_quakeworld_game_seq2,
			{ "Sequence Number", "quakeworld.game.seq2",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Sequence number of the last received packet", HFILL }},
		{ &hf_quakeworld_game_rel2,
			{ "Reliable", "quakeworld.game.rel2",
			FT_BOOLEAN, BASE_DEC, NULL, 0x0,
			"Packet was reliable and may be retransmitted", HFILL }},
		{ &hf_quakeworld_game_qport,
			{ "QPort", "quakeworld.game.qport",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"QuakeWorld Client Port", HFILL }}
	};
	static gint *ett[] = {
		&ett_quakeworld,
		&ett_quakeworld_connectionless,
		&ett_quakeworld_game,
		&ett_quakeworld_game_seq1,
		&ett_quakeworld_game_seq2,
		&ett_quakeworld_game_clc,
		&ett_quakeworld_game_svc
	};
	module_t *quakeworld_module;

	proto_quakeworld = proto_register_protocol("QuakeWorld Network Protocol",
						"QUAKEWORLD", "quakeworld");
	proto_register_field_array(proto_quakeworld, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
	quakeworld_module = prefs_register_protocol(proto_quakeworld,
		proto_reg_handoff_quakeworld);
	prefs_register_uint_preference(quakeworld_module, "udp.port",
					"QuakeWorld Server UDP Port",
					"Set the UDP port for the QuakeWorld Server",
					10, &gbl_quakeworldServerPort);
}

