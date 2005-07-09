/* packet-bittorrent.c
 * Routines for bittorrent packet dissection
 * Copyright (C) 2004 Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-tcp.h"

/*
 * See
 *
 *	http://bittorrent.com/protocol.html
 */

#define BITTORRENT_MESSAGE_CHOKE			0
#define BITTORRENT_MESSAGE_UNCHOKE			1
#define BITTORRENT_MESSAGE_INTERESTED		2
#define BITTORRENT_MESSAGE_NOT_INTERESTED	3
#define BITTORRENT_MESSAGE_HAVE				4
#define BITTORRENT_MESSAGE_BITFIELD			5
#define BITTORRENT_MESSAGE_REQUEST			6
#define BITTORRENT_MESSAGE_PIECE			7
#define BITTORRENT_MESSAGE_CANCEL			8

static const value_string bittorrent_messages[] = {
	{ BITTORRENT_MESSAGE_CHOKE, "Choke" },
	{ BITTORRENT_MESSAGE_UNCHOKE, "Unchoke" },
	{ BITTORRENT_MESSAGE_INTERESTED, "Interested" },
	{ BITTORRENT_MESSAGE_NOT_INTERESTED, "Not Interested" },
	{ BITTORRENT_MESSAGE_HAVE, "Have" },
	{ BITTORRENT_MESSAGE_BITFIELD, "Bitfield" },
	{ BITTORRENT_MESSAGE_REQUEST, "Request" },
	{ BITTORRENT_MESSAGE_PIECE, "Piece" },
	{ BITTORRENT_MESSAGE_CANCEL, "Cancel" },
	{ 0, NULL }
};

static int proto_bittorrent = -1;

static gint hf_bittorrent_field_length  = -1;
static gint hf_bittorrent_prot_name_len = -1;
static gint hf_bittorrent_prot_name     = -1;
static gint hf_bittorrent_reserved 		= -1;
static gint hf_bittorrent_sha1_hash		= -1;
static gint hf_bittorrent_peer_id 		= -1;
static gint hf_bittorrent_msg_len		= -1;
static gint hf_bittorrent_msg_type		= -1;
static gint hf_bittorrent_bitfield_data	= -1;
static gint hf_bittorrent_piece_index	= -1;
static gint hf_bittorrent_piece_begin	= -1;
static gint hf_bittorrent_piece_length	= -1;
static gint hf_bittorrent_piece_data	= -1;

static gint ett_bittorrent = -1;
static gint ett_bittorrent_msg = -1;

static gboolean bittorrent_desegment = TRUE;

static dissector_handle_t bittorrent_handle;

static guint get_bittorrent_pdu_length(tvbuff_t *tvb, int offset)
{
	if (tvb_get_guint8(tvb, offset) == 19) {
		return 20 + 20 + 20 + 8;
	} else {
		guint32 length = tvb_get_ntohl(tvb, offset);
		return 4 + length;
	}
}

static void dissect_bittorrent_message (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_tree *mtree;
	guint8 type;
	guint32 length = tvb_get_ntohl(tvb, offset);
	proto_item *ti = proto_tree_add_text(tree, tvb, offset, length, "BitTorrent Message");

	mtree = proto_item_add_subtree(ti, ett_bittorrent_msg);
								  
	proto_tree_add_item(mtree, hf_bittorrent_msg_len, tvb, offset, 4, FALSE); offset+=4;

	/* Keepalive message */
	if (length == 0) {
	    if (check_col(pinfo->cinfo, COL_INFO)) {
		    col_set_str(pinfo->cinfo, COL_INFO, "BitTorrent KeepAlive message");
		}
		return;
	}
	
	type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(mtree, hf_bittorrent_msg_type, tvb, offset, 1, FALSE); offset+=1;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		const char *val = match_strval(type, bittorrent_messages);
		if (val != NULL) {
		    col_set_str(pinfo->cinfo, COL_INFO, val);
		}
	}

	switch (type) 
	{
	case BITTORRENT_MESSAGE_CHOKE:
	case BITTORRENT_MESSAGE_UNCHOKE:
	case BITTORRENT_MESSAGE_INTERESTED:
	case BITTORRENT_MESSAGE_NOT_INTERESTED:
		/* No payload */
		break;
		

	case BITTORRENT_MESSAGE_REQUEST:
	case BITTORRENT_MESSAGE_CANCEL:
		proto_tree_add_item(mtree, hf_bittorrent_piece_index, tvb, offset, 4, FALSE); offset += 4;
		proto_tree_add_item(mtree, hf_bittorrent_piece_begin, tvb, offset, 4, FALSE); offset += 4;
		proto_tree_add_item(mtree, hf_bittorrent_piece_length, tvb, offset, 4, FALSE);
		break;
		
	case BITTORRENT_MESSAGE_HAVE:
		proto_tree_add_item(mtree, hf_bittorrent_piece_index, tvb, offset, 4, FALSE);
		break;
		
	case BITTORRENT_MESSAGE_BITFIELD:
		proto_tree_add_item(mtree, hf_bittorrent_bitfield_data, tvb, offset, tvb_length_remaining(tvb, offset), FALSE); 
		break;
		
	case BITTORRENT_MESSAGE_PIECE:
		proto_tree_add_item(mtree, hf_bittorrent_piece_index, tvb, offset, 4, FALSE); offset += 4;
		proto_tree_add_item(mtree, hf_bittorrent_piece_begin, tvb, offset, 4, FALSE); offset += 4;
		proto_tree_add_item(mtree, hf_bittorrent_piece_data, tvb, offset, tvb_length_remaining(tvb, offset), FALSE);
		break;
	}
}

static void dissect_bittorrent_welcome (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_set_str(pinfo->cinfo, COL_INFO, "BitTorrent Handshake");
	}

	proto_tree_add_item(tree, hf_bittorrent_prot_name_len, tvb, offset, 1, FALSE); offset+=1;
	proto_tree_add_item(tree, hf_bittorrent_prot_name, tvb, offset, 19, FALSE); offset += 19;
	proto_tree_add_item(tree, hf_bittorrent_reserved, tvb, offset, 8, FALSE); offset += 8;
	proto_tree_add_item(tree, hf_bittorrent_sha1_hash, tvb, offset, 20, FALSE); offset += 20;
	proto_tree_add_item(tree, hf_bittorrent_peer_id, tvb, offset, 20, FALSE); offset += 20;
}

static void dissect_bittorrent_tcp_pdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BitTorrent");
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_set_str(pinfo->cinfo, COL_INFO, "BitTorrent Peer-To-Peer connection");
	}

	ti = proto_tree_add_text(tree, tvb, 0, -1, "BitTorrent");

	tree = proto_item_add_subtree(ti, ett_bittorrent);

	if (tvb_get_guint8(tvb, 0) == 19) {
		dissect_bittorrent_welcome(tvb, pinfo, tree);
	} else {
		dissect_bittorrent_message(tvb, pinfo, tree);
	}
}

static void dissect_bittorrent (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, bittorrent_desegment, 4, get_bittorrent_pdu_length, dissect_bittorrent_tcp_pdu);
}

static const guint8 bittorrent_magic[20] = {
	19,
	'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't',
	' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'
};

static gboolean test_bittorrent_packet (tvbuff_t *tvb, packet_info *pinfo,
										     proto_tree *tree)
{
	conversation_t *conversation;

	if (tvb_memeql(tvb, 0, bittorrent_magic, sizeof bittorrent_magic) == -1) {
		return FALSE;
	}

	conversation = conversation_new (pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

	conversation_set_dissector(conversation, bittorrent_handle);
	
	dissect_bittorrent(tvb, pinfo, tree);

	return TRUE;
}



void
proto_register_bittorrent(void)
{

  static hf_register_info hf[] = {
	  { &hf_bittorrent_field_length, 
		  { "Field Length", "bittorrent.length", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_prot_name_len,
		  { "Protocol Name Length", "bittorrent.protocol.name.length", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_prot_name,
		  { "Protocol Name", "bittorrent.protocol.name", FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_reserved,
		  { "Reserved Extension Bytes", "bittorrent.reserved", FT_BYTES, BASE_DEC, NULL, 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_sha1_hash,
		  { "SHA1 Hash of info dictionary", "bittorrent.info_hash", FT_BYTES, BASE_DEC, NULL, 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_peer_id,
		  { "Peer ID", "bittorrent.peer_id", FT_BYTES, BASE_DEC, NULL, 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_msg_len,
		  { "Message Length", "bittorrent.msg.length", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	  }, 
	  { &hf_bittorrent_msg_type,
		  { "Message Type", "bittorrent.msg.type", FT_UINT8, BASE_HEX, VALS(bittorrent_messages), 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_bitfield_data,
		  { "Bitfield data", "bittorrent.msg.bitfield", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_piece_index,
		  { "Piece index", "bittorrent.piece.index", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_piece_begin,
		  { "Begin offset of piece", "bittorrent.piece.begin", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_piece_data, 
		  { "Data in a piece", "bittorrent.piece.data", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL },
	  },
	  { &hf_bittorrent_piece_length,
		  { "Piece Length", "bittorrent.piece.length", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	  },
  };

  static gint *ett[] = {
    &ett_bittorrent,
	&ett_bittorrent_msg,
  };

  module_t *bittorrent_module;

  proto_bittorrent = proto_register_protocol("BitTorrent", "BitTorrent", "bittorrent");
  proto_register_field_array(proto_bittorrent, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  bittorrent_module = prefs_register_protocol(proto_bittorrent, NULL);
  prefs_register_bool_preference(bittorrent_module, "desegment",
    "Reassemble BitTorrent messages spanning multiple TCP segments",
    "Whether the BitTorrent dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &bittorrent_desegment);
}


void
proto_reg_handoff_bittorrent(void)
{
	register_dissector("bittorrent", dissect_bittorrent, proto_bittorrent);
	bittorrent_handle = find_dissector("bittorrent");
  	heur_dissector_add("tcp", test_bittorrent_packet, proto_bittorrent);
}
