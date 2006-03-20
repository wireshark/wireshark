/* packet-netsync.c
 * Routines for Monotone Netsync packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2005 by Erwin Rol <erwin@erwinrol.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/emem.h>
#include "packet-tcp.h"

/*
 * See
 *
 *	http://www.venge.net/monotone/
 */

/* Define TCP ports for Monotone netsync */

#define TCP_PORT_NETSYNC 5253

#define NETSYNC_ROLE_SOURCE	1
#define NETSYNC_ROLE_SINK	2
#define NETSYNC_ROLE_BOTH	3

static const value_string netsync_role_vals[] = {
	{ NETSYNC_ROLE_SOURCE,	"Source" },
	{ NETSYNC_ROLE_SINK,	"Sink" },
	{ NETSYNC_ROLE_BOTH,	"Both" },
	{ 0,			NULL }
};


#define NETSYNC_CMD_ERROR	0
#define NETSYNC_CMD_BYE		1
#define NETSYNC_CMD_HELLO	2
#define NETSYNC_CMD_ANONYMOUS	3
#define NETSYNC_CMD_AUTH	4
#define NETSYNC_CMD_CONFIRM	5
#define NETSYNC_CMD_REFINE	6
#define NETSYNC_CMD_DONE	7
#define NETSYNC_CMD_SEND_DATA	8
#define NETSYNC_CMD_SEND_DELTA	9
#define NETSYNC_CMD_DATA	10
#define NETSYNC_CMD_DELTA	11
#define NETSYNC_CMD_NONEXISTANT	12

static const value_string netsync_cmd_vals[] = {
	{ NETSYNC_CMD_ERROR,		"Error" },
	{ NETSYNC_CMD_BYE, 		"Bye" },
	{ NETSYNC_CMD_HELLO,		"Hello" },
	{ NETSYNC_CMD_ANONYMOUS, 	"Anonymous" },
	{ NETSYNC_CMD_AUTH, 		"Auth" },
	{ NETSYNC_CMD_CONFIRM, 		"Confirm" },
	{ NETSYNC_CMD_REFINE, 		"Refine" },
	{ NETSYNC_CMD_DONE, 		"Done" },
	{ NETSYNC_CMD_SEND_DATA,	"Send Data" },
	{ NETSYNC_CMD_SEND_DELTA, 	"Send Delta" },
	{ NETSYNC_CMD_DATA,		"Data" },
	{ NETSYNC_CMD_DELTA,		"Delta" },
	{ NETSYNC_CMD_NONEXISTANT, 	"Nonexistant" },
	{ 0,				NULL }
};

#define NETSNYC_MERKLE_HASH_LENGTH 20

void proto_reg_handoff_netsync(void);

/* Define the monotone netsync proto */
static int proto_netsync = -1;

static int hf_netsync_version = -1;
static int hf_netsync_command = -1;
static int hf_netsync_size = -1;
static int hf_netsync_data = -1;
static int hf_netsync_checksum = -1;

static int hf_netsync_cmd_done_level = -1;
static int hf_netsync_cmd_done_type = -1;

static int hf_netsync_cmd_hello_keyname = -1;
static int hf_netsync_cmd_hello_key = -1;
static int hf_netsync_cmd_nonce = -1;

static int hf_netsync_cmd_anonymous_role = -1;
static int hf_netsync_cmd_anonymous_collection = -1;

static int hf_netsync_cmd_send_data_type = -1;
static int hf_netsync_cmd_send_data_id = -1;

static int hf_netsync_cmd_error_msg = -1;


static int hf_netsync_cmd_confirm_sig = -1;

static int hf_netsync_cmd_auth_role = -1;
static int hf_netsync_cmd_auth_collection = -1;
static int hf_netsync_cmd_auth_id = -1;
static int hf_netsync_cmd_auth_nonce1 = -1;
static int hf_netsync_cmd_auth_nonce2 = -1;
static int hf_netsync_cmd_auth_sig = -1;

static int hf_netsync_cmd_data_type = -1;
static int hf_netsync_cmd_data_id = -1;
static int hf_netsync_cmd_data_compressed = -1;
static int hf_netsync_cmd_data_payload = -1;

static int hf_netsync_cmd_delta_type = -1;
static int hf_netsync_cmd_delta_base_id = -1;
static int hf_netsync_cmd_delta_ident_id = -1;
static int hf_netsync_cmd_delta_compressed = -1;
static int hf_netsync_cmd_delta_payload = -1;

static int hf_netsync_cmd_refine_tree_node = -1;

static int hf_netsync_cmd_send_delta_type = -1;
static int hf_netsync_cmd_send_delta_base_id = -1;
static int hf_netsync_cmd_send_delta_ident_id = -1;

static int hf_netsync_cmd_nonexistant_type = -1;
static int hf_netsync_cmd_nonexistant_id = -1;

/* Define the tree for netsync */
static int ett_netsync = -1;


/*
 * Here are the global variables associated with the preferences
 * for monotone netsync
 */

static dissector_handle_t netsync_handle;

static guint global_tcp_port_netsync = TCP_PORT_NETSYNC;
static guint tcp_port_netsync = TCP_PORT_NETSYNC;
static gboolean netsync_desegment = TRUE;

static gint dissect_uleb128( tvbuff_t *tvb, gint offset, guint* size)
{
	guint shift = 0;
	guint8 tmp;
	guint start_offset = offset;

	*size = 0;

	/* get size */
	do {
		tmp = tvb_get_guint8(tvb, offset);
		offset += 1;
			
		*size |= (tmp & 0x7F) << shift;
		shift += 7;	
	} while (tmp & 0x80);


	return offset - start_offset;
}

static gint dissect_netsync_cmd_error( tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_) 
{
	guint len = 0;

	offset += dissect_uleb128( tvb, offset, &len );

	proto_tree_add_item(tree, hf_netsync_cmd_error_msg, tvb,
				offset, len, FALSE );
	offset += len;

	return offset;
}

static gint dissect_netsync_cmd_bye(tvbuff_t *tvb _U_,  gint offset, proto_tree *tree _U_, guint size _U_)
{
	return offset;
}


static gint dissect_netsync_cmd_hello(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_)
{
	guint len = 0;

	offset += dissect_uleb128( tvb, offset, &len );

	proto_tree_add_item(tree, hf_netsync_cmd_hello_keyname, tvb,
				offset, len, FALSE );
	offset += len;


	offset += dissect_uleb128( tvb, offset, &len );

	proto_tree_add_item(tree, hf_netsync_cmd_hello_key, tvb,
				offset, len, FALSE );
	offset += len;

	proto_tree_add_item(tree, hf_netsync_cmd_nonce, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	return offset;
}


static gint dissect_netsync_cmd_anonymous(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_)
{
	guint len = 0;

	proto_tree_add_item(tree, hf_netsync_cmd_anonymous_role, tvb,
				offset, 1, FALSE );
	offset += 1;

	offset += dissect_uleb128( tvb, offset, &len );

	proto_tree_add_item(tree, hf_netsync_cmd_anonymous_collection, tvb,
				offset, len, FALSE );
	offset += len;

	proto_tree_add_item(tree, hf_netsync_cmd_nonce, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	return offset;
}


static gint dissect_netsync_cmd_auth(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_)
{
	guint len = 0;

	proto_tree_add_item(tree, hf_netsync_cmd_auth_role, tvb,
				offset, 1, FALSE );
	offset += 1;


	offset += dissect_uleb128( tvb, offset, &len );

	proto_tree_add_item(tree, hf_netsync_cmd_auth_collection, tvb,
				offset, len, FALSE );
	offset += len;

	proto_tree_add_item(tree, hf_netsync_cmd_auth_id, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	offset += len;

	proto_tree_add_item(tree, hf_netsync_cmd_auth_nonce1, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	offset += len;

	proto_tree_add_item(tree, hf_netsync_cmd_auth_nonce2, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	offset += dissect_uleb128( tvb, offset, &len );

	proto_tree_add_item(tree, hf_netsync_cmd_auth_sig, tvb,
				offset, len, FALSE );
	offset += len;

	return offset;
}


static gint dissect_netsync_cmd_confirm(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_)
{
	guint len = 0;

	offset += dissect_uleb128( tvb, offset, &len );

	proto_tree_add_item(tree, hf_netsync_cmd_confirm_sig, tvb,
				offset, len, FALSE );
	offset += len;


	return offset;
}


static gint dissect_netsync_cmd_refine(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size)
{
	proto_tree_add_item(tree, hf_netsync_cmd_refine_tree_node, tvb,
				offset, size, FALSE );
	offset += size;

	return offset;
}


static gint dissect_netsync_cmd_done(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_)
{
	guint len = 0;
	guint bytes = 0;

	bytes = dissect_uleb128( tvb, offset, &len );

	proto_tree_add_uint(tree, hf_netsync_cmd_done_level, tvb,
					offset, bytes, len );
	offset += bytes;

	proto_tree_add_item(tree, hf_netsync_cmd_done_type, tvb,
				offset, 1, FALSE );
	offset += 1;

	return offset;
}


static gint dissect_netsync_cmd_send_data(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_)
{
	proto_tree_add_item(tree, hf_netsync_cmd_send_data_type, tvb,
					offset, 1, FALSE );
        offset += 1;

	proto_tree_add_item(tree, hf_netsync_cmd_send_data_id, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	return offset;
}


static gint dissect_netsync_cmd_send_delta(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_)
{
	proto_tree_add_item(tree, hf_netsync_cmd_send_delta_type, tvb,
					offset, 1, FALSE );
        offset += 1;

	proto_tree_add_item(tree, hf_netsync_cmd_send_delta_base_id, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;


	proto_tree_add_item(tree, hf_netsync_cmd_send_delta_ident_id, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	return offset;
}


static gint dissect_netsync_cmd_data(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_)
{
	guint len = -1;
	
	proto_tree_add_item(tree, hf_netsync_cmd_data_type, tvb,
				offset, 1, FALSE );
	offset += 1;

	proto_tree_add_item(tree, hf_netsync_cmd_data_id, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	proto_tree_add_item(tree, hf_netsync_cmd_data_compressed, tvb,
				offset, 1, FALSE );
	offset += 1;

	offset += dissect_uleb128( tvb, offset, &len );

	proto_tree_add_item(tree, hf_netsync_cmd_data_payload, tvb,
				offset, len, FALSE );
	offset += len;

	return offset;
}


static gint dissect_netsync_cmd_delta(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_)
{
	guint len = 0;

	proto_tree_add_item(tree, hf_netsync_cmd_delta_type, tvb,
				offset, 1, FALSE );
	offset += 1;

	proto_tree_add_item(tree, hf_netsync_cmd_delta_base_id, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	proto_tree_add_item(tree, hf_netsync_cmd_delta_ident_id, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	proto_tree_add_item(tree, hf_netsync_cmd_delta_compressed, tvb,
				offset, 1, FALSE );
	offset += 1;

	offset += dissect_uleb128( tvb, offset, &len );

	proto_tree_add_item(tree, hf_netsync_cmd_delta_payload, tvb,
				offset, len, FALSE );
	offset += len;

	return offset;
}


static gint dissect_netsync_cmd_nonexistant(tvbuff_t *tvb,  gint offset, proto_tree *tree, guint size _U_)
{
	proto_tree_add_item(tree, hf_netsync_cmd_nonexistant_type, tvb,
				offset, 1, FALSE );
	offset += 1;

	proto_tree_add_item(tree, hf_netsync_cmd_nonexistant_id, tvb,
				offset, NETSNYC_MERKLE_HASH_LENGTH, FALSE );
	offset += NETSNYC_MERKLE_HASH_LENGTH;

	return offset;
}

static guint
get_netsync_pdu_len(tvbuff_t *tvb, int offset)
{
	guint size = 0, size_bytes;

	/* skip version and command */
	offset += 2;
	
	size_bytes = dissect_uleb128( tvb, offset, &size );
		
	/* the calculated size if for the data only, this doesn't
	 * include the version (1 byte), command (1 byte), 
	 * lenght (size_bytes bytes) and checksum (4 bytes)
	 */

	return 1 + 1 + size_bytes + size + 4;
}

static void
dissect_netsync_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
	gint offset = 0;
	guint8 tmp;
	guint8 cmd, version;
	guint32 size, size_bytes, shift;
	proto_tree *ti,*netsync_tree=NULL;

	/* Set the protocol column */
	if (check_col(pinfo->cinfo,COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo,COL_PROTOCOL,"Netsync");
	}


	if (tree == NULL)
		return;
	
	while (tvb_reported_length_remaining(tvb, offset)  > 0) {
		ti = proto_tree_add_item(tree, proto_netsync, tvb, offset, -1, FALSE);
		netsync_tree = proto_item_add_subtree(ti, ett_netsync);

		version = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(netsync_tree, hf_netsync_version, tvb,
					offset, 1, FALSE );
		offset += 1;

		cmd = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(netsync_tree, hf_netsync_command, tvb,
					offset, 1, FALSE );
		offset += 1;


		/* get size */
		size = 0;
		size_bytes = 0;
		shift = 0;
		do {
			tmp = tvb_get_guint8(tvb, offset + size_bytes);
			size_bytes += 1;
			
			size |= (tmp & 0x7F) << shift;
			shift += 7;	
		} while (tmp & 0x80);
		
		
		proto_tree_add_uint(netsync_tree, hf_netsync_size, tvb,
                                        offset, size_bytes, size );
		offset += size_bytes;

		switch (cmd) {
			case NETSYNC_CMD_DONE:
				dissect_netsync_cmd_done( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_ERROR:
				dissect_netsync_cmd_error( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_BYE:
				dissect_netsync_cmd_bye( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_HELLO:
				dissect_netsync_cmd_hello( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_ANONYMOUS:
				dissect_netsync_cmd_anonymous( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_AUTH:
				dissect_netsync_cmd_auth( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_CONFIRM:
				dissect_netsync_cmd_confirm( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_REFINE:
				dissect_netsync_cmd_refine( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_SEND_DATA:
				dissect_netsync_cmd_send_data( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_SEND_DELTA:
				dissect_netsync_cmd_send_delta( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_DATA:
				dissect_netsync_cmd_data( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_DELTA:
				dissect_netsync_cmd_delta( tvb, offset, netsync_tree, size );
				break;

			case NETSYNC_CMD_NONEXISTANT:
				dissect_netsync_cmd_nonexistant( tvb, offset, netsync_tree, size );
				break;

			default:
				proto_tree_add_item(netsync_tree, hf_netsync_data, tvb,
					offset, size, FALSE );
				break;
		}

		offset += size;

		proto_tree_add_item(netsync_tree, hf_netsync_checksum, tvb,
					offset, 4, FALSE );
		offset += 4;


		proto_item_append_text(netsync_tree, " V%d, Cmd: %s (%d), Size: %d", 
					version, val_to_str(cmd, netsync_cmd_vals, "(0x%x)"), cmd, size );		

		proto_item_set_len(netsync_tree, 1+1+size_bytes+size+4);
	}
}

static void
dissect_netsync(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, netsync_desegment, 7, get_netsync_pdu_len,
					dissect_netsync_pdu);
}

void
proto_register_netsync(void) 
{
	static hf_register_info hf[] = {
		/* General */
		{ &hf_netsync_version,
			{ "Version", "netsync.version",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "Version", HFILL } },
		{ &hf_netsync_command,
			{ "Command", "netsync.command",
			  FT_UINT8, BASE_HEX, VALS(netsync_cmd_vals), 0x0,
			  "Command", HFILL } },
		{ &hf_netsync_size,
			{ "Size", "netsync.size",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "Size", HFILL } },
		{ &hf_netsync_data,
			{ "Data", "netsync.data",
			  FT_BYTES, BASE_HEX, NULL, 0x0,
			  "Data", HFILL } },
		{ &hf_netsync_checksum,
			{ "Checksum", "netsync.checksum",
			  FT_UINT32, BASE_HEX, NULL, 0x0,
			  "Checksum", HFILL } },
		{ &hf_netsync_cmd_hello_keyname,
			{ "Key Name", "netsync.cmd.hello.keyname",
			  FT_STRING, BASE_HEX, NULL, 0x0,
			  "Key Name", HFILL } },
		{ &hf_netsync_cmd_hello_key,
			{ "Key", "netsync.cmd.hello.key",
			  FT_BYTES, BASE_HEX, NULL, 0x0,
			  "Key", HFILL } },
		{ &hf_netsync_cmd_nonce,
			{ "Nonce", "netsync.cmd.nonce",
			  FT_BYTES, BASE_HEX, NULL, 0x0,
			  "Nonce", HFILL } },
		{ &hf_netsync_cmd_anonymous_role,
			{ "Role", "netsync.cmd.anonymous.role",
			  FT_UINT8, BASE_DEC, VALS(netsync_role_vals), 0x0,
			  "Role", HFILL } },
		{ &hf_netsync_cmd_anonymous_collection,
			{ "Collection", "netsync.cmd.anonymous.collection",
			  FT_STRING, BASE_DEC, NULL, 0x0,
			  "Collection", HFILL } },
		{ &hf_netsync_cmd_confirm_sig,
			{ "Signature", "netsync.cmd.confirm.signature",
			  FT_BYTES, BASE_HEX, NULL, 0x0,
			  "Signature", HFILL } },
		{ &hf_netsync_cmd_send_data_type,
			{ "Type", "netsync.cmd.send_data.type",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "Type", HFILL } },
		{ &hf_netsync_cmd_send_data_id,
			{ "ID", "netsync.cmd.send_data.id",
			  FT_BYTES, BASE_HEX, NULL, 0x0,
			  "ID", HFILL } },
		{ &hf_netsync_cmd_error_msg,
			{ "Message", "netsync.cmd.error.msg",
			  FT_STRING, BASE_DEC, NULL, 0x0,
			  "Message", HFILL } },

		{ &hf_netsync_cmd_done_level,
			{ "Level", "netsync.cmd.done.level",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "Level", HFILL } },
		{ &hf_netsync_cmd_auth_role,
			{ "Role", "netsync.cmd.auth.role",
			  FT_UINT8, BASE_DEC, VALS(netsync_role_vals), 0x0,
			  "Role", HFILL } },
		{ &hf_netsync_cmd_auth_collection,
			{ "Collection", "netsync.cmd.auth.collection",
			  FT_STRING, BASE_DEC, NULL, 0x0,
			  "Collection", HFILL } },
		{ &hf_netsync_cmd_auth_id,
			{ "ID", "netsync.cmd.auth.id",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "ID", HFILL } },
		{ &hf_netsync_cmd_auth_nonce1,
			{ "Nonce 1", "netsync.cmd.auth.nonce1",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "Nonce 1", HFILL } },
		{ &hf_netsync_cmd_auth_nonce2,
			{ "Nonce 2", "netsync.cmd.auth.nonce2",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "Nonce 2", HFILL } },
		{ &hf_netsync_cmd_auth_sig,
			{ "Signature", "netsync.cmd.auth.sig",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "Signature", HFILL } },
		{ &hf_netsync_cmd_data_type,
			{ "Type", "netsync.cmd.data.type",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "Type", HFILL } },
		{ &hf_netsync_cmd_data_id,
			{ "ID", "netsync.cmd.data.id",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "ID", HFILL } },
		{ &hf_netsync_cmd_data_compressed,
			{ "Compressed", "netsync.cmd.data.compressed",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "Compressed", HFILL } },
		{ &hf_netsync_cmd_data_payload,
			{ "Payload", "netsync.cmd.data.payload",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "Payload", HFILL } },
		{ &hf_netsync_cmd_delta_type,
			{ "Type", "netsync.cmd.delta.type",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "Type", HFILL } },
		{ &hf_netsync_cmd_delta_base_id,
			{ "Base ID", "netsync.cmd.delta.base_id",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "Base ID", HFILL } },
		{ &hf_netsync_cmd_delta_ident_id,
			{ "Ident ID", "netsync.cmd.delta.ident_id",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "Ident ID", HFILL } },
		{ &hf_netsync_cmd_delta_compressed,
			{ "Compressed", "netsync.cmd.delta.compressed",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "Compressed", HFILL } },
		{ &hf_netsync_cmd_delta_payload,
			{ "Payload", "netsync.cmd.delta.payload",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "Payload", HFILL } },
		{ &hf_netsync_cmd_refine_tree_node,
			{ "Tree Node", "netsync.cmd.refine.tree_node",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "Tree Node", HFILL } },
		{ &hf_netsync_cmd_send_delta_type,
			{ "Type", "netsync.cmd.send_delta.type",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "Type", HFILL } },
		{ &hf_netsync_cmd_send_delta_base_id,
			{ "Base ID", "netsync.cmd.send_delta.base_id",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "Base ID", HFILL } },
		{ &hf_netsync_cmd_send_delta_ident_id,
			{ "Ident ID", "netsync.cmd.send_delta.ident_id",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "Ident ID", HFILL } },
		{ &hf_netsync_cmd_nonexistant_id,
			{ "ID", "netsync.cmd.nonexistant.id",
			  FT_BYTES, BASE_DEC, NULL, 0x0,
			  "ID", HFILL } },
		{ &hf_netsync_cmd_nonexistant_type,
			{ "Type", "netsync.cmd.nonexistant.type",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "Type", HFILL } },
		{ &hf_netsync_cmd_done_type,
			{ "Type", "netsync.cmd.done.type",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "Type", HFILL } }


	};

	static gint *ett[] = {
		&ett_netsync,
	};

	module_t *netsync_module;

	proto_netsync = proto_register_protocol("Monotone Netsync", "Netsync", "netsync");
	proto_register_field_array(proto_netsync, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netsync_handle = create_dissector_handle(dissect_netsync, proto_netsync);

	netsync_module = prefs_register_protocol(proto_netsync,
						proto_reg_handoff_netsync);

	prefs_register_uint_preference(netsync_module, "tcp_port",
					"Monotone Netsync TCP Port",
					"The TCP port on which Monotone Netsync packets will be sent",
					10, &global_tcp_port_netsync);


	prefs_register_bool_preference(netsync_module, "desegment_netsync_messages",
		"Reassemble Netsync messages spanning multiple TCP segments",
		"Whether the Netsync dissector should reassemble messages spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&netsync_desegment);

}

void
proto_reg_handoff_netsync(void) 
{
	static gint initialized = 0;

	if (initialized) {
		dissector_delete("tcp.port", tcp_port_netsync, netsync_handle);
	} else {
		initialized = 1;
	}

	tcp_port_netsync = global_tcp_port_netsync;  
	dissector_add("tcp.port", global_tcp_port_netsync, netsync_handle);
}

