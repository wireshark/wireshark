/* packet-ctdb.c
 * Routines for CTDB (Cluster TDB) dissection
 * Copyright 2007, Ronnie Sahlberg
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/value_string.h>
#include <epan/conversation.h>
#include <epan/emem.h>

/* Initialize the protocol and registered fields */
static int proto_ctdb = -1;
static int hf_ctdb_length = -1;
static int hf_ctdb_opcode = -1;
static int hf_ctdb_magic = -1;
static int hf_ctdb_version = -1;
static int hf_ctdb_dst = -1;
static int hf_ctdb_src = -1;
static int hf_ctdb_id = -1;
static int hf_ctdb_flags_immediate = -1;
static int hf_ctdb_dbid = -1;
static int hf_ctdb_callid = -1;
static int hf_ctdb_status = -1;
static int hf_ctdb_datalen = -1;

/* Initialize the subtree pointers */
static gint ett_ctdb = -1;



#define CTDB_REQ_CALL		0
#define CTDB_REPLY_CALL		1
#define CTDB_REPLY_REDIRECT	2
#define CTDB_REQ_DMASTER	3
#define CTDB_REPLY_DMASTER	4
#define CTDB_REPLY_ERROR	5
#define CTDB_REQ_MESSAGE	6
static const value_string ctdb_opcodes[] = {
	{CTDB_REQ_CALL,			"CTDB_REQ_CALL"},
	{CTDB_REPLY_CALL,		"CTDB_REPLY_CALL"},
	{CTDB_REPLY_REDIRECT,		"CTDB_REPLY_REDIRECT"},
	{CTDB_REQ_DMASTER,		"CTDB_REQ_DMASTER"},
	{CTDB_REPLY_DMASTER,		"CTDB_REPLY_DMASTER"},
	{CTDB_REPLY_ERROR,		"CTDB_REPLY_ERROR"},
	{CTDB_REQ_MESSAGE,		"CTDB_REQ_MESSAGE"},
	{0,NULL}
};


static int
dissect_ctdb_reply_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int endianess)
{
	/* status */
	proto_tree_add_item(tree, hf_ctdb_status, tvb, offset, 4, endianess);
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	offset+=4;

	/* data */
	
	return offset;
}

static int
dissect_ctdb_reply_dmaster(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int endianess)
{
	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	offset+=4;

	/* data */
	
	return offset;
}

static const true_false_string flags_immediate_tfs={
	"DMASTER for the record must IMMEDIATELY be migrated to the caller",
	"Dmaster migration is not required"
};

static int
dissect_ctdb_req_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int endianess)
{
	guint32 flags;

	/* flags */
	proto_tree_add_item(tree, hf_ctdb_flags_immediate, tvb, offset, 4, endianess);
	if(endianess){
		flags=tvb_get_letohl(tvb, offset);
	} else {
		flags=tvb_get_ntohl(tvb, offset);
	}
	if(flags&0x00000001){
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " IMMEDIATE");
		}
	}	
	offset+=4;

	/* dbid */
	proto_tree_add_item(tree, hf_ctdb_dbid, tvb, offset, 4, endianess);
	offset+=4;

	/* callid */
	proto_tree_add_item(tree, hf_ctdb_callid, tvb, offset, 4, endianess);
	offset+=4;

	/* keylen */
	/* calldatalen */
	/* data */
	return offset;
}


static gboolean
dissect_ctdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_tree *tree=NULL;
	proto_item *item=NULL;
	int offset=0;
	guint32 opcode, src, dst;
	int endianess;

	/* does this look like CTDB? */
	if(tvb_length_remaining(tvb, offset)<8){
		return FALSE;
	}
	switch(tvb_get_letohl(tvb, offset+4)){
	case 0x42445443:
		endianess=FALSE;
		break;
	case 0x43544442:
		endianess=TRUE;
		break;
	default:
		return FALSE;
	}
	

	if(check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CTDB");
	}
	if(check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_ctdb, tvb, offset,
			-1, endianess);
		tree=proto_item_add_subtree(item, ett_ctdb);
	}

	/* header*/
	/* length */
	proto_tree_add_item(tree, hf_ctdb_length, tvb, offset, 4, endianess);
	offset+=4;

	/* magic */
	proto_tree_add_item(tree, hf_ctdb_magic, tvb, offset, 4, endianess);
	offset+=4;

	/* version */
	proto_tree_add_item(tree, hf_ctdb_version, tvb, offset, 4, endianess);
	offset+=4;

	/* opcode */
	proto_tree_add_item(tree, hf_ctdb_opcode, tvb, offset, 4, endianess);
	if(endianess){
		opcode=tvb_get_letohl(tvb, offset);
	} else {
		opcode=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* dst */
	proto_tree_add_item(tree, hf_ctdb_dst, tvb, offset, 4, endianess);
	if(endianess){
		dst=tvb_get_letohl(tvb, offset);
	} else {
		dst=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* src */
	proto_tree_add_item(tree, hf_ctdb_src, tvb, offset, 4, endianess);
	if(endianess){
		src=tvb_get_letohl(tvb, offset);
	} else {
		src=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* id */
	proto_tree_add_item(tree, hf_ctdb_id, tvb, offset, 4, endianess);
	offset+=4;

	if(check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s %d->%d",
			val_to_str(opcode, ctdb_opcodes, "Unknown:%d"),
			src, dst);
	}

	switch(opcode){
	case CTDB_REQ_CALL:
		offset=dissect_ctdb_req_call(tvb, offset, pinfo, tree, endianess);
		break;
	case CTDB_REPLY_CALL:
		offset=dissect_ctdb_reply_call(tvb, offset, pinfo, tree, endianess);
		break;
	case CTDB_REPLY_DMASTER:
		offset=dissect_ctdb_reply_dmaster(tvb, offset, pinfo, tree, endianess);
		break;
	case CTDB_REPLY_REDIRECT:
		break;
	case CTDB_REQ_DMASTER:
		break;
	case CTDB_REPLY_ERROR:
		break;
	case CTDB_REQ_MESSAGE:
		break;
	};

	return TRUE;
}


/*
 * Register the protocol with Wireshark
 */
void
proto_register_ctdb(void)
{
	static hf_register_info hf[] = {
	{ &hf_ctdb_length, { 
	  "Length", "ctdb.len", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "Size of CTDB PDU", HFILL }},
	{ &hf_ctdb_dst, { 
	  "Destination", "ctdb.dst", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_src, { 
	  "Source", "ctdb.src", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_id, { 
	  "Id", "ctdb.id", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "Transaction ID", HFILL }},
	{ &hf_ctdb_opcode, { 
	  "Opcode", "ctdb.opcode", FT_UINT32, BASE_DEC, 
	  VALS(ctdb_opcodes), 0x0, "CTDB command opcode", HFILL }},
	{ &hf_ctdb_flags_immediate, { 
	  "Immediate", "ctdb.immediate", FT_BOOLEAN, 32, 
	  TFS(&flags_immediate_tfs), 0x00000001, "Force migration of DMASTER?", HFILL }},
	{ &hf_ctdb_dbid, { 
	  "DB Id", "ctdb.dbid", FT_UINT32, BASE_HEX, 
	  NULL, 0x0, "Database ID", HFILL }},
	{ &hf_ctdb_callid, { 
	  "Call Id", "ctdb.callid", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "Call ID", HFILL }},
	{ &hf_ctdb_status, { 
	  "Status", "ctdb.status", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_datalen, { 
	  "Data Length", "ctdb.datalen", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_magic, { 
	  "Magic", "ctdb.magic", FT_UINT32, BASE_HEX, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_version, { 
	  "Version", "ctdb.version", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "", HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ctdb,
	};

	/* Register the protocol name and description */
	proto_ctdb = proto_register_protocol("Cluster TDB", "CTDB", "ctdb");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_ctdb, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_ctdb(void)
{
	dissector_handle_t ctdb_handle;

	ctdb_handle = new_create_dissector_handle(dissect_ctdb, proto_ctdb);
	dissector_add_handle("tcp.port", ctdb_handle);

	heur_dissector_add("tcp", dissect_ctdb, proto_ctdb);
}
