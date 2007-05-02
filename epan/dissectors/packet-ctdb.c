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
static int hf_ctdb_keylen = -1;
static int hf_ctdb_datalen = -1;
static int hf_ctdb_key = -1;
static int hf_ctdb_keyhash = -1;
static int hf_ctdb_data = -1;
static int hf_ctdb_dmaster = -1;
static int hf_ctdb_request_in = -1;
static int hf_ctdb_response_in = -1;
static int hf_ctdb_time = -1;
static int hf_ctdb_xid = -1;
static int hf_ctdb_generation = -1;
static int hf_ctdb_hopcount = -1;
static int hf_ctdb_rsn = -1;
static int hf_ctdb_ctrl_opcode = -1;
static int hf_ctdb_srvid = -1;
static int hf_ctdb_ctrl_flags = -1;

/* Initialize the subtree pointers */
static gint ett_ctdb = -1;
static gint ett_ctdb_key = -1;

/* this tree keeps track of caller/reqid for ctdb transactions */
emem_tree_t *ctdb_transactions=NULL;
typedef struct _ctdb_trans_t {
	guint32 key_hash;
	gint32 request_in;
	gint32 response_in;
	nstime_t req_time;
} ctdb_trans_t;


#define CTDB_REQ_CALL		0
#define CTDB_REPLY_CALL		1
#define CTDB_REQ_DMASTER		2
#define CTDB_REPLY_DMASTER		3
#define CTDB_REPLY_ERROR		4
#define CTDB_REQ_MESSAGE		5
#define CTDB_REQ_FINISHED		6
#define CTDB_REQ_CONTROL		7
#define CTDB_REPLY_CONTROL		8
static const value_string ctdb_opcodes[] = {
	{CTDB_REQ_CALL,		"CTDB_REQ_CALL"},
	{CTDB_REPLY_CALL,		"CTDB_REPLY_CALL"},
	{CTDB_REQ_DMASTER,		"CTDB_REQ_DMASTER"},
	{CTDB_REPLY_DMASTER,		"CTDB_REPLY_DMASTER"},
	{CTDB_REPLY_ERROR,		"CTDB_REPLY_ERROR"},
	{CTDB_REQ_MESSAGE,		"CTDB_REQ_MESSAGE"},
	{CTDB_REQ_FINISHED,		"CTDB_REQ_FINISHED"},
	{CTDB_REQ_CONTROL,		"CTDB_REQ_CONTROL"},
	{CTDB_REPLY_CONTROL,		"CTDB_REPLY_CONTROL"},
	{0,NULL}
};


#define CTDB_CONTROL_PROCESS_EXISTS		0
#define CTDB_CONTROL_STATUS			1
#define CTDB_CONTROL_CONFIG			2
#define CTDB_CONTROL_PING			3
#define CTDB_CONTROL_GETDBPATH		4
#define CTDB_CONTROL_GETVNNMAP		5
#define CTDB_CONTROL_SETVNNMAP		6
#define CTDB_CONTROL_GET_DEBUG		7
#define CTDB_CONTROL_SET_DEBUG		8
#define CTDB_CONTROL_GET_DBMAP		9
#define CTDB_CONTROL_GET_NODEMAP		10
#define CTDB_CONTROL_SET_DMASTER		11
#define CTDB_CONTROL_CLEAR_DB		12
#define CTDB_CONTROL_PULL_DB			13
#define CTDB_CONTROL_PUSH_DB			14
#define CTDB_CONTROL_GET_RECMODE		15
#define CTDB_CONTROL_SET_RECMODE		16
#define CTDB_CONTROL_STATUS_RESET		17
#define CTDB_CONTROL_DB_ATTACH		18
#define CTDB_CONTROL_SET_CALL		19
#define CTDB_CONTROL_WRITE_RECORD		20
static const value_string ctrl_opcode_vals[] = {
	{CTDB_CONTROL_PROCESS_EXISTS,"CTDB_CONTROL_PROCESS_EXISTS"},
	{CTDB_CONTROL_STATUS,	"CTDB_CONTROL_STATUS"},
	{CTDB_CONTROL_CONFIG,	"CTDB_CONTROL_CONFIG"},
	{CTDB_CONTROL_PING,		"CTDB_CONTROL_PING"},
	{CTDB_CONTROL_GETDBPATH,	"CTDB_CONTROL_GETDBPATH"},
	{CTDB_CONTROL_GETVNNMAP,	"CTDB_CONTROL_GETVNNMAP"},
	{CTDB_CONTROL_SETVNNMAP,	"CTDB_CONTROL_SETVNNMAP"},
	{CTDB_CONTROL_GET_DEBUG,	"CTDB_CONTROL_GET_DEBUG"},
	{CTDB_CONTROL_SET_DEBUG,	"CTDB_CONTROL_SET_DEBUG"},
	{CTDB_CONTROL_GET_DBMAP,	"CTDB_CONTROL_GET_DBMAP"},
	{CTDB_CONTROL_GET_NODEMAP,	"CTDB_CONTROL_GET_NODEMAP"},
	{CTDB_CONTROL_SET_DMASTER,	"CTDB_CONTROL_SET_DMASTER"},
	{CTDB_CONTROL_CLEAR_DB,	"CTDB_CONTROL_CLEAR_DB"},
	{CTDB_CONTROL_PULL_DB,	"CTDB_CONTROL_PULL_DB"},
	{CTDB_CONTROL_PUSH_DB,	"CTDB_CONTROL_PUSH_DB"},
	{CTDB_CONTROL_GET_RECMODE,	"CTDB_CONTROL_GET_RECMODE"},
	{CTDB_CONTROL_SET_RECMODE,	"CTDB_CONTROL_SET_RECMODE"},
	{CTDB_CONTROL_STATUS_RESET,	"CTDB_CONTROL_STATUS_RESET"},
	{CTDB_CONTROL_DB_ATTACH,	"CTDB_CONTROL_DB_ATTACH"},
	{CTDB_CONTROL_SET_CALL,	"CTDB_CONTROL_SET_CALL"},
	{CTDB_CONTROL_WRITE_RECORD,	"CTDB_CONTROL_WRITE_RECORD"},
	{0, NULL}
};

static void
ctdb_display_trans(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, ctdb_trans_t *ctdb_trans)
{
	proto_item *item;

	item=proto_tree_add_uint(tree, hf_ctdb_xid, tvb, 0, 0, (int)ctdb_trans);
	PROTO_ITEM_SET_GENERATED(item);

	if(ctdb_trans->request_in!=(gint32)pinfo->fd->num){
		item=proto_tree_add_uint(tree, hf_ctdb_request_in, tvb, 0, 0, ctdb_trans->request_in);
		PROTO_ITEM_SET_GENERATED(item);
	}

	if( (ctdb_trans->response_in!=-1)
	  &&(ctdb_trans->response_in!=(gint32)pinfo->fd->num) ){
		item=proto_tree_add_uint(tree, hf_ctdb_response_in, tvb, 0, 0, ctdb_trans->response_in);
		PROTO_ITEM_SET_GENERATED(item);
	}

	if((gint32)pinfo->fd->num==ctdb_trans->response_in){
		nstime_t ns;

		nstime_delta(&ns, &pinfo->fd->abs_ts, &ctdb_trans->req_time);
		item=proto_tree_add_time(tree, hf_ctdb_time, tvb, 0, 0, &ns);
		PROTO_ITEM_SET_GENERATED(item);
	}
}

static guint32
ctdb_hash(tvbuff_t *tvb, int offset, guint32 len)
{
	guint32 value;
	guint32 i;

	for(value=0x238F13AF*len, i=0; i < len; i++)
		value=(value+(tvb_get_guint8(tvb, offset+i) << (i*5 % 24)));

	return (1103515243 * value + 12345);  
}

static int
dissect_ctdb_key(proto_tree *tree, tvbuff_t *tvb, int offset, guint32 keylen, guint32 *key_hash, int endianess)
{
	guint32 keyhash;
	proto_item *key_item=NULL;
	proto_item *key_tree=NULL;

	if(tree){
		key_item=proto_tree_add_item(tree, hf_ctdb_key, tvb, offset, keylen, endianess);
		key_tree=proto_item_add_subtree(key_item, ett_ctdb_key);

	}

	keyhash=ctdb_hash(tvb, offset, keylen);
	proto_item_append_text(key_item, " (Hash:0x%08x)", keyhash);
	key_item=proto_tree_add_uint(key_tree, hf_ctdb_keyhash, tvb, 0, 0, keyhash);
	PROTO_ITEM_SET_GENERATED(key_item);

	offset+=keylen;

	if(key_hash){
		*key_hash=keyhash;
	}

	return offset;
}

static int
dissect_ctdb_reply_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int endianess)
{
	guint32 datalen;

	/* status */
	proto_tree_add_item(tree, hf_ctdb_status, tvb, offset, 4, endianess);
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* data */
	proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
	offset+=datalen;
	

	return offset;
}

static int
dissect_ctdb_reply_dmaster(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint32 reqid, guint32 dst, int endianess)
{
	guint32 datalen, keylen;
	emem_tree_key_t tkey[3];
	ctdb_trans_t *ctdb_trans;

	/* dbid */
	proto_tree_add_item(tree, hf_ctdb_dbid, tvb, offset, 4, endianess);
	offset+=4;

	/* rsn */
	proto_tree_add_item(tree, hf_ctdb_rsn, tvb, offset, 8, endianess);
	offset+=8;

	/* keylen */
	proto_tree_add_item(tree, hf_ctdb_keylen, tvb, offset, 4, endianess);
	if(endianess){
		keylen=tvb_get_letohl(tvb, offset);
	} else {
		keylen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* key */
	offset=dissect_ctdb_key(tree, tvb, offset, keylen, NULL, endianess);

	/* data */
	proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
	offset+=datalen;
	
	tkey[0].length=1;
	tkey[0].key=&reqid;
	tkey[1].length=1;
	tkey[1].key=&dst;
	tkey[2].length=0;
	ctdb_trans=se_tree_lookup32_array(ctdb_transactions, &tkey[0]);

	if(ctdb_trans){
		ctdb_trans->response_in=pinfo->fd->num;
		ctdb_display_trans(pinfo, tree, tvb, ctdb_trans);
	}

	return offset;
}

static int
dissect_ctdb_req_dmaster(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint32 reqid, int endianess)
{
	guint32 keylen, datalen, dmaster;
	emem_tree_key_t tkey[3];
	ctdb_trans_t *ctdb_trans;

	/* dbid */
	proto_tree_add_item(tree, hf_ctdb_dbid, tvb, offset, 4, endianess);
	offset+=4;

	/* rsn */
	proto_tree_add_item(tree, hf_ctdb_rsn, tvb, offset, 8, endianess);
	offset+=8;

	/* dmaster */
	proto_tree_add_item(tree, hf_ctdb_dmaster, tvb, offset, 4, endianess);
	if(endianess){
		dmaster=tvb_get_letohl(tvb, offset);
	} else {
		dmaster=tvb_get_ntohl(tvb, offset);
	}
	offset += 4;

	/* keylen */
	proto_tree_add_item(tree, hf_ctdb_keylen, tvb, offset, 4, endianess);
	if(endianess){
		keylen=tvb_get_letohl(tvb, offset);
	} else {
		keylen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* key */
	offset=dissect_ctdb_key(tree, tvb, offset, keylen, NULL, endianess);

	/* data */
	proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
	offset+=datalen;


	tkey[0].length=1;
	tkey[0].key=&reqid;
	tkey[1].length=1;
	tkey[1].key=&dmaster;
	tkey[2].length=0;
	ctdb_trans=se_tree_lookup32_array(ctdb_transactions, &tkey[0]);

	if(ctdb_trans){
		ctdb_display_trans(pinfo, tree, tvb, ctdb_trans);
	}

	return offset;
}

static int
dissect_ctdb_req_control(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint32 reqid _U_, int endianess)
{
	guint32 datalen;

	/* ctrl opcode */
	proto_tree_add_item(tree, hf_ctdb_ctrl_opcode, tvb, offset, 4, endianess);
	offset+=4;

	/* srvid */
	proto_tree_add_item(tree, hf_ctdb_srvid, tvb, offset, 8, endianess);
	offset+=8;


	/* ctrl flags */
	proto_tree_add_item(tree, hf_ctdb_ctrl_flags, tvb, offset, 4, endianess);
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* data */
	proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
	offset+=datalen;
	
	return offset;
}

static const true_false_string flags_immediate_tfs={
	"DMASTER for the record must IMMEDIATELY be migrated to the caller",
	"Dmaster migration is not required"
};

static int
dissect_ctdb_req_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint32 reqid, guint32 caller, int endianess)
{
	guint32 flags, keyhash;
	guint32 keylen, datalen;
	ctdb_trans_t *ctdb_trans=NULL;

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

	/* hopcount */
	proto_tree_add_item(tree, hf_ctdb_hopcount, tvb, offset, 4, endianess);
	offset+=4;

	/* keylen */
	proto_tree_add_item(tree, hf_ctdb_keylen, tvb, offset, 4, endianess);
	if(endianess){
		keylen=tvb_get_letohl(tvb, offset);
	} else {
		keylen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* key */
	offset=dissect_ctdb_key(tree, tvb, offset, keylen, &keyhash, endianess);

	/* data */
	proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
	offset+=datalen;

	/* setup request/response matching */
	if(!pinfo->fd->flags.visited){
		emem_tree_key_t tkey[3];

		ctdb_trans=se_alloc(sizeof(ctdb_trans_t));
		ctdb_trans->key_hash=keyhash;
		ctdb_trans->request_in=pinfo->fd->num;
		ctdb_trans->response_in=-1;
		ctdb_trans->req_time=pinfo->fd->abs_ts;
		tkey[0].length=1;
		tkey[0].key=&reqid;
		tkey[1].length=1;
		tkey[1].key=&caller;
		tkey[2].length=0;

		se_tree_insert32_array(ctdb_transactions, &tkey[0], ctdb_trans);
	} else {
		emem_tree_key_t tkey[3];

		tkey[0].length=1;
		tkey[0].key=&reqid;
		tkey[1].length=1;
		tkey[1].key=&caller;
		tkey[2].length=0;
		ctdb_trans=se_tree_lookup32_array(ctdb_transactions, &tkey[0]);
	}

	if(ctdb_trans){
		ctdb_display_trans(pinfo, tree, tvb, ctdb_trans);
	}

	return offset;
}

static gboolean
dissect_ctdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_tree *tree=NULL;
	proto_item *item=NULL;
	int offset=0;
	guint32 opcode, src, dst, reqid;
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

	/* generation */
	proto_tree_add_item(tree, hf_ctdb_generation, tvb, offset, 4, endianess);
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
	if(endianess){
		reqid=tvb_get_letohl(tvb, offset);
	} else {
		reqid=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	if(check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s %d->%d",
			val_to_str(opcode, ctdb_opcodes, "Unknown:%d"),
			src, dst);
	}

	switch(opcode){
	case CTDB_REQ_CALL:
		offset=dissect_ctdb_req_call(tvb, offset, pinfo, tree, reqid, src, endianess);
		break;
	case CTDB_REPLY_CALL:
		offset=dissect_ctdb_reply_call(tvb, offset, pinfo, tree, endianess);
		break;
	case CTDB_REPLY_DMASTER:
		offset=dissect_ctdb_reply_dmaster(tvb, offset, pinfo, tree, reqid, dst, endianess);
		break;
	case CTDB_REQ_DMASTER:
		offset=dissect_ctdb_req_dmaster(tvb, offset, pinfo, tree, reqid, endianess);
		break;
	case CTDB_REPLY_ERROR:
		break;
	case CTDB_REQ_MESSAGE:
		break;
	case CTDB_REQ_FINISHED:
		break;
	case CTDB_REQ_CONTROL:
		offset=dissect_ctdb_req_control(tvb, offset, pinfo, tree, reqid, endianess);
		break;
	case CTDB_REPLY_CONTROL:
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
	{ &hf_ctdb_keylen, { 
	  "Key Length", "ctdb.keylen", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_magic, { 
	  "Magic", "ctdb.magic", FT_UINT32, BASE_HEX, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_version, { 
	  "Version", "ctdb.version", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_dmaster, { 
	  "Dmaster", "ctdb.dmaster", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_generation, { 
	  "Generation", "ctdb.generation", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_key, { 
	  "Key", "ctdb.key", FT_BYTES, BASE_HEX, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_keyhash, { 
	  "KeyHash", "ctdb.keyhash", FT_UINT32, BASE_HEX, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_data, { 
	  "Data", "ctdb.data", FT_BYTES, BASE_HEX, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_request_in, { 
	  "Request In", "ctdb.request_in", FT_FRAMENUM, BASE_NONE, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_response_in, { 
	  "Response In", "ctdb.response_in", FT_FRAMENUM, BASE_NONE, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_time, { 
	  "Time since request", "ctdb.time", FT_RELATIVE_TIME, BASE_NONE, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_xid, { 
	  "xid", "ctdb.xid", FT_UINT32, BASE_HEX, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_hopcount, { 
	  "Hopcount", "ctdb.hopcount", FT_UINT32, BASE_DEC, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_rsn, { 
	  "RSN", "ctdb.rsn", FT_UINT64, BASE_HEX, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_ctrl_opcode, { 
	  "CTRL Opcode", "ctdb.ctrl_opcode", FT_UINT32, BASE_DEC, 
	  VALS(ctrl_opcode_vals), 0x0, "", HFILL }},
	{ &hf_ctdb_srvid, { 
	  "SrvId", "ctdb.srvid", FT_UINT64, BASE_HEX, 
	  NULL, 0x0, "", HFILL }},
	{ &hf_ctdb_ctrl_flags, { 
	  "CTRL Flags", "ctdb.ctrl_flags", FT_UINT32, BASE_HEX, 
	  NULL, 0x0, "", HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ctdb,
		&ett_ctdb_key,
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

	ctdb_transactions=se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "CTDB transactions tree");
}
