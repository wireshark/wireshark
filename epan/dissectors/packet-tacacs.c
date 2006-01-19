/* packet-tacacs.c
 * Routines for cisco tacacs/xtacacs/tacacs+ packet dissection
 * Copyright 2001, Paul Ionescu <paul@acorp.ro>
 * 
 * Full Tacacs+ parsing with decryption by
 *   Emanuele Caratti <wiz@iol.it>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from old packet-tacacs.c
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


/* rfc-1492 for tacacs and xtacacs
 * draft-grant-tacacs-02.txt for tacacs+ (tacplus)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>		/* needed to define AF_ values on Windows */
#endif

#ifdef NEED_INET_V6DEFS_H
# include "inet_v6defs.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/prefs.h>
#include <epan/crypt-md5.h>
#include <epan/emem.h>
#include "packet-tacacs.h"

static void md5_xor( guint8 *data, const char *key, int data_len, guint8 *session_id, guint8 version, guint8 seq_no );

static int proto_tacacs = -1;
static int hf_tacacs_version = -1;
static int hf_tacacs_type = -1;
static int hf_tacacs_nonce = -1;
static int hf_tacacs_userlen = -1;
static int hf_tacacs_passlen = -1;
static int hf_tacacs_response = -1;
static int hf_tacacs_reason = -1;
static int hf_tacacs_result1 = -1;
static int hf_tacacs_destaddr = -1;
static int hf_tacacs_destport = -1;
static int hf_tacacs_line = -1;
static int hf_tacacs_result2 = -1;
static int hf_tacacs_result3 = -1;

static gint ett_tacacs = -1;

static const char *tacplus_opt_key;
static GSList *tacplus_keys = NULL;

#define VERSION_TACACS	0x00
#define VERSION_XTACACS	0x80

static const value_string tacacs_version_vals[] = {
	{ VERSION_TACACS,  "TACACS" },
	{ VERSION_XTACACS, "XTACACS" },
	{ 0,               NULL }
};

#define TACACS_LOGIN		1
#define TACACS_RESPONSE		2
#define TACACS_CHANGE		3
#define TACACS_FOLLOW		4
#define TACACS_CONNECT		5
#define TACACS_SUPERUSER	6
#define TACACS_LOGOUT		7
#define TACACS_RELOAD		8
#define TACACS_SLIP_ON		9
#define TACACS_SLIP_OFF		10
#define TACACS_SLIP_ADDR	11
static const value_string tacacs_type_vals[] = {
	{ TACACS_LOGIN,     "Login" },
	{ TACACS_RESPONSE,  "Response" },
	{ TACACS_CHANGE,    "Change" },
	{ TACACS_FOLLOW,    "Follow" },
	{ TACACS_CONNECT,   "Connect" },
	{ TACACS_SUPERUSER, "Superuser" },
	{ TACACS_LOGOUT,    "Logout" },
	{ TACACS_RELOAD,    "Reload" },
	{ TACACS_SLIP_ON,   "SLIP on" },
	{ TACACS_SLIP_OFF,  "SLIP off" },
	{ TACACS_SLIP_ADDR, "SLIP Addr" },
	{ 0,                NULL }};

static const value_string tacacs_reason_vals[] = {
	{ 0  , "none" },
	{ 1  , "expiring" },
	{ 2  , "password" },
	{ 3  , "denied" },
	{ 4  , "quit" },
	{ 5  , "idle" },
	{ 6  , "drop" },
	{ 7  , "bad" },
	{ 0  , NULL }
};

static const value_string tacacs_resp_vals[] = {
	{ 0  , "this is not a response" },
	{ 1  , "accepted" },
	{ 2  , "rejected" },
	{ 0  , NULL }
};

#define UDP_PORT_TACACS	49
#define TCP_PORT_TACACS	49

static void
dissect_tacacs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *tacacs_tree;
	proto_item      *ti;
	guint8		txt_buff[255+1],version,type,userlen,passlen;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TACACS");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	version = tvb_get_guint8(tvb,0);
	if (version != 0) {
		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "XTACACS");
	}

	type = tvb_get_guint8(tvb,1);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(type, tacacs_type_vals, "Unknown (0x%02x)"));

	if (tree)
	{
		ti = proto_tree_add_protocol_format(tree, proto_tacacs,
		 tvb, 0, -1, version==0?"TACACS":"XTACACS");
		tacacs_tree = proto_item_add_subtree(ti, ett_tacacs);

		proto_tree_add_uint(tacacs_tree, hf_tacacs_version, tvb, 0, 1,
		    version);
		proto_tree_add_uint(tacacs_tree, hf_tacacs_type, tvb, 1, 1,
		    type);
		proto_tree_add_item(tacacs_tree, hf_tacacs_nonce, tvb, 2, 2,
		    FALSE);

	if (version==0)
	    {
	    if (type!=TACACS_RESPONSE)
	    	{
	    	userlen=tvb_get_guint8(tvb,4);
		proto_tree_add_uint(tacacs_tree, hf_tacacs_userlen, tvb, 4, 1,
		    userlen);
	    	passlen=tvb_get_guint8(tvb,5);
		proto_tree_add_uint(tacacs_tree, hf_tacacs_passlen, tvb, 5, 1,
		    passlen);
		tvb_get_nstringz0(tvb,6,userlen+1,txt_buff);
		proto_tree_add_text(tacacs_tree, tvb, 6, userlen,         "Username: %s",txt_buff);
		tvb_get_nstringz0(tvb,6+userlen,passlen+1,txt_buff);
		proto_tree_add_text(tacacs_tree, tvb, 6+userlen, passlen, "Password: %s",txt_buff);
		}
	    else
	    	{
	    	proto_tree_add_item(tacacs_tree, hf_tacacs_response, tvb, 4, 1,
	    	    FALSE);
	    	proto_tree_add_item(tacacs_tree, hf_tacacs_reason, tvb, 5, 1,
	    	    FALSE);
		}
	    }
	else
	    {
	    userlen=tvb_get_guint8(tvb,4);
	    proto_tree_add_uint(tacacs_tree, hf_tacacs_userlen, tvb, 4, 1,
		userlen);
	    passlen=tvb_get_guint8(tvb,5);
	    proto_tree_add_uint(tacacs_tree, hf_tacacs_passlen, tvb, 5, 1,
		passlen);
	    proto_tree_add_item(tacacs_tree, hf_tacacs_response, tvb, 6, 1,
		FALSE);
	    proto_tree_add_item(tacacs_tree, hf_tacacs_reason, tvb, 7, 1,
		FALSE);
	    proto_tree_add_item(tacacs_tree, hf_tacacs_result1, tvb, 8, 4,
		FALSE);
	    proto_tree_add_item(tacacs_tree, hf_tacacs_destaddr, tvb, 12, 4,
		FALSE);
	    proto_tree_add_item(tacacs_tree, hf_tacacs_destport, tvb, 16, 2,
		FALSE);
	    proto_tree_add_item(tacacs_tree, hf_tacacs_line, tvb, 18, 2,
		FALSE);
	    proto_tree_add_item(tacacs_tree, hf_tacacs_result2, tvb, 20, 4,
		FALSE);
	    proto_tree_add_item(tacacs_tree, hf_tacacs_result3, tvb, 24, 2,
		FALSE);
	    if (type!=TACACS_RESPONSE)
	    	{
	    	tvb_get_nstringz0(tvb,26,userlen+1,txt_buff);
	    	proto_tree_add_text(tacacs_tree, tvb, 26, userlen,  "Username: %s",txt_buff);
	    	tvb_get_nstringz0(tvb,26+userlen,passlen+1,txt_buff);
	    	proto_tree_add_text(tacacs_tree, tvb, 26+userlen, passlen, "Password; %s",txt_buff);
	    	}
	    }
	}
}

void
proto_register_tacacs(void)
{
	static hf_register_info hf[] = {
	  { &hf_tacacs_version,
	    { "Version",           "tacacs.version",
	      FT_UINT8, BASE_HEX, VALS(tacacs_version_vals), 0x0,
	      "Version", HFILL }},
	  { &hf_tacacs_type,
	    { "Type",              "tacacs.type",
	      FT_UINT8, BASE_DEC, VALS(tacacs_type_vals), 0x0,
	      "Type", HFILL }},
	  { &hf_tacacs_nonce,
	    { "Nonce",             "tacacs.nonce",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      "Nonce", HFILL }},
	  { &hf_tacacs_userlen,
	    { "Username length",   "tacacs.userlen",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      "Username length", HFILL }},
	  { &hf_tacacs_passlen,
	    { "Password length",   "tacacs.passlen",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      "Password length", HFILL }},
	  { &hf_tacacs_response,
	    { "Response",          "tacacs.response",
	      FT_UINT8, BASE_DEC, VALS(tacacs_resp_vals), 0x0,
	      "Response", HFILL }},
	  { &hf_tacacs_reason,
	    { "Reason",            "tacacs.reason",
	      FT_UINT8, BASE_DEC, VALS(tacacs_reason_vals), 0x0,
	      "Reason", HFILL }},
	  { &hf_tacacs_result1,
	    { "Result 1",          "tacacs.result1",
	      FT_UINT32, BASE_HEX, NULL, 0x0,
	      "Result 1", HFILL }},
	  { &hf_tacacs_destaddr,
	    { "Destination address", "tacacs.destaddr",
	      FT_IPv4, BASE_NONE, NULL, 0x0,
	      "Destination address", HFILL }},
	  { &hf_tacacs_destport,
	    { "Destination port",  "tacacs.destport",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      "Destination port", HFILL }},
	  { &hf_tacacs_line,
	    { "Line",              "tacacs.line",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      "Line", HFILL }},
	  { &hf_tacacs_result2,
	    { "Result 2",          "tacacs.result2",
	      FT_UINT32, BASE_HEX, NULL, 0x0,
	      "Result 2", HFILL }},
	  { &hf_tacacs_result3,
	    { "Result 3",          "tacacs.result3",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      "Result 3", HFILL }},
	};

	static gint *ett[] = {
		&ett_tacacs,
	};
	proto_tacacs = proto_register_protocol("TACACS", "TACACS", "tacacs");
	proto_register_field_array(proto_tacacs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_tacacs(void)
{
	dissector_handle_t tacacs_handle;

	tacacs_handle = create_dissector_handle(dissect_tacacs, proto_tacacs);
	dissector_add("udp.port", UDP_PORT_TACACS, tacacs_handle);
}

static int proto_tacplus = -1;
static int hf_tacplus_response = -1;
static int hf_tacplus_request = -1;
static int hf_tacplus_majvers = -1;
static int hf_tacplus_minvers = -1;
static int hf_tacplus_type = -1;
static int hf_tacplus_seqno = -1;
static int hf_tacplus_flags = -1;
static int hf_tacplus_flags_payload_type = -1;
static int hf_tacplus_flags_connection_type = -1;
static int hf_tacplus_acct_flags = -1;
static int hf_tacplus_session_id = -1;
static int hf_tacplus_packet_len = -1;

static gint ett_tacplus = -1;
static gint ett_tacplus_body = -1;
static gint ett_tacplus_body_chap = -1;
static gint ett_tacplus_flags = -1;
static gint ett_tacplus_acct_flags = -1;

typedef struct _tacplus_key_entry {
	address  *s; /* Server address */
	address  *c; /* client address */
	char	*k; /* Key */
} tacplus_key_entry;

static gint 
tacplus_decrypted_tvb_setup( tvbuff_t *tvb, tvbuff_t **dst_tvb, packet_info *pinfo, guint32 len, guint8 version, const char *key )
{
	guint8	*buff;
	guint8 session_id[4];

	/* TODO Check the possibility to use pinfo->decrypted_data */
/* session_id is in NETWORK Byte Order, and is used as byte array in the md5_xor */

	tvb_memcpy(tvb, (guint8*)session_id, 4,4); 

	buff = tvb_memdup(tvb, TAC_PLUS_HDR_SIZE, len);


	md5_xor( buff, key, len, session_id,version, tvb_get_guint8(tvb,2) );

	/* Allocate a new tvbuff, referring to the decrypted data. */
	*dst_tvb = tvb_new_real_data( buff, len, len );

	/* Arrange that the allocated packet data copy be freed when the
	   tvbuff is freed. */
	tvb_set_free_cb( *dst_tvb, g_free );

	/* Add the tvbuff to the list of tvbuffs to which the tvbuff we
	   were handed refers, so it'll get cleaned up when that tvbuff
	   is cleaned up. */
	tvb_set_child_real_data_tvbuff( tvb, *dst_tvb );

	/* Add the decrypted data to the data source list. */
	add_new_data_source(pinfo, *dst_tvb, "TACACS+ Decrypted");

	return 0;
}
static void
dissect_tacplus_args_list( tvbuff_t *tvb, proto_tree *tree, int data_off, int len_off, int arg_cnt )
{
	int i;
	guint8	buff[257];
	for(i=0;i<arg_cnt;i++){
		int len=tvb_get_guint8(tvb,len_off+i);
		proto_tree_add_text( tree, tvb, len_off+i, 1, "Arg[%d] length: %d", i, len );
		tvb_get_nstringz0(tvb, data_off, len+1, buff);
		proto_tree_add_text( tree, tvb, data_off, len, "Arg[%d] value: %s", i, buff );
		data_off+=len;
	}
}


static int
proto_tree_add_tacplus_common_fields( tvbuff_t *tvb, proto_tree *tree,  int offset, int var_off )
{
	int val;
	guint8 buff[257];
	/* priv_lvl */
	proto_tree_add_text( tree, tvb, offset, 1,
			"Privilege Level: %d", tvb_get_guint8(tvb,offset) );
	offset++;

	/* authen_type */
	val=tvb_get_guint8(tvb,offset);
	proto_tree_add_text( tree, tvb, offset, 1,
			"Authentication type: %s",
			val_to_str( val, tacplus_authen_type_vals, "Unknown Packet" ) );
	offset++;

	/* service */
	val=tvb_get_guint8(tvb,offset);
	proto_tree_add_text( tree, tvb, offset, 1,
			"Service: %s",
			val_to_str( val, tacplus_authen_service_vals, "Unknown Packet" ) );
	offset++;

	/* user_len && user */
	val=tvb_get_guint8(tvb,offset);
	proto_tree_add_text( tree, tvb, offset, 1, "User len: %d", val );
	if( val ){
		tvb_get_nstringz0(tvb, var_off, val+1, buff);
		proto_tree_add_text( tree, tvb, var_off, val, "User: %s", buff );
		var_off+=val;
	}
	offset++;


	/* port_len &&  port */
	val=tvb_get_guint8(tvb,offset);
	proto_tree_add_text( tree, tvb, offset, 1, "Port len: %d", val );
	if( val ){
		tvb_get_nstringz0(tvb, var_off, val+1, buff);
		proto_tree_add_text( tree, tvb, var_off, val, "Port: %s", buff );
		var_off+=val;
	}
	offset++;

	/* rem_addr_len && rem_addr */
	val=tvb_get_guint8(tvb,offset);
	proto_tree_add_text( tree, tvb, offset, 1, "Remaddr len: %d", val );
	if( val ){
		tvb_get_nstringz0(tvb, var_off, val+1, buff);
		proto_tree_add_text( tree, tvb, var_off, val, "Remote Address: %s", buff );
		var_off+=val;
	}
	return var_off;
}

static void
dissect_tacplus_body_authen_req_login( tvbuff_t* tvb, proto_tree *tree, int var_off )
{
	guint8 buff[257];
	guint8 val;
	val=tvb_get_guint8( tvb, AUTHEN_S_DATA_LEN_OFF );

	switch ( tvb_get_guint8(tvb, AUTHEN_S_AUTHEN_TYPE_OFF ) ) { /* authen_type */

		case TAC_PLUS_AUTHEN_TYPE_ASCII:
			proto_tree_add_text( tree, tvb, AUTHEN_S_DATA_LEN_OFF, 1, "Data: %d (not used)", val );
			if( val )
				proto_tree_add_text( tree, tvb, var_off, val, "Data" );
			break;

		case TAC_PLUS_AUTHEN_TYPE_PAP:
			proto_tree_add_text( tree, tvb, AUTHEN_S_DATA_LEN_OFF, 1, "Password Length %d", val );
			if( val ) {
				tvb_get_nstringz0( tvb, var_off, val+1, buff );
				proto_tree_add_text( tree, tvb, var_off, val, "Password: %s", buff );
			}
			break;

		case TAC_PLUS_AUTHEN_TYPE_CHAP:
			proto_tree_add_text( tree, tvb, AUTHEN_S_DATA_LEN_OFF, 1, "CHAP Data Length %d", val );
			if( val ) {
				proto_item	*pi;
				proto_tree  *pt;
				guint8 chal_len=val-(1+16); /* Response field alwayes 16 octets */
				pi = proto_tree_add_text(tree, tvb, var_off, val, "CHAP Data" );
				pt = proto_item_add_subtree( pi, ett_tacplus_body_chap );
				val= tvb_get_guint8( tvb, var_off );
				proto_tree_add_text( pt, tvb, var_off, 1, "ID: %d", val );
				var_off++;
				tvb_get_nstringz0( tvb, var_off, chal_len+1, buff );
				proto_tree_add_text( pt, tvb, var_off, chal_len, "Challenge: %s", buff );
				var_off+=chal_len;
				tvb_get_nstringz0( tvb, var_off, 16+1, buff );
				proto_tree_add_text( pt, tvb, var_off, 16 , "Response: %s", buff );
			}
			break;
		case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
			proto_tree_add_text( tree, tvb, AUTHEN_S_DATA_LEN_OFF, 1, "MSCHAP Data Length %d", val );
			if( val ) {
				proto_item	*pi;
				proto_tree  *pt;
				guint8 chal_len=val-(1+49);  /* Response field alwayes 49 octets */
				pi = proto_tree_add_text(tree, tvb, var_off, val, "MSCHAP Data" );
				pt = proto_item_add_subtree( pi, ett_tacplus_body_chap );
				val= tvb_get_guint8( tvb, var_off );
				proto_tree_add_text( pt, tvb, var_off, 1, "ID: %d", val );
				var_off++;
				tvb_get_nstringz0( tvb, var_off, chal_len+1, buff );
				proto_tree_add_text( pt, tvb, var_off, chal_len, "Challenge: %s", buff );
				var_off+=chal_len;
				tvb_get_nstringz0( tvb, var_off, 49+1, buff );
				proto_tree_add_text( pt, tvb, var_off, 49 , "Response: %s", buff );
			}
			break;
		case TAC_PLUS_AUTHEN_TYPE_ARAP:
			proto_tree_add_text( tree, tvb, AUTHEN_S_DATA_LEN_OFF, 1, "ARAP Data Length %d", val );
			if( val ) {
				proto_item	*pi;
				proto_tree  *pt;
				pi = proto_tree_add_text(tree, tvb, var_off, val, "ARAP Data" );
				pt = proto_item_add_subtree( pi, ett_tacplus_body_chap );

				tvb_get_nstringz0( tvb, var_off, 8+1, buff );
				proto_tree_add_text( pt, tvb, var_off, 8, "Nas Challenge: %s", buff );
				var_off+=8;
				tvb_get_nstringz0( tvb, var_off, 8+1, buff );
				proto_tree_add_text( pt, tvb, var_off, 8, "Remote Challenge: %s", buff );
				var_off+=8;
				tvb_get_nstringz0( tvb, var_off, 8+1, buff );
				proto_tree_add_text( pt, tvb, var_off, 8, "Remote Response: %s", buff );
				var_off+=8;
			}
			break;

		default: /* Should not be reached */
			proto_tree_add_text( tree, tvb, AUTHEN_S_DATA_LEN_OFF, 1, "Data: %d", val );
			if( val ){
				proto_tree_add_text( tree, tvb, var_off, val, "Data" );
			}
	}
}

static void
dissect_tacplus_body_authen_req( tvbuff_t* tvb, proto_tree *tree )
{
	guint8 val;
	int var_off=AUTHEN_S_VARDATA_OFF;

	/* Action */
	val=tvb_get_guint8( tvb, AUTHEN_S_ACTION_OFF );
	proto_tree_add_text( tree, tvb,
			AUTHEN_S_ACTION_OFF, 1, 
			"Action: %s", 
			val_to_str( val, tacplus_authen_action_vals, "Unknown Packet" ) );

	var_off=proto_tree_add_tacplus_common_fields( tvb, tree , AUTHEN_S_PRIV_LVL_OFF, AUTHEN_S_VARDATA_OFF );

	switch( val ) {
		case TAC_PLUS_AUTHEN_LOGIN:
			dissect_tacplus_body_authen_req_login( tvb, tree, var_off );
			break;
		case TAC_PLUS_AUTHEN_SENDAUTH:
			break;
	}
}

static void
dissect_tacplus_body_authen_req_cont( tvbuff_t *tvb, proto_tree *tree )
{
	int val;
	int var_off=AUTHEN_C_VARDATA_OFF;
	guint8 *buff=NULL;

	val=tvb_get_guint8( tvb, AUTHEN_C_FLAGS_OFF );
	proto_tree_add_text( tree, tvb,
			AUTHEN_R_FLAGS_OFF, 1, "Flags: 0x%02x %s",
			val,
			(val&TAC_PLUS_CONTINUE_FLAG_ABORT?"(Abort)":"") );


	val=tvb_get_ntohs( tvb, AUTHEN_C_USER_LEN_OFF ); 
	proto_tree_add_text( tree, tvb, AUTHEN_C_USER_LEN_OFF, 2 , "User length: %d", val );
	if( val ){
		buff=tvb_get_ephemeral_string( tvb, var_off, val );
		proto_tree_add_text( tree, tvb, var_off, val, "User: %s", buff );
		var_off+=val;
	}

	val=tvb_get_ntohs( tvb, AUTHEN_C_DATA_LEN_OFF ); 
	proto_tree_add_text( tree, tvb, AUTHEN_C_DATA_LEN_OFF, 2 ,
			"Data length: %d", val );
	if( val ){
		proto_tree_add_text( tree, tvb, var_off, val, "Data" );
	}

}

/* Server REPLY */
static void
dissect_tacplus_body_authen_rep( tvbuff_t *tvb, proto_tree *tree )
{
	int val;
	int var_off=AUTHEN_R_VARDATA_OFF;
	guint8 *buff=NULL;

	val=tvb_get_guint8( tvb, AUTHEN_R_STATUS_OFF );
	proto_tree_add_text(tree, tvb,
			AUTHEN_R_STATUS_OFF, 1, "Status: 0x%01x (%s)", val,
			val_to_str( val, tacplus_reply_status_vals, "Unknown Packet" )  );

	val=tvb_get_guint8( tvb, AUTHEN_R_FLAGS_OFF );
	proto_tree_add_text(tree, tvb,
			AUTHEN_R_FLAGS_OFF, 1, "Flags: 0x%02x %s",
			val, (val&TAC_PLUS_REPLY_FLAG_NOECHO?"(NoEcho)":"") );
	

	val=tvb_get_ntohs(tvb, AUTHEN_R_SRV_MSG_LEN_OFF );
	proto_tree_add_text( tree, tvb, AUTHEN_R_SRV_MSG_LEN_OFF, 2 ,
				"Server message length: %d", val );
	if( val ) {
		buff=tvb_get_ephemeral_string(tvb, var_off, val );
		proto_tree_add_text(tree, tvb, var_off, val, "Server message: %s", buff );
		var_off+=val;
	}

	val=tvb_get_ntohs(tvb, AUTHEN_R_DATA_LEN_OFF );
	proto_tree_add_text( tree, tvb, AUTHEN_R_DATA_LEN_OFF, 2 ,
				"Data length: %d", val );
	if( val ){
		proto_tree_add_text(tree, tvb, var_off, val, "Data" );
	}
}

static void
dissect_tacplus_body_author_req( tvbuff_t* tvb, proto_tree *tree )
{
	int val;
	int var_off;

	val=tvb_get_guint8( tvb, AUTHOR_Q_AUTH_METH_OFF ) ;
	proto_tree_add_text( tree, tvb, AUTHOR_Q_AUTH_METH_OFF, 1, 
			"Auth Method: %s", val_to_str( val, tacplus_authen_method, "Unknown Authen Method" ) );

	val=tvb_get_guint8( tvb, AUTHOR_Q_ARGC_OFF );
	var_off=proto_tree_add_tacplus_common_fields( tvb, tree ,
			AUTHOR_Q_PRIV_LVL_OFF,
			AUTHOR_Q_VARDATA_OFF + val );

	proto_tree_add_text( tree, tvb, AUTHOR_Q_ARGC_OFF, 1, "Arg count: %d", val );
	
/* var_off points after rem_addr */

	dissect_tacplus_args_list( tvb, tree, var_off, AUTHOR_Q_VARDATA_OFF, val );
}

static void
dissect_tacplus_body_author_rep( tvbuff_t* tvb, proto_tree *tree )
{
	int offset=AUTHOR_R_VARDATA_OFF;
	int val=tvb_get_guint8( tvb, AUTHOR_R_STATUS_OFF	) ;


	proto_tree_add_text( tree, tvb, AUTHOR_R_STATUS_OFF	, 1, 
			"Auth Status: 0x%01x (%s)", val,
			val_to_str( val, tacplus_author_status, "Unknown Authorization Status" ));

	val=tvb_get_ntohs( tvb, AUTHOR_R_SRV_MSG_LEN_OFF );
	offset+=val;
	proto_tree_add_text( tree, tvb, AUTHOR_R_SRV_MSG_LEN_OFF, 2, "Server Msg length: %d", val );

	val=tvb_get_ntohs( tvb, AUTHOR_R_DATA_LEN_OFF );
	offset+=val;
	proto_tree_add_text( tree, tvb, AUTHOR_R_DATA_LEN_OFF, 2, "Data length: %d", val );

	val=tvb_get_guint8( tvb, AUTHOR_R_ARGC_OFF);
	offset+=val;
	proto_tree_add_text( tree, tvb, AUTHOR_R_ARGC_OFF, 1, "Arg count: %d", val );

	dissect_tacplus_args_list( tvb, tree, offset, AUTHOR_R_VARDATA_OFF, val );
}

static void
dissect_tacplus_body_acct_req( tvbuff_t* tvb, proto_tree *tree )
{
	int val, var_off;

	proto_item *tf;
	proto_tree *flags_tree;

	val=tvb_get_guint8( tvb, ACCT_Q_FLAGS_OFF ); 
	tf = proto_tree_add_uint( tree, hf_tacplus_acct_flags, tvb, ACCT_Q_FLAGS_OFF, 1, val );

	flags_tree = proto_item_add_subtree( tf, ett_tacplus_acct_flags );
	proto_tree_add_text( flags_tree, tvb, ACCT_Q_FLAGS_OFF, 1, "%s",
			decode_boolean_bitfield( val, TAC_PLUS_ACCT_FLAG_MORE, 8,
				"More: Set", "More: Not set" ) );
	proto_tree_add_text( flags_tree, tvb, ACCT_Q_FLAGS_OFF, 1, "%s",
			decode_boolean_bitfield( val, TAC_PLUS_ACCT_FLAG_START, 8,
				"Start: Set", "Start: Not set" ) );
	proto_tree_add_text( flags_tree, tvb, ACCT_Q_FLAGS_OFF, 1, "%s",
			decode_boolean_bitfield( val, TAC_PLUS_ACCT_FLAG_STOP, 8,
				"Stop: Set", "Stop: Not set" ) );
	proto_tree_add_text( flags_tree, tvb, ACCT_Q_FLAGS_OFF, 1, "%s",
			decode_boolean_bitfield( val, TAC_PLUS_ACCT_FLAG_WATCHDOG, 8,
				"Watchdog: Set", "Watchdog: Not set" ) );

	val=tvb_get_guint8( tvb, ACCT_Q_METHOD_OFF );
	proto_tree_add_text( tree, tvb, ACCT_Q_METHOD_OFF, 1, 
			"Authen Method: 0x%01x (%s)",  
			val, val_to_str( val, tacplus_authen_method, "Unknown Authen Method" ) );

	val=tvb_get_guint8( tvb, ACCT_Q_ARG_CNT_OFF );

	/* authen_type */
	var_off=proto_tree_add_tacplus_common_fields( tvb, tree ,
			ACCT_Q_PRIV_LVL_OFF,
			ACCT_Q_VARDATA_OFF+val
			);

	proto_tree_add_text( tree, tvb, ACCT_Q_ARG_CNT_OFF, 1,
			"Arg Cnt: %d", val  );

	dissect_tacplus_args_list( tvb, tree, var_off, ACCT_Q_VARDATA_OFF, val );


}

static void
dissect_tacplus_body_acct_rep( tvbuff_t* tvb, proto_tree *tree )
{
	int val, var_off=ACCT_Q_VARDATA_OFF;

	guint8 *buff=NULL;

	/* Status */
	val=tvb_get_guint8( tvb, ACCT_R_STATUS_OFF );
	proto_tree_add_text( tree, tvb, ACCT_R_STATUS_OFF, 1, "Status: 0x%02x (%s)", val,
				val_to_str( val, tacplus_acct_status, "Bogus status..") );

	/* Server Message */
	val=tvb_get_ntohs( tvb, ACCT_R_SRV_MSG_LEN_OFF );
	proto_tree_add_text( tree, tvb, ACCT_R_SRV_MSG_LEN_OFF, 2 ,
				"Server message length: %d", val );
	if( val ) {
		buff=tvb_get_ephemeral_string( tvb, var_off, val );
		proto_tree_add_text( tree, tvb, var_off,
				val, "Server message: %s", buff );
		var_off+=val;
	}

	/*  Data */
	val=tvb_get_ntohs( tvb, ACCT_R_DATA_LEN_OFF );
	proto_tree_add_text( tree, tvb, ACCT_R_DATA_LEN_OFF, 2 ,
				"Data length: %d", val );
	if( val ) {
		buff= tvb_get_ephemeral_string( tvb, var_off, val );
		proto_tree_add_text( tree, tvb, var_off,
				val, "Data: %s", buff );
	}
}



static void
dissect_tacplus_body(tvbuff_t * hdr_tvb, tvbuff_t * tvb, proto_tree * tree )
{
	int type = tvb_get_guint8( hdr_tvb, H_TYPE_OFF );
	int seq_no = tvb_get_guint8( hdr_tvb, H_SEQ_NO_OFF );

	switch (type) {
	  case TAC_PLUS_AUTHEN:
		if (  seq_no & 0x01) {
			if ( seq_no == 1 )
				dissect_tacplus_body_authen_req( tvb, tree );
			else
				dissect_tacplus_body_authen_req_cont( tvb, tree );
		} else {
			dissect_tacplus_body_authen_rep( tvb, tree );
		}
		return;
		break;
	  case TAC_PLUS_AUTHOR:
		if ( seq_no & 0x01)
			dissect_tacplus_body_author_req( tvb, tree );
		else 
			dissect_tacplus_body_author_rep( tvb, tree );
		return;
		break;
	  case TAC_PLUS_ACCT:
		if ( seq_no & 0x01)
			dissect_tacplus_body_acct_req( tvb, tree ); 
		else
			dissect_tacplus_body_acct_rep( tvb, tree );
		return;
		break;
	}
	proto_tree_add_text( tree, tvb, 0, tvb_length( tvb ), "Bogus..");
}

#ifdef DEB_TACPLUS
static void
tacplus_print_key_entry( gpointer data, gpointer user_data )
{
	tacplus_key_entry *tacplus_data=(tacplus_key_entry *)data;
	if( user_data ) {
		printf("%s:%s=%s\n", address_to_str( tacplus_data->s ),
				address_to_str( tacplus_data->c ), tacplus_data->k );
	} else {
		printf("%s:%s\n", address_to_str( tacplus_data->s ),
				address_to_str( tacplus_data->c ) );
	}
}
#endif
static int
cmp_conv_address( gconstpointer p1, gconstpointer p2 )
{
	const tacplus_key_entry *a1=p1;
	const tacplus_key_entry *a2=p2;
	gint32	ret;
	/*
	printf("p1=>");
	tacplus_print_key_entry( p1, NULL );
	printf("p2=>");
	tacplus_print_key_entry( p2, NULL );
	*/
	ret=CMP_ADDRESS( a1->s, a2->s );
	if( !ret ) {
		ret=CMP_ADDRESS( a1->c, a2->c );
		/*
		if(ret)
			printf("No Client found!"); */
	} else {
		/* printf("No Server found!"); */
	}
	return ret;
}

static const char*
find_key( address *srv, address *cln )
{
	tacplus_key_entry data;
	GSList *match;

	data.s=srv;
	data.c=cln;
/*	printf("Looking for: ");
	tacplus_print_key_entry( (gconstpointer)&data, NULL ); */
	match=g_slist_find_custom( tacplus_keys, (gpointer)&data, cmp_conv_address );
/*	printf("Finished (%p)\n", match);  */
	if( match ) 
		return ((tacplus_key_entry*)match->data)->k;

	return (tacplus_keys?NULL:tacplus_opt_key);
}

static void
mkipv4_address( address **addr, const char *str_addr )
{
	char *addr_data;

	*addr=g_malloc( sizeof(address) );
	addr_data=g_malloc( 4 );
	inet_pton( AF_INET, str_addr, addr_data );
	(*addr)->type=AT_IPv4;
	(*addr)->len=4;
	(*addr)->data=addr_data;
}
static void
parse_tuple( char *key_from_option )
{
	char *client,*key;
	tacplus_key_entry *tacplus_data=g_malloc( sizeof(tacplus_key_entry) );
	/*
	printf("keys: %s\n", key_from_option );
	*/
	client=strchr(key_from_option,'/');
	if(!client)
		return;
	*client++='\0';
	key=strchr(client,'=');
	if(!key)
		return;
	*key++='\0';
	/*
	printf("%s %s => %s\n", key_from_option, client, key );
	*/
	mkipv4_address( &tacplus_data->s, key_from_option );
	mkipv4_address( &tacplus_data->c, client );
	tacplus_data->k=strdup( key );
	tacplus_keys = g_slist_prepend( tacplus_keys, tacplus_data );
}

static
void
free_tacplus_keys( gpointer data, gpointer user_data _U_ )
{
	g_free( ((tacplus_key_entry *)data)->k );
}

static 
void
parse_tacplus_keys( const char *keys_from_option )
{
	char *key_copy,*s,*s1;

	/* Drop old keys */
	if( tacplus_keys ) {
		g_slist_foreach( tacplus_keys, free_tacplus_keys, NULL );
		g_slist_free( tacplus_keys );
		tacplus_keys=NULL;
	}

	if( !strchr( keys_from_option, '/' ) ){
		/* option not in client/server=key format */
		return ;
	}
	key_copy=strdup(keys_from_option);
	s=key_copy;
	while(s){
		if( (s1=strchr( s, ' ' )) != NULL )
			*s1++='\0';
		parse_tuple( s );
		s=s1;
	}
	g_free( key_copy );
#ifdef DEB_TACPLUS
	g_slist_foreach( tacplus_keys, tacplus_print_key_entry, GINT_TO_POINTER(1) );
#endif
}

static void
dissect_tacplus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t	*new_tvb=NULL;
	proto_tree      *tacplus_tree;
	proto_item      *ti;
	guint8		version,flags;
	proto_tree      *flags_tree;
	proto_item      *tf;
	proto_item	*tmp_pi;
	guint32		len;
	gboolean	request=( pinfo->destport == TCP_PORT_TACACS );
	const char	*key=NULL;

	if( request ) {
		key=find_key( &pinfo->dst, &pinfo->src );
	} else {
		key=find_key(  &pinfo->src, &pinfo->dst );
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TACACS+");

	if (check_col(pinfo->cinfo, COL_INFO))
	{
		int type = tvb_get_guint8(tvb,1);
		col_add_fstr( pinfo->cinfo, COL_INFO, "%s: %s", 
				request ? "Q" : "R",
				val_to_str(type, tacplus_type_vals, "Unknown (0x%02x)"));
	}

	if (tree)
	{
		ti = proto_tree_add_protocol_format(tree, proto_tacplus,
		 tvb, 0, -1, "TACACS+");

		tacplus_tree = proto_item_add_subtree(ti, ett_tacplus);
		if (pinfo->match_port == pinfo->destport)
		{
			proto_tree_add_boolean_hidden(tacplus_tree,
			    hf_tacplus_request, tvb, 0, 0, TRUE);
		}
		else
		{
			proto_tree_add_boolean_hidden(tacplus_tree,
			    hf_tacplus_response, tvb, 0, 0, TRUE);
		}
		version = tvb_get_guint8(tvb,0);
		proto_tree_add_uint_format(tacplus_tree, hf_tacplus_majvers, tvb, 0, 1,
		    version,
		    "Major version: %s",
		    (version&0xf0)==0xc0?"TACACS+":"Unknown Version");
		proto_tree_add_uint(tacplus_tree, hf_tacplus_minvers, tvb, 0, 1,
		    version&0xf);
		proto_tree_add_item(tacplus_tree, hf_tacplus_type, tvb, 1, 1,
		    FALSE);
		proto_tree_add_item(tacplus_tree, hf_tacplus_seqno, tvb, 2, 1,
		    FALSE);
		flags = tvb_get_guint8(tvb,3);
		tf = proto_tree_add_uint_format(tacplus_tree, hf_tacplus_flags,
		    tvb, 3, 1, flags,
		    "Flags: 0x%02x (%s payload, %s)",
			flags,
		    (flags&FLAGS_UNENCRYPTED) ? "Unencrypted" :
						"Encrypted",
		    (flags&FLAGS_SINGLE) ? "Single connection" :
					   "Multiple Connections" );
		flags_tree = proto_item_add_subtree(tf, ett_tacplus_flags);
		proto_tree_add_boolean(flags_tree, hf_tacplus_flags_payload_type,
		    tvb, 3, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_tacplus_flags_connection_type,
		    tvb, 3, 1, flags);
		proto_tree_add_item(tacplus_tree, hf_tacplus_session_id, tvb, 4, 4,
		    FALSE);
		len = tvb_get_ntohl(tvb,8);
		proto_tree_add_uint(tacplus_tree, hf_tacplus_packet_len, tvb, 8, 4,
		    len);

		tmp_pi = proto_tree_add_text(tacplus_tree, tvb, TAC_PLUS_HDR_SIZE, len, "%s%s",
					((flags&FLAGS_UNENCRYPTED)?"":"Encrypted "), request?"Request":"Reply" );

		if( flags&FLAGS_UNENCRYPTED ) {
			new_tvb = tvb_new_subset( tvb, TAC_PLUS_HDR_SIZE, len, len );
		}  else {
			new_tvb=NULL;
			if( key && *key ){
				tacplus_decrypted_tvb_setup( tvb, &new_tvb, pinfo, len, version, key );
			}
		}
		if( new_tvb ) {
			/* Check to see if I've a decrypted tacacs packet */
			if( !(flags&FLAGS_UNENCRYPTED) ){ 	
				tmp_pi = proto_tree_add_text(tacplus_tree, new_tvb, 0, len, "Decrypted %s",
							request?"Request":"Reply" );
			}
			dissect_tacplus_body( tvb, new_tvb, proto_item_add_subtree( tmp_pi, ett_tacplus_body ));
		}
	}
}

static void
tacplus_pref_cb(void)
{
	parse_tacplus_keys( tacplus_opt_key );
}

void
proto_register_tacplus(void)
{
	static hf_register_info hf[] = {
	  { &hf_tacplus_response,
	    { "Response",           "tacplus.response",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if TACACS+ response", HFILL }},
	  { &hf_tacplus_request,
	    { "Request",            "tacplus.request",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if TACACS+ request", HFILL }},
	  { &hf_tacplus_majvers,
	    { "Major version",      "tacplus.majvers",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      "Major version number", HFILL }},
	  { &hf_tacplus_minvers,
	    { "Minor version",      "tacplus.minvers",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      "Minor version number", HFILL }},
	  { &hf_tacplus_type,
	    { "Type",               "tacplus.type",
	      FT_UINT8, BASE_DEC, VALS(tacplus_type_vals), 0x0,
	      "Type", HFILL }},
	  { &hf_tacplus_seqno,
	    { "Sequence number",    "tacplus.seqno",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      "Sequence number", HFILL }},
	  { &hf_tacplus_flags,
	    { "Flags",              "tacplus.flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      "Flags", HFILL }},
	  { &hf_tacplus_flags_payload_type,
	    { "Unencrypted",       "tacplus.flags.unencrypted",
	      FT_BOOLEAN, 8, TFS(&flags_set_truth), FLAGS_UNENCRYPTED,
	      "Is payload unencrypted?", HFILL }},
	  { &hf_tacplus_flags_connection_type,
	    { "Single Connection",    "tacplus.flags.singleconn",
	      FT_BOOLEAN, 8, TFS(&flags_set_truth), FLAGS_SINGLE,
	      "Is this a single connection?", HFILL }},
	  { &hf_tacplus_acct_flags,
	    { "Flags",    "tacplus.acct.flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      "Flags", HFILL }},
	  { &hf_tacplus_session_id,
	    { "Session ID",         "tacplus.session_id",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      "Session ID", HFILL }},
	  { &hf_tacplus_packet_len,
	    { "Packet length",      "tacplus.packet_len",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      "Packet length", HFILL }}
	};
	static gint *ett[] = {
		&ett_tacplus,
		&ett_tacplus_flags,
		&ett_tacplus_acct_flags,
		&ett_tacplus_body,
		&ett_tacplus_body_chap, 
	};
	module_t *tacplus_module;

	proto_tacplus = proto_register_protocol("TACACS+", "TACACS+", "tacplus");
	proto_register_field_array(proto_tacplus, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	tacplus_module = prefs_register_protocol (proto_tacplus, tacplus_pref_cb );
	prefs_register_string_preference ( tacplus_module, "key",
	"TACACS+ Encryption Key", "TACACS+ Encryption Key", &tacplus_opt_key );
}

void
proto_reg_handoff_tacplus(void)
{
	dissector_handle_t tacplus_handle;

	tacplus_handle = create_dissector_handle(dissect_tacplus,
	    proto_tacplus);
	dissector_add("tcp.port", TCP_PORT_TACACS, tacplus_handle);
}


#define MD5_LEN 16

static void
md5_xor( guint8 *data, const char *key, int data_len, guint8 *session_id, guint8 version, guint8 seq_no )
{
	int i,j,md5_len;
	md5_byte_t *md5_buff;
	md5_byte_t hash[MD5_LEN];       				/* the md5 hash */
	md5_byte_t *mdp;
	md5_state_t mdcontext;

	md5_len = 4 /* sizeof(session_id) */ + strlen(key)
			+ sizeof(version) + sizeof(seq_no);
	
	md5_buff = (md5_byte_t*)ep_alloc(md5_len+MD5_LEN);


	mdp = md5_buff;
	*(guint32*)mdp = *(guint32*)session_id;
	mdp += 4 ;
	memcpy(mdp, key, strlen(key));
	mdp += strlen(key);
	*mdp++ = version;
	*mdp++ = seq_no;


	md5_init(&mdcontext);
	md5_append(&mdcontext, md5_buff, md5_len);
	md5_finish(&mdcontext,hash);
	md5_len += MD5_LEN;
	for (i = 0; i < data_len; i += 16) {

		for (j = 0; j < 16; j++) {
			if ((i + j) >= data_len)  {
				i = data_len+1; /* To exit from the external loop  */
				break;
			}
			data[i + j] ^= hash[j];
		}
		memcpy(mdp, hash, MD5_LEN);
		md5_init(&mdcontext);
		md5_append(&mdcontext, md5_buff, md5_len);
		md5_finish(&mdcontext,hash);
	}
}
