/* packet-tacacs.c
 * Routines for cisco tacacs/xtacacs/tacacs+ packet dissection
 * Copyright 2001, Paul Ionescu <paul@acorp.ro>
 *
 * Full Tacacs+ parsing with decryption by
 *   Emanuele Caratti <wiz@iol.it>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


/* rfc-1492 for tacacs and xtacacs
 * draft-grant-tacacs-02.txt for tacacs+ (tacplus)
 * ftp://ftp.cisco.com/pub/rfc/DRAFTS/draft-grant-tacacs-02.txt
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <wsutil/md5.h>

#include "packet-tacacs.h"

void proto_reg_handoff_tacacs(void);
void proto_register_tacacs(void);

void proto_reg_handoff_tacplus(void);
void proto_register_tacplus(void);

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
static int hf_tacacs_username = -1;
static int hf_tacacs_password = -1;

static gint ett_tacacs = -1;

static gboolean tacplus_preference_desegment = TRUE;

static const char *tacplus_opt_key;
static GSList *tacplus_keys = NULL;

#define ADDR_INVLD "invalid"

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

static int
dissect_tacacs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree      *tacacs_tree;
	proto_item      *ti;
	guint8          version,type,userlen,passlen;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TACACS");
	col_clear(pinfo->cinfo, COL_INFO);

	version = tvb_get_guint8(tvb,0);
	if (version != 0) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "XTACACS");
	}

	type = tvb_get_guint8(tvb,1);
	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(type, tacacs_type_vals, "Unknown (0x%02x)"));

	if (tree)
	{
		ti = proto_tree_add_protocol_format(tree, proto_tacacs,
		 tvb, 0, -1, version==0?"TACACS":"XTACACS");
		tacacs_tree = proto_item_add_subtree(ti, ett_tacacs);

		proto_tree_add_uint(tacacs_tree, hf_tacacs_version, tvb, 0, 1, version);
		proto_tree_add_uint(tacacs_tree, hf_tacacs_type, tvb, 1, 1, type);
		proto_tree_add_item(tacacs_tree, hf_tacacs_nonce, tvb, 2, 2, ENC_BIG_ENDIAN);

		if (version==0)
		{
			if (type!=TACACS_RESPONSE)
			{
			userlen=tvb_get_guint8(tvb,4);
			proto_tree_add_uint(tacacs_tree, hf_tacacs_userlen, tvb, 4, 1, userlen);
			passlen=tvb_get_guint8(tvb,5);
			proto_tree_add_uint(tacacs_tree, hf_tacacs_passlen, tvb, 5, 1, passlen);
			proto_tree_add_item(tree, hf_tacacs_username, tvb, 6, userlen, ENC_ASCII|ENC_NA);
			proto_tree_add_item(tree, hf_tacacs_password, tvb, 6+userlen, passlen, ENC_ASCII|ENC_NA);
			}
			else
			{
				proto_tree_add_item(tacacs_tree, hf_tacacs_response, tvb, 4, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tacacs_tree, hf_tacacs_reason, tvb, 5, 1, ENC_BIG_ENDIAN);
			}
		}
		else
		{
			userlen=tvb_get_guint8(tvb,4);
			proto_tree_add_uint(tacacs_tree, hf_tacacs_userlen, tvb, 4, 1, userlen);
			passlen=tvb_get_guint8(tvb,5);
			proto_tree_add_uint(tacacs_tree, hf_tacacs_passlen, tvb, 5, 1, passlen);
			proto_tree_add_item(tacacs_tree, hf_tacacs_response, tvb, 6, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tacacs_tree, hf_tacacs_reason, tvb, 7, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tacacs_tree, hf_tacacs_result1, tvb, 8, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(tacacs_tree, hf_tacacs_destaddr, tvb, 12, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(tacacs_tree, hf_tacacs_destport, tvb, 16, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tacacs_tree, hf_tacacs_line, tvb, 18, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tacacs_tree, hf_tacacs_result2, tvb, 20, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(tacacs_tree, hf_tacacs_result3, tvb, 24, 2, ENC_BIG_ENDIAN);
			if (type!=TACACS_RESPONSE)
			{
				proto_tree_add_item(tree, hf_tacacs_username, tvb, 26, userlen, ENC_ASCII|ENC_NA);
				proto_tree_add_item(tree, hf_tacacs_password, tvb, 26+userlen, passlen, ENC_ASCII|ENC_NA);
			}
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_register_tacacs(void)
{
	static hf_register_info hf[] = {
	  { &hf_tacacs_version,
	    { "Version", "tacacs.version",
	      FT_UINT8, BASE_HEX, VALS(tacacs_version_vals), 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_type,
	    { "Type", "tacacs.type",
	      FT_UINT8, BASE_DEC, VALS(tacacs_type_vals), 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_nonce,
	    { "Nonce", "tacacs.nonce",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_userlen,
	    { "Username length", "tacacs.userlen",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_passlen,
	    { "Password length", "tacacs.passlen",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_response,
	    { "Response", "tacacs.response",
	      FT_UINT8, BASE_DEC, VALS(tacacs_resp_vals), 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_reason,
	    { "Reason", "tacacs.reason",
	      FT_UINT8, BASE_DEC, VALS(tacacs_reason_vals), 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_result1,
	    { "Result 1", "tacacs.result1",
	      FT_UINT32, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_destaddr,
	    { "Destination address", "tacacs.destaddr",
	      FT_IPv4, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_destport,
	    { "Destination port", "tacacs.destport",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_line,
	    { "Line", "tacacs.line",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_result2,
	    { "Result 2", "tacacs.result2",
	      FT_UINT32, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_result3,
	    { "Result 3", "tacacs.result3",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_username,
	    { "Username", "tacacs.username",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacacs_password,
	    { "Password", "tacacs.password",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
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
	dissector_add_uint("udp.port", UDP_PORT_TACACS, tacacs_handle);
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
static int hf_tacplus_acct_flags_more = -1;
static int hf_tacplus_acct_flags_start = -1;
static int hf_tacplus_acct_flags_stop = -1;
static int hf_tacplus_acct_flags_watchdog = -1;
static int hf_tacplus_session_id = -1;
static int hf_tacplus_packet_len = -1;
static int hf_tacplus_auth_password = -1;
static int hf_tacplus_port = -1;
static int hf_tacplus_remote_address = -1;
static int hf_tacplus_chap_challenge = -1;
static int hf_tacplus_chap_response = -1;
static int hf_tacplus_mschap_challenge = -1;
static int hf_tacplus_mschap_response = -1;
static int hf_tacplus_arap_nas_challenge = -1;
static int hf_tacplus_arap_remote_challenge = -1;
static int hf_tacplus_arap_remote_response = -1;
static int hf_tacplus_privilege_level = -1;
static int hf_tacplus_authentication_type = -1;
static int hf_tacplus_service = -1;
static int hf_tacplus_user_len = -1;
static int hf_tacplus_user = -1;
static int hf_tacplus_port_len = -1;
static int hf_tacplus_remote_address_len = -1;
static int hf_tacplus_arg_length = -1;
static int hf_tacplus_arg_value = -1;
static int hf_tacplus_chap_id = -1;
static int hf_tacplus_mschap_id = -1;
static int hf_tacplus_authen_action = -1;
static int hf_tacplus_body_authen_req_cont_flags = -1;
static int hf_tacplus_body_authen_req_cont_user_length = -1;
static int hf_tacplus_body_authen_req_cont_user = -1;
static int hf_tacplus_body_authen_req_cont_data_length = -1;
static int hf_tacplus_body_authen_rep_status = -1;
static int hf_tacplus_body_authen_rep_flags = -1;
static int hf_tacplus_body_authen_rep_server_msg_len = -1;
static int hf_tacplus_body_authen_rep_server_msg = -1;
static int hf_tacplus_body_authen_rep_server_data_len = -1;
static int hf_tacplus_body_author_req_auth_method = -1;
static int hf_tacplus_body_author_req_arg_count = -1;
static int hf_tacplus_body_author_rep_auth_status = -1;
static int hf_tacplus_body_author_rep_server_msg_len = -1;
static int hf_tacplus_body_author_rep_server_data_len = -1;
static int hf_tacplus_body_author_rep_arg_count = -1;
static int hf_tacplus_acct_authen_method = -1;
static int hf_tacplus_acct_arg_count = -1;
static int hf_tacplus_body_acct_status = -1;
static int hf_tacplus_body_acct_server_msg_len = -1;
static int hf_tacplus_body_acct_server_msg = -1;
static int hf_tacplus_body_acct_data_len = -1;
static int hf_tacplus_body_acct_data = -1;
static int hf_tacplus_data = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_tacplus_ascii_length = -1;
static int hf_tacplus_arap_data_length = -1;
static int hf_tacplus_mschap_data_length = -1;
static int hf_tacplus_chap_data_length = -1;
static int hf_tacplus_password_length = -1;
static int hf_tacplus_data_length = -1;

static gint ett_tacplus = -1;
static gint ett_tacplus_body = -1;
static gint ett_tacplus_body_chap = -1;
static gint ett_tacplus_flags = -1;
static gint ett_tacplus_acct_flags = -1;

static expert_field ei_tacplus_packet_len_invalid = EI_INIT;
static expert_field ei_tacplus_bogus_data = EI_INIT;

typedef struct _tacplus_key_entry {
	address *s; /* Server address */
	address *c; /* client address */
	char	*k; /* Key */
} tacplus_key_entry;

static gint
tacplus_decrypted_tvb_setup( tvbuff_t *tvb, tvbuff_t **dst_tvb, packet_info *pinfo, guint32 len, guint8 version, const char *key )
{
	guint8	*buff;
	guint8 session_id[4];

	/* TODO Check the possibility to use pinfo->decrypted_data */
	/* session_id is in NETWORK Byte Order, and is used as byte array in the md5_xor */

	tvb_memcpy(tvb, session_id, 4,4);

	buff = (guint8 *)tvb_memdup(pinfo->pool, tvb, TAC_PLUS_HDR_SIZE, len);


	md5_xor( buff, key, len, session_id,version, tvb_get_guint8(tvb,2) );

	/* Allocate a new tvbuff, referring to the decrypted data. */
	*dst_tvb = tvb_new_child_real_data(tvb,  buff, len, len );

	/* Add the decrypted data to the data source list. */
	add_new_data_source(pinfo, *dst_tvb, "TACACS+ Decrypted");

	return 0;
}
static void
dissect_tacplus_args_list( tvbuff_t *tvb, proto_tree *tree, int data_off, int len_off, int arg_cnt )
{
	int i;
	int len;
	guint8 *value;
	for(i=0;i<arg_cnt;i++){
		len=tvb_get_guint8(tvb,len_off+i);
		proto_tree_add_uint_format(tree, hf_tacplus_arg_length, tvb, len_off+i, 1, len,
									"Arg[%d] length: %d", i, len);
		value=tvb_get_string_enc(wmem_packet_scope(), tvb, data_off, len, ENC_ASCII|ENC_NA);
		proto_tree_add_string_format(tree, hf_tacplus_arg_value, tvb, data_off, len, value,
									"Arg[%d] value: %s", i, value);
		data_off+=len;
	}
}


static int
proto_tree_add_tacplus_common_fields( tvbuff_t *tvb, proto_tree *tree,  int offset, int var_off )
{
	int val;
	/* priv_lvl */
	proto_tree_add_item(tree, hf_tacplus_privilege_level, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* authen_type */
	proto_tree_add_item(tree, hf_tacplus_authentication_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* service */
	proto_tree_add_item(tree, hf_tacplus_service, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* user_len && user */
	val=tvb_get_guint8(tvb,offset);
	proto_tree_add_uint(tree, hf_tacplus_user_len, tvb, offset, 1, val);

	if( val ){
		proto_tree_add_item(tree, hf_tacplus_user, tvb, var_off, val, ENC_ASCII|ENC_NA);
		var_off+=val;
	}
	offset++;


	/* port_len && port */
	val=tvb_get_guint8(tvb,offset);
	proto_tree_add_uint(tree, hf_tacplus_port_len, tvb, offset, 1, val);
	if( val ){
		proto_tree_add_item(tree, hf_tacplus_port, tvb, var_off, val, ENC_ASCII|ENC_NA);
		var_off+=val;
	}
	offset++;

	/* rem_addr_len && rem_addr */
	val=tvb_get_guint8(tvb,offset);
	proto_tree_add_uint(tree, hf_tacplus_remote_address_len, tvb, offset, 1, val);
	if( val ){
		proto_tree_add_item(tree, hf_tacplus_remote_address, tvb, var_off, val, ENC_ASCII|ENC_NA);
		var_off+=val;
	}
	return var_off;
}

static void
dissect_tacplus_body_authen_req_login( tvbuff_t* tvb, proto_tree *tree, int var_off )
{
	guint8 val;
	val=tvb_get_guint8( tvb, AUTHEN_S_DATA_LEN_OFF );

	switch ( tvb_get_guint8(tvb, AUTHEN_S_AUTHEN_TYPE_OFF ) ) { /* authen_type */

		case TAC_PLUS_AUTHEN_TYPE_ASCII:
			proto_tree_add_item(tree, hf_tacplus_ascii_length, tvb, AUTHEN_S_DATA_LEN_OFF, 1, ENC_BIG_ENDIAN);
			if( val )
				proto_tree_add_item( tree, hf_tacplus_data, tvb, var_off, val, ENC_NA);
			break;

		case TAC_PLUS_AUTHEN_TYPE_PAP:
			proto_tree_add_item(tree, hf_tacplus_password_length, tvb, AUTHEN_S_DATA_LEN_OFF, 1, ENC_BIG_ENDIAN);
			if( val ) {
				proto_tree_add_item(tree, hf_tacplus_auth_password, tvb, var_off, val, ENC_ASCII|ENC_NA);
			}
			break;

		case TAC_PLUS_AUTHEN_TYPE_CHAP:
			proto_tree_add_item(tree, hf_tacplus_chap_data_length, tvb, AUTHEN_S_DATA_LEN_OFF, 1, ENC_BIG_ENDIAN);
			if( val ) {
				proto_tree *pt;
				guint8 chal_len=val-(1+16); /* Response field alwayes 16 octets */
				pt = proto_tree_add_subtree(tree, tvb, var_off, val, ett_tacplus_body_chap, NULL, "CHAP Data" );
				proto_tree_add_item(pt, hf_tacplus_chap_id, tvb, var_off, 1, ENC_BIG_ENDIAN);
				var_off++;
				proto_tree_add_item(pt, hf_tacplus_chap_challenge, tvb, var_off, chal_len, ENC_ASCII|ENC_NA);
				var_off+=chal_len;
				proto_tree_add_item(pt, hf_tacplus_chap_response, tvb, var_off, 16, ENC_ASCII|ENC_NA);
			}
			break;
		case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
			proto_tree_add_item(tree, hf_tacplus_mschap_data_length, tvb, AUTHEN_S_DATA_LEN_OFF, 1, ENC_BIG_ENDIAN);
			if( val ) {
				proto_tree *pt;
				guint8 chal_len=val-(1+49);  /* Response field alwayes 49 octets */
				pt = proto_tree_add_subtree(tree, tvb, var_off, val, ett_tacplus_body_chap, NULL, "MSCHAP Data" );
				proto_tree_add_item(pt, hf_tacplus_mschap_id, tvb, var_off, 1, ENC_BIG_ENDIAN);
				var_off++;
				proto_tree_add_item(pt, hf_tacplus_mschap_challenge, tvb, var_off, chal_len, ENC_ASCII|ENC_NA);
				var_off+=chal_len;
				proto_tree_add_item(pt, hf_tacplus_mschap_response, tvb, var_off, 49, ENC_ASCII|ENC_NA);
			}
			break;
		case TAC_PLUS_AUTHEN_TYPE_ARAP:
			proto_tree_add_item(tree, hf_tacplus_arap_data_length, tvb, AUTHEN_S_DATA_LEN_OFF, 1, ENC_BIG_ENDIAN);
			if( val ) {
				proto_tree *pt;
				pt = proto_tree_add_subtree(tree, tvb, var_off, val, ett_tacplus_body_chap, NULL, "ARAP Data" );
				proto_tree_add_item(pt, hf_tacplus_arap_nas_challenge, tvb, var_off, 8, ENC_ASCII|ENC_NA);
				var_off+=8;
				proto_tree_add_item(pt, hf_tacplus_arap_remote_challenge, tvb, var_off, 8, ENC_ASCII|ENC_NA);
				var_off+=8;
				proto_tree_add_item(pt, hf_tacplus_arap_remote_response, tvb, var_off, 8, ENC_ASCII|ENC_NA);
			}
			break;

		default: /* Should not be reached */
			proto_tree_add_item(tree, hf_tacplus_data_length, tvb, AUTHEN_S_DATA_LEN_OFF, 1, ENC_BIG_ENDIAN);
			if( val ){
				proto_tree_add_item( tree, hf_tacplus_data, tvb, var_off, val, ENC_NA);
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
	proto_tree_add_item(tree, hf_tacplus_authen_action, tvb, AUTHEN_S_ACTION_OFF, 1, ENC_BIG_ENDIAN);
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
	proto_item* ti;

	val=tvb_get_guint8( tvb, AUTHEN_C_FLAGS_OFF );
	ti = proto_tree_add_item(tree, hf_tacplus_body_authen_req_cont_flags, tvb, AUTHEN_C_FLAGS_OFF, 1, ENC_BIG_ENDIAN);
	if (val&TAC_PLUS_CONTINUE_FLAG_ABORT)
		proto_item_append_text(ti, "(Abort)");

	val=tvb_get_ntohs( tvb, AUTHEN_C_USER_LEN_OFF );
	proto_tree_add_uint(tree, hf_tacplus_body_authen_req_cont_user_length, tvb, AUTHEN_C_USER_LEN_OFF, 2, val);
	if( val ){
		proto_tree_add_item(tree, hf_tacplus_body_authen_req_cont_user, tvb, var_off, val, ENC_ASCII|ENC_NA);
		var_off+=val;
	}

	val=tvb_get_ntohs( tvb, AUTHEN_C_DATA_LEN_OFF );
	proto_tree_add_uint(tree, hf_tacplus_body_authen_req_cont_data_length, tvb, AUTHEN_C_DATA_LEN_OFF, 2, val);
	if( val ){
		proto_tree_add_item( tree, hf_tacplus_data, tvb, var_off, val, ENC_NA );
	}

}

/* Server REPLY */
static void
dissect_tacplus_body_authen_rep( tvbuff_t *tvb, proto_tree *tree )
{
	int val;
	int var_off=AUTHEN_R_VARDATA_OFF;
	proto_item* ti;

	proto_tree_add_item(tree, hf_tacplus_body_authen_rep_status, tvb, AUTHEN_R_STATUS_OFF, 1, ENC_BIG_ENDIAN);

	val=tvb_get_guint8( tvb, AUTHEN_R_FLAGS_OFF );
	ti = proto_tree_add_item(tree, hf_tacplus_body_authen_rep_flags, tvb, AUTHEN_R_FLAGS_OFF, 1, ENC_BIG_ENDIAN);
	if (val&TAC_PLUS_REPLY_FLAG_NOECHO)
		proto_item_append_text(ti, "(NoEcho)");

	val=tvb_get_ntohs(tvb, AUTHEN_R_SRV_MSG_LEN_OFF );
	proto_tree_add_uint(tree, hf_tacplus_body_authen_rep_server_msg_len, tvb, AUTHEN_R_SRV_MSG_LEN_OFF, 2, val);

	if( val ) {
		proto_tree_add_item(tree, hf_tacplus_body_authen_rep_server_msg, tvb, var_off, val, ENC_ASCII|ENC_NA);
		var_off+=val;
	}

	val=tvb_get_ntohs(tvb, AUTHEN_R_DATA_LEN_OFF );
	proto_tree_add_uint(tree, hf_tacplus_body_authen_rep_server_data_len, tvb, AUTHEN_R_DATA_LEN_OFF, 2, val);
	if( val ){
		proto_tree_add_item(tree, hf_tacplus_data, tvb, var_off, val, ENC_NA );
	}
}

static void
dissect_tacplus_body_author_req( tvbuff_t* tvb, proto_tree *tree )
{
	int val;
	int var_off;

	proto_tree_add_item(tree, hf_tacplus_body_author_req_auth_method, tvb, AUTHOR_Q_AUTH_METH_OFF, 1, ENC_BIG_ENDIAN);

	val = tvb_get_guint8( tvb, AUTHOR_Q_ARGC_OFF );
	var_off=proto_tree_add_tacplus_common_fields( tvb, tree ,
			AUTHOR_Q_PRIV_LVL_OFF,
			AUTHOR_Q_VARDATA_OFF + val);

	proto_tree_add_item(tree, hf_tacplus_body_author_req_arg_count, tvb, AUTHOR_Q_ARGC_OFF, 1, ENC_BIG_ENDIAN);

/* var_off points after rem_addr */

	dissect_tacplus_args_list( tvb, tree, var_off, AUTHOR_Q_VARDATA_OFF, val );
}

static void
dissect_tacplus_body_author_rep( tvbuff_t* tvb, proto_tree *tree )
{
	int offset=AUTHOR_R_VARDATA_OFF;
	int val;

	proto_tree_add_item(tree, hf_tacplus_body_author_rep_auth_status, tvb, AUTHOR_R_STATUS_OFF, 1, ENC_BIG_ENDIAN);

	val=tvb_get_ntohs( tvb, AUTHOR_R_SRV_MSG_LEN_OFF );
	offset+=val;
	proto_tree_add_item(tree, hf_tacplus_body_author_rep_server_msg_len, tvb, AUTHOR_R_SRV_MSG_LEN_OFF, 2, ENC_BIG_ENDIAN);

	val=tvb_get_ntohs( tvb, AUTHOR_R_DATA_LEN_OFF );
	offset+=val;
	proto_tree_add_item(tree, hf_tacplus_body_author_rep_server_data_len, tvb, AUTHOR_R_DATA_LEN_OFF, 2, ENC_BIG_ENDIAN);

	val=tvb_get_guint8( tvb, AUTHOR_R_ARGC_OFF);
	offset+=val;
	proto_tree_add_item(tree, hf_tacplus_body_author_rep_arg_count, tvb, AUTHOR_R_ARGC_OFF, 1, ENC_BIG_ENDIAN);

	dissect_tacplus_args_list( tvb, tree, offset, AUTHOR_R_VARDATA_OFF, val );
}

static void
dissect_tacplus_body_acct_req( tvbuff_t* tvb, proto_tree *tree )
{
	int val, var_off;

	proto_item *tf;
	proto_tree *flags_tree;

	tf = proto_tree_add_item( tree, hf_tacplus_acct_flags, tvb, ACCT_Q_FLAGS_OFF, 1, ENC_BIG_ENDIAN);

	flags_tree = proto_item_add_subtree( tf, ett_tacplus_acct_flags );
	proto_tree_add_item(flags_tree, hf_tacplus_acct_flags_more, tvb, ACCT_Q_FLAGS_OFF, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flags_tree, hf_tacplus_acct_flags_start, tvb, ACCT_Q_FLAGS_OFF, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flags_tree, hf_tacplus_acct_flags_stop, tvb, ACCT_Q_FLAGS_OFF, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flags_tree, hf_tacplus_acct_flags_watchdog, tvb, ACCT_Q_FLAGS_OFF, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_tacplus_acct_authen_method, tvb, ACCT_Q_METHOD_OFF, 1, ENC_BIG_ENDIAN);
	val=tvb_get_guint8( tvb, ACCT_Q_ARG_CNT_OFF );

	/* authen_type */
	var_off=proto_tree_add_tacplus_common_fields( tvb, tree ,
			ACCT_Q_PRIV_LVL_OFF,
			ACCT_Q_VARDATA_OFF+val
			);

	proto_tree_add_item(tree, hf_tacplus_acct_arg_count, tvb, ACCT_Q_ARG_CNT_OFF, 1, ENC_BIG_ENDIAN);

	dissect_tacplus_args_list( tvb, tree, var_off, ACCT_Q_VARDATA_OFF, val );


}

static void
dissect_tacplus_body_acct_rep( tvbuff_t* tvb, proto_tree *tree )
{
	int val, var_off=ACCT_Q_VARDATA_OFF;

	/* Status */
	proto_tree_add_item(tree, hf_tacplus_body_acct_status, tvb, ACCT_R_STATUS_OFF, 1, ENC_BIG_ENDIAN);

	/* Server Message */
	val=tvb_get_ntohs( tvb, ACCT_R_SRV_MSG_LEN_OFF );
	proto_tree_add_item(tree, hf_tacplus_body_acct_server_msg_len, tvb, ACCT_R_SRV_MSG_LEN_OFF, 2, ENC_BIG_ENDIAN);
	if( val ) {
		proto_tree_add_item(tree, hf_tacplus_body_acct_server_msg, tvb, var_off, val, ENC_ASCII|ENC_NA);
		var_off+=val;
	}

	/*  Data */
	val=tvb_get_ntohs( tvb, ACCT_R_DATA_LEN_OFF );
	proto_tree_add_item(tree, hf_tacplus_body_acct_data_len, tvb, ACCT_R_DATA_LEN_OFF, 2, ENC_BIG_ENDIAN);
	if( val ) {
		proto_tree_add_item(tree, hf_tacplus_body_acct_data, tvb, var_off, val, ENC_ASCII|ENC_NA);
	}
}



static void
dissect_tacplus_body(tvbuff_t * hdr_tvb, packet_info *pinfo, tvbuff_t * tvb, proto_tree * tree )
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
		break;
	  case TAC_PLUS_AUTHOR:
		if ( seq_no & 0x01)
			dissect_tacplus_body_author_req( tvb, tree );
		else
			dissect_tacplus_body_author_rep( tvb, tree );
		break;
	  case TAC_PLUS_ACCT:
		if ( seq_no & 0x01)
			dissect_tacplus_body_acct_req( tvb, tree );
		else
			dissect_tacplus_body_acct_rep( tvb, tree );
		break;
	  default:
		proto_tree_add_expert( tree, pinfo, &ei_tacplus_bogus_data, tvb, 0, -1);
		break;
	}
}

#ifdef DEB_TACPLUS
static void
tacplus_print_key_entry( gpointer data, gpointer user_data )
{
	tacplus_key_entry *tacplus_data=(tacplus_key_entry *)data;
	gchar *s_str, *c_str;

	s_str = address_to_str( NULL, tacplus_data->s );
	c_str = address_to_str( NULL, tacplus_data->c );
	if( user_data ) {
		printf("%s:%s=%s\n", s_str, c_str, tacplus_data->k );
	} else {
		printf("%s:%s\n", s_str, c_str );
	}
	wmem_free(NULL, s_str);
	wmem_free(NULL, c_str);
}
#endif
static int
cmp_conv_address( gconstpointer p1, gconstpointer p2 )
{
	const tacplus_key_entry *a1=(const tacplus_key_entry *)p1;
	const tacplus_key_entry *a2=(const tacplus_key_entry *)p2;
	gint32	ret;
	/*
	printf("p1=>");
	tacplus_print_key_entry( p1, NULL );
	printf("p2=>");
	tacplus_print_key_entry( p2, NULL );
	*/
	ret=cmp_address( a1->s, a2->s );
	if( !ret ) {
		ret=cmp_address( a1->c, a2->c );
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
	int   ret;
	char *addr_data;

	*addr=(address *)g_malloc( sizeof(address) );
	addr_data=(char *)g_malloc( 4 );
	ret = str_to_ip(str_addr, addr_data);
	if (ret)
		set_address(*addr, AT_IPv4, 4, addr_data);
	else
		set_address(*addr, AT_STRINGZ, (int)strlen(ADDR_INVLD)+1, ADDR_INVLD);
}
static void
parse_tuple( char *key_from_option )
{
	char *client,*key;
	tacplus_key_entry *tacplus_data=(tacplus_key_entry *)g_malloc( sizeof(tacplus_key_entry) );
	/*
	printf("keys: %s\n", key_from_option );
	*/
	client=strchr(key_from_option,'/');
	if(!client) {
		g_free(tacplus_data);
		return;
	}
	*client++='\0';
	key=strchr(client,'=');
	if(!key) {
		g_free(tacplus_data);
		return;
	}
	*key++='\0';
	/*
	printf("%s %s => %s\n", key_from_option, client, key );
	*/
	mkipv4_address( &tacplus_data->s, key_from_option );
	mkipv4_address( &tacplus_data->c, client );
	tacplus_data->k=g_strdup(key);
	tacplus_keys = g_slist_prepend( tacplus_keys, tacplus_data );
}

static
void
parse_tacplus_keys( const char *keys_from_option )
{
	char *key_copy,*s,*s1;

	/* Drop old keys */
	if( tacplus_keys ) {
		g_slist_free( tacplus_keys );
		tacplus_keys=NULL;
	}

	if( !strchr( keys_from_option, '/' ) ){
		/* option not in client/server=key format */
		return ;
	}
	key_copy=g_strdup(keys_from_option);
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

static int
dissect_tacplus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	tvbuff_t	*new_tvb=NULL;
	proto_tree      *tacplus_tree, *body_tree;
	proto_item      *ti, *hidden_item;
	guint8		version,flags;
	proto_tree      *flags_tree;
	proto_item      *tf;
	proto_item	*tmp_pi;
	guint32		len;
	gboolean	request=( pinfo->destport == TCP_PORT_TACACS );
	const char	*key=NULL;

	len = tvb_get_ntohl(tvb, 8);

	if(len > (guint)tvb_captured_length_remaining(tvb, 12) &&
	   pinfo->can_desegment && tacplus_preference_desegment) {
		pinfo->desegment_offset = 0;
		pinfo->desegment_len = len;
		return tvb_captured_length(tvb);
	}

	if( request ) {
		key=find_key( &pinfo->dst, &pinfo->src );
	} else {
		key=find_key(  &pinfo->src, &pinfo->dst );
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TACACS+");

	col_add_fstr( pinfo->cinfo, COL_INFO, "%s: %s",
				request ? "Q" : "R",
				val_to_str(tvb_get_guint8(tvb,1), tacplus_type_vals, "Unknown (0x%02x)"));

	if (tree)
	{
		ti = proto_tree_add_item(tree, proto_tacplus, tvb, 0, -1, ENC_NA);

		tacplus_tree = proto_item_add_subtree(ti, ett_tacplus);
		if (pinfo->match_uint == pinfo->destport)
		{
			hidden_item = proto_tree_add_boolean(tacplus_tree,
			    hf_tacplus_request, tvb, 0, 0, TRUE);
		}
		else
		{
			hidden_item = proto_tree_add_boolean(tacplus_tree,
			    hf_tacplus_response, tvb, 0, 0, TRUE);
		}
		PROTO_ITEM_SET_HIDDEN(hidden_item);

		version = tvb_get_guint8(tvb,0);
		proto_tree_add_uint_format_value(tacplus_tree, hf_tacplus_majvers, tvb, 0, 1,
		    version,
		    "%s",
		    (version&0xf0)==0xc0?"TACACS+":"Unknown Version");
		proto_tree_add_uint(tacplus_tree, hf_tacplus_minvers, tvb, 0, 1,
		    version&0xf);
		proto_tree_add_item(tacplus_tree, hf_tacplus_type, tvb, 1, 1,
		    ENC_BIG_ENDIAN);
		proto_tree_add_item(tacplus_tree, hf_tacplus_seqno, tvb, 2, 1,
		    ENC_BIG_ENDIAN);
		flags = tvb_get_guint8(tvb,3);
		tf = proto_tree_add_uint_format_value(tacplus_tree, hf_tacplus_flags,
		    tvb, 3, 1, flags,
		    "0x%02x (%s payload, %s)", flags,
		    (flags&FLAGS_UNENCRYPTED) ? "Unencrypted" : "Encrypted",
		    (flags&FLAGS_SINGLE) ? "Single connection" : "Multiple Connections" );
		flags_tree = proto_item_add_subtree(tf, ett_tacplus_flags);
		proto_tree_add_boolean(flags_tree, hf_tacplus_flags_payload_type,
		    tvb, 3, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_tacplus_flags_connection_type,
		    tvb, 3, 1, flags);
		proto_tree_add_item(tacplus_tree, hf_tacplus_session_id, tvb, 4, 4,
		    ENC_BIG_ENDIAN);

		tmp_pi = proto_tree_add_uint(tacplus_tree, hf_tacplus_packet_len, tvb, 8, 4, len);
		if ((gint)len < 1) {
			expert_add_info_format(pinfo, tmp_pi, &ei_tacplus_packet_len_invalid, "Invalid length: %u", len);
		}

		body_tree = proto_tree_add_subtree_format(tacplus_tree, tvb, TAC_PLUS_HDR_SIZE, len,
						ett_tacplus_body, NULL, "%s%s", ((flags&FLAGS_UNENCRYPTED)?"":"Encrypted "), request?"Request":"Reply" );

		if( flags&FLAGS_UNENCRYPTED ) {
			new_tvb = tvb_new_subset_length( tvb, TAC_PLUS_HDR_SIZE, len );
		}  else {
			new_tvb=NULL;
			if( key && *key ){
				tacplus_decrypted_tvb_setup( tvb, &new_tvb, pinfo, len, version, key );
			}
		}
		if( new_tvb ) {
			/* Check to see if I've a decrypted tacacs packet */
			if( !(flags&FLAGS_UNENCRYPTED) ){
				body_tree = proto_tree_add_subtree_format(tacplus_tree, new_tvb, 0, len,
							ett_tacplus_body, NULL, "Decrypted %s", request?"Request":"Reply" );
			}
			dissect_tacplus_body( tvb, pinfo, new_tvb, body_tree);
		}
	}
	return tvb_captured_length(tvb);
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
	    { "Response", "tacplus.response",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if TACACS+ response", HFILL }},
	  { &hf_tacplus_request,
	    { "Request", "tacplus.request",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if TACACS+ request", HFILL }},
	  { &hf_tacplus_majvers,
	    { "Major version", "tacplus.majvers",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      "Major version number", HFILL }},
	  { &hf_tacplus_minvers,
	    { "Minor version", "tacplus.minvers",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      "Minor version number", HFILL }},
	  { &hf_tacplus_type,
	    { "Type", "tacplus.type",
	      FT_UINT8, BASE_DEC, VALS(tacplus_type_vals), 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_seqno,
	    { "Sequence number", "tacplus.seqno",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_flags,
	    { "Flags", "tacplus.flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_flags_payload_type,
	    { "Unencrypted", "tacplus.flags.unencrypted",
	      FT_BOOLEAN, 8, TFS(&tfs_set_notset), FLAGS_UNENCRYPTED,
	      "Is payload unencrypted?", HFILL }},
	  { &hf_tacplus_flags_connection_type,
	    { "Single Connection", "tacplus.flags.singleconn",
	      FT_BOOLEAN, 8, TFS(&tfs_set_notset), FLAGS_SINGLE,
	      "Is this a single connection?", HFILL }},
	  { &hf_tacplus_acct_flags,
	    { "Flags", "tacplus.acct.flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_acct_flags_more,
	    { "More", "tacplus.acct.flags.more",
	      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TAC_PLUS_ACCT_FLAG_MORE,
	      NULL, HFILL }},
	  { &hf_tacplus_acct_flags_start,
	    { "Start", "tacplus.acct.flags.start",
	      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TAC_PLUS_ACCT_FLAG_START,
	      NULL, HFILL }},
	  { &hf_tacplus_acct_flags_stop,
	    { "Stop", "tacplus.acct.flags.stop",
	      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TAC_PLUS_ACCT_FLAG_STOP,
	      NULL, HFILL }},
	  { &hf_tacplus_acct_flags_watchdog,
	    { "Watchdog", "tacplus.acct.flags.watchdog",
	      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TAC_PLUS_ACCT_FLAG_WATCHDOG,
	      NULL, HFILL }},
	  { &hf_tacplus_session_id,
	    { "Session ID", "tacplus.session_id",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_packet_len,
	    { "Packet length", "tacplus.packet_len",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_auth_password,
	    { "Password", "tacplus.auth_password",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_port,
	    { "Port", "tacplus.port",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_remote_address,
	    { "Remote Address", "tacplus.remote_address",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_chap_challenge,
	    { "Challenge", "tacplus.chap.challenge",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_chap_response,
	    { "Response", "tacplus.chap.response",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_mschap_challenge,
	    { "Challenge", "tacplus.mschap.challenge",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_mschap_response,
	    { "Response", "tacplus.mschap.response",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_arap_nas_challenge,
	    { "Nas Challenge", "tacplus.arap.nas_challenge",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_arap_remote_challenge,
	    { "Remote Challenge", "tacplus.arap.remote_challenge",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_arap_remote_response,
	    { "Remote Response", "tacplus.arap.remote_response",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_privilege_level,
	    { "Privilege Level", "tacplus.privilege_level",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_authentication_type,
	    { "Authentication type", "tacplus.authentication_type",
	      FT_UINT8, BASE_DEC, VALS(tacplus_authen_type_vals), 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_service,
	    { "Service", "tacplus.service",
	      FT_UINT8, BASE_DEC, VALS(tacplus_authen_service_vals), 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_user_len,
	    { "User len", "tacplus.user_len",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_user,
	    { "User", "tacplus.user",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_port_len,
	    { "Port len", "tacplus.port_len",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_remote_address_len,
	    { "Remaddr len", "tacplus.address_len",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_arg_length,
	    { "Length", "tacplus.arg_length",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_arg_value,
	    { "Value", "tacplus.arg_value",
	      FT_STRINGZ, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_chap_id,
	    { "ID", "tacplus.chap.id",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_mschap_id,
	    { "ID", "tacplus.mschap.id",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_authen_action,
	    { "Action", "tacplus.authen_action",
	      FT_UINT8, BASE_DEC, VALS(tacplus_authen_action_vals), 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_authen_req_cont_flags,
	    { "Flags", "tacplus.body_authen_req_cont.flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_authen_req_cont_user_length,
	    { "User length", "tacplus.body_authen_req_cont.user_length",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_authen_req_cont_data_length,
	    { "Data length", "tacplus.body_authen_req_cont.data_length",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_authen_req_cont_user,
	    { "User", "tacplus.body_authen_req_cont.user",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_authen_rep_status,
	    { "Status", "tacplus.body_authen_rep.status",
	      FT_UINT8, BASE_HEX, VALS(tacplus_reply_status_vals), 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_authen_rep_flags,
	    { "Flags", "tacplus.body_authen_rep.flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_authen_rep_server_msg_len,
	    { "Server message length", "tacplus.body_authen_rep.server_msg_len",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_authen_rep_server_msg,
	    { "Server message", "tacplus.body_authen_rep.server_msg",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_authen_rep_server_data_len,
	    { "Data length", "tacplus.body_authen_rep_server.data_len",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_author_req_auth_method,
	    { "Auth Method", "tacplus.body_author_req.auth_method",
	      FT_UINT8, BASE_HEX, VALS(tacplus_authen_method), 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_author_req_arg_count,
	    { "Arg count", "tacplus.body_author_req.arg_count",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_author_rep_auth_status,
	    { "Auth Status", "tacplus.body_author_rep.auth_status",
	      FT_UINT8, BASE_HEX, VALS(tacplus_author_status), 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_author_rep_server_msg_len,
	    { "Server Msg length", "tacplus.body_author_rep_server.msg_len",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_author_rep_server_data_len,
	    { "Data length", "tacplus.body_author_rep_server.data_len",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_author_rep_arg_count,
	    { "Arg count", "tacplus.body_author_rep.arg_count",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_acct_authen_method,
	    { "Auth Method", "tacplus.acct.auth_method",
	      FT_UINT8, BASE_HEX, VALS(tacplus_authen_method), 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_acct_arg_count,
	    { "Arg count", "tacplus.acct.arg_count",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_acct_status,
	    { "Status", "tacplus.body_acct.status",
	      FT_UINT8, BASE_HEX, VALS(tacplus_acct_status), 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_acct_server_msg_len,
	    { "Server Msg length", "tacplus.body_acct.msg_len",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_acct_data_len,
	    { "Data length", "tacplus.body_acct.data_len",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_acct_server_msg,
	    { "Server message", "tacplus.body_acct.server_msg",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_body_acct_data,
	    { "Data", "tacplus.body_acct.data",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_tacplus_data,
	    { "Data", "tacplus.data",
	      FT_BYTES, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},

	/* Generated from convert_proto_tree_add_text.pl */
	  { &hf_tacplus_ascii_length, { "ASCII Data Length", "tacplus.ascii_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	  { &hf_tacplus_password_length, { "Password Length", "tacplus.password_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	  { &hf_tacplus_chap_data_length, { "CHAP Data Length", "tacplus.chap_data_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	  { &hf_tacplus_mschap_data_length, { "MSCHAP Data Length", "tacplus.mschap_data_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	  { &hf_tacplus_arap_data_length, { "ARAP Data Length", "tacplus.arap_data_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	  { &hf_tacplus_data_length, { "Data", "tacplus.data_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_tacplus,
		&ett_tacplus_flags,
		&ett_tacplus_acct_flags,
		&ett_tacplus_body,
		&ett_tacplus_body_chap,
	};

	static ei_register_info ei[] = {
		{ &ei_tacplus_packet_len_invalid, { "tacplus.packet_len.invalid", PI_PROTOCOL, PI_WARN, "Invalid length", EXPFILL }},
		{ &ei_tacplus_bogus_data, { "tacplus.bogus_data", PI_PROTOCOL, PI_WARN, "Bogus data", EXPFILL }},
	};

	module_t *tacplus_module;
	expert_module_t* expert_tacplus;

	proto_tacplus = proto_register_protocol("TACACS+", "TACACS+", "tacplus");
	proto_register_field_array(proto_tacplus, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_tacplus = expert_register_protocol(proto_tacplus);
	expert_register_field_array(expert_tacplus, ei, array_length(ei));
	tacplus_module = prefs_register_protocol (proto_tacplus, tacplus_pref_cb );

	prefs_register_bool_preference(tacplus_module, "desegment", "Reassemble TACACS+ messages spanning multiple TCP segments.", "Whether the TACACS+ dissector should reassemble messages spanning multiple TCP segments.  To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.", &tacplus_preference_desegment);

	prefs_register_string_preference ( tacplus_module, "key",
	"TACACS+ Encryption Key", "TACACS+ Encryption Key", &tacplus_opt_key );
}

void
proto_reg_handoff_tacplus(void)
{
	dissector_handle_t tacplus_handle;

	tacplus_handle = create_dissector_handle(dissect_tacplus,
	    proto_tacplus);
	dissector_add_uint("tcp.port", TCP_PORT_TACACS, tacplus_handle);
}


#define MD5_LEN 16

static void
md5_xor( guint8 *data, const char *key, int data_len, guint8 *session_id, guint8 version, guint8 seq_no )
{
	int i,j;
	size_t md5_len;
	md5_byte_t *md5_buff;
	md5_byte_t hash[MD5_LEN];				/* the md5 hash */
	md5_byte_t *mdp;
	md5_state_t mdcontext;

	md5_len = 4 /* sizeof(session_id) */ + strlen(key)
			+ sizeof(version) + sizeof(seq_no);

	md5_buff = (md5_byte_t*)wmem_alloc(wmem_packet_scope(), md5_len+MD5_LEN);


	mdp = md5_buff;
	memcpy(mdp, session_id, 4);
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
