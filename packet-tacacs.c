/* packet-tacacs.c
 * Routines for cisco tacacs/xtacacs/tacacs+ packet dissection
 * Copyright 2001, Paul Ionescu <paul@acorp.ro>
 *
 * $Id: packet-tacacs.c,v 1.18 2001/12/10 00:25:39 guy Exp $
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
 * draft-grant-tacacs-00.txt for tacacs+ (tacplus)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

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

#define TAC_PLUS_AUTHEN 1
#define TAC_PLUS_AUTHOR 2
#define TAC_PLUS_ACCT   3

#define UDP_PORT_TACACS	49
#define TCP_PORT_TACACS	49

static void
dissect_tacacs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *tacacs_tree;
	proto_item      *ti;
	guint8		txt_buff[256],version,type,userlen,passlen;

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
		 tvb, 0, tvb_length(tvb), version==0?"TACACS":"XTACACS");
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
		tvb_get_nstringz0(tvb,6,userlen,txt_buff);
		proto_tree_add_text(tacacs_tree, tvb, 6, userlen,         "Username: %s",txt_buff);
		tvb_get_nstringz0(tvb,6+userlen,passlen,txt_buff);
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
	    	tvb_get_nstringz0(tvb,26,userlen,txt_buff);
	    	proto_tree_add_text(tacacs_tree, tvb, 26, userlen,  "Username: %s",txt_buff);
	    	tvb_get_nstringz0(tvb,26+userlen,passlen,txt_buff);
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
static int hf_tacplus_session_id = -1;
static int hf_tacplus_packet_len = -1;

static gint ett_tacplus = -1;
static gint ett_tacplus_flags = -1;

static const value_string tacplus_type_vals[] = {
	{ TAC_PLUS_AUTHEN  , "Authentication" },
	{ TAC_PLUS_AUTHOR  , "Authorization" },
	{ TAC_PLUS_ACCT    , "Accounting" },
	{ 0 , NULL }};

#define FLAGS_UNENCRYPTED	0x01

static const true_false_string payload_type = {
  "Unencrypted",
  "Encrypted"
};

#define FLAGS_SINGLE		0x04

static const true_false_string connection_type = {
  "Single",
  "Multiple"
};

static void
dissect_tacplus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *tacplus_tree;
	proto_item      *ti;
	guint8		version,flags;
	proto_tree      *flags_tree;
	proto_item      *tf;
	guint32		len;
	gboolean	request=(pinfo->match_port == pinfo->destport);

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TACACS+");

	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_add_str(pinfo->cinfo, COL_INFO,
			request ? "Request" : "Response");	  
	}

	if (tree) 
	{
		ti = proto_tree_add_protocol_format(tree, proto_tacplus,
		 tvb, 0, tvb_length(tvb), "TACACS+");

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
		    "Flags: %s, %s (0x%02x)",
		    (flags&FLAGS_UNENCRYPTED) ? "Unencrypted payload" :
						"Encrypted payload",
		    (flags&FLAGS_SINGLE) ? "Single connection" :
					   "Multiple Connections",
		    flags);
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

		if (flags&FLAGS_UNENCRYPTED)
			proto_tree_add_text(tacplus_tree, tvb, 12, len, "Payload");
		else
			proto_tree_add_text(tacplus_tree, tvb, 12, len, "Encrypted payload");
	}
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
	    { "Payload type",       "tacplus.flags.payload_type",
	      FT_BOOLEAN, 8, TFS(&payload_type), FLAGS_UNENCRYPTED,
	      "Payload type (unencrypted or encrypted)", HFILL }},
	  { &hf_tacplus_flags_connection_type,
	    { "Connection type",    "tacplus.flags.connection_type",
	      FT_BOOLEAN, 8, TFS(&connection_type), FLAGS_SINGLE,
	      "Connection type (single or multiple)", HFILL }},
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
	};
	proto_tacplus = proto_register_protocol("TACACS+", "TACACS+", "tacplus");
	proto_register_field_array(proto_tacplus, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_tacplus(void)
{
	dissector_handle_t tacplus_handle;

	tacplus_handle = create_dissector_handle(dissect_tacplus,
	    proto_tacplus);
	dissector_add("tcp.port", TCP_PORT_TACACS, tacplus_handle);
}
