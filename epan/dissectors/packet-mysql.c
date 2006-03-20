/* packet-mysql.c
 * Routines for mysql packet dissection
 *
 * Huagang XIE <huagang@intruvert.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * the protocol spec at 
 * 	http://public.logicacmg.com/~redferni/mysql/MySQL-Protocol.html
 * and MySQL source code  
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#include "packet-tcp.h"
#include <epan/reassemble.h>
#include <epan/prefs.h>

/* Capabilities */
#define MYSQL_CAPS_LP 0x0001
#define MYSQL_CAPS_FR 0x0002
#define MYSQL_CAPS_LF 0x0004
#define MYSQL_CAPS_CD 0x0008
#define MYSQL_CAPS_NS 0x0010
#define MYSQL_CAPS_CP 0x0020
#define MYSQL_CAPS_OB 0x0040
#define MYSQL_CAPS_LI 0x0080
#define MYSQL_CAPS_IS 0x0100
#define MYSQL_CAPS_CU 0x0200
#define MYSQL_CAPS_IA 0x0400
#define MYSQL_CAPS_SL 0x0800
#define MYSQL_CAPS_II 0x1000
#define MYSQL_CAPS_TA 0x2000

static int proto_mysql = -1;
static int hf_mysql_packet_length= -1;
static int hf_mysql_packet_number= -1;
static int hf_mysql_opcode= -1;
static int hf_mysql_response_code= -1;
static int hf_mysql_error_code= -1;
static int hf_mysql_payload= -1;
static int hf_mysql_protocol= -1;
static int hf_mysql_caps= -1;
static int hf_mysql_cap_long_password= -1;
static int hf_mysql_cap_found_rows= -1;
static int hf_mysql_cap_long_flag= -1;
static int hf_mysql_cap_connect_with_db= -1;
static int hf_mysql_cap_no_schema= -1;
static int hf_mysql_cap_compress= -1;
static int hf_mysql_cap_odbc= -1;
static int hf_mysql_cap_local_files= -1;
static int hf_mysql_cap_ignore_space= -1;
static int hf_mysql_cap_change_user= -1;
static int hf_mysql_cap_interactive= -1;
static int hf_mysql_cap_ssl= -1;
static int hf_mysql_cap_ignore_sigpipe= -1;
static int hf_mysql_cap_transactions= -1;
static int hf_mysql_version = -1;
static int hf_mysql_max_packet= -1;
static int hf_mysql_user= -1;
static int hf_mysql_password= -1;
static int hf_mysql_thread_id = -1;
static int hf_mysql_salt= -1;
static int hf_mysql_charset= -1;
static int hf_mysql_status= -1;
static int hf_mysql_unused= -1;
static int hf_mysql_parameter= -1;

static gint ett_mysql = -1;
static gint ett_server_greeting = -1;
static gint ett_caps = -1;
static gint ett_request = -1;

static gboolean mysql_desegment = TRUE;

#define TCP_PORT_MySQL   3306 

#define	MySQL_SLEEP 		0
#define	MySQL_QUIT		1
#define	MySQL_INIT_DB		2
#define	MySQL_QUERY		3
#define	MySQL_FIELD_LIST	4
#define	MySQL_CREATE_DB		5
#define	MySQL_DROP_DB		6
#define MySQL_REFRESH		7
#define MySQL_SHUTDOWN		8
#define MySQL_STATISTICS 	9
#define MySQL_PROCESS_INFO 	10
#define MySQL_CONNECT		11
#define MySQL_PROCESS_KILL	12
#define MySQL_DEBUG		13
#define MySQL_PING		14
#define MySQL_TIME		15
#define MySQL_DELAY_INSERT	16
#define MySQL_CHANGE_USER	17
#define MySQL_BINLOG_DUMP	18
#define MySQL_TABLE_DUMP	19
#define MySQL_CONNECT_OUT	20


static const value_string mysql_opcode_vals[] = {
  { MySQL_SLEEP,   "SLEEP" },
  { MySQL_QUIT,   "Quit" },
  { MySQL_INIT_DB,  "Init Database" },
  { MySQL_QUERY,   "Query" },
  { MySQL_FIELD_LIST, "Field List" },
  { MySQL_CREATE_DB,  "Create Database" },
  { MySQL_DROP_DB , "Drop Database" },
  { MySQL_REFRESH , "Refresh" },
  { MySQL_SHUTDOWN , "Shutdown" },
  { MySQL_STATISTICS , "Statistics" },
  { MySQL_PROCESS_INFO , "Process Info" },
  { MySQL_CONNECT , "Connect" },
  { MySQL_PROCESS_KILL , "Process Kill" },
  { MySQL_DEBUG , "Debug" },
  { MySQL_PING , "Ping" },
  { MySQL_TIME , "Time" },
  { MySQL_DELAY_INSERT , "Delay Insert" },
  { MySQL_CHANGE_USER , "Change User" },
  { MySQL_BINLOG_DUMP , "Binlog Dump" },
  { MySQL_TABLE_DUMP, "Table Dump" },
  { MySQL_CONNECT_OUT, "Table Connect Out" },
  { 0,          NULL }
};

static const value_string mysql_status_vals[] = {
	{1, "IN_TRANS" },
	{2, "AUTOCOMMIT"},
	{ 0, NULL }
};
static const value_string mysql_charset_vals[] = {
	{1, "big5"}, 
	{2, "czech"},  
	{3,"dec8"},
	{4, "dos" },  
	{5,"german1"}, 
	{6,"hp8"},  
	{7,"koi8_ru"},
	{8,"latin1"},  
	{9,"latin2"}, 
	{9,"swe7 "},
	{10,"usa7"},
	{11,"ujis"},
	{12,"sjis"},
	{13,"cp1251"},
	{14,"danish"},
	{15,"hebrew"},
	{16,"win1251"},
	{17,"tis620"},
	{18,"euc_kr"},
	{19,"estonia"},
	{20,"hungarian"},
	{21,"koi8_ukr"},
	{22,"win1251ukr"},
	{23,"gb2312"},
	{24,"greek"},
	{25,"win1250"},
	{26,"croat"},
	{27,"gbk"},
	{28,"cp1257"},
	{29,"latin5"},
	{0,NULL}
};
#if 0
static const value_string mysql_error_code_vals[] = {
  { 0, "Not defined" },
  { 1, "File not found" },
  { 2, "Access violation" },
  { 3, "Disk full or allocation exceeded" },
  { 4, "Illegal MySQL Operation" },
  { 5, "Unknown transfer ID" },
  { 6, "File already exists" },
  { 7, "No such user" },
  { 8, "Option negotiation failed" },
  { 0, NULL }
};
#endif

static guint get_mysql_pdu_len(tvbuff_t *tvb, int offset);
static void dissect_mysql_pdu(tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *tree);
static int mysql_dissect_server_greeting(tvbuff_t *tvb, packet_info *pinfo, 
		int offset, proto_tree *tree);
static int mysql_dissect_authentication(tvbuff_t *tvb, packet_info *pinfo,
		int offset, proto_tree *tree);
static int mysql_dissect_request(tvbuff_t *tvb, packet_info *pinfo,
		int offset, proto_tree *tree);
static int mysql_dissect_response(tvbuff_t *tvb, packet_info *pinfo,
		int offset, proto_tree *tree);

static void
dissect_mysql(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, mysql_desegment, 3,
	    get_mysql_pdu_len, dissect_mysql_pdu);
}

static guint
get_mysql_pdu_len(tvbuff_t *tvb, int offset)
{
	guint plen;

	/*
	 * Get the length of the MySQL packet.
	 */
	plen = tvb_get_letoh24(tvb, offset);

	/*
	 * That length doesn't include the length field or the packet
	 * number itself; add them in.
	 */
	return plen + 4;
}

static void
dissect_mysql_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*mysql_tree = NULL;
	proto_item	*ti;
	conversation_t  *conversation;

	int		offset = 0;
	guint		packet_number;

	gboolean	is_response;

	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0);

	if (!conversation) {
		/* create a new conversation */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
				pinfo->srcport, pinfo->destport, 0);
	}


	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "MySQL");

	if (pinfo->destport == pinfo->match_port) {
		is_response=FALSE;
	}else {
		is_response=TRUE;
	}

	if (tree) {
		  ti = proto_tree_add_item(tree, proto_mysql, tvb, offset, -1, FALSE);
		  mysql_tree = proto_item_add_subtree(ti, ett_mysql);

		  proto_tree_add_item(mysql_tree, hf_mysql_packet_length, tvb,
			    offset, 3, TRUE);
	}
	offset += 3;
/* packet number */
	packet_number= tvb_get_guint8(tvb, offset);
	if (tree) {
		  proto_tree_add_uint(mysql_tree, hf_mysql_packet_number, tvb,
		    offset, 1, packet_number);
	}
	offset += 1;

	/* 	
	 *	packet == 0 && response --> server greeting
	 *	packet == 1 && request --> login request
	 */ 
	if(is_response ) {
		if( packet_number == 0 ) {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_str(pinfo->cinfo, COL_INFO, "Server Greeting" ) ; 
			}
			offset = mysql_dissect_server_greeting(tvb,pinfo,offset,mysql_tree);
		}else {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_str(pinfo->cinfo, COL_INFO, "Response" ) ; 
			}
			offset = mysql_dissect_response(tvb,pinfo,offset,mysql_tree);
		}
	} else {
		if( packet_number == 1 ) {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_str(pinfo->cinfo, COL_INFO, "Login Request") ; 
			}
			offset = mysql_dissect_authentication(tvb,pinfo,offset,mysql_tree);
		}else {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_str(pinfo->cinfo, COL_INFO, "Request") ; 
			}
			offset = mysql_dissect_request(tvb,pinfo,offset,mysql_tree);
		}
	}

/* payload */
	if (tree && tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree_add_item(mysql_tree, hf_mysql_payload,
		    tvb, offset, -1, FALSE);
	}
}
static int 
mysql_dissect_response(tvbuff_t *tvb, packet_info *pinfo,
	     	int offset, proto_tree *tree)
{
	gint response_code;
	gint error_code;

	/* response code */
	response_code= tvb_get_guint8(tvb, offset);
	if (tree) {
		proto_tree_add_uint(tree, hf_mysql_response_code, tvb,
		offset, 1, response_code);
	}
	offset +=1;
		
	if(response_code== 0xff ) {
			/* error code */
		error_code = tvb_get_letohs(tvb, offset);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error Code: %x", error_code ); 
		}
		if (tree) {
			proto_tree_add_uint(tree, hf_mysql_error_code, tvb,
			offset, 2, error_code);
		}
		offset +=2;
			
	} else {
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, " OK" ); 
		}
	}
	return offset;
}

static int
mysql_dissect_request(tvbuff_t *tvb,packet_info *pinfo,
	     	int offset, proto_tree *tree)
{
	gint opcode;
	gint strlen;
	proto_item *tf;
	proto_item *req_tree=NULL;

	if(tree) {
		tf=proto_tree_add_text(tree,tvb,offset,-1,"Command");
		req_tree = proto_item_add_subtree(tf ,ett_request);
	}

	opcode = tvb_get_guint8(tvb, offset);
	
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " Command: %s", 
			val_to_str(opcode, mysql_opcode_vals, "Unknown (%u)"));
	}

	if (req_tree) {
  		proto_tree_add_uint_format(req_tree, hf_mysql_opcode, tvb, 
				offset , 1, opcode, "Command: %s (%u)", 
				val_to_str(opcode, mysql_opcode_vals, "Unknown (%u)"),opcode);
	}
	/* command parameter */

	offset += 1;
	if ( (strlen = tvb_length_remaining(tvb,offset)) > 0 ) {
		
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " : %s",
					tvb_format_text(tvb,offset,strlen));
		}
		
		if (tree) {
			proto_tree_add_item(req_tree, hf_mysql_parameter, tvb,
				offset, strlen, FALSE );
		}
		offset +=strlen;
	}

	return offset;
}


static int
mysql_dissect_authentication(tvbuff_t *tvb, packet_info *pinfo,
		int offset, proto_tree *tree)
{
	gint16 	client_caps;
	gint32	max_packet;
	gint	strlen;

	proto_item *tf;
	proto_item *cap_tree;
	proto_item *login_tree=NULL;

	if(tree) {
		tf=proto_tree_add_text(tree,tvb,offset,-1,"Login Packet");
		login_tree = proto_item_add_subtree(tf ,ett_server_greeting);
	}

	client_caps= tvb_get_letohs(tvb, offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " Caps: 0x%x",client_caps) ; 
	}
	if(tree) {
  		tf = proto_tree_add_uint_format(login_tree, hf_mysql_caps, tvb, offset , 1, client_caps, "Caps: 0x%04x ", client_caps );
	  	cap_tree = proto_item_add_subtree(tf, ett_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_long_password, tvb, offset, 2, client_caps);
	  	proto_tree_add_boolean(cap_tree, hf_mysql_cap_found_rows, tvb, offset, 2, client_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_long_flag, tvb, offset, 2, client_caps);
	  	proto_tree_add_boolean(cap_tree, hf_mysql_cap_connect_with_db, tvb, offset, 2, client_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_no_schema, tvb, offset, 2, client_caps);
	  	proto_tree_add_boolean(cap_tree, hf_mysql_cap_compress, tvb, offset, 2, client_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_odbc, tvb, offset, 2, client_caps);
	  	proto_tree_add_boolean(cap_tree, hf_mysql_cap_local_files, tvb, offset, 2, client_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_ignore_space, tvb, offset, 2, client_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_change_user, tvb, offset, 2, client_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_interactive, tvb, offset, 2, client_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_ssl, tvb, offset, 2, client_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_ignore_sigpipe, tvb, offset, 2, client_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_transactions, tvb, offset, 2, client_caps);
	}

/*	proto_tree_add_uint(tree, hf_mysql_client_caps, tvb,
		offset, 2, client_caps);
*/
	offset +=2;
	/* 3 bytes max packet, 16777216 - x */
	max_packet = 0xffffff - tvb_get_letoh24(tvb, offset);
	if(tree) {
		proto_tree_add_uint(login_tree, hf_mysql_max_packet, tvb,
			offset, 3, max_packet);
	}
	offset +=3;
	/* User name */
	strlen = tvb_strsize(tvb,offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " ,user:  %s",
				tvb_get_ptr(tvb,offset,strlen));
	}
	if (tree) {
		proto_tree_add_item(login_tree, hf_mysql_user, tvb,
			offset, strlen, FALSE );
	}
	offset +=strlen;
	
	/* Password */
	strlen = tvb_length_remaining(tvb,offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " ,password:  %s",
				tvb_get_ptr(tvb,offset,strlen));
	}
	if (tree) {
		proto_tree_add_item(login_tree, hf_mysql_password, tvb,
			offset, strlen, FALSE );
	}
	offset +=strlen;
	
		
	return offset;
}


static int 
mysql_dissect_server_greeting(tvbuff_t *tvb, packet_info *pinfo,
		int offset, proto_tree *tree)
{
	gint protocol;
	gint strlen;
	gint32 thread_id;
	gint16 server_caps;
	gint charset;
	gint16 status;
	
	proto_item *tf;
	proto_item *greeting_tree=NULL;
	proto_item *cap_tree;

	protocol= tvb_get_guint8(tvb, offset);

	if(tree) {
		tf = proto_tree_add_text(tree,tvb,offset,-1,"Server Greeting");
		greeting_tree = proto_item_add_subtree(tf ,ett_server_greeting);
	}
	
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " Protocol : %d",protocol) ; 
	}
	if (tree) {
		proto_tree_add_uint(greeting_tree, hf_mysql_protocol, tvb,
			offset, 1, protocol);
	}
	offset +=1;
	/* version string */

	strlen = tvb_strsize(tvb,offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " ,version:  %s",
				tvb_get_ptr(tvb,offset,strlen));
	}
	if (tree) {
		proto_tree_add_item(greeting_tree, hf_mysql_version, tvb,
			offset, strlen, FALSE );
	}
	offset +=strlen;
		
	/* 4 bytes little endian thread_id */
	thread_id = tvb_get_letohl(tvb, offset);
	if(tree) {
		proto_tree_add_uint(greeting_tree, hf_mysql_thread_id, tvb,
			offset, 4, thread_id);
	}
	offset +=4;
	/* salt string */
	strlen = tvb_strsize(tvb,offset);
	if (tree) {
		proto_tree_add_item(greeting_tree, hf_mysql_salt, tvb,
			offset, strlen, FALSE );
	}
	offset +=strlen;
	/* 2 bytes CAPS */
	server_caps= tvb_get_letohs(tvb, offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " Caps: 0x%x",server_caps) ; 
	}
	if(tree) {
  		tf = proto_tree_add_uint_format(greeting_tree, hf_mysql_caps, tvb, offset , 1, server_caps, "Caps: 0x%04x ", server_caps );
	  	cap_tree = proto_item_add_subtree(tf, ett_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_long_password, tvb, offset, 2, server_caps);
	  	proto_tree_add_boolean(cap_tree, hf_mysql_cap_found_rows, tvb, offset, 2, server_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_long_flag, tvb, offset, 2, server_caps);
	  	proto_tree_add_boolean(cap_tree, hf_mysql_cap_connect_with_db, tvb, offset, 2, server_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_no_schema, tvb, offset, 2, server_caps);
	  	proto_tree_add_boolean(cap_tree, hf_mysql_cap_compress, tvb, offset, 2, server_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_odbc, tvb, offset, 2, server_caps);
	  	proto_tree_add_boolean(cap_tree, hf_mysql_cap_local_files, tvb, offset, 2, server_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_ignore_space, tvb, offset, 2, server_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_change_user, tvb, offset, 2, server_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_interactive, tvb, offset, 2, server_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_ssl, tvb, offset, 2, server_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_ignore_sigpipe, tvb, offset, 2, server_caps);
  		proto_tree_add_boolean(cap_tree, hf_mysql_cap_transactions, tvb, offset, 2, server_caps);
	}
	offset+=2;
	/* 1 byte charset */
	charset = tvb_get_guint8(tvb, offset);
	if (tree) {
		proto_tree_add_uint_format(greeting_tree, hf_mysql_charset, tvb,
			offset, 1, charset, "Charset: %s (%u)", 
			val_to_str(charset, mysql_charset_vals, "Unknown (%u)"), charset);
	}
	offset +=1;
	/* 2 byte status */
	status = tvb_get_letohs(tvb, offset);
	if (tree) {
		proto_tree_add_uint_format(greeting_tree, hf_mysql_status, tvb,
			offset, 2, status, "Status: %s (%u)",
			val_to_str(status, mysql_status_vals, "Unknown (%u)"), status); 
	}
	offset +=2;
	/* other unused */
	strlen = tvb_length_remaining(tvb,offset);

	if (tree) {
		proto_tree_add_item(greeting_tree, hf_mysql_unused, tvb,
			offset, strlen, FALSE );
	}
	offset +=strlen;
	
	return offset;
}

void
proto_register_mysql(void)
{
  static hf_register_info hf[] = {
    { &hf_mysql_packet_length,
      { "Packet Length",	      "mysql.packet_length",
	FT_UINT24, BASE_DEC, NULL,  0x0,
    	"MySQL packet length", HFILL }},

    { &hf_mysql_packet_number,
      { "Packet Number",	  "mysql.packet_number",
	FT_UINT8, BASE_DEC, NULL, 0x0,
    	"MySQL Packet Number", HFILL }},

    { &hf_mysql_opcode,
      { "Command",	  "mysql.opcode",
	FT_UINT8, BASE_DEC, NULL, 0x0,
    	"MySQL OPCODE", HFILL }},

    { &hf_mysql_response_code,
      { "Response Code",	  "mysql.response_code",
	FT_UINT8, BASE_DEC, NULL, 0x0,
    	"MySQL Respone Code", HFILL }},

    { &hf_mysql_error_code,
      { "Error Code",	  "mysql.error_code",
	FT_UINT16, BASE_DEC, NULL, 0x0,
    	"MySQL Error CODE", HFILL }},

    { &hf_mysql_protocol,
      { "Protocol",	  "mysql.protocol",
	FT_UINT8, BASE_DEC, NULL, 0x0,
    	"MySQL Protocol", HFILL }},

    { &hf_mysql_version,
      { "Version",   "mysql.version",
	FT_STRINGZ, BASE_DEC, NULL, 0x0,
    	"MySQL Version", HFILL }},

    { &hf_mysql_caps,
      { "Caps",	  "mysql.caps",
	FT_UINT16, BASE_DEC, NULL, 0x0,
    	"MySQL Capabilities", HFILL }},

     { &hf_mysql_cap_long_password,
	{ "Long Password","mysql.caps.lp", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_LP,
		"", HFILL }},
		
     { &hf_mysql_cap_found_rows,
	{ "Found Rows","mysql.caps.fr", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_FR,
		"", HFILL }},

		
     { &hf_mysql_cap_long_flag,
	{ "Long Flag","mysql.caps.lf", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_LF,
		"", HFILL }},
		
     { &hf_mysql_cap_connect_with_db,
	{ "Connect With Database","mysql.caps.cd", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_CD,
		"", HFILL }},

		
     { &hf_mysql_cap_no_schema,
	{ "Dont Allow database.table.column","mysql.caps.ns", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_NS,
		"", HFILL }},

     { &hf_mysql_cap_compress,
	{ "Can use compression protocol","mysql.caps.CP", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_CP,
		"", HFILL }},
		
     { &hf_mysql_cap_odbc,
	{ "ODBC Client","mysql.caps.ob", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_OB,
		"", HFILL }},

		
     { &hf_mysql_cap_local_files,
	{ "Can Use LOAD DATA LOCAL","mysql.caps.li", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_LI,
		"", HFILL }},
		
     { &hf_mysql_cap_ignore_space,
	{ "Ignore Spaces before (","mysql.caps.is", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_IS,
		"", HFILL }},

		
     { &hf_mysql_cap_change_user,
	{ "Support the mysql_change_user()","mysql.caps.cu", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_CU,
		"", HFILL }},

		
     { &hf_mysql_cap_interactive,
	{ "an Interactive Client","mysql.caps.ia", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_IA,
		"", HFILL }},

		
     { &hf_mysql_cap_ssl,
	{ "Switch to SSL after handshake","mysql.caps.sl", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_SL,
		"", HFILL }},

     { &hf_mysql_cap_ignore_sigpipe,
	{ "Ignore sigpipes","mysql.caps.ii", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_II,
		"", HFILL }},
		
     { &hf_mysql_cap_transactions,
	{ "Client knows about transactions","mysql.caps.ta", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_TA,
		"", HFILL }},

    { &hf_mysql_max_packet,
      { "MAX Packet",	      "mysql.max_packet",
	FT_UINT24, BASE_DEC, NULL,  0x0,
    	"MySQL Max packet", HFILL }},
		
    { &hf_mysql_user,
      { "Username",	      "mysql.user",
	FT_STRINGZ, BASE_DEC, NULL, 0x0,
    	"Login Username", HFILL }}, 

    { &hf_mysql_password,
      { "Password",	      "mysql.password",
	FT_STRING, BASE_DEC, NULL, 0x0,
    	"Login Password", HFILL }}, 

    { &hf_mysql_salt,
      { "Salt",	      "mysql.salt",
	FT_STRINGZ, BASE_DEC, NULL, 0x0,
    	"Salt", HFILL }}, 

    { &hf_mysql_thread_id,
      { "Thread ID",	      "mysql.thread_id",
	FT_UINT32, BASE_DEC, NULL,  0x0,
    	"MySQL Thread ID", HFILL }},
	
    { &hf_mysql_charset,
      { "Charset",	      "mysql.charset",
	FT_UINT8, BASE_DEC, NULL,  0x0,
    	"MySQL Charset", HFILL }},
	
    { &hf_mysql_status,
      { "Status",	      "mysql.status",
	FT_UINT16, BASE_DEC, NULL,  0x0,
    	"MySQL Status", HFILL }},

    { &hf_mysql_unused,
      { "Unused",	      "mysql.unused",
	FT_STRING, BASE_DEC, NULL, 0x0,
    	"Unused", HFILL }},

    { &hf_mysql_parameter,
      { "Parameter",	      "mysql.parameter",
	FT_STRING, BASE_DEC, NULL, 0x0,
    	"Parameter", HFILL }},
    { &hf_mysql_payload,
      { "Payload",	      "mysql.payload",
	FT_STRING, BASE_DEC, NULL, 0x0,
    	"MySQL Payload", HFILL }},
#if 0
    { &hf_mysql_destination_file,
      { "DESTINATION File",   "mysql.destination_file",
	FT_STRINGZ, BASE_DEC, NULL, 0x0,
    	"MySQL source file name", HFILL }},

    { &hf_mysql_blocknum,
      { "Block",              "mysql.block",
	FT_UINT16, BASE_DEC, NULL, 0x0,
    	"Block number", HFILL }},

    { &hf_mysql_error_code,
      { "Error code",         "mysql.error.code",
	FT_UINT16, BASE_DEC, VALS(mysql_error_code_vals), 0x0,
    	"Error code in case of MySQL error message", HFILL }},

    { &hf_mysql_error_string,
      { "Error message",      "mysql.error.message",
	FT_STRINGZ, BASE_DEC, NULL, 0x0,
    	"Error string in case of MySQL error message", HFILL }},
#endif
	};
	static gint *ett[] = {
  		&ett_mysql,
		&ett_server_greeting,
		&ett_caps,
		&ett_request,
	};
	module_t *mysql_module;

	proto_mysql = proto_register_protocol("MySQL Protocol",
				       "MySQL", "mysql");
	proto_register_field_array(proto_mysql, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	mysql_module = prefs_register_protocol(proto_mysql, NULL);
	prefs_register_bool_preference(mysql_module, "desegment_buffers",
		"Reassemble MySQL buffers spanning multiple TCP segments",
		"Whether the MySQL dissector should reassemble MySQL buffers spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&mysql_desegment);
}

void
proto_reg_handoff_mysql(void)
{
	dissector_handle_t mysql_handle;

	mysql_handle = create_dissector_handle(dissect_mysql, proto_mysql);
  
	dissector_add("tcp.port", TCP_PORT_MySQL, mysql_handle);
}
