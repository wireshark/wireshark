/* packet-mysql.c
 * Routines for mysql packet dissection
 *
 * Huagang XIE <huagang@intruvert.com>
 *
 * MySQL 4.1+ protocol by Axel Schwenke <axel@mysql.com>
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
 *  http://public.logicacmg.com/~redferni/mysql/MySQL-Protocol.html
 * and MySQL source code
 */

/* create extra output for conversation tracking */
/* #define CTDEBUG 1 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#include <epan/dissectors/packet-tcp.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>

/* Define version if we are not building ethereal statically */
#ifndef ENABLE_STATIC
#include <gmodule.h>
G_MODULE_EXPORT const gchar version[] = "0.1";
#endif


/* port for protocol registration */
#define TCP_PORT_MySQL   3306

/* client/server capabilities */
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
#define MYSQL_CAPS_RS 0x4000
#define MYSQL_CAPS_SC 0x8000

/* extended capabilities: 4.1+ client only */
#define MYSQL_CAPS_MS 0x0001
#define MYSQL_CAPS_MR 0x0002

/* status bitfield */
#define MYSQL_STAT_IT 0x0001
#define MYSQL_STAT_AC 0x0002
#define MYSQL_STAT_MR 0x0004
#define MYSQL_STAT_MU 0x0008
#define MYSQL_STAT_BI 0x0010
#define MYSQL_STAT_NI 0x0020
#define MYSQL_STAT_CR 0x0040
#define MYSQL_STAT_LR 0x0080
#define MYSQL_STAT_DR 0x0100
#define MYSQL_STAT_BS 0x0200

/* bitfield for MYSQL_REFRESH */
#define MYSQL_RFSH_GRANT   1   /* Refresh grant tables */
#define MYSQL_RFSH_LOG     2   /* Start on new log file */
#define MYSQL_RFSH_TABLES  4   /* close all tables */
#define MYSQL_RFSH_HOSTS   8   /* Flush host cache */
#define MYSQL_RFSH_STATUS  16  /* Flush status variables */
#define MYSQL_RFSH_THREADS 32  /* Flush thread cache */
#define MYSQL_RFSH_SLAVE   64  /* Reset master info and restart slave thread */
#define MYSQL_RFSH_MASTER  128 /* Remove all bin logs in the index and truncate the index */

/* MySQL operation codes */
#define MYSQL_SLEEP               0  /* not from client */
#define MYSQL_QUIT                1
#define MYSQL_INIT_DB             2
#define MYSQL_QUERY               3
#define MYSQL_FIELD_LIST          4
#define MYSQL_CREATE_DB           5
#define MYSQL_DROP_DB             6
#define MYSQL_REFRESH             7
#define MYSQL_SHUTDOWN            8
#define MYSQL_STATISTICS          9
#define MYSQL_PROCESS_INFO        10
#define MYSQL_CONNECT             11 /* not from client */
#define MYSQL_PROCESS_KILL        12
#define MYSQL_DEBUG               13
#define MYSQL_PING                14
#define MYSQL_TIME                15 /* not from client */
#define MYSQL_DELAY_INSERT        16 /* not from client */
#define MYSQL_CHANGE_USER         17
#define MYSQL_BINLOG_DUMP         18 /* replication */
#define MYSQL_TABLE_DUMP          19 /* replication */
#define MYSQL_CONNECT_OUT         20 /* replication */
#define MYSQL_REGISTER_SLAVE      21 /* replication */
#define MYSQL_STMT_PREPARE        22
#define MYSQL_STMT_EXECUTE        23
#define MYSQL_STMT_SEND_LONG_DATA 24
#define MYSQL_STMT_CLOSE          25
#define MYSQL_STMT_RESET          26
#define MYSQL_SET_OPTION          27
#define MYSQL_STMT_FETCH          28


/* decoding table: opcodes */
static const value_string mysql_opcode_vals[] = {
	{MYSQL_SLEEP,   "SLEEP"},
	{MYSQL_QUIT,   "Quit"},
	{MYSQL_INIT_DB,  "Use Database"},
	{MYSQL_QUERY,   "Query"},
	{MYSQL_FIELD_LIST, "Show Fields"},
	{MYSQL_CREATE_DB,  "Create Database"},
	{MYSQL_DROP_DB , "Drop Database"},
	{MYSQL_REFRESH , "Refresh"},
	{MYSQL_SHUTDOWN , "Shutdown"},
	{MYSQL_STATISTICS , "Statistics"},
	{MYSQL_PROCESS_INFO , "Process List"},
	{MYSQL_CONNECT , "Connect"},
	{MYSQL_PROCESS_KILL , "Kill Server Thread"},
	{MYSQL_DEBUG , "Dump Debuginfo"},
	{MYSQL_PING , "Ping"},
	{MYSQL_TIME , "Time"},
	{MYSQL_DELAY_INSERT , "Insert Delayed"},
	{MYSQL_CHANGE_USER , "Change User"},
	{MYSQL_BINLOG_DUMP , "Send Binlog"},
	{MYSQL_TABLE_DUMP, "Send Table"},
	{MYSQL_CONNECT_OUT, "Slave Connect"},
	{MYSQL_REGISTER_SLAVE, "Register Slave"},
	{MYSQL_STMT_PREPARE, "Prepare Statement"},
	{MYSQL_STMT_EXECUTE, "Execute Statement"},
	{MYSQL_STMT_SEND_LONG_DATA, "Send BLOB"},
	{MYSQL_STMT_CLOSE, "Close Statement"},
	{MYSQL_STMT_RESET, "Reset Statement"},
	{MYSQL_SET_OPTION, "Set Option"},
	{MYSQL_STMT_FETCH, "Fetch Data"},
	{0, NULL}
};


/* charset: pre-4.1 used ther term 'charset', later changed to 'collation' */
static const value_string mysql_charset_vals[] = {
	{1,  "big5"},
	{2,  "czech"},
	{3,  "dec8"},
	{4,  "dos" },
	{5,  "german1"},
	{6,  "hp8"},
	{7,  "koi8_ru"},
	{8,  "latin1"},
	{9,  "latin2"},
	{9,  "swe7 "},
	{10, "usa7"},
	{11, "ujis"},
	{12, "sjis"},
	{13, "cp1251"},
	{14, "danish"},
	{15, "hebrew"},
	{16, "win1251"},
	{17, "tis620"},
	{18, "euc_kr"},
	{19, "estonia"},
	{20, "hungarian"},
	{21, "koi8_ukr"},
	{22, "win1251ukr"},
	{23, "gb2312"},
	{24, "greek"},
	{25, "win1250"},
	{26, "croat"},
	{27, "gbk"},
	{28, "cp1257"},
	{29, "latin5"},
	{0, NULL}
};


/* collation codes may change over time, recreate with the following SQL

SELECT CONCAT('  {', ID, ',"', CHARACTER_SET_NAME,
              ' COLLATE ', COLLATION_NAME, '"},')
FROM INFORMATION_SCHEMA.COLLATIONS
ORDER BY ID
INTO OUTFILE '/tmp/mysql-collations';

*/
static const value_string mysql_collation_vals[] = {
	{3,   "dec8 COLLATE dec8_swedish_ci"},
	{4,   "cp850 COLLATE cp850_general_ci"},
	{5,   "latin1 COLLATE latin1_german1_ci"},
	{6,   "hp8 COLLATE hp8_english_ci"},
	{7,   "koi8r COLLATE koi8r_general_ci"},
	{8,   "latin1 COLLATE latin1_swedish_ci"},
	{9,   "latin2 COLLATE latin2_general_ci"},
	{10,  "swe7 COLLATE swe7_swedish_ci"},
	{11,  "ascii COLLATE ascii_general_ci"},
	{14,  "cp1251 COLLATE cp1251_bulgarian_ci"},
	{15,  "latin1 COLLATE latin1_danish_ci"},
	{16,  "hebrew COLLATE hebrew_general_ci"},
	{20,  "latin7 COLLATE latin7_estonian_cs"},
	{21,  "latin2 COLLATE latin2_hungarian_ci"},
	{22,  "koi8u COLLATE koi8u_general_ci"},
	{23,  "cp1251 COLLATE cp1251_ukrainian_ci"},
	{25,  "greek COLLATE greek_general_ci"},
	{26,  "cp1250 COLLATE cp1250_general_ci"},
	{27,  "latin2 COLLATE latin2_croatian_ci"},
	{29,  "cp1257 COLLATE cp1257_lithuanian_ci"},
	{30,  "latin5 COLLATE latin5_turkish_ci"},
	{31,  "latin1 COLLATE latin1_german2_ci"},
	{32,  "armscii8 COLLATE armscii8_general_ci"},
	{33,  "utf8 COLLATE utf8_general_ci"},
	{36,  "cp866 COLLATE cp866_general_ci"},
	{37,  "keybcs2 COLLATE keybcs2_general_ci"},
	{38,  "macce COLLATE macce_general_ci"},
	{39,  "macroman COLLATE macroman_general_ci"},
	{40,  "cp852 COLLATE cp852_general_ci"},
	{41,  "latin7 COLLATE latin7_general_ci"},
	{42,  "latin7 COLLATE latin7_general_cs"},
	{43,  "macce COLLATE macce_bin"},
	{44,  "cp1250 COLLATE cp1250_croatian_ci"},
	{47,  "latin1 COLLATE latin1_bin"},
	{48,  "latin1 COLLATE latin1_general_ci"},
	{49,  "latin1 COLLATE latin1_general_cs"},
	{50,  "cp1251 COLLATE cp1251_bin"},
	{51,  "cp1251 COLLATE cp1251_general_ci"},
	{52,  "cp1251 COLLATE cp1251_general_cs"},
	{53,  "macroman COLLATE macroman_bin"},
	{57,  "cp1256 COLLATE cp1256_general_ci"},
	{58,  "cp1257 COLLATE cp1257_bin"},
	{59,  "cp1257 COLLATE cp1257_general_ci"},
	{63,  "binary COLLATE binary"},
	{64,  "armscii8 COLLATE armscii8_bin"},
	{65,  "ascii COLLATE ascii_bin"},
	{66,  "cp1250 COLLATE cp1250_bin"},
	{67,  "cp1256 COLLATE cp1256_bin"},
	{68,  "cp866 COLLATE cp866_bin"},
	{69,  "dec8 COLLATE dec8_bin"},
	{70,  "greek COLLATE greek_bin"},
	{71,  "hebrew COLLATE hebrew_bin"},
	{72,  "hp8 COLLATE hp8_bin"},
	{73,  "keybcs2 COLLATE keybcs2_bin"},
	{74,  "koi8r COLLATE koi8r_bin"},
	{75,  "koi8u COLLATE koi8u_bin"},
	{77,  "latin2 COLLATE latin2_bin"},
	{78,  "latin5 COLLATE latin5_bin"},
	{79,  "latin7 COLLATE latin7_bin"},
	{80,  "cp850 COLLATE cp850_bin"},
	{81,  "cp852 COLLATE cp852_bin"},
	{82,  "swe7 COLLATE swe7_bin"},
	{83,  "utf8 COLLATE utf8_bin"},
	{92,  "geostd8 COLLATE geostd8_general_ci"},
	{93,  "geostd8 COLLATE geostd8_bin"},
	{94,  "latin1 COLLATE latin1_spanish_ci"},
	{99,  "cp1250 COLLATE cp1250_polish_ci"},
	{192, "utf8 COLLATE utf8_unicode_ci"},
	{193, "utf8 COLLATE utf8_icelandic_ci"},
	{194, "utf8 COLLATE utf8_latvian_ci"},
	{195, "utf8 COLLATE utf8_romanian_ci"},
	{196, "utf8 COLLATE utf8_slovenian_ci"},
	{197, "utf8 COLLATE utf8_polish_ci"},
	{198, "utf8 COLLATE utf8_estonian_ci"},
	{199, "utf8 COLLATE utf8_spanish_ci"},
	{200, "utf8 COLLATE utf8_swedish_ci"},
	{201, "utf8 COLLATE utf8_turkish_ci"},
	{202, "utf8 COLLATE utf8_czech_ci"},
	{203, "utf8 COLLATE utf8_danish_ci"},
	{204, "utf8 COLLATE utf8_lithuanian_ci"},
	{205, "utf8 COLLATE utf8_slovak_ci"},
	{206, "utf8 COLLATE utf8_spanish2_ci"},
	{207, "utf8 COLLATE utf8_roman_ci"},
	{208, "utf8 COLLATE utf8_persian_ci"},
	{209, "utf8 COLLATE utf8_esperanto_ci"},
	{210, "utf8 COLLATE utf8_hungarian_ci"},
	{0, NULL}
};


/* allowed MYSQL_SHUTDOWN levels */
static const value_string mysql_shutdown_vals[] = {
	{0,   "default"},
	{1,   "wait for connections to finish"},
	{2,   "wait for transactions to finish"},
	{8,   "wait for updates to finish"},
	{16,  "wait flush all buffers"},
	{17,  "wait flush critical buffers"},
	{254, "kill running queries"},
	{255, "kill connections"},
	{0, NULL}
};


/* allowed MYSQL_SET_OPTION values */
static const value_string mysql_option_vals[] = {
	{0, "multi statements on"},
	{1, "multi statements off"},
	{0, NULL}
};



/* protocol id */
static int proto_mysql = -1;

/* dissector configuration */
static gboolean mysql_desegment = TRUE;

/* expand-the-tree flags */
static gint ett_mysql = -1;
static gint ett_server_greeting = -1;
static gint ett_caps = -1;
static gint ett_extcaps = -1;
static gint ett_stat = -1;
static gint ett_request = -1;
static gint ett_refresh = -1;

/* protocol fields */
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
static int hf_mysql_cap_reserved= -1;
static int hf_mysql_cap_secure_connect= -1;
static int hf_mysql_extcaps= -1;
static int hf_mysql_cap_multi_statements= -1;
static int hf_mysql_cap_multi_results= -1;
static int hf_mysql_status= -1;
static int hf_mysql_stat_it= -1;
static int hf_mysql_stat_ac= -1;
static int hf_mysql_stat_mr= -1;
static int hf_mysql_stat_mu= -1;
static int hf_mysql_stat_bi= -1;
static int hf_mysql_stat_ni= -1;
static int hf_mysql_stat_cr= -1;
static int hf_mysql_stat_lr= -1;
static int hf_mysql_stat_dr= -1;
static int hf_mysql_stat_bs= -1;
static int hf_mysql_refresh= -1;
static int hf_mysql_rfsh_grants= -1;
static int hf_mysql_rfsh_log= -1;
static int hf_mysql_rfsh_tables= -1;
static int hf_mysql_rfsh_hosts= -1;
static int hf_mysql_rfsh_status= -1;
static int hf_mysql_rfsh_threads= -1;
static int hf_mysql_rfsh_slave= -1;
static int hf_mysql_rfsh_master= -1;
static int hf_mysql_packet_length= -1;
static int hf_mysql_packet_number= -1;
static int hf_mysql_opcode= -1;
static int hf_mysql_response_code= -1;
static int hf_mysql_error_code= -1;
static int hf_mysql_error_string= -1;
static int hf_mysql_sqlstate= -1;
static int hf_mysql_message= -1;
static int hf_mysql_payload= -1;
static int hf_mysql_protocol= -1;
static int hf_mysql_version = -1;
static int hf_mysql_max_packet= -1;
static int hf_mysql_user= -1;
static int hf_mysql_schema= -1;
static int hf_mysql_thread_id = -1;
static int hf_mysql_salt= -1;
static int hf_mysql_salt2= -1;
static int hf_mysql_charset= -1;
static int hf_mysql_passwd= -1;
static int hf_mysql_unused= -1;
static int hf_mysql_parameter= -1;
static int hf_mysql_affected_rows= -1;
static int hf_mysql_insert_id= -1;
static int hf_mysql_num_warn= -1;
static int hf_mysql_thd_id= -1;
static int hf_mysql_stmt_id= -1;
static int hf_mysql_query= -1;
static int hf_mysql_option= -1;
static int hf_mysql_num_rows= -1;
static int hf_mysql_param= -1;
static int hf_mysql_exec_flags= -1;
static int hf_mysql_exec_iter= -1;
static int hf_mysql_eof= -1;
static int hf_mysql_num_fields= -1;
static int hf_mysql_extra= -1;

typedef enum my_proto_state
{
	UNDEFINED,
	LOGIN,
	REQUEST,
	RESPONSE_OK,
	RESPONSE_MESSAGE,
	RESPONSE_TABULAR,
	FIELD_PACKET,
	ROW_PACKET,
	RESPONSE_PREPARE,
	PARAM_PACKET
} my_proto_state_t;

#ifdef CTDEBUG
static const value_string state_vals[] = {
	{UNDEFINED,        "undefined"},
	{LOGIN,            "login"},
	{REQUEST,          "request"},
	{RESPONSE_OK,      "response OK"},
	{RESPONSE_MESSAGE, "response message"},
	{RESPONSE_TABULAR, "tabular response"},
	{FIELD_PACKET,     "field packet"},
	{ROW_PACKET,       "row packet"},
	{RESPONSE_PREPARE, "response to PREPARE"},
	{PARAM_PACKET,     "parameter packet"},
	{0, NULL}
};
#endif

typedef struct my_conn_data
{
	guint16 srv_caps;
	guint16 clnt_caps;
	guint16 clnt_caps_ext;
	my_proto_state_t state;
	GHashTable* stmts;
#ifdef CTDEBUG
	guint32 generation;
#endif
} my_conn_data_t;


typedef struct my_stmt_data
{
	guint16 nparam;
} my_stmt_data_t;


/* function prototypes */
void proto_reg_handoff_mysql(void);
void proto_register_mysql(void);
static void dissect_mysql(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static guint get_mysql_pdu_len(tvbuff_t *tvb, int offset);
static void dissect_mysql_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int mysql_dissect_login(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, my_conn_data_t *conn_data);
static int mysql_dissect_greeting(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, my_conn_data_t *conn_data);
static int mysql_dissect_request(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, my_conn_data_t *conn_data);
static int mysql_dissect_response(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, my_conn_data_t *conn_data);
static int mysql_dissect_error_packet(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static int mysql_dissect_ok_packet(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, my_conn_data_t *conn_data);
static int mysql_dissect_server_status(tvbuff_t *tvb, int offset, proto_tree *tree);
static int mysql_dissect_collation(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 caps);
static int mysql_dissect_caps(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 *caps, const char* whom);
static int mysql_dissect_ext_caps(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 *caps, const char* whom);
static int mysql_dissect_result_header(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, my_conn_data_t *conn_data);
static int mysql_dissect_field_packet(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, my_conn_data_t *conn_data);
static int mysql_dissect_row_packet(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, my_conn_data_t *conn_data);
static int mysql_dissect_response_prepare(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, my_conn_data_t *conn_data);
static int mysql_dissect_param_packet(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, my_conn_data_t *conn_data);
static gint my_tvb_strsize(tvbuff_t *tvb, int offset);
static int tvb_get_fle(tvbuff_t *tvb, int offset, guint64 *res, guint8 *is_null);



/* plugin registration (if compiled as plugin) */
#ifndef ENABLE_STATIC
G_MODULE_EXPORT void plugin_register(void)
{
	if (proto_mysql == -1) { /* only once */
		proto_register_mysql();
	}
}

G_MODULE_EXPORT void plugin_reg_handoff(void){
	proto_reg_handoff_mysql();
}
#endif


/* dissector registration */
void proto_reg_handoff_mysql(void)
{
	dissector_handle_t mysql_handle;
	mysql_handle = create_dissector_handle(dissect_mysql, proto_mysql);
	dissector_add("tcp.port", TCP_PORT_MySQL, mysql_handle);
}


/* protocol registration */
void proto_register_mysql(void)
{
	static hf_register_info hf[]=
	{
		{ &hf_mysql_packet_length,
		{ "Packet Length", "mysql.packet_length",
		FT_UINT24, BASE_DEC, NULL,  0x0,
		"Packet Length", HFILL }},

		{ &hf_mysql_packet_number,
		{ "Packet Number", "mysql.packet_number",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Packet Number", HFILL }},

		{ &hf_mysql_opcode,
		{ "Command", "mysql.opcode",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Command", HFILL }},

		{ &hf_mysql_response_code,
		{ "Response Code", "mysql.response_code",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Response Code", HFILL }},

		{ &hf_mysql_error_code,
		{ "Error Code", "mysql.error_code",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Error Code", HFILL }},

		{ &hf_mysql_error_string,
		{ "Error message", "mysql.error.message",
		FT_STRING, BASE_DEC, NULL, 0x0,
		"Error string in case of MySQL error message", HFILL }},

		{ &hf_mysql_sqlstate,
		{ "SQL state", "mysql.sqlstate",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"", HFILL }},

		{ &hf_mysql_message,
		{ "Message", "mysql.message",
		FT_STRINGZ, BASE_DEC, NULL, 0x0,
		"Message", HFILL }},

		{ &hf_mysql_protocol,
		{ "Protocol", "mysql.protocol",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Protocol Version", HFILL }},

		{ &hf_mysql_version,
		{ "Version", "mysql.version",
		FT_STRINGZ, BASE_DEC, NULL, 0x0,
		"MySQL Version", HFILL }},

		{ &hf_mysql_caps,
		{ "Caps", "mysql.caps",
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
		{ "Long Column Flags","mysql.caps.lf",
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
		{ "Can use compression protocol","mysql.caps.cp",
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
		{ "Ignore Spaces before '('","mysql.caps.is",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_IS,
		"", HFILL }},

		{ &hf_mysql_cap_change_user,
		{ "Speaks 4.1 protocol (new flag)","mysql.caps.cu",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_CU,
		"", HFILL }},

		{ &hf_mysql_cap_interactive,
		{ "Interactive Client","mysql.caps.ia",
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
		{ "Knows about transactions","mysql.caps.ta",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_TA,
		"", HFILL }},

		{ &hf_mysql_cap_reserved,
		{ "Speaks 4.1 protocol (old flag)","mysql.caps.rs",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_RS,
		"", HFILL }},

		{ &hf_mysql_cap_secure_connect,
		{ "Can do 4.1 authentication","mysql.caps.sc",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_SC,
		"", HFILL }},

		{ &hf_mysql_extcaps,
		{ "Ext. Caps", "mysql.extcaps",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"MySQL Extended Capabilities", HFILL }},

		{ &hf_mysql_cap_multi_statements,
		{ "Supports multiple statements","mysql.caps.ms",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_MS,
		"", HFILL }},

		{ &hf_mysql_cap_multi_results,
		{ "Supports multiple results","mysql.caps.mr",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_CAPS_MR,
		"", HFILL }},

		{ &hf_mysql_max_packet,
		{ "MAX Packet", "mysql.max_packet",
		FT_UINT24, BASE_DEC, NULL,  0x0,
		"MySQL Max packet", HFILL }},

		{ &hf_mysql_user,
		{ "Username", "mysql.user",
		FT_STRINGZ, BASE_DEC, NULL, 0x0,
		"Login Username", HFILL }},

		{ &hf_mysql_schema,
		{ "Schema", "mysql.schema",
		FT_STRING, BASE_DEC, NULL, 0x0,
		"Login Schema", HFILL }},

		{ &hf_mysql_salt,
		{ "Salt", "mysql.salt",
		FT_STRINGZ, BASE_DEC, NULL, 0x0,
		"Salt", HFILL }},

		{ &hf_mysql_salt2,
		{ "Salt", "mysql.salt2",
		FT_STRINGZ, BASE_DEC, NULL, 0x0,
		"Salt", HFILL }},

		{ &hf_mysql_thread_id,
		{ "Thread ID", "mysql.thread_id",
		FT_UINT32, BASE_DEC, NULL,  0x0,
		"MySQL Thread ID", HFILL }},

		{ &hf_mysql_charset,
		{ "Charset", "mysql.charset",
		FT_UINT8, BASE_DEC, NULL,  0x0,
		"MySQL Charset", HFILL }},

		{ &hf_mysql_status,
		{ "Status", "mysql.status",
		FT_UINT16, BASE_DEC, NULL,  0x0,
		"MySQL Status", HFILL }},

		{ &hf_mysql_stat_it,
		{ "In transaction", "mysql.stat.it",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_STAT_IT,
		"", HFILL }},

		{ &hf_mysql_stat_ac,
		{ "AUTO_COMMIT", "mysql.stat.ac",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_STAT_AC,
		"", HFILL }},

		{ &hf_mysql_stat_mr,
		{ "More results", "mysql.stat.mr",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_STAT_MR,
		"", HFILL }},

		{ &hf_mysql_stat_mu,
		{ "Multi query - more resultsets", "mysql.stat.mu",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_STAT_MU,
		"", HFILL }},

		{ &hf_mysql_stat_bi,
		{ "Bad index used", "mysql.stat.bi",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_STAT_BI,
		"", HFILL }},

		{ &hf_mysql_stat_ni,
		{ "No index used", "mysql.stat.ni",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_STAT_NI,
		"", HFILL }},

		{ &hf_mysql_stat_cr,
		{ "Cursor exists", "mysql.stat.cr",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_STAT_CR,
		"", HFILL }},

		{ &hf_mysql_stat_lr,
		{ "Last row sebd", "mysql.stat.lr",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_STAT_LR,
		"", HFILL }},

		{ &hf_mysql_stat_dr,
		{ "database dropped", "mysql.stat.dr",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_STAT_DR,
		"", HFILL }},

		{ &hf_mysql_stat_bs,
		{ "No backslash escapes", "mysql.stat.bs",
		FT_BOOLEAN, 16, TFS(&flags_set_truth), MYSQL_STAT_BS,
		"", HFILL }},

		{ &hf_mysql_refresh,
		{ "Refresh Option", "mysql.refresh",
		FT_UINT8, BASE_DEC, NULL,  0x0,
		"Refresh Option", HFILL }},

		{ &hf_mysql_rfsh_grants,
		{ "reload permissions", "mysql.rfsh.grants",
		FT_BOOLEAN, 8, TFS(&flags_set_truth), MYSQL_RFSH_GRANT,
		"", HFILL }},

		{ &hf_mysql_rfsh_log,
		{ "flush logfiles", "mysql.rfsh.log",
		FT_BOOLEAN, 8, TFS(&flags_set_truth), MYSQL_RFSH_LOG,
		"", HFILL }},

		{ &hf_mysql_rfsh_tables,
		{ "flush tables", "mysql.rfsh.tables",
		FT_BOOLEAN, 8, TFS(&flags_set_truth), MYSQL_RFSH_TABLES,
		"", HFILL }},

		{ &hf_mysql_rfsh_hosts,
		{ "flush hosts", "mysql.rfsh.hosts",
		FT_BOOLEAN, 8, TFS(&flags_set_truth), MYSQL_RFSH_HOSTS,
		"", HFILL }},

		{ &hf_mysql_rfsh_status,
		{ "reset statistics", "mysql.rfsh.status",
		FT_BOOLEAN, 8, TFS(&flags_set_truth), MYSQL_RFSH_STATUS,
		"", HFILL }},

		{ &hf_mysql_rfsh_threads,
		{ "empty thread cache", "mysql.rfsh.threads",
		FT_BOOLEAN, 8, TFS(&flags_set_truth), MYSQL_RFSH_THREADS,
		"", HFILL }},

		{ &hf_mysql_rfsh_slave,
		{ "flush slave status", "mysql.rfsh.slave",
		FT_BOOLEAN, 8, TFS(&flags_set_truth), MYSQL_RFSH_SLAVE,
		"", HFILL }},

		{ &hf_mysql_rfsh_master,
		{ "flush master status", "mysql.rfsh.master",
		FT_BOOLEAN, 8, TFS(&flags_set_truth), MYSQL_RFSH_MASTER,
		"", HFILL }},

		{ &hf_mysql_unused,
		{ "Unused", "mysql.unused",
		FT_STRING, BASE_DEC, NULL, 0x0,
		"Unused", HFILL }},

		{ &hf_mysql_passwd,
		{ "Password", "mysql.passwd",
		FT_STRING, BASE_DEC, NULL, 0x0,
		"Password", HFILL }},

		{ &hf_mysql_parameter,
		{ "Parameter", "mysql.parameter",
		FT_STRING, BASE_DEC, NULL, 0x0,
		"Parameter", HFILL }},

		{ &hf_mysql_payload,
		{ "Payload", "mysql.payload",
		FT_STRING, BASE_DEC, NULL, 0x0,
		"Additional Payload", HFILL }},

		{ &hf_mysql_affected_rows,
		{ "Affected Rows", "mysql.affected_rows",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		"Affected Rows", HFILL }},

		{ &hf_mysql_insert_id,
		{ "Last INSERT ID", "mysql.insert_id",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		"Last INSERT ID", HFILL }},

		{ &hf_mysql_num_warn,
		{ "Warnings", "mysql.warnings",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Warnings", HFILL }},

		{ &hf_mysql_thd_id,
		{ "Thread ID", "mysql.thd_id",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"Thread ID", HFILL }},

		{ &hf_mysql_stmt_id,
		{ "Statement ID", "mysql.stmt_id",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"Statement ID", HFILL }},

		{ &hf_mysql_query,
		{ "Statement", "mysql.query",
		FT_STRING, BASE_DEC, NULL, 0x0,
		"Statement", HFILL }},

		{ &hf_mysql_option,
		{ "Option", "mysql.option",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Option", HFILL }},

		{ &hf_mysql_param,
		{ "Parameter", "mysql.param",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Parameter", HFILL }},

		{ &hf_mysql_num_rows,
		{ "Rows to fetch", "mysql.num_rows",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"Rows to fetch", HFILL }},

		{ &hf_mysql_exec_flags,
		{ "Flags (unused)", "mysql.exec_flags",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Flags (unused)", HFILL }},

		{ &hf_mysql_exec_iter,
		{ "Iterations (unused)", "mysql.exec_iter",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"Iterations (unused)", HFILL }},

		{ &hf_mysql_eof,
		{ "EOF", "mysql.eof",
		FT_UINT8, BASE_DEC, NULL,  0x0,
		"EOF", HFILL }},

		{ &hf_mysql_num_fields,
		{ "Number of fields", "mysql.num_fields",
		FT_UINT64, BASE_DEC, NULL,  0x0,
		"Number of fields", HFILL }},

		{ &hf_mysql_extra,
		{ "Extra data", "mysql.extra",
		FT_UINT64, BASE_DEC, NULL,  0x0,
		"Extra data", HFILL }}
	};

	static gint *ett[]=
	{
		&ett_mysql,
		&ett_server_greeting,
		&ett_caps,
		&ett_extcaps,
		&ett_stat,
		&ett_request,
		&ett_refresh,
	};

	module_t *mysql_module;

	proto_mysql= proto_register_protocol("MySQL Protocol", "MySQL", "mysql");
	proto_register_field_array(proto_mysql, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	mysql_module= prefs_register_protocol(proto_mysql, NULL);
	prefs_register_bool_preference(mysql_module, "desegment_buffers",
				       "Reassemble MySQL buffers spanning multiple TCP segments",
				       "Whether the MySQL dissector should reassemble MySQL buffers spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				       &mysql_desegment);
}


/* dissector entrypoint, handles TCP-desegmentation */
static void dissect_mysql(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, mysql_desegment, 3,
			 get_mysql_pdu_len, dissect_mysql_pdu);
}


/* dissector helper: length of PDU */
static guint get_mysql_pdu_len(tvbuff_t *tvb, int offset)
{
	guint plen= tvb_get_letoh24(tvb, offset);
	return plen + 4; /* add length field + packet number */
}


/* dissector main function: handle one PDU */
static void dissect_mysql_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *mysql_tree= NULL;
	proto_item      *ti;
	conversation_t  *conversation;
	int             offset = 0;
	guint           packet_number;
	gboolean        is_response;
	my_conn_data_t  *conn_data;
#ifdef CTDEBUG
	my_proto_state_t state_in, state_out;
	guint64         generation;
#endif

	/* get conversation, create if neccessary*/
	conversation= find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
					pinfo->ptype, pinfo->srcport,
					pinfo->destport, 0);

	if (!conversation) {
		conversation= conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
					       pinfo->ptype, pinfo->srcport,
					       pinfo->destport, 0);
	}

	/* get associated state information, create if neccessary */
	conn_data= conversation_get_proto_data(conversation, proto_mysql);
	if (!conn_data) {
		conn_data= se_alloc(sizeof(my_conn_data_t));
		conn_data->srv_caps= 0;
		conn_data->clnt_caps= 0;
		conn_data->clnt_caps_ext= 0;
		conn_data->state= UNDEFINED;
		conn_data->stmts= g_hash_table_new(g_int_hash, g_int_equal);
#ifdef CTDEBUG
		conn_data->generation= 0;
#endif
		conversation_add_proto_data(conversation, proto_mysql, conn_data);
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "MySQL");
	}

	if (pinfo->destport == pinfo->match_port) {
		is_response= FALSE;
	} else {
		is_response= TRUE;
	}

	if (tree) {
		ti= proto_tree_add_item(tree, proto_mysql, tvb, offset, -1, FALSE);
		mysql_tree= proto_item_add_subtree(ti, ett_mysql);
		proto_tree_add_item(mysql_tree, hf_mysql_packet_length, tvb,
				    offset, 3, TRUE);
	}
	offset+= 3;

	packet_number= tvb_get_guint8(tvb, offset);
	if (tree) {
		proto_tree_add_uint(mysql_tree, hf_mysql_packet_number, tvb,
				    offset, 1, packet_number);
	}
	offset+= 1;

#ifdef CTDEBUG
	state_in= conn_data->state;
	generation= conn_data->generation;
	if (tree) {
		proto_tree_add_text(mysql_tree, tvb, offset, 0, "conversation: %p", conversation);
		proto_tree_add_text(mysql_tree, tvb, offset, 0, "generation: %lld", generation);
		proto_tree_add_text(mysql_tree, tvb, offset, 0, "proto state: %s (%u)",
				    val_to_str(state_in, state_vals, "Unknown (%u)"),
				    state_in);
	}
#endif

	if (is_response ) {
		if (packet_number == 0) {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_str(pinfo->cinfo, COL_INFO, "Server Greeting" );
			}
			offset= mysql_dissect_greeting(tvb, pinfo, offset,
						       mysql_tree, conn_data);
		} else {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_str(pinfo->cinfo, COL_INFO, "Response" );
			}
			offset= mysql_dissect_response(tvb, pinfo, offset,
						       mysql_tree, conn_data);
		}
	} else {
		if (packet_number == 1) {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_str(pinfo->cinfo, COL_INFO, "Login Request");
			}
			offset= mysql_dissect_login(tvb, pinfo, offset,
						    mysql_tree, conn_data);
		} else {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_str(pinfo->cinfo, COL_INFO, "Request");
			}
			offset= mysql_dissect_request(tvb, pinfo, offset,
						      mysql_tree, conn_data);
		}
	}

#ifdef CTDEBUG
	state_out= conn_data->state;
	++(conn_data->generation);
	if (tree) {
		proto_tree_add_text(mysql_tree, tvb, offset, 0, "next proto state: %s (%u)",
				    val_to_str(state_out, state_vals, "Unknown (%u)"),
				    state_out);
	}
#endif

	/* remaining payload indicates an error */
	if (tree && tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree_add_string(mysql_tree, hf_mysql_payload, tvb, offset, -1,
				      "FIXME - dissector is incomplete");
	}
}


static int mysql_dissect_greeting(tvbuff_t *tvb, packet_info *pinfo, int offset,
				  proto_tree *tree, my_conn_data_t *conn_data)
{
	gint protocol;
	gint strlen;
	gint32 thread_id;
	guint16 server_caps;

	proto_item *tf;
	proto_item *greeting_tree= NULL;

	protocol= tvb_get_guint8(tvb, offset);

	if (protocol == 0xff) {
		return mysql_dissect_error_packet(tvb, pinfo, offset+1, tree);
	}

	conn_data->state= LOGIN;

	if (tree) {
		tf= proto_tree_add_text(tree, tvb, offset, -1, "Server Greeting");
		greeting_tree= proto_item_add_subtree(tf, ett_server_greeting);
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " proto=%d", protocol) ;
	}
	if (tree) {
		proto_tree_add_uint(greeting_tree, hf_mysql_protocol, tvb,
				    offset, 1, protocol);
	}
	offset+= 1;

	/* version string */
	strlen= tvb_strsize(tvb,offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " version=%s",
				tvb_get_ptr(tvb, offset, strlen));
	}
	if (tree) {
		proto_tree_add_item(greeting_tree, hf_mysql_version, tvb,
				    offset, strlen, FALSE );
	}
	offset+= strlen;

	/* 4 bytes little endian thread_id */
	thread_id= tvb_get_letohl(tvb, offset);
	if (tree) {
		proto_tree_add_uint(greeting_tree, hf_mysql_thread_id, tvb,
				    offset, 4, thread_id);
	}
	offset+= 4;

	/* salt string */
	strlen= tvb_strsize(tvb,offset);
	if (tree) {
		proto_tree_add_item(greeting_tree, hf_mysql_salt, tvb,
				    offset, strlen, FALSE );
	}
	offset+=strlen;

	/* rest is optional */
	if (!tvb_length_remaining(tvb, offset)) return offset;

	/* 2 bytes CAPS */
	offset= mysql_dissect_caps(tvb, offset, greeting_tree, &server_caps, "Server");
	conn_data->srv_caps= server_caps;

	/* rest is optional */
	if (!tvb_length_remaining(tvb, offset)) return offset;

	offset= mysql_dissect_collation(tvb, offset, greeting_tree, server_caps);
	offset= mysql_dissect_server_status(tvb, offset, greeting_tree);

	/* 13 bytes unused */
	if (tree) {
		proto_tree_add_item(greeting_tree, hf_mysql_unused, tvb,
				    offset, 13, FALSE );
	}
	offset+= 13;

	/* 4.1+ server: rest of salt */
	if (tvb_length_remaining(tvb, offset)) {
		strlen= tvb_strsize(tvb,offset);
		if (tree) {
			proto_tree_add_item(greeting_tree, hf_mysql_salt2, tvb,
					    offset, strlen, FALSE );
		}
		offset+= strlen;
	}

	return offset;
}


static int mysql_dissect_login(tvbuff_t *tvb, packet_info *pinfo, int offset,
			       proto_tree *tree, my_conn_data_t *conn_data)
{
	guint16  client_caps;
	guint16  ext_caps;
	guint32  max_packet;
	gint	 strlen;

	proto_item *tf;
	proto_item *login_tree= NULL;

	/* after login there can be OK or DENIED */
	conn_data->state= RESPONSE_OK;

	if (tree) {
		tf= proto_tree_add_text(tree, tvb, offset, -1, "Login Request");
		login_tree= proto_item_add_subtree(tf, ett_server_greeting);
	}

	offset= mysql_dissect_caps(tvb, offset, login_tree, &client_caps, "Client");
	conn_data->clnt_caps= client_caps;

	if (client_caps & MYSQL_CAPS_CU) /* 4.1 protocol */
	{
		offset= mysql_dissect_ext_caps(tvb, offset, login_tree, &ext_caps, "Client");
		conn_data->clnt_caps_ext= ext_caps;

		max_packet= tvb_get_letohl(tvb, offset);
		if(tree) {
			proto_tree_add_uint(login_tree, hf_mysql_max_packet, tvb,
					    offset, 4, max_packet);
		}
		offset+= 4;

		offset= mysql_dissect_collation(tvb, offset, login_tree, client_caps);

		offset+= 23; /* filler bytes */

	} else { /* pre-4.1 */
		max_packet= 0xffffff - tvb_get_letoh24(tvb, offset);
		if (tree) {
			proto_tree_add_uint(login_tree, hf_mysql_max_packet, tvb,
					    offset, 3, max_packet);
		}
		offset+= 3;
	}

	/* User name */
	strlen= my_tvb_strsize(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " user=%s",
				tvb_get_ptr(tvb,offset,strlen));
	}
	if (tree) {
		proto_tree_add_item(login_tree, hf_mysql_user, tvb,
				    offset, strlen, FALSE );
	}
	offset+= strlen;

	/* rest is optional */
	if (!tvb_length_remaining(tvb, offset)) return offset;

	/* password: asciiz or length+ascii */
	if (client_caps & MYSQL_CAPS_SC) {
		strlen= tvb_get_guint8(tvb, offset);
		offset+= 1;
	} else {
		strlen= my_tvb_strsize(tvb, offset);
	}
	if (tree && strlen > 1) {
		proto_tree_add_item(login_tree, hf_mysql_passwd,
				    tvb, offset, strlen, FALSE);
	}
	offset+= strlen;

	/* optional: initial schema */
	if (client_caps & MYSQL_CAPS_CD)
	{
		strlen= my_tvb_strsize(tvb,offset);

		if (check_col(pinfo->cinfo, COL_INFO)) {
			/* ugly hack: copy database to new buffer*/
			guint8 buf[65];
			if (strlen > 64)
				strlen= 64;
			tvb_memcpy(tvb, buf, offset, strlen);
			buf[strlen]= '\0';
			col_append_fstr(pinfo->cinfo, COL_INFO, " db=%s", buf);
		}
		if (tree) {
			proto_tree_add_item(login_tree, hf_mysql_schema, tvb,
					    offset, strlen, FALSE );
		}
		offset+= strlen;
	}

	return offset;
}


static int mysql_dissect_request(tvbuff_t *tvb,packet_info *pinfo, int offset,
				 proto_tree *tree, my_conn_data_t *conn_data)
{
	gint opcode;
	gint strlen;
	proto_item *tf;
	proto_item *req_tree= NULL;
	guint16 option;

	if (tree) {
		tf= proto_tree_add_text(tree, tvb, offset, -1, "Command");
		req_tree= proto_item_add_subtree(tf, ett_request);
	}

	opcode= tvb_get_guint8(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
				val_to_str(opcode, mysql_opcode_vals, "Unknown (%u)"));
	}
	if (req_tree) {
		proto_tree_add_uint_format(req_tree, hf_mysql_opcode, tvb,
					   offset, 1, opcode, "Command: %s (%u)",
					   val_to_str(opcode, mysql_opcode_vals, "Unknown (%u)"),
					   opcode);
	}
	offset+= 1;


	switch (opcode) {

	case MYSQL_QUIT:
		if (conn_data->stmts) {
			g_hash_table_destroy(conn_data->stmts);
			conn_data->stmts= NULL;
		}
		break;

	case MYSQL_PROCESS_INFO:
		conn_data->state= RESPONSE_TABULAR;
		break;

	case MYSQL_DEBUG:
	case MYSQL_PING:
		conn_data->state= RESPONSE_OK;
		break;

	case MYSQL_STATISTICS:
		conn_data->state= RESPONSE_MESSAGE;
		break;

	case MYSQL_INIT_DB:
	case MYSQL_CREATE_DB:
	case MYSQL_DROP_DB:
		strlen= my_tvb_strsize(tvb, offset);
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_schema, tvb,
					    offset, strlen, FALSE);
		}
		offset+= strlen;
		conn_data->state= RESPONSE_OK;
		break;

	case MYSQL_QUERY:
		strlen= my_tvb_strsize(tvb, offset);
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_query, tvb,
					    offset, strlen, FALSE);
		}
		offset+= strlen;
		conn_data->state= RESPONSE_TABULAR;
		break;

	case MYSQL_STMT_PREPARE:
		strlen= my_tvb_strsize(tvb, offset);
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_query, tvb,
					    offset, strlen, FALSE);
		}
		offset+= strlen;
		conn_data->state= RESPONSE_PREPARE;
		break;

	case MYSQL_STMT_CLOSE:
		if (conn_data->stmts) {
			gint stmt= tvb_get_letohl(tvb, offset);
			g_hash_table_remove(conn_data->stmts, &stmt);
		}
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_stmt_id,
					    tvb, offset, 4, TRUE);
		}
		offset+= 4;
		conn_data->state= REQUEST;
		break;

	case MYSQL_STMT_RESET:
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_stmt_id,
					    tvb, offset, 4, TRUE);
		}
		offset+= 4;
		conn_data->state= RESPONSE_OK;
		break;

	case MYSQL_FIELD_LIST:
		strlen= my_tvb_strsize(tvb, offset);
		if (req_tree) {
			proto_tree_add_text(req_tree, tvb, offset, strlen, "Table name: %s",
					    tvb_get_string(tvb, offset, strlen));
		}
		offset+= strlen;
		conn_data->state= RESPONSE_TABULAR;
		break;

	case MYSQL_PROCESS_KILL:
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_thd_id,
					    tvb, offset, 4, TRUE);
		}
		offset+= 4;
		conn_data->state= RESPONSE_OK;
		break;

	case MYSQL_CHANGE_USER:
		strlen= tvb_strsize(tvb, offset);
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_user, tvb,
					    offset, strlen, FALSE);
		}
		offset+= strlen;

		strlen= tvb_strsize(tvb, offset);
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_passwd, tvb,
					    offset, strlen, FALSE);
		}
		offset+= strlen;

		strlen= my_tvb_strsize(tvb, offset);
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_schema, tvb,
					    offset, strlen, FALSE);
		}
		offset+= strlen;
		conn_data->state= RESPONSE_OK;
		break;

	case MYSQL_REFRESH:
		{
			proto_item *tf;
			proto_item *rfsh_tree;
			gint refresh= tvb_get_guint8(tvb, offset);

			if (req_tree) {
				tf= proto_tree_add_uint_format(req_tree, hf_mysql_refresh, tvb, offset, 1, refresh, "Refresh Bitmap: 0x%02X ", refresh);
				rfsh_tree= proto_item_add_subtree(tf, ett_refresh);
				proto_tree_add_boolean(rfsh_tree, hf_mysql_rfsh_grants, tvb, offset, 1, refresh);
				proto_tree_add_boolean(rfsh_tree, hf_mysql_rfsh_log, tvb, offset, 1, refresh);
				proto_tree_add_boolean(rfsh_tree, hf_mysql_rfsh_tables, tvb, offset, 1, refresh);
				proto_tree_add_boolean(rfsh_tree, hf_mysql_rfsh_hosts, tvb, offset, 1, refresh);
				proto_tree_add_boolean(rfsh_tree, hf_mysql_rfsh_status, tvb, offset, 1, refresh);
				proto_tree_add_boolean(rfsh_tree, hf_mysql_rfsh_threads, tvb, offset, 1, refresh);
				proto_tree_add_boolean(rfsh_tree, hf_mysql_rfsh_slave, tvb, offset, 1, refresh);
				proto_tree_add_boolean(rfsh_tree, hf_mysql_rfsh_master, tvb, offset, 1, refresh);
			}
		}
		offset+= 1;
		conn_data->state= RESPONSE_OK;
		break;

	case MYSQL_SHUTDOWN:
		opcode= tvb_get_guint8(tvb, offset);
		if (req_tree) {
			proto_tree_add_uint_format(req_tree, hf_mysql_opcode, tvb, offset,
						   1, opcode, "Shutdown-Level: %s",
						   val_to_str(opcode, mysql_shutdown_vals, "Unknown (%u)"));
		}
		offset+= 1;
		conn_data->state= RESPONSE_OK;
		break;

	case MYSQL_SET_OPTION:
		option= tvb_get_letohs(tvb, offset);
		if (req_tree) {
			proto_tree_add_uint_format(req_tree, hf_mysql_option, tvb, offset,
						   2, option, "Option: %s",
						   val_to_str(option, mysql_option_vals, "Unknown (%u)"));
		}
		offset+= 2;
		conn_data->state= RESPONSE_OK;
		break;

	case MYSQL_STMT_FETCH:
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_stmt_id,
					    tvb, offset, 4, TRUE);
		}
		offset+= 4;

		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_num_rows,
					    tvb, offset, 4, TRUE);
		}
		offset+= 4;
		conn_data->state= RESPONSE_TABULAR;
		break;

	case MYSQL_STMT_SEND_LONG_DATA:
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_stmt_id,
					    tvb, offset, 4, TRUE);
		}
		offset+= 4;

		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_param,
					    tvb, offset, 2, TRUE);
		}
		offset+= 2;

		/* rest is data */
		strlen= tvb_reported_length_remaining(tvb, offset);
		if (tree &&  strlen > 0) {
			proto_tree_add_item(req_tree, hf_mysql_payload,
					    tvb, offset, strlen, FALSE);
		}
		offset+= strlen;
		conn_data->state= REQUEST;
		break;

	case MYSQL_STMT_EXECUTE:
		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_stmt_id,
					    tvb, offset, 4, TRUE);
		}
		offset+= 4;

		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_exec_flags,
					    tvb, offset, 1, TRUE);
		}
		offset+= 1;

		if (req_tree) {
			proto_tree_add_item(req_tree, hf_mysql_exec_iter,
					    tvb, offset, 4, TRUE);
		}
		offset+= 4;

#if 0
/* FIXME: rest needs metadata about statement */
#else
		strlen= tvb_reported_length_remaining(tvb, offset);
		if (tree &&  strlen > 0) {
			proto_tree_add_string(req_tree, hf_mysql_payload, tvb, offset,
					      strlen, "FIXME: execute dissector incomplete");
		}
		offset+= strlen;
#endif
		conn_data->state= RESPONSE_TABULAR;
		break;

/* FIXME: implement replication packets */
	case MYSQL_BINLOG_DUMP:
	case MYSQL_TABLE_DUMP:
	case MYSQL_CONNECT_OUT:
	case MYSQL_REGISTER_SLAVE:
		if (req_tree) {
			proto_tree_add_string(req_tree, hf_mysql_payload, tvb, offset, -1,
					      "FIXME: implement replication packets");
		}
		offset+= tvb_length_remaining(tvb, offset);
		conn_data->state= REQUEST;
		break;

	default:
		if (req_tree) {
			proto_tree_add_string(req_tree, hf_mysql_payload, tvb, offset, -1,
					      "unknown/invalid command code");
		}
		offset+= tvb_length_remaining(tvb, offset);
		conn_data->state= UNDEFINED;
	}

	return offset;
}


static int mysql_dissect_response(tvbuff_t *tvb, packet_info *pinfo, int offset,
				  proto_tree *tree, my_conn_data_t *conn_data)
{
	gint response_code;
        gint strlen;

	response_code= tvb_get_guint8(tvb, offset);

	if (response_code == 0xff ) {
		offset= mysql_dissect_error_packet(tvb, pinfo, offset+1, tree);
		conn_data->state= REQUEST;
	}

        else if (response_code == 0xfe && tvb_length_remaining(tvb, offset) < 9) {

		if (tree) {
			proto_tree_add_uint_format(tree, hf_mysql_eof, tvb, offset, 1,
						   response_code, "EOF marker (%u)",
						   response_code);
		}
		offset+= 1;

		/* pre-4.1 packet ends here */
		if (tvb_length_remaining(tvb, offset)) {
			if (tree) {
				proto_tree_add_item(tree, hf_mysql_num_warn,
						    tvb, offset, 2, FALSE);
			}
			offset= mysql_dissect_server_status(tvb, offset+2, tree);
		}

		if (conn_data->state == FIELD_PACKET) {
			conn_data->state= ROW_PACKET;
		} else {
			conn_data->state= REQUEST;
		}
	}

	else if (response_code == 0) {
		if (tvb_length_remaining(tvb, offset+1)
		    > tvb_get_fle(tvb, offset+1, NULL, NULL)) {
			offset= mysql_dissect_ok_packet(tvb, pinfo, offset+1,
							tree, conn_data);
		} else {
			offset= mysql_dissect_result_header(tvb, pinfo, offset,
							    tree, conn_data);
		}
	}

	else {
		switch (conn_data->state) {
		case RESPONSE_MESSAGE:
			if ((strlen= tvb_length_remaining(tvb, offset))) {
				if (tree) {
					proto_tree_add_item(tree, hf_mysql_message, tvb,
							    offset, strlen, FALSE);
				}
				offset+= strlen;
			}
			conn_data->state= REQUEST;
			break;

		case RESPONSE_TABULAR:
			offset= mysql_dissect_result_header(tvb, pinfo, offset,
							    tree, conn_data);
			break;

		case FIELD_PACKET:
			offset= mysql_dissect_field_packet(tvb, pinfo, offset,
							   tree, conn_data);
			break;

		case ROW_PACKET:
			offset= mysql_dissect_row_packet(tvb, pinfo, offset,
							 tree, conn_data);
			break;

		case RESPONSE_PREPARE:
			offset= mysql_dissect_response_prepare(tvb, pinfo, offset,
							       tree, conn_data);
			break;

		case PARAM_PACKET:
			offset= mysql_dissect_param_packet(tvb, pinfo, offset,
							   tree, conn_data);
			break;

		default:
			if (tree) {
				proto_tree_add_string(tree, hf_mysql_payload, tvb, offset, -1,
						      "unknown/invalid response");
			}
			offset+= tvb_length_remaining(tvb, offset);
			conn_data->state= UNDEFINED;
		}
	}

	return offset;
}


static int mysql_dissect_error_packet(tvbuff_t *tvb, packet_info *pinfo,
				      int offset, proto_tree *tree)
{
	gint error_code;
	error_code= tvb_get_letohs(tvb, offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " Error %d", error_code);
	}
	if (tree) {
		proto_tree_add_uint(tree, hf_mysql_error_code, tvb,
				    offset, 2, error_code);
	}
	offset+= 2;

	if (tvb_get_guint8(tvb, offset) == '#')
	{
		offset+= 1;
		proto_tree_add_item(tree, hf_mysql_sqlstate, tvb, offset, 5, FALSE);
		offset+= 5;
	}

	proto_tree_add_item(tree, hf_mysql_error_string, tvb, offset, -1, FALSE);
	offset+= tvb_reported_length_remaining(tvb, offset);

	return offset;
}


static int mysql_dissect_ok_packet(tvbuff_t *tvb, packet_info *pinfo, int offset,
				   proto_tree *tree, my_conn_data_t *conn_data)
{
	gint strlen;
	guint64 affected_rows;
	guint64 insert_id;
	int fle;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_str(pinfo->cinfo, COL_INFO, " OK" );
	}

	fle= tvb_get_fle(tvb, offset, &affected_rows, NULL);
	if (tree) {
		proto_tree_add_uint64(tree, hf_mysql_affected_rows,
				      tvb, offset, fle, affected_rows);
	}
	offset+= fle;

	fle= tvb_get_fle(tvb, offset, &insert_id, NULL);
	if (tree && insert_id) {
		proto_tree_add_uint64(tree, hf_mysql_insert_id,
				      tvb, offset, fle, insert_id);
	}
	offset+= fle;

	offset= mysql_dissect_server_status(tvb, offset, tree);

	/* 4.1+ protocol only: 2 bytes number of warnings */
	if (conn_data->clnt_caps & conn_data->srv_caps & MYSQL_CAPS_CU) {
		if (tree) {
			proto_tree_add_item(tree, hf_mysql_num_warn, tvb,
					    offset, 2, FALSE);
		}
		offset+= 2;
	}

	/* optional: message string */
	if ((strlen= tvb_length_remaining(tvb, offset))) {
		if (tree) {
			proto_tree_add_item(tree, hf_mysql_message, tvb,
					    offset, strlen, FALSE);
		}
		offset+= strlen;
	}

	conn_data->state= REQUEST;
	return offset;
}


static int mysql_dissect_server_status(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint16 status;
	proto_item *tf;
	proto_item *stat_tree;

	status= tvb_get_letohs(tvb, offset);
	if (tree) {
		tf= proto_tree_add_uint_format(tree, hf_mysql_status, tvb, offset, 2, status, "Server Status: 0x%04X ", status);
		stat_tree= proto_item_add_subtree(tf, ett_stat);
		proto_tree_add_boolean(stat_tree, hf_mysql_stat_it, tvb, offset, 2, status);
		proto_tree_add_boolean(stat_tree, hf_mysql_stat_ac, tvb, offset, 2, status);
		proto_tree_add_boolean(stat_tree, hf_mysql_stat_mr, tvb, offset, 2, status);
		proto_tree_add_boolean(stat_tree, hf_mysql_stat_mu, tvb, offset, 2, status);
		proto_tree_add_boolean(stat_tree, hf_mysql_stat_bi, tvb, offset, 2, status);
		proto_tree_add_boolean(stat_tree, hf_mysql_stat_ni, tvb, offset, 2, status);
		proto_tree_add_boolean(stat_tree, hf_mysql_stat_cr, tvb, offset, 2, status);
		proto_tree_add_boolean(stat_tree, hf_mysql_stat_lr, tvb, offset, 2, status);
		proto_tree_add_boolean(stat_tree, hf_mysql_stat_dr, tvb, offset, 2, status);
		proto_tree_add_boolean(stat_tree, hf_mysql_stat_bs, tvb, offset, 2, status);
	}
	offset+= 2;

	return offset;
}


static int mysql_dissect_collation(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 caps)
{
	gint charset= tvb_get_guint8(tvb, offset);
	if (tree) {
		proto_tree_add_uint_format(tree, hf_mysql_charset, tvb, offset, 1,
					   charset, "Charset: %s (%u)",
					   val_to_str(charset,
						      caps & MYSQL_CAPS_CU
						      ? mysql_collation_vals
						      : mysql_charset_vals,
						      "Unknown (%u)"), charset);
	}
	offset+= 1;
	return offset;
}


static int mysql_dissect_caps(tvbuff_t *tvb, int offset, proto_tree *tree,
			      guint16 *caps, const char* whom)
{
	*caps= tvb_get_letohs(tvb, offset);
	if (tree) {
		proto_item *tf= proto_tree_add_uint_format(tree, hf_mysql_caps, tvb, offset, 2, *caps,
							   "%s Capabilities: 0x%04X ", whom, *caps);
		proto_item *cap_tree= proto_item_add_subtree(tf, ett_caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_long_password, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_found_rows, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_long_flag, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_connect_with_db, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_no_schema, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_compress, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_odbc, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_local_files, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_ignore_space, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_change_user, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_interactive, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_ssl, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_ignore_sigpipe, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_transactions, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_reserved, tvb, offset, 2, *caps);
		proto_tree_add_boolean(cap_tree, hf_mysql_cap_secure_connect, tvb, offset, 2, *caps);
	}

	offset+= 2;
	return offset;
}


static int mysql_dissect_ext_caps(tvbuff_t *tvb, int offset, proto_tree *tree,
				  guint16 *caps, const char* whom)
{
	proto_item *extcap_tree;
	*caps= tvb_get_letohs(tvb, offset);
	if (tree) {
		proto_item *tf= proto_tree_add_uint_format(tree, hf_mysql_extcaps, tvb, offset, 2, *caps,
							   "Extended %s Capabilities: 0x%04X ", whom, *caps);
		extcap_tree= proto_item_add_subtree(tf, ett_extcaps);
		proto_tree_add_boolean(extcap_tree, hf_mysql_cap_multi_statements, tvb, offset, 2, *caps);
		proto_tree_add_boolean(extcap_tree, hf_mysql_cap_multi_results, tvb, offset, 2, *caps);
	}

	offset+= 2;
	return offset;
}


static int mysql_dissect_result_header(tvbuff_t *tvb, packet_info *pinfo, int offset,
				       proto_tree *tree, my_conn_data_t *conn_data)
{
	gint fle;
	guint64 num_fields, extra;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_str(pinfo->cinfo, COL_INFO, " TABULAR" );
	}

	fle= tvb_get_fle(tvb, offset, &num_fields, NULL);
	if (tree) {
		proto_tree_add_uint64(tree, hf_mysql_num_fields,
				      tvb, offset, fle, num_fields);
	}
	offset+= fle;

	if (tvb_length_remaining(tvb, offset)) {
		fle= tvb_get_fle(tvb, offset, &extra, NULL);
		if (tree) {
			proto_tree_add_uint64(tree, hf_mysql_extra,
					      tvb, offset, fle, extra);
		}
		offset+= fle;
	}

	if (num_fields) {
		conn_data->state= FIELD_PACKET;
	} else {
		conn_data->state= ROW_PACKET;
	}

	return offset;
}


static int mysql_dissect_field_packet(tvbuff_t *tvb, packet_info *pinfo, int offset,
				      proto_tree *tree, my_conn_data_t *conn_data)
{
	proto_tree_add_text(tree, tvb, offset, -1, "FIXME: write mysql_dissect_field_packet()");
	return offset + tvb_length_remaining(tvb, offset);
}


static int mysql_dissect_row_packet(tvbuff_t *tvb, packet_info *pinfo, int offset,
				    proto_tree *tree, my_conn_data_t *conn_data)
{
	proto_tree_add_text(tree, tvb, offset, -1, "FIXME: write mysql_dissect_row_packet()");
	return offset + tvb_length_remaining(tvb, offset);
}


static int mysql_dissect_response_prepare(tvbuff_t *tvb, packet_info *pinfo, int offset,
					  proto_tree *tree, my_conn_data_t *conn_data)
{
	proto_tree_add_text(tree, tvb, offset, -1, "FIXME: write mysql_dissect_response_prepare()");
	return offset + tvb_length_remaining(tvb, offset);
}


static int mysql_dissect_param_packet(tvbuff_t *tvb, packet_info *pinfo, int offset,
				      proto_tree *tree, my_conn_data_t *conn_data)
{
	proto_tree_add_text(tree, tvb, offset, -1, "FIXME: write mysql_dissect_param_packet()");
	return offset + tvb_length_remaining(tvb, offset);
}



/*
 get length of string in packet buffer

 SYNOPSIS
   my_tvb_strsize()
     tvb      packet buffer
     offset   current offset

 DESCRIPTION
   deliver length of string, delimited by either \0 or end of buffer

 RETURN VALUE
   length of string found, including \0 (if present)

*/
static gint my_tvb_strsize(tvbuff_t *tvb, int offset)
{
	gint len = tvb_strnlen(tvb, offset, -1);
	if (len == -1) {
		len = tvb_length_remaining(tvb, offset);
	} else {
		len++; /* the trailing \0 */
	}
	return len;
}


/*
 read "field length encoded" value from packet buffer

 SYNOPSIS
   tvb_get_fle()
     tvb     in    packet buffer
     offset  in    offset in buffer
     res     out   where to store FLE value, may be NULL
     is_null out   where to store ISNULL flag, may be NULL

 DESCRIPTION
   read FLE from packet buffer and store its value and ISNULL flag
   in caller provided variables

 RETURN VALUE
   length of FLE
*/
static int tvb_get_fle(tvbuff_t *tvb, int offset, guint64 *res, guint8 *is_null)
{
	guint8 prefix= tvb_get_guint8(tvb, offset);

	if (is_null)
		*is_null= 0;

	switch (prefix) {
	case 251:
		if (res)
			*res= 0;
		if (is_null)
			*is_null= 1;
		break;
	case 252:
		if (res)
			*res= tvb_get_letohs(tvb, offset+1);
		return 3;
	case 253:
		if (res)
			*res= tvb_get_letohl(tvb, offset+1);
		return 5;
	case 254:
		if (res)
			*res= tvb_get_letoh64(tvb, offset+1);
		return 9;
	default:
		if (res)
			*res= prefix;
	}

	return 1;
}


