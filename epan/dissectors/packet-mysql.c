/* packet-mysql.c
 * Routines for MySQL/MariaDB packet dissection
 *
 * Huagang XIE <huagang@intruvert.com>
 *
 * MySQL 4.1+ protocol by Axel Schwenke <axel@mysql.com>
 * MariaDB protocol by Georg Richter <georg@mariadb.com>
 *                   & Diego Dupin <diego.dupin@mariadb.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *
 * the protocol specifications
 * For MySQL at
 *  https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
 * For MariaDB at
 *  https://mariadb.com/kb/en/clientserver-protocol/
 * and MySQL source code
 */

/* create extra output for conversation tracking */
/* #define CTDEBUG 1 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include "packet-tcp.h"
#include "packet-tls-utils.h"

void proto_register_mysql(void);
void proto_reg_handoff_mysql(void);

/* port for protocol registration */
#define TCP_PORT_MySQL   3306

#define MYSQL_HEADER_LENGTH 4

/* MariaDB Server >= 10.0 sends a 5.5.5- prefix for the version, since
	 replication doesn't support a two digit version number. Version 5.5.5
   was never released in MySQL and MariaDB */
#define MARIADB_RPL_VERSION_HACK "5.5.5-"

/* client/server capabilities
 * Docs:   https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html
 * Source: https://github.com/mysql/mysql-server/blob/8.0/include/mysql_com.h
 */
#define MYSQL_CAPS_LP 0x0001 /* CLIENT_LONG_PASSWORD/CLIENT_IS_MYSQL */
#define MYSQL_CAPS_FR 0x0002 /* CLIENT_FOUND_ROWS */
#define MYSQL_CAPS_LF 0x0004 /* CLIENT_LONG_FLAG */
#define MYSQL_CAPS_CD 0x0008 /* CLIENT_CONNECT_WITH_DB */
#define MYSQL_CAPS_NS 0x0010 /* CLIENT_NO_SCHEMA */
#define MYSQL_CAPS_CP 0x0020 /* CLIENT_COMPRESS */
#define MYSQL_CAPS_OB 0x0040 /* CLIENT_ODBC */
#define MYSQL_CAPS_LI 0x0080 /* CLIENT_LOCAL_FILES */
#define MYSQL_CAPS_IS 0x0100 /* CLIENT_IGNORE_SPACE */
#define MYSQL_CAPS_CU 0x0200 /* CLIENT_PROTOCOL_41 */
#define MYSQL_CAPS_IA 0x0400 /* CLIENT_INTERACTIVE */
#define MYSQL_CAPS_SL 0x0800 /* CLIENT_SSL */
#define MYSQL_CAPS_II 0x1000 /* CLIENT_IGNORE_SPACE */
#define MYSQL_CAPS_TA 0x2000 /* CLIENT_TRANSACTIONS */
#define MYSQL_CAPS_RS 0x4000 /* CLIENT_RESERVED */
#define MYSQL_CAPS_SC 0x8000 /* CLIENT_SECURE_CONNECTION */


/* field flags */
#define MYSQL_FLD_NOT_NULL_FLAG       0x0001
#define MYSQL_FLD_PRI_KEY_FLAG        0x0002
#define MYSQL_FLD_UNIQUE_KEY_FLAG     0x0004
#define MYSQL_FLD_MULTIPLE_KEY_FLAG   0x0008
#define MYSQL_FLD_BLOB_FLAG           0x0010
#define MYSQL_FLD_UNSIGNED_FLAG       0x0020
#define MYSQL_FLD_ZEROFILL_FLAG       0x0040
#define MYSQL_FLD_BINARY_FLAG         0x0080
#define MYSQL_FLD_ENUM_FLAG           0x0100
#define MYSQL_FLD_AUTO_INCREMENT_FLAG 0x0200
#define MYSQL_FLD_TIMESTAMP_FLAG      0x0400
#define MYSQL_FLD_SET_FLAG            0x0800

/* extended capabilities: 4.1+ client only
 *
 * These are libmysqlclient flags and NOT present
 * in the protocol:
 * CLIENT_REMEMBER_OPTIONS (1UL << 31)
 */
#define MYSQL_CAPS_MS 0x0001 /* CLIENT_MULTI_STATEMENTS */
#define MYSQL_CAPS_MR 0x0002 /* CLIENT_MULTI_RESULTS */
#define MYSQL_CAPS_PM 0x0004 /* CLIENT_PS_MULTI_RESULTS */
#define MYSQL_CAPS_PA 0x0008 /* CLIENT_PLUGIN_AUTH */
#define MYSQL_CAPS_CA 0x0010 /* CLIENT_CONNECT_ATTRS */
#define MYSQL_CAPS_AL 0x0020 /* CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA */
#define MYSQL_CAPS_EP 0x0040 /* CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS */
#define MYSQL_CAPS_ST 0x0080 /* CLIENT_SESSION_TRACK */
#define MYSQL_CAPS_DE 0x0100 /* CLIENT_DEPRECATE_EOF */
#define MYSQL_CAPS_RM 0x0200 /* CLIENT_OPTIONAL_RESULTSET_METADATA */
#define MYSQL_CAPS_ZS 0x0400 /* CLIENT_ZSTD_COMPRESSION_ALGORITHM */
#define MYSQL_CAPS_QA 0x0800 /* CLIENT_QUERY_ATTRIBUTES */
#define MYSQL_CAPS_MF 0x1000 /* MULTI_FACTOR_AUTHENTICATION */
#define MYSQL_CAPS_CE 0x2000 /* CLIENT_CAPABILITY_EXTENSION */
#define MYSQL_CAPS_VC 0x4000 /* CLIENT_SSL_VERIFY_SERVER_CERT */

#define MYSQL_CAPS_UNUSED 0x8000 /* Currently only a single bit */

/* status bitfield */
#define MYSQL_STAT_IT 0x0001
#define MYSQL_STAT_AC 0x0002
#define MYSQL_STAT_MU 0x0004
#define MYSQL_STAT_MR 0x0008
#define MYSQL_STAT_BI 0x0010
#define MYSQL_STAT_NI 0x0020
#define MYSQL_STAT_CR 0x0040
#define MYSQL_STAT_LR 0x0080
#define MYSQL_STAT_DR 0x0100
#define MYSQL_STAT_BS 0x0200
#define MYSQL_STAT_MC 0x0400
#define MYSQL_STAT_QUERY_WAS_SLOW 0x0800
#define MYSQL_STAT_PS_OUT_PARAMS 0x1000
#define MYSQL_STAT_TRANS_READONLY 0x2000
#define MYSQL_STAT_SESSION_STATE_CHANGED 0x4000

/* bitfield for MYSQL_REFRESH */
#define MYSQL_RFSH_GRANT   1   /* Refresh grant tables */
#define MYSQL_RFSH_LOG     2   /* Start on new log file */
#define MYSQL_RFSH_TABLES  4   /* close all tables */
#define MYSQL_RFSH_HOSTS   8   /* Flush host cache */
#define MYSQL_RFSH_STATUS  16  /* Flush status variables */
#define MYSQL_RFSH_THREADS 32  /* Flush thread cache */
#define MYSQL_RFSH_SLAVE   64  /* Reset master info and restart slave thread */
#define MYSQL_RFSH_MASTER  128 /* Remove all bin logs in the index and truncate the index */

/* MySQL command codes (enum_server_command in mysql-server.git:include/my_command.h) */
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
#define MYSQL_DAEMON              29
#define MYSQL_BINLOG_DUMP_GTID    30 /* replication */
#define MYSQL_RESET_CONNECTION    31
#define MYSQL_CLONE               32
#define MYSQL_SUBSCRIBE_GROUP_REPLICATION_STREAM  33

/* MySQL Native Cloning Commands */
#define MYSQL_CLONE_COM_INIT    1
#define MYSQL_CLONE_COM_ATTACH  2
#define MYSQL_CLONE_COM_REINIT  3
#define MYSQL_CLONE_COM_EXECUTE 4
#define MYSQL_CLONE_COM_ACK     5
#define MYSQL_CLONE_COM_EXIT    6

/* decoding table: clone command */
static const value_string mysql_clone_command_vals[] = {
	{MYSQL_CLONE_COM_INIT,    "Init"},
	{MYSQL_CLONE_COM_ATTACH,  "Attach"},
	{MYSQL_CLONE_COM_REINIT,  "Re-init"},
	{MYSQL_CLONE_COM_EXECUTE, "Execute"},
	{MYSQL_CLONE_COM_ACK,     "Ack"},
	{MYSQL_CLONE_COM_EXIT,    "Exit"},
	{0, NULL}
};

/* MySQL Native Cloning Responses */
#define MYSQL_CLONE_COM_RES_LOCS        1
#define MYSQL_CLONE_COM_RES_DATA_DESC   2
#define MYSQL_CLONE_COM_RES_DATA        3
#define MYSQL_CLONE_COM_RES_PLUGIN      4
#define MYSQL_CLONE_COM_RES_CONFIG      5
#define MYSQL_CLONE_COM_RES_COLLATION   6
#define MYSQL_CLONE_COM_RES_PLUGIN_V2   7
#define MYSQL_CLONE_COM_RES_CONFIG_V3   8
#define MYSQL_CLONE_COM_RES_COMPLETE   99
#define MYSQL_CLONE_COM_RES_ERROR     100

/* decoding table: clone command */
static const value_string mysql_clone_response_vals[] = {
	{MYSQL_CLONE_COM_RES_LOCS,      "Remote Resource Locator"},
	{MYSQL_CLONE_COM_RES_DATA_DESC, "Remote Data Descriptor"},
	{MYSQL_CLONE_COM_RES_DATA,      "Remote Data"},
	{MYSQL_CLONE_COM_RES_PLUGIN,    "Plugin V1"},
	{MYSQL_CLONE_COM_RES_CONFIG,    "Config"},
	{MYSQL_CLONE_COM_RES_COLLATION, "Collation"},
	{MYSQL_CLONE_COM_RES_PLUGIN_V2, "Plugin V2"},
	{MYSQL_CLONE_COM_RES_CONFIG_V3, "Plugin V3"},
	{MYSQL_CLONE_COM_RES_COMPLETE,  "Complete"},
	{MYSQL_CLONE_COM_RES_ERROR,     "Error"},
	{0, NULL}
};

/* MariaDB specific commands */
#define MARIADB_STMT_BULK_EXECUTE 250

/* MariaDB bulk execute flags */
#define MARIADB_BULK_AUTOID      64
#define MARIADB_BULK_SEND_TYPES 128

/* MariaDB extended capabilities */
#define MARIADB_CAPS_PR 0x00000001 /* MARIADB_CLIENT_PROGRESS */
#define MARIADB_CAPS_CM 0x00000002 /* MARIADB_CLIENT_COM_MULTI */
#define MARIADB_CAPS_BO 0x00000004 /* MARIADB_CLIENT_STMT_BULK_OPERATIONS */
#define MARIADB_CAPS_EM 0x00000008 /* MARIADB_CLIENT_EXTENDED_METADATA */
#define MARIADB_CAPS_ME 0x00000010 /* MARIADB_CLIENT_CACHE_METADATA */

/* MariaDB bulk indicators */
#define MARIADB_INDICATOR_NONE       0
#define MARIADB_INDICATOR_NULL       1
#define MARIADB_INDICATOR_DEFAULT    2
#define MARIADB_INDICATOR_IGNORE     3
#define MARIADB_INDICATIR_IGNORE_ROW 4


/* MySQL cursor types */

#define MYSQL_CURSOR_TYPE_NO_CURSOR     0
#define MYSQL_CURSOR_TYPE_READ_ONLY     1
#define MYSQL_CURSOR_TYPE_FOR_UPDATE    2
#define MYSQL_CURSOR_TYPE_SCROLLABLE    4
#define MYSQL_PARAMETER_COUNT_AVAILABLE 8

/* MySQL parameter flags -- used internally by the dissector */

#define MYSQL_PARAM_FLAG_STREAMED 0x01

/* Compression states, internal to the dissector */
#define MYSQL_COMPRESS_NONE   0
#define MYSQL_COMPRESS_INIT   1
#define MYSQL_COMPRESS_ACTIVE 2

#define MYSQL_COMPRESS_ALG_ZLIB 0
#define MYSQL_COMPRESS_ALG_ZSTD 1

/* Generic Response Codes */
#define MYSQL_RESPONSE_OK     0x00
#define MYSQL_RESPONSE_ERR    0xFF
#define MYSQL_RESPONSE_EOF    0xFE
#define MYSQL_RESPONSE_INFILE 0xFB

/* mariadb extended keys */
#define MARIADB_EXT_META_TYPE   0
#define MARIADB_EXT_META_FORMAT 1

/* decoding table: command */
static const value_string mysql_command_vals[] = {
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
	{MYSQL_DAEMON, "Daemon"},
	{MYSQL_BINLOG_DUMP_GTID, "Send Binlog GTID"},
	{MYSQL_RESET_CONNECTION, "Reset Connection"},
	{MYSQL_CLONE, "Native cloning"},
	{MYSQL_SUBSCRIBE_GROUP_REPLICATION_STREAM, "Subscribe Group Replication Stream"},
	{MARIADB_STMT_BULK_EXECUTE, "Execute Bulk Statement"},
	{0, NULL}
};
static value_string_ext mysql_command_vals_ext = VALUE_STRING_EXT_INIT(mysql_command_vals);

/* decoding table: exec_flags */
static const value_string mysql_exec_flags_vals[] = {
	{MYSQL_CURSOR_TYPE_NO_CURSOR, "Defaults"},
	{MYSQL_CURSOR_TYPE_READ_ONLY, "Read-only cursor"},
	{MYSQL_CURSOR_TYPE_FOR_UPDATE, "Cursor for update"},
	{MYSQL_CURSOR_TYPE_SCROLLABLE, "Scrollable cursor"},
	{MYSQL_PARAMETER_COUNT_AVAILABLE, "Parameter Count Available"},
	{0, NULL}
};

/* decoding table: new_parameter_bound_flag */
static const value_string mysql_new_parameter_bound_flag_vals[] = {
	{0, "Subsequent call"},
	{1, "First call or rebound"},
	{0, NULL}
};
/*
static const value_string mariadb_bulk_flags_vals[] = {
	{MARIADB_BULK_AUTOID, "Return auto generated IDs"},
	{MARIADB_BULK_SEND_TYPES, "Send types to server"},
	{0, NULL}
};
*/
static const value_string mariadb_bulk_indicator_vals[] = {
	{MARIADB_INDICATOR_NONE, "Not set"},
	{MARIADB_INDICATOR_NULL, "Null Value"},
	{MARIADB_INDICATOR_DEFAULT, "Default Value"},
	{MARIADB_INDICATOR_IGNORE, "Don't Update Value"},
	{MARIADB_INDICATIR_IGNORE_ROW, "Ignore Row"},
	{0, NULL}
};

/* decoding table: exec_time_sign */
static const value_string mysql_exec_time_sign_vals[] = {
	{0, "Positive"},
	{1, "Negative"},
	{0, NULL}
};

/* collation codes may change over time, recreate with the following SQL

SELECT CONCAT('  {', ID, ',"', CHARACTER_SET_NAME, ' COLLATE ', COLLATION_NAME, '"},')
FROM INFORMATION_SCHEMA.COLLATIONS
ORDER BY ID
INTO OUTFILE '/var/lib/mysql-files/mysql-collations';

Last Update from MySQL 8.0.36

*/
static const value_string mysql_collation_vals[] = {
	{1,   "big5 COLLATE big5_chinese_ci"},
	{2,   "latin2 COLLATE latin2_czech_cs"},
	{3,   "dec8 COLLATE dec8_swedish_ci"},
	{4,   "cp850 COLLATE cp850_general_ci"},
	{5,   "latin1 COLLATE latin1_german1_ci"},
	{6,   "hp8 COLLATE hp8_english_ci"},
	{7,   "koi8r COLLATE koi8r_general_ci"},
	{8,   "latin1 COLLATE latin1_swedish_ci"},
	{9,   "latin2 COLLATE latin2_general_ci"},
	{10,  "swe7 COLLATE swe7_swedish_ci"},
	{11,  "ascii COLLATE ascii_general_ci"},
	{12,  "ujis COLLATE ujis_japanese_ci"},
	{13,  "sjis COLLATE sjis_japanese_ci"},
	{14,  "cp1251 COLLATE cp1251_bulgarian_ci"},
	{15,  "latin1 COLLATE latin1_danish_ci"},
	{16,  "hebrew COLLATE hebrew_general_ci"},
	{18,  "tis620 COLLATE tis620_thai_ci"},
	{19,  "euckr COLLATE euckr_korean_ci"},
	{20,  "latin7 COLLATE latin7_estonian_cs"},
	{21,  "latin2 COLLATE latin2_hungarian_ci"},
	{22,  "koi8u COLLATE koi8u_general_ci"},
	{23,  "cp1251 COLLATE cp1251_ukrainian_ci"},
	{24,  "gb2312 COLLATE gb2312_chinese_ci"},
	{25,  "greek COLLATE greek_general_ci"},
	{26,  "cp1250 COLLATE cp1250_general_ci"},
	{27,  "latin2 COLLATE latin2_croatian_ci"},
	{28,  "gbk COLLATE gbk_chinese_ci"},
	{29,  "cp1257 COLLATE cp1257_lithuanian_ci"},
	{30,  "latin5 COLLATE latin5_turkish_ci"},
	{31,  "latin1 COLLATE latin1_german2_ci"},
	{32,  "armscii8 COLLATE armscii8_general_ci"},
	{33,  "utf8mb3 COLLATE utf8mb3_general_ci"},
	{34,  "cp1250 COLLATE cp1250_czech_cs"},
	{35,  "ucs2 COLLATE ucs2_general_ci"},
	{36,  "cp866 COLLATE cp866_general_ci"},
	{37,  "keybcs2 COLLATE keybcs2_general_ci"},
	{38,  "macce COLLATE macce_general_ci"},
	{39,  "macroman COLLATE macroman_general_ci"},
	{40,  "cp852 COLLATE cp852_general_ci"},
	{41,  "latin7 COLLATE latin7_general_ci"},
	{42,  "latin7 COLLATE latin7_general_cs"},
	{43,  "macce COLLATE macce_bin"},
	{44,  "cp1250 COLLATE cp1250_croatian_ci"},
	{45,  "utf8mb4 COLLATE utf8mb4_general_ci"},
	{46,  "utf8mb4 COLLATE utf8mb4_bin"},
	{47,  "latin1 COLLATE latin1_bin"},
	{48,  "latin1 COLLATE latin1_general_ci"},
	{49,  "latin1 COLLATE latin1_general_cs"},
	{50,  "cp1251 COLLATE cp1251_bin"},
	{51,  "cp1251 COLLATE cp1251_general_ci"},
	{52,  "cp1251 COLLATE cp1251_general_cs"},
	{53,  "macroman COLLATE macroman_bin"},
	{54,  "utf16 COLLATE utf16_general_ci"},
	{55,  "utf16 COLLATE utf16_bin"},
	{56,  "utf16le COLLATE utf16le_general_ci"},
	{57,  "cp1256 COLLATE cp1256_general_ci"},
	{58,  "cp1257 COLLATE cp1257_bin"},
	{59,  "cp1257 COLLATE cp1257_general_ci"},
	{60,  "utf32 COLLATE utf32_general_ci"},
	{61,  "utf32 COLLATE utf32_bin"},
	{62,  "utf16le COLLATE utf16le_bin"},
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
	{76,  "utf8mb3 COLLATE utf8mb3_tolower_ci"},
	{77,  "latin2 COLLATE latin2_bin"},
	{78,  "latin5 COLLATE latin5_bin"},
	{79,  "latin7 COLLATE latin7_bin"},
	{80,  "cp850 COLLATE cp850_bin"},
	{81,  "cp852 COLLATE cp852_bin"},
	{82,  "swe7 COLLATE swe7_bin"},
	{83,  "utf8mb3 COLLATE utf8mb3_bin"},
	{84,  "big5 COLLATE big5_bin"},
	{85,  "euckr COLLATE euckr_bin"},
	{86,  "gb2312 COLLATE gb2312_bin"},
	{87,  "gbk COLLATE gbk_bin"},
	{88,  "sjis COLLATE sjis_bin"},
	{89,  "tis620 COLLATE tis620_bin"},
	{90,  "ucs2 COLLATE ucs2_bin"},
	{91,  "ujis COLLATE ujis_bin"},
	{92,  "geostd8 COLLATE geostd8_general_ci"},
	{93,  "geostd8 COLLATE geostd8_bin"},
	{94,  "latin1 COLLATE latin1_spanish_ci"},
	{95,  "cp932 COLLATE cp932_japanese_ci"},
	{96,  "cp932 COLLATE cp932_bin"},
	{97,  "eucjpms COLLATE eucjpms_japanese_ci"},
	{98,  "eucjpms COLLATE eucjpms_bin"},
	{99,  "cp1250 COLLATE cp1250_polish_ci"},
	{101, "utf16 COLLATE utf16_unicode_ci"},
	{102, "utf16 COLLATE utf16_icelandic_ci"},
	{103, "utf16 COLLATE utf16_latvian_ci"},
	{104, "utf16 COLLATE utf16_romanian_ci"},
	{105, "utf16 COLLATE utf16_slovenian_ci"},
	{106, "utf16 COLLATE utf16_polish_ci"},
	{107, "utf16 COLLATE utf16_estonian_ci"},
	{108, "utf16 COLLATE utf16_spanish_ci"},
	{109, "utf16 COLLATE utf16_swedish_ci"},
	{110, "utf16 COLLATE utf16_turkish_ci"},
	{111, "utf16 COLLATE utf16_czech_ci"},
	{112, "utf16 COLLATE utf16_danish_ci"},
	{113, "utf16 COLLATE utf16_lithuanian_ci"},
	{114, "utf16 COLLATE utf16_slovak_ci"},
	{115, "utf16 COLLATE utf16_spanish2_ci"},
	{116, "utf16 COLLATE utf16_roman_ci"},
	{117, "utf16 COLLATE utf16_persian_ci"},
	{118, "utf16 COLLATE utf16_esperanto_ci"},
	{119, "utf16 COLLATE utf16_hungarian_ci"},
	{120, "utf16 COLLATE utf16_sinhala_ci"},
	{121, "utf16 COLLATE utf16_german2_ci"},
	{122, "utf16 COLLATE utf16_croatian_ci"},
	{123, "utf16 COLLATE utf16_unicode_520_ci"},
	{124, "utf16 COLLATE utf16_vietnamese_ci"},
	{128, "ucs2 COLLATE ucs2_unicode_ci"},
	{129, "ucs2 COLLATE ucs2_icelandic_ci"},
	{130, "ucs2 COLLATE ucs2_latvian_ci"},
	{131, "ucs2 COLLATE ucs2_romanian_ci"},
	{132, "ucs2 COLLATE ucs2_slovenian_ci"},
	{133, "ucs2 COLLATE ucs2_polish_ci"},
	{134, "ucs2 COLLATE ucs2_estonian_ci"},
	{135, "ucs2 COLLATE ucs2_spanish_ci"},
	{136, "ucs2 COLLATE ucs2_swedish_ci"},
	{137, "ucs2 COLLATE ucs2_turkish_ci"},
	{138, "ucs2 COLLATE ucs2_czech_ci"},
	{139, "ucs2 COLLATE ucs2_danish_ci"},
	{140, "ucs2 COLLATE ucs2_lithuanian_ci"},
	{141, "ucs2 COLLATE ucs2_slovak_ci"},
	{142, "ucs2 COLLATE ucs2_spanish2_ci"},
	{143, "ucs2 COLLATE ucs2_roman_ci"},
	{144, "ucs2 COLLATE ucs2_persian_ci"},
	{145, "ucs2 COLLATE ucs2_esperanto_ci"},
	{146, "ucs2 COLLATE ucs2_hungarian_ci"},
	{147, "ucs2 COLLATE ucs2_sinhala_ci"},
	{148, "ucs2 COLLATE ucs2_german2_ci"},
	{149, "ucs2 COLLATE ucs2_croatian_ci"},
	{150, "ucs2 COLLATE ucs2_unicode_520_ci"},
	{151, "ucs2 COLLATE ucs2_vietnamese_ci"},
	{159, "ucs2 COLLATE ucs2_general_mysql500_ci"},
	{160, "utf32 COLLATE utf32_unicode_ci"},
	{161, "utf32 COLLATE utf32_icelandic_ci"},
	{162, "utf32 COLLATE utf32_latvian_ci"},
	{163, "utf32 COLLATE utf32_romanian_ci"},
	{164, "utf32 COLLATE utf32_slovenian_ci"},
	{165, "utf32 COLLATE utf32_polish_ci"},
	{166, "utf32 COLLATE utf32_estonian_ci"},
	{167, "utf32 COLLATE utf32_spanish_ci"},
	{168, "utf32 COLLATE utf32_swedish_ci"},
	{169, "utf32 COLLATE utf32_turkish_ci"},
	{170, "utf32 COLLATE utf32_czech_ci"},
	{171, "utf32 COLLATE utf32_danish_ci"},
	{172, "utf32 COLLATE utf32_lithuanian_ci"},
	{173, "utf32 COLLATE utf32_slovak_ci"},
	{174, "utf32 COLLATE utf32_spanish2_ci"},
	{175, "utf32 COLLATE utf32_roman_ci"},
	{176, "utf32 COLLATE utf32_persian_ci"},
	{177, "utf32 COLLATE utf32_esperanto_ci"},
	{178, "utf32 COLLATE utf32_hungarian_ci"},
	{179, "utf32 COLLATE utf32_sinhala_ci"},
	{180, "utf32 COLLATE utf32_german2_ci"},
	{181, "utf32 COLLATE utf32_croatian_ci"},
	{182, "utf32 COLLATE utf32_unicode_520_ci"},
	{183, "utf32 COLLATE utf32_vietnamese_ci"},
	{192, "utf8mb3 COLLATE utf8mb3_unicode_ci"},
	{193, "utf8mb3 COLLATE utf8mb3_icelandic_ci"},
	{194, "utf8mb3 COLLATE utf8mb3_latvian_ci"},
	{195, "utf8mb3 COLLATE utf8mb3_romanian_ci"},
	{196, "utf8mb3 COLLATE utf8mb3_slovenian_ci"},
	{197, "utf8mb3 COLLATE utf8mb3_polish_ci"},
	{198, "utf8mb3 COLLATE utf8mb3_estonian_ci"},
	{199, "utf8mb3 COLLATE utf8mb3_spanish_ci"},
	{200, "utf8mb3 COLLATE utf8mb3_swedish_ci"},
	{201, "utf8mb3 COLLATE utf8mb3_turkish_ci"},
	{202, "utf8mb3 COLLATE utf8mb3_czech_ci"},
	{203, "utf8mb3 COLLATE utf8mb3_danish_ci"},
	{204, "utf8mb3 COLLATE utf8mb3_lithuanian_ci"},
	{205, "utf8mb3 COLLATE utf8mb3_slovak_ci"},
	{206, "utf8mb3 COLLATE utf8mb3_spanish2_ci"},
	{207, "utf8mb3 COLLATE utf8mb3_roman_ci"},
	{208, "utf8mb3 COLLATE utf8mb3_persian_ci"},
	{209, "utf8mb3 COLLATE utf8mb3_esperanto_ci"},
	{210, "utf8mb3 COLLATE utf8mb3_hungarian_ci"},
	{211, "utf8mb3 COLLATE utf8mb3_sinhala_ci"},
	{212, "utf8mb3 COLLATE utf8mb3_german2_ci"},
	{213, "utf8mb3 COLLATE utf8mb3_croatian_ci"},
	{214, "utf8mb3 COLLATE utf8mb3_unicode_520_ci"},
	{215, "utf8mb3 COLLATE utf8mb3_vietnamese_ci"},
	{223, "utf8mb3 COLLATE utf8mb3_general_mysql500_ci"},
	{224, "utf8mb4 COLLATE utf8mb4_unicode_ci"},
	{225, "utf8mb4 COLLATE utf8mb4_icelandic_ci"},
	{226, "utf8mb4 COLLATE utf8mb4_latvian_ci"},
	{227, "utf8mb4 COLLATE utf8mb4_romanian_ci"},
	{228, "utf8mb4 COLLATE utf8mb4_slovenian_ci"},
	{229, "utf8mb4 COLLATE utf8mb4_polish_ci"},
	{230, "utf8mb4 COLLATE utf8mb4_estonian_ci"},
	{231, "utf8mb4 COLLATE utf8mb4_spanish_ci"},
	{232, "utf8mb4 COLLATE utf8mb4_swedish_ci"},
	{233, "utf8mb4 COLLATE utf8mb4_turkish_ci"},
	{234, "utf8mb4 COLLATE utf8mb4_czech_ci"},
	{235, "utf8mb4 COLLATE utf8mb4_danish_ci"},
	{236, "utf8mb4 COLLATE utf8mb4_lithuanian_ci"},
	{237, "utf8mb4 COLLATE utf8mb4_slovak_ci"},
	{238, "utf8mb4 COLLATE utf8mb4_spanish2_ci"},
	{239, "utf8mb4 COLLATE utf8mb4_roman_ci"},
	{240, "utf8mb4 COLLATE utf8mb4_persian_ci"},
	{241, "utf8mb4 COLLATE utf8mb4_esperanto_ci"},
	{242, "utf8mb4 COLLATE utf8mb4_hungarian_ci"},
	{243, "utf8mb4 COLLATE utf8mb4_sinhala_ci"},
	{244, "utf8mb4 COLLATE utf8mb4_german2_ci"},
	{245, "utf8mb4 COLLATE utf8mb4_croatian_ci"},
	{246, "utf8mb4 COLLATE utf8mb4_unicode_520_ci"},
	{247, "utf8mb4 COLLATE utf8mb4_vietnamese_ci"},
	{248,"gb18030 COLLATE gb18030_chinese_ci"},
	{249,"gb18030 COLLATE gb18030_bin"},
	{250,"gb18030 COLLATE gb18030_unicode_520_ci"},
	{255,"utf8mb4 COLLATE utf8mb4_0900_ai_ci"},
	{256,"utf8mb4 COLLATE utf8mb4_de_pb_0900_ai_ci"},
	{257,"utf8mb4 COLLATE utf8mb4_is_0900_ai_ci"},
	{258,"utf8mb4 COLLATE utf8mb4_lv_0900_ai_ci"},
	{259,"utf8mb4 COLLATE utf8mb4_ro_0900_ai_ci"},
	{260,"utf8mb4 COLLATE utf8mb4_sl_0900_ai_ci"},
	{261,"utf8mb4 COLLATE utf8mb4_pl_0900_ai_ci"},
	{262,"utf8mb4 COLLATE utf8mb4_et_0900_ai_ci"},
	{263,"utf8mb4 COLLATE utf8mb4_es_0900_ai_ci"},
	{264,"utf8mb4 COLLATE utf8mb4_sv_0900_ai_ci"},
	{265,"utf8mb4 COLLATE utf8mb4_tr_0900_ai_ci"},
	{266,"utf8mb4 COLLATE utf8mb4_cs_0900_ai_ci"},
	{267,"utf8mb4 COLLATE utf8mb4_da_0900_ai_ci"},
	{268,"utf8mb4 COLLATE utf8mb4_lt_0900_ai_ci"},
	{269,"utf8mb4 COLLATE utf8mb4_sk_0900_ai_ci"},
	{270,"utf8mb4 COLLATE utf8mb4_es_trad_0900_ai_ci"},
	{271,"utf8mb4 COLLATE utf8mb4_la_0900_ai_ci"},
	{273,"utf8mb4 COLLATE utf8mb4_eo_0900_ai_ci"},
	{274,"utf8mb4 COLLATE utf8mb4_hu_0900_ai_ci"},
	{275,"utf8mb4 COLLATE utf8mb4_hr_0900_ai_ci"},
	{277,"utf8mb4 COLLATE utf8mb4_vi_0900_ai_ci"},
	{278,"utf8mb4 COLLATE utf8mb4_0900_as_cs"},
	{279,"utf8mb4 COLLATE utf8mb4_de_pb_0900_as_cs"},
	{280,"utf8mb4 COLLATE utf8mb4_is_0900_as_cs"},
	{281,"utf8mb4 COLLATE utf8mb4_lv_0900_as_cs"},
	{282,"utf8mb4 COLLATE utf8mb4_ro_0900_as_cs"},
	{283,"utf8mb4 COLLATE utf8mb4_sl_0900_as_cs"},
	{284,"utf8mb4 COLLATE utf8mb4_pl_0900_as_cs"},
	{285,"utf8mb4 COLLATE utf8mb4_et_0900_as_cs"},
	{286,"utf8mb4 COLLATE utf8mb4_es_0900_as_cs"},
	{287,"utf8mb4 COLLATE utf8mb4_sv_0900_as_cs"},
	{288,"utf8mb4 COLLATE utf8mb4_tr_0900_as_cs"},
	{289,"utf8mb4 COLLATE utf8mb4_cs_0900_as_cs"},
	{290,"utf8mb4 COLLATE utf8mb4_da_0900_as_cs"},
	{291,"utf8mb4 COLLATE utf8mb4_lt_0900_as_cs"},
	{292,"utf8mb4 COLLATE utf8mb4_sk_0900_as_cs"},
	{293,"utf8mb4 COLLATE utf8mb4_es_trad_0900_as_cs"},
	{294,"utf8mb4 COLLATE utf8mb4_la_0900_as_cs"},
	{296,"utf8mb4 COLLATE utf8mb4_eo_0900_as_cs"},
	{297,"utf8mb4 COLLATE utf8mb4_hu_0900_as_cs"},
	{298,"utf8mb4 COLLATE utf8mb4_hr_0900_as_cs"},
	{300,"utf8mb4 COLLATE utf8mb4_vi_0900_as_cs"},
	{303,"utf8mb4 COLLATE utf8mb4_ja_0900_as_cs"},
	{304,"utf8mb4 COLLATE utf8mb4_ja_0900_as_cs_ks"},
	{305,"utf8mb4 COLLATE utf8mb4_0900_as_ci"},
	{306,"utf8mb4 COLLATE utf8mb4_ru_0900_ai_ci"},
	{307,"utf8mb4 COLLATE utf8mb4_ru_0900_as_cs"},
	{308,"utf8mb4 COLLATE utf8mb4_zh_0900_as_cs"},
	{309,"utf8mb4 COLLATE utf8mb4_0900_bin"},
	{310,"utf8mb4 COLLATE utf8mb4_nb_0900_ai_ci"},
	{311,"utf8mb4 COLLATE utf8mb4_nb_0900_as_cs"},
	{312,"utf8mb4 COLLATE utf8mb4_nn_0900_ai_ci"},
	{313,"utf8mb4 COLLATE utf8mb4_nn_0900_as_cs"},
	{314,"utf8mb4 COLLATE utf8mb4_sr_latn_0900_ai_ci"},
	{315,"utf8mb4 COLLATE utf8mb4_sr_latn_0900_as_cs"},
	{316,"utf8mb4 COLLATE utf8mb4_bs_0900_ai_ci"},
	{317,"utf8mb4 COLLATE utf8mb4_bs_0900_as_cs"},
	{318,"utf8mb4 COLLATE utf8mb4_bg_0900_ai_ci"},
	{319,"utf8mb4 COLLATE utf8mb4_bg_0900_as_cs"},
	{320,"utf8mb4 COLLATE utf8mb4_gl_0900_ai_ci"},
	{321,"utf8mb4 COLLATE utf8mb4_gl_0900_as_cs"},
	{322,"utf8mb4 COLLATE utf8mb4_mn_cyrl_0900_ai_ci"},
	{323,"utf8mb4 COLLATE utf8mb4_mn_cyrl_0900_as_cs"},
	{0, NULL}
};


static value_string_ext mysql_collation_vals_ext = VALUE_STRING_EXT_INIT(mysql_collation_vals);

/* MariaDB specific character sets and collations

   Last Update: MariaDB 10.5.4 */

static const value_string mariadb_collation_vals[] = {
	{1,"big5 COLLATE big5_chinese_ci"},
	{2,"latin2 COLLATE latin2_czech_cs"},
	{3,"dec8 COLLATE dec8_swedish_ci"},
	{4,"cp850 COLLATE cp850_general_ci"},
	{5,"latin1 COLLATE latin1_german1_ci"},
	{6,"hp8 COLLATE hp8_english_ci"},
	{7,"koi8r COLLATE koi8r_general_ci"},
	{8,"latin1 COLLATE latin1_swedish_ci"},
	{9,"latin2 COLLATE latin2_general_ci"},
	{10,"swe7 COLLATE swe7_swedish_ci"},
	{11,"ascii COLLATE ascii_general_ci"},
	{12,"ujis COLLATE ujis_japanese_ci"},
	{13,"sjis COLLATE sjis_japanese_ci"},
	{14,"cp1251 COLLATE cp1251_bulgarian_ci"},
	{15,"latin1 COLLATE latin1_danish_ci"},
	{16,"hebrew COLLATE hebrew_general_ci"},
	{18,"tis620 COLLATE tis620_thai_ci"},
	{19,"euckr COLLATE euckr_korean_ci"},
	{20,"latin7 COLLATE latin7_estonian_cs"},
	{21,"latin2 COLLATE latin2_hungarian_ci"},
	{22,"koi8u COLLATE koi8u_general_ci"},
	{23,"cp1251 COLLATE cp1251_ukrainian_ci"},
	{24,"gb2312 COLLATE gb2312_chinese_ci"},
	{25,"greek COLLATE greek_general_ci"},
	{26,"cp1250 COLLATE cp1250_general_ci"},
	{27,"latin2 COLLATE latin2_croatian_ci"},
	{28,"gbk COLLATE gbk_chinese_ci"},
	{29,"cp1257 COLLATE cp1257_lithuanian_ci"},
	{30,"latin5 COLLATE latin5_turkish_ci"},
	{31,"latin1 COLLATE latin1_german2_ci"},
	{32,"armscii8 COLLATE armscii8_general_ci"},
	{33,"utf8 COLLATE utf8_general_ci"},
	{34,"cp1250 COLLATE cp1250_czech_cs"},
	{35,"ucs2 COLLATE ucs2_general_ci"},
	{36,"cp866 COLLATE cp866_general_ci"},
	{37,"keybcs2 COLLATE keybcs2_general_ci"},
	{38,"macce COLLATE macce_general_ci"},
	{39,"macroman COLLATE macroman_general_ci"},
	{40,"cp852 COLLATE cp852_general_ci"},
	{41,"latin7 COLLATE latin7_general_ci"},
	{42,"latin7 COLLATE latin7_general_cs"},
	{43,"macce COLLATE macce_bin"},
	{44,"cp1250 COLLATE cp1250_croatian_ci"},
	{45,"utf8mb4 COLLATE utf8mb4_general_ci"},
	{46,"utf8mb4 COLLATE utf8mb4_bin"},
	{47,"latin1 COLLATE latin1_bin"},
	{48,"latin1 COLLATE latin1_general_ci"},
	{49,"latin1 COLLATE latin1_general_cs"},
	{50,"cp1251 COLLATE cp1251_bin"},
	{51,"cp1251 COLLATE cp1251_general_ci"},
	{52,"cp1251 COLLATE cp1251_general_cs"},
	{53,"macroman COLLATE macroman_bin"},
	{54,"utf16 COLLATE utf16_general_ci"},
	{55,"utf16 COLLATE utf16_bin"},
	{56,"utf16le COLLATE utf16le_general_ci"},
	{57,"cp1256 COLLATE cp1256_general_ci"},
	{58,"cp1257 COLLATE cp1257_bin"},
	{59,"cp1257 COLLATE cp1257_general_ci"},
	{60,"utf32 COLLATE utf32_general_ci"},
	{61,"utf32 COLLATE utf32_bin"},
	{62,"utf16le COLLATE utf16le_bin"},
	{63,"binary COLLATE binary"},
	{64,"armscii8 COLLATE armscii8_bin"},
	{65,"ascii COLLATE ascii_bin"},
	{66,"cp1250 COLLATE cp1250_bin"},
	{67,"cp1256 COLLATE cp1256_bin"},
	{68,"cp866 COLLATE cp866_bin"},
	{69,"dec8 COLLATE dec8_bin"},
	{70,"greek COLLATE greek_bin"},
	{71,"hebrew COLLATE hebrew_bin"},
	{72,"hp8 COLLATE hp8_bin"},
	{73,"keybcs2 COLLATE keybcs2_bin"},
	{74,"koi8r COLLATE koi8r_bin"},
	{75,"koi8u COLLATE koi8u_bin"},
	{77,"latin2 COLLATE latin2_bin"},
	{78,"latin5 COLLATE latin5_bin"},
	{79,"latin7 COLLATE latin7_bin"},
	{80,"cp850 COLLATE cp850_bin"},
	{81,"cp852 COLLATE cp852_bin"},
	{82,"swe7 COLLATE swe7_bin"},
	{83,"utf8 COLLATE utf8_bin"},
	{84,"big5 COLLATE big5_bin"},
	{85,"euckr COLLATE euckr_bin"},
	{86,"gb2312 COLLATE gb2312_bin"},
	{87,"gbk COLLATE gbk_bin"},
	{88,"sjis COLLATE sjis_bin"},
	{89,"tis620 COLLATE tis620_bin"},
	{90,"ucs2 COLLATE ucs2_bin"},
	{91,"ujis COLLATE ujis_bin"},
	{92,"geostd8 COLLATE geostd8_general_ci"},
	{93,"geostd8 COLLATE geostd8_bin"},
	{94,"latin1 COLLATE latin1_spanish_ci"},
	{95,"cp932 COLLATE cp932_japanese_ci"},
	{96,"cp932 COLLATE cp932_bin"},
	{97,"eucjpms COLLATE eucjpms_japanese_ci"},
	{98,"eucjpms COLLATE eucjpms_bin"},
	{99,"cp1250 COLLATE cp1250_polish_ci"},
	{101,"utf16 COLLATE utf16_unicode_ci"},
	{102,"utf16 COLLATE utf16_icelandic_ci"},
	{103,"utf16 COLLATE utf16_latvian_ci"},
	{104,"utf16 COLLATE utf16_romanian_ci"},
	{105,"utf16 COLLATE utf16_slovenian_ci"},
	{106,"utf16 COLLATE utf16_polish_ci"},
	{107,"utf16 COLLATE utf16_estonian_ci"},
	{108,"utf16 COLLATE utf16_spanish_ci"},
	{109,"utf16 COLLATE utf16_swedish_ci"},
	{110,"utf16 COLLATE utf16_turkish_ci"},
	{111,"utf16 COLLATE utf16_czech_ci"},
	{112,"utf16 COLLATE utf16_danish_ci"},
	{113,"utf16 COLLATE utf16_lithuanian_ci"},
	{114,"utf16 COLLATE utf16_slovak_ci"},
	{115,"utf16 COLLATE utf16_spanish2_ci"},
	{116,"utf16 COLLATE utf16_roman_ci"},
	{117,"utf16 COLLATE utf16_persian_ci"},
	{118,"utf16 COLLATE utf16_esperanto_ci"},
	{119,"utf16 COLLATE utf16_hungarian_ci"},
	{120,"utf16 COLLATE utf16_sinhala_ci"},
	{121,"utf16 COLLATE utf16_german2_ci"},
	{122,"utf16 COLLATE utf16_croatian_mysql561_ci"},
	{123,"utf16 COLLATE utf16_unicode_520_ci"},
	{124,"utf16 COLLATE utf16_vietnamese_ci"},
	{128,"ucs2 COLLATE ucs2_unicode_ci"},
	{129,"ucs2 COLLATE ucs2_icelandic_ci"},
	{130,"ucs2 COLLATE ucs2_latvian_ci"},
	{131,"ucs2 COLLATE ucs2_romanian_ci"},
	{132,"ucs2 COLLATE ucs2_slovenian_ci"},
	{133,"ucs2 COLLATE ucs2_polish_ci"},
	{134,"ucs2 COLLATE ucs2_estonian_ci"},
	{135,"ucs2 COLLATE ucs2_spanish_ci"},
	{136,"ucs2 COLLATE ucs2_swedish_ci"},
	{137,"ucs2 COLLATE ucs2_turkish_ci"},
	{138,"ucs2 COLLATE ucs2_czech_ci"},
	{139,"ucs2 COLLATE ucs2_danish_ci"},
	{140,"ucs2 COLLATE ucs2_lithuanian_ci"},
	{141,"ucs2 COLLATE ucs2_slovak_ci"},
	{142,"ucs2 COLLATE ucs2_spanish2_ci"},
	{143,"ucs2 COLLATE ucs2_roman_ci"},
	{144,"ucs2 COLLATE ucs2_persian_ci"},
	{145,"ucs2 COLLATE ucs2_esperanto_ci"},
	{146,"ucs2 COLLATE ucs2_hungarian_ci"},
	{147,"ucs2 COLLATE ucs2_sinhala_ci"},
	{148,"ucs2 COLLATE ucs2_german2_ci"},
	{149,"ucs2 COLLATE ucs2_croatian_mysql561_ci"},
	{150,"ucs2 COLLATE ucs2_unicode_520_ci"},
	{151,"ucs2 COLLATE ucs2_vietnamese_ci"},
	{159,"ucs2 COLLATE ucs2_general_mysql500_ci"},
	{160,"utf32 COLLATE utf32_unicode_ci"},
	{161,"utf32 COLLATE utf32_icelandic_ci"},
	{162,"utf32 COLLATE utf32_latvian_ci"},
	{163,"utf32 COLLATE utf32_romanian_ci"},
	{164,"utf32 COLLATE utf32_slovenian_ci"},
	{165,"utf32 COLLATE utf32_polish_ci"},
	{166,"utf32 COLLATE utf32_estonian_ci"},
	{167,"utf32 COLLATE utf32_spanish_ci"},
	{168,"utf32 COLLATE utf32_swedish_ci"},
	{169,"utf32 COLLATE utf32_turkish_ci"},
	{170,"utf32 COLLATE utf32_czech_ci"},
	{171,"utf32 COLLATE utf32_danish_ci"},
	{172,"utf32 COLLATE utf32_lithuanian_ci"},
	{173,"utf32 COLLATE utf32_slovak_ci"},
	{174,"utf32 COLLATE utf32_spanish2_ci"},
	{175,"utf32 COLLATE utf32_roman_ci"},
	{176,"utf32 COLLATE utf32_persian_ci"},
	{177,"utf32 COLLATE utf32_esperanto_ci"},
	{178,"utf32 COLLATE utf32_hungarian_ci"},
	{179,"utf32 COLLATE utf32_sinhala_ci"},
	{180,"utf32 COLLATE utf32_german2_ci"},
	{181,"utf32 COLLATE utf32_croatian_mysql561_ci"},
	{182,"utf32 COLLATE utf32_unicode_520_ci"},
	{183,"utf32 COLLATE utf32_vietnamese_ci"},
	{192,"utf8 COLLATE utf8_unicode_ci"},
	{193,"utf8 COLLATE utf8_icelandic_ci"},
	{194,"utf8 COLLATE utf8_latvian_ci"},
	{195,"utf8 COLLATE utf8_romanian_ci"},
	{196,"utf8 COLLATE utf8_slovenian_ci"},
	{197,"utf8 COLLATE utf8_polish_ci"},
	{198,"utf8 COLLATE utf8_estonian_ci"},
	{199,"utf8 COLLATE utf8_spanish_ci"},
	{200,"utf8 COLLATE utf8_swedish_ci"},
	{201,"utf8 COLLATE utf8_turkish_ci"},
	{202,"utf8 COLLATE utf8_czech_ci"},
	{203,"utf8 COLLATE utf8_danish_ci"},
	{204,"utf8 COLLATE utf8_lithuanian_ci"},
	{205,"utf8 COLLATE utf8_slovak_ci"},
	{206,"utf8 COLLATE utf8_spanish2_ci"},
	{207,"utf8 COLLATE utf8_roman_ci"},
	{208,"utf8 COLLATE utf8_persian_ci"},
	{209,"utf8 COLLATE utf8_esperanto_ci"},
	{210,"utf8 COLLATE utf8_hungarian_ci"},
	{211,"utf8 COLLATE utf8_sinhala_ci"},
	{212,"utf8 COLLATE utf8_german2_ci"},
	{213,"utf8 COLLATE utf8_croatian_mysql561_ci"},
	{214,"utf8 COLLATE utf8_unicode_520_ci"},
	{215,"utf8 COLLATE utf8_vietnamese_ci"},
	{223,"utf8 COLLATE utf8_general_mysql500_ci"},
	{224,"utf8mb4 COLLATE utf8mb4_unicode_ci"},
	{225,"utf8mb4 COLLATE utf8mb4_icelandic_ci"},
	{226,"utf8mb4 COLLATE utf8mb4_latvian_ci"},
	{227,"utf8mb4 COLLATE utf8mb4_romanian_ci"},
	{228,"utf8mb4 COLLATE utf8mb4_slovenian_ci"},
	{229,"utf8mb4 COLLATE utf8mb4_polish_ci"},
	{230,"utf8mb4 COLLATE utf8mb4_estonian_ci"},
	{231,"utf8mb4 COLLATE utf8mb4_spanish_ci"},
	{232,"utf8mb4 COLLATE utf8mb4_swedish_ci"},
	{233,"utf8mb4 COLLATE utf8mb4_turkish_ci"},
	{234,"utf8mb4 COLLATE utf8mb4_czech_ci"},
	{235,"utf8mb4 COLLATE utf8mb4_danish_ci"},
	{236,"utf8mb4 COLLATE utf8mb4_lithuanian_ci"},
	{237,"utf8mb4 COLLATE utf8mb4_slovak_ci"},
	{238,"utf8mb4 COLLATE utf8mb4_spanish2_ci"},
	{239,"utf8mb4 COLLATE utf8mb4_roman_ci"},
	{240,"utf8mb4 COLLATE utf8mb4_persian_ci"},
	{241,"utf8mb4 COLLATE utf8mb4_esperanto_ci"},
	{242,"utf8mb4 COLLATE utf8mb4_hungarian_ci"},
	{243,"utf8mb4 COLLATE utf8mb4_sinhala_ci"},
	{244,"utf8mb4 COLLATE utf8mb4_german2_ci"},
	{245,"utf8mb4 COLLATE utf8mb4_croatian_mysql561_ci"},
	{246,"utf8mb4 COLLATE utf8mb4_unicode_520_ci"},
	{247,"utf8mb4 COLLATE utf8mb4_vietnamese_ci"},
	{576,"utf8 COLLATE utf8_croatian_ci"},
	{577,"utf8 COLLATE utf8_myanmar_ci"},
	{578,"utf8 COLLATE utf8_thai_520_w2"},
	{608,"utf8mb4 COLLATE utf8mb4_croatian_ci"},
	{609,"utf8mb4 COLLATE utf8mb4_myanmar_ci"},
	{610,"utf8mb4 COLLATE utf8mb4_thai_520_w2"},
	{640,"ucs2 COLLATE ucs2_croatian_ci"},
	{641,"ucs2 COLLATE ucs2_myanmar_ci"},
	{642,"ucs2 COLLATE ucs2_thai_520_w2"},
	{672,"utf16 COLLATE utf16_croatian_ci"},
	{673,"utf16 COLLATE utf16_myanmar_ci"},
	{674,"utf16 COLLATE utf16_thai_520_w2"},
	{736,"utf32 COLLATE utf32_croatian_ci"},
	{737,"utf32 COLLATE utf32_myanmar_ci"},
	{738,"utf32 COLLATE utf32_thai_520_w2"},
	{1025,"big5 COLLATE big5_chinese_nopad_ci"},
	{1027,"dec8 COLLATE dec8_swedish_nopad_ci"},
	{1028,"cp850 COLLATE cp850_general_nopad_ci"},
	{1030,"hp8 COLLATE hp8_english_nopad_ci"},
	{1031,"koi8r COLLATE koi8r_general_nopad_ci"},
	{1032,"latin1 COLLATE latin1_swedish_nopad_ci"},
	{1033,"latin2 COLLATE latin2_general_nopad_ci"},
	{1034,"swe7 COLLATE swe7_swedish_nopad_ci"},
	{1035,"ascii COLLATE ascii_general_nopad_ci"},
	{1036,"ujis COLLATE ujis_japanese_nopad_ci"},
	{1037,"sjis COLLATE sjis_japanese_nopad_ci"},
	{1040,"hebrew COLLATE hebrew_general_nopad_ci"},
	{1042,"tis620 COLLATE tis620_thai_nopad_ci"},
	{1043,"euckr COLLATE euckr_korean_nopad_ci"},
	{1046,"koi8u COLLATE koi8u_general_nopad_ci"},
	{1048,"gb2312 COLLATE gb2312_chinese_nopad_ci"},
	{1049,"greek COLLATE greek_general_nopad_ci"},
	{1050,"cp1250 COLLATE cp1250_general_nopad_ci"},
	{1052,"gbk COLLATE gbk_chinese_nopad_ci"},
	{1054,"latin5 COLLATE latin5_turkish_nopad_ci"},
	{1056,"armscii8 COLLATE armscii8_general_nopad_ci"},
	{1057,"utf8 COLLATE utf8_general_nopad_ci"},
	{1059,"ucs2 COLLATE ucs2_general_nopad_ci"},
	{1060,"cp866 COLLATE cp866_general_nopad_ci"},
	{1061,"keybcs2 COLLATE keybcs2_general_nopad_ci"},
	{1062,"macce COLLATE macce_general_nopad_ci"},
	{1063,"macroman COLLATE macroman_general_nopad_ci"},
	{1064,"cp852 COLLATE cp852_general_nopad_ci"},
	{1065,"latin7 COLLATE latin7_general_nopad_ci"},
	{1067,"macce COLLATE macce_nopad_bin"},
	{1069,"utf8mb4 COLLATE utf8mb4_general_nopad_ci"},
	{1070,"utf8mb4 COLLATE utf8mb4_nopad_bin"},
	{1071,"latin1 COLLATE latin1_nopad_bin"},
	{1074,"cp1251 COLLATE cp1251_nopad_bin"},
	{1075,"cp1251 COLLATE cp1251_general_nopad_ci"},
	{1077,"macroman COLLATE macroman_nopad_bin"},
	{1078,"utf16 COLLATE utf16_general_nopad_ci"},
	{1079,"utf16 COLLATE utf16_nopad_bin"},
	{1080,"utf16le COLLATE utf16le_general_nopad_ci"},
	{1081,"cp1256 COLLATE cp1256_general_nopad_ci"},
	{1082,"cp1257 COLLATE cp1257_nopad_bin"},
	{1083,"cp1257 COLLATE cp1257_general_nopad_ci"},
	{1084,"utf32 COLLATE utf32_general_nopad_ci"},
	{1085,"utf32 COLLATE utf32_nopad_bin"},
	{1086,"utf16le COLLATE utf16le_nopad_bin"},
	{1088,"armscii8 COLLATE armscii8_nopad_bin"},
	{1089,"ascii COLLATE ascii_nopad_bin"},
	{1090,"cp1250 COLLATE cp1250_nopad_bin"},
	{1091,"cp1256 COLLATE cp1256_nopad_bin"},
	{1092,"cp866 COLLATE cp866_nopad_bin"},
	{1093,"dec8 COLLATE dec8_nopad_bin"},
	{1094,"greek COLLATE greek_nopad_bin"},
	{1095,"hebrew COLLATE hebrew_nopad_bin"},
	{1096,"hp8 COLLATE hp8_nopad_bin"},
	{1097,"keybcs2 COLLATE keybcs2_nopad_bin"},
	{1098,"koi8r COLLATE koi8r_nopad_bin"},
	{1099,"koi8u COLLATE koi8u_nopad_bin"},
	{1101,"latin2 COLLATE latin2_nopad_bin"},
	{1102,"latin5 COLLATE latin5_nopad_bin"},
	{1103,"latin7 COLLATE latin7_nopad_bin"},
	{1104,"cp850 COLLATE cp850_nopad_bin"},
	{1105,"cp852 COLLATE cp852_nopad_bin"},
	{1106,"swe7 COLLATE swe7_nopad_bin"},
	{1107,"utf8 COLLATE utf8_nopad_bin"},
	{1108,"big5 COLLATE big5_nopad_bin"},
	{1109,"euckr COLLATE euckr_nopad_bin"},
	{1110,"gb2312 COLLATE gb2312_nopad_bin"},
	{1111,"gbk COLLATE gbk_nopad_bin"},
	{1112,"sjis COLLATE sjis_nopad_bin"},
	{1113,"tis620 COLLATE tis620_nopad_bin"},
	{1114,"ucs2 COLLATE ucs2_nopad_bin"},
	{1115,"ujis COLLATE ujis_nopad_bin"},
	{1116,"geostd8 COLLATE geostd8_general_nopad_ci"},
	{1117,"geostd8 COLLATE geostd8_nopad_bin"},
	{1119,"cp932 COLLATE cp932_japanese_nopad_ci"},
	{1120,"cp932 COLLATE cp932_nopad_bin"},
	{1121,"eucjpms COLLATE eucjpms_japanese_nopad_ci"},
	{1122,"eucjpms COLLATE eucjpms_nopad_bin"},
	{1125,"utf16 COLLATE utf16_unicode_nopad_ci"},
	{1147,"utf16 COLLATE utf16_unicode_520_nopad_ci"},
	{1152,"ucs2 COLLATE ucs2_unicode_nopad_ci"},
	{1174,"ucs2 COLLATE ucs2_unicode_520_nopad_ci"},
	{1184,"utf32 COLLATE utf32_unicode_nopad_ci"},
	{1206,"utf32 COLLATE utf32_unicode_520_nopad_ci"},
	{1216,"utf8 COLLATE utf8_unicode_nopad_ci"},
	{1238,"utf8 COLLATE utf8_unicode_520_nopad_ci"},
	{1248,"utf8mb4 COLLATE utf8mb4_unicode_nopad_ci"},
	{1270,"utf8mb4 COLLATE utf8mb4_unicode_520_nopad_ci"},
	{0, NULL}
};


static value_string_ext mariadb_collation_vals_ext = VALUE_STRING_EXT_INIT(mariadb_collation_vals);

typedef struct {
	const char *charset;
	unsigned    encoding;
} charset_encoding_t;

static charset_encoding_t charset_encoding_array[] =
{
	/* When character_set_results is set to NULL or "binary", that
	 * tells the server to perform no conversion. The field charset
	 * should still be indicated in the column description. Error
	 * messages use presumably the server default.
	 */
	{ "utf8mb4",	ENC_UTF_8 },
	{ "utf8",	ENC_UTF_8 }, // We don't care about the distinction
	{ "utf8mb3",	ENC_UTF_8 },
	{ "latin1",	ENC_WINDOWS_1252 }, // Not ENC_ISO_8859_1
	{ "ascii",	ENC_ASCII },
	// armscii8
	// big5
	{ "binary",	ENC_NA},
	{ "cp1250",	ENC_WINDOWS_1250 },
	{ "cp1251",	ENC_WINDOWS_1251 },
	// cp1256
	// cp1257
	// cp850
	// cp852
	{ "cp866",	ENC_CP866 },
	// cp932 - https://dev.mysql.com/doc/refman/8.0/en/charset-cp932.html
	// dec8
	// eucjpms
	{ "euckr",	ENC_EUC_KR },
	{ "gb18030",	ENC_GB18030 },
	{ "gb2312",	ENC_GB18030 }, // Backwards compatible
	{ "gbk",	ENC_GB18030 }, // Backwards compatible
	// geostd8 - https://datatracker.ietf.org/doc/html/draft-giasher-geostd8-00
	{ "greek",	ENC_ISO_8859_7 },
	{ "hebrew",	ENC_ISO_8859_8 },
	// hp8
	// keybcs2
	// koi8r
	// koi8u
	{ "latin2",	ENC_ISO_8859_2 },
	{ "latin5",	ENC_ISO_8859_9 },
	{ "latin7",	ENC_ISO_8859_13 },
	// macce
	{ "macroman",	ENC_MAC_ROMAN },
	// sjis
	// swe7
	// tis620
	{ "ucs2",	ENC_UCS_2 },
	// ujis
	{ "utf16",	ENC_UTF_16 | ENC_BIG_ENDIAN },
	{ "utf16le",	ENC_UTF_16 | ENC_LITTLE_ENDIAN },
	{ "utf32",	ENC_UCS_4 }
};

static unsigned charset_to_encoding(const char *charset)
{
	if (charset == NULL) {
		return ENC_UTF_8;
	}
	// Allows passing in a collation string
	size_t token_len = strcspn(charset, " ");
	for (size_t i = 0; i < array_length(charset_encoding_array); i++) {
		if (strncmp(charset, charset_encoding_array[i].charset, token_len) == 0) {
			return charset_encoding_array[i].encoding;
		}
	}
	return ENC_UTF_8;
}

static unsigned collation_to_encoding(const unsigned collation, bool is_mariadb)
{
	// We are concerned with the character_set_client and character_set_results
	// system variables.
	// latin1 means ENC_WINDOWS_1252, not ISO-8859-1
	// MariaDB defaulted to latin1 before 10.6.15-10:
	// https://mariadb.com/docs/server/ref/mdb/system-variables/character_set_client/
	// https://mariadb.com/docs/server/ref/mdb/system-variables/character_set_results/
	// MySQL uses utf8m4 in 8.0 and utf8 (meaning utf8m3) in 5.7
	// https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_character_set_client
	// https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_character_set_client
	const char* collation_str;
	collation_str = try_val_to_str_ext(collation, is_mariadb ? &mariadb_collation_vals_ext : &mysql_collation_vals_ext);
	return charset_to_encoding(collation_str);
}

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

static const value_string mysql_session_track_type_vals[] = {
	{0, "SESSION_SYSVARS_TRACKER"},
	{1, "CURRENT_SCHEMA_TRACKER"},
	{2, "SESSION_STATE_CHANGE_TRACKER"},
	{3, "SESSION_TRACK_GTIDS"},
	{4, "SESSION_TRACK_TRANSACTION_CHARACTERISTICS"},
	{5, "SESSION_TRACK_TRANSACTION_STATE"},
	{0, NULL}
};

static const value_string mysql_response_code_vals[] = {
    { MYSQL_RESPONSE_OK,     "OK Packet" },
    { MYSQL_RESPONSE_ERR,    "ERR Packet" },
    { MYSQL_RESPONSE_EOF,    "EOF Packet" },
    { MYSQL_RESPONSE_INFILE, "LOCAL INFILE Packet" },
    { 0, NULL }
};

/* protocol id */
static int proto_mysql;

/* dissector configuration */
static bool mysql_desegment = true;
static bool mysql_showquery;

/* expand-the-tree flags */
static int ett_mysql;
static int ett_server_greeting;
static int ett_login_request;
static int ett_caps;
static int ett_extcaps;
static int ett_stat;
static int ett_row_value;
static int ett_request;
static int ett_query_attributes;
static int ett_refresh;
static int ett_field_flags;
static int ett_exec_param;
static int ett_bulk_param;
static int ett_session_track;
static int ett_session_track_data;
static int ett_extmeta;
static int ett_extmeta_data;
static int ett_connattrs;
static int ett_connattrs_attr;
static int ett_mysql_field;
static int ett_binlog_event;
static int ett_binlog_event_hb_v2;
static int ett_mysql_binary_field;

/* protocol fields */
static int hf_mysql_caps_server;
static int hf_mysql_caps_client;
static int hf_mysql_cap_long_password;
static int hf_mysql_cap_found_rows;
static int hf_mysql_cap_long_flag;
static int hf_mysql_cap_connect_with_db;
static int hf_mysql_cap_no_schema;
static int hf_mysql_cap_compress;
static int hf_mysql_cap_odbc;
static int hf_mysql_cap_local_files;
static int hf_mysql_cap_ignore_space;
static int hf_mysql_cap_change_user;
static int hf_mysql_cap_interactive;
static int hf_mysql_cap_ssl;
static int hf_mysql_cap_ignore_sigpipe;
static int hf_mysql_cap_transactions;
static int hf_mysql_cap_reserved;
static int hf_mysql_cap_secure_connect;
static int hf_mysql_extcaps_server;
static int hf_mysql_extcaps_client;
static int hf_mysql_cap_multi_statements;
static int hf_mysql_cap_multi_results;
static int hf_mysql_cap_ps_multi_results;
static int hf_mysql_cap_plugin_auth;
static int hf_mysql_cap_connect_attrs;
static int hf_mysql_cap_plugin_auth_lenenc_client_data;
static int hf_mysql_cap_client_can_handle_expired_passwords;
static int hf_mysql_cap_session_track;
static int hf_mysql_cap_deprecate_eof;
static int hf_mysql_cap_optional_metadata;
static int hf_mysql_cap_compress_zstd;
static int hf_mysql_cap_query_attrs;
static int hf_mysql_cap_mf_auth;
static int hf_mysql_cap_cap_ext;
static int hf_mysql_cap_ssl_verify_server_cert;
static int hf_mysql_cap_unused;
static int hf_mysql_server_language;
static int hf_mysql_server_status;
static int hf_mysql_stat_it;
static int hf_mysql_stat_ac;
static int hf_mysql_stat_mr;
static int hf_mysql_stat_mu;
static int hf_mysql_stat_bi;
static int hf_mysql_stat_ni;
static int hf_mysql_stat_cr;
static int hf_mysql_stat_lr;
static int hf_mysql_stat_dr;
static int hf_mysql_stat_bs;
static int hf_mysql_stat_mc;
static int hf_mysql_stat_session_state_changed;
static int hf_mysql_stat_query_was_slow;
static int hf_mysql_stat_ps_out_params;
static int hf_mysql_stat_trans_readonly;
static int hf_mysql_refresh;
static int hf_mysql_rfsh_grants;
static int hf_mysql_rfsh_log;
static int hf_mysql_rfsh_tables;
static int hf_mysql_rfsh_hosts;
static int hf_mysql_rfsh_status;
static int hf_mysql_rfsh_threads;
static int hf_mysql_rfsh_slave;
static int hf_mysql_rfsh_master;
static int hf_mysql_packet_length;
static int hf_mysql_packet_number;
static int hf_mysql_request;
static int hf_mysql_command;
static int hf_mysql_response_code;
static int hf_mysql_error_code;
static int hf_mysql_error_string;
static int hf_mysql_sqlstate;
static int hf_mysql_message;
static int hf_mysql_payload;
static int hf_mysql_server_greeting;
static int hf_mysql_session_track;
static int hf_mysql_session_track_type;
static int hf_mysql_session_track_length;
static int hf_mysql_session_track_data;
static int hf_mysql_session_track_data_length;
static int hf_mysql_session_track_sysvar_length;
static int hf_mysql_session_track_sysvar_name;
static int hf_mysql_session_track_sysvar_value;
static int hf_mysql_session_track_schema;
static int hf_mysql_session_track_schema_length;
static int hf_mysql_session_state_change;
static int hf_mysql_session_track_gtids;
static int hf_mysql_session_track_gtids_encoding;
static int hf_mysql_session_track_gtids_length;
static int hf_mysql_session_track_transaction_characteristics;
static int hf_mysql_session_track_transaction_characteristics_length;
static int hf_mysql_session_track_transaction_state;
static int hf_mysql_session_track_transaction_state_length;
static int hf_mysql_protocol;
static int hf_mysql_version;
static int hf_mysql_login_request;
static int hf_mysql_max_packet;
static int hf_mysql_user;
static int hf_mysql_table_name;
static int hf_mysql_schema;
static int hf_mysql_client_auth_plugin;
static int hf_mysql_connattrs;
static int hf_mysql_connattrs_length;
static int hf_mysql_connattrs_attr;
static int hf_mysql_connattrs_name_length;
static int hf_mysql_connattrs_name;
static int hf_mysql_connattrs_value_length;
static int hf_mysql_connattrs_value;
static int hf_mysql_zstd_compression_level;
static int hf_mysql_thread_id;
static int hf_mysql_salt;
static int hf_mysql_salt2;
static int hf_mysql_auth_plugin_length;
static int hf_mysql_auth_plugin;
static int hf_mysql_collation;
static int hf_mysql_passwd;
static int hf_mysql_unused;
static int hf_mysql_affected_rows;
static int hf_mysql_insert_id;
static int hf_mysql_num_warn;
static int hf_mysql_stmt_id;
static int hf_mysql_query_attributes;
static int hf_mysql_query_attributes_count;
static int hf_mysql_query_attributes_send_types_to_server;
static int hf_mysql_query_attribute_name_type;
static int hf_mysql_query_attribute_name;
static int hf_mysql_query_attribute_value;
static int hf_mysql_query;
static int hf_mysql_shutdown;
static int hf_mysql_option;
static int hf_mysql_num_rows;
static int hf_mysql_param;
static int hf_mysql_param_name;
static int hf_mysql_num_params;
static int hf_mysql_exec_flags4;
static int hf_mysql_exec_flags5;
static int hf_mysql_exec_iter;
static int hf_mysql_binlog_position;
static int hf_mysql_binlog_position8;
static int hf_mysql_binlog_flags;
static int hf_mysql_binlog_server_id;
static int hf_mysql_binlog_file_name;
static int hf_mysql_binlog_file_name_length;
static int hf_mysql_binlog_slave_hostname_length;
static int hf_mysql_binlog_slave_hostname;
static int hf_mysql_binlog_slave_user_length;
static int hf_mysql_binlog_slave_user;
static int hf_mysql_binlog_slave_password_length;
static int hf_mysql_binlog_slave_password;
static int hf_mysql_binlog_slave_mysql_port;
static int hf_mysql_binlog_replication_rank;
static int hf_mysql_binlog_master_id;
static int hf_mysql_binlog_event_header_timestamp;
static int hf_mysql_binlog_event_header_event_type;
static int hf_mysql_binlog_event_header_server_id;
static int hf_mysql_binlog_event_header_event_size;
static int hf_mysql_binlog_event_header_log_position;
static int hf_mysql_binlog_event_header_flags;
static int hf_mysql_binlog_event_checksum;
static int hf_mysql_binlog_event_heartbeat_v2;
static int hf_mysql_binlog_event_heartbeat_v2_otw;
static int hf_mysql_binlog_event_heartbeat_v2_otw_type;
static int hf_mysql_binlog_gtid_data;
static int hf_mysql_binlog_gtid_data_length;
static int hf_mysql_binlog_hb_event_filename;
static int hf_mysql_binlog_hb_event_log_position;
static int hf_mysql_clone_command_code;
static int hf_mysql_clone_response_code;
static int hf_mysql_eof;
static int hf_mysql_num_fields;
static int hf_mysql_extra;
static int hf_mysql_fld_catalog;
static int hf_mysql_fld_db;
static int hf_mysql_fld_table;
static int hf_mysql_fld_org_table;
static int hf_mysql_fld_name;
static int hf_mysql_fld_org_name;
static int hf_mysql_fld_charsetnr;
static int hf_mysql_fld_length;
static int hf_mysql_fld_type;
static int hf_mysql_fld_flags;
static int hf_mysql_fld_not_null;
static int hf_mysql_fld_primary_key;
static int hf_mysql_fld_unique_key;
static int hf_mysql_fld_multiple_key;
static int hf_mysql_fld_blob;
static int hf_mysql_fld_unsigned;
static int hf_mysql_fld_zero_fill;
static int hf_mysql_exec_field_null;
static int hf_mysql_null_buffer;
static int hf_mysql_fld_enum;
static int hf_mysql_fld_auto_increment;
static int hf_mysql_fld_timestamp;
static int hf_mysql_fld_set;
static int hf_mysql_fld_decimals;
static int hf_mysql_fld_default;
static int hf_mysql_row_text;
static int hf_mysql_new_parameter_bound_flag;
static int hf_mysql_exec_param;
static int hf_mysql_exec_unsigned;
static int hf_mysql_exec_field_longlong;
static int hf_mysql_exec_field_unsigned_longlong;
static int hf_mysql_exec_field_bit_length;
static int hf_mysql_exec_field_bit;
static int hf_mysql_exec_field_blob_length;
static int hf_mysql_exec_field_blob;
static int hf_mysql_exec_field_geometry_length;
static int hf_mysql_exec_field_geometry;
static int hf_mysql_exec_field_json_length;
static int hf_mysql_exec_field_string_length;
static int hf_mysql_exec_field_string;
static int hf_mysql_exec_field_double;
static int hf_mysql_exec_field_datetime_length;
static int hf_mysql_exec_field_year;
static int hf_mysql_exec_field_month;
static int hf_mysql_exec_field_day;
static int hf_mysql_exec_field_hour;
static int hf_mysql_exec_field_minute;
static int hf_mysql_exec_field_second;
static int hf_mysql_exec_field_second_b;
static int hf_mysql_exec_field_int24;
static int hf_mysql_exec_field_long;
static int hf_mysql_exec_field_unsigned_long;
static int hf_mysql_exec_field_tiny;
static int hf_mysql_exec_field_unsigned_tiny;
static int hf_mysql_exec_field_short;
static int hf_mysql_exec_field_unsigned_short;
static int hf_mysql_exec_field_float;
static int hf_mysql_exec_field_time_length;
static int hf_mysql_exec_field_time_sign;
static int hf_mysql_exec_field_time_days;
static int hf_mysql_auth_switch_request_status;
static int hf_mysql_auth_switch_request_name;
static int hf_mysql_auth_switch_request_data;
static int hf_mysql_auth_switch_response_data;
static int hf_mysql_sha2_auth;
static int hf_mysql_sha2_response;
static int hf_mysql_pubkey;
static int hf_mysql_compressed_packet_length;
static int hf_mysql_compressed_packet_length_uncompressed;
static int hf_mysql_compressed_packet_number;
static int hf_mysql_loaddata_filename;
static int hf_mysql_loaddata_payload;

//static int hf_mariadb_fld_charsetnr;
static int hf_mariadb_server_language;
static int hf_mariadb_collation;
static int hf_mariadb_cap_progress;
static int hf_mariadb_cap_commulti;
static int hf_mariadb_cap_bulk;
static int hf_mariadb_cap_extmetadata;
static int hf_mariadb_cap_cache_metadata;
static int hf_mariadb_extcaps_server;
static int hf_mariadb_extcaps_client;
static int hf_mariadb_bulk_flag_autoid;
static int hf_mariadb_bulk_flag_sendtypes;
static int hf_mariadb_bulk_caps_flags;
static int hf_mariadb_bulk_paramtypes;
static int hf_mariadb_bulk_indicator;
static int hf_mariadb_bulk_row_nr;
static int hf_mariadb_send_meta;
static int hf_mariadb_extmeta;
static int hf_mariadb_extmeta_data;
static int hf_mariadb_extmeta_length;
static int hf_mariadb_extmeta_key;
static int hf_mariadb_extmeta_type;
static int hf_mariadb_extmeta_format;

static dissector_handle_t mysql_handle;
static dissector_handle_t decompressed_handle;
static dissector_handle_t tls_handle;

static expert_field ei_mysql_dissector_incomplete;
static expert_field ei_mysql_streamed_param;
static expert_field ei_mysql_prepare_response_needed;
static expert_field ei_mysql_unknown_response;
static expert_field ei_mysql_command;
static expert_field ei_mysql_invalid_length;
static expert_field ei_mysql_compression;

/* Reassembly of decompressed packets in compressed packets {{{ */

static int hf_mysql_fragments;
static int hf_mysql_fragment;
static int hf_mysql_fragment_overlap;
static int hf_mysql_fragment_overlap_conflicts;
static int hf_mysql_fragment_multiple_tails;
static int hf_mysql_fragment_too_long_fragment;
static int hf_mysql_fragment_error;
static int hf_mysql_fragment_count;
static int hf_mysql_reassembled_in;
static int hf_mysql_reassembled_length;
static int hf_mysql_fragment_data;

static int ett_mysql_fragment;
static int ett_mysql_fragments;

static const fragment_items mysql_frag_items = {
	&ett_mysql_fragment,
	&ett_mysql_fragments,
	&hf_mysql_fragments,
	&hf_mysql_fragment,
	&hf_mysql_fragment_overlap,
	&hf_mysql_fragment_overlap_conflicts,
	&hf_mysql_fragment_multiple_tails,
	&hf_mysql_fragment_too_long_fragment,
	&hf_mysql_fragment_error,
	&hf_mysql_fragment_count,
	&hf_mysql_reassembled_in,
	&hf_mysql_reassembled_length,
	NULL,
	"MySQL fragments"
};

static reassembly_table mysql_reassembly_table;

/* }}} Reassembly of decompressed packets */

/* type constants */
static const value_string type_constants[] = {
	{0x00, "FIELD_TYPE_DECIMAL"    },
	{0x01, "FIELD_TYPE_TINY"       },
	{0x02, "FIELD_TYPE_SHORT"      },
	{0x03, "FIELD_TYPE_LONG"       },
	{0x04, "FIELD_TYPE_FLOAT"      },
	{0x05, "FIELD_TYPE_DOUBLE"     },
	{0x06, "FIELD_TYPE_NULL"       },
	{0x07, "FIELD_TYPE_TIMESTAMP"  },
	{0x08, "FIELD_TYPE_LONGLONG"   },
	{0x09, "FIELD_TYPE_INT24"      },
	{0x0a, "FIELD_TYPE_DATE"       },
	{0x0b, "FIELD_TYPE_TIME"       },
	{0x0c, "FIELD_TYPE_DATETIME"   },
	{0x0d, "FIELD_TYPE_YEAR"       },
	{0x0e, "FIELD_TYPE_NEWDATE"    },
	{0x0f, "FIELD_TYPE_VARCHAR"    },
	{0x10, "FIELD_TYPE_BIT"        },
	{0xf5, "FIELD_TYPE_JSON"       },
	{0xf6, "FIELD_TYPE_NEWDECIMAL" },
	{0xf7, "FIELD_TYPE_ENUM"       },
	{0xf8, "FIELD_TYPE_SET"        },
	{0xf9, "FIELD_TYPE_TINY_BLOB"  },
	{0xfa, "FIELD_TYPE_MEDIUM_BLOB"},
	{0xfb, "FIELD_TYPE_LONG_BLOB"  },
	{0xfc, "FIELD_TYPE_BLOB"       },
	{0xfd, "FIELD_TYPE_VAR_STRING" },
	{0xfe, "FIELD_TYPE_STRING"     },
	{0xff, "FIELD_TYPE_GEOMETRY"   },
	{0, NULL}
};

typedef enum mysql_state {
	UNDEFINED,
	LOGIN,
	REQUEST,
	RESPONSE_OK,
	RESPONSE_ERROR,
	RESPONSE_EOF,
	INTERMEDIATE_EOF,
	RESPONSE_MESSAGE,
	RESPONSE_TABULAR,
	RESPONSE_SHOW_FIELDS,
	FIELD_PACKET,
	ROW_PACKET,
	COLUMN_COUNT,
	RESPONSE_PREPARE,
	PREPARED_PARAMETERS,
	PREPARED_FIELDS,
	AUTH_SWITCH_REQUEST,
	AUTH_SWITCH_RESPONSE,
	AUTH_SHA2,
	AUTH_PUBKEY,
	AUTH_SHA2_RESPONSE,
	BINLOG_DUMP,
	CLONE_INIT,
	CLONE_ACTIVE,
	CLONE_EXIT,
	RESPONSE_LOCALINFILE,
	INFILE_DATA
} mysql_state_t;

static const value_string state_vals[] = {
	{UNDEFINED,            "undefined"},
	{LOGIN,                "login"},
	{REQUEST,              "request"},
	{RESPONSE_OK,          "response OK"},
	{RESPONSE_ERROR,       "response ERROR"},
	{RESPONSE_EOF,         "response EOF"},
	{INTERMEDIATE_EOF,     "intermediate EOF"},
	{RESPONSE_MESSAGE,     "response message"},
	{RESPONSE_TABULAR,     "tabular response"},
	{RESPONSE_SHOW_FIELDS, "response to SHOW FIELDS"},
	{FIELD_PACKET,         "field packet"},
	{ROW_PACKET,           "row packet"},
	{COLUMN_COUNT,         "column count"},
	{RESPONSE_PREPARE,     "response to PREPARE"},
	{PREPARED_PARAMETERS,  "parameters in response to PREPARE"},
	{PREPARED_FIELDS,      "fields in response to PREPARE"},
	{AUTH_SWITCH_REQUEST,  "authentication switch request"},
	{AUTH_SWITCH_RESPONSE, "authentication switch response"},
	{AUTH_SHA2,            "caching_sha2_password"},
	{AUTH_PUBKEY,          "public key request"},
	{AUTH_SHA2_RESPONSE,   "caching_sha2_password response"},
	{BINLOG_DUMP,          "binlog event"},
	{CLONE_INIT,           "cloning initializing"},
	{CLONE_ACTIVE,         "cloning active"},
	{CLONE_EXIT,           "cloning shutting down"},
	{RESPONSE_LOCALINFILE, "local infile"},
	{INFILE_DATA,          "local infile data"},
	{0, NULL}
};

typedef enum mysql_resultset_fmt {
	TEXT,
	BINARY
} mysql_resultset_fmt_t;

#define MAX_MY_METADATA_COUNT INT16_MAX // Arbitrary; is 32k enough?
typedef struct {
	uint16_t count;
	uint16_t* flags;
	uint8_t* types;
	unsigned* encodings;
} my_metadata_list_t;

/* Data for the entire conversation. Most data is fixed once known.
 * For data which changes from packet to packet such as the state,
 * this holds the value of the last value seen during the first
 * sequential pass. On subsequent passes, for random packet access,
 * the per-packet frame data below should be used to access the state.
 */
typedef struct mysql_conn_data {
	uint16_t srv_caps;
	uint16_t srv_caps_ext;
	uint16_t clnt_caps;
	uint16_t clnt_caps_ext;
	wmem_tree_t* stmts;
#ifdef CTDEBUG
	uint32_t generation;
#endif
	uint8_t major_version;
	uint32_t frame_start_ssl;
	uint32_t frame_start_compressed;
	uint8_t compressed_state;
	uint8_t compressed_alg;
	bool is_mariadb_server; /* set to 1, if connected to a MariaDB server */
	bool is_mariadb_client; /* set to 1, if connected from a MariaDB client */
	uint32_t mariadb_server_ext_caps;
	uint32_t mariadb_client_ext_caps;
	uint8_t *auth_method;
	streaming_reassembly_info_t *reassembly_info;

	/* The members below refer to the latest state or prepared statement,
	 * and is only valid during the first pass. For random access on
	 * later passes, use the data stored in the mysql_frame_data. */
	mysql_state_t state;
	mysql_resultset_fmt_t resultset_fmt;
	uint32_t stmt_id;
	uint64_t remaining_field_packet_count;
	my_metadata_list_t field_metas;
	unsigned encoding_client;
	unsigned encoding_results;
} mysql_conn_data_t;

/* Data stored for a particular PDU. Use this on random access after
 * the first pass to obtain the state at the start of a PDU.
 */
typedef struct mysql_frame_data {
	mysql_state_t state;
	mysql_resultset_fmt_t resultset_fmt;
	uint32_t stmt_id; /* The last prepared stmt ID before this PDU */
	uint64_t remaining_field_packet_count;
	my_metadata_list_t field_metas;
	unsigned encoding_client;
	unsigned encoding_results;
} mysql_frame_data_t;

typedef struct my_stmt_data {
	my_metadata_list_t param_metas;
	my_metadata_list_t field_metas;
	uint16_t bulk_flags;
} my_stmt_data_t;

typedef struct mysql_exec_dissector {
	uint8_t type;
	uint8_t unsigned_flag;
	void (*dissector)(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned charset);
} mysql_exec_dissector_t;

/* function prototypes */
static int mysql_dissect_error_packet(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, const mysql_frame_data_t *my_frame_data);
static int mysql_dissect_ok_packet(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data);
static int mysql_dissect_server_status(tvbuff_t *tvb, int offset, proto_tree *tree, uint16_t *server_status);
static int mysql_dissect_caps(tvbuff_t *tvb, int offset, proto_tree *tree, int mysql_caps, uint16_t *caps);
static int mysql_dissect_extcaps(tvbuff_t *tvb, int offset, proto_tree *tree, int mysql_extcaps, uint16_t *caps);
static int mysql_dissect_result_header(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data, const mysql_frame_data_t *my_frame_data);
static int mysql_dissect_field_packet(tvbuff_t *tvb, proto_item *pi, int offset, proto_tree *tree, packet_info *pinfo, mysql_conn_data_t *conn_data, const mysql_frame_data_t *my_frame_data);
static int mysql_dissect_text_row_packet(tvbuff_t *tvb, int offset, proto_tree *tree, const mysql_frame_data_t *my_frame_data);
static int mysql_dissect_binary_row_packet(tvbuff_t *tvb, packet_info *pinfo, proto_item *pi, int offset, proto_tree *tree, mysql_conn_data_t *conn_data, const mysql_frame_data_t *my_frame_data);
static int mysql_dissect_binlog_event_packet(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, proto_item *pi);
static int mysql_dissect_response_prepare(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data);
static int mysql_dissect_auth_switch_request(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data);
static int mysql_dissect_eof(tvbuff_t *tvb, packet_info *pinfo, proto_item *pi, int offset, proto_tree *tree, mysql_conn_data_t *conn_data);
static int mysql_dissect_auth_switch_response(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data);
static int mysql_dissect_auth_sha2(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data);
static int mysql_dissect_loaddata(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data);
static void mysql_dissect_exec_bit(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_blob(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_geometry(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_string(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_json(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_datetime(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_tiny(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_unsigned_tiny(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_short(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_unsigned_short(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_int24(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_long(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_unsigned_long(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_float(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_double(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_longlong(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_unsigned_longlong(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_year(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static void mysql_dissect_exec_null(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static char mysql_dissect_exec_param(proto_item *req_tree, tvbuff_t *tvb, int *offset,
		int *param_offset, uint8_t param_flags, packet_info *pinfo, unsigned encoding, bool queryattrs);
static char mysql_dissect_binary_row_value(tvbuff_t *tvb, packet_info *pinfo, proto_item *pi, int *offset,
		proto_item *tree, uint8_t field_type, uint16_t field_flag, unsigned field_encoding);

static void mysql_dissect_exec_primitive(tvbuff_t *tvb, packet_info *pinfo, int *param_offset,
proto_item *field_tree, const int hfindex, const int offset);
static void mysql_dissect_exec_time(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding);
static int mariadb_dissect_caps_or_flags(tvbuff_t *tvb, int offset, enum ftenum type, proto_tree *tree,
		int mariadb_caps, int * const *fields, void *value);

static int my_tvb_strsize(tvbuff_t *tvb, int offset);
static int tvb_get_fle(tvbuff_t *tvb, proto_tree* tree, int offset, uint64_t *res, uint8_t *is_null);

static int mysql_field_add_lestring(tvbuff_t *tvb, int offset, proto_tree *tree, int field, unsigned encoding);
static int dissect_mysql_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_);
static unsigned get_mysql_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_);

// type, unsigned, dissector
static const mysql_exec_dissector_t mysql_exec_dissectors[] = {
	{ 0x01, 0, mysql_dissect_exec_tiny },              // FIELD_TYPE_TINY
	{ 0x01, 1, mysql_dissect_exec_unsigned_tiny },     // FIELD_TYPE_TINY
	{ 0x02, 0, mysql_dissect_exec_short },             // FIELD_TYPE_SHORT
	{ 0x02, 1, mysql_dissect_exec_unsigned_short },    // FIELD_TYPE_SHORT
	{ 0x03, 0, mysql_dissect_exec_long },              // FIELD_TYPE_LONG
	{ 0x03, 1, mysql_dissect_exec_unsigned_long },     // FIELD_TYPE_LONG
	{ 0x04, 0, mysql_dissect_exec_float },             // FIELD_TYPE_FLOAT
	{ 0x05, 0, mysql_dissect_exec_double },            // FIELD_TYPE_DOUBLE
	{ 0x06, 0, mysql_dissect_exec_null },              // FIELD_TYPE_NULL
	{ 0x07, 0, mysql_dissect_exec_datetime },          // FIELD_TYPE_TIMESTAMP
	{ 0x07, 1, mysql_dissect_exec_datetime },          // FIELD_TYPE_TIMESTAMP
	{ 0x08, 0, mysql_dissect_exec_longlong },          // FIELD_TYPE_LONGLONG
	{ 0x08, 1, mysql_dissect_exec_unsigned_longlong }, // FIELD_TYPE_LONGLONG
	{ 0x09, 0, mysql_dissect_exec_int24 },             // FIELD_TYPE_INT24
	{ 0x09, 1, mysql_dissect_exec_int24 },             // FIELD_TYPE_INT24
	{ 0x0a, 0, mysql_dissect_exec_datetime },          // FIELD_TYPE_DATE
	{ 0x0b, 0, mysql_dissect_exec_time },              // FIELD_TYPE_TIME
	{ 0x0c, 0, mysql_dissect_exec_datetime },          // FIELD_TYPE_DATETIME
	{ 0x0d, 0, mysql_dissect_exec_year },              // FIELD_TYPE_YEAR
	{ 0x0d, 1, mysql_dissect_exec_year },              // FIELD_TYPE_YEAR
	{ 0x10, 1, mysql_dissect_exec_bit },               // FIELD_TYPE_BIT
	{ 0x10, 1, mysql_dissect_exec_bit },               // FIELD_TYPE_BIT
	{ 0xf5, 0, mysql_dissect_exec_json },              // FIELD_TYPE_JSON
	{ 0xf6, 0, mysql_dissect_exec_string },            // FIELD_TYPE_NEWDECIMAL
	{ 0xfc, 0, mysql_dissect_exec_blob },              // FIELD_TYPE_BLOB
	{ 0xfd, 0, mysql_dissect_exec_string },            // FIELD_TYPE_VAR_STRING
	{ 0xfe, 0, mysql_dissect_exec_string },            // FIELD_TYPE_STRING
	{ 0xff, 0, mysql_dissect_exec_geometry },          // FIELD_TYPE_GEOMETRY
	{ 0x00, 0, NULL },
};

static int * const mysql_rfsh_flags[] = {
	&hf_mysql_rfsh_grants,
	&hf_mysql_rfsh_log,
	&hf_mysql_rfsh_tables,
	&hf_mysql_rfsh_hosts,
	&hf_mysql_rfsh_status,
	&hf_mysql_rfsh_threads,
	&hf_mysql_rfsh_slave,
	&hf_mysql_rfsh_master,
	NULL
};

static int * const mysql_stat_flags[] = {
	&hf_mysql_stat_it,
	&hf_mysql_stat_ac,
	&hf_mysql_stat_mu,
	&hf_mysql_stat_mr,
	&hf_mysql_stat_bi,
	&hf_mysql_stat_ni,
	&hf_mysql_stat_cr,
	&hf_mysql_stat_lr,
	&hf_mysql_stat_dr,
	&hf_mysql_stat_bs,
	&hf_mysql_stat_mc,
	&hf_mysql_stat_query_was_slow,
	&hf_mysql_stat_ps_out_params,
	&hf_mysql_stat_trans_readonly,
	&hf_mysql_stat_session_state_changed,
	NULL
};

static int * const mysql_caps_flags[] = {
	&hf_mysql_cap_long_password,
	&hf_mysql_cap_found_rows,
	&hf_mysql_cap_long_flag,
	&hf_mysql_cap_connect_with_db,
	&hf_mysql_cap_no_schema,
	&hf_mysql_cap_compress,
	&hf_mysql_cap_odbc,
	&hf_mysql_cap_local_files,
	&hf_mysql_cap_ignore_space,
	&hf_mysql_cap_change_user,
	&hf_mysql_cap_interactive,
	&hf_mysql_cap_ssl,
	&hf_mysql_cap_ignore_sigpipe,
	&hf_mysql_cap_transactions,
	&hf_mysql_cap_reserved,
	&hf_mysql_cap_secure_connect,
	NULL
};

static int * const mysql_extcaps_flags[] = {
	&hf_mysql_cap_multi_statements,
	&hf_mysql_cap_multi_results,
	&hf_mysql_cap_ps_multi_results,
	&hf_mysql_cap_plugin_auth,
	&hf_mysql_cap_connect_attrs,
	&hf_mysql_cap_plugin_auth_lenenc_client_data,
	&hf_mysql_cap_client_can_handle_expired_passwords,
	&hf_mysql_cap_session_track,
	&hf_mysql_cap_deprecate_eof,
	&hf_mysql_cap_optional_metadata,
	&hf_mysql_cap_compress_zstd,
	&hf_mysql_cap_query_attrs,
	&hf_mysql_cap_mf_auth,
	&hf_mysql_cap_cap_ext,
	&hf_mysql_cap_ssl_verify_server_cert,
	&hf_mysql_cap_unused,
	NULL
};

static int * const mariadb_extcaps_flags[] = {
	&hf_mariadb_cap_progress,
	&hf_mariadb_cap_commulti,
	&hf_mariadb_cap_bulk,
	&hf_mariadb_cap_extmetadata,
	&hf_mariadb_cap_cache_metadata,
	NULL
};

static int * const mariadb_bulk_caps_flags[] = {
	&hf_mariadb_bulk_flag_autoid,
	&hf_mariadb_bulk_flag_sendtypes,
	NULL
};

static int * const mysql_fld_flags[] = {
	&hf_mysql_fld_not_null,
	&hf_mysql_fld_primary_key,
	&hf_mysql_fld_unique_key,
	&hf_mysql_fld_multiple_key,
	&hf_mysql_fld_blob,
	&hf_mysql_fld_unsigned,
	&hf_mysql_fld_zero_fill,
	&hf_mysql_fld_enum,
	&hf_mysql_fld_auto_increment,
	&hf_mysql_fld_timestamp,
	&hf_mysql_fld_set,
	NULL
};

/* Helper function to only set state on first pass */
static void mysql_set_conn_state(packet_info *pinfo, mysql_conn_data_t *conn_data, mysql_state_t state)
{
	if (!pinfo->fd->visited)
	{
		conn_data->state = state;
	}
}

static void mysql_set_resultset_fmt(packet_info *pinfo, mysql_conn_data_t *conn_data, mysql_resultset_fmt_t fmt)
{
	if (!pinfo->fd->visited)
	{
		conn_data->resultset_fmt = fmt;
	}
}

static void mysql_set_prepared_stmt_id(packet_info *pinfo, mysql_conn_data_t *conn_data, uint32_t stmt_id)
{
	if (!pinfo->fd->visited)
	{
		conn_data->stmt_id = stmt_id;
	}
}

/* Decrements the number of remaining field packets. Returns true if this
 * was the last field packet (and thus the state should change.)
 */
static bool mysql_dec_remaining_field_packet_count(packet_info *pinfo, mysql_conn_data_t *conn_data)
{
	if (!pinfo->fd->visited)
	{
		conn_data->remaining_field_packet_count--;
		return (conn_data->remaining_field_packet_count == 0);
	}
	return false;
}

static void mysql_set_remaining_field_packet_count(packet_info *pinfo, mysql_conn_data_t *conn_data, uint64_t num_fields)
{
	if (!pinfo->fd->visited)
	{
		conn_data->remaining_field_packet_count = num_fields;
	}
}

static void mysql_set_field_metas(packet_info *pinfo, mysql_conn_data_t *conn_data, my_metadata_list_t *field_metas)
{
	if (!pinfo->fd->visited)
	{
		conn_data->field_metas = *field_metas;
	}
}

static void mysql_set_encoding_client(packet_info *pinfo, mysql_conn_data_t *conn_data, unsigned encoding)
{
	if (!pinfo->fd->visited)
	{
		conn_data->encoding_client = encoding;
	}
}

static void mysql_set_encoding_results(packet_info *pinfo, mysql_conn_data_t *conn_data, unsigned encoding)
{
	if (!pinfo->fd->visited)
	{
		conn_data->encoding_results = encoding;
	}
}

static int
mysql_dissect_greeting(tvbuff_t *tvb, packet_info *pinfo, int offset,
		       proto_tree *tree, mysql_conn_data_t *conn_data,
		       const mysql_frame_data_t *my_frame_data)
{
	int protocol;
	int lenstr;
	int ver_offset;

	proto_item *tf;
	proto_item *greeting_tree;
	char buffer[7];

	protocol= tvb_get_uint8(tvb, offset);

	if (protocol == 0xff) {
		return mysql_dissect_error_packet(tvb, pinfo, offset+1, tree, my_frame_data);
	}

	mysql_set_conn_state(pinfo, conn_data, LOGIN);

	tf = proto_tree_add_item(tree, hf_mysql_server_greeting, tvb, offset, -1, ENC_NA);
	greeting_tree = proto_item_add_subtree(tf, ett_server_greeting);

	col_append_fstr(pinfo->cinfo, COL_INFO, " proto=%d", protocol) ;

	proto_tree_add_item(greeting_tree, hf_mysql_protocol, tvb, offset, 1, ENC_NA);

	offset += 1;

	/* version string */
	lenstr = tvb_strsize(tvb,offset);

	/* check if it is a MariaDB Server: MariaDB always sends 5.5.5- before real version number */
	tvb_get_raw_bytes_as_string(tvb, offset, buffer, 7);
	if (lenstr > 6 && strncmp(buffer, MARIADB_RPL_VERSION_HACK, sizeof(MARIADB_RPL_VERSION_HACK) - 1) == 0)
	{
		conn_data->is_mariadb_server= 1;
		col_append_fstr(pinfo->cinfo, COL_INFO, " version=%s ",
				tvb_format_text(pinfo->pool, tvb, offset + 6, lenstr - 7));
	} else {
		col_append_fstr(pinfo->cinfo, COL_INFO, " version=%s ",
				tvb_format_text(pinfo->pool, tvb, offset, lenstr-1));
	}

	col_set_fence(pinfo->cinfo, COL_INFO);

	proto_tree_add_item(greeting_tree, hf_mysql_version, tvb, offset, lenstr, ENC_ASCII);
	conn_data->major_version = 0;
	for (ver_offset = 0; ver_offset < lenstr; ver_offset++) {
		uint8_t ver_char = tvb_get_uint8(tvb, offset + ver_offset);
		if (ver_char == '.') break;
		conn_data->major_version = conn_data->major_version * 10 + ver_char - '0';
	}
	offset += lenstr;

	/* 4 bytes little endian thread_id */
	proto_tree_add_item(greeting_tree, hf_mysql_thread_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* salt string */
	lenstr = tvb_strsize(tvb,offset);
	proto_tree_add_item(greeting_tree, hf_mysql_salt, tvb, offset, lenstr, ENC_ASCII);
	offset += lenstr;

	/* rest is optional */
	if (!tvb_reported_length_remaining(tvb, offset)) return offset;

	/* 2 bytes CAPS */
	offset = mysql_dissect_caps(tvb, offset, greeting_tree, hf_mysql_caps_server, &conn_data->srv_caps);

	/* MariaDB server don't have the CLIENT_MYSQL/CLIENT_LONG_PASSWORD capability */
	if (!(conn_data->srv_caps & MYSQL_CAPS_LP))
	{
		conn_data->is_mariadb_server= 1;
	}

	/* rest is optional */
	if (!tvb_reported_length_remaining(tvb, offset)) return offset;

	proto_tree_add_item(greeting_tree, conn_data->is_mariadb_server ? hf_mariadb_server_language : hf_mysql_server_language, tvb, offset, 1, ENC_NA);
	offset += 1; /* for charset */

	offset = mysql_dissect_server_status(tvb, offset, greeting_tree, NULL);

	/* 2 bytes ExtCAPS */
	offset = mysql_dissect_extcaps(tvb, offset, greeting_tree, hf_mysql_extcaps_server, &conn_data->srv_caps_ext);

	/* 1 byte Auth Plugin Length */
	proto_tree_add_item(greeting_tree, hf_mysql_auth_plugin_length, tvb, offset, 1, ENC_NA);
	offset += 1;

	if (conn_data->is_mariadb_server)
	{
		/* 6 bytes unused */
		proto_tree_add_item(greeting_tree, hf_mysql_unused, tvb, offset, 6, ENC_NA);
		offset += 6;
		/* MariaDB specific extended capabilities */
		offset= mariadb_dissect_caps_or_flags(tvb, offset, FT_UINT32, greeting_tree,
										hf_mariadb_extcaps_server, mariadb_extcaps_flags, &conn_data->mariadb_server_ext_caps);
	} else {
		/* 10 bytes unused */
		proto_tree_add_item(greeting_tree, hf_mysql_unused, tvb, offset, 10, ENC_NA);
		offset += 10;
	}

	/* 4.1+ server: rest of salt */
	if (tvb_reported_length_remaining(tvb, offset)) {
		lenstr = tvb_strsize(tvb,offset);
		proto_tree_add_item(greeting_tree, hf_mysql_salt2, tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;
	}

	/* 5.x server: auth plugin */
	if (tvb_reported_length_remaining(tvb, offset)) {
		lenstr = tvb_strsize(tvb,offset);
		proto_tree_add_item(greeting_tree, hf_mysql_auth_plugin, tvb, offset, lenstr, ENC_ASCII);
		conn_data->auth_method = tvb_get_string_enc(wmem_file_scope(), tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;
	}

	return offset;
}


/*
  Add a connect attributes entry to the connattrs subtree

  return bytes read
*/
static int
add_connattrs_entry_to_tree(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *tree, int offset) {
	uint64_t lenstr;
	int orig_offset = offset, lenfle;
	proto_item *ti;
	proto_tree *connattrs_tree;
	const uint8_t *str;

	ti = proto_tree_add_item(tree, hf_mysql_connattrs_attr, tvb, offset, 1, ENC_NA);
	connattrs_tree = proto_item_add_subtree(ti, ett_connattrs_attr);

	lenfle = tvb_get_fle(tvb, connattrs_tree, offset, &lenstr, NULL);
	proto_tree_add_uint64(connattrs_tree, hf_mysql_connattrs_name_length, tvb, offset, lenfle, lenstr);
	offset += lenfle;

	proto_tree_add_item_ret_string(connattrs_tree, hf_mysql_connattrs_name, tvb, offset, (int)lenstr, ENC_ASCII|ENC_NA, pinfo->pool, &str);
	proto_item_append_text(ti, " - %s", str);
	offset += (int)lenstr;

	lenfle = tvb_get_fle(tvb, connattrs_tree, offset, &lenstr, NULL);
	proto_tree_add_uint64(connattrs_tree, hf_mysql_connattrs_value_length, tvb, offset, lenfle, lenstr);
	offset += lenfle;

	proto_tree_add_item_ret_string(connattrs_tree, hf_mysql_connattrs_value, tvb, offset, (int)lenstr, ENC_ASCII|ENC_NA, pinfo->pool, &str);
	proto_item_append_text(ti, ": %s", str);
	offset += (int)lenstr;

	proto_item_set_len(ti, offset - orig_offset);

	return (offset - orig_offset);
}

static int
mysql_dissect_login(tvbuff_t *tvb, packet_info *pinfo, int offset,
		    proto_tree *tree, mysql_conn_data_t *conn_data)
{
	int lenstr;

	proto_item *tf;
	proto_item *login_tree;

	/* after login there can be OK or DENIED */
	if (conn_data->clnt_caps & MYSQL_CAPS_SL) {
		mysql_set_conn_state(pinfo, conn_data, LOGIN);
	} else if (!(conn_data->clnt_caps == 0)) {
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_OK);
	}

	tf = proto_tree_add_item(tree, hf_mysql_login_request, tvb, offset, -1, ENC_NA);
	login_tree = proto_item_add_subtree(tf, ett_login_request);

	offset = mysql_dissect_caps(tvb, offset, login_tree, hf_mysql_caps_client, &conn_data->clnt_caps);

	/* MariaDB clients don't have the CLIENT_MYSQL/CLIENT_LONG_PASSWORD capability */
	if (!(conn_data->clnt_caps & MYSQL_CAPS_LP))
	{
		conn_data->is_mariadb_client= 1;
	}

	if (!(conn_data->frame_start_ssl) && conn_data->clnt_caps & MYSQL_CAPS_SL) /* Next packet will be use SSL */
	{
		col_set_str(pinfo->cinfo, COL_INFO, "Response: SSL Handshake");
		conn_data->frame_start_ssl = pinfo->num;
		ssl_starttls_ack(tls_handle, pinfo, mysql_handle);
	}
	if (conn_data->clnt_caps & MYSQL_CAPS_CU) /* 4.1 protocol */{
		offset = mysql_dissect_extcaps(tvb, offset, login_tree, hf_mysql_extcaps_client, &conn_data->clnt_caps_ext);

		proto_tree_add_item(login_tree, hf_mysql_max_packet, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		uint32_t collation;
		proto_tree_add_item_ret_uint(login_tree, conn_data->is_mariadb_server ? hf_mariadb_collation : hf_mysql_collation, tvb, offset, 1, ENC_NA, &collation);
		unsigned encoding = collation_to_encoding(collation, conn_data->is_mariadb_server);
		mysql_set_encoding_client(pinfo, conn_data, encoding);
		mysql_set_encoding_results(pinfo, conn_data, encoding);
		offset += 1; /* for charset */

		if (conn_data->is_mariadb_client){
			/* 19 bytes unused */
			proto_tree_add_item(login_tree, hf_mysql_unused, tvb, offset, 19, ENC_NA);
			offset += 19;
			offset= mariadb_dissect_caps_or_flags(tvb, offset, FT_UINT32, login_tree, hf_mariadb_extcaps_client, mariadb_extcaps_flags, &conn_data->mariadb_client_ext_caps);
		} else {
			/* 23 bytes unused */
			proto_tree_add_item(login_tree, hf_mysql_unused, tvb, offset, 23, ENC_NA);
			offset += 23;
		}

	} else { /* pre-4.1 */
		proto_tree_add_item(login_tree, hf_mysql_max_packet, tvb, offset, 3, ENC_LITTLE_ENDIAN);
		offset += 3;
	}

	/* User name */
	lenstr = my_tvb_strsize(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " user=%s ",
			tvb_format_text(pinfo->pool, tvb, offset, lenstr-1));
	proto_tree_add_item(login_tree, hf_mysql_user, tvb, offset, lenstr, ENC_ASCII);
	offset += lenstr;

	/* rest is optional */
	if (!tvb_reported_length_remaining(tvb, offset)) {
		col_set_fence(pinfo->cinfo, COL_INFO);
		return offset;
	}

	/* password: asciiz or length+ascii */
	if (conn_data->clnt_caps & MYSQL_CAPS_SC) {
		lenstr = tvb_get_uint8(tvb, offset);
		offset += 1;
	} else {
		lenstr = my_tvb_strsize(tvb, offset);
	}
	if (tree && lenstr > 1) {
		proto_tree_add_item(login_tree, hf_mysql_passwd, tvb, offset, lenstr, ENC_NA);
	}
	offset += lenstr;

	/* optional: initial schema */
	if (conn_data->clnt_caps & MYSQL_CAPS_CD)
	{
		lenstr= my_tvb_strsize(tvb,offset);
		if(lenstr<0){
			return offset;
		}

		col_append_fstr(pinfo->cinfo, COL_INFO, "db=%s ",
			tvb_format_text(pinfo->pool, tvb, offset, lenstr-1));
		col_set_fence(pinfo->cinfo, COL_INFO);

		proto_tree_add_item(login_tree, hf_mysql_schema, tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;
	}

	/* optional: authentication plugin */
	if (conn_data->clnt_caps_ext & MYSQL_CAPS_PA)
	{
		mysql_set_conn_state(pinfo, conn_data, AUTH_SWITCH_REQUEST);
		lenstr= my_tvb_strsize(tvb,offset);
		proto_tree_add_item(login_tree, hf_mysql_client_auth_plugin, tvb, offset, lenstr, ENC_ASCII);
		conn_data->auth_method = tvb_get_string_enc(wmem_file_scope(), tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;
	}

	/* optional: connection attributes */
	if (conn_data->clnt_caps_ext & MYSQL_CAPS_CA && tvb_reported_length_remaining(tvb, offset))
	{
		proto_tree *connattrs_tree;
		int lenfle;
		uint64_t connattrs_length;
		int length;

		lenfle = tvb_get_fle(tvb, login_tree, offset, &connattrs_length, NULL);
		tf = proto_tree_add_item(login_tree, hf_mysql_connattrs, tvb, offset, (uint32_t)connattrs_length, ENC_NA);
		connattrs_tree = proto_item_add_subtree(tf, ett_connattrs);
		proto_tree_add_uint64(connattrs_tree, hf_mysql_connattrs_length, tvb, offset, lenfle, connattrs_length);
		offset += lenfle;

		while (connattrs_length > 0) {
			length = add_connattrs_entry_to_tree(tvb, pinfo, connattrs_tree, offset);
			offset += length;
			connattrs_length -= length;
		}
	}

	if (conn_data->clnt_caps_ext & MYSQL_CAPS_ZS)
	{
		proto_tree_add_item(login_tree, hf_mysql_zstd_compression_level, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
	}
	return offset;
}

static void
mysql_dissect_exec_string(tvbuff_t *tvb, packet_info *pinfo _U_, int *param_offset, proto_item *field_tree, unsigned encoding)
{
	int lenfle;
	uint64_t param_len;

	lenfle = tvb_get_fle(tvb, field_tree, *param_offset, &param_len, NULL);
	proto_tree_add_item(field_tree, hf_mysql_exec_field_string_length, tvb, *param_offset, lenfle, ENC_ASCII);
	*param_offset += lenfle;

	if (encoding == ENC_NA) {
		proto_tree_add_item(field_tree, hf_mysql_exec_field_blob,
				tvb, *param_offset, (int)param_len, ENC_NA);
	} else {
			proto_tree_add_item(field_tree, hf_mysql_exec_field_string,
				tvb, *param_offset, (int)param_len, encoding);
	}
	*param_offset += param_len;
}

static void
mysql_dissect_exec_bit(tvbuff_t *tvb, packet_info *pinfo _U_, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	int lenfle;
	uint64_t param_len;

	lenfle = tvb_get_fle(tvb, field_tree, *param_offset, &param_len, NULL);
	proto_tree_add_item(field_tree, hf_mysql_exec_field_bit_length, tvb, *param_offset, lenfle, ENC_ASCII);
	*param_offset += lenfle;

	proto_tree_add_item(field_tree, hf_mysql_exec_field_bit,
			    tvb, *param_offset, (int)param_len, ENC_NA);
	*param_offset += param_len;
}

static void
mysql_dissect_exec_blob(tvbuff_t *tvb, packet_info *pinfo _U_, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	int lenfle;
	uint64_t param_len;

	lenfle = tvb_get_fle(tvb, field_tree, *param_offset, &param_len, NULL);
	proto_tree_add_item(field_tree, hf_mysql_exec_field_blob_length, tvb, *param_offset, lenfle, ENC_ASCII);
	*param_offset += lenfle;

	proto_tree_add_item(field_tree, hf_mysql_exec_field_blob,
			    tvb, *param_offset, (int)param_len, ENC_NA);
	*param_offset += param_len;
}

static void
mysql_dissect_exec_geometry(tvbuff_t *tvb, packet_info *pinfo _U_, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	int lenfle;
	uint64_t param_len;

	lenfle = tvb_get_fle(tvb, field_tree, *param_offset, &param_len, NULL);
	proto_tree_add_item(field_tree, hf_mysql_exec_field_geometry_length, tvb, *param_offset, lenfle, ENC_ASCII);
	*param_offset += lenfle;

	proto_tree_add_item(field_tree, hf_mysql_exec_field_geometry,
			    tvb, *param_offset, (int)param_len, ENC_NA);
	*param_offset += param_len;
}

static void
mysql_dissect_exec_json(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	static dissector_handle_t json_handle;
	tvbuff_t *next_tvb;
	int lenfle;
	uint64_t param_len;

	json_handle = find_dissector("json");
	lenfle = tvb_get_fle(tvb, field_tree, *param_offset, &param_len, NULL);
	proto_tree_add_item(field_tree, hf_mysql_exec_field_json_length, tvb, *param_offset, lenfle, ENC_ASCII);
	*param_offset += lenfle;

	next_tvb = tvb_new_subset_length(tvb, *param_offset, (int)param_len);
	call_dissector_only(json_handle, next_tvb, pinfo, field_tree, NULL);
	*param_offset += param_len;
}

static void
mysql_dissect_exec_time(tvbuff_t *tvb, packet_info *pinfo _U_, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	uint8_t param_len;

	param_len = tvb_get_uint8(tvb, *param_offset);
	proto_tree_add_item(field_tree, hf_mysql_exec_field_time_length, tvb, *param_offset, 1, ENC_NA);
	*param_offset += 1;
	if (param_len >= 1) {
		proto_tree_add_item(field_tree, hf_mysql_exec_field_time_sign, tvb, *param_offset, 1, ENC_NA);
	}
	if (param_len >= 5) {
		proto_tree_add_item(field_tree, hf_mysql_exec_field_time_days, tvb, *param_offset + 1, 4, ENC_LITTLE_ENDIAN);
	}
	if (param_len >= 8) {
		proto_tree_add_item(field_tree, hf_mysql_exec_field_hour, tvb, *param_offset + 5, 1, ENC_NA);
		proto_tree_add_item(field_tree, hf_mysql_exec_field_minute, tvb, *param_offset + 6, 1, ENC_NA);
		proto_tree_add_item(field_tree, hf_mysql_exec_field_second, tvb, *param_offset + 7, 1, ENC_NA);
	}
	if (param_len >= 12) {
		proto_tree_add_item(field_tree, hf_mysql_exec_field_second_b, tvb, *param_offset + 8, 4, ENC_LITTLE_ENDIAN);
	}
	*param_offset += param_len;
}

static void
mysql_dissect_exec_datetime(tvbuff_t *tvb, packet_info *pinfo _U_, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	uint8_t param_len;

	param_len = tvb_get_uint8(tvb, *param_offset);
	proto_tree_add_item(field_tree, hf_mysql_exec_field_datetime_length, tvb, *param_offset, 1, ENC_NA);
	*param_offset += 1;
	if (param_len >= 2) {
		proto_tree_add_item(field_tree, hf_mysql_exec_field_year, tvb, *param_offset, 2, ENC_LITTLE_ENDIAN);
	}
	if (param_len >= 4) {
		proto_tree_add_item(field_tree, hf_mysql_exec_field_month, tvb, *param_offset + 2, 1, ENC_NA);
		proto_tree_add_item(field_tree, hf_mysql_exec_field_day, tvb, *param_offset + 3, 1, ENC_NA);
	}
	if (param_len >= 7) {
		proto_tree_add_item(field_tree, hf_mysql_exec_field_hour, tvb, *param_offset + 4, 1, ENC_NA);
		proto_tree_add_item(field_tree, hf_mysql_exec_field_minute, tvb, *param_offset + 5, 1, ENC_NA);
		proto_tree_add_item(field_tree, hf_mysql_exec_field_second, tvb, *param_offset + 6, 1, ENC_NA);
	}
	if (param_len >= 11) {
		proto_tree_add_item(field_tree, hf_mysql_exec_field_second_b, tvb, *param_offset + 7, 4, ENC_LITTLE_ENDIAN);
	}
	*param_offset += param_len;
}

static void
mysql_dissect_exec_primitive(tvbuff_t *tvb, packet_info *pinfo _U_, int *param_offset, proto_item *field_tree, const int hfindex, const int offset)
{
	proto_tree_add_item(field_tree, hfindex, tvb, *param_offset, offset, ENC_LITTLE_ENDIAN);
	*param_offset += offset;
}

static void
mysql_dissect_exec_tiny(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_tiny, 1);
}

static void
mysql_dissect_exec_unsigned_tiny(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_unsigned_tiny, 1);
}

static void
mysql_dissect_exec_short(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_short, 2);
}

static void
mysql_dissect_exec_unsigned_short(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_unsigned_short, 2);
}

// Note that int24 is transferred in the binary protocol using 4 bytes, not 3.
static void
mysql_dissect_exec_int24(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_int24, 4);
}

static void
mysql_dissect_exec_long(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_long, 4);
}

static void
mysql_dissect_exec_unsigned_long(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_unsigned_long, 4);
}

static void
mysql_dissect_exec_float(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_float, 4);
}

static void
mysql_dissect_exec_double(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_double, 8);
}

static void
mysql_dissect_exec_longlong(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_longlong, 8);
}

static void
mysql_dissect_exec_unsigned_longlong(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_unsigned_longlong, 8);
}

static void
mysql_dissect_exec_year(tvbuff_t *tvb, packet_info *pinfo, int *param_offset, proto_item *field_tree, unsigned encoding _U_)
{
	mysql_dissect_exec_primitive(tvb, pinfo, param_offset, field_tree, hf_mysql_exec_field_year, 2);
}

static void
mysql_dissect_exec_null(tvbuff_t *tvb _U_, packet_info *pinfo _U_, int *param_offset _U_, proto_item *field_tree _U_, unsigned encoding _U_)
{}

static char
mysql_dissect_exec_param(proto_item *req_tree, tvbuff_t *tvb, int *offset,
			 int *param_offset, uint8_t param_flags,
			 packet_info *pinfo, unsigned encoding, bool queryattrs)
{
	uint8_t param_type, param_unsigned, lenfle;
	uint64_t param_name_len;
	proto_item *tf;
	proto_item *field_tree;
	int dissector_index = 0;

	tf = proto_tree_add_item(req_tree, hf_mysql_exec_param, tvb, *offset, 2, ENC_NA);
	field_tree = proto_item_add_subtree(tf, ett_stat);
	proto_tree_add_item(field_tree, hf_mysql_fld_type, tvb, *offset, 1, ENC_NA);
	param_type = tvb_get_uint8(tvb, *offset);
	*offset += 1; /* type */

	proto_tree_add_item(field_tree, hf_mysql_exec_unsigned, tvb, *offset, 1, ENC_NA);
	if ((tvb_get_uint8(tvb, *offset) & 128) == 128) {
		param_unsigned = 1;
	} else {
		param_unsigned = 0;
	}
	*offset += 1; /* signedness */

	// Length-encoded parameter name if query attributes are enabled.
	if (queryattrs) {
		lenfle = tvb_get_fle(tvb, field_tree, *offset, &param_name_len, NULL);
		*offset += lenfle;
		if (param_name_len>0) {
			proto_tree_add_item(field_tree, hf_mysql_param_name, tvb, *offset, (int)param_name_len, ENC_ASCII);
			*offset += param_name_len;
		}
	}

	if ((param_flags & MYSQL_PARAM_FLAG_STREAMED) == MYSQL_PARAM_FLAG_STREAMED) {
		expert_add_info(pinfo, field_tree, &ei_mysql_streamed_param);
		return 1;
	}
	while (mysql_exec_dissectors[dissector_index].dissector != NULL) {
		if (mysql_exec_dissectors[dissector_index].type == param_type &&
			mysql_exec_dissectors[dissector_index].unsigned_flag == param_unsigned) {
			mysql_exec_dissectors[dissector_index].dissector(tvb, pinfo, param_offset, field_tree, encoding);
			return 1;
		}
		dissector_index++;
	}
	return 0;
}

/* Calculate param_offset if Query Attributes are used
 * for each param:
 * <2>             param_type
 * <lenenc string> param_name
 */
static int
mysql_exec_param_offset(tvbuff_t *tvb, proto_tree *req_tree, int offset, int param_count)
{
    int lenfle;
	uint64_t param_length;

	for (int i = 0; i<param_count; i++) {
		offset += 2; // param type
		lenfle = tvb_get_fle(tvb, req_tree, offset, &param_length, NULL);
		offset += lenfle + param_length;
	}

	return offset;
}

static int
mysql_dissect_request(tvbuff_t *tvb,packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data, const mysql_frame_data_t *my_frame_data)
{
	int opcode;
	int lenstr;
	proto_item *request_item, *tf = NULL, *ti;
	proto_item *req_tree;
	uint32_t stmt_id;
	my_stmt_data_t *stmt_data;
	int stmt_pos, param_offset;
	mysql_state_t current_state = my_frame_data->state;

	/* LOCAL INFILE Request sends an empty packet after sending the file content
	 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_local_infile_request.html */
	if (tvb_reported_length_remaining(tvb, offset) == 0)
		return offset;

	switch(current_state) {
	case AUTH_SWITCH_RESPONSE:
		return mysql_dissect_auth_switch_response(tvb, pinfo, offset, tree, conn_data);
	case AUTH_SHA2:
		return mysql_dissect_auth_sha2(tvb, pinfo, offset, tree, conn_data);
	case INFILE_DATA:
		return mysql_dissect_loaddata(tvb, pinfo, offset, tree, conn_data);
	default:;
	}

	request_item = proto_tree_add_item(tree, hf_mysql_request, tvb, offset, -1, ENC_NA);
	req_tree = proto_item_add_subtree(request_item, ett_request);

	opcode = tvb_get_uint8(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str_ext(opcode, &mysql_command_vals_ext, "Unknown (%u) "));

	proto_tree_add_item(req_tree, hf_mysql_command, tvb, offset, 1, ENC_NA);
	proto_item_append_text(request_item, " %s", val_to_str_ext(opcode, &mysql_command_vals_ext, "Unknown (%u)"));
	offset += 1;


	switch (opcode) {

	case MYSQL_QUIT:
		break;

	case MYSQL_PROCESS_INFO:
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_TABULAR);
		mysql_set_resultset_fmt(pinfo, conn_data, TEXT);
		break;

	case MYSQL_DEBUG:
	case MYSQL_PING:
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_OK);
		break;

	case MYSQL_STATISTICS:
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_MESSAGE);
		break;

	case MYSQL_INIT_DB:
	case MYSQL_CREATE_DB:
	case MYSQL_DROP_DB:
		lenstr = my_tvb_strsize(tvb, offset);
		proto_tree_add_item(req_tree, hf_mysql_schema, tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_OK);
		break;

	case MYSQL_QUERY:
		/* Check both the extended capabilities of the client and server. The flag is set by the client
		 * even if the server didn't set it. This is only actively used if both set the flag. */
		if ((conn_data->clnt_caps_ext & MYSQL_CAPS_QA) && (conn_data->srv_caps_ext & MYSQL_CAPS_QA)){
			proto_item *query_attrs_item = proto_tree_add_item(req_tree, hf_mysql_query_attributes, tvb, offset, -1, ENC_NA);
			proto_item *query_attrs_tree = proto_item_add_subtree(query_attrs_item, ett_query_attributes);

			int n_params = tvb_get_uint8(tvb, offset);
			proto_tree_add_item(query_attrs_tree, hf_mysql_query_attributes_count, tvb, offset, 1, ENC_ASCII);
			offset += 2;

			if (n_params > 0) {
				int null_count = (n_params + 7) / 8;
				proto_tree_add_item(query_attrs_tree, hf_mysql_unused, tvb, offset, null_count, ENC_ASCII);
				offset += null_count;

				proto_tree_add_item(query_attrs_tree, hf_mysql_query_attributes_send_types_to_server, tvb, offset, 1, ENC_ASCII);
				offset += 1;

				unsigned encoding = my_frame_data->encoding_client;

				for (int i = 0; i < n_params; ++i) {
					proto_tree_add_item(query_attrs_tree, hf_mysql_query_attribute_name_type, tvb, offset, 2, ENC_ASCII);
					offset += 2;
					offset = mysql_field_add_lestring(tvb, offset, query_attrs_tree, hf_mysql_query_attribute_name, encoding);
				}
				for (int i = 0; i < n_params; ++i) {
					offset = mysql_field_add_lestring(tvb, offset, query_attrs_tree, hf_mysql_query_attribute_value, encoding);
				}
			}
		}
		lenstr = my_tvb_strsize(tvb, offset);
		// A query string of less than 2 doesn't make sense, this is *likely* to be a case where
		// we don't have the capability flags from the login/greeting and are missing MYSQL_CAPS_QA
		// Note that MYSQL_CAPS_QA is only used on recent MySQL and only if both the client and server
		// set it, so assuming this is set when we don't have the login/greeting will break many other
		// cases.
		//
		// If this is the case we skip 2 bytes and try again.
		if (lenstr < 2) {
			offset += 2;
			lenstr = my_tvb_strsize(tvb, offset);
		}
		proto_tree_add_item(req_tree, hf_mysql_query, tvb, offset, lenstr, my_frame_data->encoding_client);
		if (mysql_showquery) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " { %s } ",
					tvb_format_text(pinfo->pool, tvb, offset, lenstr));
			col_set_fence(pinfo->cinfo, COL_INFO);
		}
		offset += lenstr;
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_TABULAR);
		mysql_set_resultset_fmt(pinfo, conn_data, TEXT);
		break;

	case MYSQL_STMT_PREPARE:
		lenstr = my_tvb_strsize(tvb, offset);
		proto_tree_add_item(req_tree, hf_mysql_query, tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_PREPARE);
		break;

	case MYSQL_STMT_CLOSE:
		proto_tree_add_item(req_tree, hf_mysql_stmt_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		mysql_set_conn_state(pinfo, conn_data, REQUEST);
		break;

	case MYSQL_STMT_RESET:
		proto_tree_add_item(req_tree, hf_mysql_stmt_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_OK);
		break;

	case MYSQL_FIELD_LIST:
		lenstr = my_tvb_strsize(tvb, offset);
		proto_tree_add_item(req_tree, hf_mysql_table_name, tvb,  offset, lenstr, ENC_ASCII);
		offset += lenstr;
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_SHOW_FIELDS);
		break;

	case MYSQL_PROCESS_KILL:
		proto_tree_add_item(req_tree, hf_mysql_thread_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_OK);
		break;

	case MYSQL_CHANGE_USER:
		lenstr = tvb_strsize(tvb, offset);
		proto_tree_add_item(req_tree, hf_mysql_user, tvb,  offset, lenstr, ENC_ASCII);
		offset += lenstr;

		if (conn_data->clnt_caps & MYSQL_CAPS_SC) {
			lenstr = tvb_get_uint8(tvb, offset);
			offset += 1;
		} else {
			lenstr = tvb_strsize(tvb, offset);
		}
		proto_tree_add_item(req_tree, hf_mysql_passwd, tvb, offset, lenstr, ENC_NA);
		offset += lenstr;

		lenstr = my_tvb_strsize(tvb, offset);
		proto_tree_add_item(req_tree, hf_mysql_schema, tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;

		if (tvb_reported_length_remaining(tvb, offset) > 0) {
			uint32_t collation;
			proto_tree_add_item_ret_uint(req_tree, conn_data->is_mariadb_server ? hf_mariadb_collation : hf_mysql_collation, tvb, offset, 2, ENC_LITTLE_ENDIAN, &collation);
			unsigned encoding = collation_to_encoding(collation, conn_data->is_mariadb_server);
			mysql_set_encoding_client(pinfo, conn_data, encoding);
			mysql_set_encoding_results(pinfo, conn_data, encoding);
			offset += 2; /* for charset */
		}
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_OK);

		/* optional: authentication plugin */
		if (conn_data->clnt_caps_ext & MYSQL_CAPS_PA)
		{
			mysql_set_conn_state(pinfo, conn_data, AUTH_SWITCH_REQUEST);
			lenstr= my_tvb_strsize(tvb,offset);
			proto_tree_add_item(req_tree, hf_mysql_client_auth_plugin, tvb, offset, lenstr, ENC_ASCII);
			offset += lenstr;
		}

		/* optional: connection attributes */
		if ((conn_data->clnt_caps_ext & MYSQL_CAPS_CA) && (tvb_reported_length_remaining(tvb, offset) > 0))
		{
			proto_tree *connattrs_tree;
			int lenfle;
			uint64_t connattrs_length;
			int length;

			lenfle = tvb_get_fle(tvb, req_tree, offset, &connattrs_length, NULL);
			tf = proto_tree_add_item(req_tree, hf_mysql_connattrs, tvb, offset, (uint32_t)connattrs_length, ENC_NA);
			connattrs_tree = proto_item_add_subtree(tf, ett_connattrs);
			proto_tree_add_uint64(connattrs_tree, hf_mysql_connattrs_length, tvb, offset, lenfle, connattrs_length);
			offset += lenfle;

			while (connattrs_length > 0) {
				length = add_connattrs_entry_to_tree(tvb, pinfo, connattrs_tree, offset);
				offset += length;
				connattrs_length -= length;
			}
		}
		break;

	case MYSQL_REFRESH:
		proto_tree_add_bitmask_with_flags(req_tree, tvb, offset,
		    hf_mysql_refresh, ett_refresh, mysql_rfsh_flags,
		    ENC_BIG_ENDIAN, BMT_NO_APPEND);
		offset += 1;
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_OK);
		break;

	case MYSQL_SHUTDOWN:
		proto_tree_add_item(req_tree, hf_mysql_shutdown, tvb, offset, 1, ENC_NA);
		offset += 1;
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_OK);
		break;

	case MYSQL_SET_OPTION:
		proto_tree_add_item(req_tree, hf_mysql_option, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_OK);
		break;

	case MYSQL_STMT_FETCH:
		proto_tree_add_item(req_tree, hf_mysql_stmt_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(req_tree, hf_mysql_num_rows, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		mysql_set_conn_state(pinfo, conn_data, RESPONSE_TABULAR);
		mysql_set_resultset_fmt(pinfo, conn_data, BINARY);
		break;

	case MYSQL_STMT_SEND_LONG_DATA:
		proto_tree_add_item(req_tree, hf_mysql_stmt_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		stmt_id = tvb_get_letohl(tvb, offset);
		offset += 4;

		stmt_data = (my_stmt_data_t *)wmem_tree_lookup32(conn_data->stmts, stmt_id);
		if (stmt_data != NULL) {
			uint16_t data_param = tvb_get_letohs(tvb, offset);
			if (stmt_data->param_metas.count > data_param) {
				stmt_data->param_metas.flags[data_param] |= MYSQL_PARAM_FLAG_STREAMED;
			}
		}

		proto_tree_add_item(req_tree, hf_mysql_param, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		/* rest is data */
		lenstr = tvb_reported_length_remaining(tvb, offset);
		if (tree &&  lenstr > 0) {
			proto_tree_add_item(req_tree, hf_mysql_payload, tvb, offset, lenstr, ENC_NA);
		}
		offset += lenstr;
		if (current_state != RESPONSE_PREPARE) {
			// if pipelining, keeping PREPARE state
			mysql_set_conn_state(pinfo, conn_data, REQUEST);
		}
		break;

	case MARIADB_STMT_BULK_EXECUTE:
		proto_tree_add_item(req_tree, hf_mysql_stmt_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		stmt_id = tvb_get_letohl(tvb, offset);
		offset += 4;

		// use last prepared statement
		if (stmt_id == 0xffffffff) {
			stmt_id = my_frame_data->stmt_id;
		}

		stmt_data = (my_stmt_data_t *)wmem_tree_lookup32(conn_data->stmts, stmt_id);

		if (stmt_data != NULL) {
			uint32_t row_nr = 1;
			proto_item *param_tree;

			mariadb_dissect_caps_or_flags(tvb, offset, FT_UINT16, req_tree, hf_mariadb_bulk_caps_flags, mariadb_bulk_caps_flags, &stmt_data->bulk_flags);
			offset += 2;

			if ((stmt_data->bulk_flags & MARIADB_BULK_SEND_TYPES) && stmt_data->param_metas.count)
			{
				tf = proto_tree_add_item(req_tree, hf_mariadb_bulk_paramtypes, tvb, offset, -1, ENC_NA);
				param_tree = proto_item_add_subtree(tf, ett_exec_param);
				for (stmt_pos = 0; stmt_pos < stmt_data->param_metas.count; stmt_pos++) {
					stmt_data->param_metas.types[stmt_pos] = tvb_get_uint8(tvb, offset);
					proto_tree_add_item(param_tree, hf_mysql_fld_type, tvb, offset, 1, ENC_NA);
					offset+= 1;
					stmt_data->param_metas.flags[stmt_pos] = tvb_get_uint8(tvb, offset);
					proto_tree_add_item(param_tree, hf_mysql_exec_unsigned, tvb, offset, 1, ENC_NA);
					offset+= 1;
				}
			}
			while (tvb_reported_length_remaining(tvb, offset) > 0){
				tf = proto_tree_add_uint_format(req_tree, hf_mariadb_bulk_row_nr, tvb, offset, 0, row_nr, "%d. Dataset", row_nr);
				proto_item_set_generated(tf);
				param_tree = proto_item_add_subtree(tf, ett_bulk_param);

				for (stmt_pos = 0; stmt_pos < stmt_data->param_metas.count; stmt_pos++)
				{
					uint8_t indicator= tvb_get_uint8(tvb, offset);
					proto_tree_add_item(param_tree, hf_mariadb_bulk_indicator, tvb, offset, 1, ENC_NA);
					offset++;
					/* If no indicator was specified, data will follow */
					if (!indicator) {
						int dissector_index= 0;
						while (mysql_exec_dissectors[dissector_index].dissector != NULL) {
							if (mysql_exec_dissectors[dissector_index].type == stmt_data->param_metas.types[stmt_pos])
	/*	&&
								mysql_exec_dissectors[dissector_index].unsigned_flag == stmt_data->param_flags[stmt_pos]) */
							{
								mysql_exec_dissectors[dissector_index].dissector(tvb, pinfo, &offset, param_tree, stmt_data->param_metas.encodings[stmt_pos]);
								break;
							}
							dissector_index++;
						}
					}
				}
				row_nr++;
			}
		}
		if (current_state != RESPONSE_PREPARE) {
			// if pipelining, keeping PREPARE state
			mysql_set_conn_state(pinfo, conn_data, REQUEST);
		}

		break;

	case MYSQL_STMT_EXECUTE:
		// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html
		proto_tree_add_item(req_tree, hf_mysql_stmt_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		stmt_id = tvb_get_letohl(tvb, offset);
		offset += 4;

		if (conn_data->major_version >= 5) {
			proto_tree_add_item(req_tree, hf_mysql_exec_flags5, tvb, offset, 1, ENC_NA);
		} else {
			proto_tree_add_item(req_tree, hf_mysql_exec_flags4, tvb, offset, 1, ENC_NA);
		}
		uint8_t exec_flags = tvb_get_uint8(tvb, offset);
		offset += 1;

		proto_tree_add_item(req_tree, hf_mysql_exec_iter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		// use last prepared statement
		if (stmt_id == 0xffffffff) {
			stmt_id = my_frame_data->stmt_id;
		}
		stmt_data = (my_stmt_data_t *)wmem_tree_lookup32(conn_data->stmts, stmt_id);
		if (stmt_data != NULL) {
			uint64_t param_count = stmt_data->param_metas.count;
			if ((conn_data->clnt_caps_ext & MYSQL_CAPS_QA)
					&& (exec_flags & MYSQL_PARAMETER_COUNT_AVAILABLE)) {
				uint8_t lenfle = tvb_get_fle(tvb, req_tree, offset, &param_count, NULL);
				proto_tree_add_uint64(req_tree, hf_mysql_num_params, tvb, offset, lenfle, param_count);
				offset += lenfle;
			}
			if (param_count != 0) {
				uint8_t stmt_bound;
				offset += (param_count + 7) / 8; /* NULL bitmap */
				proto_tree_add_item(req_tree, hf_mysql_new_parameter_bound_flag, tvb, offset, 1, ENC_NA);
				stmt_bound = tvb_get_uint8(tvb, offset);
				offset += 1;
				if (stmt_bound == 1) {
					if (conn_data->clnt_caps_ext & MYSQL_CAPS_QA) {
						param_offset = mysql_exec_param_offset(tvb, req_tree, offset, (unsigned)param_count);
					} else {
						param_offset = offset + (unsigned)param_count * 2;
					}
					uint8_t flags;
					/* The character set for a parameter
					 * is character_set_client. */
					unsigned encoding = my_frame_data->encoding_client;
					for (stmt_pos = 0; stmt_pos < (int)param_count; stmt_pos++) {
						if (stmt_pos >= stmt_data->param_metas.count) {
							// With Query Attributes we can have more params than during the prepare.
							// this means we don't have flags for them.
							flags = 0;
						} else {
							flags = (uint8_t)stmt_data->param_metas.flags[stmt_pos];
						}
						if (!mysql_dissect_exec_param(req_tree, tvb, &offset, &param_offset,
									      flags, pinfo, encoding,
									      conn_data->clnt_caps_ext & MYSQL_CAPS_QA))
							break;
					}
					offset = param_offset;
				}
			}
		} else {
			lenstr = tvb_reported_length_remaining(tvb, offset);
			if (tree &&  lenstr > 0) {
				ti = proto_tree_add_item(req_tree, hf_mysql_payload, tvb, offset, lenstr, ENC_NA);
				expert_add_info(pinfo, ti, &ei_mysql_prepare_response_needed);
			}
			offset += lenstr;
		}

		if (current_state != RESPONSE_PREPARE) {
			// if pipelining, keeping PREPARE state
			mysql_set_conn_state(pinfo, conn_data, RESPONSE_TABULAR);
		}
		mysql_set_resultset_fmt(pinfo, conn_data, BINARY);

		break;

	case MYSQL_BINLOG_DUMP_GTID:
		// See mysql_binlog_open() in "sql-common/client.cc"

		proto_tree_add_item(req_tree, hf_mysql_binlog_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(req_tree, hf_mysql_binlog_server_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		lenstr = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(req_tree, hf_mysql_binlog_file_name_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		if (tree && lenstr > 0) {
			proto_tree_add_item(req_tree, hf_mysql_binlog_file_name, tvb, offset, lenstr, ENC_ASCII);
		}
		offset += lenstr;

		proto_tree_add_item(req_tree, hf_mysql_binlog_position8, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		lenstr = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(req_tree, hf_mysql_binlog_gtid_data_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(req_tree, hf_mysql_binlog_gtid_data, tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;

		mysql_set_conn_state(pinfo, conn_data, BINLOG_DUMP);
		break;
	case MYSQL_BINLOG_DUMP:
		proto_tree_add_item(req_tree, hf_mysql_binlog_position, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(req_tree, hf_mysql_binlog_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(req_tree, hf_mysql_binlog_server_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* binlog file name ? */
		lenstr = tvb_reported_length_remaining(tvb, offset);
		if (tree &&  lenstr > 0) {
			proto_tree_add_item(req_tree, hf_mysql_binlog_file_name, tvb, offset, lenstr, ENC_ASCII);
		}
		offset += lenstr;

		mysql_set_conn_state(pinfo, conn_data, BINLOG_DUMP);
		break;

	case MYSQL_REGISTER_SLAVE:
		proto_tree_add_item(req_tree, hf_mysql_binlog_server_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		lenstr = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(req_tree, hf_mysql_binlog_slave_hostname_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(req_tree, hf_mysql_binlog_slave_hostname, tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;

		lenstr = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(req_tree, hf_mysql_binlog_slave_user_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(req_tree, hf_mysql_binlog_slave_user, tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;

		lenstr = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(req_tree, hf_mysql_binlog_slave_password_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(req_tree, hf_mysql_binlog_slave_password, tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;

		proto_tree_add_item(req_tree, hf_mysql_binlog_slave_mysql_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(req_tree, hf_mysql_binlog_replication_rank, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(req_tree, hf_mysql_binlog_master_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		mysql_set_conn_state(pinfo, conn_data, REQUEST);
		break;

/* FIXME: implement replication packets */
	case MYSQL_TABLE_DUMP:
	case MYSQL_CONNECT_OUT:
		ti = proto_tree_add_item(req_tree, hf_mysql_payload, tvb, offset, -1, ENC_NA);
		expert_add_info_format(pinfo, ti, &ei_mysql_dissector_incomplete, "FIXME: implement replication packets");
		offset += tvb_reported_length_remaining(tvb, offset);
		mysql_set_conn_state(pinfo, conn_data, REQUEST);
		break;

	case MYSQL_CLONE:
		mysql_set_conn_state(pinfo, conn_data, CLONE_INIT);
		break;

	case MYSQL_RESET_CONNECTION:
		break;

	default:
		ti = proto_tree_add_item(req_tree, hf_mysql_payload, tvb, offset, -1, ENC_NA);
		expert_add_info(pinfo, ti, &ei_mysql_command);
		offset += tvb_reported_length_remaining(tvb, offset);
		mysql_set_conn_state(pinfo, conn_data, UNDEFINED);
	}

	proto_item_set_end(request_item, tvb, offset);
	return offset;
}

static int
mysql_dissect_response(tvbuff_t *tvb, packet_info *pinfo, int offset,
		       proto_tree *tree, mysql_conn_data_t *conn_data, proto_item *pi, const mysql_frame_data_t *my_frame_data)
{
	int response_code;
	int lenstr;
	proto_item *ti;

	mysql_state_t current_state = my_frame_data->state;
	my_stmt_data_t *stmt_data = NULL;
	if (my_frame_data->stmt_id) {
		stmt_data = (my_stmt_data_t *)wmem_tree_lookup32(conn_data->stmts, my_frame_data->stmt_id);
	}

	response_code = tvb_get_uint8(tvb, offset);
	switch (response_code) {
	case 0xff:
		proto_tree_add_item(tree, hf_mysql_response_code, tvb, offset, 1, ENC_NA);
		proto_item_append_text(pi, " - %s", val_to_str(RESPONSE_ERROR, state_vals, "Unknown (%u)"));
		offset = mysql_dissect_error_packet(tvb, pinfo, offset+1, tree, my_frame_data);
		mysql_set_conn_state(pinfo, conn_data, REQUEST);
		break;
	case 0xfe:
		proto_tree_add_item(tree, hf_mysql_response_code, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_mysql_eof, tvb, offset, 1, ENC_NA);
		offset += 1;

		if (tvb_reported_length_remaining(tvb, offset) <= 5) {
			// real EOF packet
			offset = mysql_dissect_eof(tvb, pinfo, pi, offset, tree, conn_data);

			if (current_state == PREPARED_PARAMETERS) {
				if (stmt_data != NULL && stmt_data->field_metas.count > 0) {
					proto_item_append_text(pi, " - %s", val_to_str(INTERMEDIATE_EOF, state_vals, "Unknown (%u)"));
					mysql_set_remaining_field_packet_count(pinfo, conn_data, stmt_data->field_metas.count);
					mysql_set_conn_state(pinfo, conn_data, PREPARED_FIELDS);
				} else {
					proto_item_append_text(pi, " - %s", val_to_str(RESPONSE_EOF, state_vals, "Unknown (%u)"));
					mysql_set_conn_state(pinfo, conn_data, REQUEST);
				}
			} else if (current_state == FIELD_PACKET) {
				// intermediate EOF packet
				proto_item_append_text(pi, " - %s", val_to_str(INTERMEDIATE_EOF, state_vals, "Unknown (%u)"));
				mysql_set_conn_state(pinfo, conn_data, ROW_PACKET);
			} else {
				// ending EOF packet
				proto_item_append_text(pi, " - %s", val_to_str(RESPONSE_EOF, state_vals, "Unknown (%u)"));
				mysql_set_conn_state(pinfo, conn_data, REQUEST);
			}
		} else if (tvb_reported_length_remaining(tvb, offset) < 0xffffff) {
			// not an EOF
			if (current_state == AUTH_SWITCH_REQUEST) {
				proto_item_append_text(pi, " - %s", val_to_str(AUTH_SWITCH_REQUEST, state_vals, "Unknown (%u)"));
				offset = mysql_dissect_auth_switch_request(tvb, pinfo, offset, tree, conn_data);
			} else {
				proto_item_append_text(pi, " - %s", val_to_str(RESPONSE_OK, state_vals, "Unknown (%u)"));
				offset = mysql_dissect_ok_packet(tvb, pinfo, offset, tree, conn_data);
				mysql_set_conn_state(pinfo, conn_data, REQUEST);
			}
		} else {
			// text row packet
			proto_item_append_text(pi, " - %s", val_to_str(ROW_PACKET, state_vals, "Unknown (%u)"));
			mysql_set_conn_state(pinfo, conn_data, ROW_PACKET);
			offset = mysql_dissect_text_row_packet(tvb, offset, tree, my_frame_data);
		}
		break;

	case 0x00:
		switch (current_state) {
		case RESPONSE_PREPARE:
			proto_tree_add_item(tree, hf_mysql_response_code, tvb, offset, 1, ENC_NA);
			offset+=1;
			proto_item_append_text(pi, " - %s", val_to_str(RESPONSE_PREPARE, state_vals, "Unknown (%u)"));
			offset = mysql_dissect_response_prepare(tvb, pinfo, offset, tree, conn_data);
			break;
		case ROW_PACKET:
			proto_item_append_text(pi, " - %s", val_to_str(ROW_PACKET, state_vals, "Unknown (%u)"));
			if (my_frame_data->resultset_fmt == BINARY) {
				proto_tree_add_item(tree, hf_mysql_response_code, tvb, offset, 1, ENC_NA);
				offset+=1;
				offset = mysql_dissect_binary_row_packet(tvb, pinfo, pi, offset, tree, conn_data, my_frame_data);
			} else {
				offset = mysql_dissect_text_row_packet(tvb, offset, tree, my_frame_data);
			}
			break;
		case BINLOG_DUMP:
			proto_tree_add_item(tree, hf_mysql_response_code, tvb, offset, 1, ENC_NA);
			offset+=1;
			proto_item_append_text(pi, " - %s", val_to_str(BINLOG_DUMP, state_vals, "Unknown (%u)"));
			offset = mysql_dissect_binlog_event_packet(tvb, pinfo, offset, tree, pi);
			break;
		default:
			proto_tree_add_item(tree, hf_mysql_response_code, tvb, offset, 1, ENC_NA);
			offset+=1;
			proto_item_append_text(pi, " - %s", val_to_str(RESPONSE_OK, state_vals, "Unknown (%u)"));
			offset = mysql_dissect_ok_packet(tvb, pinfo, offset, tree, conn_data);
			if (conn_data->compressed_state == MYSQL_COMPRESS_INIT) {
				/* This is the OK packet which follows the compressed protocol setup */
				conn_data->compressed_state = MYSQL_COMPRESS_ACTIVE;
			}
			if (current_state == CLONE_INIT)
				mysql_set_conn_state(pinfo, conn_data, CLONE_ACTIVE);
			break;
		}
		break;
	default:
		switch (current_state) {
		case RESPONSE_MESSAGE:
			if ((lenstr = tvb_reported_length_remaining(tvb, offset))) {
				proto_tree_add_item(tree, hf_mysql_message, tvb, offset, lenstr, ENC_ASCII);
				offset += lenstr;
			}
			mysql_set_conn_state(pinfo, conn_data, REQUEST);
			break;

		case RESPONSE_TABULAR:
		case REQUEST: /* That shouldn't be the case; maybe two requests in a row (s. bug 15074), or after pipelining */
			if (response_code == 0xfb) {
				/* https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_local_infile_request.html */
				col_append_str(pinfo->cinfo, COL_INFO, " LOCAL INFILE");
				proto_tree_add_item(tree, hf_mysql_response_code, tvb, offset, 1, ENC_NA);
				proto_item_append_text(pi, " - %s", val_to_str(RESPONSE_LOCALINFILE, state_vals, "Unknown (%u)"));

				lenstr = tvb_reported_length_remaining(tvb, ++offset);
				proto_tree_add_item(tree, hf_mysql_loaddata_filename, tvb, offset, lenstr, ENC_ASCII);
				offset += lenstr;
				mysql_set_conn_state(pinfo, conn_data, INFILE_DATA);
				break;
			}
			proto_item_append_text(pi, " - %s", val_to_str(COLUMN_COUNT, state_vals, "Unknown (%u)"));
			offset = mysql_dissect_result_header(tvb, pinfo, offset, tree, conn_data, my_frame_data);
			break;
		case PREPARED_PARAMETERS:
			proto_item_append_text(pi, " - %s", val_to_str(current_state, state_vals, "Unknown (%u)"));
			offset = mysql_dissect_field_packet(tvb, pi, offset, tree, pinfo, conn_data, my_frame_data);
			if (mysql_dec_remaining_field_packet_count(pinfo, conn_data)) {
				if (conn_data->clnt_caps_ext & MYSQL_CAPS_DE) {
					if (stmt_data != NULL && stmt_data->field_metas.count > 0) {
						mysql_set_remaining_field_packet_count(pinfo, conn_data, stmt_data->field_metas.count);
						mysql_set_conn_state(pinfo, conn_data, PREPARED_FIELDS);
					} else {
						mysql_set_conn_state(pinfo, conn_data, REQUEST);
					}
				}
			}
			break;

		case FIELD_PACKET:
		case RESPONSE_SHOW_FIELDS:
			proto_item_append_text(pi, " - %s", val_to_str(current_state, state_vals, "Unknown (%u)"));
			offset = mysql_dissect_field_packet(tvb, pi, offset, tree, pinfo, conn_data, my_frame_data);
			if (mysql_dec_remaining_field_packet_count(pinfo, conn_data) && (conn_data->clnt_caps_ext & MYSQL_CAPS_DE)) {
				mysql_set_conn_state(pinfo, conn_data, ROW_PACKET);
			}
			break;

		case ROW_PACKET:
			proto_item_append_text(pi, " - %s", val_to_str(current_state, state_vals, "Unknown (%u)"));
			offset = mysql_dissect_text_row_packet(tvb, offset, tree, my_frame_data);
			break;

		case PREPARED_FIELDS:
			proto_item_append_text(pi, " - %s", val_to_str(current_state, state_vals, "Unknown (%u)"));
			offset = mysql_dissect_field_packet(tvb, pi, offset, tree, pinfo, conn_data, my_frame_data);
			if (mysql_dec_remaining_field_packet_count(pinfo, conn_data) && (conn_data->clnt_caps_ext & MYSQL_CAPS_DE)) {
				mysql_set_conn_state(pinfo, conn_data, REQUEST);
			}
			break;

		case AUTH_SWITCH_REQUEST:
			if (tvb_reported_length_remaining(tvb,offset) == 2) {
				proto_item_append_text(pi, " - %s", val_to_str(AUTH_SHA2, state_vals, "Unknown (%u)"));
				offset = mysql_dissect_auth_sha2(tvb, pinfo, offset, tree, conn_data);
			} else {
				proto_item_append_text(pi, " - %s", val_to_str(AUTH_SWITCH_REQUEST, state_vals, "Unknown (%u)"));
				offset = mysql_dissect_auth_switch_request(tvb, pinfo, offset, tree, conn_data);
			}
			break;

		case AUTH_SHA2:
			proto_item_append_text(pi, " - %s", val_to_str(AUTH_SHA2, state_vals, "Unknown (%u)"));
			offset = mysql_dissect_auth_sha2(tvb, pinfo, offset, tree, conn_data);
			break;

		default:
			ti = proto_tree_add_item(tree, hf_mysql_payload, tvb, offset, -1, ENC_NA);
			expert_add_info(pinfo, ti, &ei_mysql_unknown_response);
			offset += tvb_reported_length_remaining(tvb, offset);
			mysql_set_conn_state(pinfo, conn_data, UNDEFINED);
		}
	}

	return offset;
}


static int
mysql_dissect_error_packet(tvbuff_t *tvb, packet_info *pinfo,
			   int offset, proto_tree *tree,
			   const mysql_frame_data_t *my_frame_data)
{
	col_append_fstr(pinfo->cinfo, COL_INFO, " Error %d ", tvb_get_letohs(tvb, offset));
	col_set_fence(pinfo->cinfo, COL_INFO);

	proto_tree_add_item(tree, hf_mysql_error_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (tvb_get_uint8(tvb, offset) == '#')
	{
		offset += 1;
		proto_tree_add_item(tree, hf_mysql_sqlstate, tvb, offset, 5, ENC_ASCII);
		offset += 5;
	}

	proto_tree_add_item(tree, hf_mysql_error_string, tvb, offset, -1, my_frame_data->encoding_results);
	offset += tvb_reported_length_remaining(tvb, offset);

	return offset;
}

/*
  Add a session track entry to the session tracking subtree

  return bytes read
*/
static int
add_session_tracker_entry_to_tree(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree, int offset, mysql_conn_data_t *conn_data) {
	uint8_t data_type; /* session tracker type */
	uint64_t length; /* complete length of session tracking entry */
	uint64_t lenstr;
	int orig_offset = offset, lenfle;
	proto_item *item, *ti;
	proto_tree *session_track_tree;
	const uint8_t *sysvar_value;
	bool charset_client = false, charset_results = false;

	ti = proto_tree_add_item(tree, hf_mysql_session_track, tvb, offset, 1, ENC_NA);
	session_track_tree = proto_item_add_subtree(ti, ett_session_track);

	proto_tree_add_item(session_track_tree, hf_mysql_session_track_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	data_type = tvb_get_uint8(tvb, offset);
	offset += 1;

	lenfle = tvb_get_fle(tvb, session_track_tree, offset, &length, NULL);
	proto_tree_add_uint64(session_track_tree, hf_mysql_session_track_length, tvb, offset, lenfle, length);
	offset += lenfle;

	switch (data_type) {
	case 0: /* SESSION_SYSVARS_TRACKER */
		lenfle = tvb_get_fle(tvb, session_track_tree, offset, &lenstr, NULL);
		proto_tree_add_uint64(session_track_tree, hf_mysql_session_track_sysvar_length, tvb, offset, lenfle, lenstr);
		offset += lenfle;

		proto_tree_add_item(session_track_tree, hf_mysql_session_track_sysvar_name, tvb, offset, (int)lenstr, ENC_ASCII);
		if (tvb_strneql(tvb, offset, "character_set_client", lenstr) == 0) {
			charset_client = true;
		} else if (tvb_strneql(tvb, offset, "character_set_results", lenstr) == 0) {
			charset_results = true;
		}
		offset += (int)lenstr;

		lenfle = tvb_get_fle(tvb, session_track_tree, offset, &lenstr, NULL);
		proto_tree_add_uint64(session_track_tree, hf_mysql_session_track_sysvar_length, tvb, offset, lenfle, lenstr);
		offset += lenfle;

		proto_tree_add_item_ret_string(session_track_tree, hf_mysql_session_track_sysvar_value, tvb, offset, (int)lenstr, ENC_ASCII, pinfo->pool, &sysvar_value);
		if (charset_client) {
			mysql_set_encoding_client(pinfo, conn_data, charset_to_encoding(sysvar_value));
		} else if (charset_results) {
			mysql_set_encoding_results(pinfo, conn_data, charset_to_encoding(sysvar_value));
		}
		offset += (int)lenstr;
		break;
	case 1: /* CURRENT_SCHEMA_TRACKER */
		lenfle = tvb_get_fle(tvb, session_track_tree, offset, &lenstr, NULL);
		proto_tree_add_uint64(session_track_tree, hf_mysql_session_track_schema_length, tvb, offset, lenfle, lenstr);
		offset += lenfle;

		proto_tree_add_item(session_track_tree, hf_mysql_session_track_schema, tvb, offset, (int)lenstr, ENC_ASCII);
		offset += (int)lenstr;
		break;
	case 2: /* SESSION_STATE_CHANGE_TRACKER */
		proto_tree_add_item(session_track_tree, hf_mysql_session_state_change, tvb, offset, 1, ENC_ASCII);
		offset++;
		break;
	case 3: /* SESSION_TRACK_GTIDS */
		proto_tree_add_item(session_track_tree, hf_mysql_session_track_gtids_encoding, tvb, offset, 1, ENC_NA);
		offset++;
		lenfle = tvb_get_fle(tvb, session_track_tree, offset, &lenstr, NULL);
		proto_tree_add_uint64(session_track_tree, hf_mysql_session_track_gtids_length, tvb, offset, lenfle, lenstr);
		offset += lenfle;

		proto_tree_add_item(session_track_tree, hf_mysql_session_track_gtids, tvb, offset, (int)lenstr, ENC_ASCII);
		offset += (int)lenstr;
		break;
	case 4: /* SESSION_TRACK_TRANSACTION_CHARACTERISTICS */
		lenfle = tvb_get_fle(tvb, session_track_tree, offset, &lenstr, NULL);
		proto_tree_add_uint64(session_track_tree, hf_mysql_session_track_transaction_characteristics_length, tvb, offset, lenfle, lenstr);
		offset += lenfle;

		proto_tree_add_item(session_track_tree, hf_mysql_session_track_transaction_characteristics, tvb, offset, (int)lenstr, ENC_ASCII);
		offset += (int)lenstr;
		break;
	case 5: /* SESSION_TRACK_TRANSACTION_STATE */
		lenfle = tvb_get_fle(tvb, session_track_tree, offset, &lenstr, NULL);
		proto_tree_add_uint64(session_track_tree, hf_mysql_session_track_transaction_state_length, tvb, offset, lenfle, lenstr);
		offset += lenfle;

		proto_tree_add_item(session_track_tree, hf_mysql_session_track_transaction_state, tvb, offset, (int)lenstr, ENC_ASCII);
		offset += (int)lenstr;
		break;
	default: /* unsupported types skipped */
		item = proto_tree_add_item(session_track_tree, hf_mysql_payload, tvb, offset, (int)length, ENC_NA);
		expert_add_info_format(pinfo, item, &ei_mysql_dissector_incomplete, "FIXME: unrecognized session tracker data");
		offset += (int)length;
	}
	proto_item_set_len(ti, offset - orig_offset);

	return (offset - orig_offset);
}


/*
  Add a extended metadata entry to the extended meta subtree

  return bytes read
*/
static int
add_extended_meta_entry_to_tree(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree, int offset) {
	uint8_t data_type;
	uint64_t lenstr;
	int orig_offset = offset, lenfle;
	proto_item *item, *ti;
	proto_tree *extmeta_tree;

	ti = proto_tree_add_item(tree, hf_mariadb_extmeta, tvb, offset, 1, ENC_NA);
	extmeta_tree = proto_item_add_subtree(ti, ett_extmeta);

	proto_tree_add_item(extmeta_tree, hf_mariadb_extmeta_key, tvb, offset, 1, ENC_BIG_ENDIAN);
	data_type = tvb_get_uint8(tvb, offset);
	offset += 1;

	lenfle = tvb_get_fle(tvb, extmeta_tree, offset, &lenstr, NULL);
	proto_tree_add_uint64(extmeta_tree, hf_mariadb_extmeta_length, tvb, offset, lenfle, lenstr);
	offset += lenfle;

	switch (data_type) {
	case 0: /* TYPE */
		proto_tree_add_item(extmeta_tree, hf_mariadb_extmeta_type, tvb, offset, (int)lenstr, ENC_ASCII);
		offset += (int)lenstr;
		break;
	case 1: /* FORMAT */
		proto_tree_add_item(extmeta_tree, hf_mariadb_extmeta_format, tvb, offset, (int)lenstr, ENC_ASCII);
		offset += (int)lenstr;
		break;
	default: /* unsupported types skipped */
		item = proto_tree_add_item(extmeta_tree, hf_mysql_payload, tvb, offset, (int)lenstr, ENC_NA);
		expert_add_info_format(pinfo, item, &ei_mysql_dissector_incomplete, "FIXME: unrecognized extended metadata data");
		offset += (int)lenstr;
	}
	proto_item_set_len(ti, offset - orig_offset);

	return (offset - orig_offset);
}

static int
mysql_dissect_ok_packet(tvbuff_t *tvb, packet_info *pinfo, int offset,
			proto_tree *tree, mysql_conn_data_t *conn_data)
{
	uint64_t lenstr = 0;
	uint64_t affected_rows;
	uint64_t insert_id;
	int fle;
	uint16_t server_status = 0;

	col_append_str(pinfo->cinfo, COL_INFO, " OK " );
	col_set_fence(pinfo->cinfo, COL_INFO);

	fle = tvb_get_fle(tvb, tree, offset, &affected_rows, NULL);
	proto_tree_add_uint64(tree, hf_mysql_affected_rows, tvb, offset, fle, affected_rows);
	offset += fle;

	fle= tvb_get_fle(tvb, tree, offset, &insert_id, NULL);
	if (tree && insert_id) {
		proto_tree_add_uint64(tree, hf_mysql_insert_id, tvb, offset, fle, insert_id);
	}
	offset += fle;

	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = mysql_dissect_server_status(tvb, offset, tree, &server_status);

		/* 4.1+ protocol only: 2 bytes number of warnings */
		if (conn_data->clnt_caps & conn_data->srv_caps & MYSQL_CAPS_CU) {
			proto_tree_add_item(tree, hf_mysql_num_warn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			lenstr = tvb_get_ntohs(tvb, offset);
			offset += 2;
		}
	}

	if (conn_data->clnt_caps_ext & MYSQL_CAPS_ST) {
		if (tvb_reported_length_remaining(tvb, offset) > 0) {
			uint64_t session_track_length;
			proto_item *tf;
			proto_item *session_track_tree = NULL;
			int length;

			offset += tvb_get_fle(tvb, tree, offset, &lenstr, NULL);
			/* first read the optional message */
			if (lenstr) {
				proto_tree_add_item(tree, hf_mysql_message, tvb, offset, (int)lenstr, ENC_ASCII);
				offset += (int)lenstr;
			}

			/* session state tracking */
			if (server_status & MYSQL_STAT_SESSION_STATE_CHANGED) {
				fle = tvb_get_fle(tvb, tree, offset, &session_track_length, NULL);
				tf = proto_tree_add_item(tree, hf_mysql_session_track_data, tvb, offset, -1, ENC_NA);
				session_track_tree = proto_item_add_subtree(tf, ett_session_track_data);
				proto_tree_add_uint64(tf, hf_mysql_session_track_data_length, tvb, offset, fle, session_track_length);
				offset += fle;

				while (session_track_length > 0) {
					length = add_session_tracker_entry_to_tree(tvb, pinfo, session_track_tree, offset, conn_data);
					offset += length;
					session_track_length -= length;
				}
			}
		}
	} else {
		/* optional: message string */
		if (tvb_reported_length_remaining(tvb, offset) > 0) {
			if(lenstr > (uint64_t)tvb_reported_length_remaining(tvb, offset))
				lenstr = tvb_reported_length_remaining(tvb, offset);
			proto_tree_add_item(tree, hf_mysql_message, tvb, offset, (int)lenstr, ENC_ASCII);
			offset += (int)lenstr;
		}
	}

	mysql_set_conn_state(pinfo, conn_data, REQUEST);
	return offset;
}


static int
mysql_dissect_server_status(tvbuff_t *tvb, int offset, proto_tree *tree, uint16_t *server_status)
{

	if (server_status) {
		*server_status = tvb_get_letohs(tvb, offset);
	}
	proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_mysql_server_status, ett_stat, mysql_stat_flags, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);

	offset += 2;

	return offset;
}


static int
mysql_dissect_caps(tvbuff_t *tvb, int offset, proto_tree *tree, int mysql_caps, uint16_t *caps)
{

	*caps= tvb_get_letohs(tvb, offset);

	proto_tree_add_bitmask_with_flags(tree, tvb, offset, mysql_caps, ett_caps, mysql_caps_flags, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);

	offset += 2;
	return offset;
}

static int
mysql_dissect_extcaps(tvbuff_t *tvb, int offset, proto_tree *tree, int mysql_extcaps, uint16_t *ext_caps)
{

	*ext_caps= tvb_get_letohs(tvb, offset);

	proto_tree_add_bitmask_with_flags(tree, tvb, offset, mysql_extcaps, ett_extcaps, mysql_extcaps_flags, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);

	offset += 2;
	return offset;
}

static int mariadb_dissect_caps_or_flags(tvbuff_t *tvb, int offset, enum ftenum type, proto_tree *tree,
                                int mariadb_caps, int * const *fields, void *value)
{
	uint8_t diff= 0;

	switch (type) {
	case FT_UINT8:
		*((uint8_t *)value)= tvb_get_uint8(tvb, offset);
		diff= 1;
		break;
	case FT_UINT16:
		*((uint16_t *)value)= tvb_get_letohs(tvb, offset);
		diff= 2;
		break;
	case FT_UINT32:
		*((uint32_t *)value)= tvb_get_letohl(tvb, offset);
		diff= 4;
		break;
	default:
		return 0;
	}
	proto_tree_add_bitmask_with_flags(tree, tvb, offset, mariadb_caps, ett_extcaps, fields, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);

	offset+= diff;
	return offset;
}

static int
mysql_dissect_result_header(tvbuff_t *tvb, packet_info *pinfo, int offset,
			    proto_tree *tree, mysql_conn_data_t *conn_data,
			    const mysql_frame_data_t *my_frame_data)
{
	int fle;
	uint64_t num_fields, extra;
	uint8_t send_meta= 0;
	my_metadata_list_t *field_metas;
	my_stmt_data_t *stmt_data;

	col_append_str(pinfo->cinfo, COL_INFO, "TABULAR " );
	col_set_fence(pinfo->cinfo, COL_INFO);

	fle = tvb_get_fle(tvb, tree, offset, &num_fields, NULL);
	proto_tree_add_uint64(tree, hf_mysql_num_fields, tvb, offset, fle, num_fields);
	offset += fle;

	/** skip info flag **/
	send_meta = 1;
	if (conn_data->mariadb_client_ext_caps & MARIADB_CAPS_ME
		&& conn_data->mariadb_server_ext_caps & MARIADB_CAPS_ME
		&& tvb_reported_length_remaining(tvb, offset)) {
		send_meta = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_mariadb_send_meta, tvb, offset, 1, ENC_NA);
		offset += 1;
	}


	if (num_fields > MAX_MY_METADATA_COUNT) {
		expert_add_info_format(pinfo, tree, &ei_mysql_invalid_length, "Invalid length: %" PRIu64, num_fields);
		return tvb_reported_length_remaining(tvb, 0);
	} else if (send_meta) {
		field_metas = wmem_new(wmem_file_scope(), my_metadata_list_t);
		field_metas->count = (uint16_t)num_fields;
		field_metas->flags = (uint16_t *)wmem_alloc0_array(wmem_file_scope(), uint16_t, (size_t)num_fields);
		field_metas->types = (uint8_t *)wmem_alloc0_array(wmem_file_scope(), uint8_t, (size_t)num_fields);
		field_metas->encodings = (unsigned *)wmem_alloc0_array(wmem_file_scope(), unsigned, (size_t)num_fields);
		mysql_set_field_metas(pinfo, conn_data, field_metas);
	} else {
		if (my_frame_data->stmt_id) {
			stmt_data = (my_stmt_data_t *)wmem_tree_lookup32(conn_data->stmts, my_frame_data->stmt_id);
			if (stmt_data != NULL) {
				field_metas = &stmt_data->field_metas;
				mysql_set_field_metas(pinfo, conn_data, field_metas);
			}
		}

	}

	if (tvb_reported_length_remaining(tvb, offset)) {
		fle = tvb_get_fle(tvb, tree, offset, &extra, NULL);
		proto_tree_add_uint64(tree, hf_mysql_extra, tvb, offset, fle, extra);
		offset += fle;
	}

	if (num_fields) {
		if (send_meta) {
			mysql_set_conn_state(pinfo, conn_data, FIELD_PACKET);
			mysql_set_remaining_field_packet_count(pinfo, conn_data, num_fields);
		} else {
			mysql_set_remaining_field_packet_count(pinfo, conn_data, 0);
			if (conn_data->clnt_caps_ext & MYSQL_CAPS_DE) {
				mysql_set_conn_state(pinfo, conn_data, ROW_PACKET);
			} else {
				/** Intermediate EOF follow **/
				mysql_set_conn_state(pinfo, conn_data, FIELD_PACKET);
			}
		}
	} else {
		mysql_set_conn_state(pinfo, conn_data, ROW_PACKET);
	}

	return offset;
}


/*
 * Add length encoded string to tree
 */
static int
mysql_field_add_lestring(tvbuff_t *tvb, int offset, proto_tree *tree, int field, unsigned encoding)
{
	uint64_t lelen;
	uint8_t is_null;
	header_field_info* hfi;
	proto_item* ti;
	proto_tree* sub_tree;
	int start_offset = offset;

	hfi = proto_registrar_get_nth(field);
	DISSECTOR_ASSERT(hfi != NULL);

	sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_mysql_field, &ti, "%s", hfi->name);

	offset += tvb_get_fle(tvb, sub_tree, offset, &lelen, &is_null);
	if(is_null)
		proto_tree_add_string(sub_tree, field, tvb, offset, 0, "NULL");
	else
	{
		proto_tree_add_item(sub_tree, field, tvb, offset, (int)lelen, encoding);
		/* Prevent infinite loop due to overflow */
		if (offset + (int)lelen < offset) {
			offset = tvb_reported_length(tvb);
		}
		else {
			offset += (int)lelen;
		}
	}
	proto_item_set_len(ti, offset -start_offset);
	return offset;
}


static int
mysql_dissect_field_packet(tvbuff_t *tvb, proto_item *pi _U_, int offset, proto_tree *tree, packet_info *pinfo _U_, mysql_conn_data_t *conn_data, const mysql_frame_data_t *my_frame_data)
{
	uint8_t fld_type;
	uint16_t fld_flag;
	unsigned fld_encoding;
	int length = tvb_reported_length(tvb);
	mysql_state_t current_state = my_frame_data->state;

	unsigned encoding = my_frame_data->encoding_results;

	/* Are these fields optional? a trace suggests they are...*/
	offset = mysql_field_add_lestring(tvb, offset, tree, hf_mysql_fld_catalog, encoding);
	if (offset >= length) {
		return offset;
	}
	offset = mysql_field_add_lestring(tvb, offset, tree, hf_mysql_fld_db, encoding);
	offset = mysql_field_add_lestring(tvb, offset, tree, hf_mysql_fld_table, encoding);
	offset = mysql_field_add_lestring(tvb, offset, tree, hf_mysql_fld_org_table, encoding);
	offset = mysql_field_add_lestring(tvb, offset, tree, hf_mysql_fld_name, encoding);
	offset = mysql_field_add_lestring(tvb, offset, tree, hf_mysql_fld_org_name, encoding);

	// mariadb extended metadata infos
	if (conn_data->mariadb_client_ext_caps & MARIADB_CAPS_EM
		&& conn_data->mariadb_server_ext_caps & MARIADB_CAPS_EM) {
		uint64_t extended_length;
		proto_item *extended_tree = NULL;
		proto_item *tf;
		int fle;

		fle = tvb_get_fle(tvb, tree, offset, &extended_length, NULL);
		tf = proto_tree_add_item(tree, hf_mariadb_extmeta_data, tvb, offset, fle + (uint32_t) extended_length, ENC_NA);
		extended_tree = proto_item_add_subtree(tf, ett_extmeta_data);
		proto_tree_add_uint64(tf, hf_mariadb_extmeta_length, tvb, offset, fle, extended_length);
		offset += fle;

		while (extended_length > 0) {
			length = add_extended_meta_entry_to_tree(tvb, pinfo, extended_tree, offset);
			offset += length;
			extended_length -= length;
		}
	}

	offset +=1; /* filler */

	uint32_t charsetnr;
	proto_tree_add_item_ret_uint(tree, hf_mysql_fld_charsetnr, tvb, offset, 2, ENC_LITTLE_ENDIAN, &charsetnr);
	fld_encoding = collation_to_encoding(charsetnr, conn_data->is_mariadb_server);
	offset += 2; /* charset */

	proto_tree_add_item(tree, hf_mysql_fld_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4; /* length */

	proto_tree_add_item(tree, hf_mysql_fld_type, tvb, offset, 1, ENC_NA);
	fld_type = tvb_get_uint8(tvb, offset);
	offset += 1; /* type */

	proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_mysql_fld_flags, ett_field_flags, mysql_fld_flags, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
	fld_flag = tvb_get_letohs(tvb, offset);
	offset += 2; /* flags */

	proto_tree_add_item(tree, hf_mysql_fld_decimals, tvb, offset, 1, ENC_NA);
	offset += 1; /* decimals */

	offset += 2; /* filler */

	if (current_state == FIELD_PACKET || current_state == PREPARED_FIELDS) {
		if (my_frame_data->field_metas.count) {
			uint64_t fieldpos = my_frame_data->field_metas.count - my_frame_data->remaining_field_packet_count;
			if (fieldpos >= my_frame_data->field_metas.count) {
				expert_add_info_format(pinfo, tree, &ei_mysql_invalid_length, "Invalid length: %" PRIu64, fieldpos);
				return tvb_reported_length_remaining(tvb, 0);
			}
			my_frame_data->field_metas.types[fieldpos] = fld_type;
			my_frame_data->field_metas.flags[fieldpos] = fld_flag;
			my_frame_data->field_metas.encodings[fieldpos] = fld_encoding;
		}
	}

	/* default (Only use for show fields) */
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = mysql_field_add_lestring(tvb, offset, tree, hf_mysql_fld_default, encoding);
	}
	return offset;
}


static int
mysql_dissect_text_row_packet(tvbuff_t *tvb, int offset, proto_tree *tree, const mysql_frame_data_t *my_frame_data)
{
	int fieldpos = 0;
	unsigned encoding;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		if (fieldpos < my_frame_data->field_metas.count) {
			encoding = my_frame_data->field_metas.encodings[fieldpos];
		} else {
			encoding = my_frame_data->encoding_results;
		}
		offset = mysql_field_add_lestring(tvb, offset, tree, hf_mysql_row_text, encoding);
		fieldpos++;
	}

	return offset;
}

static int
mysql_dissect_binary_row_packet(tvbuff_t *tvb, packet_info *pinfo, proto_item *pi, int offset, proto_tree *tree, mysql_conn_data_t *conn_data _U_, const mysql_frame_data_t *my_frame_data)
{
	int fieldpos;
	proto_item* ti;
	proto_tree* bf_tree;

	if (my_frame_data->field_metas.count) {

		/* null bitmap */
		int nfields = my_frame_data->field_metas.count;
		int null_len = (nfields + 9) / 8;

		char *null_buffer;
		null_buffer = (uint8_t *)wmem_alloc(pinfo->pool, (size_t)null_len + 1);
		tvb_get_raw_bytes_as_string(tvb, offset, null_buffer, (size_t)null_len + 1);
		proto_tree_add_bytes_with_length(tree, hf_mysql_null_buffer, tvb, offset, null_len, null_buffer, null_len);
		offset += null_len;

		for (fieldpos = 0; fieldpos < nfields; fieldpos++) {
			if ((null_buffer[(fieldpos + 2) / 8] & (1 << ((fieldpos + 2) % 8))) == 0) {
				// data is not null
				if (tvb_reported_length_remaining(tvb, offset) > 0) {
					bf_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_mysql_binary_field, &ti, "Binary Field");
					if (!mysql_dissect_binary_row_value(tvb, pinfo, pi, &offset, bf_tree,
					                                    my_frame_data->field_metas.types[fieldpos],
					                                    my_frame_data->field_metas.flags[fieldpos],
														my_frame_data->field_metas.encodings[fieldpos]))
						break;
				}
			} else {
				proto_tree_add_item(tree, hf_mysql_exec_field_null, tvb, offset, 0, ENC_NA);
			}
		}
	}


	return offset;
}

static char
mysql_dissect_binary_row_value(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *pi _U_, int *offset, proto_item *tree, uint8_t field_type, uint16_t field_flag, unsigned field_encoding)
{
	int dissector_index = 0;
	uint8_t param_unsigned = 0;
	if (field_flag & MYSQL_FLD_UNSIGNED_FLAG) {
		param_unsigned = 1;
	}

	while (mysql_exec_dissectors[dissector_index].dissector != NULL) {
		if (mysql_exec_dissectors[dissector_index].type == field_type &&
			mysql_exec_dissectors[dissector_index].unsigned_flag == param_unsigned) {
			mysql_exec_dissectors[dissector_index].dissector(tvb, pinfo, offset, tree, field_encoding);
			return 1;
		}
		dissector_index++;
	}
	return 0;
}

static int
mysql_dissect_response_prepare(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data)
{
	my_stmt_data_t *stmt_data;
	my_metadata_list_t *field_metas;
	my_metadata_list_t *param_metas;

	uint32_t stmt_id;
	uint16_t stmt_num_fields;
	uint16_t stmt_num_params;

	proto_tree_add_item_ret_uint(tree, hf_mysql_stmt_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &stmt_id);
	mysql_set_prepared_stmt_id(pinfo, conn_data, stmt_id);
	offset += 4;
	proto_tree_add_item(tree, hf_mysql_num_fields, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	stmt_num_fields = tvb_get_letohs(tvb, offset);
	offset += 2;
	proto_tree_add_item(tree, hf_mysql_num_params, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	stmt_num_params = tvb_get_letohs(tvb, offset);

	if (!pinfo->fd->visited) {
#if 0
		/* XXX: Can statement ids be reused on the same connection?
	         * If so, the tree should be a multimap or similar. If not,
	         * there should be an expert info if we see a reused one.
	         */
		if (wmem_tree_lookup32(conn_data->stmts, stmt_id) != NULL) {
			/* Expert Info? */
		}
#endif

		stmt_data = wmem_new(wmem_file_scope(), struct my_stmt_data);
		param_metas = wmem_new(wmem_file_scope(), my_metadata_list_t);
		param_metas->count = stmt_num_params;
		param_metas->flags = (uint16_t *)wmem_alloc0_array(wmem_file_scope(), uint16_t, param_metas->count);
		param_metas->types = (uint8_t *)wmem_alloc0_array(wmem_file_scope(), uint8_t, param_metas->count);
		//param_metas->encodings = (unsigned *)wmem_alloc0_array(wmem_file_scope(), unsigned, param_metas->count);
		stmt_data->param_metas = *param_metas;

		field_metas = wmem_new(wmem_file_scope(), my_metadata_list_t);
		field_metas->count = stmt_num_fields;
		field_metas->flags = (uint16_t *)wmem_alloc0_array(wmem_file_scope(), uint16_t, field_metas->count);
		field_metas->types = (uint8_t *)wmem_alloc0_array(wmem_file_scope(), uint8_t, field_metas->count);
		field_metas->encodings = (unsigned *)wmem_alloc0_array(wmem_file_scope(), unsigned, field_metas->count);
		stmt_data->field_metas = *field_metas;

		wmem_tree_insert32(conn_data->stmts, stmt_id, stmt_data);

		mysql_set_field_metas(pinfo, conn_data, field_metas);
	}

	offset += 2;
	/* Filler */
	offset += 1;
	proto_tree_add_item(tree, hf_mysql_num_warn, tvb, offset, 2, ENC_LITTLE_ENDIAN);

	if (stmt_num_params > 0) {
		mysql_set_remaining_field_packet_count(pinfo, conn_data, stmt_num_params);
		mysql_set_conn_state(pinfo, conn_data, PREPARED_PARAMETERS);
	} else if (stmt_num_fields > 0) {
		mysql_set_remaining_field_packet_count(pinfo, conn_data, stmt_num_fields);
		mysql_set_conn_state(pinfo, conn_data, PREPARED_FIELDS);
	} else {
		mysql_set_remaining_field_packet_count(pinfo, conn_data, 0);
		mysql_set_conn_state(pinfo, conn_data, REQUEST);
	}

	return offset + tvb_reported_length_remaining(tvb, offset);
}

/**
  Enumeration type for the different types of log events.
*/
enum Log_event_type {
	/**
	  Every time you add a type, you have to
	  - Assign it a number explicitly. Otherwise it will cause trouble
		if a event type before is deprecated and removed directly from
		the enum.
	  - Fix Format_description_event::Format_description_event().
	*/
	UNKNOWN_EVENT = 0,
	/*
	  Deprecated since mysql 8.0.2. It is just a placeholder,
	  should not be used anywhere else.
	*/
	START_EVENT_V3 = 1,
	QUERY_EVENT = 2,
	STOP_EVENT = 3,
	ROTATE_EVENT = 4,
	INTVAR_EVENT = 5,

	SLAVE_EVENT = 7,

	APPEND_BLOCK_EVENT = 9,
	DELETE_FILE_EVENT = 11,

	RAND_EVENT = 13,
	USER_VAR_EVENT = 14,
	FORMAT_DESCRIPTION_EVENT = 15,
	XID_EVENT = 16,
	BEGIN_LOAD_QUERY_EVENT = 17,
	EXECUTE_LOAD_QUERY_EVENT = 18,

	TABLE_MAP_EVENT = 19,

	/**
	  The V1 event numbers are used from 5.1.16 until mysql-5.6.
	*/
	WRITE_ROWS_EVENT_V1 = 23,
	UPDATE_ROWS_EVENT_V1 = 24,
	DELETE_ROWS_EVENT_V1 = 25,

	/**
	  Something out of the ordinary happened on the master
	 */
	INCIDENT_EVENT = 26,

	/**
	  Heartbeat event to be send by master at its idle time
	  to ensure master's online status to slave
	*/
	HEARTBEAT_LOG_EVENT = 27,

	/**
	  In some situations, it is necessary to send over ignorable
	  data to the slave: data that a slave can handle in case there
	  is code for handling it, but which can be ignored if it is not
	  recognized.
	*/
	IGNORABLE_LOG_EVENT = 28,
	ROWS_QUERY_LOG_EVENT = 29,

	/** Version 2 of the Row events */
	WRITE_ROWS_EVENT = 30,
	UPDATE_ROWS_EVENT = 31,
	DELETE_ROWS_EVENT = 32,

	GTID_LOG_EVENT = 33,
	ANONYMOUS_GTID_LOG_EVENT = 34,

	PREVIOUS_GTIDS_LOG_EVENT = 35,

	TRANSACTION_CONTEXT_EVENT = 36,

	VIEW_CHANGE_EVENT = 37,

	/* Prepared XA transaction terminal event similar to Xid */
	XA_PREPARE_LOG_EVENT = 38,

	/**
	  Extension of UPDATE_ROWS_EVENT, allowing partial values according
	  to binlog_row_value_options.
	*/
	PARTIAL_UPDATE_ROWS_EVENT = 39,

	TRANSACTION_PAYLOAD_EVENT = 40,

	HEARTBEAT_LOG_EVENT_V2 = 41,
	/**
	  Add new events here - right above this comment!
	  Existing events (except ENUM_END_EVENT) should never change their numbers
	*/
	ENUM_END_EVENT /* end marker */
};

static const value_string mysql_binlog_event_type_vals[] = {
	{0, "Unknown"},

	{1, "START_EVENT_V3"},
	{2, "Query"},
	{3, "Stop"},
	{4, "Rotate"},
	{5, "Intvar"},

	{7, "SLAVE_EVENT"},

	{9, "Append_block"},
	{11, "Delete_file"},

	{13, "RAND"},
	{14, "User_var"},
	{15, "Format_desc"},
	{16, "Xid"},
	{17, "Begin_load_query"},
	{18, "Execute_load_query"},

	{19, "Table_map"},

	{23, "Write_rows_v1"},
	{24, "Update_rows_v1"},
	{25, "Delete_rows_v1"},

	{26, "Incident"},

	{27, "Heartbeat"},

	{28, "Ignorable"},
	{29, "Rows_query"},

	{30, "Write_rows"},
	{31, "Update_rows"},
	{32, "Delete_rows"},

	{33, "Gtid"},
	{34, "Anonymous_Gtid"},

	{35, "Previous_gtids"},

	{36, "Transaction_context"},

	{37, "View_change"},

	{38, "XA_prepare"},

	{39, "Update_rows_partial"},

	{40, "Transaction_payload"},

	{41, "Heartbeat_v2"},
	{0, NULL},
};

static int
mysql_dissect_binlog_event_heartbeat_v2(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree)
{
	int fle;
	uint64_t num;
	proto_item *item, *parent_item;
	proto_item *hb_v2_tree, *hb_v2_subtree;

	col_append_str(pinfo->cinfo, COL_INFO, "Heartbeat_v2 ");
	col_set_fence(pinfo->cinfo, COL_INFO);
	item = proto_tree_add_item(tree, hf_mysql_binlog_event_heartbeat_v2, tvb, offset, -1, ENC_NA);
	hb_v2_tree = proto_item_add_subtree(item, ett_binlog_event);

	// OTW_HB_LOG_FILENAME_FIELD
	parent_item = proto_tree_add_item(hb_v2_tree, hf_mysql_binlog_event_heartbeat_v2_otw, tvb, offset, -1, ENC_NA);
	hb_v2_subtree = proto_item_add_subtree(parent_item, ett_binlog_event_hb_v2);

	item = proto_tree_add_item(hb_v2_subtree, hf_mysql_binlog_event_heartbeat_v2_otw_type, tvb, offset, 1, ENC_NA);
	proto_item_append_text(item, " (OTW_HB_LOG_FILENAME_FIELD)");
	proto_item_append_text(parent_item, " OTW_HB_LOG_FILENAME_FIELD");
	offset += 1;

	fle = tvb_get_fle(tvb, hb_v2_subtree, offset, &num, ENC_NA);
	offset += fle;

	proto_tree_add_item(hb_v2_subtree, hf_mysql_binlog_hb_event_filename, tvb, offset, (int) num, ENC_ASCII);
	offset += (int)num;

	// OTW_HB_LOG_POSITION_FIELD
	parent_item = proto_tree_add_item(hb_v2_tree, hf_mysql_binlog_event_heartbeat_v2_otw, tvb, offset, -1, ENC_NA);
	hb_v2_subtree = proto_item_add_subtree(parent_item, ett_binlog_event_hb_v2);
	item = proto_tree_add_item(hb_v2_subtree, hf_mysql_binlog_event_heartbeat_v2_otw_type, tvb, offset, 1, ENC_NA);
	proto_item_append_text(item, " (OTW_HB_LOG_POSITION_FIELD)");
	proto_item_append_text(parent_item, " OTW_HB_LOG_POSITION_FIELD");
	offset += 1;

	fle = tvb_get_fle(tvb, hb_v2_subtree, offset, &num, NULL);
	offset += fle;

	fle = tvb_get_fle(tvb, hb_v2_subtree, offset, &num, NULL);
	proto_tree_add_uint64(hb_v2_subtree, hf_mysql_binlog_hb_event_log_position, tvb, offset, fle, num);
	offset += fle;

	// OTW_HB_LOG_FILENAME_FIELD
	parent_item = proto_tree_add_item(hb_v2_tree, hf_mysql_binlog_event_heartbeat_v2_otw, tvb, offset, -1, ENC_NA);
	hb_v2_subtree = proto_item_add_subtree(parent_item, ett_binlog_event_hb_v2);
	item = proto_tree_add_item(hb_v2_subtree, hf_mysql_binlog_event_heartbeat_v2_otw_type, tvb, offset, 1, ENC_NA);
	proto_item_append_text(item, " (OTW_HB_HEADER_END_MARK)");
	proto_item_append_text(parent_item, " OTW_HB_HEADER_END_MARK");
	offset += 1;
	return offset;
}

static int
mysql_dissect_binlog_event_header(tvbuff_t *tvb, int offset, proto_tree *tree, proto_item *pi)
{
	proto_tree_add_item(tree, hf_mysql_binlog_event_header_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mysql_binlog_event_header_event_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_item_append_text(pi, ": %s", val_to_str(tvb_get_uint8(tvb, offset), mysql_binlog_event_type_vals, "Unknown event type: %d"));
	offset += 1;

	proto_tree_add_item(tree, hf_mysql_binlog_event_header_server_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mysql_binlog_event_header_event_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mysql_binlog_event_header_log_position, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mysql_binlog_event_header_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	return offset;
}

static int
mysql_dissect_binlog_event_packet(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, proto_item *pi)
{
	uint8_t event_type;
	int fle;

	col_append_str(pinfo->cinfo, COL_INFO, "Binlog Event " );
	col_set_fence(pinfo->cinfo, COL_INFO);

	event_type = tvb_get_uint8(tvb, offset + 4);
	offset = mysql_dissect_binlog_event_header(tvb, offset, tree, pi);

	switch (event_type) {
		case HEARTBEAT_LOG_EVENT_V2:
			offset = mysql_dissect_binlog_event_heartbeat_v2(tvb, pinfo, offset, tree);
			break;
		default:
			fle = tvb_reported_length_remaining(tvb, offset);
			offset += fle - 4;
			break;
	}
	// checksum
	proto_tree_add_item(tree, hf_mysql_binlog_event_checksum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	return offset;
}

static int
mysql_dissect_eof(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *pi _U_, int offset, proto_tree *tree, mysql_conn_data_t *conn_data _U_)
{
	uint16_t server_status = 0;
	proto_tree_add_item(tree, hf_mysql_num_warn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	offset = mysql_dissect_server_status(tvb, offset, tree, &server_status);
	return offset + tvb_reported_length_remaining(tvb, offset);
}

static int
mysql_dissect_auth_switch_request(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data _U_)
{
	int lenstr;

	col_set_str(pinfo->cinfo, COL_INFO, "Auth Switch Request " );
	col_set_fence(pinfo->cinfo, COL_INFO);
	mysql_set_conn_state(pinfo, conn_data, AUTH_SWITCH_RESPONSE);

	if (conn_data->clnt_caps_ext & MYSQL_CAPS_PA) {
		/* https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_switch_request.html */

		/* name */
		lenstr = my_tvb_strsize(tvb, offset);
		proto_tree_add_item(tree, hf_mysql_auth_switch_request_name, tvb, offset, lenstr, ENC_ASCII);
		conn_data->auth_method = tvb_get_string_enc(wmem_file_scope(), tvb, offset, lenstr, ENC_ASCII);
		offset += lenstr;

		/* Data */
		lenstr = my_tvb_strsize(tvb, offset);
		proto_tree_add_item(tree, hf_mysql_auth_switch_request_data, tvb, offset, lenstr, ENC_NA);
		offset += lenstr;
	} else {
		/* https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_old_auth_switch_request.html */

		/* Status (Always 0xfe) */
		proto_tree_add_item(tree, hf_mysql_auth_switch_request_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
	}

	return offset + tvb_reported_length_remaining(tvb, offset);

}
static int
mysql_dissect_auth_switch_response(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data _U_)
{
	int lenstr;

	col_set_str(pinfo->cinfo, COL_INFO, "Auth Switch Response " );
	col_set_fence(pinfo->cinfo, COL_INFO);

	/* Data */
	lenstr = my_tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_mysql_auth_switch_response_data, tvb, offset, lenstr, ENC_NA);
	offset += lenstr;

	if (g_strcmp0(conn_data->auth_method,"caching_sha2_password") == 0) {
		mysql_set_conn_state(pinfo, conn_data, AUTH_SHA2);
	}

	return offset + tvb_reported_length_remaining(tvb, offset);

}

/*
 caching_sha2_password authentication state

 Doc: https://dev.mysql.com/doc/dev/mysql-server/latest/page_caching_sha2_authentication_exchanges.html
*/
static int
mysql_dissect_auth_sha2(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, mysql_conn_data_t *conn_data _U_)
{
	col_set_str(pinfo->cinfo, COL_INFO, "Caching_sha2_password " );
	col_set_fence(pinfo->cinfo, COL_INFO);

	if (tvb_reported_length_remaining(tvb,offset) == 2)
		offset++;
	char *auth2_state;
	uint8_t c = tvb_get_uint8(tvb, offset);
	switch (c) {
		case 2:
			auth2_state = "request_public_key";
			mysql_set_conn_state(pinfo, conn_data, AUTH_PUBKEY);
			break;
		case 3:
			auth2_state = "fast_auth_success";
			break;
		case 4:
			auth2_state = "perform_full_authentication";
			mysql_set_conn_state(pinfo, conn_data, AUTH_SHA2);
			break;
		default:
			auth2_state = "unknown";
	}
	col_append_str(pinfo->cinfo, COL_INFO, auth2_state);
	proto_tree_add_string(tree, hf_mysql_sha2_auth, tvb, offset, 1, auth2_state);
	offset++;

	return offset + tvb_reported_length_remaining(tvb, offset);
}

/*
 Public key as requested during caching_sha2_password authentication
*/
static int
mysql_dissect_pubkey(tvbuff_t *tvb, packet_info *pinfo, int offset,
		       proto_tree *tree, mysql_conn_data_t *conn_data _U_, proto_item *pi _U_, mysql_state_t current_state _U_)
{
	tvbuff_t *next_tvb;
	col_set_str(pinfo->cinfo, COL_INFO, "Public key " );
	col_set_fence(pinfo->cinfo, COL_INFO);
	mysql_set_conn_state(pinfo, conn_data, AUTH_SHA2_RESPONSE);

	offset++;
	int len = tvb_reported_length_remaining(tvb, offset) - 1;
	next_tvb = tvb_new_subset_length(tvb, offset, len);
	add_new_data_source(pinfo, next_tvb, "public key");
	proto_tree_add_item(tree, hf_mysql_pubkey, tvb, offset, len, ENC_ASCII);
	offset += len;

	return offset + tvb_reported_length_remaining(tvb,offset);
}

/*
 If caching_sha2_password authentication is used over a non-secure channel
 then the authentication response (password) is encrypted with a RSA public key.

 This means that we can't dissect this response without access to the RSA private key.
*/
static int
mysql_dissect_sha2_response(tvbuff_t *tvb, packet_info *pinfo _U_, int offset,
		       proto_tree *tree _U_, mysql_conn_data_t *conn_data _U_, proto_item *pi _U_, mysql_state_t current_state _U_)
{
	int len = tvb_reported_length_remaining(tvb, offset);
	proto_tree_add_item(tree, hf_mysql_sha2_response, tvb, offset, len, ENC_NA);
	return offset + tvb_reported_length_remaining(tvb, offset);
}

static int
mysql_dissect_clone_request(tvbuff_t *tvb _U_, packet_info *pinfo _U_, int offset _U_,
		       proto_tree *tree _U_, mysql_conn_data_t *conn_data _U_, proto_item *pi _U_, mysql_state_t current_state _U_)
{
	uint8_t req_code = tvb_get_uint8(tvb, offset);
	switch (req_code) {
		case MYSQL_CLONE_COM_INIT:
		case MYSQL_CLONE_COM_ATTACH:
		case MYSQL_CLONE_COM_REINIT:
		case MYSQL_CLONE_COM_EXECUTE:
		case MYSQL_CLONE_COM_ACK:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(req_code, mysql_clone_command_vals, "Unknown clone request: %d"));
			proto_tree_add_item(tree, hf_mysql_clone_command_code, tvb, offset, 1, ENC_NA);
			break;
		case MYSQL_CLONE_COM_EXIT:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(req_code, mysql_clone_command_vals, "Unknown clone request: %d"));
			proto_tree_add_item(tree, hf_mysql_clone_command_code, tvb, offset, 1, ENC_NA);
			mysql_set_conn_state(pinfo, conn_data, CLONE_EXIT);
			break;
		default:
			col_append_str(pinfo->cinfo, COL_INFO, " Unknown Clone Command Code") ;
			/* TODO, Set error etc */
	}
	offset++;

	return offset;
}

static int
mysql_dissect_clone_response(tvbuff_t *tvb, packet_info *pinfo, int offset,
		       proto_tree *tree, mysql_conn_data_t *conn_data, proto_item *pi _U_, mysql_state_t current_state)
{
	uint8_t resp_code = tvb_get_uint8(tvb, offset);
	switch (resp_code) {
		case MYSQL_CLONE_COM_RES_LOCS:
		case MYSQL_CLONE_COM_RES_DATA_DESC:
		case MYSQL_CLONE_COM_RES_DATA:
		case MYSQL_CLONE_COM_RES_PLUGIN:
		case MYSQL_CLONE_COM_RES_CONFIG:
		case MYSQL_CLONE_COM_RES_COLLATION:
		case MYSQL_CLONE_COM_RES_PLUGIN_V2:
		case MYSQL_CLONE_COM_RES_CONFIG_V3:
		case MYSQL_CLONE_COM_RES_COMPLETE:
			if (current_state == CLONE_EXIT)
				mysql_set_conn_state(pinfo, conn_data, REQUEST);
			/* fall through */
		case MYSQL_CLONE_COM_RES_ERROR:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(resp_code, mysql_clone_response_vals, "unknown clone request: %d"));
			proto_tree_add_item(tree, hf_mysql_clone_response_code, tvb, offset, 1, ENC_NA);
			break;
		default:
			col_append_str(pinfo->cinfo, COL_INFO, " Unknown Clone Response Code") ;
			/* TODO, Set error etc */
	}
	offset++;

	return offset;
}

/*
 This is the payload (file content) of the LOAD DATA LOCAL INFILE
 https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_local_infile_data.html
*/
static int
mysql_dissect_loaddata(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree, mysql_conn_data_t *conn_data _U_)
{
	col_append_str(pinfo->cinfo, COL_INFO, " LOCAL INFILE Payload");
	col_set_fence(pinfo->cinfo, COL_INFO);
	int lenstr = tvb_reported_length_remaining(tvb, offset);
	tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, lenstr);
	add_new_data_source(pinfo, next_tvb, "local infile");
	proto_tree_add_item(tree, hf_mysql_loaddata_payload, tvb, offset, lenstr, ENC_NA);
	offset += lenstr;
	mysql_set_conn_state(pinfo, conn_data, REQUEST);
	return offset;
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
static int
my_tvb_strsize(tvbuff_t *tvb, int offset)
{
	int len = tvb_strnlen(tvb, offset, -1);
	if (len == -1) {
		len = tvb_reported_length_remaining(tvb, offset);
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
     tree    in....protocol tree
     offset  in    offset in buffer
     res     out   where to store FLE value, may be NULL
     is_null out   where to store ISNULL flag, may be NULL

 DESCRIPTION
   read FLE from packet buffer and store its value and ISNULL flag
   in caller provided variables

   Docs: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_dt_integers.html

 RETURN VALUE
   length of FLE
*/
static int
tvb_get_fle(tvbuff_t *tvb, proto_tree *tree _U_, int offset, uint64_t *res, uint8_t *is_null)
{
	uint8_t prefix;
	int num_bytes;
	uint64_t length;

	prefix = tvb_get_uint8(tvb, offset);

	if (is_null) {
		*is_null = 0;
	}

	switch (prefix) {
	case 251:
		if (res)
			*res = 0;
		if (is_null)
			*is_null = 1;
		return 1;
	case 252: // 0xFC
		num_bytes = 3;
		offset++;
		length = (uint64_t)tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
		break;
	case 253: // 0xFD
		num_bytes = 4;
		offset++;
		length = (uint64_t)tvb_get_uint24(tvb, offset, ENC_LITTLE_ENDIAN);
		break;
	case 254: // 0xFE
		num_bytes = 9;
		offset++;
		length = tvb_get_uint64(tvb, offset, ENC_LITTLE_ENDIAN);
		break;
	default:
		num_bytes = 1;
		length = tvb_get_uint8(tvb, offset);
	}

	if (res) {
		*res = length;
	}
	return num_bytes;
}

static unsigned
get_mysql_compressed_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	/* Compressed packet header: compressed length (3) + sequence number (1)
	 * + uncompressed packet length (3) */
	unsigned len = 7 + tvb_get_letoh24(tvb, offset);
	return len;
}

/* dissector helper: length of PDU */
static unsigned
get_mysql_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	/* Regular packet header: length (3) + sequence number (1) */
	unsigned len = 4 + tvb_get_letoh24(tvb, offset);
	return len;
}

/* dissector main function: handle one PDU */
static int
dissect_mysql_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree      *mysql_tree= NULL;
	proto_item      *ti;
	conversation_t  *conversation;
	int             offset = 0;
	unsigned        packet_number;
	bool            is_response, is_tls = false;
	mysql_conn_data_t  *conn_data;
#ifdef CTDEBUG
	mysql_state_t conn_state_in, conn_state_out, frame_state;
	uint64_t        generation;
	proto_item *pi;
#endif
	struct mysql_frame_data  *mysql_frame_data_p;

	/* get conversation, create if necessary*/
	conversation= find_or_create_conversation(pinfo);

	/* get associated state information, create if necessary */
	conn_data= (mysql_conn_data_t *)conversation_get_proto_data(conversation, proto_mysql);
	if (!conn_data) {
		conn_data = wmem_new0(wmem_file_scope(), mysql_conn_data_t);
		conn_data->stmts = wmem_tree_new(wmem_file_scope());
		conn_data->encoding_client = ENC_UTF_8;
		conn_data->encoding_results = ENC_UTF_8;

		// Client and server capability flags
		// Set in case the conversation doesn't start with greeting/login
		conn_data->clnt_caps = MYSQL_CAPS_CU;    // CLIENT_PROTOCOL_41
		conn_data->clnt_caps_ext = MYSQL_CAPS_DE // CLIENT_DEPRECATE_EOF
			^ MYSQL_CAPS_ST;                 // CLIENT_SESSION_TRACK
		conn_data->srv_caps = MYSQL_CAPS_CU;     // CLIENT_PROTOCOL_41
		conn_data->srv_caps_ext = MYSQL_CAPS_DE; // CLIENT_DEPRECATE_EOF

		conversation_add_proto_data(conversation, proto_mysql, conn_data);
	}

	/* Using tvb_raw_offset(tvb) allows storage of multiple "proto data" in a single frame
	 * (when there are multiple MySQL pdus in a single frame) */
	mysql_frame_data_p = (struct mysql_frame_data *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mysql, tvb_raw_offset(tvb));
	if (!mysql_frame_data_p) {
		/*  We haven't seen this frame before.  Store the state of the
		 *  conversation now so if/when we dissect the frame again
		 *  we'll start with the same state.
		 */
		mysql_frame_data_p = wmem_new(wmem_file_scope(), struct mysql_frame_data);
		mysql_frame_data_p->state = conn_data->state;
		mysql_frame_data_p->resultset_fmt = conn_data->resultset_fmt;
		mysql_frame_data_p->stmt_id = conn_data->stmt_id;
		mysql_frame_data_p->remaining_field_packet_count = conn_data->remaining_field_packet_count;
		mysql_frame_data_p->field_metas = conn_data->field_metas;
		mysql_frame_data_p->encoding_client = conn_data->encoding_client;
		mysql_frame_data_p->encoding_results = conn_data->encoding_results;
		p_add_proto_data(wmem_file_scope(), pinfo, proto_mysql, tvb_raw_offset(tvb), mysql_frame_data_p);
	}

	ti = proto_tree_add_item(tree, proto_mysql, tvb, offset, -1, ENC_NA);
	mysql_tree = proto_item_add_subtree(ti, ett_mysql);
	proto_tree_add_item(mysql_tree, hf_mysql_packet_length, tvb, offset, 3, ENC_LITTLE_ENDIAN);
	offset+= 3;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MySQL");

	if (pinfo->destport == pinfo->match_uint) {
		is_response= false;
	} else {
		is_response= true;
	}

	packet_number = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(mysql_tree, hf_mysql_packet_number, tvb, offset, 1, ENC_NA);
	offset += 1;

#ifdef CTDEBUG
	conn_state_in= conn_data->state;
	frame_state = mysql_frame_data_p->state;
	generation= conn_data->generation;
	if (tree) {
		pi = proto_tree_add_debug_text(mysql_tree, "conversation: %p", conversation);
		proto_item_set_generated(pi);
		pi = proto_tree_add_debug_text(mysql_tree, "generation: %" PRId64, generation);
		proto_item_set_generated(pi);
		pi = proto_tree_add_debug_text(mysql_tree, "conn state: %s (%u)",
				    val_to_str(conn_state_in, state_vals, "Unknown (%u)"),
				    conn_state_in);
		proto_item_set_generated(pi);
		pi = proto_tree_add_debug_text(mysql_tree, "frame state: %s (%u)",
				    val_to_str(frame_state, state_vals, "Unknown (%u)"),
				    frame_state);
		proto_item_set_generated(pi);
	}
#endif

	is_tls = proto_is_frame_protocol(pinfo->layers, "tls");

	if (is_response) {
		if (packet_number == 0 && mysql_frame_data_p->state == UNDEFINED) {
			col_set_str(pinfo->cinfo, COL_INFO, "Server Greeting ");
			offset = mysql_dissect_greeting(tvb, pinfo, offset, mysql_tree, conn_data, mysql_frame_data_p);
		} else if ((mysql_frame_data_p->state == CLONE_ACTIVE) || (mysql_frame_data_p->state == CLONE_EXIT)) {
			col_set_str(pinfo->cinfo, COL_INFO, "Clone Response");
			offset = mysql_dissect_clone_response(tvb, pinfo, offset, mysql_tree, conn_data, ti, mysql_frame_data_p->state);
		} else if (mysql_frame_data_p->state == AUTH_PUBKEY) {
			col_set_str(pinfo->cinfo, COL_INFO, "Public key ");
			offset = mysql_dissect_pubkey(tvb, pinfo, offset, mysql_tree, conn_data, ti, mysql_frame_data_p->state);
		} else {
			col_set_str(pinfo->cinfo, COL_INFO, "Response ");
			offset = mysql_dissect_response(tvb, pinfo, offset, mysql_tree, conn_data, ti, mysql_frame_data_p);
		}
	} else {
		if (mysql_frame_data_p->state == LOGIN && (packet_number == 1 || (packet_number == 2 && is_tls))) {
			col_set_str(pinfo->cinfo, COL_INFO, "Login Request");
			offset = mysql_dissect_login(tvb, pinfo, offset, mysql_tree, conn_data);

			// If both zlib and ZSTD flags are set then zlib is used.
			if ((conn_data->srv_caps & MYSQL_CAPS_CP) && (conn_data->clnt_caps & MYSQL_CAPS_CP)) {
				conn_data->frame_start_compressed = pinfo->num;
				conn_data->compressed_state = MYSQL_COMPRESS_INIT;
				conn_data->compressed_alg = MYSQL_COMPRESS_ALG_ZLIB;
			} else if ((conn_data->srv_caps_ext & MYSQL_CAPS_ZS) && (conn_data->clnt_caps_ext & MYSQL_CAPS_ZS)) {
				conn_data->frame_start_compressed = pinfo->num;
				conn_data->compressed_state = MYSQL_COMPRESS_INIT;
				conn_data->compressed_alg = MYSQL_COMPRESS_ALG_ZSTD;
			}
		} else if ((mysql_frame_data_p->state == CLONE_ACTIVE) || (mysql_frame_data_p->state == CLONE_EXIT)) {
			col_set_str(pinfo->cinfo, COL_INFO, "Clone Request");
			offset = mysql_dissect_clone_request(tvb, pinfo, offset, mysql_tree, conn_data, ti, mysql_frame_data_p->state);
		} else if (mysql_frame_data_p->state == AUTH_SHA2_RESPONSE) {
			col_set_str(pinfo->cinfo, COL_INFO, "Caching_sha2_password response");
			offset = mysql_dissect_sha2_response(tvb, pinfo, offset, mysql_tree, conn_data, ti, mysql_frame_data_p->state);
		} else {
			col_set_str(pinfo->cinfo, COL_INFO, "Request");
			offset = mysql_dissect_request(tvb, pinfo, offset, mysql_tree, conn_data, mysql_frame_data_p);
		}
	}

#ifdef CTDEBUG
	conn_state_out= conn_data->state;
	++(conn_data->generation);
	pi = proto_tree_add_debug_text(mysql_tree, "next proto state: %s (%u)",
			    val_to_str(conn_state_out, state_vals, "Unknown (%u)"),
			    conn_state_out);
	proto_item_set_generated(pi);
#endif

	/* remaining payload indicates an error */
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		ti = proto_tree_add_item(mysql_tree, hf_mysql_payload, tvb, offset, -1, ENC_NA);
		expert_add_info(pinfo, ti, &ei_mysql_dissector_incomplete);
	}

	return tvb_reported_length(tvb);
}

/* A helper function to reassemble MySQL decompressed PDUs on top of compressed
 * packets. Decompressed PDUs may span multiple compressed packets:
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_compression_packet.html
 * "The payload can be anything from a piece of a MySQL Packet to several MySQL
 * Packets."
 *
 * Some of this error checking is likely unnecessary when dealing with PDUs
 * that have been decompressed (would decompression really have succeeded),
 * but this could be used later instead of tcp_dissect_pdus() for the
 * uncompressed base case as well.
 */
static int
dissect_mysql_decompressed_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	tvbuff_t *volatile next_tvb;
	volatile int offset = 0;
	int offset_before;
	unsigned int remaining, pdu_len;
	while (tvb_reported_length_remaining(tvb, offset)) {
		remaining = tvb_ensure_reported_length_remaining(tvb, offset);
		if (remaining < 3) {
			pinfo->desegment_len = 3 - remaining;
			/* reassemble_streaming_data_and_call_subdissector()
			 * expects the remaining bytes of the fixed header
			 * instead of ONE_MORE_SEGMENT. */
			return tvb_reported_length(tvb);
		}

		pdu_len = get_mysql_pdu_len(pinfo, tvb, offset, data);
		if (pdu_len < MYSQL_HEADER_LENGTH) {
			/* The length value overflowed when adding the
			 * fixed portion. */
			show_reported_bounds_error(tvb, pinfo, tree);
		}
		if (remaining < pdu_len && pinfo->can_desegment) {
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = pdu_len - remaining;
			return tvb_reported_length(tvb);
		}

		next_tvb = tvb_new_subset_length(tvb, offset, pdu_len);
		if (remaining < pdu_len && !pinfo->can_desegment) {
			tvb_set_fragment(next_tvb);
		}
		TRY {
		dissect_mysql_pdu(next_tvb, pinfo, tree, data);
		}
		CATCH_NONFATAL_ERRORS {
			show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
			/* We don't need to restore pinfo->current_proto,
			 * because MySQL doesn't call anything else.
			 */
		}
		ENDTRY;
		offset_before = offset;
		offset += pdu_len;
		if (offset <= offset_before)
			break;
	}
	return tvb_reported_length(tvb);
}

/*
 * Decode a compressed packet
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_compression.html
 */
static int
dissect_mysql_compressed_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_tree *mysql_tree;
	proto_item *ti;
	tvbuff_t *next_tvb;

	conversation_t *conversation;
	mysql_conn_data_t *conn_data;
	int offset = 0;
	unsigned clen, ulen;

	/* get conversation, create if necessary*/
	conversation = find_or_create_conversation(pinfo);

	/* get associated state information, create if necessary */
	conn_data = (mysql_conn_data_t *)conversation_get_proto_data(conversation, proto_mysql);
	if (!conn_data) {
		conn_data = wmem_new0(wmem_file_scope(), mysql_conn_data_t);
		conn_data->stmts = wmem_tree_new(wmem_file_scope());
		conn_data->compressed_state = MYSQL_COMPRESS_ACTIVE;
		conn_data->encoding_client = ENC_UTF_8;
		conn_data->encoding_results = ENC_UTF_8;
		conversation_add_proto_data(conversation, proto_mysql, conn_data);
	}
	if (!conn_data->reassembly_info) {
		conn_data->reassembly_info = streaming_reassembly_info_new();
	}

	ti = proto_tree_add_item(tree, proto_mysql, tvb, offset, 7, ENC_NA);
	proto_item_append_text(ti, " - compressed packet header");
	mysql_tree = proto_item_add_subtree(ti, ett_mysql);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MySQL");

	clen = tvb_get_letoh24(tvb, offset);
	proto_tree_add_item(mysql_tree, hf_mysql_compressed_packet_length, tvb, offset, 3, ENC_LITTLE_ENDIAN);
	offset += 3;

	proto_tree_add_item(mysql_tree, hf_mysql_compressed_packet_number, tvb, offset, 1, ENC_NA);
	offset += 1;

	ulen = tvb_get_letoh24(tvb, offset);
	proto_tree_add_item(mysql_tree, hf_mysql_compressed_packet_length_uncompressed, tvb, offset, 3, ENC_LITTLE_ENDIAN);
	offset += 3;

	if (ulen>0) {
		switch (conn_data->compressed_alg) {
#ifdef HAVE_ZSTD
		case MYSQL_COMPRESS_ALG_ZSTD:
			next_tvb = tvb_child_uncompress_zstd(tvb, tvb, offset, clen);
			break;
#endif
		case MYSQL_COMPRESS_ALG_ZLIB:
		default:
			next_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, clen);
			break;
		}
		if (next_tvb) {
			add_new_data_source(pinfo, next_tvb, "compressed data");
			reassemble_streaming_data_and_call_subdissector(next_tvb, pinfo, 0, ulen, mysql_tree, tree, mysql_reassembly_table, conn_data->reassembly_info, get_virtual_frame_num64(next_tvb, pinfo, 0), decompressed_handle, tree, data, "MySQL", &mysql_frag_items, hf_mysql_fragment_data);

			offset += clen;
		} else {
			expert_add_info_format(pinfo, mysql_tree, &ei_mysql_compression, "Can't uncompress packet");
		}
	} else {
		/* No compression was chosen. It's unlikely that there are
		 * multiple PDUs, and extremely unlikely that they span
		 * frame boundaries (otherwise compression would have been
		 * used), but it doesn't hurt to do this.
		 */
		reassemble_streaming_data_and_call_subdissector(tvb, pinfo, offset, tvb_reported_length_remaining(tvb, offset), mysql_tree, tree, mysql_reassembly_table, conn_data->reassembly_info, get_virtual_frame_num64(tvb, pinfo, offset), decompressed_handle, tree, data, "MySQL", &mysql_frag_items, hf_mysql_fragment_data);
		offset = tvb_reported_length(tvb);
	}

	return offset;
}


/* dissector entrypoint, handles TCP-desegmentation */
static int
dissect_mysql(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	conversation_t *conversation;
	mysql_conn_data_t *conn_data = NULL;

	conversation = find_conversation_pinfo(pinfo, 0);
	if (conversation) {
		conn_data = (mysql_conn_data_t *)conversation_get_proto_data(conversation, proto_mysql);
	}
	if (conn_data && conn_data->compressed_state == MYSQL_COMPRESS_ACTIVE && pinfo->num > conn_data->frame_start_compressed) {
		tcp_dissect_pdus(tvb, pinfo, tree, mysql_desegment,
				 MYSQL_HEADER_LENGTH + 3,
				 get_mysql_compressed_pdu_len,
				 dissect_mysql_compressed_pdu, data);
	} else {
		tcp_dissect_pdus(tvb, pinfo, tree, mysql_desegment,
				 MYSQL_HEADER_LENGTH, get_mysql_pdu_len,
				 dissect_mysql_pdu, data);
	}

	return tvb_reported_length(tvb);
}

/* protocol registration */
void proto_register_mysql(void)
{
	static hf_register_info hf[]=
	{
		{ &hf_mysql_packet_length,
		{ "Packet Length", "mysql.packet_length",
		FT_UINT24, BASE_DEC, NULL,  0x0,
		NULL, HFILL }},

		{ &hf_mysql_packet_number,
		{ "Packet Number", "mysql.packet_number",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Packet Number (now called: Sequence ID)", HFILL }},

		{ &hf_mysql_request,
		{ "Request Command", "mysql.request",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_command,
		{ "Command", "mysql.command",
		FT_UINT8, BASE_DEC|BASE_EXT_STRING, &mysql_command_vals_ext, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_response_code,
		{ "Response Code", "mysql.response_code",
		FT_UINT8, BASE_HEX, VALS(mysql_response_code_vals), 0x0,
		NULL, HFILL }},

		{ &hf_mysql_error_code,
		{ "Error Code", "mysql.error_code",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_error_string,
		{ "Error message", "mysql.error.message",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Error string in case of MySQL error message", HFILL }},

		{ &hf_mysql_sqlstate,
		{ "SQL state", "mysql.sqlstate",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_message,
		{ "Message", "mysql.message",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_server_greeting,
		{ "Server Greeting", "mysql.server_greeting",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_protocol,
		{ "Protocol", "mysql.protocol",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Protocol Version", HFILL }},

		{ &hf_mysql_version,
		{ "Version", "mysql.version",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		"MySQL Version", HFILL }},

		{ &hf_mysql_session_track,
		{ "Session Track", "mysql.session_track",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_type,
		{ "Session tracking type", "mysql.session_track.type",
		  FT_UINT8, BASE_DEC, VALS(mysql_session_track_type_vals), 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_length,
		{ "Session tracking length", "mysql.session_track.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_data,
		{ "Session tracking data", "mysql.session_track.data",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_data_length,
		{ "Session tracking data length", "mysql.session_track.data.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_sysvar_length,
		{ "System variable change Length", "mysql.session_track.sysvar.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_sysvar_name,
		{ "System variable change Name", "mysql.session_track.sysvar.name",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_sysvar_value,
		{ "System variable change Value", "mysql.session_track.sysvar.value",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_schema_length,
		{ "Schema change length", "mysql.session_track.schema.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_schema,
		{ "Schema change", "mysql.session_track.schema",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_state_change,
		{ "State change", "mysql.session_track.state_change",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_gtids_encoding,
		{ "GTIDs encoding", "mysql.session_track.gtids.encoding",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_gtids_length,
		{ "GTIDs length", "mysql.session_track.gtids.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_gtids,
		{ "GTIDs", "mysql.session_track.gtids",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_transaction_characteristics_length,
		{ "Transaction characteristics length", "mysql.session_track.transaction_characteristics.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_transaction_characteristics,
		{ "Transaction characteristics", "mysql.session_track.transaction_characteristics",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_transaction_state_length,
		{ "Transaction state length", "mysql.session_track.transaction_state.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_session_track_transaction_state,
		{ "Transaction state", "mysql.session_track.transaction_state",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_caps_server,
		{ "Server Capabilities", "mysql.caps.server",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"MySQL Capabilities", HFILL }},

		{ &hf_mysql_caps_client,
		{ "Client Capabilities", "mysql.caps.client",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"MySQL Capabilities", HFILL }},

		{ &hf_mysql_cap_long_password,
		{ "Long Password","mysql.caps.lp",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_LP,
		NULL, HFILL }},

		{ &hf_mysql_cap_found_rows,
		{ "Found Rows","mysql.caps.fr",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_FR,
		NULL, HFILL }},

		{ &hf_mysql_cap_long_flag,
		{ "Long Column Flags","mysql.caps.lf",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_LF,
		NULL, HFILL }},

		{ &hf_mysql_cap_connect_with_db,
		{ "Connect With Database","mysql.caps.cd",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_CD,
		NULL, HFILL }},

		{ &hf_mysql_cap_no_schema,
		{ "Don't Allow database.table.column","mysql.caps.ns",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_NS,
		NULL, HFILL }},

		{ &hf_mysql_cap_compress,
		{ "Can use compression protocol","mysql.caps.cp",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_CP,
		NULL, HFILL }},

		{ &hf_mysql_cap_odbc,
		{ "ODBC Client","mysql.caps.ob",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_OB,
		NULL, HFILL }},

		{ &hf_mysql_cap_local_files,
		{ "Can Use LOAD DATA LOCAL","mysql.caps.li",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_LI,
		NULL, HFILL }},

		{ &hf_mysql_cap_ignore_space,
		{ "Ignore Spaces before '('","mysql.caps.is",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_IS,
		NULL, HFILL }},

		{ &hf_mysql_cap_change_user,
		{ "Speaks 4.1 protocol (new flag)","mysql.caps.cu",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_CU,
		NULL, HFILL }},

		{ &hf_mysql_cap_interactive,
		{ "Interactive Client","mysql.caps.ia",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_IA,
		NULL, HFILL }},

		{ &hf_mysql_cap_ssl,
		{ "Switch to SSL after handshake","mysql.caps.sl",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_SL,
		NULL, HFILL }},

		{ &hf_mysql_cap_ignore_sigpipe,
		{ "Ignore sigpipes","mysql.caps.ii",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_II,
		NULL, HFILL }},

		{ &hf_mysql_cap_transactions,
		{ "Knows about transactions","mysql.caps.ta",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_TA,
		NULL, HFILL }},

		{ &hf_mysql_cap_reserved,
		{ "Speaks 4.1 protocol (old flag)","mysql.caps.rs",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_RS,
		NULL, HFILL }},

		{ &hf_mysql_cap_secure_connect,
		{ "Can do 4.1 authentication","mysql.caps.sc",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_SC,
		NULL, HFILL }},

		{ &hf_mysql_extcaps_server,
		{ "Extended Server Capabilities", "mysql.extcaps.server",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"MySQL Extended Capabilities", HFILL }},

		{ &hf_mysql_extcaps_client,
		{ "Extended Client Capabilities", "mysql.extcaps.client",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"MySQL Extended Capabilities", HFILL }},

		{ &hf_mysql_cap_multi_statements,
		{ "Multiple statements","mysql.caps.ms",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_MS,
		NULL, HFILL }},

		{ &hf_mysql_cap_multi_results,
		{ "Multiple results","mysql.caps.mr",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_MR,
		NULL, HFILL }},

		{ &hf_mysql_cap_ps_multi_results,
		{ "PS Multiple results","mysql.caps.pm",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_PM,
		NULL, HFILL }},

		{ &hf_mysql_cap_plugin_auth,
		{ "Plugin Auth","mysql.caps.pa",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_PA,
		NULL, HFILL }},

		{ &hf_mysql_cap_connect_attrs,
		{ "Connect attrs","mysql.caps.ca",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_CA,
		NULL, HFILL }},

		{ &hf_mysql_cap_plugin_auth_lenenc_client_data,
		{ "Plugin Auth LENENC Client Data","mysql.caps.cd",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_AL,
		NULL, HFILL }},

		{ &hf_mysql_cap_client_can_handle_expired_passwords,
		{ "Client can handle expired passwords","mysql.caps.ep",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_EP,
		NULL, HFILL }},

		{ &hf_mysql_cap_session_track,
		{ "Session variable tracking","mysql.caps.session_track",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_ST,
		NULL, HFILL }},

		{ &hf_mysql_cap_deprecate_eof,
		{ "Deprecate EOF","mysql.caps.deprecate_eof",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_DE,
		NULL, HFILL }},

		{ &hf_mysql_cap_optional_metadata,
		{ "Client can handle optional resultset metadata","mysql.caps.optional_metadata",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_RM,
		NULL, HFILL }},

		{ &hf_mysql_cap_compress_zstd,
		{ "ZSTD Compression Algorithm","mysql.caps.compress_zsd",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_ZS,
		NULL, HFILL }},

		{ &hf_mysql_cap_query_attrs,
		{ "Query Attributes","mysql.caps.query_attrs",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_QA,
		NULL, HFILL }},

		{ &hf_mysql_cap_mf_auth,
		{ "Multifactor Authentication","mysql.caps.mf_auth",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_MF,
		NULL, HFILL }},

		{ &hf_mysql_cap_cap_ext,
		{ "Capability Extension","mysql.caps.cap_ext",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_CE,
		NULL, HFILL }},

		{ &hf_mysql_cap_ssl_verify_server_cert,
		{ "Client verifies server's TLS/SSL certificate","mysql.caps.vc",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_CAPS_VC,
		NULL, HFILL }},

		{ &hf_mysql_cap_unused,
		{ "Unused","mysql.caps.unused",
		FT_UINT16, BASE_HEX, NULL, MYSQL_CAPS_UNUSED,
		NULL, HFILL }},

		{ &hf_mysql_login_request,
		{ "Login Request", "mysql.login_request",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_max_packet,
		{ "MAX Packet", "mysql.max_packet",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"MySQL Max packet", HFILL }},

		{ &hf_mysql_collation,
		{ "Collation", "mysql.collation",
		FT_UINT16, BASE_DEC|BASE_EXT_STRING, &mysql_collation_vals_ext, 0x0,
		"MySQL Collation", HFILL }},

		{ &hf_mariadb_collation,
		{ "Collation", "mariadb.collation",
		FT_UINT16, BASE_DEC|BASE_EXT_STRING, &mariadb_collation_vals_ext, 0x0,
		"MariaDB Collation", HFILL }},

		{ &hf_mysql_table_name,
		{ "Table Name", "mysql.table_name",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_user,
		{ "Username", "mysql.user",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		"Login Username", HFILL }},

		{ &hf_mysql_schema,
		{ "Schema", "mysql.schema",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Login Schema", HFILL }},

		{ &hf_mysql_client_auth_plugin,
		{ "Client Auth Plugin", "mysql.client_auth_plugin",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_connattrs,
		{ "Connection Attributes", "mysql.connattrs",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_connattrs_length,
		{ "Connection Attributes length", "mysql.connattrs.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_connattrs_attr,
		{ "Connection Attribute", "mysql.connattrs.attr",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_connattrs_name_length,
		{ "Connection Attribute Name Length", "mysql.connattrs.name.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_connattrs_name,
		{ "Connection Attribute Name", "mysql.connattrs.name",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_connattrs_value_length,
		{ "Connection Attribute Value Length", "mysql.connattrs.value.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_connattrs_value,
		{ "Connection Attribute Value", "mysql.connattrs.value",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_zstd_compression_level,
		{ "ZSTD Compression Level", "mysql.compression.zstd_level",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},


		{ &hf_mariadb_extmeta_data,
		{ "Extended metadata data", "mysql.extmeta_data",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mariadb_extmeta,
		{ "Extended metadata", "mysql.extmeta",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mariadb_extmeta_length,
		{ "Extended metadata length", "mysql.extmeta.length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mariadb_extmeta_key,
		{ "Extended metadata key", "mysql.extmeta.key",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mariadb_extmeta_type,
		{ "Extended metadata type", "mysql.extmeta.type",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mariadb_extmeta_format,
		{ "Extended metadata format", "mysql.extmeta.format",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_salt,
		{ "Salt", "mysql.salt",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_salt2,
		{ "Salt", "mysql.salt2",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_auth_plugin_length,
		{ "Authentication Plugin Length", "mysql.auth_plugin.length",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_auth_plugin,
		{ "Authentication Plugin", "mysql.auth_plugin",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_thread_id,
		{ "Thread ID", "mysql.thread_id",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"MySQL Thread ID", HFILL }},

		{ &hf_mysql_server_language,
		{ "Server Language", "mysql.server_language",
		FT_UINT8, BASE_DEC|BASE_EXT_STRING, &mysql_collation_vals_ext, 0x0,
		"MySQL Charset", HFILL }},

		{ &hf_mariadb_server_language,
		{ "Server Language", "mariadb.server_language",
		FT_UINT8, BASE_DEC|BASE_EXT_STRING, &mariadb_collation_vals_ext, 0x0,
		"MySQL Charset", HFILL }},

		{ &hf_mysql_server_status,
		{ "Server Status", "mysql.server_status",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"MySQL Status", HFILL }},

		{ &hf_mysql_stat_it,
		{ "In transaction", "mysql.stat.it",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_IT,
		NULL, HFILL }},

		{ &hf_mysql_stat_ac,
		{ "AUTO_COMMIT", "mysql.stat.ac",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_AC,
		NULL, HFILL }},

		{ &hf_mysql_stat_mr,
		{ "More results", "mysql.stat.mr",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_MR,
		NULL, HFILL }},

		{ &hf_mysql_stat_mu,
		{ "Multi query / Unused", "mysql.stat.mu",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_MU,
		"Multi query / Unused with MySQL >= 5.6", HFILL }},

		{ &hf_mysql_stat_bi,
		{ "Bad index used", "mysql.stat.bi",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_BI,
		NULL, HFILL }},

		{ &hf_mysql_stat_ni,
		{ "No index used", "mysql.stat.ni",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_NI,
		NULL, HFILL }},

		{ &hf_mysql_stat_cr,
		{ "Cursor exists", "mysql.stat.cr",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_CR,
		NULL, HFILL }},

		{ &hf_mysql_stat_lr,
		{ "Last row sent", "mysql.stat.lr",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_LR,
		NULL, HFILL }},

		{ &hf_mysql_stat_dr,
		{ "Database dropped", "mysql.stat.dr",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_DR,
		NULL, HFILL }},

		{ &hf_mysql_stat_bs,
		{ "No backslash escapes", "mysql.stat.bs",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_BS,
		NULL, HFILL }},

		{ &hf_mysql_stat_mc,
		{ "Metadata changed", "mysql.stat.mc",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_MC,
		NULL, HFILL }},

		{ &hf_mysql_stat_session_state_changed,
		{ "Session state changed", "mysql.stat.session_state_changed",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_SESSION_STATE_CHANGED,
		NULL, HFILL }},

		{ &hf_mysql_stat_query_was_slow,
		{ "Query was slow", "mysql.stat.query_was_slow",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_QUERY_WAS_SLOW,
		NULL, HFILL }},

		{ &hf_mysql_stat_ps_out_params,
		{ "PS Out Params", "mysql.stat.ps_out_params",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_PS_OUT_PARAMS,
		NULL, HFILL }},

		{ &hf_mysql_stat_trans_readonly,
		{ "In Trans Readonly", "mysql.stat.trans_readonly",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_STAT_TRANS_READONLY,
		NULL, HFILL }},

		{ &hf_mysql_refresh,
		{ "Refresh Option", "mysql.refresh",
		FT_UINT8, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_rfsh_grants,
		{ "reload permissions", "mysql.rfsh.grants",
		FT_BOOLEAN, 8, TFS(&tfs_set_notset), MYSQL_RFSH_GRANT,
		NULL, HFILL }},

		{ &hf_mysql_rfsh_log,
		{ "flush logfiles", "mysql.rfsh.log",
		FT_BOOLEAN, 8, TFS(&tfs_set_notset), MYSQL_RFSH_LOG,
		NULL, HFILL }},

		{ &hf_mysql_rfsh_tables,
		{ "flush tables", "mysql.rfsh.tables",
		FT_BOOLEAN, 8, TFS(&tfs_set_notset), MYSQL_RFSH_TABLES,
		NULL, HFILL }},

		{ &hf_mysql_rfsh_hosts,
		{ "flush hosts", "mysql.rfsh.hosts",
		FT_BOOLEAN, 8, TFS(&tfs_set_notset), MYSQL_RFSH_HOSTS,
		NULL, HFILL }},

		{ &hf_mysql_rfsh_status,
		{ "reset statistics", "mysql.rfsh.status",
		FT_BOOLEAN, 8, TFS(&tfs_set_notset), MYSQL_RFSH_STATUS,
		NULL, HFILL }},

		{ &hf_mysql_rfsh_threads,
		{ "empty thread cache", "mysql.rfsh.threads",
		FT_BOOLEAN, 8, TFS(&tfs_set_notset), MYSQL_RFSH_THREADS,
		NULL, HFILL }},

		{ &hf_mysql_rfsh_slave,
		{ "flush slave status", "mysql.rfsh.slave",
		FT_BOOLEAN, 8, TFS(&tfs_set_notset), MYSQL_RFSH_SLAVE,
		NULL, HFILL }},

		{ &hf_mysql_rfsh_master,
		{ "flush master status", "mysql.rfsh.master",
		FT_BOOLEAN, 8, TFS(&tfs_set_notset), MYSQL_RFSH_MASTER,
		NULL, HFILL }},

		{ &hf_mysql_unused,
		{ "Unused", "mysql.unused",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_passwd,
		{ "Password", "mysql.passwd",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_payload,
		{ "Payload", "mysql.payload",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		"Additional Payload", HFILL }},

		{ &hf_mysql_affected_rows,
		{ "Affected Rows", "mysql.affected_rows",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_insert_id,
		{ "Last INSERT ID", "mysql.insert_id",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_num_warn,
		{ "Warnings", "mysql.warnings",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_stmt_id,
		{ "Statement ID", "mysql.stmt_id",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_query_attributes,
                { "Query Attributes", "mysql.query_attrs",
                        FT_NONE, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }},

		{ &hf_mysql_query_attributes_count,
                { "Count", "mysql.query_attrs_count",
                        FT_UINT8, BASE_DEC, NULL,  0x0,
                        NULL, HFILL }},

		{ &hf_mysql_query_attributes_send_types_to_server,
                { "Send types to server", "mysql.query_attrs_send_types_to_server",
                        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }},

		{ &hf_mysql_query_attribute_name_type,
                { "Attribute Name Type", "mysql.query_attr_name_type",
                        FT_UINT16, BASE_HEX, NULL, 0x0,
                        NULL, HFILL }},

		{ &hf_mysql_query_attribute_name,
                { "Attribute Name", "mysql.query_attr_name",
                        FT_STRING, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }},

		{ &hf_mysql_query_attribute_value,
                { "Attribute Value", "mysql.query_attr_value",
                        FT_STRING, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }},

		{ &hf_mysql_query,
		{ "Statement", "mysql.query",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_shutdown,
		{ "Shutdown Level", "mysql.shutdown",
		FT_UINT8, BASE_DEC, VALS(mysql_shutdown_vals), 0x0,
		NULL, HFILL }},

		{ &hf_mysql_option,
		{ "Option", "mysql.option",
		FT_UINT16, BASE_DEC, VALS(mysql_option_vals), 0x0,
		NULL, HFILL }},

		{ &hf_mysql_param,
		{ "Parameter", "mysql.param",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_param_name,
		{ "Name", "mysql.param_name",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_num_params,
		{ "Number of parameter", "mysql.num_params",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_num_rows,
		{ "Rows to fetch", "mysql.num_rows",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_flags4,
		{ "Flags (unused)", "mysql.exec_flags",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_flags5,
		{ "Flags", "mysql.exec_flags",
		FT_UINT8, BASE_DEC, VALS(mysql_exec_flags_vals), 0x0,
		NULL, HFILL }},

		{ &hf_mysql_new_parameter_bound_flag,
		{ "New parameter bound flag", "mysql.new_parameter_bound_flag",
		FT_UINT8, BASE_DEC, VALS(mysql_new_parameter_bound_flag_vals), 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_iter,
		{ "Iterations (unused)", "mysql.exec_iter",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_binlog_position,
		{ "Binlog Position", "mysql.binlog.position",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"Position to start at", HFILL }},

		{ &hf_mysql_binlog_position8,
		{ "Binlog Position", "mysql.binlog.position8",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		"Position to start at", HFILL }},

		{ &hf_mysql_binlog_flags,
		{ "Binlog Flags", "mysql.binlog.flags",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"(currently not used; always 0)", HFILL }},

		{ &hf_mysql_binlog_server_id,
		{ "Binlog server id", "mysql.binlog.server_id",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"server_id of the slave", HFILL }},

		{ &hf_mysql_binlog_slave_hostname_length,
		{ "Slave hostname length", "mysql.binlog.slave_hostname_length",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"slave_hostname field length", HFILL }},

		{ &hf_mysql_binlog_slave_hostname,
		{ "Slave hostname", "mysql.binlog.slave_hostname",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  "slave_hostname", HFILL }},

		{ &hf_mysql_binlog_slave_user_length,
		{ "Slave user length", "mysql.binlog.slave_user_length",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "slave_hostname field length", HFILL }},

		{ &hf_mysql_binlog_slave_user,
		{ "Slave user", "mysql.binlog.slave_user",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  "slave_user", HFILL }},

		{ &hf_mysql_binlog_slave_password_length,
		{ "Slave password length", "mysql.binlog.slave_password_length",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "slave_password field length", HFILL }},

		{ &hf_mysql_binlog_slave_password,
		{ "Slave password", "mysql.binlog.slave_password",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  "slave_password", HFILL }},

		{ &hf_mysql_binlog_slave_mysql_port,
		{ "Slave MySQL port", "mysql.binlog.slave_mysql_port",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "slave's mysql port", HFILL }},

		{ &hf_mysql_binlog_replication_rank,
		{ "Replication rank", "mysql.binlog.replication_rank",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "ignored", HFILL }},

		{ &hf_mysql_binlog_master_id,
		{ "Master id", "mysql.binlog.master_id",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "master_id of the slave", HFILL }},

		{ &hf_mysql_binlog_file_name,
		{ "Binlog file name", "mysql.binlog.file_name",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_binlog_file_name_length,
		{ "Binlog file name length", "mysql.binlog.file_name_length",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_binlog_gtid_data,
		{ "Binlog GTID Data", "mysql.binlog.gtid_data",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_binlog_gtid_data_length,
		{ "Binlog file GTID data length", "mysql.binlog.gtid_data_length",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_binlog_event_header_timestamp,
		{ "Timestamp",       "mysql.binlog.event_header.timestamp",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,       NULL,        0x0,
		NULL, HFILL }},

		{ &hf_mysql_binlog_event_header_event_type,
		{ "Binlog Event Type", "mysql.binlog.event_header.event_type",
		  FT_UINT8, BASE_DEC, VALS(mysql_binlog_event_type_vals), 0x0,
		  NULL, HFILL }},

		{ &hf_mysql_binlog_event_header_server_id,
		{ "Server ID", "mysql.binlog.event_header.server_id",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "server-id of the originating mysql-server", HFILL }},

		{ &hf_mysql_binlog_event_header_event_size,
		{ "Event Size", "mysql.binlog.event_header.event_size",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "size of the event (header, post-header, body)", HFILL }},

		{ &hf_mysql_binlog_event_header_log_position,
		{ "Binlog Position", "mysql.binlog.event_header.log_position",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "position of the next event", HFILL }},

		{ &hf_mysql_binlog_event_header_flags,
		{ "Binlog Event Flags", "mysql.binlog.event_header.flags",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "flag", HFILL }},

		{ &hf_mysql_binlog_event_checksum,
		{ "Checksum", "mysql.binlog.event_checksum",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		"binlog event checksum", HFILL }},

		{ &hf_mysql_binlog_event_heartbeat_v2,
		{ "Binlog Event: HEARTBEAT_LOG_EVENT_V2", "mysql.binlog.event_heartbeat_v2",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_binlog_event_heartbeat_v2_otw,
		{ "Entry", "mysql.binlog.event_heartbeat_v2_otw",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_binlog_event_heartbeat_v2_otw_type,
		{ "Type", "mysql.binlog.event_heartbeat_v2_otw_type",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_binlog_hb_event_filename,
		{ "Binlog Filename", "mysql.binlog.hb_event.filename",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_binlog_hb_event_log_position,
		{ "Binlog Position", "mysql.binlog.hb_event.log_position",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		"position of the next event", HFILL }},

		{ &hf_mysql_clone_command_code,
		{ "Clone Command Code", "mysql.clone.command_code",
		FT_UINT8, BASE_HEX, VALS(mysql_clone_command_vals), 0x0,
		NULL, HFILL }},

		{ &hf_mysql_clone_response_code,
		{ "Clone Response Code", "mysql.clone.response_code",
		FT_UINT8, BASE_HEX, VALS(mysql_clone_response_vals), 0x0,
		NULL, HFILL }},

		{ &hf_mysql_eof,
		{ "EOF marker", "mysql.eof",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_num_fields,
		{ "Number of fields", "mysql.num_fields",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mariadb_send_meta,
		{ "send metadata", "mysql.metadata_follows",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_extra,
		{ "Extra data", "mysql.extra",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_fld_catalog,
		{ "Catalog", "mysql.field.catalog",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Field: catalog", HFILL }},

		{ &hf_mysql_fld_db,
		{ "Database", "mysql.field.db",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Field: database", HFILL }},

		{ &hf_mysql_fld_table,
		{ "Table", "mysql.field.table",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Field: table", HFILL }},

		{ &hf_mysql_fld_org_table,
		{ "Original table", "mysql.field.org_table",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Field: original table", HFILL }},

		{ &hf_mysql_fld_name,
		{ "Name", "mysql.field.name",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Field: name", HFILL }},

		{ &hf_mysql_fld_org_name,
		{ "Original name", "mysql.field.org_name",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Field: original name", HFILL }},

		{ &hf_mysql_fld_charsetnr,
		{ "Charset number", "mysql.field.charsetnr",
		FT_UINT16, BASE_DEC|BASE_EXT_STRING, &mysql_collation_vals_ext, 0x0,
		"Field: charset number", HFILL }},

		//{ &hf_mariadb_fld_charsetnr,
		//{ "Charset number", "mariadb.field.charsetnr",
		//FT_UINT16, BASE_DEC|BASE_EXT_STRING, &mariadb_collation_vals_ext, 0x0,
		//"Field: charset number", HFILL }},

		{ &hf_mysql_fld_length,
		{ "Length", "mysql.field.length",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"Field: length", HFILL }},

		{ &hf_mysql_fld_type,
		{ "Type", "mysql.field.type",
		FT_UINT8, BASE_DEC, VALS(type_constants), 0x0,
		"Field: type", HFILL }},

		{ &hf_mysql_fld_flags,
		{ "Flags", "mysql.field.flags",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"Field: flags", HFILL }},

		{ &hf_mysql_fld_not_null,
		{ "Not null", "mysql.field.flags.not_null",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_NOT_NULL_FLAG,
		"Field: flag not null", HFILL }},

		{ &hf_mysql_fld_primary_key,
		{ "Primary key", "mysql.field.flags.primary_key",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_PRI_KEY_FLAG,
		"Field: flag primary key", HFILL }},

		{ &hf_mysql_fld_unique_key,
		{ "Unique key", "mysql.field.flags.unique_key",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_UNIQUE_KEY_FLAG,
		"Field: flag unique key", HFILL }},

		{ &hf_mysql_fld_multiple_key,
		{ "Multiple key", "mysql.field.flags.multiple_key",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_MULTIPLE_KEY_FLAG,
		"Field: flag multiple key", HFILL }},

		{ &hf_mysql_fld_blob,
		{ "Blob", "mysql.field.flags.blob",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_BLOB_FLAG,
		"Field: flag blob", HFILL }},

		{ &hf_mysql_fld_unsigned,
		{ "Unsigned", "mysql.field.flags.unsigned",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_UNSIGNED_FLAG,
		"Field: flag unsigned", HFILL }},

		{ &hf_mysql_fld_zero_fill,
		{ "Zero fill", "mysql.field.flags.zero_fill",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_ZEROFILL_FLAG,
		"Field: flag zero fill", HFILL }},

		{ &hf_mysql_null_buffer,
		{ "Row null buffer", "mysql.row.nullbuffer",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_fld_enum,
		{ "Enum", "mysql.field.flags.enum",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_ENUM_FLAG,
		"Field: flag enum", HFILL }},

		{ &hf_mysql_fld_auto_increment,
		{ "Auto increment", "mysql.field.flags.auto_increment",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_AUTO_INCREMENT_FLAG,
		"Field: flag auto increment", HFILL }},

		{ &hf_mysql_fld_timestamp,
		{ "Timestamp", "mysql.field.flags.timestamp",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_TIMESTAMP_FLAG,
		"Field: flag timestamp", HFILL }},

		{ &hf_mysql_fld_set,
		{ "Set", "mysql.field.flags.set",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MYSQL_FLD_SET_FLAG,
		"Field: flag set", HFILL }},

		{ &hf_mysql_fld_decimals,
		{ "Decimals", "mysql.field.decimals",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Field: decimals", HFILL }},

		{ &hf_mysql_fld_default,
		{ "Default", "mysql.field.default",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Field: default", HFILL }},

		{ &hf_mysql_row_text,
		{ "text", "mysql.row.text",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Field: row packet text", HFILL }},

		{ &hf_mysql_exec_param,
		{ "Parameter", "mysql.exec_param",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_unsigned,
		{ "Unsigned", "mysql.exec.unsigned",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_longlong,
		{ "Value (INT64)", "mysql.exec.field.longlong",
		FT_INT64, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_unsigned_longlong,
		{ "Value (UINT64)", "mysql.exec.field.unsigned_longlong",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_bit_length,
		{ "Length (Bit)", "mysql.exec.field.bit.length",
		FT_UINT24, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_bit,
		{ "Value (Bit)", "mysql.exec.field.bit",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_blob_length,
		{ "Length (BLOB)", "mysql.exec.field.blob.length",
		FT_UINT24, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_blob,
		{ "Value (BLOB)", "mysql.exec.field.blob",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_geometry_length,
		{ "Length (Geometry)", "mysql.exec.field.geometry.length",
		FT_UINT24, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_geometry,
		{ "Value (Geometry)", "mysql.exec.field.geometry",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_json_length,
		{ "Length (JSON)", "mysql.exec.field.json.length",
		FT_UINT24, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_string_length,
		{ "Length (String)", "mysql.exec.field.string.length",
		FT_UINT24, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_string,
		{ "Value (String)", "mysql.exec.field.string",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_double,
		{ "Value (Double)", "mysql.exec.field.double",
		FT_DOUBLE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_datetime_length,
		{ "Length", "mysql.exec.field.datetime.length",
		FT_INT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_year,
		{ "Year", "mysql.exec.field.year",
		FT_INT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_month,
		{ "Month", "mysql.exec.field.month",
		FT_INT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_day,
		{ "Day", "mysql.exec.field.day",
		FT_INT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_hour,
		{ "Hour", "mysql.exec.field.hour",
		FT_INT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_minute,
		{ "Minute", "mysql.exec.field.minute",
		FT_INT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_second,
		{ "Second", "mysql.exec.field.second",
		FT_INT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_second_b,
		{ "Billionth of a second", "mysql.exec.field.secondb",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_int24,
		{ "Value (INT24)", "mysql.exec.field.int24",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_long,
		{ "Value (INT32)", "mysql.exec.field.long",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_unsigned_long,
		{ "Value (UINT32)", "mysql.exec.field.unsigned_long",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_tiny,
		{ "Value (INT8)", "mysql.exec.field.tiny",
		FT_INT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_unsigned_tiny,
		{ "Value (UINT8)", "mysql.exec.field.unsigned_tiny",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_short,
		{ "Value (INT16)", "mysql.exec.field.short",
		FT_INT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_unsigned_short,
		{ "Value (UINT16)", "mysql.exec.field.unsigned_short",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_float,
		{ "Value (Float)", "mysql.exec.field.float",
		FT_FLOAT, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_null,
		{ "Value: -NULL-", "mysql.exec.field.null",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_time_length,
		{ "Length", "mysql.exec.field.time.length",
		FT_INT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_time_sign,
		{ "Flags", "mysql.exec.field.time.sign",
		FT_UINT8, BASE_DEC, VALS(mysql_exec_time_sign_vals), 0x0,
		NULL, HFILL }},

		{ &hf_mysql_exec_field_time_days,
		{ "Days", "mysql.exec.field.time.days",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_auth_switch_request_status,
		{ "Status", "mysql.auth_switch_request.status",
		FT_UINT8, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_auth_switch_request_name,
		{ "Auth Method Name", "mysql.auth_switch_request.name",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_auth_switch_request_data,
		{ "Auth Method Data", "mysql.auth_switch_request.data",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_auth_switch_response_data,
		{ "Auth Method Data", "mysql.auth_switch_response.data",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_sha2_auth,
		{ "SHA2 Auth State", "mysql.hf_mysql_sha2_auth.name",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_pubkey,
		{ "Public Key", "mysql.hf_mysql_pubkey",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_sha2_response,
		{ "SHA2 Auth Response", "mysql.hf_mysql_sha2_response",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_compressed_packet_length,
		{ "Compressed Packet Length", "mysql.compressed_packet_length",
		FT_UINT24, BASE_DEC, NULL,  0x0,
		NULL, HFILL }},

		{ &hf_mysql_compressed_packet_number,
		{ "Compressed Packet Number", "mysql.compressed_packet_number",
		FT_UINT24, BASE_DEC, NULL,  0x0,
		NULL, HFILL }},

		{ &hf_mysql_compressed_packet_length_uncompressed,
		{ "Uncompressed Packet Length", "mysql.compressed_packet_length_uncompressed",
		FT_UINT24, BASE_DEC, NULL,  0x0,
		NULL, HFILL }},

		{ &hf_mysql_loaddata_filename,
		{ "LOCAL INFILE Filename", "mysql.load_data.filename",
		FT_STRING, BASE_NONE, NULL,  0x0,
		NULL, HFILL }},

		{ &hf_mysql_loaddata_payload,
		{ "LOCAL INFILE Payload", "mysql.load_data.payload",
		FT_BYTES, BASE_NONE, NULL,  0x0,
		NULL, HFILL }},

		{ &hf_mariadb_cap_progress,
		{ "Progress indication", "mariadb.caps.pr",
		FT_BOOLEAN, 32, TFS(&tfs_set_notset), MARIADB_CAPS_PR,
		NULL, HFILL }},

		{ &hf_mariadb_cap_commulti,
		{ "Multi commands", "mariadb.caps.cm",
		FT_BOOLEAN, 32, TFS(&tfs_set_notset), MARIADB_CAPS_CM,
		NULL, HFILL }},

		{ &hf_mariadb_cap_bulk,
		{ "Bulk Operations", "mariadb.caps.bo",
		FT_BOOLEAN, 32, TFS(&tfs_set_notset), MARIADB_CAPS_BO,
		NULL, HFILL }},

		{ &hf_mariadb_cap_extmetadata,
		{ "Extended metadata", "mariadb.caps.em",
		FT_BOOLEAN, 32, TFS(&tfs_set_notset), MARIADB_CAPS_EM,
		NULL, HFILL }},

		{ &hf_mariadb_cap_cache_metadata,
		{ "Cache metadata", "mariadb.caps.me",
		FT_BOOLEAN, 32, TFS(&tfs_set_notset), MARIADB_CAPS_ME,
		NULL, HFILL }},

		{ &hf_mariadb_extcaps_server,
		{ "MariaDB Extended Server Capabilities", "mariadb.extcaps.server",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mariadb_extcaps_client,
		{ "MariaDB Extended Client Capabilities", "mariadb.extcaps.client",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mariadb_bulk_flag_autoid,
		{ "Return Generated Autoincrement IDs", "mariadb.bulk.flag.autoid",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MARIADB_BULK_AUTOID,
		NULL, HFILL }},

		{ &hf_mariadb_bulk_flag_sendtypes,
		{ "Send Parameter Types", "mariadb.bulk.flag.sendtypes",
		FT_BOOLEAN, 16, TFS(&tfs_set_notset), MARIADB_BULK_SEND_TYPES,
		NULL, HFILL }},

		{ &hf_mariadb_bulk_caps_flags,
		{ "MariaDB Bulk Capabilities", "mariadb.bulk.flags",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mariadb_bulk_paramtypes,
		{ "Bulk Parameter Types", "mariadb.bulk.paramtypesg",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mariadb_bulk_indicator,
		{ "Indicator", "mariadb.bulk.indicators",
		FT_UINT8, BASE_HEX, VALS(mariadb_bulk_indicator_vals), 0x00,
		NULL, HFILL }},

		{ &hf_mariadb_bulk_row_nr,
		{ "Row nr", "mariadb.bulk.row_nr",
		FT_UINT32, BASE_DEC, NULL, 0x00,
		NULL, HFILL }},

		{ &hf_mysql_fragments,
		{ "Reassembled MySQL fragments", "mysql.fragments",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_fragment,
		{ "MySQL fragment", "mysql.fragment",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_fragment_overlap,
		{ "Fragment overlap", "mysql.fragment.overlap",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_fragment_overlap_conflicts,
		{ "Conflicting data in fragment overlap", "mysql.fragment.overlap.conflicts",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_fragment_multiple_tails,
		{ "Multiple tail fragments found", "mysql.fragment.multiple_tails",
		FT_BOOLEAN, BASE_NONE, NULL, 0x00,
		NULL, HFILL }},

		{ &hf_mysql_fragment_too_long_fragment,
		{ "Fragment too long", "mysql.fragment.too_long_fragment",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_fragment_error,
		{ "Defragmentation error", "mysql.fragment.error",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_fragment_count,
		{ "Fragment count", "mysql.fragment.count",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_reassembled_in,
		{ "Reassembled in", "mysql.reassembled.in",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_mysql_reassembled_length,
		{ "Reassembled length", "mysql.reassembled.length",
		FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },

		{ &hf_mysql_fragment_data,
		{ "MySQL fragment data", "mysql.fragment.data",
		FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

	};

	static int *ett[]=
	{
		&ett_mysql,
		&ett_server_greeting,
		&ett_login_request,
		&ett_caps,
		&ett_extcaps,
		&ett_stat,
		&ett_row_value,
		&ett_request,
		&ett_refresh,
		&ett_field_flags,
		&ett_exec_param,
		&ett_bulk_param,
		&ett_session_track,
		&ett_session_track_data,
		&ett_extmeta,
		&ett_extmeta_data,
		&ett_connattrs,
		&ett_connattrs_attr,
		&ett_mysql_field,
		&ett_query_attributes,
		&ett_binlog_event,
		&ett_binlog_event_hb_v2,
		&ett_mysql_fragment,
		&ett_mysql_fragments,
		&ett_mysql_binary_field,
	};

	static ei_register_info ei[] = {
		{ &ei_mysql_dissector_incomplete, { "mysql.dissector_incomplete", PI_UNDECODED, PI_WARN, "FIXME - dissector is incomplete", EXPFILL }},
		{ &ei_mysql_streamed_param, { "mysql.streamed_param", PI_SEQUENCE, PI_CHAT, "This parameter was streamed, its value can be found in Send BLOB packets", EXPFILL }},
		{ &ei_mysql_prepare_response_needed, { "mysql.prepare_response_needed", PI_UNDECODED, PI_WARN, "PREPARE Response packet is needed to dissect the payload", EXPFILL }},
		{ &ei_mysql_command, { "mysql.command.invalid", PI_PROTOCOL, PI_WARN, "Unknown/invalid command code", EXPFILL }},
		{ &ei_mysql_unknown_response, { "mysql.unknown_response", PI_UNDECODED, PI_WARN, "unknown/invalid response", EXPFILL }},
		{ &ei_mysql_invalid_length, { "mysql.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
		{ &ei_mysql_compression, { "mysql.uncompress_failure", PI_MALFORMED, PI_WARN, "Uncompression failed", EXPFILL }},
	};

	module_t *mysql_module;
	expert_module_t* expert_mysql;

	proto_mysql = proto_register_protocol("MySQL Protocol", "MySQL", "mysql");
	proto_register_field_array(proto_mysql, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mysql = expert_register_protocol(proto_mysql);
	expert_register_field_array(expert_mysql, ei, array_length(ei));

	mysql_module = prefs_register_protocol(proto_mysql, NULL);
	prefs_register_bool_preference(mysql_module, "desegment_buffers",
					"Reassemble MySQL buffers spanning multiple TCP segments",
					"Whether the MySQL dissector should reassemble MySQL buffers spanning multiple TCP segments."
					" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
					&mysql_desegment);
	prefs_register_bool_preference(mysql_module, "show_sql_query",
					"Show SQL Query string in INFO column",
					"Whether the MySQL dissector should display the SQL query string in the INFO column.",
					&mysql_showquery);

	reassembly_table_register(&mysql_reassembly_table,
		&addresses_ports_reassembly_table_functions);
	mysql_handle = register_dissector("mysql", dissect_mysql, proto_mysql);
}

/* dissector registration */
void proto_reg_handoff_mysql(void)
{
	tls_handle = find_dissector("tls");
	decompressed_handle = create_dissector_handle(dissect_mysql_decompressed_pdus, proto_mysql);
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_MySQL, mysql_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
