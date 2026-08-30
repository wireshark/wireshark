/* packet-tns.c
 * Routines for Oracle TNS packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-tcp.h"

#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/unit_strings.h>

#include <wsutil/array.h>

void proto_register_tns(void);

#define TNS_HDR_LEN 8

/* Packet Types */
#define TNS_TYPE_CONNECT        1
#define TNS_TYPE_ACCEPT         2
#define TNS_TYPE_ACK            3
#define TNS_TYPE_REFUSE         4
#define TNS_TYPE_REDIRECT       5
#define TNS_TYPE_DATA           6
#define TNS_TYPE_NULL           7
#define TNS_TYPE_ABORT          9
#define TNS_TYPE_RESEND         11
#define TNS_TYPE_MARKER         12
#define TNS_TYPE_ATTENTION      13
#define TNS_TYPE_CONTROL        14
#define TNS_TYPE_DD             15
#define TNS_TYPE_MAX            19

/* Data Packet Functions */
#define SQLNET_SET_PROTOCOL     1
#define SQLNET_SET_DATATYPES    2
#define SQLNET_USER_OCI_FUNC    3
#define SQLNET_RETURN_STATUS    4
#define SQLNET_ACCESS_USR_ADDR  5
#define SQLNET_ROW_TRANSF_HDR   6
#define SQLNET_ROW_TRANSF_DATA  7
#define SQLNET_RETURN_OPI_PARAM 8
#define SQLNET_FUNCCOMPLETE     9
#define SQLNET_NERROR_RET_DEF   10
#define SQLNET_IOVEC_4FAST_UPI  11
#define SQLNET_LONG_4FAST_UPI   12
#define SQLNET_INVOKE_USER_CB   13
#define SQLNET_LOB_FILE_DF      14
#define SQLNET_WARNING          15
#define SQLNET_DESCRIBE_INFO    16
#define SQLNET_PIGGYBACK_FUNC   17
#define SQLNET_SIG_4UCS         18
#define SQLNET_FLUSH_BIND_DATA  19
#define SQLNET_SNS              0xdeadbeef
#define SQLNET_XTRN_PROCSERV_R1 32
#define SQLNET_XTRN_PROCSERV_R2 68

/* Return OPI Parameter's Type */
#define OPI_VERSION2            1
#define OPI_OSESSKEY            2
#define OPI_OAUTH               3

/* OCI function ids (TTI_FUN sub-functions). */
#define TTI_FETCH               5
#define TTI_ALL8                94
#define TTI_LOBOPS              96

/* desegmentation of TNS over TCP */
static bool tns_desegment = true;

static dissector_handle_t tns_handle;

static int proto_tns;
static int hf_tns_request;
static int hf_tns_response;
static int hf_tns_length;
static int hf_tns_packet_checksum;
static int hf_tns_header_checksum;
static int hf_tns_packet_type;
static int hf_tns_reserved_byte;
static int hf_tns_version;
static int hf_tns_compat_version;

static int hf_tns_service_options;
static int hf_tns_sopt_flag_bconn;
static int hf_tns_sopt_flag_pc;
static int hf_tns_sopt_flag_hc;
static int hf_tns_sopt_flag_fd;
static int hf_tns_sopt_flag_hd;
static int hf_tns_sopt_flag_dc1;
static int hf_tns_sopt_flag_dc2;
static int hf_tns_sopt_flag_dio;
static int hf_tns_sopt_flag_ap;
static int hf_tns_sopt_flag_ra;
static int hf_tns_sopt_flag_sa;

static int hf_tns_sdu_size;
static int hf_tns_max_tdu_size;

static int hf_tns_nt_proto_characteristics;
static int hf_tns_ntp_flag_hangon;
static int hf_tns_ntp_flag_crel;
static int hf_tns_ntp_flag_tduio;
static int hf_tns_ntp_flag_srun;
static int hf_tns_ntp_flag_dtest;
static int hf_tns_ntp_flag_cbio;
static int hf_tns_ntp_flag_asio;
static int hf_tns_ntp_flag_pio;
static int hf_tns_ntp_flag_grant;
static int hf_tns_ntp_flag_handoff;
static int hf_tns_ntp_flag_sigio;
static int hf_tns_ntp_flag_sigpipe;
static int hf_tns_ntp_flag_sigurg;
static int hf_tns_ntp_flag_urgentio;
static int hf_tns_ntp_flag_fdio;
static int hf_tns_ntp_flag_testop;

static int hf_tns_line_turnaround;
static int hf_tns_value_of_one;
static int hf_tns_connect_data_length;
static int hf_tns_connect_data_offset;
static int hf_tns_connect_data_max;

static int hf_tns_connect_flags0;
static int hf_tns_connect_flags1;
static int hf_tns_conn_flag_nareq;
static int hf_tns_conn_flag_nalink;
static int hf_tns_conn_flag_enablena;
static int hf_tns_conn_flag_ichg;
static int hf_tns_conn_flag_wantna;

static int hf_tns_connect_data;
static int hf_tns_trace_cf1;
static int hf_tns_trace_cf2;
static int hf_tns_trace_cid;

static int hf_tns_accept_data_length;
static int hf_tns_accept_data_offset;
static int hf_tns_accept_data;

static int hf_tns_refuse_reason_user;
static int hf_tns_refuse_reason_system;
static int hf_tns_refuse_data_length;
static int hf_tns_refuse_data;

static int hf_tns_abort_reason_user;
static int hf_tns_abort_reason_system;
static int hf_tns_abort_data;

static int hf_tns_marker_type;
static int hf_tns_marker_data_byte;
static int hf_tns_marker_function;
/* static int hf_tns_marker_data; */

static int hf_tns_redirect_data_length;
static int hf_tns_redirect_data;

static int hf_tns_control_cmd;
static int hf_tns_control_data;

static int hf_tns_data_flag;
static int hf_tns_data_flag_send;
static int hf_tns_data_flag_rc;
static int hf_tns_data_flag_c;
static int hf_tns_data_flag_reserved;
static int hf_tns_data_flag_more;
static int hf_tns_data_flag_eof;
static int hf_tns_data_flag_dic;
static int hf_tns_data_flag_rts;
static int hf_tns_data_flag_sntt;

static int hf_tns_data_id;
static int hf_tns_data_length;
static int hf_tns_data_oci_id;
static int hf_tns_data_tseq;
static int hf_tns_data_piggyback_id;
static int hf_tns_data_unused;

static int hf_tns_cursor;

static int hf_tns_data_opi_version2_banner_len;
static int hf_tns_data_opi_version2_banner;
static int hf_tns_data_opi_version2_vsnum;

static int hf_tns_data_opi_num_of_params;
static int hf_tns_data_opi_param_length;
static int hf_tns_data_opi_param_name;
static int hf_tns_data_opi_param_value;

static int hf_tns_data_setp_acc_version;
static int hf_tns_data_setp_cli_plat;
static int hf_tns_data_setp_version;
static int hf_tns_data_setp_banner;

static int hf_tns_data_sns_cli_vers;
static int hf_tns_data_sns_srv_vers;
static int hf_tns_data_sns_srvcnt;

static int hf_tns_data_setdt_charset_in;
static int hf_tns_data_setdt_charset_out;
static int hf_tns_data_setdt_flag;
static int hf_tns_data_setdt_caphdr;
static int hf_tns_data_setdt_caphdr_version;
static int hf_tns_data_setdt_caphdr_flags;
static int hf_tns_data_setdt_tblhdr;
static int hf_tns_data_setdt_idmap;
static int hf_tns_data_setdt_overrides;
static int hf_tns_data_setdt_override_client;
static int hf_tns_data_setdt_override_repr;
static int hf_tns_data_setdt_override_format;

static int hf_tns_data_oer_call_status;
static int hf_tns_data_oer_rowcount;
static int hf_tns_data_oer_err_code;
static int hf_tns_data_oer_cursor_id;
static int hf_tns_data_oer_n_batch_errcodes;
static int hf_tns_data_oer_n_batch_offsets;
static int hf_tns_data_oer_n_batch_messages;
static int hf_tns_data_oer_message;

static int hf_tns_data_iov_num_binds;
static int hf_tns_data_iov_bind_dir;

static int hf_tns_data_dcb_num_columns;
static int hf_tns_data_col_type;
static int hf_tns_data_col_precision;
static int hf_tns_data_col_scale;
static int hf_tns_data_col_max_length;
static int hf_tns_data_col_charset;
static int hf_tns_data_col_csform;
static int hf_tns_data_col_max_size;
static int hf_tns_data_col_nulls_ok;
static int hf_tns_data_col_name;

static int hf_tns_data_rxh_num_requests;
static int hf_tns_data_rxh_iter_num;
static int hf_tns_data_rxh_num_iters;

static int hf_tns_data_all8_options;
static int hf_tns_data_all8_opt_parse;
static int hf_tns_data_all8_opt_bind;
static int hf_tns_data_all8_opt_define;
static int hf_tns_data_all8_opt_execute;
static int hf_tns_data_all8_opt_commit;
static int hf_tns_data_all8_opt_plsql;
static int hf_tns_data_all8_opt_fetch;
static int hf_tns_data_all8_fetch_rows;
static int hf_tns_data_all8_bind_count;
static int hf_tns_data_all8_sql;
static int hf_tns_data_bind_value;
static int hf_tns_data_fetch_rows;
static int hf_tns_data_lob_op;
static int hf_tns_data_lob_offset;
static int hf_tns_data_col_value;

static int hf_tns_data_descriptor_row_count;
static int hf_tns_data_descriptor_row_size;

static int ett_tns;
static int ett_tns_connect;
static int ett_tns_accept;
static int ett_tns_refuse;
static int ett_tns_abort;
static int ett_tns_redirect;
static int ett_tns_marker;
static int ett_tns_attention;
static int ett_tns_control;
static int ett_tns_data;
static int ett_tns_data_flag;
static int ett_tns_acc_versions;
static int ett_tns_opi_params;
static int ett_tns_opi_par;
static int ett_tns_sopt_flag;
static int ett_tns_ntp_flag;
static int ett_tns_conn_flag;
static int ett_tns_rows;
static int ett_tns_setdt_caphdr;
static int ett_tns_setdt_overrides;
static int ett_tns_setdt_override;
static int ett_tns_oer;
static int ett_tns_iov;
static int ett_tns_dcb_col;
static int ett_tns_all8_options;
static int ett_tns_binds;
static int ett_tns_bind;
static int ett_tns_bind_row;
static int ett_tns_rxd_row;
static int ett_sql;

static expert_field ei_tns_connect_data_next_packet;
static expert_field ei_tns_data_descriptor_size_mismatch;
static expert_field ei_tns_data_piggyback_cursors;
static expert_field ei_tns_data_count_too_large;

#define TCP_PORT_TNS			1521 /* Not IANA registered */

static int * const tns_connect_flags[] = {
	&hf_tns_conn_flag_nareq,
	&hf_tns_conn_flag_nalink,
	&hf_tns_conn_flag_enablena,
	&hf_tns_conn_flag_ichg,
	&hf_tns_conn_flag_wantna,
	NULL
};

static int * const tns_service_options[] = {
	&hf_tns_sopt_flag_bconn,
	&hf_tns_sopt_flag_pc,
	&hf_tns_sopt_flag_hc,
	&hf_tns_sopt_flag_fd,
	&hf_tns_sopt_flag_hd,
	&hf_tns_sopt_flag_dc1,
	&hf_tns_sopt_flag_dc2,
	&hf_tns_sopt_flag_dio,
	&hf_tns_sopt_flag_ap,
	&hf_tns_sopt_flag_ra,
	&hf_tns_sopt_flag_sa,
	NULL
};

/* TTI_ALL8 (SQL execute) options bitmask. */
static int * const tns_all8_options[] = {
	&hf_tns_data_all8_opt_parse,
	&hf_tns_data_all8_opt_bind,
	&hf_tns_data_all8_opt_define,
	&hf_tns_data_all8_opt_execute,
	&hf_tns_data_all8_opt_commit,
	&hf_tns_data_all8_opt_plsql,
	&hf_tns_data_all8_opt_fetch,
	NULL
};

static const value_string tns_type_vals[] = {
	{TNS_TYPE_CONNECT,   "Connect" },
	{TNS_TYPE_ACCEPT,    "Accept" },
	{TNS_TYPE_ACK,       "Acknowledge" },
	{TNS_TYPE_REFUSE,    "Refuse" },
	{TNS_TYPE_REDIRECT,  "Redirect" },
	{TNS_TYPE_DATA,      "Data" },
	{TNS_TYPE_NULL,      "Null" },
	{TNS_TYPE_ABORT,     "Abort" },
	{TNS_TYPE_RESEND,    "Resend"},
	{TNS_TYPE_MARKER,    "Marker"},
	{TNS_TYPE_ATTENTION, "Attention"},
	{TNS_TYPE_CONTROL,   "Control"},
	{TNS_TYPE_DD,        "Data Descriptor"},
	{0, NULL}
};

static const value_string tns_data_funcs[] = {
	{SQLNET_SET_PROTOCOL,     "Set Protocol"},
	{SQLNET_SET_DATATYPES,    "Set Datatypes"},
	{SQLNET_USER_OCI_FUNC,    "User OCI Functions"},
	{SQLNET_RETURN_STATUS,    "Return Status"},
	{SQLNET_ACCESS_USR_ADDR,  "Access User Address Space"},
	{SQLNET_ROW_TRANSF_HDR,   "Row Transfer Header"},
	{SQLNET_ROW_TRANSF_DATA,  "Row Transfer Data"},
	{SQLNET_RETURN_OPI_PARAM, "Return OPI Parameter"},
	{SQLNET_FUNCCOMPLETE,     "Function Complete"},
	{SQLNET_NERROR_RET_DEF,   "N Error return definitions follow"},
	{SQLNET_IOVEC_4FAST_UPI,  "Sending I/O Vec only for fast UPI"},
	{SQLNET_LONG_4FAST_UPI,   "Sending long for fast UPI"},
	{SQLNET_INVOKE_USER_CB,   "Invoke user callback"},
	{SQLNET_LOB_FILE_DF,      "LOB/FILE data follows"},
	{SQLNET_WARNING,          "Warning messages - may be a set of them"},
	{SQLNET_DESCRIBE_INFO,    "Describe Information"},
	{SQLNET_PIGGYBACK_FUNC,   "Piggy back function follow"},
	{SQLNET_SIG_4UCS,         "Signals special action for untrusted callout support"},
	{SQLNET_FLUSH_BIND_DATA,  "Flush Out Bind data in DML/w RETURN when error"},
	{SQLNET_XTRN_PROCSERV_R1, "External Procedures and Services Registrations"},
	{SQLNET_XTRN_PROCSERV_R2, "External Procedures and Services Registrations"},
	{SQLNET_SNS,              "Secure Network Services"},
	{0, NULL}
};

/* Oracle TNS native data-type ids. Used by the Set Datatypes
 * negotiation to label override entries with human names. */
static const value_string tns_data_types[] = {
	{1,   "VARCHAR"},
	{2,   "NUMBER"},
	{3,   "INTEGER"},
	{4,   "FLOAT"},
	{5,   "STRING"},
	{6,   "VARNUM"},
	{7,   "DECIMAL"},
	{8,   "LONG"},
	{9,   "VCS"},
	{11,  "RID"},
	{12,  "DATE"},
	{15,  "VBI"},
	{23,  "RAW"},
	{24,  "LONG RAW"},
	{96,  "CHAR"},
	{100, "BINARY_FLOAT"},
	{101, "BINARY_DOUBLE"},
	{102, "REFCURSOR"},
	{104, "ROWID"},
	{109, "ADT"},
	{111, "REF"},
	{112, "CLOB"},
	{113, "BLOB"},
	{114, "BFILE"},
	{116, "RSET"},
	{180, "TIMESTAMP"},
	{181, "TIMESTAMP WITH TIME ZONE"},
	{182, "INTERVAL YEAR TO MONTH"},
	{183, "INTERVAL DAY TO SECOND"},
	{208, "UROWID"},
	{231, "TIMESTAMP WITH LOCAL TIME ZONE"},
	{0, NULL}
};

/* Oracle NLS character-set ids - the well-known subset, enough to name
 * the charsets seen in a Set Datatypes negotiation. */
static const value_string tns_charsets[] = {
	{31,   "WE8ISO8859P1"},
	{32,   "EE8ISO8859P2"},
	{35,   "CL8ISO8859P5"},
	{170,  "EE8MSWIN1250"},
	{171,  "CL8MSWIN1251"},
	{178,  "WE8MSWIN1252"},
	{830,  "JA16EUC"},
	{852,  "ZHS16GBK"},
	{865,  "ZHT16BIG5"},
	{867,  "ZHT16MSWIN950"},
	{871,  "US7ASCII"},
	{873,  "AL32UTF8"},
	{2000, "AL16UTF16"},
	{0, NULL}
};

/* TTI_LOBOPS operation opcodes. */
static const value_string tns_lob_ops[] = {
	{0x00001, "GET_LENGTH"},
	{0x00002, "READ"},
	{0x00020, "TRIM"},
	{0x00040, "WRITE"},
	{0x00100, "FILE_OPEN"},
	{0x00110, "CREATE_TEMP"},
	{0x00111, "FREE_TEMP"},
	{0x00200, "FILE_CLOSE"},
	{0x00400, "FILE_ISOPEN"},
	{0x00800, "FILE_EXISTS"},
	{0x04000, "GET_CHUNK_SIZE"},
	{0x08000, "OPEN"},
	{0x10000, "CLOSE"},
	{0x11000, "IS_OPEN"},
	{0x80000, "ARRAY"},
	{0, NULL}
};

/* Column character-set form (csfrm) in an OAC descriptor: whether char data
 * is in the database charset or the national (AL16UTF16) charset. */
static const value_string tns_csform_vals[] = {
	{1, "Database charset"},
	{2, "National (AL16UTF16)"},
	{0, NULL}
};

/* Bind directions reported per bind in a TTI_IOV vector (TNS_BIND_DIR_*),
 * cross-referenced with python-oracledb's constants. */
static const value_string tns_iov_bind_dirs[] = {
	{16, "OUT"},
	{32, "IN"},
	{48, "IN OUT"},
	{0, NULL}
};

static const value_string tns_data_oci_subfuncs[] = {
	{1, "Logon to Oracle"},
	{2, "Open Cursor"},
	{3, "Parse a Row"},
	{4, "Execute a Row"},
	{5, "Fetch a Row"},
	{8, "Close Cursor"},
	{9, "Logoff of Oracle"},
	{10, "Describe a select list column"},
	{11, "Define where the column goes"},
	{12, "Auto commit on"},
	{13, "Auto commit off"},
	{14, "Commit"},
	{15, "Rollback"},
	{16, "Set fatal error options"},
	{17, "Resume current operation"},
	{18, "Get Oracle version-date string"},
	{19, "Until we get rid of OASQL"},
	{20, "Cancel the current operation"},
	{21, "Get error message"},
	{22, "Exit Oracle command"},
	{23, "Special function"},
	{24, "Abort"},
	{25, "Dequeue by RowID"},
	{26, "Fetch a long column value"},
	{27, "Create Access Module"},
	{28, "Save Access Module Statement"},
	{29, "Save Access Module"},
	{30, "Parse Access Module Statement"},
	{31, "How many items?"},
	{32, "Initialize Oracle"},
	{33, "Change User ID"},
	{34, "Bind by reference positional"},
	{35, "Get n'th Bind Variable"},
	{36, "Get n'th Into Variable"},
	{37, "Bind by reference"},
	{38, "Bind by reference numeric"},
	{39, "Parse and Execute"},
	{40, "Parse for syntax (only)"},
	{41, "Parse for syntax and SQL Dictionary lookup"},
	{42, "Continue serving after EOF"},
	{43, "Array describe"},
	{44, "Init sys pars command table"},
	{45, "Finalize sys pars command table"},
	{46, "Put sys par in command table"},
	{47, "Get sys pars from command table"},
	{48, "Start Oracle (V6)"},
	{49, "Shutdown Oracle (V6)"},
	{50, "Run Independent Process (V6)"},
	{51, "Test RAM (V6)"},
	{52, "Archive operation (V6)"},
	{53, "Media Recovery - start (V6)"},
	{54, "Media Recovery - record tablespace to recover (V6)"},
	{55, "Media Recovery - get starting log seq # (V6)"},
	{56, "Media Recovery - recover using offline log (V6)"},
	{57, "Media Recovery - cancel media recovery (V6)"},
	{58, "Logon to Oracle (V6)"},
	{59, "Get Oracle version-date string in new format"},
	{60, "Initialize Oracle"},
	{61, "Reserved for MAC; close all cursors"},
	{62, "Bundled execution call"},
	{65, "For direct loader: functions"},
	{66, "For direct loader: buffer transfer"},
	{67, "Distrib. trans. mgr. RPC"},
	{68, "Describe indexes for distributed query"},
	{69, "Session operations"},
	{70, "Execute using synchronized system commit numbers"},
	{71, "Fast UPI calls to OPIAL7"},
	{72, "Long Fetch (V7)"},
	{73, "Call OPIEXE from OPIALL: no two-task access"},
	{74, "Parse Call (V7) to deal with various flavours"},
	{76, "RPC call from PL/SQL"},
	{77, "Do a KGL operation"},
	{78, "Execute and Fetch"},
	{79, "X/Open XA operation"},
	{80, "New KGL operation call"},
	{81, "2nd Half of Logon"},
	{82, "1st Half of Logon"},
	{83, "Do Streaming Operation"},
	{84, "Open Session (71 interface)"},
	{85, "X/Open XA operations (71 interface)"},
	{86, "Debugging operations"},
	{87, "Special debugging operations"},
	{88, "XA Start"},
	{89, "XA Switch and Commit"},
	{90, "Direct copy from db buffers to client address"},
	{91, "OKOD Call (In Oracle <= 7 this used to be Connect"},
	{93, "RPI Callback with ctxdef"},
	{94, "Bundled execution call (V7)"},
	{95, "Do Streaming Operation without begintxn"},
	{96, "LOB and FILE related calls"},
	{97, "File Create call"},
	{98, "Describe query (V8) call"},
	{99, "Connect (non-blocking attach host)"},
	{100, "Open a recursive cursor"},
	{101, "Bundled KPR Execution"},
	{102, "Bundled PL/SQL execution"},
	{103, "Transaction start, attach, detach"},
	{104, "Transaction commit, rollback, recover"},
	{105, "Cursor close all"},
	{106, "Failover into piggyback"},
	{107, "Session switching piggyback (V8)"},
	{108, "Do Dummy Defines"},
	{109, "Init sys pars (V8)"},
	{110, "Finalize sys pars (V8)"},
	{111, "Put sys par in par space (V8)"},
	{112, "Terminate sys pars (V8)"},
	{114, "Init Untrusted Callbacks"},
	{115, "Generic authentication call"},
	{116, "FailOver Get Instance call"},
	{117, "Oracle Transaction service Commit remote sites"},
	{118, "Get the session key"},
	{119, "Describe any (V8)"},
	{120, "Cancel All"},
	{121, "AQ Enqueue"},
	{122, "AQ Dequeue"},
	{123, "Object transfer"},
	{124, "RFS Call"},
	{125, "Kernel programmatic notification"},
	{126, "Listen"},
	{127, "Oracle Transaction service Commit remote sites (V >= 8.1.3)"},
	{128, "Dir Path Prepare"},
	{129, "Dir Path Load Stream"},
	{130, "Dir Path Misc. Ops"},
	{131, "Memory Stats"},
	{132, "AQ Properties Status"},
	{134, "Remote Fetch Archive Log FAL"},
	{135, "Client ID propagation"},
	{136, "DR Server CNX Process"},
	{138, "SPFILE parameter put"},
	{139, "KPFC exchange"},
	{140, "Object Transfer (V8.2)"},
	{141, "Push Transaction"},
	{142, "Pop Transaction"},
	{143, "KFN Operation"},
	{144, "Dir Path Unload Stream"},
	{145, "AQ batch enqueue dequeue"},
	{146, "File Transfer"},
	{147, "Ping"},
	{148, "TSM"},
	{150, "Begin TSM"},
	{151, "End TSM"},
	{152, "Set schema"},
	{153, "Fetch from suspended result set"},
	{154, "Key/Value pair"},
	{155, "XS Create session Operation"},
	{156, "XS Session Roundtrip Operation"},
	{157, "XS Piggyback Operation"},
	{158, "KSRPC Execution"},
	{159, "Streams combined capture apply"},
	{160, "AQ replay information"},
	{161, "SSCR"},
	{162, "Session Get"},
	{163, "Session RLS"},
	{165, "Workload replay data"},
	{166, "Replay statistic data"},
	{167, "Query Cache Stats"},
	{168, "Query Cache IDs"},
	{169, "RPC Test Stream"},
	{170, "Replay PL/SQL RPC"},
	{171, "XStream Out"},
	{172, "Golden Gate RPC"},
	{0, NULL}
};
static value_string_ext tns_data_oci_subfuncs_ext = VALUE_STRING_EXT_INIT(tns_data_oci_subfuncs);

/* The final byte of a TNS_MARKER body selects break vs reset:
 * 01 00 01 = break, 01 00 02 = reset. */
static const value_string tns_marker_functions[] = {
	{1, "Break (interrupt call)"},
	{2, "Reset (clear line)"},
	{0, NULL}
};

static const value_string tns_marker_types[] = {
	{0, "Data Marker - 0 Data Bytes"},
	{1, "Data Marker - 1 Data Bytes"},
	{2, "Attention Marker"},
	{0, NULL}
};

static const value_string tns_control_cmds[] = {
	{1, "Oracle Trace Command"},
	{0, NULL}
};

/* Column types from the most recent describe (TTI_DCB), threaded to a later
 * TTI_RXD response so its row values can be split per column. */
typedef struct _tns_describe_t {
	uint32_t num_cols;
	uint8_t *types;
} tns_describe_t;

typedef struct _tns_conv_info_t {
	uint32_t pending_connect_data;
	tns_describe_t *last_describe;
} tns_conv_info_t;

/* p_add_proto_data key for the describe a TTI_RXD response packet uses. */
#define TNS_PROTO_DATA_DESCRIBE 1

void proto_reg_handoff_tns(void);
static int dissect_tns_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_);

static tns_conv_info_t*
tns_get_conv_info(packet_info *pinfo)
{
	conversation_t *conversation = find_or_create_conversation(pinfo);

	tns_conv_info_t *tns_info = (tns_conv_info_t *)conversation_get_proto_data(conversation, proto_tns);
	if (!tns_info) {
		tns_info = wmem_new0(wmem_file_scope(), tns_conv_info_t);
		conversation_add_proto_data(conversation, proto_tns, tns_info);
	}
	return tns_info;
}

static unsigned get_data_func_id(tvbuff_t *tvb, int offset)
{
	/* Determine Data Function id */
	uint8_t first_byte;

	first_byte =
	    tvb_reported_length_remaining(tvb, offset) > 0 ? tvb_get_uint8(tvb, offset) : 0;

	if ( tvb_bytes_exist(tvb, offset, 4) && first_byte == 0xDE &&
	     tvb_get_uint24(tvb, offset+1, ENC_BIG_ENDIAN) == 0xADBEEF )
	{
		return SQLNET_SNS;
	}
	else
	{
		return (unsigned)first_byte;
	}
}

static int get_strtype_custom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	int ret = 1; // 1st byte contains 254 or length if smaller than 64
	int len = 0;

	wmem_strbuf_t *strbuf = wmem_strbuf_new(pinfo->pool, "");

	len = tvb_get_uint8(tvb, offset);
	if (len == 254) {
		int actual_len = 0;
		len = 0;
		do { // walk over the chunks
			len = tvb_get_uint8(tvb, offset  + ret);
			ret++; // 1st byte with the chunk size
			wmem_strbuf_append(strbuf, (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset  + ret, len, ENC_ASCII|ENC_NA));
			ret += len; // length of the string's chunk
			actual_len += len;
		} while (len == 64);
		ret++; // has to be null-terminated
		len = actual_len;
	}
	else {
		ret += len;
		wmem_strbuf_append(strbuf, (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset + 1, len, ENC_ASCII|ENC_NA));
	}

	proto_tree_add_uint(tree, hf_tns_data_opi_param_length, tvb, offset, 1, len);
	proto_tree_add_string(tree, hf_tns_data_opi_param_value, tvb, offset+1, ret-1, wmem_strbuf_get_str(strbuf));

	return ret;
}

/* Decode an Oracle variable-length integer (ub4 / sb4):
 * a length byte, then that many big-endian magnitude bytes. The low 7 bits
 * of the length byte are the magnitude width (0..4); the high bit flags a
 * negative value in sign-magnitude form (not two's complement) — so -1 is
 * 0x81 0x01 and NUMBER scale -127 is 0x81 0x7f.
 * Returns the number of bytes consumed. */
static int get_sb4_custom(tvbuff_t *tvb, int offset, int *result)
{
	uint8_t first_byte = tvb_get_uint8(tvb, offset); // Contains length of a value
	bool negative = (first_byte & 0x80) != 0;
	uint8_t width = first_byte & 0x7f;
	int magnitude = 0;

	switch(width)
	{
		case 0:
			magnitude = 0;
			break;
		case 1:
			magnitude = tvb_get_uint8(tvb, offset+1);
			break;
		case 2:
			magnitude = tvb_get_ntohs(tvb, offset+1);
			break;
		case 3:
			magnitude = tvb_get_ntoh24(tvb, offset+1);
			break;
		case 4:
			magnitude = tvb_get_ntohl(tvb, offset+1);
			break;
		default:
			/* Width 5..0x7f is not a valid 1..4-byte integer. In practice
			 * only a raw ub2 counter read through this helper reaches here;
			 * the historic client behaviour is to consume two bytes and
			 * return the negated second byte, which keeps the stream
			 * aligned. The value is discarded by such callers. */
			if ( tvb_reported_length_remaining(tvb, offset) < 2 )
			{
				/* Not even that second byte is present. The width came
				 * off the wire, so this is malformed input rather than
				 * a bug in the dissector - step over the width alone. */
				*result = 0;
				return 1;
			}
			*result = -(int)tvb_get_uint8(tvb, offset+1);
			return 2;
	}
	*result = negative ? -magnitude : magnitude;
	return width + 1;
}

/* Decode a DALC (Data-Length-And-Content) blob. The leading byte is a
 * length only in the middle of its range:
 *
 *   0x00        empty
 *   0x01..0xFD  that many data bytes follow
 *   0xFE        chunked: (len, bytes) pairs until a 0-length chunk
 *   0xFF        null - a marker only, no data follows
 *
 * The null marker consumes just itself. Reading it as a length would
 * claim 255 bytes that are not there and misalign every field after
 * it, so it has to be spelled out rather than left to the default.
 *
 * The chunk lengths in the 0xFE form are single bytes here, which is
 * the 11g shape this dissector decodes throughout; 12.2 and later
 * prefix each chunk with a variable-length ub4 instead. Telling the
 * two apart needs the field version negotiated during the handshake,
 * which is not threaded through yet.
 *
 * Returns the number of bytes consumed from the tvb and, when content
 * is non-empty, a UTF-8 string allocated from pinfo->pool. */
static int get_dalc_custom(tvbuff_t *tvb, packet_info *pinfo, int offset, const char **out_str)
{
	uint8_t first = tvb_get_uint8(tvb, offset);
	if ( first == 0 || first == 255 )
	{
		if ( out_str )
			*out_str = NULL;
		return 1;
	}
	if ( first != 254 )
	{
		if ( out_str )
			*out_str = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset + 1, first, ENC_UTF_8|ENC_NA);
		return 1 + first;
	}

	/* Chunked form: walk (len, bytes)+ until a zero-length chunk. */
	wmem_strbuf_t *strbuf = wmem_strbuf_new(pinfo->pool, "");
	int o = offset + 1;
	while ( tvb_reported_length_remaining(tvb, o) > 0 )
	{
		uint8_t chunk_len = tvb_get_uint8(tvb, o);
		o += 1;
		if ( chunk_len == 0 )
			break;
		wmem_strbuf_append(strbuf, (const char *)tvb_get_string_enc(pinfo->pool, tvb, o, chunk_len, ENC_UTF_8|ENC_NA));
		o += chunk_len;
	}
	if ( out_str )
		*out_str = wmem_strbuf_get_str(strbuf);
	return o - offset;
}

/* Decode a bytes_with_length / str_with_length field: a ub4 count, and
 * a DALC carrying the value only when that count is non-zero. The count
 * is not simply a byte to step over - an empty field is the count
 * alone, so reading a DALC anyway consumes whatever follows it.
 * Returns bytes consumed; *out_str (when non-NULL) gets the string, or
 * NULL when the field is empty. */
static int get_field_with_length(tvbuff_t *tvb, packet_info *pinfo, int offset, const char **out_str)
{
	int count = 0;
	int used = get_sb4_custom(tvb, offset, &count);
	if ( out_str )
		*out_str = NULL;
	if ( count > 0 )
		used += get_dalc_custom(tvb, pinfo, offset + used, out_str);
	return used;
}

/* Render an Oracle NUMBER value as a decimal string.
 * Base-100 float: byte 0 is the biased exponent (top bit = sign, inverted
 * for negatives); the rest are base-100 mantissa groups, with a trailing
 * 0x66 terminator on negatives.
 * Returns a pinfo->pool string, or NULL if the value is not renderable. */
static const char *tns_format_number(packet_info *pinfo, const uint8_t *data, int len)
{
	if ( len <= 0 )
		return NULL;
	if ( len == 1 )
		return (data[0] == 0x80) ? "0" : NULL; /* 0x80 = zero; sentinels skipped */

	uint8_t exp_byte = data[0];
	bool is_pos = (exp_byte & 0x80) != 0;
	int exponent = is_pos ? (exp_byte & 0x7f) - 65 : ((~exp_byte) & 0x7f) - 65;

	int mant_len = len - 1;
	if ( !is_pos && mant_len > 0 && data[len - 1] == 0x66 )
		mant_len--; /* drop the negative terminator */

	/* Build the base-100 digit string (two decimal digits per group). */
	wmem_strbuf_t *digits = wmem_strbuf_new(pinfo->pool, "");
	for ( int i = 0; i < mant_len; i++ )
	{
		int pair = is_pos ? (data[1 + i] - 1) : (101 - data[1 + i]);
		if ( pair < 0 || pair > 99 )
			return NULL; /* malformed */
		wmem_strbuf_append_printf(digits, "%02d", pair);
	}
	const char *ds = wmem_strbuf_get_str(digits);
	int dlen = (int)wmem_strbuf_get_len(digits);
	int int_digits = (exponent + 1) * 2;

	wmem_strbuf_t *ip = wmem_strbuf_new(pinfo->pool, "");
	wmem_strbuf_t *fp = wmem_strbuf_new(pinfo->pool, "");
	if ( int_digits >= dlen )
	{
		wmem_strbuf_append(ip, ds);
		for ( int i = 0; i < int_digits - dlen; i++ )
			wmem_strbuf_append_c(ip, '0');
	}
	else if ( int_digits <= 0 )
	{
		wmem_strbuf_append_c(ip, '0');
		for ( int i = 0; i < -int_digits; i++ )
			wmem_strbuf_append_c(fp, '0');
		wmem_strbuf_append(fp, ds);
	}
	else
	{
		wmem_strbuf_append(ip, wmem_strndup(pinfo->pool, ds, int_digits));
		wmem_strbuf_append(fp, ds + int_digits);
	}

	/* Trim leading zeros on the integer part, trailing zeros on the fraction. */
	const char *ips = wmem_strbuf_get_str(ip);
	while ( ips[0] == '0' && ips[1] != '\0' )
		ips++;
	char *fps = wmem_strdup(pinfo->pool, wmem_strbuf_get_str(fp));
	int flen = (int)strlen(fps);
	while ( flen > 0 && fps[flen - 1] == '0' )
		fps[--flen] = '\0';

	const char *sign = is_pos ? "" : "-";
	if ( flen > 0 )
		return wmem_strdup_printf(pinfo->pool, "%s%s.%s", sign, ips, fps);
	return wmem_strdup_printf(pinfo->pool, "%s%s", sign, ips);
}

/* Render an Oracle DATE / TIMESTAMP value as an
 * ISO-ish string. 7 bytes: century+100, year+100, month, day, hour+1,
 * minute+1, second+1; 11 bytes add 4-byte big-endian nanoseconds.
 * Returns a pinfo->pool string, or NULL. */
static const char *tns_format_date(packet_info *pinfo, const uint8_t *data, int len)
{
	if ( len < 7 )
		return NULL;
	int year = (data[0] - 100) * 100 + (data[1] - 100);
	int month = data[2], day = data[3];
	int hour = data[4] - 1, minute = data[5] - 1, second = data[6] - 1;
	if ( month < 1 || month > 12 || day < 1 || day > 31 ||
	     hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59 )
		return NULL;
	if ( len >= 11 )
	{
		uint32_t nsec = ((uint32_t)data[7] << 24) | ((uint32_t)data[8] << 16) |
				((uint32_t)data[9] << 8) | data[10];
		if ( nsec > 0 )
			return wmem_strdup_printf(pinfo->pool, "%04d-%02d-%02d %02d:%02d:%02d.%09u",
				year, month, day, hour, minute, second, nsec);
	}
	return wmem_strdup_printf(pinfo->pool, "%04d-%02d-%02d %02d:%02d:%02d",
		year, month, day, hour, minute, second);
}

static void vsnum_to_vstext_basecustom(char *result, uint32_t vsnum)
{
	/*
	 * Translate hex value to human readable version value, described at
	 * http://docs.oracle.com/cd/B28359_01/server.111/b28310/dba004.htm
	 */
	snprintf(result, ITEM_LABEL_LENGTH, "%d.%d.%d.%d.%d",
		 vsnum >> 24,
		(vsnum >> 20) & 0xf,
		(vsnum >> 12) & 0xf,
		(vsnum >>  8) & 0xf,
		 vsnum & 0xff);
}

/* Decode an OAC (Oracle Access Column) descriptor — the type/format core
 * shared by describe columns and bind descriptors. Fields
 * use the Oracle variable-length form (get_sb4_custom).
 * Returns the new offset. */
static int dissect_tns_oac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	int v = 0, start;

	/* type (ub1) */
	proto_tree_add_item(tree, hf_tns_data_col_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	/* flag (ub1, skip) */
	offset += 1;
	/* precision (sb1) */
	proto_tree_add_item(tree, hf_tns_data_col_precision, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	/* scale (ub4, may be negative — NUMBER default is -127) */
	start = offset;
	offset += get_sb4_custom(tvb, offset, &v);
	proto_tree_add_int(tree, hf_tns_data_col_scale, tvb, start, offset - start, v);
	/* max data length / buffer size (ub4) */
	start = offset;
	offset += get_sb4_custom(tvb, offset, &v);
	proto_tree_add_uint(tree, hf_tns_data_col_max_length, tvb, start, offset - start, v);
	/* max array elements (ub4, skip) */
	offset += get_sb4_custom(tvb, offset, &v);
	/* cont flags (ub4, skip) */
	offset += get_sb4_custom(tvb, offset, &v);
	/* type OID (bytes_with_length, skip) */
	offset += get_field_with_length(tvb, pinfo, offset, NULL);
	/* version (ub4, skip) */
	offset += get_sb4_custom(tvb, offset, &v);
	/* charset id (ub4) */
	start = offset;
	offset += get_sb4_custom(tvb, offset, &v);
	proto_tree_add_uint(tree, hf_tns_data_col_charset, tvb, start, offset - start, v);
	/* charset form (ub1) */
	proto_tree_add_item(tree, hf_tns_data_col_csform, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	/* max size (ub4) */
	start = offset;
	offset += get_sb4_custom(tvb, offset, &v);
	proto_tree_add_uint(tree, hf_tns_data_col_max_size, tvb, start, offset - start, v);

	return offset;
}

/* Decode one per-column metadata block of a TTI_DCB describe (11g
 * shape): an OAC descriptor plus the nullability and naming fields.
 * Returns the new offset. */
static int dissect_tns_dcb_column(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int idx)
{
	proto_tree *col_tree;
	proto_item *col_item;
	int col_start = offset, v = 0;
	uint8_t col_type = tvb_get_uint8(tvb, offset);
	const char *name = NULL;

	col_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
		ett_tns_dcb_col, &col_item, "Column %d", idx);

	offset = dissect_tns_oac(tvb, pinfo, col_tree, offset);

	/* nulls allowed (ub1) */
	proto_tree_add_item(col_tree, hf_tns_data_col_nulls_ok, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	/* v7 name length (ub1, skip) */
	offset += 1;
	/* column name (str_with_length) */
	int name_start = offset;
	offset += get_field_with_length(tvb, pinfo, offset, &name);
	if ( name )
		proto_tree_add_string(col_tree, hf_tns_data_col_name, tvb, name_start, offset - name_start, name);
	/* schema name, type name (str_with_length, skip) */
	offset += get_field_with_length(tvb, pinfo, offset, NULL);
	offset += get_field_with_length(tvb, pinfo, offset, NULL);
	/* column position (ub4, skip) */
	offset += get_sb4_custom(tvb, offset, &v);
	/* uds flags (ub4, skip) — 11g addition */
	offset += get_sb4_custom(tvb, offset, &v);

	if ( name )
		proto_item_append_text(col_item, ": %s (%s)", name,
			val_to_str_const(col_type, tns_data_types, "unknown"));
	proto_item_set_len(col_item, offset - col_start);
	return offset;
}

/* Decode one TTI_RXD column value by its describe data type, and add it as a
 * "Column N (TYPE)" item showing the raw value bytes. Ordinary values are a
 * DALC blob; ROWID / UROWID / LONG / LOB carry their own framings.
 * Object / JSON / VECTOR values have richer image
 * framings not handled here, so on those the caller stops (sets *bail) and
 * leaves the remainder to the data dissector. Returns the new offset. */
static int dissect_tns_rxd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint8_t dtype, int idx, int *bail)
{
	int v_start = offset, disp_start = offset, v = 0;
	int is_null = 0;
	uint8_t first;
	const char *rendered = NULL;

	switch ( dtype )
	{
		case 109: /* ADT / object */
		case 119: /* JSON (OSON) */
		case 127: /* VECTOR */
			*bail = 1;
			return offset;

		case 11:  /* ROWID: indicator, then obj/file/unused/block/slot (ub4) */
			first = tvb_get_uint8(tvb, offset);
			offset += 1;
			if ( first == 0 || first == 0xff )
				is_null = 1;
			else
				for ( int k = 0; k < 5; k++ )
					offset += get_sb4_custom(tvb, offset, &v);
			break;

		case 208: /* UROWID: ub4 num_bytes, a length echo byte, then the bytes */
			offset += get_sb4_custom(tvb, offset, &v);
			if ( v > 0 )
				offset += 1 + v;
			else
				is_null = 1;
			break;

		case 8:   /* LONG */
		case 24:  /* LONG RAW: value then two trailing ub4 length indicators */
			first = tvb_get_uint8(tvb, offset);
			if ( first == 0 )
			{
				offset += 1;
				is_null = 1;
			}
			else if ( first == 0xfe ) /* chunked: ub1 len chunks until 0 (11g) */
			{
				offset += 1;
				while ( tvb_reported_length_remaining(tvb, offset) > 0 )
				{
					uint8_t chunk_len = tvb_get_uint8(tvb, offset);
					offset += 1;
					if ( chunk_len == 0 )
						break;
					offset += chunk_len;
				}
			}
			else
				offset += 1 + first;
			offset += get_sb4_custom(tvb, offset, &v);
			offset += get_sb4_custom(tvb, offset, &v);
			break;

		case 112: /* CLOB */
		case 113: /* BLOB */
		case 114: /* BFILE: 0x00 NULL, else ub4 num_bytes + DALC locator block */
			first = tvb_get_uint8(tvb, offset);
			if ( first == 0 )
			{
				offset += 1;
				is_null = 1;
			}
			else
			{
				offset += get_sb4_custom(tvb, offset, &v);
				offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			}
			break;

		default: /* ordinary: a single DALC value */
			first = tvb_get_uint8(tvb, offset);
			offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			if ( first == 0 )
				is_null = 1;
			else
			{
				disp_start = v_start + 1; /* show the value bytes, not the length */
				/* Render common scalar types (never chunked): NUMBER as
				 * decimal, DATE / TIMESTAMP / TIMESTAMP LTZ as a datetime. */
				if ( first != 254 && offset > disp_start )
				{
					const uint8_t *vb = tvb_get_ptr(tvb, disp_start, offset - disp_start);
					int vlen = offset - disp_start;
					if ( dtype == 2 )
						rendered = tns_format_number(pinfo, vb, vlen);
					else if ( dtype == 12 || dtype == 180 || dtype == 231 )
						rendered = tns_format_date(pinfo, vb, vlen);
				}
			}
			break;
	}

	if ( is_null )
		proto_tree_add_bytes_format(tree, hf_tns_data_col_value, tvb,
			v_start, offset - v_start, NULL, "Column %d (%s): NULL", idx,
			val_to_str_const(dtype, tns_data_types, "unknown"));
	else if ( rendered )
		proto_tree_add_bytes_format(tree, hf_tns_data_col_value, tvb,
			disp_start, offset - disp_start, NULL, "Column %d (%s): %s", idx,
			val_to_str_const(dtype, tns_data_types, "unknown"), rendered);
	else
		proto_tree_add_bytes_format(tree, hf_tns_data_col_value, tvb,
			disp_start, offset - disp_start, NULL, "Column %d (%s)", idx,
			val_to_str_const(dtype, tns_data_types, "unknown"));
	return offset;
}

static void dissect_tns_data_descriptor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tns_tree, uint32_t length)
{
	/* This is used by Oracle 12c for at least sending LOB/FILE data. */
	proto_tree *dd_tree, *row_tree;
	proto_item *ti;
	uint32_t data_len, row_count, row_size, total_row_size = 0;
	int orig_offset = offset;

	/* We only get here after tcp_dissect_pdus(), length is guaranteed. */
	DISSECTOR_ASSERT_CMPINT(length, >=, TNS_HDR_LEN);

	dd_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1, ett_tns_data, NULL, "Data Descriptor");

	/* No idea what this is. Usually 0x0003. */
	offset += 4;
	proto_tree_add_item_ret_uint(dd_tree, hf_tns_data_length, tvb,
			offset, 4, ENC_BIG_ENDIAN, &data_len);
	offset += 4;

	/* This next parameter looks like: number of big endian shorts that follow,
	 * the sum of the shorts equals the file length above - each short maxes
	 * out at 0x1f7c = 8060, presumably related to the page size / max table
	 * row size in Microsoft SQL Server? Something about how many rows it
	 * would take to store this in-table?
	 */
	proto_tree_add_item_ret_uint(dd_tree, hf_tns_data_descriptor_row_count, tvb,
			offset, 4, ENC_BIG_ENDIAN, &row_count);
	offset += 4;
	row_tree = proto_tree_add_subtree(dd_tree, tvb, offset, row_count * 2,
		ett_tns_rows, &ti, "Rows");
	for (uint32_t i = 0; i < row_count; i++) {
		proto_tree_add_item_ret_uint(row_tree, hf_tns_data_descriptor_row_size, tvb,
				offset, 2, ENC_BIG_ENDIAN, &row_size);
		total_row_size += row_size;
		offset += 2;
	}
	proto_item_append_text(ti, " (%u bytes)", total_row_size);
	if (total_row_size != data_len) {
		expert_add_info(pinfo, ti, &ei_tns_data_descriptor_size_mismatch);
	}

	offset = orig_offset + (length - TNS_HDR_LEN);

	call_data_dissector(tvb_new_subset_length(tvb, offset, data_len), pinfo,
	    dd_tree);
}

static void dissect_tns_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tns_tree)
{
	proto_tree *data_tree;
	unsigned data_func_id;
	bool is_request;
	static int * const flags[] = {
		&hf_tns_data_flag_send,
		&hf_tns_data_flag_rc,
		&hf_tns_data_flag_c,
		&hf_tns_data_flag_reserved,
		&hf_tns_data_flag_more,
		&hf_tns_data_flag_eof,
		&hf_tns_data_flag_dic,
		&hf_tns_data_flag_rts,
		&hf_tns_data_flag_sntt,
		NULL
	};

	is_request = pinfo->match_uint == pinfo->destport;
	data_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1, ett_tns_data, NULL, "Data");

	proto_tree_add_bitmask(data_tree, tvb, offset, hf_tns_data_flag, ett_tns_data_flag, flags, ENC_BIG_ENDIAN);
	offset += 2;
	data_func_id = get_data_func_id(tvb, offset);

	/* Do this only if the Data message have a body. Otherwise, there are only Data flags. */
	int remaining = tvb_reported_length_remaining(tvb, offset);
	if ( remaining > 0 )
	{
		if (is_request) {
			if (!PINFO_FD_VISITED(pinfo)) {
				tns_conv_info_t *tns_info = tns_get_conv_info(pinfo);
				if ((uint32_t)remaining == tns_info->pending_connect_data) {
					col_append_str(pinfo->cinfo, COL_INFO, ", Connect Data");
					proto_tree_add_item(data_tree, hf_tns_connect_data, tvb,
						offset, -1, ENC_ASCII);
					p_add_proto_data(wmem_file_scope(), pinfo, proto_tns, 0,
						GUINT_TO_POINTER(tns_info->pending_connect_data));
					tns_info->pending_connect_data = 0;
					return;
				}
			} else {
				if (p_get_proto_data(wmem_file_scope(), pinfo, proto_tns, 0) != NULL) {
					col_append_str(pinfo->cinfo, COL_INFO, ", Connect Data");
					proto_tree_add_item(data_tree, hf_tns_connect_data, tvb,
						offset, -1, ENC_ASCII);
					return;
				}
			}
		}
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(data_func_id, tns_data_funcs, "unknown"));

		if ( (data_func_id != SQLNET_SNS) && (try_val_to_str(data_func_id, tns_data_funcs) != NULL) )
		{
			proto_tree_add_item(data_tree, hf_tns_data_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}

	/* Handle data functions that have more than just ID */
	switch (data_func_id)
	{
		case SQLNET_SET_PROTOCOL:
		{
			proto_tree *versions_tree;
			proto_item *ti;
			char sep;
			if ( is_request )
			{
				versions_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1, ett_tns_acc_versions, &ti, "Accepted Versions");
				sep = ':';
				for (;;) {
					/*
					 * Add each accepted version as a
					 * separate item.
					 */
					uint8_t vers;

					vers = tvb_get_uint8(tvb, offset);
					if (vers == 0) {
						/*
						 * A version of 0 terminates
						 * the list.
						 */
						break;
					}
					proto_item_append_text(ti, "%c %u", sep, vers);
					sep = ',';
					proto_tree_add_uint(versions_tree, hf_tns_data_setp_acc_version, tvb, offset, 1, vers);
					offset += 1;
				}
				offset += 1; /* skip the 0 terminator */
				proto_item_set_end(ti, tvb, offset);
				proto_tree_add_item(data_tree, hf_tns_data_setp_cli_plat, tvb, offset, -1, ENC_ASCII);

				return; /* skip call_data_dissector */
			}
			else
			{
				unsigned len;
				versions_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1, ett_tns_acc_versions, &ti, "Versions");
				sep = ':';
				for (;;) {
					/*
					 * Add each version as a separate item.
					 */
					uint8_t vers;

					vers = tvb_get_uint8(tvb, offset);
					if (vers == 0) {
						/*
						 * A version of 0 terminates
						 * the list.
						 */
						break;
					}
					proto_item_append_text(ti, "%c %u", sep, vers);
					sep = ',';
					proto_tree_add_uint(versions_tree, hf_tns_data_setp_version, tvb, offset, 1, vers);
					offset += 1;
				}
				offset += 1; /* skip the 0 terminator */
				proto_item_set_end(ti, tvb, offset);
				proto_tree_add_item_ret_length(data_tree, hf_tns_data_setp_banner, tvb, offset, -1, ENC_ASCII|ENC_NA, &len);
				offset += len;
			}
			break;
		}

		case SQLNET_SET_DATATYPES:
		{
			/* TTI_DTY: Data Type Negotiation, sent right after TTI_PRO
			 * during the TTC handshake. The body is a fixed-shape blob
			 * the client uses to tell the server which native Oracle
			 * data types it understands and what wire representation it
			 * wants for each. Layout cross-referenced with
			 * python-oracledb.
			 *
			 *   charset_in        2 bytes LE   NLS_LANGUAGE charset id
			 *   charset_out       2 bytes LE   NLS_NCHAR   charset id
			 *   flag              1 byte       capability flag (1 = std)
			 *   capability header 39 bytes     version triple + flag bytes
			 *   table header      8 bytes      group/sub counts
			 *   identity map     980 bytes     245 x (type, type, 1, 0)
			 *   type overrides    var          entries, terminated by 0
			 */
			proto_tree *caphdr_tree, *ov_tree;
			proto_item *caphdr_item, *ov_item;

			if ( !is_request )
				break;

			proto_tree_add_item(data_tree, hf_tns_data_setdt_charset_in, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(data_tree, hf_tns_data_setdt_charset_out, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(data_tree, hf_tns_data_setdt_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			caphdr_item = proto_tree_add_item(data_tree, hf_tns_data_setdt_caphdr, tvb, offset, 39, ENC_NA);
			caphdr_tree = proto_item_add_subtree(caphdr_item, ett_tns_setdt_caphdr);
			proto_tree_add_item(caphdr_tree, hf_tns_data_setdt_caphdr_version, tvb, offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(caphdr_tree, hf_tns_data_setdt_caphdr_flags, tvb, offset + 3, 36, ENC_NA);
			offset += 39;

			proto_tree_add_item(data_tree, hf_tns_data_setdt_tblhdr, tvb, offset, 8, ENC_NA);
			offset += 8;
			proto_tree_add_item(data_tree, hf_tns_data_setdt_idmap, tvb, offset, 980, ENC_NA);
			offset += 980;

			/* Walk type-override entries until the 0 terminator. Each
			 * entry is (client_type, server_repr[, format]); a 0 in the
			 * server_repr slot marks a short "client knows the id but
			 * has no override" entry. */
			ov_item = proto_tree_add_item(data_tree, hf_tns_data_setdt_overrides, tvb, offset, -1, ENC_NA);
			ov_tree = proto_item_add_subtree(ov_item, ett_tns_setdt_overrides);
			int ov_start = offset;
			while ( tvb_reported_length_remaining(tvb, offset) > 0 )
			{
				uint8_t client_type = tvb_get_uint8(tvb, offset);
				if ( client_type == 0 )
				{
					proto_tree_add_item(ov_tree, hf_tns_data_setdt_override_client, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					break;
				}
				uint8_t repr = tvb_get_uint8(tvb, offset + 1);
				int entry_len = (repr == 0) ? 2 : 4;
				proto_tree *e_tree = proto_tree_add_subtree_format(ov_tree, tvb, offset, entry_len,
					ett_tns_setdt_override, NULL, "Type %u (%s)",
					client_type, val_to_str_const(client_type, tns_data_types, "unknown"));
				proto_tree_add_item(e_tree, hf_tns_data_setdt_override_client, tvb, offset, 1, ENC_BIG_ENDIAN);
				if ( entry_len == 4 )
				{
					proto_tree_add_item(e_tree, hf_tns_data_setdt_override_repr, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(e_tree, hf_tns_data_setdt_override_format, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
				}
				offset += entry_len;
			}
			proto_item_set_len(ov_item, offset - ov_start);
			break;
		}

		case SQLNET_RETURN_STATUS:
		{
			/* TTI_OER: server-side end-of-call status block. Emitted at
			 * the end of every response — success or failure. Layout
			 * cross-referenced with python-oracledb's
			 * _process_error_info, in the Oracle 11g shape (no extended
			 * ub4 error number / ub8 rowcount that 12c+ adds).
			 *
			 * All multi-byte integers are stored in the ub4 variable-
			 * length form (see get_sb4_custom): first byte holds the
			 * value's width (0..4), followed by that many big-endian
			 * data bytes. */
			proto_tree *oer_tree;
			proto_item *oer_item;
			int oer_start = offset;
			int v;

			oer_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1, ett_tns_oer, &oer_item, "Oracle Error Return");

			/* call_status */
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_int(oer_tree, hf_tns_data_oer_call_status, tvb, oer_start, offset - oer_start, v);
			/* end-to-end seq# (skipped) */
			offset += get_sb4_custom(tvb, offset, &v);
			/* rowcount (DML affected rows on 11g) */
			int rc_start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_int(oer_tree, hf_tns_data_oer_rowcount, tvb, rc_start, offset - rc_start, v);
			/* err_code (ORA-NNNNN, 0 on success) */
			int ec_start = offset;
			int err_code = 0;
			offset += get_sb4_custom(tvb, offset, &err_code);
			proto_tree_add_int(oer_tree, hf_tns_data_oer_err_code, tvb, ec_start, offset - ec_start, err_code);
			/* array elem error #1, #2 (skipped) */
			offset += get_sb4_custom(tvb, offset, &v);
			offset += get_sb4_custom(tvb, offset, &v);
			/* cursor_id */
			int ci_start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_int(oer_tree, hf_tns_data_oer_cursor_id, tvb, ci_start, offset - ci_start, v);
			/* error position (skipped) */
			offset += get_sb4_custom(tvb, offset, &v);
			/* 6 single-byte fields: sql_type, fatal, flags, user_cursor_opts, upi_param, warn_flags */
			offset += 6;
			/* rowid: ub4 rba, ub2 part_id, 1 byte reserved, ub4 block, ub2 slot */
			offset += get_sb4_custom(tvb, offset, &v);
			offset += get_sb4_custom(tvb, offset, &v);
			offset += 1;
			offset += get_sb4_custom(tvb, offset, &v);
			offset += get_sb4_custom(tvb, offset, &v);
			/* os error (skipped) */
			offset += get_sb4_custom(tvb, offset, &v);
			/* statement #, call # (1 byte each) */
			offset += 2;
			/* padding ub2 + successful iterations ub4 */
			offset += get_sb4_custom(tvb, offset, &v);
			offset += get_sb4_custom(tvb, offset, &v);
			/* oerrdd (logical rowid), a bytes_with_length — skipped */
			offset += get_field_with_length(tvb, pinfo, offset, NULL);

			/* Batch error arrays (array DML). The code and offset arrays
			 * are each a ub4 count followed by one DALC packing that many
			 * ub4 values back to back; the message array is a ub4 count,
			 * an indicator byte, and then that many str_with_length
			 * entries each with a 2-byte trailer. All three counts are
			 * zero for an ordinary statement. */
			int n_codes = 0, n_offs = 0, n_msgs = 0;
			int nb_start = offset;
			offset += get_sb4_custom(tvb, offset, &n_codes);
			proto_tree_add_int(oer_tree, hf_tns_data_oer_n_batch_errcodes, tvb, nb_start, offset - nb_start, n_codes);
			if ( n_codes > 0 )
				offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			nb_start = offset;
			offset += get_sb4_custom(tvb, offset, &n_offs);
			proto_tree_add_int(oer_tree, hf_tns_data_oer_n_batch_offsets, tvb, nb_start, offset - nb_start, n_offs);
			if ( n_offs > 0 )
				offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			nb_start = offset;
			offset += get_sb4_custom(tvb, offset, &n_msgs);
			proto_tree_add_int(oer_tree, hf_tns_data_oer_n_batch_messages, tvb, nb_start, offset - nb_start, n_msgs);
			if ( n_msgs > 0 )
			{
				offset += 1;
				for ( int i = 0; i < n_msgs; i++ )
				{
					offset += get_field_with_length(tvb, pinfo, offset, NULL);
					offset += 2;
				}
			}

			/* Trailing message DALC — present (and meaningful) only when
			 * err_code is non-zero. */
			if ( err_code != 0 && tvb_reported_length_remaining(tvb, offset) > 0 )
			{
				const char *msg = NULL;
				int msg_start = offset;
				offset += get_dalc_custom(tvb, pinfo, offset, &msg);
				if ( msg )
				{
					proto_tree_add_string(oer_tree, hf_tns_data_oer_message, tvb, msg_start, offset - msg_start, msg);
					col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", msg);
				}
			}
			proto_item_set_len(oer_item, offset - oer_start);
			break;
		}

		case SQLNET_IOVEC_4FAST_UPI:
		{
			/* TTI_IOV: the server's I/O vector for an executed anonymous
			 * PL/SQL block that carried bind variables. It lists each
			 * bind's direction (IN / OUT / IN OUT); when any bind is
			 * OUT / IN OUT the returned values follow as a TTI_RXD row.
			 * Layout cross-referenced with python-oracledb's
			 * _process_io_vector, and
			 * verified against XE 11g.
			 *
			 * All the leading counters are stored in the ub4 variable-
			 * length form (see get_sb4_custom). The per-bind directions
			 * are one raw byte each. The trailing RXD values need each
			 * bind's declared type to decode, so we stop after the
			 * direction vector and leave the rest to the data dissector. */
			int num_requests = 0, num_iters = 0, v = 0, bv_len = 0, rid_len = 0;

			if ( !is_request )
			{
				/* flag (ub1, skip) */
				offset += 1;
				offset += get_sb4_custom(tvb, offset, &num_requests);
				offset += get_sb4_custom(tvb, offset, &num_iters);
				int num_binds = num_iters * 256 + num_requests;
				proto_tree_add_uint(data_tree, hf_tns_data_iov_num_binds, tvb, offset, 0, num_binds);
				/* num iters this time (skip) */
				offset += get_sb4_custom(tvb, offset, &v);
				/* uac buffer length (skip) */
				offset += get_sb4_custom(tvb, offset, &v);
				/* fast-fetch bit-vector: length + bytes (skip) */
				offset += get_sb4_custom(tvb, offset, &bv_len);
				if ( bv_len > 0 )
					offset += bv_len;
				/* rowid: length + bytes (skip) */
				offset += get_sb4_custom(tvb, offset, &rid_len);
				if ( rid_len > 0 )
					offset += rid_len;

				/* Per-bind direction bytes, in bind order. Bound by both
				 * the reported count and the bytes actually present so a
				 * malformed vector cannot run away. */
				proto_tree *iov_tree;
				proto_item *iov_item;
				int iov_start = offset;
				iov_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1, ett_tns_iov, &iov_item, "Bind Directions");
				for ( int i = 0; i < num_binds && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
				{
					proto_tree_add_item(iov_tree, hf_tns_data_iov_bind_dir, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
				}
				proto_item_set_len(iov_item, offset - iov_start);
			}
			break;
		}

		case SQLNET_DESCRIBE_INFO:
		{
			/* TTI_DCB: describe (column metadata) for a SELECT result set.
			 * Layout is the Oracle 11g shape. All
			 * counts use the ub4 variable-length form. Only the leading
			 * describe token is decoded here; any RXH/RXD/OER that follow
			 * in the same packet are left to the data dissector. */
			int v = 0, num_cols = 0;

			if ( is_request )
				break;

			/* describe-info preamble (chunked bytes: cursor uuid + date) */
			offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			/* max row size (ub4, skip) */
			offset += get_sb4_custom(tvb, offset, &v);
			/* number of columns */
			int nc_start = offset;
			offset += get_sb4_custom(tvb, offset, &num_cols);
			proto_tree_add_uint(data_tree, hf_tns_data_dcb_num_columns, tvb, nc_start, offset - nc_start, num_cols);
			/* The count comes off the wire and sizes the allocation
			 * below, so a count larger than the data left cannot be
			 * real - report it and decode no columns. */
			if ( num_cols < 0 ||
			     (unsigned)num_cols > tvb_reported_length_remaining(tvb, offset) )
			{
				proto_tree_add_expert(data_tree, pinfo, &ei_tns_data_count_too_large,
					tvb, nc_start, offset - nc_start);
				num_cols = 0;
			}
			if ( num_cols > 0 )
				offset += 1; /* reserved byte */

			/* Remember each column's type so a later TTI_RXD response can
			 * split its row values. Recorded once, on the first pass. */
			uint8_t *col_types = NULL;
			if ( !PINFO_FD_VISITED(pinfo) && num_cols > 0 )
				col_types = (uint8_t *)wmem_alloc_array(wmem_file_scope(), uint8_t, num_cols);
			for ( int i = 0; i < num_cols && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
			{
				if ( col_types )
					col_types[i] = tvb_get_uint8(tvb, offset);
				offset = dissect_tns_dcb_column(tvb, pinfo, data_tree, offset, i + 1);
			}
			if ( col_types )
			{
				tns_conv_info_t *tns_info = tns_get_conv_info(pinfo);
				tns_describe_t *desc = wmem_new0(wmem_file_scope(), tns_describe_t);
				desc->num_cols = num_cols;
				desc->types = col_types;
				tns_info->last_describe = desc;
			}

			/* Trailer: current date (bytes_with_length), four ub4 flags,
			 * and the query-cache key (bytes_with_length) — all skipped. */
			offset += get_field_with_length(tvb, pinfo, offset, NULL);
			for ( int i = 0; i < 4; i++ )
				offset += get_sb4_custom(tvb, offset, &v);
			offset += get_field_with_length(tvb, pinfo, offset, NULL);
			break;
		}

		case SQLNET_ROW_TRANSF_HDR:
		{
			/* TTI_RXH: row transfer header, precedes the row data in a
			 * SELECT response. All numeric fields use the ub4 variable-
			 * length form. Layout cross-referenced with
			 * python-oracledb's _process_row_header. */
			int v = 0, bv_len = 0, start;

			if ( is_request )
				break;

			/* flag (ub1, skip) */
			offset += 1;
			/* number of requests */
			start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_uint(data_tree, hf_tns_data_rxh_num_requests, tvb, start, offset - start, v);
			/* iteration number */
			start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_uint(data_tree, hf_tns_data_rxh_iter_num, tvb, start, offset - start, v);
			/* number of iterations */
			start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_uint(data_tree, hf_tns_data_rxh_num_iters, tvb, start, offset - start, v);
			/* buffer length (ub4, skip) */
			offset += get_sb4_custom(tvb, offset, &v);
			/* bit vector: length + [repeated length byte + vector bytes] */
			offset += get_sb4_custom(tvb, offset, &bv_len);
			if ( bv_len > 0 )
			{
				offset += 1;       /* repeated length byte */
				offset += bv_len;  /* bit vector */
			}
			/* rxhrid (bytes_with_length, skip) */
			offset += get_field_with_length(tvb, pinfo, offset, NULL);
			break;
		}

		case SQLNET_ROW_TRANSF_DATA:
		{
			/* TTI_RXD: row data for a SELECT result set — typically a
			 * TTI_FETCH continuation, where the describe (TTI_DCB) arrived
			 * in an earlier packet. Split each row into columns using the
			 * types remembered from that describe (threaded through
			 * conversation state); ordinary values are shown raw.
			 *
			 * The leading RXD token was already consumed above, so offset
			 * sits on the first row's first value. Differential (bit-vector)
			 * row encoding is not handled — a row that reuses a prior value
			 * would desync, so we only decode when no BVC context applies. */
			tns_describe_t *desc = NULL;

			if ( is_request )
				break;

			if ( !PINFO_FD_VISITED(pinfo) )
			{
				tns_conv_info_t *tns_info = tns_get_conv_info(pinfo);
				desc = tns_info->last_describe;
				if ( desc )
					p_add_proto_data(wmem_file_scope(), pinfo, proto_tns,
						TNS_PROTO_DATA_DESCRIBE, desc);
			}
			else
			{
				desc = (tns_describe_t *)p_get_proto_data(wmem_file_scope(), pinfo,
					proto_tns, TNS_PROTO_DATA_DESCRIBE);
			}

			if ( desc && desc->num_cols > 0 )
			{
				int rownum = 0, first_row = 1, bail = 0;
				while ( tvb_reported_length_remaining(tvb, offset) > 0 && !bail )
				{
					proto_tree *row_tree;
					proto_item *row_item;
					int r_start;

					if ( !first_row )
					{
						if ( tvb_get_uint8(tvb, offset) != SQLNET_ROW_TRANSF_DATA )
							break;
						offset += 1; /* RXD token for subsequent rows */
					}
					first_row = 0;

					r_start = offset;
					row_tree = proto_tree_add_subtree_format(data_tree, tvb, offset, -1,
						ett_tns_rxd_row, &row_item, "Row %d", ++rownum);
					for ( uint32_t c = 0; c < desc->num_cols
						&& tvb_reported_length_remaining(tvb, offset) > 0 && !bail; c++ )
						offset = dissect_tns_rxd_value(tvb, pinfo, row_tree, offset,
							desc->types[c], c + 1, &bail);
					proto_item_set_len(row_item, offset - r_start);
				}
			}
			break;
		}

		case SQLNET_USER_OCI_FUNC:
		{
			guint32 oci_id = 0;
			proto_tree_add_item_ret_uint(data_tree, hf_tns_data_oci_id, tvb, offset, 1, ENC_BIG_ENDIAN, &oci_id);
			offset += 1;
			/* Name the specific OCI call in the Info column — otherwise every
			 * function call reads only as the generic "User OCI Functions". */
			col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
				val_to_str_ext_const(oci_id, &tns_data_oci_subfuncs_ext, "unknown"));
			proto_tree_add_item(data_tree, hf_tns_data_tseq, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			if((oci_id == 115) || (oci_id == 118)){
				proto_tree_add_item(data_tree, hf_tns_data_unused, tvb, offset, 1, ENC_NA);
				offset += 1;
				int user_len = 0;
				offset += get_sb4_custom(tvb, offset, &user_len);
			}
			else if ( oci_id == TTI_FETCH )
			{
				/* TTI_FETCH: fetch more rows from an open cursor.
				 * [TTI_FUN, TTI_FETCH, seq] then cursor id and the row
				 * count, both ub4. */
				int v = 0, start;

				start = offset;
				offset += get_sb4_custom(tvb, offset, &v);
				proto_tree_add_uint(data_tree, hf_tns_cursor, tvb, start, offset - start, v);
				start = offset;
				offset += get_sb4_custom(tvb, offset, &v);
				proto_tree_add_uint(data_tree, hf_tns_data_fetch_rows, tvb, start, offset - start, v);
			}
			else if ( oci_id == TTI_ALL8 )
			{
				/* TTI_ALL8: the generic SQL execute — SELECT, DML and
				 * PL/SQL all ride this call. Layout is the Oracle 11g
				 * shape. All multi-byte integers use the ub4
				 * variable-length form.
				 *
				 * The bind descriptors (OAC) and bind values (RXD) that can
				 * trail the al8 array need per-bind type context to decode
				 * safely, so we stop after the al8 array and leave them to
				 * the data dissector. */
				int v = 0, options = 0, cursor = 0, query_len = 0, all8_len = 0;
				int fetch = 0, bind_count = 0, start;
				uint8_t query_flag;

				/* options (ub4) + flag breakdown */
				start = offset;
				offset += get_sb4_custom(tvb, offset, &options);
				proto_tree_add_bitmask_value(data_tree, tvb, start, hf_tns_data_all8_options,
					ett_tns_all8_options, tns_all8_options, (uint64_t)(uint32_t)options);
				/* cursor id (ub4) */
				start = offset;
				offset += get_sb4_custom(tvb, offset, &cursor);
				proto_tree_add_uint(data_tree, hf_tns_cursor, tvb, start, offset - start, cursor);
				/* query present flag (ub1) */
				query_flag = tvb_get_uint8(tvb, offset);
				offset += 1;
				/* query length (ub4) */
				offset += get_sb4_custom(tvb, offset, &query_len);
				/* all8 present flag (ub1) */
				offset += 1;
				/* all8 length (ub4) */
				offset += get_sb4_custom(tvb, offset, &all8_len);
				/* two reserved bytes */
				offset += 2;
				/* long max value (ub4, skip) */
				offset += get_sb4_custom(tvb, offset, &v);
				/* fetch rows (ub4) */
				start = offset;
				offset += get_sb4_custom(tvb, offset, &fetch);
				proto_tree_add_uint(data_tree, hf_tns_data_all8_fetch_rows, tvb, start, offset - start, fetch);
				/* max value (ub4, skip) */
				offset += get_sb4_custom(tvb, offset, &v);
				/* bind indicator (ub1) */
				offset += 1;
				/* bind count (ub4) */
				start = offset;
				offset += get_sb4_custom(tvb, offset, &bind_count);
				proto_tree_add_uint(data_tree, hf_tns_data_all8_bind_count, tvb, start, offset - start, bind_count);
				/* The count comes off the wire and sizes an allocation
				 * further down, so a count larger than the data left
				 * cannot be real - report it and decode no binds. */
				if ( bind_count < 0 ||
				     (unsigned)bind_count > tvb_reported_length_remaining(tvb, offset) )
				{
					proto_tree_add_expert(data_tree, pinfo, &ei_tns_data_count_too_large,
						tvb, start, offset - start);
					bind_count = 0;
				}
				/* five reserved bytes */
				offset += 5;
				/* define-columns present flag (ub1) */
				offset += 1;
				/* define-columns count (ub4, skip) */
				offset += get_sb4_custom(tvb, offset, &v);
				/* [0,0,1] marker (3 bytes) + server version slot (5 bytes) */
				offset += 8;
				/* SQL text — a flat run of query_len bytes on 11g */
				if ( query_flag && query_len > 0 )
				{
					const uint8_t *sql;
					proto_tree_add_item_ret_string(data_tree, hf_tns_data_all8_sql, tvb,
						offset, query_len, ENC_UTF_8|ENC_NA, pinfo->pool, &sql);
					col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", sql);
					offset += query_len;
				}
				/* al8i4 option array: all8_len ub4 elements (skip) */
				for ( int i = 0; i < all8_len && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
					offset += get_sb4_custom(tvb, offset, &v);

				/* Bind section: on a fresh parse with binds, one bare OAC
				 * descriptor per bind column, then one TTI_RXD row of values
				 * per iteration. A cached re-execute (no query text) omits
				 * the OACs — detecting that needs connection state, so we
				 * only decode binds when the query was present. */
				if ( bind_count > 0 && query_flag )
				{
					proto_tree *binds_tree, *bind_tree, *row_tree;
					proto_item *binds_item, *bind_item, *row_item;
					int binds_start = offset, has_lob = 0, rownum = 0;
					uint8_t *btypes;

					btypes = (uint8_t *)wmem_alloc_array(pinfo->pool, uint8_t, bind_count);
					binds_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1,
						ett_tns_binds, &binds_item, "Binds");

					for ( int i = 0; i < bind_count && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
					{
						int b_start = offset;
						uint8_t btype = tvb_get_uint8(tvb, offset);
						btypes[i] = btype;
						/* CLOB (112) / BLOB (113) binds use a temp-LOB
						 * locator value form we do not unpack. */
						if ( btype == 112 || btype == 113 )
							has_lob = 1;
						bind_tree = proto_tree_add_subtree_format(binds_tree, tvb, offset, -1,
							ett_tns_bind, &bind_item, "Bind %d: %s", i + 1,
							val_to_str_const(btype, tns_data_types, "unknown"));
						offset = dissect_tns_oac(tvb, pinfo, bind_tree, offset);
						/* A CLOB/BLOB bind OAC carries a trailing oaccolid byte. */
						if ( btype == 112 || btype == 113 )
							offset += 1;
						proto_item_set_len(bind_item, offset - b_start);
					}

					/* Value rows: a TTI_RXD token then one DALC value per bind
					 * column (an ordinary execute sends one row, executemany
					 * sends N). Values are type-encoded and shown raw. */
					while ( !has_lob && tvb_reported_length_remaining(tvb, offset) > 0
						&& tvb_get_uint8(tvb, offset) == SQLNET_ROW_TRANSF_DATA )
					{
						int r_start = offset;
						offset += 1; /* TTI_RXD token */
						row_tree = proto_tree_add_subtree_format(binds_tree, tvb, offset, -1,
							ett_tns_bind_row, &row_item, "Row %d", ++rownum);
						for ( int i = 0; i < bind_count && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
						{
							uint8_t first = tvb_get_uint8(tvb, offset);
							int val_start = offset;
							offset += get_dalc_custom(tvb, pinfo, offset, NULL);
							if ( first == 0 )
								proto_tree_add_bytes_format_value(row_tree, hf_tns_data_bind_value,
									tvb, val_start, offset - val_start, NULL, "NULL");
							else if ( first == 254 )
								proto_tree_add_item(row_tree, hf_tns_data_bind_value,
									tvb, val_start, offset - val_start, ENC_NA);
							else
								proto_tree_add_item(row_tree, hf_tns_data_bind_value,
									tvb, val_start + 1, first, ENC_NA);
						}
						proto_item_set_len(row_item, offset - r_start);
					}
					proto_item_set_len(binds_item, offset - binds_start);
				}
			}
			else if ( oci_id == TTI_LOBOPS )
			{
				/* TTI_LOBOPS: the LOB operation family (read, write, get
				 * length, create/free temp, open/close, BFILE ops). One
				 * common request layout selects behaviour by the operation
				 * opcode. All multi-byte integers use
				 * the ub4 variable-length form.
				 *
				 * We decode the common header through the source offset and
				 * show the opcode; the locator framing and trailing amount /
				 * write payload vary by opcode and locator variant, so they
				 * are left to the data dissector. */
				int v = 0, op = 0, start;

				/* CREATE_TEMP carries a fixed field block (01 01 28 ...) with
				 * no source locator instead of the common header. */
				if ( tvb_bytes_exist(tvb, offset, 3)
					&& tvb_get_uint24(tvb, offset, ENC_BIG_ENDIAN) == 0x010128 )
				{
					proto_tree_add_uint(data_tree, hf_tns_data_lob_op, tvb, offset, 3, 0x00110);
				}
				else
				{
					offset += 1;                              /* source pointer flag */
					offset += get_sb4_custom(tvb, offset, &v); /* source locator length */
					offset += 1;                              /* dest pointer flag */
					offset += get_sb4_custom(tvb, offset, &v); /* dest length */
					offset += get_sb4_custom(tvb, offset, &v); /* short source offset */
					offset += get_sb4_custom(tvb, offset, &v); /* short dest offset */
					offset += 3;                              /* charset / amount / null-lob flags */
					/* operation opcode */
					start = offset;
					offset += get_sb4_custom(tvb, offset, &op);
					proto_tree_add_uint(data_tree, hf_tns_data_lob_op, tvb, start, offset - start, op);
					col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]",
						val_to_str_const(op, tns_lob_ops, "unknown"));
					/* scn-array pointer flag + length */
					offset += 2;
					/* source offset (ub8, 1-based into the LOB) */
					start = offset;
					offset += get_sb4_custom(tvb, offset, &v);
					proto_tree_add_uint(data_tree, hf_tns_data_lob_offset, tvb, start, offset - start, v);
				}
			}
			break;
		}
		case SQLNET_RETURN_OPI_PARAM:
		{
			uint8_t skip = 0, opi = 0;

			if ( tvb_bytes_exist(tvb, offset, 11) )
			{
				/*
				 * OPI_VERSION2 response has a following pattern:
				 *
				 *                _ banner      _ vsnum
				 *               /             /
				 *    ..(.?)(Orac[le.+])(.?)(....).+$
				 *     |
				 *     \ banner length (if equal to 0 then next byte indicates the length).
				 *
				 * These differences (to skip 1 or 2 bytes) due to differences in the drivers.
				 */
				                                  /* Orac[le.+] */
				if ( tvb_get_ntohl(tvb, offset+2) == 0x4f726163 )
				{
					opi = OPI_VERSION2;
					skip = 1;
				}

				else if ( tvb_get_ntohl(tvb, offset+3) == 0x4f726163 )
				{
					opi = OPI_VERSION2;
					skip = 2;
				}

				/*
				 * OPI_OSESSKEY response has a following pattern:
				 *
				 *               _ pattern (v1|v2)
				 *              /        _ params
				 *             /        /
				 *    (....)(........)(.+).+$
				 *       ||
				 *        \ if these two bytes are equal to 0x0c00 then first byte is <Param Counts> (v1),
				 *          else next byte indicate it (v2).
				 */
				                                          /*  ....AUTH (v1) */
				else if ( tvb_get_ntoh64(tvb, offset+3) == 0x0000000c41555448 )
				{
					opi = OPI_OSESSKEY;
					skip = 1;
				}
				                                          /*  ..AUTH_V (v2) */
				else if ( tvb_get_ntoh64(tvb, offset+3) == 0x0c0c415554485f53 )
				{
					opi = OPI_OSESSKEY;
					skip = 2;
				}

				/*
				 * OPI_OAUTH response has a following pattern:
				 *
				 *               _ pattern (v1|v2)
				 *              /        _ params
				 *             /        /
				 *    (....)(........)(.+).+$
				 *       ||
				 *        \ if these two bytes are equal to 0x1300 then first byte is <Param Counts> (v1),
				 *          else next byte indicate it (v2).
				 */

				                                          /*  ....AUTH (v1) */
				else if ( tvb_get_ntoh64(tvb, offset+3) == 0x0000001341555448 )
				{
					opi = OPI_OAUTH;
					skip = 1;
				}
			                                                  /*  ..AUTH_V (v2) */
				else if ( tvb_get_ntoh64(tvb, offset+3) == 0x1313415554485f56 )
				{
					opi = OPI_OAUTH;
					skip = 2;
				}
			}

			if ( opi == OPI_VERSION2 )
			{
				proto_tree_add_item(data_tree, hf_tns_data_unused, tvb, offset, skip, ENC_NA);
				offset += skip;

				uint8_t len = tvb_get_uint8(tvb, offset);

				proto_tree_add_item(data_tree, hf_tns_data_opi_version2_banner_len, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;

				proto_tree_add_item(data_tree, hf_tns_data_opi_version2_banner, tvb, offset, len, ENC_ASCII);
				offset += len + (skip == 1 ? 1 : 0);

				proto_tree_add_item(data_tree, hf_tns_data_opi_version2_vsnum, tvb, offset, 4, (skip == 1) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN);
				offset += 4;
			}
			else if ( opi == OPI_OSESSKEY || opi == OPI_OAUTH )
			{
				proto_tree *params_tree;
				proto_item *params_ti;
				unsigned par, params;

				if ( skip == 1 )
				{
					proto_tree_add_item_ret_uint(data_tree, hf_tns_data_opi_num_of_params, tvb, offset, 1, ENC_NA, &params);
					offset += 1;

					proto_tree_add_item(data_tree, hf_tns_data_unused, tvb, offset, 5, ENC_NA);
					offset += 5;
				}
				else
				{
					proto_tree_add_item(data_tree, hf_tns_data_unused, tvb, offset, 1, ENC_NA);
					offset += 1;

					proto_tree_add_item_ret_uint(data_tree, hf_tns_data_opi_num_of_params, tvb, offset, 1, ENC_NA, &params);
					offset += 1;

					proto_tree_add_item(data_tree, hf_tns_data_unused, tvb, offset, 2, ENC_NA);
					offset += 2;
				}

				params_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1, ett_tns_opi_params, &params_ti, "Parameters");

				for ( par = 1; par <= params; par++ )
				{
					proto_tree *par_tree;
					proto_item *par_ti;
					unsigned len, offset_prev;

					par_tree = proto_tree_add_subtree(params_tree, tvb, offset, -1, ett_tns_opi_par, &par_ti, "Parameter");
					proto_item_append_text(par_ti, " %u", par);

					/* Name length */
					proto_tree_add_item_ret_uint(par_tree, hf_tns_data_opi_param_length, tvb, offset, 1, ENC_NA, &len);
					offset += 1;

					/* Name */
					if ( !(len == 0 || len == 2) ) /* Not empty (2 - SQLDeveloper specific sign). */
					{
						proto_tree_add_item(par_tree, hf_tns_data_opi_param_name, tvb, offset, len, ENC_ASCII);
						offset += len;
					}

					/* Value can be NULL. So, save offset to calculate unused data. */
					offset_prev = offset;
					offset += skip == 1 ? 4 : 2;

					/* Value length */
					if ( opi == OPI_OSESSKEY )
					{
						len = get_strtype_custom(tvb, pinfo, par_tree, offset);
					}
					else /* OPI_OAUTH */
					{
						len = tvb_get_uint8(tvb, offset_prev) == 0 ? 0 : get_strtype_custom(tvb, pinfo, par_tree, offset);
					}

					/*
					 * Value
					 *   OPI_OSESSKEY: AUTH_VFR_DATA with length 0, 9, 0x39 comes without data.
					 *   OPI_OAUTH: AUTH_VFR_DATA with length 0, 0x39 comes without data.
					 */
					if ( ((opi == OPI_OSESSKEY) && !(len == 0 || len == 9 || len == 0x39))
					  || ((opi == OPI_OAUTH) && !(len == 0 || len == 0x39)) )
					{
						proto_tree_add_item(par_tree, hf_tns_data_unused, tvb, offset_prev, offset - offset_prev, ENC_NA);
						offset += len;

						offset_prev = offset; /* Save offset to calculate rest of unused data */
					}
					else
					{
						offset += 1;
					}

					if ( opi == OPI_OSESSKEY )
					{
						/* SQL Developer specific fix */
						offset += tvb_get_uint8(tvb, offset) == 2 ? 5 : 3;
					}
					else /* OPI_OAUTH */
					{
						offset += len == 0 ? 1 : 3;
					}

					if ( skip == 1 )
					{
						offset += 1 + ((len == 0 || len == 0x39) ? 3 : 4);

						if ( opi == OPI_OAUTH )
						{
							offset += len == 0 ? 2 : 0;
						}
					}

					proto_tree_add_item(par_tree, hf_tns_data_unused, tvb, offset_prev, offset - offset_prev, ENC_NA);
					proto_item_set_end(par_ti, tvb, offset);
				}
				proto_item_set_end(params_ti, tvb, offset);
			}
			break;
		}

		case SQLNET_PIGGYBACK_FUNC:
		{
			int cursors_len = 0;
			int cursors_start;
			proto_tree_add_item(data_tree, hf_tns_data_piggyback_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(data_tree, hf_tns_data_tseq, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			cursors_start = offset;
			offset += get_sb4_custom(tvb, offset, &cursors_len);
			/* The count comes off the wire and every cursor takes at
			 * least one byte, so a count larger than the data left
			 * cannot be real. Say so and stop, rather than looping on
			 * a number somebody else chose. */
			if ( cursors_len < 0 ||
			     (unsigned)cursors_len > tvb_reported_length_remaining(tvb, offset) )
			{
				proto_tree_add_expert(data_tree, pinfo, &ei_tns_data_piggyback_cursors,
					tvb, cursors_start, offset - cursors_start);
				break;
			}
			for(int i = 0; i < cursors_len; i++) {
				int cursor = 0;
				int new_offset = get_sb4_custom(tvb, offset, &cursor);
				proto_tree_add_uint(data_tree, hf_tns_cursor, tvb, offset, new_offset - offset, cursor);
				offset = new_offset;
			}
			break;
		}
		case SQLNET_SNS:
		{
			proto_tree_add_item(data_tree, hf_tns_data_id, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(data_tree, hf_tns_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			if ( is_request )
			{
				proto_tree_add_item(data_tree, hf_tns_data_sns_cli_vers, tvb, offset, 4, ENC_BIG_ENDIAN);
			}
			else
			{
				proto_tree_add_item(data_tree, hf_tns_data_sns_srv_vers, tvb, offset, 4, ENC_BIG_ENDIAN);
			}
			offset += 4;

			proto_tree_add_item(data_tree, hf_tns_data_sns_srvcnt, tvb, offset, 2, ENC_BIG_ENDIAN);

			/* move back, to include data_id into data_dissector */
			offset -= 10;
			break;
		}
	}

	call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, data_tree);
}

static void dissect_tns_connect(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	proto_tree *connect_tree;
	uint32_t cd_offset, cd_len;
	int tns_offset = offset-8;
	static int * const flags[] = {
		&hf_tns_ntp_flag_hangon,
		&hf_tns_ntp_flag_crel,
		&hf_tns_ntp_flag_tduio,
		&hf_tns_ntp_flag_srun,
		&hf_tns_ntp_flag_dtest,
		&hf_tns_ntp_flag_cbio,
		&hf_tns_ntp_flag_asio,
		&hf_tns_ntp_flag_pio,
		&hf_tns_ntp_flag_grant,
		&hf_tns_ntp_flag_handoff,
		&hf_tns_ntp_flag_sigio,
		&hf_tns_ntp_flag_sigpipe,
		&hf_tns_ntp_flag_sigurg,
		&hf_tns_ntp_flag_urgentio,
		&hf_tns_ntp_flag_fdio,
		&hf_tns_ntp_flag_testop,
		NULL
	};

	connect_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		ett_tns_connect, NULL, "Connect");

	proto_tree_add_item(connect_tree, hf_tns_version, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_compat_version, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(connect_tree, tvb, offset, hf_tns_service_options, ett_tns_sopt_flag, tns_service_options, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_sdu_size, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_max_tdu_size, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(connect_tree, tvb, offset, hf_tns_nt_proto_characteristics, ett_tns_ntp_flag, flags, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_line_turnaround, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_value_of_one, tvb,
			offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item_ret_uint(connect_tree, hf_tns_connect_data_length, tvb,
			offset, 2, ENC_BIG_ENDIAN, &cd_len);
	offset += 2;

	proto_tree_add_item_ret_uint(connect_tree, hf_tns_connect_data_offset, tvb,
			offset, 2, ENC_BIG_ENDIAN, &cd_offset);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_connect_data_max, tvb,
			offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_bitmask(connect_tree, tvb, offset, hf_tns_connect_flags0, ett_tns_conn_flag, tns_connect_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(connect_tree, tvb, offset, hf_tns_connect_flags1, ett_tns_conn_flag, tns_connect_flags, ENC_BIG_ENDIAN);
	offset += 1;

	/*
	 * XXX - sometimes it appears that this stuff isn't present
	 * in the packet.
	 */
	if ((uint32_t)(offset + 16) <= tns_offset+cd_offset)
	{
		proto_tree_add_item(connect_tree, hf_tns_trace_cf1, tvb,
				offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(connect_tree, hf_tns_trace_cf2, tvb,
				offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(connect_tree, hf_tns_trace_cid, tvb,
				offset, 8, ENC_BIG_ENDIAN);
		/* offset += 8;*/
	}

	if ( cd_len > 0)
	{
		/* Long Connect Data (> 221 bytes?) is not in the Connect PDU
		 * but sent in an immediately following Data PDU.
		 */
		if (tvb_reported_length_remaining(tvb, tns_offset + cd_offset)) {
			proto_tree_add_item(connect_tree, hf_tns_connect_data, tvb,
				tns_offset+cd_offset, -1, ENC_ASCII);
		} else {
			proto_tree_add_expert(connect_tree, pinfo, &ei_tns_connect_data_next_packet, tvb, 0, 0);
			if (!PINFO_FD_VISITED(pinfo)) {
				tns_conv_info_t *tns_info = tns_get_conv_info(pinfo);
				tns_info->pending_connect_data = cd_len;
			}
		}
	}
}

static void dissect_tns_accept(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	proto_tree *accept_tree;
	uint32_t accept_offset, accept_len;
	int tns_offset = offset-8;

	accept_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_accept, NULL, "Accept");

	proto_tree_add_item(accept_tree, hf_tns_version, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(accept_tree, tvb, offset, hf_tns_service_options, ett_tns_sopt_flag, tns_service_options, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(accept_tree, hf_tns_sdu_size, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(accept_tree, hf_tns_max_tdu_size, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(accept_tree, hf_tns_value_of_one, tvb,
			offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item_ret_uint(accept_tree, hf_tns_accept_data_length, tvb,
			offset, 2, ENC_BIG_ENDIAN, &accept_len);
	offset += 2;

	proto_tree_add_item_ret_uint(accept_tree, hf_tns_accept_data_offset, tvb,
			offset, 2, ENC_BIG_ENDIAN, &accept_offset);
	offset += 2;

	proto_tree_add_bitmask(accept_tree, tvb, offset, hf_tns_connect_flags0, ett_tns_conn_flag, tns_connect_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(accept_tree, tvb, offset, hf_tns_connect_flags1, ett_tns_conn_flag, tns_connect_flags, ENC_BIG_ENDIAN);
	/* offset += 1; */

	if ( accept_len > 0)
	{
		proto_tree_add_item(accept_tree, hf_tns_accept_data, tvb,
			tns_offset+accept_offset, -1, ENC_ASCII);
	}
	return;
}


static void dissect_tns_refuse(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	/* TODO
	 * According to some reverse engineers, the refuse packet is also sent when the login fails.
	 * Byte 54 shows if this is due to invalid ID (0x02) or password (0x03).
	 * At now we do not have pcaps with such messages to check this statement.
	 */
	proto_tree *refuse_tree;

	refuse_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_refuse, NULL, "Refuse");

	proto_tree_add_item(refuse_tree, hf_tns_refuse_reason_user, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(refuse_tree, hf_tns_refuse_reason_system, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(refuse_tree, hf_tns_refuse_data_length, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(refuse_tree, hf_tns_refuse_data, tvb,
			offset, -1, ENC_ASCII);
}


static void dissect_tns_abort(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	proto_tree *abort_tree;

	abort_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_abort, NULL, "Abort");

	proto_tree_add_item(abort_tree, hf_tns_abort_reason_user, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(abort_tree, hf_tns_abort_reason_system, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(abort_tree, hf_tns_abort_data, tvb,
			offset, -1, ENC_ASCII);
}


static void dissect_tns_marker(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tns_tree, int is_attention)
{
	proto_tree *marker_tree;

	marker_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_marker, NULL, is_attention ? "Attention" : "Marker");

	proto_tree_add_item(marker_tree, hf_tns_marker_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(marker_tree, hf_tns_marker_data_byte, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* The last byte selects break vs reset for a data marker. */
	if ( tvb_reported_length_remaining(tvb, offset) > 0 )
	{
		uint32_t func = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(marker_tree, hf_tns_marker_function, tvb,
				offset, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				val_to_str_const(func, tns_marker_functions, "Unknown"));
	}
}

static void dissect_tns_redirect(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	proto_tree *redirect_tree;

	redirect_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_redirect, NULL, "Redirect");

	proto_tree_add_item(redirect_tree, hf_tns_redirect_data_length, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(redirect_tree, hf_tns_redirect_data, tvb,
			offset, -1, ENC_ASCII);
}

static void dissect_tns_control(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	proto_tree *control_tree;

	control_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_control, NULL, "Control");

	proto_tree_add_item(control_tree, hf_tns_control_cmd, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(control_tree, hf_tns_control_data, tvb,
			offset, -1, ENC_NA);
}

static unsigned
get_tns_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	/*
	 * Get the 16-bit length of the TNS message, including header
	 */
	unsigned length = tvb_get_ntohs(tvb, offset);
	offset += 4;
	uint8_t type = tvb_get_uint8(tvb, offset);
	/* Type 0xf (data descriptor, LOB/FILE data) has data which follows
	 * immediately (no new PDU header) but is not counted in the PDU
	 * length field either.
	 */
	if (type == TNS_TYPE_DD) {
		offset += 8;
		if (!tvb_bytes_exist(tvb, offset, 4)) {
			/* return 0 makes tcp_dissect_pdus() report
			 * DESEGMENT_ONE_MORE_SEGMENT to the TCP dissector.
			 */
			return 0;
		}
		unsigned dd_len = tvb_get_ntohl(tvb, offset);
		return length + dd_len;
	}
	return length;
}

static unsigned
get_tns_pdu_len_nochksum(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	/*
	 * Get the 32-bit length of the TNS message, including header
	 */
	unsigned length = tvb_get_ntohl(tvb, offset);
	offset += 4;
	uint8_t type = tvb_get_uint8(tvb, offset);
	/* Type 0xf (data descriptor, LOB/FILE data) has data which follows
	 * immediately (no new PDU header) but is not counted in the PDU
	 * length field either.
	 */
	if (type == TNS_TYPE_DD) {
		offset += 8;
		if (!tvb_bytes_exist(tvb, offset, 4)) {
			/* return 0 makes tcp_dissect_pdus() report
			 * DESEGMENT_ONE_MORE_SEGMENT to the TCP dissector.
			 */
			return 0;
		}
		unsigned dd_len = tvb_get_ntohl(tvb, offset);
		return length + dd_len;
	}

	return length;
}

static int
dissect_tns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	uint32_t length;
	uint16_t chksum;
	uint8_t type;

	/*
	 * First, do a sanity check to make sure what we have
	 * starts with a TNS PDU.
	 */
	if (tvb_bytes_exist(tvb, 4, 1)) {
		/*
		 * Well, we have the packet type; let's make sure
		 * it's a known type.
		 */
		type = tvb_get_uint8(tvb, 4);
		if (type < TNS_TYPE_CONNECT || type > TNS_TYPE_MAX)
			return 0;	/* it's not a known type */
	}

	/*
	 * In some messages (observed in Oracle12c) packet length has 4 bytes
	 * instead of 2.
	 *
	 * If packet length has 2 bytes, length and checksum equals two unsigned
	 * 16-bit numbers. Packet checksum is generally unused (equal zero),
	 * but 10g client may set 2nd byte to 4.
	 *
	 * Else, Oracle 12c combine these two 16-bit numbers into one 32-bit.
	 * This number represents the packet length. Checksum is omitted.
	 */
	chksum = tvb_get_ntohs(tvb, 2);

	length = (chksum == 0 || chksum == 4) ? 2 : 4;

	tcp_dissect_pdus(tvb, pinfo, tree, tns_desegment, TNS_HDR_LEN,
			(length == 2 ? get_tns_pdu_len : get_tns_pdu_len_nochksum),
			dissect_tns_pdu, data);

	return tvb_captured_length(tvb);
}

static int
dissect_tns_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *tns_tree, *ti;
	proto_item *hidden_item;
	unsigned offset = 0;
	uint32_t length;
	uint16_t chksum;
	uint8_t type;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TNS");

	col_set_str(pinfo->cinfo, COL_INFO,
			(pinfo->match_uint == pinfo->destport) ? "Request" : "Response");

	ti = proto_tree_add_item(tree, proto_tns, tvb, 0, -1, ENC_NA);
	tns_tree = proto_item_add_subtree(ti, ett_tns);

	if (pinfo->match_uint == pinfo->destport)
	{
		hidden_item = proto_tree_add_boolean(tns_tree, hf_tns_request,
					tvb, offset, 0, true);
	}
	else
	{
		hidden_item = proto_tree_add_boolean(tns_tree, hf_tns_response,
					tvb, offset, 0, true);
	}
	proto_item_set_hidden(hidden_item);

	chksum = tvb_get_ntohs(tvb, offset+2);
	if (chksum == 0 || chksum == 4)
	{
		proto_tree_add_item_ret_uint(tns_tree, hf_tns_length, tvb, offset,
					2, ENC_BIG_ENDIAN, &length);
		offset += 2;
		proto_tree_add_checksum(tns_tree, tvb, offset, hf_tns_packet_checksum,
					-1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
		offset += 2;
	}
	else
	{
		/* Oracle 12c uses checksum bytes as part of the packet length. */
		proto_tree_add_item_ret_uint(tns_tree, hf_tns_length, tvb, offset,
					4, ENC_BIG_ENDIAN, &length);
		offset += 4;
	}

	type = tvb_get_uint8(tvb, offset);
	proto_tree_add_uint(tns_tree, hf_tns_packet_type, tvb,
			offset, 1, type);
	offset += 1;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s (%u)",
			val_to_str_const(type, tns_type_vals, "Unknown"), type);

	proto_tree_add_item(tns_tree, hf_tns_reserved_byte, tvb,
			offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_checksum(tns_tree, tvb, offset, hf_tns_header_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
	offset += 2;

	switch (type)
	{
		case TNS_TYPE_CONNECT:
			dissect_tns_connect(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_ACCEPT:
			dissect_tns_accept(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_REFUSE:
			dissect_tns_refuse(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_REDIRECT:
			dissect_tns_redirect(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_ABORT:
			dissect_tns_abort(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_MARKER:
			dissect_tns_marker(tvb,offset,pinfo,tns_tree, 0);
			break;
		case TNS_TYPE_ATTENTION:
			dissect_tns_marker(tvb,offset,pinfo,tns_tree, 1);
			break;
		case TNS_TYPE_CONTROL:
			dissect_tns_control(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_DATA:
			dissect_tns_data(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_DD:
			dissect_tns_data_descriptor(tvb,offset,pinfo,tns_tree, length);
			break;
		default:
			call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo,
			    tns_tree);
			break;
	}

	return tvb_captured_length(tvb);
}

void proto_register_tns(void)
{
	static hf_register_info hf[] = {
		{ &hf_tns_response, {
			"Response", "tns.response", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "true if TNS response", HFILL }},
		{ &hf_tns_request, {
			"Request", "tns.request", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "true if TNS request", HFILL }},
		{ &hf_tns_length, {
			"Packet Length", "tns.length", FT_UINT32, BASE_DEC,
			NULL, 0x0, "Length of TNS packet", HFILL }},
		{ &hf_tns_packet_checksum, {
			"Packet Checksum", "tns.packet_checksum", FT_UINT16, BASE_HEX,
			NULL, 0x0, "Checksum of Packet Data", HFILL }},
		{ &hf_tns_header_checksum, {
			"Header Checksum", "tns.header_checksum", FT_UINT16, BASE_HEX,
			NULL, 0x0, "Checksum of Header Data", HFILL }},

		{ &hf_tns_version, {
			"Version", "tns.version", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_compat_version, {
			"Version (Compatible)", "tns.compat_version", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_service_options, {
			"Service Options", "tns.service_options", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_sopt_flag_bconn, {
			"Broken Connect Notify", "tns.so_flag.bconn", FT_BOOLEAN, 16,
			NULL, 0x2000, NULL, HFILL }},
		{ &hf_tns_sopt_flag_pc, {
			"Packet Checksum", "tns.so_flag.pc", FT_BOOLEAN, 16,
			NULL, 0x1000, NULL, HFILL }},
		{ &hf_tns_sopt_flag_hc, {
			"Header Checksum", "tns.so_flag.hc", FT_BOOLEAN, 16,
			NULL, 0x0800, NULL, HFILL }},
		{ &hf_tns_sopt_flag_fd, {
			"Full Duplex", "tns.so_flag.fd", FT_BOOLEAN, 16,
			NULL, 0x0400, NULL, HFILL }},
		{ &hf_tns_sopt_flag_hd, {
			"Half Duplex", "tns.so_flag.hd", FT_BOOLEAN, 16,
			NULL, 0x0200, NULL, HFILL }},
		{ &hf_tns_sopt_flag_dc1, {
			"Don't Care", "tns.so_flag.dc1", FT_BOOLEAN, 16,
			NULL, 0x0100, NULL, HFILL }},
		{ &hf_tns_sopt_flag_dc2, {
			"Don't Care", "tns.so_flag.dc2", FT_BOOLEAN, 16,
			NULL, 0x0080, NULL, HFILL }},
		{ &hf_tns_sopt_flag_dio, {
			"Direct IO to Transport", "tns.so_flag.dio", FT_BOOLEAN, 16,
			NULL, 0x0010, NULL, HFILL }},
		{ &hf_tns_sopt_flag_ap, {
			"Attention Processing", "tns.so_flag.ap", FT_BOOLEAN, 16,
			NULL, 0x0008, NULL, HFILL }},
		{ &hf_tns_sopt_flag_ra, {
			"Can Receive Attention", "tns.so_flag.ra", FT_BOOLEAN, 16,
			NULL, 0x0004, NULL, HFILL }},
		{ &hf_tns_sopt_flag_sa, {
			"Can Send Attention", "tns.so_flag.sa", FT_BOOLEAN, 16,
			NULL, 0x0002, NULL, HFILL }},


		{ &hf_tns_sdu_size, {
			"Session Data Unit Size", "tns.sdu_size", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_max_tdu_size, {
			"Maximum Transmission Data Unit Size", "tns.max_tdu_size", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_nt_proto_characteristics, {
			"NT Protocol Characteristics", "tns.nt_proto_characteristics", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_ntp_flag_hangon, {
			"Hangon to listener connect", "tns.ntp_flag.hangon", FT_BOOLEAN, 16,
			NULL, 0x8000, NULL, HFILL }},
		{ &hf_tns_ntp_flag_crel, {
			"Confirmed release", "tns.ntp_flag.crel", FT_BOOLEAN, 16,
			NULL, 0x4000, NULL, HFILL }},
		{ &hf_tns_ntp_flag_tduio, {
			"TDU based IO", "tns.ntp_flag.tduio", FT_BOOLEAN, 16,
			NULL, 0x2000, NULL, HFILL }},
		{ &hf_tns_ntp_flag_srun, {
			"Spawner running", "tns.ntp_flag.srun", FT_BOOLEAN, 16,
			NULL, 0x1000, NULL, HFILL }},
		{ &hf_tns_ntp_flag_dtest, {
			"Data test", "tns.ntp_flag.dtest", FT_BOOLEAN, 16,
			NULL, 0x0800, NULL, HFILL }},
		{ &hf_tns_ntp_flag_cbio, {
			"Callback IO supported", "tns.ntp_flag.cbio", FT_BOOLEAN, 16,
			NULL, 0x0400, NULL, HFILL }},
		{ &hf_tns_ntp_flag_asio, {
			"ASync IO Supported", "tns.ntp_flag.asio", FT_BOOLEAN, 16,
			NULL, 0x0200, NULL, HFILL }},
		{ &hf_tns_ntp_flag_pio, {
			"Packet oriented IO", "tns.ntp_flag.pio", FT_BOOLEAN, 16,
			NULL, 0x0100, NULL, HFILL }},
		{ &hf_tns_ntp_flag_grant, {
			"Can grant connection to another", "tns.ntp_flag.grant", FT_BOOLEAN, 16,
			NULL, 0x0080, NULL, HFILL }},
		{ &hf_tns_ntp_flag_handoff, {
			"Can handoff connection to another", "tns.ntp_flag.handoff", FT_BOOLEAN, 16,
			NULL, 0x0040, NULL, HFILL }},
		{ &hf_tns_ntp_flag_sigio, {
			"Generate SIGIO signal", "tns.ntp_flag.sigio", FT_BOOLEAN, 16,
			NULL, 0x0020, NULL, HFILL }},
		{ &hf_tns_ntp_flag_sigpipe, {
			"Generate SIGPIPE signal", "tns.ntp_flag.sigpipe", FT_BOOLEAN, 16,
			NULL, 0x0010, NULL, HFILL }},
		{ &hf_tns_ntp_flag_sigurg, {
			"Generate SIGURG signal", "tns.ntp_flag.sigurg", FT_BOOLEAN, 16,
			NULL, 0x0008, NULL, HFILL }},
		{ &hf_tns_ntp_flag_urgentio, {
			"Urgent IO supported", "tns.ntp_flag.urgentio", FT_BOOLEAN, 16,
			NULL, 0x0004, NULL, HFILL }},
		{ &hf_tns_ntp_flag_fdio, {
			"Full duplex IO supported", "tns.ntp_flag.dfio", FT_BOOLEAN, 16,
			NULL, 0x0002, NULL, HFILL }},
		{ &hf_tns_ntp_flag_testop, {
			"Test operation", "tns.ntp_flag.testop", FT_BOOLEAN, 16,
			NULL, 0x0001, NULL, HFILL }},




		{ &hf_tns_line_turnaround, {
			"Line Turnaround Value", "tns.line_turnaround", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_value_of_one, {
			"Value of 1 in Hardware", "tns.value_of_one", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_connect_data_length, {
			"Length of Connect Data", "tns.connect_data_length", FT_UINT16,
			BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0x0, NULL, HFILL }},
		{ &hf_tns_connect_data_offset, {
			"Offset to Connect Data", "tns.connect_data_offset", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_connect_data_max, {
			"Maximum Receivable Connect Data", "tns.connect_data_max", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_connect_flags0, {
			"Connect Flags 0", "tns.connect_flags0", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_connect_flags1, {
			"Connect Flags 1", "tns.connect_flags1", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_conn_flag_nareq, {
			"NA services required", "tns.connect_flags.nareq", FT_BOOLEAN, 8,
			NULL, 0x10, NULL, HFILL }},
		{ &hf_tns_conn_flag_nalink, {
			"NA services linked in", "tns.connect_flags.nalink", FT_BOOLEAN, 8,
			NULL, 0x08, NULL, HFILL }},
		{ &hf_tns_conn_flag_enablena, {
			"NA services enabled", "tns.connect_flags.enablena", FT_BOOLEAN, 8,
			NULL, 0x04, NULL, HFILL }},
		{ &hf_tns_conn_flag_ichg, {
			"Interchange is involved", "tns.connect_flags.ichg", FT_BOOLEAN, 8,
			NULL, 0x02, NULL, HFILL }},
		{ &hf_tns_conn_flag_wantna, {
			"NA services wanted", "tns.connect_flags.wantna", FT_BOOLEAN, 8,
			NULL, 0x01, NULL, HFILL }},


		{ &hf_tns_trace_cf1, {
			"Trace Cross Facility Item 1", "tns.trace_cf1", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_trace_cf2, {
			"Trace Cross Facility Item 2", "tns.trace_cf2", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_trace_cid, {
			"Trace Unique Connection ID", "tns.trace_cid", FT_UINT64, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_connect_data, {
			"Connect Data", "tns.connect_data", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_accept_data_length, {
			"Accept Data Length", "tns.accept_data_length", FT_UINT16,
			BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0x0, NULL, HFILL }},
		{ &hf_tns_accept_data, {
			"Accept Data", "tns.accept_data", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_accept_data_offset, {
			"Offset to Accept Data", "tns.accept_data_offset", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_refuse_reason_user, {
			"Refuse Reason (User)", "tns.refuse_reason_user", FT_UINT8, BASE_HEX,
			NULL, 0x0, "Refuse Reason from Application", HFILL }},
		{ &hf_tns_refuse_reason_system, {
			"Refuse Reason (System)", "tns.refuse_reason_system", FT_UINT8, BASE_HEX,
			NULL, 0x0, "Refuse Reason from System", HFILL }},
		{ &hf_tns_refuse_data_length, {
			"Refuse Data Length", "tns.refuse_data_length", FT_UINT16,
			BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0x0, NULL, HFILL }},
		{ &hf_tns_refuse_data, {
			"Refuse Data", "tns.refuse_data", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_abort_reason_user, {
			"Abort Reason (User)", "tns.abort_reason_user", FT_UINT8, BASE_HEX,
			NULL, 0x0, "Abort Reason from Application", HFILL }},
		{ &hf_tns_abort_reason_system, {
			"Abort Reason (User)", "tns.abort_reason_system", FT_UINT8, BASE_HEX,
			NULL, 0x0, "Abort Reason from System", HFILL }},
		{ &hf_tns_abort_data, {
			"Abort Data", "tns.abort_data", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_marker_type, {
			"Marker Type", "tns.marker.type", FT_UINT8, BASE_HEX,
			VALS(tns_marker_types), 0x0, NULL, HFILL }},
		{ &hf_tns_marker_data_byte, {
			"Marker Data Byte", "tns.marker.databyte", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_marker_function, {
			"Marker Function", "tns.marker.function", FT_UINT8, BASE_DEC,
			VALS(tns_marker_functions), 0x0, NULL, HFILL }},
#if 0
		{ &hf_tns_marker_data, {
			"Marker Data", "tns.marker.data", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
#endif

		{ &hf_tns_control_cmd, {
			"Control Command", "tns.control.cmd", FT_UINT16, BASE_HEX,
			VALS(tns_control_cmds), 0x0, NULL, HFILL }},
		{ &hf_tns_control_data, {
			"Control Data", "tns.control.data", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_redirect_data_length, {
			"Redirect Data Length", "tns.redirect_data_length", FT_UINT16,
			BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0x0, NULL, HFILL }},
		{ &hf_tns_redirect_data, {
			"Redirect Data", "tns.redirect_data", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_flag, {
			"Data Flag", "tns.data_flag", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_flag_send, {
			"Send Token", "tns.data_flag.send", FT_BOOLEAN, 16,
			NULL, 0x1, NULL, HFILL }},
		{ &hf_tns_data_flag_rc, {
			"Request Confirmation", "tns.data_flag.rc", FT_BOOLEAN, 16,
			NULL, 0x2, NULL, HFILL }},
		{ &hf_tns_data_flag_c, {
			"Confirmation", "tns.data_flag.c", FT_BOOLEAN, 16,
			NULL, 0x4, NULL, HFILL }},
		{ &hf_tns_data_flag_reserved, {
			"Reserved", "tns.data_flag.reserved", FT_BOOLEAN, 16,
			NULL, 0x8, NULL, HFILL }},
		{ &hf_tns_data_flag_more, {
			"More Data to Come", "tns.data_flag.more", FT_BOOLEAN, 16,
			NULL, 0x0020, NULL, HFILL }},
		{ &hf_tns_data_flag_eof, {
			"End of File", "tns.data_flag.eof", FT_BOOLEAN, 16,
			NULL, 0x0040, NULL, HFILL }},
		{ &hf_tns_data_flag_dic, {
			"Do Immediate Confirmation", "tns.data_flag.dic", FT_BOOLEAN, 16,
			NULL, 0x0080, NULL, HFILL }},
		{ &hf_tns_data_flag_rts, {
			"Request To Send", "tns.data_flag.rts", FT_BOOLEAN, 16,
			NULL, 0x0100, NULL, HFILL }},
		{ &hf_tns_data_flag_sntt, {
			"Send NT Trailer", "tns.data_flag.sntt", FT_BOOLEAN, 16,
			NULL, 0x0200, NULL, HFILL }},

		{ &hf_tns_data_id, {
			"Data ID", "tns.data_id", FT_UINT32, BASE_HEX,
			VALS(tns_data_funcs), 0x0, NULL, HFILL }},
		{ &hf_tns_data_length, {
			"Data Length", "tns.data_length", FT_UINT32,
			BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0x0, NULL, HFILL }},

		{ &hf_tns_data_oci_id, {
			"Call ID", "tns.data_oci.id", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
			&tns_data_oci_subfuncs_ext, 0x00, NULL, HFILL }},

		{ &hf_tns_data_tseq, {
			"TSeq", "tns.data_tseq", FT_UINT8, BASE_HEX,
			NULL, 0x00, NULL, HFILL }},

		{ &hf_tns_data_piggyback_id, {
			/* Also Call ID.
			   Piggyback is a message what calls a small subset of functions
			   declared in tns_data_oci_subfuncs. */
			"Call ID", "tns.data_piggyback.id", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
			&tns_data_oci_subfuncs_ext, 0x00, NULL, HFILL }},

		{ &hf_tns_data_unused, {
			"Unused", "tns.data.unused", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_cursor, {
			"Cursor", "tns.data.cursor", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_setp_acc_version, {
			"Accepted Version", "tns.data_setp_req.acc_vers", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setp_cli_plat, {
			"Client Platform", "tns.data_setp_req.cli_plat", FT_STRINGZ, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setp_version, {
			"Version", "tns.data_setp_resp.version", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setp_banner, {
			"Server Banner", "tns.data_setp_resp.banner", FT_STRINGZ, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_sns_cli_vers, {
			"Client Version", "tns.data_sns.cli_vers", FT_UINT32, BASE_CUSTOM,
			CF_FUNC(vsnum_to_vstext_basecustom), 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_srv_vers, {
			"Server Version", "tns.data_sns.srv_vers", FT_UINT32, BASE_CUSTOM,
			CF_FUNC(vsnum_to_vstext_basecustom), 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_srvcnt, {
			"Services", "tns.data_sns.srvcnt", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_setdt_charset_in, {
			"Charset In", "tns.data_setdt.charset_in", FT_UINT16, BASE_DEC,
			VALS(tns_charsets), 0x0, "NLS_LANGUAGE charset id", HFILL }},
		{ &hf_tns_data_setdt_charset_out, {
			"Charset Out", "tns.data_setdt.charset_out", FT_UINT16, BASE_DEC,
			VALS(tns_charsets), 0x0, "NLS_NCHAR charset id", HFILL }},
		{ &hf_tns_data_setdt_flag, {
			"Flag", "tns.data_setdt.flag", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setdt_caphdr, {
			"Capability Header", "tns.data_setdt.caphdr", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setdt_caphdr_version, {
			"Version", "tns.data_setdt.caphdr.version", FT_UINT24, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setdt_caphdr_flags, {
			"Flags", "tns.data_setdt.caphdr.flags", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setdt_tblhdr, {
			"Table Header", "tns.data_setdt.tblhdr", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setdt_idmap, {
			"Identity Map", "tns.data_setdt.idmap", FT_BYTES, BASE_NONE,
			NULL, 0x0, "245 entries: type N -> repr N (default mapping)", HFILL }},
		{ &hf_tns_data_setdt_overrides, {
			"Type Overrides", "tns.data_setdt.overrides", FT_NONE, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setdt_override_client, {
			"Client Type", "tns.data_setdt.override.client", FT_UINT8, BASE_DEC,
			VALS(tns_data_types), 0x0, NULL, HFILL }},
		{ &hf_tns_data_setdt_override_repr, {
			"Server Repr", "tns.data_setdt.override.repr", FT_UINT8, BASE_DEC,
			VALS(tns_data_types), 0x0, NULL, HFILL }},
		{ &hf_tns_data_setdt_override_format, {
			"Format", "tns.data_setdt.override.format", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_oer_call_status, {
			"Call Status", "tns.data_oer.call_status", FT_INT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_oer_rowcount, {
			"Row Count", "tns.data_oer.rowcount", FT_INT32, BASE_DEC,
			NULL, 0x0, "DML affected rows (11g)", HFILL }},
		{ &hf_tns_data_oer_err_code, {
			"Error Code", "tns.data_oer.err_code", FT_INT32, BASE_DEC,
			NULL, 0x0, "ORA-NNNNN (0 = success)", HFILL }},
		{ &hf_tns_data_oer_cursor_id, {
			"Cursor Id", "tns.data_oer.cursor_id", FT_INT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_oer_n_batch_errcodes, {
			"Batch Error Codes", "tns.data_oer.n_batch_errcodes", FT_INT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_oer_n_batch_offsets, {
			"Batch Error Offsets", "tns.data_oer.n_batch_offsets", FT_INT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_oer_n_batch_messages, {
			"Batch Error Messages", "tns.data_oer.n_batch_messages", FT_INT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_oer_message, {
			"Message", "tns.data_oer.message", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_opi_version2_banner_len, {
			"Banner Length", "tns.data_opi.vers2.banner_len", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_opi_version2_banner, {
			"Banner", "tns.data_opi.vers2.banner", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_opi_version2_vsnum, {
			"Version", "tns.data_opi.vers2.version", FT_UINT32, BASE_CUSTOM,
			CF_FUNC(vsnum_to_vstext_basecustom), 0x0, NULL, HFILL }},

		{ &hf_tns_data_opi_num_of_params, {
			"Number of parameters", "tns.data_opi.num_of_params", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_opi_param_length, {
			"Length", "tns.data_opi.param_length", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_opi_param_name, {
			"Name", "tns.data_opi.param_name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_opi_param_value, {
			"Value", "tns.data_opi.param_value", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_iov_num_binds, {
			"Number of Binds", "tns.data_iov.num_binds", FT_UINT32, BASE_DEC,
			NULL, 0x0, "num_iters * 256 + num_requests", HFILL }},
		{ &hf_tns_data_iov_bind_dir, {
			"Bind Direction", "tns.data_iov.bind_dir", FT_UINT8, BASE_DEC,
			VALS(tns_iov_bind_dirs), 0x0, NULL, HFILL }},

		{ &hf_tns_data_dcb_num_columns, {
			"Number of Columns", "tns.data_dcb.num_columns", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_type, {
			"Data Type", "tns.data_col.type", FT_UINT8, BASE_DEC,
			VALS(tns_data_types), 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_precision, {
			"Precision", "tns.data_col.precision", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_scale, {
			"Scale", "tns.data_col.scale", FT_INT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_max_length, {
			"Max Data Length", "tns.data_col.max_length", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_charset, {
			"Charset", "tns.data_col.charset", FT_UINT32, BASE_DEC,
			VALS(tns_charsets), 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_csform, {
			"Charset Form", "tns.data_col.csform", FT_UINT8, BASE_DEC,
			VALS(tns_csform_vals), 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_max_size, {
			"Max Size", "tns.data_col.max_size", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_nulls_ok, {
			"Nulls Allowed", "tns.data_col.nulls_ok", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_name, {
			"Column Name", "tns.data_col.name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_rxh_num_requests, {
			"Number of Requests", "tns.data_rxh.num_requests", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_rxh_iter_num, {
			"Iteration Number", "tns.data_rxh.iter_num", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_rxh_num_iters, {
			"Number of Iterations", "tns.data_rxh.num_iters", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_all8_options, {
			"Options", "tns.data_all8.options", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_parse, {
			"Parse", "tns.data_all8.options.parse", FT_BOOLEAN, 32,
			NULL, 0x0001, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_bind, {
			"Bind Values Present", "tns.data_all8.options.bind", FT_BOOLEAN, 32,
			NULL, 0x0008, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_define, {
			"Define Columns Present", "tns.data_all8.options.define", FT_BOOLEAN, 32,
			NULL, 0x0010, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_execute, {
			"Execute", "tns.data_all8.options.execute", FT_BOOLEAN, 32,
			NULL, 0x0020, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_commit, {
			"Autocommit", "tns.data_all8.options.commit", FT_BOOLEAN, 32,
			NULL, 0x0100, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_plsql, {
			"PL/SQL Block", "tns.data_all8.options.plsql", FT_BOOLEAN, 32,
			NULL, 0x0400, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_fetch, {
			"Fetch", "tns.data_all8.options.fetch", FT_BOOLEAN, 32,
			NULL, 0x8000, NULL, HFILL }},
		{ &hf_tns_data_all8_fetch_rows, {
			"Fetch Rows", "tns.data_all8.fetch_rows", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_all8_bind_count, {
			"Bind Count", "tns.data_all8.bind_count", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_all8_sql, {
			"SQL Text", "tns.data_all8.sql", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_bind_value, {
			"Bind Value", "tns.data_bind.value", FT_BYTES, BASE_NONE,
			NULL, 0x0, "Raw type-encoded bind value", HFILL }},
		{ &hf_tns_data_fetch_rows, {
			"Rows to Fetch", "tns.data_fetch.rows", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_lob_op, {
			"LOB Operation", "tns.data_lob.op", FT_UINT32, BASE_HEX,
			VALS(tns_lob_ops), 0x0, NULL, HFILL }},
		{ &hf_tns_data_lob_offset, {
			"Source Offset", "tns.data_lob.offset", FT_UINT32, BASE_DEC,
			NULL, 0x0, "1-based offset into the LOB", HFILL }},
		{ &hf_tns_data_col_value, {
			"Column Value", "tns.data_col.value", FT_BYTES, BASE_NONE,
			NULL, 0x0, "Raw type-encoded row column value", HFILL }},

		{ &hf_tns_data_descriptor_row_count, {
			"Row Count", "tns.data_descriptor.row_count", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_descriptor_row_size, {
			"Row Size", "tns.data_descriptor.row_size", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_reserved_byte, {
			"Reserved Byte", "tns.reserved_byte", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_packet_type, {
			"Packet Type", "tns.type", FT_UINT8, BASE_DEC,
			VALS(tns_type_vals), 0x0, "Type of TNS packet", HFILL }}

	};

	static int *ett[] = {
		&ett_tns,
		&ett_tns_connect,
		&ett_tns_accept,
		&ett_tns_refuse,
		&ett_tns_abort,
		&ett_tns_redirect,
		&ett_tns_marker,
		&ett_tns_attention,
		&ett_tns_control,
		&ett_tns_data,
		&ett_tns_data_flag,
		&ett_tns_acc_versions,
		&ett_tns_opi_params,
		&ett_tns_opi_par,
		&ett_tns_sopt_flag,
		&ett_tns_ntp_flag,
		&ett_tns_conn_flag,
		&ett_tns_rows,
		&ett_tns_setdt_caphdr,
		&ett_tns_setdt_overrides,
		&ett_tns_setdt_override,
		&ett_tns_oer,
		&ett_tns_iov,
		&ett_tns_dcb_col,
		&ett_tns_all8_options,
		&ett_tns_binds,
		&ett_tns_bind,
		&ett_tns_bind_row,
		&ett_tns_rxd_row,
		&ett_sql
	};

	static ei_register_info ei[] = {
		{ &ei_tns_connect_data_next_packet, { "tns.connect_data.next_packet", PI_REQUEST_CODE, PI_CHAT, "Long Connect Data (> 221 bytes) carried in subsequent Data packet", EXPFILL }},
		{ &ei_tns_data_descriptor_size_mismatch, { "tns.data_descriptor.size_mismatch", PI_PROTOCOL, PI_WARN, "Data size from summing row sizes differs from size in descriptor", EXPFILL }},
		{ &ei_tns_data_piggyback_cursors, { "tns.data.piggyback.cursors.invalid", PI_MALFORMED, PI_ERROR, "Cursor count is larger than the data left in the packet", EXPFILL }},
		{ &ei_tns_data_count_too_large, { "tns.data.count.invalid", PI_MALFORMED, PI_ERROR, "Count is larger than the data left in the packet", EXPFILL }},
	};

	module_t *tns_module;
	expert_module_t* expert_tns;

	proto_tns = proto_register_protocol("Transparent Network Substrate Protocol", "TNS", "tns");
	proto_register_field_array(proto_tns, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_tns = expert_register_protocol(proto_tns);
	expert_register_field_array(expert_tns, ei, array_length(ei));
	tns_handle = register_dissector("tns", dissect_tns, proto_tns);

	tns_module = prefs_register_protocol(proto_tns, NULL);
	prefs_register_bool_preference(tns_module, "desegment_tns_messages",
	  "Reassemble TNS messages spanning multiple TCP segments",
	  "Whether the TNS dissector should reassemble messages spanning multiple TCP segments. "
	  "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	  &tns_desegment);
}

void
proto_reg_handoff_tns(void)
{
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_TNS, tns_handle);
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
