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
static int hf_tns_data_piggyback_id;
static int hf_tns_data_unused;

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
static int ett_sql;

static expert_field ei_tns_connect_data_next_packet;
static expert_field ei_tns_data_descriptor_size_mismatch;

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

typedef struct _tns_conv_info_t {
	uint32_t pending_connect_data;
} tns_conv_info_t;

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
					col_append_fstr(pinfo->cinfo, COL_INFO, ", Connect Data");
					proto_tree_add_item(data_tree, hf_tns_connect_data, tvb,
						offset, -1, ENC_ASCII);
					p_add_proto_data(wmem_file_scope(), pinfo, proto_tns, 0,
						GUINT_TO_POINTER(tns_info->pending_connect_data));
					tns_info->pending_connect_data = 0;
					return;
				}
			} else {
				if (p_get_proto_data(wmem_file_scope(), pinfo, proto_tns, 0) != NULL) {
					col_append_fstr(pinfo->cinfo, COL_INFO, ", Connect Data");
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
				int len;
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

		case SQLNET_USER_OCI_FUNC:
			proto_tree_add_item(data_tree, hf_tns_data_oci_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;

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
						len = tvb_get_uint8(tvb, offset);
					}
					else /* OPI_OAUTH */
					{
						len = tvb_get_uint8(tvb, offset_prev) == 0 ? 0 : tvb_get_uint8(tvb, offset);
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

						proto_tree_add_item(par_tree, hf_tns_data_opi_param_length, tvb, offset, 1, ENC_NA);
						offset += 1;

						proto_tree_add_item(par_tree, hf_tns_data_opi_param_value, tvb, offset, len, ENC_ASCII);
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
			proto_tree_add_item(data_tree, hf_tns_data_piggyback_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;

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


static void dissect_tns_marker(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree, int is_attention)
{
	proto_tree *marker_tree;

	if ( is_attention )
	{
		marker_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
			    ett_tns_marker, NULL, "Marker");
	}
	else
	{
		marker_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
			    ett_tns_marker, NULL, "Attention");
	}

	proto_tree_add_item(marker_tree, hf_tns_marker_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(marker_tree, hf_tns_marker_data_byte, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(marker_tree, hf_tns_marker_data_byte, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	/*offset += 1;*/
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
	int offset = 0;
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
			BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL }},
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
			BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL }},
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
			BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL }},
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
			BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL }},
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
			BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL }},

		{ &hf_tns_data_oci_id, {
			"Call ID", "tns.data_oci.id", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
			&tns_data_oci_subfuncs_ext, 0x00, NULL, HFILL }},

		{ &hf_tns_data_piggyback_id, {
			/* Also Call ID.
			   Piggyback is a message what calls a small subset of functions
			   declared in tns_data_oci_subfuncs. */
			"Call ID", "tns.data_piggyback.id", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
			&tns_data_oci_subfuncs_ext, 0x00, NULL, HFILL }},

		{ &hf_tns_data_unused, {
			"Unused", "tns.data.unused", FT_BYTES, BASE_NONE,
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
		&ett_sql
	};

	static ei_register_info ei[] = {
		{ &ei_tns_connect_data_next_packet, { "tns.connect_data.next_packet", PI_REQUEST_CODE, PI_CHAT, "Long Connect Data (> 221 bytes) carried in subsequent Data packet", EXPFILL }},
		{ &ei_tns_data_descriptor_size_mismatch, { "tns.data_descriptor.size_mismatch", PI_PROTOCOL, PI_WARN, "Data size from summing row sizes differs from size in descriptor", EXPFILL }},
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
