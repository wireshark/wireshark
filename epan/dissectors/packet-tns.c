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

/*
 * Oracle datatype codes as they appear on the wire and in tns_data_types[].
 * python-oracledb lists most of these as its ORA_TYPE_NUM_* constants.
 */
#define TNS_DATATYPE_VARCHAR        1
#define TNS_DATATYPE_NUMBER         2
#define TNS_DATATYPE_INTEGER        3    /* BINARY_INTEGER */
#define TNS_DATATYPE_FLOAT          4
#define TNS_DATATYPE_STRING         5
#define TNS_DATATYPE_VARNUM         6
#define TNS_DATATYPE_DECIMAL        7
#define TNS_DATATYPE_LONG           8
#define TNS_DATATYPE_VCS            9
#define TNS_DATATYPE_ROWID          11   /* RID */
#define TNS_DATATYPE_DATE           12
#define TNS_DATATYPE_VBI            15
#define TNS_DATATYPE_RAW            23
#define TNS_DATATYPE_LONG_RAW       24
#define TNS_DATATYPE_CHAR           96
#define TNS_DATATYPE_BINARY_FLOAT   100
#define TNS_DATATYPE_BINARY_DOUBLE  101
#define TNS_DATATYPE_REFCURSOR      102
#define TNS_DATATYPE_ROWID_EXT      104  /* ROWID */
#define TNS_DATATYPE_ADT            109  /* object */
#define TNS_DATATYPE_REF            111
#define TNS_DATATYPE_CLOB           112
#define TNS_DATATYPE_BLOB           113
#define TNS_DATATYPE_BFILE          114
#define TNS_DATATYPE_RSET           116
#define TNS_DATATYPE_JSON           119  /* OSON */
#define TNS_DATATYPE_VECTOR         127
#define TNS_DATATYPE_TIMESTAMP      180
#define TNS_DATATYPE_TIMESTAMP_TZ   181
#define TNS_DATATYPE_INTERVAL_YM    182
#define TNS_DATATYPE_INTERVAL_DS    183
#define TNS_DATATYPE_UROWID         208
#define TNS_DATATYPE_TIMESTAMP_LTZ  231
#define TNS_DATATYPE_BOOLEAN        252

/* DALC length byte marking a slot with no value (see get_dalc_custom). */
#define TNS_DALC_ABSENT             0xFD

/* TTC field versions (compile capability 7), as python-oracledb's
 * TNS_CCAP_FIELD_VERSION_* name them. The wire shape of several messages
 * depends on the one a connection negotiates. */
#define TNS_CCAP_FIELD_VERSION  7
#define TNS_FV_11_2             6
#define TNS_FV_12_1             7
#define TNS_FV_12_2             8
#define TNS_FV_12_2_EXT1        9
#define TNS_FV_18_1             10
#define TNS_FV_18_1_EXT_1       11
#define TNS_FV_19_1             12
#define TNS_FV_19_1_EXT_1       13
#define TNS_FV_20_1             14
#define TNS_FV_20_1_EXT_1       15
#define TNS_FV_21_1             16
#define TNS_FV_23_1             17
#define TNS_FV_23_1_EXT_1       18
#define TNS_FV_23_1_EXT_2       19
#define TNS_FV_23_1_EXT_3       20
#define TNS_FV_23_1_EXT_4       21
#define TNS_FV_23_1_EXT_5       22
#define TNS_FV_23_3_EXT_6       23
#define TNS_FV_23_4             24

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
#define SQLNET_BIT_VECTOR       21
#define SQLNET_SERVER_PIGGYBACK 23
#define SQLNET_IMPLICIT_RESULTS 27
#define SQLNET_END_OF_RESPONSE  29
#define SQLNET_TOKEN            33
#define SQLNET_SNS              0xdeadbeef
#define SQLNET_XTRN_PROCSERV_R1 32
#define SQLNET_XTRN_PROCSERV_R2 68

/* Return OPI Parameter's Type */
#define OPI_VERSION2            1
#define OPI_OSESSKEY            2
#define OPI_OAUTH               3

/* An OCI client's execute preamble: offsets from the TTI_FUN byte, and
 * the 8-byte pointer indicator its fixed slots sit between. */
#define TNS_OCI_INDICATOR        UINT64_C(0xfeffffffffffffff)
#define TNS_OCI_ALL8_CURSOR      7
#define TNS_OCI_ALL8_IND         11
#define TNS_OCI_ALL8_SQLLEN3     19
#define TNS_OCI_ALL8_IND2_NARROW 23
#define TNS_OCI_ALL8_IND2_WIDE   27

/* OCI function ids (TTI_FUN sub-functions). */
#define TTI_REEXECUTE           4
#define TTI_FETCH               5
#define TTI_REEXECUTE_AND_FETCH 78
#define TTI_ALL8                94
#define TTI_LOBOPS              96
#define TTI_TPC_TXN_SWITCH      103
#define TTI_TPC_TXN_CHANGE_STATE 104
#define TTI_CLOSE_CURSORS       105
#define TTI_SET_END_TO_END_ATTR 135
#define TTI_SET_SCHEMA          152
#define TTI_SESSION_RELEASE     163
#define TTI_SESSION_STATE       176
#define TTI_PIPELINE_BEGIN      199
#define TTI_PIPELINE_END        200
#define TTI_END_USER_SEC_CTX    205

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
static int hf_tns_data_token;
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
static int hf_tns_data_auth_mode;
static int hf_tns_data_auth_mode_logon;
static int hf_tns_data_auth_mode_change_password;
static int hf_tns_data_auth_mode_sysdba;
static int hf_tns_data_auth_mode_sysoper;
static int hf_tns_data_auth_mode_with_password;
static int hf_tns_data_auth_user;

static int hf_tns_data_setp_acc_version;
static int hf_tns_data_setp_cli_plat;
static int hf_tns_data_setp_version;
static int hf_tns_data_setp_banner;
static int hf_tns_data_setp_charset;
static int hf_tns_data_setp_flags;
static int hf_tns_data_setp_ncharset;
static int hf_tns_data_setp_compile_caps;
static int hf_tns_data_setp_runtime_caps;
static int hf_tns_data_setp_field_version;

static int hf_tns_data_sns_cli_vers;
static int hf_tns_data_sns_srv_vers;
static int hf_tns_data_sns_srvcnt;
static int hf_tns_data_sns_error;
static int hf_tns_data_sns_service;
static int hf_tns_data_sns_subpackets;
static int hf_tns_data_sns_svc_error;
static int hf_tns_data_sns_sub_type;
static int hf_tns_data_sns_sub_data;
static int hf_tns_data_sns_version;
static int hf_tns_data_sns_encryption;
static int hf_tns_data_sns_integrity;

static int hf_tns_data_setdt_charset_in;
static int hf_tns_data_setdt_charset_out;
static int hf_tns_data_setdt_flag;
static int hf_tns_data_setdt_caphdr;
static int hf_tns_data_setdt_caphdr_version;
static int hf_tns_data_setdt_caphdr_flags;
static int hf_tns_data_setdt_field_version;
static int hf_tns_data_field_version;
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
static int hf_tns_data_oer_err_num_ext;
static int hf_tns_data_oer_rowcount_ext;
static int hf_tns_data_oer_sql_type;
static int hf_tns_data_oer_checksum;

static int hf_tns_data_rpa_num_al8o4;
static int hf_tns_data_rpa_al8o4;
static int hf_tns_data_rpa_al8txl;
static int hf_tns_data_rpa_num_kv;
static int hf_tns_data_rpa_registration;
static int hf_tns_data_rpa_num_rowcounts;
static int hf_tns_data_rpa_dml_rowcount;
static int hf_tns_data_spb_opcode;
static int hf_tns_data_spb_ltxid;
static int hf_tns_data_spb_os_pid;
static int hf_tns_data_spb_num_kv;
static int hf_tns_data_spb_flags;
static int hf_tns_data_spb_session_id;
static int hf_tns_data_spb_serial_num;
static int hf_tns_data_kv_text;
static int hf_tns_data_kv_binary;
static int hf_tns_data_kv_keyword;

static int hf_tns_data_wrn_code;
static int hf_tns_data_wrn_length;
static int hf_tns_data_wrn_flags;
static int hf_tns_data_wrn_message;

static int hf_tns_data_oci_oer_status;
static int hf_tns_data_oci_oer_seq;
static int hf_tns_data_oci_oer_category;
static int hf_tns_data_oci_oer_error_pos;
static int hf_tns_data_oci_oer_command;
static int hf_tns_data_oci_oer_call_seq;

static int hf_tns_data_sta_call_status;
static int hf_tns_data_sta_seq;
static int hf_tns_data_call_status_txn;
static int hf_tns_data_call_status_sess_release;

static int hf_tns_data_iov_num_binds;
static int hf_tns_data_iov_bind_dir;
static int hf_tns_data_bind_retcode;

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
static int hf_tns_data_col_uds_flags;
static int hf_tns_data_col_domain_schema;
static int hf_tns_data_col_domain_name;
static int hf_tns_data_col_annotation;
static int hf_tns_data_col_vector_dims;
static int hf_tns_data_col_vector_format;

static int hf_tns_data_rxh_num_requests;
static int hf_tns_data_rxh_iter_num;
static int hf_tns_data_rxh_num_iters;
static int hf_tns_data_bit_vector;
static int hf_tns_data_bvc_num_cols_sent;
static int hf_tns_data_irs_num_results;

static int hf_tns_data_all8_options;
static int hf_tns_data_all8_opt_parse;
static int hf_tns_data_all8_opt_bind;
static int hf_tns_data_all8_opt_define;
static int hf_tns_data_all8_opt_execute;
static int hf_tns_data_all8_opt_commit;
static int hf_tns_data_all8_opt_plsql;
static int hf_tns_data_all8_opt_fetch;
static int hf_tns_data_all8_opt_not_plsql;
static int hf_tns_data_all8_opt_describe;
static int hf_tns_data_all8_opt_batch_errors;
static int hf_tns_data_all8_iterations;
static int hf_tns_data_all8_prefetch;
static int hf_tns_data_all8_is_query;
static int hf_tns_data_all8_exec_flags;
static int hf_tns_data_all8_xflag_scrollable;
static int hf_tns_data_all8_xflag_no_cancel_on_eof;
static int hf_tns_data_all8_xflag_dml_rowcounts;
static int hf_tns_data_all8_xflag_implicit_rs;
static int hf_tns_data_all8_fetch_orientation;
static int hf_tns_data_all8_fetch_pos;
static int hf_tns_data_all8_fetch_rows;
static int hf_tns_data_all8_bind_count;
static int hf_tns_data_all8_define_count;
static int hf_tns_data_all8_oci_preamble;
static int hf_tns_data_all8_sql;
static int hf_tns_data_bind_value;
static int hf_tns_data_fetch_rows;
static int hf_tns_data_reexec_iterations;
static int hf_tns_data_reexec_options2;
static int hf_tns_data_reexec_opt2_commit;
static int hf_tns_data_lob_op;
static int hf_tns_data_lob_offset;
static int hf_tns_data_lob_locator;
static int hf_tns_data_lob_charset;
static int hf_tns_data_lob_data;
static int hf_tns_data_lob_amount;
static int hf_tns_data_lob_flag;
static int hf_tns_data_tpc_switch_op;
static int hf_tns_data_release_tag;
static int hf_tns_data_release_mode;
static int hf_tns_data_release_mode_deauth;
static int hf_tns_data_tpc_change_op;
static int hf_tns_data_tpc_format_id;
static int hf_tns_data_tpc_gtrid;
static int hf_tns_data_tpc_bqual;
static int hf_tns_data_tpc_flags;
static int hf_tns_data_tpc_timeout;
static int hf_tns_data_tpc_state;
static int hf_tns_data_tpc_context;
static int hf_tns_data_tpc_app_value;
static int hf_tns_data_tpc_internal_name;
static int hf_tns_data_tpc_external_name;
static int hf_tns_data_lob_total_size;
static int hf_tns_data_pgy_schema;
static int hf_tns_data_pgy_session_state;
static int hf_tns_data_pgy_e2e_flags;
static int hf_tns_data_pgy_client_id;
static int hf_tns_data_pgy_module;
static int hf_tns_data_pgy_action;
static int hf_tns_data_pgy_client_info;
static int hf_tns_data_pgy_dbop;
static int hf_tns_data_pgy_error_set_id;
static int hf_tns_data_pgy_error_set_mode;
static int hf_tns_data_pgy_pipeline_mode;
static int hf_tns_data_pgy_sec_flags;
static int hf_tns_data_pgy_sec_key;
static int hf_tns_data_pgy_sec_value;
static int hf_tns_data_col_value;
static int hf_tns_data_lob_size;
static int hf_tns_data_lob_chunk_size;
static int hf_tns_data_json_image;
static int hf_tns_data_vector_image;
static int hf_tns_data_obj_toid;
static int hf_tns_data_obj_image;

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
static int ett_tns_call_status;
static int ett_tns_auth_mode;
static int ett_tns_sns_service;
static int ett_tns_sns_subpacket;
static int ett_tns_release_mode;
static int ett_tns_rpa;
static int ett_tns_kv;
static int ett_tns_iov;
static int ett_tns_dcb_col;
static int ett_tns_all8_options;
static int ett_tns_all8_i4;
static int ett_tns_all8_exec_flags;
static int ett_tns_binds;
static int ett_tns_bind;
static int ett_tns_defines;
static int ett_tns_reexec_options2;
static int ett_tns_bind_row;
static int ett_tns_rxd_row;
static int ett_tns_value;
static int ett_tns_irs;
static int ett_tns_out_binds;
static int ett_sql;

static expert_field ei_tns_connect_data_next_packet;
static expert_field ei_tns_data_descriptor_size_mismatch;
static expert_field ei_tns_data_piggyback_cursors;
static expert_field ei_tns_data_count_too_large;
static expert_field ei_tns_data_encrypted;

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
	&hf_tns_data_all8_opt_fetch,
	&hf_tns_data_all8_opt_commit,
	&hf_tns_data_all8_opt_plsql,
	&hf_tns_data_all8_opt_not_plsql,
	&hf_tns_data_all8_opt_describe,
	&hf_tns_data_all8_opt_batch_errors,
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
	{SQLNET_BIT_VECTOR,       "Bit Vector"},
	{SQLNET_SERVER_PIGGYBACK, "Server-side Piggyback"},
	{SQLNET_IMPLICIT_RESULTS, "Implicit Result Sets"},
	{SQLNET_END_OF_RESPONSE,  "End of Response"},
	{SQLNET_TOKEN,            "Token"},
	{SQLNET_XTRN_PROCSERV_R1, "External Procedures and Services Registrations"},
	{SQLNET_XTRN_PROCSERV_R2, "External Procedures and Services Registrations"},
	{SQLNET_SNS,              "Secure Network Services"},
	{0, NULL}
};

/* The authentication mode of an authentication call. */
static int * const tns_auth_modes[] = {
	&hf_tns_data_auth_mode_logon,
	&hf_tns_data_auth_mode_change_password,
	&hf_tns_data_auth_mode_sysdba,
	&hf_tns_data_auth_mode_sysoper,
	&hf_tns_data_auth_mode_with_password,
	NULL
};

/* The mode of a DRCP session release. */
static int * const tns_release_modes[] = {
	&hf_tns_data_release_mode_deauth,
	NULL
};

/* The second options word of a re-execute. */
static int * const tns_reexec_options2[] = {
	&hf_tns_data_reexec_opt2_commit,
	NULL
};

/* Execute flags, the al8i4[9] word of a TTI_ALL8 execute. */
static int * const tns_all8_exec_flags[] = {
	&hf_tns_data_all8_xflag_scrollable,
	&hf_tns_data_all8_xflag_no_cancel_on_eof,
	&hf_tns_data_all8_xflag_dml_rowcounts,
	&hf_tns_data_all8_xflag_implicit_rs,
	NULL
};

/* Scrollable-cursor fetch orientation, al8i4[10] of a TTI_ALL8 execute. */
static const value_string tns_fetch_orientations[] = {
	{0x00, "None"},
	{0x01, "Current"},
	{0x02, "Next"},
	{0x04, "First"},
	{0x08, "Last"},
	{0x10, "Prior"},
	{0x20, "Absolute"},
	{0x40, "Relative"},
	{0, NULL}
};

/* Server-side piggyback opcodes (python-oracledb's
 * TNS_SERVER_PIGGYBACK_*). */
#define TNS_SPB_QUERY_CACHE_INVALIDATION 1
#define TNS_SPB_OS_PID_MTS               2
#define TNS_SPB_TRACE_EVENT              3
#define TNS_SPB_SESS_RET                 4
#define TNS_SPB_SYNC                     5
#define TNS_SPB_LTXID                    7
#define TNS_SPB_AC_REPLAY_CONTEXT        8
#define TNS_SPB_EXT_SYNC                 9
#define TNS_SPB_SESS_SIGNATURE           10

static const value_string tns_spb_opcodes[] = {
	{TNS_SPB_QUERY_CACHE_INVALIDATION, "Query Cache Invalidation"},
	{TNS_SPB_OS_PID_MTS,               "OS PID (shared server)"},
	{TNS_SPB_TRACE_EVENT,              "Trace Event"},
	{TNS_SPB_SESS_RET,                 "Session Return"},
	{TNS_SPB_SYNC,                     "Session State Sync"},
	{TNS_SPB_LTXID,                    "Logical Transaction Id"},
	{TNS_SPB_AC_REPLAY_CONTEXT,        "Application Continuity Replay Context"},
	{TNS_SPB_EXT_SYNC,                 "Extended Sync"},
	{TNS_SPB_SESS_SIGNATURE,           "Session Signature"},
	{0, NULL}
};

/* Status byte of an OCI client's status block. */
static const value_string tns_oci_oer_status_vals[] = {
	{1, "Success"},
	{5, "Error"},
	{0, NULL}
};

/* Statement command types, as V$SQL.COMMAND_TYPE numbers them. */
static const value_string tns_command_types[] = {
	{1,  "CREATE TABLE"},
	{2,  "INSERT"},
	{3,  "SELECT"},
	{6,  "UPDATE"},
	{7,  "DELETE"},
	{9,  "CREATE INDEX"},
	{12, "DROP TABLE"},
	{15, "ALTER TABLE"},
	{21, "CREATE VIEW"},
	{22, "DROP VIEW"},
	{44, "COMMIT"},
	{45, "ROLLBACK"},
	{47, "PL/SQL EXECUTE"},
	{85, "TRUNCATE TABLE"},
	{0, NULL}
};

static const value_string tns_field_versions[] = {
	{TNS_FV_11_2,       "11.2"},
	{TNS_FV_12_1,       "12.1"},
	{TNS_FV_12_2,       "12.2"},
	{TNS_FV_12_2_EXT1,  "12.2 ext 1"},
	{TNS_FV_18_1,       "18.1"},
	{TNS_FV_18_1_EXT_1, "18.1 ext 1"},
	{TNS_FV_19_1,       "19.1"},
	{TNS_FV_19_1_EXT_1, "19.1 ext 1"},
	{TNS_FV_20_1,       "20.1"},
	{TNS_FV_20_1_EXT_1, "20.1 ext 1"},
	{TNS_FV_21_1,       "21.1"},
	{TNS_FV_23_1,       "23.1"},
	{TNS_FV_23_1_EXT_1, "23.1 ext 1"},
	{TNS_FV_23_1_EXT_2, "23.1 ext 2"},
	{TNS_FV_23_1_EXT_3, "23.1 ext 3"},
	{TNS_FV_23_1_EXT_4, "23.1 ext 4"},
	{TNS_FV_23_1_EXT_5, "23.1 ext 5"},
	{TNS_FV_23_3_EXT_6, "23.3 ext 6"},
	{TNS_FV_23_4,       "23.4"},
	{0, NULL}
};

/* Two-phase commit operations (python-oracledb's TNS_TPC_*). */
static const value_string tns_tpc_switch_ops[] = {
	{0x01, "Start"},
	{0x02, "Detach"},
	{0x04, "Post-detach"},
	{0, NULL}
};

static const value_string tns_tpc_change_ops[] = {
	{0x01, "Commit"},
	{0x02, "Abort"},
	{0x03, "Prepare"},
	{0x04, "Forget"},
	{0, NULL}
};

static const value_string tns_tpc_states[] = {
	{0, "Prepared"},
	{1, "Requires commit"},
	{2, "Committed"},
	{3, "Aborted"},
	{4, "Read only"},
	{5, "Forgotten"},
	{0, NULL}
};

/* Native network services (ANO) negotiation: services, sub-packet types
 * and the encryption and integrity algorithm ids. */
#define TNS_ANO_AUTHENTICATION   1
#define TNS_ANO_ENCRYPTION       2
#define TNS_ANO_DATA_INTEGRITY   3
#define TNS_ANO_SUPERVISOR       4
#define TNS_ANO_SP_BYTES         1
#define TNS_ANO_SP_UB1           2
#define TNS_ANO_SP_VERSION       5

static const value_string tns_sns_services[] = {
	{TNS_ANO_AUTHENTICATION, "Authentication"},
	{TNS_ANO_ENCRYPTION,     "Encryption"},
	{TNS_ANO_DATA_INTEGRITY, "Data Integrity"},
	{TNS_ANO_SUPERVISOR,     "Supervisor"},
	{0, NULL}
};

static const value_string tns_sns_subpacket_types[] = {
	{0, "String"},
	{1, "Bytes"},
	{2, "UB1"},
	{3, "UB2"},
	{4, "UB4"},
	{5, "Version"},
	{6, "Status"},
	{0, NULL}
};

static const value_string tns_sns_encryption_algs[] = {
	{0,  "None"},
	{1,  "RC4_40"},
	{2,  "DES"},
	{3,  "DES40"},
	{6,  "RC4_256"},
	{8,  "RC4_56"},
	{10, "RC4_128"},
	{11, "3DES112"},
	{12, "3DES168"},
	{15, "AES128"},
	{16, "AES192"},
	{17, "AES256"},
	{0, NULL}
};

static const value_string tns_sns_integrity_algs[] = {
	{0, "None"},
	{1, "MD5"},
	{3, "SHA1"},
	{4, "SHA512"},
	{5, "SHA256"},
	{6, "SHA384"},
	{0, NULL}
};

/* Keyword numbers of the key/value pairs a server reports back, for a
 * session attribute a statement changed (python-oracledb's
 * TNS_KEYWORD_NUM_*). */
static const value_string tns_kv_keywords[] = {
	{168, "CURRENT_SCHEMA"},
	{172, "EDITION"},
	{201, "TRANSACTION_ID"},
	{0, NULL}
};

/* Oracle TNS native data-type ids. Used by the Set Datatypes
 * negotiation to label override entries with human names. */
static const value_string tns_data_types[] = {
	{TNS_DATATYPE_VARCHAR,        "VARCHAR"},
	{TNS_DATATYPE_NUMBER,         "NUMBER"},
	{TNS_DATATYPE_INTEGER,        "BINARY_INTEGER"},
	{TNS_DATATYPE_FLOAT,          "FLOAT"},
	{TNS_DATATYPE_STRING,         "STRING"},
	{TNS_DATATYPE_VARNUM,         "VARNUM"},
	{TNS_DATATYPE_DECIMAL,        "DECIMAL"},
	{TNS_DATATYPE_LONG,           "LONG"},
	{TNS_DATATYPE_VCS,            "VCS"},
	{TNS_DATATYPE_ROWID,          "RID"},
	{TNS_DATATYPE_DATE,           "DATE"},
	{TNS_DATATYPE_VBI,            "VBI"},
	{TNS_DATATYPE_RAW,            "RAW"},
	{TNS_DATATYPE_LONG_RAW,       "LONG RAW"},
	{TNS_DATATYPE_CHAR,           "CHAR"},
	{TNS_DATATYPE_BINARY_FLOAT,   "BINARY_FLOAT"},
	{TNS_DATATYPE_BINARY_DOUBLE,  "BINARY_DOUBLE"},
	{TNS_DATATYPE_REFCURSOR,      "REFCURSOR"},
	{TNS_DATATYPE_ROWID_EXT,      "ROWID"},
	{TNS_DATATYPE_ADT,            "ADT"},
	{TNS_DATATYPE_REF,            "REF"},
	{TNS_DATATYPE_CLOB,           "CLOB"},
	{TNS_DATATYPE_BLOB,           "BLOB"},
	{TNS_DATATYPE_BFILE,          "BFILE"},
	{TNS_DATATYPE_RSET,           "RSET"},
	{TNS_DATATYPE_JSON,           "JSON"},
	{TNS_DATATYPE_VECTOR,         "VECTOR"},
	{TNS_DATATYPE_TIMESTAMP,      "TIMESTAMP"},
	{TNS_DATATYPE_TIMESTAMP_TZ,   "TIMESTAMP WITH TIME ZONE"},
	{TNS_DATATYPE_INTERVAL_YM,    "INTERVAL YEAR TO MONTH"},
	{TNS_DATATYPE_INTERVAL_DS,    "INTERVAL DAY TO SECOND"},
	{TNS_DATATYPE_UROWID,         "UROWID"},
	{TNS_DATATYPE_TIMESTAMP_LTZ,  "TIMESTAMP WITH LOCAL TIME ZONE"},
	{TNS_DATATYPE_BOOLEAN,        "BOOLEAN"},
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
#define TNS_LOB_OP_FILE_ISOPEN   0x00400
#define TNS_LOB_OP_FILE_EXISTS   0x00800
#define TNS_LOB_OP_CREATE_TEMP   0x00110
#define TNS_LOB_OP_IS_OPEN       0x11000

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
#define TNS_CSFORM_NCHAR 2
static const value_string tns_csform_vals[] = {
	{1, "Database charset"},
	{2, "National (AL16UTF16)"},
	{0, NULL}
};

/* Bind directions reported per bind in a TTI_IOV vector (TNS_BIND_DIR_*),
 * cross-referenced with python-oracledb's constants. */
#define TNS_BIND_DIR_INPUT 32
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
	{176, "Session state"},
	{187, "Notify"},
	{199, "Pipeline begin"},
	{200, "Pipeline end"},
	{205, "End-user security context"},
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

/* What a value decoder needs to know about one column or bind: its
 * datatype, character set form, and the data length (buffer size) the
 * describe gave it. */
typedef struct _tns_column_t {
	uint8_t type;
	uint8_t csform;         /* character set form: 2 = national */
	uint32_t data_len;
} tns_column_t;

/* Columns from the most recent describe (TTI_DCB), threaded to a later
 * TTI_RXD response so its row values can be split per column. */
typedef struct _tns_describe_t {
	uint32_t num_cols;
	tns_column_t *cols;
} tns_describe_t;

/* The bind types of a cursor, from the execute that opened it. A later
 * execute of the same cursor may send its values with no descriptors. */
typedef struct _tns_binds_t {
	uint32_t count;
	uint32_t num_return;    /* the last num_return are RETURNING ... INTO binds */
	tns_column_t *cols;
} tns_binds_t;

/* The call a response answers: some response messages can only be read
 * knowing what was asked. */
typedef struct _tns_call_t {
	uint8_t func;           /* OCI function id */
	uint32_t exec_flags;    /* al8i4[9] of a TTI_ALL8 execute */
	uint32_t num_binds;     /* bind types of an execute */
	uint32_t num_return;    /* ... of which the last are RETURNING ... INTO binds */
	tns_column_t *binds;
	uint32_t lob_op;        /* TTI_LOBOPS operation */
	uint32_t lob_locator_len; /* ... its source locator length */
	bool lob_amount;        /* ... whether it sent an amount */
} tns_call_t;

typedef struct _tns_conv_info_t {
	uint32_t pending_connect_data;
	/* The most recent call the client made. */
	tns_call_t *last_call;
	/* The client speaks the OCI dialect: fixed-width little-endian
	 * integers and 8-byte pointer indicators, where a thin client uses
	 * variable-length integers and 1-byte pointer flags. */
	bool oci_dialect;
	/* The TTC field version the client and server settled on, from the
	 * client's TTI_DTY; 0 until seen. */
	uint8_t field_version;
	/* Native network encryption: the server picked an algorithm, and
	 * the frame of the client's last negotiation packet, after which the
	 * data packets are encrypted. */
	bool ano_encryption;
	uint32_t ano_active_after;
	tns_describe_t *last_describe;
	/* Bind types of an execute that opened a new cursor, waiting for the
	 * status that names the cursor id. */
	tns_binds_t *pending_binds;
	/* Cursor id -> tns_binds_t. */
	wmem_map_t *cursor_binds;
} tns_conv_info_t;

/* p_add_proto_data key for the describe a TTI_RXD response packet uses. */
#define TNS_PROTO_DATA_DESCRIBE 1
/* p_add_proto_data key for the remembered binds of a re-execute. */
#define TNS_PROTO_DATA_BINDS    2
/* p_add_proto_data key for the call a response packet answers. */
#define TNS_PROTO_DATA_CALL     3
/* p_add_proto_data key for whether a packet is in the OCI dialect. */
#define TNS_PROTO_DATA_OCI      4
/* p_add_proto_data key for the field version in force for a packet. */
#define TNS_PROTO_DATA_FV       5
/* p_add_proto_data key for whether a packet is encrypted. */
#define TNS_PROTO_DATA_ENCRYPTED 6

/* Execute flag asking for the rows each array DML iteration affected. */
#define TNS_EXEC_FLAGS_DML_ROWCOUNTS 0x4000

void proto_reg_handoff_tns(void);
static int dissect_tns_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_);

static tns_conv_info_t*
tns_get_conv_info(packet_info *pinfo)
{
	conversation_t *conversation = find_or_create_conversation(pinfo);

	tns_conv_info_t *tns_info = (tns_conv_info_t *)conversation_get_proto_data(conversation, proto_tns);
	if (!tns_info) {
		tns_info = wmem_new0(wmem_file_scope(), tns_conv_info_t);
		tns_info->cursor_binds = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		conversation_add_proto_data(conversation, proto_tns, tns_info);
	}
	return tns_info;
}

/* The TTC field version negotiated on the packet's connection, or 0 when
 * the negotiation was not seen - which the decoders read as the 11g
 * shape. Stored per packet on the first pass. */
static unsigned tns_field_version(packet_info *pinfo)
{
	void *stored = p_get_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_FV);
	if ( stored || PINFO_FD_VISITED(pinfo) )
		return stored ? GPOINTER_TO_UINT(stored) - 1 : 0;

	unsigned fv = tns_get_conv_info(pinfo)->field_version;
	p_add_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_FV, GUINT_TO_POINTER(fv + 1));
	return fv;
}

/* Whether the connection is known to predate 11g (a 10g server): its
 * describe lacks the fields 11g added. */
static bool tns_before_11g(packet_info *pinfo)
{
	unsigned fv = tns_field_version(pinfo);
	return fv != 0 && fv < TNS_FV_11_2;
}

/* Whether a data packet is encrypted by native network encryption.
 * Stored per packet on the first pass. */
static bool tns_is_encrypted(packet_info *pinfo)
{
	void *stored = p_get_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_ENCRYPTED);
	if ( stored || PINFO_FD_VISITED(pinfo) )
		return GPOINTER_TO_UINT(stored) == 2;

	tns_conv_info_t *tns_info = tns_get_conv_info(pinfo);
	bool encrypted = tns_info->ano_active_after && pinfo->num > tns_info->ano_active_after;
	p_add_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_ENCRYPTED, GUINT_TO_POINTER(encrypted ? 2 : 1));
	return encrypted;
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

/* Decode an Oracle variable-length ub8: a width byte (0..8), then that
 * many big-endian bytes. Returns the number of bytes consumed. */
static int get_ub8_custom(tvbuff_t *tvb, int offset, uint64_t *result)
{
	uint8_t width = tvb_get_uint8(tvb, offset);
	uint64_t value = 0;

	if ( width > 8 )
	{
		/* Not a valid width; the value came off the wire, so step over
		 * the width byte alone rather than claim bytes. */
		*result = 0;
		return 1;
	}
	for ( int i = 0; i < width; i++ )
		value = (value << 8) | tvb_get_uint8(tvb, offset + 1 + i);
	*result = value;
	return 1 + width;
}

/* Walk the chunks of a chunked (0xFE) value, starting after the 0xFE:
 * (length, bytes) pairs until a zero length. A length is one byte up to
 * field version 12.1 and a variable-length ub4 from 12.2 on. The data is
 * appended to strbuf as UTF-8 when strbuf is not NULL. Returns the bytes
 * consumed, the terminating zero included. */
static int tns_chunks_len(tvbuff_t *tvb, packet_info *pinfo, int offset, wmem_strbuf_t *strbuf)
{
	bool ub4_lengths = tns_field_version(pinfo) >= TNS_FV_12_2;
	int o = offset;

	while ( tvb_reported_length_remaining(tvb, o) > 0 )
	{
		int chunk_len;
		if ( ub4_lengths )
			o += get_sb4_custom(tvb, o, &chunk_len);
		else
		{
			chunk_len = tvb_get_uint8(tvb, o);
			o += 1;
		}
		if ( chunk_len <= 0 )
			break;
		if ( strbuf )
			wmem_strbuf_append(strbuf, (const char *)tvb_get_string_enc(pinfo->pool, tvb, o, chunk_len, ENC_UTF_8|ENC_NA));
		o += chunk_len;
	}
	return o - offset;
}

/* Decode a DALC (Data-Length-And-Content) blob. The leading byte is a
 * length only in the middle of its range:
 *
 *   0x00        empty
 *   0x01..0xFC  that many data bytes follow (252 is the longest)
 *   0xFD        absent value: the two-byte placeholder FD 01, no data
 *   0xFE        chunked: (len, bytes) pairs until a 0-length chunk
 *   0xFF        null - a marker only, no data follows
 *
 * The top three bytes are markers, not lengths. The null marker consumes
 * just itself. The absent-value placeholder fills a bind slot that has no
 * inline value - a pure OUT bind, or a NULL of a type with no inline form
 * such as BOOLEAN - and consumes itself plus the 0x01 after it. Reading
 * either as a length would claim bytes that are not there and misalign
 * every field after it, so they have to be spelled out rather than left
 * to the default.
 *
 * The chunk lengths in the 0xFE form are single bytes up to field version
 * 12.1, and variable-length ub4s from 12.2 on.
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
	if ( first == TNS_DALC_ABSENT )
	{
		if ( out_str )
			*out_str = NULL;
		return 2;
	}
	if ( first != 254 )
	{
		if ( out_str )
			*out_str = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset + 1, first, ENC_UTF_8|ENC_NA);
		return 1 + first;
	}

	/* Chunked form: (len, bytes)+ until a zero-length chunk. */
	wmem_strbuf_t *strbuf = wmem_strbuf_new(pinfo->pool, "");
	int used = 1 + tns_chunks_len(tvb, pinfo, offset + 1, strbuf);
	if ( out_str )
		*out_str = wmem_strbuf_get_str(strbuf);
	return used;
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

/* Days since 1970-01-01 of a proleptic Gregorian date, and back. */
static int64_t tns_days_from_civil(int64_t y, unsigned m, unsigned d)
{
	y -= m <= 2;
	int64_t era = (y >= 0 ? y : y - 399) / 400;
	unsigned yoe = (unsigned)(y - era * 400);
	unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
	unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097 + (int64_t)doe - 719468;
}

static void tns_civil_from_days(int64_t z, int64_t *y, unsigned *m, unsigned *d)
{
	z += 719468;
	int64_t era = (z >= 0 ? z : z - 146096) / 146097;
	unsigned doe = (unsigned)(z - era * 146097);
	unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	unsigned mp = (5 * doy + 2) / 153;
	*d = doy - (153 * mp + 2) / 5 + 1;
	*m = mp < 10 ? mp + 3 : mp - 9;
	*y = (int64_t)yoe + era * 400 + (*m <= 2);
}

/* Render an Oracle TIMESTAMP WITH TIME ZONE value: 13 bytes, the
 * 11-byte TIMESTAMP form holding the instant in UTC, then two zone
 * bytes. With the top bit of the first clear they are an offset, hour
 * + 20 and minute + 60, and the value is shown in local time with that
 * offset; with it set they hold a named zone's region id,
 * ((b0 & 0x7f) << 6) + (b1 >> 2), and the value is shown in UTC.
 * Returns a pinfo->pool string, or NULL. */
static const char *tns_format_timestamp_tz(packet_info *pinfo, const uint8_t *data, int len)
{
	const char *utc;
	uint32_t nsec;
	int64_t minutes, days, year;
	unsigned month, day;
	int tz_hour, tz_min, minute_of_day;
	char sign;

	if ( len != 13 )
		return tns_format_date(pinfo, data, len);
	utc = tns_format_date(pinfo, data, 11);
	if ( !utc )
		return NULL;
	if ( data[11] & 0x80 )
		return wmem_strdup_printf(pinfo->pool, "%s UTC (time zone region %u)", utc,
			((unsigned)(data[11] & 0x7f) << 6) + (data[12] >> 2));

	/* Shift the UTC wall clock by the offset, in whole minutes. */
	tz_hour = data[11] - 20;
	tz_min = data[12] - 60;
	days = tns_days_from_civil((data[0] - 100) * 100 + (data[1] - 100), data[2], data[3]);
	minutes = days * 1440 + (data[4] - 1) * 60 + (data[5] - 1) + tz_hour * 60 + tz_min;
	days = minutes >= 0 ? minutes / 1440 : -((-minutes + 1439) / 1440);
	minute_of_day = (int)(minutes - days * 1440);
	tns_civil_from_days(days, &year, &month, &day);

	nsec = ((uint32_t)data[7] << 24) | ((uint32_t)data[8] << 16) | ((uint32_t)data[9] << 8) | data[10];
	/* The sign goes on the whole offset: -03:30 is hour -3, minute -30. */
	sign = (tz_hour < 0 || tz_min < 0) ? '-' : '+';
	if ( nsec )
		return wmem_strdup_printf(pinfo->pool, "%04" PRId64 "-%02u-%02u %02d:%02d:%02d.%09u %c%02d:%02d",
			year, month, day, minute_of_day / 60, minute_of_day % 60, data[6] - 1, nsec,
			sign, abs(tz_hour), abs(tz_min));
	return wmem_strdup_printf(pinfo->pool, "%04" PRId64 "-%02u-%02u %02d:%02d:%02d %c%02d:%02d",
		year, month, day, minute_of_day / 60, minute_of_day % 60, data[6] - 1,
		sign, abs(tz_hour), abs(tz_min));
}

/* Render an Oracle INTERVAL YEAR TO MONTH (5 bytes: years as a
 * big-endian ub4 biased by 2^31, months biased by 60) or INTERVAL DAY TO
 * SECOND (11 bytes: days as a ub4 biased by 2^31, hours, minutes and
 * seconds each biased by 60, nanoseconds as a ub4 biased by 2^31). All
 * fields carry the interval's sign. Rendered as Oracle writes an
 * interval literal: [-]Y-MM, or [-]D HH:MM:SS[.fffffffff].
 * Returns a pinfo->pool string, or NULL. */
static const char *tns_format_interval(packet_info *pinfo, uint8_t dtype, const uint8_t *data, int len)
{
	int32_t lead = (int32_t)((((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
		((uint32_t)data[2] << 8) | data[3]) - 0x80000000u);

	if ( dtype == TNS_DATATYPE_INTERVAL_YM && len == 5 )
	{
		int months = data[4] - 60;
		bool neg = lead < 0 || months < 0;
		return wmem_strdup_printf(pinfo->pool, "%s%d-%02d", neg ? "-" : "",
			abs(lead), abs(months));
	}
	if ( dtype == TNS_DATATYPE_INTERVAL_DS && len == 11 )
	{
		int hours = data[4] - 60, minutes = data[5] - 60, seconds = data[6] - 60;
		int32_t nsec = (int32_t)((((uint32_t)data[7] << 24) | ((uint32_t)data[8] << 16) |
			((uint32_t)data[9] << 8) | data[10]) - 0x80000000u);
		bool neg = lead < 0 || hours < 0 || minutes < 0 || seconds < 0 || nsec < 0;
		if ( nsec )
			return wmem_strdup_printf(pinfo->pool, "%s%d %02d:%02d:%02d.%09d", neg ? "-" : "",
				abs(lead), abs(hours), abs(minutes), abs(seconds), abs(nsec));
		return wmem_strdup_printf(pinfo->pool, "%s%d %02d:%02d:%02d", neg ? "-" : "",
			abs(lead), abs(hours), abs(minutes), abs(seconds));
	}
	return NULL;
}

/* Render an Oracle BINARY_FLOAT (4 bytes) / BINARY_DOUBLE (8 bytes) value
 * Stored in an order-preserving IEEE-754 form: if the
 * high bit is set the value was positive (clear it), else it was negative
 * (invert all bits); then read as big-endian IEEE-754. Returns a
 * pinfo->pool string, or NULL. */
static const char *tns_format_binary_float(packet_info *pinfo, const uint8_t *data, int len)
{
	char buf[G_ASCII_DTOSTR_BUF_SIZE];

	if ( len == 4 )
	{
		uint32_t u = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
			     ((uint32_t)data[2] << 8) | data[3];
		u = (u & 0x80000000u) ? (u & 0x7fffffffu) : ~u;
		float f;
		memcpy(&f, &u, 4);
		/* Locale-independent '.' decimal separator. */
		g_ascii_formatd(buf, sizeof(buf), "%g", (double)f);
		return wmem_strdup(pinfo->pool, buf);
	}
	if ( len == 8 )
	{
		uint64_t u = 0;
		for ( int i = 0; i < 8; i++ )
			u = (u << 8) | data[i];
		u = (u & UINT64_C(0x8000000000000000)) ? (u & UINT64_C(0x7fffffffffffffff)) : ~u;
		double d;
		memcpy(&d, &u, 8);
		g_ascii_formatd(buf, sizeof(buf), "%g", d);
		return wmem_strdup(pinfo->pool, buf);
	}
	return NULL;
}

/* The base-64 alphabet of Oracle's printable rowids. */
static const char tns_rowid_alphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Append value to buf as `digits` base-64 characters, most significant
 * first. */
static void tns_rowid_append(wmem_strbuf_t *buf, uint32_t value, int digits)
{
	char chars[6];

	for ( int i = digits - 1; i >= 0; i-- )
	{
		chars[i] = tns_rowid_alphabet[value & 0x3f];
		value >>= 6;
	}
	wmem_strbuf_append_len(buf, chars, digits);
}

/* Render a physical rowid as the 18-character extended rowid ROWIDTOCHAR
 * prints: object, file, block and slot in 6, 3, 6 and 3 base-64 digits.
 * Returns a pinfo->pool string. */
static const char *tns_format_rowid(packet_info *pinfo, uint32_t rba, uint32_t part, uint32_t block, uint32_t slot)
{
	wmem_strbuf_t *buf = wmem_strbuf_new(pinfo->pool, "");

	tns_rowid_append(buf, rba, 6);
	tns_rowid_append(buf, part, 3);
	tns_rowid_append(buf, block, 6);
	tns_rowid_append(buf, slot, 3);
	return wmem_strbuf_get_str(buf);
}

/* Render a universal rowid. A leading type byte of 1 marks a physical
 * rowid, printed as above; anything else is a logical one - an
 * index-organized table's, carrying its primary key - printed as "*" and
 * the base-64 of the bytes after the type byte, unpadded. Returns a
 * pinfo->pool string, or NULL. */
static const char *tns_format_urowid(packet_info *pinfo, const uint8_t *data, int len)
{
	if ( len >= 13 && data[0] == 1 )
		return tns_format_rowid(pinfo,
			((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 8) | data[4],
			((uint32_t)data[5] << 8) | data[6],
			((uint32_t)data[7] << 24) | ((uint32_t)data[8] << 16) | ((uint32_t)data[9] << 8) | data[10],
			((uint32_t)data[11] << 8) | data[12]);
	if ( len < 2 )
		return NULL;

	wmem_strbuf_t *buf = wmem_strbuf_new(pinfo->pool, "*");
	for ( int i = 1; i < len; i += 3 )
	{
		int n = MIN(3, len - i);
		uint32_t group = (uint32_t)data[i] << 16;
		if ( n > 1 )
			group |= (uint32_t)data[i + 1] << 8;
		if ( n > 2 )
			group |= data[i + 2];
		/* n bytes give n + 1 characters */
		for ( int k = 0; k <= n; k++ )
			wmem_strbuf_append_c(buf, tns_rowid_alphabet[(group >> (18 - 6 * k)) & 0x3f]);
	}
	return wmem_strbuf_get_str(buf);
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

/* End-of-call status flags, carried by both TTI_OER and TTI_STA. */
#define TNS_CALL_STATUS_TXN_IN_PROGRESS  0x00000002
#define TNS_CALL_STATUS_SESS_RELEASE     0x00008000

/* Break out the flag bits of a call status item. A client reads the
 * transaction bit to decide whether closing or releasing the connection
 * owes a rollback. */
static void tns_add_call_status_flags(proto_item *ti, tvbuff_t *tvb, int start, int len, uint32_t status)
{
	proto_tree *st = proto_item_add_subtree(ti, ett_tns_call_status);
	proto_tree_add_boolean(st, hf_tns_data_call_status_txn, tvb, start, len, status);
	proto_tree_add_boolean(st, hf_tns_data_call_status_sess_release, tvb, start, len, status);
}

/* Decode an OAC (Oracle Access Column) descriptor — the type/format core
 * shared by describe columns and bind descriptors. Fields
 * use the Oracle variable-length form (get_sb4_custom). From field version
 * 12.2 the scale is a single signed byte, where 11g sends a variable-length
 * sb4 (NUMBER's default -127 as 0x81 0x7f), and a ub4 oaccolid follows the
 * max size.
 * When col is not NULL it receives the type and data length.
 * Returns the new offset. */
static int dissect_tns_oac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, tns_column_t *col)
{
	int v = 0, start;
	uint64_t u = 0;
	bool fv_12_2 = tns_field_version(pinfo) >= TNS_FV_12_2;

	if ( col )
		col->type = tvb_get_uint8(tvb, offset);
	/* type (ub1) */
	proto_tree_add_item(tree, hf_tns_data_col_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	/* flag (ub1, skip) */
	offset += 1;
	/* precision (sb1) */
	proto_tree_add_item(tree, hf_tns_data_col_precision, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	/* scale (may be negative — NUMBER default is -127) */
	start = offset;
	if ( fv_12_2 )
	{
		v = (int8_t)tvb_get_uint8(tvb, offset);
		offset += 1;
	}
	else
		offset += get_sb4_custom(tvb, offset, &v);
	proto_tree_add_int(tree, hf_tns_data_col_scale, tvb, start, offset - start, v);
	/* max data length / buffer size (ub4) */
	start = offset;
	offset += get_sb4_custom(tvb, offset, &v);
	proto_tree_add_uint(tree, hf_tns_data_col_max_length, tvb, start, offset - start, v);
	if ( col )
		col->data_len = (uint32_t)v;
	/* max array elements (ub4, skip) */
	offset += get_sb4_custom(tvb, offset, &v);
	/* cont flags (ub8, skip) */
	offset += get_ub8_custom(tvb, offset, &u);
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
	if ( col )
		col->csform = tvb_get_uint8(tvb, offset);
	offset += 1;
	/* max size (ub4) */
	start = offset;
	offset += get_sb4_custom(tvb, offset, &v);
	proto_tree_add_uint(tree, hf_tns_data_col_max_size, tvb, start, offset - start, v);
	/* oaccolid (ub4, skip) */
	if ( fv_12_2 )
		offset += get_sb4_custom(tvb, offset, &v);

	return offset;
}

/* Decode one per-column metadata block of a TTI_DCB describe (11g
 * shape): an OAC descriptor plus the nullability and naming fields.
 * When col is not NULL it receives what a row decoder needs.
 * Returns the new offset. */
static int dissect_tns_dcb_column(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int idx, tns_column_t *col)
{
	unsigned fv = tns_field_version(pinfo);
	int start;
	proto_tree *col_tree;
	proto_item *col_item;
	int col_start = offset, v = 0;
	uint8_t col_type = tvb_get_uint8(tvb, offset);
	const char *name = NULL;

	col_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
		ett_tns_dcb_col, &col_item, "Column %d", idx);

	offset = dissect_tns_oac(tvb, pinfo, col_tree, offset, col);

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
	/* uds flags (ub4) — an 11g addition; it marks a JSON column */
	if ( !tns_before_11g(pinfo) )
	{
		start = offset;
		offset += get_sb4_custom(tvb, offset, &v);
		proto_tree_add_uint(col_tree, hf_tns_data_col_uds_flags, tvb, start, offset - start, v);
	}
	/* 23ai: the column's SQL domain, its annotations, and a vector
	 * column's dimensions and format */
	if ( fv >= TNS_FV_23_1 )
	{
		const char *str = NULL;
		start = offset;
		offset += get_field_with_length(tvb, pinfo, offset, &str);
		if ( str )
			proto_tree_add_string(col_tree, hf_tns_data_col_domain_schema, tvb, start, offset - start, str);
		start = offset;
		offset += get_field_with_length(tvb, pinfo, offset, &str);
		if ( str )
			proto_tree_add_string(col_tree, hf_tns_data_col_domain_name, tvb, start, offset - start, str);
	}
	if ( fv >= TNS_FV_23_1_EXT_3 )
	{
		int num = 0;
		offset += get_sb4_custom(tvb, offset, &num);
		if ( num > 0 )
		{
			offset += 1;
			offset += get_sb4_custom(tvb, offset, &num);
			offset += 1;
			for ( int i = 0; i < num && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
			{
				const char *key = NULL, *value = NULL;
				start = offset;
				offset += get_field_with_length(tvb, pinfo, offset, &key);
				offset += get_field_with_length(tvb, pinfo, offset, &value);
				proto_tree_add_string_format_value(col_tree, hf_tns_data_col_annotation, tvb,
					start, offset - start, key ? key : "", "%s = %s",
					key ? key : "", value ? value : "");
				offset += get_sb4_custom(tvb, offset, &v); /* flags */
			}
			offset += get_sb4_custom(tvb, offset, &v);     /* flags */
		}
	}
	if ( fv >= TNS_FV_23_4 )
	{
		start = offset;
		offset += get_sb4_custom(tvb, offset, &v);
		proto_tree_add_uint(col_tree, hf_tns_data_col_vector_dims, tvb, start, offset - start, v);
		proto_tree_add_item(col_tree, hf_tns_data_col_vector_format, tvb, offset, 1, ENC_NA);
		offset += 1;
		offset += 1;                                         /* vector flags */
	}

	if ( name )
		proto_item_append_text(col_item, ": %s (%s)", name,
			val_to_str_const(col_type, tns_data_types, "unknown"));
	proto_item_set_len(col_item, offset - col_start);
	return offset;
}

/* Decode a describe body - the column metadata of a result set - as a
 * TTI_DCB carries it after its preamble: a ub4 max row size, a ub4 column
 * count, a reserved byte when there are columns, the columns, and a
 * trailer. When out is not NULL it receives the columns, allocated in
 * file scope. Returns the new offset. */
static int dissect_tns_describe_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, tns_describe_t **out)
{
	int v = 0, num_cols = 0, nc_start;
	tns_column_t *cols = NULL;

	/* max row size (ub4, skip) */
	offset += get_sb4_custom(tvb, offset, &v);
	/* number of columns */
	nc_start = offset;
	offset += get_sb4_custom(tvb, offset, &num_cols);
	proto_tree_add_uint(tree, hf_tns_data_dcb_num_columns, tvb, nc_start, offset - nc_start, num_cols);
	/* The count comes off the wire and sizes the allocation below, so a
	 * count larger than the data left cannot be real - report it and
	 * decode no columns. */
	if ( num_cols < 0 ||
	     (unsigned)num_cols > tvb_reported_length_remaining(tvb, offset) )
	{
		proto_tree_add_expert(tree, pinfo, &ei_tns_data_count_too_large,
			tvb, nc_start, offset - nc_start);
		num_cols = 0;
	}
	if ( num_cols > 0 )
		offset += 1; /* reserved byte */

	if ( out && num_cols > 0 )
		cols = wmem_alloc0_array(wmem_file_scope(), tns_column_t, num_cols);
	for ( int i = 0; i < num_cols && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
		offset = dissect_tns_dcb_column(tvb, pinfo, tree, offset, i + 1,
			cols ? &cols[i] : NULL);
	if ( cols )
	{
		tns_describe_t *desc = wmem_new0(wmem_file_scope(), tns_describe_t);
		desc->num_cols = num_cols;
		desc->cols = cols;
		*out = desc;
	}

	/* Trailer: current date (bytes_with_length), four ub4 flags,
	 * and the query-cache key (bytes_with_length) — all skipped. The key
	 * came with the 11g result cache: a 10g describe ends after the
	 * flags. */
	offset += get_field_with_length(tvb, pinfo, offset, NULL);
	for ( int i = 0; i < 4; i++ )
		offset += get_sb4_custom(tvb, offset, &v);
	if ( !tns_before_11g(pinfo) )
		offset += get_field_with_length(tvb, pinfo, offset, NULL);
	return offset;
}

/* Decode one row/bind value by its data type, and add it as a
 * "<prefix> N (TYPE)" item under `hf`. Ordinary values are a
 * DALC blob; ROWID / UROWID / LONG / LOB / JSON / VECTOR / object carry
 * their own framings. Returns the new offset. */
static int dissect_tns_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint8_t dtype, uint8_t csform, int idx, int hf, const char *prefix)
{
	int v_start = offset, disp_start = offset, v = 0;
	int is_null = 0, is_absent = 0;
	uint8_t first;
	const char *rendered = NULL;
	/* LOB metadata: size and chunk size, with where they sit */
	bool lob_meta = false;
	uint64_t lob_size = 0;
	int lob_chunk = 0, size_start = 0, size_len = 0, lchunk_start = 0, lchunk_len = 0;
	int image_start = 0, image_len = 0, obj_toid_start = 0, obj_toid_len = 0;
	proto_item *ti;

	switch ( dtype )
	{
		case TNS_DATATYPE_REFCURSOR:
		{
			/* A cursor - a CURSOR(...) column, or a REF CURSOR OUT
			 * bind: a ub1 length (a fixed value, ignored), the describe
			 * of the cursor's result set inline, and the ub2 id the
			 * client drains it with. The value's length is known only
			 * once the describe is read, so read it once to size the
			 * item and again to show it. */
			proto_item *ci;
			proto_tree *ct;
			int end, cursor = 0, start;

			end = dissect_tns_describe_body(tvb, pinfo, NULL, offset + 1, NULL);
			end += get_sb4_custom(tvb, end, &cursor);
			ci = proto_tree_add_bytes_format(tree, hf, tvb, offset, end - offset, NULL,
				"%s %d (%s): cursor %d", prefix, idx,
				val_to_str_const(dtype, tns_data_types, "unknown"), cursor);
			ct = proto_item_add_subtree(ci, ett_tns_value);
			offset = dissect_tns_describe_body(tvb, pinfo, ct, offset + 1, NULL);
			start = offset;
			offset += get_sb4_custom(tvb, offset, &cursor);
			proto_tree_add_uint(ct, hf_tns_cursor, tvb, start, offset - start, cursor);
			return offset;
		}

		case TNS_DATATYPE_ADT:
		{
			/* An object - or an XMLType, which is an ADT by describe - is
			 * framed the same way whether it is NULL or not:
			 *   bytes_with_length type OID | bytes_with_length OID |
			 *   bytes_with_length snapshot | ub2 version |
			 *   ub4 image length | ub2 flags | [DALC image]
			 * A NULL object has an image length of 0 and no image. */
			int toid_start = offset, img_len = 0;
			offset += get_field_with_length(tvb, pinfo, offset, NULL);
			obj_toid_start = toid_start;
			obj_toid_len = offset - toid_start;
			offset += get_field_with_length(tvb, pinfo, offset, NULL); /* OID */
			offset += get_field_with_length(tvb, pinfo, offset, NULL); /* snapshot */
			offset += get_sb4_custom(tvb, offset, &v);                  /* version */
			offset += get_sb4_custom(tvb, offset, &img_len);
			offset += get_sb4_custom(tvb, offset, &v);                  /* flags */
			if ( img_len > 0 )
			{
				image_start = offset;
				offset += get_dalc_custom(tvb, pinfo, offset, NULL);
				image_len = offset - image_start;
				rendered = wmem_strdup_printf(pinfo->pool, "object, %d-byte image", img_len);
			}
			else
				rendered = "NULL object";
			break;
		}

		case TNS_DATATYPE_JSON:   /* OSON */
		case TNS_DATATYPE_VECTOR:
			/* LOB-class, but the value itself rides in the row: the LOB
			 * metadata framing with the image spliced in ahead of the
			 * locator,
			 *   ub4 locator length | ub8 image size | ub4 chunk size |
			 *   DALC image | DALC locator
			 * The locator is a placeholder. A 0x00 is NULL. A server may
			 * instead send a bare locator, as for a CLOB, and leave the
			 * image to a LOB read; that is told apart as for a CLOB. */
			first = tvb_get_uint8(tvb, offset);
			if ( first == 0 )
			{
				offset += 1;
				is_null = 1;
				break;
			}
			offset += get_sb4_custom(tvb, offset, &v);
			if ( v > 8 && tvb_get_uint8(tvb, offset) == v )
			{
				/* bare locator */
				offset += get_dalc_custom(tvb, pinfo, offset, NULL);
				rendered = "locator only";
				break;
			}
			lob_meta = true;
			size_start = offset;
			offset += get_ub8_custom(tvb, offset, &lob_size);
			size_len = offset - size_start;
			lchunk_start = offset;
			offset += get_sb4_custom(tvb, offset, &lob_chunk);
			lchunk_len = offset - lchunk_start;
			image_start = offset;
			offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			image_len = offset - image_start;
			offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			rendered = wmem_strdup_printf(pinfo->pool, "%s image, %" PRIu64 " bytes",
				dtype == TNS_DATATYPE_JSON ? "OSON" : "vector", lob_size);
			break;

		case TNS_DATATYPE_ROWID:
		{
			/* a present indicator (0 / 0xff = NULL), then the object id
			 * (ub4), file number (ub2), an unused byte, block number
			 * (ub4) and slot number (ub2) */
			int rba = 0, part = 0, block = 0, slot = 0;
			first = tvb_get_uint8(tvb, offset);
			offset += 1;
			if ( first == 0 || first == 0xff )
			{
				is_null = 1;
				break;
			}
			offset += get_sb4_custom(tvb, offset, &rba);
			offset += get_sb4_custom(tvb, offset, &part);
			offset += 1;
			offset += get_sb4_custom(tvb, offset, &block);
			offset += get_sb4_custom(tvb, offset, &slot);
			rendered = tns_format_rowid(pinfo, (uint32_t)rba, (uint32_t)part, (uint32_t)block, (uint32_t)slot);
			break;
		}

		case TNS_DATATYPE_UROWID: /* ub4 num_bytes, a length echo byte, then the bytes */
			offset += get_sb4_custom(tvb, offset, &v);
			if ( v > 0 )
			{
				offset += 1;
				rendered = tns_format_urowid(pinfo, tvb_get_ptr(tvb, offset, v), v);
				offset += v;
			}
			else
				is_null = 1;
			break;

		case TNS_DATATYPE_LONG:
		case TNS_DATATYPE_LONG_RAW: /* value then two trailing ub4 length indicators */
			first = tvb_get_uint8(tvb, offset);
			if ( first == 0 )
			{
				offset += 1;
				is_null = 1;
			}
			else if ( first == 0xfe ) /* chunked */
				offset += 1 + tns_chunks_len(tvb, pinfo, offset + 1, NULL);
			else
				offset += 1 + first;
			offset += get_sb4_custom(tvb, offset, &v);
			offset += get_sb4_custom(tvb, offset, &v);
			break;

		case TNS_DATATYPE_CLOB:
		case TNS_DATATYPE_BLOB:
		case TNS_DATATYPE_BFILE:
			/* 0x00 NULL, else a ub4 locator length and the locator. A
			 * server sends CLOB / BLOB in one of two forms: with the LOB's
			 * size (ub8) and chunk size (ub4) between the two, or bare -
			 * and which one it picks for a client is not known. They are
			 * told apart by the byte after the length: the bare form's is
			 * the locator's own length prefix (or 0xFE when chunked), the
			 * metadata form's is the size's width, at most 8. A real
			 * locator is far longer than 8 bytes, so the two cannot meet.
			 * A BFILE is always bare. */
			first = tvb_get_uint8(tvb, offset);
			if ( first == 0 )
			{
				offset += 1;
				is_null = 1;
			}
			else
			{
				offset += get_sb4_custom(tvb, offset, &v);
				if ( dtype != TNS_DATATYPE_BFILE && v > 8 )
				{
					uint8_t next = tvb_get_uint8(tvb, offset);
					if ( next <= 8 && next != v )
					{
						lob_meta = true;
						size_start = offset;
						offset += get_ub8_custom(tvb, offset, &lob_size);
						size_len = offset - size_start;
						lchunk_start = offset;
						offset += get_sb4_custom(tvb, offset, &lob_chunk);
						lchunk_len = offset - lchunk_start;
						rendered = wmem_strdup_printf(pinfo->pool, "locator, size %" PRIu64, lob_size);
					}
				}
				offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			}
			break;

		default: /* ordinary: a single DALC value */
			first = tvb_get_uint8(tvb, offset);
			offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			if ( first == 0 )
				is_null = 1;
			else if ( first == TNS_DALC_ABSENT )
				is_absent = 1;
			else
			{
				disp_start = v_start + 1; /* show the value bytes, not the length */
				/* Render common scalar types (never chunked): NUMBER as
				 * decimal, DATE / TIMESTAMP / TIMESTAMP LTZ as a datetime. */
				if ( first != 254 && offset > disp_start )
				{
					const uint8_t *vb = tvb_get_ptr(tvb, disp_start, offset - disp_start);
					int vlen = offset - disp_start;
					/* A BINARY_INTEGER carries NUMBER bytes, not a native
					 * integer. */
					if ( dtype == TNS_DATATYPE_NUMBER || dtype == TNS_DATATYPE_INTEGER )
						rendered = tns_format_number(pinfo, vb, vlen);
					else if ( dtype == TNS_DATATYPE_DATE || dtype == TNS_DATATYPE_TIMESTAMP || dtype == TNS_DATATYPE_TIMESTAMP_LTZ )
						rendered = tns_format_date(pinfo, vb, vlen);
					else if ( dtype == TNS_DATATYPE_TIMESTAMP_TZ )
						rendered = tns_format_timestamp_tz(pinfo, vb, vlen);
					else if ( (dtype == TNS_DATATYPE_INTERVAL_YM || dtype == TNS_DATATYPE_INTERVAL_DS) && vlen >= 5 )
						rendered = tns_format_interval(pinfo, dtype, vb, vlen);
					else if ( dtype == TNS_DATATYPE_BOOLEAN )
						/* an encoded integer: 00 false, 01 01 true */
						rendered = vb[0] == 1 ? "TRUE" : "FALSE";
					else if ( dtype == TNS_DATATYPE_BINARY_FLOAT || dtype == TNS_DATATYPE_BINARY_DOUBLE )
						rendered = tns_format_binary_float(pinfo, vb, vlen);
					else if ( dtype == TNS_DATATYPE_VARCHAR || dtype == TNS_DATATYPE_STRING || dtype == TNS_DATATYPE_CHAR )
						/* VARCHAR / STRING / CHAR: character data, in the
						 * session charset (ordinarily UTF-8), or UTF-16BE
						 * for the national charset form (NCHAR,
						 * NVARCHAR2) - in a column and an OUT bind alike. */
						rendered = (const char *)tvb_get_string_enc(pinfo->pool,
							tvb, disp_start, vlen,
							csform == TNS_CSFORM_NCHAR ? ENC_UTF_16|ENC_BIG_ENDIAN : ENC_UTF_8|ENC_NA);
				}
			}
			break;
	}

	if ( is_null )
		proto_tree_add_bytes_format(tree, hf, tvb,
			v_start, offset - v_start, NULL, "%s %d (%s): NULL", prefix, idx,
			val_to_str_const(dtype, tns_data_types, "unknown"));
	else if ( is_absent )
		proto_tree_add_bytes_format(tree, hf, tvb,
			v_start, offset - v_start, NULL, "%s %d (%s): no value", prefix, idx,
			val_to_str_const(dtype, tns_data_types, "unknown"));
	else if ( rendered )
	{
		ti = proto_tree_add_bytes_format(tree, hf, tvb,
			disp_start, offset - disp_start, NULL, "%s %d (%s): %s", prefix, idx,
			val_to_str_const(dtype, tns_data_types, "unknown"), rendered);
		if ( dtype == TNS_DATATYPE_ADT )
		{
			proto_tree *vt = proto_item_add_subtree(ti, ett_tns_value);
			/* the type OID, without its ub4 count and DALC length */
			if ( obj_toid_len > 2 )
			{
				int w = 1 + (tvb_get_uint8(tvb, obj_toid_start) & 0x7f);
				proto_tree_add_item(vt, hf_tns_data_obj_toid, tvb,
					obj_toid_start + w + 1, obj_toid_len - w - 1, ENC_NA);
			}
			if ( image_len > 1 )
			{
				bool chunked = tvb_get_uint8(tvb, image_start) == 0xfe;
				proto_tree_add_item(vt, hf_tns_data_obj_image, tvb,
					chunked ? image_start : image_start + 1, chunked ? image_len : image_len - 1, ENC_NA);
			}
		}
		if ( lob_meta )
		{
			proto_tree *vt = proto_item_add_subtree(ti, ett_tns_value);
			proto_tree_add_uint64(vt, hf_tns_data_lob_size, tvb, size_start, size_len, lob_size);
			proto_tree_add_uint(vt, hf_tns_data_lob_chunk_size, tvb, lchunk_start, lchunk_len, lob_chunk);
			/* the image of a prefetched JSON / VECTOR value, without its
			 * DALC length byte (chunked images are shown whole) */
			if ( image_len > 1 )
			{
				bool chunked = tvb_get_uint8(tvb, image_start) == 0xfe;
				proto_tree_add_item(vt, dtype == TNS_DATATYPE_JSON ? hf_tns_data_json_image : hf_tns_data_vector_image,
					tvb, chunked ? image_start : image_start + 1, chunked ? image_len : image_len - 1, ENC_NA);
			}
		}
	}
	else
		proto_tree_add_bytes_format(tree, hf, tvb,
			disp_start, offset - disp_start, NULL, "%s %d (%s)", prefix, idx,
			val_to_str_const(dtype, tns_data_types, "unknown"));
	return offset;
}

/* The describe a row-data message is split by: the conversation's most
 * recent one, stored per packet on the first pass so a later pass uses
 * the same. */
static tns_describe_t *tns_current_describe(packet_info *pinfo)
{
	tns_describe_t *desc;

	if ( PINFO_FD_VISITED(pinfo) )
		return (tns_describe_t *)p_get_proto_data(wmem_file_scope(), pinfo,
			proto_tns, TNS_PROTO_DATA_DESCRIBE);

	desc = tns_get_conv_info(pinfo)->last_describe;
	if ( desc && !p_get_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_DESCRIBE) )
		p_add_proto_data(wmem_file_scope(), pinfo, proto_tns,
			TNS_PROTO_DATA_DESCRIBE, desc);
	return desc;
}

/* Count the RETURNING ... INTO binds of a statement: the placeholders
 * after INTO, in a DML statement that has RETURNING ... INTO. Each
 * placeholder is a bind of its own, and those after INTO come last. A
 * PL/SQL block is never this form - a RETURNING INTO inside one is its
 * own PL/SQL, and its target an ordinary OUT bind. String literals and
 * comments are skipped. */
static unsigned tns_count_return_binds(const char *sql)
{
	const char *p = sql;
	bool first_word = true, returning = false, into = false;
	unsigned n = 0;

	while ( *p )
	{
		if ( *p == '\'' )
		{
			for ( p++; *p && *p != '\''; p++ )
				;
			if ( *p )
				p++;
		}
		else if ( p[0] == '-' && p[1] == '-' )
		{
			while ( *p && *p != '\n' )
				p++;
		}
		else if ( p[0] == '/' && p[1] == '*' )
		{
			const char *end = strstr(p + 2, "*/");
			p = end ? end + 2 : p + strlen(p);
		}
		else if ( g_ascii_isalpha(*p) )
		{
			const char *w = p;
			size_t len;
			while ( g_ascii_isalnum(*p) || *p == '_' || *p == '$' || *p == '#' )
				p++;
			len = p - w;
			if ( first_word )
			{
				first_word = false;
				if ( !((len == 6 && (g_ascii_strncasecmp(w, "INSERT", 6) == 0
						|| g_ascii_strncasecmp(w, "UPDATE", 6) == 0
						|| g_ascii_strncasecmp(w, "DELETE", 6) == 0))
					|| (len == 5 && g_ascii_strncasecmp(w, "MERGE", 5) == 0)) )
					return 0;
			}
			else if ( !returning && len == 9 && g_ascii_strncasecmp(w, "RETURNING", 9) == 0 )
				returning = true;
			else if ( returning && !into && len == 4 && g_ascii_strncasecmp(w, "INTO", 4) == 0 )
				into = true;
		}
		else if ( *p == ':' && into && (g_ascii_isalnum(p[1]) || p[1] == '_' || p[1] == '"') )
		{
			n++;
			for ( p++; g_ascii_isalnum(*p) || *p == '_' || *p == '"'; p++ )
				;
		}
		else
			p++;
	}
	return n;
}

/* Look up the bind types remembered for a cursor, for an execute that
 * sends its values without descriptors. Stashed per packet on the first
 * pass, so a later pass gets the same answer. */
static tns_binds_t *tns_lookup_cursor_binds(packet_info *pinfo, uint32_t cursor)
{
	if ( PINFO_FD_VISITED(pinfo) )
		return (tns_binds_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_BINDS);

	tns_conv_info_t *tns_info = tns_get_conv_info(pinfo);
	tns_binds_t *binds = (tns_binds_t *)wmem_map_lookup(tns_info->cursor_binds, GUINT_TO_POINTER(cursor));
	if ( binds )
		p_add_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_BINDS, binds);
	return binds;
}

/* Decode the TTI_RXD value rows of a bind section - one row per
 * execution - with each value typed by cols[]. A CLOB / BLOB bind
 * carries a temp-LOB locator form not unpacked here, so rows with one are
 * left alone. Returns the new offset. */
static int dissect_tns_bind_rows(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, const tns_column_t *cols, uint32_t count)
{
	int rownum = 0;

	for ( uint32_t i = 0; i < count; i++ )
		if ( cols[i].type == TNS_DATATYPE_CLOB || cols[i].type == TNS_DATATYPE_BLOB )
			return offset;

	while ( tvb_reported_length_remaining(tvb, offset) > 0
		&& tvb_get_uint8(tvb, offset) == SQLNET_ROW_TRANSF_DATA )
	{
		proto_tree *row_tree;
		proto_item *row_item;
		int r_start = offset;

		offset += 1; /* TTI_RXD token */
		row_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
			ett_tns_bind_row, &row_item, "Row %d", ++rownum);
		for ( uint32_t i = 0; i < count
			&& tvb_reported_length_remaining(tvb, offset) > 0; i++ )
			offset = dissect_tns_value(tvb, pinfo, row_tree, offset,
				cols[i].type, cols[i].csform, i + 1, hf_tns_data_bind_value, "Bind");
		proto_item_set_len(row_item, offset - r_start);
	}
	return offset;
}

/* Remember the call a request makes, so the response can be read in its
 * light. Returns the record to fill in, or NULL on a later pass. */
static tns_call_t *tns_remember_call(packet_info *pinfo, uint8_t func)
{
	if ( PINFO_FD_VISITED(pinfo) )
		return NULL;

	tns_call_t *call = wmem_new0(wmem_file_scope(), tns_call_t);
	call->func = func;
	tns_get_conv_info(pinfo)->last_call = call;
	return call;
}

/* The call a response packet answers, or NULL if none was seen. */
static tns_call_t *tns_answered_call(packet_info *pinfo)
{
	if ( PINFO_FD_VISITED(pinfo) )
		return (tns_call_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_CALL);

	tns_call_t *call = tns_get_conv_info(pinfo)->last_call;
	if ( call )
		p_add_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_CALL, call);
	return call;
}

/* Decode num key/value pairs: each a ub2 text length and text, a ub2
 * binary length and bytes, and a ub2 keyword number saying which session
 * attribute the value is for. Returns the new offset. */
static int dissect_tns_kv_pairs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int num)
{
	for ( int i = 0; i < num && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
	{
		proto_tree *kv_tree;
		proto_item *kv_item;
		const char *text = NULL;
		int kv_start = offset, len = 0, keyword = 0, start;

		kv_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_tns_kv,
			&kv_item, "Key/Value Pair %d", i + 1);
		offset += get_sb4_custom(tvb, offset, &len);
		if ( len > 0 )
		{
			start = offset;
			offset += get_dalc_custom(tvb, pinfo, offset, &text);
			proto_tree_add_string(kv_tree, hf_tns_data_kv_text, tvb, start, offset - start, text);
		}
		offset += get_sb4_custom(tvb, offset, &len);
		if ( len > 0 )
		{
			start = offset;
			offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			proto_tree_add_item(kv_tree, hf_tns_data_kv_binary, tvb, start + 1, offset - start - 1, ENC_NA);
		}
		start = offset;
		offset += get_sb4_custom(tvb, offset, &keyword);
		proto_tree_add_uint(kv_tree, hf_tns_data_kv_keyword, tvb, start, offset - start, keyword);
		proto_item_append_text(kv_item, ": %s", val_to_str(pinfo->pool, keyword, tns_kv_keywords, "keyword %u"));
		if ( text )
			proto_item_append_text(kv_item, " = %s", text);
		proto_item_set_len(kv_item, offset - kv_start);
	}
	return offset;
}

/* Decode the return-parameters block (TTI_RPA) that answers an execute,
 * ahead of its closing status. With DML_ROWCOUNTS requested it ends with
 * the rows each iteration of an array DML affected. Returns the new
 * offset. */
static int dissect_tns_return_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, bool rowcounts)
{
	proto_tree *rpa_tree;
	proto_item *rpa_item;
	int rpa_start = offset, num = 0, len = 0, start;

	rpa_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_tns_rpa, &rpa_item, "Return Parameters");

	/* al8o4l: a count of ub4 words */
	start = offset;
	offset += get_sb4_custom(tvb, offset, &num);
	proto_tree_add_uint(rpa_tree, hf_tns_data_rpa_num_al8o4, tvb, start, offset - start, num);
	for ( int i = 0; i < num && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
	{
		int v = 0;
		start = offset;
		offset += get_sb4_custom(tvb, offset, &v);
		proto_tree_add_uint(rpa_tree, hf_tns_data_rpa_al8o4, tvb, start, offset - start, v);
	}
	/* al8txl: a byte count and the bytes */
	offset += get_sb4_custom(tvb, offset, &len);
	if ( len > 0 )
	{
		proto_tree_add_item(rpa_tree, hf_tns_data_rpa_al8txl, tvb, offset, len, ENC_NA);
		offset += len;
	}
	/* key/value pairs: a changed session attribute is reported here */
	start = offset;
	offset += get_sb4_custom(tvb, offset, &num);
	proto_tree_add_uint(rpa_tree, hf_tns_data_rpa_num_kv, tvb, start, offset - start, num);
	offset = dissect_tns_kv_pairs(tvb, pinfo, rpa_tree, offset, num);
	/* registration: a byte count and the bytes */
	offset += get_sb4_custom(tvb, offset, &len);
	if ( len > 0 )
	{
		proto_tree_add_item(rpa_tree, hf_tns_data_rpa_registration, tvb, offset, len, ENC_NA);
		offset += len;
	}
	/* per-iteration row counts, when the execute asked for them */
	if ( rowcounts )
	{
		start = offset;
		offset += get_sb4_custom(tvb, offset, &num);
		proto_tree_add_uint(rpa_tree, hf_tns_data_rpa_num_rowcounts, tvb, start, offset - start, num);
		for ( int i = 0; i < num && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
		{
			uint64_t rows = 0;
			start = offset;
			offset += get_ub8_custom(tvb, offset, &rows);
			proto_tree_add_uint64(rpa_tree, hf_tns_data_rpa_dml_rowcount, tvb, start, offset - start, rows);
		}
	}
	proto_item_set_len(rpa_item, offset - rpa_start);
	return offset;
}

/* From field version 23.1 ext 1 a call or piggyback header carries a ub8
 * token after its sequence number, which the reply echoes in a TOKEN
 * message. Returns the new offset. */
static int dissect_tns_call_token(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	uint64_t token = 0;
	int start = offset;

	if ( tns_field_version(pinfo) < TNS_FV_23_1_EXT_1 )
		return offset;
	offset += get_ub8_custom(tvb, offset, &token);
	proto_tree_add_uint64(tree, hf_tns_data_token, tvb, start, offset - start, token);
	return offset;
}

/* Decode a two-phase commit call: a transaction switch (103) - start,
 * detach - or a state change (104) - prepare, commit, abort, forget. The
 * header gives an operation, the lengths of a transaction context and of
 * the XID's parts, and for a switch the names; the context, the XID and
 * the rest follow. The XID is padded to 128 bytes. Returns the new
 * offset. */
static int dissect_tns_tpc_call(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint32_t func)
{
	int v = 0, ctx_len = 0, gtrid_len = 0, bqual_len = 0, xid_len = 0;
	int int_len = 0, ext_len = 0, start;
	uint8_t ctx_ptr, xid_ptr, int_ptr = 0, ext_ptr = 0;

	start = offset;
	offset += get_sb4_custom(tvb, offset, &v);
	proto_tree_add_uint(tree, func == TTI_TPC_TXN_SWITCH ? hf_tns_data_tpc_switch_op : hf_tns_data_tpc_change_op,
		tvb, start, offset - start, v);
	col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str_const(v,
		func == TTI_TPC_TXN_SWITCH ? tns_tpc_switch_ops : tns_tpc_change_ops, "unknown"));
	ctx_ptr = tvb_get_uint8(tvb, offset);
	offset += 1;
	offset += get_sb4_custom(tvb, offset, &ctx_len);
	start = offset;
	offset += get_sb4_custom(tvb, offset, &v);
	proto_tree_add_uint(tree, hf_tns_data_tpc_format_id, tvb, start, offset - start, v);
	offset += get_sb4_custom(tvb, offset, &gtrid_len);
	offset += get_sb4_custom(tvb, offset, &bqual_len);
	xid_ptr = tvb_get_uint8(tvb, offset);
	offset += 1;
	offset += get_sb4_custom(tvb, offset, &xid_len);
	if ( func == TTI_TPC_TXN_SWITCH )
	{
		start = offset;
		offset += get_sb4_custom(tvb, offset, &v);
		proto_tree_add_uint(tree, hf_tns_data_tpc_flags, tvb, start, offset - start, v);
		start = offset;
		offset += get_sb4_custom(tvb, offset, &v);
		proto_tree_add_uint(tree, hf_tns_data_tpc_timeout, tvb, start, offset - start, v);
		offset += 3; /* application value, return context and its length pointers */
		int_ptr = tvb_get_uint8(tvb, offset);
		offset += 1;
		offset += get_sb4_custom(tvb, offset, &int_len);
		ext_ptr = tvb_get_uint8(tvb, offset);
		offset += 1;
		offset += get_sb4_custom(tvb, offset, &ext_len);
	}
	else
	{
		start = offset;
		offset += get_sb4_custom(tvb, offset, &v);
		proto_tree_add_uint(tree, hf_tns_data_tpc_timeout, tvb, start, offset - start, v);
		start = offset;
		offset += get_sb4_custom(tvb, offset, &v);
		proto_tree_add_uint(tree, hf_tns_data_tpc_state, tvb, start, offset - start, v);
		offset += 1; /* out state pointer */
		start = offset;
		offset += get_sb4_custom(tvb, offset, &v);
		proto_tree_add_uint(tree, hf_tns_data_tpc_flags, tvb, start, offset - start, v);
	}
	if ( ctx_ptr && ctx_len > 0 )
	{
		proto_tree_add_item(tree, hf_tns_data_tpc_context, tvb, offset, ctx_len, ENC_NA);
		offset += ctx_len;
	}
	if ( xid_ptr && xid_len > 0 )
	{
		if ( gtrid_len >= 0 && bqual_len >= 0 && gtrid_len + bqual_len <= xid_len )
		{
			proto_tree_add_item(tree, hf_tns_data_tpc_gtrid, tvb, offset, gtrid_len, ENC_NA);
			proto_tree_add_item(tree, hf_tns_data_tpc_bqual, tvb, offset + gtrid_len, bqual_len, ENC_NA);
		}
		offset += xid_len;
	}
	if ( func == TTI_TPC_TXN_SWITCH )
	{
		start = offset;
		offset += get_sb4_custom(tvb, offset, &v);
		proto_tree_add_uint(tree, hf_tns_data_tpc_app_value, tvb, start, offset - start, v);
		if ( int_ptr && int_len > 0 )
		{
			proto_tree_add_item(tree, hf_tns_data_tpc_internal_name, tvb, offset, int_len, ENC_UTF_8);
			offset += int_len;
		}
		if ( ext_ptr && ext_len > 0 )
		{
			proto_tree_add_item(tree, hf_tns_data_tpc_external_name, tvb, offset, ext_len, ENC_UTF_8);
			offset += ext_len;
		}
	}
	return offset;
}

/* Decode the body of a piggyback other than close-cursors. Layouts
 * follow python-oracledb's _write_*_piggyback. Sets *walk when the body
 * was understood, so the call behind it can be decoded. Returns the new
 * offset. */
static int dissect_tns_piggyback_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint8_t piggyback_id, bool *walk)
{
	int v = 0, start;
	uint64_t u = 0;

	switch ( piggyback_id )
	{
		case TTI_LOBOPS:
		{
			/* close temporary LOBs: a FREE_TEMP | ARRAY LOB operation
			 * whose locators, each with its own ub2 length prefix, follow
			 * back to back - as many bytes as the total says. */
			int total = 0, op = 0;
			offset += 1;                                   /* pointer */
			start = offset;
			offset += get_sb4_custom(tvb, offset, &total);
			proto_tree_add_uint(tree, hf_tns_data_lob_total_size, tvb, start, offset - start, total);
			offset += 1;                                   /* dest locator pointer */
			offset += get_sb4_custom(tvb, offset, &v);     /* dest locator length */
			offset += get_sb4_custom(tvb, offset, &v);     /* source locator */
			offset += get_sb4_custom(tvb, offset, &v);
			offset += 3;                                   /* offsets, charset */
			start = offset;
			offset += get_sb4_custom(tvb, offset, &op);
			proto_tree_add_uint(tree, hf_tns_data_lob_op, tvb, start, offset - start, op);
			offset += 1;                                   /* scn */
			offset += get_sb4_custom(tvb, offset, &v);     /* losbscn */
			offset += get_ub8_custom(tvb, offset, &u);     /* lobscnl */
			offset += get_ub8_custom(tvb, offset, &u);
			offset += 1;
			for ( int i = 0; i < 3; i++ )                   /* array LOB fields */
			{
				offset += 1;
				offset += get_sb4_custom(tvb, offset, &v);
			}
			if ( total < 0 || (unsigned)total > tvb_reported_length_remaining(tvb, offset) )
			{
				proto_tree_add_expert(tree, pinfo, &ei_tns_data_count_too_large, tvb, offset, 0);
				return offset;
			}
			for ( int end = offset + total; offset + 2 <= end; )
			{
				int len = 2 + tvb_get_ntohs(tvb, offset);
				if ( offset + len > end )
					len = end - offset;
				proto_tree_add_item(tree, hf_tns_data_lob_locator, tvb, offset, len, ENC_NA);
				offset += len;
			}
			break;
		}

		case TTI_SET_SCHEMA:
		{
			const char *schema = NULL;
			offset += 1;                                   /* pointer */
			start = offset;
			offset += get_field_with_length(tvb, pinfo, offset, &schema);
			if ( schema )
				proto_tree_add_string(tree, hf_tns_data_pgy_schema, tvb, start, offset - start, schema);
			break;
		}

		case TTI_SESSION_STATE:
			start = offset;
			offset += get_ub8_custom(tvb, offset, &u);
			proto_tree_add_uint64(tree, hf_tns_data_pgy_session_state, tvb, start, offset - start, u);
			break;

		case TTI_PIPELINE_BEGIN:
			start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_uint(tree, hf_tns_data_pgy_error_set_id, tvb, start, offset - start, v);
			proto_tree_add_item(tree, hf_tns_data_pgy_error_set_mode, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item(tree, hf_tns_data_pgy_pipeline_mode, tvb, offset, 1, ENC_NA);
			offset += 1;
			break;

		case TTI_SET_END_TO_END_ATTR:
		{
			/* End-to-end attributes: a flags word saying which changed,
			 * then a (pointer, length) header for each attribute - some
			 * never used - and finally the strings of those that have a
			 * value, in the same order. */
			static int * const hfs[] = { &hf_tns_data_pgy_client_id, &hf_tns_data_pgy_module,
				&hf_tns_data_pgy_action, NULL, &hf_tns_data_pgy_client_info, NULL, NULL,
				&hf_tns_data_pgy_dbop };
			int lens[array_length(hfs)];

			offset += 2;                                   /* cidnam, cidser pointers */
			start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_uint(tree, hf_tns_data_pgy_e2e_flags, tvb, start, offset - start, v);
			for ( unsigned i = 0; i < array_length(hfs); i++ )
			{
				uint8_t ptr = tvb_get_uint8(tvb, offset);
				offset += 1;
				offset += get_sb4_custom(tvb, offset, &lens[i]);
				if ( !ptr || !hfs[i] )
					lens[i] = 0;
				if ( i == 3 )                                /* cideci is followed by cidcct, cidecs */
				{
					offset += 1;
					offset += get_sb4_custom(tvb, offset, &v);
				}
			}
			for ( unsigned i = 0; i < array_length(hfs); i++ )
			{
				const char *str = NULL;
				if ( lens[i] <= 0 )
					continue;
				start = offset;
				offset += get_dalc_custom(tvb, pinfo, offset, &str);
				if ( str )
					proto_tree_add_string(tree, *hfs[i], tvb, start, offset - start, str);
			}
			break;
		}

		case TTI_END_USER_SEC_CTX:
		{
			/* End-user security context: flags, then key/value pairs, each
			 * a flags word and a key, a text and a value in the
			 * bytes_with_length form. */
			int num = 0;
			start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_uint(tree, hf_tns_data_pgy_sec_flags, tvb, start, offset - start, v);
			offset += 1;                                   /* pointer */
			offset += get_sb4_custom(tvb, offset, &num);
			for ( int i = 0; i < num && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
			{
				const char *key = NULL;
				offset += get_sb4_custom(tvb, offset, &v); /* flags */
				start = offset;
				offset += get_field_with_length(tvb, pinfo, offset, &key);
				if ( key )
					proto_tree_add_string(tree, hf_tns_data_pgy_sec_key, tvb, start, offset - start, key);
				offset += get_field_with_length(tvb, pinfo, offset, NULL); /* text */
				start = offset;
				offset += get_field_with_length(tvb, pinfo, offset, NULL);
				proto_tree_add_item(tree, hf_tns_data_pgy_sec_value, tvb, start, offset - start, ENC_NA);
			}
			break;
		}

		default:
			/* An unknown body has an unknown length. */
			return offset;
	}
	*walk = true;
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

/* State carried from one TTC message to the next within a packet. */
typedef struct _tns_msg_ctx_t {
	/* The decoder ended exactly on its message's last byte. */
	bool walk;
	/* Which columns the next row sends, from a row header or a TTI_BVC:
	 * a clear bit means the value repeats the previous row's. NULL when
	 * every column is sent. */
	const uint8_t *bit_vector;
	unsigned bit_vector_len;
	/* After a TTI_IOV: the call it answers and each bind's direction, so
	 * the TTI_RXD after it can be read as the OUT bind values. */
	const tns_call_t *out_call;
	const uint8_t *bind_dirs;
} tns_msg_ctx_t;

static int dissect_tns_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *data_tree, bool is_request, unsigned data_func_id, tns_msg_ctx_t *ctx);

/* Whether a message that follows another in the same packet is one we
 * step into. A response is a run of messages back to back - a describe,
 * a row header, the rows, a status - and a request may put piggybacks in
 * front of its call. */
static bool tns_is_next_message(unsigned data_func_id, bool is_request)
{
	if ( is_request )
		return data_func_id == SQLNET_USER_OCI_FUNC || data_func_id == SQLNET_PIGGYBACK_FUNC;

	switch ( data_func_id )
	{
		case SQLNET_RETURN_STATUS:
		case SQLNET_FUNCCOMPLETE:
		case SQLNET_WARNING:
		case SQLNET_LOB_FILE_DF:
		case SQLNET_BIT_VECTOR:
		case SQLNET_SERVER_PIGGYBACK:
		case SQLNET_IMPLICIT_RESULTS:
		case SQLNET_TOKEN:
		case SQLNET_END_OF_RESPONSE:
		case SQLNET_ROW_TRANSF_HDR:
		case SQLNET_ROW_TRANSF_DATA:
		case SQLNET_RETURN_OPI_PARAM:
		case SQLNET_IOVEC_4FAST_UPI:
		case SQLNET_DESCRIBE_INFO:
			return true;
		default:
			return false;
	}
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

	/* Once native network encryption is on, a data packet is ciphertext
	 * followed by a padding and a key-fold byte; nothing in it can be
	 * decoded without the session key. */
	if ( tns_is_encrypted(pinfo) && data_func_id != SQLNET_SNS )
	{
		col_append_str(pinfo->cinfo, COL_INFO, ", Encrypted Data");
		proto_tree_add_expert(data_tree, pinfo, &ei_tns_data_encrypted, tvb, offset, tvb_reported_length_remaining(tvb, offset));
		call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, data_tree);
		return;
	}

	/* The field version the connection negotiated decides the shape of
	 * several messages; show the one in force. */
	unsigned fv = tns_field_version(pinfo);
	if ( fv )
		proto_item_set_generated(proto_tree_add_uint(data_tree, hf_tns_data_field_version, tvb, 0, 0, fv));

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

	/* Decode the first message, then step into each one after it for as
	 * long as the previous decoder ended exactly on its last byte. */
	tns_msg_ctx_t ctx = { 0 };
	offset = dissect_tns_message(tvb, offset, pinfo, data_tree, is_request, data_func_id, &ctx);
	while ( ctx.walk && tvb_reported_length_remaining(tvb, offset) > 0 )
	{
		data_func_id = tvb_get_uint8(tvb, offset);
		if ( !tns_is_next_message(data_func_id, is_request) )
			break;
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(data_func_id, tns_data_funcs, "unknown"));
		proto_tree_add_item(data_tree, hf_tns_data_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		ctx.walk = false;
		offset = dissect_tns_message(tvb, offset, pinfo, data_tree, is_request, data_func_id, &ctx);
	}

	if ( tvb_reported_length_remaining(tvb, offset) > 0 )
		call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, data_tree);
}

/* Whether a packet belongs to a conversation whose client speaks the OCI
 * dialect. Stored per packet on the first pass. */
static bool tns_is_oci(packet_info *pinfo)
{
	void *stored = p_get_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_OCI);
	if ( stored || PINFO_FD_VISITED(pinfo) )
		return GPOINTER_TO_UINT(stored) == 2;

	bool oci = tns_get_conv_info(pinfo)->oci_dialect;
	p_add_proto_data(wmem_file_scope(), pinfo, proto_tns, TNS_PROTO_DATA_OCI, GUINT_TO_POINTER(oci ? 2 : 1));
	return oci;
}

/* Decode a server message to an OCI client. Its integers are fixed-width
 * little-endian, so only the status messages, whose layout is known, are
 * decoded; the rest is left to the data dissector. Returns the new
 * offset. */
static int dissect_tns_oci_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *data_tree, unsigned data_func_id)
{
	switch ( data_func_id )
	{
		case SQLNET_RETURN_STATUS:
		{
			/* The OCI status block: 136 bytes, or a compact 24 for a
			 * query's execute status, the end of a fetch and a no-row
			 * status. Offsets count from the message id byte; a field
			 * this decoder skips is a constant or not understood. The
			 * error message follows the full form. */
			proto_tree *oer_tree;
			proto_item *oer_item;
			int base = offset - 1;
			bool full = tvb_reported_length_remaining(tvb, base) >= 136;
			uint32_t err_code;

			if ( tvb_reported_length_remaining(tvb, base) < 24 )
				return offset;
			oer_tree = proto_tree_add_subtree(data_tree, tvb, base, full ? 136 : 24, ett_tns_oer, &oer_item,
				full ? "Oracle Error Return (OCI)" : "Oracle Error Return (OCI, compact)");
			proto_tree_add_item(oer_tree, hf_tns_data_oci_oer_status, tvb, base + 1, 1, ENC_NA);
			proto_tree_add_item(oer_tree, hf_tns_data_oci_oer_seq, tvb, base + 5, 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_int(oer_tree, hf_tns_data_oer_rowcount, tvb, base + 8, 4, (int32_t)tvb_get_letohl(tvb, base + 8));
			err_code = tvb_get_letohl(tvb, base + 12);
			proto_tree_add_int(oer_tree, hf_tns_data_oer_err_code, tvb, base + 12, 4, (int32_t)err_code);
			proto_tree_add_item(oer_tree, hf_tns_data_oci_oer_category, tvb, base + 18, 1, ENC_NA);
			proto_tree_add_item(oer_tree, hf_tns_data_oci_oer_error_pos, tvb, base + 20, 1, ENC_NA);
			proto_tree_add_item(oer_tree, hf_tns_data_oci_oer_command, tvb, base + 22, 1, ENC_NA);
			if ( !full )
				return base + 24;
			/* the sequence number of the call this answers - the client's
			 * own, not the counter at offset 5 */
			proto_tree_add_item(oer_tree, hf_tns_data_oci_oer_call_seq, tvb, base + 49, 2, ENC_LITTLE_ENDIAN);
			offset = base + 136;
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
				proto_item_set_len(oer_item, offset - base);
			}
			return offset;
		}

		case SQLNET_FUNCCOMPLETE:
			/* TTI_STA, answering a commit, a rollback or a logoff: a
			 * ub4 LE call status and a ub2 LE end-to-end sequence */
			if ( !tvb_bytes_exist(tvb, offset, 6) )
				return offset;
			tns_add_call_status_flags(
				proto_tree_add_item(data_tree, hf_tns_data_sta_call_status, tvb, offset, 4, ENC_LITTLE_ENDIAN),
				tvb, offset, 4, tvb_get_letohl(tvb, offset));
			proto_tree_add_item(data_tree, hf_tns_data_sta_seq, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
			return offset + 6;

		default:
			return offset;
	}
}

/* Decode the body of one TTC message, whose id byte has already been
 * consumed. Sets ctx->walk when the decoder ended exactly on the
 * message's last byte, so the caller can step into whatever follows it.
 * Returns the new offset. */
static int dissect_tns_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *data_tree, bool is_request, unsigned data_func_id, tns_msg_ctx_t *ctx)
{
	/* The thin decoders below would misread the fixed-width integers of
	 * a server talking to an OCI client. */
	if ( !is_request && data_func_id != SQLNET_SNS && data_func_id != SQLNET_RETURN_OPI_PARAM
		&& tns_is_oci(pinfo) )
		return dissect_tns_oci_message(tvb, offset, pinfo, data_tree, data_func_id);

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

				return tvb_reported_length(tvb); /* skip call_data_dissector */
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

				/* After the banner: the server's charset (LE), flags, a
				 * count of 5-byte elements (LE), the "fdo" block (a BE
				 * length) whose tail names the national charset, and the
				 * server's compile and runtime capabilities, each behind a
				 * length byte. Capability 7 is the highest TTC field
				 * version the server offers. */
				if ( tvb_reported_length_remaining(tvb, offset) < 5 )
					break;
				proto_tree_add_item(data_tree, hf_tns_data_setp_charset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				proto_tree_add_item(data_tree, hf_tns_data_setp_flags, tvb, offset, 1, ENC_NA);
				offset += 1;
				unsigned num_elem = tvb_get_letohs(tvb, offset);
				offset += 2 + 5 * num_elem;
				unsigned fdo_len = tvb_get_ntohs(tvb, offset);
				offset += 2;
				if ( fdo_len >= 7 )
				{
					unsigned ix = 6 + tvb_get_uint8(tvb, offset + 5) + tvb_get_uint8(tvb, offset + 6);
					if ( ix + 5 <= fdo_len )
						proto_tree_add_item(data_tree, hf_tns_data_setp_ncharset, tvb, offset + ix + 3, 2, ENC_BIG_ENDIAN);
				}
				offset += fdo_len;
				uint8_t caps_len = tvb_get_uint8(tvb, offset);
				proto_tree_add_item(data_tree, hf_tns_data_setp_compile_caps, tvb, offset, 1 + caps_len, ENC_NA);
				if ( caps_len > TNS_CCAP_FIELD_VERSION )
					proto_tree_add_item(data_tree, hf_tns_data_setp_field_version, tvb,
						offset + 1 + TNS_CCAP_FIELD_VERSION, 1, ENC_NA);
				offset += 1 + caps_len;
				caps_len = tvb_get_uint8(tvb, offset);
				proto_tree_add_item(data_tree, hf_tns_data_setp_runtime_caps, tvb, offset, 1 + caps_len, ENC_NA);
				offset += 1 + caps_len;
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
			/* The header opens with the length of the client's compile
			 * capabilities, and capability 7 is the TTC field version.
			 * The client has already lowered it to the server's, so it
			 * is the one the connection uses. */
			if ( tvb_get_uint8(tvb, offset) > TNS_CCAP_FIELD_VERSION )
			{
				uint8_t fv = tvb_get_uint8(tvb, offset + 1 + TNS_CCAP_FIELD_VERSION);
				proto_tree_add_item(caphdr_tree, hf_tns_data_setdt_field_version, tvb,
					offset + 1 + TNS_CCAP_FIELD_VERSION, 1, ENC_NA);
				if ( !PINFO_FD_VISITED(pinfo) )
					tns_get_conv_info(pinfo)->field_version = fv;
			}
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
			tns_add_call_status_flags(
				proto_tree_add_int(oer_tree, hf_tns_data_oer_call_status, tvb, oer_start, offset - oer_start, v),
				tvb, oer_start, offset - oer_start, (uint32_t)v);
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
			/* The status of an execute that opened a new cursor names it:
			 * its bind types now belong to that cursor id. */
			if ( !PINFO_FD_VISITED(pinfo) && v != 0 )
			{
				tns_conv_info_t *tns_info = tns_get_conv_info(pinfo);
				if ( tns_info->pending_binds )
				{
					wmem_map_insert(tns_info->cursor_binds, GUINT_TO_POINTER(v), tns_info->pending_binds);
					tns_info->pending_binds = NULL;
				}
			}
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

			/* From 12.1 the block goes on with the error number and row
			 * count at their full widths (a ub4 and a ub8), and from 20.1
			 * with the SQL type and a server checksum. The extended error
			 * number is the one that says whether a message follows. */
			unsigned fv = tns_field_version(pinfo);
			if ( fv >= TNS_FV_12_1 )
			{
				uint64_t rows = 0;
				int start = offset;
				offset += get_sb4_custom(tvb, offset, &err_code);
				proto_tree_add_uint(oer_tree, hf_tns_data_oer_err_num_ext, tvb, start, offset - start, err_code);
				start = offset;
				offset += get_ub8_custom(tvb, offset, &rows);
				proto_tree_add_uint64(oer_tree, hf_tns_data_oer_rowcount_ext, tvb, start, offset - start, rows);
			}
			if ( fv >= TNS_FV_20_1 )
			{
				int start = offset;
				offset += get_sb4_custom(tvb, offset, &v);
				proto_tree_add_uint(oer_tree, hf_tns_data_oer_sql_type, tvb, start, offset - start, v);
				start = offset;
				offset += get_sb4_custom(tvb, offset, &v);
				proto_tree_add_uint(oer_tree, hf_tns_data_oer_checksum, tvb, start, offset - start, v);
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
			/* With the field version known the block ends where it
			 * should, so an end-of-response marker after it can be read. */
			ctx->walk = fv != 0;
			break;
		}

		case SQLNET_FUNCCOMPLETE:
		{
			/* TTI_STA: a bare status, with no error block. It answers a
			 * commit, a rollback or a logoff: a ub4 call status and the
			 * ub2 end-to-end sequence number. */
			int v = 0, start;

			if ( is_request )
				break;

			start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			tns_add_call_status_flags(
				proto_tree_add_uint(data_tree, hf_tns_data_sta_call_status, tvb, start, offset - start, v),
				tvb, start, offset - start, (uint32_t)v);
			start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_uint(data_tree, hf_tns_data_sta_seq, tvb, start, offset - start, v);
			ctx->walk = true;
			break;
		}

		case SQLNET_LOB_FILE_DF:
		{
			/* LOB content: what a TTI_LOBOPS READ returns, ahead of the
			 * return parameters. Raw bytes for a BLOB or BFILE, the LOB's
			 * character set (usually UTF-16BE) for a CLOB. */
			int start = offset;

			if ( is_request )
				break;

			offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			if ( tvb_get_uint8(tvb, start) == 0xfe ) /* chunked: shown whole */
				proto_tree_add_item(data_tree, hf_tns_data_lob_data, tvb, start, offset - start, ENC_NA);
			else if ( offset - start > 1 )
				proto_tree_add_item(data_tree, hf_tns_data_lob_data, tvb, start + 1, offset - start - 1, ENC_NA);
			ctx->walk = true;
			break;
		}

		case SQLNET_WARNING:
		{
			/* TTI_WRN: a warning that does not fail the call - PL/SQL
			 * compiled with errors, say. A ub2 warning number, a ub2
			 * message length and ub2 flags, then the message itself when
			 * both are non-zero. */
			int code = 0, len = 0, v = 0, start;

			if ( is_request )
				break;

			start = offset;
			offset += get_sb4_custom(tvb, offset, &code);
			proto_tree_add_uint(data_tree, hf_tns_data_wrn_code, tvb, start, offset - start, code);
			start = offset;
			offset += get_sb4_custom(tvb, offset, &len);
			proto_tree_add_uint(data_tree, hf_tns_data_wrn_length, tvb, start, offset - start, len);
			start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_uint(data_tree, hf_tns_data_wrn_flags, tvb, start, offset - start, v);
			if ( code != 0 && len > 0 )
			{
				const char *msg = NULL;
				start = offset;
				offset += get_dalc_custom(tvb, pinfo, offset, &msg);
				if ( msg )
				{
					proto_tree_add_string(data_tree, hf_tns_data_wrn_message, tvb, start, offset - start, msg);
					col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", msg);
				}
			}
			ctx->walk = true;
			break;
		}

		case SQLNET_SERVER_PIGGYBACK:
		{
			/* A piggyback from the server: state it pushes to the client
			 * alongside a reply, selected by an opcode. Layouts follow
			 * python-oracledb's _process_server_side_piggyback. */
			int v = 0, num = 0, start;
			uint8_t opcode;

			if ( is_request )
				break;

			proto_tree_add_item_ret_uint8(data_tree, hf_tns_data_spb_opcode, tvb, offset, 1, ENC_BIG_ENDIAN, &opcode);
			col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
				val_to_str_const(opcode, tns_spb_opcodes, "unknown"));
			offset += 1;
			switch ( opcode )
			{
				case TNS_SPB_QUERY_CACHE_INVALIDATION:
				case TNS_SPB_TRACE_EVENT:
					break;
				case TNS_SPB_LTXID:
					offset += get_sb4_custom(tvb, offset, &v);
					if ( v > 0 )
					{
						start = offset;
						offset += get_dalc_custom(tvb, pinfo, offset, NULL);
						proto_tree_add_item(data_tree, hf_tns_data_spb_ltxid, tvb, start + 1, offset - start - 1, ENC_NA);
					}
					break;
				case TNS_SPB_OS_PID_MTS:
				{
					const char *pid = NULL;
					offset += get_sb4_custom(tvb, offset, &v);
					start = offset;
					offset += get_dalc_custom(tvb, pinfo, offset, &pid);
					if ( pid )
						proto_tree_add_string(data_tree, hf_tns_data_spb_os_pid, tvb, start, offset - start, pid);
					break;
				}
				case TNS_SPB_SYNC:
					/* Session state the statement changed - a new current
					 * schema, edition or NLS setting - as key/value pairs. */
					offset += get_sb4_custom(tvb, offset, &v);  /* number of DTYs */
					offset += 1;                               /* length of DTYs */
					start = offset;
					offset += get_sb4_custom(tvb, offset, &num);
					proto_tree_add_uint(data_tree, hf_tns_data_spb_num_kv, tvb, start, offset - start, num);
					offset += 1;                               /* length */
					offset = dissect_tns_kv_pairs(tvb, pinfo, data_tree, offset, num);
					start = offset;
					offset += get_sb4_custom(tvb, offset, &v);
					proto_tree_add_uint(data_tree, hf_tns_data_spb_flags, tvb, start, offset - start, v);
					break;
				case TNS_SPB_EXT_SYNC:
					offset += get_sb4_custom(tvb, offset, &v);  /* number of DTYs */
					offset += 1;                               /* length of DTYs */
					break;
				case TNS_SPB_AC_REPLAY_CONTEXT:
					offset += get_sb4_custom(tvb, offset, &v);  /* number of DTYs */
					offset += 1;                               /* length of DTYs */
					offset += get_sb4_custom(tvb, offset, &v);  /* flags */
					offset += get_sb4_custom(tvb, offset, &v);  /* error code */
					offset += 1;                               /* queue */
					offset += get_field_with_length(tvb, pinfo, offset, NULL); /* replay context */
					break;
				case TNS_SPB_SESS_RET:
					offset += get_sb4_custom(tvb, offset, &v);  /* number of DTYs */
					offset += 1;                               /* length of DTYs */
					offset += get_sb4_custom(tvb, offset, &num);
					if ( num > 0 )
					{
						offset += 1;
						for ( int i = 0; i < num && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
						{
							offset += get_sb4_custom(tvb, offset, &v);   /* key */
							if ( v > 0 )
								offset += get_dalc_custom(tvb, pinfo, offset, NULL);
							offset += get_sb4_custom(tvb, offset, &v);   /* value */
							if ( v > 0 )
								offset += get_dalc_custom(tvb, pinfo, offset, NULL);
							offset += get_sb4_custom(tvb, offset, &v);   /* flags */
						}
					}
					start = offset;
					offset += get_sb4_custom(tvb, offset, &v);
					proto_tree_add_uint(data_tree, hf_tns_data_spb_flags, tvb, start, offset - start, v);
					start = offset;
					offset += get_sb4_custom(tvb, offset, &v);
					proto_tree_add_uint(data_tree, hf_tns_data_spb_session_id, tvb, start, offset - start, v);
					start = offset;
					offset += get_sb4_custom(tvb, offset, &v);
					proto_tree_add_uint(data_tree, hf_tns_data_spb_serial_num, tvb, start, offset - start, v);
					break;
				case TNS_SPB_SESS_SIGNATURE:
				{
					uint64_t u = 0;
					offset += get_sb4_custom(tvb, offset, &v);  /* number of DTYs */
					offset += 1;                               /* length of DTYs */
					offset += get_ub8_custom(tvb, offset, &u);  /* signature flags */
					offset += get_ub8_custom(tvb, offset, &u);  /* client signature */
					offset += get_ub8_custom(tvb, offset, &u);  /* server signature */
					break;
				}
				default:
					/* Unknown opcode: its length is unknown too. */
					return offset;
			}
			ctx->walk = true;
			break;
		}

		case SQLNET_IMPLICIT_RESULTS:
		{
			/* The result sets a PL/SQL block returned with
			 * DBMS_SQL.RETURN_RESULT: a ub4 count, then per result a
			 * length-prefixed opaque blob, the describe of its columns,
			 * and the ub2 cursor id the client fetches it with. */
			int num = 0, start;

			if ( is_request )
				break;

			start = offset;
			offset += get_sb4_custom(tvb, offset, &num);
			proto_tree_add_uint(data_tree, hf_tns_data_irs_num_results, tvb, start, offset - start, num);
			for ( int i = 0; i < num && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
			{
				proto_tree *rs_tree;
				proto_item *rs_item;
				int rs_start = offset, cursor = 0;

				rs_tree = proto_tree_add_subtree_format(data_tree, tvb, offset, -1,
					ett_tns_irs, &rs_item, "Result Set %d", i + 1);
				offset += 1 + tvb_get_uint8(tvb, offset);
				offset = dissect_tns_describe_body(tvb, pinfo, rs_tree, offset, NULL);
				start = offset;
				offset += get_sb4_custom(tvb, offset, &cursor);
				proto_tree_add_uint(rs_tree, hf_tns_cursor, tvb, start, offset - start, cursor);
				proto_item_append_text(rs_item, ": cursor %d", cursor);
				proto_item_set_len(rs_item, offset - rs_start);
			}
			ctx->walk = true;
			break;
		}

		case SQLNET_TOKEN:
		{
			/* the token of the call this answers */
			uint64_t token = 0;
			int start = offset;

			if ( is_request )
				break;
			offset += get_ub8_custom(tvb, offset, &token);
			proto_tree_add_uint64(data_tree, hf_tns_data_token, tvb, start, offset - start, token);
			ctx->walk = true;
			break;
		}

		case SQLNET_END_OF_RESPONSE:
			/* Marks the end of a response for a client that negotiated
			 * it; there is no body. */
			ctx->walk = true;
			break;

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
			 * bind's declared type to decode, so they are read only when
			 * the execute this answers was seen. */
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

				/* The OUT and IN OUT values follow as a TTI_RXD, typed by
				 * the binds of the execute this answers - readable only
				 * when that execute was seen and bound as many. */
				const tns_call_t *call = tns_answered_call(pinfo);
				if ( call && call->binds && call->num_binds == (uint32_t)num_binds
					&& offset - iov_start == num_binds )
				{
					ctx->out_call = call;
					ctx->bind_dirs = tvb_memdup(pinfo->pool, tvb, iov_start, num_binds);
					ctx->walk = true;
				}
			}
			break;
		}

		case SQLNET_DESCRIBE_INFO:
		{
			/* TTI_DCB: describe (column metadata) for a SELECT result set,
			 * in the Oracle 11g shape: a preamble, then the describe body.
			 * The columns are remembered, once, so a later TTI_RXD can
			 * split its row values. */
			tns_describe_t *desc = NULL;

			if ( is_request )
				break;

			/* describe-info preamble (chunked bytes: cursor uuid + date) */
			offset += get_dalc_custom(tvb, pinfo, offset, NULL);
			offset = dissect_tns_describe_body(tvb, pinfo, data_tree, offset,
				PINFO_FD_VISITED(pinfo) ? NULL : &desc);
			if ( desc )
				tns_get_conv_info(pinfo)->last_describe = desc;
			ctx->walk = true;
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
			/* bit vector: length + [repeated length byte + vector bytes],
			 * saying which columns the first row sends */
			offset += get_sb4_custom(tvb, offset, &bv_len);
			if ( bv_len > 0 )
			{
				offset += 1;       /* repeated length byte */
				proto_tree_add_item(data_tree, hf_tns_data_bit_vector, tvb, offset, bv_len, ENC_NA);
				ctx->bit_vector = tvb_memdup(pinfo->pool, tvb, offset, bv_len);
				ctx->bit_vector_len = bv_len;
				offset += bv_len;  /* bit vector */
			}
			/* rxhrid (bytes_with_length, skip) */
			offset += get_field_with_length(tvb, pinfo, offset, NULL);
			ctx->walk = true;
			break;
		}

		case SQLNET_BIT_VECTOR:
		{
			/* TTI_BVC: which columns the next row sends. A row that
			 * repeats values from the row before sends only the ones that
			 * changed, and the clear bits name those it left out. A ub2
			 * count of columns sent, then one bit per described column. */
			tns_describe_t *desc;
			int v = 0, start;

			if ( is_request )
				break;

			start = offset;
			offset += get_sb4_custom(tvb, offset, &v);
			proto_tree_add_uint(data_tree, hf_tns_data_bvc_num_cols_sent, tvb, start, offset - start, v);
			desc = tns_current_describe(pinfo);
			if ( !desc )
				break;
			unsigned bv_len = (desc->num_cols + 7) / 8;
			proto_tree_add_item(data_tree, hf_tns_data_bit_vector, tvb, offset, bv_len, ENC_NA);
			ctx->bit_vector = tvb_memdup(pinfo->pool, tvb, offset, bv_len);
			ctx->bit_vector_len = bv_len;
			offset += bv_len;
			ctx->walk = true;
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
			 * sits on the first row's first value. A row that follows a
			 * bit vector sends only the columns whose bit is set. */
			tns_describe_t *desc;

			if ( is_request )
				break;

			if ( ctx->bind_dirs )
			{
				/* The OUT and IN OUT bind values of a PL/SQL execute, in
				 * bind order, each followed by its sb4 return code. Out of
				 * a fetch, ROWID and UROWID come as strings and a LONG has
				 * no trailing indicators. */
				proto_tree *ob_tree;
				proto_item *ob_item;
				int ob_start = offset, rc = 0, start;

				ob_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1,
					ett_tns_out_binds, &ob_item, "Out Binds");
				for ( uint32_t i = 0; i < ctx->out_call->num_binds
					&& tvb_reported_length_remaining(tvb, offset) > 0; i++ )
				{
					uint8_t btype = ctx->out_call->binds[i].type;
					if ( ctx->bind_dirs[i] == TNS_BIND_DIR_INPUT )
						continue;
					if ( btype == TNS_DATATYPE_ROWID || btype == TNS_DATATYPE_UROWID
						|| btype == TNS_DATATYPE_LONG )
						btype = TNS_DATATYPE_VARCHAR;
					else if ( btype == TNS_DATATYPE_LONG_RAW )
						btype = TNS_DATATYPE_RAW;
					offset = dissect_tns_value(tvb, pinfo, ob_tree, offset, btype,
						ctx->out_call->binds[i].csform, i + 1,
						hf_tns_data_bind_value, "Bind");
					start = offset;
					offset += get_sb4_custom(tvb, offset, &rc);
					proto_tree_add_int(ob_tree, hf_tns_data_bind_retcode, tvb, start, offset - start, rc);
				}
				proto_item_set_len(ob_item, offset - ob_start);
				ctx->bind_dirs = NULL;
				ctx->walk = true;
				break;
			}

			const tns_call_t *rcall = tns_answered_call(pinfo);
			if ( rcall && rcall->num_return > 0 && rcall->binds )
			{
				/* The values a DML RETURNING ... INTO returned: for each
				 * return bind a ub4 row count - every row the statement
				 * touched - then that many values, each followed by its
				 * sb4 return code. */
				proto_tree *rv_tree;
				proto_item *rv_item;
				int rv_start = offset, rc = 0, start;

				rv_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1,
					ett_tns_out_binds, &rv_item, "Returned Values");
				for ( uint32_t i = rcall->num_binds - rcall->num_return; i < rcall->num_binds
					&& tvb_reported_length_remaining(tvb, offset) > 0; i++ )
				{
					int rows = 0;
					offset += get_sb4_custom(tvb, offset, &rows);
					for ( int j = 0; j < rows && tvb_reported_length_remaining(tvb, offset) > 0; j++ )
					{
						offset = dissect_tns_value(tvb, pinfo, rv_tree, offset, rcall->binds[i].type,
							rcall->binds[i].csform, i + 1, hf_tns_data_bind_value, "Bind");
						start = offset;
						offset += get_sb4_custom(tvb, offset, &rc);
						proto_tree_add_int(rv_tree, hf_tns_data_bind_retcode, tvb, start, offset - start, rc);
					}
				}
				proto_item_set_len(rv_item, offset - rv_start);
				ctx->walk = true;
				break;
			}

			desc = tns_current_describe(pinfo);

			if ( desc && desc->num_cols > 0 )
			{
				int rownum = 0, first_row = 1;
				while ( tvb_reported_length_remaining(tvb, offset) > 0 )
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
						&& tvb_reported_length_remaining(tvb, offset) > 0; c++ )
					{
						const tns_column_t *col = &desc->cols[c];
						if ( ctx->bit_vector && c / 8 < ctx->bit_vector_len
							&& !(ctx->bit_vector[c / 8] & (1 << (c % 8))) )
						{
							proto_tree_add_bytes_format(row_tree, hf_tns_data_col_value,
								tvb, offset, 0, NULL, "Column %u (%s): same as previous row",
								c + 1, val_to_str_const(col->type, tns_data_types, "unknown"));
							continue;
						}
						/* A column the describe gives no data length is
						 * NULL by definition (SELECT NULL, SELECT '')
						 * and sends no bytes at all - not even an empty
						 * DALC. LONG, LONG RAW and UROWID are the
						 * exceptions: they always carry their value. */
						if ( col->data_len == 0 && col->type != TNS_DATATYPE_LONG
							&& col->type != TNS_DATATYPE_LONG_RAW
							&& col->type != TNS_DATATYPE_UROWID )
						{
							proto_tree_add_bytes_format(row_tree, hf_tns_data_col_value,
								tvb, offset, 0, NULL, "Column %u (%s): NULL (no data length)",
								c + 1, val_to_str_const(col->type, tns_data_types, "unknown"));
							continue;
						}
						offset = dissect_tns_value(tvb, pinfo, row_tree, offset,
							col->type, col->csform, c + 1, hf_tns_data_col_value, "Column");
					}
					proto_item_set_len(row_item, offset - r_start);
					/* A bit vector covers one row only. */
					ctx->bit_vector = NULL;
				}
				ctx->walk = true;
			}
			break;
		}

		case SQLNET_USER_OCI_FUNC:
		{
			guint32 oci_id = 0;
			tns_call_t *call;
			int fun_start = offset - 1; /* the TTI_FUN byte */
			proto_tree_add_item_ret_uint(data_tree, hf_tns_data_oci_id, tvb, offset, 1, ENC_BIG_ENDIAN, &oci_id);
			offset += 1;
			call = is_request ? tns_remember_call(pinfo, (uint8_t)oci_id) : NULL;
			/* Name the specific OCI call in the Info column — otherwise every
			 * function call reads only as the generic "User OCI Functions". */
			col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
				val_to_str_ext_const(oci_id, &tns_data_oci_subfuncs_ext, "unknown"));
			proto_tree_add_item(data_tree, hf_tns_data_tseq, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			offset = dissect_tns_call_token(tvb, pinfo, data_tree, offset);
			if((oci_id == 115) || (oci_id == 118)){
				/* The two authentication calls: the session key request
				 * (118) and the authentication itself (115). A pointer
				 * and a ub4 user name length, the ub4 mode, a pointer, the
				 * ub4 number of key/value pairs, two pointers, the user
				 * name, and the pairs - each a key and a value with two
				 * lengths and a ub4 flags word. The first call's pairs
				 * carry the client's identity (program, machine, terminal,
				 * process id, OS user), which is what the server records
				 * for the session; the second's the proof, the driver name
				 * and the session settings. */
				int user_len = 0, mode = 0, num = 0, start;
				proto_tree_add_item(data_tree, hf_tns_data_unused, tvb, offset, 1, ENC_NA);
				offset += 1;
				offset += get_sb4_custom(tvb, offset, &user_len);
				start = offset;
				offset += get_sb4_custom(tvb, offset, &mode);
				proto_tree_add_bitmask_value(data_tree, tvb, start, hf_tns_data_auth_mode,
					ett_tns_auth_mode, tns_auth_modes, (uint64_t)(uint32_t)mode);
				offset += 1; /* pointer */
				start = offset;
				offset += get_sb4_custom(tvb, offset, &num);
				proto_tree_add_uint(data_tree, hf_tns_data_opi_num_of_params, tvb, start, offset - start, num);
				offset += 2; /* pointers */
				if ( user_len > 0 )
				{
					const char *user = NULL;
					start = offset;
					offset += get_dalc_custom(tvb, pinfo, offset, &user);
					if ( user )
					{
						proto_tree_add_string(data_tree, hf_tns_data_auth_user, tvb, start, offset - start, user);
						col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", user);
					}
				}
				for ( int i = 0; i < num && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
				{
					proto_tree *par_tree;
					proto_item *par_ti;
					const char *key = NULL, *value = NULL;
					int v = 0, par_start = offset;

					par_tree = proto_tree_add_subtree_format(data_tree, tvb, offset, -1,
						ett_tns_opi_par, &par_ti, "Parameter %d", i + 1);
					start = offset;
					offset += get_field_with_length(tvb, pinfo, offset, &key);
					if ( key )
						proto_tree_add_string(par_tree, hf_tns_data_opi_param_name, tvb, start, offset - start, key);
					start = offset;
					offset += get_field_with_length(tvb, pinfo, offset, &value);
					if ( value )
						proto_tree_add_string(par_tree, hf_tns_data_opi_param_value, tvb, start, offset - start, value);
					offset += get_sb4_custom(tvb, offset, &v); /* flags */
					if ( key )
						proto_item_append_text(par_ti, ": %s = %s", key, value ? value : "");
					proto_item_set_len(par_ti, offset - par_start);
				}
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
			else if ( oci_id == TTI_PIPELINE_END )
			{
				/* ends a pipeline begun by the pipeline-begin piggyback: a
				 * ub4 id, unused */
				int v = 0;
				offset += get_sb4_custom(tvb, offset, &v);
			}
			else if ( oci_id == TTI_SESSION_RELEASE )
			{
				/* DRCP: hand the session back to the pool - a tag name
				 * (a pointer and a length byte) and the release mode */
				int v = 0, start;
				uint8_t tag_ptr = tvb_get_uint8(tvb, offset);
				uint8_t tag_len = tvb_get_uint8(tvb, offset + 1);
				offset += 2;
				if ( tag_ptr && tag_len > 0 )
				{
					proto_tree_add_item(data_tree, hf_tns_data_release_tag, tvb, offset, tag_len, ENC_UTF_8);
					offset += tag_len;
				}
				start = offset;
				offset += get_sb4_custom(tvb, offset, &v);
				proto_tree_add_bitmask_value(data_tree, tvb, start, hf_tns_data_release_mode,
					ett_tns_release_mode, tns_release_modes, (uint64_t)(uint32_t)v);
			}
			else if ( oci_id == TTI_TPC_TXN_SWITCH || oci_id == TTI_TPC_TXN_CHANGE_STATE )
				offset = dissect_tns_tpc_call(tvb, pinfo, data_tree, offset, oci_id);
			else if ( oci_id == TTI_REEXECUTE || oci_id == TTI_REEXECUTE_AND_FETCH )
			{
				/* Re-execute of a cursor whose statement already ran and
				 * whose bind types did not change: the cursor id, the
				 * iteration count (the prefetch size for 78, the number
				 * of executions for 4) and two options words, then one
				 * TTI_RXD row of values per iteration with no bind
				 * descriptors - the values are typed by the execute that
				 * opened the cursor. */
				int v = 0, cursor = 0, start;

				start = offset;
				offset += get_sb4_custom(tvb, offset, &cursor);
				proto_tree_add_uint(data_tree, hf_tns_cursor, tvb, start, offset - start, cursor);
				start = offset;
				offset += get_sb4_custom(tvb, offset, &v);
				proto_tree_add_uint(data_tree, oci_id == TTI_REEXECUTE_AND_FETCH ?
					hf_tns_data_all8_prefetch : hf_tns_data_reexec_iterations,
					tvb, start, offset - start, v);
				start = offset;
				offset += get_sb4_custom(tvb, offset, &v);
				proto_tree_add_bitmask_value(data_tree, tvb, start, hf_tns_data_all8_options,
					ett_tns_all8_options, tns_all8_options, (uint64_t)(uint32_t)v);
				start = offset;
				offset += get_sb4_custom(tvb, offset, &v);
				proto_tree_add_bitmask_value(data_tree, tvb, start, hf_tns_data_reexec_options2,
					ett_tns_reexec_options2, tns_reexec_options2, (uint64_t)(uint32_t)v);

				tns_binds_t *binds = tns_lookup_cursor_binds(pinfo, cursor);
				if ( binds && tvb_reported_length_remaining(tvb, offset) > 0 )
				{
					proto_item *binds_item;
					proto_tree *binds_tree;
					int binds_start = offset;

					binds_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1,
						ett_tns_binds, &binds_item, "Binds");
					/* RETURNING ... INTO binds send no value */
					offset = dissect_tns_bind_rows(tvb, pinfo, binds_tree, offset, binds->cols,
						binds->count - binds->num_return);
					proto_item_set_len(binds_item, offset - binds_start);
				}
				if ( call && binds )
				{
					call->num_binds = binds->count;
					call->num_return = binds->num_return;
					call->binds = binds->cols;
				}
			}
			else if ( oci_id == TTI_ALL8 && tvb_bytes_exist(tvb, fun_start + TNS_OCI_ALL8_IND, 8)
				&& tvb_get_ntoh64(tvb, fun_start + TNS_OCI_ALL8_IND) == TNS_OCI_INDICATOR )
			{
				/* An OCI client's execute (sqlplus and other thick
				 * clients): a fixed preamble of 8-byte pointer indicators
				 * FE FF FF FF FF FF FF FF with little-endian scalar slots
				 * between them, and the ub1-length-prefixed SQL at the
				 * end. Offsets count from the TTI_FUN byte. The scalar
				 * slots are 8 bytes wide or 4, fixed for a connection;
				 * the second indicator tells which - it sits at 27 in the
				 * wide form and 23 in the narrow one, and the two cannot
				 * both hold. The cursor id and SQL length precede every
				 * slot and do not move; the bind count and the SQL do. */
				int base = fun_start, bind_count_off, sql_off;
				uint32_t cursor, sql_len, bind_count;
				bool wide;

				if ( tvb_bytes_exist(tvb, base + TNS_OCI_ALL8_IND2_WIDE, 8)
					&& tvb_get_ntoh64(tvb, base + TNS_OCI_ALL8_IND2_WIDE) == TNS_OCI_INDICATOR )
					wide = true;
				else if ( tvb_bytes_exist(tvb, base + TNS_OCI_ALL8_IND2_NARROW, 8)
					&& tvb_get_ntoh64(tvb, base + TNS_OCI_ALL8_IND2_NARROW) == TNS_OCI_INDICATOR )
					wide = false;
				else
					break;
				if ( !PINFO_FD_VISITED(pinfo) )
					tns_get_conv_info(pinfo)->oci_dialect = true;

				proto_tree_add_string(data_tree, hf_tns_data_all8_oci_preamble, tvb, base, 0,
					wide ? "OCI, wide (8-byte slots)" : "OCI, narrow (4-byte slots)");
				cursor = tvb_get_letohl(tvb, base + TNS_OCI_ALL8_CURSOR);
				proto_tree_add_uint(data_tree, hf_tns_cursor, tvb, base + TNS_OCI_ALL8_CURSOR, 4, cursor);
				/* three times the SQL length */
				sql_len = tvb_get_letohl(tvb, base + TNS_OCI_ALL8_SQLLEN3) / 3;
				bind_count_off = base + (wide ? 83 : 71);
				sql_off = base + (wide ? 196 : 176);
				bind_count = tvb_get_letohl(tvb, bind_count_off);
				proto_tree_add_uint(data_tree, hf_tns_data_all8_bind_count, tvb, bind_count_off, 4, bind_count);
				if ( sql_len > 0 && tvb_bytes_exist(tvb, sql_off - 1, 1) )
				{
					const char *sql = NULL;
					int start = sql_off - 1;
					uint8_t prefix = tvb_get_uint8(tvb, start);

					if ( prefix == 0xfe || prefix == sql_len )
					{
						offset = start + get_dalc_custom(tvb, pinfo, start, &sql);
						if ( sql )
						{
							/* sqlplus NUL-terminates its own queries; the
							 * string ends there */
							proto_tree_add_string(data_tree, hf_tns_data_all8_sql, tvb, start, offset - start, sql);
							col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", sql);
						}
					}
				}
			}
			else if ( oci_id == TTI_ALL8 )
			{
				/* TTI_ALL8: the generic SQL execute — SELECT, DML and
				 * PL/SQL all ride this call, in the Oracle 11g shape of a
				 * thin client, whose integers use the ub4 variable-length
				 * form. The bind (or define) descriptors and the value
				 * rows follow the al8 array. */
				int v = 0, options = 0, cursor = 0, query_len = 0, all8_len = 0;
				int fetch = 0, bind_count = 0, define_count = 0, start;
				const uint8_t *sql = NULL;
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
				/* define-columns count (ub4) */
				start = offset;
				offset += get_sb4_custom(tvb, offset, &define_count);
				proto_tree_add_uint(data_tree, hf_tns_data_all8_define_count, tvb, start, offset - start, define_count);
				if ( define_count < 0 ||
				     (unsigned)define_count > tvb_reported_length_remaining(tvb, offset) )
				{
					proto_tree_add_expert(data_tree, pinfo, &ei_tns_data_count_too_large,
						tvb, start, offset - start);
					define_count = 0;
				}
				/* registration id (low half), the al8objlist / al8objlen /
				 * al8blv pointers, al8blvl, the al8dnam pointer, al8dnaml
				 * and the registration id's high half */
				offset += get_sb4_custom(tvb, offset, &v);
				offset += 3;
				offset += get_sb4_custom(tvb, offset, &v);
				offset += 1;
				offset += get_sb4_custom(tvb, offset, &v);
				offset += get_sb4_custom(tvb, offset, &v);
				/* 12.1 adds the per-row DML count block (a pointer, the
				 * execution count, a pointer), 12.2 the SQL signature and
				 * SQL id fields, 12.2 ext 1 the chunk ids */
				unsigned fv = tns_field_version(pinfo);
				if ( fv >= TNS_FV_12_1 )
				{
					offset += 1;
					offset += get_sb4_custom(tvb, offset, &v);
					offset += 1;
				}
				if ( fv >= TNS_FV_12_2 )
				{
					offset += 1;
					offset += get_sb4_custom(tvb, offset, &v);
					offset += 1;
					offset += get_sb4_custom(tvb, offset, &v);
					offset += 1;
				}
				if ( fv >= TNS_FV_12_2_EXT1 )
				{
					offset += 1;
					offset += get_sb4_custom(tvb, offset, &v);
				}
				/* SQL text: a flat run of query_len bytes on 11g, length
				 * prefixed (and chunked when long) from 12.1 */
				if ( query_flag && query_len > 0 && fv >= TNS_FV_12_1 )
				{
					const char *text = NULL;
					start = offset;
					offset += get_dalc_custom(tvb, pinfo, offset, &text);
					if ( text )
					{
						sql = (const uint8_t *)text;
						proto_tree_add_string(data_tree, hf_tns_data_all8_sql, tvb, start, offset - start, text);
						col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", text);
					}
				}
				else if ( query_flag && query_len > 0 )
				{
					proto_tree_add_item_ret_string(data_tree, hf_tns_data_all8_sql, tvb,
						offset, query_len, ENC_UTF_8|ENC_NA, pinfo->pool, &sql);
					col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", sql);
					offset += query_len;
				}
				/* al8i4 option array: all8_len ub4 elements. Slot 1 is
				 * the execution count for DML but the number of rows to
				 * prefetch for a query, and slot 7 says which - so read
				 * the array before showing any of it. */
				{
					int al8i4[13] = {0}, al8i4_start[13] = {0}, al8i4_len[13] = {0};
					int i4_start = offset;
					proto_tree *i4_tree;
					proto_item *i4_item;

					for ( int i = 0; i < all8_len && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
					{
						start = offset;
						offset += get_sb4_custom(tvb, offset, &v);
						if ( i < (int)array_length(al8i4) )
						{
							al8i4[i] = v;
							al8i4_start[i] = start;
							al8i4_len[i] = offset - start;
						}
					}
					if ( all8_len >= (int)array_length(al8i4) )
					{
						i4_tree = proto_tree_add_subtree(data_tree, tvb, i4_start, offset - i4_start,
							ett_tns_all8_i4, &i4_item, "Execute Arguments (al8i4)");
						proto_tree_add_uint(i4_tree, al8i4[7] ? hf_tns_data_all8_prefetch : hf_tns_data_all8_iterations,
							tvb, al8i4_start[1], al8i4_len[1], al8i4[1]);
						proto_tree_add_boolean(i4_tree, hf_tns_data_all8_is_query,
							tvb, al8i4_start[7], al8i4_len[7], al8i4[7]);
						proto_tree_add_bitmask_value(i4_tree, tvb, al8i4_start[9], hf_tns_data_all8_exec_flags,
							ett_tns_all8_exec_flags, tns_all8_exec_flags, (uint64_t)(uint32_t)al8i4[9]);
						proto_tree_add_uint(i4_tree, hf_tns_data_all8_fetch_orientation,
							tvb, al8i4_start[10], al8i4_len[10], al8i4[10]);
						proto_tree_add_uint(i4_tree, hf_tns_data_all8_fetch_pos,
							tvb, al8i4_start[11], al8i4_len[11], al8i4[11]);
						if ( call )
							call->exec_flags = (uint32_t)al8i4[9];
					}
				}

				/* Bind section: one bare OAC descriptor per bind column,
				 * then one TTI_RXD row of values per iteration. A cached
				 * re-execute may leave the descriptors out and rely on
				 * the ones the cursor was opened with. Whether they are
				 * there is decided by the wire, not by the SQL text: an
				 * execute with no SQL often still carries them (every
				 * executemany after the first), and they are absent
				 * exactly when the bind area starts on a TTI_RXD, in
				 * which case the types remembered for the cursor apply.
				 *
				 * An execute that opens a new cursor (cursor id 0) learns
				 * its id only from the status that answers it, so its
				 * bind types wait for that. */
				tns_conv_info_t *tns_info = NULL;
				if ( !PINFO_FD_VISITED(pinfo) )
				{
					tns_info = tns_get_conv_info(pinfo);
					if ( cursor == 0 )
						tns_info->pending_binds = NULL;
				}
				if ( bind_count > 0 && tvb_reported_length_remaining(tvb, offset) > 0
					&& tvb_get_uint8(tvb, offset) == SQLNET_ROW_TRANSF_DATA )
				{
					tns_binds_t *binds = cursor ? tns_lookup_cursor_binds(pinfo, cursor) : NULL;
					if ( binds && binds->count == (uint32_t)bind_count )
					{
						if ( call )
						{
							call->num_binds = binds->count;
							call->num_return = binds->num_return;
							call->binds = binds->cols;
						}
						proto_item *binds_item;
						proto_tree *binds_tree;
						int binds_start = offset;

						binds_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1,
							ett_tns_binds, &binds_item, "Binds");
						offset = dissect_tns_bind_rows(tvb, pinfo, binds_tree, offset, binds->cols,
							binds->count - binds->num_return);
						proto_item_set_len(binds_item, offset - binds_start);
					}
				}
				else if ( bind_count > 0 && tvb_reported_length_remaining(tvb, offset) > 0 )
				{
					proto_tree *binds_tree, *bind_tree;
					proto_item *binds_item, *bind_item;
					int binds_start = offset;
					tns_column_t *bcols;

					bcols = wmem_alloc0_array(tns_info ? wmem_file_scope() : pinfo->pool, tns_column_t, bind_count);
					binds_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1,
						ett_tns_binds, &binds_item, "Binds");

					for ( int i = 0; i < bind_count && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
					{
						int b_start = offset;
						uint8_t btype = tvb_get_uint8(tvb, offset);
						bind_tree = proto_tree_add_subtree_format(binds_tree, tvb, offset, -1,
							ett_tns_bind, &bind_item, "Bind %d: %s", i + 1,
							val_to_str_const(btype, tns_data_types, "unknown"));
						offset = dissect_tns_oac(tvb, pinfo, bind_tree, offset, &bcols[i]);
						/* Below 12.2 a CLOB/BLOB bind OAC still carries a
						 * trailing oaccolid byte; from 12.2 every OAC does,
						 * and the OAC decoder reads it. */
						if ( (btype == TNS_DATATYPE_CLOB || btype == TNS_DATATYPE_BLOB)
							&& tns_field_version(pinfo) < TNS_FV_12_2 )
							offset += 1;
						proto_item_set_len(bind_item, offset - b_start);
					}

					/* A DML RETURNING ... INTO statement sends no values for
					 * its return binds, the last ones. */
					unsigned num_return = sql ? tns_count_return_binds((const char *)sql) : 0;
					if ( num_return > (unsigned)bind_count )
						num_return = 0;

					if ( call )
					{
						call->num_binds = bind_count;
						call->num_return = num_return;
						call->binds = bcols;
					}

					/* Remember the types for later executes of the cursor
					 * that leave the descriptors out. */
					if ( tns_info )
					{
						tns_binds_t *binds = wmem_new0(wmem_file_scope(), tns_binds_t);
						binds->count = bind_count;
						binds->num_return = num_return;
						binds->cols = bcols;
						if ( cursor != 0 )
							wmem_map_insert(tns_info->cursor_binds, GUINT_TO_POINTER(cursor), binds);
						else
							tns_info->pending_binds = binds;
					}

					/* Value rows: a TTI_RXD token then one DALC value per bind
					 * column (an ordinary execute sends one row, executemany
					 * sends N), decoded and rendered by the bind's type. */
					offset = dissect_tns_bind_rows(tvb, pinfo, binds_tree, offset, bcols, bind_count - num_return);
					proto_item_set_len(binds_item, offset - binds_start);
				}

				/* Define section: a client that wants a column in some
				 * other form than the describe gave - a CLOB as a string,
				 * say - re-executes the cursor with the DEFINE option and
				 * one OAC per column, in the bind OAC layout. It carries
				 * no binds. */
				if ( define_count > 0 )
				{
					proto_tree *defs_tree, *def_tree;
					proto_item *defs_item, *def_item;
					int defs_start = offset;
					tns_column_t *dcols = NULL;

					if ( !PINFO_FD_VISITED(pinfo) )
						dcols = wmem_alloc0_array(pinfo->pool, tns_column_t, define_count);
					defs_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1,
						ett_tns_defines, &defs_item, "Defines");
					for ( int i = 0; i < define_count && tvb_reported_length_remaining(tvb, offset) > 0; i++ )
					{
						int d_start = offset;
						uint8_t dtype = tvb_get_uint8(tvb, offset);
						def_tree = proto_tree_add_subtree_format(defs_tree, tvb, offset, -1,
							ett_tns_bind, &def_item, "Define %d: %s", i + 1,
							val_to_str_const(dtype, tns_data_types, "unknown"));
						offset = dissect_tns_oac(tvb, pinfo, def_tree, offset, dcols ? &dcols[i] : NULL);
						proto_item_set_len(def_item, offset - d_start);
					}
					proto_item_set_len(defs_item, offset - defs_start);

					/* The rows that answer a define come framed the way
					 * it asked - a CLOB defined as LONG arrives inline,
					 * with no locator - and so do the rows of every later
					 * execute of the cursor. Rows are still split by the
					 * describe's columns, so replace each column's type
					 * with the one its define gives. */
					if ( tns_info && dcols && tns_info->last_describe
						&& tns_info->last_describe->num_cols == (uint32_t)define_count )
					{
						tns_describe_t *desc = wmem_new0(wmem_file_scope(), tns_describe_t);
						desc->num_cols = define_count;
						desc->cols = (tns_column_t *)wmem_memdup(wmem_file_scope(),
							tns_info->last_describe->cols, define_count * sizeof(tns_column_t));
						for ( int i = 0; i < define_count; i++ )
						{
							desc->cols[i].type = dcols[i].type;
							desc->cols[i].csform = dcols[i].csform;
						}
						tns_info->last_describe = desc;
					}
				}
			}
			else if ( oci_id == TTI_LOBOPS )
			{
				/* TTI_LOBOPS: the LOB operation family (read, write, get
				 * length, create/free temp, open/close, BFILE ops). One
				 * common request layout selects behaviour by the operation
				 * opcode:
				 *   ub1 source pointer | ub4 source locator length |
				 *   ub1 dest pointer | ub4 dest length |
				 *   ub4 short source offset | ub4 short dest offset |
				 *   ub1 charset pointer | ub1 short amount pointer |
				 *   ub1 null-LOB pointer | ub4 operation |
				 *   ub1 SCN array pointer | ub1 SCN array length |
				 *   ub8 source offset | ub8 dest offset |
				 *   ub1 amount pointer | 3 x ub2 array-LOB slots (fixed) |
				 *   [locator] | [ub4 charset, CREATE_TEMP] |
				 *   [0x0E and the data, WRITE] | [ub8 amount]
				 * The locator is as long as the source locator length says;
				 * a temporary LOB's carries its own ub2 length prefix, which
				 * that length counts. */
				int v = 0, op = 0, loc_len = 0, start;
				uint8_t src_ptr, charset_ptr, amount_ptr;
				uint64_t u = 0;

				src_ptr = tvb_get_uint8(tvb, offset);
				offset += 1;                              /* source pointer flag */
				offset += get_sb4_custom(tvb, offset, &loc_len); /* source locator length */
				offset += 1;                              /* dest pointer flag */
				offset += get_sb4_custom(tvb, offset, &v); /* dest length */
				offset += get_sb4_custom(tvb, offset, &v); /* short source offset */
				offset += get_sb4_custom(tvb, offset, &v); /* short dest offset */
				charset_ptr = tvb_get_uint8(tvb, offset);
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
				offset += get_ub8_custom(tvb, offset, &u);
				proto_tree_add_uint64(data_tree, hf_tns_data_lob_offset, tvb, start, offset - start, u);
				/* dest offset (ub8, skip) */
				offset += get_ub8_custom(tvb, offset, &u);
				amount_ptr = tvb_get_uint8(tvb, offset);
				offset += 1;                              /* amount pointer flag */
				offset += 6;                              /* array-LOB slots */
				if ( src_ptr && loc_len > 0 )
				{
					proto_tree_add_item(data_tree, hf_tns_data_lob_locator, tvb, offset, loc_len, ENC_NA);
					offset += loc_len;
				}
				if ( charset_ptr )
				{
					start = offset;
					offset += get_sb4_custom(tvb, offset, &v);
					proto_tree_add_uint(data_tree, hf_tns_data_lob_charset, tvb, start, offset - start, v);
				}
				if ( tvb_reported_length_remaining(tvb, offset) > 0
					&& tvb_get_uint8(tvb, offset) == SQLNET_LOB_FILE_DF )
				{
					/* WRITE: a LOB_DATA marker, then the data */
					offset += 1;
					start = offset;
					offset += get_dalc_custom(tvb, pinfo, offset, NULL);
					if ( tvb_get_uint8(tvb, start) == 0xfe ) /* chunked: shown whole */
						proto_tree_add_item(data_tree, hf_tns_data_lob_data, tvb, start, offset - start, ENC_NA);
					else if ( offset - start > 1 )
						proto_tree_add_item(data_tree, hf_tns_data_lob_data, tvb, start + 1, offset - start - 1, ENC_NA);
				}
				if ( amount_ptr )
				{
					start = offset;
					offset += get_ub8_custom(tvb, offset, &u);
					proto_tree_add_uint64(data_tree, hf_tns_data_lob_amount, tvb, start, offset - start, u);
				}
				if ( call )
				{
					call->lob_op = (uint32_t)op;
					call->lob_locator_len = src_ptr ? (uint32_t)loc_len : 0;
					call->lob_amount = amount_ptr != 0;
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
			else if ( !is_request )
			{
				/* Not an authentication reply: an execute answers with
				 * its return parameters. */
				tns_call_t *call = tns_answered_call(pinfo);
				if ( call && (call->func == TTI_ALL8 || call->func == TTI_REEXECUTE
					|| call->func == TTI_REEXECUTE_AND_FETCH) )
				{
					offset = dissect_tns_return_params(tvb, pinfo, data_tree, offset,
						(call->exec_flags & TNS_EXEC_FLAGS_DML_ROWCOUNTS) != 0);
					ctx->walk = true;
				}
				else if ( call && call->func == TTI_TPC_TXN_SWITCH )
				{
					/* the application value and the transaction context
					 * (a ub2 length and the bytes) */
					int v = 0, len = 0, start = offset;
					offset += get_sb4_custom(tvb, offset, &v);
					proto_tree_add_uint(data_tree, hf_tns_data_tpc_app_value, tvb, start, offset - start, v);
					offset += get_sb4_custom(tvb, offset, &len);
					if ( len > 0 )
					{
						proto_tree_add_item(data_tree, hf_tns_data_tpc_context, tvb, offset, len, ENC_NA);
						offset += len;
					}
					ctx->walk = true;
				}
				else if ( call && call->func == TTI_TPC_TXN_CHANGE_STATE )
				{
					int v = 0, start = offset;
					offset += get_sb4_custom(tvb, offset, &v);
					proto_tree_add_uint(data_tree, hf_tns_data_tpc_state, tvb, start, offset - start, v);
					ctx->walk = true;
				}
				else if ( call && call->func == TTI_LOBOPS )
				{
					/* A LOB operation's reply: the locator as the server
					 * now sees it - as long as the one sent, and changed
					 * by a mutating call - then per operation the new
					 * temporary LOB's charset, the amount, or a boolean. */
					uint64_t u = 0;
					int start;

					if ( call->lob_locator_len > 0 )
					{
						proto_tree_add_item(data_tree, hf_tns_data_lob_locator, tvb, offset,
							call->lob_locator_len, ENC_NA);
						offset += call->lob_locator_len;
					}
					if ( call->lob_op == TNS_LOB_OP_CREATE_TEMP )
					{
						int v = 0;
						start = offset;
						offset += get_sb4_custom(tvb, offset, &v);
						proto_tree_add_uint(data_tree, hf_tns_data_lob_charset, tvb, start, offset - start, v);
						offset += 1; /* trailing flags */
					}
					else if ( call->lob_amount )
					{
						start = offset;
						offset += get_ub8_custom(tvb, offset, &u);
						proto_tree_add_uint64(data_tree, hf_tns_data_lob_amount, tvb, start, offset - start, u);
					}
					if ( call->lob_op == TNS_LOB_OP_IS_OPEN || call->lob_op == TNS_LOB_OP_FILE_EXISTS
						|| call->lob_op == TNS_LOB_OP_FILE_ISOPEN )
					{
						proto_tree_add_item(data_tree, hf_tns_data_lob_flag, tvb, offset, 1, ENC_NA);
						offset += 1;
					}
					ctx->walk = true;
				}
			}
			break;
		}

		case SQLNET_PIGGYBACK_FUNC:
		{
			int cursors_len = 0;
			int cursors_start;
			uint8_t piggyback_id = tvb_get_uint8(tvb, offset);
			proto_tree_add_item(data_tree, hf_tns_data_piggyback_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(data_tree, hf_tns_data_tseq, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			offset = dissect_tns_call_token(tvb, pinfo, data_tree, offset);
			/* Only the close-cursors piggyback carries a cursor list:
			 * a pointer byte, a ub4 count, then that many ub4 cursor
			 * ids. The other piggybacks have bodies of their own. */
			if ( piggyback_id != TTI_CLOSE_CURSORS )
			{
				offset = dissect_tns_piggyback_body(tvb, pinfo, data_tree, offset, piggyback_id, &ctx->walk);
				break;
			}
			offset += 1; /* pointer */
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
				int len = get_sb4_custom(tvb, offset, &cursor);
				proto_tree_add_uint(data_tree, hf_tns_cursor, tvb, offset, len, cursor);
				offset += len;
			}
			/* The call this piggyback rides in front of follows it. */
			ctx->walk = true;
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

			uint16_t num_services = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(data_tree, hf_tns_data_sns_srvcnt, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* With encryption picked, the client's next negotiation packet
			 * - its Diffie-Hellman public key - is the last in the clear. */
			if ( is_request && !PINFO_FD_VISITED(pinfo) )
			{
				tns_conv_info_t *tns_info = tns_get_conv_info(pinfo);
				if ( tns_info->ano_encryption && !tns_info->ano_active_after )
					tns_info->ano_active_after = pinfo->num;
			}
			offset += 2;
			proto_tree_add_item(data_tree, hf_tns_data_sns_error, tvb, offset, 1, ENC_NA);
			offset += 1;

			/* Each service: a type, a sub-packet count and an error, then
			 * the sub-packets, each a length, a type and that many bytes
			 * of payload - all big-endian. A service opens with its
			 * version; in the encryption and integrity services the
			 * sub-packet after it lists the algorithms a client offers,
			 * or holds the one the server picked. */
			for ( unsigned i = 0; i < num_services && tvb_bytes_exist(tvb, offset, 8); i++ )
			{
				proto_tree *svc_tree;
				proto_item *svc_item;
				int svc_start = offset;
				uint16_t svc_type = tvb_get_ntohs(tvb, offset);
				uint16_t num_sub = tvb_get_ntohs(tvb, offset + 2);

				svc_tree = proto_tree_add_subtree_format(data_tree, tvb, offset, -1, ett_tns_sns_service,
					&svc_item, "Service: %s", val_to_str_const(svc_type, tns_sns_services, "unknown"));
				proto_tree_add_item(svc_tree, hf_tns_data_sns_service, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(svc_tree, hf_tns_data_sns_subpackets, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(svc_tree, hf_tns_data_sns_svc_error, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
				offset += 8;
				for ( unsigned j = 0; j < num_sub && tvb_bytes_exist(tvb, offset, 4); j++ )
				{
					uint16_t len = tvb_get_ntohs(tvb, offset);
					uint16_t sub_type = tvb_get_ntohs(tvb, offset + 2);
					proto_tree *sub_tree = proto_tree_add_subtree_format(svc_tree, tvb, offset, 4 + len,
						ett_tns_sns_subpacket, NULL, "Sub-packet %u: %s, %u bytes", j + 1,
						val_to_str_const(sub_type, tns_sns_subpacket_types, "unknown"), len);
					proto_tree_add_item(sub_tree, hf_tns_data_sns_sub_type, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
					offset += 4;
					bool algs = j == 1 && (sub_type == TNS_ANO_SP_BYTES || sub_type == TNS_ANO_SP_UB1);
					if ( sub_type == TNS_ANO_SP_VERSION && len == 4 )
						proto_tree_add_item(sub_tree, hf_tns_data_sns_version, tvb, offset, 4, ENC_BIG_ENDIAN);
					else if ( algs && svc_type == TNS_ANO_ENCRYPTION )
					{
						for ( unsigned k = 0; k < len; k++ )
							proto_tree_add_item(sub_tree, hf_tns_data_sns_encryption, tvb, offset + k, 1, ENC_NA);
						/* the server's pick: anything but none turns
						 * encryption on once the client has answered */
						if ( !is_request && !PINFO_FD_VISITED(pinfo) && len == 1 && tvb_get_uint8(tvb, offset) != 0 )
							tns_get_conv_info(pinfo)->ano_encryption = true;
					}
					else if ( algs && svc_type == TNS_ANO_DATA_INTEGRITY )
						for ( unsigned k = 0; k < len; k++ )
							proto_tree_add_item(sub_tree, hf_tns_data_sns_integrity, tvb, offset + k, 1, ENC_NA);
					else if ( len > 0 )
						proto_tree_add_item(sub_tree, hf_tns_data_sns_sub_data, tvb, offset, len, ENC_NA);
					offset += len;
				}
				proto_item_set_len(svc_item, offset - svc_start);
			}
			break;
		}
	}

	return offset;
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

		{ &hf_tns_data_token, {
			"Token", "tns.data.token", FT_UINT64, BASE_DEC,
			NULL, 0x0, "Call token (23ai); the reply echoes it", HFILL }},
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
		{ &hf_tns_data_setp_charset, {
			"Charset", "tns.data_setp_resp.charset", FT_UINT16, BASE_DEC,
			VALS(tns_charsets), 0x0, "The database character set", HFILL }},
		{ &hf_tns_data_setp_flags, {
			"Server Flags", "tns.data_setp_resp.flags", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setp_ncharset, {
			"National Charset", "tns.data_setp_resp.ncharset", FT_UINT16, BASE_DEC,
			VALS(tns_charsets), 0x0, NULL, HFILL }},
		{ &hf_tns_data_setp_compile_caps, {
			"Compile Capabilities", "tns.data_setp_resp.compile_caps", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setp_runtime_caps, {
			"Runtime Capabilities", "tns.data_setp_resp.runtime_caps", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setp_field_version, {
			"Field Version", "tns.data_setp_resp.field_version", FT_UINT8, BASE_DEC,
			VALS(tns_field_versions), 0x0, "The highest TTC field version the server offers", HFILL }},
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
		{ &hf_tns_data_sns_error, {
			"Error", "tns.data_sns.error", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_service, {
			"Service", "tns.data_sns.service", FT_UINT16, BASE_DEC,
			VALS(tns_sns_services), 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_subpackets, {
			"Sub-packets", "tns.data_sns.subpackets", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_svc_error, {
			"Service Error", "tns.data_sns.service_error", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_sub_type, {
			"Sub-packet Type", "tns.data_sns.sub_type", FT_UINT16, BASE_DEC,
			VALS(tns_sns_subpacket_types), 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_version, {
			"Version", "tns.data_sns.version", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_sub_data, {
			"Sub-packet Data", "tns.data_sns.sub_data", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_encryption, {
			"Encryption Algorithm", "tns.data_sns.encryption", FT_UINT8, BASE_DEC,
			VALS(tns_sns_encryption_algs), 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_integrity, {
			"Integrity Algorithm", "tns.data_sns.integrity", FT_UINT8, BASE_DEC,
			VALS(tns_sns_integrity_algs), 0x0, NULL, HFILL }},

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
		{ &hf_tns_data_field_version, {
			"Field Version", "tns.data.field_version", FT_UINT8, BASE_DEC,
			VALS(tns_field_versions), 0x0, "TTC field version in force on the connection", HFILL }},
		{ &hf_tns_data_setdt_field_version, {
			"Field Version", "tns.data_setdt.field_version", FT_UINT8, BASE_DEC,
			VALS(tns_field_versions), 0x0, "TTC field version the connection uses", HFILL }},
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

		{ &hf_tns_data_rpa_num_al8o4, {
			"Number of al8o4 Words", "tns.data_rpa.num_al8o4", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_rpa_al8o4, {
			"al8o4", "tns.data_rpa.al8o4", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_rpa_al8txl, {
			"al8txl", "tns.data_rpa.al8txl", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_rpa_num_kv, {
			"Number of Key/Value Pairs", "tns.data_rpa.num_kv", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_rpa_registration, {
			"Registration", "tns.data_rpa.registration", FT_BYTES, BASE_NONE,
			NULL, 0x0, "Query registration; the last 8 bytes are the query id", HFILL }},
		{ &hf_tns_data_rpa_num_rowcounts, {
			"Number of Row Counts", "tns.data_rpa.num_rowcounts", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_rpa_dml_rowcount, {
			"DML Row Count", "tns.data_rpa.dml_rowcount", FT_UINT64, BASE_DEC,
			NULL, 0x0, "Rows one iteration of an array DML affected", HFILL }},
		{ &hf_tns_data_spb_opcode, {
			"Opcode", "tns.data_spb.opcode", FT_UINT8, BASE_DEC,
			VALS(tns_spb_opcodes), 0x0, NULL, HFILL }},
		{ &hf_tns_data_spb_ltxid, {
			"Logical Transaction Id", "tns.data_spb.ltxid", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_spb_os_pid, {
			"OS PID", "tns.data_spb.os_pid", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_spb_num_kv, {
			"Number of Key/Value Pairs", "tns.data_spb.num_kv", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_spb_flags, {
			"Flags", "tns.data_spb.flags", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_spb_session_id, {
			"Session Id", "tns.data_spb.session_id", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_spb_serial_num, {
			"Serial Number", "tns.data_spb.serial_num", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_kv_text, {
			"Text Value", "tns.data_kv.text", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_kv_binary, {
			"Binary Value", "tns.data_kv.binary", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_kv_keyword, {
			"Keyword", "tns.data_kv.keyword", FT_UINT16, BASE_DEC,
			VALS(tns_kv_keywords), 0x0, NULL, HFILL }},
		{ &hf_tns_data_wrn_code, {
			"Warning Code", "tns.data_wrn.code", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_wrn_length, {
			"Message Length", "tns.data_wrn.length", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_wrn_flags, {
			"Flags", "tns.data_wrn.flags", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_wrn_message, {
			"Message", "tns.data_wrn.message", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_oci_oer_status, {
			"Status", "tns.data_oer.oci_status", FT_UINT8, BASE_DEC,
			VALS(tns_oci_oer_status_vals), 0x0, NULL, HFILL }},
		{ &hf_tns_data_oci_oer_seq, {
			"End-to-End Sequence", "tns.data_oer.seq", FT_UINT16, BASE_DEC,
			NULL, 0x0, "A per-session counter the server advances with each reply", HFILL }},
		{ &hf_tns_data_oci_oer_category, {
			"Statement Category", "tns.data_oer.category", FT_UINT8, BASE_DEC,
			NULL, 0x0, "2 for a statement that produces rows or values, 1 for one that does not", HFILL }},
		{ &hf_tns_data_oci_oer_error_pos, {
			"Error Position", "tns.data_oer.error_pos", FT_UINT8, BASE_DEC,
			NULL, 0x0, "Offset into the SQL text of the parse error", HFILL }},
		{ &hf_tns_data_oci_oer_command, {
			"Command Type", "tns.data_oer.command_type", FT_UINT8, BASE_DEC,
			VALS(tns_command_types), 0x0, NULL, HFILL }},
		{ &hf_tns_data_oci_oer_call_seq, {
			"Call Sequence", "tns.data_oer.call_seq", FT_UINT16, BASE_DEC,
			NULL, 0x0, "Sequence number of the call this status answers", HFILL }},
		{ &hf_tns_data_auth_mode, {
			"Authentication Mode", "tns.data_auth.mode", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_auth_mode_logon, {
			"Logon", "tns.data_auth.mode.logon", FT_BOOLEAN, 32,
			NULL, 0x00000001, NULL, HFILL }},
		{ &hf_tns_data_auth_mode_change_password, {
			"Change Password", "tns.data_auth.mode.change_password", FT_BOOLEAN, 32,
			NULL, 0x00000002, NULL, HFILL }},
		{ &hf_tns_data_auth_mode_sysdba, {
			"SYSDBA", "tns.data_auth.mode.sysdba", FT_BOOLEAN, 32,
			NULL, 0x00000020, NULL, HFILL }},
		{ &hf_tns_data_auth_mode_sysoper, {
			"SYSOPER", "tns.data_auth.mode.sysoper", FT_BOOLEAN, 32,
			NULL, 0x00000040, NULL, HFILL }},
		{ &hf_tns_data_auth_mode_with_password, {
			"With Password", "tns.data_auth.mode.with_password", FT_BOOLEAN, 32,
			NULL, 0x00000100, NULL, HFILL }},
		{ &hf_tns_data_auth_user, {
			"User", "tns.data_auth.user", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_sta_call_status, {
			"Call Status", "tns.data_sta.call_status", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_sta_seq, {
			"End-to-End Sequence", "tns.data_sta.seq", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_call_status_txn, {
			"Transaction in progress", "tns.data.call_status.txn_in_progress", FT_BOOLEAN, 32,
			NULL, TNS_CALL_STATUS_TXN_IN_PROGRESS, NULL, HFILL }},
		{ &hf_tns_data_call_status_sess_release, {
			"Session release", "tns.data.call_status.sess_release", FT_BOOLEAN, 32,
			NULL, TNS_CALL_STATUS_SESS_RELEASE, NULL, HFILL }},
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
		{ &hf_tns_data_oer_err_num_ext, {
			"Error Number", "tns.data_oer.err_num", FT_UINT32, BASE_DEC,
			NULL, 0x0, "The error code at its full width (12.1 and later)", HFILL }},
		{ &hf_tns_data_oer_rowcount_ext, {
			"Row Count (64 bit)", "tns.data_oer.rowcount64", FT_UINT64, BASE_DEC,
			NULL, 0x0, "The row count at its full width (12.1 and later)", HFILL }},
		{ &hf_tns_data_oer_sql_type, {
			"SQL Type", "tns.data_oer.sql_type", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_oer_checksum, {
			"Server Checksum", "tns.data_oer.checksum", FT_UINT32, BASE_HEX,
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

		{ &hf_tns_data_bind_retcode, {
			"Return Code", "tns.data_bind.retcode", FT_INT32, BASE_DEC,
			NULL, 0x0, "Non-zero when an OUT value was truncated", HFILL }},
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

		{ &hf_tns_data_col_uds_flags, {
			"UDS Flags", "tns.data_col.uds_flags", FT_UINT32, BASE_HEX,
			NULL, 0x0, "Marks a JSON column", HFILL }},
		{ &hf_tns_data_col_domain_schema, {
			"Domain Schema", "tns.data_col.domain_schema", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_domain_name, {
			"Domain Name", "tns.data_col.domain_name", FT_STRING, BASE_NONE,
			NULL, 0x0, "The column's SQL domain", HFILL }},
		{ &hf_tns_data_col_annotation, {
			"Annotation", "tns.data_col.annotation", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_vector_dims, {
			"Vector Dimensions", "tns.data_col.vector_dims", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_col_vector_format, {
			"Vector Format", "tns.data_col.vector_format", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_rxh_num_requests, {
			"Number of Requests", "tns.data_rxh.num_requests", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_rxh_iter_num, {
			"Iteration Number", "tns.data_rxh.iter_num", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_bit_vector, {
			"Bit Vector", "tns.data.bit_vector", FT_BYTES, BASE_NONE,
			NULL, 0x0, "Columns the next row sends; a clear bit repeats the previous row's value", HFILL }},
		{ &hf_tns_data_bvc_num_cols_sent, {
			"Columns Sent", "tns.data_bvc.num_cols_sent", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_irs_num_results, {
			"Number of Result Sets", "tns.data_irs.num_results", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_rxh_num_iters, {
			"Number of Iterations", "tns.data_rxh.num_iters", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_all8_options, {
			"Options", "tns.data_all8.options", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_parse, {
			"Parse", "tns.data_all8.options.parse", FT_BOOLEAN, 32,
			NULL, 0x00000001, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_bind, {
			"Bind Values Present", "tns.data_all8.options.bind", FT_BOOLEAN, 32,
			NULL, 0x00000008, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_define, {
			"Define Columns Present", "tns.data_all8.options.define", FT_BOOLEAN, 32,
			NULL, 0x00000010, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_execute, {
			"Execute", "tns.data_all8.options.execute", FT_BOOLEAN, 32,
			NULL, 0x00000020, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_commit, {
			"Autocommit", "tns.data_all8.options.commit", FT_BOOLEAN, 32,
			NULL, 0x00000100, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_plsql, {
			"PL/SQL Binds", "tns.data_all8.options.plsql", FT_BOOLEAN, 32,
			NULL, 0x00000400, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_fetch, {
			"Fetch", "tns.data_all8.options.fetch", FT_BOOLEAN, 32,
			NULL, 0x00000040, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_not_plsql, {
			"Not PL/SQL", "tns.data_all8.options.not_plsql", FT_BOOLEAN, 32,
			NULL, 0x00008000, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_describe, {
			"Describe", "tns.data_all8.options.describe", FT_BOOLEAN, 32,
			NULL, 0x00020000, NULL, HFILL }},
		{ &hf_tns_data_all8_opt_batch_errors, {
			"Batch Errors", "tns.data_all8.options.batch_errors", FT_BOOLEAN, 32,
			NULL, 0x00080000, NULL, HFILL }},
		{ &hf_tns_data_all8_fetch_rows, {
			"Fetch Rows", "tns.data_all8.fetch_rows", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_all8_iterations, {
			"Execution Count", "tns.data_all8.iterations", FT_UINT32, BASE_DEC,
			NULL, 0x0, "Number of times a DML statement runs (array DML)", HFILL }},
		{ &hf_tns_data_all8_prefetch, {
			"Prefetch Rows", "tns.data_all8.prefetch", FT_UINT32, BASE_DEC,
			NULL, 0x0, "Rows a query returns with the execute, before any fetch", HFILL }},
		{ &hf_tns_data_all8_is_query, {
			"Query", "tns.data_all8.is_query", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_all8_exec_flags, {
			"Execute Flags", "tns.data_all8.exec_flags", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_all8_xflag_scrollable, {
			"Scrollable", "tns.data_all8.exec_flags.scrollable", FT_BOOLEAN, 32,
			NULL, 0x00000002, NULL, HFILL }},
		{ &hf_tns_data_all8_xflag_no_cancel_on_eof, {
			"No Cancel on EOF", "tns.data_all8.exec_flags.no_cancel_on_eof", FT_BOOLEAN, 32,
			NULL, 0x00000080, NULL, HFILL }},
		{ &hf_tns_data_all8_xflag_dml_rowcounts, {
			"DML Row Counts", "tns.data_all8.exec_flags.dml_rowcounts", FT_BOOLEAN, 32,
			NULL, 0x00004000, "Return the rows each iteration of an array DML affected", HFILL }},
		{ &hf_tns_data_all8_xflag_implicit_rs, {
			"Implicit Result Sets", "tns.data_all8.exec_flags.implicit_resultset", FT_BOOLEAN, 32,
			NULL, 0x00008000, NULL, HFILL }},
		{ &hf_tns_data_all8_fetch_orientation, {
			"Fetch Orientation", "tns.data_all8.fetch_orientation", FT_UINT32, BASE_HEX,
			VALS(tns_fetch_orientations), 0x0, NULL, HFILL }},
		{ &hf_tns_data_all8_fetch_pos, {
			"Fetch Position", "tns.data_all8.fetch_pos", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_reexec_iterations, {
			"Execution Count", "tns.data_reexec.iterations", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_reexec_options2, {
			"Options 2", "tns.data_reexec.options2", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_reexec_opt2_commit, {
			"Autocommit", "tns.data_reexec.options2.commit", FT_BOOLEAN, 32,
			NULL, 0x00000001, NULL, HFILL }},
		{ &hf_tns_data_all8_oci_preamble, {
			"Preamble", "tns.data_all8.oci_preamble", FT_STRING, BASE_NONE,
			NULL, 0x0, "The fixed execute preamble of an OCI client", HFILL }},
		{ &hf_tns_data_all8_define_count, {
			"Define Count", "tns.data_all8.define_count", FT_UINT32, BASE_DEC,
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
			"Source Offset", "tns.data_lob.offset", FT_UINT64, BASE_DEC,
			NULL, 0x0, "1-based offset into the LOB", HFILL }},
		{ &hf_tns_data_lob_locator, {
			"Locator", "tns.data_lob.locator", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_lob_charset, {
			"Charset", "tns.data_lob.charset", FT_UINT32, BASE_DEC,
			VALS(tns_charsets), 0x0, NULL, HFILL }},
		{ &hf_tns_data_lob_data, {
			"Data", "tns.data_lob.data", FT_BYTES, BASE_NONE,
			NULL, 0x0, "LOB content; UTF-16BE for a CLOB", HFILL }},
		{ &hf_tns_data_lob_total_size, {
			"Total Locator Size", "tns.data_lob.total_size", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_schema, {
			"Current Schema", "tns.data_piggyback.schema", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_session_state, {
			"Session State", "tns.data_piggyback.session_state", FT_UINT64, BASE_HEX,
			NULL, 0x0, "Request boundary: the client begins or ends a request", HFILL }},
		{ &hf_tns_data_pgy_e2e_flags, {
			"Changed Attributes", "tns.data_piggyback.e2e_flags", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_client_id, {
			"Client Identifier", "tns.data_piggyback.client_id", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_module, {
			"Module", "tns.data_piggyback.module", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_action, {
			"Action", "tns.data_piggyback.action", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_client_info, {
			"Client Info", "tns.data_piggyback.client_info", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_dbop, {
			"Database Operation", "tns.data_piggyback.dbop", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_error_set_id, {
			"Error Set Id", "tns.data_piggyback.error_set_id", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_error_set_mode, {
			"Error Set Mode", "tns.data_piggyback.error_set_mode", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_pipeline_mode, {
			"Pipeline Mode", "tns.data_piggyback.pipeline_mode", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_sec_flags, {
			"Security Context Flags", "tns.data_piggyback.sec_flags", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_sec_key, {
			"Security Context Key", "tns.data_piggyback.sec_key", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_pgy_sec_value, {
			"Security Context Value", "tns.data_piggyback.sec_value", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_release_tag, {
			"Tag", "tns.data_release.tag", FT_STRING, BASE_NONE,
			NULL, 0x0, "Session tag for the pool", HFILL }},
		{ &hf_tns_data_release_mode, {
			"Release Mode", "tns.data_release.mode", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_release_mode_deauth, {
			"Deauthenticate", "tns.data_release.mode.deauthenticate", FT_BOOLEAN, 32,
			NULL, 0x00000002, "The session is being closed, not just returned", HFILL }},
		{ &hf_tns_data_tpc_switch_op, {
			"Operation", "tns.data_tpc.switch_op", FT_UINT32, BASE_HEX,
			VALS(tns_tpc_switch_ops), 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_change_op, {
			"Operation", "tns.data_tpc.change_op", FT_UINT32, BASE_HEX,
			VALS(tns_tpc_change_ops), 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_format_id, {
			"XID Format Id", "tns.data_tpc.format_id", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_gtrid, {
			"Global Transaction Id", "tns.data_tpc.gtrid", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_bqual, {
			"Branch Qualifier", "tns.data_tpc.bqual", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_flags, {
			"Flags", "tns.data_tpc.flags", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_timeout, {
			"Timeout", "tns.data_tpc.timeout", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_state, {
			"State", "tns.data_tpc.state", FT_UINT32, BASE_DEC,
			VALS(tns_tpc_states), 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_context, {
			"Transaction Context", "tns.data_tpc.context", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_app_value, {
			"Application Value", "tns.data_tpc.app_value", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_internal_name, {
			"Internal Name", "tns.data_tpc.internal_name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_tpc_external_name, {
			"External Name", "tns.data_tpc.external_name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_lob_flag, {
			"Result", "tns.data_lob.flag", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "Whether the LOB is open, or the file exists", HFILL }},
		{ &hf_tns_data_lob_amount, {
			"Amount", "tns.data_lob.amount", FT_UINT64, BASE_DEC,
			NULL, 0x0, "Characters for a CLOB, bytes for a BLOB; the mode for OPEN", HFILL }},
		{ &hf_tns_data_col_value, {
			"Column Value", "tns.data_col.value", FT_BYTES, BASE_NONE,
			NULL, 0x0, "Raw type-encoded row column value", HFILL }},

		{ &hf_tns_data_lob_size, {
			"LOB Size", "tns.data_lob.size", FT_UINT64, BASE_DEC,
			NULL, 0x0, "Characters for a CLOB, bytes for a BLOB", HFILL }},
		{ &hf_tns_data_lob_chunk_size, {
			"LOB Chunk Size", "tns.data_lob.chunk_size", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_json_image, {
			"OSON Image", "tns.data_json.image", FT_BYTES, BASE_NONE,
			NULL, 0x0, "Binary JSON (OSON) value", HFILL }},
		{ &hf_tns_data_vector_image, {
			"Vector Image", "tns.data_vector.image", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_obj_toid, {
			"Type OID", "tns.data_obj.toid", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_obj_image, {
			"Object Image", "tns.data_obj.image", FT_BYTES, BASE_NONE,
			NULL, 0x0, "Packed object attributes, or an XMLType document", HFILL }},
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
		&ett_tns_call_status,
		&ett_tns_auth_mode,
		&ett_tns_sns_service,
		&ett_tns_sns_subpacket,
		&ett_tns_release_mode,
		&ett_tns_rpa,
		&ett_tns_kv,
		&ett_tns_iov,
		&ett_tns_dcb_col,
		&ett_tns_all8_options,
		&ett_tns_all8_i4,
		&ett_tns_all8_exec_flags,
		&ett_tns_binds,
		&ett_tns_bind,
		&ett_tns_defines,
		&ett_tns_reexec_options2,
		&ett_tns_bind_row,
		&ett_tns_rxd_row,
		&ett_tns_value,
		&ett_tns_irs,
		&ett_tns_out_binds,
		&ett_sql
	};

	static ei_register_info ei[] = {
		{ &ei_tns_connect_data_next_packet, { "tns.connect_data.next_packet", PI_REQUEST_CODE, PI_CHAT, "Long Connect Data (> 221 bytes) carried in subsequent Data packet", EXPFILL }},
		{ &ei_tns_data_descriptor_size_mismatch, { "tns.data_descriptor.size_mismatch", PI_PROTOCOL, PI_WARN, "Data size from summing row sizes differs from size in descriptor", EXPFILL }},
		{ &ei_tns_data_piggyback_cursors, { "tns.data.piggyback.cursors.invalid", PI_MALFORMED, PI_ERROR, "Cursor count is larger than the data left in the packet", EXPFILL }},
		{ &ei_tns_data_count_too_large, { "tns.data.count.invalid", PI_MALFORMED, PI_ERROR, "Count is larger than the data left in the packet", EXPFILL }},
		{ &ei_tns_data_encrypted, { "tns.data.encrypted", PI_DECRYPTION, PI_NOTE, "Encrypted by native network encryption", EXPFILL }},
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
