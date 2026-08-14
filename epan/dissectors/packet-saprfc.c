/* packet-saprfc.c
 * Routines for SAP RFC (SAP Remote Function Call Protocol) dissection
 * Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
 * Code contributed by SecureAuth Corp.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wsutil/wmem/wmem.h>
#include <wsutil/saplzclzh.h>

/*
 * Define default ports. The right range should be 33NN, but as port numbers are proprietary and not
 * IANA assigned, we leave only the one corresponding to the instance 00.
 */
#define SAPRFC_PORT_RANGE "3300"

#define SAPRFC_DEFAULT_MAX_UNCOMPRESSED_SIZE (16U * 1024U * 1024U)
#define SAPRFC_DEFAULT_MAX_REASSEMBLED_SIZE (16U * 1024U * 1024U)
#define SAPRFC_TABLE_PREFIX_LENGTH 8U
#define SAPRFC_APPC_HEADER_LEN 96U
#define SAPRFC_NORMAL_CLIENT_HEADER_LEN_V1 64U
#define SAPRFC_NORMAL_CLIENT_HEADER_LEN_V3 80U


/* SAP RFC Request Types field values */
static const value_string saprfc_reqtype_values[] = {
	{ 0x00, "GW_UNDEF_TYPE" },
	{ 0x01, "GW_CHECK_GATEWAY" },
	{ 0x02, "GW_CONNECT_GWWP" },
	{ 0x03, "GW_NORMAL_CLIENT" },
	{ 0x04, "GW_REMOTE_GATEWAY" },
	{ 0x05, "STOP_GATEWAY" },
	{ 0x06, "GW_LOCAL_R3" },
	{ 0x07, "GW_SEND_INTERNAL_ERROR" },
	{ 0x08, "GW_SEND_INFO" },
	{ 0x09, "GW_SEND_CMD" },
	{ 0x0a, "GW_WORKPROCESS_DIED" },
	{ 0x0b, "GW_REGISTER_TP" },
	{ 0x0c, "GW_UNREGISTER_TP" },
	{ 0x0d, "GW_CONNECT_DISP" },
	{ 0x0e, "GW_GET_NO_REGISTER_TP" },
	{ 0x0f, "GW_SAP_WP_CLIENT" },
	{ 0x10, "GW_CANCEL_REGISTER_TP" },
	{ 0x11, "REMOTE_GATEWAY" },
	{ 0x12, "GW_CONTAINER_RECEIVED" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP RFC Monitor Command field values */
static const value_string saprfc_monitor_cmd_values[] = {
	{ 0x01, "NOOP" },
	{ 0x02, "DELETE_CONN" },
	{ 0x03, "CANCEL_CONN" },
	{ 0x04, "RST_SINGLE_ERR_CNT" },
	{ 0x05, "RST_ALL_ERR_CNT" },
	{ 0x06, "INCREASE_TRACE" },
	{ 0x07, "DECREASE_TRACE" },
	{ 0x08, "READ_SEC_INFO" },
	{ 0x09, "REFRESH_SEC_INFO" },
	{ 0x0a, "READ_GWSYS_TBL" },
	{ 0x0b, "READ_CONN_TBL" },
	{ 0x0c, "READ_PROC_TBL" },
	{ 0x0d, "READ_CONN_ATTR" },
	{ 0x0e, "READ_MEMORY" },
	{ 0x0f, "READ_REQ_BLK" },
	{ 0x10, "ACT_STATISTIC" },
	{ 0x11, "DEACT_STATISTIC" },
	{ 0x12, "READ_STATISTIC" },
	{ 0x13, "RESET_STATISTIC" },
	{ 0x14, "READ_PARAMETER" },
	{ 0x19, "DUMP_NIBUFFER" },
	{ 0x20, "RESET_NIBUFFER" },
	{ 0x21, "ACT_EXTPGM_TRACE" },
	{ 0x22, "DEACT_EXTPGM_TRACE" },
	{ 0x23, "ACT_CONN_TRACE" },
	{ 0x24, "DEACT_CONN_TRACE" },
	{ 0x25, "RESET_TRACE" },
	{ 0x26, "SUICIDE" },
	{ 0x27, "READ_SEC_INFO2" },
	{ 0x28, "CANCEL_REG_TP" },
	{ 0x29, "DUMP" },
	{ 0x2a, "READ_GWSYS_TBL2" },
	{ 0x2b, "CHANGE_PARAMETER" },
	{ 0x2c, "GET_CONN_PARTNER" },
	{ 0x2d, "DELETE_CLIENT" },
	{ 0x2e, "DELETE_REMGW" },
	{ 0x2f, "DISCONNECT" },
	{ 0x30, "ENABLE_RESTART" },
	{ 0x31, "DISABLE_RESTART" },
	{ 0x32, "NI_TRACE" },
	{ 0x33, "CLI_INFO" },
	{ 0x34, "GW_INFO" },
	{ 0x35, "CONVID_INFO" },
	{ 0x36, "GET_NO_REG_TP" },
	{ 0x37, "CV_INFO" },
	{ 0x38, "SO_KEEPALIVE" },
	{ 0x39, "READ_CONN_TBL2" },
	{ 0x40, "READ_GWSYS_TBL3" },
	{ 0x41, "RELOAD_ACL" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP RFC APPC Header Request Type field values */
static const value_string saprfc_header_reqtype_values[] = {
	{ 0x00, "F_NO_REQUEST" },
	{ 0x01, "F_INITIALIZE_CONVERSATION" },
	{ 0x03, "F_ACCEPT_CONVERSATION" },
	{ 0x05, "F_ALLOCATE" },
	{ 0x07, "F_SEND_DATA" },
	{ 0x08, "F_ASEND_DATA" },
	{ 0x09, "F_RECEIVE" },
	{ 0x0a, "F_ARECEIVE" },
	{ 0x0b, "F_DEALLOCATE" },
	{ 0x0d, "F_SET_TP_NAME" },
	{ 0x0f, "F_SET_PARTNER_LU_NAME" },
	{ 0x11, "F_SET_SECURITY_PASSWORD" },
	{ 0x13, "F_SET_SECURITY_USER_ID" },
	{ 0x15, "F_SET_SECURITY_TYPE" },
	{ 0x17, "F_SET_CONVERSATION_TYPE" },
	{ 0x19, "F_EXTRACT_TP_NAME" },
	{ 0x1b, "F_FLUSH" },
	{ 0xc9, "F_SAP_ALLOCATE" },
	{ 0xca, "F_SAP_INIT" },
	{ 0xcb, "F_SAP_SEND" },
	{ 0xcc, "F_ASAP_SEND" },
	{ 0xcd, "F_SAP_SYNC" },
	{ 0xce, "F_SAP_PING" },
	{ 0xcf, "F_SAP_REGTP" },
	{ 0xd0, "F_SAP_UNREGTP" },
	{ 0xd1, "F_SAP_ACCPTP" },
	{ 0xd2, "F_SAP_UNACCPTP" },
	{ 0xd3, "F_SAP_CANCTP" },
	{ 0xd4, "F_SAP_SET_UID" },
	{ 0xd5, "F_SAP_CANCEL" },
	{ 0xd6, "F_SAP_CANCELED" },
	/* NULL */
	{ 0x00, NULL }
};


/* SAP RFC APPC Header Protocol field values */
static const value_string saprfc_header_protocol_values[] = {
	{ 0x00, "R2PR" },
	{ 0x01, "INT" },
	{ 0x02, "EXT" },
	{ 0x03, "CPIC" },
	{ 0x05, "NE" },
	{ 0x06, "REG" },
	{ 0x42, "CPIC" },
	{ 0x44, "EXT" },
	{ 0x45, "NE" },
	{ 0x48, "INT" },
	{ 0x61, "REG" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP RFC APPC Header APPC Return Code field values */
static const value_string saprfc_header_appc_rc_values[] = {
	{ 0x00, "CM_OK" },
	{ 0x01, "CM_ALLOCATE_FAILURE_NO_RETRY" },
	{ 0x02, "CM_ALLOCATE_FAILURE_RETRY" },
	{ 0x03, "CM_CONVERSATION_TYPE_MISMATCH" },
	{ 0x06, "CM_SECURITY_NOT_VALID" },
	{ 0x08, "CM_SYNC_LVL_NOT_SUPPORTED_PGM" },
	{ 0x09, "CM_TPN_NOT_RECOGNIZED" },
	{ 0x0a, "CM_TP_NOT_AVAILABLE_NO_RETRY" },
	{ 0x0b, "CM_TP_NOT_AVAILABLE_RETRY" },
	{ 0x11, "CM_DEALLOCATED_ABEND" },
	{ 0x12, "CM_DEALLOCATED_NORMAL" },
	{ 0x13, "CM_PARAMETER_ERROR" },
	{ 0x14, "CM_PRODUCT_SPECIFIC_ERROR" },
	{ 0x15, "CM_PROGRAM_ERROR_NO_TRUNC" },
	{ 0x16, "CM_PROGRAM_ERROR_PURGING" },
	{ 0x17, "CM_PROGRAM_ERROR_TRUNC" },
	{ 0x18, "CM_PROGRAM_PARAMETER_CHECK" },
	{ 0x19, "CM_PROGRAM_STATE_CHECK" },
	{ 0x1a, "CM_RESOURCE_FAILURE_NO_RETRY" },
	{ 0x1b, "CM_RESOURCE_FAILURE_RETRY" },
	{ 0x1c, "CM_UNSUCCESSFUL" },
	{ 0x23, "CM_OPERATION_INCOMPLETE" },
	{ 0x24, "CM_SYSTEM_EVENT" },
	{ 0x2711, "CM_SAP_TIMEOUT_RETRY" },
	{ 0x2712, "CM_CANCEL_REQUEST" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP RFC APPC Header MCPIC Parameters Client Info values */
static const value_string saprfc_header_ncpic_parameters_client_info_values[] = {
	{ 0x00, "GW_NO_CLIENT_INFO" },
	{ 0x01, "GW_EXTERNAL_CLIENT" },
	{ 0x02, "GW_R3_CLIENT" },
	/* NULL */
	{ 0x00, NULL }
};

/* ABAP/4 data types, taken from RFC SDK's saprfc.h */
#define TYPC			0
#define TYPDATE			1
#define TYPP			2
#define TYPTIME			3
#define TYPX			4
#define TYPTABH			5
#define TYPNUM			6
#define TYPFLOAT		7
#define TYPINT			8
#define TYPINT2			9
#define TYPINT1			10
/* TYPW = 11 */
#define TYP1			12
#define TYP2			13
#define TYPDECF16		23	/* IEEE 754r decimal floating point 8 bytes  */
#define TYPDECF34		24	/* IEEE 754r decimal floating point 16 bytes */

static const value_string abap_types_typename_values[] = {
	{ TYPC, "CHAR" },
	{ TYPDATE, "DATS" },
	{ TYPP, "BCD" },
	{ TYPTIME, "TIMS" },
	{ TYPX, "RAW" },
	{ TYPTABH, "ITAB" },
	{ TYPNUM, "NUMC" },
	{ TYPFLOAT, "FLTP" },
	{ TYPINT, "INT" },
	{ TYPINT2, "INT2" },
	{ TYPINT1, "INT1" },
	{ TYP1, "DATE_1" },
	{ TYP2, "DATE_2" },
	{ TYPDECF16, "DECF16" },
	{ TYPDECF34, "DECF34" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP RFC Accept Info Flag values */
#define SAPRFC_ACCEPT_INFO_EINFO						0x01
#define SAPRFC_ACCEPT_INFO_PING							0x02
#define SAPRFC_ACCEPT_INFO_SNC							0x04
#define SAPRFC_ACCEPT_INFO_CONN_EINFO					0x08
#define SAPRFC_ACCEPT_INFO_CODE_PAGE					0x10
#define SAPRFC_ACCEPT_INFO_NIPING						0x20
#define SAPRFC_ACCEPT_INFO_EXTINITOPT					0x40
#define SAPRFC_ACCEPT_INFO_GW_ACCEPT_DIST_TRACE			0x80

/* SAP RFC APPC Header Info Flags values */
#define SAPRFC_APPCHDR_INFO1_SYNC_CPIC_FUNCTION			0x01
#define SAPRFC_APPCHDR_INFO1_WITH_HOSTADDR				0x02
#define SAPRFC_APPCHDR_INFO1_WITH_GW_SAP_PARAMS_HDR		0x04
#define SAPRFC_APPCHDR_INFO1_CPIC_SYNC_REQ				0x08
#define SAPRFC_APPCHDR_INFO1_WITH_ERR_INFO				0x10
#define SAPRFC_APPCHDR_INFO1_DATA_WITH_TERM_OUTPUT		0x20
#define SAPRFC_APPCHDR_INFO1_DATA_WITH_TERM_INPUT		0x40
#define SAPRFC_APPCHDR_INFO1_R3_CPIC_LOGIN_WITH_TERM	0x80

#define SAPRFC_APPCHDR_INFO2_WITH_LONG_LU_NAME			0x01
#define SAPRFC_APPCHDR_INFO2_WITH_LONG_HOSTADDR			0x02
#define SAPRFC_APPCHDR_INFO2_GW_IMMEDIATE				0x04
#define SAPRFC_APPCHDR_INFO2_GW_SNC_ACTIVE				0x08
#define SAPRFC_APPCHDR_INFO2_GW_WAIT_LOOK_UP			0x10
#define SAPRFC_APPCHDR_INFO2_SNC_INIT_PHASE				0x20
#define SAPRFC_APPCHDR_INFO2_GW_STATELESS				0x40
#define SAPRFC_APPCHDR_INFO2_GW_NO_STATE_CHECK			0x80

#define SAPRFC_APPCHDR_INFO3_GW_WITH_CODE_PAGE 			0x01
#define SAPRFC_APPCHDR_INFO3_GW_ASYNC_RFC				0x02
#define SAPRFC_APPCHDR_INFO3_GW_CANCEL_HARD				0x04
#define SAPRFC_APPCHDR_INFO3_GW_CANCEL_SOFT				0x08
#define SAPRFC_APPCHDR_INFO3_GW_WITH_GUI_TIMEOUT		0x10
#define SAPRFC_APPCHDR_INFO3_GW_TERMIO_ERROR			0x20
#define SAPRFC_APPCHDR_INFO3_GW_EXTENDED_INIT_OPTIONS	0x40
#define SAPRFC_APPCHDR_INFO3_GW_DIST_TRACE				0x80

#define SAPRFC_APPCHDR_INFO4_GW_WITH_DBG_CTL 			0x01

/* SAP RFC APPC Header Request Type 2 Flags values */
#define SAPRFC_APPCHDR_REQTYPE2_F_V_INITIALIZE_CONVERSATION	0x01
#define SAPRFC_APPCHDR_REQTYPE2_F_V_ALLOCATE				0x02
#define SAPRFC_APPCHDR_REQTYPE2_F_V_SEND_DATA				0x04
#define SAPRFC_APPCHDR_REQTYPE2_F_V_RECEIVE					0x08
#define SAPRFC_APPCHDR_REQTYPE2_F_V_FLUSH					0x10


static int proto_saprfc;

static int hf_saprfc_version;
static int hf_saprfc_reqtype;
static int hf_saprfc_address;
static int hf_saprfc_service;
static int hf_saprfc_codepage;
static int hf_saprfc_lu;
static int hf_saprfc_tp;
static int hf_saprfc_conversation_id;
static int hf_saprfc_appc_header_version;
static int hf_saprfc_accept_info;  /* (EINFO PING CONN_EINFO EXTINITOPT GW_ACCEPT_DIST_TRACE (0xCB)) */
static int hf_saprfc_accept_info_EINFO;
static int hf_saprfc_accept_info_PING;
static int hf_saprfc_accept_info_SNC;
static int hf_saprfc_accept_info_CONN_EINFO;
static int hf_saprfc_accept_info_CODE_PAGE;
static int hf_saprfc_accept_info_NIPING;
static int hf_saprfc_accept_info_EXTINITOPT;
static int hf_saprfc_accept_info_GW_ACCEPT_DIST_TRACE;
static int hf_saprfc_idx;
static int hf_saprfc_address6;
static int hf_saprfc_rc;
static int hf_saprfc_echo_data;
static int hf_saprfc_filler;

static int hf_saprfc_monitor_cmd;

static int hf_saprfc_header;
static int hf_saprfc_header_version;
static int hf_saprfc_header_reqtype;
static int hf_saprfc_header_protocol;
static int hf_saprfc_header_mode;
static int hf_saprfc_header_uid;
static int hf_saprfc_header_gw_id;
static int hf_saprfc_header_err_len;
static int hf_saprfc_header_info2;
static int hf_saprfc_header_info2_WITH_LONG_LU_NAME;
static int hf_saprfc_header_info2_WITH_LONG_HOSTADDR;
static int hf_saprfc_header_info2_GW_IMMEDIATE;
static int hf_saprfc_header_info2_GW_SNC_ACTIVE;
static int hf_saprfc_header_info2_GW_WAIT_LOOK_UP;
static int hf_saprfc_header_info2_SNC_INIT_PHASE;
static int hf_saprfc_header_info2_GW_STATELESS;
static int hf_saprfc_header_info2_GW_NO_STATE_CHECK;
static int hf_saprfc_header_trace_level;
static int hf_saprfc_header_time;
static int hf_saprfc_header_info3;
static int hf_saprfc_header_info3_GW_WITH_CODE_PAGE;
static int hf_saprfc_header_info3_GW_ASYNC_RFC;
static int hf_saprfc_header_info3_GW_CANCEL_HARD;
static int hf_saprfc_header_info3_GW_CANCEL_SOFT;
static int hf_saprfc_header_info3_GW_WITH_GUI_TIMEOUT;
static int hf_saprfc_header_info3_GW_TERMIO_ERROR;
static int hf_saprfc_header_info3_GW_EXTENDED_INIT_OPTIONS;
static int hf_saprfc_header_info3_GW_DIST_TRACE;
static int hf_saprfc_header_timeout;
static int hf_saprfc_header_info4;
static int hf_saprfc_header_info4_GW_WITH_DBG_CTL;
static int hf_saprfc_header_sequence_no;
static int hf_saprfc_header_sap_params_len;
static int hf_saprfc_header_info;
static int hf_saprfc_header_info_SYNC_CPIC_FUNCTION;
static int hf_saprfc_header_info_WITH_HOSTADDR;
static int hf_saprfc_header_info_WITH_GW_SAP_PARAMS_HDR;
static int hf_saprfc_header_info_CPIC_SYNC_REQ;
static int hf_saprfc_header_info_WITH_ERR_INFO;
static int hf_saprfc_header_info_DATA_WITH_TERM_OUTPUT;
static int hf_saprfc_header_info_DATA_WITH_TERM_INPUT;
static int hf_saprfc_header_info_R3_CPIC_LOGIN_WITH_TERM;
static int hf_saprfc_header_reqtype2;
static int hf_saprfc_header_reqtype2_F_V_INITIALIZE_CONVERSATION;
static int hf_saprfc_header_reqtype2_F_V_ALLOCATE;
static int hf_saprfc_header_reqtype2_F_V_SEND_DATA;
static int hf_saprfc_header_reqtype2_F_V_RECEIVE;
static int hf_saprfc_header_reqtype2_F_V_FLUSH;
static int hf_saprfc_header_appc_rc;
static int hf_saprfc_header_sap_rc;  /* TODO: Add SAP Return values */
static int hf_saprfc_header_conversation_id;
static int hf_saprfc_header_ncpic_parameters;
static int hf_saprfc_header_ncpic_parameters_sdest;
static int hf_saprfc_header_ncpic_parameters_lu;
static int hf_saprfc_header_ncpic_parameters_tp;
static int hf_saprfc_header_ncpic_parameters_ctype;
static int hf_saprfc_header_ncpic_parameters_client_info;
static int hf_saprfc_header_ncpic_parameters_lu_name;
static int hf_saprfc_header_ncpic_parameters_lu_name_length;
static int hf_saprfc_header_ncpic_parameters_host_address;
static int hf_saprfc_header_ncpic_parameters_security_password;
static int hf_saprfc_header_ncpic_parameters_security_password_length;

static int hf_saprfc_header_comm_idx;
static int hf_saprfc_header_conn_idx;

static int hf_saprfc_item;
static int hf_saprfc_item_id1;
static int hf_saprfc_item_id2;
static int hf_saprfc_item_length;
static int hf_saprfc_item_value;

static int hf_saprfc_table;
static int hf_saprfc_table_structure;
static int hf_saprfc_table_structure_field;
static int hf_saprfc_table_structure_field_type;
static int hf_saprfc_table_structure_field_length;
static int hf_saprfc_table_row;
static int hf_saprfc_table_row_field;
static int hf_saprfc_table_length;
static int hf_saprfc_table_compress_header;
static int hf_saprfc_table_uncomplength;
static int hf_saprfc_table_algorithm;
static int hf_saprfc_table_magic;
static int hf_saprfc_table_special;
static int hf_saprfc_table_return_code;
static int hf_saprfc_table_content;

static int hf_saprfc_payload;


/* TODO: Add CPIC error codes (https://launchpad.support.sap.com/#/notes/63347) */
/* TODO: Add RFC logon error codes (https://launchpad.support.sap.com/#/notes/320991) */

static int ett_saprfc;

/* Expert info */
static expert_field ei_saprfc_invalid_decompression;
static expert_field ei_saprfc_invalid_decompress_length;
static expert_field ei_saprfc_invalid_table_length;
static expert_field ei_saprfc_item_length_invalid;
static expert_field ei_saprfc_unknown_item;
static expert_field ei_saprfc_short_appc_header;


/* Global decompress preference */
static bool global_saprfc_decompress = true;
static unsigned global_saprfc_max_uncompressed_size = SAPRFC_DEFAULT_MAX_UNCOMPRESSED_SIZE;

/* Global table reassembling preference */
static bool global_saprfc_table_reassembly = true;
static unsigned global_saprfc_max_reassembled_size = SAPRFC_DEFAULT_MAX_REASSEMBLED_SIZE;

/* Global highlight preference */
static bool global_saprfc_highlight_items = true;

/* Protocol handles for both external and internal dissectors */
static dissector_handle_t saprfc_handle;
static dissector_handle_t saprfcinternal_handle;

/* Keeps track of table content items */
static uint32_t global_saprfc_table_content_counter = 0;


void proto_register_saprfc(void);
void proto_reg_handoff_saprfc(void);


static bool
check_saprfc_compression(tvbuff_t *tvb, uint32_t offset)
{
	/* We check for the length, the algorithm value and the presence of magic bytes */
	if ((tvb_captured_length_remaining(tvb, offset) >= 8) &&
		((tvb_get_uint8(tvb, offset+4) == 0x11) || (tvb_get_uint8(tvb, offset+4) == 0x12)) &&
		(tvb_get_uint16(tvb, offset+5, ENC_LITTLE_ENDIAN) == 0x9d1f)){
		return true;
	}
	return false;
}


static void
dissect_saprfc_tables_compressed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int rt = 0;
	int compressed_length;
	uint32_t offset = 0;
	uint32_t reported_length = 0;
	uint32_t uncompress_length = 0;
	uint32_t table_offset = 0;
	tvbuff_t *decompressed_tvb = NULL;
	const uint8_t *compressed_buffer = NULL;
	uint8_t *decompressed_buffer = NULL;

	proto_item *compression_header = NULL;
	proto_tree *compression_header_tree = NULL;
	proto_item *decompress_return_code = NULL;
	proto_item *rl = NULL;

	/* Skip the table prefix preceding the compression header. */
	offset = SAPRFC_TABLE_PREFIX_LENGTH;

	/* Add the compression header subtree */
	compression_header = proto_tree_add_item(tree, hf_saprfc_table_compress_header, tvb, offset, 8, ENC_NA);
	compression_header_tree = proto_item_add_subtree(compression_header, ett_saprfc);

	table_offset = offset;

	/* Add the uncompressed length */
	reported_length = tvb_get_letohl(tvb, offset);
	rl = proto_tree_add_uint(compression_header_tree, hf_saprfc_table_uncomplength, tvb, offset, 4, reported_length);
	offset += 4;
	proto_item_append_text(compression_header, ", Uncompressed Len: %u", reported_length);
	col_append_fstr(pinfo->cinfo, COL_INFO, " Uncompressed Length=%u ", reported_length);

	/* Add the algorithm */
	proto_tree_add_item(compression_header_tree, hf_saprfc_table_algorithm, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	/* Add the magic bytes */
	proto_tree_add_item(compression_header_tree, hf_saprfc_table_magic, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	/* Add the max bits */
	proto_tree_add_item(compression_header_tree, hf_saprfc_table_special, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (global_saprfc_decompress){
		if (reported_length == 0 || reported_length > global_saprfc_max_uncompressed_size) {
			expert_add_info_format(pinfo, rl, &ei_saprfc_invalid_decompress_length,
					"Reported uncompressed payload length %u is invalid or exceeds the configured maximum of %u bytes",
					reported_length, global_saprfc_max_uncompressed_size);
		} else {
			compressed_length = tvb_captured_length_remaining(tvb, table_offset);
			compressed_buffer = tvb_get_ptr(tvb, table_offset, compressed_length);
			decompressed_buffer = (uint8_t *)wmem_alloc0(pinfo->pool, reported_length);
			uncompress_length = reported_length;

			rt = sap_lzclzh_decompress(pinfo->pool, compressed_buffer,
				compressed_length, decompressed_buffer, &uncompress_length);

			decompress_return_code = proto_tree_add_int_format_value(compression_header_tree,
					hf_saprfc_table_return_code, tvb, table_offset, 0, rt,
					"%d (%s)", rt, sap_lzclzh_decompress_error_string(rt));
			proto_item_set_generated(decompress_return_code);

			if (rt != CS_END_OF_STREAM) {
				expert_add_info_format(pinfo, compression_header, &ei_saprfc_invalid_decompression,
						"Decompression of table failed with return code %d (%s)",
						rt, sap_lzclzh_decompress_error_string(rt));
			} else {
				if (uncompress_length != reported_length) {
					expert_add_info_format(pinfo, rl, &ei_saprfc_invalid_decompress_length,
							"The uncompressed table length (%u) differs from the reported length (%u)",
							uncompress_length, reported_length);
				}

				decompressed_tvb = tvb_new_child_real_data(tvb, decompressed_buffer,
					uncompress_length, uncompress_length);
				add_new_data_source(pinfo, decompressed_tvb, "Uncompressed Table Data");

				/* Add the table subtree using the new tvb. */
				proto_tree_add_item(tree, hf_saprfc_table_content, decompressed_tvb, 0, -1, ENC_NA);

				/* TODO: Dissect SAP RFC Table content */
				return;
			}
		}
	}

	/* Add the payload subtree */
	proto_tree_add_item(tree, hf_saprfc_table_content, tvb, offset, -1, ENC_NA);
}

static void
dissect_saprfc_tables(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint16_t item_length){

	uint8_t *reassemble_buffer = NULL, *table_name = NULL;
	uint16_t next_item = 0;
	uint32_t reassemble_length = 0, reassemble_offset = 0, initial_offset = 0;

	proto_item *table = NULL;
	proto_tree *table_tree = NULL;
	tvbuff_t *compressed_tvb = NULL;

	/* Skip table line structure */
	if (tvb_captured_length_remaining(tvb, offset) < item_length + 6U){
		expert_add_info(pinfo, tree, &ei_saprfc_invalid_table_length);
		return;
	}
	offset += item_length + 2;

	next_item = tvb_get_ntohs(tvb, offset);
	offset+=2;
	if (next_item != 0x0301){
		return;
	}

	item_length = tvb_get_ntohs(tvb, offset);
	offset += 2;
	if (tvb_captured_length_remaining(tvb, offset) < item_length + 6U){
		expert_add_info(pinfo, tree, &ei_saprfc_invalid_table_length);
		return;
	}
	table_name = tvb_get_string_enc(pinfo->pool, tvb, offset, item_length, ENC_ASCII);
	offset += item_length;
	offset += 2;

	next_item = tvb_get_ntohs(tvb, offset);
	offset += 2;
	if (next_item != 0x0302){
		return;
	}

	item_length = tvb_get_ntohs(tvb, offset);
	offset += 2;
	if (item_length < 8 || tvb_captured_length_remaining(tvb, offset) < item_length + 6U){
		expert_add_info(pinfo, tree, &ei_saprfc_invalid_table_length);
		return;
	}
	/* Row width and count are currently not dissected, but are part of the fixed header. */
	tvb_get_ntohl(tvb, offset);
	offset += 4;
	tvb_get_ntohl(tvb, offset);
	offset += 4;
	offset += (item_length - 8) + 2;

	next_item = tvb_get_ntohs(tvb, offset);
	offset += 2;
	if (next_item != 0x0305){
		return;
	}

	item_length = tvb_get_ntohs(tvb, offset);
	offset += 2;
	if (item_length < SAPRFC_TABLE_PREFIX_LENGTH ||
	    tvb_captured_length_remaining(tvb, offset) < SAPRFC_TABLE_PREFIX_LENGTH){
		expert_add_info(pinfo, tree, &ei_saprfc_invalid_table_length);
		return;
	}

	/* Get the reassemble length */
	initial_offset = offset;
	reassemble_length = tvb_get_ntohl(tvb, offset + 4);
	if (reassemble_length < SAPRFC_TABLE_PREFIX_LENGTH ||
	    reassemble_length > global_saprfc_max_reassembled_size){
		expert_add_info_format(pinfo, tree, &ei_saprfc_invalid_table_length,
				"Reported reassembled table length %u is invalid or exceeds the configured maximum of %u bytes",
				reassemble_length, global_saprfc_max_reassembled_size);
		return;
	}
	if (item_length > (reassemble_length - reassemble_offset)){
		item_length = reassemble_length - reassemble_offset;
	}

	/* Allocate the buffer only in the scope of current packet */
	reassemble_buffer = (uint8_t *)wmem_alloc(pinfo->pool, reassemble_length);
	if (!reassemble_buffer){
		return;
	}

	/* Reassemble the table content, retaining the actual captured length. */
	while (reassemble_offset < reassemble_length){
		if (tvb_captured_length_remaining(tvb, offset) < item_length){
			break;
		}
		tvb_memcpy(tvb, reassemble_buffer + reassemble_offset, offset, item_length);
		offset += item_length;
		reassemble_offset += item_length;
		if (reassemble_offset == reassemble_length){
			break;
		}

		/* Skip the closing marker and read the next item identifier. */
		if (tvb_captured_length_remaining(tvb, offset) < 4){
			break;
		}
		offset += 2;
		next_item = tvb_get_ntohs(tvb, offset);
		offset+=2;
		if (next_item == 0x0305){
			if (tvb_captured_length_remaining(tvb, offset) < 2){
				break;
			}
			item_length = tvb_get_ntohs(tvb, offset);
			offset+=2;

			if (item_length > (reassemble_length - reassemble_offset)){
				item_length = reassemble_length - reassemble_offset;
			}

		/* If the table content doesn't continue, we've completed */
		} else {
			break;
		}
	}

	/* Expose only bytes actually copied; retain the declared length as reported length. */
	compressed_tvb = tvb_new_child_real_data(tvb, reassemble_buffer, reassemble_offset, reassemble_length);

	/* Add the Table subtree */
	table = proto_tree_add_item(tree, hf_saprfc_table, tvb, initial_offset, offset - initial_offset, ENC_NA);
	table_tree = proto_item_add_subtree(table, ett_saprfc);

	proto_item_append_text(table, ", Name=%s", table_name);

	/* Only complete tables can safely be passed to the decompressor. */
	if (reassemble_offset == reassemble_length &&
	    check_saprfc_compression(compressed_tvb, SAPRFC_TABLE_PREFIX_LENGTH)) {
		dissect_saprfc_tables_compressed(compressed_tvb, pinfo, table_tree);
	} else {
		proto_tree_add_item(table_tree, hf_saprfc_table_content, compressed_tvb,
				SAPRFC_TABLE_PREFIX_LENGTH, -1, ENC_NA);
		if (reassemble_offset != reassemble_length){
			expert_add_info_format(pinfo, table, &ei_saprfc_invalid_table_length,
					"Reassembled table contains %u of %u reported bytes",
					reassemble_offset, reassemble_length);
		}
	}

}

static void
dissect_saprfc_item(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *item_value_tree, uint32_t offset, uint8_t item_id1, uint8_t item_id2, uint16_t item_length){

	if (item_id1==0x01 && item_id2==0x02){
		const char *value_str = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, item_length, ENC_ASCII);
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, item_length, "Function Name: %s", value_str);
		proto_item_append_text(item, ", Function Name=%s", value_str);

	} else if (item_id1==0x02 && item_id2==0x01){
		const char *value_str = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, item_length, ENC_ASCII);
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, item_length, "Import Parameter Name: %s", value_str);
		proto_item_append_text(item, ", Import Parameter Name=%s", value_str);

	} else if (item_id1==0x02 && item_id2==0x05){
		const char *value_str = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, item_length, ENC_ASCII);
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, item_length, "Export Parameter Name: %s", value_str);
		proto_item_append_text(item, ", Export Parameter Name=%s", value_str);

	} else if (item_id1==0x02 && item_id2==0x13){
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, item_length, "Type Structure A");

	} else if (item_id1==0x03 && item_id2==0x01){
		const char *value_str = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, item_length, ENC_ASCII);
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, item_length, "Table Name: %s", value_str);
		proto_item_append_text(item, ", Table Name=%s", value_str);

	} else if (item_id1==0x03 && item_id2==0x02){
		uint32_t value_uint32;

		if (item_length != 8) {
			expert_add_info_format(pinfo, item_value_tree, &ei_saprfc_item_length_invalid, "Table Info length is invalid");
		}
		value_uint32 = tvb_get_ntohl(tvb, offset);
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, 4, "Row Width: %d", value_uint32);
		proto_item_append_text(item, ", Row Width=%d", value_uint32);
		offset+=4;
		value_uint32 = tvb_get_ntohl(tvb, offset);
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, 4, "Total Row Count: %d", value_uint32);
		proto_item_append_text(item, ", Total Row Count=%d", value_uint32);

	} else if (item_id1==0x03 && item_id2==0x05){
		global_saprfc_table_content_counter+= 1;
		if (global_saprfc_table_content_counter==1){
			offset += 4;  /* Skip the first 4 bytes */
			proto_tree_add_item(item_value_tree, hf_saprfc_table_length, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}

		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, item_length, "Table Content LZ");

		if (global_saprfc_table_content_counter==1){
			proto_item_append_text(item, ", Table Content LZ (first)");
		} else {
			proto_item_append_text(item, ", Table Content LZ");
		}

	} else if (item_id1==0x03 && item_id2==0x06){
		global_saprfc_table_content_counter = 0;
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, item_length, "Table Content End");
		proto_item_append_text(item, ", Table Content End");

	} else if (item_id1==0x01 && item_id2==0x36){
		const char *value_str;
		uint8_t value_uint8;
		uint32_t value_uint32;

		value_uint8 = tvb_get_uint8(tvb, offset);
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, 1, "#: %u", value_uint8);
		proto_item_append_text(item, ", #=%u", value_uint8);
		offset+=1;
		value_str = tvb_bytes_to_str(pinfo->pool, tvb, offset, 16);
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, 16, "Root-id: %s", value_str);
		proto_item_append_text(item, ", Root-id=%s", value_str);
		offset+=16;
		value_str = tvb_bytes_to_str(pinfo->pool, tvb, offset, 16);
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, 16, "Coon-id: %s", value_str);
		proto_item_append_text(item, ", Coon-id=%s", value_str);
		offset+=16;
		value_uint32 = tvb_get_ntohl(tvb, offset);
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, 4, "#: %d", value_uint32);
		proto_item_append_text(item, ", #=%u", value_uint32);

	} else if (item_id1==0xFF && item_id2==0xFF){
		proto_item_append_text(item, ", End of RFC message");

	} else {
		/* If the preference is set, report the item as unknown in the expert info */
		if (global_saprfc_highlight_items){
			expert_add_info_format(pinfo, item, &ei_saprfc_unknown_item, "The RFC item has a unknown type that is not dissected (%u %u)", item_id1, item_id2);
		}
	}
}

static void
dissect_saprfc_payload(tvbuff_t *tvb, packet_info *info, proto_tree *tree, proto_tree *parent_tree, uint32_t offset){

	uint8_t item_id1, item_id2;
	uint16_t item_value_length;
	uint32_t item_length;
	int remaining_length;
	unsigned reported_remaining_length;
	tvbuff_t *item_value_tvb = NULL;

	proto_item *item = NULL, *item_value = NULL;
	proto_tree *item_tree = NULL, *item_value_tree = NULL;

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		item_length = 0;
		item_value_length = 0;
		item_id2 = 0;

		/* Add the item subtree. We start with a item's length of 1, as we don't have yet the real size of the item */
		item = proto_tree_add_item(tree, hf_saprfc_item, tvb, offset, 1, ENC_NA);
		item_tree = proto_item_add_subtree(item, ett_saprfc);

		/* Get the first identifier */
		proto_tree_add_item_ret_uint8(item_tree, hf_saprfc_item_id1, tvb, offset, 1, ENC_BIG_ENDIAN, &item_id1);
		offset += 1;
		item_length += 1;
		proto_item_append_text(item, ": (0x%.2x)", item_id1);

		/* Check if it's an End of message */
		if (item_id1==0x0c){
			break; /* ? */

		/* Otherwise follow dissection */
		} else {
			/* ID2 and the two-byte value length must be present. */
			if (tvb_reported_length_remaining(tvb, offset) < 3 ||
			    tvb_captured_length_remaining(tvb, offset) < 3){
				expert_add_info(info, item, &ei_saprfc_item_length_invalid);
				return;
			}

			proto_tree_add_item_ret_uint8(item_tree, hf_saprfc_item_id2, tvb, offset, 1, ENC_BIG_ENDIAN, &item_id2);
			offset += 1;
			item_length += 1;
			proto_item_append_text(item, ", (0x%.2x)", item_id2);

			item_value_length = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(item_tree, hf_saprfc_item_length, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			item_length += 2;
			proto_item_append_text(item, ", Length=%d", item_value_length);
		}

		/* Every regular item includes its value followed by repeated ID markers. */
		remaining_length = tvb_captured_length_remaining(tvb, offset);
		reported_remaining_length = tvb_reported_length_remaining(tvb, offset);
		if (remaining_length < 0 || (uint32_t)remaining_length < (uint32_t)item_value_length + 2U ||
		    reported_remaining_length < (uint32_t)item_value_length + 2U){
			expert_add_info(info, item, &ei_saprfc_item_length_invalid);
			if (remaining_length > 0){
				proto_tree_add_item(item_tree, hf_saprfc_item_value, tvb, offset, remaining_length, ENC_NA);
			}
			return;
		}

		/* Now we have the real length of the item, set the proper size */
		item_length += item_value_length;
		proto_item_set_len(item, item_length);

		item_value = proto_tree_add_item(item_tree, hf_saprfc_item_value, tvb, offset, item_value_length, ENC_NA);
		item_value_tree = proto_item_add_subtree(item_value, ett_saprfc);
		item_value_tvb = tvb_new_subset_length(tvb, offset, item_value_length);
		dissect_saprfc_item(item_value_tvb, info, item, item_value_tree, 0, item_id1, item_id2, item_value_length);

		/* Also send the tables items for reassembling */
		if (global_saprfc_table_reassembly && item_id1==0x02 && item_id2==0x13){
			dissect_saprfc_tables(item_value_tvb, info, parent_tree, 0, item_value_length);
		}

		offset+= item_value_length;

		/* ID1 and ID2 are repeated as closing markers */
		offset+= 2;

		/* 0xFF 0xFF marks end of RFC message */
		if (item_id1==0xFF && item_id2==0xFF){
			break;
		}
	}

}


static void
dissect_saprfc_monitor_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version _U_, uint32_t offset){
	uint8_t opcode;

	opcode = tvb_get_uint8(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Command=%s", val_to_str_const(opcode, saprfc_monitor_cmd_values, "Unknown"));

	proto_tree_add_item(tree, hf_saprfc_monitor_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
	//offset+=1;
	proto_item_append_text(tree, ", Command=%s", val_to_str_const(opcode, saprfc_monitor_cmd_values, "Unknown"));

	// TODO: Dissect RFC monitor command opcodes
}


static void
dissect_saprfc_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset){
	uint8_t version = 0, reqtype = 0;
	proto_item *header = NULL, *info = NULL, *info2 = NULL, *info3 = NULL, *info4 = NULL, *reqtype2 = NULL, *params = NULL;
	proto_tree *header_tree = NULL, *info_tree = NULL, *info2_tree = NULL, *info3_tree = NULL, *info4_tree = NULL, *reqtype2_tree = NULL, *params_tree;

	version = tvb_get_uint8(tvb, offset);
	reqtype = tvb_get_uint8(tvb, offset + 1);

	col_append_fstr(pinfo->cinfo, COL_INFO, "APPC Version=%u, Request Type=%s", version, val_to_str_const(reqtype, saprfc_header_reqtype_values, "Unknown"));

	/* Add the APPC header subtree */
	header = proto_tree_add_item(tree, hf_saprfc_header, tvb, offset, 28, ENC_NA);
	header_tree = proto_item_add_subtree(header, ett_saprfc);

	proto_item_append_text(header, ", Version=%u, Request Type=%s", version, val_to_str_const(reqtype, saprfc_header_reqtype_values, "Unknown"));

	proto_tree_add_item(header_tree, hf_saprfc_header_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(header_tree, hf_saprfc_header_reqtype, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(header_tree, hf_saprfc_header_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(header_tree, hf_saprfc_header_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(header_tree, hf_saprfc_header_uid, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_saprfc_header_gw_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_saprfc_header_err_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	info2 = proto_tree_add_item(header_tree, hf_saprfc_header_info2, tvb, offset, 1, ENC_BIG_ENDIAN);
	info2_tree = proto_item_add_subtree(info2, ett_saprfc);
	proto_tree_add_item(info2_tree, hf_saprfc_header_info2_WITH_LONG_LU_NAME, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info2_tree, hf_saprfc_header_info2_WITH_LONG_HOSTADDR, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info2_tree, hf_saprfc_header_info2_GW_IMMEDIATE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info2_tree, hf_saprfc_header_info2_GW_SNC_ACTIVE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info2_tree, hf_saprfc_header_info2_GW_WAIT_LOOK_UP, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info2_tree, hf_saprfc_header_info2_SNC_INIT_PHASE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info2_tree, hf_saprfc_header_info2_GW_STATELESS, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info2_tree, hf_saprfc_header_info2_GW_NO_STATE_CHECK, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(header_tree, hf_saprfc_header_trace_level, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(header_tree, hf_saprfc_header_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	info3 = proto_tree_add_item(header_tree, hf_saprfc_header_info3, tvb, offset, 1, ENC_BIG_ENDIAN);
	info3_tree = proto_item_add_subtree(info3, ett_saprfc);
	proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_WITH_CODE_PAGE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_ASYNC_RFC, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_CANCEL_HARD, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_CANCEL_SOFT, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_WITH_GUI_TIMEOUT, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_TERMIO_ERROR, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_EXTENDED_INIT_OPTIONS, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_DIST_TRACE, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(header_tree, hf_saprfc_header_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	info4 = proto_tree_add_item(header_tree, hf_saprfc_header_info4, tvb, offset, 1, ENC_BIG_ENDIAN);
	info4_tree = proto_item_add_subtree(info4, ett_saprfc);
	proto_tree_add_item(info4_tree, hf_saprfc_header_info4_GW_WITH_DBG_CTL, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(header_tree, hf_saprfc_header_sequence_no, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(header_tree, hf_saprfc_header_sap_params_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	offset += 2;  /* Skip 2 bytes here */

	info = proto_tree_add_item(header_tree, hf_saprfc_header_info, tvb, offset, 1, ENC_BIG_ENDIAN);
	info_tree = proto_item_add_subtree(info, ett_saprfc);
	proto_tree_add_item(info_tree, hf_saprfc_header_info_SYNC_CPIC_FUNCTION, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info_tree, hf_saprfc_header_info_WITH_HOSTADDR, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info_tree, hf_saprfc_header_info_WITH_GW_SAP_PARAMS_HDR, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info_tree, hf_saprfc_header_info_CPIC_SYNC_REQ, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info_tree, hf_saprfc_header_info_WITH_ERR_INFO, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info_tree, hf_saprfc_header_info_DATA_WITH_TERM_OUTPUT, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info_tree, hf_saprfc_header_info_DATA_WITH_TERM_INPUT, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(info_tree, hf_saprfc_header_info_R3_CPIC_LOGIN_WITH_TERM, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	reqtype2 = proto_tree_add_item(header_tree, hf_saprfc_header_reqtype2, tvb, offset, 1, ENC_BIG_ENDIAN);
	reqtype2_tree = proto_item_add_subtree(reqtype2, ett_saprfc);
	proto_tree_add_item(reqtype2_tree, hf_saprfc_header_reqtype2_F_V_INITIALIZE_CONVERSATION, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(reqtype2_tree, hf_saprfc_header_reqtype2_F_V_ALLOCATE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(reqtype2_tree, hf_saprfc_header_reqtype2_F_V_SEND_DATA, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(reqtype2_tree, hf_saprfc_header_reqtype2_F_V_RECEIVE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(reqtype2_tree, hf_saprfc_header_reqtype2_F_V_FLUSH, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(header_tree, hf_saprfc_header_appc_rc, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(header_tree, hf_saprfc_header_sap_rc, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(header_tree, hf_saprfc_header_conversation_id, tvb, offset, 8, ENC_ASCII);
	offset += 8;

	/* Dissect the NCPIC Parameters according to the request type */
	params = proto_tree_add_item(header_tree, hf_saprfc_header_ncpic_parameters, tvb, offset, 28, ENC_NA);
	params_tree = proto_item_add_subtree(params, ett_saprfc);
	switch (reqtype){
		case 0x01:{		/* F_INITIALIZE_CONVERSATION */
			proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_sdest, tvb, offset, 8, ENC_ASCII);
			offset += 8;
			proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_lu, tvb, offset, 8, ENC_ASCII);
			offset += 8;
			proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_tp, tvb, offset, 8, ENC_ASCII);
			offset += 8;
			proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_ctype, tvb, offset, 1, ENC_ASCII);
			offset += 1;
			proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_client_info, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			offset += 2; /* Sum remaining bytes */
			break;
		}
		case 0x0f:{		/* F_SET_PARTNER_LU_NAME */
			proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_lu_name, tvb, offset, 8, ENC_ASCII);
			offset += 8;
			proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_lu_name_length, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_host_address, tvb, offset, 16, ENC_NA);
			offset += 16;
			break;
		}
		case 0x17:{		/* F_SET_SECURITY_TYPE */
			proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_security_password, tvb, offset, 8, ENC_ASCII);
			offset += 8;
			proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_security_password_length, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			offset += 16; /* Sum remaining bytes */
			break;
		}
		default:{
			offset += 28;
		}
	};

	proto_tree_add_item(header_tree, hf_saprfc_header_comm_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_saprfc_header_conn_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
}

static int
dissect_saprfc_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	uint32_t offset = 0;
	proto_item *saprfc, *payload = NULL;
	proto_tree *saprfc_tree, *payload_tree = NULL;

	/* Add the main saprfc subtree */
	saprfc = proto_tree_add_item(tree, proto_saprfc, tvb, 0, -1, ENC_NA);
	saprfc_tree = proto_item_add_subtree(saprfc, ett_saprfc);

	/* Check the payload length */
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		/* Add the payload subtree */
		payload = proto_tree_add_item(saprfc_tree, hf_saprfc_payload, tvb, offset, -1, ENC_NA);
		payload_tree = proto_item_add_subtree(payload, ett_saprfc);

		/* Dissect the payload */
		dissect_saprfc_payload(tvb, pinfo, payload_tree, saprfc_tree, offset);
	}

	return tvb_reported_length(tvb);
}

static int
dissect_saprfc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	uint32_t offset = 0;
	uint8_t version = 0, req_type = 0;
	proto_item *saprfc = NULL, *accept_info = NULL;
	proto_tree *saprfc_tree = NULL, *accept_info_tree = NULL;

	/* Add the protocol to the column */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SAPRFC");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Get version and request type values */
	if (tvb_reported_length_remaining(tvb, offset) < 2) {
		saprfc = proto_tree_add_item(tree, proto_saprfc, tvb, 0, -1, ENC_NA);
		expert_add_info_format(pinfo, saprfc, &ei_saprfc_item_length_invalid, "SAP RFC header is shorter than 2 bytes");
		return tvb_reported_length(tvb);
	}
	version = tvb_get_uint8(tvb, offset);
	req_type = tvb_get_uint8(tvb, offset + 1);

	/* Check if the message is valid or it is an APPC header */
	/* TODO: We need to find a way of performing this check, as Wireshark is
	 * state-less seems to be difficult to keep track of the requests/responses.
	 */
	if (version > 0x03){
		/* Add the main saprfc subtree */
		saprfc = proto_tree_add_item(tree, proto_saprfc, tvb, 0, -1, ENC_NA);
		saprfc_tree = proto_item_add_subtree(saprfc, ett_saprfc);
		if (tvb_reported_length_remaining(tvb, offset) < (int)SAPRFC_APPC_HEADER_LEN) {
			proto_tree_add_item(saprfc_tree, hf_saprfc_header, tvb, offset, -1, ENC_NA);
			expert_add_info_format(pinfo, saprfc, &ei_saprfc_short_appc_header, "SAP RFC APPC header is shorter than %u bytes", SAPRFC_APPC_HEADER_LEN);
			return tvb_reported_length(tvb);
		}
		dissect_saprfc_header(tvb, pinfo, saprfc_tree, offset);
		return tvb_reported_length(tvb);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, "Version=%u, Request Type=%s", version, val_to_str_const(req_type, saprfc_reqtype_values, "Unknown"));

	/* Add the main saprfc subtree */
	saprfc = proto_tree_add_item(tree, proto_saprfc, tvb, 0, -1, ENC_NA);
	saprfc_tree = proto_item_add_subtree(saprfc, ett_saprfc);

	/* Dissect common fields */
	proto_tree_add_item(saprfc_tree, hf_saprfc_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
	proto_tree_add_item(saprfc_tree, hf_saprfc_reqtype, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
	proto_item_append_text(saprfc_tree, ", Version=%u, Request Type=%s", version, val_to_str_const(req_type, saprfc_reqtype_values, "Unknown"));

	/* Dissect the remaining based on the version and request type */
		switch (req_type){

			case 0x03:		/* GW_NORMAL_CLIENT */
			case 0x0b:{		/* GW_REGISTER_TP */
				unsigned header_len = (version == 0x03) ? SAPRFC_NORMAL_CLIENT_HEADER_LEN_V3 : SAPRFC_NORMAL_CLIENT_HEADER_LEN_V1;
				int remaining = tvb_reported_length_remaining(tvb, 0);
				if (remaining < (int)header_len) {
					expert_add_info_format(pinfo, saprfc, &ei_saprfc_item_length_invalid, "SAP RFC normal client/register TP header is shorter than %u bytes", header_len);
					return tvb_reported_length(tvb);
				}
				proto_tree_add_item(saprfc_tree, hf_saprfc_address, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			offset += 4;  /* Skip 4 bytes here */
			proto_tree_add_item(saprfc_tree, hf_saprfc_service, tvb, offset, 10, ENC_ASCII);
			offset += 10;
			proto_tree_add_item(saprfc_tree, hf_saprfc_codepage, tvb, offset, 4, ENC_ASCII);
			offset += 4;
			offset += 6;  /* Skip 6 bytes here */
			proto_tree_add_item(saprfc_tree, hf_saprfc_lu, tvb, offset, 8, ENC_ASCII);
			offset += 8;
			proto_tree_add_item(saprfc_tree, hf_saprfc_tp, tvb, offset, 8, ENC_ASCII);
			offset += 8;
			proto_tree_add_item(saprfc_tree, hf_saprfc_conversation_id, tvb, offset, 8, ENC_ASCII);
			offset += 8;
			proto_tree_add_item(saprfc_tree, hf_saprfc_appc_header_version, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			accept_info = proto_tree_add_item(saprfc_tree, hf_saprfc_accept_info, tvb, offset, 1, ENC_BIG_ENDIAN);
			accept_info_tree = proto_item_add_subtree(accept_info, ett_saprfc);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_EINFO, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_PING, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_SNC, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_CONN_EINFO, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_CODE_PAGE, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_NIPING, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_EXTINITOPT, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_GW_ACCEPT_DIST_TRACE, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(saprfc_tree, hf_saprfc_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			if (version == 0x03){
				proto_tree_add_item(saprfc_tree, hf_saprfc_address6, tvb, offset, 16, ENC_NA);
				offset += 16;
			}

			proto_tree_add_item(saprfc_tree, hf_saprfc_rc, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(saprfc_tree, hf_saprfc_echo_data, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(saprfc_tree, hf_saprfc_filler, tvb, offset, 1, ENC_BIG_ENDIAN);
			break;
		}
		case 0x09:{		/* GW_SEND_CMD */
			dissect_saprfc_monitor_cmd(tvb, pinfo, saprfc_tree, version, 2);
			break;
		}
	};

	return tvb_reported_length(tvb);
}

void
proto_register_saprfc(void)
{
	static hf_register_info hf[] = {
		{ &hf_saprfc_version,
			{ "Version", "saprfc.version", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC Version", HFILL }},
		{ &hf_saprfc_reqtype,
			{ "Request Type", "saprfc.reqtype", FT_UINT8, BASE_HEX, VALS(saprfc_reqtype_values), 0x0, "SAP RFC Request Type", HFILL }},
		{ &hf_saprfc_address,
			{ "IPv4 Address", "saprfc.address", FT_IPv4, BASE_NONE, NULL, 0x0, "SAP RFC IPv4 Address", HFILL }},
		{ &hf_saprfc_service,
			{ "Service", "saprfc.service", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC Service", HFILL }},
		{ &hf_saprfc_codepage,
			{ "Codepage", "saprfc.codepage", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC Codepage", HFILL }},
		{ &hf_saprfc_lu,
			{ "LU", "saprfc.lu", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC LU", HFILL }},
		{ &hf_saprfc_tp,
			{ "TP", "saprfc.tp", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC TP", HFILL }},
		{ &hf_saprfc_conversation_id,
			{ "Conversation ID", "saprfc.conversation_id", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC Conversation ID", HFILL }},
		{ &hf_saprfc_appc_header_version,
			{ "APPC Header Version", "saprfc.appc_hd_version", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Version", HFILL }},
		{ &hf_saprfc_accept_info,
			{ "Accept Info Flags", "saprfc.accept_info", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Accept Info Flags", HFILL }},
		{ &hf_saprfc_accept_info_EINFO,
			{ "Accept Info Flag EINFO", "saprfc.accept_info.EINFO", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_EINFO, "SAP RFC Accept Info Flag EINFO", HFILL }},
		{ &hf_saprfc_accept_info_PING,
			{ "Accept Info Flag PING", "saprfc.accept_info.PING", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_PING, "SAP RFC Accept Info Flag PING", HFILL }},
		{ &hf_saprfc_accept_info_SNC,
			{ "Accept Info Flag SNC", "saprfc.accept_info.SNC", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_SNC, "SAP RFC Accept Info Flag SNC", HFILL }},
		{ &hf_saprfc_accept_info_CONN_EINFO,
			{ "Accept Info Flag CONN_EINFO", "saprfc.accept_info.CONN_EINFO", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_CONN_EINFO, "SAP RFC Accept Info Flag CONN_EINFO", HFILL }},
		{ &hf_saprfc_accept_info_CODE_PAGE,
			{ "Accept Info Flag CODE_PAGE", "saprfc.accept_info.CODE_PAGE", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_CODE_PAGE, "SAP RFC Accept Info Flag CODE_PAGE", HFILL }},
		{ &hf_saprfc_accept_info_NIPING,
			{ "Accept Info Flag NIPING", "saprfc.accept_info.NIPING", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_NIPING, "SAP RFC Accept Info Flag NIPING", HFILL }},
		{ &hf_saprfc_accept_info_EXTINITOPT,
			{ "Accept Info Flag EXTINITOPT", "saprfc.accept_info.EXTINITOPT", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_EXTINITOPT, "SAP RFC Accept Info Flag EXTINITOPT", HFILL }},
		{ &hf_saprfc_accept_info_GW_ACCEPT_DIST_TRACE,
			{ "Accept Info Flag GW_ACCEPT_DIST_TRACE", "saprfc.accept_info.GW_ACCEPT_DIST_TRACE", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_GW_ACCEPT_DIST_TRACE, "SAP RFC Accept Info Flag GW_ACCEPT_DIST_TRACE", HFILL }},
		{ &hf_saprfc_idx,
			{ "Index", "saprfc.index", FT_INT16, BASE_DEC, NULL, 0x0, "SAP RFC Index", HFILL }},
		{ &hf_saprfc_address6,
			{ "IPv6 Address", "saprfc.address6", FT_IPv6, BASE_NONE, NULL, 0x0, "SAP RFC IPv6 Address", HFILL }},
		{ &hf_saprfc_rc,
			{ "Return Code", "saprfc.rc", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC Return Code", HFILL }},
		{ &hf_saprfc_echo_data,
			{ "Echo Data", "saprfc.echo_data", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC Echo Data", HFILL }},
		{ &hf_saprfc_filler,
			{ "Filler", "saprfc.filler", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC Echo Data", HFILL }},

		/* Monitor Commands*/
		{ &hf_saprfc_monitor_cmd,
			{ "Command", "saprfc.monitor_cmd", FT_UINT8, BASE_DEC, VALS(saprfc_monitor_cmd_values), 0x0, "SAP RFC Monitor Command", HFILL }},

		/* APPC Header */
		{ &hf_saprfc_header,
			{ "APPC Header", "saprfc.appcheader", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header", HFILL }},
		{ &hf_saprfc_header_version,
			{ "Version", "saprfc.appcheader.version", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Version", HFILL }},
		{ &hf_saprfc_header_reqtype,
			{ "Request Type", "saprfc.appcheader.reqtype", FT_UINT8, BASE_HEX, VALS(saprfc_header_reqtype_values), 0x0, "SAP RFC APPC Header Request Type", HFILL }},
		{ &hf_saprfc_header_protocol,
			{ "Protocol", "saprfc.appcheader.protocol", FT_UINT8, BASE_HEX, VALS(saprfc_header_protocol_values), 0x0, "SAP RFC APPC Header Protocol", HFILL }},
		{ &hf_saprfc_header_mode,
			{ "Mode", "saprfc.appcheader.mode", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Mode", HFILL }},
		{ &hf_saprfc_header_uid,
			{ "UID", "saprfc.appcheader.uid", FT_INT16, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header UID", HFILL }},
		{ &hf_saprfc_header_gw_id,
			{ "Gateway ID", "saprfc.appcheader.gw_id", FT_UINT16, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Gateway ID", HFILL }},
		{ &hf_saprfc_header_err_len,
			{ "Error Length", "saprfc.appcheader.err_len", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Error Length", HFILL }},
		{ &hf_saprfc_header_info2,
			{ "Info 2", "saprfc.appcheader.info2", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Info 2", HFILL }},
		{ &hf_saprfc_header_info2_WITH_LONG_LU_NAME,
			{ "Info 2 Flag WITH_LONG_LU_NAME", "saprfc.info2.WITH_LONG_LU_NAME", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_WITH_LONG_LU_NAME, "SAP RFC Info 2 Flag WITH_LONG_LU_NAME", HFILL }},
		{ &hf_saprfc_header_info2_WITH_LONG_HOSTADDR,
			{ "Info 2 Flag WITH_LONG_HOSTADDR", "saprfc.info2.WITH_LONG_HOSTADDR", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_WITH_LONG_HOSTADDR, "SAP RFC Info 2 Flag WITH_LONG_HOSTADDR", HFILL }},
		{ &hf_saprfc_header_info2_GW_IMMEDIATE,
			{ "Info 2 Flag GW_IMMEDIATE", "saprfc.info2.GW_IMMEDIATE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_GW_IMMEDIATE, "SAP RFC Info 2 Flag GW_IMMEDIATE", HFILL }},
		{ &hf_saprfc_header_info2_GW_SNC_ACTIVE,
			{ "Info 2 Flag GW_SNC_ACTIVE", "saprfc.info2.GW_SNC_ACTIVE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_GW_SNC_ACTIVE, "SAP RFC Info 2 Flag GW_SNC_ACTIVE", HFILL }},
		{ &hf_saprfc_header_info2_GW_WAIT_LOOK_UP,
			{ "Info 2 Flag GW_WAIT_LOOK_UP", "saprfc.info2.GW_WAIT_LOOK_UP", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_GW_WAIT_LOOK_UP, "SAP RFC Info 2 Flag GW_WAIT_LOOK_UP", HFILL }},
		{ &hf_saprfc_header_info2_SNC_INIT_PHASE,
			{ "Info 2 Flag SNC_INIT_PHASE", "saprfc.info2.SNC_INIT_PHASE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_SNC_INIT_PHASE, "SAP RFC Info 2 Flag SNC_INIT_PHASE", HFILL }},
		{ &hf_saprfc_header_info2_GW_STATELESS,
			{ "Info 2 Flag GW_STATELESS", "saprfc.info2.GW_STATELESS", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_GW_STATELESS, "SAP RFC Info 2 Flag GW_STATELESS", HFILL }},
		{ &hf_saprfc_header_info2_GW_NO_STATE_CHECK,
			{ "Info 2 Flag GW_NO_STATE_CHECK", "saprfc.info2.GW_NO_STATE_CHECK", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_GW_NO_STATE_CHECK, "SAP RFC Info 2 Flag GW_NO_STATE_CHECK", HFILL }},
		{ &hf_saprfc_header_trace_level,
			{ "Trace Level", "saprfc.appcheader.trace_level", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Trace Level", HFILL }},
		{ &hf_saprfc_header_time,
			{ "Time", "saprfc.appcheader.time", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Time", HFILL }},
		{ &hf_saprfc_header_info3,
			{ "Info 3", "saprfc.appcheader.info3", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Info 3", HFILL }},
		{ &hf_saprfc_header_info3_GW_WITH_CODE_PAGE,
			{ "Info 3 Flag GW_WITH_CODE_PAGE", "saprfc.appcheader.info3.GW_WITH_CODE_PAGE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_WITH_CODE_PAGE, "SAP RFC APPC Header Info 3 Flag GW_WITH_CODE_PAGE", HFILL }},
		{ &hf_saprfc_header_info3_GW_ASYNC_RFC,
			{ "Info 3 Flag GW_ASYNC_RFC", "saprfc.appcheader.info3.GW_ASYNC_RFC", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_ASYNC_RFC, "SAP RFC APPC Header Info 3 Flag GW_ASYNC_RFC", HFILL }},
		{ &hf_saprfc_header_info3_GW_CANCEL_HARD,
			{ "Info 3 Flag GW_CANCEL_HARD", "saprfc.appcheader.info3.GW_CANCEL_HARD", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_CANCEL_HARD, "SAP RFC APPC Header Info 3 Flag GW_CANCEL_HARD", HFILL }},
		{ &hf_saprfc_header_info3_GW_CANCEL_SOFT,
			{ "Info 3 Flag GW_CANCEL_SOFT", "saprfc.appcheader.info3.GW_CANCEL_SOFT", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_CANCEL_SOFT, "SAP RFC APPC Header Info 3 Flag GW_CANCEL_SOFT", HFILL }},
		{ &hf_saprfc_header_info3_GW_WITH_GUI_TIMEOUT,
			{ "Info 3 Flag GW_WITH_GUI_TIMEOUT", "saprfc.appcheader.info3.GW_WITH_GUI_TIMEOUT", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_WITH_GUI_TIMEOUT, "SAP RFC APPC Header Info 3 Flag GW_WITH_GUI_TIMEOUT", HFILL }},
		{ &hf_saprfc_header_info3_GW_TERMIO_ERROR,
			{ "Info 3 Flag GW_TERMIO_ERROR", "saprfc.appcheader.info3.GW_TERMIO_ERROR", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_TERMIO_ERROR, "SAP RFC APPC Header Info 3 Flag GW_TERMIO_ERROR", HFILL }},
		{ &hf_saprfc_header_info3_GW_EXTENDED_INIT_OPTIONS,
			{ "Info 3 Flag GW_EXTENDED_INIT_OPTIONS", "saprfc.appcheader.info3.GW_EXTENDED_INIT_OPTIONS", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_EXTENDED_INIT_OPTIONS, "SAP RFC APPC Header Info 3 Flag GW_EXTENDED_INIT_OPTIONS", HFILL }},
		{ &hf_saprfc_header_info3_GW_DIST_TRACE,
			{ "Info 3 Flag GW_DIST_TRACE", "saprfc.appcheader.info3.GW_DIST_TRACE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_DIST_TRACE, "SAP RFC APPC Header Info 3 Flag GW_DIST_TRACE", HFILL }},
		{ &hf_saprfc_header_timeout,
			{ "Timeout", "saprfc.appcheader.timeout", FT_INT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Timeout", HFILL }},
		{ &hf_saprfc_header_info4,
			{ "Info 4", "saprfc.appcheader.info4", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Info 4", HFILL }},
		{ &hf_saprfc_header_info4_GW_WITH_DBG_CTL,
			{ "Info 4 Flag GW_WITH_DBG_CTL", "saprfc.appcheader.info4.GW_WITH_DBG_CTL", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO4_GW_WITH_DBG_CTL, "SAP RFC APPC Header Info 4 Flag GW_WITH_DBG_CTL", HFILL }},
		{ &hf_saprfc_header_sequence_no,
			{ "Sequence No", "saprfc.appcheader.sequence_no", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Sequence No", HFILL }},
		{ &hf_saprfc_header_sap_params_len,
			{ "SAP Parameters Length", "saprfc.appcheader.sap_params_len", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header SAP Parameters Length", HFILL }},
		{ &hf_saprfc_header_info,
			{ "Info Flags", "saprfc.appcheader.info", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Info Flags", HFILL }},
		{ &hf_saprfc_header_info_SYNC_CPIC_FUNCTION,
			{ "Info Flag SYNC_CPIC_FUNCTION", "saprfc.appcheader.info.SYNC_CPIC_FUNCTION", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_SYNC_CPIC_FUNCTION, "SAP RFC APPC Header Info Flag SYNC_CPIC_FUNCTION", HFILL }},
		{ &hf_saprfc_header_info_WITH_HOSTADDR,
			{ "Info Flag WITH_HOSTADDR", "saprfc.appcheader.info.WITH_HOSTADDR", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_WITH_HOSTADDR, "SAP RFC APPC Header Info Flag WITH_HOSTADDR", HFILL }},
		{ &hf_saprfc_header_info_WITH_GW_SAP_PARAMS_HDR,
			{ "Info Flag WITH_GW_SAP_PARAMS_HDR", "saprfc.appcheader.info.WITH_GW_SAP_PARAMS_HDR", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_WITH_GW_SAP_PARAMS_HDR, "SAP RFC APPC Header Info Flag WITH_GW_SAP_PARAMS_HDR", HFILL }},
		{ &hf_saprfc_header_info_CPIC_SYNC_REQ,
			{ "Info Flag CPIC_SYNC_REQ", "saprfc.appcheader.info.CPIC_SYNC_REQ", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_CPIC_SYNC_REQ, "SAP RFC APPC Header Info Flag CPIC_SYNC_REQ", HFILL }},
		{ &hf_saprfc_header_info_WITH_ERR_INFO,
			{ "Info Flag WITH_ERR_INFO", "saprfc.appcheader.info.WITH_ERR_INFO", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_WITH_ERR_INFO, "SAP RFC APPC Header Info Flag WITH_ERR_INFO", HFILL }},
		{ &hf_saprfc_header_info_DATA_WITH_TERM_OUTPUT,
			{ "Info Flag DATA_WITH_TERM_OUTPUT", "saprfc.appcheader.info.DATA_WITH_TERM_OUTPUT", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_DATA_WITH_TERM_OUTPUT, "SAP RFC APPC Header Info Flag DATA_WITH_TERM_OUTPUT", HFILL }},
		{ &hf_saprfc_header_info_DATA_WITH_TERM_INPUT,
			{ "Info Flag DATA_WITH_TERM_INPUT", "saprfc.appcheader.info.DATA_WITH_TERM_INPUT", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_DATA_WITH_TERM_INPUT, "SAP RFC APPC Header Info Flag DATA_WITH_TERM_INPUT", HFILL }},
		{ &hf_saprfc_header_info_R3_CPIC_LOGIN_WITH_TERM,
			{ "Info Flag R3_CPIC_LOGIN_WITH_TERM", "saprfc.appcheader.info.R3_CPIC_LOGIN_WITH_TERM", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_R3_CPIC_LOGIN_WITH_TERM, "SAP RFC APPC Header Info Flag R3_CPIC_LOGIN_WITH_TERM", HFILL }},
		{ &hf_saprfc_header_reqtype2,
			{ "Request Type 2 Flags", "saprfc.appcheader.reqtype2", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Request Type 2", HFILL }},
		{ &hf_saprfc_header_reqtype2_F_V_INITIALIZE_CONVERSATION,
			{ "Request Type 2 Flag F_V_INITIALIZE_CONVERSATION", "saprfc.appcheader.reqtype2.F_V_INITIALIZE_CONVERSATION", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_REQTYPE2_F_V_INITIALIZE_CONVERSATION, "SAP RFC Request Type 2 Flag F_V_INITIALIZE_CONVERSATION", HFILL }},
		{ &hf_saprfc_header_reqtype2_F_V_ALLOCATE,
			{ "Request Type 2 Flag F_V_ALLOCATE", "saprfc.appcheader.reqtype2.F_V_ALLOCATE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_REQTYPE2_F_V_ALLOCATE, "SAP RFC Request Type 2 Flag F_V_ALLOCATE", HFILL }},
		{ &hf_saprfc_header_reqtype2_F_V_SEND_DATA,
			{ "Request Type 2 Flag F_V_SEND_DATA", "saprfc.appcheader.reqtype2.F_V_SEND_DATA", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_REQTYPE2_F_V_SEND_DATA, "SAP RFC Request Type 2 Flag F_V_SEND_DATA", HFILL }},
		{ &hf_saprfc_header_reqtype2_F_V_RECEIVE,
			{ "Request Type 2 Flag F_V_RECEIVE", "saprfc.appcheader.reqtype2.F_V_RECEIVE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_REQTYPE2_F_V_RECEIVE, "SAP RFC Request Type 2 Flag F_V_RECEIVE", HFILL }},
		{ &hf_saprfc_header_reqtype2_F_V_FLUSH,
			{ "Request Type 2 Flag F_V_FLUSH", "saprfc.appcheader.reqtype2.F_V_FLUSH", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_REQTYPE2_F_V_FLUSH, "SAP RFC Request Type 2 Flag F_V_FLUSH", HFILL }},
		{ &hf_saprfc_header_appc_rc,
			{ "APPC Return Code", "saprfc.appcheader.appc_rc", FT_INT32, BASE_DEC, VALS(saprfc_header_appc_rc_values), 0x0, "SAP RFC APPC Header APPC Return Code", HFILL }},
		{ &hf_saprfc_header_sap_rc,
			{ "SAP Return Code", "saprfc.appcheader.sap_rc", FT_INT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header SAP Return Code", HFILL }},
		{ &hf_saprfc_header_conversation_id,
			{ "Conversation ID", "saprfc.appcheader.conversation_id", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header Conversation ID", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters,
			{ "NCPIC Parameters", "saprfc.appcheader.ncpic_parameters", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_sdest,
			{ "SDest", "saprfc.appcheader.ncpic_parameters.sdest", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters SDest", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_lu,
			{ "LU", "saprfc.appcheader.ncpic_parameters.lu", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters LU", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_tp,
			{ "TP", "saprfc.appcheader.ncpic_parameters.tp", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters TP", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_ctype,
			{ "CType", "saprfc.appcheader.ncpic_parameters.ctype", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters CType", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_client_info,
			{ "Client Info", "saprfc.appcheader.ncpic_parameters.client_info", FT_UINT8, BASE_HEX, VALS(saprfc_header_ncpic_parameters_client_info_values), 0x0, "SAP RFC APPC Header NCPIC Parameters Client Info", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_lu_name,
			{ "LU Name", "saprfc.appcheader.ncpic_parameters.lu_name", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters LU Name", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_lu_name_length,
			{ "LU Name Length", "saprfc.appcheader.ncpic_parameters.lu_name_length", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters LU Name Length", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_host_address,
			{ "Host Address", "saprfc.appcheader.ncpic_parameters.host_address", FT_IPv6, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters Host Address", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_security_password,
			{ "Security Password", "saprfc.appcheader.ncpic_parameters.security_password", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters Security Password", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_security_password_length,
			{ "Security Password Length", "saprfc.appcheader.ncpic_parameters.security_password_length", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters Security Password Length", HFILL }},

		{ &hf_saprfc_header_comm_idx,
			{ "Comm Index", "saprfc.appcheader.comm_idx", FT_INT16, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Comm Index", HFILL }},
		{ &hf_saprfc_header_conn_idx,
			{ "Conn Index", "saprfc.appcheader.conn_idx", FT_INT16, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Conn Index", HFILL }},

		/* Payload */
		{ &hf_saprfc_payload,
			{ "Message", "saprfc.message", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Message", HFILL }},

		/* Item fields */
		{ &hf_saprfc_item,
			{ "Item", "saprfc.item", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Item", HFILL }},
		{ &hf_saprfc_item_id1,
			{ "ID1", "saprfc.item.id1", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Item ID 1", HFILL }},
		{ &hf_saprfc_item_id2,
			{ "ID2", "saprfc.item.id2", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Item ID 2", HFILL }},
		{ &hf_saprfc_item_length,
			{ "Length", "saprfc.item.length", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP RFC Item Length", HFILL }},
		{ &hf_saprfc_item_value,
			{ "Value", "saprfc.item.value", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Item Value", HFILL }},

		/* Table content */
		{ &hf_saprfc_table,
			{ "Table", "saprfc.table", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table", HFILL }},
		{ &hf_saprfc_table_structure,
			{ "Table Structure", "saprfc.table.structure", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table Structure", HFILL }},
		{ &hf_saprfc_table_structure_field,
			{ "Table Structure Field", "saprfc.table.structure.field", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table Structure Field", HFILL }},
		{ &hf_saprfc_table_structure_field_type,
			{ "Table Structure Field Type", "saprfc.table.structure.field.type", FT_UINT8, BASE_DEC, VALS(abap_types_typename_values), 0x0, "SAP RFC Table Structure Field Type", HFILL }},
		{ &hf_saprfc_table_structure_field_length,
			{ "Table Structure Field Length", "saprfc.table.structure.field.length", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table Structure Field Length", HFILL }},
		{ &hf_saprfc_table_row,
			{ "Table Row", "saprfc.table.row", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table Row", HFILL }},
		{ &hf_saprfc_table_row_field,
			{ "Table Row Field", "saprfc.table.row.field", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table Row Field", HFILL }},
		{ &hf_saprfc_table_length,
			{ "Table Content Length", "saprfc.table.length", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC Table Content Length", HFILL }},
		{ &hf_saprfc_table_compress_header,
			{ "Compression Header", "saprfc.table.compression", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table Compression Header", HFILL }},
		{ &hf_saprfc_table_uncomplength,
			{ "Uncompressed Length", "saprfc.table.compression.uncomplength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC Table Uncompressed Length", HFILL }},
		{ &hf_saprfc_table_algorithm,
			{ "Compression Algorithm", "saprfc.table.compression.algorithm", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Table Compression Algorithm", HFILL }},
		{ &hf_saprfc_table_magic,
			{ "Magic Bytes", "saprfc.table.compression.magic", FT_UINT16, BASE_HEX, NULL, 0x0, "SAP RFC Table Compression Magic Bytes", HFILL }},
		{ &hf_saprfc_table_special,
			{ "Special", "saprfc.table.compression.special", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Table Special", HFILL }},
		{ &hf_saprfc_table_return_code,
			{ "Decompress Return Code", "saprfc.table.compression.returncode", FT_INT8, BASE_DEC, NULL, 0x0, "SAP RFC Decompression routine return code", HFILL }},
		{ &hf_saprfc_table_content,
			{ "Content", "saprfc.table.content", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table Content", HFILL }},

	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_saprfc
	};

	/* Register the expert info */
	static ei_register_info ei[] = {
		{ &ei_saprfc_invalid_decompression, { "saprfc.table.compression.failed", PI_MALFORMED, PI_WARN, "Decompression of table failed", EXPFILL }},
		{ &ei_saprfc_invalid_decompress_length, { "saprfc.table.compression.uncomplength.invalid", PI_MALFORMED, PI_WARN, "The uncompressed table length differs from the reported length", EXPFILL }},
		{ &ei_saprfc_invalid_table_length, { "saprfc.table.length.invalid", PI_MALFORMED, PI_WARN, "The table length is invalid", EXPFILL }},
		{ &ei_saprfc_item_length_invalid, { "saprfc.item.value.invalid_length", PI_MALFORMED, PI_WARN, "The item length is invalid", EXPFILL }},
		{ &ei_saprfc_unknown_item, { "saprfc.item.unknown", PI_UNDECODED, PI_WARN, "The RFC item has a unknown type that is not dissected", EXPFILL }},
		{ &ei_saprfc_short_appc_header, { "saprfc.appcheader.short", PI_MALFORMED, PI_WARN, "SAP RFC APPC header is too short", EXPFILL }},
	};

	module_t *saprfc_module;
	expert_module_t* saprfc_expert;

	/* Register the protocol */
	proto_saprfc = proto_register_protocol("SAP RFC Protocol", "SAPRFC", "saprfc");

	proto_register_field_array(proto_saprfc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	saprfc_expert = expert_register_protocol(proto_saprfc);
	expert_register_field_array(saprfc_expert, ei, array_length(ei));

	register_dissector("saprfc", dissect_saprfc, proto_saprfc);
	register_dissector("saprfcinternal", dissect_saprfc_internal, proto_saprfc);

	/* Register the preferences */
	saprfc_module = prefs_register_protocol(proto_saprfc, proto_reg_handoff_saprfc);
	prefs_register_bool_preference(saprfc_module, "decompress", "Decompress SAP RFC Protocol tables",
		"Whether the SAP RFC Protocol dissector should decompress table content.",
		&global_saprfc_decompress);
	prefs_register_uint_preference(saprfc_module, "max_uncompressed_size", "Maximum uncompressed table size",
		"Maximum number of bytes to allocate for an uncompressed SAP RFC table.",
		10, &global_saprfc_max_uncompressed_size);
	prefs_register_uint_preference(saprfc_module, "max_reassembled_size", "Maximum reassembled table size",
		"Maximum number of bytes to allocate while reassembling an SAP RFC table.",
		10, &global_saprfc_max_reassembled_size);

	prefs_register_bool_preference(saprfc_module, "table_reassembly", "Reassemble SAP RFC table content",
		"Whether the SAP RFC Protocol dissector should reassemble table content included in payloads.",
		&global_saprfc_table_reassembly);

	prefs_register_bool_preference(saprfc_module, "highlight_unknown_items", "Highlight unknown SAP RFC Items",
		"Whether the SAP RFC Protocol dissector should highlight unknown RFC items (might be noise and generate a lot of expert warnings)",
		&global_saprfc_highlight_items);
}


/**
 * Register Hand off for the SAP RFC Protocol
 */
void
proto_reg_handoff_saprfc(void)
{
	static bool initialized = false;

	if (!initialized) {
		saprfc_handle = create_dissector_handle(dissect_saprfc, proto_saprfc);
		saprfcinternal_handle = create_dissector_handle(dissect_saprfc_internal, proto_saprfc);
		initialized = true;
	}

	dissector_add_uint_range_with_preference("tcp.port", SAPRFC_PORT_RANGE, saprfc_handle);
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
