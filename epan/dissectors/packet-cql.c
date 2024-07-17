/* packet-cql.c
 * Routines for Apache Cassandra CQL dissection
 * Copyright 2015, Aaron Ten Clay <aarontc@aarontc.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * CQL V3 reference: https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v3.spec
 * CQL V4 reference: https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec
 */
#include "config.h"
#include <epan/conversation.h>
#include <epan/packet.h>
#include "packet-tcp.h"
#include <epan/wmem_scopes.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/addr_resolv.h>
#ifdef HAVE_LZ4
#include <lz4.h>
#endif
#ifdef HAVE_SNAPPY
#include <snappy-c.h>
#endif

#define CQL_DEFAULT_PORT 9042 /* Not IANA registered */

/* the code can reasonably attempt to decompress buffer up to 10MB */
#define MAX_UNCOMPRESSED_SIZE (10 * 1024 * 1024)

void proto_reg_handoff_cql(void);
void proto_register_cql(void);

static int proto_cql;
/* CQL header frame fields */
static int hf_cql_version;
static int hf_cql_protocol_version;
static int hf_cql_direction;
/* CQL header frame fields */
static int hf_cql_flags_bitmap;
static int hf_cql_flag_compression;
static int hf_cql_flag_tracing;
static int hf_cql_flag_reserved3;
static int hf_cql_flag_custom_payload;
static int hf_cql_flag_warning;
static int hf_cql_flag_reserved4;
static int hf_cql_stream;
static int hf_cql_opcode;
static int hf_cql_length;
/* CQL data types */
/*
static int hf_cql_int;
static int hf_cql_long;
static int hf_cql_uuid;
static int hf_cql_bytes;
static int hf_cql_inet;
*/
/* Batch flags */

static int hf_cql_batch_flag_serial_consistency;
static int hf_cql_batch_flag_default_timestamp;
static int hf_cql_batch_flag_with_name_for_values;
static int hf_cql_batch_flags_bitmap;
static int ett_cql_batch_flags_bitmap;

static int hf_cql_consistency;
static int hf_cql_string_length;
static int hf_cql_string_map_size;
static int hf_cql_string;
static int hf_cql_auth_token;
static int hf_cql_value_count;
static int hf_cql_short_bytes_length;
static int hf_cql_bytes_length;
static int hf_cql_bytes;
static int hf_cql_bigint;
static int hf_cql_scale;
static int hf_cql_boolean;
static int hf_cql_ascii;
static int hf_cql_double;
static int hf_cql_float;
static int hf_cql_custom;
static int hf_cql_null_value;
static int hf_cql_int;
static int hf_cql_uuid;
static int hf_cql_tracing_uuid;
static int hf_cql_port;
static int hf_cql_timeuuid;
static int hf_cql_varchar;
static int hf_cql_varint_count8;
static int hf_cql_varint_count16;
static int hf_cql_varint_count32;
static int hf_cql_varint_count64;
static int hf_cql_raw_compressed_bytes;
static int hf_cql_paging_state;
static int hf_cql_page_size;
static int hf_cql_timestamp;
static int hf_cql_query_id;
static int hf_cql_event_type;
static int hf_cql_event_schema_change_type;
static int hf_cql_event_schema_change_type_target;
static int hf_cql_event_schema_change_keyspace;
static int hf_cql_event_schema_change_object;
static int hf_cql_result_timestamp;
static int hf_cql_string_list_size;
static int hf_cql_batch_type;
static int hf_cql_batch_query_type;
static int hf_cql_batch_query_size;
static int hf_cql_error_code;
static int hf_cql_result_kind;
static int hf_cql_result_rows_data_type;

static int hf_cql_query_flags_bitmap;
static int hf_cql_query_flags_values;
static int hf_cql_query_flags_skip_metadata;
static int hf_cql_query_flags_page_size;
static int hf_cql_query_flags_paging_state;
static int hf_cql_query_flags_serial_consistency;
static int hf_cql_query_flags_default_timestamp;
static int hf_cql_query_flags_names_for_values;
static int hf_cql_query_flags_reserved3;

static int hf_cql_result_rows_flags_values;
static int hf_cql_result_prepared_flags_values;
static int hf_cql_result_rows_flag_global_tables_spec;
static int hf_cql_result_rows_flag_has_more_pages;
static int hf_cql_result_rows_flag_no_metadata;
static int hf_cql_result_rows_column_count;
static int hf_cql_result_rows_tuple_size;

static int hf_cql_result_prepared_pk_count;

static int hf_cql_string_result_rows_global_table_spec_ksname;
static int hf_cql_string_result_rows_global_table_spec_table_name;
static int hf_cql_string_result_rows_table_name;
static int hf_cql_string_result_rows_keyspace_name;
static int hf_cql_string_result_rows_column_name;
static int hf_cql_result_rows_row_count;
static int hf_cql_string_result_rows_udt_name;
static int hf_cql_string_result_rows_udt_size;
static int hf_cql_string_result_rows_udt_field_name;
static int hf_cql_string_result_rows_list_size;
static int hf_cql_string_result_rows_map_size;
static int hf_cql_string_result_rows_set_size;
static int hf_cql_bytesmap_string;

static int ett_cql_protocol;
static int ett_cql_version;
static int ett_cql_message;
static int ett_cql_result_columns;
static int ett_cql_results_no_metadata;
static int ett_cql_result_map;
static int ett_cql_result_set;
static int ett_cql_result_metadata;
static int ett_cql_result_rows;
static int ett_cql_result_metadata_colspec;
static int ett_cql_header_flags_bitmap;
static int ett_cql_query_flags_bitmap;
static int ett_cql_custom_payload;

static int hf_cql_response_in;
static int hf_cql_response_to;
static int hf_cql_response_time;

static int hf_cql_ipv4;
static int hf_cql_ipv6;

/* desegmentation of CQL */
static bool cql_desegment = true;

static expert_field ei_cql_data_not_dissected_yet;
static expert_field ei_cql_unexpected_negative_value;


typedef struct _cql_transaction_type {
	uint32_t req_frame;
	uint32_t rep_frame;
	nstime_t req_time;
} cql_transaction_type;

typedef struct _cql_conversation_info_type {
	wmem_map_t* streams;
} cql_conversation_type;

static const value_string cql_direction_names[] = {
	{ 0x0, "Request" },
	{ 0x8, "Response" },
	{ 0x0, NULL }
};

typedef enum {
	CQL_BATCH_FLAG_SERIAL_CONSISTENCY =   0x10,
	CQL_BATCH_FLAG_DEFAULT_TIMESTAMP =    0x20,
	CQL_BATCH_FLAG_WITH_NAME_FOR_VALUES = 0x40
} cql_batch_flags;

typedef enum {
	CQL_OPCODE_ERROR = 0x00,
	CQL_OPCODE_STARTUP = 0x01,
	CQL_OPCODE_READY = 0x02,
	CQL_OPCODE_AUTHENTICATE = 0x03,
	/* Opcode 0x04 not used in CQL */
	CQL_OPCODE_OPTIONS = 0x05,
	CQL_OPCODE_SUPPORTED = 0x06,
	CQL_OPCODE_QUERY = 0x07,
	CQL_OPCODE_RESULT = 0x08,
	CQL_OPCODE_PREPARE = 0x09,
	CQL_OPCODE_EXECUTE = 0x0A,
	CQL_OPCODE_REGISTER = 0x0B,
	CQL_OPCODE_EVENT = 0x0C,
	CQL_OPCODE_BATCH = 0x0D,
	CQL_OPCODE_AUTH_CHALLENGE = 0x0E,
	CQL_OPCODE_AUTH_RESPONSE = 0x0F,
	CQL_OPCODE_AUTH_SUCCESS = 0x10
} cql_opcode_type;

static const value_string cql_opcode_names[] = {
	{ CQL_OPCODE_ERROR, "ERROR" },
	{ CQL_OPCODE_STARTUP, "STARTUP" },
	{ CQL_OPCODE_READY, "READY" },
	{ CQL_OPCODE_AUTHENTICATE, "AUTHENTICATE" },
	{ CQL_OPCODE_OPTIONS, "OPTIONS" },
	{ CQL_OPCODE_SUPPORTED, "SUPPORTED" },
	{ CQL_OPCODE_QUERY, "QUERY" },
	{ CQL_OPCODE_RESULT, "RESULT" },
	{ CQL_OPCODE_PREPARE, "PREPARE" },
	{ CQL_OPCODE_EXECUTE, "EXECUTE" },
	{ CQL_OPCODE_REGISTER, "REGISTER" },
	{ CQL_OPCODE_EVENT, "EVENT" },
	{ CQL_OPCODE_BATCH, "BATCH" },
	{ CQL_OPCODE_AUTH_CHALLENGE, "AUTH_CHALLENGE" },
	{ CQL_OPCODE_AUTH_RESPONSE, "AUTH_RESPONSE" },
	{ CQL_OPCODE_AUTH_SUCCESS, "AUTH_SUCCESS" },
	{ 0x00, NULL }
};


typedef enum {
	CQL_HEADER_FLAG_COMPRESSION = 0x01,
	CQL_HEADER_FLAG_TRACING = 0x02,
	CQL_HEADER_FLAG_V3_RESERVED = 0xFC,
	CQL_HEADER_FLAG_CUSTOM_PAYLOAD = 0x04,
	CQL_HEADER_FLAG_WARNING = 0x08,
	CQL_HEADER_FLAG_V4_RESERVED = 0xF0
} cql_flags;

typedef enum {
	CQL_QUERY_FLAG_VALUES = 0x01,
	CQL_QUERY_FLAG_SKIP_METADATA = 0x02,
	CQL_QUERY_FLAG_PAGE_SIZE = 0x04,
	CQL_QUERY_FLAG_PAGING_STATE = 0x08,
	CQL_QUERY_FLAG_SERIAL_CONSISTENCY = 0x10,
	CQL_QUERY_FLAG_DEFAULT_TIMESTAMP = 0x20,
	CQL_QUERY_FLAG_VALUE_NAMES = 0x40,
	CQL_QUERY_FLAG_V3_RESERVED = 0x80
} cql_query_flags;


typedef enum {
	CQL_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC = 0x0001,
	CQL_RESULT_ROWS_FLAG_HAS_MORE_PAGES = 0x0002,
	CQL_RESULT_ROWS_FLAG_NO_METADATA = 0x0004
} cql_result_rows_flags;

typedef enum {
	CQL_CONSISTENCY_ANY = 0x0000,
	CQL_CONSISTENCY_ONE = 0x0001,
	CQL_CONSISTENCY_TWO = 0x0002,
	CQL_CONSISTENCY_THREE = 0x003,
	CQL_CONSISTENCY_QUORUM = 0x0004,
	CQL_CONSISTENCY_ALL = 0x0005,
	CQL_CONSISTENCY_LOCAL_QUORUM = 0x0006,
	CQL_CONSISTENCY_EACH_QUORUM = 0x0007,
	CQL_CONSISTENCY_SERIAL = 0x0008,
	CQL_CONSISTENCY_LOCAL_SERIAL = 0x0009,
	CQL_CONSISTENCY_LOCAL_ONE = 0x000A
} cql_consistencies;

static const value_string cql_consistency_names[] = {
	{ CQL_CONSISTENCY_ANY, "ANY" },
	{ CQL_CONSISTENCY_ONE, "ONE" },
	{ CQL_CONSISTENCY_TWO, "TWO" },
	{ CQL_CONSISTENCY_THREE, "THREE" },
	{ CQL_CONSISTENCY_QUORUM, "QUORUM" },
	{ CQL_CONSISTENCY_ALL, "ALL" },
	{ CQL_CONSISTENCY_LOCAL_QUORUM, "LOCAL_QUORUM" },
	{ CQL_CONSISTENCY_EACH_QUORUM, "EACH_QUORUM" },
	{ CQL_CONSISTENCY_SERIAL, "SERIAL" },
	{ CQL_CONSISTENCY_LOCAL_SERIAL, "LOCAL_SERIAL" },
	{ CQL_CONSISTENCY_LOCAL_ONE, "LOCAL_ONE" },
	{ 0x00, NULL }
};


typedef enum {
	CQL_BATCH_TYPE_LOGGED = 0,
	CQL_BATCH_TYPE_UNLOGGED = 1,
	CQL_BATCH_TYPE_COUNTER = 2
} cql_batch_types;

static const value_string cql_batch_type_names[] = {
	{ CQL_BATCH_TYPE_LOGGED, "LOGGED" },
	{ CQL_BATCH_TYPE_UNLOGGED, "UNLOGGED" },
	{ CQL_BATCH_TYPE_COUNTER, "COUNTER" },
	{ 0x00, NULL }
};

typedef enum {
	CQL_BATCH_QUERY_TYPE_QUERY = 0,
	CQL_BATCH_QUERY_TYPE_PREPARED = 1
} cql_batch_query_types;

static const value_string cql_batch_query_type_names[] = {
	{ CQL_BATCH_QUERY_TYPE_QUERY, "QUERY" },
	{ CQL_BATCH_QUERY_TYPE_PREPARED, "PREPARED" },
	{ 0x00, NULL }
};

typedef enum {
	CQL_RESULT_KIND_VOID = 0x0001,
	CQL_RESULT_KIND_ROWS = 0x0002,
	CQL_RESULT_KIND_SET_KEYSPACE = 0x0003,
	CQL_RESULT_KIND_PREPARED = 0x0004,
	CQL_RESULT_KIND_SCHEMA_CHANGE = 0x0005
} cql_result_kinds;

static const value_string cql_result_kind_names[] = {
	{ CQL_RESULT_KIND_VOID, "VOID" },
	{ CQL_RESULT_KIND_ROWS, "Rows" },
	{ CQL_RESULT_KIND_SET_KEYSPACE, "Set Keyspace" },
	{ CQL_RESULT_KIND_PREPARED, "Prepared" },
	{ CQL_RESULT_KIND_SCHEMA_CHANGE, "Schema Change" },
	{ 0x00, NULL }
};



typedef enum {
	CQL_RESULT_ROW_TYPE_CUSTOM = 0x0000,
	CQL_RESULT_ROW_TYPE_ASCII = 0x0001,
	CQL_RESULT_ROW_TYPE_BIGINT = 0x0002,
	CQL_RESULT_ROW_TYPE_BLOB = 0x0003,
	CQL_RESULT_ROW_TYPE_BOOLEAN = 0x0004,
	CQL_RESULT_ROW_TYPE_COUNTER = 0x0005,
	CQL_RESULT_ROW_TYPE_DECIMAL = 0x0006,
	CQL_RESULT_ROW_TYPE_DOUBLE = 0x0007,
	CQL_RESULT_ROW_TYPE_FLOAT = 0x0008,
	CQL_RESULT_ROW_TYPE_INT = 0x0009,
	CQL_RESULT_ROW_TYPE_TIMESTAMP = 0x000B,
	CQL_RESULT_ROW_TYPE_UUID = 0x000C,
	CQL_RESULT_ROW_TYPE_VARCHAR = 0x000D,
	CQL_RESULT_ROW_TYPE_VARINT = 0x000E,
	CQL_RESULT_ROW_TYPE_TIMEUUID = 0x000F,
	CQL_RESULT_ROW_TYPE_INET = 0x0010,
	CQL_RESULT_ROW_TYPE_DATE = 0x0011,
	CQL_RESULT_ROW_TYPE_TIME = 0x0012,
	CQL_RESULT_ROW_TYPE_SMALLINT = 0x0013,
	CQL_RESULT_ROW_TYPE_TINYINT = 0x0014,
	CQL_RESULT_ROW_TYPE_LIST = 0x0020,
	CQL_RESULT_ROW_TYPE_MAP = 0x0021,
	CQL_RESULT_ROW_TYPE_SET = 0x0022,
	CQL_RESULT_ROW_TYPE_UDT = 0x0030,
	CQL_RESULT_ROW_TYPE_TUPLE = 0x0031
} cql_result_row_data_types;

static const value_string cql_result_row_type_names[] = {
	{ CQL_RESULT_ROW_TYPE_CUSTOM, "CUSTOM" },
	{ CQL_RESULT_ROW_TYPE_ASCII, "ASCII" },
	{ CQL_RESULT_ROW_TYPE_BIGINT, "BIGINT" },
	{ CQL_RESULT_ROW_TYPE_BLOB, "BLOB" },
	{ CQL_RESULT_ROW_TYPE_BOOLEAN, "BOOLEAN" },
	{ CQL_RESULT_ROW_TYPE_COUNTER, "COUNTER" },
	{ CQL_RESULT_ROW_TYPE_DECIMAL, "DECIMAL" },
	{ CQL_RESULT_ROW_TYPE_DOUBLE, "DOUBLE" },
	{ CQL_RESULT_ROW_TYPE_FLOAT, "FLOAT" },
	{ CQL_RESULT_ROW_TYPE_INT, "INT" },
	{ CQL_RESULT_ROW_TYPE_TIMESTAMP, "TIMESTAMP" },
	{ CQL_RESULT_ROW_TYPE_UUID, "UUID" },
	{ CQL_RESULT_ROW_TYPE_VARCHAR, "VARCHAR" },
	{ CQL_RESULT_ROW_TYPE_VARINT, "VARINT" },
	{ CQL_RESULT_ROW_TYPE_TIMEUUID, "TIMEUUID" },
	{ CQL_RESULT_ROW_TYPE_INET, "INET" },
	{ CQL_RESULT_ROW_TYPE_DATE, "DATE" },
	{ CQL_RESULT_ROW_TYPE_TIME, "TIME" },
	{ CQL_RESULT_ROW_TYPE_SMALLINT, "SMALLINT" },
	{ CQL_RESULT_ROW_TYPE_TINYINT, "TINYINT" },
	{ CQL_RESULT_ROW_TYPE_LIST, "LIST" },
	{ CQL_RESULT_ROW_TYPE_MAP, "MAP" },
	{ CQL_RESULT_ROW_TYPE_SET, "SET" },
	{ CQL_RESULT_ROW_TYPE_UDT, "UDT" },
	{ CQL_RESULT_ROW_TYPE_TUPLE, "TUPLE" },
	{ 0x0, NULL }
};

/* From https://github.com/apache/cassandra/blob/cbf4dcb3345c7e2f42f6a897c66b6460b7acc2ca/doc/native_protocol_v4.spec#L1046 */
typedef enum {
	CQL_ERROR_SERVER = 0x0000,
	CQL_ERROR_PROTOCOL = 0x000A,
	CQL_ERROR_AUTH = 0x0100,
	CQL_ERROR_UNAVAILABLE = 0x1000,
	CQL_ERROR_OVERLOADED = 0x1001,
	CQL_ERROR_BOOTSTRAPPING = 0x1002,
	CQL_ERROR_TRUNCATE = 0x1003,
	CQL_ERROR_WRITE_TIMEOUT = 0x1100,
	CQL_ERROR_READ_TIMEOUT = 0x1200,
	CQL_ERROR_READ_FAILURE = 0x1300,
	CQL_ERROR_FUNCTION_FAILURE = 0x1400,
	CQL_ERROR_WRITE_FAILURE = 0x1500,
	CQL_ERROR_SYNTAX = 0x2000,
	CQL_ERROR_UNAUTHORIEZED = 0x2100,
	CQL_ERROR_INVALID = 0x2200,
	CQL_ERROR_CONFIG = 0x2300,
	CQL_ERROR_ALREADY_EXISTS = 0x2400,
	CQL_ERROR_UNPREPARED = 0x2500
} cql_error_types;

static const value_string cql_error_names[] = {
	{ CQL_ERROR_SERVER, "Server error" },
	{ CQL_ERROR_PROTOCOL, "Protocol error" },
	{ CQL_ERROR_AUTH, "Authentication error" },
	{ CQL_ERROR_UNAVAILABLE, "Unavailable exception" },
	{ CQL_ERROR_OVERLOADED, "Overloaded" },
	{ CQL_ERROR_BOOTSTRAPPING, "Is_bootstrapping" },
	{ CQL_ERROR_TRUNCATE, "Truncate_error" },
	{ CQL_ERROR_WRITE_TIMEOUT, "Write_timeout" },
	{ CQL_ERROR_READ_TIMEOUT, "Read_timeout" },
	{ CQL_ERROR_READ_FAILURE, "Read_failure" },
	{ CQL_ERROR_FUNCTION_FAILURE, "Function_failure" },
	{ CQL_ERROR_WRITE_FAILURE, "Write_failure" },
	{ CQL_ERROR_SYNTAX, "Syntax_error" },
	{ CQL_ERROR_UNAUTHORIEZED, "Unauthorized" },
	{ CQL_ERROR_INVALID, "Invalid" },
	{CQL_ERROR_CONFIG, "Config_error" },
	{ CQL_ERROR_ALREADY_EXISTS, "Already_exists" },
	{ CQL_ERROR_UNPREPARED, "Unprepared" },
	{ 0x0, NULL}
};

static int
dissect_cql_query_parameters(proto_tree* cql_subtree, tvbuff_t* tvb, int offset, int execute)
{
	int32_t bytes_length = 0;
	uint32_t flags = 0;
	uint64_t i = 0;
	uint32_t string_length = 0;
	uint32_t value_count = 0;

	static int * const cql_query_bitmaps[] = {
		&hf_cql_query_flags_values,
		&hf_cql_query_flags_skip_metadata,
		&hf_cql_query_flags_page_size,
		&hf_cql_query_flags_paging_state,
		&hf_cql_query_flags_serial_consistency,
		&hf_cql_query_flags_default_timestamp,
		&hf_cql_query_flags_names_for_values,
		&hf_cql_query_flags_reserved3,
		NULL
	};

	/* consistency */
	proto_tree_add_item(cql_subtree, hf_cql_consistency, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* flags */
	proto_tree_add_bitmask(cql_subtree, tvb, offset, hf_cql_query_flags_bitmap, ett_cql_query_flags_bitmap, cql_query_bitmaps, ENC_BIG_ENDIAN);
	flags = tvb_get_uint8(tvb, offset);
	offset += 1;

	if(flags & CQL_QUERY_FLAG_VALUES) {
		proto_tree_add_item_ret_uint(cql_subtree, hf_cql_value_count, tvb, offset, 2, ENC_BIG_ENDIAN, &value_count);
		offset += 2;
		for (i = 0; i < value_count; ++i) {
			if (!execute && flags & CQL_QUERY_FLAG_VALUE_NAMES) {
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
				offset += 2;
				proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				offset += string_length;
			}
			proto_tree_add_item_ret_int(cql_subtree, hf_cql_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
			offset += 4;
			if (bytes_length > 0) {
				proto_tree_add_item(cql_subtree, hf_cql_bytes, tvb, offset, bytes_length, ENC_NA);
				offset += bytes_length;
			}
		}
	}

	if (flags & CQL_QUERY_FLAG_PAGE_SIZE) {
		proto_tree_add_item(cql_subtree, hf_cql_page_size, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if (flags & CQL_QUERY_FLAG_PAGING_STATE) {
		proto_tree_add_item_ret_int(cql_subtree, hf_cql_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
		offset += 4;
		if (bytes_length > 0) {
			proto_tree_add_item(cql_subtree, hf_cql_bytes, tvb, offset, bytes_length, ENC_NA);
			offset += bytes_length;
		}
	}

	if (flags & CQL_QUERY_FLAG_SERIAL_CONSISTENCY) {
		proto_tree_add_item(cql_subtree, hf_cql_consistency, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (flags & CQL_QUERY_FLAG_DEFAULT_TIMESTAMP) {
		proto_tree_add_item(cql_subtree, hf_cql_timestamp, tvb, offset, 8, ENC_TIME_USECS|ENC_BIG_ENDIAN);
		offset += 8;
	}

	return offset;
}

static unsigned
get_cql_pdu_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset, void* data _U_)
{
	/* CQL has 32-bit length at 5th byte in frame. */
	uint32_t length = tvb_get_ntohl(tvb, offset + 5);

	/* Include length of frame header. */
	return length + 9;
}

static cql_transaction_type*
cql_transaction_add_request(cql_conversation_type* conv,
				packet_info* pinfo,
				int32_t stream,
				int fake)
{
	cql_transaction_type* trans;
	wmem_list_t* list;

	list = (wmem_list_t*)wmem_map_lookup(conv->streams, GINT_TO_POINTER(stream));
	if(!list) {
		list = wmem_list_new(wmem_file_scope());
	} else {
		wmem_map_remove(conv->streams, GINT_TO_POINTER(stream));
	}

	trans = wmem_new(wmem_file_scope(), cql_transaction_type);
	if (fake) {
		trans->req_frame = 0;
	} else {
		trans->req_frame = pinfo->fd->num;
	}
	trans->rep_frame = 0;
	trans->req_time = pinfo->abs_ts;

	wmem_list_append(list, (void *)trans);
	wmem_map_insert(conv->streams, GINT_TO_POINTER(stream), (void*)list);

	return trans;
}

static cql_transaction_type*
cql_enrich_transaction_with_response(cql_conversation_type* conv,
					packet_info* pinfo,
					int32_t stream)
{
	cql_transaction_type* trans;
	wmem_list_frame_t* frame;
	wmem_list_t* list;

	list = (wmem_list_t*)wmem_map_lookup(conv->streams, GINT_TO_POINTER(stream));
	if (!list) {
		return NULL;
	}

	frame = wmem_list_tail(list);
	if (!frame) {
		return NULL;
	}

	trans = (cql_transaction_type *)wmem_list_frame_data(frame);
	if (!trans) {
		return NULL;
	}

	trans->rep_frame = pinfo->fd->num;

	return trans;
}

static cql_transaction_type*
cql_transaction_lookup(cql_conversation_type* conv,
			packet_info* pinfo,
			int32_t stream)
{
	wmem_list_frame_t* frame;
	wmem_list_t* list;

	list = (wmem_list_t*)wmem_map_lookup(conv->streams, GINT_TO_POINTER(stream));
	if (!list) {
		return NULL;
	}

	frame = wmem_list_head(list);
	if (!frame) {
		return NULL;
	}

	do {
		cql_transaction_type* trans = NULL;
		trans = (cql_transaction_type *)wmem_list_frame_data(frame);
		if (trans->req_frame == pinfo->fd->num || trans->rep_frame == pinfo->fd->num) {
			return trans;
		}
	} while ((frame = wmem_list_frame_next(frame)));

	return NULL;
}

typedef enum {
	CQL_COMPRESSION_NONE = 0,
	CQL_COMPRESSION_LZ4 = 1,
	CQL_COMPRESSION_SNAPPY = 2,
	CQL_DECOMPRESSION_ATTEMPTED = 3,
} cql_compression_level;


// NOLINTNEXTLINE(misc-no-recursion)
static int parse_option(proto_tree* metadata_subtree, packet_info *pinfo, tvbuff_t* tvb, int offset)
{
	uint32_t data_type = 0;
	uint32_t string_length = 0;
	uint32_t tuple_size = 0;
	uint32_t udt_size = 0;
	uint32_t i = 0;

	proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_result_rows_data_type, tvb, offset, 2, ENC_BIG_ENDIAN, &data_type);
	offset += 2;
	increment_dissection_depth(pinfo);
	switch (data_type) {
		case CQL_RESULT_ROW_TYPE_LIST:
			offset = parse_option(metadata_subtree, pinfo, tvb, offset);
			break;
		case CQL_RESULT_ROW_TYPE_MAP:
			offset = parse_option(metadata_subtree, pinfo, tvb, offset);
			offset = parse_option(metadata_subtree, pinfo, tvb, offset);
			break;
		case CQL_RESULT_ROW_TYPE_SET:
			offset = parse_option(metadata_subtree, pinfo, tvb, offset);
			break;
		case CQL_RESULT_ROW_TYPE_UDT:
			/* keyspace */
			proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
			offset += 2;
			proto_tree_add_item(metadata_subtree, hf_cql_string_result_rows_keyspace_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
			offset += string_length;

			/* UDT name */
			proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
			offset += 2;
			proto_tree_add_item(metadata_subtree, hf_cql_string_result_rows_udt_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
			offset += string_length;

			/* UDT size */
			proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_string_result_rows_udt_size, tvb, offset, 2, ENC_BIG_ENDIAN, &udt_size);
			offset += 2;

			for (i = 0; i < udt_size; i++) {
				/* UDT field name */
				proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
				offset += 2;
				proto_tree_add_item(metadata_subtree, hf_cql_string_result_rows_udt_field_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				offset += string_length;

				/* UDT field option */
				offset = parse_option(metadata_subtree, pinfo, tvb, offset);
			}
			break;
		case CQL_RESULT_ROW_TYPE_TUPLE:
			proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_result_rows_tuple_size, tvb, offset, 2, ENC_BIG_ENDIAN, &tuple_size);
			offset += 2;
			for (i = 0; i < tuple_size; i++) {
				offset = parse_option(metadata_subtree, pinfo, tvb, offset);
			}
			break;
		default:
			break;
	}
	decrement_dissection_depth(pinfo);

	return offset;
}

static void add_varint_item(proto_tree *tree, tvbuff_t *tvb, const int offset, int length)
{
	switch (length)
	{
	case 1:
		proto_tree_add_item(tree, hf_cql_varint_count8,  tvb, offset, 1, ENC_BIG_ENDIAN);
		break;
	case 2:
		proto_tree_add_item(tree, hf_cql_varint_count16, tvb, offset, 2, ENC_BIG_ENDIAN);
		break;
	case 3:
		proto_tree_add_item(tree, hf_cql_varint_count32, tvb, offset, 3, ENC_BIG_ENDIAN);
		break;
	case 4:
		proto_tree_add_item(tree, hf_cql_varint_count32, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;
	case 5:
		proto_tree_add_item(tree, hf_cql_varint_count64, tvb, offset, 5, ENC_BIG_ENDIAN);
		break;
	case 6:
		proto_tree_add_item(tree, hf_cql_varint_count64, tvb, offset, 6, ENC_BIG_ENDIAN);
		break;
	case 7:
		proto_tree_add_item(tree, hf_cql_varint_count64, tvb, offset, 7, ENC_BIG_ENDIAN);
		break;
	case 8:
		proto_tree_add_item(tree, hf_cql_varint_count64, tvb, offset, 8, ENC_BIG_ENDIAN);
		break;
	}
}

static void add_cql_uuid(proto_tree* tree, int hf_uuid, tvbuff_t* tvb, int offset)
{
	e_guid_t guid;
	int i;

	guid.data1 = tvb_get_letohl(tvb, offset+12);
	guid.data2 = tvb_get_letohl(tvb, offset+10);
	guid.data3 = tvb_get_letohl(tvb, offset+8);

	for (i = 0; i < 8; i++)
	{
		guid.data4[i] = tvb_get_uint8(tvb, offset+(7-i));
	}

	proto_tree_add_guid(tree, hf_uuid, tvb, offset, 16, &guid);
}


// NOLINTNEXTLINE(misc-no-recursion)
static int parse_value(proto_tree* columns_subtree, packet_info *pinfo, tvbuff_t* tvb, int* offset_metadata, int offset)
{
	uint32_t data_type = 0;
	uint32_t string_length = 0;
	int32_t bytes_length = 0;
	uint32_t tuple_size = 0;
	int32_t list_size = 0;
	int32_t map_size = 0;
	int32_t set_size = 0;
	uint32_t udt_size = 0;
	proto_item *item;
	proto_item *sub_item;
	uint32_t i = 0;
	int32_t j = 0;
	int offset_metadata_backup = 0;
	uint32_t addr4;
	ws_in6_addr addr6;
	uint32_t port_number;
	proto_tree* map_subtree;
	proto_tree* set_subtree;

	proto_tree_add_item_ret_int(columns_subtree, hf_cql_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
	offset += 4;

	item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_result_rows_data_type, tvb, *offset_metadata, 2, ENC_BIG_ENDIAN, &data_type);
	proto_item_set_hidden(item);
	*offset_metadata += 2;

	if (bytes_length == -1) { // value is NULL, but need to skip metadata offsets
		proto_tree_add_item(columns_subtree, hf_cql_null_value, tvb, offset, 0, ENC_NA);
		if (data_type == CQL_RESULT_ROW_TYPE_MAP) {
			*offset_metadata += 4; /* skip the type fields of *both* key and value in the map in the metadata */
		} else if (data_type == CQL_RESULT_ROW_TYPE_SET) {
			*offset_metadata += 2; /* skip the type field of the elements in the set in the metadata */
		}
		return offset;
	}

	increment_dissection_depth(pinfo);
	switch (data_type) {
		case CQL_RESULT_ROW_TYPE_CUSTOM:
			proto_tree_add_item(columns_subtree, hf_cql_custom, tvb, offset, bytes_length, ENC_UTF_8 | ENC_NA);
			offset += bytes_length;
			break;
		case CQL_RESULT_ROW_TYPE_ASCII:
			proto_tree_add_item(columns_subtree, hf_cql_ascii, tvb, offset, bytes_length, ENC_ASCII | ENC_NA);
			offset += bytes_length;
			break;
		case CQL_RESULT_ROW_TYPE_BIGINT:
			proto_tree_add_item(columns_subtree, hf_cql_bigint, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
			break;
		case CQL_RESULT_ROW_TYPE_BLOB:
			proto_tree_add_item(columns_subtree, hf_cql_bytes, tvb, offset, bytes_length, ENC_NA);
			offset += bytes_length;
			break;
		case CQL_RESULT_ROW_TYPE_BOOLEAN:
			proto_tree_add_boolean(columns_subtree, hf_cql_boolean, tvb, offset, 1, true);
			offset += 1;
			break;
		case CQL_RESULT_ROW_TYPE_COUNTER:
			break;
		case CQL_RESULT_ROW_TYPE_DECIMAL:
			proto_tree_add_item(columns_subtree, hf_cql_scale, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			add_varint_item(columns_subtree, tvb, offset, bytes_length - 4);
			offset += bytes_length - 4;
			break;
		case CQL_RESULT_ROW_TYPE_DOUBLE:
			proto_tree_add_item(columns_subtree, hf_cql_double, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
			break;
		case CQL_RESULT_ROW_TYPE_FLOAT:
			proto_tree_add_item(columns_subtree, hf_cql_float, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case CQL_RESULT_ROW_TYPE_INT:
			proto_tree_add_item(columns_subtree, hf_cql_int, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case CQL_RESULT_ROW_TYPE_TIMESTAMP:
			proto_tree_add_item(columns_subtree, hf_cql_result_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
			break;
		case CQL_RESULT_ROW_TYPE_UUID:
			add_cql_uuid(columns_subtree, hf_cql_uuid, tvb, offset);
			offset += 16;
			break;
		case CQL_RESULT_ROW_TYPE_VARCHAR:
			proto_tree_add_item(columns_subtree, hf_cql_varchar, tvb, offset, bytes_length, ENC_ASCII);
			offset += bytes_length;
			break;
		case CQL_RESULT_ROW_TYPE_VARINT:
			add_varint_item(columns_subtree, tvb, offset, bytes_length);
			offset += bytes_length;
			break;
		case CQL_RESULT_ROW_TYPE_TIMEUUID:
			add_cql_uuid(columns_subtree, hf_cql_timeuuid, tvb, offset);
			offset += 16;
			break;
		case CQL_RESULT_ROW_TYPE_INET:
			switch (bytes_length) {
				case 4:
				case 8:
					addr4 = tvb_get_ipv4(tvb, offset);
					proto_tree_add_ipv4_format_value(columns_subtree, hf_cql_ipv4, tvb, offset, 4, addr4, "%s", get_hostname(addr4));
					offset += 4;
				break;
				case 16:
				case 20:
					tvb_get_ipv6(tvb, offset, &addr6);
					proto_tree_add_ipv6_format_value(columns_subtree, hf_cql_ipv6, tvb, offset, 16, &addr6, "%s", get_hostname6(&addr6));
					offset += 16;
					break;
				default:
					break;
			}
			/* port number is optional */
			if (bytes_length == 16 || bytes_length == 20) {
				sub_item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_port, tvb, offset, 4, ENC_BIG_ENDIAN, &port_number);
				proto_item_append_text(sub_item, " (%u)", port_number);
				offset += 4;
			}
			break;
		case CQL_RESULT_ROW_TYPE_DATE:
			break;
		case CQL_RESULT_ROW_TYPE_TIME:
			break;
		case CQL_RESULT_ROW_TYPE_SMALLINT:
			break;
		case CQL_RESULT_ROW_TYPE_TINYINT:
			break;
		case CQL_RESULT_ROW_TYPE_LIST:
			item = proto_tree_add_item_ret_int(columns_subtree, hf_cql_string_result_rows_list_size, tvb, offset, 4, ENC_BIG_ENDIAN, &list_size);
			if (list_size < 0) {
				expert_add_info(pinfo, item, &ei_cql_unexpected_negative_value);
				decrement_dissection_depth(pinfo);
				return tvb_reported_length(tvb);
			}
			offset += 4;
			offset_metadata_backup = *offset_metadata;
			for (j = 0; j < list_size; j++) {
				*offset_metadata = offset_metadata_backup;
				offset = parse_value(columns_subtree, pinfo, tvb, offset_metadata, offset);
			}
			break;
		case CQL_RESULT_ROW_TYPE_MAP:
			map_subtree = proto_tree_add_subtree(columns_subtree, tvb, offset, 0, ett_cql_result_map, NULL, "Map");
			item = proto_tree_add_item_ret_int(map_subtree, hf_cql_string_result_rows_map_size, tvb, offset, 4, ENC_BIG_ENDIAN, &map_size);
			offset += 4;
			proto_item_append_text(map_subtree, " with %" PRId32 " element(s)", map_size);
			if (map_size < 0) {
				expert_add_info(pinfo, item, &ei_cql_unexpected_negative_value);
				decrement_dissection_depth(pinfo);
				return tvb_reported_length(tvb);
			} else if (map_size == 0) {
				*offset_metadata += 4; /* skip the type fields of *both* key and value in the map in the metadata */
			} else {
				offset_metadata_backup = *offset_metadata;
				for (j = 0; j < map_size; j++) {
					*offset_metadata = offset_metadata_backup;
					offset = parse_value(map_subtree, pinfo, tvb, offset_metadata, offset);
					offset = parse_value(map_subtree, pinfo, tvb, offset_metadata, offset);
				}
			}
			break;
		case CQL_RESULT_ROW_TYPE_SET:
			set_subtree = proto_tree_add_subtree(columns_subtree, tvb, offset, 0, ett_cql_result_set, NULL, "Set");
			item = proto_tree_add_item_ret_int(set_subtree, hf_cql_string_result_rows_set_size, tvb, offset, 4, ENC_BIG_ENDIAN, &set_size);
			offset += 4;
			if (set_size < 0) {
				expert_add_info(pinfo, item, &ei_cql_unexpected_negative_value);
				decrement_dissection_depth(pinfo);
				return tvb_reported_length(tvb);
			} else if (set_size == 0) {
				*offset_metadata += 2; /* skip the type field of the elements in the set in the metadata */
			} else {
				offset_metadata_backup = *offset_metadata;
				for (j = 0; j < set_size; j++) {
					*offset_metadata = offset_metadata_backup;
					offset = parse_value(set_subtree, pinfo, tvb, offset_metadata, offset);
				}
			}
			break;
		case CQL_RESULT_ROW_TYPE_UDT:
			/* keyspace */
			item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_string_length, tvb, *offset_metadata, 2, ENC_BIG_ENDIAN, &string_length);
			proto_item_set_hidden(item);
			*offset_metadata += 2;
			item = proto_tree_add_item(columns_subtree, hf_cql_string_result_rows_keyspace_name, tvb, *offset_metadata, string_length, ENC_UTF_8 | ENC_NA);
			proto_item_set_hidden(item);
			*offset_metadata += string_length;

			/* UDT name */
			item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_string_length, tvb, *offset_metadata, 2, ENC_BIG_ENDIAN, &string_length);
			proto_item_set_hidden(item);
			*offset_metadata += 2;
			item = proto_tree_add_item(columns_subtree, hf_cql_string_result_rows_udt_name, tvb, *offset_metadata, string_length, ENC_UTF_8 | ENC_NA);
			proto_item_set_hidden(item);
			*offset_metadata += string_length;

			/* UDT size */
			item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_string_result_rows_udt_size, tvb, *offset_metadata, 2, ENC_BIG_ENDIAN, &udt_size);
			proto_item_set_hidden(item);
			*offset_metadata += 2;

			for (i = 0; i < udt_size; i++) {
				/* UDT field name */
				item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_string_length, tvb, *offset_metadata, 2, ENC_BIG_ENDIAN, &string_length);
				proto_item_set_hidden(item);
				*offset_metadata += 2;
				item = proto_tree_add_item(columns_subtree, hf_cql_string_result_rows_udt_field_name, tvb, *offset_metadata, string_length, ENC_UTF_8 | ENC_NA);
				proto_item_set_hidden(item);
				*offset_metadata += string_length;

				/* UDT field option */
				offset = parse_value(columns_subtree, pinfo, tvb, offset_metadata, offset);
			}
			break;
		case CQL_RESULT_ROW_TYPE_TUPLE:
			item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_result_rows_tuple_size, tvb, *offset_metadata, 2, ENC_BIG_ENDIAN, &tuple_size);
			proto_item_set_hidden(item);
			*offset_metadata += 2;
			for (i = 0; i < tuple_size; i++) {
				offset = parse_value(columns_subtree, pinfo, tvb, offset_metadata, offset);
			}
			break;
		default:
			break;
	}
	decrement_dissection_depth(pinfo);

	return offset;
}

static int parse_result_metadata(proto_tree* tree, packet_info *pinfo, tvbuff_t* tvb,
			int offset, int flags, int result_rows_columns_count)
{
	proto_tree* col_spec_subtree = NULL;
	uint32_t string_length = 0;
	int j;

	if ((flags & (CQL_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC | CQL_RESULT_ROWS_FLAG_NO_METADATA)) == CQL_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC) {
		proto_tree_add_item_ret_uint(tree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
		offset += 2;
		proto_tree_add_item(tree, hf_cql_string_result_rows_global_table_spec_ksname, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
		offset += string_length;

		proto_tree_add_item_ret_uint(tree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
		offset += 2;
		proto_tree_add_item(tree, hf_cql_string_result_rows_global_table_spec_table_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
		offset += string_length;
	}

	for (j = 0; j < result_rows_columns_count; ++j) {
		col_spec_subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_cql_result_metadata_colspec, NULL, "Column");
		proto_item_append_text(col_spec_subtree, " # %" PRId32 " specification", j + 1);
		if (!(flags & CQL_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC)) {
			/* ksname and tablename */
			proto_tree_add_item_ret_uint(col_spec_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
			offset += 2;
			proto_tree_add_item(col_spec_subtree, hf_cql_string_result_rows_keyspace_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
			offset += string_length;
			proto_tree_add_item_ret_uint(col_spec_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
			offset += 2;
			proto_tree_add_item(col_spec_subtree, hf_cql_string_result_rows_table_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
			offset += string_length;
		}

		/* column name */
		proto_tree_add_item_ret_uint(col_spec_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
		offset += 2;
		proto_tree_add_item(col_spec_subtree, hf_cql_string_result_rows_column_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
		offset += string_length;

		/* type "option" */
		offset = parse_option(col_spec_subtree, pinfo, tvb, offset);
	}

	return offset;
}


static int parse_result_schema_change(proto_tree* subtree, packet_info *pinfo, tvbuff_t* tvb,
			int offset)
{
	uint32_t short_bytes_length = 0;
	const uint8_t* string_event_type_target = NULL;

	proto_tree_add_item_ret_uint(subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &short_bytes_length);
	offset += 2;
	proto_tree_add_item(subtree, hf_cql_event_schema_change_type, tvb, offset, short_bytes_length, ENC_UTF_8 | ENC_NA);
	offset += short_bytes_length;
	proto_tree_add_item_ret_uint(subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &short_bytes_length);
	offset += 2;
	proto_tree_add_item_ret_string(subtree, hf_cql_event_schema_change_type_target, tvb, offset, short_bytes_length, ENC_UTF_8, pinfo->pool, &string_event_type_target);
	offset += short_bytes_length;
	/* all targets have the keyspace as the first parameter*/
	proto_tree_add_item_ret_uint(subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &short_bytes_length);
	offset += 2;
	proto_tree_add_item(subtree, hf_cql_event_schema_change_keyspace, tvb, offset, short_bytes_length, ENC_UTF_8 | ENC_NA);
	offset += short_bytes_length;
	if ((strcmp(string_event_type_target, "TABLE") == 0) || (strcmp(string_event_type_target, "TYPE") == 0)) {
		proto_tree_add_item_ret_uint(subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &short_bytes_length);
		offset += 2;
		proto_tree_add_item(subtree, hf_cql_event_schema_change_object, tvb, offset, short_bytes_length, ENC_UTF_8 | ENC_NA);
	} else {
		/* TODO: handle "FUNCTION" or "AGGREGATE" targets:
		- [string] the function/aggregate name
		- [string list] one string for each argument type (as CQL type)
		*/
	}

	return offset;
}


static int parse_row(proto_tree* columns_subtree, packet_info *pinfo, tvbuff_t* tvb,
			int offset_metadata, int offset, int result_rows_columns_count)
{
	int32_t result_rows_flags = 0;
	int string_length;
	int shadow_offset;
	proto_item *item;
	int j;

	shadow_offset = offset_metadata;
	for (j = 0; j < result_rows_columns_count; ++j) {
		if (!(result_rows_flags & CQL_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC)) {
			/* ksname and tablename */
			item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_string_length, tvb, shadow_offset, 2, ENC_BIG_ENDIAN, &string_length);
			proto_item_set_hidden(item);
			shadow_offset += 2;
			item = proto_tree_add_item(columns_subtree, hf_cql_string_result_rows_keyspace_name, tvb, shadow_offset, string_length, ENC_UTF_8 | ENC_NA);
			proto_item_set_hidden(item);
			shadow_offset += string_length;
			item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_string_length, tvb, shadow_offset, 2, ENC_BIG_ENDIAN, &string_length);
			proto_item_set_hidden(item);
			shadow_offset += 2;
			item = proto_tree_add_item(columns_subtree, hf_cql_string_result_rows_table_name, tvb, shadow_offset, string_length, ENC_UTF_8 | ENC_NA);
			proto_item_set_hidden(item);
			shadow_offset += string_length;
		}

		/* column name */
		item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_string_length, tvb, shadow_offset, 2, ENC_BIG_ENDIAN, &string_length);
		proto_item_set_hidden(item);
		shadow_offset += 2;
		item = proto_tree_add_item(columns_subtree, hf_cql_string_result_rows_column_name, tvb, shadow_offset, string_length, ENC_UTF_8 | ENC_NA);
		proto_item_set_hidden(item);
		shadow_offset += string_length;

		offset = parse_value(columns_subtree, pinfo, tvb, &shadow_offset, offset);
	}

	return offset;
}

static int
dissect_cql_tcp_pdu(tvbuff_t* raw_tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
	proto_item* ti;
	tvbuff_t* tvb = NULL;
	proto_tree* cql_tree;
	proto_tree* version_tree;
	proto_tree* cql_subtree = NULL;
	proto_tree* cust_payload_tree = NULL;
	proto_tree* rows_subtree = NULL;
	proto_tree* columns_subtree = NULL;
	proto_tree* single_column_subtree = NULL;
	proto_tree* metadata_subtree = NULL;
	proto_tree* prepared_metadata_subtree = NULL;

	int offset = 0;
	int offset_row_metadata = 0;
	uint8_t flags = 0;
	uint8_t first_byte = 0;
	uint8_t cql_version = 0;
	uint8_t server_to_client = 0;
	uint8_t opcode = 0;
	uint32_t message_length = 0;
	uint32_t map_size = 0;
	uint64_t i = 0;
	uint32_t string_length = 0;
	int32_t stream = 0;
	uint32_t batch_size = 0;
	uint32_t batch_query_type = 0;
	uint32_t result_kind = 0;
	int32_t result_rows_flags = 0;
	int32_t result_rows_columns_count = 0;
	int32_t result_prepared_flags = 0;
	int32_t result_prepared_pk_count = 0;
	int64_t j = 0;
	int64_t k = 0;
	uint32_t short_bytes_length = 0;
	int32_t bytes_length = 0;
	int32_t result_rows_row_count = 0;

	conversation_t* conversation;
	cql_conversation_type* cql_conv;
	cql_transaction_type* cql_trans = NULL;
	cql_compression_level compression_level = CQL_COMPRESSION_NONE;

	static int * const cql_batch_flags_bitmaps[] = {
		&hf_cql_batch_flag_serial_consistency,
		&hf_cql_batch_flag_default_timestamp,
		&hf_cql_batch_flag_with_name_for_values,
		NULL
	};

	static int * const cql_header_bitmaps_v3[] = {
		&hf_cql_flag_compression,
		&hf_cql_flag_tracing,
		&hf_cql_flag_reserved3,
		NULL
	};

	static int * const cql_header_bitmaps_v4[] = {
		&hf_cql_flag_compression,
		&hf_cql_flag_tracing,
		&hf_cql_flag_custom_payload,
		&hf_cql_flag_warning,
		&hf_cql_flag_reserved4,
		NULL
	};

	const uint8_t* string_event_type = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CQL");
	col_clear(pinfo->cinfo, COL_INFO);

	first_byte = tvb_get_uint8(raw_tvb, 0);
	cql_version = first_byte & (uint8_t)0x7F;
	server_to_client = first_byte & (uint8_t)0x80;
	opcode = tvb_get_uint8(raw_tvb, 4);

	col_add_fstr(pinfo->cinfo, COL_INFO, "v%d %s Type %s",
		cql_version,
		server_to_client == 0 ? "C->S" : "S->C",
		val_to_str(opcode, cql_opcode_names, "Unknown (0x%02x)")
	);

	conversation = find_or_create_conversation(pinfo);
	cql_conv = (cql_conversation_type*) conversation_get_proto_data(conversation, proto_cql);
	if(!cql_conv) {
		cql_conv = wmem_new(wmem_file_scope(), cql_conversation_type);
		cql_conv->streams = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		conversation_add_proto_data(conversation, proto_cql, cql_conv);
	}

	ti = proto_tree_add_item(tree, proto_cql, raw_tvb, 0, -1, ENC_NA);
	cql_tree = proto_item_add_subtree(ti, ett_cql_protocol);

	ti = proto_tree_add_item(cql_tree, hf_cql_version, raw_tvb, offset, 1, ENC_BIG_ENDIAN);
	version_tree = proto_item_add_subtree(ti, ett_cql_version);
	proto_tree_add_item(version_tree, hf_cql_protocol_version, raw_tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(version_tree, hf_cql_direction, raw_tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	switch(cql_version){
		case 3:
		proto_tree_add_bitmask(cql_tree, raw_tvb, offset, hf_cql_flags_bitmap, ett_cql_header_flags_bitmap, cql_header_bitmaps_v3, ENC_BIG_ENDIAN);
		break;
		case 4:
		proto_tree_add_bitmask(cql_tree, raw_tvb, offset, hf_cql_flags_bitmap, ett_cql_header_flags_bitmap, cql_header_bitmaps_v4, ENC_BIG_ENDIAN);
		break;
		default:
		proto_tree_add_item(cql_tree, hf_cql_flags_bitmap, raw_tvb, offset, 1, ENC_BIG_ENDIAN);
		break;
	}
	flags = tvb_get_uint8(raw_tvb, offset);
	offset += 1;
	proto_tree_add_item_ret_int(cql_tree, hf_cql_stream, raw_tvb, offset, 2, ENC_BIG_ENDIAN, &stream);
	offset += 2;
	proto_tree_add_item(cql_tree, hf_cql_opcode, raw_tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item_ret_uint(cql_tree, hf_cql_length, raw_tvb, offset, 4, ENC_BIG_ENDIAN, &message_length);
	offset += 4;

	/* Track the request/response. */
	if (!pinfo->fd->visited) {
		if (server_to_client == 0) {
			/* This is a request, add it to this stream tracking */
			cql_trans = cql_transaction_add_request(cql_conv, pinfo, stream, 0);
		} else {
			/* This is a response, bind the response with the latest request */
			cql_trans = cql_enrich_transaction_with_response(cql_conv, pinfo, stream);
		}
	} else {
		/* Search for any packet having this packed id as request or response */
		cql_trans = cql_transaction_lookup(cql_conv, pinfo, stream);
	}

	if (!cql_trans) {
		/* Add a fake request to this stream tracking */
		cql_trans = cql_transaction_add_request(cql_conv, pinfo, stream, 1);
	}

	/* Add state tracking to tree */
	if (server_to_client == 0 && cql_trans->rep_frame) {
		/* request */
		ti = proto_tree_add_uint(cql_tree, hf_cql_response_in, raw_tvb, 0, 0, cql_trans->rep_frame);
		proto_item_set_generated(ti);
	}
	if (server_to_client && cql_trans->req_frame) {
		/* reply */
		nstime_t ns;

		ti = proto_tree_add_uint(cql_tree, hf_cql_response_to, raw_tvb, 0, 0, cql_trans->req_frame);
		proto_item_set_generated(ti);
		nstime_delta(&ns, &pinfo->abs_ts, &cql_trans->req_time);
		ti = proto_tree_add_time(cql_tree, hf_cql_response_time, raw_tvb, 0, 0, &ns);
		proto_item_set_generated(ti);
	}

	/* We cannot rely on compression negotiation in the STARTUP message because the
	 * capture can be done at a random time hence missing the negotiation.
	 * So we will first try to decompress LZ4 then snappy
	 */
	if (flags & CQL_HEADER_FLAG_COMPRESSION) {
		compression_level = CQL_DECOMPRESSION_ATTEMPTED;
#ifdef HAVE_LZ4
		if (tvb_captured_length_remaining(raw_tvb, offset) > 4) {
			/* Set ret == 0 to make it fail in case decompression is skipped
			 * due to orig_size being too big
			 */
			uint32_t ret = 0, orig_size = tvb_get_ntohl(raw_tvb, offset);
			unsigned char *decompressed_buffer = NULL;
			offset += 4;

			/* if the decompressed size is reasonably small try to decompress data */
			if (orig_size <= MAX_UNCOMPRESSED_SIZE) {
				decompressed_buffer = (unsigned char*)wmem_alloc(pinfo->pool, orig_size);
				ret = LZ4_decompress_safe(tvb_get_ptr(raw_tvb, offset, -1),
							  decompressed_buffer,
							  tvb_captured_length_remaining(raw_tvb, offset),
							  orig_size);
			}
			/* Decompression attempt failed: rewind offset */
			if (ret != orig_size) {
				wmem_free(pinfo->pool, decompressed_buffer);
				offset -= 4;
			} else {
				/* Now re-setup the tvb buffer to have the new data */
				tvb = tvb_new_child_real_data(raw_tvb, decompressed_buffer, orig_size, orig_size);
				add_new_data_source(pinfo, tvb, "LZ4 Decompressed Data");
				/* mark the decompression as successful */
				compression_level = CQL_COMPRESSION_LZ4;
				message_length= orig_size;
			}
		}
#endif
#ifdef HAVE_SNAPPY
		if (compression_level == CQL_DECOMPRESSION_ATTEMPTED) {
			unsigned char *decompressed_buffer = NULL;
			size_t orig_size = 0;
			snappy_status ret;

			/* get the raw data length */
			ret = snappy_uncompressed_length(tvb_get_ptr(raw_tvb, offset, -1),
							 tvb_captured_length_remaining(raw_tvb, offset),
							 &orig_size);
			/* if we get the length and it's reasonably short to allocate a buffer for it
			 * proceed to try decompressing the data
			 */
			if (ret == SNAPPY_OK && orig_size <= MAX_UNCOMPRESSED_SIZE) {
				decompressed_buffer = (unsigned char*)wmem_alloc(pinfo->pool, orig_size);

				ret = snappy_uncompress(tvb_get_ptr(raw_tvb, offset, -1),
							tvb_captured_length_remaining(raw_tvb, offset),
							decompressed_buffer,
							&orig_size);
			} else {
				/* else mark the input as invalid in order to skip the rest of the
				 * procedure
				 */
				ret = SNAPPY_INVALID_INPUT;
			}
			/* if the decompression succeeded build the new tvb */
			if (ret == SNAPPY_OK) {
				tvb = tvb_new_child_real_data(raw_tvb, decompressed_buffer, (uint32_t)orig_size, (uint32_t)orig_size);
				add_new_data_source(pinfo, tvb, "Snappy Decompressed Data");
				compression_level = CQL_COMPRESSION_SNAPPY;
				message_length = (uint32_t)orig_size;
			} else {
				wmem_free(pinfo->pool, decompressed_buffer);
			}
		}
#endif
	}
	if (compression_level == CQL_COMPRESSION_NONE) {
		/* In case of decompression failure or uncompressed packet */
		tvb = tvb_new_subset_remaining(raw_tvb, offset);
	} else if (compression_level == CQL_DECOMPRESSION_ATTEMPTED) {
		proto_tree_add_item(cql_tree, hf_cql_raw_compressed_bytes, raw_tvb, offset,
					tvb_captured_length_remaining(raw_tvb, offset), ENC_NA);
		return tvb_captured_length(raw_tvb);
	}
	offset = 0;


	/* Dissect the operation. */
	if (server_to_client == 0) {
		switch (opcode) {
			case CQL_OPCODE_STARTUP:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message STARTUP");
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_map_size, tvb, offset, 2, ENC_BIG_ENDIAN, &map_size);
				offset += 2;
				for(i = 0; i < map_size; ++i) {
					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
					offset += 2;
					proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
					offset += string_length;

					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
					offset += 2;
					proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
					offset += string_length;
				}
				break;

			case CQL_OPCODE_AUTH_RESPONSE:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message AUTH_RESPONSE");

				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
				offset += 4;
				if (string_length > 0) {
					proto_tree_add_item(cql_subtree, hf_cql_auth_token, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				}
				break;

			case CQL_OPCODE_OPTIONS:
				/* body should be empty */
				break;

			case CQL_OPCODE_QUERY:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Query");

				/* Query */
				const uint8_t *query_string;
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
				offset += 4;
				proto_tree_add_item_ret_string(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA, pinfo->pool, &query_string);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", query_string);
				offset += string_length;

				/* Query parameters */
				dissect_cql_query_parameters(cql_subtree, tvb, offset, 0);

				break;


			case CQL_OPCODE_PREPARE:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message PREPARE");

				/* TODO: Link for later use by EXECUTE? */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
				offset += 4;
				proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				break;


			case CQL_OPCODE_EXECUTE:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message EXECUTE");

				/* TODO: link to original PREPARE? */

				/* Query ID */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &short_bytes_length);
				offset += 2;
				proto_tree_add_item(cql_subtree, hf_cql_query_id, tvb, offset, short_bytes_length, ENC_NA);
				offset += short_bytes_length;

				/* Query parameters */
				dissect_cql_query_parameters(cql_subtree, tvb, offset, 1);
				break;


			case CQL_OPCODE_BATCH:
				/* TODO NOT DONE */
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message BATCH");

				proto_tree_add_item(cql_subtree, hf_cql_batch_type, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;

				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_batch_query_size, tvb, offset, 2, ENC_BIG_ENDIAN, &batch_size);
				offset += 2;

				for (i = 0; i < batch_size; ++i) {
					uint32_t value_count = 0;

					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_batch_query_type, tvb, offset, 1, ENC_BIG_ENDIAN, &batch_query_type);
					batch_query_type = tvb_get_uint8(tvb, offset);
					offset += 1;
					if (batch_query_type == 0) {
						/* Query */
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
						offset += 4;
						proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						offset += string_length;
					} else if (batch_query_type == 1) {
						uint32_t query_id_bytes_length;

						/* Query ID */
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &query_id_bytes_length);
						offset += 2;
						proto_tree_add_item(cql_subtree, hf_cql_query_id, tvb, offset, query_id_bytes_length, ENC_NA);
						offset += query_id_bytes_length;
					}

					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_value_count, tvb, offset, 2, ENC_BIG_ENDIAN, &value_count);
					offset += 2;
					for (k = 0; k < value_count; ++k) {
						int32_t batch_bytes_length = 0;
						proto_tree_add_item_ret_int(cql_subtree, hf_cql_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &batch_bytes_length);
						offset += 4;
						if (batch_bytes_length > 0) {
							proto_tree_add_item(cql_subtree, hf_cql_bytes, tvb, offset, batch_bytes_length, ENC_NA);
							offset += batch_bytes_length;
						}
						/* TODO - handle both -1 and -2 batch_bytes_length values:
						-1 no byte should follow and the value represented is `null`.
						-2 no byte should follow and the value represented is `not set` not resulting in any change to the existing value.
						< -2 is an invalid value and results in an error. */
					}
				}
				/* consistency */
				proto_tree_add_item(cql_subtree, hf_cql_consistency, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_bitmask(cql_subtree, tvb, offset, hf_cql_batch_flags_bitmap, ett_cql_batch_flags_bitmap, cql_batch_flags_bitmaps, ENC_BIG_ENDIAN);
				break;

			case CQL_OPCODE_REGISTER:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message REGISTER");

				/* string list */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_list_size, tvb, offset, 2, ENC_BIG_ENDIAN, &map_size);
				offset += 2;
				for(i = 0; i < map_size; ++i) {
					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
					offset += 2;
					proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
					offset += string_length;
				}

				break;

			default:
				proto_tree_add_expert(cql_tree, pinfo, &ei_cql_data_not_dissected_yet, tvb, 0, message_length);
				break;
		}
	} else {
		if (flags & CQL_HEADER_FLAG_TRACING) {
			add_cql_uuid(cql_tree, hf_cql_tracing_uuid, tvb, offset);
			offset += 16;
		}
		switch (opcode) {
			case CQL_OPCODE_ERROR:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message ERROR");
				uint32_t error_code;
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_error_code, tvb, offset, 4, ENC_BIG_ENDIAN, &error_code);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s (0x%x)", val_to_str_const(error_code, cql_error_names, "Unknown error code"), error_code);
				offset += 4;

				/* string  */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
				offset += 2;
				proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				break;


			case CQL_OPCODE_AUTHENTICATE:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message AUTHENTICATE");

				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
				offset += 2;
				proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				break;


			case CQL_OPCODE_SUPPORTED:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message SUPPORTED");
				uint32_t multimap_count, value_count;

				/* string multimap */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_value_count, tvb, offset, 2, ENC_BIG_ENDIAN, &multimap_count);
				offset += 2;
				for (k = 0; k < multimap_count; ++k) {
						/* key - string */
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
						offset += 2;
						proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						offset += string_length;

						/* value - string list */
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_list_size, tvb, offset, 2, ENC_BIG_ENDIAN, &value_count);
						offset += 2;
						for(i = 0; i < value_count; ++i) {
								proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
								offset += 2;
								proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
								offset += string_length;
						}
				}
				break;


			case CQL_OPCODE_RESULT:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message RESULT");

				if (flags & CQL_HEADER_FLAG_CUSTOM_PAYLOAD) {
					uint32_t bytesmap_count;
					cust_payload_tree = proto_tree_add_subtree(cql_subtree, tvb, offset, 0, ett_cql_custom_payload, NULL, "Custom Payload");
					proto_tree_add_item_ret_uint(cust_payload_tree, hf_cql_value_count, tvb, offset, 2, ENC_BIG_ENDIAN, &bytesmap_count);
					offset += 2;
					for(k = 0; k < bytesmap_count; ++k) {
						proto_tree_add_item_ret_uint(cust_payload_tree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
						offset += 2;
						proto_tree_add_item(cust_payload_tree, hf_cql_bytesmap_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						offset += string_length;
						if (bytes_length > 0) {
							proto_tree_add_item(cust_payload_tree, hf_cql_bytes, tvb, offset, bytes_length, ENC_NA);
							offset += bytes_length;
						}
					}
					return offset;
				}

				proto_tree_add_item_ret_int(cql_subtree, hf_cql_result_kind, tvb, offset, 4, ENC_BIG_ENDIAN, &result_kind);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(result_kind, cql_result_kind_names, "Unknown kind"));
				offset += 4;

				switch (result_kind) {
					case CQL_RESULT_KIND_VOID:
						/* Nothing */
						break;

					case CQL_RESULT_KIND_ROWS:
						metadata_subtree = proto_tree_add_subtree(cql_subtree, tvb, offset, 0, ett_cql_result_metadata, &ti, "Result Metadata");
						proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_result_rows_flags_values, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_flags);
						proto_tree_add_item(metadata_subtree, hf_cql_result_rows_flag_global_tables_spec, tvb, offset, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(metadata_subtree, hf_cql_result_rows_flag_has_more_pages, tvb, offset, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(metadata_subtree, hf_cql_result_rows_flag_no_metadata, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;

						ti = proto_tree_add_item_ret_int(metadata_subtree, hf_cql_result_rows_column_count, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_columns_count);
						if (result_rows_columns_count < 0) {
							expert_add_info(pinfo, ti, &ei_cql_unexpected_negative_value);
							return tvb_reported_length(tvb);
						}
						offset += 4;

						if (result_rows_flags & CQL_RESULT_ROWS_FLAG_HAS_MORE_PAGES) {
							/* show paging state */
							proto_tree_add_item_ret_int(metadata_subtree, hf_cql_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
							offset += 4;
							if (bytes_length > 0) {
								proto_tree_add_item(metadata_subtree, hf_cql_paging_state, tvb, offset, bytes_length, ENC_NA);
								offset += bytes_length;
							}
						}

						if (result_rows_flags & CQL_RESULT_ROWS_FLAG_NO_METADATA) {
							/* There will be no col_spec elements. */
						} else {
							/* Instead of bloating everything by creating a duplicate structure hierarchy in memory
							 * simply remember the offset of the row metadata for later parsing of the actual rows.
							 **/
							offset_row_metadata = offset;
							offset = parse_result_metadata(metadata_subtree, pinfo, tvb, offset, result_rows_flags, result_rows_columns_count);
						}

						rows_subtree = proto_tree_add_subtree(cql_subtree, tvb, offset, 0, ett_cql_result_rows, &ti, "Rows");
						ti = proto_tree_add_item_ret_int(rows_subtree, hf_cql_result_rows_row_count, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_row_count);
						if (result_rows_row_count < 0) {
							expert_add_info(pinfo, ti, &ei_cql_unexpected_negative_value);
							return tvb_reported_length(tvb);
						}
						col_append_fstr(pinfo->cinfo, COL_INFO, " (%d rows)", result_rows_row_count);
						offset += 4;

						if (result_rows_columns_count) {
							for (j = 0; j < result_rows_row_count; ++j) {
								columns_subtree = proto_tree_add_subtree(rows_subtree, tvb, offset, 0, ett_cql_result_columns, &ti, "Data (columns)");
								proto_item_append_text(columns_subtree, " for row # %" PRId64, j + 1);

								if (offset_row_metadata) {
									offset = parse_row(columns_subtree, pinfo, tvb, offset_row_metadata, offset, result_rows_columns_count);
								} else {
									for (k = 0; k < result_rows_columns_count; ++k) {
										proto_tree_add_item_ret_int(columns_subtree, hf_cql_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
										offset += 4;
										single_column_subtree = proto_tree_add_subtree(columns_subtree, tvb, offset, bytes_length > 0 ? bytes_length : 0, ett_cql_results_no_metadata, &ti, "Column data");
										if (bytes_length > 0) {
											proto_item_append_text(single_column_subtree, " for column # %" PRId64, k + 1);
											proto_tree_add_item(single_column_subtree, hf_cql_bytes, tvb, offset, bytes_length, ENC_NA);
											offset += bytes_length;
										} else if (bytes_length == -1) {
											proto_item_append_text(single_column_subtree, " is NULL for column # %" PRId64, k + 1);
										} else if (bytes_length == -2) {
											proto_item_append_text(single_column_subtree, " is not set for column # %" PRId64, k + 1);
										} else {
											expert_add_info(pinfo, ti, &ei_cql_unexpected_negative_value);
											return tvb_reported_length(tvb);
										}
									}
								}
							}
						}

						break;

					case CQL_RESULT_KIND_SET_KEYSPACE:
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
						offset += 2;
						proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						break;


					case CQL_RESULT_KIND_PREPARED:
						/* <id><metadata><result_metadata> */

						/* Query ID */
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &short_bytes_length);
						offset += 2;
						proto_tree_add_item(cql_subtree, hf_cql_query_id, tvb, offset, short_bytes_length, ENC_NA);
						offset += short_bytes_length;

						/* metadata: <flags><columns_count><pk_count>[<pk_index_1>...<pk_index_n>][<global_table_spec>?<col_spec_1>...<col_spec_n>] */
						prepared_metadata_subtree = proto_tree_add_subtree(cql_subtree, tvb, offset, 0, ett_cql_result_metadata, &ti, "Prepared Metadata");
						proto_tree_add_item_ret_uint(prepared_metadata_subtree, hf_cql_result_prepared_flags_values, tvb, offset, 4, ENC_BIG_ENDIAN, &result_prepared_flags);
						proto_tree_add_item(prepared_metadata_subtree, hf_cql_result_rows_flag_global_tables_spec, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;
						proto_tree_add_item_ret_int(prepared_metadata_subtree, hf_cql_result_rows_column_count, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_columns_count);
						offset += 4;
						proto_tree_add_item_ret_int(prepared_metadata_subtree, hf_cql_result_prepared_pk_count, tvb, offset, 4, ENC_BIG_ENDIAN, &result_prepared_pk_count);
						offset += 4;

						/* TODO: skipping all pk_index elements for now*/

						if (result_prepared_flags & CQL_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC) {
							/* <global_table_spec> - two strings - name of keyspace and name of table */
							proto_tree_add_item_ret_uint(prepared_metadata_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
							offset += 2;
							proto_tree_add_item(prepared_metadata_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
							offset += string_length;
							proto_tree_add_item_ret_uint(prepared_metadata_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
							offset += 2;
							proto_tree_add_item(prepared_metadata_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
							offset += string_length;
						}

						metadata_subtree = proto_tree_add_subtree(cql_subtree, tvb, offset, 0, ett_cql_result_metadata, &ti, "Result Metadata");
						proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_result_rows_flags_values, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_flags);
						proto_tree_add_item(metadata_subtree, hf_cql_result_rows_flag_global_tables_spec, tvb, offset, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(metadata_subtree, hf_cql_result_rows_flag_has_more_pages, tvb, offset, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(metadata_subtree, hf_cql_result_rows_flag_no_metadata, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;

						ti = proto_tree_add_item_ret_int(metadata_subtree, hf_cql_result_rows_column_count, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_columns_count);
						if (result_rows_columns_count < 0) {
							expert_add_info(pinfo, ti, &ei_cql_unexpected_negative_value);
							return tvb_reported_length(tvb);
						}
						offset += 4;

						if (result_rows_flags & CQL_RESULT_ROWS_FLAG_HAS_MORE_PAGES) {
							/* show paging state */
							proto_tree_add_item_ret_int(metadata_subtree, hf_cql_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
							offset += 4;
							if (bytes_length > 0) {
								proto_tree_add_item(metadata_subtree, hf_cql_paging_state, tvb, offset, bytes_length, ENC_NA);
								offset += bytes_length;
							}
						}

						/* <result_metadata> is identical to rows result metadata */
						parse_result_metadata(metadata_subtree, pinfo, tvb, offset, result_rows_flags, result_rows_columns_count);

						break;
					case CQL_RESULT_KIND_SCHEMA_CHANGE:
						/*offset = */parse_result_schema_change(cql_subtree, pinfo, tvb, offset);
						break;

					default:
						proto_tree_add_expert(cql_subtree, pinfo, &ei_cql_data_not_dissected_yet, tvb, 0, message_length);
						break;
				}

				break;


			case CQL_OPCODE_EVENT:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message EVENT");

				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &short_bytes_length);
				offset += 2;

				proto_tree_add_item_ret_string(cql_subtree, hf_cql_event_type, tvb, offset, short_bytes_length, ENC_UTF_8, pinfo->pool, &string_event_type);
				offset += short_bytes_length;
				proto_item_append_text(cql_subtree, " (type: %s)", string_event_type);

				if (strcmp(string_event_type, "SCHEMA_CHANGE") == 0) {
					/*offset = */parse_result_schema_change(cql_subtree, pinfo, tvb, offset);
				} else {
					/* TODO: handle "TOPOLOGY_CHANGE" and "STATUS_CHANGE" event types as well*/
				}
				break;


			case CQL_OPCODE_AUTH_CHALLENGE:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message AUTH_CHALLENGE");

				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
				offset += 4;
				proto_tree_add_item(cql_subtree, hf_cql_auth_token, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				break;


			case CQL_OPCODE_AUTH_SUCCESS:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message AUTH_SUCCESS");

				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
				offset += 4;
				if (string_length > 0) {
					proto_tree_add_item(cql_subtree, hf_cql_auth_token, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				}
				break;

			default:
				proto_tree_add_expert(cql_subtree, pinfo, &ei_cql_data_not_dissected_yet, tvb, 0, message_length);
				break;
		}
	}

	return tvb_reported_length(tvb);
}

static int
dissect_cql_tcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
	uint8_t version;
	/* This dissector version only understands CQL protocol v3 and v4. */
	if (tvb_reported_length(tvb) < 1)
		return 0;

	version = tvb_get_uint8(tvb, 0) & 0x7F;
	if ((version != 3 && version != 4))
		return 0;

	tcp_dissect_pdus(tvb, pinfo, tree, cql_desegment, 9 /* bytes to determine length of PDU */, get_cql_pdu_len, dissect_cql_tcp_pdu, data);
	return tvb_reported_length(tvb);
}

void
proto_reg_handoff_cql(void)
{
	dissector_add_uint_with_preference("tcp.port", CQL_DEFAULT_PORT, find_dissector("cql"));
}


void
proto_register_cql(void)
{
	expert_module_t* expert_cql;
	static hf_register_info hf[] = {
		{
			&hf_cql_batch_flag_serial_consistency,
			{
				"Serial Consistency", "cql.batch.flags.serial_consistency",
				FT_BOOLEAN, 8,
				NULL, CQL_BATCH_FLAG_SERIAL_CONSISTENCY,
				NULL, HFILL
			}
		},
		{
			&hf_cql_batch_flag_default_timestamp,
			{
				"Default Timestamp", "cql.batch.flags.default_timestamp",
				FT_BOOLEAN, 8,
				NULL, CQL_BATCH_FLAG_DEFAULT_TIMESTAMP,
				NULL, HFILL
			}
		},
		{
			&hf_cql_batch_flag_with_name_for_values,
			{
				"With Name For Value", "cql.batch.flags.with_name_for_values",
				FT_BOOLEAN, 8,
				NULL, CQL_BATCH_FLAG_WITH_NAME_FOR_VALUES,
				NULL, HFILL
			}
		},
		{
			&hf_cql_batch_flags_bitmap,
			{
				"Flags", "cql.batch.flags",
				FT_UINT8, BASE_HEX,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_version,
			{
				"Version", "cql.version",
				FT_UINT8, BASE_HEX,
				NULL, 0x0,
				"CQL protocol version (not language version)", HFILL
			}
		},
		{
			&hf_cql_protocol_version,
			{
				"Protocol version", "cql.protocol_version",
				FT_UINT8, BASE_DEC,
				NULL, 0x0F,
				NULL, HFILL
			}
		},
		{
			&hf_cql_direction,
			{
				"Direction", "cql.direction",
				FT_UINT8, BASE_HEX,
				VALS(cql_direction_names), 0xF0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_flags_bitmap,
			{
				"Flags", "cql.flags",
				FT_UINT8, BASE_HEX,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_result_rows_flags_values,
			{
				"Rows Result Flags", "cql.result.rows.flags",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_result_prepared_flags_values,
			{
				"Prepared Result Flags", "cql.result.prepared.flags",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_result_rows_flag_global_tables_spec,
			{
				"Global tables spec.", "cql.result.rows.flags.global_tables",
				FT_BOOLEAN, 32,
				NULL, CQL_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC,
				NULL, HFILL
			}
		},
		{
			&hf_cql_result_rows_flag_has_more_pages,
			{
				"Has More Pages", "cql.result.rows.flags.has_more_pages",
				FT_BOOLEAN, 32,
				NULL, CQL_RESULT_ROWS_FLAG_HAS_MORE_PAGES,
				NULL, HFILL
			}
		},
		{
			&hf_cql_result_rows_flag_no_metadata,
			{
				"No Metadata", "cql.result.rows.flags.no_metadata",
				FT_BOOLEAN, 32,
				NULL, CQL_RESULT_ROWS_FLAG_NO_METADATA,
				NULL, HFILL
			}
		},
		{
			&hf_cql_flag_compression,
			{
				"Compression", "cql.flags.compression",
				FT_BOOLEAN, 8,
				NULL, CQL_HEADER_FLAG_COMPRESSION,
				NULL, HFILL
			}
		},
		{
			&hf_cql_flag_tracing,
			{
				"Tracing", "cql.flags.tracing",
				FT_BOOLEAN, 8,
				NULL, CQL_HEADER_FLAG_TRACING,
				NULL, HFILL
			}
		},
		{
			&hf_cql_flag_custom_payload,
			{
				"Custom Payload", "cql.flags.custom_payload",
				FT_BOOLEAN, 8,
				NULL, CQL_HEADER_FLAG_CUSTOM_PAYLOAD,
				NULL, HFILL
			}
		},
		{
			&hf_cql_flag_warning,
			{
				"Warning", "cql.flags.warning",
				FT_BOOLEAN, 8,
				NULL, CQL_HEADER_FLAG_WARNING,
				NULL, HFILL
			}
		},
		{
			&hf_cql_flag_reserved3,
			{
				"Reserved", "cql.flags.reserved",
				FT_UINT8, BASE_HEX,
				NULL, CQL_HEADER_FLAG_V3_RESERVED,
				NULL, HFILL
			}
		},
		{
			&hf_cql_flag_reserved4,
			{
				"Reserved", "cql.flags.reserved",
				FT_UINT8, BASE_HEX,
				NULL, CQL_HEADER_FLAG_V4_RESERVED,
				NULL, HFILL
			}
		},
		{
			&hf_cql_query_flags_bitmap,
			{
				"Flags", "cql.query.flags",
				FT_UINT8, BASE_HEX,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_query_flags_page_size,
			{
				"Page Size", "cql.query.flags.page_size",
				FT_BOOLEAN, 8,
				NULL, CQL_QUERY_FLAG_PAGE_SIZE,
				NULL, HFILL
			}
		},
		{
			&hf_cql_query_flags_skip_metadata,
			{
				"Skip Metadata", "cql.query.flags.skip_metadata",
				FT_BOOLEAN, 8,
				NULL, CQL_QUERY_FLAG_SKIP_METADATA,
				NULL, HFILL
			}
		},
		{
			&hf_cql_query_flags_values,
			{
				"Values", "cql.query.flags.values",
				FT_BOOLEAN, 8,
				NULL, CQL_QUERY_FLAG_VALUES,
				NULL, HFILL
			}
		},
		{
			&hf_cql_query_flags_default_timestamp,
			{
				"Default Timestamp", "cql.query.flags.default_timestamp",
				FT_BOOLEAN, 8,
				NULL, CQL_QUERY_FLAG_DEFAULT_TIMESTAMP,
				NULL, HFILL
			}
		},
		{
			&hf_cql_query_flags_names_for_values,
			{
				"Names for Values", "cql.query.flags.value_names",
				FT_BOOLEAN, 8,
				NULL, CQL_QUERY_FLAG_VALUE_NAMES,
				NULL, HFILL
			}
		},
		{
			&hf_cql_query_flags_paging_state,
			{
				"Paging State", "cql.query.flags.paging_state",
				FT_BOOLEAN, 8,
				NULL, CQL_QUERY_FLAG_PAGING_STATE,
				NULL, HFILL
			}
		},
		{
			&hf_cql_query_flags_serial_consistency,
			{
				"Serial Consistency", "cql.query.flags.serial_consistency",
				FT_BOOLEAN, 8,
				NULL, CQL_QUERY_FLAG_SERIAL_CONSISTENCY,
				NULL, HFILL
			}
		},
		{
			&hf_cql_query_flags_reserved3,
			{
				"Reserved", "cql.query_flags.reserved",
				FT_UINT8, BASE_HEX,
				NULL, CQL_QUERY_FLAG_V3_RESERVED,
				NULL, HFILL
			}
		},
		{
			&hf_cql_stream,
			{
				"Stream Identifier", "cql.stream",
				FT_INT16, BASE_DEC,
				NULL, 0x0,
				"Stream identifier this packet belongs to", HFILL
			}
		},
		{
			&hf_cql_opcode,
			{
				"Opcode", "cql.opcode",
				FT_UINT8, BASE_DEC,
				VALS(cql_opcode_names), 0x7F, /* Mask the highest-order bit because it indicates message direction, not opcode. */
				"CQL operation this packet describes", HFILL
			}
		},
		{
			&hf_cql_batch_type,
			{
				"Batch type", "cql.batch_type",
				FT_UINT8, BASE_DEC,
				VALS(cql_batch_type_names), 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_batch_query_type,
			{
				"Batch query type", "cql.batch_query_type",
				FT_UINT8, BASE_DEC,
				VALS(cql_batch_query_type_names), 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_cql_length,
			{
				"Message Length", "cql.message_length",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_map_size,
			{
				"String Map Size", "cql.string_map_size",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of strings in the map", HFILL
			}
		},
		{
			&hf_cql_string_list_size,
			{
				"String List Size", "cql.string_list_size",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of strings in the list", HFILL
			}
		},
		{
			&hf_cql_string,
			{
				"String", "cql.string",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				"UTF-8 string value", HFILL
			}
		},
		{
			&hf_cql_auth_token,
			{
				"Auth Token", "cql.auth_token",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				"[bytes] auth token", HFILL
			}
		},
		{
			&hf_cql_string_result_rows_global_table_spec_ksname,
			{
				"Global Spec Keyspace Name", "cql.result.rows.keyspace_name",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_global_table_spec_table_name,
			{
				"Global Spec Table Name", "cql.result.rows.table_name",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_table_name,
			{
				"Table Name", "cql.result.rows.table_name",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_udt_name,
			{
				"User Defined Type Name", "cql.result.rows.udt_name",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_udt_field_name,
			{
				"User Defined Type field Name", "cql.result.rows.udt_field_name",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_udt_size,
			{
				"User Defined Type Size", "cql.result.rows.udt_size",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_list_size,
			{
				"List Size", "cql.result.rows.list_size",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_map_size,
			{
				"No. of key/value pairs in map", "cql.result.rows.map_size",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_set_size,
			{
				"Set Size", "cql.result.rows.set_size",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_keyspace_name,
			{
				"Keyspace Name", "cql.result.rows.keyspace_name",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_bytesmap_string,
			{
				"Key", "cql.bytesmap.key",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_column_name,
			{
				"Column Name", "cql.result.rows.column_name",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_length,
			{
				"String Length", "cql.string_length",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				"Length of the subsequent string value", HFILL
			}
		},
		{
			&hf_cql_consistency,
			{
				"Consistency", "cql.consistency",
				FT_UINT16, BASE_HEX,
				VALS(cql_consistency_names), 0x0,
				"CQL consistency level specification", HFILL
			}
		},
		{
			&hf_cql_value_count,
			{
				"Value count", "cql.value_count",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of subsequent values", HFILL
			}
		},
		{
			&hf_cql_bytes_length,
			{
				"Bytes length", "cql.bytes_length.int",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				"Number of subsequent bytes", HFILL
			}
		},
		{
			&hf_cql_short_bytes_length,
			{
				"Bytes length", "cql.bytes_length.short",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of subsequent bytes", HFILL
			}
		},		{
			&hf_cql_bytes,
			{
				"Bytes", "cql.bytes",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				"Raw byte array", HFILL
			}
		},
		{
			&hf_cql_bigint,
			{
				"Bigint", "cql.bigint",
				FT_INT64, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_scale,
			{
				"Scale", "cql.scale",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_ascii,
			{
				"Ascii", "cql.ascii",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				"An Ascii string", HFILL
			}
		},
		{
			&hf_cql_double,
			{
				"Double float", "cql.double",
				FT_DOUBLE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_float,
			{
				"Float", "cql.float",
				FT_FLOAT, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_int,
			{
				"Int", "cql.int",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_varint_count8,
			{
				"Varint", "cql.varint",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			},
		},
		{
			&hf_cql_varint_count16,
			{
				"Varint", "cql.varint",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			},
		},
		{
			&hf_cql_varint_count32,
			{
				"Varint", "cql.varint",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			},
		},
		{
			&hf_cql_varint_count64,
			{
				"Varint", "cql.varint64",
				FT_UINT64, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			},
		},
		{
			&hf_cql_varchar,
			{
				"Varchar", "cql.varchar",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_timeuuid,
			{
				"Time Uuid", "cql.timeuuid",
				FT_GUID, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_custom,
			{
				"Custom", "cql.custom",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				"A custom field", HFILL
			}
		},
		{
			&hf_cql_null_value,
			{
				"NULL value", "cql.null_value",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				"A NULL value", HFILL
			}
		},
		{
			&hf_cql_raw_compressed_bytes,
			{
				"Raw compressed bytes", "cql.raw_compressed_bytes",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				"Raw byte that failed to be decompressed", HFILL
			}
		},

		{
			&hf_cql_paging_state,
			{
				"Paging State", "cql.paging_state",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				"Paging state byte array", HFILL
			}
		},
		{
			&hf_cql_page_size,
			{
				"Page size", "cql.page_size",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				"Desired page size of result (in CQL3 rows)", HFILL
			}
		},
		{
			&hf_cql_response_in,
			{
				"Response in", "cql.response_in",
				FT_FRAMENUM, BASE_NONE,
				NULL, 0x0,
				"The response to this CQL request is in this frame", HFILL
			}
		},
		{
			&hf_cql_response_to,
			{
				"Request in", "cql.response_to",
				FT_FRAMENUM, BASE_NONE,
				NULL, 0x0,
				"This is a response to the CQL request in this fame", HFILL
			}
		},
		{
			&hf_cql_response_time,
			{
				"Response time", "cql.response_time",
				FT_RELATIVE_TIME, BASE_NONE,
				NULL, 0x0,
				"The time between the request and the response", HFILL
			}
		},
		{
			&hf_cql_timestamp,
			{
				"Timestamp", "cql.timestamp",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_query_id,
			{
				"Query ID", "cql.query_id",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				"CQL query id resulting from a PREPARE statement", HFILL
			}
		},
		{
			&hf_cql_event_type,
			{
				"Event Type", "cql.event_type",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				"CQL Event Type", HFILL
			}
		},
		{
			&hf_cql_event_schema_change_type,
			{
				"Schema change type", "cql.schema_change_type",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				"CQL Schema Change Type", HFILL
			}
		},
		{
			&hf_cql_event_schema_change_type_target,
			{
				"Schema change target", "cql.schema_change_target",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				"CQL Schema Change target object", HFILL
			}
		},
		{
			&hf_cql_event_schema_change_object,
			{
				"Schema change event object name", "cql.schema_change_object_name",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				"CQL Schema Change object name", HFILL
			}
		},
		{
			&hf_cql_event_schema_change_keyspace,
			{
				"Schema change event keyspace name", "cql.schema_change_keyspace",
				FT_STRING, BASE_NONE,
				NULL, 0x0,
				"CQL Schema Change keyspace name", HFILL
			}
		},
		{
			&hf_cql_batch_query_size,
			{
				"Batch Query Size", "cql.batch_query_size",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of statements in CQL batch", HFILL
			}
		},
		{
			&hf_cql_error_code,
			{
				"Error Code", "cql.error_code",
				FT_UINT32, BASE_HEX,
				VALS(cql_error_names), 0x0,
				"Error code from CQL server", HFILL
			}
		},
		{
			&hf_cql_result_kind,
			{
				"Result Kind", "cql.result.kind",
				FT_INT32, BASE_DEC,
				VALS(cql_result_kind_names), 0x0,
				"Kind of result from CQL server", HFILL
			}
		},
		{
			&hf_cql_result_rows_column_count,
			{
				"Column Count", "cql.result.rows.column_count",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				"Count of columns in a rows result from CQL server", HFILL
			}
		},
		{
			&hf_cql_result_prepared_pk_count,
			{
				"PK Count", "cql.result.prepared.pk_count",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				"Count of Partition Key columns in a Prepared result from CQL server", HFILL
			}
		},
		{
			&hf_cql_result_rows_tuple_size,
			{
				"Tuple Size", "cql.result.rows.tuple_size",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Size of a tuple rows result from CQL server", HFILL
			}
		},
		{
			&hf_cql_result_timestamp,
			{
				"Timestamp (Epoch Time)", "cql.result.timestamp",
				FT_INT64, BASE_DEC,
				NULL, 0x0,
				"Timestamp result", HFILL
			}
		},
		{
			&hf_cql_result_rows_data_type,
			{
				"CQL Data Type", "cql.data_type",
				FT_UINT16, BASE_DEC,
				VALS(cql_result_row_type_names), 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_result_rows_row_count,
			{
				"CQL Result Rows Count", "cql.result.rows.row_count",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				"Number of rows returned in CQL result", HFILL
			}
		},
		{
			&hf_cql_uuid,
			{
				"UUID", "cql.uuid",
				FT_GUID, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_tracing_uuid,
			{
				"Tracing UUID", "cql.tracing_uuid",
				FT_GUID, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_port,
			{
				"Port", "cql.port",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_boolean,
			{
				"Boolean", "cql.boolean",
				FT_BOOLEAN, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_ipv4,
			{
				"IPV4", "cql.ipv4",
				FT_IPv4, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_ipv6,
			{
				"IPV6", "cql.ipv6",
				FT_IPv6, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
	};

	static ei_register_info ei[] = {
		{ &ei_cql_data_not_dissected_yet,
		  { "cql.ie_data_not_dissected_yet",
			 PI_UNDECODED, PI_WARN, "IE data not dissected yet", EXPFILL }},
		{ &ei_cql_unexpected_negative_value,
		  { "cql.unexpected_negative_value",
			 PI_UNDECODED, PI_ERROR, "Unexpected negative value", EXPFILL }},
	};

	static int* ett[] = {
		&ett_cql_protocol,
		&ett_cql_version,
		&ett_cql_message,
		&ett_cql_result_columns,
		&ett_cql_results_no_metadata,
		&ett_cql_result_map,
		&ett_cql_result_set,
		&ett_cql_result_metadata,
		&ett_cql_result_metadata_colspec,
		&ett_cql_result_rows,
		&ett_cql_header_flags_bitmap,
		&ett_cql_query_flags_bitmap,
		&ett_cql_batch_flags_bitmap,
	};

	proto_cql = proto_register_protocol("Cassandra CQL Protocol", "CQL", "cql" );
	register_dissector("cql", dissect_cql_tcp, proto_cql);

	proto_register_field_array(proto_cql, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_cql = expert_register_protocol(proto_cql);
	expert_register_field_array(expert_cql, ei, array_length(ei));
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
