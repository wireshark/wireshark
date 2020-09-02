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
#include <epan/dissectors/packet-tcp.h>
#include <epan/wmem/wmem.h>
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

static int proto_cql = -1;
/* CQL header frame fields */
static int hf_cql_version = -1;
static int hf_cql_protocol_version = -1;
static int hf_cql_direction = -1;
/* CQL header frame fields */
static int hf_cql_flags_bitmap = -1;
static int hf_cql_flag_compression = -1;
static int hf_cql_flag_tracing = -1;
static int hf_cql_flag_reserved3 = -1;
static int hf_cql_flag_custom_payload = -1;
static int hf_cql_flag_warning = -1;
static int hf_cql_flag_reserved4 = -1;
static int hf_cql_stream = -1;
static int hf_cql_opcode = -1;
static int hf_cql_length = -1;
/* CQL data types */
/*
static int hf_cql_int = -1;
static int hf_cql_long = -1;
static int hf_cql_uuid = -1;
static int hf_cql_bytes = -1;
static int hf_cql_inet = -1;
*/
/* Batch flags */

static int hf_cql_batch_flag_serial_consistency = -1;
static int hf_cql_batch_flag_default_timestamp = -1;
static int hf_cql_batch_flag_with_name_for_values = -1;
static int hf_cql_batch_flags_bitmap = -1;
static int ett_cql_batch_flags_bitmap = -1;

static int hf_cql_consistency = -1;
static int hf_cql_string_length = -1;
static int hf_cql_string_map_size = -1;
static int hf_cql_string = -1;
static int hf_cql_value_count = -1;
static int hf_cql_short_bytes_length = -1;
static int hf_cql_bytes_length = -1;
static int hf_cql_bytes = -1;
static int hf_cql_bigint = -1;
static int hf_cql_scale = -1;
static int hf_cql_boolean = -1;
static int hf_cql_ascii = - 1;
static int hf_cql_double = -1;
static int hf_cql_float = -1;
static int hf_cql_custom = -1;
static int hf_cql_int = -1;
static int hf_cql_uuid = -1;
static int hf_cql_port = -1;
static int hf_cql_timeuuid = -1;
static int hf_cql_varchar = -1;
static int hf_cql_varint_count8 = -1;
static int hf_cql_varint_count16 = -1;
static int hf_cql_varint_count32 = -1;
static int hf_cql_varint_count64 = -1;
static int hf_cql_raw_compressed_bytes = -1;
static int hf_cql_paging_state = -1;
static int hf_cql_page_size = -1;
static int hf_cql_timestamp = -1;
static int hf_cql_query_id = -1;
static int hf_cql_result_timestamp = -1;
static int hf_cql_string_list_size = -1;
static int hf_cql_batch_type = -1;
static int hf_cql_batch_query_type = -1;
static int hf_cql_batch_query_size = -1;
static int hf_cql_error_code = -1;
static int hf_cql_result_kind = -1;
static int hf_cql_result_rows_data_type = -1;

static int hf_cql_query_flags_bitmap = -1;
static int hf_cql_query_flags_values = -1;
static int hf_cql_query_flags_skip_metadata = -1;
static int hf_cql_query_flags_page_size = -1;
static int hf_cql_query_flags_paging_state = -1;
static int hf_cql_query_flags_serial_consistency = -1;
static int hf_cql_query_flags_default_timestamp = -1;
static int hf_cql_query_flags_names_for_values = -1;
static int hf_cql_query_flags_reserved3 = -1;

static int hf_cql_result_rows_flags_values = -1;
static int hf_cql_result_rows_flag_global_tables_spec = -1;
static int hf_cql_result_rows_flag_has_more_pages = -1;
static int hf_cql_result_rows_flag_no_metadata = -1;
static int hf_cql_result_rows_column_count = -1;
static int hf_cql_result_rows_tuple_size = -1;

static int hf_cql_string_result_rows_global_table_spec_ksname = -1;
static int hf_cql_string_result_rows_global_table_spec_table_name = -1;
static int hf_cql_string_result_rows_table_name = -1;
static int hf_cql_string_result_rows_keyspace_name = -1;
static int hf_cql_string_result_rows_column_name = -1;
static int hf_cql_result_rows_row_count = -1;
static int hf_cql_string_result_rows_udt_name = -1;
static int hf_cql_string_result_rows_udt_size = -1;
static int hf_cql_string_result_rows_udt_field_name = -1;
static int hf_cql_string_result_rows_list_size = -1;
static int hf_cql_string_result_rows_map_size = -1;
static int hf_cql_string_result_rows_set_size = -1;

static int ett_cql_protocol = -1;
static int ett_cql_version = -1;
static int ett_cql_message = -1;
static int ett_cql_result_columns = -1;
static int ett_cql_result_metadata = -1;
static int ett_cql_result_rows = -1;
static int ett_cql_header_flags_bitmap = -1;
static int ett_cql_query_flags_bitmap = -1;

static int hf_cql_response_in = -1;
static int hf_cql_response_to = -1;
static int hf_cql_response_time = -1;

static int hf_cql_ipv4 = -1;
static int hf_cql_ipv6 = -1;

/* desegmentation of CQL */
static gboolean cql_desegment = TRUE;

static expert_field ei_cql_data_not_dissected_yet = EI_INIT;
static expert_field ei_cql_unexpected_negative_value = EI_INIT;


typedef struct _cql_transaction_type {
	guint32 req_frame;
	guint32 rep_frame;
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
	CQL_BATCH_FLAG_SERIAL_CONSISTENCY = 0x10,
	CQL_BATCH_FLAG_DEFAULT_TIMESTAMP = 0x020,
	CQL_BATCH_FLAG_WITH_NAME_FOR_VALUES = 0x040
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
	{ CQL_RESULT_ROW_TYPE_TUPLE, "TUBPLE" },
	{ 0x0, NULL }
};

static gint
dissect_cql_query_parameters(proto_tree* cql_subtree, tvbuff_t* tvb, gint offset, int execute)
{
	gint32 bytes_length = 0;
	guint32 flags = 0;
	guint64 i = 0;
	guint32 string_length = 0;
	guint32 value_count = 0;

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
	flags = tvb_get_guint8(tvb, offset);
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
		proto_tree_add_item(cql_subtree, hf_cql_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	}

	return offset;
}

static guint
get_cql_pdu_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset, void* data _U_)
{
	/* CQL has 32-bit length at 5th byte in frame. */
	guint32 length = tvb_get_ntohl(tvb, offset + 5);

	/* Include length of frame header. */
	return length + 9;
}

static cql_transaction_type*
cql_transaction_add_request(cql_conversation_type* conv,
				packet_info* pinfo,
				gint32 stream,
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
					gint32 stream)
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
			gint32 stream)
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


static int parse_option(proto_tree* metadata_subtree, tvbuff_t* tvb, gint offset)
{
	guint32 data_type = 0;
	guint32 string_length = 0;
	guint32 tuple_size = 0;
	guint32 udt_size = 0;
	guint32 i = 0;

	proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_result_rows_data_type, tvb, offset, 2, ENC_BIG_ENDIAN, &data_type);
	offset += 2;
	switch (data_type) {
		case CQL_RESULT_ROW_TYPE_LIST:
			offset = parse_option(metadata_subtree, tvb, offset);
			break;
		case CQL_RESULT_ROW_TYPE_MAP:
			offset = parse_option(metadata_subtree, tvb, offset);
			offset = parse_option(metadata_subtree, tvb, offset);
			break;
		case CQL_RESULT_ROW_TYPE_SET:
			offset = parse_option(metadata_subtree, tvb, offset);
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
				offset = parse_option(metadata_subtree, tvb, offset);
			}
			break;
		case CQL_RESULT_ROW_TYPE_TUPLE:
			proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_result_rows_tuple_size, tvb, offset, 2, ENC_BIG_ENDIAN, &tuple_size);
			offset += 2;
			for (i = 0; i < tuple_size; i++) {
				offset = parse_option(metadata_subtree, tvb, offset);
			}
			break;
		default:
			break;
	}

	return offset;
}

static void add_varint_item(proto_tree *tree, tvbuff_t *tvb, const gint offset, gint length)
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

static void add_cql_uuid(proto_tree* tree, int hf_uuid, tvbuff_t* tvb, gint offset)
{
	e_guid_t guid;
	int i;

	guid.data1 = tvb_get_letohl(tvb, offset+12);
	guid.data2 = tvb_get_letohl(tvb, offset+10);
	guid.data3 = tvb_get_letohl(tvb, offset+8);

	for (i = 0; i < 8; i++)
	{
		guid.data4[i] = tvb_get_guint8(tvb, offset+(7-i));
	}

	proto_tree_add_guid(tree, hf_uuid, tvb, offset, 16, &guid);
}


static int parse_value(proto_tree* columns_subtree, packet_info *pinfo, tvbuff_t* tvb, gint* offset_metadata, gint offset)
{
	guint32 data_type = 0;
	guint32 string_length = 0;
	gint32 bytes_length = 0;
	guint32 tuple_size = 0;
	gint32 list_size = 0;
	gint32 map_size = 0;
	gint32 set_size = 0;
	guint32 udt_size = 0;
	proto_item *item;
	proto_item *sub_item;
	guint32 i = 0;
	gint32 j = 0;
	gint offset_metadata_backup = 0;
	guint32 addr4;
	ws_in6_addr addr6;
	guint32 port_number;

	proto_tree_add_item_ret_int(columns_subtree, hf_cql_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
	offset += 4;

	item = proto_tree_add_item_ret_uint(columns_subtree, hf_cql_result_rows_data_type, tvb, *offset_metadata, 2, ENC_BIG_ENDIAN, &data_type);
	proto_item_set_hidden(item);
	*offset_metadata += 2;

	if (bytes_length == -1) {
		return offset;
	}

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
			proto_tree_add_boolean(columns_subtree, hf_cql_boolean, tvb, offset, 1, TRUE);
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
			proto_tree_add_item(columns_subtree, hf_cql_varchar, tvb, offset, bytes_length, ENC_ASCII|ENC_NA);
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
			item = proto_tree_add_item_ret_int(columns_subtree, hf_cql_string_result_rows_map_size, tvb, offset, 4, ENC_BIG_ENDIAN, &map_size);
			if (map_size < 0) {
				expert_add_info(pinfo, item, &ei_cql_unexpected_negative_value);
				return tvb_reported_length(tvb);
			}
			offset += 4;
			offset_metadata_backup = *offset_metadata;
			for (j = 0; j < map_size; j++) {
				*offset_metadata = offset_metadata_backup;
				offset = parse_value(columns_subtree, pinfo, tvb, offset_metadata, offset);
				offset = parse_value(columns_subtree, pinfo, tvb, offset_metadata, offset);
			}
			break;
		case CQL_RESULT_ROW_TYPE_SET:
			item = proto_tree_add_item_ret_int(columns_subtree, hf_cql_string_result_rows_set_size, tvb, offset, 4, ENC_BIG_ENDIAN, &set_size);
			if (set_size < 0) {
				expert_add_info(pinfo, item, &ei_cql_unexpected_negative_value);
				return tvb_reported_length(tvb);
			}
			offset += 4;
			offset_metadata_backup = *offset_metadata;
			for (j = 0; j < set_size; j++) {
				*offset_metadata = offset_metadata_backup;
				offset = parse_value(columns_subtree, pinfo, tvb, offset_metadata, offset);
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

	return offset;
}

static int parse_row(proto_tree* columns_subtree, packet_info *pinfo, tvbuff_t* tvb,
			gint offset_metadata, gint offset, gint result_rows_columns_count)
{
	gint32 result_rows_flags = 0;
	gint string_length;
	gint shadow_offset;
	proto_item *item;
	gint j;

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
	proto_tree* rows_subtree = NULL;
	proto_tree* columns_subtree = NULL;
	proto_tree* metadata_subtree = NULL;

	gint offset = 0;
	gint offset_row_metadata = 0;
	guint8 flags = 0;
	guint8 first_byte = 0;
	guint8 cql_version = 0;
	guint8 server_to_client = 0;
	guint8 opcode = 0;
	guint32 message_length = 0;
	guint32 map_size = 0;
	guint64 i = 0;
	guint32 string_length = 0;
	gint32 stream = 0;
	guint32 batch_size = 0;
	guint32 batch_query_type = 0;
	guint32 result_kind = 0;
	gint32 result_rows_flags = 0;
	gint32 result_rows_columns_count = 0;
	gint64 j = 0;
	gint64 k = 0;
	gint32 bytes_length = 0;
	gint32 result_rows_row_count = 0;

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

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CQL");
	col_clear(pinfo->cinfo, COL_INFO);

	first_byte = tvb_get_guint8(raw_tvb, 0);
	cql_version = first_byte & (guint8)0x7F;
	server_to_client = first_byte & (guint8)0x80;
	opcode = tvb_get_guint8(raw_tvb, 4);

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
	flags = tvb_get_guint8(raw_tvb, offset);
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

	/* We cannot rely on compression negociation in the STARTUP message because the
	 * capture can be done at a random time hence missing the negociation.
	 * So we will first try to decompress LZ4 then snappy
	 */
	if (flags & CQL_HEADER_FLAG_COMPRESSION) {
		compression_level = CQL_DECOMPRESSION_ATTEMPTED;
#ifdef HAVE_LZ4
		if (tvb_captured_length_remaining(raw_tvb, offset) > 4) {
			/* Set ret == 0 to make it fail in case decompression is skipped
			 * due to orig_size being too big
			 */
			guint32 ret = 0, orig_size = tvb_get_ntohl(raw_tvb, offset);
			guchar *decompressed_buffer = NULL;
			offset += 4;

			/* if the decompressed size is reasonably small try to decompress data */
			if (orig_size <= MAX_UNCOMPRESSED_SIZE) {
				decompressed_buffer = (guchar*)wmem_alloc(pinfo->pool, orig_size);
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
				add_new_data_source(pinfo, tvb, "Decompressed Data");
				/* mark the decompression as successful */
				compression_level = CQL_COMPRESSION_LZ4;
				message_length= orig_size;
			}
		}
#endif
#ifdef HAVE_SNAPPY
		if (compression_level == CQL_DECOMPRESSION_ATTEMPTED) {
			guchar *decompressed_buffer = NULL;
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
				decompressed_buffer = (guchar*)wmem_alloc(pinfo->pool, orig_size);

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
				tvb = tvb_new_child_real_data(raw_tvb, decompressed_buffer, (guint32)orig_size, (guint32)orig_size);
				add_new_data_source(pinfo, tvb, "Decompressed Data");
				compression_level = CQL_COMPRESSION_SNAPPY;
				message_length = (guint32)orig_size;
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
				/* not implemented */
				break;

			case CQL_OPCODE_OPTIONS:
				/* body should be empty */
				break;

			case CQL_OPCODE_QUERY:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Query");

				/* Query */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
				offset += 4;
				proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
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
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &bytes_length);
				offset += 2;
				proto_tree_add_item(cql_subtree, hf_cql_query_id, tvb, offset, bytes_length, ENC_NA);
				offset += bytes_length;

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
					guint32 value_count = 0;

					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_batch_query_type, tvb, offset, 1, ENC_BIG_ENDIAN, &batch_query_type);
					batch_query_type = tvb_get_guint8(tvb, offset);
					offset += 1;
					if (batch_query_type == 0) {
						/* Query */
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
						offset += 4;
						proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						offset += string_length;
					} else if (batch_query_type == 1) {
						guint32 query_id_bytes_length;

						/* Query ID */
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &query_id_bytes_length);
						offset += 2;
						proto_tree_add_item(cql_subtree, hf_cql_query_id, tvb, offset, query_id_bytes_length, ENC_NA);
						offset += query_id_bytes_length;
					}

					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_value_count, tvb, offset, 2, ENC_BIG_ENDIAN, &value_count);
					offset += 2;
					for (k = 0; k < value_count; ++k) {
						guint32 batch_bytes_length = 0;
						proto_tree_add_item_ret_int(cql_subtree, hf_cql_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &batch_bytes_length);
						offset += 4;
						proto_tree_add_item(cql_subtree, hf_cql_bytes, tvb, offset, batch_bytes_length, ENC_NA);
						offset += batch_bytes_length;
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
		switch (opcode) {
			case CQL_OPCODE_ERROR:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message ERROR");

				proto_tree_add_item(cql_subtree, hf_cql_error_code, tvb, offset, 4, ENC_BIG_ENDIAN);

				/* string  */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
				offset += 2;
				proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				break;


			case CQL_OPCODE_AUTHENTICATE:
				/* Not implemented. */
				break;


			case CQL_OPCODE_SUPPORTED:
				/* Not implemented. */
				break;


			case CQL_OPCODE_RESULT:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_message, &ti, "Message RESULT");

				proto_tree_add_item_ret_int(cql_subtree, hf_cql_result_kind, tvb, offset, 4, ENC_BIG_ENDIAN, &result_kind);
				offset += 4;

				switch (result_kind) {
					case CQL_RESULT_KIND_VOID:
						/* Nothing */
						break;

					case CQL_RESULT_KIND_ROWS:
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_result_rows_flags_values, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_flags);
						proto_tree_add_item(cql_subtree, hf_cql_result_rows_flag_global_tables_spec, tvb, offset, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(cql_subtree, hf_cql_result_rows_flag_has_more_pages, tvb, offset, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(cql_subtree, hf_cql_result_rows_flag_no_metadata, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;

						metadata_subtree = proto_tree_add_subtree(cql_subtree, tvb, offset, 0, ett_cql_result_metadata, &ti, "Metadata");

						ti = proto_tree_add_item_ret_int(metadata_subtree, hf_cql_result_rows_column_count, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_columns_count);
						if (result_rows_columns_count < 0) {
							expert_add_info(pinfo, ti, &ei_cql_unexpected_negative_value);
							return tvb_reported_length(tvb);
						}
						offset += 4;

						if (result_rows_flags & CQL_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC) {
							proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
							offset += 2;
							proto_tree_add_item(metadata_subtree, hf_cql_string_result_rows_global_table_spec_ksname, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
							offset += string_length;

							proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
							offset += 2;
							proto_tree_add_item(metadata_subtree, hf_cql_string_result_rows_global_table_spec_table_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
							offset += string_length;
						}

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

							for (j = 0; j < result_rows_columns_count; ++j) {
								if (!(result_rows_flags & CQL_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC)) {
									/* ksname and tablename */
									proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
									offset += 2;
									proto_tree_add_item(metadata_subtree, hf_cql_string_result_rows_keyspace_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
									offset += string_length;
									proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
									offset += 2;
									proto_tree_add_item(metadata_subtree, hf_cql_string_result_rows_table_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
									offset += string_length;
								}

								/* column name */
								proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
								offset += 2;
								proto_tree_add_item(metadata_subtree, hf_cql_string_result_rows_column_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
								offset += string_length;


								/* type "option" */
								offset = parse_option(metadata_subtree, tvb, offset);
							}
						}

						rows_subtree = proto_tree_add_subtree(cql_subtree, tvb, offset, 0, ett_cql_result_rows, &ti, "Rows");
						ti = proto_tree_add_item_ret_int(rows_subtree, hf_cql_result_rows_row_count, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_row_count);
						if (result_rows_row_count < 0) {
							expert_add_info(pinfo, ti, &ei_cql_unexpected_negative_value);
							return tvb_reported_length(tvb);
						}
						offset += 4;

						if (result_rows_columns_count) {
							for (j = 0; j < result_rows_row_count; ++j) {
								columns_subtree = proto_tree_add_subtree(rows_subtree, tvb, offset, 0, ett_cql_result_columns, &ti, "Data (Columns)");

								if (offset_row_metadata) {
									offset = parse_row(columns_subtree, pinfo, tvb, offset_row_metadata, offset, result_rows_columns_count);
								} else {
									for (k = 0; k < result_rows_columns_count; ++k) {
										proto_tree_add_item_ret_int(columns_subtree, hf_cql_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
										offset += 4;
										proto_tree_add_item(columns_subtree, hf_cql_bytes, tvb, offset, bytes_length, ENC_NA);
										offset += bytes_length;
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
						/* Query ID */
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &bytes_length);
						offset += 2;
						proto_tree_add_item(cql_subtree, hf_cql_query_id, tvb, offset, bytes_length, ENC_NA);
						break;


					case CQL_RESULT_KIND_SCHEMA_CHANGE:
						proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						offset += string_length;
						proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						offset += string_length;
						proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						break;

					default:
						proto_tree_add_expert(cql_subtree, pinfo, &ei_cql_data_not_dissected_yet, tvb, 0, message_length);
						break;
				}

				break;


			case CQL_OPCODE_EVENT:
				proto_tree_add_item(cql_subtree, hf_cql_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				break;


			case CQL_OPCODE_AUTH_CHALLENGE:
				break;


			case CQL_OPCODE_AUTH_SUCCESS:
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
	guint8 version;
	/* This dissector version only understands CQL protocol v3 and v4. */
	if (tvb_reported_length(tvb) < 1)
		return 0;

	version = tvb_get_guint8(tvb, 0) & 0x7F;
	if ((version != 3 && version != 4))
		return 0;

	tcp_dissect_pdus(tvb, pinfo, tree, cql_desegment, 9 /* bytes to determine length of PDU */, get_cql_pdu_len, dissect_cql_tcp_pdu, data);
	return tvb_reported_length(tvb);
}

void
proto_reg_handoff_cql(void)
{
	static dissector_handle_t cql_handle;

	cql_handle = create_dissector_handle(dissect_cql_tcp, proto_cql);
	dissector_add_uint_with_preference("tcp.port", CQL_DEFAULT_PORT, cql_handle);
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
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				"UTF-8 string value", HFILL
			}
		},
		{
			&hf_cql_string_result_rows_global_table_spec_ksname,
			{
				"Global Spec Keyspace Name", "cql.result.rows.keyspace_name",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_global_table_spec_table_name,
			{
				"Global Spec Table Name", "cql.result.rows.table_name",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_table_name,
			{
				"Table Name", "cql.result.rows.table_name",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_udt_name,
			{
				"User Defined Type Name", "cql.result.rows.udt_name",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_udt_field_name,
			{
				"User Defined Type field Name", "cql.result.rows.udt_field_name",
				FT_STRING, STR_UNICODE,
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
				"Map Size", "cql.result.rows.map_size",
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
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_string_result_rows_column_name,
			{
				"Column Name", "cql.result.rows.column_name",
				FT_STRING, STR_UNICODE,
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
				FT_STRING, STR_ASCII,
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
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_timeuuid,
			{
				"Time Uuid", "cql.timeuuid",
				FT_GUID, STR_ASCII,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_custom,
			{
				"Custom", "cql.custom",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				"A custom field", HFILL
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
				FT_INT32, BASE_DEC,
				NULL, 0x0,
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

	static gint* ett[] = {
		&ett_cql_protocol,
		&ett_cql_version,
		&ett_cql_message,
		&ett_cql_result_columns,
		&ett_cql_result_metadata,
		&ett_cql_result_rows,
		&ett_cql_header_flags_bitmap,
		&ett_cql_query_flags_bitmap,
		&ett_cql_batch_flags_bitmap,
	};

	proto_cql = proto_register_protocol("Cassandra CQL Protocol", "CQL", "cql" );

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
