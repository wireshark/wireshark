/* packet-cql.c
 * Routines for Apache Cassandra CQL dissection
 * Copyright 2015, Aaron Ten Clay <aarontc@aarontc.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * CQL V3 reference: https://github.com/apache/cassandra/blob/cassandra-2.1.11/doc/native_protocol_v3.spec
 */
#include "config.h"
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>


#define CQL_DEFAULT_PORT 9042


void proto_reg_handoff_cql(void);
void proto_register_cql(void);

static int proto_cql = -1;
/* CQL header frame fields */
static int hf_cql_version = -1;
/* CQL v3 header frame fields */
static int hf_cql_v3_flags_bitmap = -1;
static int hf_cql_v3_flag_compression = -1;
static int hf_cql_v3_flag_tracing = -1;
static int hf_cql_v3_stream = -1;
static int hf_cql_v3_opcode = -1;
static int hf_cql_v3_length = -1;
/* CQL v3 data types */
/*
static int hf_cql_v3_int = -1;
static int hf_cql_v3_long = -1;
static int hf_cql_v3_uuid = -1;
static int hf_cql_v3_bytes = -1;
static int hf_cql_v3_inet = -1;
*/
static int hf_cql_v3_consistency = -1;
static int hf_cql_v3_string_length = -1;
static int hf_cql_v3_string_map_size = -1;
static int hf_cql_v3_string = -1;
static int hf_cql_v3_value_count = -1;
static int hf_cql_v3_short_bytes_length = -1;
static int hf_cql_v3_bytes_length = -1;
static int hf_cql_v3_bytes = -1;
static int hf_cql_v3_paging_state = -1;
static int hf_cql_v3_page_size = -1;
static int hf_cql_v3_timestamp = -1;
static int hf_cql_v3_query_id = -1;
static int hf_cql_v3_string_list_size = -1;
static int hf_cql_v3_batch_type = -1;
static int hf_cql_v3_batch_query_type = -1;
static int hf_cql_v3_batch_query_size = -1;
static int hf_cql_v3_error_code = -1;
static int hf_cql_v3_result_kind = -1;
static int hf_cql_v3_result_rows_data_type = -1;

static int hf_cql_v3_query_flags_values = -1;
static int hf_cql_v3_query_flags_skip_metadata = -1;
static int hf_cql_v3_query_flags_page_size = -1;
static int hf_cql_v3_query_flags_paging_state = -1;
static int hf_cql_v3_query_flags_serial_consistency = -1;
static int hf_cql_v3_query_flags_default_timestamp = -1;
static int hf_cql_v3_query_flags_names_for_values = -1;


static int hf_cql_v3_result_rows_flags_values = -1;
static int hf_cql_v3_result_rows_flag_global_tables_spec = -1;
static int hf_cql_v3_result_rows_flag_has_more_pages = -1;
static int hf_cql_v3_result_rows_flag_no_metadata = -1;
static int hf_cql_v3_result_rows_column_count = -1;

static int hf_cql_v3_string_result_rows_global_table_spec_ksname = -1;
static int hf_cql_v3_string_result_rows_global_table_spec_table_name = -1;
static int hf_cql_v3_string_result_rows_table_name = -1;
static int hf_cql_v3_string_result_rows_keyspace_name = -1;
static int hf_cql_v3_string_result_rows_column_name = -1;
static int hf_cql_v3_result_rows_row_count = -1;

static int ett_cql_protocol = -1;
static int ett_cql_v3_message = -1;
static int ett_cql_v3_result_columns = -1;
static int ett_cql_v3_result_metadata = -1;
static int ett_cql_v3_result_rows = -1;


static int hf_cql_v3_response_in = -1;
static int hf_cql_v3_response_to = -1;
static int hf_cql_v3_response_time = -1;

/* desegmentation of CQL v3 */
static gboolean cql_v3_desegment = TRUE;

static expert_field ei_cql_data_not_dissected_yet = EI_INIT;


typedef struct _cql_v3_transaction_type {
	guint32 req_frame;
	guint32 rep_frame;
	nstime_t req_time;
} cql_v3_transaction_type;

typedef struct _cql_v3_conversation_info_type {
	wmem_map_t* streams;
} cql_v3_conversation_type;

typedef enum {
	CQL_V3_OPCODE_ERROR = 0x00,
	CQL_V3_OPCODE_STARTUP = 0x01,
	CQL_V3_OPCODE_READY = 0x02,
	CQL_V3_OPCODE_AUTHENTICATE = 0x03,
	/* Opcode 0x04 not used in CQL v3 */
	CQL_V3_OPCODE_OPTIONS = 0x05,
	CQL_V3_OPCODE_SUPPORTED = 0x06,
	CQL_V3_OPCODE_QUERY = 0x07,
	CQL_V3_OPCODE_RESULT = 0x08,
	CQL_V3_OPCODE_PREPARE = 0x09,
	CQL_V3_OPCODE_EXECUTE = 0x0A,
	CQL_V3_OPCODE_REGISTER = 0x0B,
	CQL_V3_OPCODE_EVENT = 0x0C,
	CQL_V3_OPCODE_BATCH = 0x0D,
	CQL_V3_OPCODE_AUTH_CHALLENGE = 0x0E,
	CQL_V3_OPCODE_AUTH_RESPONSE = 0x0F,
	CQL_V3_OPCODE_AUTH_SUCCESS = 0x10
} cql_v3_opcode_type;

static const value_string cql_v3_opcode_names[] = {
	{ CQL_V3_OPCODE_ERROR, "ERROR" },
	{ CQL_V3_OPCODE_STARTUP, "STARTUP" },
	{ CQL_V3_OPCODE_READY, "READY" },
	{ CQL_V3_OPCODE_AUTHENTICATE, "AUTHENTICATE" },
	{ CQL_V3_OPCODE_OPTIONS, "OPTIONS" },
	{ CQL_V3_OPCODE_SUPPORTED, "SUPPORTED" },
	{ CQL_V3_OPCODE_QUERY, "QUERY" },
	{ CQL_V3_OPCODE_RESULT, "RESULT" },
	{ CQL_V3_OPCODE_PREPARE, "PREPARE" },
	{ CQL_V3_OPCODE_EXECUTE, "EXECUTE" },
	{ CQL_V3_OPCODE_REGISTER, "REGISTER" },
	{ CQL_V3_OPCODE_EVENT, "EVENT" },
	{ CQL_V3_OPCODE_BATCH, "BATCH" },
	{ CQL_V3_OPCODE_AUTH_CHALLENGE, "AUTH_CHALLENGE" },
	{ CQL_V3_OPCODE_AUTH_RESPONSE, "AUTH_RESPONSE" },
	{ CQL_V3_OPCODE_AUTH_SUCCESS, "AUTH_SUCCESS" },
	{ 0x00, NULL }
};


typedef enum {
	CQL_V3_FLAG_COMPRESSION = 0x01,
	CQL_V3_FLAG_TRACING = 0x02
} cql_v3_flags;

typedef enum {
	CQL_V3_QUERY_FLAG_VALUES = 0x01,
	CQL_V3_QUERY_FLAG_SKIP_METADATA = 0x02,
	CQL_V3_QUERY_FLAG_PAGE_SIZE = 0x04,
	CQL_V3_QUERY_FLAG_PAGING_STATE = 0x08,
	CQL_V3_QUERY_FLAG_SERIAL_CONSISTENCY = 0x10,
	CQL_V3_QUERY_FLAG_DEFAULT_TIMESTAMP = 0x20,
	CQL_V3_QUERY_FLAG_VALUE_NAMES = 0x40
} cql_v3_query_flags;


typedef enum {
	CQL_V3_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC = 0x0001,
	CQL_V3_RESULT_ROWS_FLAG_HAS_MORE_PAGES = 0x0002,
	CQL_V3_RESULT_ROWS_FLAG_NO_METADATA = 0x0004
} cql_v3_result_rows_flags;

typedef enum {
	CQL_V3_CONSISTENCY_ANY = 0x0000,
	CQL_V3_CONSISTENCY_ONE = 0x0001,
	CQL_V3_CONSISTENCY_TWO = 0x0002,
	CQL_V3_CONSISTENCY_THREE = 0x003,
	CQL_V3_CONSISTENCY_QUORUM = 0x0004,
	CQL_V3_CONSISTENCY_ALL = 0x0005,
	CQL_V3_CONSISTENCY_LOCAL_QUORUM = 0x0006,
	CQL_V3_CONSISTENCY_EACH_QUORUM = 0x0007,
	CQL_V3_CONSISTENCY_SERIAL = 0x0008,
	CQL_V3_CONSISTENCY_LOCAL_SERIAL = 0x0009,
	CQL_V3_CONSISTENCY_LOCAL_ONE = 0x000A
} cql_v3_consistencies;

static const value_string cql_v3_consistency_names[] = {
	{ CQL_V3_CONSISTENCY_ANY, "ANY" },
	{ CQL_V3_CONSISTENCY_ONE, "ONE" },
	{ CQL_V3_CONSISTENCY_TWO, "TWO" },
	{ CQL_V3_CONSISTENCY_THREE, "THREE" },
	{ CQL_V3_CONSISTENCY_QUORUM, "QUORUM" },
	{ CQL_V3_CONSISTENCY_ALL, "ALL" },
	{ CQL_V3_CONSISTENCY_LOCAL_QUORUM, "LOCAL_QUORUM" },
	{ CQL_V3_CONSISTENCY_EACH_QUORUM, "EACH_QUORUM" },
	{ CQL_V3_CONSISTENCY_SERIAL, "SERIAL" },
	{ CQL_V3_CONSISTENCY_LOCAL_SERIAL, "LOCAL_SERIAL" },
	{ CQL_V3_CONSISTENCY_LOCAL_ONE, "LOCAL_ONE" },
	{ 0x00, NULL }
};


typedef enum {
	CQL_V3_BATCH_TYPE_LOGGED = 0,
	CQL_V3_BATCH_TYPE_UNLOGGED = 1,
	CQL_V3_BATCH_TYPE_COUNTER = 2
} cql_v3_batch_types;

static const value_string cql_v3_batch_type_names[] = {
	{ CQL_V3_BATCH_TYPE_LOGGED, "LOGGED" },
	{ CQL_V3_BATCH_TYPE_UNLOGGED, "UNLOGGED" },
	{ CQL_V3_BATCH_TYPE_COUNTER, "COUNTER" },
	{ 0x00, NULL }
};

typedef enum {
	CQL_V3_BATCH_QUERY_TYPE_QUERY = 0,
	CQL_V3_BATCH_QUERY_TYPE_PREPARED = 1
} cql_v3_batch_query_types;

static const value_string cql_v3_batch_query_type_names[] = {
	{ CQL_V3_BATCH_QUERY_TYPE_QUERY, "QUERY" },
	{ CQL_V3_BATCH_QUERY_TYPE_PREPARED, "PREPARED" },
	{ 0x00, NULL }
};

typedef enum {
	CQL_V3_RESULT_KIND_VOID = 0x0001,
	CQL_V3_RESULT_KIND_ROWS = 0x0002,
	CQL_V3_RESULT_KIND_SET_KEYSPACE = 0x0003,
	CQL_V3_RESULT_KIND_PREPARED = 0x0004,
	CQL_V3_RESULT_KIND_SCHEMA_CHANGE = 0x0005
} cql_v3_result_kinds;

static const value_string cql_v3_result_kind_names[] = {
	{ CQL_V3_RESULT_KIND_VOID, "VOID" },
	{ CQL_V3_RESULT_KIND_ROWS, "Rows" },
	{ CQL_V3_RESULT_KIND_SET_KEYSPACE, "Set Keyspace" },
	{ CQL_V3_RESULT_KIND_PREPARED, "Prepared" },
	{ CQL_V3_RESULT_KIND_SCHEMA_CHANGE, "Schema Change" },
	{ 0x00, NULL }
};



typedef enum {
	CQL_V3_RESULT_ROW_TYPE_CUSTOM = 0x0000,
	CQL_V3_RESULT_ROW_TYPE_ASCII = 0x0001,
	CQL_V3_RESULT_ROW_TYPE_BIGINT = 0x0002,
	CQL_V3_RESULT_ROW_TYPE_BLOB = 0x0003,
	CQL_V3_RESULT_ROW_TYPE_BOOLEAN = 0x0004,
	CQL_V3_RESULT_ROW_TYPE_COUNTER = 0x0005,
	CQL_V3_RESULT_ROW_TYPE_DECIMAL = 0x0006,
	CQL_V3_RESULT_ROW_TYPE_DOUBLE = 0x0007,
	CQL_V3_RESULT_ROW_TYPE_FLOAT = 0x0008,
	CQL_V3_RESULT_ROW_TYPE_INT = 0x0009,
	CQL_V3_RESULT_ROW_TYPE_TIMESTAMP = 0x000B,
	CQL_V3_RESULT_ROW_TYPE_UUID = 0x000C,
	CQL_V3_RESULT_ROW_TYPE_VARCHAR = 0x000D,
	CQL_V3_RESULT_ROW_TYPE_VARINT = 0x000E,
	CQL_V3_RESULT_ROW_TYPE_TIMEUUID = 0x000F,
	CQL_V3_RESULT_ROW_TYPE_INET = 0x0010,
	CQL_V3_RESULT_ROW_TYPE_LIST = 0x0020,
	CQL_V3_RESULT_ROW_TYPE_MAP = 0x0021,
	CQL_V3_RESULT_ROW_TYPE_SET = 0x0022,
	CQL_V3_RESULT_ROW_TYPE_UDT = 0x0030,
	CQL_V3_RESULT_ROW_TYPE_TUPLE = 0x0031
} cql_result_row_data_types;

static const value_string cql_v3_result_row_type_names[] = {
	{ CQL_V3_RESULT_ROW_TYPE_CUSTOM, "CUSTOM" },
	{ CQL_V3_RESULT_ROW_TYPE_ASCII, "ASCII" },
	{ CQL_V3_RESULT_ROW_TYPE_BIGINT, "BIGINT" },
	{ CQL_V3_RESULT_ROW_TYPE_BLOB, "BLOB" },
	{ CQL_V3_RESULT_ROW_TYPE_BOOLEAN, "BOOLEAN" },
	{ CQL_V3_RESULT_ROW_TYPE_COUNTER, "COUNTER" },
	{ CQL_V3_RESULT_ROW_TYPE_DECIMAL, "DECIMAL" },
	{ CQL_V3_RESULT_ROW_TYPE_DOUBLE, "DOUBLE" },
	{ CQL_V3_RESULT_ROW_TYPE_FLOAT, "FLOAT" },
	{ CQL_V3_RESULT_ROW_TYPE_INT, "INT" },
	{ CQL_V3_RESULT_ROW_TYPE_TIMESTAMP, "TIMESTAMP" },
	{ CQL_V3_RESULT_ROW_TYPE_UUID, "UUID" },
	{ CQL_V3_RESULT_ROW_TYPE_VARCHAR, "VARCHAR" },
	{ CQL_V3_RESULT_ROW_TYPE_VARINT, "VARINT" },
	{ CQL_V3_RESULT_ROW_TYPE_TIMEUUID, "TIMEUUID" },
	{ CQL_V3_RESULT_ROW_TYPE_INET, "INET" },
	{ CQL_V3_RESULT_ROW_TYPE_LIST, "LIST" },
	{ CQL_V3_RESULT_ROW_TYPE_MAP, "MAP" },
	{ CQL_V3_RESULT_ROW_TYPE_SET, "SET" },
	{ CQL_V3_RESULT_ROW_TYPE_UDT, "UDT" },
	{ CQL_V3_RESULT_ROW_TYPE_TUPLE, "TUBPLE" },
	{ 0x0, NULL }
};

static gint
dissect_cql_v3_query_parameters(proto_tree* cql_subtree, tvbuff_t* tvb, gint offset, int execute)
{
	gint32 bytes_length = 0;
	guint32 flags = 0;
	guint64 i = 0;
	guint32 string_length = 0;
	guint32 value_count = 0;

	static const int * bitmaps[] = {
		&hf_cql_v3_query_flags_values,
		&hf_cql_v3_query_flags_skip_metadata,
		&hf_cql_v3_query_flags_page_size,
		&hf_cql_v3_query_flags_paging_state,
		&hf_cql_v3_query_flags_serial_consistency,
		&hf_cql_v3_query_flags_default_timestamp,
		&hf_cql_v3_query_flags_names_for_values,
		NULL
	};

	/* consistency */
	proto_tree_add_item(cql_subtree, hf_cql_v3_consistency, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* flags */
	proto_tree_add_bitmask(cql_subtree, tvb, offset, hf_cql_v3_flags_bitmap, hf_cql_v3_flags_bitmap, bitmaps, ENC_BIG_ENDIAN);
	flags = tvb_get_guint8(tvb, offset);
	offset += 1;

	if(flags & CQL_V3_QUERY_FLAG_VALUES) {
		proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_value_count, tvb, offset, 2, ENC_BIG_ENDIAN, &value_count);
		offset += 2;
		for (i = 0; i < value_count; ++i) {
			if (!execute && flags & CQL_V3_QUERY_FLAG_VALUE_NAMES) {
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
				offset += 2;
				proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				offset += string_length;
			}
			proto_tree_add_item_ret_int(cql_subtree, hf_cql_v3_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
			offset += 4;
			if (bytes_length > 0) {
				proto_tree_add_item(cql_subtree, hf_cql_v3_bytes, tvb, offset, bytes_length, ENC_NA);
				offset += bytes_length;
			}
		}
	}

	if (flags & CQL_V3_QUERY_FLAG_PAGE_SIZE) {
		proto_tree_add_item(cql_subtree, hf_cql_v3_page_size, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if (flags & CQL_V3_QUERY_FLAG_PAGING_STATE) {
		proto_tree_add_item_ret_int(cql_subtree, hf_cql_v3_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
		offset += 4;
		if (bytes_length > 0) {
			proto_tree_add_item(cql_subtree, hf_cql_v3_bytes, tvb, offset, bytes_length, ENC_NA);
			offset += bytes_length;
		}
	}

	if (flags & CQL_V3_QUERY_FLAG_SERIAL_CONSISTENCY) {
		proto_tree_add_item(cql_subtree, hf_cql_v3_consistency, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (flags & CQL_V3_QUERY_FLAG_DEFAULT_TIMESTAMP) {
		proto_tree_add_item(cql_subtree, hf_cql_v3_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	}

	return offset;
}

static guint
get_cql_v3_pdu_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset, void* data _U_)
{
	/* CQL v3 has 32-bit length at 5th byte in frame. */
	guint32 length = tvb_get_ntohl(tvb, offset + 5);

	/* Include length of frame header. */
	return length + 9;
}

static cql_v3_transaction_type*
cql_transaction_add_request(cql_v3_conversation_type* conv,
				packet_info* pinfo,
				gint32 stream,
				int fake)
{
	cql_v3_transaction_type* trans;
	wmem_list_t* list;

	list = (wmem_list_t*)wmem_map_lookup(conv->streams, GINT_TO_POINTER(stream));
	if(!list) {
		list = wmem_list_new(wmem_file_scope());
	} else {
		wmem_map_remove(conv->streams, GINT_TO_POINTER(stream));
	}

	trans = wmem_new(wmem_file_scope(), cql_v3_transaction_type);
	if (fake) {
		trans->req_frame = 0;
	} else {
		trans->req_frame = pinfo->fd->num;
	}
	trans->rep_frame = 0;
	trans->req_time = pinfo->fd->abs_ts;

	wmem_list_append(list, (void *)trans);
	wmem_map_insert(conv->streams, GINT_TO_POINTER(stream), (void*)list);

	return trans;
}

static cql_v3_transaction_type*
cql_enrich_transaction_with_response(cql_v3_conversation_type* conv,
					packet_info* pinfo,
					gint32 stream)
{
	cql_v3_transaction_type* trans;
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

	trans = (cql_v3_transaction_type *)wmem_list_frame_data(frame);
	if (!trans) {
		return NULL;
	}

	trans->rep_frame = pinfo->fd->num;

	return trans;
}

static cql_v3_transaction_type*
cql_transaction_lookup(cql_v3_conversation_type* conv,
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
		cql_v3_transaction_type* trans = NULL;
		trans = (cql_v3_transaction_type *)wmem_list_frame_data(frame);
		if (trans->req_frame == pinfo->fd->num || trans->rep_frame == pinfo->fd->num) {
			return trans;
		}
	} while ((frame = wmem_list_frame_next(frame)));

	return NULL;
}

static int
dissect_cql_v3_tcp_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
	proto_item* ti;
	proto_tree* cql_tree;
	proto_tree* cql_subtree = NULL;
	proto_tree* rows_subtree = NULL;
	proto_tree* metadata_subtree = NULL;

	gint offset = 0;
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
	gint32 bytes_length = 0;
	guint32 result_rows_data_type = 0;
	guint32 result_rows_row_count = 0;

	conversation_t* conversation;
	cql_v3_conversation_type* cql_conv;
	cql_v3_transaction_type* cql_trans = NULL;

	static const int * bitmaps[] = {
		&hf_cql_v3_flag_compression,
		&hf_cql_v3_flag_tracing,
		NULL
	};

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CQL");
	col_clear(pinfo->cinfo, COL_INFO);

	first_byte = tvb_get_guint8(tvb, 0);
	cql_version = first_byte & (guint8)0x7F;
	server_to_client = first_byte & (guint8)0x80;
	opcode = tvb_get_guint8(tvb, 4);

	col_add_fstr(pinfo->cinfo, COL_INFO, "v%d %s Type %s",
		cql_version,
		server_to_client == 0 ? "C->S" : "S->C",
		val_to_str(opcode, cql_v3_opcode_names, "Unknown (0x%02x)")
	);

	conversation = find_or_create_conversation(pinfo);
	cql_conv = (cql_v3_conversation_type*) conversation_get_proto_data(conversation, proto_cql);
	if(!cql_conv) {
		cql_conv = wmem_new(wmem_file_scope(), cql_v3_conversation_type);
		cql_conv->streams = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		conversation_add_proto_data(conversation, proto_cql, cql_conv);
	}

	ti = proto_tree_add_item(tree, proto_cql, tvb, 0, -1, ENC_NA);
	cql_tree = proto_item_add_subtree(ti, ett_cql_protocol);

	proto_tree_add_item(cql_tree, hf_cql_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_bitmask(cql_tree, tvb, offset, hf_cql_v3_flags_bitmap, hf_cql_v3_flags_bitmap, bitmaps, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item_ret_int(cql_tree, hf_cql_v3_stream, tvb, offset, 2, ENC_BIG_ENDIAN, &stream);
	offset += 2;
	proto_tree_add_item(cql_tree, hf_cql_v3_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item_ret_uint(cql_tree, hf_cql_v3_length, tvb, offset, 4, ENC_BIG_ENDIAN, &message_length);
	offset += 4;


	/* Track the request/response. */
	if (!pinfo->fd->flags.visited) {
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
		ti = proto_tree_add_uint(cql_tree, hf_cql_v3_response_in, tvb, 0, 0, cql_trans->rep_frame);
		PROTO_ITEM_SET_GENERATED(ti);
	}
	if (server_to_client && cql_trans->req_frame) {
		/* reply */
		nstime_t ns;

		ti = proto_tree_add_uint(cql_tree, hf_cql_v3_response_to, tvb, 0, 0, cql_trans->req_frame);
		PROTO_ITEM_SET_GENERATED(ti);
		nstime_delta(&ns, &pinfo->fd->abs_ts, &cql_trans->req_time);
		ti = proto_tree_add_time(cql_tree, hf_cql_v3_response_time, tvb, 0, 0, &ns);
		PROTO_ITEM_SET_GENERATED(ti);
	}

	/* Dissect the operation. */
	if (server_to_client == 0) {
		switch (opcode) {
			case CQL_V3_OPCODE_STARTUP:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_v3_message, &ti, "Message STARTUP");
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_map_size, tvb, offset, 2, ENC_BIG_ENDIAN, &map_size);
				offset += 2;
				for(i = 0; i < map_size; ++i) {
					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
					offset += 2;
					proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
					offset += string_length;

					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
					offset += 2;
					proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
					offset += string_length;
				}
				break;

			case CQL_V3_OPCODE_AUTH_RESPONSE:
				/* not implemented */
				break;

			case CQL_V3_OPCODE_OPTIONS:
				/* body should be empty */
				break;

			case CQL_V3_OPCODE_QUERY:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_v3_message, &ti, "Query");

				/* Query */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
				offset += 4;
				proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				offset += string_length;

				/* Query parameters */
				dissect_cql_v3_query_parameters(cql_subtree, tvb, offset, 0);

				break;


			case CQL_V3_OPCODE_PREPARE:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_v3_message, &ti, "Message PREPARE");

				/* TODO: Link for later use by EXECUTE? */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
				offset += 4;
				proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				break;


			case CQL_V3_OPCODE_EXECUTE:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_v3_message, &ti, "Message EXECUTE");

				/* TODO: link to original PREPARE? */

				/* Query ID */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &bytes_length);
				offset += 2;
				proto_tree_add_item(cql_subtree, hf_cql_v3_query_id, tvb, offset, bytes_length, ENC_NA);
				offset += bytes_length;

				/* Query parameters */
				dissect_cql_v3_query_parameters(cql_subtree, tvb, offset, 1);
				break;


			case CQL_V3_OPCODE_BATCH:
				/* TODO NOT DONE */
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_v3_message, &ti, "Message BATCH");

				proto_tree_add_item(cql_subtree, hf_cql_v3_batch_type, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;

				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_batch_query_size, tvb, offset, 2, ENC_BIG_ENDIAN, &batch_size);
				offset += 2;

				for (i = 0; i < batch_size; ++i) {
					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_batch_query_type, tvb, offset, 1, ENC_BIG_ENDIAN, &batch_query_type);
					offset += 1;
					if (batch_query_type == 0) {
						/* Query */
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_length, tvb, offset, 4, ENC_BIG_ENDIAN, &string_length);
						offset += 4;
						proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						offset += string_length;

						/* Query parameters */
						offset = dissect_cql_v3_query_parameters(cql_subtree, tvb, offset, 0);
					} else if (batch_query_type == 1) {
						/* short ID from preparation before. */
						proto_tree_add_item(cql_subtree, hf_cql_v3_query_id, tvb, offset, 2, ENC_NA);
						offset += 2;
					}
				}
				break;

			case CQL_V3_OPCODE_REGISTER:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_v3_message, &ti, "Message REGISTER");

				/* string list */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_list_size, tvb, offset, 2, ENC_BIG_ENDIAN, &map_size);
				offset += 2;
				for(i = 0; i < map_size; ++i) {
					proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
					offset += 2;
					proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
					offset += string_length;
				}

				break;

			default:
				proto_tree_add_expert(cql_tree, pinfo, &ei_cql_data_not_dissected_yet, tvb, 0, message_length);
				break;
		}
	} else {
		switch (opcode) {
			case CQL_V3_OPCODE_ERROR:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_v3_message, &ti, "Message ERROR");

				proto_tree_add_item(cql_subtree, hf_cql_v3_error_code, tvb, offset, 4, ENC_BIG_ENDIAN);

				/* string  */
				proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
				offset += 2;
				proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				break;


			case CQL_V3_OPCODE_AUTHENTICATE:
				/* Not implemented. */
				break;


			case CQL_V3_OPCODE_SUPPORTED:
				/* Not implemented. */
				break;


			case CQL_V3_OPCODE_RESULT:
				cql_subtree = proto_tree_add_subtree(cql_tree, tvb, offset, message_length, ett_cql_v3_message, &ti, "Message RESULT");

				proto_tree_add_item_ret_int(cql_subtree, hf_cql_v3_result_kind, tvb, offset, 4, ENC_BIG_ENDIAN, &result_kind);
				offset += 4;

				switch (result_kind) {
					case CQL_V3_RESULT_KIND_VOID:
						/* Nothing */
						break;

					case CQL_V3_RESULT_KIND_ROWS:
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_result_rows_flags_values, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_flags);
						proto_tree_add_item(cql_subtree, hf_cql_v3_result_rows_flag_global_tables_spec, tvb, offset, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(cql_subtree, hf_cql_v3_result_rows_flag_has_more_pages, tvb, offset, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(cql_subtree, hf_cql_v3_result_rows_flag_no_metadata, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;

						metadata_subtree = proto_tree_add_subtree(cql_subtree, tvb, offset, 0, ett_cql_v3_result_metadata, &ti, "Metadata");

						proto_tree_add_item_ret_int(metadata_subtree, hf_cql_v3_result_rows_column_count, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_columns_count);
						offset += 4;

						if (result_rows_flags & CQL_V3_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC) {
							proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
							offset += 2;
							proto_tree_add_item(metadata_subtree, hf_cql_v3_string_result_rows_global_table_spec_ksname, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
							offset += string_length;

							proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
							offset += 2;
							proto_tree_add_item(metadata_subtree, hf_cql_v3_string_result_rows_global_table_spec_table_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
							offset += string_length;
						}

						if (result_rows_flags & CQL_V3_RESULT_ROWS_FLAG_HAS_MORE_PAGES) {
							/* show paging state */
							proto_tree_add_item_ret_int(metadata_subtree, hf_cql_v3_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
							offset += 4;
							if (bytes_length > 0) {
								proto_tree_add_item(metadata_subtree, hf_cql_v3_paging_state, tvb, offset, bytes_length, ENC_NA);
								offset += bytes_length;
							}
						}

						if (result_rows_flags & CQL_V3_RESULT_ROWS_FLAG_NO_METADATA) {
							/* There will be no col_spec elements. */
						} else {

							for (j = 0; j < result_rows_columns_count; ++j) {
								if (!(result_rows_flags & CQL_V3_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC)) {
									/* ksname and tablename */
									proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
									offset += 2;
									proto_tree_add_item(metadata_subtree, hf_cql_v3_string_result_rows_keyspace_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
									offset += string_length;
									proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
									offset += 2;
									proto_tree_add_item(metadata_subtree, hf_cql_v3_string_result_rows_table_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
									offset += string_length;
								}

								/* column name */
								proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
								offset += 2;
								proto_tree_add_item(metadata_subtree, hf_cql_v3_string_result_rows_column_name, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
								offset += string_length;


								/* type "option" */
								proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_v3_result_rows_data_type, tvb, offset, 2, ENC_BIG_ENDIAN, &result_rows_data_type);
								offset += 2;
								switch (result_rows_data_type) {
									case CQL_V3_RESULT_ROW_TYPE_CUSTOM:
										proto_tree_add_item(metadata_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
										offset += string_length;
										break;

									case CQL_V3_RESULT_ROW_TYPE_LIST:
										/* TODO Handle nested types */
										return 12;
									case CQL_V3_RESULT_ROW_TYPE_MAP:
										/* TODO Handle nested types */
										return 13;

									case CQL_V3_RESULT_ROW_TYPE_SET:
										proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_v3_result_rows_data_type, tvb, offset, 2, ENC_BIG_ENDIAN, &result_rows_data_type);
										offset += 2;
										/* TODO Handle nested types */
										break;

									case CQL_V3_RESULT_ROW_TYPE_UDT:
										/* TODO Handle nested types */
										return 16;
									default:
										break;
								}
							}
						}

						rows_subtree = proto_tree_add_subtree(cql_subtree, tvb, offset, 0, ett_cql_v3_result_rows, &ti, "Rows");
						proto_tree_add_item_ret_uint(rows_subtree, hf_cql_v3_result_rows_row_count, tvb, offset, 4, ENC_BIG_ENDIAN, &result_rows_row_count);

						/*
						for (j = 0; j < result_rows_row_count; ++j) {
							columns_subtree = proto_tree_add_subtree(rows_subtree, tvb, offset, 0, ett_cql_v3_result_columns, &ti, "Data (Columns)");

							for (k = 0; k < result_rows_columns_count; ++k) {
								proto_tree_add_item_ret_uint(columns_subtree, hf_cql_v3_bytes_length, tvb, offset, 4, ENC_BIG_ENDIAN, &bytes_length);
								offset += 4;
								proto_tree_add_item(columns_subtree, hf_cql_v3_bytes, tvb, offset, bytes_length, ENC_NA);
								offset += bytes_length;
							}
						}
						*/


						break;


					case CQL_V3_RESULT_KIND_SET_KEYSPACE:
						proto_tree_add_item_ret_uint(cql_subtree, hf_cql_v3_string_length, tvb, offset, 2, ENC_BIG_ENDIAN, &string_length);
						offset += 2;
						proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						break;


					case CQL_V3_RESULT_KIND_PREPARED:
						/* Query ID */
						proto_tree_add_item_ret_uint(metadata_subtree, hf_cql_v3_short_bytes_length, tvb, offset, 2, ENC_BIG_ENDIAN, &bytes_length);
						offset += 2;
						proto_tree_add_item(metadata_subtree, hf_cql_v3_query_id, tvb, offset, bytes_length, ENC_NA);

						break;


					case CQL_V3_RESULT_KIND_SCHEMA_CHANGE:
						proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						offset += string_length;
						proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						offset += string_length;
						proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
						break;

					default:
						proto_tree_add_expert(cql_subtree, pinfo, &ei_cql_data_not_dissected_yet, tvb, 0, message_length);
						break;
				}

				break;


			case CQL_V3_OPCODE_EVENT:
				proto_tree_add_item(cql_subtree, hf_cql_v3_string, tvb, offset, string_length, ENC_UTF_8 | ENC_NA);
				break;


			case CQL_V3_OPCODE_AUTH_CHALLENGE:
				break;


			case CQL_V3_OPCODE_AUTH_SUCCESS:
				break;

			default:
				proto_tree_add_expert(cql_subtree, pinfo, &ei_cql_data_not_dissected_yet, tvb, 0, message_length);
				break;
		}
	}

	return tvb_reported_length(tvb);
}

static int
dissect_cql_v3_tcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
	/* This dissector version only understands CQL protocol v3. */
	if (tvb_reported_length(tvb) < 1)
		return 0;

	if ((tvb_get_guint8(tvb, 0) & 0x7F) != 3)
		return 0;

	tcp_dissect_pdus(tvb, pinfo, tree, cql_v3_desegment, 9 /* bytes to determine length of PDU */, get_cql_v3_pdu_len, dissect_cql_v3_tcp_pdu, data);
	return tvb_reported_length(tvb);
}

void
proto_reg_handoff_cql(void)
{
	static dissector_handle_t cql_handle;

	cql_handle = create_dissector_handle(dissect_cql_v3_tcp, proto_cql);
	dissector_add_uint("tcp.port", CQL_DEFAULT_PORT, cql_handle);
}


void
proto_register_cql(void)
{
	expert_module_t* expert_cql;
	static hf_register_info hf[] = {
		{
			&hf_cql_version,
			{
				"Version", "cql.version",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				"CQL protocol version (not language version)", HFILL
			}
		},
		{
			&hf_cql_v3_flags_bitmap,
			{
				"Flags", "cql.flags",
				FT_UINT8, BASE_HEX,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_result_rows_flags_values,
			{
				"Rows Result Flags", "cql.result.rows.flags",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_result_rows_flag_global_tables_spec,
			{
				"Global tables spec.", "cql.result.rows.flags.global_tables",
				FT_BOOLEAN, 32,
				NULL, CQL_V3_RESULT_ROWS_FLAG_GLOBAL_TABLES_SPEC,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_result_rows_flag_has_more_pages,
			{
				"Has More Pages", "cql.result.rows.flags.has_more_pages",
				FT_BOOLEAN, 32,
				NULL, CQL_V3_RESULT_ROWS_FLAG_HAS_MORE_PAGES,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_result_rows_flag_no_metadata,
			{
				"No Metadata", "cql.result.rows.flags.no_metadata",
				FT_BOOLEAN, 32,
				NULL, CQL_V3_RESULT_ROWS_FLAG_NO_METADATA,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_flag_compression,
			{
				"Compression", "cql.flags.compression",
				FT_BOOLEAN, 8,
				NULL, CQL_V3_FLAG_COMPRESSION,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_flag_tracing,
			{
				"Tracing", "cql.flags.tracing",
				FT_BOOLEAN, 8,
				NULL, CQL_V3_FLAG_TRACING,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_query_flags_page_size,
			{
				"Page Size", "cql.query.flags.page_size",
				FT_BOOLEAN, 8,
				NULL, CQL_V3_QUERY_FLAG_PAGE_SIZE,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_query_flags_skip_metadata,
			{
				"Skip Metadata", "cql.query.flags.skip_metadata",
				FT_BOOLEAN, 8,
				NULL, CQL_V3_QUERY_FLAG_SKIP_METADATA,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_query_flags_values,
			{
				"Values", "cql.query.flags.values",
				FT_BOOLEAN, 8,
				NULL, CQL_V3_QUERY_FLAG_VALUES,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_query_flags_default_timestamp,
			{
				"Default Timestamp", "cql.query.flags.default_timestamp",
				FT_BOOLEAN, 8,
				NULL, CQL_V3_QUERY_FLAG_DEFAULT_TIMESTAMP,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_query_flags_names_for_values,
			{
				"Names for Values", "cql.query.flags.value_names",
				FT_BOOLEAN, 8,
				NULL, CQL_V3_QUERY_FLAG_VALUE_NAMES,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_query_flags_paging_state,
			{
				"Paging State", "cql.query.flags.paging_state",
				FT_BOOLEAN, 8,
				NULL, CQL_V3_QUERY_FLAG_PAGING_STATE,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_query_flags_serial_consistency,
			{
				"Serial Consistency", "cql.query.flags.serial_consistency",
				FT_BOOLEAN, 8,
				NULL, CQL_V3_QUERY_FLAG_SERIAL_CONSISTENCY,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_stream,
			{
				"Stream Identifier", "cql.stream",
				FT_INT16, BASE_DEC,
				NULL, 0x0,
				"Stream identifier this packet belongs to", HFILL
			}
		},
		{
			&hf_cql_v3_opcode,
			{
				"Opcode", "cql.opcode",
				FT_UINT8, BASE_DEC,
				VALS(cql_v3_opcode_names), 0x7F, /* Mask the highest-order bit because it indicates message direction, not opcode. */
				"CQL operation this packet describes", HFILL
			}
		},
		{
			&hf_cql_v3_batch_type,
			{
				"Batch type", "cql.batch_type",
				FT_UINT8, BASE_DEC,
				VALS(cql_v3_batch_type_names), 0x0,
				"CQL batch type", HFILL
			}
		},
		{
			&hf_cql_v3_batch_query_type,
			{
				"Batch query type", "cql.batch_query_type",
				FT_UINT8, BASE_DEC,
				VALS(cql_v3_batch_query_type_names), 0x00,
				"CQL batch query type", HFILL
			}
		},
		{
			&hf_cql_v3_length,
			{
				"Message Length", "cql.message_length",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_cql_v3_string_map_size,
			{
				"String Map Size", "cql.string_map_size",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of strings in the map", HFILL
			}
		},
		{
			&hf_cql_v3_string_list_size,
			{
				"String List Size", "cql.string_list_size",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of strings in the list", HFILL
			}
		},
		{
			&hf_cql_v3_string,
			{
				"String", "cql.string",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				"UTF-8 string value", HFILL
			}
		},
		{
			&hf_cql_v3_string_result_rows_global_table_spec_ksname,
			{
				"Global Spec Keyspace Name", "cql.result.rows.keyspace_name",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				"UTF-8 string value", HFILL
			}
		},
		{
			&hf_cql_v3_string_result_rows_global_table_spec_table_name,
			{
				"Global Spec Table Name", "cql.result.rows.table_name",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				"UTF-8 string value", HFILL
			}
		},
		{
			&hf_cql_v3_string_result_rows_table_name,
			{
				"Table Name", "cql.result.rows.table_name",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				"UTF-8 string value", HFILL
			}
		},
		{
			&hf_cql_v3_string_result_rows_keyspace_name,
			{
				"Keyspace Name", "cql.result.rows.keyspace_name",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				"UTF-8 string value", HFILL
			}
		},
		{
			&hf_cql_v3_string_result_rows_column_name,
			{
				"Column Name", "cql.result.rows.column_name",
				FT_STRING, STR_UNICODE,
				NULL, 0x0,
				"UTF-8 string value", HFILL
			}
		},
		{
			&hf_cql_v3_string_length,
			{
				"String Length", "cql.string_length",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				"Length of the subsequent string value", HFILL
			}
		},
		{
			&hf_cql_v3_consistency,
			{
				"Consistency", "cql.consistency",
				FT_UINT16, BASE_HEX,
				VALS(cql_v3_consistency_names), 0x0,
				"CQL consistency level specification", HFILL
			}
		},
		{
			&hf_cql_v3_value_count,
			{
				"Value count", "cql.value_count",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of subsequent values", HFILL
			}
		},
		{
			&hf_cql_v3_bytes_length,
			{
				"Bytes length", "cql.bytes_length.int",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				"Number of subsequent bytes", HFILL
			}
		},
		{
			&hf_cql_v3_short_bytes_length,
			{
				"Bytes length", "cql.bytes_length.short",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of subsequent bytes", HFILL
			}
		},		{
			&hf_cql_v3_bytes,
			{
				"Bytes", "cql.bytes",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				"Raw byte array", HFILL
			}
		},
		{
			&hf_cql_v3_paging_state,
			{
				"Paging State", "cql.paging_state",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				"Paging state byte array", HFILL
			}
		},
		{
			&hf_cql_v3_page_size,
			{
				"Page size", "cql.page_size",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				"Desired page size of result (in CQL3 rows)", HFILL
			}
		},
		{
			&hf_cql_v3_response_in,
			{
				"Response in", "cql.response_in",
				FT_FRAMENUM, BASE_NONE,
				NULL, 0x0,
				"The response to this CQL request is in this frame", HFILL
			}
		},
		{
			&hf_cql_v3_response_to,
			{
				"Request in", "cql.response_to",
				FT_FRAMENUM, BASE_NONE,
				NULL, 0x0,
				"This is a response to the CQL request in this fame", HFILL
			}
		},
		{
			&hf_cql_v3_response_time,
			{
				"Response time", "cql.response_time",
				FT_RELATIVE_TIME, BASE_NONE,
				NULL, 0x0,
				"The time between the request and the response", HFILL
			}
		},
		{
			&hf_cql_v3_timestamp,
			{
				"Timestamp", "cql.timestamp",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
				NULL, 0x0,
				"CQL timestamp", HFILL
			}
		},
		{
			&hf_cql_v3_query_id,
			{
				"Query ID", "cql.query_id",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				"CQL query id resulting from a PREPARE statement", HFILL
			}
		},
		{
			&hf_cql_v3_batch_query_size,
			{
				"Batch Query Size", "cql.batch_query_size",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of statements in CQL batch", HFILL
			}
		},
		{
			&hf_cql_v3_error_code,
			{
				"Error Code", "cql.error_code",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				"Error code from CQL server", HFILL
			}
		},
		{
			&hf_cql_v3_result_kind,
			{
				"Result Kind", "cql.result.kind",
				FT_INT32, BASE_DEC,
				VALS(cql_v3_result_kind_names), 0x0,
				"Kind of result from CQL server", HFILL
			}
		},
		{
			&hf_cql_v3_result_rows_column_count,
			{
				"Column Count", "cql.result.rows.column_count",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				"Count of columns in a rows result from CQL server", HFILL
			}
		},
		{
			&hf_cql_v3_result_rows_data_type,
			{
				"CQL Data Type", "cql.data_type",
				FT_UINT16, BASE_DEC,
				VALS(cql_v3_result_row_type_names), 0x0,
				"CQL data type name", HFILL
			}
		},
		{
			&hf_cql_v3_result_rows_row_count,
			{
				"CQL Result Rows Count", "cql.result.rows.row_count",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				"Number of rows returned in CQL result", HFILL
			}
		}
	};

	static ei_register_info ei[] = {
		{ &ei_cql_data_not_dissected_yet,
		  { "cql.ie_data_not_dissected_yet",
			 PI_UNDECODED, PI_WARN, "IE data not dissected yet", EXPFILL }},
	};

	static gint* ett[] = {
		&ett_cql_protocol,
		&ett_cql_v3_message,
		&ett_cql_v3_result_columns,
		&ett_cql_v3_result_metadata,
		&ett_cql_v3_result_rows
	};

	proto_cql = proto_register_protocol("Cassandra CQL Protocol", "CQL", "cql" );

	proto_register_field_array(proto_cql, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_cql = expert_register_protocol(proto_cql);
	expert_register_field_array(expert_cql, ei, array_length(ei));
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
