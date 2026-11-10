/* packet-json.c
 * Routines for JSON dissection
 * References:
 *     RFC 4627: https://tools.ietf.org/html/rfc4627
 *     Website:  http://json.org/
 *
 * Copyright 2010, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <inttypes.h>

#ifdef __linux__
#include <unistd.h>  /* For readlink() */
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/wsjson.h>

#include <wsutil/str_util.h>
#include <wsutil/strtoi.h>
#include <wsutil/unicode-utils.h>
#include <wsutil/inet_addr.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/regex.h>

#include <wiretap/wtap.h>

#include "packet-media-type.h"
#include "packet-acdr.h"
#include "packet-json.h"
#include "packet-http.h"
#include "packet-http2.h"
#include "json-dictionary.h"

void proto_register_json(void);
void event_register_json(void);
void proto_reg_handoff_json(void);
void event_reg_handoff_json(void);

static char* json_string_unescape(wmem_allocator_t *scope, const char *string, size_t *length_ptr);
static const char* get_json_string(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int len, bool remove_quotes);

static dissector_handle_t json_handle;
static dissector_handle_t json_file_handle;

static int proto_json;
static int proto_http = -1;

//Used to get AC DR proto data
static int proto_acdr;

static int hf_json_array;
static int hf_json_array_compact;
static int hf_json_array_item_compact;
static int hf_json_array_raw;
static int hf_json_array_item_raw;
static int hf_json_binary_data;
static int hf_json_ignored_leading_bytes;
static int hf_json_key;
static int hf_json_member;
static int hf_json_member_compact;
static int hf_json_member_raw;
static int hf_json_member_with_value;
static int hf_json_object;
static int hf_json_object_compact;
static int hf_json_object_raw;
static int hf_json_path;
static int hf_json_path_with_value;
static int hf_json_value_false;
static int hf_json_value_nan;
static int hf_json_value_null;
static int hf_json_value_number;
static int hf_json_value_string;
static int hf_json_value_true;

static int ett_json;
static int ett_json_array;
static int ett_json_object;
static int ett_json_member;
/* Define the trees for json compact form */
static int ett_json_compact;
static int ett_json_array_compact;
static int ett_json_object_compact;
static int ett_json_member_compact;
/* Define the trees for json raw form */
static int ett_json_raw;
static int ett_json_array_raw;
static int ett_json_object_raw;
static int ett_json_member_raw;
/* Define the trees for JSON+ form */
static int ett_json_plus;
static int ett_json_plus_object;
static int ett_json_plus_array;

static expert_field ei_json_malformed = EI_INIT;

/* Expert info identifiers for JSON+ */
static expert_field ei_json_plus_invalid_json = EI_INIT;
static expert_field ei_json_plus_parse_error = EI_INIT;
static expert_field ei_json_plus_type_mismatch = EI_INIT;

/* Global dictionary for JSON+ (loaded from XML) */
static json_dictionary_t json_plus_dictionary;

/* Per-packet gate for dictionary field parsing.
 *
 * When the loaded dictionary contains at least one <protocol> entry, the user
 * wants field-level dissection to happen ONLY for packets that match one of
 * those protocols (via path regex or port). This flag is set at the start of
 * each JSON dissection inside the dispatch block:
 *   true  - no <protocol> entries, or a matching <protocol> was found
 *   false - <protocol> entries exist but none matched (skip dictionary fields)
 *
 * Default true preserves behavior when JSON+ is off (no dispatch block runs)
 * and when no protocols are loaded. */
static bool jsonplus_dict_active = true;

/* Per-packet: the json_protocol_t* that matched dispatch, or NULL.
 * Set in the dispatch block before any field lookup.  Drives
 * jsonplus_lookup_field_by_path() to search proto->fields instead of
 * the global dict->fields when a protocol is active. */
static json_protocol_t *jsonplus_current_protocol = NULL;

/* True when `port` is in the protocol's port_list. Used to enforce
 * condition="and": when a protocol matched on one criterion, this helper
 * verifies the other criterion (port) also matches. */
static bool
jsonplus_proto_port_matches(const json_protocol_t *p, unsigned port)
{
	for (GSList *e = p->port_list; e; e = e->next) {
		if (port == *(unsigned *)e->data) return true;
	}
	return false;
}

/* JSON+ constants */
#define JSON_PLUS_MAX_PATH_DEPTH 32

/* Forward declaration for JSON+ dissection */
static int jsonplus_display_json_tree_dict(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, wmem_allocator_t *pool,
				  jsmntok_t *tokens, int token_idx, const char *json_buf,
				  const char **path_parts, int path_depth);

/* Preferences */
static bool json_compact;

static bool json_raw;

static bool json_plus;

/* JSON+ specific preferences */
static bool gbl_json_desegment = true;
static bool gbl_json_run_external_parsers = false;
static bool gbl_json_run_external_parsers_cli = false;
static bool gbl_json_parser_prefs_initialized = false;

/* Determine whether to hide the tree of original form or root item of compact, raw or JSON+ form
 * based on the enabled status of compact_form, raw_form, and json_plus preferences.
 * If the preference auto_hide is true and compact_form, raw_form, or json_plus is true, hide the tree of
 * original form. If the preference auto_hide is true and only one of preference of
 * compact_form, raw_form, or json_plus is true, then hide the root item of compact, raw, or JSON+ form and put
 * the content of compact, raw, or JSON+ form under the tree item of JSON protocol directly.
 */
static bool auto_hide;

static bool ignore_leading_bytes;

static bool hide_extended_path_based_filtering;

static bool unescape_strings;

static dissector_handle_t text_lines_handle;
static dissector_handle_t falco_json_handle;

typedef enum {
	JSON_TOKEN_INVALID = -1,
	JSON_TOKEN_NUMBER = 0,
	JSON_TOKEN_STRING,
	JSON_TOKEN_FALSE,
	JSON_TOKEN_NULL,
	JSON_TOKEN_TRUE,
	JSON_TOKEN_NAN,

	/* not really tokens ... */
	JSON_OBJECT,
	JSON_ARRAY

} json_token_type_t;

typedef enum {
	JSON_MARK_TYPE_NONE = 0,
	JSON_MARK_TYPE_BEGIN_OBJECT,
	JSON_MARK_TYPE_END_OBJECT,
	JSON_MARK_TYPE_BEGIN_ARRAY,
	JSON_MARK_TYPE_END_ARRAY,
	JSON_MARK_TYPE_MEMBER_NAME,
	JSON_MARK_TYPE_VALUE
} json_mark_type_t;

typedef struct {
	wmem_stack_t *stack;
	wmem_stack_t *stack_compact; /* Used for compact json form only */
	wmem_stack_t *array_idx;	/* Used for compact json form only.
									Top item: -3.
									Object: < 0.
									Array -1: no key, -2: has key  */
	wmem_stack_t* stack_path;
	packet_info* pinfo;
	wmem_stack_t* stack_raw; /* Used for raw json form only */
	json_mark_type_t prev_item_type_raw; /* Used for raw json form only */
	proto_item* prev_item_raw; /* Used for raw json form only */

	/* Tokenized JSON text (see json_tokenize()) */
	tvbuff_t *tvb;
	const char *buf;	/* JSON text; token offsets are relative to it */
	int buf_len;
	int base_offset;	/* tvb offset of buf[0] */
	jsmntok_t *tokens;
	int num_tokens;
	int parse_result;	/* jsmn result: >= 0 on success, enum jsmnerr on error */
	int parse_error_offset;	/* where jsmn stopped on error, relative to buf */
	int error_offset;	/* first error found while dissecting, relative to buf, or -1 */
	const char *error_msg;
} json_parser_data_t;

/* A JSON value or object member key, located in the tvb */
typedef struct {
	json_token_type_t type;
	int offset;		/* tvb offset; strings include the quotation marks */
	int len;
	int close_offset;	/* objects and arrays: tvb offset of the closing bracket, or -1 if missing */
} json_elem_t;

#define JSON_COMPACT_TOP_ITEM -3
#define JSON_COMPACT_OBJECT_WITH_KEY -2
#define JSON_COMPACT_OBJECT_WITHOUT_KEY -1
#define JSON_COMPACT_ARRAY 0

#define JSON_ARRAY_BEGIN(data) wmem_stack_push((data)->array_idx, GINT_TO_POINTER(JSON_COMPACT_ARRAY))
#define JSON_OBJECT_BEGIN(data) wmem_stack_push((data)->array_idx, GINT_TO_POINTER(JSON_COMPACT_OBJECT_WITHOUT_KEY))
#define JSON_ARRAY_OBJECT_END(data) wmem_stack_pop((data)->array_idx)
#define JSON_INSIDE_ARRAY(idx) (idx >= JSON_COMPACT_ARRAY)
#define JSON_OBJECT_SET_HAS_KEY(idx) (idx == JSON_COMPACT_OBJECT_WITH_KEY)

#define json_hide_original_tree() (auto_hide && (json_compact || json_raw || json_plus))
#define json_hide_root_item() (auto_hide && ((json_compact + json_raw + json_plus) == 1))

static void
json_array_index_increment(json_parser_data_t *data)
{
	int idx = GPOINTER_TO_INT(wmem_stack_pop(data->array_idx));
	idx++;
	wmem_stack_push(data->array_idx, GINT_TO_POINTER(idx));
}

static void
json_object_add_key(json_parser_data_t *data)
{
	wmem_stack_pop(data->array_idx);
	wmem_stack_push(data->array_idx, GINT_TO_POINTER(JSON_COMPACT_OBJECT_WITH_KEY));
}

static char*
json_string_unescape(wmem_allocator_t *scope, const char *string, size_t *length_ptr)
{
	size_t read_index = 0;
	size_t string_length = strlen(string);

	wmem_strbuf_t* output_string_buffer = wmem_strbuf_new_sized(scope, string_length);

	while (true)
	{
		// Do not overflow input string
		if (!(read_index < string_length))
		{
			break;
		}

		uint8_t current_character = string[read_index];

		// character that IS NOT escaped
		if (current_character != '\\')
		{
			// A single UTF-8 character can cover more than one byte.
			// Copy all bytes that belong to that character and forward currend_index by that amount of bytes
			int utf8_character_length = ws_utf8_char_len(current_character);

			if (utf8_character_length <= 0)
			{
				break;
			}

			for (int i = 0; i < utf8_character_length; i++)
			{
				// Do not overflow input string
				if (!(read_index < string_length))
				{
					break;
				}

				current_character = string[read_index];
				read_index++;
				wmem_strbuf_append_c(output_string_buffer, current_character);
			}
		}
		// character that IS escaped
		else
		{
			read_index++;

			// Do not overflow input string
			if (!(read_index < string_length))
			{
				break;
			}

			current_character = string[read_index];

			if (current_character == '\"' || current_character == '\\' || current_character == '/')
			{
				read_index++;
				wmem_strbuf_append_c(output_string_buffer, current_character);
			}
			else if (current_character == 'b')
			{
				read_index++;
				wmem_strbuf_append_c(output_string_buffer, '\b');
			}
			else if (current_character == 'f')
			{
				read_index++;
				wmem_strbuf_append_c(output_string_buffer, '\f');
			}
			else if (current_character == 'n')
			{
				read_index++;
				wmem_strbuf_append_c(output_string_buffer, '\n');
			}
			else if (current_character == 'r')
			{
				read_index++;
				wmem_strbuf_append_c(output_string_buffer, '\r');
			}
			else if (current_character == 't')
			{
				read_index++;
				wmem_strbuf_append_c(output_string_buffer, '\t');
			}
			else if (current_character == 'u')
			{
				read_index++;

				uint32_t code_point = 0;
				bool is_valid_unicode_character = true;

				for (int i = 0; i < 4; i++)
				{
					// Do not overflow input string
					if (!(read_index < string_length))
					{
						is_valid_unicode_character = false;
						break;
					}

					current_character = string[read_index];
					read_index++;

					int nibble = ws_xton(current_character);

					if(nibble < 0)
					{
						is_valid_unicode_character = false;
						break;
					}

					code_point <<= 4;
					code_point |= nibble;
				}

				if ((IS_LEAD_SURROGATE(code_point)))
				{
					// Do not overflow input string
					if (!(read_index < string_length))
					{
						break;
					}
					current_character = string[read_index];

					if (current_character == '\\')
					{
						read_index++;

						// Do not overflow input string
						if (!(read_index < string_length))
						{
							break;
						}

						current_character = string[read_index];
						if (current_character == 'u') {
							uint16_t lead_surrogate = code_point;
							uint16_t trail_surrogate = 0;

							read_index++;

							for (int i = 0; i < 4; i++)
							{
								// Do not overflow input string
								if (!(read_index < string_length))
								{
									is_valid_unicode_character = false;
									break;
								}

								current_character = string[read_index];
								read_index++;

								int nibble = ws_xton(current_character);

								if (nibble < 0)
								{
									is_valid_unicode_character = false;
									break;
								}

								trail_surrogate <<= 4;
								trail_surrogate |= nibble;
							}

							if ((IS_TRAIL_SURROGATE(trail_surrogate)))
							{
								code_point = SURROGATE_VALUE(lead_surrogate, trail_surrogate);
							}
							else
							{
								is_valid_unicode_character = false;
							}
						}
						else
						{
							read_index++;
							is_valid_unicode_character = false;
						}
					}
					else
					{
						read_index++;
						is_valid_unicode_character = false;
					}
				}
				else if ((IS_TRAIL_SURROGATE(code_point)))
				{
					is_valid_unicode_character = false;
				}

				if (is_valid_unicode_character)
				{
					if (g_unichar_validate(code_point) && g_unichar_isprint(code_point))
					{
						char length_test_buffer[6];
						int utf8_character_length = (int)g_unichar_to_utf8(code_point, length_test_buffer);

						for (int i = 0; i < utf8_character_length; i++)
						{
							current_character = length_test_buffer[i];
							wmem_strbuf_append_c(output_string_buffer, current_character);

						}
					}
				}
				else
				{
					wmem_strbuf_append_unichar_repl(output_string_buffer);
				}
			}
			else
			{
				/* not valid by JSON grammar (jsmn does not allow it) */
				DISSECTOR_ASSERT_NOT_REACHED();
			}
		}
	}

	if (length_ptr)
		*length_ptr = wmem_strbuf_get_len(output_string_buffer);

	return wmem_strbuf_finalize(output_string_buffer);
}

/* This functions allocates memory with packet_scope but the returned pointer
 * cannot be freed. */
static const char*
get_json_string(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int len, bool remove_quotes)
{
	char *string;
	size_t length;

	string = (char*)tvb_get_string_enc(scope, tvb, offset, len, ENC_UTF_8);

	if (unescape_strings) {
		string = json_string_unescape(scope, string, &length);
	}
	else {
		length = strlen(string);
	}

	if (remove_quotes) {
		if (string[length - 1] == '"') {
			string[length - 1] = '\0';
		}
		if (string[0] == '"') {
			string += 1;
		}
	}

	return string;
}

GHashTable* json_header_fields_hash;

/* The decoder registered for key_str in json_header_fields_hash, or NULL if
 * there is none or its protocol is disabled.
 */
static json_data_decoder_t*
json_key_decoder(const char* key_str)
{
	json_data_decoder_t* json_data_decoder_rec = (json_data_decoder_t*)g_hash_table_lookup(json_header_fields_hash, key_str);
	int hf_id;

	if (json_data_decoder_rec == NULL) {
		return NULL;
	}

	hf_id = *json_data_decoder_rec->hf_id;
	DISSECTOR_ASSERT(hf_id > 0);

	int proto_id = proto_registrar_is_protocol(hf_id) ? hf_id : proto_registrar_get_parent(hf_id);
	if (!proto_is_protocol_enabled(find_protocol_by_id(proto_id))) {
		return NULL;
	}
	return json_data_decoder_rec;
}

/* Add the field registered for key_str for value and call the registered
 * decoder, if any, on it.
 */
static proto_item*
json_key_add_value(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, const char* key_str,
		const json_data_decoder_t* json_data_decoder_rec, const json_elem_t* value)
{
	proto_item* ti;
	int offset = value->offset;
	int len = value->len;

	/* Remove the quotation marks from strings (the decoder functions
	 * apparently expect that.)
	 */
	if (value->type == JSON_TOKEN_STRING && len >= 2) {
		offset += 1;
		len -= 2;
	}
	/* XXX - Every hf_id in packet-json_3gpp.c is a FT_STRING. Should other
	 * types be supported (perhaps verified against the JSON token type?)
	 * Should the encoding be ENC_UTF_8? Should the string be unescaped here?
	 */
	ti = proto_tree_add_item(tree, *json_data_decoder_rec->hf_id, tvb, offset, len, ENC_ASCII);
	if (json_data_decoder_rec->json_data_decoder) {
		(*json_data_decoder_rec->json_data_decoder)(tvb, tree, pinfo, offset, len, key_str);
	}
	return ti;
}

/* If key_str is registered in json_header_fields_hash, add the registered
 * field for value (if not NULL) and call the registered decoder, if any, on
 * it. Returns the item added, or NULL if nothing was added.
 */
static proto_item*
json_key_lookup(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, const char* key_str,
		const json_elem_t* value)
{
	json_data_decoder_t* json_data_decoder_rec = json_key_decoder(key_str);

	if (json_data_decoder_rec == NULL || value == NULL) {
		return NULL;
	}
	return json_key_add_value(tree, tvb, pinfo, key_str, json_data_decoder_rec, value);
}

/* Like json_key_lookup(), for each of the n_values values of an array.
 * Returns the last item added, or NULL if nothing was added.
 */
static proto_item*
json_key_lookup_array(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, const char* key_str,
		const json_elem_t* values, int n_values)
{
	json_data_decoder_t* json_data_decoder_rec = json_key_decoder(key_str);
	proto_item* ti = NULL;

	if (json_data_decoder_rec == NULL) {
		return NULL;
	}
	for (int i = 0; i < n_values; i++) {
		ti = json_key_add_value(tree, tvb, pinfo, key_str, json_data_decoder_rec, &values[i]);
	}
	return ti;
}

static char*
join_strings(wmem_allocator_t *pool, const char* string_a, const char* string_b, char separator)
{
	if (string_a == NULL)
	{
		return NULL;
	}
	if (string_b == NULL)
	{
		return NULL;
	}

	wmem_strbuf_t* output_string_buffer = wmem_strbuf_new(pool, string_a);

	if (separator != '\0')
	{
		wmem_strbuf_append_c(output_string_buffer, separator);
	}

	wmem_strbuf_append(output_string_buffer, string_b);

	char* output_string = wmem_strbuf_finalize(output_string_buffer);
	return output_string;
}

/*
 * Tokenizing
 */

/* Tokenize the JSON text buf[0, len) with jsmn into a token array allocated
 * from scope, growing the array as needed.
 *
 * jsmn in strict mode rejects NaN. If allow_nan is set, a value starting
 * with 'N' is accepted as a primitive anyway and *has_nan (if not NULL) is
 * set; json_literal_type() checks the text later.
 *
 * Returns the jsmn result: >= 0 on success, or an enum jsmnerr with
 * *error_offset set to where jsmn stopped. The tokens filled before an error
 * are valid. buf is modified during the call but restored before returning.
 */
static int
json_tokenize(wmem_allocator_t *scope, char *buf, int len, bool allow_nan,
		jsmntok_t **tokens_out, int *num_tokens_out, int *error_offset, bool *has_nan)
{
	jsmn_parser parser;
	unsigned max_tokens = (unsigned)len / 8 + 16;
	jsmntok_t *tokens = wmem_alloc_array(scope, jsmntok_t, max_tokens);
	wmem_array_t *nan_offsets = NULL;
	int rc;

	jsmn_init(&parser);
	for (;;) {
		rc = jsmn_parse(&parser, buf, (size_t)len, tokens, max_tokens);
		if (rc == JSMN_ERROR_NOMEM) {
			/* Every token starts at a different byte, so jsmn never
			 * needs more than len tokens. */
			if (max_tokens >= (unsigned)len)
				break;
			/* jsmn resumes where it stopped once given more tokens. */
			max_tokens = MIN(max_tokens * 2, (unsigned)len);
			tokens = (jsmntok_t *)wmem_realloc(scope, tokens, (size_t)max_tokens * sizeof(jsmntok_t));
			continue;
		}
		if (rc == JSMN_ERROR_INVAL && allow_nan &&
		    parser.pos < (unsigned)len && buf[parser.pos] == 'N') {
			/* jsmn stopped at the 'N' without changing its state.
			 * Make the value start like "null" and resume. */
			if (!nan_offsets)
				nan_offsets = wmem_array_new(scope, sizeof(unsigned));
			wmem_array_append_one(nan_offsets, parser.pos);
			buf[parser.pos] = 'n';
			continue;
		}
		break;
	}

	if (nan_offsets) {
		unsigned *offsets = (unsigned *)wmem_array_get_raw(nan_offsets);
		for (unsigned i = 0; i < wmem_array_get_count(nan_offsets); i++) {
			buf[offsets[i]] = 'N';
		}
		if (has_nan)
			*has_nan = true;
	}

	*tokens_out = tokens;
	*num_tokens_out = (int)parser.toknext;
	*error_offset = rc < 0 ? (int)parser.pos : len;
	return rc;
}

/*
 * Tree building, called by the walker below in document order
 */

static void
json_begin_object(json_parser_data_t *data, const json_elem_t *obj)
{
	tvbuff_t *tvb = data->tvb;
	proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
	proto_tree *subtree;
	proto_item *ti;

	ti = proto_tree_add_item(tree, hf_json_object, tvb, obj->offset, obj->len, ENC_UTF_8);
	if (json_hide_original_tree() && wmem_stack_count(data->stack) == 1) {
		proto_item_set_hidden(ti);
	}

	subtree = proto_item_add_subtree(ti, ett_json_object);
	wmem_stack_push(data->stack, subtree);

	if (json_compact) {
		proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);
		proto_tree *subtree_compact;
		proto_item *ti_compact;

		int idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));

		if (JSON_INSIDE_ARRAY(idx)) {
			ti_compact = proto_tree_add_none_format(tree_compact, hf_json_object_compact, tvb, obj->offset, obj->len, "%d:", idx);
			subtree_compact = proto_item_add_subtree(ti_compact, ett_json_object_compact);
			json_array_index_increment(data);
		} else {
			subtree_compact = tree_compact;
		}
		wmem_stack_push(data->stack_compact, subtree_compact);

		JSON_OBJECT_BEGIN(data);
	}

	if (json_raw) {
		proto_tree* tree_raw = (proto_tree*)wmem_stack_peek(data->stack_raw);
		proto_tree* subtree_raw;
		proto_item* ti_raw;

		if (data->prev_item_raw && data->prev_item_type_raw == JSON_MARK_TYPE_END_OBJECT) {
			proto_item_append_text(data->prev_item_raw, ",");
		}

		if (data->prev_item_type_raw == JSON_MARK_TYPE_MEMBER_NAME) {
			/* this is an object value of an member, add the "{" just after the member name */
			ti_raw = data->prev_item_raw;
			proto_item_append_text(ti_raw, " {");
		} else {
			/* this object is either the top object or an element of an array, add the "{" as a single item */
			ti_raw = proto_tree_add_none_format(tree_raw, hf_json_object_raw, tvb, obj->offset, obj->len, "{");
		}

		subtree_raw = proto_item_add_subtree(ti_raw, ett_json_object_raw);
		wmem_stack_push(data->stack_raw, subtree_raw);

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_BEGIN_OBJECT;
	}
}

static void
json_end_object(json_parser_data_t *data, const json_elem_t *obj)
{
	wmem_stack_pop(data->stack);

	if (json_compact) {
		proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);
		proto_item *parent_item = proto_tree_get_parent(tree_compact);

		int idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));

		if (JSON_OBJECT_SET_HAS_KEY(idx))
			proto_item_append_text(parent_item, " {...}");
		else
			proto_item_append_text(parent_item, " {}");

		wmem_stack_pop(data->stack_compact);

		JSON_ARRAY_OBJECT_END(data);
	}

	if (json_raw) {
		proto_tree* tree_raw = (proto_tree*)wmem_stack_peek(data->stack_raw);
		proto_tree* parent_tree = proto_tree_get_parent_tree(tree_raw);
		proto_item* ti_raw = NULL;
		if (data->prev_item_type_raw == JSON_MARK_TYPE_BEGIN_OBJECT) { /* an empty object */
			ti_raw = data->prev_item_raw;
			proto_item_append_text(ti_raw, "}");
		} else if (obj->close_offset >= 0) {
			ti_raw = proto_tree_add_none_format(parent_tree, hf_json_object_raw, data->tvb, obj->close_offset, 1, "}");
		}
		wmem_stack_pop(data->stack_raw);

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_END_OBJECT;
	}
}

/* value is NULL if the member has no (valid) value */
static void
json_begin_member(json_parser_data_t *data, const json_elem_t *key, const json_elem_t *value)
{
	tvbuff_t *tvb = data->tvb;
	proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
	proto_tree *subtree;
	proto_item *ti;
	int member_offset = key->offset;
	int member_len = value ? value->offset + value->len - key->offset : key->len;

	const char* key_string_without_quotation_marks = get_json_string(data->pinfo->pool, tvb, key->offset, key->len, true);

	ti = proto_tree_add_string(tree, hf_json_member, tvb, member_offset, member_len, key_string_without_quotation_marks);

	subtree = proto_item_add_subtree(ti, ett_json_member);
	wmem_stack_push(data->stack, subtree);

	// extended path based filtering
	char* last_key_string = (char*)wmem_stack_pop(data->stack_path);
	char* base_path = (char*)wmem_stack_pop(data->stack_path);
	wmem_stack_push(data->stack_path, base_path);
	wmem_stack_push(data->stack_path, last_key_string);

	char* path = join_strings(data->pinfo->pool, base_path, key_string_without_quotation_marks, '/');
	wmem_stack_push(data->stack_path, path);
	/* stack won't write/free pointer. */
	wmem_stack_push(data->stack_path, (void *)key_string_without_quotation_marks);

	if (json_compact) {
		proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);
		proto_tree *subtree_compact;
		proto_item *ti_compact;

		ti_compact = json_key_lookup(tree_compact, tvb, data->pinfo, key_string_without_quotation_marks, value);
		if (!ti_compact) {
			ti_compact = proto_tree_add_none_format(tree_compact, hf_json_member_compact, tvb, member_offset, member_len, "\"%s\":", key_string_without_quotation_marks);
		}

		subtree_compact = proto_item_add_subtree(ti_compact, ett_json_member_compact);
		wmem_stack_push(data->stack_compact, subtree_compact);
	}

	if (json_raw) {
		proto_tree* tree_raw = (proto_tree*)wmem_stack_peek(data->stack_raw);
		proto_tree* subtree_raw;
		proto_item* ti_raw;

		if (data->prev_item_raw && data->prev_item_type_raw != JSON_MARK_TYPE_BEGIN_OBJECT && data->prev_item_type_raw != JSON_MARK_TYPE_BEGIN_ARRAY) {
			proto_item_append_text(data->prev_item_raw, ",");
		}

		ti_raw = json_key_lookup(tree_raw, tvb, data->pinfo, key_string_without_quotation_marks, value);
		if (!ti_raw) {
			ti_raw = proto_tree_add_none_format(tree_raw, hf_json_member_raw, tvb, member_offset, member_len, "\"%s\":", key_string_without_quotation_marks);
		}

		subtree_raw = proto_item_add_subtree(ti_raw, ett_json_member_raw);
		wmem_stack_push(data->stack_raw, subtree_raw);

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_MEMBER_NAME;
	}
}

static void
json_end_member(json_parser_data_t *data, const json_elem_t *key, const json_elem_t *value)
{
	tvbuff_t *tvb = data->tvb;
	proto_tree *tree = (proto_tree *)wmem_stack_pop(data->stack);
	int member_offset = key->offset;
	int member_len = value ? value->offset + value->len - key->offset : key->len;

	if (tree) {
		const char* key_string_without_quotation_marks = get_json_string(data->pinfo->pool, tvb, key->offset, key->len, true);

		proto_tree_add_string(tree, hf_json_key, tvb, key->offset, key->len, key_string_without_quotation_marks);
	}

	// extended path based filtering
	wmem_stack_pop(data->stack_path); // Pop key
	char* path = (char*)wmem_stack_pop(data->stack_path);
	if (tree)
	{
		proto_item* path_item = proto_tree_add_string(tree, hf_json_path, tvb, member_offset, member_len, path);
		proto_item_set_generated(path_item);
		if (hide_extended_path_based_filtering)
		{
			proto_item_set_hidden(path_item);
		}
	}

	if (json_compact) {
		wmem_stack_pop(data->stack_compact);
		json_object_add_key(data);
	}

	if (json_raw) {
		wmem_stack_pop(data->stack_raw);
	}
}

static void json_tok_to_elem(const json_parser_data_t *data, int idx, json_elem_t *elem);
static int json_next_sibling(const json_parser_data_t *data, int idx);

/* idx is the token index of the array, for looking up its elements */
static void
json_begin_array(json_parser_data_t *data, const json_elem_t *arr, int idx)
{
	tvbuff_t *tvb = data->tvb;
	proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
	proto_tree *subtree;
	proto_item *ti;

	ti = proto_tree_add_item(tree, hf_json_array, tvb, arr->offset, arr->len, ENC_NA);
	if (json_hide_original_tree() && wmem_stack_count(data->stack) == 1) {
		proto_item_set_hidden(ti);
	}

	subtree = proto_item_add_subtree(ti, ett_json_array);
	wmem_stack_push(data->stack, subtree);

	// extended path based filtering
	char* last_key_string = (char*)wmem_stack_pop(data->stack_path);
	char* base_path = (char*)wmem_stack_pop(data->stack_path);
	wmem_stack_push(data->stack_path, base_path);
	wmem_stack_push(data->stack_path, last_key_string);

	char* path = join_strings(data->pinfo->pool, base_path, "[]", '/');

	wmem_stack_push(data->stack_path, path);
	wmem_stack_push(data->stack_path, "[]");

	// Try key_lookup on each element of the array
	if (g_hash_table_contains(json_header_fields_hash, last_key_string)) {
		const jsmntok_t *tok = &data->tokens[idx];
		json_elem_t *items = wmem_alloc_array(data->pinfo->pool, json_elem_t, tok->size);
		int n_items = 0;

		for (int child = idx + 1; n_items < tok->size && child < data->num_tokens; n_items++) {
			json_tok_to_elem(data, child, &items[n_items]);
			child = json_next_sibling(data, child);
		}
		json_key_lookup_array(tree, tvb, data->pinfo, last_key_string, items, n_items);
	}

	if (json_compact) {
		proto_tree* tree_compact = (proto_tree*)wmem_stack_peek(data->stack_compact);
		proto_tree* subtree_compact;
		proto_item* ti_compact;

		int array_idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));

		if (JSON_INSIDE_ARRAY(array_idx)) {
			ti_compact = proto_tree_add_none_format(tree_compact, hf_json_array_compact, tvb, arr->offset, arr->len, "%d:", array_idx);
			subtree_compact = proto_item_add_subtree(ti_compact, ett_json_array_compact);
			json_array_index_increment(data);
		} else {
			subtree_compact = tree_compact;
		}
		wmem_stack_push(data->stack_compact, subtree_compact);

		JSON_ARRAY_BEGIN(data);
	}

	if (json_raw) {
		proto_tree* tree_raw = (proto_tree*)wmem_stack_peek(data->stack_raw);
		proto_tree* subtree_raw;
		proto_item* ti_raw;

		if (data->prev_item_raw && data->prev_item_type_raw == JSON_MARK_TYPE_END_ARRAY) {
			proto_item_append_text(data->prev_item_raw, ",");
		}

		if (data->prev_item_type_raw == JSON_MARK_TYPE_MEMBER_NAME) {
			/* this is an array value of an member, add the "[" just after the member name */
			ti_raw = data->prev_item_raw;
			proto_item_append_text(ti_raw, " [");
		} else {
			/* this array is either the top element or an element of an array, add the "[" as a single item */
			ti_raw = proto_tree_add_none_format(tree_raw, hf_json_array_raw, tvb, arr->offset, arr->len, "[");
		}

		subtree_raw = proto_item_add_subtree(ti_raw, ett_json_array_raw);
		wmem_stack_push(data->stack_raw, subtree_raw);

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_BEGIN_ARRAY;
	}
}

static void
json_end_array(json_parser_data_t *data, const json_elem_t *arr)
{
	wmem_stack_pop(data->stack);

	// extended path based filtering
	wmem_stack_pop(data->stack_path); // Pop key
	wmem_stack_pop(data->stack_path); // Pop path

	if (json_compact) {
		proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);
		proto_item *parent_item = proto_tree_get_parent(tree_compact);

		int idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));
		if (idx == 0)
			proto_item_append_text(parent_item, " []");
		else
			proto_item_append_text(parent_item, " [...]");

		wmem_stack_pop(data->stack_compact);

		JSON_ARRAY_OBJECT_END(data);
	}

	if (json_raw) {
		proto_tree* tree_raw = (proto_tree*)wmem_stack_peek(data->stack_raw);
		proto_tree* parent_tree = proto_tree_get_parent_tree(tree_raw);
		proto_item* ti_raw = NULL;
		if (data->prev_item_type_raw == JSON_MARK_TYPE_BEGIN_ARRAY) { /* an empty array */
			ti_raw = data->prev_item_raw;
			proto_item_append_text(ti_raw, "]");
		} else if (arr->close_offset >= 0) {
			ti_raw = proto_tree_add_none_format(parent_tree, hf_json_array_raw, data->tvb, arr->close_offset, 1, "]");
		}
		wmem_stack_pop(data->stack_raw);

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_END_ARRAY;
	}
}

/* A string, number, true, false, null or NaN */
static void
json_value(json_parser_data_t *data, const json_elem_t *val)
{
	tvbuff_t *tvb = data->tvb;
	proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
	json_token_type_t value_id = val->type;

	// extended path based filtering
	char* key_string = (char*)wmem_stack_pop(data->stack_path);
	char* path = (char*)wmem_stack_pop(data->stack_path);

	/* Strings (always with their quotation marks here) without the quotation marks */
	const char* value_str = get_json_string(data->pinfo->pool, tvb, val->offset, val->len,
		value_id == JSON_TOKEN_STRING);

	char* path_with_value = join_strings(data->pinfo->pool, path, value_str, ':');
	char* memeber_with_value = join_strings(data->pinfo->pool, key_string, value_str, ':');
	proto_item* path_with_value_item = proto_tree_add_string(tree, hf_json_path_with_value, tvb, val->offset, val->len, path_with_value);
	proto_item* member_with_value_item = proto_tree_add_string(tree, hf_json_member_with_value, tvb, val->offset, val->len, memeber_with_value);

	proto_item_set_generated(path_with_value_item);
	proto_item_set_generated(member_with_value_item);

	if (hide_extended_path_based_filtering)
	{
		proto_item_set_hidden(path_with_value_item);
		proto_item_set_hidden(member_with_value_item);
	}

	wmem_stack_push(data->stack_path, path);
	wmem_stack_push(data->stack_path, key_string);

	switch (value_id) {
		case JSON_TOKEN_STRING: {
			// Try key_lookup
			proto_item *key_lookup = json_key_lookup(tree, tvb, data->pinfo, key_string, val);
			if (!key_lookup) {
				proto_tree_add_string(tree, hf_json_value_string, tvb, val->offset, val->len, value_str);
			}

			break;
		}

		case JSON_TOKEN_NUMBER:
			proto_tree_add_double(tree, hf_json_value_number, tvb, val->offset, val->len, g_ascii_strtod(value_str, NULL));

			break;

		case JSON_TOKEN_FALSE:
			proto_tree_add_item(tree, hf_json_value_false, tvb, val->offset, val->len, ENC_NA);

			break;

		case JSON_TOKEN_NULL:
			proto_tree_add_item(tree, hf_json_value_null, tvb, val->offset, val->len, ENC_NA);

			break;

		case JSON_TOKEN_TRUE:
			proto_tree_add_item(tree, hf_json_value_true, tvb, val->offset, val->len, ENC_NA);

			break;

		case JSON_TOKEN_NAN:
			proto_tree_add_item(tree, hf_json_value_nan, tvb, val->offset, val->len, ENC_NA);

			break;

		default:
			proto_tree_add_format_text(tree, tvb, val->offset, val->len);
			break;
	}

	if (json_compact) {
		proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);

		int idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));

		char *val_str = (char*)tvb_get_string_enc(data->pinfo->pool, tvb, val->offset, val->len, ENC_UTF_8);

		if (JSON_INSIDE_ARRAY(idx)) {
			proto_tree_add_none_format(tree_compact, hf_json_array_item_compact, tvb, val->offset, val->len, "%d: %s", idx, val_str);
			json_array_index_increment(data);
		} else {
			proto_item *parent_item = proto_tree_get_parent(tree_compact);
			proto_item_append_text(parent_item, " %s", val_str);
		}
	}

	if (json_raw) {
		proto_tree* tree_raw = (proto_tree*)wmem_stack_peek(data->stack_raw);
		proto_item* ti_raw;
		char* val_str = (char*)tvb_get_string_enc(data->pinfo->pool, tvb, val->offset, val->len, ENC_UTF_8);

		if (data->prev_item_raw && data->prev_item_type_raw == JSON_MARK_TYPE_VALUE) {
			proto_item_append_text(data->prev_item_raw, ","); /* this value is an element of an array */
		}

		if (data->prev_item_raw && data->prev_item_type_raw == JSON_MARK_TYPE_MEMBER_NAME) {
			ti_raw = proto_tree_get_parent(tree_raw);
			proto_item_append_text(ti_raw, " %s", val_str);
		} else {
			ti_raw = proto_tree_add_none_format(tree_raw, hf_json_array_item_raw, tvb, val->offset, val->len, "%s", val_str);
		}

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_VALUE;
	}
}

/*
 * Walking the tokens
 *
 * jsmn does not check everything the JSON grammar (RFC 8259) requires: it
 * takes any run of printable characters starting with '-', a digit, 't',
 * 'f' or 'n' as a primitive, and it does not check the ',' and ':'
 * separators. The walker checks both, and stops at the first error.
 */

static bool
json_is_ws(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int
json_skip_ws(const json_parser_data_t *data, int pos)
{
	while (pos < data->buf_len && json_is_ws(data->buf[pos]))
		pos++;
	return pos;
}

/* Start of token idx in buf, including the opening quotation mark of a string */
static int
json_tok_start(const json_parser_data_t *data, int idx)
{
	const jsmntok_t *tok = &data->tokens[idx];
	return tok->type == JSMN_STRING ? tok->start - 1 : tok->start;
}

/* End (exclusive) of token idx in buf, including the closing quotation mark
 * of a string; -1 for an object or array that is not closed */
static int
json_tok_end(const json_parser_data_t *data, int idx)
{
	const jsmntok_t *tok = &data->tokens[idx];
	return tok->type == JSMN_STRING ? tok->end + 1 : tok->end;
}

/* Token index after the subtree of token idx */
static int
json_next_sibling(const json_parser_data_t *data, int idx)
{
	for (int remaining = 1; remaining > 0 && idx < data->num_tokens; idx++) {
		remaining += data->tokens[idx].size - 1;
	}
	return idx;
}

/* Type of the primitive text s[0, len): true, false, null, NaN or a number
 * as in RFC 8259 section 6. */
static json_token_type_t
json_literal_type(const char *s, int len)
{
	int pos = 0;
	int digits;

	if (len == 4 && memcmp(s, "true", 4) == 0)
		return JSON_TOKEN_TRUE;
	if (len == 5 && memcmp(s, "false", 5) == 0)
		return JSON_TOKEN_FALSE;
	if (len == 4 && memcmp(s, "null", 4) == 0)
		return JSON_TOKEN_NULL;
	if (len == 3 && memcmp(s, "NaN", 3) == 0)
		return JSON_TOKEN_NAN;

	/* number = [ minus ] int [ frac ] [ exp ] */
	if (pos < len && s[pos] == '-')
		pos++;
	/* int = zero / ( digit1-9 *DIGIT ) */
	if (pos < len && s[pos] == '0') {
		pos++;
	} else if (pos < len && s[pos] >= '1' && s[pos] <= '9') {
		while (pos < len && g_ascii_isdigit(s[pos]))
			pos++;
	} else {
		return JSON_TOKEN_INVALID;
	}
	/* frac = decimal-point 1*DIGIT */
	if (pos < len && s[pos] == '.') {
		pos++;
		for (digits = 0; pos < len && g_ascii_isdigit(s[pos]); digits++)
			pos++;
		if (digits == 0)
			return JSON_TOKEN_INVALID;
	}
	/* exp = e [ minus / plus ] 1*DIGIT */
	if (pos < len && (s[pos] == 'e' || s[pos] == 'E')) {
		pos++;
		if (pos < len && (s[pos] == '-' || s[pos] == '+'))
			pos++;
		for (digits = 0; pos < len && g_ascii_isdigit(s[pos]); digits++)
			pos++;
		if (digits == 0)
			return JSON_TOKEN_INVALID;
	}
	return pos == len ? JSON_TOKEN_NUMBER : JSON_TOKEN_INVALID;
}

static void
json_tok_to_elem(const json_parser_data_t *data, int idx, json_elem_t *elem)
{
	const jsmntok_t *tok = &data->tokens[idx];
	int start = json_tok_start(data, idx);
	int end = json_tok_end(data, idx);

	elem->close_offset = -1;
	switch (tok->type) {
	case JSMN_OBJECT:
	case JSMN_ARRAY:
		elem->type = tok->type == JSMN_OBJECT ? JSON_OBJECT : JSON_ARRAY;
		if (end > start) {
			elem->close_offset = data->base_offset + end - 1;
		} else {
			/* Not closed: cover what jsmn got through */
			end = MAX(data->parse_error_offset, start + 1);
		}
		break;
	case JSMN_STRING:
		elem->type = JSON_TOKEN_STRING;
		break;
	default:
		elem->type = json_literal_type(data->buf + start, end - start);
		break;
	}
	elem->offset = data->base_offset + start;
	elem->len = end - start;
}

/* Record the first error found */
static void
json_set_error(json_parser_data_t *data, int pos, const char *msg)
{
	if (data->error_offset < 0) {
		data->error_offset = pos;
		data->error_msg = msg;
	}
}

/* Record the error that made jsmn stop */
static void
json_set_parse_error(json_parser_data_t *data)
{
	int pos = data->parse_error_offset;

	if (data->parse_result == JSMN_ERROR_PART) {
		/* jsmn stops at a NUL as if the data ended there */
		const char *nul = (const char *)memchr(data->buf + pos, '\0', data->buf_len - pos);

		if (nul)
			json_set_error(data, (int)(nul - data->buf), "unexpected NUL character");
		else
			json_set_error(data, pos, "unexpected end of data");
	} else {
		json_set_error(data, pos, "unexpected character");
	}
}

/* Check that buf[from, to) holds whitespace around exactly one sep, or only
 * whitespace if sep is '\0' */
static bool
json_check_gap(json_parser_data_t *data, int from, int to, char sep)
{
	bool seen = (sep == '\0');

	for (int pos = from; pos < to; pos++) {
		char c = data->buf[pos];

		if (json_is_ws(c))
			continue;
		if (!seen && c == sep) {
			seen = true;
			continue;
		}
		json_set_error(data, pos, "unexpected character");
		return false;
	}
	if (!seen) {
		json_set_error(data, to, sep == ',' ? "expected ','" : "expected ':'");
		return false;
	}
	return true;
}

static int json_walk_value(json_parser_data_t *data, int idx, unsigned depth);

/* Returns the token index after the object, or -1 on error */
static int
// NOLINTNEXTLINE(misc-no-recursion)
json_walk_object(json_parser_data_t *data, int idx, unsigned depth)
{
	const jsmntok_t *tok = &data->tokens[idx];
	json_elem_t obj;
	int cursor = tok->start + 1;	/* end of the last member */
	int next = idx + 1;
	bool ok = true;

	json_tok_to_elem(data, idx, &obj);
	json_begin_object(data, &obj);

	for (int k = 0; k < tok->size; k++) {
		int key_idx = next;
		int value_idx = key_idx + 1;
		const jsmntok_t *key_tok;
		json_elem_t key, value;

		/* jsmn counts a child only once its token is filled */
		if (key_idx >= data->num_tokens) {
			json_set_parse_error(data);
			ok = false;
			break;
		}
		key_tok = &data->tokens[key_idx];
		if (!json_check_gap(data, cursor, json_tok_start(data, key_idx), k == 0 ? '\0' : ',')) {
			ok = false;
			break;
		}
		if (key_tok->type != JSMN_STRING) {
			json_set_error(data, json_tok_start(data, key_idx), "expected string");
			ok = false;
			break;
		}
		json_tok_to_elem(data, key_idx, &key);

		if (key_tok->size == 0 ||
		    !json_check_gap(data, json_tok_end(data, key_idx), json_tok_start(data, value_idx), ':')) {
			/* No value; show the key anyway */
			json_begin_member(data, &key, NULL);
			json_end_member(data, &key, NULL);
			if (key_tok->size == 0) {
				int pos = json_skip_ws(data, json_tok_end(data, key_idx));

				if (data->parse_result < 0 && value_idx >= data->num_tokens)
					json_set_parse_error(data);
				else if (pos < data->buf_len && data->buf[pos] == ':')
					json_set_error(data, json_skip_ws(data, pos + 1), "expected value");
				else
					json_set_error(data, pos, "expected ':'");
			}
			ok = false;
			break;
		}

		json_tok_to_elem(data, value_idx, &value);
		json_begin_member(data, &key, &value);
		next = json_walk_value(data, value_idx, depth);
		json_end_member(data, &key, &value);
		if (next < 0) {
			ok = false;
			break;
		}
		if (key_tok->size > 1) {
			/* More than one value after the ':' */
			json_set_error(data, json_tok_start(data, next), "expected ','");
			ok = false;
			break;
		}
		cursor = json_tok_end(data, value_idx);
	}

	if (ok) {
		if (tok->end < 0) {
			json_set_parse_error(data);
			ok = false;
		} else {
			/* Nothing but whitespace before the '}' */
			ok = json_check_gap(data, cursor, tok->end - 1, '\0');
		}
	}

	json_end_object(data, &obj);
	return ok ? next : -1;
}

/* Returns the token index after the array, or -1 on error */
static int
// NOLINTNEXTLINE(misc-no-recursion)
json_walk_array(json_parser_data_t *data, int idx, unsigned depth)
{
	const jsmntok_t *tok = &data->tokens[idx];
	json_elem_t arr;
	int cursor = tok->start + 1;	/* end of the last element */
	int next = idx + 1;
	bool ok = true;

	json_tok_to_elem(data, idx, &arr);
	json_begin_array(data, &arr, idx);

	for (int k = 0; k < tok->size; k++) {
		int item_idx = next;

		if (item_idx >= data->num_tokens) {
			json_set_parse_error(data);
			ok = false;
			break;
		}
		if (!json_check_gap(data, cursor, json_tok_start(data, item_idx), k == 0 ? '\0' : ',')) {
			ok = false;
			break;
		}
		next = json_walk_value(data, item_idx, depth);
		if (next < 0) {
			ok = false;
			break;
		}
		cursor = json_tok_end(data, item_idx);
	}

	if (ok) {
		if (tok->end < 0) {
			json_set_parse_error(data);
			ok = false;
		} else {
			/* Nothing but whitespace before the ']' */
			ok = json_check_gap(data, cursor, tok->end - 1, '\0');
		}
	}

	json_end_array(data, &arr);
	return ok ? next : -1;
}

/* Dissect the value at token idx. Returns the token index after it, or -1
 * on error.
 *
 * Objects and arrays nested deeper than a quarter of the maximum tree depth
 * are reported as malformed instead of dissected: each object adds two
 * levels to the tree (the object and its member), and the protocols that
 * carry the JSON need some more. This also bounds the recursion. */
static int
// NOLINTNEXTLINE(misc-no-recursion)
json_walk_value(json_parser_data_t *data, int idx, unsigned depth)
{
	const jsmntok_t *tok = &data->tokens[idx];
	json_elem_t val;

	if (tok->type == JSMN_OBJECT || tok->type == JSMN_ARRAY) {
		if (depth >= prefs.gui_max_tree_depth / 4) {
			json_set_error(data, tok->start, "nested too deeply");
			return -1;
		}
		if (tok->type == JSMN_OBJECT)
			return json_walk_object(data, idx, depth + 1);
		return json_walk_array(data, idx, depth + 1);
	}

	json_tok_to_elem(data, idx, &val);
	if (val.type == JSON_TOKEN_INVALID) {
		json_set_error(data, json_tok_start(data, idx), "invalid value");
		return -1;
	}
	json_value(data, &val);
	if (tok->size != 0) {
		/* jsmn took a ':' after this value as a member separator */
		json_set_error(data, json_skip_ws(data, json_tok_end(data, idx)), "unexpected character");
		return -1;
	}
	return idx + 1;
}

/* Dissect the objects and arrays at the start of the JSON text, one after
 * the other. Returns how much of the text was dissected, including
 * whitespace after the last value; on error, up to where the error is. */
static int
json_dissect_tokens(json_parser_data_t *data)
{
	int consumed = 0;
	int idx = 0;

	while (idx < data->num_tokens) {
		const jsmntok_t *tok = &data->tokens[idx];

		if ((tok->type != JSMN_OBJECT && tok->type != JSMN_ARRAY) ||
		    tok->start != json_skip_ws(data, consumed))
			break;

		idx = json_walk_value(data, idx, 0);
		if (idx < 0)
			return MIN(data->error_offset, data->buf_len);

		consumed = json_skip_ws(data, tok->end);
	}
	return consumed;
}

static int
dissect_json(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	if (falco_json_handle) {
		int falco_len = call_dissector_only(falco_json_handle, tvb, pinfo, tree, NULL);
		if (falco_len > 0) {
			return falco_len;
		}
	}

	proto_tree *json_tree = NULL;
	proto_item *ti = NULL;

	json_parser_data_t parser_data;

	media_content_info_t *content_info;
	const char *data_name;
	int offset;

	/* Save pinfo*/
	parser_data.pinfo = pinfo;
	/* JSON dissector can be called in a JSON native file or when transported
	 * by another protocol; for a JSON file, this dissector is called by the
	 * frame dissector, which only sets COL_PROTOCOL and COL_INFO if the
	 * dissector it calls fails, so this will make the entry in the Protocol
	 * column accordingly.
	 */

	/* Reset per-packet: stale globals from a prior frame must not leak through.
	 * When protocols are defined, default to inactive until a match is found. */
	jsonplus_dict_active = !json_plus_dictionary.has_any_protocol;
	jsonplus_current_protocol = NULL;

	// Check if JSON+ mode is enabled with a custom protocol name
	if (json_plus && json_plus_dictionary.protocols) {
		json_protocol_t *protocol = NULL;

		/* Path-based match first - more specific than port. We pull the URI
		 * from whichever HTTP version is carrying this JSON:
		 *   - HTTP/2: :path pseudo-header (http2_get_header_value).
		 *   - HTTP/1.1: request_uri from the HTTP req/res tracker via
		 *     p_get_proto_data. Same pattern as packet-grpc.c.
		 * In raw TCP/UDP JSON contexts both lookups return NULL and we fall
		 * through to the port lookup. */
		/* Fetch the URI once - used by both path-matching loop and the AND
		 * cross-check when port matches first.
		 *
		 * IMPORTANT: gate http2_get_header_value() on the frame actually
		 * having http2 in its layer stack. The function calls
		 * find_or_create_conversation() + get_http2_session() internally,
		 * which CREATES an HTTP/2 session on the conversation as a side
		 * effect. Calling it unconditionally would tag plain HTTP/1.1
		 * (or other non-HTTP/2) traffic as HTTP/2 from then on. */
		const char *uri = NULL;
		if (proto_is_frame_protocol(pinfo->layers, "http2")) {
			uri = http2_get_header_value(pinfo, HTTP2_HEADER_PATH, false);
		}
		if (!uri && proto_http != -1 &&
		    proto_is_frame_protocol(pinfo->layers, "http")) {
			http_req_res_t *rr = (http_req_res_t *)p_get_proto_data(
				wmem_file_scope(), pinfo, proto_http,
				HTTP_PROTO_DATA_REQRES);
			if (rr) uri = rr->request_uri;
		}

		if (uri && json_plus_dictionary.path_matchers) {
			/* Walk the full list and keep the LAST match, not the first.
			 * path_matchers is appended in load order, so the last entry
			 * to match is the one loaded most recently — personal
			 * dictionaries (loaded after system) and later entries in a
			 * single config.txt both win. Matches the "later loaded wins"
			 * rule used for ports (wmem_tree_insert32 overwrite) and
			 * fields (wmem_tree_insert_string overwrite). */
			for (GSList *m = json_plus_dictionary.path_matchers; m; m = m->next) {
				json_protocol_t *p = (json_protocol_t *)m->data;
				if (!p->path_regex || !ws_regex_matches(p->path_regex, uri))
					continue;
				/* condition="and" with both path and ports configured: the
				 * port must also match. Otherwise skip to the next path
				 * candidate. */
				if (p->require_all && p->port_list &&
				    !jsonplus_proto_port_matches(p, pinfo->destport) &&
				    !jsonplus_proto_port_matches(p, pinfo->srcport)) {
					continue;
				}
				protocol = p;
			}
		}

		/* Fall back to port lookup if no path match. */
		if (!protocol) {
			json_protocol_t *p = (json_protocol_t *)wmem_tree_lookup32(
				json_plus_dictionary.protocols, pinfo->destport);
			if (!p) {
				p = (json_protocol_t *)wmem_tree_lookup32(
					json_plus_dictionary.protocols, pinfo->srcport);
			}
			/* condition="and" with both path and ports: URI must also match
			 * this protocol's regex. */
			if (p && p->require_all && p->path_regex) {
				if (uri && ws_regex_matches(p->path_regex, uri))
					protocol = p;
			} else {
				protocol = p;
			}
		}

		if (protocol && protocol->display_name) {
			// Use custom protocol display name
			col_set_str(pinfo->cinfo, COL_PROTOCOL, protocol->display_name);
		} else {
			// Fallback to default
			col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "JSON");
		}

		/* Gate dictionary field parsing: if the dictionary defines any
		 * <protocol> entries and none matched, suppress dictionary lookups
		 * so the JSON tree renders as generic JSON instead of being parsed
		 * with the wrong dictionary. When no <protocol> entries exist,
		 * dictionary fields apply globally (backward compat). */
		jsonplus_dict_active =
			!json_plus_dictionary.has_any_protocol || (protocol != NULL);
		jsonplus_current_protocol = protocol;
	} else {
		col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "JSON");
		jsonplus_dict_active = true;
	}

	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "JSON");

	data_name = pinfo->match_string;
	if (! (data_name && data_name[0])) {
		/*
		 * No information from "match_string"
		 */
		content_info = (media_content_info_t *)data;
		if (content_info == NULL) {
			/*
			 * No information from dissector data
			 */
			data_name = NULL;
		} else {
			data_name = content_info->media_str;
			if (! (data_name && data_name[0])) {
				/*
				 * No information from dissector data
				 */
				data_name = NULL;
			}
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_json, tvb, 0, -1, ENC_NA);
		json_tree = proto_item_add_subtree(ti, ett_json);

		if (data_name)
			proto_item_append_text(ti, ": %s", data_name);
	}

	offset = 0;
	p_add_proto_data(pinfo->pool, pinfo, proto_json, 0, tvb);

	parser_data.stack = wmem_stack_new(pinfo->pool);
	wmem_stack_push(parser_data.stack, json_tree);

	// extended path based filtering
	parser_data.stack_path = wmem_stack_new(pinfo->pool);
	wmem_stack_push(parser_data.stack_path, "");
	wmem_stack_push(parser_data.stack_path, "");

	int buffer_length = (int)tvb_captured_length(tvb);
	if (ignore_leading_bytes)
	{
		while (offset < buffer_length)
		{
			uint8_t current_character = tvb_get_uint8(tvb, offset);
			if (current_character == '[' || current_character == '{')
			{
				break;
			}
			offset++;
		}

		if(offset > 0)
		{
			proto_tree_add_item(json_tree ? json_tree : tree, hf_json_ignored_leading_bytes, tvb, 0, offset, ENC_ASCII);
		}
	}

	if (json_compact) {
		proto_tree* json_tree_compact = json_hide_root_item() ? json_tree :
			proto_tree_add_subtree(json_tree, tvb, 0, -1, ett_json_compact, NULL, "JSON compact form:");

		parser_data.stack_compact = wmem_stack_new(pinfo->pool);
		wmem_stack_push(parser_data.stack_compact, json_tree_compact);

		parser_data.array_idx = wmem_stack_new(pinfo->pool);
		wmem_stack_push(parser_data.array_idx, GINT_TO_POINTER(JSON_COMPACT_TOP_ITEM)); /* top element */
	}

	if (json_raw) {
		proto_tree* json_tree_raw = json_hide_root_item() ? json_tree :
			proto_tree_add_subtree(json_tree, tvb, 0, -1, ett_json_raw, NULL, "JSON raw form:");

		parser_data.stack_raw = wmem_stack_new(pinfo->pool);
		wmem_stack_push(parser_data.stack_raw, json_tree_raw);

		parser_data.prev_item_raw = NULL;
		parser_data.prev_item_type_raw = JSON_MARK_TYPE_NONE;
	}

	/* Tokenize once, for the JSON+ form and for the other forms */
	int json_len = buffer_length - offset;
	char *json_buf = (char *)tvb_memdup(pinfo->pool, tvb, offset, json_len);
	bool has_nan = false;

	parser_data.tvb = tvb;
	parser_data.buf = json_buf;
	parser_data.buf_len = json_len;
	parser_data.base_offset = offset;
	parser_data.parse_result = json_tokenize(pinfo->pool, json_buf, json_len, true,
		&parser_data.tokens, &parser_data.num_tokens, &parser_data.parse_error_offset, &has_nan);
	parser_data.error_offset = -1;
	parser_data.error_msg = NULL;

	proto_tree* json_tree_plus = NULL;
	if (json_plus) {
		// JSON+ (dictionary-driven) dissection
		json_tree_plus = json_hide_root_item() ? json_tree :
			proto_tree_add_subtree(json_tree, tvb, 0, -1, ett_json_plus, NULL, "JSON+ form:");

		/* Add the protocol-presence boolean so the packet is filterable
		 * by json.<protocol-name> (e.g. json.nudm_sdm). Hidden so it
		 * doesn't clutter the tree display. */
		if (jsonplus_current_protocol &&
		    jsonplus_current_protocol->hf_proto_present != -1) {
			proto_item *pi = proto_tree_add_boolean(json_tree_plus,
				jsonplus_current_protocol->hf_proto_present,
				tvb, 0, 0, true);
			proto_item_set_hidden(pi);
		}
	}

	offset += json_dissect_tokens(&parser_data);

	if (parser_data.error_offset >= 0) {
		int error_offset = parser_data.error_offset;

		proto_tree_add_expert_format(json_tree, pinfo, &ei_json_malformed, tvb,
			parser_data.base_offset + error_offset, error_offset < json_len ? 1 : 0,
			"Malformed JSON: %s", parser_data.error_msg);
	}

	if (json_plus) {
		/* What json_validate() accepts, without its limit of 1024 tokens.
		 * jsmn also accepts e.g. a key without a value, which the JSON+
		 * functions do not expect; json_dissect_tokens() did not. */
		bool is_valid = json_len > 0 && json_buf[0] != '\0' &&
			parser_data.parse_result >= 0 && !has_nan &&
			parser_data.error_offset < 0;

		if (!is_valid) {
			proto_item *item = proto_tree_add_item(json_tree_plus, hf_json_binary_data,
				tvb, parser_data.base_offset, json_len, ENC_NA);
			proto_item_append_text(ti, " [Invalid JSON]");
			expert_add_info(pinfo, item, &ei_json_plus_invalid_json);
		} else if (parser_data.num_tokens > 0) {
			// Check if dictionary is loaded
			if (json_plus_dictionary.fields) {
				const char *path_parts[JSON_PLUS_MAX_PATH_DEPTH];
				jsonplus_display_json_tree_dict(tvb, json_tree_plus, pinfo, pinfo->pool, parser_data.tokens, 0, json_buf,
					path_parts, 0);
			} else {
				proto_tree_add_expert_format(json_tree_plus, pinfo, &ei_json_plus_parse_error,
					tvb, parser_data.base_offset, json_len,
					"JSON+ dictionary not loaded. Check resources/protocols/json/config.txt");
			}
		}
	}

	proto_item_set_len(ti, offset);

	/* if we have some unparsed data, pass to data-text-lines dissector (?) */
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		tvbuff_t *next_tvb;

		next_tvb = tvb_new_subset_remaining(tvb, offset);

		call_dissector_with_data(text_lines_handle, next_tvb, pinfo, tree, data);
	} else if (data_name) {
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(%s)", data_name);
	}

	return tvb_captured_length(tvb);
}

 // For dissecting JSON in a file; we don't get passed a media type.
static int
dissect_json_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	return dissect_json(tvb, pinfo, tree, NULL);
}

/* This function tries to understand if the payload is json or not */
static bool
dissect_json_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	int len = (int)tvb_captured_length(tvb);
	jsmntok_t *tokens;
	int num_tokens;
	int error_offset;

	/* An empty buffer or a leading NUL would make jsmn see an empty text */
	if (len == 0 || tvb_get_uint8(tvb, 0) == '\0')
		return false;

	char *buf = (char *)tvb_memdup(pinfo->pool, tvb, 0, len);
	if (json_tokenize(pinfo->pool, buf, len, false, &tokens, &num_tokens, &error_offset, NULL) < 0)
		return false;

	return (dissect_json(tvb, pinfo, tree, data) != 0);
}

/* This function tries to understand if the payload is sitting on top of AC DR */
static bool
dissect_json_acdr_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	unsigned acdr_prot = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_acdr, 0));
	if (acdr_prot == ACDR_VoiceAI)
		return dissect_json_heur(tvb, pinfo, tree, data);
	return false;
}

/*
 * JSON+ (Dictionary-Driven) Dissection Functions
 */

// Helper structure for case-insensitive field search
typedef struct {
	const char *search_path;
	json_field_t *found_field;
} case_insensitive_search_t;

/*
 Callback for wmem_tree_foreach to find case-insensitive match
 Only checks fields that explicitly requested case-insensitive matching
 */
static bool
jsonplus_case_insensitive_matcher(const void *key, void *value, void *userdata)
{
	const char *field_path = (const char *)key;
	json_field_t *field = (json_field_t *)value;
	case_insensitive_search_t *search = (case_insensitive_search_t *)userdata;

	// Only check fields that explicitly requested case-insensitive matching
	if (field->case_insensitive) {
		if (g_ascii_strcasecmp(field_path, search->search_path) == 0) {
			search->found_field = field;
			return true;
		}
	}

	return false;
}

/* Case-insensitive field search over an arbitrary wmem_tree.
 * Only called when an exact (case-sensitive) match fails and the tree is
 * known to contain at least one case_insensitive field. */
static json_field_t *
jsonplus_find_case_insensitive_field_in(wmem_tree_t *tree, const char *path)
{
	case_insensitive_search_t search_data;
	search_data.search_path = path;
	search_data.found_field = NULL;
	wmem_tree_foreach(tree, jsonplus_case_insensitive_matcher, &search_data);
	return search_data.found_field;
}

/* Look up a field by path.  When a specific protocol matched dispatch,
 * search that protocol's scoped field tree; otherwise fall back to the
 * global dict->fields (backward-compat / no-protocol mode). */
static json_field_t *
jsonplus_lookup_field_by_path(const char *path)
{
	if (!path || !jsonplus_dict_active)
		return NULL;

	wmem_tree_t *search_tree;
	bool has_ci;

	if (jsonplus_current_protocol && jsonplus_current_protocol->fields) {
		search_tree = jsonplus_current_protocol->fields;
		has_ci = jsonplus_current_protocol->has_case_insensitive_fields;
	} else {
		if (!json_plus_dictionary.fields) return NULL;
		search_tree = json_plus_dictionary.fields;
		has_ci = json_plus_dictionary.has_case_insensitive_fields;
	}

	json_field_t *field = (json_field_t *)wmem_tree_lookup_string(search_tree, path, 0);
	if (field) return field;

	if (has_ci)
		field = jsonplus_find_case_insensitive_field_in(search_tree, path);

	return field;
}

/* Returns true when path_parts[0] is a root-array element index like "[0]", "[12]", etc.
 * Used to detect that we're inside a root-level array so the bare-path fallback applies. */
static bool
jsonplus_path_has_root_array_prefix(const char **path_parts, int path_depth)
{
	if (path_depth < 1) return false;
	const char *p0 = path_parts[0];
	if (!p0 || p0[0] != '[') return false;
	const char *p = p0 + 1;
	while (*p >= '0' && *p <= '9') p++;
	return (*p == ']' && *(p + 1) == '\0');
}

/*
 * Normalize array indices in path for dictionary lookup
 * Converts "items[5]" to "items[]", "users[0].name" to "users[].name"
 * Returns: wmem-allocated normalized path
 */
static char *
jsonplus_normalize_array_path(wmem_allocator_t *pool, const char *path)
{
	wmem_strbuf_t *norm_buf;
	const char *p;
	bool in_bracket = false;

	if (!path) {
		return NULL;
	}

	norm_buf = wmem_strbuf_new(pool, "");

	for (p = path; *p != '\0'; p++) {
		if (*p == '[') {
			// Start of array index
			in_bracket = true;
			wmem_strbuf_append_c(norm_buf, '[');
		}
		else if (*p == ']') {
			// End of array index
			in_bracket = false;
			wmem_strbuf_append_c(norm_buf, ']');
		}
		else if (!in_bracket) {
			// Not inside brackets
			wmem_strbuf_append_c(norm_buf, *p);
		}
		// Inside brackets - skip digits to normalize to []
	}

	return wmem_strbuf_finalize(norm_buf);
}

/*
 * Build JSON path from current position
 * path_parts: array of path components (ie., ["user", "profile", "age"])
 * depth: number of components
 * Returns: wmem-allocated path string (ie., "user.profile.age")
 */
static char *
jsonplus_build_json_path(wmem_allocator_t *pool, const char **path_parts, int depth)
{
	wmem_strbuf_t *path_buf;
	int i;

	if (depth <= 0) {
		return wmem_strdup(pool, "");
	}

	path_buf = wmem_strbuf_new(pool, "");

	for (i = 0; i < depth; i++) {
		if (i > 0) {
			wmem_strbuf_append_c(path_buf, '.');
		}
		wmem_strbuf_append(path_buf, path_parts[i]);
	}

	return wmem_strbuf_finalize(path_buf);
}

 // look up enum name from value_string

static const char *
jsonplus_lookup_enum_name(value_string *vs, int64_t value)
{
	if (!vs) return NULL;

	while (vs->strptr != NULL) {
		if (vs->value == (guint32)value) {
			return vs->strptr;
		}
		vs++;
	}
	return NULL;
}

 /* Helper to add info label to Info column
  Clears the Info column on first label, then appends labels */

static void
jsonplus_add_info_label(packet_info *pinfo, const char *format, ...)
{
	va_list args;
	char buffer[256];

	if (!pinfo) return;

	// Format the string
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	// Check if we've already cleared the Info column for this packet
	void *cleared_flag = p_get_proto_data(pinfo->pool, pinfo, proto_json, 1);

	if (!cleared_flag) {
		// First info label - clear the entire Info column
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_str(pinfo->cinfo, COL_INFO, buffer);
		// clear it
		p_add_proto_data(pinfo->pool, pinfo, proto_json, 1, (void *)1);
	} else {
		// Subsequent labels, append
		col_append_str(pinfo->cinfo, COL_INFO, buffer);
	}
}

 // Parser result output
typedef struct {
	char *append_text;
	GPtrArray *child_fields;
} jsonplus_parser_result_t;

typedef struct {
	char *filter_name;
	char *value;
	int hf_id;         // Header field ID dynamically registered
} jsonplus_parser_child_field_t;

/* wmem destroy callback: free only the GPtrArray container. The elements it
 * holds are allocated from the same wmem pool and are reclaimed by the pool
 * itself, so we must not let g_ptr_array_free() free them (hence false).
 */
static bool
jsonplus_free_child_fields_cb(wmem_allocator_t *scope _U_, wmem_cb_event_t event _U_, void *data)
{
	g_ptr_array_free((GPtrArray *)data, false);
	return false;
}

static jsonplus_parser_result_t *
jsonplus_execute_parser(json_field_t *field, const char *value, wmem_allocator_t *pool)
{
	char *parser_path;
	jsonplus_parser_result_t *result;
	const char *data_dir;
	gchar *standard_output = NULL;
	gchar *standard_error = NULL;
	gint exit_status = 0;
	GError *error = NULL;
	gchar **argv;
	gint argc;
	gchar *field_value_arg;

	if (!field || !field->parser || !value) {
		return NULL;
	}

	// Resolve parser script: personal first (<persconfdir>/json/parsers/),
	// fall back to system (<datadir>/json/parsers/). Matches the dictionary
	// loader precedence — a personal copy shadows the system copy. Lookup
	// happens once per dissected field invocation, so the file_exists()
	// stat is acceptable; cache it later if it shows up in profiles.
	parser_path = NULL;
	char *personal_json_dir = get_persconffile_path("json", false, NULL);
	if (personal_json_dir) {
		char *personal_path = wmem_strdup_printf(pool,
			"%s%cparsers%c%s",
			personal_json_dir, G_DIR_SEPARATOR, G_DIR_SEPARATOR,
			field->parser);
		if (file_exists(personal_path)) {
			parser_path = personal_path;
		} else {
			wmem_free(pool, personal_path);
		}
		g_free(personal_json_dir);
	}
	if (!parser_path) {
		data_dir = get_datafile_dir(NULL);
		parser_path = wmem_strdup_printf(pool,
			"%s%cjson%cparsers%c%s",
			data_dir, G_DIR_SEPARATOR, G_DIR_SEPARATOR,
			G_DIR_SEPARATOR, field->parser);
	}

	// Build argument array
	field_value_arg = wmem_strdup_printf(pool, "%s::%s", field->name, value);

	if (field->parser_args) {
		// Parse additional arguments
		gchar **extra_args;
		if (!g_shell_parse_argv(field->parser_args, &argc, &extra_args, &error)) {
			g_clear_error(&error);
			return NULL;
		}

		argv = g_new0(gchar *, argc + 3);
		argv[0] = parser_path;
		argv[1] = field_value_arg;
		/* Duplicate each extra arg into pool-owned memory so that the whole
		 * strv returned by g_shell_parse_argv() can be freed here without
		 * leaking the individual strings (argv only holds borrowed pointers).
		 */
		for (gint i = 0; i < argc; i++) {
			argv[i + 2] = wmem_strdup(pool, extra_args[i]);
		}
		argv[argc + 2] = NULL;
		g_strfreev(extra_args);
	} else {
		argv = g_new0(gchar *, 3);
		argv[0] = parser_path;
		argv[1] = field_value_arg;
		argv[2] = NULL;
	}

	if (!g_spawn_sync(NULL,
	                  argv,
	                  NULL,
	                  G_SPAWN_SEARCH_PATH,
	                  NULL,
	                  NULL,
	                  &standard_output,
	                  &standard_error,
	                  &exit_status,
	                  &error)) {
		// Spawn failed
		g_free(argv);
		g_clear_error(&error);
		return NULL;
	}

	g_free(argv);

	if (exit_status != 0 || !standard_output) {
		g_free(standard_output);
		g_free(standard_error);
		return NULL;
	}

	result = wmem_new0(pool, jsonplus_parser_result_t);
	result->append_text = NULL;
	result->child_fields = g_ptr_array_new();
	/* The GPtrArray is a glib allocation living on a wmem-allocated result;
	 * free its container when the pool is torn down to avoid a leak.
	 */
	wmem_register_callback(pool, jsonplus_free_child_fields_cb, result->child_fields);

	// Parse output line by line
	gchar **lines = g_strsplit(standard_output, "\n", -1);
	for (gint i = 0; lines[i] != NULL; i++) {
		gchar *line = lines[i];

		// Skip empty lines
		if (strlen(line) == 0) continue;

		if (g_str_has_prefix(line, "APPEND:")) {
			gchar *text = line + 7;
			while (*text == ' ' || *text == '\t') text++;
			result->append_text = wmem_strdup(pool, text);
		}
		else if (g_str_has_prefix(line, "CHILD:")) {
			gchar *spec = line + 6;
			// Skip leading whitespace
			while (*spec == ' ' || *spec == '\t') spec++;

			// Parse: filter|value
			gchar **parts = g_strsplit(spec, "|", 2);
			guint num_parts = g_strv_length(parts);

			if (num_parts == 2) {
				// Create child field entry
				jsonplus_parser_child_field_t *child = wmem_new0(pool, jsonplus_parser_child_field_t);
				child->filter_name = wmem_strdup(pool, parts[0]);
				child->value = wmem_strdup(pool, parts[1]);
				child->hf_id = -1;

				g_ptr_array_add(result->child_fields, child);
			}
			g_strfreev(parts);
		}
	}

	g_strfreev(lines);
	g_free(standard_output);
	g_free(standard_error);

	return result;
}

 // Dissect special display types (IPv4, IPv6, MAC, timestamps, etc.)
static void
jsonplus_dissect_dict_special_field(tvbuff_t *tvb, proto_tree *tree, wmem_allocator_t *pool, jsmntok_t *token,
			   const char *json_buf, json_field_t *field)
{
	int token_len = token->end - token->start;
	const char *value_str = json_buf + token->start;
	char *str_value;

	if (!tree) return;  // No tree during first pass

	str_value = wmem_strndup(pool, value_str, token_len);

	switch (field->display_type) {
	case JSON_DISPLAY_IPV4: {
		// Parse IPv4 address from string
		ws_in4_addr addr;
		if (ws_inet_pton4(str_value, &addr)) {
			proto_tree_add_ipv4(tree, field->hf_value, tvb,
				token->start, token_len, addr);
		} else {
			// Failed to parse - add as string with expert info
			proto_item *ti = proto_tree_add_string(tree, field->hf_value, tvb,
				token->start, token_len, str_value);
			expert_add_info(NULL, ti, &ei_json_plus_type_mismatch);
		}
		break;
	}

	case JSON_DISPLAY_IPV6: {
		// Parse IPv6 address from string
		ws_in6_addr addr;
		if (ws_inet_pton6(str_value, &addr)) {
			proto_tree_add_ipv6(tree, field->hf_value, tvb,
				token->start, token_len, &addr);
		} else {
			// Failed to parse - add as string with expert info
			proto_item *ti = proto_tree_add_string(tree, field->hf_value, tvb,
				token->start, token_len, str_value);
			expert_add_info(NULL, ti, &ei_json_plus_type_mismatch);
		}
		break;
	}

	case JSON_DISPLAY_ETHER: {
		// Parse MAC address from string
		uint8_t addr[6];
		unsigned int a0, a1, a2, a3, a4, a5;
		if (sscanf(str_value, "%x:%x:%x:%x:%x:%x",
			   &a0, &a1, &a2, &a3, &a4, &a5) == 6) {
			addr[0] = (uint8_t)a0;
			addr[1] = (uint8_t)a1;
			addr[2] = (uint8_t)a2;
			addr[3] = (uint8_t)a3;
			addr[4] = (uint8_t)a4;
			addr[5] = (uint8_t)a5;
			proto_tree_add_ether(tree, field->hf_value, tvb,
				token->start, token_len, addr);
		} else {
			// Failed to parse - add as string with expert info
			proto_item *ti = proto_tree_add_string(tree, field->hf_value, tvb,
				token->start, token_len, str_value);
			expert_add_info(NULL, ti, &ei_json_plus_type_mismatch);
		}
		break;
	}

	case JSON_DISPLAY_ABSOLUTE_TIME: {
		// Parse Unix timestamp
		int64_t timestamp;
		if (ws_strtoi64(str_value, NULL, &timestamp)) {
			nstime_t ts;
			ts.secs = (time_t)timestamp;
			ts.nsecs = 0;
			proto_tree_add_time(tree, field->hf_value, tvb,
				token->start, token_len, &ts);
		} else {
			// Failed to parse - add as string
			proto_item *ti = proto_tree_add_string(tree, field->hf_value, tvb,
				token->start, token_len, str_value);
			expert_add_info(NULL, ti, &ei_json_plus_type_mismatch);
		}
		break;
	}

	case JSON_DISPLAY_RELATIVE_TIME: {
		// Parse relative time in seconds
		double rel_time;
		if (sscanf(str_value, "%lf", &rel_time) == 1) {
			nstime_t ts;
			ts.secs = (time_t)rel_time;
			ts.nsecs = (int)((rel_time - ts.secs) * 1000000000);
			proto_tree_add_time(tree, field->hf_value, tvb,
				token->start, token_len, &ts);
		} else {
			// Failed to parse - add as string
			proto_item *ti = proto_tree_add_string(tree, field->hf_value, tvb,
				token->start, token_len, str_value);
			expert_add_info(NULL, ti, &ei_json_plus_type_mismatch);
		}
		break;
	}

	case JSON_DISPLAY_HEX2DEC: {
		// Parse hex string and display as decimal
		uint64_t uint_val;
		char *endptr = NULL;

		uint_val = g_ascii_strtoull(str_value, &endptr, 16);

		if (endptr && *endptr == '\0') {
			// Check if field has enums then downgraded to 32-bit
			if (field->enum_values) {
				proto_tree_add_uint(tree, field->hf_value, tvb,
					token->start, token_len, (uint32_t)uint_val);
			} else {
				// No enum use 64bit with  compact hex format
				proto_tree_add_uint64_format_value(tree, field->hf_value, tvb,
					token->start, token_len, uint_val,
					"%"PRIu64" (0x%"PRIx64")", uint_val, uint_val);
			}
		} else {
			// Failed to parse, add  as string with expert info
			proto_item *ti = proto_tree_add_string(tree, field->hf_value, tvb,
				token->start, token_len, str_value);
			expert_add_info(NULL, ti, &ei_json_plus_type_mismatch);
		}
		break;
	}

	default:
		// Shouldn't happen, but fall back to string
		proto_tree_add_string(tree, field->hf_value, tvb,
			token->start, token_len, str_value);
		break;
	}
}

 // Dissect a string field using dictionary definition
static void
jsonplus_dissect_dict_string_field(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, wmem_allocator_t *pool,
			  jsmntok_t *token, const char *json_buf, json_field_t *field)
{
	int token_len = token->end - token->start;
	const char *value_str = json_buf + token->start;
	char *display_str;

	display_str = wmem_strndup(pool, value_str, token_len);

	// Append to Info column if requested
	if (field->info_label && pinfo) {
		jsonplus_add_info_label(pinfo, " %s: %s", field->info_label, display_str);
	}

	if (!tree) return;  // No tree during first pass

	// Check if this field has special display formatting
	if (field->display_type != JSON_DISPLAY_NONE) {
		jsonplus_dissect_dict_special_field(tvb, tree, pool, token, json_buf, field);
		return;
	}

	jsonplus_parser_result_t *parser_result = NULL;

	// Always use GUI preference if set
	bool parsers_enabled = (gbl_json_run_external_parsers || gbl_json_run_external_parsers_cli);

	if (field->parser && parsers_enabled) {
		parser_result = jsonplus_execute_parser(field, display_str, pool);
	}

	// Add field to tree
	proto_item *ti;
	if (parser_result && parser_result->append_text) {
		// Append parsed text to field display
		char *full_display = wmem_strdup_printf(pool, "%s %s",
			display_str, parser_result->append_text);
		ti = proto_tree_add_string(tree, field->hf_value, tvb,
			token->start, token_len, full_display);
	} else {
		ti = proto_tree_add_string(tree, field->hf_value, tvb,
			token->start, token_len, display_str);
	}

	// Add parser child fields as subtree items
	if (parser_result && parser_result->child_fields &&
	    parser_result->child_fields->len > 0) {

		proto_tree *subtree = proto_item_add_subtree(ti, ett_json_plus_object);

		// Iterate through child fields in order
		for (guint i = 0; i < parser_result->child_fields->len; i++) {
			jsonplus_parser_child_field_t *child = (jsonplus_parser_child_field_t *)g_ptr_array_index(parser_result->child_fields, i);

			// Try to find pre-defined child field by matching path/filter name
			json_field_t *child_field = NULL;
			if (field->child_fields && json_plus_dictionary.fields) {
				// Extract path from filter name (remove "json." prefix if present)
				const char *filter_name = child->filter_name;
				if (strncmp(filter_name, "json.", 5) == 0) {
					const char *path = filter_name + 5;  /* Skip "json." */
					child_field = jsonplus_lookup_field_by_path(path);
				}
			}

			// Check if we have a predefined child field
			if (child_field && child_field->hf_value != -1) {
				// Use the pre-registered field with correct type
				if (child_field->type == JSON_FIELD_INTEGER) {
					int64_t int_val;
					if (ws_strtoi64(child->value, NULL, &int_val)) {
						proto_tree_add_int64(subtree, child_field->hf_value,
							tvb, token->start, token_len, int_val);
					} else {
						// Failed to parse - add as string
						ti = proto_tree_add_uint64_format_value(subtree,
							child_field->hf_value, tvb, token->start, token_len, 0,
							"Cannot convert value: %s", child->value);
						expert_add_info(NULL, ti, &ei_json_plus_type_mismatch);
					}
				} else if (child_field->type == JSON_FIELD_UNSIGNED) {
					uint64_t uint_val;
					if (ws_strtou64(child->value, NULL, &uint_val)) {
						proto_tree_add_int64(subtree, child_field->hf_value,
							tvb, token->start, token_len, uint_val);
					} else {
						// Failed to parse - add as string
						ti = proto_tree_add_uint64_format_value(subtree,
							child_field->hf_value, tvb, token->start, token_len, 0,
							"Cannot convert value: %s", child->value);
						expert_add_info(NULL, ti, &ei_json_plus_type_mismatch);
					}
				} else if (child_field->type == JSON_FIELD_BOOLEAN) {
					bool bool_val = (strcmp(child->value, "true") == 0 ||
					                 strcmp(child->value, "1") == 0);
					proto_tree_add_boolean(subtree, child_field->hf_value,
						tvb, token->start, token_len, bool_val);
				} else {
					// String or other types
					proto_tree_add_string(subtree, child_field->hf_value,
						tvb, token->start, token_len, child->value);
				}
			} else {
				// Field not found in dictionary  show warning
				proto_tree_add_string_format(subtree, hf_json_value_string,
					tvb, token->start, token_len, child->value,
					"%s: %s [Not in dictionary]", child->filter_name, child->value);
			}
		}
	}
}

 // Dissect an integer field using dictionary definition
static void
jsonplus_dissect_dict_integer_field(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, wmem_allocator_t *pool,
			   jsmntok_t *token, const char *json_buf, json_field_t *field)
{
	int token_len = token->end - token->start;
	const char *value_str = json_buf + token->start;
	char *num_str;
	int64_t value;

	num_str = wmem_strndup(pool, value_str, token_len);
	if (ws_strtoi64(num_str, NULL, &value)) {
		// Append to Info column if requested
		if (field->info_label && pinfo) {
			const char *enum_name = jsonplus_lookup_enum_name(field->enum_values, value);
			if (enum_name) {
				jsonplus_add_info_label(pinfo, " %s: %s", field->info_label, enum_name);
			} else {
				jsonplus_add_info_label(pinfo, " %s: %" PRId64, field->info_label, value);
			}
		}

		if (!tree) return;  // No tree during first pass

		// Check for special display types
		if (field->display_type == JSON_DISPLAY_ABSOLUTE_TIME) {
			// Convert Unix timestamp to nstime_t
			nstime_t ts;
			ts.secs = (time_t)value;
			ts.nsecs = 0;
			proto_tree_add_time(tree, field->hf_value, tvb,
				token->start, token_len, &ts);
		} else if (field->display_type == JSON_DISPLAY_RELATIVE_TIME) {
			// Treat integer as seconds for relative time
			nstime_t ts;
			ts.secs = (time_t)value;
			ts.nsecs = 0;
			proto_tree_add_time(tree, field->hf_value, tvb,
				token->start, token_len, &ts);
		} else if (field->enum_values) {
			// Use 32bit function if field has enums
			proto_tree_add_int(tree, field->hf_value, tvb,
				token->start, token_len, (gint32)value);
		} else {
			proto_tree_add_int64(tree, field->hf_value, tvb,
				token->start, token_len, value);
		}
	} else {
		if (!tree) return;  // No tree during first pass

		// Fallback to string if parsing fails
		proto_tree_add_string(tree, field->hf_value, tvb,
			token->start, token_len, num_str);
	}
}

 // Dissect an unsigned integer field using dictionary definition
static void
jsonplus_dissect_dict_unsigned_field(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, wmem_allocator_t *pool,
			    jsmntok_t *token, const char *json_buf, json_field_t *field)
{
	int token_len = token->end - token->start;
	const char *value_str = json_buf + token->start;
	char *num_str;
	uint64_t value;

	num_str = wmem_strndup(pool, value_str, token_len);
	if (ws_strtou64(num_str, NULL, &value)) {
		// Append to Info column
		if (field->info_label && pinfo) {
			const char *enum_name = jsonplus_lookup_enum_name(field->enum_values, (int64_t)value);
			if (enum_name) {
				jsonplus_add_info_label(pinfo, " %s: %s", field->info_label, enum_name);
			} else {
				jsonplus_add_info_label(pinfo, " %s: %" PRIu64, field->info_label, value);
			}
		}

		if (!tree) return;  // No tree during first pass

		// Check for special display types
		if (field->display_type == JSON_DISPLAY_ABSOLUTE_TIME) {
			// Convert Unix timestamp to nstime_t
			nstime_t ts;
			ts.secs = (time_t)value;
			ts.nsecs = 0;
			proto_tree_add_time(tree, field->hf_value, tvb,
				token->start, token_len, &ts);
		} else if (field->display_type == JSON_DISPLAY_RELATIVE_TIME) {
			// Treat integer as seconds for relative time
			nstime_t ts;
			ts.secs = (time_t)value;
			ts.nsecs = 0;
			proto_tree_add_time(tree, field->hf_value, tvb,
				token->start, token_len, &ts);
		} else if (field->enum_values) {
			// Use 32bit function if field has enums
			proto_tree_add_uint(tree, field->hf_value, tvb,
				token->start, token_len, (guint32)value);
		} else {
			proto_tree_add_uint64(tree, field->hf_value, tvb,
				token->start, token_len, value);
		}
	} else {
		if (!tree) return;  // No tree during first pass

		// Fallback to string if parsing fails
		proto_tree_add_string(tree, field->hf_value, tvb,
			token->start, token_len, num_str);
	}
}

 // Dissect a float field using dictionary definition
static void
jsonplus_dissect_dict_float_field(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, wmem_allocator_t *pool,
			 jsmntok_t *token, const char *json_buf, json_field_t *field)
{
	int token_len = token->end - token->start;
	const char *value_str = json_buf + token->start;
	char *num_str;
	double value;

	num_str = wmem_strndup(pool, value_str, token_len);
	if (sscanf(num_str, "%lf", &value) == 1) {
		// Append to Info column
		if (field->info_label && pinfo) {
			jsonplus_add_info_label(pinfo, " %s: %.2f", field->info_label, value);
		}

		if (!tree) return;  // No tree during first pass

		proto_tree_add_double(tree, field->hf_value, tvb,
			token->start, token_len, value);
	} else {
		if (!tree) return;  // No tree during first pass

		// Fallback to string if parsing fails
		proto_tree_add_string(tree, field->hf_value, tvb,
			token->start, token_len, num_str);
	}
}

// Dissect a boolean field using dictionary definition
static void
jsonplus_dissect_dict_boolean_field(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, wmem_allocator_t *pool _U_,
			   jsmntok_t *token, const char *json_buf, json_field_t *field)
{
	int token_len = token->end - token->start;
	const char *value_str = json_buf + token->start;
	bool value;

	if (token_len == 4 && strncmp(value_str, "true", 4) == 0) {
		value = true;
	} else {
		value = false;
	}

	// Append to Info column
	if (field->info_label && pinfo) {
		jsonplus_add_info_label(pinfo, " %s: %s", field->info_label, value ? "true" : "false");
	}

	if (!tree) return;  // No tree during first pass

	proto_tree_add_boolean(tree, field->hf_value, tvb,
		token->start, token_len, value);
}

// Count tokens in a JSON value (for skipping during first pass)
// NOLINTNEXTLINE(misc-no-recursion)
static int jsonplus_count_json_tokens(jsmntok_t *tokens, int token_idx, int depth)
{
	// Nesting is attacker-controlled; stop descending instead of asserting.
	if (depth >= JSON_PLUS_MAX_PATH_DEPTH) {
		return 1;  // Count only the current token, do not recurse further
	}
	jsmntok_t *token = &tokens[token_idx];
	int count = 1;  // Start with current token
	int i, child_idx;

	if (token->type == JSMN_OBJECT) {
		// Skip over all key/value pairs. Count each child exactly once and
		// advance by that amount (counting twice per child was O(2^depth)).
		child_idx = token_idx + 1;
		for (i = 0; i < token->size; i++) {
			// Skip key
			int key_tokens = jsonplus_count_json_tokens(tokens, child_idx, depth + 1);
			count += key_tokens;
			child_idx += key_tokens;
			// Skip value
			int value_tokens = jsonplus_count_json_tokens(tokens, child_idx, depth + 1);
			count += value_tokens;
			child_idx += value_tokens;
		}
	}
	else if (token->type == JSMN_ARRAY) {
		// Skip over all elements
		child_idx = token_idx + 1;
		for (i = 0; i < token->size; i++) {
			int elem_tokens = jsonplus_count_json_tokens(tokens, child_idx, depth + 1);
			count += elem_tokens;
			child_idx += elem_tokens;
		}
	}

	return count;
}

/* Find the first <wildcardfield> on a json_field_t whose regex matches key_str */
static json_wildcard_field_t *
jsonplus_find_wildcard_field(json_field_t *field, const char *key_str)
{
	if (!field || !field->wildcard_fields || !key_str)
		return NULL;
	for (wmem_list_frame_t *wc = wmem_list_head(field->wildcard_fields); wc; wc = wmem_list_frame_next(wc)) {
		json_wildcard_field_t *jwf = (json_wildcard_field_t *)wmem_list_frame_data(wc);
		if (jwf->match_re && ws_regex_matches(jwf->match_re, key_str))
			return jwf;
	}
	return NULL;
}


// Dissect an object field using dictionary definition
// NOLINTNEXTLINE(misc-no-recursion)
static int jsonplus_dissect_dict_object_field(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, wmem_allocator_t *pool,
			  jsmntok_t *tokens, int token_idx, const char *json_buf, json_field_t *field,
			  const char **path_parts, int path_depth)
{
	// Nesting depth is attacker-controlled: skip this subtree gracefully
	// instead of asserting. Return the token count so the caller advances.
	if (path_depth >= JSON_PLUS_MAX_PATH_DEPTH) {
		if (tree) {
			proto_tree_add_expert_format(tree, pinfo, &ei_json_plus_parse_error,
				tvb, 0, 0, "JSON+ nesting too deep, skipping (max %d)",
				JSON_PLUS_MAX_PATH_DEPTH);
		}
		return jsonplus_count_json_tokens(tokens, token_idx, 0);
	}
	jsmntok_t *token = &tokens[token_idx];
	proto_item *ti;
	proto_tree *subtree;
	int child_idx;
	int i;
	int tokens_consumed = 1;

	// Append to Info column during first pass
	if (field->info_label && pinfo) {
		jsonplus_add_info_label(pinfo, " %s", field->info_label);
	}

	// During first pass, still need to process children for info labels
	if (!tree) {
		// No tree available (first pass), but iterate children for info labels
		child_idx = token_idx + 1;
		for (i = 0; i < token->size; i++) {
			// Get key
			jsmntok_t *key_token = &tokens[child_idx];
			if (key_token->type != JSMN_STRING) {
				child_idx++;
				continue;
			}

			char *key_str = wmem_strndup(pool,
				json_buf + key_token->start,
				key_token->end - key_token->start);

			/* Move to value */
			child_idx++;

			/* Add key to path — use wildcard alias if matched */
			if (path_depth < JSON_PLUS_MAX_PATH_DEPTH) {
				json_wildcard_field_t *jwf = jsonplus_find_wildcard_field(field, key_str);
				path_parts[path_depth] = jwf ? jwf->alias : key_str;

				int consumed = jsonplus_display_json_tree_dict(tvb, NULL, pinfo, pool, tokens,
					child_idx, json_buf, path_parts, path_depth + 1);
				child_idx += consumed;
			} else {
				// Path too deep, skip
				int consumed = jsonplus_count_json_tokens(tokens, child_idx, path_depth);
				child_idx += consumed;
			}
		}
		tokens_consumed = child_idx - token_idx;
		return tokens_consumed;
	}

	ti = proto_tree_add_item(tree, field->hf_value, tvb,
		token->start, token->end - token->start, ENC_NA);
	if (!ti || !field->ett) {
		// Can't create subtree, just return token count
		return jsonplus_count_json_tokens(tokens, token_idx, path_depth);
	}
	subtree = proto_item_add_subtree(ti, *field->ett);

	// Iterate over object members
	child_idx = token_idx + 1;
	for (i = 0; i < token->size; i++) {
		// Get key
		jsmntok_t *key_token = &tokens[child_idx];
		if (key_token->type != JSMN_STRING) {
			child_idx++;
			continue;
		}

		char *key_str = wmem_strndup(pool,
			json_buf + key_token->start,
			key_token->end - key_token->start);

		// Move to value
		child_idx++;

		/* Add key to path — substitute alias for wildcard keys */
		if (path_depth < JSON_PLUS_MAX_PATH_DEPTH) {
			json_wildcard_field_t *jwf = jsonplus_find_wildcard_field(field, key_str);
			if (jwf) {
				/* Emit the actual runtime key as a labeled string field */
				if (jwf->hf_key_value != -1) {
					proto_tree_add_string(subtree, jwf->hf_key_value, tvb,
						key_token->start,
						key_token->end - key_token->start,
						key_str);
				}
				/* Substitute alias so child paths resolve against dictionary */
				path_parts[path_depth] = jwf->alias;
			} else {
				path_parts[path_depth] = key_str;
			}

			int consumed = jsonplus_display_json_tree_dict(tvb, subtree, pinfo, pool, tokens,
				child_idx, json_buf, path_parts, path_depth + 1);
			child_idx += consumed;
		} else {
			// Path too deep, skip
			child_idx++;
		}
	}

	tokens_consumed = child_idx - token_idx;
	return tokens_consumed;
}

// Dissect an array field using dictionary definition
// NOLINTNEXTLINE(misc-no-recursion)
static int jsonplus_dissect_dict_array_field(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, wmem_allocator_t *pool,
			 jsmntok_t *tokens, int token_idx, const char *json_buf, json_field_t *field,
			 const char **path_parts, int path_depth)
{
	// Nesting depth is attacker-controlled: skip this subtree gracefully
	// instead of asserting. Return the token count so the caller advances.
	if (path_depth >= JSON_PLUS_MAX_PATH_DEPTH) {
		if (tree) {
			proto_tree_add_expert_format(tree, pinfo, &ei_json_plus_parse_error,
				tvb, 0, 0, "JSON+ nesting too deep, skipping (max %d)",
				JSON_PLUS_MAX_PATH_DEPTH);
		}
		return jsonplus_count_json_tokens(tokens, token_idx, 0);
	}
	jsmntok_t *token = &tokens[token_idx];
	proto_item *ti;
	proto_tree *subtree;
	int child_idx;
	int i;
	int tokens_consumed = 1;

	// During first pass, process array elements for info labels
	if (!tree) {
		// No tree available first pass, but iterate elements for info labels
		child_idx = token_idx + 1;
		for (i = 0; i < token->size; i++) {
			char *elem_path;

			if (path_depth > 0) {
				// Construct path like items[5] from parent items
				elem_path = wmem_strdup_printf(pool, "%s[%d]",
					path_parts[path_depth - 1], i);
			} else {
				elem_path = wmem_strdup_printf(pool, "[%d]", i);
			}

			if (path_depth < JSON_PLUS_MAX_PATH_DEPTH) {
				// Replace the current level with indexed array element
				path_parts[path_depth - 1] = elem_path;

				// Process element for info labels
				int consumed = jsonplus_display_json_tree_dict(tvb, NULL, pinfo, pool, tokens,
					child_idx, json_buf, path_parts, path_depth);
				child_idx += consumed;
			} else {
				int consumed = jsonplus_count_json_tokens(tokens, child_idx, path_depth);
				child_idx += consumed;
			}
		}
		tokens_consumed = child_idx - token_idx;
		return tokens_consumed;
	}

	/* Create subtree for array */
	ti = proto_tree_add_item(tree, field->hf_value, tvb,
		token->start, token->end - token->start, ENC_NA);
	if (!ti || !field->ett) {
		// Can't create subtree, just return token count
		return jsonplus_count_json_tokens(tokens, token_idx, path_depth);
	}
	subtree = proto_item_add_subtree(ti, *field->ett);

	proto_item_append_text(ti, " [%d elements]", token->size);

	// Iterate over array elements
	const char *parent_path_backup = (path_depth > 0) ? path_parts[path_depth - 1] : NULL;

	child_idx = token_idx + 1;
	for (i = 0; i < token->size; i++) {
		jsmntok_t *elem_token = &tokens[child_idx];
		proto_item *elem_ti;
		proto_tree *elem_subtree;
		char *elem_path;

		/* Create subtree for this array element */
		elem_ti = proto_tree_add_none_format(subtree, hf_json_array, tvb,
			elem_token->start, elem_token->end - elem_token->start,
			"%s %d", field->name, i);
		elem_subtree = proto_item_add_subtree(elem_ti, ett_json_plus_array);

		if (path_depth > 0) {
			// Construct path like items[5] from parent item
			elem_path = wmem_strdup_printf(pool, "%s[%d]", parent_path_backup, i);
		} else {
			elem_path = wmem_strdup_printf(pool, "[%d]", i);
		}

		if (path_depth < JSON_PLUS_MAX_PATH_DEPTH) {
			/* Replace the current level with indexed array element */
			path_parts[path_depth - 1] = elem_path;

			// Process element - dictionary lookup will normalize [i] to []
			int consumed = jsonplus_display_json_tree_dict(tvb, elem_subtree, pinfo, pool, tokens,
				child_idx, json_buf, path_parts, path_depth);
			child_idx += consumed;
		} else {
			child_idx++;
		}
	}

	tokens_consumed = child_idx - token_idx;
	return tokens_consumed;
}

/*
 * Dissect JSON using dictionary definitions (main recursive function)
 * Returns the number of tokens consumed
 */
// NOLINTNEXTLINE(misc-no-recursion)
static int jsonplus_display_json_tree_dict(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, wmem_allocator_t *pool,
		       jsmntok_t *tokens, int token_idx, const char *json_buf,
		       const char **path_parts, int path_depth)
{
	// Nesting depth is attacker-controlled: skip this subtree gracefully
	// instead of asserting. Return the token count so the caller advances.
	if (path_depth >= JSON_PLUS_MAX_PATH_DEPTH) {
		if (tree) {
			proto_tree_add_expert_format(tree, pinfo, &ei_json_plus_parse_error,
				tvb, 0, 0, "JSON+ nesting too deep, skipping (max %d)",
				JSON_PLUS_MAX_PATH_DEPTH);
		}
		return jsonplus_count_json_tokens(tokens, token_idx, 0);
	}
	jsmntok_t *token = &tokens[token_idx];
	json_field_t *field = NULL;
	char *current_path;
	char *normalized_path = NULL;
	int tokens_consumed = 1;

	// Build current path
	current_path = jsonplus_build_json_path(pool, path_parts, path_depth);

	/* Look up field in dictionary with array index normalization */
	if (current_path && current_path[0] != '\0') {
		// First try exact match
		field = jsonplus_lookup_field_by_path(current_path);

		// Normalize path for array indices
		normalized_path = jsonplus_normalize_array_path(pool, current_path);

		/* If not found, try with normalized array indices */
		if (!field && normalized_path && strcmp(normalized_path, current_path) != 0) {
			field = jsonplus_lookup_field_by_path(normalized_path);
		}

		/* If still not found and we're inside a root-level array element, try
		 * stripping the leading "[N]." prefix so that bare dictionary entries
		 * (e.g. path="singleNssai.sst") match from both root-object and root-array
		 * JSON without requiring duplicate [].prefixed entries. */
		if (!field && jsonplus_path_has_root_array_prefix(path_parts, path_depth)) {
			const char *dot = strchr(current_path, '.');
			if (dot) {
				const char *bare_path = dot + 1;
				field = jsonplus_lookup_field_by_path(bare_path);
				if (!field) {
					char *bare_normalized = jsonplus_normalize_array_path(pool, bare_path);
					if (bare_normalized && strcmp(bare_normalized, bare_path) != 0) {
						field = jsonplus_lookup_field_by_path(bare_normalized);
					}
				}
			}
		}
	}

	// Special handling for root-level object process children with dictionary
	if (!field && path_depth == 0 && token->type == JSMN_OBJECT) {
		int child_idx = token_idx + 1;
		int i;

		for (i = 0; i < token->size; i++) {
			// Get key
			jsmntok_t *key_token = &tokens[child_idx];
			if (key_token->type != JSMN_STRING) {
				child_idx++;
				continue;
			}

			char *key_str = wmem_strndup(pool,
				json_buf + key_token->start,
				key_token->end - key_token->start);

			// Move to value
			child_idx++;

			/* Add key to path for lookup */
			if (path_depth < JSON_PLUS_MAX_PATH_DEPTH) {
				path_parts[0] = key_str;

				/* Recursively process value with this key as path */
				int consumed = jsonplus_display_json_tree_dict(tvb, tree, pinfo, pool, tokens,
					child_idx, json_buf, path_parts, 1);
				child_idx += consumed;
			} else {
				child_idx++;
			}
		}

		tokens_consumed = child_idx - token_idx;
		return tokens_consumed;
	}

	/* Special handling for root-level array: process children with dictionary */
	else if (!field && path_depth == 0 && token->type == JSMN_ARRAY) {
		proto_item *ti = NULL;
		proto_tree *subtree = tree;

		if (tree) {
			ti = proto_tree_add_none_format(tree, hf_json_array, tvb,
				token->start, token->end - token->start, "[]");
			if (ti) {
				subtree = proto_item_add_subtree(ti, ett_json_plus_array);
			}
		}

		int child_idx = token_idx + 1;
		for (int i = 0; i < token->size; i++) {
			/* "[0]" normalizes to "[]" enabling dictionary lookup for path="[]" entries */
			path_parts[0] = wmem_strdup_printf(pool, "[%d]", i);
			int consumed = jsonplus_display_json_tree_dict(tvb, subtree, pinfo, pool, tokens,
				child_idx, json_buf, path_parts, 1);
			child_idx += consumed;
		}

		tokens_consumed = child_idx - token_idx;
		return tokens_consumed;
	}

	if (field) {
		/* Check for type mismatch: if field is Array but token is Object,
		 * we're likely at an array element (anonymous object), not the array itself.
		 * Treat this as if no field was found and process children normally. */
		if (field->type == JSON_FIELD_ARRAY && token->type == JSMN_OBJECT) {
			field = NULL;
		}
		/* Check for type mismatch: if field is Object but token is Array,
		 * similar situation - treat as anonymous array element */
		else if (field->type == JSON_FIELD_OBJECT && token->type == JSMN_ARRAY) {
			field = NULL;
		}
	}

	if (field) {
		// Use dictionary field definition
		if (token->type == JSMN_OBJECT) {
			tokens_consumed = jsonplus_dissect_dict_object_field(tvb, tree, pinfo, pool, tokens,
				token_idx, json_buf, field, path_parts, path_depth);
		}
		else if (token->type == JSMN_ARRAY) {
			tokens_consumed = jsonplus_dissect_dict_array_field(tvb, tree, pinfo, pool, tokens,
				token_idx, json_buf, field, path_parts, path_depth);
		}
		else if (token->type == JSMN_STRING) {
			jsonplus_dissect_dict_string_field(tvb, tree, pinfo, pool, token, json_buf, field);
		}
		else if (token->type == JSMN_PRIMITIVE) {
			int token_len = token->end - token->start;
			const char *value_str = json_buf + token->start;

			if (token_len == 4 && strncmp(value_str, "null", 4) == 0) {
				// Null - just add item
				if (tree) proto_tree_add_item(tree, field->hf_value, tvb,
					token->start, token_len, ENC_NA);
			}
			else if ((token_len == 4 && strncmp(value_str, "true", 4) == 0) ||
				 (token_len == 5 && strncmp(value_str, "false", 5) == 0)) {
				// Boolean
				jsonplus_dissect_dict_boolean_field(tvb, tree, pinfo, pool, token, json_buf, field);
			}
			else {
				// Number - check field type
				if (field->type == JSON_FIELD_INTEGER) {
					jsonplus_dissect_dict_integer_field(tvb, tree, pinfo, pool, token, json_buf, field);
				}
				else if (field->type == JSON_FIELD_UNSIGNED) {
					jsonplus_dissect_dict_unsigned_field(tvb, tree, pinfo, pool, token, json_buf, field);
				}
				else if (field->type == JSON_FIELD_FLOAT) {
					jsonplus_dissect_dict_float_field(tvb, tree, pinfo, pool, token, json_buf, field);
				}
				else {
					/* Default to string */
					jsonplus_dissect_dict_string_field(tvb, tree, pinfo, pool, token, json_buf, field);
				}
			}
		}
	}
	/* If no field found, show basic JSON structure */
	else if (token->type == JSMN_OBJECT) {
		/* Anonymous object - show as generic object with members */
		proto_item *ti = NULL;
		proto_tree *subtree = tree;
		const char *obj_name = (path_depth > 0) ? path_parts[path_depth - 1] : NULL;

		if (tree) {
			ti = proto_tree_add_item(tree, hf_json_object, tvb,
				token->start, token->end - token->start, ENC_UTF_8);
			if (ti) {
				const char *obj_display = (token->size == 0) ? "{}" : "{...}";
				if (obj_name) {
					// Check if this is an array element
					const char *bracket = strchr(obj_name, '[');
					if (bracket) {
						// Array element  extract index and show as "0: {...}"
						int array_idx = 0;
						sscanf(bracket + 1, "%d", &array_idx);
						proto_item_set_text(ti, "%d: %s", array_idx, obj_display);
					} else {
						// Regular object with key name
						proto_item_set_text(ti, "%s: %s", obj_name, obj_display);
					}
				} else {
					// Root object
					proto_item_set_text(ti, "%s", obj_display);
				}
				subtree = proto_item_add_subtree(ti, ett_json_plus_object);
			}
		}

		// Iterate members and look up children in dictionary
		int child_idx = token_idx + 1;
		int i;

		for (i = 0; i < token->size; i++) {
			// Get key
			jsmntok_t *key_token = &tokens[child_idx];
			if (key_token->type != JSMN_STRING) {
				child_idx++;
				continue;
			}

			char *key_str = wmem_strndup(pool,
				json_buf + key_token->start,
				key_token->end - key_token->start);

			/* Move to value */
			child_idx++;

			/* Add key to path */
			if (path_depth < JSON_PLUS_MAX_PATH_DEPTH) {
				path_parts[path_depth] = key_str;

				// Process value with updated path
				int consumed = jsonplus_display_json_tree_dict(tvb, subtree, pinfo, pool, tokens,
					child_idx, json_buf, path_parts, path_depth + 1);
				child_idx += consumed;
			} else {
				child_idx++;
			}
		}

		tokens_consumed = child_idx - token_idx;
	}
	else if (token->type == JSMN_ARRAY) {
		/* Anonymous array  show as generic array with elements */
		proto_item *ti = NULL;
		proto_tree *subtree = tree;
		const char *array_name = (path_depth > 0) ? path_parts[path_depth - 1] : NULL;

		if (tree) {
			if (array_name && !strchr(array_name, '[')) {
				// Show with key name
				ti = proto_tree_add_none_format(tree, hf_json_array, tvb,
					token->start, token->end - token->start,
					"%s: []", array_name);
			} else if (array_name && strchr(array_name, '[')) {
				/* Array element containing an array - show as "0: []" */
				int array_idx = 0;
				const char *bracket = strchr(array_name, '[');
				sscanf(bracket + 1, "%d", &array_idx);
				ti = proto_tree_add_none_format(tree, hf_json_array, tvb,
					token->start, token->end - token->start,
					"%d: []", array_idx);
			} else {
				// Root array
				ti = proto_tree_add_none_format(tree, hf_json_array, tvb,
					token->start, token->end - token->start,
					"[]");
			}
			if (ti) {
				subtree = proto_item_add_subtree(ti, ett_json_plus_array);
			}
		}

		/* Iterate array elements */
		int child_idx = token_idx + 1;
		int i;

		for (i = 0; i < token->size; i++) {
			char *elem_path;

			/* Construct path like "items[5]" from parent */
			if (path_depth > 0) {
				elem_path = wmem_strdup_printf(pool, "%s[%d]", path_parts[path_depth - 1], i);
			} else {
				elem_path = wmem_strdup_printf(pool, "[%d]", i);
			}

			if (path_depth < JSON_PLUS_MAX_PATH_DEPTH) {
				/* Update path with array index (guard against path_depth==0 underflow) */
				const char *orig_path = (path_depth > 0) ? path_parts[path_depth - 1] : NULL;
				if (path_depth > 0) {
					path_parts[path_depth - 1] = elem_path;
				}

				/* Process element */
				int consumed = jsonplus_display_json_tree_dict(tvb, subtree, pinfo, pool, tokens,
					child_idx, json_buf, path_parts, path_depth);
				child_idx += consumed;

				/* Restore original path */
				if (path_depth > 0 && orig_path) {
					path_parts[path_depth - 1] = orig_path;
				}
			} else {
				int consumed = jsonplus_count_json_tokens(tokens, child_idx, path_depth);
				child_idx += consumed;
			}
		}

		tokens_consumed = child_idx - token_idx;
	}
	else if (token->type == JSMN_STRING) {
		/* Anonymous string */
		if (tree) {
			int token_len = token->end - token->start;
			char *str_value = wmem_strndup(pool, json_buf + token->start, token_len);
			const char *key_name = (path_depth > 0) ? path_parts[path_depth - 1] : NULL;
			bool is_array_elem = (key_name && strchr(key_name, '['));

			if (key_name && !is_array_elem) {
				/* Show with key name (not an array element) */
				proto_tree_add_string_format(tree, hf_json_value_string, tvb,
					token->start, token_len, str_value,
					"%s: %s", key_name, str_value);
			} else if (is_array_elem) {
				/* Array element - show as "0: value" */
				int array_idx = 0;
				const char *bracket = strchr(key_name, '[');
				sscanf(bracket + 1, "%d", &array_idx);
				proto_tree_add_string_format(tree, hf_json_value_string, tvb,
					token->start, token_len, str_value,
					"%d: %s", array_idx, str_value);
			} else {
				// No key fallback
				proto_tree_add_string(tree, hf_json_value_string, tvb,
					token->start, token_len, str_value);
			}
		}
		tokens_consumed = 1;
	}
	else if (token->type == JSMN_PRIMITIVE) {
		/* Anonymous (number, boolean, null) */
		if (tree) {
			int token_len = token->end - token->start;
			const char *value_str = json_buf + token->start;
			const char *key_name = (path_depth > 0) ? path_parts[path_depth - 1] : NULL;
			bool is_array_elem = (key_name && strchr(key_name, '['));
			int array_idx = 0;

			if (is_array_elem) {
				const char *bracket = strchr(key_name, '[');
				sscanf(bracket + 1, "%d", &array_idx);
			}

			if (token_len == 4 && strncmp(value_str, "null", 4) == 0) {
				if (key_name && !is_array_elem) {
					proto_tree_add_none_format(tree, hf_json_value_null, tvb,
						token->start, token_len, "%s: null", key_name);
				} else if (is_array_elem) {
					proto_tree_add_none_format(tree, hf_json_value_null, tvb,
						token->start, token_len, "%d: null", array_idx);
				} else {
					proto_tree_add_item(tree, hf_json_value_null, tvb,
						token->start, token_len, ENC_NA);
				}
			}
			else if (token_len == 4 && strncmp(value_str, "true", 4) == 0) {
				if (key_name && !is_array_elem) {
					proto_tree_add_none_format(tree, hf_json_value_true, tvb,
						token->start, token_len, "%s: true", key_name);
				} else if (is_array_elem) {
					proto_tree_add_none_format(tree, hf_json_value_true, tvb,
						token->start, token_len, "%d: true", array_idx);
				} else {
					proto_tree_add_item(tree, hf_json_value_true, tvb,
						token->start, token_len, ENC_NA);
				}
			}
			else if (token_len == 5 && strncmp(value_str, "false", 5) == 0) {
				if (key_name && !is_array_elem) {
					proto_tree_add_none_format(tree, hf_json_value_false, tvb,
						token->start, token_len, "%s: false", key_name);
				} else if (is_array_elem) {
					proto_tree_add_none_format(tree, hf_json_value_false, tvb,
						token->start, token_len, "%d: false", array_idx);
				} else {
					proto_tree_add_item(tree, hf_json_value_false, tvb,
						token->start, token_len, ENC_NA);
				}
			}
			else {
				/* Number - parse as double */
				char *num_str = wmem_strndup(pool, value_str, token_len);
				double num_val = g_ascii_strtod(num_str, NULL);
				if (key_name && !is_array_elem) {
					proto_tree_add_double_format(tree, hf_json_value_number, tvb,
						token->start, token_len, num_val,
						"%s: %g", key_name, num_val);
				} else if (is_array_elem) {
					proto_tree_add_double_format(tree, hf_json_value_number, tvb,
						token->start, token_len, num_val,
						"%d: %g", array_idx, num_val);
				} else {
					proto_tree_add_double(tree, hf_json_value_number, tvb,
						token->start, token_len, num_val);
				}
			}
		}
		tokens_consumed = 1;
	}

	return tokens_consumed;
}

// End of JSON+ (Dictionary-Driven) Dissection Functions

static void
register_static_headers(void) {

	json_header_fields_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

}

/* Read CLI-only preference from preferences file
 * Only reads and sets the preference if running in tshark */
static void
read_cli_parser_preference(void)
{
	char *pref_file = get_persconffile_path("preferences", TRUE, NULL);
	FILE *fp;
	char line[512];
	bool is_tshark = false;

	/* Default to FALSE */
	gbl_json_run_external_parsers_cli = false;

	/* Detect if we're running tshark by checking the executable name */
#ifdef __linux__
	char exe_path[512];
	ssize_t len;
	len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len != -1) {
		exe_path[len] = '\0';
		/* Check if executable name contains tshark */
		if (strstr(exe_path, "tshark") != NULL) {
			is_tshark = true;
		}
	}
#else
	is_tshark = true;
#endif

	/* If not tshark, don't read CLI preference */
	if (!is_tshark) {
		g_free(pref_file);
		return;
	}

	if (!pref_file) {
		g_free(pref_file);
		return;
	}

	fp = ws_fopen(pref_file, "r");
	if (!fp) {
		g_free(pref_file);
		return;
	}

	/* Search for json.plus_run_external_parsers_cli line */
	while (fgets(line, sizeof(line), fp)) {
		/* Look for our CLI preference */
		if (strstr(line, "json.plus_run_external_parsers_cli:") != NULL) {
			/* Check if it's set to TRUE */
			if (strstr(line, "TRUE") != NULL || strstr(line, "true") != NULL) {
				gbl_json_run_external_parsers_cli = true;
			}
			break;
		}
	}

	fclose(fp);
	g_free(pref_file);
}

static void
json_prefs_apply(void)
{
	// On first call (initialization)
	if (!gbl_json_parser_prefs_initialized) {
		gbl_json_run_external_parsers = false;

		/* Read CLI-only preference from file for tshark */
		read_cli_parser_preference();

		gbl_json_parser_prefs_initialized = true;
	}
}

/* Forward declaration: the definition is just below common_register_json,
 * which references it in register_shutdown_routine(). */
static void json_plus_dictionary_shutdown(void);

static void
common_register_json(void)
{
	static hf_register_info hf[] = {
		{ &hf_json_array,
			{ "Array", "json.array",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON array", HFILL }
		},
		{ &hf_json_object,
			{ "Object", "json.object",
			  FT_STRING, BASE_NONE|BASE_NO_DISPLAY_VALUE, NULL, 0x00,
			  "JSON object", HFILL }
		},
		{ &hf_json_member,
			{ "Member", "json.member",
			  FT_STRING, BASE_NONE, NULL, 0x00,
			  "JSON object member", HFILL }
		},
		{ &hf_json_key,
			{ "Key", "json.key",
			  FT_STRING, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_json_path,
			{ "Path", "json.path",
			  FT_STRING, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_json_path_with_value,
			{ "Path with value", "json.path_with_value",
			  FT_STRING, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_json_member_with_value,
			{ "Member with value", "json.member_with_value",
			  FT_STRING, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_json_value_string,
			{ /* FT_STRINGZ? */ 	 "String value", "json.value.string",
			  FT_STRING, BASE_NONE, NULL, 0x00,
			  "JSON string value", HFILL }
		},
		{ &hf_json_value_number,
			{ "Number value", "json.value.number",
			  FT_DOUBLE, BASE_NONE, NULL, 0x00,
			  "JSON number value", HFILL }
		},
		{ &hf_json_value_false,
			{ "False value", "json.value.false",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON false value", HFILL }
		},
		{ &hf_json_value_null,
			{ "Null value", "json.value.null",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON null value", HFILL }
		},
		{ &hf_json_value_true,
			{ "True value", "json.value.true",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON true value", HFILL }
		},
		{ &hf_json_value_nan,
			{ "NaN value", "json.value.nan",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON NaN value", HFILL }
		},
		{ &hf_json_array_compact,
			{ "Array compact", "json.array_compact",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON array compact", HFILL }
		},
		{ &hf_json_object_compact,
			{ "Object compact", "json.object_compact",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON object compact", HFILL }
		},
		{ &hf_json_member_compact,
			{ "Member compact", "json.member_compact",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON member compact", HFILL }
		},
		{ &hf_json_array_item_compact,
			{ "Array item compact", "json.array_item_compact",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON array item compact", HFILL }
		},
		{ &hf_json_binary_data,
			{ "Binary data", "json.binary_data",
			  FT_BYTES, BASE_NONE, NULL, 0x00,
			  "JSON binary data", HFILL }
		},
		{ &hf_json_ignored_leading_bytes,
			{ "Ignored leading bytes", "json.ignored_leading_bytes",
			  FT_STRING, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_json_array_raw,
			{ "Array raw", "json.array_raw",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON array raw", HFILL }
		},
		{ &hf_json_object_raw,
			{ "Object raw", "json.object_raw",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON object raw", HFILL }
		},
		{ &hf_json_member_raw,
			{ "Member raw", "json.member_raw",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON member raw", HFILL }
		},
		{ &hf_json_array_item_raw,
			{ "Array item raw", "json.array_item_raw",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  "JSON array item raw", HFILL }
		},

	};

	static int *ett[] = {
		&ett_json,
		&ett_json_array,
		&ett_json_object,
		&ett_json_member,
		&ett_json_compact,
		&ett_json_array_compact,
		&ett_json_object_compact,
		&ett_json_member_compact,
		&ett_json_raw,
		&ett_json_array_raw,
		&ett_json_object_raw,
		&ett_json_member_raw,
		&ett_json_plus,
		&ett_json_plus_object,
		&ett_json_plus_array,
	};

	/* Expert info */
	static ei_register_info ei[] = {
		{ &ei_json_malformed,
		  { "json.malformed", PI_MALFORMED, PI_ERROR,
		    "Malformed JSON", EXPFILL }
		},
		{ &ei_json_plus_invalid_json,
		  { "json.plus.invalid_json", PI_MALFORMED, PI_ERROR,
		    "Invalid JSON syntax", EXPFILL }
		},
		{ &ei_json_plus_parse_error,
		  { "json.plus.parse_error", PI_MALFORMED, PI_ERROR,
		    "JSON parse error", EXPFILL }
		},
		{ &ei_json_plus_type_mismatch,
		  { "json.plus.type_mismatch", PI_PROTOCOL, PI_WARN,
		    "Field value does not match expected type", EXPFILL }
		},
	};

	module_t *json_module;

	proto_json = proto_register_protocol("JavaScript Object Notation", "JSON", "json");
	proto_register_field_array(proto_json, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register expert info for JSON+ */
	expert_module_t *expert_json = expert_register_protocol(proto_json);
	expert_register_field_array(expert_json, ei, array_length(ei));

	/* Initialize JSON+ dictionary structure */
	json_plus_dictionary.fields = wmem_tree_new(wmem_epan_scope());
	json_plus_dictionary.protocols = wmem_tree_new(wmem_epan_scope());
	json_plus_dictionary.types = NULL;
	json_plus_dictionary.has_case_insensitive_fields = false;
	json_plus_dictionary.path_matchers = NULL;
	json_plus_dictionary.all_protocols = NULL;
	json_plus_dictionary.has_any_protocol = false;
	json_plus_dictionary.wildcard_regexes = NULL;

	/* Load JSON+ dictionary from XML files */
	wmem_array_t *dynamic_hf_array = wmem_array_new(wmem_epan_scope(),
		sizeof(hf_register_info));
	GPtrArray *dynamic_ett_array = g_ptr_array_new();

	load_json_dictionary(dynamic_hf_array, dynamic_ett_array, &json_plus_dictionary);

	/* Register dynamic fields from dictionary */
	if (wmem_array_get_count(dynamic_hf_array) > 0) {
		proto_register_field_array(proto_json,
			(hf_register_info *)wmem_array_get_raw(dynamic_hf_array),
			wmem_array_get_count(dynamic_hf_array));
	}

	/* Register dynamic subtrees from dictionary */
	if (dynamic_ett_array->len > 0) {
		proto_register_subtree_array((int **)dynamic_ett_array->pdata,
			dynamic_ett_array->len);
	}

	g_ptr_array_free(dynamic_ett_array, true);

	json_handle = register_dissector("json", dissect_json, proto_json);
	json_file_handle = register_dissector("json_file", dissect_json_file, proto_json);

	/* Use register_shutdown_routine (program-exit hook), NOT
	 * register_cleanup_routine — the latter fires on every capture-file
	 * close (via epan_free → cleanup_dissection), which would wipe the
	 * dictionary's regex objects and path_matchers list between files,
	 * leaving subsequent file opens with no protocol dispatch. */
	register_shutdown_routine(json_plus_dictionary_shutdown);

	json_module = prefs_register_protocol(proto_json, json_prefs_apply);
	prefs_register_bool_preference(json_module, "compact_form",
		"Display JSON in compact form",
		"Display JSON like in browsers devtool",
		&json_compact);

	prefs_register_bool_preference(json_module, "raw_form",
		"Display JSON in raw form",
		"Display JSON like in vscode editor",
		&json_raw);

	prefs_register_bool_preference(json_module, "plus_form",
		"Display JSON in JSON+ form",
		"Display JSON with dictionary-driven field parsing",
		&json_plus);

	prefs_register_bool_preference(json_module, "auto_hide",
		"Hide tree or root item automatically",
		"Determine whether to hide the tree of original form or root item of compact, raw, or JSON+ form"
		" based on the enabled status of compact_form, raw_form, and plus_form preferences.",
		&auto_hide);

	prefs_register_bool_preference(json_module, "ignore_leading_bytes",
		"Ignore leading non JSON bytes",
		"Leading bytes will be ignored until first '[' or '{' is found.",
		&ignore_leading_bytes);

	prefs_register_bool_preference(json_module, "hide_extended_path_based_filtering",
		"Hide extended path based filtering",
		"Hide extended path based filtering",
		&hide_extended_path_based_filtering);

	prefs_register_bool_preference(json_module, "unescape_strings",
		"Replace character escapes with the escaped literal value",
		"Replace character escapes with the escaped literal value",
		&unescape_strings);

	/* JSON+ specific preferences */
	prefs_register_bool_preference(json_module, "plus_desegment",
		"JSON+: Reassemble JSON messages spanning multiple TCP segments",
		"Whether the JSON+ dissector should reassemble messages "
		"spanning multiple TCP segments. "
		"To use this option, you must also enable "
		"\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&gbl_json_desegment);

	/* Register parser preference  */
	prefs_register_bool_preference(json_module, "plus_run_external_parsers",
		"JSON+: Run external parsers for this session",
		"Check to run the external parser defined in the dictionary for the duration that wireshark is open.",
		&gbl_json_run_external_parsers);

	prefs_register_obsolete_preference(json_module, "plus_run_external_parsers_cli");

	/* Fill hash table with static headers */
	register_static_headers();
}

/* Cleanup wrapper for register_shutdown_routine(): free ws_regex_t objects
 * and GSList scaffolding owned by the JSON+ dictionary at program exit. */
static void
json_plus_dictionary_shutdown(void)
{
	json_dictionary_cleanup(&json_plus_dictionary);
}

void
proto_register_json(void)
{
	common_register_json();
}

void
event_register_json(void)
{
	common_register_json();
}


static void common_reg_handoff_json(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_JSON, json_file_handle);

	dissector_add_string("media_type", "application/json", json_handle); /* RFC 4627 */
	dissector_add_string("media_type", "application/senml+json", json_handle); /* RFC 8428 */
	dissector_add_string("media_type", "application/sensml+json", json_handle); /* RFC 8428 */
	dissector_add_string("media_type", "application/json-rpc", json_handle); /* JSON-RPC over HTTP */
	dissector_add_string("media_type", "application/jsonrequest", json_handle); /* JSON-RPC over HTTP */
	dissector_add_string("media_type", "application/dds-web+json", json_handle); /* DDS Web Integration Service over HTTP */
	dissector_add_string("media_type", "application/vnd.oma.lwm2m+json", json_handle); /* LWM2M JSON over CoAP */
	dissector_add_string("media_type", "application/problem+json", json_handle); /* RFC 7807 Problem Details for HTTP APIs*/
	dissector_add_string("media_type", "application/merge-patch+json", json_handle); /* RFC 7386 HTTP PATCH methods (RFC 5789) */
	dissector_add_string("media_type", "application/json-patch+json", json_handle); /* RFC 6902 JavaScript Object Notation (JSON) Patch */
	dissector_add_string("media_type", "application/x-ndjson", json_handle);
	dissector_add_string("media_type", "application/3gppHal+json", json_handle);

	text_lines_handle = find_dissector_add_dependency("data-text-lines", proto_json);
}

void
proto_reg_handoff_json(void)
{
	common_reg_handoff_json();
	heur_dissector_add("http", dissect_json_heur, "JSON over HTTP", "json_http", proto_json, HEURISTIC_DISABLE);
	heur_dissector_add("hpfeeds", dissect_json_heur, "JSON over HPFEEDS", "json_hpfeeds", proto_json, HEURISTIC_ENABLE);
	heur_dissector_add("db-lsp", dissect_json_heur, "JSON over DB-LSP", "json_db_lsp", proto_json, HEURISTIC_ENABLE);
	heur_dissector_add("udp", dissect_json_acdr_heur, "JSON over AC DR", "json_acdr", proto_json, HEURISTIC_ENABLE);

	dissector_add_for_decode_as("udp.port", json_file_handle);
	dissector_add_for_decode_as("nats.subject", json_handle);

	dissector_add_string("media_type.suffix", "json", json_handle);  /* RFC 6839 */
	dissector_add_string("grpc_message_type", "application/grpc+json", json_handle);
	dissector_add_uint_range_with_preference("tcp.port", "", json_file_handle); /* JSON-RPC over TCP */
	dissector_add_uint_range_with_preference("udp.port", "", json_file_handle); /* JSON-RPC over UDP */

	proto_acdr = proto_get_id_by_filter_name("acdr");
	proto_http = proto_get_id_by_filter_name("http");
}


void
event_reg_handoff_json(void)
{
	common_reg_handoff_json();
	falco_json_handle = find_dissector("falcojson");
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
