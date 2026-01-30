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
#include <epan/tvbparse.h>
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

#include <wiretap/wtap.h>

#include "packet-media-type.h"
#include "packet-acdr.h"
#include "packet-json.h"
#include "json-dictionary.h"

void proto_register_json(void);
void event_register_json(void);
void proto_reg_handoff_json(void);
void event_reg_handoff_json(void);

static char* json_string_unescape(wmem_allocator_t *scope, const char *string, size_t *length_ptr);
static const char* get_json_string(wmem_allocator_t *scope, tvbparse_elem_t *tok, bool remove_quotes);

static dissector_handle_t json_handle;
static dissector_handle_t json_file_handle;

static int proto_json;

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

/* Expert info identifiers for JSON+ */
static expert_field ei_json_plus_invalid_json = EI_INIT;
static expert_field ei_json_plus_parse_error = EI_INIT;
static expert_field ei_json_plus_type_mismatch = EI_INIT;

/* Global dictionary for JSON+ (loaded from XML) */
static json_dictionary_t json_plus_dictionary;

/* JSON+ constants */
#define JSON_PLUS_MAX_TOKENS 4096
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

static tvbparse_wanted_t* want;
static tvbparse_wanted_t* want_ignore;

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
} json_parser_data_t;

#define JSON_COMPACT_TOP_ITEM -3
#define JSON_COMPACT_OBJECT_WITH_KEY -2
#define JSON_COMPACT_OBJECT_WITHOUT_KEY -1
#define JSON_COMPACT_ARRAY 0

#define JSON_ARRAY_BEGIN(json_tvbparse_data) wmem_stack_push(json_tvbparse_data->array_idx, GINT_TO_POINTER(JSON_COMPACT_ARRAY))
#define JSON_OBJECT_BEGIN(json_tvbparse_data) wmem_stack_push(json_tvbparse_data->array_idx, GINT_TO_POINTER(JSON_COMPACT_OBJECT_WITHOUT_KEY))
#define JSON_ARRAY_OBJECT_END(json_tvbparse_data) wmem_stack_pop(json_tvbparse_data->array_idx)
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
				/* not valid by JSON grammar (tvbparse rules should not allow it) */
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
get_json_string(wmem_allocator_t *scope, tvbparse_elem_t *tok, bool remove_quotes)
{
	char *string;
	size_t length;

	string = (char*)tvb_get_string_enc(scope, tok->tvb, tok->offset, tok->len, ENC_UTF_8);

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

static proto_item*
json_key_lookup(proto_tree* tree, tvbparse_elem_t* tok, const char* key_str, packet_info* pinfo, bool use_compact)
{
	proto_item* ti;
	int hf_id;
	int offset, len;

	json_data_decoder_t* json_data_decoder_rec = (json_data_decoder_t*)g_hash_table_lookup(json_header_fields_hash, key_str);
	if (json_data_decoder_rec == NULL) {
		return NULL;
	}

	hf_id = *json_data_decoder_rec->hf_id;
	DISSECTOR_ASSERT(hf_id > 0);

	int proto_id = proto_registrar_is_protocol(hf_id) ? hf_id : proto_registrar_get_parent(hf_id);
	if (!proto_is_protocol_enabled(find_protocol_by_id(proto_id))) {
		return NULL;
	}

	/*
	 * use_compact == true: "tok is the composed element of the member"
	 *	This is only called from before_member when the value is a
	 /	JSON_TOKEN_STRING.
	 * use_compact == false: "tok is the composed element whose subelement is the value"
	 *	For this, arrays with matching key are passed in before_array,
	 *	strings are passed in after_value, and other types aren't passed in.
	 */
	const tvbparse_elem_t* value_tok = tok;
	if (use_compact) {
		/* tok refers to the member ("key":"value")
		 * tok->sub is the key string
		 * tok->sub->next is the ':'
		 * tok->sub->last is a set with one element
		 * tok->sub->last->sub is the value
		 */
		DISSECTOR_ASSERT(tok->sub);
		value_tok = tok->sub->last;
	}
	/* tok is a set with one element
	 * tok->sub is the value
	 */
	DISSECTOR_ASSERT(value_tok && value_tok->sub);
	value_tok = value_tok->sub;

	json_token_type_t value_id = (json_token_type_t)value_tok->id;

	offset = value_tok->offset;
	len = value_tok->len;
	/* Remove the quotation marks from strings (the decoder functions
	 * apparently expect that.)
	 */
	if (value_id == JSON_TOKEN_STRING && len >= 2) {
		offset += 1;
		len -= 2;
	}
	/* XXX - Every hf_id in packet-json_3gpp.c is a FT_STRING. Should other
	 * types be supported (perhaps verified against the JSON token type?)
	 * Should the encoding be ENC_UTF_8? Should the string be unescaped here?
	 */
	ti = proto_tree_add_item(tree, hf_id, tok->tvb, offset, len, ENC_ASCII);
	if (json_data_decoder_rec->json_data_decoder) {
		(*json_data_decoder_rec->json_data_decoder)(value_tok->tvb, tree, pinfo, offset, len, key_str);
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
	tvbparse_t *tt;

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

	// Check if JSON+ mode is enabled with a custom protocol name
	if (json_plus && json_plus_dictionary.protocols) {
		// Look up protocol by destination or source port
		json_protocol_t *protocol = (json_protocol_t *)wmem_tree_lookup32(
			json_plus_dictionary.protocols, pinfo->destport);

		if (!protocol) {
			// Try source port (for server responses)
			protocol = (json_protocol_t *)wmem_tree_lookup32(
				json_plus_dictionary.protocols, pinfo->srcport);
		}

		if (protocol && protocol->display_name) {
			// Use custom protocol display name
			col_set_str(pinfo->cinfo, COL_PROTOCOL, protocol->display_name);
		} else {
			// Fallback to default
			col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "JSON");
		}
	} else {
		col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "JSON");
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

	if (json_plus) {
		// JSON+ (dictionary-driven) dissection
		proto_tree* json_tree_plus = json_hide_root_item() ? json_tree :
			proto_tree_add_subtree(json_tree, tvb, 0, -1, ett_json_plus, NULL, "JSON+ form:");

		// Get JSON data for JSON+ parser
		unsigned len = tvb_reported_length_remaining(tvb, offset);
		const char *json_buf = (const char *)tvb_memdup(pinfo->pool, tvb, offset, len);

		// Validate JSON
		bool is_valid = json_validate((const uint8_t *)json_buf, len);

		if (!is_valid) {
			proto_item *item = proto_tree_add_item(json_tree_plus, hf_json_binary_data,
				tvb, offset, len, ENC_UTF_8);
			proto_item_append_text(ti, " [Invalid JSON]");
			expert_add_info(pinfo, item, &ei_json_plus_invalid_json);
		} else {
			// Allocate token array for parsing
			jsmntok_t *tokens = wmem_alloc_array(pinfo->pool, jsmntok_t, JSON_PLUS_MAX_TOKENS);

			// Parse JSON
			int num_tokens = json_parse_len(json_buf, len, tokens, JSON_PLUS_MAX_TOKENS);

			if (num_tokens < 0) {
				// Parse error
				proto_item *item = proto_tree_add_item(json_tree_plus, hf_json_binary_data,
					tvb, offset, len, ENC_UTF_8);
				proto_item_append_text(ti, " [JSON Parse Error: %d]", num_tokens);
				expert_add_info_format(pinfo, item, &ei_json_plus_parse_error,
					"JSON parse error: %d", num_tokens);
			} else if (num_tokens > 0) {
				// Check if dictionary is loaded
				if (json_plus_dictionary.fields) {
					const char *path_parts[JSON_PLUS_MAX_PATH_DEPTH];
					jsonplus_display_json_tree_dict(tvb, json_tree_plus, pinfo, pinfo->pool, tokens, 0, json_buf,
						path_parts, 0);
				} else {
					proto_tree_add_expert_format(json_tree_plus, pinfo, &ei_json_plus_parse_error,
						tvb, offset, len,
						"JSON+ dictionary not loaded. Check resources/protocols/json/config.txt");
				}
			}
		}
	}

	tt = tvbparse_init(pinfo->pool, tvb, offset, buffer_length - offset, &parser_data, want_ignore);

	/* only one json in packet? */
	while (tvbparse_get(tt, want))
	{ }

	offset = tvbparse_curr_offset(tt);

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

static void
before_object(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
	proto_tree *subtree;
	proto_item *ti;

	ti = proto_tree_add_item(tree, hf_json_object, tok->tvb, tok->offset, tok->len, ENC_UTF_8);
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
			ti_compact = proto_tree_add_none_format(tree_compact, hf_json_object_compact, tok->tvb, tok->offset, tok->len, "%d:", idx);
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
			ti_raw = proto_tree_add_none_format(tree_raw, hf_json_object_raw, tok->tvb, tok->offset, tok->len, "{");
		}

		subtree_raw = proto_item_add_subtree(ti_raw, ett_json_object_raw);
		wmem_stack_push(data->stack_raw, subtree_raw);

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_BEGIN_OBJECT;
	}
}

static void
after_object(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t* tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

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
		proto_item* ti_raw;
		if (data->prev_item_type_raw == JSON_MARK_TYPE_BEGIN_OBJECT) { /* an empty object */
			ti_raw = data->prev_item_raw;
			proto_item_append_text(ti_raw, "}");
		} else {
			tvbparse_elem_t* tok_last = tok->sub->last;
			ti_raw = proto_tree_add_none_format(parent_tree, hf_json_object_raw, tok_last->tvb, tok_last->offset, tok_last->len, "}");
		}
		wmem_stack_pop(data->stack_raw);

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_END_OBJECT;
	}
}

static void
before_member(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
	proto_tree *subtree;
	proto_item *ti;

	const char* key_string_without_quotation_marks = get_json_string(data->pinfo->pool, tok->sub, true);

	ti = proto_tree_add_string(tree, hf_json_member, tok->tvb, tok->offset, tok->len, key_string_without_quotation_marks);

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
		proto_item *ti_compact = NULL;

		tvbparse_elem_t *key_tok = tok->sub;

		if (key_tok && key_tok->id == JSON_TOKEN_STRING) {
			ti_compact = json_key_lookup(tree_compact, tok, key_string_without_quotation_marks, data->pinfo, true);
			if (!ti_compact) {
				ti_compact = proto_tree_add_none_format(tree_compact, hf_json_member_compact, tok->tvb, tok->offset, tok->len, "\"%s\":", key_string_without_quotation_marks);
			}
		} else {
			ti_compact = proto_tree_add_item(tree_compact, hf_json_member_compact, tok->tvb, tok->offset, tok->len, ENC_NA);
		}

		subtree_compact = proto_item_add_subtree(ti_compact, ett_json_member_compact);
		wmem_stack_push(data->stack_compact, subtree_compact);
	}

	if (json_raw) {
		proto_tree* tree_raw = (proto_tree*)wmem_stack_peek(data->stack_raw);
		proto_tree* subtree_raw;
		proto_item* ti_raw = NULL;
		tvbparse_elem_t* key_tok = tok->sub;

		if (data->prev_item_raw && data->prev_item_type_raw != JSON_MARK_TYPE_BEGIN_OBJECT && data->prev_item_type_raw != JSON_MARK_TYPE_BEGIN_ARRAY) {
			proto_item_append_text(data->prev_item_raw, ",");
		}

		if (key_tok && key_tok->id == JSON_TOKEN_STRING) {
			ti_raw = json_key_lookup(tree_raw, tok, key_string_without_quotation_marks, data->pinfo, true);
			if (!ti_raw) {
				ti_raw = proto_tree_add_none_format(tree_raw, hf_json_member_raw, tok->tvb, tok->offset, tok->len, "\"%s\":", key_string_without_quotation_marks);
			}
		} else {
			ti_raw = proto_tree_add_item(tree_raw, hf_json_member_raw, tok->tvb, tok->offset, tok->len, ENC_NA);
		}

		subtree_raw = proto_item_add_subtree(ti_raw, ett_json_member_raw);
		wmem_stack_push(data->stack_raw, subtree_raw);

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_MEMBER_NAME;
	}
}

static void
after_member(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	proto_tree *tree = (proto_tree *)wmem_stack_pop(data->stack);

	tvbparse_elem_t* key_tok = tok->sub;
	if (tree && key_tok && key_tok->id == JSON_TOKEN_STRING) {

		const char* key_string_without_quotation_marks = get_json_string(data->pinfo->pool, key_tok, true);

		proto_tree_add_string(tree, hf_json_key, key_tok->tvb, key_tok->offset, key_tok->len, key_string_without_quotation_marks);
	}

	// extended path based filtering
	wmem_stack_pop(data->stack_path); // Pop key
	char* path = (char*)wmem_stack_pop(data->stack_path);
	if (tree)
	{
		proto_item* path_item = proto_tree_add_string(tree, hf_json_path, tok->tvb, tok->offset, tok->len, path);
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

static void
before_array(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
	proto_tree *subtree;
	proto_item *ti;

	ti = proto_tree_add_item(tree, hf_json_array, tok->tvb, tok->offset, tok->len, ENC_NA);
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

	// Try key_lookup
	json_key_lookup(tree, tok, last_key_string, data->pinfo, false);

	if (json_compact) {
		proto_tree* tree_compact = (proto_tree*)wmem_stack_peek(data->stack_compact);
		proto_tree* subtree_compact;
		proto_item* ti_compact;

		int idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));

		if (JSON_INSIDE_ARRAY(idx)) {
			ti_compact = proto_tree_add_none_format(tree_compact, hf_json_array_compact, tok->tvb, tok->offset, tok->len, "%d:", idx);
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
			ti_raw = proto_tree_add_none_format(tree_raw, hf_json_array_raw, tok->tvb, tok->offset, tok->len, "[");
		}

		subtree_raw = proto_item_add_subtree(ti_raw, ett_json_array_raw);
		wmem_stack_push(data->stack_raw, subtree_raw);

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_BEGIN_ARRAY;
	}
}

static void
after_array(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t* tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

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
		proto_item* ti_raw;
		if (data->prev_item_type_raw == JSON_MARK_TYPE_BEGIN_ARRAY) { /* an empty array */
			ti_raw = data->prev_item_raw;
			proto_item_append_text(ti_raw, "]");
		} else {
			tvbparse_elem_t* tok_last = tok->sub->last;
			ti_raw = proto_tree_add_none_format(parent_tree, hf_json_array_raw, tok_last->tvb, tok_last->offset, tok_last->len, "]");
		}
		wmem_stack_pop(data->stack_raw);

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_END_ARRAY;
	}
}

static void
after_value(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
	json_token_type_t value_id = tok->sub ? (json_token_type_t)tok->sub->id : JSON_TOKEN_INVALID;

	if (!(value_id == JSON_TOKEN_STRING || value_id == JSON_TOKEN_NUMBER || value_id == JSON_TOKEN_FALSE
		|| value_id == JSON_TOKEN_NULL || value_id == JSON_TOKEN_TRUE || value_id == JSON_TOKEN_NAN))
	{
		return;
	}

	// extended path based filtering
	char* key_string = (char*)wmem_stack_pop(data->stack_path);
	char* path = (char*)wmem_stack_pop(data->stack_path);

	const char* value_str = NULL;
	if (value_id == JSON_TOKEN_STRING && tok->len >= 2)
	{
		value_str = get_json_string(data->pinfo->pool, tok, true);
	}
	else
	{
		value_str = get_json_string(data->pinfo->pool, tok, false);
	}

	char* path_with_value = join_strings(data->pinfo->pool, path, value_str, ':');
	char* memeber_with_value = join_strings(data->pinfo->pool, key_string, value_str, ':');
	proto_item* path_with_value_item = proto_tree_add_string(tree, hf_json_path_with_value, tok->tvb, tok->offset, tok->len, path_with_value);
	proto_item* member_with_value_item = proto_tree_add_string(tree, hf_json_member_with_value, tok->tvb, tok->offset, tok->len, memeber_with_value);

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
		case JSON_TOKEN_STRING:
			if (tok->len >= 2) {
				// Try key_lookup
				proto_item *key_lookup = NULL;
				key_lookup = json_key_lookup(tree, tok, key_string, data->pinfo, false);
				if (!key_lookup) {
					proto_tree_add_string(tree, hf_json_value_string, tok->tvb, tok->offset, tok->len, value_str);
				}
			}
			else
			{
				proto_tree_add_item(tree, hf_json_value_string, tok->tvb, tok->offset, tok->len, ENC_ASCII | ENC_NA);
			}

			break;

		case JSON_TOKEN_NUMBER:
			proto_tree_add_double(tree, hf_json_value_number, tok->tvb, tok->offset, tok->len, g_ascii_strtod(value_str, NULL));

			break;

		case JSON_TOKEN_FALSE:
			proto_tree_add_item(tree, hf_json_value_false, tok->tvb, tok->offset, tok->len, ENC_NA);

			break;

		case JSON_TOKEN_NULL:
			proto_tree_add_item(tree, hf_json_value_null, tok->tvb, tok->offset, tok->len, ENC_NA);

			break;

		case JSON_TOKEN_TRUE:
			proto_tree_add_item(tree, hf_json_value_true, tok->tvb, tok->offset, tok->len, ENC_NA);

			break;

		case JSON_TOKEN_NAN:
			proto_tree_add_item(tree, hf_json_value_nan, tok->tvb, tok->offset, tok->len, ENC_NA);

			break;

		default:
			proto_tree_add_format_text(tree, tok->tvb, tok->offset, tok->len);
			break;
	}

	if (json_compact) {
		proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);

		int idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));

		char *val_str = (char*)tvb_get_string_enc(data->pinfo->pool, tok->tvb, tok->offset, tok->len, ENC_UTF_8);

		if (JSON_INSIDE_ARRAY(idx)) {
			proto_tree_add_none_format(tree_compact, hf_json_array_item_compact, tok->tvb, tok->offset, tok->len, "%d: %s", idx, val_str);
			json_array_index_increment(data);
		} else {
			proto_item *parent_item = proto_tree_get_parent(tree_compact);
			proto_item_append_text(parent_item, " %s", val_str);
		}
	}

	if (json_raw) {
		proto_tree* tree_raw = (proto_tree*)wmem_stack_peek(data->stack_raw);
		proto_item* ti_raw;
		char* val_str = (char*)tvb_get_string_enc(data->pinfo->pool, tok->tvb, tok->offset, tok->len, ENC_UTF_8);

		if (data->prev_item_raw && data->prev_item_type_raw == JSON_MARK_TYPE_VALUE) {
			proto_item_append_text(data->prev_item_raw, ","); /* this value is an element of an array */
		}

		if (data->prev_item_raw && data->prev_item_type_raw == JSON_MARK_TYPE_MEMBER_NAME) {
			ti_raw = proto_tree_get_parent(tree_raw);
			proto_item_append_text(ti_raw, " %s", val_str);
		} else {
			ti_raw = proto_tree_add_none_format(tree_raw, hf_json_array_item_raw, tok->tvb, tok->offset, tok->len, "%s", val_str);
		}

		data->prev_item_raw = ti_raw;
		data->prev_item_type_raw = JSON_MARK_TYPE_VALUE;
	}
}

static void
init_json_parser(void) {
	static tvbparse_wanted_t _want_object;
	static tvbparse_wanted_t _want_array;

	tvbparse_wanted_t *want_object, *want_array;
	tvbparse_wanted_t *want_member;
	tvbparse_wanted_t *want_string;
	tvbparse_wanted_t *want_number, *want_int;
	tvbparse_wanted_t *want_value;
	tvbparse_wanted_t *want_value_separator;

#define tvbparse_optional(id, private_data, before_cb, after_cb, wanted) \
	tvbparse_some(id, 0, 1, private_data, before_cb, after_cb, wanted)

	tvbparse_wanted_t *want_quot = tvbparse_char(-1,"\"",NULL,NULL,NULL);

	want_string = tvbparse_set_seq(JSON_TOKEN_STRING, NULL, NULL, NULL,
			want_quot,
			tvbparse_some(-1, 0, INT_MAX, NULL, NULL, NULL,
				tvbparse_set_oneof(-1, NULL, NULL, NULL,
					tvbparse_not_chars(-1, 0, 0, "\"" "\\", NULL, NULL, NULL), /* XXX, without invalid unicode characters */
					tvbparse_set_seq(-1, NULL, NULL, NULL,
						tvbparse_char(-1, "\\", NULL, NULL, NULL),
						tvbparse_set_oneof(-1, NULL, NULL, NULL,
							tvbparse_chars(-1, 0, 1, "\"" "\\" "/bfnrt", NULL, NULL, NULL),
							tvbparse_set_seq(-1, NULL, NULL, NULL,
								tvbparse_char(-1, "u", NULL, NULL, NULL),
								tvbparse_chars(-1, 4, 4, "0123456789abcdefABCDEF", NULL, NULL, NULL),
								NULL),
							NULL),
						NULL),
					NULL)
				),
			want_quot,
			NULL);

	want_value_separator = tvbparse_char(-1, ",", NULL, NULL, NULL);

	/* int = zero / ( digit1-9 *DIGIT ) */
	want_int = tvbparse_set_oneof(-1, NULL, NULL, NULL,
			tvbparse_char(-1, "0", NULL, NULL, NULL),
			tvbparse_set_seq(-1, NULL, NULL, NULL,
				tvbparse_chars(-1, 1, 1, "123456789", NULL, NULL, NULL),
				tvbparse_optional(-1, NULL, NULL, NULL, /* tvbparse_chars() don't respect 0 as min_len ;/ */
					tvbparse_chars(-1, 0, 0, "0123456789", NULL, NULL, NULL)),
				NULL),
			NULL);

	/* number = [ minus ] int [ frac ] [ exp ] */
	want_number = tvbparse_set_seq(JSON_TOKEN_NUMBER, NULL, NULL, NULL,
			tvbparse_optional(-1, NULL, NULL, NULL, /* tvbparse_chars() don't respect 0 as min_len ;/ */
				tvbparse_chars(-1, 0, 1, "-", NULL, NULL, NULL)),
			want_int,
			/* frac = decimal-point 1*DIGIT */
			tvbparse_optional(-1, NULL, NULL, NULL,
				tvbparse_set_seq(-1, NULL, NULL, NULL,
					tvbparse_char(-1, ".", NULL, NULL, NULL),
					tvbparse_chars(-1, 1, 0, "0123456789", NULL, NULL, NULL),
					NULL)),
			/* exp = e [ minus / plus ] 1*DIGIT */
			tvbparse_optional(-1, NULL, NULL, NULL,
				tvbparse_set_seq(-1, NULL, NULL, NULL,
					tvbparse_char(-1, "eE", NULL, NULL, NULL),
					tvbparse_optional(-1, NULL, NULL, NULL, /* tvbparse_chars() don't respect 0 as min_len ;/ */
						tvbparse_chars(-1, 0, 1, "-+", NULL, NULL, NULL)),
					tvbparse_chars(-1, 1, 0, "0123456789", NULL, NULL, NULL),
					NULL)),
			NULL);

	/* value = false / null / true / object / array / number / string */
	want_value = tvbparse_set_oneof(-1, NULL, NULL, after_value,
			tvbparse_string(JSON_TOKEN_FALSE, "false", NULL, NULL, NULL),
			tvbparse_string(JSON_TOKEN_NULL, "null", NULL, NULL, NULL),
			tvbparse_string(JSON_TOKEN_TRUE, "true", NULL, NULL, NULL),
			tvbparse_string(JSON_TOKEN_NAN, "NaN", NULL, NULL, NULL),
			&_want_object,
			&_want_array,
			want_number,
			want_string,
			NULL);

	/* array = begin-array [ value *( value-separator value ) ] end-array */
	want_array = tvbparse_set_seq(JSON_ARRAY, NULL, before_array, after_array,
			tvbparse_char(-1, "[", NULL, NULL, NULL),
			tvbparse_optional(-1, NULL, NULL, NULL,
				tvbparse_set_seq(-1, NULL, NULL, NULL,
					want_value,
					tvbparse_some(-1, 0, INT_MAX, NULL, NULL, NULL,
						tvbparse_set_seq(-1, NULL, NULL, NULL,
							want_value_separator,
							want_value,
							NULL)),
					NULL)
				),
			tvbparse_char(-1, "]", NULL, NULL, NULL),
			NULL);
	_want_array = *want_array;

	/* member = string name-separator value */
	want_member = tvbparse_set_seq(-1, NULL, before_member, after_member,
			want_string,
			tvbparse_char(-1, ":", NULL, NULL, NULL),
			want_value,
			NULL);

	/* object = begin-object [ member *( value-separator member ) ] end-object */
	want_object = tvbparse_set_seq(JSON_OBJECT, NULL, before_object, after_object,
			tvbparse_char(-1, "{", NULL, NULL, NULL),
			tvbparse_optional(-1, NULL, NULL, NULL,
				tvbparse_set_seq(-1, NULL, NULL, NULL,
					want_member,
					tvbparse_some(-1, 0, INT_MAX, NULL, NULL, NULL,
						tvbparse_set_seq(-1, NULL, NULL, NULL,
							want_value_separator,
							want_member,
							NULL)),
					NULL)
				),
			tvbparse_char(-1, "}", NULL, NULL, NULL),
			NULL);
	_want_object = *want_object;

	want_ignore = tvbparse_chars(-1, 1, 0, " \t\r\n", NULL, NULL, NULL);

	/* JSON-text = object / array */
	want = tvbparse_set_oneof(-1, NULL, NULL, NULL,
		want_object,
		want_array,
		/* tvbparse_not_chars(-1, 1, 0, " \t\r\n", NULL, NULL, NULL), */
		NULL);

	/* XXX, heur? */
}

/* This function tries to understand if the payload is json or not */
static bool
dissect_json_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	unsigned len = tvb_captured_length(tvb);
	const uint8_t* buf = tvb_get_string_enc(pinfo->pool, tvb, 0, len, ENC_ASCII);

	if (json_validate(buf, len) == false)
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

/*
  Find field with case-insensitive path matching
  Only called when exact (case-sensitive) match fails
  Returns first matching field where case_insensitive=true and paths match case-insensitively
 */
static json_field_t *
jsonplus_find_case_insensitive_field(const char *path)
{
	case_insensitive_search_t search_data;
	search_data.search_path = path;
	search_data.found_field = NULL;

	wmem_tree_foreach(json_plus_dictionary.fields,
			  jsonplus_case_insensitive_matcher,
			  &search_data);

	return search_data.found_field;
}

/*
  Look up field definition by path in JSON+ dictionary
  Uses two-phase lookup:
   First: Try exact case-sensitive match
   Second: If no match, try case-insensitive search, only if dictionary has case-insensitive fields)
 */
static json_field_t *
jsonplus_lookup_field_by_path(const char *path)
{
	json_field_t *field;

	if (!path || !json_plus_dictionary.fields) {
		return NULL;
	}

	//Try exact case-sensitive match
	field = (json_field_t *)wmem_tree_lookup_string(json_plus_dictionary.fields, path, 0);

	if (field) {
		return field;
	}

	//Try case-insensitive search only if dictionary has case fields
	if (json_plus_dictionary.has_case_insensitive_fields) {
		field = jsonplus_find_case_insensitive_field(path);
	}

	return field;
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

	// Build full parser path: <datadir>/json/
	data_dir = get_datafile_dir(NULL);
	parser_path = wmem_strdup_printf(pool, "%s%cjson%cparsers%c%s",
		data_dir, G_DIR_SEPARATOR, G_DIR_SEPARATOR, G_DIR_SEPARATOR,
		field->parser);

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
		for (gint i = 0; i < argc; i++) {
			argv[i + 2] = extra_args[i];
		}
		argv[argc + 2] = NULL;
		g_free(extra_args);
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
					ws_strtoi64(child->value, NULL, &int_val);
					proto_tree_add_int64(subtree, child_field->hf_value,
						tvb, token->start, token_len, int_val);
				} else if (child_field->type == JSON_FIELD_UNSIGNED) {
					uint64_t uint_val;
					ws_strtou64(child->value, NULL, &uint_val);
					proto_tree_add_uint64(subtree, child_field->hf_value,
						tvb, token->start, token_len, uint_val);
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
	DISSECTOR_ASSERT(depth < JSON_PLUS_MAX_PATH_DEPTH);
	jsmntok_t *token = &tokens[token_idx];
	int count = 1;  // Start with current token
	int i, child_idx;

	if (token->type == JSMN_OBJECT) {
		// Skip over all key value pairs
		child_idx = token_idx + 1;
		for (i = 0; i < token->size; i++) {
			// Skip key
			count += jsonplus_count_json_tokens(tokens, child_idx, depth + 1);
			child_idx += jsonplus_count_json_tokens(tokens, child_idx, depth + 1);
			// Skip value
			count += jsonplus_count_json_tokens(tokens, child_idx, depth + 1);
			child_idx += jsonplus_count_json_tokens(tokens, child_idx, depth + 1);
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

// Dissect an object field using dictionary definition
// NOLINTNEXTLINE(misc-no-recursion)
static int jsonplus_dissect_dict_object_field(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, wmem_allocator_t *pool,
			  jsmntok_t *tokens, int token_idx, const char *json_buf, json_field_t *field,
			  const char **path_parts, int path_depth)
{
	DISSECTOR_ASSERT(path_depth < JSON_PLUS_MAX_PATH_DEPTH);
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

			// Add key to path
			if (path_depth < JSON_PLUS_MAX_PATH_DEPTH) {
				path_parts[path_depth] = key_str;

				// Process value with updated path
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

		// Add key to path
		if (path_depth < JSON_PLUS_MAX_PATH_DEPTH) {
			path_parts[path_depth] = key_str;

			// Process value with updated path
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
	DISSECTOR_ASSERT(path_depth < JSON_PLUS_MAX_PATH_DEPTH);
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
	DISSECTOR_ASSERT(path_depth < JSON_PLUS_MAX_PATH_DEPTH);
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
				/* Update path with array index */
				const char *orig_path = (path_depth > 0) ? path_parts[path_depth - 1] : NULL;
				path_parts[path_depth - 1] = elem_path;

				/* Process element */
				int consumed = jsonplus_display_json_tree_dict(tvb, subtree, pinfo, pool, tokens,
					child_idx, json_buf, path_parts, path_depth);
				child_idx += consumed;

				/* Restore original path */
				if (orig_path) {
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
	const char *pref_file = get_persconffile_path("preferences", TRUE, NULL);
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
		return;
	}

	if (!pref_file) return;

	fp = ws_fopen(pref_file, "r");
	if (!fp) return;

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

	/* Expert info for JSON+ */
	static ei_register_info ei[] = {
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

	init_json_parser();

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
	heur_dissector_add("hpfeeds", dissect_json_heur, "JSON over HPFEEDS", "json_hpfeeds", proto_json, HEURISTIC_ENABLE);
	heur_dissector_add("db-lsp", dissect_json_heur, "JSON over DB-LSP", "json_db_lsp", proto_json, HEURISTIC_ENABLE);
	heur_dissector_add("udp", dissect_json_acdr_heur, "JSON over AC DR", "json_acdr", proto_json, HEURISTIC_ENABLE);

	dissector_add_for_decode_as("udp.port", json_file_handle);

	dissector_add_string("media_type.suffix", "json", json_handle);  /* RFC 6839 */
	dissector_add_string("grpc_message_type", "application/grpc+json", json_handle);
	dissector_add_uint_range_with_preference("tcp.port", "", json_file_handle); /* JSON-RPC over TCP */
	dissector_add_uint_range_with_preference("udp.port", "", json_file_handle); /* JSON-RPC over UDP */

	proto_acdr = proto_get_id_by_filter_name("acdr");
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
