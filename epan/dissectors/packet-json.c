/* packet-json.c
 * Routines for JSON dissection
 * References:
 *     RFC 4627: http://tools.ietf.org/html/rfc4627
 *     Website:  http://json.org/
 *
 * Copyright 2010, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/tvbparse.h>

static gint proto_json = -1;

static gint ett_json = -1;
static gint ett_json_array = -1;
static gint ett_json_object = -1;
static gint ett_json_member = -1;

static gint hf_json_array = -1;
static gint hf_json_object = -1;
static gint hf_json_member = -1;
/* XXX, static gint hf_json_member_key = -1; */

static gint hf_json_value_string = -1;
static gint hf_json_value_number = -1;
static gint hf_json_value_false = -1;
static gint hf_json_value_null = -1;
static gint hf_json_value_true = -1;

static tvbparse_wanted_t* want;
static tvbparse_wanted_t* want_ignore;

static dissector_handle_t text_lines_handle;

typedef enum {
	JSON_TOKEN_INVALID = -1,
	JSON_TOKEN_NUMBER = 0,
	JSON_TOKEN_STRING,
	JSON_TOKEN_FALSE,
	JSON_TOKEN_NULL,
	JSON_TOKEN_TRUE,

	/* not really tokens ... */
	JSON_OBJECT,
	JSON_ARRAY

} json_token_type_t;

typedef struct {
	ep_stack_t stack;

} json_parser_data_t;

static void
dissect_json(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *json_tree = NULL;
	proto_item *ti = NULL;

	json_parser_data_t parser_data;
	tvbparse_t *tt;

	const char *data_name;
	int offset;

	data_name = pinfo->match_string;
	if (!(data_name && data_name[0])) {
		/*
		 * No information from "match_string"
		 */
		data_name = (char *)(pinfo->private_data);
		if (!(data_name && data_name[0])) {
			/*
			 * No information from "private_data"
			 */
			data_name = NULL;
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_json, tvb, 0, -1, ENC_NA);
		json_tree = proto_item_add_subtree(ti, ett_json);

		if (data_name)
			proto_item_append_text(ti, ": %s", data_name);
	}

	offset = 0;
	
	parser_data.stack = ep_stack_new();
	ep_stack_push(parser_data.stack, json_tree);

	tt = tvbparse_init(tvb, offset, -1, &parser_data, want_ignore);

	/* XXX, only one json in packet? */
	while ((tvbparse_get(tt, want)))
		;

	offset = tvbparse_curr_offset(tt);

	proto_item_set_len(ti, offset);

	/* if we have some unparsed data, pass to data-text-lines dissector (?) */
	if (tvb_length_remaining(tvb, offset) != 0) {
		int datalen, reported_datalen;
		tvbuff_t *next_tvb;
		
		datalen = tvb_length_remaining(tvb, offset);
		reported_datalen = tvb_reported_length_remaining(tvb, offset);

		next_tvb = tvb_new_subset(tvb, offset, datalen, reported_datalen);

		call_dissector(text_lines_handle, next_tvb, pinfo, tree);
	} else if (data_name) {
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(%s)", data_name);
	}
}

static void before_object(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	proto_tree *tree = ep_stack_peek(data->stack);
	proto_tree *subtree;
	proto_item *ti;

	ti = proto_tree_add_item(tree, hf_json_object, tok->tvb, tok->offset, tok->len, ENC_NA);

	subtree = proto_item_add_subtree(ti, ett_json_object);
	ep_stack_push(data->stack, subtree);
}

static void after_object(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *elem _U_) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	ep_stack_pop(data->stack);
}

static void before_member(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	proto_tree *tree = ep_stack_peek(data->stack);
	proto_tree *subtree;
	proto_item *ti;

	ti = proto_tree_add_item(tree, hf_json_member, tok->tvb, tok->offset, tok->len, ENC_NA);

	subtree = proto_item_add_subtree(ti, ett_json_member);
	ep_stack_push(data->stack, subtree);
}

static void after_member(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	proto_tree *tree = ep_stack_pop(data->stack);

	if (tree) {
		tvbparse_elem_t *key_tok = tok->sub;

		if (key_tok && key_tok->id == JSON_TOKEN_STRING) {
			char *key = tvb_get_ephemeral_string(key_tok->tvb, key_tok->offset, key_tok->len);

			proto_item_append_text(tree, " Key: %s", key);
		}
		/* XXX, hf_json_member_key */
	}
}

static void before_array(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	proto_tree *tree = ep_stack_peek(data->stack);
	proto_tree *subtree;
	proto_item *ti;

	ti = proto_tree_add_item(tree, hf_json_array, tok->tvb, tok->offset, tok->len, ENC_NA);

	subtree = proto_item_add_subtree(ti, ett_json_array);
	ep_stack_push(data->stack, subtree);
}

static void after_array(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *elem _U_) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	ep_stack_pop(data->stack);
}

static void after_value(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
	json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

	proto_tree *tree = ep_stack_peek(data->stack);
	json_token_type_t value_id = JSON_TOKEN_INVALID;

	if (tok->sub)
		value_id = tok->sub->id;

	switch (value_id) {
		case JSON_TOKEN_STRING:
			if (tok->len >= 2) {
				char *str = ep_alloc(tok->len - 1);

				/* XXX, for now only strip quotes, later we can unescape string */
				tvb_memcpy(tok->tvb, str, tok->offset + 1, tok->len - 2);
				str[tok->len - 2] = '\0';
				proto_tree_add_string(tree, hf_json_value_string, tok->tvb, tok->offset, tok->len, str);
			} else
				proto_tree_add_item(tree, hf_json_value_string, tok->tvb, tok->offset, tok->len, ENC_ASCII|ENC_NA);
			break;

		case JSON_TOKEN_NUMBER:
			/* XXX, convert to number */
			proto_tree_add_item(tree, hf_json_value_number, tok->tvb, tok->offset, tok->len, ENC_ASCII|ENC_NA);
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

		case JSON_OBJECT:
		case JSON_ARRAY:
			/* already added */
			break;

		default:
			proto_tree_add_text(tree, tok->tvb, tok->offset, tok->len, "%s", tvb_format_text(tok->tvb, tok->offset, tok->len));
			break;
	}
}

static void init_json_parser(void) {
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

	want_string = tvbparse_quoted(JSON_TOKEN_STRING, NULL, NULL, NULL, '\"', '\\');

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
					tvbparse_some(-1, 0, G_MAXINT, NULL, NULL, NULL, 
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
					tvbparse_some(-1, 0, G_MAXINT, NULL, NULL, NULL, 
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

void
proto_register_json(void) {
	static gint *ett[] = {
		&ett_json,
		&ett_json_array,
		&ett_json_object,
		&ett_json_member
	};

	static hf_register_info hf[] = {
		{ &hf_json_array,
			{ "Array", "json.array", FT_NONE, BASE_NONE, NULL, 0x00, "JSON array", HFILL }
		}, 
		{ &hf_json_object,
			{ "Object", "json.object", FT_NONE, BASE_NONE, NULL, 0x00, "JSON object", HFILL }
		}, 
		{ &hf_json_member,
			{ "Member", "json.member", FT_NONE, BASE_NONE, NULL, 0x00, "JSON object member", HFILL },
		},
/* XXX
		{ &hf_json_member_key,
			{ "Key", "json.member.key", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL },
		},
*/
		{ &hf_json_value_string, /* FT_STRINGZ? */
			{ "String value", "json.value.string", FT_STRING, BASE_NONE, NULL, 0x00, "JSON string value", HFILL },
		},
		{ &hf_json_value_number, /* FT_DOUBLE/ FT_INT64? */
			{ "Number value", "json.value.number", FT_STRING, BASE_NONE, NULL, 0x00, "JSON number value", HFILL },
		},
		{ &hf_json_value_false,
			{ "False value", "json.value.false", FT_NONE, BASE_NONE, NULL, 0x00, "JSON false value", HFILL },
		},
		{ &hf_json_value_null,
			{ "Null value", "json.value.null", FT_NONE, BASE_NONE, NULL, 0x00, "JSON null value", HFILL },
		},
		{ &hf_json_value_true,
			{ "True value", "json.value.true", FT_NONE, BASE_NONE, NULL, 0x00, "JSON true value", HFILL },
		},

	};

	proto_json = proto_register_protocol("JavaScript Object Notation", "JSON", "json");

	proto_register_field_array(proto_json, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("json", dissect_json, proto_json);

	init_json_parser();
}

void
proto_reg_handoff_json(void)
{
	dissector_handle_t json_handle;

	json_handle = find_dissector("json");

	dissector_add_string("media_type", "application/json", json_handle); /* RFC 4627 */

	text_lines_handle = find_dissector("data-text-lines");
}

