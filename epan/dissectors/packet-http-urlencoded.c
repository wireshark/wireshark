/* packet-http-urlencoded.c
 * Routines for dissection of HTTP urlecncoded form, based on packet-text-media.c (C) Olivier Biot, 2004.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/charsets.h>
#include <epan/strutil.h>
#include <wsutil/str_util.h>

#include "packet-media-type.h"

void proto_register_http_urlencoded(void);
void proto_reg_handoff_http_urlencoded(void);

static dissector_handle_t form_urlencoded_handle;

static int proto_urlencoded;

static int hf_form_key;
static int hf_form_value;

static int ett_form_urlencoded;
static int ett_form_keyvalue;

static ws_mempbrk_pattern pbrk_key;
static ws_mempbrk_pattern pbrk_value;

static int
get_form_key_value(wmem_allocator_t *pool, tvbuff_t *tvb, char **ptr, int offset, const ws_mempbrk_pattern *pbrk)
{
	const int orig_offset = offset;
	int found_offset;
	uint8_t ch;
	char *tmp;
	int len;

	len = 0;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		found_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset, -1, pbrk, &ch);
		if (found_offset == -1) {
			len += tvb_reported_length_remaining(tvb, offset);
			break;
		}
		len += (found_offset - offset);
		offset = found_offset;
		if (ch == '%') {
			if (tvb_reported_length_remaining(tvb, offset) < 2) {
				return -1;
			}
			offset++;
			ch = tvb_get_uint8(tvb, offset);
			if (ws_xton(ch) == -1)
				return -1;

			offset++;
			ch = tvb_get_uint8(tvb, offset);
			if (ws_xton(ch) == -1)
				return -1;
		} else if (ch != '+') {
			/* Key, matched '=', stop. */
			break;
		}

		len++;
		offset++;
	}

	*ptr = tmp = (char*)wmem_alloc(pool, len + 1);
	tmp[len] = '\0';

	len = 0;
	offset = orig_offset;
	while (tvb_reported_length_remaining(tvb, offset)) {
		found_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset, -1, pbrk, &ch);
		if (found_offset == -1) {
			tvb_memcpy(tvb, &tmp[len], offset, tvb_reported_length_remaining(tvb, offset));
			offset = tvb_reported_length(tvb);
			break;
		}
		tvb_memcpy(tvb, &tmp[len], offset, found_offset - offset);
		len += (found_offset - offset);
		offset = found_offset;
		if (ch == '%') {
			uint8_t ch1, ch2;

			offset++;
			ch1 = tvb_get_uint8(tvb, offset);

			offset++;
			ch2 = tvb_get_uint8(tvb, offset);

			tmp[len] = ws_xton(ch1) << 4 | ws_xton(ch2);

		} else if (ch == '+') {
			tmp[len] = ' ';
		} else {
			/* Key, matched '=', stop */
			break;
		}

		len++;
		offset++;
	}

	return offset;
}


static int
dissect_form_urlencoded(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	proto_tree	*url_tree;
	proto_tree	*sub;
	proto_item	*ti;
	int		offset = 0, next_offset, end_offset;
	const char	*data_name;
	media_content_info_t *content_info;
	tvbuff_t	*sequence_tvb;

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

	if (data_name)
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(%s)", data_name);

	ti = proto_tree_add_item(tree, proto_urlencoded, tvb, 0, -1, ENC_NA);
	if (data_name)
		proto_item_append_text(ti, ": %s", data_name);
	url_tree = proto_item_add_subtree(ti, ett_form_urlencoded);

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		char *key, *value;
		char *key_decoded, *value_decoded;

		end_offset = tvb_find_guint8(tvb, offset, -1, '&');
		if (end_offset == -1) {
			end_offset = (int)tvb_reported_length(tvb);
		}
		sub = proto_tree_add_subtree(url_tree, tvb, offset, end_offset - offset, ett_form_keyvalue, NULL, "Form item");

		sequence_tvb = tvb_new_subset_length(tvb, 0, end_offset);
		next_offset = get_form_key_value(pinfo->pool, sequence_tvb, &key, offset, &pbrk_key);
		if (next_offset == -1)
			break;
		/* XXX: Only UTF-8 is conforming according to WHATWG, though we
		 * ought to look for a "charset" parameter in media_str
		 * to handle other encodings.
		 * Our charset functions should probably return a boolean
		 * indicating that replacement characters had to be used,
		 * and that the string was not the expected encoding.
		 */
		key_decoded = get_utf_8_string(pinfo->pool, key, (int)strlen(key));
		proto_tree_add_string(sub, hf_form_key, tvb, offset, next_offset - offset, key_decoded);
		proto_item_append_text(sub, ": \"%s\"", format_text(pinfo->pool, key, strlen(key)));

		offset = next_offset+1;

		next_offset = get_form_key_value(pinfo->pool, sequence_tvb, &value, offset, &pbrk_value);
		if (next_offset == -1)
			break;
		value_decoded = get_utf_8_string(pinfo->pool, value, (int)strlen(value));
		proto_tree_add_string(sub, hf_form_value, tvb, offset, next_offset - offset, value_decoded);
		proto_item_append_text(sub, " = \"%s\"", format_text(pinfo->pool, value, strlen(value)));

		offset = next_offset+1;
	}

	return tvb_captured_length(tvb);
}

void
proto_register_http_urlencoded(void)
{
	static hf_register_info hf[] = {
		{ &hf_form_key,
			{ "Key", "urlencoded-form.key",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_form_value,
			{ "Value", "urlencoded-form.value",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_form_urlencoded,
		&ett_form_keyvalue
	};

	proto_urlencoded = proto_register_protocol("HTML Form URL Encoded", "URL Encoded Form Data", "urlencoded-form");

	form_urlencoded_handle = register_dissector("urlencoded-form", dissect_form_urlencoded, proto_urlencoded);

	proto_register_field_array(proto_urlencoded, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ws_mempbrk_compile(&pbrk_key, "%+=");
	ws_mempbrk_compile(&pbrk_value, "%+");
}

void
proto_reg_handoff_http_urlencoded(void)
{
	dissector_add_string("media_type", "application/x-www-form-urlencoded", form_urlencoded_handle);
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
