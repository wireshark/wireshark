/* packet-http-urlencoded.c
 * Routines for dissection of HTTP urlecncoded form, based on packet-text-media.c (C) Olivier Biot, 2004.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/wmem/wmem.h>

static gint proto_urlencoded = -1;

static gint hf_form_keyvalue = -1;
static gint hf_form_key = -1;
static gint hf_form_value = -1;

static gint ett_form_urlencoded = -1;
static gint ett_form_keyvalue = -1;

static guint8
get_hexa(guint8 a)
{
	if (a >= '0' && a <= '9')
		return a - '0';
	if (a >= 'A' && a <= 'F')
		return (a - 'A') + 10;
	if (a >= 'a' && a <= 'f')
		return (a - 'a') + 10;

	return 0xff;
}

static int
get_form_key_value(tvbuff_t *tvb, char **ptr, int offset, char stop)
{
	const int orig_offset = offset;
	char *tmp;
	int len;

	len = 0;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		guint8 ch;

		ch = tvb_get_guint8(tvb, offset);
		if (!ch)
			return -1;
		if (ch == stop)
			break;
		if (ch == '%') {
			offset++;
			ch = tvb_get_guint8(tvb, offset);
			if (get_hexa(ch) > 15)
				return -1;

			offset++;
			ch = tvb_get_guint8(tvb, offset);
			if (get_hexa(ch) > 15)
				return -1;
		}

		len++;
		offset++;
	}

	*ptr = tmp = (char*)wmem_alloc(wmem_packet_scope(), len + 1);
	tmp[len] = '\0';

	len = 0;
	offset = orig_offset;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		guint8 ch;

		ch = tvb_get_guint8(tvb, offset);
		if (!ch)
			return -1;
		if (ch == stop)
			break;

		if (ch == '%') {
			guint8 ch1, ch2;
			
			offset++;
			ch1 = tvb_get_guint8(tvb, offset);

			offset++;
			ch2 = tvb_get_guint8(tvb, offset);

			tmp[len] = get_hexa(ch1) << 4 | get_hexa(ch2);

		} else if (ch == '+')
			tmp[len] = ' ';
		else 
			tmp[len] = ch;

		len++;
		offset++;
	}

	return offset;
}


static void
dissect_form_urlencoded(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*url_tree;
	proto_tree	*sub;
	proto_item	*ti;
	gint		offset = 0, next_offset;
	const char	*data_name;

	data_name = pinfo->match_string;
	if (! (data_name && data_name[0])) {
		/*
		 * No information from "match_string"
		 */
		data_name = (char *)(pinfo->private_data);
		if (! (data_name && data_name[0])) {
			/*
			 * No information from "private_data"
			 */
			data_name = NULL;
		}
	}

	if (data_name)
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(%s)", data_name);

	ti = proto_tree_add_item(tree, proto_urlencoded, tvb, 0, -1, ENC_NA);
	if (data_name)
		proto_item_append_text(ti, ": %s", data_name);
	url_tree = proto_item_add_subtree(ti, ett_form_urlencoded);

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		const int start_offset = offset;
		char *key, *value;

		ti = proto_tree_add_item(url_tree, hf_form_keyvalue, tvb, offset, 0, ENC_NA);

		sub = proto_item_add_subtree(ti, ett_form_keyvalue);

		next_offset = get_form_key_value(tvb, &key, offset, '=');
		if (next_offset == -1)
			break;
		proto_tree_add_string(sub, hf_form_key, tvb, offset, next_offset - offset, key);
		proto_item_append_text(sub, ": \"%s\"", key);

		offset = next_offset+1;

		next_offset = get_form_key_value(tvb, &value, offset, '&');
		if (next_offset == -1)
			break;
		proto_tree_add_string(sub, hf_form_value, tvb, offset, next_offset - offset, value);
		proto_item_append_text(sub, " = \"%s\"", value);

		offset = next_offset+1;

		proto_item_set_len(ti, offset - start_offset);
	}
}

void
proto_register_http_urlencoded(void)
{
	static hf_register_info hf[] = {
		{ &hf_form_keyvalue,
			{ "Form item", "urlencoded-form", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_form_key,
			{ "Key", "urlencoded-form.key", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_form_value,
			{ "Value", "urlencoded-form.value", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_form_urlencoded,
		&ett_form_keyvalue
	};


	proto_urlencoded = proto_register_protocol("HTML Form URL Encoded", "URL Encoded Form Data", "urlencoded-form");
	register_dissector("urlencoded-form", dissect_form_urlencoded, proto_urlencoded);

	proto_register_field_array(proto_urlencoded, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_http_urlencoded(void)
{
	dissector_handle_t form_urlencoded_handle;

	form_urlencoded_handle = find_dissector("urlencoded-form");

	dissector_add_string("media_type", "application/x-www-form-urlencoded", form_urlencoded_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
