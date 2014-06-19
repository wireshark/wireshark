/* packet-data.c
 * Routines for raw data (default case)
 * Gilbert Ramirez <gram@alumni.rice.edu>
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

#define NEW_PROTO_TREE_API

#include "config.h"

#include <glib.h>

#include <wsutil/md5.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include "packet-data.h"

/* proto_data cannot be static because it's referenced in the
 * print routines
 */
void proto_register_data(void);

int proto_data = -1;

#define DATA_HFI_INIT HFI_INIT(proto_data)

static header_field_info hfi_data_data DATA_HFI_INIT =
	  { "Data", "data.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_text DATA_HFI_INIT =
	  { "Text", "data.text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_len DATA_HFI_INIT =
	  { "Length", "data.len", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_md5_hash DATA_HFI_INIT =
	  { "Payload MD5 hash", "data.md5_hash", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static gboolean new_pane = FALSE;
static gboolean show_as_text = FALSE;
static gboolean generate_md5_hash = FALSE;

static gint ett_data = -1;

static void
dissect_data(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	gint bytes;

	if (tree) {
		bytes = tvb_length_remaining(tvb, 0);
		if (bytes > 0) {
			tvbuff_t   *data_tvb;
			proto_item *ti;
			proto_tree *data_tree;
			if (new_pane) {
				guint8 *real_data = (guint8 *)tvb_memdup(NULL, tvb, 0, bytes);
				data_tvb = tvb_new_child_real_data(tvb,real_data,bytes,bytes);
				tvb_set_free_cb(data_tvb, g_free);
				add_new_data_source(pinfo, data_tvb, "Not dissected data bytes");
			} else {
				data_tvb = tvb;
			}
			ti = proto_tree_add_protocol_format(tree, proto_data, tvb,
				0,
				bytes, "Data (%d byte%s)", bytes,
				plurality(bytes, "", "s"));
			data_tree = proto_item_add_subtree(ti, ett_data);

			proto_tree_add_item(data_tree, &hfi_data_data, data_tvb, 0, bytes, ENC_NA);

			if (show_as_text) {
				proto_tree_add_item(data_tree, &hfi_data_text, data_tvb, 0, bytes, ENC_ASCII|ENC_NA);
			}

			if(generate_md5_hash) {
				const guint8 *cp;
				md5_state_t   md_ctx;
				md5_byte_t    digest[16];
				const gchar  *digest_string;

				cp = tvb_get_ptr(tvb, 0, bytes);

				md5_init(&md_ctx);
				md5_append(&md_ctx, cp, bytes);
				md5_finish(&md_ctx, digest);

				digest_string = bytestring_to_str(wmem_packet_scope(), digest, 16, '\0');
				ti = proto_tree_add_string(data_tree, &hfi_data_md5_hash, tvb, 0, 0, digest_string);
				PROTO_ITEM_SET_GENERATED(ti);
			}

			ti = proto_tree_add_int(data_tree, &hfi_data_len, data_tvb, 0, 0, bytes);
			PROTO_ITEM_SET_GENERATED (ti);
		}
	}
}

void
proto_register_data(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_data_data,
		&hfi_data_text,
		&hfi_data_md5_hash,
		&hfi_data_len,
	};
#endif

	static gint *ett[] = {
		&ett_data
	};

	module_t *module_data;

	proto_data = proto_register_protocol (
		"Data",		/* name */
		"Data",		/* short name */
		"data"		/* abbrev */
		);

	register_dissector("data", dissect_data, proto_data);

	proto_register_fields(proto_data, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	module_data = prefs_register_protocol( proto_data, NULL);
	prefs_register_bool_preference(module_data,
		"datapref.newpane",
		"Show not dissected data on new Packet Bytes pane",
		"Show not dissected data on new Packet Bytes pane",
		&new_pane);
	prefs_register_bool_preference(module_data,
		"show_as_text",
		"Show data as text",
		"Show data as text in the Packet Details pane",
		&show_as_text);
	prefs_register_bool_preference(module_data,
				       "md5_hash",
				       "Generate MD5 hash",
				       "Whether or not MD5 hashes should be generated and shown for each payload.",
				       &generate_md5_hash);

	/*
	 * "Data" is used to dissect something whose normal dissector
	 * is disabled, so it cannot itself be disabled.
	 */
	proto_set_cant_toggle(proto_data);
}
