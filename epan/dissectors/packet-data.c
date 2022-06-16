/* packet-data.c
 * Routines for raw data (default case)
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/str_util.h>

#include <packet-tls.h>
#include <packet-dtls.h>

void proto_register_data(void);
void proto_reg_handoff_data(void);


static int proto_data = -1;

static int hf_data_data = -1;
static int hf_data_len = -1;
static int hf_data_md5_hash = -1;
static int hf_data_text = -1;
static int hf_data_uncompressed_data = -1;
static int hf_data_uncompressed_len = -1;

static gboolean new_pane = FALSE;
static gboolean uncompress_data = FALSE;
static gboolean show_as_text = FALSE;
static gboolean generate_md5_hash = FALSE;

static gint ett_data = -1;

static dissector_handle_t data_handle;

static int
dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	gint bytes;

	if (tree) {
		bytes = tvb_captured_length(tvb);
		if (bytes > 0) {
			tvbuff_t   *data_tvb;
			tvbuff_t   *uncompr_tvb = NULL;
			gint	    uncompr_len = 0;
			proto_item *ti;
			proto_tree *data_tree;
			if (new_pane) {
				guint8 *real_data = (guint8 *)tvb_memdup(pinfo->pool, tvb, 0, bytes);
				data_tvb = tvb_new_child_real_data(tvb,real_data,bytes,bytes);
				add_new_data_source(pinfo, data_tvb, "Not dissected data bytes");
			} else {
				data_tvb = tvb;
			}
			ti = proto_tree_add_protocol_format(tree, proto_data, tvb,
				0,
				bytes, "Data (%d byte%s)", bytes,
				plurality(bytes, "", "s"));
			data_tree = proto_item_add_subtree(ti, ett_data);

			proto_tree_add_item(data_tree, hf_data_data, data_tvb, 0, bytes, ENC_NA);

			if (uncompress_data) {
				uncompr_tvb = tvb_child_uncompress(data_tvb, data_tvb, 0, tvb_reported_length(data_tvb));

				if (uncompr_tvb) {
					uncompr_len = tvb_reported_length(uncompr_tvb);
					add_new_data_source(pinfo, uncompr_tvb, "Uncompressed Data");
					proto_tree_add_item(data_tree, hf_data_uncompressed_data, uncompr_tvb, 0, uncompr_len, ENC_NA);
					ti = proto_tree_add_int(data_tree, hf_data_uncompressed_len, uncompr_tvb, 0, 0, uncompr_len);
					proto_item_set_generated (ti);
				}
			}

			if (show_as_text) {
				if (uncompr_tvb && uncompr_len > 0) {
					proto_tree_add_item(data_tree, hf_data_text, uncompr_tvb, 0, uncompr_len, ENC_ASCII);
					col_add_fstr(pinfo->cinfo, COL_INFO, "%s", tvb_format_text_wsp(pinfo->pool, uncompr_tvb, 0, uncompr_len));
				} else {
					proto_tree_add_item(data_tree, hf_data_text, data_tvb, 0, bytes, ENC_ASCII);
					col_add_fstr(pinfo->cinfo, COL_INFO, "%s", tvb_format_text_wsp(pinfo->pool, data_tvb, 0, bytes));
				}
			}

			if(generate_md5_hash) {
				const guint8 *cp;
				guint8	      digest[HASH_MD5_LENGTH];
				const gchar  *digest_string;

				cp = tvb_get_ptr(tvb, 0, bytes);

				gcry_md_hash_buffer(GCRY_MD_MD5, digest, cp, bytes);
				digest_string = bytes_to_str_punct(pinfo->pool, digest, HASH_MD5_LENGTH, '\0');
				ti = proto_tree_add_string(data_tree, hf_data_md5_hash, tvb, 0, 0, digest_string);
				proto_item_set_generated(ti);
			}

			ti = proto_tree_add_int(data_tree, hf_data_len, data_tvb, 0, 0, bytes);
			proto_item_set_generated (ti);
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_register_data(void)
{
	static hf_register_info hf[] = {
		{ &hf_data_data,
			{ "Data", "data.data",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_data_text,
			{ "Text", "data.text",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_data_uncompressed_data,
			{ "Uncompressed Data", "data.uncompressed.data",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_data_uncompressed_len,
			{ "Uncompressed Length", "data.uncompressed.len",
			  FT_INT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_data_len,
			{ "Length", "data.len",
			  FT_INT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_data_md5_hash,
			{ "Payload MD5 hash", "data.md5_hash",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_data
	};

	module_t *module_data;

	proto_data = proto_register_protocol (
		"Data",		/* name */
		"Data",		/* short name */
		"data"		/* abbrev */
		);

	data_handle = register_dissector("data", dissect_data, proto_data);

	proto_register_field_array(proto_data, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	module_data = prefs_register_protocol( proto_data, NULL);
	prefs_register_bool_preference(module_data,
		"datapref.newpane",
		"Show not dissected data on new Packet Bytes pane",
		"Show not dissected data on new Packet Bytes pane",
		&new_pane);
#ifdef HAVE_ZLIB
	prefs_register_bool_preference(module_data,
		"uncompress_data",
		"Try to uncompress zlib compressed data",
		"Try to uncompress zlib compressed data and show as uncompressed if successful",
		&uncompress_data);
#endif
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

static void
add_foreach_decode_as(const gchar *table_name, const gchar *ui_name _U_, gpointer user_data)
{
        dissector_handle_t handle = (dissector_handle_t) user_data;
        dissector_table_t dissector_table = find_dissector_table(table_name);


        if (dissector_table_supports_decode_as(dissector_table))
                dissector_add_for_decode_as(table_name, handle);
}

void
proto_reg_handoff_data(void)
{
	dissector_add_string("media_type", "application/octet-stream", data_handle);
	ssl_dissector_add(0, data_handle);
	dtls_dissector_add(0, data_handle);

	dissector_all_tables_foreach_table(add_foreach_decode_as, (gpointer)data_handle, NULL);
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
