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

#include "packet-tls.h"
#include "packet-dtls.h"

void proto_register_data(void);
void proto_reg_handoff_data(void);


static int proto_data;

static int hf_data_data;
static int hf_data_len;
static int hf_data_md5_hash;
static int hf_data_text;
static int hf_data_uncompressed_data;
static int hf_data_uncompressed_len;

static bool new_pane;
static bool uncompress_data;
static bool show_as_text;
static bool generate_md5_hash;

static int ett_data;

static dissector_handle_t data_handle;

static int
dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int bytes;
	char *display_str;

	if (tree) {
		bytes = tvb_captured_length(tvb);
		if (bytes > 0) {
			tvbuff_t   *data_tvb;
			tvbuff_t   *uncompr_tvb = NULL;
			int	    uncompr_len = 0;
			proto_item *ti;
			proto_tree *data_tree;
			if (new_pane) {
				uint8_t *real_data = (uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, bytes);
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
				uncompr_tvb = tvb_child_uncompress_zlib(data_tvb, data_tvb, 0, tvb_reported_length(data_tvb));

				if (uncompr_tvb) {
					uncompr_len = tvb_reported_length(uncompr_tvb);
					add_new_data_source(pinfo, uncompr_tvb, "Uncompressed Data");
					proto_tree_add_item(data_tree, hf_data_uncompressed_data, uncompr_tvb, 0, uncompr_len, ENC_NA);
					ti = proto_tree_add_int(data_tree, hf_data_uncompressed_len, uncompr_tvb, 0, 0, uncompr_len);
					proto_item_set_generated (ti);
				}
			}

			if (show_as_text) {
				tvbuff_t *text_tvb;
				int text_length;
				if (uncompr_tvb && uncompr_len > 0) {
					text_tvb = uncompr_tvb;
					text_length = uncompr_len;
				} else {
					text_tvb = data_tvb;
					text_length = bytes;
				}
				proto_tree_add_item_ret_display_string(data_tree, hf_data_text, text_tvb, 0, text_length, ENC_UTF_8, pinfo->pool, &display_str);
				col_add_str(pinfo->cinfo, COL_INFO, display_str);
			}

			if(generate_md5_hash) {
				const uint8_t *cp;
				uint8_t	      digest[HASH_MD5_LENGTH];
				const char   *digest_string;

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

	static int *ett[] = {
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
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
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
add_foreach_decode_as(const char *table_name, const char *ui_name _U_, void *user_data)
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

	dissector_all_tables_foreach_table(add_foreach_decode_as, (void *)data_handle, NULL);
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
