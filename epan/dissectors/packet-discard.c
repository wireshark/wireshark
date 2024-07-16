/* packet-discard.c
 * Routines for Discard Protocol dissection
 *
 * Discard specs taken from RFC 863
 * https://tools.ietf.org/html/rfc863
 *
 * Inspiration from packet-chargen.c and packet-data.
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
#include <wsutil/wsgcrypt.h>
#include <wsutil/to_str.h>

#define DISCARD_PORT_UDP 9
#define DISCARD_PORT_TCP 9

void proto_register_discard(void);
void proto_reg_handoff_discard(void);

static int proto_discard;

static int hf_discard_data;
static int hf_discard_text;
static int hf_discard_md5_hash;
static int hf_discard_len;

static bool show_as_text;
static bool generate_md5_hash;

static int ett_discard;

/* dissect_discard - dissects discard packet data
 * tvb - tvbuff for packet data (IN)
 * pinfo - packet info
 * proto_tree - resolved protocol tree
 */
static int
dissect_discard(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* dissector_data _U_)
{
	proto_tree* discard_tree;
	proto_item* ti;
	uint32_t len;
	uint32_t cap_len;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DISCARD");

	if (show_as_text) {
		col_set_str(pinfo->cinfo, COL_INFO, "Discard: ");
	} else {
		col_set_str(pinfo->cinfo, COL_INFO, "Discard");
	}

	ti = proto_tree_add_item(tree, proto_discard, tvb, 0, -1, ENC_NA);
	discard_tree = proto_item_add_subtree(ti, ett_discard);

	len = tvb_reported_length(tvb);
	cap_len = tvb_captured_length(tvb);

	proto_tree_add_item(discard_tree, hf_discard_data, tvb, 0, -1, ENC_NA);

	if (show_as_text) {
		char *display_str;

		proto_tree_add_item_ret_display_string(discard_tree, hf_discard_text, tvb, 0, -1, ENC_ASCII, pinfo->pool, &display_str);
		col_append_str(pinfo->cinfo, COL_INFO, display_str);
	}

	if (generate_md5_hash) {
		const uint8_t *cp;
		uint8_t       digest[HASH_MD5_LENGTH];
		const char   *digest_string;

		cp = tvb_get_ptr(tvb, 0, cap_len);

		gcry_md_hash_buffer(GCRY_MD_MD5, digest, cp, cap_len);
		digest_string = bytes_to_str_punct(pinfo->pool, digest, HASH_MD5_LENGTH, '\0');

		ti = proto_tree_add_string(discard_tree, hf_discard_md5_hash, tvb, 0, 0, digest_string);
		proto_item_set_generated(ti);
	}

	ti = proto_tree_add_uint(discard_tree, hf_discard_len, tvb, 0, 0, len);
	proto_item_set_generated(ti);

	if(len > cap_len) {
		/*
		 * Trigger _ws.short, e.g. [Packet size limited during capture: DISCARD truncated]
		 */
		tvb_get_ptr(tvb, 0, len);
	}

	return cap_len;
}

void
proto_register_discard(void)
{
	static hf_register_info hf[] = {
		{ &hf_discard_data, {
			"Data", "discard.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_discard_text, {
			"Text", "discard.text",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_discard_md5_hash, {
			"Payload MD5 hash", "discard.md5_hash",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_discard_len, {
			"Reported Length", "discard.len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_discard,
	};

	module_t *module_data;

	proto_discard = proto_register_protocol("Discard Protocol", "DISCARD", "discard");

	proto_register_field_array(proto_discard, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	module_data = prefs_register_protocol(proto_discard, NULL);

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
}

void
proto_reg_handoff_discard(void)
{
	dissector_handle_t discard_handle;

	discard_handle = create_dissector_handle(dissect_discard, proto_discard);
	dissector_add_uint_with_preference("udp.port", DISCARD_PORT_UDP, discard_handle);
	dissector_add_uint_with_preference("tcp.port", DISCARD_PORT_TCP, discard_handle);
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
