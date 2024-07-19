/*
 * packet-nmf.c
 *
 * Routines for [MC-NMF] .NET Message Framing Protocol
 *
 * Copyright 2017 Stefan Metzmacher <metze@samba.org>
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

#include <wsutil/str_util.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include "packet-tcp.h"
#include "packet-windows-common.h"
#include "packet-gssapi.h"

#define NMF_PORT 9389

void proto_register_nmf(void);
void proto_reg_handoff_nmf(void);

static dissector_handle_t gssapi_handle;
static dissector_handle_t gssapi_wrap_handle;

static dissector_handle_t xml_handle;

static int proto_nmf = -1;

static int ett_nmf = -1;
static int ett_nmf_payload = -1;

static int hf_nmf_record = -1;
static int hf_nmf_record_type = -1;
static int hf_nmf_version_major = -1;
static int hf_nmf_version_minor = -1;
static int hf_nmf_mode_value = -1;
static int hf_nmf_via_length = -1;
static int hf_nmf_via_value = -1;
static int hf_nmf_known_mode_value = -1;
static int hf_nmf_sized_envelope_length = -1;
static int hf_nmf_upgrade_length = -1;
static int hf_nmf_upgrade_protocol = -1;
static int hf_nmf_negotiate_type = -1;
static int hf_nmf_negotiate_length = -1;
static int hf_nmf_protect_length = -1;

static bool nmf_reassemble = true;

enum nmf_record_type {
	NMF_VERSION_RECORD		= 0x00,
	NMF_MODE_RECORD			= 0x01,
	NMF_VIA_RECORD			= 0x02,
	NMF_KNOWN_ENCODING_RECORD	= 0x03,
	NMF_EXTENSIBLE_ENCODING_RECORD	= 0x04,
	NMF_UNSIZED_ENVELOPE_RECORD	= 0x05,
	NMF_SIZED_ENVELOPE_RECORD	= 0x06,
	NMF_END_RECORD			= 0x07,
	NMF_FAULT_RECORD		= 0x08,
	NMF_UPGRADE_REQUEST_RECORD	= 0x09,
	NMF_UPGRADE_RESPONSE_RECORD	= 0x0A,
	NMF_PREAMBLE_ACK_RECORD		= 0x0B,
	NMF_PREAMBLE_END_RECORD		= 0x0C
};

static const value_string record_types[] = {
	{ NMF_VERSION_RECORD,			"Version Record"},
	{ NMF_MODE_RECORD,			"Mode Record"},
	{ NMF_VIA_RECORD,			"Via Record"},
	{ NMF_KNOWN_ENCODING_RECORD,		"Known Encoding Record"},
	{ NMF_EXTENSIBLE_ENCODING_RECORD,	"Extensible Encoding Record"},
	{ NMF_UNSIZED_ENVELOPE_RECORD,		"Unsized Envelope Record"},
	{ NMF_SIZED_ENVELOPE_RECORD,		"Sized Envelope Record"},
	{ NMF_END_RECORD,			"End Record"},
	{ NMF_FAULT_RECORD,			"Fault Record"},
	{ NMF_UPGRADE_REQUEST_RECORD,		"Upgrade Request Record"},
	{ NMF_UPGRADE_RESPONSE_RECORD,		"Upgrade Response Record"},
	{ NMF_PREAMBLE_ACK_RECORD,		"Preamble Ack Record"},
	{ NMF_PREAMBLE_END_RECORD,		"Preamble End Record"},
	{ 0, NULL }
};

static const value_string mode_values[] = {
	{ 0x01,		"Singleton-Unsized"},
	{ 0x02,		"Duplex"},
	{ 0x03,		"Simplex"},
	{ 0, NULL }
};

static const value_string known_mode_values[] = {
	{ 0x00,		"SOAP 1.1 UTF-8"},
	{ 0x01,		"SOAP 1.1 UTF-16"},
	{ 0x02,		"SOAP 1.1 Unicode Little-Endian"},
	{ 0x03,		"SOAP 1.2 UTF-8"},
	{ 0x04,		"SOAP 1.2 UTF-16"},
	{ 0x05,		"SOAP 1.2 Unicode Little-Endian"},
	{ 0x06,		"SOAP 1.2 MOTM"},
	{ 0x07,		"SOAP 1.2 Binary"},
	{ 0x08,		"SOAP 1.2 Binary with in-band dictionary"},
	{ 0, NULL }
};

typedef struct nmf_conv_info_t {
	uint32_t fnum_upgraded;
	uint32_t fnum_negotiated;
} nmf_conv_info_t;

static int
dissect_nmf_record_size(tvbuff_t *tvb, proto_tree *tree,
			int hf_index, int offset, uint32_t *_size)
{
	uint8_t byte = tvb_get_uint8(tvb, offset);
	uint32_t size = 0;
	uint8_t shift = 0;
	int start_offset = offset;

	do {
		byte = tvb_get_uint8(tvb, offset);
		offset += 1;

		size |= (uint32_t)(byte & 0x7F) << shift;
		shift += 7;
	} while (byte & 0x80);

	if (_size != NULL) {
		*_size = size;
	}

	if (tree != NULL && hf_index != -1) {
		proto_item *item = NULL;
		item = proto_tree_add_item(tree, hf_index, tvb,
					   start_offset, -1, ENC_NA);
		proto_item_set_end(item, tvb, offset);
		proto_item_append_text(item, ": %u (0x%x)",
				       (unsigned)size, (unsigned)size);
	}

	return offset;
}

static int
dissect_nmf_record(tvbuff_t *tvb, packet_info *pinfo,
		   nmf_conv_info_t *nmf_info,
		   proto_tree *tree, int offset)
{
	proto_item *record_item = NULL;
	proto_tree *record_tree = NULL;
	const char *record_name = NULL;
	enum nmf_record_type record_type;
	uint32_t size = 0;
	const uint8_t *str = NULL;
	tvbuff_t *payload_tvb = NULL;
	tvbuff_t *xml_tvb = NULL;

	record_item = proto_tree_add_item(tree, hf_nmf_record, tvb, offset, -1, ENC_NA);
	proto_item_append_text(record_item, ", start_offset=0x%x, ", (unsigned)offset);
	record_tree = proto_item_add_subtree(record_item, ett_nmf);

	record_type = (enum nmf_record_type)tvb_get_uint8(tvb, offset);
	record_name = val_to_str_const((uint32_t)record_type, record_types,
				       "Unknown Record");
	proto_tree_add_item(record_tree, hf_nmf_record_type,
			    tvb, offset, 1, ENC_NA);
	offset += 1;

	col_append_str(pinfo->cinfo, COL_INFO, record_name);
	proto_item_append_text(record_item, "%s", record_name);

	switch (record_type) {
	case NMF_VERSION_RECORD:
		proto_tree_add_item(record_tree, hf_nmf_version_major,
				    tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(record_tree, hf_nmf_version_minor,
				    tvb, offset, 1, ENC_NA);
		offset += 1;
		break;
	case NMF_MODE_RECORD:
		proto_tree_add_item(record_tree, hf_nmf_mode_value,
				    tvb, offset, 1, ENC_NA);
		offset += 1;
		break;
	case NMF_VIA_RECORD:
		offset = dissect_nmf_record_size(tvb, record_tree,
						 hf_nmf_via_length,
						 offset, &size);
		if (offset <= 0) {
			return -1;
		}

		proto_tree_add_item_ret_string(record_tree, hf_nmf_via_value,
					       tvb, offset, size, ENC_UTF_8,
					       wmem_packet_scope(), &str);
		offset += size;
		proto_item_append_text(record_item, ": %s", (const char *)str);
		break;
	case NMF_KNOWN_ENCODING_RECORD:
		proto_tree_add_item(record_tree, hf_nmf_known_mode_value,
				    tvb, offset, 1, ENC_NA);
		offset += 1;
		break;
	case NMF_EXTENSIBLE_ENCODING_RECORD:
		/* TODO */
		break;
	case NMF_UNSIZED_ENVELOPE_RECORD:
		/* TODO */
		break;
	case NMF_SIZED_ENVELOPE_RECORD:
		offset = dissect_nmf_record_size(tvb, record_tree,
						 hf_nmf_sized_envelope_length,
						 offset, &size);
		if (offset <= 0) {
			return -1;
		}

		payload_tvb = tvb_new_subset_length(tvb, offset, size);
		offset += size;
		proto_item_append_text(record_item, ": Payload (%u byte%s)",
				       size, plurality(size, "", "s"));
		proto_tree_add_format_text(record_tree, payload_tvb, 0, size);
#if 0
		if (0) {
			/* TODO:
			 *
			 * 1. reassemble payload
			 * 2. use
			 *    [MC-NBFSE] .NET Binary Format: SOAP Extension
			 *    [MC-NBFS]  .NET Binary Format: SOAP Data Structure
			 *    [MC-NBFX]  .NET Binary Format: XML Data Structure
			 *    to generate XML
			 * 3. call the XML dissector.
			 */
			if (payload_tvb != NULL) {
				xml_tvb = NULL;
			}
		}
#endif
		if (xml_tvb != NULL) {
			call_dissector_with_data(xml_handle, xml_tvb, pinfo,
					         record_tree, NULL);
		}
		break;
	case NMF_END_RECORD:
		/* TODO */
		break;
	case NMF_FAULT_RECORD:
		/* TODO */
		break;
	case NMF_UPGRADE_REQUEST_RECORD:
		offset = dissect_nmf_record_size(tvb, record_tree,
						 hf_nmf_upgrade_length,
						 offset, &size);
		if (offset <= 0) {
			return -1;
		}

		proto_tree_add_item_ret_string(record_tree, hf_nmf_upgrade_protocol,
					       tvb, offset, size, ENC_UTF_8,
					       wmem_packet_scope(), &str);
		offset += size;
		proto_item_append_text(record_item, ": %s", (const char *)str);
		break;

	case NMF_UPGRADE_RESPONSE_RECORD:
		nmf_info->fnum_upgraded = pinfo->fd->num;
		break;
	case NMF_PREAMBLE_ACK_RECORD:
		/* TODO */
		break;
	case NMF_PREAMBLE_END_RECORD:
		/* TODO */
		break;
	}

	proto_item_append_text(record_item, ", end_offset=0x%x", (unsigned)offset);
	proto_item_set_end(record_item, tvb, offset);

	return offset;
}

static unsigned
nmf_get_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *_info)
{
	nmf_conv_info_t *nmf_info = (nmf_conv_info_t *)_info;
	enum nmf_record_type record_type;
	uint32_t size = 0;
	int start_offset = offset;

	if (pinfo->fd->num > nmf_info->fnum_negotiated) {
		unsigned remaining = tvb_captured_length_remaining(tvb, offset);
		unsigned len = 0;
		unsigned needed = 0;

		if (remaining < 4) {
			return 0;
		}

		len = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
		offset += 4;

		needed = 4 + len;
		return needed;
	}

	if (pinfo->fd->num > nmf_info->fnum_upgraded) {
		unsigned remaining = tvb_captured_length_remaining(tvb, offset);
		unsigned len = 0;
		unsigned needed = 0;

		if (remaining < 5) {
			return 0;
		}

		offset += 3;

		len = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
		offset += 2;

		needed = 5 + len;
		return needed;
	}

	record_type = (enum nmf_record_type)tvb_get_uint8(tvb, offset);
	offset += 1;

	switch (record_type) {
	case NMF_VERSION_RECORD:
		offset += 2;
		break;
	case NMF_MODE_RECORD:
		offset += 1;
		break;
	case NMF_VIA_RECORD:
		offset = dissect_nmf_record_size(tvb, NULL, -1,
						 offset, &size);
		if (offset <= 0) {
			return 0;
		}
		offset += size;
		break;
	case NMF_KNOWN_ENCODING_RECORD:
		offset += 1;
		break;
	case NMF_EXTENSIBLE_ENCODING_RECORD:
		/* TODO */
		break;
	case NMF_UNSIZED_ENVELOPE_RECORD:
		/* TODO */
		break;
	case NMF_SIZED_ENVELOPE_RECORD:
		offset = dissect_nmf_record_size(tvb, NULL, -1,
						 offset, &size);
		if (offset <= 0) {
			return 0;
		}
		offset += size;
		break;
	case NMF_END_RECORD:
		/* TODO */
		break;
	case NMF_FAULT_RECORD:
		/* TODO */
		break;
	case NMF_UPGRADE_REQUEST_RECORD:
		offset = dissect_nmf_record_size(tvb, NULL, -1,
						 offset, &size);
		if (offset <= 0) {
			return 0;
		}
		offset += size;
		break;

	case NMF_UPGRADE_RESPONSE_RECORD:
		break;
	case NMF_PREAMBLE_ACK_RECORD:
		/* TODO */
		break;
	case NMF_PREAMBLE_END_RECORD:
		/* TODO */
		break;
	}

	return offset - start_offset;
}

static int
dissect_nmf_payload(tvbuff_t *tvb, packet_info *pinfo,
		    proto_tree *tree, nmf_conv_info_t *nmf_info)
{
	int offset = 0;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		int ret;

		ret = dissect_nmf_record(tvb, pinfo, nmf_info, tree, offset);
		if (ret <= 0) {
			return -1;
		}
		offset += ret;
	}

	return offset;
}

static int
dissect_nmf_pdu(tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *tree, void *_info)
{
	nmf_conv_info_t *nmf_info = (nmf_conv_info_t *)_info;

	pinfo->fragmented = true;

	if (pinfo->fd->num > nmf_info->fnum_negotiated) {
		proto_item *item = proto_tree_get_parent(tree);
		uint32_t len = 0;
		int offset = 0;
		tvbuff_t *gssapi_tvb = NULL;
		tvbuff_t *plain_tvb = NULL, *decr_tvb= NULL;
		int ver_len;
		gssapi_encrypt_info_t gssapi_encrypt;

		len = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_nmf_negotiate_length,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		col_set_str(pinfo->cinfo, COL_INFO, "NMF GSSAPI");
		col_add_fstr(pinfo->cinfo, COL_INFO,
			     "Protected Packet len: %u (0x%x)",
			     (unsigned)len, (unsigned)len);
		proto_item_append_text(item, ", Protected Packet len: %u (0x%x)",
				(unsigned)len, (unsigned)len);

		gssapi_tvb = tvb_new_subset_length(tvb, offset, len);
		offset += len;

		/* Attempt decryption of the GSSAPI wrapped data if possible */
		memset(&gssapi_encrypt, 0, sizeof(gssapi_encrypt));
		gssapi_encrypt.decrypt_gssapi_tvb=DECRYPT_GSSAPI_NORMAL;

		ver_len = call_dissector_with_data(gssapi_wrap_handle, gssapi_tvb,
					           pinfo, tree, &gssapi_encrypt);
		/* if we could unwrap, do a tvb shuffle */
		if (gssapi_encrypt.gssapi_decrypted_tvb) {
			decr_tvb=gssapi_encrypt.gssapi_decrypted_tvb;
		} else if (gssapi_encrypt.gssapi_wrap_tvb) {
			plain_tvb=gssapi_encrypt.gssapi_wrap_tvb;
		}

		/*
		* if we don't have unwrapped data,
		* see if the wrapping involved encryption of the
		* data; if not, just use the plaintext data.
		*/
		if (!decr_tvb && !plain_tvb) {
			if(!gssapi_encrypt.gssapi_data_encrypted){
				 plain_tvb = tvb_new_subset_remaining(gssapi_tvb, ver_len);
			}
		}

		if (decr_tvb) {
			proto_tree *enc_tree = NULL;
			unsigned decr_len = tvb_reported_length(decr_tvb);

			col_set_str(pinfo->cinfo, COL_INFO, "NMF GSS-API Privacy (decrypted): ");

			if (tree) {
				enc_tree = proto_tree_add_subtree_format(tree, decr_tvb, 0, -1,
									 ett_nmf_payload, NULL,
									 "GSS-API Encrypted payload (%d byte%s)",
									 decr_len,
									 plurality(decr_len, "", "s"));
			}
			dissect_nmf_payload(decr_tvb, pinfo, enc_tree, nmf_info);
		} else if (plain_tvb) {
			proto_tree *plain_tree = NULL;
			unsigned plain_len = tvb_reported_length(plain_tvb);

			col_set_str(pinfo->cinfo, COL_INFO, "NMF GSS-API Integrity: ");

			if (tree) {
				plain_tree = proto_tree_add_subtree_format(tree, plain_tvb, 0, -1,
									   ett_nmf_payload, NULL,
									   "GSS-API payload (%d byte%s)",
									   plain_len,
									   plurality(plain_len, "", "s"));
			}

			dissect_nmf_payload(plain_tvb, pinfo, plain_tree, nmf_info);
		} else {
			col_add_fstr(pinfo->cinfo, COL_INFO, "NMF GSS-API Privacy: payload (%d byte%s)",
				     len, plurality(len, "", "s"));

			proto_tree_add_format_text(tree, gssapi_tvb, 0, len);
		}
		return offset;
	}

	if (pinfo->fd->num > nmf_info->fnum_upgraded) {
		proto_item *item = proto_tree_get_parent(tree);
		unsigned rlen = tvb_reported_length(tvb);
		uint16_t len = 0;
		uint8_t type;
		int offset = 0;
		tvbuff_t *negotiate_tvb = NULL;

		col_set_str(pinfo->cinfo, COL_INFO, "NMF Upgrade");

		type = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_nmf_negotiate_type,
				    tvb, offset, 1, ENC_NA);
		offset += 1;
		if (type == 0x14) {
			nmf_info->fnum_negotiated = pinfo->fd->num;
		}

		offset += 2;

		len = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_nmf_negotiate_length,
				    tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		col_add_fstr(pinfo->cinfo, COL_INFO,
			     "Upgraded Packet rlen: %u (0x%x)",
			     (unsigned)rlen, (unsigned)rlen);
		proto_item_append_text(item, ", Upgraded Packet rlen: %u (0x%x) len: %u (0x%x) type: 0x%02x",
				(unsigned)rlen, (unsigned)rlen,
				(unsigned)len, (unsigned)len,
				(unsigned)type);
		negotiate_tvb = tvb_new_subset_length(tvb, offset, len);

		call_dissector(gssapi_handle, negotiate_tvb, pinfo, tree);
		offset += len;
		return offset;
	}

	return dissect_nmf_record(tvb, pinfo, nmf_info, tree, 0);
}

static int
dissect_nmf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, _U_ void *_unused)
{
	conversation_t *conv = NULL;
	nmf_conv_info_t *nmf_info = NULL;
	proto_tree *tree = NULL;
	proto_item *item = NULL;

	conv = find_or_create_conversation(pinfo);
	nmf_info = (nmf_conv_info_t *)conversation_get_proto_data(conv,
								  proto_nmf);
	if (nmf_info == NULL) {
		nmf_info = wmem_new0(wmem_file_scope(), nmf_conv_info_t);
		nmf_info->fnum_upgraded = 0xffffffff;
		nmf_info->fnum_negotiated = 0xffffffff;
		conversation_add_proto_data(conv, proto_nmf, nmf_info);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NMF");
	col_set_str(pinfo->cinfo, COL_INFO, "NMF...");

	if (parent_tree != NULL) {
		item = proto_tree_add_item(parent_tree, proto_nmf, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_nmf);
	}

	tcp_dissect_pdus(tvb, pinfo, tree, nmf_reassemble,
			 1, /* fixed_length */
			 nmf_get_pdu_len,
			 dissect_nmf_pdu,
			 nmf_info);
	return tvb_captured_length(tvb);
}

void proto_register_nmf(void)
{
	static int *ett[] = {
		&ett_nmf,
		&ett_nmf_payload,
	};
	static hf_register_info hf[] = {
	{ &hf_nmf_record,
		{ "Record", "nmf.record",
		FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_nmf_record_type,
		{ "Type", "nmf.type",
		FT_UINT8, BASE_DEC, VALS(record_types), 0, NULL, HFILL }},
	{ &hf_nmf_version_major,
		{ "Version Major", "nmf.version.major",
		FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_nmf_version_minor,
		{ "Version minor", "nmf.version.minor",
		FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_nmf_mode_value,
		{ "Mode", "nmf.mode.value",
		FT_UINT8, BASE_DEC, VALS(mode_values), 0, NULL, HFILL }},
	{ &hf_nmf_via_length,
		{ "Length", "nmf.via.length",
		FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_nmf_via_value,
		{ "URI", "nmf.via.uri",
		FT_STRING, BASE_NONE, NULL, 0x0, "Via URI", HFILL }},
	{ &hf_nmf_known_mode_value,
		{ "Mode", "nmf.known_mode.value",
		FT_UINT8, BASE_DEC, VALS(known_mode_values), 0, NULL, HFILL }},
	{ &hf_nmf_sized_envelope_length,
		{ "Length", "nmf.sized_envelope.length",
		FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_nmf_upgrade_length,
		{ "Length", "nmf.upgrade.length",
		FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_nmf_upgrade_protocol,
		{ "Upgrade Protocol", "nmf.upgrade.protocol",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_nmf_negotiate_type,
		{ "Negotiate Type", "nmf.negotiate.type",
		FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_nmf_negotiate_length,
		{ "Negotiate Length", "nmf.negotiate.length",
		FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_nmf_protect_length,
		{ "Protect Length", "nmf.protect.length",
		FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};
	module_t *nmf_module = NULL;

	proto_nmf = proto_register_protocol("NMF (.NET Message Framing Protocol)",
					    "NMF", "nmf");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_nmf, hf, array_length(hf));

	nmf_module = prefs_register_protocol(proto_nmf, NULL);
	prefs_register_bool_preference(nmf_module,
				       "reassemble_nmf",
				       "Reassemble NMF fragments",
				       "Whether the NMF dissector should reassemble fragmented payloads",
				       &nmf_reassemble);
}


void
proto_reg_handoff_nmf(void)
{
	dissector_handle_t nmf_handle;

	nmf_handle = create_dissector_handle(dissect_nmf, proto_nmf);
	dissector_add_uint_with_preference("tcp.port", NMF_PORT, nmf_handle);

	gssapi_handle = find_dissector_add_dependency("gssapi", proto_nmf);
	gssapi_wrap_handle = find_dissector_add_dependency("gssapi_verf", proto_nmf);

	xml_handle = find_dissector_add_dependency("xml", proto_nmf);
}
