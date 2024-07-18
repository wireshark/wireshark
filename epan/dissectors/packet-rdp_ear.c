/* Packet-rdp_ear.c
 * Routines for the redirected authentication RDP channel
 * Copyright 2023, David Fort <contact@hardening-consulting.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * See: "[MS-RDPEAR] "
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/value_string.h>
#include <epan/asn1.h>

#include "packet-gssapi.h"
#include "packet-ber.h"


#define PNAME  "RDP authentication redirection virtual channel Protocol"
#define PSNAME "rdpear"
#define PFNAME "rdp_ear"

void proto_register_rdp_ear(void);
void proto_reg_handoff_rdp_ear(void);


static int proto_rdp_ear;

static int hf_rdpear_protocolMagic;
static int hf_rdpear_length;
static int hf_rdpear_version;
static int hf_rdpear_reserved;
static int hf_rdpear_tspkgcontext;

static int hf_rdpear_payload;
static int hf_rdpear_packet_version;
static int hf_rdpear_packet_packageName;
static int hf_rdpear_packet_buffer;

static int ett_rdp_ear;
static int ett_rdp_ear_innerPacket;

static dissector_handle_t gssapi_wrap_handle;

static int
dissect_rdpear_ber_VERSION(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index) {
	offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);
	return offset;
}

static int
dissect_rdpear_ber_packageName(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index) {
	offset = dissect_ber_octet_string_with_encoding(implicit_tag, actx, tree, tvb, offset, hf_index, NULL, ENC_UTF_16|ENC_LITTLE_ENDIAN);
	return offset;
}

static int
dissect_rdpear_ber_packetBuffer(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index) {
	offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);
	return offset;
}


static const ber_sequence_t TSRemoteGuardInnerPacket_sequence[] = {
	{ &hf_rdpear_packet_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_rdpear_ber_VERSION },
	{ &hf_rdpear_packet_packageName, BER_CLASS_CON, 1, 0, dissect_rdpear_ber_packageName },
	{ &hf_rdpear_packet_buffer, BER_CLASS_CON, 2, 0, dissect_rdpear_ber_packetBuffer },
	{ NULL, 0, 0, 0, NULL }
};


static int dissect_rcg_payload(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	offset = dissect_ber_sequence(false, &asn1_ctx, tree, tvb, offset,
			TSRemoteGuardInnerPacket_sequence, hf_rdpear_payload, ett_rdp_ear_innerPacket);

	return offset;
}

static int
dissect_rdp_ear(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	tvbuff_t *payload_tvb = NULL;
	tvbuff_t *decr_tvb = NULL;
	gssapi_encrypt_info_t gssapi_encrypt;
	proto_item *item;
	int nextOffset, offset = 0;
	uint32_t pduLength;
	proto_tree *tree;

	parent_tree = proto_tree_get_root(parent_tree);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDPEAR");
	col_clear(pinfo->cinfo, COL_INFO);

	pduLength = tvb_get_uint32(tvb, offset + 4, ENC_LITTLE_ENDIAN) + 24;
	nextOffset = offset + pduLength;

	item = proto_tree_add_item(parent_tree, proto_rdp_ear, tvb, offset, pduLength, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rdp_ear);

	proto_tree_add_item(tree, hf_rdpear_protocolMagic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_rdpear_length, tvb, offset, 4,	ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_rdpear_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_rdpear_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_rdpear_tspkgcontext, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* ================== */
	payload_tvb = tvb_new_subset_length(tvb, offset, pduLength - 24);
	memset(&gssapi_encrypt, 0, sizeof(gssapi_encrypt));
	gssapi_encrypt.decrypt_gssapi_tvb = DECRYPT_GSSAPI_NORMAL;
	call_dissector_with_data(gssapi_wrap_handle, payload_tvb, pinfo, tree, &gssapi_encrypt);

	decr_tvb = gssapi_encrypt.gssapi_decrypted_tvb;

	if (decr_tvb != NULL) {
		dissect_rcg_payload(pinfo, tree, decr_tvb, 0);
	}

	offset = nextOffset;
	return offset;
}


void proto_register_rdp_ear(void) {
	static hf_register_info hf[] = {
		{ &hf_rdpear_protocolMagic,
			{ "Protocol magic", "rdp_ear.magic",
				FT_UINT32, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},
		{ &hf_rdpear_length,
			{ "Length", "rdp_ear.length",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},
		{ &hf_rdpear_version,
			{ "Version", "rdp_ear.version",
				FT_UINT32, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},
		{ &hf_rdpear_reserved,
			{ "Reserved", "rdp_ear.reserved",
				FT_UINT32, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},
		{ &hf_rdpear_tspkgcontext,
			{ "TsPkgContext", "rdp_ear.tspkgcontext",
				FT_UINT64, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},
		{ &hf_rdpear_payload,
			{ "Payload", "rdp_ear.payload",
				FT_NONE, BASE_NONE, NULL, 0,
				NULL, HFILL }},
		{ &hf_rdpear_packet_version,
			{ "Version", "rdp_ear.payload.version",
				FT_INT32, BASE_DEC, NULL, 0,
				NULL, HFILL }},
		{ &hf_rdpear_packet_packageName,
			{ "Package", "rdp_ear.payload.package",
				FT_STRING, BASE_NONE, NULL, 0,
				NULL, HFILL }},
		{ &hf_rdpear_packet_buffer,
			{ "Buffer", "rdp_ear.payload.buffer",
				FT_BYTES, BASE_NONE, NULL, 0,
				NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_rdp_ear,
		&ett_rdp_ear_innerPacket,
	};

	proto_rdp_ear = proto_register_protocol(PNAME, PSNAME, PFNAME);

	/* Register fields and subtrees */
	proto_register_field_array(proto_rdp_ear, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("rdp_ear", dissect_rdp_ear, proto_rdp_ear);
}

void proto_reg_handoff_rdp_ear(void) {
	gssapi_wrap_handle = find_dissector_add_dependency("gssapi_verf", proto_rdp_ear);
}
