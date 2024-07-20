/* packet-xip-serval.c
 * Routines for XIP Serval dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Serval is a service-centric architecture that has been ported to XIA to
 * allow applications to communicate using service names.
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/in_cksum.h>
#include <ipproto.h>

void proto_register_xip_serval(void);
void proto_reg_handoff_xip_serval(void);

static dissector_handle_t tcp_handle;
static dissector_handle_t udp_handle;

static int proto_xip_serval;

/* XIP Serval header. */
static int hf_xip_serval_hl;
static int hf_xip_serval_proto;
static int hf_xip_serval_check;
static int hf_xip_serval_check_status;

/* XIP Serval general extension header. */
static int hf_xip_serval_ext_type;
static int hf_xip_serval_ext_length;

/* XIP Serval control extension header. */
static int hf_xip_serval_cext;
static int hf_xip_serval_cext_flags;
static int hf_xip_serval_cext_syn;
static int hf_xip_serval_cext_rsyn;
static int hf_xip_serval_cext_ack;
static int hf_xip_serval_cext_nack;
static int hf_xip_serval_cext_rst;
static int hf_xip_serval_cext_fin;
static int hf_xip_serval_cext_verno;
static int hf_xip_serval_cext_ackno;
static int hf_xip_serval_cext_nonce;

static int ett_xip_serval_tree;
static int ett_xip_serval_cext;
static int ett_xip_serval_cext_flags;

static expert_field ei_xip_serval_bad_len;
static expert_field ei_xip_serval_bad_proto;
static expert_field ei_xip_serval_bad_checksum;
static expert_field ei_xip_serval_bad_ext;

#define XIP_SERVAL_PROTO_DATA		0
static const value_string xip_serval_proto_vals[] = {
	{ XIP_SERVAL_PROTO_DATA,	"Data" },
	{ IP_PROTO_TCP,			"TCP" },
	{ IP_PROTO_UDP,			"UDP" },
	{ 0,				NULL },
};

static int * const xip_serval_cext_flags[] = {
	&hf_xip_serval_cext_syn,
	&hf_xip_serval_cext_rsyn,
	&hf_xip_serval_cext_ack,
	&hf_xip_serval_cext_nack,
	&hf_xip_serval_cext_rst,
	&hf_xip_serval_cext_fin,
	NULL
};

#define XIP_SERVAL_MIN_LEN		4

#define XIP_SERVAL_EXT_MIN_LEN		2
#define XIP_SERVAL_EXT_TYPE_MASK	0xF0
#define XIP_SERVAL_EXT_TYPE_CONTROL	0

#define XIP_SERVAL_CEXT_FLAGS_WIDTH	8
#define XIP_SERVAL_CEXT_NONCE_SIZE	8
#define XIP_SERVAL_CEXT_LEN		20

#define XSRVL_LEN			0
#define XSRVL_PRO			1
#define XSRVL_CHK			2
#define XSRVL_EXT			4

static uint8_t
display_xip_serval_control_ext(tvbuff_t *tvb, proto_tree *xip_serval_tree,
	int offset, uint8_t type, uint8_t length)
{
	proto_tree *cext_tree;
	proto_item *ti;

	/* Create Serval Control Extension tree. */
	ti = proto_tree_add_item(xip_serval_tree, hf_xip_serval_cext, tvb,
		offset, length, ENC_NA);
	cext_tree = proto_item_add_subtree(ti, ett_xip_serval_cext);

	/* Add XIP Serval extension type. */
	proto_tree_add_uint(cext_tree, hf_xip_serval_ext_type, tvb,
		offset, 1, type);
	offset++;

	/* Add XIP Serval extension length. */
	proto_tree_add_item(cext_tree, hf_xip_serval_ext_length, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* Create XIP Serval Control Extension flags tree. */
	proto_tree_add_bitmask(cext_tree, tvb, offset,
		hf_xip_serval_cext_flags, ett_xip_serval_cext_flags,
		xip_serval_cext_flags, ENC_BIG_ENDIAN);

	/* Skip two bits for res1. */
	offset++;

	/* Skip a byte for res2. */
	offset++;

	/* Add verification number. */
	proto_tree_add_item(cext_tree, hf_xip_serval_cext_verno,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Add acknowledgement number. */
	proto_tree_add_item(cext_tree, hf_xip_serval_cext_ackno,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Add nonce. */
	proto_tree_add_item(cext_tree, hf_xip_serval_cext_nonce,
		tvb, offset, 8, ENC_NA);

	/* Displayed XIP_SERVAL_CEXT_LEN bytes. */
	return XIP_SERVAL_CEXT_LEN;
}

static uint8_t
display_xip_serval_ext(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti,
	proto_tree *xip_serval_tree, int offset)
{
	uint8_t type = tvb_get_uint8(tvb, offset) & XIP_SERVAL_EXT_TYPE_MASK;
	uint8_t length = tvb_get_uint8(tvb, offset + 1);

	/* For now, the only type of extension header in XIP Serval is
	 * the control extension header.
	 */
	switch (type) {
	case XIP_SERVAL_EXT_TYPE_CONTROL:
		return display_xip_serval_control_ext(tvb, xip_serval_tree,
			offset, type, length);
	default:
		expert_add_info_format(pinfo, ti, &ei_xip_serval_bad_ext,
			"Unrecognized Serval extension header type: 0x%02x",
			type);
		return 0;
	}
}

static void
display_xip_serval(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *xip_serval_tree;
	proto_item *ti, *hl_ti;
	tvbuff_t *next_tvb;

	vec_t cksum_vec;
	int offset;
	uint8_t xsh_len, protocol, bytes_remaining;

	/* Get XIP Serval header length, stored as number of 32-bit words. */
	xsh_len = tvb_get_uint8(tvb, XSRVL_LEN) << 2;

	/* Create XIP Serval header tree. */
	ti = proto_tree_add_item(tree, proto_xip_serval, tvb,
		0, xsh_len, ENC_NA);
	xip_serval_tree = proto_item_add_subtree(ti, ett_xip_serval_tree);

	/* Add XIP Serval header length. */
	hl_ti = proto_tree_add_item(xip_serval_tree, hf_xip_serval_hl, tvb,
		XSRVL_LEN, 1, ENC_BIG_ENDIAN);
	if (tvb_captured_length(tvb) < xsh_len)
		expert_add_info_format(pinfo, hl_ti, &ei_xip_serval_bad_len,
			"Header Length field (%d bytes) cannot be greater than actual number of bytes left in packet (%d bytes)",
			xsh_len, tvb_captured_length(tvb));

	/* Add XIP Serval protocol. If it's not data, TCP, or UDP, the
	 * packet is malformed.
	 */
	proto_tree_add_item(xip_serval_tree, hf_xip_serval_proto, tvb,
		XSRVL_PRO, 1, ENC_BIG_ENDIAN);
	protocol = tvb_get_uint8(tvb, XSRVL_PRO);
	if (!try_val_to_str(protocol, xip_serval_proto_vals))
		expert_add_info_format(pinfo, ti, &ei_xip_serval_bad_proto,
			"Unrecognized protocol type: %d", protocol);

	/* Compute checksum. */
	SET_CKSUM_VEC_TVB(cksum_vec, tvb, 0, xsh_len);

	proto_tree_add_checksum(xip_serval_tree, tvb, XSRVL_CHK, hf_xip_serval_check, hf_xip_serval_check_status, &ei_xip_serval_bad_checksum, pinfo, in_cksum(&cksum_vec, 1),
							ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
	offset = XSRVL_EXT;

	/* If there's still more room, check for extension headers. */
	bytes_remaining = xsh_len - offset;
	while (bytes_remaining >= XIP_SERVAL_EXT_MIN_LEN) {
		int8_t bytes_displayed = display_xip_serval_ext(tvb, pinfo, ti,
			xip_serval_tree, offset);

		/* Extension headers are malformed, so we can't say
		 * what the rest of the packet holds. Stop dissecting.
		 */
		if (bytes_displayed <= 0)
			return;

		offset += bytes_displayed;
		bytes_remaining -= bytes_displayed;
	}

	switch (protocol) {
	case XIP_SERVAL_PROTO_DATA:
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		call_data_dissector(next_tvb, pinfo, tree);
		break;
	case IP_PROTO_TCP: {
		/* Get the Data Offset field of the TCP header, which is
		 * the high nibble of the 12th octet and represents the
		 * size of the TCP header of 32-bit words.
		 */
		uint8_t tcp_len = hi_nibble(tvb_get_uint8(tvb, offset + 12))*4;
		next_tvb = tvb_new_subset_length(tvb, offset, tcp_len);
		call_dissector(tcp_handle, next_tvb, pinfo, tree);
		break;
	}
	case IP_PROTO_UDP:
		/* The UDP header is always 8 bytes. */
		next_tvb = tvb_new_subset_length(tvb, offset, 8);
		call_dissector(udp_handle, next_tvb, pinfo, tree);
		break;
	default:
		break;
	}
}

static int
dissect_xip_serval(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data _U_)
{
	if (tvb_reported_length(tvb) < XIP_SERVAL_MIN_LEN)
		return 0;

	col_append_str(pinfo->cinfo, COL_INFO, " (with Serval)");

	display_xip_serval(tvb, pinfo, tree);
	return tvb_captured_length(tvb);
}

void
proto_register_xip_serval(void)
{
	static hf_register_info hf[] = {

		/* Serval Header. */

		{ &hf_xip_serval_hl,
		{ "Header Length", "xip_serval.hl", FT_UINT8,
		   BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,	NULL, HFILL }},

		{ &hf_xip_serval_proto,
		{ "Protocol", "xip_serval.proto", FT_UINT8,
		   BASE_DEC, VALS(xip_serval_proto_vals), 0x0, NULL, HFILL }},

		{ &hf_xip_serval_check,
		{ "Checksum", "xip_serval.check", FT_UINT16,
		   BASE_HEX, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_serval_check_status,
		{ "Checksum Status", "xip_serval.check.status", FT_UINT8,
		   BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL }},

		/* Serval Extension Header. */

		{ &hf_xip_serval_ext_type,
		{ "Extension Type", "xip_serval.ext_type", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_serval_ext_length,
		{ "Extension Length", "xip_serval.ext_length", FT_UINT8,
		   BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,	NULL, HFILL }},

		/* Serval Control Extension Header. */

		{ &hf_xip_serval_cext,
		{ "Serval Control Extension", "xip_serval.cext",
		   FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_flags,
		{ "Flags", "xip_serval.cext_flags", FT_UINT8, BASE_HEX,
		  NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_syn,
		{ "SYN", "xip_serval.cext_syn", FT_BOOLEAN, 8,
		  TFS(&tfs_set_notset), 0x80, NULL, HFILL }},

		{ &hf_xip_serval_cext_rsyn,
		{ "RSYN", "xip_serval.cext_rsyn", FT_BOOLEAN, 8,
		  TFS(&tfs_set_notset), 0x40, NULL, HFILL }},

		{ &hf_xip_serval_cext_ack,
		{ "ACK", "xip_serval.cext_ack", FT_BOOLEAN, 8,
		  TFS(&tfs_set_notset), 0x20, NULL, HFILL }},

		{ &hf_xip_serval_cext_nack,
		{ "NACK", "xip_serval.cext_nack", FT_BOOLEAN, 8,
		  TFS(&tfs_set_notset), 0x10, NULL, HFILL }},

		{ &hf_xip_serval_cext_rst,
		{ "RST", "xip_serval.cext_rst", FT_BOOLEAN, 8,
		  TFS(&tfs_set_notset), 0x08, NULL, HFILL }},

		{ &hf_xip_serval_cext_fin,
		{ "FIN", "xip_serval.cext_fin", FT_BOOLEAN, 8,
		  TFS(&tfs_set_notset), 0x04, NULL, HFILL }},

		{ &hf_xip_serval_cext_verno,
		{ "Version Number", "xip_serval.cext_verno", FT_UINT32,
		  BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_ackno,
		{ "Acknowledgement Number", "xip_serval.cext_ackno",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_nonce,
		{ "Nonce", "xip_serval.cext_nonce", FT_BYTES,
		  SEP_SPACE, NULL, 0x0, NULL, HFILL }}
	};

	static int *ett[] = {
		&ett_xip_serval_tree,
		&ett_xip_serval_cext,
		&ett_xip_serval_cext_flags
	};

	static ei_register_info ei[] = {

		{ &ei_xip_serval_bad_len,
		{ "xip_serval.bad_len", PI_MALFORMED, PI_ERROR,
		  "Bad header length", EXPFILL }},

		{ &ei_xip_serval_bad_ext,
		{ "xip_serval.bad_ext", PI_MALFORMED, PI_ERROR,
		  "Bad extension header type", EXPFILL }},

		{ &ei_xip_serval_bad_proto,
		{ "xip_serval.bad_proto", PI_MALFORMED, PI_ERROR,
		  "Bad protocol type", EXPFILL }},

		{ &ei_xip_serval_bad_checksum,
		{ "xip_serval.bad_checksum", PI_MALFORMED, PI_ERROR,
		  "Incorrect checksum", EXPFILL }}
	};

	expert_module_t* expert_xip_serval;

	proto_xip_serval = proto_register_protocol("XIP Serval", "XIP Serval", "xipserval");
	register_dissector("xipserval", dissect_xip_serval,
		proto_xip_serval);
	proto_register_field_array(proto_xip_serval, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_xip_serval = expert_register_protocol(proto_xip_serval);
	expert_register_field_array(expert_xip_serval, ei, array_length(ei));
}

void
proto_reg_handoff_xip_serval(void)
{
	tcp_handle = find_dissector_add_dependency("tcp", proto_xip_serval);
	udp_handle = find_dissector_add_dependency("udp", proto_xip_serval);
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
