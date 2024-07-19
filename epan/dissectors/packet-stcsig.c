/* packet-stcsig.c
 * Routines for dissecting Spirent Test Center Signatures
 * Copyright 2018 Joerg Mayer (see AUTHORS file)
 * Based on disassembly of Spirent's modified version of Wireshark 1.10.3
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* The logic is based on the dissassembly of libwireshark.dll which was
 * part of wireshark-win64-1.10.3-spirent-2.exe, distributed by Spirent
 * to customers of their Spirent Test Center.
 * As the installer displays the normal GPLv2+ license the choice was
 * made to go with dissassembly instead of finding out who to ask for
 * the source code.
 *
 * Please report errors or missing features when compared to the original.
 */

/* TODO:
 * - Find out the meaning of the unknown trailer (perhaps some fcs or
 *   some prbseq related stuff?)
 * - Find out meaning of prbseq
 * - Is there a (fixed) structure in the csp field?
 * - Validate the timestamp decoding: The seconds value is identical to
 *   Spirent's stcsig dissector, the ns value differs significantly
 * - Find out what the TSLR really stands for - currently just a guess
 */
#include "config.h"

#include <epan/packet.h>
#include <tfs.h>

void proto_register_stcsig(void);
void proto_reg_handoff_stcsig(void);

#define PROTO_SHORT_NAME "STCSIG"
#define PROTO_LONG_NAME "Spirent Test Center Signature"

static int proto_stcsig;

static int hf_stcsig_csp;
static int hf_stcsig_iv;
static int hf_stcsig_prbseq;
static int hf_stcsig_rawdata;
static int hf_stcsig_seqnum_complement;
static int hf_stcsig_seqnum_edm;
static int hf_stcsig_seqnum_sm;
static int hf_stcsig_streamid;
static int hf_stcsig_streamindex;
static int hf_stcsig_streamtype;
static int hf_stcsig_timestamp;
static int hf_stcsig_tslr;
static int hf_stcsig_unknown;

static int ett_stcsig;
static int ett_stcsig_streamid;

static const true_false_string tfs_end_start = { "EndOfFrame", "StartOfFrame" };

static const true_false_string tfs_hard_soft = { "Hard", "Soft" };

/*
 * For the last 20 bytes of the data section to be a Spirent Signature
 * the fist byte (offset 0) plus the 11th byte (offset 10) of the deocded
 * signature must add up to 255
 */
static bool
is_signature(tvbuff_t *tvb, int sigoffset)
{
	/*
	 * How to generate the table below:
	 *
	 * static uint8_t runit = 1;
	 * for(int k=0; k<256; k++) {
	 * 	obfuscation_value = k;
	 * 	for(int i=1; i<=10; i++) {
	 * 		obfuscation_value = deobfuscate_this[obfuscation_value];
	 * 	}
	 * 	printf("0x%02x, ", obfuscation_value);
	 * 	if (k%8 == 7) printf("\n");
	 * }
	 */

	static const uint8_t deobfuscate_offset_10[256] = {
		0x00, 0x86, 0x0d, 0x8b, 0x9d, 0x1b, 0x90, 0x16,
		0xbc, 0x3a, 0xb1, 0x37, 0x21, 0xa7, 0x2c, 0xaa,
		0x78, 0xfe, 0x75, 0xf3, 0xe5, 0x63, 0xe8, 0x6e,
		0xc4, 0x42, 0xc9, 0x4f, 0x59, 0xdf, 0x54, 0xd2,
		0xf1, 0x77, 0xfc, 0x7a, 0x6c, 0xea, 0x61, 0xe7,
		0x4d, 0xcb, 0x40, 0xc6, 0xd0, 0x56, 0xdd, 0x5b,
		0x89, 0x0f, 0x84, 0x02, 0x14, 0x92, 0x19, 0x9f,
		0x35, 0xb3, 0x38, 0xbe, 0xa8, 0x2e, 0xa5, 0x23,
		0xe2, 0x64, 0xef, 0x69, 0x7f, 0xf9, 0x72, 0xf4,
		0x5e, 0xd8, 0x53, 0xd5, 0xc3, 0x45, 0xce, 0x48,
		0x9a, 0x1c, 0x97, 0x11, 0x07, 0x81, 0x0a, 0x8c,
		0x26, 0xa0, 0x2b, 0xad, 0xbb, 0x3d, 0xb6, 0x30,
		0x13, 0x95, 0x1e, 0x98, 0x8e, 0x08, 0x83, 0x05,
		0xaf, 0x29, 0xa2, 0x24, 0x32, 0xb4, 0x3f, 0xb9,
		0x6b, 0xed, 0x66, 0xe0, 0xf6, 0x70, 0xfb, 0x7d,
		0xd7, 0x51, 0xda, 0x5c, 0x4a, 0xcc, 0x47, 0xc1,
		0x43, 0xc5, 0x4e, 0xc8, 0xde, 0x58, 0xd3, 0x55,
		0xff, 0x79, 0xf2, 0x74, 0x62, 0xe4, 0x6f, 0xe9,
		0x3b, 0xbd, 0x36, 0xb0, 0xa6, 0x20, 0xab, 0x2d,
		0x87, 0x01, 0x8a, 0x0c, 0x1a, 0x9c, 0x17, 0x91,
		0xb2, 0x34, 0xbf, 0x39, 0x2f, 0xa9, 0x22, 0xa4,
		0x0e, 0x88, 0x03, 0x85, 0x93, 0x15, 0x9e, 0x18,
		0xca, 0x4c, 0xc7, 0x41, 0x57, 0xd1, 0x5a, 0xdc,
		0x76, 0xf0, 0x7b, 0xfd, 0xeb, 0x6d, 0xe6, 0x60,
		0xa1, 0x27, 0xac, 0x2a, 0x3c, 0xba, 0x31, 0xb7,
		0x1d, 0x9b, 0x10, 0x96, 0x80, 0x06, 0x8d, 0x0b,
		0xd9, 0x5f, 0xd4, 0x52, 0x44, 0xc2, 0x49, 0xcf,
		0x65, 0xe3, 0x68, 0xee, 0xf8, 0x7e, 0xf5, 0x73,
		0x50, 0xd6, 0x5d, 0xdb, 0xcd, 0x4b, 0xc0, 0x46,
		0xec, 0x6a, 0xe1, 0x67, 0x71, 0xf7, 0x7c, 0xfa,
		0x28, 0xae, 0x25, 0xa3, 0xb5, 0x33, 0xb8, 0x3e,
		0x94, 0x12, 0x99, 0x1f, 0x09, 0x8f, 0x04, 0x82
	};
	uint8_t	byte0;
	uint8_t byte10;

	/* Byte 0 also is the initialization vector for the obfuscation of offsets 1 - 15 */
	byte0 = tvb_get_uint8(tvb, sigoffset);
	byte10 = tvb_get_uint8(tvb, sigoffset + 10);

	if (byte0 + (byte10 ^ deobfuscate_offset_10[byte0]) == 255) {
		return true;
	} else {
		return false;
	}
}

static void
decode_signature(uint8_t* decode_buffer)
{
	static const uint8_t deobfuscate_this[256] = {
		0x00, 0x71, 0xe3, 0x92, 0xb6, 0xc7, 0x55, 0x24,
		0x1c, 0x6d, 0xff, 0x8e, 0xaa, 0xdb, 0x49, 0x38,
		0x39, 0x48, 0xda, 0xab, 0x8f, 0xfe, 0x6c, 0x1d,
		0x25, 0x54, 0xc6, 0xb7, 0x93, 0xe2, 0x70, 0x01,
		0x72, 0x03, 0x91, 0xe0, 0xc4, 0xb5, 0x27, 0x56,
		0x6e, 0x1f, 0x8d, 0xfc, 0xd8, 0xa9, 0x3b, 0x4a,
		0x4b, 0x3a, 0xa8, 0xd9, 0xfd, 0x8c, 0x1e, 0x6f,
		0x57, 0x26, 0xb4, 0xc5, 0xe1, 0x90, 0x02, 0x73,
		0xe4, 0x95, 0x07, 0x76, 0x52, 0x23, 0xb1, 0xc0,
		0xf8, 0x89, 0x1b, 0x6a, 0x4e, 0x3f, 0xad, 0xdc,
		0xdd, 0xac, 0x3e, 0x4f, 0x6b, 0x1a, 0x88, 0xf9,
		0xc1, 0xb0, 0x22, 0x53, 0x77, 0x06, 0x94, 0xe5,
		0x96, 0xe7, 0x75, 0x04, 0x20, 0x51, 0xc3, 0xb2,
		0x8a, 0xfb, 0x69, 0x18, 0x3c, 0x4d, 0xdf, 0xae,
		0xaf, 0xde, 0x4c, 0x3d, 0x19, 0x68, 0xfa, 0x8b,
		0xb3, 0xc2, 0x50, 0x21, 0x05, 0x74, 0xe6, 0x97,
		0xb8, 0xc9, 0x5b, 0x2a, 0x0e, 0x7f, 0xed, 0x9c,
		0xa4, 0xd5, 0x47, 0x36, 0x12, 0x63, 0xf1, 0x80,
		0x81, 0xf0, 0x62, 0x13, 0x37, 0x46, 0xd4, 0xa5,
		0x9d, 0xec, 0x7e, 0x0f, 0x2b, 0x5a, 0xc8, 0xb9,
		0xca, 0xbb, 0x29, 0x58, 0x7c, 0x0d, 0x9f, 0xee,
		0xd6, 0xa7, 0x35, 0x44, 0x60, 0x11, 0x83, 0xf2,
		0xf3, 0x82, 0x10, 0x61, 0x45, 0x34, 0xa6, 0xd7,
		0xef, 0x9e, 0x0c, 0x7d, 0x59, 0x28, 0xba, 0xcb,
		0x5c, 0x2d, 0xbf, 0xce, 0xea, 0x9b, 0x09, 0x78,
		0x40, 0x31, 0xa3, 0xd2, 0xf6, 0x87, 0x15, 0x64,
		0x65, 0x14, 0x86, 0xf7, 0xd3, 0xa2, 0x30, 0x41,
		0x79, 0x08, 0x9a, 0xeb, 0xcf, 0xbe, 0x2c, 0x5d,
		0x2e, 0x5f, 0xcd, 0xbc, 0x98, 0xe9, 0x7b, 0x0a,
		0x32, 0x43, 0xd1, 0xa0, 0x84, 0xf5, 0x67, 0x16,
		0x17, 0x66, 0xf4, 0x85, 0xa1, 0xd0, 0x42, 0x33,
		0x0b, 0x7a, 0xe8, 0x99, 0xbd, 0xcc, 0x5e, 0x2f
	};
	uint8_t obfuscation_value;

	obfuscation_value = decode_buffer[0];

	for(int i=1; i<16; i++) {
		obfuscation_value = deobfuscate_this[obfuscation_value];
		decode_buffer[i] ^= obfuscation_value;
	}
	/* decode_buffer[16...19] is unobfuscated */
}

static int
dissect_stcsig(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int        bytes, length;
	int        sig_offset;

	tvbuff_t   *stcsig_tvb;
	proto_item *ti;
	proto_tree *stcsig_tree;
	proto_tree *stcsig_streamid_tree;
	uint8_t    *real_stcsig;

	uint64_t   timestamp_2_5_ns;
	nstime_t   timestamp;

	length = tvb_captured_length(tvb);
	if (length >= 21 && tvb_get_uint8(tvb, length - 21) == 0 && is_signature(tvb, length - 20)) {
		bytes = 20;
	} else if (length >= 25 && tvb_get_uint8(tvb, length - 25) == 0 && is_signature(tvb, length - 24)) {
		/* Sigsize + 4 bytes FCS */
		bytes = 24;
	} else if (length >= 29 && tvb_get_uint8(tvb, length - 29) == 0 && is_signature(tvb, length - 28)) {
		/* Sigsize + 8 bytes FCS, i.e. FibreChannel */
		bytes = 28;
	} else if (length >= 20 && is_signature(tvb, length - 20)) {
		bytes = 20;
	} else if (length >= 24 && is_signature(tvb, length - 24)) {
		/* Sigsize + 4 bytes FCS */
		bytes = 24;
	} else if (length >= 28 && is_signature(tvb, length - 28)) {
		/* Sigsize + 8 bytes FCS, i.e. FibreChannel */
		bytes = 28;
	} else {
		return 0;
	}
	sig_offset = length - bytes;

#if 0
	/* Maybe make this a preference */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	col_set_str(pinfo->cinfo, COL_INFO, PROTO_LONG_NAME);
#endif

	real_stcsig = (uint8_t *)tvb_memdup(pinfo->pool, tvb, sig_offset, 20);
	decode_signature(real_stcsig);
	stcsig_tvb = tvb_new_child_real_data(tvb, real_stcsig, 20, 20);
	add_new_data_source(pinfo, stcsig_tvb, PROTO_LONG_NAME);

	ti = proto_tree_add_item(tree, proto_stcsig, tvb, sig_offset, 20, ENC_NA);
	stcsig_tree = proto_item_add_subtree(ti, ett_stcsig);

	proto_tree_add_item(stcsig_tree, hf_stcsig_rawdata, tvb, sig_offset, 20, ENC_NA);
	proto_tree_add_item(stcsig_tree, hf_stcsig_iv, stcsig_tvb, 0, 1, ENC_NA);
	ti = proto_tree_add_item(stcsig_tree, hf_stcsig_streamid, stcsig_tvb, 1, 4, ENC_BIG_ENDIAN);
	stcsig_streamid_tree = proto_item_add_subtree(ti, ett_stcsig_streamid);
	/* This subtree is mostly an optical hierarchy, auto expand it */
	tree_expanded_set(ett_stcsig_streamid, true);
	proto_tree_add_item(stcsig_streamid_tree, hf_stcsig_csp, stcsig_tvb, 1, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(stcsig_streamid_tree, hf_stcsig_streamtype, stcsig_tvb, 3, 1, ENC_NA);
	proto_tree_add_item(stcsig_streamid_tree, hf_stcsig_streamindex, stcsig_tvb, 3, 2, ENC_BIG_ENDIAN);
	if (tvb_get_ntohs(stcsig_tvb, 5) + tvb_get_ntohs(stcsig_tvb, 7) == 0xffff) {
		proto_tree_add_item(stcsig_tree, hf_stcsig_seqnum_complement, stcsig_tvb, 5, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(stcsig_tree, hf_stcsig_seqnum_edm, stcsig_tvb, 7, 4, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item(stcsig_tree, hf_stcsig_seqnum_sm, stcsig_tvb, 5, 6, ENC_BIG_ENDIAN);
	}
	timestamp_2_5_ns = (uint64_t)(tvb_get_uint8(stcsig_tvb, 15) & 0xfc) << 30;
	timestamp_2_5_ns |= tvb_get_ntohl(stcsig_tvb, 11);
	timestamp.secs = (time_t)(timestamp_2_5_ns / 400000000L);
	timestamp.nsecs = (int)(timestamp_2_5_ns % 400000000L);
	proto_tree_add_time(stcsig_tree, hf_stcsig_timestamp, stcsig_tvb, 11, 5, &timestamp);
	proto_tree_add_item(stcsig_tree, hf_stcsig_prbseq, stcsig_tvb, 15, 1, ENC_NA);
	proto_tree_add_item(stcsig_tree, hf_stcsig_tslr, stcsig_tvb, 15, 1, ENC_NA);
	proto_tree_add_item(stcsig_tree, hf_stcsig_unknown, stcsig_tvb, 16, 4, ENC_NA);

	/* Ignored for post-dissectors but required by function type */
	return length;
}

void
proto_register_stcsig(void)
{
	static hf_register_info hf[] = {
		{ &hf_stcsig_rawdata,
			{ "Raw Data", "stcsig.rawdata",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_stcsig_iv,
			{ "IV", "stcsig.iv",
			  FT_UINT8, BASE_HEX, NULL, 0x0,
			  "Deobfuscation Initialization Vector and Complement of Sequence Low Byte", HFILL }
		},
		{ &hf_stcsig_streamid,
			{ "StreamID", "stcsig.streamid",
			  FT_INT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_stcsig_csp,
			{ "ChassisSlotPort", "stcsig.csp",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_stcsig_seqnum_complement,
			{ "Complement (EDM)", "stcsig.complement",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  "Complement of high bytes of Sequence Number", HFILL }
		},
		{ &hf_stcsig_seqnum_edm,
			{ "Sequence Number (EDM)", "stcsig.seqnum",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "Sequence Number (Enhanced Detection Mode)", HFILL }
		},
		{ &hf_stcsig_seqnum_sm,
			{ "Sequence Number (SM)", "stcsig.seqnum.sm",
			  FT_UINT48, BASE_DEC, NULL, 0x0,
			  "Sequence Number (Sequence Mode)", HFILL }
		},
		{ &hf_stcsig_streamindex,
			{ "Stream Index", "stcsig.streamindex",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_stcsig_timestamp,
			{ "Timestamp", "stcsig.timestamp",
			  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_stcsig_prbseq,
			{ "Pseudo-Random Binary Sequence", "stcsig.prbseq",
			  FT_BOOLEAN, 8, NULL, 0x02,
			  NULL, HFILL }
		},
		{ &hf_stcsig_tslr,
			{ "TSLR", "stcsig.tslr",
			  FT_BOOLEAN, 8, TFS(&tfs_end_start), 0x01,
			  "Time Stamp Location Reference", HFILL }
		},
		{ &hf_stcsig_streamtype,
			{ "StreamType", "stcsig.streamtype",
			  FT_BOOLEAN, 8, TFS(&tfs_hard_soft), 0x80,
			  NULL, HFILL }
		},
		{ &hf_stcsig_unknown,
			{ "Unknown", "stcsig.unknown",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  "Unknown Trailer (not obfuscated)", HFILL }
		},
	};

	static int *ett[] = {
		&ett_stcsig,
		&ett_stcsig_streamid
	};

	dissector_handle_t stcsig_handle;

	proto_stcsig = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "stcsig");

	proto_register_field_array(proto_stcsig, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	stcsig_handle = register_dissector("stcsig", dissect_stcsig, proto_stcsig);
	register_postdissector(stcsig_handle);

	/* STCSIG is a rarely used case, disable it by default for performance reasons. */
	proto_disable_by_default(proto_stcsig);
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
