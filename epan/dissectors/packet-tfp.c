/* packet-tfp.c
 * Routines for Tinkerforge protocol packet disassembly
 * By Ishraq Ibne Ashraf <ishraq@tinkerforge.com>
 * Copyright 2013 Ishraq Ibne Ashraf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-usb.h"

/* defines */
#define tfp_PORT 4223 /* Not IANA registered */

#define tfp_USB_VENDOR_ID  0x16D0
#define tfp_USB_PRODUCT_ID 0x063D

#define BASE58_MAX_STR_SIZE 13

void proto_reg_handoff_tfp(void);
void proto_register_tfp(void);

static dissector_handle_t tfp_handle_tcp;

/* variables for creating the tree */
static int proto_tfp;
static int ett_tfp;

/* header field variables */
static int hf_tfp_uid;
static int hf_tfp_uid_numeric;
static int hf_tfp_len;
static int hf_tfp_fid;
static int hf_tfp_seq;
static int hf_tfp_r;
static int hf_tfp_a;
static int hf_tfp_oo;
static int hf_tfp_e;
static int hf_tfp_future_use;
static int hf_tfp_payload;

/* bit and byte offsets for dissection */
static const int byte_offset_len	   = 4;
static const int byte_offset_fid	   = 5;
static const int byte_count_tfp_uid	   = 4;
static const int byte_count_tfp_len	   = 1;
static const int byte_count_tfp_fid	   = 1;
static const int byte_count_tfp_flags	   = 2;
static const int bit_count_tfp_seq	   = 4;
static const int bit_count_tfp_r	   = 1;
static const int bit_count_tfp_a	   = 1;
static const int bit_count_tfp_oo	   = 2;
static const int bit_count_tfp_e	   = 2;
static const int bit_count_tfp_future_use = 6;

/* base58 encoding variable */
static const char BASE58_ALPHABET[] =
	"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

/* function for encoding a number to base58 string */
static void
base58_encode(uint32_t value, char *str) {

	uint32_t mod;
	int     i = 0;
	int     k;
	char	reverse_str[BASE58_MAX_STR_SIZE] = {'\0'};

	while (value >= 58) {
		mod = value % 58;
		reverse_str[i] = BASE58_ALPHABET[mod];
		value = value / 58;
		++i;
	}

	reverse_str[i] = BASE58_ALPHABET[value];

	for (k = 0; k <= i; k++) {
		str[k] = reverse_str[i - k];
	}

	for (; k < BASE58_MAX_STR_SIZE; k++) {
		str[k] = '\0';
	}
}

/* common dissector function for dissecting TFP payloads */
static void
dissect_tfp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	int    byte_offset = 0;
	int    bit_offset  = 48;

	uint8_t hv_tfp_len;
	uint8_t hv_tfp_fid;
	uint8_t hv_tfp_seq;

	char   tfp_uid_string[BASE58_MAX_STR_SIZE];

	base58_encode(tvb_get_letohl(tvb, 0), &tfp_uid_string[0]);

	hv_tfp_len = tvb_get_uint8(tvb, byte_offset_len);
	hv_tfp_fid = tvb_get_uint8(tvb, byte_offset_fid);
	hv_tfp_seq = tvb_get_bits8(tvb, bit_offset, bit_count_tfp_seq);

	col_add_fstr(pinfo->cinfo, COL_INFO,
			"UID: %s, Len: %d, FID: %d, Seq: %d",
			&tfp_uid_string[0], hv_tfp_len, hv_tfp_fid, hv_tfp_seq);

	/* call for details */
	if (tree) {
		proto_tree *tfp_tree;
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_tfp, tvb, 0, -1,
						    "Tinkerforge Protocol, UID: %s, Len: %d, FID: %d, Seq: %d",
						    &tfp_uid_string[0], hv_tfp_len, hv_tfp_fid, hv_tfp_seq);
		tfp_tree = proto_item_add_subtree(ti, ett_tfp);

		/* Use ...string_format_value() so we can show the complete generated string but specify */
		/*  the field length as being just the 4 bytes from which the string is generated.	 */
		ti = proto_tree_add_string_format_value(tfp_tree,
							hf_tfp_uid,
							tvb, byte_offset, byte_count_tfp_uid,
							&tfp_uid_string[0], "%s", &tfp_uid_string[0]);
		proto_item_set_generated(ti);

		proto_tree_add_item(tfp_tree,
				    hf_tfp_uid_numeric,
				    tvb,
				    byte_offset,
				    byte_count_tfp_uid,
				    ENC_LITTLE_ENDIAN);

		byte_offset += byte_count_tfp_uid;

		proto_tree_add_item(tfp_tree,
				    hf_tfp_len,
				    tvb,
				    byte_offset,
				    byte_count_tfp_len,
				    ENC_LITTLE_ENDIAN);

		byte_offset += byte_count_tfp_len;

		proto_tree_add_item(tfp_tree,
				    hf_tfp_fid,
				    tvb,
				    byte_offset,
				    byte_count_tfp_fid,
				    ENC_LITTLE_ENDIAN);

		byte_offset += byte_count_tfp_fid;

		proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_seq,
					 tvb,
					 bit_offset,
					 bit_count_tfp_seq,
					 ENC_LITTLE_ENDIAN);

		bit_offset += bit_count_tfp_seq;

		proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_r,
					 tvb,
					 bit_offset,
					 bit_count_tfp_r,
					 ENC_LITTLE_ENDIAN);

		bit_offset += bit_count_tfp_r;

		proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_a,
					 tvb,
					 bit_offset,
					 bit_count_tfp_a,
					 ENC_LITTLE_ENDIAN);

		bit_offset += bit_count_tfp_a;

		proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_oo,
					 tvb,
					 bit_offset,
					 bit_count_tfp_oo,
					 ENC_LITTLE_ENDIAN);

		bit_offset += bit_count_tfp_oo;

		proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_e,
					 tvb,
					 bit_offset,
					 bit_count_tfp_e,
					 ENC_LITTLE_ENDIAN);

		bit_offset += bit_count_tfp_e;

		proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_future_use,
					 tvb,
					 bit_offset,
					 bit_count_tfp_future_use,
					 ENC_LITTLE_ENDIAN);

		/*bit_offset += bit_count_tfp_future_use;*/

		if ((tvb_reported_length(tvb)) > 8) {

			byte_offset += byte_count_tfp_flags;

			proto_tree_add_item(tfp_tree, hf_tfp_payload, tvb, byte_offset, -1, ENC_NA);
		}
	}
}

/* dissector function for dissecting TCP payloads */
static int
dissect_tfp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TFP over TCP");
	col_clear(pinfo->cinfo, COL_INFO);

	dissect_tfp_common(tvb, pinfo, tree);
	return tvb_captured_length(tvb);
}

/* dissector function for dissecting USB payloads */
static bool
dissect_tfp_bulk_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	usb_conv_info_t *usb_conv_info = (usb_conv_info_t *)data;

	if ((usb_conv_info != NULL) &&
		(usb_conv_info->deviceVendor == tfp_USB_VENDOR_ID) &&
		(usb_conv_info->deviceProduct == tfp_USB_PRODUCT_ID)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TFP over USB");
		col_clear(pinfo->cinfo, COL_INFO);
		dissect_tfp_common(tvb, pinfo, tree);
		return true;
	}

	return false;
}

/* protocol register function */
void
proto_register_tfp(void)
{
	/* defining header formats */
	static hf_register_info hf_tfp[] = {
		{ &hf_tfp_uid,
			{ "UID (String)",
			  "tfp.uid",
			  FT_STRINGZ,
			  BASE_NONE,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		},
		{ &hf_tfp_uid_numeric,
			{ "UID (Numeric)",
			  "tfp.uid_numeric",
			  FT_UINT32,
			  BASE_DEC,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		},
		{ &hf_tfp_len,
			{ "Length",
			  "tfp.len",
			  FT_UINT8,
			  BASE_DEC,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		},
		{ &hf_tfp_fid,
			{ "Function ID",
			  "tfp.fid",
			  FT_UINT8,
			  BASE_DEC,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		},
		{ &hf_tfp_seq,
			{ "Sequence Number",
			  "tfp.seq",
			  FT_UINT8,
			  BASE_DEC,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		},
		{ &hf_tfp_r,
			{ "Response Expected",
			  "tfp.r",
			  FT_UINT8,
			  BASE_DEC,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		},
		{ &hf_tfp_a,
			{ "Authentication",
			  "tfp.a",
			  FT_UINT8,
			  BASE_DEC,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		},
		{ &hf_tfp_oo,
			{ "Other Options",
			  "tfp.oo",
			  FT_UINT8,
			  BASE_DEC,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		},
		{ &hf_tfp_e,
			{ "Error Code",
			  "tfp.e",
			  FT_UINT8,
			  BASE_DEC,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		},
		{ &hf_tfp_future_use,
			{ "Future Use",
			  "tfp.future_use",
			  FT_UINT8,
			  BASE_DEC,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		},
		{ &hf_tfp_payload,
			{ "Payload",
			  "tfp.payload",
			  FT_BYTES,
			  BASE_NONE,
			  NULL,
			  0x0,
			  NULL,
			  HFILL
			}
		}
	};

	/* setup protocol subtree array */
	static int *ett[] = {
		&ett_tfp
	};

	/* defining the protocol and its names */
	proto_tfp = proto_register_protocol (
		"Tinkerforge Protocol",
		"TFP",
		"tfp"
	);

	proto_register_field_array(proto_tfp, hf_tfp, array_length(hf_tfp));
	proto_register_subtree_array(ett, array_length(ett));
	tfp_handle_tcp = register_dissector("tfp", dissect_tfp_tcp, proto_tfp);
}

/* handoff function */
void
proto_reg_handoff_tfp(void) {

	dissector_add_uint_with_preference("tcp.port", tfp_PORT, tfp_handle_tcp);
	heur_dissector_add("usb.bulk", dissect_tfp_bulk_heur, "Tinkerforge USB bulk endpoint", "tfp_usb_bulk", proto_tfp, HEURISTIC_ENABLE);
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
