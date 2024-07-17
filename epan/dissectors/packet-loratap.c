/* packet-loratap.c
 * Dissector routines for the LoRaTap encapsulation
 * By Erik de Jong <erikdejong@gmail.com>
 * Copyright 2017 Erik de Jong
 *
 * LoRaTap encapsulation, version 1
 * By Ales Povalac <alpov@alpov.net>
 * Copyright 2022 Ales Povalac
 * 
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <epan/to_str.h>

void proto_reg_handoff_loratap(void);
void proto_register_loratap(void);

static dissector_handle_t loratap_handle;

static dissector_table_t loratap_dissector_table;

static int proto_loratap;
static int hf_loratap_header_version_type;
static int hf_loratap_header_length_type;
static int hf_loratap_header_padding;
static int hf_loratap_header_channel_type;
static int hf_loratap_header_channel_frequency_type;
static int hf_loratap_header_channel_bandwidth_type;
static int hf_loratap_header_channel_sf_type;
static int hf_loratap_header_rssi_type;
static int hf_loratap_header_rssi_packet_type;
static int hf_loratap_header_rssi_max_type;
static int hf_loratap_header_rssi_current_type;
static int hf_loratap_header_rssi_snr_type;
static int hf_loratap_header_syncword_type;
static int hf_loratap_header_tag_type;
static int hf_loratap_header_payload_type;
static int hf_loratap_header_source_gw_type;
static int hf_loratap_header_timestamp_type;
static int hf_loratap_header_datarate_type;
static int hf_loratap_header_if_channel_type;
static int hf_loratap_header_rf_chain_type;
static int hf_loratap_header_cr_type;
static int hf_loratap_header_flags_type;
static int hf_loratap_header_flags_mod_fsk_type;
static int hf_loratap_header_flags_iq_inverted_type;
static int hf_loratap_header_flags_implicit_hdr_type;
static int hf_loratap_header_flags_crc_type;
static int hf_loratap_header_flags_padding_type;

static int * const hfx_loratap_header_flags[] = {
	&hf_loratap_header_flags_mod_fsk_type,
	&hf_loratap_header_flags_iq_inverted_type,
	&hf_loratap_header_flags_implicit_hdr_type,
	&hf_loratap_header_flags_crc_type,
	&hf_loratap_header_flags_padding_type,
	NULL
};

static int ett_loratap;
static int ett_loratap_flags;
static int ett_loratap_channel;
static int ett_loratap_rssi;

static const value_string channel_bandwidth[] = {
	{ 1, "125 kHz" },
	{ 2, "250 kHz" },
	{ 4, "500 kHz" },
	{ 0, NULL}
};

static const value_string syncwords[] = {
	{ 0x12, "Private LoRa" },
	{ 0x34, "LoRaWAN" },
	{ 0, NULL}
};

static const value_string coding_rates[] = {
	{ 0, "none" },
	{ 5, "4/5" },
	{ 6, "4/6" },
	{ 7, "4/7" },
	{ 8, "4/8" },
	{ 0, NULL}
};

static const value_string crc_state[] = {
	{ 1, "CRC OK" },
	{ 2, "CRC Bad" },
	{ 4, "No CRC" },
	{ 0, NULL}
};

static void
rssi_base_custom(char *buffer, uint32_t value)
{
	if (value == 255) {
		snprintf(buffer, ITEM_LABEL_LENGTH, "N/A");
	} else {
		snprintf(buffer, ITEM_LABEL_LENGTH, "%.0f dBm", -139. + (float)value);
	}
}

static void
snr_base_custom(char *buffer, uint32_t value)
{
	snprintf(buffer, ITEM_LABEL_LENGTH, "%.1f dB", ((int8_t)value) / 4.);
}

static void
loratap_prompt(packet_info *pinfo, char* result)
{
	snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "LoRaTap syncword 0x%02x as", GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_loratap, 0)));
}

static void *
loratap_value(packet_info *pinfo)
{
	return p_get_proto_data(pinfo->pool, pinfo, proto_loratap, 0);
}

static int
dissect_loratap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_item *ti, *channel_item, *rssi_item;
	proto_tree *loratap_tree, *channel_tree, *rssi_tree;
	int32_t current_offset = 0;
	int32_t header_v1_offset = 15;
	uint16_t length;
	uint32_t lt_length, lt_version;
	bool try_dissect;
	uint32_t syncword;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoRaTap");
	col_clear(pinfo->cinfo, COL_INFO);
	length = tvb_get_uint16(tvb, 2, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(tree, proto_loratap, tvb, 0, length, ENC_NA);
	loratap_tree = proto_item_add_subtree(ti, ett_loratap);
	proto_tree_add_item_ret_uint(loratap_tree, hf_loratap_header_version_type, tvb, current_offset, 1, ENC_NA, &lt_version);
	current_offset++;
	proto_tree_add_item(loratap_tree, hf_loratap_header_padding, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	proto_tree_add_item_ret_uint(loratap_tree, hf_loratap_header_length_type, tvb, current_offset, 2, ENC_NA, &lt_length);
	current_offset += 2;
	if (lt_version == 1) {
		proto_tree_add_item(loratap_tree, hf_loratap_header_source_gw_type, tvb, header_v1_offset, 8, ENC_NA);
		set_address_tvb(&pinfo->dl_src, AT_EUI64, 8, tvb, header_v1_offset);
		copy_address_shallow(&pinfo->src, &pinfo->dl_src);
		proto_item_append_text(ti, ", Src: %s", address_to_display(pinfo->pool, &pinfo->src));
		header_v1_offset += 8;
		proto_tree_add_item(loratap_tree, hf_loratap_header_timestamp_type, tvb, header_v1_offset, 4, ENC_NA);
		header_v1_offset += 4;
		proto_tree_add_bitmask(loratap_tree, tvb, header_v1_offset, hf_loratap_header_flags_type, ett_loratap_flags, hfx_loratap_header_flags, ENC_NA);
		try_dissect = (tvb_get_uint8(tvb, header_v1_offset) & 0x28); /* Only try the next dissector for CRC OK and No CRC packets with v1 encapsulation */
		header_v1_offset++;
	} else {
		try_dissect = true; /* Always try the next dissector for v0 encapsulation */
	}

	channel_item = proto_tree_add_item(loratap_tree, hf_loratap_header_channel_type, tvb, current_offset, 0, ENC_NA);
	channel_tree = proto_item_add_subtree(channel_item, ett_loratap_channel);
	proto_tree_add_item(channel_tree, hf_loratap_header_channel_frequency_type, tvb, current_offset, 4, ENC_NA);
	current_offset += 4;
	proto_tree_add_item(channel_tree, hf_loratap_header_channel_bandwidth_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	proto_tree_add_item(channel_tree, hf_loratap_header_channel_sf_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	if (lt_version == 1) {
		proto_tree_add_item(channel_tree, hf_loratap_header_cr_type, tvb, header_v1_offset, 1, ENC_NA);
		header_v1_offset++;
		proto_tree_add_item(channel_tree, hf_loratap_header_datarate_type, tvb, header_v1_offset, 2, ENC_NA);
		header_v1_offset += 2;
		proto_tree_add_item(channel_tree, hf_loratap_header_if_channel_type, tvb, header_v1_offset, 1, ENC_NA);
		header_v1_offset++;
		proto_tree_add_item(channel_tree, hf_loratap_header_rf_chain_type, tvb, header_v1_offset, 1, ENC_NA);
		header_v1_offset++;
	}

	rssi_item = proto_tree_add_item(loratap_tree, hf_loratap_header_rssi_type, tvb, current_offset, 0, ENC_NA);
	rssi_tree = proto_item_add_subtree(rssi_item, ett_loratap_rssi);
	proto_tree_add_item(rssi_tree, hf_loratap_header_rssi_packet_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	proto_tree_add_item(rssi_tree, hf_loratap_header_rssi_max_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	proto_tree_add_item(rssi_tree, hf_loratap_header_rssi_current_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	proto_tree_add_item(rssi_tree, hf_loratap_header_rssi_snr_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	proto_tree_add_item_ret_uint(loratap_tree, hf_loratap_header_syncword_type, tvb, current_offset, 1, ENC_NA, &syncword);
	current_offset++;
	if (lt_version == 1) {
		proto_tree_add_item(loratap_tree, hf_loratap_header_tag_type, tvb, header_v1_offset, 2, ENC_NA);
	}

	/* Seek to data - skip lt_length of header, this allows future extensions */
	current_offset = lt_length;
	length = tvb_reported_length_remaining(tvb, lt_length);
	proto_tree_add_bytes_format_value(loratap_tree, hf_loratap_header_payload_type, tvb, current_offset, length, NULL, "%d bytes", length);

	p_add_proto_data(pinfo->pool, pinfo, proto_loratap, 0, GUINT_TO_POINTER((unsigned)syncword));
	next_tvb = tvb_new_subset_length(tvb, current_offset, length);

	if (!try_dissect || !dissector_try_uint_new(loratap_dissector_table, syncword, next_tvb, pinfo, tree, true, NULL)) {
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

void
proto_reg_handoff_loratap(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_LORATAP, loratap_handle);
	dissector_add_for_decode_as("udp.port", loratap_handle);
}

void
proto_register_loratap(void)
{
	static hf_register_info hf[] = {
	{ &hf_loratap_header_version_type,
		{ "Header Version", "loratap.version",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_length_type,
		{ "Header Length", "loratap.header_length",
		FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
		&units_byte_bytes, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_padding,
		{ "Header Padding", "loratap.padding",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_channel_type,
		{ "Channel", "loratap.channel",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_channel_frequency_type,
		{ "Frequency", "loratap.channel.frequency",
		FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
		&units_hz, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_channel_bandwidth_type,
		{ "Bandwidth", "loratap.channel.bandwidth",
		FT_UINT8, BASE_DEC,
		VALS(channel_bandwidth), 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_channel_sf_type,
		{ "Spreading Factor", "loratap.channel.sf",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_rssi_type,
		{ "RSSI / SNR", "loratap.rssi",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_rssi_packet_type,
		{ "Packet RSSI", "loratap.rssi.packet",
		FT_UINT8, BASE_CUSTOM,
		CF_FUNC(rssi_base_custom), 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_rssi_max_type,
		{ "Max RSSI", "loratap.rssi.max",
		FT_UINT8, BASE_CUSTOM,
		CF_FUNC(rssi_base_custom), 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_rssi_current_type,
		{ "Current RSSI", "loratap.rssi.current",
		FT_UINT8, BASE_CUSTOM,
		CF_FUNC(rssi_base_custom), 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_rssi_snr_type,
		{ "SNR", "loratap.rssi.snr",
		FT_UINT8, BASE_CUSTOM,
		CF_FUNC(snr_base_custom), 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_syncword_type,
		{ "Sync Word", "loratap.syncword",
		FT_UINT8, BASE_HEX,
		VALS(syncwords), 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_tag_type,
		{ "Tag", "loratap.tag",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_payload_type,
		{ "Payload", "loratap.payload",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_source_gw_type,
		{ "Source", "loratap.srcgw",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_timestamp_type,
		{ "Timestamp", "loratap.timestamp",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_datarate_type,
		{ "FSK datarate", "loratap.channel.datarate",
		FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
		&units_bit_sec, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_if_channel_type,
		{ "IF channel", "loratap.channel.if_channel",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_rf_chain_type,
		{ "RF chain", "loratap.channel.rf_chain",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_cr_type,
		{ "Coding Rate", "loratap.channel.cr",
		FT_UINT8, BASE_DEC,
		VALS(coding_rates), 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_flags_type,
		{ "Flags", "loratap.flags",
		FT_UINT8, BASE_HEX,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_flags_mod_fsk_type,
		{ "FSK Modulation", "loratap.flags.mod_fsk",
		FT_BOOLEAN, 8,
		TFS(&tfs_set_notset), 0x01,
		NULL, HFILL }
	},
	{ &hf_loratap_header_flags_iq_inverted_type,
		{ "IQ Inverted", "loratap.flags.iq_inverted",
		FT_BOOLEAN, 8,
		TFS(&tfs_set_notset), 0x02,
		NULL, HFILL }
	},
	{ &hf_loratap_header_flags_implicit_hdr_type,
		{ "Implicit Header", "loratap.flags.implicit_hdr",
		FT_BOOLEAN, 8,
		TFS(&tfs_set_notset), 0x04,
		NULL, HFILL }
	},
	{ &hf_loratap_header_flags_crc_type,
		{ "Checksum", "loratap.flags.crc",
		FT_UINT8, BASE_HEX,
		VALS(crc_state), 0x38,
		NULL, HFILL }
	},
	{ &hf_loratap_header_flags_padding_type,
		{ "Padding", "loratap.flags.padding",
		FT_UINT8, BASE_DEC,
		NULL, 0xC0,
		NULL, HFILL }
	},
	};

	/* Register for decode as */
	static build_valid_func loratap_da_build_value[1] = {loratap_value};
	static decode_as_value_t loratap_da_values = {loratap_prompt, 1, loratap_da_build_value};
	static decode_as_t loratap_da = {"loratap", "loratap.syncword", 1, 0, &loratap_da_values, NULL, NULL, decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_loratap,
		&ett_loratap_flags,
		&ett_loratap_channel,
		&ett_loratap_rssi
	};

	proto_loratap = proto_register_protocol (
		"LoRaTap header",	/* name */
		"LoRaTap",		/* short name */
		"loratap"		/* abbrev */
	);

	loratap_handle = register_dissector("loratap", dissect_loratap, proto_loratap);
	proto_register_field_array(proto_loratap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	loratap_dissector_table = register_dissector_table("loratap.syncword", "LoRa Syncword", proto_loratap, FT_UINT8, BASE_HEX);
	register_decode_as(&loratap_da);
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
