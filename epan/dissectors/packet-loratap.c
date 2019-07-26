/* packet-loratap.c
 * Dissector routines for the LoRaTap encapsulation
 * By Erik de Jong <erikdejong@gmail.com>
 * Copyright 2017 Erik de Jong
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <wiretap/wtap.h>
#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>

void proto_reg_handoff_loratap(void);
void proto_register_loratap(void);

static dissector_handle_t loratap_handle;

static dissector_table_t loratap_dissector_table;

static int proto_loratap = -1;
static int hf_loratap_header_version_type = -1;
static int hf_loratap_header_length_type = -1;
static int hf_loratap_header_padding = -1;
static int hf_loratap_header_channel_type = -1;
static int hf_loratap_header_channel_frequency_type = -1;
static int hf_loratap_header_channel_bandwidth_type = -1;
static int hf_loratap_header_channel_sf_type = -1;
static int hf_loratap_header_rssi_type = -1;
static int hf_loratap_header_rssi_packet_type = -1;
static int hf_loratap_header_rssi_max_type = -1;
static int hf_loratap_header_rssi_current_type = -1;
static int hf_loratap_header_rssi_snr_type = -1;
static int hf_loratap_header_syncword_type = -1;

static gint ett_loratap = -1;

static const value_string channel_bandwidth[] = {
	{ 1, "125 KHz" },
	{ 2, "250 KHz" },
	{ 4, "500 KHz" },
	{ 0, NULL}
};

static const value_string syncwords[] = {
	{ 0x34, "LoRaWAN" },
	{ 0, NULL}
};

static void
rssi_base_custom(gchar *buffer, guint32 value) {
	g_snprintf(buffer, ITEM_LABEL_LENGTH, "%.0f dBm", -139 + (float)value);
}

static void
snr_base_custom(gchar *buffer, guint32 value) {
	if( value & 0x80 ) {
		value = ( ( ~value + 1 ) & 0xFF ) >> 2;
	} else {
		value = ( value & 0xFF ) >> 2;
	}
	g_snprintf(buffer, ITEM_LABEL_LENGTH, "%d dB", value);
}

static void
loratap_prompt(packet_info *pinfo, gchar* result)
{
	g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "LoRaTap syncword 0x%02x as", GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_loratap, 0)));
}

static gpointer
loratap_value(packet_info *pinfo)
{
	return p_get_proto_data(pinfo->pool, pinfo, proto_loratap, 0);
}

static int
dissect_loratap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_item *ti, *channel_item, *rssi_item;
	proto_tree *loratap_tree, *channel_tree, *rssi_tree;
	gint32 current_offset = 0;
	guint16 length;
	guint32 syncword;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoRaTap");
	col_clear(pinfo->cinfo,COL_INFO);
	length = tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN);
	ti = proto_tree_add_item(tree, proto_loratap, tvb, 0, length, ENC_NA);
	loratap_tree = proto_item_add_subtree(ti, ett_loratap);
	proto_tree_add_item(loratap_tree, hf_loratap_header_version_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	proto_tree_add_item(loratap_tree, hf_loratap_header_padding, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	proto_tree_add_item(loratap_tree, hf_loratap_header_length_type, tvb, current_offset, 2, ENC_NA);
	current_offset += 2;
	channel_item = proto_tree_add_item(loratap_tree, hf_loratap_header_channel_type, tvb, current_offset, 6, ENC_NA);
	channel_tree = proto_item_add_subtree(channel_item, ett_loratap);
	proto_tree_add_item(channel_tree, hf_loratap_header_channel_frequency_type, tvb, current_offset, 4, ENC_NA);
	current_offset += 4;
	proto_tree_add_item(channel_tree, hf_loratap_header_channel_bandwidth_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	proto_tree_add_item(channel_tree, hf_loratap_header_channel_sf_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	rssi_item = proto_tree_add_item(loratap_tree, hf_loratap_header_rssi_type, tvb, current_offset, 4, ENC_NA);
	rssi_tree = proto_item_add_subtree(rssi_item, ett_loratap);
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
	p_add_proto_data(pinfo->pool, pinfo, proto_loratap, 0, GUINT_TO_POINTER((guint)syncword));
	next_tvb = tvb_new_subset_length_caplen(tvb, current_offset, tvb_captured_length_remaining(tvb, current_offset), tvb_reported_length_remaining(tvb, current_offset));

	if (!dissector_try_uint_new(loratap_dissector_table, syncword, next_tvb, pinfo, tree, TRUE, NULL)) {
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
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_padding,
		{ "Padding", "loratap.padding",
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
		{ "RSSI", "loratap.rssi",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_rssi_packet_type,
		{ "Packet", "loratap.rssi.packet",
		FT_UINT8, BASE_CUSTOM,
		CF_FUNC(rssi_base_custom), 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_rssi_max_type,
		{ "Max", "loratap.rssi.max",
		FT_UINT8, BASE_CUSTOM,
		CF_FUNC(rssi_base_custom), 0x0,
		NULL, HFILL }
	},
	{ &hf_loratap_header_rssi_current_type,
		{ "Current", "loratap.rssi.current",
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
	};

	/* Register for decode as */
	static build_valid_func loratap_da_build_value[1] = {loratap_value};
	static decode_as_value_t loratap_da_values = {loratap_prompt, 1, loratap_da_build_value};
	static decode_as_t loratap_da = {"loratap", "loratap.syncword", 1, 0, &loratap_da_values, NULL, NULL, decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_loratap
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
