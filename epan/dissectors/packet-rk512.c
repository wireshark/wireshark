/* packet-rk512.c
 * Routines for RK 512 protocol dissection
 * Copyright 2022 Michael Mann
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/crc16.h>

void proto_register_rk512(void);
void proto_reg_handoff_rk512(void);

static int proto_rk512;

//static int hf_rk512_garbage_data;
static int hf_rk512_reply_header;
static int hf_rk512_data_block_type;
static int hf_rk512_size;
static int hf_rk512_coordination_flag;
static int hf_rk512_device_code;
static int hf_rk512_protocol_version;
static int hf_rk512_status;
static int hf_rk512_scan_number;
static int hf_rk512_telegram_number;
static int hf_rk512_data_type;
static int hf_rk512_measurement_data_type;
static int hf_rk512_measurement_data;
static int hf_rk512_measurement_data_distance;
static int hf_rk512_measurement_data_flags;
static int hf_rk512_checksum;
static int hf_rk512_checksum_status;

static int ett_rk512;
static int ett_rk512_measurement_data;
static int ett_rk512_measurement_data_value;
static int ett_rk512_continuous_data;

static expert_field ei_rk512_reply_header;
static expert_field ei_rk512_data_type;
static expert_field ei_rk512_checksum;

//Preferences
static unsigned rk512_num_measurements_pts = 541;

#define RK512_HEADER_SIZE   4
#define RK512_CRC_SIZE   2
//Used to find the start of packets
static const uint8_t HEADER_SEQUENCE[RK512_HEADER_SIZE] = { 0, 0, 0, 0 };
static tvbuff_t* tvb_header_signature = NULL;

#define MEASUREMENT_DATA		0xBBBB
#define REFLECTOR_DATA			0xCCCC


static const value_string device_code_vals[] = {
	{ 7, "Host" },
	{ 8, "Guest" },
	{ 0, NULL }
};

static const value_string status_vals[] = {
	{ 0, "Normal" },
	{ 1, "Lockout" },
	{ 0, NULL }
};

#define BLOCKNUM_CONTINUOUSDATA		0x0000		// 0
#define BLOCKNUM_SCID				0x0017		// 23
#define BLOCKNUM_TOKEN				0x0019		// 25
#define BLOCKNUM_DATAMODE			0x0067		// 103

static const value_string data_block_type_vals[] = {
	{ BLOCKNUM_CONTINUOUSDATA, "Continuous Data" },
	{ BLOCKNUM_SCID, "SCID" },
	{ BLOCKNUM_TOKEN, "Token" },
	{ BLOCKNUM_DATAMODE, "Data Mode" },
	{ 0, NULL }
};

static const value_string datatype_vals[] = {
	{ MEASUREMENT_DATA, "Measurement data" },
	{ REFLECTOR_DATA, "Reflector data" },
	{ 0, NULL }
};

/* Copied and renamed from proto.c because global value_strings don't work for plugins */
static const value_string plugin_proto_checksum_vals[] = {
	{ PROTO_CHECKSUM_E_BAD,        "Bad"  },
	{ PROTO_CHECKSUM_E_GOOD,       "Good" },
	{ PROTO_CHECKSUM_E_UNVERIFIED, "Unverified" },
	{ PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },
	{ 0, NULL }
};

static int* const rk512_measurement_data_fields[] = {
	&hf_rk512_measurement_data_distance,
	&hf_rk512_measurement_data_flags,
	NULL,
};

static unsigned
get_rk512_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	uint32_t len = 0;

	len = tvb_get_ntohs(tvb, offset + RK512_HEADER_SIZE + 2);	//length in words

	//Yes, this is a horrible hack but works with the captures seen
	if ((rk512_num_measurements_pts == 381) && (len == 392))
		len = 390;

	return ((len*2) + RK512_HEADER_SIZE + 2 + RK512_CRC_SIZE);
}

static int
dissect_rk512_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree		*rk512_tree, *continous_data_tree, *measurement_tree;
	proto_item		*ti, *header_item, *continous_data_item, *data_item;
	int				offset = 0, start_offset;
	uint32_t			tag, block_type, data_type, sub_data_type, size;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RK512");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_rk512, tvb, 0, -1, ENC_NA);
	rk512_tree = proto_item_add_subtree(ti, ett_rk512);

	header_item = proto_tree_add_item_ret_uint(rk512_tree, hf_rk512_reply_header, tvb, offset, 4, ENC_BIG_ENDIAN, &tag);
	offset += 4;
	if (tag != 0)
		expert_add_info(pinfo, header_item, &ei_rk512_reply_header);

	proto_tree_add_item_ret_uint(rk512_tree, hf_rk512_data_block_type, tvb, offset, 2, ENC_BIG_ENDIAN, &block_type);
	offset += 2;

	col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(block_type, data_block_type_vals, "Unknown"));

	switch (block_type)
	{
	case BLOCKNUM_CONTINUOUSDATA:
		start_offset = offset;
		continous_data_tree = proto_tree_add_subtree(rk512_tree, tvb, offset, -1, ett_rk512_continuous_data, &continous_data_item, "Continuous Data");

		proto_tree_add_item_ret_uint(continous_data_tree, hf_rk512_size, tvb, offset, 2, ENC_BIG_ENDIAN, &size);
		size *= 2;		//size is in words
		offset += 2;
		proto_tree_add_item(continous_data_tree, hf_rk512_coordination_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(continous_data_tree, hf_rk512_device_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(continous_data_tree, hf_rk512_protocol_version, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(continous_data_tree, hf_rk512_status, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(continous_data_tree, hf_rk512_scan_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(continous_data_tree, hf_rk512_telegram_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		data_item = proto_tree_add_item_ret_uint(continous_data_tree, hf_rk512_data_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &data_type);
		offset += 2;

		switch (data_type)
		{
		case MEASUREMENT_DATA:
		{
			//Yes, this is a horrible hack but works with the captures seen
			if ((rk512_num_measurements_pts == 381) && (size == 784))
				size = 780;

			uint8_t* crc_data;
			proto_tree_add_item_ret_uint(continous_data_tree, hf_rk512_measurement_data_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sub_data_type);
			offset += 2;
			measurement_tree = proto_tree_add_subtree(continous_data_tree, tvb, offset, rk512_num_measurements_pts * 2, ett_rk512_measurement_data, NULL, "Measurement Data");
			for (unsigned i = 0; i < rk512_num_measurements_pts; i++)
			{
				proto_tree_add_bitmask(measurement_tree, tvb, offset, hf_rk512_measurement_data, ett_rk512_measurement_data_value, rk512_measurement_data_fields, ENC_BIG_ENDIAN);
				offset += 2;
			}

			//Create data to compute the CRC
			crc_data = (uint8_t*)wmem_alloc(wmem_packet_scope(), size + 2);
			//start with a word with value 0
			crc_data[0] = 0;
			crc_data[1] = 0;
			//copy the rest of the packet
			tvb_memcpy(tvb, &crc_data[2], start_offset, size);

			proto_tree_add_checksum(rk512_tree, tvb, offset,
				hf_rk512_checksum, hf_rk512_checksum_status, &ei_rk512_checksum, pinfo,
				crc16_x25_ccitt_seed(crc_data, size + 2, 0xFFFF), ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
			offset += 2;
			break;
		}
		case REFLECTOR_DATA:
			break;
		default:
			expert_add_info(pinfo, data_item, &ei_rk512_data_type);
			break;
		}

		proto_item_set_len(continous_data_item, offset - start_offset);
		break;
	case BLOCKNUM_SCID:
		break;
	case BLOCKNUM_TOKEN:
		break;
	case BLOCKNUM_DATAMODE:
		break;
	}

	return tvb_captured_length(tvb);
}

static int
dissect_rk512(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, true, 8, get_rk512_pdu_len, dissect_rk512_pdu, data);
	return tvb_captured_length(tvb);
}

static bool
dissect_rk512_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
	int signature_start, offset;
	uint16_t block_type;
	tvbuff_t* rk512_tvb;

	signature_start = tvb_find_tvb(tvb, tvb_header_signature, 0);
	if (signature_start == -1) {
		return false;
	}

	//keep track of the offset for verification of upcoming fields
	offset = signature_start + RK512_HEADER_SIZE;

	//Make sure there are enough bytes for the rest of the field checks
	if (tvb_captured_length_remaining(tvb, offset) < 2)
		return false;

	//Make sure it's supported block type
	block_type = tvb_get_ntohs(tvb, offset);
	if (try_val_to_str(block_type, data_block_type_vals) == NULL)
		return false;

	offset += 2;
	if (block_type == BLOCKNUM_CONTINUOUSDATA)
	{
		uint16_t datatype;
		if (tvb_captured_length_remaining(tvb, offset) < 18)
			return false;

		datatype = tvb_get_ntohs(tvb, offset+14);
		if (try_val_to_str(datatype, datatype_vals) == NULL)
			return false;
	}

	rk512_tvb = tvb_new_subset_remaining(tvb, signature_start);
	dissect_rk512(rk512_tvb, pinfo, tree, data);
	return true;
}

static void
rk512_shutdown(void)
{
	tvb_free(tvb_header_signature);
}

static void
rk512_fmt_version( char *result, uint32_t revision )
{
		snprintf( result, ITEM_LABEL_LENGTH, "%d.%d",
		(uint8_t)(revision & 0xFF), (uint8_t)(( revision & 0xFF00 ) >> 8));
}

void
proto_register_rk512(void)
{
	expert_module_t* expert_rk512;

	static hf_register_info hf[] = {
		//{ &hf_rk512_garbage_data,
		//	{ "Garbage Data", "rk512.garbage_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_rk512_reply_header,
			{ "Reply Header", "rk512.reply_header", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_rk512_data_block_type,
			{ "Data Block Type", "rk512.data_block_type", FT_UINT16, BASE_DEC, VALS(data_block_type_vals), 0x0, NULL, HFILL } },
		{ &hf_rk512_size,
			{ "Message Size", "rk512.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_rk512_coordination_flag,
			{ "Coordination Flag", "rk512.coordination_flag", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_rk512_device_code,
			{ "Device Code", "rk512.device_code", FT_UINT8, BASE_HEX, VALS(device_code_vals), 0x0, NULL, HFILL } },
		{ &hf_rk512_protocol_version,
			{ "Protocol Version", "rk512.protocol_version.version", FT_UINT16, BASE_CUSTOM, CF_FUNC(rk512_fmt_version), 0x0, NULL, HFILL } },
		{ &hf_rk512_status,
			{ "Status", "rk512.status", FT_UINT16, BASE_HEX, VALS(status_vals), 0x0, NULL, HFILL } },
		{ &hf_rk512_scan_number,
			{ "Scan number", "rk512.scan_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_rk512_telegram_number,
			{ "Telegram number", "rk512.telegram_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_rk512_data_type,
			{ "Data type", "rk512.data_type", FT_UINT16, BASE_HEX, VALS(datatype_vals), 0x0, NULL, HFILL } },
		{ &hf_rk512_measurement_data_type,
			{ "Measurement datatype", "rk512.measurement.data_type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_rk512_measurement_data,
			{ "Measurement data", "rk512.measurement.data", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_rk512_measurement_data_distance,
			{ "Distance", "rk512.measurement.data.distance", FT_UINT16, BASE_DEC, NULL, 0x1FFF, NULL, HFILL } },
		{ &hf_rk512_measurement_data_flags,
			{ "Flags", "rk512.measurement.data.flags", FT_UINT16, BASE_HEX, NULL, 0xE000, NULL, HFILL } },
		{ &hf_rk512_checksum,
			{ "Checksum", "rk512.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_rk512_checksum_status,
			{ "CRC Status", "rk512.checksum_status", FT_UINT8, BASE_NONE, &plugin_proto_checksum_vals, 0x0, NULL, HFILL } },

	};

	static int *ett[] = {
		&ett_rk512,
		&ett_rk512_continuous_data,
		&ett_rk512_measurement_data,
		&ett_rk512_measurement_data_value
	};

	static ei_register_info ei[] = {
		{ &ei_rk512_reply_header, { "rk512.reply_header.not_zero", PI_PROTOCOL, PI_WARN, "Reply header not zero", EXPFILL }},
		{ &ei_rk512_data_type, { "rk512.data_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown data type", EXPFILL }},
		{ &ei_rk512_checksum, { "rk512.checksum.incorrect", PI_CHECKSUM, PI_WARN, "Checksum incorrect", EXPFILL }},
	};


	proto_rk512 = proto_register_protocol("SICK RK512", "RK512", "rk512");
	proto_register_field_array(proto_rk512, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_rk512 = expert_register_protocol(proto_rk512);
	expert_register_field_array(expert_rk512, ei, array_length(ei));

	module_t* rk512_module = prefs_register_protocol(proto_rk512, NULL);
	prefs_register_uint_preference(rk512_module, "num_measurement_pts",
			"Number of measurement points",
			"Number of measurement points within the packet",
			10, &rk512_num_measurements_pts);

	tvb_header_signature = tvb_new_real_data(HEADER_SEQUENCE, sizeof(HEADER_SEQUENCE), sizeof(HEADER_SEQUENCE));

	register_shutdown_routine(rk512_shutdown);
}

void
proto_reg_handoff_rk512(void)
{
	dissector_handle_t rk512_handle;

	rk512_handle = create_dissector_handle(dissect_rk512, proto_rk512);
	dissector_add_for_decode_as("tcp.port", rk512_handle);
	heur_dissector_add("tcp", dissect_rk512_heur, "RK512 over TCP", "rk512_tcp", proto_rk512, HEURISTIC_ENABLE);
}

/*
* Editor modelines  -  http://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: t
* End:
*
* vi: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=false:
*/
