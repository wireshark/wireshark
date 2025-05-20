/** @file
 *
 * Routines for Ouster VLP-16 camera data
 * Protocol has been deprecated, but a copy of documentation
 * can be found at https://csis.pace.edu/robotlab/papers/VelodyneVLP16.pdf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/unit_strings.h>
#include <wsutil/utf8_entities.h>

void proto_register_vlp16(void);
void proto_reg_handoff_vlp16(void);

static int proto_vlp16_data;
static int proto_vlp16_position;

static int hf_vlp16_data_block_id;
static int hf_vlp16_data_rotational_position;
static int hf_vlp16_data_laser_distance;
static int hf_vlp16_data_laser_intensity;
static int hf_vlp16_data_gps_timestamp;
static int hf_vlp16_data_factory_field1;
static int hf_vlp16_data_factory_field2;

static int hf_vlp16_position_zero_data;
static int hf_vlp16_position_gyro;
static int hf_vlp16_position_temp;
static int hf_vlp16_position_accelx;
static int hf_vlp16_position_accely;
static int hf_vlp16_position_gps_timestamp;
static int hf_vlp16_position_sentence;
static int hf_vlp16_position_unused;

static int ett_vlp16_data;
static int ett_vlp16_data_firing;
static int ett_vlp16_data_firing_item;
static int ett_vlp16_data_laser_returns;
static int ett_vlp16_data_laser_return_item;

static int ett_vlp16_position;
static int ett_vlp16_position_item;

static expert_field ei_vlp16_position_zero_data;


static const unit_name_string vlp16_deg_s = { "deg/s", NULL };
static const unit_name_string vlp16_accel = { "G", NULL };


#define NUM_HDL_FIRING			12
#define NUM_LASER_PER_FIRING		32

#define VLP16_ZERO_DATA_LENGTH		14
#define NUM_VLP16_POSITION		3

#define GYRO_SCALE					0.09766   /* deg / s */
#define TEMP_SCALE					0.1453    /* C */
#define TEMP_OFFSET					25.0     /* C */
#define ACCEL_SCALE					0.001221 /* G */

static const value_string vlp16_factory_field1_vals[] = {
	{ 0x37,   "Strongest Return" },
	{ 0x38,   "Last Return" },
	{ 0x39,   "Dual Return" },
	{ 0, NULL }
};

static const value_string vlp16_factory_field2_vals[] = {
	{ 0x21,   "HDL-32E" },
	{ 0x22,   "VLP-16" },
	{ 0, NULL }
};

static uint16_t
twos_complement_12bit(uint16_t value)
{
	return (-2048 * ((value & 0xFFF) >> 11) + (value & 0x7FF));
}


static int
dissect_vlp16_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree      *vlp16_data_tree, *firing_tree, *firing_subtree, *laser_tree, *laser_subtree;
	proto_item      *ti;
	int				offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "VLP-16 Data");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_vlp16_data, tvb, 0, -1, ENC_NA);
	vlp16_data_tree = proto_item_add_subtree(ti, ett_vlp16_data);

	firing_tree = proto_tree_add_subtree(vlp16_data_tree, tvb, offset, NUM_HDL_FIRING*(4+(NUM_LASER_PER_FIRING*3)), ett_vlp16_data_firing, NULL, "Firing Data");
	for (int fire_index = 1; fire_index <= NUM_HDL_FIRING; fire_index++)
	{
		firing_subtree = proto_tree_add_subtree_format(firing_tree, tvb, offset, 4+(NUM_LASER_PER_FIRING*3), ett_vlp16_data_firing_item, NULL, "Firing %d", fire_index);
		proto_tree_add_item(firing_subtree, hf_vlp16_data_block_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(firing_subtree, hf_vlp16_data_rotational_position, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		laser_tree = proto_tree_add_subtree(firing_subtree, tvb, offset, NUM_LASER_PER_FIRING*3, ett_vlp16_data_laser_returns, NULL, "Laser Returns");
		for (int laser_index = 1; laser_index <= NUM_LASER_PER_FIRING; laser_index++)
		{
			laser_subtree = proto_tree_add_subtree_format(laser_tree, tvb, offset, 3, ett_vlp16_data_laser_return_item, NULL, "Laser Return %d", laser_index);
			proto_tree_add_item(laser_subtree, hf_vlp16_data_laser_distance, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(laser_subtree, hf_vlp16_data_laser_intensity, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
		}
	}

	proto_tree_add_item(vlp16_data_tree, hf_vlp16_data_gps_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_tree_add_item(vlp16_data_tree, hf_vlp16_data_factory_field1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(vlp16_data_tree, hf_vlp16_data_factory_field2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	return offset;
}

static int
dissect_vlp16_position(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree		*vlp16_tree, *position_tree;
	proto_item		*ti, *zero_item;
	int				offset = 0;
	uint16_t			gyro, temp, accelx, accely;
	double			gyro_value, temp_value, accelx_value, accely_value;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "VLP-16 Position");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_vlp16_position, tvb, 0, -1, ENC_NA);
	vlp16_tree = proto_item_add_subtree(ti, ett_vlp16_position);

	zero_item = proto_tree_add_item(vlp16_tree, hf_vlp16_position_zero_data, tvb, offset, VLP16_ZERO_DATA_LENGTH, ENC_NA);
	for (int i = 0; i < VLP16_ZERO_DATA_LENGTH; i++)
	{
		if (tvb_get_uint8(tvb, offset + i) != 0)
		{
			expert_add_info(pinfo, zero_item, &ei_vlp16_position_zero_data);
			break;
		}
	}
	offset += VLP16_ZERO_DATA_LENGTH;

	for (int position_index = 1; position_index <= NUM_VLP16_POSITION; position_index++)
	{
		position_tree = proto_tree_add_subtree_format(vlp16_tree, tvb, offset, 8, ett_vlp16_position_item, NULL, "Position %d", position_index);
		gyro = tvb_get_letohs(tvb, offset) & 0xFFF;
		gyro_value = twos_complement_12bit(gyro) * GYRO_SCALE;
		proto_tree_add_double(position_tree, hf_vlp16_position_gyro, tvb, offset, 2, gyro_value);
		offset += 2;
		temp = tvb_get_letohs(tvb, offset) & 0xFFF;
		temp_value = (twos_complement_12bit(temp) * TEMP_SCALE) + TEMP_OFFSET;
		proto_tree_add_double(position_tree, hf_vlp16_position_temp, tvb, offset, 2, temp_value);
		offset += 2;
		accelx = tvb_get_letohs(tvb, offset) & 0xFFF;
		accelx_value = twos_complement_12bit(accelx) * ACCEL_SCALE;
		proto_tree_add_double(position_tree, hf_vlp16_position_accelx, tvb, offset, 2, accelx_value);
		offset += 2;
		accely = tvb_get_letohs(tvb, offset) & 0xFFF;
		accely_value = twos_complement_12bit(accely) * ACCEL_SCALE;
		proto_tree_add_double(position_tree, hf_vlp16_position_accely, tvb, offset, 2, accely_value);
		offset += 2;
	}

	proto_tree_add_item(vlp16_tree, hf_vlp16_position_unused, tvb, offset, 160, ENC_NA);
	offset += 160;

	proto_tree_add_item(vlp16_tree, hf_vlp16_position_gps_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(vlp16_tree, hf_vlp16_position_unused, tvb, offset, 4, ENC_NA);
	offset += 4;

	proto_tree_add_item(vlp16_tree, hf_vlp16_position_sentence, tvb, offset, 72, ENC_NA|ENC_ASCII);
	offset += 72;

	proto_tree_add_item(vlp16_tree, hf_vlp16_position_unused, tvb, offset, 234, ENC_NA);
	offset += 234;

	return offset;
}

void
proto_register_vlp16(void)
{
	static hf_register_info hf_vlp16_data[] = {
		{ &hf_vlp16_data_block_id,
			{ "Block Identifier", "vlp16_data.block_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_vlp16_data_rotational_position,
			{ "Rotational Position", "vlp16_data.rotational_position", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_vlp16_data_laser_distance,
			{ "Distance", "vlp16_data.laser.distance", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_vlp16_data_laser_intensity,
			{ "Intensity", "vlp16_data.laser.intensity", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_vlp16_data_gps_timestamp,
			{ "GPS Timestamp", "vlp16_data.gps_timestamp", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_microseconds), 0x0, NULL, HFILL}},
		{ &hf_vlp16_data_factory_field1,
			{ "Factory Field1", "vlp16_data.factory_field1", FT_UINT8, BASE_HEX, VALS(vlp16_factory_field1_vals), 0x0, NULL, HFILL }},
		{ &hf_vlp16_data_factory_field2,
			{ "Factory Field2", "vlp16_data.factory_field2", FT_UINT8, BASE_HEX, VALS(vlp16_factory_field2_vals), 0x0, NULL, HFILL }},
	};

	static hf_register_info hf_vlp16_position[] = {
		{ &hf_vlp16_position_zero_data,
			{ "Zero data", "vlp16_position.zero_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_vlp16_position_gyro,
			{ "Gyro", "vlp16_position.position.gyro", FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&vlp16_deg_s), 0x0, NULL, HFILL }},
		{ &hf_vlp16_position_temp,
			{ "Temperature", "vlp16_position.position.temp", FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_celsius), 0x0, NULL, HFILL }},
		{ &hf_vlp16_position_accelx,
			{ "Accel X", "vlp16_position.position.accelx", FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&vlp16_accel), 0x0, NULL, HFILL }},
		{ &hf_vlp16_position_accely,
			{ "Accel Y", "vlp16_position.position.accely", FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&vlp16_accel), 0x0, NULL, HFILL }},
		{ &hf_vlp16_position_gps_timestamp,
			{ "GPS Timestamp", "vlp16_position.gps_timestamp", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_microseconds), 0x0, NULL, HFILL }},
		{ &hf_vlp16_position_sentence,
			{ "Sentence", "vlp16_position.sentence", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_vlp16_position_unused,
			{ "Unused", "vlp16_position.unused", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static int *ett_vlp16data[] = {
		&ett_vlp16_data,
		&ett_vlp16_data_firing,
		&ett_vlp16_data_firing_item,
		&ett_vlp16_data_laser_returns,
		&ett_vlp16_data_laser_return_item
	};

	static int *ett_vlp16position[] = {
		&ett_vlp16_position,
		&ett_vlp16_position_item,
	};

	static ei_register_info ei_vlp16_position[] = {
		{ &ei_vlp16_position_zero_data, { "vlp16_position.zero_data.not_zero", PI_PROTOCOL, PI_ERROR, "Not all bytes of zero data have value 0", EXPFILL }},
	};

	expert_module_t* expert_vlp16_position;

	proto_vlp16_data = proto_register_protocol("VLP-16 Data Protocol", "VLP-16 Data", "vlp16_data");
	proto_vlp16_position  = proto_register_protocol("VLP-16 Position Protocol", "VLP-16 Position", "vlp16_position");

	proto_register_field_array(proto_vlp16_data, hf_vlp16_data, array_length(hf_vlp16_data));
	proto_register_field_array(proto_vlp16_position, hf_vlp16_position, array_length(hf_vlp16_position));

	proto_register_subtree_array(ett_vlp16data, array_length(ett_vlp16data));
	proto_register_subtree_array(ett_vlp16position, array_length(ett_vlp16position));

	expert_vlp16_position = expert_register_protocol(proto_vlp16_position);
	expert_register_field_array(expert_vlp16_position, ei_vlp16_position, array_length(ei_vlp16_position));

}

void
proto_reg_handoff_vlp16(void)
{
	dissector_handle_t vlp16_data_handle, vlp16_position_handle;

	vlp16_data_handle = create_dissector_handle(dissect_vlp16_data, proto_vlp16_data);
	dissector_add_for_decode_as("udp.port", vlp16_data_handle);

	vlp16_position_handle = create_dissector_handle(dissect_vlp16_position, proto_vlp16_position);
	dissector_add_for_decode_as("udp.port", vlp16_position_handle);
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
