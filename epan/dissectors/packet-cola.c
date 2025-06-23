/* packet-cola.c
 * Routines for SICK CoLA A and CoLA B protocols
 *
 * Copyright 2024 Michael Mann
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
#include <epan/expert.h>
#include <epan/to_str.h>
#include <wsutil/strtoi.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/utf8_entities.h>
#include <epan/dissectors/packet-tcp.h>

void proto_register_sick_cola(void);
void proto_reg_handoff_sick_cola(void);

static int proto_sick_cola_a;
static int proto_sick_cola_b;

static int hf_sick_cola_b_magic_number;
static int hf_sick_cola_b_length;
static int hf_sick_cola_b_checksum;
static int hf_sick_cola_b_checksum_status;
static int hf_sick_cola_command;
static int hf_sick_cola_method_name;
static int hf_sick_cola_set_access_mode_user_level;
static int hf_sick_cola_set_access_mode_password;
static int hf_sick_cola_answer_name;
static int hf_sick_cola_set_access_mode_change_level;
static int hf_sick_cola_set_scan_cfg_scan_frequency;
static int hf_sick_cola_set_scan_cfg_num_active_scanners;
static int hf_sick_cola_set_scan_cfg_angular_resolution;
static int hf_sick_cola_set_scan_cfg_start_angle;
static int hf_sick_cola_set_scan_cfg_stop_angle;
static int hf_sick_cola_set_scan_cfg_status_code;
static int hf_sick_cola_set_scan_cfg_mode;
static int hf_sick_cola_read_name;
static int hf_sick_cola_write_name;
static int hf_sick_cola_mm_alignment_node_layer_activation;
static int hf_sick_cola_standby_status_code;
static int hf_sick_cola_startmeas_status_code;
static int hf_sick_cola_stopmeas_status_code;
static int hf_sick_cola_autostartmeas_enable;
static int hf_sick_cola_clapplication_mode;
static int hf_sick_cola_set_active_app_count;
static int hf_sick_cola_set_active_app_id;
static int hf_sick_cola_set_active_app_active;
static int hf_sick_cola_set_password_user_level;
static int hf_sick_cola_set_password_hash;
static int hf_sick_cola_set_password_status_code;
static int hf_sick_cola_check_password_user_level;
static int hf_sick_cola_check_password_hash;
static int hf_sick_cola_check_password_status_code;
static int hf_sick_cola_lcm_cfg_strategy;
static int hf_sick_cola_lcm_cfg_response_time;
static int hf_sick_cola_lcm_cfg_threshold_warning;
static int hf_sick_cola_lcm_cfg_threshold_error;
static int hf_sick_cola_cm_cont_lvlm_availability;
static int hf_sick_cola_ee_write_all_status_code;
static int hf_sick_cola_run_status_code;
static int hf_sick_cola_scan_data_cfg_data_channel;
static int hf_sick_cola_scan_data_cfg_remission;
static int hf_sick_cola_scan_data_cfg_resolution;
static int hf_sick_cola_scan_data_cfg_unit;
static int hf_sick_cola_scan_data_cfg_encoder;
static int hf_sick_cola_scan_data_cfg_position;
static int hf_sick_cola_scan_data_cfg_device_name;
static int hf_sick_cola_scan_data_cfg_comment;
static int hf_sick_cola_scan_data_cfg_time;
static int hf_sick_cola_scan_data_cfg_output_rate;
static int hf_sick_cola_change_output_range_status_code;
static int hf_sick_cola_change_output_range_angular_resolution;
static int hf_sick_cola_change_output_range_start_angle;
static int hf_sick_cola_change_output_range_stop;
static int hf_sick_cola_output_range_num_sectors;
static int hf_sick_cola_output_range_angular_resolution;
static int hf_sick_cola_output_range_start_angle;
static int hf_sick_cola_output_range_stop;
static int hf_sick_cola_event_name;
static int hf_sick_cola_scan_data_start_stop;
static int hf_sick_cola_scan_data_version;
static int hf_sick_cola_scan_data_device_number;
static int hf_sick_cola_scan_data_serial_number;
static int hf_sick_cola_scan_data_device_status;
static int hf_sick_cola_scan_data_telegram_counter;
static int hf_sick_cola_scan_data_scan_counter;
static int hf_sick_cola_scan_data_time_since_startup;
static int hf_sick_cola_scan_data_transmission_time;
static int hf_sick_cola_scan_data_di_status;
static int hf_sick_cola_scan_data_do_status;
static int hf_sick_cola_scan_data_layer_angle;
static int hf_sick_cola_scan_data_scan_frequency;
static int hf_sick_cola_scan_data_measurement_frequency;
static int hf_sick_cola_scan_data_encoder_amount;
static int hf_sick_cola_scan_data_encoder_position;
static int hf_sick_cola_scan_data_encoder_speed;
static int hf_sick_cola_scan_data_num_16bit_channels;
static int hf_sick_cola_scan_data_output_channel_content;
static int hf_sick_cola_scan_data_output_channel_scale_factor;
static int hf_sick_cola_scan_data_output_channel_scale_factor_offset;
static int hf_sick_cola_scan_data_output_channel_start_angle;
static int hf_sick_cola_scan_data_output_channel_size_single_angular_step;
static int hf_sick_cola_scan_data_num_data_points;
static int hf_sick_cola_scan_data_16bit_output_channel_data;
static int hf_sick_cola_scan_data_num_8bit_channels;
static int hf_sick_cola_scan_data_8bit_output_channel_data;
static int hf_sick_cola_scan_data_position_present;
static int hf_sick_cola_scan_data_position_x;
static int hf_sick_cola_scan_data_position_y;
static int hf_sick_cola_scan_data_position_z;
static int hf_sick_cola_scan_data_rotation_x;
static int hf_sick_cola_scan_data_rotation_y;
static int hf_sick_cola_scan_data_rotation_z;
static int hf_sick_cola_scan_data_rotation_type;
static int hf_sick_cola_scan_data_transmit_device_name;
static int hf_sick_cola_scan_data_device_name_present;
static int hf_sick_cola_scan_data_device_name;
static int hf_sick_cola_scan_data_comment_present;
static int hf_sick_cola_scan_data_comment;
static int hf_sick_cola_scan_data_time_present;
static int hf_sick_cola_scan_data_time;
static int hf_sick_cola_scan_data_display_event_info;
static int hf_sick_cola_scan_data_event_info_type;
static int hf_sick_cola_scan_data_event_info_encoder_position;
static int hf_sick_cola_scan_data_event_info_encosder_timestamp;
static int hf_sick_cola_scan_data_event_info_encoder_angle;
static int hf_sick_cola_set_date_time;
static int hf_sick_cola_set_date_time_status_code;
static int hf_sick_cola_stims_status_code;
static int hf_sick_cola_stims_temp_out_of_range;
static int hf_sick_cola_stims_time_length;
static int hf_sick_cola_stims_time;
static int hf_sick_cola_stims_date_length;
static int hf_sick_cola_stims_date;
static int hf_sick_cola_stims_led1;
static int hf_sick_cola_stims_led2;
static int hf_sick_cola_stims_led3;
static int hf_sick_cola_stims_reserved;
static int hf_sick_cola_device_time;
static int hf_sick_cola_ntp_tsc_role;
static int hf_sick_cola_ntp_interface_data;
static int hf_sick_cola_ntp_ipaddress;
static int hf_sick_cola_ntp_gmt_timezone_offset;
static int hf_sick_cola_ntp_timesync;
static int hf_sick_cola_ntp_max_offset_time;
static int hf_sick_cola_particle_filter_status;
static int hf_sick_cola_particle_filter_threshold;
static int hf_sick_cola_mean_filter_status;
static int hf_sick_cola_mean_filter_num_scans;
static int hf_sick_cola_mean_filter_final_part;
static int hf_sick_cola_nto1_filter_status;
static int hf_sick_cola_echo_filter_status;
static int hf_sick_cola_fog_filter_status;
static int hf_sick_cola_fog_filter_enable;
static int hf_sick_cola_fog_filter_sensitivity_level;
static int hf_sick_cola_digital_nearfield_filter_status;
static int hf_sick_cola_digital_nearfield_filter_active_sector_vector;
static int hf_sick_cola_encoder_increment_source;
static int hf_sick_cola_encoder_setting;
static int hf_sick_cola_encoder_resolution;
static int hf_sick_cola_encoder_fixed_speed;
static int hf_sick_cola_encoder_speed_threshold;
static int hf_sick_cola_encoder_speed;
static int hf_sick_cola_output_do3_func;
static int hf_sick_cola_output_do1_func;
static int hf_sick_cola_output_do1_logic;
static int hf_sick_cola_output_do2_func;
static int hf_sick_cola_output_do2_logic;
static int hf_sick_cola_output_sync_mode_data;
static int hf_sick_cola_output_sync_phase_data;
static int hf_sick_cola_input_do3and4_func;
static int hf_sick_cola_input_debounce_time_data;
static int hf_sick_cola_set_output_state_number;
static int hf_sick_cola_set_output_state_state;
static int hf_sick_cola_output_state_start_stop;
static int hf_sick_cola_output_state_status_version;
static int hf_sick_cola_output_state_status_system_counter;
static int hf_sick_cola_output_state_state;
static int hf_sick_cola_output_state_count;
static int hf_sick_cola_output_state_ext_state;
static int hf_sick_cola_output_state_ext_count;
static int hf_sick_cola_output_state_time_present;
static int hf_sick_cola_output_state_time;
static int hf_sick_cola_input_sync_status_data;
static int hf_sick_cola_input_signal_frequency;
static int hf_sick_cola_set_output_state_status_code;
static int hf_sick_cola_b_sopas_command;
static int hf_sick_cola_b_sopas_command_data;
static int hf_sick_cola_a_stx;
static int hf_sick_cola_a_etx;
static int hf_sick_cola_a_sopas_command;
static int hf_sick_cola_a_sopas_command_data;
static int hf_sick_cola_sopas_error_code;


static int ett_sick_cola_a;
static int ett_sick_cola_b;
static int ett_scan_data_device;
static int ett_scan_data_status_info;
static int ett_scan_data_frequency;
static int ett_scan_data_16bit_output_channels;
static int ett_scan_data_16bit_output_channel;
static int ett_scan_data_16bit_output_data;
static int ett_scan_data_8bit_output_channels;
static int ett_scan_data_8bit_output_channel;
static int ett_scan_data_8bit_output_data;
static int ett_scan_data_position;
static int ett_scan_data_time;
static int ett_scan_data_event_info;
static int ett_output_state_status;
static int ett_output_state;
static int ett_output_state_x;
static int ett_ext_output_state;
static int ett_ext_output_state_x;
static int ett_output_state_time;

static expert_field ei_sick_cola_command = EI_INIT;
static expert_field ei_sick_cola_command_name = EI_INIT;
static expert_field ei_sick_cola_command_parameter = EI_INIT;
static expert_field ei_sick_cola_b_checksum = EI_INIT;

//Preferences
static uint32_t g_number_of_outputs = 1;

#define SICK_COLA_B_HEADER_SIZE			8
#define SICK_COLA_B_MAGIC_NUMBER		0x02020202

#define SICK_COLA_A_STX					0x02
#define SICK_COLA_A_ETX					0x03
#define SICK_COLA_DELIMITER				0x20		//space character
#define SICK_COLA_A_MIN_LENGTH			6

#define SICK_COLA_COMMAND_READ			0x73524E20	//sRN
#define SICK_COLA_COMMAND_WRITE			0x73574E20	//sWN
#define SICK_COLA_COMMAND_METHOD		0x734D4E20	//sMN
#define SICK_COLA_COMMAND_EVENT			0x73454E20	//sEN

#define SICK_COLA_COMMAND_SOPAS_BINARY	0x73524900	//sRI
#define SICK_COLA_COMMAND_SOPAS_ASCII	0x73524920	//sRI

#define SICK_COLA_COMMAND_ANSWER_sRA	0x73524120
#define SICK_COLA_COMMAND_ANSWER_sWA	0x73574120
#define SICK_COLA_COMMAND_ANSWER_sAN	0x73414E20
#define SICK_COLA_COMMAND_ANSWER_sEA	0x73454120
#define SICK_COLA_COMMAND_ANSWER_sSN	0x73534E20
#define SICK_COLA_COMMAND_ANSWER_sFA	0x73464120
#define SICK_COLA_COMMAND_ANSWER_sFA_NULL	0x73464100

#define SICK_COLA_COMMAND_ANSWER_SOPAS_BINARY	0x73524100	//sRA


static const value_string cola_command_vals[] = {
	{ SICK_COLA_COMMAND_READ,   "Read" },
	{ SICK_COLA_COMMAND_WRITE,   "Write" },
	{ SICK_COLA_COMMAND_METHOD,   "Method" },
	{ SICK_COLA_COMMAND_EVENT,   "Event" },
	{ SICK_COLA_COMMAND_ANSWER_sRA,   "Answer (sRA)" },
	{ SICK_COLA_COMMAND_ANSWER_sWA,   "Answer (sWA)" },
	{ SICK_COLA_COMMAND_ANSWER_sAN,   "Answer (sAN)" },
	{ SICK_COLA_COMMAND_ANSWER_sEA,   "Answer (sEA)" },
	{ SICK_COLA_COMMAND_ANSWER_sSN,   "Answer (sSN)" },
	{ SICK_COLA_COMMAND_ANSWER_sFA,   "Answer (sFA)" },
	{ SICK_COLA_COMMAND_ANSWER_sFA_NULL,   "Answer (sFA)" },
	{ SICK_COLA_COMMAND_SOPAS_BINARY,   "SOPAS Specific (Binary)" },
	{ SICK_COLA_COMMAND_SOPAS_ASCII,   "SOPAS Specific (ASCII)" },
	{ SICK_COLA_COMMAND_ANSWER_SOPAS_BINARY,   "Answer (SOPAS Binary)" },
	{ 0, NULL }
};

static const value_string sick_cola_return_vals[] = {
	{ 0,	"Error" },
	{ 1,	"Success" },
	{ 0,	NULL }
};



static const value_string access_mode_user_level_vals[] = {
	{ 2,	"Maintenance" },
	{ 3,	"Authorized client" },
	{ 4,	"Service" },
	{ 0xFFFFFFFF,	"Invalid number" },
	{ 0,	NULL }
};

static const value_string set_scan_cfg_status_code_vals[] = {
	{ 0,	"No Error" },
	{ 1,	"Frequency error" },
	{ 2,	"Resolution error" },
	{ 3,	"Resolution and scan area error" },
	{ 4,	"Scan area error" },
	{ 5,	"Other error" },
	{ 0,	NULL }
};

//values are in ascii
static const value_string layer_activation_vals[] = {
	{ '0',	"All layers" },
	{ '1',	"Red layer -2,5" },
	{ '2',	"Blue layer 0" },
	{ '3',	"Green layer +2,5" },
	{ '4',	"Yellow layer +5" },
	{ 0,	NULL }
};

static const value_string start_stop_measure_status_code_vals[] = {
	{ 0,	"No error" },
	{ 1,	"Not allowed" },
	{ 0,	NULL }
};

static const value_string autostartmeas_enable_vals[] = {
	{ 0,	"OFF" },
	{ 1,	"ON" },
	{ 0,	NULL }
};

static const value_string clapplication_mode_vals[] = {
	{ 0,	"Scan only" },
	{ 0x11,	"Field application" },
	{ 0,	NULL }
};

static const value_string lcm_cfg_strategy_vals[] = {
	{ 0,	"Inactive" },
	{ 1,	"High available" },
	{ 2,	"Available" },
	{ 3,	"Sensitive" },
	{ 4,	"Semi-sensitive" },
	{ 0,	NULL }
};

static const value_string sick_cola_resolution_vals[] = {
	{ 0,	"8 bit" },
	{ 1,	"16 bit" },
	{ 0, NULL }
};

static const value_string sick_cola_stop_start_vals[] = {
	{ 0,	"Stop" },
	{ 1,	"Start" },
	{ 0, NULL }
};

static const value_string sick_cola_device_status_vals[] = {
	{ 0,	"Ok" },
	{ 1,	"Error" },
	{ 2,	"Pollution Warning" },
	{ 5,	"Pollution Error" },
	{ 0, NULL }
};

static const value_string sick_cola_position_present_vals[] = {
	{ 0,	"No Position Data" },
	{ 1,	"Position Data" },
	{ 0, NULL }
};

static const value_string sick_cola_rotation_type_vals[] = {
	{ 0,	"No Rotation" },
	{ 1,	"Pitch" },
	{ 2,	"Roll" },
	{ 3,	"Free" },
	{ 0, NULL }
};

static const value_string sick_cola_name_present_vals[] = {
	{ 0,	"No Name" },
	{ 1,	"Name" },
	{ 0, NULL }
};

static const value_string sick_cola_comment_present_vals[] = {
	{ 0,	"No Comment" },
	{ 1,	"Comment" },
	{ 0, NULL }
};

static const value_string sick_cola_time_present_vals[] = {
	{ 0,	"No Timestamp" },
	{ 1,	"Timestamp" },
	{ 0, NULL }
};

static const value_string sick_cola_display_event_info_vals[] = {
	{ 0,	"No information" },
	{ 1,	"Transmit Information" },
	{ 0, NULL }
};

static const value_string stims_status_vals[] = {
	{ 0,	"Undefined" },
	{ 1,	"Initialization" },
	{ 2,	"Configuration" },
	{ 3,	"Lower case" },
	{ 4,	"Rotating" },
	{ 5,	"In preparation" },
	{ 6,	"Ready" },
	{ 7,	"Measurement active" },
	{ 0, NULL }
};

static const value_string sick_cola_led_vals[] = {
	{ 0,	"Inactive" },
	{ 1,	"Active" },
	{ 0, NULL }
};

static const value_string ntp_tsc_role_vals[] = {
	{ 0,	"None" },
	{ 1,	"Client" },
	{ 2,	"Server" },
	{ 0, NULL }
};

static const value_string ntp_interface_data_vals[] = {
	{ 0,	"Ethernet" },
	{ 1,	"CAN" },
	{ 0, NULL }
};

static const value_string echo_filter_status_vals[] = {
	{ 0,	"First echo" },
	{ 1,	"All echos" },
	{ 2,	"Last echo" },
	{ 0, NULL }
};

static const value_string fog_filter_status_vals[] = {
	{ 0,	"Glitch" },
	{ 1,	"Fog" },
	{ 0, NULL }
};

static const value_string encoder_increment_source_vals[] = {
	{ 0,	"Fixed Speed" },
	{ 1,	"Encoder" },
	{ 0, NULL }
};

static const value_string encoder_setting_vals[] = {
	{ 0,	"Off" },
	{ 1,	"Single increment/INC1" },
	{ 2,	"Direction recognition (phase)" },
	{ 3,	"Direction recognition (level)" },
	{ 0, NULL }
};

static const value_string sick_cola_do3_func_vals[] = {
	{ 0,	"No function" },
	{ 1,	"SOPAS command" },
	{ 2,	"Device Ready" },
	{ 3,	"Application" },
	{ 4,	"Application/Device Ready" },
	{ 5,	"Device Ready/Contamination" },
	{ 6,	"Contamination" },
	{ 7,	"Master Synchronisation" },
	{ 0, NULL }
};

static const value_string sick_cola_do1_func_vals[] = {
	{ 0,	"No function" },
	{ 1,	"Command" },
	{ 2,	"Device Ready" },
	{ 3,	"Application/Device Ready" },
	{ 4,	"Sync pulse" },
	{ 5,	"Sync index" },
	{ 0, NULL }
};

static const value_string sick_cola_logic_state_vals[] = {
	{ 0,   "Active High" },
	{ 1,   "Active Low" },
	{ 0, NULL }
};

static const value_string sick_cola_do2_func_vals[] = {
	{ 0,	"No function" },
	{ 1,	"Command" },
	{ 2,	"Device Ready" },
	{ 3,	"Application/Device Ready" },
	{ 0, NULL }
};

static const value_string sick_cola_sync_mode_data_vals[] = {
	{ 0,	"No sync" },
	{ 1,	"Sync by wire" },
	{ 2,	"Sync by CAN" },
	{ 0, NULL }
};

static const value_string sick_cola_do3and4_func_vals[] = {
	{ 0,	"No function" },
	{ 1,	"Encoder" },
	{ 2,	"Slave sync" },
	{ 3,	"Digit Input" },
	{ 0, NULL }
};

static const value_string sick_cola_sync_status_vals[] = {
	{ 1,	"None" },
	{ 2,	"Too slow" },
	{ 4,	"Good" },
	{ 8,	"Too fast" },
	{ 0, NULL }
};

static const value_string sick_cola_sopas_error_vals[] = {
	{ 0,	"No error" },
	{ 1,	"Wrong userlevel, access to method not allowed" },
	{ 2,	"Trying to access a method with an unknown Sopas index" },
	{ 3,	"Trying to access a variable with an unknown Sopas index" },
	{ 4,	"Local condition violated" },
	{ 5,	"Invalid data given for variable (DEPRECATED)" },
	{ 6,	"An error with unknown reason occurred (DEPRECATED)" },
	{ 7,	"The communication buffer was too small for the amount of data that should be serialised." },
	{ 8,	"More data was expected, the allocated buffer could not be filled." },
	{ 9,	"The variable that shall be serialised has an unknown type." },
	{ 10,	"It is not allowed to write values to this variable." },
	{ 11,	"When using names instead of indices, a command was issued that the nameserver does not understand." },
	{ 12,	"The CoLa protocol specification does not define the given command, command is unknown." },
	{ 13,	"It is not possible to issue more than one command at a time to an SRT device." },
	{ 14,	"An array was accessed over its maximum length." },
	{ 15,	"The event you wanted to register for does not exist, the index is unknown." },
	{ 16,	"The value does not fit into the value field, it is too large." },
	{ 17,	"Character is unknown, probably not alphanumeric." },
	{ 18,	"No operating system message could be created for GET variable" },
	{ 19,	"No operating system message could be created for PUT variable" },
	{ 20,	"Internal error in the firmware" },
	{ 21,	"The Sopas Hubaddress is either too short or too long" },
	{ 22,	"The Sopas Hubaddress is invalid, it can not be decoded (Syntax)" },
	{ 23,	"Too many hubs in the address" },
	{ 24,	"When parsing a HubAddress an expected blank was not found. The HubAddress is not valid." },
	{ 25,	"An asynchronous method call was made although the device was built with 'AsyncMethodsSuppressed'" },
	{ 26,	"Complex Arrays not supported" },

	{ 0, NULL }
};

/* Copied and renamed from proto.c because global value_strings don't work for plugins */
static const value_string plugin_proto_checksum_vals[] = {
	{ PROTO_CHECKSUM_E_BAD,        "Bad"  },
	{ PROTO_CHECKSUM_E_GOOD,       "Good" },
	{ PROTO_CHECKSUM_E_UNVERIFIED, "Unverified" },
	{ PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },

	{ 0,        NULL }
};

static const unit_name_string sick_cola_units_ticks_mm = { "ticks/mm", NULL };

static uint8_t get_crc8_xor(tvbuff_t *p, uint8_t len, uint8_t offset) {
	uint8_t FCS = 0x00;
	uint8_t tmp;

	while (len--) {
		tmp = tvb_get_uint8(p,offset);
		FCS ^= tmp;
		offset++;
	}

	return FCS;
}

static uint8_t*
cola_get_ascii_parameter_string(packet_info *pinfo, tvbuff_t *tvb, int offset, int* new_offset)
{
	uint8_t* str_parameter;
	int parameter_end;

	parameter_end = tvb_find_uint8(tvb, offset, -1, SICK_COLA_DELIMITER);
	if (parameter_end < 0)
	{
		*new_offset = -1;
		return NULL;
	}

	str_parameter = tvb_get_string_enc(pinfo->pool, tvb, offset, parameter_end - offset, ENC_NA | ENC_ASCII);
	*new_offset = parameter_end;
	return str_parameter;
}

static bool
cola_ascii_add_parameter_U32(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name, uint32_t scale_factor)
{
	uint8_t* str_parameter;
	int parameter_end_offset;
	unsigned paramU32;

	str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou32(str_parameter, NULL, &paramU32))
		return false;

	proto_tree_add_uint(tree, hf_parameter, tvb, *offset, parameter_end_offset - *offset, paramU32/scale_factor);

	*offset = parameter_end_offset+1;
	return true;
}

static bool
cola_ascii_add_parameter_REAL(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name)
{
	uint8_t* str_parameter;
	int parameter_end_offset;
	unsigned paramU32;
	float paramFloat;

	str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou32(str_parameter, NULL, &paramU32))
		return false;

	memcpy(&paramFloat, &paramU32, 4);
	proto_tree_add_float(tree, hf_parameter, tvb, *offset, parameter_end_offset - *offset, paramFloat);

	*offset = parameter_end_offset+1;
	return true;
}

static bool
cola_ascii_add_parameter_I32(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name, int scale_factor)
{
	uint8_t* str_parameter;
	int parameter_end_offset;
	unsigned paramU32;

	str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou32(str_parameter, NULL, &paramU32))
		return false;

	proto_tree_add_int(tree, hf_parameter, tvb, *offset, parameter_end_offset - *offset, ((int32_t)paramU32)/scale_factor);

	*offset = parameter_end_offset+1;
	return true;
}

static bool
cola_ascii_add_parameter_I16(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name)
{
	uint8_t* str_parameter;
	int parameter_end_offset;
	uint16_t paramU16;

	str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou16(str_parameter, NULL, &paramU16))
		return false;

	proto_tree_add_int(tree, hf_parameter, tvb, *offset, parameter_end_offset - *offset, (int16_t)paramU16);

	*offset = parameter_end_offset+1;
	return true;
}
static bool
cola_ascii_add_parameter_2U8(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name)
{
	uint8_t* str_parameter;
	int parameter_end_offset, start_offset = *offset;
	uint16_t param1, param2, paramU16;

	str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou16(str_parameter, NULL, &param1))
		return false;

	*offset = parameter_end_offset+1;
	str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou16(str_parameter, NULL, &param2))
		return false;

	paramU16 = ((param1 << 8) & 0xFF00) | (param2 & 0x00FF);

	proto_tree_add_uint(tree, hf_parameter, tvb, *offset, parameter_end_offset - start_offset, paramU16);

	*offset = parameter_end_offset+1;
	return true;
}

static bool
cola_ascii_add_parameter_string(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name)
{
	uint8_t* str_parameter;
	int parameter_end_offset;

	str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	proto_tree_add_string(tree, hf_parameter, tvb, *offset, parameter_end_offset - *offset, str_parameter);

	*offset = parameter_end_offset+1;
	return true;
}


static int
diplay_timestamp_field(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_field, bool binary)
{
	int time_offset = offset;
	struct tm time_info;
	time_t time_info_seconds;
	nstime_t ns_time_info;

	if (binary)
	{
		time_info.tm_year = tvb_get_ntohs(tvb, time_offset)-1900;
		time_offset += 2;
		time_info.tm_mon = tvb_get_uint8(tvb, time_offset)-1;
		time_offset += 1;
		time_info.tm_mday = tvb_get_uint8(tvb, time_offset);
		time_offset += 1;
		time_info.tm_hour = tvb_get_uint8(tvb, time_offset);
		time_offset += 1;
		time_info.tm_min = tvb_get_uint8(tvb, time_offset);
		time_offset += 1;
		time_info.tm_sec = tvb_get_uint8(tvb, time_offset);
		time_offset += 1;

		time_info_seconds = mktime(&time_info);
		ns_time_info.secs = time_info_seconds;
		ns_time_info.nsecs = tvb_get_ntohl(tvb, time_offset)*1000;
		proto_tree_add_time(tree, hf_field, tvb, offset, 11, &ns_time_info);
		offset += 11;
	}

	return offset;
}

static int
dissect_sick_cola_read(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, bool binary _U_)
{
	int offset = 0;
	const uint8_t* read_name;

	proto_tree_add_item_ret_string(tree, hf_sick_cola_read_name, tvb, offset, -1, ENC_NA | ENC_ASCII, pinfo->pool, &read_name);
	offset = tvb_reported_length(tvb);

	return offset;
}

static int
dissect_sick_cola_write(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, bool binary)
{
	int offset = 0;
	const uint8_t* write_name;

	//find the space character for method name
	int write_name_end = tvb_find_uint8(tvb, offset, -1, SICK_COLA_DELIMITER);
	if (write_name_end < 0)
	{
		expert_add_info(pinfo, tree, &ei_sick_cola_command_name);
		return tvb_reported_length(tvb);
	}

	//don't include the space delimiter in the string
	proto_tree_add_item_ret_string(tree, hf_sick_cola_write_name, tvb, offset, write_name_end - offset, ENC_NA | ENC_ASCII, pinfo->pool, &write_name);
	offset = write_name_end+1;


	if (strcmp(write_name, "MMAlignmentMode") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_mm_alignment_node_layer_activation, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "LMPautostartmeas") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_autostartmeas_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "CLApplication") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_clapplication_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
	}
	else if (strcmp(write_name, "SetActiveApplications") == 0)
	{
		uint32_t count;

		if (binary)
		{
			proto_tree_add_item_ret_uint(tree, hf_sick_cola_set_active_app_count, tvb, offset, 1, ENC_BIG_ENDIAN, &count);
			offset += 1;
			for (uint32_t i = 0; i < count; i++)
			{
				proto_tree_add_item(tree, hf_sick_cola_set_active_app_id, tvb, offset, 4, ENC_ASCII);
				offset += 4;
				proto_tree_add_item(tree, hf_sick_cola_set_active_app_active, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
			}
		}
	}
	else if (strcmp(write_name, "LCMcfg") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_lcm_cfg_strategy, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_lcm_cfg_response_time, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_sick_cola_lcm_cfg_threshold_warning, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_sick_cola_lcm_cfg_threshold_error, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if (strcmp(write_name, "LMDscandatacfg") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_scan_data_cfg_data_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(tree, hf_sick_cola_scan_data_cfg_remission, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_scan_data_cfg_resolution, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_scan_data_cfg_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_scan_data_cfg_encoder, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(tree, hf_sick_cola_scan_data_cfg_position, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_scan_data_cfg_device_name, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_scan_data_cfg_comment, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_scan_data_cfg_time, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_scan_data_cfg_output_rate, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
	}
	else if (strcmp(write_name, "LMPoutputRange") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_change_output_range_status_code, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			float angular_resolution = tvb_get_ntohl(tvb, offset) / 10000.f;
			proto_tree_add_float(tree, hf_sick_cola_change_output_range_angular_resolution, tvb, offset, 4, angular_resolution);
			offset += 4;
			int start_angle = (int)tvb_get_ntohl(tvb, offset);
			proto_tree_add_float(tree, hf_sick_cola_change_output_range_start_angle, tvb, offset, 4, start_angle/10000.f);
			offset += 4;
			int stop_angle = (int)tvb_get_ntohl(tvb, offset);
			proto_tree_add_float(tree, hf_sick_cola_change_output_range_stop, tvb, offset, 4, stop_angle/10000.f);
			offset += 4;

		}
	}
	else if (strcmp(write_name, "TSCRole") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_ntp_tsc_role, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "TSCTCInterface") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_ntp_interface_data, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "TSCTCSrvAddr") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_ntp_ipaddress, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if (strcmp(write_name, "TSCTCtimezone") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_ntp_gmt_timezone_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "TSCTCupdatetime") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_ntp_timesync, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if (strcmp(write_name, "LFPparticle") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_particle_filter_status, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_particle_filter_threshold, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
	}
	else if (strcmp(write_name, "LFPmeanfilter") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_mean_filter_status, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_mean_filter_num_scans, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(tree, hf_sick_cola_mean_filter_final_part, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "LFPnto1filter") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_nto1_filter_status, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "FREchoFilter") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_echo_filter_status, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "MSsuppmode") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_fog_filter_status, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "CLFogFilterEn") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_fog_filter_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "MCSenseLevel") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_fog_filter_sensitivity_level, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "CLNFDigFilterEn") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_digital_nearfield_filter_status, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "CLHWFilterSectEn") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_digital_nearfield_filter_active_sector_vector, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if (strcmp(write_name, "LICsrc") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_encoder_increment_source, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "LICencset") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_encoder_setting, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "LICencres") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_encoder_resolution, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if (strcmp(write_name, "LICFixVel") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_encoder_fixed_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if ((strcmp(write_name, "DO6Fnc") == 0) ||
			 (strcmp(write_name, "DO3Fnc") == 0))
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_output_do3_func, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "DO1Fnc") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_output_do1_func, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "DO1Logic") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_output_do1_logic, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if (strcmp(write_name, "DO2Fnc") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_output_do2_func, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "DO2Logic") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_output_do2_logic, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if (strcmp(write_name, "SYMode") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_output_sync_mode_data, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "SYPhase") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_output_sync_phase_data, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
	}
	else if (strcmp(write_name, "DO3And4Fnc") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_input_do3and4_func, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(write_name, "DI3DebTim") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_input_debounce_time_data, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
	}

	return offset;
}

static int
dissect_sick_cola_method(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, bool binary)
{
	int offset = 0;
	const uint8_t* method_name;
	int parameter_end;

	//find the space character for method name
	int method_end = tvb_find_uint8(tvb, offset, -1, SICK_COLA_DELIMITER);
	if (method_end < 0)
	{
		//The command must have no parameters
		proto_tree_add_item(tree, hf_sick_cola_method_name, tvb, offset, -1, ENC_ASCII);
		return tvb_reported_length(tvb);
	}

	//don't include the space delimiter in the string
	proto_tree_add_item_ret_string(tree, hf_sick_cola_method_name, tvb, offset, method_end - offset, ENC_NA | ENC_ASCII, pinfo->pool, &method_name);
	offset = method_end+1;

	if (strcmp(method_name, "SetAccessMode") == 0)
	{
		uint32_t password;
		char str_password[20];
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_set_access_mode_user_level, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			password = tvb_get_ntohl(tvb, offset);
			proto_tree_add_string(tree, hf_sick_cola_set_access_mode_password, tvb, offset, 4, dword_to_hex(str_password, password));
			offset += 4;
		}
		else
		{
			parameter_end = tvb_find_uint8(tvb, offset, -1, SICK_COLA_DELIMITER);
			if (parameter_end < 0)
			{
				expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for SetAccessMode user level");
				return tvb_reported_length(tvb);
			}

			uint32_t user_level;
			uint8_t* str_user_level = tvb_get_string_enc(pinfo->pool, tvb, offset, parameter_end - offset, ENC_NA | ENC_ASCII);
			if (ws_strtou32(str_user_level, NULL, &user_level))
			{
				proto_tree_add_uint(tree, hf_sick_cola_set_access_mode_user_level, tvb, offset, parameter_end - offset, user_level);
			}
			else
			{
				proto_tree_add_uint(tree, hf_sick_cola_set_access_mode_user_level, tvb, offset, parameter_end - offset, 0xFFFFFFFF);
			}
			offset = parameter_end+1;

			proto_tree_add_item(tree, hf_sick_cola_set_access_mode_password, tvb, offset, -1, ENC_ASCII);
			offset = tvb_reported_length(tvb);
		}
	}
	else if (strcmp(method_name, "mLMPsetscancfg") == 0)
	{
		if (binary)
		{
			uint32_t scan_frequency = tvb_get_ntohl(tvb, offset) / 100;
			proto_tree_add_uint(tree, hf_sick_cola_set_scan_cfg_scan_frequency, tvb, offset, 4, scan_frequency);
			offset += 4;
			proto_tree_add_item(tree, hf_sick_cola_set_scan_cfg_num_active_scanners, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			float angular_resolution = tvb_get_ntohl(tvb, offset) / 10000.f;
			proto_tree_add_float(tree, hf_sick_cola_set_scan_cfg_angular_resolution, tvb, offset, 4, angular_resolution);
			offset += 4;
			int start_angle = (int)tvb_get_ntohl(tvb, offset);
			proto_tree_add_float(tree, hf_sick_cola_set_scan_cfg_start_angle, tvb, offset, 4, start_angle/10000.f);
			offset += 4;
			int stop_angle = (int)tvb_get_ntohl(tvb, offset);
			proto_tree_add_float(tree, hf_sick_cola_set_scan_cfg_stop_angle, tvb, offset, 4, stop_angle/10000.f);
			offset += 4;
		}
	}
	else if (strcmp(method_name, "mCLsetscancfglist") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_set_scan_cfg_mode, tvb, offset, 1, ENC_NA);
			offset += 1;
		}
	}
	else if (strcmp(method_name, "SetPassword") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_set_password_user_level, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_set_password_hash, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if (strcmp(method_name, "CheckPassword") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_check_password_user_level, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_check_password_hash, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if (strcmp(method_name, "LSPsetdatetime") == 0)
	{
		if (binary)
		{
			offset = diplay_timestamp_field(tree, tvb, offset, hf_sick_cola_set_date_time, binary);
		}
	}
	else if (strcmp(method_name, "mDOSetOutput") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_set_output_state_number, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_set_output_state_state, tvb, offset, 1, ENC_NA);
			offset += 1;
		}
	}


	return offset;
}

static int
dissect_sick_cola_event(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, bool binary)
{
	int offset = 0;
	const uint8_t* event_name;

	//find the space character for method name
	int event_end = tvb_find_uint8(tvb, offset, -1, SICK_COLA_DELIMITER);
	if (event_end < 0)
	{
		//The command must have no parameters
		proto_tree_add_item(tree, hf_sick_cola_event_name, tvb, offset, -1, ENC_ASCII);
		return tvb_reported_length(tvb);
	}

	//don't include the space delimiter in the string
	proto_tree_add_item_ret_string(tree, hf_sick_cola_event_name, tvb, offset, event_end - offset, ENC_NA | ENC_ASCII, pinfo->pool, &event_name);
	offset = event_end+1;

	if (strcmp(event_name, "LMDscandata") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_scan_data_start_stop, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(event_name, "LIDoutputstate") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_output_state_start_stop, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}

	return offset;
}

static int
dissect_binary_scan_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	proto_tree *device_tree, *status_info_tree, *frequency_tree, *output_channel16_tree, *output_channel8_tree,
				*data_tree, *channel_tree, *position_tree, *time_tree, *event_tree;
	proto_item *output_channel16_item, *output_channel8_item, *channel_item;

	proto_tree_add_item(tree, hf_sick_cola_scan_data_version, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	device_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_scan_data_device, NULL, "Device");
	proto_tree_add_item(device_tree, hf_sick_cola_scan_data_device_number, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(device_tree, hf_sick_cola_scan_data_serial_number, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(device_tree, hf_sick_cola_scan_data_device_status, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	status_info_tree = proto_tree_add_subtree(tree, tvb, offset, 18, ett_scan_data_status_info, NULL, "Status Info");
	proto_tree_add_item(status_info_tree, hf_sick_cola_scan_data_telegram_counter, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(status_info_tree, hf_sick_cola_scan_data_scan_counter, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(status_info_tree, hf_sick_cola_scan_data_time_since_startup, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(status_info_tree, hf_sick_cola_scan_data_transmission_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(status_info_tree, hf_sick_cola_scan_data_di_status, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(status_info_tree, hf_sick_cola_scan_data_do_status, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	uint16_t layer_angle;
	if (ws_hexstrtou16(tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII), NULL, &layer_angle))
	{
		proto_tree_add_int(status_info_tree, hf_sick_cola_scan_data_layer_angle, tvb, offset, 2, (int16_t)layer_angle);
	}
	else
	{
		proto_tree_add_int(status_info_tree, hf_sick_cola_scan_data_layer_angle, tvb, offset, 2, 0);
	}
	offset += 2;

	frequency_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_scan_data_frequency, NULL, "Frequencies");
        uint32_t scan_frequency = tvb_get_ntohl(tvb, offset) / 100;
	proto_tree_add_uint(frequency_tree, hf_sick_cola_scan_data_scan_frequency, tvb, offset, 4, scan_frequency);
	offset += 4;
	proto_tree_add_item(frequency_tree, hf_sick_cola_scan_data_measurement_frequency, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	uint32_t encoder_amount;
	proto_tree_add_item_ret_uint(tree, hf_sick_cola_scan_data_encoder_amount, tvb, offset, 2, ENC_BIG_ENDIAN, &encoder_amount);
	offset += 2;
	if (encoder_amount != 0)
	{
		proto_tree_add_item(tree, hf_sick_cola_scan_data_encoder_position, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_sick_cola_scan_data_encoder_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	output_channel16_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_scan_data_16bit_output_channels, &output_channel16_item, "16-bit Channels");

	uint32_t num_channels, channel, datasize;
	int start_offset = offset, channel_start;
	proto_tree_add_item_ret_uint(output_channel16_tree, hf_sick_cola_scan_data_num_16bit_channels, tvb, offset, 2, ENC_BIG_ENDIAN, &num_channels);
	offset += 2;
	for (channel = 0; channel < num_channels; channel++)
	{
		channel_start = offset;
		channel_tree = proto_tree_add_subtree_format(output_channel16_tree, tvb, offset, 2, ett_scan_data_16bit_output_channel, &channel_item, "Channel #%d", channel+1);

		proto_tree_add_item(channel_tree, hf_sick_cola_scan_data_output_channel_content, tvb, offset, 5, ENC_ASCII);
		offset += 5;
		proto_tree_add_item(channel_tree, hf_sick_cola_scan_data_output_channel_scale_factor, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(channel_tree, hf_sick_cola_scan_data_output_channel_scale_factor_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		int start_angle = (int)tvb_get_ntohl(tvb, offset);
		proto_tree_add_int(channel_tree, hf_sick_cola_scan_data_output_channel_start_angle, tvb, offset, 4, start_angle/10000);
		offset += 4;
                float angular_step = tvb_get_ntohs(tvb, offset) / 10000.0f;
		proto_tree_add_float(channel_tree, hf_sick_cola_scan_data_output_channel_size_single_angular_step, tvb, offset, 2, angular_step);
		offset += 2;
		proto_tree_add_item_ret_uint(channel_tree, hf_sick_cola_scan_data_num_data_points, tvb, offset, 2, ENC_BIG_ENDIAN, &datasize);
		offset += 2;
		data_tree = proto_tree_add_subtree(channel_tree, tvb, offset, datasize*2, ett_scan_data_16bit_output_data, NULL, "Data");
		for (uint32_t i = 0; i < datasize; i++)
		{
			proto_tree_add_item(data_tree, hf_sick_cola_scan_data_16bit_output_channel_data, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		proto_item_set_len(channel_item, offset - channel_start);
	}
	proto_item_set_len(output_channel16_item, offset - start_offset);

	start_offset = offset;
	output_channel8_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_scan_data_8bit_output_channels, &output_channel8_item, "8-bit Channels");

	proto_tree_add_item_ret_uint(output_channel8_tree, hf_sick_cola_scan_data_num_8bit_channels, tvb, offset, 2, ENC_BIG_ENDIAN, &num_channels);
	offset += 2;
	for (channel = 0; channel < num_channels; channel++)
	{
		channel_start = offset;
		channel_tree = proto_tree_add_subtree_format(output_channel8_tree, tvb, offset, 2, ett_scan_data_8bit_output_channel, &channel_item, "Channel #%d", channel+1);

		proto_tree_add_item(channel_tree, hf_sick_cola_scan_data_output_channel_content, tvb, offset, 5, ENC_ASCII);
		offset += 5;
		proto_tree_add_item(channel_tree, hf_sick_cola_scan_data_output_channel_scale_factor, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(channel_tree, hf_sick_cola_scan_data_output_channel_scale_factor_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		int start_angle = (int)tvb_get_ntohl(tvb, offset);
		proto_tree_add_int(channel_tree, hf_sick_cola_scan_data_output_channel_start_angle, tvb, offset, 4, start_angle/10000);
		offset += 4;
                float angular_step = tvb_get_ntohs(tvb, offset) / 10000.0f;
                proto_tree_add_float(channel_tree, hf_sick_cola_scan_data_output_channel_size_single_angular_step, tvb, offset, 2, angular_step);
		offset += 2;
		proto_tree_add_item_ret_uint(channel_tree, hf_sick_cola_scan_data_num_data_points, tvb, offset, 2, ENC_BIG_ENDIAN, &datasize);
		offset += 2;
		data_tree = proto_tree_add_subtree(channel_tree, tvb, offset, datasize, ett_scan_data_8bit_output_data, NULL, "Data");
		for (uint32_t i = 0; i < datasize; i++)
		{
			proto_tree_add_item(data_tree, hf_sick_cola_scan_data_8bit_output_channel_data, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
		proto_item_set_len(channel_item, offset - channel_start);
	}
	proto_item_set_len(output_channel8_item, offset - start_offset);

	uint16_t position_present = tvb_get_ntohs(tvb, offset);
	if (position_present)
	{
		position_tree = proto_tree_add_subtree(tree, tvb, offset, 28, ett_scan_data_position, NULL, "Position");

		proto_tree_add_item(position_tree, hf_sick_cola_scan_data_position_present, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(position_tree, hf_sick_cola_scan_data_position_x, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(position_tree, hf_sick_cola_scan_data_position_y, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(position_tree, hf_sick_cola_scan_data_position_z, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(position_tree, hf_sick_cola_scan_data_rotation_x, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(position_tree, hf_sick_cola_scan_data_rotation_y, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(position_tree, hf_sick_cola_scan_data_rotation_z, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(position_tree, hf_sick_cola_scan_data_rotation_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(position_tree, hf_sick_cola_scan_data_transmit_device_name, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	else
	{
		proto_tree_add_item(tree, hf_sick_cola_scan_data_position_present, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	uint16_t name_present = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_sick_cola_scan_data_device_name_present, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	if (name_present)
	{
		uint16_t name_length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_sick_cola_scan_data_device_name, tvb, offset, 2, ENC_BIG_ENDIAN|ENC_ASCII);
		offset += (name_length + 2);
	}

	uint16_t comment_present = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_sick_cola_scan_data_comment_present, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	if (comment_present)
	{
		uint16_t comment_length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_sick_cola_scan_data_comment, tvb, offset, 2, ENC_BIG_ENDIAN|ENC_ASCII);
		offset += (comment_length + 2);
	}

	uint16_t time_present = tvb_get_ntohs(tvb, offset);
	if (time_present)
	{
		time_tree = proto_tree_add_subtree(tree, tvb, offset, 13, ett_scan_data_time, NULL, "Time");

		proto_tree_add_item(time_tree, hf_sick_cola_scan_data_time_present, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		offset = diplay_timestamp_field(time_tree, tvb, offset, hf_sick_cola_scan_data_time, true);
	}
	else
	{
		proto_tree_add_item(tree, hf_sick_cola_scan_data_time_present, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	uint16_t event_present = tvb_get_ntohs(tvb, offset);
	if (event_present )
	{
		event_tree = proto_tree_add_subtree(tree, tvb, offset, 13, ett_scan_data_event_info, NULL, "Event Info");
		proto_tree_add_item(event_tree, hf_sick_cola_scan_data_display_event_info, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(event_tree, hf_sick_cola_scan_data_event_info_type, tvb, offset, 4, ENC_ASCII);
		offset += 4;
		proto_tree_add_item(event_tree, hf_sick_cola_scan_data_event_info_encoder_position, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(event_tree, hf_sick_cola_scan_data_event_info_encosder_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(event_tree, hf_sick_cola_scan_data_event_info_encoder_angle, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

	}
	else
	{
		proto_tree_add_item(tree, hf_sick_cola_scan_data_display_event_info, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	return offset;
}

static int
dissect_ascii_scan_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	proto_tree *device_tree, *status_info_tree, *frequency_tree, *output_channel16_tree, *output_channel8_tree,
		*data_tree, *channel_tree;
	proto_item *device_item, *status_info_item, *frequency_item, *output_channel16_item, *data_item, *output_channel8_item, *channel_item;
	int save_offset, parameter_end_offset, data_start_offset;
	uint8_t* str_parameter;

	if (!cola_ascii_add_parameter_U32(tree, hf_sick_cola_scan_data_version, pinfo, tvb, &offset, "ScanData version", 1))
		return tvb_reported_length(tvb);

	save_offset = offset;
	device_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_scan_data_device, &device_item, "Device");

	if (!cola_ascii_add_parameter_U32(device_tree, hf_sick_cola_scan_data_device_number, pinfo, tvb, &offset, "ScanData Device number", 1))
		return tvb_reported_length(tvb);
	if (!cola_ascii_add_parameter_U32(device_tree, hf_sick_cola_scan_data_serial_number, pinfo, tvb, &offset, "ScanData Serial Number", 1))
		return tvb_reported_length(tvb);
	if (!cola_ascii_add_parameter_2U8(device_tree, hf_sick_cola_scan_data_device_status, pinfo, tvb, &offset, "ScanData Device Status"))
		return tvb_reported_length(tvb);

	proto_item_set_len(device_item, offset - save_offset);

	save_offset = offset;
	status_info_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_scan_data_status_info, &status_info_item, "Status Info");

	if (!cola_ascii_add_parameter_U32(status_info_tree, hf_sick_cola_scan_data_telegram_counter, pinfo, tvb, &offset, "ScanData Telegram counter", 1))
		return tvb_reported_length(tvb);

	if (!cola_ascii_add_parameter_U32(status_info_tree, hf_sick_cola_scan_data_scan_counter, pinfo, tvb, &offset, "ScanData Scan counter", 1))
		return tvb_reported_length(tvb);

	if (!cola_ascii_add_parameter_U32(status_info_tree, hf_sick_cola_scan_data_time_since_startup, pinfo, tvb, &offset, "ScanData Time Since Startup", 1))
		return tvb_reported_length(tvb);

	if (!cola_ascii_add_parameter_U32(status_info_tree, hf_sick_cola_scan_data_transmission_time, pinfo, tvb, &offset, "ScanData Transmission Time", 1))
		return tvb_reported_length(tvb);

	if (!cola_ascii_add_parameter_2U8(status_info_tree, hf_sick_cola_scan_data_di_status, pinfo, tvb, &offset, "ScanData Digital Input Status"))
		return tvb_reported_length(tvb);

	if (!cola_ascii_add_parameter_2U8(status_info_tree, hf_sick_cola_scan_data_do_status, pinfo, tvb, &offset, "ScanData Digital Output Status"))
		return tvb_reported_length(tvb);

	if (!cola_ascii_add_parameter_I16(status_info_tree, hf_sick_cola_scan_data_layer_angle, pinfo, tvb, &offset, "ScanData Layer Angle"))
		return tvb_reported_length(tvb);

	proto_item_set_len(status_info_item, offset - save_offset);

	save_offset = offset;
	frequency_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_scan_data_frequency, &frequency_item, "Frequencies");

	if (!cola_ascii_add_parameter_U32(frequency_tree, hf_sick_cola_scan_data_scan_frequency, pinfo, tvb, &offset, "ScanData Scan Frequency", 100))
		return tvb_reported_length(tvb);

	if (!cola_ascii_add_parameter_U32(frequency_tree, hf_sick_cola_scan_data_measurement_frequency, pinfo, tvb, &offset, "ScanData Measurement Frequency", 1))
		return tvb_reported_length(tvb);

	proto_item_set_len(frequency_item, offset - save_offset);

	str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for ScanData Amount of Encoder");
		return false;
	}

	uint32_t encoder_amount;
	if (!ws_hexstrtou32(str_parameter, NULL, &encoder_amount))
		return false;

	proto_tree_add_uint(tree, hf_sick_cola_scan_data_encoder_amount, tvb, offset, parameter_end_offset-offset, encoder_amount);
	offset = parameter_end_offset + 1;
	if (encoder_amount != 0)
	{
		if (!cola_ascii_add_parameter_U32(tree, hf_sick_cola_scan_data_encoder_position, pinfo, tvb, &offset, "ScanData Encoder Position", 1))
			return tvb_reported_length(tvb);

		if (!cola_ascii_add_parameter_U32(tree, hf_sick_cola_scan_data_encoder_speed, pinfo, tvb, &offset, "ScanData Encoder Speed", 1))
			return tvb_reported_length(tvb);
	}

	//16-bit channels
	str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for ScanData Amount of 16-bit channels");
		return false;
	}

	uint32_t num_channels, channel, angular_step, datasize;
	int channel_start;
	if (!ws_hexstrtou32(str_parameter, NULL, &num_channels))
		return false;

	save_offset = offset;
	output_channel16_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_scan_data_16bit_output_channels, &output_channel16_item, "16-bit Channels");

	proto_tree_add_uint(output_channel16_tree, hf_sick_cola_scan_data_num_16bit_channels, tvb, parameter_end_offset-offset, 2, num_channels);
	offset = parameter_end_offset + 1;

	for (channel = 0; channel < num_channels; channel++)
	{
		channel_start = offset;
		channel_tree = proto_tree_add_subtree_format(output_channel16_tree, tvb, offset, 0, ett_scan_data_16bit_output_channel, &channel_item, "Channel #%d", channel+1);

		if (!cola_ascii_add_parameter_string(channel_tree, hf_sick_cola_scan_data_output_channel_content, pinfo, tvb, &offset, "ScanData 16-bit Channel Content"))
			return tvb_reported_length(tvb);

		if (!cola_ascii_add_parameter_REAL(channel_tree, hf_sick_cola_scan_data_output_channel_scale_factor, pinfo, tvb, &offset, "ScanData Scale Factor"))
			return tvb_reported_length(tvb);

		if (!cola_ascii_add_parameter_REAL(channel_tree, hf_sick_cola_scan_data_output_channel_scale_factor_offset, pinfo, tvb, &offset, "ScanData Scale Factor Offset"))
			return tvb_reported_length(tvb);

		if (!cola_ascii_add_parameter_I32(channel_tree, hf_sick_cola_scan_data_output_channel_start_angle, pinfo, tvb, &offset, "ScanData Start Angle", 10000))
			return tvb_reported_length(tvb);

		str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, offset, &parameter_end_offset);
		if (str_parameter == NULL)
		{
			expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for ScanData Size of Angular Step");
			return false;
		}

		if (!ws_hexstrtou32(str_parameter, NULL, &angular_step))
			return false;

		proto_tree_add_float(channel_tree, hf_sick_cola_scan_data_output_channel_size_single_angular_step, tvb, offset, parameter_end_offset-offset, angular_step/10000.0f);
		offset = parameter_end_offset + 1;

		str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, offset, &parameter_end_offset);
		if (str_parameter == NULL)
		{
			expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for ScanData 16-bit Channel Amount of Data");
			return false;
		}

		if (!ws_hexstrtou32(str_parameter, NULL, &datasize))
			return false;

		proto_tree_add_uint(channel_tree, hf_sick_cola_scan_data_num_data_points, tvb, offset, parameter_end_offset-offset, datasize);
		offset = parameter_end_offset + 1;

		data_start_offset = offset;
		data_tree = proto_tree_add_subtree(channel_tree, tvb, offset, 0, ett_scan_data_16bit_output_data, &data_item, "Data");
		for (uint32_t i = 0; i < datasize; i++)
		{
			if (!cola_ascii_add_parameter_U32(data_tree, hf_sick_cola_scan_data_16bit_output_channel_data, pinfo, tvb, &offset, "ScanData 16-bit Channel Data", 1))
				return tvb_reported_length(tvb);
		}
		proto_item_set_len(data_item, offset - data_start_offset);
		proto_item_set_len(channel_item, offset - channel_start);
	}
	proto_item_set_len(output_channel16_item, offset - save_offset);

	//8-bit channels
	str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for ScanData Amount of 8-bit channels");
		return false;
	}

	if (!ws_hexstrtou32(str_parameter, NULL, &num_channels))
		return false;

	save_offset = offset;
	output_channel8_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_scan_data_8bit_output_channels, &output_channel8_item, "8-bit Channels");

	proto_tree_add_uint(output_channel8_tree, hf_sick_cola_scan_data_num_8bit_channels, tvb, parameter_end_offset-offset, 2, num_channels);
	offset = parameter_end_offset + 1;

	for (channel = 0; channel < num_channels; channel++)
	{
		channel_start = offset;
		channel_tree = proto_tree_add_subtree_format(output_channel8_tree, tvb, offset, 2, ett_scan_data_8bit_output_channel, &channel_item, "Channel #%d", channel+1);

		if (!cola_ascii_add_parameter_string(channel_tree, hf_sick_cola_scan_data_output_channel_content, pinfo, tvb, &offset, "ScanData 16-bit Channel Content"))
			return tvb_reported_length(tvb);

		if (!cola_ascii_add_parameter_REAL(channel_tree, hf_sick_cola_scan_data_output_channel_scale_factor, pinfo, tvb, &offset, "ScanData Scale Factor"))
			return tvb_reported_length(tvb);

		if (!cola_ascii_add_parameter_REAL(channel_tree, hf_sick_cola_scan_data_output_channel_scale_factor_offset, pinfo, tvb, &offset, "ScanData Scale Factor Offset"))
			return tvb_reported_length(tvb);

		if (!cola_ascii_add_parameter_I32(channel_tree, hf_sick_cola_scan_data_output_channel_start_angle, pinfo, tvb, &offset, "ScanData Start Angle", 10000))
			return tvb_reported_length(tvb);

		str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, offset, &parameter_end_offset);
		if (str_parameter == NULL)
		{
			expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for ScanData Size of Angular Step");
			return false;
		}

		if (!ws_hexstrtou32(str_parameter, NULL, &angular_step))
			return false;

		proto_tree_add_float(channel_tree, hf_sick_cola_scan_data_output_channel_size_single_angular_step, tvb, offset, parameter_end_offset-offset, angular_step/10000.0f);
		offset = parameter_end_offset + 1;

		str_parameter = cola_get_ascii_parameter_string(pinfo, tvb, offset, &parameter_end_offset);
		if (str_parameter == NULL)
		{
			expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for ScanData 16-bit Channel Amount of Data");
			return false;
		}

		if (!ws_hexstrtou32(str_parameter, NULL, &datasize))
			return false;

		proto_tree_add_uint(channel_tree, hf_sick_cola_scan_data_num_data_points, tvb, offset, parameter_end_offset-offset, datasize);
		offset = parameter_end_offset + 1;

		data_start_offset = offset;
		data_tree = proto_tree_add_subtree(channel_tree, tvb, offset, 0, ett_scan_data_8bit_output_data, &data_item, "Data");
		for (uint32_t i = 0; i < datasize; i++)
		{
			if (!cola_ascii_add_parameter_U32(data_tree, hf_sick_cola_scan_data_16bit_output_channel_data, pinfo, tvb, &offset, "ScanData 8-bit Channel Data", 1))
				return tvb_reported_length(tvb);
		}
		proto_item_set_len(data_item, offset - data_start_offset);
		proto_item_set_len(channel_item, offset - channel_start);
	}

	proto_item_set_len(output_channel8_item, offset - save_offset);


	return offset;
}

static int
dissect_output_state(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, bool binary)
{
	proto_tree *status_tree, *output_tree, *outX_tree, *time_tree;

	status_tree = proto_tree_add_subtree(tree, tvb, offset, 6, ett_output_state_status, NULL, "Status code");
	proto_tree_add_item(status_tree, hf_sick_cola_output_state_status_version, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(status_tree, hf_sick_cola_output_state_status_system_counter, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	output_tree = proto_tree_add_subtree(tree, tvb, offset, 5*g_number_of_outputs, ett_output_state, NULL, "Outputs");
	for (uint32_t i = 0; i < g_number_of_outputs; i++)
	{
		outX_tree = proto_tree_add_subtree_format(output_tree, tvb, offset, 5, ett_output_state_x, NULL, "Output #%d", i+1);
		proto_tree_add_item(outX_tree, hf_sick_cola_output_state_state, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(outX_tree, hf_sick_cola_output_state_count, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	output_tree = proto_tree_add_subtree(tree, tvb, offset, 5*g_number_of_outputs, ett_ext_output_state, NULL, "Ext. Outputs");
	for (uint32_t i = 0; i < g_number_of_outputs; i++)
	{
		outX_tree = proto_tree_add_subtree_format(output_tree, tvb, offset, 5, ett_ext_output_state_x, NULL, "Ext. Output #%d", i+1);
		proto_tree_add_item(outX_tree, hf_sick_cola_output_state_ext_state, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(outX_tree, hf_sick_cola_output_state_ext_count, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	uint16_t time_present = tvb_get_ntohs(tvb, offset);
	if (time_present)
	{
		time_tree = proto_tree_add_subtree(tree, tvb, offset, 12, ett_output_state_time, NULL, "Time");

		proto_tree_add_item(time_tree, hf_sick_cola_output_state_time_present, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		offset = diplay_timestamp_field(time_tree, tvb, offset, hf_sick_cola_output_state_time, binary);
	}
	else
	{
		proto_tree_add_item(tree, hf_sick_cola_output_state_time_present, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	return offset;
}

static int
dissect_sick_cola_answer_sra(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, bool binary)
{
	int offset = 0;
	const uint8_t* answer_name;

	//find the space character for read name
	int answer_end = tvb_find_uint8(tvb, offset, -1, SICK_COLA_DELIMITER);
	if (answer_end < 0)
	{
		//The command must have no parameters
		proto_tree_add_item(tree, hf_sick_cola_answer_name, tvb, offset, -1, ENC_ASCII);
		return tvb_reported_length(tvb);
	}
	else
	{
		//don't include the space delimiter in the string
		proto_tree_add_item_ret_string(tree, hf_sick_cola_answer_name, tvb, offset, answer_end - offset, ENC_NA | ENC_ASCII, pinfo->pool, &answer_name);
		offset = answer_end+1;
	}


	if (strcmp(answer_name, "LMPscancfg") == 0)
	{
		if (binary)
		{
			uint32_t scan_frequency = tvb_get_ntohl(tvb, offset) / 100;
			proto_tree_add_uint(tree, hf_sick_cola_set_scan_cfg_scan_frequency, tvb, offset, 4, scan_frequency);
			offset += 4;
			proto_tree_add_item(tree, hf_sick_cola_set_scan_cfg_num_active_scanners, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			float angular_resolution = tvb_get_ntohl(tvb, offset) / 10000.f;
			proto_tree_add_float(tree, hf_sick_cola_set_scan_cfg_angular_resolution, tvb, offset, 4, angular_resolution);
			offset += 4;
			int start_angle = (int)tvb_get_ntohl(tvb, offset);
			proto_tree_add_float(tree, hf_sick_cola_set_scan_cfg_start_angle, tvb, offset, 4, start_angle/10000.f);
			offset += 4;
			int stop_angle = (int)tvb_get_ntohl(tvb, offset);
			proto_tree_add_float(tree, hf_sick_cola_set_scan_cfg_stop_angle, tvb, offset, 4, stop_angle/10000.f);
			offset += 4;
		}
	}
	else if (strcmp(answer_name, "LCMcfg") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_lcm_cfg_strategy, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_lcm_cfg_response_time, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(tree, hf_sick_cola_lcm_cfg_threshold_warning, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(tree, hf_sick_cola_lcm_cfg_threshold_error, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
	}
	else if (strcmp(answer_name, "CMContLvlM") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_cm_cont_lvlm_availability, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "LMPoutputRange") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_output_range_num_sectors, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			float angular_resolution = tvb_get_ntohl(tvb, offset) / 10000.f;
			proto_tree_add_float(tree, hf_sick_cola_output_range_angular_resolution, tvb, offset, 4, angular_resolution);
			offset += 4;
			int start_angle = (int)tvb_get_ntohl(tvb, offset);
			proto_tree_add_float(tree, hf_sick_cola_output_range_start_angle, tvb, offset, 4, start_angle/10000.f);
			offset += 4;
			int stop_angle = (int)tvb_get_ntohl(tvb, offset);
			proto_tree_add_float(tree, hf_sick_cola_output_range_stop, tvb, offset, 4, stop_angle/10000.f);
			offset += 4;
		}
	}
	else if (strcmp(answer_name, "LMDscandata") == 0)
	{
		if (binary)
		{
			offset = dissect_binary_scan_data(tree, pinfo, tvb, offset);
		}
		else
		{
			offset = dissect_ascii_scan_data(tree, pinfo, tvb, offset);
		}
	}
	else if (strcmp(answer_name, "STlms") == 0)
	{
		proto_tree_add_item(tree, hf_sick_cola_stims_status_code, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_sick_cola_stims_temp_out_of_range, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_sick_cola_stims_time_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		//manually format the time
		uint16_t hour, minute, second, day, month, year;
		hour = tvb_get_ntohs(tvb, offset);
		minute = tvb_get_ntohs(tvb, offset+3);
		second = tvb_get_ntohs(tvb, offset+6);
		proto_tree_add_string(tree, hf_sick_cola_stims_time, tvb, offset, 8,
			wmem_strdup_printf(pinfo->pool, "%d:%02d:%02d", hour, minute, second));
		offset += 8;

		proto_tree_add_item(tree, hf_sick_cola_stims_date_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		day = tvb_get_ntohs(tvb, offset);
		month = tvb_get_ntohs(tvb, offset+3);
		year = tvb_get_ntohl(tvb, offset+6);
		proto_tree_add_string(tree, hf_sick_cola_stims_date, tvb, offset, 10,
			wmem_strdup_printf(pinfo->pool, "%02d/%02d/%04d", day, month, year));
		offset += 10;

		proto_tree_add_item(tree, hf_sick_cola_stims_led1, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_sick_cola_stims_led2, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_sick_cola_stims_led3, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_sick_cola_stims_reserved, tvb, offset, 6, ENC_NA);
		offset += 6;
	}
	else if (strcmp(answer_name, "DeviceTime") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_device_time, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "TSCTCmaxoffset") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_ntp_max_offset_time, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "TSCTCdelay") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_ntp_max_offset_time, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "CLFogFilterEn") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_fog_filter_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "LICSpTh") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_encoder_speed_threshold, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "LICencsp") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_encoder_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	else if (strcmp(answer_name, "LIDoutputstate") == 0)
	{
		offset = dissect_output_state(tree, pinfo, tvb, offset, binary);
	}
	else if (strcmp(answer_name, "SYextmon") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_input_sync_status_data, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_sick_cola_input_signal_frequency, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}

	return offset;
}

static int
dissect_sick_cola_answer_swa(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, bool binary _U_)
{
	int offset = 0;
	const uint8_t* answer_name;

	proto_tree_add_item_ret_string(tree, hf_sick_cola_answer_name, tvb, offset, -1, ENC_NA | ENC_ASCII, pinfo->pool, &answer_name);
	offset = tvb_reported_length(tvb);

	return offset;
}

static int
dissect_sick_cola_answer_san(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, bool binary)
{
	int offset = 0;
	const uint8_t* answer_name;
	int parameter_length;

	//find the space character for answer name
	int answer_end = tvb_find_uint8(tvb, offset, -1, SICK_COLA_DELIMITER);
	if (answer_end < 0)
	{
		//The command must have no parameters
		proto_tree_add_item(tree, hf_sick_cola_answer_name, tvb, offset, -1, ENC_ASCII);
		return tvb_reported_length(tvb);
	}

	//don't include the space delimiter in the string
	proto_tree_add_item_ret_string(tree, hf_sick_cola_answer_name, tvb, offset, answer_end - offset, ENC_NA | ENC_ASCII, pinfo->pool, &answer_name);
	offset = answer_end+1;

	if (strcmp(answer_name, "SetAccessMode") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_set_access_mode_change_level, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
		else
		{
			parameter_length = tvb_reported_length_remaining(tvb, offset);
			uint32_t change_level;
			uint8_t* str_change_level = tvb_get_string_enc(pinfo->pool, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
			if (ws_strtou32(str_change_level, NULL, &change_level))
			{
				proto_tree_add_uint(tree, hf_sick_cola_set_access_mode_change_level, tvb, offset, parameter_length, change_level);
			}
			else
			{
				proto_tree_add_uint(tree, hf_sick_cola_set_access_mode_change_level, tvb, offset, parameter_length, 0xFFFFFFFF);
			}
		}
	}
	else if (strcmp(answer_name, "mLMPsetscancfg") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_set_scan_cfg_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			uint32_t scan_frequency = tvb_get_ntohl(tvb, offset) / 100;
			proto_tree_add_uint(tree, hf_sick_cola_set_scan_cfg_scan_frequency, tvb, offset, 4, scan_frequency);
			offset += 4;
			proto_tree_add_item(tree, hf_sick_cola_set_scan_cfg_num_active_scanners, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			float angular_resolution = tvb_get_ntohl(tvb, offset) / 10000.f;
			proto_tree_add_float(tree, hf_sick_cola_set_scan_cfg_angular_resolution, tvb, offset, 4, angular_resolution);
			offset += 4;
			int start_angle = (int)tvb_get_ntohl(tvb, offset);
			proto_tree_add_float(tree, hf_sick_cola_set_scan_cfg_start_angle, tvb, offset, 4, start_angle/10000.f);
			offset += 4;
			int stop_angle = (int)tvb_get_ntohl(tvb, offset);
			proto_tree_add_float(tree, hf_sick_cola_set_scan_cfg_stop_angle, tvb, offset, 4, stop_angle/10000.f);
			offset += 4;
		}
	}
	else if (strcmp(answer_name, "mCLsetscancfglist") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_set_scan_cfg_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "LMCstandby") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_standby_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "LMCstartmeas") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_startmeas_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
		else
		{
			//status code should be rest of packet
			parameter_length = tvb_reported_length_remaining(tvb, offset);
			uint8_t* str_status_code = tvb_get_string_enc(pinfo->pool, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
			uint32_t status_code;
			if (ws_strtou32(str_status_code, NULL, &status_code))
			{
				proto_tree_add_uint(tree, hf_sick_cola_startmeas_status_code, tvb, offset, parameter_length, status_code);
			}
			else
			{
				proto_tree_add_uint(tree, hf_sick_cola_startmeas_status_code, tvb, offset, parameter_length, status_code);
			}
		}
	}
	else if (strcmp(answer_name, "LMCstopmeas") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_stopmeas_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "SetPassword") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_set_password_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "CheckPassword") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_check_password_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "mEEwriteall") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_ee_write_all_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "Run") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_run_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	else if (strcmp(answer_name, "LSPsetdatetime") == 0)
	{
		if (binary)
		{
			offset = diplay_timestamp_field(tree, tvb, offset, hf_sick_cola_set_date_time_status_code, binary);
		}
	}
	else if (strcmp(answer_name, "mDOSetOutput") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_set_output_state_status_code, tvb, offset, 1, ENC_NA);
			offset += 1;
		}
	}

	return offset;
}

static int
dissect_sick_cola_answer_sea(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, bool binary)
{
	int offset = 0;
	const uint8_t* answer_name;

	//find the space character for answer name
	int answer_end = tvb_find_uint8(tvb, offset, -1, SICK_COLA_DELIMITER);
	if (answer_end < 0)
	{
		//The command must have no parameters
		proto_tree_add_item(tree, hf_sick_cola_answer_name, tvb, offset, -1, ENC_ASCII);
		return tvb_reported_length(tvb);
	}

	//don't include the space delimiter in the string
	proto_tree_add_item_ret_string(tree, hf_sick_cola_answer_name, tvb, offset, answer_end - offset, ENC_NA | ENC_ASCII, pinfo->pool, &answer_name);
	offset = answer_end+1;

	if (strcmp(answer_name, "LMDscandata") == 0)
	{
		if (binary)
		{
			proto_tree_add_item(tree, hf_sick_cola_scan_data_start_stop, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}

	return offset;
}


static int
dissect_sick_cola_answer_ssn(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, bool binary)
{
	int offset = 0;
	const uint8_t* answer_name;

	//find the space character for answer name
	int answer_end = tvb_find_uint8(tvb, offset, -1, SICK_COLA_DELIMITER);
	if (answer_end < 0)
	{
		//The command must have no parameters
		proto_tree_add_item(tree, hf_sick_cola_answer_name, tvb, offset, -1, ENC_ASCII);
		return tvb_reported_length(tvb);
	}

	//don't include the space delimiter in the string
	proto_tree_add_item_ret_string(tree, hf_sick_cola_answer_name, tvb, offset, answer_end - offset, ENC_NA | ENC_ASCII, pinfo->pool, &answer_name);
	offset = answer_end+1;

	if (strcmp(answer_name, "LMDscandata") == 0)
	{
		if (binary)
		{
			offset = dissect_binary_scan_data(tree, pinfo, tvb, offset);
		}
		else
		{
			offset = dissect_ascii_scan_data(tree, pinfo, tvb, offset);
		}

	}
	else if (strcmp(answer_name, "LIDoutputstate") == 0)
	{
		offset = dissect_output_state(tree, pinfo, tvb, offset, binary);
	}

	return offset;
}

static int
dissect_sick_cola_answer_sfa(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, bool binary)
{
	int offset = 0;

	if (binary)
	{
		proto_tree_add_item(tree, hf_sick_cola_sopas_error_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	else
	{
		uint8_t* str_error;
		uint32_t error;
		int length = tvb_reported_length_remaining(tvb, offset);

		str_error = tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_NA | ENC_ASCII);
		if (!ws_hexstrtou32(str_error, NULL, &error))
			return 0;

		proto_tree_add_uint(tree, hf_sick_cola_sopas_error_code, tvb, offset, length, error);
		offset = tvb_reported_length(tvb);
	}

	return offset;
}

static unsigned
get_sick_cola_b_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	uint32_t len = 0;

	len = tvb_get_ntohl(tvb, offset+4);

	return len+SICK_COLA_B_HEADER_SIZE+1;
}

static int
dissect_sick_cola_b_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *cola_b_tree;
	proto_item *ti, *command_item;
	int				offset = 0, start_crc_offset;
	uint32_t			command, length;
	tvbuff_t		*command_tvb;

	if (tvb_get_ntohl(tvb, offset) != SICK_COLA_B_MAGIC_NUMBER)
	{
		//not our packet
		return 0;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoLa B");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_sick_cola_b, tvb, offset, -1, ENC_NA);
	cola_b_tree = proto_item_add_subtree(ti, ett_sick_cola_b);

	proto_tree_add_item(cola_b_tree, hf_sick_cola_b_magic_number, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item_ret_uint(cola_b_tree, hf_sick_cola_b_length, tvb, offset, 4, ENC_BIG_ENDIAN, &length);
	offset += 4;

	start_crc_offset = offset;
	command_item = proto_tree_add_item_ret_uint(cola_b_tree, hf_sick_cola_command, tvb, offset, 4, ENC_BIG_ENDIAN, &command);
	col_set_str(pinfo->cinfo, COL_INFO, tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII));
	offset += 4;

	command_tvb = tvb_new_subset_length(tvb, offset, length);
	switch (command)
	{
	case SICK_COLA_COMMAND_READ:
		dissect_sick_cola_read(cola_b_tree, pinfo, command_tvb, true);
		break;
	case SICK_COLA_COMMAND_WRITE:
		dissect_sick_cola_write(cola_b_tree, pinfo, command_tvb, true);
		break;
	case SICK_COLA_COMMAND_METHOD:
		dissect_sick_cola_method(cola_b_tree, pinfo, command_tvb, true);
		break;
	case SICK_COLA_COMMAND_EVENT:
		dissect_sick_cola_event(cola_b_tree, pinfo, command_tvb, true);
		break;
	case SICK_COLA_COMMAND_ANSWER_sRA:
		dissect_sick_cola_answer_sra(cola_b_tree, pinfo, command_tvb, true);
		break;
	case SICK_COLA_COMMAND_ANSWER_sWA:
		dissect_sick_cola_answer_swa(cola_b_tree, pinfo, command_tvb, true);
		break;
	case SICK_COLA_COMMAND_ANSWER_sAN:
		dissect_sick_cola_answer_san(cola_b_tree, pinfo, command_tvb, true);
		break;
	case SICK_COLA_COMMAND_ANSWER_sEA:
		dissect_sick_cola_answer_sea(cola_b_tree, pinfo, command_tvb, true);
		break;
	case SICK_COLA_COMMAND_ANSWER_sSN:
		dissect_sick_cola_answer_ssn(cola_b_tree, pinfo, command_tvb, true);
		break;
	case SICK_COLA_COMMAND_ANSWER_sFA:
	case SICK_COLA_COMMAND_ANSWER_sFA_NULL:
		dissect_sick_cola_answer_sfa(cola_b_tree, pinfo, command_tvb, true);
		break;
	case SICK_COLA_COMMAND_SOPAS_BINARY:
	case SICK_COLA_COMMAND_ANSWER_SOPAS_BINARY:
		proto_tree_add_item(cola_b_tree, hf_sick_cola_b_sopas_command, tvb, offset-4, 4, ENC_ASCII);
		proto_tree_add_item(cola_b_tree, hf_sick_cola_b_sopas_command_data, tvb, offset, tvb_reported_length_remaining(tvb, offset)-1, ENC_NA);
		break;

	default:
		expert_add_info(pinfo, command_item, &ei_sick_cola_command);
		break;
	}

	offset += (length-4);

	//Add the checksum
	proto_tree_add_checksum(cola_b_tree, tvb, offset,
		hf_sick_cola_b_checksum, hf_sick_cola_b_checksum_status, &ei_sick_cola_b_checksum, pinfo,
		get_crc8_xor(tvb, length, start_crc_offset), ENC_NA, PROTO_CHECKSUM_VERIFY);

	return tvb_captured_length(tvb);
}


static int
dissect_sick_cola_b(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, true, SICK_COLA_B_HEADER_SIZE, get_sick_cola_b_pdu_len, dissect_sick_cola_b_pdu, data);
	return tvb_captured_length(tvb);
}

static bool
dissect_sick_cola_b_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (tvb_captured_length(tvb) >= 4) { /* check of data is big enough for base header. */
		uint32_t magic_number = tvb_get_ntohl(tvb, 0);

		if (magic_number == SICK_COLA_B_MAGIC_NUMBER)
		{
			dissect_sick_cola_b(tvb, pinfo, tree, data);
			return true;
		}
	}
	return false;
}

static int
dissect_sick_cola_a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree      *cola_a_tree;
	proto_item      *ti, *command_item;
	int				offset = 0;
	uint32_t			command;
	int			etxp = 0; /* ETX position */
	tvbuff_t		*command_tvb;

	//Ensure there is a start and end delimiter
	if (tvb_get_uint8(tvb, offset) != SICK_COLA_A_STX)
		return 0;

	etxp = tvb_find_uint8(tvb, 1, -1, SICK_COLA_A_ETX);
	if (etxp == -1)
	{
		//see if the next frame has it
		pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
		pinfo->desegment_offset = 0;
		return -1;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoLa A");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_sick_cola_a, tvb, offset, -1, ENC_NA);
	cola_a_tree = proto_item_add_subtree(ti, ett_sick_cola_a);

	proto_tree_add_item(cola_a_tree, hf_sick_cola_a_stx, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	command_item = proto_tree_add_item_ret_uint(cola_a_tree, hf_sick_cola_command, tvb, offset, 4, ENC_BIG_ENDIAN, &command);
	col_set_str(pinfo->cinfo, COL_INFO, tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII));
	offset += 4;

	command_tvb = tvb_new_subset_length(tvb, offset, etxp-offset);
	switch (command)
	{
	case SICK_COLA_COMMAND_READ:
		dissect_sick_cola_read(cola_a_tree, pinfo, command_tvb, false);
		break;
	case SICK_COLA_COMMAND_WRITE:
		dissect_sick_cola_write(cola_a_tree, pinfo, command_tvb, false);
		break;
	case SICK_COLA_COMMAND_METHOD:
		dissect_sick_cola_method(cola_a_tree, pinfo, command_tvb, false);
		break;
	case SICK_COLA_COMMAND_EVENT:
		dissect_sick_cola_event(cola_a_tree, pinfo, command_tvb, false);
		break;
	case SICK_COLA_COMMAND_ANSWER_sRA:
		dissect_sick_cola_answer_sra(cola_a_tree, pinfo, command_tvb, false);
		break;
	case SICK_COLA_COMMAND_ANSWER_sWA:
		dissect_sick_cola_answer_swa(cola_a_tree, pinfo, command_tvb, false);
		break;
	case SICK_COLA_COMMAND_ANSWER_sAN:
		dissect_sick_cola_answer_san(cola_a_tree, pinfo, command_tvb, false);
		break;
	case SICK_COLA_COMMAND_ANSWER_sEA:
		dissect_sick_cola_answer_sea(cola_a_tree, pinfo, command_tvb, false);
		break;
	case SICK_COLA_COMMAND_ANSWER_sSN:
		dissect_sick_cola_answer_ssn(cola_a_tree, pinfo, command_tvb, false);
		break;
	case SICK_COLA_COMMAND_ANSWER_sFA:
	case SICK_COLA_COMMAND_ANSWER_sFA_NULL:
		dissect_sick_cola_answer_sfa(cola_a_tree, pinfo, command_tvb, false);
		break;
	case SICK_COLA_COMMAND_SOPAS_ASCII:
		proto_tree_add_item(cola_a_tree, hf_sick_cola_a_sopas_command, tvb, offset-4, 4, ENC_ASCII);
		proto_tree_add_item(cola_a_tree, hf_sick_cola_a_sopas_command_data, tvb, offset, tvb_reported_length_remaining(tvb, offset)-1, ENC_NA);
		break;

	default:
		expert_add_info(pinfo, command_item, &ei_sick_cola_command);
		break;
	}

	proto_tree_add_item(cola_a_tree, hf_sick_cola_a_etx, tvb, etxp, 1, ENC_BIG_ENDIAN);

	return tvb_captured_length(tvb);
}

static bool
dissect_sick_cola_a_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	int etxp;

	if (tvb_captured_length(tvb) < SICK_COLA_A_MIN_LENGTH)
		return false;

	if (tvb_get_uint8(tvb, 0) != SICK_COLA_A_STX)
		return false;

        /* Try getting the command */
        uint32_t command = tvb_get_ntohl(tvb, 1);
        if (try_val_to_str(command, cola_command_vals) == NULL)
            return false;

	etxp = tvb_find_uint8(tvb, 1, -1, SICK_COLA_A_ETX);
	if (etxp == -1)
		return false;

	/* Ok, looks like a valid packet, go dissect. */
	dissect_sick_cola_a(tvb, pinfo, tree, data);
	return true;
}

void
proto_register_sick_cola(void)
{
	expert_module_t* expert_sick_cola;

	static hf_register_info hf[] = {
		{ &hf_sick_cola_b_magic_number,
			{ "Magic Number", "sick_cola.binary.magic_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_b_length,
			{ "Length", "sick_cola.binary.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_b_checksum,
			{ "Checksum", "sick_cola.binary.checksum", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_b_checksum_status,
			{ "CRC Status", "sick_cola.binary.checksum_status", FT_UINT8, BASE_NONE, &plugin_proto_checksum_vals, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_a_stx,
			{ "STX", "sick_cola.ascii.stx", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_a_etx,
			{ "ETX", "sick_cola.ascii.etx", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_command,
			{ "Command", "sick_cola.command", FT_UINT32, BASE_NONE, VALS(cola_command_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_method_name,
			{ "Method Name", "sick_cola.method_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_access_mode_user_level,
			{ "User level", "sick_cola.set_access_mode.user_level", FT_UINT8, BASE_DEC, VALS(access_mode_user_level_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_access_mode_password,
			{ "Password", "sick_cola.set_access_mode.password", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_access_mode_change_level,
			{ "Change level", "sick_cola.set_access_mode.change_level", FT_UINT8, BASE_DEC, VALS(sick_cola_return_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_answer_name,
			{ "Answer Name", "sick_cola.answer_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_scan_cfg_scan_frequency,
			{ "Scan Frequency", "sick_cola.set_scan_cfg.scan_frequency", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_hz), 0x0, NULL, HFILL}},
		{ &hf_sick_cola_set_scan_cfg_num_active_scanners,
			{ "Number of Active Scanners", "sick_cola.set_scan_cfg.num_active_scanners", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_scan_cfg_angular_resolution,
			{ "Angular resolution", "sick_cola.set_scan_cfg.angular_resolution", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_scan_cfg_start_angle,
			{ "Start angle", "sick_cola.set_scan_cfg.start_angle", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_scan_cfg_stop_angle,
			{ "Stop Angle", "sick_cola.set_scan_cfg.stop_angle", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_scan_cfg_status_code,
			{ "Status code", "sick_cola.set_scan_cfg.status_code", FT_UINT8, BASE_DEC, VALS(set_scan_cfg_status_code_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_read_name,
			{ "Read Command", "sick_cola.read_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_write_name,
			{ "Write Command", "sick_cola.write_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_mm_alignment_node_layer_activation,
			{ "Layer activation", "sick_cola.mm_alignment_node.layer_activation", FT_UINT8, BASE_DEC, VALS(layer_activation_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_scan_cfg_mode,
			{ "Mode", "sick_cola.set_scan_cfg.mode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_standby_status_code,
			{ "Status code", "sick_cola.standby.status_code", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_startmeas_status_code,
			{ "Status code", "sick_cola.startmeas.status_code", FT_UINT8, BASE_DEC, VALS(start_stop_measure_status_code_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stopmeas_status_code,
			{ "Status code", "sick_cola.stopmeas.status_code", FT_UINT8, BASE_DEC, VALS(start_stop_measure_status_code_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_autostartmeas_enable,
			{ "Autostart", "sick_cola.autostartmeas.enable", FT_UINT8, BASE_DEC, VALS(autostartmeas_enable_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_clapplication_mode,
			{ "Mode", "sick_cola.clapplication.mode", FT_UINT16, BASE_DEC, VALS(clapplication_mode_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_active_app_count,
			{ "Array length", "sick_cola.set_active_app.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_active_app_id,
			{ "Identifier", "sick_cola.set_active_app.id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_active_app_active,
			{ "Active", "sick_cola.set_active_app.active", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_password_user_level,
			{ "User level", "sick_cola.set_password.user_level", FT_UINT8, BASE_DEC, VALS(access_mode_user_level_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_password_hash,
			{ "Mode", "sick_cola.set_password.hash", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_password_status_code,
			{ "Status code", "sick_cola.set_password.status_code", FT_UINT8, BASE_DEC, VALS(sick_cola_return_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_check_password_user_level,
			{ "User level", "sick_cola.check_password.user_level", FT_UINT8, BASE_DEC, VALS(access_mode_user_level_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_check_password_hash,
			{ "Mode", "sick_cola.check_password.hash", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_check_password_status_code,
			{ "Status code", "sick_cola.check_password.status_code", FT_UINT8, BASE_DEC, VALS(sick_cola_return_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_lcm_cfg_strategy,
			{ "Strategy", "sick_cola.lcm_cfg.strategy", FT_UINT8, BASE_DEC, VALS(lcm_cfg_strategy_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_lcm_cfg_response_time,
			{ "Response Time", "sick_cola.lcm_cfg.response_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_lcm_cfg_threshold_warning,
			{ "Threshold Warning", "sick_cola.lcm_cfg.threshold_warning", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_lcm_cfg_threshold_error,
			{ "Threshold Error", "sick_cola.lcm_cfg.threshold_error", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_cm_cont_lvlm_availability,
			{ "Channel availability", "sick_cola.cm_cont_lvlm.availability", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_percent), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_ee_write_all_status_code,
			{ "Status code", "sick_cola.ee_write_all.status_code", FT_UINT8, BASE_DEC, VALS(sick_cola_return_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_run_status_code,
			{ "Status code", "sick_cola.run.status_code", FT_UINT8, BASE_DEC, VALS(sick_cola_return_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_cfg_data_channel,
			{ "Data channel", "sick_cola.scan_data_cfg.data_channel", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_cfg_remission,
			{ "Remission", "sick_cola.scan_data_cfg.remission", FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_cfg_resolution,
			{ "Remission", "sick_cola.scan_data_cfg.resolution", FT_UINT8, BASE_DEC, VALS(sick_cola_resolution_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_cfg_unit,
			{ "Unit (digits)", "sick_cola.scan_data_cfg.unit", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_cfg_encoder,
			{ "Encoder", "sick_cola.scan_data_cfg.encoder", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_cfg_position,
			{ "Position", "sick_cola.scan_data_cfg.position", FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_cfg_device_name,
			{ "Device name", "sick_cola.scan_data_cfg.device_name", FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_cfg_comment,
			{ "Comment", "sick_cola.scan_data_cfg.comment", FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_cfg_time,
			{ "Time", "sick_cola.scan_data_cfg.time", FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_cfg_output_rate,
			{ "Output rate", "sick_cola.scan_data_cfg.output_rate", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_change_output_range_status_code,
			{ "Status code", "sick_cola.change_output_range.status_code", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_change_output_range_angular_resolution,
			{ "Angular resolution", "sick_cola.change_output_range.angular_resolution", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_change_output_range_start_angle,
			{ "Start angle", "sick_cola.change_output_range.start_angle", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_change_output_range_stop,
			{ "Stop Angle", "sick_cola.change_output_range.stop_angle", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_range_num_sectors,
			{ "Number of sectors", "sick_cola.output_range.num_sectors", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_range_angular_resolution,
			{ "Angular resolution", "sick_cola.output_range.angular_resolution", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_range_start_angle,
			{ "Start angle", "sick_cola.output_range.start_angle", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_range_stop,
			{ "Stop Angle", "sick_cola.output_range.stop_angle", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_event_name,
			{ "Event", "sick_cola.event_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_start_stop,
			{ "Start/Stop", "sick_cola.scan_data.start_stop", FT_UINT8, BASE_DEC, VALS(sick_cola_stop_start_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_version,
			{ "Version", "sick_cola.scan_data.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_device_number,
			{ "Device Number", "sick_cola.scan_data.device_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_serial_number,
			{ "Serial Number", "sick_cola.scan_data.serial_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_device_status,
			{ "Device Status", "sick_cola.scan_data.device_status", FT_UINT16, BASE_DEC, VALS(sick_cola_device_status_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_telegram_counter,
			{ "Telegram Counter", "sick_cola.scan_data.telegram_counter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_scan_counter,
			{ "Scan Counter", "sick_cola.scan_data.scan_counter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_time_since_startup,
			{ "Time since startup", "sick_cola.scan_data.time_since_startup", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_microseconds), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_transmission_time,
			{ "Transmission Time", "sick_cola.scan_data.transmission_time", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_microseconds), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_di_status,
			{ "Digital Input Status", "sick_cola.scan_data.di_status", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_do_status,
			{ "Digital Output Status", "sick_cola.scan_data.do_status", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_layer_angle,
			{ "Layer Angle", "sick_cola.scan_data.layer_angle", FT_INT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_scan_frequency,
			{ "Frequency", "sick_cola.scan_data.frequency", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_measurement_frequency,
			{ "Measurement Frequency", "sick_cola.scan_data.measurement_frequency", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_encoder_amount,
			{ "Amount of encoder", "sick_cola.scan_data.encoder_amount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_encoder_position,
			{ "Encoder Position", "sick_cola.scan_data.encoder_position", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_tick_ticks), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_encoder_speed,
			{ "Encoder Speed", "sick_cola.scan_data.encoder_speed", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&sick_cola_units_ticks_mm), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_num_16bit_channels,
			{ "Number of 16-bit channels", "sick_cola.scan_data.num_16bit_channels", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_output_channel_content,
			{ "Content", "sick_cola.scan_data.output_channel.content", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_output_channel_scale_factor,
			{ "Scale Factor", "sick_cola.scan_data.output_channel.scale_factor", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_output_channel_scale_factor_offset,
			{ "Scale Factor Offset", "sick_cola.scan_data.output_channel.scale_factor_offset", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_output_channel_start_angle,
			{ "Start angle", "sick_cola.scan_data.output_channel.start_angle", FT_INT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL}},
		{ &hf_sick_cola_scan_data_output_channel_size_single_angular_step,
			{ "Size of single angular step", "sick_cola.scan_data.output_channel.size_single_angular_step", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_degrees), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_num_data_points,
			{ "Number of data points", "sick_cola.scan_data.num_data_points", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_16bit_output_channel_data,
			{ "16-bit data", "sick_cola.scan_data.output_channel.16bit_data", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_8bit_output_channel_data,
			{ "8-bit data", "sick_cola.scan_data.output_channel.8bit_data", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_num_8bit_channels,
			{ "Number of 8-bit channels", "sick_cola.scan_data.num_8bit_channels", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_position_present,
			{ "Position Present", "sick_cola.scan_data.position_present", FT_UINT16, BASE_DEC, VALS(sick_cola_position_present_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_position_x,
			{ "X Position", "sick_cola.scan_data.position_x", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_position_y,
			{ "Y Position", "sick_cola.scan_data.position_y", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_position_z,
			{ "Z Position", "sick_cola.scan_data.position_z", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_rotation_x,
			{ "X Rotation", "sick_cola.scan_data.rotation_x", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_rotation_y,
			{ "Y Rotation", "sick_cola.scan_data.rotation_y", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_rotation_z,
			{ "Z Rotation", "sick_cola.scan_data.rotation_z", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_rotation_type,
			{ "Rotation Type", "sick_cola.scan_data.rotation_type", FT_UINT16, BASE_DEC, VALS(sick_cola_rotation_type_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_transmit_device_name,
			{ "Transmit Device Name", "sick_cola.scan_data.transmit_device_name", FT_UINT16, BASE_DEC, VALS(sick_cola_name_present_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_device_name_present,
			{ "Device Name Present", "sick_cola.scan_data.device_name_present", FT_UINT16, BASE_DEC, VALS(sick_cola_name_present_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_device_name,
			{ "Device Name", "sick_cola.scan_data.device_name", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_comment_present,
			{ "Comment Present", "sick_cola.scan_data.comment_present", FT_UINT16, BASE_DEC, VALS(sick_cola_comment_present_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_comment,
			{ "Comment", "sick_cola.scan_data.comment", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_time_present,
			{ "Time Present", "sick_cola.scan_data.time_present", FT_UINT16, BASE_DEC, VALS(sick_cola_time_present_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_time,
			{ "Time", "sick_cola.scan_data.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_display_event_info,
			{ "Display Event Information", "sick_cola.scan_data.display_event_info", FT_UINT16, BASE_DEC, VALS(sick_cola_display_event_info_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_event_info_type,
			{ "Type", "sick_cola.scan_data.event_info.type", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_event_info_encoder_position,
			{ "Encoder Position", "sick_cola.scan_data.event_info.encoder_position", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_event_info_encosder_timestamp,
			{ "Timestamp", "sick_cola.scan_data.event_info.timestamp", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_microseconds), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_scan_data_event_info_encoder_angle,
			{ "Encoder Angle", "sick_cola.scan_data.event_info.encoder_angle", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_date_time,
			{ "Set timestamp", "sick_cola.set_date_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_date_time_status_code,
			{ "Status code", "sick_cola.set_date_time.status_code", FT_UINT8, BASE_DEC, VALS(sick_cola_return_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stims_status_code,
			{ "Status code", "sick_cola.stims.status_code", FT_UINT16, BASE_DEC, VALS(stims_status_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stims_temp_out_of_range,
			{ "Temperature out of range", "sick_cola.stims.temp_out_of_range", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stims_time_length,
			{ "Time length", "sick_cola.stims.time_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stims_time,
			{ "Time", "sick_cola.stims.time", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stims_date_length,
			{ "Date length", "sick_cola.stims.date_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stims_date,
			{ "Date", "sick_cola.stims.date", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stims_led1,
			{ "LED1", "sick_cola.stims.led1", FT_UINT16, BASE_DEC, VALS(sick_cola_led_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stims_led2,
			{ "LED2", "sick_cola.stims.led2", FT_UINT16, BASE_DEC, VALS(sick_cola_led_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stims_led3,
			{ "LED3", "sick_cola.stims.led3", FT_UINT16, BASE_DEC, VALS(sick_cola_led_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_stims_reserved,
			{ "Reserved", "sick_cola.stims.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_device_time,
			{ "Device time", "sick_cola.device_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_ntp_tsc_role,
			{ "TSC Role", "sick_cola.ntp.tsc_role", FT_UINT8, BASE_DEC, VALS(ntp_tsc_role_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_ntp_interface_data,
			{ "Timesync interface", "sick_cola.ntp.interface_data", FT_UINT8, BASE_DEC, VALS(ntp_interface_data_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_ntp_ipaddress,
			{ "NTP IP address", "sick_cola.ntp.ipaddress", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_ntp_gmt_timezone_offset,
			{ "GMT Timezone offset", "sick_cola.ntp.gmt_timezone_offset", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_ntp_timesync,
			{ "Timesync", "sick_cola.ntp.timesync", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_seconds), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_ntp_max_offset_time,
			{ "Max offset Time", "sick_cola.ntp.max_offset_time", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_particle_filter_status,
			{ "Status code", "sick_cola.particle_filter.status", FT_BOOLEAN, BASE_NONE, TFS(&tfs_active_inactive), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_particle_filter_threshold,
			{ "Filter Threshold", "sick_cola.particle_filter.threshold", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_mean_filter_status,
			{ "Status code", "sick_cola.mean_filter.status", FT_BOOLEAN, BASE_NONE, TFS(&tfs_active_inactive), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_mean_filter_num_scans,
			{ "Number of scans", "sick_cola.mean_filter.num_scans", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_mean_filter_final_part,
			{ "Final part", "sick_cola.mean_filter.final_part", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_nto1_filter_status,
			{ "Status code", "sick_cola.nto1_filter.status", FT_BOOLEAN, BASE_NONE, TFS(&tfs_active_inactive), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_echo_filter_status,
			{ "Status code", "sick_cola.echo_filter.status", FT_UINT8, BASE_DEC, VALS(echo_filter_status_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_fog_filter_status,
			{ "Status code", "sick_cola.fog_filter.status", FT_UINT8, BASE_DEC, VALS(fog_filter_status_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_fog_filter_enable,
			{ "Enable", "sick_cola.fog_filter.enable", FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_fog_filter_sensitivity_level,
			{ "Sensitivity Level", "sick_cola.fog_filter.sensitivity_level", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_digital_nearfield_filter_status,
			{ "Status code", "sick_cola.digital_nearfield_filter.status", FT_UINT8, BASE_DEC, VALS(fog_filter_status_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_digital_nearfield_filter_active_sector_vector,
			{ "Active sector vector", "sick_cola.digital_nearfield_filter.active_sector_vector", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_encoder_increment_source,
			{ "Increment Source", "sick_cola.encoder.increment_source", FT_UINT8, BASE_DEC, VALS(encoder_increment_source_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_encoder_setting,
			{ "Encoder Setting", "sick_cola.encoder.setting", FT_UINT8, BASE_DEC, VALS(encoder_setting_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_encoder_resolution,
			{ "Encoder resolution", "sick_cola.encoder.resolution", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_encoder_fixed_speed,
			{ "Fixed speed", "sick_cola.encoder.fixed_speed", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_encoder_speed_threshold,
			{ "Speed Threshold", "sick_cola.encoder.speed_threshold", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_percent), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_encoder_speed,
			{ "Encoder Speed", "sick_cola.encoder.speed", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_m_s), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_state_start_stop,
			{ "Start/Stop", "sick_cola.output_state.start_stop", FT_UINT8, BASE_DEC, VALS(sick_cola_stop_start_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_state_status_version,
			{ "Number of scans", "sick_cola.output_state.status.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_state_status_system_counter,
			{ "Number of scans", "sick_cola.output_state.status.system_counter", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_microseconds), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_state_state,
			{ "State", "sick_cola.output_state.state", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_state_count,
			{ "Count", "sick_cola.output_state.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_state_ext_state,
			{ "State", "sick_cola.output_state.ext_state", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_state_ext_count,
			{ "Count", "sick_cola.output_state.ext_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_state_time_present,
			{ "Time Present", "sick_cola.output_state.time_present", FT_UINT16, BASE_DEC, VALS(sick_cola_time_present_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_state_time,
			{ "Time", "sick_cola.output_state.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_output_state_number,
			{ "Output number", "sick_cola.set_output_state.number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_output_state_state,
			{ "Output state", "sick_cola.set_output_state.state", FT_BOOLEAN, BASE_NONE, TFS(&tfs_active_inactive), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_set_output_state_status_code,
			{ "Status code", "sick_cola.set_output_state.status_code", FT_UINT8, BASE_DEC, VALS(sick_cola_return_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_do3_func,
			{ "Output state", "sick_cola.output.do3_func", FT_UINT8, BASE_DEC, VALS(sick_cola_do3_func_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_do1_func,
			{ "Output 1 function", "sick_cola.output.do1_func", FT_UINT8, BASE_DEC, VALS(sick_cola_do1_func_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_do1_logic,
			{ "Output 1 Logic State", "sick_cola.output.do1_logic", FT_UINT32, BASE_DEC, VALS(sick_cola_logic_state_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_do2_func,
			{ "Output 2 function", "sick_cola.output.do2_func", FT_UINT8, BASE_DEC, VALS(sick_cola_do2_func_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_do2_logic,
			{ "Output 2 Logic State", "sick_cola.output.do2_logic", FT_UINT32, BASE_DEC, VALS(sick_cola_logic_state_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_sync_mode_data,
			{ "Sync mode data", "sick_cola.output.sync_mode_data", FT_UINT8, BASE_DEC, VALS(sick_cola_sync_mode_data_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_output_sync_phase_data,
			{ "Sync phase data", "sick_cola.output.sync_phase_data", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_input_do3and4_func,
			{ "Input state", "sick_cola.input.do3and4_func", FT_UINT8, BASE_DEC, VALS(sick_cola_do3and4_func_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_input_debounce_time_data,
			{ "Debounce time data", "sick_cola.input.debounce_time_data", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_input_sync_status_data,
			{ "Sync Status data", "sick_cola.input.sync_status_data", FT_UINT8, BASE_DEC, VALS(sick_cola_sync_status_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola_input_signal_frequency,
			{ "Signal frequency", "sick_cola.input.signal_frequency", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_b_sopas_command,
			{ "SICK Command", "sick_cola.binary.sick_command", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_b_sopas_command_data,
			{ "Command Data", "sick_cola.binary.sick_command_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_a_sopas_command,
			{ "SICK Command", "sick_cola.ascii.sick_command", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_a_sopas_command_data,
			{ "Command Data", "sick_cola.ascii.sick_command_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola_sopas_error_code,
			{ "Error code", "sick_cola.sopas_error_code", FT_UINT32, BASE_DEC, VALS(sick_cola_sopas_error_vals), 0x0, NULL, HFILL } },
	};

	static int *ett[] = {
		&ett_sick_cola_a,
		&ett_sick_cola_b,
		&ett_scan_data_device,
		&ett_scan_data_status_info,
		&ett_scan_data_frequency,
		&ett_scan_data_16bit_output_channels,
		&ett_scan_data_16bit_output_channel,
		&ett_scan_data_16bit_output_data,
		&ett_scan_data_8bit_output_channels,
		&ett_scan_data_8bit_output_channel,
		&ett_scan_data_8bit_output_data,
		&ett_scan_data_position,
		&ett_scan_data_time,
		&ett_scan_data_event_info,
		&ett_output_state_status,
		&ett_output_state,
		&ett_output_state_x,
		&ett_ext_output_state,
		&ett_ext_output_state_x,
		&ett_output_state_time,
	};

	static ei_register_info ei[] = {
		{ &ei_sick_cola_command, { "sick_cola.command.unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
		{ &ei_sick_cola_command_name, { "sick_cola.command.name.missing", PI_MALFORMED, PI_ERROR, "Command name missing", EXPFILL }},
		{ &ei_sick_cola_command_parameter, { "sick_cola.command.parameter.error", PI_MALFORMED, PI_ERROR, "Command parameter parse error", EXPFILL }},
		{ &ei_sick_cola_b_checksum, { "sick_cola.binary.checksum.incorrect", PI_PROTOCOL, PI_WARN, "Checksum incorrect", EXPFILL }},
	};

	proto_sick_cola_a = proto_register_protocol("SICK CoLA A", "CoLA A", "sick_cola.ascii");
	proto_sick_cola_b = proto_register_protocol("SICK CoLA B", "CoLA B", "sick_cola.binary");

	proto_register_field_array(proto_sick_cola_a, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_sick_cola = expert_register_protocol(proto_sick_cola_a);
	expert_register_field_array(expert_sick_cola, ei, array_length(ei));

}

void
proto_reg_handoff_sick_cola(void)
{
	dissector_handle_t cola_a_handle, cola_b_handle;

	cola_a_handle = create_dissector_handle(dissect_sick_cola_a, proto_sick_cola_a);
	dissector_add_for_decode_as("tcp.port", cola_a_handle);
	cola_b_handle = create_dissector_handle(dissect_sick_cola_b, proto_sick_cola_b);
	dissector_add_for_decode_as("tcp.port", cola_b_handle);

	heur_dissector_add("tcp", dissect_sick_cola_b_heur, "SICK CoLa B over TCP", "sick_cola_b_tcp", proto_sick_cola_b, HEURISTIC_ENABLE);
	heur_dissector_add("tcp", dissect_sick_cola_a_heur, "SICK CoLa A over TCP", "sick_cola_a_tcp", proto_sick_cola_a, HEURISTIC_ENABLE);

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
