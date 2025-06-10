/* packet-navitrol.c
 * Routines for Navitec Systems Navitrol device
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/unit_strings.h>
#include <epan/dissectors/packet-tcp.h>
#include <stdlib.h>

void proto_register_navitrol(void);
void proto_reg_handoff_navitrol(void);

static int proto_navitrol;

static int hf_navitrol_protocol_version;
static int hf_navitrol_message_id;
static int hf_navitrol_message_length;
static int hf_navitrol_measurement_mode;
static int hf_navitrol_ip_address;
static int hf_navitrol_port_front;
static int hf_navitrol_port_rear;
static int hf_navitrol_raw_data_status;
static int hf_navitrol_position_x;
static int hf_navitrol_position_y;
static int hf_navitrol_position_x_double;
static int hf_navitrol_position_y_double;
static int hf_navitrol_position_heading;
static int hf_navitrol_floor;
static int hf_navitrol_teaching_command;
static int hf_navitrol_error_code;
static int hf_navitrol_error_count;
static int hf_navitrol_message_number;
static int hf_navitrol_cum_s_long;
static int hf_navitrol_cum_s_trans;
static int hf_navitrol_raw_heading;
static int hf_navitrol_timestamp;
static int hf_navitrol_position_initialize_status;
static int hf_navitrol_position_confidence;
static int hf_navitrol_error_description;
static int hf_navitrol_saved_log_number;
static int hf_navitrol_software_version;
static int hf_navitrol_comm_version;
static int hf_navitrol_time_set_status;
static int hf_navitrol_position_correction_status;
static int hf_navitrol_set_time;
static int hf_navitrol_vel_long;
static int hf_navitrol_vel_trans;
static int hf_navitrol_vel_angular;
static int hf_navitrol_cum_s_left;
static int hf_navitrol_cum_s_right;
static int hf_navitrol_driving_enabled;
static int hf_navitrol_read_status;
static int hf_navitrol_speed_left;
static int hf_navitrol_speed_right;
static int hf_navitrol_errors_stopping_driving;
static int hf_navitrol_start_stop_mode;
static int hf_navitrol_clear_log;
static int hf_navitrol_log_save_length;
static int hf_navitrol_raw_ds;
static int hf_navitrol_raw_dh;
static int hf_navitrol_position_confidence_float;
static int hf_navitrol_floor_changed_status;


static int ett_navitrol;

static expert_field ei_navitrol_message_id;

/* Preference for endianness */
static unsigned navitrol_endian = ENC_LITTLE_ENDIAN;

static const enum_val_t navitrol_endian_vals[] = {
	{ "little_endian", "Little Endian",	ENC_LITTLE_ENDIAN},
	{ "big_endian",	 "Big Endian", ENC_BIG_ENDIAN },
	{ NULL, NULL, 0 }
};

enum navitrol_message_types
{
	//requests
	nav_InitializePosition_v1 = 1,
	nav_GetPositionCorrection = 2,
	nav_ChangeFloor = 3,
	nav_ToggleTeaching_v1 = 4,
	nav_ErrorDescriptionRes_v1 = 5,
	nav_ErrorDescriptionListReq_v1 = 6,
	nav_StartStopClearSaveLog = 7,
	nav_ReadEnvironmentFile_v1 = 8,
	nav_StartSendRawData = 9,
	nav_StopSendRawData = 10,
	nav_GetVersion_v1 = 11,
	nav_RebootNavitrol_v1 = 12,
	nav_SetTime_v1 = 13,
	nav_GetPositionCorrectionOdometry = 14,
	nav_InitializePosition = 1001,
	nav_ToggleTeaching = 1004,
	nav_ErrorDescriptionReq = 1005,
	nav_ErrorDescriptionListReq = 1006,
	nav_SaveLog = 1007,
	nav_ReadEnvironmentFile = 1008,
	nav_GetVersion = 1011,
	nav_RebootNavitrol = 1012,
	nav_SetTime = 1013,
	nav_PositionCorrectionCumulative = 1014,
	nav_PositionCorrectionVelocity = 1015,
	nav_OdometerUpdateDifferentialVehicle = 1016,

	//responses
	nav_PositionInitialized_v1 = 101,
	nav_PositionCorrection_v1_deprecated = 102,
	nav_FloorChanged = 103,
	nav_TeachingToggled_v1 = 104,
	nav_SendRawDataStarted = 109,
	nav_SendRawDataStopped = 110,
	nav_PositionCorrection_v1 = 114,
	nav_PositionInitialized = 1101,
	nav_TeachingToggled = 1104,
	nav_ErrorDescriptionRes = 1105,
	nav_ErrorDescriptionListRes = 1106,
	nav_LogSaved = 1107,
	nav_EnvironmentFileRead = 1108,
	nav_Version = 1111,
	nav_RebootedNavitrol = 1112,
	nav_TimeSet = 1113,
	nav_PositionCorrection = 1114,
	nav_MotorControlDifferentialVehicle = 1116,
	nav_Error = 201,
};

static const value_string message_id_vals[] = {
	{ nav_InitializePosition_v1,	"Initialize position" },
	{ nav_GetPositionCorrection,	"Get position correction" },
	{ nav_ChangeFloor,	"Change floor" },
	{ nav_ToggleTeaching_v1,	"Start/Stop teaching" },
	{ nav_ErrorDescriptionRes_v1,	"Request error description" },
	{ nav_ErrorDescriptionListReq_v1, "Error description list" },
	{ nav_StartStopClearSaveLog, "Start/Stop/Clear/Save log" },
	{ nav_StartSendRawData,	"Start sending scanner measurements" },
	{ nav_StopSendRawData,	"Stop sending scanner measurements" },
	{ nav_GetVersion_v1,	"Request versions" },
	{ nav_RebootNavitrol_v1,	"Reboot Navitrol" },
	{ nav_SetTime_v1,	"Set time" },
	{ nav_GetPositionCorrectionOdometry,	"Get position correction including raw odometry" },
	{ nav_PositionInitialized_v1,	"Initialize position" },
	{ nav_PositionCorrection_v1_deprecated,	"Position correction" },
	{ nav_FloorChanged,	"Floor changed" },
	{ nav_TeachingToggled_v1,	"Teaching started/stopped" },
	{ nav_SendRawDataStarted,	"Scanner measurements started" },
	{ nav_SendRawDataStopped,	"Scanner measurements stopped" },
	{ nav_PositionCorrection_v1,	"Position correction" },
	{ nav_Error,	"Error message" },
	{ nav_InitializePosition,	"Initialize position" },
	{ nav_ToggleTeaching,	"Teaching" },
	{ nav_ErrorDescriptionReq,	"Request error description" },
	{ nav_ErrorDescriptionListReq,	"Request error description list" },
	{ nav_SaveLog,	"Save log" },
	{ nav_ReadEnvironmentFile,	"Read environment file" },
	{ nav_GetVersion,	"Request versions" },
	{ nav_RebootNavitrol,	"Reboot Navitrol" },
	{ nav_SetTime,	"Set time" },
	{ nav_PositionCorrectionCumulative,	"Get position correction - cumulative" },
	{ nav_PositionCorrectionVelocity,	"Get position correction - velocity" },
	{ nav_OdometerUpdateDifferentialVehicle, "Odometer update differential vehicle (Navitrol controls the vehicle)" },
	{ nav_PositionInitialized,	"Position initialized" },
	{ nav_TeachingToggled,	"Teaching toggled" },
	{ nav_ErrorDescriptionRes,	"Error description" },
	{ nav_ErrorDescriptionListRes, "Error description list" },
	{ nav_LogSaved,	"Log saved" },
	{ nav_EnvironmentFileRead,	"Environment file read" },
	{ nav_Version,	"Version Info" },
	{ nav_RebootedNavitrol,	"Navitrol rebooted" },
	{ nav_TimeSet,	"Time set" },
	{ nav_PositionCorrection,	"Position correction" },
	{ nav_MotorControlDifferentialVehicle,	"Motor control differential vehicle" },

	{ 0,		NULL }
};

static const value_string mesasurement_mode_vals[] = {
	{ 0, "Off" },
	{ 1, "Both scanners" },
	{ 2, "Front scanner" },
	{ 3, "Rear scanner" },
	{ 0, NULL }
};

static const value_string status_vals[] = {
	{ 0, "Failed" },
	{ 1, "Succeeded" },
	{ 0, NULL }
};

static const value_string position_correction_status_vals[] = {
	{ 0, "Failed" },
	{ 1, "Succeeded" },
	{ 2, "Teaching" },
	{ 0, NULL }
};

static const value_string teaching_vals[] = {
	{ 0, "Invalid" },
	{ 1, "Start teaching" },
	{ 2, "Stop teaching" },
	{ 0, NULL }
};

static const value_string driving_status_vals[] = {
	{ 0, "Invalid" },
	{ 1, "Enabled" },
	{ 2, "Disabled error active" },
	{ 3, "Disabled manual mode" },
	{ 4, "Disabled ESTOP" },
	{ 0, NULL }
};

static const value_string error_driving_vals[] = {
	{ 0, "No Errors" },
	{ 1, "Error stopping driving" },
	{ 0, NULL }
};

static const value_string start_stop_log_mode_vals[] = {
	{ 0, "Stop logging" },
	{ 1, "Start/continue logging" },
	{ 0, NULL }
};

static const value_string clear_log_vals[] = {
	{ 0, "Do Nothing" },
	{ 1, "Clear log" },
	{ 0, NULL }
};

static unsigned
get_navitrol_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	uint16_t len;

	/* Get the length of the data from the header. */
	len = tvb_get_uint32(tvb, offset + 4, navitrol_endian);

	return len;
}

static int
dissect_navitrol_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree      *navitrol_tree;
	proto_item      *ti, *message_item;
	int				offset = 0;
	uint32_t			i, message_id, error_count;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "navitrol");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_navitrol, tvb, 0, -1, ENC_NA);
	navitrol_tree = proto_item_add_subtree(ti, ett_navitrol);

	message_id = tvb_get_uint32(tvb, offset, navitrol_endian);
	if (message_id & 0xFFFF0000)
	{
		proto_tree_add_item(navitrol_tree, hf_navitrol_protocol_version, tvb, offset, 2, navitrol_endian);
		offset += 2;
		message_item = proto_tree_add_item(navitrol_tree, hf_navitrol_message_id, tvb, offset, 2, navitrol_endian);
		offset += 2;
		message_id = ((message_id >> 16) & 0xFFFF);
	}
	else
	{
		proto_tree_add_uint(navitrol_tree, hf_navitrol_protocol_version, tvb, offset, 0, 1);
		message_item = proto_tree_add_item(navitrol_tree, hf_navitrol_message_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
	}

	col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_id, message_id_vals, "Unknown"));

	proto_tree_add_item(navitrol_tree, hf_navitrol_message_length, tvb, offset, 4, navitrol_endian);
	offset += 4;

	switch (message_id)
	{
	case nav_InitializePosition_v1: //Initialize position v1
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_x_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_y_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_heading, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case nav_GetPositionCorrection:	//Get position correction v1
		proto_tree_add_item(navitrol_tree, hf_navitrol_message_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_x_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_y_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_heading, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case nav_GetPositionCorrectionOdometry:	//Get position correction with raw odometry v1
		proto_tree_add_item(navitrol_tree, hf_navitrol_message_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_x_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_y_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_heading, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_raw_ds, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_raw_dh, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case nav_ChangeFloor:		//Change floor v1
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case nav_FloorChanged:		//Floor changed v1
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor_changed_status, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case nav_StartStopClearSaveLog:
		proto_tree_add_item(navitrol_tree, hf_navitrol_start_stop_mode, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(navitrol_tree, hf_navitrol_clear_log, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(navitrol_tree, hf_navitrol_log_save_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case nav_StartSendRawData:	//Start sending scanner measurements v1
		proto_tree_add_item(navitrol_tree, hf_navitrol_measurement_mode, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(navitrol_tree, hf_navitrol_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_port_front, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_port_rear, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case nav_SendRawDataStarted:	//Scanner measurement sending started v1
		proto_tree_add_item(navitrol_tree, hf_navitrol_raw_data_status, tvb, offset, 1, ENC_NA);
		/* offset += 1; */
		break;

	case nav_InitializePosition:	//Initialize position v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_x, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_y, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_heading, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, navitrol_endian);
		/* offset += 4; */
		break;

	case nav_ToggleTeaching_v1:	//Start/Stop teaching v1
	case nav_ToggleTeaching:	//Start/Stop teaching v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_teaching_command, tvb, offset, 2, navitrol_endian);
		/* offset += 2; */
		break;

	case nav_ErrorDescriptionRes_v1: //Request error description v1
	case nav_ErrorDescriptionReq:	//Request error description v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_error_code, tvb, offset, 4, navitrol_endian);
		/* offset += 4; */
		break;

	case nav_SetTime_v1:	//Set time v1
		{
			int start_offset = offset;
			struct tm tm_set_time;
			time_t set_time_seconds;
			nstime_t ns_set_time;

			tm_set_time.tm_sec = tvb_get_uint8(tvb, offset);
			offset += 1;
			tm_set_time.tm_min = tvb_get_uint8(tvb, offset);
			offset += 1;
			tm_set_time.tm_hour = tvb_get_uint8(tvb, offset);
			offset += 1;
			tm_set_time.tm_mday = tvb_get_uint8(tvb, offset);
			offset += 1;
			tm_set_time.tm_mon = tvb_get_uint8(tvb, offset);
			offset += 1;
			tm_set_time.tm_year = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN)-1900;
			/* offset += 4; */

			set_time_seconds = mktime(&tm_set_time);
			ns_set_time.secs = set_time_seconds;
			ns_set_time.nsecs = 0;
			proto_tree_add_time(navitrol_tree, hf_navitrol_set_time, tvb, start_offset,
				9, &ns_set_time);

		}
		break;

	case nav_SetTime:	//Set time v3
		{
			int start_offset = offset;
			struct tm tm_set_time;
			time_t set_time_seconds;
			nstime_t ns_set_time;

			tm_set_time.tm_year = tvb_get_uint32(tvb, offset, navitrol_endian)-1900;
			offset += 4;
			tm_set_time.tm_mon = tvb_get_uint16(tvb, offset, navitrol_endian);
			offset += 2;
			tm_set_time.tm_mday = tvb_get_uint16(tvb, offset, navitrol_endian);
			offset += 2;
			tm_set_time.tm_hour = tvb_get_uint16(tvb, offset, navitrol_endian);
			offset += 2;
			tm_set_time.tm_min = tvb_get_uint16(tvb, offset, navitrol_endian);
			offset += 2;
			tm_set_time.tm_sec = tvb_get_uint16(tvb, offset, navitrol_endian);
			/* offset += 2; */
			tm_set_time.tm_isdst = -1;

			set_time_seconds = mktime(&tm_set_time);
			ns_set_time.secs = set_time_seconds;
			ns_set_time.nsecs = 0;
			proto_tree_add_time(navitrol_tree, hf_navitrol_set_time, tvb, start_offset,
				14, &ns_set_time);

		}
		break;

	case nav_PositionCorrection_v1:
	case nav_PositionCorrection_v1_deprecated:
		proto_tree_add_item(navitrol_tree, hf_navitrol_message_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_correction_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_x_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_y_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_heading, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_confidence_float, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case nav_PositionCorrectionCumulative:	//Get position correction - cumulative v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_message_number, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_x, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_y, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_heading, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_cum_s_long, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_cum_s_trans, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_raw_heading, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_timestamp, tvb, offset, 4, navitrol_endian);
		/* offset += 4; */
		break;

	case nav_PositionCorrectionVelocity:	//Get position correction - velocity v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_message_number, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_x, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_y, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_heading, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_vel_long, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_vel_trans, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_vel_angular, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_timestamp, tvb, offset, 4, navitrol_endian);
		/* offset += 4; */
		break;

	case nav_OdometerUpdateDifferentialVehicle:
		proto_tree_add_item(navitrol_tree, hf_navitrol_message_number, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_cum_s_left, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_cum_s_right, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_driving_enabled, tvb, offset, 2, navitrol_endian);
		offset += 2;
		proto_tree_add_item(navitrol_tree, hf_navitrol_timestamp, tvb, offset, 4, navitrol_endian);
		/* offset += 4; */
		break;

	case nav_PositionInitialized_v1: //Position Initialized v1
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_initialize_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_x_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_y_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_heading, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_confidence_float, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case nav_PositionInitialized: //Position Initialized v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_x, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_y, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_heading, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_initialize_status, tvb, offset, 2, navitrol_endian);
		offset += 2;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_confidence, tvb, offset, 2, navitrol_endian);
		/* offset += 2; */
		break;

	case nav_TeachingToggled_v1:	//Teaching response v1
		proto_tree_add_item(navitrol_tree, hf_navitrol_teaching_command, tvb, offset, 1, ENC_NA);
		/* offset += 1; */
		break;

	case nav_TeachingToggled:	//Teaching response v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_teaching_command, tvb, offset, 2, navitrol_endian);
		/* offset += 2; */
		break;

	case nav_ErrorDescriptionRes: // Error description response v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_error_code, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_error_description, tvb, offset, 200, ENC_ASCII);
		/* offset += 200; */
		break;

	case nav_ErrorDescriptionListRes:  // Error description response v3
		proto_tree_add_item_ret_uint(navitrol_tree, hf_navitrol_error_count, tvb, offset, 4, navitrol_endian, &error_count);
		offset += 4;
		for (i = 0; i < error_count; i++)
		{
			proto_tree_add_item(navitrol_tree, hf_navitrol_error_code, tvb, offset, 4, navitrol_endian);
			offset += 4;
		}
		for (i = 0; i < error_count; i++)
		{
			proto_tree_add_item(navitrol_tree, hf_navitrol_error_description, tvb, offset, 200, ENC_ASCII);
			offset += 200;
		}
		break;

	case nav_LogSaved:			//Log saved v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_saved_log_number, tvb, offset, 4, navitrol_endian);
		/* offset += 4; */
		break;

	case nav_EnvironmentFileRead:	//Environment file read v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_read_status, tvb, offset, 2, navitrol_endian);
		/* offset += 2; */
		break;

	case nav_Version:			//Version information v3
	{
		proto_tree_add_item(navitrol_tree, hf_navitrol_software_version, tvb, offset, 4, navitrol_endian);
		offset += 4;
		uint32_t version = tvb_get_uint32(tvb, offset, navitrol_endian) / 10000;
		proto_tree_add_uint(navitrol_tree, hf_navitrol_comm_version, tvb, offset, 4, version);
		/* offset += 4; */
		break;
	}

	case nav_TimeSet:		//Time set v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_time_set_status, tvb, offset, 2, navitrol_endian);
		/* offset += 2; */
		break;

	case nav_PositionCorrection:	//Position correction v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_message_number, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_x, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_y, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_heading, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_floor, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_correction_status, tvb, offset, 2, navitrol_endian);
		offset += 2;
		proto_tree_add_item(navitrol_tree, hf_navitrol_position_confidence, tvb, offset, 2, navitrol_endian);
		/* offset += 2; */
		break;

	case nav_MotorControlDifferentialVehicle:	//Motor control differential vehicle v3
		proto_tree_add_item(navitrol_tree, hf_navitrol_message_number, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_speed_left, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_speed_right, tvb, offset, 4, navitrol_endian);
		offset += 4;
		proto_tree_add_item(navitrol_tree, hf_navitrol_errors_stopping_driving, tvb, offset, 2, navitrol_endian);
		/* offset += 2; */
		break;

	case nav_Error:		//Error message
		proto_tree_add_item_ret_uint(navitrol_tree, hf_navitrol_error_count, tvb, offset, 4, navitrol_endian, &error_count);
		offset += 4;
		for (i = 0; i < error_count; i++)
		{
			proto_tree_add_item(navitrol_tree, hf_navitrol_error_code, tvb, offset, 4, navitrol_endian);
			offset += 4;
		}
		break;

	//Commands that have no data
	case nav_ErrorDescriptionListReq:
	case nav_ErrorDescriptionListReq_v1:
	case nav_ReadEnvironmentFile:
	case nav_ReadEnvironmentFile_v1:
	case nav_RebootedNavitrol:
	case nav_StopSendRawData:
	case nav_SendRawDataStopped:
	case nav_SaveLog:
	case nav_GetVersion:
	case nav_GetVersion_v1:
	case nav_RebootNavitrol:
	case nav_RebootNavitrol_v1:
		break;
	default:
		expert_add_info(pinfo, message_item, &ei_navitrol_message_id);
		break;
	}

	return tvb_captured_length(tvb);
}

static int
dissect_navitrol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, true, 8, get_navitrol_pdu_len, dissect_navitrol_pdu, data);
	return tvb_captured_length(tvb);
}

static void
navitrol_software_version( char *result, uint32_t version )
{
	uint32_t release_version, minor_version, branch_version;

	release_version = version / 10000;
	version %= 10000;
	minor_version = version / 100;
	branch_version = version % 100;

	snprintf( result, ITEM_LABEL_LENGTH, "%u.%02u.%02u", release_version, minor_version, branch_version);
}

void
proto_register_navitrol(void)
{
	module_t *navitrol_module;
	expert_module_t* expert_navitrol;

	static hf_register_info hf[] = {
		{ &hf_navitrol_protocol_version,
			{ "Protocol version", "navitrol.protocol_version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_message_id,
			{ "Message ID", "navitrol.message_id", FT_UINT32, BASE_DEC, VALS(message_id_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_message_length,
			{ "Message length", "navitrol.message_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_measurement_mode,
			{ "Measurement sending mode", "navitrol.measurement_mode", FT_UINT8, BASE_DEC, VALS(mesasurement_mode_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_ip_address,
			{ "IP Address", "navitrol.ip_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_port_front,
			{ "Front port", "navitrol.port_front", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_port_rear,
			{ "Rear port", "navitrol.port_rear", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_raw_data_status,
			{ "Status", "navitrol.raw_data_status", FT_UINT8, BASE_DEC, VALS(status_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_position_x,
			{ "X", "navitrol.position_x", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_position_y,
			{ "Y", "navitrol.position_y", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_position_x_double,
			{ "X", "navitrol.position_x.double", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_position_y_double,
			{ "Y", "navitrol.position_y.double", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_position_heading,
			{ "Heading", "navitrol.position_heading", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_floor,
			{ "Floor", "navitrol.floor", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_cum_s_long,
			{ "Cumulative raw odometer distance heading", "navitrol.cum_s_long", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_cum_s_trans,
			{ "Cumulative raw odometer distance transversal", "navitrol.cum_s_trans", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_teaching_command,
			{ "Command", "navitrol.teaching_command", FT_UINT16, BASE_DEC, VALS(teaching_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_error_code,
			{ "Error code", "navitrol.error_code", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_error_count,
			{ "Error count", "navitrol.error_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_message_number,
			{ "Message number", "navitrol.message_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_raw_heading,
			{ "Raw heading", "navitrol.raw_heading", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_timestamp,
			{ "Timestamp", "navitrol.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_position_initialize_status,
			{ "Position initialize status", "navitrol.position_initialize_status", FT_UINT16, BASE_DEC, VALS(status_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_position_confidence,
			{ "Position confidence", "navitrol.position_confidence", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_percent), 0x0, NULL, HFILL } },
		{ &hf_navitrol_position_confidence_float,
			{ "Position confidence", "navitrol.position_confidence_f", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_percent), 0x0, NULL, HFILL } },
		{ &hf_navitrol_error_description,
			{ "Error description", "navitrol.error_description", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_saved_log_number,
			{ "Saved log number", "navitrol.saved_log_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_software_version,
			{ "Software version", "navitrol.software_version", FT_UINT32, BASE_CUSTOM, CF_FUNC(navitrol_software_version), 0x0, NULL, HFILL } },
		{ &hf_navitrol_comm_version,
			{ "Communication protocol version", "navitrol.comm_version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_time_set_status,
			{ "Time set status", "navitrol.time_set_status", FT_UINT16, BASE_DEC, VALS(status_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_position_correction_status,
			{ "Position correction status", "navitrol.position_correction_status", FT_UINT16, BASE_DEC, VALS(position_correction_status_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_set_time,
			{ "Set time", "navitrol.set_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_vel_long,
			{ "Raw dead reckoning velocity heading", "navitrol.vel_long", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_vel_trans,
			{ "Raw dead reckoning velocity transversal", "navitrol.vel_trans", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_vel_angular,
			{ "Raw dead reckoning angular velocity", "navitrol.vel_angular", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_cum_s_left,
			{ "Cumulative raw odometer left wheel (in 0.1 millimeters)", "navitrol.cum_s_left", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_cum_s_right,
			{ "Cumulative raw odometer right wheel (in 0.1 millimeters)", "navitrol.cum_s_right", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_driving_enabled,
			{ "Driving enabled", "navitrol.driving_enabled", FT_UINT16, BASE_DEC, VALS(driving_status_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_read_status,
			{ "Read status", "navitrol.read_status", FT_UINT16, BASE_DEC, VALS(status_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_speed_left,
			{ "Speed left", "navitrol.speed_left", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_speed_right,
			{ "Speed right", "navitrol.speed_right", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_errors_stopping_driving,
			{ "Errors stopping driving", "navitrol.errors_stopping_driving", FT_UINT16, BASE_DEC, VALS(error_driving_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_start_stop_mode,
			{ "Start/stop mode", "navitrol.start_stop_mode", FT_UINT8, BASE_DEC, VALS(start_stop_log_mode_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_clear_log,
			{ "Clear log", "navitrol.clear_log", FT_UINT8, BASE_DEC, VALS(clear_log_vals), 0x0, NULL, HFILL } },
		{ &hf_navitrol_log_save_length,
			{ "Length of log to save to file", "navitrol.log_save_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_raw_ds,
			{ "RawDs", "navitrol.raw_ds", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_raw_dh,
			{ "RawDh", "navitrol.raw_dh", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_navitrol_floor_changed_status,
			{ "Floor changed status", "navitrol.floor_changed_status", FT_UINT8, BASE_DEC, VALS(status_vals), 0x0, NULL, HFILL } },
	};

	static int *ett[] = {
		&ett_navitrol,
	};

	static ei_register_info ei[] = {
		{ &ei_navitrol_message_id, { "navitrol.message_id.unknown", PI_PROTOCOL, PI_WARN, "Unknown message ID", EXPFILL }},
	};

	proto_navitrol = proto_register_protocol("Navitec Systems Navitrol", "Navitrol", "navitrol");
	proto_register_field_array(proto_navitrol, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_navitrol = expert_register_protocol(proto_navitrol);
	expert_register_field_array(expert_navitrol, ei, array_length(ei));

	navitrol_module = prefs_register_protocol(proto_navitrol, NULL);

	prefs_register_enum_preference(navitrol_module, "endian",
		"Endianness of protocol",
		"Endianness applied to protocol fields",
		&navitrol_endian,
		navitrol_endian_vals,
		false);

}

void
proto_reg_handoff_navitrol(void)
{
	dissector_handle_t navitrol_handle;

	navitrol_handle = create_dissector_handle(dissect_navitrol, proto_navitrol);
	dissector_add_for_decode_as("tcp.port", navitrol_handle);
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
