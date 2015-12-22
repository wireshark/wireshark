/* packet-zbee-zcl-misc.c
 * Dissector routines for the ZigBee ZCL SE clusters like
 * Messaging
 * By Fabio Tarabelloni <fabio.tarabelloni@reloc.it>
 * Copyright 2013 RELOC s.r.l.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*  Include Files */
#include "config.h"


#include <epan/packet.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"

/* ########################################################################## */
/* #### (0x0201) THERMOSTAT CLUSTER ######################################### */
/* ########################################################################## */

/* Cluster-specific commands and parameters */
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_CIR             0x00
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_FPS             0x01
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_SLPI            0x02
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_SSPI            0x03
#define ZBEE_ZCL_CSC_POLL_CONTROL_S_CI              0x00
#define ZBEE_ZCL_CSC_THERMOSTAT_C_CWS               0x03
#define ZBEE_ZCL_CSC_THERMOSTAT_C_GWS               0x02
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SRL               0x00
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS               0x01
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_AV        0x80
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_FR        0x20
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_MO        0x02
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_SA        0x40
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_SU        0x01
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_TH        0x10
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_TU        0x04
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_WE        0x08
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_B          0x03
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_C          0x02
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_H          0x01
#define ZBEE_ZCL_CSC_THERMOSTAT_S_GWSR              0x00

#define ZBEE_ZCL_THERMOSTAT_NUM_ETT             3

/* Thermostat Information Attributes */
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_LOCAL_TEMP               0x0000
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_OUTDOOR_TEMP             0x0001
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_OCCUPANCY                0x0002
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_ABS_MIN_HEAT_SETPOINT    0x0003
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_ABS_MAX_HEAT_SETPOINT    0x0004
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_ABS_MIN_COOL_SETPOINT    0x0005
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_ABS_MAX_COOL_SETPOINT    0x0006
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_PI_COOL_DEMAND           0x0007
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_PI_HEAT_DEMAND           0x0008
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_HVAC_TYPE_CONFIG         0x0009
/* Thermostat Settings Attributes */
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_LOCAL_TEMP_CALIBRATION   0x0010
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_OCCUPIED_COOL_SETPOINT   0x0011
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_OCCUPIED_HEAT_SETPOINT   0x0012
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_UNOCCUPIED_COOL_SETPOINT 0x0013
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_UNOCCUPIED_HEAT_SETPOINT 0x0014
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_MIN_HEAT_SETPOINT        0x0015
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_MAX_HEAT_SETPOINT        0x0016
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_MIN_COOL_SETPOINT        0x0017
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_MAX_COOL_SETPOINT        0x0018
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_MIN_SETPOINT_DEADBAND    0x0019
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_REMOTE_SENSING           0x001A
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_CONTROL_SEQUENCE         0x001B
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_SYSTEM_MODE              0x001C
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_ALARM_MASK               0x001D
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_RUNNING_MODE             0x001E
/* Schedule & HVAC Relay Attributes. */
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_START_OF_WEEK            0x0020
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_NUM_WEEKLY_TRANSITIONS   0x0021
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_NUM_DAILY_TRANSITIONS    0x0022
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_SETPOINT_HOLD            0x0023
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_SETPOINT_HOLD_DURATION   0x0024
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_PROGRAMMING_MODE         0x0025
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_RUNNING_STATE            0x0029
/* Setpoint Change Tracking Attributes. */
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_SETPOINT_CHANGE_SOURCE   0x0030
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_SETPOINT_CHANGE_AMOUNT   0x0031
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_SETPOINT_CHANGE_TIME     0x0032
/* Air Conditioning Atrributes. */
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_AC_TYPE                  0x0040
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_AC_CAPACITY              0x0041
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_AC_REFRIGERANT_TYPE      0x0042
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_AC_COMPRESSOR_TYPE       0x0043
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_AC_ERROR_CODE            0x0044
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_AC_LOUVER_POSITION       0x0045
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_AC_COIL_TEMPERATURE      0x0046
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_AC_CAPACITY_FORMAT       0x0047

static const value_string zbee_zcl_thermostat_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_LOCAL_TEMP,               "LocalTemperature" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_OUTDOOR_TEMP,             "OutdoorTemperature" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_OCCUPANCY,                "Occupancy" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_ABS_MIN_HEAT_SETPOINT,    "AbsMinHeatSetpointLimit" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_ABS_MAX_HEAT_SETPOINT,    "AbsMaxHeatSetpointLimit" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_ABS_MIN_COOL_SETPOINT,    "AbsMinCoolSetpointLimit" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_ABS_MAX_COOL_SETPOINT,    "AbsMaxCoolSetpointLimit" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_PI_COOL_DEMAND,           "PICoolingDemand" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_PI_HEAT_DEMAND,           "PIHeatingDemand" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_HVAC_TYPE_CONFIG,         "HVACSystemTypeConfiguration" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_LOCAL_TEMP_CALIBRATION,   "LocalTemperatureCalibration" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_OCCUPIED_COOL_SETPOINT,   "OccupiedCoolingSetpoint" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_OCCUPIED_HEAT_SETPOINT,   "OccupiedHeatingSetpoint" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_UNOCCUPIED_COOL_SETPOINT, "UnoccupiedCoolingSetpoint" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_UNOCCUPIED_HEAT_SETPOINT, "UnoccupiedHeatingSetpoint" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_MIN_HEAT_SETPOINT,        "MinHeatSetpointLimit" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_MAX_HEAT_SETPOINT,        "MaxHeatSetpointLimit" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_MIN_COOL_SETPOINT,        "MinCoolSetpointLimit" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_MAX_COOL_SETPOINT,        "MaxCoolSetpointLimit" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_MIN_SETPOINT_DEADBAND,    "MinSetpointDeadBand" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_REMOTE_SENSING,           "RemoteSensing" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_CONTROL_SEQUENCE,         "ControlSequenceOfOperation" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_SYSTEM_MODE,              "SystemMode" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_ALARM_MASK,               "AlarmMask" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_RUNNING_MODE,             "ThermostatRunningMode" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_START_OF_WEEK,            "StartOfWeek" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_NUM_WEEKLY_TRANSITIONS,   "NumberOfWeeklyTransitions" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_NUM_DAILY_TRANSITIONS,    "NumberOfDailyTransitions" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_SETPOINT_HOLD,            "TemperatureSetpointHold" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_SETPOINT_HOLD_DURATION,   "TemperatureSetpointHoldDuration" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_PROGRAMMING_MODE,         "ThermostatProgrammingOperationMode" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_RUNNING_STATE,            "ThermostatRunningState" },
    { 0, NULL }
};

/* RemoteSensing bitmask. */
#define ZBEE_ZCL_THERMOSTAT_REMOTE_SENSE_LOCAL          0x01
#define ZBEE_ZCL_THERMOSTAT_REMOTE_SENSE_OUTDOOR        0x02
#define ZBEE_ZCL_THERMOSTAT_REMOTE_SENSE_OCCUPANCY      0x04

#define ZBEE_ZCL_THERMOSTAT_ALARM_INIT_FAILURE          0x01
#define ZBEE_ZCL_THERMOSTAT_ALARM_HARDWARE_FAILURE      0x02
#define ZBEE_ZCL_THERMOSTAT_ALARM_CALIBRATION_FAILURE   0x04

/* Programming operation mode bits. */
#define ZBEE_ZCL_THERMOSTAT_PROGRAM_MODE_SCHEDULE       0x01
#define ZBEE_ZCL_THERMOSTAT_PROGRAM_MODE_AUTO           0x02
#define ZBEE_ZCL_THERMOSTAT_PROGRAM_MODE_ENERGY_STAR    0x04

/* HVAC Running State bits. */
#define ZBEE_ZCL_THERMOSTAT_RUNNING_STATE_HEAT          0x0001
#define ZBEE_ZCL_THERMOSTAT_RUNNING_STATE_COOL          0x0002
#define ZBEE_ZCL_THERMOSTAT_RUNNING_STATE_FAN           0x0004
#define ZBEE_ZCL_THERMOSTAT_RUNNING_STATE_HEAT2         0x0008
#define ZBEE_ZCL_THERMOSTAT_RUNNING_STATE_COOL2         0x0010
#define ZBEE_ZCL_THERMOSTAT_RUNNING_STATE_FAN2          0x0020
#define ZBEE_ZCL_THERMOSTAT_RUNNING_STATE_FAN3          0x0040

/* Client-to-server commands. */
#define ZBEE_ZCL_CMD_ID_THERMOSTAT_SETPOINT             0x00
#define ZBEE_ZCL_CMD_ID_THERMOSTAT_SET_SCHEDULE         0x01
#define ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_SCHEDULE         0x02
#define ZBEE_ZCL_CMD_ID_THERMOSTAT_CLEAR_SCHEDULE       0x03
#define ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_RELAY_LOG        0x04
static const value_string zbee_zcl_thermostat_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_THERMOSTAT_SETPOINT,      "Setpoint Raise/Lower" },
    { ZBEE_ZCL_CMD_ID_THERMOSTAT_SET_SCHEDULE,  "Set Weekly Schedule" },
    { ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_SCHEDULE,  "Get Weekly Schedule" },
    { ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_RELAY_LOG, "Get Relay Status Log" },
    { 0, NULL }
};

#define ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_SCHEDULE_RESPONSE    0x00
#define ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_RELAY_LOG_RESPONSE   0x01
static const value_string zbee_zcl_thermostat_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_SCHEDULE_RESPONSE, "Get Weekly Schedule Response" },
    { ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_RELAY_LOG_RESPONSE,"Get Relay Status Log Response" },
    { 0, NULL }
};

#define ZBEE_ZCL_CMD_THERMOSTAT_SCHEDULE_MODE_SEQUENCE_HEAT 0x01
#define ZBEE_ZCL_CMD_THERMOSTAT_SCHEDULE_MODE_SEQUENCE_COOL 0x02

/* Setpoint mode names. */
static const value_string zbee_zcl_thermostat_setpoint_mode_names[] = {
    { 0,    "Heat" },
    { 1,    "Cool" },
    { 2,    "Both" },
    { 0, NULL }
};

/*************************/
/* Global Variables      */
/*************************/
static int proto_zbee_zcl_thermostat = -1;

static int hf_zbee_zcl_thermostat_attr_id = -1;
static int hf_zbee_zcl_thermostat_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_thermostat_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_thermostat_setpoint_mode = -1;
static int hf_zbee_zcl_thermostat_setpoint_amount = -1;

static int hf_zbee_zcl_thermostat_schedule_num_trans = -1;
static int hf_zbee_zcl_thermostat_schedule_day_sequence = -1;
static int hf_zbee_zcl_thermostat_schedule_day_sunday = -1;
static int hf_zbee_zcl_thermostat_schedule_day_monday = -1;
static int hf_zbee_zcl_thermostat_schedule_day_tuesday = -1;
static int hf_zbee_zcl_thermostat_schedule_day_wednesday = -1;
static int hf_zbee_zcl_thermostat_schedule_day_thursday = -1;
static int hf_zbee_zcl_thermostat_schedule_day_friday = -1;
static int hf_zbee_zcl_thermostat_schedule_day_saturday = -1;
static int hf_zbee_zcl_thermostat_schedule_day_vacation = -1;
static int hf_zbee_zcl_thermostat_schedule_mode_sequence = -1;
static int hf_zbee_zcl_thermostat_schedule_mode_heat = -1;
static int hf_zbee_zcl_thermostat_schedule_mode_cool = -1;
static int hf_zbee_zcl_thermostat_schedule_time = -1;
static int hf_zbee_zcl_thermostat_schedule_heat = -1;
static int hf_zbee_zcl_thermostat_schedule_cool = -1;

static gint ett_zbee_zcl_thermostat = -1;
static gint ett_zbee_zcl_thermostat_schedule_days = -1;
static gint ett_zbee_zcl_thermostat_schedule_mode = -1;

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_thermostat(void);
void proto_reg_handoff_zbee_zcl_thermostat(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_thermostat_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

static int  dissect_zcl_thermostat_schedule(proto_tree *tree, tvbuff_t *tvb, guint offset);
static void dissect_zcl_thermostat_schedule_days(proto_tree *tree, tvbuff_t *tvb, guint offset);
static void dissect_zcl_thermostat_schedule_mode(proto_tree *tree, tvbuff_t *tvb, guint offset);

/**
 *Helper function to dissect a Thermostat scheduling days bitmask.
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset payload offset of the ZoneStatus value.
*/
static void
dissect_zcl_thermostat_schedule_days(proto_tree *tree, tvbuff_t *tvb, guint offset)
{

    static const int *thermostat_schedule_days[] = {
        &hf_zbee_zcl_thermostat_schedule_day_sunday,
        &hf_zbee_zcl_thermostat_schedule_day_monday,
        &hf_zbee_zcl_thermostat_schedule_day_tuesday,
        &hf_zbee_zcl_thermostat_schedule_day_wednesday,
        &hf_zbee_zcl_thermostat_schedule_day_thursday,
        &hf_zbee_zcl_thermostat_schedule_day_friday,
        &hf_zbee_zcl_thermostat_schedule_day_saturday,
        &hf_zbee_zcl_thermostat_schedule_day_vacation,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_zcl_thermostat_schedule_day_sequence,
        ett_zbee_zcl_thermostat_schedule_days, thermostat_schedule_days, ENC_NA);

} /* dissect_zcl_thermostat_schedule_days */

/**
 *Helper function to dissect a Thermostat scheduling mode bitmask.
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset payload offset of the ZoneStatus value.
*/
static void
dissect_zcl_thermostat_schedule_mode(proto_tree *tree, tvbuff_t *tvb, guint offset)
{

    static const int *thermostat_schedule_modes[] = {
        &hf_zbee_zcl_thermostat_schedule_mode_heat,
        &hf_zbee_zcl_thermostat_schedule_mode_cool,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_zcl_thermostat_schedule_mode_sequence,
        ett_zbee_zcl_thermostat_schedule_mode, thermostat_schedule_modes, ENC_NA);
}

/**
 *Helper function to dissect a Thermostat schedule, which has
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset payload offset of the ZoneStatus value.
 *@return length of parsed data.
*/
static int
dissect_zcl_thermostat_schedule(proto_tree *tree, tvbuff_t *tvb, guint offset)
{
    guint       start = offset;
    guint8      num_transitions;
    guint8      mode_sequence;
    int         i;

    num_transitions = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_zcl_thermostat_schedule_num_trans, tvb, offset, 1,
        num_transitions);
    offset++;

    dissect_zcl_thermostat_schedule_days(tree, tvb, offset);
    offset++;

    mode_sequence = tvb_get_guint8(tvb, offset);
    dissect_zcl_thermostat_schedule_mode(tree, tvb, offset);
    offset++;

    /* Parse the list of setpoint transitions. */
    for (i = 0; i < num_transitions; i++) {
        nstime_t tv;
        tv.secs = tvb_get_letohs(tvb, offset) * 60;
        tv.nsecs = 0;
        proto_tree_add_time(tree, hf_zbee_zcl_thermostat_schedule_time, tvb, offset, 2, &tv);
        offset += 2;

        if (mode_sequence & ZBEE_ZCL_CMD_THERMOSTAT_SCHEDULE_MODE_SEQUENCE_HEAT) {
            float setpoint = (gint16)tvb_get_letohs(tvb, offset);
            proto_tree_add_float(tree, hf_zbee_zcl_thermostat_schedule_heat,
                    tvb, offset, 2, (setpoint / 100.0f));
            offset += 2;
        }
        if (mode_sequence & ZBEE_ZCL_CMD_THERMOSTAT_SCHEDULE_MODE_SEQUENCE_COOL) {
            float setpoint = (gint16)tvb_get_letohs(tvb, offset);
            proto_tree_add_float(tree, hf_zbee_zcl_thermostat_schedule_cool,
                    tvb, offset, 2, (setpoint / 100.0f));
            offset += 2;
        }
    } /* for */

    /* Return the number of bytes parsed. */
    return (offset - start);
} /* dissect_zcl_thermostat_cmd_schedule */

/**
 *ZigBee ZCL Thermostat cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param data pointer to ZCL packet structure.
 *@return length of parsed data.
*/
static int
dissect_zbee_zcl_thermostat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    zbee_zcl_packet   *zcl;
    guint             offset = 0;
    guint8            cmd_id;
    float             amount;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_thermostat_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_thermostat_srv_rx_cmd_id, tvb, offset, 1, cmd_id);
        offset++;

        /* Handle the command dissection. */
        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_THERMOSTAT_SETPOINT:
                /* Setpoint Raise/Lower. */
                proto_tree_add_item(tree, hf_zbee_zcl_thermostat_setpoint_mode,
                    tvb, offset, 1, ENC_NA);
                offset++;
                amount = (gint8)tvb_get_guint8(tvb, offset);
                proto_tree_add_float(tree, hf_zbee_zcl_thermostat_setpoint_amount,
                    tvb, offset, 1, (amount / 100.0f));
                offset++;
                break;

            case ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_SCHEDULE:
                /* Get Weekly Schedule. */
                dissect_zcl_thermostat_schedule_days(tree, tvb, offset);
                offset++;
                dissect_zcl_thermostat_schedule_mode(tree, tvb, offset);
                offset++;
                break;

            case ZBEE_ZCL_CMD_ID_THERMOSTAT_SET_SCHEDULE:
                /* Set Weekly Schedule. */
                dissect_zcl_thermostat_schedule(tree, tvb, offset);
                break;

            case ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_RELAY_LOG:
                /* No Payload - fall-through. */
            default:
                break;
        } /* switch */
    } else {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_thermostat_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_thermostat_srv_tx_cmd_id, tvb, offset, 1, cmd_id);
        offset++;

        /* Handle the command dissection. */
        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_SCHEDULE_RESPONSE:
                /* Get Weekly Schedule Response. */
                dissect_zcl_thermostat_schedule(tree, tvb, offset);
                break;

            case ZBEE_ZCL_CMD_ID_THERMOSTAT_GET_RELAY_LOG_RESPONSE:
                /* TODO: Implement Me! */
            default:
                break;
        } /* switch */
    }

    return tvb_captured_length(tvb);
} /* dissect_zbee_zcl_thermostat */

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
 *@param attr_id attribute identifier
 *@param data_type attribute data type
*/
static void
dissect_zcl_thermostat_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_thermostat_attr_data*/

/**
 *ZigBee ZCL IAS Zone cluste protocol registration.
 *
*/
void
proto_register_zbee_zcl_thermostat(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_thermostat_attr_id,
            { "Attribute", "zbee_zcl_hvac.thermostat.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_thermostat_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_thermostat_srv_rx_cmd_id,
            { "Command", "zbee_zcl_hvac.thermostat.cmd.srv_rx.id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_thermostat_srv_rx_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_srv_tx_cmd_id,
            { "Command", "zbee_zcl_hvac.thermostat.cmd.srv_tx.id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_thermostat_srv_tx_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_setpoint_mode,
            { "Mode", "zbee_zcl_hvac.thermostat.mode", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_thermostat_setpoint_mode_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_setpoint_amount,
            { "Amount", "zbee_zcl_hvac.thermostat.amount", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_num_trans,
            { "Number of Transitions for Sequence", "zbee_zcl_hvac.thermostat.num_trans", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_day_sequence,
            { "Days of Week for Sequence", "zbee_zcl_hvac.thermostat.day_sequence", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_day_sunday,
            { "Sunday", "zbee_zcl_hvac.thermostat.day.sunday", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01, NULL,
                HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_day_monday,
            { "Monday", "zbee_zcl_hvac.thermostat.day.monday", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02, NULL,
                HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_day_tuesday,
            { "Tuesday", "zbee_zcl_hvac.thermostat.day.tuesday", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04, NULL,
                HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_day_wednesday,
            { "Wednesday", "zbee_zcl_hvac.thermostat.day.wednesday", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08, NULL,
                HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_day_thursday,
            { "Thursday", "zbee_zcl_hvac.thermostat.day.thursday", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x10, NULL,
                HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_day_friday,
            { "Friday", "zbee_zcl_hvac.thermostat.day.friday", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x20, NULL,
                HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_day_saturday,
            { "Saturday", "zbee_zcl_hvac.thermostat.day.saturday", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x40, NULL,
                HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_day_vacation,
            { "Away/Vacation", "zbee_zcl_hvac.thermostat.day.vacation", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x80, NULL,
                HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_mode_sequence,
            { "Mode for Sequence", "zbee_zcl_hvac.thermostat.mode_sequence", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_mode_heat,
            { "Heating", "zbee_zcl_hvac.thermostat.mode.heat", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_mode_cool,
            { "Cooling", "zbee_zcl_hvac.thermostat.mode.cool", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_time,
            { "Transition Time", "zbee_zcl_hvac.thermostat.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                "Setpoint transition time relative to midnight of the scheduled day", HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_heat,
            { "Heating Setpoint", "zbee_zcl_hvac.thermostat.heat", FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Heating setpoint in degrees Celcius", HFILL }},

        { &hf_zbee_zcl_thermostat_schedule_cool,
            { "Cooling Setpoint", "zbee_zcl_hvac.thermostat.cool", FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Cooling setpoint in degrees Celcius", HFILL }}
    };

    /* ZCL IAS Zone subtrees */
    static gint *ett[ZBEE_ZCL_THERMOSTAT_NUM_ETT];

    ett[0] = &ett_zbee_zcl_thermostat;
    ett[1] = &ett_zbee_zcl_thermostat_schedule_days;
    ett[2] = &ett_zbee_zcl_thermostat_schedule_mode;

    /* Register the ZigBee ZCL IAS Zoben cluster protocol name and description */
    proto_zbee_zcl_thermostat = proto_register_protocol("ZigBee ZCL Thermostat", "ZCL Thermostat", ZBEE_PROTOABBREV_ZCL_THERMOSTAT);
    proto_register_field_array(proto_zbee_zcl_thermostat, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL IAS Zone dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_THERMOSTAT, dissect_zbee_zcl_thermostat, proto_zbee_zcl_thermostat);
} /*proto_register_zbee_zcl_thermostat*/

/**
 *Hands off the ZCL Thermostat dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_thermostat(void)
{
    dissector_handle_t thermostat_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    thermostat_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_THERMOSTAT);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_THERMOSTAT, thermostat_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_thermostat,
                            ett_zbee_zcl_thermostat,
                            ZBEE_ZCL_CID_THERMOSTAT,
                            hf_zbee_zcl_thermostat_attr_id,
                            hf_zbee_zcl_thermostat_srv_rx_cmd_id,
                            hf_zbee_zcl_thermostat_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_thermostat_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_thermostat*/

/* ########################################################################## */
/* #### (0x0500) IAS ZONE CLUSTER ########################################### */
/* ########################################################################## */

#define ZBEE_ZCL_IAS_ZONE_NUM_ETT               2

/* IAS Zone Server Attributes */
#define ZBEE_ZCL_ATTR_ID_IAS_ZONE_STATE         0x0000
#define ZBEE_ZCL_ATTR_ID_IAS_ZONE_TYPE          0x0001
#define ZBEE_ZCL_ATTR_ID_IAS_ZONE_STATUS        0x0002
#define ZBEE_ZCL_ATTR_ID_IAS_CIE_ADDRESS        0x0010

static const value_string zbee_zcl_ias_zone_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_IAS_ZONE_STATE,          "ZoneState" },
    { ZBEE_ZCL_ATTR_ID_IAS_ZONE_TYPE,           "ZoneType" },
    { ZBEE_ZCL_ATTR_ID_IAS_ZONE_STATUS,         "ZoneStatus" },
    { ZBEE_ZCL_ATTR_ID_IAS_CIE_ADDRESS,         "IAS_CIE_Address" },
    { 0, NULL }
};

/* IAS Zone States */
#define ZBEE_IAS_ZONE_STATE_NOT_ENROLLED        0x00
#define ZBEE_IAS_ZONE_STATE_ENROLLED            0x01
static const value_string zbee_ias_state_names[] = {
    { ZBEE_IAS_ZONE_STATE_NOT_ENROLLED,         "Not Enrolled" },
    { ZBEE_IAS_ZONE_STATE_ENROLLED,             "Enrolled" },
    { 0, NULL }
};

/* IAS Zone Type values. */
#define ZBEE_IAS_ZONE_TYPE_STANDARD_CIE         0x0000
#define ZBEE_IAS_ZONE_TYPE_MOTION_SENSOR        0x000D
#define ZBEE_IAS_ZONE_TYPE_CONTACT_SWITCH       0x0015
#define ZBEE_IAS_ZONE_TYPE_FIRE_SENSOR          0x0028
#define ZBEE_IAS_ZONE_TYPE_WATER_SENSOR         0x002A
#define ZBEE_IAS_ZONE_TYPE_GAS_SENSOR           0x002B
#define ZBEE_IAS_ZONE_TYPE_PERSONAL_EMERGENCY   0x002C
#define ZBEE_IAS_ZONE_TYPE_VIBRATION_SENSOR     0x002D
#define ZBEE_IAS_ZONE_TYPE_REMOTE_CONTROL       0x010F
#define ZBEE_IAS_ZONE_TYPE_KEY_FOB              0x0115
#define ZBEE_IAS_ZONE_TYPE_KEYPAD               0x021D
#define ZBEE_IAS_ZONE_TYPE_STANDARD_WARNING     0x0225
#define ZBEE_IAS_ZONE_TYPE_INVALID_ZONE_TYPE    0xFFFF

#define ZBEE_IAS_ZONE_STATUS_ALARM1             0x0001
#define ZBEE_IAS_ZONE_STATUS_ALARM2             0x0002
#define ZBEE_IAS_ZONE_STATUS_TAMPER             0x0004
#define ZBEE_IAS_ZONE_STATUS_BATTERY            0x0008
#define ZBEE_IAS_ZONE_STATUS_SUPERVISION        0x0010
#define ZBEE_IAS_ZONE_STATUS_RESTORE            0x0020
#define ZBEE_IAS_ZONE_STATUS_TROUBLE            0x0040
#define ZBEE_IAS_ZONE_STATUS_AC_MAINS           0x0080

static const value_string zbee_ias_type_names[] = {
    { ZBEE_IAS_ZONE_TYPE_STANDARD_CIE,          "Standard CIE" },
    { ZBEE_IAS_ZONE_TYPE_MOTION_SENSOR,         "Motion sensor" },
    { ZBEE_IAS_ZONE_TYPE_CONTACT_SWITCH,        "Contact switch" },
    { ZBEE_IAS_ZONE_TYPE_FIRE_SENSOR,           "Fire sensor" },
    { ZBEE_IAS_ZONE_TYPE_WATER_SENSOR,          "Water sensor" },
    { ZBEE_IAS_ZONE_TYPE_GAS_SENSOR,            "Gas sensor" },
    { ZBEE_IAS_ZONE_TYPE_PERSONAL_EMERGENCY,    "Personal emergency device" },
    { ZBEE_IAS_ZONE_TYPE_VIBRATION_SENSOR,      "Vibration/movement sensor" },
    { ZBEE_IAS_ZONE_TYPE_REMOTE_CONTROL,        "Remote control" },
    { ZBEE_IAS_ZONE_TYPE_KEY_FOB,               "Key fob" },
    { ZBEE_IAS_ZONE_TYPE_KEYPAD,                "Keypad" },
    { ZBEE_IAS_ZONE_TYPE_STANDARD_WARNING,      "Standard warning device" },
    { ZBEE_IAS_ZONE_TYPE_INVALID_ZONE_TYPE,     "Invalid zone type" },
    { 0, NULL }
};

/* Server-to-client command IDs. */
#define ZBEE_ZCL_CMD_ID_IAS_ZONE_ENROLL_NOTIFY      0x00
#define ZBEE_ZCL_CMD_ID_IAS_ZONE_ENROLL_REQUEST     0x01
static const value_string zbee_zcl_ias_zone_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_IAS_ZONE_ENROLL_REQUEST, "Zone Enroll Request" },
    { ZBEE_ZCL_CMD_ID_IAS_ZONE_ENROLL_NOTIFY, "Zone Status Change Notification" },
    { 0, NULL }
};

/* Client-to-server command IDs. */
#define ZBEE_ZCL_CMD_ID_IAS_ZONE_ENROLL_RESPONSE    0x00
static const value_string zbee_zcl_ias_zone_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_IAS_ZONE_ENROLL_RESPONSE, "Zone Enroll Response" },
    { 0, NULL }
};


static const value_string zbee_zcl_ias_zone_enroll_code_names[] = {
    { 0,    "Success" },
    { 1,    "Not Supported" },
    { 2,    "No enroll permit" },
    { 3,    "Too many zones" },
    { 0, NULL }
};

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_ias_zone = -1;

static int hf_zbee_zcl_ias_zone_attr_id = -1;
static int hf_zbee_zcl_ias_zone_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_ias_zone_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_ias_zone_enroll_code = -1;
static int hf_zbee_zcl_ias_zone_zone_id = -1;
static int hf_zbee_zcl_ias_zone_state = -1;
static int hf_zbee_zcl_ias_zone_type = -1;
static int hf_zbee_zcl_ias_zone_status = -1;
static int hf_zbee_zcl_ias_zone_delay = -1;
static int hf_zbee_zcl_ias_zone_ext_status = -1;
static int hf_zbee_zcl_ias_zone_status_ac_mains = -1;
static int hf_zbee_zcl_ias_zone_status_alarm1 = -1;
static int hf_zbee_zcl_ias_zone_status_alarm2 = -1;
static int hf_zbee_zcl_ias_zone_status_battery = -1;
static int hf_zbee_zcl_ias_zone_status_restore_reports = -1;
static int hf_zbee_zcl_ias_zone_status_supervision_reports = -1;
static int hf_zbee_zcl_ias_zone_status_tamper = -1;
static int hf_zbee_zcl_ias_zone_status_trouble = -1;

static const true_false_string tfs_ac_mains = {
    "AC/Mains fault",
    "AC/Mains OK"
};

static const true_false_string tfs_alarmed_or_not = {
    "Opened or alarmed",
    "Closed or not alarmed"
};

static const true_false_string tfs_battery = {
    "Low battery",
    "Battery OK"
};

static const true_false_string tfs_reports_or_not = {
    "Reports",
    "Does not report"
};

static const true_false_string tfs_reports_restore = {
    "Reports restore",
    "Does not report restore"
};

static const true_false_string tfs_tampered_or_not = {
    "Tampered",
    "Not tampered"
};

static const true_false_string tfs_trouble_failure = {
    "Trouble/Failure",
    "OK"
};

static gint ett_zbee_zcl_ias_zone = -1;
static gint ett_zbee_zcl_ias_zone_status = -1;

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_ias_zone(void);
void proto_reg_handoff_zbee_zcl_ias_zone(void);

/* Command Dissector Helpers. */
static int dissect_zbee_zcl_ias_zone   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

/* Attribute Dissector Helpers */
static void dissect_zcl_ias_zone_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* ZoneStatus bitmask helper */
static void dissect_zcl_ias_zone_status     (proto_tree *tree, tvbuff_t *tvb, guint offset);

/**
 *Helper function to dissect the IAS ZoneStatus bitmask.
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset payload offset of the ZoneStatus value.
*/
static void
dissect_zcl_ias_zone_status(proto_tree *tree, tvbuff_t *tvb, guint offset)
{
    static const int *ias_zone_statuses[] = {
        &hf_zbee_zcl_ias_zone_status_alarm1,
        &hf_zbee_zcl_ias_zone_status_alarm2,
        &hf_zbee_zcl_ias_zone_status_tamper,
        &hf_zbee_zcl_ias_zone_status_battery,
        &hf_zbee_zcl_ias_zone_status_supervision_reports,
        &hf_zbee_zcl_ias_zone_status_restore_reports,
        &hf_zbee_zcl_ias_zone_status_trouble,
        &hf_zbee_zcl_ias_zone_status_ac_mains,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_zcl_ias_zone_status, ett_zbee_zcl_ias_zone_status, ias_zone_statuses, ENC_NA);

} /* dissect_zcl_ias_zone_status */

/**
 *ZigBee ZCL IAS Zone cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param data pointer to ZCL packet structure.
 *@return length of parsed data.
*/
static int
dissect_zbee_zcl_ias_zone(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    zbee_zcl_packet   *zcl;
    guint             offset = 0;
    guint8            cmd_id;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_ias_zone_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_ias_zone_srv_rx_cmd_id, tvb, offset, 1, cmd_id);
        offset++;

        /* Handle the command dissection. */
        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_IAS_ZONE_ENROLL_RESPONSE:
                proto_tree_add_item(tree, hf_zbee_zcl_ias_zone_enroll_code, tvb, offset, 1, ENC_NA);
                offset++;
                proto_tree_add_item(tree, hf_zbee_zcl_ias_zone_zone_id, tvb, offset, 1, ENC_NA);
                offset++;
                break;

            default:
                break;
        } /* switch */
    } else {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_ias_zone_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_ias_zone_srv_tx_cmd_id, tvb, offset, 1, cmd_id);
        offset++;

        /* Handle the command dissection. */
        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_IAS_ZONE_ENROLL_NOTIFY:
                dissect_zcl_ias_zone_status(tree, tvb, offset);
                offset += 2;
                proto_tree_add_item(tree, hf_zbee_zcl_ias_zone_ext_status, tvb, offset,
                    1, ENC_NA);
                offset += 1;
                proto_tree_add_item(tree, hf_zbee_zcl_ias_zone_zone_id, tvb, offset, 1,
                    ENC_NA);
                offset += 1;
                proto_tree_add_item(tree, hf_zbee_zcl_ias_zone_delay, tvb, offset, 2,
                    ENC_LITTLE_ENDIAN);

            case ZBEE_ZCL_CMD_ID_IAS_ZONE_ENROLL_REQUEST:
            default:
                break;
        } /* switch */
    }

    return tvb_reported_length(tvb);
} /* dissect_zbee_zcl_ias_zone */

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
 *@param attr_id attribute identifier
 *@param data_type attribute data type
*/
static void
dissect_zcl_ias_zone_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {
        case ZBEE_ZCL_ATTR_ID_IAS_ZONE_STATE:
            proto_tree_add_item(tree, hf_zbee_zcl_ias_zone_state, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_IAS_ZONE_TYPE:
            proto_tree_add_item(tree, hf_zbee_zcl_ias_zone_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_IAS_ZONE_STATUS:
            dissect_zcl_ias_zone_status(tree, tvb, *offset);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_IAS_CIE_ADDRESS:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_ias_zone_attr_data*/

/**
 *Hands off the ZCL IAS Zone dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_ias_zone(void)
{
    dissector_handle_t zone_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    zone_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_IAS_ZONE);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_IAS_ZONE, zone_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_ias_zone,
                            ett_zbee_zcl_ias_zone,
                            ZBEE_ZCL_CID_IAS_ZONE,
                            hf_zbee_zcl_ias_zone_attr_id,
                            hf_zbee_zcl_ias_zone_srv_rx_cmd_id,
                            hf_zbee_zcl_ias_zone_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_ias_zone_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_ias_zone*/

/**
 *ZigBee ZCL IAS Zone cluste protocol registration.
 *
*/
void
proto_register_zbee_zcl_ias_zone(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_ias_zone_attr_id,
            { "Attribute", "zbee_zcl_ias.zone.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_ias_zone_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_zone_srv_rx_cmd_id,
            { "Command", "zbee_zcl_ias.zone.cmd.srv_rx.id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_ias_zone_srv_rx_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_srv_tx_cmd_id,
            { "Command", "zbee_zcl_ias.zone.cmd.srv_tx.id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_ias_zone_srv_tx_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_enroll_code,
            { "Enroll response code", "zbee_zcl_ias.zone.enroll_code", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_ias_zone_enroll_code_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_zone_id,
            { "Zone ID", "zbee_zcl_ias.zone.zone_id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_state,
            { "ZoneState", "zbee_zcl_ias.zone.state", FT_UINT16, BASE_HEX, VALS(zbee_ias_state_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_type,
            { "ZoneType", "zbee_zcl_ias.zone.type", FT_UINT16, BASE_HEX, VALS(zbee_ias_type_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_status,
            { "ZoneStatus", "zbee_zcl_ias.zone.status", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_delay,
            { "Delay (in quarterseconds)", "zbee_zcl_ias.zone.delay", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_ext_status,
            { "Extended Status", "zbee_zcl_ias.zone.ext_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_status_alarm1,
            { "Alarm 1", "zbee_zcl_ias.zone.status.alarm_1", FT_BOOLEAN, 16, TFS(&tfs_alarmed_or_not), ZBEE_IAS_ZONE_STATUS_ALARM1, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_status_alarm2,
            { "Alarm 2", "zbee_zcl_ias.zone.status.alarm_2", FT_BOOLEAN, 16, TFS(&tfs_alarmed_or_not), ZBEE_IAS_ZONE_STATUS_ALARM2, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_status_battery,
            { "Battery", "zbee_zcl_ias.zone.status.battery", FT_BOOLEAN, 16, TFS(&tfs_battery), ZBEE_IAS_ZONE_STATUS_BATTERY, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_status_tamper,
            { "Tamper", "zbee_zcl_ias.zone.status.tamper", FT_BOOLEAN, 16, TFS(&tfs_tampered_or_not), ZBEE_IAS_ZONE_STATUS_TAMPER, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_status_supervision_reports,
            { "Supervision Reports", "zbee_zcl_ias.zone.status.supervision_reports", FT_BOOLEAN, 16,
                TFS(&tfs_reports_or_not), ZBEE_IAS_ZONE_STATUS_SUPERVISION, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_status_restore_reports,
            { "Restore Reports", "zbee_zcl_ias.zone.status.restore_reports", FT_BOOLEAN, 16,
                TFS(&tfs_reports_restore), ZBEE_IAS_ZONE_STATUS_RESTORE, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_status_trouble,
            { "Trouble", "zbee_zcl_ias.zone.status.trouble", FT_BOOLEAN, 16, TFS(&tfs_trouble_failure), ZBEE_IAS_ZONE_STATUS_TROUBLE, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_status_ac_mains,
            { "AC (mains)", "zbee_zcl_ias.zone.status.ac_mains", FT_BOOLEAN, 16, TFS(&tfs_ac_mains), ZBEE_IAS_ZONE_STATUS_AC_MAINS, NULL,
                HFILL }}
    };

    /* ZCL IAS Zone subtrees */
    static gint *ett[ZBEE_ZCL_IAS_ZONE_NUM_ETT];

    ett[0] = &ett_zbee_zcl_ias_zone;
    ett[1] = &ett_zbee_zcl_ias_zone_status;

    /* Register the ZigBee ZCL IAS Zoben cluster protocol name and description */
    proto_zbee_zcl_ias_zone = proto_register_protocol("ZigBee ZCL IAS Zone", "ZCL IAS Zone", ZBEE_PROTOABBREV_ZCL_IAS_ZONE);
    proto_register_field_array(proto_zbee_zcl_ias_zone, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL IAS Zone dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_IAS_ZONE, dissect_zbee_zcl_ias_zone, proto_zbee_zcl_ias_zone);
} /*proto_register_zbee_zcl_ias_zone*/

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
