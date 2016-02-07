/* packet-zbee-zcl-hvac.c
 * Dissector routines for the ZigBee ZCL HVAC clusters
 * By Aditya Jain <aditya.jain@samsung.com>
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
#include <epan/to_str.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"

/* ########################################################################## */
/* #### (0x0200) PUMP CONFIGURATION AND CONTROL CLUSTER ##################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_NUM_ETT                                    3

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_PRESSURE                       0x0000  /* Maximum Pressure */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_SPEED                          0x0001  /* Maximum Speed */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_FLOW                           0x0002  /* Maximum Flow */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_PRESSURE                 0x0003  /* Minimum Constant Pressure */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_PRESSURE                 0x0004  /* Maximum Constant Pressure */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_COMP_PRESSURE                  0x0005  /* Minimum Compensated Pressure */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_POWER_MAX_COMP_PRESSURE            0x0006  /* Maximum Compensated Pressure */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_SPEED                    0x0007  /* Minimum Constant Speed */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_SPEED                    0x0008  /* Maximum Constant Speed */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_FLOW                     0x0009  /* Minimum Constant Flow */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_FLOW                     0x000a  /* Maximum Constant Flow */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_TEMP                     0x000b  /* Minimum Constant Temperature */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_TEMP                     0x000c  /* Maximum Constant Temperature */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_PUMP_STATUS                        0x0010  /* Pump Status */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_EFFECTIVE_OPR_MODE                 0x0011  /* Effective Operation Mode */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_EFFECTIVE_CTRL_MODE                0x0012  /* Effective Control Mode */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_CAPACITY                           0x0013  /* Capacity */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_SPEED                              0x0014  /* Speed */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_LIFETIME_RUNNING_HOURS             0x0015  /* Lifetime Running Hours */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_POWER                              0x0016  /* Power */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_LIFETIME_ENERGY_CONS               0x0017  /* Lifetime Energy Consumed */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_OPR_MODE                           0x0020  /* Operation Mode */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_CTRL_MODE                          0x0021  /* Control Mode */
#define ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_ALARM_MASK                         0x0022  /* Alarm Mask */

/*Server commands received - none*/

/*Server commands generated - none*/

/*Pump Status Mask Values*/
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_DEVICE_FAULT                        0x0001    /* Device Fault */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_SUPPLY_FAULT                        0x0002    /* Supply Fault */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_SPEED_LOW                           0x0004    /* Speed Low */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_SPEED_HIGH                          0x0008    /* Speed High */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_LOCAL_OVERRIDE                      0x0010    /* Local Override */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_RUNNING                             0x0020    /* Running */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_REMOTE_PRESSURE                     0x0040    /* Remote Pressure */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_REMOTE_FLOW                         0x0080    /* Remote Flow */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_REMOTE_TEMP                         0x0100    /* Remote Temperature */

/*Alarm Mask Values*/
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_VOLTAGE_TOO_LOW                      0x0001    /* Supply voltage too low */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_VOLTAGE_TOO_HIGH                     0x0002    /* Supply voltage too high */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_PWR_MISSING_PHASE                    0x0004    /* Power missing phase */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_PRESSURE_TOO_LOW                     0x0008    /* System pressure too low */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_PRESSURE_TOO_HIGH                    0x0010    /* System pressure too high */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_DRY_RUNNING                          0x0020    /* Dry running */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_MTR_TEMP_TOO_HIGH                    0x0040    /* Motor temperature too high */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_PUMP_MTR_FATAL_FAILURE               0x0080    /* Pump motor has fatal failure */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_ELEC_TEMP_TOO_HIGH                   0x0100    /* Electronic temperature too high */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_PUMP_BLOCK                           0x0200    /* Pump blocked */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_SENSOR_FAILURE                       0x0400    /* Sensor failure */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_ELEC_NON_FATAL_FAILURE               0x0800    /* Electronic non-fatal failure */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_ELEC_FATAL_FAILURE                   0x1000    /* Electronic fatal failure */
#define ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_GENERAL_FAULT                        0x2000    /* Genral fault */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_pump_config_control(void);
void proto_reg_handoff_zbee_zcl_pump_config_control(void);

/* Command Dissector Helpers */
static void dissect_zcl_pump_config_control_attr_data      (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_pump_config_control = -1;

static int hf_zbee_zcl_pump_config_control_attr_id = -1;
static int hf_zbee_zcl_pump_config_control_attr_eff_opr_mode = -1;
static int hf_zbee_zcl_pump_config_control_attr_opr_mode = -1;
static int hf_zbee_zcl_pump_config_control_attr_eff_ctrl_mode = -1;
static int hf_zbee_zcl_pump_config_control_attr_ctrl_mode = -1;
static int hf_zbee_zcl_pump_config_control_status = -1;
static int hf_zbee_zcl_pump_config_control_status_device_fault = -1;
static int hf_zbee_zcl_pump_config_control_status_supply_fault = -1;
static int hf_zbee_zcl_pump_config_control_status_speed_low = -1;
static int hf_zbee_zcl_pump_config_control_status_speed_high = -1;
static int hf_zbee_zcl_pump_config_control_status_local_override = -1;
static int hf_zbee_zcl_pump_config_control_status_running = -1;
static int hf_zbee_zcl_pump_config_control_status_rem_pressure = -1;
static int hf_zbee_zcl_pump_config_control_status_rem_flow = -1;
static int hf_zbee_zcl_pump_config_control_status_rem_temp = -1;
static int hf_zbee_zcl_pump_config_control_alarm = -1;
static int hf_zbee_zcl_pump_config_control_alarm_volt_too_low = -1;
static int hf_zbee_zcl_pump_config_control_alarm_volt_too_high = -1;
static int hf_zbee_zcl_pump_config_control_alarm_pwr_missing_phase = -1;
static int hf_zbee_zcl_pump_config_control_alarm_press_too_low = -1;
static int hf_zbee_zcl_pump_config_control_alarm_press_too_high = -1;
static int hf_zbee_zcl_pump_config_control_alarm_dry_running = -1;
static int hf_zbee_zcl_pump_config_control_alarm_mtr_temp_too_high = -1;
static int hf_zbee_zcl_pump_config_control_alarm_pump_mtr_fatal_fail = -1;
static int hf_zbee_zcl_pump_config_control_alarm_elec_temp_too_high = -1;
static int hf_zbee_zcl_pump_config_control_alarm_pump_block = -1;
static int hf_zbee_zcl_pump_config_control_alarm_sensor_fail = -1;
static int hf_zbee_zcl_pump_config_control_alarm_elec_non_fatal_fail = -1;
static int hf_zbee_zcl_pump_config_control_alarm_fatal_fail = -1;
static int hf_zbee_zcl_pump_config_control_alarm_gen_fault = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_pump_config_control = -1;
static gint ett_zbee_zcl_pump_config_control_status = -1;
static gint ett_zbee_zcl_pump_config_control_alarm = -1;

/* Attributes */
static const value_string zbee_zcl_pump_config_control_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_PRESSURE,                            "Maximum Pressure" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_SPEED,                               "Maximum Speed" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_FLOW,                                "Maximum Flow" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_PRESSURE,                      "Minimum Constant Pressure" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_PRESSURE,                      "Maximum Constant Pressure" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_COMP_PRESSURE,                       "Minimum Compensated Pressure" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_POWER_MAX_COMP_PRESSURE,                 "Maximum Compensated Pressure" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_SPEED,                         "Minimum Constant Speed" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_SPEED,                         "Maximum Constant Speed" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_FLOW,                          "Minimum Constant Flow" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_FLOW,                          "Maximum Constant Flow" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_TEMP,                          "Minimum Constant Temperature" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_TEMP,                          "Maximum Constant Temperature" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_PUMP_STATUS,                             "Pump Status" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_EFFECTIVE_OPR_MODE,                      "Effective Operation Mode" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_EFFECTIVE_CTRL_MODE,                     "Effective Control Mode" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_CAPACITY,                                "Capacity" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_SPEED,                                   "Speed" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_LIFETIME_RUNNING_HOURS,                  "Lifetime Running Hours" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_POWER,                                   "Power" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_LIFETIME_ENERGY_CONS,                    "Lifetime Energy Consumed" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_OPR_MODE,                                "Operation Mode" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_CTRL_MODE,                               "Control Mode" },
    { ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_ALARM_MASK,                              "Alarm Mask" },
    { 0, NULL }
};

/*Operation Mode Values*/
static const value_string zbee_zcl_pump_config_control_operation_mode_names[] = {
    {0, "Noramal"},
    {1, "Minimum"},
    {2, "Maximum"},
    {3, "Local"},
    {0, NULL}
};

/*Control Mode Values*/
static const value_string zbee_zcl_pump_config_control_control_mode_names[] = {
    {0, "Constant Speed"},
    {1, "Constant Pressure"},
    {2, "proportional Pressure"},
    {3, "Constant Flow"},
    {4, "Reserved"},
    {5, "Constat Temperature"},
    {6, "Reserved"},
    {7, "Automatic"},
    {0, NULL}
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Pump Configuration and Control cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/

static int
dissect_zbee_zcl_pump_config_control(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_pump_config_control*/


/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
 *@param attr_id attribute identifier
 *@param data_type attribute data type
*/
void
dissect_zcl_pump_config_control_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    static const int * pump_status[] = {
        &hf_zbee_zcl_pump_config_control_status_device_fault,
        &hf_zbee_zcl_pump_config_control_status_supply_fault,
        &hf_zbee_zcl_pump_config_control_status_speed_low,
        &hf_zbee_zcl_pump_config_control_status_speed_high,
        &hf_zbee_zcl_pump_config_control_status_local_override,
        &hf_zbee_zcl_pump_config_control_status_running,
        &hf_zbee_zcl_pump_config_control_status_rem_pressure,
        &hf_zbee_zcl_pump_config_control_status_rem_flow,
        &hf_zbee_zcl_pump_config_control_status_rem_temp,
        NULL
    };

    static const int * alarm_mask[] = {
        &hf_zbee_zcl_pump_config_control_alarm_volt_too_low,
        &hf_zbee_zcl_pump_config_control_alarm_volt_too_high,
        &hf_zbee_zcl_pump_config_control_alarm_pwr_missing_phase,
        &hf_zbee_zcl_pump_config_control_alarm_press_too_low,
        &hf_zbee_zcl_pump_config_control_alarm_press_too_high,
        &hf_zbee_zcl_pump_config_control_alarm_dry_running,
        &hf_zbee_zcl_pump_config_control_alarm_mtr_temp_too_high,
        &hf_zbee_zcl_pump_config_control_alarm_pump_mtr_fatal_fail,
        &hf_zbee_zcl_pump_config_control_alarm_elec_temp_too_high,
        &hf_zbee_zcl_pump_config_control_alarm_pump_block,
        &hf_zbee_zcl_pump_config_control_alarm_sensor_fail,
        &hf_zbee_zcl_pump_config_control_alarm_elec_non_fatal_fail,
        &hf_zbee_zcl_pump_config_control_alarm_fatal_fail,
        &hf_zbee_zcl_pump_config_control_alarm_gen_fault,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_EFFECTIVE_OPR_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_pump_config_control_attr_eff_opr_mode, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_OPR_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_pump_config_control_attr_opr_mode, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_EFFECTIVE_CTRL_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_pump_config_control_attr_eff_ctrl_mode, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_CTRL_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_pump_config_control_attr_ctrl_mode, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_PUMP_STATUS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_pump_config_control_status, ett_zbee_zcl_pump_config_control_status, pump_status, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_ALARM_MASK:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_pump_config_control_alarm, ett_zbee_zcl_pump_config_control_alarm, alarm_mask, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_PRESSURE:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_SPEED:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_FLOW:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_PRESSURE:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_PRESSURE:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_COMP_PRESSURE:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_POWER_MAX_COMP_PRESSURE:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_SPEED:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_SPEED:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_FLOW:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_FLOW:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MIN_CONST_TEMP:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_MAX_CONST_TEMP:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_CAPACITY:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_SPEED:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_LIFETIME_RUNNING_HOURS:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_POWER:
        case ZBEE_ZCL_ATTR_ID_PUMP_CONFIG_CONTROL_LIFETIME_ENERGY_CONS:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_pump_config_control_attr_data*/


/**
 *ZigBee ZCL Pump Configuration and Control cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_pump_config_control(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_pump_config_control_attr_id,
            { "Attribute", "zbee_zcl_hvac.pump_config_control.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_pump_config_control_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_attr_eff_opr_mode,
            { "Effective Operation Mode", "zbee_zcl_hvac.pump_config_control.attr.effective_opr_mode", FT_UINT8, BASE_DEC, VALS(zbee_zcl_pump_config_control_operation_mode_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_attr_opr_mode,
            { "Operation Mode", "zbee_zcl_hvac.pump_config_control.attr.opr_mode", FT_UINT8, BASE_DEC, VALS(zbee_zcl_pump_config_control_operation_mode_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_attr_eff_ctrl_mode,
            { "Effective Control Mode", "zbee_zcl_hvac.pump_config_control.attr.ctrl_mode", FT_UINT8, BASE_DEC, VALS(zbee_zcl_pump_config_control_control_mode_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_attr_ctrl_mode,
            { "Control Mode", "zbee_zcl_hvac.pump_config_control.attr.ctrl_mode", FT_UINT8, BASE_DEC, VALS(zbee_zcl_pump_config_control_control_mode_names),
            0x00, NULL, HFILL } },

        /* start Pump Status fields */
        { &hf_zbee_zcl_pump_config_control_status,
            { "Pump Status", "zbee_zcl_hvac.pump_config_control.attr.status", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_status_device_fault,
            { "Device Fault", "zbee_zcl_hvac.pump_config_control.attr.status.device_fault", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_DEVICE_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_status_supply_fault,
            { "Supply Fault", "zbee_zcl_hvac.pump_config_control.attr.status.supply_fault", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_SUPPLY_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_status_speed_low,
            { "Speed Low", "zbee_zcl_hvac.pump_config_control.attr.status.speed_low", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_SPEED_LOW, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_status_speed_high,
            { "Speed High", "zbee_zcl_hvac.pump_config_control.attr.status.speed_high", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_SPEED_HIGH, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_status_local_override,
            { "Local Override", "zbee_zcl_hvac.pump_config_control.attr.status.local_override", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_LOCAL_OVERRIDE, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_status_running,
            { "Running", "zbee_zcl_hvac.pump_config_control.attr.status.running", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_RUNNING, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_status_rem_pressure,
            { "Remote Pressure", "zbee_zcl_hvac.pump_config_control.attr.status.rem_pressure", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_REMOTE_PRESSURE, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_status_rem_flow,
            { "Remote Flow", "zbee_zcl_hvac.pump_config_control.attr.status.rem_flow", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_REMOTE_FLOW, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_status_rem_temp,
            { "Remote Temperature", "zbee_zcl_hvac.pump_config_control.attr.status.rem_temp", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_STATUS_REMOTE_TEMP, NULL, HFILL } },
        /* end Pump Status fields */

        /*start Alarm Mask fields*/
        { &hf_zbee_zcl_pump_config_control_alarm,
            { "Alarm Mask", "zbee_zcl_hvac.pump_config_control.attr.alarm", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_volt_too_low,
            { "Supply voltage too low", "zbee_zcl_hvac.pump_config_control.attr.alarm.volt_too_low", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_VOLTAGE_TOO_LOW, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_volt_too_high,
            { "Supply voltage too high", "zbee_zcl_hvac.pump_config_control.attr.alarm.volt_too_high", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_VOLTAGE_TOO_HIGH, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_pwr_missing_phase,
            { "Power missing phase", "zbee_zcl_hvac.pump_config_control.attr.alarm.pwr_missing_phase", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_PWR_MISSING_PHASE, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_press_too_low,
            { "System pressure too low", "zbee_zcl_hvac.pump_config_control.attr.alarm.press_too_low", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_PRESSURE_TOO_LOW, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_press_too_high,
            { "System pressure too high", "zbee_zcl_hvac.pump_config_control.attr.alarm.press_too_high", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_PRESSURE_TOO_HIGH, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_dry_running,
            { "Dry running", "zbee_zcl_hvac.pump_config_control.attr.alarm.dry_running", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_DRY_RUNNING, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_mtr_temp_too_high,
            { "Motor temperature too high", "zbee_zcl_hvac.pump_config_control.attr.alarm.mtr_temp_too_high", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_MTR_TEMP_TOO_HIGH, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_pump_mtr_fatal_fail,
            { "Pump motor has fatal failure", "zbee_zcl_hvac.pump_config_control.attr.alarm.mtr_fatal_fail", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_PUMP_MTR_FATAL_FAILURE, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_elec_temp_too_high,
            { "Electronic temperature too high", "zbee_zcl_hvac.pump_config_control.attr.alarm.elec_temp_too_high", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_ELEC_TEMP_TOO_HIGH, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_pump_block,
            { "Pump blocked", "zbee_zcl_hvac.pump_config_control.attr.alarm.pump_block", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_PUMP_BLOCK, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_sensor_fail,
            { "Sensor failure", "zbee_zcl_hvac.pump_config_control.attr.alarm.sensor_fail", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_SENSOR_FAILURE, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_elec_non_fatal_fail,
            { "Electronic non-fatal failure", "zbee_zcl_hvac.pump_config_control.attr.alarm.elec_non_fatal_fail", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_ELEC_NON_FATAL_FAILURE, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_fatal_fail,
            { "Electronic fatal failure", "zbee_zcl_hvac.pump_config_control.attr.alarm.elec_fatal_fail", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_ELEC_FATAL_FAILURE, NULL, HFILL } },

        { &hf_zbee_zcl_pump_config_control_alarm_gen_fault,
            { "Genral fault", "zbee_zcl_hvac.pump_config_control.attr.alarm.gen_fault", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            ZBEE_ZCL_PUMP_CONFIG_CONTROL_ALARM_GENERAL_FAULT, NULL, HFILL } }
        /* end Alarm Mask fields */
    };

    /* ZCL Pump Configuration and Control subtrees */
    static gint *ett[ZBEE_ZCL_PUMP_CONFIG_CONTROL_NUM_ETT];

    ett[0] = &ett_zbee_zcl_pump_config_control;
    ett[1] = &ett_zbee_zcl_pump_config_control_status;
    ett[2] = &ett_zbee_zcl_pump_config_control_alarm;

    /* Register the ZigBee ZCL Pump Configuration and Control cluster protocol name and description */
    proto_zbee_zcl_pump_config_control = proto_register_protocol("ZigBee ZCL Pump Configuration and Control", "ZCL Pump Configuration and Control", ZBEE_PROTOABBREV_ZCL_PUMP_CONFIG_CTRL);
    proto_register_field_array(proto_zbee_zcl_pump_config_control, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Pump Configuration and Control dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_PUMP_CONFIG_CTRL, dissect_zbee_zcl_pump_config_control, proto_zbee_zcl_pump_config_control);
} /*proto_register_zbee_zcl_pump_config_control*/

/**
 *Hands off the ZCL Pump Configuration and Control dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_pump_config_control(void)
{
    dissector_handle_t pump_config_ctrl_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    pump_config_ctrl_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_PUMP_CONFIG_CTRL);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_PUMP_CONFIG_CONTROL, pump_config_ctrl_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_pump_config_control,
                            ett_zbee_zcl_pump_config_control,
                            ZBEE_ZCL_CID_PUMP_CONFIG_CONTROL,
                            hf_zbee_zcl_pump_config_control_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_pump_config_control_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_pump_config_control*/


/* ########################################################################## */
/* #### (0x0202) FAN CONTROL CLUSTER ######################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_FAN_CONTROL_NUM_ETT                          1

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_FAN_CONTROL_FAN_MODE                 0x0000  /* Fan Mode */
#define ZBEE_ZCL_ATTR_ID_FAN_CONTROL_FAN_MODE_SEQUENCE        0x0001  /* Fan Mode Sequence */

/*Server commands received - none*/

/*Server commands generated - none*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_fan_control(void);
void proto_reg_handoff_zbee_zcl_fan_control(void);

/* Command Dissector Helpers */
static void dissect_zcl_fan_control_attr_data      (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_fan_control = -1;

static int hf_zbee_zcl_fan_control_attr_id = -1;
static int hf_zbee_zcl_fan_control_attr_fan_mode = -1;
static int hf_zbee_zcl_fan_control_attr_fan_mode_seq = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_fan_control = -1;

/* Attributes */
static const value_string zbee_zcl_fan_control_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_FAN_CONTROL_FAN_MODE,                "Fan Mode" },
    { ZBEE_ZCL_ATTR_ID_FAN_CONTROL_FAN_MODE_SEQUENCE,       "Fan Mode Sequence" },
    { 0, NULL }
};

/*Fan Mode Sequence Values*/
static const value_string zbee_zcl_fan_control_fan_mode_seq_names[] = {
    { 0x00,     "Low/Med/High" },
    { 0x01,     "Low/High" },
    { 0x02,     "Low/Med/High/Auto" },
    { 0x03,     "Low/High/Auto" },
    { 0x04,     "On/Auto" },
    { 0,        NULL}
};

/*Fan Mode Values*/
static const value_string zbee_zcl_fan_control_fan_mode_names[] = {
    { 0x00,     "Off" },
    { 0x01,     "Low" },
    { 0x02,     "Medium" },
    { 0x03,     "High" },
    { 0x04,     "On" },
    { 0x05,     "Auto" },
    { 0x06,     "Smart" },
    { 0,        NULL}
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Fan Control cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/

static int
dissect_zbee_zcl_fan_control(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_fan_control*/


/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
 *@param attr_id attribute identifier
 *@param data_type attribute data type
*/
void
dissect_zcl_fan_control_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_FAN_CONTROL_FAN_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_fan_control_attr_fan_mode, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_FAN_CONTROL_FAN_MODE_SEQUENCE:
            proto_tree_add_item(tree, hf_zbee_zcl_fan_control_attr_fan_mode_seq, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_fan_control_attr_data*/


/**
 *ZigBee ZCL Fan Control cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_fan_control(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_fan_control_attr_id,
            { "Attribute", "zbee_zcl_hvac.fan_control.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_fan_control_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_fan_control_attr_fan_mode,
            { "Fan Mode", "zbee_zcl_hvac.fan_control.attr.fan_mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_fan_control_fan_mode_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_fan_control_attr_fan_mode_seq,
            { "Fan Mode Sequence", "zbee_zcl_hvac.fan_control.attr.fan_mode_seq", FT_UINT8, BASE_HEX, VALS(zbee_zcl_fan_control_fan_mode_seq_names),
            0x00, NULL, HFILL } }
    };

    /* ZCL Fan Control subtrees */
    static gint *ett[ZBEE_ZCL_FAN_CONTROL_NUM_ETT];

    ett[0] = &ett_zbee_zcl_fan_control;

    /* Register the ZigBee ZCL Fan Control cluster protocol name and description */
    proto_zbee_zcl_fan_control = proto_register_protocol("ZigBee ZCL Fan Control", "ZCL Fan Control", ZBEE_PROTOABBREV_ZCL_FAN_CONTROL);
    proto_register_field_array(proto_zbee_zcl_fan_control, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Fan Control dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_FAN_CONTROL, dissect_zbee_zcl_fan_control, proto_zbee_zcl_fan_control);
} /*proto_register_zbee_zcl_fan_control*/

/**
 *Hands off the ZCL Fan Control dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_fan_control(void)
{
    dissector_handle_t fan_control_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    fan_control_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_FAN_CONTROL);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_FAN_CONTROL, fan_control_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_fan_control,
                            ett_zbee_zcl_fan_control,
                            ZBEE_ZCL_CID_FAN_CONTROL,
                            hf_zbee_zcl_fan_control_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_fan_control_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_fan_control*/


/* ########################################################################## */
/* #### (0x0203) DEHUMIDIFICATION CONTROL CLUSTER ########################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_DEHUMIDIFICATION_CONTROL_NUM_ETT                          1

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RELATIVE_HUMIDITY             0x0000  /* Relative Humidity */
#define ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_COOLING                 0x0001  /* Dehumidification Cooling */
#define ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RH_DEHUM_SETPOINT             0x0010  /* Relative Humidity Dehumidification Setpoint */
#define ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RELATIVE_HUMIDITY_MODE        0x0011  /* Relative Humidity Mode */
#define ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_LOCKOUT                 0x0012  /* Dehumidification Lockout */
#define ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_HYSTERESIS              0x0013  /* Dehumidification Hysteresis */
#define ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_MAX_COOL                0x0014  /* Dehumidification Max Cool */
#define ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RELATIVE_HUMIDITY_DISPLAY     0x0015  /* Relative Humidity Display */

/*Server commands received - none*/

/*Server commands generated - none*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_dehumidification_control(void);
void proto_reg_handoff_zbee_zcl_dehumidification_control(void);

/* Command Dissector Helpers */
static void dissect_zcl_dehumidification_control_attr_data      (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_dehumidification_control = -1;

static int hf_zbee_zcl_dehumidification_control_attr_id = -1;
static int hf_zbee_zcl_dehumidification_control_attr_rel_hum_mode = -1;
static int hf_zbee_zcl_dehumidification_control_attr_dehum_lockout = -1;
static int hf_zbee_zcl_dehumidification_control_attr_rel_hum_display = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_dehumidification_control = -1;

/* Attributes */
static const value_string zbee_zcl_dehumidification_control_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RELATIVE_HUMIDITY,            "Relative Humidity" },
    { ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_COOLING,                "Dehumidification Cooling" },
    { ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RH_DEHUM_SETPOINT,            "Relative Humidity Dehumidification Setpoint" },
    { ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RELATIVE_HUMIDITY_MODE,       "Relative Humidity Mode" },
    { ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_LOCKOUT,                "Dehumidification Lockout" },
    { ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_HYSTERESIS,             "Dehumidification Hysteresis" },
    { ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_MAX_COOL,               "Dehumidification Max Cool" },
    { ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RELATIVE_HUMIDITY_DISPLAY,    "Relative Humidity Display" },
    { 0, NULL }
};

/*Relative Humidity Mode Values*/
static const value_string zbee_zcl_dehumidification_control_rel_hum_mode_names[] = {
    { 0x00,     "Relative Humidity measured locally" },
    { 0x01,     "Relative Humidity updated over network" },
    { 0,        NULL}
};

/*Dehumidification Lockout Values*/
static const value_string zbee_zcl_dehumidification_control_dehum_lockout_names[] = {
    { 0x00,     "Dehumidification is not allowed" },
    { 0x01,     "Dehumidification is allowed" },
    { 0,        NULL}
};

/*Relative Humidity Display Values*/
static const value_string zbee_zcl_dehumidification_control_rel_hum_display_names[] = {
    { 0x00,     "Relative Humidity is not displayed" },
    { 0x01,     "Relative Humidity is displayed" },
    { 0,        NULL}
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Dehumidification Control cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/

static int
dissect_zbee_zcl_dehumidification_control(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);;
} /*dissect_zbee_zcl_dehumidification_control*/


/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
 *@param attr_id attribute identifier
 *@param data_type attribute data type
*/
void
dissect_zcl_dehumidification_control_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RELATIVE_HUMIDITY_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_dehumidification_control_attr_rel_hum_mode, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_LOCKOUT:
            proto_tree_add_item(tree, hf_zbee_zcl_dehumidification_control_attr_dehum_lockout, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RELATIVE_HUMIDITY_DISPLAY:
            proto_tree_add_item(tree, hf_zbee_zcl_dehumidification_control_attr_rel_hum_display, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RELATIVE_HUMIDITY:
        case ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_COOLING:
        case ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_RH_DEHUM_SETPOINT:
        case ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_HYSTERESIS:
        case ZBEE_ZCL_ATTR_ID_DEHUMIDIFICATION_CONTROL_DEHUM_MAX_COOL:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_dehumidification_control_attr_data*/


/**
 *ZigBee ZCL Dehumidification Control cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_dehumidification_control(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_dehumidification_control_attr_id,
            { "Attribute", "zbee_zcl_hvac.dehumidification_control.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_dehumidification_control_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_dehumidification_control_attr_rel_hum_mode,
            { "Relative Humidity Mode", "zbee_zcl_hvac.dehumidification_control.attr.rel_humidity_mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_dehumidification_control_rel_hum_mode_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_dehumidification_control_attr_dehum_lockout,
            { "Dehumidification Lockout", "zbee_zcl_hvac.dehumidification_control.attr.dehumidification_lockout", FT_UINT8, BASE_HEX, VALS(zbee_zcl_dehumidification_control_dehum_lockout_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_dehumidification_control_attr_rel_hum_display,
            { "Relative Humidity Display", "zbee_zcl_hvac.dehumidification_control.attr.rel_humidity_display", FT_UINT8, BASE_HEX, VALS(zbee_zcl_dehumidification_control_rel_hum_display_names),
            0x00, NULL, HFILL } }
    };

    /* ZCL Dehumidification Control subtrees */
    static gint *ett[ZBEE_ZCL_DEHUMIDIFICATION_CONTROL_NUM_ETT];

    ett[0] = &ett_zbee_zcl_dehumidification_control;

    /* Register the ZigBee ZCL Dehumidification Control cluster protocol name and description */
    proto_zbee_zcl_dehumidification_control = proto_register_protocol("ZigBee ZCL Dehumidification Control", "ZCL Dehumidification Control", ZBEE_PROTOABBREV_ZCL_DEHUMIDIFICATION_CONTROL);
    proto_register_field_array(proto_zbee_zcl_dehumidification_control, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Dehumidification Control dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_DEHUMIDIFICATION_CONTROL, dissect_zbee_zcl_dehumidification_control, proto_zbee_zcl_dehumidification_control);
} /*proto_register_zbee_zcl_dehumidification_control*/

/**
 *Hands off the ZCL Dehumidification Control dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_dehumidification_control(void)
{
    dissector_handle_t dehumidification_control_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    dehumidification_control_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_DEHUMIDIFICATION_CONTROL);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_DEHUMIDIFICATION_CONTROL, dehumidification_control_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_dehumidification_control,
                            ett_zbee_zcl_dehumidification_control,
                            ZBEE_ZCL_CID_DEHUMIDIFICATION_CONTROL,
                            hf_zbee_zcl_dehumidification_control_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_dehumidification_control_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_dehumidification_control*/


/* ########################################################################## */
/* #### (0x0204) THERMOSTAT USER INTERFACE CONFIGURATION CLUSTER ############ */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_THERMOSTAT_UI_CONFIG_NUM_ETT                          1

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_UI_CONFIG_TEMP_DISP_MODE           0x0000  /* Temperature Display Mode */
#define ZBEE_ZCL_ATTR_ID_THERMOSTAT_UI_CONFIG_KEYPAD_LOCKOUT           0x0001  /* Keypad Lockout */

/*Server commands received - none*/

/*Server commands generated - none*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_thermostat_ui_config(void);
void proto_reg_handoff_zbee_zcl_thermostat_ui_config(void);

/* Command Dissector Helpers */
static void dissect_zcl_thermostat_ui_config_attr_data      (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_thermostat_ui_config = -1;

static int hf_zbee_zcl_thermostat_ui_config_attr_id = -1;
static int hf_zbee_zcl_thermostat_ui_config_attr_temp_disp_mode = -1;
static int hf_zbee_zcl_thermostat_ui_config_attr_keypad_lockout = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_thermostat_ui_config = -1;

/* Attributes */
static const value_string zbee_zcl_thermostat_ui_config_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_UI_CONFIG_TEMP_DISP_MODE,         "Temperature Display Mode" },
    { ZBEE_ZCL_ATTR_ID_THERMOSTAT_UI_CONFIG_KEYPAD_LOCKOUT,         "Keypad Lockout" },
    { 0, NULL }
};

/*Temp Display Mode Values*/
static const value_string zbee_zcl_thermostat_ui_config_temp_disp_mode_names[] = {
    { 0x00,     "Temperature in degree Celsius" },
    { 0x01,     "Temperature in degree Fahrenheit" },
    { 0,        NULL}
};

/*Keypad Lockout Values*/
static const value_string zbee_zcl_thermostat_ui_config_keypad_lockout_names[] = {
    { 0x00,     "No lockout" },
    { 0x01,     "Level 1 lockout" },
    { 0x02,     "Level 2 lockout" },
    { 0x03,     "Level 3 lockout" },
    { 0x04,     "Level 4 lockout" },
    { 0x05,     "Level 5 lockout" },
    { 0,        NULL}
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Thermostat User Interface Configuration cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/

static int
dissect_zbee_zcl_thermostat_ui_config(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_thermostat_ui_config*/


/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
 *@param attr_id attribute identifier
 *@param data_type attribute data type
*/
void
dissect_zcl_thermostat_ui_config_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_THERMOSTAT_UI_CONFIG_TEMP_DISP_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_thermostat_ui_config_attr_temp_disp_mode, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_THERMOSTAT_UI_CONFIG_KEYPAD_LOCKOUT:
            proto_tree_add_item(tree, hf_zbee_zcl_thermostat_ui_config_attr_keypad_lockout, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_thermostat_ui_config_attr_data*/


/**
 *ZigBee ZCL Thermostat User Interface Configuration cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_thermostat_ui_config(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_thermostat_ui_config_attr_id,
            { "Attribute", "zbee_zcl_hvac.thermostat_ui_config.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_thermostat_ui_config_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_thermostat_ui_config_attr_temp_disp_mode,
            { "Temperature Display Mode", "zbee_zcl_hvac.thermostat_ui_config.attr.temp_disp_mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_thermostat_ui_config_temp_disp_mode_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_thermostat_ui_config_attr_keypad_lockout,
            { "Keypad Lockout", "zbee_zcl_hvac.thermostat_ui_config.attr.keypad_lockout", FT_UINT8, BASE_HEX, VALS(zbee_zcl_thermostat_ui_config_keypad_lockout_names),
            0x00, NULL, HFILL } }
    };

    /* ZCL Thermostat User Interface Configuration subtrees */
    static gint *ett[ZBEE_ZCL_THERMOSTAT_UI_CONFIG_NUM_ETT];
    ett[0] = &ett_zbee_zcl_thermostat_ui_config;

    /* Register the ZigBee ZCL Thermostat User Interface Configuration cluster protocol name and description */
    proto_zbee_zcl_thermostat_ui_config = proto_register_protocol("ZigBee ZCL Thermostat User Interface Configuration", "ZCL Thermostat User Interface Configuration", ZBEE_PROTOABBREV_ZCL_THERMOSTAT_UI_CONFIG);
    proto_register_field_array(proto_zbee_zcl_thermostat_ui_config, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Thermostat User Interface Configuration dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_THERMOSTAT_UI_CONFIG, dissect_zbee_zcl_thermostat_ui_config, proto_zbee_zcl_thermostat_ui_config);
} /*proto_register_zbee_zcl_thermostat_ui_config*/

/**
 *Hands off the ZCL Thermostat User Interface Configuration dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_thermostat_ui_config(void)
{
    dissector_handle_t thermostat_ui_config_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    thermostat_ui_config_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_THERMOSTAT_UI_CONFIG);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_THERMOSTAT_UI_CONFIG, thermostat_ui_config_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_thermostat_ui_config,
                            ett_zbee_zcl_thermostat_ui_config,
                            ZBEE_ZCL_CID_THERMOSTAT_UI_CONFIG,
                            hf_zbee_zcl_thermostat_ui_config_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_thermostat_ui_config_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_thermostat_ui_config*/

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
