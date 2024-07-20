/* packet-zbee-zcl-general.c
 * Dissector routines for the ZigBee ZCL General clusters like
 * Basic, Identify, OnOff ...
 * By Fabio Tarabelloni <fabio.tarabelloni@reloc.it>
 * Copyright 2013 RELOC s.r.l.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*  Include Files */
#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <wsutil/bits_ctz.h>
#include <wsutil/epochs.h>
#include <wsutil/utf8_entities.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"


/* ########################################################################## */
/* #### (0x0000) BASIC CLUSTER ############################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_BASIC_ZCL_VERSION              0x0000  /* ZCL Version */
#define ZBEE_ZCL_ATTR_ID_BASIC_APPL_VERSION             0x0001  /* Application Version */
#define ZBEE_ZCL_ATTR_ID_BASIC_STACK_VERSION            0x0002  /* Stack Version */
#define ZBEE_ZCL_ATTR_ID_BASIC_HW_VERSION               0x0003  /* HW Version */
#define ZBEE_ZCL_ATTR_ID_BASIC_MANUFACTURER_NAME        0x0004  /* Manufacturer Name */
#define ZBEE_ZCL_ATTR_ID_BASIC_MODEL_ID                 0x0005  /* Model Identifier */
#define ZBEE_ZCL_ATTR_ID_BASIC_DATE_CODE                0x0006  /* Date Code */
#define ZBEE_ZCL_ATTR_ID_BASIC_POWER_SOURCE             0x0007  /* Power Source */
#define ZBEE_ZCL_ATTR_ID_BASIC_LOCATION_DESCR           0x0010  /* Location Description */
#define ZBEE_ZCL_ATTR_ID_BASIC_PHY_ENVIRONMENT          0x0011  /* Physical Environment */
#define ZBEE_ZCL_ATTR_ID_BASIC_DEVICE_ENABLED           0x0012  /* Device Enabled */
#define ZBEE_ZCL_ATTR_ID_BASIC_ALARM_MASK               0x0013  /* Alarm Mask */
#define ZBEE_ZCL_ATTR_ID_BASIC_DISABLE_LOCAL_CFG        0x0014  /* Disable Local Config */
#define ZBEE_ZCL_ATTR_ID_BASIC_SW_BUILD_ID              0x4000  /* SW Build Id */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_BASIC_RESET_FACTORY_DEFAULTS    0x00  /* Reset to Factory Defaults */

/* Server Commands Generated - None */

/* Power Source Id */
#define ZBEE_ZCL_BASIC_PWR_SRC_UNKNOWN                  0x00    /* Unknown */
#define ZBEE_ZCL_BASIC_PWR_SRC_MAINS_1PH                0x01    /* Mains (single phase) */
#define ZBEE_ZCL_BASIC_PWR_SRC_MAINS_3PH                0x02    /* Mains (3 phase) */
#define ZBEE_ZCL_BASIC_PWR_SRC_BATTERY                  0x03    /* Battery */
#define ZBEE_ZCL_BASIC_PWR_SRC_DC_SRC                   0x04    /* DC source */
#define ZBEE_ZCL_BASIC_PWR_SRC_EMERGENCY_1              0x05    /* Emergency mains constantly powered */
#define ZBEE_ZCL_BASIC_PWR_SRC_EMERGENCY_2              0x06    /* Emergency mains and transfer switch */

/* Device Enable Values */
#define ZBEE_ZCL_BASIC_DISABLED                         0x00    /* Disabled */
#define ZBEE_ZCL_BASIC_ENABLED                          0x01    /* Enabled */

/* Alarm Mask bit-mask */
#define ZBEE_ZCL_BASIC_ALARM_GEN_HW_FAULT               0x01    /* General hardware fault */
#define ZBEE_ZCL_BASIC_ALARM_GEN_SW_FAULT               0x02    /* General software fault */
#define ZBEE_ZCL_BASIC_ALARM_RESERVED                   0xfc    /* Reserved */

/* Disable Local Config bit-mask */
#define ZBEE_ZCL_BASIC_DIS_LOC_CFG_RESET                0x01    /* Reset (to factory defaults) */
#define ZBEE_ZCL_BASIC_DIS_LOC_CFG_DEV_CFG              0x02    /* Device configuration */
#define ZBEE_ZCL_BASIC_DIS_LOC_CFG_RESERVED             0xfc    /* Reserved */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_basic(void);
void proto_reg_handoff_zbee_zcl_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_basic;

static int hf_zbee_zcl_basic_attr_id;
static int hf_zbee_zcl_basic_pwr_src;
static int hf_zbee_zcl_basic_dev_en;
static int hf_zbee_zcl_basic_alarm_mask;
static int hf_zbee_zcl_basic_alarm_mask_gen_hw_fault;
static int hf_zbee_zcl_basic_alarm_mask_gen_sw_fault;
static int hf_zbee_zcl_basic_alarm_mask_reserved;
static int hf_zbee_zcl_basic_disable_local_cfg;
static int hf_zbee_zcl_basic_disable_local_cfg_reset;
static int hf_zbee_zcl_basic_disable_local_cfg_device_cfg;
static int hf_zbee_zcl_basic_disable_local_cfg_reserved;
static int hf_zbee_zcl_basic_srv_rx_cmd_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_basic;
static int ett_zbee_zcl_basic_alarm_mask;
static int ett_zbee_zcl_basic_dis_local_cfg;

/* Attributes */
static const value_string zbee_zcl_basic_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_BASIC_ZCL_VERSION,           "ZCL Version" },
    { ZBEE_ZCL_ATTR_ID_BASIC_APPL_VERSION,          "Application Version" },
    { ZBEE_ZCL_ATTR_ID_BASIC_STACK_VERSION,         "Stack Version" },
    { ZBEE_ZCL_ATTR_ID_BASIC_HW_VERSION,            "HW Version" },
    { ZBEE_ZCL_ATTR_ID_BASIC_MANUFACTURER_NAME,     "Manufacturer Name" },
    { ZBEE_ZCL_ATTR_ID_BASIC_MODEL_ID,              "Model Identifier" },
    { ZBEE_ZCL_ATTR_ID_BASIC_DATE_CODE,             "Date Code" },
    { ZBEE_ZCL_ATTR_ID_BASIC_POWER_SOURCE,          "Power Source" },
    { ZBEE_ZCL_ATTR_ID_BASIC_LOCATION_DESCR,        "Location Description" },
    { ZBEE_ZCL_ATTR_ID_BASIC_PHY_ENVIRONMENT,       "Physical Environment" },
    { ZBEE_ZCL_ATTR_ID_BASIC_DEVICE_ENABLED,        "Device Enabled" },
    { ZBEE_ZCL_ATTR_ID_BASIC_ALARM_MASK,            "Alarm Mask" },
    { ZBEE_ZCL_ATTR_ID_BASIC_DISABLE_LOCAL_CFG,     "Disable Local Config" },
    { ZBEE_ZCL_ATTR_ID_BASIC_SW_BUILD_ID,           "Software Build Id" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_basic_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_BASIC_RESET_FACTORY_DEFAULTS, "Reset to Factory Defaults" },
    { 0, NULL }
};

/* Power Source Names */
static const value_string zbee_zcl_basic_pwr_src_names[] = {
    { ZBEE_ZCL_BASIC_PWR_SRC_UNKNOWN,       "Unknown" },
    { ZBEE_ZCL_BASIC_PWR_SRC_MAINS_1PH,     "Mains (single phase)" },
    { ZBEE_ZCL_BASIC_PWR_SRC_MAINS_3PH,     "Mains (3 phase)" },
    { ZBEE_ZCL_BASIC_PWR_SRC_BATTERY,       "Battery" },
    { ZBEE_ZCL_BASIC_PWR_SRC_DC_SRC,        "DC source" },
    { ZBEE_ZCL_BASIC_PWR_SRC_EMERGENCY_1,   "Emergency mains constantly powered" },
    { ZBEE_ZCL_BASIC_PWR_SRC_EMERGENCY_2,   "Emergency mains and transfer switch" },
    { 0, NULL }
};

/* Device Enable Names */
static const value_string zbee_zcl_basic_dev_en_names[] = {
    { ZBEE_ZCL_BASIC_DISABLED,      "Disabled" },
    { ZBEE_ZCL_BASIC_ENABLED,       "Enabled" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_basic
 *  DESCRIPTION
 *      ZigBee ZCL Basic cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      void *data          - pointer to ZCL packet structure.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_basic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_basic_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        if (tree) {
            /* Add the command ID. */
            proto_tree_add_item(tree, hf_zbee_zcl_basic_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        /*offset++;*/

        /* Call the appropriate command dissector */
        switch (cmd_id) {

            case ZBEE_ZCL_CMD_ID_BASIC_RESET_FACTORY_DEFAULTS:
                /* No payload */
                break;

            default:
                break;
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{

    static int * const alarm_mask[] = {
        &hf_zbee_zcl_basic_alarm_mask_gen_hw_fault,
        &hf_zbee_zcl_basic_alarm_mask_gen_sw_fault,
        &hf_zbee_zcl_basic_alarm_mask_reserved,
        NULL
    };

    static int * const local_cfg[] = {
        &hf_zbee_zcl_basic_disable_local_cfg_reset,
        &hf_zbee_zcl_basic_disable_local_cfg_device_cfg,
        &hf_zbee_zcl_basic_disable_local_cfg_reserved,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_BASIC_POWER_SOURCE:
            proto_tree_add_item(tree, hf_zbee_zcl_basic_pwr_src, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BASIC_DEVICE_ENABLED:
            proto_tree_add_item(tree, hf_zbee_zcl_basic_dev_en, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BASIC_ALARM_MASK:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_basic_alarm_mask , ett_zbee_zcl_basic_alarm_mask, alarm_mask, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BASIC_DISABLE_LOCAL_CFG:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_basic_disable_local_cfg , ett_zbee_zcl_basic_dis_local_cfg, local_cfg, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BASIC_ZCL_VERSION:
        case ZBEE_ZCL_ATTR_ID_BASIC_APPL_VERSION:
        case ZBEE_ZCL_ATTR_ID_BASIC_STACK_VERSION:
        case ZBEE_ZCL_ATTR_ID_BASIC_HW_VERSION:
        case ZBEE_ZCL_ATTR_ID_BASIC_MANUFACTURER_NAME:
        case ZBEE_ZCL_ATTR_ID_BASIC_MODEL_ID:
        case ZBEE_ZCL_ATTR_ID_BASIC_DATE_CODE:
        case ZBEE_ZCL_ATTR_ID_BASIC_PHY_ENVIRONMENT:
        case ZBEE_ZCL_ATTR_ID_BASIC_LOCATION_DESCR:
        case ZBEE_ZCL_ATTR_ID_BASIC_SW_BUILD_ID:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_basic_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_basic
 *  DESCRIPTION
 *      ZigBee ZCL Basic cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_basic(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_basic_attr_id,
            { "Attribute", "zbee_zcl_general.basic.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_basic_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_basic_pwr_src,
            { "Power Source", "zbee_zcl_general.basic.attr.pwr_src", FT_UINT8, BASE_HEX, VALS(zbee_zcl_basic_pwr_src_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_basic_dev_en,
            { "Device Enabled", "zbee_zcl_general.basic.attr.dev_en", FT_UINT8, BASE_HEX, VALS(zbee_zcl_basic_dev_en_names),
            0x00, NULL, HFILL } },

        /* start Alarm Mask fields */
        { &hf_zbee_zcl_basic_alarm_mask,
            { "Alarm Mask",  "zbee_zcl_general.basic.attr.alarm_mask", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL } },

        { &hf_zbee_zcl_basic_alarm_mask_gen_hw_fault,
            { "General hardware fault", "zbee_zcl_general.basic.attr.alarm_mask.gen_hw_fault", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_BASIC_ALARM_GEN_HW_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_basic_alarm_mask_gen_sw_fault,
            { "General software fault", "zbee_zcl_general.basic.attr.alarm_mask.gen_sw_fault", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_BASIC_ALARM_GEN_SW_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_basic_alarm_mask_reserved,
            { "Reserved", "zbee_zcl_general.basic.attr.alarm_mask.reserved", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_BASIC_ALARM_RESERVED, NULL, HFILL } },
        /* end Alarm Mask fields */

        /* start Disable Local Config fields */
        { &hf_zbee_zcl_basic_disable_local_cfg,
            { "Disable Local Config",  "zbee_zcl_general.basic.attr.dis_loc_cfg", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL } },

        { &hf_zbee_zcl_basic_disable_local_cfg_reset,
            { "Reset (to factory defaults)", "zbee_zcl_general.basic.attr.dis_loc_cfg.reset", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_BASIC_DIS_LOC_CFG_RESET , NULL, HFILL } },

        { &hf_zbee_zcl_basic_disable_local_cfg_device_cfg,
            { "Device configuration", "zbee_zcl_general.basic.attr.dis_loc_cfg.dev_cfg", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_BASIC_DIS_LOC_CFG_DEV_CFG , NULL, HFILL } },

        { &hf_zbee_zcl_basic_disable_local_cfg_reserved,
            { "Reserved", "zbee_zcl_general.basic.attr.dis_loc_cfg.reserved", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_BASIC_DIS_LOC_CFG_RESERVED , NULL, HFILL } },
        /* end Disable Local Config fields */

        { &hf_zbee_zcl_basic_srv_rx_cmd_id,
          { "Command", "zbee_zcl_general.basic.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_basic_srv_rx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Basic subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_basic,
        &ett_zbee_zcl_basic_alarm_mask,
        &ett_zbee_zcl_basic_dis_local_cfg
    };

    /* Register the ZigBee ZCL Basic cluster protocol name and description */
    proto_zbee_zcl_basic = proto_register_protocol("ZigBee ZCL Basic", "ZCL Basic", ZBEE_PROTOABBREV_ZCL_BASIC);
    proto_register_field_array(proto_zbee_zcl_basic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Basic dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_BASIC, dissect_zbee_zcl_basic, proto_zbee_zcl_basic);
} /*proto_register_zbee_zcl_basic*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_basic
 *  DESCRIPTION
 *      Hands off the ZCL Basic dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_basic(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_BASIC,
                            proto_zbee_zcl_basic,
                            ett_zbee_zcl_basic,
                            ZBEE_ZCL_CID_BASIC,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_basic_attr_id,
                            hf_zbee_zcl_basic_attr_id,
                            hf_zbee_zcl_basic_srv_rx_cmd_id,
                            -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_basic*/



/* ########################################################################## */
/* #### (0x0001) POWER CONFIGURATION CLUSTER ################################ */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE           0x0000  /* Mains voltage */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_FREQUENCY         0x0001  /* Mains frequency */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_ALARM_MASK        0x0010  /* Mains Alarm Mask */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE_MIN_THR   0x0011  /* Mains Voltage Min Threshold */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE_MAX_THR   0x0012  /* Mains Voltage Max Threshold */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE_DWELL_TP  0x0013  /* Mains Voltage Dwell Trip Point */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_VOLTAGE         0x0020  /* Battery Voltage */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_PERCENTAGE      0x0021  /* Battery Percentage Remaining */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_MANUFACTURER    0x0030  /* Battery Manufacturer */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_SIZE            0x0031  /* Battery Size */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_AH_RATING       0x0032  /* Battery AHr Rating */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_QUANTITY        0x0033  /* Battery Quantity */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_RATED_VOLTAGE   0x0034  /* Battery Rated Voltage */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_ALARM_MASK      0x0035  /* Battery Alarm Mask */
#define ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_VOLTAGE_MIN_THR 0x0036  /* Battery Voltage Min Threshold */

/* Server Commands Received - None */

/* Server Commands Generated - None */

/* Mains Alarm Mask bit-mask */
#define ZBEE_ZCL_POWER_CONF_MAINS_ALARM_LOW         0x01    /* Mains voltage too low */
#define ZBEE_ZCL_POWER_CONF_MAINS_ALARM_HIGH        0x02    /* Mains voltage too high */
#define ZBEE_ZCL_POWER_CONF_MAINS_ALARM_RESERVED    0xfc    /* Reserved */

/* Battery Size values */
#define ZBEE_ZCL_POWER_CONF_BAT_TYPE_NO_BAT         0x00    /* No battery */
#define ZBEE_ZCL_POWER_CONF_BAT_TYPE_BUILT_IN       0x01    /* Built in */
#define ZBEE_ZCL_POWER_CONF_BAT_TYPE_OTHER          0x02    /* Other */
#define ZBEE_ZCL_POWER_CONF_BAT_TYPE_AA             0x03    /* AA */
#define ZBEE_ZCL_POWER_CONF_BAT_TYPE_AAA            0x04    /* AAA */
#define ZBEE_ZCL_POWER_CONF_BAT_TYPE_C              0x05    /* C */
#define ZBEE_ZCL_POWER_CONF_BAT_TYPE_D              0x06    /* D */
#define ZBEE_ZCL_POWER_CONF_BAT_TYPE_UNKNOWN        0xFF    /* Unknown */

/* Battery alarm mask bit-mask */
#define ZBEE_ZCL_POWER_CONF_BATTERY_ALARM_LOW       0x01    /* Battery voltage too low */
#define ZBEE_ZCL_POWER_CONF_BATTERY_ALARM_RESERVED  0xfe    /* Reserved */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_power_config(void);
void proto_reg_handoff_zbee_zcl_power_config(void);

/* Command Dissector Helpers */
static void dissect_zcl_power_config_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_power_config;
static int hf_zbee_zcl_power_config_attr_id;
static int hf_zbee_zcl_power_config_batt_type;
static int hf_zbee_zcl_power_config_mains_alarm_mask;
static int hf_zbee_zcl_power_config_mains_alarm_mask_low;
static int hf_zbee_zcl_power_config_mains_alarm_mask_high;
static int hf_zbee_zcl_power_config_mains_alarm_mask_reserved;
static int hf_zbee_zcl_power_config_batt_alarm_mask;
static int hf_zbee_zcl_power_config_batt_alarm_mask_low;
static int hf_zbee_zcl_power_config_batt_alarm_mask_reserved;
static int hf_zbee_zcl_power_config_mains_voltage;
static int hf_zbee_zcl_power_config_mains_frequency;
static int hf_zbee_zcl_power_config_mains_voltage_min_thr;
static int hf_zbee_zcl_power_config_mains_voltage_max_thr;
static int hf_zbee_zcl_power_config_mains_voltage_dwell_tp;
static int hf_zbee_zcl_power_config_batt_voltage;
static int hf_zbee_zcl_power_config_batt_percentage;
static int hf_zbee_zcl_power_config_batt_ah_rating;
static int hf_zbee_zcl_power_config_batt_rated_voltage;
static int hf_zbee_zcl_power_config_batt_voltage_min_thr;
/* Initialize the subtree pointers */
static int ett_zbee_zcl_power_config;
static int ett_zbee_zcl_power_config_mains_alarm_mask;
static int ett_zbee_zcl_power_config_batt_alarm_mask;

/* Attributes */
static const value_string zbee_zcl_power_config_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE,           "Mains Voltage" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_FREQUENCY,         "Mains Frequency" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_ALARM_MASK,        "Mains Alarm Mask" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE_MIN_THR,   "Mains Voltage Min Threshold" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE_MAX_THR,   "Mains Voltage Max Threshold" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE_DWELL_TP,  "Mains Voltage Dwell Trip Point" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_VOLTAGE,         "Battery Voltage" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_PERCENTAGE,      "Battery Percentage Remaining" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_MANUFACTURER,    "Battery Manufacturer" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_SIZE,            "Battery Size" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_AH_RATING,       "Battery AHr Rating" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_QUANTITY,        "Battery Quantity" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_RATED_VOLTAGE,   "Battery Rated Voltage" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_ALARM_MASK,      "Battery Alarm Mask" },
    { ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_VOLTAGE_MIN_THR, "Battery Voltage Minimum Threshold" },
    { 0, NULL }
};


/* Battery size Names */
static const value_string zbee_zcl_power_config_batt_type_names[] = {
    { ZBEE_ZCL_POWER_CONF_BAT_TYPE_NO_BAT,         "No battery" },
    { ZBEE_ZCL_POWER_CONF_BAT_TYPE_BUILT_IN,       "Built in" },
    { ZBEE_ZCL_POWER_CONF_BAT_TYPE_OTHER,          "Other" },
    { ZBEE_ZCL_POWER_CONF_BAT_TYPE_AA,             "AA" },
    { ZBEE_ZCL_POWER_CONF_BAT_TYPE_AAA,            "AAA" },
    { ZBEE_ZCL_POWER_CONF_BAT_TYPE_C,              "C" },
    { ZBEE_ZCL_POWER_CONF_BAT_TYPE_D,              "D" },
    { ZBEE_ZCL_POWER_CONF_BAT_TYPE_UNKNOWN,        "Unknown" },
    { 0, NULL }
};


/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_power_config
 *  DESCRIPTION
 *      ZigBee ZCL power configuration cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_power_config(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_power_config*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *    decode_power_conf_voltage
 *  DESCRIPTION
 *    this function decodes voltage values
 *  PARAMETERS
 *      unsigned *s        - string to display
 *      uint32_t value   - value to decode
 *  RETURNS
 *    none
 *---------------------------------------------------------------
 */
static void
decode_power_conf_voltage(char *s, uint32_t value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%d.%d [V]", value/10, value%10);
    return;
} /*decode_power_conf_voltage*/

  /*FUNCTION:------------------------------------------------------
  *  NAME
  *    decode_power_conf_percentage
  *  DESCRIPTION
  *    this function decodes percentage values
  *  PARAMETERS
  *      unsigned *s        - string to display
  *      uint32_t value   - value to decode
  *  RETURNS
  *    none
  *---------------------------------------------------------------
  */
static void
decode_power_conf_percentage(char *s, uint32_t value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%.1f [%%]", value/2.0);
    return;
} /*decode_power_conf_percentage*/

  /*FUNCTION:------------------------------------------------------
 *  NAME
 *    decode_power_conf_frequency
 *  DESCRIPTION
 *    this function decodes mains frequency values
 *  PARAMETERS
 *      unsigned *s        - string to display
 *      uint32_t value   - value to decode
 *  RETURNS
 *    none
 *---------------------------------------------------------------
 */
static void
decode_power_conf_frequency(char *s, uint32_t value)
{
    if(value == 0x00)
        snprintf(s, ITEM_LABEL_LENGTH, "Frequency too low to be measured (or DC supply)");
    else if(value == 0xfe)
        snprintf(s, ITEM_LABEL_LENGTH, "Frequency too high to be measured");
    else if (value == 0xff)
        snprintf(s, ITEM_LABEL_LENGTH, "Frequency could not be measured");
    else
        snprintf(s, ITEM_LABEL_LENGTH, "%d [Hz]", value*2);
    return;
} /*decode_power_conf_frequency*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *    decode_power_conf_batt_AHr
 *  DESCRIPTION
 *    this function decodes battery capacity values
 *  PARAMETERS
 *      unsigned *s        - string to display
 *      uint32_t value   - value to decode
 *  RETURNS
 *    none
 *---------------------------------------------------------------
 */
static void
decode_power_conf_batt_AHr(char *s, uint32_t value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%d [mAHr]", value*10);
    return;
} /*decode_power_conf_batt_AHr*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_power_config_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_power_config_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    proto_item *it;
    static int * const mains_alarm_mask[] = {
        &hf_zbee_zcl_power_config_mains_alarm_mask_low,
        &hf_zbee_zcl_power_config_mains_alarm_mask_high,
        &hf_zbee_zcl_power_config_mains_alarm_mask_reserved,
        NULL
    };

    static int * const batt_alarm_mask[] = {
        &hf_zbee_zcl_power_config_batt_alarm_mask_low,
        &hf_zbee_zcl_power_config_batt_alarm_mask_reserved,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE:
            proto_tree_add_item(tree, hf_zbee_zcl_power_config_mains_voltage, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_FREQUENCY:
            proto_tree_add_item(tree, hf_zbee_zcl_power_config_mains_frequency, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_ALARM_MASK:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_power_config_mains_alarm_mask, ett_zbee_zcl_power_config_mains_alarm_mask, mains_alarm_mask, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE_MIN_THR:
            proto_tree_add_item(tree, hf_zbee_zcl_power_config_mains_voltage_min_thr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE_MAX_THR:
            proto_tree_add_item(tree, hf_zbee_zcl_power_config_mains_voltage_max_thr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_MAINS_VOLTAGE_DWELL_TP:
            it = proto_tree_add_item(tree, hf_zbee_zcl_power_config_mains_voltage_dwell_tp, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(it, " [s]");
            *offset += 2;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_SIZE:
            proto_tree_add_item(tree, hf_zbee_zcl_power_config_batt_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_VOLTAGE:
            proto_tree_add_item(tree, hf_zbee_zcl_power_config_batt_voltage, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_PERCENTAGE:
            proto_tree_add_item(tree, hf_zbee_zcl_power_config_batt_percentage, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_AH_RATING:
            proto_tree_add_item(tree, hf_zbee_zcl_power_config_batt_ah_rating, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_RATED_VOLTAGE:
            proto_tree_add_item(tree, hf_zbee_zcl_power_config_batt_rated_voltage, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_ALARM_MASK:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_power_config_batt_alarm_mask, ett_zbee_zcl_power_config_batt_alarm_mask, batt_alarm_mask, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_VOLTAGE_MIN_THR:
            proto_tree_add_item(tree, hf_zbee_zcl_power_config_batt_voltage_min_thr, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_MANUFACTURER:
        case ZBEE_ZCL_ATTR_ID_POWER_CONF_BATTERY_QUANTITY:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_power_config_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_power_config
 *  DESCRIPTION
 *      ZigBee ZCL power configuration cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_power_config(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_power_config_attr_id,
            { "Attribute", "zbee_zcl_general.power_config.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_power_config_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_batt_type,
            { "Battery Type", "zbee_zcl_general.power_config.attr.batt_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_power_config_batt_type_names),
            0x00, NULL, HFILL } },

        /* start mains Alarm Mask fields */
        { &hf_zbee_zcl_power_config_mains_alarm_mask,
            { "Mains Alarm Mask",  "zbee_zcl_general.power_config.attr.mains_alarm_mask", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_mains_alarm_mask_low,
            { "Mains Voltage too low", "zbee_zcl_general.power_config.attr.mains_alarm_mask.mains_too_low", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_POWER_CONF_MAINS_ALARM_LOW, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_mains_alarm_mask_high,
            { "Mains Voltage too high", "zbee_zcl_general.power_config.attr.mains_alarm_mask.mains_too_high", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_POWER_CONF_MAINS_ALARM_HIGH, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_mains_alarm_mask_reserved,
            { "Reserved", "zbee_zcl_general.power_config.attr.mains_alarm_mask.reserved", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_POWER_CONF_MAINS_ALARM_RESERVED, NULL, HFILL } },
        /* end mains Alarm Mask fields */

        /* start battery Alarm Mask fields */
        { &hf_zbee_zcl_power_config_batt_alarm_mask,
            { "Battery Alarm Mask",  "zbee_zcl_general.power_config.attr.batt_alarm_mask", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_batt_alarm_mask_low,
            { "Battery Voltage too low", "zbee_zcl_general.power_config.batt_attr.alarm_mask.batt_too_low", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_POWER_CONF_BATTERY_ALARM_LOW, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_batt_alarm_mask_reserved,
            { "Reserved", "zbee_zcl_general.power_config.attr.batt_alarm_mask.reserved", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_POWER_CONF_BATTERY_ALARM_RESERVED, NULL, HFILL } },
        /* end battery Alarm Mask fields */

        { &hf_zbee_zcl_power_config_mains_voltage,
            { "Measured Mains Voltage", "zbee_zcl_general.power_config.attr.mains_voltage", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_power_conf_voltage),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_mains_frequency,
            { "Measured Mains Frequency", "zbee_zcl_general.power_config.attr.mains_frequency", FT_UINT8, BASE_CUSTOM, CF_FUNC(decode_power_conf_frequency),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_mains_voltage_min_thr,
            { "Mains Voltage Minimum Threshold", "zbee_zcl_general.power_config.attr.mains_volt_min", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_power_conf_voltage),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_mains_voltage_max_thr,
            { "Mains Voltage Maximum Threshold", "zbee_zcl_general.power_config.attr.mains_volt_max", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_power_conf_voltage),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_batt_voltage,
            { "Measured Battery Voltage", "zbee_zcl_general.power_config.attr.batt_voltage", FT_UINT8, BASE_CUSTOM, CF_FUNC(decode_power_conf_voltage),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_batt_percentage,
            { "Remaining Battery Percentage", "zbee_zcl_general.power_config.attr.batt_percentage", FT_UINT8, BASE_CUSTOM, CF_FUNC(decode_power_conf_percentage),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_batt_ah_rating,
            { "Battery Capacity", "zbee_zcl_general.power_config.attr.batt_AHr", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_power_conf_batt_AHr),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_batt_rated_voltage,
            { "Battery Rated Voltage", "zbee_zcl_general.power_config.attr.batt_rated_voltage", FT_UINT8, BASE_CUSTOM, CF_FUNC(decode_power_conf_voltage),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_batt_voltage_min_thr,
            { "Battery Voltage Minimum Threshold", "zbee_zcl_general.power_config.attr.batt_voltage_min_thr", FT_UINT8, BASE_CUSTOM, CF_FUNC(decode_power_conf_voltage),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_power_config_mains_voltage_dwell_tp,
            { "Mains Voltage Dwell Trip Point", "zbee_zcl_general.power_config.attr.mains_dwell_tp", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },
    };

    /* ZCL power configuration subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_power_config,
        &ett_zbee_zcl_power_config_mains_alarm_mask,
        &ett_zbee_zcl_power_config_batt_alarm_mask
    };

    /* Register the ZigBee ZCL power configuration cluster protocol name and description */
    proto_zbee_zcl_power_config = proto_register_protocol("ZigBee ZCL Power Configuration", "ZCL Power Configuration", ZBEE_PROTOABBREV_ZCL_POWER_CONFIG);
    proto_register_field_array(proto_zbee_zcl_power_config, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL power configuration dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_POWER_CONFIG, dissect_zbee_zcl_power_config, proto_zbee_zcl_power_config);
} /*proto_register_zbee_zcl_power_config*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_power_config
 *  DESCRIPTION
 *      Hands off the ZCL power configuration dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_power_config(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_POWER_CONFIG,
                            proto_zbee_zcl_power_config,
                            ett_zbee_zcl_power_config,
                            ZBEE_ZCL_CID_POWER_CONFIG,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_power_config_attr_id,
                            hf_zbee_zcl_power_config_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_power_config_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_power_config*/


/* ########################################################################## */
/* #### (0x0002) DEVICE TEMPERATURE CONFIGURATION CLUSTER ################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_CURRENT_TEMP                  0x0000  /*Current Temperature*/
#define ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_MIN_TEMP_EXP                  0x0001  /*Min Temperature Experienced*/
#define ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_MAX_TEMP_EXP                  0x0002  /*Max Temperature Experienced*/
#define ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_OVER_TEMP_TOTAL_DWELL         0x0003  /*Over Temperature Total Dwell*/

#define ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_DEVICE_TEMP_ALARM_MASK        0x0010  /*Device Temperature Alarm Mask*/
#define ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_LOW_TEMP_THRESHOLD            0x0011  /*Low Temperature Threshold*/
#define ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_HIGH_TEMP_THRESHOLD           0x0012  /*High Temperature Threshold*/
#define ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_LOW_TEMP_DWELL_TRIP_POINT     0x0013  /*Low Temperature Dwell Trip Point*/
#define ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_HIGH_TEMP_DWELL_TRIP_POINT    0x0014  /*High Temperature Dwell Trip Point*/

/*Server commands received - none*/

/*Server commands generated - none*/

/*Device Temperature Alarm Mask Value*/
#define ZBEE_ZCL_DEVICE_TEMPERATURE_CONFIGURATION_DEVICE_TEMP_ALARM_MASK_TOO_LOW        0x01    /*Mains Voltage too low*/
#define ZBEE_ZCL_DEVICE_TEMPERATURE_CONFIGURATION_DEVICE_TEMP_ALARM_MASK_TOO_HIGH       0x02    /*Mains Voltage too high*/
#define ZBEE_ZCL_DEVICE_TEMPERATURE_CONFIGURATION_DEVICE_TEMP_ALARM_MASK_RESERVED       0xfc    /*Mains Voltage reserved*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_device_temperature_configuration(void);
void proto_reg_handoff_zbee_zcl_device_temperature_configuration(void);

/* Command Dissector Helpers */
static void dissect_zcl_device_temperature_configuration_attr_data      (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_device_temperature_configuration;

static int hf_zbee_zcl_device_temperature_configuration_attr_id;
static int hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask;
static int hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask_too_low;
static int hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask_too_high;
static int hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask_reserved;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_device_temperature_configuration;
static int ett_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask;

/* Attributes */
static const value_string zbee_zcl_device_temperature_configuration_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_CURRENT_TEMP,                   "Current Temperature" },
    { ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_MIN_TEMP_EXP,                   "Min Temperature Experienced" },
    { ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_MAX_TEMP_EXP,                   "Max Temperature Experienced" },
    { ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_OVER_TEMP_TOTAL_DWELL,          "Over Temperature Total Dwell" },
    { ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_DEVICE_TEMP_ALARM_MASK,         "Device Temperature Alarm Mask" },
    { ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_LOW_TEMP_THRESHOLD,             "Low Temperature Threshold" },
    { ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_HIGH_TEMP_THRESHOLD,            "High Temperature Threshold" },
    { ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_LOW_TEMP_DWELL_TRIP_POINT,      "Low Temperature Dwell Trip Point" },
    { ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_HIGH_TEMP_DWELL_TRIP_POINT,     "High Temperature Dwell Trip Point" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_device_temperature_configuration
 *  DESCRIPTION
 *      ZigBee ZCL Device Temperature Configuration cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_device_temperature_configuration(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
	return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_device_temperature_configuration*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_device_temperature_configuration_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_device_temperature_configuration_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    static int * const device_temp_alarm_mask[] = {
        &hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask_too_low,
        &hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask_too_high,
        &hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask_reserved,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_DEVICE_TEMP_ALARM_MASK:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask, ett_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask, device_temp_alarm_mask, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_CURRENT_TEMP:
        case ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_MIN_TEMP_EXP:
        case ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_MAX_TEMP_EXP:
        case ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_OVER_TEMP_TOTAL_DWELL:
        case ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_LOW_TEMP_THRESHOLD:
        case ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_HIGH_TEMP_THRESHOLD:
        case ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_LOW_TEMP_DWELL_TRIP_POINT:
        case ZBEE_ZCL_ATTR_ID_DEVICE_TEMPERATURE_CONFIGURATION_HIGH_TEMP_DWELL_TRIP_POINT:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_device_temperature_configuration_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_device_temperature_configuration
 *  DESCRIPTION
 *      ZigBee ZCL Device Temperature Configuration cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_device_temperature_configuration(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_device_temperature_configuration_attr_id,
            { "Attribute", "zbee_zcl_general.device_temperature_configuration.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_device_temperature_configuration_attr_names),
            0x00, NULL, HFILL } },

        /* start Device Temperature Alarm Mask fields */
        { &hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask,
            { "Device Temperature Alarm Mask", "zbee_zcl_general.device_temperature_configuration.attr.device_temp_alarm_mask", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask_too_low,
            { "Device Temperature too low", "zbee_zcl_general.device_temperature_configuration.attr.device_temp_alarm_mask.too_low", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_DEVICE_TEMPERATURE_CONFIGURATION_DEVICE_TEMP_ALARM_MASK_TOO_LOW, NULL, HFILL } },

        { &hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask_too_high,
            { "Device Temperature too high", "zbee_zcl_general.device_temperature_configuration.attr.device_temp_alarm_mask.too_high", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_DEVICE_TEMPERATURE_CONFIGURATION_DEVICE_TEMP_ALARM_MASK_TOO_HIGH, NULL, HFILL } },

        { &hf_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask_reserved,
            { "Reserved", "zbee_zcl_general.device_temperature_configuration.attr.device_temp_alarm_mask.reserved", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_DEVICE_TEMPERATURE_CONFIGURATION_DEVICE_TEMP_ALARM_MASK_RESERVED, NULL, HFILL } }
        /* end Device Temperature Alarm Mask fields */
    };

    /* ZCL Device Temperature Configuration subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_device_temperature_configuration,
        &ett_zbee_zcl_device_temperature_configuration_device_temp_alarm_mask
    };

    /* Register the ZigBee ZCL Device Temperature Configuration cluster protocol name and description */
    proto_zbee_zcl_device_temperature_configuration = proto_register_protocol("ZigBee ZCL Device Temperature Configuration", "ZCL Device Temperature Configuration", ZBEE_PROTOABBREV_ZCL_DEVICE_TEMP_CONFIG);
    proto_register_field_array(proto_zbee_zcl_device_temperature_configuration, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Device Temperature Configuration dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_DEVICE_TEMP_CONFIG, dissect_zbee_zcl_device_temperature_configuration, proto_zbee_zcl_device_temperature_configuration);
} /*proto_register_zbee_zcl_device_temperature_configuration*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_device_temperature_configuration
 *  DESCRIPTION
 *      Hands off the ZCL Device Temperature Configuration dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_device_temperature_configuration(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_DEVICE_TEMP_CONFIG,
                            proto_zbee_zcl_device_temperature_configuration,
                            ett_zbee_zcl_device_temperature_configuration,
                            ZBEE_ZCL_CID_DEVICE_TEMP_CONFIG,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_device_temperature_configuration_attr_id,
                            hf_zbee_zcl_device_temperature_configuration_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_device_temperature_configuration_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_device_temperature_configuration*/


/* ########################################################################## */
/* #### (0x0003) IDENTIFY CLUSTER ########################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_IDENTIFY_IDENTIFY_TIME         0x0000  /* Identify Time */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY               0x00  /* Identify */
#define ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY         0x01  /* Identify Query */
#define ZBEE_ZCL_CMD_ID_IDENTIFY_TRIGGER_EFFECT         0x40  /* Trigger Effect */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY_RSP     0x00  /* Identify Query Response */


/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_identify(void);
void proto_reg_handoff_zbee_zcl_identify(void);

/* Command Dissector Helpers */
static void dissect_zcl_identify_identify               (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_identify_identifyqueryrsp       (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_identify_triggereffect          (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_identify_attr_data              (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_identify;

static int hf_zbee_zcl_identify_attr_id;
static int hf_zbee_zcl_identify_identify_time;
static int hf_zbee_zcl_identify_identify_timeout;
static int hf_zbee_zcl_identify_effect_id;
static int hf_zbee_zcl_identify_effect_variant;
static int hf_zbee_zcl_identify_srv_rx_cmd_id;
static int hf_zbee_zcl_identify_srv_tx_cmd_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_identify;

/* Attributes */
static const value_string zbee_zcl_identify_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_IDENTIFY_IDENTIFY_TIME,      "Identify Time" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_identify_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY,            "Identify" },
    { ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY,      "Identify Query" },
    { ZBEE_ZCL_CMD_ID_IDENTIFY_TRIGGER_EFFECT,      "Trigger Effect" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_identify_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY_RSP,  "Identify Query Response" },
    { 0, NULL }
};

/* Trigger Effects */
static const value_string zbee_zcl_identify_effect_id_names[] = {
    { 0x00,     "Blink" },
    { 0x01,     "Breathe" },
    { 0x02,     "Okay" },
    { 0x0b,     "Channel change" },
    { 0xfe,     "Finish" },
    { 0xff,     "Stop" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_identify
 *  DESCRIPTION
 *      ZigBee ZCL Identify cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      void *data          - pointer to ZCL packet structure.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_identify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_identify_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_identify_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_identify, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY:
                    dissect_zcl_identify_identify(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY:
                    /* without payload*/
                    break;

                case ZBEE_ZCL_CMD_ID_IDENTIFY_TRIGGER_EFFECT:
                    dissect_zcl_identify_triggereffect(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_identify_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_identify_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_identify, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY_RSP:
                    dissect_zcl_identify_identifyqueryrsp(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_identify*/


 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_identify_identify
 *  DESCRIPTION
 *      this function decodes the Identify payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_identify_identify(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Identify Time" field */
    proto_tree_add_item(tree, hf_zbee_zcl_identify_identify_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_identify_identify*/


 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_identify_identifyqueryrsp
 *  DESCRIPTION
 *      this function decodes the IdentifyQueryResponse payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_identify_identifyqueryrsp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Identify Timeout" field */
    proto_tree_add_item(tree, hf_zbee_zcl_identify_identify_timeout, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_identify_identifyqueryrsp*/

 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_identify_triggereffect
 *  DESCRIPTION
 *      this function decodes the Trigger Effect payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_identify_triggereffect(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Trigger Effect Id" field */
    proto_tree_add_item(tree, hf_zbee_zcl_identify_effect_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Trigger Effect Variant" field */
    proto_tree_add_item(tree, hf_zbee_zcl_identify_effect_variant, tvb, *offset, 1, ENC_NA);
    *offset += 1;

} /*dissect_zcl_identify_triggereffect*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_identify_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_identify_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_IDENTIFY_IDENTIFY_TIME:
            proto_tree_add_item(tree, hf_zbee_zcl_identify_identify_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_identify_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_identify
 *  DESCRIPTION
 *      ZigBee ZCL Identify cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_identify(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_identify_attr_id,
            { "Attribute", "zbee_zcl_general.identify.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_identify_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_identify_identify_time,
            { "Identify Time", "zbee_zcl_general.identify.attr.identify_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_seconds),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_identify_identify_timeout,
            { "Identify Timeout", "zbee_zcl_general.identify.identify_timeout", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_seconds),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_identify_effect_id,
            { "Effect", "zbee_zcl_general.identify.effect_id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_identify_effect_id_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_identify_effect_variant,
            { "Variant", "zbee_zcl_general.identify.effect_variant", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_identify_srv_rx_cmd_id,
          { "Command", "zbee_zcl_general.identify.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_identify_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_identify_srv_tx_cmd_id,
          { "Command", "zbee_zcl_general.identify.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_identify_srv_tx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Identify subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_identify
    };

    /* Register the ZigBee ZCL Identify cluster protocol name and description */
    proto_zbee_zcl_identify = proto_register_protocol("ZigBee ZCL Identify", "ZCL Identify", ZBEE_PROTOABBREV_ZCL_IDENTIFY);
    proto_register_field_array(proto_zbee_zcl_identify, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Identify dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_IDENTIFY, dissect_zbee_zcl_identify, proto_zbee_zcl_identify);

} /*proto_register_zbee_zcl_identify*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_identify
 *  DESCRIPTION
 *      Hands off the ZCL Identify dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_identify(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_IDENTIFY,
                            proto_zbee_zcl_identify,
                            ett_zbee_zcl_identify,
                            ZBEE_ZCL_CID_IDENTIFY,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_identify_attr_id,
                            hf_zbee_zcl_identify_attr_id,
                            hf_zbee_zcl_identify_srv_rx_cmd_id,
                            hf_zbee_zcl_identify_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_identify_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_identify*/


/* ########################################################################## */
/* #### (0x0004) GROUPS CLUSTER ############################################# */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_CMD_ID_GROUPS_NAME_SUPPORT_MASK                0x80  /*Name support Mask*/
/* Attributes */
#define ZBEE_ZCL_ATTR_ID_GROUPS_NAME_SUPPORT                    0x0000  /* Groups Name Support*/

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_GROUPS_ADD_GROUP                        0x00  /* Add Group */
#define ZBEE_ZCL_CMD_ID_GROUPS_VIEW_GROUP                       0x01  /* View Group */
#define ZBEE_ZCL_CMD_ID_GROUPS_ADD_GET_GROUP_MEMBERSHIP         0x02  /* Get Group Membership */
#define ZBEE_ZCL_CMD_ID_GROUPS_REMOVE_GROUP                     0x03  /* Remove a Group */
#define ZBEE_ZCL_CMD_ID_GROUPS_REMOVE_ALL_GROUPS                0x04  /* Remove all Groups */
#define ZBEE_ZCL_CMD_ID_GROUPS_ADD_GROUP_IF_IDENTIFYING         0x05  /* Add Group if Identifying */


/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_GROUPS_ADD_GROUP_RESPONSE               0x00  /* Add Group Response */
#define ZBEE_ZCL_CMD_ID_GROUPS_VIEW_GROUP_RESPONSE              0x01  /* View Group Response */
#define ZBEE_ZCL_CMD_ID_GROUPS_GET_GROUP_MEMBERSHIP_RESPONSE    0x02  /* Get Group Membership Response */
#define ZBEE_ZCL_CMD_ID_GROUPS_REMOVE_GROUP_RESPONSE            0x03  /* Remove a Group Response */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_groups(void);
void proto_reg_handoff_zbee_zcl_groups(void);

/* Command Dissector Helpers */
static void dissect_zcl_groups_add_group_or_if_identifying      (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_groups_view_group                       (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_groups_get_group_membership             (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_groups_remove_group                     (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_groups_add_remove_group_response        (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_groups_view_group_response              (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_groups_get_group_membership_response    (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

static void dissect_zcl_groups_attr_data                        (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_groups;

static int hf_zbee_zcl_groups_attr_id;
static int hf_zbee_zcl_groups_group_name_support;
static int hf_zbee_zcl_groups_group_id;
static int hf_zbee_zcl_groups_group_count;
static int hf_zbee_zcl_groups_group_capacity;
static int hf_zbee_zcl_groups_status;
static int hf_zbee_zcl_groups_attr_str_len;
static int hf_zbee_zcl_groups_attr_str;
static int hf_zbee_zcl_groups_srv_rx_cmd_id;
static int hf_zbee_zcl_groups_srv_tx_cmd_id;
static int hf_zbee_zcl_groups_group_list;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_groups;
static int ett_zbee_zcl_groups_grp_ctrl;

/* Attributes */
static const value_string zbee_zcl_groups_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_GROUPS_NAME_SUPPORT,      "Groups Name Support" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_groups_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_GROUPS_ADD_GROUP,                 "Add Group" },
    { ZBEE_ZCL_CMD_ID_GROUPS_VIEW_GROUP,                "View Group" },
    { ZBEE_ZCL_CMD_ID_GROUPS_ADD_GET_GROUP_MEMBERSHIP,  "Get Group Membership" },
    { ZBEE_ZCL_CMD_ID_GROUPS_REMOVE_GROUP,              "Remove a Group" },
    { ZBEE_ZCL_CMD_ID_GROUPS_REMOVE_ALL_GROUPS,         "Remove all Groups" },
    { ZBEE_ZCL_CMD_ID_GROUPS_ADD_GROUP_IF_IDENTIFYING,  "Add Group if Identifying" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_groups_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_GROUPS_ADD_GROUP_RESPONSE,            "Add Group Response" },
    { ZBEE_ZCL_CMD_ID_GROUPS_VIEW_GROUP_RESPONSE,           "View Group Response" },
    { ZBEE_ZCL_CMD_ID_GROUPS_GET_GROUP_MEMBERSHIP_RESPONSE, "Get Group Membership Response" },
    { ZBEE_ZCL_CMD_ID_GROUPS_REMOVE_GROUP_RESPONSE,         "Remove a Group Response" },
    { 0, NULL }
};


/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_groups
 *  DESCRIPTION
 *      ZigBee ZCL Groups cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_groups_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_groups_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_groups, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_GROUPS_ADD_GROUP:
                    dissect_zcl_groups_add_group_or_if_identifying(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_GROUPS_VIEW_GROUP:
                    dissect_zcl_groups_view_group(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_GROUPS_ADD_GET_GROUP_MEMBERSHIP:
                    dissect_zcl_groups_get_group_membership(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_GROUPS_REMOVE_GROUP:
                    dissect_zcl_groups_remove_group(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_GROUPS_REMOVE_ALL_GROUPS:
                    /* without payload*/
                    break;

                case ZBEE_ZCL_CMD_ID_GROUPS_ADD_GROUP_IF_IDENTIFYING:
                    dissect_zcl_groups_add_group_or_if_identifying(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_groups_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_groups_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_groups, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_GROUPS_ADD_GROUP_RESPONSE:
                    dissect_zcl_groups_add_remove_group_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_GROUPS_VIEW_GROUP_RESPONSE:
                    dissect_zcl_groups_view_group_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_GROUPS_GET_GROUP_MEMBERSHIP_RESPONSE:
                    dissect_zcl_groups_get_group_membership_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_GROUPS_REMOVE_GROUP_RESPONSE:
                    dissect_zcl_groups_add_remove_group_response(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_groups*/


 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_groups_add_group_or_if_identifying
 *  DESCRIPTION
 *      this function decodes the Add Group or Add Group If
 *      Identifying payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_groups_add_group_or_if_identifying(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    unsigned attr_uint;
    uint8_t *attr_string;

    /* Retrieve "Group ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_groups_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Group Name" field */
    attr_uint = tvb_get_uint8(tvb, *offset); /* string length */
    if (attr_uint == 0xff) attr_uint = 0;

    proto_tree_add_uint(tree, hf_zbee_zcl_groups_attr_str_len, tvb, *offset, 1, attr_uint);

    *offset += 1;

    attr_string = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, attr_uint, ENC_ASCII);

    proto_item_append_text(tree, ", String: %s", attr_string);
    proto_tree_add_string(tree, hf_zbee_zcl_groups_attr_str, tvb, *offset, attr_uint, attr_string);

    *offset += attr_uint;

} /*dissect_zcl_groups_add_group*/


 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_groups_view_group
 *  DESCRIPTION
 *      this function decodes the View Group payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_groups_view_group(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Groups Timeout" field */
    proto_tree_add_item(tree, hf_zbee_zcl_groups_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_groups_view_group*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_groups_get_group_membership
*  DESCRIPTION
*      this function decodes the Get Group Membership payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_groups_get_group_membership(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   proto_item *grp_list;
   proto_tree *grp_list_tree;
   uint8_t count, i;
   /* Retrieve "Group Count" field */
   count = tvb_get_uint8(tvb, *offset);
   proto_tree_add_uint(tree, hf_zbee_zcl_groups_group_count, tvb, *offset, 1, count);
   *offset += 1;

   if(count > 0)
      {
          grp_list = proto_tree_add_item(tree, hf_zbee_zcl_groups_group_list, tvb, *offset, 2*count, ENC_NA);
          grp_list_tree = proto_item_add_subtree(grp_list, ett_zbee_zcl_groups_grp_ctrl);
          /* Retrieve "Group List" members */
          for( i = 0; i < count; i++)
          {
               proto_tree_add_item(grp_list_tree, hf_zbee_zcl_groups_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
               *offset += 2;
          }
      }

} /*dissect_zcl_groups_get_group_membership*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_groups_remove_group
*  DESCRIPTION
*      this function decodes the Remove Group payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_groups_remove_group(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Groups ID" field */
   proto_tree_add_item(tree, hf_zbee_zcl_groups_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

} /*dissect_zcl_groups_remove_group*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_groups_add_group_response
*  DESCRIPTION
*      this function decodes the Add Group Response payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_groups_add_remove_group_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Status" field */
   proto_tree_add_item(tree, hf_zbee_zcl_groups_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Groups ID" field */
   proto_tree_add_item(tree, hf_zbee_zcl_groups_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

} /*dissect_zcl_groups_remove_group*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_groups_view_group_response
*  DESCRIPTION
*      this function decodes the View Group Response payload
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_groups_view_group_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    unsigned attr_uint;
    uint8_t *attr_string;
   /* Retrieve "Status" field */
   proto_tree_add_item(tree, hf_zbee_zcl_groups_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Group ID" field */
   proto_tree_add_item(tree, hf_zbee_zcl_groups_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Group Name" field */
   attr_uint = tvb_get_uint8(tvb, *offset); /* string length */
   if (attr_uint == 0xff) attr_uint = 0;

   proto_tree_add_uint(tree, hf_zbee_zcl_groups_attr_str_len, tvb, *offset, 1, attr_uint);

   *offset += 1;

   attr_string = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, attr_uint, ENC_ASCII);

   proto_item_append_text(tree, ", String: %s", attr_string);
   proto_tree_add_string(tree, hf_zbee_zcl_groups_attr_str, tvb, *offset, attr_uint, attr_string);

   *offset += attr_uint;
} /*dissect_zcl_groups_add_group*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_groups_get_group_membership_response
*  DESCRIPTION
*      this function decodes the Get Group Membership Response payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_groups_get_group_membership_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   proto_item *grp_list;
   proto_tree *grp_list_tree;
   uint8_t count, i;

   /* Retrieve "Capacity" field */
   proto_tree_add_item(tree, hf_zbee_zcl_groups_group_capacity, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Group Count" field */
   count = tvb_get_uint8(tvb, *offset);
   proto_tree_add_uint(tree, hf_zbee_zcl_groups_group_count, tvb, *offset, 1, count);
   *offset += 1;
   if(count > 0)
   {
       grp_list = proto_tree_add_item(tree, hf_zbee_zcl_groups_group_list, tvb, *offset, 2*count, ENC_NA);
       grp_list_tree = proto_item_add_subtree(grp_list, ett_zbee_zcl_groups_grp_ctrl);
       /* Retrieve "Group List" members */
       for( i = 0; i < count; i++)
       {
            proto_tree_add_item(grp_list_tree, hf_zbee_zcl_groups_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
       }
   }

} /*dissect_zcl_groups_get_group_membership*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_groups_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_groups_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_GROUPS_NAME_SUPPORT:
            proto_tree_add_item(tree, hf_zbee_zcl_groups_group_name_support, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_groups_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_groups
 *  DESCRIPTION
 *      ZigBee ZCL Groups cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_groups(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_groups_attr_id,
            { "Attribute", "zbee_zcl_general.groups.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_groups_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_groups_group_name_support,
            { "Group Name Support", "zbee_zcl_general.groups.attr.group_name_support", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_CMD_ID_GROUPS_NAME_SUPPORT_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_groups_group_id,
            { "Group ID", "zbee_zcl_general.groups.group_id", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_groups_group_list,
            {"Group List", "zbee_zcl_general.groups.group_list",FT_NONE,BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_groups_group_count,
            { "Group Count", "zbee_zcl_general.groups.group_count", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_groups_group_capacity,
            { "Group Capacity", "zbee_zcl_general.groups.group_capacity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_groups_status,
            { "Group Status", "zbee_zcl_general.groups.group_status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_status_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_groups_attr_str_len,
            { "Length", "zbee_zcl_general.groups.attr_str_len", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_groups_attr_str,
            { "String", "zbee_zcl_general.groups_attr_str", FT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_groups_srv_rx_cmd_id,
          { "Command", "zbee_zcl_general.groups.cmd_srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_groups_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_groups_srv_tx_cmd_id,
          { "Command", "zbee_zcl_general.groups.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_groups_srv_tx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Groups subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_groups,
        &ett_zbee_zcl_groups_grp_ctrl
    };

    /* Register the ZigBee ZCL Groups cluster protocol name and description */
    proto_zbee_zcl_groups = proto_register_protocol("ZigBee ZCL Groups", "ZCL Groups", ZBEE_PROTOABBREV_ZCL_GROUPS);
    proto_register_field_array(proto_zbee_zcl_groups, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Groups dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_GROUPS, dissect_zbee_zcl_groups, proto_zbee_zcl_groups);

} /*proto_register_zbee_zcl_groups*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_groups
 *  DESCRIPTION
 *      Hands off the ZCL Groups dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_groups(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_GROUPS,
                            proto_zbee_zcl_groups,
                            ett_zbee_zcl_groups,
                            ZBEE_ZCL_CID_GROUPS,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_groups_attr_id,
                            hf_zbee_zcl_groups_attr_id,
                            hf_zbee_zcl_groups_srv_rx_cmd_id,
                            hf_zbee_zcl_groups_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_groups_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_groups*/


/* ########################################################################## */
/* #### (0x0005) SCENES CLUSTER ############################################# */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_ATTR_SCENES_SCENE_VALID_MASK                   0x01  /* bit     0 */

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_SCENES_SCENE_COUNT                     0x0000  /* Scene Count */
#define ZBEE_ZCL_ATTR_ID_SCENES_CURRENT_SCENE                   0x0001  /* Current Scene */
#define ZBEE_ZCL_ATTR_ID_SCENES_CURRENT_GROUP                   0x0002  /* Current Group */
#define ZBEE_ZCL_ATTR_ID_SCENES_SCENE_VALID                     0x0003  /* Scene Valid */
#define ZBEE_ZCL_ATTR_ID_SCENES_NAME_SUPPORT                    0x0004  /* Name Support */
#define ZBEE_ZCL_ATTR_ID_SCENES_LAST_CONFIGURED_BY              0x0005  /* Last Configured By */

/* Scene Name Support */
#define ZBEE_ZCL_SCENES_NAME_NOT_SUPPORTED                      0x00  /* Scene Names Not Supported */
#define ZBEE_ZCL_SCENES_NAME_SUPPORTED                          0x01  /* Scene Names Supported */

/* Copy Mode */
#define ZBEE_ZCL_SCENES_COPY_SPECIFIED                          0x00  /* Copy Specified Scenes */
#define ZBEE_ZCL_SCENES_COPY_ALL                                0x01  /* Copy All Scenes */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_SCENES_ADD_SCENE                        0x00  /* Add Scene */
#define ZBEE_ZCL_CMD_ID_SCENES_VIEW_SCENE                       0x01  /* View Scene */
#define ZBEE_ZCL_CMD_ID_SCENES_REMOVE_SCENE                     0x02  /* Remove a Scene */
#define ZBEE_ZCL_CMD_ID_SCENES_REMOVE_ALL_SCENES                0x03  /* Remove all Scenes */
#define ZBEE_ZCL_CMD_ID_SCENES_STORE_SCENE                      0x04  /* Store Scene */
#define ZBEE_ZCL_CMD_ID_SCENES_RECALL_SCENE                     0x05  /* Recall Scene */
#define ZBEE_ZCL_CMD_ID_SCENES_GET_SCENE_MEMBERSHIP             0x06  /* Get Scene Membership */
#define ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_ADD_SCENE               0x40  /* Enhanced Add Scene */
#define ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_VIEW_SCENE              0x41  /* Enhanced View Scene */
#define ZBEE_ZCL_CMD_ID_SCENES_COPY_SCENE                       0x42  /* Copy Scene */
#define ZBEE_ZCL_CMD_ID_SCENES_NAME_SUPPORT_MASK                0x80

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_SCENES_ADD_SCENE_RESPONSE               0x00  /* Add Scene Response */
#define ZBEE_ZCL_CMD_ID_SCENES_VIEW_SCENE_RESPONSE              0x01  /* View Scene Response */
#define ZBEE_ZCL_CMD_ID_SCENES_REMOVE_SCENE_RESPONSE            0x02  /* Remove a Scene Response */
#define ZBEE_ZCL_CMD_ID_SCENES_REMOVE_ALL_SCENES_RESPONSE       0x03  /* Remove all Scenes Response */
#define ZBEE_ZCL_CMD_ID_SCENES_STORE_SCENE_RESPONSE             0x04  /* Store Scene Response */
#define ZBEE_ZCL_CMD_ID_SCENES_GET_SCENE_MEMBERSHIP_RESPONSE    0x06  /* Get Scene Membership Response */
#define ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_ADD_SCENE_RESPONSE      0x40  /* Enhanced Add Scene Response */
#define ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_VIEW_SCENE_RESPONSE     0x41  /* Enhanced View Scene Response */
#define ZBEE_ZCL_CMD_ID_SCENES_COPY_SCENE_RESPONSE              0x42  /* Copy Scene Response */

/* Enhanced */
#define IS_ENHANCED                                             true
#define IS_NOT_ENHANCED                                         false

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_scenes(void);
void proto_reg_handoff_zbee_zcl_scenes(void);

/* Command Dissector Helpers */
static void dissect_zcl_scenes_add_scene                                    (tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool enhanced);
static void dissect_zcl_scenes_view_remove_store_recall_scene               (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_scenes_remove_all_get_scene_membership              (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_scenes_copy_scene                                   (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_scenes_add_remove_store_scene_response              (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_scenes_view_scene_response                          (tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool enhanced);
static void dissect_zcl_scenes_remove_all_scenes_response                   (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_scenes_get_scene_membership_response                (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_scenes_copy_scene_response                          (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

static void dissect_zcl_scenes_extension_fields                             (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_scenes_attr_data                                    (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_scenes;

static int hf_zbee_zcl_scenes_attr_id;
static int hf_zbee_zcl_scenes_attr_id_scene_valid;
static int hf_zbee_zcl_scenes_attr_id_name_support;
static int hf_zbee_zcl_scenes_group_id;
static int hf_zbee_zcl_scenes_group_id_from;
static int hf_zbee_zcl_scenes_group_id_to;
static int hf_zbee_zcl_scenes_scene_id;
static int hf_zbee_zcl_scenes_scene_id_from;
static int hf_zbee_zcl_scenes_scene_id_to;
static int hf_zbee_zcl_scenes_transit_time;
static int hf_zbee_zcl_scenes_enh_transit_time;
static int hf_zbee_zcl_scenes_extension_set_cluster;
static int hf_zbee_zcl_scenes_extension_set_onoff;
static int hf_zbee_zcl_scenes_extension_set_level;
static int hf_zbee_zcl_scenes_extension_set_x;
static int hf_zbee_zcl_scenes_extension_set_y;
static int hf_zbee_zcl_scenes_extension_set_hue;
static int hf_zbee_zcl_scenes_extension_set_saturation;
static int hf_zbee_zcl_scenes_extension_set_color_loop_active;
static int hf_zbee_zcl_scenes_extension_set_color_loop_direction;
static int hf_zbee_zcl_scenes_extension_set_color_loop_time;
static int hf_zbee_zcl_scenes_extension_set_cooling_setpoint;
static int hf_zbee_zcl_scenes_extension_set_heating_setpoint;
static int hf_zbee_zcl_scenes_extension_set_system_mode;
static int hf_zbee_zcl_scenes_extension_set_lock_state;
static int hf_zbee_zcl_scenes_extension_set_lift_percentage;
static int hf_zbee_zcl_scenes_extension_set_tilt_percentage;

static int hf_zbee_zcl_scenes_status;
static int hf_zbee_zcl_scenes_capacity;
static int hf_zbee_zcl_scenes_scene_count;
static int hf_zbee_zcl_scenes_attr_str_len;
static int hf_zbee_zcl_scenes_attr_str;
static int hf_zbee_zcl_scenes_srv_rx_cmd_id;
static int hf_zbee_zcl_scenes_srv_tx_cmd_id;
static int hf_zbee_zcl_scenes_scene_list;
static int hf_zbee_zcl_scenes_copy_mode;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_scenes;
static int ett_zbee_zcl_scenes_scene_ctrl;
static int ett_zbee_zcl_scenes_extension_field_set;

/* Attributes */
static const value_string zbee_zcl_scenes_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_SCENES_SCENE_COUNT,          "Scene Count" },
    { ZBEE_ZCL_ATTR_ID_SCENES_CURRENT_SCENE,        "Current Scene" },
    { ZBEE_ZCL_ATTR_ID_SCENES_CURRENT_GROUP,        "Current Group" },
    { ZBEE_ZCL_ATTR_ID_SCENES_SCENE_VALID,          "Scene Valid" },
    { ZBEE_ZCL_ATTR_ID_SCENES_NAME_SUPPORT,         "Name Support" },
    { ZBEE_ZCL_ATTR_ID_SCENES_LAST_CONFIGURED_BY,   "Last Configured By" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_scenes_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_SCENES_ADD_SCENE,             "Add Scene" },
    { ZBEE_ZCL_CMD_ID_SCENES_VIEW_SCENE,            "View Scene" },
    { ZBEE_ZCL_CMD_ID_SCENES_REMOVE_SCENE,          "Remove a Scene" },
    { ZBEE_ZCL_CMD_ID_SCENES_REMOVE_ALL_SCENES,     "Remove all Scenes" },
    { ZBEE_ZCL_CMD_ID_SCENES_STORE_SCENE,           "Store Scene" },
    { ZBEE_ZCL_CMD_ID_SCENES_RECALL_SCENE,          "Recall Scene" },
    { ZBEE_ZCL_CMD_ID_SCENES_GET_SCENE_MEMBERSHIP,  "Get Scene Membership" },
    { ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_ADD_SCENE,    "Enhanced Add Scene" },
    { ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_VIEW_SCENE,   "Enhanced View Scene" },
    { ZBEE_ZCL_CMD_ID_SCENES_COPY_SCENE,            "Copy Scene" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_scenes_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_SCENES_ADD_SCENE_RESPONSE,            "Add Scene Response" },
    { ZBEE_ZCL_CMD_ID_SCENES_VIEW_SCENE_RESPONSE,           "View Scene Response" },
    { ZBEE_ZCL_CMD_ID_SCENES_REMOVE_SCENE_RESPONSE,         "Remove a Scene Response" },
    { ZBEE_ZCL_CMD_ID_SCENES_REMOVE_ALL_SCENES_RESPONSE,    "Remove all Scene Response" },
    { ZBEE_ZCL_CMD_ID_SCENES_STORE_SCENE_RESPONSE,          "Store Scene Response" },
    { ZBEE_ZCL_CMD_ID_SCENES_GET_SCENE_MEMBERSHIP_RESPONSE, "Get Scene Membership Response" },
    { ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_ADD_SCENE_RESPONSE,   "Enhanced Add Scene Response" },
    { ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_VIEW_SCENE_RESPONSE,  "Enhanced View Scene Response" },
    { ZBEE_ZCL_CMD_ID_SCENES_COPY_SCENE_RESPONSE,           "Copy Scene Response" },
    { 0, NULL }
};

/* Scene Names Support Values */
static const value_string zbee_zcl_scenes_group_names_support_values[] = {
    { ZBEE_ZCL_SCENES_NAME_NOT_SUPPORTED,   "Scene names not supported" },
    { ZBEE_ZCL_SCENES_NAME_SUPPORTED,       "Scene names supported" },
    { 0, NULL }
};

/* Scene Copy Mode Values */
static const value_string zbee_zcl_scenes_copy_mode_values[] = {
    { ZBEE_ZCL_SCENES_COPY_SPECIFIED,   "Copy Specified Scenes" },
    { ZBEE_ZCL_SCENES_COPY_ALL,         "Copy All Scenes" },
    { 0, NULL }
};

/* Color Loop Directions */
static const value_string zbee_zcl_scenes_color_loop_direction_values[] = {
    { 0x00,   "Hue is Decrementing" },
    { 0x01,   "Hue is Incrementing" },
    { 0, NULL }
};


/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *    decode_color_xy
 *  DESCRIPTION
 *    this function decodes color xy values
 *  PARAMETERS
 *      unsigned *s        - string to display
 *      uint16_t value   - value to decode
 *  RETURNS
 *    none
 *---------------------------------------------------------------
 */
static void
decode_color_xy(char *s, uint16_t value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%.4lf", value/65535.0);
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *    decode_setpoint
 *  DESCRIPTION
 *    this function decodes the setpoint
 *  PARAMETERS
 *      unsigned *s        - string to display
 *      uint16_t value   - value to decode
 *  RETURNS
 *    none
 *---------------------------------------------------------------
 */
static void decode_setpoint(char *s, int16_t value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%.2lf [" UTF8_DEGREE_SIGN "C]", value/100.0);
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_scenes
 *  DESCRIPTION
 *      ZigBee ZCL Scenes cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_scenes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_scenes_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_scenes_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_scenes, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_SCENES_ADD_SCENE:
                    dissect_zcl_scenes_add_scene(tvb, payload_tree, &offset, IS_NOT_ENHANCED);
                    break;

                case ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_ADD_SCENE:
                    dissect_zcl_scenes_add_scene(tvb, payload_tree, &offset, IS_ENHANCED);
                    break;

                case ZBEE_ZCL_CMD_ID_SCENES_VIEW_SCENE:
                case ZBEE_ZCL_CMD_ID_SCENES_REMOVE_SCENE:
                case ZBEE_ZCL_CMD_ID_SCENES_STORE_SCENE:
                case ZBEE_ZCL_CMD_ID_SCENES_RECALL_SCENE:
                case ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_VIEW_SCENE:
                    dissect_zcl_scenes_view_remove_store_recall_scene(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_SCENES_REMOVE_ALL_SCENES:
                case ZBEE_ZCL_CMD_ID_SCENES_GET_SCENE_MEMBERSHIP:
                    dissect_zcl_scenes_remove_all_get_scene_membership(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_SCENES_COPY_SCENE:
                    dissect_zcl_scenes_copy_scene(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_scenes_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_scenes_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_scenes, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_SCENES_ADD_SCENE_RESPONSE:
                case ZBEE_ZCL_CMD_ID_SCENES_REMOVE_SCENE_RESPONSE:
                case ZBEE_ZCL_CMD_ID_SCENES_STORE_SCENE_RESPONSE:
                case ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_ADD_SCENE_RESPONSE:
                    dissect_zcl_scenes_add_remove_store_scene_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_SCENES_VIEW_SCENE_RESPONSE:
                    dissect_zcl_scenes_view_scene_response(tvb, payload_tree, &offset, IS_NOT_ENHANCED);
                    break;

                case ZBEE_ZCL_CMD_ID_SCENES_ENHANCED_VIEW_SCENE_RESPONSE:
                    dissect_zcl_scenes_view_scene_response(tvb, payload_tree, &offset, IS_ENHANCED);
                    break;

                case ZBEE_ZCL_CMD_ID_SCENES_REMOVE_ALL_SCENES_RESPONSE:
                    dissect_zcl_scenes_remove_all_scenes_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_SCENES_GET_SCENE_MEMBERSHIP_RESPONSE:
                    dissect_zcl_scenes_get_scene_membership_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_SCENES_COPY_SCENE_RESPONSE:
                    dissect_zcl_scenes_copy_scene_response(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_scenes*/


 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_scenes_add_scene
 *  DESCRIPTION
 *      this function decodes the Add Scene payload.
 *  PARAMETERS
 *      tvb      - the tv buffer of the current data_type
 *      tree     - the tree to append this item to
 *      offset   - offset of data in tvb
 *      enhanced - use enhanced transition time
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_scenes_add_scene(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool enhanced)
{
    unsigned attr_uint;
    uint8_t *attr_string;

    /* Retrieve "Group ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Scene ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_scene_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Transition Time" field */
    proto_tree_add_item(tree, enhanced ? hf_zbee_zcl_scenes_enh_transit_time : hf_zbee_zcl_scenes_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve Scene Name */
    attr_uint = tvb_get_uint8(tvb, *offset); /* string length */
    if (attr_uint == 0xff) attr_uint = 0;

    proto_tree_add_uint(tree, hf_zbee_zcl_scenes_attr_str_len, tvb, *offset, 1, attr_uint);

    *offset += 1;

    attr_string = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, attr_uint, ENC_ASCII);

    proto_item_append_text(tree, ", String: %s", attr_string);
    proto_tree_add_string(tree, hf_zbee_zcl_scenes_attr_str, tvb, *offset, attr_uint, attr_string);

    *offset += attr_uint;

    /* Retrieve "Extension Set" field */
    dissect_zcl_scenes_extension_fields(tvb, tree, offset);

} /*dissect_zcl_scenes_add_scene*/


 /*FUNCTION:--------------------------------------------------------------------
 *  NAME
 *      dissect_zcl_scenes_view_remove_store_recall_scene
 *  DESCRIPTION
 *      this function decodes the View, Remove, Store and Recall Scene payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *------------------------------------------------------------------------------
 */
static void
dissect_zcl_scenes_view_remove_store_recall_scene(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Group ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Scene ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_scene_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_scenes_view_remove_store_recall_scene*/


/*FUNCTION:-------------------------------------------------------------------
*  NAME
*      dissect_zcl_scenes_remove_all_get_scene_membership
*  DESCRIPTION
*      this function decodes the Remove all and Get Scene Membership payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*-----------------------------------------------------------------------------
*/
static void
dissect_zcl_scenes_remove_all_get_scene_membership(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Group ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_scenes_remove_all_get_scene_membership*/


/*FUNCTION:--------------------------------------------------------------------
 *  NAME
 *      dissect_zcl_scenes_copy_scene
 *  DESCRIPTION
 *      this function decodes the Copy Scene payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *------------------------------------------------------------------------------
 */
static void
dissect_zcl_scenes_copy_scene(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_copy_mode, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Group ID From" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_group_id_from, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Scene ID From" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_scene_id_from, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Group ID To" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_group_id_to, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Scene ID To" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_scene_id_to, tvb, *offset, 1, ENC_NA);
    *offset += 1;

} /*dissect_zcl_scenes_copy_scene*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_scenes_add_remove_store_scene_response
*  DESCRIPTION
*      this function decodes the Add, Remove, Store Scene payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_scenes_add_remove_store_scene_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Status" field */
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Group ID" field */
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Scene ID" field */
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_scene_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

} /*dissect_zcl_scenes_add_remove_store_scene_response*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_scenes_view_scene_response
*  DESCRIPTION
*      this function decodes the View Scene Response payload.
*  PARAMETERS
*      tvb      - the tv buffer of the current data_type
*      tree     - the tree to append this item to
*      offset   - offset of data in tvb
*      enhanced - use enhanced transition time
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_scenes_view_scene_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool enhanced)
{
    uint8_t status, *attr_string;
    unsigned attr_uint;

    /* Retrieve "Status" field */
    status = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Group ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Scene ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_scenes_scene_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    if(status == ZBEE_ZCL_STAT_SUCCESS)
    {
        /* Retrieve "Transition Time" field */
        proto_tree_add_item(tree, enhanced ? hf_zbee_zcl_scenes_enh_transit_time : hf_zbee_zcl_scenes_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve Scene Name */
        attr_uint = tvb_get_uint8(tvb, *offset); /* string length */
        if (attr_uint == 0xff) attr_uint = 0;

        proto_tree_add_uint(tree, hf_zbee_zcl_scenes_attr_str_len, tvb, *offset, 1, attr_uint);

        *offset += 1;

        attr_string = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, attr_uint, ENC_ASCII);

        proto_item_append_text(tree, ", String: %s", attr_string);
        proto_tree_add_string(tree, hf_zbee_zcl_scenes_attr_str, tvb, *offset, attr_uint, attr_string);

        *offset += attr_uint;

        /* Retrieve "Extension Set" field */
        dissect_zcl_scenes_extension_fields(tvb, tree, offset);

    }

} /*dissect_zcl_scenes_view_scene_response*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_scenes_remove_all_scenes_response
*  DESCRIPTION
*      this function decodes the Remove All Scenes Response payload
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_scenes_remove_all_scenes_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Status" field */
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Group ID" field */
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

} /*dissect_zcl_scenes_remove_all_scenes_response*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_scenes_get_scene_membership_response
*  DESCRIPTION
*      this function decodes the Get Scene Membership Response payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_scenes_get_scene_membership_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   proto_item *scene_list;
   proto_tree *scene_list_tree;
   uint8_t status, count, i;

   /* Retrieve "Status" field */
   status = tvb_get_uint8(tvb, *offset);
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Capacity" field */
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_capacity, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Group ID" field */
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   if(status == ZBEE_ZCL_STAT_SUCCESS)
   {
       /* Retrieve "Scene Count" field */
       count = tvb_get_uint8(tvb, *offset);
       proto_tree_add_uint(tree, hf_zbee_zcl_scenes_scene_count, tvb, *offset, 1, count);
       *offset += 1;

       if(count>0)
         {
            scene_list=proto_tree_add_item(tree, hf_zbee_zcl_scenes_scene_list, tvb, *offset, count, ENC_NA);
            scene_list_tree = proto_item_add_subtree(scene_list, ett_zbee_zcl_scenes_scene_ctrl);
            /* Retrieve "Scene List" */
            for( i = 0; i < count; i++)
            {
              proto_tree_add_item(scene_list_tree, hf_zbee_zcl_scenes_scene_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
              *offset += 1;
            }
         }
   }

} /*dissect_zcl_scenes_get_scene_membership_response*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_scenes_copy_scene_response
 *  DESCRIPTION
 *      this function decodes the Copy Scene payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_scenes_copy_scene_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Status" field */
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_status, tvb, *offset, 1, ENC_NA);
   *offset += 1;

   /* Retrieve "Group ID From" field */
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_group_id_from, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Scene ID From" field */
   proto_tree_add_item(tree, hf_zbee_zcl_scenes_scene_id_from, tvb, *offset, 1, ENC_NA);
   *offset += 1;

} /*dissect_zcl_scenes_copy_scene_response*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_scenes_extension_fields
 *  DESCRIPTION
 *      this function decodes the extension set fields
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void dissect_zcl_scenes_extension_fields(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t     set = 1;
    proto_tree *subtree;

    // Is there an extension field?
    bool hasExtensionField = tvb_offset_exists(tvb, *offset+2);

    while (hasExtensionField)
    {
        // Retrieve the cluster and the length
        uint32_t cluster = tvb_get_uint16(tvb, *offset, ENC_LITTLE_ENDIAN);
        uint8_t length  = tvb_get_uint8 (tvb, *offset+2);

        // Create a subtree
        subtree = proto_tree_add_subtree_format(tree, tvb, *offset, length, ett_zbee_zcl_scenes_extension_field_set, NULL, "Extension field set %d", set++);
        proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_cluster, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 3;

        switch (cluster)
        {
        case ZBEE_ZCL_CID_ON_OFF:
            if (length >= 1)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_onoff, tvb, *offset, 1, ENC_NA);
                length  -= 1;
                *offset += 1;
            }
            break;

        case ZBEE_ZCL_CID_LEVEL_CONTROL:
            if (length >= 1)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_level, tvb, *offset, 1, ENC_NA);
                length  -= 1;
                *offset += 1;
            }
            break;

        case ZBEE_ZCL_CID_COLOR_CONTROL:
            if (length >= 2)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                length  -= 2;
                *offset += 2;
            }
            if (length >= 2)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                length  -= 2;
                *offset += 2;
            }
            if (length >= 2)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_hue, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                length  -= 2;
                *offset += 2;
            }
            if (length >= 1)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_saturation, tvb, *offset, 1, ENC_NA);
                length  -= 1;
                *offset += 1;
            }
            if (length >= 1)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_color_loop_active, tvb, *offset, 1, ENC_NA);
                length  -= 1;
                *offset += 1;
            }
            if (length >= 1)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_color_loop_direction, tvb, *offset, 1, ENC_NA);
                length  -= 1;
                *offset += 1;
            }
            if (length >= 2)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_color_loop_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                length  -= 2;
                *offset += 2;
            }
            break;

        case ZBEE_ZCL_CID_DOOR_LOCK:
            if (length >= 1)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_lock_state, tvb, *offset, 1, ENC_NA);
                length  -= 1;
                *offset += 1;
            }
            break;

        case ZBEE_ZCL_CID_WINDOW_COVERING:
            if (length >= 1)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_lift_percentage, tvb, *offset, 1, ENC_NA);
                length  -= 1;
                *offset += 1;
            }
            if (length >= 1)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_tilt_percentage, tvb, *offset, 1, ENC_NA);
                length  -= 1;
                *offset += 1;
            }
            break;

        case ZBEE_ZCL_CID_THERMOSTAT:
            if (length >= 2)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_cooling_setpoint, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                length  -= 2;
                *offset += 2;
            }
            if (length >= 2)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_heating_setpoint, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                length  -= 2;
                *offset += 2;
            }
            if (length >= 1)
            {
                proto_tree_add_item(subtree, hf_zbee_zcl_scenes_extension_set_system_mode, tvb, *offset, 1, ENC_NA);
                length  -= 1;
                *offset += 1;
            }
            break;
        }

        *offset += length;
        hasExtensionField = tvb_offset_exists(tvb, *offset+2);
    }
}


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_scenes_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_scenes_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_SCENES_SCENE_VALID:
            proto_tree_add_item(tree, hf_zbee_zcl_scenes_attr_id_scene_valid, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_SCENES_NAME_SUPPORT:
            proto_tree_add_item(tree, hf_zbee_zcl_scenes_attr_id_name_support, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_SCENES_SCENE_COUNT:
        case ZBEE_ZCL_ATTR_ID_SCENES_CURRENT_SCENE:
        case ZBEE_ZCL_ATTR_ID_SCENES_CURRENT_GROUP:
        case ZBEE_ZCL_ATTR_ID_SCENES_LAST_CONFIGURED_BY:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_scenes_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_scenes
 *  DESCRIPTION
 *      ZigBee ZCL Scenes cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_scenes(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_scenes_attr_id,
            { "Attribute", "zbee_zcl_general.scenes.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_scenes_attr_names),
            0x00, NULL, HFILL } },

       { &hf_zbee_zcl_scenes_scene_list,
            {"Scene List", "zbee_zcl_general.groups.scene_list",FT_NONE,BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_group_id,
            { "Group ID", "zbee_zcl_general.scenes.group_id", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_group_id_from,
            { "Group ID From", "zbee_zcl_general.scenes.group_id_from", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_group_id_to,
            { "Group ID To", "zbee_zcl_general.scenes.group_id_to", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_scene_id,
            { "Scene ID", "zbee_zcl_general.scenes.scene_id", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_scene_id_from,
            { "Scene ID From", "zbee_zcl_general.scenes.scene_id_from", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_scene_id_to,
            { "Scene ID To", "zbee_zcl_general.scenes.scene_id_to", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_transit_time,
            { "Transition Time", "zbee_zcl_general.scenes.transit_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_seconds),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_enh_transit_time,
            { "Transition Time", "zbee_zcl_general.scenes.enh_transit_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_100ms),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_status,
            { "Scenes Status", "zbee_zcl_general.scenes.scenes_status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_status_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_capacity,
            { "Scene Capacity", "zbee_zcl_general.scenes.scene_capacity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_scene_count,
            { "Scene Count", "zbee_zcl_general.scenes.scene_count", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_attr_id_name_support,
            { "Scene Name Support", "zbee_zcl_general.scenes.attr.name_support", FT_UINT8, BASE_HEX, VALS(zbee_zcl_scenes_group_names_support_values),
            ZBEE_ZCL_CMD_ID_SCENES_NAME_SUPPORT_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_attr_id_scene_valid,
            { "Scene Valid", "zbee_zcl_general.scenes.scene_valid", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_ATTR_SCENES_SCENE_VALID_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_attr_str_len,
            { "Length", "zbee_zcl_general.scenes.attr_str_len", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_attr_str,
            { "String", "zbee_zcl_general.scenes.attr_str", FT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_cluster,
            { "Cluster", "zbee_zcl_general.scenes.extension_set.cluster", FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_aps_cid_names),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_onoff,
            { "On/Off", "zbee_zcl_general.scenes.extension_set.onoff", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_level,
            { "Level", "zbee_zcl_general.scenes.extension_set.level", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_x,
            { "Color X", "zbee_zcl_general.scenes.extension_set.color_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_y,
            { "Color Y", "zbee_zcl_general.scenes.extension_set.color_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_hue,
            { "Enhanced Hue", "zbee_zcl_general.scenes.extension_set.hue", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_saturation,
            { "Saturation", "zbee_zcl_general.scenes.extension_set.saturation", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_color_loop_active,
            { "Color Loop Active", "zbee_zcl_general.scenes.extension_set.color_loop_active", FT_BOOLEAN, BASE_NONE, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_color_loop_direction,
            { "Color Loop Direction", "zbee_zcl_general.scenes.extension_set.color_loop_direction", FT_UINT8, BASE_DEC, VALS(zbee_zcl_scenes_color_loop_direction_values),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_color_loop_time,
            { "Color Loop Time", "zbee_zcl_general.scenes.extension_set.color_loop_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_seconds),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_lock_state,
            { "Lock State", "zbee_zcl_general.scenes.extension_set.lock_state", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_lift_percentage,
            { "Current Position Lift Percentage", "zbee_zcl_general.scenes.extension_set.current_position_lift_percentage", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_tilt_percentage,
            { "Current Position Tilt Percentage", "zbee_zcl_general.scenes.extension_set.current_position_tilt_percentage", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_cooling_setpoint,
            { "Occupied Cooling Setpoint", "zbee_zcl_general.scenes.extension_set.occupied_cooling_setpoint", FT_INT16, BASE_CUSTOM, CF_FUNC(decode_setpoint),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_heating_setpoint,
            { "Occupied Heating Setpoint", "zbee_zcl_general.scenes.extension_set.occupied_heating_setpoint", FT_INT16, BASE_CUSTOM, CF_FUNC(decode_setpoint),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_extension_set_system_mode,
            { "System Mode", "zbee_zcl_general.scenes.extension_set.system_mode", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_scenes_copy_mode,
            { "Scene Copy Mode", "zbee_zcl_general.scenes.copy_mode", FT_UINT8, BASE_DEC, VALS(zbee_zcl_scenes_copy_mode_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_srv_rx_cmd_id,
          { "Command", "zbee_zcl_general.scenes.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_scenes_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_scenes_srv_tx_cmd_id,
          { "Command", "zbee_zcl_general.scenes.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_scenes_srv_tx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Scenes subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_scenes,
        &ett_zbee_zcl_scenes_scene_ctrl,
        &ett_zbee_zcl_scenes_extension_field_set
    };

    /* Register the ZigBee ZCL Scenes cluster protocol name and description */
    proto_zbee_zcl_scenes = proto_register_protocol("ZigBee ZCL Scenes", "ZCL Scenes", ZBEE_PROTOABBREV_ZCL_SCENES);
    proto_register_field_array(proto_zbee_zcl_scenes, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Scenes dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_SCENES, dissect_zbee_zcl_scenes, proto_zbee_zcl_scenes);

} /*proto_register_zbee_zcl_scenes*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_scenes
 *  DESCRIPTION
 *      Hands off the ZCL Scenes dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_scenes(void)
{

    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_SCENES,
                            proto_zbee_zcl_scenes,
                            ett_zbee_zcl_scenes,
                            ZBEE_ZCL_CID_SCENES,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_scenes_attr_id,
                            hf_zbee_zcl_scenes_attr_id,
                            hf_zbee_zcl_scenes_srv_rx_cmd_id,
                            hf_zbee_zcl_scenes_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_scenes_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_scenes*/


/* ########################################################################## */
/* #### (0x0006) ON/OFF CLUSTER ############################################# */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ON_OFF_ATTR_ID_ONOFF               0x0000
#define ZBEE_ZCL_ON_OFF_ATTR_ID_GLOBALSCENECONTROL  0x4000
#define ZBEE_ZCL_ON_OFF_ATTR_ID_ONTIME              0x4001
#define ZBEE_ZCL_ON_OFF_ATTR_ID_OFFWAITTIME         0x4002
#define ZBEE_ZCL_ON_OFF_ATTR_ID_STARTUPONOFF        0x4003

/* Server Commands Received */
#define ZBEE_ZCL_ON_OFF_CMD_OFF                         0x00  /* Off */
#define ZBEE_ZCL_ON_OFF_CMD_ON                          0x01  /* On */
#define ZBEE_ZCL_ON_OFF_CMD_TOGGLE                      0x02  /* Toggle */
#define ZBEE_ZCL_ON_OFF_CMD_OFF_WITH_EFFECT             0x40  /* Off with effect */
#define ZBEE_ZCL_ON_OFF_CMD_ON_WITH_RECALL_GLOBAL_SCENE 0x41  /* On with recall global scene */
#define ZBEE_ZCL_ON_OFF_CMD_ON_WITH_TIMED_OFF           0x42  /* On with timed off */

/* On/Off Control Field */
#define ZBEE_ZCL_ON_OFF_TIMED_OFF_CONTROL_MASK_ACCEPT_ONLY_WHEN_ON   0x01
#define ZBEE_ZCL_ON_OFF_TIMED_OFF_CONTROL_MASK_RESERVED              0xFE

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_on_off(void);
void proto_reg_handoff_zbee_zcl_on_off(void);

/* Command Dissector Helpers */
static void dissect_zcl_on_off_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_on_off;

static int hf_zbee_zcl_on_off_attr_id;
static int hf_zbee_zcl_on_off_attr_onoff;
static int hf_zbee_zcl_on_off_attr_globalscenecontrol;
static int hf_zbee_zcl_on_off_attr_ontime;
static int hf_zbee_zcl_on_off_attr_offwaittime;
static int hf_zbee_zcl_on_off_attr_startuponoff;
static int hf_zbee_zcl_on_off_srv_rx_cmd_id;

static int hf_zbee_zcl_on_off_effect_identifier;
static int hf_zbee_zcl_on_off_effect_variant_delayed_all_off;
static int hf_zbee_zcl_on_off_effect_variant_dying_light;
static int hf_zbee_zcl_on_off_effect_variant_reserved;

static int hf_zbee_zcl_on_off_timed_off_control_mask;
static int hf_zbee_zcl_on_off_timed_off_control_mask_accept_only_when_on;
static int hf_zbee_zcl_on_off_timed_off_control_mask_reserved;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_on_off;
static int ett_zbee_zcl_on_off_timed_off_control_mask;

/* Attributes */
static const value_string zbee_zcl_on_off_attr_names[] = {
    { ZBEE_ZCL_ON_OFF_ATTR_ID_ONOFF,                "OnOff" },
    { ZBEE_ZCL_ON_OFF_ATTR_ID_GLOBALSCENECONTROL,   "GlobalSceneControl" },
    { ZBEE_ZCL_ON_OFF_ATTR_ID_ONTIME,               "OnTime" },
    { ZBEE_ZCL_ON_OFF_ATTR_ID_OFFWAITTIME,          "OffWaitTime" },
    { ZBEE_ZCL_ON_OFF_ATTR_ID_STARTUPONOFF,         "StartUpOnOff" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_on_off_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_ON_OFF_CMD_OFF,                          "Off" },
    { ZBEE_ZCL_ON_OFF_CMD_ON,                           "On" },
    { ZBEE_ZCL_ON_OFF_CMD_TOGGLE,                       "Toggle" },
    { ZBEE_ZCL_ON_OFF_CMD_OFF_WITH_EFFECT,              "Off with effect" },
    { ZBEE_ZCL_ON_OFF_CMD_ON_WITH_RECALL_GLOBAL_SCENE,  "On with recall global scene" },
    { ZBEE_ZCL_ON_OFF_CMD_ON_WITH_TIMED_OFF,            "On with timed off" },
    { 0, NULL }
};

static const range_string zbee_zcl_on_off_effect_identifier_names[] = {
    { 0x00, 0x00, "Delayed All Off" },
    { 0x01, 0x01, "Dying Light" },
    { 0x02, 0xFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string zbee_zcl_on_off_effect_variant_delayed_all_off_names[] = {
    { 0x00, 0x00, "Fade to off in 0.8 seconds" },
    { 0x01, 0x01, "No fade" },
    { 0x02, 0x02, "50% dim down in 0.8 seconds then fade to off in 12 seconds" },
    { 0x03, 0xFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string zbee_zcl_on_off_effect_variant_dying_light_names[] = {
    { 0x00, 0x00, "20% dim up in 0.5s then fade to off in 1 second" },
    { 0x01, 0xFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string zbee_zcl_on_off_effect_variant_reserved_names[] = {
    { 0x00, 0xFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string zbee_zcl_on_off_startup_on_off_names[] = {
    { 0x00, 0x00, "Set the OnOff attribute to Off" },
    { 0x01, 0x01, "Set the OnOff attribute to On" },
    { 0x02, 0x02, "Toggle the OnOff attribute" },
    { 0x03, 0xFE, "Reserved" },
    { 0xFF, 0xFF, "Set the OnOff attribute to its previous value" },
    { 0, 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_onoff
 *  DESCRIPTION
 *      ZigBee ZCL OnOff cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      void *data          - pointer to ZCL packet structure.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_on_off(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree       *payload_tree;
    zbee_zcl_packet  *zcl;
    unsigned   offset = 0;
    uint8_t cmd_id;
    int     rem_len;
    uint8_t effect_identifier = 0;

    static int * const onoff_control_mask[] = {
        &hf_zbee_zcl_on_off_timed_off_control_mask_accept_only_when_on,
        &hf_zbee_zcl_on_off_timed_off_control_mask_reserved,
        NULL
    };

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_on_off_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_on_off_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_on_off, NULL, "Payload");

            switch (cmd_id) {
                case ZBEE_ZCL_ON_OFF_CMD_OFF_WITH_EFFECT:
                    proto_tree_add_item(payload_tree, hf_zbee_zcl_on_off_effect_identifier, tvb, offset, 1, ENC_NA);
                    effect_identifier = tvb_get_uint8(tvb, offset);
                    offset += 1;
                    switch (effect_identifier) {
                        case 0x00:
                            proto_tree_add_item(payload_tree, hf_zbee_zcl_on_off_effect_variant_delayed_all_off, tvb, offset, 1, ENC_NA);
                            break;
                        case 0x01:
                            proto_tree_add_item(payload_tree, hf_zbee_zcl_on_off_effect_variant_dying_light, tvb, offset, 1, ENC_NA);
                            break;
                        default:
                            proto_tree_add_item(payload_tree, hf_zbee_zcl_on_off_effect_variant_reserved, tvb, offset, 1, ENC_NA);
                            break;
                    }
                    break;

                case ZBEE_ZCL_ON_OFF_CMD_ON_WITH_TIMED_OFF:
                    proto_tree_add_bitmask(payload_tree, tvb, offset, hf_zbee_zcl_on_off_timed_off_control_mask, ett_zbee_zcl_on_off_timed_off_control_mask, onoff_control_mask, ENC_LITTLE_ENDIAN);
                    offset += 1;

                    dissect_zcl_on_off_attr_data(payload_tree, tvb, &offset, ZBEE_ZCL_ON_OFF_ATTR_ID_ONTIME, FT_UINT16, false);
                    dissect_zcl_on_off_attr_data(payload_tree, tvb, &offset, ZBEE_ZCL_ON_OFF_ATTR_ID_OFFWAITTIME, FT_UINT16, false);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_on_off*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_on_off_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_on_off_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ON_OFF_ATTR_ID_ONOFF:
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_attr_onoff, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ON_OFF_ATTR_ID_GLOBALSCENECONTROL:
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_attr_globalscenecontrol, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ON_OFF_ATTR_ID_ONTIME:
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_attr_ontime, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ON_OFF_ATTR_ID_OFFWAITTIME:
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_attr_offwaittime, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ON_OFF_ATTR_ID_STARTUPONOFF:
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_attr_startuponoff, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_on_off_attr_data*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_on_off
 *  DESCRIPTION
 *      ZigBee ZCL OnOff cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_on_off(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_on_off_attr_id,
            { "Attribute", "zbee_zcl_general.onoff.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_on_off_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_attr_onoff,
            { "On/off Control", "zbee_zcl_general.onoff.attr.onoff", FT_BOOLEAN, BASE_NONE, TFS(&tfs_on_off),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_attr_globalscenecontrol,
            { "Global Scene Control", "zbee_zcl_general.onoff.attr.globalscenecontrol", FT_BOOLEAN, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_attr_ontime,
            { "On Time", "zbee_zcl_general.onoff.attr.ontime", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_100ms),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_attr_offwaittime,
            { "Off Wait Time", "zbee_zcl_general.onoff.attr.offwaittime", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_100ms),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_attr_startuponoff,
            { "Startup On Off", "zbee_zcl_general.onoff.attr.startuponoff", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_on_off_startup_on_off_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_effect_identifier,
            { "Effect Identifier", "zbee_zcl_general.onoff.effect_identifier", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_on_off_effect_identifier_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_effect_variant_delayed_all_off,
            { "Effect Variant", "zbee_zcl_general.onoff.effect_variant", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_on_off_effect_variant_delayed_all_off_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_effect_variant_dying_light,
            { "Effect Variant", "zbee_zcl_general.onoff.effect_variant", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_on_off_effect_variant_dying_light_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_effect_variant_reserved,
            { "Effect Variant", "zbee_zcl_general.onoff.effect_variant", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_on_off_effect_variant_reserved_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_timed_off_control_mask,
            { "On/Off Control Mask", "zbee_zcl_general.onoff.onoff_control_mask", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_timed_off_control_mask_accept_only_when_on,
            { "Accept Only When On", "zbee_zcl_general.onoff.onoff_control_mask.accept_only_when_on", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_ON_OFF_TIMED_OFF_CONTROL_MASK_ACCEPT_ONLY_WHEN_ON, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_timed_off_control_mask_reserved,
            { "Reserved", "zbee_zcl_general.onoff.onoff_control_mask.reserved", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_ON_OFF_TIMED_OFF_CONTROL_MASK_RESERVED, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_srv_rx_cmd_id,
            { "Command", "zbee_zcl_general.onoff.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_on_off_srv_rx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL OnOff subtrees */
    static int *ett[] = { &ett_zbee_zcl_on_off,
                          &ett_zbee_zcl_on_off_timed_off_control_mask };

    /* Register the ZigBee ZCL OnOff cluster protocol name and description */
    proto_zbee_zcl_on_off = proto_register_protocol("ZigBee ZCL OnOff", "ZCL OnOff", ZBEE_PROTOABBREV_ZCL_ONOFF);
    proto_register_field_array(proto_zbee_zcl_on_off, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL OnOff dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_ONOFF, dissect_zbee_zcl_on_off, proto_zbee_zcl_on_off);
} /* proto_register_zbee_zcl_on_off */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_on_off
 *  DESCRIPTION
 *      Hands off the Zcl OnOff cluster dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_on_off(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_ONOFF,
                            proto_zbee_zcl_on_off,
                            ett_zbee_zcl_on_off,
                            ZBEE_ZCL_CID_ON_OFF,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_on_off_attr_id,
                            hf_zbee_zcl_on_off_attr_id,
                            hf_zbee_zcl_on_off_srv_rx_cmd_id,
                            -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_on_off_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_on_off*/

/* ############################################################################################### */
/* #### (0x0007) ON/OFF SWITCH CONFIGURATION CLUSTER ############################################# */
/* ############################################################################################### */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ON_OFF_SWITCH_CONFIGURATION_ATTR_ID_SWITCH_TYPE     0x0000     /* Switch Type */
#define ZBEE_ZCL_ON_OFF_SWITCH_CONFIGURATION_ATTR_ID_SWITCH_ACTIONS  0x0010  /* Switch Actions */

/* No Server Commands Received */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_on_off_switch_configuration(void);
void proto_reg_handoff_zbee_zcl_on_off_switch_configuration(void);

/* Command Dissector Helpers */
static void dissect_zcl_on_off_switch_configuration_attr_data     (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_on_off_switch_configuration;

static int hf_zbee_zcl_on_off_switch_configuration_attr_id;
static int hf_zbee_zcl_on_off_switch_configuration_attr_switch_type;
static int hf_zbee_zcl_on_off_switch_configuration_attr_switch_actions;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_on_off_switch_configuration;

/* Attributes */
static const value_string zbee_zcl_on_off_switch_configuration_attr_names[] = {
    { ZBEE_ZCL_ON_OFF_SWITCH_CONFIGURATION_ATTR_ID_SWITCH_TYPE,     "Switch Type" },
    { ZBEE_ZCL_ON_OFF_SWITCH_CONFIGURATION_ATTR_ID_SWITCH_ACTIONS,  "Switch Actions" },
    { 0, NULL }
};

/* Switch Type Names */
static const value_string zbee_zcl_on_off_switch_configuration_switch_type_names[] = {
    { 0x00, "Toggle" },
    { 0x01, "Momentary" },
    { 0, NULL }
};

/* Switch Actions Names */
static const value_string zbee_zcl_on_off_switch_configuration_switch_actions_names[] = {
    { 0x00, "On" },
    { 0x01, "Off" },
    { 0x02, "Toggle" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_on_off_switch_configuration
 *  DESCRIPTION
 *      ZigBee ZCL OnOff Switch Configuration cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_on_off_switch_configuration(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_on_off_switch_configuration*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_on_off_switch_configuration_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_on_off_switch_configuration_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ON_OFF_SWITCH_CONFIGURATION_ATTR_ID_SWITCH_TYPE:
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_switch_configuration_attr_switch_type, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ON_OFF_SWITCH_CONFIGURATION_ATTR_ID_SWITCH_ACTIONS:
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_switch_configuration_attr_switch_actions, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_on_off_switch_configuration_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_on_off_switch_configuration
 *  DESCRIPTION
 *      ZigBee ZCL OnOff cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_on_off_switch_configuration(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_on_off_switch_configuration_attr_id,
            { "Attribute", "zbee_zcl_general.onoff_switch_configuration.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_on_off_switch_configuration_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_switch_configuration_attr_switch_type,
            { "Switch Type", "zbee_zcl_general.onoff.attr.switch_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_on_off_switch_configuration_switch_type_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_switch_configuration_attr_switch_actions,
            { "Switch Action", "zbee_zcl_general.onoff.attr.switch_actions", FT_UINT8, BASE_HEX, VALS(zbee_zcl_on_off_switch_configuration_switch_actions_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Identify subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_on_off_switch_configuration
    };

    /* Register the ZigBee ZCL OnOff Switch Configuration cluster protocol name and description */
    proto_zbee_zcl_on_off_switch_configuration = proto_register_protocol("ZigBee ZCL OnOff Switch Configuration", "ZCL OnOff Switch Configuration", ZBEE_PROTOABBREV_ZCL_ONOFF_SWITCH_CONFIG);
    proto_register_field_array(proto_zbee_zcl_on_off_switch_configuration, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL OnOff dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_ONOFF_SWITCH_CONFIG, dissect_zbee_zcl_on_off_switch_configuration, proto_zbee_zcl_on_off_switch_configuration);
} /* proto_register_zbee_zcl_on_off_switch_configuration */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_on_off_switch_configuration
 *  DESCRIPTION
 *      Hands off the Zcl OnOff cluster dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_on_off_switch_configuration(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_ONOFF_SWITCH_CONFIG,
                            proto_zbee_zcl_on_off_switch_configuration,
                            ett_zbee_zcl_on_off_switch_configuration,
                            ZBEE_ZCL_CID_ON_OFF_SWITCH_CONFIG,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_on_off_switch_configuration_attr_id,
                            hf_zbee_zcl_on_off_switch_configuration_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_on_off_switch_configuration_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_on_off_switch_configuration*/

/* ########################################################################## */
/* #### (0x0009) ALARMS CLUSTER ############################################# */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_ALARMS_ALARM_COUNT         0x0000  /* Alarm Count */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_ALARMS_RESET_ALARM          0x00  /* Reset Alarm */
#define ZBEE_ZCL_CMD_ID_ALARMS_RESET_ALL_ALARMS     0x01  /* Reset All Alarms */
#define ZBEE_ZCL_CMD_ID_ALARMS_GET_ALARM            0x02  /* Get Alarm */
#define ZBEE_ZCL_CMD_ID_ALARMS_RESET_ALARM_LOG      0x03  /* Reset Alarm Log */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_ALARMS_ALARM                0x00  /* Alarm */
#define ZBEE_ZCL_CMD_ID_ALARMS_GET_ALARM_RESPONSE   0x01  /* Get Alarm Response */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_alarms(void);
void proto_reg_handoff_zbee_zcl_alarms(void);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_alarms;

static int hf_zbee_zcl_alarms_attr_id;
static int hf_zbee_zcl_alarms_alarm_code;
static int hf_zbee_zcl_alarms_cluster_id;
static int hf_zbee_zcl_alarms_status;
static int hf_zbee_zcl_alarms_timestamp;
static int hf_zbee_zcl_alarms_srv_rx_cmd_id;
static int hf_zbee_zcl_alarms_srv_tx_cmd_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_alarms;

/* Attributes */
static const value_string zbee_zcl_alarms_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_ALARMS_ALARM_COUNT,      "Alarm Count" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_alarms_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_ALARMS_RESET_ALARM,       "Reset Alarm" },
    { ZBEE_ZCL_CMD_ID_ALARMS_RESET_ALL_ALARMS,  "Reset All Alarms" },
    { ZBEE_ZCL_CMD_ID_ALARMS_GET_ALARM,         "Get Alarm" },
    { ZBEE_ZCL_CMD_ID_ALARMS_RESET_ALARM_LOG,   "Reset Alarm Log" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_alarms_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_ALARMS_ALARM,             "Alarm" },
    { ZBEE_ZCL_CMD_ID_ALARMS_GET_ALARM_RESPONSE,"Get Alarm Response" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_alarms_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *--------------------------------------------------------------- */
static void
dissect_zcl_alarms_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {
        case ZBEE_ZCL_ATTR_ID_ALARMS_ALARM_COUNT:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_alarms_attr_data*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_alarms_alarm_and_reset_alarm
 *  DESCRIPTION
 *      this function decodes the Alarm and Reset Alarm payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_alarms_alarm_and_reset_alarm(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Alarm Code" field */
    proto_tree_add_item(tree, hf_zbee_zcl_alarms_alarm_code, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Cluster ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_alarms_cluster_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_alarms_alarm_and_reset_alarm*/


 /*FUNCTION:--------------------------------------------------------------------
 *  NAME
 *      dissect_zcl_alarms_get_alarm_response
 *  DESCRIPTION
 *      this function decodes the Get Alarm Response payload
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *------------------------------------------------------------------------------
 */

static void
dissect_zcl_alarms_get_alarm_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
     uint8_t status;

    /* Retrieve "Status" field */
    status = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_alarms_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    if(status == ZBEE_ZCL_STAT_SUCCESS)
    {
        /* Retrieve "Alarm Code" field */
        proto_tree_add_item(tree, hf_zbee_zcl_alarms_alarm_code, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;

        /* Retrieve "Cluster ID" field */
        proto_tree_add_item(tree, hf_zbee_zcl_alarms_cluster_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve "Timestamp" field */
        proto_tree_add_item(tree, hf_zbee_zcl_alarms_timestamp, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }

} /*dissect_zcl_alarms_get_alarm_response*/



/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_alarms
 *  DESCRIPTION
 *      ZigBee ZCL Alarms cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_alarms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_alarms_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_alarms_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_alarms, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_ALARMS_RESET_ALARM:
                    dissect_zcl_alarms_alarm_and_reset_alarm(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_ALARMS_RESET_ALL_ALARMS:
                case ZBEE_ZCL_CMD_ID_ALARMS_GET_ALARM:
                case ZBEE_ZCL_CMD_ID_ALARMS_RESET_ALARM_LOG:
                    /* No Payload */
                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_alarms_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_alarms_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_alarms, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_ALARMS_ALARM:
                    dissect_zcl_alarms_alarm_and_reset_alarm(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_ALARMS_GET_ALARM_RESPONSE:
                    dissect_zcl_alarms_get_alarm_response(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_alarms*/





/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_alarms
 *  DESCRIPTION
 *      ZigBee ZCL Alarms cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_alarms(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_alarms_attr_id,
            { "Attribute", "zbee_zcl_general.alarms.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_alarms_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_alarms_alarm_code,
            { "Alarm Code", "zbee_zcl_general.alarms.alarm_code", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_alarms_cluster_id,
            { "Cluster ID", "zbee_zcl_general.alarms.cluster_id", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_alarms_status,
            { "Status", "zbee_zcl_general.alarms.status", FT_UINT8, BASE_DEC, VALS(zbee_zcl_status_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_alarms_timestamp,
            { "Timestamp", "zbee_zcl_general.alarms.timestamp", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_alarms_srv_rx_cmd_id,
          { "Command", "zbee_zcl_general.alarms.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_alarms_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_alarms_srv_tx_cmd_id,
          { "Command", "zbee_zcl_general.alarms.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_alarms_srv_tx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Alarms subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_alarms
    };

    /* Register the ZigBee ZCL Alarms cluster protocol name and description */
    proto_zbee_zcl_alarms = proto_register_protocol("ZigBee ZCL Alarms", "ZCL Alarms", ZBEE_PROTOABBREV_ZCL_ALARMS);
    proto_register_field_array(proto_zbee_zcl_alarms, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Alarms dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_ALARMS, dissect_zbee_zcl_alarms, proto_zbee_zcl_alarms);

} /*proto_register_zbee_zcl_alarms*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_alarms
 *  DESCRIPTION
 *      Hands off the ZCL Alarms dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_alarms(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_ALARMS,
                            proto_zbee_zcl_alarms,
                            ett_zbee_zcl_alarms,
                            ZBEE_ZCL_CID_ALARMS,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_alarms_attr_id,
                            hf_zbee_zcl_alarms_attr_id,
                            hf_zbee_zcl_alarms_srv_rx_cmd_id,
                            hf_zbee_zcl_alarms_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_alarms_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_alarms*/


/* ########################################################################## */
/* #### (0x000A) TIME CLUSTER ############################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_TIME_TIME              0x0000  /* Time */
#define ZBEE_ZCL_ATTR_ID_TIME_TIME_STATUS       0x0001  /* Time Status */
#define ZBEE_ZCL_ATTR_ID_TIME_TIME_ZONE         0x0002  /* Time Zone */
#define ZBEE_ZCL_ATTR_ID_TIME_DST_START         0x0003  /* Daylight Saving Time Start*/
#define ZBEE_ZCL_ATTR_ID_TIME_DST_END           0x0004  /* Daylight Saving Time End */
#define ZBEE_ZCL_ATTR_ID_TIME_DST_SHIFT         0x0005  /* Daylight Saving Time Shift */
#define ZBEE_ZCL_ATTR_ID_TIME_STD_TIME          0x0006  /* Standard Time */
#define ZBEE_ZCL_ATTR_ID_TIME_LOCAL_TIME        0x0007  /* Local Time */
#define ZBEE_ZCL_ATTR_ID_TIME_LAST_SET_TIME     0x0008  /* Last Set Time */
#define ZBEE_ZCL_ATTR_ID_TIME_VALID_UNTIL_TIME  0x0009  /* Valid Until Time */

/* Server commands received - none */

/* Server commands generated - none */

/* Time Status Mask Value */
#define ZBEE_ZCL_TIME_MASTER                     0x01    /* Master Clock */
#define ZBEE_ZCL_TIME_SYNCHRONIZED               0x02    /* Synchronized */
#define ZBEE_ZCL_TIME_MASTER_ZONE_DST            0x04    /* Master for Time Zone and DST */
#define ZBEE_ZCL_TIME_SUPERSEDING                0x08    /* Superseded */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_time(void);
void proto_reg_handoff_zbee_zcl_time(void);


/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_time;

static int hf_zbee_zcl_time_attr_id;
static int hf_zbee_zcl_time_status;
static int hf_zbee_zcl_time_status_master;
static int hf_zbee_zcl_time_status_synchronized;
static int hf_zbee_zcl_time_status_master_zone_dst;
static int hf_zbee_zcl_time_status_superseding;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_time;
static int ett_zbee_zcl_time_status_mask;

/* Attributes */
static const value_string zbee_zcl_time_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_TIME_TIME,               "Time" },
    { ZBEE_ZCL_ATTR_ID_TIME_TIME_STATUS,        "Time Status" },
    { ZBEE_ZCL_ATTR_ID_TIME_TIME_ZONE,          "Time Zone" },
    { ZBEE_ZCL_ATTR_ID_TIME_DST_START,          "Daylight Saving Time Start" },
    { ZBEE_ZCL_ATTR_ID_TIME_DST_END,            "Daylight Saving Time End" },
    { ZBEE_ZCL_ATTR_ID_TIME_DST_SHIFT,          "Daylight Saving Time Shift" },
    { ZBEE_ZCL_ATTR_ID_TIME_STD_TIME,           "Standard Time" },
    { ZBEE_ZCL_ATTR_ID_TIME_LOCAL_TIME,         "Local Time" },
    { ZBEE_ZCL_ATTR_ID_TIME_LAST_SET_TIME,      "Last Set Time" },
    { ZBEE_ZCL_ATTR_ID_TIME_VALID_UNTIL_TIME,   "Valid Until Time" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_time_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *--------------------------------------------------------------- */
static void
dissect_zcl_time_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    static int * const time_status_mask[] = {
        &hf_zbee_zcl_time_status_master,
        &hf_zbee_zcl_time_status_synchronized,
        &hf_zbee_zcl_time_status_master_zone_dst,
        &hf_zbee_zcl_time_status_superseding,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_TIME_TIME_STATUS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_time_status, ett_zbee_zcl_time_status_mask, time_status_mask, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_TIME_TIME:
        case ZBEE_ZCL_ATTR_ID_TIME_TIME_ZONE:
        case ZBEE_ZCL_ATTR_ID_TIME_DST_START:
        case ZBEE_ZCL_ATTR_ID_TIME_DST_END:
        case ZBEE_ZCL_ATTR_ID_TIME_DST_SHIFT:
        case ZBEE_ZCL_ATTR_ID_TIME_STD_TIME:
        case ZBEE_ZCL_ATTR_ID_TIME_LOCAL_TIME:
        case ZBEE_ZCL_ATTR_ID_TIME_LAST_SET_TIME:
        case ZBEE_ZCL_ATTR_ID_TIME_VALID_UNTIL_TIME:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_time_attr_data*/
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_time
 *  DESCRIPTION
 *      ZigBee ZCL Time cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_time(tvbuff_t _U_ *tvb, packet_info _U_ * pinfo, proto_tree _U_* tree, void _U_* data)
{
    /* No commands is being received and generated by server
     * No cluster specific commands  are received by client
     */
    return 0;
} /*dissect_zbee_zcl_time*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_time
 *  DESCRIPTION
 *      ZigBee ZCL Time cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_time(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_time_attr_id,
            { "Attribute", "zbee_zcl_general.time.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_time_attr_names),
            0x00, NULL, HFILL } },

        /* start Time Status Mask fields */
        { &hf_zbee_zcl_time_status,
            { "Time Status", "zbee_zcl_general.time.attr.time_status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_time_status_master,
            { "Master", "zbee_zcl_general.time.attr.time_status.master",  FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_TIME_MASTER, NULL, HFILL } },

        { &hf_zbee_zcl_time_status_synchronized,
            { "Synchronized", "zbee_zcl_general.time.attr.time_status.synchronized", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_TIME_SYNCHRONIZED, NULL, HFILL } },

        { &hf_zbee_zcl_time_status_master_zone_dst,
            { "Master for Time Zone and DST", "zbee_zcl_general.time.attr.time_status.master_zone_dst", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_TIME_MASTER_ZONE_DST, NULL, HFILL } },

        { &hf_zbee_zcl_time_status_superseding,
            { "Superseded", "zbee_zcl_general.time.attr.time_status.superseding", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_TIME_SUPERSEDING, NULL, HFILL } }
        /* end Time Status Mask fields */
    };

    /* ZCL Time subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_time,
        &ett_zbee_zcl_time_status_mask
    };

    /* Register the ZigBee ZCL Time cluster protocol name and description */
    proto_zbee_zcl_time = proto_register_protocol("ZigBee ZCL Time", "ZCL Time", ZBEE_PROTOABBREV_ZCL_TIME);
    proto_register_field_array(proto_zbee_zcl_time, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Time dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_TIME, dissect_zbee_zcl_time, proto_zbee_zcl_time);
} /*proto_register_zbee_zcl_time*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_time
 *  DESCRIPTION
 *      Hands off the ZCL Time dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_time(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_TIME,
                            proto_zbee_zcl_time,
                            ett_zbee_zcl_time,
                            ZBEE_ZCL_CID_TIME,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_time_attr_id,
                            hf_zbee_zcl_time_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_time_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_time*/




/* ########################################################################## */
/* #### (0x0008) LEVEL_CONTROL CLUSTER ###################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_CURRENT_LEVEL            0x0000  /* Current Level */
#define ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_REMAINING_TIME           0x0001  /* Remaining Time */
#define ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_ONOFF_TRANSIT_TIME       0x0010  /* OnOff Transition Time */
#define ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_ON_LEVEL                 0x0011  /* On Level */
#define ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_STARTUP_LEVEL            0x4000  /* Startup Level */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE_TO_LEVEL             0x00  /* Move to Level */
#define ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE                      0x01  /* Move */
#define ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STEP                      0x02  /* Step */
#define ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STOP                      0x03  /* Stop */
#define ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE_TO_LEVEL_WITH_ONOFF  0x04  /* Move to Level with OnOff */
#define ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE_WITH_ONOFF           0x05  /* Move with OnOff */
#define ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STEP_WITH_ONOFF           0x06  /* Step with OnOff */
#define ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STOP_WITH_ONOFF           0x07  /* Stop with OnOff */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_level_control(void);
void proto_reg_handoff_zbee_zcl_level_control(void);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_level_control;

static int hf_zbee_zcl_level_control_attr_id;
static int hf_zbee_zcl_level_control_attr_current_level;
static int hf_zbee_zcl_level_control_attr_remaining_time;
static int hf_zbee_zcl_level_control_attr_onoff_transmit_time;
static int hf_zbee_zcl_level_control_attr_on_level;
static int hf_zbee_zcl_level_control_attr_startup_level;
static int hf_zbee_zcl_level_control_level;
static int hf_zbee_zcl_level_control_move_mode;
static int hf_zbee_zcl_level_control_rate;
static int hf_zbee_zcl_level_control_step_mode;
static int hf_zbee_zcl_level_control_step_size;
static int hf_zbee_zcl_level_control_transit_time;
static int hf_zbee_zcl_level_control_srv_rx_cmd_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_level_control;

/* Attributes */
static const value_string zbee_zcl_level_control_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_CURRENT_LEVEL,             "Current Level" },
    { ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_REMAINING_TIME,            "Remaining Time" },
    { ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_ONOFF_TRANSIT_TIME,        "OnOff Transition Time" },
    { ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_ON_LEVEL,                  "On Level" },
    { ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_STARTUP_LEVEL,             "Startup Level" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_level_control_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE_TO_LEVEL,              "Move to Level" },
    { ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE,                       "Move" },
    { ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STEP,                       "Step" },
    { ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STOP,                       "Stop" },
    { ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE_TO_LEVEL_WITH_ONOFF,   "Move to Level with OnOff" },
    { ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE_WITH_ONOFF,            "Move with OnOff" },
    { ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STEP_WITH_ONOFF,            "Step with OnOff" },
    { ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STOP_WITH_ONOFF,            "Stop with OnOff" },
    { 0, NULL }
};

/* Move Mode Values */
static const value_string zbee_zcl_level_control_move_step_mode_values[] = {
    { 0x00,   "Up" },
    { 0x01,   "Down" },
    { 0, NULL }
};

static const range_string zbee_zcl_level_control_startup_level_names[] = {
    { 0x00, 0x00, "Set the CurrentLevel attribute to the minimum" },
    { 0x01, 0xFE, "Set the CurrentLevel attribute to this value" },
    { 0xFF, 0xFF, "Set the CurrentLevel attribute to its previous value" },
    { 0, 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_level_control_move_to_level
 *  DESCRIPTION
 *      this function decodes the Move to Level payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_level_control_move_to_level(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Level" field */
    proto_tree_add_item(tree, hf_zbee_zcl_level_control_level, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Transition Time" field */
    proto_tree_add_item(tree, hf_zbee_zcl_level_control_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_level_control_move_to_level*/


 /*FUNCTION:--------------------------------------------------------------------
 *  NAME
 *      dissect_zcl_level_control_move
 *  DESCRIPTION
 *      this function decodes the Move payload
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *------------------------------------------------------------------------------
 */

static void
dissect_zcl_level_control_move(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Move Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_level_control_move_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Rate" field */
    proto_tree_add_item(tree, hf_zbee_zcl_level_control_rate, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_level_control_move*/


/*FUNCTION:-------------------------------------------------------------------
*  NAME
*      dissect_zcl_level_control_step
*  DESCRIPTION
*      this function decodes the Step payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*-----------------------------------------------------------------------------
*/
static void
dissect_zcl_level_control_step(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Step Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_level_control_step_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Step Size" field */
    proto_tree_add_item(tree, hf_zbee_zcl_level_control_step_size, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Transition Time" field */
    proto_tree_add_item(tree, hf_zbee_zcl_level_control_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_level_control_step*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_level_control_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_level_control
 *  DESCRIPTION
 *      ZigBee ZCL Level Control cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_level_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_level_control_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_level_control_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_level_control, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE_TO_LEVEL:
                case ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE_TO_LEVEL_WITH_ONOFF:
                    dissect_zcl_level_control_move_to_level(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE:
                case ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_MOVE_WITH_ONOFF:
                    dissect_zcl_level_control_move(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STEP:
                case ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STEP_WITH_ONOFF:
                    dissect_zcl_level_control_step(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STOP:
                case ZBEE_ZCL_CMD_ID_LEVEL_CONTROL_STOP_WITH_ONOFF:
                    /* No Payload */
                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_level_control*/



static void
dissect_zcl_level_control_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {
        case ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_CURRENT_LEVEL:
            proto_tree_add_item(tree, hf_zbee_zcl_level_control_attr_current_level, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_REMAINING_TIME:
            proto_tree_add_item(tree, hf_zbee_zcl_level_control_attr_remaining_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_ONOFF_TRANSIT_TIME:
            proto_tree_add_item(tree, hf_zbee_zcl_level_control_attr_onoff_transmit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_ON_LEVEL:
            proto_tree_add_item(tree, hf_zbee_zcl_level_control_attr_on_level, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_LEVEL_CONTROL_STARTUP_LEVEL:
            proto_tree_add_item(tree, hf_zbee_zcl_level_control_attr_startup_level, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_level_control_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_level_control
 *  DESCRIPTION
 *      ZigBee ZCL Level Control cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_level_control(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_level_control_attr_id,
            { "Attribute", "zbee_zcl_general.level_control.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_level_control_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_attr_current_level,
            { "Current Level", "zbee_zcl_general.level_control.attr.current_level", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_attr_remaining_time,
            { "Remaining Time", "zbee_zcl_general.level_control.attr.remaining_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_100ms),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_attr_onoff_transmit_time,
            { "Current Level", "zbee_zcl_general.level_control.attr.onoff_transmit_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_100ms),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_attr_on_level,
            { "On Level", "zbee_zcl_general.level_control.attr.on_level", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_attr_startup_level,
            { "Startup Level", "zbee_zcl_general.level_control.attr.startup_level", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_level_control_startup_level_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_level,
            { "Level", "zbee_zcl_general.level_control.level", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_move_mode,
            { "Move Mode", "zbee_zcl_general.level_control.move_mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_level_control_move_step_mode_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_rate,
            { "Rate", "zbee_zcl_general.level_control.rate", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_step_mode,
            { "Step Mode", "zbee_zcl_general.level_control.step_mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_level_control_move_step_mode_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_step_size,
            { "Step Size", "zbee_zcl_general.level_control.step_size", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_transit_time,
            { "Transition Time", "zbee_zcl_general.level_control.transit_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_100ms),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_level_control_srv_rx_cmd_id,
          { "Command", "zbee_zcl_general.level_control.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_level_control_srv_rx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Identify subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_level_control
    };

    /* Register the ZigBee ZCL Level Control cluster protocol name and description */
    proto_zbee_zcl_level_control = proto_register_protocol("ZigBee ZCL Level Control", "ZCL Level Control", ZBEE_PROTOABBREV_ZCL_LEVEL_CONTROL);
    proto_register_field_array(proto_zbee_zcl_level_control, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Level Control dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_LEVEL_CONTROL, dissect_zbee_zcl_level_control, proto_zbee_zcl_level_control);

} /*proto_register_zbee_zcl_level_control*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_level_control
 *  DESCRIPTION
 *      Hands off the ZCL Level Control dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_level_control(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_LEVEL_CONTROL,
                            proto_zbee_zcl_level_control,
                            ett_zbee_zcl_level_control,
                            ZBEE_ZCL_CID_LEVEL_CONTROL,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_level_control_attr_id,
                            hf_zbee_zcl_level_control_attr_id,
                            hf_zbee_zcl_level_control_srv_rx_cmd_id,
                            -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_level_control_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_level_control*/


/* ########################################################################## */
/* #### (0x000B) RSSI LOCATION CLUSTER ###################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE                        0x0000  /* Location Type */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD                      0x0001  /* Location Method */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_AGE                         0x0002  /* Location Age */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_QUALITY_MEASURE                      0x0003  /* Quality Measure */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_NUMBER_OF_DEVICES                    0x0004  /* Number of Devices */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_COORDINATE_1                         0x0010  /* Coordinate 1 */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_COORDINATE_2                         0x0011  /* Coordinate 2 */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_COORDINATE_3                         0x0012  /* Coordinate 3 */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_POWER                                0x0013  /* Power */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_PATH_LOSS_EXPONENT                   0x0014  /* Path Loss Exponent */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_REPORTING_PERIOD                     0x0015  /* Reporting Period */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_CALCULATION_PERIOD                   0x0016  /* Calculation Period */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_NUMBER_RSSI_MEAS                     0x0017  /* Number RSSI Measurements */

/* Location Type Mask Values */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_ABSOLUTE               0x01    /* Absolute/Measured */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_2D                     0x02    /* 2D/3D */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_COORDINATE             0x0C    /* Coordinate System */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_RESERVED               0xF0    /* Coordinate System */

/* Location Method Values */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD_LATERATION           0x00    /* Lateration */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD_SIGNPOSTING          0x01    /* Signposting */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD_RF_FINGERPRINTING    0x02    /* RF Fingerprinting */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD_OUT_OF_BAND          0x03    /* Out of Band */
#define ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD_CENTRALIZED          0x04    /* Centralized */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_SET_ABSOLUTE_LOCATION                 0x00    /* Set Absolute Location */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_SET_DEVICE_CONFIG                     0x01    /* Set Device Configuration */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_GET_DEVICE_CONFIG                     0x02    /* Get Device Configuration */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_GET_LOCATION_DATA                     0x03    /* Get Location Data */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_RSSI_RESPONSE                         0x04    /* RSSI Response */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_SEND_PINGS                            0x05    /* Send Pings */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_ANCHOR_NODE_ANNOUNCE                  0x06    /* Anchor Node Announce */


/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_DEVICE_CONFIG_RESPONSE                0x00    /* Device Configuration Response */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_LOCATION_DATA_RESPONSE                0x01    /* Location Data Response */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_LOCATION_DATA_NOTIF                   0x02    /* Location Data Notification */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_COMPACT_LOCATION_DATA_NOTIF           0x03    /* Compact Location Data Notification */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_RSSI_PING                             0x04    /* RSSI Ping */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_RSSI_REQUEST                          0x05    /* RSSI Request */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_REPORT_RSSI_MEAS                      0x06    /* Report RSSI Measurements */
#define ZBEE_ZCL_CMD_ID_RSSI_LOCATION_REQUEST_OWN_LOCATION                  0x07    /* Request Own Location */


/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_rssi_location(void);
void proto_reg_handoff_zbee_zcl_rssi_location(void);

/* Command Dissector Helpers */
static void dissect_zcl_rssi_location_set_absolute_location                         (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_set_device_config                             (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_get_device_config                             (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_get_location_data                             (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_rssi_response                                 (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_send_pings                                    (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_anchor_node_announce                          (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

static void dissect_zcl_rssi_location_device_config_response                        (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_location_data_response                        (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_location_data_notif                           (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_compact_location_data_notif                   (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_rssi_ping                                     (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_report_rssi_meas                              (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_rssi_location_request_own_location                          (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

static void dissect_zcl_rssi_location_attr_data                        (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_rssi_location;

static int hf_zbee_zcl_rssi_location_attr_id;
static int hf_zbee_zcl_rssi_location_location_type;
static int hf_zbee_zcl_rssi_location_location_type_absolute;
static int hf_zbee_zcl_rssi_location_location_type_2D;
static int hf_zbee_zcl_rssi_location_location_type_coordinate_system;
static int hf_zbee_zcl_rssi_location_location_type_reserved;
static int hf_zbee_zcl_rssi_location_attr_id_location_method;
static int hf_zbee_zcl_rssi_location_coordinate1;
static int hf_zbee_zcl_rssi_location_coordinate2;
static int hf_zbee_zcl_rssi_location_coordinate3;
static int hf_zbee_zcl_rssi_location_power;
static int hf_zbee_zcl_rssi_location_path_loss_expo;
static int hf_zbee_zcl_rssi_location_calc_period;
static int hf_zbee_zcl_rssi_location_number_rssi_meas;
static int hf_zbee_zcl_rssi_location_reporting_period;
static int hf_zbee_zcl_rssi_location_target_add;
static int hf_zbee_zcl_rssi_location_header;
static int hf_zbee_zcl_rssi_location_header_abs_only;
static int hf_zbee_zcl_rssi_location_header_recalc;
static int hf_zbee_zcl_rssi_location_header_bcast_ind;
static int hf_zbee_zcl_rssi_location_header_bcast_res;
static int hf_zbee_zcl_rssi_location_header_compact_res;
static int hf_zbee_zcl_rssi_location_header_res;
static int hf_zbee_zcl_rssi_location_number_responses;
static int hf_zbee_zcl_rssi_location_replaying_device;
static int hf_zbee_zcl_rssi_location_rssi;
static int hf_zbee_zcl_rssi_location_anchor_node_add;
static int hf_zbee_zcl_rssi_location_status;
static int hf_zbee_zcl_rssi_location_quality_measure;
static int hf_zbee_zcl_rssi_location_location_age;
static int hf_zbee_zcl_rssi_location_reporting_add;
static int hf_zbee_zcl_rssi_location_no_of_neigh;
static int hf_zbee_zcl_rssi_location_neighbour_add;
static int hf_zbee_zcl_rssi_location_request_add;
static int hf_zbee_zcl_rssi_location_srv_rx_cmd_id;
static int hf_zbee_zcl_rssi_location_srv_tx_cmd_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_rssi_location;
static int ett_zbee_zcl_rssi_location_location_type;
static int ett_zbee_zcl_rssi_location_header;

/* Attributes */
static const value_string zbee_zcl_rssi_location_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE,                     "Location Type" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD,                   "Location Method" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_AGE,                      "Location Age" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_QUALITY_MEASURE,                   "Quality Measure" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_NUMBER_OF_DEVICES,                 "Number of Devices" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_COORDINATE_1,                      "Coordinate 1" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_COORDINATE_2,                      "Coordinate 2" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_COORDINATE_3,                      "Coordinate 3" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_POWER,                             "Power" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_PATH_LOSS_EXPONENT,                "Path Loss Exponent" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_REPORTING_PERIOD,                  "Reporting Period" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_CALCULATION_PERIOD,                "Calculation Period" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_NUMBER_RSSI_MEAS,                  "Number RSSI Measurements" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_rssi_location_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_SET_ABSOLUTE_LOCATION,              "Set Absolute Location" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_SET_DEVICE_CONFIG,                  "Set Device Configuration" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_GET_DEVICE_CONFIG,                  "Get Device Configuration" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_GET_LOCATION_DATA,                  "Get Location Data" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_RSSI_RESPONSE,                      "RSSI Response" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_SEND_PINGS,                         "Send Pings" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_ANCHOR_NODE_ANNOUNCE,               "Anchor Node Announce" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_rssi_location_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_DEVICE_CONFIG_RESPONSE,             "Device Configuration Response" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_LOCATION_DATA_RESPONSE,             "Location Data Response" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_LOCATION_DATA_NOTIF,                "Location Data Notification" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_COMPACT_LOCATION_DATA_NOTIF,        "Compact Location Data Notification" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_RSSI_PING,                          "RSSI Ping" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_RSSI_REQUEST,                       "RSSI Request" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_REPORT_RSSI_MEAS,                   "Report RSSI Measurements" },
    { ZBEE_ZCL_CMD_ID_RSSI_LOCATION_REQUEST_OWN_LOCATION,               "Request Own Location" },
    { 0, NULL }
};

/* Location Method Values */
static const value_string zbee_zcl_rssi_location_location_method_values[] = {
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD_LATERATION,        "Lateration" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD_SIGNPOSTING,       "Signposting" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD_RF_FINGERPRINTING, "RF Fingerprinting" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD_OUT_OF_BAND,       "Out of Band" },
    { ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD_CENTRALIZED,       "Centralized" },
    { 0, NULL }
};

/* Location type absolute values*/
static const value_string zbee_zcl_rssi_location_location_type_abs_values[] = {
    {0, "Measured Location"},
    {1, "Absolute Location"},
    {0, NULL}
};

/* Location type 2D/3D values*/
static const value_string zbee_zcl_rssi_location_location_type_2D_values[] = {
    {0, "Three Dimensional"},
    {1, "Two Dimensional"},
    {0, NULL}
};

/* Location type Coordinate System values*/
static const value_string zbee_zcl_rssi_location_location_type_coordinate_values[] = {
    {0, "Rectangular"},
    {1, "Reserved"},
    {2, "Reserved"},
    {3, "Reserved"},
    {0, NULL}
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_rssi_location
 *  DESCRIPTION
 *      ZigBee ZCL RSSI Location cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_rssi_location(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_rssi_location_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_rssi_location, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_SET_ABSOLUTE_LOCATION:
                    dissect_zcl_rssi_location_set_absolute_location(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_SET_DEVICE_CONFIG:
                    dissect_zcl_rssi_location_set_device_config(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_GET_DEVICE_CONFIG:
                    dissect_zcl_rssi_location_get_device_config(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_GET_LOCATION_DATA:
                    dissect_zcl_rssi_location_get_location_data(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_RSSI_RESPONSE:
                    dissect_zcl_rssi_location_rssi_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_SEND_PINGS:
                    dissect_zcl_rssi_location_send_pings(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_ANCHOR_NODE_ANNOUNCE:
                    dissect_zcl_rssi_location_anchor_node_announce(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_rssi_location_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_rssi_location, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_DEVICE_CONFIG_RESPONSE:
                    dissect_zcl_rssi_location_device_config_response(tvb, payload_tree, &offset);
                    break;
                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_LOCATION_DATA_RESPONSE:
                    dissect_zcl_rssi_location_location_data_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_LOCATION_DATA_NOTIF:
                    dissect_zcl_rssi_location_location_data_notif(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_COMPACT_LOCATION_DATA_NOTIF:
                    dissect_zcl_rssi_location_compact_location_data_notif(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_RSSI_PING:
                    dissect_zcl_rssi_location_rssi_ping(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_RSSI_REQUEST:
                    /* No Payload */
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_REPORT_RSSI_MEAS:
                    dissect_zcl_rssi_location_report_rssi_meas(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_RSSI_LOCATION_REQUEST_OWN_LOCATION:
                    dissect_zcl_rssi_location_request_own_location(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_rssi_location*/


 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_rssi_location_set_absolute_location
 *  DESCRIPTION
 *      this function decodes the Set Absolute Location payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_rssi_location_set_absolute_location(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Coordinate 1" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate1, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Coordinate 2" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate2, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Coordinate 3" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate3, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Power" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_power, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Path Loss Exponent" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_path_loss_expo, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_rssi_location_set_absolute_location*/


 /*FUNCTION:--------------------------------------------------------------------
 *  NAME
 *      dissect_zcl_rssi_location_set_device_config
 *  DESCRIPTION
 *      this function decodes the Set Device Configuration payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *------------------------------------------------------------------------------
 */
static void
dissect_zcl_rssi_location_set_device_config(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Power" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_power, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Path Loss Exponent" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_path_loss_expo, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Calculation Period" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_calc_period, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Number RSSI Measurements" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_number_rssi_meas, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Reporting Period" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_reporting_period, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_rssi_location_set_device_config*/


/*FUNCTION:-------------------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_get_device_config
*  DESCRIPTION
*      this function decodes the Get Device Configuration payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*-----------------------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_get_device_config(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Target Address" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_target_add, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;

} /*dissect_zcl_rssi_location_get_device_config*/


/*FUNCTION:-------------------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_get_location_data
*  DESCRIPTION
*      this function decodes the Get Location Data payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*-----------------------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_get_location_data(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
     uint8_t header;

    static int * const location_header_fields[] = {
        &hf_zbee_zcl_rssi_location_header_abs_only,
        &hf_zbee_zcl_rssi_location_header_recalc,
        &hf_zbee_zcl_rssi_location_header_bcast_ind,
        &hf_zbee_zcl_rssi_location_header_bcast_res,
        &hf_zbee_zcl_rssi_location_header_compact_res,
        &hf_zbee_zcl_rssi_location_header_res,
        NULL
    };

    /* Retrieve "8-bit header" field */
    header = tvb_get_uint8(tvb, *offset);
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_rssi_location_header, ett_zbee_zcl_rssi_location_header, location_header_fields, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve the number responses field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_number_responses, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve the IEEE address field */
    if(header & 0x04)
    {
        proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_target_add, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;
    }

} /*dissect_zcl_rssi_location_get_location_data*/


/*FUNCTION:--------------------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_rssi_response
*  DESCRIPTION
*      this function decodes the RSSI Response payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*------------------------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_rssi_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Replaying Device" field */
   proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_replaying_device, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
   *offset += 8;

   /* Retrieve "Coordinate 1" field */
   proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate1, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Coordinate 2" field */
   proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate2, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Coordinate 3" field */
   proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate3, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "RSSI" field */
   proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_rssi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Number RSSI Measurements" field */
   proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_number_rssi_meas, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

} /*dissect_zcl_rssi_location_rssi_response*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_send_pings
*  DESCRIPTION
*      this function decodes the Send Pings payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_send_pings(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Target Address" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_target_add, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;

    /* Retrieve "Number RSSI Measurements" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_number_rssi_meas, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Calculation Period" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_calc_period, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_rssi_location_send_pings*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_anchor_node_announce
*  DESCRIPTION
*      this function decodes the Anchor Node Announce payload
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_anchor_node_announce(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Anchor Node Address" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_anchor_node_add, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;

    /* Retrieve "Coordinate 1" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate1, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Coordinate 2" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate2, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Coordinate 3" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate3, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_rssi_location_anchor_node_announce*/


/*FUNCTION:--------------------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_device_config_response
*  DESCRIPTION
*      this function decodes the Device Configuration Response payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*------------------------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_device_config_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   uint8_t status;

   /* Retrieve "Status" field */
   status = tvb_get_uint8(tvb, *offset);
   proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   if(status == ZBEE_ZCL_STAT_SUCCESS)
   {
       /* Retrieve "Power" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_power, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

       /* Retrieve "Path Loss Exponent" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_path_loss_expo, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

       /* Retrieve "Calculation Period" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_calc_period, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

       /* Retrieve "Number RSSI Measurements" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_number_rssi_meas, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
       *offset += 1;

       /* Retrieve "Reporting Period" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_reporting_period, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;
   }

} /*dissect_zcl_rssi_location_device_config_response*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_location_data_response
*  DESCRIPTION
*      this function decodes the Location Data Response payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_location_data_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   uint8_t status;

   /* Retrieve "Status" field */
   status = tvb_get_uint8(tvb, *offset);
   proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   if(status == ZBEE_ZCL_STAT_SUCCESS)
   {
       /* Retrieve "Location Type" field */
       dissect_zcl_rssi_location_attr_data(tree, tvb, offset, ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE, ZBEE_ZCL_8_BIT_DATA, false);

       /* Retrieve "Coordinate 1" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate1, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

       /* Retrieve "Coordinate 2" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate2, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

       /* Retrieve "Coordinate 3" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate3, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

       /* Retrieve "Power" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_power, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

       /* Retrieve "Path Loss Exponent" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_path_loss_expo, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

       /* Retrieve "Location Method" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_attr_id_location_method, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
       *offset += 1;

       /* Retrieve "Quality Measure" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_quality_measure, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
       *offset += 1;

       /* Retrieve "Location Age" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_location_age, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;
   }

} /*dissect_zcl_rssi_location_location_data_response*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_location_data_notif
*  DESCRIPTION
*      this function decodes the Location Data Notification payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_location_data_notif(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t temp;

    /* Retrieve "Location Type" field */
    temp = tvb_get_uint8(tvb, *offset);
    dissect_zcl_rssi_location_attr_data(tree, tvb, offset, ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE, ZBEE_ZCL_8_BIT_DATA, false);

    /* Retrieve "Coordinate 1" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate1, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Coordinate 2" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate2, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

   if((temp & ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_2D) != 0x02)
   {
       /* Retrieve "Coordinate 3" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate3, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;
   }

       /* Retrieve "Power" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_power, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

       /* Retrieve "Path Loss Exponent" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_path_loss_expo, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

   if((temp & ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_COORDINATE) != 0x0C)
   {
       /* Retrieve "Location Method" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_attr_id_location_method, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
       *offset += 1;

       /* Retrieve "Quality Measure" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_quality_measure, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
       *offset += 1;

       /* Retrieve "Location Age" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_location_age, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

   }

} /*dissect_zcl_rssi_location_location_data_notif*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_compact_location_data_notif
*  DESCRIPTION
*      this function decodes the Location Data Notification payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_compact_location_data_notif(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t temp;

    /* Retrieve "Location Type" field */
    temp = tvb_get_uint8(tvb, *offset);
    dissect_zcl_rssi_location_attr_data(tree, tvb, offset, ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE, ZBEE_ZCL_8_BIT_DATA, false);

    /* Retrieve "Coordinate 1" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate1, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Coordinate 2" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate2, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

   if((temp & ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_2D) != 0x02)
   {
       /* Retrieve "Coordinate 3" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate3, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;
   }

   if((temp & ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_COORDINATE) != 0x0C)
   {
       /* Retrieve "Quality Measure" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_quality_measure, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
       *offset += 1;

       /* Retrieve "Location Age" field */
       proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_location_age, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;

   }

} /*dissect_zcl_rssi_location_compact_location_data_notif*/

/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_rssi_ping
*  DESCRIPTION
*      this function decodes the RSSI Ping payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_rssi_ping(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Location Type" field */
    dissect_zcl_rssi_location_attr_data(tree, tvb, offset, ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE, ZBEE_ZCL_8_BIT_DATA, false);


} /*dissect_zcl_rssi_location_rssi_ping*/


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_report_rssi_meas
*  DESCRIPTION
*      this function decodes the Report RSSI Measurements payload
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_report_rssi_meas(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t count, i;
    /* Retrieve "Reporting Address" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_reporting_add, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;

    /* Retrieve "Number of Neighbours" field */
    count = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_no_of_neigh, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    for( i = 0; i < count; i++)
    {
        /* Retrieve "Neighbour Address" field */
        proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_neighbour_add, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;

        /* Retrieve "Coordinate 1" field */
        proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate1, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve "Coordinate 2" field */
        proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate2, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve "Coordinate 3" field */
        proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_coordinate3, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve "RSSI" field */
        proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_rssi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;

        /* Retrieve "Number RSSI Measurements" field */
        proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_number_rssi_meas, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }

} /*dissect_zcl_rssi_location_report_rssi_meas*/


/*FUNCTION:-------------------------------------------------------------------
*  NAME
*      dissect_zcl_rssi_location_request_own_location
*  DESCRIPTION
*      this function decodes the Request Own Location payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*-----------------------------------------------------------------------------
*/
static void
dissect_zcl_rssi_location_request_own_location(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Requesting Address Address" field */
    proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_request_add, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;

} /*dissect_zcl_rssi_location_request_own_location*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_rssi_location_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_rssi_location_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    static int * const location_type[] = {
        &hf_zbee_zcl_rssi_location_location_type_absolute,
        &hf_zbee_zcl_rssi_location_location_type_2D,
        &hf_zbee_zcl_rssi_location_location_type_coordinate_system,
        &hf_zbee_zcl_rssi_location_location_type_reserved,
        NULL
    };

    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_rssi_location_location_type, ett_zbee_zcl_rssi_location_location_type, location_type, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_METHOD:
            proto_tree_add_item(tree, hf_zbee_zcl_rssi_location_attr_id_location_method, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_AGE:
        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_QUALITY_MEASURE:
        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_NUMBER_OF_DEVICES:
        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_COORDINATE_1:
        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_COORDINATE_2:
        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_COORDINATE_3:
        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_POWER:
        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_PATH_LOSS_EXPONENT:
        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_REPORTING_PERIOD:
        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_CALCULATION_PERIOD:
        case ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_NUMBER_RSSI_MEAS:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_rssi_location_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_rssi_location
 *  DESCRIPTION
 *      ZigBee ZCL RSSI Location cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_rssi_location(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_rssi_location_attr_id,
            { "Attribute", "zbee_zcl_general.rssi_location.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_rssi_location_attr_names),
            0x00, NULL, HFILL } },

        /* start Location Type fields */
        { &hf_zbee_zcl_rssi_location_location_type,
            { "Location Type", "zbee_zcl_general.rssi_location.attr_id.location_type", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_location_type_absolute,
            { "Location Type Absolute/Measured", "zbee_zcl_general.rssi_location.attr_id.location_type.abs", FT_UINT8, BASE_HEX, VALS(zbee_zcl_rssi_location_location_type_abs_values),
            ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_ABSOLUTE, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_location_type_2D,
            { "Location Type 2D/3D", "zbee_zcl_general.rssi_location.attr_id.location_type.2D", FT_UINT8, BASE_HEX, VALS(zbee_zcl_rssi_location_location_type_2D_values),
            ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_2D, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_location_type_coordinate_system,
            { "Location Type Coordinate System", "zbee_zcl_general.rssi_location.attr_id.location_type.coordinate", FT_UINT8, BASE_HEX, VALS(zbee_zcl_rssi_location_location_type_coordinate_values),
            ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_COORDINATE, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_location_type_reserved,
            { "Reserved", "zbee_zcl_general.rssi_location.attr_id.location_type.reserved", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_ATTR_ID_RSSI_LOCATION_LOCATION_TYPE_RESERVED, NULL, HFILL } },
        /* end Location Type fields */

        { &hf_zbee_zcl_rssi_location_attr_id_location_method,
            { "Location Method", "zbee_zcl_general.rssi_location.attr_id.location_method", FT_UINT8, BASE_HEX, VALS(zbee_zcl_rssi_location_location_method_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_coordinate1,
            { "Coordinate 1", "zbee_zcl_general.rssi_location.coordinate1", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_coordinate2,
            { "Coordinate 2", "zbee_zcl_general.rssi_location.coordinate2", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_coordinate3,
            { "Coordinate 3", "zbee_zcl_general.rssi_location.coordinate3", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_power,
            { "Power", "zbee_zcl_general.rssi_location.power", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_path_loss_expo,
            { "Path Loss Exponent", "zbee_zcl_general.rssi_location.path_loss_exponent", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_calc_period,
            { "Calculation Period", "zbee_zcl_general.rssi_location.calc_period", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_number_rssi_meas,
            { "Number RSSI Measurements", "zbee_zcl_general.rssi_location.number_rssi_meas", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_reporting_period,
            { "Reporting Period", "zbee_zcl_general.rssi_location.reporting_period", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_target_add,
            { "Target Address", "zbee_zcl_general.rssi_location.target_add", FT_UINT64, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_header,
            { "Header Data", "zbee_zcl_general.rssi_location.location_header", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_header_abs_only,
            { "Absolute Only", "zbee_zcl_general.rssi_location.header.abs_only", FT_BOOLEAN, 8, NULL,
            0x01, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_header_recalc,
            { "Recalculate", "zbee_zcl_general.rssi_location.header.recalc", FT_BOOLEAN, 8, NULL,
            0x02, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_header_bcast_ind,
            { "Broadcast Indicator", "zbee_zcl_general.rssi_location.header.bcast_ind", FT_BOOLEAN, 8, NULL,
            0x04, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_header_bcast_res,
            { "Broadcast Response", "zbee_zcl_general.rssi_location.header.bcast_response", FT_BOOLEAN, 8, NULL,
            0x08, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_header_compact_res,
            { "Compact Response", "zbee_zcl_general.rssi_location.compact_res", FT_BOOLEAN, 8, NULL,
            0x10, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_header_res,
            { "Reserved", "zbee_zcl_general.rssi_location.reserved", FT_BOOLEAN, 8, NULL,
            0xE0, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_number_responses,
            { "Number Responses", "zbee_zcl_general.rssi_location.number_responses", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_replaying_device,
            { "Replying Device", "zbee_zcl_general.rssi_location.replying_device", FT_UINT64, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_rssi,
            { "RSSI", "zbee_zcl_general.rssi_location.rssi", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_anchor_node_add,
            { "Anchor Node Address", "zbee_zcl_general.rssi_location.anchor_node_add", FT_UINT64, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_status,
            { "Status", "zbee_zcl_general.rssi_location.status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_status_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_quality_measure,
            { "Quality Measure", "zbee_zcl_general.rssi_location.quality_measure", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_location_age,
            { "Location Age", "zbee_zcl_general.rssi_location.location_age", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_reporting_add,
            { "Reporting Address", "zbee_zcl_general.rssi_location.reporting_add", FT_UINT64, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_no_of_neigh,
            { "Number of Neighbours", "zbee_zcl_general.rssi_location.no_of_neigh", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_neighbour_add,
            { "Neighbour Address", "zbee_zcl_general.rssi_location.neighbour_add", FT_UINT64, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_request_add,
            { "Requesting Address", "zbee_zcl_general.rssi_location.request_add", FT_UINT64, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_srv_rx_cmd_id,
          { "Command", "zbee_zcl_general.rssi_location.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_rssi_location_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_rssi_location_srv_tx_cmd_id,
          { "Command", "zbee_zcl_general.rssi_location.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_rssi_location_srv_tx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL RSSI Location subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_rssi_location,
        &ett_zbee_zcl_rssi_location_location_type,
        &ett_zbee_zcl_rssi_location_header
    };

    /* Register the ZigBee ZCL RSSI Location cluster protocol name and description */
    proto_zbee_zcl_rssi_location = proto_register_protocol("ZigBee ZCL RSSI Location", "ZCL RSSI Location", ZBEE_PROTOABBREV_ZCL_RSSI_LOCATION);
    proto_register_field_array(proto_zbee_zcl_rssi_location, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL RSSI Location dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_RSSI_LOCATION, dissect_zbee_zcl_rssi_location, proto_zbee_zcl_rssi_location);

} /*proto_register_zbee_zcl_rssi_location*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_rssi_location
 *  DESCRIPTION
 *      Hands off the ZCL RSSI Location dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_rssi_location(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_RSSI_LOCATION,
                            proto_zbee_zcl_rssi_location,
                            ett_zbee_zcl_rssi_location,
                            ZBEE_ZCL_CID_RSSI_LOCATION,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_rssi_location_attr_id,
                            hf_zbee_zcl_rssi_location_attr_id,
                            hf_zbee_zcl_rssi_location_srv_rx_cmd_id,
                            hf_zbee_zcl_rssi_location_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_rssi_location_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_rssi_location*/

/****************************************************************************************************/
/****************************************************************************************************/
/****************************************************************************************************/


/* Reliability Enumeration Values */
#define ZBEE_ZCL_RELIABILITY_NO_FAULT_DETECTED              0x00    /* No Fault Detected */
#define ZBEE_ZCL_RELIABILITY_NO_SENSOR                      0x01    /* No Sensor */
#define ZBEE_ZCL_RELIABILITY_OVER_RANGE                     0x02    /* Over Range */
#define ZBEE_ZCL_RELIABILITY_UNDER_RANGE                    0x03    /* Under Range */
#define ZBEE_ZCL_RELIABILITY_OPEN_LOOP                      0x04    /* Open Loop */
#define ZBEE_ZCL_RELIABILITY_SHORTED_LOOP                   0x05    /* Shorted Loop */
#define ZBEE_ZCL_RELIABILITY_NO_OUTPUT                      0x06    /* No Output */
#define ZBEE_ZCL_RELIABILITY_UNRELIABLE_OTHER               0x07    /* Unreliable Other */
#define ZBEE_ZCL_RELIABILITY_PROCESS_ERROR                  0x08    /* Process Error */
#define ZBEE_ZCL_RELIABILITY_MULTI_STATE_FAULT              0x09    /* Multi-State Fault */
#define ZBEE_ZCL_RELIABILITY_CONFIGURATION_ERROR            0x0A    /* Configuration Error */

static const value_string zbee_zcl_reliability_names[] = {
    {ZBEE_ZCL_RELIABILITY_NO_FAULT_DETECTED,    "No Fault Detected"},
    {ZBEE_ZCL_RELIABILITY_NO_SENSOR,            "No Sensor"},
    {ZBEE_ZCL_RELIABILITY_OVER_RANGE,           "Over Range"},
    {ZBEE_ZCL_RELIABILITY_UNDER_RANGE,          "Under Range"},
    {ZBEE_ZCL_RELIABILITY_OPEN_LOOP,            "Open Loop"},
    {ZBEE_ZCL_RELIABILITY_SHORTED_LOOP,         "Shorted Loop"},
    {ZBEE_ZCL_RELIABILITY_NO_OUTPUT,            "No Output"},
    {ZBEE_ZCL_RELIABILITY_UNRELIABLE_OTHER,     "Unreliable Other"},
    {ZBEE_ZCL_RELIABILITY_PROCESS_ERROR,        "Process Error"},
    {ZBEE_ZCL_RELIABILITY_MULTI_STATE_FAULT,    "Multi-State Fault"},
    {ZBEE_ZCL_RELIABILITY_CONFIGURATION_ERROR,  "Configuration Error"},
    {0, NULL}
};

/* Status Flags Mask Values */
#define ZBEE_ZCL_STATUS_IN_ALARM                0x01      /* In Alarm Flag */
#define ZBEE_ZCL_STATUS_FAULT                   0x02      /* Fault Flag */
#define ZBEE_ZCL_STATUS_OVERRIDDEN              0x04      /* Overridden Flag */
#define ZBEE_ZCL_STATUS_OUT_OF_SERVICE          0x08      /* Out of Service Flag */


/* ########################################################################## */
/* #### (0x000C) ANALOG INPUT (BASIC) CLUSTER ############################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_DESCRIPTION                     0x001C  /* Description */
#define ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_MAX_PRESENT_VALUE               0x0041  /* Max Present Value */
#define ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_MIN_PRESENT_VALUE               0x0045  /* Min Present Value */
#define ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_OUT_OF_SERVICE                  0x0051  /* Out of Service */
#define ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_PRESENT_VALUE                   0x0055  /* Present Value */
#define ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_RELIABILITY                     0x0067  /* Reliability */
#define ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_RESOLUTION                      0x006A  /* Resolution */
#define ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_STATUS_FLAGS                    0x006F  /* Status Flags */
#define ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_ENGINEERING_UNITS               0x0075  /* Engineering Units */
#define ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_APPLICATION_TYPE                0x0100  /* Application Type */

/*Server commands received - none*/

/*Server commands generated - none*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_analog_input_basic(void);
void proto_reg_handoff_zbee_zcl_analog_input_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_analog_input_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_analog_input_basic;

static int hf_zbee_zcl_analog_input_basic_attr_id;
static int hf_zbee_zcl_analog_input_basic_reliability;
static int hf_zbee_zcl_analog_input_basic_status_flags;
static int hf_zbee_zcl_analog_input_basic_status_in_alarm;
static int hf_zbee_zcl_analog_input_basic_status_fault;
static int hf_zbee_zcl_analog_input_basic_status_overridden;
static int hf_zbee_zcl_analog_input_basic_status_out_of_service;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_analog_input_basic;
static int ett_zbee_zcl_analog_input_basic_status_flags;

/* Attributes */
static const value_string zbee_zcl_analog_input_basic_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_DESCRIPTION,          "Description" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_MAX_PRESENT_VALUE,    "Max Present Value" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_MIN_PRESENT_VALUE,    "Min Present Value" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_OUT_OF_SERVICE,       "Out of Service" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_PRESENT_VALUE,        "Present Value" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_RELIABILITY,          "Reliability" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_RESOLUTION,           "Resolution" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_STATUS_FLAGS,         "Status Flags" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_ENGINEERING_UNITS,    "Engineering Units" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_APPLICATION_TYPE,     "Application Type" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_analog_input_basic
 *  DESCRIPTION
 *      ZigBee ZCL Analog Input Basic cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_analog_input_basic(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
	return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_analog_input_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_analog_input_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_analog_input_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    static int * const status_flags[] = {
        &hf_zbee_zcl_analog_input_basic_status_in_alarm,
        &hf_zbee_zcl_analog_input_basic_status_fault,
        &hf_zbee_zcl_analog_input_basic_status_overridden,
        &hf_zbee_zcl_analog_input_basic_status_out_of_service,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_RELIABILITY:
            proto_tree_add_item(tree, hf_zbee_zcl_analog_input_basic_reliability, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_STATUS_FLAGS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_analog_input_basic_status_flags, ett_zbee_zcl_analog_input_basic_status_flags, status_flags, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_DESCRIPTION:
        case ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_MAX_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_MIN_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_OUT_OF_SERVICE:
        case ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_RESOLUTION:
        case ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_ENGINEERING_UNITS:
        case ZBEE_ZCL_ATTR_ID_ANALOG_INPUT_BASIC_APPLICATION_TYPE:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_analog_input_basic_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_analog_input_basic
 *  DESCRIPTION
 *      ZigBee ZCL Analog Input Basic cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_analog_input_basic(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_analog_input_basic_attr_id,
            { "Attribute", "zbee_zcl_general.analog_input_basic.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_analog_input_basic_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_analog_input_basic_reliability,
            { "Reliability", "zbee_zcl_general.analog_input_basic.attr.reliability", FT_UINT8, BASE_HEX, VALS(zbee_zcl_reliability_names),
            0x00, NULL, HFILL } },

        /* start Status Flags fields */
        { &hf_zbee_zcl_analog_input_basic_status_flags,
            { "Status Flags", "zbee_zcl_general.analog_input_basic.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_analog_input_basic_status_in_alarm,
            { "In Alarm Status", "zbee_zcl_general.analog_input_basic.attr.status.in_alarm", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_IN_ALARM, NULL, HFILL } },

        { &hf_zbee_zcl_analog_input_basic_status_fault,
            { "Fault Status", "zbee_zcl_general.analog_input_basic.attr.status.fault",FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_analog_input_basic_status_overridden,
            { "Overridden Status", "zbee_zcl_general.analog_input_basic.attr.status.overridden", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OVERRIDDEN, NULL, HFILL } },

        { &hf_zbee_zcl_analog_input_basic_status_out_of_service,
            { "Out of Service Status", "zbee_zcl_general.analog_input_basic.attr.status.out_of_service", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OUT_OF_SERVICE, NULL, HFILL } }
        /* end Status Flags fields */
    };

    /* ZCL Analog Input Basic subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_analog_input_basic,
        &ett_zbee_zcl_analog_input_basic_status_flags
    };



    /* Register the ZigBee ZCL Analog Input Basic cluster protocol name and description */
    proto_zbee_zcl_analog_input_basic = proto_register_protocol("ZigBee ZCL Analog Input Basic", "ZCL Analog Input Basic", ZBEE_PROTOABBREV_ZCL_ANALOG_INPUT_BASIC);
    proto_register_field_array(proto_zbee_zcl_analog_input_basic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Analog Input Basic dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_ANALOG_INPUT_BASIC, dissect_zbee_zcl_analog_input_basic, proto_zbee_zcl_analog_input_basic);
} /*proto_register_zbee_zcl_analog_input_basic*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_analog_input_basic
 *  DESCRIPTION
 *      Hands off the ZCL Analog Input Basic dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_analog_input_basic(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_ANALOG_INPUT_BASIC,
                            proto_zbee_zcl_analog_input_basic,
                            ett_zbee_zcl_analog_input_basic,
                            ZBEE_ZCL_CID_ANALOG_INPUT_BASIC,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_analog_input_basic_attr_id,
                            hf_zbee_zcl_analog_input_basic_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_analog_input_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_analog_input_basic*/


/* ########################################################################## */
/* #### (0x000D) ANALOG OUTPUT (BASIC) CLUSTER ############################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_DESCRIPTION                     0x001C  /* Description */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_MAX_PRESENT_VALUE               0x0041  /* Max Present Value */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_MIN_PRESENT_VALUE               0x0045  /* Min Present Value */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_OUT_OF_SERVICE                  0x0051  /* Out of Service */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_PRESENT_VALUE                   0x0055  /* Present Value */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_PRIORITY_ARRAY                  0x0057  /* Priority Array */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_RELIABILITY                     0x0067  /* Reliability */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_RELINQUISH_DEFAULT              0x0068  /* Relinquish Default */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_RESOLUTION                      0x006A  /* Resolution */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_STATUS_FLAGS                    0x006F  /* Status Flags */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_ENGINEERING_UNITS               0x0075  /* Engineering Units */
#define ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_APPLICATION_TYPE                0x0100  /* Application Type */

/*Server commands received - none*/

/*Server commands generated - none*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_analog_output_basic(void);
void proto_reg_handoff_zbee_zcl_analog_output_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_analog_output_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_analog_output_basic;

static int hf_zbee_zcl_analog_output_basic_attr_id;
static int hf_zbee_zcl_analog_output_basic_reliability;
static int hf_zbee_zcl_analog_output_basic_status_flags;
static int hf_zbee_zcl_analog_output_basic_status_in_alarm;
static int hf_zbee_zcl_analog_output_basic_status_fault;
static int hf_zbee_zcl_analog_output_basic_status_overridden;
static int hf_zbee_zcl_analog_output_basic_status_out_of_service;
static int hf_zbee_zcl_analog_output_basic_priority_array_bool;
static int hf_zbee_zcl_analog_output_basic_priority_array_sing_prec;
static int hf_zbee_zcl_analog_output_basic_priority_array;
static int hf_zbee_zcl_analog_output_basic_structure;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_analog_output_basic;
static int ett_zbee_zcl_analog_output_basic_status_flags;
static int ett_zbee_zcl_analog_output_basic_priority_array;
static int ett_zbee_zcl_analog_output_basic_priority_array_structure;

/* Attributes */
static const value_string zbee_zcl_analog_output_basic_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_DESCRIPTION,          "Description" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_MAX_PRESENT_VALUE,    "Max Present Value" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_MIN_PRESENT_VALUE,    "Min Present Value" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_OUT_OF_SERVICE,       "Out of Service" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_PRESENT_VALUE,        "Present Value" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_PRIORITY_ARRAY,       "Priority Array" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_RELIABILITY,          "Reliability" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_RELINQUISH_DEFAULT,   "Relinquish Default" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_RESOLUTION,           "Resolution" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_STATUS_FLAGS,         "Status Flags" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_ENGINEERING_UNITS,    "Engineering Units" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_APPLICATION_TYPE,     "Application Type" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_analog_output_basic
 *  DESCRIPTION
 *      ZigBee ZCL Analog Output Basic cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_analog_output_basic(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
	return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_analog_output_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_analog_output_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_analog_output_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    proto_item  *ti = NULL, *tj = NULL;
    proto_tree  *sub_tree = NULL, *sub = NULL;
    int i;

    static int * const status_flags[] = {
        &hf_zbee_zcl_analog_output_basic_status_in_alarm,
        &hf_zbee_zcl_analog_output_basic_status_fault,
        &hf_zbee_zcl_analog_output_basic_status_overridden,
        &hf_zbee_zcl_analog_output_basic_status_out_of_service,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_PRIORITY_ARRAY:
            ti = proto_tree_add_item(tree,hf_zbee_zcl_analog_output_basic_priority_array, tvb, *offset, 80, ENC_NA);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_analog_output_basic_priority_array);

            for(i = 1; i <= 16; i++)
            {
                tj = proto_tree_add_item(sub_tree, hf_zbee_zcl_analog_output_basic_structure, tvb, *offset, 5, ENC_NA);
                proto_item_append_text(tj," %d",i);
                sub = proto_item_add_subtree(tj, ett_zbee_zcl_analog_output_basic_priority_array_structure);
                proto_tree_add_item(sub, hf_zbee_zcl_analog_output_basic_priority_array_bool, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
                *offset += 1;
                proto_tree_add_item(sub, hf_zbee_zcl_analog_output_basic_priority_array_sing_prec, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            break;

        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_RELIABILITY:
            proto_tree_add_item(tree, hf_zbee_zcl_analog_output_basic_reliability, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_STATUS_FLAGS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_analog_output_basic_status_flags, ett_zbee_zcl_analog_output_basic_status_flags, status_flags, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_DESCRIPTION:
        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_MAX_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_MIN_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_OUT_OF_SERVICE:
        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_RELINQUISH_DEFAULT:
        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_RESOLUTION:
        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_ENGINEERING_UNITS:
        case ZBEE_ZCL_ATTR_ID_ANALOG_OUTPUT_BASIC_APPLICATION_TYPE:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_analog_output_basic_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_analog_output_basic
 *  DESCRIPTION
 *      ZigBee ZCL Analog Output Basic cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_analog_output_basic(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_analog_output_basic_attr_id,
            { "Attribute", "zbee_zcl_general.analog_output_basic.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_analog_output_basic_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_analog_output_basic_reliability,
            { "Reliability", "zbee_zcl_general.analog_output_basic.attr.reliability", FT_UINT8, BASE_HEX, VALS(zbee_zcl_reliability_names),
            0x0, NULL, HFILL } },

        /* start Status Flags fields */
        { &hf_zbee_zcl_analog_output_basic_status_flags,
            { "Status Flags", "zbee_zcl_general.analog_output_basic.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_analog_output_basic_status_in_alarm,
            { "In Alarm Status", "zbee_zcl_general.analog_output_basic.attr.status.in_alarm", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_IN_ALARM, NULL, HFILL } },

        { &hf_zbee_zcl_analog_output_basic_status_fault,
            { "Fault Status", "zbee_zcl_general.analog_output_basic.attr.status.fault", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_analog_output_basic_status_overridden,
            { "Overridden Status", "zbee_zcl_general.analog_output_basic.attr.status.overridden", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OVERRIDDEN, NULL, HFILL } },

        { &hf_zbee_zcl_analog_output_basic_status_out_of_service,
            { "Out of Service Status", "zbee_zcl_general.analog_output_basic.attr.status.out_of_service", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OUT_OF_SERVICE, NULL, HFILL } },
        /* end Status Flags fields */

        { &hf_zbee_zcl_analog_output_basic_priority_array_bool,
            { "Valid/Invalid", "zbee_zcl_general.analog_output_basic.attr.priority_array.bool", FT_BOOLEAN, BASE_NONE, TFS(&tfs_invalid_valid),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_analog_output_basic_priority_array_sing_prec,
            { "Priority Value", "zbee_zcl_general.analog_output_basic.attr.priority_array.sing_prec", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_analog_output_basic_priority_array,
            { "Priority Array", "zbee_zcl_general.analog_output_basic.priority_array", FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_analog_output_basic_structure,
            { "Structure", "zbee_zcl_general.analog_output_basic.structure", FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL } }
    };

    /* ZCL Analog Output Basic subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_analog_output_basic,
        &ett_zbee_zcl_analog_output_basic_status_flags,
        &ett_zbee_zcl_analog_output_basic_priority_array,
        &ett_zbee_zcl_analog_output_basic_priority_array_structure
    };



    /* Register the ZigBee ZCL Analog Output Basic cluster protocol name and description */
    proto_zbee_zcl_analog_output_basic = proto_register_protocol("ZigBee ZCL Analog Output Basic", "ZCL Analog Output Basic", ZBEE_PROTOABBREV_ZCL_ANALOG_OUTPUT_BASIC);
    proto_register_field_array(proto_zbee_zcl_analog_output_basic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Analog Output Basic dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_ANALOG_OUTPUT_BASIC, dissect_zbee_zcl_analog_output_basic, proto_zbee_zcl_analog_output_basic);
} /*proto_register_zbee_zcl_analog_output_basic*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_analog_output_basic
 *  DESCRIPTION
 *      Hands off the ZCL Analog Output Basic dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_analog_output_basic(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_ANALOG_OUTPUT_BASIC,
                            proto_zbee_zcl_analog_output_basic,
                            ett_zbee_zcl_analog_output_basic,
                            ZBEE_ZCL_CID_ANALOG_OUTPUT_BASIC,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_analog_output_basic_attr_id,
                            hf_zbee_zcl_analog_output_basic_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_analog_output_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_analog_output_basic*/


/* ########################################################################## */
/* #### (0x000E) ANALOG VALUE (BASIC) CLUSTER ############################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_DESCRIPTION                     0x001C  /* Description */
#define ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_OUT_OF_SERVICE                  0x0051  /* Out of Service */
#define ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_PRESENT_VALUE                   0x0055  /* Present Value */
#define ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_PRIORITY_ARRAY                  0x0057  /* Priority Array */
#define ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_RELIABILITY                     0x0067  /* Reliability */
#define ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_RELINQUISH_DEFAULT              0x0068  /* Relinquish Default */
#define ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_STATUS_FLAGS                    0x006F  /* Status Flags */
#define ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_ENGINEERING_UNITS               0x0075  /* Engineering Units */
#define ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_APPLICATION_TYPE                0x0100  /* Application Type */

/*Server commands received - none*/

/*Server commands generated - none*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_analog_value_basic(void);
void proto_reg_handoff_zbee_zcl_analog_value_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_analog_value_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_analog_value_basic;

static int hf_zbee_zcl_analog_value_basic_attr_id;
static int hf_zbee_zcl_analog_value_basic_reliability;
static int hf_zbee_zcl_analog_value_basic_status_flags;
static int hf_zbee_zcl_analog_value_basic_status_in_alarm;
static int hf_zbee_zcl_analog_value_basic_status_fault;
static int hf_zbee_zcl_analog_value_basic_status_overridden;
static int hf_zbee_zcl_analog_value_basic_status_out_of_service;
static int hf_zbee_zcl_analog_value_basic_priority_array_bool;
static int hf_zbee_zcl_analog_value_basic_priority_array_sing_prec;
static int hf_zbee_zcl_analog_value_basic_priority_array;
static int hf_zbee_zcl_analog_value_basic_structure;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_analog_value_basic;
static int ett_zbee_zcl_analog_value_basic_status_flags;
static int ett_zbee_zcl_analog_value_basic_priority_array;
static int ett_zbee_zcl_analog_value_basic_priority_array_structure;

/* Attributes */
static const value_string zbee_zcl_analog_value_basic_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_DESCRIPTION,          "Description" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_OUT_OF_SERVICE,       "Out of Service" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_PRESENT_VALUE,        "Present Value" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_PRIORITY_ARRAY,       "Priority Array" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_RELIABILITY,          "Reliability" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_RELINQUISH_DEFAULT,   "Relinquish Default" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_STATUS_FLAGS,         "Status Flags" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_ENGINEERING_UNITS,    "Engineering Units" },
    { ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_APPLICATION_TYPE,     "Application Type" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_analog_value_basic
 *  DESCRIPTION
 *      ZigBee ZCL Analog Value Basic cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_analog_value_basic(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
	return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_analog_value_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_analog_value_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_analog_value_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    proto_item  *ti = NULL, *tj = NULL;
    proto_tree  *sub_tree = NULL, *sub = NULL;
    int i;

    static int * const status_flags[] = {
        &hf_zbee_zcl_analog_value_basic_status_in_alarm,
        &hf_zbee_zcl_analog_value_basic_status_fault,
        &hf_zbee_zcl_analog_value_basic_status_overridden,
        &hf_zbee_zcl_analog_value_basic_status_out_of_service,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_PRIORITY_ARRAY:
            ti = proto_tree_add_item(tree,hf_zbee_zcl_analog_value_basic_priority_array, tvb, *offset, 80, ENC_NA);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_analog_value_basic_priority_array);

            for( i = 1; i <= 16; i++)
            {
                tj = proto_tree_add_item(sub_tree, hf_zbee_zcl_analog_value_basic_structure, tvb, *offset, 5, ENC_NA);
                proto_item_append_text(tj," %d",i);
                sub = proto_item_add_subtree(tj, ett_zbee_zcl_analog_value_basic_priority_array_structure);
                proto_tree_add_item(sub, hf_zbee_zcl_analog_value_basic_priority_array_bool, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
                *offset += 1;
                proto_tree_add_item(sub, hf_zbee_zcl_analog_value_basic_priority_array_sing_prec, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            break;

        case ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_RELIABILITY:
            proto_tree_add_item(tree, hf_zbee_zcl_analog_value_basic_reliability, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_STATUS_FLAGS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_analog_value_basic_status_flags, ett_zbee_zcl_analog_value_basic_status_flags, status_flags, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_DESCRIPTION:
        case ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_OUT_OF_SERVICE:
        case ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_RELINQUISH_DEFAULT:
        case ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_ENGINEERING_UNITS:
        case ZBEE_ZCL_ATTR_ID_ANALOG_VALUE_BASIC_APPLICATION_TYPE:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_analog_value_basic_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_analog_value_basic
 *  DESCRIPTION
 *      ZigBee ZCL Analog Value Basic cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_analog_value_basic(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_analog_value_basic_attr_id,
            { "Attribute", "zbee_zcl_general.analog_value_basic.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_analog_value_basic_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_analog_value_basic_reliability,
            { "Reliability", "zbee_zcl_general.analog_value_basic.attr.reliability", FT_UINT8, BASE_HEX, VALS(zbee_zcl_reliability_names),
            0x00, NULL, HFILL } },

        /* start Status Flags fields */
        { &hf_zbee_zcl_analog_value_basic_status_flags,
            { "Status Flags", "zbee_zcl_general.analog_value_basic.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_analog_value_basic_status_in_alarm,
            { "In Alarm Status", "zbee_zcl_general.analog_value_basic.attr.status.in_alarm", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_IN_ALARM, NULL, HFILL } },

        { &hf_zbee_zcl_analog_value_basic_status_fault,
            { "Fault Status", "zbee_zcl_general.analog_value_basic.attr.status.fault", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_analog_value_basic_status_overridden,
            { "Overridden Status", "zbee_zcl_general.analog_value_basic.attr.status.overridden", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OVERRIDDEN, NULL, HFILL } },

        { &hf_zbee_zcl_analog_value_basic_status_out_of_service,
            { "Out of Service Status", "zbee_zcl_general.analog_value_basic.attr.status.out_of_service", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OUT_OF_SERVICE, NULL, HFILL } },
        /* end Status Flags fields */

        { &hf_zbee_zcl_analog_value_basic_priority_array_bool,
            { "Valid/Invalid", "zbee_zcl_general.analog_value_basic.attr.priority_array.bool", FT_BOOLEAN, BASE_NONE, TFS(&tfs_invalid_valid),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_analog_value_basic_priority_array_sing_prec,
            { "Priority Value", "zbee_zcl_general.analog_value_basic.attr.priority_array.sing_prec", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_analog_value_basic_priority_array,
            { "Priority Array", "zbee_zcl_general.analog_value_basic.priority_array", FT_NONE, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_analog_value_basic_structure,
            { "Structure", "zbee_zcl_general.analog_value_basic.structure", FT_NONE, BASE_NONE, NULL,
            0x00, NULL, HFILL } }
    };

    /* ZCL Analog Value Basic subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_analog_value_basic,
        &ett_zbee_zcl_analog_value_basic_status_flags,
        &ett_zbee_zcl_analog_value_basic_priority_array,
        &ett_zbee_zcl_analog_value_basic_priority_array_structure
    };

    /* Register the ZigBee ZCL Analog Value Basic cluster protocol name and description */
    proto_zbee_zcl_analog_value_basic = proto_register_protocol("ZigBee ZCL Analog Value Basic", "ZCL Analog Value Basic", ZBEE_PROTOABBREV_ZCL_ANALOG_VALUE_BASIC);
    proto_register_field_array(proto_zbee_zcl_analog_value_basic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Analog Value Basic dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_ANALOG_VALUE_BASIC, dissect_zbee_zcl_analog_value_basic, proto_zbee_zcl_analog_value_basic);
} /*proto_register_zbee_zcl_analog_value_basic*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_analog_value_basic
 *  DESCRIPTION
 *      Hands off the ZCL Analog Value Basic dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_analog_value_basic(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_ANALOG_VALUE_BASIC,
                            proto_zbee_zcl_analog_value_basic,
                            ett_zbee_zcl_analog_value_basic,
                            ZBEE_ZCL_CID_ANALOG_VALUE_BASIC,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_analog_value_basic_attr_id,
                            hf_zbee_zcl_analog_value_basic_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_analog_value_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_analog_value_basic*/


/* ########################################################################## */
/* #### (0x000F) BINARY INPUT (BASIC) CLUSTER ############################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_ACTIVE_TEXT                     0x0004  /* Active Text */
#define ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_DESCRIPTION                     0x001C  /* Description */
#define ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_INACTIVE_TEXT                   0x002E  /* Inactive Text */
#define ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_OUT_OF_SERVICE                  0x0051  /* Out of Service */
#define ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_POLARITY                        0x0054  /* Polarity */
#define ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_PRESENT_VALUE                   0x0055  /* Present Value */
#define ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_RELIABILITY                     0x0067  /* Reliability */
#define ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_STATUS_FLAGS                    0x006F  /* Status Flags */
#define ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_APPLICATION_TYPE                0x0100  /* Application Type */

/*Server commands received - none*/

/*Server commands generated - none*/

static const value_string zbee_zcl_binary_input_polarity_values[] = {
    {0, "Normal"},
    {1, "Reversed"},
    {0, NULL}
};

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_binary_input_basic(void);
void proto_reg_handoff_zbee_zcl_binary_input_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_binary_input_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_binary_input_basic;

static int hf_zbee_zcl_binary_input_basic_attr_id;
static int hf_zbee_zcl_binary_input_basic_status_flags;
static int hf_zbee_zcl_binary_input_basic_status_in_alarm;
static int hf_zbee_zcl_binary_input_basic_status_fault;
static int hf_zbee_zcl_binary_input_basic_status_overridden;
static int hf_zbee_zcl_binary_input_basic_status_out_of_service;
static int hf_zbee_zcl_binary_input_basic_polarity;
static int hf_zbee_zcl_binary_input_basic_reliability;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_binary_input_basic;
static int ett_zbee_zcl_binary_input_basic_status_flags;

/* Attributes */
static const value_string zbee_zcl_binary_input_basic_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_ACTIVE_TEXT,          "Active Text" },
    { ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_DESCRIPTION,          "Description" },
    { ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_INACTIVE_TEXT,        "Inactive Text" },
    { ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_OUT_OF_SERVICE,       "Out of Service" },
    { ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_POLARITY,             "Polarity" },
    { ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_PRESENT_VALUE,        "Present Value" },
    { ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_RELIABILITY,          "Reliability" },
    { ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_STATUS_FLAGS,         "Status Flags" },
    { ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_APPLICATION_TYPE,     "Application Type" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_binary_input_basic
 *  DESCRIPTION
 *      ZigBee ZCL Binary Input Basic cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_binary_input_basic(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_binary_input_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_binary_input_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_binary_input_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    static int * const status_flags[] = {
        &hf_zbee_zcl_binary_input_basic_status_in_alarm,
        &hf_zbee_zcl_binary_input_basic_status_fault,
        &hf_zbee_zcl_binary_input_basic_status_overridden,
        &hf_zbee_zcl_binary_input_basic_status_out_of_service,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_POLARITY:
            proto_tree_add_item(tree, hf_zbee_zcl_binary_input_basic_polarity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_RELIABILITY:
            proto_tree_add_item(tree, hf_zbee_zcl_binary_input_basic_reliability, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_STATUS_FLAGS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_binary_input_basic_status_flags, ett_zbee_zcl_binary_input_basic_status_flags, status_flags, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_ACTIVE_TEXT:
        case ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_INACTIVE_TEXT:
        case ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_DESCRIPTION:
        case ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_OUT_OF_SERVICE:
        case ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_BINARY_INPUT_BASIC_APPLICATION_TYPE:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_binary_input_basic_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_binary_input_basic
 *  DESCRIPTION
 *      ZigBee ZCL Binary Input Basic cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_binary_input_basic(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_binary_input_basic_attr_id,
            { "Attribute", "zbee_zcl_general.binary_input_basic.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_binary_input_basic_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_input_basic_reliability,
            { "Reliability", "zbee_zcl_general.binary_input_basic.attr.reliability", FT_UINT8, BASE_HEX, VALS(zbee_zcl_reliability_names),
            0x00, NULL, HFILL } },

        /* start Status Flags fields */
        { &hf_zbee_zcl_binary_input_basic_status_flags,
            { "Status Flags", "zbee_zcl_general.binary_input_basic.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_input_basic_status_in_alarm,
            { "In Alarm Status", "zbee_zcl_general.binary_input_basic.attr.status.in_alarm", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_IN_ALARM, NULL, HFILL } },

        { &hf_zbee_zcl_binary_input_basic_status_fault,
            { "Fault Status", "zbee_zcl_general.binary_input_basic.attr.status.fault", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_binary_input_basic_status_overridden,
            { "Overridden Status", "zbee_zcl_general.binary_input_basic.attr.status.overridden", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OVERRIDDEN, NULL, HFILL } },

        { &hf_zbee_zcl_binary_input_basic_status_out_of_service,
            { "Out of Service Status", "zbee_zcl_general.binary_input_basic.attr.status.out_of_service", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OUT_OF_SERVICE, NULL, HFILL } },
        /* end Status Flags fields */

        { &hf_zbee_zcl_binary_input_basic_polarity,
            { "Polarity", "zbee_zcl_general.binary_input_basic.attr.polarity", FT_UINT8, BASE_HEX, VALS(zbee_zcl_binary_input_polarity_values),
            0x00, NULL, HFILL } }

    };

    /* ZCL Binary Input Basic subtrees */
    static int *ett[] = {
             &ett_zbee_zcl_binary_input_basic,
             &ett_zbee_zcl_binary_input_basic_status_flags
    };

    /* Register the ZigBee ZCL Binary Input Basic cluster protocol name and description */
    proto_zbee_zcl_binary_input_basic = proto_register_protocol("ZigBee ZCL Binary Input Basic", "ZCL Binary Input Basic", ZBEE_PROTOABBREV_ZCL_BINARY_INPUT_BASIC);
    proto_register_field_array(proto_zbee_zcl_binary_input_basic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Binary Input Basic dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_BINARY_INPUT_BASIC, dissect_zbee_zcl_binary_input_basic, proto_zbee_zcl_binary_input_basic);
} /*proto_register_zbee_zcl_binary_input_basic*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_binary_input_basic
 *  DESCRIPTION
 *      Hands off the ZCL Binary Input Basic dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_binary_input_basic(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_BINARY_INPUT_BASIC,
                            proto_zbee_zcl_binary_input_basic,
                            ett_zbee_zcl_binary_input_basic,
                            ZBEE_ZCL_CID_BINARY_INPUT_BASIC,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_binary_input_basic_attr_id,
                            hf_zbee_zcl_binary_input_basic_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_binary_input_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_binary_input_basic*/

/* ########################################################################## */
/* #### (0x0010) BINARY OUTPUT (BASIC) CLUSTER ############################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_ACTIVE_TEXT                     0x0004  /* Active Text */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_DESCRIPTION                     0x001C  /* Description */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_INACTIVE_TEXT                   0x002E  /* Inactive Text */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_MIN_OFF_TIME                    0x0042  /* Maximum Off Time */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_MIN_ON_TIME                     0x0043  /* Minimum On Time */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_OUT_OF_SERVICE                  0x0051  /* Out of Service */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_POLARITY                        0x0054  /* Polarity */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_PRESENT_VALUE                   0x0055  /* Present Value */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_PRIORITY_ARRAY                  0x0057  /* Priority Array */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_RELIABILITY                     0x0067  /* Reliability */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_RELINQUISH_DEFAULT              0x0068  /* Relinquish Default */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_STATUS_FLAGS                    0x006F  /* Status Flags */
#define ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_APPLICATION_TYPE                0x0100  /* Application Type */

/*Server commands received - none*/

/*Server commands generated - none*/

static const value_string zbee_zcl_binary_output_polarity_values[] = {
    {0, "Normal"},
    {1, "Reversed"},
    {0, NULL}
};

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_binary_output_basic(void);
void proto_reg_handoff_zbee_zcl_binary_output_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_binary_output_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_binary_output_basic;

static int hf_zbee_zcl_binary_output_basic_attr_id;
static int hf_zbee_zcl_binary_output_basic_status_flags;
static int hf_zbee_zcl_binary_output_basic_status_in_alarm;
static int hf_zbee_zcl_binary_output_basic_status_fault;
static int hf_zbee_zcl_binary_output_basic_status_overridden;
static int hf_zbee_zcl_binary_output_basic_status_out_of_service;
static int hf_zbee_zcl_binary_output_basic_priority_array_bool;
static int hf_zbee_zcl_binary_output_basic_priority_array_sing_prec;
static int hf_zbee_zcl_binary_output_basic_polarity;
static int hf_zbee_zcl_binary_output_basic_reliability;
static int hf_zbee_zcl_binary_output_basic_priority_array;
static int hf_zbee_zcl_binary_output_basic_structure;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_binary_output_basic;
static int ett_zbee_zcl_binary_output_basic_status_flags;
static int ett_zbee_zcl_binary_output_basic_priority_array;
static int ett_zbee_zcl_binary_output_basic_priority_array_structure;

/* Attributes */
static const value_string zbee_zcl_binary_output_basic_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_ACTIVE_TEXT,          "Active Text" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_DESCRIPTION,          "Description" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_INACTIVE_TEXT,        "Inactive Text" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_MIN_OFF_TIME,         "Minimum Off Time" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_MIN_ON_TIME,          "Minimum On Time" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_OUT_OF_SERVICE,       "Out of Service" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_POLARITY,             "Polarity" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_PRESENT_VALUE,        "Present Value" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_PRIORITY_ARRAY,       "Priority Array" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_RELIABILITY,          "Reliability" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_RELINQUISH_DEFAULT,   "Relinquish Default" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_STATUS_FLAGS,         "Status Flags" },
    { ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_APPLICATION_TYPE,     "Application Type" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_binary_output_basic
 *  DESCRIPTION
 *      ZigBee ZCL Binary Output Basic cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_binary_output_basic(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_binary_output_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_binary_output_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_binary_output_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    proto_item  *ti = NULL, *tj = NULL;
    proto_tree  *sub_tree = NULL, *sub = NULL;
    int i;

    static int * const status_flags[] = {
        &hf_zbee_zcl_binary_output_basic_status_in_alarm,
        &hf_zbee_zcl_binary_output_basic_status_fault,
        &hf_zbee_zcl_binary_output_basic_status_overridden,
        &hf_zbee_zcl_binary_output_basic_status_out_of_service,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_PRIORITY_ARRAY:
            ti = proto_tree_add_item(tree,hf_zbee_zcl_binary_output_basic_priority_array, tvb, *offset, 80, ENC_NA);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_binary_output_basic_priority_array);

            for(i = 1; i <= 16; i++)
            {
                tj = proto_tree_add_item(sub_tree, hf_zbee_zcl_binary_output_basic_structure, tvb, *offset, 5, ENC_NA);
                proto_item_append_text(tj," %d",i);
                sub = proto_item_add_subtree(tj, ett_zbee_zcl_binary_output_basic_priority_array_structure);
                proto_tree_add_item(sub, hf_zbee_zcl_binary_output_basic_priority_array_bool, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
                *offset += 1;
                proto_tree_add_item(sub, hf_zbee_zcl_binary_output_basic_priority_array_sing_prec, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            break;

        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_POLARITY:
            proto_tree_add_item(tree, hf_zbee_zcl_binary_output_basic_polarity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_RELIABILITY:
            proto_tree_add_item(tree, hf_zbee_zcl_binary_output_basic_reliability, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_STATUS_FLAGS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_binary_output_basic_status_flags, ett_zbee_zcl_binary_output_basic_status_flags, status_flags, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_ACTIVE_TEXT:
        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_DESCRIPTION:
        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_INACTIVE_TEXT:
        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_MIN_OFF_TIME:
        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_MIN_ON_TIME:
        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_OUT_OF_SERVICE:
        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_RELINQUISH_DEFAULT:
        case ZBEE_ZCL_ATTR_ID_BINARY_OUTPUT_BASIC_APPLICATION_TYPE:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_binary_output_basic_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_binary_output_basic
 *  DESCRIPTION
 *      ZigBee ZCL Binary Output Basic cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_binary_output_basic(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_binary_output_basic_attr_id,
            { "Attribute", "zbee_zcl_general.binary_output_basic.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_binary_output_basic_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_output_basic_reliability,
            { "Reliability", "zbee_zcl_general.binary_output_basic.attr.reliability", FT_UINT8, BASE_HEX, VALS(zbee_zcl_reliability_names),
            0x00, NULL, HFILL } },

        /* start Status Flags fields */
        { &hf_zbee_zcl_binary_output_basic_status_flags,
            { "Status Flags", "zbee_zcl_general.binary_output_basic.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_output_basic_status_in_alarm,
            { "In Alarm Status", "zbee_zcl_general.binary_output_basic.attr.status.in_alarm", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_IN_ALARM, NULL, HFILL } },

        { &hf_zbee_zcl_binary_output_basic_status_fault,
            { "Fault Status", "zbee_zcl_general.binary_output_basic.attr.status.fault", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_binary_output_basic_status_overridden,
            { "Overridden Status", "zbee_zcl_general.binary_output_basic.attr.status.overridden", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OVERRIDDEN, NULL, HFILL } },

        { &hf_zbee_zcl_binary_output_basic_status_out_of_service,
            { "Out of Service Status", "zbee_zcl_general.binary_output_basic.attr.status.out_of_service", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OUT_OF_SERVICE, NULL, HFILL } },
        /* end Status Flags fields */

        { &hf_zbee_zcl_binary_output_basic_polarity,
            { "Polarity", "zbee_zcl_general.binary_output_basic.attr.polarity", FT_UINT8, BASE_HEX, VALS(zbee_zcl_binary_output_polarity_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_output_basic_priority_array_bool,
            { "Valid/Invalid", "zbee_zcl_general.binary_output_basic.attr.priority_array.bool", FT_BOOLEAN, BASE_NONE, TFS(&tfs_invalid_valid),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_output_basic_priority_array_sing_prec,
            { "Priority Value", "zbee_zcl_general.binary_output_basic.attr.priority_array.sing_prec", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_output_basic_priority_array,
            { "Priority Array", "zbee_zcl_general.binary_output_basic.priority_array", FT_NONE, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_output_basic_structure,
            { "Structure", "zbee_zcl_general.binary_output_basic.structure", FT_NONE, BASE_NONE, NULL,
            0x00, NULL, HFILL } }
    };

    /* ZCL Binary Output Basic subtrees */
    static int *ett[] = {
            &ett_zbee_zcl_binary_output_basic,
            &ett_zbee_zcl_binary_output_basic_status_flags,
            &ett_zbee_zcl_binary_output_basic_priority_array,
            &ett_zbee_zcl_binary_output_basic_priority_array_structure
    };

    /* Register the ZigBee ZCL Binary Output Basic cluster protocol name and description */
    proto_zbee_zcl_binary_output_basic = proto_register_protocol("ZigBee ZCL Binary Output Basic", "ZCL Binary Output Basic", ZBEE_PROTOABBREV_ZCL_BINARY_OUTPUT_BASIC);
    proto_register_field_array(proto_zbee_zcl_binary_output_basic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Binary Output Basic dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_BINARY_OUTPUT_BASIC, dissect_zbee_zcl_binary_output_basic, proto_zbee_zcl_binary_output_basic);
} /*proto_register_zbee_zcl_binary_output_basic*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_binary_output_basic
 *  DESCRIPTION
 *      Hands off the ZCL Binary Output Basic dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_binary_output_basic(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_BINARY_OUTPUT_BASIC,
                            proto_zbee_zcl_binary_output_basic,
                            ett_zbee_zcl_binary_output_basic,
                            ZBEE_ZCL_CID_BINARY_OUTPUT_BASIC,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_binary_output_basic_attr_id,
                            hf_zbee_zcl_binary_output_basic_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_binary_output_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_binary_output_basic*/

/* ########################################################################## */
/* #### (0x0011) BINARY VALUE (BASIC) CLUSTER ############################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_ACTIVE_TEXT                     0x0004  /* Active Text */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_DESCRIPTION                     0x001C  /* Description */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_INACTIVE_TEXT                   0x002E  /* Inactive Text */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_MIN_OFF_TIME                    0x0042  /* Maximum Off Time */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_MIN_ON_TIME                     0x0043  /* Minimum On Time */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_OUT_OF_SERVICE                  0x0051  /* Out of Service */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_PRESENT_VALUE                   0x0055  /* Present Value */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_PRIORITY_ARRAY                  0x0057  /* Priority Array */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_RELIABILITY                     0x0067  /* Reliability */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_RELINQUISH_DEFAULT              0x0068  /* Relinquish Default */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_STATUS_FLAGS                    0x006F  /* Status Flags */
#define ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_APPLICATION_TYPE                0x0100  /* Application Type */

/*Server commands received - none*/

/*Server commands generated - none*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_binary_value_basic(void);
void proto_reg_handoff_zbee_zcl_binary_value_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_binary_value_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_binary_value_basic;

static int hf_zbee_zcl_binary_value_basic_attr_id;
static int hf_zbee_zcl_binary_value_basic_status_flags;
static int hf_zbee_zcl_binary_value_basic_status_in_alarm;
static int hf_zbee_zcl_binary_value_basic_status_fault;
static int hf_zbee_zcl_binary_value_basic_status_overridden;
static int hf_zbee_zcl_binary_value_basic_status_out_of_service;
static int hf_zbee_zcl_binary_value_basic_priority_array_bool;
static int hf_zbee_zcl_binary_value_basic_priority_array_sing_prec;
static int hf_zbee_zcl_binary_value_basic_reliability;
static int hf_zbee_zcl_binary_value_basic_priority_array;
static int hf_zbee_zcl_binary_value_basic_structure;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_binary_value_basic;
static int ett_zbee_zcl_binary_value_basic_status_flags;
static int ett_zbee_zcl_binary_value_basic_priority_array;
static int ett_zbee_zcl_binary_value_basic_priority_array_structure;

/* Attributes */
static const value_string zbee_zcl_binary_value_basic_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_ACTIVE_TEXT,          "Active Text" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_DESCRIPTION,          "Description" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_INACTIVE_TEXT,        "Inactive Text" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_MIN_OFF_TIME,         "Minimum Off Time" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_MIN_ON_TIME,          "Minimum On Time" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_OUT_OF_SERVICE,       "Out of Service" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_PRESENT_VALUE,        "Present Value" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_PRIORITY_ARRAY,       "Priority Array" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_RELIABILITY,          "Reliability" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_RELINQUISH_DEFAULT,   "Relinquish Default" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_STATUS_FLAGS,         "Status Flags" },
    { ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_APPLICATION_TYPE,     "Application Type" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_binary_value_basic
 *  DESCRIPTION
 *      ZigBee ZCL Binary Value Basic cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_binary_value_basic(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_binary_value_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_binary_value_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_binary_value_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    proto_item  *ti = NULL, *tj = NULL;
    proto_tree  *sub_tree = NULL, *sub = NULL;
    int i;

    static int * const status_flags[] = {
        &hf_zbee_zcl_binary_value_basic_status_in_alarm,
        &hf_zbee_zcl_binary_value_basic_status_fault,
        &hf_zbee_zcl_binary_value_basic_status_overridden,
        &hf_zbee_zcl_binary_value_basic_status_out_of_service,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_PRIORITY_ARRAY:
            ti = proto_tree_add_item(tree,hf_zbee_zcl_binary_value_basic_priority_array, tvb, *offset, 80, ENC_NA);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_binary_value_basic_priority_array);

            for( i = 1; i <= 16; i++)
            {
                tj = proto_tree_add_item(sub_tree, hf_zbee_zcl_binary_value_basic_structure, tvb, *offset, 5, ENC_NA);
                proto_item_append_text(tj," %d",i);
                sub = proto_item_add_subtree(tj, ett_zbee_zcl_binary_value_basic_priority_array_structure);
                proto_tree_add_item(sub, hf_zbee_zcl_binary_value_basic_priority_array_bool, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
                *offset += 1;
                proto_tree_add_item(sub, hf_zbee_zcl_binary_value_basic_priority_array_sing_prec, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            break;

        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_RELIABILITY:
            proto_tree_add_item(tree, hf_zbee_zcl_binary_value_basic_reliability, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_STATUS_FLAGS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_binary_value_basic_status_flags, ett_zbee_zcl_binary_value_basic_status_flags, status_flags, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_ACTIVE_TEXT:
        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_DESCRIPTION:
        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_INACTIVE_TEXT:
        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_MIN_OFF_TIME:
        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_MIN_ON_TIME:
        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_OUT_OF_SERVICE:
        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_RELINQUISH_DEFAULT:
        case ZBEE_ZCL_ATTR_ID_BINARY_VALUE_BASIC_APPLICATION_TYPE:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_binary_value_basic_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_binary_value_basic
 *  DESCRIPTION
 *      ZigBee ZCL Binary Value Basic cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_binary_value_basic(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_binary_value_basic_attr_id,
            { "Attribute", "zbee_zcl_general.binary_value_basic.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_binary_value_basic_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_value_basic_reliability,
            { "Reliability", "zbee_zcl_general.binary_value_basic.attr.reliability", FT_UINT8, BASE_HEX, VALS(zbee_zcl_reliability_names),
            0x00, NULL, HFILL } },

        /* start Status Flags fields */
        { &hf_zbee_zcl_binary_value_basic_status_flags,
            { "Status Flags", "zbee_zcl_general.binary_value_basic.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_value_basic_status_in_alarm,
            { "In Alarm Status", "zbee_zcl_general.binary_value_basic.attr.status.in_alarm", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_IN_ALARM, NULL, HFILL } },

        { &hf_zbee_zcl_binary_value_basic_status_fault,
            { "Fault Status", "zbee_zcl_general.binary_value_basic.attr.status.fault", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_binary_value_basic_status_overridden,
            { "Overridden Status", "zbee_zcl_general.binary_value_basic.attr.status.overridden", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OVERRIDDEN, NULL, HFILL } },

        { &hf_zbee_zcl_binary_value_basic_status_out_of_service,
            { "Out of Service Status", "zbee_zcl_general.binary_value_basic.attr.status.out_of_service", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OUT_OF_SERVICE, NULL, HFILL } },
        /* end Status Flags fields */

        { &hf_zbee_zcl_binary_value_basic_priority_array_bool,
            { "Valid/Invalid", "zbee_zcl_general.binary_value_basic.attr.priority_array.bool", FT_BOOLEAN, BASE_NONE, TFS(&tfs_invalid_valid),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_value_basic_priority_array_sing_prec,
            { "Priority Value", "zbee_zcl_general.binary_value_basic.attr.priority_array.sing_prec", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_value_basic_priority_array,
            { "Priority Array", "zbee_zcl_general.binary_value_basic.priority_array", FT_NONE, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_binary_value_basic_structure,
            { "Structure", "zbee_zcl_general.binary_value_basic.structure", FT_NONE, BASE_NONE, NULL,
            0x00, NULL, HFILL } }
    };

    /* ZCL Binary Value Basic subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_binary_value_basic,
        &ett_zbee_zcl_binary_value_basic_status_flags,
        &ett_zbee_zcl_binary_value_basic_priority_array,
        &ett_zbee_zcl_binary_value_basic_priority_array_structure
    };

    /* Register the ZigBee ZCL Binary Value Basic cluster protocol name and description */
    proto_zbee_zcl_binary_value_basic = proto_register_protocol("ZigBee ZCL Binary Value Basic", "ZCL Binary Value Basic", ZBEE_PROTOABBREV_ZCL_BINARY_VALUE_BASIC);
    proto_register_field_array(proto_zbee_zcl_binary_value_basic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Binary Value Basic dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_BINARY_VALUE_BASIC, dissect_zbee_zcl_binary_value_basic, proto_zbee_zcl_binary_value_basic);
} /*proto_register_zbee_zcl_binary_value_basic*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_binary_value_basic
 *  DESCRIPTION
 *      Hands off the ZCL Binary Value Basic dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_binary_value_basic(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_BINARY_VALUE_BASIC,
                            proto_zbee_zcl_binary_value_basic,
                            ett_zbee_zcl_binary_value_basic,
                            ZBEE_ZCL_CID_BINARY_VALUE_BASIC,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_binary_value_basic_attr_id,
                            hf_zbee_zcl_binary_value_basic_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_binary_value_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_binary_value_basic*/


/* ########################################################################## */
/* #### (0x0012) MULTISTATE INPUT (BASIC) CLUSTER ########################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_STATE_TEXT                      0x000E  /* State Text */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_DESCRIPTION                     0x001C  /* Description */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_NUMBER_OF_STATES                0x004A  /* Number of States */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_OUT_OF_SERVICE                  0x0051  /* Out of Service */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_PRESENT_VALUE                   0x0055  /* Present Value */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_RELIABILITY                     0x0067  /* Reliability */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_STATUS_FLAGS                    0x006F  /* Status Flags */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_APPLICATION_TYPE                0x0100  /* Application Type */

/*Server commands received - none*/

/*Server commands generated - none*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_multistate_input_basic(void);
void proto_reg_handoff_zbee_zcl_multistate_input_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_multistate_input_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_multistate_input_basic;

static int hf_zbee_zcl_multistate_input_basic_attr_id;
static int hf_zbee_zcl_multistate_input_basic_status_flags;
static int hf_zbee_zcl_multistate_input_basic_status_in_alarm;
static int hf_zbee_zcl_multistate_input_basic_status_fault;
static int hf_zbee_zcl_multistate_input_basic_status_overridden;
static int hf_zbee_zcl_multistate_input_basic_status_out_of_service;
static int hf_zbee_zcl_multistate_input_basic_reliability;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_multistate_input_basic;
static int ett_zbee_zcl_multistate_input_basic_status_flags;

/* Attributes */
static const value_string zbee_zcl_multistate_input_basic_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_STATE_TEXT,           "State Text" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_DESCRIPTION,          "Description" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_NUMBER_OF_STATES,     "Number of States" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_OUT_OF_SERVICE,       "Out of Service" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_PRESENT_VALUE,        "Present Value" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_RELIABILITY,          "Reliability" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_STATUS_FLAGS,         "Status Flags" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_APPLICATION_TYPE,     "Application Type" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_multistate_input_basic
 *  DESCRIPTION
 *      ZigBee ZCL Multistate Input Basic cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_multistate_input_basic(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_multistate_input_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_multistate_input_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_multistate_input_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    static int * const status_flags[] = {
        &hf_zbee_zcl_multistate_input_basic_status_in_alarm,
        &hf_zbee_zcl_multistate_input_basic_status_fault,
        &hf_zbee_zcl_multistate_input_basic_status_overridden,
        &hf_zbee_zcl_multistate_input_basic_status_out_of_service,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_RELIABILITY:
            proto_tree_add_item(tree, hf_zbee_zcl_multistate_input_basic_reliability, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_STATUS_FLAGS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_multistate_input_basic_status_flags, ett_zbee_zcl_multistate_input_basic_status_flags, status_flags, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_DESCRIPTION:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_NUMBER_OF_STATES:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_OUT_OF_SERVICE:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_INPUT_BASIC_APPLICATION_TYPE:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_multistate_input_basic_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_multistate_input_basic
 *  DESCRIPTION
 *      ZigBee ZCL Multistate Input Basic cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_multistate_input_basic(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_multistate_input_basic_attr_id,
            { "Attribute", "zbee_zcl_general.multistate_input_basic.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_multistate_input_basic_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_input_basic_reliability,
            { "Reliability", "zbee_zcl_general.multistate_input_basic.attr.reliability", FT_UINT8, BASE_HEX, VALS(zbee_zcl_reliability_names),
            0x00, NULL, HFILL } },

        /* start Status Flags fields */
        { &hf_zbee_zcl_multistate_input_basic_status_flags,
            { "Status Flags", "zbee_zcl_general.multistate_input_basic.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_input_basic_status_in_alarm,
            { "In Alarm Status", "zbee_zcl_general.multistate_input_basic.attr.status.in_alarm", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_IN_ALARM, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_input_basic_status_fault,
            { "Fault Status", "zbee_zcl_general.multistate_input_basic.attr.status.fault", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_input_basic_status_overridden,
            { "Overridden Status", "zbee_zcl_general.multistate_input_basic.attr.status.overridden", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OVERRIDDEN, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_input_basic_status_out_of_service,
            { "Out of Service Status", "zbee_zcl_general.multistate_input_basic.attr.status.out_of_service", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OUT_OF_SERVICE, NULL, HFILL } }
        /* end Status Flags fields */
    };

    /* ZCL Multistate Input Basic subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_multistate_input_basic,
        &ett_zbee_zcl_multistate_input_basic_status_flags
    };

    /* Register the ZigBee ZCL Multistate Input Basic cluster protocol name and description */
    proto_zbee_zcl_multistate_input_basic = proto_register_protocol("ZigBee ZCL Multistate Input Basic", "ZCL Multistate Input Basic", ZBEE_PROTOABBREV_ZCL_MULTISTATE_INPUT_BASIC);
    proto_register_field_array(proto_zbee_zcl_multistate_input_basic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Multistate Input Basic dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_MULTISTATE_INPUT_BASIC, dissect_zbee_zcl_multistate_input_basic, proto_zbee_zcl_multistate_input_basic);
} /*proto_register_zbee_zcl_multistate_input_basic*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_multistate_input_basic
 *  DESCRIPTION
 *      Hands off the ZCL Multistate Input Basic dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_multistate_input_basic(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_MULTISTATE_INPUT_BASIC,
                            proto_zbee_zcl_multistate_input_basic,
                            ett_zbee_zcl_multistate_input_basic,
                            ZBEE_ZCL_CID_MULTISTATE_INPUT_BASIC,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_multistate_input_basic_attr_id,
                            hf_zbee_zcl_multistate_input_basic_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_multistate_input_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_multistate_input_basic*/


/* ########################################################################## */
/* #### (0x0013) MULTISTATE OUTPUT (BASIC) CLUSTER ########################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_STATE_TEXT                      0x000E  /* State Text */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_DESCRIPTION                     0x001C  /* Description */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_NUMBER_OF_STATES                0x004A  /* Number of States */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_OUT_OF_SERVICE                  0x0051  /* Out of Service */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_PRESENT_VALUE                   0x0055  /* Present Value */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_PRIORITY_ARRAY                  0x0057  /* Priority Array */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_RELIABILITY                     0x0067  /* Reliability */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_RELINQUISH_DEFAULT              0x0068  /* Relinquish Default */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_STATUS_FLAGS                    0x006F  /* Status Flags */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_APPLICATION_TYPE                0x0100  /* Application Type */

/*Server commands received - none*/

/*Server commands generated - none*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_multistate_output_basic(void);
void proto_reg_handoff_zbee_zcl_multistate_output_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_multistate_output_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_multistate_output_basic;

static int hf_zbee_zcl_multistate_output_basic_attr_id;
static int hf_zbee_zcl_multistate_output_basic_status_flags;
static int hf_zbee_zcl_multistate_output_basic_status_in_alarm;
static int hf_zbee_zcl_multistate_output_basic_status_fault;
static int hf_zbee_zcl_multistate_output_basic_status_overridden;
static int hf_zbee_zcl_multistate_output_basic_status_out_of_service;
static int hf_zbee_zcl_multistate_output_basic_reliability;
static int hf_zbee_zcl_multistate_output_basic_priority_array_bool;
static int hf_zbee_zcl_multistate_output_basic_priority_array_sing_prec;
static int hf_zbee_zcl_multistate_output_basic_priority_array;
static int hf_zbee_zcl_multistate_output_basic_structure;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_multistate_output_basic;
static int ett_zbee_zcl_multistate_output_basic_status_flags;
static int ett_zbee_zcl_multistate_output_basic_priority_array;
static int ett_zbee_zcl_multistate_output_basic_priority_array_structure;

/* Attributes */
static const value_string zbee_zcl_multistate_output_basic_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_STATE_TEXT,           "State Text" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_DESCRIPTION,          "Description" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_NUMBER_OF_STATES,     "Number of States" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_OUT_OF_SERVICE,       "Out of Service" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_PRESENT_VALUE,        "Present Value" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_PRIORITY_ARRAY,       "Priority Array" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_RELIABILITY,          "Reliability" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_RELINQUISH_DEFAULT,   "Relinquish Default" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_STATUS_FLAGS,         "Status Flags" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_APPLICATION_TYPE,     "Application Type" },
    { 0, NULL }
};

static const value_string zbee_zcl_multistate_output_basic_priority_array_bool_values[] = {
    { 0x01, "Valid" },
    { 0x00, "Invalid" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_multistate_output_basic
 *  DESCRIPTION
 *      ZigBee ZCL Multistate Output Basic cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_multistate_output_basic(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_multistate_output_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_multistate_output_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_multistate_output_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    proto_item  *ti = NULL, *tj = NULL;
    proto_tree  *sub_tree = NULL, *sub = NULL;
    int i;

    static int * const status_flags[] = {
        &hf_zbee_zcl_multistate_output_basic_status_in_alarm,
        &hf_zbee_zcl_multistate_output_basic_status_fault,
        &hf_zbee_zcl_multistate_output_basic_status_overridden,
        &hf_zbee_zcl_multistate_output_basic_status_out_of_service,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_PRIORITY_ARRAY:
            ti = proto_tree_add_item(tree,hf_zbee_zcl_multistate_output_basic_priority_array, tvb, *offset, 80, ENC_NA);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_multistate_output_basic_priority_array);

            for( i = 1; i <= 16; i++)
            {
                tj = proto_tree_add_item(sub_tree, hf_zbee_zcl_multistate_output_basic_structure, tvb, *offset, 5, ENC_NA);
                proto_item_append_text(tj," %d",i);
                sub = proto_item_add_subtree(tj, ett_zbee_zcl_multistate_output_basic_priority_array_structure);
                proto_tree_add_item(sub, hf_zbee_zcl_multistate_output_basic_priority_array_bool, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
                *offset += 1;
                proto_tree_add_item(sub, hf_zbee_zcl_multistate_output_basic_priority_array_sing_prec, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            break;

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_RELIABILITY:
            proto_tree_add_item(tree, hf_zbee_zcl_multistate_output_basic_reliability, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_STATUS_FLAGS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_multistate_output_basic_status_flags, ett_zbee_zcl_multistate_output_basic_status_flags, status_flags, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_DESCRIPTION:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_NUMBER_OF_STATES:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_OUT_OF_SERVICE:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_RELINQUISH_DEFAULT:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_OUTPUT_BASIC_APPLICATION_TYPE:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_multistate_output_basic_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_multistate_output_basic
 *  DESCRIPTION
 *      ZigBee ZCL Multistate Output Basic cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_multistate_output_basic(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_multistate_output_basic_attr_id,
            { "Attribute", "zbee_zcl_general.multistate_output_basic.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_multistate_output_basic_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_output_basic_reliability,
            { "Reliability", "zbee_zcl_general.multistate_output_basic.attr.reliability", FT_UINT8, BASE_HEX, VALS(zbee_zcl_reliability_names),
            0x00, NULL, HFILL } },

        /* start Status Flags fields */
        { &hf_zbee_zcl_multistate_output_basic_status_flags,
            { "Status Flags", "zbee_zcl_general.multistate_output_basic.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_output_basic_status_in_alarm,
            { "In Alarm Status", "zbee_zcl_general.multistate_output_basic.attr.status.in_alarm", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_IN_ALARM, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_output_basic_status_fault,
            { "Fault Status", "zbee_zcl_general.multistate_output_basic.attr.status.fault", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_output_basic_status_overridden,
            { "Overridden Status", "zbee_zcl_general.multistate_output_basic.attr.status.overridden", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OVERRIDDEN, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_output_basic_status_out_of_service,
            { "Out of Service Status", "zbee_zcl_general.multistate_output_basic.attr.status.out_of_service", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OUT_OF_SERVICE, NULL, HFILL } },
        /* end Status Flags fields */

        { &hf_zbee_zcl_multistate_output_basic_priority_array_bool,
            { "Valid/Invalid", "zbee_zcl_general.multistate_output_basic.attr.priority_array.bool", FT_UINT8, BASE_HEX, VALS(zbee_zcl_multistate_output_basic_priority_array_bool_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_output_basic_priority_array_sing_prec,
            { "Priority Value", "zbee_zcl_general.multistate_output_basic.attr.priority_array.sing_prec", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } } ,

        { &hf_zbee_zcl_multistate_output_basic_priority_array,
            { "Priority Array", "zbee_zcl_general.multistate_output_basic.priority_array", FT_NONE, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_output_basic_structure,
            { "Structure", "zbee_zcl_general.multistate_output_basic.structure", FT_NONE, BASE_NONE, NULL,
            0x00, NULL, HFILL } }
};

    /* ZCL Multistate Output Basic subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_multistate_output_basic,
        &ett_zbee_zcl_multistate_output_basic_status_flags,
        &ett_zbee_zcl_multistate_output_basic_priority_array,
        &ett_zbee_zcl_multistate_output_basic_priority_array_structure
    };

    /* Register the ZigBee ZCL Multistate Output Basic cluster protocol name and description */
    proto_zbee_zcl_multistate_output_basic = proto_register_protocol("ZigBee ZCL Multistate Output Basic", "ZCL Multistate Output Basic", ZBEE_PROTOABBREV_ZCL_MULTISTATE_OUTPUT_BASIC);
    proto_register_field_array(proto_zbee_zcl_multistate_output_basic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Multistate Output Basic dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_MULTISTATE_OUTPUT_BASIC, dissect_zbee_zcl_multistate_output_basic, proto_zbee_zcl_multistate_output_basic);
} /*proto_register_zbee_zcl_multistate_output_basic*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_multistate_output_basic
 *  DESCRIPTION
 *      Hands off the ZCL Multistate Output Basic dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_multistate_output_basic(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_MULTISTATE_OUTPUT_BASIC,
                            proto_zbee_zcl_multistate_output_basic,
                            ett_zbee_zcl_multistate_output_basic,
                            ZBEE_ZCL_CID_MULTISTATE_OUTPUT_BASIC,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_multistate_output_basic_attr_id,
                            hf_zbee_zcl_multistate_output_basic_attr_id,
                            -1,-1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_multistate_output_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_multistate_output_basic*/


/* ########################################################################## */
/* #### (0x0014) MULTISTATE VALUE (BASIC) CLUSTER ########################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_STATE_TEXT                      0x000E  /* State Text */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_DESCRIPTION                     0x001C  /* Description */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_NUMBER_OF_STATES                0x004A  /* Number of States */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_OUT_OF_SERVICE                  0x0051  /* Out of Service */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_PRESENT_VALUE                   0x0055  /* Present Value */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_PRIORITY_ARRAY                  0x0057  /* Priority Array */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_RELIABILITY                     0x0067  /* Reliability */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_RELINQUISH_DEFAULT              0x0068  /* Relinquish Default */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_STATUS_FLAGS                    0x006F  /* Status Flags */
#define ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_APPLICATION_TYPE                0x0100  /* Application Type */

/*Server commands received - none*/

/*Server commands generated - none*/

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_multistate_value_basic(void);
void proto_reg_handoff_zbee_zcl_multistate_value_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_multistate_value_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_multistate_value_basic;

static int hf_zbee_zcl_multistate_value_basic_attr_id;
static int hf_zbee_zcl_multistate_value_basic_status_flags;
static int hf_zbee_zcl_multistate_value_basic_status_in_alarm;
static int hf_zbee_zcl_multistate_value_basic_status_fault;
static int hf_zbee_zcl_multistate_value_basic_status_overridden;
static int hf_zbee_zcl_multistate_value_basic_status_out_of_service;
static int hf_zbee_zcl_multistate_value_basic_reliability;
static int hf_zbee_zcl_multistate_value_basic_priority_array_bool;
static int hf_zbee_zcl_multistate_value_basic_priority_array_sing_prec;
static int hf_zbee_zcl_multistate_value_basic_priority_array;
static int hf_zbee_zcl_multistate_value_basic_structure;


/* Initialize the subtree pointers */
static int ett_zbee_zcl_multistate_value_basic;
static int ett_zbee_zcl_multistate_value_basic_status_flags;
static int ett_zbee_zcl_multistate_value_basic_priority_array;
static int ett_zbee_zcl_multistate_value_basic_priority_array_structure;

/* Attributes */
static const value_string zbee_zcl_multistate_value_basic_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_STATE_TEXT,           "State Text" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_DESCRIPTION,          "Description" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_NUMBER_OF_STATES,     "Number of States" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_OUT_OF_SERVICE,       "Out of Service" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_PRESENT_VALUE,        "Present Value" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_PRIORITY_ARRAY,       "Priority Array" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_RELIABILITY,          "Reliability" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_RELINQUISH_DEFAULT,   "Relinquish Default" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_STATUS_FLAGS,         "Status Flags" },
    { ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_APPLICATION_TYPE,     "Application Type" },
    { 0, NULL }
};

static const value_string zbee_zcl_multistate_value_basic_priority_array_bool_values[] = {
    { 0x01, "Valid" },
    { 0x00, "Invalid" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_multistate_value_basic
 *  DESCRIPTION
 *      ZigBee ZCL Multistate Value Basic cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */

static int
dissect_zbee_zcl_multistate_value_basic(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_multistate_value_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_multistate_value_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_multistate_value_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    proto_item  *ti = NULL, *tj = NULL;
    proto_tree  *sub_tree = NULL, *sub = NULL;
    int i;

    static int * const status_flags[] = {
        &hf_zbee_zcl_multistate_value_basic_status_in_alarm,
        &hf_zbee_zcl_multistate_value_basic_status_fault,
        &hf_zbee_zcl_multistate_value_basic_status_overridden,
        &hf_zbee_zcl_multistate_value_basic_status_out_of_service,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_PRIORITY_ARRAY:
            ti = proto_tree_add_item(tree,hf_zbee_zcl_multistate_value_basic_priority_array, tvb, *offset, 80, ENC_NA);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_multistate_value_basic_priority_array);

            for( i = 1; i <= 16; i++)
            {
                tj = proto_tree_add_item(sub_tree,hf_zbee_zcl_multistate_value_basic_structure, tvb, *offset, 5,ENC_NA);
                proto_item_append_text(tj," %d",i);
                sub = proto_item_add_subtree(tj, ett_zbee_zcl_multistate_value_basic_priority_array_structure);
                proto_tree_add_item(sub, hf_zbee_zcl_multistate_value_basic_priority_array_bool, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
                *offset += 1;
                proto_tree_add_item(sub, hf_zbee_zcl_multistate_value_basic_priority_array_sing_prec, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            break;

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_RELIABILITY:
            proto_tree_add_item(tree, hf_zbee_zcl_multistate_value_basic_reliability, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_STATUS_FLAGS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_multistate_value_basic_status_flags, ett_zbee_zcl_multistate_value_basic_status_flags, status_flags, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_DESCRIPTION:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_NUMBER_OF_STATES:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_OUT_OF_SERVICE:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_RELINQUISH_DEFAULT:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_PRESENT_VALUE:
        case ZBEE_ZCL_ATTR_ID_MULTISTATE_VALUE_BASIC_APPLICATION_TYPE:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_multistate_value_basic_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_multistate_value_basic
 *  DESCRIPTION
 *      ZigBee ZCL Multistate Value Basic cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_multistate_value_basic(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_multistate_value_basic_attr_id,
            { "Attribute", "zbee_zcl_general.multistate_value_basic.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_multistate_value_basic_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_value_basic_reliability,
            { "Reliability", "zbee_zcl_general.multistate_value_basic.attr.reliability", FT_UINT8, BASE_HEX, VALS(zbee_zcl_reliability_names),
            0x00, NULL, HFILL } },

        /* start Status Flags fields */
        { &hf_zbee_zcl_multistate_value_basic_status_flags,
            { "Status Flags", "zbee_zcl_general.multistate_value_basic.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_value_basic_status_in_alarm,
            { "In Alarm Status", "zbee_zcl_general.multistate_value_basic.attr.status.in_alarm", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_IN_ALARM, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_value_basic_status_fault,
            { "Fault Status", "zbee_zcl_general.multistate_value_basic.attr.status.fault", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_FAULT, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_value_basic_status_overridden,
            { "Overridden Status", "zbee_zcl_general.multistate_value_basic.attr.status.overridden", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OVERRIDDEN, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_value_basic_status_out_of_service,
            { "Out of Service Status", "zbee_zcl_general.multistate_value_basic.attr.status.out_of_service", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_STATUS_OUT_OF_SERVICE, NULL, HFILL } },
        /* end Status Flags fields */

        { &hf_zbee_zcl_multistate_value_basic_priority_array_bool,
            { "Valid/Invalid", "zbee_zcl_general.multistate_value_basic.attr.priority_array.bool", FT_UINT8, BASE_HEX, VALS(zbee_zcl_multistate_value_basic_priority_array_bool_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_value_basic_priority_array_sing_prec,
            { "Priority Value", "zbee_zcl_general.multistate_value_basic.attr.priority_array.sing_prec", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_value_basic_priority_array,
            { "Priority Array", "zbee_zcl_general.multistate_value_basic.priority_array", FT_NONE, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_multistate_value_basic_structure,
            { "Structure", "zbee_zcl_general.multistate_value_basic.structure", FT_NONE, BASE_NONE, NULL,
            0x00, NULL, HFILL } }
    };

    /* ZCL Multistate Value Basic subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_multistate_value_basic,
        &ett_zbee_zcl_multistate_value_basic_status_flags,
        &ett_zbee_zcl_multistate_value_basic_priority_array,
        &ett_zbee_zcl_multistate_value_basic_priority_array_structure
    };

    /* Register the ZigBee ZCL Multistate Value Basic cluster protocol name and description */
    proto_zbee_zcl_multistate_value_basic = proto_register_protocol("ZigBee ZCL Multistate Value Basic", "ZCL Multistate Value Basic", ZBEE_PROTOABBREV_ZCL_MULTISTATE_VALUE_BASIC);
    proto_register_field_array(proto_zbee_zcl_multistate_value_basic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Multistate Value Basic dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_MULTISTATE_VALUE_BASIC, dissect_zbee_zcl_multistate_value_basic, proto_zbee_zcl_multistate_value_basic);
} /*proto_register_zbee_zcl_multistate_value_basic*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_multistate_value_basic
 *  DESCRIPTION
 *      Hands off the ZCL Multistate Value Basic dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_multistate_value_basic(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_MULTISTATE_VALUE_BASIC,
                            proto_zbee_zcl_multistate_value_basic,
                            ett_zbee_zcl_multistate_value_basic,
                            ZBEE_ZCL_CID_MULTISTATE_VALUE_BASIC,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_multistate_value_basic_attr_id,
                            hf_zbee_zcl_multistate_value_basic_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_multistate_value_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_multistate_value_basic*/

/* ########################################################################## */
/* #### (0x0015) COMMISSIONING CLUSTER ###################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_SHORT_ADDRESS                        0x0000  /* Short Address */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_EXTENDED_PAN_ID                      0x0001  /* Extended PAN Id */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_PAN_ID                               0x0002  /* PAN Id */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_CHANNEL_MASK                         0x0003  /* Channel Mask */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_PROTOCOL_VERSION                     0x0004  /* Protocol Version */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_STACK_PROFILE                        0x0005  /* Stack Profile */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_STARTUP_CONTROL                      0x0006  /* Startup Control */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_TRUST_CENTER_ADDRESS                 0x0010  /* Trust Center Address */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_TRUST_CENTER_MASTER_KEY              0x0011  /* Trust Center Master Key */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_KEY                          0x0012  /* Network Key */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_USE_INSECURE_JOIN                    0x0013  /* Use Insecure Join */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_PRECONFIGURED_LINK_KEY               0x0014  /* Preconfigured Link Key */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_KEY_SEQ_NUM                  0x0015  /* Network Key Sequence Number */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_KEY_TYPE                     0x0016  /* Network Key Type */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_MANAGER_ADDRESS              0x0017  /* Network Manager Address */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_SCAN_ATTEMPTS                        0x0020  /* Scan Attempts */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_TIME_BETWEEN_SCANS                   0x0021  /* Time Between Scans */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_REJOIN_INTERVAL                      0x0022  /* Rejoin Interval */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_MAX_REJOIN_INTERVAL                  0x0023  /* Max Rejoin Interval */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_INDIRECT_POLL_RATE                   0x0030  /* Indirect Poll Rate */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_PARENT_RETRY_THRESHOLD               0x0031  /* Parent Retry Threshold */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_CONCENTRATOR_FLAG                    0x0040  /* Concentrator Flag */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_CONCENTRATOR_RADIUS                  0x0041  /* Concentrator Radius */
#define ZBEE_ZCL_ATTR_ID_COMMISSIONING_CONCENTRATOR_DISCOVERY_TIME          0x0042  /* Concentrator Discovery Time */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTART_DEVICE                        0x00  /* Restart Device */
#define ZBEE_ZCL_CMD_ID_COMMISSIONING_SAVE_STARTUP_PARAMETERS               0x01  /* Save Startup Parameters */
#define ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTORE_STARTUP_PARAMETERS            0x02  /* Restore Startup Parameters */
#define ZBEE_ZCL_CMD_ID_COMMISSIONING_RESET_STARTUP_PARAMETERS              0x03  /* Reset Startup Parameters */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTART_DEVICE_RESPONSE               0x00  /* Restart Device Response */
#define ZBEE_ZCL_CMD_ID_COMMISSIONING_SAVE_STARTUP_PARAMETERS_RESPONSE      0x01  /* Save Startup Parameters Response */
#define ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTORE_STARTUP_PARAMETERS_RESPONSE   0x02  /* Restore Startup Parameters Response */
#define ZBEE_ZCL_CMD_ID_COMMISSIONING_RESET_STARTUP_PARAMETERS_RESPONSE     0x03  /* Reset Startup Parameters Response */

/* Restart Device Options Field Mask Values */
#define ZBEE_ZCL_COMMISSIONING_RESTART_DEVICE_OPTIONS_STARTUP_MODE          0x07
#define ZBEE_ZCL_COMMISSIONING_RESTART_DEVICE_OPTIONS_IMMEDIATE             0x08
#define ZBEE_ZCL_COMMISSIONING_RESTART_DEVICE_OPTIONS_RESERVED              0xF0

/* Reset Startup Parameters Options Field Mask Values */
#define ZBEE_ZCL_COMMISSIONING_RESET_STARTUP_OPTIONS_RESET_CURRENT          0x01
#define ZBEE_ZCL_COMMISSIONING_RESET_STARTUP_OPTIONS_RESET_ALL              0x02
#define ZBEE_ZCL_COMMISSIONING_RESET_STARTUP_OPTIONS_ERASE_INDEX            0x04
#define ZBEE_ZCL_COMMISSIONING_RESET_STARTUP_OPTIONS_RESERVED               0xFC


/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_commissioning(void);
void proto_reg_handoff_zbee_zcl_commissioning(void);

/* Command Dissector Helpers */
static void dissect_zcl_commissioning_restart_device                        (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_commissioning_save_restore_startup_parameters       (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_commissioning_reset_startup_parameters              (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_commissioning_response                              (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

static void dissect_zcl_commissioning_attr_data                             (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_commissioning;

static int hf_zbee_zcl_commissioning_attr_id;
static int hf_zbee_zcl_commissioning_attr_stack_profile;
static int hf_zbee_zcl_commissioning_attr_startup_control;
static int hf_zbee_zcl_commissioning_restart_device_options;
static int hf_zbee_zcl_commissioning_restart_device_options_startup_mode;
static int hf_zbee_zcl_commissioning_restart_device_options_immediate;
static int hf_zbee_zcl_commissioning_restart_device_options_reserved;
static int hf_zbee_zcl_commissioning_delay;
static int hf_zbee_zcl_commissioning_jitter;
static int hf_zbee_zcl_commissioning_options;
static int hf_zbee_zcl_commissioning_index;
static int hf_zbee_zcl_commissioning_reset_startup_options;
static int hf_zbee_zcl_commissioning_reset_startup_options_reset_current;
static int hf_zbee_zcl_commissioning_reset_startup_options_reset_all;
static int hf_zbee_zcl_commissioning_reset_startup_options_erase_index;
static int hf_zbee_zcl_commissioning_reset_startup_options_reserved;
static int hf_zbee_zcl_commissioning_status;
static int hf_zbee_zcl_commissioning_srv_rx_cmd_id;
static int hf_zbee_zcl_commissioning_srv_tx_cmd_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_commissioning;
static int ett_zbee_zcl_commissioning_restart_device_options;
static int ett_zbee_zcl_commissioning_reset_startup_options;

/* Attributes */
static const value_string zbee_zcl_commissioning_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_SHORT_ADDRESS,                         "Short Address" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_EXTENDED_PAN_ID,                       "Extended PAN Id" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_PAN_ID,                                "PAN Id" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_CHANNEL_MASK,                          "Channel Mask" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_PROTOCOL_VERSION,                      "Protocol Version" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_STACK_PROFILE,                         "Stack Profile" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_STARTUP_CONTROL,                       "Startup Control" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_TRUST_CENTER_ADDRESS,                  "Trust Center Address" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_TRUST_CENTER_MASTER_KEY,               "Trust Center Master Key" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_KEY,                           "Network Key" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_USE_INSECURE_JOIN,                     "Use Insecure Join" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_PRECONFIGURED_LINK_KEY,                "Preconfigured Link Key" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_KEY_SEQ_NUM,                   "Network Key Sequence Number" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_KEY_TYPE,                      "Network Key Type" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_MANAGER_ADDRESS,               "Network Manager Address" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_SCAN_ATTEMPTS,                         "Scan Attempts" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_TIME_BETWEEN_SCANS,                    "Time Between Scans" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_REJOIN_INTERVAL,                       "Rejoin Interval" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_MAX_REJOIN_INTERVAL,                   "Max Rejoin Interval" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_INDIRECT_POLL_RATE,                    "Indirect Poll Rate" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_PARENT_RETRY_THRESHOLD,                "Parent Retry Threshold" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_CONCENTRATOR_FLAG,                     "Concentrator Flag" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_CONCENTRATOR_RADIUS,                   "Concentrator Radius" },
    { ZBEE_ZCL_ATTR_ID_COMMISSIONING_CONCENTRATOR_DISCOVERY_TIME,           "Concentrator Discovery Time" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_commissioning_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTART_DEVICE,                         "Commissioning - Restart Device" },
    { ZBEE_ZCL_CMD_ID_COMMISSIONING_SAVE_STARTUP_PARAMETERS,                "Commissioning - Save Startup Parameters" },
    { ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTORE_STARTUP_PARAMETERS,             "Commissioning - Restore Startup Parameters" },
    { ZBEE_ZCL_CMD_ID_COMMISSIONING_RESET_STARTUP_PARAMETERS,               "Commissioning - Reset Startup Parameters" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_commissioning_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTART_DEVICE_RESPONSE,                "Commissioning - Restart Device Response" },
    { ZBEE_ZCL_CMD_ID_COMMISSIONING_SAVE_STARTUP_PARAMETERS_RESPONSE,       "Commissioning - Save Startup Parameters Response" },
    { ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTORE_STARTUP_PARAMETERS_RESPONSE,    "Commissioning - Startup Parameters Response" },
    { ZBEE_ZCL_CMD_ID_COMMISSIONING_RESET_STARTUP_PARAMETERS_RESPONSE,      "Commissioning - Reset Startup Parameters Response" },
    { 0, NULL }
};

static const value_string zbee_zcl_commissioning_stack_profile_values[] = {
    {0x01, "ZigBee Stack Profile"},
    {0x02, "ZigBee PRO Stack Profile"},
    {0, NULL}
};

static const value_string zbee_zcl_commissioning_startup_control_values[] = {
    {0x00, "Device is part of the network indicated by the Extended PAN Id"},
    {0x01, "Device should form a network with the Extended PAN Id"},
    {0x02, "Device should rejoin the network with Extended PAN Id"},
    {0x03, "Device should join the network using MAC Association"},
    {0, NULL}
};

static const value_string zbee_zcl_commissioning_startup_mode_values[] ={
    {0, "Restart Device using current set of startup parameters"},
    {1, "Restart Device using current set of stack attributes"},
    {0, NULL}
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_commissioning
 *  DESCRIPTION
 *      ZigBee ZCL Commissioning cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_commissioning(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_commissioning_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_commissioning_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_commissioning, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTART_DEVICE:
                    dissect_zcl_commissioning_restart_device(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COMMISSIONING_RESET_STARTUP_PARAMETERS:
                    dissect_zcl_commissioning_reset_startup_parameters(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COMMISSIONING_SAVE_STARTUP_PARAMETERS:
                case ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTORE_STARTUP_PARAMETERS:
                    dissect_zcl_commissioning_save_restore_startup_parameters(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_commissioning_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_commissioning_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_commissioning, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTART_DEVICE_RESPONSE:
                case ZBEE_ZCL_CMD_ID_COMMISSIONING_SAVE_STARTUP_PARAMETERS_RESPONSE:
                case ZBEE_ZCL_CMD_ID_COMMISSIONING_RESTORE_STARTUP_PARAMETERS_RESPONSE:
                case ZBEE_ZCL_CMD_ID_COMMISSIONING_RESET_STARTUP_PARAMETERS_RESPONSE:
                    dissect_zcl_commissioning_response(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_commissioning*/


 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_commissioning_restart_device
 *  DESCRIPTION
 *      this function decodes the Restart Device payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_commissioning_restart_device(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    static int * const restart_device_mask[] = {
        &hf_zbee_zcl_commissioning_restart_device_options_startup_mode,
        &hf_zbee_zcl_commissioning_restart_device_options_immediate,
        &hf_zbee_zcl_commissioning_restart_device_options_reserved,
        NULL
    };

    /* Retrieve "Options" field */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_commissioning_restart_device_options, ett_zbee_zcl_commissioning_restart_device_options, restart_device_mask, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Delay" field */
    proto_tree_add_item(tree, hf_zbee_zcl_commissioning_delay, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Jitter" field */
    proto_tree_add_item(tree, hf_zbee_zcl_commissioning_jitter, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_commissioning_restart_device*/


 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_commissioning_save_restore_startup_parameters
 *  DESCRIPTION
 *      this function decodes the Save and Restore payload.
 *  PARAMETERS
 *      tvb     - the tv buffer of the current data_type
 *      tree    - the tree to append this item to
 *      offset  - offset of data in tvb
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_commissioning_save_restore_startup_parameters(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Options" field */
    proto_tree_add_item(tree, hf_zbee_zcl_commissioning_options, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Index" field */
    proto_tree_add_item(tree, hf_zbee_zcl_commissioning_index, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_commissioning_save_restore_startup_parameters*/

/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_commissioning_reset_startup_parameters
*  DESCRIPTION
*      this function decodes the Reset Startup Parameters payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_commissioning_reset_startup_parameters(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    static int * const reset_startup_mask[] = {
        &hf_zbee_zcl_commissioning_reset_startup_options_reset_current,
        &hf_zbee_zcl_commissioning_reset_startup_options_reset_all,
        &hf_zbee_zcl_commissioning_reset_startup_options_erase_index,
        &hf_zbee_zcl_commissioning_reset_startup_options_reserved,
        NULL
    };

   /* Retrieve "Options" field */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_commissioning_reset_startup_options, ett_zbee_zcl_commissioning_reset_startup_options, reset_startup_mask, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Index" field */
   proto_tree_add_item(tree, hf_zbee_zcl_commissioning_index, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

} /*dissect_zcl_commissioning_reset_startup_parameters*/

/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_zcl_commissioning_response
*  DESCRIPTION
*      this function decodes the Response payload.
*  PARAMETERS
*      tvb     - the tv buffer of the current data_type
*      tree    - the tree to append this item to
*      offset  - offset of data in tvb
*  RETURNS
*      none
*---------------------------------------------------------------
*/
static void
dissect_zcl_commissioning_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Status" field */
   proto_tree_add_item(tree, hf_zbee_zcl_commissioning_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

} /*dissect_zcl_commissioning_response*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_commissioning_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_commissioning_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_STACK_PROFILE:
            proto_tree_add_item(tree, hf_zbee_zcl_commissioning_attr_stack_profile, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_STARTUP_CONTROL:
            proto_tree_add_item(tree, hf_zbee_zcl_commissioning_attr_startup_control, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_SHORT_ADDRESS:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_EXTENDED_PAN_ID:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_PAN_ID:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_CHANNEL_MASK:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_PROTOCOL_VERSION:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_TRUST_CENTER_ADDRESS:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_TRUST_CENTER_MASTER_KEY:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_KEY:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_USE_INSECURE_JOIN:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_PRECONFIGURED_LINK_KEY:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_KEY_SEQ_NUM:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_KEY_TYPE:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_NETWORK_MANAGER_ADDRESS:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_SCAN_ATTEMPTS:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_TIME_BETWEEN_SCANS:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_REJOIN_INTERVAL:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_MAX_REJOIN_INTERVAL:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_INDIRECT_POLL_RATE:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_PARENT_RETRY_THRESHOLD:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_CONCENTRATOR_FLAG:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_CONCENTRATOR_RADIUS:
        case ZBEE_ZCL_ATTR_ID_COMMISSIONING_CONCENTRATOR_DISCOVERY_TIME:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_commissioning_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_commissioning
 *  DESCRIPTION
 *      ZigBee ZCL Commissioning cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_commissioning(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_commissioning_attr_id,
            { "Attribute", "zbee_zcl_general.commissioning.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_commissioning_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_attr_stack_profile,
            { "Stack Profile", "zbee_zcl_general.commissioning.attr.stack_profile", FT_UINT8, BASE_HEX, VALS(zbee_zcl_commissioning_stack_profile_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_attr_startup_control,
            { "Startup Control", "zbee_zcl_general.commissioning.attr.startup_control", FT_UINT8, BASE_HEX, VALS(zbee_zcl_commissioning_startup_control_values),
            0x00, NULL, HFILL } },

        /* start Restart Device Options fields */
        { &hf_zbee_zcl_commissioning_restart_device_options,
            { "Restart Device Options", "zbee_zcl_general.commissioning.restart_device_options", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_restart_device_options_startup_mode,
            { "Startup Mode", "zbee_zcl_general.commissioning.restart_device_options.startup_mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_commissioning_startup_mode_values),
            ZBEE_ZCL_COMMISSIONING_RESTART_DEVICE_OPTIONS_STARTUP_MODE, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_restart_device_options_immediate,
            { "Immediate", "zbee_zcl_general.commissioning.restart_device_options.immediate", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_COMMISSIONING_RESTART_DEVICE_OPTIONS_IMMEDIATE, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_restart_device_options_reserved,
            { "Reserved", "zbee_zcl_general.commissioning.restart_device_options.reserved", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_COMMISSIONING_RESTART_DEVICE_OPTIONS_RESERVED, NULL, HFILL } },
        /* end Restart Device Options fields */

        { &hf_zbee_zcl_commissioning_delay,
            { "Delay", "zbee_zcl_general.commissioning.delay", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_jitter,
            { "Jitter", "zbee_zcl_general.commissioning.jitter", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_options,
            { "Options (Reserved)", "zbee_zcl_general.commissioning.options", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_index,
            { "Index", "zbee_zcl_general.commissioning.index", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        /* start Reset Startup Options fields */
        { &hf_zbee_zcl_commissioning_reset_startup_options,
            { "Reset Startup Options", "zbee_zcl_general.commissioning.reset_startup_options", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_reset_startup_options_reset_current,
            { "Reset Current", "zbee_zcl_general.commissioning.reset_startup_options.current", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_COMMISSIONING_RESET_STARTUP_OPTIONS_RESET_CURRENT, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_reset_startup_options_reset_all,
            { "Reset All", "zbee_zcl_general.commissioning.reset_startup_options.reset_all", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_COMMISSIONING_RESET_STARTUP_OPTIONS_RESET_ALL, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_reset_startup_options_erase_index,
            { "Erase Index", "zbee_zcl_general.commissioning.reset_startup_options.erase_index", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_COMMISSIONING_RESET_STARTUP_OPTIONS_ERASE_INDEX, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_reset_startup_options_reserved,
            { "Reserved", "zbee_zcl_general.commissioning.reset_startup_options.reserved", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_COMMISSIONING_RESET_STARTUP_OPTIONS_RESERVED, NULL, HFILL } },
        /* end Reset Startup Options fields */

        { &hf_zbee_zcl_commissioning_status,
            { "Status", "zbee_zcl_general.commissioning.status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_status_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_srv_rx_cmd_id,
          { "Command", "zbee_zcl_general.commissioning.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_commissioning_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_commissioning_srv_tx_cmd_id,
          { "Command", "zbee_zcl_general.commissioning.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_commissioning_srv_tx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Commissioning subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_commissioning,
        &ett_zbee_zcl_commissioning_restart_device_options,
        &ett_zbee_zcl_commissioning_reset_startup_options
    };

    /* Register the ZigBee ZCL Commissioning cluster protocol name and description */
    proto_zbee_zcl_commissioning = proto_register_protocol("ZigBee ZCL Commissioning", "ZCL Commissioning", ZBEE_PROTOABBREV_ZCL_COMMISSIONING);
    proto_register_field_array(proto_zbee_zcl_commissioning, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Commissioning dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_COMMISSIONING, dissect_zbee_zcl_commissioning, proto_zbee_zcl_commissioning);

} /*proto_register_zbee_zcl_commissioning*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_commissioning
 *  DESCRIPTION
 *      Hands off the ZCL Commissioning dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_commissioning(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_COMMISSIONING,
                            proto_zbee_zcl_commissioning,
                            ett_zbee_zcl_commissioning,
                            ZBEE_ZCL_CID_COMMISSIONING,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_commissioning_attr_id,
                            hf_zbee_zcl_commissioning_attr_id,
                            hf_zbee_zcl_commissioning_srv_rx_cmd_id,
                            hf_zbee_zcl_commissioning_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_commissioning_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_commissioning*/


/* ########################################################################## */
/* #### (0x0016) PARTITION ################################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_PART_NUM_GENERIC_ETT                   3
#define ZBEE_ZCL_PART_NUM_NACK_ID_ETT                   16
#define ZBEE_ZCL_PART_NUM_ATTRS_ID_ETT                  16
#define ZBEE_ZCL_PART_NUM_ETT                           (ZBEE_ZCL_PART_NUM_GENERIC_ETT + \
                                                        ZBEE_ZCL_PART_NUM_NACK_ID_ETT + \
                                                        ZBEE_ZCL_PART_NUM_ATTRS_ID_ETT)

#define ZBEE_ZCL_PART_OPT_1_BLOCK                       0x01
#define ZBEE_ZCL_PART_OPT_INDIC_LEN                     0x02
#define ZBEE_ZCL_PART_OPT_RESERVED                      0xc0

#define ZBEE_ZCL_PART_ACK_OPT_NACK_LEN                  0x01
#define ZBEE_ZCL_PART_ACK_OPT_RESERVED                  0xFE

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_PART_MAX_IN_TRANSF_SIZE        0x0000  /* Maximum Incoming Transfer Size */
#define ZBEE_ZCL_ATTR_ID_PART_MAX_OUT_TRANSF_SIZE       0x0001  /* Maximum Outgoing Transfer Size */
#define ZBEE_ZCL_ATTR_ID_PART_PARTITIONED_FRAME_SIZE    0x0002  /* Partitioned Frame Size */
#define ZBEE_ZCL_ATTR_ID_PART_LARGE_FRAME_SIZE          0x0003  /* Large Frame Size */
#define ZBEE_ZCL_ATTR_ID_PART_ACK_FRAME_NUM             0x0004  /* Number of Ack Frame*/
#define ZBEE_ZCL_ATTR_ID_PART_NACK_TIMEOUT              0x0005  /* Nack Timeout */
#define ZBEE_ZCL_ATTR_ID_PART_INTERFRAME_DELEAY         0x0006  /* Interframe Delay */
#define ZBEE_ZCL_ATTR_ID_PART_SEND_RETRIES_NUM          0x0007  /* Number of Send Retries */
#define ZBEE_ZCL_ATTR_ID_PART_SENDER_TIMEOUT            0x0008  /* Sender Timeout */
#define ZBEE_ZCL_ATTR_ID_PART_RECEIVER_TIMEOUT          0x0009  /* Receiver Timeout */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_PART_TRANSF_PART_FRAME          0x00  /* Transfer Partitioned Frame */
#define ZBEE_ZCL_CMD_ID_PART_RD_HANDSHAKE_PARAM         0x01  /* Read Handshake Param */
#define ZBEE_ZCL_CMD_ID_PART_WR_HANDSHAKE_PARAM         0x02  /* Write Handshake Param */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_PART_MULTI_ACK                  0x00  /* Multiple Ack */
#define ZBEE_ZCL_CMD_ID_PART_RD_HANDSHAKE_PARAM_RSP     0x01  /* Read Handshake Param Response */


/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_part(void);
void proto_reg_handoff_zbee_zcl_part(void);

/* Command Dissector Helpers */
static void dissect_zcl_part_trasfpartframe         (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_part_rdhandshakeparam       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, bool direction);
static void dissect_zcl_part_wrhandshakeparam       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, bool direction);
static void dissect_zcl_part_multiack               (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_part_rdhandshakeparamrsp    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, bool direction);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_part;

static int hf_zbee_zcl_part_attr_id;
static int hf_zbee_zcl_part_srv_tx_cmd_id;
static int hf_zbee_zcl_part_srv_rx_cmd_id;
static int hf_zbee_zcl_part_opt;
static int hf_zbee_zcl_part_opt_first_block;
static int hf_zbee_zcl_part_opt_indic_len;
static int hf_zbee_zcl_part_opt_res;
static int hf_zbee_zcl_part_first_frame_id;
static int hf_zbee_zcl_part_part_indicator;
static int hf_zbee_zcl_part_part_frame;
static int hf_zbee_zcl_part_partitioned_cluster_id;
static int hf_zbee_zcl_part_ack_opt;
static int hf_zbee_zcl_part_ack_opt_nack_id_len;
static int hf_zbee_zcl_part_ack_opt_res;
static int hf_zbee_zcl_part_nack_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_part;
static int ett_zbee_zcl_part_fragm_options;
static int ett_zbee_zcl_part_ack_opts;
static int ett_zbee_zcl_part_nack_id_list[ZBEE_ZCL_PART_NUM_NACK_ID_ETT];
static int ett_zbee_zcl_part_attrs_id_list[ZBEE_ZCL_PART_NUM_ATTRS_ID_ETT];

/* Attributes */
static const value_string zbee_zcl_part_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_PART_MAX_IN_TRANSF_SIZE,     "Maximum Incoming Transfer Size" },
    { ZBEE_ZCL_ATTR_ID_PART_MAX_OUT_TRANSF_SIZE,    "Maximum Outgoing Transfer Size" },
    { ZBEE_ZCL_ATTR_ID_PART_PARTITIONED_FRAME_SIZE, "Partitioned Frame Size" },
    { ZBEE_ZCL_ATTR_ID_PART_LARGE_FRAME_SIZE,       "Large Frame Size" },
    { ZBEE_ZCL_ATTR_ID_PART_ACK_FRAME_NUM,          "Number of Ack Frame" },
    { ZBEE_ZCL_ATTR_ID_PART_NACK_TIMEOUT,           "Nack Timeout" },
    { ZBEE_ZCL_ATTR_ID_PART_INTERFRAME_DELEAY,      "Interframe Delay" },
    { ZBEE_ZCL_ATTR_ID_PART_SEND_RETRIES_NUM,       "Number of Send Retries" },
    { ZBEE_ZCL_ATTR_ID_PART_SENDER_TIMEOUT,         "Sender Timeout" },
    { ZBEE_ZCL_ATTR_ID_PART_RECEIVER_TIMEOUT,       "Receiver Timeout" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_part_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_PART_TRANSF_PART_FRAME,       "Transfer Partitioned Frame" },
    { ZBEE_ZCL_CMD_ID_PART_RD_HANDSHAKE_PARAM,      "Read Handshake Param" },
    { ZBEE_ZCL_CMD_ID_PART_WR_HANDSHAKE_PARAM,      "Write Handshake Param" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_part_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_PART_MULTI_ACK,               "Multiple Ack" },
    { ZBEE_ZCL_CMD_ID_PART_RD_HANDSHAKE_PARAM_RSP,  "Read Handshake Param Response" },
    { 0, NULL }
};

/* ID Length */
static const value_string zbee_zcl_part_id_length_names[] = {
    { 0,        "1-Byte length" },
    { 1,        "2-Bytes length" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_part
 *  DESCRIPTION
 *      ZigBee ZCL Partition cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      void *data          - pointer to ZCL packet structure.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_part(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree  *payload_tree;
    zbee_zcl_packet  *zcl;
    unsigned    offset = 0;
    uint8_t     cmd_id;
    int         rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_part_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_part_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_part, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_PART_TRANSF_PART_FRAME:
                    dissect_zcl_part_trasfpartframe(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PART_RD_HANDSHAKE_PARAM:
                    dissect_zcl_part_rdhandshakeparam(tvb, pinfo, payload_tree, &offset, zcl->direction);
                    break;

                case ZBEE_ZCL_CMD_ID_PART_WR_HANDSHAKE_PARAM:
                    dissect_zcl_part_wrhandshakeparam(tvb, pinfo, payload_tree, &offset, zcl->direction);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_part_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_part_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_part, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_PART_MULTI_ACK:
                    dissect_zcl_part_multiack(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PART_RD_HANDSHAKE_PARAM_RSP:
                    dissect_zcl_part_rdhandshakeparamrsp(tvb, pinfo, payload_tree, &offset, zcl->direction);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_part*/

 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_part_trasfpartframe
 *  DESCRIPTION
 *      This function manages the Transfer Partition Frame payload
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      offset              - pointer of buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void dissect_zcl_part_trasfpartframe(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{

    uint8_t   options;
    int       frame_len;

    static int * const part_opt[] = {
        &hf_zbee_zcl_part_opt_first_block,
        &hf_zbee_zcl_part_opt_indic_len,
        &hf_zbee_zcl_part_opt_res,
        NULL
    };

    /* Retrieve "Fragmentation Options" field */
    options = tvb_get_uint8(tvb, *offset);
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_part_opt, ett_zbee_zcl_part_fragm_options, part_opt, ENC_NA);
    *offset += 1;

    /* Retrieve "PartitionIndicator" field */
    if ((options & ZBEE_ZCL_PART_OPT_INDIC_LEN) ==  0)
    {
        /* 1-byte length */
        proto_tree_add_item(tree, hf_zbee_zcl_part_part_indicator, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }
    else {
        /* 2-bytes length */
        proto_tree_add_item(tree, hf_zbee_zcl_part_part_indicator, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }

    /* Retrieve "PartitionedFrame" field */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_part_part_frame, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &frame_len);
    *offset += frame_len;

} /*dissect_zcl_part_trasfpartframe*/

 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_part_rdhandshakeparam
 *  DESCRIPTION
 *      This function manages the ReadHandshakeParam payload
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      offset              - offset
 *      direction           - ZCL direction
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_part_rdhandshakeparam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, bool direction)
{
    /* Retrieve "Partitioned Cluster ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_part_partitioned_cluster_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Dissect the attribute id list */
    dissect_zcl_read_attr(tvb, pinfo, tree, offset, ZBEE_ZCL_CID_PARTITION, ZBEE_MFG_CODE_NONE, direction);
} /*dissect_zcl_part_rdhandshakeparam*/

 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_part_wrhandshakeparam
 *  DESCRIPTION
 *      This function manages the WriteAndShakeParam payload
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      offset              - offset
 *      direction           - ZCL direction
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_part_wrhandshakeparam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, bool direction)
{
    /* Retrieve "Partitioned Cluster ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_part_partitioned_cluster_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Dissect the attributes list */
    dissect_zcl_write_attr(tvb, pinfo, tree, offset, ZBEE_ZCL_CID_PARTITION, ZBEE_MFG_CODE_NONE, direction);

} /*dissect_zcl_part_wrhandshakeparam*/


/* Management of Cluster specific commands sent by the server */

 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_part_multiack
 *  DESCRIPTION
 *      This function manages the MultipleACK payload
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo, -
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      offset              - offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_part_multiack(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    unsigned   tvb_len = tvb_reported_length(tvb);
    unsigned   i = 0;
    uint8_t options;

    static int * const ack_opts[] = {
        &hf_zbee_zcl_part_ack_opt_nack_id_len,
        &hf_zbee_zcl_part_ack_opt_res,
        NULL
    };

    /* Retrieve "Ack Options" field */
    options = tvb_get_uint8(tvb, *offset);
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_part_ack_opt, ett_zbee_zcl_part_ack_opts, ack_opts, ENC_NA);
    *offset += 1;

    /* Retrieve "First Frame ID" field */
    if ((options & ZBEE_ZCL_PART_ACK_OPT_NACK_LEN) ==  0)
    {
        /* 1-byte length */
        proto_tree_add_item(tree, hf_zbee_zcl_part_first_frame_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }
    else {
        /* 2-bytes length */
        proto_tree_add_item(tree, hf_zbee_zcl_part_first_frame_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }

    /* Dissect the nack id list */
    while ( *offset < tvb_len && i < ZBEE_ZCL_PART_NUM_NACK_ID_ETT )
    {
        if ((options & ZBEE_ZCL_PART_ACK_OPT_NACK_LEN) ==  0)
        {
            /* 1-byte length */
            proto_tree_add_item(tree, hf_zbee_zcl_part_nack_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
        }
        else {
            /* 2-bytes length */
            proto_tree_add_item(tree, hf_zbee_zcl_part_nack_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
        }

        i++;
    }
} /*dissect_zcl_part_multiack*/

 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_part_rdhandshakeparamrsp
 *  DESCRIPTION
 *      This function manages the ReadHandshakeParamResponse payload
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      offset              - offset
 *      direction           - ZCL direction
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_part_rdhandshakeparamrsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, bool direction)
{
    /* Retrieve "Partitioned Cluster ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_part_partitioned_cluster_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Dissect the attributes list */
    dissect_zcl_read_attr_resp(tvb, pinfo, tree, offset, ZBEE_ZCL_CID_PARTITION, ZBEE_MFG_CODE_NONE, direction);
} /*dissect_zcl_part_rdhandshakeparamrsp*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_part
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void proto_register_zbee_zcl_part(void)
{
    uint8_t i, j;

    static hf_register_info hf[] = {

        { &hf_zbee_zcl_part_attr_id,
            { "Attribute", "zbee_zcl_general.part.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_part_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_part_srv_tx_cmd_id,
            { "Command", "zbee_zcl_general.part.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_part_srv_tx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_part_srv_rx_cmd_id,
            { "Command", "zbee_zcl_general.part.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_part_srv_rx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_part_opt,
            { "Fragmentation Options", "zbee_zcl_general.part.opt", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_part_opt_first_block,
            { "First Block", "zbee_zcl_general.part.opt.first_block", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_PART_OPT_1_BLOCK, NULL, HFILL } },

        { &hf_zbee_zcl_part_opt_indic_len,
            { "Indicator length", "zbee_zcl_general.part.opt.indic_len", FT_UINT8, BASE_DEC, VALS(zbee_zcl_part_id_length_names),
            ZBEE_ZCL_PART_OPT_INDIC_LEN, NULL, HFILL } },

        { &hf_zbee_zcl_part_opt_res,
            { "Reserved", "zbee_zcl_general.part.opt.res", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_PART_OPT_RESERVED, NULL, HFILL } },

        { &hf_zbee_zcl_part_first_frame_id,
            { "First Frame ID", "zbee_zcl_general.part.first_frame_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_part_part_indicator,
            { "Partition Indicator", "zbee_zcl_general.part.part_indicator", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_part_part_frame,
            { "Partition Frame", "zbee_zcl_general.part.part_frame", FT_UINT_BYTES, SEP_COLON, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_part_partitioned_cluster_id,
            { "Partitioned Cluster ID", "zbee_zcl_general.part.part_cluster_id", FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_aps_cid_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_part_ack_opt,
            { "Ack Options", "zbee_zcl_general.ack_opt.part", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_part_ack_opt_nack_id_len,
            { "Nack Id Length", "zbee_zcl_general.ack_opt.part.nack_id.len", FT_UINT8, BASE_HEX, VALS(zbee_zcl_part_id_length_names),
            ZBEE_ZCL_PART_ACK_OPT_NACK_LEN, NULL, HFILL } },

        { &hf_zbee_zcl_part_ack_opt_res,
            { "Reserved", "zbee_zcl_general.part.ack_opt.reserved", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_PART_ACK_OPT_RESERVED, NULL, HFILL } },

        { &hf_zbee_zcl_part_nack_id,
            { "Nack Id", "zbee_zcl_general.part.nack_id", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL } }

    };

    /* ZCL Partition subtrees */
    int *ett[ZBEE_ZCL_PART_NUM_ETT] = {
        &ett_zbee_zcl_part,
        &ett_zbee_zcl_part_fragm_options,
        &ett_zbee_zcl_part_ack_opts
    };

    /* initialize attribute subtree types */
    for ( i = 0, j = ZBEE_ZCL_PART_NUM_GENERIC_ETT; i < ZBEE_ZCL_PART_NUM_NACK_ID_ETT; i++, j++) {
        ett[j] = &ett_zbee_zcl_part_nack_id_list[i];
    }

    for ( i = 0; i < ZBEE_ZCL_PART_NUM_ATTRS_ID_ETT; i++, j++) {
        ett[j] = &ett_zbee_zcl_part_attrs_id_list[i];
    }

    /* Register ZigBee ZCL Partition protocol with Wireshark. */
    proto_zbee_zcl_part = proto_register_protocol("ZigBee ZCL Partition", "ZCL Partition", ZBEE_PROTOABBREV_ZCL_PART);
    proto_register_field_array(proto_zbee_zcl_part, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Partition dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_PART, dissect_zbee_zcl_part, proto_zbee_zcl_part);
} /* proto_register_zbee_zcl_part */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_part
 *  DESCRIPTION
 *      Registers the zigbee ZCL Partition cluster dissector with Wireshark.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_zbee_zcl_part(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_PART,
                            proto_zbee_zcl_part,
                            ett_zbee_zcl_part,
                            ZBEE_ZCL_CID_PARTITION,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_part_attr_id,
                            hf_zbee_zcl_part_attr_id,
                            hf_zbee_zcl_part_srv_rx_cmd_id,
                            hf_zbee_zcl_part_srv_tx_cmd_id,
                            NULL
                         );

} /*proto_reg_handoff_zbee_zcl_part*/

/* ########################################################################## */
/* #### (0x0019) OTA UPGRADE CLUSTER ######################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_OTA_UPGRADE_SERVER_ID              0x0000  /* Upgrade Server ID */
#define ZBEE_ZCL_ATTR_ID_OTA_FILE_OFFSET                    0x0001  /* File Offset */
#define ZBEE_ZCL_ATTR_ID_OTA_CURRENT_FILE_VERSION           0x0002  /* Current File Version */
#define ZBEE_ZCL_ATTR_ID_OTA_CURRENT_ZB_STACK_VERSION       0x0003  /* Current ZigBee Stack Version */
#define ZBEE_ZCL_ATTR_ID_OTA_DOWNLOADED_FILE_VERSION        0x0004  /* Downloaded File Version */
#define ZBEE_ZCL_ATTR_ID_OTA_DOWNLOADED_ZB_STACK_VERSION    0x0005  /* Downloaded ZigBee Stack Version */
#define ZBEE_ZCL_ATTR_ID_OTA_IMAGE_UPGRADE_STATUS           0x0006  /* Image Upgrade Status */
#define ZBEE_ZCL_ATTR_ID_OTA_MANUFACTURER_ID                0x0007  /* Manufacturer ID */
#define ZBEE_ZCL_ATTR_ID_OTA_IMAGE_TYPE_ID                  0x0008  /* Image Type ID */
#define ZBEE_ZCL_ATTR_ID_OTA_MIN_BLOCK_REQ_DELAY            0x0009  /* Minimum Block Request Delay */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_OTA_IMAGE_NOTIFY                      0x00  /* Image Notify */
#define ZBEE_ZCL_CMD_ID_OTA_QUERY_NEXT_IMAGE_RSP              0x02  /* Query Next Image Response */
#define ZBEE_ZCL_CMD_ID_OTA_IMAGE_BLOCK_RSP                   0x05  /* Image Block Response */
#define ZBEE_ZCL_CMD_ID_OTA_UPGRADE_END_RSP                   0x07  /* Upgrade End Response */
#define ZBEE_ZCL_CMD_ID_OTA_QUERY_SPEC_FILE_RSP               0x09  /* Query Specific File Response */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_OTA_QUERY_NEXT_IMAGE_REQ              0x01  /* Query Next Image Request */
#define ZBEE_ZCL_CMD_ID_OTA_IMAGE_BLOCK_REQ                   0x03  /* Image Block Request */
#define ZBEE_ZCL_CMD_ID_OTA_IMAGE_PAGE_REQ                    0x04  /* Image Page Request */
#define ZBEE_ZCL_CMD_ID_OTA_UPGRADE_END_REQ                   0x06  /* Upgrade End Request */
#define ZBEE_ZCL_CMD_ID_OTA_QUERY_SPEC_FILE_REQ               0x08  /* Query Specific File Request */

/* Payload Type */
#define ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ                          0x00  /* Query Jitter */
#define ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ_MC                       0x01  /* Query Jitter and Manufacturer Code */
#define ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ_MC_IT                    0x02  /* Query Jitter, Manufacturer Code and Image Type */
#define ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ_MC_IT_FV                 0x03  /* Query Jitter, Manufacturer Code, Image Type and File Version */

/* Image Type */
#define ZBEE_ZCL_OTA_IMG_TYPE_MFR_LOW                       0x0000  /* Manufacturer Specific (Low value) */
#define ZBEE_ZCL_OTA_IMG_TYPE_MFR_HIGH                      0xffbf  /* Manufacturer Specific (High value) */
#define ZBEE_ZCL_OTA_IMG_TYPE_SECURITY                      0xffc0  /* Security Credential */
#define ZBEE_ZCL_OTA_IMG_TYPE_CONFIG                        0xffc1  /* Configuration */
#define ZBEE_ZCL_OTA_IMG_TYPE_LOG                           0xffc2  /* Log */
#define ZBEE_ZCL_OTA_IMG_TYPE_UNASSIGNED_LOW                0xffc3  /* Reserved: Unassigned (Low value) */
#define ZBEE_ZCL_OTA_IMG_TYPE_UNASSIGNED_HIGH               0xfffe  /* Reserved: Unassigned (High value) */
#define ZBEE_ZCL_OTA_IMG_TYPE_WILD_CARD                     0xffff  /* Reserved: Wild Card */

/* ZigBee Stack Version */
#define ZBEE_ZCL_OTA_ZB_STACK_VER_2006                      0x0000  /* ZigBee 2006 */
#define ZBEE_ZCL_OTA_ZB_STACK_VER_2007                      0x0001  /* ZigBee 2007 */
#define ZBEE_ZCL_OTA_ZB_STACK_VER_PRO                       0x0002  /* ZigBee Pro */
#define ZBEE_ZCL_OTA_ZB_STACK_VER_IP                        0x0003  /* ZigBee IP */
#define ZBEE_ZCL_OTA_ZB_STACK_VER_RESERVED_LO               0x0004  /* Reserved Low */
#define ZBEE_ZCL_OTA_ZB_STACK_VER_RESERVED_HI               0xffff  /* Reserved High */

/* Image Upgrade Status */
#define ZBEE_ZCL_OTA_STATUS_NORMAL                            0x00  /* Normal */
#define ZBEE_ZCL_OTA_STATUS_DOWNLOAD_IN_PROGRESS              0x01  /* Download in progress */
#define ZBEE_ZCL_OTA_STATUS_DOWNLOAD_COMPLETE                 0x02  /* Download complete */
#define ZBEE_ZCL_OTA_STATUS_WAITING_TO_UPGRADE                0x03  /* Waiting to upgrade */
#define ZBEE_ZCL_OTA_STATUS_COUNT_DOWN                        0x04  /* Count down */
#define ZBEE_ZCL_OTA_STATUS_WAIT_FOR_MORE                     0x05  /* Wait for more */
                                                                    /* 0x06-0xff - Reserved */
/* File Version mask */
#define ZBEE_ZCL_OTA_FILE_VERS_APPL_RELEASE             0xFF000000  /* Application Release */
#define ZBEE_ZCL_OTA_FILE_VERS_APPL_BUILD               0x00FF0000  /* Application Build */
#define ZBEE_ZCL_OTA_FILE_VERS_STACK_RELEASE            0x0000FF00  /* Stack Release */
#define ZBEE_ZCL_OTA_FILE_VERS_STACK_BUILD              0x000000FF  /* Stack Build */

/* Field Control bitmask field list for Query Next Image Request */
#define ZBEE_ZCL_OTA_QUERY_NEXT_IMAGE_REQ_FIELD_CTRL_HW_VER_PRESENT         0x01  /* bit 0 */
#define ZBEE_ZCL_OTA_QUERY_NEXT_IMAGE_REQ_FIELD_CTRL_RESERVED               0xfe  /* bit 1-7 */

/* Field Control bitmask field list for Image Block Request */
#define ZBEE_ZCL_OTA_IMAGE_BLOCK_REQ_FIELD_CTRL_REQUEST_NODE_ADDR_PRESENT   0x01  /* bit 0 - Request node IEEE address Present */
#define ZBEE_ZCL_OTA_IMAGE_BLOCK_REQ_FIELD_CTRL_MIN_BLOCK_PERIOD_PRESENT    0x02  /* bit 1 - Minimum block period Present */
#define ZBEE_ZCL_OTA_IMAGE_BLOCK_REQ_FIELD_CTRL_RESERVED                    0xfc  /* bit 2-7 */

/* Field Control bitmask field list for Image Page Request */
#define ZBEE_ZCL_OTA_IMAGE_PAGE_REQ_FIELD_CTRL_REQUEST_NODE_ADDR_PRESENT    0x01  /* bit 0 - Request node IEEE address Present */
#define ZBEE_ZCL_OTA_IMAGE_PAGE_REQ_FIELD_CTRL_RESERVED                     0xfe  /* bit 1-7 */

/* OTA Time */
#define ZBEE_ZCL_OTA_TIME_NOW                           0x00000000  /* Now */
#define ZBEE_ZCL_OTA_TIME_UTC_LO                        0x00000001  /* UTC Low Boundary */
#define ZBEE_ZCL_OTA_TIME_UTC_HI                        0xfffffffe  /* UTC High Boundary */
#define ZBEE_ZCL_OTA_TIME_WAIT                          0xffffffff  /* Wait for a Upgrade command (not used for RequestTime) */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_ota(void);
void proto_reg_handoff_zbee_zcl_ota(void);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_ota;

static int hf_zbee_zcl_ota_attr_id;
static int hf_zbee_zcl_ota_srv_tx_cmd_id;
static int hf_zbee_zcl_ota_srv_rx_cmd_id;
static int hf_zbee_zcl_ota_image_upgrade_status;
static int hf_zbee_zcl_ota_zb_stack_ver;
static int hf_zbee_zcl_ota_file_offset;
static int hf_zbee_zcl_ota_payload_type;
static int hf_zbee_zcl_ota_query_jitter;
static int hf_zbee_zcl_ota_manufacturer_code;
static int hf_zbee_zcl_ota_image_type;
static int hf_zbee_zcl_ota_file_version;
static int hf_zbee_zcl_ota_file_version_appl_release;
static int hf_zbee_zcl_ota_file_version_appl_build;
static int hf_zbee_zcl_ota_file_version_stack_release;
static int hf_zbee_zcl_ota_file_version_stack_build;
static int hf_zbee_zcl_ota_query_next_image_req_field_ctrl;
static int hf_zbee_zcl_ota_query_next_image_req_field_ctrl_hw_ver_present;
static int hf_zbee_zcl_ota_query_next_image_req_field_ctrl_reserved;
static int hf_zbee_zcl_ota_image_block_req_field_ctrl;
static int hf_zbee_zcl_ota_image_block_req_field_ctrl_ieee_addr_present;
static int hf_zbee_zcl_ota_image_block_req_field_ctrl_min_block_period_present;
static int hf_zbee_zcl_ota_image_block_req_field_ctrl_reserved;
static int hf_zbee_zcl_ota_image_page_req_field_ctrl;
static int hf_zbee_zcl_ota_image_page_req_field_ctrl_ieee_addr_present;
static int hf_zbee_zcl_ota_image_page_req_field_ctrl_reserved;
static int hf_zbee_zcl_ota_hw_version;
static int hf_zbee_zcl_ota_status;
static int hf_zbee_zcl_ota_image_size;
static int hf_zbee_zcl_ota_max_data_size;
static int hf_zbee_zcl_ota_min_block_period;
static int hf_zbee_zcl_ota_req_node_addr;
static int hf_zbee_zcl_ota_current_time;
static int hf_zbee_zcl_ota_request_time;
static int hf_zbee_zcl_ota_upgrade_time;
static int hf_zbee_zcl_ota_upgrade_time_utc;
static int hf_zbee_zcl_ota_data_size;
static int hf_zbee_zcl_ota_image_data;
static int hf_zbee_zcl_ota_page_size;
static int hf_zbee_zcl_ota_rsp_spacing;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_ota;
static int ett_zbee_zcl_ota_query_next_image_req_field_ctrl;
static int ett_zbee_zcl_ota_image_block_req_field_ctrl;
static int ett_zbee_zcl_ota_image_page_req_field_ctrl;
static int ett_zbee_zcl_ota_file_version;

/* Attributes */
static const value_string zbee_zcl_ota_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_OTA_UPGRADE_SERVER_ID,               "Upgrade Server ID" },
    { ZBEE_ZCL_ATTR_ID_OTA_FILE_OFFSET,                     "File Offset" },
    { ZBEE_ZCL_ATTR_ID_OTA_CURRENT_FILE_VERSION,            "Current File Version" },
    { ZBEE_ZCL_ATTR_ID_OTA_CURRENT_ZB_STACK_VERSION,        "Current ZigBee Stack Version" },
    { ZBEE_ZCL_ATTR_ID_OTA_DOWNLOADED_FILE_VERSION,         "Downloaded File Version" },
    { ZBEE_ZCL_ATTR_ID_OTA_DOWNLOADED_ZB_STACK_VERSION,     "Downloaded ZigBee Stack Version" },
    { ZBEE_ZCL_ATTR_ID_OTA_IMAGE_UPGRADE_STATUS,            "Image Upgrade Status" },
    { ZBEE_ZCL_ATTR_ID_OTA_MANUFACTURER_ID,                 "Manufacturer ID" },
    { ZBEE_ZCL_ATTR_ID_OTA_IMAGE_TYPE_ID,                   "Image Type ID" },
    { ZBEE_ZCL_ATTR_ID_OTA_MIN_BLOCK_REQ_DELAY,             "Minimum Block Request Delay" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_ota_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_OTA_QUERY_NEXT_IMAGE_REQ,             "Query Next Image Request" },
    { ZBEE_ZCL_CMD_ID_OTA_IMAGE_BLOCK_REQ,                  "Image Block Request" },
    { ZBEE_ZCL_CMD_ID_OTA_IMAGE_PAGE_REQ,                   "Image Page Request" },
    { ZBEE_ZCL_CMD_ID_OTA_UPGRADE_END_REQ,                  "Upgrade End Request" },
    { ZBEE_ZCL_CMD_ID_OTA_QUERY_SPEC_FILE_REQ,              "Query Specific File Request" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_ota_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_OTA_IMAGE_NOTIFY,                     "Image Notify" },
    { ZBEE_ZCL_CMD_ID_OTA_QUERY_NEXT_IMAGE_RSP,             "Query Next Image Response" },
    { ZBEE_ZCL_CMD_ID_OTA_IMAGE_BLOCK_RSP,                  "Image Block Response" },
    { ZBEE_ZCL_CMD_ID_OTA_UPGRADE_END_RSP,                  "Upgrade End Response" },
    { ZBEE_ZCL_CMD_ID_OTA_QUERY_SPEC_FILE_RSP,              "Query Specific File Response" },
    { 0, NULL }
};

/* Payload Type */
static const value_string zbee_zcl_ota_paylaod_type_names[] = {
    { ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ,                         "Query Jitter" },
    { ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ_MC,                      "Query Jitter and Manufacturer Code" },
    { ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ_MC_IT,                   "Query Jitter, Manufacturer Code and Image Type" },
    { ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ_MC_IT_FV,                "Query Jitter, Manufacturer Code, Image Type and File Version" },
    { 0, NULL }
};

/* Image Upgrade Status */
static const value_string zbee_zcl_ota_image_upgrade_attr_status_names[] = {
    { ZBEE_ZCL_OTA_STATUS_NORMAL,                           "Normal" },
    { ZBEE_ZCL_OTA_STATUS_DOWNLOAD_IN_PROGRESS,             "Download in progress" },
    { ZBEE_ZCL_OTA_STATUS_DOWNLOAD_COMPLETE,                "Download complete" },
    { ZBEE_ZCL_OTA_STATUS_WAITING_TO_UPGRADE,               "Waiting to upgrade" },
    { ZBEE_ZCL_OTA_STATUS_COUNT_DOWN,                       "Count down" },
    { ZBEE_ZCL_OTA_STATUS_WAIT_FOR_MORE,                    "Wait for more" },
    { 0, NULL }
};

/* ZigBee Stack Version */
static const range_string zbee_zcl_ota_zb_stack_ver_names[] = {
    { ZBEE_ZCL_OTA_ZB_STACK_VER_2006,         ZBEE_ZCL_OTA_ZB_STACK_VER_2006,         "ZigBee 2006" },
    { ZBEE_ZCL_OTA_ZB_STACK_VER_2007,         ZBEE_ZCL_OTA_ZB_STACK_VER_2007,         "ZigBee 2007" },
    { ZBEE_ZCL_OTA_ZB_STACK_VER_PRO,          ZBEE_ZCL_OTA_ZB_STACK_VER_PRO,          "ZigBee Pro" },
    { ZBEE_ZCL_OTA_ZB_STACK_VER_IP,           ZBEE_ZCL_OTA_ZB_STACK_VER_IP,           "ZigBee IP" },
    { ZBEE_ZCL_OTA_ZB_STACK_VER_RESERVED_LO,  ZBEE_ZCL_OTA_ZB_STACK_VER_RESERVED_HI,  "Reserved" },
    { 0, 0, NULL },
};

/* Image Type */
static const range_string zbee_zcl_ota_image_type_names[] = {
    {ZBEE_ZCL_OTA_IMG_TYPE_MFR_LOW,         ZBEE_ZCL_OTA_IMG_TYPE_MFR_HIGH,         "Manufacturer Specific" },
    {ZBEE_ZCL_OTA_IMG_TYPE_SECURITY,        ZBEE_ZCL_OTA_IMG_TYPE_SECURITY,         "Security Credential" },
    {ZBEE_ZCL_OTA_IMG_TYPE_CONFIG,          ZBEE_ZCL_OTA_IMG_TYPE_CONFIG,           "Configuration" },
    {ZBEE_ZCL_OTA_IMG_TYPE_LOG,             ZBEE_ZCL_OTA_IMG_TYPE_LOG,              "Log" },
    {ZBEE_ZCL_OTA_IMG_TYPE_UNASSIGNED_LOW,  ZBEE_ZCL_OTA_IMG_TYPE_UNASSIGNED_HIGH,  "Reserved: Unassigned" },
    {ZBEE_ZCL_OTA_IMG_TYPE_WILD_CARD,       ZBEE_ZCL_OTA_IMG_TYPE_WILD_CARD,        "Reserved: Wild Card" },
    { 0, 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_zcl_ota_curr_time
 *  DESCRIPTION
 *    this function decode the current time field
 *  PARAMETERS
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_zcl_ota_curr_time(char *s, uint32_t value)
{
    if (value == ZBEE_ZCL_OTA_TIME_NOW) {
        snprintf(s, ITEM_LABEL_LENGTH, "Now");
    }
    else {
        char *tmp;
        value += EPOCH_DELTA_2000_01_01_00_00_00_UTC;
        tmp = abs_time_secs_to_str(NULL, value, ABSOLUTE_TIME_LOCAL, 1);
        snprintf(s, ITEM_LABEL_LENGTH, "%s", tmp);
        wmem_free(NULL, tmp);
    }

    return;
} /*decode_zcl_ota_curr_time*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_zcl_ota_req_time
 *  DESCRIPTION
 *    this function decode the request time field
 *  PARAMETERS
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_zcl_ota_req_time(char *s, uint32_t value)
{
    if (value == ZBEE_ZCL_OTA_TIME_WAIT) {
        snprintf(s, ITEM_LABEL_LENGTH, "Wrong Value");
    }
    else {
        /* offset from now */
        char *tmp = signed_time_secs_to_str(NULL, value);
        snprintf(s, ITEM_LABEL_LENGTH, "%s from now", tmp);
        wmem_free(NULL, tmp);
    }

    return;
} /*decode_zcl_ota_req_time*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_zcl_ota_upgr_time
 *  DESCRIPTION
 *    this function decode the upgrade time field
 *  PARAMETERS
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_zcl_ota_upgr_time(char *s, uint32_t value)
{
    if (value == ZBEE_ZCL_OTA_TIME_WAIT) {
        snprintf(s, ITEM_LABEL_LENGTH, "Wait for upgrade command");
    }
    else {
        /* offset from now */
        char *tmp = signed_time_secs_to_str(NULL, value);
        snprintf(s, ITEM_LABEL_LENGTH, "%s from now", tmp);
        wmem_free(NULL, tmp);
    }

    return;
} /*decode_zcl_ota_upgr_time*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_zcl_ota_upgr_time_utc
 *  DESCRIPTION
 *    this function decode the upgrade time field when it is UTC time
 *  PARAMETERS
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_zcl_ota_upgr_time_utc(char *s, uint32_t value)
{
    if (value == ZBEE_ZCL_OTA_TIME_WAIT) {
        snprintf(s, ITEM_LABEL_LENGTH, "Wait for upgrade command");
    }
    else {
        char *tmp;
        value += EPOCH_DELTA_2000_01_01_00_00_00_UTC;
        tmp = abs_time_secs_to_str(NULL, value, ABSOLUTE_TIME_LOCAL, 1);
        snprintf(s, ITEM_LABEL_LENGTH, "%s", tmp);
        wmem_free(NULL, tmp);
    }

    return;
} /*decode_zcl_ota_upgr_time_utc*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_zcl_ota_size_in_bytes
 *  DESCRIPTION
 *    this function decodes size in bytes
 *  PARAMETERS
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_zcl_ota_size_in_bytes(char *s, uint32_t value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%d [Bytes]", value);
} /*decode_zcl_ota_size_in_bytes*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_file_version_field
 *  DESCRIPTION
 *      this function is called in order to decode "FileVersion" field,
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_file_version_field(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    static int * const file_version[] = {
        &hf_zbee_zcl_ota_file_version_appl_release,
        &hf_zbee_zcl_ota_file_version_appl_build,
        &hf_zbee_zcl_ota_file_version_stack_release,
        &hf_zbee_zcl_ota_file_version_stack_build,
        NULL
    };

    /* 'File Version' field present, retrieves it */
    /* File version is Little endian. as well as all ZigBee data structures:
       "The endianness used in each data field shall be little endian in order
       to be compliant with general ZigBee messages."
       File version A: 0x10053519 represents application release 1.0 build 05 with stack release 3.5 b19
    */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_ota_file_version, ett_zbee_zcl_ota_file_version, file_version, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_ota_file_version_field*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_field_ctrl_field
 *  DESCRIPTION
 *      this function is called in order to decode "FileVersion" field,
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *      int hf_hdr          - hf_hdr
 *      int ett            - ett subtree index
 *      int* const *fields  - fields an array of pointers to int that lists all the fields of the bitmask
 *  RETURNS
 *      uint8_t             - field ctrl value
 *---------------------------------------------------------------
 */
static uint8_t
dissect_zcl_ota_field_ctrl_field(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, int hf_hdr, int ett, int * const *fields)
{
    uint8_t     field;

    /* Retrieve 'Field Control' field */
    field = tvb_get_uint8(tvb, *offset);
    proto_tree_add_bitmask(tree, tvb, *offset, hf_hdr, ett, fields, ENC_NA);
    *offset += 1;

    return field;
} /*dissect_zcl_ota_field_ctrl_field*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_imagenotify
 *  DESCRIPTION
 *      this function is called in order to decode "ImageNotify",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_imagenotify(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t payload_type;

    /* Retrieve 'Payload type' field */
    payload_type = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_ota_payload_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve 'Query Jitter' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_query_jitter, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Check if there are optional fields */

    if (payload_type >= ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ_MC) {
        /* 'Manufacturer Code' field present, retrieves it */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }

    if (payload_type >= ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ_MC_IT) {
        /* 'Image Type' field present, retrieves it */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }

    if (payload_type >= ZBEE_ZCL_OTA_PAYLOAD_TYPE_QJ_MC_IT_FV) {
        /* 'File Version' field present, retrieves it */
        dissect_zcl_ota_file_version_field(tvb, tree, offset);
    }

} /*dissect_zcl_ota_imagenotify*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_querynextimagereq
 *  DESCRIPTION
 *      this function is called in order to decode "QueryNextImageRequest",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_querynextimagereq(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    static int * const fields[] = {
        &hf_zbee_zcl_ota_query_next_image_req_field_ctrl_hw_ver_present,
        &hf_zbee_zcl_ota_query_next_image_req_field_ctrl_reserved,
        NULL
    };

    uint8_t field_ctrl;

    /* Retrieve 'Field Control' field */
    field_ctrl = dissect_zcl_ota_field_ctrl_field(tvb, tree, offset, hf_zbee_zcl_ota_query_next_image_req_field_ctrl, ett_zbee_zcl_ota_query_next_image_req_field_ctrl, fields);

    /* Retrieve 'Manufacturer Code' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'Image Type' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'File Version' field */
    dissect_zcl_ota_file_version_field(tvb, tree, offset);

    /* Check if there are optional fields */
    if (field_ctrl & ZBEE_ZCL_OTA_QUERY_NEXT_IMAGE_REQ_FIELD_CTRL_HW_VER_PRESENT) {
        /* 'Hardware Version' field present, retrieves it */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_hw_version, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }
} /*dissect_zcl_ota_querynextimagereq*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_querynextimagersp
 *  DESCRIPTION
 *      this function is called in order to decode "QueryNextImageResponse",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_querynextimagersp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t status;

    /* Retrieve 'Status' field */
    status = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_ota_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Check if there are optional fields */
    if (status == ZBEE_ZCL_STAT_SUCCESS) {
        /* Retrieve 'Manufacturer Code' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve 'Image Type' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve 'File Version' field */
        dissect_zcl_ota_file_version_field(tvb, tree, offset);

        /* Retrieve 'Image Size' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_image_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }

} /*dissect_zcl_ota_querynextimagersp*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_imageblockreq
 *  DESCRIPTION
 *      this function is called in order to decode "ImageBlockRequest",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_imageblockreq(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    static int * const fields[] = {
        &hf_zbee_zcl_ota_image_block_req_field_ctrl_ieee_addr_present,
        &hf_zbee_zcl_ota_image_block_req_field_ctrl_min_block_period_present,
        &hf_zbee_zcl_ota_image_block_req_field_ctrl_reserved,
        NULL
    };

    uint8_t field_ctrl;

    /* Retrieve 'Field Control' field */
    field_ctrl = dissect_zcl_ota_field_ctrl_field(tvb, tree, offset, hf_zbee_zcl_ota_image_block_req_field_ctrl, ett_zbee_zcl_ota_image_block_req_field_ctrl, fields);

    /* Retrieve 'Manufacturer Code' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'Image Type' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'File Version' field */
    dissect_zcl_ota_file_version_field(tvb, tree, offset);

    /* Retrieve 'File Offset' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_file_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve 'Maximum Data Size' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_max_data_size, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Check if there are optional fields */
    if (field_ctrl & ZBEE_ZCL_OTA_IMAGE_BLOCK_REQ_FIELD_CTRL_REQUEST_NODE_ADDR_PRESENT) {
        /* 'Request Node Address' field present, retrieve it */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_req_node_addr, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;
    }
    if (field_ctrl & ZBEE_ZCL_OTA_IMAGE_BLOCK_REQ_FIELD_CTRL_MIN_BLOCK_PERIOD_PRESENT) {
        /* 'Minimum Block Period' field present, retrieve it */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_min_block_period, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }
} /*dissect_zcl_ota_imageblockreq*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_imagepagereq
 *  DESCRIPTION
 *      this function is called in order to decode "ImagePageRequest",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_imagepagereq(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    static int * const fields[] = {
        &hf_zbee_zcl_ota_image_page_req_field_ctrl_ieee_addr_present,
        &hf_zbee_zcl_ota_image_page_req_field_ctrl_reserved,
        NULL
    };

    uint8_t field_ctrl;

    /* Retrieve 'Field Control' field */
    field_ctrl = dissect_zcl_ota_field_ctrl_field(tvb, tree, offset, hf_zbee_zcl_ota_image_page_req_field_ctrl, ett_zbee_zcl_ota_image_page_req_field_ctrl, fields);

    /* Retrieve 'Manufacturer Code' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'Image Type' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'File Version' field */
    dissect_zcl_ota_file_version_field(tvb, tree, offset);

    /* Retrieve 'File Offset' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_file_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve 'Maximum Data Size' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_max_data_size, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve 'Page Size' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_page_size, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'Response Spacing' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_rsp_spacing, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Check if there are optional fields */
    if (field_ctrl & ZBEE_ZCL_OTA_IMAGE_PAGE_REQ_FIELD_CTRL_REQUEST_NODE_ADDR_PRESENT) {
        /* 'Request Node Address' field present, retrieves it */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_req_node_addr, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;
    }
} /*dissect_zcl_ota_imagepagereq*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_imageblockrsp
 *  DESCRIPTION
 *      this function is called in order to decode "ImageBlockResponse",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_imageblockrsp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t status;
    uint8_t data_size;

    /* Retrieve 'Status' field */
    status = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_ota_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    if (status == ZBEE_ZCL_STAT_SUCCESS) {
        /* Retrieve 'Manufacturer Code' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve 'Image Type' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve 'File Version' field */
        dissect_zcl_ota_file_version_field(tvb, tree, offset);

        /* Retrieve 'File Offset' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_file_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;

        /* Retrieve 'Data Size' field */
        data_size = tvb_get_uint8(tvb, *offset);
        proto_tree_add_item(tree, hf_zbee_zcl_ota_data_size, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Retrieve 'Image Data' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_image_data, tvb, *offset, data_size, ENC_NA);
        *offset += data_size;
    }
    else if (status == ZBEE_ZCL_STAT_OTA_WAIT_FOR_DATA) {
        /* Retrieve 'Current Time' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_current_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;

        /* Retrieve 'Request Time' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_request_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }
    else {
      /* */
    }

} /*dissect_zcl_ota_imageblockrsp*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_upgradeendreq
 *  DESCRIPTION
 *      this function is called in order to decode "UpgradeEndRequest",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_upgradeendreq(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve 'Status' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve 'Manufacturer Code' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'Image Type' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'File Version' field */
    dissect_zcl_ota_file_version_field(tvb, tree, offset);

} /*dissect_zcl_ota_upgradeendreq*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_upgradeendrsp
 *  DESCRIPTION
 *      this function is called in order to decode "UpgradeEndResponse",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_upgradeendrsp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint32_t current_time = 0;

    /* Retrieve 'Manufacturer Code' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'Image Type' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'File Version' field */
    dissect_zcl_ota_file_version_field(tvb, tree, offset);

    /* Retrieve 'Current Time' field */
    proto_tree_add_item_ret_uint(tree, hf_zbee_zcl_ota_current_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &current_time);
    *offset += 4;

    /* Retrieve 'Upgrade Time' field */
    if (current_time == 0)
    {
        /* Upgrade Time is offset time from now */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_upgrade_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }
    else
    {
        /* Upgrade Time is UTC time */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_upgrade_time_utc, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }

} /*dissect_zcl_ota_upgradeendrsp*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_queryspecfilereq
 *  DESCRIPTION
 *      this function is called in order to decode "QuerySpecificFileRequest",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_queryspecfilereq(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* 'Request Node Address' field present, retrieves it */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_req_node_addr, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;

    /* Retrieve 'Manufacturer Code' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'Image Type' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'File Version' field */
    dissect_zcl_ota_file_version_field(tvb, tree, offset);

    /* Retrieve 'ZigBee Stack Version' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_zb_stack_ver, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_ota_queryspecfilereq*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_queryspecfilersp
 *  DESCRIPTION
 *      this function is called in order to decode "QuerySpecificFileResponse",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_queryspecfilersp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t status;

    /* Retrieve 'Status' field */
    status = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_ota_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    if (status == ZBEE_ZCL_STAT_SUCCESS) {
        /* Retrieve 'Manufacturer Code' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve 'Image Type' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Retrieve 'File Version' field */
        dissect_zcl_ota_file_version_field(tvb, tree, offset);

        /* Retrieve 'Image Size' field */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_image_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }

} /*dissect_zcl_ota_queryspecfilersp*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch ( attr_id )
    {
        case ZBEE_ZCL_ATTR_ID_OTA_CURRENT_FILE_VERSION:
        case ZBEE_ZCL_ATTR_ID_OTA_DOWNLOADED_FILE_VERSION:
            dissect_zcl_ota_file_version_field(tvb, tree, offset);
            break;

        case ZBEE_ZCL_ATTR_ID_OTA_CURRENT_ZB_STACK_VERSION:
        case ZBEE_ZCL_ATTR_ID_OTA_DOWNLOADED_ZB_STACK_VERSION:
            proto_tree_add_item(tree, hf_zbee_zcl_ota_zb_stack_ver, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_OTA_IMAGE_UPGRADE_STATUS:
            proto_tree_add_item(tree, hf_zbee_zcl_ota_image_upgrade_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_OTA_MANUFACTURER_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_OTA_IMAGE_TYPE_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_OTA_MIN_BLOCK_REQ_DELAY:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }
} /*dissect_zcl_ota_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_ota
 *  DESCRIPTION
 *      ZigBee ZCL OTA cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      void *data          - pointer to ZCL packet structure.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_ota(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /* Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_ota_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_ota, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_OTA_QUERY_NEXT_IMAGE_REQ:
                    dissect_zcl_ota_querynextimagereq(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_OTA_IMAGE_BLOCK_REQ:
                    dissect_zcl_ota_imageblockreq(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_OTA_IMAGE_PAGE_REQ:
                    dissect_zcl_ota_imagepagereq(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_OTA_UPGRADE_END_REQ:
                    dissect_zcl_ota_upgradeendreq(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_OTA_QUERY_SPEC_FILE_REQ:
                    dissect_zcl_ota_queryspecfilereq(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_ota_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_ota, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_OTA_IMAGE_NOTIFY:
                    dissect_zcl_ota_imagenotify(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_OTA_QUERY_NEXT_IMAGE_RSP:
                    dissect_zcl_ota_querynextimagersp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_OTA_IMAGE_BLOCK_RSP:
                    dissect_zcl_ota_imageblockrsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_OTA_UPGRADE_END_RSP:
                    dissect_zcl_ota_upgradeendrsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_OTA_QUERY_SPEC_FILE_RSP:
                    dissect_zcl_ota_queryspecfilersp(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_ota*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_ota
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void proto_register_zbee_zcl_ota(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_ota_attr_id,
            { "Attribute", "zbee_zcl_general.ota.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_ota_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_srv_tx_cmd_id,
            { "Command", "zbee_zcl_general.ota.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ota_srv_tx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_srv_rx_cmd_id,
            { "Command", "zbee_zcl_general.ota.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ota_srv_rx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_upgrade_status,
            { "Image Upgrade Status", "zbee_zcl_general.ota.status_attr", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ota_image_upgrade_attr_status_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_zb_stack_ver,
            { "ZigBee Stack Version", "zbee_zcl_general.ota.zb_stack.ver", FT_UINT16, BASE_HEX | BASE_RANGE_STRING,
            RVALS(zbee_zcl_ota_zb_stack_ver_names), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_payload_type,
            { "Payload Type", "zbee_zcl_general.ota.payload.type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ota_paylaod_type_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_query_jitter,
            { "Query Jitter", "zbee_zcl_general.ota.query_jitter", FT_UINT8, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_seconds),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_manufacturer_code,
            { "Manufacturer Code", "zbee_zcl_general.ota.manufacturer_code", FT_UINT16, BASE_HEX, VALS(zbee_mfr_code_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_type,
            { "Image Type", "zbee_zcl_general.ota.image.type", FT_UINT16, BASE_HEX | BASE_RANGE_STRING,
            RVALS(zbee_zcl_ota_image_type_names), 0x0, NULL, HFILL } },

/* Begin FileVersion fields */
        { &hf_zbee_zcl_ota_file_version,
            { "File Version", "zbee_zcl_general.ota.file.version", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_file_version_appl_release,
            { "Application Release", "zbee_zcl_general.ota.file.version.appl.release", FT_UINT32, BASE_DEC, NULL,
            ZBEE_ZCL_OTA_FILE_VERS_APPL_RELEASE, NULL, HFILL } },

        { &hf_zbee_zcl_ota_file_version_appl_build,
            { "Application Build", "zbee_zcl_general.ota.file.version.appl.build", FT_UINT32, BASE_DEC, NULL,
            ZBEE_ZCL_OTA_FILE_VERS_APPL_BUILD, NULL, HFILL } },

        { &hf_zbee_zcl_ota_file_version_stack_release,
            { "Stack Release", "zbee_zcl_general.ota.file.version.stack.release", FT_UINT32, BASE_DEC, NULL,
            ZBEE_ZCL_OTA_FILE_VERS_STACK_RELEASE, NULL, HFILL } },

        { &hf_zbee_zcl_ota_file_version_stack_build,
            { "Stack Build", "zbee_zcl_general.ota.file.version.stack.build", FT_UINT32, BASE_DEC, NULL,
            ZBEE_ZCL_OTA_FILE_VERS_STACK_BUILD, NULL, HFILL } },
/* End FileVersion fields */

/* Begin FieldControl fields Query Next Image Request */
        { &hf_zbee_zcl_ota_query_next_image_req_field_ctrl,
            { "Field Control", "zbee_zcl_general.ota.query_next_image_req.field_ctrl",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_query_next_image_req_field_ctrl_hw_ver_present,
            { "Hardware Version", "zbee_zcl_general.ota.query_next_image_req.field_ctrl.hw_ver_present",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), ZBEE_ZCL_OTA_QUERY_NEXT_IMAGE_REQ_FIELD_CTRL_HW_VER_PRESENT, NULL, HFILL } },

        { &hf_zbee_zcl_ota_query_next_image_req_field_ctrl_reserved,
            { "Reserved", "zbee_zcl_general.ota.query_next_image_req.field_ctrl.reserved", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_OTA_QUERY_NEXT_IMAGE_REQ_FIELD_CTRL_RESERVED, NULL, HFILL } },
/* End FieldControl fields Query Next Image Request */

/* Begin FieldControl fields Image Block Request */
        { &hf_zbee_zcl_ota_image_block_req_field_ctrl,
            { "Field Control", "zbee_zcl_general.ota.image_block_req.field_ctrl",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_block_req_field_ctrl_ieee_addr_present,
            { "Request Node Address", "zbee_zcl_general.ota.image_block_req.field_ctrl.request_node_addr_present",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), ZBEE_ZCL_OTA_IMAGE_BLOCK_REQ_FIELD_CTRL_REQUEST_NODE_ADDR_PRESENT, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_block_req_field_ctrl_min_block_period_present,
            { "Minimum Block Period", "zbee_zcl_general.ota.image_block_req.field_ctrl.min_block_period",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), ZBEE_ZCL_OTA_IMAGE_BLOCK_REQ_FIELD_CTRL_MIN_BLOCK_PERIOD_PRESENT, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_block_req_field_ctrl_reserved,
            { "Reserved", "zbee_zcl_general.ota.query_next_image_req.field_ctrl.reserved", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_OTA_IMAGE_BLOCK_REQ_FIELD_CTRL_RESERVED, NULL, HFILL } },
/* End FieldControl fields Image Block Request */

/* Begin FieldControl fields Image Page Request */
        { &hf_zbee_zcl_ota_image_page_req_field_ctrl,
            { "Field Control", "zbee_zcl_general.ota.image_page_req.field_ctrl",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_page_req_field_ctrl_ieee_addr_present,
            { "Request Node Address", "zbee_zcl_general.ota.query_next_image_req.field_ctrl.request_node_addr_present",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), ZBEE_ZCL_OTA_IMAGE_PAGE_REQ_FIELD_CTRL_REQUEST_NODE_ADDR_PRESENT, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_page_req_field_ctrl_reserved,
            { "Reserved", "zbee_zcl_general.ota.image_page_req.field_ctrl.reserved", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_OTA_IMAGE_PAGE_REQ_FIELD_CTRL_RESERVED, NULL, HFILL } },
/* End FieldControl fields Image Page Request */

        { &hf_zbee_zcl_ota_hw_version,
            { "Hardware Version", "zbee_zcl_general.ota.hw_ver", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_status,
            { "Status", "zbee_zcl_general.ota.status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_status_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_size,
            { "Image Size", "zbee_zcl_general.ota.image.size", FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_zcl_ota_size_in_bytes),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_file_offset,
            { "File Offset", "zbee_zcl_general.ota.file.offset", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_max_data_size,
            { "Max Data Size", "zbee_zcl_general.ota.max_data_size", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_min_block_period,
            { "Minimum Block Period", "zbee_zcl_general.ota.min_block_period", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_req_node_addr,
            { "Ieee Address", "zbee_zcl_general.ota.ieee_addr", FT_UINT64, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_page_size,
            { "Page Size", "zbee_zcl_general.ota.page.size", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_ota_size_in_bytes),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_rsp_spacing,
            { "Response Spacing", "zbee_zcl_general.ota.rsp_spacing", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_current_time,
            { "Current Time", "zbee_zcl_general.ota.current_time", FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_zcl_ota_curr_time),
            0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ota_request_time,
            { "Request Time", "zbee_zcl_general.ota.request_time", FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_zcl_ota_req_time),
            0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ota_upgrade_time,
            { "Upgrade Time", "zbee_zcl_general.ota.upgrade_time", FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_zcl_ota_upgr_time),
            0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ota_upgrade_time_utc,
            { "Upgrade Time", "zbee_zcl_general.ota.upgrade_time_utc", FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_zcl_ota_upgr_time_utc),
            0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ota_data_size,
            { "Data Size", "zbee_zcl_general.ota.data_size", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_data,
            { "Image Data", "zbee_zcl_general.ota.image.data", FT_BYTES, SEP_COLON, NULL,
            0x00, NULL, HFILL } }
   };

    /* ZCL OTA subtrees */
    int *ett[] = {
        &ett_zbee_zcl_ota,
        &ett_zbee_zcl_ota_query_next_image_req_field_ctrl,
        &ett_zbee_zcl_ota_image_block_req_field_ctrl,
        &ett_zbee_zcl_ota_image_page_req_field_ctrl,
        &ett_zbee_zcl_ota_file_version
    };

    /* Register ZigBee ZCL Ota protocol with Wireshark. */
    proto_zbee_zcl_ota = proto_register_protocol("ZigBee ZCL OTA", "ZCL OTA", ZBEE_PROTOABBREV_ZCL_OTA);
    proto_register_field_array(proto_zbee_zcl_ota, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL OTA dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_OTA, dissect_zbee_zcl_ota, proto_zbee_zcl_ota);

} /* proto_register_zbee_zcl_ota */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_ota
 *  DESCRIPTION
 *      Registers the zigbee ZCL OTA cluster dissector with Wireshark.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_zbee_zcl_ota(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_OTA,
                            proto_zbee_zcl_ota,
                            ett_zbee_zcl_ota,
                            ZBEE_ZCL_CID_OTA_UPGRADE,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_ota_attr_id,
                            hf_zbee_zcl_ota_attr_id,
                            hf_zbee_zcl_ota_srv_rx_cmd_id,
                            hf_zbee_zcl_ota_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_ota_attr_data
                         );

} /*proto_reg_handoff_zbee_zcl_ota*/

/* ########################################################################## */
/* #### (0x001A) POWER PROFILE CLUSTER ###################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_PWR_PROF_NUM_GENERIC_ETT         4
#define ZBEE_ZCL_PWR_PROF_NUM_PWR_PROF_ETT        5
#define ZBEE_ZCL_PWR_PROF_NUM_EN_PHS_ETT          16
#define ZBEE_ZCL_PWR_PROF_NUM_ETT                 (ZBEE_ZCL_PWR_PROF_NUM_GENERIC_ETT +  \
                                                   ZBEE_ZCL_PWR_PROF_NUM_PWR_PROF_ETT + \
                                                   ZBEE_ZCL_PWR_PROF_NUM_EN_PHS_ETT)

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_PWR_PROF_TOT_PROF_NUM              0x0000  /* Total Profile Number */
#define ZBEE_ZCL_ATTR_ID_PWR_PROF_MULTIPLE_SCHED            0x0001  /* Multiple Schedule */
#define ZBEE_ZCL_ATTR_ID_PWR_PROF_ENERGY_FORMAT             0x0002  /* Energy Formatting */
#define ZBEE_ZCL_ATTR_ID_PWR_PROF_ENERGY_REMOTE             0x0003  /* Energy Remote */
#define ZBEE_ZCL_ATTR_ID_PWR_PROF_SCHED_MODE                0x0004  /* Schedule Mode */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_REQ                           0x00  /* Power Profile Request */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_STATE_REQ                     0x01  /* Power Profile State Request */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE_RSP                 0x02  /* Get Power Profile Price Response */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_GET_OVERALL_SCHED_PRICE_RSP            0x03  /* Get Overall Schedule Price Response */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_NOTIF              0x04  /* Energy Phases Schedule Notification */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_RSP                0x05  /* Energy Phases Schedule Response */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_SCHED_CONSTRS_REQ             0x06  /* Power Profile Schedule Constraints Request */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_STATE_REQ          0x07  /* Energy Phases Schedule State Request */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE_EXT_RSP             0x08  /* Get Power Profile Price Extended Response */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_NOTIF                         0x00  /* Power Profile Notification */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_RSP                           0x01  /* Power Profile Response */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_STATE_RSP                     0x02  /* Power Profile State Response */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE                     0x03  /* Get Power Profile Price */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_STATE_NOTIF                   0x04  /* Power Profile State Notification */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_GET_OVERALL_SCHED_PRICE                0x05  /* Get Overall Schedule Price */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_REQ                0x06  /* Energy Phases Schedule Request */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_STATE_RSP          0x07  /* Energy Phases Schedule State Response */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_STATE_NOITIF       0x08  /* Energy Phases Schedule State Notification */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_SCHED_CONSTRS_NOTIF           0x09  /* Power Profile Schedule Constraints Notification */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_SCHED_CONSTRS_RSP             0x0A  /* Power Profile Schedule Constraints Response */
#define ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE_EXT                 0x0B  /* Get Power Profile Price Extended */

/* Power Profile StateId */
#define ZBEE_ZCL_PWR_PROF_STATE_ID_PWR_PROF_IDLE                        0x00  /* Power Profile Idle */
#define ZBEE_ZCL_PWR_PROF_STATE_ID_PWR_PROF_PROGRAMMED                  0x01  /* Power Profile Programmed */
#define ZBEE_ZCL_PWR_PROF_STATE_ID_EN_PH_RUNNING                        0x03  /* Energy Phase Running */
#define ZBEE_ZCL_PWR_PROF_STATE_ID_EN_PH_PAUSE                          0x04  /* Energy Phase Pause */
#define ZBEE_ZCL_PWR_PROF_STATE_ID_EN_PH_WAITING_TO_START               0x05  /* Energy Phase Waiting to Start */
#define ZBEE_ZCL_PWR_PROF_STATE_ID_EN_PH_WAITING_PAUSED                 0x06  /* Energy Phase Waiting Pause */
#define ZBEE_ZCL_PWR_PROF_STATE_ID_PWR_PROF_ENDED                       0x07  /* Power Profile Ended */

/* Energy Formatting bitmask field list */
#define ZBEE_ZCL_OPT_PWRPROF_NUM_R_DIGIT                                0x07  /* bits 0..2 */
#define ZBEE_ZCL_OPT_PWRPROF_NUM_L_DIGIT                                0x78  /* bits 3..6 */
#define ZBEE_ZCL_OPT_PWRPROF_NO_LEADING_ZERO                            0x80  /* bit     7 */

/* Schedule Mode bitmask field list */
#define ZBEE_ZCL_OPT_PWRPROF_SCHED_CHEAPEST                             0x01  /* bit     0 */
#define ZBEE_ZCL_OPT_PWRPROF_SCHED_GREENEST                             0x02  /* bit     1 */
#define ZBEE_ZCL_OPT_PWRPROF_SCHED_RESERVED                             0xfc  /* bits 2..7 */

/* Options bitmask field list */
#define ZBEE_ZCL_OPT_PWRPROF_STIME_PRESENT                              0x01  /* bit     0 */
#define ZBEE_ZCL_OPT_PWRPROF_RESERVED                                   0xfe  /* bits 1..7 */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_pwr_prof(void);
void proto_reg_handoff_zbee_zcl_pwr_prof(void);

/* Command Dissector Helpers */
static void dissect_zcl_pwr_prof_pwrprofreq                 (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_pwr_prof_getpwrprofpricersp         (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_pwr_prof_getoverallschedpricersp    (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_pwr_prof_enphsschednotif            (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

static void dissect_zcl_energy_phase                        (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_pwr_prof_pwrprofnotif               (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_power_profile                       (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_pwr_prof_pwrprofstatersp            (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_pwr_prof_pwrprofschedcontrsnotif    (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_pwr_prof_pwrprofpriceext            (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

static void dissect_zcl_pwr_prof_attr_data  (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */
static void decode_power_profile_id     (char *s, uint8_t id);
static void decode_price_in_cents       (char *s, uint32_t value);
static void decode_power_in_watt        (char *s, uint16_t value);
static void decode_energy               (char *s, uint16_t value);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_pwr_prof;

static int hf_zbee_zcl_pwr_prof_attr_id;
static int hf_zbee_zcl_pwr_prof_tot_prof_num;
static int hf_zbee_zcl_pwr_prof_multiple_sched;
static int hf_zbee_zcl_pwr_prof_energy_format;
static int hf_zbee_zcl_pwr_prof_energy_format_rdigit;
static int hf_zbee_zcl_pwr_prof_energy_format_ldigit;
static int hf_zbee_zcl_pwr_prof_energy_format_noleadingzero;
static int hf_zbee_zcl_pwr_prof_energy_remote;
static int hf_zbee_zcl_pwr_prof_sched_mode;
static int hf_zbee_zcl_pwr_prof_sched_mode_cheapest;
static int hf_zbee_zcl_pwr_prof_sched_mode_greenest;
static int hf_zbee_zcl_pwr_prof_sched_mode_reserved;
static int hf_zbee_zcl_pwr_prof_srv_tx_cmd_id;
static int hf_zbee_zcl_pwr_prof_srv_rx_cmd_id;
static int hf_zbee_zcl_pwr_prof_pwr_prof_id;
static int hf_zbee_zcl_pwr_prof_currency;
static int hf_zbee_zcl_pwr_prof_price;
static int hf_zbee_zcl_pwr_prof_price_trailing_digit;
static int hf_zbee_zcl_pwr_prof_num_of_sched_phases;
static int hf_zbee_zcl_pwr_prof_scheduled_time;
static int hf_zbee_zcl_pwr_prof_pwr_prof_count;
static int hf_zbee_zcl_pwr_prof_num_of_trans_phases;
static int hf_zbee_zcl_pwr_prof_energy_phase_id;
static int hf_zbee_zcl_pwr_prof_macro_phase_id;
static int hf_zbee_zcl_pwr_prof_expect_duration;
static int hf_zbee_zcl_pwr_prof_peak_power;
static int hf_zbee_zcl_pwr_prof_energy;
static int hf_zbee_zcl_pwr_prof_max_active_delay;
static int hf_zbee_zcl_pwr_prof_pwr_prof_rem_ctrl;
static int hf_zbee_zcl_pwr_prof_pwr_prof_state;
static int hf_zbee_zcl_pwr_prof_start_after;
static int hf_zbee_zcl_pwr_prof_stop_before;
static int hf_zbee_zcl_pwr_prof_options;
static int hf_zbee_zcl_pwr_prof_options_01;
static int hf_zbee_zcl_pwr_prof_options_res;
static int hf_zbee_zcl_pwr_prof_pwr_prof_stime;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_pwr_prof;
static int ett_zbee_zcl_pwr_prof_options;
static int ett_zbee_zcl_pwr_prof_en_format;
static int ett_zbee_zcl_pwr_prof_sched_mode;
static int ett_zbee_zcl_pwr_prof_pwrprofiles[ZBEE_ZCL_PWR_PROF_NUM_PWR_PROF_ETT];
static int ett_zbee_zcl_pwr_prof_enphases[ZBEE_ZCL_PWR_PROF_NUM_EN_PHS_ETT];

/* Attributes */
static const value_string zbee_zcl_pwr_prof_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_PWR_PROF_TOT_PROF_NUM,                    "Total Profile Number" },
    { ZBEE_ZCL_ATTR_ID_PWR_PROF_MULTIPLE_SCHED,                  "Multiple Scheduling" },
    { ZBEE_ZCL_ATTR_ID_PWR_PROF_ENERGY_FORMAT,                   "Energy Formatting" },
    { ZBEE_ZCL_ATTR_ID_PWR_PROF_ENERGY_REMOTE,                   "Energy Remote" },
    { ZBEE_ZCL_ATTR_ID_PWR_PROF_SCHED_MODE,                      "Schedule Mode" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_pwr_prof_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_REQ,                     "Power Profile Request" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_STATE_REQ,               "Power Profile State Request" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE_RSP,           "Get Power Profile Price Response" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_GET_OVERALL_SCHED_PRICE_RSP,      "Get Overall Schedule Price Response" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_NOTIF,        "Energy Phases Schedule Notification" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_RSP,          "Energy Phases Schedule Response" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_SCHED_CONSTRS_REQ,       "Power Profile Schedule Constraints Request" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_STATE_REQ,    "Energy Phases Schedule State Request" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE_EXT_RSP,       "Get Power Profile Price Extended Response" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_pwr_prof_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_NOTIF,                   "Power Profile Notification" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_RSP,                     "Power Profile Response" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_STATE_RSP,               "Power Profile State Response" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE,               "Get Power Profile Price" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_STATE_NOTIF,             "Power Profile State Notification" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_GET_OVERALL_SCHED_PRICE,          "Get Overall Schedule Price" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_REQ,          "Energy Phases Schedule Request" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_STATE_RSP,    "Energy Phases Schedule State Response" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_STATE_NOITIF, "Energy Phases Schedule State Notification" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_SCHED_CONSTRS_NOTIF,     "Power Profile Schedule Constraints Notification" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_SCHED_CONSTRS_RSP,       "Power Profile Schedule Constraints Response" },
    { ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE_EXT,           "Get Power Profile Price Extended" },
    { 0, NULL }
};

/* Currencies (values defined by ISO 4217) */
static const value_string zbee_zcl_currecy_names[] = {
    { 0x03D2,                                                    "EUR" },
    { 0x033A,                                                    "GBP" },
    { 0x0348,                                                    "USD" },
    { 0, NULL }
};

/* Power Profile State */
static const value_string zbee_zcl_pwr_prof_state_names[] = {
    { ZBEE_ZCL_PWR_PROF_STATE_ID_PWR_PROF_IDLE,                  "Power Profile Idle" },
    { ZBEE_ZCL_PWR_PROF_STATE_ID_PWR_PROF_PROGRAMMED,            "Power Profile Programmed" },
    { ZBEE_ZCL_PWR_PROF_STATE_ID_EN_PH_RUNNING,                  "Energy Phase Running" },
    { ZBEE_ZCL_PWR_PROF_STATE_ID_EN_PH_PAUSE,                    "Energy Phase Pause" },
    { ZBEE_ZCL_PWR_PROF_STATE_ID_EN_PH_WAITING_TO_START,         "Energy Phase Waiting to Start" },
    { ZBEE_ZCL_PWR_PROF_STATE_ID_EN_PH_WAITING_PAUSED,           "Energy Phase Waiting Paused" },
    { ZBEE_ZCL_PWR_PROF_STATE_ID_PWR_PROF_ENDED,                 "Power Profile Ended" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_pwr_prof
 *  DESCRIPTION
 *      ZigBee ZCL Power Profile cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      void *data          - pointer to ZCL packet structure.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_pwr_prof (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_pwr_prof_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_pwr_prof, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_REQ:
                case ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_SCHED_CONSTRS_REQ:
                case ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_STATE_REQ:
                    dissect_zcl_pwr_prof_pwrprofreq(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_STATE_REQ:
                    /* No payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE_RSP:
                case ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE_EXT_RSP:
                    dissect_zcl_pwr_prof_getpwrprofpricersp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PWR_PROF_GET_OVERALL_SCHED_PRICE_RSP:
                    dissect_zcl_pwr_prof_getoverallschedpricersp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_NOTIF:
                case ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_RSP:
                    dissect_zcl_pwr_prof_enphsschednotif(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_pwr_prof_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_pwr_prof, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_NOTIF:
                case ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_RSP:
                    dissect_zcl_pwr_prof_pwrprofnotif(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_STATE_RSP:
                case ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_STATE_NOTIF:
                    dissect_zcl_pwr_prof_pwrprofstatersp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PWR_PROF_GET_OVERALL_SCHED_PRICE:
                    /* no payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_STATE_RSP:
                case ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_STATE_NOITIF:
                    dissect_zcl_pwr_prof_enphsschednotif(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE:
                case ZBEE_ZCL_CMD_ID_PWR_PROF_ENERGY_PHASES_SCHED_REQ:
                    dissect_zcl_pwr_prof_pwrprofreq(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_SCHED_CONSTRS_NOTIF:
                case ZBEE_ZCL_CMD_ID_PWR_PROF_PWR_PROF_SCHED_CONSTRS_RSP:
                    dissect_zcl_pwr_prof_pwrprofschedcontrsnotif(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PWR_PROF_GET_PWR_PROF_PRICE_EXT:
                    dissect_zcl_pwr_prof_pwrprofpriceext(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_pwr_prof*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_pwrprofreq
 *  DESCRIPTION
 *      this function is called in order to decode "PowerProfileRequest",
 *      "PowerProfileScheduleConstraintsRequest", "EnergyPhasesScheduleStateRequest",
 *      "GetPowerProfilePrice" and "EnergyPhasesScheduleRequest" payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_pwrprofreq(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Power Profile Id" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

} /*dissect_zcl_pwr_prof_pwrprofreq*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_getpwrprofpricersp
 *  DESCRIPTION
 *      this function is called in order to decode "GetPowerProfilePriceResponse"
 *      and "PowerProfilePriceExtendedResponse" payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_getpwrprofpricersp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Power Profile Id" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Currency" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_currency, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Price" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_price, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve "Price Trailing Digit" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_price_trailing_digit, tvb, *offset, 1, ENC_NA);
    *offset += 1;

} /*dissect_zcl_pwr_prof_getpwrprofpricersp*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_getoverallschedpricersp
 *  DESCRIPTION
 *      this function is called in order to decode "GetOverallSchedulePriceResponse"
 *      payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_getoverallschedpricersp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Currency" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_currency, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Price" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_price, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve "Price Trailing Digit" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_price_trailing_digit, tvb, *offset, 1, ENC_NA);
    *offset += 1;

} /*dissect_zcl_pwr_prof_getoverallschedpricersp*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_sched_energy_phase
 *  DESCRIPTION
 *      this function is called in order to decode "ScheduledEnergyPhases"
 *      element.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_sched_energy_phase(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Energy Phase ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_energy_phase_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Scheduled Time */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_scheduled_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_sched_energy_phase*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_enphsschednotif
 *  DESCRIPTION
 *      this function is called in order to decode "EnergyPhasesScheduleNotification"
 *      and "EnergyPhasesScheduleResoponse" payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_enphsschednotif(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree  *sub_tree = NULL;

    unsigned i;
    uint8_t num_of_sched_phases;

    /* Retrieve "Power Profile Id" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Number of Scheduled Phases" field */
    num_of_sched_phases = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_num_of_sched_phases, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Scheduled Energy Phases decoding */
    for (i=0 ; (i<num_of_sched_phases && i < ZBEE_ZCL_PWR_PROF_NUM_EN_PHS_ETT); i++) {
        /* Create subtree */
        sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 1,
                        ett_zbee_zcl_pwr_prof_enphases[i], NULL, "Energy Phase #%u", i);

        dissect_zcl_sched_energy_phase(tvb, sub_tree, offset);
    }
} /*dissect_zcl_pwr_prof_enphsschednotif*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_energy_phase
 *  DESCRIPTION
 *      this function is called in order to decode "EnergyPhases"
 *      element.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_energy_phase(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_energy_phase_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_macro_phase_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_expect_duration, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_peak_power, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_energy, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_max_active_delay, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_energy_phase*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_pwrprofnotif
 *  DESCRIPTION
 *      this function is called in order to decode "PowerProfileNotification"
 *      and "PowerProfileResponse" payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_pwrprofnotif(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree  *sub_tree = NULL;

    unsigned i;
    uint8_t total_profile_number;
    uint8_t num_of_transferred_phases;

    /* Retrieve "Total Profile Number" field */
    total_profile_number = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_tot_prof_num, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    if ( total_profile_number != 0 ) {
        /* Retrieve "Power Profile Id" field */
        proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_id, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Retrieve "Number of Transferred Phases" field */
        num_of_transferred_phases = tvb_get_uint8(tvb, *offset);
        proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_num_of_trans_phases, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Energy Phases decoding */
        for ( i=0 ; (i<num_of_transferred_phases && i < ZBEE_ZCL_PWR_PROF_NUM_EN_PHS_ETT); i++) {
            /* Create subtree */
            sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 1,
                        ett_zbee_zcl_pwr_prof_enphases[i], NULL, "Energy Phase #%u", i);

            dissect_zcl_energy_phase(tvb, sub_tree, offset);
        }
    }
}


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_power_profile
 *  DESCRIPTION
 *      this function is called in order to decode "PowerProfile"
 *      element.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_power_profile(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Power Profile Id */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Energy Phase Id */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_energy_phase_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Power Profile Remote Control */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_rem_ctrl, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Power Profile State */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_state, tvb, *offset, 1, ENC_NA);
    *offset += 1;

} /*dissect_zcl_power_profile*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_pwrprofstatersp
 *  DESCRIPTION
 *      this function is called in order to decode "PowerProfileStateResponse"
 *      and "PowerProfileStateNotification" payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_pwrprofstatersp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree  *sub_tree = NULL;

    unsigned i;
    uint8_t power_profile_count;

    /* Retrieve "Total Profile Number" field */
    power_profile_count = MIN(tvb_get_uint8(tvb, *offset), ZBEE_ZCL_PWR_PROF_NUM_PWR_PROF_ETT);
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_count, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Energy Phases decoding */
    for (i=0 ; i<power_profile_count ; i++) {
        /* Create subtree */
        sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 1,
                    ett_zbee_zcl_pwr_prof_pwrprofiles[i], NULL, "Power Profile #%u", i);

        dissect_zcl_power_profile(tvb, sub_tree, offset);
    }
} /*dissect_zcl_pwr_prof_pwrprofstatersp*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_pwrprofschedcontrsnotif
 *  DESCRIPTION
 *      this function is called in order to decode "PowerProfileScheduleConstraintsNotification"
 *      and "PowerProfileScheduleConstraintsResponse" payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_pwrprofschedcontrsnotif(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Power Profile Id" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Start After" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_start_after, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Stop Before" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_stop_before, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_pwr_prof_pwrprofschedcontrsnotif*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_pwrprofpriceext
 *  DESCRIPTION
 *      this function is called in order to decode "GetPowerProfilePriceExtended"
 *      and "PowerProfileScheduleConstraintsResponse" payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_pwrprofpriceext(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    static int * const options[] = {
        &hf_zbee_zcl_pwr_prof_options_01,
        &hf_zbee_zcl_pwr_prof_options_res,
        NULL
    };

    /* Retrieve "Options" field */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_pwr_prof_options, ett_zbee_zcl_pwr_prof_options, options, ENC_NA);
    *offset += 1;

    /* Retrieve "Power Profile Id" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Power Profile Start Time" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_stime, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_pwr_prof_pwrprofpriceext*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    static int * const format_fields[] = {
        &hf_zbee_zcl_pwr_prof_energy_format_rdigit,
        &hf_zbee_zcl_pwr_prof_energy_format_ldigit,
        &hf_zbee_zcl_pwr_prof_energy_format_noleadingzero,
        NULL
    };
    static int * const modes[] = {
        &hf_zbee_zcl_pwr_prof_sched_mode_cheapest,
        &hf_zbee_zcl_pwr_prof_sched_mode_greenest,
        &hf_zbee_zcl_pwr_prof_sched_mode_reserved,
        NULL
    };

    /* Dissect attribute data type and data */
    switch ( attr_id )
    {
        case ZBEE_ZCL_ATTR_ID_PWR_PROF_TOT_PROF_NUM:
            proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_tot_prof_num, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_PWR_PROF_MULTIPLE_SCHED:
            proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_multiple_sched, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_PWR_PROF_ENERGY_FORMAT:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_pwr_prof_energy_format, ett_zbee_zcl_pwr_prof_en_format, format_fields, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_PWR_PROF_ENERGY_REMOTE:
            proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_energy_remote, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_PWR_PROF_SCHED_MODE:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_pwr_prof_sched_mode, ett_zbee_zcl_pwr_prof_sched_mode, modes, ENC_NA);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
        break;
    }
} /*dissect_zcl_pwr_prof_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_power_profile_id
 *  DESCRIPTION
 *      this function decodes the power profile custom type
 *  PARAMETERS
 *      unsigned *s        - string to display
 *      uint16_t value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_power_profile_id(char *s, uint8_t id)
{
    if (id == 0) {
        snprintf(s, ITEM_LABEL_LENGTH, "%d (All)", id);
    }
    else {
        snprintf(s, ITEM_LABEL_LENGTH, "%d", id);
    }
} /*decode_power_profile_id*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_price_in_cents
 *  DESCRIPTION
 *      this function decodes price type variable
 *  PARAMETERS
 *      unsigned *s        - string to display
 *      uint16_t value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_price_in_cents(char *s, uint32_t value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%d cents", value);
} /* decode_price_in_cents */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_power_in_watt
 *  DESCRIPTION
 *      this function decodes watt power type variable
 *  PARAMETERS
 *      unsigned *s        - string to display
 *      uint16_t value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_power_in_watt(char *s, uint16_t value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%d Watt", value);
} /* decode_power_in_watt */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_energy
 *  DESCRIPTION
 *      this function decodes energy type variable
 *  PARAMETERS
 *      unsigned *s        - string to display
 *      uint16_t value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_energy(char *s, uint16_t value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%d Watt per hours", value);
} /* decode_energy */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      func_decode_delayinminute
 *  DESCRIPTION
 *    this function decodes minute delay type variable
 *  PARAMETERS
 *      unsigned *s        - string to display
 *      uint16_t value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
func_decode_delayinminute(char *s, uint16_t value)
{
    if (value == 0) {
        snprintf(s, ITEM_LABEL_LENGTH, "%d minutes (Not permitted)", value);
    }
    else {
        snprintf(s, ITEM_LABEL_LENGTH, "%d minutes", value);
    }

} /* func_decode_delayinminute*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_pwr_prof
 *  DESCRIPTION
 *      ZigBee ZCL PowerProfile cluster protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_pwr_prof(void)
{
    unsigned i, j;

    static hf_register_info hf[] = {

        { &hf_zbee_zcl_pwr_prof_tot_prof_num,
            { "Total Profile Number", "zbee_zcl_general.pwrprof.attr.totprofnum", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_multiple_sched,
            { "Multiple Scheduling", "zbee_zcl_general.pwrprof.attr.multiplesched", FT_BOOLEAN, BASE_NONE,
            TFS(&tfs_supported_not_supported), 0x0, NULL, HFILL } },

/* Begin EnergyFormatting fields */
        { &hf_zbee_zcl_pwr_prof_energy_format,
            { "Data", "zbee_zcl_general.pwrprof.attr.energyformat",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_energy_format_rdigit,
            { "Number of Digits to the right of the Decimal Point", "zbee_zcl_general.pwrprof.attr.energyformat.rdigit",
            FT_UINT8, BASE_DEC, NULL, ZBEE_ZCL_OPT_PWRPROF_NUM_R_DIGIT, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_energy_format_ldigit,
            { "Number of Digits to the left of the Decimal Point", "zbee_zcl_general.pwrprof.attr.energyformat.ldigit",
            FT_UINT8, BASE_DEC, NULL, ZBEE_ZCL_OPT_PWRPROF_NUM_L_DIGIT, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_energy_format_noleadingzero,
            { "Suppress leading zeros.", "zbee_zcl_general.pwrprof.attr.energyformat.noleadingzero",
            FT_BOOLEAN, 8, NULL, ZBEE_ZCL_OPT_PWRPROF_NO_LEADING_ZERO, NULL, HFILL } },
/* End EnergyFormatting fields */

        { &hf_zbee_zcl_pwr_prof_energy_remote,
            { "Energy Remote", "zbee_zcl_general.pwrprof.attr.energyremote", FT_BOOLEAN, BASE_NONE,
            TFS(&tfs_enabled_disabled), 0x0, NULL, HFILL } },

/* Begin ScheduleMode fields */
        { &hf_zbee_zcl_pwr_prof_sched_mode,
            { "Schedule Mode", "zbee_zcl_general.pwrprof.attr.schedmode",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_sched_mode_cheapest,
            { "Schedule Mode Cheapest", "zbee_zcl_general.pwrprof.attr.schedmode.cheapest",
            FT_BOOLEAN, 8, TFS(&tfs_active_inactive), ZBEE_ZCL_OPT_PWRPROF_SCHED_CHEAPEST, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_sched_mode_greenest,
            { "Schedule Mode Greenest", "zbee_zcl_general.pwrprof.attr.schedmode.greenest",
            FT_BOOLEAN, 8, TFS(&tfs_active_inactive), ZBEE_ZCL_OPT_PWRPROF_SCHED_GREENEST, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_sched_mode_reserved,
            { "Schedule Mode Reserved", "zbee_zcl_general.pwrprof.attr.schedmode.reserved",
            FT_UINT8, BASE_HEX, NULL, ZBEE_ZCL_OPT_PWRPROF_SCHED_RESERVED, NULL, HFILL } },
/* End ScheduleMode fields */

        { &hf_zbee_zcl_pwr_prof_attr_id,
            { "Attribute",   "zbee_zcl_general.pwrprof.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_pwr_prof_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_srv_tx_cmd_id,
            { "Command",   "zbee_zcl_general.pwrprof.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_pwr_prof_srv_tx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_srv_rx_cmd_id,
            { "Command",   "zbee_zcl_general.pwrprof.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_pwr_prof_srv_rx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_pwr_prof_id,
            { "Power Profile ID", "zbee_zcl_general.pwrprof.pwrprofid", FT_UINT8, BASE_CUSTOM, CF_FUNC(decode_power_profile_id), 0x00,
            "Identifier of the specific profile", HFILL } },

        { &hf_zbee_zcl_pwr_prof_currency,
            { "Currency", "zbee_zcl_general.pwrprof.currency", FT_UINT16, BASE_HEX, VALS(zbee_zcl_currecy_names), 0x0,
            "Local unit of currency (ISO 4217) used in the price field.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_price,
            { "Price", "zbee_zcl_general.pwrprof.price", FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_price_in_cents), 0x0,
            "Price of the energy of a specific Power Profile.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_price_trailing_digit,
            { "Price Trailing Digit", "zbee_zcl_general.pwrprof.pricetrailingdigit", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Number of digits to the right of the decimal point.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_num_of_sched_phases,
            { "Number of Scheduled Phases", "zbee_zcl_general.pwrprof.numofschedphases", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Total number of the energy phases of the Power Profile that need to be scheduled.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_energy_phase_id,
            { "Energy Phase ID", "zbee_zcl_general.pwrprof.energyphaseid", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Identifier of the specific phase.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_scheduled_time,
            { "Scheduled Time", "zbee_zcl_general.pwrprof.scheduledtime", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_minutes), 0x0,
            NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_macro_phase_id,
            { "Macro Phase ID", "zbee_zcl_general.pwrprof.macrophaseid", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Identifier of the specific energy phase.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_expect_duration,
            { "Expected Duration", "zbee_zcl_general.pwrprof.expectduration", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_minutes), 0x0,
            "The estimated duration of the specific phase.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_num_of_trans_phases,
            { "Number of Transferred Phases", "zbee_zcl_general.pwrprof.numoftransphases", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_peak_power,
            { "Peak Power", "zbee_zcl_general.pwrprof.peakpower", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_power_in_watt), 0x0,
            "The estimated power for the specific phase.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_energy,
            { "Energy", "zbee_zcl_general.pwrprof.energy", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_energy), 0x0,
            "The estimated energy consumption for the accounted phase.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_max_active_delay,
            { "Max Activation Delay", "zbee_zcl_general.pwrprof.maxactivdelay", FT_UINT16, BASE_CUSTOM, CF_FUNC(func_decode_delayinminute), 0x0,
            "The maximum interruption time between the end of the previous phase and the beginning of the specific phase.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_pwr_prof_count,
            { "Power Profile Count", "zbee_zcl_general.pwrprof.pwrprofcount", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_pwr_prof_rem_ctrl,
            { "Power Profile Remote Control", "zbee_zcl_general.pwrprof.pwrprofremctrl", FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x00,
            "It indicates if the PowerProfile is currently remotely controllable or not.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_pwr_prof_state,
            { "Power Profile State", "zbee_zcl_general.pwrprof.pwrprofstate", FT_UINT8, BASE_HEX, VALS(zbee_zcl_pwr_prof_state_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_start_after,
            { "Start After", "zbee_zcl_general.pwrprof.startafter", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_minutes), 0x0,
            NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_stop_before,
            { "Stop Before", "zbee_zcl_general.pwrprof.stopbefore", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_minutes), 0x0,
            NULL, HFILL } },

/* Begin Options fields */
        { &hf_zbee_zcl_pwr_prof_options,
            { "Options", "zbee_zcl_general.pwrprof.options", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_options_01,
            { "PowerProfileStartTime Field Present", "zbee_zcl_general.pwrprof.options.01", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_OPT_PWRPROF_STIME_PRESENT, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_options_res,
            { "Reserved", "zbee_zcl_general.pwrprof.options.reserved", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_OPT_PWRPROF_RESERVED, NULL, HFILL } },
/* End Options fields */

        { &hf_zbee_zcl_pwr_prof_pwr_prof_stime,
            { "Power Profile Start Time", "zbee_zcl_general.pwrprof.pwrprofstime", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_minutes), 0x0,
            NULL, HFILL } }

  };

    /* ZCL PowerProfile subtrees */
    static int *ett[ZBEE_ZCL_PWR_PROF_NUM_ETT] = {
        &ett_zbee_zcl_pwr_prof,
        &ett_zbee_zcl_pwr_prof_options,
        &ett_zbee_zcl_pwr_prof_en_format,
        &ett_zbee_zcl_pwr_prof_sched_mode
    };

    /* initialize attribute subtree types */
    for ( i = 0, j = ZBEE_ZCL_PWR_PROF_NUM_GENERIC_ETT; i < ZBEE_ZCL_PWR_PROF_NUM_PWR_PROF_ETT; i++, j++ ) {
        ett[j] = &ett_zbee_zcl_pwr_prof_pwrprofiles[i];
    }

    for ( i = 0; i < ZBEE_ZCL_PWR_PROF_NUM_EN_PHS_ETT; i++, j++ ) {
        ett[j] = &ett_zbee_zcl_pwr_prof_enphases[i];
    }

    /* Register the ZigBee ZCL PowerProfile cluster protocol name and description */
    proto_zbee_zcl_pwr_prof = proto_register_protocol("ZigBee ZCL Power Profile", "ZCL Power Profile", ZBEE_PROTOABBREV_ZCL_PWRPROF);
    proto_register_field_array(proto_zbee_zcl_pwr_prof, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Power Profile dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_PWRPROF, dissect_zbee_zcl_pwr_prof, proto_zbee_zcl_pwr_prof);
} /* proto_register_zbee_zcl_pwr_prof */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_pwr_prof
 *  DESCRIPTION
 *      Hands off the Zcl Power Profile cluster dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_pwr_prof(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_PWRPROF,
                            proto_zbee_zcl_pwr_prof,
                            ett_zbee_zcl_pwr_prof,
                            ZBEE_ZCL_CID_POWER_PROFILE,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_pwr_prof_attr_id,
                            hf_zbee_zcl_pwr_prof_attr_id,
                            hf_zbee_zcl_pwr_prof_srv_rx_cmd_id,
                            hf_zbee_zcl_pwr_prof_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_pwr_prof_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_pwr_prof*/

/* ########################################################################## */
/* #### (0x001B) APPLIANCE CONTROL CLUSTER ################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_APPL_CTRL_NUM_GENERIC_ETT                      3
#define ZBEE_ZCL_APPL_CTRL_NUM_FUNC_ETT                         32
#define ZBEE_ZCL_APPL_CTRL_NUM_ETT                              (ZBEE_ZCL_APPL_CTRL_NUM_GENERIC_ETT + \
                                                                ZBEE_ZCL_APPL_CTRL_NUM_FUNC_ETT)

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_APPL_CTRL_START_TIME                   0x0000  /* Start Time */
#define ZBEE_ZCL_ATTR_ID_APPL_CTRL_FINISH_TIME                  0x0001  /* Finish Time */
#define ZBEE_ZCL_ATTR_ID_APPL_CTRL_REMAINING_TIME               0x0002  /* Remaining Time */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_APPL_CTRL_EXECUTION_CMD                 0x00  /* Execution of a Command */
#define ZBEE_ZCL_CMD_ID_APPL_CTRL_SIGNAL_STATE                  0x01  /* Signal State */
#define ZBEE_ZCL_CMD_ID_APPL_CTRL_WRITE_FUNCS                   0x02  /* Write Functions */
#define ZBEE_ZCL_CMD_ID_APPL_CTRL_OVERLOAD_PAUSE_RESUME         0x03  /* Overload Pause Resume */
#define ZBEE_ZCL_CMD_ID_APPL_CTRL_OVERLOAD_PAUSE                0x04  /* Overload Pause */
#define ZBEE_ZCL_CMD_ID_APPL_CTRL_OVERLOAD_WARNING              0x05  /* Overload Warning */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_APPL_CTRL_SIGNAL_STATE_RSP              0x00  /* Signal State Response */
#define ZBEE_ZCL_CMD_ID_APPL_CTRL_SIGNAL_STATE_NOTIF            0x01  /* Signal State Notification */

/* Execution Of a Command - Command Ids list */
#define ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_RESERVED                 0x00  /* Reserved */
#define ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_START                    0x01  /* Start appliance cycle */
#define ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_STOP                     0x02  /* Stop appliance cycle */
#define ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_PAUSE                    0x03  /* Pause appliance cycle */
#define ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_START_SUPERFREEZING      0x04  /* Start superfreezing cycle */
#define ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_STOP_SUPERFREEZING       0x05  /* Stop superfreezing cycle */
#define ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_START_SUPERCOOLING       0x06  /* Start supercooling cycle */
#define ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_STOP_SUPERCOOLING        0x07  /* Stop supercooling cycle */
#define ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_DISABLE_GAS              0x08  /* Disable gas */
#define ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_ENABLE_GAS               0x09  /* Enable gas */

/* CECED Time mask */
#define ZBEE_ZCL_APPL_CTRL_TIME_MM                              0x003f  /* Minutes */
#define ZBEE_ZCL_APPL_CTRL_TIME_ENCOD_TYPE                      0x00c0  /* Encoding Type */
#define ZBEE_ZCL_APPL_CTRL_TIME_HH                              0xff00  /* Hours */

/* Time encoding values */
#define ZBEE_ZCL_APPL_CTRL_TIME_ENCOD_REL                       0x00
#define ZBEE_ZCL_APPL_CTRL_TIME_ENCOD_ABS                       0x01

/* Overload Warnings */
#define ZBEE_ZCL_APPL_CTRL_ID_OVRL_WARN_1                       0x00
#define ZBEE_ZCL_APPL_CTRL_ID_OVRL_WARN_2                       0x01
#define ZBEE_ZCL_APPL_CTRL_ID_OVRL_WARN_3                       0x02
#define ZBEE_ZCL_APPL_CTRL_ID_OVRL_WARN_4                       0x03
#define ZBEE_ZCL_APPL_CTRL_ID_OVRL_WARN_5                       0x04

/* Appliance Status Ids list */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_RESERVED                   0x00  /* Reserved */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_OFF                        0x01  /* Appliance in off state */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_STANDBY                    0x02  /* Appliance in stand-by */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_PRG                        0x03  /* Appliance already programmed */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_PRG_WAITING_TO_START       0x04  /* Appliance already programmed and ready to start */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_RUNNING                    0x05  /* Appliance is running */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_PAUSE                      0x06  /* Appliance is in pause */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_END_PRG                    0x07  /* Appliance end programmed tasks */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_FAILURE                    0x08  /* Appliance is in a failure state */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_PRG_INTERRUPTED            0x09  /* The appliance programmed tasks have been interrupted */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_IDLE                       0x1a  /* Appliance in idle state */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_RINSE_HOLD                 0x1b  /* Appliance rinse hold */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_SERVICE                    0x1c  /* Appliance in service state */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_SUPERFREEZING              0x1d  /* Appliance in superfreezing state */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_SUPERCOOLING               0x1e  /* Appliance in supercooling state */
#define ZBEE_ZCL_APPL_CTRL_ID_STATUS_SUPERHEATING               0x1f  /* Appliance in superheating state */

/* Remote Enable Flags mask */
#define ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_FLAGS                   0x0f
#define ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_STATUS2                 0xf0

/* Remote Enable Flags values */
#define ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_DIS                     0x00  /* Disabled */
#define ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_EN_REM_EN_CTRL          0x01  /* Enable Remote and Energy Control */
#define ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_TEMP_LOCK_DIS           0x07  /* Temporarily locked/disabled */
#define ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_EN_REM_CTRL             0x0f  /* Enable Remote Control */

/* Device Status 2 values */
#define ZBEE_ZCL_APPL_CTRL_STATUS2_PROPRIETARY_0                0x00  /* Proprietary */
#define ZBEE_ZCL_APPL_CTRL_STATUS2_PROPRIETARY_1                0x01  /* Proprietary */
#define ZBEE_ZCL_APPL_CTRL_STATUS2_IRIS_SYMPTOM_CODE            0x02  /* Iris symptom code */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_appl_ctrl(void);
void proto_reg_handoff_zbee_zcl_appl_ctrl(void);

/* Command Dissector Helpers */
static void dissect_zcl_appl_ctrl_exec_cmd              (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_appl_ctrl_attr_func             (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_appl_ctrl_wr_funcs              (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_appl_ctrl_ovrl_warning          (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_appl_ctrl_signal_state_rsp      (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

static void dissect_zcl_appl_ctrl_attr_data             (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_appl_ctrl;

static int hf_zbee_zcl_appl_ctrl_attr_id;
static int hf_zbee_zcl_appl_ctrl_time;
static int hf_zbee_zcl_appl_ctrl_time_mm;
static int hf_zbee_zcl_appl_ctrl_time_encoding_type;
static int hf_zbee_zcl_appl_ctrl_time_hh;
static int hf_zbee_zcl_appl_ctrl_srv_tx_cmd_id;
static int hf_zbee_zcl_appl_ctrl_srv_rx_cmd_id;
static int hf_zbee_zcl_appl_ctrl_exec_cmd_id;
static int hf_zbee_zcl_appl_ctrl_attr_func_id;
static int hf_zbee_zcl_appl_ctrl_attr_func_data_type;
static int hf_zbee_zcl_appl_ctrl_warning_id;
static int hf_zbee_zcl_appl_ctrl_appl_status;
static int hf_zbee_zcl_appl_ctrl_rem_en_flags_raw;
static int hf_zbee_zcl_appl_ctrl_rem_en_flags;
static int hf_zbee_zcl_appl_ctrl_status2;
static int hf_zbee_zcl_appl_ctrl_status2_array;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_appl_ctrl;
static int ett_zbee_zcl_appl_ctrl_flags;
static int ett_zbee_zcl_appl_ctrl_time;
static int ett_zbee_zcl_appl_ctrl_func[ZBEE_ZCL_APPL_CTRL_NUM_FUNC_ETT];

/* Attributes */
static const value_string zbee_zcl_appl_ctrl_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_APPL_CTRL_START_TIME,                    "Start Time" },
    { ZBEE_ZCL_ATTR_ID_APPL_CTRL_FINISH_TIME,                   "Finish Time" },
    { ZBEE_ZCL_ATTR_ID_APPL_CTRL_REMAINING_TIME,                "Remaining Time" },
    { 0, NULL }
};
static value_string_ext zbee_zcl_appl_ctrl_attr_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_appl_ctrl_attr_names);

/* Server Commands Received */
static const value_string zbee_zcl_appl_ctrl_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_APPL_CTRL_EXECUTION_CMD,                  "Execution of a Command" },
    { ZBEE_ZCL_CMD_ID_APPL_CTRL_SIGNAL_STATE,                   "Signal State" },
    { ZBEE_ZCL_CMD_ID_APPL_CTRL_WRITE_FUNCS,                    "Write Functions" },
    { ZBEE_ZCL_CMD_ID_APPL_CTRL_OVERLOAD_PAUSE_RESUME,          "Overload Pause Resume" },
    { ZBEE_ZCL_CMD_ID_APPL_CTRL_OVERLOAD_PAUSE,                 "Overload Pause" },
    { ZBEE_ZCL_CMD_ID_APPL_CTRL_OVERLOAD_WARNING,               "Overload Warning" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_appl_ctrl_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_APPL_CTRL_SIGNAL_STATE_RSP,               "Signal State Response" },
    { ZBEE_ZCL_CMD_ID_APPL_CTRL_SIGNAL_STATE_NOTIF,             "Signal State Notification" },
    { 0, NULL }
};

/* Execution Of a Command - Command Name */
static const value_string zbee_zcl_appl_ctrl_exec_cmd_names[] = {
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_RESERVED,                  "Reserved" },
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_START,                     "Start" },
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_STOP,                      "Stop" },
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_PAUSE,                     "Pause" },
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_START_SUPERFREEZING,       "Start Superfreezing" },
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_STOP_SUPERFREEZING,        "Stop Superfreezing" },
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_START_SUPERCOOLING,        "Start Supercooling" },
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_STOP_SUPERCOOLING,         "Stop Supercooling" },
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_DISABLE_GAS,               "Disable Gas" },
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_ENABLE_GAS,                "Enable Gas" },
    { 0, NULL }
};

/* Appliance Status Names list */
static const value_string zbee_zcl_appl_ctrl_appl_status_names[] = {
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_RESERVED,                    "Reserved" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_OFF,                         "Off" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_STANDBY,                     "Stand-by" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_PRG,                         "Programmed" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_PRG_WAITING_TO_START,        "Waiting to Start" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_RUNNING,                     "Running" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_PAUSE,                       "Pause" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_END_PRG,                     "End Programmed" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_FAILURE,                     "Failure" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_PRG_INTERRUPTED,             "Programme Interrupted" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_IDLE,                        "Idle" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_RINSE_HOLD,                  "Raise Hold" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_SERVICE,                     "Service" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_SUPERFREEZING,               "Superfreezing" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_SUPERCOOLING,                "Supercooling" },
    { ZBEE_ZCL_APPL_CTRL_ID_STATUS_SUPERHEATING,                "Superheating" },
    { 0, NULL }
};

/* Remote Enable Flags Names list */
static const value_string zbee_zcl_appl_ctrl_rem_flags_names[] = {
    { ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_DIS,                      "Disable" },
    { ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_EN_REM_EN_CTRL,           "Enable Remote and Energy Control" },
    { ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_TEMP_LOCK_DIS,            "Temporarily locked/disabled" },
    { ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_EN_REM_CTRL,              "Enable Remote Control" },
    { 0, NULL }
};

/* Appliance Status 2 Names list */
static const value_string zbee_zcl_appl_ctrl_status2_names[] = {
    { ZBEE_ZCL_APPL_CTRL_STATUS2_PROPRIETARY_0,                 "Proprietary" },
    { ZBEE_ZCL_APPL_CTRL_STATUS2_PROPRIETARY_1,                 "Proprietary" },
    { ZBEE_ZCL_APPL_CTRL_STATUS2_IRIS_SYMPTOM_CODE,             "Iris symptom code" },
    { 0, NULL }
};

/* Overload Warning Names list */
static const value_string zbee_zcl_appl_ctrl_ovrl_warning_names[] = {
    { ZBEE_ZCL_APPL_CTRL_ID_OVRL_WARN_1,    "Overall power above 'available power' level" },
    { ZBEE_ZCL_APPL_CTRL_ID_OVRL_WARN_2,    "Overall power above 'power threshold' level" },
    { ZBEE_ZCL_APPL_CTRL_ID_OVRL_WARN_3,    "Overall power back below the 'available power' level" },
    { ZBEE_ZCL_APPL_CTRL_ID_OVRL_WARN_4,    "Overall power back below the 'power threshold' level" },
    { ZBEE_ZCL_APPL_CTRL_ID_OVRL_WARN_5,    "Overall power will be potentially above 'available power' level if the appliance starts" },
    { 0, NULL }
};

/* CEDEC Time Encoding Names list */
static const value_string zbee_zcl_appl_ctrl_time_encoding_type_names[] = {
    { ZBEE_ZCL_APPL_CTRL_TIME_ENCOD_REL,    "Relative" },
    { ZBEE_ZCL_APPL_CTRL_TIME_ENCOD_ABS,    "Absolute" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_appl_ctrl
 *  DESCRIPTION
 *      ZigBee ZCL Appliance Control cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      void *data          - pointer to ZCL packet structure.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_appl_ctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_appl_ctrl_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_appl_ctrl, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_APPL_CTRL_EXECUTION_CMD:
                    dissect_zcl_appl_ctrl_exec_cmd(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_APPL_CTRL_SIGNAL_STATE:
                case ZBEE_ZCL_CMD_ID_APPL_CTRL_OVERLOAD_PAUSE_RESUME:
                case ZBEE_ZCL_CMD_ID_APPL_CTRL_OVERLOAD_PAUSE:
                    /* No payload */
                    break;

                case ZBEE_ZCL_CMD_ID_APPL_CTRL_WRITE_FUNCS:
                    dissect_zcl_appl_ctrl_wr_funcs(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_APPL_CTRL_OVERLOAD_WARNING:
                    dissect_zcl_appl_ctrl_ovrl_warning(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_appl_ctrl_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_appl_ctrl, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_APPL_CTRL_SIGNAL_STATE_RSP:
                case ZBEE_ZCL_CMD_ID_APPL_CTRL_SIGNAL_STATE_NOTIF:
                    dissect_zcl_appl_ctrl_signal_state_rsp(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
}


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_appl_ctrl_exec_cmd
 *  DESCRIPTION
 *      this function is called in order to decode "ExecutionOfACommand"
 *      payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_exec_cmd(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Command Id" field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_exec_cmd_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_appl_ctrl_exec_cmd*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_appl_ctrl_attr_func
 *  DESCRIPTION
 *      this function is called in order to decode "Function" element.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_attr_func(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t func_data_type;
    uint16_t func_id;

    /* ID */
    func_id = tvb_get_letohs(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_attr_func_id, tvb, *offset, 2,ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_item_append_text(tree, ", %s",
    val_to_str_ext_const(func_id, &zbee_zcl_appl_ctrl_attr_names_ext, "Reserved"));

    /* Data Type */
    func_data_type = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_attr_func_data_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Function Data Dissector */
    dissect_zcl_appl_ctrl_attr_data(tree, tvb, offset, func_id, func_data_type, false);

} /*dissect_zcl_appl_ctrl_attr_func*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_appl_ctrl_wr_funcs
 *  DESCRIPTION
 *      this function is called in order to decode "WriteFunctions"
 *      payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_wr_funcs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
  proto_tree  *sub_tree = NULL;
  unsigned tvb_len;
  unsigned i = 0;

  tvb_len = tvb_reported_length(tvb);
  while ( *offset < tvb_len && i < ZBEE_ZCL_APPL_CTRL_NUM_FUNC_ETT ) {
    /* Create subtree for attribute status field */
    sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 0,
            ett_zbee_zcl_appl_ctrl_func[i], NULL, "Function #%d", i);
    i++;

    /* Dissect the attribute identifier */
    dissect_zcl_appl_ctrl_attr_func(tvb, sub_tree, offset);
  }

} /*dissect_zcl_appl_ctrl_wr_funcs*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_appl_ctrl_ovrl_warning
 *  DESCRIPTION
 *      this function is called in order to decode "OverloadWarning"
 *      payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_ovrl_warning(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Warning Id" field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_warning_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

} /*dissect_zcl_appl_ctrl_ovrl_warning*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_appl_ctrl_signal_state_rsp
 *  DESCRIPTION
 *      this function is called in order to decode "SignalStateResponse"
 *      "SignalStateNotification" payload.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      unsigned *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_signal_state_rsp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    static int * const flags[] = {
        &hf_zbee_zcl_appl_ctrl_rem_en_flags,
        &hf_zbee_zcl_appl_ctrl_status2,
        NULL
    };

    /* Retrieve "Appliance Status" field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_appl_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Remote Enable" field */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_appl_ctrl_rem_en_flags_raw, ett_zbee_zcl_appl_ctrl_flags, flags, ENC_NA);
    *offset += 1;

    /* Retrieve "Appliance Status 2" field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_status2_array, tvb, *offset, 3, ENC_BIG_ENDIAN);
} /*dissect_zcl_appl_ctrl_signal_state_rsp*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_appl_ctrl_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    static int * const flags[] = {
        &hf_zbee_zcl_appl_ctrl_time_mm,
        &hf_zbee_zcl_appl_ctrl_time_encoding_type,
        &hf_zbee_zcl_appl_ctrl_time_hh,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_APPL_CTRL_START_TIME:
        case ZBEE_ZCL_ATTR_ID_APPL_CTRL_FINISH_TIME:
        case ZBEE_ZCL_ATTR_ID_APPL_CTRL_REMAINING_TIME:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_appl_ctrl_time, ett_zbee_zcl_appl_ctrl_time, flags, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }
} /*dissect_zcl_appl_ctrl_attr_data*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_appl_ctrl
 *  DESCRIPTION
 *      this function registers the ZCL Appliance Control dissector
 *      and all its information.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_appl_ctrl(void)
{
    unsigned i, j;

    static hf_register_info hf[] = {

        { &hf_zbee_zcl_appl_ctrl_attr_id,
            { "Attribute", "zbee_zcl_general.applctrl.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_ctrl_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_time,
            { "Data", "zbee_zcl_general.applctrl.time", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_time_mm,
            { "Minutes", "zbee_zcl_general.applctrl.time.mm", FT_UINT16, BASE_DEC, NULL, ZBEE_ZCL_APPL_CTRL_TIME_MM,
            NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_time_encoding_type,
            { "Encoding Type", "zbee_zcl_general.applctrl.time.encoding_type", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_ctrl_time_encoding_type_names),
            ZBEE_ZCL_APPL_CTRL_TIME_ENCOD_TYPE, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_time_hh,
            { "Hours", "zbee_zcl_general.applctrl.time.hh", FT_UINT16, BASE_DEC, NULL, ZBEE_ZCL_APPL_CTRL_TIME_HH,
            NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_srv_tx_cmd_id,
            { "Command", "zbee_zcl_general.applctrl.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_ctrl_srv_tx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_srv_rx_cmd_id,
            { "Command", "zbee_zcl_general.applctrl.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_ctrl_srv_rx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_appl_status,
            { "Appliance Status", "zbee_zcl_general.applctrl.status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_ctrl_appl_status_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_rem_en_flags_raw,
            { "Remote Enable Flags", "zbee_zcl_general.applctrl.remote_enable_flags", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_rem_en_flags,
            { "Remote Enable Flags", "zbee_zcl_general.applctrl.remenflags", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_ctrl_rem_flags_names),
            ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_FLAGS, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_status2,
            { "Appliance Status 2", "zbee_zcl_general.applctrl.status2", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_ctrl_status2_names),
            ZBEE_ZCL_APPL_CTRL_REM_EN_FLAGS_STATUS2, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_status2_array,
            { "Appliance Status 2", "zbee_zcl_general.applctrl.status2.array", FT_UINT24, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_exec_cmd_id,
            { "Command", "zbee_zcl_general.applctrl.execcmd.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_ctrl_exec_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_attr_func_id,
            { "ID", "zbee_zcl_general.applctrl.attr_func.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_ctrl_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_attr_func_data_type,
            { "Data Type", "zbee_zcl_general.applctrl.attr_func.datatype", FT_UINT8, BASE_HEX, VALS(zbee_zcl_short_data_type_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_ctrl_warning_id,
            { "Warning", "zbee_zcl_general.applctrl.ovrlwarning.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_ctrl_ovrl_warning_names),
            0x0, NULL, HFILL } }

    };

    /* ZCL ApplianceControl subtrees */
    int *ett[ZBEE_ZCL_APPL_CTRL_NUM_ETT] = {
        &ett_zbee_zcl_appl_ctrl,
        &ett_zbee_zcl_appl_ctrl_flags,
        &ett_zbee_zcl_appl_ctrl_time
    };

    /* initialize attribute subtree types */
    for ( i = 0, j = ZBEE_ZCL_APPL_CTRL_NUM_GENERIC_ETT; i < ZBEE_ZCL_APPL_CTRL_NUM_FUNC_ETT; i++, j++) {
        ett[j] = &ett_zbee_zcl_appl_ctrl_func[i];
    }

    /* Register the ZigBee ZCL ApplianceControl cluster protocol name and description */
    proto_zbee_zcl_appl_ctrl = proto_register_protocol("ZigBee ZCL Appliance Control", "ZCL Appliance Control", ZBEE_PROTOABBREV_ZCL_APPLCTRL);
    proto_register_field_array(proto_zbee_zcl_appl_ctrl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Appliance Control dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_APPLCTRL, dissect_zbee_zcl_appl_ctrl, proto_zbee_zcl_appl_ctrl);
} /*proto_register_zbee_zcl_appl_ctrl*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_appl_ctrl
 *  DESCRIPTION
 *      Hands off the Zcl Appliance Control dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_appl_ctrl(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_APPLCTRL,
                            proto_zbee_zcl_appl_ctrl,
                            ett_zbee_zcl_appl_ctrl,
                            ZBEE_ZCL_CID_APPLIANCE_CONTROL,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_appl_ctrl_attr_id,
                            hf_zbee_zcl_appl_ctrl_attr_id,
                            hf_zbee_zcl_appl_ctrl_srv_rx_cmd_id,
                            hf_zbee_zcl_appl_ctrl_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_appl_ctrl_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_appl_ctrl*/

/* ########################################################################## */
/* #### (0x0020) POLL CONTROL CLUSTER ####################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Poll Control Attributes */
#define ZBEE_ZCL_ATTR_ID_POLL_CTRL_CHECK_IN             0x0000
#define ZBEE_ZCL_ATTR_ID_POLL_CTRL_LONG_POLL            0x0001
#define ZBEE_ZCL_ATTR_ID_POLL_CTRL_SHORT_POLL           0x0002
#define ZBEE_ZCL_ATTR_ID_POLL_CTRL_FAST_POLL            0x0003
#define ZBEE_ZCL_ATTR_ID_POLL_CTRL_CHECK_IN_MIN         0x0004
#define ZBEE_ZCL_ATTR_ID_POLL_CTRL_LONG_POLL_MIN        0x0005
#define ZBEE_ZCL_ATTR_ID_POLL_CTRL_FAST_POLL_TIMEOUT    0x0006

static const value_string zbee_zcl_poll_ctrl_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_POLL_CTRL_CHECK_IN,          "Check-inInterval" },
    { ZBEE_ZCL_ATTR_ID_POLL_CTRL_LONG_POLL,         "LongPollInterval" },
    { ZBEE_ZCL_ATTR_ID_POLL_CTRL_SHORT_POLL,        "ShortPollInterval" },
    { ZBEE_ZCL_ATTR_ID_POLL_CTRL_FAST_POLL,         "FastPollTimeout" },
    { ZBEE_ZCL_ATTR_ID_POLL_CTRL_CHECK_IN_MIN,      "Check-inIntervalMin" },
    { ZBEE_ZCL_ATTR_ID_POLL_CTRL_LONG_POLL_MIN,     "LongPollIntervalMin" },
    { ZBEE_ZCL_ATTR_ID_POLL_CTRL_FAST_POLL_TIMEOUT, "FastPollTimeoutMax" },
    { 0, NULL }
};

/* Server-to-client command IDs. */
#define ZBEE_ZCL_CMD_ID_POLL_CTRL_CHECK_IN          0x00
static const value_string zbee_zcl_poll_ctrl_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_POLL_CTRL_CHECK_IN,           "Check-in" },
    { 0, NULL }
};

/* Client-to-server command IDs. */
#define ZBEE_ZCL_CMD_ID_POLL_CTRL_CHECK_IN_RESPONSE 0x00
#define ZBEE_ZCL_CMD_ID_POLL_CTRL_FAST_POLL_STOP    0x01
#define ZBEE_ZCL_CMD_ID_POLL_CTRL_SET_LONG_POLL     0x02
#define ZBEE_ZCL_CMD_ID_POLL_CTRL_SET_SHORT_POLL    0x03
static const value_string zbee_zcl_poll_ctrl_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_POLL_CTRL_CHECK_IN_RESPONSE,  "Check-in Response" },
    { ZBEE_ZCL_CMD_ID_POLL_CTRL_FAST_POLL_STOP,     "Fast Poll Stop" },
    { ZBEE_ZCL_CMD_ID_POLL_CTRL_SET_LONG_POLL,      "Set Long Poll Interval" },
    { ZBEE_ZCL_CMD_ID_POLL_CTRL_SET_SHORT_POLL,     "Set Short Poll Interval" },
    { 0, NULL }
};

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_poll_ctrl;

static int hf_zbee_zcl_poll_ctrl_attr_id;
static int hf_zbee_zcl_poll_ctrl_srv_rx_cmd_id;
static int hf_zbee_zcl_poll_ctrl_srv_tx_cmd_id;
static int hf_zbee_zcl_poll_ctrl_start_fast_polling;
static int hf_zbee_zcl_poll_ctrl_fast_poll_timeout;
static int hf_zbee_zcl_poll_ctrl_new_long_poll_interval;
static int hf_zbee_zcl_poll_ctrl_new_short_poll_interval;

static int ett_zbee_zcl_poll_ctrl;

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_poll_ctrl(void);
void proto_reg_handoff_zbee_zcl_poll_ctrl(void);

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_poll_ctrl
 *  DESCRIPTION
 *      ZigBee ZCL Poll Control cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      void *data          - pointer to ZCL packet structure.
 *  RETURNS
 *      int                 - length of parsed data.
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_poll_ctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_poll_ctrl_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_poll_ctrl_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* Handle the command dissection. */
        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_POLL_CTRL_CHECK_IN_RESPONSE:
                proto_tree_add_item(tree, hf_zbee_zcl_poll_ctrl_start_fast_polling, tvb, offset, 1, ENC_NA);
                offset++;
                proto_tree_add_item(tree, hf_zbee_zcl_poll_ctrl_fast_poll_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                break;

            case ZBEE_ZCL_CMD_ID_POLL_CTRL_FAST_POLL_STOP:
                /* no payload. */
                break;

            case ZBEE_ZCL_CMD_ID_POLL_CTRL_SET_LONG_POLL:
                proto_tree_add_item(tree, hf_zbee_zcl_poll_ctrl_new_long_poll_interval, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;

            case ZBEE_ZCL_CMD_ID_POLL_CTRL_SET_SHORT_POLL:
                proto_tree_add_item(tree, hf_zbee_zcl_poll_ctrl_new_short_poll_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                break;

            default:
                break;
        } /* switch */
    } else {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_poll_ctrl_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_poll_ctrl_srv_tx_cmd_id, tvb, offset, 1, ENC_NA);
        offset++;

        /* Handle the command dissection. */
        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_POLL_CTRL_CHECK_IN:
                /* No payload - fall through. */
            default:
                break;
        } /* switch */
    }

    return tvb_captured_length(tvb);
} /* dissect_zbee_zcl_poll_ctrl */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_poll_ctrl_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      unsigned *offset       - pointer to buffer offset
 *      uint16_t attr_id     - attribute identifier
 *      unsigned data_type     - attribute data type
 *      bool client_attr- ZCL client
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_poll_ctrl_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id _U_, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);

} /*dissect_zcl_poll_ctrl_attr_data*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_poll_ctrl
 *  DESCRIPTION
 *      ZigBee ZCL Poll Control cluster protocol registration.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_poll_ctrl(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_poll_ctrl_attr_id,
            { "Attribute", "zbee_zcl_general.poll.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_poll_ctrl_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_poll_ctrl_srv_rx_cmd_id,
            { "Command", "zbee_zcl_general.poll.cmd.srv_rx.id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_poll_ctrl_srv_rx_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_poll_ctrl_srv_tx_cmd_id,
            { "Command", "zbee_zcl_general.poll.cmd.srv_tx.id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_poll_ctrl_srv_tx_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_poll_ctrl_start_fast_polling,
            { "Start Fast Polling", "zbee_zcl_general.poll.start", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_poll_ctrl_fast_poll_timeout,
            { "Fast Poll Timeout (quarterseconds)", "zbee_zcl_general.poll.fast_timeout", FT_UINT16, BASE_DEC, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_poll_ctrl_new_long_poll_interval,
            { "New Long Poll Interval", "zbee_zcl_general.poll.new_long_interval", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
                HFILL }},

        { &hf_zbee_zcl_poll_ctrl_new_short_poll_interval,
            { "New Short Poll Interval", "zbee_zcl_general.poll.new_short_interval", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
                HFILL }}
    };

    /* ZCL Poll Control subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_poll_ctrl
    };

    /* Register the ZigBee ZCL Poll Control cluster protocol name and description */
    proto_zbee_zcl_poll_ctrl = proto_register_protocol("ZigBee ZCL Poll Control", "ZCL Poll Control", ZBEE_PROTOABBREV_ZCL_POLL);
    proto_register_field_array(proto_zbee_zcl_poll_ctrl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Poll Control dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_POLL, dissect_zbee_zcl_poll_ctrl, proto_zbee_zcl_poll_ctrl);
} /*proto_register_zbee_zcl_poll_ctrl*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_poll_ctrl
 *  DESCRIPTION
 *      Hands off the ZCL Poll Control dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_zbee_zcl_poll_ctrl(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_POLL,
                            proto_zbee_zcl_poll_ctrl,
                            ett_zbee_zcl_poll_ctrl,
                            ZBEE_ZCL_CID_POLL_CONTROL,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_poll_ctrl_attr_id,
                            hf_zbee_zcl_poll_ctrl_attr_id,
                            hf_zbee_zcl_poll_ctrl_srv_rx_cmd_id,
                            hf_zbee_zcl_poll_ctrl_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_poll_ctrl_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_poll_ctrl*/



/* ########################################################################## */
/* #### (0x0021) GREEN POWER CLUSTER ######################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Green Power Attributes */

#define ZBEE_ZCL_ATTR_GPS_MAX_SINK_TABLE_ENTRIES     0x0000
#define ZBEE_ZCL_ATTR_GPS_SINK_TABLE                 0x0001
#define ZBEE_ZCL_ATTR_GPS_COMMUNICATION_MODE         0x0002
#define ZBEE_ZCL_ATTR_GPS_COMMISSIONING_EXIT_MODE    0x0003
#define ZBEE_ZCL_ATTR_GPS_COMMISSIONING_WINDOW       0x0004
#define ZBEE_ZCL_ATTR_GPS_SECURITY_LEVEL             0x0005
#define ZBEE_ZCL_ATTR_GPS_FUNCTIONALITY              0x0006
#define ZBEE_ZCL_ATTR_GPS_ACTIVE_FUNCTIONALITY       0x0007
#define ZBEE_ZCL_ATTR_GPP_MAX_PROXY_TABLE_ENTRIES    0x0010
#define ZBEE_ZCL_ATTR_GPP_PROXY_TABLE                0x0011
#define ZBEE_ZCL_ATTR_GPP_NOTIFICATION_RETRY_NUMBER  0x0012
#define ZBEE_ZCL_ATTR_GPP_NOTIFICATION_RETRY_TIMER   0x0013
#define ZBEE_ZCL_ATTR_GPP_MAX_SEARCH_COUNTER         0x0014
#define ZBEE_ZCL_ATTR_GPP_BLOCKED_GPDID              0x0015
#define ZBEE_ZCL_ATTR_GPP_FUNCTIONALITY              0x0016
#define ZBEE_ZCL_ATTR_GPP_ACTIVE_FUNCTIONALITY       0x0017
#define ZBEE_ZCL_ATTR_GP_SHARED_SECURITY_KEY_TYPE    0x0020
#define ZBEE_ZCL_ATTR_GP_SHARED_SECURITY_KEY         0x0021
#define ZBEE_ZCL_ATTR_GP_LINK_KEY                    0x0022

static const value_string zbee_zcl_gp_attr_names[] = {
    { ZBEE_ZCL_ATTR_GPS_MAX_SINK_TABLE_ENTRIES,     "gpsMaxSinkTableEntries" },
    { ZBEE_ZCL_ATTR_GPS_SINK_TABLE,                 "SinkTable" },
    { ZBEE_ZCL_ATTR_GPS_COMMUNICATION_MODE,         "gpsCommunicationMode" },
    { ZBEE_ZCL_ATTR_GPS_COMMISSIONING_EXIT_MODE,    "gpsCommissioningExitMode" },
    { ZBEE_ZCL_ATTR_GPS_COMMISSIONING_WINDOW,       "gpsCommissioningWindow" },
    { ZBEE_ZCL_ATTR_GPS_SECURITY_LEVEL,             "gpsSecurityLevel" },
    { ZBEE_ZCL_ATTR_GPS_FUNCTIONALITY,              "gpsFunctionality" },
    { ZBEE_ZCL_ATTR_GPS_ACTIVE_FUNCTIONALITY,       "gpsActiveFunctionality" },
    { ZBEE_ZCL_ATTR_GPP_MAX_PROXY_TABLE_ENTRIES,    "gppMaxProxyTableEntries" },
    { ZBEE_ZCL_ATTR_GPP_PROXY_TABLE,                "ProxyTable" },
    { ZBEE_ZCL_ATTR_GPP_NOTIFICATION_RETRY_NUMBER,  "gppNotificationRetryNumber" },
    { ZBEE_ZCL_ATTR_GPP_NOTIFICATION_RETRY_TIMER,   "gppNotificationRetryTimer" },
    { ZBEE_ZCL_ATTR_GPP_MAX_SEARCH_COUNTER,         "gppMaxSearchCounter" },
    { ZBEE_ZCL_ATTR_GPP_BLOCKED_GPDID,              "gppBlockedGPDID" },
    { ZBEE_ZCL_ATTR_GPP_FUNCTIONALITY,              "gppFunctionality" },
    { ZBEE_ZCL_ATTR_GPP_ACTIVE_FUNCTIONALITY,       "gppActiveFunctionality" },
    { ZBEE_ZCL_ATTR_GP_SHARED_SECURITY_KEY_TYPE,    "gpSharedSecurityKeyType" },
    { ZBEE_ZCL_ATTR_GP_SHARED_SECURITY_KEY,         "gpSharedSecurityKey" },
    { ZBEE_ZCL_ATTR_GP_LINK_KEY,                    "gpLinkKey" },
    { 0, NULL }
};

/* Server-to-client command IDs. */
#define ZBEE_ZCL_CMD_ID_GP_NOTIFICATION_RESPONSE     0x00
#define ZBEE_ZCL_CMD_ID_GP_PAIRING                   0x01
#define ZBEE_ZCL_CMD_ID_GP_PROXY_COMMISSIONING_MODE  0x02
#define ZBEE_ZCL_CMD_ID_GP_RESPONSE                  0x06
#define ZBEE_ZCL_CMD_ID_GP_TRANS_TBL_RESPONSE        0x08
#define ZBEE_ZCL_CMD_ID_GP_SINK_TABLE_RESPONSE       0x0a
#define ZBEE_ZCL_CMD_ID_GP_PROXY_TABLE_REQUEST       0x0b

static const value_string zbee_zcl_gp_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_GP_NOTIFICATION_RESPONSE,     "GP Notification Response" },
    { ZBEE_ZCL_CMD_ID_GP_PAIRING,                   "GP Pairing" },
    { ZBEE_ZCL_CMD_ID_GP_PROXY_COMMISSIONING_MODE,  "GP Proxy Commissioning Mode" },
    { ZBEE_ZCL_CMD_ID_GP_RESPONSE,                  "GP Response" },
    { ZBEE_ZCL_CMD_ID_GP_TRANS_TBL_RESPONSE,        "GP Translation Table Response" },
    { ZBEE_ZCL_CMD_ID_GP_SINK_TABLE_RESPONSE,       "GP Sink Table Response" },
    { ZBEE_ZCL_CMD_ID_GP_PROXY_TABLE_REQUEST,       "GP Proxy Table Request" },
    { 0, NULL }
};

/* Client-to-server command IDs. */
#define ZBEE_CMD_ID_GP_NOTIFICATION                        0x00
#define ZBEE_CMD_ID_GP_PAIRING_SEARCH                      0x01
#define ZBEE_CMD_ID_GP_TUNNELING_STOP                      0x03
#define ZBEE_CMD_ID_GP_COMMISSIONING_NOTIFICATION          0x04
#define ZBEE_CMD_ID_GP_SINK_COMMISSIONING_MODE             0x05
#define ZBEE_CMD_ID_GP_TRANSLATION_TABLE_UPDATE_COMMAND    0x07
#define ZBEE_CMD_ID_GP_TRANSLATION_TABLE_REQUEST           0x08
#define ZBEE_CMD_ID_GP_PAIRING_CONFIGURATION               0x09
#define ZBEE_CMD_ID_GP_SINK_TABLE_REQUEST                  0x0a
#define ZBEE_CMD_ID_GP_PROXY_TABLE_RESPONSE                0x0b

static const value_string zbee_zcl_gp_srv_rx_cmd_names[] = {
    { ZBEE_CMD_ID_GP_NOTIFICATION,                      "GP Notification" },
    { ZBEE_CMD_ID_GP_PAIRING_SEARCH,                    "GP Pairing Search" },
    { ZBEE_CMD_ID_GP_TUNNELING_STOP,                    "GP Tunneling Stop" },
    { ZBEE_CMD_ID_GP_COMMISSIONING_NOTIFICATION,        "GP Commissioning Notification" },
    { ZBEE_CMD_ID_GP_SINK_COMMISSIONING_MODE,           "GP Sink Commissioning Mode" },
    { ZBEE_CMD_ID_GP_TRANSLATION_TABLE_UPDATE_COMMAND,  "GP Translation Table Update" },
    { ZBEE_CMD_ID_GP_TRANSLATION_TABLE_REQUEST,         "GP Translation Table Request" },
    { ZBEE_CMD_ID_GP_PAIRING_CONFIGURATION,             "GP Pairing Configuration" },
    { ZBEE_CMD_ID_GP_SINK_TABLE_REQUEST,                "GP Sink Table Request" },
    { ZBEE_CMD_ID_GP_PROXY_TABLE_RESPONSE,              "GP Proxy Table Response" },
    { 0, NULL }
};

static const value_string zbee_zcl_gp_comm_mode_actions[] = {
    { 0, "Exit commissioning mode" },
    { 1, "Enter commissioning mode" },
    { 0, NULL }
};

static const value_string zbee_zcl_gp_app_ids[] = {
    { 0, "0b000 4b SrcID; no Endpoint" },
    { 2, "0b010 8b IEEE; Endpoint presents" },
    { 0, NULL }
};

static const value_string zbee_zcl_gp_secur_levels[] = {
    { 0, "No security" },
    { 1, "Reserved" },
    { 2, "4B frame counter and 4B MIC only" },
    { 3, "Encryption & 4B frame counter and 4B MIC" },
    { 0, NULL }
};

static const value_string zbee_zcl_gp_secur_key_types[] = {
    { 0, "No key" },
    { 1, "ZigBee NWK key" },
    { 2, "GPD group key" },
    { 3, "NWK-key derived GPD group key" },
    { 4, "(individual) out-of-the-box GPD key" },
    { 7, "Derived individual GPD key" },
    { 0, NULL }
};

static const value_string zbee_zcl_gp_communication_modes[] = {
    { 0, "Full unicast" },
    { 1, "Groupcast to DGroupID" },
    { 2, "Groupcast to pre-commissioned GroupID" },
    { 3, "Lightweight unicast" },
    { 0, NULL }
};

static const value_string zbee_zcl_gp_lqi_vals[] = {
    { 0, "Poor" },
    { 1, "Moderate" },
    { 2, "High" },
    { 3, "Excellent" },
    { 0, NULL }
};

static const value_string zbee_zcl_gp_channels[] = {
    { 0, "Channel 11" },
    { 1, "Channel 12" },
    { 2, "Channel 13" },
    { 3, "Channel 14" },
    { 4, "Channel 15" },
    { 5, "Channel 16" },
    { 6, "Channel 17" },
    { 7, "Channel 18" },
    { 8, "Channel 19" },
    { 9, "Channel 20" },
    { 10, "Channel 21" },
    { 11, "Channel 22" },
    { 12, "Channel 23" },
    { 13, "Channel 24" },
    { 14, "Channel 25" },
    { 15, "Channel 26" },
    { 0, NULL }
};

static const value_string zbee_gp_pc_actions[] = {
    { 0, "No action" },
    { 1, "Extend Sink Table entry" },
    { 2, "Replace Sink Table entry" },
    { 3, "Remove a pairing" },
    { 4, "Remove GPD" },
    { 0, NULL }
};

static const value_string zbee_zcl_gp_proxy_sink_tbl_req_type[] = {
    { 0, "Request table entries by GPD ID" },
    { 1, "Request table entries by Index" },
    { 0, NULL }
};

#define ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_ACTION                             1
#define ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_EXIT_MODE                          (7<<1)
#define ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_ON_COMMISSIONING_WINDOW_EXPIRATION ((1<<0)<<1)
#define ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_ON_PAIRING_SUCCESS                 ((1<<1)<<1)
#define ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_ON_GP_PROXY_COMM_MODE              ((1<<2)<<1)
#define ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_CHANNEL_PRESENT                    (1<<4)
#define ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_UNICAST                            (1<<5)


#define ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_APP_ID                           (7<<0)
#define ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_RX_AFTER_TX                      (1<<3)
#define ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_SECUR_LEVEL                      (3<<4)
#define ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_SECUR_KEY_TYPE                   (7<<6)
#define ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_SECUR_FAILED                     (1<<9)
#define ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_BIDIR_CAP                        (1<<10)
#define ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_PROXY_INFO_PRESENT               (1<<11)

#define ZBEE_ZCL_GP_GPP_GPD_LINK_RSSI                                                  0x3f
#define ZBEE_ZCL_GP_GPP_GPD_LINK_LQI                                                   (3<<6)

#define ZBEE_ZCL_GP_NOTIFICATION_OPTION_APP_ID                                         (7<<0)
#define ZBEE_ZCL_GP_NOTIFICATION_OPTION_ALSO_UNICAST                                   (1<<3)
#define ZBEE_ZCL_GP_NOTIFICATION_OPTION_ALSO_DERIVED_GROUP                             (1<<4)
#define ZBEE_ZCL_GP_NOTIFICATION_OPTION_ALSO_COMMISSIONED_GROUP                        (1<<5)
#define ZBEE_ZCL_GP_NOTIFICATION_OPTION_SECUR_LEVEL                                    (3<<6)
#define ZBEE_ZCL_GP_NOTIFICATION_OPTION_SECUR_KEY_TYPE                                 (7<<8)
#define ZBEE_ZCL_GP_NOTIFICATION_OPTION_RX_AFTER_TX                                    (1<<11)
#define ZBEE_ZCL_GP_NOTIFICATION_OPTION_TX_Q_FULL                                      (1<<12)
#define ZBEE_ZCL_GP_NOTIFICATION_OPTION_BIDIR_CAP                                      (1<<13)
#define ZBEE_ZCL_GP_NOTIFICATION_OPTION_PROXY_INFO_PRESENT                             (1<<14)

#define ZBEE_ZCL_GP_PAIRING_OPTION_APP_ID                                              (7<<0)
#define ZBEE_ZCL_GP_PAIRING_OPTION_ADD_SINK                                            (1<<3)
#define ZBEE_ZCL_GP_PAIRING_OPTION_REMOVE_GPD                                          (1<<4)
#define ZBEE_ZCL_GP_PAIRING_OPTION_COMMUNICATION_MODE                                  (3<<5)
#define ZBEE_ZCL_GP_PAIRING_OPTION_GPD_FIXED                                           (1<<7)
#define ZBEE_ZCL_GP_PAIRING_OPTION_GPD_MAC_SEQ_NUM_CAP                                 (1<<8)
#define ZBEE_ZCL_GP_PAIRING_OPTION_SECUR_LEVEL                                         (3<<9)
#define ZBEE_ZCL_GP_PAIRING_OPTION_SECUR_KEY_TYPE                                      (7<<11)
#define ZBEE_ZCL_GP_PAIRING_OPTION_GPD_FRAME_CNT_PRESENT                               (1<<14)
#define ZBEE_ZCL_GP_PAIRING_OPTION_GPD_SECUR_KEY_PRESENT                               (1<<15)
#define ZBEE_ZCL_GP_PAIRING_OPTION_ASSIGNED_ALIAS_PRESENT                              (1<<16)
#define ZBEE_ZCL_GP_PAIRING_OPTION_FWD_RADIUS_PRESENT                                  (1<<17)

#define ZBEE_ZCL_GP_RESPONSE_OPTION_APP_ID                                             (7<<0)
#define ZBEE_ZCL_GP_RESPONSE_OPTION_TX_ON_ENDPOINT_MATCH                               (1<<3)

#define ZBEE_ZCL_GP_RESPONSE_TX_CHANNEL                                                (0xf<<0)

#define ZBEE_ZCL_GP_CMD_PC_ACTIONS_ACTION                                              (7<<0)
#define ZBEE_ZCL_GP_CMD_PC_ACTIONS_SEND_GP_PAIRING                                     (1<<3)

#define ZBEE_ZCL_GP_CMD_PC_OPT_APP_ID                                                  (7<<0)
#define ZBEE_ZCL_GP_CMD_PC_OPT_COMMUNICATION_MODE                                      (3<<3)
#define ZBEE_ZCL_GP_CMD_PC_OPT_SEQ_NUMBER_CAP                                          (1<<5)
#define ZBEE_ZCL_GP_CMD_PC_OPT_RX_ON_CAP                                               (1<<6)
#define ZBEE_ZCL_GP_CMD_PC_OPT_FIXED_LOCATION                                          (1<<7)
#define ZBEE_ZCL_GP_CMD_PC_OPT_ASSIGNED_ALIAS                                          (1<<8)
#define ZBEE_ZCL_GP_CMD_PC_OPT_SECURITY_USE                                            (1<<9)
#define ZBEE_ZCL_GP_CMD_PC_OPT_APP_INFO_PRESENT                                        (1<<10)
#define ZBEE_ZCL_GP_COMMUNICATION_MODE_GROUPCAST_PRECOMMISSIONED                       2
#define ZBEE_ZCL_GP_PAIRING_CONFIGURATION_OPTION_COMMUNICATION_MODE_SHIFT              3
#define ZBEE_ZCL_GP_CMD_PC_SECUR_LEVEL                                                 (3<<0)
#define ZBEE_ZCL_GP_CMD_PC_SECUR_KEY_TYPE                                              (7<<2)
#define ZBEE_ZCL_GP_CMD_PC_APP_INFO_MANUF_ID_PRESENT                                   (1<<0)
#define ZBEE_ZCL_GP_CMD_PC_APP_INFO_MODEL_ID_PRESENT                                   (1<<1)
#define ZBEE_ZCL_GP_CMD_PC_APP_INFO_GPD_COMMANDS_PRESENT                               (1<<2)
#define ZBEE_ZCL_GP_CMD_PC_APP_INFO_CLUSTER_LIST_PRESENT                               (1<<3)
#define ZBEE_ZCL_GP_CLUSTER_LIST_LEN_SRV                                               (0xf<<0)
#define ZBEE_ZCL_GP_CLUSTER_LIST_LEN_CLI                                               (0xf<<4)
#define ZBEE_ZCL_GP_CLUSTER_LIST_LEN_CLI_SHIFT                                         4

#define ZBEE_ZCL_GP_PROXY_SINK_TBL_REQ_CMD_APP_ID                                      (0x07<<0)
#define ZBEE_ZCL_GP_PROXY_SINK_TBL_REQ_CMD_REQ_TYPE                                    (0x03<<3)
#define ZBEE_ZCL_GP_PROXY_SINK_TBL_REQ_CMD_REQ_TYPE_SHIFT                              3

#define ZBEE_ZCL_GP_SINK_TBL_OPT_APP_ID                                                (7<<0)
#define ZBEE_ZCL_GP_SINK_TBL_OPT_COMMUNICATION_MODE                                    (3<<3)
#define ZBEE_ZCL_GP_SINK_TBL_OPT_SEQ_NUMBER_CAP                                        (1<<5)
#define ZBEE_ZCL_GP_SINK_TBL_OPT_RX_ON_CAP                                             (1<<6)
#define ZBEE_ZCL_GP_SINK_TBL_OPT_FIXED_LOCATION                                        (1<<7)
#define ZBEE_ZCL_GP_SINK_TBL_OPT_ASSIGNED_ALIAS                                        (1<<8)
#define ZBEE_ZCL_GP_SINK_TBL_OPT_SECURITY_USE                                          (1<<9)

#define ZBEE_ZCL_GP_PROXY_TBL_OPT_APP_ID                                               (7<<0)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_ENTRY_ACTIVE                                         (1<<3)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_ENTRY_VALID                                          (1<<4)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_SEQ_NUMBER_CAP                                       (1<<5)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_LW_UCAST_GPS                                         (1<<6)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_DERIVED_GROUP_GPS                                    (1<<7)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_COMM_GROUP_GPS                                       (1<<8)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_FIRST_TO_FORWARD                                     (1<<9)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_IN_RANGE                                             (1<<10)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_GPD_FIXED                                            (1<<11)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_HAS_ALL_UCAST_ROUTES                                 (1<<12)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_ASSIGNED_ALIAS                                       (1<<13)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_SECURITY_USE                                         (1<<14)
#define ZBEE_ZCL_GP_PROXY_TBL_OPT_OPTIONS_EXTENTIONS                                   (1<<15)

#define ZBEE_ZCL_GP_PROXY_TBL_EXT_OPT_FULL_UCAST_GPS                                   (1<<0)

#define ZBEE_ZCL_GP_SECUR_OPT_SECUR_LEVEL                                              (3<<0)
#define ZBEE_ZCL_GP_SECUR_OPT_SECUR_KEY_TYPE                                           (7<<2)

/* Sink Commissioning Mode command */
#define ZBEE_ZCL_GP_CMD_SINK_COMM_MODE_OPTIONS_FLD_ACTION                              (1<<0)
#define ZBEE_ZCL_GP_CMD_SINK_COMM_MODE_OPTIONS_FLD_INV_GPM_IN_SECUR                    (1<<1)
#define ZBEE_ZCL_GP_CMD_SINK_COMM_MODE_OPTIONS_FLD_INV_GPM_IN_PAIRING                  (1<<2)
#define ZBEE_ZCL_GP_CMD_SINK_COMM_MODE_OPTIONS_FLD_INV_PROXIES                         (1<<3)

/* gppFunctionality attribute */
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GP_FEATURE                                       (1<<0)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_DIRECT_COMM                                      (1<<1)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_DERIVED_GCAST_COMM                               (1<<2)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_PRE_COMMISSIONED_GCAST_COMM                      (1<<3)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_FULL_UCAST_COMM                                  (1<<4)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_LW_UCAST_COMM                                    (1<<5)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_BIDIR_OP                                         (1<<7)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_PROXY_TBL_MAINTENANCE                            (1<<8)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GP_COMMISSIONING                                 (1<<10)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_CT_BASED_COMMISSIONING                           (1<<11)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_MAINTENANCE_OF_GPD                               (1<<12)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GPD_SECUR_LVL_00                                 (1<<13)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GPD_SECUR_LVL_01                                 (1<<14)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GPD_SECUR_LVL_10                                 (1<<15)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GPD_SECUR_LVL_11                                 (1<<16)
#define ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GPD_IEEE_ADDRESS                                 (1<<19)
/* gppActiveFunctionality attribute */
#define ZBEE_ZCL_GP_ATTR_GPP_ACTIVE_FUNC_FLD_GP_FUNCTIONALITY                          (1<<0)

/* gpsFunctionality attribute */
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GP_FEATURE                                       (1<<0)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_DIRECT_COMM                                      (1<<1)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_DERIVED_GCAST_COMM                               (1<<2)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_PRE_COMMISSIONED_GCAST_COMM                      (1<<3)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_FULL_UCAST_COMM                                  (1<<4)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_LW_UCAST_COMM                                    (1<<5)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_PROXIMITY_BIDIR_OP                               (1<<6)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_MULTI_HOP_BIDIR_OP                               (1<<7)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_PROXY_TBL_MAINTENANCE                            (1<<8)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_PROXIMITY_COMMISSIONING                          (1<<9)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_MULTI_HOP_COMMISSIONING                          (1<<10)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_CT_BASED_COMMISSIONING                           (1<<11)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_MAINTENANCE_OF_GPD                               (1<<12)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GPD_SECUR_LVL_00                                 (1<<13)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GPD_SECUR_LVL_01                                 (1<<14)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GPD_SECUR_LVL_10                                 (1<<15)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GPD_SECUR_LVL_11                                 (1<<16)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_SINK_TBL_BASED_GCAST_FORWARDING                  (1<<17)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_TRANSLATION_TABLE                                (1<<18)
#define ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GPD_IEEE_ADDRESS                                 (1<<19)
/* gpsActiveFunctionality attribute */
#define ZBEE_ZCL_GP_ATTR_GPS_ACTIVE_FUNC_FLD_GP_FUNCTIONALITY                          (1<<0)

/* gpsCommissioningExitMode attribute */
#define ZBEE_ZCL_GP_ATTR_GPS_COMM_EXIT_MODE_FLD_ON_COMM_WINDOW_EXPIRE                  (1<<0)
#define ZBEE_ZCL_GP_ATTR_GPS_COMM_EXIT_MODE_FLD_ON_PAIRING_SUCCESS                     (1<<1)
#define ZBEE_ZCL_GP_ATTR_GPS_COMM_EXIT_MODE_FLD_ON_GP_PROXY_COMM_MODE                  (1<<2)

/* gpsCommunicationMode attribute */
#define ZBEE_ZCL_GP_ATTR_GPS_COMMUNICATION_MODE_FLD_MODE                               (3<<0)

/* gpsSecurityLevel attribute */
#define ZBEE_ZCL_GP_ATTR_GPS_SECUR_LVL_FLD_MIN_GPD_SECUR_LVL                           (3<<0)
#define ZBEE_ZCL_GP_ATTR_GPS_SECUR_LVL_FLD_PROTECTION_WITH_GP_LINK_KEY                 (1<<2)
#define ZBEE_ZCL_GP_ATTR_GPS_SECUR_LVL_FLD_INVOLVE_TC                                  (1<<3)

/* Definitions for application IDs. */
#define ZBEE_ZCL_GP_APP_ID_DEFAULT                                                     0x00
#define ZBEE_ZCL_GP_APP_ID_ZGP                                                         0x02

/** Definitions for Request type sub-field of the Options field of the
 *  GP Sink Table Request and GP Proxy Table request commands
 */
#define ZBEE_ZCL_GP_PROXY_SINK_TABLE_REQ_CMD_REQUSET_BY_GPD_ID                          0
#define ZBEE_ZCL_GP_PROXY_SINK_TABLE_REQ_CMD_REQUSET_BY_INDEX                           1

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_gp;

static int hf_zbee_zcl_gp_attr_id;
static int hf_zbee_zcl_gp_srv_rx_cmd_id;
static int hf_zbee_zcl_gp_srv_tx_cmd_id;

static int ett_zbee_zcl_gp;

/* GP_PROXY_COMMISSIONING_MODE */
static int ett_zbee_gp_cmd_proxy_commissioning_mode_options;
static int ett_zbee_gp_cmd_proxy_commissioning_mode_exit_mode;
static int hf_zbee_gp_cmd_proxy_commissioning_mode_options;
static int hf_zbee_gp_cmd_pcm_opt_action;
static int hf_zbee_gp_cmd_pcm_opt_exit_mode;
static int hf_zbee_gp_cmd_pcm_opt_channel_present;
static int hf_zbee_gp_cmd_pcm_opt_unicast_comm;
static int hf_zbee_gp_cmd_proxy_commissioning_mode_exit_mode;
static int hf_zbee_gp_cmd_pcm_exit_mode_on_comm_window_expire;
static int hf_zbee_gp_cmd_pcm_exit_mode_on_pairing_success;
static int hf_zbee_gp_cmd_pcm_exit_mode_on_gp_proxy_comm_mode;
static int hf_zbee_zcl_gp_commissioning_window;
static int hf_zbee_zcl_gp_channel;

/* GP_COMMISSIONING_NOTIFICATION */
static int hf_zbee_gp_cmd_comm_notif_opt_app_id;
static int hf_zbee_gp_cmd_comm_notif_opt_rx_after_tx;
static int hf_zbee_gp_cmd_comm_notif_opt_secur_level;
static int hf_zbee_gp_cmd_comm_notif_opt_secur_key_type;
static int hf_zbee_gp_cmd_comm_notif_opt_secur_fail;
static int hf_zbee_gp_cmd_comm_notif_opt_bidir_cap;
static int hf_zbee_gp_cmd_comm_notif_opt_proxy_info_present;
static int hf_zbee_gp_cmd_commissioning_notification_options;
static int ett_zbee_gp_cmd_commissioning_notification_options;
static int hf_zbee_gp_src_id;
static int hf_zbee_gp_ieee;
static int hf_zbee_gp_endpoint;
static int hf_zbee_gp_secur_frame_counter;
static int hf_zbee_gp_gpd_command_id;
static int hf_zbee_gp_short_addr;
static int hf_zbee_gp_gpp_gpd_link;
static int hf_zbee_gp_mic;
static int ett_zbee_gp_gpp_gpd_link;
static int hf_zbee_gpp_gpd_link_rssi;
static int hf_zbee_gpp_gpd_link_lqi;
static int hf_zbee_gp_gpd_payload_size;


/* GP_NOTIFICATION */
static int hf_zbee_gp_cmd_notification_options;
static int ett_zbee_gp_cmd_notification_options;
static int hf_zbee_gp_cmd_notif_opt_app_id;
static int hf_zbee_gp_cmd_notif_opt_also_unicast;
static int hf_zbee_gp_cmd_notif_opt_also_derived_group;
static int hf_zbee_gp_cmd_notif_opt_also_comm_group;
static int hf_zbee_gp_cmd_notif_opt_secur_level;
static int hf_zbee_gp_cmd_notif_opt_secur_key_type;
static int hf_zbee_gp_cmd_notif_opt_rx_after_tx;
static int hf_zbee_gp_cmd_notif_opt_tx_q_full;
static int hf_zbee_gp_cmd_notif_opt_bidir_cap;
static int hf_zbee_gp_cmd_notif_opt_proxy_info_present;

/* GP_PAIRING */
static int hf_zbee_gp_cmd_pairing_opt_app_id;
static int hf_zbee_gp_cmd_pairing_opt_add_sink;
static int hf_zbee_gp_cmd_pairing_opt_remove_gpd;
static int hf_zbee_gp_cmd_pairing_opt_communication_mode;
static int hf_zbee_gp_cmd_pairing_opt_gpd_fixed;
static int hf_zbee_gp_cmd_pairing_opt_gpd_mac_seq_num_cap;
static int hf_zbee_gp_cmd_pairing_opt_secur_level;
static int hf_zbee_gp_cmd_pairing_opt_secur_key_type;
static int hf_zbee_gp_cmd_pairing_opt_gpd_frame_cnt_present;
static int hf_zbee_gp_cmd_pairing_opt_gpd_secur_key_present;
static int hf_zbee_gp_cmd_pairing_opt_assigned_alias_present;
static int hf_zbee_gp_cmd_pairing_opt_fwd_radius_present;
static int hf_zbee_gp_cmd_pairing_options;
static int ett_zbee_gp_cmd_pairing_options;
static int hf_zbee_gp_sink_ieee;
static int hf_zbee_gp_sink_nwk;
static int hf_zbee_gp_sink_group_id;
static int hf_zbee_gp_device_id;
static int hf_zbee_gp_assigned_alias;
static int hf_zbee_gp_forwarding_radius;
static int hf_zbee_gp_gpd_key;
static int hf_zbee_gp_groupcast_radius;

/* GP Response */
static int hf_zbee_gp_cmd_response_options;
static int ett_zbee_gp_cmd_response_options;
static int hf_zbee_gp_cmd_response_tx_channel;
static int ett_zbee_gp_cmd_response_tx_channel;
static int hf_zbee_gp_cmd_resp_opt_app_id;
static int hf_zbee_gp_cmd_resp_opt_tx_on_ep_match;
static int hf_zbee_gp_tmp_master_short_addr;
static int hf_zbee_gp_cmd_resp_tx_channel;

/* GP_PAIRING_CONFIGURATION */
static int hf_zbee_gp_cmd_pc_actions_action;
static int hf_zbee_gp_cmd_pc_actions_send_gp_pairing;
static int hf_zbee_gp_cmd_pc_opt_app_id;
static int hf_zbee_gp_cmd_pc_opt_communication_mode;
static int hf_zbee_gp_cmd_pc_opt_seq_number_cap;
static int hf_zbee_gp_cmd_px_opt_rx_on_cap;
static int hf_zbee_gp_cmd_pc_opt_fixed_location;
static int hf_zbee_gp_cmd_pc_opt_assigned_alias;
static int hf_zbee_gp_cmd_pc_opt_security_use;
static int hf_zbee_gp_cmd_pc_opt_app_info_present;
static int hf_zbee_gp_cmd_pc_secur_level;
static int hf_zbee_gp_cmd_pc_secur_key_type;
static int hf_zbee_gp_cmd_pc_app_info_manuf_id_present;
static int hf_zbee_gp_cmd_pc_app_info_model_id_present;
static int hf_zbee_gp_cmd_pc_app_info_gpd_commands_present;
static int hf_zbee_gp_cmd_pc_app_info_cluster_list_present;
static int hf_zbee_gp_cmd_pc_actions;
static int ett_zbee_gp_cmd_pc_actions;
static int hf_zbee_gp_cmd_pc_options;
static int ett_zbee_gp_cmd_pc_options;
static int ett_zbee_zcl_gp_group_list;
static int hf_zbee_gp_group_list_len;
static int hf_zbee_gp_group_list_group_id;
static int hf_zbee_gp_group_list_alias;
static int hf_zbee_gp_cmd_pc_secur_options;
static int ett_zbee_gp_cmd_pc_secur_options;
static int hf_zbee_gp_n_paired_endpoints;
static int hf_zbee_gp_paired_endpoint;
static int hf_zbee_gp_cmd_pc_app_info;
static int ett_zbee_gp_cmd_pc_app_info;
static int hf_zbee_zcl_gp_manufacturer_id;
static int hf_zbee_zcl_gp_model_id;
static int hf_zbee_gp_n_gpd_commands;
static int hf_zbee_gp_gpd_command;
static int hf_zbee_gp_n_srv_clusters;
static int hf_zbee_gp_n_cli_clusters;
static int hf_zbee_gp_gpd_cluster_id;
static int ett_zbee_zcl_gp_ep;
static int ett_zbee_zcl_gp_cmds;
static int ett_zbee_zcl_gp_clusters;
static int ett_zbee_zcl_gp_srv_clusters;
static int ett_zbee_zcl_gp_cli_clusters;

/* GP_SINK_TABLE_REQUEST and GP_PROXY_TABLE_REQUEST */
static int ett_zbee_zcl_proxy_sink_tbl_req_options;
static int hf_zbee_zcl_proxy_sink_tbl_req_options;
static int hf_zbee_zcl_proxy_sink_tbl_req_fld_app_id;
static int hf_zbee_zcl_proxy_sink_tbl_req_fld_req_type;
static int hf_zbee_zcl_proxy_sink_tbl_req_index;

/* GP_SINK_TABLE_RESPONSE and GP_PROXY_TABLE_RESPONSE */
static int hf_zbee_zcl_proxy_sink_tbl_resp_status;
static int hf_zbee_zcl_proxy_sink_tbl_resp_entries_total;
static int hf_zbee_zcl_proxy_sink_tbl_resp_start_index;
static int hf_zbee_zcl_proxy_sink_tbl_resp_entries_count;

/* GP SINK_COMMISSIONING_MODE */
static int ett_zbee_zcl_gp_cmd_sink_comm_mode_options;
static int hf_zbee_zcl_gp_cmd_sink_comm_mode_options;

static int hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_action;
static int hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_inv_gpm_in_secur;
static int hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_inv_gpm_in_pairing;
static int hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_inv_proxies;

static int hf_zbee_gp_zcl_cmd_sink_comm_mode_gpm_addr_for_secur;
static int hf_zbee_gp_zcl_cmd_sink_comm_mode_gpm_addr_for_pairing;
static int hf_zbee_gp_zcl_cmd_sink_comm_mode_sink_ep;

/* GP Sink Table Attribute */
static int ett_zbee_gp_sink_tbl;
static int ett_zbee_gp_sink_tbl_entry;
static int ett_zbee_gp_sink_tbl_entry_options;

static int hf_zbee_gp_sink_tbl_length;
static int hf_zbee_gp_sink_tbl_entry_options;

static int hf_zbee_gp_sink_tbl_entry_options_app_id;
static int hf_zbee_gp_sink_tbl_entry_options_comm_mode;
static int hf_zbee_gp_sink_tbl_entry_options_seq_num_cap;
static int hf_zbee_gp_sink_tbl_entry_options_rx_on_cap;
static int hf_zbee_gp_sink_tbl_entry_options_fixed_loc;
static int hf_zbee_gp_sink_tbl_entry_options_assigned_alias;
static int hf_zbee_gp_sink_tbl_entry_options_sec_use;

static int ett_zbee_gp_sec_options;
static int hf_zbee_gp_sec_options;
static int hf_zbee_gp_sec_options_sec_level;
static int hf_zbee_gp_sec_options_sec_key_type;

/* GP Proxy Table Attribute */
static int ett_zbee_gp_proxy_tbl;
static int ett_zbee_gp_proxy_tbl_entry;
static int ett_zbee_gp_proxy_tbl_entry_options;
static int ett_zbee_gp_proxy_tbl_entry_ext_options;

static int hf_zbee_gp_proxy_tbl_length;
static int hf_zbee_gp_proxy_tbl_entry_options;
static int hf_zbee_gp_proxy_tbl_entry_ext_options;

static int hf_zbee_gp_proxy_tbl_entry_options_app_id;
static int hf_zbee_gp_proxy_tbl_entry_options_entry_active;
static int hf_zbee_gp_proxy_tbl_entry_options_entry_valid;
static int hf_zbee_gp_proxy_tbl_entry_options_seq_num_cap;
static int hf_zbee_gp_proxy_tbl_entry_options_lw_ucast_gps;
static int hf_zbee_gp_proxy_tbl_entry_options_derived_group_gps;
static int hf_zbee_gp_proxy_tbl_entry_options_comm_group_gps;
static int hf_zbee_gp_proxy_tbl_entry_options_first_to_forward;
static int hf_zbee_gp_proxy_tbl_entry_options_in_range;
static int hf_zbee_gp_proxy_tbl_entry_options_gpd_fixed;
static int hf_zbee_gp_proxy_tbl_entry_options_has_all_ucast_routes;
static int hf_zbee_gp_proxy_tbl_entry_options_assigned_alias;
static int hf_zbee_gp_proxy_tbl_entry_options_sec_use;
static int hf_zbee_gp_proxy_tbl_entry_options_opt_ext;

static int hf_zbee_gp_proxy_tbl_entry_search_counter;

static int hf_zbee_gp_proxy_tbl_entry_ext_options_full_ucast_gps;

static int ett_zbee_gp_sink_address_list;
static int hf_zbee_gp_sink_address_list_length;

/* GP gppFunctionality Attribute */
static int ett_zbee_zcl_gp_attr_gpp_func;
static int hf_zbee_zcl_gp_attr_gpp_func;

static int hf_zbee_zcl_gp_attr_gpp_func_fld_gp_feature;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_direct_comm;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_derived_gcast_comm;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_pre_commissioned_gcast_comm;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_full_ucast_comm;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_lw_ucast_comm;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_bidir_op;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_proxy_tbl_maintenance;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_gp_commissioning;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_ct_based_commissioning;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_maintenance_of_gpd;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_00;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_01;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_10;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_11;
static int hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_ieee_address;

/* GP gppActiveFunctionality Attribute */
static int ett_zbee_zcl_gp_attr_gpp_active_func;
static int hf_zbee_zcl_gp_attr_gpp_active_func;
static int hf_zbee_zcl_gp_attr_gpp_active_func_fld_gp_functionality;

/* GP gpsFunctionality Attribute */
static int ett_zbee_zcl_gp_attr_gps_func;
static int hf_zbee_zcl_gp_attr_gps_func;

static int hf_zbee_zcl_gp_attr_gps_func_fld_gp_feature;
static int hf_zbee_zcl_gp_attr_gps_func_fld_direct_comm;
static int hf_zbee_zcl_gp_attr_gps_func_fld_derived_gcast_comm;
static int hf_zbee_zcl_gp_attr_gps_func_fld_pre_commissioned_gcast_comm;
static int hf_zbee_zcl_gp_attr_gps_func_fld_full_ucast_comm;
static int hf_zbee_zcl_gp_attr_gps_func_fld_lw_ucast_comm;
static int hf_zbee_zcl_gp_attr_gps_func_fld_proximity_bidir_op;
static int hf_zbee_zcl_gp_attr_gps_func_fld_multi_hop_bidir_op;
static int hf_zbee_zcl_gp_attr_gps_func_fld_proxy_tbl_maintenance;
static int hf_zbee_zcl_gp_attr_gps_func_fld_proximity_commissioning;
static int hf_zbee_zcl_gp_attr_gps_func_fld_multi_hop_commissioning;
static int hf_zbee_zcl_gp_attr_gps_func_fld_ct_based_commissioning;
static int hf_zbee_zcl_gp_attr_gps_func_fld_maintenance_of_gpd;
static int hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_00;
static int hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_01;
static int hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_10;
static int hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_11;
static int hf_zbee_zcl_gp_attr_gps_func_fld_sink_tbl_based_gcast_forwarding;
static int hf_zbee_zcl_gp_attr_gps_func_fld_translation_table;
static int hf_zbee_zcl_gp_attr_gps_func_fld_gpd_ieee_address;

/* GP gppActiveFunctionality Attribute */
static int ett_zbee_zcl_gp_attr_gps_active_func;
static int hf_zbee_zcl_gp_attr_gps_active_func;
static int hf_zbee_zcl_gp_attr_gps_active_func_fld_gp_functionality;

/* GP gpsCommissioningExitMode Attribute */
static int ett_zbee_zcl_gp_attr_gps_comm_exit_mode;
static int hf_zbee_zcl_gp_attr_gps_comm_exit_mode;
static int hf_zbee_zcl_gp_attr_gps_comm_exit_mode_fld_on_comm_window_expire;
static int hf_zbee_zcl_gp_attr_gps_comm_exit_mode_fld_on_pairing_success;
static int hf_zbee_zcl_gp_attr_gps_comm_exit_mode_fld_on_gp_proxy_comm_mode;

/* GP gpsCommunicationMode Attribute */
static int ett_zbee_zcl_gp_attr_gps_communication_mode;
static int hf_zbee_zcl_gp_attr_gps_communication_mode;
static int hf_zbee_zcl_gp_attr_gps_communication_mode_fld_mode;

/* GP gpsSecurityLevel Attribute */
static int ett_zbee_zcl_gp_attr_gps_secur_lvl;
static int hf_zbee_zcl_gp_attr_gps_secur_lvl;
static int hf_zbee_zcl_gp_attr_gps_secur_lvl_fld_min_gpd_secur_lvl;
static int hf_zbee_zcl_gp_attr_gps_secur_lvl_fld_protection_with_gp_link_key;
static int hf_zbee_zcl_gp_attr_gps_secur_lvl_fld_involve_tc;

/* reuse ZGPD command names */
extern value_string_ext zbee_nwk_gp_cmd_names_ext;
/* reuse devices table from ZGPD parser */
extern const value_string zbee_nwk_gp_device_ids_names[];

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_gp(void);
void proto_reg_handoff_zbee_zcl_gp(void);

static dissector_handle_t zgp_handle;


/**
 *      dissect_zbee_zcl_gp_payload
 *
 *      ZigBee ZCL Green Power data payload cluster dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param pinfo  - pointer to packet information fields
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned          payload_size;

    proto_tree_add_item(tree, hf_zbee_gp_gpd_command_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    payload_size = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_gp_gpd_payload_size, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (payload_size != 0 && payload_size != 0xff) {
        tvbuff_t *gtvb = tvb_new_composite();
        bool writable = col_get_writable(pinfo->cinfo, COL_INFO);

        /* remove payload length and put command id instead */
        tvb_composite_append(gtvb, tvb_new_subset_length(tvb, offset-2, 1));
        tvb_composite_append(gtvb, tvb_new_subset_length(tvb, offset, payload_size));
        tvb_composite_finalize(gtvb);
        /* prevent overwriting COL_INFO */
        col_set_writable(pinfo->cinfo, COL_INFO, false);
        call_dissector_only(zgp_handle, gtvb, pinfo, tree, NULL);
        col_set_writable(pinfo->cinfo, COL_INFO, writable);
        offset += payload_size;
    }
    return offset;
}

/**
 *      dissect_zbee_zcl_gp_group_list
 *
 *      ZigBee ZCL Green Power Group List dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *      @param text   - string attached to Group list subtree
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_group_list(tvbuff_t *tvb, proto_tree *tree, unsigned offset, const char* text)
{
    uint8_t len = tvb_get_uint8(tvb, offset);
    proto_tree *gl_tree  = proto_tree_add_subtree_format(tree, tvb, offset, len*4+1,
                               ett_zbee_zcl_gp_group_list, NULL, "%s #%d", text, len);

    proto_tree_add_item(gl_tree, hf_zbee_gp_group_list_len, tvb, offset, 1, ENC_NA);
    offset += 1;
    while (len) {
        proto_tree_add_item(gl_tree, hf_zbee_gp_group_list_group_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(gl_tree, hf_zbee_gp_group_list_alias, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        len--;
    }

    return offset;
} /*dissect_zbee_zcl_gp_group_list*/

/**
 *      dissect_zbee_zcl_gp_sink_address_list
 *
 *      ZigBee ZCL Green Power Sink Address List dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *      @param text   - string attached to Sink Address list subtree
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_sink_address_list(tvbuff_t *tvb, proto_tree *tree, unsigned offset, const char* text)
{
    uint8_t len = tvb_get_uint8(tvb, offset);
    proto_tree *subtree  = proto_tree_add_subtree_format(tree, tvb, offset, len*10+1,
                               ett_zbee_gp_sink_address_list, NULL, "%s #%d", text, len);

    proto_tree_add_item(subtree, hf_zbee_gp_sink_address_list_length, tvb, offset, 1, ENC_NA);
    offset += 1;
    while (len) {
        proto_tree_add_item(subtree, hf_zbee_gp_sink_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(subtree, hf_zbee_gp_sink_nwk, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        len--;
    }

    return offset;
} /*dissect_zbee_zcl_gp_sink_address_list*/

/**
 *      dissect_zbee_zcl_gp_sink_table_entry
 *
 *      ZigBee ZCL Green Power Sink Table entry dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *      @param idx    - entry index
 *
 *      @return 1 if entry parsed, 0 - otherwise.
 */
static int
dissect_zbee_zcl_gp_sink_table_entry(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, unsigned idx)
{
    uint16_t options = 0;
    uint16_t app_id, comm_mode;
    proto_tree *subtree;
    static int * const n_options[] = {
        &hf_zbee_gp_sink_tbl_entry_options_app_id,
        &hf_zbee_gp_sink_tbl_entry_options_comm_mode,
        &hf_zbee_gp_sink_tbl_entry_options_seq_num_cap,
        &hf_zbee_gp_sink_tbl_entry_options_rx_on_cap,
        &hf_zbee_gp_sink_tbl_entry_options_fixed_loc,
        &hf_zbee_gp_sink_tbl_entry_options_assigned_alias,
        &hf_zbee_gp_sink_tbl_entry_options_sec_use,
        NULL
    };
    static int * const n_secur_options[] = {
        &hf_zbee_gp_sec_options_sec_level,
        &hf_zbee_gp_sec_options_sec_key_type,
        NULL
    };

    subtree = proto_tree_add_subtree_format(tree, tvb, *offset, -1, ett_zbee_gp_sink_tbl_entry,
                                            NULL, "Sink Table Entry #%d", idx);

    /* Options - 2 bytes */
    options = tvb_get_uint16(tvb, *offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(subtree, tvb, *offset, hf_zbee_gp_sink_tbl_entry_options,
                           ett_zbee_gp_sink_tbl_entry_options, n_options, ENC_LITTLE_ENDIAN);
    *offset += 2;

    app_id = (options & ZBEE_ZCL_GP_SINK_TBL_OPT_APP_ID) >> ws_ctz(ZBEE_ZCL_GP_SINK_TBL_OPT_APP_ID);
    switch (app_id) {
        case ZBEE_ZCL_GP_APP_ID_DEFAULT:
            /* Add 4 byte SRC ID */
            proto_tree_add_item(subtree, hf_zbee_gp_src_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
            break;
        case ZBEE_ZCL_GP_APP_ID_ZGP:
            /* Add IEEE address and endpoint (9 bytes) */
            proto_tree_add_item(subtree, hf_zbee_gp_ieee, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            *offset += 8;
            proto_tree_add_item(subtree, hf_zbee_gp_endpoint, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;
        default:
            /* Bad entry - stop Sink Table Entry parsing */
            return 0;
    }

    /* Device ID - 1 byte */
    proto_tree_add_item(subtree, hf_zbee_gp_device_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Group list */
    comm_mode = (options & ZBEE_ZCL_GP_SINK_TBL_OPT_COMMUNICATION_MODE) >>
        ws_ctz(ZBEE_ZCL_GP_SINK_TBL_OPT_COMMUNICATION_MODE);
    if (comm_mode == ZBEE_ZCL_GP_COMMUNICATION_MODE_GROUPCAST_PRECOMMISSIONED) {
        *offset = dissect_zbee_zcl_gp_group_list(tvb, subtree, *offset, "GroupList");
    }

    /* GPD Assigned Alias: 2 bytes */
    if (options & ZBEE_ZCL_GP_SINK_TBL_OPT_ASSIGNED_ALIAS) {
        proto_tree_add_item(subtree, hf_zbee_gp_assigned_alias, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }

    /* Groupcast radius: 1 byte */
    proto_tree_add_item(subtree, hf_zbee_gp_groupcast_radius, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Security options: 1 byte */
    if (options & ZBEE_ZCL_GP_SINK_TBL_OPT_SECURITY_USE) {
        proto_tree_add_bitmask(subtree, tvb, *offset, hf_zbee_gp_sec_options,
                               ett_zbee_gp_sec_options, n_secur_options, ENC_NA);
        *offset += 1;
    }

    /* GPD Frame Counter: 4 bytes */
    if ((options & ZBEE_ZCL_GP_SINK_TBL_OPT_SECURITY_USE) || (options & ZBEE_ZCL_GP_SINK_TBL_OPT_SEQ_NUMBER_CAP)) {
        proto_tree_add_item(subtree, hf_zbee_gp_secur_frame_counter, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }

    /* GPD key: 16 bytes */
    if (options & ZBEE_ZCL_GP_SINK_TBL_OPT_SECURITY_USE) {
      proto_tree_add_item(subtree, hf_zbee_gp_gpd_key, tvb, *offset, 16, ENC_NA);
      *offset += 16;
    }

    return 1;
}

/**
 *      dissect_zbee_zcl_gp_sink_table
 *
 *      ZigBee ZCL Green Power Sink Table dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_sink_table(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
    uint16_t sink_tbl_len, n_parsed_octets;
    uint8_t n_tbl_entries;
    proto_tree *sink_tbl_tree;

    n_parsed_octets = 0;
    n_tbl_entries = 0;
    sink_tbl_len = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

    sink_tbl_tree = proto_tree_add_subtree_format(tree, tvb, offset, sink_tbl_len,
                         ett_zbee_gp_sink_tbl, NULL, "Sink Table: length = %d", sink_tbl_len);
    proto_tree_add_item(sink_tbl_tree, hf_zbee_gp_sink_tbl_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (sink_tbl_len == 0) {
        return offset;
    }

    while (n_parsed_octets < sink_tbl_len) {
        unsigned old_offset = offset;
        if (dissect_zbee_zcl_gp_sink_table_entry(tvb, sink_tbl_tree, &offset, n_tbl_entries + 1)) {
            n_parsed_octets += offset - old_offset;
        }
        else {
            /* Bad Sink Table Entry - stop Sink Table attribute dissection */
            break;
        }

        ++n_tbl_entries;
    }

    return offset;
} /*dissect_zbee_zcl_gp_sink_table*/

/**
 *      dissect_zbee_zcl_gp_proxy_table_entry
 *
 *      ZigBee ZCL Green Power Proxy Table entry dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *      @param idx    - entry index
 *
 *      @return 1 if entry parsed, 0 - otherwise.
 */
static int
dissect_zbee_zcl_gp_proxy_table_entry(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, unsigned idx)
{
    uint16_t options = 0;
    uint16_t ext_options = 0;
    uint16_t app_id;
    proto_tree *subtree;
    static int * const n_options[] = {
        &hf_zbee_gp_proxy_tbl_entry_options_app_id,
        &hf_zbee_gp_proxy_tbl_entry_options_entry_active,
        &hf_zbee_gp_proxy_tbl_entry_options_entry_valid,
        &hf_zbee_gp_proxy_tbl_entry_options_seq_num_cap,
        &hf_zbee_gp_proxy_tbl_entry_options_lw_ucast_gps,
        &hf_zbee_gp_proxy_tbl_entry_options_derived_group_gps,
        &hf_zbee_gp_proxy_tbl_entry_options_comm_group_gps,
        &hf_zbee_gp_proxy_tbl_entry_options_first_to_forward,
        &hf_zbee_gp_proxy_tbl_entry_options_in_range,
        &hf_zbee_gp_proxy_tbl_entry_options_gpd_fixed,
        &hf_zbee_gp_proxy_tbl_entry_options_has_all_ucast_routes,
        &hf_zbee_gp_proxy_tbl_entry_options_assigned_alias,
        &hf_zbee_gp_proxy_tbl_entry_options_sec_use,
        &hf_zbee_gp_proxy_tbl_entry_options_opt_ext,
        NULL
    };
    static int * const n_ext_options[] = {
        &hf_zbee_gp_proxy_tbl_entry_ext_options_full_ucast_gps,
        NULL
    };
    static int * const n_secur_options[] = {
        &hf_zbee_gp_sec_options_sec_level,
        &hf_zbee_gp_sec_options_sec_key_type,
        NULL
    };

    subtree = proto_tree_add_subtree_format(tree, tvb, *offset, -1,
                  ett_zbee_gp_proxy_tbl_entry, NULL, "Proxy Table Entry #%d", idx);

    /* Options - 2 bytes */
    options = tvb_get_uint16(tvb, *offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(subtree, tvb, *offset, hf_zbee_gp_proxy_tbl_entry_options,
                           ett_zbee_gp_proxy_tbl_entry_options, n_options, ENC_LITTLE_ENDIAN);
    *offset += 2;

    app_id = (options & ZBEE_ZCL_GP_PROXY_TBL_OPT_APP_ID) >> ws_ctz(ZBEE_ZCL_GP_PROXY_TBL_OPT_APP_ID);
    switch (app_id) {
        case ZBEE_ZCL_GP_APP_ID_DEFAULT:
            /* Add 4 byte SRC ID */
            proto_tree_add_item(subtree, hf_zbee_gp_src_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
            break;
        case ZBEE_ZCL_GP_APP_ID_ZGP:
            /* Add IEEE address and endpoint (9 bytes) */
            proto_tree_add_item(subtree, hf_zbee_gp_ieee, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            *offset += 8;
            proto_tree_add_item(subtree, hf_zbee_gp_endpoint, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;
        default:
            /* Bad entry - stop Proxy Table entry parsing */
            return 0;
    }


    /* Assigned Alias - 2 bytes */
    if (options & ZBEE_ZCL_GP_PROXY_TBL_OPT_ASSIGNED_ALIAS) {
        proto_tree_add_item(subtree, hf_zbee_gp_assigned_alias, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }

    /* Security Options - 1 byte */
    if (options & ZBEE_ZCL_GP_PROXY_TBL_OPT_SECURITY_USE) {
        proto_tree_add_bitmask(subtree, tvb, *offset, hf_zbee_gp_sec_options,
                               ett_zbee_gp_sec_options, n_secur_options, ENC_NA);
        *offset += 1;
    }

    /* GPD Frame Counter: 4 bytes */
    if ((options & ZBEE_ZCL_GP_PROXY_TBL_OPT_SECURITY_USE) || (options & ZBEE_ZCL_GP_PROXY_TBL_OPT_SEQ_NUMBER_CAP)) {
        proto_tree_add_item(subtree, hf_zbee_gp_secur_frame_counter, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }

    /* GPD key: 16 bytes */
    if (options & ZBEE_ZCL_GP_PROXY_TBL_OPT_SECURITY_USE) {
      proto_tree_add_item(subtree, hf_zbee_gp_gpd_key, tvb, *offset, 16, ENC_NA);
      *offset += 16;
    }

    if (options & ZBEE_ZCL_GP_PROXY_TBL_OPT_LW_UCAST_GPS) {
        *offset = dissect_zbee_zcl_gp_sink_address_list(tvb, subtree, *offset, "Lightweight Sink Address list");
    }

    /* Sink Group list */
    if (options & ZBEE_ZCL_GP_PROXY_TBL_OPT_COMM_GROUP_GPS) {
        *offset = dissect_zbee_zcl_gp_group_list(tvb, subtree, *offset, "Sink GroupList");
    }

    /* Groupcast radius: 1 byte */
    proto_tree_add_item(subtree, hf_zbee_gp_groupcast_radius, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Search Counter: 1 byte */
    if (!(options & ZBEE_ZCL_GP_PROXY_TBL_OPT_ENTRY_ACTIVE) || !(options & ZBEE_ZCL_GP_PROXY_TBL_OPT_ENTRY_VALID)) {
        proto_tree_add_item(subtree, hf_zbee_gp_proxy_tbl_entry_search_counter, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }

    /* Extended Options: 2 bytes */
    if (options & ZBEE_ZCL_GP_PROXY_TBL_OPT_OPTIONS_EXTENTIONS) {
      ext_options = tvb_get_uint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      proto_tree_add_bitmask(subtree, tvb, *offset, hf_zbee_gp_proxy_tbl_entry_ext_options,
                             ett_zbee_gp_proxy_tbl_entry_ext_options, n_ext_options, ENC_LITTLE_ENDIAN);
      *offset += 1;
    }

    /* Full unicast sink address list */
    if (ext_options & ZBEE_ZCL_GP_PROXY_TBL_EXT_OPT_FULL_UCAST_GPS) {
        *offset = dissect_zbee_zcl_gp_sink_address_list(tvb, subtree, *offset, "Full unicast Sink Address list");
    }

    return 1;
}

/**
 *      dissect_zbee_zcl_gp_proxy_table
 *
 *      ZigBee ZCL Green Power Proxy Table dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_proxy_table(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
    uint16_t proxy_tbl_len, n_parsed_octets;
    uint8_t n_tbl_entries;
    proto_tree *proxy_tbl_tree;

    n_parsed_octets = 0;
    n_tbl_entries = 0;
    proxy_tbl_len = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

    proxy_tbl_tree = proto_tree_add_subtree_format(tree, tvb, offset, proxy_tbl_len,
                         ett_zbee_gp_proxy_tbl, NULL, "Proxy Table: length = %d", proxy_tbl_len);
    proto_tree_add_item(proxy_tbl_tree, hf_zbee_gp_proxy_tbl_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (proxy_tbl_len == 0) {
        return offset;
    }

    while (n_parsed_octets < proxy_tbl_len) {
        unsigned old_offset = offset;
        if (dissect_zbee_zcl_gp_proxy_table_entry(tvb, proxy_tbl_tree, &offset, n_tbl_entries + 1)) {
            n_parsed_octets += offset - old_offset;
        }
        else {
            /* Bad Proxy Table entry - stop Proxy Table attribute dissection */
            break;
        }

        ++n_tbl_entries;
    }

    return offset;
} /*dissect_zbee_zcl_gp_proxy_table*/

/**
 *      dissect_zbee_zcl_gp_attr_gpp_functionality
 *
 *      ZigBee ZCL Green Power gppFunctionality dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_attr_gpp_functionality(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
    static int * const n_fields[] = {
        &hf_zbee_zcl_gp_attr_gpp_func_fld_gp_feature,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_direct_comm,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_derived_gcast_comm,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_pre_commissioned_gcast_comm,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_full_ucast_comm,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_lw_ucast_comm,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_bidir_op,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_proxy_tbl_maintenance,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_gp_commissioning,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_ct_based_commissioning,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_maintenance_of_gpd,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_00,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_01,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_10,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_11,
        &hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_ieee_address,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_zcl_gp_attr_gpp_func,
                           ett_zbee_zcl_gp_attr_gpp_func, n_fields, ENC_LITTLE_ENDIAN);
    offset += 3;

    return offset;
} /*dissect_zbee_zcl_gp_attr_gpp_functionality*/

/**
 *      dissect_zbee_zcl_gp_attr_gpp_active_functionality
 *
 *      ZigBee ZCL Green Power gppActiveFunctionality dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_attr_gpp_active_functionality(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
    static int * const n_fields[] = {
        &hf_zbee_zcl_gp_attr_gpp_active_func_fld_gp_functionality,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_zcl_gp_attr_gpp_active_func,
                           ett_zbee_zcl_gp_attr_gpp_active_func, n_fields, ENC_LITTLE_ENDIAN);
    offset += 3;

    return offset;
} /*dissect_zbee_zcl_gp_attr_gpp_active_functionality*/

/**
 *      dissect_zbee_zcl_gp_attr_gps_functionality
 *
 *      ZigBee ZCL Green Power gpsFunctionality dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_attr_gps_functionality(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
    static int * const n_fields[] = {
        &hf_zbee_zcl_gp_attr_gps_func_fld_gp_feature,
        &hf_zbee_zcl_gp_attr_gps_func_fld_direct_comm,
        &hf_zbee_zcl_gp_attr_gps_func_fld_derived_gcast_comm,
        &hf_zbee_zcl_gp_attr_gps_func_fld_pre_commissioned_gcast_comm,
        &hf_zbee_zcl_gp_attr_gps_func_fld_full_ucast_comm,
        &hf_zbee_zcl_gp_attr_gps_func_fld_lw_ucast_comm,
        &hf_zbee_zcl_gp_attr_gps_func_fld_proximity_bidir_op,
        &hf_zbee_zcl_gp_attr_gps_func_fld_multi_hop_bidir_op,
        &hf_zbee_zcl_gp_attr_gps_func_fld_proxy_tbl_maintenance,
        &hf_zbee_zcl_gp_attr_gps_func_fld_proximity_commissioning,
        &hf_zbee_zcl_gp_attr_gps_func_fld_multi_hop_commissioning,
        &hf_zbee_zcl_gp_attr_gps_func_fld_ct_based_commissioning,
        &hf_zbee_zcl_gp_attr_gps_func_fld_maintenance_of_gpd,
        &hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_00,
        &hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_01,
        &hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_10,
        &hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_11,
        &hf_zbee_zcl_gp_attr_gps_func_fld_sink_tbl_based_gcast_forwarding,
        &hf_zbee_zcl_gp_attr_gps_func_fld_translation_table,
        &hf_zbee_zcl_gp_attr_gps_func_fld_gpd_ieee_address,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_zcl_gp_attr_gps_func,
                           ett_zbee_zcl_gp_attr_gps_func, n_fields, ENC_LITTLE_ENDIAN);
    offset += 3;

    return offset;
} /*dissect_zbee_zcl_gp_attr_gps_functionality*/

/**
 *      dissect_zbee_zcl_gp_attr_gps_active_functionality
 *
 *      ZigBee ZCL Green Power gpsActiveFunctionality dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_attr_gps_active_functionality(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
    static int * const n_fields[] = {
        &hf_zbee_zcl_gp_attr_gps_active_func_fld_gp_functionality,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_zcl_gp_attr_gps_active_func,
                           ett_zbee_zcl_gp_attr_gps_active_func, n_fields, ENC_LITTLE_ENDIAN);
    offset += 3;

    return offset;
} /*dissect_zbee_zcl_gp_attr_gps_active_functionality*/

/**
 *      dissect_zbee_zcl_gp_attr_gps_communication_mode
 *
 *      ZigBee ZCL Green Power gpsCommunicationMode dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_attr_gps_communication_mode(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
    static int * const n_fields[] = {
        &hf_zbee_zcl_gp_attr_gps_communication_mode_fld_mode,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_zcl_gp_attr_gps_communication_mode,
                           ett_zbee_zcl_gp_attr_gps_communication_mode, n_fields, ENC_NA);
    offset += 1;

    return offset;
} /*dissect_zbee_zcl_gp_attr_gps_communication_mode*/

/**
 *      dissect_zbee_zcl_gp_attr_gps_comm_exit_mode
 *
 *      ZigBee ZCL Green Power gpsCommissioningExitMode dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_attr_gps_comm_exit_mode(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
    static int * const n_fields[] = {
        &hf_zbee_zcl_gp_attr_gps_comm_exit_mode_fld_on_comm_window_expire,
        &hf_zbee_zcl_gp_attr_gps_comm_exit_mode_fld_on_pairing_success,
        &hf_zbee_zcl_gp_attr_gps_comm_exit_mode_fld_on_gp_proxy_comm_mode,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_zcl_gp_attr_gps_comm_exit_mode,
                           ett_zbee_zcl_gp_attr_gps_comm_exit_mode, n_fields, ENC_NA);
    offset += 1;

    return offset;
} /*dissect_zbee_zcl_gp_attr_gps_comm_exit_mode*/

/**
 *      dissect_zbee_zcl_gp_attr_gps_secur_lvl
 *
 *      ZigBee ZCL Green Power gpsSecurityLevel dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param offset - offset in a buffer
 *
 *      @return new offset.
 */
static int
dissect_zbee_zcl_gp_attr_gps_secur_lvl(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
    static int * const n_fields[] = {
        &hf_zbee_zcl_gp_attr_gps_secur_lvl_fld_min_gpd_secur_lvl,
        &hf_zbee_zcl_gp_attr_gps_secur_lvl_fld_protection_with_gp_link_key,
        &hf_zbee_zcl_gp_attr_gps_secur_lvl_fld_involve_tc,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_zcl_gp_attr_gps_secur_lvl,
                           ett_zbee_zcl_gp_attr_gps_secur_lvl, n_fields, ENC_NA);
    offset += 1;

    return offset;
} /*dissect_zbee_zcl_gp_attr_gps_secur_lvl*/

/**
 *      dissect_zcl_gp_proxy_sink_table_request
 *
 *      ZigBee ZCL Green Power cluster dissector for Proxy Table Request
 *      and Sink Table Request commands
 *
 *      @param tree      - pointer to data tree Wireshark uses to display packet.
 *      @param tvb       - pointer to buffer containing raw packet.
 *      @param offset    - pointer to buffer offset
 */
static void
dissect_zcl_gp_proxy_sink_table_request(proto_tree *tree, tvbuff_t *tvb, unsigned *offset)
{
    /* get Options field */
    uint8_t options = tvb_get_uint8(tvb, *offset);
    uint8_t app_id, req_type;
    static int * const n_options[] = {
        &hf_zbee_zcl_proxy_sink_tbl_req_fld_app_id,
        &hf_zbee_zcl_proxy_sink_tbl_req_fld_req_type,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_proxy_sink_tbl_req_options,
                           ett_zbee_zcl_proxy_sink_tbl_req_options, n_options, ENC_NA);
    *offset += 1;
    app_id = options & ZBEE_ZCL_GP_PROXY_SINK_TBL_REQ_CMD_APP_ID;
    req_type = (options & ZBEE_ZCL_GP_PROXY_SINK_TBL_REQ_CMD_REQ_TYPE) >>
        ZBEE_ZCL_GP_PROXY_SINK_TBL_REQ_CMD_REQ_TYPE_SHIFT;
    if (req_type == ZBEE_ZCL_GP_PROXY_SINK_TABLE_REQ_CMD_REQUSET_BY_GPD_ID) {
        /* Include GPD ID and/or Endpoint */
        if (app_id == ZBEE_ZCL_GP_APP_ID_DEFAULT) {
            /* App_id = 000: GPD SRC ID only */
            proto_tree_add_item(tree, hf_zbee_gp_src_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
        }
        else if (app_id == ZBEE_ZCL_GP_APP_ID_ZGP) {
            /* App_id = 010: MAC address + Endpoint */
            proto_tree_add_item(tree, hf_zbee_gp_ieee, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            *offset += 8;
            proto_tree_add_item(tree, hf_zbee_gp_endpoint, tvb, *offset, 1, ENC_NA);
            *offset += 1;
        }
    }
    else if (req_type == ZBEE_ZCL_GP_PROXY_SINK_TABLE_REQ_CMD_REQUSET_BY_INDEX) {
        /* Include index only */
        proto_tree_add_item(tree, hf_zbee_zcl_proxy_sink_tbl_req_index, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }
} /*dissect_zcl_gp_proxy_sink_table_request*/

/**
 *      dissect_zcl_gp_proxy_sink_table_response
 *
 *      ZigBee ZCL Green Power cluster dissector for Proxy Table response
 *      and Sink Table Request commands
 *
 *      @param tree      - pointer to data tree Wireshark uses to display packet.
 *      @param tvb       - pointer to buffer containing raw packet.
 *      @param offset    - pointer to buffer offset
 *      @param attr_id   - attribute (should be ZBEE_ZCL_ATTR_GPS_SINK_TABLE or
 *                         ZBEE_ZCL_ATTR_GPP_PROXY_TABLE) that will be reported
 */
static void
dissect_zcl_gp_proxy_sink_table_response(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id)
{
    uint8_t entries_count, start_index;
    unsigned i, stop;

    if ( !((attr_id == ZBEE_ZCL_ATTR_GPS_SINK_TABLE) || (attr_id == ZBEE_ZCL_ATTR_GPP_PROXY_TABLE)) ) {
        return;
    }

    proto_tree_add_item(tree, hf_zbee_zcl_proxy_sink_tbl_resp_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_proxy_sink_tbl_resp_entries_total, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    start_index = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_proxy_sink_tbl_resp_start_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    entries_count = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_proxy_sink_tbl_resp_entries_count, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    for (i = 0, stop = 0; i < entries_count && !stop; i++) {
        switch (attr_id) {
            case ZBEE_ZCL_ATTR_GPS_SINK_TABLE:
                stop = !dissect_zbee_zcl_gp_sink_table_entry(tvb, tree, (unsigned*) offset, start_index + i);
                break;
            case ZBEE_ZCL_ATTR_GPP_PROXY_TABLE:
                stop = !dissect_zbee_zcl_gp_proxy_table_entry(tvb, tree, (unsigned*) offset, start_index + i);
                break;
        }
    }
} /*dissect_zcl_gp_proxy_sink_table_response*/

/**
 *      dissect_zcl_gp_sink_comm_mode
 *
 *      ZigBee ZCL Green Power cluster dissector for Sink Commissioning Mode
 *      and Sink Table Request commands
 *
 *      @param tree      - pointer to data tree Wireshark uses to display packet.
 *      @param tvb       - pointer to buffer containing raw packet.
 *      @param offset    - pointer to buffer offset
 */
static void
dissect_zcl_gp_sink_comm_mode(proto_tree *tree, tvbuff_t *tvb, unsigned *offset)
{
    static int * const n_options[] = {
        &hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_action,
        &hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_inv_gpm_in_secur,
        &hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_inv_gpm_in_pairing,
        &hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_inv_proxies,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_gp_cmd_sink_comm_mode_options,
                           ett_zbee_zcl_gp_cmd_sink_comm_mode_options, n_options, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_gp_zcl_cmd_sink_comm_mode_gpm_addr_for_secur, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_gp_zcl_cmd_sink_comm_mode_gpm_addr_for_pairing, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_gp_zcl_cmd_sink_comm_mode_sink_ep, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_gp_sink_comm_mode*/

/**
 *      dissect_zbee_zcl_gp
 *
 *      ZigBee ZCL Green Power cluster dissector for wireshark.
 *
 *      @param tvb    - pointer to buffer containing raw packet.
 *      @param pinfo  - pointer to packet information fields
 *      @param tree   - pointer to data tree Wireshark uses to display packet.
 *      @param data   - pointer to ZCL packet structure.
 *
 *      @return length of parsed data.
 */
static int
dissect_zbee_zcl_gp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    static int * const gpp_gpd_link[] = {
        &hf_zbee_gpp_gpd_link_rssi,
        &hf_zbee_gpp_gpd_link_lqi,
        NULL
    };

    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
                        val_to_str_const(cmd_id, zbee_zcl_gp_srv_rx_cmd_names, "Unknown Command"),
                        zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_gp_srv_rx_cmd_id, tvb, offset, 1, ENC_NA);
        offset++;

        /* Handle the command dissection. */
        switch (cmd_id) {
            case ZBEE_CMD_ID_GP_NOTIFICATION:
            {
                static int * const n_options[] = {
                    &hf_zbee_gp_cmd_notif_opt_app_id,
                    &hf_zbee_gp_cmd_notif_opt_also_unicast,
                    &hf_zbee_gp_cmd_notif_opt_also_derived_group,
                    &hf_zbee_gp_cmd_notif_opt_also_comm_group,
                    &hf_zbee_gp_cmd_notif_opt_secur_level,
                    &hf_zbee_gp_cmd_notif_opt_secur_key_type,
                    &hf_zbee_gp_cmd_notif_opt_rx_after_tx,
                    &hf_zbee_gp_cmd_notif_opt_tx_q_full,
                    &hf_zbee_gp_cmd_notif_opt_bidir_cap,
                    &hf_zbee_gp_cmd_notif_opt_proxy_info_present,
                    NULL
                };
                uint16_t options = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

                proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_notification_options,
                                       ett_zbee_gp_cmd_notification_options, n_options, ENC_LITTLE_ENDIAN);
                offset += 2;
                if ((options & ZBEE_ZCL_GP_NOTIFICATION_OPTION_APP_ID) == 0) {
                    proto_tree_add_item(tree, hf_zbee_gp_src_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
                else {
                    proto_tree_add_item(tree, hf_zbee_gp_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                    offset += 8;
                    proto_tree_add_item(tree, hf_zbee_gp_endpoint, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
                proto_tree_add_item(tree, hf_zbee_gp_secur_frame_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                offset = dissect_zbee_zcl_gp_payload(tvb, pinfo, tree, offset);

                if (options & ZBEE_ZCL_GP_NOTIFICATION_OPTION_PROXY_INFO_PRESENT) {
                    proto_tree_add_item(tree, hf_zbee_gp_short_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_gpp_gpd_link,
                                           ett_zbee_gp_gpp_gpd_link,
                                           gpp_gpd_link, ENC_LITTLE_ENDIAN);
                    offset += 1;
                }
                break;
            }

            case ZBEE_CMD_ID_GP_PAIRING_SEARCH:
            case ZBEE_CMD_ID_GP_TUNNELING_STOP:
                /* TODO: add commands parse */
                break;

            case ZBEE_CMD_ID_GP_COMMISSIONING_NOTIFICATION:
            {
                static int * const commn_options[] = {
                    &hf_zbee_gp_cmd_comm_notif_opt_app_id,
                    &hf_zbee_gp_cmd_comm_notif_opt_rx_after_tx,
                    &hf_zbee_gp_cmd_comm_notif_opt_secur_level,
                    &hf_zbee_gp_cmd_comm_notif_opt_secur_key_type,
                    &hf_zbee_gp_cmd_comm_notif_opt_secur_fail,
                    &hf_zbee_gp_cmd_comm_notif_opt_bidir_cap,
                    &hf_zbee_gp_cmd_comm_notif_opt_proxy_info_present,
                    NULL
                };
                uint16_t options = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

                proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_commissioning_notification_options,
                                       ett_zbee_gp_cmd_commissioning_notification_options, commn_options, ENC_LITTLE_ENDIAN);
                offset += 2;
                if ((options & ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_APP_ID) == 0) {
                    proto_tree_add_item(tree, hf_zbee_gp_src_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
                else {
                    proto_tree_add_item(tree, hf_zbee_gp_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                    offset += 8;
                    proto_tree_add_item(tree, hf_zbee_gp_endpoint, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
                proto_tree_add_item(tree, hf_zbee_gp_secur_frame_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                offset = dissect_zbee_zcl_gp_payload(tvb, pinfo, tree, offset);

                if (options & ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_PROXY_INFO_PRESENT) {
                    proto_tree_add_item(tree, hf_zbee_gp_short_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_gpp_gpd_link,
                                           ett_zbee_gp_gpp_gpd_link,
                                           gpp_gpd_link, ENC_LITTLE_ENDIAN);
                    offset += 1;
                }
                if (options & ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_SECUR_FAILED) {
                    proto_tree_add_item(tree, hf_zbee_gp_mic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
                break;
            }

            case ZBEE_CMD_ID_GP_PAIRING_CONFIGURATION:
            {
                static int * const pc_actions[] = {
                    &hf_zbee_gp_cmd_pc_actions_action,
                    &hf_zbee_gp_cmd_pc_actions_send_gp_pairing,
                    NULL
                };
                static int * const pc_options[] = {
                    &hf_zbee_gp_cmd_pc_opt_app_id,
                    &hf_zbee_gp_cmd_pc_opt_communication_mode,
                    &hf_zbee_gp_cmd_pc_opt_seq_number_cap,
                    &hf_zbee_gp_cmd_px_opt_rx_on_cap,
                    &hf_zbee_gp_cmd_pc_opt_fixed_location,
                    &hf_zbee_gp_cmd_pc_opt_assigned_alias,
                    &hf_zbee_gp_cmd_pc_opt_security_use,
                    &hf_zbee_gp_cmd_pc_opt_app_info_present,
                    NULL
                };
                uint16_t options;

                proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_pc_actions,
                                       ett_zbee_gp_cmd_pc_actions, pc_actions, ENC_NA);
                offset += 1;

                options = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

                proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_pc_options,
                                       ett_zbee_gp_cmd_pc_options, pc_options, ENC_LITTLE_ENDIAN);
                offset += 2;

                if ((options & ZBEE_ZCL_GP_CMD_PC_OPT_APP_ID) == 0) {
                    proto_tree_add_item(tree, hf_zbee_gp_src_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
                else {
                    proto_tree_add_item(tree, hf_zbee_gp_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                    offset += 8;
                    proto_tree_add_item(tree, hf_zbee_gp_endpoint, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                proto_tree_add_item(tree, hf_zbee_gp_device_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (((options & ZBEE_ZCL_GP_CMD_PC_OPT_COMMUNICATION_MODE) >> ZBEE_ZCL_GP_PAIRING_CONFIGURATION_OPTION_COMMUNICATION_MODE_SHIFT)
                    == ZBEE_ZCL_GP_COMMUNICATION_MODE_GROUPCAST_PRECOMMISSIONED) {
                    uint8_t     len = tvb_get_uint8(tvb, offset);
                    proto_tree  *gl_tree  = proto_tree_add_subtree_format(tree, tvb, offset, len*4+1, ett_zbee_zcl_gp_group_list, NULL, "GroupList #%d", len);

                    proto_tree_add_item(gl_tree, hf_zbee_gp_group_list_len, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    while (len)
                    {
                        proto_tree_add_item(gl_tree, hf_zbee_gp_group_list_group_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(gl_tree, hf_zbee_gp_group_list_alias, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                        len--;
                    }
                }

                if (options & ZBEE_ZCL_GP_CMD_PC_OPT_ASSIGNED_ALIAS) {
                    proto_tree_add_item(tree, hf_zbee_gp_assigned_alias, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }

                proto_tree_add_item(tree, hf_zbee_gp_forwarding_radius, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (options & ZBEE_ZCL_GP_CMD_PC_OPT_SECURITY_USE) {
                    static int * const secur_options[] = {
                        &hf_zbee_gp_cmd_pc_secur_level,
                        &hf_zbee_gp_cmd_pc_secur_key_type,
                        NULL
                    };
                    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_pc_secur_options,
                                           ett_zbee_gp_cmd_pc_secur_options, secur_options, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(tree, hf_zbee_gp_secur_frame_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(tree, hf_zbee_gp_gpd_key, tvb, offset, 16, ENC_NA);
                    offset += 16;
                }
                {
                    uint8_t n_paired_endpoints = tvb_get_uint8(tvb, offset);
                    proto_tree  *ep_tree  = proto_tree_add_subtree_format(tree, tvb, offset, n_paired_endpoints+1, ett_zbee_zcl_gp_ep, NULL, "Paired Endpoints #%d", n_paired_endpoints);
                    proto_tree_add_item(ep_tree, hf_zbee_gp_n_paired_endpoints, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    if (n_paired_endpoints != 0 && n_paired_endpoints != 0xfd
                        && n_paired_endpoints != 0xfe && n_paired_endpoints != 0xff)
                    {
                        while (n_paired_endpoints)
                        {
                            proto_tree_add_item(ep_tree, hf_zbee_gp_paired_endpoint, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            n_paired_endpoints--;
                        }
                    }
                }
                if (options & ZBEE_ZCL_GP_CMD_PC_OPT_APP_INFO_PRESENT) {
                    static int * const app_info[] = {
                        &hf_zbee_gp_cmd_pc_app_info_manuf_id_present,
                        &hf_zbee_gp_cmd_pc_app_info_model_id_present,
                        &hf_zbee_gp_cmd_pc_app_info_gpd_commands_present,
                        &hf_zbee_gp_cmd_pc_app_info_cluster_list_present,
                        NULL
                    };
                    uint8_t appi = tvb_get_uint8(tvb, offset);

                    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_pc_app_info,
                                           ett_zbee_gp_cmd_pc_app_info, app_info, ENC_NA);
                    offset += 1;
                    if (appi & ZBEE_ZCL_GP_CMD_PC_APP_INFO_MANUF_ID_PRESENT) {
                        proto_tree_add_item(tree, hf_zbee_zcl_gp_manufacturer_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                    }
                    if (appi & ZBEE_ZCL_GP_CMD_PC_APP_INFO_MODEL_ID_PRESENT) {
                        proto_tree_add_item(tree, hf_zbee_zcl_gp_model_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                    }
                    if (appi & ZBEE_ZCL_GP_CMD_PC_APP_INFO_GPD_COMMANDS_PRESENT) {
                        uint8_t n_commands = tvb_get_uint8(tvb, offset);
                        proto_tree  *c_tree  = proto_tree_add_subtree_format(tree, tvb, offset, n_commands+1, ett_zbee_zcl_gp_cmds, NULL, "GPD CommandID list #%d", n_commands);
                        proto_tree_add_item(c_tree, hf_zbee_gp_n_gpd_commands, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        while (n_commands)
                        {
                            proto_tree_add_item(c_tree, hf_zbee_gp_gpd_command, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            n_commands--;
                        }
                    }
                    if (appi & ZBEE_ZCL_GP_CMD_PC_APP_INFO_CLUSTER_LIST_PRESENT) {
                        uint8_t n = tvb_get_uint8(tvb, offset);
                        uint8_t n_srv_clusters = n & ZBEE_ZCL_GP_CLUSTER_LIST_LEN_SRV;
                        uint8_t n_cli_clusters = (n & ZBEE_ZCL_GP_CLUSTER_LIST_LEN_CLI) >> ZBEE_ZCL_GP_CLUSTER_LIST_LEN_CLI_SHIFT;
                        proto_tree  *cl_tree  = proto_tree_add_subtree_format(tree, tvb, offset, n*2+1, ett_zbee_zcl_gp_clusters, NULL, "Cluster List #%d/%d", n_srv_clusters, n_cli_clusters);
                        proto_tree_add_item(cl_tree, hf_zbee_gp_n_srv_clusters, tvb, offset, 1, ENC_NA);
                        proto_tree_add_item(cl_tree, hf_zbee_gp_n_cli_clusters, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        if (n_srv_clusters)
                        {
                            proto_tree  *s_tree  = proto_tree_add_subtree_format(cl_tree, tvb, offset, n_srv_clusters*2, ett_zbee_zcl_gp_srv_clusters, NULL, "Server clusters #%d", n_srv_clusters);
                            while (n_srv_clusters)
                            {
                                proto_tree_add_item(s_tree, hf_zbee_gp_gpd_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                                offset += 2;
                                n_srv_clusters--;
                            }
                        }
                        if (n_cli_clusters)
                        {
                            proto_tree  *c_tree  = proto_tree_add_subtree_format(cl_tree, tvb, offset, n_cli_clusters*2, ett_zbee_zcl_gp_cli_clusters, NULL, "Client clusters #%d", n_cli_clusters);
                            while (n_cli_clusters)
                            {
                                proto_tree_add_item(c_tree, hf_zbee_gp_gpd_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                                offset += 2;
                                n_cli_clusters--;
                            }
                        }
                    }
                }
                break;
            }

            case ZBEE_CMD_ID_GP_SINK_COMMISSIONING_MODE:
                dissect_zcl_gp_sink_comm_mode(tree, tvb, &offset);
                break;
            case ZBEE_CMD_ID_GP_TRANSLATION_TABLE_UPDATE_COMMAND:
            case ZBEE_CMD_ID_GP_TRANSLATION_TABLE_REQUEST:
                /* TODO: add commands parse */
                break;
            case ZBEE_CMD_ID_GP_SINK_TABLE_REQUEST:
                dissect_zcl_gp_proxy_sink_table_request(tree, tvb, &offset);
                break;
            case ZBEE_CMD_ID_GP_PROXY_TABLE_RESPONSE:
                dissect_zcl_gp_proxy_sink_table_response(tree, tvb, &offset, ZBEE_ZCL_ATTR_GPP_PROXY_TABLE);
                break;

            default:
                break;
        } /* switch */
    } else {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
                        val_to_str_const(cmd_id, zbee_zcl_gp_srv_tx_cmd_names, "Unknown Command"),
                        zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_gp_srv_tx_cmd_id, tvb, offset, 1, ENC_NA);
        offset++;

        /* Handle the command dissection. */
        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_GP_NOTIFICATION_RESPONSE:
                /* TODO: add commands parse */
                break;

            case ZBEE_ZCL_CMD_ID_GP_PAIRING:
            {
                static int * const p_options[] = {
                    &hf_zbee_gp_cmd_pairing_opt_app_id,
                    &hf_zbee_gp_cmd_pairing_opt_add_sink,
                    &hf_zbee_gp_cmd_pairing_opt_remove_gpd,
                    &hf_zbee_gp_cmd_pairing_opt_communication_mode,
                    &hf_zbee_gp_cmd_pairing_opt_gpd_fixed,
                    &hf_zbee_gp_cmd_pairing_opt_gpd_mac_seq_num_cap,
                    &hf_zbee_gp_cmd_pairing_opt_secur_level,
                    &hf_zbee_gp_cmd_pairing_opt_secur_key_type,
                    &hf_zbee_gp_cmd_pairing_opt_gpd_frame_cnt_present,
                    &hf_zbee_gp_cmd_pairing_opt_gpd_secur_key_present,
                    &hf_zbee_gp_cmd_pairing_opt_assigned_alias_present,
                    &hf_zbee_gp_cmd_pairing_opt_fwd_radius_present,
                    NULL
                };
                uint32_t options = tvb_get_uint24(tvb, offset, ENC_LITTLE_ENDIAN);

                proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_pairing_options,
                                       ett_zbee_gp_cmd_pairing_options, p_options, ENC_LITTLE_ENDIAN);
                offset += 3;
                if ((options & ZBEE_ZCL_GP_PAIRING_OPTION_APP_ID) == 0) {
                    proto_tree_add_item(tree, hf_zbee_gp_src_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
                else {
                    proto_tree_add_item(tree, hf_zbee_gp_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                    offset += 8;
                    proto_tree_add_item(tree, hf_zbee_gp_endpoint, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
                if ((options & ZBEE_ZCL_GP_PAIRING_OPTION_REMOVE_GPD) == 0 &&
                    /* see Table 37 */
                    (options & ZBEE_ZCL_GP_PAIRING_OPTION_COMMUNICATION_MODE) == ZBEE_ZCL_GP_PAIRING_OPTION_COMMUNICATION_MODE) {
                    proto_tree_add_item(tree, hf_zbee_gp_sink_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                    offset += 8;
                    proto_tree_add_item(tree, hf_zbee_gp_sink_nwk, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
                if ((options & ZBEE_ZCL_GP_PAIRING_OPTION_REMOVE_GPD) == 0 &&
                    (options & ZBEE_ZCL_GP_PAIRING_OPTION_COMMUNICATION_MODE) != ZBEE_ZCL_GP_PAIRING_OPTION_COMMUNICATION_MODE &&
                    (options & ZBEE_ZCL_GP_PAIRING_OPTION_COMMUNICATION_MODE) != 0) {
                    proto_tree_add_item(tree, hf_zbee_gp_sink_group_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
                if (options & ZBEE_ZCL_GP_PAIRING_OPTION_ADD_SINK) {
                    proto_tree_add_item(tree, hf_zbee_gp_device_id, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
                if (options & ZBEE_ZCL_GP_PAIRING_OPTION_GPD_FRAME_CNT_PRESENT) {
                    proto_tree_add_item(tree, hf_zbee_gp_secur_frame_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
                if (options & ZBEE_ZCL_GP_PAIRING_OPTION_GPD_SECUR_KEY_PRESENT) {
                    proto_tree_add_item(tree, hf_zbee_gp_gpd_key, tvb, offset, 16, ENC_NA);
                    offset += 16;
                }
                if (options & ZBEE_ZCL_GP_PAIRING_OPTION_ASSIGNED_ALIAS_PRESENT) {
                    proto_tree_add_item(tree, hf_zbee_gp_assigned_alias, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
                if (options & ZBEE_ZCL_GP_PAIRING_OPTION_FWD_RADIUS_PRESENT) {
                    proto_tree_add_item(tree, hf_zbee_gp_forwarding_radius, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
                break;
            }

            case ZBEE_ZCL_CMD_ID_GP_PROXY_COMMISSIONING_MODE:
            {
                static int * const pcm_options[] = {
                    &hf_zbee_gp_cmd_pcm_opt_action,
                    &hf_zbee_gp_cmd_pcm_opt_exit_mode,
                    &hf_zbee_gp_cmd_pcm_opt_channel_present,
                    &hf_zbee_gp_cmd_pcm_opt_unicast_comm,
                    NULL
                };
                uint8_t options = tvb_get_uint8(tvb, offset);
                proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_proxy_commissioning_mode_options,
                                       ett_zbee_gp_cmd_proxy_commissioning_mode_options, pcm_options, ENC_NA);
                if (options & ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_ACTION) {
                    static int * const exit_mode[] = {
                        &hf_zbee_gp_cmd_pcm_exit_mode_on_comm_window_expire,
                        &hf_zbee_gp_cmd_pcm_exit_mode_on_pairing_success,
                        &hf_zbee_gp_cmd_pcm_exit_mode_on_gp_proxy_comm_mode,
                        NULL
                    };
                    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_proxy_commissioning_mode_exit_mode,
                                           ett_zbee_gp_cmd_proxy_commissioning_mode_exit_mode, exit_mode, ENC_NA);
                }
                offset += 1;
                if (options & ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_ON_COMMISSIONING_WINDOW_EXPIRATION) {
                    proto_tree_add_item(tree, hf_zbee_zcl_gp_commissioning_window, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
                if (options & ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_CHANNEL_PRESENT) {
                    proto_tree_add_item(tree, hf_zbee_zcl_gp_channel, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
                break;
            }

            case ZBEE_ZCL_CMD_ID_GP_RESPONSE:
            {
                static int * const rsp_options[] = {
                    &hf_zbee_gp_cmd_resp_opt_app_id,
                    &hf_zbee_gp_cmd_resp_opt_tx_on_ep_match,
                    NULL
                };
                static int * const tx_ch[] = {
                    &hf_zbee_gp_cmd_resp_tx_channel,
                    NULL
                };
                uint8_t options = tvb_get_uint8(tvb, offset);

                proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_response_options,
                                       ett_zbee_gp_cmd_response_options, rsp_options, ENC_LITTLE_ENDIAN);
                offset += 1;
                proto_tree_add_item(tree, hf_zbee_gp_tmp_master_short_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_gp_cmd_response_tx_channel,
                                       ett_zbee_gp_cmd_response_tx_channel, tx_ch, ENC_LITTLE_ENDIAN);
                offset += 1;

                if ((options & ZBEE_ZCL_GP_RESPONSE_OPTION_APP_ID) == 0) {
                    proto_tree_add_item(tree, hf_zbee_gp_src_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
                else {
                    proto_tree_add_item(tree, hf_zbee_gp_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                    offset += 8;
                    proto_tree_add_item(tree, hf_zbee_gp_endpoint, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                offset = dissect_zbee_zcl_gp_payload(tvb, pinfo, tree, offset);
                break;
            }
            case ZBEE_ZCL_CMD_ID_GP_TRANS_TBL_RESPONSE:
                /* TODO: add commands parse */
                break;
            case ZBEE_ZCL_CMD_ID_GP_SINK_TABLE_RESPONSE:
                dissect_zcl_gp_proxy_sink_table_response(tree, tvb, &offset, ZBEE_ZCL_ATTR_GPS_SINK_TABLE);
                break;
            case ZBEE_ZCL_CMD_ID_GP_PROXY_TABLE_REQUEST:
                dissect_zcl_gp_proxy_sink_table_request(tree, tvb, &offset);
                break;
            default:
                break;
        } /* switch */
    }

    /* Call the data dissector for any leftover bytes. */
    if (tvb_captured_length(tvb) > offset) {
        call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
    }

    return tvb_captured_length(tvb);
} /* dissect_zbee_zcl_gp */


/**
 *      dissect_zcl_gp_attr_data
 *
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *
 *      @param tree        - pointer to data tree Wireshark uses to display packet.
 *      @param tvb         - pointer to buffer containing raw packet.
 *      @param offset      - pointer to buffer offset
 *      @param attr_id     - attribute identifier
 *      @param data_type   - attribute data type
 *      @param client_attr - ZCL client
 */
static void
dissect_zcl_gp_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id _U_, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {
        case ZBEE_ZCL_ATTR_GPS_SINK_TABLE:
            *offset = dissect_zbee_zcl_gp_sink_table(tvb, tree, *offset);
            break;
        case ZBEE_ZCL_ATTR_GPS_COMMUNICATION_MODE:
            *offset = dissect_zbee_zcl_gp_attr_gps_communication_mode(tvb, tree, *offset);
            break;
        case ZBEE_ZCL_ATTR_GPS_COMMISSIONING_EXIT_MODE:
            *offset = dissect_zbee_zcl_gp_attr_gps_comm_exit_mode(tvb, tree, *offset);
            break;
        case ZBEE_ZCL_ATTR_GPS_SECURITY_LEVEL:
            *offset = dissect_zbee_zcl_gp_attr_gps_secur_lvl(tvb, tree, *offset);
            break;
        case ZBEE_ZCL_ATTR_GPS_FUNCTIONALITY:
            *offset = dissect_zbee_zcl_gp_attr_gps_functionality(tvb, tree, *offset);
            break;
        case ZBEE_ZCL_ATTR_GPS_ACTIVE_FUNCTIONALITY:
            *offset = dissect_zbee_zcl_gp_attr_gps_active_functionality(tvb, tree, *offset);
            break;
        case ZBEE_ZCL_ATTR_GPP_PROXY_TABLE:
            *offset = dissect_zbee_zcl_gp_proxy_table(tvb, tree, *offset);
            break;
        case ZBEE_ZCL_ATTR_GPP_FUNCTIONALITY:
            *offset = dissect_zbee_zcl_gp_attr_gpp_functionality(tvb, tree, *offset);
            break;
        case ZBEE_ZCL_ATTR_GPP_ACTIVE_FUNCTIONALITY:
            *offset = dissect_zbee_zcl_gp_attr_gpp_active_functionality(tvb, tree, *offset);
            break;
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
    }


} /*dissect_zcl_gp_attr_data*/

/**
 *      proto_register_zbee_zcl_gp
 *
 *      ZigBee ZCL Green Power cluster protocol registration.
 */
void
proto_register_zbee_zcl_gp(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_gp_attr_id,
            { "Attribute", "zbee_zcl_general.gp.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_gp_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_gp_srv_rx_cmd_id,
            { "Command", "zbee_zcl_general.gp.cmd.srv_rx.id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_gp_srv_rx_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_gp_srv_tx_cmd_id,
            { "Command", "zbee_zcl_general.gp.cmd.srv_tx.id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_gp_srv_tx_cmd_names), 0x0, NULL, HFILL }},

        /* GP Proxy Commissioning Mode command  */
        { &hf_zbee_gp_cmd_proxy_commissioning_mode_options,
          { "Options", "zbee_zcl_general.gp.proxy_comm_mode.options", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},
        { &hf_zbee_zcl_gp_commissioning_window,
          { "Commissioning window", "zbee_zcl_general.gp.proxy_comm_mode.comm_window", FT_UINT16, BASE_DEC,
            NULL, 0x0, "Commissioning window in seconds", HFILL }},
        { &hf_zbee_zcl_gp_channel,
          { "Channel", "zbee_zcl_general.gp.proxy_comm_mode.channel", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Identifier of the channel the devices SHOULD switch to on reception", HFILL }},
        { &hf_zbee_gp_cmd_pcm_opt_action,
          { "Action", "zbee_zcl_general.gp.proxy_comm_mode.opt.action", FT_UINT8, BASE_DEC,
            VALS(zbee_zcl_gp_comm_mode_actions), ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_ACTION, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pcm_opt_exit_mode,
          { "Exit mode", "zbee_zcl_general.gp.proxy_comm_mode.opt.exit_mode", FT_UINT8, BASE_HEX,
            NULL, ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_EXIT_MODE, "Commissioning mode exit requirements", HFILL }},
        { &hf_zbee_gp_cmd_pcm_opt_channel_present,
          { "Channel present", "zbee_zcl_general.gp.proxy_comm_mode.opt.ch_present", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_CHANNEL_PRESENT, "If set to 0b1, it indicates that the Channel field is present", HFILL }},
        { &hf_zbee_gp_cmd_pcm_opt_unicast_comm,
          { "Unicast", "zbee_zcl_general.gp.proxy_comm_mode.opt.unicast", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_UNICAST, "Send the GP Commissioning Notification commands in broadcast (0) vs unicast (1)", HFILL }},
        { &hf_zbee_gp_cmd_proxy_commissioning_mode_exit_mode,
          { "Exit mode", "zbee_zcl_general.gp.proxy_comm_mode.opt.exit_mode", FT_UINT8, BASE_HEX,
            NULL, ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_EXIT_MODE, "Commissioning mode exit requirements", HFILL }},
        { &hf_zbee_gp_cmd_pcm_exit_mode_on_comm_window_expire,
          { "On Window expire", "zbee_zcl_general.gp.proxy_comm_mode.opt.exit_mode.win_expire", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_ON_COMMISSIONING_WINDOW_EXPIRATION, "On CommissioningWindow expiration", HFILL }},
        { &hf_zbee_gp_cmd_pcm_exit_mode_on_pairing_success,
          { "On first Pairing success", "zbee_zcl_general.gp.proxy_comm_mode.opt.exit_mode.pair_succs", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_ON_PAIRING_SUCCESS, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pcm_exit_mode_on_gp_proxy_comm_mode,
          { "On GP Proxy Commissioning Mode", "zbee_zcl_general.gp.proxy_comm_mode.opt.exit_mode.proxy_comm_mode", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_PROXY_COMMISSIONING_MODE_OPTION_ON_GP_PROXY_COMM_MODE, "On GP Proxy Commissioning Mode (exit)", HFILL }},

        /* GP Commissioning Notification command */
        { &hf_zbee_gp_cmd_commissioning_notification_options,
          { "Options", "zbee_zcl_general.gp.comm_notif.options", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},
        { &hf_zbee_gp_cmd_comm_notif_opt_app_id,
          { "ApplicationID", "zbee_zcl_general.gp.comm_notif.opt.app_id", FT_UINT16, BASE_HEX,
            VALS(zbee_zcl_gp_app_ids), ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_APP_ID, NULL, HFILL }},
        { &hf_zbee_gp_cmd_comm_notif_opt_rx_after_tx,
          { "RxAfterTx", "zbee_zcl_general.gp.comm_notif.opt.rx_after_tx", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_RX_AFTER_TX, NULL, HFILL }},
        { &hf_zbee_gp_cmd_comm_notif_opt_secur_level,
          { "SecurityLevel", "zbee_zcl_general.gp.comm_notif.opt.secur_lev", FT_UINT16, BASE_HEX,
            VALS(zbee_zcl_gp_secur_levels), ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_SECUR_LEVEL, NULL, HFILL }},
        { &hf_zbee_gp_cmd_comm_notif_opt_secur_key_type,
          { "SecurityKeyType", "zbee_zcl_general.gp.comm_notif.opt.secur_key_type", FT_UINT16, BASE_HEX,
            VALS(zbee_zcl_gp_secur_key_types), ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_SECUR_KEY_TYPE, NULL, HFILL }},
        { &hf_zbee_gp_cmd_comm_notif_opt_secur_fail,
          { "Security processing failed", "zbee_zcl_general.gp.comm_notif.opt.secur_failed", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_SECUR_FAILED, NULL, HFILL }},
        { &hf_zbee_gp_cmd_comm_notif_opt_bidir_cap,
          { "Bidirectional Capability", "zbee_zcl_general.gp.comm_notif.opt.bidir_cap", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_BIDIR_CAP, NULL, HFILL }},
        { &hf_zbee_gp_cmd_comm_notif_opt_proxy_info_present,
          { "Proxy info present", "zbee_zcl_general.gp.comm_notif.opt.proxy_info", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_COMMISSIONING_NOTIFICATION_OPTION_PROXY_INFO_PRESENT, NULL, HFILL }},
        { &hf_zbee_gp_src_id,
          { "SrcID", "zbee_zcl_general.gp.src_id", FT_UINT32, BASE_HEX,
            NULL, 0, "GPD Source identifier", HFILL }},
        { &hf_zbee_gp_ieee,
          { "GPD IEEE", "zbee_zcl_general.gp.gpd_ieee", FT_EUI64, BASE_NONE,
            NULL, 0, "GPD IEEE address", HFILL }},
        { &hf_zbee_gp_endpoint,
          { "Endpoint", "zbee_zcl_general.gp.endpoint", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_secur_frame_counter,
          { "Frame counter", "zbee_zcl_general.gp.frame_cnt", FT_UINT32, BASE_DEC,
            NULL, 0, "GPD security frame counter", HFILL }},
        { &hf_zbee_gp_gpd_command_id,
            { "ZGPD CommandID", "zbee_zcl_general.gp.command_id", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
              &zbee_nwk_gp_cmd_names_ext, 0x0, NULL, HFILL }},
        { &hf_zbee_gp_short_addr,
          { "GPP short address", "zbee_zcl_general.gp.gpp_short", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_gpp_gpd_link,
          { "GPP-GPD link", "zbee_zcl_general.gp.gpd_gpp_link", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_mic,
          { "MIC", "zbee_zcl_general.gp.mic", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gpp_gpd_link_rssi,
          { "RSSI", "zbee_zcl_general.gp.gpp_gpd_link.rssi", FT_UINT8, BASE_HEX,
            NULL, ZBEE_ZCL_GP_GPP_GPD_LINK_RSSI, NULL, HFILL }},
        { &hf_zbee_gpp_gpd_link_lqi,
          { "LQI", "zbee_zcl_general.gp.gpp_gpd_link.lqi", FT_UINT8, BASE_HEX,
            VALS(zbee_zcl_gp_lqi_vals), ZBEE_ZCL_GP_GPP_GPD_LINK_LQI, NULL, HFILL }},
        { &hf_zbee_gp_gpd_payload_size,
          { "Payload size", "zbee_zcl_general.gp.payload_size", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        /* GP Notification */
        { &hf_zbee_gp_cmd_notification_options,
          { "Options", "zbee_zcl_general.gp.notif.opt", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_cmd_notif_opt_app_id,
          { "ApplicationID", "zbee_zcl_general.gp.notif.opt.app_id", FT_UINT16, BASE_HEX,
            VALS(zbee_zcl_gp_app_ids), ZBEE_ZCL_GP_NOTIFICATION_OPTION_APP_ID, NULL, HFILL }},
        { &hf_zbee_gp_cmd_notif_opt_also_unicast,
          { "Also Unicast", "zbee_zcl_general.gp.notif.opt.also_unicast", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_NOTIFICATION_OPTION_ALSO_UNICAST, NULL, HFILL }},
        { &hf_zbee_gp_cmd_notif_opt_also_derived_group,
          { "Also Derived Group", "zbee_zcl_general.gp.notif.opt.also_derived_grp", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_NOTIFICATION_OPTION_ALSO_DERIVED_GROUP, NULL, HFILL }},
        { &hf_zbee_gp_cmd_notif_opt_also_comm_group,
          { "Also Commissioned Group", "zbee_zcl_general.gp.notif.opt.also_comm_grp", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_NOTIFICATION_OPTION_ALSO_COMMISSIONED_GROUP, NULL, HFILL }},
        { &hf_zbee_gp_cmd_notif_opt_secur_level,
          { "SecurityLevel", "zbee_zcl_general.gp.notif.opt.secur_lev", FT_UINT16, BASE_HEX,
            VALS(zbee_zcl_gp_secur_levels), ZBEE_ZCL_GP_NOTIFICATION_OPTION_SECUR_LEVEL, NULL, HFILL }},
        { &hf_zbee_gp_cmd_notif_opt_secur_key_type,
          { "SecurityKeyType", "zbee_zcl_general.gp.notif.opt.secur_key_type", FT_UINT16, BASE_HEX,
            VALS(zbee_zcl_gp_secur_key_types), ZBEE_ZCL_GP_NOTIFICATION_OPTION_SECUR_KEY_TYPE, NULL, HFILL }},
        { &hf_zbee_gp_cmd_notif_opt_rx_after_tx,
          { "RxAfterTx", "zbee_zcl_general.gp.comm_notif.opt.rx_after_tx", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_NOTIFICATION_OPTION_RX_AFTER_TX, NULL, HFILL }},
        { &hf_zbee_gp_cmd_notif_opt_tx_q_full,
          { "gpTxQueueFull", "zbee_zcl_general.gp.comm_notif.opt.tx_q_full", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_NOTIFICATION_OPTION_TX_Q_FULL, NULL, HFILL }},
        { &hf_zbee_gp_cmd_notif_opt_bidir_cap,
          { "Bidirectional Capability", "zbee_zcl_general.gp.notif.opt.bidir_cap", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_NOTIFICATION_OPTION_BIDIR_CAP, NULL, HFILL }},
        { &hf_zbee_gp_cmd_notif_opt_proxy_info_present,
          { "Proxy info present", "zbee_zcl_general.gp.notif.opt.proxy_info", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_NOTIFICATION_OPTION_PROXY_INFO_PRESENT, NULL, HFILL }},


        /* GP Pairing */
        { &hf_zbee_gp_cmd_pairing_opt_app_id,
          { "ApplicationID", "zbee_zcl_general.gp.pairing.opt.app_id", FT_UINT24, BASE_HEX,
            VALS(zbee_zcl_gp_app_ids), ZBEE_ZCL_GP_PAIRING_OPTION_APP_ID, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_add_sink,
          { "Add Sink", "zbee_zcl_general.gp.pairing.opt.add_sink", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_PAIRING_OPTION_ADD_SINK, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_remove_gpd,
          { "Remove GPD", "zbee_zcl_general.gp.pairing.opt.remove_gpd", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_PAIRING_OPTION_REMOVE_GPD, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_communication_mode,
          { "Communication mode", "zbee_zcl_general.gp.pairing.opt.comm_mode", FT_UINT24, BASE_HEX,
            VALS(zbee_zcl_gp_communication_modes), ZBEE_ZCL_GP_PAIRING_OPTION_COMMUNICATION_MODE, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_gpd_fixed,
          { "GPD Fixed", "zbee_zcl_general.gp.pairing.opt.gpd_fixed", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_PAIRING_OPTION_GPD_FIXED, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_gpd_mac_seq_num_cap,
          { "MAC Seq number cap", "zbee_zcl_general.gp.pairing.opt.seq_num_cap", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_PAIRING_OPTION_GPD_MAC_SEQ_NUM_CAP, "GPD MAC sequence number capabilities", HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_secur_level,
          { "SecurityLevel", "zbee_zcl_general.gp.pairing.opt.secur_lev", FT_UINT24, BASE_HEX,
            VALS(zbee_zcl_gp_secur_levels), ZBEE_ZCL_GP_PAIRING_OPTION_SECUR_LEVEL, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_secur_key_type,
          { "SecurityKeyType", "zbee_zcl_general.gp.pairing.opt.secur_key_type", FT_UINT24, BASE_HEX,
            VALS(zbee_zcl_gp_secur_key_types), ZBEE_ZCL_GP_PAIRING_OPTION_SECUR_KEY_TYPE, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_gpd_frame_cnt_present,
          { "Frame Counter present", "zbee_zcl_general.gp.pairing.opt.frame_counter_present", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_PAIRING_OPTION_GPD_FRAME_CNT_PRESENT, "GPD security Frame Counter present", HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_gpd_secur_key_present,
          { "Key present", "zbee_zcl_general.gp.pairing.opt.key_present", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_PAIRING_OPTION_GPD_SECUR_KEY_PRESENT, "GPD security key present", HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_assigned_alias_present,
          { "Assigned Alias present", "zbee_zcl_general.gp.pairing.opt.asn_alias_present", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_PAIRING_OPTION_ASSIGNED_ALIAS_PRESENT, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pairing_opt_fwd_radius_present,
          { "Forwarding Radius present", "zbee_zcl_general.gp.pairing.opt.fwd_radius_present", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_PAIRING_OPTION_FWD_RADIUS_PRESENT, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pairing_options,
          { "Options", "zbee_zcl_general.gp.pairing.opt", FT_UINT24, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_sink_ieee,
          { "Sink IEEE", "zbee_zcl_general.gp.sink_ieee", FT_EUI64, BASE_NONE,
            NULL, 0, "Sink IEEE address", HFILL }},
        { &hf_zbee_gp_sink_nwk,
          { "Sink NWK", "zbee_zcl_general.gp.sink_nwk", FT_UINT16, BASE_HEX,
            NULL, 0, "Sink NWK address", HFILL }},
        { &hf_zbee_gp_sink_group_id,
          { "Sink GroupID", "zbee_zcl_general.gp.sink_grp", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_device_id,
          { "DeviceID", "zbee_zcl_general.gp.dev_id", FT_UINT8, BASE_HEX,
            VALS(zbee_nwk_gp_device_ids_names), 0, NULL, HFILL }},
        { &hf_zbee_gp_assigned_alias,
          { "Assigned alias", "zbee_zcl_general.gp.asn_alias", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_forwarding_radius,
          { "Forwarding Radius", "zbee_zcl_general.gp.fw_radius", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_gpd_key,
          { "GPD key", "zbee_zcl_general.gp.gpd_key", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_groupcast_radius,
          { "Groupcast radius", "zbee_zcl_general.gp.groupcast_radius", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        /* GP Response */
        { &hf_zbee_gp_cmd_response_options,
          { "Options", "zbee_zcl_general.gp.response.opt", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_cmd_resp_opt_app_id,
          { "ApplicationID", "zbee_zcl_general.gp.response.opt.app_id", FT_UINT8, BASE_HEX,
            NULL, ZBEE_ZCL_GP_RESPONSE_OPTION_APP_ID, NULL, HFILL }},
        { &hf_zbee_gp_cmd_resp_opt_tx_on_ep_match,
          { "Transmit on endpoint match", "zbee_zcl_general.gp.response.opt.tx_on_ep_match", FT_UINT8, BASE_HEX,
            NULL, ZBEE_ZCL_GP_RESPONSE_OPTION_TX_ON_ENDPOINT_MATCH, NULL, HFILL }},
        { &hf_zbee_gp_cmd_response_tx_channel,
          { "TempMaster Tx channel", "zbee_zcl_general.gp.response.tmpmaster_tx_chan", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_cmd_resp_tx_channel,
          { "Transmit channel", "zbee_zcl_general.gp.response.opt.tx_chan", FT_UINT8, BASE_HEX,
            VALS(zbee_zcl_gp_channels), ZBEE_ZCL_GP_RESPONSE_TX_CHANNEL, NULL, HFILL }},
        { &hf_zbee_gp_tmp_master_short_addr,
          { "TempMaster short address", "zbee_zcl_general.gp.response.tmpmaster_addr", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        /* GP Pairing Configuration */
        { &hf_zbee_gp_cmd_pc_actions_action,
          { "Action", "zbee_zcl_general.gp.pc.action.action", FT_UINT8, BASE_HEX,
            VALS(zbee_gp_pc_actions), ZBEE_ZCL_GP_CMD_PC_ACTIONS_ACTION, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_actions_send_gp_pairing,
          { "Send GP Pairing", "zbee_zcl_general.gp.pc.action.send_gp_pairing", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_CMD_PC_ACTIONS_SEND_GP_PAIRING, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_opt_app_id,
          { "ApplicationID", "zbee_zcl_general.gp.pp.opt.app_id", FT_UINT16, BASE_HEX,
            NULL, ZBEE_ZCL_GP_CMD_PC_OPT_APP_ID, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_opt_communication_mode,
          { "Communication mode", "zbee_zcl_general.gp.pc.opt.comm_mode", FT_UINT16, BASE_HEX,
            VALS(zbee_zcl_gp_communication_modes), ZBEE_ZCL_GP_CMD_PC_OPT_COMMUNICATION_MODE, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_opt_seq_number_cap,
          { "Sequence number capabilities", "zbee_zcl_general.gp.pc.opt.seq_num_cap", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_CMD_PC_OPT_SEQ_NUMBER_CAP, NULL, HFILL }},
        { &hf_zbee_gp_cmd_px_opt_rx_on_cap,
          { "RxOnCapability", "zbee_zcl_general.gp.pc.opt.rx_on_cap", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_CMD_PC_OPT_RX_ON_CAP, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_opt_fixed_location,
          { "FixedLocation", "zbee_zcl_general.gp.pc.opt.fixed_loc", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_CMD_PC_OPT_FIXED_LOCATION, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_opt_assigned_alias,
          { "AssignedAlias", "zbee_zcl_general.gp.pc.opt.asn_alias", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_CMD_PC_OPT_ASSIGNED_ALIAS, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_opt_security_use,
          { "Security use", "zbee_zcl_general.gp.pc.opt.secur_use", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_CMD_PC_OPT_SECURITY_USE, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_opt_app_info_present,
          { "Application in-formation present", "zbee_zcl_general.gp.pc.opt.app_info_present", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_CMD_PC_OPT_APP_INFO_PRESENT, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_secur_level,
          { "SecurityLevel", "zbee_zcl_general.gp.pc.secur.secur_lev", FT_UINT8, BASE_HEX,
            VALS(zbee_zcl_gp_secur_levels), ZBEE_ZCL_GP_CMD_PC_SECUR_LEVEL, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_secur_key_type,
          { "SecurityKeyType", "zbee_zcl_general.gp.pc.secur.secur_key_type", FT_UINT8, BASE_HEX,
            VALS(zbee_zcl_gp_secur_key_types), ZBEE_ZCL_GP_CMD_PC_SECUR_KEY_TYPE, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_app_info_manuf_id_present,
          { "ManufacturerID present", "zbee_zcl_general.gp.pc.app.manuf_id_present", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_CMD_PC_APP_INFO_MANUF_ID_PRESENT, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_app_info_model_id_present,
          { "ModelID present", "zbee_zcl_general.gp.pc.app.model_id_present", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_CMD_PC_APP_INFO_MODEL_ID_PRESENT, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_app_info_gpd_commands_present,
          { "GPD commands present", "zbee_zcl_general.gp.pc.app.gpd_cmds_present", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_CMD_PC_APP_INFO_GPD_COMMANDS_PRESENT, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_app_info_cluster_list_present,
          { "Cluster list present", "zbee_zcl_general.gp.pc.app.cluster_list_present", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_CMD_PC_APP_INFO_CLUSTER_LIST_PRESENT, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_actions,
          { "Actions", "zbee_zcl_general.gp.pc.actions", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_options,
          { "Options", "zbee_zcl_general.gp.pc.options", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_group_list_len,
          { "Group list length", "zbee_zcl_general.gp.group_list.len", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_group_list_group_id,
          { "Group id", "zbee_zcl_general.gp.group_list.group", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_group_list_alias,
          { "Alias", "zbee_zcl_general.gp.group_list.alias", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_secur_options,
          { "Security Options", "zbee_zcl_general.gp.pc.secur_options", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_n_paired_endpoints,
          { "Number of paired endpoints", "zbee_zcl_general.gp.pc.n_ep", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_paired_endpoint,
          { "Paired endpoint", "zbee_zcl_general.gp.pc.endpoint", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_cmd_pc_app_info,
          { "Application information", "zbee_zcl_general.gp.pc.app_info", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_zcl_gp_manufacturer_id,
          { "Manufacturer ID", "zbee_zcl_general.gp.pc.manufacturer_id", FT_UINT16, BASE_HEX,
            VALS(zbee_mfr_code_names), 0x0, NULL, HFILL }},
        { &hf_zbee_zcl_gp_model_id,
          { "Model ID", "zbee_zcl_general.gp.pc.model_id", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_n_gpd_commands,
          { "Number of GPD commands", "zbee_zcl_general.gp.pc.n_gpd_commands", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_gpd_command,
          { "ZGPD Command ID", "zbee_zcl_general.gp.pc.gpd_command", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
            &zbee_nwk_gp_cmd_names_ext, 0x0, NULL, HFILL }},
        { &hf_zbee_gp_n_srv_clusters,
          { "Number of Server clusters", "zbee_zcl_general.gp.pc.n_srv_clusters", FT_UINT8, BASE_DEC,
            NULL, ZBEE_ZCL_GP_CLUSTER_LIST_LEN_SRV, NULL, HFILL }},
        { &hf_zbee_gp_n_cli_clusters,
          { "Number of Client clusters", "zbee_zcl_general.gp.pc.n_clnt_clusters", FT_UINT8, BASE_DEC,
            NULL, ZBEE_ZCL_GP_CLUSTER_LIST_LEN_CLI, NULL, HFILL }},
        { &hf_zbee_gp_gpd_cluster_id,
          { "Cluster ID", "zbee_zcl_general.gp.pc.cluster", FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_aps_cid_names),
            0x0, NULL, HFILL }},

        /* GP Sink Table Request and  GP Proxy Table Request commands */
        { &hf_zbee_zcl_proxy_sink_tbl_req_options,
          { "Options", "zbee_zcl_general.gp.proxy_sink_tbl_req.options", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_zcl_proxy_sink_tbl_req_fld_app_id,
          { "Application ID", "zbee_zcl_general.gp.proxy_sink_tbl_req.options.app_id", FT_UINT8, BASE_HEX,
            NULL, ZBEE_ZCL_GP_PROXY_SINK_TBL_REQ_CMD_APP_ID, NULL, HFILL }},
        { &hf_zbee_zcl_proxy_sink_tbl_req_fld_req_type,
          { "Request type", "zbee_zcl_general.gp.proxy_sink_tbl_req.options.req_type", FT_UINT8, BASE_HEX,
            VALS(zbee_zcl_gp_proxy_sink_tbl_req_type), ZBEE_ZCL_GP_PROXY_SINK_TBL_REQ_CMD_REQ_TYPE, NULL, HFILL }},
        { &hf_zbee_zcl_proxy_sink_tbl_req_index,
          { "Index", "zbee_zcl_general.gp.proxy_sink_tbl_req.index", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        /* GP Sink Table Response and  GP Proxy Table Response commands */
        { &hf_zbee_zcl_proxy_sink_tbl_resp_status,
          { "Status", "zbee_zcl_general.gp.proxy_sink_tbl_resp.status", FT_UINT8, BASE_HEX,
            VALS(zbee_zcl_status_names), 0, NULL, HFILL }},
        { &hf_zbee_zcl_proxy_sink_tbl_resp_entries_total,
          { "Total number of non-empty entries", "zbee_zcl_general.gp.proxy_sink_tbl_resp.entries_total", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_zcl_proxy_sink_tbl_resp_start_index,
          { "Start index", "zbee_zcl_general.gp.proxy_sink_tbl_resp.start_index", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_zcl_proxy_sink_tbl_resp_entries_count,
          { "Entries count", "zbee_zcl_general.gp.proxy_sink_tbl_resp.entries_count", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        /* GP Sink Commissioning Mode command */
        { &hf_zbee_zcl_gp_cmd_sink_comm_mode_options,
          { "Options", "zbee_zcl_general.gp.sink_comm_mode.options", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_action,
          { "Action", "zbee_zcl_general.gp.sink_comm_mode.options.action", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_CMD_SINK_COMM_MODE_OPTIONS_FLD_ACTION, NULL, HFILL }},
        { &hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_inv_gpm_in_secur,
          { "Involve GPM in security", "zbee_zcl_general.gp.sink_comm_mode.options.inv_gpm_in_secur", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_CMD_SINK_COMM_MODE_OPTIONS_FLD_INV_GPM_IN_SECUR, NULL, HFILL }},
        { &hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_inv_gpm_in_pairing,
          { "Involve GPM in pairing", "zbee_zcl_general.gp.sink_comm_mode.options.inv_gpm_in_pairing", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_CMD_SINK_COMM_MODE_OPTIONS_FLD_INV_GPM_IN_PAIRING, NULL, HFILL }},
        { &hf_zbee_zcl_gp_cmd_sink_comm_mode_options_fld_inv_proxies,
          { "Involve proxies", "zbee_zcl_general.gp.sink_comm_mode.options.inv_proxies", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_CMD_SINK_COMM_MODE_OPTIONS_FLD_INV_PROXIES, NULL, HFILL }},

        { &hf_zbee_gp_zcl_cmd_sink_comm_mode_gpm_addr_for_secur,
          { "GPM address for security", "zbee_zcl_general.gp.sink_comm_mode.gpm_addr_for_secur", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_zcl_cmd_sink_comm_mode_gpm_addr_for_pairing,
          { "GPM address for pairing", "zbee_zcl_general.gp.sink_comm_mode.gpm_addr_for_pairing", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_zcl_cmd_sink_comm_mode_sink_ep,
          { "Sink Endpoint", "zbee_zcl_general.gp.sink_comm_mode.sink_ep", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        /* GP Sink Table attribute */
        { &hf_zbee_gp_sink_tbl_length,
          { "Sink Table length", "zbee_zcl_general.gp.sink_tbl_len", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_sink_tbl_entry_options,
          { "Options", "zbee_zcl_general.gp.sink_tbl.entry.opt", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_sec_options,
          { "Security Options", "zbee_zcl_general.gp.secur", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_gp_sink_tbl_entry_options_app_id,
          { "ApplicationID", "zbee_zcl_general.gp.sink_tbl.entry.opt.app_id", FT_UINT16, BASE_HEX,
            NULL, ZBEE_ZCL_GP_SINK_TBL_OPT_APP_ID, NULL, HFILL }},
        { &hf_zbee_gp_sink_tbl_entry_options_comm_mode,
          { "Communication Mode", "zbee_zcl_general.gp.sink_tbl.entry.opt.comm_mode", FT_UINT16, BASE_HEX,
            VALS(zbee_zcl_gp_communication_modes), ZBEE_ZCL_GP_SINK_TBL_OPT_COMMUNICATION_MODE, NULL, HFILL }},
        { &hf_zbee_gp_sink_tbl_entry_options_seq_num_cap,
          { "Sequence number capabilities", "zbee_zcl_general.gp.sink_tbl.entry.opt.seq_num_cap", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_SINK_TBL_OPT_SEQ_NUMBER_CAP, NULL, HFILL }},
        { &hf_zbee_gp_sink_tbl_entry_options_rx_on_cap,
          { "Rx On Capability", "zbee_zcl_general.gp.sink_tbl.entry.opt.rx_on_cap", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_SINK_TBL_OPT_RX_ON_CAP, NULL, HFILL }},
        { &hf_zbee_gp_sink_tbl_entry_options_fixed_loc,
          { "Fixed Location", "zbee_zcl_general.gp.sink_tbl.entry.opt.fixed_loc", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_SINK_TBL_OPT_FIXED_LOCATION, NULL, HFILL }},
        { &hf_zbee_gp_sink_tbl_entry_options_assigned_alias,
          { "Assigned Alias", "zbee_zcl_general.gp.sink_tbl.entry.opt.asn_alias", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_SINK_TBL_OPT_ASSIGNED_ALIAS, NULL, HFILL }},
        { &hf_zbee_gp_sink_tbl_entry_options_sec_use,
          { "Security use", "zbee_zcl_general.gp.sink_tbl.entry.opt.secur_use", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_SINK_TBL_OPT_SECURITY_USE, NULL, HFILL }},

        { &hf_zbee_gp_sec_options_sec_level,
          { "Security Level", "zbee_zcl_general.gp.secur.secur_lev", FT_UINT8, BASE_HEX,
            VALS(zbee_zcl_gp_secur_levels), ZBEE_ZCL_GP_SECUR_OPT_SECUR_LEVEL, NULL, HFILL }},
        { &hf_zbee_gp_sec_options_sec_key_type,
          { "Security Key Type", "zbee_zcl_general.gp.secur.secur_key_type", FT_UINT8, BASE_HEX,
            VALS(zbee_zcl_gp_secur_key_types), ZBEE_ZCL_GP_SECUR_OPT_SECUR_KEY_TYPE, NULL, HFILL }},

        /* GP Proxy Table attribute */
        { &hf_zbee_gp_proxy_tbl_length,
          { "Proxy Table length", "zbee_zcl_general.gp.proxy_tbl_len", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options,
          { "Options", "zbee_zcl_general.gp.proxy_tbl.entry.opt", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_ext_options,
          { "Extended Options", "zbee_zcl_general.gp.proxy_tbl.entry.ext_opt", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_gp_proxy_tbl_entry_options_app_id,
          { "ApplicationID", "zbee_zcl_general.gp.proxy_tbl.entry.opt.app_id", FT_UINT16, BASE_HEX,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_APP_ID, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_entry_active,
          { "EntryActive", "zbee_zcl_general.gp.proxy_tbl.entry.opt.entry_active", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_ENTRY_ACTIVE, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_entry_valid,
          { "EntryValid", "zbee_zcl_general.gp.proxy_tbl.entry.opt.entry_valid", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_ENTRY_VALID, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_seq_num_cap,
          { "Sequence number capabilities", "zbee_zcl_general.gp.proxy_tbl.entry.opt.seq_num_cap", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_SEQ_NUMBER_CAP, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_lw_ucast_gps,
          { "Lightweight Unicast GPS", "zbee_zcl_general.gp.proxy_tbl.entry.opt.lw_ucast_gps", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_LW_UCAST_GPS, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_derived_group_gps,
          { "Derived  Group GPS", "zbee_zcl_general.gp.proxy_tbl.entry.opt.derived_group_gps", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_DERIVED_GROUP_GPS, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_comm_group_gps,
          { "Commissioned Group GPS", "zbee_zcl_general.gp.proxy_tbl.entry.opt.comm_group_gps", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_COMM_GROUP_GPS, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_first_to_forward,
          { "FirstToForward", "zbee_zcl_general.gp.proxy_tbl.entry.opt.first_to_forward", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_FIRST_TO_FORWARD, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_in_range,
          { "InRange", "zbee_zcl_general.gp.proxy_tbl.entry.opt.in_range", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_IN_RANGE, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_gpd_fixed,
          { "GPD Fixed", "zbee_zcl_general.gp.proxy_tbl.entry.opt.gpd_fixed", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_GPD_FIXED, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_has_all_ucast_routes,
          { "HasAllUnicastRoutes", "zbee_zcl_general.gp.proxy_tbl.entry.opt.has_all_ucast_routes", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_HAS_ALL_UCAST_ROUTES, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_assigned_alias,
          { "AssignedAlias", "zbee_zcl_general.gp.proxy_tbl.entry.opt.asn_alias", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_ASSIGNED_ALIAS, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_sec_use,
          { "SecurityUse", "zbee_zcl_general.gp.proxy_tbl.entry.opt.secur_use", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_SECURITY_USE, NULL, HFILL }},
        { &hf_zbee_gp_proxy_tbl_entry_options_opt_ext,
          { "Options Extension", "zbee_zcl_general.gp.proxy_tbl.entry.opt.ext_opt", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_OPT_OPTIONS_EXTENTIONS, NULL, HFILL }},

        { &hf_zbee_gp_proxy_tbl_entry_search_counter,
          { "Search Counter", "zbee_zcl_general.gp.proxy_tbl.entry.search_counter", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_gp_proxy_tbl_entry_ext_options_full_ucast_gps,
          { "Full unicast GPS", "zbee_zcl_general.gp.proxy_tbl.entry.ext_opt.full_ucast_gps", FT_BOOLEAN, 16,
            NULL, ZBEE_ZCL_GP_PROXY_TBL_EXT_OPT_FULL_UCAST_GPS, NULL, HFILL }},

        { &hf_zbee_gp_sink_address_list_length,
          { "Sink Address list length", "zbee_zcl_general.gp.sink_addr_list_len", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        /* gppFunctionality attribute */
        { &hf_zbee_zcl_gp_attr_gpp_func,
          { "gppFunctionality", "zbee_zcl_general.gp.attr.gpp_func", FT_UINT24, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_zcl_gp_attr_gpp_func_fld_gp_feature,
          { "GP feature", "zbee_zcl_general.gp.attr.gpp_func.gp_feature", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GP_FEATURE, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_direct_comm,
          { "Direct communication", "zbee_zcl_general.gp.attr.gpp_func.direct_comm", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_DIRECT_COMM, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_derived_gcast_comm,
          { "Derived groupcast communication", "zbee_zcl_general.gp.attr.gpp_func.derived_gcast_comm", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_DERIVED_GCAST_COMM, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_pre_commissioned_gcast_comm,
          { "Pre-commissioned groupcast communication", "zbee_zcl_general.gp.attr.gpp_func.pre_commissioned_gcast_comm", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_PRE_COMMISSIONED_GCAST_COMM, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_full_ucast_comm,
          { "Full unicast communication", "zbee_zcl_general.gp.attr.gpp_func.full_ucast_comm", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_FULL_UCAST_COMM, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_lw_ucast_comm,
          { "Lightweight unicast communication", "zbee_zcl_general.gp.attr.gpp_func.lw_ucast_comm", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_LW_UCAST_COMM, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_bidir_op,
          { "Bidirectional operation", "zbee_zcl_general.gp.attr.gpp_func.bidir_op", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_BIDIR_OP, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_proxy_tbl_maintenance,
          { "Proxy Table maintenance", "zbee_zcl_general.gp.attr.gpp_func.proxy_tbl_maintenance", FT_BOOLEAN, 24,
              NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_PROXY_TBL_MAINTENANCE, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_gp_commissioning,
          { "GP commissioning", "zbee_zcl_general.gp.attr.gpp_func.gp_commissioning", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GP_COMMISSIONING, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_ct_based_commissioning,
          { "CT-based commissioning", "zbee_zcl_general.gp.attr.gpp_func.ct_based_commissioning", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_CT_BASED_COMMISSIONING, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_maintenance_of_gpd,
          { "Maintenance of GPD", "zbee_zcl_general.gp.attr.gpp_func.maintenance_of_gpd", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_MAINTENANCE_OF_GPD, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_00,
          { "gpdSecurityLevel = 0b00", "zbee_zcl_general.gp.attr.gpp_func.gpd_secur_lvl_00", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GPD_SECUR_LVL_00, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_01,
          { "Deprecated: gpdSecurityLevel = 0b01", "zbee_zcl_general.gp.attr.gpp_func.gpd_secur_lvl_01", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GPD_SECUR_LVL_01, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_10,
          { "gpdSecurityLevel = 0b10", "zbee_zcl_general.gp.attr.gpp_func.gpd_secur_lvl_10", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GPD_SECUR_LVL_10, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_secur_lvl_11,
          { "gpdSecurityLevel = 0b11", "zbee_zcl_general.gp.attr.gpp_func.gpd_secur_lvl_11", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GPD_SECUR_LVL_11, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gpp_func_fld_gpd_ieee_address,
          { "GPD IEEE address", "zbee_zcl_general.gp.attr.gpp_func.gpd_ieee_address", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_FUNC_FLD_GPD_IEEE_ADDRESS, NULL, HFILL }},

        /* gppActiveFunctionality attribute */
        { &hf_zbee_zcl_gp_attr_gpp_active_func,
          { "gppActiveFunctionality", "zbee_zcl_general.gp.attr.gpp_active_func", FT_UINT24, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_zcl_gp_attr_gpp_active_func_fld_gp_functionality,
          { "GP functionality", "zbee_zcl_general.gp.attr.gpp_active_func.gp_functionality", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPP_ACTIVE_FUNC_FLD_GP_FUNCTIONALITY, NULL, HFILL }},

        /* gpsFunctionality attribute */
        { &hf_zbee_zcl_gp_attr_gps_func,
          { "gpsFunctionality", "zbee_zcl_general.gp.attr.gps_func", FT_UINT24, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_zcl_gp_attr_gps_func_fld_gp_feature,
          { "GP feature", "zbee_zcl_general.gp.attr.gps_func.gp_feature", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GP_FEATURE, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_direct_comm,
          { "Direct communication", "zbee_zcl_general.gp.attr.gps_func.direct_comm", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_DIRECT_COMM, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_derived_gcast_comm,
          { "Derived groupcast communication", "zbee_zcl_general.gp.attr.gps_func.derived_gcast_comm", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_DERIVED_GCAST_COMM, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_pre_commissioned_gcast_comm,
          { "Pre-commissioned groupcast communication", "zbee_zcl_general.gp.attr.gps_func.pre_commissioned_gcast_comm", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_PRE_COMMISSIONED_GCAST_COMM, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_full_ucast_comm,
          { "Full unicast communication", "zbee_zcl_general.gp.attr.gps_func.full_ucast_comm", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_FULL_UCAST_COMM, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_lw_ucast_comm,
          { "Lightweight unicast communication", "zbee_zcl_general.gp.attr.gps_func.lw_ucast_comm", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_LW_UCAST_COMM, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_proximity_bidir_op,
          { "Proximity bidirectional operation", "zbee_zcl_general.gp.attr.gps_func.proximity_bidir_op", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_PROXIMITY_BIDIR_OP, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_multi_hop_bidir_op,
          { "Multi-hop bidirectional operation", "zbee_zcl_general.gp.attr.gps_func.multi_hop_bidir_op", FT_BOOLEAN, 24,
              NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_MULTI_HOP_BIDIR_OP, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_proxy_tbl_maintenance,
          { "Proxy Table maintenance", "zbee_zcl_general.gp.attr.gps_func.proxy_tbl_maintenance", FT_BOOLEAN, 24,
              NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_PROXY_TBL_MAINTENANCE, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_proximity_commissioning,
          { "Proximity commissioning", "zbee_zcl_general.gp.attr.gps_func.proximity_commissioning", FT_BOOLEAN, 24,
              NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_PROXIMITY_COMMISSIONING, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_multi_hop_commissioning,
          { "Multi-hop commissioning","zbee_zcl_general.gp.attr.gps_func.multi_hop_commissioning", FT_BOOLEAN, 24,
              NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_MULTI_HOP_COMMISSIONING, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_ct_based_commissioning,
          { "CT-based commissioning", "zbee_zcl_general.gp.attr.gps_func.ct_based_commissioning", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_CT_BASED_COMMISSIONING, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_maintenance_of_gpd,
          { "Maintenance of GPD", "zbee_zcl_general.gp.attr.gps_func.maintenance_of_gpd", FT_BOOLEAN, 24,
              NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_MAINTENANCE_OF_GPD, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_00,
          { "gpdSecurityLevel = 0b00", "zbee_zcl_general.gp.attr.gps_func.gpd_secur_lvl_00", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GPD_SECUR_LVL_00, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_01,
          { "Deprecated: gpdSecurityLevel = 0b01", "zbee_zcl_general.gp.attr.gps_func.gpd_secur_lvl_01", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GPD_SECUR_LVL_01, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_10,
          { "gpdSecurityLevel = 0b10", "zbee_zcl_general.gp.attr.gps_func.gpd_secur_lvl_10", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GPD_SECUR_LVL_10, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_gpd_secur_lvl_11,
          { "gpdSecurityLevel = 0b11", "zbee_zcl_general.gp.attr.gps_func.gpd_secur_lvl_11", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GPD_SECUR_LVL_11, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_sink_tbl_based_gcast_forwarding,
          { "Sink Table-based groupcast forwarding", "zbee_zcl_general.gp.attr.gps_func.sink_tbl_based_gcast_forwarding", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_SINK_TBL_BASED_GCAST_FORWARDING, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_translation_table,
          { "Translation Table", "zbee_zcl_general.gp.attr.gps_func.translation_table", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_TRANSLATION_TABLE, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_func_fld_gpd_ieee_address,
          { "GPD IEEE address", "zbee_zcl_general.gp.attr.gps_func.gpd_ieee_address", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_FUNC_FLD_GPD_IEEE_ADDRESS, NULL, HFILL }},

        /* gpsActiveFunctionality attribute */
        { &hf_zbee_zcl_gp_attr_gps_active_func,
          { "gpsActiveFunctionality", "zbee_zcl_general.gp.attr.gps_active_func", FT_UINT24, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_zcl_gp_attr_gps_active_func_fld_gp_functionality,
          { "GP functionality", "zbee_zcl_general.gp.attr.gps_active_func.gp_functionality", FT_BOOLEAN, 24,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_ACTIVE_FUNC_FLD_GP_FUNCTIONALITY, NULL, HFILL }},

        /* gpsCommunicationMode attribute */
        { &hf_zbee_zcl_gp_attr_gps_communication_mode,
          { "gpsCommunicationMode", "zbee_zcl_general.gp.attr.gps_communication_mode", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_zcl_gp_attr_gps_communication_mode_fld_mode,
          { "Mode", "zbee_zcl_general.gp.attr.gps_communication_mode.mode", FT_UINT8, BASE_HEX,
            VALS(zbee_zcl_gp_communication_modes), ZBEE_ZCL_GP_ATTR_GPS_COMMUNICATION_MODE_FLD_MODE, NULL, HFILL }},

        /* gpsCommissioningExitMode attribute */
        { &hf_zbee_zcl_gp_attr_gps_comm_exit_mode,
          { "gpsCommissioningExitMode", "zbee_zcl_general.gp.attr.gps_comm_exit_mode", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_zcl_gp_attr_gps_comm_exit_mode_fld_on_comm_window_expire,
          { "On CommissioningWindow expiration", "zbee_zcl_general.gp.attr.gps_comm_exit_mode.on_comm_window_expire",
            FT_BOOLEAN, 8, NULL, ZBEE_ZCL_GP_ATTR_GPS_COMM_EXIT_MODE_FLD_ON_COMM_WINDOW_EXPIRE, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_comm_exit_mode_fld_on_pairing_success,
          { "On first Pairing success", "zbee_zcl_general.gp.attr.gps_comm_exit_mode.on_pairing_success",
            FT_BOOLEAN, 8, NULL, ZBEE_ZCL_GP_ATTR_GPS_COMM_EXIT_MODE_FLD_ON_PAIRING_SUCCESS, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_comm_exit_mode_fld_on_gp_proxy_comm_mode,
          { "On GP Proxy Commissioning Mode (exit)", "zbee_zcl_general.gp.attr.gps_comm_exit_mode.on_gp_proxy_comm_mode",
            FT_BOOLEAN, 8, NULL, ZBEE_ZCL_GP_ATTR_GPS_COMM_EXIT_MODE_FLD_ON_GP_PROXY_COMM_MODE, NULL, HFILL }},

        /* gpsSecurityLevel attribute */
        { &hf_zbee_zcl_gp_attr_gps_secur_lvl,
          { "gpsSecurityLevel", "zbee_zcl_general.gp.attr.gps_secur_lvl", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_zbee_zcl_gp_attr_gps_secur_lvl_fld_min_gpd_secur_lvl,
          { "Minimal GPD Security Level", "zbee_zcl_general.gp.attr.gps_secur_lvl.min_gpd_secur_lvl", FT_UINT8, BASE_HEX,
            VALS(zbee_zcl_gp_secur_levels), ZBEE_ZCL_GP_ATTR_GPS_SECUR_LVL_FLD_MIN_GPD_SECUR_LVL, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_secur_lvl_fld_protection_with_gp_link_key,
          { "Protection with  gpLinkKey", "zbee_zcl_general.gp.attr.gps_secur_lvl.protection_with_gp_link_key", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_SECUR_LVL_FLD_PROTECTION_WITH_GP_LINK_KEY, NULL, HFILL }},
        { &hf_zbee_zcl_gp_attr_gps_secur_lvl_fld_involve_tc,
          { "Involve TC", "zbee_zcl_general.gp.attr.gps_secur_lvl.involve_tc", FT_BOOLEAN, 8,
            NULL, ZBEE_ZCL_GP_ATTR_GPS_SECUR_LVL_FLD_INVOLVE_TC, NULL, HFILL }}
    };

    /* ZCL Green Power subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_gp,
        &ett_zbee_gp_cmd_proxy_commissioning_mode_options,
        &ett_zbee_gp_cmd_proxy_commissioning_mode_exit_mode,
        &ett_zbee_gp_cmd_commissioning_notification_options,
        &ett_zbee_gp_gpp_gpd_link,
        &ett_zbee_gp_cmd_notification_options,
        &ett_zbee_gp_cmd_pairing_options,
        &ett_zbee_gp_cmd_response_options,
        &ett_zbee_gp_cmd_response_tx_channel,
        &ett_zbee_gp_cmd_pc_actions,
        &ett_zbee_gp_cmd_pc_options,
        &ett_zbee_zcl_gp_group_list,
        &ett_zbee_gp_cmd_pc_secur_options,
        &ett_zbee_gp_cmd_pc_app_info,
        &ett_zbee_zcl_gp_ep,
        &ett_zbee_zcl_gp_cmds,
        &ett_zbee_zcl_gp_clusters,
        &ett_zbee_zcl_gp_srv_clusters,
        &ett_zbee_zcl_gp_cli_clusters,
        &ett_zbee_zcl_proxy_sink_tbl_req_options,
        &ett_zbee_zcl_gp_cmd_sink_comm_mode_options,
        &ett_zbee_gp_sink_tbl,
        &ett_zbee_gp_sink_tbl_entry,
        &ett_zbee_gp_sink_tbl_entry_options,
        &ett_zbee_gp_sec_options,
        &ett_zbee_gp_proxy_tbl,
        &ett_zbee_gp_proxy_tbl_entry,
        &ett_zbee_gp_proxy_tbl_entry_options,
        &ett_zbee_gp_proxy_tbl_entry_ext_options,
        &ett_zbee_gp_sink_address_list,
        &ett_zbee_zcl_gp_attr_gpp_func,
        &ett_zbee_zcl_gp_attr_gpp_active_func,
        &ett_zbee_zcl_gp_attr_gps_func,
        &ett_zbee_zcl_gp_attr_gps_active_func,
        &ett_zbee_zcl_gp_attr_gps_communication_mode,
        &ett_zbee_zcl_gp_attr_gps_comm_exit_mode,
        &ett_zbee_zcl_gp_attr_gps_secur_lvl
    };


    /* Register the ZigBee ZCL Green Power cluster protocol name and description */
    proto_zbee_zcl_gp = proto_register_protocol("ZigBee ZCL Green Power", "ZCL Green Power", ZBEE_PROTOABBREV_ZCL_GP);
    proto_register_field_array(proto_zbee_zcl_gp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Green Power dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_GP, dissect_zbee_zcl_gp, proto_zbee_zcl_gp);
} /*proto_register_zbee_zcl_gp*/

/**
 *      proto_reg_handoff_zbee_zcl_gp
 *
 *      Hands off the ZCL Green Power dissector.
 */
void
proto_reg_handoff_zbee_zcl_gp(void)
{
    zgp_handle = find_dissector(ZBEE_PROTOABBREV_NWK_GP_CMD);

    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_GP,
                            proto_zbee_zcl_gp,
                            ett_zbee_zcl_gp,
                            ZBEE_ZCL_CID_GP,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_gp_attr_id,
                            hf_zbee_zcl_gp_attr_id,
                            hf_zbee_zcl_gp_srv_rx_cmd_id,
                            hf_zbee_zcl_gp_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_gp_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_gp*/

/* ########################################################################## */
/* #### (0x1000) TOUCHLINK COMMISSIONING CLUSTER ############################ */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/
/*Server commands received*/
#define ZBEE_ZCL_CMD_ID_SCAN_REQUEST                    0x00
#define ZBEE_ZCL_CMD_ID_DEVICE_INFO_REQUEST             0x02
#define ZBEE_ZCL_CMD_ID_IDENTIFY_REQUEST                0x06
#define ZBEE_ZCL_CMD_ID_FACTORT_RESET_REQUEST           0x07
#define ZBEE_ZCL_CMD_ID_NETWORK_START_REQUEST           0x10
#define ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ROUTER_REQUEST     0x12
#define ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ENDDEV_REQUEST     0x14
#define ZBEE_ZCL_CMD_ID_NETWORK_UPDATE_REQUEST          0x16
#define ZBEE_ZCL_CMD_ID_GET_GROUP_IDENTIFIERS_REQUEST   0x41
#define ZBEE_ZCL_CMD_ID_GET_ENDPOINT_LIST_REQUEST       0x42

/*Server commands generated*/
#define ZBEE_ZCL_CMD_ID_SCAN_RESPONSE                   0x01
#define ZBEE_ZCL_CMD_ID_DEVICE_INFO_RESPONSE            0x03
#define ZBEE_ZCL_CMD_ID_NETWORK_START_RESPONSE          0x11
#define ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ROUTER_RESPONSE    0x13
#define ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ENDDEV_RESPONSE    0x15
#define ZBEE_ZCL_CMD_ID_ENDPOINT_INFORMATION            0x40
#define ZBEE_ZCL_CMD_ID_GET_GROUP_IDENTIFIERS_RESPONSE  0x41
#define ZBEE_ZCL_CMD_ID_GET_ENDPOINT_LIST_RESPONSE      0x42

/*ZigBee Information Mask Value*/
#define ZBEE_ZCL_TOUCHLINK_ZBEE_INFO_TYPE       0x03
#define ZBEE_ZCL_TOUCHLINK_ZBEE_INFO_RXIDLE     0x04

/*Touchlink Information Mask Values*/
#define ZBEE_ZCL_TOUCHLINK_INFO_FACTORY         0x01
#define ZBEE_ZCL_TOUCHLINK_INFO_ASSIGNMENT      0x02
#define ZBEE_ZCL_TOUCHLINK_INFO_INITIATOR       0x10
#define ZBEE_ZCL_TOUCHLINK_INFO_UNDEFINED       0x20
#define ZBEE_ZCL_TOUCHLINK_INFO_PROFILE_INTEROP 0x80

/*Touchlink Key Indices*/
#define ZBEE_ZCL_TOUCHLINK_KEYID_DEVELOPMENT    0
#define ZBEE_ZCL_TOUCHLINK_KEYID_MASTER         4
#define ZBEE_ZCL_TOUCHLINK_KEYID_CERTIFICATION  15

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_touchlink(void);
void proto_reg_handoff_zbee_zcl_touchlink(void);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_touchlink;

static int hf_zbee_zcl_touchlink_rx_cmd_id;
static int hf_zbee_zcl_touchlink_tx_cmd_id;
static int hf_zbee_zcl_touchlink_transaction_id;
static int hf_zbee_zcl_touchlink_zbee;
static int hf_zbee_zcl_touchlink_zbee_type;
static int hf_zbee_zcl_touchlink_zbee_rxidle;
static int hf_zbee_zcl_touchlink_info;
static int hf_zbee_zcl_touchlink_info_factory;
static int hf_zbee_zcl_touchlink_info_assignment;
static int hf_zbee_zcl_touchlink_info_initiator;
static int hf_zbee_zcl_touchlink_info_undefined;
static int hf_zbee_zcl_touchlink_info_profile_introp;
static int hf_zbee_zcl_touchlink_start_index;
static int hf_zbee_zcl_touchlink_ident_duration;

static int hf_zbee_zcl_touchlink_rssi_correction;
static int hf_zbee_zcl_touchlink_response_id;
static int hf_zbee_zcl_touchlink_ext_panid;
static int hf_zbee_zcl_touchlink_nwk_update_id;
static int hf_zbee_zcl_touchlink_channel;
static int hf_zbee_zcl_touchlink_nwk_addr;
static int hf_zbee_zcl_touchlink_ext_addr;
static int hf_zbee_zcl_touchlink_panid;
static int hf_zbee_zcl_touchlink_sub_devices;
static int hf_zbee_zcl_touchlink_total_groups;
static int hf_zbee_zcl_touchlink_endpoint;
static int hf_zbee_zcl_touchlink_profile_id;
static int hf_zbee_zcl_touchlink_device_id;
static int hf_zbee_zcl_touchlink_version;
static int hf_zbee_zcl_touchlink_group_count;
static int hf_zbee_zcl_touchlink_group_begin;
static int hf_zbee_zcl_touchlink_group_end;
static int hf_zbee_zcl_touchlink_group_type;
static int hf_zbee_zcl_touchlink_group_id;
static int hf_zbee_zcl_touchlink_addr_range_begin;
static int hf_zbee_zcl_touchlink_addr_range_end;
static int hf_zbee_zcl_touchlink_group_range_begin;
static int hf_zbee_zcl_touchlink_group_range_end;
static int hf_zbee_zcl_touchlink_key_bitmask;
static int hf_zbee_zcl_touchlink_key_bit_dev;
static int hf_zbee_zcl_touchlink_key_bit_master;
static int hf_zbee_zcl_touchlink_key_bit_cert;
static int hf_zbee_zcl_touchlink_key_index;
static int hf_zbee_zcl_touchlink_key;
static int hf_zbee_zcl_touchlink_init_addr;
static int hf_zbee_zcl_touchlink_init_eui64;
static int hf_zbee_zcl_touchlink_status;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_touchlink;
static int ett_zbee_zcl_touchlink_zbee;
static int ett_zbee_zcl_touchlink_info;
static int ett_zbee_zcl_touchlink_keybits;
static int ett_zbee_zcl_touchlink_groups;

/* Command names */
static const value_string zbee_zcl_touchlink_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_SCAN_REQUEST, "Scan Request" },
    { ZBEE_ZCL_CMD_ID_DEVICE_INFO_REQUEST, "Device Information Request" },
    { ZBEE_ZCL_CMD_ID_IDENTIFY_REQUEST, "Identify Request" },
    { ZBEE_ZCL_CMD_ID_FACTORT_RESET_REQUEST, "Reset to Factory New Request" },
    { ZBEE_ZCL_CMD_ID_NETWORK_START_REQUEST, "Network Start Request" },
    { ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ROUTER_REQUEST, "Network Join Router Request" },
    { ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ENDDEV_REQUEST, "Network Join End Device Request" },
    { ZBEE_ZCL_CMD_ID_NETWORK_UPDATE_REQUEST, "Network Update Request" },
    { ZBEE_ZCL_CMD_ID_GET_GROUP_IDENTIFIERS_REQUEST, "Get Group Identifiers Request" },
    { ZBEE_ZCL_CMD_ID_GET_ENDPOINT_LIST_REQUEST, "Get Endpoint List Request" },
    { 0, NULL }
};
static const value_string zbee_zcl_touchlink_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_SCAN_RESPONSE, "Scan Response" },
    { ZBEE_ZCL_CMD_ID_DEVICE_INFO_RESPONSE, "Device Information Response" },
    { ZBEE_ZCL_CMD_ID_NETWORK_START_RESPONSE, "Network Start Response" },
    { ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ROUTER_RESPONSE, "Network Join Router Response" },
    { ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ENDDEV_RESPONSE, "Network Join End Device Response" },
    { ZBEE_ZCL_CMD_ID_ENDPOINT_INFORMATION, "Endpoint Information" },
    { ZBEE_ZCL_CMD_ID_GET_GROUP_IDENTIFIERS_RESPONSE, "Get Group Identifiers Response" },
    { ZBEE_ZCL_CMD_ID_GET_ENDPOINT_LIST_RESPONSE, "Get Endpoint List Response" },
    { 0, NULL }
};

/* ZigBee logical types */
static const value_string zbee_zcl_touchlink_zbee_type_names[] = {
    { 0, "coordinator" },
    { 1, "router" },
    { 2, "end device" },
    { 0, NULL }
};

static const value_string zbee_zcl_touchlink_status_names[] = {
    { 0x00, "Success" },
    { 0x01, "Failure" },
    { 0, NULL }
};

static const value_string zbee_zcl_touchlink_profile_interop_names[] = {
    { 0, "ZLL" },
    { 1, "Zigbee 3.0" },
    { 0, NULL }
};

static const value_string zbee_zcl_touchlink_keyid_names[] = {
    { ZBEE_ZCL_TOUCHLINK_KEYID_DEVELOPMENT, "Development Key" },
    { ZBEE_ZCL_TOUCHLINK_KEYID_MASTER, "Master Key" },
    { ZBEE_ZCL_TOUCHLINK_KEYID_CERTIFICATION, "Certification Key" },
    { 0, NULL }
};

#define ZBEE_ZCL_TOUCHLINK_NUM_KEYID    16
#define ZBEE_ZCL_TOUCHLINK_KEY_SIZE     16

/*************************/
/* Function Bodies       */
/*************************/
/**
 *This function decodes the Scan Request payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_touchlink_scan_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    static int * const zbee_info_flags[] = {
        &hf_zbee_zcl_touchlink_zbee_type,
        &hf_zbee_zcl_touchlink_zbee_rxidle,
        NULL
    };
    static int * const zll_info_flags[] = {
        &hf_zbee_zcl_touchlink_info_factory,
        &hf_zbee_zcl_touchlink_info_assignment,
        &hf_zbee_zcl_touchlink_info_initiator,
        &hf_zbee_zcl_touchlink_info_undefined,
        &hf_zbee_zcl_touchlink_info_profile_introp,
        NULL
    };
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_touchlink_zbee, ett_zbee_zcl_touchlink_zbee, zbee_info_flags, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_touchlink_info, ett_zbee_zcl_touchlink_info, zll_info_flags, ENC_LITTLE_ENDIAN);
    *offset += 1;
} /*dissect_zcl_touchlink_scan_request*/

/**
 *This function decodes the Identify Request payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_touchlink_identify_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_ident_duration, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_touchlink_identify_request*/

/**
 *This function decodes the Network Start Request payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_touchlink_network_start_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_ext_panid, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_key_index, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_key, tvb, *offset, 16, ENC_NA);
    *offset += 16;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_channel, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_panid, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_nwk_addr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_group_begin, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_group_end, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_addr_range_begin, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_addr_range_end, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_group_range_begin, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_group_range_end, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_init_eui64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_init_addr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_touchlink_network_start_request*/

/**
 *This function decodes the Network Join Router/EndDevice Request payloads.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_touchlink_network_join_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_ext_panid, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_key_index, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_key, tvb, *offset, 16, ENC_NA);
    *offset += 16;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_nwk_update_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_channel, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_panid, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_nwk_addr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_group_begin, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_group_end, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_addr_range_begin, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_addr_range_end, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_group_range_begin, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_group_range_end, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_touchlink_network_join_request*/

/**
 *This function decodes the Scan Response payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_touchlink_network_update_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_ext_panid, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_nwk_update_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_channel, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_panid, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_nwk_addr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_touchlink_network_update_request*/

/**
 *This function decodes the Scan Response payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_touchlink_scan_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    static int * const zbee_info_flags[] = {
        &hf_zbee_zcl_touchlink_zbee_type,
        &hf_zbee_zcl_touchlink_zbee_rxidle,
        NULL
    };
    static int * const zll_info_flags[] = {
        &hf_zbee_zcl_touchlink_info_factory,
        &hf_zbee_zcl_touchlink_info_assignment,
        &hf_zbee_zcl_touchlink_info_initiator,
        &hf_zbee_zcl_touchlink_info_undefined,
        &hf_zbee_zcl_touchlink_info_profile_introp,
        NULL
    };
    static int * const zll_keybit_flags[] = {
        &hf_zbee_zcl_touchlink_key_bit_dev,
        &hf_zbee_zcl_touchlink_key_bit_master,
        &hf_zbee_zcl_touchlink_key_bit_cert,
        NULL
    };
    uint8_t subdev;

    /* Parse out the fixed-format stuff */
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_rssi_correction, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_touchlink_zbee, ett_zbee_zcl_touchlink_zbee, zbee_info_flags, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_touchlink_info, ett_zbee_zcl_touchlink_info, zll_info_flags, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_touchlink_key_bitmask, ett_zbee_zcl_touchlink_keybits, zll_keybit_flags, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_response_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_ext_panid, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_nwk_update_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_channel, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_panid, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_nwk_addr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    subdev = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_sub_devices, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_total_groups, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* The remaining fields are only present when sub-devices is one. */
    if (subdev == 1) {
        proto_tree_add_item(tree, hf_zbee_zcl_touchlink_endpoint, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
        proto_tree_add_item(tree, hf_zbee_zcl_touchlink_profile_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
        proto_tree_add_item(tree, hf_zbee_zcl_touchlink_device_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
        proto_tree_add_item(tree, hf_zbee_zcl_touchlink_version, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
        proto_tree_add_item(tree, hf_zbee_zcl_touchlink_group_count, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }
} /*dissect_zcl_touchlink_scan_response*/

/**
 *This function decodes the Network Start Response payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_touchlink_network_start_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_ext_panid, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_nwk_update_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_channel, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_panid, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /* dissect_zcl_touchlink_network_start_response */

/**
 *This function decodes the Endpoint Information payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_touchlink_endpoint_info(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_ext_addr, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_nwk_addr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_endpoint, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_profile_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_device_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_version, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
} /* dissect_zcl_touchlink_endpoint_info */

/**
 *This function decodes the Get Group Identifiers Response payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_touchlink_group_id_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree *list_tree;
    uint8_t count;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_total_groups, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_start_index, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    count = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_group_count, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    list_tree = proto_tree_add_subtree(tree, tvb, *offset, count * 3, ett_zbee_zcl_touchlink_groups, NULL, "Group Information Records");
    while (count--) {
        proto_tree_add_item(list_tree, hf_zbee_zcl_touchlink_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
        proto_tree_add_item(list_tree, hf_zbee_zcl_touchlink_group_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }
} /* dissect_zcl_touchlink_group_id_response */

/**
 *ZigBee ZCL Touchlink Commissioining cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_touchlink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               hf_cmd_id;
    const value_string *vals_cmd_id;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        hf_cmd_id = hf_zbee_zcl_touchlink_rx_cmd_id;
        vals_cmd_id = zbee_zcl_touchlink_rx_cmd_names;
    } else {
        hf_cmd_id = hf_zbee_zcl_touchlink_tx_cmd_id;
        vals_cmd_id = zbee_zcl_touchlink_tx_cmd_names;
    }

    /* Append the command name to the info column. */
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
        val_to_str_const(cmd_id, vals_cmd_id, "Unknown Command"),
        zcl->tran_seqno);
    /* Add the command ID. */
    if (tree) {
        proto_tree_add_item(tree, hf_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }
    offset++;

    /* All touchlink commands begin with a transaction identifier.  */
    proto_tree_add_item(tree, hf_zbee_zcl_touchlink_transaction_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Call the appropriate command dissector */
        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_SCAN_REQUEST:
                dissect_zcl_touchlink_scan_request(tvb, tree, &offset);
                break;

            case ZBEE_ZCL_CMD_ID_IDENTIFY_REQUEST:
                dissect_zcl_touchlink_identify_request(tvb, tree, &offset);
                break;

            case ZBEE_ZCL_CMD_ID_FACTORT_RESET_REQUEST:
                /* No payload */
                break;

            case ZBEE_ZCL_CMD_ID_NETWORK_START_REQUEST:
                dissect_zcl_touchlink_network_start_request(tvb, tree, &offset);
                break;

            case ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ROUTER_REQUEST:
            case ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ENDDEV_REQUEST:
                dissect_zcl_touchlink_network_join_request(tvb, tree, &offset);
                break;

            case ZBEE_ZCL_CMD_ID_NETWORK_UPDATE_REQUEST:
                dissect_zcl_touchlink_network_update_request(tvb, tree, &offset);
                break;

            case ZBEE_ZCL_CMD_ID_DEVICE_INFO_REQUEST:
            case ZBEE_ZCL_CMD_ID_GET_GROUP_IDENTIFIERS_REQUEST:
            case ZBEE_ZCL_CMD_ID_GET_ENDPOINT_LIST_REQUEST:
                proto_tree_add_item(tree, hf_zbee_zcl_touchlink_start_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                break;

            default:
                break;
        }
    }
    else {
        /* Call the appropriate command dissector */
        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_SCAN_RESPONSE:
                dissect_zcl_touchlink_scan_response(tvb, tree, &offset);
                break;

            case ZBEE_ZCL_CMD_ID_NETWORK_START_RESPONSE:
                dissect_zcl_touchlink_network_start_response(tvb, tree, &offset);
                break;

            case ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ROUTER_RESPONSE:
            case ZBEE_ZCL_CMD_ID_NETWORK_JOIN_ENDDEV_RESPONSE:
                proto_tree_add_item(tree, hf_zbee_zcl_touchlink_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                break;

            case ZBEE_ZCL_CMD_ID_DEVICE_INFO_RESPONSE:
                break;

            case ZBEE_ZCL_CMD_ID_ENDPOINT_INFORMATION:
                dissect_zcl_touchlink_endpoint_info(tvb, tree, &offset);
                break;

            case ZBEE_ZCL_CMD_ID_GET_GROUP_IDENTIFIERS_RESPONSE:
                dissect_zcl_touchlink_group_id_response(tvb, tree, &offset);
                break;

            case ZBEE_ZCL_CMD_ID_GET_ENDPOINT_LIST_RESPONSE:
                /* No payload */
                break;

            default:
                break;
        }
    }

    /* Dump leftover data. */
    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        tvbuff_t *excess = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(excess, pinfo, proto_tree_get_root(tree));
    }
    return offset;
} /*dissect_zbee_zcl_touchlink*/

/**
 *ZigBee ZCL Touchlink Commissioning cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_touchlink(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_zbee_zcl_touchlink_rx_cmd_id,
            { "Command", "zbee_zcl_general.touchlink.rx_cmd_id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_touchlink_rx_cmd_names),
            0x00, NULL, HFILL } },
        { &hf_zbee_zcl_touchlink_tx_cmd_id,
            { "Command", "zbee_zcl_general.touchlink.tx_cmd_id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_touchlink_tx_cmd_names),
            0x00, NULL, HFILL } },
        { &hf_zbee_zcl_touchlink_transaction_id,
            { "Transaction ID", "zbee_zcl_general.touchlink.transaction_id", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        /* ZigBee Information Bitmask */
        { &hf_zbee_zcl_touchlink_zbee,
            { "ZigBee Information", "zbee_zcl_general.touchlink.zbee", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_touchlink_zbee_type,
            { "Logical type", "zbee_zcl_general.touchlink.zbee.type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_touchlink_zbee_type_names),
            ZBEE_ZCL_TOUCHLINK_ZBEE_INFO_TYPE, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_zbee_rxidle,
            { "Rx on when idle", "zbee_zcl_general.touchlink.zbee.rxidle", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
            ZBEE_ZCL_TOUCHLINK_ZBEE_INFO_RXIDLE, NULL, HFILL } },

        /* Touchlink Information Bitmask */
        { &hf_zbee_zcl_touchlink_info,
            { "Touchlink Information", "zbee_zcl_general.touchlink.info", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_touchlink_info_factory,
            { "Factory new", "zbee_zcl_general.touchlink.info.factory", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
            ZBEE_ZCL_TOUCHLINK_INFO_FACTORY, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_info_assignment,
            { "Address assignment", "zbee_zcl_general.touchlink.info.assignment", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
            ZBEE_ZCL_TOUCHLINK_INFO_ASSIGNMENT, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_info_initiator,
            { "Link initiator", "zbee_zcl_general.touchlink.info.initiator", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
            ZBEE_ZCL_TOUCHLINK_INFO_INITIATOR, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_info_undefined,
            { "Undefined", "zbee_zcl_general.touchlink.info.undefined", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_TOUCHLINK_INFO_UNDEFINED, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_info_profile_introp,
            { "Profile Interop", "zbee_zcl_general.touchlink.info.profile.interop", FT_UINT8, BASE_HEX, VALS(zbee_zcl_touchlink_profile_interop_names),
            ZBEE_ZCL_TOUCHLINK_INFO_PROFILE_INTEROP, NULL, HFILL } },

        /* Touchlink Key Information Bitmask */
        { &hf_zbee_zcl_touchlink_key_bitmask,
            { "Key Bitmask", "zbee_zcl_general.touchlink.key_bitmask", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_key_bit_dev,
            { "Development Key", "zbee_zcl_general.touchlink.key_bitmask.dev", FT_BOOLEAN, 16, TFS(&tfs_yes_no),
            (1<<ZBEE_ZCL_TOUCHLINK_KEYID_DEVELOPMENT), NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_key_bit_master,
            { "Master Key", "zbee_zcl_general.touchlink.key_bitmask.master", FT_BOOLEAN, 16, TFS(&tfs_yes_no),
            (1<<ZBEE_ZCL_TOUCHLINK_KEYID_MASTER), NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_key_bit_cert,
            { "Certification Key", "zbee_zcl_general.touchlink.key_bitmask.cert", FT_BOOLEAN, 16, TFS(&tfs_yes_no),
            (1<<ZBEE_ZCL_TOUCHLINK_KEYID_CERTIFICATION), NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_start_index,
            { "Start index", "zbee_zcl_general.touchlink.index", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_ident_duration,
            { "Identify duration", "zbee_zcl_general.touchlink.duration", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_rssi_correction,
            { "RSSI Correction", "zbee_zcl_general.touchlink.rssi_correction", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_response_id,
            { "Response ID", "zbee_zcl_general.touchlink.response_id", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_ext_panid,
            { "Extended PAN ID", "zbee_zcl_general.touchlink.ext_panid", FT_EUI64, BASE_NONE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_nwk_update_id,
            { "Network Update ID", "zbee_zcl_general.touchlink.nwk_update_id", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_channel,
            { "Logical Channel", "zbee_zcl_general.touchlink.channel", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_nwk_addr,
            { "Network Address", "zbee_zcl_general.touchlink.nwk_addr", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_ext_addr,
            { "Extended Address", "zbee_zcl_general.touchlink.ext_addr", FT_EUI64, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_panid,
            { "PAN ID", "zbee_zcl_general.touchlink.panid", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_sub_devices,
            { "Sub-devices", "zbee_zcl_general.touchlink.sub_devices", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_total_groups,
            { "Total Group Identifiers", "zbee_zcl_general.touchlink.total_groups", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_endpoint,
            { "Endpoint", "zbee_zcl_general.touchlink.endpoint", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_profile_id,
            { "Profile ID", "zbee_zcl_general.touchlink.profile_id", FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_aps_apid_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_device_id,
            { "Device ID", "zbee_zcl_general.touchlink.device_id", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_version,
            { "Version", "zbee_zcl_general.touchlink.version", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_group_count,
            { "Group ID Count", "zbee_zcl_general.touchlink.group_count", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_group_begin,
            { "Group ID Begin", "zbee_zcl_general.touchlink.group_begin", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_group_end,
            { "Group ID End", "zbee_zcl_general.touchlink.group_end", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_group_type,
            { "Group Type", "zbee_zcl_general.touchlink.group_type", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_group_id,
            { "Group ID", "zbee_zcl_general.touchlink.group_id", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_addr_range_begin,
            { "Free Address Range Begin", "zbee_zcl_general.touchlink.addr_range_begin", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_addr_range_end,
            { "Free Address Range End", "zbee_zcl_general.touchlink.addr_range_end", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_group_range_begin,
            { "Free Group ID Range Begin", "zbee_zcl_general.touchlink.group_range_begin", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_group_range_end,
            { "Free Group ID Range End", "zbee_zcl_general.touchlink.group_range_end", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_key_index,
            { "Key Index", "zbee_zcl_general.touchlink.key_index", FT_UINT8, BASE_DEC, VALS(zbee_zcl_touchlink_keyid_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_key,
            { "Encrypted Network Key", "zbee_zcl_general.touchlink.key", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_init_eui64,
            { "Initiator Extended Address", "zbee_zcl_general.touchlink.init_eui", FT_EUI64, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_init_addr,
            { "Initiator Network Address", "zbee_zcl_general.touchlink.init_addr", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_touchlink_status,
            { "Status", "zbee_zcl_general.touchlink.status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_touchlink_status_names),
            0x00, NULL, HFILL } },
    };

    /* ZCL Touchlink subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_touchlink,
        &ett_zbee_zcl_touchlink_zbee,
        &ett_zbee_zcl_touchlink_info,
        &ett_zbee_zcl_touchlink_keybits,
        &ett_zbee_zcl_touchlink_groups,
    };

    /* Register the ZigBee ZCL Touchlink cluster protocol name and description */
    proto_zbee_zcl_touchlink = proto_register_protocol("ZigBee ZCL Touchlink", "ZCL Touchlink", ZBEE_PROTOABBREV_ZCL_TOUCHLINK);
    proto_register_field_array(proto_zbee_zcl_touchlink, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Touchlink Commissioning dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_TOUCHLINK, dissect_zbee_zcl_touchlink, proto_zbee_zcl_touchlink);
} /*proto_register_zbee_zcl_touchlink*/

/**
 *Hands off the ZCL Touchlink Commissioning dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_touchlink(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_TOUCHLINK,
                            proto_zbee_zcl_touchlink,
                            ett_zbee_zcl_touchlink,
                            ZBEE_ZCL_CID_ZLL,
                            ZBEE_MFG_CODE_NONE,
                            -1, -1,
                            hf_zbee_zcl_touchlink_rx_cmd_id, hf_zbee_zcl_touchlink_tx_cmd_id,
                            NULL
                         );
} /*proto_reg_handoff_zbee_zcl_touchlink*/

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
