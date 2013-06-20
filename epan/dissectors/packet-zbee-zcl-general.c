/* packet-zbee-zcl-general.c
 * Dissector routines for the ZigBee ZCL General clusters like
 * Basic, Identify, OnOff ...
 * By Fabio Tarabelloni <fabio.tarabelloni@reloc.it>
 * Copyright 2013 RELOC s.r.l.
 *
 * $Id$
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

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"

/* ########################################################################## */
/* #### (0x0000) BASIC CLUSTER ############################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_BASIC_NUM_GENERIC_ETT                  3
#define ZBEE_ZCL_BASIC_NUM_ETT                          ZBEE_ZCL_BASIC_NUM_GENERIC_ETT

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
#define ZBEE_ZCL_BASIC_PWR_SRC_EMERGENCY_2              0x06    /* Emergency mains and tranfer switch */

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

/* Command Dissector Helpers */

/* Private functions prototype */
static void dissect_zcl_basic_attr_id        (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id);
static void dissect_zcl_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_basic = -1;

static int hf_zbee_zcl_basic_attr_id = -1;
static int hf_zbee_zcl_basic_pwr_src = -1;
static int hf_zbee_zcl_basic_dev_en = -1;
static int hf_zbee_zcl_basic_alarm_mask_gen_hw_fault = -1;
static int hf_zbee_zcl_basic_alarm_mask_gen_sw_fault = -1;
static int hf_zbee_zcl_basic_alarm_mask_reserved = -1;
static int hf_zbee_zcl_basic_disable_local_cfg_reset = -1;
static int hf_zbee_zcl_basic_disable_local_cfg_device_cfg = -1;
static int hf_zbee_zcl_basic_disable_local_cfg_reserved = -1;
static int hf_zbee_zcl_basic_srv_rx_cmd_id = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_basic = -1;
static gint ett_zbee_zcl_basic_alarm_mask = -1;
static gint ett_zbee_zcl_basic_dis_local_cfg = -1;

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
    { ZBEE_ZCL_BASIC_PWR_SRC_EMERGENCY_2,   "Emergency mains and tranfer switch" },
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
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zbee_zcl_basic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    zbee_zcl_packet   *zcl = (zbee_zcl_packet *)pinfo->private_data;
    guint             offset = 0;
    guint8            cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        if (tree) {
            /* Add the command ID. */
            proto_tree_add_item(tree, hf_zbee_zcl_basic_srv_rx_cmd_id, tvb, offset, 1, cmd_id);
        }
        offset += (int)1;

        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_basic_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Call the appropriate command dissector */
        switch (cmd_id) {

            case ZBEE_ZCL_CMD_ID_BASIC_RESET_FACTORY_DEFAULTS:
                /* No payload */
                break;

            default:
                break;
        }
    }
} /*dissect_zbee_zcl_basic*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_basic_attr_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint16 attr_id     - attribute identifier
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_basic_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id)
{
    proto_tree_add_item(tree, hf_zbee_zcl_basic_attr_id, tvb, *offset, 2, attr_id);
} /*dissect_zcl_basic_attr_id*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_basic_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint16 attr_id     - attribute identifier
 *      guint data_type     - attribute data type
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_basic_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;
    guint8      value8;

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_BASIC_POWER_SOURCE:
            proto_tree_add_item(tree, hf_zbee_zcl_basic_pwr_src, tvb, *offset, 1, ENC_NA);
            *offset += (int)1;
            break;

        case ZBEE_ZCL_ATTR_ID_BASIC_DEVICE_ENABLED:
            proto_tree_add_item(tree, hf_zbee_zcl_basic_dev_en, tvb, *offset, 1, ENC_NA);
            *offset += (int)1;
            break;

        case ZBEE_ZCL_ATTR_ID_BASIC_ALARM_MASK:
            value8 = tvb_get_guint8(tvb, *offset);
            ti = proto_tree_add_text(tree, tvb, *offset, 1, "Alarm Mask: 0x%02x", value8);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_basic_alarm_mask);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_alarm_mask_gen_hw_fault, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_alarm_mask_gen_sw_fault, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_alarm_mask_reserved, tvb, *offset, 1, ENC_NA);
            *offset += (int)1;
            break;

        case ZBEE_ZCL_ATTR_ID_BASIC_DISABLE_LOCAL_CFG:
            value8 = tvb_get_guint8(tvb, *offset);
            ti = proto_tree_add_text(tree, tvb, *offset, 1, "Disable Local Config: 0x%02x", value8);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_basic_dis_local_cfg);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_disable_local_cfg_reset, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_disable_local_cfg_device_cfg, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_disable_local_cfg_reserved, tvb, *offset, 1, ENC_NA);
            *offset += (int)1;
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
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
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
    static gint *ett[ZBEE_ZCL_BASIC_NUM_ETT];

    ett[0] = &ett_zbee_zcl_basic;
    ett[1] = &ett_zbee_zcl_basic_alarm_mask;
    ett[2] = &ett_zbee_zcl_basic_dis_local_cfg;

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
    dissector_handle_t basic_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    basic_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_BASIC);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_BASIC, basic_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_basic,
                            ett_zbee_zcl_basic,
                            ZBEE_ZCL_CID_BASIC,
                            (zbee_zcl_fn_attr_id)dissect_zcl_basic_attr_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_basic_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_basic*/

/* ########################################################################## */
/* #### (0x0003) IDENTIFY CLUSTER ########################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_IDENTIFY_NUM_GENERIC_ETT               1
#define ZBEE_ZCL_IDENTIFY_NUM_ETT                       ZBEE_ZCL_IDENTIFY_NUM_GENERIC_ETT

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_IDENTIFY_IDENTIFY_TIME         0x0000  /* Identify Time */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY               0x00  /* Identify */
#define ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY         0x01  /* Identify Query */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY_RSP     0x00  /* Identify Query Response */


/*************************/
/* Function Declarations */
/*************************/

/* Command Dissector Helpers */
static void dissect_zcl_identify_identify               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_identify_identifyqueryrsp       (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/* Private functions prototype */
static void dissect_zcl_identify_attr_id                (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id);
static void dissect_zcl_identify_attr_data              (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_identify = -1;

static int hf_zbee_zcl_identify_attr_id = -1;
static int hf_zbee_zcl_identify_identify_time = -1;
static int hf_zbee_zcl_identify_identify_timeout = -1;
static int hf_zbee_zcl_identify_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_identify_srv_tx_cmd_id = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_identify = -1;

/* Attributes */
static const value_string zbee_zcl_identify_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_IDENTIFY_IDENTIFY_TIME,      "Identify Time" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_identify_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY,            "Identify" },
    { ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY,      "Identify Query" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_identify_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY_RSP,  "Identify Query Response" },
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
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zbee_zcl_identify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item        *payload_root = NULL;
    proto_tree        *payload_tree = NULL;
    zbee_zcl_packet   *zcl = (zbee_zcl_packet *)pinfo->private_data;
    guint             offset = 0;
    guint8            cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        if (tree) {
            /* Add the command ID. */
            proto_tree_add_item(tree, hf_zbee_zcl_identify_srv_rx_cmd_id, tvb, offset, 1, cmd_id);
            /* Check is this command has a payload, than add the payload tree */
            if (offset != (tvb_length(tvb) - 1)) {
                payload_root = proto_tree_add_text(tree, tvb, offset, tvb_length(tvb), "Payload");
                payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_identify);
            }
        }
        offset += (int)1;

        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_identify_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Call the appropriate command dissector */
        switch (cmd_id) {

            case ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY:
                dissect_zcl_identify_identify(tvb, payload_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY:
                /* without payload*/
                break;

            default:
                break;
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */

        if (tree) {
            /* Add the command ID. */
            proto_tree_add_item(tree, hf_zbee_zcl_identify_srv_tx_cmd_id, tvb, offset, 1, cmd_id);
            /* Check is this command has a payload, than add the payload tree */
            if (offset != (tvb_length(tvb) - 1)) {
                payload_root = proto_tree_add_text(tree, tvb, offset, tvb_length(tvb), "Payload");
                payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_identify);
            }
        }
        offset += (int)1;

        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_identify_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Call the appropriate command dissector */
        switch (cmd_id) {

            case ZBEE_ZCL_CMD_ID_IDENTIFY_IDENTITY_QUERY_RSP:
                dissect_zcl_identify_identifyqueryrsp(tvb, payload_tree, &offset);
                break;

            default:
                break;
        }
    }
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
dissect_zcl_identify_identify(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve "Identify Time" field */
    proto_tree_add_item(tree, hf_zbee_zcl_identify_identify_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += (int)2;

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
dissect_zcl_identify_identifyqueryrsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve "Identify Timeout" field */
    proto_tree_add_item(tree, hf_zbee_zcl_identify_identify_timeout, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += (int)2;

} /*dissect_zcl_identify_identifyqueryrsp*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_identify_attr_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint16 attr_id     - attribute identifier
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_identify_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id)
{
    proto_tree_add_item(tree, hf_zbee_zcl_identify_attr_id, tvb, *offset, 2, attr_id);
} /*dissect_zcl_identify_attr_id*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_identify_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint16 attr_id     - attribute identifier
 *      guint data_type     - attribute data type
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_identify_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_IDENTIFY_IDENTIFY_TIME:
            proto_tree_add_item(tree, hf_zbee_zcl_identify_identify_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += (int)2;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
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
            { "Identify Time", "zbee_zcl_general.identify.attr.identify_time", FT_UINT16, BASE_CUSTOM, decode_zcl_time_in_seconds,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_identify_identify_timeout,
            { "Identify Timeout", "zbee_zcl_general.identify.identify_timeout", FT_UINT16, BASE_CUSTOM, decode_zcl_time_in_seconds,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_identify_srv_rx_cmd_id,
          { "Command", "zbee_zcl_general.identify.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_identify_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_identify_srv_tx_cmd_id,
          { "Command", "zbee_zcl_general.identify.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_identify_srv_tx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Identify subtrees */
    static gint *ett[ZBEE_ZCL_IDENTIFY_NUM_ETT];
    ett[0] = &ett_zbee_zcl_identify;

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
    dissector_handle_t identify_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    identify_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_IDENTIFY);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_IDENTIFY, identify_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_identify,
                            ett_zbee_zcl_identify,
                            ZBEE_ZCL_CID_IDENTIFY,
                            (zbee_zcl_fn_attr_id)dissect_zcl_identify_attr_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_identify_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_identify*/

/* ########################################################################## */
/* #### (0x0006) ON/OFF CLUSTER ############################################# */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ON_OFF_ATTR_ID_ONOFF     0x0000

/* Server Commands Received */
#define ZBEE_ZCL_ON_OFF_CMD_OFF           0x00  /* Off */
#define ZBEE_ZCL_ON_OFF_CMD_ON            0x01  /* On */
#define ZBEE_ZCL_ON_OFF_CMD_TOGGLE        0x02  /* Toggle */

/*************************/
/* Function Declarations */
/*************************/

void proto_reg_handoff_zbee_zcl_on_off(void);

/* Command Dissector Helpers */

/* Private functions prototype */
static void dissect_zcl_on_off_attr_id       (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id);
static void dissect_zcl_on_off_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_on_off = -1;

static int hf_zbee_zcl_on_off_attr_id = -1;
static int hf_zbee_zcl_on_off_attr_onoff = -1;
static int hf_zbee_zcl_on_off_srv_rx_cmd_id = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_on_off = -1;

/* Attributes */
static const value_string zbee_zcl_on_off_attr_names[] = {
    { ZBEE_ZCL_ON_OFF_ATTR_ID_ONOFF,    "OnOff" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_on_off_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_ON_OFF_CMD_OFF,          "Off" },
    { ZBEE_ZCL_ON_OFF_CMD_ON,           "On" },
    { ZBEE_ZCL_ON_OFF_CMD_TOGGLE,       "Toggle" },
    { 0, NULL }
};

/* OnOff Names */
static const value_string zbee_zcl_on_off_onoff_names[] = {
    { 0, "Off" },
    { 1, "On" },
    { 0, NULL }
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
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zbee_zcl_on_off(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    zbee_zcl_packet  *zcl = (zbee_zcl_packet *)pinfo->private_data;
    guint   offset = 0;
    guint8  cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        if (tree) {
            /* Add the command ID. */
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_srv_rx_cmd_id, tvb, offset, 1, cmd_id);
        }
        offset += (int)1;

        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_on_off_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);
    }
} /*dissect_zbee_zcl_on_off*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_on_off_attr_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint16 attr_id     - attribute identifier
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_on_off_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id)
{
    proto_tree_add_item(tree, hf_zbee_zcl_on_off_attr_id, tvb, *offset, 2, attr_id);
} /*dissect_zcl_on_off_attr_id*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_on_off_attr_data
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes data.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint16 attr_id     - attribute identifier
 *      guint data_type     - attribute data type
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_on_off_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ON_OFF_ATTR_ID_ONOFF:
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_attr_onoff, tvb, *offset, 1, ENC_NA);
            *offset += (int)1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
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
            { "Data Value", "zbee_zcl_general.onoff.attr.onoff", FT_UINT8, BASE_HEX, VALS(zbee_zcl_on_off_onoff_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_srv_rx_cmd_id,
            { "Command", "zbee_zcl_general.onoff.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_on_off_srv_rx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* Register the ZigBee ZCL OnOff cluster protocol name and description */
    proto_zbee_zcl_on_off = proto_register_protocol("ZigBee ZCL OnOff", "ZCL OnOff", ZBEE_PROTOABBREV_ZCL_ONOFF);
    proto_register_field_array(proto_zbee_zcl_on_off, hf, array_length(hf));

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
    dissector_handle_t on_off_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    on_off_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_ONOFF);

    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_ON_OFF, on_off_handle);
    zbee_zcl_init_cluster(  proto_zbee_zcl_on_off,
                            ett_zbee_zcl_on_off,
                            ZBEE_ZCL_CID_ON_OFF,
                            (zbee_zcl_fn_attr_id)dissect_zcl_on_off_attr_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_on_off_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_on_off*/
