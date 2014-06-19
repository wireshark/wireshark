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
#include <epan/to_str.h>

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

void proto_register_zbee_zcl_basic(void);
void proto_reg_handoff_zbee_zcl_basic(void);

/* Command Dissector Helpers */
static void dissect_zcl_basic_attr_id        (proto_tree *tree, tvbuff_t *tvb, guint *offset);
static void dissect_zcl_basic_attr_data      (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);
static void dissect_zcl_basic_cmd_id         (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint8 cmd_dir);

/* Private functions prototype */

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
static int
dissect_zbee_zcl_basic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    zbee_zcl_packet   *zcl;
    guint             offset = 0;
    guint8            cmd_id;

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
            proto_tree_add_item(tree, hf_zbee_zcl_basic_srv_rx_cmd_id, tvb, offset, 1, cmd_id);
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

    return tvb_length(tvb);
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
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_basic_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_basic_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
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
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BASIC_DEVICE_ENABLED:
            proto_tree_add_item(tree, hf_zbee_zcl_basic_dev_en, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BASIC_ALARM_MASK:
            value8 = tvb_get_guint8(tvb, *offset);
            ti = proto_tree_add_text(tree, tvb, *offset, 1, "Alarm Mask: 0x%02x", value8);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_basic_alarm_mask);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_alarm_mask_gen_hw_fault, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_alarm_mask_gen_sw_fault, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_alarm_mask_reserved, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BASIC_DISABLE_LOCAL_CFG:
            value8 = tvb_get_guint8(tvb, *offset);
            ti = proto_tree_add_text(tree, tvb, *offset, 1, "Disable Local Config: 0x%02x", value8);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_basic_dis_local_cfg);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_disable_local_cfg_reset, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_disable_local_cfg_device_cfg, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_basic_disable_local_cfg_reserved, tvb, *offset, 1, ENC_NA);
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
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_basic_attr_data*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_basic_cmd_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster command identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint8 cmd_dir      - command direction
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_basic_cmd_id(proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir)
{
    if (cmd_dir == ZBEE_ZCL_FCF_TO_CLIENT)
        proto_tree_add_item(tree, hf_zbee_zcl_basic_srv_rx_cmd_id, tvb, *offset, 1, ENC_NA);

} /*dissect_zcl_basic_cmd_id*/


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
    new_register_dissector(ZBEE_PROTOABBREV_ZCL_BASIC, dissect_zbee_zcl_basic, proto_zbee_zcl_basic);
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
                            (zbee_zcl_fn_attr_data)dissect_zcl_basic_attr_data,
                            (zbee_zcl_fn_cmd_id)dissect_zcl_basic_cmd_id
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

void proto_register_zbee_zcl_identify(void);
void proto_reg_handoff_zbee_zcl_identify(void);

/* Command Dissector Helpers */
static void dissect_zcl_identify_identify               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_identify_identifyqueryrsp       (tvbuff_t *tvb, proto_tree *tree, guint *offset);

static void dissect_zcl_identify_attr_id                (proto_tree *tree, tvbuff_t *tvb, guint *offset);
static void dissect_zcl_identify_attr_data              (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);
static void dissect_zcl_identify_cmd_id                 (proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir);

/* Private functions prototype */

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
static int
dissect_zbee_zcl_identify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item        *payload_root;
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    guint             offset = 0;
    guint8            cmd_id;
    gint              rem_len;

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
        proto_tree_add_item(tree, hf_zbee_zcl_identify_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_identify);

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
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_identify_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_identify_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_identify);

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

    return tvb_length(tvb);
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
dissect_zcl_identify_identifyqueryrsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve "Identify Timeout" field */
    proto_tree_add_item(tree, hf_zbee_zcl_identify_identify_timeout, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

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
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_identify_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_identify_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
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
            *offset += 2;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_identify_attr_data*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_identify_cmd_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster command identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint8 cmd_dir      - command direction
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_identify_cmd_id(proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir)
{
    if (cmd_dir == ZBEE_ZCL_FCF_TO_CLIENT)
        proto_tree_add_item(tree, hf_zbee_zcl_identify_srv_rx_cmd_id, tvb, *offset, 1, ENC_NA);
    else
        proto_tree_add_item(tree, hf_zbee_zcl_identify_srv_tx_cmd_id, tvb, *offset, 1, ENC_NA);
} /*dissect_zcl_identify_cmd_id*/

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
    new_register_dissector(ZBEE_PROTOABBREV_ZCL_IDENTIFY, dissect_zbee_zcl_identify, proto_zbee_zcl_identify);

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
                            (zbee_zcl_fn_attr_data)dissect_zcl_identify_attr_data,
                            (zbee_zcl_fn_cmd_id)dissect_zcl_identify_cmd_id
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

void proto_register_zbee_zcl_on_off(void);
void proto_reg_handoff_zbee_zcl_on_off(void);

/* Command Dissector Helpers */
static void dissect_zcl_on_off_attr_id       (proto_tree *tree, tvbuff_t *tvb, guint *offset);
static void dissect_zcl_on_off_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);
static void dissect_zcl_on_off_cmd_id        (proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir);

/* Private functions prototype */

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
static int
dissect_zbee_zcl_on_off(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    zbee_zcl_packet  *zcl;
    guint   offset = 0;
    guint8  cmd_id;

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
        proto_tree_add_item(tree, hf_zbee_zcl_on_off_srv_rx_cmd_id, tvb, offset, 1, cmd_id);
        /*offset++;*/
    }

    return tvb_length(tvb);
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
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_on_off_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_on_off_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
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
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_on_off_attr_data*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_on_off_cmd_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster command identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint8 cmd_dir      - command direction
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_on_off_cmd_id(proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir)
{
    if (cmd_dir == ZBEE_ZCL_FCF_TO_CLIENT)
        proto_tree_add_item(tree, hf_zbee_zcl_on_off_srv_rx_cmd_id, tvb, *offset, 1, ENC_NA);
} /*dissect_zcl_on_off_cmd_id*/


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
    new_register_dissector(ZBEE_PROTOABBREV_ZCL_ONOFF, dissect_zbee_zcl_on_off, proto_zbee_zcl_on_off);
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
                            (zbee_zcl_fn_attr_data)dissect_zcl_on_off_attr_data,
                            (zbee_zcl_fn_cmd_id)dissect_zcl_on_off_cmd_id
                         );
} /*proto_reg_handoff_zbee_zcl_on_off*/

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
#define ZBEE_ZCL_ATTR_ID_PART_PARTIONED_FRAME_SIZE      0x0002  /* Partioned Frame Size */
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
static void dissect_zcl_part_trasfpartframe         (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_part_rdhandshakeparam       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_part_wrhandshakeparam       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_part_multiack               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_part_rdhandshakeparamrsp    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);

static void dissect_zcl_part_attr_id                (proto_tree *tree, tvbuff_t *tvb, guint *offset);
static void dissect_zcl_part_cmd_id                 (proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_part = -1;

static int hf_zbee_zcl_part_attr_id = -1;
static int hf_zbee_zcl_part_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_part_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_part_opt_first_block = -1;
static int hf_zbee_zcl_part_opt_indic_len = -1;
static int hf_zbee_zcl_part_opt_res = -1;
static int hf_zbee_zcl_part_first_frame_id = -1;
static int hf_zbee_zcl_part_part_indicator = -1;
static int hf_zbee_zcl_part_part_frame = -1;
static int hf_zbee_zcl_part_part_frame_len = -1;
static int hf_zbee_zcl_part_partitioned_cluster_id = -1;
static int hf_zbee_zcl_part_ack_opt_nack_id_len = -1;
static int hf_zbee_zcl_part_ack_opt_res = -1;
static int hf_zbee_zcl_part_nack_id = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_part = -1;
static gint ett_zbee_zcl_part_fragm_options = -1;
static gint ett_zbee_zcl_part_ack_opts = -1;
static gint ett_zbee_zcl_part_nack_id_list[ZBEE_ZCL_PART_NUM_NACK_ID_ETT];
static gint ett_zbee_zcl_part_attrs_id_list[ZBEE_ZCL_PART_NUM_ATTRS_ID_ETT];

/* Attributes */
static const value_string zbee_zcl_part_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_PART_MAX_IN_TRANSF_SIZE,     "Maximum Incoming Transfer Size" },
    { ZBEE_ZCL_ATTR_ID_PART_MAX_OUT_TRANSF_SIZE,    "Maximum Outgoing Transfer Size" },
    { ZBEE_ZCL_ATTR_ID_PART_PARTIONED_FRAME_SIZE,   "Partioned Frame Size" },
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

/* ID Lenght */
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
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_part(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item  *payload_root;
    proto_tree  *payload_tree;
    zbee_zcl_packet  *zcl;
    guint       offset = 0;
    guint8      cmd_id;
    gint        rem_len;

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
        proto_tree_add_item(tree, hf_zbee_zcl_part_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_part);

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_PART_TRANSF_PART_FRAME:
                    dissect_zcl_part_trasfpartframe(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PART_RD_HANDSHAKE_PARAM:
                    dissect_zcl_part_rdhandshakeparam(tvb, pinfo, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PART_WR_HANDSHAKE_PARAM:
                    dissect_zcl_part_wrhandshakeparam(tvb, pinfo, payload_tree, &offset);
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
        proto_tree_add_item(tree, hf_zbee_zcl_part_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_part);

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_PART_MULTI_ACK:
                    dissect_zcl_part_multiack(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PART_RD_HANDSHAKE_PARAM_RSP:
                    dissect_zcl_part_rdhandshakeparamrsp(tvb, pinfo, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_length(tvb);
} /*dissect_zbee_zcl_part*/

 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_part_trasfpartframe
 *  DESCRIPTION
 *      This function manages the Trasfer Partition Frame payload
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      offset              - pointer of buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void dissect_zcl_part_trasfpartframe(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree *sub_tree = NULL;
    proto_item *ti;

    guint8    options;
    guint16   u16len;
    guint8    frame_len;
    guint8    *data_frame;

    /* Retrieve "Fragmentation Options" field */
    options = tvb_get_guint8(tvb, *offset);
    ti = proto_tree_add_text(tree, tvb, *offset, 1, "Fragmentation Options: 0x%02x", options);
    sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_part_fragm_options);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_part_opt_first_block, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_part_opt_indic_len, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_part_opt_res, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "PartitionIndicator" field */
    if ((options & ZBEE_ZCL_PART_OPT_INDIC_LEN) ==  0)
    {
        /* 1-byte length */
        u16len = (guint16)tvb_get_guint8(tvb, *offset);
        proto_tree_add_item(tree, hf_zbee_zcl_part_part_indicator, tvb, *offset, 1, (u16len & 0xFF));
        *offset += 1;
    }
    else {
        /* 2-bytes length */
        u16len = tvb_get_letohs(tvb, *offset);
        proto_tree_add_item(tree, hf_zbee_zcl_part_part_indicator, tvb, *offset, 2, u16len);
        *offset += 2;
    }

    /* Retrieve PartitionedFrame length field */
    frame_len = tvb_get_guint8(tvb, *offset); /* string length */
    if (frame_len == ZBEE_ZCL_INVALID_STR_LENGTH)
        frame_len = 0;
    proto_tree_add_item(tree, hf_zbee_zcl_part_part_frame_len, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "PartitionedFrame" field */
    data_frame = tvb_bytes_to_ep_str_punct(tvb, *offset, frame_len, ':');
    proto_tree_add_string(tree, hf_zbee_zcl_part_part_frame, tvb, *offset, frame_len, data_frame);
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
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_part_rdhandshakeparam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
    /* Retrieve "Partitioned Cluster ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_part_partitioned_cluster_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Dissect the attribute id list */
    dissect_zcl_read_attr(tvb, pinfo, tree, offset, ZBEE_ZCL_CID_PARTITION);
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
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_part_wrhandshakeparam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
    /* Retrieve "Partitioned Cluster ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_part_partitioned_cluster_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Dissect the attributes list */
    dissect_zcl_write_attr(tvb, pinfo, tree, offset, ZBEE_ZCL_CID_PARTITION);

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
dissect_zcl_part_multiack(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree *sub_tree = NULL;
    proto_item *ti;

    guint   tvb_len = tvb_reported_length(tvb);
    guint   i = 0;
    guint8  options;
    guint16 first_frame_id;
    guint16 nack_id;

    /* Retrieve "Ack Options" field */
    options = tvb_get_guint8(tvb, *offset);
    ti = proto_tree_add_text(tree, tvb, *offset, 1, "Ack Options: 0x%02x", options);
    sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_part_ack_opts);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_part_ack_opt_nack_id_len, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_part_ack_opt_res, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "First Frame ID" field */
    if ((options & ZBEE_ZCL_PART_ACK_OPT_NACK_LEN) ==  0)
    {
        /* 1-byte length */
        first_frame_id = (guint16)tvb_get_guint8(tvb, *offset);
        proto_tree_add_item(tree, hf_zbee_zcl_part_first_frame_id, tvb, *offset, 1, (first_frame_id & 0xFF));
        *offset += 1;
    }
    else {
        /* 2-bytes length */
        first_frame_id = tvb_get_letohs(tvb, *offset);
        proto_tree_add_item(tree, hf_zbee_zcl_part_first_frame_id, tvb, *offset, 2, first_frame_id);
        *offset += 2;
    }

    /* Dissect the nack id list */
    while ( *offset < tvb_len && i < ZBEE_ZCL_PART_NUM_NACK_ID_ETT )
    {
        if ((options & ZBEE_ZCL_PART_ACK_OPT_NACK_LEN) ==  0)
        {
            /* 1-byte length */
            nack_id = (guint16)tvb_get_guint8(tvb, *offset);
            proto_tree_add_item(tree, hf_zbee_zcl_part_nack_id, tvb, *offset, 1, (nack_id & 0xFF));
            *offset += 1;
        }
        else {
            /* 2-bytes length */
            nack_id = tvb_get_letohs(tvb, *offset);
            proto_tree_add_item(tree, hf_zbee_zcl_part_nack_id, tvb, *offset, 2, nack_id);
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
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_part_rdhandshakeparamrsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
    /* Retrieve "Partitioned Cluster ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_part_partitioned_cluster_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Dissect the attributes list */
    dissect_zcl_read_attr_resp(tvb, pinfo, tree, offset, ZBEE_ZCL_CID_PARTITION);
} /*dissect_zcl_part_rdhandshakeparamrsp*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_part_attr_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_part_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_part_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
} /*dissect_zcl_part_attr_id*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_part_cmd_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster command identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint8 cmd_dir      - command direction
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_part_cmd_id(proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir)
{
    if (cmd_dir == ZBEE_ZCL_FCF_TO_CLIENT)
        proto_tree_add_item(tree, hf_zbee_zcl_part_srv_rx_cmd_id, tvb, *offset, 1, ENC_NA);
    else
        proto_tree_add_item(tree, hf_zbee_zcl_part_srv_tx_cmd_id, tvb, *offset, 1, ENC_NA);
} /*dissect_zcl_part_cmd_id*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_part
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
void proto_register_zbee_zcl_part(void)
{
    guint8  i, j;

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

        { &hf_zbee_zcl_part_part_frame_len,
            { "Partition Frame Length", "zbee_zcl_general.part.part_frame_length", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_part_part_frame,
            { "Partition Frame", "zbee_zcl_general.part.part_frame", FT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_part_partitioned_cluster_id,
            { "Partitioned Cluster ID", "zbee_zcl_general.part.part_cluster_id", FT_UINT16, BASE_HEX, VALS(zbee_aps_cid_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_part_ack_opt_nack_id_len,
            { "Nack Id Length", "zbee_zcl_general.ack_opt.part.nack_id.len", FT_UINT8, BASE_HEX, VALS(zbee_zcl_part_id_length_names),
            ZBEE_ZCL_PART_ACK_OPT_NACK_LEN, NULL, HFILL } },

        { &hf_zbee_zcl_part_ack_opt_res,
            { "Reserved", "zbee_zcl_general.part.ack_opt.reserved", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_PART_ACK_OPT_RESERVED, NULL, HFILL } },

        { &hf_zbee_zcl_part_nack_id,
            { "Nack Id", "zbee_zcl_general.part.nack_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } }

    };

    /* ZCL Partition subtrees */
    gint *ett[ZBEE_ZCL_PART_NUM_ETT];

    ett[0] = &ett_zbee_zcl_part;
    ett[1] = &ett_zbee_zcl_part_fragm_options;
    ett[2] = &ett_zbee_zcl_part_ack_opts;

    /* initialize attribute subtree types */
    for ( i = 0, j = ZBEE_ZCL_PART_NUM_GENERIC_ETT; i < ZBEE_ZCL_PART_NUM_NACK_ID_ETT; i++, j++) {
        ett_zbee_zcl_part_nack_id_list[i] = -1;
        ett[j] = &ett_zbee_zcl_part_nack_id_list[i];
    }

    for ( i = 0; i < ZBEE_ZCL_PART_NUM_ATTRS_ID_ETT; i++, j++) {
        ett_zbee_zcl_part_attrs_id_list[i] = -1;
        ett[j] = &ett_zbee_zcl_part_attrs_id_list[i];
    }

    /* Register ZigBee ZCL Partition protocol with Wireshark. */
    proto_zbee_zcl_part = proto_register_protocol("ZigBee ZCL Partition", "ZCL Partition", ZBEE_PROTOABBREV_ZCL_PART);
    proto_register_field_array(proto_zbee_zcl_part, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Partition dissector. */
    new_register_dissector(ZBEE_PROTOABBREV_ZCL_PART, dissect_zbee_zcl_part, proto_zbee_zcl_part);

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
    dissector_handle_t part_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    part_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_PART);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_PARTITION, part_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_part,
                            ett_zbee_zcl_part,
                            ZBEE_ZCL_CID_PARTITION,
                            (zbee_zcl_fn_attr_id)dissect_zcl_part_attr_id,
                            NULL,
                            (zbee_zcl_fn_cmd_id)dissect_zcl_part_cmd_id
                         );

} /*proto_reg_handoff_zbee_zcl_part*/

/* ########################################################################## */
/* #### (0x0019) OTA UPGRADE CLUSTER ######################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_OTA_NUM_GENERIC_ETT                        3
#define ZBEE_ZCL_OTA_NUM_ETT                                (ZBEE_ZCL_OTA_NUM_GENERIC_ETT)

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_OTA_UPGRADE_SERVER_ID              0x0000  /* Upgrade Served ID */
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
#define ZBEE_ZCL_OTA_FILE_VERS_APPL_RELEASE             0x000000FF  /* Application Release */
#define ZBEE_ZCL_OTA_FILE_VERS_APPL_BUILD               0x0000FF00  /* Application Build */
#define ZBEE_ZCL_OTA_FILE_VERS_STACK_RELEASE            0x00FF0000  /* Stack Release */
#define ZBEE_ZCL_OTA_FILE_VERS_STACK_BUILD              0xFF000000  /* Stack Build */

/* Field Control bitmask field list */
#define ZBEE_ZCL_OTA_FIELD_CTRL_HW_VER_PRESENT                0x01  /* bit     0 */
#define ZBEE_ZCL_OTA_FIELD_CTRL_RESERVED                      0xfe  /* bit   1-7 */
#define ZBEE_ZCL_OTA_FIELD_CTRL_IEEE_ADDR_PRESENT             0x01  /* bit     0 - Request nodes IEEE address Present  */

/* OTA Time */
#define ZBEE_ZCL_OTA_TIME_NOW                           0x00000000  /* Now */
#define ZBEE_ZCL_OTA_TIME_UTC_LO                        0x00000001  /* UTC Low Boundary */
#define ZBEE_ZCL_OTA_TIME_UTC_HI                        0xfffffffe  /* UTC High Boundary */
#define ZBEE_ZCL_OTA_TIME_WAIT                          0xffffffff  /* Wait for a Upgrade command (not used for RequesTime) */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_ota(void);
void proto_reg_handoff_zbee_zcl_ota(void);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_ota = -1;

static int hf_zbee_zcl_ota_attr_id = -1;
static int hf_zbee_zcl_ota_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_ota_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_ota_image_upgrade_status = -1;
static int hf_zbee_zcl_ota_zb_stack_ver = -1;
static int hf_zbee_zcl_ota_file_offset = -1;
static int hf_zbee_zcl_ota_payload_type = -1;
static int hf_zbee_zcl_ota_query_jitter = -1;
static int hf_zbee_zcl_ota_manufacturer_code = -1;
static int hf_zbee_zcl_ota_image_type = -1;
static int hf_zbee_zcl_ota_file_version_appl_release = -1;
static int hf_zbee_zcl_ota_file_version_appl_build = -1;
static int hf_zbee_zcl_ota_file_version_stack_release = -1;
static int hf_zbee_zcl_ota_file_version_stack_build = -1;
static int hf_zbee_zcl_ota_field_ctrl_hw_ver_present = -1;
static int hf_zbee_zcl_ota_field_ctrl_reserved = -1;
static int hf_zbee_zcl_ota_hw_version = -1;
static int hf_zbee_zcl_ota_status = -1;
static int hf_zbee_zcl_ota_image_size = -1;
static int hf_zbee_zcl_ota_max_data_size = -1;
static int hf_zbee_zcl_ota_req_node_addr = -1;
static int hf_zbee_zcl_ota_current_time = -1;
static int hf_zbee_zcl_ota_request_time = -1;
static int hf_zbee_zcl_ota_upgrade_time = -1;
static int hf_zbee_zcl_ota_data_size = -1;
static int hf_zbee_zcl_ota_image_data = -1;
static int hf_zbee_zcl_ota_page_size = -1;
static int hf_zbee_zcl_ota_rsp_spacing = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_ota = -1;
static gint ett_zbee_zcl_ota_field_ctrl = -1;
static gint ett_zbee_zcl_ota_file_version = -1;

/* Attributes */
static const value_string zbee_zcl_ota_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_OTA_UPGRADE_SERVER_ID,               "Upgrade Served ID" },
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
decode_zcl_ota_curr_time(gchar *s, guint32 value)
{
     if (value == ZBEE_ZCL_OTA_TIME_NOW)
         g_snprintf(s, ITEM_LABEL_LENGTH, "Now");
     else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%s", abs_time_secs_to_str(wmem_packet_scope(), value, ABSOLUTE_TIME_LOCAL, 1));

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
decode_zcl_ota_req_time(gchar *s, guint32 value)
{
     if (value == ZBEE_ZCL_OTA_TIME_WAIT)
         g_snprintf(s, ITEM_LABEL_LENGTH, "Wrong Value");
     else
         /* offset from now */
        g_snprintf(s, ITEM_LABEL_LENGTH, "%s from now", time_secs_to_str(wmem_packet_scope(), value));

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
decode_zcl_ota_upgr_time(gchar *s, guint32 value)
{
     if (value == ZBEE_ZCL_OTA_TIME_WAIT)
         g_snprintf(s, ITEM_LABEL_LENGTH, "Wait for upgrade command");
     else
         /* offset from now */
        g_snprintf(s, ITEM_LABEL_LENGTH, "%s from now", time_secs_to_str(wmem_packet_scope(), value));

    return;
} /*decode_zcl_ota_upgr_time*/

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
decode_zcl_ota_size_in_bytes(gchar *s, guint32 value)
{
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d [Bytes]", value);
} /*decode_zcl_ota_size_in_bytes*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_file_version_field
 *  DESCRIPTION
 *      this function is called in order to decode "FileVersion" field,
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_file_version_field(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree  *sub_tree = NULL;
    proto_item  *ti;
    guint32     file_version;

    /* 'File Version' field present, retrieves it */
    file_version = tvb_get_ntohl(tvb, *offset);
    ti = proto_tree_add_text(tree, tvb, *offset, 4, "File Version: 0x%08x", file_version);
    sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_ota_file_version);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_ota_file_version_appl_release, tvb, *offset, 4, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_ota_file_version_appl_build, tvb, *offset, 4, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_ota_file_version_stack_release, tvb, *offset, 4, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_ota_file_version_stack_build, tvb, *offset, 4, ENC_NA);
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static guint8
dissect_zcl_ota_field_ctrl_field(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree  *sub_tree = NULL;
    proto_item  *ti;
    guint8      field_ctrl;

    /* Retrieve 'Field Control' field */
    field_ctrl = tvb_get_guint8(tvb, *offset);
    ti = proto_tree_add_text(tree, tvb, *offset, 1, "Field Control: 0x%02x", field_ctrl);
    sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_ota_field_ctrl);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_ota_field_ctrl_hw_ver_present, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_ota_field_ctrl_reserved, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    return field_ctrl;
} /*dissect_zcl_ota_field_ctrl_field*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_imagenotify
 *  DESCRIPTION
 *      this function is called in order to decode "ImageNotify",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_imagenotify(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8  payload_type;

    /* Retrieve 'Payload type' field */
    payload_type = tvb_get_guint8(tvb, *offset);
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_querynextimagereq(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8  field_ctrl;

    /* Retrieve 'Field Control' field */
    field_ctrl = dissect_zcl_ota_field_ctrl_field(tvb, tree, offset);

    /* Retrieve 'Manufacturer Code' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'Image Type' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'File Version' field */
    dissect_zcl_ota_file_version_field(tvb, tree, offset);

    /* Check if there are optional fields */

    if (field_ctrl & ZBEE_ZCL_OTA_FIELD_CTRL_HW_VER_PRESENT) {
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_querynextimagersp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8  status;

    /* Retrieve 'Status' field */
    status = tvb_get_guint8(tvb, *offset);
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_imageblockreq(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8  field_ctrl;

    /* Retrieve 'Field Control' field */
    field_ctrl = dissect_zcl_ota_field_ctrl_field(tvb, tree, offset);

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

    if (field_ctrl & ZBEE_ZCL_OTA_FIELD_CTRL_IEEE_ADDR_PRESENT) {
        /* 'Requerst Node Address' field present, retrieves it */
        proto_tree_add_item(tree, hf_zbee_zcl_ota_req_node_addr, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_imagepagereq(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8  field_ctrl;

    /* Retrieve 'Field Control' field */
    field_ctrl = dissect_zcl_ota_field_ctrl_field(tvb, tree, offset);

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

    if (field_ctrl & ZBEE_ZCL_OTA_FIELD_CTRL_IEEE_ADDR_PRESENT) {
        /* 'Requerst Node Address' field present, retrieves it */
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_imageblockrsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8  status;
    guint8  data_size;
    guint8  *image_data;

    /* Retrieve 'Status' field */
    status = tvb_get_guint8(tvb, *offset);
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
        data_size = tvb_get_guint8(tvb, *offset);
        proto_tree_add_item(tree, hf_zbee_zcl_ota_data_size, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Retrieve 'Image Data' field */
        image_data = tvb_bytes_to_ep_str_punct(tvb, *offset, data_size, ':');
        proto_tree_add_string(tree, hf_zbee_zcl_ota_image_data, tvb, *offset, data_size, image_data);
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_upgradeendreq(tvbuff_t *tvb, proto_tree *tree, guint *offset)
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_upgradeendrsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve 'Manufacturer Code' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'Image Type' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_image_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve 'File Version' field */
    dissect_zcl_ota_file_version_field(tvb, tree, offset);

    /* Retrieve 'Current Time' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_current_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve 'Upgrade Time' field */
    proto_tree_add_item(tree, hf_zbee_zcl_ota_upgrade_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

} /*dissect_zcl_ota_upgradeendrsp*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_queryspecfilereq
 *  DESCRIPTION
 *      this function is called in order to decode "QuerySpecificFileRequest",
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_queryspecfilereq(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* 'Requerst Node Address' field present, retrieves it */
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_queryspecfilersp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8  status;

    /* Retrieve 'Status' field */
    status = tvb_get_guint8(tvb, *offset);
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
 *      dissect_zcl_ota_attr_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_ota_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
} /*dissect_zcl_ota_attr_id*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_attr_data
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
static void
dissect_zcl_ota_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_ota_attr_data*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_ota_cmd_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster command identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint8 cmd_dir      - command direction
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_ota_cmd_id(proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir)
{
    if (cmd_dir == ZBEE_ZCL_FCF_TO_CLIENT)
        proto_tree_add_item(tree, hf_zbee_zcl_ota_srv_rx_cmd_id, tvb, *offset, 1, ENC_NA);
    else
        proto_tree_add_item(tree, hf_zbee_zcl_ota_srv_tx_cmd_id, tvb, *offset, 1, ENC_NA);
} /*dissect_zcl_ota_cmd_id*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_ota
 *  DESCRIPTION
 *      ZigBee ZCL OTA cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_ota(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item        *payload_root;
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    guint             offset = 0;
    guint8            cmd_id;
    gint              rem_len;

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
        proto_tree_add_item(tree, hf_zbee_zcl_ota_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_ota);

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
        proto_tree_add_item(tree, hf_zbee_zcl_ota_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_ota);

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

    return tvb_length(tvb);
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
 *      guint *offset       - pointer to buffer offset
 *      guint16 attr_id     - attribute identifier
 *      guint data_type     - attribute data type
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
            { "Query Jitter", "zbee_zcl_general.ota.query_jitter", FT_UINT16, BASE_CUSTOM, decode_zcl_time_in_seconds,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_manufacturer_code,
            { "Manufacturer Code", "zbee_zcl_general.ota.manufacturer_code", FT_UINT16, BASE_HEX, VALS(zbee_mfr_code_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_type,
            { "Image Type", "zbee_zcl_general.ota.image.type", FT_UINT16, BASE_HEX | BASE_RANGE_STRING,
            RVALS(zbee_zcl_ota_image_type_names), 0x0, NULL, HFILL } },

/* Begin FileVersion fields */
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

/* Begin FieldControl fields */
        { &hf_zbee_zcl_ota_field_ctrl_hw_ver_present,
            { "Hardware Version", "zbee_zcl_general.ota.field_ctrl_hw_ver_present",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), ZBEE_ZCL_OTA_FIELD_CTRL_HW_VER_PRESENT, NULL, HFILL } },

        { &hf_zbee_zcl_ota_field_ctrl_reserved,
            { "Reserved", "zbee_zcl_general.ota.field_ctrl_reserved", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_OTA_FIELD_CTRL_RESERVED, NULL, HFILL } },
/* End FieldControl fields */

        { &hf_zbee_zcl_ota_hw_version,
            { "Hardware Version", "zbee_zcl_general.ota.hw_ver", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_status,
            { "Status", "zbee_zcl_general.ota.status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_status_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_size,
            { "Image Size", "zbee_zcl_general.ota.image.size", FT_UINT32, BASE_CUSTOM, decode_zcl_ota_size_in_bytes,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_file_offset,
            { "File Offset", "zbee_zcl_general.ota.file.offset", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_max_data_size,
            { "Max Data Size", "zbee_zcl_general.ota.max_data_size", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_req_node_addr,
            { "Ieee Address", "zbee_zcl_general.ota.ieee_addr", FT_UINT64, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_page_size,
            { "Page Size", "zbee_zcl_general.ota.page.size", FT_UINT16, BASE_CUSTOM, decode_zcl_ota_size_in_bytes,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_rsp_spacing,
            { "Response Spacing", "zbee_zcl_general.ota.rsp_spacing", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ota_current_time,
            { "Current Time", "zbee_zcl_general.ota.current_time", FT_UINT32, BASE_CUSTOM, decode_zcl_ota_curr_time,
            0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ota_request_time,
            { "Request Time", "zbee_zcl_general.ota.request_time", FT_UINT32, BASE_CUSTOM, decode_zcl_ota_req_time,
            0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ota_upgrade_time,
            { "Upgrade Time", "zbee_zcl_general.ota.upgrade_time", FT_UINT32, BASE_CUSTOM, decode_zcl_ota_upgr_time,
            0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ota_data_size,
            { "Data Size", "zbee_zcl_general.ota.data_size", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ota_image_data,
            { "Image Data", "zbee_zcl_general.ota.image.data", FT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } }
   };

    /* ZCL OTA subtrees */
    gint *ett[ZBEE_ZCL_OTA_NUM_ETT];
    ett[0] = &ett_zbee_zcl_ota;
    ett[1] = &ett_zbee_zcl_ota_field_ctrl;
    ett[2] = &ett_zbee_zcl_ota_file_version;

    /* Register ZigBee ZCL Ota protocol with Wireshark. */
    proto_zbee_zcl_ota = proto_register_protocol("ZigBee ZCL OTA", "ZCL OTA", ZBEE_PROTOABBREV_ZCL_OTA);
    proto_register_field_array(proto_zbee_zcl_ota, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL OTA dissector. */
    new_register_dissector(ZBEE_PROTOABBREV_ZCL_OTA, dissect_zbee_zcl_ota, proto_zbee_zcl_ota);

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
    dissector_handle_t ota_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    ota_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_OTA);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_OTA_UPGRADE, ota_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_ota,
                            ett_zbee_zcl_ota,
                            ZBEE_ZCL_CID_OTA_UPGRADE,
                            (zbee_zcl_fn_attr_id)dissect_zcl_ota_attr_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_ota_attr_data,
                            (zbee_zcl_fn_cmd_id)dissect_zcl_ota_cmd_id
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
static void dissect_zcl_pwr_prof_pwrprofreq                 (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pwr_prof_getpwrprofpricersp         (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pwr_prof_getoverallschedpricersp    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pwr_prof_enphsschednotif            (tvbuff_t *tvb, proto_tree *tree, guint *offset);

static void dissect_zcl_energy_phase                        (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pwr_prof_pwrprofnotif               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_power_profile                       (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pwr_prof_pwrprofstatersp            (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pwr_prof_pwrprofschedcontrsnotif    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pwr_prof_pwrprofpriceext            (tvbuff_t *tvb, proto_tree *tree, guint *offset);

static void dissect_zcl_pwr_prof_attr_id    (proto_tree *tree, tvbuff_t *tvb, guint *offset);
static void dissect_zcl_pwr_prof_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);
static void dissect_zcl_pwr_prof_cmd_id     (proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir);

/* Private functions prototype */
static void decode_power_profile_id     (gchar *s, guint8 id);
static void decode_price_in_cents       (gchar *s, guint32 value);
static void decode_power_in_watt        (gchar *s, guint16 value);
static void decode_energy               (gchar *s, guint16 value);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_pwr_prof = -1;

static int hf_zbee_zcl_pwr_prof_attr_id = -1;
static int hf_zbee_zcl_pwr_prof_tot_prof_num = -1;
static int hf_zbee_zcl_pwr_prof_multiple_sched = -1;
static int hf_zbee_zcl_pwr_prof_energy_format_rdigit = -1;
static int hf_zbee_zcl_pwr_prof_energy_format_ldigit = -1;
static int hf_zbee_zcl_pwr_prof_energy_format_noleadingzero = -1;
static int hf_zbee_zcl_pwr_prof_energy_remote = -1;
static int hf_zbee_zcl_pwr_prof_sched_mode_cheapest = -1;
static int hf_zbee_zcl_pwr_prof_sched_mode_greenest = -1;
static int hf_zbee_zcl_pwr_prof_sched_mode_reserved = -1;
static int hf_zbee_zcl_pwr_prof_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_pwr_prof_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_pwr_prof_pwr_prof_id = -1;
static int hf_zbee_zcl_pwr_prof_currency = -1;
static int hf_zbee_zcl_pwr_prof_price = -1;
static int hf_zbee_zcl_pwr_prof_price_trailing_digit = -1;
static int hf_zbee_zcl_pwr_prof_num_of_sched_phases = -1;
static int hf_zbee_zcl_pwr_prof_scheduled_time = -1;
static int hf_zbee_zcl_pwr_prof_pwr_prof_count = -1;
static int hf_zbee_zcl_pwr_prof_num_of_trans_phases = -1;
static int hf_zbee_zcl_pwr_prof_energy_phase_id = -1;
static int hf_zbee_zcl_pwr_prof_macro_phase_id = -1;
static int hf_zbee_zcl_pwr_prof_expect_duration = -1;
static int hf_zbee_zcl_pwr_prof_peak_power = -1;
static int hf_zbee_zcl_pwr_prof_energy = -1;
static int hf_zbee_zcl_pwr_prof_max_active_delay = -1;
static int hf_zbee_zcl_pwr_prof_pwr_prof_rem_ctrl = -1;
static int hf_zbee_zcl_pwr_prof_pwr_prof_state = -1;
static int hf_zbee_zcl_pwr_prof_start_after = -1;
static int hf_zbee_zcl_pwr_prof_stop_before = -1;
static int hf_zbee_zcl_pwr_prof_options_01 = -1;
static int hf_zbee_zcl_pwr_prof_options_res = -1;
static int hf_zbee_zcl_pwr_prof_pwr_prof_stime = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_pwr_prof = -1;
static gint ett_zbee_zcl_pwr_prof_options = -1;
static gint ett_zbee_zcl_pwr_prof_en_format = -1;
static gint ett_zbee_zcl_pwr_prof_sched_mode = -1;
static gint ett_zbee_zcl_pwr_prof_pwrprofiles[ZBEE_ZCL_PWR_PROF_NUM_PWR_PROF_ETT];
static gint ett_zbee_zcl_pwr_prof_enphases[ZBEE_ZCL_PWR_PROF_NUM_EN_PHS_ETT];

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
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_pwr_prof (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item        *payload_root;
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    guint             offset = 0;
    guint8            cmd_id;
    gint              rem_len;

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
        proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_pwr_prof);

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
        proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_pwr_prof);

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

    return tvb_length(tvb);
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_pwrprofreq(tvbuff_t *tvb, proto_tree *tree, guint *offset)
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_getpwrprofpricersp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_getoverallschedpricersp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_sched_energy_phase(tvbuff_t *tvb, proto_tree *tree, guint *offset)
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_enphsschednotif(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

    guint i;
    guint8 num_of_sched_phases;

    /* Retrieve "Power Profile Id" field */
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Number of Scheduled Phases" field */
    num_of_sched_phases = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_num_of_sched_phases, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Scheduled Energy Phases decoding */
    for (i=0 ; i<num_of_sched_phases ; i++) {
        /* Create subtree */
        ti = proto_tree_add_text(tree, tvb, *offset, 1, "Energy Phase #%u", i);
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_pwr_prof_enphases[i]);

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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_energy_phase(tvbuff_t *tvb, proto_tree *tree, guint *offset)
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_pwrprofnotif(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

    guint i;
    guint8 total_profile_number;
    guint8 num_of_transferred_phases;

    /* Retrieve "Total Profile Number" field */
    total_profile_number = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_tot_prof_num, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    if ( total_profile_number != 0 ) {
        /* Retrieve "Power Profile Id" field */
        proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_id, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Retrieve "Number of Transferred Phases" field */
        num_of_transferred_phases = tvb_get_guint8(tvb, *offset);
        proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_num_of_trans_phases, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Energy Phases decoding */
        for ( i=0 ; i<num_of_transferred_phases ; i++) {
            /* Create subtree */
            ti = proto_tree_add_text(tree, tvb, *offset, 1, "Energy Phase #%u", i);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_pwr_prof_enphases[i]);

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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_power_profile(tvbuff_t *tvb, proto_tree *tree, guint *offset)
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_pwrprofstatersp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

    guint i;
    guint8 power_profile_count;

    /* Retrieve "Total Profile Number" field */
    power_profile_count = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_pwr_prof_count, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Energy Phases decoding */
    for (i=0 ; i<power_profile_count ; i++) {
        /* Create subtree */
        ti = proto_tree_add_text(tree, tvb, *offset, 1, "Power Profile #%u", i);
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_pwr_prof_pwrprofiles[i]);

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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_pwrprofschedcontrsnotif(tvbuff_t *tvb, proto_tree *tree, guint *offset)
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_pwrprofpriceext(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree *sub_tree = NULL;
    proto_item *ti;
    guint8 options;

    /* Retrieve "Options" field */
    options = tvb_get_guint8(tvb, *offset);
    ti = proto_tree_add_text(tree, tvb, *offset, 1, "Options: 0x%02x", options);
    sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_pwr_prof_options);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_pwr_prof_options_01, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_pwr_prof_options_res, tvb, *offset, 1, ENC_NA);
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
 *      dissect_zcl_pwr_prof_attr_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
} /*dissect_zcl_pwr_prof_attr_id*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_attr_data
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
static void
dissect_zcl_pwr_prof_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;
    guint8      value8;

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
            value8 = tvb_get_guint8(tvb, *offset);
            ti = proto_tree_add_text(tree, tvb, *offset, 1, "Data: 0x%02x", value8);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_pwr_prof_en_format);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_pwr_prof_energy_format_rdigit, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_pwr_prof_energy_format_ldigit, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_pwr_prof_energy_format_noleadingzero, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_PWR_PROF_ENERGY_REMOTE:
            proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_energy_remote, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_PWR_PROF_SCHED_MODE:
            value8 = tvb_get_guint8(tvb, *offset);
            ti = proto_tree_add_text(tree, tvb, *offset, 1, "Schedule Mode: 0x%02x", value8);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_pwr_prof_sched_mode);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_pwr_prof_sched_mode_cheapest, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_pwr_prof_sched_mode_greenest, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_pwr_prof_sched_mode_reserved, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
        break;
    }
} /*dissect_zcl_pwr_prof_attr_data*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_pwr_prof_cmd_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster command identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint8 cmd_dir      - command direction
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_pwr_prof_cmd_id(proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir)
{
    if (cmd_dir == ZBEE_ZCL_FCF_TO_CLIENT)
        proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_srv_rx_cmd_id, tvb, *offset, 1, ENC_NA);
    else
        proto_tree_add_item(tree, hf_zbee_zcl_pwr_prof_srv_tx_cmd_id, tvb, *offset, 1, ENC_NA);
} /*dissect_zcl_pwr_prof_cmd_id*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_power_profile_id
 *  DESCRIPTION
 *      this function decodes the power profile custom type
 *  PARAMETERS
 *      guint *s        - string to display
 *      guint16 value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_power_profile_id(gchar *s, guint8 id)
{
    if (id == 0) {
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d (All)", id);
    }
    else {
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d", id);
    }
} /*decode_power_profile_id*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_price_in_cents
 *  DESCRIPTION
 *      this function decodes price type variable
 *  PARAMETERS
 *      guint *s        - string to display
 *      guint16 value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_price_in_cents(gchar *s, guint32 value)
{
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d cents", value);
} /* decode_price_in_cents */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_power_in_watt
 *  DESCRIPTION
 *      this function decodes watt power type variable
 *  PARAMETERS
 *      guint *s        - string to display
 *      guint16 value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_power_in_watt(gchar *s, guint16 value)
{
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d Watt", value);
} /* decode_power_in_watt */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_energy
 *  DESCRIPTION
 *      this function decodes energy type variable
 *  PARAMETERS
 *      guint *s        - string to display
 *      guint16 value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_energy(gchar *s, guint16 value)
{
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d Watt per hours", value);
} /* decode_energy */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      func_decode_delayinminute
 *  DESCRIPTION
 *    this function decodes minute delay type variable
 *  PARAMETERS
 *      guint *s        - string to display
 *      guint16 value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
func_decode_delayinminute(gchar *s, guint16 value)
{
    if (value == 0) {
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d minutes (Not permitted)", value);
    }
    else {
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d minutes", value);
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
    guint i, j;

    static hf_register_info hf[] = {

        { &hf_zbee_zcl_pwr_prof_tot_prof_num,
            { "Total Profile Number", "zbee_zcl_general.pwrprof.attr.totprofnum", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_multiple_sched,
            { "Multiple Scheduling", "zbee_zcl_general.pwrprof.attr.multiplesched", FT_BOOLEAN, BASE_NONE,
            TFS(&tfs_supported_not_supported), 0x0, NULL, HFILL } },

/* Begin EnergyFormatting fields */
        { &hf_zbee_zcl_pwr_prof_energy_format_rdigit,
            { "Number of Digits to the right of the Decimal Point", "zbee_zcl_general.pwrprof.attr.energyformat.rdigit",
            FT_UINT8, BASE_DEC, NULL, ZBEE_ZCL_OPT_PWRPROF_NUM_R_DIGIT, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_energy_format_ldigit,
            { "Number of Digits to the left of the Decimal Point", "zbee_zcl_general.pwrprof.attr.energyformat.ldigit",
            FT_UINT8, BASE_DEC, NULL, ZBEE_ZCL_OPT_PWRPROF_NUM_L_DIGIT, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_energy_format_noleadingzero,
            { "Suppress leading zeros.", "zbee_zcl_general.pwrprof.attr.energyformat.noleadingzero",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), ZBEE_ZCL_OPT_PWRPROF_NO_LEADING_ZERO, NULL, HFILL } },
/* End EnergyFormatting fields */

        { &hf_zbee_zcl_pwr_prof_energy_remote,
            { "Energy Remote", "zbee_zcl_general.pwrprof.attr.energyremote", FT_BOOLEAN, BASE_NONE,
            TFS(&tfs_enabled_disabled), 0x0, NULL, HFILL } },

/* Begin ScheduleMode fields */
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
            { "Power Profile ID", "zbee_zcl_general.pwrprof.pwrprofid", FT_UINT8, BASE_CUSTOM, decode_power_profile_id, 0x00,
            "Identifier of the specific profile", HFILL } },

        { &hf_zbee_zcl_pwr_prof_currency,
            { "Currency", "zbee_zcl_general.pwrprof.currency", FT_UINT16, BASE_HEX, VALS(zbee_zcl_currecy_names), 0x0,
            "Local unit of currency (ISO 4217) used in the price field.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_price,
            { "Price", "zbee_zcl_general.pwrprof.price", FT_UINT32, BASE_CUSTOM, decode_price_in_cents, 0x0,
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
            { "Scheduled Time", "zbee_zcl_general.pwrprof.scheduledtime", FT_UINT16, BASE_CUSTOM, decode_zcl_time_in_minutes, 0x0,
            NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_macro_phase_id,
            { "Macro Phase ID", "zbee_zcl_general.pwrprof.macrophaseid", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Identifier of the specific energy phase.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_expect_duration,
            { "Expected Duration", "zbee_zcl_general.pwrprof.expecduration", FT_UINT16, BASE_CUSTOM, decode_zcl_time_in_minutes, 0x0,
            "The estimated duration of the specific phase.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_num_of_trans_phases,
            { "Number of Transferred Phases", "zbee_zcl_general.pwrprof.numoftransphases", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_peak_power,
            { "Peak Power", "zbee_zcl_general.pwrprof.peakpower", FT_UINT16, BASE_CUSTOM, decode_power_in_watt, 0x0,
            "The estimated power for the specific phase.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_energy,
            { "Energy", "zbee_zcl_general.pwrprof.energy", FT_UINT16, BASE_CUSTOM, decode_energy, 0x0,
            "The estimated energy consumption for the accounted phase.", HFILL } },

        { &hf_zbee_zcl_pwr_prof_max_active_delay,
            { "Max Activation Delay", "zbee_zcl_general.pwrprof.maxactivdelay", FT_UINT16, BASE_CUSTOM, func_decode_delayinminute, 0x0,
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
            { "Start After", "zbee_zcl_general.pwrprof.startafter", FT_UINT16, BASE_CUSTOM, decode_zcl_time_in_minutes, 0x0,
            NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_stop_before,
            { "Stop Before", "zbee_zcl_general.pwrprof.stopbefore", FT_UINT16, BASE_CUSTOM, decode_zcl_time_in_minutes, 0x0,
            NULL, HFILL } },

/* Begin Options fields */
        { &hf_zbee_zcl_pwr_prof_options_01,
            { "PowerProfileStartTime Field Present", "zbee_zcl_general.pwrprof.options.01", FT_BOOLEAN, 8, TFS(&tfs_true_false),
            ZBEE_ZCL_OPT_PWRPROF_STIME_PRESENT, NULL, HFILL } },

        { &hf_zbee_zcl_pwr_prof_options_res,
            { "Reserved", "zbee_zcl_general.pwrprof.options.reserved", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_OPT_PWRPROF_RESERVED, NULL, HFILL } },
/* End Options fields */

        { &hf_zbee_zcl_pwr_prof_pwr_prof_stime,
            { "Power Profile Start Time", "zbee_zcl_general.pwrprof.pwrprofstime", FT_UINT16, BASE_CUSTOM, decode_zcl_time_in_minutes, 0x0,
            NULL, HFILL } }

  };

    /* ZCL PowerProfile subtrees */
    static gint *ett[ZBEE_ZCL_PWR_PROF_NUM_ETT];

    ett[0] = &ett_zbee_zcl_pwr_prof;
    ett[1] = &ett_zbee_zcl_pwr_prof_options;
    ett[2] = &ett_zbee_zcl_pwr_prof_en_format;
    ett[3] = &ett_zbee_zcl_pwr_prof_sched_mode;

    /* initialize attribute subtree types */
    for ( i = 0, j = ZBEE_ZCL_PWR_PROF_NUM_GENERIC_ETT; i < ZBEE_ZCL_PWR_PROF_NUM_PWR_PROF_ETT; i++, j++ ) {
        ett_zbee_zcl_pwr_prof_pwrprofiles[i] = -1;
        ett[j] = &ett_zbee_zcl_pwr_prof_pwrprofiles[i];
    }

    for ( i = 0; i < ZBEE_ZCL_PWR_PROF_NUM_EN_PHS_ETT; i++, j++ ) {
        ett_zbee_zcl_pwr_prof_enphases[i] = -1;
        ett[j] = &ett_zbee_zcl_pwr_prof_enphases[i];
    }

    /* Register the ZigBee ZCL PowerProfile cluster protocol name and description */
    proto_zbee_zcl_pwr_prof = proto_register_protocol("ZigBee ZCL Power Profile", "ZCL Power Profile", ZBEE_PROTOABBREV_ZCL_PWRPROF);
    proto_register_field_array(proto_zbee_zcl_pwr_prof, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Power Profile dissector. */
    new_register_dissector(ZBEE_PROTOABBREV_ZCL_PWRPROF, dissect_zbee_zcl_pwr_prof, proto_zbee_zcl_pwr_prof);

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
    dissector_handle_t pwr_prof_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    pwr_prof_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_PWRPROF);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_POWER_PROFILE, pwr_prof_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_pwr_prof,
                            ett_zbee_zcl_pwr_prof,
                            ZBEE_ZCL_CID_POWER_PROFILE,
                            (zbee_zcl_fn_attr_id)dissect_zcl_pwr_prof_attr_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_pwr_prof_attr_data,
                            (zbee_zcl_fn_cmd_id)dissect_zcl_pwr_prof_cmd_id
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
static void dissect_zcl_appl_ctrl_exec_cmd              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_appl_ctrl_attr_func             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_appl_ctrl_wr_funcs              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_appl_ctrl_ovrl_warning          (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_appl_ctrl_signal_state_rsp      (tvbuff_t *tvb, proto_tree *tree, guint *offset);

static void dissect_zcl_appl_ctrl_attr_id               (proto_tree *tree, tvbuff_t *tvb, guint *offset);
static void dissect_zcl_appl_ctrl_attr_data             (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);
static void dissect_zcl_appl_ctrl_cmd_id                (proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_appl_ctrl = -1;

static int hf_zbee_zcl_appl_ctrl_attr_id = -1;
static int hf_zbee_zcl_appl_ctrl_time_mm = -1;
static int hf_zbee_zcl_appl_ctrl_time_encoding_type = -1;
static int hf_zbee_zcl_appl_ctrl_time_hh = -1;
static int hf_zbee_zcl_appl_ctrl_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_appl_ctrl_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_appl_ctrl_exec_cmd_id = -1;
static int hf_zbee_zcl_appl_ctrl_attr_func_id = -1;
static int hf_zbee_zcl_appl_ctrl_attr_func_data_type = -1;
static int hf_zbee_zcl_appl_ctrl_warning_id = -1;
static int hf_zbee_zcl_appl_ctrl_appl_status = -1;
static int hf_zbee_zcl_appl_ctrl_rem_en_flags = -1;
static int hf_zbee_zcl_appl_ctrl_status2 = -1;
static int hf_zbee_zcl_appl_ctrl_status2_array = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_appl_ctrl = -1;
static gint ett_zbee_zcl_appl_ctrl_flags = -1;
static gint ett_zbee_zcl_appl_ctrl_time = -1;
static gint ett_zbee_zcl_appl_ctrl_func[ZBEE_ZCL_APPL_CTRL_NUM_FUNC_ETT];

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
    { ZBEE_ZCL_APPL_CTRL_EXEC_CMD_ID_START_SUPERFREEZING,       "Stop Superfreezing" },
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
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_appl_ctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item        *payload_root;
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    guint             offset = 0;
    guint8            cmd_id;
    gint              rem_len;

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
        proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_appl_ctrl);

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
        proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_appl_ctrl);

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

    return tvb_length(tvb);
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_exec_cmd(tvbuff_t *tvb, proto_tree *tree, guint *offset)
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_attr_func(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8  func_data_type;
    guint16 func_id;

    /* ID */
    func_id = tvb_get_letohs(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_attr_func_id, tvb, *offset, 2,ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_item_append_text(tree, ", %s",
    val_to_str_ext_const(func_id, &zbee_zcl_appl_ctrl_attr_names_ext, "Reserved"));

    /* Data Type */
    func_data_type = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_attr_func_data_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Function Data Dissector */
    dissect_zcl_appl_ctrl_attr_data(tree, tvb, offset, func_id, func_data_type);

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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_wr_funcs(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
  proto_item  *ti = NULL;
  proto_tree  *sub_tree = NULL;
  guint tvb_len;
  guint i = 0;

  tvb_len = tvb_reported_length(tvb);
  while ( *offset < tvb_len && i < ZBEE_ZCL_APPL_CTRL_NUM_FUNC_ETT ) {
    /* Create subtree for attribute status field */
    ti = proto_tree_add_text(tree, tvb, *offset, 0, "Function #%d", i);
    sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_appl_ctrl_func[i]);
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_ovrl_warning(tvbuff_t *tvb, proto_tree *tree, guint *offset)
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
 *      guint *offset       - pointer to buffer offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_signal_state_rsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;
    guint8      flags;

    /* Retrieve "Appliance Status" field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_appl_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Remote Enable" field */
    flags = tvb_get_guint8(tvb, *offset);
    ti = proto_tree_add_text(tree, tvb, *offset, 1, "Remote Enable Flags: 0x%02x", flags);
    sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_appl_ctrl_flags);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_ctrl_rem_en_flags, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_ctrl_status2, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Appliance Status 2" field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_status2_array, tvb, *offset, 3, ENC_BIG_ENDIAN);
} /*dissect_zcl_appl_ctrl_signal_state_rsp*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_appl_ctrl_attr_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster attributes identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
} /*dissect_zcl_appl_ctrl_attr_id*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_appl_ctrl_attr_data
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
static void
dissect_zcl_appl_ctrl_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;
    guint16     raw_time;

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_APPL_CTRL_START_TIME:
        case ZBEE_ZCL_ATTR_ID_APPL_CTRL_FINISH_TIME:
        case ZBEE_ZCL_ATTR_ID_APPL_CTRL_REMAINING_TIME:
            raw_time = tvb_get_letohs(tvb, *offset);
            ti = proto_tree_add_text(tree, tvb, *offset, 2, "Data: 0x%04x", raw_time);
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_appl_ctrl_time);

            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_ctrl_time_mm, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_ctrl_time_encoding_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_ctrl_time_hh, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_appl_ctrl_attr_data*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_appl_ctrl_cmd_id
 *  DESCRIPTION
 *      this function is called by ZCL foundation dissector in order to decode
 *      specific cluster command identifier.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      guint *offset       - pointer to buffer offset
 *      guint8 cmd_dir      - command direction
 *
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_appl_ctrl_cmd_id(proto_tree* tree, tvbuff_t* tvb, guint* offset, guint8 cmd_dir)
{
    if (cmd_dir == ZBEE_ZCL_FCF_TO_CLIENT)
        proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_srv_rx_cmd_id, tvb, *offset, 1, ENC_NA);
    else
        proto_tree_add_item(tree, hf_zbee_zcl_appl_ctrl_srv_tx_cmd_id, tvb, *offset, 1, ENC_NA);
} /*dissect_zcl_appl_ctrl_cmd_id*/

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
    guint i, j;

    static hf_register_info hf[] = {

        { &hf_zbee_zcl_appl_ctrl_attr_id,
            { "Attribute", "zbee_zcl_general.applctrl.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_ctrl_attr_names),
            0x0, NULL, HFILL } },

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
    gint *ett[ZBEE_ZCL_APPL_CTRL_NUM_ETT];

    ett[0] = &ett_zbee_zcl_appl_ctrl;
    ett[1] = &ett_zbee_zcl_appl_ctrl_flags;
    ett[2] = &ett_zbee_zcl_appl_ctrl_time;

    /* initialize attribute subtree types */
    for ( i = 0, j = ZBEE_ZCL_APPL_CTRL_NUM_GENERIC_ETT; i < ZBEE_ZCL_APPL_CTRL_NUM_FUNC_ETT; i++, j++) {
        ett_zbee_zcl_appl_ctrl_func[i] = -1;
        ett[j] = &ett_zbee_zcl_appl_ctrl_func[i];
    }

    /* Register the ZigBee ZCL ApplianceControl cluster protocol name and description */
    proto_zbee_zcl_appl_ctrl = proto_register_protocol("ZigBee ZCL Appliance Control", "ZCL Appliance Control", ZBEE_PROTOABBREV_ZCL_APPLCTRL);
    proto_register_field_array(proto_zbee_zcl_appl_ctrl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Appliance Control dissector. */
    new_register_dissector(ZBEE_PROTOABBREV_ZCL_APPLCTRL, dissect_zbee_zcl_appl_ctrl, proto_zbee_zcl_appl_ctrl);

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
    dissector_handle_t appl_ctrl_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    appl_ctrl_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_APPLCTRL);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_APPLIANCE_CONTROL, appl_ctrl_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_appl_ctrl,
                            ett_zbee_zcl_appl_ctrl,
                            ZBEE_ZCL_CID_APPLIANCE_CONTROL,
                            (zbee_zcl_fn_attr_id)dissect_zcl_appl_ctrl_attr_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_appl_ctrl_attr_data,
                            (zbee_zcl_fn_cmd_id)dissect_zcl_appl_ctrl_cmd_id
                         );
} /*proto_reg_handoff_zbee_zcl_appl_ctrl*/
