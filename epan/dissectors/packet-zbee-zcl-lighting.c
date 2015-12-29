/* packet-zbee-zcl-lighting.c
 * Dissector routines for the ZigBee ZCL Lighting clusters
 * Color Control, Ballast Configuration
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
/* #### (0x0300) COLOR CONTROL CLUSTER ###################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_COLOR_CONTROL_NUM_ETT                                              1

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_HUE                                  0x0000  /* Color Hue */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_SATURATION                           0x0001  /* Current Saturation */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_REMAINING_TIME                               0x0002  /* Remaining Time */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_X                                    0x0003  /* Current X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_Y                                    0x0004  /* Current Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_DRIFT_COMPENSATION                           0x0005  /* Drift Compensation */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COMPENSATION_TEXT                            0x0006  /* Compensation Text */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMP                                   0x0007  /* Color Temperature */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_MODE                                   0x0008  /* Color Mode */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_NO_OF_PRIMARIES                              0x0010  /* Number of Primaries */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1X                                   0x0011  /* Primary 1X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1Y                                   0x0012  /* Primary 1Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1INTENSITY                           0x0013  /* Primary 1intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2X                                   0x0015  /* Primary 2X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2Y                                   0x0016  /* Primary 2Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2INTENSITY                           0x0017  /* Primary 2intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3X                                   0x0019  /* Primary 3X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3Y                                   0x001a  /* Primary 3Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3INTENSITY                           0x001b  /* Primary 3intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4X                                   0x0020  /* Primary 4X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4Y                                   0x0021  /* Primary 4Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4INTENSITY                           0x0022  /* Primary 4intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5X                                   0x0024  /* Primary 5X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5Y                                   0x0025  /* Primary 5Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5INTENSITY                           0x0026  /* Primary 5intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6X                                   0x0028  /* Primary 6X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6Y                                   0x0029  /* Primary 6Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6INTENSITY                           0x002a  /* Primary 6intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_X                                0x0030  /* White Point X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_Y                                0x0031  /* White Point Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_RX                               0x0032  /* Color Point RX */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_RY                               0x0033  /* Color Point RY */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_INTENSITY                      0x0034  /* Color Point Rintensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_GX                               0x0036  /* Color Point GX */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_GY                               0x0037  /* Color Point GY */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_INTENSITY                      0x0038  /* Color Point Gintensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_BX                               0x003a  /* Color Point BX */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_BY                               0x003b  /* Color Point BY */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_INTENSITY                      0x003c  /* Color Point Bintensity */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_HUE                                   0x00  /* Move to Hue */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_HUE                                      0x01  /* Move Hue */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_HUE                                      0x02  /* Step Hue */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_SATURATION                            0x03  /* Move to Saturation */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_SATURATION                               0x04  /* Move Saturation */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_SATURATION                               0x05  /* Step Saturation */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_HUE_AND_SATURATION                    0x06  /* Move to Hue and Saturation */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_COLOR                                 0x07  /* Move to Color */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_COLOR                                    0x08  /* Move Color */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_COLOR                                    0x09  /* Step Color */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_COLOR_TEMP                            0x0a  /* Move to Color Temperature */


/* Server Commands Generated - None */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_color_control(void);
void proto_reg_handoff_zbee_zcl_color_control(void);

/* Command Dissector Helpers */
static void dissect_zcl_color_control_move_to_hue                               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_move_hue_saturation                       (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_step_hue_saturation                       (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_move_to_saturation                        (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_move_to_hue_and_saturation                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_move_to_color                             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_move_color                                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_step_color                                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_move_to_color_temp                        (tvbuff_t *tvb, proto_tree *tree, guint *offset);

static void dissect_zcl_color_control_attr_data                                 (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_color_control = -1;

static int hf_zbee_zcl_color_control_attr_id = -1;
static int hf_zbee_zcl_color_control_attr_drift_compensation = -1;
static int hf_zbee_zcl_color_control_attr_color_mode = -1;
static int hf_zbee_zcl_color_control_hue = -1;
static int hf_zbee_zcl_color_control_direction = -1;
static int hf_zbee_zcl_color_control_transit_time = -1;
static int hf_zbee_zcl_color_control_move_mode = -1;
static int hf_zbee_zcl_color_control_rate = -1;
static int hf_zbee_zcl_color_control_step_mode = -1;
static int hf_zbee_zcl_color_control_step_size = -1;
static int hf_zbee_zcl_color_control_transit_time_8bit = -1;
static int hf_zbee_zcl_color_control_saturation = -1;
static int hf_zbee_zcl_color_control_color_X = -1;
static int hf_zbee_zcl_color_control_color_Y = -1;
static int hf_zbee_zcl_color_control_rate_X = -1;
static int hf_zbee_zcl_color_control_rate_Y = -1;
static int hf_zbee_zcl_color_control_step_X = -1;
static int hf_zbee_zcl_color_control_step_Y = -1;
static int hf_zbee_zcl_color_control_color_temp = -1;
static int hf_zbee_zcl_color_control_srv_rx_cmd_id = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_color_control = -1;

/* Attributes */
static const value_string zbee_zcl_color_control_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_HUE,                   "Color Hue" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_SATURATION,            "Current Saturation" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_REMAINING_TIME,                "Remaining Time" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_X,                     "Current X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_Y,                     "Current Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_DRIFT_COMPENSATION,            "Drift Compensation" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COMPENSATION_TEXT,             "Compensation Text" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMP,                    "Color Temperature" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_MODE,                    "Color Mode" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_NO_OF_PRIMARIES,               "Number of Primaries" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1X,                    "Primary 1X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1Y,                    "Primary 1Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1INTENSITY,            "Primary 1intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2X,                    "Primary 2X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2Y,                    "Primary 2Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2INTENSITY,            "Primary 2intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3X,                    "Primary 3X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3Y,                    "Primary 3Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3INTENSITY,            "Primary 3intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4X,                    "Primary 4X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4Y,                    "Primary 4Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4INTENSITY,            "Primary 4intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5X,                    "Primary 5X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5Y,                    "Primary 5Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5INTENSITY,            "Primary 5intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6X,                    "Primary 6X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6Y,                    "Primary 6Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6INTENSITY,            "Primary 6intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_X,                 "White Point X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_Y,                 "White Point Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_RX,                "Color Point RX" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_RY,                "Color Point RY" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_INTENSITY,       "Color Point Rintensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_GX,                "Color Point GX" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_GY,                "Color Point GY" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_INTENSITY,       "Color Point Gintensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_BX,                "Color Point BX" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_BY,                "Color Point BY" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_INTENSITY,       "Color Point Bintensity" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_color_control_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_HUE,                    "Move to Hue" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_HUE,                       "Move Hue" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_HUE,                       "Step Hue" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_SATURATION,             "Move to Saturation" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_SATURATION,                "Move Saturation" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_SATURATION,                "Step Saturation" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_HUE_AND_SATURATION,     "Move to Hue and Saturation" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_COLOR,                  "Move to Color" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_COLOR,                     "Move Color" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_COLOR,                     "Step Color" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_COLOR_TEMP,             "Move to Color Temperature" },
    { 0, NULL }
};

/* Drift Compensation Values */
static const value_string zbee_zcl_color_control_drift_compensation_values[] = {
    { 0x00,   "None" },
    { 0x01,   "Other/Unknown" },
    { 0x02,   "Temperature monitoring" },
    { 0x03,   "Optical Luminance Monitoring and Feedback" },
    { 0x04,   "Optical Color Monitoring and Feedback" },
    { 0, NULL }
};

/* Color Mode Values */
static const value_string zbee_zcl_color_control_color_mode_values[] = {
    { 0x00,   "Current Hue and Current Saturation" },
    { 0x01,   "Current X and Current Y" },
    { 0x02,   "Color Temperature" },
    { 0x03,   "Optical luminance monitoring and feedback" },
    { 0x04,   "Optical color monitoring and feedback" },
    { 0, NULL }
};

/* Direction Values */
static const value_string zbee_zcl_color_control_direction_values[] = {
    { 0x00,   "Shortest Distance" },
    { 0x01,   "Longest Distance" },
    { 0x02,   "Up" },
    { 0x03,   "Down" },
    { 0, NULL }
};

/* Move Mode Values */
static const value_string zbee_zcl_color_control_move_mode[] = {
    { 0x00,   "Stop" },
    { 0x01,   "Up" },
    { 0x02,   "Reserved" },
    { 0x03,   "Down" },
    { 0, NULL }
};

/* Step Mode Values */
static const value_string zbee_zcl_color_control_step_mode[] = {
    { 0x00,   "Reserved" },
    { 0x01,   "Up" },
    { 0x02,   "Reserved" },
    { 0x03,   "Down" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Color Control cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_color_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
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
            val_to_str_const(cmd_id, zbee_zcl_color_control_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_color_control_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_color_control, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_HUE:
                    dissect_zcl_color_control_move_to_hue(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_HUE:
                    dissect_zcl_color_control_move_hue_saturation(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_HUE:
                    dissect_zcl_color_control_step_hue_saturation(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_SATURATION:
                    dissect_zcl_color_control_move_to_saturation(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_SATURATION:
                    dissect_zcl_color_control_move_hue_saturation(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_SATURATION:
                    dissect_zcl_color_control_step_hue_saturation(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_HUE_AND_SATURATION:
                    dissect_zcl_color_control_move_to_hue_and_saturation(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_COLOR:
                    dissect_zcl_color_control_move_to_color(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_COLOR:
                    dissect_zcl_color_control_move_color(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_COLOR:
                    dissect_zcl_color_control_step_color(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_COLOR_TEMP:
                    dissect_zcl_color_control_move_to_color_temp(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_color_control*/


/**
 *This function decodes the Add Group or Add Group If
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_move_to_hue(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve "Hue" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_hue, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Direction" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_direction, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Transition Time" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_color_control_move_to_hue*/


/**
 *This function decodes the Move Hue and Move Saturation payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_move_hue_saturation(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve "Move Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_move_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Rate" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_rate, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_color_control_move_hue_saturation*/


/**
 *This function decodes the Step Hue and Step Saturation payload
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_step_hue_saturation(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
   /* Retrieve "Step Mode" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_step_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Step Size" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_step_size, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Transition Time" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_transit_time_8bit, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

} /*dissect_zcl_color_control_step_hue_saturation*/


/**
 *This function decodes the Move to Saturation payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_move_to_saturation(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
   /* Retrieve "Saturation" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_saturation, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Transition Time" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

} /*dissect_zcl_color_control_move_to_saturation*/


/**
 *This function decodes the Move to Hue and Saturation payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_move_to_hue_and_saturation(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
   /* Retrieve "Hue" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_hue, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Saturation" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_saturation, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Transition Time" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

} /*dissect_zcl_color_control_move_to_hue_and_saturation*/


/**
 *This function decodes the Move to Color payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_move_to_color(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
   /* Retrieve "Color X" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_X, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Color Y" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_Y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Transition Time" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

} /*dissect_zcl_color_control_move_to_color*/

/**
 *This function decodes the Move Color payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_move_color(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
   /* Retrieve "Rate X" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_rate_X, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Rate Y" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_rate_Y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

} /*dissect_zcl_color_control_move_color*/


/**
 *This function decodes the Step Color payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_step_color(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
   /* Retrieve "Step X" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_step_X, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Step Y" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_step_Y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Transition Time" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

} /*dissect_zcl_color_control_step_color*/

/**
 *This function decodes the Move to Color Temperature payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_move_to_color_temp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
   /* Retrieve "Color Temperature" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_temp, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "Transition Time" field */
   proto_tree_add_item(tree, hf_zbee_zcl_color_control_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

} /*dissect_zcl_color_control_move_to_color_temp*/


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
dissect_zcl_color_control_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_DRIFT_COMPENSATION:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_drift_compensation, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_REMAINING_TIME:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_HUE:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_SATURATION:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_X:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_Y:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COMPENSATION_TEXT:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMP:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_NO_OF_PRIMARIES:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1X:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1Y:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1INTENSITY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2X:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2Y:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2INTENSITY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3X:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3Y:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3INTENSITY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4X:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4Y:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4INTENSITY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5X:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5Y:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5INTENSITY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6X:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6Y:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6INTENSITY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_X:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_Y:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_RX:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_RY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_INTENSITY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_GX:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_GY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_INTENSITY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_BX:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_BY:
        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_INTENSITY:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_color_control_attr_data*/


/**
 *ZigBee ZCL Color Control cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_color_control(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_color_control_attr_id,
            { "Attribute", "zbee_zcl_lighting.color_control.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_color_control_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_drift_compensation,
            { "Drift Compensation", "zbee_zcl_lighting.color_control.attr.drift_compensation", FT_UINT8, BASE_HEX, VALS(zbee_zcl_color_control_drift_compensation_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_mode,
            { "Color Mode", "zbee_zcl_lighting.color_control.color_mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_color_control_color_mode_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_hue,
            { "Hue", "zbee_zcl_lighting.color_control.hue", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_direction,
            { "Direction", "zbee_zcl_lighting.color_control.direction", FT_UINT8, BASE_HEX, VALS(zbee_zcl_color_control_direction_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_transit_time,
            { "Transition Time", "zbee_zcl_lighting.color_control.transit_time", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_move_mode,
            { "Move Mode", "zbee_zcl_lighting.color_control.move_mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_color_control_move_mode),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_rate,
            { "Rate", "zbee_zcl_lighting.color_control.rate", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_step_mode,
            { "Step Mode", "zbee_zcl_lighting.color_control.step_mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_color_control_step_mode),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_step_size,
            { "Step Size", "zbee_zcl_lighting.color_control.step_size", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_transit_time_8bit,
            { "Transition Time", "zbee_zcl_lighting.color_control.transition_time_8bit", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_saturation,
            { "Saturation", "zbee_zcl_lighting.color_control.saturation", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_color_X,
            { "Color X", "zbee_zcl_lighting.color_control.color_x", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_color_Y,
            { "Color Y", "zbee_zcl_lighting.color_control.color_y", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_rate_X,
            { "Rate X", "zbee_zcl_lighting.color_control.rate_x", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_rate_Y,
            { "Rate Y", "zbee_zcl_lighting.color_control.rate_y", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_step_X,
            { "Step X", "zbee_zcl_lighting.color_control.step_x", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_step_Y,
            { "Step Y", "zbee_zcl_lighting.color_control.step_y", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_color_temp,
            { "Color temperature", "zbee_zcl_lighting.color_control.color_temp", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_srv_rx_cmd_id,
          { "Command", "zbee_zcl_lighting.color_control.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_color_control_srv_rx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Color Control subtrees */
    static gint *ett[ZBEE_ZCL_COLOR_CONTROL_NUM_ETT];
    ett[0] = &ett_zbee_zcl_color_control;

    /* Register the ZigBee ZCL Color Control cluster protocol name and description */
    proto_zbee_zcl_color_control = proto_register_protocol("ZigBee ZCL Color Control", "ZCL Color Control", ZBEE_PROTOABBREV_ZCL_COLOR_CONTROL);
    proto_register_field_array(proto_zbee_zcl_color_control, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Color Control dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_COLOR_CONTROL, dissect_zbee_zcl_color_control, proto_zbee_zcl_color_control);

} /*proto_register_zbee_zcl_color_control*/


/**
 *Hands off the ZCL Color Control dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_color_control(void)
{
    dissector_handle_t color_control_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    color_control_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_COLOR_CONTROL);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_COLOR_CONTROL, color_control_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_color_control,
                            ett_zbee_zcl_color_control,
                            ZBEE_ZCL_CID_COLOR_CONTROL,
                            hf_zbee_zcl_color_control_attr_id,
                            hf_zbee_zcl_color_control_srv_rx_cmd_id,
                            -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_color_control_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_color_control*/


/* ########################################################################## */
/* #### (0x0300) BALLAST CONFIGURATION CLUSTER ############################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_BALLAST_CONFIGURATION_NUM_ETT                                    3

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_PHYSICAL_MIN_LEVEL                 0x0000  /* Physical Min Level */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_PHYSICAL_MAX_LEVEL                 0x0001  /* Physical Max Level */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_BALLAST_STATUS                     0x0002  /* Ballast Status */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_MIN_LEVEL                          0x0010  /* Min Level */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_MAX_LEVEL                          0x0011  /* Max Level */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_POWER_ON_LEVEL                     0x0012  /* Power On Level */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_POWER_ON_FADE_TIME                 0x0013  /* Power On Fade Time */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_INTRINSIC_BALLAST_FACTOR           0x0014  /* Intrinsic Ballast Factor */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_BALLAST_FACT_ADJ                   0x0015  /* Ballast Factor Adjustment */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_QUANTITY                      0x0020  /* Lamp Quantity */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_TYPE                          0x0030  /* Lamp Type */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_MANUFACTURER                  0x0031  /* Lamp Manufacturer */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_RATED_HOURS                   0x0032  /* Lamp Rated Hours */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_BURN_HOURS                    0x0033  /* Lamp Burn Hours */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_ALARM_MODE                    0x0034  /* Lamp Alarm Mode */
#define ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_BURN_HOURS_TRIP_POINT         0x0035  /* Lamp Burn Hours Trip Point */

/*Server commands received - none*/

/*Server commands generated - none*/

/*Ballast Status Mask Values*/
#define ZBEE_ZCL_BALLAST_CONFIGURATION_STATUS_NON_OPERATIONAL                     0x01    /* Non-operational */
#define ZBEE_ZCL_BALLAST_CONFIGURATION_STATUS_LAMP_NOT_IN_SOCKET                  0x02    /* Lamp Not in Socket */

/*Lamp Alarm Mode Mask Value*/
#define ZBEE_ZCL_BALLAST_CONFIGURATION_LAMP_ALARM_MODE_LAMP_BURN_HOURS            0x01    /* Lamp Burn Hours */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_ballast_configuration(void);
void proto_reg_handoff_zbee_zcl_ballast_configuration(void);

/* Command Dissector Helpers */
static void dissect_zcl_ballast_configuration_attr_data      (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_ballast_configuration = -1;

static int hf_zbee_zcl_ballast_configuration_attr_id = -1;
static int hf_zbee_zcl_ballast_configuration_status = -1;
static int hf_zbee_zcl_ballast_configuration_status_non_operational = -1;
static int hf_zbee_zcl_ballast_configuration_status_lamp_not_in_socket = -1;
static int hf_zbee_zcl_ballast_configuration_lamp_alarm_mode = -1;
static int hf_zbee_zcl_ballast_configuration_lamp_alarm_mode_lamp_burn_hours = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_ballast_configuration = -1;
static gint ett_zbee_zcl_ballast_configuration_status = -1;
static gint ett_zbee_zcl_ballast_configuration_lamp_alarm_mode = -1;

/* Attributes */
static const value_string zbee_zcl_ballast_configuration_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_PHYSICAL_MIN_LEVEL,                "Physical Min Level" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_PHYSICAL_MAX_LEVEL,                "Physical Max Level" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_BALLAST_STATUS,                    "Ballast Status" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_MIN_LEVEL,                         "Min Level" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_MAX_LEVEL,                         "Max Level" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_POWER_ON_LEVEL,                    "Power On Level" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_POWER_ON_FADE_TIME,                "Power On Fade Time" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_INTRINSIC_BALLAST_FACTOR,          "Intrinsic Ballast Factor" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_BALLAST_FACT_ADJ,                  "Ballast Factor Adjustment" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_QUANTITY,                     "Lamp Quantity" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_TYPE,                         "Lamp Type" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_MANUFACTURER,                 "Lamp Manufacturer" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_RATED_HOURS,                  "Lamp Rated Hours" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_BURN_HOURS,                   "Lamp Burn Hours" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_ALARM_MODE,                   "Lamp Alarm Mode" },
    { ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_BURN_HOURS_TRIP_POINT,        "Lamp Burn Hours Trip Point" },
    { 0, NULL }
};

/*Non-operational Values*/
static const value_string zbee_zcl_ballast_configuration_status_non_operational_names[] = {
    {0, "Fully Operational"},
    {1, "Not Fully Operational"},
    {0, NULL}
};

/*Not in Socket Values*/
static const value_string zbee_zcl_ballast_configuration_status_lamp_not_in_socket_names[] = {
    {0, "All lamps in Socket"},
    {1, "Atleast one lamp not in Socket"},
    {0, NULL}
};


/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Ballast Configuration cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/

static int
dissect_zbee_zcl_ballast_configuration(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_ballast_configuration*/


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
dissect_zcl_ballast_configuration_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    static const int * ballast_status[] = {
        &hf_zbee_zcl_ballast_configuration_status_non_operational,
        &hf_zbee_zcl_ballast_configuration_status_lamp_not_in_socket,
        NULL
    };

    static const int * lamp_alarm_mode[] = {
        &hf_zbee_zcl_ballast_configuration_lamp_alarm_mode_lamp_burn_hours,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_BALLAST_STATUS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_ballast_configuration_status, ett_zbee_zcl_ballast_configuration_status, ballast_status, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_ALARM_MODE:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_ballast_configuration_lamp_alarm_mode, ett_zbee_zcl_ballast_configuration_lamp_alarm_mode, lamp_alarm_mode, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_PHYSICAL_MIN_LEVEL:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_PHYSICAL_MAX_LEVEL:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_MIN_LEVEL:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_MAX_LEVEL:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_POWER_ON_LEVEL:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_POWER_ON_FADE_TIME:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_INTRINSIC_BALLAST_FACTOR:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_BALLAST_FACT_ADJ:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_QUANTITY:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_TYPE:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_MANUFACTURER:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_RATED_HOURS:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_BURN_HOURS:
        case ZBEE_ZCL_ATTR_ID_BALLAST_CONFIGURATION_LAMP_BURN_HOURS_TRIP_POINT:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_ballast_configuration_attr_data*/


/**
 *ZigBee ZCL Ballast Configuration cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_ballast_configuration(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_ballast_configuration_attr_id,
            { "Attribute", "zbee_zcl_lighting.ballast_configuration.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_ballast_configuration_attr_names),
            0x00, NULL, HFILL } },

        /* start Ballast Status fields */
        { &hf_zbee_zcl_ballast_configuration_status,
            { "Status", "zbee_zcl_lighting.ballast_configuration.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ballast_configuration_status_non_operational,
            { "Non-operational", "zbee_zcl_lighting.ballast_configuration.attr.status.non_operational", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ballast_configuration_status_non_operational_names),
            ZBEE_ZCL_BALLAST_CONFIGURATION_STATUS_NON_OPERATIONAL, NULL, HFILL } },

        { &hf_zbee_zcl_ballast_configuration_status_lamp_not_in_socket,
            { "Not in Socket", "zbee_zcl_lighting.ballast_configuration.attr.status.not_in_socket", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ballast_configuration_status_lamp_not_in_socket_names),
            ZBEE_ZCL_BALLAST_CONFIGURATION_STATUS_LAMP_NOT_IN_SOCKET, NULL, HFILL } },
        /* end Ballast Status fields */

        /*stat Lamp Alarm Mode fields*/
        { &hf_zbee_zcl_ballast_configuration_lamp_alarm_mode,
            { "Lamp Alarm Mode", "zbee_zcl_lighting.ballast_configuration.attr.lamp_alarm_mode", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ballast_configuration_lamp_alarm_mode_lamp_burn_hours,
            { "Lamp Burn Hours", "zbee_zcl_lighting.ballast_configuration.attr.lamp_alarm_mode.lamp_burn_hours", FT_BOOLEAN, 8, NULL,
            ZBEE_ZCL_BALLAST_CONFIGURATION_LAMP_ALARM_MODE_LAMP_BURN_HOURS, NULL, HFILL } }
        /* end Lamp Alarm Mode fields */
    };

    /* ZCL Ballast Configuration subtrees */
    static gint *ett[ZBEE_ZCL_BALLAST_CONFIGURATION_NUM_ETT];

    ett[0] = &ett_zbee_zcl_ballast_configuration;
    ett[1] = &ett_zbee_zcl_ballast_configuration_status;
    ett[2] = &ett_zbee_zcl_ballast_configuration_lamp_alarm_mode;

    /* Register the ZigBee ZCL Ballast Configuration cluster protocol name and description */
    proto_zbee_zcl_ballast_configuration = proto_register_protocol("ZigBee ZCL Ballast Configuration", "ZCL Ballast Configuration", ZBEE_PROTOABBREV_ZCL_BALLAST_CONFIG);
    proto_register_field_array(proto_zbee_zcl_ballast_configuration, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Ballast Configuration dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_BALLAST_CONFIG, dissect_zbee_zcl_ballast_configuration, proto_zbee_zcl_ballast_configuration);
} /*proto_register_zbee_zcl_ballast_configuration*/

/**
 *Hands off the ZCL Ballast Configuration dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_ballast_configuration(void)
{
    dissector_handle_t ballast_config_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    ballast_config_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_BALLAST_CONFIG);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_BALLAST_CONFIG, ballast_config_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_ballast_configuration,
                            ett_zbee_zcl_ballast_configuration,
                            ZBEE_ZCL_CID_BALLAST_CONFIG,
                            hf_zbee_zcl_ballast_configuration_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_ballast_configuration_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_ballast_configuration*/

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
