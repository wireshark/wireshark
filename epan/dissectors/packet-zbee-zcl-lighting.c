/* packet-zbee-zcl-lighting.c
 * Dissector routines for the ZigBee ZCL Lighting clusters
 * Color Control, Ballast Configuration
 * By Aditya Jain <aditya.jain@samsung.com>
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

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"

/* ########################################################################## */
/* #### (0x0300) COLOR CONTROL CLUSTER ###################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_COLOR_CONTROL_NUM_ETT                                              3

#define ZBEE_ZCL_COLOR_CAPABILITIES_SUPPORT_HS_MASK                                 0x0001  /* bit 0 */
#define ZBEE_ZCL_COLOR_CAPABILITIES_SUPPORT_EHS_MASK                                0x0002  /* bit 1 */
#define ZBEE_ZCL_COLOR_CAPABILITIES_SUPPORT_LOOP_MASK                               0x0004  /* bit 2 */
#define ZBEE_ZCL_COLOR_CAPABILITIES_SUPPORT_XY_MASK                                 0x0008  /* bit 3 */
#define ZBEE_ZCL_COLOR_CAPABILITIES_SUPPORT_CT_MASK                                 0x0010  /* bit 4 */
#define ZBEE_ZCL_COLOR_LOOP_UPDATE_ACTION_MASK                                      0x01    /* bit 0 */
#define ZBEE_ZCL_COLOR_LOOP_UPDATE_DIRECTION_MASK                                   0x02    /* bit 1 */
#define ZBEE_ZCL_COLOR_LOOP_UPDATE_TIME_MASK                                        0x04    /* bit 2 */
#define ZBEE_ZCL_COLOR_LOOP_UPDATE_START_HUE_MASK                                   0x08    /* bit 3 */

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_HUE                                  0x0000  /* Current Hue */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_SATURATION                           0x0001  /* Current Saturation */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_REMAINING_TIME                               0x0002  /* Remaining Time */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_X                                    0x0003  /* Current X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_Y                                    0x0004  /* Current Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_DRIFT_COMPENSATION                           0x0005  /* Drift Compensation */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COMPENSATION_TEXT                            0x0006  /* Compensation Text */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMP                                   0x0007  /* Color Temperature */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_MODE                                   0x0008  /* Color Mode */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_NO_OF_PRIMARIES                              0x0010  /* Number of Primaries */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1_X                                  0x0011  /* Primary 1X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1_Y                                  0x0012  /* Primary 1Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1_INTENSITY                          0x0013  /* Primary 1intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2_X                                  0x0015  /* Primary 2X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2_Y                                  0x0016  /* Primary 2Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2_INTENSITY                          0x0017  /* Primary 2intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3_X                                  0x0019  /* Primary 3X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3_Y                                  0x001a  /* Primary 3Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3_INTENSITY                          0x001b  /* Primary 3intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4_X                                  0x0020  /* Primary 4X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4_Y                                  0x0021  /* Primary 4Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4_INTENSITY                          0x0022  /* Primary 4intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5_X                                  0x0024  /* Primary 5X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5_Y                                  0x0025  /* Primary 5Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5_INTENSITY                          0x0026  /* Primary 5intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6_X                                  0x0028  /* Primary 6X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6_Y                                  0x0029  /* Primary 6Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6_INTENSITY                          0x002a  /* Primary 6intensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_X                                0x0030  /* White Point X */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_Y                                0x0031  /* White Point Y */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_X                              0x0032  /* Color Point RX */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_Y                              0x0033  /* Color Point RY */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_INTENSITY                      0x0034  /* Color Point Rintensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_X                              0x0036  /* Color Point GX */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_Y                              0x0037  /* Color Point GY */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_INTENSITY                      0x0038  /* Color Point Gintensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_X                              0x003a  /* Color Point BX */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_Y                              0x003b  /* Color Point BY */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_INTENSITY                      0x003c  /* Color Point Bintensity */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_ENHANCED_CURRENT_HUE                         0x4000  /* Enhanced Current Hue */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_ENHANCED_COLOR_MODE                          0x4001  /* Enhanced Color Mode */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_ACTIVE                            0x4002  /* Color Loop Active */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_DIRECTION                         0x4003  /* Color Loop Direction */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_TIME                              0x4004  /* Color Loop Time */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_START_ENH_HUE                     0x4005  /* Color Loop Start Enhanced Hue */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_STORED_ENH_HUE                    0x4006  /* Color Loop Stored Enhanced Hue */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_CAPABILITIES                           0x400a  /* Color Capabilities */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMPERATURE_PHYS_MIN                   0x400b  /* Color Temperature Physical Min */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMPERATURE_PHYS_MAX                   0x400c  /* Color Temperature Physical Max */
#define ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_STARTUP_COLOR_TEMPERATURE                    0x4010  /* Startup Color Temperature */

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
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_MOVE_TO_HUE                          0x40  /* Enhanced Move to Hue */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_MOVE_HUE                             0x41  /* Enhanced Move Hue */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_STEP_HUE                             0x42  /* Enhanced Step Hue */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_MOVE_TO_HUE_AND_SATURATION           0x43  /* Enhanced Move to Hue and Saturation */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_COLOR_LOOP_SET                                0x44  /* Color Loop Set */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STOP_MOVE_STEP                                0x47  /* Stop Move Step */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_COLOR_TEMP                               0x4b  /* Move Color Temperature */
#define ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_COLOR_TEMP                               0x4c  /* Step Color Temperature */

#define ZBEE_ZCL_NORMAL_HUE                                                         FALSE
#define ZBEE_ZCL_ENHANCED_HUE                                                       TRUE

/* Server Commands Generated - None */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_color_control(void);
void proto_reg_handoff_zbee_zcl_color_control(void);

/* Command Dissector Helpers */
static void dissect_zcl_color_control_move_to_hue                               (tvbuff_t *tvb, proto_tree *tree, guint *offset, gboolean enhanced);
static void dissect_zcl_color_control_move_hue_saturation                       (tvbuff_t *tvb, proto_tree *tree, guint *offset, gboolean enhanced);
static void dissect_zcl_color_control_step_hue_saturation                       (tvbuff_t *tvb, proto_tree *tree, guint *offset, gboolean enhanced);
static void dissect_zcl_color_control_move_to_saturation                        (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_move_to_hue_and_saturation                (tvbuff_t *tvb, proto_tree *tree, guint *offset, gboolean enhanced);
static void dissect_zcl_color_control_move_to_color                             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_move_color                                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_step_color                                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_move_to_color_temp                        (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_color_loop_set                            (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_move_color_temp                           (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_color_control_step_color_temp                           (tvbuff_t *tvb, proto_tree *tree, guint *offset);

static void dissect_zcl_color_control_attr_data                                 (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_color_control = -1;

static int hf_zbee_zcl_color_control_attr_id = -1;
static int hf_zbee_zcl_color_control_attr_current_hue = -1;
static int hf_zbee_zcl_color_control_attr_current_saturation = -1;
static int hf_zbee_zcl_color_control_attr_remaining_time = -1;
static int hf_zbee_zcl_color_control_attr_color_x = -1;
static int hf_zbee_zcl_color_control_attr_color_y = -1;
static int hf_zbee_zcl_color_control_attr_drift_compensation = -1;
static int hf_zbee_zcl_color_control_attr_color_temperature = -1;
static int hf_zbee_zcl_color_control_attr_color_mode = -1;
static int hf_zbee_zcl_color_control_attr_nr_of_primaries = -1;
static int hf_zbee_zcl_color_control_attr_primary_1_x = -1;
static int hf_zbee_zcl_color_control_attr_primary_1_y = -1;
static int hf_zbee_zcl_color_control_attr_primary_1_intensity = -1;
static int hf_zbee_zcl_color_control_attr_primary_2_x = -1;
static int hf_zbee_zcl_color_control_attr_primary_2_y = -1;
static int hf_zbee_zcl_color_control_attr_primary_2_intensity = -1;
static int hf_zbee_zcl_color_control_attr_primary_3_x = -1;
static int hf_zbee_zcl_color_control_attr_primary_3_y = -1;
static int hf_zbee_zcl_color_control_attr_primary_3_intensity = -1;
static int hf_zbee_zcl_color_control_attr_primary_4_x = -1;
static int hf_zbee_zcl_color_control_attr_primary_4_y = -1;
static int hf_zbee_zcl_color_control_attr_primary_4_intensity = -1;
static int hf_zbee_zcl_color_control_attr_primary_5_x = -1;
static int hf_zbee_zcl_color_control_attr_primary_5_y = -1;
static int hf_zbee_zcl_color_control_attr_primary_5_intensity = -1;
static int hf_zbee_zcl_color_control_attr_primary_6_x = -1;
static int hf_zbee_zcl_color_control_attr_primary_6_y = -1;
static int hf_zbee_zcl_color_control_attr_primary_6_intensity = -1;
static int hf_zbee_zcl_color_control_attr_white_point_x = -1;
static int hf_zbee_zcl_color_control_attr_white_point_y = -1;
static int hf_zbee_zcl_color_control_attr_red_x = -1;
static int hf_zbee_zcl_color_control_attr_red_y = -1;
static int hf_zbee_zcl_color_control_attr_red_intensity = -1;
static int hf_zbee_zcl_color_control_attr_green_x = -1;
static int hf_zbee_zcl_color_control_attr_green_y = -1;
static int hf_zbee_zcl_color_control_attr_green_intensity = -1;
static int hf_zbee_zcl_color_control_attr_blue_x = -1;
static int hf_zbee_zcl_color_control_attr_blue_y = -1;
static int hf_zbee_zcl_color_control_attr_blue_intensity = -1;
static int hf_zbee_zcl_color_control_attr_enhanced_current_hue = -1;
static int hf_zbee_zcl_color_control_attr_enhanced_color_mode = -1;
static int hf_zbee_zcl_color_control_attr_color_loop_active = -1;
static int hf_zbee_zcl_color_control_attr_color_loop_direction = -1;
static int hf_zbee_zcl_color_control_attr_color_loop_time = -1;
static int hf_zbee_zcl_color_control_attr_color_loop_start_enhanced_hue = -1;
static int hf_zbee_zcl_color_control_attr_color_loop_stored_enhanced_hue = -1;
static int hf_zbee_zcl_color_control_attr_color_capabilities = -1;
static int hf_zbee_zcl_color_control_attr_color_capabilities_hs = -1;
static int hf_zbee_zcl_color_control_attr_color_capabilities_ehs = -1;
static int hf_zbee_zcl_color_control_attr_color_capabilities_loop = -1;
static int hf_zbee_zcl_color_control_attr_color_capabilities_xy = -1;
static int hf_zbee_zcl_color_control_attr_color_capabilities_ct = -1;
static int hf_zbee_zcl_color_control_attr_color_temperature_phys_min = -1;
static int hf_zbee_zcl_color_control_attr_color_temperature_phys_max = -1;
static int hf_zbee_zcl_color_control_attr_startup_color_temperature = -1;
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
static int hf_zbee_zcl_color_control_enhanced_hue = -1;
static int hf_zbee_zcl_color_control_enhanced_rate = -1;
static int hf_zbee_zcl_color_control_enhanced_step_size = -1;
static int hf_zbee_zcl_color_control_color_loop_update_flags = -1;
static int hf_zbee_zcl_color_control_color_loop_update_action = -1;
static int hf_zbee_zcl_color_control_color_loop_update_direction = -1;
static int hf_zbee_zcl_color_control_color_loop_update_time = -1;
static int hf_zbee_zcl_color_control_color_loop_update_start_hue = -1;
static int hf_zbee_zcl_color_control_color_loop_action = -1;
static int hf_zbee_zcl_color_control_color_loop_direction = -1;
static int hf_zbee_zcl_color_control_color_loop_time = -1;
static int hf_zbee_zcl_color_control_color_loop_start_hue = -1;
static int hf_zbee_zcl_color_control_color_temp_min = -1;
static int hf_zbee_zcl_color_control_color_temp_max = -1;
static int hf_zbee_zcl_color_control_srv_rx_cmd_id = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_color_control = -1;
static gint ett_zbee_zcl_color_control_color_capabilities = -1;
static gint ett_zbee_zcl_color_control_color_loop_settings = -1;

/* Attributes */
static const value_string zbee_zcl_color_control_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_HUE,                   "Current Hue" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_SATURATION,            "Current Saturation" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_REMAINING_TIME,                "Remaining Time" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_X,                     "Current X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_Y,                     "Current Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_DRIFT_COMPENSATION,            "Drift Compensation" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COMPENSATION_TEXT,             "Compensation Text" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMP,                    "Color Temperature" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_MODE,                    "Color Mode" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_NO_OF_PRIMARIES,               "Number of Primaries" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1_X,                   "Primary 1 X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1_Y,                   "Primary 1 Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1_INTENSITY,           "Primary 1 Intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2_X,                   "Primary 2 X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2_Y,                   "Primary 2 Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2_INTENSITY,           "Primary 2 Intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3_X,                   "Primary 3 X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3_Y,                   "Primary 3 Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3_INTENSITY,           "Primary 3 Intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4_X,                   "Primary 4 X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4_Y,                   "Primary 4 Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4_INTENSITY,           "Primary 4 Intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5_X,                   "Primary 5 X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5_Y,                   "Primary 5 Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5_INTENSITY,           "Primary 5 Intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6_X,                   "Primary 6 X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6_Y,                   "Primary 6 Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6_INTENSITY,           "Primary 6 Intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_X,                 "White Point X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_Y,                 "White Point Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_X,               "Color Point Red X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_Y,               "Color Point Red Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_INTENSITY,       "Color Point Red Intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_X,               "Color Point Green X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_Y,               "Color Point Green Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_INTENSITY,       "Color Point Green Intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_X,               "Color Point Blue X" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_Y,               "Color Point Blue Y" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_INTENSITY,       "Color Point Blue Intensity" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_ENHANCED_CURRENT_HUE,          "Enhanced Current Hue" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_ENHANCED_COLOR_MODE,           "Enhanced Color Mode" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_ACTIVE,             "Color Loop Active" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_DIRECTION,          "Color Loop Direction" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_TIME,               "Color Loop Time" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_START_ENH_HUE,      "Color Loop Start Enhanced Hue" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_STORED_ENH_HUE,     "Color Loop Stored Enhanced Hue" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_CAPABILITIES,            "Color Capabilities" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMPERATURE_PHYS_MIN,    "Color Temperature Physical Min" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMPERATURE_PHYS_MAX,    "Color Temperature Physical Max" },
    { ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_STARTUP_COLOR_TEMPERATURE,     "Startup Color Temperature" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_color_control_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_HUE,                            "Move to Hue" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_HUE,                               "Move Hue" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_HUE,                               "Step Hue" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_SATURATION,                     "Move to Saturation" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_SATURATION,                        "Move Saturation" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_SATURATION,                        "Step Saturation" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_HUE_AND_SATURATION,             "Move to Hue and Saturation" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_COLOR,                          "Move to Color" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_COLOR,                             "Move Color" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_COLOR,                             "Step Color" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_COLOR_TEMP,                     "Move to Color Temperature" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_MOVE_TO_HUE,                   "Enhanced Move to Hue" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_MOVE_HUE,                      "Enhanced Move Hue" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_STEP_HUE,                      "Enhanced Step Hue" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_MOVE_TO_HUE_AND_SATURATION,    "Enhanced Move to Hue and Saturation" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_COLOR_LOOP_SET,                         "Color Loop Set" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STOP_MOVE_STEP,                         "Stop Move Step" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_COLOR_TEMP,                        "Move Color Temperature" },
    { ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_COLOR_TEMP,                        "Step Color Temperature" },
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
    { 0x00,   "Hue and Saturation" },
    { 0x01,   "Color X and Y" },
    { 0x02,   "Color Temperature" },
    { 0x03,   "Enhanced Hue and Saturation" },
    { 0, NULL }
};

/* Color Loop Directions */
static const value_string zbee_zcl_color_control_color_loop_direction_values[] = {
    { 0x00,   "Hue is Decrementing" },
    { 0x01,   "Hue is Incrementing" },
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

/* Move Mode Values */
static const value_string zbee_zcl_color_control_action[] = {
    { 0x00,   "De-activate" },
    { 0x01,   "Activate from the value in the ColorLoopStartEnhancedHue field" },
    { 0x02,   "Activate from the value of the EnhancedCurrentHue attribute" },
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
        proto_tree_add_item(tree, hf_zbee_zcl_color_control_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_color_control, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_HUE:
                    dissect_zcl_color_control_move_to_hue(tvb, payload_tree, &offset, ZBEE_ZCL_NORMAL_HUE);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_HUE:
                    dissect_zcl_color_control_move_hue_saturation(tvb, payload_tree, &offset, ZBEE_ZCL_NORMAL_HUE);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_HUE:
                    dissect_zcl_color_control_step_hue_saturation(tvb, payload_tree, &offset, ZBEE_ZCL_NORMAL_HUE);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_SATURATION:
                    dissect_zcl_color_control_move_to_saturation(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_SATURATION:
                    dissect_zcl_color_control_move_hue_saturation(tvb, payload_tree, &offset, ZBEE_ZCL_NORMAL_HUE);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_SATURATION:
                    dissect_zcl_color_control_step_hue_saturation(tvb, payload_tree, &offset, ZBEE_ZCL_NORMAL_HUE);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_TO_HUE_AND_SATURATION:
                    dissect_zcl_color_control_move_to_hue_and_saturation(tvb, payload_tree, &offset, ZBEE_ZCL_NORMAL_HUE);
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

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_MOVE_TO_HUE:
                    dissect_zcl_color_control_move_to_hue(tvb, payload_tree, &offset, ZBEE_ZCL_ENHANCED_HUE);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_MOVE_HUE:
                    dissect_zcl_color_control_move_hue_saturation(tvb, payload_tree, &offset, ZBEE_ZCL_ENHANCED_HUE);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_STEP_HUE:
                    dissect_zcl_color_control_step_hue_saturation(tvb, payload_tree, &offset, ZBEE_ZCL_ENHANCED_HUE);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_ENHANCED_MOVE_TO_HUE_AND_SATURATION:
                    dissect_zcl_color_control_move_to_hue_and_saturation(tvb, payload_tree, &offset, ZBEE_ZCL_ENHANCED_HUE);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_COLOR_LOOP_SET:
                    dissect_zcl_color_control_color_loop_set(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_MOVE_COLOR_TEMP:
                    dissect_zcl_color_control_move_color_temp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STEP_COLOR_TEMP:
                    dissect_zcl_color_control_step_color_temp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_COLOR_CONTROL_STOP_MOVE_STEP:
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
dissect_zcl_color_control_move_to_hue(tvbuff_t *tvb, proto_tree *tree, guint *offset, gboolean enhanced)
{
    /* Retrieve "Hue" field */
    if (enhanced)
    {
        proto_tree_add_item(tree, hf_zbee_zcl_color_control_enhanced_hue, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }
    else
    {
        proto_tree_add_item(tree, hf_zbee_zcl_color_control_hue, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }

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
dissect_zcl_color_control_move_hue_saturation(tvbuff_t *tvb, proto_tree *tree, guint *offset, gboolean enhanced)
{
    /* Retrieve "Move Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_move_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Rate" field */
    if (enhanced)
    {
        proto_tree_add_item(tree, hf_zbee_zcl_color_control_enhanced_rate, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }
    else
    {
        proto_tree_add_item(tree, hf_zbee_zcl_color_control_rate, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }

} /*dissect_zcl_color_control_move_hue_saturation*/


/**
 *This function decodes the Step Hue and Step Saturation payload
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_step_hue_saturation(tvbuff_t *tvb, proto_tree *tree, guint *offset, gboolean enhanced)
{
    /* Retrieve "Step Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_step_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Step Size" field */
    if (enhanced)
    {
        proto_tree_add_item(tree, hf_zbee_zcl_color_control_enhanced_step_size, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }
    else
    {
        proto_tree_add_item(tree, hf_zbee_zcl_color_control_step_size, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }

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
dissect_zcl_color_control_move_to_hue_and_saturation(tvbuff_t *tvb, proto_tree *tree, guint *offset, gboolean enhanced)
{
    /* Retrieve "Hue" field */
    if (enhanced)
    {
        proto_tree_add_item(tree, hf_zbee_zcl_color_control_enhanced_hue, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }
    else
    {
        proto_tree_add_item(tree, hf_zbee_zcl_color_control_hue, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }

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
 *This function decodes the Color Loop Set payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_color_control_color_loop_set(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    static int * const color_loop_update_fields[] = {
        &hf_zbee_zcl_color_control_color_loop_update_action,
        &hf_zbee_zcl_color_control_color_loop_update_direction,
        &hf_zbee_zcl_color_control_color_loop_update_time,
        &hf_zbee_zcl_color_control_color_loop_update_start_hue,
        NULL
    };

    /* Retrieve "Update Flags" field */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_color_control_color_loop_update_flags, ett_zbee_zcl_color_control_color_loop_settings, color_loop_update_fields, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Action" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_loop_action, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Direction" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_loop_direction, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Time" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_loop_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Start Hue" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_loop_start_hue, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_color_control_color_loop_set*/

  /**
  *This function decodes the Move Color Temperature payload.
  *
  *@param  tvb the tv buffer of the current data_type
  *@param  tree the tree to append this item to
  *@param  offset offset of data in tvb
  */
static void
dissect_zcl_color_control_move_color_temp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve "Move Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_move_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Rate" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_enhanced_rate, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Color Temperature Min" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_temp_min, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Color Temperature Max" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_temp_max, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_color_control_move_color_temp*/

  /**
  *This function decodes the Step Color Temperature payload.
  *
  *@param  tvb the tv buffer of the current data_type
  *@param  tree the tree to append this item to
  *@param  offset offset of data in tvb
  */
static void
dissect_zcl_color_control_step_color_temp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve "Step Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_step_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Step" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_enhanced_step_size, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Time" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_transit_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Color Temperature Min" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_temp_min, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Color Temperature Max" field */
    proto_tree_add_item(tree, hf_zbee_zcl_color_control_color_temp_max, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_color_control_step_color_temp*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *    decode_color_xy
 *  DESCRIPTION
 *    this function decodes color xy values
 *  PARAMETERS
 *      guint *s        - string to display
 *      guint16 value   - value to decode
 *  RETURNS
 *    none
 *---------------------------------------------------------------
 */
static void
decode_color_xy(gchar *s, guint16 value)
{
    g_snprintf(s, ITEM_LABEL_LENGTH, "%.4lf", value/65535.0);
    return;
} /*decode_power_conf_voltage*/

  /*FUNCTION:------------------------------------------------------
  *  NAME
  *    decode_color_temperature
  *  DESCRIPTION
  *    this function decodes color temperature values
  *  PARAMETERS
  *      guint *s        - string to display
  *      guint16 value   - value to decode
  *  RETURNS
  *    none
  *---------------------------------------------------------------
  */
static void
decode_color_temperature(gchar *s, guint16 value)
{
    if (value == 0) {
        g_snprintf(s, ITEM_LABEL_LENGTH, "%u [Mired]", value);
    } else {
        g_snprintf(s, ITEM_LABEL_LENGTH, "%u [Mired] (%u [K])", value, 1000000/value);
    }
    return;
} /*decode_color_temperature*/

  /*FUNCTION:------------------------------------------------------
  *  NAME
  *    decode_startup_color_temperature
  *  DESCRIPTION
  *    this function decodes color temperature values
  *  PARAMETERS
  *      guint *s        - string to display
  *      guint16 value   - value to decode
  *  RETURNS
  *    none
  *---------------------------------------------------------------
  */
static void
decode_startup_color_temperature(gchar *s, guint16 value)
{
    if (value == 0xffff)
    {
        g_snprintf(s, ITEM_LABEL_LENGTH, "Set the Color Temperature attribute to its previous value");
    }
    else
    {
        decode_color_temperature(s, value);
    }
    return;
} /*decode_startup_color_temperature*/

  /**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
 *@param attr_id attribute identifier
 *@param data_type attribute data type
 *@param client_attr ZCL client
*/
void
dissect_zcl_color_control_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    static int * const capabilities_fields[] = {
        &hf_zbee_zcl_color_control_attr_color_capabilities_hs,
        &hf_zbee_zcl_color_control_attr_color_capabilities_ehs,
        &hf_zbee_zcl_color_control_attr_color_capabilities_loop,
        &hf_zbee_zcl_color_control_attr_color_capabilities_xy,
        &hf_zbee_zcl_color_control_attr_color_capabilities_ct,
        NULL
    };

    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_HUE:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_current_hue, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_SATURATION:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_current_saturation, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_REMAINING_TIME:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_remaining_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_CURRENT_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_DRIFT_COMPENSATION:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_drift_compensation, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMP:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_temperature, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_mode, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_NO_OF_PRIMARIES:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_nr_of_primaries, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_1_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_1_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_1_INTENSITY:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_1_intensity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_2_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_2_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_2_INTENSITY:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_2_intensity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_3_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_3_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_3_INTENSITY:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_3_intensity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_4_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_4_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_4_INTENSITY:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_4_intensity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_5_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_5_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_5_INTENSITY:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_5_intensity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_6_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_6_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_PRIMARY_6_INTENSITY:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_primary_6_intensity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_white_point_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_WHITE_POINT_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_white_point_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_red_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_red_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_R_INTENSITY:
            proto_tree_add_item(tree,hf_zbee_zcl_color_control_attr_red_intensity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_green_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_green_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_G_INTENSITY:
            proto_tree_add_item(tree,hf_zbee_zcl_color_control_attr_green_intensity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_X:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_blue_x, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_Y:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_blue_y, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_POINT_B_INTENSITY:
            proto_tree_add_item(tree,hf_zbee_zcl_color_control_attr_blue_intensity, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_ENHANCED_CURRENT_HUE:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_enhanced_current_hue, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_ENHANCED_COLOR_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_enhanced_color_mode, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_ACTIVE:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_loop_active, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_DIRECTION:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_loop_direction, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_TIME:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_loop_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_START_ENH_HUE:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_loop_start_enhanced_hue, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_LOOP_STORED_ENH_HUE:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_loop_stored_enhanced_hue, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_CAPABILITIES:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_color_control_attr_color_capabilities, ett_zbee_zcl_color_control_color_capabilities, capabilities_fields, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMPERATURE_PHYS_MIN:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_temperature_phys_min, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COLOR_TEMPERATURE_PHYS_MAX:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_color_temperature_phys_max, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_STARTUP_COLOR_TEMPERATURE:
            proto_tree_add_item(tree, hf_zbee_zcl_color_control_attr_startup_color_temperature, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_COLOR_CONTROL_COMPENSATION_TEXT:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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

        { &hf_zbee_zcl_color_control_attr_current_hue,
            { "Hue", "zbee_zcl_lighting.color_control.attr.current_hue", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_current_saturation,
            { "Saturation", "zbee_zcl_lighting.color_control.attr.current_satuaration", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_remaining_time,
            { "Time", "zbee_zcl_lighting.color_control.attr.remaining_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_100ms),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_x,
            { "X", "zbee_zcl_lighting.color_control.attr.color_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.color_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_drift_compensation,
            { "Drift Compensation", "zbee_zcl_lighting.color_control.attr.drift_compensation", FT_UINT8, BASE_HEX, VALS(zbee_zcl_color_control_drift_compensation_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_temperature,
            { "Color Temperature", "zbee_zcl_lighting.color_control.attr.color_temperature", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_temperature),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_mode,
            { "Color Mode", "zbee_zcl_lighting.color_control.attr.color_mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_color_control_color_mode_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_nr_of_primaries,
            { "Number", "zbee_zcl_lighting.color_control.attr.nr_of_primaries", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_1_x,
            { "X", "zbee_zcl_lighting.color_control.attr.primary_1_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_1_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.primary_1_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_1_intensity,
            { "Intensity", "zbee_zcl_lighting.color_control.attr.primary_1_intensity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_2_x,
            { "X", "zbee_zcl_lighting.color_control.attr.primary_2_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_2_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.primary_2_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_2_intensity,
            { "Intensity", "zbee_zcl_lighting.color_control.attr.primary_2_intensity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_3_x,
            { "X", "zbee_zcl_lighting.color_control.attr.primary_3_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_3_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.primary_3_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_3_intensity,
            { "Intensity", "zbee_zcl_lighting.color_control.attr.primary_3_intensity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_4_x,
            { "X", "zbee_zcl_lighting.color_control.attr.primary_4_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_4_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.primary_4_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_4_intensity,
            { "Intensity", "zbee_zcl_lighting.color_control.attr.primary_4_intensity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_5_x,
            { "X", "zbee_zcl_lighting.color_control.attr.primary_5_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_5_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.primary_5_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_5_intensity,
            { "Intensity", "zbee_zcl_lighting.color_control.attr.primary_5_intensity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_6_x,
            { "X", "zbee_zcl_lighting.color_control.attr.primary_6_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_6_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.primary_6_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_primary_6_intensity,
            { "Intensity", "zbee_zcl_lighting.color_control.attr.primary_6_intensity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_white_point_x,
            { "X", "zbee_zcl_lighting.color_control.attr.white_point_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_white_point_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.white_point_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_red_x,
            { "X", "zbee_zcl_lighting.color_control.attr.red_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_red_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.red_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_red_intensity,
            { "Intensity", "zbee_zcl_lighting.color_control.attr.red_intensity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_green_x,
            { "X", "zbee_zcl_lighting.color_control.attr.green_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_green_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.green_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_green_intensity,
            { "Intensity", "zbee_zcl_lighting.color_control.attr.green_intensity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_blue_x,
            { "X", "zbee_zcl_lighting.color_control.attr.blue_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_blue_y,
            { "Y", "zbee_zcl_lighting.color_control.attr.blue_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_blue_intensity,
            { "Intensity", "zbee_zcl_lighting.color_control.attr.blue_intensity", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_enhanced_current_hue,
            { "Enhanced Hue", "zbee_zcl_lighting.color_control.attr.enhanced_current_hue", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_enhanced_color_mode,
            { "Enhanced Color Mode", "zbee_zcl_lighting.color_control.attr.enhanced_color_mode", FT_UINT8, BASE_DEC, VALS(zbee_zcl_color_control_color_mode_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_loop_active,
            { "Active", "zbee_zcl_lighting.color_control.attr.color_loop_active", FT_BOOLEAN, 8, TFS(&tfs_true_false),
                0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_loop_direction,
            { "Direction", "zbee_zcl_lighting.color_control.attr.color_loop_direction", FT_UINT8, BASE_DEC, VALS(zbee_zcl_color_control_color_loop_direction_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_loop_time,
            { "Time", "zbee_zcl_lighting.color_control.attr.color_loop_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_seconds),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_loop_start_enhanced_hue,
            { "Enhanced Hue", "zbee_zcl_lighting.color_control.attr.color_loop_start_enhanced_hue", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_loop_stored_enhanced_hue,
            { "Enhanced Hue", "zbee_zcl_lighting.color_control.attr.color_loop_stored_enhanced_hue", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_capabilities,
            { "Capabilities", "zbee_zcl_lighting.color_control.attr.color_capabilities", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_capabilities_hs,
            { "Support Hue and Saturation", "zbee_zcl_lighting.color_control.attr.color_capabilities.hue_saturation", FT_UINT16, BASE_DEC, NULL,
                ZBEE_ZCL_COLOR_CAPABILITIES_SUPPORT_HS_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_capabilities_ehs,
            { "Support Enhanced Hue and Saturation", "zbee_zcl_lighting.color_control.attr.color_capabilities.enhanced_hue_saturation", FT_UINT16, BASE_DEC, NULL,
                ZBEE_ZCL_COLOR_CAPABILITIES_SUPPORT_EHS_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_capabilities_loop,
            { "Support Color Loop", "zbee_zcl_lighting.color_control.attr.color_capabilities.color_loop", FT_UINT16, BASE_DEC, NULL,
                ZBEE_ZCL_COLOR_CAPABILITIES_SUPPORT_LOOP_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_capabilities_xy,
            { "Support Color XY", "zbee_zcl_lighting.color_control.attr.color_capabilities.color_xy", FT_UINT16, BASE_DEC, NULL,
                ZBEE_ZCL_COLOR_CAPABILITIES_SUPPORT_XY_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_capabilities_ct,
            { "Support Color Temperature", "zbee_zcl_lighting.color_control.attr.color_capabilities.color_temperature", FT_UINT16, BASE_DEC, NULL,
                ZBEE_ZCL_COLOR_CAPABILITIES_SUPPORT_CT_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_temperature_phys_min,
            { "Color Temperature", "zbee_zcl_lighting.color_control.attr.color_temperature_physical_min", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_temperature),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_color_temperature_phys_max,
            { "Color Temperature", "zbee_zcl_lighting.color_control.attr.color_temperature_physical_max", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_temperature),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_attr_startup_color_temperature,
            { "Startup Color Temparature", "zbee_zcl_lighting.color_control.attr.startup_color_temperature", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_startup_color_temperature),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_hue,
            { "Hue", "zbee_zcl_lighting.color_control.hue", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_direction,
            { "Direction", "zbee_zcl_lighting.color_control.direction", FT_UINT8, BASE_DEC, VALS(zbee_zcl_color_control_direction_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_transit_time,
            { "Transition Time", "zbee_zcl_lighting.color_control.transit_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_100ms),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_move_mode,
            { "Move Mode", "zbee_zcl_lighting.color_control.move_mode", FT_UINT8, BASE_DEC, VALS(zbee_zcl_color_control_move_mode),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_rate,
            { "Rate", "zbee_zcl_lighting.color_control.rate", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_step_mode,
            { "Step Mode", "zbee_zcl_lighting.color_control.step_mode", FT_UINT8, BASE_DEC, VALS(zbee_zcl_color_control_step_mode),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_step_size,
            { "Step Size", "zbee_zcl_lighting.color_control.step_size", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_transit_time_8bit,
            { "Transition Time", "zbee_zcl_lighting.color_control.transition_time_8bit", FT_UINT8, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_100ms),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_saturation,
            { "Saturation", "zbee_zcl_lighting.color_control.saturation", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_color_X,
            { "Color X", "zbee_zcl_lighting.color_control.color_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_color_Y,
            { "Color Y", "zbee_zcl_lighting.color_control.color_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_rate_X,
            { "Rate X", "zbee_zcl_lighting.color_control.rate_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_rate_Y,
            { "Rate Y", "zbee_zcl_lighting.color_control.rate_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_step_X,
            { "Step X", "zbee_zcl_lighting.color_control.step_x", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_step_Y,
            { "Step Y", "zbee_zcl_lighting.color_control.step_y", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_xy),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_color_temp,
            { "Color temperature", "zbee_zcl_lighting.color_control.color_temp", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_temperature),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_enhanced_hue,
            { "Enhanced Hue", "zbee_zcl_lighting.color_control.enhanced_hue", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_enhanced_rate,
            { "Enhanced Rate", "zbee_zcl_lighting.color_control.enhanced_rate", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_enhanced_step_size,
            { "Enhanced Step Size", "zbee_zcl_lighting.color_control.enhanced_step_size", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_color_loop_update_flags,
            { "Update Flags", "zbee_zcl_lighting.color_control.color_loop_update", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_color_loop_update_action,
            { "Update Action", "zbee_zcl_lighting.color_control.color_loop_update.action", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_COLOR_LOOP_UPDATE_ACTION_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_color_loop_update_direction,
            { "Update Direction", "zbee_zcl_lighting.color_control.color_loop_update.direction", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_COLOR_LOOP_UPDATE_DIRECTION_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_color_loop_update_time,
            { "Update Time", "zbee_zcl_lighting.color_control.color_loop_update.time", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_COLOR_LOOP_UPDATE_TIME_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_color_loop_update_start_hue,
            { "Update Start Hue", "zbee_zcl_lighting.color_control.color_loop_update.start_hue", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_COLOR_LOOP_UPDATE_START_HUE_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_color_loop_action,
            { "Action", "zbee_zcl_lighting.color_control.color_loop_action", FT_UINT8, BASE_DEC, VALS(zbee_zcl_color_control_action),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_color_loop_direction,
            { "Direction", "zbee_zcl_lighting.color_control.color_loop_direction", FT_UINT8, BASE_DEC, VALS(zbee_zcl_color_control_color_loop_direction_values),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_color_loop_time,
            { "Time", "zbee_zcl_lighting.color_control.color_loop_time", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_time_in_seconds),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_color_loop_start_hue,
            { "Enhanced Hue", "zbee_zcl_lighting.color_control.color_loop_start_hue", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_color_control_color_temp_min,
            { "Color Temperature Minimum Mired", "zbee_zcl_lighting.color_control.color_temp_min", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_temperature),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_color_temp_max,
            { "Color Temperature Maximum Mired", "zbee_zcl_lighting.color_control.color_temp_max", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_color_temperature),
            0x00, NULL, HFILL }},

        { &hf_zbee_zcl_color_control_srv_rx_cmd_id,
          { "Command", "zbee_zcl_lighting.color_control.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_color_control_srv_rx_cmd_names),
            0x00, NULL, HFILL } }
    };

    /* ZCL Color Control subtrees */
    static gint *ett[ZBEE_ZCL_COLOR_CONTROL_NUM_ETT];
    ett[0] = &ett_zbee_zcl_color_control;
    ett[1] = &ett_zbee_zcl_color_control_color_capabilities;
    ett[2] = &ett_zbee_zcl_color_control_color_loop_settings;

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
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_COLOR_CONTROL,
                            proto_zbee_zcl_color_control,
                            ett_zbee_zcl_color_control,
                            ZBEE_ZCL_CID_COLOR_CONTROL,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_color_control_attr_id,
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
static void dissect_zcl_ballast_configuration_attr_data      (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

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
 *@param client_attr ZCL client
*/
void
dissect_zcl_ballast_configuration_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    static int * const ballast_status[] = {
        &hf_zbee_zcl_ballast_configuration_status_non_operational,
        &hf_zbee_zcl_ballast_configuration_status_lamp_not_in_socket,
        NULL
    };

    static int * const lamp_alarm_mode[] = {
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_BALLAST_CONFIG,
                            proto_zbee_zcl_ballast_configuration,
                            ett_zbee_zcl_ballast_configuration,
                            ZBEE_ZCL_CID_BALLAST_CONFIG,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_ballast_configuration_attr_id,
                            hf_zbee_zcl_ballast_configuration_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_ballast_configuration_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_ballast_configuration*/

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
