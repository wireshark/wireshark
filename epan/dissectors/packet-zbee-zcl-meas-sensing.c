/* packet-zbee-zcl-meas-sensing.c
 * Dissector routines for the ZigBee ZCL Measurement & Sensing clusters like
 * Illuminance Measurement, Temperature Measurement ...
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

#include <math.h>
#include <epan/packet.h>

#include <wsutil/utf8_entities.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"


/* ########################################################################## */
/* #### (0x0400) ILLUMINANCE MEASUREMENT CLUSTER ############################ */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_ILLUM_MEAS_NUM_GENERIC_ETT                     1
#define ZBEE_ZCL_ILLUM_MEAS_NUM_ETT                             ZBEE_ZCL_ILLUM_MEAS_NUM_GENERIC_ETT

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MEASURED_VALUE              0x0000  /* Measured Value */
#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MIN_MEASURED_VALUE          0x0001  /* Min Measured Value */
#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MAX_MEASURED_VALUE          0x0002  /* Max Measured Value */
#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_TOLERANCE                   0x0003  /* Tolerance */
#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_LIGHT_SENSOR_TYPE           0x0004  /* Light Sensor Type */

/* Server Commands Received - None */

/* Server Commands Generated - None */

#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_TOO_LOW_VALUE        0x0000  /* Too Low Value */
#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_INVALID_VALUE        0x8000  /* Invalid Value */

#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MIN_LO_VALUE         0x0002  /* Minimum Value (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MIN_HI_VALUE         0xfffd  /* Minimum Value (High Bound) */

#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MAX_LO_VALUE         0x0001  /* Maximum Value (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MAX_HI_VALUE         0xfffe  /* Maximum Value (High Bound) */

#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_TOL_LO_VALUE         0x0000  /* Tolerance (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_TOL_HI_VALUE         0x0800  /* Tolerance (Low Bound) */

#define ZBEE_ZCL_ILLUM_MEAS_SENSOR_TYPE_PHOTODIODE       0x00  /* Photodiode */
#define ZBEE_ZCL_ILLUM_MEAS_SENSOR_TYPE_CMOS             0x01  /* CMOS */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_illum_meas(void);
void proto_reg_handoff_zbee_zcl_illum_meas(void);

/* Command Dissector Helpers */
static void dissect_zcl_illum_meas_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */
static void decode_illum_meas_value              (gchar *s, guint16 value);
static void decode_illum_meas_min_value          (gchar *s, guint16 value);
static void decode_illum_meas_max_value          (gchar *s, guint16 value);
static void decode_illum_meas_tolerance          (gchar *s, guint16 value);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_illum_meas = -1;

static int hf_zbee_zcl_illum_meas_attr_id = -1;
static int hf_zbee_zcl_illum_meas_measured_value = -1;
static int hf_zbee_zcl_illum_meas_min_measured_value = -1;
static int hf_zbee_zcl_illum_meas_max_measured_value = -1;
static int hf_zbee_zcl_illum_meas_tolerance = -1;
static int hf_zbee_zcl_illum_meas_sensor_type = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_illum_meas = -1;

/* Attributes */
static const value_string zbee_zcl_illum_meas_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MEASURED_VALUE,       "Measured Value" },
    { ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MIN_MEASURED_VALUE,   "Min Measured Value" },
    { ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MAX_MEASURED_VALUE,   "Max Measured Value" },
    { ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_TOLERANCE,            "Tolerance" },
    { ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_LIGHT_SENSOR_TYPE,    "Light Sensor Type" },
    { 0, NULL }
};

static const value_string zbee_zcl_illum_meas_sensor_type_names[] = {
    { ZBEE_ZCL_ILLUM_MEAS_SENSOR_TYPE_PHOTODIODE,       "Photodiode" },
    { ZBEE_ZCL_ILLUM_MEAS_SENSOR_TYPE_CMOS,             "CMOS" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Illuminance Measurement cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_illum_meas(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_illum_meas*/

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
dissect_zcl_illum_meas_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_illum_meas_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

            case ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MIN_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_illum_meas_min_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MAX_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_illum_meas_max_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_TOLERANCE:
            proto_tree_add_item(tree, hf_zbee_zcl_illum_meas_tolerance, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_LIGHT_SENSOR_TYPE:
            proto_tree_add_item(tree, hf_zbee_zcl_illum_meas_sensor_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_illum_meas_attr_data*/

/**
 *This function decodes illuminance value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_illum_meas_value(gchar *s, guint16 value)
{
    if (value == ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_TOO_LOW_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Value too low to be measured");
    else if (value == ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_INVALID_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Invalid value");
    else
        /* calculate lux value from measured value according to doc 07-5123-04 */
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d (=%f [lx])", value, pow(10,value/10000.0)-1);

    return;
} /*decode_illum_meas_value*/

/**
 *This function decodes minimum illuminance value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_illum_meas_min_value(gchar *s, guint16 value)
{
    if ( (value < ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MIN_LO_VALUE) ||
         (value > ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MIN_HI_VALUE) )
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d (=%f [lx])", value, pow(10,value/10000.0)-1);

    return;
} /*decode_illum_meas_min_value*/

/**
 *This function decodes maximum illuminance value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_illum_meas_max_value(gchar *s, guint16 value)
{
    if ( (value < ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MAX_LO_VALUE) ||
         (value > ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_MAX_HI_VALUE) )
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d (=%f [lx])", value, pow(10,value/10000.0)-1);

    return;
} /*decode_illum_meas_max_value*/

/**
 *This function decodes tolerance value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_illum_meas_tolerance(gchar *s, guint16 value)
{
    if (value > ZBEE_ZCL_ATTR_ID_ILLUM_MEAS_TOL_HI_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d", value);

    return;
} /*decode_illum_meas_tolerance*/

/**
 *This function registers the ZCL Illuminance Measurement dissector
 *
*/
void
proto_register_zbee_zcl_illum_meas(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_illum_meas_attr_id,
            { "Attribute", "zbee_zcl_meas_sensing.illummeas.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_illum_meas_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_illum_meas_measured_value,
            { "Measured Value", "zbee_zcl_meas_sensing.illummeas.attr.value", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_illum_meas_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_illum_meas_min_measured_value,
            { "Min Measured Value", "zbee_zcl_meas_sensing.illummeas.attr.value.min", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_illum_meas_min_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_illum_meas_max_measured_value,
            { "Max Measured Value", "zbee_zcl_meas_sensing.illummeas.attr.value.max", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_illum_meas_max_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_illum_meas_tolerance,
            { "Tolerance", "zbee_zcl_meas_sensing.illummeas.attr.tolerance", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_illum_meas_tolerance),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_illum_meas_sensor_type,
            { "Sensor Type", "zbee_zcl_meas_sensing.illummeas.attr.sensor_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_illum_meas_sensor_type_names),
            0x00, NULL, HFILL } }

    };

    /* Register the ZigBee ZCL Illuminance Measurement cluster protocol name and description */
    proto_zbee_zcl_illum_meas = proto_register_protocol("ZigBee ZCL Illuminance Meas.", "ZCL Illuminance Meas.", ZBEE_PROTOABBREV_ZCL_ILLUMMEAS);
    proto_register_field_array(proto_zbee_zcl_illum_meas, hf, array_length(hf));

    /* Register the ZigBee ZCL Illuminance Measurement dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_ILLUMMEAS, dissect_zbee_zcl_illum_meas, proto_zbee_zcl_illum_meas);

} /*proto_register_zbee_zcl_illum_meas*/


/**
 *Hands off the ZCL Illuminance Measurement dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_illum_meas(void)
{
    zbee_zcl_init_cluster(  proto_zbee_zcl_illum_meas,
                            ett_zbee_zcl_illum_meas,
                            ZBEE_ZCL_CID_ILLUMINANCE_MEASUREMENT,
                            hf_zbee_zcl_illum_meas_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_illum_meas_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_illum_meas*/


/* ########################################################################## */
/* #### (0x0401) ILLUMINANCE LEVEL SENSING CLUSTER ########################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_ILLUM_LEVEL_SEN_NUM_GENERIC_ETT                    1
#define ZBEE_ZCL_ILLUM_LEVEL_SEN_NUM_ETT                            ZBEE_ZCL_ILLUM_LEVEL_SEN_NUM_GENERIC_ETT

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_LEVEL_STATUS               0x0000  /* Level Status */
#define ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_LIGHT_SENSOR_TYPE          0x0001  /* Light Sensor Type */
#define ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_ILLUM_TARGET_LEVEL         0x0010  /* Illuminance Target Level */

/* Server Commands Received - None */

/* Server Commands Generated - None */

#define ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_TOO_LOW_VALUE              0x0000  /* Too Low Value */
#define ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_INVALID_VALUE              0x8000  /* Invalid Value */

#define ZBEE_ZCL_ILLUM_LEVEL_SEN_SENSOR_TYPE_PHOTODIODE             0x00  /* Photodiode */
#define ZBEE_ZCL_ILLUM_LEVEL_SEN_SENSOR_TYPE_CMOS                   0x01  /* CMOS */

#define ZBEE_ZCL_ILLUM_LEVEL_SEN_ILLUM_ON_TARGET                    0x00  /* Illuminance on Target */
#define ZBEE_ZCL_ILLUM_LEVEL_SEN_ILLUM_BELOW_TARGET                 0x01  /* Illuminance below Target */
#define ZBEE_ZCL_ILLUM_LEVEL_SEN_ILLUM_ABOVE_TARGET                 0x02  /* Illuminance above Target */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_illum_level_sen(void);
void proto_reg_handoff_zbee_zcl_illum_level_sen(void);

/* Command Dissector Helpers */
static void dissect_zcl_illum_level_sen_attr_data               (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */
static void decode_illum_level_sen_target_level                 (gchar *s, guint16 value);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_illum_level_sen = -1;

static int hf_zbee_zcl_illum_level_sen_attr_id = -1;
static int hf_zbee_zcl_illum_level_sen_level_status = -1;
static int hf_zbee_zcl_illum_level_sen_light_sensor_type = -1;
static int hf_zbee_zcl_illum_level_sen_illum_target_level = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_illum_level_sen = -1;

/* Attributes */
static const value_string zbee_zcl_illum_level_sen_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_LEVEL_STATUS,        "Level Status" },
    { ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_LIGHT_SENSOR_TYPE,   "Light Sensor Type" },
    { ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_ILLUM_TARGET_LEVEL,  "Illuminance Target Level" },
    { 0, NULL }
};

static const value_string zbee_zcl_illum_level_sen_sensor_type_names[] = {
    { ZBEE_ZCL_ILLUM_LEVEL_SEN_SENSOR_TYPE_PHOTODIODE,      "Photodiode" },
    { ZBEE_ZCL_ILLUM_LEVEL_SEN_SENSOR_TYPE_CMOS,            "CMOS" },
    { 0, NULL }
};

static const value_string zbee_zcl_illum_level_sen_level_status_names[] = {
    { ZBEE_ZCL_ILLUM_LEVEL_SEN_ILLUM_ON_TARGET,             "Illuminance on Target" },
    { ZBEE_ZCL_ILLUM_LEVEL_SEN_ILLUM_BELOW_TARGET,          "Illuminance below Target" },
    { ZBEE_ZCL_ILLUM_LEVEL_SEN_ILLUM_ABOVE_TARGET,          "Illuminance above Target" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Illuminance Level Sensing cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_illum_level_sen(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_illum_level_sen*/

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
dissect_zcl_illum_level_sen_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_LEVEL_STATUS:
            proto_tree_add_item(tree, hf_zbee_zcl_illum_level_sen_level_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_LIGHT_SENSOR_TYPE:
            proto_tree_add_item(tree, hf_zbee_zcl_illum_level_sen_light_sensor_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_ILLUM_TARGET_LEVEL:
            proto_tree_add_item(tree, hf_zbee_zcl_illum_level_sen_illum_target_level, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_illum_level_sen_attr_data*/

/**
 *This function decodes illuminance value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_illum_level_sen_target_level(gchar *s, guint16 value)
{
    if (value == ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_TOO_LOW_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Value too low to be measured");
    else if (value == ZBEE_ZCL_ATTR_ID_ILLUM_LEVEL_SEN_INVALID_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Invalid value");
    else
        /* calculate lux value from measured value according to doc 07-5123-04 */
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d (=%f [lx])", value, pow(10,value/10000.0)-1);

    return;
} /*decode_illum_level_sen_value*/

/**
 *This function registers the ZCL Illuminance Level Sensing dissector
 *
*/
void
proto_register_zbee_zcl_illum_level_sen(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_illum_level_sen_attr_id,
            { "Attribute", "zbee_zcl_meas_sensing.illumlevelsen.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_illum_level_sen_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_illum_level_sen_level_status,
            { "Level Status", "zbee_zcl_meas_sensing.illumlevelsen.attr.level_status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_illum_level_sen_level_status_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_illum_level_sen_light_sensor_type,
            { "Light Sensor Type", "zbee_zcl_meas_sensing.illumlevelsen.attr.light_sensor_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_illum_level_sen_sensor_type_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_illum_level_sen_illum_target_level,
            { "Target Level", "zbee_zcl_meas_sensing.illumlevelsen.attr.target_level", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_illum_level_sen_target_level),
            0x00, NULL, HFILL } }
    };

    /* Register the ZigBee ZCL Illuminance Level Sensing cluster protocol name and description */
    proto_zbee_zcl_illum_level_sen = proto_register_protocol("ZigBee ZCL Illuminance Level Sensing", "ZCL Illuminance Level Sensing", ZBEE_PROTOABBREV_ZCL_ILLUMLEVELSEN);
    proto_register_field_array(proto_zbee_zcl_illum_level_sen, hf, array_length(hf));

    /* Register the ZigBee ZCL Illuminance Level Sensing dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_ILLUMLEVELSEN, dissect_zbee_zcl_illum_level_sen, proto_zbee_zcl_illum_level_sen);

} /*proto_register_zbee_zcl_illum_level_sen*/


/**
 *Hands off the ZCL Illuminance Level Sensing dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_illum_level_sen(void)
{
    zbee_zcl_init_cluster(  proto_zbee_zcl_illum_level_sen,
                            ett_zbee_zcl_illum_level_sen,
                            ZBEE_ZCL_CID_ILLUMINANCE_LEVEL_SENSING,
                            hf_zbee_zcl_illum_level_sen_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_illum_level_sen_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_illum_level_sen*/



/* ########################################################################## */
/* #### (0x0402) TEMPERATURE MEASUREMENT CLUSTER ############################ */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_TEMP_MEAS_NUM_GENERIC_ETT              1
#define ZBEE_ZCL_TEMP_MEAS_NUM_ETT                      ZBEE_ZCL_TEMP_MEAS_NUM_GENERIC_ETT

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MEASURED_VALUE       0x0000  /* Measured Value */
#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MIN_MEASURED_VALUE   0x0001  /* Min Measured Value */
#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MAX_MEASURED_VALUE   0x0002  /* Max Measured Value */
#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_TOLERANCE            0x0003  /* Tolerance */

/* Server Commands Received - None */

/* Server Commands Generated - None */

#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_INVALID_VALUE        0x8000  /* Invalid Value */

#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MIN_LO_VALUE         0x954d  /* Minimum Value (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MIN_HI_VALUE         0x7ffe  /* Minimum Value (High Bound) */

#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MAX_LO_VALUE         0x954e  /* Maximum Value (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MAX_HI_VALUE         0x7fff  /* Maximum Value (High Bound) */

#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_TOL_LO_VALUE         0x0000  /* Tolerance (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_TEMP_MEAS_TOL_HI_VALUE         0x0800  /* Tolerance (Low Bound) */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_temp_meas(void);
void proto_reg_handoff_zbee_zcl_temp_meas(void);

/* Command Dissector Helpers */
static void dissect_zcl_temp_meas_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */
static void decode_temp_meas_value              (gchar *s, gint16 value);
static void decode_temp_meas_min_value          (gchar *s, gint16 value);
static void decode_temp_meas_max_value          (gchar *s, gint16 value);
static void decode_temp_meas_tolerance          (gchar *s, guint16 value);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_temp_meas = -1;

static int hf_zbee_zcl_temp_meas_attr_id = -1;
static int hf_zbee_zcl_temp_meas_measured_value = -1;
static int hf_zbee_zcl_temp_meas_min_measured_value = -1;
static int hf_zbee_zcl_temp_meas_max_measured_value = -1;
static int hf_zbee_zcl_temp_meas_tolerance = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_temp_meas = -1;

/* Attributes */
static const value_string zbee_zcl_temp_meas_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MEASURED_VALUE,        "Measured Value" },
    { ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MIN_MEASURED_VALUE,    "Min Measured Value" },
    { ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MAX_MEASURED_VALUE,    "Max Measured Value" },
    { ZBEE_ZCL_ATTR_ID_TEMP_MEAS_TOLERANCE,             "Tolerance" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Temperature Measurement cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_temp_meas(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_temp_meas*/

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
dissect_zcl_temp_meas_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_temp_meas_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MIN_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_temp_meas_min_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MAX_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_temp_meas_max_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_TEMP_MEAS_TOLERANCE:
            proto_tree_add_item(tree, hf_zbee_zcl_temp_meas_tolerance, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_temp_meas_attr_data*/

/**
 *This function decodes temperature value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_temp_meas_value(gchar *s, gint16 value)
{
    if (value == (gint16)ZBEE_ZCL_ATTR_ID_TEMP_MEAS_INVALID_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Invalid value");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f [" UTF8_DEGREE_SIGN "C]", value/100.0);

    return;
} /*decode_temp_meas_value*/

/**
 *This function decodes minimum temperature value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_temp_meas_min_value(gchar *s, gint16 value)
{
    if ( (value < (gint16)ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MIN_LO_VALUE) ||
         (value > (gint16)ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MIN_HI_VALUE) )
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f [" UTF8_DEGREE_SIGN "C]", value/100.0);

    return;
} /*decode_temp_meas_min_value*/

/**
 *This function decodes maximum temperature value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_temp_meas_max_value(gchar *s, gint16 value)
{
    if (value < (gint16)ZBEE_ZCL_ATTR_ID_TEMP_MEAS_MAX_LO_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f [" UTF8_DEGREE_SIGN "C]", value/100.0);

    return;
} /*decode_temp_meas_max_value*/

/**
 *This function decodes tolerance value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_temp_meas_tolerance(gchar *s, guint16 value)
{
    if (value > ZBEE_ZCL_ATTR_ID_TEMP_MEAS_TOL_HI_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%d [" UTF8_DEGREE_SIGN "C]", value/100, value%100);

    return;
} /*decode_temp_meas_tolerance*/

/**
 *This function registers the ZCL Temperature Measurement dissector
 *
*/
void
proto_register_zbee_zcl_temp_meas(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_temp_meas_attr_id,
            { "Attribute", "zbee_zcl_meas_sensing.tempmeas.attr_idd", FT_UINT16, BASE_HEX, VALS(zbee_zcl_temp_meas_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_temp_meas_measured_value,
            { "Measured Value", "zbee_zcl_meas_sensing.tempmeas.attr.value", FT_INT16, BASE_CUSTOM, CF_FUNC(decode_temp_meas_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_temp_meas_min_measured_value,
            { "Min Measured Value", "zbee_zcl_meas_sensing.tempmeas.attr.value.min", FT_INT16, BASE_CUSTOM, CF_FUNC(decode_temp_meas_min_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_temp_meas_max_measured_value,
            { "Max Measured Value", "zbee_zcl_meas_sensing.tempmeas.attr.value.max", FT_INT16, BASE_CUSTOM, CF_FUNC(decode_temp_meas_max_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_temp_meas_tolerance,
            { "Tolerance", "zbee_zcl_meas_sensing.tempmeas.attr.tolerance", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_temp_meas_tolerance),
            0x00, NULL, HFILL } }

    };

    /* Register the ZigBee ZCL Temperature Measurement cluster protocol name and description */
    proto_zbee_zcl_temp_meas = proto_register_protocol("ZigBee ZCL Temperature Meas.", "ZCL Temperature Meas.", ZBEE_PROTOABBREV_ZCL_TEMPMEAS);
    proto_register_field_array(proto_zbee_zcl_temp_meas, hf, array_length(hf));

    /* Register the ZigBee ZCL Temperature Measurement dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_TEMPMEAS, dissect_zbee_zcl_temp_meas, proto_zbee_zcl_temp_meas);
} /*proto_register_zbee_zcl_temp_meas*/

/**
 *Hands off the ZCL Temperature Measurement dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_temp_meas(void)
{
    zbee_zcl_init_cluster(  proto_zbee_zcl_temp_meas,
                            ett_zbee_zcl_temp_meas,
                            ZBEE_ZCL_CID_TEMPERATURE_MEASUREMENT,
                            hf_zbee_zcl_temp_meas_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_temp_meas_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_temp_meas*/


/* ########################################################################## */
/* #### (0x0403) PRESSURE MEASUREMENT CLUSTER ############################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_PRESS_MEAS_NUM_GENERIC_ETT              1
#define ZBEE_ZCL_PRESS_MEAS_NUM_ETT                      ZBEE_ZCL_PRESS_MEAS_NUM_GENERIC_ETT

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MEASURED_VALUE       0x0000  /* Measured Value */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MIN_MEASURED_VALUE   0x0001  /* Min Measured Value */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MAX_MEASURED_VALUE   0x0002  /* Max Measured Value */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_TOLERANCE            0x0003  /* Tolerance */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALED_VALUE         0x0010  /* Scaled Value */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MIN_SCALED_VALUE     0x0011  /* Min Scaled Value */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MAX_SCALED_VALUE     0x0012  /* Max Scaled Value */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALED_TOLERANCE     0x0013  /* Scaled Tolerance */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALE                0x0014  /* Scale */

/* Server Commands Received - None */

/* Server Commands Generated - None */

#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_INVALID_VALUE        0x8000  /* Invalid Value */

#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MIN_LO_VALUE         0x8001  /* Minimum Value (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MIN_HI_VALUE         0x7ffe  /* Minimum Value (High Bound) */

#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MAX_LO_VALUE         0x8002  /* Maximum Value (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MAX_HI_VALUE         0x7fff  /* Maximum Value (High Bound) */

#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_TOL_LO_VALUE         0x0000  /* Tolerance (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_TOL_HI_VALUE         0x0800  /* Tolerance (Low Bound) */

#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALE_LO_VALUE       0x81  /* Scale (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALE_HI_VALUE       0x7f  /* Scale (Low Bound) */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_press_meas(void);
void proto_reg_handoff_zbee_zcl_press_meas(void);

/* Command Dissector Helpers */
static void dissect_zcl_press_meas_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */
static void decode_press_meas_value              (gchar *s, gint16 value);
static void decode_press_meas_min_value          (gchar *s, gint16 value);
static void decode_press_meas_max_value          (gchar *s, gint16 value);
static void decode_press_meas_tolerance          (gchar *s, guint16 value);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_press_meas = -1;

static int hf_zbee_zcl_press_meas_attr_id = -1;
static int hf_zbee_zcl_press_meas_measured_value = -1;
static int hf_zbee_zcl_press_meas_min_measured_value = -1;
static int hf_zbee_zcl_press_meas_max_measured_value = -1;
static int hf_zbee_zcl_press_meas_tolerance = -1;
static int hf_zbee_zcl_press_meas_scaled_value = -1;
static int hf_zbee_zcl_press_meas_min_scaled_value = -1;
static int hf_zbee_zcl_press_meas_max_scaled_value = -1;
static int hf_zbee_zcl_press_meas_scaled_tolerance = -1;
static int hf_zbee_zcl_press_meas_scale = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_press_meas = -1;

/* Attributes */
static const value_string zbee_zcl_press_meas_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MEASURED_VALUE,       "Measured Value" },
    { ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MIN_MEASURED_VALUE,   "Min Measured Value" },
    { ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MAX_MEASURED_VALUE,   "Max Measured Value" },
    { ZBEE_ZCL_ATTR_ID_PRESS_MEAS_TOLERANCE,            "Tolerance" },
    { ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALED_VALUE,         "Scaled Value" },
    { ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MIN_SCALED_VALUE,     "Min Scaled Value" },
    { ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MAX_SCALED_VALUE,     "Max Scaled Value" },
    { ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALED_TOLERANCE,     "Scaled Tolerance" },
    { ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALE,                "Scale" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Pressure Measurement cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_press_meas(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_press_meas*/

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
dissect_zcl_press_meas_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_press_meas_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MIN_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_press_meas_min_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MAX_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_press_meas_max_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_PRESS_MEAS_TOLERANCE:
            proto_tree_add_item(tree, hf_zbee_zcl_press_meas_tolerance, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_press_meas_scaled_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MIN_SCALED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_press_meas_min_scaled_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MAX_SCALED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_press_meas_max_scaled_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALED_TOLERANCE:
            proto_tree_add_item(tree, hf_zbee_zcl_press_meas_scaled_tolerance, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_PRESS_MEAS_SCALE:
            proto_tree_add_item(tree, hf_zbee_zcl_press_meas_scale, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_press_meas_attr_data*/

/**
 *This function decodes pressure value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_press_meas_value(gchar *s, gint16 value)
{
    if (value == (gint16)ZBEE_ZCL_ATTR_ID_PRESS_MEAS_INVALID_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Invalid value");
    if (value < (gint16)ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MIN_LO_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%d [kPa]", value/10, value%10);

    return;
} /*decode_press_meas_value*/

/**
 *This function decodes minimum pressure value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_press_meas_min_value(gchar *s, gint16 value)
{
    if (value > (gint16)ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MIN_HI_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%d [kPa]", value/10, value%10);

    return;
} /*decode_press_meas_min_value*/

/**
 *This function decodes maximum pressure value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_press_meas_max_value(gchar *s, gint16 value)
{
    if (value < (gint16)ZBEE_ZCL_ATTR_ID_PRESS_MEAS_MAX_LO_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%d [kPa]", value/10, value%10);

    return;
} /*decode_press_meas_max_value*/

/**
 *This function decodes tolerance value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_press_meas_tolerance(gchar *s, guint16 value)
{
    if (value > (guint16)ZBEE_ZCL_ATTR_ID_PRESS_MEAS_TOL_HI_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
         g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%d [kPa]", value/10, value%10);

    return;
} /*decode_press_meas_tolerance*/

/**
 *This function registers the ZCL Pressure Measurement dissector
 *
*/
void
proto_register_zbee_zcl_press_meas(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_press_meas_attr_id,
            { "Attribute", "zbee_zcl_meas_sensing.pressmeas.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_press_meas_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_press_meas_measured_value,
            { "Measured Value", "zbee_zcl_meas_sensing.pressmeas.attr.value", FT_INT16, BASE_CUSTOM, CF_FUNC(decode_press_meas_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_press_meas_min_measured_value,
            { "Min Measured Value", "zbee_zcl_meas_sensing.pressmeas.attr.value.min", FT_INT16, BASE_CUSTOM, CF_FUNC(decode_press_meas_min_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_press_meas_max_measured_value,
            { "Max Measured Value", "zbee_zcl_meas_sensing.pressmeas.attr.value.max", FT_INT16, BASE_CUSTOM, CF_FUNC(decode_press_meas_max_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_press_meas_tolerance,
            { "Tolerance", "zbee_zcl_meas_sensing.pressmeas.attr.tolerance", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_press_meas_tolerance),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_press_meas_scaled_value,
            { "Scaled Value", "zbee_zcl_meas_sensing.pressmeas.attr.scaled_value", FT_INT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_press_meas_min_scaled_value,
            { "Min Scaled Value", "zbee_zcl_meas_sensing.pressmeas.attr.scaled_value.min", FT_INT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_press_meas_max_scaled_value,
            { "Max Scaled Value", "zbee_zcl_meas_sensing.pressmeas.attr.scaled_value.max", FT_INT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_press_meas_scaled_tolerance,
            { "Scaled Tolerance", "zbee_zcl_meas_sensing.pressmeas.attr.scaled_tolerance", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_press_meas_scale,
            { "Scale", "zbee_zcl_meas_sensing.pressmeas.attr.scale", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } }

    };

    /* Register the ZigBee ZCL Pressure Measurement cluster protocol name and description */
    proto_zbee_zcl_press_meas = proto_register_protocol("ZigBee ZCL Pressure Meas.", "ZCL Pressure Meas.", ZBEE_PROTOABBREV_ZCL_PRESSMEAS);
    proto_register_field_array(proto_zbee_zcl_press_meas, hf, array_length(hf));

    /* Register the ZigBee ZCL Pressure Measurement dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_PRESSMEAS, dissect_zbee_zcl_press_meas, proto_zbee_zcl_press_meas);
} /*proto_register_zbee_zcl_press_meas*/

/**
 *Hands off the ZCL Pressure Measurement dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_press_meas(void)
{
    zbee_zcl_init_cluster(  proto_zbee_zcl_press_meas,
                            ett_zbee_zcl_press_meas,
                            ZBEE_ZCL_CID_PRESSURE_MEASUREMENT,
                            hf_zbee_zcl_press_meas_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_press_meas_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_press_meas*/

/* ########################################################################## */
/* #### (0x0404) FLOW MEASUREMENT CLUSTER ################################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_FLOW_MEAS_NUM_GENERIC_ETT                     1
#define ZBEE_ZCL_FLOW_MEAS_NUM_ETT                             ZBEE_ZCL_FLOW_MEAS_NUM_GENERIC_ETT

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MEASURED_VALUE              0x0000  /* Measured Value */
#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MIN_MEASURED_VALUE          0x0001  /* Min Measured Value */
#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MAX_MEASURED_VALUE          0x0002  /* Max Measured Value */
#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_TOLERANCE                   0x0003  /* Tolerance */

/* Server Commands Received - None */

/* Server Commands Generated - None */

#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_TOO_LOW_VALUE        0x0000  /* Too Low Value */
#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_INVALID_VALUE        0xffff  /* Invalid Value */

#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MIN_LO_VALUE         0x0000  /* Minimum Value (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MIN_HI_VALUE         0xfffd  /* Minimum Value (High Bound) */

#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MAX_LO_VALUE         0x0001  /* Maximum Value (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MAX_HI_VALUE         0xfffe  /* Maximum Value (High Bound) */

#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_TOL_LO_VALUE         0x0000  /* Tolerance (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_FLOW_MEAS_TOL_HI_VALUE         0x0800  /* Tolerance (Low Bound) */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_flow_meas(void);
void proto_reg_handoff_zbee_zcl_flow_meas(void);

/* Command Dissector Helpers */
static void dissect_zcl_flow_meas_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */
static void decode_flow_meas_value              (gchar *s, guint16 value);
static void decode_flow_meas_min_value          (gchar *s, guint16 value);
static void decode_flow_meas_max_value          (gchar *s, guint16 value);
static void decode_flow_meas_tolerance          (gchar *s, guint16 value);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_flow_meas = -1;

static int hf_zbee_zcl_flow_meas_attr_id = -1;
static int hf_zbee_zcl_flow_meas_measured_value = -1;
static int hf_zbee_zcl_flow_meas_min_measured_value = -1;
static int hf_zbee_zcl_flow_meas_max_measured_value = -1;
static int hf_zbee_zcl_flow_meas_tolerance = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_flow_meas = -1;

/* Attributes */
static const value_string zbee_zcl_flow_meas_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MEASURED_VALUE,       "Measured Value" },
    { ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MIN_MEASURED_VALUE,   "Min Measured Value" },
    { ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MAX_MEASURED_VALUE,   "Max Measured Value" },
    { ZBEE_ZCL_ATTR_ID_FLOW_MEAS_TOLERANCE,            "Tolerance" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Flow Measurement cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_flow_meas(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_flow_meas*/

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
dissect_zcl_flow_meas_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_flow_meas_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MIN_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_flow_meas_min_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MAX_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_flow_meas_max_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_FLOW_MEAS_TOLERANCE:
            proto_tree_add_item(tree, hf_zbee_zcl_flow_meas_tolerance, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_flow_meas_attr_data*/

/**
 *This function decodes flow value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_flow_meas_value(gchar *s, guint16 value)
{
    if (value == ZBEE_ZCL_ATTR_ID_FLOW_MEAS_TOO_LOW_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Value too low to be measured");
    else if (value == ZBEE_ZCL_ATTR_ID_FLOW_MEAS_INVALID_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Invalid value");
    else
        /* calculate flow value from measured value according to doc 07-5123-04 */
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d (=%f [m^3/h])", value, value/10.0);

    return;
} /*decode_flow_meas_value*/

/**
 *This function decodes minimum flow value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_flow_meas_min_value(gchar *s, guint16 value)
{
    if ( (value > ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MIN_LO_VALUE) ||
         (value > ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MIN_HI_VALUE) )
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d (=%f [m^3/h])", value, value/10.0);

    return;
} /*decode_flow_meas_min_value*/

/**
 *This function decodes maximum flow value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_flow_meas_max_value(gchar *s, guint16 value)
{
    if ( (value < ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MAX_LO_VALUE) ||
         (value > ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MAX_HI_VALUE) )
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d (=%f [m^3/h])", value, value/10.0);

    return;
} /*decode_flow_meas_max_value*/

/**
 *This function decodes tolerance value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_flow_meas_tolerance(gchar *s, guint16 value)
{
    if (value > ZBEE_ZCL_ATTR_ID_FLOW_MEAS_TOL_HI_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d", value);

    return;
} /*decode_flow_meas_tolerance*/

/**
 *This function registers the ZCL Flow Measurement dissector
 *
*/
void
proto_register_zbee_zcl_flow_meas(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_flow_meas_attr_id,
            { "Attribute", "zbee_zcl_meas_sensing.flowmeas.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_flow_meas_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_flow_meas_measured_value,
            { "Measured Value", "zbee_zcl_meas_sensing.flowmeas.attr.value", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_flow_meas_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_flow_meas_min_measured_value,
            { "Min Measured Value", "zbee_zcl_meas_sensing.flowmeas.attr.value.min", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_flow_meas_min_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_flow_meas_max_measured_value,
            { "Max Measured Value", "zbee_zcl_meas_sensing.flowmeas.attr.value.max", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_flow_meas_max_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_flow_meas_tolerance,
            { "Tolerance", "zbee_zcl_meas_sensing.flowmeas.attr.tolerance", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_flow_meas_tolerance),
            0x00, NULL, HFILL } }
    };

    /* Register the ZigBee ZCL Flow Measurement cluster protocol name and description */
    proto_zbee_zcl_flow_meas = proto_register_protocol("ZigBee ZCL Flow Meas.", "ZCL Flow Meas.", ZBEE_PROTOABBREV_ZCL_FLOWMEAS);
    proto_register_field_array(proto_zbee_zcl_flow_meas, hf, array_length(hf));

    /* Register the ZigBee ZCL Flow Measurement dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_FLOWMEAS, dissect_zbee_zcl_flow_meas, proto_zbee_zcl_flow_meas);

} /*proto_register_zbee_zcl_flow_meas*/


/**
 *Hands off the ZCL Flow Measurement dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_flow_meas(void)
{
    zbee_zcl_init_cluster(  proto_zbee_zcl_flow_meas,
                            ett_zbee_zcl_flow_meas,
                            ZBEE_ZCL_CID_FLOW_MEASUREMENT,
                            hf_zbee_zcl_flow_meas_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_flow_meas_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_flow_meas*/

/* ########################################################################## */
/* #### (0x0405) RELATIVE HUMIDITY MEASUREMENT CLUSTER ###################### */
/* ########################################################################## */


/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_RELHUM_MEAS_NUM_GENERIC_ETT              1
#define ZBEE_ZCL_RELHUM_MEAS_NUM_ETT                      ZBEE_ZCL_RELHUM_MEAS_NUM_GENERIC_ETT

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MEASURED_VALUE       0x0000  /* Measured Value */
#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MIN_MEASURED_VALUE   0x0001  /* Min Measured Value */
#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MAX_MEASURED_VALUE   0x0002  /* Max Measured Value */
#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_TOLERANCE            0x0003  /* Tolerance */

/* Server Commands Received - None */

/* Server Commands Generated - None */

#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_INVALID_VALUE        0xffff  /* Invalid Value */

#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MIN_LO_VALUE         0x0000  /* Minimum Value (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MIN_HI_VALUE         0x270f  /* Minimum Value (High Bound) */

#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MAX_LO_VALUE         0x0000  /* Maximum Value (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MAX_HI_VALUE         0x2710  /* Maximum Value (High Bound) */

#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_TOL_LO_VALUE         0x0000  /* Tolerance (Low Bound) */
#define ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_TOL_HI_VALUE         0x0800  /* Tolerance (Low Bound) */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_relhum_meas(void);
void proto_reg_handoff_zbee_zcl_relhum_meas(void);

/* Command Dissector Helpers */
static void dissect_zcl_relhum_meas_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */
static void decode_relhum_meas_value              (gchar *s, guint16 value);
static void decode_relhum_meas_min_value          (gchar *s, guint16 value);
static void decode_relhum_meas_max_value          (gchar *s, guint16 value);
static void decode_relhum_meas_tolerance          (gchar *s, guint16 value);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_relhum_meas = -1;

static int hf_zbee_zcl_relhum_meas_attr_id = -1;
static int hf_zbee_zcl_relhum_meas_measured_value = -1;
static int hf_zbee_zcl_relhum_meas_min_measured_value = -1;
static int hf_zbee_zcl_relhum_meas_max_measured_value = -1;
static int hf_zbee_zcl_relhum_meas_tolerance = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_relhum_meas = -1;

/* Attributes */
static const value_string zbee_zcl_relhum_meas_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MEASURED_VALUE,        "Measured Value" },
    { ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MIN_MEASURED_VALUE,    "Min Measured Value" },
    { ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MAX_MEASURED_VALUE,    "Max Measured Value" },
    { ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_TOLERANCE,             "Tolerance" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Relative Humidity Measurement cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_relhum_meas(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_relhum_meas*/

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
dissect_zcl_relhum_meas_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_relhum_meas_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MIN_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_relhum_meas_min_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MAX_MEASURED_VALUE:
            proto_tree_add_item(tree, hf_zbee_zcl_relhum_meas_max_measured_value, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_TOLERANCE:
            proto_tree_add_item(tree, hf_zbee_zcl_relhum_meas_tolerance, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_relhum_meas_attr_data*/

/**
 *This function decodes relative humidity value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_relhum_meas_value(gchar *s, guint16 value)
{
    if (value == ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_INVALID_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Invalid value");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%02d [%%]", value/100, value%100);

    return;
} /*decode_relhum_meas_value*/

/**
 *This function decodes minimum relative humidity value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_relhum_meas_min_value(gchar *s, guint16 value)
{
    if (value > ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MIN_HI_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%02d [%%]", value/100, value%100);

    return;
} /*decode_relhum_meas_min_value*/

/**
 *This function decodes maximum relative humidity value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_relhum_meas_max_value(gchar *s, guint16 value)
{
    if (value > ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_MAX_HI_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%02d [%%]", value/100, value%100);

    return;
} /*decode_relhum_meas_max_value*/

/**
 *This function decodes tolerance value
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_relhum_meas_tolerance(gchar *s, guint16 value)
{
    if (value > ZBEE_ZCL_ATTR_ID_RELHUM_MEAS_TOL_HI_VALUE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Out of range");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%02d [%%]", value/100, value%100);

    return;
} /*decode_relhum_meas_tolerance*/

/**
 *This function registers the ZCL Relative Humidity Measurement dissector
 *
*/
void
proto_register_zbee_zcl_relhum_meas(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_relhum_meas_attr_id,
            { "Attribute", "zbee_zcl_meas_sensing.relhummeas.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_relhum_meas_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_relhum_meas_measured_value,
            { "Measured Value", "zbee_zcl_meas_sensing.relhummeas.attr.value", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_relhum_meas_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_relhum_meas_min_measured_value,
            { "Min Measured Value", "zbee_zcl_meas_sensing.relhummeas.attr.value.min", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_relhum_meas_min_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_relhum_meas_max_measured_value,
            { "Max Measured Value", "zbee_zcl_meas_sensing.relhummeas.attr.value.max", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_relhum_meas_max_value),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_relhum_meas_tolerance,
            { "Tolerance", "zbee_zcl_meas_sensing.relhummeas.attr.tolerance", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_relhum_meas_tolerance),
            0x00, NULL, HFILL } }

    };

    /* Register the ZigBee ZCL Relative Humidity Measurement cluster protocol name and description */
    proto_zbee_zcl_relhum_meas = proto_register_protocol("ZigBee ZCL Rel. Humidity Meas.", "ZCL Relative Humidity Meas.", ZBEE_PROTOABBREV_ZCL_RELHUMMEAS);
    proto_register_field_array(proto_zbee_zcl_relhum_meas, hf, array_length(hf));

    /* Register the ZigBee ZCL Relative Humidity Measurement dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_RELHUMMEAS, dissect_zbee_zcl_relhum_meas, proto_zbee_zcl_relhum_meas);
} /*proto_register_zbee_zcl_relhum_meas*/


/**
 *Hands off the ZCL Relative Humidity Measurement dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_relhum_meas(void)
{
    zbee_zcl_init_cluster(  proto_zbee_zcl_relhum_meas,
                            ett_zbee_zcl_relhum_meas,
                            ZBEE_ZCL_CID_REL_HUMIDITY_MEASUREMENT,
                            hf_zbee_zcl_relhum_meas_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_relhum_meas_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_relhum_meas*/


/* ########################################################################## */
/* #### (0x0406) OCCUPANCY SENSING CLUSTER ################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_OCC_SEN_NUM_GENERIC_ETT                        2
#define ZBEE_ZCL_OCC_SEN_NUM_ETT                                ZBEE_ZCL_OCC_SEN_NUM_GENERIC_ETT

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_OCC_SEN_OCCUPANCY                      0x0000  /* Occupancy */
#define ZBEE_ZCL_ATTR_ID_OCC_SEN_OCC_SENSOR_TYPE                0x0001  /* Occupancy Sensor Type */
#define ZBEE_ZCL_ATTR_ID_OCC_SEN_PIR_OCC_TO_UNOCC_DELAY         0x0010  /* PIR Occupied to Unoccupied Delay */
#define ZBEE_ZCL_ATTR_ID_OCC_SEN_PIR_UNOCC_TO_OCC_DELAY         0x0011  /* PIR Unoccupied to Occupied Delay */
#define ZBEE_ZCL_ATTR_ID_OCC_SEN_PIR_UNOCC_TO_OCC_THOLD         0x0012  /* PIR Unoccupied to Occupied Threshold */
#define ZBEE_ZCL_ATTR_ID_OCC_SEN_USONIC_OCC_TO_UNOCC_DELAY      0x0020  /* Ultrasonic Occupied to Unoccupied Threshold */
#define ZBEE_ZCL_ATTR_ID_OCC_SEN_USONIC_UNOCC_TO_OCC_DELAY      0x0021  /* Ultrasonic Unoccupied to Occupied Delay */
#define ZBEE_ZCL_ATTR_ID_OCC_SEN_USONIC_UNOCC_TO_OCC_THOLD      0x0022  /* Ultrasonic Unoccupied to Occupied Threshold */

/* Server Commands Received - None */

/* Server Commands Generated - None */

/* Occupancy Mask fields */
#define ZBEE_ZCL_OCCUPANCY_SENSED_OCC                           0x01  /* Sensed Occupancy */

/* Sensed Occupancy Values */
#define ZBEE_ZCL_OCCUPANCY_SENSED_OCC_UNOCCUPIED              0x00  /* Occupied */
#define ZBEE_ZCL_OCCUPANCY_SENSED_OCC_OCCUPIED                0x01  /* Unoccupied */

/* Occupancy Sensor Type */
#define ZBEE_ZCL_OCC_SENSOR_TYPE_PIR                            0x00  /* PIR */
#define ZBEE_ZCL_OCC_SENSOR_TYPE_USONIC                         0x01  /* Ultrasonic */
#define ZBEE_ZCL_OCC_SENSOR_TYPE_PIR_AND_USONIC                 0x02  /* PIR and Ultrasonic */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_occ_sen(void);
void proto_reg_handoff_zbee_zcl_occ_sen(void);

/* Command Dissector Helpers */
static void dissect_zcl_occ_sen_attr_data               (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_occ_sen = -1;

static int hf_zbee_zcl_occ_sen_attr_id = -1;
static int hf_zbee_zcl_occ_sen_occupancy = -1;
static int hf_zbee_zcl_occ_sen_occ_sensor_type = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_occ_sen = -1;
static gint ett_zbee_zcl_occ = -1;

/* Attributes */
static const value_string zbee_zcl_occ_sen_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_OCC_SEN_OCCUPANCY,                   "Occupancy" },
    { ZBEE_ZCL_ATTR_ID_OCC_SEN_OCC_SENSOR_TYPE,             "Occupancy Sensor Type" },
    { ZBEE_ZCL_ATTR_ID_OCC_SEN_PIR_OCC_TO_UNOCC_DELAY,      "PIR Occupied to Unoccupied Delay" },
    { ZBEE_ZCL_ATTR_ID_OCC_SEN_PIR_UNOCC_TO_OCC_DELAY,      "PIR Unoccupied to Occupied Delay" },
    { ZBEE_ZCL_ATTR_ID_OCC_SEN_PIR_UNOCC_TO_OCC_THOLD,      "PIR Unoccupied to Occupied Threshold" },
    { ZBEE_ZCL_ATTR_ID_OCC_SEN_USONIC_OCC_TO_UNOCC_DELAY,   "Ultrasonic Occupied to Unoccupied Threshold" },
    { ZBEE_ZCL_ATTR_ID_OCC_SEN_USONIC_UNOCC_TO_OCC_DELAY,   "Ultrasonic Unoccupied to Occupied Delay" },
    { ZBEE_ZCL_ATTR_ID_OCC_SEN_USONIC_UNOCC_TO_OCC_THOLD,   "Ultrasonic Unoccupied to Occupied Threshold" },
    { 0, NULL }
};

/* Sensed Occupancy Values */
static const value_string zbee_zcl_occ_sen_sensed_occ_names[] = {
    { ZBEE_ZCL_OCCUPANCY_SENSED_OCC_UNOCCUPIED,     "Unoccupied" },
    { ZBEE_ZCL_OCCUPANCY_SENSED_OCC_OCCUPIED,       "Occupied" },
    { 0, NULL }
};

/* Occupancy Sensor types */
static const value_string zbee_zcl_occ_sen_sensor_type_names[] = {
    { ZBEE_ZCL_OCC_SENSOR_TYPE_PIR,                 "PIR" },
    { ZBEE_ZCL_OCC_SENSOR_TYPE_USONIC,              "Ultrasonic" },
    { ZBEE_ZCL_OCC_SENSOR_TYPE_PIR_AND_USONIC,      "PIR and Ultrasonic" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Occupancy Sensing cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_occ_sen(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_occ_sen*/

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
dissect_zcl_occ_sen_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    static const int *occupancy[] = {
        &hf_zbee_zcl_occ_sen_occupancy,
        NULL
    };

    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_OCC_SEN_OCCUPANCY:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_occ_sen_occupancy, ett_zbee_zcl_occ, occupancy, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_OCC_SEN_OCC_SENSOR_TYPE:
            proto_tree_add_item(tree, hf_zbee_zcl_occ_sen_occ_sensor_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_OCC_SEN_PIR_OCC_TO_UNOCC_DELAY:
        case ZBEE_ZCL_ATTR_ID_OCC_SEN_PIR_UNOCC_TO_OCC_DELAY:
        case ZBEE_ZCL_ATTR_ID_OCC_SEN_PIR_UNOCC_TO_OCC_THOLD:
        case ZBEE_ZCL_ATTR_ID_OCC_SEN_USONIC_OCC_TO_UNOCC_DELAY:
        case ZBEE_ZCL_ATTR_ID_OCC_SEN_USONIC_UNOCC_TO_OCC_DELAY:
        case ZBEE_ZCL_ATTR_ID_OCC_SEN_USONIC_UNOCC_TO_OCC_THOLD:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_occ_sen_attr_data*/

/**
 *This function registers the ZCL Occupancy Sensing dissector
 *
*/
void
proto_register_zbee_zcl_occ_sen(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_occ_sen_attr_id,
            { "Attribute", "zbee_zcl_meas_sensing.occsen.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_occ_sen_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_occ_sen_occupancy,
            { "Occupancy", "zbee_zcl_meas_sensing.occsen.attr.occupancy", FT_UINT8, BASE_HEX, VALS(zbee_zcl_occ_sen_sensed_occ_names),
            ZBEE_ZCL_OCCUPANCY_SENSED_OCC, NULL, HFILL } },

        { &hf_zbee_zcl_occ_sen_occ_sensor_type,
            { "Occupancy Sensor Type", "zbee_zcl_meas_sensing.occsen.attr.occ_sensor_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_occ_sen_sensor_type_names),
            0x00, NULL, HFILL } }
    };


    /* Register the ZigBee ZCL Occupancy Sensing cluster protocol name and description */
    proto_zbee_zcl_occ_sen = proto_register_protocol("ZigBee ZCL Occupancy Sensing", "ZCL Occupancy Sensing", ZBEE_PROTOABBREV_ZCL_OCCSEN);
    proto_register_field_array(proto_zbee_zcl_occ_sen, hf, array_length(hf));

    /* Register the ZigBee ZCL Occupancy Sensing dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_OCCSEN, dissect_zbee_zcl_occ_sen, proto_zbee_zcl_occ_sen);

} /*proto_register_zbee_zcl_occ_sen*/


/**
 *Hands off the ZCL Occupancy Sensing dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_occ_sen(void)
{
    zbee_zcl_init_cluster(  proto_zbee_zcl_occ_sen,
                            ett_zbee_zcl_occ_sen,
                            ZBEE_ZCL_CID_ILLUMINANCE_LEVEL_SENSING,
                            hf_zbee_zcl_occ_sen_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_occ_sen_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_occ_sen*/


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
