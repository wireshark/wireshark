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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
static void dissect_zcl_illum_meas_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_illum_meas_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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

    /* ZCL Illuminance Measurement subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_illum_meas
    };

    /* Register the ZigBee ZCL Illuminance Measurement cluster protocol name and description */
    proto_zbee_zcl_illum_meas = proto_register_protocol("ZigBee ZCL Illuminance Meas.", "ZCL Illuminance Meas.", ZBEE_PROTOABBREV_ZCL_ILLUMMEAS);
    proto_register_field_array(proto_zbee_zcl_illum_meas, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_ILLUMMEAS,
                            proto_zbee_zcl_illum_meas,
                            ett_zbee_zcl_illum_meas,
                            ZBEE_ZCL_CID_ILLUMINANCE_MEASUREMENT,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_illum_meas_attr_id,
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
static void dissect_zcl_illum_level_sen_attr_data               (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_illum_level_sen_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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

    /* ZCL Illuminance Level Sensing subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_illum_level_sen
    };

    /* Register the ZigBee ZCL Illuminance Level Sensing cluster protocol name and description */
    proto_zbee_zcl_illum_level_sen = proto_register_protocol("ZigBee ZCL Illuminance Level Sensing", "ZCL Illuminance Level Sensing", ZBEE_PROTOABBREV_ZCL_ILLUMLEVELSEN);
    proto_register_field_array(proto_zbee_zcl_illum_level_sen, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_ILLUMLEVELSEN,
                            proto_zbee_zcl_illum_level_sen,
                            ett_zbee_zcl_illum_level_sen,
                            ZBEE_ZCL_CID_ILLUMINANCE_LEVEL_SENSING,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_illum_level_sen_attr_id,
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
static void dissect_zcl_temp_meas_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_temp_meas_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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

    /* ZCL Temperature Measurement subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_temp_meas
    };

    /* Register the ZigBee ZCL Temperature Measurement cluster protocol name and description */
    proto_zbee_zcl_temp_meas = proto_register_protocol("ZigBee ZCL Temperature Meas.", "ZCL Temperature Meas.", ZBEE_PROTOABBREV_ZCL_TEMPMEAS);
    proto_register_field_array(proto_zbee_zcl_temp_meas, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_TEMPMEAS,
                            proto_zbee_zcl_temp_meas,
                            ett_zbee_zcl_temp_meas,
                            ZBEE_ZCL_CID_TEMPERATURE_MEASUREMENT,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_temp_meas_attr_id,
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
static void dissect_zcl_press_meas_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_press_meas_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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

    /* ZCL Pressure Measurement subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_press_meas
    };

    /* Register the ZigBee ZCL Pressure Measurement cluster protocol name and description */
    proto_zbee_zcl_press_meas = proto_register_protocol("ZigBee ZCL Pressure Meas.", "ZCL Pressure Meas.", ZBEE_PROTOABBREV_ZCL_PRESSMEAS);
    proto_register_field_array(proto_zbee_zcl_press_meas, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_PRESSMEAS,
                            proto_zbee_zcl_press_meas,
                            ett_zbee_zcl_press_meas,
                            ZBEE_ZCL_CID_PRESSURE_MEASUREMENT,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_press_meas_attr_id,
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
static void dissect_zcl_flow_meas_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_flow_meas_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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
    if ( /*(value < ZBEE_ZCL_ATTR_ID_FLOW_MEAS_MIN_LO_VALUE) ||*/
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

    /* ZCL Flow Measurement subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_flow_meas
    };

    /* Register the ZigBee ZCL Flow Measurement cluster protocol name and description */
    proto_zbee_zcl_flow_meas = proto_register_protocol("ZigBee ZCL Flow Meas.", "ZCL Flow Meas.", ZBEE_PROTOABBREV_ZCL_FLOWMEAS);
    proto_register_field_array(proto_zbee_zcl_flow_meas, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_FLOWMEAS,
                            proto_zbee_zcl_flow_meas,
                            ett_zbee_zcl_flow_meas,
                            ZBEE_ZCL_CID_FLOW_MEASUREMENT,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_flow_meas_attr_id,
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
static void dissect_zcl_relhum_meas_attr_data     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_relhum_meas_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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

    /* ZCL Relative Humidity Measurement subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_relhum_meas
    };

    /* Register the ZigBee ZCL Relative Humidity Measurement cluster protocol name and description */
    proto_zbee_zcl_relhum_meas = proto_register_protocol("ZigBee ZCL Rel. Humidity Meas.", "ZCL Relative Humidity Meas.", ZBEE_PROTOABBREV_ZCL_RELHUMMEAS);
    proto_register_field_array(proto_zbee_zcl_relhum_meas, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_RELHUMMEAS,
                            proto_zbee_zcl_relhum_meas,
                            ett_zbee_zcl_relhum_meas,
                            ZBEE_ZCL_CID_REL_HUMIDITY_MEASUREMENT,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_relhum_meas_attr_id,
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

#define ZBEE_ZCL_OCC_SEN_NUM_ETT                                2

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
static void dissect_zcl_occ_sen_attr_data               (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_occ_sen = -1;

static int hf_zbee_zcl_occ_sen_attr_id = -1;
static int hf_zbee_zcl_occ_sen_occupancy = -1;
static int hf_zbee_zcl_occ_sen_occupancy_occupied = -1;
static int hf_zbee_zcl_occ_sen_occ_sensor_type = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_occ_sen = -1;
static gint ett_zbee_zcl_occ_sen_occupancy = -1;

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_occ_sen_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    static int * const occupancy[] = {
        &hf_zbee_zcl_occ_sen_occupancy_occupied,
        NULL
    };

    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_OCC_SEN_OCCUPANCY:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_occ_sen_occupancy, ett_zbee_zcl_occ_sen_occupancy, occupancy, ENC_LITTLE_ENDIAN);
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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
            { "Occupancy", "zbee_zcl_meas_sensing.occsen.attr.occupancy", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_occ_sen_occupancy_occupied,
            { "Occupied", "zbee_zcl_meas_sensing.occsen.attr.occupancy_occupied", FT_BOOLEAN, 8, TFS(&tfs_true_false),
            ZBEE_ZCL_OCCUPANCY_SENSED_OCC, NULL, HFILL } },

        { &hf_zbee_zcl_occ_sen_occ_sensor_type,
            { "Occupancy Sensor Type", "zbee_zcl_meas_sensing.occsen.attr.occ_sensor_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_occ_sen_sensor_type_names),
            0x00, NULL, HFILL } }
    };


    /* ZCL Occupancy Sensing subtrees */
    static gint *ett[ZBEE_ZCL_OCC_SEN_NUM_ETT];
    ett[0] = &ett_zbee_zcl_occ_sen;
    ett[1] = &ett_zbee_zcl_occ_sen_occupancy;

    /* Register the ZigBee ZCL Occupancy Sensing cluster protocol name and description */
    proto_zbee_zcl_occ_sen = proto_register_protocol("ZigBee ZCL Occupancy Sensing", "ZCL Occupancy Sensing", ZBEE_PROTOABBREV_ZCL_OCCSEN);
    proto_register_field_array(proto_zbee_zcl_occ_sen, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_OCCSEN,
                            proto_zbee_zcl_occ_sen,
                            ett_zbee_zcl_occ_sen,
                            ZBEE_ZCL_CID_OCCUPANCY_SENSING,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_occ_sen_attr_id,
                            hf_zbee_zcl_occ_sen_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_occ_sen_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_occ_sen*/

/* ########################################################################## */
/* #### (0x0b04) ELECTRICAL MEASUREMENT CLUSTER ############################# */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_ELEC_MES_NUM_ETT                                               1

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASUREMENT_TYPE                              0x0000
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE                                    0x0100
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE_MIN                                0x0101
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE_MAX                                0x0102
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT                                    0x0103
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT_MIN                                0x0104
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT_MAX                                0x0105
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_POWER                                      0x0106
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_POWER_MIN                                  0x0107
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_POWER_MAX                                  0x0108
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE_MULTIPLIER                         0x0200
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE_DIVISOR                            0x0201
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT_MULTIPLIER                         0x0202
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT_DIVISOR                            0x0203
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_POWER_MULTIPLIER                           0x0204
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_POWER_DIVISOR                              0x0205
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_FREQUENCY                                  0x0300
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_FREQUENCY_MIN                              0x0301
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_FREQUENCY_MAX                              0x0302
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_NEUTRAL_CURRENT                               0x0303
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_TOTAL_ACTIVE_POWER                            0x0304
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_TOTAL_REACTIVE_POWER                          0x0305
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_TOTAL_APPARENT_POWER                          0x0306
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_1ST_HARMONIC_CURRENT                 0x0307
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_3RD_HARMONIC_CURRENT                 0x0308
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_5TH_HARMONIC_CURRENT                 0x0309
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_7TH_HARMONIC_CURRENT                 0x030A
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_9TH_HARMONIC_CURRENT                 0x030B
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_11TH_HARMONIC_CURRENT                0x030C
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_1ST_HARMONIC_CURRENT           0x030D
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_3RD_HARMONIC_CURRENT           0x030E
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_5TH_HARMONIC_CURRENT           0x030F
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_7TH_HARMONIC_CURRENT           0x0310
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_9TH_HARMONIC_CURRENT           0x0311
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_11TH_HARMONIC_CURRENT          0x0312
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_FREQUENCY_MULTIPLIER                       0x0400
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_FREQUENCY_DIVISOR                          0x0401
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_POWER_MULTIPLIER                              0x0402
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_POWER_DIVISOR                                 0x0403
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_HARMONIC_CURRENT_MULTIPLIER                   0x0404
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_PHASE_HARMONIC_CURRENT_MULTIPLIER             0x0405
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_LINE_CURRENT                                  0x0501
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_CURRENT                                0x0502
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_CURRENT                              0x0503
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE                                   0x0505
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MIN                               0x0506
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MAX                               0x0507
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT                                   0x0508
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MIN                               0x0509
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MAX                               0x050A
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER                                  0x050B
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MIN                              0x050C
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MAX                              0x050D
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_POWER                                0x050E
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_APPARENT_POWER                                0x050F
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_POWER_FACTOR                                  0x0510
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_VOLTAGE_MEASUREMENT_PERIOD        0x0511
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_OVER_VOLTAGE_COUNTER              0x0512
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_UNDER_VOLTAGE_COUNTER             0x0513
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_OVER_VOLTAGE_PERIOD               0x0514
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_UNDER_VOLTAGE_PERIOD              0x0515
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SAG_PERIOD                        0x0516
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SWELL_PERIOD                      0x0517
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_VOLTAGE_MULTIPLIER                         0x0600
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_VOLTAGE_DIVISOR                            0x0601
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_CURRENT_MULTIPLIER                         0x0602
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_CURRENT_DIVISOR                            0x0603
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_POWER_MULTIPLIER                           0x0604
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_POWER_DIVISOR                              0x0605
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_OVERLOAD_ALARMS_MASK                       0x0700
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE_OVERLOAD                           0x0701
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT_OVERLOAD                           0x0702
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_ALARMS_MASK                                0x0800
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_VOLTAGE_OVERLOAD                           0x0801
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_CURRENT_OVERLOAD                           0x0802
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_ACTIVE_POWER_OVERLOAD                      0x0803
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_REACTIVE_POWER_OVERLOAD                    0x0804
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_OVER_VOLTAGE                      0x0805
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_UNDER_VOLTAGE                     0x0806
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_OVER_VOLTAGE                      0x0807
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_UNDER_VOLTAGE                     0x0808
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SAG                               0x0809
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SWELL                             0x080A
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_LINE_CURRENT_PH_B                             0x0901
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_CURRENT_PH_B                           0x0902
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_CURRENT_PH_B                         0x0903
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_PH_B                              0x0905
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MIN_PH_B                          0x0906
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MAX_PH_B                          0x0907
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_PH_B                              0x0908
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MIN_PH_B                          0x0909
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MAX_PH_B                          0x090A
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_PH_B                             0x090B
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MIN_PH_B                         0x090C
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MAX_PH_B                         0x090D
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_POWER_PH_B                           0x090E
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_APPARENT_POWER_PH_B                           0x090F
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_POWER_FACTOR_PH_B                             0x0910
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_VOLTAGE_MEASUREMENT_PERIOD_PH_B   0x0911
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_OVER_VOLTAGE_COUNTER_PH_B         0x0912
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_UNDER_VOLTAGE_COUNTER_PH_B        0x0913
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_OVER_VOLTAGE_PERIOD_PH_B          0x0914
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_UNDER_VOLTAGE_PERIOD_PH_B         0x0915
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SAG_PERIOD_PH_B                   0x0916
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SWELL_PERIOD_PH_B                 0x0917
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_LINE_CURRENT_PH_C                             0x0A01
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_CURRENT_PH_C                         0x0A03
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_PH_C                              0x0A05
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MIN_PH_C                          0x0A06
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MAX_PH_C                          0x0A07
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_PH_C                              0x0A08
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MIN_PH_C                          0x0A09
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MAX_PH_C                          0x0A0A
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_PH_C                             0x0A0B
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MIN_PH_C                         0x0A0C
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MAX_PH_C                         0x0A0D
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_POWER_PH_C                           0x0A0E
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_APPARENT_POWER_PH_C                           0x0A0F
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_POWER_FACTOR_PH_C                             0x0A10
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_VOLTAGE_MEASUREMENT_PERIOD_PH_C   0x0A11
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_OVER_VOLTAGE_COUNTER_PH_C         0x0A12
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_UNDER_VOLTAGE_COUNTER_PH_C        0x0A13
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_OVER_VOLTAGE_PERIOD_PH_C          0x0A14
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_UNDER_VOLTAGE_PERIOD_PH_C         0x0A15
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SAG_PERIOD_PH_C                   0x0A16
#define ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SWELL_PERIOD_PH_C                 0x0A17

/* Server Commands Received */
#define ZBEE_ZCL_CMD_GET_PROFILE_INFO                                           0x00
#define ZBEE_ZCL_CMD_GET_MEASUREMENT_PROFILE_INFO                               0x01

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_GET_PROFILE_INFO_RESPONSE                                  0x00
#define ZBEE_ZCL_CMD_GET_MEASUREMENT_PROFILE_INFO_RESPONSE                      0x01

/* Profile Interval Period */
#define ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_DAILY                         0
#define ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_60_MINUTES                    1
#define ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_30_MINUTES                    2
#define ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_15_MINUTES                    3
#define ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_10_MINUTES                    4
#define ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_7_5_MINUTES                   5
#define ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_5_MINUTES                     6
#define ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_2_5_MINUTES                   7

/* List of Status Valid Values */
#define ZBEE_ZCL_ELEC_MES_STATUS_SUCCESS                                        0x00
#define ZBEE_ZCL_ELEC_MES_STATUS_ATTRIBUTE_PROFILE_NOT_SUPPORTED                0x01
#define ZBEE_ZCL_ELEC_MES_STATUS_INVALID_START_TIME                             0x02
#define ZBEE_ZCL_ELEC_MES_STATUS_MORE_INTERVALS_REQUESTED_THAN_CAN_BE_RET       0x03
#define ZBEE_ZCL_ELEC_MES_STATUS_NO_INTERVALS_AVAILABLE_FOR_THE_REQ_TIME        0x04

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_elec_mes(void);
void proto_reg_handoff_zbee_zcl_elec_mes(void);

/* Command Dissector Helpers */
static void dissect_zcl_elec_mes_attr_data                              (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);
static void dissect_zcl_elec_mes_get_measurement_profile_info           (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_elec_mes_get_profile_info_response              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_elec_mes_get_measurement_profile_info_response  (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_elec_mes = -1;

static int hf_zbee_zcl_elec_mes_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_elec_mes_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_elec_mes_attr_id = -1;
static int hf_zbee_zcl_elec_mes_start_time = -1;
static int hf_zbee_zcl_elec_mes_number_of_intervals = -1;
static int hf_zbee_zcl_elec_mes_profile_count = -1;
static int hf_zbee_zcl_elec_mes_profile_interval_period = -1;
static int hf_zbee_zcl_elec_mes_max_number_of_intervals = -1;
static int hf_zbee_zcl_elec_mes_status = -1;
static int hf_zbee_zcl_elec_mes_number_of_intervals_delivered = -1;
static int hf_zbee_zcl_elec_mes_intervals = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_elec_mes = -1;

/* Attributes */
static const value_string zbee_zcl_elec_mes_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASUREMENT_TYPE,                                           "Measurement Type" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE,                                                 "DC Voltage" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE_MIN,                                             "DC Voltage Min" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE_MAX,                                             "DC Voltage Max" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT,                                                 "DC Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT_MIN,                                             "DC Current Min" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT_MAX,                                             "DC Current Max" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_POWER,                                                   "DC Power" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_POWER_MIN,                                               "DC Power Min" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_POWER_MAX,                                               "DC Power Max" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE_MULTIPLIER,                                      "DC Voltage Multiplier" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE_DIVISOR,                                         "DC Voltage Divisor" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT_MULTIPLIER,                                      "DC Current Multiplier" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT_DIVISOR,                                         "DC Current Divisor" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_POWER_MULTIPLIER,                                        "DC Power Multiplier" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_POWER_DIVISOR,                                           "DC Power Divisor" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_FREQUENCY,                                               "AC Frequency" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_FREQUENCY_MIN,                                           "AC Frequency Min" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_FREQUENCY_MAX,                                           "AC Frequency Max" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_NEUTRAL_CURRENT,                                            "Neutral Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_TOTAL_ACTIVE_POWER,                                         "Total Active Power" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_TOTAL_REACTIVE_POWER,                                       "Total Reactive Power" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_TOTAL_APPARENT_POWER,                                       "Total Apparent Power" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_1ST_HARMONIC_CURRENT,                              "Measured 1st Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_3RD_HARMONIC_CURRENT,                              "Measured 3rd Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_5TH_HARMONIC_CURRENT,                              "Measured 5th Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_7TH_HARMONIC_CURRENT,                              "Measured 7th Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_9TH_HARMONIC_CURRENT,                              "Measured 9th Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_11TH_HARMONIC_CURRENT,                             "Measured 11th Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_1ST_HARMONIC_CURRENT,                        "Measured Phase 1st Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_3RD_HARMONIC_CURRENT,                        "Measured Phase 3rd Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_5TH_HARMONIC_CURRENT,                        "Measured Phase 5th Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_7TH_HARMONIC_CURRENT,                        "Measured Phase 7th Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_9TH_HARMONIC_CURRENT,                        "Measured Phase 9th Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_MEASURED_PHASE_11TH_HARMONIC_CURRENT,                       "Measured Phase 11th Harmonic Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_FREQUENCY_MULTIPLIER,                                    "AC Frequency Multiplier" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_FREQUENCY_DIVISOR,                                       "AC Frequency Divisor" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_POWER_MULTIPLIER,                                           "Power Multiplier" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_POWER_DIVISOR,                                              "Power Divisor" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_HARMONIC_CURRENT_MULTIPLIER,                                "Harmonic Current Multiplier" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_PHASE_HARMONIC_CURRENT_MULTIPLIER,                          "Phase Harmonic Current Multiplier" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_LINE_CURRENT,                                               "Line Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_CURRENT,                                             "Active Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_CURRENT,                                           "Reactive Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE,                                                "RMS Voltage" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MIN,                                            "RMS Voltage Min" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MAX,                                            "RMS Voltage Max" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT,                                                "RMS Current" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MIN,                                            "RMS Current Min" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MAX,                                            "RMS Current Max" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER,                                               "Active Power" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MIN,                                           "Active Power Min" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MAX,                                           "Active Power Max" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_POWER,                                             "Reactive Power" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_APPARENT_POWER,                                             "Apparent Power" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_POWER_FACTOR,                                               "Power Factor" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_VOLTAGE_MEASUREMENT_PERIOD,                     "Average RMS Voltage Measurement Period" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_OVER_VOLTAGE_COUNTER,                           "Average RMS Over Voltage Counter" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_UNDER_VOLTAGE_COUNTER,                          "Average RMS Under Voltage Counter" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_OVER_VOLTAGE_PERIOD,                            "RMS Extreme Over Voltage Period" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_UNDER_VOLTAGE_PERIOD,                           "RMS Extreme Under Voltage Period" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SAG_PERIOD,                                     "RMS Voltage Sag Period" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SWELL_PERIOD,                                   "RMS Voltage Swell Period" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_VOLTAGE_MULTIPLIER,                                      "AC Voltage Multiplier" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_VOLTAGE_DIVISOR,                                         "AC Voltage Divisor" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_CURRENT_MULTIPLIER,                                      "AC Current Multiplier" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_CURRENT_DIVISOR,                                         "AC Current Divisor" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_POWER_MULTIPLIER,                                        "AC Power Multiplier" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_POWER_DIVISOR,                                           "AC Power Divisor" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_OVERLOAD_ALARMS_MASK,                                    "DC Overload Alarms Mask" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_VOLTAGE_OVERLOAD,                                        "DC Voltage Overload" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_DC_CURRENT_OVERLOAD,                                        "DC Current Overload" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_ALARMS_MASK,                                             "AC Alarms Mask" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_VOLTAGE_OVERLOAD,                                        "AC Voltage Overload" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_CURRENT_OVERLOAD,                                        "AC Current Overload" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_ACTIVE_POWER_OVERLOAD,                                   "AC Active Power Overload" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AC_REACTIVE_POWER_OVERLOAD,                                 "AC Reactive Power Overload" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_OVER_VOLTAGE,                                   "Average RMS Over Voltage" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_UNDER_VOLTAGE,                                  "Average RMS Under Voltage" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_OVER_VOLTAGE,                                   "RMS Extreme Over Voltage" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_UNDER_VOLTAGE,                                  "RMS Extreme Under Voltage" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SAG,                                            "RMS Voltage Sag" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SWELL,                                          "RMS Voltage Swell" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_LINE_CURRENT_PH_B,                                          "Line Current Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_CURRENT_PH_B,                                        "Active Current Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_CURRENT_PH_B,                                      "Reactive Current Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_PH_B,                                           "RMS Voltage Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MIN_PH_B,                                       "RMS Voltage Min Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MAX_PH_B,                                       "RMS Voltage Max Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_PH_B,                                           "RMS Current Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MIN_PH_B,                                       "RMS Current Min Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MAX_PH_B,                                       "RMS Current Max Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_PH_B,                                          "Active Power Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MIN_PH_B,                                      "Active Power Min Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MAX_PH_B,                                      "Active Power Max Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_POWER_PH_B,                                        "Reactive Power Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_APPARENT_POWER_PH_B,                                        "Apparent Power Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_POWER_FACTOR_PH_B,                                          "Power Factor Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_VOLTAGE_MEASUREMENT_PERIOD_PH_B,                "Average RMS Voltage Measurement Period Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_OVER_VOLTAGE_COUNTER_PH_B,                      "Average RMS Over Voltage Counter Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_UNDER_VOLTAGE_COUNTER_PH_B,                     "Average RMS Under Voltage Counter Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_OVER_VOLTAGE_PERIOD_PH_B,                       "RMS Extreme Over Voltage Period Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_UNDER_VOLTAGE_PERIOD_PH_B,                      "RMS Extreme Under Voltage Period Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SAG_PERIOD_PH_B,                                "RMS Voltage Sag Period Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SWELL_PERIOD_PH_B,                              "RMS Voltage Swell Period Ph B" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_LINE_CURRENT_PH_C,                                          "Line Current Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_CURRENT_PH_C,                                      "Reactive Current Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_PH_C,                                           "RMS Voltage Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MIN_PH_C,                                       "RMS Voltage Min Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_MAX_PH_C,                                       "RMS Voltage Max Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_PH_C,                                           "RMS Current Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MIN_PH_C,                                       "RMS Current Min Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_CURRENT_MAX_PH_C,                                       "RMS Current Max Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_PH_C,                                          "Active Power Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MIN_PH_C,                                      "Active Power Min Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_ACTIVE_POWER_MAX_PH_C,                                      "Active Power Max Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_REACTIVE_POWER_PH_C,                                        "Reactive Power Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_APPARENT_POWER_PH_C,                                        "Apparent Power Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_POWER_FACTOR_PH_C,                                          "Power Factor Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_VOLTAGE_MEASUREMENT_PERIOD_PH_C,                "Average RMS Voltage Measurement Period Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_OVER_VOLTAGE_COUNTER_PH_C,                      "Average RMS Over Voltage Counter Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_AVERAGE_RMS_UNDER_VOLTAGE_COUNTER_PH_C,                     "Average RMS Under Voltage Counter Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_OVER_VOLTAGE_PERIOD_PH_C,                       "RMS Extreme Over Voltage Period Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_EXTREME_UNDER_VOLTAGE_PERIOD_PH_C,                      "RMS Extreme Under Voltage Period Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SAG_PERIOD_PH_C,                                "RMS Voltage Sag Period Ph C" },
    { ZBEE_ZCL_ATTR_ID_ELEC_MES_RMS_VOLTAGE_SWELL_PERIOD_PH_C,                              "RMS Voltage Swell Period Ph C" },
    { 0, NULL }
};
static value_string_ext zbee_zcl_elec_mes_attr_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_elec_mes_attr_names);

/* Server Commands Received */
static const value_string zbee_zcl_elec_mes_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_GET_PROFILE_INFO,                                                        "Get Profile Info", },
    { ZBEE_ZCL_CMD_GET_MEASUREMENT_PROFILE_INFO,                                            "Get Measurement Profile", },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_elec_mes_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_GET_PROFILE_INFO_RESPONSE,                                               "Get Profile Info Response", },
    { ZBEE_ZCL_CMD_GET_MEASUREMENT_PROFILE_INFO_RESPONSE,                                   "Get Measurement Profile Response", },
    { 0, NULL }
};

/* Profile Interval Period */
static const value_string zbee_zcl_elec_mes_profile_interval_period_names[] = {
    { ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_DAILY,                                      "Daily", },
    { ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_60_MINUTES,                                 "60 Minutes", },
    { ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_30_MINUTES,                                 "30 Minutes", },
    { ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_15_MINUTES,                                 "15 Minutes", },
    { ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_10_MINUTES,                                 "10 Minutes", },
    { ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_7_5_MINUTES,                                "7.5 Minutes", },
    { ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_5_MINUTES,                                  "5 Minutes", },
    { ZBEE_ZCL_ELEC_MES_PROFILE_INTERVAL_PERIOD_2_5_MINUTES,                                "2.5 Minutes", },
    { 0, NULL }
};

/* List of Status Valid Values */
static const value_string zbee_zcl_elec_mes_status_names[] = {
    { ZBEE_ZCL_ELEC_MES_STATUS_SUCCESS,                                                     "Success", },
    { ZBEE_ZCL_ELEC_MES_STATUS_ATTRIBUTE_PROFILE_NOT_SUPPORTED,                             "Attribute Profile not supported", },
    { ZBEE_ZCL_ELEC_MES_STATUS_INVALID_START_TIME,                                          "Invalid Start Time", },
    { ZBEE_ZCL_ELEC_MES_STATUS_MORE_INTERVALS_REQUESTED_THAN_CAN_BE_RET,                    "More intervals requested than can be returned", },
    { ZBEE_ZCL_ELEC_MES_STATUS_NO_INTERVALS_AVAILABLE_FOR_THE_REQ_TIME,                     "No intervals available for the requested time", },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Electrical Measurement cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_elec_mes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_elec_mes_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_elec_mes_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_elec_mes, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_GET_PROFILE_INFO:
                    /* No Payload */
                    break;

                case ZBEE_ZCL_CMD_GET_MEASUREMENT_PROFILE_INFO:
                    dissect_zcl_elec_mes_get_measurement_profile_info(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_elec_mes_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_elec_mes_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_elec_mes, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_GET_PROFILE_INFO_RESPONSE:
                    dissect_zcl_elec_mes_get_profile_info_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_GET_MEASUREMENT_PROFILE_INFO_RESPONSE:
                    dissect_zcl_elec_mes_get_measurement_profile_info_response(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_elec_mes*/

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
static void
dissect_zcl_elec_mes_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }
} /*dissect_zcl_elec_mes_attr_data*/

/**
 *This function manages the Get Measurement Profile Info payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void dissect_zcl_elec_mes_get_measurement_profile_info(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_elec_mes_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_number_of_intervals, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

/**
 *This function manages the Get Profile Info Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void dissect_zcl_elec_mes_get_profile_info_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_profile_count, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_profile_interval_period, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_max_number_of_intervals, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    while (tvb_reported_length_remaining(tvb, *offset) > 0) {
        proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }
}

/**
 *This function manages the Get Measurement Profile Info Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void dissect_zcl_elec_mes_get_measurement_profile_info_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;
    guint rem_len;

    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_elec_mes_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_profile_interval_period, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_number_of_intervals_delivered, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    rem_len = tvb_reported_length_remaining(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_elec_mes_intervals, tvb, *offset, rem_len, ENC_NA);
    *offset += rem_len;
}

/**
 *This function registers the ZCL Occupancy Sensing dissector
 *
*/
void
proto_register_zbee_zcl_elec_mes(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_elec_mes_srv_tx_cmd_id,
            { "Command", "zbee_zcl_meas_sensing.elecmes.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_elec_mes_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_elec_mes_srv_rx_cmd_id,
            { "Command", "zbee_zcl_meas_sensing.elecmes.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_elec_mes_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_elec_mes_attr_id,
            { "Attribute", "zbee_zcl_meas_sensing.elecmes.attr_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &zbee_zcl_elec_mes_attr_names_ext,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_elec_mes_start_time,
            { "Start Time", "zbee_zcl_meas_sensing.elecmes.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_elec_mes_number_of_intervals,
            { "Number of Intervals", "zbee_zcl_meas_sensing.elecmes.number_of_intervals", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_elec_mes_profile_count,
            { "Profile Count", "zbee_zcl_meas_sensing.elecmes.profile_count", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_elec_mes_profile_interval_period,
            { "Profile Interval Pediod", "zbee_zcl_meas_sensing.elecmes.profile_interval_period", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_elec_mes_max_number_of_intervals,
            { "Max Number of Intervals", "zbee_zcl_meas_sensing.elecmes.max_number_of_intervals", FT_UINT8, BASE_DEC, VALS(zbee_zcl_elec_mes_profile_interval_period_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_elec_mes_status,
            { "Status", "zbee_zcl_meas_sensing.elecmes.status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_elec_mes_status_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_elec_mes_number_of_intervals_delivered,
            { "Number of Intervals Delivered", "zbee_zcl_meas_sensing.elecmes.number_of_intervals_delivered", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_elec_mes_intervals,
            { "Intervals", "zbee_zcl_meas_sensing.elecmes.intervals", FT_BYTES, BASE_NONE, NULL,
            0x00, NULL, HFILL } }
    };

    /* ZCL Electrical Measurement subtrees */
    static gint *ett[ZBEE_ZCL_ELEC_MES_NUM_ETT];
    ett[0] = &ett_zbee_zcl_elec_mes;

    /* Register the ZigBee ZCL Electrical Measurement cluster protocol name and description */
    proto_zbee_zcl_elec_mes = proto_register_protocol("ZigBee ZCL Electrical Measurement", "ZCL Electrical Measurement", ZBEE_PROTOABBREV_ZCL_ELECMES);
    proto_register_field_array(proto_zbee_zcl_elec_mes, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Electrical Measurement dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_ELECMES, dissect_zbee_zcl_elec_mes, proto_zbee_zcl_elec_mes);

} /*proto_register_zbee_zcl_elec_mes*/


/**
 *Hands off the ZCL Electrical Measurement dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_elec_mes(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_ELECMES,
                            proto_zbee_zcl_elec_mes,
                            ett_zbee_zcl_elec_mes,
                            ZBEE_ZCL_CID_ELECTRICAL_MEASUREMENT,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_elec_mes_attr_id,
                            -1,
                            hf_zbee_zcl_elec_mes_srv_rx_cmd_id,
                            hf_zbee_zcl_elec_mes_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_elec_mes_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_elec_mes*/

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
