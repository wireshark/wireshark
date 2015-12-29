/* packet-zbee-zcl-closures.c
 * Dissector routines for the ZigBee ZCL Closures clusters
 * Shade configuration, Door Lock
 * By <aditya.jain@samsung.com>
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
/* #### (0x0100) SHADE CONFIGURATION CLUSTER ################################ */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_SHADE_CONFIGURATION_NUM_ETT                                       2

/*Attributes*/
#define ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_PHYSICAL_CLOSED_LIMIT                 0x0000  /* Physical Closed Limit */
#define ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_MOTOR_STEP_SIZE                       0x0001  /* Motor Step Size */
#define ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_STATUS                                0x0002  /* Status */
#define ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_CLOSED_LIMIT                          0x0010  /* Closed Limit */
#define ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_MODE                                  0x0011  /* Mode */

/*Server commands received - none*/

/*Server commands generated - none*/

/*Status Mask Value*/
#define ZBEE_ZCL_SHADE_CONFIGURATION_STATUS_SHADE_OPERATIONAL                       0x01    /* Shade Operational */
#define ZBEE_ZCL_SHADE_CONFIGURATION_STATUS_SHADE_ADJUSTING                         0x02    /* Shade Adjusting */
#define ZBEE_ZCL_SHADE_CONFIGURATION_STATUS_SHADE_DIRECTION                         0x04    /* Shade Direction */
#define ZBEE_ZCL_SHADE_CONFIGURATION_STATUS_MOTOR_FORWARD_DIRECTION                 0x08    /* Motor Forward Direction */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_shade_configuration(void);
void proto_reg_handoff_zbee_zcl_shade_configuration(void);

/* Command Dissector Helpers */
static void dissect_zcl_shade_configuration_attr_data      (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_shade_configuration = -1;

static int hf_zbee_zcl_shade_configuration_attr_id = -1;
static int hf_zbee_zcl_shade_configuration_status = -1;
static int hf_zbee_zcl_shade_configuration_status_shade_operational = -1;
static int hf_zbee_zcl_shade_configuration_status_shade_adjusting = -1;
static int hf_zbee_zcl_shade_configuration_status_shade_direction = -1;
static int hf_zbee_zcl_shade_configuration_status_motor_forward_direction = -1;
static int hf_zbee_zcl_shade_configuration_mode = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_shade_configuration = -1;
static gint ett_zbee_zcl_shade_configuration_status = -1;

/* Attributes */
static const value_string zbee_zcl_shade_configuration_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_PHYSICAL_CLOSED_LIMIT,       "Physical Closed Limit" },
    { ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_MOTOR_STEP_SIZE,             "Motor Step Size" },
    { ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_STATUS,                      "Status" },
    { ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_CLOSED_LIMIT,                "Closed Limit" },
    { ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_MODE,                        "Mode" },
    { 0, NULL }
};

/*Shade and motor direction values*/
static const value_string zbee_zcl_shade_configuration_shade_motor_direction_names[] = {
    {0, "Closing"},
    {1, "Opening"},
    {0, NULL}
};

/*Mode Values*/
static const value_string zbee_zcl_shade_configuration_mode_names[] = {
    {0, "Normal"},
    {1, "Configure"},
    {0, NULL}
};


/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Shade Configuration cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/

static int
dissect_zbee_zcl_shade_configuration(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_shade_configuration*/


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
dissect_zcl_shade_configuration_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    static const int * shade_config_status[] = {
        &hf_zbee_zcl_shade_configuration_status_shade_operational,
        &hf_zbee_zcl_shade_configuration_status_shade_adjusting,
        &hf_zbee_zcl_shade_configuration_status_shade_direction,
        &hf_zbee_zcl_shade_configuration_status_motor_forward_direction,
        NULL
    };

    /* Dissect attribute data type and data */
    switch (attr_id) {

        case ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_STATUS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_shade_configuration_status, ett_zbee_zcl_shade_configuration_status, shade_config_status, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_MODE:
            proto_tree_add_item(tree, hf_zbee_zcl_shade_configuration_mode, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_PHYSICAL_CLOSED_LIMIT:
        case ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_MOTOR_STEP_SIZE:
        case ZBEE_ZCL_ATTR_ID_SHADE_CONFIGURATION_CLOSED_LIMIT:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_shade_configuration_attr_data*/


/**
 *ZigBee ZCL Shade Configuration cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_shade_configuration(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_shade_configuration_attr_id,
            { "Attribute", "zbee_zcl_closures.shade_configuration.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_shade_configuration_attr_names),
            0x00, NULL, HFILL } },

        /* start Shade Configuration Status fields */
        { &hf_zbee_zcl_shade_configuration_status,
            { "Shade Configuration Status", "zbee_zcl_closures.shade_configuration.attr.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_shade_configuration_status_shade_operational,
            { "Shade Operational", "zbee_zcl_closures.shade_configuration.attr.status.shade_operational", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_SHADE_CONFIGURATION_STATUS_SHADE_OPERATIONAL, NULL, HFILL } },

        { &hf_zbee_zcl_shade_configuration_status_shade_adjusting,
            { "Shade Adjusting", "zbee_zcl_closures.shade_configuration.attr.status.shade_adjusting", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_SHADE_CONFIGURATION_STATUS_SHADE_ADJUSTING, NULL, HFILL } },

        { &hf_zbee_zcl_shade_configuration_status_shade_direction,
            { "Shade Direction", "zbee_zcl_closures.shade_configuration.attr.status.shade_direction", FT_UINT8, BASE_DEC, VALS(zbee_zcl_shade_configuration_shade_motor_direction_names),
            ZBEE_ZCL_SHADE_CONFIGURATION_STATUS_SHADE_DIRECTION, NULL, HFILL } },

        { &hf_zbee_zcl_shade_configuration_status_motor_forward_direction,
            { "Motor Forward Direction", "zbee_zcl_closures.shade_configuration.attr.status.motor_forward_direction", FT_UINT8, BASE_DEC, VALS(zbee_zcl_shade_configuration_shade_motor_direction_names),
            ZBEE_ZCL_SHADE_CONFIGURATION_STATUS_MOTOR_FORWARD_DIRECTION, NULL, HFILL } },
        /* end Shade Configuration Status fields */

        { &hf_zbee_zcl_shade_configuration_mode,
            { "Mode", "zbee_zcl_closures.shade_configuration.attr.mode", FT_UINT8, BASE_HEX, VALS(zbee_zcl_shade_configuration_mode_names),
            0x00, NULL, HFILL } }
    };

    /* ZCL Shade Configuration subtrees */
    static gint *ett[ZBEE_ZCL_SHADE_CONFIGURATION_NUM_ETT];

    ett[0] = &ett_zbee_zcl_shade_configuration;
    ett[1] = &ett_zbee_zcl_shade_configuration_status;

    /* Register the ZigBee ZCL Shade Configuration cluster protocol name and description */
    proto_zbee_zcl_shade_configuration = proto_register_protocol("ZigBee ZCL Shade Configuration", "ZCL Shade Configuration", ZBEE_PROTOABBREV_ZCL_SHADE_CONFIG);
    proto_register_field_array(proto_zbee_zcl_shade_configuration, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Shade Configuration dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_SHADE_CONFIG, dissect_zbee_zcl_shade_configuration, proto_zbee_zcl_shade_configuration);
} /*proto_register_zbee_zcl_shade_configuration*/

/**
 *Hands off the ZCL Shade Configuration dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_shade_configuration(void)
{
    dissector_handle_t shade_config_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    shade_config_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_SHADE_CONFIG);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_SHADE_CONFIG, shade_config_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_shade_configuration,
                            ett_zbee_zcl_shade_configuration,
                            ZBEE_ZCL_CID_SHADE_CONFIG,
                            hf_zbee_zcl_shade_configuration_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_shade_configuration_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_shade_configuration*/


/* ########################################################################## */
/* #### (0x0101) DOOR LOCK CLUSTER ########################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_DOOR_LOCK_NUM_ETT                                  1

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_DOOR_LOCK_LOCK_STATE                       0x0000  /* Lock State */
#define ZBEE_ZCL_ATTR_ID_DOOR_LOCK_LOCK_TYPE                        0x0001  /* Lock Type */
#define ZBEE_ZCL_ATTR_ID_DOOR_LOCK_ACTUATOR_ENABLED                 0x0002  /* Actuator Enabled */
#define ZBEE_ZCL_ATTR_ID_DOOR_LOCK_DOOR_STATE                       0x0003  /* Door State */
#define ZBEE_ZCL_ATTR_ID_DOOR_LOCK_DOOR_OPEN_EVENTS                 0x0004  /* Door Open Events */
#define ZBEE_ZCL_ATTR_ID_DOOR_LOCK_DOOR_CLOSED_EVENTS               0x0005  /* Door Closed Events */
#define ZBEE_ZCL_ATTR_ID_DOOR_LOCK_OPEN_PERIOD                      0x0006  /* Open Period */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_DOOR_LOCK_LOCK_DOOR                         0x00  /* Lock Door */
#define ZBEE_ZCL_CMD_ID_DOOR_LOCK_UNLOCK_DOOR                       0x01  /* Unlock Door */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_DOOR_LOCK_LOCK_DOOR_RESPONSE                0x00  /* Lock Door Response */
#define ZBEE_ZCL_CMD_ID_DOOR_LOCK_UNLOCK_DOOR_RESPONSE              0x01  /* Unlock Door Response */


/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_door_lock(void);
void proto_reg_handoff_zbee_zcl_door_lock(void);

/* Command Dissector Helpers */
static void dissect_zcl_door_lock_lock_unlock_door_response        (tvbuff_t *tvb, proto_tree *tree, guint *offset);

static void dissect_zcl_door_lock_attr_data                        (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_door_lock = -1;

static int hf_zbee_zcl_door_lock_attr_id = -1;
static int hf_zbee_zcl_door_lock_lock_state = -1;
static int hf_zbee_zcl_door_lock_lock_type = -1;
static int hf_zbee_zcl_door_lock_door_state = -1;
static int hf_zbee_zcl_door_lock_actuator_enabled = -1;
static int hf_zbee_zcl_door_lock_status = -1;
static int hf_zbee_zcl_door_lock_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_door_lock_srv_tx_cmd_id = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_door_lock = -1;

/* Attributes */
static const value_string zbee_zcl_door_lock_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_DOOR_LOCK_LOCK_STATE,            "Lock State" },
    { ZBEE_ZCL_ATTR_ID_DOOR_LOCK_LOCK_TYPE,             "Lock Type" },
    { ZBEE_ZCL_ATTR_ID_DOOR_LOCK_ACTUATOR_ENABLED,      "Actuator Enabled" },
    { ZBEE_ZCL_ATTR_ID_DOOR_LOCK_DOOR_STATE,            "Door State" },
    { ZBEE_ZCL_ATTR_ID_DOOR_LOCK_DOOR_OPEN_EVENTS,      "Door Open Events" },
    { ZBEE_ZCL_ATTR_ID_DOOR_LOCK_DOOR_CLOSED_EVENTS,    "Door Closed Events" },
    { ZBEE_ZCL_ATTR_ID_DOOR_LOCK_OPEN_PERIOD,           "Open Period" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_door_lock_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_DOOR_LOCK_LOCK_DOOR,              "Lock Door" },
    { ZBEE_ZCL_CMD_ID_DOOR_LOCK_UNLOCK_DOOR,            "Unlock Door" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_door_lock_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_DOOR_LOCK_LOCK_DOOR_RESPONSE,     "Lock Door Response" },
    { ZBEE_ZCL_CMD_ID_DOOR_LOCK_UNLOCK_DOOR_RESPONSE,   "Unlock Door Response" },
    { 0, NULL }
};

/* Lock State Values */
static const value_string zbee_zcl_door_lock_lock_state_values[] = {
    { 0x00,   "Not Fully Locked" },
    { 0x01,   "Locked" },
    { 0x02,   "Unlocked" },
    { 0, NULL }
};

/* Lock Type Values */
static const value_string zbee_zcl_door_lock_lock_type_values[] = {
    { 0x00,   "Deadbolt" },
    { 0x01,   "Magnetic" },
    { 0x02,   "Other" },
    { 0, NULL }
};

/* Door State Values */
static const value_string zbee_zcl_door_lock_door_state_values[] = {
    { 0x00,   "Open" },
    { 0x01,   "Closed" },
    { 0x02,   "Error (Jammed)" },
    { 0x03,   "Error (Forced Open)" },
    { 0x04,   "Error (Unspecified)" },
    { 0, NULL }
};


/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Door Lock cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_door_lock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_door_lock_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_door_lock_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            /*payload_tree =*/ proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_door_lock, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_DOOR_LOCK_LOCK_DOOR:
                case ZBEE_ZCL_CMD_ID_DOOR_LOCK_UNLOCK_DOOR:
                    /* No Payload */
                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_door_lock_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_door_lock_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_door_lock, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_DOOR_LOCK_LOCK_DOOR_RESPONSE:
                case ZBEE_ZCL_CMD_ID_DOOR_LOCK_UNLOCK_DOOR_RESPONSE:
                    dissect_zcl_door_lock_lock_unlock_door_response(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_door_lock*/


/**
 *This function decodes the lock and unlock door response
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_door_lock_lock_unlock_door_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve "Status" field */
    proto_tree_add_item(tree, hf_zbee_zcl_door_lock_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_door_lock_lock_unlock_door_response*/


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
dissect_zcl_door_lock_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_DOOR_LOCK_LOCK_STATE:
            proto_tree_add_item(tree, hf_zbee_zcl_door_lock_lock_state, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_DOOR_LOCK_LOCK_TYPE:
            proto_tree_add_item(tree, hf_zbee_zcl_door_lock_lock_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_DOOR_LOCK_ACTUATOR_ENABLED:
            proto_tree_add_item(tree, hf_zbee_zcl_door_lock_actuator_enabled, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_DOOR_LOCK_DOOR_STATE:
            proto_tree_add_item(tree, hf_zbee_zcl_door_lock_door_state, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_DOOR_LOCK_DOOR_OPEN_EVENTS:
        case ZBEE_ZCL_ATTR_ID_DOOR_LOCK_DOOR_CLOSED_EVENTS:
        case ZBEE_ZCL_ATTR_ID_DOOR_LOCK_OPEN_PERIOD:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_door_lock_attr_data*/


/**
 *ZigBee ZCL Door Lock cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_door_lock(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_door_lock_attr_id,
            { "Attribute", "zbee_zcl_closures.door_lock.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_door_lock_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_door_lock_lock_state,
            { "Lock State", "zbee_zcl_closures.door_lock.attr.lock_state", FT_UINT8, BASE_HEX, VALS(zbee_zcl_door_lock_lock_state_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_door_lock_lock_type,
            { "Lock Type", "zbee_zcl_closures.door_lock.attr.lock_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_door_lock_lock_type_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_door_lock_door_state,
            { "Door State", "zbee_zcl_closures.door_lock.attr.door_state", FT_UINT8, BASE_HEX, VALS(zbee_zcl_door_lock_door_state_values),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_door_lock_actuator_enabled,
            { "Actuator enabled", "zbee_zcl_closures.door_lock.attr.actuator_enabled", FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled),
            0x01, NULL, HFILL } },

        { &hf_zbee_zcl_door_lock_status,
            { "Lock Status", "zbee_zcl_closures.door_lock.status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_status_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_door_lock_srv_rx_cmd_id,
          { "Command", "zbee_zcl_closures.door_lock.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_door_lock_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_door_lock_srv_tx_cmd_id,
          { "Command", "zbee_zcl_closures.door_lock.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_door_lock_srv_tx_cmd_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Door Lock subtrees */
    static gint *ett[ZBEE_ZCL_DOOR_LOCK_NUM_ETT];
    ett[0] = &ett_zbee_zcl_door_lock;

    /* Register the ZigBee ZCL Door Lock cluster protocol name and description */
    proto_zbee_zcl_door_lock = proto_register_protocol("ZigBee ZCL Door Lock", "ZCL Door Lock", ZBEE_PROTOABBREV_ZCL_DOOR_LOCK);
    proto_register_field_array(proto_zbee_zcl_door_lock, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Door Lock dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_DOOR_LOCK, dissect_zbee_zcl_door_lock, proto_zbee_zcl_door_lock);

} /*proto_register_zbee_zcl_door_lock*/


/**
 *Hands off the ZCL Door Lock dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_door_lock(void)
{
    dissector_handle_t door_lock_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    door_lock_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_DOOR_LOCK);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_DOOR_LOCK, door_lock_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_door_lock,
                            ett_zbee_zcl_door_lock,
                            ZBEE_ZCL_CID_DOOR_LOCK,
                            hf_zbee_zcl_door_lock_attr_id,
                            hf_zbee_zcl_door_lock_srv_rx_cmd_id,
                            hf_zbee_zcl_door_lock_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_door_lock_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_door_lock*/

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
