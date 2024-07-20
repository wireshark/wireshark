/* packet-zbee-zcl-sas.c
 * Dissector routines for the ZigBee ZCL Security and Safety Interfaces clusters
 * By Aditya Jain <aditya.jain@samsung.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * https://zigbeealliance.org/wp-content/uploads/2021/10/07-5123-08-Zigbee-Cluster-Library.pdf
 */

/*  Include Files */
#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"


/* ########################################################################## */
/* #### (0x0501) IAS ACE CLUSTER ############################################ */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/
#define ZBEE_ZCL_IAS_ACE_NUM_ETT                               7

/* Attributes - none */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_ARM                     0x00  /* Arm */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_BYPASS                  0x01  /* Bypass */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_EMERGENCY               0x02  /* Emergency */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_FIRE                    0x03  /* Fire */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_PANIC                   0x04  /* Panic */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_ID_MAP         0x05  /* Get Zone ID Map */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_INFO           0x06  /* Get Zone Information */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_GET_PANEL_STATUS        0x07  /* Get Panel Status */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_GET_BYPASSED_ZONE_LIST  0x08  /* Get Bypassed Zone List */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_STATUS         0x09  /* Get Zone Status */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_ARM_RES                 0x00  /* Arm Response */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_ID_MAP_RES     0x01  /* Get Zone ID Map Response */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_INFO_RES       0x02  /* Get Zone Information Response */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_ZONE_STATUS_CHANGED     0x03  /* Zone Status Changed */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_PANEL_STATUS_CHANGED    0x04  /* Panel Status Changed */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_GET_PANEL_STATUS_RES    0x05  /* Get Panel Status Response */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_SET_BYPASSED_ZONE_LIST  0x06  /* Set Bypassed Zone List */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_BYPASS_RES              0x07  /* Bypass Response */
#define ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_STATUS_RES     0x08  /* Get Zone Status Response */


/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_ias_ace(void);
void proto_reg_handoff_zbee_zcl_ias_ace(void);

/* Command Dissector Helpers */
static void dissect_zcl_ias_ace_arm                     (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_bypass                  (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_get_zone_info           (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_get_zone_status         (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_arm_res                 (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_get_zone_id_map_res     (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_get_zone_info_res       (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_zone_status_changed     (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_panel_status_changed    (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_get_panel_status_res    (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_set_bypassed_zone_list  (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_bypassed_res            (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_ace_get_zone_status_res     (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_ias_ace;

static int hf_zbee_zcl_ias_ace_arm_mode;
static int hf_zbee_zcl_ias_ace_no_of_zones;
static int hf_zbee_zcl_ias_ace_zone_id;
static int hf_zbee_zcl_ias_ace_zone_id_list;
static int hf_zbee_zcl_ias_ace_arm_notif;
static int hf_zbee_zcl_ias_ace_zone_id_map_section;
static int hf_zbee_zcl_ias_ace_zone_type;
static int hf_zbee_zcl_ias_ace_ieee_add;
static int hf_zbee_zcl_ias_ace_srv_rx_cmd_id;
static int hf_zbee_zcl_ias_ace_srv_tx_cmd_id;
static int hf_zbee_zcl_ias_ace_starting_zone_id;
static int hf_zbee_zcl_ias_ace_max_number_of_zone_ids;
static int hf_zbee_zcl_ias_ace_zone_status_mask_flag;
static int hf_zbee_zcl_ias_ace_zone_status_mask;
static int hf_zbee_zcl_ias_ace_zone_status;
static int hf_zbee_zcl_ias_ace_zone_audible_notif;
static int hf_zbee_zcl_ias_ace_zone_label;
static int hf_zbee_zcl_ias_ace_panel_status;
static int hf_zbee_zcl_ias_ace_seconds_remaining;
static int hf_zbee_zcl_ias_ace_alarm_status;
static int hf_zbee_zcl_ias_ace_number_of_zones;
static int hf_zbee_zcl_ias_ace_zone_status_complete;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_ias_ace;
static int ett_zbee_zcl_ias_ace_zone_id;
static int ett_zbee_zcl_ias_ace_zone_id_map_sec;
static int ett_zbee_zcl_ias_ace_zone_id_map_sec_elem;
static int ett_zbee_zcl_ias_ace_bypassed_zone_list;
static int ett_zbee_zcl_ias_ace_bypassed_resp_list;
static int ett_zbee_zcl_ias_ace_get_zone_status_resp_list;

/* Server Commands Received */
static const value_string zbee_zcl_ias_ace_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_IAS_ACE_ARM,                    "Arm" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_BYPASS,                 "Bypass" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_EMERGENCY,              "Emergency" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_FIRE,                   "Fire" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_PANIC,                  "Panic" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_ID_MAP,        "Get Zone ID Map" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_INFO,          "Get Zone Information" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_GET_PANEL_STATUS,       "Get Panel Status" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_GET_BYPASSED_ZONE_LIST, "Get Bypassed Zone List" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_STATUS,        "Get Zone Status" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_ias_ace_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_IAS_ACE_ARM_RES,                "Arm Response" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_ID_MAP_RES,    "Get Zone ID Map Response" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_INFO_RES,      "Get Zone Information Response" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_ZONE_STATUS_CHANGED,    "Zone Status Changed" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_PANEL_STATUS_CHANGED,   "Panel Status Changed" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_GET_PANEL_STATUS_RES,   "Get Panel Status Response" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_SET_BYPASSED_ZONE_LIST, "Set Bypassed Zone List" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_BYPASS_RES,             "Bypass Response" },
    { ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_STATUS_RES,    "Get Zone Status Response" },
    { 0, NULL }
};

/* Arm Mode Values */
static const value_string arm_mode_values[] = {
  { 0x00, "Disarm" },
  { 0x01, "Arm Day/Home Zones Only" },
  { 0x02, "Arm Night/Sleep Zones Only" },
  { 0x03, "Arm All Zones" },
  { 0, NULL }
};

/* Arm Notification Values */
static const value_string arm_notif_values[] = {
  { 0x00, "All Zones Disarmed" },
  { 0x01, "Only Day/Home Zones Armed" },
  { 0x02, "Only Night/Sleep Zones Armed" },
  { 0x03, "All Zones Armed" },
  { 0, NULL }
};

/* Audible Notification Values */
static const value_string audible_notif_values[] = {
  { 0x00, "Mute" },
  { 0x01, "Default sound" },
  { 0, NULL }
};

/* Panel Status Values */
static const value_string panel_status_values[] = {
  { 0x00, "Panel disarmed" },
  { 0x01, "Armed stay" },
  { 0x02, "Armed night" },
  { 0x03, "Armed away" },
  { 0x04, "Exit delay" },
  { 0x05, "Entry delay" },
  { 0x06, "Not ready to arm" },
  { 0x07, "In alarm" },
  { 0x08, "Arming Stay" },
  { 0x09, "Arming Night" },
  { 0x0a, "Arming Away" },
  { 0, NULL }
};

/* Panel Status Values */
static const value_string alarm_status_values[] = {
  { 0x00, "No alarm" },
  { 0x01, "Burglar" },
  { 0x02, "Fire" },
  { 0x03, "Emergency" },
  { 0x04, "Police Panic" },
  { 0x05, "Fire Panic" },
  { 0x06, "Emergency Panic" },
  { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL IAS ACE cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_ias_ace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_ias_ace_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_ias_ace, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_IAS_ACE_ARM:
                    dissect_zcl_ias_ace_arm(tvb, payload_tree, &offset);
                    break;
                case ZBEE_ZCL_CMD_ID_IAS_ACE_BYPASS:
                    dissect_zcl_ias_ace_bypass(tvb, payload_tree, &offset);
                    break;
                case ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_INFO:
                    dissect_zcl_ias_ace_get_zone_info(tvb, payload_tree, &offset);
                    break;
                case ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_STATUS:
                    dissect_zcl_ias_ace_get_zone_status(tvb, payload_tree, &offset);
                    break;
                case ZBEE_ZCL_CMD_ID_IAS_ACE_EMERGENCY:
                case ZBEE_ZCL_CMD_ID_IAS_ACE_FIRE:
                case ZBEE_ZCL_CMD_ID_IAS_ACE_PANIC:
                case ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_ID_MAP:
                case ZBEE_ZCL_CMD_ID_IAS_ACE_GET_BYPASSED_ZONE_LIST:
                case ZBEE_ZCL_CMD_ID_IAS_ACE_GET_PANEL_STATUS:
                    /* No Payload */
                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_ias_ace_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_ias_ace, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_IAS_ACE_ARM_RES:
                    dissect_zcl_ias_ace_arm_res(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_ID_MAP_RES:
                    dissect_zcl_ias_ace_get_zone_id_map_res(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_INFO_RES:
                    dissect_zcl_ias_ace_get_zone_info_res(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_IAS_ACE_ZONE_STATUS_CHANGED:
                    dissect_zcl_ias_ace_zone_status_changed(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_IAS_ACE_PANEL_STATUS_CHANGED:
                    dissect_zcl_ias_ace_panel_status_changed(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_IAS_ACE_GET_PANEL_STATUS_RES:
                    dissect_zcl_ias_ace_get_panel_status_res(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_IAS_ACE_SET_BYPASSED_ZONE_LIST:
                    dissect_zcl_ias_ace_set_bypassed_zone_list(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_IAS_ACE_BYPASS_RES:
                    dissect_zcl_ias_ace_bypassed_res(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_IAS_ACE_GET_ZONE_STATUS_RES:
                    dissect_zcl_ias_ace_get_zone_status_res(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_ias_ace*/


/**
 *This function decodes the Arm payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_arm(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Arm Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_arm_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_ias_ace_arm*/


/**
 *This function decodes the Bypass payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_bypass(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_item *zone_id_list = NULL;
    proto_tree *sub_tree = NULL;
    uint8_t num, i;

    /* Retrieve "Number of Zones" field */
    num = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_no_of_zones, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Zone ID" fields */
    zone_id_list = proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_id_list, tvb, *offset, num, ENC_NA);
    sub_tree = proto_item_add_subtree(zone_id_list, ett_zbee_zcl_ias_ace_zone_id);

    for(i = 0; i < num; i++){
        proto_tree_add_item(sub_tree, hf_zbee_zcl_ias_ace_zone_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }
} /*dissect_zcl_ias_ace_bypass*/


/**
 *This function decodes the Get Zone Information payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_get_zone_info(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Zone ID" field */
   proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

} /*dissect_zcl_ias_ace_get_zone_info*/


/**
 *This function decodes the Get Zone Status payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_get_zone_status(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Starting Zone ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_starting_zone_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Max Number of Zone IDs" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_max_number_of_zone_ids, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Zone Status Mask Flag" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_status_mask_flag, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Zone Status Mask" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_status_mask, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_ias_ace_get_zone_status*/


/**
 *This function decodes the Zone Status Changed payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_zone_status_changed(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    int length;

    /* Retrieve "Zone ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Zone Status" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_status, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Audible Notification" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_audible_notif, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Rate Label */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_ias_ace_zone_label, tvb, *offset, 1, ENC_NA | ENC_ZIGBEE, &length);
    *offset += length;

} /*dissect_zcl_ias_ace_zone_status_changed*/


/**
 *This function decodes the Panel Status Changed payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_panel_status_changed(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Panel Status" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_panel_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Seconds Remaining" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_seconds_remaining, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Audible Notification" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_audible_notif, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Alarm Status" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_alarm_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_ias_ace_panel_status_changed*/


/**
 *This function decodes the Get Panel Status Response payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_get_panel_status_res(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Panel Status" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_panel_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Seconds Remaining" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_seconds_remaining, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Audible Notification" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_audible_notif, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Alarm Status" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_alarm_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_ias_ace_get_panel_status_res*/


/**
 *This function decodes the Set Bypassed Zone List payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_set_bypassed_zone_list(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    size_t length = tvb_get_uint8(tvb, *offset);

    /* Retrieve "Number of Zones" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_number_of_zones, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    if (length > 0) {
        proto_tree *subtree;
        subtree = proto_item_add_subtree(tree, ett_zbee_zcl_ias_ace_bypassed_zone_list);

        for (size_t i = 0; i < length; i++) {
            /* Retrieve "Zone ID n" field */
            proto_tree_add_item(subtree, hf_zbee_zcl_ias_ace_zone_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
        }
    }
} /*dissect_zcl_ias_ace_set_bypassed_zone_list*/


/**
 *This function decodes the Set Bypassed Zone List payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_bypassed_res(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    size_t length = tvb_get_uint8(tvb, *offset);

    /* Retrieve "Number of Zones" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_number_of_zones, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    if (length > 0) {
        proto_tree *subtree;
        subtree = proto_item_add_subtree(tree, ett_zbee_zcl_ias_ace_bypassed_resp_list);

        for (size_t i = 0; i < length; i++) {
            /* Retrieve "Bypass Result for Zone ID n" field */
            proto_tree_add_item(subtree, hf_zbee_zcl_ias_ace_zone_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
        }
    }
} /*dissect_zcl_ias_ace_bypassed_res */



/**
 *This function decodes the Set Bypassed Zone List payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_get_zone_status_res(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    size_t length = 0;

    /* Retrieve "Zone Status Complete" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_status_complete, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    length = tvb_get_uint8(tvb, *offset);

    /* Retrieve "Number of Zones" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_number_of_zones, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    if (length > 0) {
        proto_tree *subtree;
        subtree = proto_item_add_subtree(tree, ett_zbee_zcl_ias_ace_get_zone_status_resp_list);

        for (size_t i = 0; i < length; i++) {
            /* Retrieve "Bypass Result for Zone ID n" field */
            proto_tree_add_item(subtree, hf_zbee_zcl_ias_ace_zone_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
        }
    }
} /*dissect_zcl_ias_ace_get_zone_status_res */

/**
 *This function decodes the Arm Response payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_arm_res(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Arm Notification" field */
   proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_arm_notif, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

} /*dissect_zcl_ias_ace_arm_res*/


/**
 *This function decodes the Bypass payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_get_zone_id_map_res(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   uint8_t i;

   /* Retrieve "Zone ID" fields */
   for(i = 0; i < 16; i++){
       proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_id_map_section, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
       *offset += 2;
   }
} /*dissect_zcl_ias_ace_get_zone_id_map_res*/


/**
 *This function decodes the Get Zone Information Response payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_ace_get_zone_info_res(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
   /* Retrieve "Zone ID" field */
   proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
   *offset += 1;

   /* Retrieve "Zone Type" field */
   proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_zone_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
   *offset += 2;

   /* Retrieve "IEEE Address" field */
   proto_tree_add_item(tree, hf_zbee_zcl_ias_ace_ieee_add, tvb, *offset, 8, ENC_NA);
   *offset += 8;

} /*dissect_zcl_ias_ace_get_zone_info_res*/


/**
 *ZigBee ZCL IAS ACE cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_ias_ace(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_ias_ace_arm_mode,
            { "Arm Mode", "zbee_zcl_sas.ias_ace.arm_mode", FT_UINT8, BASE_DEC, VALS(arm_mode_values),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_no_of_zones,
            { "Number of Zones", "zbee_zcl_sas.ias_ace.no_of_zones", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_zone_id,
            { "Zone ID", "zbee_zcl_sas.ias_ace.zone_id", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_zone_id_list,
            { "Zone ID List", "zbee_zcl_sas.ias_ace.zone_id_list", FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_arm_notif,
            { "Arm Notifications", "zbee_zcl_sas.ias_ace.arm_notif", FT_UINT8, BASE_DEC, VALS(arm_notif_values),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_zone_id_map_section,
            { "Zone ID Map Section", "zbee_zcl_sas.ias_ace.zone_id_map_section", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_zone_type,
            { "Zone Type", "zbee_zcl_sas.ias_ace.zone_type", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_ieee_add,
            { "IEEE Address", "zbee_zcl_sas.ias_ace.ieee_add", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_srv_rx_cmd_id,
          { "Command", "zbee_zcl_sas.ias_ace.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ias_ace_srv_rx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_srv_tx_cmd_id,
          { "Command", "zbee_zcl_sas.ias_ace.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ias_ace_srv_tx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_starting_zone_id,
          { "Starting Zone ID", "zbee_zcl_sas.ias_ace.cmd.starting_zone_id", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_max_number_of_zone_ids,
          { "Max Number Of Zone IDs", "zbee_zcl_sas.ias_ace.cmd.max_number_of_zone_ids", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_zone_status_mask_flag,
          { "Zone Status Mask Flag", "zbee_zcl_sas.ias_ace.cmd.zone_status_mask_flag", FT_BOOLEAN, BASE_NONE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_zone_status_mask,
          { "Zone Status Mask", "zbee_zcl_sas.ias_ace.cmd.zone_status_mask", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_zone_status,
          { "Zone Status", "zbee_zcl_sas.ias_ace.cmd.zone_status", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_zone_audible_notif,
          { "Audible Notification", "zbee_zcl_sas.ias_ace.cmd.zone_audible_notif", FT_UINT16, BASE_HEX, VALS(audible_notif_values),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_zone_label,
          { "Zone Label", "zbee_zcl_sas.ias_ace.cmd.zone_label", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_panel_status,
          { "Panel Status", "zbee_zcl_sas.ias_ace.cmd.panel_status", FT_UINT8, BASE_HEX, VALS(panel_status_values),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_seconds_remaining,
          { "Seconds Remaining", "zbee_zcl_sas.ias_ace.cmd.seconds_remaining", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_alarm_status,
          { "Alarm Status", "zbee_zcl_sas.ias_ace.cmd.alarm_status", FT_UINT8, BASE_HEX, VALS(alarm_status_values),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_number_of_zones,
          { "Number of Zones", "zbee_zcl_sas.ias_ace.cmd.number_of_zones", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_ace_zone_status_complete,
          { "Zone Status Complete", "zbee_zcl_sas.ias_ace.cmd.zone_status_complete", FT_BOOLEAN, BASE_NONE, NULL,
            0x0, NULL, HFILL } },
    };

    /* ZCL IAS ACE subtrees */
    static int *ett[ZBEE_ZCL_IAS_ACE_NUM_ETT];
    ett[0] = &ett_zbee_zcl_ias_ace;
    ett[1] = &ett_zbee_zcl_ias_ace_zone_id;
    ett[2] = &ett_zbee_zcl_ias_ace_zone_id_map_sec;
    ett[3] = &ett_zbee_zcl_ias_ace_zone_id_map_sec_elem;
    ett[4] = &ett_zbee_zcl_ias_ace_bypassed_zone_list;
    ett[5] = &ett_zbee_zcl_ias_ace_bypassed_resp_list;
    ett[6] = &ett_zbee_zcl_ias_ace_get_zone_status_resp_list;

    /* Register the ZigBee ZCL IAS ACE cluster protocol name and description */
    proto_zbee_zcl_ias_ace = proto_register_protocol("ZigBee ZCL IAS ACE", "ZCL IAS ACE", ZBEE_PROTOABBREV_ZCL_IAS_ACE);
    proto_register_field_array(proto_zbee_zcl_ias_ace, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL IAS ACE dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_IAS_ACE, dissect_zbee_zcl_ias_ace, proto_zbee_zcl_ias_ace);

} /*proto_register_zbee_zcl_ias_ace*/


/**
 *Hands off the ZCL IAS ACE dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_ias_ace(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_IAS_ACE,
                            proto_zbee_zcl_ias_ace,
                            ett_zbee_zcl_ias_ace,
                            ZBEE_ZCL_CID_IAS_ACE,
                            ZBEE_MFG_CODE_NONE,
                            -1, -1,
                            hf_zbee_zcl_ias_ace_srv_rx_cmd_id,
                            hf_zbee_zcl_ias_ace_srv_tx_cmd_id,
                            NULL
                         );
} /*proto_reg_handoff_zbee_zcl_ias_ace*/


/* ########################################################################## */
/* #### (0x0502) IAS WD CLUSTER ############################################# */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/
#define ZBEE_ZCL_IAS_WD_NUM_ETT                             1
#define ZBEE_ZCL_IAS_WD_WARNING_MODE_MASK                   0xF0
#define ZBEE_ZCL_IAS_WD_STROBE_2BIT_MASK                    0x0C
#define ZBEE_ZCL_IAS_WD_SWQUAWK_MODE_MASK                   0xF0
#define ZBEE_ZCL_IAS_WD_STROBE_1BIT_MASK                    0x08
#define ZBEE_ZCL_IAS_WD_SWQUAWK_LEVEL_MASK                  0x03

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_IAS_WD_MAX_DURATION                0x0000  /* Max Duration */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_IAS_WD_START_WARNING                0x00  /* Start Warning */
#define ZBEE_ZCL_CMD_ID_IAS_WD_SQUAWK                       0x01  /* Squawk */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_ias_wd(void);
void proto_reg_handoff_zbee_zcl_ias_wd(void);

/* Command Dissector Helpers */
static void dissect_zcl_ias_wd_attr_data                (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);
static void dissect_zcl_ias_wd_start_warning            (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_ias_wd_squawk                   (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_ias_wd;

static int hf_zbee_zcl_ias_wd_attr_id;
static int hf_zbee_zcl_ias_wd_warning_mode;
static int hf_zbee_zcl_ias_wd_strobe_2bit;
static int hf_zbee_zcl_ias_wd_squawk_mode;
static int hf_zbee_zcl_ias_wd_strobe_1bit;
static int hf_zbee_zcl_ias_wd_warning_duration;
static int hf_zbee_zcl_ias_wd_squawk_level;
static int hf_zbee_zcl_ias_wd_srv_rx_cmd_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_ias_wd;

/* Attributes */
static const value_string zbee_zcl_ias_wd_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_IAS_WD_MAX_DURATION,                 "Maximum Duration" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_ias_wd_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_IAS_WD_START_WARNING,      "Start Warning" },
    { ZBEE_ZCL_CMD_ID_IAS_WD_SQUAWK,             "Squawk" },
    { 0, NULL }
};

/* Warning Mode Values */
static const value_string warning_mode_values[] = {
  { 0, "Stop (no warning)" },
  { 1, "Burglar" },
  { 2, "Fire" },
  { 3, "Emergency" },
  { 0, NULL }
};

/* Strobe 2-bit Values */
static const value_string strobe_2bit_values[] = {
  { 0, "No Strobe" },
  { 1, "Use strobe in parallel to warning" },
  { 0, NULL }
};

/* Strobe 1-bit Values */
static const value_string strobe_1bit_values[] = {
  { 0, "No Strobe" },
  { 1, "Use strobe blink in parallel to squawk" },
  { 0, NULL }
};

/* Squawk Mode Values */
static const value_string squawk_mode_values[] = {
  { 0, "Notification sound for 'System is armed'" },
  { 1, "Notification sound for 'System is disarmed'" },
  { 0, NULL }
};

/* Squawk Level Values */
static const value_string squawk_level_values[] = {
  { 0, "Low level sound" },
  { 1, "Medium level sound" },
  { 2, "High level sound" },
  { 3, "Very high level sound" },
  { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL IAS WD cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_ias_wd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_ias_wd_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_ias_wd_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check if this command has a payload, then add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_ias_wd, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_IAS_WD_START_WARNING:
                    dissect_zcl_ias_wd_start_warning(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_IAS_WD_SQUAWK:
                    dissect_zcl_ias_wd_squawk(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_ias_wd*/


/**
 *This function decodes the Start Warning payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_wd_start_warning(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Warning Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_wd_warning_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

    /* Retrieve "Strobe" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_wd_strobe_2bit, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Retrieve "Warning Duration" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_wd_warning_duration, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

} /*dissect_zcl_ias_wd_start_warning*/


/**
 *This function decodes the Squawk payload.
 *
 *@param  tvb the tv buffer of the current data_type
 *@param  tree the tree to append this item to
 *@param  offset offset of data in tvb
*/
static void
dissect_zcl_ias_wd_squawk(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Squawk Mode" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_wd_squawk_mode, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

    /* Retrieve "Strobe" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_wd_strobe_1bit, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

    /* Retrieve "Squawk Level" field */
    proto_tree_add_item(tree, hf_zbee_zcl_ias_wd_squawk_level, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_ias_wd_squawk*/


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
dissect_zcl_ias_wd_attr_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {
        case ZBEE_ZCL_ATTR_ID_IAS_WD_MAX_DURATION:
        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_ias_wd_attr_data*/


/**
 *ZigBee ZCL IAS WD cluster protocol registration routine.
 *
*/
void
proto_register_zbee_zcl_ias_wd(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_ias_wd_attr_id,
            { "Attribute", "zbee_zcl_sas.ias_wd.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_ias_wd_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_wd_warning_mode,
            { "Warning Mode", "zbee_zcl_sas.ias_wd.warning_mode", FT_UINT8, BASE_DEC, VALS(warning_mode_values),
            ZBEE_ZCL_IAS_WD_WARNING_MODE_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_ias_wd_strobe_2bit,
            { "Strobe", "zbee_zcl_sas.ias_wd.strobe", FT_UINT8, BASE_DEC, VALS(strobe_2bit_values),
            ZBEE_ZCL_IAS_WD_STROBE_2BIT_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_ias_wd_squawk_mode,
            { "Squawk Mode", "zbee_zcl_sas.ias_wd.squawk_mode", FT_UINT8, BASE_DEC, VALS(squawk_mode_values),
            ZBEE_ZCL_IAS_WD_SWQUAWK_MODE_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_ias_wd_strobe_1bit,
            { "Strobe", "zbee_zcl_sas.ias_wd.strobe", FT_UINT8, BASE_DEC, VALS(strobe_1bit_values),
            ZBEE_ZCL_IAS_WD_STROBE_1BIT_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_ias_wd_warning_duration,
            { "Warning Duration", "zbee_zcl_sas.ias_wd.warning_duration", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_ias_wd_squawk_level,
            { "Squawk Level", "zbee_zcl_sas.ias_wd.squawk_level", FT_UINT8, BASE_DEC, VALS(squawk_level_values),
            ZBEE_ZCL_IAS_WD_SWQUAWK_LEVEL_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_ias_wd_srv_rx_cmd_id,
          { "Command", "zbee_zcl_sas.ias_wd.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ias_wd_srv_rx_cmd_names),
            0x0, NULL, HFILL } }
    };

    /* ZCL IAS WD subtrees */
    static int *ett[ZBEE_ZCL_IAS_WD_NUM_ETT];
    ett[0] = &ett_zbee_zcl_ias_wd;

    /* Register the ZigBee ZCL IAS WD cluster protocol name and description */
    proto_zbee_zcl_ias_wd = proto_register_protocol("ZigBee ZCL IAS WD", "ZCL IAS WD", ZBEE_PROTOABBREV_ZCL_IAS_WD);
    proto_register_field_array(proto_zbee_zcl_ias_wd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL IAS WD dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_IAS_WD, dissect_zbee_zcl_ias_wd, proto_zbee_zcl_ias_wd);

} /*proto_register_zbee_zcl_ias_wd*/


/**
 *Hands off the ZCL IAS WD dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_ias_wd(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_IAS_WD,
                            proto_zbee_zcl_ias_wd,
                            ett_zbee_zcl_ias_wd,
                            ZBEE_ZCL_CID_IAS_WD,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_ias_wd_attr_id,
                            hf_zbee_zcl_ias_wd_attr_id,
                            hf_zbee_zcl_ias_wd_srv_rx_cmd_id,
                            -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_ias_wd_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_ias_wd*/

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
