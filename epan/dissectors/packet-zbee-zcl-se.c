/* packet-zbee-zcl-se.c
 * Dissector routines for the ZigBee ZCL SE clusters like
 * Messaging
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


#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/to_str.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"
#include "packet-zbee-security.h"

/* ########################################################################## */
/* #### common to all SE clusters ########################################### */
/* ########################################################################## */

#define ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS            0xFFFE
#define ZBEE_ZCL_SE_ATTR_REPORT_PENDING                     0x00
#define ZBEE_ZCL_SE_ATTR_REPORT_COMPLETE                    0x01

static const value_string zbee_zcl_se_reporting_status_names[] = {
    { ZBEE_ZCL_SE_ATTR_REPORT_PENDING,                   "Pending" },
    { ZBEE_ZCL_SE_ATTR_REPORT_COMPLETE,                  "Complete" },
    { 0, NULL }
};

#define ZBEE_ZCL_SE_ATTR_NAMES \
    { ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS,            "Attribute Reporting Status" }

/*************************/
/* Global Variables      */
/*************************/

/* ########################################################################## */
/* #### (0x0703) MESSAGING CLUSTER ########################################## */
/* ########################################################################## */

/* Attributes - None (other than Attribute Reporting Status) */
static const value_string zbee_zcl_msg_attr_names[] = {
    ZBEE_ZCL_SE_ATTR_NAMES,
    { 0, NULL }
};

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_MSG_GET_LAST_MSG                0x00  /* Get Last Message */
#define ZBEE_ZCL_CMD_ID_MSG_MSG_CONFIRM                 0x01  /* Message Confirmation */
#define ZBEE_ZCL_CMD_ID_MSG_GET_MESSAGE_CANCEL          0x02  /* Get Message Cancellation */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_MSG_DISPLAY_MSG                 0x00  /* Display Message */
#define ZBEE_ZCL_CMD_ID_MSG_CANCEL_MSG                  0x01  /* Cancel Message */
#define ZBEE_ZCL_CMD_ID_MSG_DISPLAY_PROTECTED_MSG       0x02  /* Display Protected Message */
#define ZBEE_ZCL_CMD_ID_MSG_CANCEL_ALL_MSG              0x03  /* Cancel All Messages */

/* Message Control Field Bit Map */
#define ZBEE_ZCL_MSG_CTRL_TX_MASK                       0x03
#define ZBEE_ZCL_MSG_CTRL_IMPORTANCE_MASK               0x0C
#define ZBEE_ZCL_MSG_CTRL_RESERVED_MASK                 0x50
#define ZBEE_ZCL_MSG_CTRL_ENHANCED_CONFIRM_MASK         0x20
#define ZBEE_ZCL_MSG_CTRL_CONFIRM_MASK                  0x80

#define ZBEE_ZCL_MSG_CTRL_TX_NORMAL_ONLY                0x00 /* Normal Transmission Only */
#define ZBEE_ZCL_MSG_CTRL_TX_NORMAL_ANON_INTERPAN       0x01 /* Normal and Anonymous Inter-PAN Transmission Only */
#define ZBEE_ZCL_MSG_CTRL_TX_ANON_INTERPAN_ONLY         0x02 /* Anonymous Inter-PAN Transmission Only */

#define ZBEE_ZCL_MSG_CTRL_IMPORTANCE_LOW                0x00 /* Low */
#define ZBEE_ZCL_MSG_CTRL_IMPORTANCE_MEDIUM             0x01 /* Medium */
#define ZBEE_ZCL_MSG_CTRL_IMPORTANCE_HIGH               0x02 /* High */
#define ZBEE_ZCL_MSG_CTRL_IMPORTANCE_CRITICAL           0x03 /* Critical */

#define ZBEE_ZCL_MSG_EXT_CTRL_STATUS_MASK               0x01

#define ZBEE_ZCL_MSG_CONFIRM_CTRL_MASK                  0x01

#define ZBEE_ZCL_MSG_START_TIME_NOW                     0x00000000 /* Now */

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_msg(void);
void proto_reg_handoff_zbee_zcl_msg(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_msg_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Command Dissector Helpers */
static void dissect_zcl_msg_display             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_msg_cancel              (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_msg_confirm             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_msg_cancel_all          (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_msg_get_cancel          (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/* Private functions prototype */
static void decode_zcl_msg_duration             (gchar *s, guint16 value);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_msg = -1;

static int hf_zbee_zcl_msg_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_msg_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_msg_attr_id = -1;
static int hf_zbee_zcl_msg_attr_reporting_status = -1;
static int hf_zbee_zcl_msg_message_id = -1;
static int hf_zbee_zcl_msg_ctrl = -1;
static int hf_zbee_zcl_msg_ctrl_tx = -1;
static int hf_zbee_zcl_msg_ctrl_importance = -1;
static int hf_zbee_zcl_msg_ctrl_enh_confirm = -1;
static int hf_zbee_zcl_msg_ctrl_reserved = -1;
static int hf_zbee_zcl_msg_ctrl_confirm = -1;
static int hf_zbee_zcl_msg_ext_ctrl = -1;
static int hf_zbee_zcl_msg_ext_ctrl_status = -1;
static int hf_zbee_zcl_msg_start_time = -1;
static int hf_zbee_zcl_msg_duration = -1;
static int hf_zbee_zcl_msg_message_length = - 1;
static int hf_zbee_zcl_msg_message = -1;
static int hf_zbee_zcl_msg_confirm_time = -1;
static int hf_zbee_zcl_msg_confirm_ctrl = -1;
static int hf_zbee_zcl_msg_confirm_response = -1;
static int hf_zbee_zcl_msg_confirm_response_length = - 1;
static int hf_zbee_zcl_msg_implementation_time = -1;
static int hf_zbee_zcl_msg_earliest_time = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_msg = -1;
static gint ett_zbee_zcl_msg_message_control = -1;
static gint ett_zbee_zcl_msg_ext_message_control = -1;

static expert_field ei_zbee_zcl_msg_msg_ctrl_depreciated = EI_INIT;

/* Server Commands Received */
static const value_string zbee_zcl_msg_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_MSG_GET_LAST_MSG,                 "Get Last Message" },
    { ZBEE_ZCL_CMD_ID_MSG_MSG_CONFIRM,                  "Message Confirmation" },
    { ZBEE_ZCL_CMD_ID_MSG_GET_MESSAGE_CANCEL,           "Get Message Cancellation" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_msg_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_MSG_DISPLAY_MSG,                  "Display Message" },
    { ZBEE_ZCL_CMD_ID_MSG_CANCEL_MSG,                   "Cancel Message" },
    { ZBEE_ZCL_CMD_ID_MSG_DISPLAY_PROTECTED_MSG,        "Display Protected Message"},
    { ZBEE_ZCL_CMD_ID_MSG_CANCEL_ALL_MSG,               "Cancel All Messages" },
    { 0, NULL }
};

/* Message Control Transmission */
static const value_string zbee_zcl_msg_ctrl_tx_names[] = {
    { ZBEE_ZCL_MSG_CTRL_TX_NORMAL_ONLY,                 "Normal Transmission Only" },
    { ZBEE_ZCL_MSG_CTRL_TX_NORMAL_ANON_INTERPAN,        "Normal and Anonymous Inter-PAN Transmission Only" },
    { ZBEE_ZCL_MSG_CTRL_TX_ANON_INTERPAN_ONLY,          "Anonymous Inter-PAN Transmission Only" },
    { 0, NULL }
};

/* Message Control Importance */
static const value_string zbee_zcl_msg_ctrl_importance_names[] = {
    { ZBEE_ZCL_MSG_CTRL_IMPORTANCE_LOW,                 "Low" },
    { ZBEE_ZCL_MSG_CTRL_IMPORTANCE_MEDIUM,              "Medium" },
    { ZBEE_ZCL_MSG_CTRL_IMPORTANCE_HIGH,                "High" },
    { ZBEE_ZCL_MSG_CTRL_IMPORTANCE_CRITICAL,            "Critical" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

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
dissect_zcl_msg_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    switch (attr_id) {
        /* no cluster specific attributes */

        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS:
            proto_tree_add_item(tree, hf_zbee_zcl_msg_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_ias_zone_attr_data*/

/**
 *ZigBee ZCL Messaging cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_msg_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_msg_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_msg, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_MSG_GET_LAST_MSG:
                    /* No payload */
                    break;

                case ZBEE_ZCL_CMD_ID_MSG_MSG_CONFIRM:
                    dissect_zcl_msg_confirm(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MSG_GET_MESSAGE_CANCEL:
                    dissect_zcl_msg_get_cancel(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_msg_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_msg_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_msg, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_MSG_DISPLAY_MSG:
                    dissect_zcl_msg_display(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MSG_CANCEL_MSG:
                    dissect_zcl_msg_cancel(tvb, pinfo, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MSG_DISPLAY_PROTECTED_MSG:
                    dissect_zcl_msg_display(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MSG_CANCEL_ALL_MSG:
                    dissect_zcl_msg_cancel_all(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_msg*/

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_msg_display(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint   msg_len;
    guint8 *msg_data;

    static const int * message_ctrl_flags[] = {
        &hf_zbee_zcl_msg_ctrl_tx,
        &hf_zbee_zcl_msg_ctrl_importance,
        &hf_zbee_zcl_msg_ctrl_enh_confirm,
        &hf_zbee_zcl_msg_ctrl_reserved,
        &hf_zbee_zcl_msg_ctrl_confirm,
        NULL
    };

    static const int * message_ext_ctrl_flags[] = {
        &hf_zbee_zcl_msg_ext_ctrl_status,
        NULL
    };

    /* Message ID */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_message_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Message Control */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_msg_ctrl, ett_zbee_zcl_msg_message_control, message_ctrl_flags, ENC_NA);
    *offset += 1;

    /* Start Time */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_start_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Duration In Minutes*/
    proto_tree_add_item(tree, hf_zbee_zcl_msg_duration, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Message Length */
    msg_len = tvb_get_guint8(tvb, *offset); /* string length */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_message_length, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Message */
    msg_data = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, msg_len, ENC_LITTLE_ENDIAN);
    proto_tree_add_string(tree, hf_zbee_zcl_msg_message, tvb, *offset, msg_len, msg_data);
    *offset += msg_len;

    /* (Optional) Extended Message Control */
    if (tvb_reported_length_remaining(tvb, *offset) > 0) {
        proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_msg_ext_ctrl, ett_zbee_zcl_msg_ext_message_control, message_ext_ctrl_flags, ENC_NA);
        *offset += 1;
    }

} /*dissect_zcl_msg_display*/

/**
 *This function manages the Cancel Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_msg_cancel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
    gint8 msg_ctrl;

    /* Message ID */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_message_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Message Control */
    msg_ctrl = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_msg_ctrl, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    if (msg_ctrl != 0x00) {
       expert_add_info(pinfo, tree, &ei_zbee_zcl_msg_msg_ctrl_depreciated);
    }

} /* dissect_zcl_msg_cancel */


/**
 *Send Cancel All command
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_msg_cancel_all(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t impl_time;

    /* Retrieve "Confirmation Time" field */
    impl_time.secs = tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    impl_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_msg_implementation_time, tvb, *offset, 4, &impl_time);
    *offset += 4;

} /* dissect_zcl_msg_cancel_all */

/**
 *Send Cancel All command
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_msg_get_cancel(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t impl_time;

    /* Earliest Implementation Time */
    impl_time.secs = tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    impl_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_msg_earliest_time, tvb, *offset, 4, &impl_time);
    *offset += 4;

} /* dissect_zcl_msg_get_cancel */


/**
 *This function manages the Message Confirmation payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_msg_confirm(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint   msg_len;
    guint8 *msg_data;
    nstime_t confirm_time;

    /* Retrieve "Message ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_message_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve "Confirmation Time" field */
    confirm_time.secs = tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    confirm_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_msg_confirm_time, tvb, *offset, 4, &confirm_time);
    *offset += 4;

    /* (Optional) Confirm Control */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_msg_confirm_ctrl, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Response Text Length */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    msg_len = tvb_get_guint8(tvb, *offset); /* string length */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_confirm_response_length, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Response Text, but is we have a length we expect to find the subsequent string */
    if (msg_len > 0) {
        msg_data = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, msg_len, ENC_LITTLE_ENDIAN);
        proto_tree_add_string(tree, hf_zbee_zcl_msg_confirm_response, tvb, *offset, msg_len, msg_data);
        *offset += msg_len;
    }

} /* dissect_zcl_msg_confirm */

/**
 *This function decodes duration in minute type variable
 *
*/
static void
decode_zcl_msg_duration(gchar *s, guint16 value)
{
    if (value == 0xffff)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Until changed");
    else
        g_snprintf(s, ITEM_LABEL_LENGTH, "%d minutes", value);
    return;
} /*decode_zcl_msg_duration*/

/**
 *This function decodes start time, with peculiarity case for
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_zcl_msg_start_time(gchar *s, guint32 value)
{
    if (value == ZBEE_ZCL_MSG_START_TIME_NOW)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Now");
    else {
        gchar *start_time;
        value += ZBEE_ZCL_NSTIME_UTC_OFFSET;
        start_time = abs_time_secs_to_str (NULL, value, ABSOLUTE_TIME_LOCAL, TRUE);
        g_snprintf(s, ITEM_LABEL_LENGTH, "%s", start_time);
        wmem_free(NULL, start_time);
    }
} /* decode_zcl_msg_start_time */

/**
 *This function registers the ZCL Messaging dissector
 *
*/
void
proto_register_zbee_zcl_msg(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_msg_attr_id,
            { "Attribute", "zbee_zcl_se.msg.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_msg_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_msg_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.msg.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.msg.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_msg_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.msg.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_msg_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_message_id,
            { "Message ID", "zbee_zcl_se.msg.message.id", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

/* Start of 'Message Control' fields */
        { &hf_zbee_zcl_msg_ctrl,
            { "Message Control", "zbee_zcl_se.msg.message.ctrl", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_msg_ctrl_tx,
            { "Transmission", "zbee_zcl_se.msg.message.ctrl.tx", FT_UINT8, BASE_HEX, VALS(zbee_zcl_msg_ctrl_tx_names),
            ZBEE_ZCL_MSG_CTRL_TX_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_msg_ctrl_importance,
            { "Importance", "zbee_zcl_se.msg.message.ctrl.importance", FT_UINT8, BASE_HEX, VALS(zbee_zcl_msg_ctrl_importance_names),
            ZBEE_ZCL_MSG_CTRL_IMPORTANCE_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_msg_ctrl_enh_confirm,
            { "Confirmation", "zbee_zcl_se.msg.message.ctrl.enhconfirm", FT_BOOLEAN, 8, TFS(&tfs_required_not_required),
            ZBEE_ZCL_MSG_CTRL_ENHANCED_CONFIRM_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_msg_ctrl_reserved,
            { "Reserved", "zbee_zcl_se.msg.message.ctrl.reserved", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_MSG_CTRL_RESERVED_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_msg_ctrl_confirm,
            { "Confirmation", "zbee_zcl_se.msg.message.ctrl.confirm", FT_BOOLEAN, 8, TFS(&tfs_required_not_required),
            ZBEE_ZCL_MSG_CTRL_CONFIRM_MASK, NULL, HFILL } },
/* End of 'Message Control' fields */

/* Start of 'Extended Message Control' fields */
        { &hf_zbee_zcl_msg_ext_ctrl,
            { "Extended Message Control", "zbee_zcl_se.msg.message.ext.ctrl", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_msg_ext_ctrl_status,
            { "Message Confirmation Status", "zbee_zcl_se.msg.message.ext.ctrl.status", FT_BOOLEAN, 8, TFS(&tfs_confirmed_unconfirmed),
            ZBEE_ZCL_MSG_EXT_CTRL_STATUS_MASK, NULL, HFILL } },
/* End of 'Extended Message Control' fields */

        { &hf_zbee_zcl_msg_start_time,
            { "Start Time", "zbee_zcl_se.msg.message.start_time", FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_zcl_msg_start_time),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_duration,
            { "Duration", "zbee_zcl_se.msg.message.duration", FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zcl_msg_duration),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_message_length,
            { "Message Length", "zbee_zcl_se.msg.message.length", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_message,
            { "Message", "zbee_zcl_se.msg.message", FT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_confirm_time,
            { "Confirmation Time", "zbee_zcl_se.msg.message.confirm_time",  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_msg_confirm_ctrl,
            { "Confirmation Control", "zbee_zcl_se.msg.message.confirm.ctrl", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_MSG_CONFIRM_CTRL_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_msg_confirm_response_length,
            { "Response Length", "zbee_zcl_se.msg.message.length", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_confirm_response,
            { "Response", "zbee_zcl_se.msg.message", FT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_implementation_time,
            { "Implementation Time", "zbee_zcl_se.msg.impl_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_msg_earliest_time,
            { "Earliest Implementation Time", "zbee_zcl_se.msg.earliest_impl_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0, NULL, HFILL } },

    };

    /* ZCL Messaging subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_msg,
        &ett_zbee_zcl_msg_message_control,
        &ett_zbee_zcl_msg_ext_message_control,
    };

    /* Expert Info */
    expert_module_t* expert_zbee_zcl_msg;
    static ei_register_info ei[] = {
        { &ei_zbee_zcl_msg_msg_ctrl_depreciated, { "zbee_zcl_se.msg.msg_ctrl.depreciated", PI_PROTOCOL, PI_WARN, "Message Control depreciated in this message, should be 0x00", EXPFILL }},
    };

    /* Register the ZigBee ZCL Messaging cluster protocol name and description */
    proto_zbee_zcl_msg = proto_register_protocol("ZigBee ZCL Messaging", "ZCL Messaging", ZBEE_PROTOABBREV_ZCL_MSG);
    proto_register_field_array(proto_zbee_zcl_msg, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_zbee_zcl_msg = expert_register_protocol(proto_zbee_zcl_msg);
    expert_register_field_array(expert_zbee_zcl_msg, ei, array_length(ei));

    /* Register the ZigBee ZCL Messaging dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_MSG, dissect_zbee_zcl_msg, proto_zbee_zcl_msg);
} /*proto_register_zbee_zcl_msg*/

/**
 *Hands off the Zcl Messaging dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_msg(void)
{
    dissector_handle_t msg_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    msg_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_MSG);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_MESSAGE, msg_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_msg,
                            ett_zbee_zcl_msg,
                            ZBEE_ZCL_CID_MESSAGE,
                            hf_zbee_zcl_msg_attr_id,
                            hf_zbee_zcl_msg_srv_rx_cmd_id,
                            hf_zbee_zcl_msg_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_msg_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_msg*/

/* ########################################################################## */
/* #### (0x0704) TUNNELING CLUSTER ########################################### */
/* ########################################################################## */

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_TUN_CLOSE_TIMEOUT             0x0000   /* Close Tunnel Timeout */

static const value_string zbee_zcl_tun_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_TUN_CLOSE_TIMEOUT,      "Close Tunnel Timeout" },
    ZBEE_ZCL_SE_ATTR_NAMES,
    { 0, NULL }
};

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_TUN_REQUEST_TUNNEL                       0x00  /* Request Tunnel */
#define ZBEE_ZCL_CMD_ID_TUN_CLOSE_TUNNEL                         0x01  /* Close Tunnel */
#define ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA                        0x02  /* Transfer Data */
#define ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_ERROR                  0x03  /* Transfer Data Error */
#define ZBEE_ZCL_CMD_ID_TUN_ACK_TRANSFER_DATA                    0x04  /* Ack Transfer Data */
#define ZBEE_ZCL_CMD_ID_TUN_READY_DATA                           0x05  /* Ready Data */
#define ZBEE_ZCL_CMD_ID_TUN_GET_SUPPORTED_PROTOCOLS              0x06  /* Get Supported Tunnel Protocols */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_TUN_REQUEST_TUNNEL_RSP                   0x00  /* Request Tunnel Response*/
#define ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_TX                     0x01  /* Transfer Data */
#define ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_ERROR_TX               0x02  /* Transfer Data Error */
#define ZBEE_ZCL_CMD_ID_TUN_ACK_TRANSFER_DATA_TX                 0x03  /* Ack Transfer Data */
#define ZBEE_ZCL_CMD_ID_TUN_READY_DATA_TX                        0x04  /* Ready Data */
#define ZBEE_ZCL_CMD_ID_TUN_GET_SUPPORTED_PROTOCOLS_RSP          0x05  /* Get Supported Tunnel Protocols */
#define ZBEE_ZCL_CMD_ID_TUN_CLOSURE_NOTIFY                       0x06  /* Tunnel Closure Notification */

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_tun(void);
void proto_reg_handoff_zbee_zcl_tun(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_tun_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_tun = -1;

static int hf_zbee_zcl_tun_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_tun_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_tun_attr_id = -1;
static int hf_zbee_zcl_tun_attr_reporting_status = -1;
static int hf_zbee_zcl_tun_attr_close_timeout = -1;
static int hf_zbee_zcl_tun_protocol_id = -1;
static int hf_zbee_zcl_tun_manufacturer_code = -1;
static int hf_zbee_zcl_tun_flow_control_support = -1;
static int hf_zbee_zcl_tun_max_in_size = -1;
static int hf_zbee_zcl_tun_tunnel_id = -1;
static int hf_zbee_zcl_tun_num_octets_left = -1;
static int hf_zbee_zcl_tun_protocol_offset = -1;
static int hf_zbee_zcl_tun_protocol_list_complete = -1;
static int hf_zbee_zcl_tun_protocol_count = -1;
static int hf_zbee_zcl_tun_transfer_status = -1;
static int hf_zbee_zcl_tun_transfer_data = -1;
static int hf_zbee_zcl_tun_transfer_data_status = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_tun = -1;

/* Subdissector handles. */
static dissector_handle_t       ipv4_handle;
static dissector_handle_t       ipv6_handle;

/* Server Commands Received */
static const value_string zbee_zcl_tun_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_TUN_REQUEST_TUNNEL,                 "Request Tunnel" },
    { ZBEE_ZCL_CMD_ID_TUN_CLOSE_TUNNEL,                   "Close Tunnel" },
    { ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA,                  "Transfer Data" },
    { ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_ERROR,            "Transfer Data Error" },
    { ZBEE_ZCL_CMD_ID_TUN_ACK_TRANSFER_DATA,              "Ack Transfer Data" },
    { ZBEE_ZCL_CMD_ID_TUN_READY_DATA,                     "Ready Data" },
    { ZBEE_ZCL_CMD_ID_TUN_GET_SUPPORTED_PROTOCOLS,        "Get Supported Protocols" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_tun_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_TUN_REQUEST_TUNNEL_RSP,             "Request Tunnel Response" },
    { ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_TX,               "Transfer Data" },
    { ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_ERROR_TX,         "Transfer Data Error" },
    { ZBEE_ZCL_CMD_ID_TUN_ACK_TRANSFER_DATA_TX,           "Ack Transfer Data" },
    { ZBEE_ZCL_CMD_ID_TUN_READY_DATA_TX,                  "Ready Data" },
    { ZBEE_ZCL_CMD_ID_TUN_GET_SUPPORTED_PROTOCOLS_RSP,    "Get Supported Tunnel Protocols" },
    { ZBEE_ZCL_CMD_ID_TUN_CLOSURE_NOTIFY,                 "Tunnel Closure Notification" },
    { 0, NULL }
};

#define ZBEE_ZCL_TUN_PROTO_DLMS                    0x00
#define ZBEE_ZCL_TUN_PROTO_IEC_61107               0x01
#define ZBEE_ZCL_TUN_PROTO_ANSI_C12                0x02
#define ZBEE_ZCL_TUN_PROTO_M_BUS                   0x03
#define ZBEE_ZCL_TUN_PROTO_SML                     0x04
#define ZBEE_ZCL_TUN_PROTO_CLIMATE_TALK            0x05
#define ZBEE_ZCL_TUN_PROTO_GB_HRGP                 0x06
#define ZBEE_ZCL_TUN_PROTO_IPV6                    0x07
#define ZBEE_ZCL_TUN_PROTO_IPV4                    0x08
#define ZBEE_ZCL_TUN_PROTO_NULL                    0x09
#define ZBEE_ZCL_TUN_PROTO_TEST                     199
#define ZBEE_ZCL_TUN_PROTO_MANUFACTURER             200
#define ZBEE_ZCL_TUN_PROTO_RESERVED                0xFF

static const value_string zbee_zcl_tun_protocol_names[] = {
    { ZBEE_ZCL_TUN_PROTO_DLMS,            "DLMS/COSEM (IEC 62056)" },
    { ZBEE_ZCL_TUN_PROTO_IEC_61107,       "IEC 61107" },
    { ZBEE_ZCL_TUN_PROTO_ANSI_C12,        "ANSI C12" },
    { ZBEE_ZCL_TUN_PROTO_M_BUS,           "M-BUS" },
    { ZBEE_ZCL_TUN_PROTO_SML,             "SML" },
    { ZBEE_ZCL_TUN_PROTO_CLIMATE_TALK,    "ClimateTalk" },
    { ZBEE_ZCL_TUN_PROTO_GB_HRGP,         "GB-HRGP" },
    { ZBEE_ZCL_TUN_PROTO_IPV6,            "IPv6" },
    { ZBEE_ZCL_TUN_PROTO_IPV4,            "IPv4" },
    { ZBEE_ZCL_TUN_PROTO_NULL,            "null" },
    { ZBEE_ZCL_TUN_PROTO_TEST,            "test" },
    { ZBEE_ZCL_TUN_PROTO_MANUFACTURER,    "Manufacturer Specific" },
    { ZBEE_ZCL_TUN_PROTO_RESERVED,        "Reserved" },
    { 0, NULL }
};

#define ZBEE_ZCL_TUN_TRANS_STATUS_NO_TUNNEL               0x00
#define ZBEE_ZCL_TUN_TRANS_STATUS_WRONG_DEV               0x01
#define ZBEE_ZCL_TUN_TRANS_STATUS_OVERFLOW                0x02

static const value_string zbee_zcl_tun_trans_data_status_names[] = {
    { ZBEE_ZCL_TUN_TRANS_STATUS_NO_TUNNEL,        "Tunnel ID Does Not Exist" },
    { ZBEE_ZCL_TUN_TRANS_STATUS_WRONG_DEV,        "Wrong Device" },
    { ZBEE_ZCL_TUN_TRANS_STATUS_OVERFLOW,         "Data Overflow" },
    { 0, NULL }
};

#define ZBEE_ZCL_TUN_STATUS_SUCCESS                       0x00
#define ZBEE_ZCL_TUN_STATUS_BUSY                          0x01
#define ZBEE_ZCL_TUN_STATUS_NO_MORE_IDS                   0x02
#define ZBEE_ZCL_TUN_STATUS_PROTO_NOT_SUPP                0x03
#define ZBEE_ZCL_TUN_STATUS_FLOW_CONTROL_NOT_SUPP         0x04

static const value_string zbee_zcl_tun_status_names[] = {
    { ZBEE_ZCL_TUN_STATUS_SUCCESS,                "Success" },
    { ZBEE_ZCL_TUN_STATUS_BUSY,                   "Busy" },
    { ZBEE_ZCL_TUN_STATUS_NO_MORE_IDS,            "No More Tunnel IDs" },
    { ZBEE_ZCL_TUN_STATUS_PROTO_NOT_SUPP,         "Protocol Not Supported" },
    { ZBEE_ZCL_TUN_STATUS_FLOW_CONTROL_NOT_SUPP,  "Flow Control Not Supported" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

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
dissect_zcl_tun_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    switch (attr_id) {
        /* cluster specific attributes */
        case ZBEE_ZCL_ATTR_ID_TUN_CLOSE_TIMEOUT:
            proto_tree_add_item(tree, hf_zbee_zcl_tun_attr_close_timeout, tvb, *offset, 2, ENC_NA);
            *offset += 2;
            break;

        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS:
            proto_tree_add_item(tree, hf_zbee_zcl_tun_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_ias_zone_attr_data*/

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_request_tunnel(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_tun_protocol_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_flow_control_support, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_max_in_size, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
}

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_close_tunnel(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_tun_tunnel_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
}

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_transfer_data(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    gint length;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_tunnel_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    length = tvb_reported_length_remaining(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_tun_transfer_data, tvb, *offset, length, ENC_NA);
    *offset += length;
}

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_transfer_data_error(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_tun_tunnel_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_transfer_data_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_ack_transfer_data(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_tun_tunnel_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_num_octets_left, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
}

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_ready_data(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_tun_tunnel_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_num_octets_left, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
}

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_get_supported(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_tun_protocol_offset, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
}

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_request_tunnel_rsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_tun_tunnel_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_transfer_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_max_in_size, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
}

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_get_supported_rsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint16     mfg_code;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_protocol_list_complete, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_tun_protocol_count, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    while (tvb_reported_length_remaining(tvb, *offset) > 0) {
        mfg_code = tvb_get_letohs(tvb, *offset);
        if (mfg_code == 0xFFFF) {
            proto_tree_add_string(tree, hf_zbee_zcl_tun_manufacturer_code, tvb, *offset, 2, "Standard Protocol (Mfg Code 0xFFFF)");
        }
        else {
            proto_tree_add_item(tree, hf_zbee_zcl_tun_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        }
        *offset += 2;

        proto_tree_add_item(tree, hf_zbee_zcl_tun_protocol_id, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }
}

/**
 *This function manages the Display Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_closure_notify(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_tun_tunnel_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
}

/**
 *ZigBee ZCL Messaging cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_tun(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_tun_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_tun_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_tun, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_TUN_REQUEST_TUNNEL:
                    dissect_zcl_tun_request_tunnel(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_CLOSE_TUNNEL:
                    dissect_zcl_tun_close_tunnel(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA:
                    dissect_zcl_tun_transfer_data(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_ERROR:
                    dissect_zcl_tun_transfer_data_error(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_ACK_TRANSFER_DATA:
                    dissect_zcl_tun_ack_transfer_data(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_READY_DATA:
                    dissect_zcl_tun_ready_data(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_GET_SUPPORTED_PROTOCOLS:
                    dissect_zcl_tun_get_supported(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_tun_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_tun_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_tun, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_TUN_REQUEST_TUNNEL_RSP:
                    dissect_zcl_tun_request_tunnel_rsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_TX:
                    dissect_zcl_tun_transfer_data(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_ERROR_TX:
                    dissect_zcl_tun_transfer_data_error(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_ACK_TRANSFER_DATA_TX:
                    dissect_zcl_tun_ack_transfer_data(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_READY_DATA_TX:
                    dissect_zcl_tun_ready_data(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_GET_SUPPORTED_PROTOCOLS_RSP:
                    dissect_zcl_tun_get_supported_rsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_TUN_CLOSURE_NOTIFY:
                    dissect_zcl_tun_closure_notify(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_tun*/

/**
 *This function registers the ZCL Messaging dissector
 *
*/
void
proto_register_zbee_zcl_tun(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_tun_attr_id,
            { "Attribute", "zbee_zcl_se.tun.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_tun_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_tun_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.tun.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_attr_close_timeout,
            { "Close Tunnel Timeout", "zbee_zcl_se.tun.attr.close_tunnel", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_tun_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.tun.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_tun_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.tun.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_tun_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_protocol_id,
            { "Protocol ID", "zbee_zcl_se.tun.protocol_id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_tun_protocol_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_manufacturer_code,
            { "Manufacturer Code", "zbee_zcl_se.tun.manufacturer_code", FT_UINT16, BASE_HEX, VALS(zbee_mfr_code_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_flow_control_support,
            { "Flow Control Supported", "zbee_zcl_se.tun.flow_control_supported", FT_BOOLEAN, 8, TFS(&tfs_true_false),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_max_in_size,
            { "Max Incoming Transfer Size", "zbee_zcl_se.tun.max_in_transfer_size", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_tunnel_id,
            { "Tunnel Id", "zbee_zcl_se.tun.tunnel_id", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_num_octets_left,
            { "Num Octets Left", "zbee_zcl_se.tun.octets_left", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_protocol_offset,
            { "Protocol Offset", "zbee_zcl_se.tun.protocol_offset", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_transfer_status,
            { "Transfer Status", "zbee_zcl_se.tun.transfer_status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_tun_status_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_transfer_data,
            { "Transfer Data", "zbee_zcl_se.tun.transfer_data", FT_BYTES, BASE_NONE, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_tun_transfer_data_status,
            { "Transfer Data Status", "zbee_zcl_se.tun.transfer_data_status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_tun_trans_data_status_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_protocol_count,
            { "Protocol Count", "zbee_zcl_se.tun.protocol_count", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_tun_protocol_list_complete,
            { "List Complete", "zbee_zcl_se.tun.protocol_list_complete", FT_BOOLEAN, 8, TFS(&tfs_true_false),
            0x00, NULL, HFILL } },

    };

    /* ZCL Messaging subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_tun,
    };

    /* Register the ZigBee ZCL Messaging cluster protocol name and description */
    proto_zbee_zcl_tun = proto_register_protocol("ZigBee ZCL Tunneling", "ZCL Tunneling", ZBEE_PROTOABBREV_ZCL_TUN);
    proto_register_field_array(proto_zbee_zcl_tun, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Messaging dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_TUN, dissect_zbee_zcl_tun, proto_zbee_zcl_tun);

} /* proto_register_zbee_zcl_tun */

/**
 *Hands off the Zcl Messaging dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_tun(void)
{
    dissector_handle_t msg_handle;

    ipv4_handle = find_dissector("ipv4");
    ipv6_handle = find_dissector("ipv6");

    /* Register our dissector with the ZigBee application dissectors. */
    msg_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_TUN);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_TUNNELING, msg_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_tun,
                            ett_zbee_zcl_tun,
                            ZBEE_ZCL_CID_TUNNELING,
                            hf_zbee_zcl_tun_attr_id,
                            hf_zbee_zcl_tun_srv_rx_cmd_id,
                            hf_zbee_zcl_tun_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_tun_attr_data
                         );
} /* proto_reg_handoff_zbee_zcl_tun */

/* ########################################################################## */
/* #### (0x0800) KEY ESTABLISHMENT ########################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_ke = -1;
static gint ett_zbee_zcl_ke_cert = -1;
static gint ett_zbee_zcl_ke_key_usage = -1;

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_KE_SUITE                     0x0000  /* Key Establishment Suite */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_ke(void);
void proto_reg_handoff_zbee_zcl_ke(void);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_ke = -1;
static int hf_zbee_zcl_ke_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_ke_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_ke_attr_id = -1;
static int hf_zbee_zcl_ke_suite = -1;
static int hf_zbee_zcl_ke_ephemeral_time = -1;
static int hf_zbee_zcl_ke_confirm_time = -1;
static int hf_zbee_zcl_ke_status = -1;
static int hf_zbee_zcl_ke_wait_time = -1;
static int hf_zbee_zcl_ke_cert_reconstr = -1;
static int hf_zbee_zcl_ke_cert_subject = -1;
static int hf_zbee_zcl_ke_cert_issuer = -1;
static int hf_zbee_zcl_ke_cert_profile_attr = -1;
static int hf_zbee_zcl_ke_cert_type = -1;
static int hf_zbee_zcl_ke_cert_serialno = -1;
static int hf_zbee_zcl_ke_cert_curve = -1;
static int hf_zbee_zcl_ke_cert_hash = -1;
static int hf_zbee_zcl_ke_cert_valid_from = -1;
static int hf_zbee_zcl_ke_cert_valid_to = -1;
static int hf_zbee_zcl_ke_cert_key_usage_agreement = -1;
static int hf_zbee_zcl_ke_cert_key_usage_signature = -1;
static int hf_zbee_zcl_ke_ephemeral_qeu = -1;
static int hf_zbee_zcl_ke_ephemeral_qev = -1;
static int hf_zbee_zcl_ke_macu = -1;
static int hf_zbee_zcl_ke_macv = -1;

/* Server Commands Received and Generates (symmetrical) */
#define ZBEE_ZCL_CMD_ID_KE_INITIATE                     0x00  /* Initiate Key Establishment */
#define ZBEE_ZCL_CMD_ID_KE_EPHEMERAL                    0x01  /* Ephemeral Data Request */
#define ZBEE_ZCL_CMD_ID_KE_CONFIRM                      0x02  /* Confirm Key Data Request */
#define ZBEE_ZCL_CMD_ID_KE_TERMINATE                    0x03  /* Terminate Key Establishment */

#define ZBEE_ZCL_KE_SUITE_1                           0x0001
#define ZBEE_ZCL_KE_SUITE_2                           0x0002

#define ZBEE_ZCL_KE_TYPE_NO_EXT                         0x00  /* no extensions were used */

#define ZBEE_ZCL_KE_CURVE_SECT283K1                     0x0D

#define ZBEE_ZCL_KE_HASH_AES_MMO                        0x08

#define ZBEE_ZCL_KE_USAGE_KEY_AGREEMENT                 0x08
#define ZBEE_ZCL_KE_USAGE_DIGITAL_SIGNATURE             0x80

/* Attributes */
static const value_string zbee_zcl_ke_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_KE_SUITE,           "Supported Key Establishment Suites" },
    { 0, NULL }
};

/* Server Commands Received and Generated */
static const value_string zbee_zcl_ke_srv_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_KE_INITIATE,     "Initiate Key Establishment" },
    { ZBEE_ZCL_CMD_ID_KE_EPHEMERAL,    "Ephemeral Data" },
    { ZBEE_ZCL_CMD_ID_KE_CONFIRM,      "Confirm Key Data" },
    { ZBEE_ZCL_CMD_ID_KE_TERMINATE,    "Terminate Key Establishment" },
    { 0, NULL }
};

/* Suite Names */
static const value_string zbee_zcl_ke_suite_names[] = {
    { ZBEE_ZCL_KE_SUITE_1,                 "Crypto Suite 1 (CBKE K163)" },
    { ZBEE_ZCL_KE_SUITE_2,                 "Crypto Suite 2 (CBKE K283)" },
    { 0, NULL }
};

/* Crypto Suite 2 Type Names */
static const value_string zbee_zcl_ke_type_names[] = {
    { ZBEE_ZCL_KE_TYPE_NO_EXT,             "No Extensions" },
    { 0, NULL }
};

/* Crypto Suite 2 Curve Names */
static const value_string zbee_zcl_ke_curve_names[] = {
    { ZBEE_ZCL_KE_CURVE_SECT283K1,         "sect283k1" },
    { 0, NULL }
};

/* Crypto Suite 2 Hash Names */
static const value_string zbee_zcl_ke_hash_names[] = {
    { ZBEE_ZCL_KE_HASH_AES_MMO,            "AES MMO" },
    { 0, NULL }
};

#define ZBEE_ZCL_KE_STATUS_RESERVED                     0x00
#define ZBEE_ZCL_KE_STATUS_UNKNOWN_ISSUER               0x01
#define ZBEE_ZCL_KE_STATUS_BAD_KEY_CONFIRM              0x02
#define ZBEE_ZCL_KE_STATUS_BAD_MESSAGE                  0x03
#define ZBEE_ZCL_KE_STATUS_NO_RESOURCES                 0x04
#define ZBEE_ZCL_KE_STATUS_UNSUPPORTED_SUITE            0x05
#define ZBEE_ZCL_KE_STATUS_INVALID_CERTIFICATE          0x06

static const value_string zbee_zcl_ke_status_names[] = {
    { ZBEE_ZCL_KE_STATUS_RESERVED,             "Reserved" },
    { ZBEE_ZCL_KE_STATUS_UNKNOWN_ISSUER,       "Unknown Issuer"},
    { ZBEE_ZCL_KE_STATUS_BAD_KEY_CONFIRM,      "Bad Key Confirm"},
    { ZBEE_ZCL_KE_STATUS_BAD_MESSAGE,          "Bad Message"},
    { ZBEE_ZCL_KE_STATUS_NO_RESOURCES,         "No Resources"},
    { ZBEE_ZCL_KE_STATUS_UNSUPPORTED_SUITE,    "Unsupported Suite"},
    { ZBEE_ZCL_KE_STATUS_INVALID_CERTIFICATE,  "Invalid Certificate"},
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/


/**
 *This function dissects the Suite 1 Certificate
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_ke_suite1_certificate(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_reconstr, tvb, *offset, 22, ENC_NA);
    *offset += 22;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_subject, tvb, *offset, 8, ENC_NA);
    *offset += 8;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_issuer, tvb, *offset, 8, ENC_NA);
    *offset += 8;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_profile_attr, tvb, *offset, 10, ENC_NA);
    *offset += 10;

} /*dissect_zcl_ke_suite1_certificate*/

/**
 *This function dissects the Suite 2 Certificate
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_ke_suite2_certificate(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t      valid_from_time;
    nstime_t      valid_to_time;
    guint32       valid_to;
    guint8        key_usage;
    proto_tree   *usage_tree;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_serialno, tvb, *offset, 8, ENC_NA);
    *offset += 8;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_curve, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_hash, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_issuer, tvb, *offset, 8, ENC_NA);
    *offset += 8;

    valid_from_time.secs = (time_t)tvb_get_ntoh40(tvb, *offset);
    valid_from_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_ke_cert_valid_from, tvb, *offset, 5, &valid_from_time);
    *offset += 5;

    valid_to = tvb_get_ntohl(tvb, *offset);
    if (valid_to == 0xFFFFFFFF) {
        proto_tree_add_time_format(tree, hf_zbee_zcl_ke_cert_valid_to, tvb, *offset, 4, &valid_to_time, "Valid To: does not expire (0xFFFFFFFF)");
    }
    else {
        valid_to_time.secs = valid_from_time.secs + valid_to;
        valid_to_time.nsecs = 0;
        proto_tree_add_time(tree, hf_zbee_zcl_ke_cert_valid_to, tvb, *offset, 4, &valid_to_time);
    }
    *offset += 4;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_subject, tvb, *offset, 8, ENC_NA);
    *offset += 8;

    key_usage = tvb_get_guint8(tvb, *offset);
    usage_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 1, ett_zbee_zcl_ke_key_usage, NULL, "Key Usage (0x%02x)", key_usage);

    proto_tree_add_item(usage_tree, hf_zbee_zcl_ke_cert_key_usage_agreement, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(usage_tree, hf_zbee_zcl_ke_cert_key_usage_signature, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_cert_reconstr, tvb, *offset, 37, ENC_NA);
    *offset += 37;

} /*dissect_zcl_ke_suite2_certificate*/

/**
 *This function manages the Initiate Key Establishment message
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_ke_initiate(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    gint               rem_len;
    proto_tree        *subtree;
    guint16            suite;

    suite = tvb_get_letohs(tvb, *offset);

    proto_tree_add_item(tree, hf_zbee_zcl_ke_suite, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_ephemeral_time, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_confirm_time, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    rem_len = tvb_reported_length_remaining(tvb, *offset);
    subtree = proto_tree_add_subtree(tree, tvb, *offset, rem_len, ett_zbee_zcl_ke_cert, NULL, "Implicit Certificate");

    switch (suite) {
        case ZBEE_ZCL_KE_SUITE_1:
            dissect_zcl_ke_suite1_certificate(tvb, subtree, offset);
            break;

        case ZBEE_ZCL_KE_SUITE_2:
            dissect_zcl_ke_suite2_certificate(tvb, subtree, offset);
            break;

        default:
            break;
    }
} /* dissect_zcl_ke_initiate */

/**
 *This function dissects the Ephemeral Data QEU
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static int
dissect_zcl_ke_ephemeral_qeu(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    gint length;

    /* size depends on suite but without a session we don't know that here */
    /* so just report what we have */
    length = tvb_reported_length_remaining(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_ke_ephemeral_qeu, tvb, *offset, length, ENC_NA);
    *offset += length;
    return tvb_captured_length(tvb);
}

/**
 *This function dissects the Ephemeral Data QEV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static int
dissect_zcl_ke_ephemeral_qev(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    gint length;

    /* size depends on suite but without a session we don't know that here */
    /* so just report what we have */
    length = tvb_reported_length_remaining(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_ke_ephemeral_qev, tvb, *offset, length, ENC_NA);
    *offset += length;
    return tvb_captured_length(tvb);
}

/**
 *This function dissects the Confirm MACU
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static int
dissect_zcl_ke_confirm_macu(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_ke_macu, tvb, *offset, ZBEE_SEC_CONST_BLOCKSIZE, ENC_NA);
    *offset += ZBEE_SEC_CONST_BLOCKSIZE;
    return tvb_captured_length(tvb);
}

/**
 *This function dissects the Confirm MACV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static int
dissect_zcl_ke_confirm_macv(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_ke_macv, tvb, *offset, ZBEE_SEC_CONST_BLOCKSIZE, ENC_NA);
    *offset += ZBEE_SEC_CONST_BLOCKSIZE;
    return tvb_captured_length(tvb);
}

/**
 *This function dissects the Terminate Key Establishment message
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_ke_terminate(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_ke_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_wait_time, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_zbee_zcl_ke_suite, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
}

/**
 *ZigBee ZCL Key Establishment cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_ke(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
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
            val_to_str_const(cmd_id, zbee_zcl_ke_srv_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_ke_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, offset);
        offset += 1; /* delay from last add_item */
        if (rem_len > 0) {

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_KE_INITIATE:
                    dissect_zcl_ke_initiate(tvb, tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_KE_EPHEMERAL:
                    return dissect_zcl_ke_ephemeral_qeu(tvb, tree, &offset);

                case ZBEE_ZCL_CMD_ID_KE_CONFIRM:
                    return dissect_zcl_ke_confirm_macu(tvb, tree, &offset);

                case ZBEE_ZCL_CMD_ID_KE_TERMINATE:
                    dissect_zcl_ke_terminate(tvb, tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_ke_srv_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_ke_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_KE_INITIATE:
                    dissect_zcl_ke_initiate(tvb, tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_KE_EPHEMERAL:
                    return dissect_zcl_ke_ephemeral_qev(tvb, tree, &offset);

                case ZBEE_ZCL_CMD_ID_KE_CONFIRM:
                    return dissect_zcl_ke_confirm_macv(tvb, tree, &offset);

                case ZBEE_ZCL_CMD_ID_KE_TERMINATE:
                    dissect_zcl_ke_terminate(tvb, tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_ke*/


/**
 *This function registers the ZCL Messaging dissector
 *
*/
void
proto_register_zbee_zcl_ke(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_ke_attr_id,
            { "Attribute", "zbee_zcl_se.ke.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_ke_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ke_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.ke.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ke_srv_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ke_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.ke.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ke_srv_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ke_suite,
            { "Key Establishment Suite", "zbee_zcl_se.ke.attr.suite", FT_UINT16, BASE_HEX, VALS(zbee_zcl_ke_suite_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ke_ephemeral_time,
            { "Ephemeral Data Generate Time", "zbee_zcl_se.ke.init.ephemeral.time", FT_UINT8, BASE_DEC, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_confirm_time,
            { "Confirm Key Generate Time", "zbee_zcl_se.ke.init.confirm.time", FT_UINT8, BASE_DEC, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_status,
            { "Status", "zbee_zcl_se.ke.terminate.status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ke_status_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ke_wait_time,
            { "Wait Time", "zbee_zcl_se.ke.terminate.wait.time", FT_UINT8, BASE_DEC, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_reconstr,
            { "Public Key", "zbee_zcl_se.ke.cert.reconst", FT_BYTES, BASE_NONE, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_subject,
            { "Subject", "zbee_zcl_se.ke.cert.subject", FT_BYTES, BASE_NONE, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_issuer,
            { "Issuer", "zbee_zcl_se.ke.cert.issuer", FT_BYTES, BASE_NONE, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_profile_attr,
            { "Profile Attribute Data", "zbee_zcl_se.ke.cert.profile", FT_BYTES, BASE_NONE, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_type,
            { "Type", "zbee_zcl_se.ke.cert.type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ke_type_names),
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_serialno,
            { "Serial No", "zbee_zcl_se.ke.cert.serialno", FT_UINT64, BASE_HEX, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_curve,
            { "Curve", "zbee_zcl_se.ke.cert.curve", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ke_curve_names),
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_hash,
            { "Hash", "zbee_zcl_se.ke.cert.hash", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ke_hash_names),
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_valid_from,
            { "Valid From", "zbee_zcl_se.ke.cert.valid.from", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_valid_to,
            { "Valid To", "zbee_zcl_se.ke.cert.valid.to", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_cert_key_usage_agreement,
            { "Key Agreement", "zbee_zcl_se.ke.cert.key.usage.agreement", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled),
            ZBEE_ZCL_KE_USAGE_KEY_AGREEMENT, NULL, HFILL }},

        { &hf_zbee_zcl_ke_cert_key_usage_signature,
            { "Digital Signature", "zbee_zcl_se.ke.cert.key.usage.signature", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled),
            ZBEE_ZCL_KE_USAGE_DIGITAL_SIGNATURE, NULL, HFILL }},

        { &hf_zbee_zcl_ke_ephemeral_qeu,
            { "Ephemeral Data (QEU)", "zbee_zcl_se.ke.qeu", FT_BYTES, BASE_NONE, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_ephemeral_qev,
            { "Ephemeral Data (QEV)", "zbee_zcl_se.ke.qev", FT_BYTES, BASE_NONE, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_macu,
            { "Message Authentication Code (MACU)", "zbee_zcl_se.ke.macu", FT_BYTES, BASE_NONE, NULL,
            0, NULL, HFILL } },

        { &hf_zbee_zcl_ke_macv,
            { "Message Authentication Code (MACV)", "zbee_zcl_se.ke.macv", FT_BYTES, BASE_NONE, NULL,
            0, NULL, HFILL } },
    };

    /* subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_ke,
        &ett_zbee_zcl_ke_cert,
        &ett_zbee_zcl_ke_key_usage,
    };

    /* Register the ZigBee ZCL Messaging cluster protocol name and description */
    proto_zbee_zcl_ke = proto_register_protocol("ZigBee ZCL Key Establishment", "ZCL Key Establishment", ZBEE_PROTOABBREV_ZCL_KE);
    proto_register_field_array(proto_zbee_zcl_ke, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Messaging dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_KE, dissect_zbee_zcl_ke, proto_zbee_zcl_ke);
} /*proto_register_zbee_zcl_ke*/

/**
 *Hands off the Zcl Key Establishment dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_ke(void)
{
    dissector_handle_t ke_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    ke_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_KE);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_KE, ke_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_ke,
                            ett_zbee_zcl_ke,
                            ZBEE_ZCL_CID_KE,
                            hf_zbee_zcl_ke_attr_id,
                            hf_zbee_zcl_ke_srv_rx_cmd_id,
                            hf_zbee_zcl_ke_srv_tx_cmd_id,
                            NULL
                         );
} /*proto_reg_handoff_zbee_zcl_ke*/

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
