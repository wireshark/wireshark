/* packet-zbee-zcl-ha.c
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

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/to_str.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"

/* ########################################################################## */
/* #### (0x0703) MESSAGING CLUSTER ########################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_MSG_NUM_GENERIC_ETT                   2
#define ZBEE_ZCL_MSG_NUM_ETT                           (ZBEE_ZCL_MSG_NUM_GENERIC_ETT)

/* Attributes - None */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_MSG_GET_LAST_MSG                0x00  /* Get Last Message */
#define ZBEE_ZCL_CMD_ID_MSG_MSG_CONFIRM                 0x01  /* Message Confirmation */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_MSG_DISPLAY_MSG                 0x00  /* Display Message */
#define ZBEE_ZCL_CMD_ID_MSG_CANCEL_MSG                  0x01  /* Cancel Message */

/* Message Control Field Bit Map */
#define ZBEE_ZCL_MSG_CTRL_TX_MASK                       0x03
#define ZBEE_ZCL_MSG_CTRL_IMPORTANCE_MASK               0x0C
#define ZBEE_ZCL_MSG_CTRL_RESERVED_MASK                 0x70
#define ZBEE_ZCL_MSG_CTRL_CONFIRM_MASK                  0x80

#define ZBEE_ZCL_MSG_CTRL_TX_NORMAL_ONLY                0x00 /* Normal Transmission Only */
#define ZBEE_ZCL_MSG_CTRL_TX_NORMAL_ANON_INTERPAN       0x01 /* Normal and Anonymous Inter-PAN Transmission Only */
#define ZBEE_ZCL_MSG_CTRL_TX_ANON_INTERPAN_ONLY         0x02 /* Anonymous Inter-PAN Transmission Only */

#define ZBEE_ZCL_MSG_CTRL_IMPORTANCE_LOW                0x00 /* Low */
#define ZBEE_ZCL_MSG_CTRL_IMPORTANCE_MEDIUM             0x01 /* Medium */
#define ZBEE_ZCL_MSG_CTRL_IMPORTANCE_HIGH               0x02 /* High */
#define ZBEE_ZCL_MSG_CTRL_IMPORTANCE_CRITICAL           0x03 /* Critical */

#define ZBEE_ZCL_MSG_START_TIME_NOW                     0x00000000 /* Now */

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_msg(void);
void proto_reg_handoff_zbee_zcl_msg(void);

/* Command Dissector Helpers */
static void dissect_zcl_msg_display             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_msg_cancel              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_msg_confirm             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_msg_cmd_id              (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint8 cmd_dir);

/* Private functions prototype */
static void decode_zcl_msg_duration             (gchar *s, guint16 value);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_msg = -1;

static int hf_zbee_zcl_msg_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_msg_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_msg_message_id = -1;
static int hf_zbee_zcl_msg_ctrl_tx = -1;
static int hf_zbee_zcl_msg_ctrl_importance = -1;
static int hf_zbee_zcl_msg_ctrl_reserved = -1;
static int hf_zbee_zcl_msg_ctrl_confirm = -1;
static int hf_zbee_zcl_msg_start_time = -1;
static int hf_zbee_zcl_msg_duration = -1;
static int hf_zbee_zcl_msg_message_length =- 1;
static int hf_zbee_zcl_msg_message = -1;
static int hf_zbee_zcl_msg_confirm_time = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_msg = -1;
static gint ett_zbee_zcl_msg_message_control = -1;

/* Server Commands Received */
static const value_string zbee_zcl_msg_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_MSG_GET_LAST_MSG,                 "Get Last Message" },
    { ZBEE_ZCL_CMD_ID_MSG_MSG_CONFIRM,                  "Message Confirmation" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_msg_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_MSG_DISPLAY_MSG,                  "Display Message" },
    { ZBEE_ZCL_CMD_ID_MSG_CANCEL_MSG,                   "Cancel Message" },
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

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl_msg
 *  DESCRIPTION
 *      ZigBee ZCL Messaging cluster dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
dissect_zbee_zcl_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_msg_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_msg_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_msg);

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_MSG_GET_LAST_MSG:
                    /* No payload */
                    break;

                case ZBEE_ZCL_CMD_ID_MSG_MSG_CONFIRM:
                    dissect_zcl_msg_confirm(tvb, payload_tree, &offset);
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
            payload_root = proto_tree_add_text(tree, tvb, offset, rem_len, "Payload");
            payload_tree = proto_item_add_subtree(payload_root, ett_zbee_zcl_msg);

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_MSG_DISPLAY_MSG:
                    dissect_zcl_msg_display(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MSG_CANCEL_MSG:
                    dissect_zcl_msg_cancel(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_length(tvb);
} /*dissect_zbee_zcl_msg*/

 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_msg_display
 *  DESCRIPTION
 *      This function manages the Display Message payload
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      offset              - offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_msg_display(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree *sub_tree = NULL;
    proto_item *ti;
    guint8 control;
    guint  msg_len;
    guint8 *msg_data;

    /* Retrieve "Message ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_message_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve "Message Control" field */
    control = tvb_get_guint8(tvb, *offset);
    ti = proto_tree_add_text(tree, tvb, *offset, 1, "Message Control: 0x%02x", control);
    sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_msg_message_control);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_msg_ctrl_tx, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_msg_ctrl_importance, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_msg_ctrl_reserved, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_msg_ctrl_confirm, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Start Time" field */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_start_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve "Duration In Minutes" field */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_duration, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Retrieve "Message Length" field */
    msg_len = tvb_get_guint8(tvb, *offset); /* string length */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_message_length, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Retrieve "Message" field */
    msg_data = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, msg_len, ENC_LITTLE_ENDIAN);
    proto_tree_add_string(tree, hf_zbee_zcl_msg_message, tvb, *offset, msg_len, msg_data);
    *offset += msg_len;

} /*dissect_zcl_msg_display*/

 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_msg_cancel
 *  DESCRIPTION
 *      This function manages the Cancel Message payload
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      offset              - offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_msg_cancel(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree *sub_tree = NULL;
    proto_item *ti;
    guint8 control;

    /* Retrieve "Message ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_message_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve "Message Control" field */
    control = tvb_get_guint8(tvb, *offset);
    ti = proto_tree_add_text(tree, tvb, *offset, 1, "Message Control: 0x%02x", control);
    sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_msg_message_control);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_msg_ctrl_tx, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_msg_ctrl_importance, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_msg_ctrl_reserved, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_zbee_zcl_msg_ctrl_confirm, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

 /*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_msg_confirm
 *  DESCRIPTION
 *      This function manages the Message Confirmation payload
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      offset              - offset
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
dissect_zcl_msg_confirm(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t confirm_time;

    /* Retrieve "Message ID" field */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_message_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve "Confirmation Time" field */
    confirm_time.secs = tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    confirm_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_msg_confirm_time, tvb, *offset, 4, &confirm_time);
    *offset += 4;
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_zcl_msg_duration
 *  DESCRIPTION
 *    this function decodes duration in minute type variable
 *  PARAMETERS
 *  RETURNS
 *      none
 *---------------------------------------------------------------
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

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_zcl_msg_start_time
 *  DESCRIPTION
 *      this function decodes start time, with peculiarity case for
 *      messaging specifications.
 *  PARAMETERS
 *      guint *s        - string to display
 *      guint32 value   - value to decode
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static void
decode_zcl_msg_start_time(gchar *s, guint32 value)
{
    if (value == ZBEE_ZCL_MSG_START_TIME_NOW)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Now");
    else {
        value += ZBEE_ZCL_NSTIME_UTC_OFFSET;
        g_snprintf(s, ITEM_LABEL_LENGTH, "%s", abs_time_secs_to_str (wmem_packet_scope(), value, ABSOLUTE_TIME_LOCAL, TRUE));
    }
} /* decode_zcl_msg_start_time */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_msg_cmd_id
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
dissect_zcl_msg_cmd_id(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint8 cmd_dir)
{
    if (cmd_dir == ZBEE_ZCL_FCF_TO_CLIENT)
        proto_tree_add_item(tree, hf_zbee_zcl_msg_srv_rx_cmd_id, tvb, *offset, 1, ENC_NA);
    else
        proto_tree_add_item(tree, hf_zbee_zcl_msg_srv_tx_cmd_id, tvb, *offset, 1, ENC_NA);

} /*dissect_zcl_msg_cmd_id*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl_msg
 *  DESCRIPTION
 *      this function registers the ZCL Messaging dissector
 *      and all its information.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
proto_register_zbee_zcl_msg(void)
{
    static hf_register_info hf[] = {

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
        { &hf_zbee_zcl_msg_ctrl_tx,
            { "Transmission", "zbee_zcl_se.msg.message.ctrl.tx", FT_UINT8, BASE_HEX, VALS(zbee_zcl_msg_ctrl_tx_names),
            ZBEE_ZCL_MSG_CTRL_TX_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_msg_ctrl_importance,
            { "Importance", "zbee_zcl_se.msg.message.ctrl.importance", FT_UINT8, BASE_HEX, VALS(zbee_zcl_msg_ctrl_importance_names),
            ZBEE_ZCL_MSG_CTRL_IMPORTANCE_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_msg_ctrl_reserved,
            { "Reserved", "zbee_zcl_se.msg.message.ctrl.reserved", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_MSG_CTRL_RESERVED_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_msg_ctrl_confirm,
            { "Confirmation", "zbee_zcl_se.msg.message.ctrl.confirm", FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested),
            ZBEE_ZCL_MSG_CTRL_CONFIRM_MASK, NULL, HFILL } },
/* End of 'Message Control' fields */

        { &hf_zbee_zcl_msg_start_time,
            { "Start Time", "zbee_zcl_se.msg.message.start_time", FT_UINT32, BASE_CUSTOM, decode_zcl_msg_start_time,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_duration,
            { "Duration", "zbee_zcl_se.msg.message.duration", FT_UINT16, BASE_CUSTOM, decode_zcl_msg_duration,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_message_length,
            { "Message Length", "zbee_zcl_se.msg.message.length", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_message,
            { "Message", "zbee_zcl_se.msg.message", FT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_confirm_time,
            { "Confirmation Time", "zbee_zcl_se.msg.message.confirm_time",  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,
            0x0, NULL, HFILL }}

    };

    /* ZCL Messaging subtrees */
    gint *ett[ZBEE_ZCL_MSG_NUM_ETT];

    ett[0] = &ett_zbee_zcl_msg;
    ett[1] = &ett_zbee_zcl_msg_message_control;

    /* Register the ZigBee ZCL Messaging cluster protocol name and description */
    proto_zbee_zcl_msg = proto_register_protocol("ZigBee ZCL Messaging", "ZCL Messaging", ZBEE_PROTOABBREV_ZCL_MSG);
    proto_register_field_array(proto_zbee_zcl_msg, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Messaging dissector. */
    new_register_dissector(ZBEE_PROTOABBREV_ZCL_MSG, dissect_zbee_zcl_msg, proto_zbee_zcl_msg);

} /*proto_register_zbee_zcl_msg*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl_msg
 *  DESCRIPTION
 *      Hands off the Zcl Messaging dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
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
                            NULL,
                            NULL,
                            (zbee_zcl_fn_cmd_id)dissect_zcl_msg_cmd_id
                         );
} /*proto_reg_handoff_zbee_zcl_msg*/

