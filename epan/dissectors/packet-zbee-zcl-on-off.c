/* packet-zbee-zcl-on-off.c
 * Dissector routines for the ZigBee ZCL On Off cluster
 * By Fabio Tarabelloni <fabio.tarabelloni@reloc.it>
 * Copyright 2012 RELOC s.r.l.
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

/********************
 * Global Variables *
 ********************/

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
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_srv_rx_cmd_id, tvb, offset, sizeof(guint8), cmd_id);
        }
        /*offset += (int)sizeof(guint8);*/

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
 *  PARAMETERS
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
dissect_zcl_on_off_attr_id(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id)
{
    proto_tree_add_item(tree, hf_zbee_zcl_on_off_attr_id, tvb, *offset, sizeof(guint16), attr_id);
} /*dissect_zcl_on_off_attr_id*/


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_on_off_attr_data
 *  DESCRIPTION
 *  PARAMETERS
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
            proto_tree_add_item(tree, hf_zbee_zcl_on_off_attr_onoff, tvb, *offset, sizeof(guint8), ENC_NA);
            *offset += (int)sizeof(guint8);
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
            { "Attribute", "zbee.zcl.on_off.attr.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_on_off_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_attr_onoff,
            { "Data Value", "zbee.zcl.on_off.attr.onoff", FT_UINT8, BASE_HEX, VALS(zbee_zcl_on_off_onoff_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_on_off_srv_rx_cmd_id,
            { "Command", "zbee.zcl.on_off.srv_rx.cmd.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_on_off_srv_rx_cmd_names),
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
