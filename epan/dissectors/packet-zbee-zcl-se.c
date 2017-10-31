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

#define ZBEE_ZCL_SE_ATTR_REPORT_PENDING                     0x00
#define ZBEE_ZCL_SE_ATTR_REPORT_COMPLETE                    0x01

static const value_string zbee_zcl_se_reporting_status_names[] = {
    { ZBEE_ZCL_SE_ATTR_REPORT_PENDING,                   "Pending" },
    { ZBEE_ZCL_SE_ATTR_REPORT_COMPLETE,                  "Complete" },
    { 0, NULL }
};

/**
 *Dissect an octet string by adding a subtree showing length and octets
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to buffer offset
 *@param idx one of the ett_ array elements registered with proto_register_subtree_array()
 *@param hfindex_len length field
 *@param hfindex_data data field
*/
static void dissect_zcl_octet_string(tvbuff_t *tvb, proto_tree *tree, guint *offset,
        gint idx, int hfindex_len, int hfindex_data)
{
    guint8 octet_len;
    proto_tree* subtree;

    /* Add subtree */
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 0, idx, NULL, proto_registrar_get_name(hfindex_data));

    /* Length */
    octet_len = tvb_get_guint8(tvb, *offset);
    if (octet_len == ZBEE_ZCL_INVALID_STR_LENGTH) {
        octet_len = 0;
    }
    proto_tree_add_item(subtree, hfindex_len, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Data */
    proto_tree_add_item(subtree, hfindex_data, tvb, *offset, octet_len, ENC_NA);
    *offset += octet_len;

    /* Set length of subtree */
    proto_item_set_end(proto_tree_get_parent(subtree), tvb, *offset);
}

/*************************/
/* Global Variables      */
/*************************/

/* ########################################################################## */
/* #### (0x0025) KEEP-ALIVE CLUSTER ######################################### */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_keep_alive_attr_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_ATTR_ID_KEEP_ALIVE_BASE,                       0x0000, "Keep-Alive Base" ) \
    XXX(ZBEE_ZCL_ATTR_ID_KEEP_ALIVE_JITTER,                     0x0001, "Keep-Alive Jitter" ) \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_KEEP_ALIVE,      0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_keep_alive_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_keep_alive_attr_names);
static value_string_ext zbee_zcl_keep_alive_attr_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_keep_alive_attr_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_keep_alive(void);
void proto_reg_handoff_zbee_zcl_keep_alive(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_keep_alive_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/*************************/
/* Global Variables      */
/*************************/

static dissector_handle_t keep_alive_handle;

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_keep_alive = -1;

static int hf_zbee_zcl_keep_alive_attr_id = -1;
static int hf_zbee_zcl_keep_alive_attr_reporting_status = -1;
static int hf_zbee_zcl_keep_alive_base = -1;
static int hf_zbee_zcl_keep_alive_jitter = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_keep_alive = -1;

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
dissect_zcl_keep_alive_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_KEEP_ALIVE:
            proto_tree_add_item(tree, hf_zbee_zcl_keep_alive_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_KEEP_ALIVE_BASE:
            proto_tree_add_item(tree, hf_zbee_zcl_keep_alive_base, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_KEEP_ALIVE_JITTER:
            proto_tree_add_item(tree, hf_zbee_zcl_keep_alive_jitter, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_keep_alive_attr_data*/


/**
 *ZigBee ZCL Keep-Alive cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_keep_alive(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_keep_alive*/

/**
 *This function registers the ZCL Keep-Alive dissector
 *
*/
void
proto_register_zbee_zcl_keep_alive(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_keep_alive_attr_id,
            { "Attribute", "zbee_zcl_se.keep_alive.attr_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &zbee_zcl_keep_alive_attr_names_ext,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_keep_alive_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.keep_alive.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_keep_alive_base,
            { "Keep-Alive Base", "zbee_zcl_se.keep_alive.attr.base", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_keep_alive_jitter,
            { "Keep-Alive Jitter", "zbee_zcl_se.keep_alive.attr.jitter", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },
    };

    /* ZCL Keep-Alive subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_keep_alive
    };

    /* Register the ZigBee ZCL Keep-Alive cluster protocol name and description */
    proto_zbee_zcl_keep_alive = proto_register_protocol("ZigBee ZCL Keep-Alive", "ZCL Keep-Alive", ZBEE_PROTOABBREV_ZCL_KEEP_ALIVE);
    proto_register_field_array(proto_zbee_zcl_keep_alive, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Keep-Alive dissector. */
    keep_alive_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_KEEP_ALIVE, dissect_zbee_zcl_keep_alive, proto_zbee_zcl_keep_alive);
} /*proto_register_zbee_zcl_keep_alive*/

/**
 *Hands off the ZCL Keep-Alive dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_keep_alive(void)
{
    /* Register our dissector with the ZigBee application dissectors. */
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_KEEP_ALIVE, keep_alive_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_keep_alive,
                            ett_zbee_zcl_keep_alive,
                            ZBEE_ZCL_CID_KEEP_ALIVE,
                            hf_zbee_zcl_keep_alive_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_keep_alive_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_keep_alive*/

/* ########################################################################## */
/* #### (0x0700) PRICE CLUSTER ############################################## */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_price_attr_names_VALUE_STRING_LIST(XXX) \
/* Block Threshold (Delivered) Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_1_THRESHOLD,               0x0100, "Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_2_THRESHOLD,               0x0101, "Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_3_THRESHOLD,               0x0102, "Block 3 Threshold" ) \
/* Block Period (Delivered) Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_THRESHOLD_MULTIPLIER,            0x0202, "Threshold Multiplier" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_THRESHOLD_DIVISOR,               0x0203, "Threshold Divisor" ) \
/* Commodity */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_COMMODITY_TYPE,                  0x0300, "Commodity Type" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_STANDING_CHARGE,                 0x0301, "Standing Charge" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CONVERSION_FACTOR,               0x0302, "Conversion Factor" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CONVERSION_FACTOR_TRAILING_DIGIT,0x0303, "Conversion Factor TrailingDigit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CALORIFIC_VALUE,                 0x0304, "Calorific Value" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CALORIFIC_VALUE_UNIT,            0x0305, "Calorific Value Unit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CALORIFIC_VALUE_TRAILING_DIGIT,  0x0306, "Calorific Value Trailing Digit" ) \
/* Block Price Information (Delivered) */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_1_PRICE,           0x0400, "No Tier Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_2_PRICE,           0x0401, "No Tier Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_3_PRICE,           0x0402, "No Tier Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_4_PRICE,           0x0403, "No Tier Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_1_PRICE,            0x0410, "Tier 1 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_1_PRICE,            0x0420, "Tier 2 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_1_PRICE,            0x0430, "Tier 3 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_1_PRICE,            0x0440, "Tier 4 Block 1 Price" ) \
/* Tariff Information Set (Delivered) */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_UNIT_OF_MEASURE,                 0x0615, "Unit of Measure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CURRENCY,                        0x0616, "Currency" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TRAILING_DIGIT,            0x0617, "Price Trailing Digit" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_PRICE,           0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_price_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_price_attr_names);

/* Server Commands Received */
#define zbee_zcl_price_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_CURRENT_PRICE,                0x00, "Get Current Price" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_SCHEDULED_PRICES,             0x01, "Get Scheduled Prices" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_PRICE_ACKNOWLEDGEMENT,        0x02, "Price Acknowledgement" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_BLOCK_PERIOD,                 0x03, "Get Block Period(s)" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_CONVERSION_FACTOR,            0x04, "Get Conversion Factor" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_CALORIFIC_VALUE,              0x05, "Get Calorific Value" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_TARIFF_INFORMATION,           0x06, "Get Tariff Information" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_PRICE_MATRIX,                 0x07, "Get Price Matrix" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_BLOCK_THRESHOLDS,             0x08, "Get Block Thresholds" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_CO2_VALUE,                    0x09, "Get CO2 Value" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_TIER_LABELS,                  0x0A, "Get Tier Labels" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_BILLING_PERIOD,               0x0B, "Get Billing Period" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_CONSOLIDATED_BILL,            0x0C, "Get Consolidated Bill" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_CPP_EVENT_RESPONSE,               0x0D, "CPP Event Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_CREDIT_PAYMENT,               0x0E, "Get Credit Payment" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_CURRENCY_CONVERSION,          0x0F, "Get Currency Conversion" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_GET_TARIFF_CANCELLATION,          0x10, "Get Tariff Cancellation" )

VALUE_STRING_ENUM(zbee_zcl_price_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_price_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_price_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_PRICE,                    0x00, "Publish Price" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_BLOCK_PERIOD,             0x01, "Publish Block Period" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CONVERSION_FACTOR,        0x02, "Publish Conversion Factor" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CALORIFIC_VALUE,          0x03, "Publish Calorific Value" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_TARIFF_INFORMATION,       0x04, "Publish Tariff Information" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_PRICE_MATRIX,             0x05, "Publish Price Matrix" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_BLOCK_THRESHOLDS,         0x06, "Publish Block Thresholds" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CO2_VALUE,                0x07, "Publish CO2 Value" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_TIER_LABELS,              0x08, "Publish Tier Labels" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_BILLING_PERIOD,           0x09, "PublishBillingPeriod" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CONSOLIDATED_BILL,        0x0A, "Publish Consolidated Bill" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CPP_EVENT,                0x0B, "Publish CPP Event" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CREDIT_PAYMENT,           0x0C, "Publish Credit Payment" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CURRENCY_CONVERSION,      0x0D, "Publish Currency Conversion" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_CANCEL_TARIFF,                    0x0E, "Cancel Tariff" )

VALUE_STRING_ENUM(zbee_zcl_price_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_price_srv_tx_cmd_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_price(void);
void proto_reg_handoff_zbee_zcl_price(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_price_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/*************************/
/* Global Variables      */
/*************************/

static dissector_handle_t price_handle;

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_price = -1;

static int hf_zbee_zcl_price_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_price_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_price_attr_id = -1;
static int hf_zbee_zcl_price_attr_reporting_status = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_price = -1;

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
dissect_zcl_price_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_PRICE:
            proto_tree_add_item(tree, hf_zbee_zcl_price_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_price_attr_data*/

/**
 *ZigBee ZCL Price cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_price_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_price_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_price, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CURRENT_PRICE:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_SCHEDULED_PRICES:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_PRICE_ACKNOWLEDGEMENT:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_BLOCK_PERIOD:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CONVERSION_FACTOR:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CALORIFIC_VALUE:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_TARIFF_INFORMATION:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_PRICE_MATRIX:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_BLOCK_THRESHOLDS:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CO2_VALUE:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_TIER_LABELS:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_BILLING_PERIOD:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CONSOLIDATED_BILL:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_CPP_EVENT_RESPONSE:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CREDIT_PAYMENT:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CURRENCY_CONVERSION:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_TARIFF_CANCELLATION:
                    /* Add function to dissect payload */
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_price_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_price_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_price, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_PRICE:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_BLOCK_PERIOD:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CONVERSION_FACTOR:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CALORIFIC_VALUE:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_TARIFF_INFORMATION:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_PRICE_MATRIX:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_BLOCK_THRESHOLDS:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CO2_VALUE:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_TIER_LABELS:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_BILLING_PERIOD:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CONSOLIDATED_BILL:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CPP_EVENT:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CREDIT_PAYMENT:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CURRENCY_CONVERSION:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_CANCEL_TARIFF:
                    /* Add function to dissect payload */
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_price*/

/**
 *This function registers the ZCL Price dissector
 *
*/
void
proto_register_zbee_zcl_price(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_price_attr_id,
            { "Attribute", "zbee_zcl_se.price.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_price_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_price_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.price.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.price.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.price.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

    };

    /* ZCL Price subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_price,
    };

    /* Register the ZigBee ZCL Price cluster protocol name and description */
    proto_zbee_zcl_price = proto_register_protocol("ZigBee ZCL Price", "ZCL Price", ZBEE_PROTOABBREV_ZCL_PRICE);
    proto_register_field_array(proto_zbee_zcl_price, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Price dissector. */
    price_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_PRICE, dissect_zbee_zcl_price, proto_zbee_zcl_price);
} /*proto_register_zbee_zcl_price*/

/**
 *Hands off the ZCL Price dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_price(void)
{
    /* Register our dissector with the ZigBee application dissectors. */
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_PRICE, price_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_price,
                            ett_zbee_zcl_price,
                            ZBEE_ZCL_CID_PRICE,
                            hf_zbee_zcl_price_attr_id,
                            hf_zbee_zcl_price_srv_rx_cmd_id,
                            hf_zbee_zcl_price_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_price_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_price*/

/* ########################################################################## */
/* #### (0x0702) METERING CLUSTER ########################################## */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_met_attr_names_VALUE_STRING_LIST(XXX) \
/* Client: Notification AttributeSet / Server: Reading Information Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_FUNC_NOTI_FLAGS_CUR_SUM_DEL,       0x0000, "Client: Functional Notification Flags / Server: Current Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_2_CUR_SUM_RECV,         0x0001, "Client: Notification Flags 2 / Server: Current Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_3_CUR_MAX_DE_DEL,       0x0002, "Client: Notification Flags 3 / Server: Current Max Demand Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_4_CUR_MAX_DE_RECV,      0x0003, "Client: Notification Flags 4 / Server: Current Max Demand Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_5_DFT_SUM,              0x0004, "Client: Notification Flags 5 / Server: DFTSummation" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_6_DAI_FREE_TIME,        0x0005, "Client: Notification Flags 6 / Server: Daily Freeze Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_7_POW_FAC,              0x0006, "Client: Notification Flags 7 / Server: Power Factor" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_8_READ_SNAP_TIME,       0x0007, "Client: Notification Flags 8 / Server: Reading Snapshot Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MAX_DEMAND_DEL_TIME,           0x0008, "Current Max Demand Delivered Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MAX_DEMAND_RECV_TIME,          0x0009, "Current Max Demand Received Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DEFAULT_UPDATE_PERIOD,             0x000A, "Default Update Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_FAST_POLL_UPDATE_PERIOD,           0x000B, "Fast Poll Update Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_BLOCK_PER_CON_DEL,             0x000C, "Current Block Period Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DAILY_CON_TARGET,                  0x000D, "Daily Consumption Target" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_BLOCK,                     0x000E, "Current Block" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PROFILE_INTERVAL_PERIOD,           0x000F, "Profile Interval Period" ) \
/*     XXX(ZBEE_ZCL_ATTR_ID_MET_DEPRECATED,                        0x0010, "Deprecated" }, */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PRESET_READING_TIME,               0x0011, "Preset Reading Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_VOLUME_PER_REPORT,                 0x0012, "Volume Per Report" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_FLOW_RESTRICTION,                  0x0013, "Flow Restriction" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_SUPPLY_STATUS,                     0x0014, "Supply Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_INLET_ENER_CAR_SUM,            0x0015, "Current Inlet Energy Carrier Summation" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_OUTLET_ENER_CAR_SUM,           0x0016, "Current Outlet Energy Carrier Summation" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_INLET_TEMPERATURE,                 0x0017, "Inlet Temperature" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_OUTLET_TEMPERATURE,                0x0018, "Outlet Temperature" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CONTROL_TEMPERATURE,               0x0019, "Control Temperature" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_INLET_ENER_CAR_DEM,            0x001A, "Current Inlet Energy Carrier Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_OUTLET_ENER_CAR_DEM,           0x001B, "Current Outlet Energy Carrier Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_BLOCK_CON_DEL,                0x001C, "Previous Block Period Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_BLOCL_CON_RECV,               0x001D, "Current Block Period Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_BLOCK_RECEIVED,            0x001E, "Current Block Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DFT_SUMMATION_RECEIVED,            0x001F, "DFT Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ACTIVE_REG_TIER_DEL,               0x0020, "Active Register Tier Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ACTIVE_REG_TIER_RECV,              0x0021, "Active Register Tier Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_LAST_BLOCK_SWITCH_TIME,            0x0022, "Last Block Switch Time" ) \
/* Summation TOU Information Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_1_SUM_DEL,            0x0100, "Current Tier 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_2_SUM_DEL,            0x0102, "Current Tier 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_3_SUM_DEL,            0x0104, "Current Tier 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_4_SUM_DEL,            0x0106, "Current Tier 4 Summation Delivered" ) \
/* Meter Status Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_STATUS,                            0x0200, "Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_REMAIN_BAT_LIFE_DAYS,              0x0205, "Remaining Battery Life in Days" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_METER_ID,                  0x0206, "Current Meter ID" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_AMBIENT_CON_IND,                   0x0207, "Ambient Consumption Indicator" ) \
/* Formatting */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_UNIT_OF_MEASURE,                   0x0300, "Unit of Measure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_MULTIPLIER,                        0x0301, "Multiplier" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DIVISOR,                           0x0302, "Divisor" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_SUMMATION_FORMATTING,              0x0303, "Summation Formatting" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_METERING_DEVICE_TYPE,              0x0306, "Metering Device Type" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_SITE_ID,                           0x0307, "Site ID" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUSTOMER_ID_NUMBER,                0x0311, "Customer ID Number" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ALT_UNIT_OF_MEASURE,               0x0312, "Alternative Unit of Measure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ALT_CON_FORMATTING,                0x0314, "Alternative Consumption Formatting" ) \
/* Historical Consumption Attribute */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_INSTANT_DEMAND,                    0x0400, "Instantaneous Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_DAY_CON_DEL,                   0x0401, "Current Day Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_CON_DEL,                  0x0403, "Previous Day Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_2_DAY_CON_DEL,                0x0420, "Previous Day 2 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_3_DAY_CON_DEL,                0x0422, "Previous Day 3 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_4_DAY_CON_DEL,                0x0424, "Previous Day 4 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_5_DAY_CON_DEL,                0x0426, "Previous Day 5 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_6_DAY_CON_DEL,                0x0428, "Previous Day 6 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_7_DAY_CON_DEL,                0x042A, "Previous Day 7 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_8_DAY_CON_DEL,                0x042C, "Previous Day 8 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_WEEK_CON_DEL,                  0x0430, "Current Week Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_CON_DEL,                 0x0432, "Previous Week Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_2_CON_DEL,               0x0434, "Previous Week 2 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_3_CON_DEL,               0x0436, "Previous Week 3 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_4_CON_DEL,               0x0438, "Previous Week 4 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_5_CON_DEL,               0x043A, "Previous Week 5 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MONTH_CON_DEL,                 0x0440, "Current Month Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_CON_DEL,                0x0442, "Previous Month Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_2_CON_DEL,              0x0444, "Previous Month 2 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_3_CON_DEL,              0x0446, "Previous Month 3 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_4_CON_DEL,              0x0448, "Previous Month 4 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_5_CON_DEL,              0x044A, "Previous Month 5 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_6_CON_DEL,              0x044C, "Previous Month 6 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_7_CON_DEL,              0x044E, "Previous Month 7 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_8_CON_DEL,              0x0450, "Previous Month 8 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_9_CON_DEL,              0x0452, "Previous Month 9 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_10_CON_DEL,             0x0454, "Previous Month 10 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_11_CON_DEL,             0x0456, "Previous Month 11 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_12_CON_DEL,             0x0458, "Previous Month 12 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_13_CON_DEL,             0x045A, "Previous Month 13 Consumption Delivered" ) \
/* Supply Limit Attributes */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_SUPPLY_TAMPER_STATE,               0x0607, "Supply Tamper State" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_SUPPLY_DEPLETION_STATE,            0x0608, "Supply Depletion State" ) \
/* Block Information Attribute Set (Delivered) */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_1_SUM_DEL,       0x0700, "Current No Tier Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_2_SUM_DEL,       0x0701, "Current No Tier Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_3_SUM_DEL,       0x0702, "Current No Tier Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_4_SUM_DEL,       0x0703, "Current No Tier Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_1_SUM_DEL,        0x0710, "Current Tier 1 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_2_SUM_DEL,        0x0711, "Current Tier 1 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_3_SUM_DEL,        0x0712, "Current Tier 1 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_4_SUM_DEL,        0x0713, "Current Tier 1 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_1_SUM_DEL,        0x0720, "Current Tier 2 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_2_SUM_DEL,        0x0721, "Current Tier 2 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_3_SUM_DEL,        0x0722, "Current Tier 2 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_4_SUM_DEL,        0x0723, "Current Tier 2 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_1_SUM_DEL,        0x0730, "Current Tier 3 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_2_SUM_DEL,        0x0731, "Current Tier 3 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_3_SUM_DEL,        0x0732, "Current Tier 3 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_4_SUM_DEL,        0x0733, "Current Tier 3 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_1_SUM_DEL,        0x0740, "Current Tier 4 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_2_SUM_DEL,        0x0741, "Current Tier 4 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_3_SUM_DEL,        0x0742, "Current Tier 4 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_4_SUM_DEL,        0x0743, "Current Tier 4 Block 4 Summation Delivered" ) \
/* Meter Billing Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_BILL_TO_DATE_DELIVERED,            0x0A00, "Bill To Date Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_BILL_TO_DATE_TIMESTAMP_DEL,        0x0A01, "BillToDateTimeStampDelivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_BILL_DELIVERED_TRAILING_DIGIT,     0x0A04, "Bill Delivered Trailing Digit" ) \
/* Alternative Historical Consumption Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_DAY_ALT_CON_DEL,               0x0C01, "Current Day Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_ALT_CON_DEL,              0x0C03, "Previous Day Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_2_ALT_CON_DEL,            0x0C20, "Previous Day 2 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_3_ALT_CON_DEL,            0x0C22, "Previous Day 3 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_4_ALT_CON_DEL,            0x0C24, "Previous Day 4 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_5_ALT_CON_DEL,            0x0C26, "Previous Day 5 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_6_ALT_CON_DEL,            0x0C28, "Previous Day 6 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_7_ALT_CON_DEL,            0x0C2A, "Previous Day 7 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_8_ALT_CON_DEL,            0x0C2C, "Previous Day 8 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_WEEK_ALT_CON_DEL,              0x0C30, "Current Week Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_ALT_CON_DEL,             0x0C32, "Previous Week Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_2_ALT_CON_DEL,           0x0C34, "Previous Week 2 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_3_ALT_CON_DEL,           0x0C36, "Previous Week 3 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_4_ALT_CON_DEL,           0x0C38, "Previous Week 4 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_5_ALT_CON_DEL,           0x0C3A, "Previous Week 5 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MONTH_ALT_CON_DEL,             0x0C40, "Current Month Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_ALT_CON_DEL,            0x0C42, "Previous Month Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_2_ALT_CON_DEL,          0x0C44, "Previous Month 2 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_3_ALT_CON_DEL,          0x0C46, "Previous Month 3 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_4_ALT_CON_DEL,          0x0C48, "Previous Month 4 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_5_ALT_CON_DEL,          0x0C4A, "Previous Month 5 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_6_ALT_CON_DEL,          0x0C4C, "Previous Month 6 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_7_ALT_CON_DEL,          0x0C4E, "Previous Month 7 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_8_ALT_CON_DEL,          0x0C50, "Previous Month 8 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_9_ALT_CON_DEL,          0x0C52, "Previous Month 9 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_10_ALT_CON_DEL,         0x0C54, "Previous Month 10 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_11_ALT_CON_DEL,         0x0C56, "Previous Month 11 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_12_ALT_CON_DEL,         0x0C58, "Previous Month 12 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_13_ALT_CON_DEL,         0x0C5A, "Previous Month 13 Alternative Consumption Delivered" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_MET,             0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_met_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_met_attr_names);
static value_string_ext zbee_zcl_met_attr_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_met_attr_names);

/* Server Commands Received */
#define zbee_zcl_met_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_MET_GET_PROFILE,                        0x00, "Get Profile" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_REQUEST_MIRROR_RSP,                 0x01, "Request Mirror Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_MIRROR_REMOVED,                     0x02, "Mirror Removed" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_REQUEST_FAST_POLL_MODE,             0x03, "Request Fast Poll Mode" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_SCHEDULE_SNAPSHOT,                  0x04, "Schedule Snapshot" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_TAKE_SNAPSHOT,                      0x05, "Take Snapshot" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_GET_SNAPSHOT,                       0x06, "Get Snapshot" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_START_SAMPLING,                     0x07, "Start Sampling" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_GET_SAMPLED_DATA,                   0x08, "Get Sampled Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_MIRROR_REPORT_ATTRIBUTE_RESPONSE,   0x09, "Mirror Report Attribute Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_RESET_LOAD_LIMIT_COUNTER,           0x0A, "Reset Load Limit Counter" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_CHANGE_SUPPLY,                      0x0B, "Change Supply" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_LOCAL_CHANGE_SUPPLY,                0x0C, "Local Change Supply" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_SET_SUPPLY_STATUS,                  0x0D, "Set Supply Status" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_SET_UNCONTROLLED_FLOW_THRESHOLD,    0x0E, "Set Uncontrolled Flow Threshold" )

VALUE_STRING_ENUM(zbee_zcl_met_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_met_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_met_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_MET_GET_PROFILE_RESPONSE,               0x00, "Get Profile Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_REQUEST_MIRROR,                     0x01, "Request Mirror" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_REMOVE_MIRROR,                      0x02, "Remove Mirror" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_REQUEST_FAST_POLL_MODE_RESPONSE,    0x03, "Request Fast Poll Mode Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_SCHEDULE_SNAPSHOT_RESPONSE,         0x04, "Schedule Snapshot Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_TAKE_SNAPSHOT_RESPONSE,             0x05, "Take Snapshot Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_PUBLISH_SNAPSHOT,                   0x06, "Publish Snapshot" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_GET_SAMPLED_DATA_RSP,               0x07, "Get Sampled Data Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_CONFIGURE_MIRROR,                   0x08, "Configure Mirror" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_CONFIGURE_NOTIFICATION_SCHEME,      0x09, "Configure Notification Scheme" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_CONFIGURE_NOTIFICATION_FLAG,        0x0A, "Configure Notification Flag" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_GET_NOTIFIED_MESSAGE,               0x0B, "Get Notified Message" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_SUPPLY_STATUS_RESPONSE,             0x0C, "Supply Status Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_START_SAMPLING_RESPONSE,            0x0D, "Start Sampling Response" )

VALUE_STRING_ENUM(zbee_zcl_met_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_met_srv_tx_cmd_names);

/* Functional Notification Flags */
#define ZBEE_ZCL_FUNC_NOTI_FLAG_NEW_OTA_FIRMWARE                                0x00000001
#define ZBEE_ZCL_FUNC_NOTI_FLAG_CBKE_UPDATE_REQUESTED                           0x00000002
#define ZBEE_ZCL_FUNC_NOTI_FLAG_TIME_SYNC                                       0x00000004
#define ZBEE_ZCL_FUNC_NOTI_FLAG_RESERVED_1                                      0x00000008
#define ZBEE_ZCL_FUNC_NOTI_FLAG_STAY_AWAKE_REQUEST_HAN                          0x00000010
#define ZBEE_ZCL_FUNC_NOTI_FLAG_STAY_AWAKE_REQUEST_WAN                          0x00000020
#define ZBEE_ZCL_FUNC_NOTI_FLAG_PUSH_HISTORICAL_METERING_DATA_ATTRIBUTE_SET     0x000001C0
#define ZBEE_ZCL_FUNC_NOTI_FLAG_PUSH_HISTORICAL_PREPAYMENT_DATA_ATTRIBUTE_SET   0x00000E00
#define ZBEE_ZCL_FUNC_NOTI_FLAG_PUSH_ALL_STATIC_DATA_BASIC_CLUSTER              0x00001000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_PUSH_ALL_STATIC_DATA_METERING_CLUSTER           0x00002000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_PUSH_ALL_STATIC_DATA_PREPAYMENT_CLUSTER         0x00004000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_NETWORK_KEY_ACTIVE                              0x00008000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_DISPLAY_MESSAGE                                 0x00010000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_CANCEL_ALL_MESSAGES                             0x00020000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_CHANGE_SUPPLY                                   0x00040000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_LOCAL_CHANGE_SUPPLY                             0x00080000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_SET_UNCONTROLLED_FLOW_THRESHOLD                 0x00100000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_TUNNEL_MESSAGE_PENDING                          0x00200000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_GET_SNAPSHOT                                    0x00400000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_GET_SAMPLED_DATA                                0x00800000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_RESERVED_2                                      0xFF000000

/* Notification Flags 2 */
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_PRICE                                      0x00000001
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_BLOCK_PERIOD                               0x00000002
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_TARIFF_INFORMATION                         0x00000004
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CONVERSION_FACTOR                          0x00000008
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CALORIFIC_VALUE                            0x00000010
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CO2_VALUE                                  0x00000020
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_BILLING_PERIOD                             0x00000040
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CONSOLIDATED_BILL                          0x00000080
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_PRICE_MATRIX                               0x00000100
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_BLOCK_THRESHOLDS                           0x00000200
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CURRENCY_CONVERSION                        0x00000400
#define ZBEE_ZCL_NOTI_FLAG_2_RESERVED                                           0x00000800
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CREDIT_PAYMENT_INFO                        0x00001000
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CPP_EVENT                                  0x00002000
#define ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_TIER_LABELS                                0x00004000
#define ZBEE_ZCL_NOTI_FLAG_2_CANCEL_TARIFF                                      0x00008000
#define ZBEE_ZCL_NOTI_FLAG_2_RESERVED_FUTURE                                    0xFFFF0000

/* Notification Flags 3 */
#define ZBEE_ZCL_NOTI_FLAG_3_PUBLISH_CALENDAR                                   0x00000001
#define ZBEE_ZCL_NOTI_FLAG_3_PUBLISH_SPECIAL_DAYS                               0x00000002
#define ZBEE_ZCL_NOTI_FLAG_3_PUBLISH_SEASONS                                    0x00000004
#define ZBEE_ZCL_NOTI_FLAG_3_PUBLISH_WEEK                                       0x00000008
#define ZBEE_ZCL_NOTI_FLAG_3_PUBLISH_DAY                                        0x00000010
#define ZBEE_ZCL_NOTI_FLAG_3_CANCEL_DAY                                         0x00000020
#define ZBEE_ZCL_NOTI_FLAG_3_RESERVED                                           0xFFFFFFC0

/* Notification Flags 4 */
#define ZBEE_ZCL_NOTI_FLAG_4_SELECT_AVAILABLE_EMERGENCY_CREDIT                  0x00000001
#define ZBEE_ZCL_NOTI_FLAG_4_CHANGE_DEBT                                        0x00000002
#define ZBEE_ZCL_NOTI_FLAG_4_EMERGENCY_CREDIT_SETUP                             0x00000004
#define ZBEE_ZCL_NOTI_FLAG_4_CONSUMER_TOP_UP                                    0x00000008
#define ZBEE_ZCL_NOTI_FLAG_4_CREDIT_ADJUSTMENT                                  0x00000010
#define ZBEE_ZCL_NOTI_FLAG_4_CHANGE_PAYMENT_MODE                                0x00000020
#define ZBEE_ZCL_NOTI_FLAG_4_GET_PREPAY_SNAPSHOT                                0x00000040
#define ZBEE_ZCL_NOTI_FLAG_4_GET_TOP_UP_LOG                                     0x00000080
#define ZBEE_ZCL_NOTI_FLAG_4_SET_LOW_CREDIT_WARNING_LEVEL                       0x00000100
#define ZBEE_ZCL_NOTI_FLAG_4_GET_DEBT_REPAYMENT_LOG                             0x00000200
#define ZBEE_ZCL_NOTI_FLAG_4_SET_MAXIMUM_CREDIT_LIMIT                           0x00000400
#define ZBEE_ZCL_NOTI_FLAG_4_SET_OVERALL_DEBT_CAP                               0x00000800
#define ZBEE_ZCL_NOTI_FLAG_4_RESERVED                                           0xFFFFF000

/* Notification Flags 5 */
#define ZBEE_ZCL_NOTI_FLAG_5_PUBLISH_CHANGE_OF_TENANCY                          0x00000001
#define ZBEE_ZCL_NOTI_FLAG_5_PUBLISH_CHANGE_OF_SUPPLIER                         0x00000002
#define ZBEE_ZCL_NOTI_FLAG_5_REQUEST_NEW_PASSWORD_1_RESPONSE                    0x00000004
#define ZBEE_ZCL_NOTI_FLAG_5_REQUEST_NEW_PASSWORD_2_RESPONSE                    0x00000008
#define ZBEE_ZCL_NOTI_FLAG_5_REQUEST_NEW_PASSWORD_3_RESPONSE                    0x00000010
#define ZBEE_ZCL_NOTI_FLAG_5_REQUEST_NEW_PASSWORD_4_RESPONSE                    0x00000020
#define ZBEE_ZCL_NOTI_FLAG_5_UPDATE_SITE_ID                                     0x00000040
#define ZBEE_ZCL_NOTI_FLAG_5_RESET_BATTERY_COUNTER                              0x00000080
#define ZBEE_ZCL_NOTI_FLAG_5_UPDATE_CIN                                         0x00000100
#define ZBEE_ZCL_NOTI_FLAG_5_RESERVED                                           0XFFFFFE00

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_met(void);
void proto_reg_handoff_zbee_zcl_met(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_met_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Command Dissector Helpers */
static void dissect_zcl_met_request_mirror_rsp      (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_get_snapshot            (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_get_sampled_data        (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_local_change_supply     (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_publish_snapshot        (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_get_sampled_data_rsp    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_configure_mirror        (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_get_notified_msg        (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

static dissector_handle_t met_handle;

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_met = -1;

static int hf_zbee_zcl_met_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_met_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_met_attr_id = -1;
static int hf_zbee_zcl_met_attr_reporting_status = -1;

static int hf_zbee_zcl_met_func_noti_flags = -1;
static int hf_zbee_zcl_met_func_noti_flag_new_ota_firmware = -1;
static int hf_zbee_zcl_met_func_noti_flag_cbke_update_request = -1;
static int hf_zbee_zcl_met_func_noti_flag_time_sync = -1;
static int hf_zbee_zcl_met_func_noti_flag_stay_awake_request_han = -1;
static int hf_zbee_zcl_met_func_noti_flag_stay_awake_request_wan = -1;
static int hf_zbee_zcl_met_func_noti_flag_push_historical_metering_data_attribute_set = -1;
static int hf_zbee_zcl_met_func_noti_flag_push_historical_prepayment_data_attribute_set = -1;
static int hf_zbee_zcl_met_func_noti_flag_push_all_static_data_basic_cluster = -1;
static int hf_zbee_zcl_met_func_noti_flag_push_all_static_data_metering_cluster = -1;
static int hf_zbee_zcl_met_func_noti_flag_push_all_static_data_prepayment_cluster = -1;
static int hf_zbee_zcl_met_func_noti_flag_network_key_active = -1;
static int hf_zbee_zcl_met_func_noti_flag_display_message = -1;
static int hf_zbee_zcl_met_func_noti_flag_cancel_all_messages = -1;
static int hf_zbee_zcl_met_func_noti_flag_change_supply = -1;
static int hf_zbee_zcl_met_func_noti_flag_local_change_supply = -1;
static int hf_zbee_zcl_met_func_noti_flag_set_uncontrolled_flow_threshold = -1;
static int hf_zbee_zcl_met_func_noti_flag_tunnel_message_pending = -1;
static int hf_zbee_zcl_met_func_noti_flag_get_snapshot = -1;
static int hf_zbee_zcl_met_func_noti_flag_get_sampled_data = -1;
static int hf_zbee_zcl_met_func_noti_flag_reserved = -1;
static int hf_zbee_zcl_met_noti_flags_2 = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_price = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_block_period = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_tariff_info = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_conversion_factor = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_calorific_value = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_co2_value = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_billing_period = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_consolidated_bill = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_price_matrix = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_block_thresholds = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_currency_conversion = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_credit_payment_info = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_cpp_event = -1;
static int hf_zbee_zcl_met_noti_flag_2_publish_tier_labels = -1;
static int hf_zbee_zcl_met_noti_flag_2_cancel_tariff = -1;
static int hf_zbee_zcl_met_noti_flag_2_reserved = -1;
static int hf_zbee_zcl_met_noti_flags_3 = -1;
static int hf_zbee_zcl_met_noti_flag_3_publish_calendar = -1;
static int hf_zbee_zcl_met_noti_flag_3_publish_special_days = -1;
static int hf_zbee_zcl_met_noti_flag_3_publish_seasons = -1;
static int hf_zbee_zcl_met_noti_flag_3_publish_week = -1;
static int hf_zbee_zcl_met_noti_flag_3_publish_day = -1;
static int hf_zbee_zcl_met_noti_flag_3_cancel_calendar = -1;
static int hf_zbee_zcl_met_noti_flag_3_reserved = -1;
static int hf_zbee_zcl_met_noti_flags_4 = -1;
static int hf_zbee_zcl_met_noti_flag_4_select_available_emergency_credit = -1;
static int hf_zbee_zcl_met_noti_flag_4_change_debt = -1;
static int hf_zbee_zcl_met_noti_flag_4_emergency_credit_setup = -1;
static int hf_zbee_zcl_met_noti_flag_4_consumer_top_up = -1;
static int hf_zbee_zcl_met_noti_flag_4_credit_adjustment = -1;
static int hf_zbee_zcl_met_noti_flag_4_change_payment_mode = -1;
static int hf_zbee_zcl_met_noti_flag_4_get_prepay_snapshot = -1;
static int hf_zbee_zcl_met_noti_flag_4_get_top_up_log = -1;
static int hf_zbee_zcl_met_noti_flag_4_set_low_credit_warning_level = -1;
static int hf_zbee_zcl_met_noti_flag_4_get_debt_repayment_log = -1;
static int hf_zbee_zcl_met_noti_flag_4_set_maximum_credit_limit = -1;
static int hf_zbee_zcl_met_noti_flag_4_set_overall_debt_cap = -1;
static int hf_zbee_zcl_met_noti_flag_4_reserved = -1;
static int hf_zbee_zcl_met_noti_flags_5 = -1;
static int hf_zbee_zcl_met_noti_flag_5_publish_change_of_tenancy = -1;
static int hf_zbee_zcl_met_noti_flag_5_publish_change_of_supplier = -1;
static int hf_zbee_zcl_met_noti_flag_5_request_new_password_1_response = -1;
static int hf_zbee_zcl_met_noti_flag_5_request_new_password_2_response = -1;
static int hf_zbee_zcl_met_noti_flag_5_request_new_password_3_response = -1;
static int hf_zbee_zcl_met_noti_flag_5_request_new_password_4_response = -1;
static int hf_zbee_zcl_met_noti_flag_5_update_site_id = -1;
static int hf_zbee_zcl_met_noti_flag_5_reset_battery_counter = -1;
static int hf_zbee_zcl_met_noti_flag_5_update_cin = -1;
static int hf_zbee_zcl_met_noti_flag_5_reserved = -1;
static int hf_zbee_zcl_met_request_mirror_rsp_endpoint_id = -1;
static int hf_zbee_zcl_met_get_snapshot_start_time = -1;
static int hf_zbee_zcl_met_get_snapshot_end_time = -1;
static int hf_zbee_zcl_met_get_snapshot_snapshot_offset = -1;
static int hf_zbee_zcl_met_get_snapshot_snapshot_cause = -1;
static int hf_zbee_zcl_met_get_sampled_data_sample_id = -1;
static int hf_zbee_zcl_met_get_sampled_data_sample_start_time = -1;
static int hf_zbee_zcl_met_get_sampled_data_sample_type = -1;
static int hf_zbee_zcl_met_get_sampled_data_number_of_samples = -1;
static int hf_zbee_zcl_met_local_change_supply_supply_status = -1;
static int hf_zbee_zcl_met_publish_snapshot_snapshot_id = -1;
static int hf_zbee_zcl_met_publish_snapshot_snapshot_time = -1;
static int hf_zbee_zcl_met_publish_snapshot_snapshots_found = -1;
static int hf_zbee_zcl_met_publish_snapshot_cmd_index = -1;
static int hf_zbee_zcl_met_publish_snapshot_total_commands = -1;
static int hf_zbee_zcl_met_publish_snapshot_snapshot_cause = -1;
static int hf_zbee_zcl_met_publish_snapshot_snapshot_payload_type = -1;
static int hf_zbee_zcl_met_publish_snapshot_snapshot_sub_payload = -1;
static int hf_zbee_zcl_met_get_sampled_data_rsp_sample_id = -1;
static int hf_zbee_zcl_met_get_sampled_data_rsp_sample_start_time = -1;
static int hf_zbee_zcl_met_get_sampled_data_rsp_sample_type = -1;
static int hf_zbee_zcl_met_get_sampled_data_rsp_sample_request_interval = -1;
static int hf_zbee_zcl_met_get_sampled_data_rsp_sample_number_of_samples = -1;
static int hf_zbee_zcl_met_get_sampled_data_rsp_sample_samples = -1;
static int hf_zbee_zcl_met_configure_mirror_issuer_event_id = -1;
static int hf_zbee_zcl_met_configure_mirror_reporting_interval = -1;
static int hf_zbee_zcl_met_configure_mirror_mirror_notification_reporting = -1;
static int hf_zbee_zcl_met_configure_mirror_notification_scheme = -1;
static int hf_zbee_zcl_met_get_notified_msg_notification_scheme = -1;
static int hf_zbee_zcl_met_get_notified_msg_notification_flag_attribute_id = -1;
static int hf_zbee_zcl_met_get_notified_msg_notification_flags = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_met = -1;
static gint ett_zbee_zcl_met_func_noti_flags = -1;
static gint ett_zbee_zcl_met_noti_flags_2 = -1;
static gint ett_zbee_zcl_met_noti_flags_3 = -1;
static gint ett_zbee_zcl_met_noti_flags_4 = -1;
static gint ett_zbee_zcl_met_noti_flags_5 = -1;

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
dissect_zcl_met_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_MET:
            proto_tree_add_item(tree, hf_zbee_zcl_met_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_MET_FUNC_NOTI_FLAGS_CUR_SUM_DEL:
            if (data_type == ZBEE_ZCL_32_BIT_BITMAP) {
                proto_item_append_text(tree, ", Functional Notification Flags");

                static const int* func_noti_flags[] = {
                        &hf_zbee_zcl_met_func_noti_flag_new_ota_firmware,
                        &hf_zbee_zcl_met_func_noti_flag_cbke_update_request,
                        &hf_zbee_zcl_met_func_noti_flag_time_sync,
                        &hf_zbee_zcl_met_func_noti_flag_stay_awake_request_han,
                        &hf_zbee_zcl_met_func_noti_flag_stay_awake_request_wan,
                        &hf_zbee_zcl_met_func_noti_flag_push_historical_metering_data_attribute_set,
                        &hf_zbee_zcl_met_func_noti_flag_push_historical_prepayment_data_attribute_set,
                        &hf_zbee_zcl_met_func_noti_flag_push_all_static_data_basic_cluster,
                        &hf_zbee_zcl_met_func_noti_flag_push_all_static_data_metering_cluster,
                        &hf_zbee_zcl_met_func_noti_flag_push_all_static_data_prepayment_cluster,
                        &hf_zbee_zcl_met_func_noti_flag_network_key_active,
                        &hf_zbee_zcl_met_func_noti_flag_display_message,
                        &hf_zbee_zcl_met_func_noti_flag_cancel_all_messages,
                        &hf_zbee_zcl_met_func_noti_flag_change_supply,
                        &hf_zbee_zcl_met_func_noti_flag_local_change_supply,
                        &hf_zbee_zcl_met_func_noti_flag_set_uncontrolled_flow_threshold,
                        &hf_zbee_zcl_met_func_noti_flag_tunnel_message_pending,
                        &hf_zbee_zcl_met_func_noti_flag_get_snapshot,
                        &hf_zbee_zcl_met_func_noti_flag_get_sampled_data,
                        &hf_zbee_zcl_met_func_noti_flag_reserved,
                        NULL
                };

                proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_func_noti_flags, ett_zbee_zcl_met_func_noti_flags, func_noti_flags, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            else {
                dissect_zcl_attr_data(tvb, tree, offset, data_type);
            }
            break;

        case ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_2_CUR_SUM_RECV:
            if (data_type == ZBEE_ZCL_32_BIT_BITMAP) {
                proto_item_append_text(tree, ", Notification Flags 2");

                static const int* noti_flags_2[] = {
                        &hf_zbee_zcl_met_noti_flag_2_publish_price,
                        &hf_zbee_zcl_met_noti_flag_2_publish_block_period,
                        &hf_zbee_zcl_met_noti_flag_2_publish_tariff_info,
                        &hf_zbee_zcl_met_noti_flag_2_publish_conversion_factor,
                        &hf_zbee_zcl_met_noti_flag_2_publish_calorific_value,
                        &hf_zbee_zcl_met_noti_flag_2_publish_co2_value,
                        &hf_zbee_zcl_met_noti_flag_2_publish_billing_period,
                        &hf_zbee_zcl_met_noti_flag_2_publish_consolidated_bill,
                        &hf_zbee_zcl_met_noti_flag_2_publish_price_matrix,
                        &hf_zbee_zcl_met_noti_flag_2_publish_block_thresholds,
                        &hf_zbee_zcl_met_noti_flag_2_publish_currency_conversion,
                        &hf_zbee_zcl_met_noti_flag_2_publish_credit_payment_info,
                        &hf_zbee_zcl_met_noti_flag_2_publish_cpp_event,
                        &hf_zbee_zcl_met_noti_flag_2_publish_tier_labels,
                        &hf_zbee_zcl_met_noti_flag_2_cancel_tariff,
                        &hf_zbee_zcl_met_noti_flag_2_reserved,
                        NULL
                };

                proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_2, ett_zbee_zcl_met_noti_flags_2, noti_flags_2, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            else {
                dissect_zcl_attr_data(tvb, tree, offset, data_type);
            }
            break;

        case ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_3_CUR_MAX_DE_DEL:
            if (data_type == ZBEE_ZCL_32_BIT_BITMAP) {
                proto_item_append_text(tree, ", Notification Flags 3");

                static const int* noti_flags_3[] = {
                        &hf_zbee_zcl_met_noti_flag_3_publish_calendar,
                        &hf_zbee_zcl_met_noti_flag_3_publish_special_days,
                        &hf_zbee_zcl_met_noti_flag_3_publish_seasons,
                        &hf_zbee_zcl_met_noti_flag_3_publish_week,
                        &hf_zbee_zcl_met_noti_flag_3_publish_day,
                        &hf_zbee_zcl_met_noti_flag_3_cancel_calendar,
                        &hf_zbee_zcl_met_noti_flag_3_reserved,
                        NULL
                };

                proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_3, ett_zbee_zcl_met_noti_flags_3, noti_flags_3, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            else {
                dissect_zcl_attr_data(tvb, tree, offset, data_type);
            }
            break;

        case ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_4_CUR_MAX_DE_RECV:
            if (data_type == ZBEE_ZCL_32_BIT_BITMAP) {
                proto_item_append_text(tree, ", Notification Flags 4");

                static const int* noti_flags_4[] = {
                        &hf_zbee_zcl_met_noti_flag_4_select_available_emergency_credit,
                        &hf_zbee_zcl_met_noti_flag_4_change_debt,
                        &hf_zbee_zcl_met_noti_flag_4_emergency_credit_setup,
                        &hf_zbee_zcl_met_noti_flag_4_consumer_top_up,
                        &hf_zbee_zcl_met_noti_flag_4_credit_adjustment,
                        &hf_zbee_zcl_met_noti_flag_4_change_payment_mode,
                        &hf_zbee_zcl_met_noti_flag_4_get_prepay_snapshot,
                        &hf_zbee_zcl_met_noti_flag_4_get_top_up_log,
                        &hf_zbee_zcl_met_noti_flag_4_set_low_credit_warning_level,
                        &hf_zbee_zcl_met_noti_flag_4_get_debt_repayment_log,
                        &hf_zbee_zcl_met_noti_flag_4_set_maximum_credit_limit,
                        &hf_zbee_zcl_met_noti_flag_4_set_overall_debt_cap,
                        &hf_zbee_zcl_met_noti_flag_4_reserved,
                        NULL
                };

                proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_4, ett_zbee_zcl_met_noti_flags_4, noti_flags_4, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            else {
                dissect_zcl_attr_data(tvb, tree, offset, data_type);
            }
            break;

        case ZBEE_ZCL_ATTR_ID_MET_NOTI_FLAGS_5_DFT_SUM:
            if (data_type == ZBEE_ZCL_32_BIT_BITMAP) {
                proto_item_append_text(tree, ", Notification Flags 5");

                static const int* noti_flags_5[] = {
                        &hf_zbee_zcl_met_noti_flag_5_publish_change_of_tenancy,
                        &hf_zbee_zcl_met_noti_flag_5_publish_change_of_supplier,
                        &hf_zbee_zcl_met_noti_flag_5_request_new_password_1_response,
                        &hf_zbee_zcl_met_noti_flag_5_request_new_password_2_response,
                        &hf_zbee_zcl_met_noti_flag_5_request_new_password_3_response,
                        &hf_zbee_zcl_met_noti_flag_5_request_new_password_4_response,
                        &hf_zbee_zcl_met_noti_flag_5_update_site_id,
                        &hf_zbee_zcl_met_noti_flag_5_reset_battery_counter,
                        &hf_zbee_zcl_met_noti_flag_5_update_cin,
                        &hf_zbee_zcl_met_noti_flag_5_reserved,
                        NULL
                };

                proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_5, ett_zbee_zcl_met_noti_flags_5, noti_flags_5, ENC_LITTLE_ENDIAN);
                *offset += 4;
            }
            else {
                dissect_zcl_attr_data(tvb, tree, offset, data_type);
            }
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_met_attr_data*/

/**
 *ZigBee ZCL Metering cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_met(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_met_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_met_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_met, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_MET_REQUEST_MIRROR_RSP:
                    dissect_zcl_met_request_mirror_rsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_GET_SNAPSHOT:
                    dissect_zcl_met_get_snapshot(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_GET_SAMPLED_DATA:
                    dissect_zcl_met_get_sampled_data(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_LOCAL_CHANGE_SUPPLY:
                    dissect_zcl_met_local_change_supply(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_met_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_met_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_met, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_MET_REQUEST_MIRROR:
                    /* No payload */
                    break;

                case ZBEE_ZCL_CMD_ID_MET_PUBLISH_SNAPSHOT:
                    dissect_zcl_met_publish_snapshot(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_GET_SAMPLED_DATA_RSP:
                    dissect_zcl_met_get_sampled_data_rsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_CONFIGURE_MIRROR:
                    dissect_zcl_met_configure_mirror(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_GET_NOTIFIED_MESSAGE:
                    dissect_zcl_met_get_notified_msg(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_met*/

/**
 *This function manages the Request Mirror Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_request_mirror_rsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* EndPoint ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_request_mirror_rsp_endpoint_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_met_get_snapshot*/

/**
 *This function manages the Get Snapshot payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_get_snapshot(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;
    nstime_t end_time;
    gint rem_len = tvb_reported_length_remaining(tvb, *offset);

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_get_snapshot_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    if (rem_len > 9) {
        /* End Time - not part of SE 1.1b specification */
        end_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
        end_time.nsecs = 0;
        proto_tree_add_time(tree, hf_zbee_zcl_met_get_snapshot_end_time, tvb, *offset, 4, &end_time);
        *offset += 4;
    }

    /* Snapshot Offset */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_snapshot_snapshot_offset, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Snapshot Cause */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_snapshot_snapshot_cause, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_met_get_snapshot*/

/**
 *This function manages the Get Sampled Data payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_get_sampled_data(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t sample_time;

    /* Sample ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_sampled_data_sample_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Sample Start Time */
    sample_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    sample_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_get_sampled_data_sample_start_time, tvb, *offset, 4, &sample_time);
    *offset += 4;

    /* Sample Type */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_sampled_data_sample_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Number of Samples */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_sampled_data_number_of_samples, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_met_get_sampled_data*/

/**
 *This function manages the Local Change Supply payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_local_change_supply(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Proposed Supply Status */
    proto_tree_add_item(tree, hf_zbee_zcl_met_local_change_supply_supply_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
} /*dissect_zcl_met_local_change_supply*/

/**
 *This function manages the Publish Snapshot payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_publish_snapshot(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t snapshot_time;
    gint rem_len;

    /* Snapshot ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_snapshot_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Snapshot Time */
    snapshot_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    snapshot_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_publish_snapshot_snapshot_time, tvb, *offset, 4, &snapshot_time);
    *offset += 4;

    /* Total Snapshots Found */
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_snapshots_found, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_cmd_index, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_total_commands, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Snapshot Cause */
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_snapshot_cause, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Snapshot Payload Type */
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_snapshot_payload_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Snapshot Sub-Payload */
    rem_len = tvb_reported_length_remaining(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_snapshot_sub_payload, tvb, *offset, rem_len, ENC_NA);
    *offset += rem_len;
} /*dissect_zcl_met_publish_snapshot*/

/**
 *This function manages the Get Sampled Data Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_get_sampled_data_rsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t sample_start_time;
    gint rem_len;

    /* Snapshot ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_sampled_data_rsp_sample_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Sample Start Time */
    sample_start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    sample_start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_get_sampled_data_rsp_sample_start_time, tvb, *offset, 4, &sample_start_time);
    *offset += 4;

    /* Sample Type */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_sampled_data_rsp_sample_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Sample Request Interval */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_sampled_data_rsp_sample_request_interval, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Number of Samples */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_sampled_data_rsp_sample_number_of_samples, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Samples */
    rem_len = tvb_reported_length_remaining(tvb, *offset);
    while (rem_len >= 3) {
        guint32 val = tvb_get_guint24(tvb, *offset, ENC_LITTLE_ENDIAN);
        proto_tree_add_uint(tree, hf_zbee_zcl_met_get_sampled_data_rsp_sample_samples, tvb, *offset, 3, val);
        *offset += 3;
        rem_len -= 3;
    }
} /*dissect_zcl_met_get_sampled_data_rsp*/

/**
 *This function manages the Configure Mirror payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_configure_mirror(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_mirror_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Reporting Interval */
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_mirror_reporting_interval, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
    *offset += 3;

    /* Mirror Notification Reporting */
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_mirror_mirror_notification_reporting, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Notification Scheme */
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_mirror_notification_scheme, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
} /*dissect_zcl_met_configure_mirror*/

/**
 *This function manages the Get Notified Message payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_get_notified_msg(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Notification Scheme */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_notified_msg_notification_scheme, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Notification Flag attribute ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_notified_msg_notification_flag_attribute_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Notification Flags #N */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_notified_msg_notification_flags, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_met_get_notified_msg*/

/**
 *This function registers the ZCL Metering dissector
 *
*/
void
proto_register_zbee_zcl_met(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_met_attr_id,
            { "Attribute", "zbee_zcl_se.met.attr_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &zbee_zcl_met_attr_names_ext,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_met_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.met.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        /* Functional Notification Flags */
        { &hf_zbee_zcl_met_func_noti_flags,
            { "Functional Notification Flags", "zbee_zcl_se.met.attr.func_noti_flag", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_new_ota_firmware,
            { "New OTA Firmware", "zbee_zcl_se.met.attr.func_noti_flag.new_ota_firmware", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_NEW_OTA_FIRMWARE, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_cbke_update_request,
            { "CBKE Update Request", "zbee_zcl_se.met.attr.func_noti_flag.cbke_update_request", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_CBKE_UPDATE_REQUESTED, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_time_sync,
            { "Time Sync", "zbee_zcl_se.met.attr.func_noti_flag.time_sync", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_TIME_SYNC, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_stay_awake_request_han,
            { "Stay Awake Request HAN", "zbee_zcl_se.met.attr.func_noti_flag.stay_awake_request_han", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_STAY_AWAKE_REQUEST_HAN, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_stay_awake_request_wan,
            { "Stay Awake Request WAN", "zbee_zcl_se.met.attr.func_noti_flag.stay_awake_request_wan", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_STAY_AWAKE_REQUEST_WAN, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_push_historical_metering_data_attribute_set,
            { "Push Historical Metering Data Attribute Set", "zbee_zcl_se.met.attr.func_noti_flag.push_historical_metering_data_attribute_set", FT_UINT32, BASE_HEX, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_PUSH_HISTORICAL_METERING_DATA_ATTRIBUTE_SET, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_push_historical_prepayment_data_attribute_set,
            { "Push Historical Prepayment Data Attribute Set", "zbee_zcl_se.met.attr.func_noti_flag.push_historical_prepayment_data_attribute_set", FT_UINT32, BASE_HEX, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_PUSH_HISTORICAL_PREPAYMENT_DATA_ATTRIBUTE_SET, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_push_all_static_data_basic_cluster,
            { "Push All Static Data - Basic Cluster", "zbee_zcl_se.met.attr.func_noti_flag.push_all_static_data_basic_cluster", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_PUSH_ALL_STATIC_DATA_BASIC_CLUSTER, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_push_all_static_data_metering_cluster,
            { "Push All Static Data - Metering Cluster", "zbee_zcl_se.met.attr.func_noti_flag.push_all_static_data_metering_cluster", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_PUSH_ALL_STATIC_DATA_METERING_CLUSTER, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_push_all_static_data_prepayment_cluster,
            { "Push All Static Data - Prepayment Cluster", "zbee_zcl_se.met.attr.func_noti_flag.push_all_static_data_prepayment_cluster", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_PUSH_ALL_STATIC_DATA_PREPAYMENT_CLUSTER, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_network_key_active,
            { "Network Key Active", "zbee_zcl_se.met.attr.func_noti_flag.network_key_active", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_NETWORK_KEY_ACTIVE, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_display_message,
            { "Display Message", "zbee_zcl_se.met.attr.func_noti_flag.display_message", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_DISPLAY_MESSAGE, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_cancel_all_messages,
            { "Cancel All Messages", "zbee_zcl_se.met.attr.func_noti_flag.cancel_all_messages", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_CANCEL_ALL_MESSAGES, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_change_supply,
            { "Change Supply", "zbee_zcl_se.met.attr.func_noti_flag.change_supply", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_CHANGE_SUPPLY, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_local_change_supply,
            { "Local Change Supply", "zbee_zcl_se.met.attr.func_noti_flag.local_change_supply", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_LOCAL_CHANGE_SUPPLY, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_set_uncontrolled_flow_threshold,
            { "Set Uncontrolled Flow Threshold", "zbee_zcl_se.met.attr.func_noti_flag.set_uncontrolled_flow_threshold", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_SET_UNCONTROLLED_FLOW_THRESHOLD, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_tunnel_message_pending,
            { "Tunnel Message Pending", "zbee_zcl_se.met.attr.func_noti_flag.tunnel_message_pending", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_TUNNEL_MESSAGE_PENDING, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_get_snapshot,
            { "Get Snapshot", "zbee_zcl_se.met.attr.func_noti_flag.get_snapshot", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_GET_SNAPSHOT, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_get_sampled_data,
            { "Get Sampled Data", "zbee_zcl_se.met.attr.func_noti_flag.get_sampled_data", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_GET_SAMPLED_DATA, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_reserved,
            { "Reserved", "zbee_zcl_se.met.attr.func_noti_flag.reserved", FT_UINT32, BASE_HEX, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_RESERVED_1 | ZBEE_ZCL_FUNC_NOTI_FLAG_RESERVED_2, NULL, HFILL } },

        /* Notification Flags 2 */
        { &hf_zbee_zcl_met_noti_flags_2,
            { "Notification Flags 2", "zbee_zcl_se.met.attr.noti_flag_2", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_price,
            { "Publish Price", "zbee_zcl_se.met.attr.noti_flag_2.publish_price", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_PRICE, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_block_period,
            { "Publish Block Period", "zbee_zcl_se.met.attr.noti_flag_2.publish_block_period", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_BLOCK_PERIOD, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_tariff_info,
            { "Publish Tariff Information", "zbee_zcl_se.met.attr.noti_flag_2.publish_tariff_info", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_TARIFF_INFORMATION, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_conversion_factor,
            { "Publish Conversion Factor", "zbee_zcl_se.met.attr.noti_flag_2.publish_conversion_factor", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CONVERSION_FACTOR, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_calorific_value,
            { "Publish Calorific Value", "zbee_zcl_se.met.attr.noti_flag_2.publish_calorific_value", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CALORIFIC_VALUE, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_co2_value,
            { "Publish CO2 Value", "zbee_zcl_se.met.attr.noti_flag_2.publish_co2_value", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CO2_VALUE, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_billing_period,
            { "Publish Billing Period", "zbee_zcl_se.met.attr.noti_flag_2.publish_billing_period", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_BILLING_PERIOD, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_consolidated_bill,
            { "Publish Consolidated Bill", "zbee_zcl_se.met.attr.noti_flag_2.publish_consolidated_bill", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CONSOLIDATED_BILL, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_price_matrix,
            { "Publish Price Matrix", "zbee_zcl_se.met.attr.noti_flag_2.publish_price_matrix", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_PRICE_MATRIX, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_block_thresholds,
            { "Publish Block Thresholds", "zbee_zcl_se.met.attr.noti_flag_2.publish_block_thresholds", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_BLOCK_THRESHOLDS, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_currency_conversion,
            { "Publish Currency Conversion", "zbee_zcl_se.met.attr.noti_flag_2.publish_currency_conversion", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CURRENCY_CONVERSION, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_credit_payment_info,
            { "Publish Credit Payment Info", "zbee_zcl_se.met.attr.noti_flag_2.publish_credit_payment_info", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CREDIT_PAYMENT_INFO, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_cpp_event,
            { "Publish CPP Event", "zbee_zcl_se.met.attr.noti_flag_2.publish_cpp_event", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_CPP_EVENT, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_publish_tier_labels,
            { "Publish Tier Labels", "zbee_zcl_se.met.attr.noti_flag_2.publish_tier_labels", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_PUBLISH_TIER_LABELS, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_cancel_tariff,
            { "Cancel Tariff", "zbee_zcl_se.met.attr.noti_flag_2.cancel_tariff", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_CANCEL_TARIFF, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_2_reserved,
            { "Reserved", "zbee_zcl_se.met.attr.noti_flag_2.reserved", FT_UINT32, BASE_HEX, NULL,
            ZBEE_ZCL_NOTI_FLAG_2_RESERVED | ZBEE_ZCL_NOTI_FLAG_2_RESERVED_FUTURE, NULL, HFILL } },

        /* Notification Flags 3 */
        { &hf_zbee_zcl_met_noti_flags_3,
            { "Notification Flags 3", "zbee_zcl_se.met.attr.noti_flag_3", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_3_publish_calendar,
            { "Publish Calendar", "zbee_zcl_se.met.attr.noti_flag_3.publish_calendar", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_3_PUBLISH_CALENDAR, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_3_publish_special_days,
            { "Publish Special Days", "zbee_zcl_se.met.attr.noti_flag_3.publish_special_days", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_3_PUBLISH_SPECIAL_DAYS, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_3_publish_seasons,
            { "Publish Seasons", "zbee_zcl_se.met.attr.noti_flag_3.publish_seasons", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_3_PUBLISH_SEASONS, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_3_publish_week,
            { "Publish Week", "zbee_zcl_se.met.attr.noti_flag_3.publish_week", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_3_PUBLISH_WEEK, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_3_publish_day,
            { "Publish Day", "zbee_zcl_se.met.attr.noti_flag_3.publish_day", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_3_PUBLISH_DAY, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_3_cancel_calendar,
            { "Cancel Calendar", "zbee_zcl_se.met.attr.noti_flag_3.cancel_calendar", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_3_CANCEL_DAY, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_3_reserved,
            { "Reserved", "zbee_zcl_se.met.attr.noti_flag_3.reserved", FT_UINT32, BASE_HEX, NULL,
            ZBEE_ZCL_NOTI_FLAG_3_RESERVED , NULL, HFILL } },

        /* Notification Flags 4 */
        { &hf_zbee_zcl_met_noti_flags_4,
            { "Notification Flags 4", "zbee_zcl_se.met.attr.noti_flag_4", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_select_available_emergency_credit,
            { "Select Available Emergency Credit", "zbee_zcl_se.met.attr.noti_flag_4.select_available_emergency_credit", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_SELECT_AVAILABLE_EMERGENCY_CREDIT, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_change_debt,
            { "Change Debt", "zbee_zcl_se.met.attr.noti_flag_4.change_debt", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_CHANGE_DEBT, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_emergency_credit_setup,
            { "Emergency Credit Setup", "zbee_zcl_se.met.attr.noti_flag_4.emergency_credit_setup", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_EMERGENCY_CREDIT_SETUP, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_consumer_top_up,
            { "Consumer Top Up", "zbee_zcl_se.met.attr.noti_flag_4.consumer_top_up", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_CONSUMER_TOP_UP, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_credit_adjustment,
            { "Credit Adjustment", "zbee_zcl_se.met.attr.noti_flag_4.credit_adjustment", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_CREDIT_ADJUSTMENT, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_change_payment_mode,
            { "Change Payment Mode", "zbee_zcl_se.met.attr.noti_flag_4.change_payment_mode", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_CHANGE_PAYMENT_MODE, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_get_prepay_snapshot,
            { "Get Prepay Snapshot", "zbee_zcl_se.met.attr.noti_flag_4.get_prepay_snapshot", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_GET_PREPAY_SNAPSHOT, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_get_top_up_log,
            { "Get Top Up Log", "zbee_zcl_se.met.attr.noti_flag_4.get_top_up_log", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_GET_TOP_UP_LOG, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_set_low_credit_warning_level,
            { "Set Low Credit Warning Level", "zbee_zcl_se.met.attr.noti_flag_4.set_low_credit_warning_level", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_SET_LOW_CREDIT_WARNING_LEVEL, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_get_debt_repayment_log,
            { "Get Debt Repayment Log", "zbee_zcl_se.met.attr.noti_flag_4.get_debt_repayment_log", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_GET_DEBT_REPAYMENT_LOG, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_set_maximum_credit_limit,
            { "Set Maximum Credit Limit", "zbee_zcl_se.met.attr.noti_flag_4.set_maximum_credit_limit", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_SET_MAXIMUM_CREDIT_LIMIT, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_set_overall_debt_cap,
            { "Set Overall Debt Cap", "zbee_zcl_se.met.attr.noti_flag_4.set_overall_debt_cap", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_SET_OVERALL_DEBT_CAP, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_4_reserved,
            { "Reserved", "zbee_zcl_se.met.attr.noti_flag_4.reserved", FT_UINT32, BASE_HEX, NULL,
            ZBEE_ZCL_NOTI_FLAG_4_RESERVED, NULL, HFILL } },

        /* Notification Flags 5 */
        { &hf_zbee_zcl_met_noti_flags_5,
            { "Notification Flags 5", "zbee_zcl_se.met.attr.noti_flag_5", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_5_publish_change_of_tenancy,
            { "Publish Change of Tenancy", "zbee_zcl_se.met.attr.noti_flag_5.publish_change_of_tenancy", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_5_PUBLISH_CHANGE_OF_TENANCY, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_5_publish_change_of_supplier,
            { "Publish Change of Supplier", "zbee_zcl_se.met.attr.noti_flag_5.publish_change_of_supplier", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_5_PUBLISH_CHANGE_OF_SUPPLIER, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_5_request_new_password_1_response,
            { "Request New Password 1 Response", "zbee_zcl_se.met.attr.noti_flag_5.request_new_password_1_response", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_5_REQUEST_NEW_PASSWORD_1_RESPONSE, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_5_request_new_password_2_response,
            { "Request New Password 2 Response", "zbee_zcl_se.met.attr.noti_flag_5.request_new_password_2_response", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_5_REQUEST_NEW_PASSWORD_2_RESPONSE, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_5_request_new_password_3_response,
            { "Request New Password 3 Response", "zbee_zcl_se.met.attr.noti_flag_5.request_new_password_3_response", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_5_REQUEST_NEW_PASSWORD_3_RESPONSE, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_5_request_new_password_4_response,
            { "Request New Password 4 Response", "zbee_zcl_se.met.attr.noti_flag_5.request_new_password_4_response", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_5_REQUEST_NEW_PASSWORD_4_RESPONSE, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_5_update_site_id,
            { "Update Site ID", "zbee_zcl_se.met.attr.noti_flag_5.update_site_id", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_5_UPDATE_SITE_ID, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_5_reset_battery_counter,
            { "Reset Battery Counter", "zbee_zcl_se.met.attr.noti_flag_5.reset_battery_counter", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_5_RESET_BATTERY_COUNTER, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_5_update_cin,
            { "Update CIN", "zbee_zcl_se.met.attr.noti_flag_5.update_cin", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_NOTI_FLAG_5_UPDATE_CIN, NULL, HFILL } },

        { &hf_zbee_zcl_met_noti_flag_5_reserved,
            { "Reserved", "zbee_zcl_se.met.attr.noti_flag_5.reserved", FT_UINT32, BASE_HEX, NULL,
            ZBEE_ZCL_NOTI_FLAG_5_RESERVED, NULL, HFILL } },

        { &hf_zbee_zcl_met_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.met.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_met_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.met.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_met_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_request_mirror_rsp_endpoint_id,
            { "EndPoint ID", "zbee_zcl_se.met.request_mirror_rsp.endpoint_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_snapshot_start_time,
            { "Start Time", "zbee_zcl_se.met.get_snapshot.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_snapshot_end_time,
            { "End Time", "zbee_zcl_se.met.get_snapshot.end_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_snapshot_snapshot_offset,
            { "Snapshot Offset", "zbee_zcl_se.met.get_snapshot.snapshot_offset", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_snapshot_snapshot_cause,
            { "Snapshot Cause", "zbee_zcl_se.met.get_snapshot.snapshot_cause", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_sampled_data_sample_id,
            { "Sample ID", "zbee_zcl_se.met.get_sampled_data.sample_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_sampled_data_sample_start_time,
            { "Sample Start Time", "zbee_zcl_se.met.get_sampled_data.sample_start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_sampled_data_sample_type,
            { "Sample Type", "zbee_zcl_se.met.get_sampled_data.sample_type", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_sampled_data_number_of_samples,
            { "Number of Samples", "zbee_zcl_se.met.get_sampled_data.number_of_samples", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_local_change_supply_supply_status,
            { "Proposed Supply Status", "zbee_zcl_se.met.local_change_supply.supply_status", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_publish_snapshot_snapshot_id,
            { "Snapshot ID", "zbee_zcl_se.met.publish_snapshot.snapshot_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_publish_snapshot_snapshot_time,
            { "Snapshot Time", "zbee_zcl_se.met.publish_snapshot.snapshot_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_publish_snapshot_snapshots_found,
            { "Total Snapshots Found", "zbee_zcl_se.met.publish_snapshot.snapshots_found", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_publish_snapshot_cmd_index,
            { "Command Index", "zbee_zcl_se.met.publish_snapshot.command_index", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_publish_snapshot_total_commands,
            { "Total Number of Commands", "zbee_zcl_se.met.publish_snapshot.total_commands", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_publish_snapshot_snapshot_cause,
            { "Snapshot Cause", "zbee_zcl_se.met.publish_snapshot.snapshot_cause", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_publish_snapshot_snapshot_payload_type,
            { "Snapshot Payload Type", "zbee_zcl_se.met.publish_snapshot.payload_type", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_publish_snapshot_snapshot_sub_payload,
            { "Snapshot Sub-Payload", "zbee_zcl_se.met.publish_snapshot.sub_payload", FT_BYTES, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_sampled_data_rsp_sample_id,
            { "Sample ID", "zbee_zcl_se.met.get_sampled_data_rsp.sample_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_sampled_data_rsp_sample_start_time,
            { "Sample Start Time", "zbee_zcl_se.met.get_sampled_data_rsp.sample_start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_sampled_data_rsp_sample_type,
            { "Sample Type", "zbee_zcl_se.met.get_sampled_data_rsp.sample_type", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_sampled_data_rsp_sample_request_interval,
            { "Sample Request Interval", "zbee_zcl_se.met.get_sampled_data_rsp.sample_request_interval", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_sampled_data_rsp_sample_number_of_samples,
            { "Number of Samples", "zbee_zcl_se.met.get_sampled_data_rsp.number_of_samples", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_sampled_data_rsp_sample_samples,
            { "Samples", "zbee_zcl_se.met.get_sampled_data_rsp.samples", FT_UINT24, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_mirror_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.configure_mirror.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_mirror_reporting_interval,
            { "Reporting Interval", "zbee_zcl_se.met.configure_mirror.reporting_interval", FT_UINT24, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_mirror_mirror_notification_reporting,
            { "Mirror Notification Reporting", "zbee_zcl_se.met.configure_mirror.mirror_notification_reporting", FT_BOOLEAN, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_mirror_notification_scheme,
            { "Notification Scheme", "zbee_zcl_se.met.configure_mirror.notification_scheme", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_notified_msg_notification_scheme,
            { "Notification Scheme", "zbee_zcl_se.met.get_notified_msg.notification_scheme", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_notified_msg_notification_flag_attribute_id,
            { "Notification Flag attribute ID", "zbee_zcl_se.met.get_notified_msg.notification_flag_attribute_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_notified_msg_notification_flags,
            { "Notification Flags", "zbee_zcl_se.met.get_notified_msg.notification_flags", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } }
    };

    /* ZCL Metering subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_met,
        &ett_zbee_zcl_met_func_noti_flags,
        &ett_zbee_zcl_met_noti_flags_2,
        &ett_zbee_zcl_met_noti_flags_3,
        &ett_zbee_zcl_met_noti_flags_4,
        &ett_zbee_zcl_met_noti_flags_5
    };

    /* Register the ZigBee ZCL Metering cluster protocol name and description */
    proto_zbee_zcl_met = proto_register_protocol("ZigBee ZCL Metering", "ZCL Metering", ZBEE_PROTOABBREV_ZCL_MET);
    proto_register_field_array(proto_zbee_zcl_met, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Metering dissector. */
    met_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_MET, dissect_zbee_zcl_met, proto_zbee_zcl_met);
} /*proto_register_zbee_zcl_met*/

/**
 *Hands off the ZCL Metering dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_met(void)
{
    /* Register our dissector with the ZigBee application dissectors. */
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_SIMPLE_METERING, met_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_met,
                            ett_zbee_zcl_met,
                            ZBEE_ZCL_CID_SIMPLE_METERING,
                            hf_zbee_zcl_met_attr_id,
                            hf_zbee_zcl_met_srv_rx_cmd_id,
                            hf_zbee_zcl_met_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_met_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_met*/

/* ########################################################################## */
/* #### (0x0703) MESSAGING CLUSTER ########################################## */
/* ########################################################################## */

/* Attributes - None (other than Attribute Reporting Status) */
#define zbee_zcl_msg_attr_names_VALUE_STRING_LIST(XXX) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_MSG,     0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_msg_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_msg_attr_names);

/* Server Commands Received */
#define zbee_zcl_msg_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_MSG_GET_LAST_MSG,               0x00, "Get Last Message" ) \
    XXX(ZBEE_ZCL_CMD_ID_MSG_MSG_CONFIRM,                0x01, "Message Confirmation" ) \
    XXX(ZBEE_ZCL_CMD_ID_MSG_GET_MESSAGE_CANCEL,         0x02, "Get Message Cancellation" )

VALUE_STRING_ENUM(zbee_zcl_msg_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_msg_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_msg_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_MSG_DISPLAY_MSG,                0x00, "Display Message" ) \
    XXX(ZBEE_ZCL_CMD_ID_MSG_CANCEL_MSG,                 0x01, "Cancel Message" ) \
    XXX(ZBEE_ZCL_CMD_ID_MSG_DISPLAY_PROTECTED_MSG,      0x02, "Display Protected Message" ) \
    XXX(ZBEE_ZCL_CMD_ID_MSG_CANCEL_ALL_MSG,             0x03, "Cancel All Messages" )

VALUE_STRING_ENUM(zbee_zcl_msg_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_msg_srv_tx_cmd_names);

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

static dissector_handle_t msg_handle;

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
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_MSG:
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
        proto_tree_add_uint(tree, hf_zbee_zcl_msg_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

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
        proto_tree_add_uint(tree, hf_zbee_zcl_msg_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

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
 *This function manages the Cancel All Messages payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_msg_cancel_all(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t impl_time;

    /* Implementation Date/Time */
    impl_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    impl_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_msg_implementation_time, tvb, *offset, 4, &impl_time);
    *offset += 4;

} /* dissect_zcl_msg_cancel_all */

/**
 *This function manages the Get Message Cancellation payload
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
    impl_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
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

    /* Message ID */
    proto_tree_add_item(tree, hf_zbee_zcl_msg_message_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Confirmation Time */
    confirm_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
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
 * This function decodes start time, with a special case for
 * ZBEE_ZCL_MSG_START_TIME_NOW.
 *
 * @param s string to display
 * @param value value to decode
*/
static void
decode_zcl_msg_start_time(gchar *s, guint32 value)
{
    if (value == ZBEE_ZCL_MSG_START_TIME_NOW)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Now");
    else {
        gchar *start_time;
        time_t epoch_time = (time_t)value + ZBEE_ZCL_NSTIME_UTC_OFFSET;
        start_time = abs_time_secs_to_str (NULL, epoch_time, ABSOLUTE_TIME_LOCAL, TRUE);
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
    msg_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_MSG, dissect_zbee_zcl_msg, proto_zbee_zcl_msg);
} /*proto_register_zbee_zcl_msg*/

/**
 *Hands off the ZCL Messaging dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_msg(void)
{
    /* Register our dissector with the ZigBee application dissectors. */
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
#define zbee_zcl_tun_attr_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_ATTR_ID_TUN_CLOSE_TIMEOUT,                     0x0000, "Close Tunnel Timeout" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_TUN,             0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_tun_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_tun_attr_names);

/* Server Commands Received */
#define zbee_zcl_tun_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_REQUEST_TUNNEL,                     0x00, "Request Tunnel" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_CLOSE_TUNNEL,                       0x01, "Close Tunnel" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA,                      0x02, "Transfer Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_ERROR,                0x03, "Transfer Data Error" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_ACK_TRANSFER_DATA,                  0x04, "Ack Transfer Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_READY_DATA,                         0x05, "Ready Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_GET_SUPPORTED_PROTOCOLS,            0x06, "Get Supported Protocols" )

VALUE_STRING_ENUM(zbee_zcl_tun_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_tun_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_tun_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_REQUEST_TUNNEL_RSP,                 0x00, "Request Tunnel Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_TX,                   0x01, "Transfer Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_ERROR_TX,             0x02, "Transfer Data Error" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_ACK_TRANSFER_DATA_TX,               0x03, "Ack Transfer Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_READY_DATA_TX,                      0x04, "Ready Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_GET_SUPPORTED_PROTOCOLS_RSP,        0x05, "Get Supported Tunnel Protocols" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_CLOSURE_NOTIFY,                     0x06, "Tunnel Closure Notification" )

VALUE_STRING_ENUM(zbee_zcl_tun_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_tun_srv_tx_cmd_names);

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

static dissector_handle_t tun_handle;

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

#define zbee_zcl_tun_protocol_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_TUN_PROTO_DLMS,                                0x00, "DLMS/COSEM (IEC 62056)" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_IEC_61107,                           0x01, "IEC 61107" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_ANSI_C12,                            0x02, "ANSI C12" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_M_BUS,                               0x03, "M-BUS" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_SML,                                 0x04, "SML" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_CLIMATE_TALK,                        0x05, "ClimateTalk" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_GB_HRGP,                             0x06, "GB-HRGP" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_IPV6,                                0x07, "IPv6" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_IPV4,                                0x08, "IPv4" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_NULL,                                0x09, "null" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_TEST,                                 199, "test" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_MANUFACTURER,                         200, "Manufacturer Specific" ) \
    XXX(ZBEE_ZCL_TUN_PROTO_RESERVED,                            0xFF, "Reserved" )

VALUE_STRING_ENUM(zbee_zcl_tun_protocol_names);
VALUE_STRING_ARRAY(zbee_zcl_tun_protocol_names);

#define zbee_zcl_tun_trans_data_status_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_TUN_TRANS_STATUS_NO_TUNNEL,                    0x00, "Tunnel ID Does Not Exist" ) \
    XXX(ZBEE_ZCL_TUN_TRANS_STATUS_WRONG_DEV,                    0x01, "Wrong Device" ) \
    XXX(ZBEE_ZCL_TUN_TRANS_STATUS_OVERFLOW,                     0x02, "Data Overflow" )

VALUE_STRING_ENUM(zbee_zcl_tun_trans_data_status_names);
VALUE_STRING_ARRAY(zbee_zcl_tun_trans_data_status_names);

#define zbee_zcl_tun_status_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_TUN_STATUS_SUCCESS,                            0x00, "Success" ) \
    XXX(ZBEE_ZCL_TUN_STATUS_BUSY,                               0x01, "Busy" ) \
    XXX(ZBEE_ZCL_TUN_STATUS_NO_MORE_IDS,                        0x02, "No More Tunnel IDs" ) \
    XXX(ZBEE_ZCL_TUN_STATUS_PROTO_NOT_SUPP,                     0x03, "Protocol Not Supported" ) \
    XXX(ZBEE_ZCL_TUN_STATUS_FLOW_CONTROL_NOT_SUPP,              0x04, "Flow Control Not Supported" )

VALUE_STRING_ENUM(zbee_zcl_tun_status_names);
VALUE_STRING_ARRAY(zbee_zcl_tun_status_names);

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
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_TUN:
            proto_tree_add_item(tree, hf_zbee_zcl_tun_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_ias_zone_attr_data*/

/**
 *This function manages the Request Tunnel payload
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
 *This function manages the Close Tunnel payload
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
 *This function manages the Transfer Data payload
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
 *This function manages the Transfer Data Error payload
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
 *This function manages the Ack Transfer Data payload
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
 *This function manages the Ready Data payload
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
 *This function manages the Get Supported Tunnel Protocols payload
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
 *This function manages the Request Tunnel Response payload
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
 *This function manages the Supported Tunnel Protocols Response payload
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
 *This function manages the Tunnel Closure Notification payload
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
 *ZigBee ZCL Tunneling cluster dissector for wireshark.
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
        proto_tree_add_uint(tree, hf_zbee_zcl_tun_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

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
        proto_tree_add_uint(tree, hf_zbee_zcl_tun_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

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
 *This function registers the ZCL Tunneling dissector
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

    /* ZCL Tunneling subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_tun,
    };

    /* Register the ZigBee ZCL Tunneling cluster protocol name and description */
    proto_zbee_zcl_tun = proto_register_protocol("ZigBee ZCL Tunneling", "ZCL Tunneling", ZBEE_PROTOABBREV_ZCL_TUN);
    proto_register_field_array(proto_zbee_zcl_tun, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Tunneling dissector. */
    tun_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_TUN, dissect_zbee_zcl_tun, proto_zbee_zcl_tun);

} /* proto_register_zbee_zcl_tun */

/**
 *Hands off the ZCL Tunneling dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_tun(void)
{
    ipv4_handle = find_dissector("ipv4");
    ipv6_handle = find_dissector("ipv6");

    /* Register our dissector with the ZigBee application dissectors. */
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_TUNNELING, tun_handle);

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
/* #### (0x0705) PREPAYMENT CLUSTER ########################################## */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_pp_attr_names_VALUE_STRING_LIST(XXX) \
/* Prepayment Information Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PAYMENT_CONTROL_CONFIGURATION,      0x0000, "Payment Control Configuration" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CREDIT_REMAINING,                   0x0001, "Credit Remaining" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_EMERGENCY_CREDIT_REMAINING,         0x0002, "Emergency Credit Remaining" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_ACCUMULATED_DEBT,                   0x0005, "Accumulated Debt" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_OVERALL_DEBT_CAP,                   0x0006, "Overall Debt Cap" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_EMERGENCY_CREDIT_LIMIT,             0x0010, "Emergency Credit Limit / Allowance" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_EMERGENCY_CREDIT_THRESHOLD,         0x0011, "Emergency Credit Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_MAX_CREDIT_LIMIT,                   0x0021, "Max Credit Limit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_MAX_CREDIT_PER_TOPUP,               0x0022, "Max Credit Per Top Up" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_LOW_CREDIT_WARNING,                 0x0031, "Low Credit Warning" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CUT_OFF_VALUE,                      0x0040, "Cut Off Value" ) \
/* Debt Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_AMOUNT_1,                      0x0211, "Debt Amount 1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_FREQ_1,               0x0216, "Debt Recovery Frequency 1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_AMOUNT_1,             0x0217, "Debt Recovery Amount 1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_TOP_UP_PERCENTAGE_1,  0x0219, "Debt Recovery Top Up Percentage 1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_AMOUNT_2,                      0x0221, "Debt Amount 2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_FREQ_2,               0x0226, "Debt Recovery Frequency 2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_AMOUNT_2,             0x0227, "Debt Recovery Amount 2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_TOP_UP_PERCENTAGE_2,  0x0229, "Debt Recovery Top Up Percentage 2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_AMOUNT_3,                      0x0231, "Debt Amount 3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_FREQ_3,               0x0236, "Debt Recovery Frequency 3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_AMOUNT_3,             0x0237, "Debt Recovery Amount 3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_TOP_UP_PERCENTAGE_3,  0x0239, "Debt Recovery Top Up Percentage 3" ) \
/* Alarm Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREPAYMENT_ALARM_STATUS,            0x0400, "Prepayment Alarm Status" ) \
/* Historical Cost Consumption Information Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PP_HISTORICAL_COST_CON_FORMAT,         0x0500, "Historical Cost Consumption Formatting" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CONSUMPTION_UNIT_OF_MEASUREMENT,    0x0501, "Consumption Unit of Measurement" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENCY_SCALING_FACTOR,            0x0502, "Currency Scaling Factor" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENCY,                           0x0503, "Currency" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENT_DAY_COST_CON_DELIVERED,     0x051C, "Current Day Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_COST_CON_DELIVERED,    0x051E, "Previous Day Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_2_COST_CON_DELIVERED,  0x0520, "Previous Day 2 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_3_COST_CON_DELIVERED,  0x0522, "Previous Day 3 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_4_COST_CON_DELIVERED,  0x0524, "Previous Day 4 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_5_COST_CON_DELIVERED,  0x0526, "Previous Day 5 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_6_COST_CON_DELIVERED,  0x0528, "Previous Day 6 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_7_COST_CON_DELIVERED,  0x052A, "Previous Day 7 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_8_COST_CON_DELIVERED,  0x052C, "Previous Day 8 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENT_WEEK_COST_CON_DELIVERED,    0x0530, "Current Week Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_COST_CON_DELIVERED,   0x0532, "Previous Week Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_2_COST_CON_DELIVERED, 0x0534, "Previous Week 2 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_3_COST_CON_DELIVERED, 0x0536, "Previous Week 3 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_4_COST_CON_DELIVERED, 0x0538, "Previous Week 4 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_5_COST_CON_DELIVERED, 0x053A, "Previous Week 5 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENT_MON_COST_CON_DELIVERED,     0x0540, "Current Month Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_COST_CON_DELIVERED,    0x0542, "Previous Month Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_2_COST_CON_DELIVERED,  0x0544, "Previous Month 2 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_3_COST_CON_DELIVERED,  0x0546, "Previous Month 3 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_4_COST_CON_DELIVERED,  0x0548, "Previous Month 4 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_5_COST_CON_DELIVERED,  0x054A, "Previous Month 5 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_6_COST_CON_DELIVERED,  0x054C, "Previous Month 6 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_7_COST_CON_DELIVERED,  0x054E, "Previous Month 7 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_8_COST_CON_DELIVERED,  0x0550, "Previous Month 8 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_9_COST_CON_DELIVERED,  0x0552, "Previous Month 9 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_10_COST_CON_DELIVERED, 0x0554, "Previous Month 10 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_11_COST_CON_DELIVERED, 0x0556, "Previous Month 11 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_12_COST_CON_DELIVERED, 0x0558, "Previous Month 12 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_13_COST_CON_DELIVERED, 0x055A, "Previous Month 13 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_HISTORICAL_FREEZE_TIME,             0x055C, "Historical Freeze Time" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_PP,              0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_pp_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_pp_attr_names);
static value_string_ext zbee_zcl_pp_attr_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_pp_attr_names);

/* Server Commands Received */
#define zbee_zcl_pp_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_PP_SELECT_AVAILABLE_EMERGENCY_CREDIT,   0x00, "Select Available Emergency Credit" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_CHANGE_DEBT,                         0x02, "Change Debt" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_EMERGENCY_CREDIT_SETUP,              0x03, "Emergency Credit Setup" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_CONSUMER_TOP_UP,                     0x04, "Consumer Top Up" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_CREDIT_ADJUSTMENT,                   0x05, "Credit Adjustment" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_CHANGE_PAYMENT_MODE,                 0x06, "Change Payment Mode" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_GET_PREPAY_SNAPTSHOT,                0x07, "Get Prepay Snapshot" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_GET_TOP_UP_LOG,                      0x08, "Get Top Up Log" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_SET_LOW_CREDIT_WARNING_LEVEL,        0x09, "Set Low Credit Warning Level" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_GET_DEBT_REPAYMENT_LOG,              0x0A, "Get Debt Repayment Log" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_SET_MAXIMUM_CREDIT_LIMIT,            0x0B, "Set Maximum Credit Limit" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_SET_OVERALL_DEBT_CAP,                0x0C, "Set Overall Debt Cap" )

VALUE_STRING_ENUM(zbee_zcl_pp_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_pp_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_pp_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_PP_PUBLISH_PREPAY_SNAPSHOT,             0x01, "Publish Prepay Snapshot" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_CHANGE_PAYMENT_MODE_RESPONSE,        0x02, "Change Payment Mode Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_CONSUMER_TOP_UP_RESPONSE,            0x03, "Consumer Top Up Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_PUBLISH_TOP_UP_LOG,                  0x05, "Publish Top Up Log" ) \
    XXX(ZBEE_ZCL_CMD_ID_PP_PUBLISH_DEBT_LOG,                    0x06, "Publish Debt Log" )

VALUE_STRING_ENUM(zbee_zcl_pp_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_pp_srv_tx_cmd_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_pp(void);
void proto_reg_handoff_zbee_zcl_pp(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_pp_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Command Dissector Helpers */
static void dissect_zcl_pp_select_available_emergency_credit    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_change_debt                          (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_emergency_credit_setup               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_consumer_top_up                      (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_credit_adjustment                    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_change_payment_mode                  (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_get_prepay_snapshot                  (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_get_top_up_log                       (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_set_low_credit_warning_level         (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_get_debt_repayment_log               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_set_maximum_credit_limit             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_set_overall_debt_cap                 (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_publish_prepay_snapshot              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_change_payment_mode_response         (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_consumer_top_up_response             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_publish_top_up_log                   (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_pp_publish_debt_log                     (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

static dissector_handle_t pp_handle;

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_pp = -1;

static int hf_zbee_zcl_pp_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_pp_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_pp_attr_id = -1;
static int hf_zbee_zcl_pp_attr_reporting_status = -1;
static int hf_zbee_zcl_pp_select_available_emc_cmd_issue_date_time = -1;
static int hf_zbee_zcl_pp_select_available_emc_originating_device = -1;
static int hf_zbee_zcl_pp_change_debt_issuer_event_id = -1;
static int hf_zbee_zcl_pp_change_debt_label = -1;
static int hf_zbee_zcl_pp_change_debt_amount = -1;
static int hf_zbee_zcl_pp_change_debt_recovery_method = -1;
static int hf_zbee_zcl_pp_change_debt_amount_type = -1;
static int hf_zbee_zcl_pp_change_debt_recovery_start_time = -1;
static int hf_zbee_zcl_pp_change_debt_recovery_collection_time = -1;
static int hf_zbee_zcl_pp_change_debt_recovery_frequency = -1;
static int hf_zbee_zcl_pp_change_debt_recovery_amount = -1;
static int hf_zbee_zcl_pp_change_debt_recovery_balance_percentage = -1;
static int hf_zbee_zcl_pp_emergency_credit_setup_issuer_event_id = -1;
static int hf_zbee_zcl_pp_emergency_credit_setup_start_time = -1;
static int hf_zbee_zcl_pp_emergency_credit_setup_emergency_credit_limit = -1;
static int hf_zbee_zcl_pp_emergency_credit_setup_emergency_credit_threshold = -1;
static int hf_zbee_zcl_pp_consumer_top_up_originating_device = -1;
static int hf_zbee_zcl_pp_consumer_top_up_top_up_code_len = -1;
static int hf_zbee_zcl_pp_consumer_top_up_top_up_code = -1;
static int hf_zbee_zcl_pp_credit_adjustment_issuer_event_id = -1;
static int hf_zbee_zcl_pp_credit_adjustment_start_time = -1;
static int hf_zbee_zcl_pp_credit_adjustment_credit_adjustment_type = -1;
static int hf_zbee_zcl_pp_credit_adjustment_credit_adjustment_value = -1;
static int hf_zbee_zcl_pp_change_payment_mode_provider_id = -1;
static int hf_zbee_zcl_pp_change_payment_mode_issuer_event_id = -1;
static int hf_zbee_zcl_pp_change_payment_mode_implementation_date_time = -1;
static int hf_zbee_zcl_pp_change_payment_mode_proposed_payment_control_configuration = -1;
static int hf_zbee_zcl_pp_change_payment_mode_cut_off_value = -1;
static int hf_zbee_zcl_pp_get_prepay_snapshot_earliest_start_time = -1;
static int hf_zbee_zcl_pp_get_prepay_snapshot_latest_end_time = -1;
static int hf_zbee_zcl_pp_get_prepay_snapshot_snapshot_offset = -1;
static int hf_zbee_zcl_pp_get_prepay_snapshot_snapshot_cause = -1;
static int hf_zbee_zcl_pp_get_top_up_log_latest_end_time = -1;
static int hf_zbee_zcl_pp_get_top_up_log_number_of_records = -1;
static int hf_zbee_zcl_pp_set_low_credit_warning_level_low_credit_warning_level = -1;
static int hf_zbee_zcl_pp_get_debt_repayment_log_latest_end_time = -1;
static int hf_zbee_zcl_pp_get_debt_repayment_log_number_of_debts = -1;
static int hf_zbee_zcl_pp_get_debt_repayment_log_debt_type = -1;
static int hf_zbee_zcl_pp_set_maximum_credit_limit_provider_id = -1;
static int hf_zbee_zcl_pp_set_maximum_credit_limit_issuer_event_id = -1;
static int hf_zbee_zcl_pp_set_maximum_credit_limit_implementation_date_time = -1;
static int hf_zbee_zcl_pp_set_maximum_credit_limit_maximum_credit_level = -1;
static int hf_zbee_zcl_pp_set_maximum_credit_limit_maximum_credit_per_top_up = -1;
static int hf_zbee_zcl_pp_set_overall_debt_cap_limit_provider_id = -1;
static int hf_zbee_zcl_pp_set_overall_debt_cap_limit_issuer_event_id = -1;
static int hf_zbee_zcl_pp_set_overall_debt_cap_limit_implementation_date_time = -1;
static int hf_zbee_zcl_pp_set_overall_debt_cap_limit_overall_debt_cap = -1;
static int hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_id = -1;
static int hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_time = -1;
static int hf_zbee_zcl_pp_publish_prepay_snapshot_total_snapshots_found = -1;
static int hf_zbee_zcl_pp_publish_prepay_snapshot_command_index = -1;
static int hf_zbee_zcl_pp_publish_prepay_snapshot_total_number_of_commands = -1;
static int hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_cause = -1;
static int hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_payload_type = -1;
static int hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_payload = -1;
static int hf_zbee_zcl_pp_change_payment_mode_response_friendly_credit = -1;
static int hf_zbee_zcl_pp_change_payment_mode_response_friendly_credit_calendar_id = -1;
static int hf_zbee_zcl_pp_change_payment_mode_response_emergency_credit_limit = -1;
static int hf_zbee_zcl_pp_change_payment_mode_response_emergency_credit_threshold = -1;
static int hf_zbee_zcl_pp_consumer_top_up_response_result_type = -1;
static int hf_zbee_zcl_pp_consumer_top_up_response_top_up_value = -1;
static int hf_zbee_zcl_pp_consumer_top_up_response_source_of_top_up = -1;
static int hf_zbee_zcl_pp_consumer_top_up_response_credit_remaining = -1;
static int hf_zbee_zcl_pp_publish_top_up_log_command_index = -1;
static int hf_zbee_zcl_pp_publish_top_up_log_total_number_of_commands = -1;
static int hf_zbee_zcl_pp_publish_top_up_log_top_up_code_len = -1;
static int hf_zbee_zcl_pp_publish_top_up_log_top_up_code = -1;
static int hf_zbee_zcl_pp_publish_top_up_log_top_up_amount = -1;
static int hf_zbee_zcl_pp_publish_top_up_log_top_up_time = -1;
static int hf_zbee_zcl_pp_publish_debt_log_command_index = -1;
static int hf_zbee_zcl_pp_publish_debt_log_total_number_of_commands = -1;
static int hf_zbee_zcl_pp_publish_debt_log_collection_time = -1;
static int hf_zbee_zcl_pp_publish_debt_log_amount_collected = -1;
static int hf_zbee_zcl_pp_publish_debt_log_debt_type = -1;
static int hf_zbee_zcl_pp_publish_debt_log_outstanding_debt = -1;

/* Initialize the subtree pointers */
#define ZBEE_ZCL_SE_PP_NUM_INDIVIDUAL_ETT             3
#define ZBEE_ZCL_SE_PP_NUM_PUBLISH_TOP_UP_LOG_ETT     30
#define ZBEE_ZCL_SE_PP_NUM_PUBLISH_DEBT_LOG_ETT       30
#define ZBEE_ZCL_SE_PP_NUM_TOTAL_ETT                  (ZBEE_ZCL_SE_PP_NUM_INDIVIDUAL_ETT + \
                                                       ZBEE_ZCL_SE_PP_NUM_PUBLISH_TOP_UP_LOG_ETT + \
                                                       ZBEE_ZCL_SE_PP_NUM_PUBLISH_DEBT_LOG_ETT)

static gint ett_zbee_zcl_pp = -1;
static gint ett_zbee_zcl_pp_consumer_top_up_top_up_code = -1;
static gint ett_zbee_zcl_pp_publish_top_up_log_top_up_code = -1;
static gint ett_zbee_zcl_pp_publish_top_up_entry[ZBEE_ZCL_SE_PP_NUM_PUBLISH_TOP_UP_LOG_ETT];
static gint ett_zbee_zcl_pp_publish_debt_log_entry[ZBEE_ZCL_SE_PP_NUM_PUBLISH_DEBT_LOG_ETT];

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
dissect_zcl_pp_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_PP:
            proto_tree_add_item(tree, hf_zbee_zcl_pp_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_pp_attr_data*/

/**
 *ZigBee ZCL Prepayment cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_pp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_pp_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_pp_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_pp, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_PP_SELECT_AVAILABLE_EMERGENCY_CREDIT:
                    dissect_zcl_pp_select_available_emergency_credit(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_CHANGE_DEBT:
                    dissect_zcl_pp_change_debt(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_EMERGENCY_CREDIT_SETUP:
                    dissect_zcl_pp_emergency_credit_setup(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_CONSUMER_TOP_UP:
                    dissect_zcl_pp_consumer_top_up(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_CREDIT_ADJUSTMENT:
                    dissect_zcl_pp_credit_adjustment(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_CHANGE_PAYMENT_MODE:
                    dissect_zcl_pp_change_payment_mode(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_GET_PREPAY_SNAPTSHOT:
                    dissect_zcl_pp_get_prepay_snapshot(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_GET_TOP_UP_LOG:
                    dissect_zcl_pp_get_top_up_log(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_SET_LOW_CREDIT_WARNING_LEVEL:
                    dissect_zcl_pp_set_low_credit_warning_level(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_GET_DEBT_REPAYMENT_LOG:
                    dissect_zcl_pp_get_debt_repayment_log(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_SET_MAXIMUM_CREDIT_LIMIT:
                    dissect_zcl_pp_set_maximum_credit_limit(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_SET_OVERALL_DEBT_CAP:
                    dissect_zcl_pp_set_overall_debt_cap(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_pp_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_pp_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_pp, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_PP_PUBLISH_PREPAY_SNAPSHOT:
                    dissect_zcl_pp_publish_prepay_snapshot(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_CHANGE_PAYMENT_MODE_RESPONSE:
                    dissect_zcl_pp_change_payment_mode_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_CONSUMER_TOP_UP_RESPONSE:
                    dissect_zcl_pp_consumer_top_up_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_PUBLISH_TOP_UP_LOG:
                    dissect_zcl_pp_publish_top_up_log(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PP_PUBLISH_DEBT_LOG:
                    dissect_zcl_pp_publish_debt_log(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_pp*/

/**
 *This function manages the Select Available Emergency Credit payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_select_available_emergency_credit(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Command Issue Date/Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_select_available_emc_cmd_issue_date_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Originating Device */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_select_available_emc_originating_device, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_pp_select_available_emergency_credit*/

/**
 *This function manages the Change Debt payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_change_debt(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8 label_length;
    nstime_t start_time;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_debt_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Debt Label */
    label_length = tvb_get_guint8(tvb, *offset) + 1;
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_debt_label, tvb, *offset, label_length, ENC_NA);
    *offset += label_length;

    /* Debt Amount */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_debt_amount, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Debt Recovery Method */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_debt_recovery_method, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Debt Amount Type */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_debt_amount_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Debt Recovery Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_change_debt_recovery_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Debt Recovery Collection Time */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_debt_recovery_collection_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Debt Recovery Frequency */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_debt_recovery_frequency, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Debt Recovery Amount */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_debt_recovery_amount, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Debt Recovery Balance Percentage */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_debt_recovery_balance_percentage, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_pp_change_debt*/

/**
 *This function manages the Select Available Emergency Credit payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_emergency_credit_setup(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_emergency_credit_setup_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_emergency_credit_setup_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Emergency Credit Limit */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_emergency_credit_setup_emergency_credit_limit, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Emergency Credit Threshold */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_emergency_credit_setup_emergency_credit_threshold, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_pp_emergency_credit_setup*/

/**
 *This function manages the Consumer Top Up payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_consumer_top_up(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Originating Device */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_consumer_top_up_originating_device, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* TopUp Code */
    dissect_zcl_octet_string(tvb, tree, offset,
            ett_zbee_zcl_pp_consumer_top_up_top_up_code,
            hf_zbee_zcl_pp_consumer_top_up_top_up_code_len,
            hf_zbee_zcl_pp_consumer_top_up_top_up_code);
} /*dissect_zcl_pp_consumer_top_up*/

/**
 *This function manages the Credit Adjustment payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_credit_adjustment(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_credit_adjustment_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_credit_adjustment_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Credit Adjustment Type */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_credit_adjustment_credit_adjustment_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Credit Adjustment Value */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_credit_adjustment_credit_adjustment_value, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_pp_credit_adjustment*/

/**
 *This function manages the Change Payment Mode payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_change_payment_mode(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_payment_mode_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_payment_mode_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Implementation Date/Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_change_payment_mode_implementation_date_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Proposed Payment Control Configuration */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_payment_mode_proposed_payment_control_configuration, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Cut Off Value */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_payment_mode_cut_off_value, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_pp_change_payment_mode*/

/**
 *This function manages the Get Prepay Snapshot payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_get_prepay_snapshot(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;
    nstime_t end_time;

    /* Earliest Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_get_prepay_snapshot_earliest_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Latest End Time */
    end_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    end_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_get_prepay_snapshot_latest_end_time, tvb, *offset, 4, &end_time);
    *offset += 4;

    /* Snapshot Offset */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_get_prepay_snapshot_snapshot_offset, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Snapshot Cause */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_get_prepay_snapshot_snapshot_cause, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_pp_get_prepay_snapshot*/

/**
 *This function manages the Get Top Up Log payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_get_top_up_log(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t end_time;

    /* Latest End Time */
    end_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    end_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_get_top_up_log_latest_end_time, tvb, *offset, 4, &end_time);
    *offset += 4;

    /* Number of Records */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_get_top_up_log_number_of_records, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_pp_get_top_up_log*/

/**
 *This function manages the Set Low Credit Warning Level payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_set_low_credit_warning_level(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Low Credit Warning Level */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_set_low_credit_warning_level_low_credit_warning_level, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_pp_set_low_credit_warning_level*/

  /**
  *This function manages the Get Debt Repayment Log payload
  *
  *@param tvb pointer to buffer containing raw packet.
  *@param tree pointer to data tree Wireshark uses to display packet.
  *@param offset pointer to offset from caller
  */
static void
dissect_zcl_pp_get_debt_repayment_log(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t end_time;

    /* Latest End Time */
    end_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    end_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_get_debt_repayment_log_latest_end_time, tvb, *offset, 4, &end_time);
    *offset += 4;

    /* Number of Records */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_get_debt_repayment_log_number_of_debts, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Debt Type */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_get_debt_repayment_log_debt_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_pp_get_debt_repayment_log*/

/**
 *This function manages the Set Maximum Credit Limit payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_set_maximum_credit_limit(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_set_maximum_credit_limit_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_set_maximum_credit_limit_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Implementation Date/Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_set_maximum_credit_limit_implementation_date_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Maximum Credit Level */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_set_maximum_credit_limit_maximum_credit_level, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Maximum Credit Per Top Up  */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_set_maximum_credit_limit_maximum_credit_per_top_up, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_pp_set_maximum_credit_limit*/

/**
 *This function manages the Set Overall Debt Cap payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_set_overall_debt_cap(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_set_overall_debt_cap_limit_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_set_overall_debt_cap_limit_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Implementation Date/Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_set_overall_debt_cap_limit_implementation_date_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Overall Debt Cap */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_set_overall_debt_cap_limit_overall_debt_cap, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_pp_set_overall_debt_cap*/

/**
 *This function manages the Publish Prepay Snapshot payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_publish_prepay_snapshot(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t snapshot_time;
    gint rem_len;

    /* Snapshot ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Snapshot Time */
    snapshot_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    snapshot_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_time, tvb, *offset, 4, &snapshot_time);
    *offset += 4;

    /* Total Snapshots Found */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_total_snapshots_found, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_command_index, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_total_number_of_commands, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Snapshot Cause */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_cause, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Snapshot Payload Type */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_payload_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Snapshot Payload */
    rem_len = tvb_reported_length_remaining(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_payload, tvb, *offset, rem_len, ENC_NA);
    *offset += rem_len;
} /*dissect_zcl_pp_publish_prepay_snapshot*/

/**
 *This function manages the Change Payment Mode Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_change_payment_mode_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Friendly Credit */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_payment_mode_response_friendly_credit, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Friendly Credit Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_payment_mode_response_friendly_credit_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Emergency Credit Limit */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_payment_mode_response_emergency_credit_limit, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Emergency Credit Threshold */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_change_payment_mode_response_emergency_credit_threshold, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_pp_change_payment_mode_response*/

/**
 *This function manages the Consumer Top Up Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_consumer_top_up_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Result Type */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_consumer_top_up_response_result_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Top Up Value */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_consumer_top_up_response_top_up_value, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Source of Top up */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_consumer_top_up_response_source_of_top_up, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Credit Remaining */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_consumer_top_up_response_credit_remaining, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_pp_consumer_top_up_response*/

/**
 *This function manages the Publish Top Up Log payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_publish_top_up_log(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint i = 0;
    nstime_t top_up_time;
    proto_tree *sub_tree;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_top_up_log_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_top_up_log_total_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Top Up Payload */
    while (tvb_reported_length_remaining(tvb, *offset) > 0 && i < ZBEE_ZCL_SE_PP_NUM_PUBLISH_TOP_UP_LOG_ETT) {
        /* Add subtree */
        sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 0, ett_zbee_zcl_pp_publish_top_up_entry[i], NULL, "TopUp Log %d", i + 1);
        i++;

        /* Top Up Code */
        dissect_zcl_octet_string(tvb, sub_tree, offset,
                ett_zbee_zcl_pp_publish_top_up_log_top_up_code,
                hf_zbee_zcl_pp_publish_top_up_log_top_up_code_len,
                hf_zbee_zcl_pp_publish_top_up_log_top_up_code);

        /* Top Up Amount */
        proto_tree_add_item(sub_tree, hf_zbee_zcl_pp_publish_top_up_log_top_up_amount, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;

        /* Top Up Time */
        top_up_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
        top_up_time.nsecs = 0;
        proto_tree_add_time(sub_tree, hf_zbee_zcl_pp_publish_top_up_log_top_up_time, tvb, *offset, 4, &top_up_time);
        *offset += 4;

        /* Set length of subtree */
        proto_item_set_end(proto_tree_get_parent(sub_tree), tvb, *offset);
    }
} /*dissect_zcl_pp_publish_top_up_log*/

/**
 *This function manages the Publish Debt Log payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_pp_publish_debt_log(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint i = 0;
    nstime_t collection_time;
    proto_tree *sub_tree;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_debt_log_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_debt_log_total_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Debt Payload */
    while (tvb_reported_length_remaining(tvb, *offset) > 0 && i < ZBEE_ZCL_SE_PP_NUM_PUBLISH_DEBT_LOG_ETT) {
        /* Add subtree */
        sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 4 + 4 + 1 + 4, ett_zbee_zcl_pp_publish_debt_log_entry[i], NULL, "Debt Log %d", i + 1);
        i++;

        /* Collection Time */
        collection_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
        collection_time.nsecs = 0;
        proto_tree_add_time(sub_tree, hf_zbee_zcl_pp_publish_debt_log_collection_time, tvb, *offset, 4, &collection_time);
        *offset += 4;

        /* Amount Collected */
        proto_tree_add_item(sub_tree, hf_zbee_zcl_pp_publish_debt_log_amount_collected, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;

        /* Debt Type */
        proto_tree_add_item(sub_tree, hf_zbee_zcl_pp_publish_debt_log_debt_type, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Outstanding Debt */
        proto_tree_add_item(sub_tree, hf_zbee_zcl_pp_publish_debt_log_outstanding_debt, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }
} /*dissect_zcl_pp_publish_debt_log*/

/**
 *This function registers the ZCL Prepayment dissector
 *
*/
void
proto_register_zbee_zcl_pp(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_pp_attr_id,
            { "Attribute", "zbee_zcl_se.pp.attr_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &zbee_zcl_pp_attr_names_ext,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_pp_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.pp.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.pp.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_pp_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.pp.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_pp_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_select_available_emc_cmd_issue_date_time,
            { "Command Issue Date/Time", "zbee_zcl_se.pp.select_available_emc.cmd_issue_date_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_select_available_emc_originating_device,
            { "Originating Device", "zbee_zcl_se.pp.select_available_emc.originating_device", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_debt_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.pp.change_debt.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_debt_label,
            { "Debt Label", "zbee_zcl_se.pp.change_debt.debt_label", FT_BYTES, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_debt_amount,
            { "Debt Amount", "zbee_zcl_se.pp.change_debt.debt_amount", FT_INT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_debt_recovery_method,
            { "Debt Recovery Method", "zbee_zcl_se.pp.change_debt.recovery_method", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_debt_amount_type,
            { "Debt Amount Type", "zbee_zcl_se.pp.change_debt.amount_type", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_debt_recovery_start_time,
            { "Debt Recovery Start Time", "zbee_zcl_se.pp.change_debt.recovery_start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_debt_recovery_collection_time,
            { "Debt Recovery Collection Time", "zbee_zcl_se.pp.change_debt.recovery_collection_time", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_debt_recovery_frequency,
            { "Debt Recovery Frequency", "zbee_zcl_se.pp.change_debt.recovery_frequency", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_debt_recovery_amount,
            { "Debt Recovery Amount", "zbee_zcl_se.pp.change_debt.recovery_amount", FT_INT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_debt_recovery_balance_percentage,
            { "Debt Recovery Balance Percentage", "zbee_zcl_se.pp.change_debt.recovery_balance_percentage", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_emergency_credit_setup_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.pp.emc_setup.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_emergency_credit_setup_start_time,
            { "Start Time", "zbee_zcl_se.pp.emc_setup.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_emergency_credit_setup_emergency_credit_limit,
            { "Emergency Credit Limit", "zbee_zcl_se.pp.emc_setup.emc_limit", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_emergency_credit_setup_emergency_credit_threshold,
            { "Emergency Credit Threshold", "zbee_zcl_se.pp.emc_setup.emc_threshold", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_consumer_top_up_originating_device,
            { "Originating Device", "zbee_zcl_se.pp.consumer_top_up.originating_device", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_consumer_top_up_top_up_code_len,
            { "Length", "zbee_zcl_se.pp.consumer_top_up.top_up_code_len", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_consumer_top_up_top_up_code,
            { "TopUp Code", "zbee_zcl_se.pp.consumer_top_up.top_up_code", FT_BYTES, SEP_COLON, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_credit_adjustment_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.pp.credit_adjustment.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_credit_adjustment_start_time,
            { "Start Time", "zbee_zcl_se.pp.credit_adjustment.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_credit_adjustment_credit_adjustment_type,
            { "Credit Adjustment Type", "zbee_zcl_se.pp.credit_adjustment.credit_adjustment_type", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_credit_adjustment_credit_adjustment_value,
            { "Credit Adjustment Value", "zbee_zcl_se.pp.credit_adjustment.credit_adjustment_value", FT_INT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_payment_mode_provider_id,
            { "Provider ID", "zbee_zcl_se.pp.change_payment_mode.provider_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_payment_mode_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.pp.change_payment_mode.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_payment_mode_implementation_date_time,
            { "Implementation Date/Time", "zbee_zcl_se.pp.change_payment_mode.implementation_date_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_payment_mode_proposed_payment_control_configuration,
            { "Proposed Payment Control Configuration", "zbee_zcl_se.pp.change_payment_mode.payment_control_configuration", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_payment_mode_cut_off_value,
            { "Cut Off Value", "zbee_zcl_se.pp.change_payment_mode.cut_off_value", FT_INT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_get_prepay_snapshot_earliest_start_time,
            { "Earliest Start Time", "zbee_zcl_se.pp.get_prepay_snapshot.earliest_start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_get_prepay_snapshot_latest_end_time,
            { "Latest End Time", "zbee_zcl_se.pp.get_prepay_snapshot.latest_end_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_get_prepay_snapshot_snapshot_offset,
            { "Snapshot Offset", "zbee_zcl_se.pp.get_prepay_snapshot.snapshot_offset", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_get_prepay_snapshot_snapshot_cause,
            { "Snapshot Cause", "zbee_zcl_se.pp.get_prepay_snapshot.snapshot_cause", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_get_top_up_log_latest_end_time,
            { "Latest End Time", "zbee_zcl_se.pp.get_top_up_log.latest_end_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_get_top_up_log_number_of_records,
            { "Number of Records", "zbee_zcl_se.pp.get_top_up_log.number_of_records", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_set_low_credit_warning_level_low_credit_warning_level,
            { "Low Credit Warning Level", "zbee_zcl_se.pp.set_low_credit_warning_level.low_credit_warning_level", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_get_debt_repayment_log_latest_end_time,
            { "Latest End Time", "zbee_zcl_se.pp.get_debt_repayment_log.latest_end_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_get_debt_repayment_log_number_of_debts,
            { "Number of Records", "zbee_zcl_se.pp.get_debt_repayment_log.number_of_records", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_get_debt_repayment_log_debt_type,
            { "Debt Type", "zbee_zcl_se.pp.get_debt_repayment_log.debt_type", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_set_maximum_credit_limit_provider_id,
            { "Provider ID", "zbee_zcl_se.pp.set_maximum_credit_limit.provider_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_set_maximum_credit_limit_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.pp.set_maximum_credit_limit.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_set_maximum_credit_limit_implementation_date_time,
            { "Implementation Date/Time", "zbee_zcl_se.pp.set_maximum_credit_limit.implementation_date_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_set_maximum_credit_limit_maximum_credit_level,
            { "Maximum Credit Level", "zbee_zcl_se.pp.set_maximum_credit_limit.max_credit_level", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_set_maximum_credit_limit_maximum_credit_per_top_up,
            { "Maximum Credit Per Top Up", "zbee_zcl_se.pp.set_maximum_credit_limit.max_credit_per_top_up", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_set_overall_debt_cap_limit_provider_id,
            { "Provider ID", "zbee_zcl_se.pp.set_overall_debt_cap_limit.provider_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_set_overall_debt_cap_limit_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.pp.set_overall_debt_cap_limit.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_set_overall_debt_cap_limit_implementation_date_time,
            { "Implementation Date/Time", "zbee_zcl_se.pp.set_overall_debt_cap_limit.implementation_date_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_set_overall_debt_cap_limit_overall_debt_cap,
            { "Overall Debt Cap", "zbee_zcl_se.pp.set_overall_debt_cap_limit.overall_debt_cap", FT_INT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_id,
            { "Snapshot ID", "zbee_zcl_se.pp.publish_prepay_snapshot.snapshot_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_time,
            { "Snapshot Time", "zbee_zcl_se.pp.publish_prepay_snapshot.snapshot_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_prepay_snapshot_total_snapshots_found,
            { "Total Snapshots Found", "zbee_zcl_se.pp.publish_prepay_snapshot.total_snapshots_found", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_prepay_snapshot_command_index,
            { "Command Index", "zbee_zcl_se.pp.publish_prepay_snapshot.command_index", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_prepay_snapshot_total_number_of_commands,
            { "Total Number of Commands", "zbee_zcl_se.pp.publish_prepay_snapshot.total_number_of_commands", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_cause,
            { "Snapshot Cause", "zbee_zcl_se.pp.publish_prepay_snapshot.snapshot_cause", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_payload_type,
            { "Snapshot Payload Type", "zbee_zcl_se.pp.publish_prepay_snapshot.snapshot_payload_type", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_payload,
            { "Snapshot Payload", "zbee_zcl_se.pp.publish_prepay_snapshot.snapshot_payload", FT_BYTES, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_payment_mode_response_friendly_credit,
            { "Friendly Credit", "zbee_zcl_se.pp.change_payment_mode_response.friendly_credit", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_payment_mode_response_friendly_credit_calendar_id,
            { "Friendly Credit Calendar ID", "zbee_zcl_se.pp.change_payment_mode_response.friendly_credit_calendar_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_payment_mode_response_emergency_credit_limit,
            { "Emergency Credit Limit", "zbee_zcl_se.pp.change_payment_mode_response.emc_limit", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_change_payment_mode_response_emergency_credit_threshold,
            { "Emergency Credit Threshold", "zbee_zcl_se.pp.change_payment_mode_response.emc_threshold", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_consumer_top_up_response_result_type,
            { "Result Type", "zbee_zcl_se.pp.consumer_top_up_response.result_type", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_consumer_top_up_response_top_up_value,
            { "Top Up Value", "zbee_zcl_se.pp.consumer_top_up_response.top_up_value", FT_INT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_consumer_top_up_response_source_of_top_up,
            { "Source of Top up", "zbee_zcl_se.pp.consumer_top_up_response.source_of_top_up", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_consumer_top_up_response_credit_remaining,
            { "Credit Remaining", "zbee_zcl_se.pp.consumer_top_up_response.credit_remaining", FT_INT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_top_up_log_command_index,
            { "Command Index", "zbee_zcl_se.pp.publish_top_up_log.command_index", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_top_up_log_total_number_of_commands,
            { "Total Number of Commands", "zbee_zcl_se.pp.publish_top_up_log.total_number_of_commands", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_top_up_log_top_up_code_len,
            { "Length", "zbee_zcl_se.pp.publish_top_up_log.top_up_code_len", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_top_up_log_top_up_code,
            { "TopUp Code", "zbee_zcl_se.pp.publish_top_up_log.top_up_code", FT_BYTES, SEP_COLON, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_top_up_log_top_up_amount,
            { "TopUp Amount", "zbee_zcl_se.pp.publish_top_up_log.top_up_amount", FT_INT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_top_up_log_top_up_time,
            { "TopUp Time", "zbee_zcl_se.pp.publish_top_up_log.top_up_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_debt_log_command_index,
            { "Command Index", "zbee_zcl_se.pp.publish_debt_log.command_index", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_debt_log_total_number_of_commands,
            { "Total Number of Commands", "zbee_zcl_se.pp.publish_debt_log.total_number_of_commands", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_debt_log_collection_time,
            { "Collection Time", "zbee_zcl_se.pp.publish_debt_log.collection_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_debt_log_amount_collected,
            { "Amount Collected", "zbee_zcl_se.pp.publish_debt_log.amount_collected", FT_INT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_debt_log_debt_type,
            { "Debt Type", "zbee_zcl_se.pp.publish_debt_log.debt_type", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_pp_publish_debt_log_outstanding_debt,
            { "Outstanding Debt", "zbee_zcl_se.pp.publish_debt_log.outstanding_debt", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },
    };

    /* ZCL Prepayment subtrees */
    gint *ett[ZBEE_ZCL_SE_PP_NUM_TOTAL_ETT];
    ett[0] = &ett_zbee_zcl_pp;
    ett[1] = &ett_zbee_zcl_pp_consumer_top_up_top_up_code;
    ett[2] = &ett_zbee_zcl_pp_publish_top_up_log_top_up_code;

    guint j = ZBEE_ZCL_SE_PP_NUM_INDIVIDUAL_ETT;

    /* Initialize Publish Top Up Log subtrees */
    for (guint i = 0; i < ZBEE_ZCL_SE_PP_NUM_PUBLISH_TOP_UP_LOG_ETT; i++, j++) {
        ett_zbee_zcl_pp_publish_top_up_entry[i] = -1;
        ett[j] = &ett_zbee_zcl_pp_publish_top_up_entry[i];
    }

    /* Initialize Publish Debt Log subtrees */
    for (guint i = 0; i < ZBEE_ZCL_SE_PP_NUM_PUBLISH_DEBT_LOG_ETT; i++, j++ ) {
        ett_zbee_zcl_pp_publish_debt_log_entry[i] = -1;
        ett[j] = &ett_zbee_zcl_pp_publish_debt_log_entry[i];
    }

    /* Register the ZigBee ZCL Prepayment cluster protocol name and description */
    proto_zbee_zcl_pp = proto_register_protocol("ZigBee ZCL Prepayment", "ZCL Prepayment", ZBEE_PROTOABBREV_ZCL_PRE_PAYMENT);
    proto_register_field_array(proto_zbee_zcl_pp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Prepayment dissector. */
    pp_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_PRE_PAYMENT, dissect_zbee_zcl_pp, proto_zbee_zcl_pp);
} /*proto_register_zbee_zcl_pp*/

/**
 *Hands off the ZCL Prepayment dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_pp(void)
{
    /* Register our dissector with the ZigBee application dissectors. */
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_PRE_PAYMENT, pp_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_pp,
                            ett_zbee_zcl_pp,
                            ZBEE_ZCL_CID_PRE_PAYMENT,
                            hf_zbee_zcl_pp_attr_id,
                            hf_zbee_zcl_pp_srv_rx_cmd_id,
                            hf_zbee_zcl_pp_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_pp_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_pp*/

/* ########################################################################## */
/* #### (0x0707) CALENDAR CLUSTER ########################################### */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_calendar_attr_names_VALUE_STRING_LIST(XXX) \
/* Auxiliary Switch Label Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_CAL_AUX_SWITCH_1_LABEL,                0x0000, "Aux Switch 1 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_CAL_AUX_SWITCH_2_LABEL,                0x0001, "Aux Switch 2 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_CAL_AUX_SWITCH_3_LABEL,                0x0002, "Aux Switch 3 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_CAL_AUX_SWITCH_4_LABEL,                0x0003, "Aux Switch 4 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_CAL_AUX_SWITCH_5_LABEL,                0x0004, "Aux Switch 5 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_CAL_AUX_SWITCH_6_LABEL,                0x0005, "Aux Switch 6 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_CAL_AUX_SWITCH_7_LABEL,                0x0006, "Aux Switch 7 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_CAL_AUX_SWITCH_8_LABEL,                0x0007, "Aux Switch 8 Label" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_CAL,             0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_calendar_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_calendar_attr_names);

/* Server Commands Received */
#define zbee_zcl_calendar_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_GET_CALENDAR,                       0x00, "Get Calendar" ) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_GET_DAY_PROFILES,                   0x01, "Get Day Profiles" ) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_GET_WEEK_PROFILES,                  0x02, "Get Week Profiles" ) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_GET_SEASONS,                        0x03, "Get Seasons" ) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_GET_SPECIAL_DAYS,                   0x04, "Get Special Days" ) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_GET_CALENDAR_CANCELLATION,          0x05, "Get Calendar Cancellation" )

VALUE_STRING_ENUM(zbee_zcl_calendar_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_calendar_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_calendar_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_PUBLISH_CALENDAR,                   0x00, "Publish Calendar" ) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_PUBLISH_DAY_PROFILE,                0x01, "Publish Day Profile" ) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_PUBLISH_WEEK_PROFILE,               0x02, "Publish Week Profile" ) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_PUBLISH_SEASONS,                    0x03, "Publish Seasons" ) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_PUBLISH_SPECIAL_DAYS,               0x04, "Publish Special Days" ) \
    XXX(ZBEE_ZCL_CMD_ID_CAL_CANCEL_CALENDAR,                    0x05, "Cancel Calendar" )

VALUE_STRING_ENUM(zbee_zcl_calendar_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_calendar_srv_tx_cmd_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_calendar(void);
void proto_reg_handoff_zbee_zcl_calendar(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_calendar_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/*************************/
/* Global Variables      */
/*************************/

static dissector_handle_t calendar_handle;

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_calendar = -1;

static int hf_zbee_zcl_calendar_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_calendar_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_calendar_attr_id = -1;
static int hf_zbee_zcl_calendar_attr_reporting_status = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_calendar = -1;

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
dissect_zcl_calendar_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_CAL:
            proto_tree_add_item(tree, hf_zbee_zcl_calendar_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_calendar_attr_data*/

/**
 *ZigBee ZCL Calendar cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_calendar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_calendar_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_calendar_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_calendar, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_CAL_GET_CALENDAR:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_GET_DAY_PROFILES:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_GET_WEEK_PROFILES:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_GET_SEASONS:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_GET_SPECIAL_DAYS:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_GET_CALENDAR_CANCELLATION:
                    /* Add function to dissect payload */
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_calendar_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_calendar_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_calendar, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_CAL_PUBLISH_CALENDAR:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_PUBLISH_DAY_PROFILE:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_PUBLISH_WEEK_PROFILE:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_PUBLISH_SEASONS:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_PUBLISH_SPECIAL_DAYS:
                    /* Add function to dissect payload */
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_CANCEL_CALENDAR:
                    /* Add function to dissect payload */
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_calendar*/

/**
 *This function registers the ZCL Calendar dissector
 *
*/
void
proto_register_zbee_zcl_calendar(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_calendar_attr_id,
            { "Attribute", "zbee_zcl_se.calendar.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_calendar_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.calendar.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.calendar.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_calendar_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.calendar.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_calendar_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

    };

    /* ZCL Calendar subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_calendar,
    };

    /* Register the ZigBee ZCL Calendar cluster protocol name and description */
    proto_zbee_zcl_calendar = proto_register_protocol("ZigBee ZCL Calendar", "ZCL Calendar", ZBEE_PROTOABBREV_ZCL_CALENDAR);
    proto_register_field_array(proto_zbee_zcl_calendar, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Calendar dissector. */
    calendar_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_CALENDAR, dissect_zbee_zcl_calendar, proto_zbee_zcl_calendar);
} /*proto_register_zbee_zcl_calendar*/

/**
 *Hands off the ZCL Calendar dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_calendar(void)
{
    /* Register our dissector with the ZigBee application dissectors. */
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_CALENDAR, calendar_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_calendar,
                            ett_zbee_zcl_calendar,
                            ZBEE_ZCL_CID_CALENDAR,
                            hf_zbee_zcl_calendar_attr_id,
                            hf_zbee_zcl_calendar_srv_rx_cmd_id,
                            hf_zbee_zcl_calendar_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_calendar_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_calendar*/

/* ########################################################################## */
/* #### (0x0709) EVENTS CLUSTER ############################################# */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_events_attr_names_VALUE_STRING_LIST(XXX) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_EVENTS,          0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_events_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_events_attr_names);

/* Server Commands Received */
#define zbee_zcl_events_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_EVENTS_GET_EVENT_LOG,                   0x00, "Get Event Log" ) \
    XXX(ZBEE_ZCL_CMD_ID_EVENTS_CLEAR_EVENT_LOG_REQUEST,         0x01, "Clear Event Log Request" )

VALUE_STRING_ENUM(zbee_zcl_events_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_events_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_events_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_EVENTS_PUBLISH_EVENT,                   0x00, "Publish Event" ) \
    XXX(ZBEE_ZCL_CMD_ID_EVENTS_PUBLISH_EVENT_LOG,               0x01, "Publish Event Log" ) \
    XXX(ZBEE_ZCL_CMD_ID_EVENTS_CLEAR_EVENT_LOG_RESPONSE,        0x02, "Clear Event Log Response" )

VALUE_STRING_ENUM(zbee_zcl_events_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_events_srv_tx_cmd_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_events(void);
void proto_reg_handoff_zbee_zcl_events(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_events_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Command Dissector Helpers */
static void dissect_zcl_events_get_event_log                    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_events_clear_event_log_request          (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_events_publish_event                    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_events_publish_event_log                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_events_clear_event_log_response         (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

static dissector_handle_t events_handle;

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_events = -1;

static int hf_zbee_zcl_events_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_events_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_events_attr_id = -1;
static int hf_zbee_zcl_events_attr_reporting_status = -1;
static int hf_zbee_zcl_events_get_event_log_event_control_log_id = -1;
static int hf_zbee_zcl_events_get_event_log_event_id = -1;
static int hf_zbee_zcl_events_get_event_log_start_time = -1;
static int hf_zbee_zcl_events_get_event_log_end_time = -1;
static int hf_zbee_zcl_events_get_event_log_number_of_events = -1;
static int hf_zbee_zcl_events_get_event_log_event_offset = -1;
static int hf_zbee_zcl_events_clear_event_log_request_log_id = -1;
static int hf_zbee_zcl_events_publish_event_log_id = -1;
static int hf_zbee_zcl_events_publish_event_event_id = -1;
static int hf_zbee_zcl_events_publish_event_event_time = -1;
static int hf_zbee_zcl_events_publish_event_event_control = -1;
static int hf_zbee_zcl_events_publish_event_event_data_len = -1;
static int hf_zbee_zcl_events_publish_event_event_data = -1;
static int hf_zbee_zcl_events_publish_event_log_total_number_of_matching_events = -1;
static int hf_zbee_zcl_events_publish_event_log_command_index = -1;
static int hf_zbee_zcl_events_publish_event_log_total_commands = -1;
static int hf_zbee_zcl_events_publish_event_log_number_of_events_log_payload_control = -1;
static int hf_zbee_zcl_events_publish_event_log_log_id = -1;
static int hf_zbee_zcl_events_publish_event_log_event_id = -1;
static int hf_zbee_zcl_events_publish_event_log_event_time = -1;
static int hf_zbee_zcl_events_publish_event_log_event_data_len = -1;
static int hf_zbee_zcl_events_publish_event_log_event_data = -1;
static int hf_zbee_zcl_events_clear_event_log_response_cleared_event_logs = -1;

/* Initialize the subtree pointers */
#define ZBEE_ZCL_SE_EVENTS_NUM_INDIVIDUAL_ETT             3
#define ZBEE_ZCL_SE_EVENTS_NUM_PUBLISH_EVENT_LOG_ETT      100 // The Great Britain Companion Specification (GBCS) allows up to 100 even though ZigBee only allows 15
#define ZBEE_ZCL_SE_EVENTS_NUM_TOTAL_ETT                  (ZBEE_ZCL_SE_EVENTS_NUM_INDIVIDUAL_ETT + ZBEE_ZCL_SE_EVENTS_NUM_PUBLISH_EVENT_LOG_ETT)

static gint ett_zbee_zcl_events = -1;
static gint ett_zbee_zcl_events_publish_event_event_data = -1;
static gint ett_zbee_zcl_events_publish_event_log_event_data = -1;
static gint ett_zbee_zcl_events_publish_event_log_entry[ZBEE_ZCL_SE_EVENTS_NUM_PUBLISH_EVENT_LOG_ETT];

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
dissect_zcl_events_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_EVENTS:
            proto_tree_add_item(tree, hf_zbee_zcl_events_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_events_attr_data*/

/**
 *ZigBee ZCL Events cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_events(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_events_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_events_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_events, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_EVENTS_GET_EVENT_LOG:
                    dissect_zcl_events_get_event_log(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_EVENTS_CLEAR_EVENT_LOG_REQUEST:
                    dissect_zcl_events_clear_event_log_request(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_events_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_events_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_events, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_EVENTS_PUBLISH_EVENT:
                    dissect_zcl_events_publish_event(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_EVENTS_PUBLISH_EVENT_LOG:
                    dissect_zcl_events_publish_event_log(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_EVENTS_CLEAR_EVENT_LOG_RESPONSE:
                    dissect_zcl_events_clear_event_log_response(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_events*/

/**
 *This function manages the Get Event Log payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_events_get_event_log(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t    start_time;
    nstime_t    end_time;

    /* Event Control / Log ID */
    proto_tree_add_item(tree, hf_zbee_zcl_events_get_event_log_event_control_log_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_events_get_event_log_event_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_events_get_event_log_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* End Time */
    end_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    end_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_events_get_event_log_end_time, tvb, *offset, 4, &end_time);
    *offset += 4;

    /* Number of Events */
    proto_tree_add_item(tree, hf_zbee_zcl_events_get_event_log_number_of_events, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Event Offset */
    proto_tree_add_item(tree, hf_zbee_zcl_events_get_event_log_event_offset, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_events_get_event_log*/

/**
 *This function manages the Clear Event Log Request payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_events_clear_event_log_request(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Log ID */
    proto_tree_add_item(tree, hf_zbee_zcl_events_clear_event_log_request_log_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_events_clear_event_log_request*/

/**
 *This function manages the Publish Event payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_events_publish_event(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t    event_time;

    /* Log ID */
    proto_tree_add_item(tree, hf_zbee_zcl_events_publish_event_log_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_events_publish_event_event_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Event Time */
    event_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    event_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_events_publish_event_event_time, tvb, *offset, 4, &event_time);
    *offset += 4;

    /* Event Control */
    proto_tree_add_item(tree, hf_zbee_zcl_events_publish_event_event_control, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Event Data */
    dissect_zcl_octet_string(tvb, tree, offset,
            ett_zbee_zcl_events_publish_event_event_data,
            hf_zbee_zcl_events_publish_event_event_data_len,
            hf_zbee_zcl_events_publish_event_event_data);
} /*dissect_zcl_events_publish_event*/

/**
 *This function manages the Publish Event Log payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_events_publish_event_log(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree* event_log_tree;
    nstime_t    event_time;

    /* Total Number of Matching Events */
    proto_tree_add_item(tree, hf_zbee_zcl_events_publish_event_log_total_number_of_matching_events, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_events_publish_event_log_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_events_publish_event_log_total_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Number of Events / Log Payload Control */
    proto_tree_add_item(tree, hf_zbee_zcl_events_publish_event_log_number_of_events_log_payload_control, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    for (gint i = 0; tvb_reported_length_remaining(tvb, *offset) > 0 && i < ZBEE_ZCL_SE_EVENTS_NUM_PUBLISH_EVENT_LOG_ETT; i++) {
        /* Add subtree */
        event_log_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 0, ett_zbee_zcl_events_publish_event_log_entry[i], NULL, "Event Log %d", i + 1);

        /* Log ID */
        proto_tree_add_item(event_log_tree, hf_zbee_zcl_events_publish_event_log_log_id, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Event ID */
        proto_item_append_text(event_log_tree, ", Event ID: 0x%04x", tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN));
        proto_tree_add_item(event_log_tree, hf_zbee_zcl_events_publish_event_log_event_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Event Time */
        event_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
        event_time.nsecs = 0;
        proto_tree_add_time(event_log_tree, hf_zbee_zcl_events_publish_event_log_event_time, tvb, *offset, 4, &event_time);
        *offset += 4;

        /* Event Data */
        dissect_zcl_octet_string(tvb, event_log_tree, offset,
                ett_zbee_zcl_events_publish_event_log_event_data,
                hf_zbee_zcl_events_publish_event_log_event_data_len,
                hf_zbee_zcl_events_publish_event_log_event_data);

        /* Set length of subtree */
        proto_item_set_end(proto_tree_get_parent(event_log_tree), tvb, *offset);
    }
} /*dissect_zcl_events_publish_event_log*/

/**
 *This function manages the Clear Event Log Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_events_clear_event_log_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Cleared Event Logs */
    proto_tree_add_item(tree, hf_zbee_zcl_events_clear_event_log_response_cleared_event_logs, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_events_clear_event_log_response*/

/**
 *This function registers the ZCL Events dissector
 *
*/
void
proto_register_zbee_zcl_events(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_events_attr_id,
            { "Attribute", "zbee_zcl_se.events.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_events_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_events_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.events.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.events.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_events_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.events.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_events_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_get_event_log_event_control_log_id,
            { "Event Control / Log ID", "zbee_zcl_se.events.get_event_log.event_control_log_id", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_get_event_log_event_id,
            { "Event ID", "zbee_zcl_se.events.get_event_log.event_id", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_get_event_log_start_time,
            { "Start Time", "zbee_zcl_se.events.get_event_log.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_get_event_log_end_time,
            { "End Time", "zbee_zcl_se.events.get_event_log.end_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_get_event_log_number_of_events,
            { "Number of Events", "zbee_zcl_se.events.get_event_log.number_of_events", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_get_event_log_event_offset,
            { "Event Offset", "zbee_zcl_se.events.get_event_log.number_of_events", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_clear_event_log_request_log_id,
            { "Log ID", "zbee_zcl_se.events.clear_event_log_request.log_id", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_log_id,
            { "Log ID", "zbee_zcl_se.events.publish_event.log_id", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_event_id,
            { "Event ID", "zbee_zcl_se.events.publish_event.event_id", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_event_time,
            { "Event Time", "zbee_zcl_se.events.publish_event.event_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_event_control,
            { "Event Control", "zbee_zcl_se.events.publish_event.event_control", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_event_data_len,
            { "Length", "zbee_zcl_se.events.publish_event.event_data_len", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_event_data,
            { "Event Data", "zbee_zcl_se.events.publish_event.event_data", FT_BYTES, SEP_COLON, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_log_total_number_of_matching_events,
            { "Total Number of Matching Events", "zbee_zcl_se.events.publish_event_log.event_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_log_command_index,
            { "Command Index", "zbee_zcl_se.events.publish_event_log.command_index", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_log_total_commands,
            { "Total Commands", "zbee_zcl_se.events.publish_event_log.total_commands", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_log_number_of_events_log_payload_control,
            { "Number of Events / Log Payload Control", "zbee_zcl_se.events.publish_event_log.number_of_events_log_payload_control", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_log_log_id,
            { "Log ID", "zbee_zcl_se.events.publish_event_log.log_id", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_log_event_id,
            { "Event ID", "zbee_zcl_se.events.publish_event_log.event_id", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_log_event_time,
            { "Event Time", "zbee_zcl_se.events.publish_event_log.event_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_log_event_data_len,
            { "Length", "zbee_zcl_se.events.publish_event_log.event_data_len", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_publish_event_log_event_data,
            { "Event Data", "zbee_zcl_se.events.publish_event_log.event_data", FT_BYTES, SEP_COLON, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_clear_event_log_response_cleared_event_logs,
            { "Cleared Event Logs", "zbee_zcl_se.events.clear_event_log_response.cleared_event_logs", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

    };

    /* ZCL Events subtrees */
    gint *ett[ZBEE_ZCL_SE_EVENTS_NUM_TOTAL_ETT];
    ett[0] = &ett_zbee_zcl_events;
    ett[1] = &ett_zbee_zcl_events_publish_event_event_data;
    ett[2] = &ett_zbee_zcl_events_publish_event_log_event_data;

    guint j = ZBEE_ZCL_SE_EVENTS_NUM_INDIVIDUAL_ETT;

    /* Initialize Publish Event Log subtrees */
    for (guint i = 0; i < ZBEE_ZCL_SE_EVENTS_NUM_PUBLISH_EVENT_LOG_ETT; i++, j++) {
        ett_zbee_zcl_events_publish_event_log_entry[i] = -1;
        ett[j] = &ett_zbee_zcl_events_publish_event_log_entry[i];
    }

    /* Register the ZigBee ZCL Events cluster protocol name and description */
    proto_zbee_zcl_events = proto_register_protocol("ZigBee ZCL Events", "ZCL Events", ZBEE_PROTOABBREV_ZCL_EVENTS);
    proto_register_field_array(proto_zbee_zcl_events, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Events dissector. */
    events_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_EVENTS, dissect_zbee_zcl_events, proto_zbee_zcl_events);
} /*proto_register_zbee_zcl_events*/

/**
 *Hands off the ZCL Events dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_events(void)
{
    /* Register our dissector with the ZigBee application dissectors. */
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_EVENTS, events_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_events,
                            ett_zbee_zcl_events,
                            ZBEE_ZCL_CID_EVENTS,
                            hf_zbee_zcl_events_attr_id,
                            hf_zbee_zcl_events_srv_rx_cmd_id,
                            hf_zbee_zcl_events_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_events_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_events*/

/* ########################################################################## */
/* #### (0x070A) MDU PAIRING CLUSTER ############################################ */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_mdu_pairing_attr_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_MDU_PAIRING,         0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_mdu_pairing_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_mdu_pairing_attr_names);
static value_string_ext zbee_zcl_mdu_pairing_attr_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_mdu_pairing_attr_names);

/* Server Commands Received */
#define zbee_zcl_mdu_pairing_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_MDU_PAIRING_REQUEST,    0x00, "Pairing Request" )

VALUE_STRING_ENUM(zbee_zcl_mdu_pairing_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_mdu_pairing_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_mdu_pairing_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_MDU_PAIRING_RESPONSE,   0x00, "Pairing Response" )

VALUE_STRING_ENUM(zbee_zcl_mdu_pairing_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_mdu_pairing_srv_tx_cmd_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_mdu_pairing(void);
void proto_reg_handoff_zbee_zcl_mdu_pairing(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_mdu_pairing_attr_data        (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Command Dissector Helpers */
static void dissect_zcl_mdu_pairing_request (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_mdu_pairing_response(tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

static dissector_handle_t mdu_pairing_handle;

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_mdu_pairing = -1;

static int hf_zbee_zcl_mdu_pairing_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_mdu_pairing_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_mdu_pairing_attr_id = -1;
static int hf_zbee_zcl_mdu_pairing_attr_reporting_status = -1;
static int hf_zbee_zcl_mdu_pairing_info_version = -1;
static int hf_zbee_zcl_mdu_pairing_total_devices_number = -1;
static int hf_zbee_zcl_mdu_pairing_cmd_id = -1;
static int hf_zbee_zcl_mdu_pairing_total_commands_number = -1;
static int hf_zbee_zcl_mdu_pairing_device_eui64 = -1;
static int hf_zbee_zcl_mdu_pairing_local_info_version = -1;
static int hf_zbee_zcl_mdu_pairing_requesting_device_eui64 = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_mdu_pairing = -1;

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
dissect_zcl_mdu_pairing_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_MDU_PAIRING:
            proto_tree_add_item(tree, hf_zbee_zcl_mdu_pairing_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_mdu_pairing_attr_data*/

/**
 *ZigBee ZCL MDU Pairing cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_mdu_pairing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_mdu_pairing_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_mdu_pairing_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_mdu_pairing, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_MDU_PAIRING_REQUEST:
                    dissect_zcl_mdu_pairing_request(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_mdu_pairing_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_mdu_pairing_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_mdu_pairing, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_MDU_PAIRING_RESPONSE:
                    dissect_zcl_mdu_pairing_response(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_mdu_pairing*/

/**
 *This function manages the Pairing Request payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_mdu_pairing_request(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Local pairing information version */
    proto_tree_add_item(tree, hf_zbee_zcl_mdu_pairing_local_info_version, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* EUI64 of Requesting Device */
    proto_tree_add_item(tree, hf_zbee_zcl_mdu_pairing_requesting_device_eui64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
} /*dissect_zcl_mdu_pairing_request*/

/**
 *This function manages the Pairing Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_mdu_pairing_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8 devices_num;

    /* Pairing information version */
    proto_tree_add_item(tree, hf_zbee_zcl_mdu_pairing_info_version, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Total Number of Devices */
    devices_num = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_mdu_pairing_total_devices_number, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Command index */
    proto_tree_add_item(tree, hf_zbee_zcl_mdu_pairing_cmd_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_mdu_pairing_total_commands_number, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* EUI64 of Devices */
    for (gint i = 0; tvb_reported_length_remaining(tvb, *offset) >= 8 && i < devices_num; i++) {
        /* EUI64 of Device i */
        proto_tree_add_item(tree, hf_zbee_zcl_mdu_pairing_device_eui64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;
    }
} /*dissect_zcl_mdu_pairing_response*/

/**
 *This function registers the ZCL MDU Pairing dissector
 *
*/
void
proto_register_zbee_zcl_mdu_pairing(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_mdu_pairing_attr_id,
            { "Attribute", "zbee_zcl_se.mdu_pairing.attr_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &zbee_zcl_mdu_pairing_attr_names_ext,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_mdu_pairing_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.mdu_pairing.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_mdu_pairing_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.mdu_pairing.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_mdu_pairing_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_mdu_pairing_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.mdu_pairing.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_mdu_pairing_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_mdu_pairing_info_version,
            { "Pairing information version", "zbee_zcl_se.mdu_pairing.info_version", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_mdu_pairing_total_devices_number,
            { "Total Number of Devices", "zbee_zcl_se.mdu_pairing.total_devices_number", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_mdu_pairing_cmd_id,
            { "Command Index", "zbee_zcl_se.mdu_pairing.command_index", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_mdu_pairing_total_commands_number,
            { "Total Number of Commands", "zbee_zcl_se.mdu_pairing.total_commands_number", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_mdu_pairing_device_eui64,
            { "Device EUI64", "zbee_zcl_se.mdu_pairing.device_eui64", FT_EUI64, BASE_NONE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_mdu_pairing_local_info_version,
            { "Local Pairing Information Version", "zbee_zcl_se.mdu_pairing.local_info_version", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_mdu_pairing_requesting_device_eui64,
            { "EUI64 of Requesting Device", "zbee_zcl_se.mdu_pairing.requesting_device_eui64",  FT_EUI64, BASE_NONE, NULL,
            0x0, NULL, HFILL } },
    };

    /* ZCL MDU Pairing subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_mdu_pairing
    };

    /* Register the ZigBee ZCL MDU Pairing cluster protocol name and description */
    proto_zbee_zcl_mdu_pairing = proto_register_protocol("ZigBee ZCL MDU Pairing", "ZCL MDU Pairing", ZBEE_PROTOABBREV_ZCL_MDU_PAIRING);
    proto_register_field_array(proto_zbee_zcl_mdu_pairing, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL MDU Pairing dissector. */
    mdu_pairing_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_MDU_PAIRING, dissect_zbee_zcl_mdu_pairing, proto_zbee_zcl_mdu_pairing);
} /*proto_register_zbee_zcl_mdu_pairing*/

/**
 *Hands off the ZCL MDU Pairing dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_mdu_pairing(void)
{
    /* Register our dissector with the ZigBee application dissectors. */
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_MDU_PAIRING, mdu_pairing_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_mdu_pairing,
                            ett_zbee_zcl_mdu_pairing,
                            ZBEE_ZCL_CID_MDU_PAIRING,
                            hf_zbee_zcl_mdu_pairing_attr_id,
                            hf_zbee_zcl_mdu_pairing_srv_rx_cmd_id,
                            hf_zbee_zcl_mdu_pairing_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_mdu_pairing_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_mdu_pairing*/

/* ########################################################################## */
/* #### (0x070B) SUB-GHZ CLUSTER ############################################ */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_sub_ghz_attr_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_ATTR_ID_SUB_GHZ_CHANNEL_CHANGE,                0x0000, "Channel Change" ) \
    XXX(ZBEE_ZCL_ATTR_ID_SUB_GHZ_PAGE_28_CHANNEL_MASK,          0x0001, "Page 28 Channel Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_SUB_GHZ_PAGE_29_CHANNEL_MASK,          0x0002, "Page 29 Channel Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_SUB_GHZ_PAGE_30_CHANNEL_MASK,          0x0003, "Page 30 Channel Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_SUB_GHZ_PAGE_31_CHANNEL_MASK,          0x0004, "Page 31 Channel Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_SUB_GHZ,         0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_sub_ghz_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_sub_ghz_attr_names);
static value_string_ext zbee_zcl_sub_ghz_attr_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_sub_ghz_attr_names);

/* Server Commands Received */
#define zbee_zcl_sub_ghz_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_SUB_GHZ_GET_SUSPEND_ZCL_MESSAGES_STATUS,  0x00, "Get Suspend ZCL Messages Status" )

VALUE_STRING_ENUM(zbee_zcl_sub_ghz_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_sub_ghz_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_sub_ghz_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_SUB_GHZ_SUSPEND_ZCL_MESSAGES,             0x00, "Suspend ZCL Messages" )

VALUE_STRING_ENUM(zbee_zcl_sub_ghz_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_sub_ghz_srv_tx_cmd_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_sub_ghz(void);
void proto_reg_handoff_zbee_zcl_sub_ghz(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_sub_ghz_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Command Dissector Helpers */
static void dissect_zcl_sub_ghz_suspend_zcl_messages(tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

static dissector_handle_t sub_ghz_handle;

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_sub_ghz = -1;

static int hf_zbee_zcl_sub_ghz_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_sub_ghz_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_sub_ghz_attr_id = -1;
static int hf_zbee_zcl_sub_ghz_attr_reporting_status = -1;
static int hf_zbee_zcl_sub_ghz_zcl_messages_suspension_period = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_sub_ghz = -1;

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
dissect_zcl_sub_ghz_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_SUB_GHZ:
            proto_tree_add_item(tree, hf_zbee_zcl_sub_ghz_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_SUB_GHZ_CHANNEL_CHANGE:
        case ZBEE_ZCL_ATTR_ID_SUB_GHZ_PAGE_28_CHANNEL_MASK:
        case ZBEE_ZCL_ATTR_ID_SUB_GHZ_PAGE_29_CHANNEL_MASK:
        case ZBEE_ZCL_ATTR_ID_SUB_GHZ_PAGE_30_CHANNEL_MASK:
        case ZBEE_ZCL_ATTR_ID_SUB_GHZ_PAGE_31_CHANNEL_MASK:
        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }
} /*dissect_zcl_sub_ghz_attr_data*/


/**
 *ZigBee ZCL Sub-Ghz cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_sub_ghz(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_sub_ghz_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_sub_ghz_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_sub_ghz, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_SUB_GHZ_GET_SUSPEND_ZCL_MESSAGES_STATUS:
                    /* No Payload */
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_sub_ghz_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_sub_ghz_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_sub_ghz, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_SUB_GHZ_SUSPEND_ZCL_MESSAGES:
                    dissect_zcl_sub_ghz_suspend_zcl_messages(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_sub_ghz*/

/**
 *This function manages the Suspend ZCL Messages payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_sub_ghz_suspend_zcl_messages(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* (Optional) Suspension Period */
    if (tvb_reported_length_remaining(tvb, *offset) > 0) {
        proto_tree_add_item(tree, hf_zbee_zcl_sub_ghz_zcl_messages_suspension_period, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }
} /*dissect_zcl_sub_ghz_suspend_zcl_messages*/

/**
 *This function registers the ZCL Sub-Ghz dissector
 *
*/
void
proto_register_zbee_zcl_sub_ghz(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_sub_ghz_attr_id,
            { "Attribute", "zbee_zcl_se.sub_ghz.attr_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &zbee_zcl_sub_ghz_attr_names_ext,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_sub_ghz_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.sub_ghz.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_sub_ghz_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.sub_ghz.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_sub_ghz_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_sub_ghz_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.sub_ghz.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_sub_ghz_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_sub_ghz_zcl_messages_suspension_period,
            { "ZCL Messages Suspension Period", "zbee_zcl_se.sub_ghz.zcl_messages_suspension_period", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },
    };

    /* ZCL Sub-Ghz subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_sub_ghz
    };

    /* Register the ZigBee ZCL Sub-Ghz cluster protocol name and description */
    proto_zbee_zcl_sub_ghz = proto_register_protocol("ZigBee ZCL Sub-Ghz", "ZCL Sub-Ghz", ZBEE_PROTOABBREV_ZCL_SUB_GHZ);
    proto_register_field_array(proto_zbee_zcl_sub_ghz, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Sub-Ghz dissector. */
    sub_ghz_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_SUB_GHZ, dissect_zbee_zcl_sub_ghz, proto_zbee_zcl_sub_ghz);
} /*proto_register_zbee_zcl_sub_ghz*/

/**
 *Hands off the ZCL Sub-Ghz dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_sub_ghz(void)
{
    /* Register our dissector with the ZigBee application dissectors. */
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_SUB_GHZ, sub_ghz_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_sub_ghz,
                            ett_zbee_zcl_sub_ghz,
                            ZBEE_ZCL_CID_SUB_GHZ,
                            hf_zbee_zcl_sub_ghz_attr_id,
                            hf_zbee_zcl_sub_ghz_srv_rx_cmd_id,
                            hf_zbee_zcl_sub_ghz_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_sub_ghz_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_sub_ghz*/

/* ########################################################################## */
/* #### (0x0800) KEY ESTABLISHMENT ########################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_KE_USAGE_KEY_AGREEMENT                         0x08
#define ZBEE_ZCL_KE_USAGE_DIGITAL_SIGNATURE                     0x80

/* Attributes */
#define zbee_zcl_ke_attr_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_ATTR_ID_KE_SUITE,                              0x0000, "Supported Key Establishment Suites" )

VALUE_STRING_ARRAY(zbee_zcl_ke_attr_names);

/* Server Commands Received and Generated */
#define zbee_zcl_ke_srv_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_KE_INITIATE,                            0x00, "Initiate Key Establishment" ) \
    XXX(ZBEE_ZCL_CMD_ID_KE_EPHEMERAL,                           0x01, "Ephemeral Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_KE_CONFIRM,                             0x02, "Confirm Key Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_KE_TERMINATE,                           0x03, "Terminate Key Establishment" )

VALUE_STRING_ENUM(zbee_zcl_ke_srv_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_ke_srv_cmd_names);

/* Suite Names */
#define zbee_zcl_ke_suite_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_KE_SUITE_1,                                    0x0001, "Crypto Suite 1 (CBKE K163)" ) \
    XXX(ZBEE_ZCL_KE_SUITE_2,                                    0x0002, "Crypto Suite 2 (CBKE K283)" )

VALUE_STRING_ENUM(zbee_zcl_ke_suite_names);
VALUE_STRING_ARRAY(zbee_zcl_ke_suite_names);

/* Crypto Suite 2 Type Names */
#define zbee_zcl_ke_type_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_KE_TYPE_NO_EXT,                                0x00, "No Extensions" )

VALUE_STRING_ARRAY(zbee_zcl_ke_type_names);

/* Crypto Suite 2 Curve Names */
#define zbee_zcl_ke_curve_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_KE_CURVE_SECT283K1,                            0x0D, "sect283k1" )

VALUE_STRING_ARRAY(zbee_zcl_ke_curve_names);

/* Crypto Suite 2 Hash Names */
#define zbee_zcl_ke_hash_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_KE_HASH_AES_MMO,                               0x08, "AES MMO" )

VALUE_STRING_ARRAY(zbee_zcl_ke_hash_names);

#define zbee_zcl_ke_status_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_KE_STATUS_RESERVED,                            0x00, "Reserved" ) \
    XXX(ZBEE_ZCL_KE_STATUS_UNKNOWN_ISSUER,                      0x01, "Unknown Issuer" ) \
    XXX(ZBEE_ZCL_KE_STATUS_BAD_KEY_CONFIRM,                     0x02, "Bad Key Confirm" ) \
    XXX(ZBEE_ZCL_KE_STATUS_BAD_MESSAGE,                         0x03, "Bad Message" ) \
    XXX(ZBEE_ZCL_KE_STATUS_NO_RESOURCES,                        0x04, "No Resources" ) \
    XXX(ZBEE_ZCL_KE_STATUS_UNSUPPORTED_SUITE,                   0x05, "Unsupported Suite" ) \
    XXX(ZBEE_ZCL_KE_STATUS_INVALID_CERTIFICATE,                 0x06, "Invalid Certificate" )

VALUE_STRING_ARRAY(zbee_zcl_ke_status_names);

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_ke(void);
void proto_reg_handoff_zbee_zcl_ke(void);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

static dissector_handle_t ke_handle;

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

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_ke = -1;
static gint ett_zbee_zcl_ke_cert = -1;
static gint ett_zbee_zcl_ke_key_usage = -1;

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
        proto_tree_add_uint(tree, hf_zbee_zcl_ke_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

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
        proto_tree_add_uint(tree, hf_zbee_zcl_ke_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

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
 *This function registers the ZCL Key Establishment dissector
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

    /* Register the ZigBee ZCL Key Establishment cluster protocol name and description */
    proto_zbee_zcl_ke = proto_register_protocol("ZigBee ZCL Key Establishment", "ZCL Key Establishment", ZBEE_PROTOABBREV_ZCL_KE);
    proto_register_field_array(proto_zbee_zcl_ke, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Key Establishment dissector. */
    ke_handle = register_dissector(ZBEE_PROTOABBREV_ZCL_KE, dissect_zbee_zcl_ke, proto_zbee_zcl_ke);
} /*proto_register_zbee_zcl_ke*/

/**
 *Hands off the ZCL Key Establishment dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_ke(void)
{
    /* Register our dissector with the ZigBee application dissectors. */
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
