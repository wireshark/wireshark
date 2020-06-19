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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
 *Dissect a ZigBee Date
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to buffer offset
 *@param subtree_name name for the subtree
 *@param idx one of the ett_ array elements registered with proto_register_subtree_array()
 *@param hfindex_yy year field
 *@param hfindex_mm month field
 *@param hfindex_md month day field
 *@param hfindex_wd week day field
*/
static void dissect_zcl_date(tvbuff_t *tvb, proto_tree *tree, guint *offset,
                             gint idx, const char* subtree_name, int hfindex_yy, int hfindex_mm, int hfindex_md,
                             int hfindex_wd)
{
    guint8 yy;
    proto_tree* subtree;

    /* Add subtree */
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 4, idx, NULL, subtree_name);

    /* Year */
    yy = tvb_get_guint8(tvb, *offset);
    proto_tree_add_uint(subtree, hfindex_yy, tvb, *offset, 1, yy + 1900);
    *offset += 1;

    /* Month */
    proto_tree_add_item(subtree, hfindex_mm, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Month Day */
    proto_tree_add_item(subtree, hfindex_md, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Week Day */
    proto_tree_add_item(subtree, hfindex_wd, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_date*/

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

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_keep_alive(void);
void proto_reg_handoff_zbee_zcl_keep_alive(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_keep_alive_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

/*************************/
/* Global Variables      */
/*************************/

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_keep_alive_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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
            { "Attribute", "zbee_zcl_se.keep_alive.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_keep_alive_attr_names),
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
    register_dissector(ZBEE_PROTOABBREV_ZCL_KEEP_ALIVE, dissect_zbee_zcl_keep_alive, proto_zbee_zcl_keep_alive);
} /*proto_register_zbee_zcl_keep_alive*/

/**
 *Hands off the ZCL Keep-Alive dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_keep_alive(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_KEEP_ALIVE,
                            proto_zbee_zcl_keep_alive,
                            ett_zbee_zcl_keep_alive,
                            ZBEE_ZCL_CID_KEEP_ALIVE,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_keep_alive_attr_id,
                            -1,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_keep_alive_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_keep_alive*/

/* ########################################################################## */
/* #### (0x0700) PRICE CLUSTER ############################################## */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_price_attr_server_names_VALUE_STRING_LIST(XXX) \
/* Tier Label (Delivered) Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_PRICE_LABEL,              0x0000, "Tier 1 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_PRICE_LABEL,              0x0001, "Tier 2 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_PRICE_LABEL,              0x0002, "Tier 3 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_PRICE_LABEL,              0x0003, "Tier 4 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_PRICE_LABEL,              0x0004, "Tier 5 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_PRICE_LABEL,              0x0005, "Tier 6 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_PRICE_LABEL,              0x0006, "Tier 7 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_PRICE_LABEL,              0x0007, "Tier 8 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_PRICE_LABEL,              0x0008, "Tier 9 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_PRICE_LABEL,             0x0009, "Tier 10 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_PRICE_LABEL,             0x000A, "Tier 11 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_PRICE_LABEL,             0x000B, "Tier 12 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_PRICE_LABEL,             0x000C, "Tier 13 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_PRICE_LABEL,             0x000D, "Tier 14 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_PRICE_LABEL,             0x000E, "Tier 15 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_16_PRICE_LABEL,             0x000F, "Tier 16 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_17_PRICE_LABEL,             0x0010, "Tier 17 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_18_PRICE_LABEL,             0x0011, "Tier 18 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_19_PRICE_LABEL,             0x0012, "Tier 19 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_20_PRICE_LABEL,             0x0013, "Tier 20 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_21_PRICE_LABEL,             0x0014, "Tier 21 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_22_PRICE_LABEL,             0x0015, "Tier 22 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_23_PRICE_LABEL,             0x0016, "Tier 23 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_24_PRICE_LABEL,             0x0017, "Tier 24 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_25_PRICE_LABEL,             0x0018, "Tier 25 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_26_PRICE_LABEL,             0x0019, "Tier 26 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_27_PRICE_LABEL,             0x001A, "Tier 27 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_28_PRICE_LABEL,             0x001B, "Tier 28 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_29_PRICE_LABEL,             0x001C, "Tier 29 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_30_PRICE_LABEL,             0x001D, "Tier 30 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_31_PRICE_LABEL,             0x001E, "Tier 31 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_32_PRICE_LABEL,             0x001F, "Tier 32 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_33_PRICE_LABEL,             0x0020, "Tier 33 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_34_PRICE_LABEL,             0x0021, "Tier 34 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_35_PRICE_LABEL,             0x0022, "Tier 35 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_36_PRICE_LABEL,             0x0023, "Tier 36 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_37_PRICE_LABEL,             0x0024, "Tier 37 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_38_PRICE_LABEL,             0x0025, "Tier 38 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_39_PRICE_LABEL,             0x0026, "Tier 39 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_40_PRICE_LABEL,             0x0027, "Tier 40 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_41_PRICE_LABEL,             0x0028, "Tier 41 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_42_PRICE_LABEL,             0x0029, "Tier 42 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_43_PRICE_LABEL,             0x002A, "Tier 43 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_44_PRICE_LABEL,             0x002B, "Tier 44 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_45_PRICE_LABEL,             0x002C, "Tier 45 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_46_PRICE_LABEL,             0x002D, "Tier 46 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_47_PRICE_LABEL,             0x002E, "Tier 47 Price Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_48_PRICE_LABEL,             0x002F, "Tier 48 Price Label" ) \
/* Block Threshold (Delivered) Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_1_THRESHOLD,               0x0100, "Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_2_THRESHOLD,               0x0101, "Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_3_THRESHOLD,               0x0102, "Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_4_THRESHOLD,               0x0103, "Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_5_THRESHOLD,               0x0104, "Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_6_THRESHOLD,               0x0105, "Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_7_THRESHOLD,               0x0106, "Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_8_THRESHOLD,               0x0107, "Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_9_THRESHOLD,               0x0108, "Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_10_THRESHOLD,              0x0109, "Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_11_THRESHOLD,              0x010A, "Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_12_THRESHOLD,              0x010B, "Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_13_THRESHOLD,              0x010C, "Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_14_THRESHOLD,              0x010D, "Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_15_THRESHOLD,              0x010E, "Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_THRESHOLD_COUNT,           0x010F, "Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_1_THRESHOLD,        0x0110, "Tier 1 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_2_THRESHOLD,        0x0111, "Tier 1 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_3_THRESHOLD,        0x0112, "Tier 1 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_4_THRESHOLD,        0x0113, "Tier 1 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_5_THRESHOLD,        0x0114, "Tier 1 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_6_THRESHOLD,        0x0115, "Tier 1 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_7_THRESHOLD,        0x0116, "Tier 1 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_8_THRESHOLD,        0x0117, "Tier 1 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_9_THRESHOLD,        0x0118, "Tier 1 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_10_THRESHOLD,       0x0119, "Tier 1 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_11_THRESHOLD,       0x011A, "Tier 1 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_12_THRESHOLD,       0x011B, "Tier 1 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_13_THRESHOLD,       0x011C, "Tier 1 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_14_THRESHOLD,       0x011D, "Tier 1 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_15_THRESHOLD,       0x011E, "Tier 1 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_THRESHOLD_COUNT,    0x011F, "Tier 1 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_1_THRESHOLD,        0x0120, "Tier 2 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_2_THRESHOLD,        0x0121, "Tier 2 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_3_THRESHOLD,        0x0122, "Tier 2 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_4_THRESHOLD,        0x0123, "Tier 2 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_5_THRESHOLD,        0x0124, "Tier 2 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_6_THRESHOLD,        0x0125, "Tier 2 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_7_THRESHOLD,        0x0126, "Tier 2 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_8_THRESHOLD,        0x0127, "Tier 2 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_9_THRESHOLD,        0x0128, "Tier 2 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_10_THRESHOLD,       0x0129, "Tier 2 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_11_THRESHOLD,       0x012A, "Tier 2 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_12_THRESHOLD,       0x012B, "Tier 2 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_13_THRESHOLD,       0x012C, "Tier 2 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_14_THRESHOLD,       0x012D, "Tier 2 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_15_THRESHOLD,       0x012E, "Tier 2 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_THRESHOLD_COUNT,    0x012F, "Tier 2 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_1_THRESHOLD,        0x0130, "Tier 3 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_2_THRESHOLD,        0x0131, "Tier 3 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_3_THRESHOLD,        0x0132, "Tier 3 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_4_THRESHOLD,        0x0133, "Tier 3 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_5_THRESHOLD,        0x0134, "Tier 3 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_6_THRESHOLD,        0x0135, "Tier 3 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_7_THRESHOLD,        0x0136, "Tier 3 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_8_THRESHOLD,        0x0137, "Tier 3 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_9_THRESHOLD,        0x0138, "Tier 3 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_10_THRESHOLD,       0x0139, "Tier 3 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_11_THRESHOLD,       0x013A, "Tier 3 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_12_THRESHOLD,       0x013B, "Tier 3 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_13_THRESHOLD,       0x013C, "Tier 3 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_14_THRESHOLD,       0x013D, "Tier 3 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_15_THRESHOLD,       0x013E, "Tier 3 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_THRESHOLD_COUNT,    0x013F, "Tier 3 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_1_THRESHOLD,        0x0140, "Tier 4 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_2_THRESHOLD,        0x0141, "Tier 4 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_3_THRESHOLD,        0x0142, "Tier 4 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_4_THRESHOLD,        0x0143, "Tier 4 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_5_THRESHOLD,        0x0144, "Tier 4 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_6_THRESHOLD,        0x0145, "Tier 4 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_7_THRESHOLD,        0x0146, "Tier 4 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_8_THRESHOLD,        0x0147, "Tier 4 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_9_THRESHOLD,        0x0148, "Tier 4 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_10_THRESHOLD,       0x0149, "Tier 4 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_11_THRESHOLD,       0x014A, "Tier 4 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_12_THRESHOLD,       0x014B, "Tier 4 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_13_THRESHOLD,       0x014C, "Tier 4 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_14_THRESHOLD,       0x014D, "Tier 4 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_15_THRESHOLD,       0x014E, "Tier 4 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_THRESHOLD_COUNT,    0x014F, "Tier 4 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_1_THRESHOLD,        0x0150, "Tier 5 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_2_THRESHOLD,        0x0151, "Tier 5 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_3_THRESHOLD,        0x0152, "Tier 5 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_4_THRESHOLD,        0x0153, "Tier 5 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_5_THRESHOLD,        0x0154, "Tier 5 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_6_THRESHOLD,        0x0155, "Tier 5 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_7_THRESHOLD,        0x0156, "Tier 5 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_8_THRESHOLD,        0x0157, "Tier 5 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_9_THRESHOLD,        0x0158, "Tier 5 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_10_THRESHOLD,       0x0159, "Tier 5 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_11_THRESHOLD,       0x015A, "Tier 5 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_12_THRESHOLD,       0x015B, "Tier 5 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_13_THRESHOLD,       0x015C, "Tier 5 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_14_THRESHOLD,       0x015D, "Tier 5 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_15_THRESHOLD,       0x015E, "Tier 5 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_THRESHOLD_COUNT,    0x015F, "Tier 5 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_1_THRESHOLD,        0x0160, "Tier 6 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_2_THRESHOLD,        0x0161, "Tier 6 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_3_THRESHOLD,        0x0162, "Tier 6 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_4_THRESHOLD,        0x0163, "Tier 6 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_5_THRESHOLD,        0x0164, "Tier 6 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_6_THRESHOLD,        0x0165, "Tier 6 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_7_THRESHOLD,        0x0166, "Tier 6 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_8_THRESHOLD,        0x0167, "Tier 6 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_9_THRESHOLD,        0x0168, "Tier 6 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_10_THRESHOLD,       0x0169, "Tier 6 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_11_THRESHOLD,       0x016A, "Tier 6 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_12_THRESHOLD,       0x016B, "Tier 6 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_13_THRESHOLD,       0x016C, "Tier 6 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_14_THRESHOLD,       0x016D, "Tier 6 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_15_THRESHOLD,       0x016E, "Tier 6 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_THRESHOLD_COUNT,    0x016F, "Tier 6 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_1_THRESHOLD,        0x0170, "Tier 7 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_2_THRESHOLD,        0x0171, "Tier 7 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_3_THRESHOLD,        0x0172, "Tier 7 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_4_THRESHOLD,        0x0173, "Tier 7 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_5_THRESHOLD,        0x0174, "Tier 7 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_6_THRESHOLD,        0x0175, "Tier 7 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_7_THRESHOLD,        0x0176, "Tier 7 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_8_THRESHOLD,        0x0177, "Tier 7 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_9_THRESHOLD,        0x0178, "Tier 7 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_10_THRESHOLD,       0x0179, "Tier 7 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_11_THRESHOLD,       0x017A, "Tier 7 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_12_THRESHOLD,       0x017B, "Tier 7 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_13_THRESHOLD,       0x017C, "Tier 7 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_14_THRESHOLD,       0x017D, "Tier 7 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_15_THRESHOLD,       0x017E, "Tier 7 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_THRESHOLD_COUNT,    0x017F, "Tier 7 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_1_THRESHOLD,        0x0180, "Tier 8 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_2_THRESHOLD,        0x0181, "Tier 8 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_3_THRESHOLD,        0x0182, "Tier 8 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_4_THRESHOLD,        0x0183, "Tier 8 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_5_THRESHOLD,        0x0184, "Tier 8 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_6_THRESHOLD,        0x0185, "Tier 8 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_7_THRESHOLD,        0x0186, "Tier 8 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_8_THRESHOLD,        0x0187, "Tier 8 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_9_THRESHOLD,        0x0188, "Tier 8 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_10_THRESHOLD,       0x0189, "Tier 8 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_11_THRESHOLD,       0x018A, "Tier 8 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_12_THRESHOLD,       0x018B, "Tier 8 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_13_THRESHOLD,       0x018C, "Tier 8 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_14_THRESHOLD,       0x018D, "Tier 8 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_15_THRESHOLD,       0x018E, "Tier 8 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_THRESHOLD_COUNT,    0x018F, "Tier 8 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_1_THRESHOLD,        0x0190, "Tier 9 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_2_THRESHOLD,        0x0191, "Tier 9 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_3_THRESHOLD,        0x0192, "Tier 9 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_4_THRESHOLD,        0x0193, "Tier 9 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_5_THRESHOLD,        0x0194, "Tier 9 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_6_THRESHOLD,        0x0195, "Tier 9 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_7_THRESHOLD,        0x0196, "Tier 9 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_8_THRESHOLD,        0x0197, "Tier 9 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_9_THRESHOLD,        0x0198, "Tier 9 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_10_THRESHOLD,       0x0199, "Tier 9 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_11_THRESHOLD,       0x019A, "Tier 9 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_12_THRESHOLD,       0x019B, "Tier 9 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_13_THRESHOLD,       0x019C, "Tier 9 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_14_THRESHOLD,       0x019D, "Tier 9 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_15_THRESHOLD,       0x019E, "Tier 9 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_THRESHOLD_COUNT,    0x019F, "Tier 9 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_1_THRESHOLD,       0x01A0, "Tier 10 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_2_THRESHOLD,       0x01A1, "Tier 10 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_3_THRESHOLD,       0x01A2, "Tier 10 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_4_THRESHOLD,       0x01A3, "Tier 10 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_5_THRESHOLD,       0x01A4, "Tier 10 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_6_THRESHOLD,       0x01A5, "Tier 10 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_7_THRESHOLD,       0x01A6, "Tier 10 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_8_THRESHOLD,       0x01A7, "Tier 10 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_9_THRESHOLD,       0x01A8, "Tier 10 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_10_THRESHOLD,      0x01A9, "Tier 10 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_11_THRESHOLD,      0x01AA, "Tier 10 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_12_THRESHOLD,      0x01AB, "Tier 10 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_13_THRESHOLD,      0x01AC, "Tier 10 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_14_THRESHOLD,      0x01AD, "Tier 10 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_15_THRESHOLD,      0x01AE, "Tier 10 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_THRESHOLD_COUNT,   0x01AF, "Tier 10 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_1_THRESHOLD,       0x01B0, "Tier 11 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_2_THRESHOLD,       0x01B1, "Tier 11 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_3_THRESHOLD,       0x01B2, "Tier 11 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_4_THRESHOLD,       0x01B3, "Tier 11 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_5_THRESHOLD,       0x01B4, "Tier 11 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_6_THRESHOLD,       0x01B5, "Tier 11 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_7_THRESHOLD,       0x01B6, "Tier 11 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_8_THRESHOLD,       0x01B7, "Tier 11 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_9_THRESHOLD,       0x01B8, "Tier 11 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_10_THRESHOLD,      0x01B9, "Tier 11 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_11_THRESHOLD,      0x01BA, "Tier 11 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_12_THRESHOLD,      0x01BB, "Tier 11 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_13_THRESHOLD,      0x01BC, "Tier 11 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_14_THRESHOLD,      0x01BD, "Tier 11 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_15_THRESHOLD,      0x01BE, "Tier 11 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_THRESHOLD_COUNT,   0x01BF, "Tier 11 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_1_THRESHOLD,       0x01C0, "Tier 12 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_2_THRESHOLD,       0x01C1, "Tier 12 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_3_THRESHOLD,       0x01C2, "Tier 12 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_4_THRESHOLD,       0x01C3, "Tier 12 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_5_THRESHOLD,       0x01C4, "Tier 12 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_6_THRESHOLD,       0x01C5, "Tier 12 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_7_THRESHOLD,       0x01C6, "Tier 12 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_8_THRESHOLD,       0x01C7, "Tier 12 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_9_THRESHOLD,       0x01C8, "Tier 12 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_10_THRESHOLD,      0x01C9, "Tier 12 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_11_THRESHOLD,      0x01CA, "Tier 12 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_12_THRESHOLD,      0x01CB, "Tier 12 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_13_THRESHOLD,      0x01CC, "Tier 12 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_14_THRESHOLD,      0x01CD, "Tier 12 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_15_THRESHOLD,      0x01CE, "Tier 12 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_THRESHOLD_COUNT,   0x01CF, "Tier 12 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_1_THRESHOLD,       0x01D0, "Tier 13 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_2_THRESHOLD,       0x01D1, "Tier 13 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_3_THRESHOLD,       0x01D2, "Tier 13 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_4_THRESHOLD,       0x01D3, "Tier 13 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_5_THRESHOLD,       0x01D4, "Tier 13 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_6_THRESHOLD,       0x01D5, "Tier 13 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_7_THRESHOLD,       0x01D6, "Tier 13 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_8_THRESHOLD,       0x01D7, "Tier 13 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_9_THRESHOLD,       0x01D8, "Tier 13 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_10_THRESHOLD,      0x01D9, "Tier 13 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_11_THRESHOLD,      0x01DA, "Tier 13 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_12_THRESHOLD,      0x01DB, "Tier 13 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_13_THRESHOLD,      0x01DC, "Tier 13 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_14_THRESHOLD,      0x01DD, "Tier 13 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_15_THRESHOLD,      0x01DE, "Tier 13 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_THRESHOLD_COUNT,   0x01DF, "Tier 13 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_1_THRESHOLD,       0x01E0, "Tier 14 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_2_THRESHOLD,       0x01E1, "Tier 14 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_3_THRESHOLD,       0x01E2, "Tier 14 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_4_THRESHOLD,       0x01E3, "Tier 14 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_5_THRESHOLD,       0x01E4, "Tier 14 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_6_THRESHOLD,       0x01E5, "Tier 14 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_7_THRESHOLD,       0x01E6, "Tier 14 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_8_THRESHOLD,       0x01E7, "Tier 14 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_9_THRESHOLD,       0x01E8, "Tier 14 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_10_THRESHOLD,      0x01E9, "Tier 14 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_11_THRESHOLD,      0x01EA, "Tier 14 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_12_THRESHOLD,      0x01EB, "Tier 14 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_13_THRESHOLD,      0x01EC, "Tier 14 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_14_THRESHOLD,      0x01ED, "Tier 14 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_15_THRESHOLD,      0x01EE, "Tier 14 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_THRESHOLD_COUNT,   0x01EF, "Tier 14 Block Threshold Count" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_1_THRESHOLD,       0x01F0, "Tier 15 Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_2_THRESHOLD,       0x01F1, "Tier 15 Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_3_THRESHOLD,       0x01F2, "Tier 15 Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_4_THRESHOLD,       0x01F3, "Tier 15 Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_5_THRESHOLD,       0x01F4, "Tier 15 Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_6_THRESHOLD,       0x01F5, "Tier 15 Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_7_THRESHOLD,       0x01F6, "Tier 15 Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_8_THRESHOLD,       0x01F7, "Tier 15 Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_9_THRESHOLD,       0x01F8, "Tier 15 Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_10_THRESHOLD,      0x01F9, "Tier 15 Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_11_THRESHOLD,      0x01FA, "Tier 15 Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_12_THRESHOLD,      0x01FB, "Tier 15 Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_13_THRESHOLD,      0x01FC, "Tier 15 Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_14_THRESHOLD,      0x01FD, "Tier 15 Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_15_THRESHOLD,      0x01FE, "Tier 15 Block 15 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_THRESHOLD_COUNT,   0x01FF, "Tier 15 Block Threshold Count" ) \
/* Block Period (Delivered) Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_START_OF_BLOCK_PERIOD,           0x0200, "Start of Block Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_PERIOD_DURATION,           0x0201, "Block Period Duration" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_THRESHOLD_MULTIPLIER,            0x0202, "Threshold Multiplier" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_THRESHOLD_DIVISOR,               0x0203, "Threshold Divisor" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_BLOCK_PERIOD_DURATION_TYPE,      0x0204, "Block Period Duration Type" ) \
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
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_5_PRICE,           0x0404, "No Tier Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_6_PRICE,           0x0405, "No Tier Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_7_PRICE,           0x0406, "No Tier Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_8_PRICE,           0x0407, "No Tier Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_9_PRICE,           0x0408, "No Tier Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_10_PRICE,          0x0409, "No Tier Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_11_PRICE,          0x040A, "No Tier Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_12_PRICE,          0x040B, "No Tier Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_13_PRICE,          0x040C, "No Tier Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_14_PRICE,          0x040D, "No Tier Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_15_PRICE,          0x040E, "No Tier Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NO_TIER_BLOCK_16_PRICE,          0x040F, "No Tier Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_1_PRICE,            0x0410, "Tier 1 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_2_PRICE,            0x0411, "Tier 1 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_3_PRICE,            0x0412, "Tier 1 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_4_PRICE,            0x0413, "Tier 1 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_5_PRICE,            0x0414, "Tier 1 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_6_PRICE,            0x0415, "Tier 1 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_7_PRICE,            0x0416, "Tier 1 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_8_PRICE,            0x0417, "Tier 1 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_9_PRICE,            0x0418, "Tier 1 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_10_PRICE,           0x0419, "Tier 1 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_11_PRICE,           0x041A, "Tier 1 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_12_PRICE,           0x041B, "Tier 1 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_13_PRICE,           0x041C, "Tier 1 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_14_PRICE,           0x041D, "Tier 1 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_15_PRICE,           0x041E, "Tier 1 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_1_BLOCK_16_PRICE,           0x041F, "Tier 1 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_1_PRICE,            0x0420, "Tier 2 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_2_PRICE,            0x0421, "Tier 2 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_3_PRICE,            0x0422, "Tier 2 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_4_PRICE,            0x0423, "Tier 2 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_5_PRICE,            0x0424, "Tier 2 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_6_PRICE,            0x0425, "Tier 2 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_7_PRICE,            0x0426, "Tier 2 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_8_PRICE,            0x0427, "Tier 2 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_9_PRICE,            0x0428, "Tier 2 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_10_PRICE,           0x0429, "Tier 2 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_11_PRICE,           0x042A, "Tier 2 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_12_PRICE,           0x042B, "Tier 2 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_13_PRICE,           0x042C, "Tier 2 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_14_PRICE,           0x042D, "Tier 2 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_15_PRICE,           0x042E, "Tier 2 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_2_BLOCK_16_PRICE,           0x042F, "Tier 2 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_1_PRICE,            0x0430, "Tier 3 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_2_PRICE,            0x0431, "Tier 3 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_3_PRICE,            0x0432, "Tier 3 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_4_PRICE,            0x0433, "Tier 3 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_5_PRICE,            0x0434, "Tier 3 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_6_PRICE,            0x0435, "Tier 3 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_7_PRICE,            0x0436, "Tier 3 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_8_PRICE,            0x0437, "Tier 3 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_9_PRICE,            0x0438, "Tier 3 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_10_PRICE,           0x0439, "Tier 3 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_11_PRICE,           0x043A, "Tier 3 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_12_PRICE,           0x043B, "Tier 3 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_13_PRICE,           0x043C, "Tier 3 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_14_PRICE,           0x043D, "Tier 3 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_15_PRICE,           0x043E, "Tier 3 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_3_BLOCK_16_PRICE,           0x043F, "Tier 3 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_1_PRICE,            0x0440, "Tier 4 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_2_PRICE,            0x0441, "Tier 4 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_3_PRICE,            0x0442, "Tier 4 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_4_PRICE,            0x0443, "Tier 4 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_5_PRICE,            0x0444, "Tier 4 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_6_PRICE,            0x0445, "Tier 4 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_7_PRICE,            0x0446, "Tier 4 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_8_PRICE,            0x0447, "Tier 4 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_9_PRICE,            0x0448, "Tier 4 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_10_PRICE,           0x0449, "Tier 4 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_11_PRICE,           0x044A, "Tier 4 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_12_PRICE,           0x044B, "Tier 4 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_13_PRICE,           0x044C, "Tier 4 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_14_PRICE,           0x044D, "Tier 4 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_15_PRICE,           0x044E, "Tier 4 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_4_BLOCK_16_PRICE,           0x044F, "Tier 4 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_1_PRICE,            0x0450, "Tier 5 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_2_PRICE,            0x0451, "Tier 5 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_3_PRICE,            0x0452, "Tier 5 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_4_PRICE,            0x0453, "Tier 5 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_5_PRICE,            0x0454, "Tier 5 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_6_PRICE,            0x0455, "Tier 5 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_7_PRICE,            0x0456, "Tier 5 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_8_PRICE,            0x0457, "Tier 5 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_9_PRICE,            0x0458, "Tier 5 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_10_PRICE,           0x0459, "Tier 5 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_11_PRICE,           0x045A, "Tier 5 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_12_PRICE,           0x045B, "Tier 5 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_13_PRICE,           0x045C, "Tier 5 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_14_PRICE,           0x045D, "Tier 5 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_15_PRICE,           0x045E, "Tier 5 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_5_BLOCK_16_PRICE,           0x045F, "Tier 5 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_1_PRICE,            0x0460, "Tier 6 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_2_PRICE,            0x0461, "Tier 6 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_3_PRICE,            0x0462, "Tier 6 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_4_PRICE,            0x0463, "Tier 6 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_5_PRICE,            0x0464, "Tier 6 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_6_PRICE,            0x0465, "Tier 6 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_7_PRICE,            0x0466, "Tier 6 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_8_PRICE,            0x0467, "Tier 6 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_9_PRICE,            0x0468, "Tier 6 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_10_PRICE,           0x0469, "Tier 6 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_11_PRICE,           0x046A, "Tier 6 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_12_PRICE,           0x046B, "Tier 6 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_13_PRICE,           0x046C, "Tier 6 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_14_PRICE,           0x046D, "Tier 6 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_15_PRICE,           0x046E, "Tier 6 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_6_BLOCK_16_PRICE,           0x046F, "Tier 6 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_1_PRICE,            0x0470, "Tier 7 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_2_PRICE,            0x0471, "Tier 7 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_3_PRICE,            0x0472, "Tier 7 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_4_PRICE,            0x0473, "Tier 7 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_5_PRICE,            0x0474, "Tier 7 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_6_PRICE,            0x0475, "Tier 7 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_7_PRICE,            0x0476, "Tier 7 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_8_PRICE,            0x0477, "Tier 7 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_9_PRICE,            0x0478, "Tier 7 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_10_PRICE,           0x0479, "Tier 7 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_11_PRICE,           0x047A, "Tier 7 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_12_PRICE,           0x047B, "Tier 7 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_13_PRICE,           0x047C, "Tier 7 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_14_PRICE,           0x047D, "Tier 7 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_15_PRICE,           0x047E, "Tier 7 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_7_BLOCK_16_PRICE,           0x047F, "Tier 7 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_1_PRICE,            0x0480, "Tier 8 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_2_PRICE,            0x0481, "Tier 8 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_3_PRICE,            0x0482, "Tier 8 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_4_PRICE,            0x0483, "Tier 8 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_5_PRICE,            0x0484, "Tier 8 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_6_PRICE,            0x0485, "Tier 8 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_7_PRICE,            0x0486, "Tier 8 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_8_PRICE,            0x0487, "Tier 8 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_9_PRICE,            0x0488, "Tier 8 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_10_PRICE,           0x0489, "Tier 8 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_11_PRICE,           0x048A, "Tier 8 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_12_PRICE,           0x048B, "Tier 8 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_13_PRICE,           0x048C, "Tier 8 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_14_PRICE,           0x048D, "Tier 8 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_15_PRICE,           0x048E, "Tier 8 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_8_BLOCK_16_PRICE,           0x048F, "Tier 8 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_1_PRICE,            0x0490, "Tier 9 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_2_PRICE,            0x0491, "Tier 9 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_3_PRICE,            0x0492, "Tier 9 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_4_PRICE,            0x0493, "Tier 9 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_5_PRICE,            0x0494, "Tier 9 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_6_PRICE,            0x0495, "Tier 9 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_7_PRICE,            0x0496, "Tier 9 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_8_PRICE,            0x0497, "Tier 9 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_9_PRICE,            0x0498, "Tier 9 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_10_PRICE,           0x0499, "Tier 9 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_11_PRICE,           0x049A, "Tier 9 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_12_PRICE,           0x049B, "Tier 9 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_13_PRICE,           0x049C, "Tier 9 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_14_PRICE,           0x049D, "Tier 9 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_15_PRICE,           0x049E, "Tier 9 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_9_BLOCK_16_PRICE,           0x049F, "Tier 9 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_1_PRICE,           0x04A0, "Tier 10 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_2_PRICE,           0x04A1, "Tier 10 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_3_PRICE,           0x04A2, "Tier 10 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_4_PRICE,           0x04A3, "Tier 10 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_5_PRICE,           0x04A4, "Tier 10 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_6_PRICE,           0x04A5, "Tier 10 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_7_PRICE,           0x04A6, "Tier 10 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_8_PRICE,           0x04A7, "Tier 10 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_9_PRICE,           0x04A8, "Tier 10 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_10_PRICE,          0x04A9, "Tier 10 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_11_PRICE,          0x04AA, "Tier 10 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_12_PRICE,          0x04AB, "Tier 10 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_13_PRICE,          0x04AC, "Tier 10 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_14_PRICE,          0x04AD, "Tier 10 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_15_PRICE,          0x04AE, "Tier 10 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_10_BLOCK_16_PRICE,          0x04AF, "Tier 10 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_1_PRICE,           0x04B0, "Tier 11 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_2_PRICE,           0x04B1, "Tier 11 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_3_PRICE,           0x04B2, "Tier 11 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_4_PRICE,           0x04B3, "Tier 11 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_5_PRICE,           0x04B4, "Tier 11 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_6_PRICE,           0x04B5, "Tier 11 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_7_PRICE,           0x04B6, "Tier 11 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_8_PRICE,           0x04B7, "Tier 11 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_9_PRICE,           0x04B8, "Tier 11 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_10_PRICE,          0x04B9, "Tier 11 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_11_PRICE,          0x04BA, "Tier 11 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_12_PRICE,          0x04BB, "Tier 11 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_13_PRICE,          0x04BC, "Tier 11 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_14_PRICE,          0x04BD, "Tier 11 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_15_PRICE,          0x04BE, "Tier 11 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_11_BLOCK_16_PRICE,          0x04BF, "Tier 11 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_1_PRICE,           0x04C0, "Tier 12 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_2_PRICE,           0x04C1, "Tier 12 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_3_PRICE,           0x04C2, "Tier 12 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_4_PRICE,           0x04C3, "Tier 12 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_5_PRICE,           0x04C4, "Tier 12 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_6_PRICE,           0x04C5, "Tier 12 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_7_PRICE,           0x04C6, "Tier 12 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_8_PRICE,           0x04C7, "Tier 12 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_9_PRICE,           0x04C8, "Tier 12 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_10_PRICE,          0x04C9, "Tier 12 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_11_PRICE,          0x04CA, "Tier 12 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_12_PRICE,          0x04CB, "Tier 12 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_13_PRICE,          0x04CC, "Tier 12 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_14_PRICE,          0x04CD, "Tier 12 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_15_PRICE,          0x04CE, "Tier 12 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_12_BLOCK_16_PRICE,          0x04CF, "Tier 12 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_1_PRICE,           0x04D0, "Tier 13 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_2_PRICE,           0x04D1, "Tier 13 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_3_PRICE,           0x04D2, "Tier 13 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_4_PRICE,           0x04D3, "Tier 13 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_5_PRICE,           0x04D4, "Tier 13 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_6_PRICE,           0x04D5, "Tier 13 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_7_PRICE,           0x04D6, "Tier 13 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_8_PRICE,           0x04D7, "Tier 13 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_9_PRICE,           0x04D8, "Tier 13 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_10_PRICE,          0x04D9, "Tier 13 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_11_PRICE,          0x04DA, "Tier 13 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_12_PRICE,          0x04DB, "Tier 13 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_13_PRICE,          0x04DC, "Tier 13 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_14_PRICE,          0x04DD, "Tier 13 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_15_PRICE,          0x04DE, "Tier 13 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_13_BLOCK_16_PRICE,          0x04DF, "Tier 13 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_1_PRICE,           0x04E0, "Tier 14 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_2_PRICE,           0x04E1, "Tier 14 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_3_PRICE,           0x04E2, "Tier 14 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_4_PRICE,           0x04E3, "Tier 14 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_5_PRICE,           0x04E4, "Tier 14 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_6_PRICE,           0x04E5, "Tier 14 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_7_PRICE,           0x04E6, "Tier 14 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_8_PRICE,           0x04E7, "Tier 14 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_9_PRICE,           0x04E8, "Tier 14 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_10_PRICE,          0x04E9, "Tier 14 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_11_PRICE,          0x04EA, "Tier 14 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_12_PRICE,          0x04EB, "Tier 14 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_13_PRICE,          0x04EC, "Tier 14 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_14_PRICE,          0x04ED, "Tier 14 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_15_PRICE,          0x04EE, "Tier 14 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_14_BLOCK_16_PRICE,          0x04EF, "Tier 14 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_1_PRICE,           0x04F0, "Tier 15 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_2_PRICE,           0x04F1, "Tier 15 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_3_PRICE,           0x04F2, "Tier 15 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_4_PRICE,           0x04F3, "Tier 15 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_5_PRICE,           0x04F4, "Tier 15 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_6_PRICE,           0x04F5, "Tier 15 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_7_PRICE,           0x04F6, "Tier 15 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_8_PRICE,           0x04F7, "Tier 15 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_9_PRICE,           0x04F8, "Tier 15 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_10_PRICE,          0x04F9, "Tier 15 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_11_PRICE,          0x04FA, "Tier 15 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_12_PRICE,          0x04FB, "Tier 15 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_13_PRICE,          0x04FC, "Tier 15 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_14_PRICE,          0x04FD, "Tier 15 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_15_PRICE,          0x04FE, "Tier 15 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_15_BLOCK_16_PRICE,          0x04FF, "Tier 15 Block 16 Price" ) \
/* Extended Price Information (Delivered) Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_16,                   0x050F, "Price Tier 16" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_17,                   0x0510, "Price Tier 17" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_18,                   0x0511, "Price Tier 18" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_19,                   0x0512, "Price Tier 19" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_20,                   0x0513, "Price Tier 20" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_21,                   0x0514, "Price Tier 21" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_22,                   0x0515, "Price Tier 22" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_23,                   0x0516, "Price Tier 23" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_24,                   0x0517, "Price Tier 24" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_25,                   0x0518, "Price Tier 25" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_26,                   0x0519, "Price Tier 26" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_27,                   0x051A, "Price Tier 27" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_28,                   0x051B, "Price Tier 28" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_29,                   0x051C, "Price Tier 29" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_30,                   0x051D, "Price Tier 30" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_31,                   0x051E, "Price Tier 31" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_32,                   0x051F, "Price Tier 32" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_33,                   0x0520, "Price Tier 33" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_34,                   0x0521, "Price Tier 34" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_35,                   0x0522, "Price Tier 35" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_36,                   0x0523, "Price Tier 36" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_37,                   0x0524, "Price Tier 37" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_38,                   0x0525, "Price Tier 38" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_39,                   0x0526, "Price Tier 39" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_40,                   0x0527, "Price Tier 40" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_41,                   0x0528, "Price Tier 41" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_42,                   0x0529, "Price Tier 42" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_43,                   0x052A, "Price Tier 43" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_44,                   0x052B, "Price Tier 44" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_45,                   0x052C, "Price Tier 45" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_46,                   0x052D, "Price Tier 46" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_47,                   0x052E, "Price Tier 47" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TIER_48,                   0x052F, "Price Tier 48" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CPP_1_PRICE,                     0x05FE, "CPP 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CPP_2_PRICE,                     0x05FF, "CPP 2 Price" ) \
/* Tariff Information Set (Delivered) */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TARIFF_LABEL,                    0x0610, "Tariff Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NUMBER_OF_PRICE_TIERS_IN_USE,    0x0611, "Number of Price Tiers in Use" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_NUMBER_OF_BLOCK_THRES_IN_USE,    0x0612, "Number of Block Thresholds in Use" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TIER_BLOCK_MODE,                 0x0613, "Tier Block Mode" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_UNIT_OF_MEASURE,                 0x0615, "Unit of Measure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CURRENCY,                        0x0616, "Currency" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PRICE_TRAILING_DIGIT,            0x0617, "Price Trailing Digit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_TARIFF_RESOLUTION_PERIOD,        0x0619, "Tariff Resolution Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CO2,                             0x0620, "CO2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CO2_UNIT,                        0x0621, "CO2 Unit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CO2_TRAILING_DIGIT,              0x0622, "CO2 Trailing Digit" ) \
/* Billing Information (Delivered) Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CURRENT_BILLING_PERIOD_START,    0x0700, "Current Billing Period Start" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CURRENT_BILLING_PERIOD_DURATION, 0x0701, "Current Billing Period Duration" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_LAST_BILLING_PERIOD_START,       0x0702, "Last Billing Period Start" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_LAST_BILLING_PERIOD_DURATION,    0x0703, "Last Billing Period Duration" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_LAST_BILLING_PERIOD_CON_BILL,    0x0704, "Last Billing Period Consolidated Bill" ) \
/* Credit Payment Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_DUE_DATE,         0x0800, "Credit Payment Due Date" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_STATUS,           0x0801, "Credit Payment Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_OVER_DUE_AMOUNT,  0x0802, "Credit Payment Over Due Amount" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PAYMENT_DISCOUNT,                0x080A, "Payment Discount" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_PAYMENT_DISCOUNT_PERIOD,         0x080B, "Payment Discount Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_1,                0x0810, "Credit Payment #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_DATE_1,           0x0811, "Credit Payment Date #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_REF_1,            0x0812, "Credit Payment Ref #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_2,                0x0820, "Credit Payment #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_DATE_2,           0x0821, "Credit Payment Date #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_REF_2,            0x0822, "Credit Payment Ref #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_3,                0x0830, "Credit Payment #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_DATE_3,           0x0831, "Credit Payment Date #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_REF_3,            0x0832, "Credit Payment Ref #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_4,                0x0840, "Credit Payment #4" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_DATE_4,           0x0841, "Credit Payment Date #4" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_REF_4,            0x0842, "Credit Payment Ref #4" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_5,                0x0850, "Credit Payment #5" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_DATE_5,           0x0851, "Credit Payment Date #5" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CREDIT_PAYMENT_REF_5,            0x0852, "Credit Payment Ref #5" ) \
/* Received Tier Label Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_1_PRICE_LABEL,     0x8000, "Received Tier 1 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_2_PRICE_LABEL,     0x8001, "Received Tier 2 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_3_PRICE_LABEL,     0x8002, "Received Tier 3 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_4_PRICE_LABEL,     0x8003, "Received Tier 4 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_5_PRICE_LABEL,     0x8004, "Received Tier 5 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_6_PRICE_LABEL,     0x8005, "Received Tier 6 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_7_PRICE_LABEL,     0x8006, "Received Tier 7 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_8_PRICE_LABEL,     0x8007, "Received Tier 8 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_9_PRICE_LABEL,     0x8008, "Received Tier 9 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_10_PRICE_LABEL,    0x8009, "Received Tier 10 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_11_PRICE_LABEL,    0x800A, "Received Tier 11 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_12_PRICE_LABEL,    0x800B, "Received Tier 12 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_13_PRICE_LABEL,    0x800C, "Received Tier 13 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_14_PRICE_LABEL,    0x800D, "Received Tier 14 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_15_PRICE_LABEL,    0x800E, "Received Tier 15 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_16_PRICE_LABEL,    0x800F, "Received Tier 16 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_17_PRICE_LABEL,    0x8010, "Received Tier 17 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_18_PRICE_LABEL,    0x8011, "Received Tier 18 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_19_PRICE_LABEL,    0x8012, "Received Tier 19 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_20_PRICE_LABEL,    0x8013, "Received Tier 20 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_21_PRICE_LABEL,    0x8014, "Received Tier 21 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_22_PRICE_LABEL,    0x8015, "Received Tier 22 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_23_PRICE_LABEL,    0x8016, "Received Tier 23 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_24_PRICE_LABEL,    0x8017, "Received Tier 24 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_25_PRICE_LABEL,    0x8018, "Received Tier 25 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_26_PRICE_LABEL,    0x8019, "Received Tier 26 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_27_PRICE_LABEL,    0x801A, "Received Tier 27 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_28_PRICE_LABEL,    0x801B, "Received Tier 28 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_29_PRICE_LABEL,    0x801C, "Received Tier 29 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_30_PRICE_LABEL,    0x801D, "Received Tier 30 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_31_PRICE_LABEL,    0x801E, "Received Tier 31 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_32_PRICE_LABEL,    0x801F, "Received Tier 32 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_33_PRICE_LABEL,    0x8020, "Received Tier 33 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_34_PRICE_LABEL,    0x8021, "Received Tier 34 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_35_PRICE_LABEL,    0x8022, "Received Tier 35 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_36_PRICE_LABEL,    0x8023, "Received Tier 36 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_37_PRICE_LABEL,    0x8024, "Received Tier 37 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_38_PRICE_LABEL,    0x8025, "Received Tier 38 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_39_PRICE_LABEL,    0x8026, "Received Tier 39 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_40_PRICE_LABEL,    0x8027, "Received Tier 40 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_41_PRICE_LABEL,    0x8028, "Received Tier 41 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_42_PRICE_LABEL,    0x8029, "Received Tier 42 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_43_PRICE_LABEL,    0x802A, "Received Tier 43 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_44_PRICE_LABEL,    0x802B, "Received Tier 44 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_45_PRICE_LABEL,    0x802C, "Received Tier 45 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_46_PRICE_LABEL,    0x802D, "Received Tier 46 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_47_PRICE_LABEL,    0x802E, "Received Tier 47 Price label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_48_PRICE_LABEL,    0x802F, "Received Tier 48 Price label" ) \
/* Received Block Threshold Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_1_THRESHOLD,      0x8100, "Received Block 1 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_2_THRESHOLD,      0x8101, "Received Block 2 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_3_THRESHOLD,      0x8102, "Received Block 3 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_4_THRESHOLD,      0x8103, "Received Block 4 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_5_THRESHOLD,      0x8104, "Received Block 5 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_6_THRESHOLD,      0x8105, "Received Block 6 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_7_THRESHOLD,      0x8106, "Received Block 7 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_8_THRESHOLD,      0x8107, "Received Block 8 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_9_THRESHOLD,      0x8108, "Received Block 9 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_10_THRESHOLD,     0x8109, "Received Block 10 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_11_THRESHOLD,     0x810A, "Received Block 11 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_12_THRESHOLD,     0x810B, "Received Block 12 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_13_THRESHOLD,     0x810C, "Received Block 13 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_14_THRESHOLD,     0x810D, "Received Block 14 Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_15_THRESHOLD,     0x810E, "Received Block 15 Threshold" ) \
/* Received Block Period Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_START_OF_BLOCK_PERIOD,  0x8200, "Received Start of Block Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_BLOCK_PERIOD_DURATION,  0x8201, "Received Block Period Duration" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_THRESHOLD_MULTIPLIER,   0x8202, "Received Threshold Multiplier" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_THRESHOLD_DIVISOR,      0x8203, "Received Threshold Divisor" ) \
/* Received Block Price Information Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_1_PRICE,        0x8400, "Rx No Tier Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_2_PRICE,        0x8401, "Rx No Tier Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_3_PRICE,        0x8402, "Rx No Tier Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_4_PRICE,        0x8403, "Rx No Tier Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_5_PRICE,        0x8404, "Rx No Tier Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_6_PRICE,        0x8405, "Rx No Tier Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_7_PRICE,        0x8406, "Rx No Tier Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_8_PRICE,        0x8407, "Rx No Tier Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_9_PRICE,        0x8408, "Rx No Tier Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_10_PRICE,       0x8409, "Rx No Tier Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_11_PRICE,       0x840A, "Rx No Tier Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_12_PRICE,       0x840B, "Rx No Tier Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_13_PRICE,       0x840C, "Rx No Tier Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_14_PRICE,       0x840D, "Rx No Tier Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_15_PRICE,       0x840E, "Rx No Tier Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NO_TIER_BLOCK_16_PRICE,       0x840F, "Rx No Tier Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_1_PRICE,         0x8410, "Rx Tier 1 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_2_PRICE,         0x8411, "Rx Tier 1 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_3_PRICE,         0x8412, "Rx Tier 1 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_4_PRICE,         0x8413, "Rx Tier 1 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_5_PRICE,         0x8414, "Rx Tier 1 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_6_PRICE,         0x8415, "Rx Tier 1 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_7_PRICE,         0x8416, "Rx Tier 1 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_8_PRICE,         0x8417, "Rx Tier 1 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_9_PRICE,         0x8418, "Rx Tier 1 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_10_PRICE,        0x8419, "Rx Tier 1 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_11_PRICE,        0x841A, "Rx Tier 1 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_12_PRICE,        0x841B, "Rx Tier 1 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_13_PRICE,        0x841C, "Rx Tier 1 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_14_PRICE,        0x841D, "Rx Tier 1 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_15_PRICE,        0x841E, "Rx Tier 1 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_1_BLOCK_16_PRICE,        0x841F, "Rx Tier 1 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_1_PRICE,         0x8420, "Rx Tier 2 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_2_PRICE,         0x8421, "Rx Tier 2 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_3_PRICE,         0x8422, "Rx Tier 2 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_4_PRICE,         0x8423, "Rx Tier 2 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_5_PRICE,         0x8424, "Rx Tier 2 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_6_PRICE,         0x8425, "Rx Tier 2 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_7_PRICE,         0x8426, "Rx Tier 2 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_8_PRICE,         0x8427, "Rx Tier 2 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_9_PRICE,         0x8428, "Rx Tier 2 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_10_PRICE,        0x8429, "Rx Tier 2 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_11_PRICE,        0x842A, "Rx Tier 2 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_12_PRICE,        0x842B, "Rx Tier 2 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_13_PRICE,        0x842C, "Rx Tier 2 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_14_PRICE,        0x842D, "Rx Tier 2 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_15_PRICE,        0x842E, "Rx Tier 2 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_2_BLOCK_16_PRICE,        0x842F, "Rx Tier 2 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_1_PRICE,         0x8430, "Rx Tier 3 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_2_PRICE,         0x8431, "Rx Tier 3 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_3_PRICE,         0x8432, "Rx Tier 3 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_4_PRICE,         0x8433, "Rx Tier 3 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_5_PRICE,         0x8434, "Rx Tier 3 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_6_PRICE,         0x8435, "Rx Tier 3 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_7_PRICE,         0x8436, "Rx Tier 3 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_8_PRICE,         0x8437, "Rx Tier 3 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_9_PRICE,         0x8438, "Rx Tier 3 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_10_PRICE,        0x8439, "Rx Tier 3 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_11_PRICE,        0x843A, "Rx Tier 3 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_12_PRICE,        0x843B, "Rx Tier 3 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_13_PRICE,        0x843C, "Rx Tier 3 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_14_PRICE,        0x843D, "Rx Tier 3 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_15_PRICE,        0x843E, "Rx Tier 3 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_3_BLOCK_16_PRICE,        0x843F, "Rx Tier 3 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_1_PRICE,         0x8440, "Rx Tier 4 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_2_PRICE,         0x8441, "Rx Tier 4 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_3_PRICE,         0x8442, "Rx Tier 4 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_4_PRICE,         0x8443, "Rx Tier 4 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_5_PRICE,         0x8444, "Rx Tier 4 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_6_PRICE,         0x8445, "Rx Tier 4 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_7_PRICE,         0x8446, "Rx Tier 4 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_8_PRICE,         0x8447, "Rx Tier 4 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_9_PRICE,         0x8448, "Rx Tier 4 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_10_PRICE,        0x8449, "Rx Tier 4 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_11_PRICE,        0x844A, "Rx Tier 4 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_12_PRICE,        0x844B, "Rx Tier 4 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_13_PRICE,        0x844C, "Rx Tier 4 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_14_PRICE,        0x844D, "Rx Tier 4 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_15_PRICE,        0x844E, "Rx Tier 4 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_4_BLOCK_16_PRICE,        0x844F, "Rx Tier 4 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_1_PRICE,         0x8450, "Rx Tier 5 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_2_PRICE,         0x8451, "Rx Tier 5 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_3_PRICE,         0x8452, "Rx Tier 5 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_4_PRICE,         0x8453, "Rx Tier 5 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_5_PRICE,         0x8454, "Rx Tier 5 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_6_PRICE,         0x8455, "Rx Tier 5 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_7_PRICE,         0x8456, "Rx Tier 5 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_8_PRICE,         0x8457, "Rx Tier 5 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_9_PRICE,         0x8458, "Rx Tier 5 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_10_PRICE,        0x8459, "Rx Tier 5 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_11_PRICE,        0x845A, "Rx Tier 5 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_12_PRICE,        0x845B, "Rx Tier 5 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_13_PRICE,        0x845C, "Rx Tier 5 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_14_PRICE,        0x845D, "Rx Tier 5 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_15_PRICE,        0x845E, "Rx Tier 5 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_5_BLOCK_16_PRICE,        0x845F, "Rx Tier 5 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_1_PRICE,         0x8460, "Rx Tier 6 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_2_PRICE,         0x8461, "Rx Tier 6 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_3_PRICE,         0x8462, "Rx Tier 6 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_4_PRICE,         0x8463, "Rx Tier 6 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_5_PRICE,         0x8464, "Rx Tier 6 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_6_PRICE,         0x8465, "Rx Tier 6 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_7_PRICE,         0x8466, "Rx Tier 6 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_8_PRICE,         0x8467, "Rx Tier 6 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_9_PRICE,         0x8468, "Rx Tier 6 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_10_PRICE,        0x8469, "Rx Tier 6 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_11_PRICE,        0x846A, "Rx Tier 6 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_12_PRICE,        0x846B, "Rx Tier 6 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_13_PRICE,        0x846C, "Rx Tier 6 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_14_PRICE,        0x846D, "Rx Tier 6 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_15_PRICE,        0x846E, "Rx Tier 6 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_6_BLOCK_16_PRICE,        0x846F, "Rx Tier 6 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_1_PRICE,         0x8470, "Rx Tier 7 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_2_PRICE,         0x8471, "Rx Tier 7 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_3_PRICE,         0x8472, "Rx Tier 7 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_4_PRICE,         0x8473, "Rx Tier 7 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_5_PRICE,         0x8474, "Rx Tier 7 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_6_PRICE,         0x8475, "Rx Tier 7 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_7_PRICE,         0x8476, "Rx Tier 7 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_8_PRICE,         0x8477, "Rx Tier 7 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_9_PRICE,         0x8478, "Rx Tier 7 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_10_PRICE,        0x8479, "Rx Tier 7 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_11_PRICE,        0x847A, "Rx Tier 7 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_12_PRICE,        0x847B, "Rx Tier 7 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_13_PRICE,        0x847C, "Rx Tier 7 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_14_PRICE,        0x847D, "Rx Tier 7 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_15_PRICE,        0x847E, "Rx Tier 7 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_7_BLOCK_16_PRICE,        0x847F, "Rx Tier 7 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_1_PRICE,         0x8480, "Rx Tier 8 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_2_PRICE,         0x8481, "Rx Tier 8 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_3_PRICE,         0x8482, "Rx Tier 8 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_4_PRICE,         0x8483, "Rx Tier 8 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_5_PRICE,         0x8484, "Rx Tier 8 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_6_PRICE,         0x8485, "Rx Tier 8 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_7_PRICE,         0x8486, "Rx Tier 8 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_8_PRICE,         0x8487, "Rx Tier 8 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_9_PRICE,         0x8488, "Rx Tier 8 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_10_PRICE,        0x8489, "Rx Tier 8 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_11_PRICE,        0x848A, "Rx Tier 8 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_12_PRICE,        0x848B, "Rx Tier 8 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_13_PRICE,        0x848C, "Rx Tier 8 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_14_PRICE,        0x848D, "Rx Tier 8 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_15_PRICE,        0x848E, "Rx Tier 8 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_8_BLOCK_16_PRICE,        0x848F, "Rx Tier 8 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_1_PRICE,         0x8490, "Rx Tier 9 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_2_PRICE,         0x8491, "Rx Tier 9 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_3_PRICE,         0x8492, "Rx Tier 9 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_4_PRICE,         0x8493, "Rx Tier 9 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_5_PRICE,         0x8494, "Rx Tier 9 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_6_PRICE,         0x8495, "Rx Tier 9 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_7_PRICE,         0x8496, "Rx Tier 9 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_8_PRICE,         0x8497, "Rx Tier 9 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_9_PRICE,         0x8498, "Rx Tier 9 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_10_PRICE,        0x8499, "Rx Tier 9 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_11_PRICE,        0x849A, "Rx Tier 9 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_12_PRICE,        0x849B, "Rx Tier 9 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_13_PRICE,        0x849C, "Rx Tier 9 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_14_PRICE,        0x849D, "Rx Tier 9 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_15_PRICE,        0x849E, "Rx Tier 9 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_9_BLOCK_16_PRICE,        0x849F, "Rx Tier 9 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_1_PRICE,        0x84A0, "Rx Tier 10 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_2_PRICE,        0x84A1, "Rx Tier 10 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_3_PRICE,        0x84A2, "Rx Tier 10 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_4_PRICE,        0x84A3, "Rx Tier 10 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_5_PRICE,        0x84A4, "Rx Tier 10 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_6_PRICE,        0x84A5, "Rx Tier 10 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_7_PRICE,        0x84A6, "Rx Tier 10 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_8_PRICE,        0x84A7, "Rx Tier 10 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_9_PRICE,        0x84A8, "Rx Tier 10 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_10_PRICE,       0x84A9, "Rx Tier 10 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_11_PRICE,       0x84AA, "Rx Tier 10 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_12_PRICE,       0x84AB, "Rx Tier 10 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_13_PRICE,       0x84AC, "Rx Tier 10 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_14_PRICE,       0x84AD, "Rx Tier 10 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_15_PRICE,       0x84AE, "Rx Tier 10 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_10_BLOCK_16_PRICE,       0x84AF, "Rx Tier 10 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_1_PRICE,        0x84B0, "Rx Tier 11 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_2_PRICE,        0x84B1, "Rx Tier 11 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_3_PRICE,        0x84B2, "Rx Tier 11 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_4_PRICE,        0x84B3, "Rx Tier 11 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_5_PRICE,        0x84B4, "Rx Tier 11 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_6_PRICE,        0x84B5, "Rx Tier 11 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_7_PRICE,        0x84B6, "Rx Tier 11 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_8_PRICE,        0x84B7, "Rx Tier 11 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_9_PRICE,        0x84B8, "Rx Tier 11 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_10_PRICE,       0x84B9, "Rx Tier 11 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_11_PRICE,       0x84BA, "Rx Tier 11 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_12_PRICE,       0x84BB, "Rx Tier 11 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_13_PRICE,       0x84BC, "Rx Tier 11 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_14_PRICE,       0x84BD, "Rx Tier 11 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_15_PRICE,       0x84BE, "Rx Tier 11 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_11_BLOCK_16_PRICE,       0x84BF, "Rx Tier 11 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_1_PRICE,        0x84C0, "Rx Tier 12 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_2_PRICE,        0x84C1, "Rx Tier 12 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_3_PRICE,        0x84C2, "Rx Tier 12 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_4_PRICE,        0x84C3, "Rx Tier 12 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_5_PRICE,        0x84C4, "Rx Tier 12 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_6_PRICE,        0x84C5, "Rx Tier 12 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_7_PRICE,        0x84C6, "Rx Tier 12 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_8_PRICE,        0x84C7, "Rx Tier 12 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_9_PRICE,        0x84C8, "Rx Tier 12 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_10_PRICE,       0x84C9, "Rx Tier 12 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_11_PRICE,       0x84CA, "Rx Tier 12 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_12_PRICE,       0x84CB, "Rx Tier 12 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_13_PRICE,       0x84CC, "Rx Tier 12 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_14_PRICE,       0x84CD, "Rx Tier 12 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_15_PRICE,       0x84CE, "Rx Tier 12 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_12_BLOCK_16_PRICE,       0x84CF, "Rx Tier 12 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_1_PRICE,        0x84D0, "Rx Tier 13 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_2_PRICE,        0x84D1, "Rx Tier 13 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_3_PRICE,        0x84D2, "Rx Tier 13 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_4_PRICE,        0x84D3, "Rx Tier 13 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_5_PRICE,        0x84D4, "Rx Tier 13 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_6_PRICE,        0x84D5, "Rx Tier 13 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_7_PRICE,        0x84D6, "Rx Tier 13 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_8_PRICE,        0x84D7, "Rx Tier 13 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_9_PRICE,        0x84D8, "Rx Tier 13 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_10_PRICE,       0x84D9, "Rx Tier 13 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_11_PRICE,       0x84DA, "Rx Tier 13 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_12_PRICE,       0x84DB, "Rx Tier 13 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_13_PRICE,       0x84DC, "Rx Tier 13 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_14_PRICE,       0x84DD, "Rx Tier 13 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_15_PRICE,       0x84DE, "Rx Tier 13 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_13_BLOCK_16_PRICE,       0x84DF, "Rx Tier 13 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_1_PRICE,        0x84E0, "Rx Tier 14 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_2_PRICE,        0x84E1, "Rx Tier 14 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_3_PRICE,        0x84E2, "Rx Tier 14 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_4_PRICE,        0x84E3, "Rx Tier 14 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_5_PRICE,        0x84E4, "Rx Tier 14 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_6_PRICE,        0x84E5, "Rx Tier 14 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_7_PRICE,        0x84E6, "Rx Tier 14 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_8_PRICE,        0x84E7, "Rx Tier 14 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_9_PRICE,        0x84E8, "Rx Tier 14 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_10_PRICE,       0x84E9, "Rx Tier 14 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_11_PRICE,       0x84EA, "Rx Tier 14 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_12_PRICE,       0x84EB, "Rx Tier 14 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_13_PRICE,       0x84EC, "Rx Tier 14 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_14_PRICE,       0x84ED, "Rx Tier 14 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_15_PRICE,       0x84EE, "Rx Tier 14 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_14_BLOCK_16_PRICE,       0x84EF, "Rx Tier 14 Block 16 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_1_PRICE,        0x84F0, "Rx Tier 15 Block 1 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_2_PRICE,        0x84F1, "Rx Tier 15 Block 2 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_3_PRICE,        0x84F2, "Rx Tier 15 Block 3 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_4_PRICE,        0x84F3, "Rx Tier 15 Block 4 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_5_PRICE,        0x84F4, "Rx Tier 15 Block 5 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_6_PRICE,        0x84F5, "Rx Tier 15 Block 6 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_7_PRICE,        0x84F6, "Rx Tier 15 Block 7 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_8_PRICE,        0x84F7, "Rx Tier 15 Block 8 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_9_PRICE,        0x84F8, "Rx Tier 15 Block 9 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_10_PRICE,       0x84F9, "Rx Tier 15 Block 10 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_11_PRICE,       0x84FA, "Rx Tier 15 Block 11 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_12_PRICE,       0x84FB, "Rx Tier 15 Block 12 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_13_PRICE,       0x84FC, "Rx Tier 15 Block 13 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_14_PRICE,       0x84FD, "Rx Tier 15 Block 14 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_15_PRICE,       0x84FE, "Rx Tier 15 Block 15 Price" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_TIER_15_BLOCK_16_PRICE,       0x84FF, "Rx Tier 15 Block 16 Price" ) \
/* Received Extended Price Information Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_16,          0x850F, "Received Price Tier 16" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_17,          0x8510, "Received Price Tier 17" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_18,          0x8511, "Received Price Tier 18" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_19,          0x8512, "Received Price Tier 19" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_20,          0x8513, "Received Price Tier 20" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_21,          0x8514, "Received Price Tier 21" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_22,          0x8515, "Received Price Tier 22" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_23,          0x8516, "Received Price Tier 23" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_24,          0x8517, "Received Price Tier 24" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_25,          0x8518, "Received Price Tier 25" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_26,          0x8519, "Received Price Tier 26" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_27,          0x851A, "Received Price Tier 27" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_28,          0x851B, "Received Price Tier 28" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_29,          0x851C, "Received Price Tier 29" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_30,          0x851D, "Received Price Tier 30" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_31,          0x851E, "Received Price Tier 31" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_32,          0x851F, "Received Price Tier 32" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_33,          0x8520, "Received Price Tier 33" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_34,          0x8521, "Received Price Tier 34" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_35,          0x8522, "Received Price Tier 35" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_36,          0x8523, "Received Price Tier 36" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_37,          0x8524, "Received Price Tier 37" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_38,          0x8525, "Received Price Tier 38" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_39,          0x8526, "Received Price Tier 39" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_40,          0x8527, "Received Price Tier 40" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_41,          0x8528, "Received Price Tier 41" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_42,          0x8529, "Received Price Tier 42" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_43,          0x852A, "Received Price Tier 43" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_44,          0x852B, "Received Price Tier 44" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_45,          0x852C, "Received Price Tier 45" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_46,          0x852D, "Received Price Tier 46" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_47,          0x852E, "Received Price Tier 47" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_PRICE_TIER_48,          0x852F, "Received Price Tier 48" ) \
/* Received Tariff Information Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TARIFF_LABEL,           0x8610, "Received Tariff label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NUM_OF_PRICE_TIERS_IN_USE,    0x8611, "Received Number of Tariff Tiers in Use" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_NUM_OF_BLOCK_THRES_IN_USE,    0x8612, "Received Number of Block Thresholds in Use" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TIER_BLOCK_MODE,        0x8613, "Received Tier Block Mode" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_TARIFF_RES_PERIOD,      0x8615, "Received tariff Resolution Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_CO2,                    0x8625, "Received CO2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_CO2_UNIT,               0x8626, "Received CO2 Unit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RECEIVED_CO2_TRAILING_DIGIT,     0x8627, "Received CO2 Trailing Digit" ) \
/* Received Billing Information Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_CURRENT_BILLING_PERIOD_START, 0x8700, "Received Current Billing Period Start" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_CURRENT_BILLING_PERIOD_DUR,   0x8701, "Received Current Billing Period Duration" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_LAST_BILLING_PERIOD_START,    0x8702, "Received Last Billing Period Start" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_RX_LAST_BILLING_PERIOD_CON_BILL, 0x8704, "Received Last Billing Period Consolidated Bill" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_PRICE,           0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_price_attr_server_names);
VALUE_STRING_ARRAY(zbee_zcl_price_attr_server_names);
static value_string_ext zbee_zcl_price_attr_server_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_price_attr_server_names);

#define zbee_zcl_price_attr_client_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CLNT_PRICE_INC_RND_MINUTES,      0x0000, "Price Increase Randomize Minutes" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CLNT_PRICE_DEC_RND_MINUTES,      0x0001, "Price Decrease Randomize Minutes" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PRICE_CLNT_COMMODITY_TYPE,             0x0002, "Commodity Type" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_PRICE_CLNT,      0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_price_attr_client_names);
VALUE_STRING_ARRAY(zbee_zcl_price_attr_client_names);

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
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_BILLING_PERIOD,           0x09, "Publish Billing Period" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CONSOLIDATED_BILL,        0x0A, "Publish Consolidated Bill" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CPP_EVENT,                0x0B, "Publish CPP Event" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CREDIT_PAYMENT,           0x0C, "Publish Credit Payment" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CURRENCY_CONVERSION,      0x0D, "Publish Currency Conversion" ) \
    XXX(ZBEE_ZCL_CMD_ID_PRICE_CANCEL_TARIFF,                    0x0E, "Cancel Tariff" )

VALUE_STRING_ENUM(zbee_zcl_price_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_price_srv_tx_cmd_names);

/* Block Period Control Field BitMap - Price Acknowledgement */
#define zbee_zcl_price_block_period_control_price_acknowledgement_names_VALUE_STRING_LIST(XXX)  \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_CONTROL_PRICE_ACKNOLEDGEMENT_NOT_REQUIRED,  0x0, "Price Acknowledgement not required" ) \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_CONTROL_PRICE_ACKNOLEDGEMENT_REQUIRED,      0x1, "Price Acknowledgement required" )

VALUE_STRING_ARRAY(zbee_zcl_price_block_period_control_price_acknowledgement_names);

/* Block Period Control Field BitMap - Repeating Block */
#define zbee_zcl_price_block_period_control_repeating_block_names_VALUE_STRING_LIST(XXX)  \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_CONTROL_REPEATING_BLOCK_NON_REPEATING,      0x0, "Non Repeating Block" ) \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_CONTROL_REPEATING_BLOCK_REPEATING,          0x1, "Repeating Block" )

VALUE_STRING_ARRAY(zbee_zcl_price_block_period_control_repeating_block_names);

/* Block Period DurationTimebase Enumeration */
#define zbee_zcl_price_block_period_duration_timebase_names_VALUE_STRING_LIST(XXX)  \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_TIMEBASE_MINUTE,                   0x0, "Minutes" ) \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_TIMEBASE_DAY,                      0x1, "Days" ) \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_TIMEBASE_WEEK,                     0x2, "Weeks" ) \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_TIMEBASE_MONTH,                    0x3, "Months" )

VALUE_STRING_ARRAY(zbee_zcl_price_block_period_duration_timebase_names);

/* Block Period Duration Control Enumeration */
#define zbee_zcl_price_block_period_duration_control_names_VALUE_STRING_LIST(XXX)  \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_CONTROL_START_OF_TIMEBASE,         0x0, "Start of Timebase" ) \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_CONTROL_END_OF_TIMEBASE,           0x1, "End of Timebase" ) \
    XXX(ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_CONTROL_NOT_SPECIFIED,             0x2, "Not Specified" )

VALUE_STRING_ARRAY(zbee_zcl_price_block_period_duration_control_names);

/* Tariff Type Enumeration */
#define zbee_zcl_price_tariff_type_names_VALUE_STRING_LIST(XXX)  \
    XXX(ZBEE_ZCL_PRICE_TARIFF_TYPE_DELIVERED_TARIFF,                            0x0, "Delivered Tariff" ) \
    XXX(ZBEE_ZCL_PRICE_TARIFF_TYPE_RECEIVED_TARIFF,                             0x1, "Received Tariff" ) \
    XXX(ZBEE_ZCL_PRICE_TARIFF_TYPE_DELIVERED_AND_RECEIVED_TARIFF,               0x2, "delivered and Received Tariff" )

VALUE_STRING_ARRAY(zbee_zcl_price_tariff_type_names);

/* Tariff Resolution Period Enumeration */
#define zbee_zcl_price_tariff_resolution_period_names_VALUE_STRING_LIST(XXX)  \
   XXX(ZBEE_ZCL_PRICE_TARIFF_RESOLUTION_PERIOD_NOT_DEFINED,                     0x00, "Not Defined" ) \
   XXX(ZBEE_ZCL_PRICE_TARIFF_RESOLUTION_PERIOD_BLOCK_PERIOD,                    0x01, "Block Period" ) \
   XXX(ZBEE_ZCL_PRICE_TARIFF_RESOLUTION_PERIOD_1_DAY,                           0x02, "1 Day" )

VALUE_STRING_ARRAY(zbee_zcl_price_tariff_resolution_period_names);

/* Tariff Charging Scheme Enumeration */
#define zbee_zcl_price_tariff_charging_scheme_names_VALUE_STRING_LIST(XXX)  \
    XXX(ZBEE_ZCL_PRICE_TARIFF_CHARGING_SCHEME_TOU_TARIFF,                       0x0, "TOU Tariff" ) \
    XXX(ZBEE_ZCL_PRICE_TARIFF_CHARGING_SCHEME_BLOCK_TARIFF,                     0x1, "Block Tariff" ) \
    XXX(ZBEE_ZCL_PRICE_TARIFF_CHARGING_SCHEME_BLOCK_TOU_WITH_COMMON_THRES,      0x2, "Block/TOU Tariff with common thresholds" ) \
    XXX(ZBEE_ZCL_PRICE_TARIFF_CHARGING_SCHEME_BLOCK_TOU_WITH_INDIV_TRHES,       0x3, "Block/TOU Tariff with individual thresholds per tier" )

VALUE_STRING_ARRAY(zbee_zcl_price_tariff_charging_scheme_names);

/* Tariff Type */
#define ZBEE_ZCL_PRICE_TARIFF_TYPE 0x0F

/* Trailing Digit and Price Tier */
#define ZBEE_ZCL_PRICE_TIER           0x0F
#define ZBEE_ZCL_PRICE_TRAILING_DIGIT 0xF0

/* Number of Price Tiers and Register Tier */
#define ZBEE_ZCL_PRICE_REGISTER_TIER           0x0F
#define ZBEE_ZCL_PRICE_NUMBER_OF_PRICE_TIERS   0xF0

/* Alternate Cost Trailing Digit */
#define ZBEE_ZCL_PRICE_ALTERNATE_COST_TRAILING_DIGIT      0xF0

/* Block Period Duration Type */
#define ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_TIMEBASE  0x0F
#define ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_CONTROL   0xF0

/* Block Period Control Field BitMap */
#define ZBEE_ZCL_PRICE_BLOCK_PERIOD_CONTROL_PRICE_ACKNOWLEDGEMENT   0x01
#define ZBEE_ZCL_PRICE_BLOCK_PERIOD_CONTROL_REPEATING_BLOCK         0x02

/* Conversion Factor Trailing Digit */
#define ZBEE_ZCL_PRICE_CONVERSION_FACTOR_TRAILING_DIGIT      0xF0

/* Calorific Value Trailing Digit */
#define ZBEE_ZCL_PRICE_CALORIFIC_VALUE_TRAILING_DIGIT      0xF0

/* Tariff Type / Charging Scheme */
#define ZBEE_ZCL_PRICE_TARIFF_INFORMATION_TYPE            0x0F
#define ZBEE_ZCL_PRICE_TARIFF_INFORMATION_CHARGING_SCHEME 0xF0

/* Tariff Information Price Trailing Digit */
#define ZBEE_ZCL_PRICE_TARIFF_INFORMATION_PRICE_TRAILING_DIGIT      0xF0

/* Price Matrix Tier/Block ID */
#define ZBEE_ZCL_PRICE_PRICE_MATRIX_TIER_BLOCK_ID_BLOCK     0x0F
#define ZBEE_ZCL_PRICE_PRICE_MATRIX_TIER_BLOCK_ID_TIER      0xF0

/* Block Thresholds Tier/Number of Block Thresholds */
#define ZBEE_ZCL_PRICE_BLOCK_THRESHOLDS_NUMBER_OF_BLOCK_THRESHOLDS     0x0F
#define ZBEE_ZCL_PRICE_BLOCK_THRESHOLDS_TIER                           0xF0

/* CO2 Value Trailing Digit */
#define ZBEE_ZCL_PRICE_CO2_VALUE_TRAILING_DIGIT      0xF0

/* Billing Period Duration Type */
#define ZBEE_ZCL_PRICE_BILLING_PERIOD_DURATION_TIMEBASE     0x0F
#define ZBEE_ZCL_PRICE_BILLING_PERIOD_DURATION_CONTROL      0xF0

/* Billign Period Tariff Type */
#define ZBEE_ZCL_PRICE_BILLING_PERIOD_TARIFF_TYPE 0x0F

/* Consolidated Bill Trailing Digit */
#define ZBEE_ZCL_PRICE_CONSOLIDATED_BILL_TRAILING_DIGIT      0xF0

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_price(void);
void proto_reg_handoff_zbee_zcl_price(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_price_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

/* Command Dissector Helpers */
static void dissect_zcl_price_get_current_price              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_scheduled_prices           (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_price_acknowledgement      (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_block_period               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_conversion_factor          (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_calorific_value            (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_tariff_information         (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_price_matrix               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_block_thresholds           (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_co2_value                  (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_tier_labels                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_billing_period             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_consolidated_bill          (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_cpp_event                  (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_get_credit_payment             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_price                  (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_block_period           (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_conversion_factor      (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_calorific_value        (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_tariff_information     (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_price_matrix           (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_block_thresholds       (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_co2_value              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_tier_labels            (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_billing_period         (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_consolidated_bill      (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_cpp_event              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_credit_payment         (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_currency_conversion    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_price_publish_cancel_tariff          (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_price = -1;

static int hf_zbee_zcl_price_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_price_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_price_attr_server_id = -1;
static int hf_zbee_zcl_price_attr_client_id = -1;
static int hf_zbee_zcl_price_attr_reporting_status = -1;
static int hf_zbee_zcl_price_provider_id = -1;
static int hf_zbee_zcl_price_issuer_event_id = -1;
static int hf_zbee_zcl_price_min_issuer_event_id = -1;
static int hf_zbee_zcl_price_issuer_tariff_id = -1;
static int hf_zbee_zcl_price_command_index = -1;
static int hf_zbee_zcl_price_total_number_of_commands = -1;
static int hf_zbee_zcl_price_number_of_commands = -1;
static int hf_zbee_zcl_price_number_of_events = -1;
static int hf_zbee_zcl_price_number_of_records = -1;
static int hf_zbee_zcl_price_number_of_block_thresholds = -1;
static int hf_zbee_zcl_price_number_of_generation_tiers = -1;
static int hf_zbee_zcl_price_extended_number_of_price_tiers = -1;
static int hf_zbee_zcl_price_command_options = -1;
static int hf_zbee_zcl_price_control = -1;
static int hf_zbee_zcl_price_tier = -1;
static int hf_zbee_zcl_price_tariff_type_mask = -1;
static int hf_zbee_zcl_price_tariff_type = -1;
static int hf_zbee_zcl_price_tariff_resolution_period = -1;
static int hf_zbee_zcl_price_cpp_auth = -1;
static int hf_zbee_zcl_price_cpp_price_tier= -1;
static int hf_zbee_zcl_price_rate_label = -1;
static int hf_zbee_zcl_price_unit_of_measure = -1;
static int hf_zbee_zcl_price_currency = -1;
static int hf_zbee_zcl_price_trailing_digit_and_price_tier = -1;
static int hf_zbee_zcl_price_trailing_digit = -1;
static int hf_zbee_zcl_price_extended_price_tier = -1;
static int hf_zbee_zcl_price_number_of_price_tiers_and_register_tier = -1;
static int hf_zbee_zcl_price_register_tier = -1;
static int hf_zbee_zcl_price_number_of_price_tiers = -1;
static int hf_zbee_zcl_price_extended_register_tier = -1;
static int hf_zbee_zcl_price_duration_in_minutes = -1;
static int hf_zbee_zcl_price = -1;
static int hf_zbee_zcl_price_ratio = -1;
static int hf_zbee_zcl_price_generation_price = -1;
static int hf_zbee_zcl_price_generation_price_ratio = -1;
static int hf_zbee_zcl_price_generation_tier = -1;
static int hf_zbee_zcl_price_alternate_cost_delivered = -1;
static int hf_zbee_zcl_price_alternate_cost_unit = -1;
static int hf_zbee_zcl_price_alternate_cost_trailing_digit_mask = -1;
static int hf_zbee_zcl_price_alternate_cost_trailing_digit = -1;
static int hf_zbee_zcl_price_start_time = -1;
static int hf_zbee_zcl_price_earliest_start_time = -1;
static int hf_zbee_zcl_price_latest_end_time = -1;
static int hf_zbee_zcl_price_current_time = -1;
static int hf_zbee_zcl_price_price_ack_time = -1;
static int hf_zbee_zcl_price_block_period_start_time = -1;
static int hf_zbee_zcl_price_block_period_duration = -1;
static int hf_zbee_zcl_price_block_period_duration_type = -1;
static int hf_zbee_zcl_price_block_period_duration_timebase = -1;
static int hf_zbee_zcl_price_block_period_duration_control = -1;
static int hf_zbee_zcl_price_block_period_control = -1;
static int hf_zbee_zcl_price_block_period_control_price_acknowledgement = -1;
static int hf_zbee_zcl_price_block_period_control_repeating_block = -1;
static int hf_zbee_zcl_price_conversion_factor = -1;
static int hf_zbee_zcl_price_conversion_factor_trailing_digit_mask = -1;
static int hf_zbee_zcl_price_conversion_factor_trailing_digit = -1;
static int hf_zbee_zcl_price_calorific_value = -1;
static int hf_zbee_zcl_price_calorific_value_unit = -1;
static int hf_zbee_zcl_price_calorific_value_trailing_digit_mask = -1;
static int hf_zbee_zcl_price_calorific_value_trailing_digit = -1;
static int hf_zbee_zcl_price_tariff_information_type_and_charging_scheme = -1;
static int hf_zbee_zcl_price_tariff_information_type = -1;
static int hf_zbee_zcl_price_tariff_information_charging_scheme = -1;
static int hf_zbee_zcl_price_tariff_information_tariff_label = -1;
static int hf_zbee_zcl_price_tariff_information_number_of_price_tiers_in_use = -1;
static int hf_zbee_zcl_price_tariff_information_number_of_block_thresholds_in_use = -1;
static int hf_zbee_zcl_price_tariff_information_price_trailing_digit_mask = -1;
static int hf_zbee_zcl_price_tariff_information_price_trailing_digit = -1;
static int hf_zbee_zcl_price_tariff_information_standing_charge = -1;
static int hf_zbee_zcl_price_tariff_information_tier_block_mode = -1;
static int hf_zbee_zcl_price_tariff_information_block_threshold_multiplier = -1;
static int hf_zbee_zcl_price_tariff_information_block_threshold_divisor = -1;
static int hf_zbee_zcl_price_price_matrix_sub_payload_control = -1;
static int hf_zbee_zcl_price_price_matrix_tier_block_id = -1;
static int hf_zbee_zcl_price_price_matrix_tier_block_id_block = -1;
static int hf_zbee_zcl_price_price_matrix_tier_block_id_tier = -1;
static int hf_zbee_zcl_price_price_matrix_tier_block_id_tou_tier = -1;
static int hf_zbee_zcl_price_price_matrix_price = -1;
static int hf_zbee_zcl_price_block_thresholds_sub_payload_control = -1;
static int hf_zbee_zcl_price_block_thresholds_tier_number_of_block_thresholds = -1;
static int hf_zbee_zcl_price_block_thresholds_tier = -1;
static int hf_zbee_zcl_price_block_thresholds_number_of_block_thresholds = -1;
static int hf_zbee_zcl_price_block_thresholds_block_threshold = -1;
static int hf_zbee_zcl_price_co2_value = -1;
static int hf_zbee_zcl_price_co2_unit = -1;
static int hf_zbee_zcl_price_co2_value_trailing_digit_mask = -1;
static int hf_zbee_zcl_price_co2_value_trailing_digit = -1;
static int hf_zbee_zcl_price_tier_labels_number_of_labels = -1;
static int hf_zbee_zcl_price_tier_labels_tier_id = -1;
static int hf_zbee_zcl_price_tier_labels_tier_label = -1;
static int hf_zbee_zcl_price_billing_period_start_time = -1;
static int hf_zbee_zcl_price_billing_period_duration = -1;
static int hf_zbee_zcl_price_billing_period_duration_type = -1;
static int hf_zbee_zcl_price_billing_period_duration_timebase = -1;
static int hf_zbee_zcl_price_billing_period_duration_control = -1;
static int hf_zbee_zcl_price_consolidated_bill = -1;
static int hf_zbee_zcl_price_consolidated_bill_trailing_digit_mask = -1;
static int hf_zbee_zcl_price_consolidated_bill_trailing_digit = -1;
static int hf_zbee_zcl_price_credit_payment_due_date = -1;
static int hf_zbee_zcl_price_credit_payment_overdue_amount = -1;
static int hf_zbee_zcl_price_credit_payment_status = -1;
static int hf_zbee_zcl_price_credit_payment = -1;
static int hf_zbee_zcl_price_credit_payment_date = -1;
static int hf_zbee_zcl_price_credit_payment_ref = -1;
static int hf_zbee_zcl_price_old_currency = -1;
static int hf_zbee_zcl_price_new_currency = -1;
static int hf_zbee_zcl_price_currency_change_control_flags = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_price = -1;
static gint ett_zbee_zcl_price_tariff_type = -1;
static gint ett_zbee_zcl_price_trailing_digit_and_price_tier = -1;
static gint ett_zbee_zcl_price_number_of_price_tiers_and_register_tier = -1;
static gint ett_zbee_zcl_price_alternate_cost_trailing_digit = -1;
static gint ett_zbee_zcl_price_block_period_control = -1;
static gint ett_zbee_zcl_price_block_period_duration_type = -1;
static gint ett_zbee_zcl_price_conversion_factor_trailing_digit = -1;
static gint ett_zbee_zcl_price_calorific_value_trailing_digit = -1;
static gint ett_zbee_zcl_price_tariff_information_tariff_type_and_charging_scheme = -1;
static gint ett_zbee_zcl_price_tariff_information_price_trailing_digit = -1;
static gint ett_zbee_zcl_price_price_matrix_tier_block_id = -1;
static gint ett_zbee_zcl_price_block_thresholds_tier_number_of_block_thresholds = -1;
static gint ett_zbee_zcl_price_co2_value_trailing_digit = -1;
static gint ett_zbee_zcl_price_billing_period_duration_type = -1;
static gint ett_zbee_zcl_price_consolidated_bill_trailing_digit = -1;

static int * const zbee_zcl_price_billing_period_duration_type[] = {
    &hf_zbee_zcl_price_billing_period_duration_timebase,
    &hf_zbee_zcl_price_billing_period_duration_control,
    NULL
};

static int * const zbee_zcl_price_block_period_duration_type[] = {
    &hf_zbee_zcl_price_block_period_duration_timebase,
    &hf_zbee_zcl_price_block_period_duration_control,
    NULL
};

static int * const zbee_zcl_price_block_period_control[] = {
    &hf_zbee_zcl_price_block_period_control_price_acknowledgement,
    &hf_zbee_zcl_price_block_period_control_repeating_block,
    NULL
};

static int * const zbee_zcl_price_tariff_type_mask[] = {
    &hf_zbee_zcl_price_tariff_type,
    NULL
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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_price_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_PRICE:
            proto_tree_add_item(tree, hf_zbee_zcl_price_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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
            val_to_str_const(cmd_id, zbee_zcl_price_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_price_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_price, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CURRENT_PRICE:
                    dissect_zcl_price_get_current_price(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_SCHEDULED_PRICES:
                    dissect_zcl_price_get_scheduled_prices(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_PRICE_ACKNOWLEDGEMENT:
                    dissect_zcl_price_get_price_acknowledgement(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_BLOCK_PERIOD:
                    dissect_zcl_price_get_block_period(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CONVERSION_FACTOR:
                    dissect_zcl_price_get_conversion_factor(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CALORIFIC_VALUE:
                    dissect_zcl_price_get_calorific_value(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_TARIFF_INFORMATION:
                    dissect_zcl_price_get_tariff_information(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_PRICE_MATRIX:
                    dissect_zcl_price_get_price_matrix(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_BLOCK_THRESHOLDS:
                    dissect_zcl_price_get_block_thresholds(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CO2_VALUE:
                    dissect_zcl_price_get_co2_value(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_TIER_LABELS:
                    dissect_zcl_price_get_tier_labels(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_BILLING_PERIOD:
                    dissect_zcl_price_get_billing_period(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CONSOLIDATED_BILL:
                    dissect_zcl_price_get_consolidated_bill(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_CPP_EVENT_RESPONSE:
                    dissect_zcl_price_get_cpp_event(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CREDIT_PAYMENT:
                    dissect_zcl_price_get_credit_payment(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_CURRENCY_CONVERSION:
                    /* No Payload */
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_GET_TARIFF_CANCELLATION:
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
            val_to_str_const(cmd_id, zbee_zcl_price_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_price_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_price, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_PRICE:
                    dissect_zcl_price_publish_price(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_BLOCK_PERIOD:
                    dissect_zcl_price_publish_block_period(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CONVERSION_FACTOR:
                    dissect_zcl_price_publish_conversion_factor(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CALORIFIC_VALUE:
                    dissect_zcl_price_publish_calorific_value(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_TARIFF_INFORMATION:
                    dissect_zcl_price_publish_tariff_information(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_PRICE_MATRIX:
                    dissect_zcl_price_publish_price_matrix(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_BLOCK_THRESHOLDS:
                    dissect_zcl_price_publish_block_thresholds(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CO2_VALUE:
                    dissect_zcl_price_publish_co2_value(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_TIER_LABELS:
                    dissect_zcl_price_publish_tier_labels(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_BILLING_PERIOD:
                    dissect_zcl_price_publish_billing_period(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CONSOLIDATED_BILL:
                    dissect_zcl_price_publish_consolidated_bill(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CPP_EVENT:
                    dissect_zcl_price_publish_cpp_event(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CREDIT_PAYMENT:
                    dissect_zcl_price_publish_credit_payment(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_PUBLISH_CURRENCY_CONVERSION:
                    dissect_zcl_price_publish_currency_conversion(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_PRICE_CANCEL_TARIFF:
                    dissect_zcl_price_publish_cancel_tariff(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_price*/

/**
 *This function manages the Get Current Price payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_current_price(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Command Options */
    proto_tree_add_item(tree, hf_zbee_zcl_price_command_options, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_price_get_current_price*/

/**
 *This function manages the Get Scheduled Prices payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_scheduled_prices(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Number of Events */
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_events, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_price_get_scheduled_prices*/

/**
 *This function manages the Get Price Acknowledgement payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_price_acknowledgement(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t price_ack_time;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Price Ack Time */
    price_ack_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    price_ack_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_price_ack_time, tvb, *offset, 4, &price_ack_time);
    *offset += 4;

    /* Price Control */
    proto_tree_add_item(tree, hf_zbee_zcl_price_control, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_price_get_price_acknowledgement*/

/**
 *This function manages the Get Block Period payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_block_period(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Number of Events */
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_events, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Tariff Type */
    if (tvb_reported_length_remaining(tvb, *offset) > 0) {
        proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_type, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }
} /*dissect_zcl_price_get_block_period*/

/**
 *This function manages the Get Conversion Factor payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_conversion_factor(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t earliest_start_time;

    /* Earliest Start Time */
    earliest_start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    earliest_start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_earliest_start_time, tvb, *offset, 4, &earliest_start_time);
    *offset += 4;

    /* Min Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_min_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_price_get_conversion_factor*/

/**
 *This function manages the Get Calorific Value payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_calorific_value(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t earliest_start_time;

    /* Earliest Start Time */
    earliest_start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    earliest_start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_earliest_start_time, tvb, *offset, 4, &earliest_start_time);
    *offset += 4;

    /* Min Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_min_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_price_get_calorific_value*/

/**
 *This function manages the Get Tariff Information payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_tariff_information(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t earliest_start_time;

    /* Earliest Start Time */
    earliest_start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    earliest_start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_earliest_start_time, tvb, *offset, 4, &earliest_start_time);
    *offset += 4;

    /* Min Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_min_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Tariff Type */
    proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

} /*dissect_zcl_price_get_tariff_information*/

/**
 *This function manages the Get Price Matrix payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_price_matrix(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Tariff ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_tariff_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_price_get_price_matrix*/

/**
 *This function manages the Get Block Thresholds payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_block_thresholds(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Tariff ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_tariff_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_price_get_block_thresholds*/

/**
 *This function manages the Get CO2 Value payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_co2_value(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t earliest_start_time;

    /* Earliest Start Time */
    earliest_start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    earliest_start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_earliest_start_time, tvb, *offset, 4, &earliest_start_time);
    *offset += 4;

    /* Min Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_min_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Tariff Type */
    if (tvb_reported_length_remaining(tvb, *offset) > 0) {
        proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_type, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }
} /*dissect_zcl_price_get_co2_value*/

/**
 *This function manages the Get Tier Labels payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_tier_labels(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Tariff ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_tariff_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_price_get_tier_labels*/

/**
 *This function manages the Get Billing Period payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_billing_period(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t earliest_start_time;

    /* Earliest Start Time */
    earliest_start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    earliest_start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_earliest_start_time, tvb, *offset, 4, &earliest_start_time);
    *offset += 4;

    /* Min Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_min_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Tariff Type */
    if (tvb_reported_length_remaining(tvb, *offset) > 0) {
        proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_type, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }

} /*dissect_zcl_price_get_billing_period*/

/**
 *This function manages the Get Consolidated Bill payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_consolidated_bill(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t earliest_start_time;

    /* Earliest Start Time */
    earliest_start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    earliest_start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_earliest_start_time, tvb, *offset, 4, &earliest_start_time);
    *offset += 4;

    /* Min Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_min_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Tariff Type */
    if (tvb_reported_length_remaining(tvb, *offset) > 0) {
        proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_type, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }

} /*dissect_zcl_price_get_consolidated_bill*/

/**
 *This function manages the Get CPP Event Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_cpp_event(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* CPP Auth */
    proto_tree_add_item(tree, hf_zbee_zcl_price_cpp_auth, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_price_get_event_response*/

/**
 *This function manages the Get Credit Payment payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_get_credit_payment(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t latest_end_time;

    /* Latest End Time */
    latest_end_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    latest_end_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_latest_end_time, tvb, *offset, 4, &latest_end_time);
    *offset += 4;

    /* Number of Records */
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_records, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_price_get_credit_payment*/

/**
 *This function manages the Publish Price payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_price(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;
    nstime_t current_time;
    int length;

    static int * const trailing_digit[] = {
        &hf_zbee_zcl_price_tier,
        &hf_zbee_zcl_price_trailing_digit,
        NULL
    };

    static int * const number_of_price_tiers_and_register_tier[] = {
        &hf_zbee_zcl_price_register_tier,
        &hf_zbee_zcl_price_number_of_price_tiers,
        NULL
    };

    static int * const alternate_cost_trailing_digit[] = {
        &hf_zbee_zcl_price_alternate_cost_trailing_digit,
        NULL
    };

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Rate Label */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_price_rate_label, tvb, *offset, 1, ENC_NA | ENC_ZIGBEE, &length);
    *offset += length;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Current Time */
    current_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    current_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_current_time, tvb, *offset, 4, &current_time);
    *offset += 4;

    /* Unit of Measure */
    proto_tree_add_item(tree, hf_zbee_zcl_price_unit_of_measure, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Currency */
    proto_tree_add_item(tree, hf_zbee_zcl_price_currency, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Price Trailing Digit and Price Tier */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_trailing_digit_and_price_tier, ett_zbee_zcl_price_trailing_digit_and_price_tier, trailing_digit, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Number of Price Tiers and Register Tier */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_number_of_price_tiers_and_register_tier, ett_zbee_zcl_price_number_of_price_tiers_and_register_tier, number_of_price_tiers_and_register_tier, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Duration in Minutes */
    proto_tree_add_item(tree, hf_zbee_zcl_price_duration_in_minutes, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Price */
    proto_tree_add_item(tree, hf_zbee_zcl_price, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* (Optional) Price Ratio */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_ratio, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Generation Price */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_generation_price, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* (Optional) Generation Price Ratio */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_generation_price_ratio, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Alternate Cost Delivered */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_alternate_cost_delivered, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* (Optional) Alternate Cost Unit */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_alternate_cost_unit, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Alternate Cost Trailing Digit */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_alternate_cost_trailing_digit_mask, ett_zbee_zcl_price_alternate_cost_trailing_digit, alternate_cost_trailing_digit, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* (Optional) Number of Block Thresholds */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_block_thresholds, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Price Control */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_control, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Number of Generation Tiers */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_number_of_generation_tiers, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Generation Tier */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_generation_tier, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Extended Number of Price Tiers */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_extended_number_of_price_tiers, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Extended Price Tier */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_extended_price_tier, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* (Optional) Extended Register Tier */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item(tree, hf_zbee_zcl_price_extended_register_tier, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_price_publish_price*/

/**
 *This function manages the Publish Block Period payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_block_period(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t block_period_start_time;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Block Period Start Time */
    block_period_start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    block_period_start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_block_period_start_time, tvb, *offset, 4, &block_period_start_time);
    *offset += 4;

    /* Block Period Duration */
    proto_tree_add_item(tree, hf_zbee_zcl_price_block_period_duration, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
    *offset += 3;

    /* Block Period Control */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_block_period_control, ett_zbee_zcl_price_block_period_control, zbee_zcl_price_block_period_control, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Block Period Duration Type */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_block_period_duration_type, ett_zbee_zcl_price_block_period_duration_type, zbee_zcl_price_block_period_duration_type, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Tariff Type */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_tariff_type_mask, ett_zbee_zcl_price_tariff_type, zbee_zcl_price_tariff_type_mask, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Tariff Resolution Period */
    proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_resolution_period, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_price_publish_block_period*/

/**
 *This function manages the Publish Conversion Factor payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_conversion_factor(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    static int * const conversion_factor_trailing_digit[] = {
        &hf_zbee_zcl_price_conversion_factor_trailing_digit,
        NULL
    };

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Conversion Factor */
    proto_tree_add_item(tree, hf_zbee_zcl_price_conversion_factor, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Conversion Factor Trailing digit */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_conversion_factor_trailing_digit_mask, ett_zbee_zcl_price_conversion_factor_trailing_digit, conversion_factor_trailing_digit, ENC_LITTLE_ENDIAN);
    *offset += 1;
} /*dissect_zcl_price_publish_conversion_factor*/

/**
 *This function manages the Publish Calorific Value payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_calorific_value(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    static int * const calorific_value_trailing_digit[] = {
        &hf_zbee_zcl_price_calorific_value_trailing_digit,
        NULL
    };

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Calorific Value */
    proto_tree_add_item(tree, hf_zbee_zcl_price_calorific_value, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Calorific Value Unit */
    proto_tree_add_item(tree, hf_zbee_zcl_price_calorific_value_unit, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Calorific Value Trailing digit */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_calorific_value_trailing_digit_mask, ett_zbee_zcl_price_calorific_value_trailing_digit, calorific_value_trailing_digit, ENC_LITTLE_ENDIAN);
    *offset += 1;
} /*dissect_zcl_price_publish_calorific_value*/

/**
 *This function manages the Publish Tariff Information payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_tariff_information(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    int length;
    nstime_t start_time;

    static int * const price_trailing_digit[] = {
        &hf_zbee_zcl_price_tariff_information_price_trailing_digit,
        NULL
    };

    static int * const type_and_charging_scheme[] = {
        &hf_zbee_zcl_price_tariff_information_type,
        &hf_zbee_zcl_price_tariff_information_charging_scheme,
        NULL
    };

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Tariff ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_tariff_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Tariff Type / Charging Scheme */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_tariff_information_type_and_charging_scheme, ett_zbee_zcl_price_tariff_information_tariff_type_and_charging_scheme, type_and_charging_scheme, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Tariff Label */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_price_tariff_information_tariff_label, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &length);
    *offset += length;

    /* Number of Price Tiers in Use */
    proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_information_number_of_price_tiers_in_use, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Number of Block Thresholds in Use */
    proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_information_number_of_block_thresholds_in_use, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Unit of Measure */
    proto_tree_add_item(tree, hf_zbee_zcl_price_unit_of_measure, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Currency */
    proto_tree_add_item(tree, hf_zbee_zcl_price_currency, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Price Trailing Digit */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_tariff_information_price_trailing_digit_mask, ett_zbee_zcl_price_tariff_information_price_trailing_digit, price_trailing_digit, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Standing Charge */
    proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_information_standing_charge, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Tier Block Mode */
    proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_information_tier_block_mode, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Block Threshold Multiplier */
    proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_information_block_threshold_multiplier, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
    *offset += 3;

    /* Block Threshold Divisor */
    proto_tree_add_item(tree, hf_zbee_zcl_price_tariff_information_block_threshold_divisor, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
    *offset += 3;
} /*dissect_zcl_price_publish_tariff_information*/

/**
 *This function manages the Publish Price Matrix payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_price_matrix(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8 sub_payload_control;
    nstime_t start_time;

    static int * const tier_block_id[] = {
        &hf_zbee_zcl_price_price_matrix_tier_block_id_block,
        &hf_zbee_zcl_price_price_matrix_tier_block_id_tier,
        NULL
    };

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Issuer Tariff ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_tariff_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_price_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_price_total_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Sub-Payload Control */
    sub_payload_control = tvb_get_guint8(tvb, *offset) && 0x01; /* First bit determines Tier/Block ID field type */
    proto_tree_add_item(tree, hf_zbee_zcl_price_price_matrix_sub_payload_control, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    while (tvb_reported_length_remaining(tvb, *offset) > 0) {
        /* Tier/Block ID */
        if (sub_payload_control == 0)
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_price_matrix_tier_block_id, ett_zbee_zcl_price_price_matrix_tier_block_id, tier_block_id, ENC_LITTLE_ENDIAN);
        else
            proto_tree_add_item(tree, hf_zbee_zcl_price_price_matrix_tier_block_id_tou_tier, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Price */
        proto_tree_add_item(tree, hf_zbee_zcl_price_price_matrix_price, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }
} /*dissect_zcl_price_publish_price_matrix*/

/**
 *This function manages the Publish Block Thresholds payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_block_thresholds(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8 sub_payload_control;
    nstime_t start_time;

    static int * const tier_number_of_block_thresholds[] = {
        &hf_zbee_zcl_price_block_thresholds_number_of_block_thresholds,
        &hf_zbee_zcl_price_block_thresholds_tier,
        NULL
    };

    static int * const number_of_block_thresholds[] = {
        &hf_zbee_zcl_price_block_thresholds_number_of_block_thresholds,
        NULL
    };

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Issuer Tariff ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_tariff_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_price_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_price_total_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Sub-Payload Control */
    sub_payload_control = tvb_get_guint8(tvb, *offset) && 0x01; /* First bit determines Tier/Number of Block Thresholds field type */
    proto_tree_add_item(tree, hf_zbee_zcl_price_block_thresholds_sub_payload_control, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    while (tvb_reported_length_remaining(tvb, *offset) > 0) {
        guint8 thresholds;

        /* Tier/Number of Block Thresholds */
        thresholds = tvb_get_guint8(tvb, *offset) & ZBEE_ZCL_PRICE_BLOCK_THRESHOLDS_NUMBER_OF_BLOCK_THRESHOLDS;
        if (sub_payload_control == 0)
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_block_thresholds_tier_number_of_block_thresholds, ett_zbee_zcl_price_block_thresholds_tier_number_of_block_thresholds, tier_number_of_block_thresholds, ENC_LITTLE_ENDIAN);
        else
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_block_thresholds_tier_number_of_block_thresholds, ett_zbee_zcl_price_block_thresholds_tier_number_of_block_thresholds, number_of_block_thresholds, ENC_LITTLE_ENDIAN);
        *offset += 1;

        /* Block Threshold(s) */
        for (gint i = 0; i < thresholds; i++) {
            proto_tree_add_item(tree, hf_zbee_zcl_price_block_thresholds_block_threshold, tvb, *offset, 6, ENC_LITTLE_ENDIAN);
            *offset += 6;
        }
    }
} /*dissect_zcl_price_publish_block_thresholds*/

/**
 *This function manages the Publish CO2 Value payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_co2_value(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    static int * const co2_value_trailing_digit[] = {
        &hf_zbee_zcl_price_co2_value_trailing_digit,
        NULL
    };

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Tariff Type */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_tariff_type_mask, ett_zbee_zcl_price_tariff_type, zbee_zcl_price_tariff_type_mask, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* CO2 Value */
    proto_tree_add_item(tree, hf_zbee_zcl_price_co2_value, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* CO2 Unit */
    proto_tree_add_item(tree, hf_zbee_zcl_price_co2_unit, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* CO2 Value Trailing Digit */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_co2_value_trailing_digit_mask, ett_zbee_zcl_price_co2_value_trailing_digit, co2_value_trailing_digit, ENC_LITTLE_ENDIAN);
    *offset += 1;
} /*dissect_zcl_price_publish_co2_value*/

/**
 *This function manages the Publish Tier Labels payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_tier_labels(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8 number_of_labels;
    int length;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Tariff ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_tariff_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_price_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_price_total_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Number of Labels */
    number_of_labels = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_price_tier_labels_number_of_labels, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    for (gint i = 0; tvb_reported_length_remaining(tvb, *offset) >= 0 && i < number_of_labels; i++) {
        /* Tier ID */
        proto_tree_add_item(tree, hf_zbee_zcl_price_tier_labels_tier_id, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Tier Label */
        proto_tree_add_item_ret_length(tree, hf_zbee_zcl_price_tier_labels_tier_label, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &length);
        *offset += length;
    }
} /*dissect_zcl_price_publish_tier_labels*/

/**
 *This function manages the Publish Consolidated Bill payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_billing_period(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Billing Period Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_billing_period_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Billing Period Duration */
    proto_tree_add_item(tree, hf_zbee_zcl_price_billing_period_duration, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
    *offset += 3;

    /* Billing Period Duration Type */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_billing_period_duration_type, ett_zbee_zcl_price_billing_period_duration_type, zbee_zcl_price_billing_period_duration_type, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Tariff Type */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_tariff_type_mask, ett_zbee_zcl_price_tariff_type, zbee_zcl_price_tariff_type_mask, ENC_LITTLE_ENDIAN);
    *offset += 1;
} /*dissect_zcl_price_publish_billing_period*/

/**
 *This function manages the Publish Consolidated Bill payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_consolidated_bill(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    static int * const bill_trailing_digit[] = {
        &hf_zbee_zcl_price_consolidated_bill_trailing_digit,
        NULL
    };

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Billing Period Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Billing Period Duration */
    proto_tree_add_item(tree, hf_zbee_zcl_price_billing_period_duration, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
    *offset += 3;

    /* Billing Period Duration Type */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_billing_period_duration_type, ett_zbee_zcl_price_billing_period_duration_type, zbee_zcl_price_billing_period_duration_type, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Tariff Type */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_tariff_type_mask, ett_zbee_zcl_price_tariff_type, zbee_zcl_price_tariff_type_mask, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Consolidated Bill */
    proto_tree_add_item(tree, hf_zbee_zcl_price_consolidated_bill, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Currency */
    proto_tree_add_item(tree, hf_zbee_zcl_price_currency, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Bill Trailing Digit */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_consolidated_bill_trailing_digit_mask, ett_zbee_zcl_price_consolidated_bill_trailing_digit, bill_trailing_digit, ENC_LITTLE_ENDIAN);
    *offset += 1;
} /*dissect_zcl_price_publish_consolidated_bill*/
/**
 *This function manages the Publish CPP Event payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_cpp_event(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Duration in Minutes */
    proto_tree_add_item(tree, hf_zbee_zcl_price_duration_in_minutes, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Tariff Type */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_tariff_type_mask, ett_zbee_zcl_price_tariff_type, zbee_zcl_price_tariff_type_mask, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* CPP Price Tier */
    proto_tree_add_item(tree, hf_zbee_zcl_price_cpp_price_tier, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* CPP Auth */
    proto_tree_add_item(tree, hf_zbee_zcl_price_cpp_auth, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_price_publish_cpp_event*/


/**
 *This function manages the Publish Credit Payment payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_credit_payment(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t credit_payment_due_date;
    nstime_t credit_payment_date;
    int length;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Credit Payment Due Date */
    credit_payment_due_date.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    credit_payment_due_date.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_credit_payment_due_date, tvb, *offset, 4, &credit_payment_due_date);
    *offset += 4;

    /* Credit Payment Overdue Amount */
    proto_tree_add_item(tree, hf_zbee_zcl_price_credit_payment_overdue_amount, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Credit Payment Status */
    proto_tree_add_item(tree, hf_zbee_zcl_price_credit_payment_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Credit Payment */
    proto_tree_add_item(tree, hf_zbee_zcl_price_credit_payment, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Credit Payment Date */
    credit_payment_date.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    credit_payment_date.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_credit_payment_date, tvb, *offset, 4, &credit_payment_date);
    *offset += 4;

    /* Credit Payment Ref */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_price_credit_payment_ref, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &length);
    *offset += length;
} /*dissect_zcl_price_publish_credit_payment*/

/**
 *This function manages the Publish Currency Conversion payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_currency_conversion(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    static int * const conversion_factor_trailing_digit[] = {
        &hf_zbee_zcl_price_conversion_factor_trailing_digit,
        NULL
    };

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_price_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Old Currency */
    proto_tree_add_item(tree, hf_zbee_zcl_price_old_currency, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* New Currency */
    proto_tree_add_item(tree, hf_zbee_zcl_price_new_currency, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Conversion Factor */
    proto_tree_add_item(tree, hf_zbee_zcl_price_conversion_factor, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Conversion Factor Trailing digit */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_conversion_factor_trailing_digit_mask, ett_zbee_zcl_price_conversion_factor_trailing_digit, conversion_factor_trailing_digit, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Currency Change Control Flags */
    proto_tree_add_item(tree, hf_zbee_zcl_price_currency_change_control_flags, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_price_publish_currency_conversion*/

/**
 *This function manages the Publish Cancel Tariff payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_price_publish_cancel_tariff(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_price_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Tariff Type */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_price_tariff_type_mask, ett_zbee_zcl_price_tariff_type, zbee_zcl_price_tariff_type_mask, ENC_LITTLE_ENDIAN);
    *offset += 1;
} /*dissect_zcl_price_publish_cancel_tariff*/

/**
 *This function registers the ZCL Price dissector
 *
*/
void
proto_register_zbee_zcl_price(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_price_attr_server_id,
            { "Attribute", "zbee_zcl_se.price.attr_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &zbee_zcl_price_attr_server_names_ext,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_price_attr_client_id,
            { "Attribute", "zbee_zcl_se.price.attr_client_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_price_attr_client_names),
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

        { &hf_zbee_zcl_price_provider_id,
            { "Provider ID", "zbee_zcl_se.price.provider_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.price.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_min_issuer_event_id,
            { "Min Issuer Event ID", "zbee_zcl_se.price.min_issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_issuer_tariff_id,
            { "Issuer Tariff ID", "zbee_zcl_se.price.issuer_tariff_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_command_index,
            { "Command Index", "zbee_zcl_se.price.command_index", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_total_number_of_commands,
            { "Total Number of Commands", "zbee_zcl_se.price.total_number_of_commands", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_number_of_commands,
            { "Number of Commands", "zbee_zcl_se.price.number_of_commands", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_number_of_events,
            { "Number of Events", "zbee_zcl_se.price.number_of_events", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_number_of_records,
            { "Number of Records", "zbee_zcl_se.price.number_of_records", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_number_of_block_thresholds,
            { "Number of Block Thresholds", "zbee_zcl_se.price.number_of_block_thresholds", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_number_of_generation_tiers,
            { "Number of Generation Tiers", "zbee_zcl_se.price.number_of_generation_tiers", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_extended_number_of_price_tiers,
            { "Extended Number of Price Tiers", "zbee_zcl_se.price.extended_number_of_price_tiers", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_command_options,
            { "Command Options", "zbee_zcl_se.price.command_options", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_control,
            { "Price Control", "zbee_zcl_se.price.control", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        /* start Tariff Type fields */
        { &hf_zbee_zcl_price_tariff_type_mask,
            { "Tariff Type", "zbee_zcl_se.price.tariff_type_mask", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

         { &hf_zbee_zcl_price_tariff_type,
            { "Tariff Type", "zbee_zcl_se.price.tariff_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_tariff_type_names),
            ZBEE_ZCL_PRICE_TARIFF_TYPE, NULL, HFILL } },
         /* end Tariff Type fields */

        { &hf_zbee_zcl_price_tariff_resolution_period,
            { "Tariff Resolution Period", "zbee_zcl_se.price.tariff.resolution_period", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_tariff_resolution_period_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_cpp_price_tier,
            { "CPP Price Tier", "zbee_zcl_se.price.cpp_price_tier", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_cpp_auth,
            { "CPP Auth", "zbee_zcl_se.price.cpp_auth", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_rate_label,
            { "Rate Label", "zbee_zcl_se.price.rate_label", FT_UINT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_unit_of_measure,
            { "Unit of Measure", "zbee_zcl_se.price.unit_of_measure", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_currency,
            { "Currency", "zbee_zcl_se.price.currency", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        /* start Trailing Digit and Price Tier fields */
        { &hf_zbee_zcl_price_trailing_digit_and_price_tier,
            { "Trailing Digit and Price Tier", "zbee_zcl_se.price.trailing_digit_and_price_tier", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_tier,
            { "Price Tier", "zbee_zcl_se.price.tier", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_PRICE_TIER, NULL, HFILL } },

        { &hf_zbee_zcl_price_trailing_digit,
            { "Trailing Digit", "zbee_zcl_se.price.trailing_digit", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_PRICE_TRAILING_DIGIT, NULL, HFILL } },
         /* end Trailing Digit and Price Tier fields */

        /* start Number of Price Tiers and Register Tier fields */
        { &hf_zbee_zcl_price_number_of_price_tiers_and_register_tier,
            { "Number of Price Tiers and Register Tier", "zbee_zcl_se.price.number_of_price_tiers_and_register_tier", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_register_tier,
            { "Register Tier", "zbee_zcl_se.price.register_tier", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_PRICE_REGISTER_TIER, NULL, HFILL } },

        { &hf_zbee_zcl_price_number_of_price_tiers,
            { "Number of Price Tiers", "zbee_zcl_se.price.number_of_price_tiers", FT_UINT8, BASE_HEX, NULL,
            ZBEE_ZCL_PRICE_NUMBER_OF_PRICE_TIERS, NULL, HFILL } },
        /* end Number of Price Tiers and Register Tier fields */

        { &hf_zbee_zcl_price_extended_price_tier,
            { "Extended Price Tier", "zbee_zcl_se.price.extended_price_tier", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_extended_register_tier,
            { "Extended Register Tier", "zbee_zcl_se.price.extended_register_tier", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_duration_in_minutes,
            { "Duration in Minutes", "zbee_zcl_se.price.duration_in_minutes", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price,
            { "Price", "zbee_zcl_se.price.price", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_ratio,
            { "Price Ratio", "zbee_zcl_se.price.price.ratio", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_generation_price,
            { "Generation Price", "zbee_zcl_se.price.generation_price", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_generation_price_ratio,
            { "Generation Price Ratio", "zbee_zcl_se.price.generation_price.ratio", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_generation_tier,
            { "Generation Tier", "zbee_zcl_se.price.generation_tier", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_alternate_cost_delivered,
            { "Alternate Cost Delivered", "zbee_zcl_se.price.alternate_cost_delivered", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_alternate_cost_unit,
            { "Alternate Cost Unit", "zbee_zcl_se.price.alternate_cost.unit", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        /* start Alternate Cost Trailing Digit */
        { &hf_zbee_zcl_price_alternate_cost_trailing_digit_mask,
            { "Alternate Cost Trailing Digit", "zbee_zcl_se.price.alternate_cost.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_alternate_cost_trailing_digit,
            { "Alternate Cost Trailing Digit", "zbee_zcl_se.price.alternate_cost.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_PRICE_ALTERNATE_COST_TRAILING_DIGIT, NULL, HFILL } },
        /* end Alternate Cost Trailing Digit */

        { &hf_zbee_zcl_price_start_time,
            { "Start Time", "zbee_zcl_se.price.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_earliest_start_time,
            { "Earliest Start Time", "zbee_zcl_se.price.earliest_start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_latest_end_time,
            { "Latest End Time", "zbee_zcl_se.price.latest_end_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_current_time,
            { "Current Time", "zbee_zcl_se.price.current_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_price_ack_time,
            { "Price Ack Time", "zbee_zcl_se.price.price_ack_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_block_period_start_time,
            { "Block Period Start Time", "zbee_zcl_se.price.block_period.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_block_period_duration,
            { "Block Period Duration", "zbee_zcl_se.price.block_period.duration", FT_UINT24, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        /* start Block Period Control */
        { &hf_zbee_zcl_price_block_period_control,
            { "Block Period Control", "zbee_zcl_se.price.block_period.control", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_block_period_control_price_acknowledgement,
            { "Price Acknowledgement", "zbee_zcl_se.price.block_period.control.price_acknowledgement", FT_UINT8, BASE_DEC, VALS(zbee_zcl_price_block_period_control_price_acknowledgement_names),
            ZBEE_ZCL_PRICE_BLOCK_PERIOD_CONTROL_PRICE_ACKNOWLEDGEMENT, NULL, HFILL } },

        { &hf_zbee_zcl_price_block_period_control_repeating_block,
            { "Repeating Block", "zbee_zcl_se.price.block_period.control.repeating_block", FT_UINT8, BASE_DEC, VALS(zbee_zcl_price_block_period_control_repeating_block_names),
            ZBEE_ZCL_PRICE_BLOCK_PERIOD_CONTROL_REPEATING_BLOCK, NULL, HFILL } },
        /* end Block Period Control */

        /* start Block Period Duration Type fields */
        { &hf_zbee_zcl_price_block_period_duration_type,
            { "Block Period Duration Type", "zbee_zcl_se.price.block_period.duration.type", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_block_period_duration_timebase,
            { "Duration Timebase", "zbee_zcl_se.price.block_period.duration.timebase", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_block_period_duration_timebase_names),
            ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_TIMEBASE, NULL, HFILL } },

        { &hf_zbee_zcl_price_block_period_duration_control,
            { "Duration Control", "zbee_zcl_se.price.block_period.duration.control", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_block_period_duration_control_names),
            ZBEE_ZCL_PRICE_BLOCK_PERIOD_DURATION_CONTROL, NULL, HFILL } },
        /* end Block Period Duration Type fields */

        { &hf_zbee_zcl_price_conversion_factor,
            { "Conversion Factor", "zbee_zcl_se.price.conversion_factor", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        /* start Conversion Factor Trailing Digit fields */
        { &hf_zbee_zcl_price_conversion_factor_trailing_digit_mask,
            { "Conversion Factor Trailing Digit", "zbee_zcl_se.price.conversion_factor_trailing_digit", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

         { &hf_zbee_zcl_price_conversion_factor_trailing_digit,
            { "Conversion Factor Trailing Digit", "zbee_zcl_se.price.conversion_factor.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_PRICE_CONVERSION_FACTOR_TRAILING_DIGIT, NULL, HFILL } },
        /* end Conversion Factor Trailing Digit fields */

        { &hf_zbee_zcl_price_calorific_value,
            { "Calorific Value", "zbee_zcl_se.price.calorific_value", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_calorific_value_unit,
            { "Calorific Value Unit", "zbee_zcl_se.price.calorific_value.unit", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        /* start Calorific Value Trailing Digit fields */
        { &hf_zbee_zcl_price_calorific_value_trailing_digit_mask,
            { "Calorific Value Trailing Digit", "zbee_zcl_se.price.calorific_value.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

         { &hf_zbee_zcl_price_calorific_value_trailing_digit,
            { "Calorific Value Trailing Digit", "zbee_zcl_se.price.calorific_value.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_PRICE_CALORIFIC_VALUE_TRAILING_DIGIT, NULL, HFILL } },
        /* end Calorific Value Trailing Digit fields */

        /* start Tariff Information Type/Charging Scheme fields */
        { &hf_zbee_zcl_price_tariff_information_type_and_charging_scheme,
            { "Tariff Type/Charging Scheme", "zbee_zcl_se.price.tariff_information.type_and_charging_scheme", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

         { &hf_zbee_zcl_price_tariff_information_type,
            { "Tariff Type", "zbee_zcl_se.price.tariff_information.type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_tariff_type_names),
            ZBEE_ZCL_PRICE_TARIFF_INFORMATION_TYPE, NULL, HFILL } },

         { &hf_zbee_zcl_price_tariff_information_charging_scheme,
            { "Charging Scheme", "zbee_zcl_se.price.tariff_information.charging_scheme", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_tariff_charging_scheme_names),
            ZBEE_ZCL_PRICE_TARIFF_INFORMATION_CHARGING_SCHEME, NULL, HFILL } },
         /* end Tariff Information Type/Charging Scheme fields */

        { &hf_zbee_zcl_price_tariff_information_tariff_label,
            { "Tariff Label", "zbee_zcl_se.price.tariff_information.tariff_label", FT_UINT_STRING, STR_UNICODE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_tariff_information_number_of_price_tiers_in_use,
            { "Number of Price Tiers in Use", "zbee_zcl_se.price.tariff_information.number_of_price_tiers_in_use", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_tariff_information_number_of_block_thresholds_in_use,
            { "Number of Block Thresholds in Use", "zbee_zcl_se.price.tariff_information.number_of_block_thresholds_in_use", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        /* start Price Trailing Digit fields */
        { &hf_zbee_zcl_price_tariff_information_price_trailing_digit_mask,
            { "Price Trailing Digit", "zbee_zcl_se.price.tariff_information.price.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_tariff_information_price_trailing_digit,
            { "Price Trailing Digit", "zbee_zcl_se.price.tariff_information.price.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_PRICE_TARIFF_INFORMATION_PRICE_TRAILING_DIGIT, NULL, HFILL } },
        /* start Price Trailing Digit fields */

        { &hf_zbee_zcl_price_tariff_information_standing_charge,
            { "Standing Charge", "zbee_zcl_se.price.tariff_information.standing_charge", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_tariff_information_tier_block_mode,
            { "Tier Block Mode", "zbee_zcl_se.price.tariff_information.tier_block_mode", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_block_thresholds_number_of_block_thresholds,
            { "Number of Block Thresholds", "zbee_zcl_se.price.tariff_information.number_of_block_thresholds", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_PRICE_BLOCK_THRESHOLDS_NUMBER_OF_BLOCK_THRESHOLDS, NULL, HFILL } },

        { &hf_zbee_zcl_price_tariff_information_block_threshold_multiplier,
            { "Block Threshold Multiplier", "zbee_zcl_se.price.tariff_information.block_threshold_multiplier", FT_UINT24, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_tariff_information_block_threshold_divisor,
            { "Block Threshold Divisor", "zbee_zcl_se.price.tariff_information.block_threshold_divisor", FT_UINT24, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_price_matrix_sub_payload_control,
            { "Sub Payload Control", "zbee_zcl_se.price.price_matrix.sub_payload_control", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        /* start Tier/Block ID fields */
        { &hf_zbee_zcl_price_price_matrix_tier_block_id,
            { "Tier/Block ID", "zbee_zcl_se.price.price_matrix.tier_block_id", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_price_matrix_tier_block_id_block,
            { "Block", "zbee_zcl_se.price.price_matrix.block", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_PRICE_PRICE_MATRIX_TIER_BLOCK_ID_BLOCK, NULL, HFILL } },

        { &hf_zbee_zcl_price_price_matrix_tier_block_id_tier,
            { "Tier", "zbee_zcl_se.price.price_matrix.tier", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_PRICE_PRICE_MATRIX_TIER_BLOCK_ID_TIER, NULL, HFILL } },
        /* end Tier/Block ID fields */

        { &hf_zbee_zcl_price_price_matrix_tier_block_id_tou_tier,
            { "Tier", "zbee_zcl_se.price.price_matrix.tier", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_price_matrix_price,
            { "Price", "zbee_zcl_se.price.price_matrix.price", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_block_thresholds_sub_payload_control,
            { "Sub Payload Control", "zbee_zcl_se.price.block_thresholds.sub_payload_control", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        /* start Tier/Number of Block Thresholds fields */
        { &hf_zbee_zcl_price_block_thresholds_tier_number_of_block_thresholds,
            { "Tier/Number of Block Thresholds", "zbee_zcl_se.price.block_thresholds.tier_number_of_block_thresholds", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_block_thresholds_tier,
            { "Tier", "zbee_zcl_se.price.block_thresholds.tier", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_PRICE_BLOCK_THRESHOLDS_TIER, NULL, HFILL } },
        /* end Tier/Number of Block Thresholds fields */

        { &hf_zbee_zcl_price_block_thresholds_block_threshold,
            { "Block Threshold", "zbee_zcl_se.price.block_threshold", FT_UINT48, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_co2_value,
            { "CO2 Value", "zbee_zcl_se.price.co2.value", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_co2_unit,
            { "CO2 Unit", "zbee_zcl_se.price.co2.unit", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        /* start CO2 Trailing Digit fields */
        { &hf_zbee_zcl_price_co2_value_trailing_digit_mask,
            { "CO2 Value Trailing Digit", "zbee_zcl_se.price.co2.value.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_co2_value_trailing_digit,
            { "CO2 Value Trailing Digit", "zbee_zcl_se.price.co2.value.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_PRICE_CO2_VALUE_TRAILING_DIGIT, NULL, HFILL } },
        /* end CO2 Trailing Digit fields */

        { &hf_zbee_zcl_price_tier_labels_number_of_labels,
            { "Number of Labels", "zbee_zcl_se.price.tier_labels.number_of_labels", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_tier_labels_tier_id,
            { "Tier ID", "zbee_zcl_se.price.tier_labels.tier_id", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_tier_labels_tier_label,
            { "Tariff Label", "zbee_zcl_se.price.tier_labels.tier_label", FT_UINT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_billing_period_start_time,
            { "Billing Period Start Time", "zbee_zcl_se.price.billing_period.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_billing_period_duration,
            { "Billing Period Duration", "zbee_zcl_se.price.billing_period.duration", FT_UINT24, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        /* start Billing Period Duration Type fields */
        { &hf_zbee_zcl_price_billing_period_duration_type,
            { "Billing Period Duration Type", "zbee_zcl_se.price.billing_period.duration.type", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_billing_period_duration_timebase,
            { "Duration Timebase", "zbee_zcl_se.price.billing_period.duration.timebase", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_block_period_duration_timebase_names),
            ZBEE_ZCL_PRICE_BILLING_PERIOD_DURATION_TIMEBASE, NULL, HFILL } },

        { &hf_zbee_zcl_price_billing_period_duration_control,
            { "Duration Control", "zbee_zcl_se.price.billing_period.duration.control", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_block_period_duration_control_names),
            ZBEE_ZCL_PRICE_BILLING_PERIOD_DURATION_CONTROL, NULL, HFILL } },
        /* end Billing Period Duration Type fields */

        { &hf_zbee_zcl_price_consolidated_bill,
            { "Consolidated Bill", "zbee_zcl_se.price.consolidated_bill", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        /* start Consolidated Bill Trailing Digit fields */
        { &hf_zbee_zcl_price_consolidated_bill_trailing_digit_mask,
            { "Bill Trailing Digit", "zbee_zcl_se.price.consolidated_bill.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_consolidated_bill_trailing_digit,
            { "Bill Trailing Digit", "zbee_zcl_se.price.consolidated_bill.trailing_digit", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_PRICE_CONSOLIDATED_BILL_TRAILING_DIGIT, NULL, HFILL } },
        /* end Consolidated Bill Trailing Digit fields */

        { &hf_zbee_zcl_price_credit_payment_due_date,
            { "Credit Payment Due Date", "zbee_zcl_se.price.credit_payment.due_date", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_credit_payment_date,
            { "Credit Payment Date", "zbee_zcl_se.price.credit_payment.date", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_credit_payment_overdue_amount,
            { "Credit Payment Overdue Amount", "zbee_zcl_se.price.credit_payment.overdue_amount", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_credit_payment_status,
            { "Credit Payment Status", "zbee_zcl_se.price.credit_payment.status", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_credit_payment,
            { "Credit Payment", "zbee_zcl_se.price.credit_payment", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_credit_payment_ref,
            { "Credit Payment Ref", "zbee_zcl_se.price.credit_payment.ref", FT_UINT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_old_currency,
            { "Old Currency", "zbee_zcl_se.price.old_currency", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_new_currency,
            { "New Currency", "zbee_zcl_se.price.new_currency", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_price_currency_change_control_flags,
            { "Currency Change Control Flags", "zbee_zcl_se.price.currency_change_control_flags", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },
   };

    /* ZCL Price subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_price,
        &ett_zbee_zcl_price_tariff_type,
        &ett_zbee_zcl_price_trailing_digit_and_price_tier,
        &ett_zbee_zcl_price_number_of_price_tiers_and_register_tier,
        &ett_zbee_zcl_price_alternate_cost_trailing_digit,
        &ett_zbee_zcl_price_block_period_control,
        &ett_zbee_zcl_price_block_period_duration_type,
        &ett_zbee_zcl_price_conversion_factor_trailing_digit,
        &ett_zbee_zcl_price_calorific_value_trailing_digit,
        &ett_zbee_zcl_price_tariff_information_tariff_type_and_charging_scheme,
        &ett_zbee_zcl_price_tariff_information_price_trailing_digit,
        &ett_zbee_zcl_price_price_matrix_tier_block_id,
        &ett_zbee_zcl_price_block_thresholds_tier_number_of_block_thresholds,
        &ett_zbee_zcl_price_co2_value_trailing_digit,
        &ett_zbee_zcl_price_billing_period_duration_type,
        &ett_zbee_zcl_price_consolidated_bill_trailing_digit,
    };

    /* Register the ZigBee ZCL Price cluster protocol name and description */
    proto_zbee_zcl_price = proto_register_protocol("ZigBee ZCL Price", "ZCL Price", ZBEE_PROTOABBREV_ZCL_PRICE);
    proto_register_field_array(proto_zbee_zcl_price, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Price dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_PRICE, dissect_zbee_zcl_price, proto_zbee_zcl_price);
} /*proto_register_zbee_zcl_price*/

/**
 *Hands off the ZCL Price dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_price(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_PRICE,
                            proto_zbee_zcl_price,
                            ett_zbee_zcl_price,
                            ZBEE_ZCL_CID_PRICE,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_price_attr_server_id,
                            hf_zbee_zcl_price_attr_client_id,
                            hf_zbee_zcl_price_srv_rx_cmd_id,
                            hf_zbee_zcl_price_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_price_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_price*/

/* ########################################################################## */
/* #### (0x0701) DEMAND RESPONSE AND LOAD CONTROL CLUSTER ################### */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_drlc_attr_client_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_ATTR_ID_DRLC_CLNT_UTILITY_ENROLLMENT_GROUP,   0x0000, "Utility Enrollment Group" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DRLC_CLNT_START_RANDOMIZATION_MINUTES,0x0001, "Start Randomization Minutes" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DRLC_CLNT_DURATION_RND_MINUTES,       0x0002, "Duration Randomization Minutes" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DRLC_CLNT_DEVICE_CLASS_VALUE,         0x0003, "Device Class Value" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_DRLC_CLNT,      0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_drlc_attr_client_names);
VALUE_STRING_ARRAY(zbee_zcl_drlc_attr_client_names);

/* Server Commands Received */
#define zbee_zcl_drlc_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_DRLC_REPORT_EVENT_STATUS,        0x00, "Report Event Status" ) \
    XXX(ZBEE_ZCL_CMD_ID_DRLC_GET_SCHEDULED_EVENTS,       0x01, "Get Scheduled Events" )

VALUE_STRING_ENUM(zbee_zcl_drlc_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_drlc_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_drlc_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_DRLC_LOAD_CONTROL_EVENT,               0x00, "Load Control Event" ) \
    XXX(ZBEE_ZCL_CMD_ID_DRLC_CANCEL_LOAD_CONTROL_EVENT,        0x01, "Cancel Load Control Event" ) \
    XXX(ZBEE_ZCL_CMD_ID_DRLC_CANCEL_ALL_LOAD_CONTROL_EVENTS,   0x02, "Cancel All Load Control Events" )

VALUE_STRING_ENUM(zbee_zcl_drlc_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_drlc_srv_tx_cmd_names);

#define ZBEE_ZCL_DRLC_TEMP_OFFSET_NOT_USED 0xFF
#define ZBEE_ZCL_DRLC_TEMP_OFFSET_DIVIDER  10.0f

#define ZBEE_ZCL_DRLC_TEMP_SET_POINT_NOT_USED 0x8000
#define ZBEE_ZCL_DRLC_TEMP_SET_POINT_DIVIDER 100.0f

#define ZBEE_ZCL_DRLC_AVERAGE_LOAD_ADJUSTMENT_PERCENTAGE 0x80

static const range_string zbee_zcl_drlc_load_control_event_criticality_level[] = {
    { 0x0, 0x0,   "Reserved" },
    { 0x1, 0x1,   "Green" },
    { 0x2, 0x2,   "1" },
    { 0x3, 0x3,   "2" },
    { 0x4, 0x4,   "3" },
    { 0x5, 0x5,   "4" },
    { 0x6, 0x6,   "5" },
    { 0x7, 0x7,   "Emergency" },
    { 0x8, 0x8,   "Planned Outage" },
    { 0x9, 0x9,   "Service Disconnect" },
    { 0x0A, 0x0F, "Utility Defined" },
    { 0x10, 0xFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string zbee_zcl_drlc_report_event_status_event_status[] = {
    { 0x0, 0x0, "Reserved for future use." },
    { 0x01, 0x01, "Load Control Event command received" },
    { 0x02, 0x02, "Event started" },
    { 0x03, 0x03, "Event completed" },
    { 0x04, 0x04, "User has chosen to \"Opt-Out\", user will not participate in this event" },
    { 0x05, 0x05, "User has chosen to \"Opt-In\", user will participate in this event" },
    { 0x06, 0x06, "The event has been cancelled" },
    { 0x07, 0x07, "The event has been superseded" },
    { 0x08, 0x08, "Event partially completed with User \"Opt-Out\"." },
    { 0x09, 0x09, "Event partially completed due to User \"Opt-In\"." },
    { 0x0A, 0x0A, "Event completed, no User participation (Previous \"Opt-Out\")." },
    { 0x0B, 0xF7, "Reserved for future use." },
    { 0xF8, 0xF8, "Rejected - Invalid Cancel Command (Default)" },
    { 0xF9, 0xF9, "Rejected - Invalid Cancel Command (Invalid Effective Time)" },
    { 0xFA, 0xFA , "Reserved" },
    { 0xFB, 0xFB, "Rejected - Event was received after it had expired (Current Time > Start Time + Duration)" },
    { 0xFC, 0xFC, "Reserved for future use." },
    { 0xFD, 0xFD, "Rejected - Invalid Cancel Command (Undefined Event)" },
    { 0xFE, 0xFE, "Load Control Event command Rejected" },
    { 0xFF, 0xFF, "Reserved for future use." },
    { 0, 0, NULL }
};

static const range_string zbee_zcl_drlc_report_event_signature_type[] = {
    { 0x0, 0x0, "No Signature" },
    { 0x01, 0x01, "ECDSA" },
    { 0x02, 0xFF, "Reserved" },
    { 0, 0, NULL }
};

static const true_false_string zbee_zcl_drlc_randomize_start_tfs = {
    "Randomize Start time",
    "Randomized Start not Applied"
};

static const true_false_string zbee_zcl_drlc_randomize_duration_tfs = {
    "Randomize Duration time",
    "Randomized Duration not Applied"
};
/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_drlc(void);
void proto_reg_handoff_zbee_zcl_drlc(void);

static void decode_zcl_msg_start_time                                   (gchar *s, guint32 value);
static void decode_zcl_drlc_temp_offset                                 (gchar *s, guint8 value);
static void decode_zcl_drlc_temp_set_point                              (gchar *s, gint16 value);
static void decode_zcl_drlc_average_load_adjustment_percentage          (gchar *s, gint8 value);

static void dissect_zcl_drlc_load_control_event             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_drlc_cancel_load_control_event      (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_drlc_cancel_all_load_control_event  (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_drlc_report_event_status            (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_drlc_get_scheduled_events           (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/* Attribute Dissector Helpers */
static void dissect_zcl_drlc_attr_data                                  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);
/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_drlc = -1;

static int hf_zbee_zcl_drlc_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_drlc_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_drlc_attr_client_id = -1;
static int hf_zbee_zcl_drlc_attr_reporting_status = -1;
static int hf_zbee_zcl_drlc_issuer_event_id = -1;
static int hf_zbee_zcl_drlc_device_class = -1;
static int hf_zbee_zcl_drlc_device_class_hvac_compressor_or_furnace = -1;
static int hf_zbee_zcl_drlc_device_class_strip_heaters_baseboard_heaters = -1;
static int hf_zbee_zcl_drlc_device_class_water_heater = -1;
static int hf_zbee_zcl_drlc_device_class_pool_pump_spa_jacuzzi = -1;
static int hf_zbee_zcl_drlc_device_class_smart_appliances = -1;
static int hf_zbee_zcl_drlc_device_class_irrigation_pump = -1;
static int hf_zbee_zcl_drlc_device_class_managed_c_i_loads= -1;
static int hf_zbee_zcl_drlc_device_class_simple_misc_loads = -1;
static int hf_zbee_zcl_drlc_device_class_exterior_lighting = -1;
static int hf_zbee_zcl_drlc_device_class_interior_lighting = -1;
static int hf_zbee_zcl_drlc_device_class_electric_vehicle = -1;
static int hf_zbee_zcl_drlc_device_class_generation_systems = -1;
static int hf_zbee_zcl_drlc_device_class_reserved = -1;
static int hf_zbee_zcl_drlc_utility_enrollment_group = -1;
static int hf_zbee_zcl_drlc_start_time = -1;
static int hf_zbee_zcl_drlc_duration_in_minutes = -1;
static int hf_zbee_zcl_drlc_criticality_level = -1;
static int hf_zbee_zcl_drlc_cooling_temp_offset = -1;
static int hf_zbee_zcl_drlc_heating_temp_offset = -1;
static int hf_zbee_zcl_drlc_cooling_temp_set_point = -1;
static int hf_zbee_zcl_drlc_heating_temp_set_point = -1;
static int hf_zbee_zcl_drlc_average_load_adjustment_percentage = -1;
static int hf_zbee_zcl_drlc_duty_cycle = -1;
static int hf_zbee_zcl_drlc_event_control = -1;
static int hf_zbee_zcl_drlc_event_control_randomize_start_time = -1;
static int hf_zbee_zcl_drlc_event_control_randomize_duration_time = -1;
static int hf_zbee_zcl_drlc_event_control_reserved = -1;
static int hf_zbee_zcl_drlc_cancel_control = -1;
static int hf_zbee_zcl_drlc_cancel_control_event_in_process = -1;
static int hf_zbee_zcl_drlc_cancel_control_reserved = -1;
static int hf_zbee_zcl_drlc_effective_time = -1;
static int hf_zbee_zcl_drlc_report_event_issuer_event_id = -1;
static int hf_zbee_zcl_drlc_report_event_event_status = -1;
static int hf_zbee_zcl_drlc_report_event_event_status_time = -1;
static int hf_zbee_zcl_drlc_report_event_criticality_level_applied = -1;
static int hf_zbee_zcl_drlc_report_event_cooling_temp_set_point_applied = -1;
static int hf_zbee_zcl_drlc_report_event_heating_temp_set_point_applied = -1;
static int hf_zbee_zcl_drlc_report_event_average_load_adjustment_percentage = -1;
static int hf_zbee_zcl_drlc_report_event_duty_cycle = -1;
static int hf_zbee_zcl_drlc_report_event_event_control = -1;
static int hf_zbee_zcl_drlc_report_event_signature_type = -1;
static int hf_zbee_zcl_drlc_report_event_signature = -1;
static int hf_zbee_zcl_drlc_get_scheduled_events_start_time = -1;
static int hf_zbee_zcl_drlc_get_scheduled_events_number_of_events = -1;
static int hf_zbee_zcl_drlc_get_scheduled_events_issuer_event_id = -1;

static int* const zbee_zcl_drlc_control_event_device_classes[] = {
    &hf_zbee_zcl_drlc_device_class_hvac_compressor_or_furnace,
    &hf_zbee_zcl_drlc_device_class_strip_heaters_baseboard_heaters,
    &hf_zbee_zcl_drlc_device_class_water_heater,
    &hf_zbee_zcl_drlc_device_class_pool_pump_spa_jacuzzi,
    &hf_zbee_zcl_drlc_device_class_smart_appliances,
    &hf_zbee_zcl_drlc_device_class_irrigation_pump,
    &hf_zbee_zcl_drlc_device_class_managed_c_i_loads,
    &hf_zbee_zcl_drlc_device_class_simple_misc_loads,
    &hf_zbee_zcl_drlc_device_class_exterior_lighting,
    &hf_zbee_zcl_drlc_device_class_interior_lighting,
    &hf_zbee_zcl_drlc_device_class_electric_vehicle,
    &hf_zbee_zcl_drlc_device_class_generation_systems,
    &hf_zbee_zcl_drlc_device_class_reserved,
    NULL
};

static int* const hf_zbee_zcl_drlc_event_control_flags[] = {
    &hf_zbee_zcl_drlc_event_control_randomize_start_time,
    &hf_zbee_zcl_drlc_event_control_randomize_duration_time,
    &hf_zbee_zcl_drlc_event_control_reserved,
    NULL
};

static int* const hf_zbee_zcl_drlc_cancel_control_flags[] = {
    &hf_zbee_zcl_drlc_cancel_control_event_in_process,
    &hf_zbee_zcl_drlc_cancel_control_reserved,
    NULL
};
/* Initialize the subtree pointers */
static gint ett_zbee_zcl_drlc = -1;
static gint ett_zbee_zcl_drlc_device_class = -1;
static gint ett_zbee_zcl_drlc_event_control = -1;
static gint ett_zbee_zcl_drlc_cancel_control = -1;

/*************************/
/* Function Bodies       */
/*************************/
/**
 * This function decodes Temperature Offset.
 *
 * @param s string to display
 * @param value value to decode
*/
static void
decode_zcl_drlc_temp_offset(gchar *s, guint8 value)
{
    if (value == ZBEE_ZCL_DRLC_TEMP_OFFSET_NOT_USED)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Not Used");
    else {
        gfloat temp_delta;
        temp_delta = value / ZBEE_ZCL_DRLC_TEMP_OFFSET_DIVIDER;
        g_snprintf(s, ITEM_LABEL_LENGTH, "%+.2f%s", temp_delta, units_degree_celsius.singular);
    }
} /*decode_zcl_msg_start_time*/

/**
 * This function decodes Temperature Set Point.
 *
 * @param s string to display
 * @param value value to decode
*/
static void decode_zcl_drlc_temp_set_point(gchar *s, gint16 value)
{
    if (value & ZBEE_ZCL_DRLC_TEMP_SET_POINT_NOT_USED)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Not Used");
    else {
        gfloat temp_delta;
        temp_delta = value / ZBEE_ZCL_DRLC_TEMP_SET_POINT_DIVIDER;
        g_snprintf(s, ITEM_LABEL_LENGTH, "%+.2f%s", temp_delta, units_degree_celsius.singular);
    }
} /*decode_zcl_drlc_temp_set_point*/

/**
 * This function decodes Average Load Adjustment Percentage.
 *
 * @param s string to display
 * @param value value to decode
*/
static void decode_zcl_drlc_average_load_adjustment_percentage(gchar *s, gint8 value)
{
    if (value & ZBEE_ZCL_DRLC_AVERAGE_LOAD_ADJUSTMENT_PERCENTAGE)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Not Used");
    else {
        g_snprintf(s, ITEM_LABEL_LENGTH, "%+d%%", value);
    }
} /*decode_zcl_drlc_average_load_adjustment_percentage*/

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
dissect_zcl_drlc_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_DRLC_CLNT:
            proto_tree_add_item(tree, hf_zbee_zcl_drlc_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }
} /*dissect_zcl_drlc_attr_data*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *DRLC Load Control Event Command Payload.
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_drlc_load_control_event(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_issuer_event_id, tvb,
                        *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Device Class */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_drlc_device_class, ett_zbee_zcl_drlc_device_class,
                           zbee_zcl_drlc_control_event_device_classes, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Utility Enrollment Group */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_utility_enrollment_group, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Start Time */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_start_time, tvb,
                        *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    /* Duration In Minutes */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_duration_in_minutes, tvb,
                        *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Criticality Level */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_criticality_level, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Cooling Temperature Offset */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_cooling_temp_offset, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Heating Temperature Offset */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_heating_temp_offset, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Cooling Temperature Set Point */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_cooling_temp_set_point, tvb,
                        *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Heating Temperature Set Point */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_heating_temp_set_point, tvb,
                        *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Average Load Adjustment Percentage */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_average_load_adjustment_percentage, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Duty Cycle */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_duty_cycle, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Event Control */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_drlc_event_control, ett_zbee_zcl_drlc_event_control,
                           hf_zbee_zcl_drlc_event_control_flags, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_drlc_load_control_event*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *DRLC Cancel Load Control Event Command Payload.
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_drlc_cancel_load_control_event(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_issuer_event_id, tvb,
                        *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Device Class */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_drlc_device_class, ett_zbee_zcl_drlc_device_class,
                           zbee_zcl_drlc_control_event_device_classes, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Utility Enrollment Group */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_utility_enrollment_group, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Cancel Control */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_drlc_cancel_control, ett_zbee_zcl_drlc_cancel_control,
                           hf_zbee_zcl_drlc_cancel_control_flags, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Effective Time */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_effective_time, tvb,
                        *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

}

/**
 *This function is called by ZCL foundation dissector in order to decode
 *DRLC Cancel All Load Control Events Command Payload.
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_drlc_cancel_all_load_control_event(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Cancel Control */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_drlc_cancel_control, ett_zbee_zcl_drlc_cancel_control,
                           hf_zbee_zcl_drlc_cancel_control_flags, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zcl_drlc_cancel_all_load_control_event*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *DRLC Report Event Status Command Payload.
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_drlc_report_event_status(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t event_status_time;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_report_event_issuer_event_id, tvb,
                        *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Event Status */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_report_event_event_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Event Status Time */
    event_status_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    event_status_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_drlc_report_event_event_status_time, tvb, *offset, 4, &event_status_time);
    *offset += 4;

    /* Criticality Level Applied */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_report_event_criticality_level_applied, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Cooling Temperature Set Point Applied */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_report_event_cooling_temp_set_point_applied, tvb,
                        *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Heating Temperature Set Point Applied */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_report_event_heating_temp_set_point_applied, tvb,
                        *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Average Load Adjustment Percentage Applied */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_report_event_average_load_adjustment_percentage, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Duty Cycle Applied */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_report_event_duty_cycle, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Event Control */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_drlc_report_event_event_control, ett_zbee_zcl_drlc_event_control,
                           hf_zbee_zcl_drlc_event_control_flags, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* Signature Type */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_report_event_signature_type, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Signature */
    guint rem_len;
    rem_len = tvb_reported_length_remaining(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_report_event_signature, tvb,
                        *offset, rem_len, ENC_NA);
    *offset += rem_len;
} /*dissect_zcl_drlc_report_event_status*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *DRLC Get Scheduled Events Command Payload.
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_drlc_get_scheduled_events(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;
    gint     rem_len;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_drlc_get_scheduled_events_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Number of Events */
    proto_tree_add_item(tree, hf_zbee_zcl_drlc_get_scheduled_events_number_of_events, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    rem_len = tvb_reported_length_remaining(tvb, *offset);
    if (rem_len > 3) {
        /* Issuer Event ID */
        proto_tree_add_item(tree, hf_zbee_zcl_drlc_get_scheduled_events_issuer_event_id, tvb,
                            *offset, rem_len, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }
} /*dissect_zcl_drlc_report_event_status*/

/**
 *ZigBee ZCL DRLC cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_drlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    zbee_zcl_packet   *zcl;
    guint             offset = 0;
    guint8            cmd_id;
    gint              rem_len;
    proto_tree       *payload_tree;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_drlc_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_drlc_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_drlc, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_DRLC_REPORT_EVENT_STATUS:
                    dissect_zcl_drlc_report_event_status(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DRLC_GET_SCHEDULED_EVENTS:
                    dissect_zcl_drlc_get_scheduled_events(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_drlc_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_drlc_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_drlc, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_DRLC_LOAD_CONTROL_EVENT:
                    dissect_zcl_drlc_load_control_event(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DRLC_CANCEL_LOAD_CONTROL_EVENT:
                    dissect_zcl_drlc_cancel_load_control_event(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DRLC_CANCEL_ALL_LOAD_CONTROL_EVENTS:
                    dissect_zcl_drlc_cancel_all_load_control_event(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_drlc*/

/**
 *This function registers the ZCL DRLC dissector
 *
*/
void
proto_register_zbee_zcl_drlc(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_drlc_attr_client_id,
            { "Attribute", "zbee_zcl_se.drlc.attr_client_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_drlc_attr_client_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.drlc.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.drlc.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_drlc_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.drlc.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_drlc_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.drlc.issuer_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class,
            { "Device Class", "zbee_zcl_se.drlc.device_class",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_hvac_compressor_or_furnace,
            { "HVAC Compressor or Furnace", "zbee_zcl_se.drlc.device_class.hvac_compressor_or_furnace",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_strip_heaters_baseboard_heaters,
            { "Strip Heaters/Baseboard Heaters", "zbee_zcl_se.drlc.device_class.strip_heaters_baseboard_heaters",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_water_heater,
            { "Water Heater", "zbee_zcl_se.drlc.device_class.water_heater",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_pool_pump_spa_jacuzzi,
            { "Pool Pump/Spa/Jacuzzi", "zbee_zcl_se.drlc.device_class.pool_pump_spa_jacuzzi",
            FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_smart_appliances,
            { "Smart Appliances", "zbee_zcl_se.drlc.device_class.smart_appliances",
            FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_irrigation_pump,
            { "Irrigation Pump", "zbee_zcl_se.drlc.device_class.irrigation_pump",
            FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_managed_c_i_loads,
            { "Managed Commercial & Industrial (C&I) loads", "zbee_zcl_se.drlc.device_class.managed_c_i_loads",
            FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_simple_misc_loads,
            { "Simple misc. (Residential On/Off) loads", "zbee_zcl_se.drlc.device_class.simple_misc_loads",
            FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_exterior_lighting,
            { "Exterior Lighting", "zbee_zcl_se.drlc.device_class.exterior_lighting",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_interior_lighting,
            { "Interior Lighting", "zbee_zcl_se.drlc.device_class.interior_lighting",
            FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_electric_vehicle,
            { "Electric Vehicle", "zbee_zcl_se.drlc.device_class.electric_vehicle",
            FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_generation_systems,
            { "Generation Systems", "zbee_zcl_se.drlc.device_class.generation_systems",
            FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_device_class_reserved ,
            { "Reserved", "zbee_zcl_se.drlc.device_class.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_utility_enrollment_group,
            { "Utility Enrollment Group", "zbee_zcl_se.drlc.utility_enrollment_group",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_start_time,
            { "Start Time", "zbee_zcl_se.drlc.start_time",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_zcl_msg_start_time), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_duration_in_minutes,
            { "Duration In Minutes", "zbee_zcl_se.drlc.duration_in_minutes",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_criticality_level,
            { "Criticality Level", "zbee_zcl_se.drlc.criticality_level",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_drlc_load_control_event_criticality_level), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_cooling_temp_offset,
            { "Cooling Temperature Offset", "zbee_zcl_se.drlc.cooling_temperature_offset",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_temp_offset), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_heating_temp_offset,
            { "Heating Temperature Offset", "zbee_zcl_se.drlc.heating_temperature_offset",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_temp_offset), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_cooling_temp_set_point,
            { "Cooling Temperature Set Point", "zbee_zcl_se.drlc.cooling_temperature_set_point",
            FT_INT16, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_temp_set_point), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_heating_temp_set_point,
            { "Heating Temperature Set Point", "zbee_zcl_se.drlc.heating_temperature_set_point",
            FT_INT16, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_temp_set_point), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_average_load_adjustment_percentage,
            { "Average Load Adjustment Percentage", "zbee_zcl_se.drlc.average_load_adjustment_percentage",
            FT_INT8, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_average_load_adjustment_percentage), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_duty_cycle,
            { "Duty Cycle", "zbee_zcl_se.drlc.duty_cycle",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_event_control,
            { "Event Control", "zbee_zcl_se.drlc.event_control",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_event_control_randomize_start_time,
            { "Randomize Start time", "zbee_zcl_se.drlc.randomize_start_time",
            FT_BOOLEAN, 8, TFS(&zbee_zcl_drlc_randomize_start_tfs), 0x01, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_event_control_randomize_duration_time,
            { "Randomize Duration time", "zbee_zcl_se.drlc.randomize_duration_time",
            FT_BOOLEAN, 8, TFS(&zbee_zcl_drlc_randomize_duration_tfs), 0x02, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_event_control_reserved,
            { "Reserved", "zbee_zcl_se.drlc.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_cancel_control,
            { "Cancel Control", "zbee_zcl_se.drlc.cancel_control",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_cancel_control_event_in_process,
            { "Event in process", "zbee_zcl_se.drlc.cancel_control.event_in_process",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_cancel_control_reserved,
            { "Reserved", "zbee_zcl_se.drlc.cancel_control.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFE, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_effective_time,
            { "Reserved", "zbee_zcl_se.drlc.effective_time",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_zcl_msg_start_time), 0xFE, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.drlc.report_event.issuer_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_event_status,
            { "Event Status", "zbee_zcl_se.drlc.report_event.event_status",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_drlc_report_event_status_event_status), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_event_status_time,
            { "Event Status Time", "zbee_zcl_se.drlc.report_event.event_status_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_criticality_level_applied ,
            { "Criticality Level Applied", "zbee_zcl_se.drlc.report_event.criticality_level_applied",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_drlc_load_control_event_criticality_level), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_cooling_temp_set_point_applied,
            { "Cooling Temperature Set Point Applied", "zbee_zcl_se.drlc.report_event.cooling_temperature_set_point_applied",
            FT_INT16, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_temp_set_point), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_heating_temp_set_point_applied,
            { "Heating Temperature Set Point Applied", "zbee_zcl_se.drlc.report_event.heating_temperature_set_point_applied",
            FT_INT16, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_temp_set_point), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_average_load_adjustment_percentage ,
            { "Average Load Adjustment Percentage Applied", "zbee_zcl_se.drlc.report_event.average_load_adjustment_percentage_applied",
            FT_INT8, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_average_load_adjustment_percentage), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_duty_cycle,
            { "Duty Cycle Applied", "zbee_zcl_se.drlc.report_event.duty_cycle_applied",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_event_control ,
            { "Event Control", "zbee_zcl_se.drlc.report_event.event_control",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_signature_type,
            { "Signature Type", "zbee_zcl_se.drlc.report_event.signature_type",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_drlc_report_event_signature_type), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_report_event_signature,
            { "Signature", "zbee_zcl_se.drlc.report_event.signature",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_get_scheduled_events_start_time,
            { "Start Time", "zbee_zcl_se.drlc.get_scheduled_events.start_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_get_scheduled_events_number_of_events,
            { "Number of Events", "zbee_zcl_se.drlc.get_scheduled_events.numbers_of_events",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_drlc_get_scheduled_events_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.drlc.get_scheduled_events.issuer_event_id",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    };

    /* ZCL DRLC subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_drlc,
        &ett_zbee_zcl_drlc_device_class,
        &ett_zbee_zcl_drlc_event_control,
        &ett_zbee_zcl_drlc_cancel_control
    };

    /* Register the ZigBee ZCL DRLC cluster protocol name and description */
    proto_zbee_zcl_drlc = proto_register_protocol("ZigBee ZCL DLRC", "ZCL DLRC", ZBEE_PROTOABBREV_ZCL_DRLC);
    proto_register_field_array(proto_zbee_zcl_drlc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL DRLC dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_DRLC, dissect_zbee_zcl_drlc, proto_zbee_zcl_drlc);
} /*proto_register_zbee_zcl_drlc*/

/**
 *Hands off the ZCL DRLC dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_drlc(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_DRLC,
                            proto_zbee_zcl_drlc,
                            ett_zbee_zcl_drlc,
                            ZBEE_ZCL_CID_DEMAND_RESPONSE_LOAD_CONTROL,
                            ZBEE_MFG_CODE_NONE,
                            -1,
                            hf_zbee_zcl_drlc_attr_client_id,
                            hf_zbee_zcl_drlc_srv_rx_cmd_id,
                            hf_zbee_zcl_drlc_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_drlc_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_drlc*/

/* ########################################################################## */
/* #### (0x0702) METERING CLUSTER ########################################## */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_met_attr_server_names_VALUE_STRING_LIST(XXX) \
/* Reading Information Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_SUM_DEL,                       0x0000, "Current Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_SUM_RECV,                      0x0001, "Current Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MAX_DE_DEL,                    0x0002, "Current Max Demand Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MAX_DE_RECV,                   0x0003, "Current Max Demand Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DFT_SUM,                           0x0004, "DFTSummation" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DAILY_FREEZE_TIME,                 0x0005, "Daily Freeze Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_POWER_FACTOR,                      0x0006, "Power Factor" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_READ_SNAP_TIME,                    0x0007, "Reading Snapshot Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MAX_DEMAND_DEL_TIME,           0x0008, "Current Max Demand Delivered Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MAX_DEMAND_RECV_TIME,          0x0009, "Current Max Demand Received Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DEFAULT_UPDATE_PERIOD,             0x000A, "Default Update Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_FAST_POLL_UPDATE_PERIOD,           0x000B, "Fast Poll Update Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_BLOCK_PER_CON_DEL,             0x000C, "Current Block Period Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DAILY_CON_TARGET,                  0x000D, "Daily Consumption Target" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_BLOCK,                     0x000E, "Current Block" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PROFILE_INTERVAL_PERIOD,           0x000F, "Profile Interval Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DEPRECATED,                        0x0010, "Deprecated" ) \
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
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_1_SUM_RECV,           0x0101, "Current Tier 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_2_SUM_DEL,            0x0102, "Current Tier 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_2_SUM_RECV,           0x0103, "Current Tier 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_3_SUM_DEL,            0x0104, "Current Tier 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_3_SUM_RECV,           0x0105, "Current Tier 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_4_SUM_DEL,            0x0106, "Current Tier 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_4_SUM_RECV,           0x0107, "Current Tier 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_5_SUM_DEL,            0x0108, "Current Tier 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_5_SUM_RECV,           0x0109, "Current Tier 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_6_SUM_DEL,            0x010A, "Current Tier 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_6_SUM_RECV,           0x010B, "Current Tier 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_7_SUM_DEL,            0x010C, "Current Tier 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_7_SUM_RECV,           0x010D, "Current Tier 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_8_SUM_DEL,            0x010E, "Current Tier 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_8_SUM_RECV,           0x010F, "Current Tier 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_9_SUM_DEL,            0x0110, "Current Tier 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_9_SUM_RECV,           0x0111, "Current Tier 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_10_SUM_DEL,           0x0112, "Current Tier 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_10_SUM_RECV,          0x0113, "Current Tier 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_11_SUM_DEL,           0x0114, "Current Tier 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_11_SUM_RECV,          0x0115, "Current Tier 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_12_SUM_DEL,           0x0116, "Current Tier 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_12_SUM_RECV,          0x0117, "Current Tier 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_13_SUM_DEL,           0x0118, "Current Tier 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_13_SUM_RECV,          0x0119, "Current Tier 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_14_SUM_DEL,           0x011A, "Current Tier 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_14_SUM_RECV,          0x011B, "Current Tier 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_15_SUM_DEL,           0x011C, "Current Tier 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_15_SUM_RECV,          0x011D, "Current Tier 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_16_SUM_DEL,           0x011E, "Current Tier 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_16_SUM_RECV,          0x011F, "Current Tier 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_17_SUM_DEL,           0x0120, "Current Tier 17 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_17_SUM_RECV,          0x0121, "Current Tier 17 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_18_SUM_DEL,           0x0122, "Current Tier 18 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_18_SUM_RECV,          0x0123, "Current Tier 18 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_19_SUM_DEL,           0x0124, "Current Tier 19 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_19_SUM_RECV,          0x0125, "Current Tier 19 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_20_SUM_DEL,           0x0126, "Current Tier 20 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_20_SUM_RECV,          0x0127, "Current Tier 20 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_21_SUM_DEL,           0x0128, "Current Tier 21 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_21_SUM_RECV,          0x0129, "Current Tier 21 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_22_SUM_DEL,           0x012A, "Current Tier 22 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_22_SUM_RECV,          0x012B, "Current Tier 22 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_23_SUM_DEL,           0x012C, "Current Tier 23 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_23_SUM_RECV,          0x012D, "Current Tier 23 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_24_SUM_DEL,           0x012E, "Current Tier 24 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_24_SUM_RECV,          0x012F, "Current Tier 24 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_25_SUM_DEL,           0x0130, "Current Tier 25 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_25_SUM_RECV,          0x0131, "Current Tier 25 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_26_SUM_DEL,           0x0132, "Current Tier 26 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_26_SUM_RECV,          0x0133, "Current Tier 26 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_27_SUM_DEL,           0x0134, "Current Tier 27 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_27_SUM_RECV,          0x0135, "Current Tier 27 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_28_SUM_DEL,           0x0136, "Current Tier 28 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_28_SUM_RECV,          0x0137, "Current Tier 28 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_29_SUM_DEL,           0x0138, "Current Tier 29 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_29_SUM_RECV,          0x0139, "Current Tier 29 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_30_SUM_DEL,           0x013A, "Current Tier 30 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_30_SUM_RECV,          0x013B, "Current Tier 30 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_31_SUM_DEL,           0x013C, "Current Tier 31 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_31_SUM_RECV,          0x013D, "Current Tier 31 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_32_SUM_DEL,           0x013E, "Current Tier 32 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_32_SUM_RECV,          0x013F, "Current Tier 32 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_33_SUM_DEL,           0x0140, "Current Tier 33 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_33_SUM_RECV,          0x0141, "Current Tier 33 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_34_SUM_DEL,           0x0142, "Current Tier 34 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_34_SUM_RECV,          0x0143, "Current Tier 34 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_35_SUM_DEL,           0x0144, "Current Tier 35 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_35_SUM_RECV,          0x0145, "Current Tier 35 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_36_SUM_DEL,           0x0146, "Current Tier 36 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_36_SUM_RECV,          0x0147, "Current Tier 36 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_37_SUM_DEL,           0x0148, "Current Tier 37 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_37_SUM_RECV,          0x0149, "Current Tier 37 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_38_SUM_DEL,           0x014A, "Current Tier 38 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_38_SUM_RECV,          0x014B, "Current Tier 38 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_39_SUM_DEL,           0x014C, "Current Tier 39 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_39_SUM_RECV,          0x014D, "Current Tier 39 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_40_SUM_DEL,           0x014E, "Current Tier 40 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_40_SUM_RECV,          0x014F, "Current Tier 40 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_41_SUM_DEL,           0x0150, "Current Tier 41 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_41_SUM_RECV,          0x0151, "Current Tier 41 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_42_SUM_DEL,           0x0152, "Current Tier 42 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_42_SUM_RECV,          0x0153, "Current Tier 42 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_43_SUM_DEL,           0x0154, "Current Tier 43 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_43_SUM_RECV,          0x0155, "Current Tier 43 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_44_SUM_DEL,           0x0156, "Current Tier 44 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_44_SUM_RECV,          0x0157, "Current Tier 44 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_45_SUM_DEL,           0x0158, "Current Tier 45 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_45_SUM_RECV,          0x0159, "Current Tier 45 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_46_SUM_DEL,           0x015A, "Current Tier 46 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_46_SUM_RECV,          0x015B, "Current Tier 46 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_47_SUM_DEL,           0x015C, "Current Tier 47 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_47_SUM_RECV,          0x015D, "Current Tier 47 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_48_SUM_DEL,           0x015E, "Current Tier 48 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_TIER_48_SUM_RECV,          0x015F, "Current Tier 48 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CPP1_SUMMATION_DELIVERED,          0x01FC, "CPP1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CPP2_SUMMATION_DELIVERED,          0x01FE, "CPP2 Summation Delivered" ) \
/* Meter Status Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_STATUS,                            0x0200, "Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_REMAIN_BAT_LIFE,                   0x0201, "Remaining Battery Life" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_HOURS_IN_OPERATION,                0x0202, "Hours in Operation" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_HOURS_IN_FAULT,                    0x0203, "Hours in Fault" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_EXTENDED_STATUS,                   0x0204, "Extended Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_REMAIN_BAT_LIFE_DAYS,              0x0205, "Remaining Battery Life in Days" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_METER_ID,                  0x0206, "Current Meter ID" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_AMBIENT_CON_IND,                   0x0207, "Ambient Consumption Indicator" ) \
/* Formatting */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_UNIT_OF_MEASURE,                   0x0300, "Unit of Measure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_MULTIPLIER,                        0x0301, "Multiplier" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DIVISOR,                           0x0302, "Divisor" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_SUMMATION_FORMATTING,              0x0303, "Summation Formatting" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DEMAND_FORMATTING,                 0x0304, "Demand Formatting" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_HISTORICAL_CON_FORMATTING,         0x0305, "Historical Consumption Formatting" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_METERING_DEVICE_TYPE,              0x0306, "Metering Device Type" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_SITE_ID,                           0x0307, "Site ID" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_METER_SERIAL_NUMBER,               0x0308, "Meter Serial Number" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ENERGY_CARRIER_UNIT_OF_MEASURE,    0x0309, "Energy Carrier Unit of Measure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ENERGY_CARRIER_SUMMATION_FORMAT,   0x030A, "Energy Carrier Summation Formatting" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ENERGY_CARRIER_DEMAND_FORMAT,      0x030B, "Energy Carrier Demand Formatting" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_TEMPERATURE_UNIT_OF_MEASURE,       0x030C, "Temperature Unit of Measure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_TEMPERATURE_FORMATTING,            0x030D, "Temperature Formatting" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_MODULE_SERIAL_NUMBER,              0x030E, "Module Serial Number" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_OPERATING_TARIFF_LABEL_DELIVERED,  0x030F, "Operating Tariff Label Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_OPERATING_TARIFF_LABEL_RECEIVED,   0x0310, "Operating Tariff Label Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUSTOMER_ID_NUMBER,                0x0311, "Customer ID Number" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ALT_UNIT_OF_MEASURE,               0x0312, "Alternative Unit of Measure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ALT_DEMAND_FORMATTING,             0x0313, "Alternative Demand Formatting" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ALT_CON_FORMATTING,                0x0314, "Alternative Consumption Formatting" ) \
/* Historical Consumption Attribute */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_INSTANT_DEMAND,                    0x0400, "Instantaneous Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_DAY_CON_DEL,                   0x0401, "Current Day Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_DAY_CON_RECV,                  0x0402, "Current Day Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_CON_DEL,                  0x0403, "Previous Day Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_CON_RECV,                 0x0404, "Previous Day Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_PAR_PROF_INT_START_DEL,    0x0405, "Current Partial Profile Interval Start Time Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_PAR_PROF_INT_START_RECV,   0x0406, "Current Partial Profile Interval Start Time Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_PAR_PROF_INT_VALUE_DEL,    0x0407, "Current Partial Profile Interval Value Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_PAR_PROF_INT_VALUE_RECV,   0x0408, "Current Partial Profile Interval Value Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_DAY_MAX_PRESSURE,          0x0409, "Current Day Max Pressure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_DAY_MIN_PRESSURE,          0x040A, "Current Day Min Pressure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREVIOUS_DAY_MAX_PRESSURE,         0x040B, "Previous Day Max Pressure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREVIOUS_DAY_MIN_PRESSURE,         0x040C, "Previous Day Min Pressure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_DAY_MAX_DEMAND,            0x040D, "Current Day Max Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREVIOUS_DAY_MAX_DEMAND,           0x040E, "Previous Day Max Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_MONTH_MAX_DEMAND,          0x040F, "Current Month Max Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_YEAR_MAX_DEMAND,           0x0410, "Current Year Max Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_DAY_MAX_ENERGY_CARR_DEM,   0x0411, "Current Day Max Energy Carrier Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREVIOUS_DAY_MAX_ENERGY_CARR_DEM,  0x0412, "Previous Day Max Energy Carrier Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_MONTH_MAX_ENERGY_CARR_DEM, 0x0413, "Current Month Max Energy Carrier Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_MONTH_MIN_ENERGY_CARR_DEM, 0x0414, "Current Month Min Energy Carrier Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_YEAR_MAX_ENERGY_CARR_DEM,  0x0415, "Current Year Max Energy Carrier Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_YEAR_MIN_ENERGY_CARR_DEM,  0x0416, "Current Year Min Energy Carrier Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_2_DAY_CON_DEL,                0x0420, "Previous Day 2 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_2_DAY_CON_RECV,               0x0421, "Previous Day 2 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_3_DAY_CON_DEL,                0x0422, "Previous Day 3 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_3_DAY_CON_RECV,               0x0423, "Previous Day 3 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_4_DAY_CON_DEL,                0x0424, "Previous Day 4 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_4_DAY_CON_RECV,               0x0425, "Previous Day 4 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_5_DAY_CON_DEL,                0x0426, "Previous Day 5 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_5_DAY_CON_RECV,               0x0427, "Previous Day 5 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_6_DAY_CON_DEL,                0x0428, "Previous Day 6 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_6_DAY_CON_RECV,               0x0429, "Previous Day 6 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_7_DAY_CON_DEL,                0x042A, "Previous Day 7 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_7_DAY_CON_RECV,               0x042B, "Previous Day 7 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_8_DAY_CON_DEL,                0x042C, "Previous Day 8 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_8_DAY_CON_RECV,               0x042D, "Previous Day 8 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_WEEK_CON_DEL,                  0x0430, "Current Week Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_WEEK_CON_RECV,                 0x0431, "Current Week Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_CON_DEL,                 0x0432, "Previous Week Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_CON_RECV,                0x0433, "Previous Week Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_2_CON_DEL,               0x0434, "Previous Week 2 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_2_CON_RECV,              0x0435, "Previous Week 2 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_3_CON_DEL,               0x0436, "Previous Week 3 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_3_CON_RECV,              0x0437, "Previous Week 3 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_4_CON_DEL,               0x0438, "Previous Week 4 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_4_CON_RECV,              0x0439, "Previous Week 4 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_5_CON_DEL,               0x043A, "Previous Week 5 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_5_CON_RECV,              0x043B, "Previous Week 5 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MONTH_CON_DEL,                 0x0440, "Current Month Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MONTH_CON_RECV,                0x0441, "Current Month Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_CON_DEL,                0x0442, "Previous Month Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_CON_RECV,               0x0443, "Previous Month Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_2_CON_DEL,              0x0444, "Previous Month 2 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_2_CON_RECV,             0x0445, "Previous Month 2 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_3_CON_DEL,              0x0446, "Previous Month 3 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_3_CON_RECV,             0x0447, "Previous Month 3 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_4_CON_DEL,              0x0448, "Previous Month 4 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_4_CON_RECV,             0x0449, "Previous Month 4 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_5_CON_DEL,              0x044A, "Previous Month 5 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_5_CON_RECV,             0x044B, "Previous Month 5 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_6_CON_DEL,              0x044C, "Previous Month 6 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_6_CON_RECV,             0x044D, "Previous Month 6 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_7_CON_DEL,              0x044E, "Previous Month 7 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_7_CON_RECV,             0x044F, "Previous Month 7 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_8_CON_DEL,              0x0450, "Previous Month 8 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_8_CON_RECV,             0x0451, "Previous Month 8 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_9_CON_DEL,              0x0452, "Previous Month 9 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_9_CON_RECV,             0x0453, "Previous Month 9 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_10_CON_DEL,             0x0454, "Previous Month 10 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_10_CON_RECV,            0x0455, "Previous Month 10 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_11_CON_DEL,             0x0456, "Previous Month 11 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_11_CON_RECV,            0x0457, "Previous Month 11 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_12_CON_DEL,             0x0458, "Previous Month 12 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_12_CON_RECV,            0x0459, "Previous Month 12 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_13_CON_DEL,             0x045A, "Previous Month 13 Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_13_CON_RECV,            0x045B, "Previous Month 13 Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_HISTORICAL_FREEZE_TIME,            0x045C, "Historical Freeze Time" ) \
/* Load Profile Configuration */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_MAX_NUMBER_OF_PERIODS_DELIVERED,   0x0500, "Max Number of Periods Delivered" ) \
/* Supply Limit Attributes */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_DEMAND_DELIVERED,          0x0600, "Current Demand Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DEMAND_LIMIT,                      0x0601, "Demand Limit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DEMAND_INTEGRATION_PERIOD,         0x0602, "Demand Integration Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_NUMBER_OF_DEMAND_SUBINTERVALS,     0x0603, "Number of Demand Subintervals" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_DEMAND_LIMIT_ARM_DURATION,         0x0604, "Demand Limit Arm Duration" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_LOAD_LIMIT_SUPPLY_STATE,           0x0605, "Load Limit Supply State" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_LOAD_LIMIT_COUNTER,                0x0606, "Load Limit Counter" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_SUPPLY_TAMPER_STATE,               0x0607, "Supply Tamper State" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_SUPPLY_DEPLETION_STATE,            0x0608, "Supply Depletion State" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_SUPPLY_UNCONTROLLED_FLOW_STATE,    0x0609, "Supply Uncontrolled Flow State" ) \
/* Block Information Attribute Set (Delivered) */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_1_SUM_DEL,       0x0700, "Current No Tier Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_2_SUM_DEL,       0x0701, "Current No Tier Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_3_SUM_DEL,       0x0702, "Current No Tier Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_4_SUM_DEL,       0x0703, "Current No Tier Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_5_SUM_DEL,       0x0704, "Current No Tier Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_6_SUM_DEL,       0x0705, "Current No Tier Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_7_SUM_DEL,       0x0706, "Current No Tier Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_8_SUM_DEL,       0x0707, "Current No Tier Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_9_SUM_DEL,       0x0708, "Current No Tier Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_10_SUM_DEL,      0x0709, "Current No Tier Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_11_SUM_DEL,      0x070A, "Current No Tier Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_12_SUM_DEL,      0x070B, "Current No Tier Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_13_SUM_DEL,      0x070C, "Current No Tier Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_14_SUM_DEL,      0x070D, "Current No Tier Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_15_SUM_DEL,      0x070E, "Current No Tier Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_16_SUM_DEL,      0x070F, "Current No Tier Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_1_SUM_DEL,        0x0710, "Current Tier 1 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_2_SUM_DEL,        0x0711, "Current Tier 1 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_3_SUM_DEL,        0x0712, "Current Tier 1 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_4_SUM_DEL,        0x0713, "Current Tier 1 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_5_SUM_DEL,        0x0714, "Current Tier 1 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_6_SUM_DEL,        0x0715, "Current Tier 1 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_7_SUM_DEL,        0x0716, "Current Tier 1 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_8_SUM_DEL,        0x0717, "Current Tier 1 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_9_SUM_DEL,        0x0718, "Current Tier 1 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_10_SUM_DEL,       0x0719, "Current Tier 1 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_11_SUM_DEL,       0x071A, "Current Tier 1 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_12_SUM_DEL,       0x071B, "Current Tier 1 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_13_SUM_DEL,       0x071C, "Current Tier 1 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_14_SUM_DEL,       0x071D, "Current Tier 1 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_15_SUM_DEL,       0x071E, "Current Tier 1 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_16_SUM_DEL,       0x071F, "Current Tier 1 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_1_SUM_DEL,        0x0720, "Current Tier 2 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_2_SUM_DEL,        0x0721, "Current Tier 2 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_3_SUM_DEL,        0x0722, "Current Tier 2 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_4_SUM_DEL,        0x0723, "Current Tier 2 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_5_SUM_DEL,        0x0724, "Current Tier 2 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_6_SUM_DEL,        0x0725, "Current Tier 2 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_7_SUM_DEL,        0x0726, "Current Tier 2 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_8_SUM_DEL,        0x0727, "Current Tier 2 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_9_SUM_DEL,        0x0728, "Current Tier 2 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_10_SUM_DEL,       0x0729, "Current Tier 2 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_11_SUM_DEL,       0x072A, "Current Tier 2 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_12_SUM_DEL,       0x072B, "Current Tier 2 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_13_SUM_DEL,       0x072C, "Current Tier 2 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_14_SUM_DEL,       0x072D, "Current Tier 2 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_15_SUM_DEL,       0x072E, "Current Tier 2 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_16_SUM_DEL,       0x072F, "Current Tier 2 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_1_SUM_DEL,        0x0730, "Current Tier 3 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_2_SUM_DEL,        0x0731, "Current Tier 3 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_3_SUM_DEL,        0x0732, "Current Tier 3 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_4_SUM_DEL,        0x0733, "Current Tier 3 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_5_SUM_DEL,        0x0734, "Current Tier 3 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_6_SUM_DEL,        0x0735, "Current Tier 3 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_7_SUM_DEL,        0x0736, "Current Tier 3 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_8_SUM_DEL,        0x0737, "Current Tier 3 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_9_SUM_DEL,        0x0738, "Current Tier 3 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_10_SUM_DEL,       0x0739, "Current Tier 3 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_11_SUM_DEL,       0x073A, "Current Tier 3 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_12_SUM_DEL,       0x073B, "Current Tier 3 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_13_SUM_DEL,       0x073C, "Current Tier 3 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_14_SUM_DEL,       0x073D, "Current Tier 3 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_15_SUM_DEL,       0x073E, "Current Tier 3 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_16_SUM_DEL,       0x073F, "Current Tier 3 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_1_SUM_DEL,        0x0740, "Current Tier 4 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_2_SUM_DEL,        0x0741, "Current Tier 4 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_3_SUM_DEL,        0x0742, "Current Tier 4 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_4_SUM_DEL,        0x0743, "Current Tier 4 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_5_SUM_DEL,        0x0744, "Current Tier 4 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_6_SUM_DEL,        0x0745, "Current Tier 4 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_7_SUM_DEL,        0x0746, "Current Tier 4 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_8_SUM_DEL,        0x0747, "Current Tier 4 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_9_SUM_DEL,        0x0748, "Current Tier 4 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_10_SUM_DEL,       0x0749, "Current Tier 4 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_11_SUM_DEL,       0x074A, "Current Tier 4 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_12_SUM_DEL,       0x074B, "Current Tier 4 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_13_SUM_DEL,       0x074C, "Current Tier 4 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_14_SUM_DEL,       0x074D, "Current Tier 4 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_15_SUM_DEL,       0x074E, "Current Tier 4 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_16_SUM_DEL,       0x074F, "Current Tier 4 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_1_SUM_DEL,        0x0750, "Current Tier 5 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_2_SUM_DEL,        0x0751, "Current Tier 5 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_3_SUM_DEL,        0x0752, "Current Tier 5 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_4_SUM_DEL,        0x0753, "Current Tier 5 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_5_SUM_DEL,        0x0754, "Current Tier 5 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_6_SUM_DEL,        0x0755, "Current Tier 5 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_7_SUM_DEL,        0x0756, "Current Tier 5 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_8_SUM_DEL,        0x0757, "Current Tier 5 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_9_SUM_DEL,        0x0758, "Current Tier 5 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_10_SUM_DEL,       0x0759, "Current Tier 5 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_11_SUM_DEL,       0x075A, "Current Tier 5 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_12_SUM_DEL,       0x075B, "Current Tier 5 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_13_SUM_DEL,       0x075C, "Current Tier 5 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_14_SUM_DEL,       0x075D, "Current Tier 5 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_15_SUM_DEL,       0x075E, "Current Tier 5 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_16_SUM_DEL,       0x075F, "Current Tier 5 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_1_SUM_DEL,        0x0760, "Current Tier 6 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_2_SUM_DEL,        0x0761, "Current Tier 6 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_3_SUM_DEL,        0x0762, "Current Tier 6 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_4_SUM_DEL,        0x0763, "Current Tier 6 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_5_SUM_DEL,        0x0764, "Current Tier 6 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_6_SUM_DEL,        0x0765, "Current Tier 6 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_7_SUM_DEL,        0x0766, "Current Tier 6 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_8_SUM_DEL,        0x0767, "Current Tier 6 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_9_SUM_DEL,        0x0768, "Current Tier 6 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_10_SUM_DEL,       0x0769, "Current Tier 6 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_11_SUM_DEL,       0x076A, "Current Tier 6 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_12_SUM_DEL,       0x076B, "Current Tier 6 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_13_SUM_DEL,       0x076C, "Current Tier 6 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_14_SUM_DEL,       0x076D, "Current Tier 6 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_15_SUM_DEL,       0x076E, "Current Tier 6 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_16_SUM_DEL,       0x076F, "Current Tier 6 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_1_SUM_DEL,        0x0770, "Current Tier 7 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_2_SUM_DEL,        0x0771, "Current Tier 7 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_3_SUM_DEL,        0x0772, "Current Tier 7 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_4_SUM_DEL,        0x0773, "Current Tier 7 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_5_SUM_DEL,        0x0774, "Current Tier 7 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_6_SUM_DEL,        0x0775, "Current Tier 7 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_7_SUM_DEL,        0x0776, "Current Tier 7 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_8_SUM_DEL,        0x0777, "Current Tier 7 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_9_SUM_DEL,        0x0778, "Current Tier 7 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_10_SUM_DEL,       0x0779, "Current Tier 7 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_11_SUM_DEL,       0x077A, "Current Tier 7 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_12_SUM_DEL,       0x077B, "Current Tier 7 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_13_SUM_DEL,       0x077C, "Current Tier 7 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_14_SUM_DEL,       0x077D, "Current Tier 7 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_15_SUM_DEL,       0x077E, "Current Tier 7 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_16_SUM_DEL,       0x077F, "Current Tier 7 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_1_SUM_DEL,        0x0780, "Current Tier 8 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_2_SUM_DEL,        0x0781, "Current Tier 8 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_3_SUM_DEL,        0x0782, "Current Tier 8 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_4_SUM_DEL,        0x0783, "Current Tier 8 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_5_SUM_DEL,        0x0784, "Current Tier 8 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_6_SUM_DEL,        0x0785, "Current Tier 8 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_7_SUM_DEL,        0x0786, "Current Tier 8 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_8_SUM_DEL,        0x0787, "Current Tier 8 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_9_SUM_DEL,        0x0788, "Current Tier 8 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_10_SUM_DEL,       0x0789, "Current Tier 8 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_11_SUM_DEL,       0x078A, "Current Tier 8 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_12_SUM_DEL,       0x078B, "Current Tier 8 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_13_SUM_DEL,       0x078C, "Current Tier 8 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_14_SUM_DEL,       0x078D, "Current Tier 8 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_15_SUM_DEL,       0x078E, "Current Tier 8 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_16_SUM_DEL,       0x078F, "Current Tier 8 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_1_SUM_DEL,        0x0790, "Current Tier 9 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_2_SUM_DEL,        0x0791, "Current Tier 9 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_3_SUM_DEL,        0x0792, "Current Tier 9 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_4_SUM_DEL,        0x0793, "Current Tier 9 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_5_SUM_DEL,        0x0794, "Current Tier 9 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_6_SUM_DEL,        0x0795, "Current Tier 9 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_7_SUM_DEL,        0x0796, "Current Tier 9 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_8_SUM_DEL,        0x0797, "Current Tier 9 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_9_SUM_DEL,        0x0798, "Current Tier 9 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_10_SUM_DEL,       0x0799, "Current Tier 9 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_11_SUM_DEL,       0x079A, "Current Tier 9 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_12_SUM_DEL,       0x079B, "Current Tier 9 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_13_SUM_DEL,       0x079C, "Current Tier 9 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_14_SUM_DEL,       0x079D, "Current Tier 9 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_15_SUM_DEL,       0x079E, "Current Tier 9 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_16_SUM_DEL,       0x079F, "Current Tier 9 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_1_SUM_DEL,       0x07A0, "Current Tier 10 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_2_SUM_DEL,       0x07A1, "Current Tier 10 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_3_SUM_DEL,       0x07A2, "Current Tier 10 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_4_SUM_DEL,       0x07A3, "Current Tier 10 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_5_SUM_DEL,       0x07A4, "Current Tier 10 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_6_SUM_DEL,       0x07A5, "Current Tier 10 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_7_SUM_DEL,       0x07A6, "Current Tier 10 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_8_SUM_DEL,       0x07A7, "Current Tier 10 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_9_SUM_DEL,       0x07A8, "Current Tier 10 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_10_SUM_DEL,      0x07A9, "Current Tier 10 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_11_SUM_DEL,      0x07AA, "Current Tier 10 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_12_SUM_DEL,      0x07AB, "Current Tier 10 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_13_SUM_DEL,      0x07AC, "Current Tier 10 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_14_SUM_DEL,      0x07AD, "Current Tier 10 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_15_SUM_DEL,      0x07AE, "Current Tier 10 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_16_SUM_DEL,      0x07AF, "Current Tier 10 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_1_SUM_DEL,       0x07B0, "Current Tier 11 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_2_SUM_DEL,       0x07B1, "Current Tier 11 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_3_SUM_DEL,       0x07B2, "Current Tier 11 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_4_SUM_DEL,       0x07B3, "Current Tier 11 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_5_SUM_DEL,       0x07B4, "Current Tier 11 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_6_SUM_DEL,       0x07B5, "Current Tier 11 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_7_SUM_DEL,       0x07B6, "Current Tier 11 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_8_SUM_DEL,       0x07B7, "Current Tier 11 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_9_SUM_DEL,       0x07B8, "Current Tier 11 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_10_SUM_DEL,      0x07B9, "Current Tier 11 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_11_SUM_DEL,      0x07BA, "Current Tier 11 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_12_SUM_DEL,      0x07BB, "Current Tier 11 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_13_SUM_DEL,      0x07BC, "Current Tier 11 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_14_SUM_DEL,      0x07BD, "Current Tier 11 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_15_SUM_DEL,      0x07BE, "Current Tier 11 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_16_SUM_DEL,      0x07BF, "Current Tier 11 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_1_SUM_DEL,       0x07C0, "Current Tier 12 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_2_SUM_DEL,       0x07C1, "Current Tier 12 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_3_SUM_DEL,       0x07C2, "Current Tier 12 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_4_SUM_DEL,       0x07C3, "Current Tier 12 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_5_SUM_DEL,       0x07C4, "Current Tier 12 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_6_SUM_DEL,       0x07C5, "Current Tier 12 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_7_SUM_DEL,       0x07C6, "Current Tier 12 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_8_SUM_DEL,       0x07C7, "Current Tier 12 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_9_SUM_DEL,       0x07C8, "Current Tier 12 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_10_SUM_DEL,      0x07C9, "Current Tier 12 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_11_SUM_DEL,      0x07CA, "Current Tier 12 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_12_SUM_DEL,      0x07CB, "Current Tier 12 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_13_SUM_DEL,      0x07CC, "Current Tier 12 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_14_SUM_DEL,      0x07CD, "Current Tier 12 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_15_SUM_DEL,      0x07CE, "Current Tier 12 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_16_SUM_DEL,      0x07CF, "Current Tier 12 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_1_SUM_DEL,       0x07D0, "Current Tier 13 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_2_SUM_DEL,       0x07D1, "Current Tier 13 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_3_SUM_DEL,       0x07D2, "Current Tier 13 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_4_SUM_DEL,       0x07D3, "Current Tier 13 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_5_SUM_DEL,       0x07D4, "Current Tier 13 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_6_SUM_DEL,       0x07D5, "Current Tier 13 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_7_SUM_DEL,       0x07D6, "Current Tier 13 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_8_SUM_DEL,       0x07D7, "Current Tier 13 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_9_SUM_DEL,       0x07D8, "Current Tier 13 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_10_SUM_DEL,      0x07D9, "Current Tier 13 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_11_SUM_DEL,      0x07DA, "Current Tier 13 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_12_SUM_DEL,      0x07DB, "Current Tier 13 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_13_SUM_DEL,      0x07DC, "Current Tier 13 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_14_SUM_DEL,      0x07DD, "Current Tier 13 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_15_SUM_DEL,      0x07DE, "Current Tier 13 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_16_SUM_DEL,      0x07DF, "Current Tier 13 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_1_SUM_DEL,       0x07E0, "Current Tier 14 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_2_SUM_DEL,       0x07E1, "Current Tier 14 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_3_SUM_DEL,       0x07E2, "Current Tier 14 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_4_SUM_DEL,       0x07E3, "Current Tier 14 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_5_SUM_DEL,       0x07E4, "Current Tier 14 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_6_SUM_DEL,       0x07E5, "Current Tier 14 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_7_SUM_DEL,       0x07E6, "Current Tier 14 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_8_SUM_DEL,       0x07E7, "Current Tier 14 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_9_SUM_DEL,       0x07E8, "Current Tier 14 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_10_SUM_DEL,      0x07E9, "Current Tier 14 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_11_SUM_DEL,      0x07EA, "Current Tier 14 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_12_SUM_DEL,      0x07EB, "Current Tier 14 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_13_SUM_DEL,      0x07EC, "Current Tier 14 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_14_SUM_DEL,      0x07ED, "Current Tier 14 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_15_SUM_DEL,      0x07EE, "Current Tier 14 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_16_SUM_DEL,      0x07EF, "Current Tier 14 Block 16 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_1_SUM_DEL,       0x07F0, "Current Tier 15 Block 1 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_2_SUM_DEL,       0x07F1, "Current Tier 15 Block 2 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_3_SUM_DEL,       0x07F2, "Current Tier 15 Block 3 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_4_SUM_DEL,       0x07F3, "Current Tier 15 Block 4 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_5_SUM_DEL,       0x07F4, "Current Tier 15 Block 5 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_6_SUM_DEL,       0x07F5, "Current Tier 15 Block 6 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_7_SUM_DEL,       0x07F6, "Current Tier 15 Block 7 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_8_SUM_DEL,       0x07F7, "Current Tier 15 Block 8 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_9_SUM_DEL,       0x07F8, "Current Tier 15 Block 9 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_10_SUM_DEL,      0x07F9, "Current Tier 15 Block 10 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_11_SUM_DEL,      0x07FA, "Current Tier 15 Block 11 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_12_SUM_DEL,      0x07FB, "Current Tier 15 Block 12 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_13_SUM_DEL,      0x07FC, "Current Tier 15 Block 13 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_14_SUM_DEL,      0x07FD, "Current Tier 15 Block 14 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_15_SUM_DEL,      0x07FE, "Current Tier 15 Block 15 Summation Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_16_SUM_DEL,      0x07FF, "Current Tier 15 Block 16 Summation Delivered" ) \
/* Alarms Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_GENERIC_ALARM_MASK,                0x0800, "Generic Alarm Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ELECTRICITY_ALARM_MASK,            0x0801, "Electricity Alarm Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_GENERIC_FLOW_PRESS_ALARM_MASK,     0x0802, "Generic Flow/Pressure Alarm Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_WATER_SPECIFIC_ALARM_MASK,         0x0803, "Water Specific Alarm Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_HEAT_COOLING_SPECIFIC_ALARM_MASK,  0x0804, "Heat and Cooling Specific Alarm Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_GAS_SPECIFIC_ALARM_MASK,           0x0805, "Gas Specific Alarm Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_EXTENDED_GENERIC_ALARM_MASK,       0x0806, "Extended Generic Alarm Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_MANUFACTURER_ALARM_MASK,           0x0807, "Manufacturer Alarm Mask" ) \
/* Block Information Attribute Set (Received) */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_1_SUM_RECV,      0x0900, "Current No Tier Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_2_SUM_RECV,      0x0901, "Current No Tier Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_3_SUM_RECV,      0x0902, "Current No Tier Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_4_SUM_RECV,      0x0903, "Current No Tier Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_5_SUM_RECV,      0x0904, "Current No Tier Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_6_SUM_RECV,      0x0905, "Current No Tier Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_7_SUM_RECV,      0x0906, "Current No Tier Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_8_SUM_RECV,      0x0907, "Current No Tier Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_9_SUM_RECV,      0x0908, "Current No Tier Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_10_SUM_RECV,     0x0909, "Current No Tier Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_11_SUM_RECV,     0x090A, "Current No Tier Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_12_SUM_RECV,     0x090B, "Current No Tier Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_13_SUM_RECV,     0x090C, "Current No Tier Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_14_SUM_RECV,     0x090D, "Current No Tier Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_15_SUM_RECV,     0x090E, "Current No Tier Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_NO_TIER_BLOCK_16_SUM_RECV,     0x090F, "Current No Tier Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_1_SUM_RECV,       0x0910, "Current Tier 1 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_2_SUM_RECV,       0x0911, "Current Tier 1 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_3_SUM_RECV,       0x0912, "Current Tier 1 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_4_SUM_RECV,       0x0913, "Current Tier 1 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_5_SUM_RECV,       0x0914, "Current Tier 1 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_6_SUM_RECV,       0x0915, "Current Tier 1 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_7_SUM_RECV,       0x0916, "Current Tier 1 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_8_SUM_RECV,       0x0917, "Current Tier 1 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_9_SUM_RECV,       0x0918, "Current Tier 1 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_10_SUM_RECV,      0x0919, "Current Tier 1 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_11_SUM_RECV,      0x091A, "Current Tier 1 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_12_SUM_RECV,      0x091B, "Current Tier 1 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_13_SUM_RECV,      0x091C, "Current Tier 1 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_14_SUM_RECV,      0x091D, "Current Tier 1 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_15_SUM_RECV,      0x091E, "Current Tier 1 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_1_BLOCK_16_SUM_RECV,      0x091F, "Current Tier 1 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_1_SUM_RECV,       0x0920, "Current Tier 2 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_2_SUM_RECV,       0x0921, "Current Tier 2 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_3_SUM_RECV,       0x0922, "Current Tier 2 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_4_SUM_RECV,       0x0923, "Current Tier 2 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_5_SUM_RECV,       0x0924, "Current Tier 2 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_6_SUM_RECV,       0x0925, "Current Tier 2 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_7_SUM_RECV,       0x0926, "Current Tier 2 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_8_SUM_RECV,       0x0927, "Current Tier 2 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_9_SUM_RECV,       0x0928, "Current Tier 2 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_10_SUM_RECV,      0x0929, "Current Tier 2 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_11_SUM_RECV,      0x092A, "Current Tier 2 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_12_SUM_RECV,      0x092B, "Current Tier 2 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_13_SUM_RECV,      0x092C, "Current Tier 2 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_14_SUM_RECV,      0x092D, "Current Tier 2 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_15_SUM_RECV,      0x092E, "Current Tier 2 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_2_BLOCK_16_SUM_RECV,      0x092F, "Current Tier 2 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_1_SUM_RECV,       0x0930, "Current Tier 3 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_2_SUM_RECV,       0x0931, "Current Tier 3 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_3_SUM_RECV,       0x0932, "Current Tier 3 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_4_SUM_RECV,       0x0933, "Current Tier 3 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_5_SUM_RECV,       0x0934, "Current Tier 3 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_6_SUM_RECV,       0x0935, "Current Tier 3 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_7_SUM_RECV,       0x0936, "Current Tier 3 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_8_SUM_RECV,       0x0937, "Current Tier 3 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_9_SUM_RECV,       0x0938, "Current Tier 3 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_10_SUM_RECV,      0x0939, "Current Tier 3 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_11_SUM_RECV,      0x093A, "Current Tier 3 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_12_SUM_RECV,      0x093B, "Current Tier 3 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_13_SUM_RECV,      0x093C, "Current Tier 3 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_14_SUM_RECV,      0x093D, "Current Tier 3 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_15_SUM_RECV,      0x093E, "Current Tier 3 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_3_BLOCK_16_SUM_RECV,      0x093F, "Current Tier 3 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_1_SUM_RECV,       0x0940, "Current Tier 4 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_2_SUM_RECV,       0x0941, "Current Tier 4 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_3_SUM_RECV,       0x0942, "Current Tier 4 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_4_SUM_RECV,       0x0943, "Current Tier 4 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_5_SUM_RECV,       0x0944, "Current Tier 4 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_6_SUM_RECV,       0x0945, "Current Tier 4 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_7_SUM_RECV,       0x0946, "Current Tier 4 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_8_SUM_RECV,       0x0947, "Current Tier 4 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_9_SUM_RECV,       0x0948, "Current Tier 4 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_10_SUM_RECV,      0x0949, "Current Tier 4 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_11_SUM_RECV,      0x094A, "Current Tier 4 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_12_SUM_RECV,      0x094B, "Current Tier 4 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_13_SUM_RECV,      0x094C, "Current Tier 4 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_14_SUM_RECV,      0x094D, "Current Tier 4 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_15_SUM_RECV,      0x094E, "Current Tier 4 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_4_BLOCK_16_SUM_RECV,      0x094F, "Current Tier 4 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_1_SUM_RECV,       0x0950, "Current Tier 5 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_2_SUM_RECV,       0x0951, "Current Tier 5 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_3_SUM_RECV,       0x0952, "Current Tier 5 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_4_SUM_RECV,       0x0953, "Current Tier 5 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_5_SUM_RECV,       0x0954, "Current Tier 5 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_6_SUM_RECV,       0x0955, "Current Tier 5 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_7_SUM_RECV,       0x0956, "Current Tier 5 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_8_SUM_RECV,       0x0957, "Current Tier 5 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_9_SUM_RECV,       0x0958, "Current Tier 5 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_10_SUM_RECV,      0x0959, "Current Tier 5 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_11_SUM_RECV,      0x095A, "Current Tier 5 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_12_SUM_RECV,      0x095B, "Current Tier 5 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_13_SUM_RECV,      0x095C, "Current Tier 5 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_14_SUM_RECV,      0x095D, "Current Tier 5 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_15_SUM_RECV,      0x095E, "Current Tier 5 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_5_BLOCK_16_SUM_RECV,      0x095F, "Current Tier 5 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_1_SUM_RECV,       0x0960, "Current Tier 6 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_2_SUM_RECV,       0x0961, "Current Tier 6 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_3_SUM_RECV,       0x0962, "Current Tier 6 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_4_SUM_RECV,       0x0963, "Current Tier 6 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_5_SUM_RECV,       0x0964, "Current Tier 6 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_6_SUM_RECV,       0x0965, "Current Tier 6 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_7_SUM_RECV,       0x0966, "Current Tier 6 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_8_SUM_RECV,       0x0967, "Current Tier 6 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_9_SUM_RECV,       0x0968, "Current Tier 6 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_10_SUM_RECV,      0x0969, "Current Tier 6 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_11_SUM_RECV,      0x096A, "Current Tier 6 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_12_SUM_RECV,      0x096B, "Current Tier 6 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_13_SUM_RECV,      0x096C, "Current Tier 6 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_14_SUM_RECV,      0x096D, "Current Tier 6 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_15_SUM_RECV,      0x096E, "Current Tier 6 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_6_BLOCK_16_SUM_RECV,      0x096F, "Current Tier 6 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_1_SUM_RECV,       0x0970, "Current Tier 7 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_2_SUM_RECV,       0x0971, "Current Tier 7 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_3_SUM_RECV,       0x0972, "Current Tier 7 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_4_SUM_RECV,       0x0973, "Current Tier 7 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_5_SUM_RECV,       0x0974, "Current Tier 7 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_6_SUM_RECV,       0x0975, "Current Tier 7 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_7_SUM_RECV,       0x0976, "Current Tier 7 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_8_SUM_RECV,       0x0977, "Current Tier 7 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_9_SUM_RECV,       0x0978, "Current Tier 7 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_10_SUM_RECV,      0x0979, "Current Tier 7 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_11_SUM_RECV,      0x097A, "Current Tier 7 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_12_SUM_RECV,      0x097B, "Current Tier 7 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_13_SUM_RECV,      0x097C, "Current Tier 7 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_14_SUM_RECV,      0x097D, "Current Tier 7 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_15_SUM_RECV,      0x097E, "Current Tier 7 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_7_BLOCK_16_SUM_RECV,      0x097F, "Current Tier 7 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_1_SUM_RECV,       0x0980, "Current Tier 8 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_2_SUM_RECV,       0x0981, "Current Tier 8 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_3_SUM_RECV,       0x0982, "Current Tier 8 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_4_SUM_RECV,       0x0983, "Current Tier 8 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_5_SUM_RECV,       0x0984, "Current Tier 8 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_6_SUM_RECV,       0x0985, "Current Tier 8 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_7_SUM_RECV,       0x0986, "Current Tier 8 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_8_SUM_RECV,       0x0987, "Current Tier 8 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_9_SUM_RECV,       0x0988, "Current Tier 8 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_10_SUM_RECV,      0x0989, "Current Tier 8 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_11_SUM_RECV,      0x098A, "Current Tier 8 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_12_SUM_RECV,      0x098B, "Current Tier 8 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_13_SUM_RECV,      0x098C, "Current Tier 8 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_14_SUM_RECV,      0x098D, "Current Tier 8 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_15_SUM_RECV,      0x098E, "Current Tier 8 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_8_BLOCK_16_SUM_RECV,      0x098F, "Current Tier 8 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_1_SUM_RECV,       0x0990, "Current Tier 9 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_2_SUM_RECV,       0x0991, "Current Tier 9 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_3_SUM_RECV,       0x0992, "Current Tier 9 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_4_SUM_RECV,       0x0993, "Current Tier 9 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_5_SUM_RECV,       0x0994, "Current Tier 9 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_6_SUM_RECV,       0x0995, "Current Tier 9 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_7_SUM_RECV,       0x0996, "Current Tier 9 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_8_SUM_RECV,       0x0997, "Current Tier 9 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_9_SUM_RECV,       0x0998, "Current Tier 9 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_10_SUM_RECV,      0x0999, "Current Tier 9 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_11_SUM_RECV,      0x099A, "Current Tier 9 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_12_SUM_RECV,      0x099B, "Current Tier 9 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_13_SUM_RECV,      0x099C, "Current Tier 9 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_14_SUM_RECV,      0x099D, "Current Tier 9 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_15_SUM_RECV,      0x099E, "Current Tier 9 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_9_BLOCK_16_SUM_RECV,      0x099F, "Current Tier 9 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_1_SUM_RECV,      0x09A0, "Current Tier 10 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_2_SUM_RECV,      0x09A1, "Current Tier 10 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_3_SUM_RECV,      0x09A2, "Current Tier 10 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_4_SUM_RECV,      0x09A3, "Current Tier 10 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_5_SUM_RECV,      0x09A4, "Current Tier 10 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_6_SUM_RECV,      0x09A5, "Current Tier 10 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_7_SUM_RECV,      0x09A6, "Current Tier 10 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_8_SUM_RECV,      0x09A7, "Current Tier 10 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_9_SUM_RECV,      0x09A8, "Current Tier 10 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_10_SUM_RECV,     0x09A9, "Current Tier 10 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_11_SUM_RECV,     0x09AA, "Current Tier 10 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_12_SUM_RECV,     0x09AB, "Current Tier 10 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_13_SUM_RECV,     0x09AC, "Current Tier 10 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_14_SUM_RECV,     0x09AD, "Current Tier 10 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_15_SUM_RECV,     0x09AE, "Current Tier 10 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_10_BLOCK_16_SUM_RECV,     0x09AF, "Current Tier 10 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_1_SUM_RECV,      0x09B0, "Current Tier 11 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_2_SUM_RECV,      0x09B1, "Current Tier 11 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_3_SUM_RECV,      0x09B2, "Current Tier 11 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_4_SUM_RECV,      0x09B3, "Current Tier 11 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_5_SUM_RECV,      0x09B4, "Current Tier 11 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_6_SUM_RECV,      0x09B5, "Current Tier 11 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_7_SUM_RECV,      0x09B6, "Current Tier 11 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_8_SUM_RECV,      0x09B7, "Current Tier 11 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_9_SUM_RECV,      0x09B8, "Current Tier 11 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_10_SUM_RECV,     0x09B9, "Current Tier 11 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_11_SUM_RECV,     0x09BA, "Current Tier 11 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_12_SUM_RECV,     0x09BB, "Current Tier 11 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_13_SUM_RECV,     0x09BC, "Current Tier 11 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_14_SUM_RECV,     0x09BD, "Current Tier 11 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_15_SUM_RECV,     0x09BE, "Current Tier 11 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_11_BLOCK_16_SUM_RECV,     0x09BF, "Current Tier 11 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_1_SUM_RECV,      0x09C0, "Current Tier 12 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_2_SUM_RECV,      0x09C1, "Current Tier 12 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_3_SUM_RECV,      0x09C2, "Current Tier 12 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_4_SUM_RECV,      0x09C3, "Current Tier 12 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_5_SUM_RECV,      0x09C4, "Current Tier 12 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_6_SUM_RECV,      0x09C5, "Current Tier 12 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_7_SUM_RECV,      0x09C6, "Current Tier 12 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_8_SUM_RECV,      0x09C7, "Current Tier 12 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_9_SUM_RECV,      0x09C8, "Current Tier 12 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_10_SUM_RECV,     0x09C9, "Current Tier 12 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_11_SUM_RECV,     0x09CA, "Current Tier 12 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_12_SUM_RECV,     0x09CB, "Current Tier 12 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_13_SUM_RECV,     0x09CC, "Current Tier 12 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_14_SUM_RECV,     0x09CD, "Current Tier 12 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_15_SUM_RECV,     0x09CE, "Current Tier 12 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_12_BLOCK_16_SUM_RECV,     0x09CF, "Current Tier 12 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_1_SUM_RECV,      0x09D0, "Current Tier 13 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_2_SUM_RECV,      0x09D1, "Current Tier 13 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_3_SUM_RECV,      0x09D2, "Current Tier 13 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_4_SUM_RECV,      0x09D3, "Current Tier 13 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_5_SUM_RECV,      0x09D4, "Current Tier 13 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_6_SUM_RECV,      0x09D5, "Current Tier 13 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_7_SUM_RECV,      0x09D6, "Current Tier 13 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_8_SUM_RECV,      0x09D7, "Current Tier 13 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_9_SUM_RECV,      0x09D8, "Current Tier 13 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_10_SUM_RECV,     0x09D9, "Current Tier 13 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_11_SUM_RECV,     0x09DA, "Current Tier 13 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_12_SUM_RECV,     0x09DB, "Current Tier 13 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_13_SUM_RECV,     0x09DC, "Current Tier 13 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_14_SUM_RECV,     0x09DD, "Current Tier 13 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_15_SUM_RECV,     0x09DE, "Current Tier 13 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_13_BLOCK_16_SUM_RECV,     0x09DF, "Current Tier 13 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_1_SUM_RECV,      0x09E0, "Current Tier 14 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_2_SUM_RECV,      0x09E1, "Current Tier 14 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_3_SUM_RECV,      0x09E2, "Current Tier 14 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_4_SUM_RECV,      0x09E3, "Current Tier 14 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_5_SUM_RECV,      0x09E4, "Current Tier 14 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_6_SUM_RECV,      0x09E5, "Current Tier 14 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_7_SUM_RECV,      0x09E6, "Current Tier 14 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_8_SUM_RECV,      0x09E7, "Current Tier 14 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_9_SUM_RECV,      0x09E8, "Current Tier 14 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_10_SUM_RECV,     0x09E9, "Current Tier 14 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_11_SUM_RECV,     0x09EA, "Current Tier 14 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_12_SUM_RECV,     0x09EB, "Current Tier 14 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_13_SUM_RECV,     0x09EC, "Current Tier 14 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_14_SUM_RECV,     0x09ED, "Current Tier 14 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_15_SUM_RECV,     0x09EE, "Current Tier 14 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_14_BLOCK_16_SUM_RECV,     0x09EF, "Current Tier 14 Block 16 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_1_SUM_RECV,      0x09F0, "Current Tier 15 Block 1 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_2_SUM_RECV,      0x09F1, "Current Tier 15 Block 2 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_3_SUM_RECV,      0x09F2, "Current Tier 15 Block 3 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_4_SUM_RECV,      0x09F3, "Current Tier 15 Block 4 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_5_SUM_RECV,      0x09F4, "Current Tier 15 Block 5 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_6_SUM_RECV,      0x09F5, "Current Tier 15 Block 6 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_7_SUM_RECV,      0x09F6, "Current Tier 15 Block 7 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_8_SUM_RECV,      0x09F7, "Current Tier 15 Block 8 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_9_SUM_RECV,      0x09F8, "Current Tier 15 Block 9 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_10_SUM_RECV,     0x09F9, "Current Tier 15 Block 10 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_11_SUM_RECV,     0x09FA, "Current Tier 15 Block 11 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_12_SUM_RECV,     0x09FB, "Current Tier 15 Block 12 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_13_SUM_RECV,     0x09FC, "Current Tier 15 Block 13 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_14_SUM_RECV,     0x09FD, "Current Tier 15 Block 14 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_15_SUM_RECV,     0x09FE, "Current Tier 15 Block 15 Summation Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_TIER_15_BLOCK_16_SUM_RECV,     0x09FF, "Current Tier 15 Block 16 Summation Received" ) \
/* Meter Billing Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_BILL_TO_DATE_DELIVERED,            0x0A00, "Bill to Date Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_BILL_TO_DATE_TIMESTAMP_DEL,        0x0A01, "Bill to Date Time Stamp Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PROJECTED_BILL_DELIVERED,          0x0A02, "Projected Bill Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PROJECTED_BILL_TIME_STAMP_DEL,     0x0A03, "Projected Bill Time Stamp Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_BILL_DELIVERED_TRAILING_DIGIT,     0x0A04, "Bill Delivered Trailing Digit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_BILL_TO_DATE_RECEIVED,             0x0A10, "Bill to Date Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_BILL_TO_DATE_TIMESTAMP_RECEIVED,   0x0A11, "Bill to Date Time Stamp Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PROJECTED_BILL_RECEIVED,           0x0A12, "Projected Bill Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PROJECTED_BILL_TIME_STAMP_RECV,    0x0A13, "Projected Bill Time Stamp Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_BILL_RECEIVED_TRAILING_DIGIT,      0x0A14, "Bill Received Trailing Digit" ) \
/* Supply Control Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PROPOSED_CHANGE_SUPPLY_IMP_TIME,   0x0B00, "Proposed Change Supply Implementation Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PROPOSED_CHANGE_SUPPLY_STATUS,     0x0B01, "Proposed Change Supply Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_UNCONTROLLED_FLOW_THRESHOLD,       0x0B10, "Uncontrolled Flow Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_UNCONTROLLED_FLOW_UNIT_OF_MEAS,    0x0B11, "Uncontrolled Flow Unit of Measure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_UNCONTROLLED_FLOW_MULTIPLIER,      0x0B12, "Uncontrolled Flow Multiplier" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_UNCONTROLLED_FLOW_DIVISOR,         0x0B13, "Uncontrolled Flow Divisor" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_FLOW_STABILISATION_PERIOD,         0x0B14, "Flow Stabilisation Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_FLOW_MEASUREMENT_PERIOD,           0x0B15, "Flow Measurement Period" ) \
/* Alternative Historical Consumption Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_ALTERNATIVE_INSTANT_DEMAND,        0x0C00, "Alternative Instantaneous Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_DAY_ALT_CON_DEL,               0x0C01, "Current Day Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_DAY_ALT_CON_RECV,              0x0C02, "Current Day Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_ALT_CON_DEL,              0x0C03, "Previous Day Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_ALT_CON_RECV,             0x0C04, "Previous Day Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_ALT_PAR_PROF_INT_DEL,      0x0C05, "Current Alternative Partial Profile Interval Start Time Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_ALT_PAR_PROF_INT_RECV,     0x0C06, "Current Alternative Partial Profile Interval Start Time Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_ALT_PAR_PROF_INT_VAL_DEL,  0x0C07, "Current Alternative Partial Profile Interval Value Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_ALT_PAR_PROF_INT_VAL_RECV, 0x0C08, "Current Alternative Partial Profile Interval Value Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_DAY_ALT_MAX_PRESS,         0x0C09, "Current Day Alternative Max Pressure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_DAY_ALT_MIN_PRESS,         0x0C0A, "Current Day Alternative Min Pressure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREVIOUS_DAY_ALT_MAX_PRESS,        0x0C0B, "Previous Day Alternative Max Pressure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREVIOUS_DAY_ALT_MIN_PRESS,        0x0C0C, "Previous Day Alternative Min Pressure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_DAY_ALT_MAX_DEMAND,        0x0C0D, "Current Day Alternative Max Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREVIOUS_DAY_ALT_MAX_DEMAND,       0x0C0E, "Previous Day Alternative Max Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_MONTH_ALT_MAX_DEMAND,      0x0C0F, "Current Month Alternative Max Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CURRENT_YEAR_ALT_MAX_DEMAND,       0x0C10, "Current Year Alternative Max Demand" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_2_ALT_CON_DEL,            0x0C20, "Previous Day 2 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_2_ALT_CON_RECV,           0x0C21, "Previous Day 2 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_3_ALT_CON_DEL,            0x0C22, "Previous Day 3 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_3_ALT_CON_RECV,           0x0C23, "Previous Day 3 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_4_ALT_CON_DEL,            0x0C24, "Previous Day 4 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_4_ALT_CON_RECV,           0x0C25, "Previous Day 4 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_5_ALT_CON_DEL,            0x0C26, "Previous Day 5 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_5_ALT_CON_RECV,           0x0C27, "Previous Day 5 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_6_ALT_CON_DEL,            0x0C28, "Previous Day 6 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_6_ALT_CON_RECV,           0x0C29, "Previous Day 6 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_7_ALT_CON_DEL,            0x0C2A, "Previous Day 7 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_7_ALT_CON_RECV,           0x0C2B, "Previous Day 7 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_8_ALT_CON_DEL,            0x0C2C, "Previous Day 8 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_DAY_8_ALT_CON_RECV,           0x0C2D, "Previous Day 8 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_WEEK_ALT_CON_DEL,              0x0C30, "Current Week Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_WEEK_ALT_CON_RECV,             0x0C31, "Current Week Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_ALT_CON_DEL,             0x0C32, "Previous Week Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_ALT_CON_RECV,            0x0C33, "Previous Week Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_2_ALT_CON_DEL,           0x0C34, "Previous Week 2 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_2_ALT_CON_RECV,          0x0C35, "Previous Week 2 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_3_ALT_CON_DEL,           0x0C36, "Previous Week 3 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_3_ALT_CON_RECV,          0x0C37, "Previous Week 3 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_4_ALT_CON_DEL,           0x0C38, "Previous Week 4 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_4_ALT_CON_RECV,          0x0C39, "Previous Week 4 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_5_ALT_CON_DEL,           0x0C3A, "Previous Week 5 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_WEEK_5_ALT_CON_RECV,          0x0C3B, "Previous Week 5 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MONTH_ALT_CON_DEL,             0x0C40, "Current Month Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CUR_MONTH_ALT_CON_RECV,            0x0C41, "Current Month Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_ALT_CON_DEL,            0x0C42, "Previous Month Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_ALT_CON_RECV,           0x0C43, "Previous Month Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_2_ALT_CON_DEL,          0x0C44, "Previous Month 2 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_2_ALT_CON_RECV,         0x0C45, "Previous Month 2 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_3_ALT_CON_DEL,          0x0C46, "Previous Month 3 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_3_ALT_CON_RECV,         0x0C47, "Previous Month 3 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_4_ALT_CON_DEL,          0x0C48, "Previous Month 4 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_4_ALT_CON_RECV,         0x0C49, "Previous Month 4 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_5_ALT_CON_DEL,          0x0C4A, "Previous Month 5 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_5_ALT_CON_RECV,         0x0C4B, "Previous Month 5 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_6_ALT_CON_DEL,          0x0C4C, "Previous Month 6 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_6_ALT_CON_RECV,         0x0C4D, "Previous Month 6 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_7_ALT_CON_DEL,          0x0C4E, "Previous Month 7 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_7_ALT_CON_RECV,         0x0C4F, "Previous Month 7 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_8_ALT_CON_DEL,          0x0C50, "Previous Month 8 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_8_ALT_CON_RECV,         0x0C51, "Previous Month 8 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_9_ALT_CON_DEL,          0x0C52, "Previous Month 9 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_9_ALT_CON_RECV,         0x0C53, "Previous Month 9 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_10_ALT_CON_DEL,         0x0C54, "Previous Month 10 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_10_ALT_CON_RECV,        0x0C55, "Previous Month 10 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_11_ALT_CON_DEL,         0x0C56, "Previous Month 11 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_11_ALT_CON_RECV,        0x0C57, "Previous Month 11 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_12_ALT_CON_DEL,         0x0C58, "Previous Month 12 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_12_ALT_CON_RECV,        0x0C59, "Previous Month 12 Alternative Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_13_ALT_CON_DEL,         0x0C5A, "Previous Month 13 Alternative Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_PREV_MONTH_13_ALT_CON_RECV,        0x0C5B, "Previous Month 13 Alternative Consumption Received" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_MET,             0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_met_attr_server_names);
VALUE_STRING_ARRAY(zbee_zcl_met_attr_server_names);
static value_string_ext zbee_zcl_met_attr_server_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_met_attr_server_names);

#define zbee_zcl_met_attr_client_names_VALUE_STRING_LIST(XXX) \
/* Notification AttributeSet*/ \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CLNT_FUNC_NOTI_FLAGS,              0x0000, "Functional Notification Flags" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_2,                 0x0001, "Notification Flags 2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_3,                 0x0002, "Notification Flags 3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_4,                 0x0003, "Notification Flags 4" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_5,                 0x0004, "Notification Flags 5" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_6,                 0x0005, "Notification Flags 6" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_7,                 0x0006, "Notification Flags 7" ) \
    XXX(ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_8,                 0x0007, "Notification Flags 8" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_MET_CLNT,        0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_met_attr_client_names);
VALUE_STRING_ARRAY(zbee_zcl_met_attr_client_names);

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
    XXX(ZBEE_ZCL_CMD_ID_MET_CONFIGURE_NOTIFICATION_FLAGS,       0x0A, "Configure Notification Flags" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_GET_NOTIFIED_MESSAGE,               0x0B, "Get Notified Message" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_SUPPLY_STATUS_RESPONSE,             0x0C, "Supply Status Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_MET_START_SAMPLING_RESPONSE,            0x0D, "Start Sampling Response" )

VALUE_STRING_ENUM(zbee_zcl_met_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_met_srv_tx_cmd_names);

#define ZBEE_ZCL_MET_NOTIFICATION_SCHEME_A 0x1
#define ZBEE_ZCL_MET_NOTIFICATION_SCHEME_B 0x2

static const range_string zbee_zcl_met_notification_scheme[] = {
    { 0x0, 0x0,   "No Notification Scheme Defined" },
    { ZBEE_ZCL_MET_NOTIFICATION_SCHEME_A, ZBEE_ZCL_MET_NOTIFICATION_SCHEME_A,   "Predefined Notification Scheme A" },
    { ZBEE_ZCL_MET_NOTIFICATION_SCHEME_B, ZBEE_ZCL_MET_NOTIFICATION_SCHEME_B,   "Predefined Notification Scheme B" },
    { 0x3, 0x80,  "Reserved" },
    { 0x81, 0xFE, "For MSP Requirements" },
    { 0xFF, 0xFF, "Reserved" },
    { 0, 0, NULL }
};

/* Snapshot Schedule Confirmation */
#define zbee_zcl_met_snapshot_schedule_confirmation_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_CONFIRMATION_ID_ACCEPTED, 0x00, "Accepted" )                                 \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_CONFIRMATION_ID_TYPE_NOT_SUPPORTED, 0x01, "Snapshot Type not supported")     \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_CONFIRMATION_ID_CAUSE_NOT_SUPPORTED, 0x02, "Snapshot Cause not supported")   \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_CONFIRMATION_ID_CURRENTLY_NOT_AVAILABLE, 0x03, "Snapshot Cause not supported")   \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_CONFIRMATION_ID_NOT_SUPPORTED_BY_DEVICE, 0x04, "Snapshot Schedules not supported by device")   \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_CONFIRMATION_ID_INSUFFICIENT_SPACE, 0x05, "Insufficient space for snapshot schedule")

VALUE_STRING_ENUM(zbee_zcl_met_snapshot_schedule_confirmation);
VALUE_STRING_ARRAY(zbee_zcl_met_snapshot_schedule_confirmation);

/* Snapshot Schedule Frequency Type*/
#define zbee_zcl_met_snapshot_schedule_frequency_type_VALUE_STRING_LIST(XXX)  \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_FREQUENCY_TYPE_DAY, 0x0, "Day" )           \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_FREQUENCY_TYPE_WEEK, 0x1, "Week" )         \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_FREQUENCY_TYPE_MONTH, 0x2, "Month" )       \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_FREQUENCY_TYPE_RESERVED, 0x3, "Reserved" )

VALUE_STRING_ENUM(zbee_zcl_met_snapshot_schedule_frequency_type);
VALUE_STRING_ARRAY(zbee_zcl_met_snapshot_schedule_frequency_type);

/* Snapshot Schedule Wild-Card Frequency*/
#define zbee_zcl_met_snapshot_schedule_frequency_wild_card_VALUE_STRING_LIST(XXX)   \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_FREQUENCY_WILD_CARD_START_OF, 0x0, "Start of" )              \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_FREQUENCY_WILD_CARD_END_OF,   0x1, "End of" )                \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_FREQUENCY_WILD_CARD_NOT_USED, 0x2, "Wild-card not used" )    \
    XXX(ZBEE_ZCL_SNAPSHOT_SCHEDULE_FREQUENCY_WILD_CARD_RESERVED, 0x3, "Reserved" )

VALUE_STRING_ENUM(zbee_zcl_met_snapshot_schedule_frequency_wild_card);
VALUE_STRING_ARRAY(zbee_zcl_met_snapshot_schedule_frequency_wild_card);

/* Snapshot Payload Type */
#define zbee_zcl_met_snapshot_payload_type_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_SNAPSHOT_PAYLOAD_TYPE_TOU_INFO_SET_DELIVERED_REGISTERS, 0, "TOU Information Set Delivered Registers" )                                 \
    XXX(ZBEE_ZCL_SNAPSHOT_PAYLOAD_TYPE_TOU_INFO_SET_RECEIVED_REGISTERS, 1, "TOU Information Set Received Registers")     \
    XXX(ZBEE_ZCL_SNAPSHOT_PAYLOAD_TYPE_BLOCK_TIER_INFO_SET_DELIVERED, 2, "Block Tier Information Set Delivered")   \
    XXX(ZBEE_ZCL_SNAPSHOT_PAYLOAD_TYPE_BLOCK_TIER_INFO_SET_RECEIVED, 3, "Block Tier Information Set Received")   \
    XXX(ZBEE_ZCL_SNAPSHOT_PAYLOAD_TYPE_TOU_INFO_SET_DELIVERED_NO_BILLING, 4, "TOU Information Set Delivered (No Billing)")   \
    XXX(ZBEE_ZCL_SNAPSHOT_PAYLOAD_TYPE_TOU_INFO_SET_RECEIVED_NO_BILLING, 5, "TOU Information Set Received (No Billing)")     \
    XXX(ZBEE_ZCL_SNAPSHOT_PAYLOAD_TYPE_BLOCK_TIER_INFO_SET_DELIVERED_NO_BILLING, 6, "Block Tier Information Set Delivered (No Billing)")     \
    XXX(ZBEE_ZCL_SNAPSHOT_PAYLOAD_TYPE_BLOCK_TIER_INFO_SET_RECEIVED_NO_BILLING, 7, "Block Tier Information Set Received (No Billing)")     \
    XXX(ZBEE_ZCL_SNAPSHOT_PAYLOAD_TYPE_DATA_UNAVAILABLE, 128, "Data Unavailable")

VALUE_STRING_ENUM(zbee_zcl_met_snapshot_payload_type);
VALUE_STRING_ARRAY(zbee_zcl_met_snapshot_payload_type);

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
#define ZBEE_ZCL_FUNC_NOTI_FLAG_NEW_SUB_GHZ_CHANNEL_MASKS_AVAILABLE             0x01000000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_ENERGY_SCAN_PENDING                             0x02000000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_CHANNEL_CHANGE_PENDING                          0x04000000
#define ZBEE_ZCL_FUNC_NOTI_FLAG_RESERVED_2                                      0xF8000000

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
static void dissect_zcl_met_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

/* Command Dissector Helpers */
static void dissect_zcl_met_get_profile                     (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_request_mirror_rsp              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_mirror_removed                  (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_request_fast_poll_mode          (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_schedule_snapshot               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_take_snapshot                   (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_get_snapshot                    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_start_sampling                  (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_get_sampled_data                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_mirror_report_attribute_response(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_reset_load_limit_counter        (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_change_supply                   (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_local_change_supply             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_set_supply_status               (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_set_uncontrolled_flow_threshold (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_get_profile_response            (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_request_fast_poll_mode_response (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_schedule_snapshot_response      (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_take_snapshot_response          (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_publish_snapshot                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_get_sampled_data_rsp            (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_configure_mirror                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_configure_notification_scheme   (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_configure_notification_flags    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_get_notified_msg                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_supply_status_response          (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_start_sampling_response         (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_met_notification_flags              (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 noti_flags_number);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_met = -1;

static int hf_zbee_zcl_met_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_met_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_met_attr_server_id = -1;
static int hf_zbee_zcl_met_attr_client_id = -1;
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
static int hf_zbee_zcl_met_func_noti_flag_new_sub_ghz_channel_masks_available = -1;
static int hf_zbee_zcl_met_func_noti_flag_energy_scan_pending = -1;
static int hf_zbee_zcl_met_func_noti_flag_channel_change_pending = -1;
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
static int hf_zbee_zcl_met_get_profile_interval_channel = -1;
static int hf_zbee_zcl_met_get_profile_end_time = -1;
static int hf_zbee_zcl_met_get_profile_number_of_periods = -1;
static int hf_zbee_zcl_met_request_mirror_rsp_endpoint_id = -1;
static int hf_zbee_zcl_met_mirror_removed_removed_endpoint_id = -1;
static int hf_zbee_zcl_met_request_fast_poll_mode_fast_poll_update_period = -1;
static int hf_zbee_zcl_met_request_fast_poll_mode_duration = -1;
static int hf_zbee_zcl_met_schedule_snapshot_issuer_event_id = -1;
static int hf_zbee_zcl_met_schedule_snapshot_command_index = -1;
static int hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_schedule_id = -1;
static int hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_start_time = -1;
static int hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_schedule = -1;
static int hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_shapshot_payload_type = -1;
static int hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_cause = -1;
static int hf_zbee_zcl_met_schedule_snapshot_total_number_of_commands = -1;
static int hf_zbee_zcl_met_take_snapshot_snapshot_cause = -1;
static int hf_zbee_zcl_met_get_snapshot_start_time = -1;
static int hf_zbee_zcl_met_get_snapshot_end_time = -1;
static int hf_zbee_zcl_met_get_snapshot_snapshot_offset = -1;
static int hf_zbee_zcl_met_get_snapshot_snapshot_cause = -1;
static int hf_zbee_zcl_met_start_sampling_issuer_event_id = -1;
static int hf_zbee_zcl_met_start_sampling_start_sampling_time = -1;
static int hf_zbee_zcl_met_start_sampling_sample_type = -1;
static int hf_zbee_zcl_met_start_sampling_sample_request_interval = -1;
static int hf_zbee_zcl_met_start_sampling_max_number_of_samples = -1;
static int hf_zbee_zcl_met_get_sampled_data_sample_id = -1;
static int hf_zbee_zcl_met_get_sampled_data_sample_start_time = -1;
static int hf_zbee_zcl_met_get_sampled_data_sample_type = -1;
static int hf_zbee_zcl_met_get_sampled_data_number_of_samples = -1;
static int hf_zbee_zcl_met_start_sampling_response_sample_id = -1;
static int hf_zbee_zcl_met_mirror_report_attribute_response_notification_scheme = -1;
static int hf_zbee_zcl_met_mirror_report_attribute_response_notification_flags_n = -1;
static int hf_zbee_zcl_met_reset_load_limit_counter_provider_id = -1;
static int hf_zbee_zcl_met_reset_load_limit_counter_issuer_event_id = -1;
static int hf_zbee_zcl_met_change_supply_provider_id = -1;
static int hf_zbee_zcl_met_change_supply_issuer_event_id = -1;
static int hf_zbee_zcl_met_change_supply_request_date_time = -1;
static int hf_zbee_zcl_met_change_supply_implementation_date_time = -1;
static int hf_zbee_zcl_met_change_supply_proposed_supply_status = -1;
static int hf_zbee_zcl_met_change_supply_supply_control_bits = -1;
static int hf_zbee_zcl_met_local_change_supply_proposed_supply_status = -1;
static int hf_zbee_zcl_met_set_supply_status_issuer_event_id = -1;
static int hf_zbee_zcl_met_set_supply_status_supply_tamper_state = -1;
static int hf_zbee_zcl_met_set_supply_status_supply_depletion_state = -1;
static int hf_zbee_zcl_met_set_supply_status_supply_uncontrolled_flow_state = -1;
static int hf_zbee_zcl_met_set_supply_status_load_limit_supply_state = -1;
static int hf_zbee_zcl_met_set_uncontrolled_flow_threshold_provider_id = -1;
static int hf_zbee_zcl_met_set_uncontrolled_flow_threshold_issuer_event_id = -1;
static int hf_zbee_zcl_met_set_uncontrolled_flow_threshold_uncontrolled_flow_threshold = -1;
static int hf_zbee_zcl_met_set_uncontrolled_flow_threshold_unit_of_measure = -1;
static int hf_zbee_zcl_met_set_uncontrolled_flow_threshold_multiplier = -1;
static int hf_zbee_zcl_met_set_uncontrolled_flow_threshold_divisor = -1;
static int hf_zbee_zcl_met_set_uncontrolled_flow_threshold_stabilisation_period = -1;
static int hf_zbee_zcl_met_set_uncontrolled_flow_threshold_measurement_period = -1;
static int hf_zbee_zcl_met_get_profile_response_end_time = -1;
static int hf_zbee_zcl_met_get_profile_response_status = -1;
static int hf_zbee_zcl_met_get_profile_response_profile_interval_period = -1;
static int hf_zbee_zcl_met_get_profile_response_number_of_periods_delivered = -1;
static int hf_zbee_zcl_met_get_profile_response_intervals = -1;
static int hf_zbee_zcl_met_request_fast_poll_mode_response_applied_update_period = -1;
static int hf_zbee_zcl_met_request_fast_poll_mode_response_fast_poll_mode_end_time = -1;
static int hf_zbee_zcl_met_schedule_snapshot_response_issuer_event_id = -1;
static int hf_zbee_zcl_met_schedule_snapshot_response_snapshot_schedule_id = -1;
static int hf_zbee_zcl_met_schedule_snapshot_response_snapshot_schedule_confirmation = -1;
static int hf_zbee_zcl_met_take_snapshot_response_snapshot_id = -1;
static int hf_zbee_zcl_met_take_snapshot_response_snapshot_confirmation = -1;
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
static int hf_zbee_zcl_met_configure_notification_scheme_issuer_event_id = -1;
static int hf_zbee_zcl_met_configure_notification_scheme_notification_scheme = -1;
static int hf_zbee_zcl_met_configure_notification_scheme_notification_flag_order = -1;
static int hf_zbee_zcl_met_configure_notification_flags_issuer_event_id = -1;
static int hf_zbee_zcl_met_configure_notification_flags_notification_scheme = -1;
static int hf_zbee_zcl_met_configure_notification_flags_notification_flag_attribute_id = -1;
static int hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_cluster_id = -1;
static int hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_manufacturer_code = -1;
static int hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_no_of_commands = -1;
static int hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_command_identifier = -1;
static int hf_zbee_zcl_met_get_notified_msg_notification_scheme = -1;
static int hf_zbee_zcl_met_get_notified_msg_notification_flag_attribute_id = -1;
static int hf_zbee_zcl_met_get_notified_msg_notification_flags = -1;
static int hf_zbee_zcl_met_supply_status_response_provider_id = -1;
static int hf_zbee_zcl_met_supply_status_response_issuer_event_id = -1;
static int hf_zbee_zcl_met_supply_status_response_implementation_date_time = -1;
static int hf_zbee_zcl_met_supply_status_response_supply_status_after_implementation = -1;
static int hf_zbee_zcl_met_snapshot_cause_general = -1;
static int hf_zbee_zcl_met_snapshot_cause_end_of_billing_period = -1;
static int hf_zbee_zcl_met_snapshot_cause_end_of_block_period = -1;
static int hf_zbee_zcl_met_snapshot_cause_change_of_tariff_information = -1;
static int hf_zbee_zcl_met_snapshot_cause_change_of_price_matrix = -1;
static int hf_zbee_zcl_met_snapshot_cause_change_of_block_thresholds = -1;
static int hf_zbee_zcl_met_snapshot_cause_change_of_cv = -1;
static int hf_zbee_zcl_met_snapshot_cause_change_of_cf = -1;
static int hf_zbee_zcl_met_snapshot_cause_change_of_calendar = -1;
static int hf_zbee_zcl_met_snapshot_cause_critical_peak_pricing = -1;
static int hf_zbee_zcl_met_snapshot_cause_manually_triggered_from_client = -1;
static int hf_zbee_zcl_met_snapshot_cause_end_of_resolve_period = -1;
static int hf_zbee_zcl_met_snapshot_cause_change_of_tenancy = -1;
static int hf_zbee_zcl_met_snapshot_cause_change_of_supplier = -1;
static int hf_zbee_zcl_met_snapshot_cause_change_of_meter_mode = -1;
static int hf_zbee_zcl_met_snapshot_cause_debt_payment = -1;
static int hf_zbee_zcl_met_snapshot_cause_scheduled_snapshot = -1;
static int hf_zbee_zcl_met_snapshot_cause_ota_firmware_download = -1;
static int hf_zbee_zcl_met_snapshot_cause_reserved = -1;
static int hf_zbee_zcl_met_snapshot_schedule_frequency = -1;
static int hf_zbee_zcl_met_snapshot_schedule_frequency_type = -1;
static int hf_zbee_zcl_met_snapshot_schedule_frequency_wild_card = -1;

static int* const zbee_zcl_met_snapshot_schedule_bits[] = {
    &hf_zbee_zcl_met_snapshot_schedule_frequency,
    &hf_zbee_zcl_met_snapshot_schedule_frequency_type,
    &hf_zbee_zcl_met_snapshot_schedule_frequency_wild_card,
    NULL
};

static int* const zbee_zcl_met_func_noti_flags[] = {
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
        &hf_zbee_zcl_met_func_noti_flag_new_sub_ghz_channel_masks_available,
        &hf_zbee_zcl_met_func_noti_flag_energy_scan_pending,
        &hf_zbee_zcl_met_func_noti_flag_channel_change_pending,
        &hf_zbee_zcl_met_func_noti_flag_reserved,
        NULL
};

static int* const zbee_zcl_met_noti_flags_2[] = {
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

static int* const zbee_zcl_met_noti_flags_3[] = {
        &hf_zbee_zcl_met_noti_flag_3_publish_calendar,
        &hf_zbee_zcl_met_noti_flag_3_publish_special_days,
        &hf_zbee_zcl_met_noti_flag_3_publish_seasons,
        &hf_zbee_zcl_met_noti_flag_3_publish_week,
        &hf_zbee_zcl_met_noti_flag_3_publish_day,
        &hf_zbee_zcl_met_noti_flag_3_cancel_calendar,
        &hf_zbee_zcl_met_noti_flag_3_reserved,
        NULL
};

static int* const zbee_zcl_met_noti_flags_4[] = {
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

static int* const zbee_zcl_met_noti_flags_5[] = {
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

static int* const zbee_zcl_met_snapshot_cause_flags[] = {
        &hf_zbee_zcl_met_snapshot_cause_general,
        &hf_zbee_zcl_met_snapshot_cause_end_of_billing_period,
        &hf_zbee_zcl_met_snapshot_cause_end_of_block_period,
        &hf_zbee_zcl_met_snapshot_cause_change_of_tariff_information,
        &hf_zbee_zcl_met_snapshot_cause_change_of_price_matrix,
        &hf_zbee_zcl_met_snapshot_cause_change_of_block_thresholds,
        &hf_zbee_zcl_met_snapshot_cause_change_of_cv,
        &hf_zbee_zcl_met_snapshot_cause_change_of_cf,
        &hf_zbee_zcl_met_snapshot_cause_change_of_calendar,
        &hf_zbee_zcl_met_snapshot_cause_critical_peak_pricing,
        &hf_zbee_zcl_met_snapshot_cause_manually_triggered_from_client,
        &hf_zbee_zcl_met_snapshot_cause_end_of_resolve_period,
        &hf_zbee_zcl_met_snapshot_cause_change_of_tenancy,
        &hf_zbee_zcl_met_snapshot_cause_change_of_supplier,
        &hf_zbee_zcl_met_snapshot_cause_change_of_meter_mode,
        &hf_zbee_zcl_met_snapshot_cause_debt_payment,
        &hf_zbee_zcl_met_snapshot_cause_scheduled_snapshot,
        &hf_zbee_zcl_met_snapshot_cause_ota_firmware_download,
        &hf_zbee_zcl_met_snapshot_cause_reserved,
        NULL
};

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_met = -1;
static gint ett_zbee_zcl_met_func_noti_flags = -1;
static gint ett_zbee_zcl_met_noti_flags_2 = -1;
static gint ett_zbee_zcl_met_noti_flags_3 = -1;
static gint ett_zbee_zcl_met_noti_flags_4 = -1;
static gint ett_zbee_zcl_met_noti_flags_5 = -1;
static gint ett_zbee_zcl_met_snapshot_cause_flags = -1;
static gint ett_zbee_zcl_met_snapshot_schedule = -1;
static gint ett_zbee_zcl_met_schedule_snapshot_response_payload = -1;
static gint ett_zbee_zcl_met_schedule_snapshot_payload = -1;
static gint ett_zbee_zcl_met_mirror_noti_flag = -1;
static gint ett_zbee_zcl_met_bit_field_allocation = -1;

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_met_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    if (client_attr) {
        switch (attr_id) {
            /* applies to all SE clusters */
            case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_MET_CLNT:
                proto_tree_add_item(tree, hf_zbee_zcl_met_attr_reporting_status, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;

            case ZBEE_ZCL_ATTR_ID_MET_CLNT_FUNC_NOTI_FLAGS:
                proto_item_append_text(tree, ", Functional Notification Flags");
                proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_func_noti_flags, ett_zbee_zcl_met_func_noti_flags, zbee_zcl_met_func_noti_flags, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;

            case ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_2:
                proto_item_append_text(tree, ", Notification Flags 2");
                proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_2, ett_zbee_zcl_met_noti_flags_2, zbee_zcl_met_noti_flags_2, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;

            case ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_3:
                proto_item_append_text(tree, ", Notification Flags 3");
                proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_3, ett_zbee_zcl_met_noti_flags_3, zbee_zcl_met_noti_flags_3, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;

            case ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_4:
                proto_item_append_text(tree, ", Notification Flags 4");
                proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_4, ett_zbee_zcl_met_noti_flags_4, zbee_zcl_met_noti_flags_4, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;

            case ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_5:
                proto_item_append_text(tree, ", Notification Flags 5");
                proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_5, ett_zbee_zcl_met_noti_flags_5, zbee_zcl_met_noti_flags_5, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;

            default: /* Catch all */
                dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
                break;
        }
    }
    else {
        switch (attr_id) {
            /* applies to all SE clusters */
            case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_MET:
                proto_tree_add_item(tree, hf_zbee_zcl_met_attr_reporting_status, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;

            default: /* Catch all */
                dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
                break;
        }
    }
} /*dissect_zcl_met_attr_data*/

/**
 *This function manages the Start Sampling Response payload.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void dissect_zcl_met_start_sampling_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Sample ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_start_sampling_response_sample_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_met_start_sampling_response*/

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

                case ZBEE_ZCL_CMD_ID_MET_GET_PROFILE:
                    dissect_zcl_met_get_profile(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_REQUEST_MIRROR_RSP:
                    dissect_zcl_met_request_mirror_rsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_MIRROR_REMOVED:
                    dissect_zcl_met_mirror_removed(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_REQUEST_FAST_POLL_MODE:
                    dissect_zcl_met_request_fast_poll_mode(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_SCHEDULE_SNAPSHOT:
                    dissect_zcl_met_schedule_snapshot(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_TAKE_SNAPSHOT:
                    dissect_zcl_met_take_snapshot(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_GET_SNAPSHOT:
                    dissect_zcl_met_get_snapshot(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_START_SAMPLING:
                    dissect_zcl_met_start_sampling(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_GET_SAMPLED_DATA:
                    dissect_zcl_met_get_sampled_data(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_MIRROR_REPORT_ATTRIBUTE_RESPONSE:
                    dissect_zcl_met_mirror_report_attribute_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_RESET_LOAD_LIMIT_COUNTER:
                    dissect_zcl_met_reset_load_limit_counter(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_CHANGE_SUPPLY:
                    dissect_zcl_met_change_supply(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_LOCAL_CHANGE_SUPPLY:
                    dissect_zcl_met_local_change_supply(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_SET_SUPPLY_STATUS:
                    dissect_zcl_met_set_supply_status(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_SET_UNCONTROLLED_FLOW_THRESHOLD:
                    dissect_zcl_met_set_uncontrolled_flow_threshold(tvb, payload_tree, &offset);
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

                case ZBEE_ZCL_CMD_ID_MET_GET_PROFILE_RESPONSE:
                    dissect_zcl_met_get_profile_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_REQUEST_MIRROR:
                    /* No payload */
                    break;

                case ZBEE_ZCL_CMD_ID_MET_REMOVE_MIRROR:
                    /* No payload */
                    break;

                case ZBEE_ZCL_CMD_ID_MET_REQUEST_FAST_POLL_MODE_RESPONSE:
                    dissect_zcl_met_request_fast_poll_mode_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_SCHEDULE_SNAPSHOT_RESPONSE:
                    dissect_zcl_met_schedule_snapshot_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_TAKE_SNAPSHOT_RESPONSE:
                    dissect_zcl_met_take_snapshot_response(tvb, payload_tree, &offset);
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

                case ZBEE_ZCL_CMD_ID_MET_CONFIGURE_NOTIFICATION_SCHEME:
                    dissect_zcl_met_configure_notification_scheme(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_CONFIGURE_NOTIFICATION_FLAGS:
                    dissect_zcl_met_configure_notification_flags(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_GET_NOTIFIED_MESSAGE:
                    dissect_zcl_met_get_notified_msg(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_SUPPLY_STATUS_RESPONSE:
                    dissect_zcl_met_supply_status_response(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_MET_START_SAMPLING_RESPONSE:
                    dissect_zcl_met_start_sampling_response(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_met*/

/**
 *This function manages the Get Profile payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_get_profile(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t end_time;

    /* Interval Channel */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_profile_interval_channel, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* End Time */
    end_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    end_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_get_profile_end_time, tvb, *offset, 4, &end_time);
    *offset += 4;

    /* Number of Periods */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_profile_number_of_periods, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_met_get_profile*/

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
} /*dissect_zcl_met_request_mirror_rsp*/

/**
 *This function manages the Mirror Removed payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_mirror_removed(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Removed EndPoint ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_mirror_removed_removed_endpoint_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_met_mirror_removed*/

/**
 *This function manages the Request Fast Poll Mode payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_request_fast_poll_mode(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Fast Poll Update Period */
    proto_tree_add_item(tree, hf_zbee_zcl_met_request_fast_poll_mode_fast_poll_update_period, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Duration */
    proto_tree_add_item(tree, hf_zbee_zcl_met_request_fast_poll_mode_duration, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_met_request_fast_poll_mode*/

/**
 *This function manages the Schedule Snapshot payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_schedule_snapshot(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;
    /* Issue Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_schedule_snapshot_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_met_schedule_snapshot_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_met_schedule_snapshot_total_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Snapshot Schedule Payload */
    proto_tree *payload_tree;

    payload_tree = proto_tree_add_subtree(tree, tvb, *offset, 13,
                ett_zbee_zcl_met_schedule_snapshot_payload, NULL, "Snapshot Schedule Payload");

    /* Snapshot Schedule ID */
    proto_tree_add_item(payload_tree, hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_schedule_id,
                        tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Snapshot Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Snapshot Schedule */
    proto_tree_add_bitmask(payload_tree, tvb, *offset, hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_schedule,
                        ett_zbee_zcl_met_snapshot_schedule,
                        zbee_zcl_met_snapshot_schedule_bits, ENC_LITTLE_ENDIAN);
    *offset += 3;

    /* Snapshot Payload Type */
    proto_tree_add_item(payload_tree, hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_shapshot_payload_type,
                        tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Snapshot Cause */
    proto_tree_add_bitmask(payload_tree, tvb, *offset, hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_cause,
                           ett_zbee_zcl_met_snapshot_cause_flags, zbee_zcl_met_snapshot_cause_flags, ENC_LITTLE_ENDIAN);
    *offset += 4;

} /*dissect_zcl_met_schedule_snapshot*/

/**
 *This function manages the Take Snapshot payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_take_snapshot(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Snapshot Cause */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_take_snapshot_snapshot_cause,
                           ett_zbee_zcl_met_snapshot_cause_flags, zbee_zcl_met_snapshot_cause_flags, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_met_take_snapshot*/

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

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_get_snapshot_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    if (gPREF_zbee_se_protocol_version >= ZBEE_SE_VERSION_1_2) {
        /* End Time - Introduced from ZCL version 1.2 */
        end_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
        end_time.nsecs = 0;
        proto_tree_add_time(tree, hf_zbee_zcl_met_get_snapshot_end_time, tvb, *offset, 4, &end_time);
        *offset += 4;
    }

    /* Snapshot Offset */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_snapshot_snapshot_offset, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Snapshot Cause */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_get_snapshot_snapshot_cause,
                           ett_zbee_zcl_met_snapshot_cause_flags, zbee_zcl_met_snapshot_cause_flags, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_met_get_snapshot*/

/**
 *This function manages the Start Sampling payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_start_sampling(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t sample_time;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_start_sampling_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Sampling Time */
    sample_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    sample_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_start_sampling_start_sampling_time, tvb, *offset, 4, &sample_time);
    *offset += 4;

    /* Sample Type */
    proto_tree_add_item(tree, hf_zbee_zcl_met_start_sampling_sample_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Sample Request Interval */
    proto_tree_add_item(tree, hf_zbee_zcl_met_start_sampling_sample_request_interval, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Max Number of Samples */
    proto_tree_add_item(tree, hf_zbee_zcl_met_start_sampling_max_number_of_samples, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_met_start_sampling*/

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
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_sampled_data_sample_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Number of Samples */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_sampled_data_number_of_samples, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_met_get_sampled_data*/

/**
 *This function manages the Mirror Report Attribute Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_mirror_report_attribute_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8 notif_scheme_type;
    gint   noti_flags_count;

    notif_scheme_type = tvb_get_guint8(tvb, *offset);
    /* Notification Scheme */
    proto_tree_add_item(tree, hf_zbee_zcl_met_mirror_report_attribute_response_notification_scheme, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    switch(notif_scheme_type) {
        case ZBEE_ZCL_MET_NOTIFICATION_SCHEME_A:
            noti_flags_count = 1;
            break;
        case ZBEE_ZCL_MET_NOTIFICATION_SCHEME_B:
            noti_flags_count = 5;
            break;
        default:
            noti_flags_count = -1;
            break;
    }
    if (noti_flags_count > 0) {
        for (guint16 noti_flags_number = 0; noti_flags_number < noti_flags_count; noti_flags_number++) {
            dissect_zcl_met_notification_flags(tvb, tree, offset, noti_flags_number);
        }
    } else {
        /* Notification Flag */
        while (tvb_reported_length_remaining(tvb, *offset) > 0) {
            proto_tree *notification_flag_tree;
            notification_flag_tree = proto_tree_add_subtree(tree, tvb, *offset, 4, ett_zbee_zcl_met_mirror_noti_flag, NULL, "Notification Flags");
            proto_tree_add_item(notification_flag_tree, hf_zbee_zcl_met_mirror_report_attribute_response_notification_flags_n,
                                tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
        }
    }
} /*dissect_zcl_met_mirror_report_attribute_response*/

/**
 *This function manages the Reset Load Limit Counter  payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_reset_load_limit_counter(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_reset_load_limit_counter_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_reset_load_limit_counter_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_met_reset_load_limit_counter*/

/**
 *This function manages the Change Supply payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_change_supply(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t request_time;
    nstime_t implementation_time;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_change_supply_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_change_supply_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Request Date/Time */
    request_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    request_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_change_supply_request_date_time, tvb, *offset, 4, &request_time);
    *offset += 4;

    /* Implementation Date/Time */
    implementation_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    implementation_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_change_supply_implementation_date_time, tvb, *offset, 4, &implementation_time);
    *offset += 4;

    /* Proposed Supple Status */
    proto_tree_add_item(tree, hf_zbee_zcl_met_change_supply_proposed_supply_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Supple Control Bits */
    proto_tree_add_item(tree, hf_zbee_zcl_met_change_supply_supply_control_bits, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_met_change_supply*/

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
    proto_tree_add_item(tree, hf_zbee_zcl_met_local_change_supply_proposed_supply_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_met_local_change_supply*/

/**
 *This function manages the Set Supply Status payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_set_supply_status(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_supply_status_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Supply Tamper State */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_supply_status_supply_tamper_state, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Supply Depletion State */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_supply_status_supply_depletion_state, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Supply Uncontrolled Flow State */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_supply_status_supply_uncontrolled_flow_state, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Load Limit Supply State */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_supply_status_load_limit_supply_state, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_met_set_supply_status*/

/**
 *This function manages the Set Uncontrolled Flow Threshold payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_set_uncontrolled_flow_threshold(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_uncontrolled_flow_threshold_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_uncontrolled_flow_threshold_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Uncontrolled Flow Threshold */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_uncontrolled_flow_threshold_uncontrolled_flow_threshold, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Unit of Measure */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_uncontrolled_flow_threshold_unit_of_measure, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Multiplier */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_uncontrolled_flow_threshold_multiplier, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Divisor */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_uncontrolled_flow_threshold_divisor, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Stabilisation Period */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_uncontrolled_flow_threshold_stabilisation_period, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Measurement Period */
    proto_tree_add_item(tree, hf_zbee_zcl_met_set_uncontrolled_flow_threshold_measurement_period, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_met_set_uncontrolled_flow_threshold*/

/**
 *This function manages the Get Profile Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_get_profile_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t end_time;

    /* End Time */
    end_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    end_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_get_profile_response_end_time, tvb, *offset, 4, &end_time);
    *offset += 4;

    /* Status */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_profile_response_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Profile Interval Period */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_profile_response_profile_interval_period, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Number of Periods Delivered */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_profile_response_number_of_periods_delivered, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Intervals */
    while (tvb_reported_length_remaining(tvb, *offset) > 0) {
        proto_tree_add_item(tree, hf_zbee_zcl_met_get_profile_response_intervals, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
        *offset += 3;
    }
} /*dissect_zcl_met_get_profile_response*/

/**
 *This function manages the Request Fast Poll Mode Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_request_fast_poll_mode_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Applied Update Period */
    proto_tree_add_item(tree, hf_zbee_zcl_met_request_fast_poll_mode_response_applied_update_period, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Fast Poll End Time */
    proto_tree_add_item(tree, hf_zbee_zcl_met_request_fast_poll_mode_response_fast_poll_mode_end_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_met_request_fast_poll_mode_response*/

/**
 *This function manages the Schedule Snapshot Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_schedule_snapshot_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_schedule_snapshot_response_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    while (tvb_reported_length_remaining(tvb, *offset) > 0) {
        proto_tree *payload_tree;

        payload_tree = proto_tree_add_subtree(tree, tvb, *offset, 2,
                ett_zbee_zcl_met_schedule_snapshot_response_payload, NULL, "Snapshot Response Payload");

        /* Snapshot Schedule ID */
        proto_tree_add_item(payload_tree, hf_zbee_zcl_met_schedule_snapshot_response_snapshot_schedule_id, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        /* Snapshot Schedule Confirmation */
        proto_tree_add_item(payload_tree, hf_zbee_zcl_met_schedule_snapshot_response_snapshot_schedule_confirmation, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }
} /*dissect_zcl_met_schedule_snapshot_response*/

/**
 *This function manages the Take Snapshot Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_take_snapshot_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Snapshot ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_take_snapshot_response_snapshot_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Snapshot Confirmation */
    proto_tree_add_item(tree, hf_zbee_zcl_met_take_snapshot_response_snapshot_confirmation, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_met_take_snapshot_response*/

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
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_snapshots_found, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_cmd_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_total_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Snapshot Cause */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_publish_snapshot_snapshot_cause,
                           ett_zbee_zcl_met_snapshot_cause_flags, zbee_zcl_met_snapshot_cause_flags, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Snapshot Payload Type */
    proto_tree_add_item(tree, hf_zbee_zcl_met_publish_snapshot_snapshot_payload_type, tvb, *offset, 1, ENC_NA);
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
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_sampled_data_rsp_sample_type, tvb, *offset, 1, ENC_NA);
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
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_mirror_notification_scheme, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_met_configure_mirror*/

/**
 *This function manages the Configure Notification Scheme payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_configure_notification_scheme(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_notification_scheme_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Notification Scheme */
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_notification_scheme_notification_scheme, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Notification Flag Order */
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_notification_scheme_notification_flag_order, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_met_configure_notification_scheme*/

/**
 *This function manages the Configure Notification Flags payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_configure_notification_flags(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree *bit_field_allocation_tree;
    gint rem_len;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_notification_flags_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Notification Scheme */
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_notification_flags_notification_scheme, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Notification Attribute ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_configure_notification_flags_notification_flag_attribute_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    bit_field_allocation_tree = proto_tree_add_subtree(tree, tvb, *offset, -1, ett_zbee_zcl_met_bit_field_allocation, NULL, "Bit Field Allocation");

    /* Cluster ID */
    proto_tree_add_item(bit_field_allocation_tree, hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_cluster_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Manufacturer Code */
    proto_tree_add_item(bit_field_allocation_tree, hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_manufacturer_code, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* No. of Commands */
    proto_tree_add_item(bit_field_allocation_tree, hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_no_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    rem_len = tvb_reported_length_remaining(tvb, *offset);
    while (rem_len >= 1) {
        /* Command Identifier */
        proto_tree_add_item(bit_field_allocation_tree, hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_command_identifier, tvb, *offset, 1, ENC_NA);
        *offset += 1;
        rem_len -= 1;
    }
} /*dissect_zcl_met_configure_notification_flags*/

static void
dissect_zcl_met_notification_flags(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 noti_flags_number)
{
    /* Notification Flags #N */
    switch (noti_flags_number) {
        case ZBEE_ZCL_ATTR_ID_MET_CLNT_FUNC_NOTI_FLAGS:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_func_noti_flags, ett_zbee_zcl_met_func_noti_flags, zbee_zcl_met_func_noti_flags, ENC_LITTLE_ENDIAN);
            break;
        case ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_2:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_2, ett_zbee_zcl_met_noti_flags_2, zbee_zcl_met_noti_flags_2, ENC_LITTLE_ENDIAN);
            break;
        case ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_3:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_3, ett_zbee_zcl_met_noti_flags_3, zbee_zcl_met_noti_flags_3, ENC_LITTLE_ENDIAN);
            break;
        case ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_4:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_4, ett_zbee_zcl_met_noti_flags_4, zbee_zcl_met_noti_flags_4, ENC_LITTLE_ENDIAN);
            break;
        case ZBEE_ZCL_ATTR_ID_MET_CLNT_NOTI_FLAGS_5:
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_met_noti_flags_5, ett_zbee_zcl_met_noti_flags_5, zbee_zcl_met_noti_flags_5, ENC_LITTLE_ENDIAN);
            break;
        default:
            proto_tree_add_item(tree, hf_zbee_zcl_met_get_notified_msg_notification_flags, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            break;
    }
    *offset += 4;

}

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
    guint16 noti_flags_number;

    /* Notification Scheme */
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_notified_msg_notification_scheme, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Notification Flag attribute ID */
    noti_flags_number = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_zbee_zcl_met_get_notified_msg_notification_flag_attribute_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    dissect_zcl_met_notification_flags(tvb, tree, offset, noti_flags_number);
} /*dissect_zcl_met_get_notified_msg*/

/**
 *This function manages the Supply Status Response payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_met_supply_status_response(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t implementation_date_time;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_supply_status_response_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_met_supply_status_response_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Implementation Date/Time */
    implementation_date_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    implementation_date_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_met_supply_status_response_implementation_date_time, tvb, *offset, 4, &implementation_date_time);
    *offset += 4;

    /* Supply Status After Implementation */
    proto_tree_add_item(tree, hf_zbee_zcl_met_supply_status_response_supply_status_after_implementation, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_met_supply_status_response*/

/**
 *This function registers the ZCL Metering dissector
 *
*/
void
proto_register_zbee_zcl_met(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_met_attr_server_id,
            { "Attribute", "zbee_zcl_se.met.attr_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &zbee_zcl_met_attr_server_names_ext,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_met_attr_client_id,
            { "Attribute", "zbee_zcl_se.met.attr_client_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_met_attr_client_names),
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

        { &hf_zbee_zcl_met_func_noti_flag_new_sub_ghz_channel_masks_available,
            { "New Sub-GHz Channel Masks Available", "zbee_zcl_se.met.attr.func_noti_flag.new_sub_ghz_channel_masks_available", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_NEW_SUB_GHZ_CHANNEL_MASKS_AVAILABLE, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_energy_scan_pending,
            { "Energy Scan Pending", "zbee_zcl_se.met.attr.func_noti_flag.energy_scan_pending", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_ENERGY_SCAN_PENDING, NULL, HFILL } },

        { &hf_zbee_zcl_met_func_noti_flag_channel_change_pending,
            { "Channel Change Pending", "zbee_zcl_se.met.attr.func_noti_flag.channel_change_pending", FT_BOOLEAN, 32, NULL,
            ZBEE_ZCL_FUNC_NOTI_FLAG_CHANNEL_CHANGE_PENDING, NULL, HFILL } },

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

        { &hf_zbee_zcl_met_get_profile_interval_channel,
            { "Interval Channel", "zbee_zcl_se.met.get_profile.interval_channel", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_profile_end_time,
            { "End Time", "zbee_zcl_se.met.get_profile.end_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_profile_number_of_periods,
            { "Number of Periods", "zbee_zcl_se.met.get_profile.number_of_periods", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_request_mirror_rsp_endpoint_id,
            { "EndPoint ID", "zbee_zcl_se.met.request_mirror_rsp.endpoint_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_mirror_removed_removed_endpoint_id,
            { "Removed EndPoint ID", "zbee_zcl_se.met.mirror_removed.removed_endpoint_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_request_fast_poll_mode_fast_poll_update_period,
            { "Fast Poll Update Period", "zbee_zcl_se.met.request_fast_poll_mode.fast_poll_update_period", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_request_fast_poll_mode_duration,
            { "Duration", "zbee_zcl_se.met.request_fast_poll_mode.duration", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.schedule_snapshot.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_command_index,
            { "Command Index", "zbee_zcl_se.met.schedule_snapshot.command_index", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_total_number_of_commands,
            { "Total Number of Commands", "zbee_zcl_se.met.schedule_snapshot.total_number_of_commands", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_schedule_id,
            { "Snapshot Schedule ID", "zbee_zcl_se.met.schedule_snapshot.snapshot_schedule_payload.snapshot_schedule_id", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_start_time,
            { "Snapshot Start Time", "zbee_zcl_se.met.schedule_snapshot.snapshot_schedule_payload.snapshot_start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_schedule,
            { "Snapshot Schedule", "zbee_zcl_se.met.schedule_snapshot.snapshot_schedule_payload.snapshot_schedule", FT_UINT24, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_shapshot_payload_type,
            { "Snapshot Payload Type", "zbee_zcl_se.met.schedule_snapshot.snapshot_schedule_payload.snapshot_payload_type",
                FT_UINT8, BASE_DEC, VALS(zbee_zcl_met_snapshot_payload_type),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_snapshot_schedule_payload_snapshot_cause,
            { "Snapshot Cause", "zbee_zcl_se.met.schedule_snapshot.snapshot_schedule_payload.snapshot_cause", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_snapshot_schedule_frequency,
            { "Snapshot Schedule Frequency", "zbee_zcl_se.met.snapshot_schedule.frequency",
                FT_UINT24, BASE_DEC, NULL,
            0x0FFFFF, NULL, HFILL } },

        { &hf_zbee_zcl_met_snapshot_schedule_frequency_type,
            { "Snapshot Schedule Frequency Type", "zbee_zcl_se.met.snapshot_schedule.frequency_type",
                FT_UINT24, BASE_HEX, VALS(zbee_zcl_met_snapshot_schedule_frequency_type),
            0x300000, NULL, HFILL } },

        { &hf_zbee_zcl_met_snapshot_schedule_frequency_wild_card,
            { "Snapshot Schedule Frequency Wild Card", "zbee_zcl_se.met.snapshot_schedule.frequency_wild_card",
                FT_UINT24, BASE_HEX,VALS(zbee_zcl_met_snapshot_schedule_frequency_wild_card),
            0xC00000, NULL, HFILL } },

        { &hf_zbee_zcl_met_take_snapshot_snapshot_cause,
            { "Snapshot Cause", "zbee_zcl_se.met.take_snapshot.snapshot_cause", FT_UINT32, BASE_HEX, NULL,
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

        { &hf_zbee_zcl_met_start_sampling_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.start_sampling.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_start_sampling_start_sampling_time,
            { "Start Sampling Time", "zbee_zcl_se.met.start_sampling.start_sampling_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_start_sampling_sample_type,
            { "Sample Type", "zbee_zcl_se.met.start_sampling.sample_type", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_start_sampling_sample_request_interval,
            { "Sample Request Interval", "zbee_zcl_se.met.start_sampling.sample_request_interval", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_start_sampling_max_number_of_samples,
            { "Max Number of Samples", "zbee_zcl_se.met.start_sampling.max_number_of_samples", FT_UINT16, BASE_DEC, NULL,
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

        { &hf_zbee_zcl_met_start_sampling_response_sample_id,
            { "Sample ID", "zbee_zcl_se.met.start_sampling_response.sample_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_mirror_report_attribute_response_notification_scheme,
            { "Notification Scheme", "zbee_zcl_se.met.mirror_report_attribute_response.notification_scheme", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_met_notification_scheme),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_mirror_report_attribute_response_notification_flags_n,
            { "Notification Flag", "zbee_zcl_se.met.mirror_report_attribute_response.notification_flags_n", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_reset_load_limit_counter_provider_id,
            { "Provider ID", "zbee_zcl_se.met.reset_load_limit_counter.provider_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_reset_load_limit_counter_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.reset_load_limit_counter.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_change_supply_provider_id,
            { "Provider ID", "zbee_zcl_se.met.change_supply.provider_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_change_supply_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.change_supply.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_change_supply_request_date_time,
            { "Request Date/Time", "zbee_zcl_se.met.change_supply.request_date_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_change_supply_implementation_date_time,
            { "Implementation Date/Time", "zbee_zcl_se.met.change_supply.implementation_date_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_change_supply_proposed_supply_status,
            { "Proposed Supply Status", "zbee_zcl_se.met.change_supply.proposed_supply_status", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_change_supply_supply_control_bits,
            { "Supply Control bits", "zbee_zcl_se.met.change_supply.supply_control_bits", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_local_change_supply_proposed_supply_status,
            { "Proposed Supply Status", "zbee_zcl_se.met.local_change_supply.proposed_supply_status", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_supply_status_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.set_supply_status.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_supply_status_supply_tamper_state,
            { "Supply Tamper State", "zbee_zcl_se.met.set_supply_status.supply_tamper_state", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_supply_status_supply_depletion_state,
            { "Supply Depletion State", "zbee_zcl_se.met.set_supply_status.supply_depletion_state", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_supply_status_supply_uncontrolled_flow_state,
            { "Supply Uncontrolled Flow State", "zbee_zcl_se.met.set_supply_status.supply_uncontrolled_flow_state", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_supply_status_load_limit_supply_state,
            { "Load Limit Supply State", "zbee_zcl_se.met.set_supply_status.load_limit_supply_state", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_uncontrolled_flow_threshold_provider_id,
            { "Provider ID", "zbee_zcl_se.met.set_uncontrolled_flow_threshold.provider_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_uncontrolled_flow_threshold_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.set_uncontrolled_flow_threshold.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_uncontrolled_flow_threshold_uncontrolled_flow_threshold,
            { "Uncontrolled Flow Threshold", "zbee_zcl_se.met.set_uncontrolled_flow_threshold.uncontrolled_flow_threshold", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_uncontrolled_flow_threshold_unit_of_measure,
            { "Unit of Measure", "zbee_zcl_se.met.set_uncontrolled_flow_threshold.unit_of_measure", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_uncontrolled_flow_threshold_multiplier,
            { "Multiplier", "zbee_zcl_se.met.set_uncontrolled_flow_threshold.multiplier", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_uncontrolled_flow_threshold_divisor,
            { "Divisor", "zbee_zcl_se.met.set_uncontrolled_flow_threshold.divisor", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_uncontrolled_flow_threshold_stabilisation_period,
            { "Stabilisation Period", "zbee_zcl_se.met.set_uncontrolled_flow_threshold.stabilisation_period", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_set_uncontrolled_flow_threshold_measurement_period,
            { "Measurement Period", "zbee_zcl_se.met.set_uncontrolled_flow_threshold.measurement_period", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_profile_response_end_time,
            { "End Time", "zbee_zcl_se.met.get_profile_response.end_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_profile_response_status,
            { "Status", "zbee_zcl_se.met.get_profile_response.status", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_profile_response_profile_interval_period,
            { "Profile Interval Period", "zbee_zcl_se.met.get_profile_response.profile_interval_period", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_profile_response_number_of_periods_delivered,
            { "Number of Periods Delivered", "zbee_zcl_se.met.get_profile_response.number_of_periods_delivered", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_profile_response_intervals,
            { "Intervals", "zbee_zcl_se.met.get_profile_response.intervals", FT_UINT24, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_request_fast_poll_mode_response_applied_update_period,
            { "Applied Update Period (seconds)", "zbee_zcl_se.met.request_fast_poll_mode_response.applied_update_period", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_request_fast_poll_mode_response_fast_poll_mode_end_time,
            { "Fast Poll Mode End Time", "zbee_zcl_se.met.request_fast_poll_mode_response.fast_poll_mode_end_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_response_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.schedule_snapshot_response.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_response_snapshot_schedule_id,
            { "Snapshot Schedule ID", "zbee_zcl_se.met.schedule_snapshot_response.response_snapshot_schedule_id", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_schedule_snapshot_response_snapshot_schedule_confirmation,
            { "Snapshot Schedule Confirmation", "zbee_zcl_se.met.schedule_snapshot_response.snapshot_schedule_confirmation", FT_UINT8, BASE_HEX, VALS(zbee_zcl_met_snapshot_schedule_confirmation),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_take_snapshot_response_snapshot_id,
            { "Snapshot ID", "zbee_zcl_se.met.take_snapshot_response.snapshot_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_take_snapshot_response_snapshot_confirmation,
            { "Snapshot Confirmation", "zbee_zcl_se.met.take_snapshot_response.snapshot_confirmation", FT_UINT8, BASE_HEX, NULL,
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
            { "Snapshot Payload Type", "zbee_zcl_se.met.publish_snapshot.payload_type", FT_UINT8, BASE_DEC, VALS(zbee_zcl_met_snapshot_payload_type),
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
            { "Notification Scheme", "zbee_zcl_se.met.configure_mirror.notification_scheme", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_met_notification_scheme),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_notification_scheme_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.configure_notification_scheme.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_notification_scheme_notification_scheme,
            { "Notification Scheme", "zbee_zcl_se.met.configure_notification_scheme.notification_scheme", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_met_notification_scheme),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_notification_scheme_notification_flag_order,
            { "Notification Flag Order", "zbee_zcl_se.met.configure_notification_scheme.notification_flag_order", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_notification_flags_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.configure_notification_flags.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_notification_flags_notification_scheme,
            { "Notification Scheme", "zbee_zcl_se.met.configure_notification_flags.notification_scheme", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_met_notification_scheme),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_notification_flags_notification_flag_attribute_id,
            { "Notification Flag Attribute ID", "zbee_zcl_se.met.configure_notification_flags.notification_flag_attribute_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_met_attr_client_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_cluster_id,
            { "Cluster ID", "zbee_zcl_se.met.configure_notification_flags.bit_field_allocation.cluster_id", FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_aps_cid_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_manufacturer_code,
            { "Manufacturer Code", "zbee_zcl_se.met.configure_notification_flags.bit_field_allocation.manufacturer_code", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_no_of_commands,
            { "No. of Commands", "zbee_zcl_se.met.configure_notification_flags.bit_field_allocation.no_of_commands", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_configure_notification_flags_bit_field_allocation_command_identifier,
            { "Command Identifier", "zbee_zcl_se.met.configure_notification_flags.bit_field_allocation.command_identifier", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_notified_msg_notification_scheme,
            { "Notification Scheme", "zbee_zcl_se.met.get_notified_msg.notification_scheme", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_met_notification_scheme),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_notified_msg_notification_flag_attribute_id,
            { "Notification Flag attribute ID", "zbee_zcl_se.met.get_notified_msg.notification_flag_attribute_id", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_get_notified_msg_notification_flags,
            { "Notification Flags", "zbee_zcl_se.met.get_notified_msg.notification_flags", FT_UINT32, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_supply_status_response_provider_id,
            { "Provider ID", "zbee_zcl_se.met.supply_status_response.provider_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_supply_status_response_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.met.supply_status_response.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_supply_status_response_implementation_date_time,
            { "Implementation Date/Time", "zbee_zcl_se.met.supply_status_response.implementation_date_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_supply_status_response_supply_status_after_implementation,
            { "Supply Status After Implementation", "zbee_zcl_se.met.supply_status_response.supply_status_after_implementation", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_snapshot_cause_general,
            { "General", "zbee_zcl_se.met.snapshot_cause.general", FT_BOOLEAN, 32, NULL,
            0x00000001, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_end_of_billing_period,
            { "End of Billing Period", "zbee_zcl_se.met.snapshot_cause.end_of_billing_period", FT_BOOLEAN, 32, NULL,
            0x00000002, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_end_of_block_period,
            { "End of Block Period", "zbee_zcl_se.met.snapshot_cause.end_of_block_period", FT_BOOLEAN, 32, NULL,
            0x00000004, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_change_of_tariff_information,
            { "Change of Tariff Information", "zbee_zcl_se.met.snapshot_cause.change_of_tariff_information", FT_BOOLEAN, 32, NULL,
            0x00000008, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_change_of_price_matrix,
            { "Change of Price Matrix", "zbee_zcl_se.met.snapshot_cause.change_of_price_matrix", FT_BOOLEAN, 32, NULL,
            0x00000010, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_change_of_block_thresholds,
            { "Change of Block Thresholds", "zbee_zcl_se.met.snapshot_cause.change_of_block_thresholds", FT_BOOLEAN, 32, NULL,
            0x00000020, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_change_of_cv,
            { "Change of CV", "zbee_zcl_se.met.snapshot_cause.change_of_cv", FT_BOOLEAN, 32, NULL,
            0x00000040, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_change_of_cf,
            { "Change of CF", "zbee_zcl_se.met.snapshot_cause.change_of_cf", FT_BOOLEAN, 32, NULL,
            0x00000080, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_change_of_calendar,
            { "Change of Calendar", "zbee_zcl_se.met.snapshot_cause.change_of_calendar", FT_BOOLEAN, 32, NULL,
            0x00000100, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_critical_peak_pricing,
            { "Critical Peak Pricing", "zbee_zcl_se.met.snapshot_cause.critical_peak_pricing", FT_BOOLEAN, 32, NULL,
            0x00000200, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_manually_triggered_from_client,
            { "Manually Triggered from Client", "zbee_zcl_se.met.snapshot_cause.manually_triggered_from_client", FT_BOOLEAN, 32, NULL,
            0x00000400, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_end_of_resolve_period,
            { "End of Resolve Period", "zbee_zcl_se.met.snapshot_cause.end_of_resolve_period", FT_BOOLEAN, 32, NULL,
            0x00000800, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_change_of_tenancy,
            { "Change of Tenancy", "zbee_zcl_se.met.snapshot_cause.change_of_tenancy", FT_BOOLEAN, 32, NULL,
            0x00001000, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_change_of_supplier,
            { "Change of Supplier", "zbee_zcl_se.met.snapshot_cause.change_of_supplier", FT_BOOLEAN, 32, NULL,
            0x00002000, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_change_of_meter_mode,
            { "Change of (Meter) Mode", "zbee_zcl_se.met.snapshot_cause.change_of_meter_mode", FT_BOOLEAN, 32, NULL,
            0x00004000, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_debt_payment,
            { "Debt Payment", "zbee_zcl_se.met.snapshot_cause.debt_payment", FT_BOOLEAN, 32, NULL,
            0x00008000, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_scheduled_snapshot,
            { "Scheduled Snapshot", "zbee_zcl_se.met.snapshot_cause.scheduled_snapshot", FT_BOOLEAN, 32, NULL,
            0x00010000, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_ota_firmware_download,
            { "OTA Firmware Download", "zbee_zcl_se.met.snapshot_cause.ota_firmware_download", FT_BOOLEAN, 32, NULL,
            0x00020000, NULL, HFILL } },
        { &hf_zbee_zcl_met_snapshot_cause_reserved,
            { "Reserved", "zbee_zcl_se.met.snapshot_cause.reserved", FT_UINT32, BASE_HEX, NULL,
            0xFFFC0000, NULL, HFILL } }
    };

    /* ZCL Metering subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_met,
        &ett_zbee_zcl_met_func_noti_flags,
        &ett_zbee_zcl_met_noti_flags_2,
        &ett_zbee_zcl_met_noti_flags_3,
        &ett_zbee_zcl_met_noti_flags_4,
        &ett_zbee_zcl_met_noti_flags_5,
        &ett_zbee_zcl_met_snapshot_cause_flags,
        &ett_zbee_zcl_met_snapshot_schedule,
        &ett_zbee_zcl_met_schedule_snapshot_response_payload,
        &ett_zbee_zcl_met_schedule_snapshot_payload,
        &ett_zbee_zcl_met_mirror_noti_flag,
        &ett_zbee_zcl_met_bit_field_allocation
    };

    /* Register the ZigBee ZCL Metering cluster protocol name and description */
    proto_zbee_zcl_met = proto_register_protocol("ZigBee ZCL Metering", "ZCL Metering", ZBEE_PROTOABBREV_ZCL_MET);
    proto_register_field_array(proto_zbee_zcl_met, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Metering dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_MET, dissect_zbee_zcl_met, proto_zbee_zcl_met);
} /*proto_register_zbee_zcl_met*/

/**
 *Hands off the ZCL Metering dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_met(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_MET,
                            proto_zbee_zcl_met,
                            ett_zbee_zcl_met,
                            ZBEE_ZCL_CID_SIMPLE_METERING,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_met_attr_server_id,
                            hf_zbee_zcl_met_attr_client_id,
                            hf_zbee_zcl_met_srv_rx_cmd_id,
                            hf_zbee_zcl_met_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_met_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_met*/

/* ########################################################################## */
/* #### (0x0703) MESSAGING CLUSTER ########################################## */
/* ########################################################################## */

/* Attributes - None */

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
static int hf_zbee_zcl_msg_message = -1;
static int hf_zbee_zcl_msg_confirm_time = -1;
static int hf_zbee_zcl_msg_confirm_ctrl = -1;
static int hf_zbee_zcl_msg_confirm_response = -1;
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

    static int * const message_ctrl_flags[] = {
        &hf_zbee_zcl_msg_ctrl_tx,
        &hf_zbee_zcl_msg_ctrl_importance,
        &hf_zbee_zcl_msg_ctrl_enh_confirm,
        &hf_zbee_zcl_msg_ctrl_reserved,
        &hf_zbee_zcl_msg_ctrl_confirm,
        NULL
    };

    static int * const message_ext_ctrl_flags[] = {
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

    /* Message */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_msg_message, tvb, *offset, 1, ENC_NA | ENC_ZIGBEE, &msg_len);
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

    /* (Optional) Response Text, but is we have a length we expect to find the subsequent string */
    if ( tvb_reported_length_remaining(tvb, *offset) <= 0 ) return;
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_msg_confirm_response, tvb, *offset, 1, ENC_NA | ENC_ZIGBEE, &msg_len);
    *offset += msg_len;
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
        start_time = abs_time_secs_to_str (NULL, epoch_time, ABSOLUTE_TIME_UTC, TRUE);
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

        { &hf_zbee_zcl_msg_message,
            { "Message", "zbee_zcl_se.msg.message", FT_UINT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_msg_confirm_time,
            { "Confirmation Time", "zbee_zcl_se.msg.message.confirm_time",  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_msg_confirm_ctrl,
            { "Confirmation Control", "zbee_zcl_se.msg.message.confirm.ctrl", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
            ZBEE_ZCL_MSG_CONFIRM_CTRL_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_msg_confirm_response,
            { "Response", "zbee_zcl_se.msg.message", FT_UINT_STRING, BASE_NONE, NULL,
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
 *Hands off the ZCL Messaging dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_msg(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_MSG,
                            proto_zbee_zcl_msg,
                            ett_zbee_zcl_msg,
                            ZBEE_ZCL_CID_MESSAGE,
                            ZBEE_MFG_CODE_NONE,
                            -1, -1,
                            hf_zbee_zcl_msg_srv_rx_cmd_id,
                            hf_zbee_zcl_msg_srv_tx_cmd_id,
                            NULL
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
    XXX(ZBEE_ZCL_CMD_ID_TUN_GET_SUPPORTED_PROTOCOLS,            0x06, "Get Supported Tunnel Protocols" )

VALUE_STRING_ENUM(zbee_zcl_tun_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_tun_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_tun_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_REQUEST_TUNNEL_RSP,                 0x00, "Request Tunnel Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_TX,                   0x01, "Transfer Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_TRANSFER_DATA_ERROR_TX,             0x02, "Transfer Data Error" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_ACK_TRANSFER_DATA_TX,               0x03, "Ack Transfer Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_READY_DATA_TX,                      0x04, "Ready Data" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_GET_SUPPORTED_PROTOCOLS_RSP,        0x05, "Supported Tunnel Protocols Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_TUN_CLOSURE_NOTIFY,                     0x06, "Tunnel Closure Notification" )

VALUE_STRING_ENUM(zbee_zcl_tun_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_tun_srv_tx_cmd_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_tun(void);
void proto_reg_handoff_zbee_zcl_tun(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_tun_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

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
static int hf_zbee_zcl_tun_transfer_data_status = -1;

static heur_dissector_list_t zbee_zcl_tun_heur_subdissector_list;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_tun = -1;

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_tun_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
*/
static void
dissect_zcl_tun_transfer_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
    gint length;
    heur_dtbl_entry_t *hdtbl_entry;
    tvbuff_t *data_tvb;
    proto_tree *root_tree = proto_tree_get_root(tree);

    proto_tree_add_item(tree, hf_zbee_zcl_tun_tunnel_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    length = tvb_reported_length_remaining(tvb, *offset);
    data_tvb = tvb_new_subset_remaining(tvb, *offset);
    *offset += length;

    if (dissector_try_heuristic(zbee_zcl_tun_heur_subdissector_list, data_tvb, pinfo, root_tree, &hdtbl_entry, NULL)) {
        return;
    }

    call_data_dissector(data_tvb, pinfo, root_tree);
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
    proto_tree_add_item(tree, hf_zbee_zcl_tun_protocol_offset, tvb, *offset, 1, ENC_NA);
    *offset += 1;
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
            proto_tree_add_uint_format(tree, hf_zbee_zcl_tun_manufacturer_code, tvb, *offset, 2, mfg_code, "Standard Protocol (Mfg Code %#x)", mfg_code);
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
                    dissect_zcl_tun_transfer_data(tvb, pinfo, payload_tree, &offset);
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
                    dissect_zcl_tun_transfer_data(tvb, pinfo, payload_tree, &offset);
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

    /* Make heuristic dissectors possible */
    zbee_zcl_tun_heur_subdissector_list = register_heur_dissector_list(ZBEE_PROTOABBREV_ZCL_TUN, proto_zbee_zcl_tun);

    /* Register the ZigBee ZCL Tunneling dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_TUN, dissect_zbee_zcl_tun, proto_zbee_zcl_tun);

} /* proto_register_zbee_zcl_tun */

/**
 *Hands off the ZCL Tunneling dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_tun(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_TUN,
                            proto_zbee_zcl_tun,
                            ett_zbee_zcl_tun,
                            ZBEE_ZCL_CID_TUNNELING,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_tun_attr_id,
                            -1,
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
    XXX(ZBEE_ZCL_ATTR_ID_PP_CREDIT_STATUS,                      0x0003, "Credit Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CREDIT_REMAINING_TIMESTAMP,         0x0004, "Credit Remaining Timestamp" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_ACCUMULATED_DEBT,                   0x0005, "Accumulated Debt" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_OVERALL_DEBT_CAP,                   0x0006, "Overall Debt Cap" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_EMERGENCY_CREDIT_LIMIT,             0x0010, "Emergency Credit Limit / Allowance" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_EMERGENCY_CREDIT_THRESHOLD,         0x0011, "Emergency Credit Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOTAL_CREDIT_ADDED,                 0x0020, "Total Credit Added" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_MAX_CREDIT_LIMIT,                   0x0021, "Max Credit Limit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_MAX_CREDIT_PER_TOPUP,               0x0022, "Max Credit Per Top Up" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_FRIENDLY_CREDIT_WARNING,            0x0030, "Friendly Credit Warning" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_LOW_CREDIT_WARNING,                 0x0031, "Low Credit Warning" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_IHD_LOW_CREDIT_WARNING,             0x0032, "IHD Low Credit Warning" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_INTERRUPT_SUSPEND_TIME,             0x0033, "Interrupt Suspend Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_REMAINING_FRIENDLY_CREDIT_TIME,     0x0034, "Remaining Friendly Credit Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_NEXT_FRIENDLY_CREDIT_PERIOD,        0x0035, "Next Friendly Credit Period" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CUT_OFF_VALUE,                      0x0040, "Cut Off Value" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOKEN_CARRIER_ID,                   0x0080, "Token Carrier ID" ) \
/* Top-up Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_DATE_TIME_1,                  0x0100, "Top-up Date/time #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_AMOUNT_1,                     0x0101, "Top-up Amount #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_ORIGINATING_DEVICE_1,               0x0102, "Originating Device #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_CODE_1,                       0x0103, "Top-up Code #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_DATE_TIME_2,                  0x0110, "Top-up Date/time #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_AMOUNT_2,                     0x0111, "Top-up Amount #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_ORIGINATING_DEVICE_2,               0x0112, "Originating Device #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_CODE_2,                       0x0113, "Top-up Code #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_DATE_TIME_3,                  0x0120, "Top-up Date/time #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_AMOUNT_3,                     0x0121, "Top-up Amount #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_ORIGINATING_DEVICE_3,               0x0122, "Originating Device #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_CODE_3,                       0x0123, "Top-up Code #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_DATE_TIME_4,                  0x0130, "Top-up Date/time #4" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_AMOUNT_4,                     0x0131, "Top-up Amount #4" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_ORIGINATING_DEVICE_4,               0x0132, "Originating Device #4" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_CODE_4,                       0x0133, "Top-up Code #4" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_DATE_TIME_5,                  0x0140, "Top-up Date/time #5" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_AMOUNT_5,                     0x0141, "Top-up Amount #5" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_ORIGINATING_DEVICE_5,               0x0142, "Originating Device #5" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_TOPUP_CODE_5,                       0x0143, "Top-up Code #5" ) \
/* Debt Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_LABEL_1,                       0x0210, "Debt Label #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_AMOUNT_1,                      0x0211, "Debt Amount #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_METHOD_1,             0x0212, "Debt Recovery Method #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_START_TIME_1,         0x0213, "Debt Recovery Start Time #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_COLLECTION_TIME_1,    0x0214, "Debt Recovery Collection Time #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_FREQ_1,               0x0216, "Debt Recovery Frequency #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_AMOUNT_1,             0x0217, "Debt Recovery Amount #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_TOP_UP_PERCENTAGE_1,  0x0219, "Debt Recovery Top Up Percentage #1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_LABEL_2,                       0x0220, "Debt Label #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_AMOUNT_2,                      0x0221, "Debt Amount #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_METHOD_2,             0x0222, "Debt Recovery Method #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_START_TIME_2,         0x0223, "Debt Recovery Start Time #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_COLLECTION_TIME_2,    0x0224, "Debt Recovery Collection Time #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_FREQ_2,               0x0226, "Debt Recovery Frequency #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_AMOUNT_2,             0x0227, "Debt Recovery Amount #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_TOP_UP_PERCENTAGE_2,  0x0229, "Debt Recovery Top Up Percentage #2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_LABEL_3,                       0x0230, "Debt Label #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_AMOUNT_3,                      0x0231, "Debt Amount #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_METHOD_3,             0x0232, "Debt Recovery Method #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_START_TIME_3,         0x0233, "Debt Recovery Start Time #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_COLLECTION_TIME_3,    0x0234, "Debt Recovery Collection Time #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_FREQ_3,               0x0236, "Debt Recovery Frequency #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_AMOUNT_3,             0x0237, "Debt Recovery Amount #3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_DEBT_RECOVERY_TOP_UP_PERCENTAGE_3,  0x0239, "Debt Recovery Top Up Percentage #3" ) \
/* Alarm Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREPAYMENT_ALARM_STATUS,            0x0400, "Prepayment Alarm Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREPAY_GENERIC_ALARM_MASK,          0x0401, "Prepay Generic Alarm Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREPAY_SWITCH_ALARM_MASK,           0x0402, "Prepay Switch Alarm Mask" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREPAY_EVENT_ALARM_MASK,            0x0403, "Prepay Event Alarm Mask" ) \
/* Historical Cost Consumption Information Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_PP_HISTORICAL_COST_CON_FORMAT,         0x0500, "Historical Cost Consumption Formatting" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CONSUMPTION_UNIT_OF_MEASUREMENT,    0x0501, "Consumption Unit of Measurement" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENCY_SCALING_FACTOR,            0x0502, "Currency Scaling Factor" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENCY,                           0x0503, "Currency" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENT_DAY_COST_CON_DELIVERED,     0x051C, "Current Day Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENT_DAY_COST_CON_RECEIVED,      0x051D, "Current Day Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_COST_CON_DELIVERED,    0x051E, "Previous Day Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_COST_CON_RECEIVED,     0x051F, "Previous Day Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_2_COST_CON_DELIVERED,  0x0520, "Previous Day 2 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_2_COST_CON_RECEIVED,   0x0521, "Previous Day 2 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_3_COST_CON_DELIVERED,  0x0522, "Previous Day 3 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_3_COST_CON_RECEIVED,   0x0523, "Previous Day 3 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_4_COST_CON_DELIVERED,  0x0524, "Previous Day 4 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_4_COST_CON_RECEIVED,   0x0525, "Previous Day 4 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_5_COST_CON_DELIVERED,  0x0526, "Previous Day 5 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_5_COST_CON_RECEIVED,   0x0527, "Previous Day 5 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_6_COST_CON_DELIVERED,  0x0528, "Previous Day 6 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_6_COST_CON_RECEIVED,   0x0529, "Previous Day 6 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_7_COST_CON_DELIVERED,  0x052A, "Previous Day 7 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_7_COST_CON_RECEIVED,   0x052B, "Previous Day 7 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_8_COST_CON_DELIVERED,  0x052C, "Previous Day 8 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_DAY_8_COST_CON_RECEIVED,   0x052D, "Previous Day 8 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENT_WEEK_COST_CON_DELIVERED,    0x0530, "Current Week Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENT_WEEK_COST_CON_RECEIVED,     0x0531, "Current Week Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_COST_CON_DELIVERED,   0x0532, "Previous Week Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_COST_CON_RECEIVED,    0x0533, "Previous Week Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_2_COST_CON_DELIVERED, 0x0534, "Previous Week 2 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_2_COST_CON_RECEIVED,  0x0535, "Previous Week 2 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_3_COST_CON_DELIVERED, 0x0536, "Previous Week 3 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_3_COST_CON_RECEIVED,  0x0537, "Previous Week 3 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_4_COST_CON_DELIVERED, 0x0538, "Previous Week 4 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_4_COST_CON_RECEIVED,  0x0539, "Previous Week 4 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_5_COST_CON_DELIVERED, 0x053A, "Previous Week 5 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_WEEK_5_COST_CON_RECEIVED,  0x053B, "Previous Week 5 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENT_MON_COST_CON_DELIVERED,     0x0540, "Current Month Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_CURRENT_MON_COST_CON_RECEIVED,      0x0541, "Current Month Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_COST_CON_DELIVERED,    0x0542, "Previous Month Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_COST_CON_RECEIVED,     0x0543, "Previous Month Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_2_COST_CON_DELIVERED,  0x0544, "Previous Month 2 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_2_COST_CON_RECEIVED,   0x0545, "Previous Month 2 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_3_COST_CON_DELIVERED,  0x0546, "Previous Month 3 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_3_COST_CON_RECEIVED,   0x0547, "Previous Month 3 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_4_COST_CON_DELIVERED,  0x0548, "Previous Month 4 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_4_COST_CON_RECEIVED,   0x0549, "Previous Month 4 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_5_COST_CON_DELIVERED,  0x054A, "Previous Month 5 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_5_COST_CON_RECEIVED,   0x054B, "Previous Month 5 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_6_COST_CON_DELIVERED,  0x054C, "Previous Month 6 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_6_COST_CON_RECEIVED,   0x054D, "Previous Month 6 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_7_COST_CON_DELIVERED,  0x054E, "Previous Month 7 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_7_COST_CON_RECEIVED,   0x054F, "Previous Month 7 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_8_COST_CON_DELIVERED,  0x0550, "Previous Month 8 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_8_COST_CON_RECEIVED,   0x0551, "Previous Month 8 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_9_COST_CON_DELIVERED,  0x0552, "Previous Month 9 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_9_COST_CON_RECEIVED,   0x0553, "Previous Month 9 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_10_COST_CON_DELIVERED, 0x0554, "Previous Month 10 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_10_COST_CON_RECEIVED,  0x0555, "Previous Month 10 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_11_COST_CON_DELIVERED, 0x0556, "Previous Month 11 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_11_COST_CON_RECEIVED,  0x0557, "Previous Month 11 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_12_COST_CON_DELIVERED, 0x0558, "Previous Month 12 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_12_COST_CON_RECEIVED,  0x0559, "Previous Month 12 Cost Consumption Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_13_COST_CON_DELIVERED, 0x055A, "Previous Month 13 Cost Consumption Delivered" ) \
    XXX(ZBEE_ZCL_ATTR_ID_PP_PREVIOUS_MON_13_COST_CON_RECEIVED,  0x055B, "Previous Month 13 Cost Consumption Received" ) \
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
static void dissect_zcl_pp_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

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
static int hf_zbee_zcl_pp_publish_top_up_log_top_up_code = -1;
static int hf_zbee_zcl_pp_publish_top_up_log_top_up_amount = -1;
static int hf_zbee_zcl_pp_publish_top_up_log_top_up_time = -1;
static int hf_zbee_zcl_pp_publish_debt_log_command_index = -1;
static int hf_zbee_zcl_pp_publish_debt_log_total_number_of_commands = -1;
static int hf_zbee_zcl_pp_publish_debt_log_collection_time = -1;
static int hf_zbee_zcl_pp_publish_debt_log_amount_collected = -1;
static int hf_zbee_zcl_pp_publish_debt_log_debt_type = -1;
static int hf_zbee_zcl_pp_publish_debt_log_outstanding_debt = -1;
static int hf_zbee_zcl_pp_payment_control_configuration = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_disconnection_enabled = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_prepayment_enabled = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_credit_management_enabled = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_credit_display_enabled = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_account_base = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_contactor_fitted = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_standing_charge_configuration = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_emergency_standing_charge_configuration = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_debt_configuration = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_emergency_debt_configuration = -1;
static int hf_zbee_zcl_pp_payment_control_configuration_reserved = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_general = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_end_of_billing_period = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_change_of_tariff_information = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_change_of_price_matrix = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_manually_triggered_from_client = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_change_of_tenancy = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_change_of_supplier = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_change_of_meter_mode = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_top_up_addition = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_debt_credit_addition = -1;
static int hf_zbee_zcl_pp_snapshot_payload_cause_reserved = -1;

static int* const zbee_zcl_pp_payment_control_configuration_flags[] = {
        &hf_zbee_zcl_pp_payment_control_configuration_disconnection_enabled,
        &hf_zbee_zcl_pp_payment_control_configuration_prepayment_enabled,
        &hf_zbee_zcl_pp_payment_control_configuration_credit_management_enabled,
        &hf_zbee_zcl_pp_payment_control_configuration_credit_display_enabled,
        &hf_zbee_zcl_pp_payment_control_configuration_account_base,
        &hf_zbee_zcl_pp_payment_control_configuration_contactor_fitted,
        &hf_zbee_zcl_pp_payment_control_configuration_standing_charge_configuration,
        &hf_zbee_zcl_pp_payment_control_configuration_emergency_standing_charge_configuration,
        &hf_zbee_zcl_pp_payment_control_configuration_debt_configuration,
        &hf_zbee_zcl_pp_payment_control_configuration_emergency_debt_configuration,
        &hf_zbee_zcl_pp_payment_control_configuration_reserved,
        NULL
};

static int* const zbee_zcl_pp_snapshot_payload_cause_flags[] = {
        &hf_zbee_zcl_pp_snapshot_payload_cause_general,
        &hf_zbee_zcl_pp_snapshot_payload_cause_end_of_billing_period,
        &hf_zbee_zcl_pp_snapshot_payload_cause_change_of_tariff_information,
        &hf_zbee_zcl_pp_snapshot_payload_cause_change_of_price_matrix,
        &hf_zbee_zcl_pp_snapshot_payload_cause_manually_triggered_from_client,
        &hf_zbee_zcl_pp_snapshot_payload_cause_change_of_tenancy,
        &hf_zbee_zcl_pp_snapshot_payload_cause_change_of_supplier,
        &hf_zbee_zcl_pp_snapshot_payload_cause_change_of_meter_mode,
        &hf_zbee_zcl_pp_snapshot_payload_cause_top_up_addition,
        &hf_zbee_zcl_pp_snapshot_payload_cause_debt_credit_addition,
        &hf_zbee_zcl_pp_snapshot_payload_cause_reserved,
        NULL
};

/* Initialize the subtree pointers */
#define ZBEE_ZCL_SE_PP_NUM_INDIVIDUAL_ETT             3
#define ZBEE_ZCL_SE_PP_NUM_PUBLISH_TOP_UP_LOG_ETT     30
#define ZBEE_ZCL_SE_PP_NUM_PUBLISH_DEBT_LOG_ETT       30
#define ZBEE_ZCL_SE_PP_NUM_TOTAL_ETT                  (ZBEE_ZCL_SE_PP_NUM_INDIVIDUAL_ETT + \
                                                       ZBEE_ZCL_SE_PP_NUM_PUBLISH_TOP_UP_LOG_ETT + \
                                                       ZBEE_ZCL_SE_PP_NUM_PUBLISH_DEBT_LOG_ETT)

static gint ett_zbee_zcl_pp = -1;
static gint ett_zbee_zcl_pp_payment_control_configuration = -1;
static gint ett_zbee_zcl_pp_snapshot_payload_cause = -1;
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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_pp_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_PP:
            proto_tree_add_item(tree, hf_zbee_zcl_pp_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;
        case ZBEE_ZCL_ATTR_ID_PP_PAYMENT_CONTROL_CONFIGURATION:
            proto_item_append_text(tree, ", Payment Control Configuration");
            proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_pp_payment_control_configuration,
                                   ett_zbee_zcl_pp_payment_control_configuration, zbee_zcl_pp_payment_control_configuration_flags, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;
        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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
    int length;

    /* Originating Device */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_consumer_top_up_originating_device, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* TopUp Code */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_pp_consumer_top_up_top_up_code, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &length);
    *offset += length;
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
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_pp_change_payment_mode_proposed_payment_control_configuration,
                           ett_zbee_zcl_pp_payment_control_configuration, zbee_zcl_pp_payment_control_configuration_flags, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_pp_get_prepay_snapshot_snapshot_cause,
                           ett_zbee_zcl_pp_snapshot_payload_cause, zbee_zcl_pp_snapshot_payload_cause_flags, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_total_snapshots_found, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_total_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Snapshot Cause */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_cause,
                           ett_zbee_zcl_pp_snapshot_payload_cause, zbee_zcl_pp_snapshot_payload_cause_flags, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Snapshot Payload Type */
    proto_tree_add_item(tree, hf_zbee_zcl_pp_publish_prepay_snapshot_snapshot_payload_type, tvb, *offset, 1, ENC_NA);
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
    gint length;
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
        proto_tree_add_item_ret_length(sub_tree, hf_zbee_zcl_pp_publish_top_up_log_top_up_code, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &length);
        *offset += length;

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

        { &hf_zbee_zcl_pp_consumer_top_up_top_up_code,
            { "TopUp Code", "zbee_zcl_se.pp.consumer_top_up.top_up_code", FT_UINT_BYTES, SEP_COLON, NULL,
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

        { &hf_zbee_zcl_pp_publish_top_up_log_top_up_code,
            { "TopUp Code", "zbee_zcl_se.pp.publish_top_up_log.top_up_code", FT_UINT_BYTES, SEP_COLON, NULL,
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

        { &hf_zbee_zcl_pp_payment_control_configuration,
            { "Payment Control Configuration", "zbee_zcl_se.pp.attr.payment_control_configuration", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_disconnection_enabled,
            { "Disconnection Enabled", "zbee_zcl_se.pp.attr.payment_control_configuration.disconnection_enabled", FT_BOOLEAN, 16, NULL,
            0x0001, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_prepayment_enabled,
            { "Prepayment Enabled", "zbee_zcl_se.pp.attr.payment_control_configuration.prepayment_enabled", FT_BOOLEAN, 16, NULL,
            0x0002, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_credit_management_enabled,
            { "Credit Management Enabled", "zbee_zcl_se.pp.attr.payment_control_configuration.credit_management_enabled", FT_BOOLEAN, 16, NULL,
            0x0004, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_credit_display_enabled,
            { "Credit Display Enabled", "zbee_zcl_se.pp.attr.payment_control_configuration.credit_display_enabled", FT_BOOLEAN, 16, NULL,
            0x0010, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_account_base,
            { "Account Base", "zbee_zcl_se.pp.attr.payment_control_configuration.account_base", FT_BOOLEAN, 16, NULL,
            0x0040, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_contactor_fitted,
            { "Contactor Fitted", "zbee_zcl_se.pp.attr.payment_control_configuration.contactor_fitted", FT_BOOLEAN, 16, NULL,
            0x0080, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_standing_charge_configuration,
            { "Standing Charge Configuration", "zbee_zcl_se.pp.attr.payment_control_configuration.standing_charge_configuration", FT_BOOLEAN, 16, NULL,
            0x0100, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_emergency_standing_charge_configuration,
            { "Emergency Standing Charge Configuration", "zbee_zcl_se.pp.attr.payment_control_configuration.emergency_standing_charge_configuration", FT_BOOLEAN, 16, NULL,
            0x0200, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_debt_configuration,
            { "Debt Configuration", "zbee_zcl_se.pp.attr.payment_control_configuration.debt_configuration", FT_BOOLEAN, 16, NULL,
            0x0400, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_emergency_debt_configuration,
            { "Emergency Debt Configuration", "zbee_zcl_se.pp.attr.payment_control_configuration.emergency_debt_configuration", FT_BOOLEAN, 16, NULL,
            0x0800, NULL, HFILL } },
        { &hf_zbee_zcl_pp_payment_control_configuration_reserved,
            { "Reserved", "zbee_zcl_se.pp.attr.payment_control_configuration.reserved", FT_UINT16, BASE_HEX, NULL,
            0xF028, NULL, HFILL } },

        { &hf_zbee_zcl_pp_snapshot_payload_cause_general,
            { "General", "zbee_zcl_se.pp.snapshot_payload_cause.general", FT_BOOLEAN, 32, NULL,
            0x00000001, NULL, HFILL } },
        { &hf_zbee_zcl_pp_snapshot_payload_cause_end_of_billing_period,
            { "End of Billing Period", "zbee_zcl_se.pp.snapshot_payload_cause.end_of_billing_period", FT_BOOLEAN, 32, NULL,
            0x00000002, NULL, HFILL } },
        { &hf_zbee_zcl_pp_snapshot_payload_cause_change_of_tariff_information,
            { "Change of Tariff Information", "zbee_zcl_se.pp.snapshot_payload_cause.change_of_tariff_information", FT_BOOLEAN, 32, NULL,
            0x00000008, NULL, HFILL } },
        { &hf_zbee_zcl_pp_snapshot_payload_cause_change_of_price_matrix,
            { "Change of Price Matrix", "zbee_zcl_se.pp.snapshot_payload_cause.change_of_price_matrix", FT_BOOLEAN, 32, NULL,
            0x00000010, NULL, HFILL } },
        { &hf_zbee_zcl_pp_snapshot_payload_cause_manually_triggered_from_client,
            { "Manually Triggered from Client", "zbee_zcl_se.pp.snapshot_payload_cause.manually_triggered_from_client", FT_BOOLEAN, 32, NULL,
            0x00000400, NULL, HFILL } },
        { &hf_zbee_zcl_pp_snapshot_payload_cause_change_of_tenancy,
            { "Change of Tenancy", "zbee_zcl_se.pp.snapshot_payload_cause.change_of_tenancy", FT_BOOLEAN, 32, NULL,
            0x00001000, NULL, HFILL } },
        { &hf_zbee_zcl_pp_snapshot_payload_cause_change_of_supplier,
            { "Change of Supplier", "zbee_zcl_se.pp.snapshot_payload_cause.change_of_supplier", FT_BOOLEAN, 32, NULL,
            0x00002000, NULL, HFILL } },
        { &hf_zbee_zcl_pp_snapshot_payload_cause_change_of_meter_mode,
            { "Change of (Meter) Mode", "zbee_zcl_se.pp.snapshot_payload_cause.change_of_meter_mode", FT_BOOLEAN, 32, NULL,
            0x00004000, NULL, HFILL } },
        { &hf_zbee_zcl_pp_snapshot_payload_cause_top_up_addition,
            { "TopUp addition", "zbee_zcl_se.pp.snapshot_payload_cause.top_up_addition", FT_BOOLEAN, 32, NULL,
            0x00040000, NULL, HFILL } },
        { &hf_zbee_zcl_pp_snapshot_payload_cause_debt_credit_addition,
            { "Debt/Credit addition", "zbee_zcl_se.pp.snapshot_payload_cause.debt_credit_addition", FT_BOOLEAN, 32, NULL,
            0x00080000, NULL, HFILL } },
        { &hf_zbee_zcl_pp_snapshot_payload_cause_reserved,
            { "Reserved", "zbee_zcl_se.pp.snapshot_payload_cause.reserved", FT_UINT32, BASE_HEX, NULL,
            0xFFF38BE4, NULL, HFILL } },
    };

    /* ZCL Prepayment subtrees */
    gint *ett[ZBEE_ZCL_SE_PP_NUM_TOTAL_ETT];
    ett[0] = &ett_zbee_zcl_pp;
    ett[1] = &ett_zbee_zcl_pp_payment_control_configuration;
    ett[2] = &ett_zbee_zcl_pp_snapshot_payload_cause;

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
    register_dissector(ZBEE_PROTOABBREV_ZCL_PRE_PAYMENT, dissect_zbee_zcl_pp, proto_zbee_zcl_pp);
} /*proto_register_zbee_zcl_pp*/

/**
 *Hands off the ZCL Prepayment dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_pp(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_PRE_PAYMENT,
                            proto_zbee_zcl_pp,
                            ett_zbee_zcl_pp,
                            ZBEE_ZCL_CID_PRE_PAYMENT,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_pp_attr_id,
                            -1,
                            hf_zbee_zcl_pp_srv_rx_cmd_id,
                            hf_zbee_zcl_pp_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_pp_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_pp*/

/* ########################################################################## */
/* #### (0x0706) ENERGY MANAGEMENT CLUSTER ################################## */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_energy_management_attr_names_VALUE_STRING_LIST(XXX) \
/* Block Threshold (Delivered) Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_ENERGY_MANAGEMENT_LOAD_CONTROL_STATE,              0x0000, "Load Control State" ) \
    XXX(ZBEE_ZCL_ATTR_ID_ENERGY_MANAGEMENT_CURRENT_EVENT_ID,                0x0001, "Current Event ID" ) \
    XXX(ZBEE_ZCL_ATTR_ID_ENERGY_MANAGEMENT_CURRENT_EVENT_STATUS,            0x0002, "Current Event Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_ENERGY_MANAGEMENT_CONFORMANCE_LEVEL,               0x0003, "Conformance Level" ) \
    XXX(ZBEE_ZCL_ATTR_ID_ENERGY_MANAGEMENT_MINIMUM_OFF_TIME,                0x0004, "Minimum Off Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_ENERGY_MANAGEMENT_MINIMUM_ON_TIME,                 0x0005, "Minimum On Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_ENERGY_MANAGEMENT_MINIMUM_CYCLE_PERIOD,            0x0006, "Minimum Cycle Period" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_ENERGY_MANAGEMENT,           0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_energy_management_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_energy_management_attr_names);

/* Server Commands Received */
#define zbee_zcl_energy_management_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_ENERGY_MANAGEMENT_MANAGE_EVENT,                0x00, "Manage Event" )

VALUE_STRING_ENUM(zbee_zcl_energy_management_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_energy_management_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_energy_management_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_ENERGY_MANAGEMENT_REPORT_EVENT_STATUS,              0x00, "Report Event Status" )

VALUE_STRING_ENUM(zbee_zcl_energy_management_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_energy_management_srv_tx_cmd_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_energy_management(void);
void proto_reg_handoff_zbee_zcl_energy_management(void);

static void dissect_zbee_zcl_energy_management_manage_event             (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zbee_zcl_energy_management_report_event_status      (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/* Attribute Dissector Helpers */
static void dissect_zcl_energy_management_attr_data                     (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_energy_management = -1;

static int hf_zbee_zcl_energy_management_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_energy_management_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_energy_management_attr_id = -1;
static int hf_zbee_zcl_energy_management_attr_reporting_status = -1;
static int hf_zbee_zcl_energy_management_issuer_event_id = -1;
static int hf_zbee_zcl_energy_management_device_class = -1;
static int hf_zbee_zcl_energy_management_device_class_hvac_compressor_or_furnace = -1;
static int hf_zbee_zcl_energy_management_device_class_strip_heaters_baseboard_heaters = -1;
static int hf_zbee_zcl_energy_management_device_class_water_heater = -1;
static int hf_zbee_zcl_energy_management_device_class_pool_pump_spa_jacuzzi = -1;
static int hf_zbee_zcl_energy_management_device_class_smart_appliances = -1;
static int hf_zbee_zcl_energy_management_device_class_irrigation_pump = -1;
static int hf_zbee_zcl_energy_management_device_class_managed_c_i_loads= -1;
static int hf_zbee_zcl_energy_management_device_class_simple_misc_loads = -1;
static int hf_zbee_zcl_energy_management_device_class_exterior_lighting = -1;
static int hf_zbee_zcl_energy_management_device_class_interior_lighting = -1;
static int hf_zbee_zcl_energy_management_device_class_electric_vehicle = -1;
static int hf_zbee_zcl_energy_management_device_class_generation_systems = -1;
static int hf_zbee_zcl_energy_management_device_class_reserved = -1;
static int hf_zbee_zcl_energy_management_utility_enrollment_group = -1;
static int hf_zbee_zcl_energy_management_action_required = -1;
static int hf_zbee_zcl_energy_management_action_required_opt_out_of_event = -1;
static int hf_zbee_zcl_energy_management_action_required_opt_into_event = -1;
static int hf_zbee_zcl_energy_management_action_required_disable_duty_cycling = -1;
static int hf_zbee_zcl_energy_management_action_required_enable_duty_cycling = -1;
static int hf_zbee_zcl_energy_management_action_required_reserved = -1;

static int hf_zbee_zcl_energy_management_report_event_issuer_event_id = -1;
static int hf_zbee_zcl_energy_management_report_event_event_status = -1;
static int hf_zbee_zcl_energy_management_report_event_event_status_time = -1;
static int hf_zbee_zcl_energy_management_report_event_criticality_level_applied = -1;
static int hf_zbee_zcl_energy_management_report_event_cooling_temp_set_point_applied = -1;
static int hf_zbee_zcl_energy_management_report_event_heating_temp_set_point_applied = -1;
static int hf_zbee_zcl_energy_management_report_event_average_load_adjustment_percentage = -1;
static int hf_zbee_zcl_energy_management_report_event_duty_cycle = -1;
static int hf_zbee_zcl_energy_management_report_event_event_control = -1;
static int hf_zbee_zcl_energy_management_report_event_event_control_randomize_start_time = -1;
static int hf_zbee_zcl_energy_management_report_event_event_control_randomize_duration_time = -1;
static int hf_zbee_zcl_energy_management_report_event_event_control_reserved = -1;


static int* const zbee_zcl_energy_management_device_classes[] = {
    &hf_zbee_zcl_energy_management_device_class_hvac_compressor_or_furnace,
    &hf_zbee_zcl_energy_management_device_class_strip_heaters_baseboard_heaters,
    &hf_zbee_zcl_energy_management_device_class_water_heater,
    &hf_zbee_zcl_energy_management_device_class_pool_pump_spa_jacuzzi,
    &hf_zbee_zcl_energy_management_device_class_smart_appliances,
    &hf_zbee_zcl_energy_management_device_class_irrigation_pump,
    &hf_zbee_zcl_energy_management_device_class_managed_c_i_loads,
    &hf_zbee_zcl_energy_management_device_class_simple_misc_loads,
    &hf_zbee_zcl_energy_management_device_class_exterior_lighting,
    &hf_zbee_zcl_energy_management_device_class_interior_lighting,
    &hf_zbee_zcl_energy_management_device_class_electric_vehicle,
    &hf_zbee_zcl_energy_management_device_class_generation_systems,
    &hf_zbee_zcl_energy_management_device_class_reserved,
    NULL
};

static int* const zbee_zcl_energy_management_action_required[] = {
    &hf_zbee_zcl_energy_management_action_required_opt_out_of_event,
    &hf_zbee_zcl_energy_management_action_required_opt_into_event,
    &hf_zbee_zcl_energy_management_action_required_disable_duty_cycling,
    &hf_zbee_zcl_energy_management_action_required_enable_duty_cycling,
    &hf_zbee_zcl_energy_management_action_required_reserved,
    NULL
};

static int* const hf_zbee_zcl_energy_management_event_control_flags[] = {
    &hf_zbee_zcl_energy_management_report_event_event_control_randomize_start_time,
    &hf_zbee_zcl_energy_management_report_event_event_control_randomize_duration_time,
    &hf_zbee_zcl_energy_management_report_event_event_control_reserved,
    NULL
};

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_energy_management = -1;
static gint ett_zbee_zcl_energy_management_device_class = -1;
static gint ett_zbee_zcl_energy_management_actions_required = -1;
static gint ett_zbee_zcl_energy_management_report_event_event_control = -1;

static const range_string zbee_zcl_energy_management_load_control_event_criticality_level[] = {
    { 0x0, 0x0,   "Reserved" },
    { 0x1, 0x1,   "Green" },
    { 0x2, 0x2,   "1" },
    { 0x3, 0x3,   "2" },
    { 0x4, 0x4,   "3" },
    { 0x5, 0x5,   "4" },
    { 0x6, 0x6,   "5" },
    { 0x7, 0x7,   "Emergency" },
    { 0x8, 0x8,   "Planned Outage" },
    { 0x9, 0x9,   "Service Disconnect" },
    { 0x0A, 0x0F, "Utility Defined" },
    { 0x10, 0xFF, "Reserved" },
    { 0, 0, NULL }
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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_energy_management_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_ENERGY_MANAGEMENT:
            proto_tree_add_item(tree, hf_zbee_zcl_energy_management_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }
} /*dissect_zcl_energy_management_attr_data*/

/**
 *ZigBee ZCL Energy Management cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zbee_zcl_energy_management_manage_event(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_energy_management_issuer_event_id, tvb,
                        *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Device Class */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_energy_management_device_class, ett_zbee_zcl_energy_management_device_class,
                           zbee_zcl_energy_management_device_classes, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Utility Enrollment Group */
    proto_tree_add_item(tree, hf_zbee_zcl_energy_management_utility_enrollment_group, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Action(s) Required */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_energy_management_action_required, ett_zbee_zcl_energy_management_actions_required,
                           zbee_zcl_energy_management_action_required, ENC_NA);
    *offset += 1;
}

/**
 *ZigBee ZCL Energy Management cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zbee_zcl_energy_management_report_event_status(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Event Control */
    nstime_t event_status_time;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_energy_management_report_event_issuer_event_id, tvb,
                        *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Event Status */
    proto_tree_add_item(tree, hf_zbee_zcl_energy_management_report_event_event_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Event Status Time */
    event_status_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    event_status_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_energy_management_report_event_event_status_time, tvb, *offset, 4, &event_status_time);
    *offset += 4;

    /* Criticality Level Applied */
    proto_tree_add_item(tree, hf_zbee_zcl_energy_management_report_event_criticality_level_applied, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Cooling Temperature Set Point Applied */
    proto_tree_add_item(tree, hf_zbee_zcl_energy_management_report_event_cooling_temp_set_point_applied, tvb,
                        *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Heating Temperature Set Point Applied */
    proto_tree_add_item(tree, hf_zbee_zcl_energy_management_report_event_heating_temp_set_point_applied, tvb,
                        *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Average Load Adjustment Percentage Applied */
    proto_tree_add_item(tree, hf_zbee_zcl_energy_management_report_event_average_load_adjustment_percentage, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Duty Cycle Applied */
    proto_tree_add_item(tree, hf_zbee_zcl_energy_management_report_event_duty_cycle, tvb,
                        *offset, 1, ENC_NA);
    *offset += 1;

    /* Event Control */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_energy_management_report_event_event_control, ett_zbee_zcl_energy_management_report_event_event_control,
                           hf_zbee_zcl_energy_management_event_control_flags, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /*dissect_zbee_zcl_energy_management_report_event_status*/

/**
 *ZigBee ZCL Energy Management cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_energy_management(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_energy_management_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_energy_management_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_energy_management, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_ENERGY_MANAGEMENT_MANAGE_EVENT:
                    dissect_zbee_zcl_energy_management_manage_event(tvb, tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_energy_management_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_energy_management_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_energy_management, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_ENERGY_MANAGEMENT_REPORT_EVENT_STATUS:
                    dissect_zbee_zcl_energy_management_report_event_status(tvb, tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_energy_management*/

/**
 *This function registers the ZCL Energy_Management dissector
 *
*/
void
proto_register_zbee_zcl_energy_management(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_energy_management_attr_id,
            { "Attribute", "zbee_zcl_se.energy_management.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_energy_management_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.energy_management.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.energy_management.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_energy_management_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.energy_management.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_energy_management_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.energy_management.issuer_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class,
            { "Device Class", "zbee_zcl_se.energy_management.device_class",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_hvac_compressor_or_furnace,
            { "HVAC Compressor or Furnace", "zbee_zcl_se.energy_management.device_class.hvac_compressor_or_furnace",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_strip_heaters_baseboard_heaters,
            { "Strip Heaters/Baseboard Heaters", "zbee_zcl_se.energy_management.device_class.strip_heaters_baseboard_heaters",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_water_heater,
            { "Water Heater", "zbee_zcl_se.energy_management.device_class.water_heater",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_pool_pump_spa_jacuzzi,
            { "Pool Pump/Spa/Jacuzzi", "zbee_zcl_se.energy_management.device_class.pool_pump_spa_jacuzzi",
            FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_smart_appliances,
            { "Smart Appliances", "zbee_zcl_se.energy_management.device_class.smart_appliances",
            FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_irrigation_pump,
            { "Irrigation Pump", "zbee_zcl_se.energy_management.device_class.irrigation_pump",
            FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_managed_c_i_loads,
            { "Managed Commercial & Industrial (C&I) loads", "zbee_zcl_se.energy_management.device_class.managed_c_i_loads",
            FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_simple_misc_loads,
            { "Simple misc. (Residential On/Off) loads", "zbee_zcl_se.energy_management.device_class.simple_misc_loads",
            FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_exterior_lighting,
            { "Exterior Lighting", "zbee_zcl_se.energy_management.device_class.exterior_lighting",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_interior_lighting,
            { "Interior Lighting", "zbee_zcl_se.energy_management.device_class.interior_lighting",
            FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_electric_vehicle,
            { "Electric Vehicle", "zbee_zcl_se.energy_management.device_class.electric_vehicle",
            FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_generation_systems,
            { "Generation Systems", "zbee_zcl_se.energy_management.device_class.generation_systems",
            FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_device_class_reserved ,
            { "Reserved", "zbee_zcl_se.energy_management.device_class.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_utility_enrollment_group,
            { "Utility Enrollment Group", "zbee_zcl_se.energy_management.utility_enrollment_group",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_action_required,
            { "Action(s) Required", "zbee_zcl_se.energy_management.action_required",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_action_required_opt_out_of_event,
            { "Opt Out of Event", "zbee_zcl_se.energy_management.action_required.opt_out_of_event",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_action_required_opt_into_event,
            { "Opt Into Event", "zbee_zcl_se.energy_management.action_required.opt_into_event",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_action_required_disable_duty_cycling,
            { "Disable Duty Cycling", "zbee_zcl_se.energy_management.action_required.disable_duty_cycling",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_action_required_enable_duty_cycling,
            { "Enable Duty Cycling", "zbee_zcl_se.energy_management.action_required.enable_duty_cycling",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_action_required_reserved,
            { "Reserved", "zbee_zcl_se.energy_management.action_required.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.energy_management.report_event.issuer_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_event_status,
            { "Event Status", "zbee_zcl_se.energy_management.report_event.event_status",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_event_status_time,
            { "Event Status Time", "zbee_zcl_se.energy_management.report_event.event_status_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_criticality_level_applied ,
            { "Criticality Level Applied", "zbee_zcl_se.energy_management.report_event.criticality_level_applied",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_zcl_energy_management_load_control_event_criticality_level), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_cooling_temp_set_point_applied,
            { "Cooling Temperature Set Point Applied", "zbee_zcl_se.energy_management.report_event.cooling_temperature_set_point_applied",
            FT_INT16, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_temp_set_point), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_heating_temp_set_point_applied,
            { "Heating Temperature Set Point Applied", "zbee_zcl_se.energy_management.report_event.heating_temperature_set_point_applied",
            FT_INT16, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_temp_set_point), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_average_load_adjustment_percentage ,
            { "Average Load Adjustment Percentage Applied", "zbee_zcl_se.energy_management.report_event.average_load_adjustment_percentage_applied",
            FT_INT8, BASE_CUSTOM, CF_FUNC(decode_zcl_drlc_average_load_adjustment_percentage), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_duty_cycle,
            { "Duty Cycle Applied", "zbee_zcl_se.energy_management.report_event.duty_cycle_applied",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_event_control,
            { "Event Control", "zbee_zcl_se.energy_management.report_event.event_control",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_event_control_randomize_start_time,
            { "Randomize Start time", "zbee_zcl_se.energy_management.report_event.randomize_start_time",
            FT_BOOLEAN, 8, TFS(&zbee_zcl_drlc_randomize_start_tfs), 0x01, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_event_control_randomize_duration_time,
            { "Randomize Duration time", "zbee_zcl_se.energy_management.report_event.randomize_duration_time",
            FT_BOOLEAN, 8, TFS(&zbee_zcl_drlc_randomize_duration_tfs), 0x02, NULL, HFILL } },

        { &hf_zbee_zcl_energy_management_report_event_event_control_reserved,
            { "Reserved", "zbee_zcl_se.energy_management.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC, NULL, HFILL } },
    };

    /* ZCL Energy_Management subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_energy_management,
        &ett_zbee_zcl_energy_management_device_class,
        &ett_zbee_zcl_energy_management_actions_required,
        &ett_zbee_zcl_energy_management_report_event_event_control,
    };

    /* Register the ZigBee ZCL Energy Management cluster protocol name and description */
    proto_zbee_zcl_energy_management = proto_register_protocol("ZigBee ZCL Energy Management", "ZCL Energy Management", ZBEE_PROTOABBREV_ZCL_ENERGY_MANAGEMENT);
    proto_register_field_array(proto_zbee_zcl_energy_management, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Energy Management dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_ENERGY_MANAGEMENT, dissect_zbee_zcl_energy_management, proto_zbee_zcl_energy_management);
} /*proto_register_zbee_zcl_energy_management*/

/**
 *Hands off the ZCL Energy_Management dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_energy_management(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_ENERGY_MANAGEMENT,
                            proto_zbee_zcl_energy_management,
                            ett_zbee_zcl_energy_management,
                            ZBEE_ZCL_CID_ENERGY_MANAGEMENT,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_energy_management_attr_id,
                            -1,
                            hf_zbee_zcl_energy_management_srv_rx_cmd_id,
                            hf_zbee_zcl_energy_management_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_energy_management_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_energy_management*/


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
static void dissect_zcl_calendar_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

/* Command Dissector Helpers */
static void dissect_zcl_calendar_get_calendar (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_calendar_get_day_profiles(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_calendar_get_week_profiles(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_calendar_get_seasons(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_calendar_get_special_days(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_calendar_publish_calendar(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_calendar_publish_day_profile(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_calendar_publish_week_profile(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_calendar_publish_seasons(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_calendar_publish_special_days(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_calendar_cancel(tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_calendar = -1;

static int hf_zbee_zcl_calendar_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_calendar_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_calendar_attr_id = -1;
static int hf_zbee_zcl_calendar_attr_reporting_status = -1;
static int hf_zbee_zcl_calendar_type = -1;
static int hf_zbee_zcl_calendar_start_time = -1;
static int hf_zbee_zcl_calendar_earliest_start_time = -1;
static int hf_zbee_zcl_calendar_time_reference = -1;
static int hf_zbee_zcl_calendar_name = -1;
static int hf_zbee_zcl_calendar_command_index = -1;
static int hf_zbee_zcl_calendar_date_year = -1;
static int hf_zbee_zcl_calendar_date_month = -1;
static int hf_zbee_zcl_calendar_date_month_day = -1;
static int hf_zbee_zcl_calendar_date_week_day = -1;
static int hf_zbee_zcl_calendar_provider_id = -1;
static int hf_zbee_zcl_calendar_issuer_event_id = -1;
static int hf_zbee_zcl_calendar_min_issuer_event_id = -1;
static int hf_zbee_zcl_calendar_issuer_calendar_id = -1;
static int hf_zbee_zcl_calendar_day_id = -1;
static int hf_zbee_zcl_calendar_day_id_ref = -1;
static int hf_zbee_zcl_calendar_day_id_ref_monday = -1;
static int hf_zbee_zcl_calendar_day_id_ref_tuesday = -1;
static int hf_zbee_zcl_calendar_day_id_ref_wednesday = -1;
static int hf_zbee_zcl_calendar_day_id_ref_thursday = -1;
static int hf_zbee_zcl_calendar_day_id_ref_friday = -1;
static int hf_zbee_zcl_calendar_day_id_ref_saturday = -1;
static int hf_zbee_zcl_calendar_day_id_ref_sunday = -1;
static int hf_zbee_zcl_calendar_week_id = -1;
static int hf_zbee_zcl_calendar_week_id_ref = -1;
static int hf_zbee_zcl_calendar_start_day_id = -1;
static int hf_zbee_zcl_calendar_start_week_id = -1;
static int hf_zbee_zcl_calendar_number_of_calendars = -1;
static int hf_zbee_zcl_calendar_number_of_events = -1;
static int hf_zbee_zcl_calendar_number_of_days = -1;
static int hf_zbee_zcl_calendar_number_of_weeks = -1;
static int hf_zbee_zcl_calendar_number_of_seasons = -1;
static int hf_zbee_zcl_calendar_number_of_day_profiles = -1;
static int hf_zbee_zcl_calendar_number_of_week_profiles = -1;
static int hf_zbee_zcl_calendar_total_number_of_schedule_entries = -1;
static int hf_zbee_zcl_calendar_total_number_of_special_days = -1;
static int hf_zbee_zcl_calendar_total_number_of_commands = -1;
static int hf_zbee_zcl_calendar_schedule_entry_start_time = -1;
static int hf_zbee_zcl_calendar_schedule_entry_price_tier = -1;
static int hf_zbee_zcl_calendar_schedule_entry_friendly_credit_enable = -1;
static int hf_zbee_zcl_calendar_schedule_entry_auxiliary_load_switch_state = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_calendar = -1;
static gint ett_zbee_zcl_calendar_special_day_date = -1;
static gint ett_zbee_zcl_calendar_season_start_date = -1;

#define zbee_zcl_calendar_type_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CALENDAR_TYPE_DELIVERED,                                0x00, "Delivered Calendar" ) \
    XXX(ZBEE_ZCL_CALENDAR_TYPE_RECEIVED,                                 0x01, "Received Calendar" ) \
    XXX(ZBEE_ZCL_CALENDAR_TYPE_DELIVERED_AND_RECEIVED,                   0x02, "Delivered and Received Calendar" ) \
    XXX(ZBEE_ZCL_CALENDAR_TYPE_FRIENDLY_CREDIT,                          0x03, "Friendly Credit Calendar" ) \
    XXX(ZBEE_ZCL_CALENDAR_TYPE_AUXILIARY_LOAD_SWITCH,                    0x04, "Auxiliary Load Switch Calendar" )

VALUE_STRING_ENUM(zbee_zcl_calendar_type_names);
VALUE_STRING_ARRAY(zbee_zcl_calendar_type_names);

#define zbee_zcl_calendar_time_reference_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CALENDAR_TIME_REFERENCE_UTC_TIME,                     0x00, "UTC Time" ) \
    XXX(ZBEE_ZCL_CALENDAR_TIME_REFERENCE_STANDARD_TIME,                0x01, "Standard Time" ) \
    XXX(ZBEE_ZCL_CALENDAR_TIME_REFERENCE_LOCAL_TIME,                   0x02, "Local Time" )

VALUE_STRING_ENUM(zbee_zcl_calendar_time_reference_names);
VALUE_STRING_ARRAY(zbee_zcl_calendar_time_reference_names);

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
 *@param client_attr ZCL client
 */
static void
dissect_zcl_calendar_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_CAL:
            proto_tree_add_item(tree, hf_zbee_zcl_calendar_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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
                        val_to_str_const(cmd_id, zbee_zcl_calendar_srv_rx_cmd_names, "Unknown Command"),
                        zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_calendar_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_calendar, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_CAL_GET_CALENDAR:
                    dissect_zcl_calendar_get_calendar(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_GET_DAY_PROFILES:
                    dissect_zcl_calendar_get_day_profiles(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_GET_WEEK_PROFILES:
                    dissect_zcl_calendar_get_week_profiles(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_GET_SEASONS:
                    dissect_zcl_calendar_get_seasons(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_GET_SPECIAL_DAYS:
                    dissect_zcl_calendar_get_special_days(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_GET_CALENDAR_CANCELLATION:
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
                        val_to_str_const(cmd_id, zbee_zcl_calendar_srv_tx_cmd_names, "Unknown Command"),
                        zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_calendar_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_calendar, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_CAL_PUBLISH_CALENDAR:
                    dissect_zcl_calendar_publish_calendar(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_PUBLISH_DAY_PROFILE:
                    dissect_zcl_calendar_publish_day_profile(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_PUBLISH_WEEK_PROFILE:
                    dissect_zcl_calendar_publish_week_profile(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_PUBLISH_SEASONS:
                    dissect_zcl_calendar_publish_seasons(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_PUBLISH_SPECIAL_DAYS:
                    dissect_zcl_calendar_publish_special_days(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_CAL_CANCEL_CALENDAR:
                    dissect_zcl_calendar_cancel(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_calendar*/

/**
 *This function manages the Get Calendar payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_get_calendar(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t earliest_start_time;

    /* Earliest Start Time */
    earliest_start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    earliest_start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_calendar_earliest_start_time, tvb, *offset, 4, &earliest_start_time);
    *offset += 4;

    /* Min Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_min_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Number of Calendars */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_number_of_calendars, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Calendar Type */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_calendar_get_calendar*/

/**
 *This function manages the Get Day Profiles payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_get_day_profiles(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Day Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_start_day_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Number of Days */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_number_of_days, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_calendar_get_day_profiles*/

/**
 *This function manages the Get Week Profiles payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_get_week_profiles(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Week Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_start_week_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Number of Weeks */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_number_of_weeks, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_calendar_get_week_profiles*/

/**
 *This function manages the Get Seasons payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_get_seasons(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_calendar_get_seasons*/

/**
 *This function manages the Get Special Days payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_get_special_days(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_calendar_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Number of Events */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_number_of_events, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Calendar Type */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_calendar_get_special_days*/

/**
 *This function manages the Publish Calendar payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_publish_calendar(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;
    int length;

    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_calendar_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Calendar Type */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Calendar Time Reference */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_time_reference, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Calendar Name */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_calendar_name, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &length);
    *offset += length;

    /* Number of Seasons */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_number_of_seasons, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Number of Week Profiles */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_number_of_week_profiles, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Number of Day Profiles */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_number_of_day_profiles, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_calendar_publish_calendar*/

/**
 *This function manages the Publish Day Profile payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_publish_day_profile(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8   schedule_entries_count;
    guint8   calendar_type;

    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Day ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_day_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Schedule Entries */
    schedule_entries_count = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_total_number_of_schedule_entries, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_total_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Calendar Type */
    calendar_type = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    for (gint i = 0; tvb_reported_length_remaining(tvb, *offset) >= 3 && i < schedule_entries_count; i++) {
        /* Start Time */
        proto_tree_add_item(tree, hf_zbee_zcl_calendar_schedule_entry_start_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        switch (calendar_type) {
            /* Rate Start Time */
            case ZBEE_ZCL_CALENDAR_TYPE_DELIVERED:
            case ZBEE_ZCL_CALENDAR_TYPE_RECEIVED:
            case ZBEE_ZCL_CALENDAR_TYPE_DELIVERED_AND_RECEIVED:
                /* Price Tier */
                proto_tree_add_item(tree, hf_zbee_zcl_calendar_schedule_entry_price_tier, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;

            /* Friendly Credit Start Time */
            case ZBEE_ZCL_CALENDAR_TYPE_FRIENDLY_CREDIT:
                /* Price Tier */
                proto_tree_add_item(tree, hf_zbee_zcl_calendar_schedule_entry_friendly_credit_enable, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;

            /* Auxiliary Load Start Time */
            case ZBEE_ZCL_CALENDAR_TYPE_AUXILIARY_LOAD_SWITCH:
                /* Price Tier */
                proto_tree_add_item(tree, hf_zbee_zcl_calendar_schedule_entry_auxiliary_load_switch_state, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;
        }
    }
} /*dissect_zcl_calendar_publish_day_profile*/

/**
 *This function manages the Publish Week Profile payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_publish_week_profile(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Week ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_week_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Day ID Ref Monday */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_day_id_ref_monday, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Day ID Ref Tuesday */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_day_id_ref_tuesday, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Day ID Ref Wednesday */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_day_id_ref_wednesday, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Day ID Ref Thursday */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_day_id_ref_thursday, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Day ID Ref Friday */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_day_id_ref_friday, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Day ID Ref Saturday */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_day_id_ref_saturday, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Day ID Ref Sunday */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_day_id_ref_sunday, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_calendar_publish_week_profile*/

/**
 *This function manages the Publish Season Profile payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_publish_seasons(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_total_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    for (gint i = 0; tvb_reported_length_remaining(tvb, *offset) >= 5; i++) {
        /* Season Start Date */
        dissect_zcl_date(tvb, tree, offset, ett_zbee_zcl_calendar_season_start_date, "Season Start Date", hf_zbee_zcl_calendar_date_year, hf_zbee_zcl_calendar_date_month, hf_zbee_zcl_calendar_date_month_day, hf_zbee_zcl_calendar_date_week_day);

        /* Week ID Ref */
        proto_tree_add_item(tree, hf_zbee_zcl_calendar_week_id_ref, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }
} /*dissect_zcl_calendar_publish_seasons*/

/**
 *This function manages the Publish Special Days payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_publish_special_days(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8   total_special_days_count;
    nstime_t start_time;

    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_calendar_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Calendar Type */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Special Days */
    total_special_days_count = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_total_number_of_special_days, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Number of Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_total_number_of_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    for (gint i = 0; tvb_reported_length_remaining(tvb, *offset) >= 5 && i < total_special_days_count; i++) {
        /* Special Day Date */
        dissect_zcl_date(tvb, tree, offset, ett_zbee_zcl_calendar_special_day_date, "Special Day Date", hf_zbee_zcl_calendar_date_year, hf_zbee_zcl_calendar_date_month, hf_zbee_zcl_calendar_date_month_day, hf_zbee_zcl_calendar_date_week_day);

        /* Day ID Ref */
        proto_tree_add_item(tree, hf_zbee_zcl_calendar_day_id_ref, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }
} /*dissect_zcl_calendar_publish_special_days*/

/**
 *This function manages the Cancel Calendar payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_calendar_cancel(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_issuer_calendar_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Calendar Type */
    proto_tree_add_item(tree, hf_zbee_zcl_calendar_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_calendar_cancel*/

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

        { &hf_zbee_zcl_calendar_type,
          { "Calendar Type", "zbee_zcl_se.calendar.type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_calendar_type_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_start_time,
            { "Start Time", "zbee_zcl_se.calendar.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_earliest_start_time,
            { "Earliest Start Time", "zbee_zcl_se.calendar.earliest_start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_time_reference,
          { "Calendar Time Reference", "zbee_zcl_se.calendar.time_reference", FT_UINT8, BASE_HEX, VALS(zbee_zcl_calendar_time_reference_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_name,
            { "Calendar Name", "zbee_zcl_se.calendar.name", FT_UINT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_command_index,
            { "Command Index", "zbee_zcl_se.calendar.command_index", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_date_year,
            { "Year", "zbee_zcl_se.calendar.date.year", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_date_month,
            { "Month", "zbee_zcl_se.calendar.date.month", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_date_month_day,
            { "Month Day", "zbee_zcl_se.calendar.date.month_day", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_date_week_day,
            { "Week Day", "zbee_zcl_se.calendar.date.week_day", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_provider_id,
            { "Provider ID", "zbee_zcl_se.calendar.provider_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.calendar.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_min_issuer_event_id,
            { "Min. Issuer Event ID", "zbee_zcl_se.calendar.min_issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_issuer_calendar_id,
            { "Issuer Calendar ID", "zbee_zcl_se.calendar.issuer_calendar_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_day_id,
            { "Day ID", "zbee_zcl_se.calendar.day_id", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_day_id_ref,
            { "Day ID Ref", "zbee_zcl_se.calendar.day_id_ref", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_day_id_ref_monday,
            { "Day ID Ref Monday", "zbee_zcl_se.calendar.day_id_ref_monday", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_day_id_ref_tuesday,
            { "Day ID Ref Tuesday", "zbee_zcl_se.calendar.day_id_ref_tuesday", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_day_id_ref_wednesday,
            { "Day ID Ref Wednesday", "zbee_zcl_se.calendar.day_id_ref_wednesday", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_day_id_ref_thursday,
            { "Day ID Ref Thursday", "zbee_zcl_se.calendar.day_id_ref_thursday", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_day_id_ref_friday,
            { "Day ID Ref Friday", "zbee_zcl_se.calendar.day_id_ref_friday", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_day_id_ref_saturday,
            { "Day ID Ref Saturday", "zbee_zcl_se.calendar.day_id_ref_saturday", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_day_id_ref_sunday,
            { "Day ID Ref Sunday", "zbee_zcl_se.calendar.day_id_ref_sunday", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_week_id,
            { "Week ID", "zbee_zcl_se.calendar.week_id", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_week_id_ref,
            { "Week ID Ref", "zbee_zcl_se.calendar.week_id_ref", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_start_day_id,
            { "Start Day ID", "zbee_zcl_se.calendar.start_day_id", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_start_week_id,
            { "Start Week ID", "zbee_zcl_se.calendar.start_week_id", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_number_of_calendars,
            { "Number of Calendars", "zbee_zcl_se.calendar.number_of_calendars", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_number_of_events,
            { "Number of Events", "zbee_zcl_se.calendar.number_of_events", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_number_of_days,
            { "Number of Days", "zbee_zcl_se.calendar.number_of_days", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_number_of_weeks,
            { "Number of Weeks", "zbee_zcl_se.calendar.number_of_weeks", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_number_of_seasons,
            { "Number of Seasons", "zbee_zcl_se.calendar.number_of_seasons", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_number_of_day_profiles,
            { "Number of Day Profiles", "zbee_zcl_se.calendar.number_of_day_profiles", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_number_of_week_profiles,
            { "Number of Week Profiles", "zbee_zcl_se.calendar.number_of_week_profiles", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_total_number_of_schedule_entries,
            { "Total Number of Schedule Entries", "zbee_zcl_se.calendar.total_number_of_schedule_entries", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_total_number_of_special_days,
            { "Total Number of Special Days", "zbee_zcl_se.calendar.total_number_of_special_days", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_total_number_of_commands,
            { "Total Number of Commands", "zbee_zcl_se.calendar.total_number_of_commands", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_schedule_entry_start_time,
            { "Start Time", "zbee_zcl_se.calendar.schedule_entry.start_time", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_schedule_entry_price_tier,
            { "Price Tier", "zbee_zcl_se.calendar.schedule_entry.price_tier", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_schedule_entry_friendly_credit_enable,
          { "Friendly Credit Enable", "zbee_zcl_se.calendar.schedule_entry.friendly_credit_enable", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_calendar_schedule_entry_auxiliary_load_switch_state,
            { "Auxiliary Load Switch State", "zbee_zcl_se.calendar.schedule_entry.auxiliary_load_switch_state", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

    };

    /* ZCL Calendar subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_calendar,
        &ett_zbee_zcl_calendar_special_day_date,
        &ett_zbee_zcl_calendar_season_start_date,
    };

    /* Register the ZigBee ZCL Calendar cluster protocol name and description */
    proto_zbee_zcl_calendar = proto_register_protocol("ZigBee ZCL Calendar", "ZCL Calendar", ZBEE_PROTOABBREV_ZCL_CALENDAR);
    proto_register_field_array(proto_zbee_zcl_calendar, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Calendar dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_CALENDAR, dissect_zbee_zcl_calendar, proto_zbee_zcl_calendar);
} /*proto_register_zbee_zcl_calendar*/

/**
 *Hands off the ZCL Calendar dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_calendar(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_CALENDAR,
                            proto_zbee_zcl_calendar,
                            ett_zbee_zcl_calendar,
                            ZBEE_ZCL_CID_CALENDAR,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_calendar_attr_id,
                            -1,
                            hf_zbee_zcl_calendar_srv_rx_cmd_id,
                            hf_zbee_zcl_calendar_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_calendar_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_calendar*/

/* ----------------------- Daily Schedule cluster ---------------------- */
/* Attributes */
#define zbee_zcl_daily_schedule_attr_names_VALUE_STRING_LIST(XXX) \
/* Auxiliary Switch Label Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_AUX_SWITCH_1_LABEL,                0x0000, "Aux Switch 1 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_AUX_SWITCH_2_LABEL,                0x0001, "Aux Switch 2 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_AUX_SWITCH_3_LABEL,                0x0002, "Aux Switch 3 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_AUX_SWITCH_4_LABEL,                0x0003, "Aux Switch 4 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_AUX_SWITCH_5_LABEL,                0x0004, "Aux Switch 5 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_AUX_SWITCH_6_LABEL,                0x0005, "Aux Switch 6 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_AUX_SWITCH_7_LABEL,                0x0006, "Aux Switch 7 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_AUX_SWITCH_8_LABEL,                0x0007, "Aux Switch 8 Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_CURRENT_AUX_LOAD_SWITCH_STATE,     0x0100, "Current Auxiliary Load Switch State" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_CURRENT_DELIVERED_TIER,            0x0101, "Current Delivered Tier" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_CURRENT_TIER_LABEL,                0x0102, "Current Tier Label" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_LINKY_PEAK_PERIOD_STATUS,          0x0103, "Linky Peak Period Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_PEAK_START_TIME,                   0x0104, "Peak Start Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_PEAK_END_TIME,                     0x0105, "Peak End Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DSH_CURRENT_TARIFF_LABEL,              0x0106, "Current Tariff Label" ) \

VALUE_STRING_ENUM(zbee_zcl_daily_schedule_attr_names);
VALUE_STRING_ARRAY(zbee_zcl_daily_schedule_attr_names);

/* Server Commands Received */
#define zbee_zcl_daily_schedule_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_DSH_GET_SCHEDULE,                       0x00, "Get Schedule" ) \
    XXX(ZBEE_ZCL_CMD_ID_DSH_GET_DAY_PROFILE,                    0x01, "Get Day Profile" ) \
    XXX(ZBEE_ZCL_CMD_ID_DSH_GET_SCHEDULE_CANCELLATION,          0x05, "Get Schedule Cancellation" ) \

VALUE_STRING_ENUM(zbee_zcl_daily_schedule_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_daily_schedule_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_daily_schedule_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_DSH_PUBLISH_SCHEDULE,                   0x00, "Publish Schedule" ) \
    XXX(ZBEE_ZCL_CMD_ID_DSH_PUBLISH_DAY_PROFILE,                0x01, "Publish Day Profile" ) \
    XXX(ZBEE_ZCL_CMD_ID_DSH_CANCEL_SCHEDULE,                    0x05, "Cancel Schedule" ) \

VALUE_STRING_ENUM(zbee_zcl_daily_schedule_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_daily_schedule_srv_tx_cmd_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_daily_schedule(void);
void proto_reg_handoff_zbee_zcl_daily_schedule(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_daily_schedule_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

/* Command Dissector Helpers */
static void dissect_zcl_daily_schedule_get_schedule(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_daily_schedule_get_day_profile(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_daily_schedule_publish_schedule(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_daily_schedule_publish_day_profile(tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_daily_schedule_cancel_schedule(tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_daily_schedule = -1;

static int hf_zbee_zcl_daily_schedule_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_daily_schedule_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_daily_schedule_attr_server_id = -1;
/* Get Schedule cmd */
static int hf_zbee_zcl_daily_schedule_type = -1;
static int hf_zbee_zcl_daily_schedule_name = -1;
static int hf_zbee_zcl_daily_schedule_start_time = -1;
static int hf_zbee_zcl_daily_schedule_earliest_start_time = -1;
static int hf_zbee_zcl_daily_schedule_command_index = -1;
static int hf_zbee_zcl_daily_schedule_id = -1;
static int hf_zbee_zcl_daily_schedule_time_reference = -1;
static int hf_zbee_zcl_daily_schedule_provider_id = -1;
static int hf_zbee_zcl_daily_schedule_issuer_event_id = -1;
static int hf_zbee_zcl_daily_schedule_min_issuer_event_id = -1;
static int hf_zbee_zcl_daily_schedule_number_of_schedules = -1;
static int hf_zbee_zcl_daily_schedule_total_number_of_schedule_entries = -1;
static int hf_zbee_zcl_daily_schedule_schedule_entry_start_time = -1;
static int hf_zbee_zcl_daily_schedule_schedule_entry_price_tier = -1;
static int hf_zbee_zcl_daily_schedule_schedule_entry_auxiliary_load_switch_state = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_daily_schedule = -1;

#define zbee_zcl_daily_schedule_type_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_SCHEDULE_TYPE_LINKY_SCHEDULE,                           0x00, "Linky Schedule" ) \

VALUE_STRING_ENUM(zbee_zcl_daily_schedule_type_names);
VALUE_STRING_ARRAY(zbee_zcl_daily_schedule_type_names);

#define zbee_zcl_daily_schedule_time_reference_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_SCHEDULE_TIME_REFERENCE_UTC_TIME,                     0x00, "UTC Time" ) \
    XXX(ZBEE_ZCL_SCHEDULE_TIME_REFERENCE_STANDARD_TIME,                0x01, "Standard Time" ) \
    XXX(ZBEE_ZCL_SCHEDULE_TIME_REFERENCE_LOCAL_TIME,                   0x02, "Local Time" )

VALUE_STRING_ENUM(zbee_zcl_daily_schedule_time_reference_names);
VALUE_STRING_ARRAY(zbee_zcl_daily_schedule_time_reference_names);

/**
 *ZigBee ZCL Daily Schedule cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 */
static int
dissect_zbee_zcl_daily_schedule(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
                        val_to_str_const(cmd_id, zbee_zcl_calendar_srv_rx_cmd_names, "Unknown Command"),
                        zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_daily_schedule_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_daily_schedule, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_DSH_GET_SCHEDULE:
                    dissect_zcl_daily_schedule_get_schedule(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DSH_GET_DAY_PROFILE:
                    dissect_zcl_daily_schedule_get_day_profile(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DSH_GET_SCHEDULE_CANCELLATION:
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
                        val_to_str_const(cmd_id, zbee_zcl_daily_schedule_srv_tx_cmd_names, "Unknown Command"),
                        zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_daily_schedule_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_daily_schedule, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

                case ZBEE_ZCL_CMD_ID_DSH_PUBLISH_SCHEDULE:
                    dissect_zcl_daily_schedule_publish_schedule(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DSH_PUBLISH_DAY_PROFILE:
                    dissect_zcl_daily_schedule_publish_day_profile(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DSH_CANCEL_SCHEDULE:
                    dissect_zcl_daily_schedule_cancel_schedule(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_daily_schedule*/

/**
 *This function manages the Publish Calendar payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_daily_schedule_publish_schedule(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t start_time;
    int length;

    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Schedule ID */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_daily_schedule_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Schedule Type */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Schedule Time Reference */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_time_reference, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Schedule Name */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_daily_schedule_name, tvb, *offset, 1, ENC_NA | ENC_ZIGBEE, &length);
    *offset += length;
} /*dissect_zcl_daily_schedule_publish_schedule*/

/**
 *This function manages the Publish Day Profile payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_daily_schedule_publish_day_profile(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint8   schedule_entries_count;
    guint8   calendar_type;

    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Total Number of Schedule Entries */
    schedule_entries_count = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_total_number_of_schedule_entries, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Number of Schedules */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_number_of_schedules, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Calendar Type */
    calendar_type = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    for (gint i = 0; tvb_reported_length_remaining(tvb, *offset) >= 4 && i < schedule_entries_count; i++) {
        /* Start Time */
        proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_schedule_entry_start_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        switch (calendar_type) {
            /* Rate Start Time */
            case ZBEE_ZCL_SCHEDULE_TYPE_LINKY_SCHEDULE:
                /* Price Tier */
                proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_schedule_entry_price_tier, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                /* Auxiliary Load Switch State */
                proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_schedule_entry_auxiliary_load_switch_state, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;
        }
    }
} /*dissect_zcl_daily_schedule_publish_day_profile*/

/**
 *This function manages the Cancel Calendar payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_daily_schedule_cancel_schedule(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Calendar ID */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Schedule Type */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_calendar_cancel*/

/**
 *This function manages the Get Calendar payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_daily_schedule_get_schedule(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    nstime_t earliest_start_time;

    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Earliest Start Time */
    earliest_start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    earliest_start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_daily_schedule_earliest_start_time, tvb, *offset, 4, &earliest_start_time);
    *offset += 4;

    /* Min Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_min_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Number of Schedules */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_number_of_schedules, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Schedule Type */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_daily_schedule_get_schedule*/

/**
 *This function manages the Get Day Profiles payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to offset from caller
 */
static void
dissect_zcl_daily_schedule_get_day_profile(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Provider Id */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Schedule ID */
    proto_tree_add_item(tree, hf_zbee_zcl_daily_schedule_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_daily_schedule_get_day_profile*/

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
dissect_zcl_daily_schedule_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    (void)attr_id;
    /* Catch all */
    dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
} /*dissect_zcl_calendar_attr_data*/

/**
 *This function registers the ZCL Calendar dissector
 *
*/
void
proto_register_zbee_zcl_daily_schedule(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_daily_schedule_attr_server_id,
            { "Attribute", "zbee_zcl_se.daily_schedule.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_daily_schedule_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.daily_schedule.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_daily_schedule_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.daily_schedule.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_daily_schedule_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_type,
          { "Schedule Type", "zbee_zcl_se.daily_schedule.type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_daily_schedule_type_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_start_time,
            { "Start Time", "zbee_zcl_se.daily_schedule.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_earliest_start_time,
            { "Earliest Start Time", "zbee_zcl_se.daily_schedule.earliest_start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_time_reference,
          { "Schedule Time Reference", "zbee_zcl_se.daily_schedule.time_reference", FT_UINT8, BASE_HEX, VALS(zbee_zcl_daily_schedule_time_reference_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_name,
            { "Schedule Name", "zbee_zcl_se.daily_schedule.name", FT_UINT_STRING, BASE_NONE, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_command_index,
            { "Command Index", "zbee_zcl_se.daily_schedule.command_index", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_provider_id,
            { "Provider ID", "zbee_zcl_se.daily_schedule.provider_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.daily_schedule.issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_min_issuer_event_id,
            { "Min. Issuer Event ID", "zbee_zcl_se.daily_schedule.min_issuer_event_id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_id,
            { "Schedule ID", "zbee_zcl_se.daily_schedule.id", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_total_number_of_schedule_entries,
            { "Total Number of Schedule Entries", "zbee_zcl_se.daily_schedule.total_number_of_schedule_entries", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_number_of_schedules,
            { "Number of Schedules", "zbee_zcl_se.daily_schedule.number_of_schedules", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_schedule_entry_start_time,
            { "Start Time", "zbee_zcl_se.daily_schedule.schedule_entry.start_time", FT_UINT16, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_schedule_entry_price_tier,
            { "Price Tier", "zbee_zcl_se.daily_schedule.schedule_entry.price_tier", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_daily_schedule_schedule_entry_auxiliary_load_switch_state,
            { "Auxiliary Load Switch State", "zbee_zcl_se.daily_schedule.schedule_entry.auxiliary_load_switch_state", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

    };

    /* ZCL Daily Schedule subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_daily_schedule,
    };

    /* Register the ZigBee ZCL Calendar cluster protocol name and description */
    proto_zbee_zcl_daily_schedule = proto_register_protocol("ZigBee ZCL Daily Schedule", "ZCL Daily Schedule", ZBEE_PROTOABBREV_ZCL_DAILY_SCHEDULE);
    proto_register_field_array(proto_zbee_zcl_daily_schedule, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Daily Schedule dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_DAILY_SCHEDULE, dissect_zbee_zcl_daily_schedule, proto_zbee_zcl_daily_schedule);
} /*proto_register_zbee_zcl_calendar*/

void
proto_reg_handoff_zbee_zcl_daily_schedule(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_DAILY_SCHEDULE,
                            proto_zbee_zcl_daily_schedule,
                            ett_zbee_zcl_daily_schedule,
                            ZBEE_ZCL_CID_DAILY_SCHEDULE,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_daily_schedule_attr_server_id,
                            -1,
                            hf_zbee_zcl_daily_schedule_srv_rx_cmd_id,
                            hf_zbee_zcl_daily_schedule_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_daily_schedule_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_calendar*/


/* ########################################################################## */
/* #### (0x0708) DEVICE_MANAGEMENT CLUSTER ############################################## */
/* ########################################################################## */

/* Attributes */
#define zbee_zcl_device_management_attr_server_names_VALUE_STRING_LIST(XXX) \
/* Supplier Control Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_PROVIDER_ID,                                 0x0100, "Provider ID" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_PROVIDER_NAME,                               0x0101, "Provider Name" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_PROVIDER_CONTACT_DETAILS,                    0x0102, "Provider Contact Details" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_PROPOSED_PROVIDER_ID,                        0x0110, "Proposed Provider ID" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_PROPOSED_PROVIDER_NAME,                      0x0111, "Proposed Provider Name" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_PROPOSED_PROVIDER_CHANGE_DATE_TIME,          0x0112, "Proposed Provider Change Date/Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_PROPOSED_PROVIDER_CHANGE_CONTROL,            0x0113, "Proposed Provider Change Control" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_PROPOSED_PROVIDER_CONTACT_DETAILS,           0x0114, "Proposed Provider Contact Details" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_RECEIVED_PROVIDER_ID,                        0x0120, "Received Provider ID" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_RECEIVED_PROVIDER_NAME,                      0x0121, "Received Provider Name" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_RECEIVED_PROVIDER_CONTACT_DETAILS,           0x0122, "Received Provider Contact Details" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_RECEIVED_PROPOSED_PROVIDER_ID,               0x0130, "Received Proposed Provider ID" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_RECEIVED_PROPOSED_PROVIDER_NAME,             0x0131, "Received Proposed Provider Name" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_RECEIVED_PROPOSED_PROVIDER_CHANGE_DATE_TIME, 0x0132, "Received Proposed Provider Change Date/Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_RECEIVED_PROPOSED_PROVIDER_CHANGE_CONTROL,   0x0133, "Received Proposed Provider Change Control" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_RECEIVED_PROPOSED_PROVIDER_CONTACT_DETAILS,  0x0134, "Received Proposed Provider Contact Details" ) \
  /* Tenancy Control Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CHANGE_OF_TENANCY_UPDATE_DATE_TIME,          0x0200, "Change of Tenancy Update Date/Time" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_PROPOSED_TENANCY_CHANGE_CONTROL,             0x0201, "Proposed Tenancy Change control" ) \
/* Backhaul Control Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_WAN_STATUS,                                  0x0300, "WAN Status" ) \
/* HAN Control Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_LOW_MEDIUM_THRESHOLD,                        0x0400, "Low Medium Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_MEDIUM_HIGH_THRESHOLD,                       0x0401, "Medium High Threshold" ) \
/* Add client attribute sets */ \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_DEVICE_MANAGEMENT,                       0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_device_management_attr_server_names);
VALUE_STRING_ARRAY(zbee_zcl_device_management_attr_server_names);

#define zbee_zcl_device_management_attr_client_names_VALUE_STRING_LIST(XXX) \
/* Supplier Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PROVIDER_ID,                            0x0000, "Provider ID" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_RECEIVED_PROVIDER_ID,                   0x0010, "Received Provider ID" ) \
/* Price Event Configuration Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TOU_TARIFF_ACTIVATION,                  0x0100, "TOU Tariff Activation" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_BLOCK_TARIFF_ACTIVATED,                 0x0101, "Block Tariff Activated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_BLOCK_TOU_TARIFF_ACTIVATED,             0x0102, "Block TOU Tariff Activated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SINGLE_TARIFF_RATE_ACTIVATED,           0x0103, "Single Tariff Rate Activated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ASYNCHRONOUS_BILLING_OCCURRED,          0x0104, "Asynchronous Billing Occurred" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SYNCHRONOUS_BILLING_OCCURRED,           0x0105, "Synchronous Billing Occurred" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TARIFF_NOT_SUPPORTED,                   0x0106, "Tariff Not Supported" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PRICE_CLUSTER_NOT_FOUND,                0x0107, "Price Cluster Not Found" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CURRENCY_CHANGE_PASSIVE_ACTIVATED,      0x0108, "Currency Change Passive Activated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CURRENCY_CHANGE_PASSIVE_UPDATED,        0x0109, "Currency Change Passive Updated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PRICE_MATRIX_PASSIVE_ACTIVATED,         0x010A, "Price Matrix Passive Activated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PRICE_MATRIX_PASSIVE_UPDATED,           0x010B, "Price Matrix Passive Updated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TARIFF_CHANGE_PASSIVE_ACTIVATED,        0x010C, "Tariff Change Passive Activated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TARIFF_CHANGED_PASSIVE_UPDATED,         0x010D, "Tariff Changed Passive Updated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_PRICE_RECEIVED,                 0x01B0, "Publish Price Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_PRICE_ACTIONED,                 0x01B1, "Publish Price Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_PRICE_CANCELLED,                0x01B2, "Publish Price Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_PRICE_REJECTED,                 0x01B3, "Publish Price Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_TARIFF_INFORMATION_RECEIVED,    0x01B4, "Publish Tariff Information Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_TARIFF_INFORMATION_ACTIONED,    0x01B5, "Publish Tariff Information Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_TARIFF_INFORMATION_CANCELLED,   0x01B6, "Publish Tariff Information Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_TARIFF_INFORMATION_REJECTED,    0x01B7, "Publish Tariff Information Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_PRICE_MATRIX_RECEIVED,          0x01B8, "Publish Price Matrix Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_PRICE_MATRIX_ACTIONED,          0x01B9, "Publish Price Matrix Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_PRICE_MATRIX_CANCELLED,         0x01BA, "Publish Price Matrix Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_PRICE_MATRIX_REJECTED,          0x01BB, "Publish Price Matrix Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BLOCK_THRESHOLDS_RECEIVED,      0x01BC, "Publish Block Thresholds Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BLOCK_THRESHOLDS_ACTIONED,      0x01BD, "Publish Block Thresholds Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BLOCK_THRESHOLDS_CANCELLED,     0x01BE, "Publish Block Thresholds Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BLOCK_THRESHOLDS_REJECTED,      0x01BF, "Publish Block Thresholds Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CALORIFIC_VALUE_RECEIVED,       0x01C0, "Publish Calorific Value Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CALORIFIC_VALUE_ACTIONED,       0x01C1, "Publish Calorific Value Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CALORIFIC_VALUE_CANCELLED,      0x01C2, "Publish Calorific Value Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CALORIFIC_VALUE_REJECTED,       0x01C3, "Publish Calorific Value Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CONVERSION_FACTOR_RECEIVED,     0x01C4, "Publish Conversion Factor Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CONVERSION_FACTOR_ACTIONED,     0x01C5, "Publish Conversion Factor Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CONVERSION_FACTOR_CANCELLED,    0x01C6, "Publish Conversion Factor Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CONVERSION_FACTOR_REJECTED,     0x01C7, "Publish Conversion Factor Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CO2_VALUE_RECEIVED,             0x01C8, "Publish CO2 Value Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CO2_VALUE_ACTIONED,             0x01C9, "Publish CO2 Value Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CO2_VALUE_CANCELLED,            0x01CA, "Publish CO2 Value Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CO2_VALUE_REJECTED,             0x01CB, "Publish CO2 Value Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CPP_EVENT_RECEIVED,             0x01CC, "Publish CPP event Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CPP_EVENT_ACTIONED,             0x01CD, "Publish CPP event Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CPP_EVENT_CANCELLED,            0x01CE, "Publish CPP event Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CPP_EVENT_REJECTED,             0x01CF, "Publish CPP event Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_TIER_LABELS_RECEIVED,           0x01D0, "Publish Tier Labels Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_TIER_LABELS_ACTIONED,           0x01D1, "Publish Tier Labels Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_TIER_LABELS_CANCELLED,          0x01D2, "Publish Tier Labels Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_TIER_LABELS_REJECTED,           0x01D3, "Publish Tier Labels Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BILLING_PERIOD_RECEIVED,        0x01D4, "Publish Billing Period Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BILLING_PERIOD_ACTIONED,        0x01D5, "Publish Billing Period Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BILLING_PERIOD_CANCELLED,       0x01D6, "Publish Billing Period Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BILLING_PERIOD_REJECTED,        0x01D7, "Publish Billing Period Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CONSOLIDATED_BILL_RECEIVED,     0x01D8, "Publish Consolidated Bill Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CONSOLIDATED_BILL_ACTIONED,     0x01D9, "Publish Consolidated Bill Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CONSOLIDATED_BILL_CANCELLED,    0x01DA, "Publish Consolidated Bill Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CONSOLIDATED_BILL_REJECTED,     0x01DB, "Publish Consolidated Bill Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BLOCK_PERIOD_RECEIVED,          0x01DC, "Publish Block Period Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BLOCK_PERIOD_ACTIONED,          0x01DD, "Publish Block Period Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BLOCK_PERIOD_CANCELLED,         0x01DE, "Publish Block Period Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_BLOCK_PERIOD_REJECTED,          0x01DF, "Publish Block Period Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CREDIT_PAYMENT_INFO_RECEIVED,   0x01E0, "Publish Credit Payment Info Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CREDIT_PAYMENT_INFO_ACTIONED,   0x01E1, "Publish Credit Payment Info Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CREDIT_PAYMENT_INFO_CANCELLED,  0x01E2, "Publish Credit Payment Info Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CREDIT_PAYMENT_INFO_REJECTED,   0x01E3, "Publish Credit Payment Info Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CURRENCY_CONVERSION_RECEIVED,   0x01E4, "Publish Currency Conversion Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CURRENCY_CONVERSION_ACTIONED,   0x01E5, "Publish Currency Conversion Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CURRENCY_CONVERSION_CANCELLED,  0x01E6, "Publish Currency Conversion Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CURRENCY_CONVERSION_REJECTED,   0x01E7, "Publish Currency Conversion Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_RESERVED_FOR_PRICE_CLUSTER_GROUP_ID,    0x01FF, "Reserved for Price Cluster Group ID" ) \
/* Metering Event Configuration Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHECK_METER,                            0x0200, "Check Meter" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOW_BATTERY,                            0x0201, "Low Battery" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TAMPER_DETECT,                          0x0202, "Tamper Detect" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SUPPLY_STATUS,                          0x0203, "Supply Status" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SUPPLY_QUALITY,                         0x0204, "Supply Quality" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LEAK_DETECT,                            0x0205, "Leak Detect" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SERVICE_DISCONNECT,                     0x0206, "Service Disconnect" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_METERING_REVERSE_FLOW_GAS_WATER_HEAT,   0x0207, "Reverse Flow (Gas, Water, Heat/Cooling)" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_METER_COVER_REMOVED,                    0x0208, "Meter Cover Removed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_METER_COVER_CLOSED,                     0x0209, "Meter Cover Closed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_STRONG_MAGNETIC_FIELD,                  0x020A, "Strong Magnetic Field" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_NO_STRONG_MAGNETIC_FIELD,               0x020B, "No Strong Magnetic Field" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_BATTERY_FAILURE,                        0x020C, "Battery Failure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PROGRAM_MEMORY_ERROR,                   0x020D, "Program Memory Error" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_RAM_ERROR,                              0x020E, "RAM Error" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_NV_MEMORY_ERROR,                        0x020F, "NV Memory Error" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOW_VOLTAGE_L1,                         0x0210, "Low Voltage L1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_HIGH_VOLTAGE_L1,                        0x0211, "High Voltage L1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOW_VOLTAGE_L2,                         0x0212, "Low Voltage L2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_HIGH_VOLTAGE_L2,                        0x0213, "High Voltage L2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOW_VOLTAGE_L3,                         0x0214, "Low Voltage L3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_HIGH_VOLTAGE_L3,                        0x0215, "High Voltage L3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_OVER_CURRENT_L1,                        0x0216, "Over Current L1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_OVER_CURRENT_L2,                        0x0217, "Over Current L2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_OVER_CURRENT_L3,                        0x0218, "Over Current L3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FREQUENCY_TOO_LOW_L1,                   0x0219, "Frequency too Low L1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FREQUENCY_TOO_HIGH_L1,                  0x021A, "Frequency too High L1" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FREQUENCY_TOO_LOW_L2,                   0x021B, "Frequency too Low L2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FREQUENCY_TOO_HIGH_L2,                  0x021C, "Frequency too High L2" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FREQUENCY_TOO_LOW_L3,                   0x021D, "Frequency too Low L3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FREQUENCY_TOO_HIGH_L3,                  0x021E, "Frequency too High L3" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GROUND_FAULT,                           0x021F, "Ground Fault" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ELECTRIC_TAMPER_DETECT,                 0x0220, "Electric Tamper Detect" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_INCORRECT_POLARITY,                     0x0221, "Incorrect Polarity" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CURRENT_NO_VOLTAGE,                     0x0222, "Current No Voltage" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UNDER_VOLTAGE,                          0x0223, "Under Voltage" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_OVER_VOLTAGE,                           0x0224, "Over Voltage" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_NORMAL_VOLTAGE,                         0x0225, "Normal Voltage" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PF_BELOW_THRESHOLD,                     0x0226, "PF Below Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PF_ABOVE_THRESHOLD,                     0x0227, "PF Above Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TERMINAL_COVER_REMOVED,                 0x0228, "Terminal Cover Removed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TERMINAL_COVER_CLOSED,                  0x0229, "Terminal Cover Closed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_BURST_DETECT,                           0x0230, "Burst Detect" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PRESSURE_TOO_LOW,                       0x0231, "Pressure too Low" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PRESSURE_TOO_HIGH,                      0x0232, "Pressure too High" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FLOW_SENSOR_COMMUNICATION_ERROR,        0x0233, "Flow Sensor Communication Error" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FLOW_SENSOR_MEASUREMENT_FAULT,          0x0234, "Flow Sensor Measurement Fault" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FLOW_SENSOR_REVERSE_FLOW,               0x0235, "Flow Sensor Reverse Flow" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FLOW_SENSOR_AIR_DETECT,                 0x0236, "Flow Sensor Air Detect" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PIPE_EMPTY,                             0x0237, "Pipe Empty" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_INLET_TEMPERATURE_SENSOR_FAULT,         0x0250, "Inlet Temperature Sensor Fault" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_OUTLET_TEMPERATURE_SENDOR_FAULT,        0x0251, "Outlet Temperature Sendor Fault" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_REVERSE_FLOW,                           0x0260, "Reverse Flow" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TILT_TAMPER,                            0x0261, "Tilt Tamper" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_BATTERY_COVER_REMOVED,                  0x0262, "Battery Cover Removed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_BATTERY_COVER_CLOSED,                   0x0263, "Battery Cover Closed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_EXCESS_FLOW,                            0x0264, "Excess Flow" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TILT_TAMPER_ENDED,                      0x0265, "Tilt Tamper Ended" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MEASUREMENT_SYSTEM_ERROR,               0x0270, "Measurement System Error" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_WATCHDOG_ERROR,                         0x0271, "Watchdog Error" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SUPPLY_DISCONNECT_FAILURE,              0x0272, "Supply Disconnect Failure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SUPPLY_CONNECT_FAILURE,                 0x0273, "Supply Connect Failure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MEASUREMENT_SOFTWARE_CHANGED,           0x0274, "Measurement Software Changed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DST_ENABLED,                            0x0275, "DST Enabled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DST_DISABLED,                           0x0276, "DST Disabled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CLOCK_ADJUST_BACKWARD,                  0x0277, "Clock Adjust Backward" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CLOCK_ADJUST_FORWARD,                   0x0278, "Clock Adjust Forward" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CLOCK_INVALID,                          0x0279, "Clock Invalid" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_COMMUNICATION_ERROR_HAN,                0x027A, "Communication Error HAN" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_COMMUNICATION_OK_HAN,                   0x027B, "Communication OK HAN" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_METER_FRAUD_ATTEMPT,                    0x027C, "Meter Fraud Attempt" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_POWER_LOSS,                             0x027D, "Power Loss" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UNUSUAL_HAN_TRAFFIC,                    0x027E, "Unusual HAN Traffic" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UNEXPECTED_CLOCK_CHANGE,                0x027F, "Unexpected Clock Change" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_COMMS_USING_UNAUTHENTICATED_COMPONENT,  0x0280, "Comms Using Unauthenticated Component" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MET_ERROR_REGISTER_CLEAR,               0x0281, "Metering Error Register Clear" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MET_ALARM_REGISTER_CLEAR,               0x0282, "Metering Alarm Register Clear" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UNEXPECTED_HW_RESET,                    0x0283, "Unexpected HW Reset" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UNEXPECTED_PROGRAM_EXECUTION,           0x0284, "Unexpected Program Execution" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LIMIT_THRESHOLD_EXCEEDED,               0x0285, "Limit Threshold Exceeded" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LIMIT_THRESHOLD_OK,                     0x0286, "Limit Threshold OK" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LIMIT_THRESHOLD_CHANGED,                0x0287, "Limit Threshold Changed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MAXIMUM_DEMAND_EXCEEDED,                0x0288, "Maximum Demand Exceeded" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PROFILE_CLEARED,                        0x0289, "Profile Cleared" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOAD_PROFILE_CLEARED,                   0x028A, "Load Profile Cleared" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_BATTERY_WARNING,                        0x028B, "Battery Warning" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_WRONG_SIGNATURE,                        0x028C, "Wrong Signature" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_NO_SIGNATURE,                           0x028D, "No Signature" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SIGNATURE_NOT_VALID,                    0x028E, "Signature Not Valid" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UNAUTHORISED_ACTION_FROM_HAN,           0x028F, "Unauthorized Action From HAN" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FAST_POLLING_START,                     0x0290, "Fast Polling Start" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FAST_POLLING_END,                       0x0291, "Fast Polling End" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_METER_REPORTING_INTERVAL_CHANGED,       0x0292, "Meter Reporting Interval Changed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DISCONNECT_TO_LOAD_LIMIT,               0x0293, "Disconnect to Load Limit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_METER_SUPPLY_STATUS_REGISTER_CHANGED,   0x0294, "Meter Supply Status Register Changed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_METER_ALARM_STATUS_REGISTER_CHANGED,    0x0295, "Meter Alarm Status Register Changed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_EXTENDED_METER_ALARM_STATUS_REG_CHANGED,0x0296, "Extended Meter Alarm Status Register Changed." ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DATA_ACCESS_VIA_LOCAL_PORT,             0x0297, "Data Access Via Local Port" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CONFIGURE_MIRROR_SUCCESS,               0x0298, "Configure Mirror Success" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CONFIGURE_MIRROR_FAILURE,               0x0299, "Configure Mirror Failure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CONFIGURE_NOTIFICATION_FLAG_SCHEME_SUCC,0x029A, "Configure Notification Flag Scheme Success" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CONFIGURE_NOTIFICATION_FLAG_SCHEME_FAIL,0x029B, "Configure Notification Flag Scheme Failure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CONFIGURE_NOTIFICATION_FLAGS_SUCCESS,   0x029C, "Configure Notification Flags Success" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CONFIGURE_NOTIFICATION_FLAGS_FAILURE,   0x029D, "Configure Notification Flags Failure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_STAY_AWAKE_REQUEST_HAN,                 0x029E, "Stay Awake Request HAN" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_STAY_AWAKE_REQUEST_WAN,                 0x029F, "Stay Awake Request WAN" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUFACTURER_SPECIFIC_A,                0x02B0, "Manufacturer Specific A" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUFACTURER_SPECIFIC_B,                0x02B1, "Manufacturer Specific B" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUFACTURER_SPECIFIC_C,                0x02B2, "Manufacturer Specific C" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUFACTURER_SPECIFIC_D,                0x02B3, "Manufacturer Specific D" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUFACTURER_SPECIFIC_E,                0x02B4, "Manufacturer Specific E" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUFACTURER_SPECIFIC_F,                0x02B5, "Manufacturer Specific F" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUFACTURER_SPECIFIC_G,                0x02B6, "Manufacturer Specific G" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUFACTURER_SPECIFIC_H,                0x02B7, "Manufacturer Specific H" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUFACTURER_SPECIFIC_I,                0x02B8, "Manufacturer Specific I" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_PROFILE_COMMAND_RECEIVED,           0x02C0, "Get Profile Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_PROFILE_COMMAND_ACTIONED,           0x02C1, "Get Profile Command Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_PROFILE_COMMAND_CANCELLED,          0x02C2, "Get Profile Command Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_PROFILE_COMMAND_REJECTED,           0x02C3, "Get Profile Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_REQUEST_MIRROR_RESPONSE_COMMAND_RECV,   0x02C4, "Request Mirror Response Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_REQUEST_MIRROR_RESPONSE_COMMAND_ACTION, 0x02C5, "Request Mirror Response Command Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_REQUEST_MIRROR_RESPONSE_COMMAND_CANCEL, 0x02C6, "Request Mirror Response Command Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_REQUEST_MIRROR_RESPONSE_COMMAND_REJECT, 0x02C7, "Request Mirror Response Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MIRROR_REMOVED_COMMAND_RECEIVED,        0x02C8, "Mirror Removed Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MIRROR_REMOVED_COMMAND_ACTIONED,        0x02C9, "Mirror Removed Command Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MIRROR_REMOVED_COMMAND_CANCELLED,       0x02CA, "Mirror Removed Command Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MIRROR_REMOVED_COMMAND_REJECTED,        0x02CB, "Mirror Removed Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SNAPSHOT_COMMAND_RECEIVED,          0x02CC, "Get Snapshot Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SNAPSHOT_COMMAND_ACTIONED,          0x02CD, "Get Snapshot Command Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SNAPSHOT_COMMAND_CANCELLED,         0x02CE, "Get Snapshot Command Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SNAPSHOT_COMMAND_REJECTED,          0x02CF, "Get Snapshot Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TAKE_SNAPSHOT_COMMAND_RECEIVED,         0x02D0, "Take Snapshot Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TAKE_SNAPSHOT_COMMAND_ACTIONED,         0x02D1, "Take Snapshot Command Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TAKE_SNAPSHOT_COMMAND_CANCELLED,        0x02D2, "Take Snapshot Command Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TAKE_SNAPSHOT_COMMAND_REJECTED,         0x02D3, "Take Snapshot Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MIRROR_REPORT_ATTRIBUTE_RSP_CMD_RECV,   0x02D4, "Mirror Report Attribute Response Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MIRROR_REPORT_ATTRIBUTE_RSP_CMD_ACTION, 0x02D5, "Mirror Report Attribute Response Command Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MIRROR_REPORT_ATTRIBUTE_RSP_CMD_CANCEL, 0x02D6, "Mirror Report Attribute Response Command Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MIRROR_REPORT_ATTRIBUTE_RSP_CMD_REJECT, 0x02D7, "Mirror Report Attribute Response Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SCHEDULE_SNAPSHOT_COMMAND_RECEIVED,     0x02D8, "Schedule Snapshot Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SCHEDULE_SNAPSHOT_COMMAND_ACTIONED,     0x02D9, "Schedule Snapshot Command Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SCHEDULE_SNAPSHOT_COMMAND_CANCELLED,    0x02DA, "Schedule Snapshot Command Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SCHEDULE_SNAPSHOT_COMMAND_REJECTED,     0x02DB, "Schedule Snapshot Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_START_SAMPLING_COMMAND_RECEIVED,        0x02DC, "Start Sampling Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_START_SAMPLING_COMMAND_ACTIONED,        0x02DD, "Start Sampling Command Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_START_SAMPLING_COMMAND_CANCELLED,       0x02DE, "Start Sampling Command Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_START_SAMPLING_COMMAND_REJECTED,        0x02DF, "Start Sampling Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SAMPLED_DATA_COMMAND_RECEIVED,      0x02E0, "Get Sampled Data Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SAMPLED_DATA_COMMAND_ACTIONED,      0x02E1, "Get Sampled Data Command Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SAMPLED_DATA_COMMAND_CANCELLED,     0x02E2, "Get Sampled Data Command Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SAMPLED_DATA_COMMAND_REJECTED,      0x02E3, "Get Sampled Data Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SUPPLY_ON,                              0x02E4, "Supply On" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SUPPLY_ARMED,                           0x02E5, "Supply Armed" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SUPPLY_OFF,                             0x02E6, "Supply Off" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DISCONNECTED_DUE_TO_TAMPER_DETECTED,    0x02E7, "Disconnected due to Tamper Detected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUAL_DISCONNECT,                      0x02E8, "Manual Disconnect" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MANUAL_CONNECT,                         0x02E9, "Manual Connect" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_REMOTE_DISCONNECTION,                   0x02EA, "Remote Disconnection" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_REMOTE_CONNECT,                         0x02EB, "Remote Connect" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOCAL_DISCONNECTION,                    0x02EC, "Local Disconnection" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOCAL_CONNECT,                          0x02ED, "Local Connect" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_SUPPLY_RECEIVED,                 0x02EE, "Change Supply Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_SUPPLY_ACTIONED,                 0x02EF, "Change Supply Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_SUPPLY_CANCELLED,                0x02F0, "Change Supply Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_SUPPLY_REJECTED,                 0x02F1, "Change Supply Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOCAL_CHANGE_SUPPLY_RECEIVED,           0x02F2, "Local Change Supply Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOCAL_CHANGE_SUPPLY_ACTIONED,           0x02F3, "Local Change Supply Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOCAL_CHANGE_SUPPLY_CANCELLED,          0x02F4, "Local Change Supply Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOCAL_CHANGE_SUPPLY_REJECTED,           0x02F5, "Local Change Supply Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_UNCONTROLLED_FLOW_THRES_RECV,   0x02F6, "Publish Uncontrolled Flow Threshold Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_UNCONTROLLED_FLOW_THRES_ACTION, 0x02F7, "Publish Uncontrolled Flow Threshold Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_UNCONTROLLED_FLOW_THRES_CANCEL, 0x02F8, "Publish Uncontrolled Flow Threshold Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_UNCONTROLLED_FLOW_THRES_REJECY, 0x02F9, "Publish Uncontrolled Flow Threshold Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_RESERVED_FOR_METERING_CLUSTER_GROUP_ID, 0x02FF, "Reserved for Metering Cluster Group Id" ) \
/* Messaging Event Configuration Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MESSAGE_CONFIRMATION_SENT,              0x0300, "Message Confirmation Sent" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DISPLAY_MESSAGE_RECEIVED,               0x03C0, "Display Message Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DISPLAY_MESSAGE_ACTIONED,               0x03C1, "Display Message Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DISPLAY_MESSAGE_CANCELLED,              0x03C2, "Display Message Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DISPLAY_MESSAGE_REJECTED,               0x03C3, "Display Message Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CANCEL_MESSAGE_RECEIVED,                0x03C4, "Cancel Message Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CANCEL_MESSAGE_ACTIONED,                0x03C5, "Cancel Message Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CANCEL_MESSAGE_CANCELLED,               0x03C6, "Cancel Message Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CANCEL_MESSAGE_REJECTED,                0x03C7, "Cancel Message Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_RESERVED_FOR_MESSAGING_CLUSTER_GROUP_ID,0x03FF, "Reserved for Messaging Cluster Group ID" ) \
/* Prepayment Event Configuration Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_LOW_CREDIT,                             0x0400, "Low Credit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_NO_CREDIT_ZERO_CREDIT,                  0x0401, "No Credit (Zero Credit)" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CREDIT_EXHAUSTED,                       0x0402, "Credit Exhausted" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_EMERGENCY_CREDIT_ENABLED,               0x0403, "Emergency Credit Enabled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_EMERGENCY_CREDIT_EXHAUSTED,             0x0404, "Emergency Credit Exhausted" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_IHD_LOW_CREDIT_WARNING,                 0x0405, "IHD Low Credit Warning" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PHYSICAL_ATTACK_ON_THE_PREPAY_METER,    0x0420, "Physical Attack on the Prepay Meter" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ELECTRONIC_ATTACK_ON_THE_PREPAY_METER,  0x0421, "Electronic Attack on the Prepay Meter" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DISCOUNT_APPLIED,                       0x0422, "Discount Applied" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CREDIT_ADJUSTMENT,                      0x0423, "Credit Adjustment" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CREDIT_ADJUST_FAIL,                     0x0424, "Credit Adjust Fail" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DEBT_ADJUSTMENT,                        0x0425, "Debt Adjustment" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_DEBT_ADJUST_FAIL,                       0x0426, "Debt Adjust Fail" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MODE_CHANGE,                            0x0427, "Mode Change" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TOPUP_CODE_ERROR,                       0x0428, "Topup Code Error" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TOPUP_ALREADY_USED,                     0x0429, "Topup Already Used" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TOPUP_CODE_INVALID,                     0x042A, "Topup Code Invalid" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TOPUP_ACCEPTED_VIA_REMOTE,              0x042B, "Topup Accepted via Remote" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TOPUP_ACCEPTED_VIA_MANUAL_ENTRY,        0x042C, "Topup Accepted via Manual Entry" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FRIENDLY_CREDIT_IN_USE,                 0x042D, "Friendly Credit in Use" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FRIENDLY_CREDIT_PERIOD_END_WARNING,     0x042E, "Friendly Credit Period End Warning" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FRIENDLY_CREDIT_PERIOD_END,             0x042F, "Friendly Credit Period End" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PP_ERROR_REGISTER_CLEAR,                0x0430, "Prepayment Error Register Clear" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PP_ALARM_REGISTER_CLEAR,                0x0431, "Prepayment Alarm Register Clear" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PREPAY_CLUSTER_NOT_FOUND,               0x0432, "Prepay Cluster Not Found" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TOPUP_VALUE_TOO_LARGE,                  0x0433, "Topup Value too Large" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MODE_CREDIT_2_PREPAY,                   0x0441, "Mode Credit 2 Prepay" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MODE_PREPAY_2_CREDIT,                   0x0442, "Mode Prepay 2 Credit" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_MODE_DEFAULT,                           0x0443, "Mode Default" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SELECT_AVAILABLE_EMERG_CREDIT_RECV,     0x04C0, "Select Available Emergency Credit Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SELECT_AVAILABLE_EMERG_CREDIT_ACTION,   0x04C1, "Select Available Emergency Credit Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SELECT_AVAILABLE_EMERG_CREDIT_CANCEL,   0x04C2, "Select Available Emergency Credit Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SELECT_AVAILABLE_EMERG_CREDIT_REJECT,   0x04C3, "Select Available Emergency Credit Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_DEBT_RECEIVED,                   0x04C4, "Change Debt Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_DEBT_ACTIONED,                   0x04C5, "Change Debt Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_DEBT_CANCELLED,                  0x04C6, "Change Debt Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_DEBT_REJECTED,                   0x04C7, "Change Debt Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_EMERGENCY_CREDIT_SETUP_RECEIVED,        0x04C8, "Emergency Credit Setup Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_EMERGENCY_CREDIT_SETUP_ACTIONED,        0x04C9, "Emergency Credit Setup Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_EMERGENCY_CREDIT_SETUP_CANCELLED,       0x04CA, "Emergency Credit Setup Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_EMERGENCY_CREDIT_SETUP_REJECTED,        0x04CB, "Emergency Credit Setup Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CONSUMER_TOPUP_RECEIVED,                0x04CC, "Consumer Topup Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CONSUMER_TOPUP_ACTIONED,                0x04CD, "Consumer Topup Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CONSUMER_TOPUP_CANCELLED,               0x04CE, "Consumer Topup Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CONSUMER_TOPUP_REJECTED,                0x04CF, "Consumer Topup Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CREDIT_ADJUSTMENT_RECEIVED,             0x04D0, "Credit Adjustment Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CREDIT_ADJUSTMENT_ACTIONED,             0x04D1, "Credit Adjustment Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CREDIT_ADJUSTMENT_CANCELLED,            0x04D2, "Credit Adjustment Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CREDIT_ADJUSTMENT_REJECTED,             0x04D3, "Credit Adjustment Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_PAYMENT_MODE_RECEIVED,           0x04D4, "Change Payment Mode Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_PAYMENT_MODE_ACTIONED,           0x04D5, "Change Payment Mode Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_PAYMENT_MODE_CANCELLED,          0x04D6, "Change Payment Mode Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_PAYMENT_MODE_REJECTED,           0x04D7, "Change Payment Mode Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_PREPAY_SNAPSHOT_RECEIVED,           0x04D8, "Get Prepay Snapshot Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_PREPAY_SNAPSHOT_ACTIONED,           0x04D9, "Get Prepay Snapshot Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_PREPAY_SNAPSHOT_CANCELLED,          0x04DA, "Get Prepay Snapshot Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_PREPAY_SNAPSHOT_REJECTED,           0x04DB, "Get Prepay Snapshot Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_TOPUP_LOG_RECEIVED,                 0x04DC, "Get Topup Log Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_TOPUP_LOG_ACTIONED,                 0x04DD, "Get Topup Log Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_TOPUP_LOG_CANCELLED,                0x04DE, "Get Topup Log Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_TOPUP_LOG_REJECTED,                 0x04DF, "Get Topup Log Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_LOW_CREDIT_WARNING_LEVEL_RECEIVED,  0x04E0, "Set Low Credit Warning Level Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_LOW_CREDIT_WARNING_LEVEL_ACTIONED,  0x04E1, "Set Low Credit Warning Level Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_LOW_CREDIT_WARNING_LEVEL_CANCELLED, 0x04E2, "Set Low Credit Warning Level Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_LOW_CREDIT_WARNING_LEVEL_REJECTED,  0x04E3, "Set Low Credit Warning Level Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_DEBT_REPAY_LOG_RECEIVED,            0x04E4, "Get Debt Repay Log Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_DEBT_REPAY_LOG_ACTIONED,            0x04E5, "Get Debt Repay Log Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_DEBT_REPAY_LOG_CANCELLED,           0x04E6, "Get Debt Repay Log Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_DEBT_REPAY_LOG_REJECTED,            0x04E7, "Get Debt Repay Log Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_MAXIMUM_CREDIT_LIMIT_RECEIVED,      0x04E8, "Set Maximum Credit Limit Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_MAXIMUM_CREDIT_LIMIT_ACTIONED,      0x04E9, "Set Maximum Credit Limit Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_MAXIMUM_CREDIT_LIMIT_CANCELLED,     0x04EA, "Set Maximum Credit Limit Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_MAXIMUM_CREDIT_LIMIT_REJECTED,      0x04EB, "Set Maximum Credit Limit Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_OVERALL_DEBT_CAP_RECEIVED,          0x04EC, "Set Overall Debt Cap Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_OVERALL_DEBT_CAP_ACTIONED,          0x04ED, "Set Overall Debt Cap Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_OVERALL_DEBT_CAP_CANCELLED,         0x04EE, "Set Overall Debt Cap Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_OVERALL_DEBT_CAP_REJECTED,          0x04EF, "Set Overall Debt Cap Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_RESERVED_FOR_PP_CLUSTER_GROUP_ID,       0x04FF, "Reserved for Prepayment Cluster Group ID" ) \
/* Calendar Event Configuration Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CALENDAR_CLUSTER_NOT_FOUND,             0x0500, "Calendar Cluster Not Found" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CALENDAR_CHANGE_PASSIVE_ACTIVATED,      0x0501, "Calendar Change Passive Activated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CALENDAR_CHANGE_PASSIVE_UPDATED,        0x0502, "Calendar Change Passive Updated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CALENDAR_RECEIVED,              0x05C0, "Publish Calendar Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CALENDAR_ACTIONED,              0x05C1, "Publish Calendar Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CALENDAR_CANCELLED,             0x05C2, "Publish Calendar Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_CALENDAR_REJECTED,              0x05C3, "Publish Calendar Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_DAY_PROFILE_RECEIVED,           0x05C4, "Publish Day Profile Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_DAY_PROFILE_ACTIONED,           0x05C5, "Publish Day Profile Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_DAY_PROFILE_CANCELLED,          0x05C6, "Publish Day Profile Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_DAY_PROFILE_REJECTED,           0x05C7, "Publish Day Profile Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_WEEK_PROFILE_RECEIVED,          0x05C8, "Publish Week Profile Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_WEEK_PROFILE_ACTIONED,          0x05C9, "Publish Week Profile Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_WEEK_PROFILE_CANCELLED,         0x05CA, "Publish Week Profile Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_WEEK_PROFILE_REJECTED,          0x05CB, "Publish Week Profile Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_SEASONS_RECEIVED,               0x05CC, "Publish Seasons Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_SEASONS_ACTIONED,               0x05CD, "Publish Seasons Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_SEASONS_CANCELLED,              0x05CE, "Publish Seasons Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_SEASONS_REJECTED,               0x05CF, "Publish Seasons Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_SPECIAL_DAYS_RECEIVED,          0x05D0, "Publish Special Days Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_SPECIAL_DAYS_ACTIONED,          0x05D1, "Publish Special Days Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_SPECIAL_DAYS_CANCELLED,         0x05D2, "Publish Special Days Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_SPECIAL_DAYS_REJECTED,          0x05D3, "Publish Special Days Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_RESERVED_FOR_CALENDAR_CLUSTER_GROUP_ID, 0x05FF, "Reserved For Calendar Cluster Group ID" ) \
/* Device Management Event Configuration Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PASSWORD_1_CHANGE,                      0x0600, "Password 1 Change" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PASSWORD_2_CHANGE,                      0x0601, "Password 2 Change" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PASSWORD_3_CHANGE,                      0x0602, "Password 3 Change" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PASSWORD_4_CHANGE,                      0x0603, "Password 4 Change" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_EVENT_LOG_CLEARED,                      0x0604, "Event Log Cleared" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ZIGBEE_APS_TIMEOUT,                     0x0610, "ZigBee APS Timeout" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ZIGBEE_IEEE_TRANS_FAILURE_OVER_THRES,   0x0611, "ZigBee IEEE Transmission Failure Over Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ZIGBEE_IEEE_FRAME_CHECK_SEQ_THRES,      0x0612, "ZigBee IEEE Frame Check Sequence Threshold" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ERROR_CERTIFICATE,                      0x0613, "Error Certificate" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ERROR_SIGNATURE,                        0x0614, "Error Signature" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ERROR_PROGRAM_STORAGE,                  0x0615, "Error Program Storage" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_COT_RECEIVED,                   0x06C0, "Publish CoT Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_COT_ACTIONED,                   0x06C1, "Publish CoT Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_COT_CANCELLED,                  0x06C2, "Publish CoT Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_COT_REJECTED,                   0x06C3, "Publish CoT Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_COS_RECEIVED,                   0x06C4, "Publish CoS Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_COS_ACTIONED,                   0x06C5, "Publish CoS Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_COS_CANCELLED,                  0x06C6, "Publish CoS Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PUBLISH_COS_REJECTED,                   0x06C7, "Publish CoS Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_PASSWORD_RECEIVED,               0x06C8, "Change Password Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_PASSWORD_ACTIONED,               0x06C9, "Change Password Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_PASSWORD_CANCELLED,              0x06CA, "Change Password Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CHANGE_PASSWORD_REJECTED,               0x06CB, "Change Password Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_EVENT_CONFIGURATION_RECEIVED,       0x06CC, "Set Event Configuration Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_EVENT_CONFIGURATION_ACTIONED,       0x06CD, "Set Event Configuration Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_EVENT_CONFIGURATION_CANCELLED,      0x06CE, "Set Event Configuration Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_SET_EVENT_CONFIGURATION_REJECTED,       0x06CF, "Set Event Configuration Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPDATE_SITE_ID_RECEIVED,                0x06D0, "Update Site ID Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPDATE_SITE_ID_ACTIONED,                0x06D1, "Update Site ID Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPDATE_SITE_ID_CANCELLED,               0x06D2, "Update Site ID Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPDATE_SITE_ID_REJECTED,                0x06D3, "Update Site ID Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPDATE_CIN_RECEIVED,                    0x06D4, "Update CIN Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPDATE_CIN_ACTIONED,                    0x06D5, "Update CIN Actioned" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPDATE_CIN_CANCELLED,                   0x06D6, "Update CIN Cancelled" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPDATE_CIN_REJECTED,                    0x06D7, "Update CIN Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_RESERVED_FOR_DM_CLUSTER_ID,             0x06FF, "Reserved for Device Management Cluster Group ID" ) \
/* Tunnel Event Configuration Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TUNNELING_CLUSTER_NOT_FOUND,            0x0700, "Tunneling Cluster Not Found" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UNSUPPORTED_PROTOCOL,                   0x0701, "Unsupported Protocol" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_INCORRECT_PROTOCOL,                     0x0702, "Incorrect Protocol" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_REQUEST_TUNNEL_COMMAND_RECEIVED,        0x07C0, "Request Tunnel Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_REQUEST_TUNNEL_COMMAND_REJECTED,        0x07C1, "Request Tunnel Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_REQUEST_TUNNEL_COMMAND_GENERATED,       0x07C2, "Request Tunnel Command Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CLOSE_TUNNEL_COMMAND_RECEIVED,          0x07C3, "Close Tunnel Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CLOSE_TUNNEL_COMMAND_REJECTED,          0x07C4, "Close Tunnel Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_CLOSE_TUNNEL_COMMAND_GENERATED,         0x07C5, "Close Tunnel Command Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TRANSFER_DATA_COMMAND_RECEIVED,         0x07C6, "Transfer Data Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TRANSFER_DATA_COMMAND_REJECTED,         0x07C7, "Transfer Data Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TRANSFER_DATA_COMMAND_GENERATED,        0x07C8, "Transfer Data Command Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TRANSFER_DATA_ERROR_COMMAND_RECEIVED,   0x07C9, "Transfer Data Error Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TRANSFER_DATA_ERROR_COMMAND_REJECTED,   0x07CA, "Transfer Data Error Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_TRANSFER_DATA_ERROR_COMMAND_GENERATED,  0x07CB, "Transfer Data Error Command Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ACK_TRANSFER_DATA_COMMAND_RECEIVED,     0x07CC, "Ack Transfer Data Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ACK_TRANSFER_DATA_COMMAND_REJECTED,     0x07CD, "Ack Transfer Data Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_ACK_TRANSFER_DATA_COMMAND_GENERATED,    0x07CE, "Ack Transfer Data Command Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_READY_DATA_COMMAND_RECEIVED,            0x07CF, "Ready Data Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_READY_DATA_COMMAND_REJECTED,            0x07D0, "Ready Data Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_READY_DATA_COMMAND_GENERATED,           0x07D1, "Ready Data Command Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SUPPORTED_TUNNEL_PROT_CMD_RECV,     0x07D2, "Get Supported Tunnel Protocols Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SUPPORTED_TUNNEL_PROT_CMD_REJECT,   0x07D3, "Get Supported Tunnel Protocols Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_GET_SUPPORTED_TUNNEL_PROT_CMD_GENERATED,0x07D4, "Get Supported Tunnel Protocols Command Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_RESERVED_FOR_TUNNEL_CLUSTER_GROUP_ID,   0x07FF, "Reserved for Tunnel Cluster Group ID" ) \
/* OTA Event Configuration Attribute Set */ \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FIRMWARE_READY_FOR_ACTIVATION,          0x0800, "Firmware Ready for Activation" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FIRMWARE_ACTIVATED,                     0x0801, "Firmware Activated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_FIRMWARE_ACTIVATION_FAILURE,            0x0802, "Firmware Activation Failure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PATCH_READY_FOR_ACTIVATION,             0x0803, "Patch Ready for Activation" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PATCH_ACTIVATED,                        0x0804, "Patch Activated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_PATCH_FAILURE,                          0x0805, "Patch Failure" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_IMAGE_NOTIFY_COMMAND_RECEIVED,          0x08C0, "Image Notify Command Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_IMAGE_NOTIFY_COMMAND_REJECTED,          0x08C1, "Image Notify Command Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_QUERY_NEXT_IMAGE_REQUEST_GENERATED,     0x08C2, "Query Next Image Request Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_QUERY_NEXT_IMAGE_RESPONSE_RECEIVED,     0x08C3, "Query Next Image Response Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_QUERY_NEXT_IMAGE_RESPONSE_REJECTED,     0x08C4, "Query Next Image Response Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_IMAGE_BLOCK_REQUEST_GENERATED,          0x08C5, "Image Block Request Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_IMAGE_PAGE_REQUEST_GENERATED,           0x08C6, "Image Page Request Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_IMAGE_BLOCK_RESPONSE_RECEIVED,          0x08C7, "Image Block Response Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_IMAGE_BLOCK_RESPONSE_REJECTED,          0x08C8, "Image Block Response Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPGRADE_END_REQUEST_GENERATED,          0x08C9, "Upgrade End Request Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPGRADE_END_RESPONSE_RECEIVED,          0x08CA, "Upgrade End Response Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_UPGRADE_END_RESPONSE_REJECTED,          0x08CB, "Upgrade End Response Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_QUERY_SPECIFIC_FILE_REQUEST_GENERATED,  0x08CC, "Query Specific File Request Generated" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_QUERY_SPECIFIC_FILE_RESPONSE_RECEIVED,  0x08CD, "Query Specific File Response Received" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_QUERY_SPECIFIC_FILE_RESPONSE_REJECTED,  0x08CE, "Query Specific File Response Rejected" ) \
    XXX(ZBEE_ZCL_ATTR_ID_DEVICE_MANAGEMENT_CLNT_RESERVED_FOR_OTA_CLUSTER_GROUP_ID,      0x08FF, "Reserved For OTA Cluster Group ID" ) \
/* Smart Energy */ \
    XXX(ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_DEVICE_MANAGEMENT_CLNT,                  0xFFFE, "Attribute Reporting Status" )

VALUE_STRING_ENUM(zbee_zcl_device_management_attr_client_names);
VALUE_STRING_ARRAY(zbee_zcl_device_management_attr_client_names);
static value_string_ext zbee_zcl_device_management_attr_client_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_device_management_attr_client_names);

/* Server Commands Received */
#define zbee_zcl_device_management_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_GET_CHANGE_OF_TENANCY,           0x00, "Get Change Of Tenancy" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_GET_CHANGE_OF_SUPPLIER,          0x01, "Get Change Of Supplier" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_REQUEST_NEW_PASSWORD,            0x02, "Request New Password" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_GET_SITE_ID,                     0x03, "Get Site ID" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_REPORT_EVENT_CONFIGURATION,      0x04, "Report Event Configuration" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_GET_CIN,                         0x05, "Get CIN" )

VALUE_STRING_ENUM(zbee_zcl_device_management_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_device_management_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_device_management_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_PUBLISH_CHANGE_OF_TENANCY,           0x00, "Publish Change Of Tenancy" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_PUBLISH_CHANGE_OF_SUPPLIER,          0x01, "Publish Change Of Supplier" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_REQUEST_NEW_PASSWORD_RESPONSE,       0x02, "Request New Password Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_UPDATE_SITE_ID,                      0x03, "Update Site ID" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_SET_EVENT_CONFIGURATION,             0x04, "Set Event Configuration" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_GET_EVENT_CONFIGURATION,             0x05, "Get Event Configuration" ) \
    XXX(ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_UPDATE_CIN,                          0x06, "Update CIN" )

VALUE_STRING_ENUM(zbee_zcl_device_management_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_device_management_srv_tx_cmd_names);

#define zbee_zcl_device_management_password_types_VALUE_STRING_LIST(XXX)  \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_PASSWORD_TYPE_RESERVED, 0x00, "Reserved")        \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_PASSWORD_TYPE_PASSWORD_1, 0x01, "Password 1")    \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_PASSWORD_TYPE_PASSWORD_2, 0x02, "Password 2")    \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_PASSWORD_TYPE_PASSWORD_3, 0x03, "Password 3")    \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_PASSWORD_TYPE_PASSWORD_4, 0x04, "Password 4")

VALUE_STRING_ENUM(zbee_zcl_device_management_password_types);
VALUE_STRING_ARRAY(zbee_zcl_device_management_password_types);

#define zbee_zcl_device_management_event_configuration_log_types_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_EVENT_CONFIGURATION_DO_NOT_LOG, 0x0, "Do not Log")       \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_EVENT_CONFIGURATION_LOG_AS_TAMPER, 0x1, "Log as Tamper") \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_EVENT_CONFIGURATION_LOG_AS_FAULT, 0x2, "Log as Fault")   \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_EVENT_CONFIGURATION_LOG_AS_GENERAL_EVENT, 0x3, "Log as General Event")   \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_EVENT_CONFIGURATION_LOG_AS_SECURITY_EVENT, 0x4, "Log as Security Event") \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_EVENT_CONFIGURATION_LOG_AS_NETWORK_EVENT, 0x5, "Log as Network Event")

VALUE_STRING_ENUM(zbee_zcl_device_management_event_configuration_log_types);
VALUE_STRING_ARRAY(zbee_zcl_device_management_event_configuration_log_types);

#define zbee_zcl_device_management_contactor_states_VALUE_STRING_LIST(XXX)  \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_SUPPLY_OFF,       0x0, "Supply OFF")         \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_SUPPLY_OFF_ARMED, 0x1, "Supply OFF / ARMED") \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_SUPPLY_ON,        0x2, "Supply ON")          \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_SUPPLY_UNCHANGED, 0x3, "Supply UNCHANGED")

VALUE_STRING_ENUM(zbee_zcl_device_management_contactor_states);
VALUE_STRING_ARRAY(zbee_zcl_device_management_contactor_states);

#define zbee_zcl_device_management_configuration_controls_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_CONFIGURATION_CONTROL_APPLY_BY_LIST, 0x00, "Apply by List")  \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_CONFIGURATION_CONTROL_APPLY_BY_EVENT_GROUP, 0x01, "Apply by Event Group")  \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_CONFIGURATION_CONTROL_APPLY_BY_LOG_TYPE, 0x02, "Apply by Log Type")  \
    XXX(ZBEE_ZCL_DEVICE_MANAGEMENT_CONFIGURATION_CONTROL_APPLY_BY_CONFIGURATION_MATCH, 0x03, "Apply by Configuration Match")

VALUE_STRING_ENUM(zbee_zcl_device_management_configuration_controls);
VALUE_STRING_ARRAY(zbee_zcl_device_management_configuration_controls);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_zbee_zcl_device_management(void);
void proto_reg_handoff_zbee_zcl_device_management(void);

/* Attribute Dissector Helpers */
static void dissect_zcl_device_management_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_device_management = -1;

static int hf_zbee_zcl_device_management_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_device_management_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_device_management_attr_server_id = -1;
static int hf_zbee_zcl_device_management_attr_client_id = -1;
static int hf_zbee_zcl_device_management_attr_reporting_status = -1;
static int hf_zbee_zcl_device_management_password_type = -1;
static int hf_zbee_zcl_device_management_command_index = -1;
static int hf_zbee_zcl_device_management_total_commands = -1;
static int hf_zbee_zcl_device_management_event_id= -1;
static int hf_zbee_zcl_device_management_event_configuration = -1;
static int hf_zbee_zcl_device_management_event_configuration_logging = -1;
static int hf_zbee_zcl_device_management_event_configuration_push_event_to_wan = -1;
static int hf_zbee_zcl_device_management_event_configuration_push_event_to_han = -1;
static int hf_zbee_zcl_device_management_event_configuration_raise_alarm_zigbee = -1;
static int hf_zbee_zcl_device_management_event_configuration_raise_alarm_physical = -1;
static int hf_zbee_zcl_device_management_event_configuration_reserved = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_provider_id = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_issuer_event_id = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_tariff_type = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_implementation_date = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_pre_snapshot = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_post_snapshot = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reset_credit_register = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reset_debit_register = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reset_billing_period = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_tariff_plan = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_standing_charge = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_block_historical_load_profile_information = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_historical_load_profile_information = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_ihd_data_consumer = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_ihd_data_supplier = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_meter_contactor_state = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_transaction_log = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_prepayment_data = -1;
static int hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reserved = -1;

static int hf_zbee_zcl_device_management_publish_change_of_supplier_current_provider_id = -1;
static int hf_zbee_zcl_device_management_publish_change_of_supplier_issuer_event_id = -1;
static int hf_zbee_zcl_device_management_publish_change_of_supplier_tariff_type = -1;
static int hf_zbee_zcl_device_management_publish_change_of_supplier_proposed_provider_id = -1;
static int hf_zbee_zcl_device_management_publish_change_of_supplier_provider_change_implementation_time = -1;
static int hf_zbee_zcl_device_management_publish_change_of_supplier_provider_change_control = -1;
static int hf_zbee_zcl_device_management_publish_change_of_supplier_provider_proposed_provider_name = -1;
static int hf_zbee_zcl_device_management_publish_change_of_supplier_provider_proposed_provider_contact_details = -1;

static int hf_zbee_zcl_device_management_request_new_password_issuer_event_id = -1;
static int hf_zbee_zcl_device_management_request_new_password_implementation_date = -1;
static int hf_zbee_zcl_device_management_request_new_password_password = -1;
static int hf_zbee_zcl_device_management_request_new_password_duration_in_minutes = -1;

static int hf_zbee_zcl_device_management_update_site_id_issuer_event_id = -1;
static int hf_zbee_zcl_device_management_update_site_id_site_id_time = -1;
static int hf_zbee_zcl_device_management_update_site_id_provider_id = -1;
static int hf_zbee_zcl_device_management_update_site_id_site_id = -1;

static int hf_zbee_zcl_device_management_set_event_configuration_issuer_event_id = -1;
static int hf_zbee_zcl_device_management_set_event_configuration_start_time = -1;
static int hf_zbee_zcl_device_management_set_event_configuration_configuration_control = -1;
static int hf_zbee_zcl_device_management_set_event_configuration_event_configuration_number_of_events = -1;
static int hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_id = -1;
static int hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_group_id = -1;
static int hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_log_id = -1;
static int hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_configuration_value_match = -1;

static int hf_zbee_zcl_device_management_get_event_configuration_event_id = -1;

static int hf_zbee_zcl_device_management_update_cin_issuer_event_id = -1;
static int hf_zbee_zcl_device_management_update_cin_cin_implementation_time = -1;
static int hf_zbee_zcl_device_management_update_cin_provider_id = -1;
static int hf_zbee_zcl_device_management_update_cin_customerid_number = -1;

static int* const hf_zbee_zcl_device_management_event_configuration_flags[] = {
    &hf_zbee_zcl_device_management_event_configuration_logging,
    &hf_zbee_zcl_device_management_event_configuration_push_event_to_wan,
    &hf_zbee_zcl_device_management_event_configuration_push_event_to_han,
    &hf_zbee_zcl_device_management_event_configuration_raise_alarm_zigbee,
    &hf_zbee_zcl_device_management_event_configuration_raise_alarm_physical,
    &hf_zbee_zcl_device_management_event_configuration_reserved,
    NULL
};

static int* const hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_flags[] = {
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_pre_snapshot,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_post_snapshot,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reset_credit_register,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reset_debit_register,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reset_billing_period,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_tariff_plan,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_standing_charge,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_block_historical_load_profile_information,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_historical_load_profile_information,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_ihd_data_consumer,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_ihd_data_supplier,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_meter_contactor_state,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_transaction_log,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_prepayment_data,
    &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reserved,
    NULL
};

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_device_management = -1;
static gint ett_zbee_zcl_device_management_event_configuration_payload = -1;
static gint ett_zbee_zcl_device_management_event_configuration = -1;
static gint ett_zbee_zcl_device_management_proposed_tenancy_change_control = -1;

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_device_management_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
{
    switch (attr_id) {
        /* applies to all SE clusters */
        case ZBEE_ZCL_ATTR_ID_SE_ATTR_REPORT_STATUS_DEVICE_MANAGEMENT:
            proto_tree_add_item(tree, hf_zbee_zcl_device_management_attr_reporting_status, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default: /* Catch all */
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
            break;
    }
} /*dissect_zcl_device_management_attr_data*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_device_management_request_new_password(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    /* Password Type */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_password_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_device_management_report_event_configuration(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    proto_tree *event_configuration_payload;
    guint rem_len;

    /* Command Index */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_command_index, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Total Commands */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_total_commands, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    rem_len = tvb_reported_length_remaining(tvb, *offset);
    /* Event Configuration Payload */
    event_configuration_payload = proto_tree_add_subtree(tree, tvb, *offset, rem_len, ett_zbee_zcl_device_management_event_configuration_payload, NULL, "Event Configuration Payload");

    while(tvb_reported_length_remaining(tvb, *offset) > 2) {
        /* Event ID */
        proto_tree_add_item(event_configuration_payload, hf_zbee_zcl_device_management_event_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        /* Event Configuration */
        proto_tree_add_bitmask(event_configuration_payload, tvb, *offset, hf_zbee_zcl_device_management_event_configuration,
                               ett_zbee_zcl_device_management_event_configuration, hf_zbee_zcl_device_management_event_configuration_flags, ENC_NA);
        *offset += 1;
    }
}

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_device_management_publish_change_of_tenancy(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    nstime_t impl_date;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_publish_change_of_tenancy_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_publish_change_of_tenancy_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Tariff Type */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_publish_change_of_tenancy_tariff_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Implementation Date/Time */
    impl_date.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    impl_date.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_device_management_publish_change_of_tenancy_implementation_date, tvb, *offset, 4, &impl_date);
    *offset += 4;

    /* Proposed Tenancy Change Control */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control,
                               ett_zbee_zcl_device_management_proposed_tenancy_change_control, hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_flags, ENC_NA);
    *offset += 4;

} /*dissect_zcl_device_management_publish_change_of_tenancy*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_device_management_publish_change_of_supplier(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    nstime_t impl_time;
    gint name_length;
    gint detail_length;

    /* Current Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_publish_change_of_supplier_current_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_publish_change_of_supplier_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Tariff Type */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_publish_change_of_supplier_tariff_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Proposed Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_publish_change_of_supplier_proposed_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Provider Change Implementation Time */
    impl_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    impl_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_device_management_publish_change_of_supplier_provider_change_implementation_time, tvb, *offset, 4, &impl_time);
    *offset += 4;

    /* Provider Change Control */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_publish_change_of_supplier_provider_change_control, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Proposed Provider Name */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_device_management_publish_change_of_supplier_provider_proposed_provider_name, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &name_length);
    *offset += name_length;

    /* Proposed Provider Contact Details */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_device_management_publish_change_of_supplier_provider_proposed_provider_contact_details, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &detail_length);
    *offset += detail_length;

} /*dissect_zcl_device_management_publish_change_of_supplier*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_device_management_request_new_password_response(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    nstime_t impl_date;
    gint     password_length;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_request_new_password_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Implementation Date/Time */
    impl_date.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    impl_date.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_device_management_request_new_password_implementation_date, tvb, *offset, 4, &impl_date);
    *offset += 4;

    /* Duration in minutes */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_request_new_password_duration_in_minutes, tvb, *offset, 2, ENC_NA);
    *offset += 2;

    /* Password Type */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_password_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Password */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_device_management_request_new_password_password, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &password_length);
    *offset += password_length;

} /*dissect_zcl_device_management_request_new_password_response*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_device_management_update_site_id(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    nstime_t siteid_time;
    gint     siteid_length;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_update_site_id_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* SiteID Time */
    siteid_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    siteid_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_device_management_update_site_id_site_id_time, tvb, *offset, 4, &siteid_time);
    *offset += 4;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_update_site_id_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* SiteID */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_device_management_update_site_id_site_id, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &siteid_length);
    *offset += siteid_length;

} /*dissect_zcl_device_management_update_site_id*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_device_management_set_event_configuration(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    nstime_t start_time;
    guint8   config_control;
    guint8   number_of_events;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_set_event_configuration_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Start Date/Time */
    start_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    start_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_device_management_set_event_configuration_start_time, tvb, *offset, 4, &start_time);
    *offset += 4;

    /* Event Configuration */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_zbee_zcl_device_management_event_configuration,
                           ett_zbee_zcl_device_management_event_configuration, hf_zbee_zcl_device_management_event_configuration_flags, ENC_NA);
    *offset += 1;

    /* Configuration Control */
    config_control = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_set_event_configuration_configuration_control, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Event Configuration Payload */
    switch (config_control) {
        case ZBEE_ZCL_DEVICE_MANAGEMENT_CONFIGURATION_CONTROL_APPLY_BY_LIST:
            number_of_events = tvb_get_guint8(tvb, *offset);
            /* Number of Events */
            proto_tree_add_item(tree, hf_zbee_zcl_device_management_set_event_configuration_event_configuration_number_of_events, tvb, *offset, 1, ENC_NA);
            *offset += 1;

            /* Event IDs */
            for (guint i = 0; tvb_reported_length_remaining(tvb, *offset) > 0 && i < number_of_events; i++) {
                proto_tree_add_item(tree, hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
            }
            break;
        case ZBEE_ZCL_DEVICE_MANAGEMENT_CONFIGURATION_CONTROL_APPLY_BY_EVENT_GROUP:
            /* Event Group ID */
            proto_tree_add_item(tree, hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_group_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;
        case ZBEE_ZCL_DEVICE_MANAGEMENT_CONFIGURATION_CONTROL_APPLY_BY_LOG_TYPE:
            /* Log ID */
            proto_tree_add_item(tree, hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_log_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        case ZBEE_ZCL_DEVICE_MANAGEMENT_CONFIGURATION_CONTROL_APPLY_BY_CONFIGURATION_MATCH:
            /* Configuration Value Match */
            proto_tree_add_item(tree, hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_configuration_value_match, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
    }
} /*dissect_zcl_device_management_set_event_configuration*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_device_management_get_event_configuration(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    /* Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_get_event_configuration_event_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /*dissect_zcl_device_management_get_event_configuration*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_device_management_update_cin(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    nstime_t cin_impl_time;
    gint     customer_id_length;

    /* Issuer Event ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_update_cin_issuer_event_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* CIN Implementation Time */
    cin_impl_time.secs = (time_t)tvb_get_letohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
    cin_impl_time.nsecs = 0;
    proto_tree_add_time(tree, hf_zbee_zcl_device_management_update_cin_cin_implementation_time, tvb, *offset, 4, &cin_impl_time);
    *offset += 4;

    /* Provider ID */
    proto_tree_add_item(tree, hf_zbee_zcl_device_management_update_cin_provider_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* CustomerID Number */
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_device_management_update_cin_customerid_number, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &customer_id_length);
    *offset += customer_id_length;
} /*dissect_zcl_device_management_update_cin*/

/**
 *ZigBee ZCL Device Management cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_device_management(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    zbee_zcl_packet  *zcl;
    proto_tree       *payload_tree;
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
            val_to_str_const(cmd_id, zbee_zcl_device_management_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_device_management_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_device_management, NULL, "Payload");
            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_GET_CHANGE_OF_TENANCY:
                    /* No Payload */
                    break;
                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_GET_CHANGE_OF_SUPPLIER:
                    /* No Payload */
                    break;
                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_REQUEST_NEW_PASSWORD:
                    dissect_zcl_device_management_request_new_password(payload_tree, tvb, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_GET_SITE_ID:
                    /* No Payload */
                    break;

                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_REPORT_EVENT_CONFIGURATION:
                    dissect_zcl_device_management_report_event_configuration(payload_tree, tvb, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_GET_CIN:
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
            val_to_str_const(cmd_id, zbee_zcl_device_management_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_device_management_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_device_management, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {

               case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_PUBLISH_CHANGE_OF_TENANCY:
                    dissect_zcl_device_management_publish_change_of_tenancy(payload_tree, tvb, &offset);
                    break;
               case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_PUBLISH_CHANGE_OF_SUPPLIER:
                    dissect_zcl_device_management_publish_change_of_supplier(payload_tree, tvb, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_REQUEST_NEW_PASSWORD_RESPONSE:
                    dissect_zcl_device_management_request_new_password_response(payload_tree, tvb, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_UPDATE_SITE_ID:
                    dissect_zcl_device_management_update_site_id(payload_tree, tvb, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_SET_EVENT_CONFIGURATION:
                    dissect_zcl_device_management_set_event_configuration(payload_tree, tvb, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_GET_EVENT_CONFIGURATION:
                    dissect_zcl_device_management_get_event_configuration(payload_tree, tvb, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_DEVICE_MANAGEMENT_UPDATE_CIN:
                    dissect_zcl_device_management_update_cin(payload_tree, tvb, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_device_management*/

/**
 *This function registers the ZCL Device Management dissector
 *
*/
void
proto_register_zbee_zcl_device_management(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_device_management_attr_server_id,
            { "Attribute", "zbee_zcl_se.device_management.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_device_management_attr_server_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_attr_client_id,
            { "Attribute", "zbee_zcl_se.device_management.attr_client_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &zbee_zcl_device_management_attr_client_names_ext,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_attr_reporting_status,                         /* common to all SE clusters */
            { "Attribute Reporting Status", "zbee_zcl_se.device_management.attr.attr_reporting_status",
            FT_UINT8, BASE_HEX, VALS(zbee_zcl_se_reporting_status_names), 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.device_management.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_device_management_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.device_management.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_device_management_srv_rx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_password_type,
            { "Password Type", "zbee_zcl_se.device_management.password_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_device_management_password_types),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_command_index,
            { "Command Index", "zbee_zcl_se.device_management.command_index", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_total_commands,
            { "Total Commands", "zbee_zcl_se.device_management.total_commands", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_event_id,
            { "Event ID", "zbee_zcl_se.device_management.event_id", FT_UINT16, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_event_configuration,
            { "Event Configuration", "zbee_zcl_se.device_management.event_configuration", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_event_configuration_logging,
            { "Logging", "zbee_zcl_se.device_management.event_configuration.logging", FT_UINT8, BASE_HEX, VALS(zbee_zcl_device_management_event_configuration_log_types),
            0x07, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_event_configuration_push_event_to_wan,
            { "Push Event to WAN", "zbee_zcl_se.device_management.event_configuration.push_event_to_wan", FT_BOOLEAN, 8, NULL,
            0x08, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_event_configuration_push_event_to_han,
            { "Push Event to HAN", "zbee_zcl_se.device_management.event_configuration.push_event_to_han", FT_BOOLEAN, 8, NULL,
            0x10, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_event_configuration_raise_alarm_zigbee,
            { "Raise Alarm (Zigbee)", "zbee_zcl_se.device_management.event_configuration.raise_alarm_zigbee", FT_BOOLEAN, 8, NULL,
            0x20, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_event_configuration_raise_alarm_physical,
            { "Raise Alarm (Physical)", "zbee_zcl_se.device_management.event_configuration.raise_alarm_physical", FT_BOOLEAN, 8, NULL,
            0x40, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_event_configuration_reserved,
            { "Reserved", "zbee_zcl_se.device_management.event_configuration.reserved", FT_UINT8, BASE_HEX, NULL,
            0x80, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_provider_id,
            { "Provider ID", "zbee_zcl_se.device_management.publish_change_of_tenancy.provider_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.device_management.publish_change_of_tenancy.issuer_event_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_tariff_type,
            { "Tariff Type", "zbee_zcl_se.device_management.publish_change_of_tenancy.tariff_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_tariff_type_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_implementation_date,
            { "Implementation Date/Time", "zbee_zcl_se.device_management.publish_change_of_tenancy.implementation_date", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control,
            { "Proposed Tenancy Change Control", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_pre_snapshot,
            { "Pre Snapshots", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.pre_snapshot", FT_BOOLEAN, 32, NULL,
            0x00000001, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_post_snapshot,
            { "Post Snapshots", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.post_snapshot", FT_BOOLEAN, 32, NULL,
            0x00000002, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reset_credit_register,
            { "Reset Credit Register", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.reset_credit_register", FT_BOOLEAN, 32, NULL,
            0x00000004, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reset_debit_register,
            { "Reset Debit Register", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.reset_debit_register", FT_BOOLEAN, 32, NULL,
            0x00000008, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reset_billing_period,
            { "Reset Billing Period", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.reset_billing_period", FT_BOOLEAN, 32, NULL,
            0x00000010, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_tariff_plan,
            { "Clear Tariff Plan", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.clear_tariff_plan", FT_BOOLEAN, 32, NULL,
            0x00000020, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_standing_charge,
            { "Clear Standing Charge", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.clear_standing_charge", FT_BOOLEAN, 32, NULL,
            0x00000040, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_block_historical_load_profile_information,
            { "Block Historical Load Profile Information", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.block_historical_load_profile_information", FT_BOOLEAN, 32, NULL,
            0x00000080, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_historical_load_profile_information,
            { "Clear Historical Load Profile Information", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.clear_historical_load_profile_information", FT_BOOLEAN, 32, NULL,
            0x00000100, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_ihd_data_consumer,
            { "Clear IHD Data - Consumer", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.clear_ihd_data_consumer", FT_BOOLEAN, 32, NULL,
            0x00000200, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_ihd_data_supplier,
            { "Clear IHD Data - Supplier", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.clear_ihd_data_supplier", FT_BOOLEAN, 32, NULL,
            0x00000400, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_meter_contactor_state,
            { "Meter Contactor State \"On / Off / Armed\"", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.meter_contactor_state", FT_UINT32, BASE_HEX, VALS(zbee_zcl_device_management_contactor_states),
            0x00001800, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_transaction_log,
            { "Clear Transaction Log", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.clear_transaction_log", FT_BOOLEAN, 32, NULL,
            0x00002000, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_clear_prepayment_data,
            { "Clear Prepayment Data", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.clear_prepayment_data", FT_BOOLEAN, 32, NULL,
            0x00004000, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_tenancy_proposed_tenancy_change_control_reserved,
            { "Reserved", "zbee_zcl_se.device_management.publish_change_of_tenancy.proposed_tenancy_change_control.reserved", FT_UINT32, BASE_HEX, NULL,
            0xFFFF8000, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_supplier_current_provider_id,
            { "Current Provider ID", "zbee_zcl_se.device_management.publish_change_of_supplier.current_provider_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_supplier_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.device_management.publish_change_of_supplier.issuer_event_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_supplier_tariff_type,
            { "Tariff Type", "zbee_zcl_se.device_management.publish_change_of_supplier.tariff_type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_price_tariff_type_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_supplier_proposed_provider_id,
            { "Proposed Provider ID", "zbee_zcl_se.device_management.publish_change_of_supplier.proposed_provider_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_supplier_provider_change_implementation_time,
            { "Provider Change Implementation Time", "zbee_zcl_se.device_management.publish_change_of_supplier.provider_change_implementation_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_supplier_provider_change_control,
            { "Provider Change Control", "zbee_zcl_se.device_management.publish_change_of_supplier.provider_change_control", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_supplier_provider_proposed_provider_name,
            { "Proposed Provider Name", "zbee_zcl_se.device_management.publish_change_of_supplier.provider_proposed_provider_name", FT_UINT_STRING, STR_UNICODE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_publish_change_of_supplier_provider_proposed_provider_contact_details,
            { "Proposed Provider Contact Details", "zbee_zcl_se.device_management.publish_change_of_supplier.provider_proposed_provider_contact_details", FT_UINT_STRING, STR_UNICODE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_request_new_password_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.device_management.request_new_password.issuer_event_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_request_new_password_implementation_date,
            { "Implementation Date/Time", "zbee_zcl_se.device_management.request_new_password.implementation_date", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_request_new_password_duration_in_minutes,
            { "Duration in minutes", "zbee_zcl_se.device_management.request_new_password.duration_in_minutes", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_request_new_password_password,
            { "Password", "zbee_zcl_se.device_management.request_new_password.password", FT_UINT_STRING, STR_UNICODE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_update_site_id_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.device_management.update_site_id.issuer_event_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_update_site_id_site_id_time,
            { "SiteID Time", "zbee_zcl_se.device_management.update_site_id.site_id_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_update_site_id_provider_id,
            { "Provider ID", "zbee_zcl_se.device_management.update_site_id.provider_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_update_site_id_site_id,
            { "SiteID", "zbee_zcl_se.device_management.update_site_id.site_id", FT_UINT_STRING, STR_UNICODE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_get_event_configuration_event_id,
            { "Event ID", "zbee_zcl_se.device_management.get_event_configuration.event_id", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_update_cin_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.device_management.update_cin.issuer_event_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_update_cin_cin_implementation_time,
            { "CIN Implementation Time", "zbee_zcl_se.device_management.update_cin.cin_implementation_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_update_cin_provider_id,
            { "Provider ID", "zbee_zcl_se.device_management.update_cin.provider_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_update_cin_customerid_number,
            { "CustomerID Number", "zbee_zcl_se.device_management.update_cin.customerid_number", FT_UINT_STRING, STR_UNICODE, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_set_event_configuration_issuer_event_id,
            { "Issuer Event ID", "zbee_zcl_se.device_management.set_event_configuration.issuer_event_id", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_set_event_configuration_start_time,
            { "Start Date/Time", "zbee_zcl_se.device_management.set_event_configuration.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_set_event_configuration_configuration_control,
            { "Configuration Control", "zbee_zcl_se.device_management.set_event_configuration.configuration_control", FT_UINT8, BASE_HEX, VALS(zbee_zcl_device_management_configuration_controls),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_set_event_configuration_event_configuration_number_of_events,
            { "Number of Events", "zbee_zcl_se.device_management.set_event_configuration.event_configuration.number_of_events", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_id,
            { "Event ID", "zbee_zcl_se.device_management.set_event_configuration.event_configuration.number_of_events", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_group_id,
            { "Event Group ID", "zbee_zcl_se.device_management.set_event_configuration.event_configuration.event_group_id", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_log_id,
            { "Log ID", "zbee_zcl_se.device_management.set_event_configuration.event_configuration.log_id", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_device_management_set_event_configuration_event_configuration_event_configuration_value_match,
            { "Configuration Value Match", "zbee_zcl_se.device_management.set_event_configuration.event_configuration.configuration_value_match", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

    };

    /* ZCL Device Management subtrees */
    gint *ett[] = {
        &ett_zbee_zcl_device_management,
        &ett_zbee_zcl_device_management_event_configuration_payload,
        &ett_zbee_zcl_device_management_event_configuration,
        &ett_zbee_zcl_device_management_proposed_tenancy_change_control
    };

    /* Register the ZigBee ZCL Device Management cluster protocol name and description */
    proto_zbee_zcl_device_management = proto_register_protocol("ZigBee ZCL Device Management", "ZCL Device Management", ZBEE_PROTOABBREV_ZCL_DEVICE_MANAGEMENT);
    proto_register_field_array(proto_zbee_zcl_device_management, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Device Management dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_DEVICE_MANAGEMENT, dissect_zbee_zcl_device_management, proto_zbee_zcl_device_management);
} /*proto_register_zbee_zcl_device_management*/

/**
 *Hands off the ZCL Device Management dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_device_management(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_DEVICE_MANAGEMENT,
                            proto_zbee_zcl_device_management,
                            ett_zbee_zcl_device_management,
                            ZBEE_ZCL_CID_DEVICE_MANAGEMENT,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_device_management_attr_server_id,
                            hf_zbee_zcl_device_management_attr_client_id,
                            hf_zbee_zcl_device_management_srv_rx_cmd_id,
                            hf_zbee_zcl_device_management_srv_tx_cmd_id,
                            (zbee_zcl_fn_attr_data)dissect_zcl_device_management_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_device_management*/


/* ########################################################################## */
/* #### (0x0709) EVENTS CLUSTER ############################################# */
/* ########################################################################## */

/* Attributes - None */

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

/* Command Dissector Helpers */
static void dissect_zcl_events_get_event_log                    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_events_clear_event_log_request          (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_events_publish_event                    (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_events_publish_event_log                (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_events_clear_event_log_response         (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_events = -1;

static int hf_zbee_zcl_events_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_events_srv_rx_cmd_id = -1;
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
static int hf_zbee_zcl_events_publish_event_event_data = -1;
static int hf_zbee_zcl_events_publish_event_log_total_number_of_matching_events = -1;
static int hf_zbee_zcl_events_publish_event_log_command_index = -1;
static int hf_zbee_zcl_events_publish_event_log_total_commands = -1;
static int hf_zbee_zcl_events_publish_event_log_number_of_events_log_payload_control = -1;
static int hf_zbee_zcl_events_publish_event_log_log_id = -1;
static int hf_zbee_zcl_events_publish_event_log_event_id = -1;
static int hf_zbee_zcl_events_publish_event_log_event_time = -1;
static int hf_zbee_zcl_events_publish_event_log_event_data = -1;
static int hf_zbee_zcl_events_clear_event_log_response_cleared_event_logs = -1;

/* Initialize the subtree pointers */
#define ZBEE_ZCL_SE_EVENTS_NUM_INDIVIDUAL_ETT             1
#define ZBEE_ZCL_SE_EVENTS_NUM_PUBLISH_EVENT_LOG_ETT      100 // The Great Britain Companion Specification (GBCS) allows up to 100 even though ZigBee only allows 15
#define ZBEE_ZCL_SE_EVENTS_NUM_TOTAL_ETT                  (ZBEE_ZCL_SE_EVENTS_NUM_INDIVIDUAL_ETT + ZBEE_ZCL_SE_EVENTS_NUM_PUBLISH_EVENT_LOG_ETT)

static gint ett_zbee_zcl_events = -1;
static gint ett_zbee_zcl_events_publish_event_log_entry[ZBEE_ZCL_SE_EVENTS_NUM_PUBLISH_EVENT_LOG_ETT];

/*************************/
/* Function Bodies       */
/*************************/

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
    gint        length;

    if (gPREF_zbee_se_protocol_version >= ZBEE_SE_VERSION_1_2) {
        /* Log ID - Introduced from ZCL version 1.2 */
        proto_tree_add_item(tree, hf_zbee_zcl_events_publish_event_log_id, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }

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
    proto_tree_add_item_ret_length(tree, hf_zbee_zcl_events_publish_event_event_data, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &length);
    *offset += length;
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
    int         length;

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

        if (gPREF_zbee_se_protocol_version >= ZBEE_SE_VERSION_1_2) {
            /* Log ID - Introduced from ZCL version 1.2 */
            proto_tree_add_item(event_log_tree, hf_zbee_zcl_events_publish_event_log_log_id, tvb, *offset, 1, ENC_NA);
            *offset += 1;
        }

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
        proto_tree_add_item_ret_length(event_log_tree, hf_zbee_zcl_events_publish_event_log_event_data, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &length);
        *offset += length;

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

        { &hf_zbee_zcl_events_publish_event_event_data,
            { "Event Data", "zbee_zcl_se.events.publish_event.event_data", FT_UINT_BYTES, SEP_COLON, NULL,
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

        { &hf_zbee_zcl_events_publish_event_log_event_data,
            { "Event Data", "zbee_zcl_se.events.publish_event_log.event_data", FT_UINT_BYTES, SEP_COLON, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_events_clear_event_log_response_cleared_event_logs,
            { "Cleared Event Logs", "zbee_zcl_se.events.clear_event_log_response.cleared_event_logs", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

    };

    /* ZCL Events subtrees */
    gint *ett[ZBEE_ZCL_SE_EVENTS_NUM_TOTAL_ETT];
    ett[0] = &ett_zbee_zcl_events;

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
    register_dissector(ZBEE_PROTOABBREV_ZCL_EVENTS, dissect_zbee_zcl_events, proto_zbee_zcl_events);
} /*proto_register_zbee_zcl_events*/

/**
 *Hands off the ZCL Events dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_events(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_EVENTS,
                            proto_zbee_zcl_events,
                            ett_zbee_zcl_events,
                            ZBEE_ZCL_CID_EVENTS,
                            ZBEE_MFG_CODE_NONE,
                            -1, -1,
                            hf_zbee_zcl_events_srv_rx_cmd_id,
                            hf_zbee_zcl_events_srv_tx_cmd_id,
                            NULL
                         );
} /*proto_reg_handoff_zbee_zcl_events*/

/* ########################################################################## */
/* #### (0x070A) MDU PAIRING CLUSTER ############################################ */
/* ########################################################################## */

/* Attributes - None */

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

/* Command Dissector Helpers */
static void dissect_zcl_mdu_pairing_request (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_mdu_pairing_response(tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_mdu_pairing = -1;

static int hf_zbee_zcl_mdu_pairing_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_mdu_pairing_srv_rx_cmd_id = -1;
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
    register_dissector(ZBEE_PROTOABBREV_ZCL_MDU_PAIRING, dissect_zbee_zcl_mdu_pairing, proto_zbee_zcl_mdu_pairing);
} /*proto_register_zbee_zcl_mdu_pairing*/

/**
 *Hands off the ZCL MDU Pairing dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_mdu_pairing(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_MDU_PAIRING,
                            proto_zbee_zcl_mdu_pairing,
                            ett_zbee_zcl_mdu_pairing,
                            ZBEE_ZCL_CID_MDU_PAIRING,
                            ZBEE_MFG_CODE_NONE,
                            -1, -1,
                            hf_zbee_zcl_mdu_pairing_srv_rx_cmd_id,
                            hf_zbee_zcl_mdu_pairing_srv_tx_cmd_id,
                            NULL
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
static void dissect_zcl_sub_ghz_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr);

/* Command Dissector Helpers */
static void dissect_zcl_sub_ghz_suspend_zcl_messages(tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/

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
 *@param client_attr ZCL client
*/
static void
dissect_zcl_sub_ghz_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type, gboolean client_attr)
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
            dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
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
            /* payload_tree = */proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_sub_ghz, NULL, "Payload");

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
            { "Attribute", "zbee_zcl_se.sub_ghz.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_sub_ghz_attr_names),
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
    register_dissector(ZBEE_PROTOABBREV_ZCL_SUB_GHZ, dissect_zbee_zcl_sub_ghz, proto_zbee_zcl_sub_ghz);
} /*proto_register_zbee_zcl_sub_ghz*/

/**
 *Hands off the ZCL Sub-Ghz dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_sub_ghz(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_SUB_GHZ,
                            proto_zbee_zcl_sub_ghz,
                            ett_zbee_zcl_sub_ghz,
                            ZBEE_ZCL_CID_SUB_GHZ,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_sub_ghz_attr_id,
                            -1,
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

/* Server Commands Received */
#define zbee_zcl_ke_srv_rx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_KE_INITIATE_REQ,                        0x00, "Initiate Key Establishment Request" ) \
    XXX(ZBEE_ZCL_CMD_ID_KE_EPHEMERAL_REQ,                       0x01, "Ephemeral Data Request" ) \
    XXX(ZBEE_ZCL_CMD_ID_KE_CONFIRM_REQ,                         0x02, "Confirm Key Data Request" ) \
    XXX(ZBEE_ZCL_CMD_ID_KE_CLNT_TERMINATE,                      0x03, "Terminate Key Establishment" )

VALUE_STRING_ENUM(zbee_zcl_ke_srv_rx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_ke_srv_rx_cmd_names);

/* Server Commands Generated */
#define zbee_zcl_ke_srv_tx_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(ZBEE_ZCL_CMD_ID_KE_INITIATE_RSP,                        0x00, "Initiate Key Establishment Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_KE_EPHEMERAL_RSP,                       0x01, "Ephemeral Data Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_KE_CONFIRM_RSP,                         0x02, "Confirm Key Data Response" ) \
    XXX(ZBEE_ZCL_CMD_ID_KE_SRV_TERMINATE,                       0x03, "Terminate Key Establishment" )

VALUE_STRING_ENUM(zbee_zcl_ke_srv_tx_cmd_names);
VALUE_STRING_ARRAY(zbee_zcl_ke_srv_tx_cmd_names);

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

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_ke = -1;
static int hf_zbee_zcl_ke_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_ke_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_ke_attr_id = -1;
static int hf_zbee_zcl_ke_attr_client_id = -1;
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
            val_to_str_const(cmd_id, zbee_zcl_ke_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_ke_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, offset);
        offset += 1; /* delay from last add_item */
        if (rem_len > 0) {

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_KE_INITIATE_REQ:
                    dissect_zcl_ke_initiate(tvb, tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_KE_EPHEMERAL_REQ:
                    return dissect_zcl_ke_ephemeral_qeu(tvb, tree, &offset);

                case ZBEE_ZCL_CMD_ID_KE_CONFIRM_REQ:
                    return dissect_zcl_ke_confirm_macu(tvb, tree, &offset);

                case ZBEE_ZCL_CMD_ID_KE_CLNT_TERMINATE:
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
            val_to_str_const(cmd_id, zbee_zcl_ke_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_uint(tree, hf_zbee_zcl_ke_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_KE_INITIATE_RSP:
                    dissect_zcl_ke_initiate(tvb, tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_KE_EPHEMERAL_RSP:
                    return dissect_zcl_ke_ephemeral_qev(tvb, tree, &offset);

                case ZBEE_ZCL_CMD_ID_KE_CONFIRM_RSP:
                    return dissect_zcl_ke_confirm_macv(tvb, tree, &offset);

                case ZBEE_ZCL_CMD_ID_KE_SRV_TERMINATE:
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

        /* Server and client attributes are the same but should of cause be put in the correct field */
        { &hf_zbee_zcl_ke_attr_client_id,
            { "Attribute", "zbee_zcl_se.ke.attr_client_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_ke_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ke_srv_tx_cmd_id,
            { "Command", "zbee_zcl_se.ke.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ke_srv_tx_cmd_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_ke_srv_rx_cmd_id,
            { "Command", "zbee_zcl_se.ke.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_ke_srv_rx_cmd_names),
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
    register_dissector(ZBEE_PROTOABBREV_ZCL_KE, dissect_zbee_zcl_ke, proto_zbee_zcl_ke);
} /*proto_register_zbee_zcl_ke*/

/**
 *Hands off the ZCL Key Establishment dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_ke(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_KE,
                            proto_zbee_zcl_ke,
                            ett_zbee_zcl_ke,
                            ZBEE_ZCL_CID_KE,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_ke_attr_id,
                            hf_zbee_zcl_ke_attr_client_id,
                            hf_zbee_zcl_ke_srv_rx_cmd_id,
                            hf_zbee_zcl_ke_srv_tx_cmd_id,
                            NULL
                         );
} /*proto_reg_handoff_zbee_zcl_ke*/

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
