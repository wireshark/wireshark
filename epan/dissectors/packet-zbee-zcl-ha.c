/* packet-zbee-zcl-ha.c
 * Dissector routines for the ZigBee ZCL HA clusters like
 * Appliance Identification, Meter Identification ...
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
#include <epan/to_str.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"

/* ########################################################################## */
/* #### (0x0B00) APPLIANCE IDENTIFICATION CLUSTER ########################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_APPL_IDT_NUM_GENERIC_ETT               2
#define ZBEE_ZCL_APPL_IDT_NUM_ETT                       ZBEE_ZCL_APPL_IDT_NUM_GENERIC_ETT

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_BASIC_IDENT           0x0000  /* Basic Identification */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_COMPANY_NAME          0x0010  /* Company Name */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_COMPANY_ID            0x0011  /* Company ID */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_BRAND_NAME            0x0012  /* Brand Name */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_BRAND_ID              0x0013  /* Brand ID */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_MODEL                 0x0014  /* Model */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_PART_NUM              0x0015  /* Part Number */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_REV              0x0016  /* Product Revision */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_SW_REV                0x0017  /* Software Revision */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_NAME        0x0018  /* Product Type Name */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_ID          0x0019  /* Product Type ID */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_CECED_SPEC_VER        0x001A  /* CECED Specification Version */

/* Server Commands Received - None */

/* Server Commands Generated - None */

/* Companies Id */
#define ZBEE_ZCL_APPL_IDT_COMPANY_ID_IC                 0x4943  /* Indesit Company */

/* Brands Id */
#define ZBEE_ZCL_APPL_IDT_BRAND_ID_AR                   0x4152  /* Ariston */
#define ZBEE_ZCL_APPL_IDT_BRAND_ID_IN                   0x494E  /* Indesit */
#define ZBEE_ZCL_APPL_IDT_BRAND_ID_SC                   0x5343  /* Scholtes */
#define ZBEE_ZCL_APPL_IDT_BRAND_ID_ST                   0x5354  /* Stinol */

/* Product Types Id */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WG               0x0000  /* WhiteGoods */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_DW               0x5601  /* Dishwasher */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_TD               0x5602  /* Tumble Dryer */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WD               0x5603  /* Washer Dryer */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WM               0x5604  /* Washing Machine */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_GO               0x5E01  /* Oven */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_HB               0x5E03  /* Hobs */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_OV               0x5E06  /* Electrical Oven */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_IH               0x5E09  /* Induction Hobs */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_RF               0x6601  /* Refrigerator Freezer */

/* Product Name Types Id */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WG          0x0000  /* WhiteGoods */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_DW          0x4457  /* Dishwasher */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_TD          0x5444  /* Tumble Dryer */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WD          0x5744  /* Washer Dryer */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WM          0x574D  /* Washing Machine */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_GO          0x474F  /* Oven */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_HB          0x4842  /* Hobs */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_OV          0x4F56  /* Electrical Oven */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_IH          0x4948  /* Induction Hobs */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_RF          0x5246  /* Refrigerator Freezer */

/* CECED Specification Version values */
#define ZBEE_ZCL_APPL_IDT_CECED_SPEC_VAL_1_0_NOT_CERT   0x10  /* Compliant with v1.0, not certified */
#define ZBEE_ZCL_APPL_IDT_CECED_SPEC_VAL_1_0_CERT       0x1A  /* Compliant with v1.0, certified */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_appl_idt(void);
void proto_reg_handoff_zbee_zcl_appl_idt(void);

/* Command Dissector Helpers */
static void dissect_zcl_appl_idt_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_appl_idt = -1;

static int hf_zbee_zcl_appl_idt_attr_id = -1;
static int hf_zbee_zcl_appl_idt_company_id = -1;
static int hf_zbee_zcl_appl_idt_brand_id = -1;
static int hf_zbee_zcl_appl_idt_string_len = -1;
static int hf_zbee_zcl_appl_idt_prod_type_name = -1;
static int hf_zbee_zcl_appl_idt_prod_type_id = -1;
static int hf_zbee_zcl_appl_idt_ceced_spec_ver = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_appl_idt = -1;
static gint ett_zbee_zcl_appl_idt_basic = -1;

/* Attributes */
static const value_string zbee_zcl_appl_idt_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_BASIC_IDENT,      "Basic Identification" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_COMPANY_NAME,     "Company Name" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_COMPANY_ID,       "Company Id" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_BRAND_NAME,       "Brand Name" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_BRAND_ID,         "Brand Id" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_MODEL,            "Model" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_PART_NUM,         "Part Number" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_REV,         "Product Revision" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_SW_REV,           "Software Revision" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_NAME,   "Product Type Name" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_ID,     "Product Type Id" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_CECED_SPEC_VER,   "CECED Specification Version" },
    { 0, NULL }
};

/* Company Names */
static const value_string zbee_zcl_appl_idt_company_names[] = {
    { ZBEE_ZCL_APPL_IDT_COMPANY_ID_IC,      "Indesit Company" },
    { 0, NULL }
};

/* Brand Names */
static const value_string zbee_zcl_appl_idt_brand_names[] = {
    { ZBEE_ZCL_APPL_IDT_BRAND_ID_AR,        "Ariston" },
    { ZBEE_ZCL_APPL_IDT_BRAND_ID_IN,        "Indesit" },
    { ZBEE_ZCL_APPL_IDT_BRAND_ID_SC,        "Scholtes" },
    { ZBEE_ZCL_APPL_IDT_BRAND_ID_ST,        "Stinol" },
    { 0, NULL }
};

/* Product Type Names */
static const value_string zbee_zcl_appl_idt_prod_type_names[] = {
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WG,    "WhiteGoods" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_DW,    "Dishwasher" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_TD,    "Tumble Dryer" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WD,    "Washer Dryer" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WM,    "Washing Machine" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_GO,    "Oven" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_HB,    "Hobs" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_OV,    "Electrical Oven" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_IH,    "Induction Hobs" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_RF,    "Refrigerator Freezer" },
    { 0, NULL }
};

/* Product Type Name Names */
static const value_string zbee_zcl_appl_idt_prod_type_name_names[] = {
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WG,    "WhiteGoods" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_DW,    "Dishwasher" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_TD,    "Tumble Dryer" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WD,    "Washer Dryer" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WM,    "Washing Machine" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_GO,    "Oven" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_HB,    "Hobs" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_OV,    "Electrical Oven" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_IH,    "Induction Hobs" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_RF,    "Refrigerator Freezer" },
    { 0, NULL }
};

/* CECED Specification Version Names */
static const value_string zbee_zcl_appl_idt_ceced_spec_ver_names[] = {
    { ZBEE_ZCL_APPL_IDT_CECED_SPEC_VAL_1_0_NOT_CERT,  "Compliant with v1.0, not certified" },
    { ZBEE_ZCL_APPL_IDT_CECED_SPEC_VAL_1_0_CERT,      "Compliant with v1.0, certified" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Appliance Identification cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_appl_idt(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
	return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_appl_idt*/

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
dissect_zcl_appl_idt_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    proto_tree  *sub_tree;
    guint64     value64;

    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_BASIC_IDENT:
            value64 = tvb_get_letoh56(tvb, *offset);
            sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 8, ett_zbee_zcl_appl_idt_basic, NULL,
                    "Basic Identification: 0x%" G_GINT64_MODIFIER "x", value64);

            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_idt_company_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_idt_brand_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_idt_prod_type_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_idt_ceced_spec_ver, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_COMPANY_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_company_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_BRAND_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_brand_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_NAME:
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_string_len, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_prod_type_name, tvb, *offset, 2, ENC_BIG_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_prod_type_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_CECED_SPEC_VER:
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_ceced_spec_ver, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_appl_idt_attr_data*/

/**
 *This function registers the ZCL Appliance Identification dissector
 *
*/
void
proto_register_zbee_zcl_appl_idt(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_appl_idt_attr_id,
            { "Attribute", "zbee_zcl_ha.applident.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_idt_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_company_id,
            { "Company ID", "zbee_zcl_ha.applident.attr.company.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_idt_company_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_brand_id,
            { "Brand ID", "zbee_zcl_ha.applident.attr.brand.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_idt_brand_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_string_len,
            { "Length", "zbee_zcl_ha.applident.string.len", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_prod_type_name,
            { "Product Type Name", "zbee_zcl_ha.applident.attr.prod_type.name", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_idt_prod_type_name_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_prod_type_id,
            { "Product Type ID", "zbee_zcl_ha.applident.attr.prod_type.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_idt_prod_type_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_ceced_spec_ver,
            { "CECED Spec. Version", "zbee_zcl_ha.applident.attr.ceced_spec_ver", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_idt_ceced_spec_ver_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Appliance Identification subtrees */
    gint *ett[ZBEE_ZCL_APPL_IDT_NUM_ETT];

    ett[0] = &ett_zbee_zcl_appl_idt;
    ett[1] = &ett_zbee_zcl_appl_idt_basic;

    /* Register the ZigBee ZCL Appliance Identification cluster protocol name and description */
    proto_zbee_zcl_appl_idt = proto_register_protocol("ZigBee ZCL Appliance Identification", "ZCL Appliance Identification", ZBEE_PROTOABBREV_ZCL_APPLIDT);
    proto_register_field_array(proto_zbee_zcl_appl_idt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Appliance Identification dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_APPLIDT, dissect_zbee_zcl_appl_idt, proto_zbee_zcl_appl_idt);
} /*proto_register_zbee_zcl_appl_idt*/

/**
 *Hands off the Zcl Appliance Identification dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_appl_idt(void)
{
    zbee_zcl_init_cluster(  proto_zbee_zcl_appl_idt,
                            ett_zbee_zcl_appl_idt,
                            ZBEE_ZCL_CID_APPLIANCE_IDENTIFICATION,
                            hf_zbee_zcl_appl_idt_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_appl_idt_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_appl_idt*/

/* ########################################################################## */
/* #### (0x0B01) METER IDENTIFICATION CLUSTER ############################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_COMPANY_NAME                   0x0000  /* Company Name */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_METER_TYPE_ID                  0x0001  /* Meter Type ID */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_DATA_QUALITY_ID                0x0004  /* Data Quality ID */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_CUSTOMER_NAME                  0x0005  /* Customer Name */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_MODEL                          0x0006  /* Model */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_PART_NUM                       0x0007  /* Part Number */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_PRODUCT_REVISION               0x0008  /* Product Revision */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_SW_REVISION                    0x000a  /* Software Revision */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_UTILITY_NAME                   0x000b  /* Utility Name */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_POD                            0x000c  /* POD */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_AVAILABLE_PWR                  0x000d  /* Available Power */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_PWR_TH                         0x000e  /* Power Threshold */

/* Server Commands Received - None */

/* Server Commands Generated - None */


/* Meter Type IDs */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_1_METER               0x0000 /* Utility Primary Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_P_METER               0x0001 /* Utility Production Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_2_METER               0x0000 /* Utility Secondary Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_1_METER               0x0100 /* Private Primary Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_P_METER               0x0101 /* Private Primary Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_2_METER               0x0102 /* Private Primary Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_GENERIC_METER                 0x0110 /* Generic Meter */


/* Data Quality IDs */
#define ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_DATA_CERTIF              0x0000 /* All Data Certified */
#define ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_CERTIF_WO_INST_PWR       0x0001 /* Only Instantaneous Power not Certified */
#define ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_CERTIF_WO_CUM_CONS       0x0002 /* Only Cumulated Consumption not Certified */
#define ZBEE_ZCL_MET_IDT_DATA_QLTY_NOT_CERTIF_DATA              0x0003 /* Not Certified Data */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_met_idt(void);
void proto_reg_handoff_zbee_zcl_met_idt(void);

/* Command Dissector Helpers */
static void dissect_zcl_met_idt_attr_data  (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_met_idt = -1;

static int hf_zbee_zcl_met_idt_attr_id = -1;
static int hf_zbee_zcl_met_idt_meter_type_id = -1;
static int hf_zbee_zcl_met_idt_data_quality_id = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_met_idt = -1;

/* Attributes */
static const value_string zbee_zcl_met_idt_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_MET_IDT_COMPANY_NAME,            "Company Name" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_METER_TYPE_ID,           "Meter Type ID" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_DATA_QUALITY_ID,         "Data Quality ID" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_CUSTOMER_NAME,           "Customer Name" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_MODEL,                   "Model" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_PART_NUM,                "Part Number" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_PRODUCT_REVISION,        "Product Revision" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_SW_REVISION,             "Software Revision" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_UTILITY_NAME,            "Utility Name" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_POD,                     "POD" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_AVAILABLE_PWR,           "Available Power" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_PWR_TH,                  "Power Threshold" },
    { 0, NULL }
};

/* Meter Type IDs */
static const value_string zbee_zcl_met_idt_meter_type_names[] = {
    { ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_1_METER,        "Utility Primary Meter" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_P_METER,        "Meter Type ID" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_2_METER,        "Data Quality ID" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_1_METER,        "Customer Name" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_P_METER,        "Model" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_2_METER,        "Part Number" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_GENERIC_METER,          "Product Revision" },
    { 0, NULL }
};

/* Data Quality IDs */
static const value_string zbee_zcl_met_idt_data_quality_names[] = {
    { ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_DATA_CERTIF,               "All Data Certified" },
    { ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_CERTIF_WO_INST_PWR,        "Only Instantaneous Power not Certified" },
    { ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_CERTIF_WO_CUM_CONS,        "Only Cumulated Consumption not Certified" },
    { ZBEE_ZCL_MET_IDT_DATA_QLTY_NOT_CERTIF_DATA,               "Not Certified Data" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Meter Identification cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_met_idt(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_met_idt*/

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
dissect_zcl_met_idt_attr_data(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_MET_IDT_METER_TYPE_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_met_idt_meter_type_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_MET_IDT_DATA_QUALITY_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_met_idt_data_quality_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        default:
            dissect_zcl_attr_data(tvb, tree, offset, data_type);
            break;
    }

} /*dissect_zcl_met_idt_attr_data*/

/**
 *This function registers the ZCL Meter Identification dissector
 *
*/
void
proto_register_zbee_zcl_met_idt(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_met_idt_attr_id,
            { "Attribute",   "zbee_zcl_ha.metidt.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_met_idt_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_idt_meter_type_id,
            { "Meter Type ID", "zbee_zcl_ha.metidt.attr.meter_type.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_met_idt_meter_type_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_idt_data_quality_id,
            { "Data Quality ID", "zbee_zcl_ha.metidt.attr.data_quality.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_met_idt_data_quality_names),
            0x00, NULL, HFILL } }

    };

    /* Register the ZigBee ZCL Meter Identification cluster protocol name and description */
    proto_zbee_zcl_met_idt = proto_register_protocol("ZigBee ZCL Meter Identification", "ZCL Meter Identification", ZBEE_PROTOABBREV_ZCL_METIDT);
    proto_register_field_array(proto_zbee_zcl_met_idt, hf, array_length(hf));

    /* Register the ZigBee ZCL Meter Identification dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_METIDT, dissect_zbee_zcl_met_idt, proto_zbee_zcl_met_idt);
} /*proto_register_zbee_zcl_met_idt*/

/**
 *Hands off the Zcl Meter Identification dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_met_idt(void)
{
    zbee_zcl_init_cluster(  proto_zbee_zcl_met_idt,
                            ett_zbee_zcl_met_idt,
                            ZBEE_ZCL_CID_METER_IDENTIFICATION,
                            hf_zbee_zcl_met_idt_attr_id,
                            -1, -1,
                            (zbee_zcl_fn_attr_data)dissect_zcl_met_idt_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_met_idt*/

/* ########################################################################## */
/* #### (0x0B02) APPLIANCE EVENTS AND ALERT CLUSTER ######################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_APPL_EVTALT_NUM_GENERIC_ETT              1
#define ZBEE_ZCL_APPL_EVTALT_NUM_STRUCT_ETT               15
#define ZBEE_ZCL_APPL_EVTALT_NUM_ETT                      (ZBEE_ZCL_APPL_EVTALT_NUM_GENERIC_ETT + \
                                                          ZBEE_ZCL_APPL_EVTALT_NUM_STRUCT_ETT)
/* Attributes - None */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_CMD        0x00  /* Get Alerts */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_RSP_CMD    0x00  /* Get Alerts Response */
#define ZBEE_ZCL_CMD_ID_APPL_EVTALT_ALERTS_NOTIF_CMD      0x01  /* Alerts Notification */
#define ZBEE_ZCL_CMD_ID_APPL_EVTALT_EVENT_NOTIF_CMD       0x02  /* Event Notification */

/* Alert Count masks */
#define ZBEE_ZCL_APPL_EVTALT_COUNT_NUM_MASK               0x0F  /* Number of Alerts : [0..3] */
#define ZBEE_ZCL_APPL_EVTALT_COUNT_TYPE_MASK              0xF0  /* Type of Alerts : [4..7] */

/* Alert structure masks */
#define ZBEE_ZCL_APPL_EVTALT_ALERT_ID_MASK                0x0000FF  /* Alerts Id : [0..7] */
#define ZBEE_ZCL_APPL_EVTALT_CATEGORY_MASK                0x000F00  /* Cetegory : [8..11] */
#define ZBEE_ZCL_APPL_EVTALT_STATUS_MASK                  0x003000  /* Presence / Recovery: [12..13] */
#define ZBEE_ZCL_APPL_EVTALT_RESERVED_MASK                0x00C000  /* Reserved : [14..15] */
#define ZBEE_ZCL_APPL_EVTALT_PROPRIETARY_MASK             0xFF0000  /* Non-Standardized / Proprietary : [16..23] */

/* Category values */
#define ZBEE_ZCL_APPL_EVTALT_CATEGORY_RESERVED            0x00  /* Reserved */
#define ZBEE_ZCL_APPL_EVTALT_CATEGORY_WARNING             0x01  /* Warning */
#define ZBEE_ZCL_APPL_EVTALT_CATEGORY_DANGER              0x02  /* Danger */
#define ZBEE_ZCL_APPL_EVTALT_CATEGORY_FAILURE             0x03  /* Failure */

/* Status values */
#define ZBEE_ZCL_APPL_EVTALT_STATUS_RECOVERY              0x00  /* Recovery */
#define ZBEE_ZCL_APPL_EVTALT_STATUS_PRESENCE              0x01  /* Presence */

/* Event Identification */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_END_OF_CYCLE           0x01  /* End Of Cycle */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_RESERVED_1             0x02  /* Reserved */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_RESERVED_2             0x03  /* Reserved */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_TEMP_REACHED           0x04  /* Temperature Reached */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_END_OF_COOKING         0x05  /* End Of Cooking */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_SW_OFF                 0x06  /* Switching Off */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_WRONG_DATA             0xf7  /* Wrong Data */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_appl_evtalt(void);
void proto_reg_handoff_zbee_zcl_appl_evtalt(void);

/* Command Dissector Helpers */
static void dissect_zcl_appl_evtalt_get_alerts_rsp        (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_appl_evtalt_event_notif           (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_appl_evtalt = -1;

static int hf_zbee_zcl_appl_evtalt_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_appl_evtalt_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_appl_evtalt_count_num = -1;
static int hf_zbee_zcl_appl_evtalt_count_type = -1;
static int hf_zbee_zcl_appl_evtalt_alert_id = -1;
static int hf_zbee_zcl_appl_evtalt_category = -1;
static int hf_zbee_zcl_appl_evtalt_status = -1;
static int hf_zbee_zcl_appl_evtalt_reserved = -1;
static int hf_zbee_zcl_appl_evtalt_proprietary = -1;
static int hf_zbee_zcl_appl_evtalt_event_hdr = -1;
static int hf_zbee_zcl_appl_evtalt_event_id = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_appl_evtalt = -1;
static gint ett_zbee_zcl_appl_evtalt_alerts_struct[ZBEE_ZCL_APPL_EVTALT_NUM_STRUCT_ETT];

/* Server Commands Received */
static const value_string zbee_zcl_appl_evtalt_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_CMD,       "Get Alerts" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_appl_evtalt_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_RSP_CMD,   "Get Alerts Response" },
    { ZBEE_ZCL_CMD_ID_APPL_EVTALT_ALERTS_NOTIF_CMD,     "Alerts Notification" },
    { ZBEE_ZCL_CMD_ID_APPL_EVTALT_EVENT_NOTIF_CMD,      "Event Notification" },
    { 0, NULL }
};

/* Event Identification */
static const value_string zbee_zcl_appl_evtalt_event_id_names[] = {
    { ZBEE_ZCL_APPL_EVTALT_EVENT_END_OF_CYCLE,          "End Of Cycle" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_RESERVED_1,            "Reserved" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_RESERVED_2,            "Reserved" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_TEMP_REACHED,          "Temperature Reached" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_END_OF_COOKING,        "End Of Cooking" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_SW_OFF,                "Switching Off" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_WRONG_DATA,            "Wrong Data" },
    { 0, NULL }
};

/* Category values */
static const value_string zbee_zcl_appl_evtalt_category_names[] = {
    { ZBEE_ZCL_APPL_EVTALT_CATEGORY_RESERVED,           "Reserved" },
    { ZBEE_ZCL_APPL_EVTALT_CATEGORY_WARNING,            "Warning" },
    { ZBEE_ZCL_APPL_EVTALT_CATEGORY_DANGER,             "Danger" },
    { ZBEE_ZCL_APPL_EVTALT_CATEGORY_FAILURE,            "Failure" },
    { 0, NULL }
};

/* Status values */
static const value_string zbee_zcl_appl_evtalt_status_names[] = {
    { ZBEE_ZCL_APPL_EVTALT_STATUS_RECOVERY,             "Recovery" },
    { ZBEE_ZCL_APPL_EVTALT_STATUS_PRESENCE,             "Presence" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Appliance Events and Alerts cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_appl_evtalt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_appl_evtalt_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            /*payload_tree = */proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_appl_evtalt, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_CMD:
                    /* No payload */
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_appl_evtalt_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_appl_evtalt, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_RSP_CMD:
                case ZBEE_ZCL_CMD_ID_APPL_EVTALT_ALERTS_NOTIF_CMD:
                    dissect_zcl_appl_evtalt_get_alerts_rsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_APPL_EVTALT_EVENT_NOTIF_CMD:
                    dissect_zcl_appl_evtalt_event_notif(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_appl_evtalt*/

/**
 *This function is called in order to decode alerts structure payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset offset in the tvb buffer
*/
static void
dissect_zcl_appl_evtalt_alerts_struct(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_alert_id, tvb, *offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_category, tvb, *offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_status, tvb, *offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_reserved, tvb, *offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_proprietary, tvb, *offset, 3, ENC_BIG_ENDIAN);
    *offset += 3;
} /*dissect_zcl_appl_evtalt_alerts_struct*/

/**
 *This function is called in order to decode the GetAlertsRespose payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset offset in the tvb buffer
*/
static void
dissect_zcl_appl_evtalt_get_alerts_rsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree  *sub_tree = NULL;
    guint       i;
    guint8      count;

    /* Retrieve "Alert Count" field */
    count = tvb_get_guint8(tvb, *offset) & ZBEE_ZCL_APPL_EVTALT_COUNT_NUM_MASK;
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_count_num, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_count_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Alerts structure decoding */
    for ( i=0 ; i<count ; i++)
    {
        /* Create subtree */
        sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 1,
                    ett_zbee_zcl_appl_evtalt_alerts_struct[i], NULL, "Alerts Structure #%u", i);

        dissect_zcl_appl_evtalt_alerts_struct(tvb, sub_tree, offset);
    }
} /*dissect_zcl_appl_evtalt_get_alerts_rsp*/

/**
 *This function is called in order to decode the EventNotification payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset offset in the tvb buffer
*/
static void
dissect_zcl_appl_evtalt_event_notif(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve "Event Header" field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_event_hdr, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    /* Retrieve "Event Identification" field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_event_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_appl_evtalt_event_notif*/

/**
 *This function registers the ZCL Appliance Events and Alert dissector
 *
*/
void
proto_register_zbee_zcl_appl_evtalt(void)
{
    guint i, j;

    static hf_register_info hf[] = {

        { &hf_zbee_zcl_appl_evtalt_srv_tx_cmd_id,
            { "Command", "zbee_zcl_ha.applevtalt.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_evtalt_srv_tx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_srv_rx_cmd_id,
            { "Command", "zbee_zcl_ha.applevtalt.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_evtalt_srv_rx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_count_num,
            { "Number of Alerts", "zbee_zcl_ha.applevtalt.count.num", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_APPL_EVTALT_COUNT_NUM_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_count_type,
            { "Type of Alerts", "zbee_zcl_ha.applevtalt.count.type", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_APPL_EVTALT_COUNT_TYPE_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_alert_id,
            { "Alert Id", "zbee_zcl_ha.applevtalt.alert_id", FT_UINT24, BASE_HEX, NULL,
            ZBEE_ZCL_APPL_EVTALT_ALERT_ID_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_category,
            { "Category", "zbee_zcl_ha.applevtalt.category", FT_UINT24, BASE_HEX, VALS(zbee_zcl_appl_evtalt_category_names),
            ZBEE_ZCL_APPL_EVTALT_CATEGORY_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_status,
            { "Status", "zbee_zcl_ha.applevtalt.status", FT_UINT24, BASE_HEX, VALS(zbee_zcl_appl_evtalt_status_names),
            ZBEE_ZCL_APPL_EVTALT_STATUS_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_reserved,
            { "Reserved", "zbee_zcl_ha.applevtalt.reserved", FT_UINT24, BASE_HEX, NULL,
            ZBEE_ZCL_APPL_EVTALT_RESERVED_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_proprietary,
            { "Proprietary", "zbee_zcl_ha.applevtalt.proprietary", FT_UINT24, BASE_HEX, NULL,
            ZBEE_ZCL_APPL_EVTALT_PROPRIETARY_MASK, NULL, HFILL } },

         { &hf_zbee_zcl_appl_evtalt_event_hdr,
            { "Event Header", "zbee_zcl_ha.applevtalt.event.header", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

         { &hf_zbee_zcl_appl_evtalt_event_id,
            { "Event Id", "zbee_zcl_ha.applevtalt.event.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_evtalt_event_id_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Appliance Events And Alerts subtrees */
    gint *ett[ZBEE_ZCL_APPL_EVTALT_NUM_ETT];

    ett[0] = &ett_zbee_zcl_appl_evtalt;

    /* initialize attribute subtree types */
    for ( i = 0, j = ZBEE_ZCL_APPL_EVTALT_NUM_GENERIC_ETT; i < ZBEE_ZCL_APPL_EVTALT_NUM_STRUCT_ETT; i++, j++) {
        ett_zbee_zcl_appl_evtalt_alerts_struct[i] = -1;
        ett[j] = &ett_zbee_zcl_appl_evtalt_alerts_struct[i];
    }

    /* Register the ZigBee ZCL Appliance Events And Alerts cluster protocol name and description */
    proto_zbee_zcl_appl_evtalt = proto_register_protocol("ZigBee ZCL Appliance Events & Alert", "ZCL Appliance Events & Alert", ZBEE_PROTOABBREV_ZCL_APPLEVTALT);
    proto_register_field_array(proto_zbee_zcl_appl_evtalt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Appliance Control dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_APPLEVTALT, dissect_zbee_zcl_appl_evtalt, proto_zbee_zcl_appl_evtalt);
} /*proto_register_zbee_zcl_appl_evtalt*/

/**
 *Hands off the Zcl Appliance Events And Alerts dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_appl_evtalt(void)
{
    dissector_handle_t appl_evtalt_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    appl_evtalt_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_APPLEVTALT);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_APPLIANCE_EVENTS_AND_ALERT, appl_evtalt_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_appl_evtalt,
                            ett_zbee_zcl_appl_evtalt,
                            ZBEE_ZCL_CID_APPLIANCE_EVENTS_AND_ALERT,
                            -1,
                            hf_zbee_zcl_appl_evtalt_srv_rx_cmd_id,
                            hf_zbee_zcl_appl_evtalt_srv_tx_cmd_id,
                            NULL
                         );
} /*proto_reg_handoff_zbee_zcl_appl_evtalt*/

/* ########################################################################## */
/* #### (0x0B03) APPLIANCE STATISTICS CLUSTER ############################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_APPL_STATS_NUM_GENERIC_ETT                     1
#define ZBEE_ZCL_APPL_STATS_NUM_LOGS_ETT                        16
#define ZBEE_ZCL_APPL_STATS_NUM_ETT                             (ZBEE_ZCL_APPL_STATS_NUM_GENERIC_ETT + \
                                                                 ZBEE_ZCL_APPL_STATS_NUM_LOGS_ETT)

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_APPL_STATS_LOG_MAX_SIZE                0x0000  /* Log Max Size */
#define ZBEE_ZCL_ATTR_ID_APPL_STATS_LOG_QUEUE_MAX_SIZE          0x0001  /* Log Queue Max Size */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_REQ                      0x00  /* Log Request */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_REQ                0x01  /* Log Queue Request */

/* Server Commands Generated - None */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_NOTIF                    0x00  /* Log Notification */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_RSP                      0x01  /* Log Response */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_RSP                0x02  /* Log Queue Response */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_STATS_AVAILABLE              0x03  /* Statistics Available */

/* Others */
#define ZBEE_ZCL_APPL_STATS_INVALID_TIME                        0xffffffff /* Invalid UTC Time */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_appl_stats(void);
void proto_reg_handoff_zbee_zcl_appl_stats(void);

/* Command Dissector Helpers */
static void dissect_zcl_appl_stats_log_req              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_appl_stats_log_rsp              (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void dissect_zcl_appl_stats_log_queue_rsp        (tvbuff_t *tvb, proto_tree *tree, guint *offset);

/* Private functions prototype */
static void decode_zcl_appl_stats_utc_time              (gchar *s, guint32 value);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_appl_stats = -1;

static int hf_zbee_zcl_appl_stats_attr_id = -1;
static int hf_zbee_zcl_appl_stats_srv_tx_cmd_id = -1;
static int hf_zbee_zcl_appl_stats_srv_rx_cmd_id = -1;
static int hf_zbee_zcl_appl_stats_utc_time = -1;
static int hf_zbee_zcl_appl_stats_log_length = -1;
static int hf_zbee_zcl_appl_stats_log_payload = -1;
static int hf_zbee_zcl_appl_stats_log_queue_size = -1;
static int hf_zbee_zcl_appl_stats_log_id = -1;

/* Initialize the subtree pointers */
static gint ett_zbee_zcl_appl_stats = -1;
static gint ett_zbee_zcl_appl_stats_logs[ZBEE_ZCL_APPL_STATS_NUM_LOGS_ETT];

/* Attributes */
static const value_string zbee_zcl_appl_stats_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_APPL_STATS_LOG_MAX_SIZE,         "Log Max Size" },
    { ZBEE_ZCL_ATTR_ID_APPL_STATS_LOG_QUEUE_MAX_SIZE,   "Log Queue Max Size" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_appl_stats_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_REQ,               "Log Request" },
    { ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_REQ,         "Log Queue Request" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_appl_stats_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_NOTIF,             "Log Notification" },
    { ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_RSP,               "Log Response" },
    { ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_RSP,         "Log Queue Response" },
    { ZBEE_ZCL_CMD_ID_APPL_STATS_STATS_AVAILABLE,       "Statistics Available" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Appliance Statistics cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_appl_stats (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
            val_to_str_const(cmd_id, zbee_zcl_appl_stats_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_srv_rx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_appl_stats, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_REQ:
                    dissect_zcl_appl_stats_log_req(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_REQ:
                    /* No payload */
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_appl_stats_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_srv_tx_cmd_id, tvb, offset, 1, cmd_id);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_appl_stats, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_NOTIF:
                case ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_RSP:
                    dissect_zcl_appl_stats_log_rsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_RSP:
                case ZBEE_ZCL_CMD_ID_APPL_STATS_STATS_AVAILABLE:
                    dissect_zcl_appl_stats_log_queue_rsp(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_appl_stats*/

/**
 *This function is called in order to decode "LogRequest" payload command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_appl_stats_log_req(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    /* Retrieve 'Log ID' field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_appl_stats_log_req*/

/**
 *This function is called in order to decode "LogNotification" and
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_appl_stats_log_rsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint32 log_len;

    /* Retrieve 'UTCTime' field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_utc_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve 'Log ID' field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve 'Log Length' field */
    log_len = tvb_get_letohl(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_length, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve 'Log Payload' field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_payload, tvb, *offset, log_len, ENC_NA);
    *offset += log_len;
}/*dissect_zcl_appl_stats_log_rsp*/

/**
 *This function is called in order to decode "LogQueueResponse" and
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_appl_stats_log_queue_rsp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    gint list_len;

    /* Retrieve 'Log Queue Size' field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_queue_size, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Dissect the attribute id list */
    list_len = tvb_reported_length_remaining(tvb, *offset);
    if ( list_len > 0 ) {
        while ( *offset < (guint)list_len ) {
            /* Retrieve 'Log ID' field */
            proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
        }
    }
}/*dissect_zcl_appl_stats_log_queue_rsp*/

/**
 *This function decodes utc time, with peculiarity case for
 *
 *@param s string to display
 *@param value value to decode
*/
static void
decode_zcl_appl_stats_utc_time(gchar *s, guint32 value)
{
    if (value == ZBEE_ZCL_APPL_STATS_INVALID_TIME)
        g_snprintf(s, ITEM_LABEL_LENGTH, "Invalid UTC Time");
    else {
        gchar *utc_time;
        value += ZBEE_ZCL_NSTIME_UTC_OFFSET;
        utc_time = abs_time_secs_to_str (NULL, value, ABSOLUTE_TIME_LOCAL, TRUE);
        g_snprintf(s, ITEM_LABEL_LENGTH, "%s", utc_time);
        wmem_free(NULL, utc_time);
    }
} /* decode_zcl_appl_stats_utc_time */

/**
 *This function registers the ZCL Appliance Statistics dissector
 *
*/
void
proto_register_zbee_zcl_appl_stats(void)
{
    guint i, j;

    static hf_register_info hf[] = {

        { &hf_zbee_zcl_appl_stats_attr_id,
            { "Attribute", "zbee_zcl_ha.applstats.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_stats_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_srv_tx_cmd_id,
            { "Command", "zbee_zcl_ha.applstats.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_stats_srv_tx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_srv_rx_cmd_id,
            { "Command", "zbee_zcl_ha.applstats.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_stats_srv_rx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_utc_time,
            { "UTC Time", "zbee_zcl_ha.applstats.utc_time", FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_zcl_appl_stats_utc_time),
            0x0, NULL, HFILL }},

        { &hf_zbee_zcl_appl_stats_log_length,
            { "Log Length", "zbee_zcl_ha.applstats.log.length", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_log_id,
            { "Log ID", "zbee_zcl_ha.applstats.log.id", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_log_queue_size,
            { "Log Queue Size", "zbee_zcl_ha.applstats.log_queue_size", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_log_payload,
            { "Log Payload", "zbee_zcl_ha.applstats.log.payload", FT_BYTES, SEP_COLON, NULL,
            0x00, NULL, HFILL } },

    };

    /* ZCL ApplianceStatistics subtrees */
    static gint *ett[ZBEE_ZCL_APPL_STATS_NUM_ETT];

    ett[0] = &ett_zbee_zcl_appl_stats;

    /* initialize attribute subtree types */
    for ( i = 0, j = ZBEE_ZCL_APPL_STATS_NUM_GENERIC_ETT; i < ZBEE_ZCL_APPL_STATS_NUM_LOGS_ETT; i++, j++ ) {
        ett_zbee_zcl_appl_stats_logs[i] = -1;
        ett[j] = &ett_zbee_zcl_appl_stats_logs[i];
    }

    /* Register the ZigBee ZCL Appliance Statistics cluster protocol name and description */
    proto_zbee_zcl_appl_stats = proto_register_protocol("ZigBee ZCL Appliance Statistics", "ZCL Appliance Statistics", ZBEE_PROTOABBREV_ZCL_APPLSTATS);
    proto_register_field_array(proto_zbee_zcl_appl_stats, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Appliance Statistics dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_APPLSTATS, dissect_zbee_zcl_appl_stats, proto_zbee_zcl_appl_stats);
} /* proto_register_zbee_zcl_appl_stats */

/**
 *Hands off the Zcl Appliance Statistics cluster dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_appl_stats(void)
{
    dissector_handle_t appl_stats_handle;

    /* Register our dissector with the ZigBee application dissectors. */
    appl_stats_handle = find_dissector(ZBEE_PROTOABBREV_ZCL_APPLSTATS);
    dissector_add_uint("zbee.zcl.cluster", ZBEE_ZCL_CID_APPLIANCE_STATISTICS, appl_stats_handle);

    zbee_zcl_init_cluster(  proto_zbee_zcl_appl_stats,
                            ett_zbee_zcl_appl_stats,
                            ZBEE_ZCL_CID_APPLIANCE_STATISTICS,
                            hf_zbee_zcl_appl_stats_attr_id,
                            hf_zbee_zcl_appl_stats_srv_rx_cmd_id,
                            hf_zbee_zcl_appl_stats_srv_tx_cmd_id,
                            NULL
                         );
} /*proto_reg_handoff_zbee_zcl_appl_stats*/

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
