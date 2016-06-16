/* packet-canopen.c
 * Routines for CANopen dissection
 * Copyright 2011, Yegor Yefremov <yegorslists@googlemail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_canopen(void);
void proto_reg_handoff_canopen(void);

/* Initialize the protocol and registered fields */
static int proto_canopen = -1;
static int hf_canopen_cob_id = -1;
static int hf_canopen_function_code = -1;
static int hf_canopen_node_id = -1;
static int hf_canopen_pdo_data = -1;
static int hf_canopen_pdo_data_string = -1;
static int hf_canopen_sdo_cmd = -1;
static int hf_canopen_sdo_cmd_ccs = -1;
static int hf_canopen_sdo_cmd_scs = -1;
static int hf_canopen_sdo_cmd_toggle = -1;
static int hf_canopen_sdo_cmd_updown_n = -1;
static int hf_canopen_sdo_cmd_updown_c = -1;
static int hf_canopen_sdo_cmd_init_n = -1;
static int hf_canopen_sdo_cmd_init_e = -1;
static int hf_canopen_sdo_cmd_init_s = -1;
static int hf_canopen_sdo_main_idx = -1;
static int hf_canopen_sdo_sub_idx = -1;
static int hf_canopen_sdo_data = -1;
static int hf_canopen_sdo_abort_code = -1;
static int hf_canopen_reserved = -1;
static int hf_canopen_em_err_code = -1;
static int hf_canopen_em_err_reg = -1;
static int hf_canopen_em_err_field = -1;
static int hf_canopen_nmt_ctrl_cs = -1;
static int hf_canopen_nmt_ctrl_node_id = -1;
static int hf_canopen_nmt_guard_state = -1;
static int hf_canopen_nmt_guard_toggle = -1;
static int hf_canopen_sync_counter = -1;
static int hf_canopen_lss_cs = -1;
static int hf_canopen_lss_addr_vendor = -1;
static int hf_canopen_lss_addr_product = -1;
static int hf_canopen_lss_addr_revision = -1;
static int hf_canopen_lss_addr_revision_low = -1;
static int hf_canopen_lss_addr_revision_high = -1;
static int hf_canopen_lss_addr_serial = -1;
static int hf_canopen_lss_addr_serial_low = -1;
static int hf_canopen_lss_addr_serial_high = -1;
static int* hf_canopen_lss_addr_ident[] = {
        &hf_canopen_lss_addr_vendor,
        &hf_canopen_lss_addr_product,
        &hf_canopen_lss_addr_revision_low,
        &hf_canopen_lss_addr_revision_high,
        &hf_canopen_lss_addr_serial_low,
        &hf_canopen_lss_addr_serial_high
};
static int* hf_canopen_lss_addr_inquire[] = {
        &hf_canopen_lss_addr_vendor,
        &hf_canopen_lss_addr_product,
        &hf_canopen_lss_addr_revision,
        &hf_canopen_lss_addr_serial
};
static int hf_canopen_lss_fastscan_id = -1;
static int hf_canopen_lss_fastscan_check = -1;
static int hf_canopen_lss_fastscan_sub = -1;
static int hf_canopen_lss_fastscan_next = -1;
static int hf_canopen_lss_switch_mode = -1;
static int hf_canopen_lss_nid = -1;
static int hf_canopen_lss_conf_id_err_code = -1;
static int hf_canopen_lss_conf_bt_err_code = -1;
static int hf_canopen_lss_store_conf_err_code = -1;
static int hf_canopen_lss_spec_err = -1;
static int hf_canopen_lss_bt_tbl_selector = -1;
static int hf_canopen_lss_bt_tbl_index = -1;
static int hf_canopen_lss_abt_delay = -1;
static int hf_canopen_time_stamp = -1;
static int hf_canopen_time_stamp_ms = -1;
static int hf_canopen_time_stamp_days = -1;


  /* Download segment request (ccs=0) decode mask */
static const int *sdo_cmd_fields_ccs0[] = {
  &hf_canopen_sdo_cmd_ccs,
  &hf_canopen_sdo_cmd_toggle,
  &hf_canopen_sdo_cmd_updown_n,
  &hf_canopen_sdo_cmd_updown_c,
  NULL
};
/* Initiate download request (ccs=1) decode mask */
static const int *sdo_cmd_fields_ccs1[] = {
  &hf_canopen_sdo_cmd_ccs,
  &hf_canopen_sdo_cmd_init_n,
  &hf_canopen_sdo_cmd_init_e,
  &hf_canopen_sdo_cmd_init_s,
  NULL
};
/* Initiate upload request (ccs=2) decode mask */
static const int *sdo_cmd_fields_ccs2[] = {
  &hf_canopen_sdo_cmd_ccs,
  NULL
};
/* Download segment request (ccs=3) decode mask */
static const int *sdo_cmd_fields_ccs3[] = {
  &hf_canopen_sdo_cmd_ccs,
  &hf_canopen_sdo_cmd_toggle,
  NULL
};
/*  */
static const int *sdo_cmd_fields_ccs4[] = {
  &hf_canopen_sdo_cmd_ccs,
  NULL
};
/* Block upload (ccs=5) decode mask */
static const int *sdo_cmd_fields_ccs5[] = {
  &hf_canopen_sdo_cmd_ccs,
  /* TODO: full decoding depends on subcommand */
  NULL
};
/* Block download (ccs=6) decode mask */
static const int *sdo_cmd_fields_ccs6[] = {
  &hf_canopen_sdo_cmd_ccs,
  /* TODO: full decoding depends on subcommand */
  NULL
};

static const int **_sdo_cmd_fields_ccs[] = {
  sdo_cmd_fields_ccs0,
  sdo_cmd_fields_ccs1,
  sdo_cmd_fields_ccs2,
  sdo_cmd_fields_ccs3,
  sdo_cmd_fields_ccs4,
  sdo_cmd_fields_ccs5,
  sdo_cmd_fields_ccs6
};

static inline const int **
sdo_cmd_fields_ccs(guint cs)
{
    if (cs < array_length(_sdo_cmd_fields_ccs))
        return _sdo_cmd_fields_ccs[cs];
    return NULL;
}


/* (scs=0) decode mask */
static const int *sdo_cmd_fields_scs0[] = {
  &hf_canopen_sdo_cmd_scs,
  &hf_canopen_sdo_cmd_toggle,
  &hf_canopen_sdo_cmd_updown_n,
  &hf_canopen_sdo_cmd_updown_c,
  NULL
};
/* (scs=1) decode mask */
static const int *sdo_cmd_fields_scs1[] = {
  &hf_canopen_sdo_cmd_scs,
  &hf_canopen_sdo_cmd_toggle,
  NULL
};
/* (scs=2) decode mask */
static const int *sdo_cmd_fields_scs2[] = {
  &hf_canopen_sdo_cmd_scs,
  &hf_canopen_sdo_cmd_init_n,
  &hf_canopen_sdo_cmd_init_e,
  &hf_canopen_sdo_cmd_init_s,
  NULL
};
/* (scs=3) decode mask */
static const int *sdo_cmd_fields_scs3[] = {
  &hf_canopen_sdo_cmd_scs,
  NULL
};
/* (scs=4) decode mask */
static const int *sdo_cmd_fields_scs4[] = {
  &hf_canopen_sdo_cmd_scs,
  NULL
};
/* (scs=5) decode mask */
static const int *sdo_cmd_fields_scs5[] = {
  &hf_canopen_sdo_cmd_scs,
  /* TODO: full decoding depends on subcommand */
  NULL
};
/* (scs=6) decode mask */
static const int *sdo_cmd_fields_scs6[] = {
  &hf_canopen_sdo_cmd_scs,
  /* TODO: full decoding depends on subcommand */
  NULL
};


static const int **_sdo_cmd_fields_scs[] = {
  sdo_cmd_fields_scs0,
  sdo_cmd_fields_scs1,
  sdo_cmd_fields_scs2,
  sdo_cmd_fields_scs3,
  sdo_cmd_fields_scs4,
  sdo_cmd_fields_scs5,
  sdo_cmd_fields_scs6
};

static inline const int **
sdo_cmd_fields_scs(guint cs)
{
    if (cs < array_length(_sdo_cmd_fields_scs))
        return _sdo_cmd_fields_scs[cs];
    return NULL;
}

/* Initialize the subtree pointers */
static gint ett_canopen = -1;
static gint ett_canopen_cob = -1;
static gint ett_canopen_type = -1;
static gint ett_canopen_sdo_cmd = -1;

/* broadcast messages */
#define FC_NMT                  0x0
#define FC_SYNC                 0x1
#define FC_TIME_STAMP           0x2

/* point-to-point messages */
#define FC_EMERGENCY            0x1
#define FC_PDO1_TX              0x3
#define FC_PDO1_RX              0x4
#define FC_PDO2_TX              0x5
#define FC_PDO2_RX              0x6
#define FC_PDO3_TX              0x7
#define FC_PDO3_RX              0x8
#define FC_PDO4_TX              0x9
#define FC_PDO4_RX              0xA
#define FC_DEFAULT_SDO_TX       0xB
#define FC_DEFAULT_SDO_RX       0xC
#define FC_NMT_ERR_CONTROL      0xE

static const value_string CAN_open_bcast_msg_type_vals[] = {
    { FC_NMT,              "NMT"},
    { FC_SYNC,             "SYNC"},
    { FC_TIME_STAMP,       "TIME STAMP"},
    { 0, NULL}
};

static const value_string CAN_open_p2p_msg_type_vals[] = {
    { FC_EMERGENCY,        "EMCY"},
    { FC_PDO1_TX,          "PDO1 (tx)"},
    { FC_PDO1_RX,          "PDO1 (rx)"},
    { FC_PDO2_TX,          "PDO2 (tx)"},
    { FC_PDO2_RX,          "PDO2 (rx)"},
    { FC_PDO3_TX,          "PDO3 (tx)"},
    { FC_PDO3_RX,          "PDO3 (rx)"},
    { FC_PDO4_TX,          "PDO4 (tx)"},
    { FC_PDO4_RX,          "PDO4 (rx)"},
    { FC_DEFAULT_SDO_TX,   "Default-SDO (tx)"},
    { FC_DEFAULT_SDO_RX,   "Default-SDO (rx)"},
    { FC_NMT_ERR_CONTROL,  "NMT Error Control"},
    { 0, NULL}
};

/* message types */
#define MT_UNKNOWN                       0
#define MT_NMT_CTRL                      1
#define MT_SYNC                          2
#define MT_TIME_STAMP                    3
#define MT_EMERGENCY                     4
#define MT_PDO                           5
#define MT_SDO                           6
#define MT_NMT_ERR_CTRL                  7
#define MT_LSS_MASTER                    10
#define MT_LSS_SLAVE                     11

/* TIME STAMP conversion defines */
#define TS_DAYS_BETWEEN_1970_AND_1984   5113
#define TS_SECONDS_IN_PER_DAY           86400
#define TS_NANOSEC_PER_MSEC             1000000

/* SDO command specifier */
#define SDO_CCS_DOWN_SEG_REQ    0
#define SDO_CCS_INIT_DOWN_REQ   1
#define SDO_CCS_INIT_UP_REQ     2
#define SDO_CCS_UP_SEQ_REQ      3
#define SDO_CCS_BLOCK_UP        5
#define SDO_CCS_BLOCK_DOWN      6

#define SDO_SCS_UP_SEQ_RESP     0
#define SDO_SCS_DOWN_SEG_RESP   1
#define SDO_SCS_INIT_UP_RESP    2
#define SDO_SCS_INIT_DOWN_RESP  3
#define SDO_SCS_BLOCK_DOWN      5
#define SDO_SCS_BLOCK_UP        6

#define SDO_CS_ABORT_TRANSFER   4

static const range_string obj_dict[] = {
    { 0x0000, 0x0000, "not used"},
    { 0x0001, 0x001F, "Static data types"},
    { 0x0020, 0x003F, "Complex data types"},
    { 0x0040, 0x005F, "Manufacturer-specific complex data types"},
    { 0x0060, 0x025F, "Device profile specific data types"},
    { 0x0260, 0x03FF, "reserved"},
    { 0x0400, 0x0FFF, "reserved"},
    { 0x1000, 0x1FFF, "Communication profile area"},
    { 0x2000, 0x5FFF, "Manufacturer-specific profile area"},
    { 0x6000, 0x67FF, "Standardized profile area 1st logical device"},
    { 0x6800, 0x6FFF, "Standardized profile area 2nd logical device"},
    { 0x7000, 0x77FF, "Standardized profile area 3rd logical device"},
    { 0x7800, 0x7FFF, "Standardized profile area 4th logical device"},
    { 0x8000, 0x87FF, "Standardized profile area 5th logical device"},
    { 0x8800, 0x8FFF, "Standardized profile area 6th logical device"},
    { 0x9000, 0x97FF, "Standardized profile area 7th logical device"},
    { 0x9800, 0x9FFF, "Standardized profile area 8th logical device"},
    { 0xA000, 0xAFFF, "Standardized network variable area"},
    { 0xB000, 0xBFFF, "Standardized system variable area"},
    { 0xC000, 0xFFFF, "reserved"},
    { 0,      0,      NULL}
};

/* NMT command specifiers */
static const value_string nmt_ctrl_cs[] = {
    { 0x01, "Start remote node"},
    { 0x02, "Stop remote node"},
    { 0x80, "Enter pre-operational state"},
    { 0x81, "Reset node"},
    { 0x82, "Reset communication"},
    { 0, NULL}
};

/* NMT states */
static const value_string nmt_guard_state[] = {
    { 0x00, "Boot-up"},
    { 0x04, "Stopped"},
    { 0x05, "Operational"},
    { 0x7F, "Pre-operational"},
    { 0, NULL}
};

/* SDO Client command specifier */
static const value_string sdo_ccs[] = {
    { 0x00, "Download segment request"},
    { 0x01, "Initiate download request"},
    { 0x02, "Initiate upload request"},
    { 0x03, "Upload segment request"},
    { 0x04, "Abort transfer"},
    { 0x05, "Block upload"},
    { 0x06, "Block download"},
    { 0, NULL}
};

/* SDO Server command specifier */
static const value_string sdo_scs[] = {
    { 0x00, "Upload segment response"},
    { 0x01, "Download segment response"},
    { 0x02, "Initiate upload response"},
    { 0x03, "Initiate download response"},
    { 0x04, "Abort transfer"},
    { 0x05, "Block download"},
    { 0x06, "Block upload"},
    { 0, NULL}
};

static const value_string sdo_abort_code[] = {
    { 0x05030000, "Toggle bit not alternated"},
    { 0x05040000, "SDO protocol timed out"},
    { 0x05040001, "Client/server command specifier not valid or unknown"},
    { 0x05040002, "Invalid block size"},
    { 0x05040003, "Invalid sequence number"},
    { 0x05040004, "CRC error"},
    { 0x05040005, "Out of memory"},
    { 0x06010000, "Unsupported access to an object"},
    { 0x06010001, "Attempt to read a write only object"},
    { 0x06010002, "Attempt to write a read only object"},
    { 0x06020000, "Object does not exist in the object dictionary"},
    { 0x06040041, "Object cannot be mapped to the PDO"},
    { 0x06040042, "The number and length of the objects to be mapped would exceed PDO length"},
    { 0x06040043, "General parameter incompatibility reason"},
    { 0x06040047, "General internal incompatibility in the device"},
    { 0x06060000, "Access failed due to an hardware error"},
    { 0x06070010, "Data type does not match, length of service parameter does not match"},
    { 0x06070012, "Data type does not match, length of service parameter too high"},
    { 0x06070013, "Data type does not match, length of service parameter too low"},
    { 0x06090011, "Sub-index does not exist"},
    { 0x06090030, "Invalid value for parameter"},
    { 0x06090031, "Value of parameter written too high"},
    { 0x06090032, "Value of parameter written too low"},
    { 0x06090036, "Maximum value is less than minimum value"},
    { 0x060A0023, "Resource not available: SDO connection"},
    { 0x08000000, "General error"},
    { 0x08000020, "Data cannot be transferred or stored to the application"},
    { 0x08000021, "Data cannot be transferred or stored to the application because of local control"},
    { 0x08000022, "Data cannot be transferred or stored to the application because of the present device state"},
    { 0x08000023, "Object dictionary dynamic generation fails or no object dictionary is present"},
    { 0x08000024, "No data available"},
    { 0, NULL}
};

/* LSS COB-IDs */
#define LSS_MASTER_CAN_ID                  0x7E5
#define LSS_SLAVE_CAN_ID                   0x7E4

/* LSS Switch state services */
#define LSS_CS_SWITCH_GLOBAL               0x04
#define LSS_CS_SWITCH_SELECTIVE_VENDOR     0x40
#define LSS_CS_SWITCH_SELECTIVE_PRODUCT    0x41
#define LSS_CS_SWITCH_SELECTIVE_REVISION   0x42
#define LSS_CS_SWITCH_SELECTIVE_SERIAL     0x43
#define LSS_CS_SWITCH_SELECTIVE_RESP       0x44
/* LSS Configuration services */
#define LSS_CS_CONF_NODE_ID                0x11
#define LSS_CS_CONF_BIT_TIMING             0x13
#define LSS_CS_CONF_ACT_BIT_TIMING         0x15
#define LSS_CS_CONF_STORE                  0x17
/* LSS Inquire services */
#define LSS_CS_INQ_VENDOR_ID               0x5A
#define LSS_CS_INQ_PRODUCT_CODE            0x5B
#define LSS_CS_INQ_REV_NUMBER              0x5C
#define LSS_CS_INQ_SERIAL_NUMBER           0x5D
#define LSS_CS_INQ_NODE_ID                 0x5E
/* LSS Identification services */
#define LSS_CS_IDENT_REMOTE_VENDOR         0x46
#define LSS_CS_IDENT_REMOTE_PRODUCT        0x47
#define LSS_CS_IDENT_REMOTE_REV_LOW        0x48
#define LSS_CS_IDENT_REMOTE_REV_HIGH       0x49
#define LSS_CS_IDENT_REMOTE_SERIAL_LOW     0x4A
#define LSS_CS_IDENT_REMOTE_SERIAL_HIGH    0x4B
#define LSS_CS_IDENT_REMOTE_NON_CONF       0x4C
#define LSS_CS_IDENT_SLAVE                 0x4F
#define LSS_CS_IDENT_NON_CONF_SLAVE        0x50
#define LSS_CS_IDENT_FASTSCAN              0x51


/* LSS command specifier */
static const value_string lss_cs_code[] = {
    { 0x04, "Switch state global protocol"},
    { 0x11, "Configure node-ID protocol"},
    { 0x13, "Configure bit timing protocol"},
    { 0x15, "Activate bit timing parameters protocol"},
    { 0x17, "Store configuration protocol"},
    { 0x40, "Switch state selective protocol"},
    { 0x41, "Switch state selective protocol"},
    { 0x42, "Switch state selective protocol"},
    { 0x43, "Switch state selective protocol"},
    { 0x44, "Switch state selective protocol"},
    { 0x46, "Identify remote slave protocol"},
    { 0x47, "Identify remote slave protocol"},
    { 0x48, "Identify remote slave protocol"},
    { 0x49, "Identify remote slave protocol"},
    { 0x4A, "Identify remote slave protocol"},
    { 0x4B, "Identify remote slave protocol"},
    { 0x4C, "Identify non-configured remote slave protocol"},
    { 0x4F, "Identify slave protocol"},
    { 0x50, "Identify non-configured slave protocol"},
    { 0x51, "LSS Fastscan protocol"},
    { 0x5A, "Inquire identity vendor-ID protocol"},
    { 0x5B, "Inquire identity product code protocol"},
    { 0x5C, "Inquire identity revision number protocol"},
    { 0x5D, "Inquire identity serial number protocol"},
    { 0x5E, "Inquire node-ID protocol"},
    { 0, NULL}
};

static const value_string lss_fastscan_subnext[] = {
    { 0x0, "Vendor-ID"},
    { 0x1, "Product code"},
    { 0x2, "Revision number"},
    { 0x3, "Serial number"},
    { 0, NULL}
};

static const value_string lss_switch_mode[] = {
    { 0x0, "Waiting state"},
    { 0x1, "Configuration state"},
    { 0, NULL}
};

static const value_string lss_conf_id_err_code[] = {
    { 0x00, "Protocol successfully completed"},
    { 0x01, "NID out of range"},
    { 0xFF, "Implementation specific error"},
    { 0, NULL}
};

static const value_string lss_conf_bt_err_code[] = {
    { 0x00, "Protocol successfully completed"},
    { 0x01, "Bit rate not supported"},
    { 0xFF, "Implementation specific error"},
    { 0, NULL}
};

static const value_string lss_store_conf_err_code[] = {
    { 0x00, "Protocol successfully completed"},
    { 0x01, "Store configuration not supported"},
    { 0x02, "Storage media access erro"},
    { 0xFF, "Implementation specific error"},
    { 0, NULL}
};

static const value_string bit_timing_tbl[] = {
    { 0x00, "1000 kbit/s"},
    { 0x01, "800 kbit/s"},
    { 0x02, "500 kbit/s"},
    { 0x03, "250 kbit/s"},
    { 0x04, "125 kbit/s"},
    { 0x05, "Reserved"},
    { 0x06, "50 kbit/s"},
    { 0x07, "20 kbit/s"},
    { 0x08, "10 kbit/s"},
    { 0x09, "Auto bit rate detection"},
    { 0, NULL}
};


static const value_string lss_id_remote_slave[] = {
    { 0x46, "Vendor-ID"},
    { 0x47, "Product-code"},
    { 0x48, "Revision-number (low)"},
    { 0x49, "Revision-number (high)"},
    { 0x4A, "Serial-number (low)"},
    { 0x4B, "Serial-number (high)"},
    { 0, NULL}
};

static const value_string lss_inquire_id[] = {
    { 0x5A, "Vendor-ID"},
    { 0x5B, "Product-code"},
    { 0x5C, "Revision-number"},
    { 0x5D, "Serial-number"},
    { 0x5E, "Node-ID"},
    { 0, NULL}
};

static guint
canopen_detect_msg_type(guint function_code, guint node_id)
{
    switch (function_code) {
        case FC_NMT:
            return MT_NMT_CTRL;
            break;
        case FC_SYNC:
            if (node_id == 0) {
                return MT_SYNC;
            } else {
                return MT_EMERGENCY;
            }
            break;
        case FC_TIME_STAMP:
            return MT_TIME_STAMP;
            break;
        case FC_PDO1_TX:
            return MT_PDO;
            break;
        case FC_PDO1_RX:
            return MT_PDO;
            break;
        case FC_PDO2_TX:
            return MT_PDO;
            break;
        case FC_PDO2_RX:
            return MT_PDO;
            break;
        case FC_PDO3_TX:
            return MT_PDO;
            break;
        case FC_PDO3_RX:
            return MT_PDO;
            break;
        case FC_PDO4_TX:
            return MT_PDO;
            break;
        case FC_PDO4_RX:
            return MT_PDO;
            break;
        case FC_DEFAULT_SDO_TX:
            return MT_SDO;
            break;
        case FC_DEFAULT_SDO_RX:
            return MT_SDO;
            break;
        case FC_NMT_ERR_CONTROL:
            return MT_NMT_ERR_CTRL;
            break;
        case LSS_MASTER_CAN_ID >> 7:
            if (node_id == (LSS_MASTER_CAN_ID & 0x7F)) {
                return MT_LSS_MASTER;
            } else if (node_id == (LSS_SLAVE_CAN_ID & 0x7F)) {
                return MT_LSS_SLAVE;
            }
            return MT_UNKNOWN;
            break;
        default:
            return MT_UNKNOWN;
            break;
    }
}

struct can_identifier
{
    guint32 id;
};


static void
dissect_sdo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *canopen_type_tree, guint function_code)
{
    int offset = 0;
    guint8 sdo_mux = 0, sdo_data = 0;
    guint8 sdo_cs = 0;
    const gint **sdo_cmd_fields;

    /* get SDO command specifier */
    sdo_cs = tvb_get_bits8(tvb, 0, 3);

    if (function_code == FC_DEFAULT_SDO_RX) {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                ": %s", val_to_str(sdo_cs, sdo_ccs,
                    "Unknown (0x%x)"));

        sdo_cmd_fields = sdo_cmd_fields_ccs(sdo_cs);
        if (sdo_cmd_fields == NULL) {
            proto_tree_add_item(canopen_type_tree, hf_canopen_sdo_cmd, tvb, 0, 1, ENC_LITTLE_ENDIAN);
            /* XXX Add expert info */
            return;
        }
        proto_tree_add_bitmask(canopen_type_tree, tvb, offset,
                hf_canopen_sdo_cmd, ett_canopen_sdo_cmd, sdo_cmd_fields, ENC_LITTLE_ENDIAN);
        offset++;

        switch (sdo_cs) {
            case SDO_CCS_DOWN_SEG_REQ:
                sdo_mux = 0;
                sdo_data = 7;
                break;
            case SDO_CCS_INIT_DOWN_REQ:
                sdo_mux = 1;
                sdo_data = 4;
                break;
            case SDO_CCS_INIT_UP_REQ:
                sdo_mux = 1;
                sdo_data = 0;
                break;
            case SDO_CCS_UP_SEQ_REQ:
                sdo_mux = 0;
                sdo_data = 0;
                break;
            case SDO_CS_ABORT_TRANSFER:
            case SDO_CCS_BLOCK_UP:
            case SDO_CCS_BLOCK_DOWN:
                sdo_mux = 1;
                sdo_data = 4;
                break;
            default:
                return;
        }
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                ": %s", val_to_str(sdo_cs, sdo_scs,
                    "Unknown (0x%x)"));

        sdo_cmd_fields = sdo_cmd_fields_scs(sdo_cs);
        if (sdo_cmd_fields == NULL) {
            proto_tree_add_item(canopen_type_tree, hf_canopen_sdo_cmd, tvb, 0, 1, ENC_LITTLE_ENDIAN);
            /* XXX Add expert info */
            return;
        }
        proto_tree_add_bitmask(canopen_type_tree, tvb, offset,
                hf_canopen_sdo_cmd, ett_canopen_sdo_cmd, sdo_cmd_fields, ENC_LITTLE_ENDIAN);
        offset++;

        switch (sdo_cs) {
            case SDO_SCS_UP_SEQ_RESP:
                sdo_mux = 0;
                sdo_data = 7;
                break;
            case SDO_SCS_DOWN_SEG_RESP:
                sdo_mux = 0;
                sdo_data = 0;
                break;
            case SDO_SCS_INIT_UP_RESP:
                sdo_mux = 1;
                sdo_data = 4;
                break;
            case SDO_SCS_INIT_DOWN_RESP:
                sdo_mux = 1;
                sdo_data = 0;
                break;
            case SDO_CS_ABORT_TRANSFER:
            case SDO_SCS_BLOCK_DOWN:
            case SDO_SCS_BLOCK_UP:
                sdo_mux = 1;
                sdo_data = 4;
                break;
            default:
                return;
        }
    }

    if (sdo_mux) {
        /* decode mux */
        proto_tree_add_item(canopen_type_tree,
                hf_canopen_sdo_main_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(canopen_type_tree,
                hf_canopen_sdo_sub_idx, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
    }

    if (sdo_cs == 4) {
        /* SDO abort transfer */
        proto_tree_add_item(canopen_type_tree,
                hf_canopen_sdo_abort_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        return;
    }

    if (sdo_data) {
        proto_tree_add_item(canopen_type_tree,
                hf_canopen_sdo_data, tvb, offset, sdo_data, ENC_NA);
    } else {
        /* Reserved */
        proto_tree_add_item(canopen_type_tree,
                hf_canopen_reserved, tvb, offset, 7 - 3 * sdo_mux - sdo_data , ENC_NA);
    }
}

static void
dissect_lss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *canopen_type_tree, guint msg_type_id)
{
    int offset = 0;
    int reserved = 0;
    guint8 lss_cs;
    guint8 lss_bc_mask;
    guint16 lss_abt_delay;

    proto_tree_add_item(canopen_type_tree,
            hf_canopen_lss_cs, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    /* LSS command specifier */
    lss_cs = tvb_get_guint8(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str(lss_cs, lss_cs_code, "Unknown (0x%x)"));
    offset++;

    if (msg_type_id == MT_LSS_MASTER) {

        /* Master commands */
        switch (lss_cs) {
            case LSS_CS_SWITCH_GLOBAL:
                col_append_fstr(pinfo->cinfo, COL_INFO,
                        ": %s", val_to_str(tvb_get_guint8(tvb, offset), lss_switch_mode, "Unknown (0x%x)"));

                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_switch_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                reserved = 6;
                break;
            case LSS_CS_SWITCH_SELECTIVE_VENDOR:
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_addr_vendor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                reserved = 3;
                break;
            case LSS_CS_SWITCH_SELECTIVE_PRODUCT:
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_addr_product, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                reserved = 3;
                break;
            case LSS_CS_SWITCH_SELECTIVE_REVISION:
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_addr_revision, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                reserved = 3;
                break;
            case LSS_CS_SWITCH_SELECTIVE_SERIAL:
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_addr_serial, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                reserved = 3;
                break;
            case LSS_CS_CONF_NODE_ID:
                col_append_fstr(pinfo->cinfo, COL_INFO, ": 0x%02x", tvb_get_guint8(tvb, offset));

                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_nid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                reserved = 6;
                break;
            case LSS_CS_CONF_BIT_TIMING:
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_bt_tbl_selector, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;

                /* XXX Note that current dissector only works for table selector 0x00 (CiA 301 Table 1) */
                col_append_fstr(pinfo->cinfo, COL_INFO,
                        ": %s", val_to_str(tvb_get_guint8(tvb, offset), bit_timing_tbl, "Unknown (0x%x)"));
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_bt_tbl_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                reserved = 5;
                break;
            case LSS_CS_CONF_ACT_BIT_TIMING:
                lss_abt_delay = tvb_get_letohl(tvb, offset);

                col_append_fstr(pinfo->cinfo, COL_INFO, ": %d ms", lss_abt_delay);

                proto_tree_add_uint_format_value(canopen_type_tree,
                        hf_canopen_lss_abt_delay, tvb, offset, 2, lss_abt_delay,
                        "%d ms (0x%02x)", lss_abt_delay, lss_abt_delay);


                offset += 2;
                reserved = 5;
                break;
            case LSS_CS_CONF_STORE:
            case LSS_CS_INQ_VENDOR_ID:
            case LSS_CS_INQ_PRODUCT_CODE:
            case LSS_CS_INQ_REV_NUMBER:
            case LSS_CS_INQ_SERIAL_NUMBER:
            case LSS_CS_INQ_NODE_ID:
                reserved = 7;
                break;
            case LSS_CS_IDENT_REMOTE_VENDOR:
            case LSS_CS_IDENT_REMOTE_PRODUCT:
            case LSS_CS_IDENT_REMOTE_REV_LOW:
            case LSS_CS_IDENT_REMOTE_REV_HIGH:
            case LSS_CS_IDENT_REMOTE_SERIAL_LOW:
            case LSS_CS_IDENT_REMOTE_SERIAL_HIGH:
                col_append_fstr(pinfo->cinfo, COL_INFO, ", %s 0x%08x",
                        val_to_str(lss_cs, lss_id_remote_slave, "(Unknown)"), tvb_get_letohl(tvb, offset));

                proto_tree_add_item(canopen_type_tree,
                        *hf_canopen_lss_addr_ident[lss_cs - LSS_CS_IDENT_REMOTE_VENDOR], tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                reserved = 3;
                break;
            case LSS_CS_IDENT_REMOTE_NON_CONF:
                reserved = 7;
                break;
            case LSS_CS_IDENT_FASTSCAN:
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_fastscan_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                lss_bc_mask = tvb_get_guint8(tvb, offset);
                if (lss_bc_mask == 0x80) {
                    proto_tree_add_uint_format_value(canopen_type_tree,
                            hf_canopen_lss_fastscan_check, tvb, offset, 1, lss_bc_mask,
                            "All LSS slaves (0x%02x)", lss_bc_mask);
                } else if (lss_bc_mask < 32) {
                    proto_tree_add_uint_format_value(canopen_type_tree,
                            hf_canopen_lss_fastscan_check, tvb, offset, 1,
                            lss_bc_mask, "0x%x (0x%02x)",
                            ~((1 << lss_bc_mask) - 1),
                            lss_bc_mask);
                } else {
                    proto_tree_add_uint_format_value(canopen_type_tree,
                            hf_canopen_lss_fastscan_check, tvb, offset, 1, lss_bc_mask,
                            "Reserved (0x%02x)", lss_bc_mask);
                }
                offset++;
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_fastscan_sub, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_fastscan_next, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                break;
            default: /* invalid command specifier */
                return;
        }

    } else {

        /* Slave commands */
        switch (lss_cs) {
            case LSS_CS_SWITCH_SELECTIVE_RESP:
                reserved = 7;
                break;
            case LSS_CS_CONF_NODE_ID:
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_conf_id_err_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_spec_err, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                reserved = 5;
                break;
            case LSS_CS_CONF_BIT_TIMING:
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_conf_bt_err_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);

                offset++;
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_spec_err, tvb, offset, 1, ENC_LITTLE_ENDIAN);

                offset++;
                reserved = 5;
                break;
            case LSS_CS_CONF_STORE:
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_store_conf_err_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_spec_err, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                reserved = 5;
                break;
            case LSS_CS_INQ_VENDOR_ID:
            case LSS_CS_INQ_PRODUCT_CODE:
            case LSS_CS_INQ_REV_NUMBER:
            case LSS_CS_INQ_SERIAL_NUMBER:
                col_append_fstr(pinfo->cinfo, COL_INFO,
                        ", %s 0x%08x", val_to_str(lss_cs, lss_inquire_id, "(Unknown)"), tvb_get_letohl(tvb, offset));

                proto_tree_add_item(canopen_type_tree,
                        *hf_canopen_lss_addr_inquire[lss_cs - LSS_CS_INQ_VENDOR_ID], tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                reserved = 3;
                break;
            case LSS_CS_INQ_NODE_ID:
                col_append_fstr(pinfo->cinfo, COL_INFO,
                        ", %s 0x%08x", val_to_str(lss_cs, lss_inquire_id, "(Unknown)"), tvb_get_letohl(tvb, offset));

                proto_tree_add_item(canopen_type_tree,
                        hf_canopen_lss_nid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;
                reserved = 6;
                break;
            case LSS_CS_IDENT_SLAVE:
                reserved = 7;
                break;
            case LSS_CS_IDENT_NON_CONF_SLAVE:
                reserved = 7;
                break;
            default: /* invalid command specifier */
                return;
        }

    }

    if (reserved) {
        proto_tree_add_item(canopen_type_tree,
                hf_canopen_reserved, tvb, offset, reserved, ENC_NA);
    }

}

/* Code to actually dissect the packets */
static int
dissect_canopen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    guint        function_code;
    guint        node_id;
    guint32      time_stamp_msec;
    guint32      time_stamp_days;
    struct can_identifier can_id;
    guint        msg_type_id;
    nstime_t     time_stamp;
    gint         can_data_len = tvb_reported_length(tvb);
    const gchar *function_code_str;
    int offset = 0;
    guint8 nmt_node_id;

    proto_item *ti, *cob_ti;
    proto_tree *canopen_tree;
    proto_tree *canopen_cob_tree;
    proto_tree *canopen_type_tree;

    DISSECTOR_ASSERT(data);
    can_id = *((struct can_identifier*)data);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CANopen");
    col_clear(pinfo->cinfo, COL_INFO);

    node_id       = can_id.id & 0x7F;
    function_code = (can_id.id >> 7) & 0x0F;

    msg_type_id = canopen_detect_msg_type(function_code, node_id);

    if (msg_type_id == MT_LSS_MASTER) {
        function_code_str = "LSS (Master)";
        col_add_str(pinfo->cinfo, COL_INFO, function_code_str);
    } else if (msg_type_id == MT_LSS_SLAVE) {
        function_code_str = "LSS (Slave)";
        col_add_str(pinfo->cinfo, COL_INFO, function_code_str);
    } else {

        if (node_id == 0 ) {
            /* broadcast */
            function_code_str = val_to_str(function_code, CAN_open_bcast_msg_type_vals, "Unknown (%u)");
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s", function_code_str);
        } else {
            /* point-to-point */
            function_code_str = val_to_str(function_code, CAN_open_p2p_msg_type_vals, "Unknown (%u)");
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s", function_code_str);
        }
    }

    ti = proto_tree_add_item(tree, proto_canopen, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    canopen_tree = proto_item_add_subtree(ti, ett_canopen);

    /* add COB-ID with function code and node id */
    cob_ti = proto_tree_add_uint(canopen_tree, hf_canopen_cob_id, tvb, 0, 0, can_id.id);
    canopen_cob_tree = proto_item_add_subtree(cob_ti, ett_canopen_cob);

    /* add function code */
    ti = proto_tree_add_uint(canopen_cob_tree, hf_canopen_function_code, tvb, 0, 0, can_id.id);
    PROTO_ITEM_SET_GENERATED(ti);

    /* add node id */
    ti = proto_tree_add_uint(canopen_cob_tree, hf_canopen_node_id, tvb, 0, 0, can_id.id);
    PROTO_ITEM_SET_GENERATED(ti);

    /* add CANopen frame type */

    canopen_type_tree = proto_tree_add_subtree_format(canopen_tree, tvb, 0,
                                  tvb_reported_length(tvb),
                                  ett_canopen_type, NULL, "Type: %s", function_code_str);
    switch(msg_type_id)
    {
    case MT_NMT_CTRL:
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str(tvb_get_guint8(tvb, offset), nmt_ctrl_cs, "Unknown (0x%x)"));

        proto_tree_add_item(canopen_type_tree,
            hf_canopen_nmt_ctrl_cs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        nmt_node_id = tvb_get_guint8(tvb, offset);
        if (nmt_node_id == 0x00) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " [All]");
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " [0x%x]", nmt_node_id);
        }

        proto_tree_add_item(canopen_type_tree,
            hf_canopen_nmt_ctrl_node_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case MT_NMT_ERR_CTRL:
        if (tvb_reported_length(tvb) > 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str(tvb_get_bits8(tvb, 1, 7), nmt_guard_state, "(Unknown)"));

            proto_tree_add_item(canopen_type_tree,
                hf_canopen_nmt_guard_toggle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(canopen_type_tree,
                hf_canopen_nmt_guard_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " [0x%x]", node_id);
        break;
    case MT_SYNC:
        /* Show optional counter parameter if present */
        if (tvb_reported_length(tvb) > 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%d]", tvb_get_guint8(tvb, offset));

            proto_tree_add_item(canopen_type_tree,
                hf_canopen_sync_counter, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        break;
    case MT_TIME_STAMP:
        /* calculate the real time stamp */
        time_stamp_msec = tvb_get_letohl(tvb, offset);
        time_stamp_days = tvb_get_letohs(tvb, offset + 4);
        time_stamp.secs = (time_stamp_days + TS_DAYS_BETWEEN_1970_AND_1984)
            * TS_SECONDS_IN_PER_DAY + (time_stamp_msec / 1000);
        time_stamp.nsecs = (time_stamp_msec % 1000) * TS_NANOSEC_PER_MSEC;

        proto_tree_add_time(canopen_type_tree,
            hf_canopen_time_stamp, tvb, offset, 6, &time_stamp);

        proto_tree_add_uint(canopen_type_tree,
            hf_canopen_time_stamp_ms, tvb, offset, 4, time_stamp_msec);
        offset += 4;

        proto_tree_add_uint(canopen_type_tree,
            hf_canopen_time_stamp_days, tvb, offset, 2, time_stamp_days);

        break;
    case MT_EMERGENCY:
        proto_tree_add_item(canopen_type_tree,
            hf_canopen_em_err_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(canopen_type_tree,
            hf_canopen_em_err_reg, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        proto_tree_add_item(canopen_type_tree,
            hf_canopen_em_err_field, tvb, offset, 4, ENC_NA);
        break;
    case MT_PDO:
        if (can_data_len != 0) {
            proto_tree_add_item(canopen_type_tree,
                hf_canopen_pdo_data, tvb, offset, can_data_len, ENC_NA);
        }
        else {
            proto_tree_add_string(canopen_type_tree,
                hf_canopen_pdo_data_string, tvb, offset, 0, "empty");
        }
        break;
    case MT_SDO:

        dissect_sdo(tvb, pinfo, canopen_type_tree, function_code);

        break;
    case MT_LSS_MASTER:
    case MT_LSS_SLAVE:

        dissect_lss(tvb, pinfo, canopen_type_tree, msg_type_id);

        break;
    }

    return tvb_reported_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_canopen(void)
{
    static hf_register_info hf[] = {
        /* COB-ID */
        { &hf_canopen_cob_id,
          { "COB-ID",           "canopen.cob_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_function_code,
          { "Function code", "canopen.function_code",
            FT_UINT32, BASE_HEX, NULL, 0x780,
            NULL, HFILL }
        },
        { &hf_canopen_node_id,
          { "Node-ID", "canopen.node_id",
            FT_UINT32, BASE_HEX, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_canopen_pdo_data,
          { "Data", "canopen.pdo.data.bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_pdo_data_string,
          { "Data", "canopen.pdo.data.string",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        /* SDO */
        { &hf_canopen_sdo_cmd,
          { "SDO command byte", "canopen.sdo.cmd",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_sdo_cmd_ccs,
          { "Client command specifier", "canopen.sdo.ccs",
            FT_UINT8, BASE_HEX, VALS(sdo_ccs), 0xE0,
            NULL, HFILL }
        },
        { &hf_canopen_sdo_cmd_scs,
          { "Server command specifier", "canopen.sdo.ccs",
            FT_UINT8, BASE_HEX, VALS(sdo_scs), 0xE0,
            NULL, HFILL }
        },
        { &hf_canopen_sdo_cmd_toggle,
          { "Toggle bit", "canopen.sdo.toggle",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            "toggle", HFILL }},
        { &hf_canopen_sdo_cmd_updown_n,
          { "Non-data bytes", "canopen.sdo.n",
            FT_UINT8, BASE_DEC, NULL, 0x0E,
            "toggle", HFILL }},
        { &hf_canopen_sdo_cmd_updown_c,
          { "No more segments", "canopen.sdo.c",
            FT_BOOLEAN, 8, NULL, 0x01,
            "toggle", HFILL }},
        { &hf_canopen_sdo_cmd_init_n,
          { "Non-data bytes", "canopen.sdo.n",
            FT_UINT8, BASE_DEC, NULL, 0x0C,
            "toggle", HFILL }},
        { &hf_canopen_sdo_cmd_init_e,
          { "Expedited transfer", "canopen.sdo.e",
            FT_BOOLEAN, 8, NULL, 0x02,
            "toggle", HFILL }},
        { &hf_canopen_sdo_cmd_init_s,
          { "Data set size indicated", "canopen.sdo.s",
            FT_BOOLEAN, 8, NULL, 0x01,
            "toggle", HFILL }},
        { &hf_canopen_sdo_main_idx,
          { "OD main-index", "canopen.sdo.main_idx",
            FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(obj_dict), 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_sdo_sub_idx,
          { "OD sub-index", "canopen.sdo.sub_idx",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_sdo_data,
          { "Data", "canopen.sdo.data.bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_sdo_abort_code,
          { "Abort code", "canopen.sdo.abort_code",
            FT_UINT32, BASE_HEX, VALS(sdo_abort_code), 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_reserved,
          { "Reserved", "canopen.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_canopen_em_err_code,
          { "Error code", "canopen.em.err_code",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_em_err_reg,
          { "Error register", "canopen.em.err_reg",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_em_err_field,
          { "Manufacture specific error field", "canopen.em.err_field",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_nmt_ctrl_cs,
          { "Command specifier", "canopen.nmt_ctrl.cd",
            FT_UINT8, BASE_HEX, VALS(nmt_ctrl_cs), 0xFF,
            NULL, HFILL }
        },
        { &hf_canopen_nmt_ctrl_node_id,
          { "Node-ID", "canopen.nmt_ctrl.node_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_nmt_guard_toggle,
          { "Reserved/Toggle", "canopen.nmt_guard.toggle",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_canopen_nmt_guard_state,
          { "State", "canopen.nmt_guard.state",
            FT_UINT8, BASE_HEX, VALS(nmt_guard_state), 0x7F,
            NULL, HFILL }
        },
        /* SYNC */
        { &hf_canopen_sync_counter,
          { "Counter", "canopen.sync.counter",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        /* LSS */
        { &hf_canopen_lss_cs,
          { "Command specifier", "canopen.lss.cs",
            FT_UINT8, BASE_HEX, VALS(lss_cs_code), 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_addr_vendor,
          { "Vendor-ID", "canopen.lss.addr.vendor",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_addr_product,
          { "Product-code", "canopen.lss.addr.product",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_addr_revision,
          { "Revision-number", "canopen.lss.addr.revision",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_addr_revision_low,
          { "Revision-number (low)", "canopen.lss.addr.revision_low",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_addr_revision_high,
          { "Revision-number (high)", "canopen.lss.addr.revision_high",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_addr_serial,
          { "Serial-number", "canopen.lss.addr.serial",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_addr_serial_low,
          { "Serial-number (low)", "canopen.lss.addr.serial_low",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_addr_serial_high,
          { "Serial-number (high)", "canopen.lss.addr.serial_high",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_fastscan_id,
          { "IDNumber", "canopen.lss.fastscan.id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_fastscan_check,
          { "Bit Check", "canopen.lss.fastscan.check",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_fastscan_sub,
          { "LSS Sub", "canopen.lss.fastscan.sub",
            FT_UINT8, BASE_HEX, VALS(lss_fastscan_subnext), 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_fastscan_next,
          { "LSS Next", "canopen.lss.fastscan.next",
            FT_UINT8, BASE_HEX, VALS(lss_fastscan_subnext), 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_switch_mode,
          { "Mode", "canopen.lss.switch.mode",
            FT_UINT8, BASE_HEX, VALS(lss_switch_mode), 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_nid,
          { "NID", "canopen.lss.nid",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_conf_id_err_code,
          { "Error code", "canopen.lss.conf_id.err_code",
            FT_UINT8, BASE_HEX, VALS(lss_conf_id_err_code), 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_conf_bt_err_code,
          { "Error code", "canopen.lss.conf_bt.err_code",
            FT_UINT8, BASE_HEX, VALS(lss_conf_bt_err_code), 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_store_conf_err_code,
          { "Error code", "canopen.lss.store_conf.err_code",
            FT_UINT8, BASE_HEX, VALS(lss_store_conf_err_code), 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_spec_err,
          { "Spec-error", "canopen.lss.spec_err",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_bt_tbl_selector,
          { "Table selector", "canopen.lss.bt.tbl_selector",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_bt_tbl_index,
          { "Table index", "canopen.lss.bt.tbl_index",
            FT_UINT8, BASE_HEX, VALS(bit_timing_tbl), 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_lss_abt_delay,
          { "Switch delay", "canopen.lss.abt_delay",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },


        { &hf_canopen_time_stamp,
          { "Time stamp",           "canopen.time_stamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_time_stamp_ms,
          { "Time, after Midnight in Milliseconds", "canopen.time_stamp_ms",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_time_stamp_days,
          { "Current day since 1 Jan 1984", "canopen.time_stamp_days",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_canopen,
        &ett_canopen_cob,
        &ett_canopen_type,
        &ett_canopen_sdo_cmd
    };

    proto_canopen = proto_register_protocol("CANopen",
                                            "CANOPEN",
                                            "canopen");

    proto_register_field_array(proto_canopen, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_canopen(void)
{
   dissector_handle_t canopen_handle;

   canopen_handle = create_dissector_handle( dissect_canopen, proto_canopen );
   dissector_add_for_decode_as("can.subdissector", canopen_handle );
}

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
