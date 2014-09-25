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

#include <glib.h>

#include <epan/packet.h>

void proto_register_canopen(void);

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

static const int **sdo_cmd_fields_ccs[] = {
  sdo_cmd_fields_ccs0,
  sdo_cmd_fields_ccs1,
  sdo_cmd_fields_ccs2,
  sdo_cmd_fields_ccs3,
  sdo_cmd_fields_ccs4,
  sdo_cmd_fields_ccs5,
  sdo_cmd_fields_ccs6
};


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


static const int **sdo_cmd_fields_scs[] = {
  sdo_cmd_fields_scs0,
  sdo_cmd_fields_scs1,
  sdo_cmd_fields_scs2,
  sdo_cmd_fields_scs3,
  sdo_cmd_fields_scs4,
  sdo_cmd_fields_scs5,
  sdo_cmd_fields_scs6
};

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
dissect_sdo(tvbuff_t *tvb, proto_tree *canopen_type_tree, guint function_code)
{
    int offset = 0;
    guint8 sdo_mux = 0, sdo_data = 0;
    guint8 sdo_cs = 0;

    /* get SDO command specifier */
    sdo_cs = tvb_get_bits8(tvb, 0, 3);

    if (function_code == FC_DEFAULT_SDO_RX) {

        proto_tree_add_bitmask(canopen_type_tree, tvb, offset,
                hf_canopen_sdo_cmd, ett_canopen_sdo_cmd, sdo_cmd_fields_ccs[sdo_cs], ENC_LITTLE_ENDIAN);
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

        proto_tree_add_bitmask(canopen_type_tree, tvb, offset,
                hf_canopen_sdo_cmd, ett_canopen_sdo_cmd, sdo_cmd_fields_scs[sdo_cs], ENC_LITTLE_ENDIAN);
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

    DISSECTOR_ASSERT(data);
    can_id = *((struct can_identifier*)data);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CANopen");
    col_clear(pinfo->cinfo, COL_INFO);

    node_id       = can_id.id & 0x7F;
    function_code = (can_id.id >> 7) & 0x0F;

    msg_type_id = canopen_detect_msg_type(function_code, node_id);

    if (node_id == 0 ) {
        /* broadcast */
        function_code_str = val_to_str(function_code, CAN_open_bcast_msg_type_vals, "Unknown (%u)");
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s", function_code_str);
    } else {
        /* point-to-point */
        function_code_str = val_to_str(function_code, CAN_open_p2p_msg_type_vals, "Unknown (%u)");
        col_add_fstr(pinfo->cinfo, COL_INFO, "p2p %s", function_code_str);
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                    tvb_bytes_to_ep_str_punct(tvb, offset, can_data_len, ' '));

    if (tree) {
        proto_item *ti, *cob_ti;
        proto_tree *canopen_tree;
        proto_tree *canopen_cob_tree;
        proto_tree *canopen_type_tree;

        ti = proto_tree_add_item(tree, proto_canopen, tvb, 0,
            (msg_type_id == MT_SYNC) || (msg_type_id == MT_NMT_ERR_CTRL) ? 0 : -1, ENC_NA);
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
                                      (msg_type_id == MT_SYNC) || (msg_type_id == MT_NMT_ERR_CTRL) ? 0 : -1,
                                      ett_canopen_type, NULL, "Type: %s", function_code_str);
        switch(msg_type_id)
        {
        case MT_NMT_CTRL:
            proto_tree_add_item(canopen_type_tree,
                hf_canopen_nmt_ctrl_cs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(canopen_type_tree,
                hf_canopen_nmt_ctrl_node_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;
        case MT_NMT_ERR_CTRL:
            if (tvb_reported_length(tvb) > 0) {
                proto_tree_add_item(canopen_type_tree,
                    hf_canopen_nmt_guard_toggle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(canopen_type_tree,
                    hf_canopen_nmt_guard_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            }
            break;
        case MT_SYNC:
            /* Show optional counter parameter if present */
            if (tvb_reported_length(tvb) > 0) {
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

            dissect_sdo(tvb, canopen_type_tree, function_code);

            break;
        }
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
          { "Data", "canopen.pdo.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_pdo_data_string,
          { "Data", "canopen.pdo.data",
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
          { "Data", "canopen.sdo.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_canopen_sdo_abort_code,
          { "Abort code", "canopen.sdo.data",
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

    new_register_dissector("canopen", dissect_canopen, proto_canopen);

    proto_register_field_array(proto_canopen, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
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
