/* packet-lg8979.c
 * Routines for Landis & Gyr (Telegyr) 8979 Protocol (lg8979) Dissection
 * By Chris Bontje (cbontje[AT]gmail.com
 * Copyright 2013-2014
 *
 ************************************************************************************************
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

#include "config.h"

#include <epan/packet.h>
#include "packet-tcp.h"
#include <epan/prefs.h>

void proto_register_lg8979(void);

/* Initialize the protocol and registered fields */
static int proto_lg8979                    = -1;
static int hf_lg8979_header                = -1;
static int hf_lg8979_shr                   = -1;
static int hf_lg8979_mfc                   = -1;
static int hf_lg8979_ack                   = -1;
static int hf_lg8979_con                   = -1;
static int hf_lg8979_frz                   = -1;
static int hf_lg8979_ind                   = -1;
static int hf_lg8979_sch                   = -1;
static int hf_lg8979_slg                   = -1;
static int hf_lg8979_address               = -1;
static int hf_lg8979_lastblock             = -1;
static int hf_lg8979_funccode              = -1;
static int hf_lg8979_length                = -1;
static int hf_lg8979_start_ptnum16         = -1;
static int hf_lg8979_start_ptnum8          = -1;
static int hf_lg8979_stop_ptnum16          = -1;
static int hf_lg8979_stop_ptnum8           = -1;
static int hf_lg8979_ang_point             = -1;
static int hf_lg8979_adc_ref_zero          = -1;
static int hf_lg8979_adc_ref_neg90         = -1;
static int hf_lg8979_adc_ref_pos90         = -1;
static int hf_lg8979_ind_chgrpt_ptnum      = -1;
static int hf_lg8979_ind_chgrpt_status     = -1;
static int hf_lg8979_ind_chgrpt_change     = -1;
static int hf_lg8979_ind_frcrpt_status_b0  = -1;
static int hf_lg8979_ind_frcrpt_status_b1  = -1;
static int hf_lg8979_ind_frcrpt_status_b2  = -1;
static int hf_lg8979_ind_frcrpt_status_b3  = -1;
static int hf_lg8979_ind_frcrpt_status_b4  = -1;
static int hf_lg8979_ind_frcrpt_status_b5  = -1;
static int hf_lg8979_ind_frcrpt_status_b6  = -1;
static int hf_lg8979_ind_frcrpt_status_b7  = -1;
static int hf_lg8979_ind_frcrpt_change_b0  = -1;
static int hf_lg8979_ind_frcrpt_change_b1  = -1;
static int hf_lg8979_ind_frcrpt_change_b2  = -1;
static int hf_lg8979_ind_frcrpt_change_b3  = -1;
static int hf_lg8979_ind_frcrpt_change_b4  = -1;
static int hf_lg8979_ind_frcrpt_change_b5  = -1;
static int hf_lg8979_ind_frcrpt_change_b6  = -1;
static int hf_lg8979_ind_frcrpt_change_b7  = -1;
static int hf_lg8979_soe_chgrpt_ptnum      = -1;
static int hf_lg8979_soe_chgrpt_status     = -1;
static int hf_lg8979_soe_chgrpt_change     = -1;
static int hf_lg8979_soe_frcrpt_status_b0  = -1;
static int hf_lg8979_soe_frcrpt_status_b1  = -1;
static int hf_lg8979_soe_frcrpt_status_b2  = -1;
static int hf_lg8979_soe_frcrpt_status_b3  = -1;
static int hf_lg8979_soe_frcrpt_status_b4  = -1;
static int hf_lg8979_soe_frcrpt_status_b5  = -1;
static int hf_lg8979_soe_frcrpt_status_b6  = -1;
static int hf_lg8979_soe_frcrpt_status_b7  = -1;
static int hf_lg8979_soe_frcrpt_change_b0  = -1;
static int hf_lg8979_soe_frcrpt_change_b1  = -1;
static int hf_lg8979_soe_frcrpt_change_b2  = -1;
static int hf_lg8979_soe_frcrpt_change_b3  = -1;
static int hf_lg8979_soe_frcrpt_change_b4  = -1;
static int hf_lg8979_soe_frcrpt_change_b5  = -1;
static int hf_lg8979_soe_frcrpt_change_b6  = -1;
static int hf_lg8979_soe_frcrpt_change_b7  = -1;
static int hf_lg8979_digin_b0              = -1;
static int hf_lg8979_digin_b1              = -1;
static int hf_lg8979_digin_b2              = -1;
static int hf_lg8979_digin_b3              = -1;
static int hf_lg8979_digin_b4              = -1;
static int hf_lg8979_digin_b5              = -1;
static int hf_lg8979_digin_b6              = -1;
static int hf_lg8979_digin_b7              = -1;
static int hf_lg8979_digin_b8              = -1;
static int hf_lg8979_digin_b9              = -1;
static int hf_lg8979_digin_b10             = -1;
static int hf_lg8979_digin_b11             = -1;
static int hf_lg8979_digin_b12             = -1;
static int hf_lg8979_digin_b13             = -1;
static int hf_lg8979_digin_b14             = -1;
static int hf_lg8979_digin_b15             = -1;
static int hf_lg8979_acc_point             = -1;
static int hf_lg8979_soe_logchg_ptnum      = -1;
static int hf_lg8979_soe_logchg_newstat    = -1;
static int hf_lg8979_soe_logchg_mon        = -1;
static int hf_lg8979_soe_logchg_day        = -1;
static int hf_lg8979_soe_logchg_hour       = -1;
static int hf_lg8979_soe_logchg_min        = -1;
static int hf_lg8979_soe_logchg_sec        = -1;
static int hf_lg8979_soe_logchg_msec       = -1;
static int hf_lg8979_ang_output_val        = -1;
static int hf_lg8979_sbo_tripclose         = -1;
static int hf_lg8979_sbo_timercnt          = -1;
static int hf_lg8979_digout_data           = -1;
static int hf_lg8979_pul_output_base       = -1;
static int hf_lg8979_pul_output_dur        = -1;
static int hf_lg8979_pul_output_rl         = -1;
static int hf_lg8979_ang_deadband          = -1;
static int hf_lg8979_acc_preset            = -1;
static int hf_lg8979_rtucfg_num_chassis    = -1;
static int hf_lg8979_rtucfg_chassis_num    = -1;
static int hf_lg8979_rtucfg_card_slot      = -1;
static int hf_lg8979_timesync_mon          = -1;
static int hf_lg8979_timesync_day          = -1;
static int hf_lg8979_timesync_hour         = -1;
static int hf_lg8979_timesync_min          = -1;
static int hf_lg8979_timesync_sec          = -1;
static int hf_lg8979_timesync_msec         = -1;
static int hf_lg8979_timebias_value        = -1;
static int hf_lg8979_timebias_proctime     = -1;
static int hf_lg8979_firmware_ver          = -1;
static int hf_lg8979_exprpt_code           = -1;
static int hf_lg8979_exprpt_parm           = -1;
static int hf_lg8979_crc16                 = -1;

/* Initialize the subtree pointers */
static gint ett_lg8979                   = -1;
static gint ett_lg8979_flags             = -1;
static gint ett_lg8979_funccode          = -1;
static gint ett_lg8979_point             = -1;
static gint ett_lg8979_ts                = -1;

#define PORT_LG8979    0

/* Globals for L&G 8979 Protocol Preferences */
static gboolean lg8979_desegment = TRUE;
static guint global_lg8979_tcp_port = PORT_LG8979; /* Port 0, by default */

#define LG8979_HEADER             0xFF

#define LG8979_DIR_INDETERMINATE  0
#define LG8979_DIR_MASTER_TO_RTU  1
#define LG8979_DIR_RTU_TO_MASTER  2

/* Function Codes */
#define LG8979_FC_ANG_CHGRPT      0
#define LG8979_FC_ANG_FRCRPT      1
#define LG8979_FC_ANGGRP_CHGRPT   2
#define LG8979_FC_ANGGRP_FRCRPT   3
#define LG8979_FC_ADC_FRCRPT      5
#define LG8979_FC_IND_CHGRPT      6
#define LG8979_FC_IND_FRCRPT      7
#define LG8979_FC_SOE_CHGRPT      8
#define LG8979_FC_SOE_FRCRPT      9
#define LG8979_FC_DIG_FRCRPT      11
#define LG8979_FC_ACC_CHGRPT      12
#define LG8979_FC_ACC_FRCRPT      13
#define LG8979_FC_SOELOG_CHGRPT   14
#define LG8979_FC_ANG_OUTPUT      20
#define LG8979_FC_SBO_SELECT      21
#define LG8979_FC_SBO_OPERATE     22
#define LG8979_FC_DIG_OUTPUT      23
#define LG8979_FC_ACC_FREEZE      24
#define LG8979_FC_PUL_OUTPUT      25
#define LG8979_FC_PULTR_OUTPUT    26
#define LG8979_FC_SBO_IMEXECUTE   28
#define LG8979_FC_RTU_RESTART     30
#define LG8979_FC_RTU_CONFIG      31
#define LG8979_FC_TIME_SYNC       32
#define LG8979_FC_TIME_BIAS       33
#define LG8979_FC_ANG_DEADBAND    34
#define LG8979_FC_ANGGRP_DEFINE   35
#define LG8979_FC_ACC_PRESET      36
#define LG8979_FC_CONT_REQUEST    37
#define LG8979_FC_REPEAT_MSG      38
#define LG8979_FC_FIRMWARE_CFG    39
#define LG8979_FC_TABLE_READ      47
#define LG8979_FC_TABLE_WRITE     48
#define LG8979_FC_SPRPT_INT       50
#define LG8979_FC_SPRPT_SEQNUM    51
#define LG8979_FC_EXP_RPT         63

static const value_string lg8979_funccode_vals[] = {
    { LG8979_FC_ANG_CHGRPT,         "Analog Change Report" },
    { LG8979_FC_ANG_FRCRPT,         "Analog Force Report" },
    { LG8979_FC_ANGGRP_CHGRPT,      "Analog Group Change Report" },
    { LG8979_FC_ANGGRP_FRCRPT,      "Analog Group Force Report" },
    { 4,                            "Unknown/Invalid Function" },
    { LG8979_FC_ADC_FRCRPT,         "ADC Reference Force Report" },
    { LG8979_FC_IND_CHGRPT,         "Indication Change Report" },
    { LG8979_FC_IND_FRCRPT,         "Indication Force Report" },
    { LG8979_FC_SOE_CHGRPT,         "SOE Change Report" },
    { LG8979_FC_SOE_FRCRPT,         "SOE Force Report" },
    { 10,                           "Unknown/Invalid Function" },
    { LG8979_FC_DIG_FRCRPT,         "Digital Input Force Report" },
    { LG8979_FC_ACC_CHGRPT,         "Accumulator Change Report" },
    { LG8979_FC_ACC_FRCRPT,         "Accumulator Force Report" },
    { LG8979_FC_SOELOG_CHGRPT,      "SOE Log Change Report" },
    { 15,                           "Unknown/Invalid Function" },
    { 16,                           "Unknown/Invalid Function" },
    { 17,                           "Unknown/Invalid Function" },
    { 18,                           "Unknown/Invalid Function" },
    { 19,                           "Unknown/Invalid Function" },
    { LG8979_FC_ANG_OUTPUT,         "Analog Output" },
    { LG8979_FC_SBO_SELECT,         "SBO Select" },
    { LG8979_FC_SBO_OPERATE,        "SBO Operate" },
    { LG8979_FC_DIG_OUTPUT,         "Digital Output" },
    { LG8979_FC_ACC_FREEZE,         "Accumulator Freeze" },
    { LG8979_FC_PUL_OUTPUT,         "Pulse Output" },
    { LG8979_FC_PULTR_OUTPUT,       "Pulse Train Output" },
    { 27,                           "Unknown/Invalid Function" },
    { LG8979_FC_SBO_IMEXECUTE,      "SBO Immediate Execute" },
    { 29,                           "Unknown/Invalid Function" },
    { LG8979_FC_RTU_RESTART,        "Restart RTU" },
    { LG8979_FC_RTU_CONFIG,         "RTU Configuration" },
    { LG8979_FC_TIME_SYNC,          "Time Synchronization" },
    { LG8979_FC_TIME_BIAS,          "Time Bias" },
    { LG8979_FC_ANG_DEADBAND,       "Analog Deadbands" },
    { LG8979_FC_ANGGRP_DEFINE,      "Analog Group Define" },
    { LG8979_FC_ACC_PRESET,         "Accumulator Preset" },
    { LG8979_FC_CONT_REQUEST,       "Continuation Request" },
    { LG8979_FC_REPEAT_MSG,         "Repeat Last Message" },
    { LG8979_FC_FIRMWARE_CFG,       "Firmware Configuration" },
    { 40,                           "Unknown/Invalid Function" },
    { 41,                           "Unknown/Invalid Function" },
    { 42,                           "Unknown/Invalid Function" },
    { 43,                           "Unknown/Invalid Function" },
    { 44,                           "Unknown/Invalid Function" },
    { 45,                           "Unknown/Invalid Function" },
    { 46,                           "Unknown/Invalid Function" },
    { LG8979_FC_TABLE_READ,         "Table Read" },
    { LG8979_FC_TABLE_WRITE,        "Table Write" },
    { 49,                           "Unknown/Invalid Function" },
    { LG8979_FC_SPRPT_INT,          "Spontaneous Report Interval" },
    { LG8979_FC_SPRPT_SEQNUM,       "Spontaneous Report Sequence Number" },
    { 52,                           "Unknown/Invalid Function" },
    { 53,                           "Unknown/Invalid Function" },
    { 54,                           "Unknown/Invalid Function" },
    { 55,                           "Unknown/Invalid Function" },
    { 56,                           "Unknown/Invalid Function" },
    { 57,                           "Unknown/Invalid Function" },
    { 58,                           "Unknown/Invalid Function" },
    { 59,                           "Unknown/Invalid Function" },
    { 60,                           "Unknown/Invalid Function" },
    { 61,                           "Unknown/Invalid Function" },
    { 62,                           "Unknown/Invalid Function" },
    { LG8979_FC_EXP_RPT,            "Exception Report" },
    { 0,                         NULL }
};
static value_string_ext lg8979_funccode_vals_ext = VALUE_STRING_EXT_INIT(lg8979_funccode_vals);

static const value_string lg8979_cardcode_vals[] = {
    { 0,        "Non-Existent Slot" },
    { 1,        "Analog Input" },
    { 2,        "A/D Converter" },
    { 3,        "Analog Output" },
    { 4,        "Indication Input" },
    { 5,        "24-Bit Digital Output" },
    { 7,        "SBO Control Output" },
    { 8,        "Accumulator, Form A" },
    { 11,       "32-Bit Digital Output" },
    { 12,       "Accumulator, Form C" },
    { 15,       "Pulse Output" },
    { 28,       "SOE Input" },
    { 29,       "KWH Input" },
    { 30,       "Serial Data Collector" },
    { 31,       "Empty Slot" },
    { 0,                         NULL }
};

static const value_string lg8979_exprpt_code_vals[] = {
    { 0x00,  "Warm Restart" },
    { 0x01,  "Cold Start" },
    { 0x02,  "Insufficient Ram" },
    { 0x03,  "Bus Failure" },
    { 0x04,  "SBO Failure" },
    { 0x05,  "Analog Failure" },
    { 0x06,  "Indication/SOE Failure" },
    { 0x07,  "Card Placement Error" },
    { 0x08,  "Not Used" },
    { 0x09,  "Invalid Function Code" },
    { 0x0A,  "Invalid Block Length" },
    { 0x0B,  "Non-Existent Point" },
    { 0x0C,  "Invalid Parameter" },
    { 0x0D,  "Select/Execute Mismatch" },
    { 0x0E,  "Function Not Allowed" },
    { 0x0F,  "Not Used" },
    { 0x10,  "Database Setup has Changed" },
    { 0x11,  "Indication Change Sequence" },
    { 0,     NULL }
};

static const value_string lg8979_exprpt_parm_vals[] = {
    { 0x00,       "N/A" },
    { 0x01,       "1=Requested CLDSTRT" },
    { 0x02,       "N/A" },
    { 0x03,       "Unit" },
    { 0x04,       "Unit/Slot" },
    { 0x05,       "Unit/Slot" },
    { 0x06,       "Unit/Slot" },
    { 0x07,       "Unit/Slot" },
    { 0x08,       "N/A" },
    { 0x09,       "Function Code" },
    { 0x0A,       "Block Length" },
    { 0x0B,       "Point" },
    { 0x0C,       "Parameter" },
    { 0x0D,       "Execute Point" },
    { 0x0E,       "Function Code" },
    { 0x0F,       "N/A" },
    { 0x10,       "N/A" },
    { 0x11,       "1=Time Order (0=Not T/O)" },
    { 0,                         NULL }
};

static const value_string lg8979_sbo_tripclose_vals[] = {
    { 0x00, "Trip" },
    { 0x01, "Close" },
    { 0,    NULL }
};

static const value_string lg8979_pul_output_base_vals[] = {
    { 0x00, "10 msec" },
    { 0x01, "100 msec" },
    { 0x02, "1 sec" },
    { 0x03, "10 sec" },
    { 0,    NULL }
};

static const value_string lg8979_pul_output_rl_vals[] = {
    { 0x00, "Lower" },
    { 0x01, "Raise" },
    { 0,    NULL }
};


/*****************************************************************/
/*  Adds text to item, with trailing "," if required             */
/*****************************************************************/
static gboolean
add_item_text(proto_item *item, const gchar *text, gboolean comma_needed)
{
  if (comma_needed) {
    proto_item_append_text(item, ", ");
  }
  proto_item_append_text(item, "%s", text);
  return TRUE;
}

/*************************************************************/
/* Try to determine "direction" of message.                  */
/* Check the data length within the packet and compare       */
/* vs. the function code. Master->RTU messages will have a   */
/* fixed length that can be used to determine the direction  */
/* of the message                                            */
/*************************************************************/
static int
classify_lg8979_packet(tvbuff_t *tvb)
{
    guint8 func, len, data_len, flags;

    len = tvb_length(tvb);
    /* If TVB length is equal to 5, this is classifed as a 'short response message' */
    /* and is guaranteed to be RTU->Master only */
    if (len == 5) {
        return LG8979_DIR_RTU_TO_MASTER;
    }

    /* If TVB length is greater than 5, let's dig deeper */
    if (len > 5) {

        flags = tvb_get_guint8(tvb, 1);

        /* Flags vary between message types, so let's try those first to determine the message direction  */
        /* If both bit 3 and bit 4 are set, this is almost certainly a RTU->Master message */
        if ( (flags & 0x04) && (flags & 0x08) ){
            return LG8979_DIR_RTU_TO_MASTER;
        }
        /* If anything is in bits 3-6 without bit 7, this is a RTU->Master message */
        else if ( (flags & 0x78) && !(flags & 0x80) ){
            return LG8979_DIR_RTU_TO_MASTER;
        }

        func = tvb_get_guint8(tvb, 3) & 0x7F;
        data_len = tvb_get_guint8(tvb, 4);

        /* If we have more data in the tvb then should be there, this is a stacked RTU->Master response */
        if (len > (data_len + 5 + 2)) {
            return LG8979_DIR_RTU_TO_MASTER;
        }

        switch (func) {
            case LG8979_FC_ANG_CHGRPT:
            case LG8979_FC_ADC_FRCRPT:
            case LG8979_FC_IND_CHGRPT:
            case LG8979_FC_SOE_CHGRPT:
            case LG8979_FC_ACC_CHGRPT:
            case LG8979_FC_SOELOG_CHGRPT:
            case LG8979_FC_REPEAT_MSG:
            case LG8979_FC_RTU_CONFIG:
            case LG8979_FC_FIRMWARE_CFG:
                if (data_len == 0) {
                    return LG8979_DIR_MASTER_TO_RTU;
                }
                else {
                    return LG8979_DIR_RTU_TO_MASTER;
                }
                break;

            case LG8979_FC_ANGGRP_CHGRPT:
            case LG8979_FC_ANGGRP_FRCRPT:
                if (data_len == 1) {
                    return LG8979_DIR_MASTER_TO_RTU;
                }
                else {
                    return LG8979_DIR_RTU_TO_MASTER;
                }
                break;


            case LG8979_FC_DIG_FRCRPT:
            case LG8979_FC_ACC_FRCRPT:
            case LG8979_FC_TIME_BIAS:
                if (data_len == 2) {
                    return LG8979_DIR_MASTER_TO_RTU;
                }
                else {
                    return LG8979_DIR_RTU_TO_MASTER;
                }
                break;

            case LG8979_FC_ANG_FRCRPT:
            case LG8979_FC_IND_FRCRPT:
            case LG8979_FC_SOE_FRCRPT:
                if (data_len == 4) {
                    return LG8979_DIR_MASTER_TO_RTU;
                }
                else {
                    return LG8979_DIR_RTU_TO_MASTER;
                }
                break;

            /* These are either totally or mostly master->RTU operations */
            case LG8979_FC_ANG_OUTPUT:
            case LG8979_FC_SBO_SELECT:
            case LG8979_FC_SBO_OPERATE:
            case LG8979_FC_DIG_OUTPUT:
            case LG8979_FC_ACC_FREEZE:
            case LG8979_FC_PUL_OUTPUT:
            case LG8979_FC_PULTR_OUTPUT:
            case LG8979_FC_SBO_IMEXECUTE:
            case LG8979_FC_TIME_SYNC:
            case LG8979_FC_ANG_DEADBAND:
            case LG8979_FC_ACC_PRESET:
            case LG8979_FC_CONT_REQUEST:

                return LG8979_DIR_MASTER_TO_RTU;
                break;

            case LG8979_FC_EXP_RPT:
                return LG8979_DIR_RTU_TO_MASTER;
                break;

            default:
                return LG8979_DIR_INDETERMINATE;
                break;
        }
    }

    /* else, cannot classify */
    return LG8979_DIR_INDETERMINATE;
}

/******************************************************************************************************/
/* Code to dissect L&G 8979 Protocol packets */
/******************************************************************************************************/
static int
dissect_lg8979(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *lg8979_item=NULL, *lg8979_flags_item=NULL, *lg8979_fc_item=NULL, *lg8979_point_item=NULL, *lg8979_ts_item=NULL, *lg8979_slot_item=NULL, *lg8979_expparm_item=NULL;
    proto_tree    *lg8979_tree=NULL, *lg8979_flags_tree=NULL, *lg8979_fc_tree=NULL, *lg8979_point_tree=NULL, *lg8979_ts_tree=NULL;
    int           offset=0;
    guint8        rtu_addr, func, packet_type, data_len, ptnum8, tripclose, rl, exp_code, exp_parm;
    guint8        ts_mon, ts_day, ts_hr, ts_min, ts_sec;
    guint16       len, ptnum, ptval, ana12_val;
    guint16       ts_ms;
    gint          num_points=0, cnt=0;
    gboolean      shr, con, frz, ind, sch, slg, ack, comma_needed=FALSE, new_status, change;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "L&G 8979");
    col_clear(pinfo->cinfo, COL_INFO);

    len = tvb_length(tvb);

    lg8979_item = proto_tree_add_protocol_format(tree, proto_lg8979, tvb, 0, len, "Landis & Gyr Telegyr 8979");
    lg8979_tree = proto_item_add_subtree(lg8979_item, ett_lg8979);

    /* Add 0xFF Header to Protocol Tree */
    proto_tree_add_item(lg8979_tree, hf_lg8979_header, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* "Request" or "Response" */
    packet_type = classify_lg8979_packet(tvb);

    /* This packet type is classified as a "Request" and is deemed in the direction of "master -> RTU" */
    if (packet_type == LG8979_DIR_MASTER_TO_RTU) {

        col_clear(pinfo->cinfo, COL_INFO); /* clear out stuff in the info column */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Master -> RTU");

        /* Add Flags to Protocol Tree */
        shr = tvb_get_guint8(tvb, offset) & 0x80;
        ack = tvb_get_guint8(tvb, offset) & 0x04;

        lg8979_flags_item = proto_tree_add_text(lg8979_tree, tvb, offset, 1, "Flags");
        lg8979_flags_tree = proto_item_add_subtree(lg8979_flags_item, ett_lg8979_flags);

        proto_item_append_text(lg8979_flags_item, " (");
        if (shr) comma_needed = add_item_text(lg8979_flags_item, "SHR", comma_needed);
        if (ack)                add_item_text(lg8979_flags_item, "ACK", comma_needed);
        proto_item_append_text(lg8979_flags_item, ")");

        proto_tree_add_item(lg8979_flags_tree, hf_lg8979_shr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(lg8979_flags_tree, hf_lg8979_mfc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(lg8979_flags_tree, hf_lg8979_ack, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        /* Add RTU Address to Protocol Tree */
        rtu_addr = tvb_get_guint8(tvb, offset);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Address: %d", rtu_addr);

        proto_tree_add_item(lg8979_tree, hf_lg8979_address, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        if (!shr) {
            /* Add Function Code & last Mark Block to Protocol Tree */
            /* Function code is 7 lower bits of byte , LMB is 8th bit*/
            func = tvb_get_guint8(tvb, offset) & 0x7f;

            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_const(func, lg8979_funccode_vals, "Unknown Function Code"));

            lg8979_fc_item = proto_tree_add_text(lg8979_tree, tvb, offset, 1,
                      "Function Code: %s (%d)", val_to_str_const(func, lg8979_funccode_vals, "Unknown Function Code"), func);
            lg8979_fc_tree = proto_item_add_subtree(lg8979_fc_item, ett_lg8979_funccode);

            proto_tree_add_item(lg8979_fc_tree, hf_lg8979_lastblock, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(lg8979_fc_tree, hf_lg8979_funccode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            data_len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(lg8979_tree, hf_lg8979_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            switch (func) {
                /* Function Code 0 Analog Change Report */
                /* Function Code 7 Indication Force Report */
                /* Function Code 9 SOE Force Report */
                case LG8979_FC_ANG_FRCRPT:
                case LG8979_FC_IND_FRCRPT:
                case LG8979_FC_SOE_FRCRPT:
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_tree, hf_lg8979_stop_ptnum16, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    break;

                /* Function Code 11 Digital Input Force Report */
                /* Function Code 13 Accumulator Force Report */
                case LG8979_FC_DIG_FRCRPT:
                case LG8979_FC_ACC_FRCRPT:
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_tree, hf_lg8979_stop_ptnum8, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;

                /* Function Code 20 Analog Output */
                case LG8979_FC_ANG_OUTPUT:
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_tree, hf_lg8979_ang_output_val, tvb, offset+1, 2, ENC_LITTLE_ENDIAN);
                    offset += 3;
                    break;

                /* Function Code 21 SBO Select */
                case LG8979_FC_SBO_SELECT:

                    /* Get 8-bit point number and trip/close command-code */
                    ptnum = tvb_get_guint8(tvb, offset);
                    tripclose = (tvb_get_guint8(tvb, offset+1) & 0x80) >> 7;

                    lg8979_point_item = proto_tree_add_text(lg8979_tree, tvb, offset, 2, "SBO Command, Pt.Num: %u, Code: %s",
                       ptnum, val_to_str_const(tripclose, lg8979_sbo_tripclose_vals, "Unknown Control Code"));
                    lg8979_point_tree = proto_item_add_subtree(lg8979_point_item, ett_lg8979_point);

                    /* Update the Information Column with Command Details */
                    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Output: %u, Code: %s",
                           ptnum, val_to_str_const(tripclose, lg8979_sbo_tripclose_vals, "Unknown Control Code"));

                    /* Add SBO Select Details to tree */
                    proto_tree_add_item(lg8979_point_tree, hf_lg8979_start_ptnum8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_point_tree, hf_lg8979_sbo_tripclose, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_point_tree, hf_lg8979_sbo_timercnt, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;

                /* Function Code 22 SBO Operate */
                case LG8979_FC_SBO_OPERATE:

                    /* Get 8-bit point number */
                    ptnum = tvb_get_guint8(tvb, offset);

                    /* Update the Information Column with Command Details */
                    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Output: %u", ptnum);

                    /* Add 8-bit point number to tree */
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    break;

                /* Function Code 23 Digital Output */
                case LG8979_FC_DIG_OUTPUT:

                    /* Add Digital Output Details to tree */
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_tree, hf_lg8979_digout_data, tvb, offset+1, 3, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    break;

                /* Function Code 25 Pulse Output */
                case LG8979_FC_PUL_OUTPUT:

                    ptnum = tvb_get_guint8(tvb, offset);
                    rl = (tvb_get_guint8(tvb, offset+1) & 0x80) >> 7;

                    lg8979_point_item = proto_tree_add_text(lg8979_tree, tvb, offset, 2, "Pulse Output, Pt.Num: %u, Code: %s",
                       ptnum, val_to_str_const(rl, lg8979_pul_output_rl_vals, "Unknown Control Code"));
                    lg8979_point_tree = proto_item_add_subtree(lg8979_point_item, ett_lg8979_point);

                    /* Add Pulse Output Details to tree */
                    proto_tree_add_item(lg8979_point_tree, hf_lg8979_start_ptnum8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_point_tree, hf_lg8979_pul_output_base, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_point_tree, hf_lg8979_pul_output_dur, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_point_tree, hf_lg8979_pul_output_rl, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;

                /* Function Code 32 Time Synchronization */
                case LG8979_FC_TIME_SYNC:

                    /* Add 7-byte time-sync value to tree */
                    ts_mon = tvb_get_guint8(tvb, offset);
                    ts_day = tvb_get_guint8(tvb, offset+1);
                    ts_hr = tvb_get_guint8(tvb, offset+2);
                    ts_min = tvb_get_guint8(tvb, offset+3);
                    ts_sec = tvb_get_guint8(tvb, offset+4);
                    ts_ms = tvb_get_letohs(tvb, offset+5);

                    lg8979_ts_item = proto_tree_add_text(lg8979_tree, tvb, offset, 7, "Time-Sync Value: %02d/%02d %02d:%02d:%02d.%03d", ts_mon, ts_day, ts_hr, ts_min, ts_sec, ts_ms);
                    lg8979_ts_tree = proto_item_add_subtree(lg8979_ts_item, ett_lg8979_ts);

                    proto_tree_add_item(lg8979_ts_tree, hf_lg8979_timesync_mon, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_ts_tree, hf_lg8979_timesync_day, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_ts_tree, hf_lg8979_timesync_hour, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_ts_tree, hf_lg8979_timesync_min, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_ts_tree, hf_lg8979_timesync_sec, tvb, offset+4, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(lg8979_ts_tree, hf_lg8979_timesync_msec, tvb, offset+5, 2, ENC_LITTLE_ENDIAN);
                    offset += 7;
                    break;

                /* Function Code 33 Time Bias */
                case LG8979_FC_TIME_BIAS:
                    proto_tree_add_item(lg8979_tree, hf_lg8979_timebias_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;

                /* Function Code 34 Analog Deadband Write */
                case LG8979_FC_ANG_DEADBAND:

                    /* Get analog point number base and add to tree */
                    ptnum = tvb_get_letohs(tvb, offset);
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    num_points = (data_len-2);

                    for (cnt=0; cnt<num_points; cnt++) {

                        ptval = tvb_get_guint8(tvb, offset);
                        proto_tree_add_uint_format(lg8979_tree, hf_lg8979_ang_deadband, tvb, offset, 1, ptnum, "Point Number %u: New Deadband: %u", ptnum, ptval);
                        ptnum += 1;
                        offset += 1;
                    }

                    break;

                /* Function Code 36 Accumulator Preset */
                case LG8979_FC_ACC_PRESET:

                    /* Each qty to follow has a 8-bit point number followed by a 16-bit value */
                    num_points = ((data_len)/3);

                    for (cnt=0; cnt<num_points; cnt++) {

                        ptnum8 = tvb_get_guint8(tvb, offset);
                        ptval = tvb_get_letohs(tvb, offset+1);
                        proto_tree_add_uint_format(lg8979_tree, hf_lg8979_acc_preset, tvb, offset, 3, ptnum8, "Acc Point Number %u: Preset: %u", ptnum8, ptval);
                        offset += 3;
                    }

                    break;

                default:
                    break;
            } /* func */

        } /* !shr */

        /* Add CRC-16 */
        proto_tree_add_item(lg8979_tree, hf_lg8979_crc16, tvb, offset, 2, ENC_BIG_ENDIAN);

    }
    /* This packet type is classified as a "Response" and is deemed in the direction of "RTU -> master" */
    else if (packet_type == LG8979_DIR_RTU_TO_MASTER) {

        col_clear(pinfo->cinfo, COL_INFO); /* clear out stuff in the info column */
        col_add_fstr(pinfo->cinfo, COL_INFO, "RTU -> Master");

        /* Retrieve and add Flags to Protocol Tree */
        shr = tvb_get_guint8(tvb, offset) & 0x80;
        con = tvb_get_guint8(tvb, offset) & 0x40;
        frz = tvb_get_guint8(tvb, offset) & 0x20;
        ind = tvb_get_guint8(tvb, offset) & 0x10;
        sch = tvb_get_guint8(tvb, offset) & 0x08;
        slg = tvb_get_guint8(tvb, offset) & 0x04;

        lg8979_flags_item = proto_tree_add_text(lg8979_tree, tvb, offset, 1, "Flags");
        lg8979_flags_tree = proto_item_add_subtree(lg8979_flags_item, ett_lg8979_flags);

        proto_item_append_text(lg8979_flags_item, " (");
        if (shr) comma_needed = add_item_text(lg8979_flags_item, "SHR", comma_needed);
        if (con) comma_needed = add_item_text(lg8979_flags_item, "CON", comma_needed);
        if (frz) comma_needed = add_item_text(lg8979_flags_item, "FRZ", comma_needed);
        if (ind) comma_needed = add_item_text(lg8979_flags_item, "IND", comma_needed);
        if (sch) comma_needed = add_item_text(lg8979_flags_item, "SCH", comma_needed);
        if (slg)                add_item_text(lg8979_flags_item, "SLG", comma_needed);
        proto_item_append_text(lg8979_flags_item, ")");

        proto_tree_add_item(lg8979_flags_tree, hf_lg8979_shr, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(lg8979_flags_tree, hf_lg8979_con, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(lg8979_flags_tree, hf_lg8979_frz, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(lg8979_flags_tree, hf_lg8979_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(lg8979_flags_tree, hf_lg8979_sch, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(lg8979_flags_tree, hf_lg8979_slg, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Add RTU Address to Protocol Tree */
        rtu_addr = tvb_get_guint8(tvb, offset);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Address: %d", rtu_addr);

        proto_tree_add_item(lg8979_tree, hf_lg8979_address, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* If this is not a short response, and there are at least 2 bytes remaining continue to process function codes */
        while ((!shr) && (tvb_length_remaining(tvb, offset) > 2)){

            /* Add Function Code & last Mark Block to Protocol Tree */
            /* Function code is 7 lower bits of byte , LMB is 8th bit*/
            func = tvb_get_guint8(tvb, offset) & 0x7f;
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_const(func, lg8979_funccode_vals, "Unknown Function Code"));

            lg8979_fc_item = proto_tree_add_text(lg8979_tree, tvb, offset, 1,
                      "Function Code: %s (%d)", val_to_str_const(func, lg8979_funccode_vals, "Unknown Function Code"), func);
            lg8979_fc_tree = proto_item_add_subtree(lg8979_fc_item, ett_lg8979_funccode);

            proto_tree_add_item(lg8979_fc_tree, hf_lg8979_lastblock, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(lg8979_fc_tree, hf_lg8979_funccode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            data_len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(lg8979_tree, hf_lg8979_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            switch (func) {
                /* Function Code 0 Analog Change Report */
                case LG8979_FC_ANG_CHGRPT:

                    num_points = (data_len / 3);

                    for (cnt=0; cnt<num_points; cnt++) {

                        ptnum = ( tvb_get_guint8(tvb, offset) | ((tvb_get_guint8(tvb, offset+1) & 0x0F) << 8) );
                        ptval = ( ((tvb_get_guint8(tvb, offset+1) & 0xF0) >> 4) | (tvb_get_guint8(tvb, offset+2) << 4) );
                        proto_tree_add_uint_format(lg8979_tree, hf_lg8979_ang_point, tvb, offset, 3, ptnum, "Point Number %u: %u", ptnum, ptval);
                        offset += 3;
                    }
                    break;

                /* Function Code 1 Analog Force Report */
                case LG8979_FC_ANG_FRCRPT:

                    ptnum = tvb_get_letohs(tvb, offset);
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    /* Decode 12-bit analog data following this 3-byte bit pattern.
                     * Byte 1: PtVal 'N' LSB
                     * Byte 2: PtVal 'N+1' LSB : PtVal 'N' MSB
                     * Byte 3: PtVal 'N+1' MSB
                     * To determine the number of points based on the data bytes, we need to know
                     * if we have an even or odd number of data bytes.
                    */

                    /* even number of data bytes */
                    if (((data_len-2) % 3) == 0) {
                        num_points = (((data_len-2) / 3) * 2);
                    }
                    /* odd number of data bytes */
                    else {
                        num_points = ((((data_len-2) / 3) * 2) + 1);
                    }

                    /* loop through the data bytes decoding 12-bit analogs.  When on an even count, offset by 1 and on an odd, offset by 2. */
                    for (cnt=0; cnt < num_points; cnt++) {
                        if (cnt%2 == 0) {

                            ana12_val = ( tvb_get_guint8(tvb, offset) | ((tvb_get_guint8(tvb, offset+1) & 0x0F) << 8) );
                            proto_tree_add_uint_format(lg8979_tree, hf_lg8979_ang_point, tvb, offset, 2, ptnum, "Point Number %u: %u", ptnum, ana12_val);
                            offset += 1;

                            /* If we are in the last run through the for loop, increment the offset by 1 more byte than normal */
                            if (cnt == (num_points - 1)) {
                                offset += 1;
                            }
                        }
                        else {

                            ana12_val = ( ((tvb_get_guint8(tvb, offset) & 0xF0) >> 4) | (tvb_get_guint8(tvb, offset+1) << 4) );
                            proto_tree_add_uint_format(lg8979_tree, hf_lg8979_ang_point, tvb, offset, 2, ptnum, "Point Number %u: %u", ptnum, ana12_val);
                            offset += 2;
                        }
                        ptnum += 1;
                    }

                    break;

                /* Function Code 5 ADC Reference Force Report */
                /* Same byte pattern as 3 sequential analogs in a Force Report would follow */
                case LG8979_FC_ADC_FRCRPT:

                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    /* Retrieve the 0 and -90% references */
                    ana12_val = ( tvb_get_guint8(tvb, offset) | ((tvb_get_guint8(tvb, offset+1) & 0x0F) << 8) );
                    proto_tree_add_uint(lg8979_tree, hf_lg8979_adc_ref_zero, tvb, offset, 2, ana12_val);

                    ana12_val = ( ((tvb_get_guint8(tvb, offset+1) & 0xF0) >> 4) | (tvb_get_guint8(tvb, offset+2) << 4) );
                    proto_tree_add_uint(lg8979_tree, hf_lg8979_adc_ref_neg90, tvb, offset+1, 2, ana12_val);

                    offset += 3;

                    /* Retreive the +90% reference */
                    ana12_val = ( tvb_get_guint8(tvb, offset) | ((tvb_get_guint8(tvb, offset+1) & 0x0F) << 8) );
                    proto_tree_add_uint(lg8979_tree, hf_lg8979_adc_ref_pos90, tvb, offset, 2, ana12_val);
                    offset += 2;

                    break;

                /* Function Code 6 Indication Change Report */
                case LG8979_FC_IND_CHGRPT:

                    num_points = (data_len / 2);

                    for (cnt=0; cnt<num_points; cnt++) {
                        /* Get 12-bit point number and new status / change bits */
                        ptnum = tvb_get_letohs(tvb, offset) & 0xFFF;
                        new_status = (tvb_get_guint8(tvb, offset+1) & 0x80) >> 7;
                        change = (tvb_get_guint8(tvb, offset+1) & 0x40) >> 6;

                        lg8979_point_item = proto_tree_add_text(lg8979_tree, tvb, offset, 2,
                           "Indication Change Report, Point Number: %u, Status: %u, Change %u", ptnum, new_status, change);
                        lg8979_point_tree = proto_item_add_subtree(lg8979_point_item, ett_lg8979_point);

                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_chgrpt_ptnum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_chgrpt_status, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_chgrpt_change, tvb, offset, 2, ENC_LITTLE_ENDIAN);

                        offset += 2;
                    }

                    break;

                /* Function Code 7 Indication Force Report */
                case LG8979_FC_IND_FRCRPT:

                    ptnum = tvb_get_letohs(tvb, offset);
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    num_points = ((data_len - 2) / 2);

                    for (cnt=0; cnt<num_points; cnt++) {
                        lg8979_point_item = proto_tree_add_text(lg8979_tree, tvb, offset, 1, "Indication Status, Base Point Num %d", ptnum);
                        lg8979_point_tree = proto_item_add_subtree(lg8979_point_item, ett_lg8979_point);

                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_status_b0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_status_b1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_status_b2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_status_b3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_status_b4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_status_b5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_status_b6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_status_b7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;

                        lg8979_point_item = proto_tree_add_text(lg8979_tree, tvb, offset, 1, "Indication Change, Base Point Num %d", ptnum);
                        lg8979_point_tree = proto_item_add_subtree(lg8979_point_item, ett_lg8979_point);

                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_change_b0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_change_b1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_change_b2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_change_b3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_change_b4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_change_b5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_change_b6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_ind_frcrpt_change_b7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;

                        ptnum += 8;
                    }

                    break;

                /* Function Code 8 SOE Change Report */
                case LG8979_FC_SOE_CHGRPT:

                    num_points = (data_len / 2);

                    for (cnt=0; cnt<num_points; cnt++) {
                        /* Get 12-bit point number and new status / change bits */
                        ptnum = tvb_get_letohs(tvb, offset) & 0xFFF;
                        new_status = (tvb_get_guint8(tvb, offset+1) & 0x80) >> 7;
                        change = (tvb_get_guint8(tvb, offset+1) & 0x40) >> 6;

                        lg8979_point_item = proto_tree_add_text(lg8979_tree, tvb, offset, 2,
                           "SOE Change Report, Point Number: %u, Status: %u, Change %u", ptnum, new_status, change);
                        lg8979_point_tree = proto_item_add_subtree(lg8979_point_item, ett_lg8979_point);

                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_chgrpt_ptnum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_chgrpt_status, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_chgrpt_change, tvb, offset, 2, ENC_LITTLE_ENDIAN);

                        offset += 2;
                    }

                    break;

                /* Function Code 9 SOE Force Report */
                case LG8979_FC_SOE_FRCRPT:

                    ptnum = tvb_get_letohs(tvb, offset);
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    num_points = ((data_len - 2) / 2);

                    for (cnt=0; cnt<num_points; cnt++) {
                        lg8979_point_item = proto_tree_add_text(lg8979_tree, tvb, offset, 1, "SOE Status, Base Point Num %d", ptnum);
                        lg8979_point_tree = proto_item_add_subtree(lg8979_point_item, ett_lg8979_point);

                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_status_b0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_status_b1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_status_b2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_status_b3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_status_b4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_status_b5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_status_b6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_status_b7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;

                        lg8979_point_item = proto_tree_add_text(lg8979_tree, tvb, offset, 1, "SOE Change, Base Point Num %d", ptnum);
                        lg8979_point_tree = proto_item_add_subtree(lg8979_point_item, ett_lg8979_point);

                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_change_b0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_change_b1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_change_b2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_change_b3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_change_b4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_change_b5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_change_b6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_frcrpt_change_b7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;

                        ptnum += 8;
                    }

                    break;

                /* Function Code 11 Digital Input Force Report */
                case LG8979_FC_DIG_FRCRPT:

                    ptnum8 = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;

                    /* 1 byte per start block and 2 bytes per 16-bit block to follow */
                    num_points = ((data_len-1)/2);

                    for (cnt=0; cnt<num_points; cnt++) {

                        lg8979_point_item = proto_tree_add_text(lg8979_tree, tvb, offset, 2, "Digital Input Block %d", ptnum8);
                        lg8979_point_tree = proto_item_add_subtree(lg8979_point_item, ett_lg8979_point);

                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b3, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b4, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b5, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b6, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b7, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b8, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b9, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b10, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b11, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b12, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b13, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b14, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_digin_b15, tvb, offset, 2, ENC_LITTLE_ENDIAN);

                        ptnum8 += 1;
                        offset += 2;
                    }

                    break;


                /* Function Code 12 Accumulator Change Report */
                /* Function Code 13 Accumulator Force Report */
                case LG8979_FC_ACC_CHGRPT:
                case LG8979_FC_ACC_FRCRPT:

                    ptnum8 = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(lg8979_tree, hf_lg8979_start_ptnum8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;

                    /* 1 byte for start point number and 2 bytes for each 16-bit accumulator value */
                    num_points = ((data_len-1) / 2);

                    for (cnt=0; cnt<num_points; cnt++) {

                        lg8979_point_item = proto_tree_add_item(lg8979_tree, hf_lg8979_acc_point, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_item_prepend_text(lg8979_point_item, "Point Number %u, ", ptnum8);

                        offset += 2;
                        ptnum8 += 1;

                    }

                    break;

                /* Function Code 14 SOE Log Change Report */
                case LG8979_FC_SOELOG_CHGRPT:

                    /* 9 bytes for each SOE Record */
                    num_points = (data_len / 9);

                    for (cnt=0; cnt<num_points; cnt++) {

                        /* Get 12-bit point number and new status bit */
                        ptnum = tvb_get_letohs(tvb, offset) & 0xFFF;
                        new_status = (tvb_get_guint8(tvb, offset+1) & 0x80) >> 7;

                        lg8979_point_item = proto_tree_add_text(lg8979_tree, tvb, offset, 9,
                           "SOE Log Change Report, Point Number: %u, New Status: %u", ptnum, new_status);
                        lg8979_point_tree = proto_item_add_subtree(lg8979_point_item, ett_lg8979_point);

                        /* Add 12-bit point number and "new status" bit to tree */
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_logchg_ptnum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_point_tree, hf_lg8979_soe_logchg_newstat, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;

                        /* Add 7-byte time-stamp to tree */
                        ts_mon = tvb_get_guint8(tvb, offset);
                        ts_day = tvb_get_guint8(tvb, offset+1);
                        ts_hr = tvb_get_guint8(tvb, offset+2);
                        ts_min = tvb_get_guint8(tvb, offset+3);
                        ts_sec = tvb_get_guint8(tvb, offset+4);
                        ts_ms = tvb_get_letohs(tvb, offset+5);

                        lg8979_ts_item = proto_tree_add_text(lg8979_point_tree, tvb, offset, 7, "SOE Time Stamp: [%02d/%02d %02d:%02d:%02d.%03d]", ts_mon, ts_day, ts_hr, ts_min, ts_sec, ts_ms);
                        lg8979_ts_tree = proto_item_add_subtree(lg8979_ts_item, ett_lg8979_ts);

                        proto_tree_add_item(lg8979_ts_tree, hf_lg8979_soe_logchg_mon, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_ts_tree, hf_lg8979_soe_logchg_day, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_ts_tree, hf_lg8979_soe_logchg_hour, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_ts_tree, hf_lg8979_soe_logchg_min, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_ts_tree, hf_lg8979_soe_logchg_sec, tvb, offset+4, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(lg8979_ts_tree, hf_lg8979_soe_logchg_msec, tvb, offset+5, 2, ENC_LITTLE_ENDIAN);
                        offset += 7;
                    }

                    break;

                /* Function Code 31 RTU Configuration */
                case LG8979_FC_RTU_CONFIG:

                    /* Number of IO Chassis */
                    proto_tree_add_item(lg8979_tree, hf_lg8979_rtucfg_num_chassis, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;

                    /* Chassis Number */
                    proto_tree_add_item(lg8979_tree, hf_lg8979_rtucfg_chassis_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;

                    /* Card Codes For Each Slot (0-15) */
                    for (cnt=0; cnt<16; cnt++) {
                        lg8979_slot_item = proto_tree_add_item(lg8979_tree, hf_lg8979_rtucfg_card_slot, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_item_prepend_text(lg8979_slot_item, "Slot %d, ", cnt);
                        offset += 1;
                    }

                    break;

                /* Function Code 33 Time Bias */
                case LG8979_FC_TIME_BIAS:
                    /* Add Time Bias "Processing Time" to tree */
                    proto_tree_add_item(lg8979_tree, hf_lg8979_timebias_proctime, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    break;

                /* Function Code 39 Firmware Configuration */
                case LG8979_FC_FIRMWARE_CFG:
                    proto_tree_add_item(lg8979_tree, hf_lg8979_firmware_ver, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;

                /* Function Code 63 Exception Report */
                /* Parameter byte is context-sensitive to the Code byte used */
                /* For example, if the Code byte is 0x01 (Cold Start) the parameter byte is always 0 */
                /* If the code byte is 0x09 (Function Code), the parameter byte is the value of the disallowed function code */
                case LG8979_FC_EXP_RPT:

                    exp_code = tvb_get_guint8(tvb, offset);
                    exp_parm = tvb_get_guint8(tvb, offset+1);

                    proto_tree_add_item(lg8979_tree, hf_lg8979_exprpt_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    lg8979_expparm_item = proto_tree_add_item(lg8979_tree, hf_lg8979_exprpt_parm, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                    proto_item_prepend_text(lg8979_expparm_item, "Parameter: %s, ",
                                            val_to_str_const(exp_code, lg8979_exprpt_parm_vals, "Unknown Parameters"));
                    /* Function code lookup, if required */
                    if (exp_code == 14) {
                        proto_item *lg8979_dfc_item=NULL;
                        lg8979_dfc_item = proto_tree_add_text(lg8979_tree, tvb, offset+1, 1, "Disallowed Function Code: %s",
                        val_to_str_const(exp_parm, lg8979_funccode_vals, "Unknown Function Code"));
                        PROTO_ITEM_SET_GENERATED(lg8979_dfc_item);
                    }

                    offset += 2;
                    break;

                default:
                    break;
            }

        } /* !shr */

        if (shr) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Short Response");
        }

        /* Add CRC-16 */
        proto_tree_add_item(lg8979_tree, hf_lg8979_crc16, tvb, offset, 2, ENC_BIG_ENDIAN);

    } /* packet type */

    return tvb_length(tvb);

}

/******************************************************************************************************/
/* Return length of L&G 8979 Protocol over TCP message (used for re-assembly)                         */
/******************************************************************************************************/
static guint
get_lg8979_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_)
{

    guint len;
    len = tvb_length(tvb);

    return len;
}

/******************************************************************************************************/
/* Dissect (and possibly Re-assemble) L&G 8979 protocol payload data */
/******************************************************************************************************/
static int
dissect_lg8979_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    gint length = tvb_length(tvb);

    /* Check for a L&G8979 packet.  It should begin with 0xFF */
    if(length < 2 || tvb_get_guint8(tvb, 0) != 0xFF) {
        /* Not a L&G 8979 Protocol packet, just happened to use the same port */
        return FALSE;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, lg8979_desegment, 1,
                   get_lg8979_len, dissect_lg8979, data);

    return tvb_length(tvb);
}


/******************************************************************************************************/
/* Dissect "simple" L&G 8979 protocol payload (no TCP re-assembly) */
/******************************************************************************************************/
static int
dissect_lg8979_simple(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint length = tvb_length(tvb);

    /* Check for a L&G8979 packet.  It should begin with 0xFF */
    if(length < 2 || tvb_get_guint8(tvb, 0) != 0xFF) {
        /* Not a L&G 8979 Protocol packet, just happened to use the same port */
        return FALSE;
    }

    dissect_lg8979(tvb, pinfo, tree, data);

    return tvb_length(tvb);
}

/******************************************************************************************************/
/* Register the protocol with Wireshark */
/******************************************************************************************************/
void proto_reg_handoff_lg8979(void);

void
proto_register_lg8979(void)
{
    /* L&G 8979 Protocol header fields */
    static hf_register_info lg8979_hf[] = {
        { &hf_lg8979_header,
        { "Header", "lg8979.header", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_shr,
        { "SHR: Short Response Flag", "lg8979.shr", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
        { &hf_lg8979_mfc,
        { "MFC: Multi Function Code", "lg8979.mfc", FT_UINT8, BASE_DEC, NULL, 0x78, NULL, HFILL }},
        { &hf_lg8979_ack,
        { "ACK: Acknowledge Flag", "lg8979.ack", FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL }},
        { &hf_lg8979_con,
        { "CON: Continuation Flag", "lg8979.con", FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL }},
        { &hf_lg8979_frz,
        { "FRZ: Accumulator Freeze Flag", "lg8979.frz", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
        { &hf_lg8979_ind,
        { "IND: Indication Change Flag", "lg8979.ind", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
        { &hf_lg8979_sch,
        { "SCH: SOE Change Flag", "lg8979.sch", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL }},
        { &hf_lg8979_slg,
        { "SLG: SOE Log Flag", "lg8979.slg", FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL }},
        { &hf_lg8979_address,
        { "RTU Address", "lg8979.address", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_lastblock,
        { "Last Block Mark", "lg8979.lastblock", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
        { &hf_lg8979_funccode,
        { "Function Code", "lg8979.funccode", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &lg8979_funccode_vals_ext, 0x7F, NULL, HFILL }},
        { &hf_lg8979_length,
        { "Data Length", "lg8979.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_start_ptnum16,
        { "Start Point Number (16-bit)", "lg8979.start_ptnum16", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_start_ptnum8,
        { "Start Point Number (8-bit)", "lg8979.start_ptnum8", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_stop_ptnum16,
        { "Stop Point Number (16-bit)", "lg8979.stop_ptnum16", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_stop_ptnum8,
        { "Stop Point Number (8-bit)", "lg8979.stop_ptnum8", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_ang_point,
        { "Analog Point", "lg8979.ang_point", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_adc_ref_zero,
        { "ADC Reference (0%)", "lg8979.adc_ref_zero", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_adc_ref_neg90,
        { "ADC Reference (-90%)", "lg8979.adc_ref_neg90", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_adc_ref_pos90,
        { "ADC Reference (+90%)", "lg8979.adc_ref_pos90", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_ind_chgrpt_ptnum,
        { "Point Number (12-bit)", "lg8979.ind_chgrpt_ptnum", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }},
        { &hf_lg8979_ind_chgrpt_status,
        { "Status Bit", "lg8979.ind_chgrpt_status", FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL }},
        { &hf_lg8979_ind_chgrpt_change,
        { "Change Bit", "lg8979.ind_chgrpt_change", FT_UINT16, BASE_DEC, NULL, 0x4000, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_status_b0,
        { "Status Bit 0", "lg8979.ind.frcrpt.status_b0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_status_b1,
        { "Status Bit 1", "lg8979.ind.frcrpt.status_b1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_status_b2,
        { "Status Bit 2", "lg8979.ind.frcrpt.status_b2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_status_b3,
        { "Status Bit 3", "lg8979.ind.frcrpt.status_b3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_status_b4,
        { "Status Bit 4", "lg8979.ind.frcrpt.status_b4", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_status_b5,
        { "Status Bit 5", "lg8979.ind.frcrpt.status_b5", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_status_b6,
        { "Status Bit 6", "lg8979.ind.frcrpt.status_b6", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_status_b7,
        { "Status Bit 7", "lg8979.ind.frcrpt.status_b7", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_change_b0,
        { "Change Bit 0", "lg8979.ind.frcrpt.change_b0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_change_b1,
        { "Change Bit 1", "lg8979.ind.frcrpt.change_b1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_change_b2,
        { "Change Bit 2", "lg8979.ind.frcrpt.change_b2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_change_b3,
        { "Change Bit 3", "lg8979.ind.frcrpt.change_b3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_change_b4,
        { "Change Bit 4", "lg8979.ind.frcrpt.change_b4", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_change_b5,
        { "Change Bit 5", "lg8979.ind.frcrpt.change_b5", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_change_b6,
        { "Change Bit 6", "lg8979.ind.frcrpt.change_b6", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
        { &hf_lg8979_ind_frcrpt_change_b7,
        { "Change Bit 7", "lg8979.ind.frcrpt.change_b7", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
        { &hf_lg8979_soe_chgrpt_ptnum,
        { "Point Number (12-bit)", "lg8979.soe_chgrpt_ptnum", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }},
        { &hf_lg8979_soe_chgrpt_status,
        { "Status Bit", "lg8979.soe_chgrpt_status", FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL }},
        { &hf_lg8979_soe_chgrpt_change,
        { "Change Bit", "lg8979.soe_chgrpt_change", FT_UINT16, BASE_DEC, NULL, 0x4000, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_status_b0,
        { "Status Bit 0", "lg8979.soe.frcrpt.status_b0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_status_b1,
        { "Status Bit 1", "lg8979.soe.frcrpt.status_b1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_status_b2,
        { "Status Bit 2", "lg8979.soe.frcrpt.status_b2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_status_b3,
        { "Status Bit 3", "lg8979.soe.frcrpt.status_b3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_status_b4,
        { "Status Bit 4", "lg8979.soe.frcrpt.status_b4", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_status_b5,
        { "Status Bit 5", "lg8979.soe.frcrpt.status_b5", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_status_b6,
        { "Status Bit 6", "lg8979.soe.frcrpt.status_b6", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_status_b7,
        { "Status Bit 7", "lg8979.soe.frcrpt.status_b7", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_change_b0,
        { "Change Bit 0", "lg8979.soe.frcrpt.change_b0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_change_b1,
        { "Change Bit 1", "lg8979.soe.frcrpt.change_b1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_change_b2,
        { "Change Bit 2", "lg8979.soe.frcrpt.change_b2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_change_b3,
        { "Change Bit 3", "lg8979.soe.frcrpt.change_b3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_change_b4,
        { "Change Bit 4", "lg8979.soe.frcrpt.change_b4", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_change_b5,
        { "Change Bit 5", "lg8979.soe.frcrpt.change_b5", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_change_b6,
        { "Change Bit 6", "lg8979.soe.frcrpt.change_b6", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
        { &hf_lg8979_soe_frcrpt_change_b7,
        { "Change Bit 7", "lg8979.soe.frcrpt.change_b7", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
        { &hf_lg8979_digin_b0,
        { "Digital Input Bit 0", "lg8979.digin_b0", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},
        { &hf_lg8979_digin_b1,
        { "Digital Input Bit 1", "lg8979.digin_b1", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }},
        { &hf_lg8979_digin_b2,
        { "Digital Input Bit 2", "lg8979.digin_b2", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }},
        { &hf_lg8979_digin_b3,
        { "Digital Input Bit 3", "lg8979.digin_b3", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL }},
        { &hf_lg8979_digin_b4,
        { "Digital Input Bit 4", "lg8979.digin_b4", FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL }},
        { &hf_lg8979_digin_b5,
        { "Digital Input Bit 5", "lg8979.digin_b5", FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL }},
        { &hf_lg8979_digin_b6,
        { "Digital Input Bit 6", "lg8979.digin_b6", FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL }},
        { &hf_lg8979_digin_b7,
        { "Digital Input Bit 7", "lg8979.digin_b7", FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL }},
        { &hf_lg8979_digin_b8,
        { "Digital Input Bit 8", "lg8979.digin_b8", FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL }},
        { &hf_lg8979_digin_b9,
        { "Digital Input Bit 9", "lg8979.digin_b9", FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL }},
        { &hf_lg8979_digin_b10,
        { "Digital Input Bit 10", "lg8979.digin_b10", FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL }},
        { &hf_lg8979_digin_b11,
        { "Digital Input Bit 11", "lg8979.digin_b11", FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL }},
        { &hf_lg8979_digin_b12,
        { "Digital Input Bit 12", "lg8979.digin_b12", FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL }},
        { &hf_lg8979_digin_b13,
        { "Digital Input Bit 13", "lg8979.digin_b13", FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL }},
        { &hf_lg8979_digin_b14,
        { "Digital Input Bit 14", "lg8979.digin_b14", FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL }},
        { &hf_lg8979_digin_b15,
        { "Digital Input Bit 15", "lg8979.digin_b15", FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }},
        { &hf_lg8979_acc_point,
        { "Value", "lg8979.acc_point", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_soe_logchg_ptnum,
        { "Point Number", "lg8979.soe_logchg_ptnum", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }},
        { &hf_lg8979_soe_logchg_newstat,
        { "New Status", "lg8979.soe_logchg_newstat", FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL }},
        { &hf_lg8979_soe_logchg_mon,
        { "Month", "lg8979.soe_logchg_mon", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_soe_logchg_day,
        { "Day", "lg8979.soe_logchg_day", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_soe_logchg_hour,
        { "Hours", "lg8979.soe_logchg_hour", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_soe_logchg_min,
        { "Minute", "lg8979.soe_logchg_min", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_soe_logchg_sec,
        { "Second", "lg8979.soe_logchg_sec", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_soe_logchg_msec,
        { "Milli-Second", "lg8979.soe_logchg_msec", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_ang_output_val,
        { "Point Value", "lg8979.ang_output_val", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }},
        { &hf_lg8979_sbo_tripclose,
        { "Trip/Close Control Code", "lg8979.sbo_tripclose", FT_UINT8, BASE_DEC, VALS(lg8979_sbo_tripclose_vals), 0x80, NULL, HFILL }},
        { &hf_lg8979_sbo_timercnt,
        { "Timer Count", "lg8979.sbo_timercnt", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
        { &hf_lg8979_digout_data,
        { "Data", "lg8979.digout_data", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_pul_output_base,
        { "Base Time", "lg8979.pul_output_base", FT_UINT8, BASE_HEX, VALS(lg8979_pul_output_base_vals), 0x03, NULL, HFILL }},
        { &hf_lg8979_pul_output_dur,
        { "Duration", "lg8979.pul_output_dur", FT_UINT8, BASE_HEX, NULL, 0x7C, NULL, HFILL }},
        { &hf_lg8979_pul_output_rl,
        { "Raise/Lower", "lg8979.pul_output_rl", FT_UINT8, BASE_HEX, VALS(lg8979_pul_output_rl_vals), 0x80, NULL, HFILL }},
        { &hf_lg8979_ang_deadband,
        { "Deadband", "lg8979.ang_deadband", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_acc_preset,
        { "Preset Value", "lg8979.acc_preset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_rtucfg_num_chassis,
        { "Number of I/O Chassis in RTU", "lg8979.rtucfg_num_chassis", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_rtucfg_chassis_num,
        { "Chassis Number", "lg8979.rtucfg_chassis_num", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_rtucfg_card_slot,
        { "Card Code", "lg8979.rtucfg_card_slot", FT_UINT8, BASE_DEC, VALS(lg8979_cardcode_vals), 0x0, NULL, HFILL }},
        { &hf_lg8979_timesync_mon,
        { "Month", "lg8979.timesync_mon", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_timesync_day,
        { "Day", "lg8979.timesync_day", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_timesync_hour,
        { "Hours", "lg8979.timesync_hour", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_timesync_min,
        { "Minute", "lg8979.timesync_min", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_timesync_sec,
        { "Second", "lg8979.timesync_sec", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_timesync_msec,
        { "Milli-Second", "lg8979.timesync_msec", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_timebias_value,
        { "Time Bias Value", "lg8979.timebias_value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_firmware_ver,
        { "Firmware Version", "lg8979.firmware_ver", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_timebias_proctime,
        { "Time Bias Processing Time (ms)", "lg8979.timebias_proctime", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_exprpt_code,
        { "Exception Report Code", "lg8979.exprpt_code", FT_UINT8, BASE_DEC, VALS(lg8979_exprpt_code_vals), 0x0, NULL, HFILL }},
        { &hf_lg8979_exprpt_parm,
        { "Value", "lg8979.exprpt_parm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lg8979_crc16,
        { "CRC-16", "lg8979.crc16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_lg8979,
        &ett_lg8979_flags,
        &ett_lg8979_funccode,
        &ett_lg8979_point,
        &ett_lg8979_ts,
   };

    module_t *lg8979_module;

    /* Register the protocol name and description */
    proto_lg8979 = proto_register_protocol("Landis & Gyr Telegyr 8979", "L&G 8979", "lg8979");

    /* Registering protocol to be called by another dissector */
    new_register_dissector("lg8979", dissect_lg8979_simple, proto_lg8979);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_lg8979, lg8979_hf, array_length(lg8979_hf));
    proto_register_subtree_array(ett, array_length(ett));


    /* Register required preferences for L&G 8979 register decoding */
    lg8979_module = prefs_register_protocol(proto_lg8979, proto_reg_handoff_lg8979);

    /*  L&G 8979 - Desegmentmentation; defaults to TRUE for TCP desegmentation*/
    prefs_register_bool_preference(lg8979_module, "desegment",
                                  "Desegment all L&G 8979 Protocol packets spanning multiple TCP segments",
                                  "Whether the L&G 8979 dissector should desegment all messages spanning multiple TCP segments",
                                  &lg8979_desegment);


    /* L&G 8979 Preference - Default TCP Port, allows for "user" port either than 0. */
    prefs_register_uint_preference(lg8979_module, "tcp.port",
                                  "L&G 8979 Protocol Port",
                                  "Set the TCP port for L&G 8979 Protocol packets (if other than the default of 0)",
                                  10, &global_lg8979_tcp_port);
}

/******************************************************************************************************/
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
 */
/******************************************************************************************************/
void
proto_reg_handoff_lg8979(void)
{
    static int lg8979_prefs_initialized = FALSE;
    static dissector_handle_t lg8979_handle;
    static unsigned int lg8979_port;

    /* Make sure to use L&G 8979 Protocol Preferences field to determine default TCP port */
    if (! lg8979_prefs_initialized) {
        lg8979_handle = new_create_dissector_handle(dissect_lg8979_tcp, proto_lg8979);
        lg8979_prefs_initialized = TRUE;
    }

    if(lg8979_port != 0 && lg8979_port != global_lg8979_tcp_port){
        dissector_delete_uint("tcp.port", lg8979_port, lg8979_handle);
    }

    if(global_lg8979_tcp_port != 0 && lg8979_port != global_lg8979_tcp_port) {
        dissector_add_uint("tcp.port", global_lg8979_tcp_port, lg8979_handle);
    }

    lg8979_port = global_lg8979_tcp_port;

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
