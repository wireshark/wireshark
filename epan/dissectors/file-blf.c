/* file-blf.c
 * BLF File Format.
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2020-2021 Dr. Lars Voelker
  *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This dissector allows to parse BLF files.
 */

 /*
  * The following was used as a reference for the file format:
  *     https://bitbucket.org/tobylorenz/vector_blf
  * The repo above includes multiple examples files as well.
  */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/wmem/wmem.h>
#include <wiretap/blf.h>

static int proto_blf = -1;

static int hf_blf_file_header = -1;
static int hf_blf_file_header_magic = -1;
static int hf_blf_file_header_length = -1;
static int hf_blf_file_header_api = -1;
static int hf_blf_file_header_app = -1;
static int hf_blf_file_header_comp_level = -1;
static int hf_blf_file_header_app_major = -1;
static int hf_blf_file_header_app_minor = -1;
static int hf_blf_file_header_len_comp = -1;
static int hf_blf_file_header_len_uncomp = -1;
static int hf_blf_file_header_obj_count = -1;
static int hf_blf_file_header_app_build = -1;
static int hf_blf_file_header_start_date = -1;
static int hf_blf_file_header_end_date = -1;
static int hf_blf_file_header_restore_point_offset = -1;

static int hf_blf_lobj = -1;
static int hf_blf_lobj_hdr = -1;
static int hf_blf_lobj_magic = -1;
static int hf_blf_lobj_hdr_len = -1;
static int hf_blf_lobj_hdr_type = -1;
static int hf_blf_lobj_obj_len = -1;
static int hf_blf_lobj_obj_type = -1;
static int hf_blf_lobj_hdr_remains = -1;
static int hf_blf_lobj_payload = -1;

static int hf_blf_cont_comp_method = -1;
static int hf_blf_cont_res1 = -1;
static int hf_blf_cont_res2 = -1;
static int hf_blf_cont_uncomp_size = -1;
static int hf_blf_cont_res4 = -1;
static int hf_blf_cont_payload = -1;

static gint ett_blf = -1;
static gint ett_blf_header = -1;
static gint ett_blf_obj = -1;
static gint ett_blf_obj_header = -1;
static gint ett_blf_logcontainer_payload = -1;

static const value_string blf_object_names[] = {
    { BLF_OBJTYPE_UNKNOWN,                          "Unknown" },
    { BLF_OBJTYPE_CAN_MESSAGE,                      "CAN Message" },
    { BLF_OBJTYPE_CAN_ERROR,                        "CAN Error" },
    { BLF_OBJTYPE_CAN_OVERLOAD,                     "CAN Overload" },
    { BLF_OBJTYPE_CAN_STATISTIC,                    "CAN Statistics" },
    { BLF_OBJTYPE_APP_TRIGGER,                      "App Trigger" },
    { BLF_OBJTYPE_ENV_INTEGER,                      "Env Integer" },
    { BLF_OBJTYPE_ENV_DOUBLE,                       "Env Double" },
    { BLF_OBJTYPE_ENV_STRING,                       "Env String" },
    { BLF_OBJTYPE_ENV_DATA,                         "Env Data" },
    { BLF_OBJTYPE_LOG_CONTAINER,                    "Log Container" },
    { BLF_OBJTYPE_LIN_MESSAGE,                      "LIN Message" },
    { BLF_OBJTYPE_LIN_CRC_ERROR,                    "LIN CRC Error" },
    { BLF_OBJTYPE_LIN_DLC_INFO,                     "LIN DLC Info" },
    { BLF_OBJTYPE_LIN_RCV_ERROR,                    "LIN Receive Error" },
    { BLF_OBJTYPE_LIN_SND_ERROR,                    "LIN Send Error" },
    { BLF_OBJTYPE_LIN_SLV_TIMEOUT,                  "LIN Slave Timeout" },
    { BLF_OBJTYPE_LIN_SCHED_MODCH,                  "LIN Schedule Mode Change" },
    { BLF_OBJTYPE_LIN_SYN_ERROR,                    "LIN Sync Error" },
    { BLF_OBJTYPE_LIN_BAUDRATE,                     "LIN Baudrate" },
    { BLF_OBJTYPE_LIN_SLEEP,                        "LIN Sleep" },
    { BLF_OBJTYPE_LIN_WAKEUP,                       "LIN Wakeup" },
    { BLF_OBJTYPE_MOST_SPY,                         "MOST Spy" },
    { BLF_OBJTYPE_MOST_CTRL,                        "MOST Control" },
    { BLF_OBJTYPE_MOST_LIGHTLOCK,                   "MOST Light Lock" },
    { BLF_OBJTYPE_MOST_STATISTIC,                   "MOST Statistics" },
    { BLF_OBJTYPE_FLEXRAY_DATA,                     "FlexRay Data" },
    { BLF_OBJTYPE_FLEXRAY_SYNC,                     "FlexRay Sync" },
    { BLF_OBJTYPE_CAN_DRIVER_ERROR,                 "CAN Driver Error" },
    { BLF_OBJTYPE_MOST_PKT,                         "MOST Packet" },
    { BLF_OBJTYPE_MOST_PKT2,                        "MOST Packet 2" },
    { BLF_OBJTYPE_MOST_HWMODE,                      "MOST Hardware Mode" },
    { BLF_OBJTYPE_MOST_REG,                         "MOST Register Data" },
    { BLF_OBJTYPE_MOST_GENREG,                      "MOST Register Data" },
    { BLF_OBJTYPE_MOST_NETSTATE,                    "MOST Net State" },
    { BLF_OBJTYPE_MOST_DATALOST,                    "MOST Data Lost" },
    { BLF_OBJTYPE_MOST_TRIGGER,                     "MOST Trigger" },
    { BLF_OBJTYPE_FLEXRAY_CYCLE,                    "FlexRay Cycle" },
    { BLF_OBJTYPE_FLEXRAY_MESSAGE,                  "FlexRay Message" },
    { BLF_OBJTYPE_LIN_CHECKSUM_INFO,                "LIN Checksum Info" },
    { BLF_OBJTYPE_LIN_SPIKE_EVENT,                  "LIN Spike Event" },
    { BLF_OBJTYPE_CAN_DRIVER_SYNC,                  "CAN Driver Sync" },
    { BLF_OBJTYPE_FLEXRAY_STATUS,                   "FlexRay Status" },
    { BLF_OBJTYPE_GPS_EVENT,                        "GPS Event" },
    { BLF_OBJTYPE_FLEXRAY_ERROR,                    "FlexRay Error" },
    { BLF_OBJTYPE_FLEXRAY_STATUS,                   "FlexRay Status" },
    { BLF_OBJTYPE_FLEXRAY_STARTCYCLE,               "FlexRay Start Cycle" },
    { BLF_OBJTYPE_FLEXRAY_RCVMESSAGE,               "FlexRay Receive Message" },
    { BLF_OBJTYPE_REALTIMECLOCK,                    "Realtime Clock" },
    { BLF_OBJTYPE_LIN_STATISTIC,                    "LIN Statistics" },
    { BLF_OBJTYPE_J1708_MESSAGE,                    "J1708 Message" },
    { BLF_OBJTYPE_J1708_VIRTUAL_MSG,                "J1708 Virtual Message" },
    { BLF_OBJTYPE_LIN_MESSAGE2,                     "LIN Message 2" },
    { BLF_OBJTYPE_LIN_SND_ERROR2,                   "LIN Send Error 2" },
    { BLF_OBJTYPE_LIN_SYN_ERROR2,                   "LIN Sync Error 2" },
    { BLF_OBJTYPE_LIN_CRC_ERROR2,                   "LIN CRC Error 2" },
    { BLF_OBJTYPE_LIN_RCV_ERROR2,                   "LIN Receive Error 2" },
    { BLF_OBJTYPE_LIN_WAKEUP2,                      "LIN Wakeup 2" },
    { BLF_OBJTYPE_LIN_SPIKE_EVENT2,                 "LIN Spike Event 2" },
    { BLF_OBJTYPE_LIN_LONG_DOM_SIG,                 "LIN Long Dominant Signal" },
    { BLF_OBJTYPE_APP_TEXT,                         "Text" },
    { BLF_OBJTYPE_FLEXRAY_RCVMESSAGE_EX,            "FlexRay Receive Message Ext" },
    { BLF_OBJTYPE_MOST_STATISTICEX,                 "MOST Statistics Ext" },
    { BLF_OBJTYPE_MOST_TXLIGHT,                     "MOST TX Light" },
    { BLF_OBJTYPE_MOST_ALLOCTAB,                    "MOST Allocation Table" },
    { BLF_OBJTYPE_MOST_STRESS,                      "MOST Stress" },
    { BLF_OBJTYPE_ETHERNET_FRAME,                   "Ethernet Frame" },
    { BLF_OBJTYPE_SYS_VARIABLE,                     "System Variable" },
    { BLF_OBJTYPE_CAN_ERROR_EXT,                    "CAN Error Ext" },
    { BLF_OBJTYPE_CAN_DRIVER_ERROR_EXT,             "CAN Driver Error Ext" },
    { BLF_OBJTYPE_LIN_LONG_DOM_SIG2,                "LIN Long Dominant Signal 2" },
    { BLF_OBJTYPE_MOST_150_MESSAGE,                 "MOST150 Message" },
    { BLF_OBJTYPE_MOST_150_PKT,                     "MOST150 Packet" },
    { BLF_OBJTYPE_MOST_ETHERNET_PKT,                "MOST Ethernet Packet" },
    { BLF_OBJTYPE_MOST_150_MESSAGE_FRAGMENT,        "MOST150 Message Fragment" },
    { BLF_OBJTYPE_MOST_150_PKT_FRAGMENT,            "MOST150 Packet Fragment" },
    { BLF_OBJTYPE_MOST_ETHERNET_PKT_FRAGMENT,       "MOST Ethernet Packet Fragment" },
    { BLF_OBJTYPE_MOST_SYSTEM_EVENT,                "MOST System Event" },
    { BLF_OBJTYPE_MOST_150_ALLOCTAB,                "MOST150 Allocation Table" },
    { BLF_OBJTYPE_MOST_50_MESSAGE,                  "MOST50 Message" },
    { BLF_OBJTYPE_MOST_50_PKT,                      "MOST50 Packet" },
    { BLF_OBJTYPE_CAN_MESSAGE2,                     "CAN Message 2" },
    { BLF_OBJTYPE_LIN_UNEXPECTED_WAKEUP,            "LIN Unexpected Wakeup" },
    { BLF_OBJTYPE_LIN_SHORT_OR_SLOW_RESPONSE,       "LIN Short or Slow Response" },
    { BLF_OBJTYPE_LIN_DISTURBANCE_EVENT,            "LIN Disturbance" },
    { BLF_OBJTYPE_SERIAL_EVENT,                     "Serial" },
    { BLF_OBJTYPE_OVERRUN_ERROR,                    "Overrun Error" },
    { BLF_OBJTYPE_EVENT_COMMENT,                    "Comment" },
    { BLF_OBJTYPE_WLAN_FRAME,                       "WLAN Frame" },
    { BLF_OBJTYPE_WLAN_STATISTIC,                   "WLAN Statistics" },
    { BLF_OBJTYPE_MOST_ECL,                         "MOST Electric Control Line" },
    { BLF_OBJTYPE_GLOBAL_MARKER,                    "Global Marker" },
    { BLF_OBJTYPE_AFDX_FRAME,                       "AFDX Frame" },
    { BLF_OBJTYPE_AFDX_STATISTIC,                   "AFDX Statistics" },
    { BLF_OBJTYPE_KLINE_STATUSEVENT,                "KLINE Status" },
    { BLF_OBJTYPE_CAN_FD_MESSAGE,                   "CANFD Message" },
    { BLF_OBJTYPE_CAN_FD_MESSAGE_64,                "CANFD Message 64" },
    { BLF_OBJTYPE_ETHERNET_RX_ERROR,                "Ethernet RX Error" },
    { BLF_OBJTYPE_ETHERNET_STATUS,                  "Ethernet Status" },
    { BLF_OBJTYPE_CAN_FD_ERROR_64,                  "CANFD Error 64" },
    { BLF_OBJTYPE_AFDX_STATUS,                      "AFDX Status" },
    { BLF_OBJTYPE_AFDX_BUS_STATISTIC,               "AFDX Bus Statistics" },
    { BLF_OBJTYPE_AFDX_ERROR_EVENT,                 "AFDX Error" },
    { BLF_OBJTYPE_A429_ERROR,                       "A429 Error" },
    { BLF_OBJTYPE_A429_STATUS,                      "A429 Status" },
    { BLF_OBJTYPE_A429_BUS_STATISTIC,               "A429 Bus Statistics" },
    { BLF_OBJTYPE_A429_MESSAGE,                     "A429 Message" },
    { BLF_OBJTYPE_ETHERNET_STATISTIC,               "Ethernet Statistics" },
    { BLF_OBJTYPE_TEST_STRUCTURE,                   "Test Structure" },
    { BLF_OBJTYPE_DIAG_REQUEST_INTERPRETATION,      "Diagnostics Request Interpretation" },
    { BLF_OBJTYPE_ETHERNET_FRAME_EX,                "Ethernet Frame Ext" },
    { BLF_OBJTYPE_ETHERNET_FRAME_FORWARDED,         "Ethernet Frame Forwarded" },
    { BLF_OBJTYPE_ETHERNET_ERROR_EX,                "Ethernet Error Ext" },
    { BLF_OBJTYPE_ETHERNET_ERROR_FORWARDED,         "Ethernet Error Forwarded" },
    { BLF_OBJTYPE_FUNCTION_BUS,                     "Function Bus" },
    { BLF_OBJTYPE_DATA_LOST_BEGIN,                  "Data Lost Begin" },
    { BLF_OBJTYPE_DATA_LOST_END,                    "Data Lost End" },
    { BLF_OBJTYPE_WATER_MARK_EVENT,                 "Watermark" },
    { BLF_OBJTYPE_TRIGGER_CONDITION,                "Trigger Condition" },
    { BLF_OBJTYPE_CAN_SETTING_CHANGED,              "CAN Settings Changed" },
    { BLF_OBJTYPE_DISTRIBUTED_OBJECT_MEMBER,        "Distributed Object Member" },
    { BLF_OBJTYPE_ATTRIBUTE_EVENT,                  "Attribute Event" },
    { 0, NULL }
};

static const value_string application_names[] = {
    { 0,    "Unknown" },
    { 1,    "Vector CANalyzer" },
    { 2,    "Vector CANoe" },
    { 3,    "Vector CANstress" },
    { 4,    "Vector CANlog" },
    { 5,    "Vector CANape" },
    { 6,    "Vector CANcaseXL log" },
    { 7,    "Vector Logger Configurator" },
    { 200,  "Porsche Logger" },
    { 201,  "CAETEC Logger" },
    { 202,  "Vector Network Simulator" },
    { 203,  "IPETRONIK logger" },
    { 204,  "RT PK" },
    { 205,  "PikeTec" },
    { 206,  "Sparks" },
    { 0, NULL }
};


#define BLF_COMPRESSION_NONE    0
#define BLF_COMPRESSION_ZLIB    2

static const value_string blf_compression_names[] = {
    { BLF_COMPRESSION_NONE,     "No Compression" },
    { BLF_COMPRESSION_ZLIB,     "Compression ZLIB" },
    { 0, NULL }
};

void proto_register_file_blf(void);
void proto_reg_handoff_file_blf(void);
static int dissect_blf_next_object(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

#define MAGIC_NUMBER_SIZE 4
static const guint8 blf_file_magic[MAGIC_NUMBER_SIZE] = { 'L', 'O', 'G', 'G' };
static const guint8 blf_lobj_magic[MAGIC_NUMBER_SIZE] = { 'L', 'O', 'B', 'J' };


static proto_item *
dissect_blf_header_date(proto_tree *tree, int hf, tvbuff_t *tvb, gint offset, gint length) {
    static const value_string weekday_names[] = {
    { 0,    "Sunday"},
    { 1,    "Monday"},
    { 2,    "Tuesday"},
    { 3,    "Wednesday"},
    { 4,    "Thursday"},
    { 5,    "Friday"},
    { 6,    "Saturday"},
    { 0, NULL }
    };

    guint16 year        = tvb_get_guint16(tvb, offset +  0, ENC_LITTLE_ENDIAN);
    guint16 month       = tvb_get_guint16(tvb, offset +  2, ENC_LITTLE_ENDIAN);
    guint16 day_of_week = tvb_get_guint16(tvb, offset +  4, ENC_LITTLE_ENDIAN);
    guint16 day         = tvb_get_guint16(tvb, offset +  6, ENC_LITTLE_ENDIAN);
    guint16 hour        = tvb_get_guint16(tvb, offset +  8, ENC_LITTLE_ENDIAN);
    guint16 minute      = tvb_get_guint16(tvb, offset + 10, ENC_LITTLE_ENDIAN);
    guint16 sec         = tvb_get_guint16(tvb, offset + 12, ENC_LITTLE_ENDIAN);
    guint16 ms          = tvb_get_guint16(tvb, offset + 14, ENC_LITTLE_ENDIAN);

    header_field_info *hfinfo = proto_registrar_get_nth(hf);

    return proto_tree_add_bytes_format(tree, hf, tvb, offset, length, NULL,
                                       "%s: %s %d-%02d-%02d %02d:%02d:%02d.%03d",
                                       hfinfo->name,
                                       val_to_str(day_of_week, weekday_names, "%d"),
                                       year, month, day, hour, minute, sec, ms);
}

static proto_item *
dissect_blf_api_version(proto_tree *tree, int hf, tvbuff_t *tvb, gint offset, gint length) {
    guint8 major = tvb_get_guint8(tvb, offset + 0);
    guint8 minor = tvb_get_guint8(tvb, offset + 1);
    guint8 build = tvb_get_guint8(tvb, offset + 2);
    guint8 patch = tvb_get_guint8(tvb, offset + 3);

    header_field_info *hfinfo = proto_registrar_get_nth(hf);

    return proto_tree_add_bytes_format(tree, hf, tvb, offset, length, NULL, "%s: %d.%d.%d.%d",
                                       hfinfo->name, major, minor, build, patch);
}

static int
dissect_blf_lobj(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset_orig) {
    proto_item    *ti_root = NULL;
    proto_item    *ti = NULL;
    proto_tree    *objtree = NULL;
    proto_tree    *subtree = NULL;
    volatile gint  offset = offset_orig;
    tvbuff_t      *sub_tvb;

    guint          hdr_length = tvb_get_guint16(tvb, offset_orig + 4, ENC_LITTLE_ENDIAN);
    guint          obj_length;
    guint          obj_type;
    guint32        comp_method;

    /* this should never happen since we should only be called with at least 16 Bytes present */
    if (tvb_captured_length_remaining(tvb, offset_orig) < 16) {
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti_root = proto_tree_add_item(tree, hf_blf_lobj, tvb, offset, -1, ENC_NA);
    objtree = proto_item_add_subtree(ti_root, ett_blf_obj);

    ti = proto_tree_add_item(objtree, hf_blf_lobj_hdr, tvb, offset, hdr_length, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_blf_obj);

    proto_tree_add_item(subtree, hf_blf_lobj_magic, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(subtree, hf_blf_lobj_hdr_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_blf_lobj_hdr_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(subtree, hf_blf_lobj_obj_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &obj_length);
    offset += 4;
    proto_tree_add_item_ret_uint(subtree, hf_blf_lobj_obj_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &obj_type);
    offset += 4;

    /* check if the whole object is present or if it was truncated */
    if (tvb_captured_length_remaining(tvb, offset_orig) < (gint)obj_length) {
        proto_item_set_end(ti_root, tvb, offset_orig + tvb_captured_length_remaining(tvb, offset_orig));
        proto_item_append_text(ti_root, " TRUNCATED");
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    proto_item_set_end(ti_root, tvb, offset_orig + obj_length);
    proto_item_append_text(ti_root, " (%s)", val_to_str(obj_type, blf_object_names, "%d"));

    switch (obj_type) {
        case BLF_OBJTYPE_LOG_CONTAINER:
            proto_tree_add_item_ret_uint(objtree, hf_blf_cont_comp_method, tvb, offset, 2, ENC_LITTLE_ENDIAN, &comp_method);
            offset += 2;
            proto_tree_add_item(objtree, hf_blf_cont_res1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(objtree, hf_blf_cont_res2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(objtree, hf_blf_cont_uncomp_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(objtree, hf_blf_cont_res4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            if (comp_method == BLF_COMPRESSION_NONE) {
                sub_tvb = tvb_new_subset_length_caplen(tvb, offset, offset_orig + obj_length - offset, offset_orig + obj_length - offset);
            } else {
                sub_tvb = tvb_child_uncompress(tvb, tvb, offset, offset_orig + obj_length - offset);
                if (sub_tvb) {
                    add_new_data_source(pinfo, sub_tvb, "Decompressed Data");
                }
            }

            /* TODO: actually the objects might overlap containers, which we do not consider here... */
            if (sub_tvb) {
                guint offset_sub = 0;
                ti = proto_tree_add_item(objtree, hf_blf_cont_payload, sub_tvb, 0, offset_orig + obj_length - offset, ENC_NA);
                subtree = proto_item_add_subtree(ti, ett_blf_logcontainer_payload);

                guint tmp = 42;
                while ((offset_sub + 16 <= offset_orig + obj_length - offset) && (tmp > 0)) {
                    tmp = dissect_blf_next_object(sub_tvb, pinfo, subtree, offset_sub);
                    offset_sub += tmp;
                }
            }
            break;
        default:
            if (offset - offset_orig < (gint)hdr_length) {
                proto_tree_add_item(subtree, hf_blf_lobj_hdr_remains, tvb, offset, hdr_length - (offset - offset_orig), ENC_NA);
                offset = offset_orig + hdr_length;
            }

            proto_tree_add_item(objtree, hf_blf_lobj_payload, tvb, offset, obj_length - hdr_length, ENC_NA);
            offset = offset_orig + obj_length;
            break;
    }

    return (gint)obj_length;
}

static int
dissect_blf_next_object(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset) {
    gint offset_orig = offset;

    while (tvb_captured_length_remaining(tvb, offset) >= 16) {
        if (tvb_memeql(tvb, offset, blf_lobj_magic, MAGIC_NUMBER_SIZE) != 0) {
            offset += 1;
        } else {
            int bytes_parsed = dissect_blf_lobj(tvb, pinfo, tree, offset);
            if (bytes_parsed <= 0) {
                return 0;
            } else {
                offset += bytes_parsed;
            }
        }
    }

    return offset - offset_orig;
}


static int
dissect_blf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    volatile gint    offset = 0;
    proto_tree      *blf_tree;
    proto_tree      *subtree;
    proto_item      *ti;
    guint            length;

    if (tvb_captured_length(tvb) < 8 || tvb_memeql(tvb, 0, blf_file_magic, MAGIC_NUMBER_SIZE) != 0) {
        /* does not start with LOGG, so this is not BLF it seems */
        return 0;
    }

    ti = proto_tree_add_item(tree, proto_blf, tvb, offset, -1, ENC_NA);
    blf_tree = proto_item_add_subtree(ti, ett_blf);
    length = tvb_get_guint32(tvb, 4, ENC_LITTLE_ENDIAN);

    ti = proto_tree_add_item(blf_tree, hf_blf_file_header, tvb, offset, length, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_blf_header);

    proto_tree_add_item(subtree, hf_blf_file_header_magic, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(subtree, hf_blf_file_header_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    dissect_blf_api_version(subtree, hf_blf_file_header_api, tvb, offset, 4);
    offset += 4;
    proto_tree_add_item(subtree, hf_blf_file_header_app, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(subtree, hf_blf_file_header_comp_level, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(subtree, hf_blf_file_header_app_major, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(subtree, hf_blf_file_header_app_minor, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(subtree, hf_blf_file_header_len_comp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(subtree, hf_blf_file_header_len_uncomp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(subtree, hf_blf_file_header_obj_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_blf_file_header_app_build, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    dissect_blf_header_date(subtree, hf_blf_file_header_start_date, tvb, offset, 16);
    offset += 16;
    dissect_blf_header_date(subtree, hf_blf_file_header_end_date, tvb, offset, 16);
    offset += 16;
    proto_tree_add_item(subtree, hf_blf_file_header_restore_point_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 8;

    offset += dissect_blf_next_object(tvb, pinfo, blf_tree, offset);

    return offset;
}

static gboolean
dissect_blf_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    return dissect_blf(tvb, pinfo, tree, NULL) > 0;
}

void
proto_register_file_blf(void) {
    static hf_register_info hf[] = {
        { &hf_blf_file_header,
            { "File Header", "blf.file_header", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_magic,
            { "Magic", "blf.file_header.magic", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_length,
            { "Header Length", "blf.file_header.length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_api,
            { "API Version", "blf.file_header.api", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_app,
            { "Application", "blf.file_header.application", FT_UINT8, BASE_DEC, VALS(application_names), 0x00, NULL, HFILL }},
        { &hf_blf_file_header_comp_level,
            { "Compression Level", "blf.file_header.compression_level", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_app_major,
            { "Application Major Version", "blf.file_header.application_major", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_app_minor,
            { "Application Minor Version", "blf.file_header.application_minor", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_len_comp,
            { "Length (compressed)", "blf.file_header.length_compressed", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_len_uncomp,
            { "Length (uncompressed)", "blf.file_header.length_uncompressed", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_obj_count,
            { "Object Count", "blf.file_header.object_count", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_app_build,
            { "Application Build", "blf.file_header.application_build", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_start_date,
            { "Start Date", "blf.file_header.start_date", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_end_date,
            { "End Date", "blf.file_header.end_date", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_file_header_restore_point_offset,
            { "Restore Point Offset", "blf.file_header.restore_point_offset", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }},

        { &hf_blf_lobj,
            { "Object", "blf.object", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_lobj_hdr,
            { "Object Header", "blf.object.header", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_lobj_magic,
            { "Magic", "blf.object.header.magic", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_lobj_hdr_len,
            { "Header Length", "blf.object.header.header_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_lobj_hdr_type,
            { "Header Type", "blf.object.header.header_type", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_lobj_obj_len,
            { "Object Length", "blf.object.header.object_length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_lobj_obj_type,
            { "Object Type", "blf.object.header.object_type", FT_UINT32, BASE_DEC, VALS(blf_object_names), 0x00, NULL, HFILL }},
        { &hf_blf_lobj_hdr_remains,
            { "Header unparsed", "blf.object.header.unparsed", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_lobj_payload,
            { "Payload", "blf.object.payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},

        { &hf_blf_cont_comp_method,
            { "Compression Method", "blf.object.logcontainer.compression_method", FT_UINT16, BASE_HEX, VALS(blf_compression_names), 0x00, NULL, HFILL }},
        { &hf_blf_cont_res1,
            { "Reserved", "blf.object.logcontainer.res1", FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_cont_res2,
            { "Reserved", "blf.object.logcontainer.res2", FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_cont_uncomp_size,
            { "Uncompressed Length", "blf.object.logcontainer.uncompressed_length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_cont_res4,
            { "Reserved", "blf.object.logcontainer.res4", FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_cont_payload,
            { "Payload", "blf.object.logcontainer.payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},

    };

    static gint *ett[] = {
        &ett_blf,
        &ett_blf_header,
        &ett_blf_obj,
        &ett_blf_obj_header,
        &ett_blf_logcontainer_payload,
    };

    proto_blf = proto_register_protocol("BLF File Format", "File-BLF", "file-blf");
    proto_register_field_array(proto_blf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("file-blf", dissect_blf, proto_blf);
}

void
proto_reg_handoff_file_blf(void) {
    heur_dissector_add("wtap_file", dissect_blf_heur, "BLF File", "blf_wtap", proto_blf, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
