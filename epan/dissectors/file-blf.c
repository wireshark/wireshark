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

#include <wiretap/blf.h>

static int proto_blf;
static int proto_blf_ethernetstatus_obj;
static int proto_blf_ethernetphystate_obj;

static dissector_handle_t xml_handle;

static int hf_blf_file_header;
static int hf_blf_file_header_magic;
static int hf_blf_file_header_length;
static int hf_blf_file_header_api;
static int hf_blf_file_header_app;
static int hf_blf_file_header_comp_level;
static int hf_blf_file_header_app_major;
static int hf_blf_file_header_app_minor;
static int hf_blf_file_header_len_comp;
static int hf_blf_file_header_len_uncomp;
static int hf_blf_file_header_obj_count;
static int hf_blf_file_header_app_build;
static int hf_blf_file_header_start_date;
static int hf_blf_file_header_end_date;
static int hf_blf_file_header_restore_point_offset;

static int hf_blf_lobj;
static int hf_blf_lobj_hdr;
static int hf_blf_lobj_magic;
static int hf_blf_lobj_hdr_len;
static int hf_blf_lobj_hdr_type;
static int hf_blf_lobj_obj_len;
static int hf_blf_lobj_obj_type;
static int hf_blf_lobj_hdr_remains;
static int hf_blf_lobj_payload;

static int hf_blf_cont_comp_method;
static int hf_blf_cont_res1;
static int hf_blf_cont_res2;
static int hf_blf_cont_uncomp_size;
static int hf_blf_cont_res4;
static int hf_blf_cont_payload;

static int hf_blf_app_text_source;
static int hf_blf_app_text_reservedapptext1;
static int hf_blf_app_text_textlength;
static int hf_blf_app_text_reservedapptext2;
static int hf_blf_app_text_data_version;
static int hf_blf_app_text_channelno;
static int hf_blf_app_text_busstype;
static int hf_blf_app_text_can_fd_channel;
static int hf_blf_app_text_metadata_remaining_length;
static int hf_blf_app_text_metadata_type;
static int hf_blf_app_text_traceline_source;
static int hf_blf_app_text_traceline_display_in_tracewindow;
static int hf_blf_app_text_traceline_ascii_conversion_wo_comment_indicator_timestamp;
static int hf_blf_app_text_text;
static int hf_blf_trigg_cond_state;
static int hf_blf_trigg_cond_triggerblocknamelength;
static int hf_blf_trigg_cond_triggerconditionlength;
static int hf_blf_trigg_cond_triggerblockname;
static int hf_blf_trigg_cond_triggercondition;
static int hf_blf_sys_var_type;
static int hf_blf_sys_var_rep;
static int hf_blf_sys_var_reservedsystemvariable1;
static int hf_blf_sys_var_namelength;
static int hf_blf_sys_var_datalength;
static int hf_blf_sys_var_reservedsystemvariable2;
static int hf_blf_sys_var_name;
static int hf_blf_sys_var_data;
static int hf_blf_eth_status_channel;
static int hf_blf_eth_status_flags1_b0;
static int hf_blf_eth_status_flags1_b1;
static int hf_blf_eth_status_flags1_b2;
static int hf_blf_eth_status_flags1_b3;
static int hf_blf_eth_status_flags1_b4;
static int hf_blf_eth_status_flags1_b5;
static int hf_blf_eth_status_flags1_b6;
static int hf_blf_eth_status_flags1_b7;
static int hf_blf_eth_status_flags1_b8;
static int hf_blf_eth_status_flags1_b9;

static int hf_blf_eth_status_linkstatus;
static int hf_blf_eth_status_ethernetphy;
static int hf_blf_eth_status_duplex;
static int hf_blf_eth_status_mdi;
static int hf_blf_eth_status_connector;
static int hf_blf_eth_status_clockmode;
static int hf_blf_eth_status_pairs;
static int hf_blf_eth_status_hardwarechannel;
static int hf_blf_eth_status_bitrate;
static int hf_blf_eth_status_linkupduration;
static int hf_blf_eth_frame_ext_structlength;
static int hf_blf_eth_frame_ext_flags;
static int hf_blf_eth_frame_ext_channel;
static int hf_blf_eth_frame_ext_hardwarechannel;
static int hf_blf_eth_frame_ext_frameduration;
static int hf_blf_eth_frame_ext_framechecksum;
static int hf_blf_eth_frame_ext_dir;
static int hf_blf_eth_frame_ext_framelength;
static int hf_blf_eth_frame_ext_framehandle;
static int hf_blf_eth_frame_ext_reservedethernetframeex;

static int hf_blf_eth_phystate_channel;
static int hf_blf_eth_phy_state_flags1_b0;
static int hf_blf_eth_phy_state_flags1_b1;
static int hf_blf_eth_phy_state_flags1_b2;
static int hf_blf_eth_phy_state_phystate;
static int hf_blf_eth_phy_state_eventstate;
static int hf_blf_eth_phy_state_hardwarechannel;
static int hf_blf_eth_phy_state_res1;

static expert_field ei_blf_file_header_length_too_short;
static expert_field ei_blf_object_header_length_too_short;
static expert_field ei_blf_object_length_less_than_header_length;

static int ett_blf;
static int ett_blf_header;
static int ett_blf_obj;
static int ett_blf_obj_header;
static int ett_blf_logcontainer_payload;
static int ett_blf_app_text_payload;

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
    { BLF_OBJTYPE_FLEXRAY_STATUS2,                  "FlexRay Status 2" },
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
    { BLF_OBJTYPE_DISTRIBUTED_OBJECT_CHANGE,        "Distributed Object Change" },
    { BLF_OBJTYPE_ETHERNET_PHY_STATE,               "Ethernet PHY State" },
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

static const value_string blf_app_text_source_vals[] = {
    { 0,     "Measurement comment" },
    { 1,     "Database channel information" },
    { 2,     "Meta data" },
    { 3,     "Attachment" },
    { 4,     "Trace line" },
    { 0, NULL }
};

static const value_string blf_trigger_cond_state_vals[] = {
    { 0,     "Unknown" },
    { 1,     "Start" },
    { 2,     "Stop" },
    { 3,     "StartStop"},
    { 0, NULL }
};

static const value_string blf_sys_var_type_vals[] = {
    { 1,     "Double" },
    { 2,     "Long" },
    { 3,     "String"},
    { 4,     "DoubleArray"},
    { 5,     "LongArray"},
    { 6,     "LongLong"},
    { 7,     "ByteArray"},
    { 0, NULL }
};

static const value_string blf_eth_status_linkstatus_vals[] = {
    { 0,     "UnknownLinkStatus" },
    { 1,     "LinkDown" },
    { 2,     "LinkUp"},
    { 3,     "Negotiate"},
    { 4,     "LinkError"},
    { 0, NULL }
};

static const value_string blf_eth_status_ethernetphy_vals[] = {
    { 0,     "UnknownEthernetPhy" },
    { 1,     "Ieee802_3" },
    { 2,     "BroadR_Reach"},
    { 0, NULL }
};

static const value_string blf_eth_status_duplex_vals[] = {
    { 0,     "UnknownDuplex" },
    { 1,     "HalfDuplex" },
    { 2,     "FullDuplex"},
    { 0, NULL }
};

static const value_string blf_eth_status_mdi_vals[] = {
    { 0,     "UnknownMDI" },
    { 1,     "Direct" },
    { 2,     "Crossover"},
    { 0, NULL }
};

static const value_string blf_eth_status_connector_vals[] = {
    { 0,     "UnknownConnector" },
    { 1,     "RJ45" },
    { 2,     "D-sub"},
    { 0, NULL }
};

static const value_string blf_eth_status_clockmode_vals[] = {
    { 0,     "UnknownClockMode" },
    { 1,     "Master" },
    { 2,     "Slave"},
    { 0, NULL }
};

static const value_string blf_eth_status_pairs_vals[] = {
    { 0,     "UnknownPairs" },
    { 1,     "1" },
    { 2,     "2"},
    { 3,     "4"},
    { 0, NULL }
};

static const value_string blf_bustype_vals[] = {
    { BLF_BUSTYPE_CAN,      "CAN" },
    { BLF_BUSTYPE_LIN,      "LIN" },
    { BLF_BUSTYPE_MOST,     "MOST"},
    { BLF_BUSTYPE_FLEXRAY,  "FLEXRAY"},
    { BLF_BUSTYPE_J1708,    "J1708"},
    { BLF_BUSTYPE_ETHERNET, "ETHERNET"},
    { BLF_BUSTYPE_WLAN,     "WLAN"},
    { BLF_BUSTYPE_AFDX,     "AFDX"},
    { 0, NULL }
};

static const value_string blf_app_text_metadata_type_vals[] = {
    { 1,     "General" },
    { 2,     "Channels" },
    { 3,     "Identity" },
    { 0, NULL }
};

static const value_string hf_blf_app_text_traceline_source_vals[] = {
    { 0,     "Write to log" },
    { 1,     "Timer" },
    { 2,     "Write to X" },
    { 3,     "Node layer" },
    { 4,     "CAPL on board" },
    { 0, NULL }
};

static const value_string blf_eth_phystate_phystate_vals[] = {
    { 0,     "Invalid" },
    { 1,     "Normal" },
    { 2,     "Sleep"},
    { 3,     "PowerOff"},
    { 4,     "SleepRequest"},
    { 0, NULL }
};

static const value_string blf_eth_phystate_eventstate_vals[] = {
    { 0,     "Invalid" },
    { 1,     "SleepReceived" },
    { 2,     "SleepSent"},
    { 3,     "SleepAbort"},
    { 4,     "SleepAckReceived"},
    { 8,     "WakeUpReceived"},
    { 9,     "WakeUpSent"},
    { 17,    "PowerOff"},
    { 18,    "PowerOn"},
    { 25,    "Activated"},
    { 0, NULL }
};

#define BLF_BUSTYPE_CAN 1
#define BLF_BUSTYPE_LIN 5
#define BLF_BUSTYPE_MOST 6
#define BLF_BUSTYPE_FLEXRAY 7
#define BLF_BUSTYPE_J1708 9
#define BLF_BUSTYPE_ETHERNET 11
#define BLF_BUSTYPE_WLAN 13
#define BLF_BUSTYPE_AFDX 14

void proto_register_file_blf(void);
void proto_reg_handoff_file_blf(void);
static int dissect_blf_next_object(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

#define MAGIC_NUMBER_SIZE 4
static const uint8_t blf_file_magic[MAGIC_NUMBER_SIZE] = { 'L', 'O', 'G', 'G' };
static const uint8_t blf_lobj_magic[MAGIC_NUMBER_SIZE] = { 'L', 'O', 'B', 'J' };


static proto_item *
dissect_blf_header_date(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, int length) {
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

    uint16_t year        = tvb_get_uint16(tvb, offset +  0, ENC_LITTLE_ENDIAN);
    uint16_t month       = tvb_get_uint16(tvb, offset +  2, ENC_LITTLE_ENDIAN);
    uint16_t day_of_week = tvb_get_uint16(tvb, offset +  4, ENC_LITTLE_ENDIAN);
    uint16_t day         = tvb_get_uint16(tvb, offset +  6, ENC_LITTLE_ENDIAN);
    uint16_t hour        = tvb_get_uint16(tvb, offset +  8, ENC_LITTLE_ENDIAN);
    uint16_t minute      = tvb_get_uint16(tvb, offset + 10, ENC_LITTLE_ENDIAN);
    uint16_t sec         = tvb_get_uint16(tvb, offset + 12, ENC_LITTLE_ENDIAN);
    uint16_t ms          = tvb_get_uint16(tvb, offset + 14, ENC_LITTLE_ENDIAN);

    header_field_info *hfinfo = proto_registrar_get_nth(hf);

    return proto_tree_add_bytes_format(tree, hf, tvb, offset, length, NULL,
                                       "%s: %s %d-%02d-%02d %02d:%02d:%02d.%03d",
                                       hfinfo->name,
                                       val_to_str(day_of_week, weekday_names, "%d"),
                                       year, month, day, hour, minute, sec, ms);
}

static proto_item *
dissect_blf_api_version(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, int length) {
    uint8_t major = tvb_get_uint8(tvb, offset + 0);
    uint8_t minor = tvb_get_uint8(tvb, offset + 1);
    uint8_t build = tvb_get_uint8(tvb, offset + 2);
    uint8_t patch = tvb_get_uint8(tvb, offset + 3);

    header_field_info *hfinfo = proto_registrar_get_nth(hf);

    return proto_tree_add_bytes_format(tree, hf, tvb, offset, length, NULL, "%s: %d.%d.%d.%d",
                                       hfinfo->name, major, minor, build, patch);
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_blf_lobj(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset_orig) {
    proto_item    *ti_root = NULL;
    proto_item    *ti = NULL;
    proto_item    *ti_lobj_hdr;
    proto_tree    *objtree = NULL;
    proto_tree    *subtree = NULL;
    volatile int   offset = offset_orig;
    tvbuff_t      *sub_tvb;

    uint32_t       hdr_length;
    uint32_t       obj_length;
    unsigned       obj_type;
    uint32_t       comp_method;

    /* this should never happen since we should only be called with at least 16 Bytes present */
    if (tvb_captured_length_remaining(tvb, offset_orig) < 16) {
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti_root = proto_tree_add_item(tree, hf_blf_lobj, tvb, offset, -1, ENC_NA);
    objtree = proto_item_add_subtree(ti_root, ett_blf_obj);

    ti_lobj_hdr = proto_tree_add_item(objtree, hf_blf_lobj_hdr, tvb, offset, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti_lobj_hdr, ett_blf_obj);

    proto_tree_add_item(subtree, hf_blf_lobj_magic, tvb, offset, 4, ENC_NA);
    offset += 4;
    ti = proto_tree_add_item_ret_uint(subtree, hf_blf_lobj_hdr_len, tvb, offset, 2, ENC_LITTLE_ENDIAN, &hdr_length);
    if (hdr_length < sizeof (struct blf_blockheader)) {
        expert_add_info(pinfo, ti, &ei_blf_object_header_length_too_short);
    }
    offset += 2;
    proto_tree_add_item(subtree, hf_blf_lobj_hdr_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    ti = proto_tree_add_item_ret_uint(subtree, hf_blf_lobj_obj_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &obj_length);
    if (obj_length < hdr_length) {
        expert_add_info(pinfo, ti, &ei_blf_object_length_less_than_header_length);
    }
    offset += 4;
    proto_tree_add_item_ret_uint(subtree, hf_blf_lobj_obj_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &obj_type);
    offset += 4;
    proto_item_set_end(ti_lobj_hdr, tvb, offset);

    /* check if the whole object is present or if it was truncated */
    if (tvb_captured_length_remaining(tvb, offset_orig) < (int)obj_length) {
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
                sub_tvb = tvb_new_subset_length(tvb, offset, offset_orig + obj_length - offset);
            } else {
                sub_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, offset_orig + obj_length - offset);
                if (sub_tvb) {
                    add_new_data_source(pinfo, sub_tvb, "Decompressed Data");
                }
            }

            /* TODO: actually the objects might overlap containers, which we do not consider here... */
            if (sub_tvb) {
                unsigned offset_sub = 0;
                ti = proto_tree_add_item(objtree, hf_blf_cont_payload, sub_tvb, 0, offset_orig + obj_length - offset, ENC_NA);
                subtree = proto_item_add_subtree(ti, ett_blf_logcontainer_payload);

                unsigned tmp = 42;
                while ((offset_sub + 16 <= offset_orig + obj_length - offset) && (tmp > 0)) {
                    tmp = dissect_blf_next_object(sub_tvb, pinfo, subtree, offset_sub);
                    offset_sub += tmp;
                }
            }
            break;
        case BLF_OBJTYPE_APP_TEXT:
        {
            unsigned source;
            unsigned textlength;
            if (offset - offset_orig < (int)hdr_length) {
                proto_tree_add_item(subtree, hf_blf_lobj_hdr_remains, tvb, offset, hdr_length - (offset - offset_orig), ENC_NA);
                offset = offset_orig + hdr_length;
            }

            ti = proto_tree_add_item(objtree, hf_blf_lobj_payload, tvb, offset, obj_length - hdr_length, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_blf_app_text_payload);

            proto_tree_add_item_ret_uint(subtree, hf_blf_app_text_source, tvb, offset, 4, ENC_LITTLE_ENDIAN, &source);
            offset += 4;

            /*uint32_t reservedAppText1 {};*/
            switch (source) {
            case BLF_APPTEXT_CHANNEL:
                /* 1: Database channel information
                 * - reserved contains channel information. The following
                 * - table show how the 4 bytes are used:
                 *   - Bit 0-7: Version of the data
                 *   - Bit 8-15: Channel number
                 *   - Bit 15-23: Bus type of the channel. One of the
                 *     following values:
                 *     - 1: BL_BUSTYPE_CAN
                 *     - 5: BL_BUSTYPE_LIN
                 *     - 6: BL_BUSTYPE_MOST
                 *     - 7: BL_BUSTYPE_FLEXRAY
                 *     - 9: BL_BUSTYPE_J1708
                 *     - 10: BL_BUSTYPE_ETHERNET
                 *     - 13: BL_BUSTYPE_WLAN
                 *     - 14: BL_BUSTYPE_AFDX
                 *   - Bit 24: Flag, that determines, if channel is a CAN-
                 *     FD channel
                 *   - Bit 25-31: Unused at the moment
                 * - text contains database information for the specific
                 *   channel. Each database is defined by the database path and
                 *   the cluster name (if available). The single databases and the
                 *   cluster name are separated by a semicolon. Example:
                 *   \<Path1\>;\<ClusterName1\>;\<Path2\>;\<ClusterName2\>;...
                 *   If for a database there's no cluster name available, an
                 *   empty string is written as cluster name.
                 */
                proto_tree_add_item(subtree, hf_blf_app_text_data_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(subtree, hf_blf_app_text_channelno, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(subtree, hf_blf_app_text_busstype, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(subtree, hf_blf_app_text_can_fd_channel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;
            case BLF_APPTEXT_METADATA:
                proto_tree_add_item(subtree, hf_blf_app_text_metadata_remaining_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(subtree, hf_blf_app_text_metadata_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;
            case BLF_APPTEXT_TRACELINE:
                proto_tree_add_item(subtree, hf_blf_app_text_traceline_source, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(subtree, hf_blf_app_text_traceline_display_in_tracewindow, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(subtree, hf_blf_app_text_traceline_ascii_conversion_wo_comment_indicator_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;
            default:
                proto_tree_add_item(subtree, hf_blf_app_text_reservedapptext1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;
            }
            offset += 4;
            /*uint32_t textLength {};*/
            proto_tree_add_item_ret_uint(subtree, hf_blf_app_text_textlength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &textlength);
            offset += 4;
            /*uint32_t reservedAppText2 {};*/
            proto_tree_add_item(subtree, hf_blf_app_text_reservedapptext2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            /* If there is less than 38 characters this is not XML
             * <?xml version="1.0" encoding="UTF-8"?>
             */
            if ((textlength > 37) && (tvb_strncaseeql(tvb, offset, "<?xml", 5) == 0) &&( xml_handle)) {
                tvbuff_t* new_tvb = tvb_new_subset_length(tvb, offset, textlength);
                call_dissector(xml_handle, new_tvb, pinfo, subtree);
            } else {
                proto_tree_add_item(subtree, hf_blf_app_text_text, tvb, offset, textlength, ENC_UTF_8|ENC_NA);
            }
        }
            break;
        case BLF_OBJTYPE_SYS_VARIABLE:
        {
            uint32_t namelength;
            uint32_t datalength;

            if (offset - offset_orig < (int)hdr_length) {
                proto_tree_add_item(subtree, hf_blf_lobj_hdr_remains, tvb, offset, hdr_length - (offset - offset_orig), ENC_NA);
                offset = offset_orig + hdr_length;
            }

            ti = proto_tree_add_item(objtree, hf_blf_lobj_payload, tvb, offset, obj_length - hdr_length, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_blf_app_text_payload);

            /* uint32_t type {}; */
            proto_tree_add_item(subtree, hf_blf_sys_var_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            /* uint32_t representation {}; */
            proto_tree_add_item(subtree, hf_blf_sys_var_rep, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            /* uint64_t reservedSystemVariable1 {}; */
            proto_tree_add_item(subtree, hf_blf_sys_var_reservedsystemvariable1, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            /* uint32_t nameLength {}; */
            proto_tree_add_item_ret_uint(subtree, hf_blf_sys_var_namelength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &namelength);
            offset += 4;
            /* uint32_t dataLength {}; */
            proto_tree_add_item_ret_uint(subtree, hf_blf_sys_var_datalength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &datalength);
            offset += 4;
            /* uint64_t reservedSystemVariable2 {}; */
            proto_tree_add_item(subtree, hf_blf_sys_var_reservedsystemvariable2, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(subtree, hf_blf_sys_var_name, tvb, offset, namelength, ENC_UTF_8 | ENC_NA);
            offset += namelength;
            proto_tree_add_item(subtree, hf_blf_sys_var_data, tvb, offset, datalength, ENC_NA);
            offset += datalength;
        }
        break;
        case BLF_OBJTYPE_ETHERNET_STATUS:
        {
            static int* const flags1[] = {
                &hf_blf_eth_status_flags1_b9,
                &hf_blf_eth_status_flags1_b8,
                &hf_blf_eth_status_flags1_b7,
                &hf_blf_eth_status_flags1_b6,
                &hf_blf_eth_status_flags1_b5,
                &hf_blf_eth_status_flags1_b4,
                &hf_blf_eth_status_flags1_b3,
                &hf_blf_eth_status_flags1_b2,
                &hf_blf_eth_status_flags1_b1,
                &hf_blf_eth_status_flags1_b0,
                NULL
            };
            if (offset - offset_orig < (int)hdr_length) {
                proto_tree_add_item(subtree, hf_blf_lobj_hdr_remains, tvb, offset, hdr_length - (offset - offset_orig), ENC_NA);
                offset = offset_orig + hdr_length;
            }

            ti = proto_tree_add_item(objtree, hf_blf_lobj_payload, tvb, offset, obj_length - hdr_length, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_blf_app_text_payload);

            /* uint16_t channel {}; */
            proto_tree_add_item(subtree, hf_blf_eth_status_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* uint16_t flags; */
            proto_tree_add_bitmask_list(subtree, tvb, offset, 2, flags1, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* uint8_t linkStatus {}; */
            proto_tree_add_item(subtree, hf_blf_eth_status_linkstatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* uint8_t ethernetPhy {};*/
            proto_tree_add_item(subtree, hf_blf_eth_status_ethernetphy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* uint8_t duplex {}; */
            proto_tree_add_item(subtree, hf_blf_eth_status_duplex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* uint8_t mdi {}; */
            proto_tree_add_item(subtree, hf_blf_eth_status_mdi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* uint8_t connector {};*/
            proto_tree_add_item(subtree, hf_blf_eth_status_connector, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* uint8_t clockMode {}; */
            proto_tree_add_item(subtree, hf_blf_eth_status_clockmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* uint8_t pairs {}; */
            proto_tree_add_item(subtree, hf_blf_eth_status_pairs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* uint8_t hardwareChannel {};*/
            proto_tree_add_item(subtree, hf_blf_eth_status_hardwarechannel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* uint32_t bitrate {}; */
            proto_tree_add_item(subtree, hf_blf_eth_status_bitrate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            if (offset_orig + obj_length - offset >= 8) {
                proto_tree_add_item(subtree, hf_blf_eth_status_linkupduration, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            }
        }
            break;
        case BLF_OBJTYPE_ETHERNET_FRAME_EX:
        {
            if (offset - offset_orig < (int)hdr_length) {
                proto_tree_add_item(subtree, hf_blf_lobj_hdr_remains, tvb, offset, hdr_length - (offset - offset_orig), ENC_NA);
                offset = offset_orig + hdr_length;
            }

            ti = proto_tree_add_item(objtree, hf_blf_lobj_payload, tvb, offset, obj_length - hdr_length, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_blf_app_text_payload);

            /* uint16_t structLength {}; */
            proto_tree_add_item(subtree, hf_blf_eth_frame_ext_structlength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* uint16_t flags {}; */
            proto_tree_add_item(subtree, hf_blf_eth_frame_ext_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* uint16_t channel {}; */
            proto_tree_add_item(subtree, hf_blf_eth_frame_ext_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* uint16_t hardwareChannel {}; */
            proto_tree_add_item(subtree, hf_blf_eth_frame_ext_hardwarechannel, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* uint64_t frameDuration {}; */
            proto_tree_add_item(subtree, hf_blf_eth_frame_ext_frameduration, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            /* uint32_t frameChecksum {}; */
            proto_tree_add_item(subtree, hf_blf_eth_frame_ext_framechecksum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            /* uint16_t dir {}; */
            proto_tree_add_item(subtree, hf_blf_eth_frame_ext_dir, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* uint16_t frameLength {}; */
            proto_tree_add_item(subtree, hf_blf_eth_frame_ext_framelength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* uint32_t frameHandle {}; */
            proto_tree_add_item(subtree, hf_blf_eth_frame_ext_framehandle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            /* uint32_t reservedEthernetFrameEx {}; */
            proto_tree_add_item(subtree, hf_blf_eth_frame_ext_reservedethernetframeex, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;
        case BLF_OBJTYPE_TRIGGER_CONDITION:
        {
            uint32_t triggerblocknamelength;
            uint32_t triggerconditionlength;

            if (offset - offset_orig < (int)hdr_length) {
                proto_tree_add_item(subtree, hf_blf_lobj_hdr_remains, tvb, offset, hdr_length - (offset - offset_orig), ENC_NA);
                offset = offset_orig + hdr_length;
            }

            ti = proto_tree_add_item(objtree, hf_blf_lobj_payload, tvb, offset, obj_length - hdr_length, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_blf_app_text_payload);

            /* uint32_t state {}; */
            proto_tree_add_item(subtree, hf_blf_trigg_cond_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            /* uint32_t triggerBlockNameLength {}; */
            proto_tree_add_item_ret_uint(subtree, hf_blf_trigg_cond_triggerblocknamelength, tvb, offset, 4, ENC_LITTLE_ENDIAN,&triggerblocknamelength);
            offset += 4;
            /* uint32_t triggerConditionLength {};*/
            proto_tree_add_item_ret_uint(subtree, hf_blf_trigg_cond_triggerconditionlength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &triggerconditionlength);
            offset += 4;
            /* std::string triggerBlockName {};*/
            proto_tree_add_item(subtree, hf_blf_trigg_cond_triggerblockname, tvb, offset, triggerblocknamelength, ENC_UTF_8 | ENC_NA);
            offset += triggerblocknamelength;
            /* std::string triggerCondition {};*/
            proto_tree_add_item(subtree, hf_blf_trigg_cond_triggercondition, tvb, offset, triggerconditionlength, ENC_UTF_8 | ENC_NA);
            offset += triggerconditionlength;
        }
        break;
        case BLF_OBJTYPE_ETHERNET_PHY_STATE:
        {
            static int* const flags1[] = {
                &hf_blf_eth_phy_state_flags1_b2,
                &hf_blf_eth_phy_state_flags1_b1,
                &hf_blf_eth_phy_state_flags1_b0,
                NULL
            };
            if (offset - offset_orig < (int)hdr_length) {
                proto_tree_add_item(subtree, hf_blf_lobj_hdr_remains, tvb, offset, hdr_length - (offset - offset_orig), ENC_NA);
                offset = offset_orig + hdr_length;
            }

            ti = proto_tree_add_item(objtree, hf_blf_lobj_payload, tvb, offset, obj_length - hdr_length, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_blf_app_text_payload);

            /* uint16_t channel {}; */
            proto_tree_add_item(subtree, hf_blf_eth_phystate_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* uint16_t flags; */
            proto_tree_add_bitmask_list(subtree, tvb, offset, 2, flags1, ENC_BIG_ENDIAN);
            offset += 2;
            /* uint8_t phyState {}; */
            proto_tree_add_item(subtree, hf_blf_eth_phy_state_phystate, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            /* uint8_t eventState {}; */
            proto_tree_add_item(subtree, hf_blf_eth_phy_state_eventstate, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            /* uint8_t hardwareChannel {}; */
            proto_tree_add_item(subtree, hf_blf_eth_phy_state_hardwarechannel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            /* uint8_t res1 {}; */
            proto_tree_add_item(subtree, hf_blf_eth_phy_state_res1, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
        break;
        default:
            if (offset - offset_orig < (int)hdr_length) {
                proto_tree_add_item(subtree, hf_blf_lobj_hdr_remains, tvb, offset, hdr_length - (offset - offset_orig), ENC_NA);
                offset = offset_orig + hdr_length;
            }

            proto_tree_add_item(objtree, hf_blf_lobj_payload, tvb, offset, obj_length - hdr_length, ENC_NA);
            offset = offset_orig + obj_length;
            break;
    }

    return (int)obj_length;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_blf_next_object(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset) {
    int offset_orig = offset;

    while (tvb_captured_length_remaining(tvb, offset) >= 16) {
        if (tvb_memeql(tvb, offset, blf_lobj_magic, MAGIC_NUMBER_SIZE) != 0) {
            offset += 1;
        } else {
            increment_dissection_depth(pinfo);
            int bytes_parsed = dissect_blf_lobj(tvb, pinfo, tree, offset);
            decrement_dissection_depth(pinfo);
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
    volatile int     offset = 0;
    proto_tree      *blf_tree;
    uint32_t         header_length;
    proto_tree      *subtree;
    proto_item      *ti;
    unsigned         length;

    if (tvb_captured_length(tvb) < 8 || tvb_memeql(tvb, 0, blf_file_magic, MAGIC_NUMBER_SIZE) != 0) {
        /* does not start with LOGG, so this is not BLF it seems */
        return 0;
    }

    ti = proto_tree_add_item(tree, proto_blf, tvb, offset, -1, ENC_NA);
    blf_tree = proto_item_add_subtree(ti, ett_blf);
    length = tvb_get_uint32(tvb, 4, ENC_LITTLE_ENDIAN);

    ti = proto_tree_add_item(blf_tree, hf_blf_file_header, tvb, offset, length, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_blf_header);

    proto_tree_add_item(subtree, hf_blf_file_header_magic, tvb, offset, 4, ENC_NA);
    offset += 4;
    ti = proto_tree_add_item_ret_uint(subtree, hf_blf_file_header_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &header_length);
    if (header_length < sizeof (struct blf_fileheader)) {
        expert_add_info(pinfo, ti, &ei_blf_file_header_length_too_short);
    }
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

static bool
dissect_blf_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_blf(tvb, pinfo, tree, data) > 0;
}

static int
dissect_blf_ethernetstatus_obj(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {
    proto_item *ti;
    proto_tree* blf_tree;
    int offset = 0;

    static int* const flags1[] = {
        &hf_blf_eth_status_flags1_b9,
        &hf_blf_eth_status_flags1_b8,
        &hf_blf_eth_status_flags1_b7,
        &hf_blf_eth_status_flags1_b6,
        &hf_blf_eth_status_flags1_b5,
        &hf_blf_eth_status_flags1_b4,
        &hf_blf_eth_status_flags1_b3,
        &hf_blf_eth_status_flags1_b2,
        &hf_blf_eth_status_flags1_b1,
        &hf_blf_eth_status_flags1_b0,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLF Ethernet Status");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_blf_ethernetstatus_obj, tvb, offset, -1, ENC_NA);
    blf_tree = proto_item_add_subtree(ti, ett_blf);

    /* uint16_t channel {}; */
    uint32_t channel;
    proto_tree_add_item_ret_uint(blf_tree, hf_blf_eth_status_channel, tvb, offset, 2, ENC_BIG_ENDIAN, &channel);
    offset += 2;
    /* uint16_t flags; */
    uint16_t flags = tvb_get_ntohs(tvb, offset);
    proto_tree_add_bitmask_list(blf_tree, tvb, offset, 2, flags1, ENC_BIG_ENDIAN);
    offset += 2;

    /* uint8_t linkStatus {}; */
    uint32_t linkstatus;
    ti = proto_tree_add_item_ret_uint(blf_tree, hf_blf_eth_status_linkstatus, tvb, offset, 1, ENC_BIG_ENDIAN, &linkstatus);
    if ((flags & BLF_ETH_STATUS_LINKSTATUS) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint8_t ethernetPhy {};*/
    ti = proto_tree_add_item(blf_tree, hf_blf_eth_status_ethernetphy, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((flags & BLF_ETH_STATUS_ETHERNETPHY) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint8_t duplex {}; */
    ti = proto_tree_add_item(blf_tree, hf_blf_eth_status_duplex, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((flags & BLF_ETH_STATUS_DUPLEX) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint8_t mdi {}; */
    ti = proto_tree_add_item(blf_tree, hf_blf_eth_status_mdi, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((flags & BLF_ETH_STATUS_MDITYPE) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint8_t connector {};*/
    ti = proto_tree_add_item(blf_tree, hf_blf_eth_status_connector, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((flags & BLF_ETH_STATUS_CONNECTOR) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint8_t clockMode {}; */
    ti = proto_tree_add_item(blf_tree, hf_blf_eth_status_clockmode, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((flags & BLF_ETH_STATUS_CLOCKMODE) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint8_t pairs {}; */
    ti = proto_tree_add_item(blf_tree, hf_blf_eth_status_pairs, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((flags & BLF_ETH_STATUS_BRPAIR) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint8_t hardwareChannel {};*/
    uint32_t hardwarechannel;
    ti = proto_tree_add_item_ret_uint(blf_tree, hf_blf_eth_status_hardwarechannel, tvb, offset, 1, ENC_BIG_ENDIAN, &hardwarechannel);
    if ((flags & BLF_ETH_STATUS_HARDWARECHANNEL) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint32_t bitrate {}; */
    ti = proto_tree_add_item(blf_tree, hf_blf_eth_status_bitrate, tvb, offset, 4, ENC_BIG_ENDIAN);
    if ((flags & BLF_ETH_STATUS_BITRATE) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 4;

    if ((int)tvb_captured_length(tvb) >= offset + 8) {
        /* uint64_t linkUpDuration {}; */
        ti = proto_tree_add_item(blf_tree, hf_blf_eth_status_linkupduration, tvb, offset, 8, ENC_BIG_ENDIAN);
        if ((flags & BLF_ETH_STATUS_LINKUPDURATION) == 0) {
            proto_item_append_text(ti, " - Invalid");
        }
    }

    if ((flags & BLF_ETH_STATUS_LINKSTATUS) != 0) {
        if ((flags & BLF_ETH_STATUS_HARDWARECHANNEL) == 0) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "ETH-%u %s", channel, val_to_str_const(linkstatus, blf_eth_status_linkstatus_vals, "Unknown"));
        } else {
            col_add_fstr(pinfo->cinfo, COL_INFO, "ETH-%u-%u %s", channel, hardwarechannel, val_to_str_const(linkstatus, blf_eth_status_linkstatus_vals, "Unknown"));
        }
    }

    return tvb_reported_length(tvb);
}

static int
dissect_blf_ethernetphystate_obj(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {
    proto_item* ti;
    proto_tree* blf_tree;
    int offset = 0;

    static int* const flags1[] = {
        &hf_blf_eth_phy_state_flags1_b2,
        &hf_blf_eth_phy_state_flags1_b1,
        &hf_blf_eth_phy_state_flags1_b0,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLF Ethernet PHY State");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_blf_ethernetphystate_obj, tvb, offset, -1, ENC_NA);
    blf_tree = proto_item_add_subtree(ti, ett_blf);

    /* uint16_t channel {}; */
    uint32_t channel;
    proto_tree_add_item_ret_uint(blf_tree, hf_blf_eth_phystate_channel, tvb, offset, 2, ENC_BIG_ENDIAN, &channel);
    offset += 2;

    /* uint16_t flags; */
    uint16_t flags = tvb_get_ntohs(tvb, offset);
    proto_tree_add_bitmask_list(blf_tree, tvb, offset, 2, flags1, ENC_BIG_ENDIAN);
    offset += 2;

    /* uint8_t phyState {}; */
    uint32_t phyState;
    ti = proto_tree_add_item_ret_uint(blf_tree, hf_blf_eth_phy_state_phystate, tvb, offset, 1, ENC_BIG_ENDIAN, &phyState);
    if ((flags & BLF_PHY_STATE_PHYSTATE) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint8_t eventState {}; */
    uint32_t eventState;
    ti = proto_tree_add_item_ret_uint(blf_tree, hf_blf_eth_phy_state_eventstate, tvb, offset, 1, ENC_BIG_ENDIAN, &eventState);
    if ((flags & BLF_PHY_STATE_PHYEVENT) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint8_t hardwareChannel {}; */
    uint32_t hardwareChannel;
    ti = proto_tree_add_item_ret_uint(blf_tree, hf_blf_eth_phy_state_hardwarechannel, tvb, offset, 1, ENC_BIG_ENDIAN, &hardwareChannel);
    if ((flags & BLF_PHY_STATE_HARDWARECHANNEL) == 0) {
        proto_item_append_text(ti, " - Invalid");
    }
    offset += 1;

    /* uint8_t res1 {}; */
    proto_tree_add_item(blf_tree, hf_blf_eth_phy_state_res1, tvb, offset, 1, ENC_BIG_ENDIAN);

    if ((flags & (BLF_PHY_STATE_PHYSTATE | BLF_PHY_STATE_PHYEVENT)) != 0) {
        /* One of the two is valid */
        if ((flags & BLF_PHY_STATE_HARDWARECHANNEL) == 0) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "ETH-%u", channel);
        }
        else {
            col_add_fstr(pinfo->cinfo, COL_INFO, "ETH-%u-%u", channel, hardwareChannel);
        }
        if ((flags & BLF_PHY_STATE_PHYSTATE) != 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " - State: %s", val_to_str_const(phyState, blf_eth_phystate_phystate_vals, "Unknown"));
        }
        if ((flags & BLF_PHY_STATE_PHYEVENT) != 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " - Event: %s", val_to_str_const(eventState, blf_eth_phystate_eventstate_vals, "Unknown"));
        }
    }

    return tvb_reported_length(tvb);
}


void
proto_register_file_blf(void) {
    expert_module_t  *expert_blf;

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
        { &hf_blf_app_text_source,
            { "Source", "blf.object.app_text.source", FT_UINT32, BASE_DEC, VALS(blf_app_text_source_vals), 0x00, NULL, HFILL }},
        { &hf_blf_app_text_reservedapptext1,
            { "reservedAppText1", "blf.object.app_text.reservedapptext1", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_app_text_textlength,
            { "Text length", "blf.object.app_text.textlength", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_app_text_reservedapptext2,
            { "reservedAppText2", "blf.object.app_text.reservedapptext2", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_app_text_data_version,
            { "Version", "blf.object.app_text.version", FT_UINT32, BASE_DEC, NULL, 0x000000ff, NULL, HFILL }},
        { &hf_blf_app_text_channelno,
            { "Channel number", "blf.object.app_text.channelno", FT_UINT32, BASE_DEC, NULL, 0x0000ff00, NULL, HFILL }},
        { &hf_blf_app_text_busstype,
            { "Bus type", "blf.object.app_text.bustype", FT_UINT32, BASE_DEC, VALS(blf_bustype_vals), 0x00ff0000, NULL, HFILL}},
        { &hf_blf_app_text_can_fd_channel,
            { "CAN FD-Channel", "blf.object.app_text.can_fd_channel", FT_BOOLEAN, 32, NULL, 0x01000000, NULL, HFILL }},
        { &hf_blf_app_text_metadata_remaining_length,
            { "Remaining length", "blf.object.app_text.remaining_length", FT_UINT32, BASE_DEC, NULL, 0x00ffffff, NULL, HFILL }},
        { &hf_blf_app_text_metadata_type,
            { "Metadata type", "blf.object.app_text.metadata_type", FT_UINT32, BASE_DEC, VALS(blf_app_text_metadata_type_vals), 0xff000000, NULL, HFILL}},
        { &hf_blf_app_text_traceline_source,
            { "Metadata type", "blf.object.app_text.traceline_source", FT_UINT32, BASE_DEC, VALS(hf_blf_app_text_traceline_source_vals), 0x0000000f, NULL, HFILL}},
        { &hf_blf_app_text_traceline_display_in_tracewindow,
            { "Display in trace window", "blf.object.app_text.display_in_tracewindow", FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL}},
        { &hf_blf_app_text_traceline_ascii_conversion_wo_comment_indicator_timestamp,
            { "ASCII conversion should be done without comment indicator and timestamp", "blf.object.app_text.ascii_conversion_wo_comment_indicator_timestamp", FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL}},
        { &hf_blf_app_text_text,
            { "Text", "blf.object.app_text.text", FT_STRINGZPAD, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_trigg_cond_state,
            { "State", "blf.object.trigg_con.state", FT_UINT32, BASE_DEC, VALS(blf_trigger_cond_state_vals), 0x00, NULL, HFILL}},
        { &hf_blf_trigg_cond_triggerblocknamelength,
            { "Trigger blockname length", "blf.object.trigg_con.triggerblocknamelength", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_trigg_cond_triggerconditionlength,
            { "Trigger condition length", "blf.object.trigg_con.triggerconditionlength", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_trigg_cond_triggerblockname,
            { "Trigger blockname", "blf.object.trigg_con.triggerblockname", FT_STRINGZPAD, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_trigg_cond_triggercondition,
            { "Trigger condition", "blf.object.trigg_con.triggercondition", FT_STRINGZPAD, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_sys_var_type,
            { "Type", "blf.object.sys_var.type", FT_UINT32, BASE_DEC, VALS(blf_sys_var_type_vals), 0x00, NULL, HFILL}},
        { &hf_blf_sys_var_rep,
            { "Representation", "blf.object.sys_var.representation", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_sys_var_reservedsystemvariable1,
            { "Reserved systemvariable 1", "blf.object.sys_var.reservedsystemvariable1", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_sys_var_namelength,
            { "Name length", "blf.object.sys_var.namelength", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}},
        { &hf_blf_sys_var_datalength,
            { "Data length", "blf.object.sys_var.datalength", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}},
        { &hf_blf_sys_var_reservedsystemvariable2,
            { "Reserved systemvariable 2", "blf.object.sys_var.reservedsystemvariable2", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_blf_sys_var_name,
            { "Name", "blf.object.sys_var.name", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_blf_sys_var_data,
            { "Data", "blf.object.sys_var.data", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_blf_eth_status_channel,
            { "Channel", "blf.object.eth_status.channel", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_status_flags1_b0,
            { "LinkStatus",   "blf.object.eth_status.flags.b0", FT_BOOLEAN, 16, NULL, 0x0001,  NULL, HFILL } },
        { &hf_blf_eth_status_flags1_b1,
            { "Bitrate",   "blf.object.eth_status.flags.b1", FT_BOOLEAN, 16, NULL, 0x0002,  NULL, HFILL } },
        { &hf_blf_eth_status_flags1_b2,
            { "EthernetPhy",   "blf.object.eth_status.flags.b2", FT_BOOLEAN, 16, NULL, 0x0004,  NULL, HFILL } },
        { &hf_blf_eth_status_flags1_b3,
            { "Duplex",   "blf.object.eth_status.flags.b3", FT_BOOLEAN, 16, NULL, 0x0008,  NULL, HFILL } },
        { &hf_blf_eth_status_flags1_b4,
            { "MdiType",   "blf.object.eth_status.flags.b4", FT_BOOLEAN, 16, NULL, 0x0010,  NULL, HFILL } },
        { &hf_blf_eth_status_flags1_b5,
            { "Connector",   "blf.object.eth_status.flags.b5", FT_BOOLEAN, 16, NULL, 0x0020,  NULL, HFILL } },
        { &hf_blf_eth_status_flags1_b6,
            { "ClockMode",   "blf.object.eth_status.flags.b6", FT_BOOLEAN, 16, NULL, 0x0040,  NULL, HFILL } },
        { &hf_blf_eth_status_flags1_b7,
            { "BrPair",   "blf.object.eth_status.flags.b7", FT_BOOLEAN, 16, NULL, 0x0080,  NULL, HFILL } },
        { &hf_blf_eth_status_flags1_b8,
            { "HardwareChannel",   "blf.object.eth_status.flags.b8", FT_BOOLEAN, 16, NULL, 0x0100,  NULL, HFILL } },
        { &hf_blf_eth_status_flags1_b9,
            { "Link up duration",   "blf.object.eth_status.flags.b9", FT_BOOLEAN, 16, NULL, 0x0200,  NULL, HFILL } },
        { &hf_blf_eth_status_linkstatus,
            { "Link status", "blf.object.eth_status.linkstatus", FT_UINT8, BASE_DEC, VALS(blf_eth_status_linkstatus_vals), 0x00, NULL, HFILL}},
        { &hf_blf_eth_status_ethernetphy,
            { "Ethernet PHY", "blf.object.eth_status.ethernetphy", FT_UINT8, BASE_DEC, VALS(blf_eth_status_ethernetphy_vals), 0x00, NULL, HFILL}},
        { &hf_blf_eth_status_duplex,
            { "Duplex", "blf.object.eth_status.duplex", FT_UINT8, BASE_DEC, VALS(blf_eth_status_duplex_vals), 0x00, NULL, HFILL}},
        { &hf_blf_eth_status_mdi,
            { "MDI", "blf.object.eth_status.mdi", FT_UINT8, BASE_DEC, VALS(blf_eth_status_mdi_vals), 0x00, NULL, HFILL}},
        { &hf_blf_eth_status_connector,
            { "Connector", "blf.object.eth_status.connector", FT_UINT8, BASE_DEC, VALS(blf_eth_status_connector_vals), 0x00, NULL, HFILL}},
        { &hf_blf_eth_status_clockmode,
            { "Clock mode", "blf.object.eth_status.clockmode", FT_UINT8, BASE_DEC, VALS(blf_eth_status_clockmode_vals), 0x00, NULL, HFILL}},
        { &hf_blf_eth_status_pairs,
            { "Pairs", "blf.object.eth_status.pairs", FT_UINT8, BASE_DEC, VALS(blf_eth_status_pairs_vals), 0x00, NULL, HFILL}},
        { &hf_blf_eth_status_hardwarechannel,
            { "Hardware channel", "blf.object.eth_status.hardwarechannel", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_status_bitrate,
            { "Bitrate (kbps)", "blf.object.eth_status.bitrate", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_status_linkupduration,
            { "Link up duration (ns)", "blf.object.eth_status.linkupduration", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_frame_ext_structlength,
            { "Struct length", "blf.object.eth_frame_ext.structlength", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_frame_ext_flags,
            { "Flags", "blf.object.eth_frame_ext.flags", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_frame_ext_channel,
            { "Channel", "blf.object.eth_frame_ext.channel", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_frame_ext_hardwarechannel,
            { "Hardware Channel", "blf.object.eth_frame_ext.hardwarechannel", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_frame_ext_frameduration,
            { "Frame duration", "blf.object.eth_frame_ext.frameduration", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_frame_ext_framechecksum,
            { "Frame checksum", "blf.object.eth_frame_ext.framechecksum", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_frame_ext_dir,
            { "Dir", "blf.object.eth_frame_ext.dir", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_frame_ext_framelength,
            { "Frame length", "blf.object.eth_frame_ext.frame_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_frame_ext_framehandle,
            { "Frame handle", "blf.object.eth_frame_ext.frame_handle", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_frame_ext_reservedethernetframeex,
            { "Reserved ethernet frame ex", "blf.object.eth_frame_ext.reservedethernetframeex", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_phystate_channel,
            { "Channel", "blf.object.eth_phy_state.channel", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_phy_state_flags1_b0,
            { "PHYState", "blf.object.eth_phy_state.flags.b0", FT_BOOLEAN, 16, NULL, 0x0001,  NULL, HFILL } },
        { &hf_blf_eth_phy_state_flags1_b1,
            { "PHYEvent", "blf.object.eth_phy_state.flags.b1", FT_BOOLEAN, 16, NULL, 0x0002,  NULL, HFILL } },
        { &hf_blf_eth_phy_state_flags1_b2,
            { "HardwareChannel", "blf.object.eth_phy_state.flags.b2", FT_BOOLEAN, 16, NULL, 0x0004,  NULL, HFILL } },
        { &hf_blf_eth_phy_state_phystate,
            { "PHY state", "blf.object.eth_status.phystate", FT_UINT8, BASE_DEC, VALS(blf_eth_phystate_phystate_vals), 0x00, NULL, HFILL} },
        { &hf_blf_eth_phy_state_eventstate,
            { "Event state", "blf.object.eth_status.eventstate", FT_UINT8, BASE_DEC, VALS(blf_eth_phystate_eventstate_vals), 0x00, NULL, HFILL} },
        { &hf_blf_eth_phy_state_hardwarechannel,
            { "Hardware channel", "blf.object.eth_status.hardwarechannel", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL} },
        { &hf_blf_eth_phy_state_res1,
            { "Reserved", "blf.object.eth_status.res1", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL} },
    };

    static ei_register_info ei[] = {
        { &ei_blf_file_header_length_too_short,
            { "blf.file_header_length_too_short", PI_MALFORMED, PI_ERROR,
                "file header length is too short",
                EXPFILL }},
        { &ei_blf_object_header_length_too_short,
            { "blf.object_header_length_too_short", PI_MALFORMED, PI_ERROR,
                "object header length is too short",
                EXPFILL }},
        { &ei_blf_object_length_less_than_header_length,
            { "blf.object_length_less_than_header_length", PI_MALFORMED, PI_ERROR,
                "object length is less than the object header length",
                EXPFILL }},
    };

    static int *ett[] = {
        &ett_blf,
        &ett_blf_header,
        &ett_blf_obj,
        &ett_blf_obj_header,
        &ett_blf_logcontainer_payload,
        &ett_blf_app_text_payload,
    };

    proto_blf = proto_register_protocol("BLF File Format", "File-BLF", "file-blf");
    proto_blf_ethernetstatus_obj = proto_register_protocol("BLF Ethernet Status", "BLF-Ethernet-Status", "blf-ethernet-status");
    proto_blf_ethernetphystate_obj = proto_register_protocol("BLF Ethernet PHY State", "BLF-Ethernet-PHY-State", "blf-ethernet-phystate");
    expert_blf = expert_register_protocol(proto_blf);
    expert_register_field_array(expert_blf, ei, array_length(ei));

    proto_register_field_array(proto_blf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("file-blf", dissect_blf, proto_blf);
    register_dissector("blf-ethernetstatus-obj", dissect_blf_ethernetstatus_obj, proto_blf_ethernetstatus_obj);
    register_dissector("blf-ethernetphystate-obj", dissect_blf_ethernetphystate_obj, proto_blf_ethernetphystate_obj);
}

void
proto_reg_handoff_file_blf(void) {
    heur_dissector_add("wtap_file", dissect_blf_heur, "BLF File", "blf_wtap", proto_blf, HEURISTIC_ENABLE);
    xml_handle = find_dissector_add_dependency("xml", proto_blf);
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
