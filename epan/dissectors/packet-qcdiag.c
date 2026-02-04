/* packet-qcdiag.c
 * Dissector routines for Qualcomm DIAG packet handling
 *
 * Credits/Sources:
 * - Osmocom Wireshark qcdiag branch
 *   https://gitea.osmocom.org/osmocom/wireshark/src/branch/osmocom/qcdiag
 *
 * - SCAT: Signaling Collection and Analysis Tool
 *   https://github.com/fgsect/scat/
 *
 * - Android Tools MSM8996
 *   https://github.com/bcyj/android_tools_leeco_msm8996
 *
 * (C) 2016-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2025 by Oliver Smith <osmith@sysmocom.de>
 * (C) 2026 by Tamas Regos <regost@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Qualcomm Documents
 * ------------------
 * 80-V1294-1: CDMA Dual-Mode Subscriber Station Serial Data Interface Control Document
 * 80-V1294-7: Call Manager Subsystem Interface Control Document
 * 80-V4083-1: Serial Interface Control Document for UMTS
 * 80-V2708-1: Serial Interface Control Document for WCDMA
 * 80-V5295-1: Serial Interface Control Document for GSM and GPRS
 * 80-VP457-1: Long Term Evolution (LTE) Interface Control Document
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/to_str.h>
#include <epan/unit_strings.h>

#include "packet-gsmtap.h"
#include "packet-qcdiag.h"

void proto_register_qcdiag(void);
void proto_reg_handoff_qcdiag(void);

static dissector_handle_t qcdiag_handle;
static dissector_handle_t data_handle;
static dissector_handle_t text_lines_handle;

static dissector_table_t qcdiag_dissector_table;
static dissector_table_t qcdiag_subsys_dissector_table;

static int proto_qcdiag;

static int hf_qcdiag_logcode;
static int hf_qcdiag_len;
static int hf_qcdiag_ver;
static int hf_qcdiag_cmd;
static int hf_qcdiag_verno_comp_date;
static int hf_qcdiag_verno_comp_time;
static int hf_qcdiag_verno_rel_date;
static int hf_qcdiag_verno_rel_time;
static int hf_qcdiag_verno_ver_dir;
static int hf_qcdiag_verno_scm;
static int hf_qcdiag_verno_mob_cai_rev;
static int hf_qcdiag_verno_mob_model;
static int hf_qcdiag_verno_mob_firm_rev;
static int hf_qcdiag_verno_sci;
static int hf_qcdiag_verno_msm_ver;
static int hf_qcdiag_esn;
static int hf_qcdiag_bad_cmd;
static int hf_qcdiag_bad_parm;
static int hf_qcdiag_bad_len;
static int hf_qcdiag_bad_mode;
static int hf_qcdiag_diag_ver;
static int hf_qcdiag_ts;
static int hf_qcdiag_parm_set_id;
static int hf_qcdiag_parm_set_value;
static int hf_qcdiag_parm_set_time;
static int hf_qcdiag_mode_change;

static int hf_qcdiag_subsys_id;
static int hf_qcdiag_subsys_cmd_code;

static int hf_qcdiag_logcfg_res;
static int hf_qcdiag_logcfg_operation;
static int hf_qcdiag_logcfg_status;
static int hf_qcdiag_logcfg_equip_id;
static int hf_qcdiag_logcfg_last_item;
static int hf_qcdiag_log_on_demand_logcode;
static int hf_qcdiag_log_on_demand_status;
static int hf_qcdiag_protocol_loopback;
static int hf_qcdiag_ext_build_id_ver;
static int hf_qcdiag_ext_build_id_res;
static int hf_qcdiag_ext_build_id_msm;
static int hf_qcdiag_ext_build_id_mob_model;
static int hf_qcdiag_ext_build_id_sw_rev;
static int hf_qcdiag_ext_build_id_mob_model_str;

static int ett_qcdiag;
static int ett_qcdiag_cmd_subtree;
static int ett_qcdiag_log_codes_enabled;

static const value_string qcdiag_cmds[] = {
    { DIAG_VERNO_F,                "Version Information" },
    { DIAG_ESN_F,                  "Mobile Station Electronic Serial Number (ESN)" },
    { DIAG_PEEKB_F,                "Memory Peek Byte" },
    { DIAG_PEEKW_F,                "Memory Peek Word" },
    { DIAG_PEEKD_F,                "Memory Peek DWord" },
    { DIAG_POKEB_F,                "Memory Poek Byte" },
    { DIAG_POKEW_F,                "Memory Poke Word" },
    { DIAG_POKED_F,                "Memory Poke DWord" },
    { DIAG_OUTP_F,                 "Port Output Byte" },
    { DIAG_OUTPW_F,                "Port Output Word" },
    { DIAG_INP_F,                  "Port Input Byte" },
    { DIAG_INPW_F,                 "Port Input Word" },
    { DIAG_DMSS_STATUS_F,          "DMSS Status" },
    { DIAG_PEEK_VOCODER_F,         "Peek Vocoder" },
    { DIAG_POKE_VOCODER_F,         "Poke Vocoder" },
    { DIAG_LOGMASK_F,              "Set Logging Mask" },
    { DIAG_LOG_F,                  "Get Log" },
    { DIAG_NV_PEEK_F,              "Peek NV Memory" },
    { DIAG_NV_POKE_F,              "Poke NV Memory" },
    { DIAG_BAD_CMD_F,              "Invalid Command Error" },
    { DIAG_BAD_PARM_F,             "Invalid Parameters Error" },
    { DIAG_BAD_LEN_F,              "Invalid Packet Length Error" },
    { DIAG_BAD_DEVICE_F,           "Device Originated Error" },
    { DIAG_BAD_VOC_F,              "Vocoder Originated Error" },
    { DIAG_BAD_MODE_F,             "Invalid Mode Error" },
    { DIAG_TAGRAPH_F,              "Temporal Analyzer Power/Voice Information" },
    { DIAG_MARKOV_F,               "Markov Statistics" },
    { DIAG_MARKOV_RESET_F,         "Reset Markov Statistics" },
    { DIAG_DIAG_VER_F,             "Diagnostic Protocol Version" },
    { DIAG_TS_F,                   "Timestamp" },
    { DIAG_TA_PARM_F,              "Set Temporal Analyzer Parameters" },
    { DIAG_MSG_F,                  "Message Report Config" },
    { DIAG_HS_KEY_F,               "Emulate Handset Keypress" },
    { DIAG_HS_LOCK_F,              "Emulate Handset Lock/Unlock" },
    { DIAG_HS_SCREEN_F,            "Emulate Handset Display" },
    { DIAG_PARM_RETRIEVE_F,        "Parameter Retrieval" },
    { DIAG_PARM_SET_F,             "Parameter Download" },
    { DIAG_EXT_DEVICE_ID_F,        "External Device ID" },
    { DIAG_NV_READ_F,              "Read NV Item" },
    { DIAG_NV_WRITE_F,             "Write NV Item" },
    { DIAG_CONFIG_TABLE_F,         "Configure Table" },
    { DIAG_MODE_CHANGE_F,          "Mode Change" },
    { DIAG_ERR_READ_F,             "Retrieve Error Record" },
    { DIAG_ERR_CLEAR_F,            "Clear Error Record'" },
    { DIAG_SER_RESET_F,            "Symbol Error Rate Counter Reset" },
    { DIAG_SER_REPORT_F,           "Symbol Error Rate Counter Report" },
    { DIAG_TEST_F,                 "Run Specified Test" },
    { DIAG_GET_DIPSW_F,            "Get DIP Switch Settings" },
    { DIAG_SET_DIPSW_F,            "Set DIP Switch Settings" },
    { DIAG_VOC_PCM_LB_F,           "Start/Stop Vocoder PCM Loopback" },
    { DIAG_VOC_PKT_LB_F,           "Start/Stop Vocoder PKT Loopback" },
    { DIAG_CALL_ORIG_F,            "Call Origination" },
    { DIAG_CALL_END_F,             "Call Termination" },
    { DIAG_DLOAD_F,                "Switch To Download Protocol" },
    { DIAG_TEST_MODE_F,            "Test Mode Command" },
    { DIAG_SEND_PKT_SEQ_NUMS_F,    "Send Packet Sequence Numbers" },
    { DIAG_CFG_SLEEP_MODE_F,       "Configure Sleep Mode" },
    { DIAG_GET_SYS_TIME_F,         "Get System Time" },
    { DIAG_STATE_F,                "Get Phone State" },
    { DIAG_PILOT_SETS_F,           "Get Pilot Set Information" },
    { DIAG_SPC_F,                  "Send Service Programming Code" },
    { DIAG_BAD_SPC_MODE_F,         "Service Programming Code Related Error Response" },
    { DIAG_PARM_GET2_F,            "Get Parameters 2.0" },
    { DIAG_SERIAL_CHG_F,           "Serial Mode Change" },
    { DIAG_GET_CDMA_RSSI_F,        "Get CDMA RSSI" },
    { DIAG_PASSWORD_F,             "Security Password" },
    { DIAG_BAD_SEC_MODE_F,         "Bad Security Mode" },
    { DIAG_PR_LIST_WR_F,           "Write Preferred Roaming List" },
    { DIAG_PR_LIST_RD_F,           "Read Preferred Roaming List" },
    { DIAG_READ_SMS_MESSAGE_F,     "Read SMS Message" },
    { DIAG_SUBSYS_CMD_F,           "Subsystem Dispatcher" },
    { DIAG_NV_WRITE_OFFLINE_F,     "Write NV Without Going Offline" },
    { DIAG_GET_CALLER_ID_F,        "Get Caller ID/Service Option" },
    { DIAG_MODIFY_STATUS_MASK_F,   "Modify Status Mask" },
    { DIAG_AUDIO_CONTROL_F,        "Audio Control" },
    { DIAG_AKEY_F,                 "A-Key" },
    { DIAG_FEATURE_QUERY_F,        "Feature Query" },
    { DIAG_EXT_DIAG_CMD_F,         "Extended DIAG Command" },
    { DIAG_SMS_READ_F,             "Read SMS Message From NV" },
    { DIAG_SMS_WRITE_F,            "Write SMS Message To NV" },
    { DIAG_SUP_FER_F,              "Get FER Info For Supplemental Channels" },
    { DIAG_SUP_WALSH_CODES_F,      "Get Supplemental Channel Walsh Codes" },
    { DIAG_SET_MAX_SUP_CH_F,       "Set Max Number Of Supplemental Channels" },
    { DIAG_PARM_GET_IS95B_F,       "Get Parameters" },
    { DIAG_FS_OP_F,                "Embedded File System Operation" },
    { DIAG_AKEY_VERIFY_F,          "A-Key Verification" },
    { DIAG_BMP_HS_SCREEN_F,        "Emulate Handset Bitmap Screen" },
    { DIAG_CONFIG_COMM_F,          "Communications Configuration" },
    { DIAG_EXT_LOGMASK_F,          "Set Extended Logmask" },
    { DIAG_RESERVED_94_F,          "Reserved" },
    { DIAG_RESERVED_95_F,          "Reserved" },
    { DIAG_EVENT_REPORT_F,         "Static Event Reporting" },
    { DIAG_STREAMING_CONFIG_F,     "Streaming Output Config" },
    { DIAG_EXT_PARM_RETRIEVAL_F,   "Extensible Parameter Retrieval" },
    { DIAG_STATUS_SNAPSHOT_F,      "Get DMSS State/Status Snapshot" },
    { DIAG_RPC_F,                  "RPC Support" },
    { DIAG_GET_PROPERTY_F,         "Get Property" },
    { DIAG_PUT_PROPERTY_F,         "Put Property" },
    { DIAG_GET_GUID_F,             "Get GUID" },
    { DIAG_USER_CMD_F,             "User Callback Invocation" },
    { DIAG_GET_PERM_PROPERTY_F,    "Get Permanent Property" },
    { DIAG_PUT_PERM_PROPERTY_F,    "Put Permanent Property" },
    { DIAG_PERM_USER_CMD_F,        "Permanent User Callback Invocation" },
    { DIAG_GPS_SESS_CTRL_F,        "GPS Session Control" },
    { DIAG_GPS_GRID_F,             "Search GPS Grid" },
    { DIAG_GPS_STATISTICS_F,       "Get GPS Statistics" },
    { DIAG_ROUTE_F,                "DIAG Packet Routing" },
    { DIAG_IS2000_STATUS_F,        "Get IS-2000 Status" },
    { DIAG_RLP_STAT_RESET_F,       "Reset Radio Link Protocol (RLP) Statistics" },
    { DIAG_TDSO_STAT_RESET_F,      "Reset (S)TDSO Statistics" },
    { DIAG_LOG_CONFIG_F,           "Logging Configuration" },
    { DIAG_TRACE_EVENT_REPORT_F,   "Trace Event Report Control" },
    { DIAG_SBI_READ_F,             "SBI Read" },
    { DIAG_SBI_WRITE_F,            "SBI Write" },
    { DIAG_SSD_VERIFY_F,           "Verify SSD" },
    { DIAG_LOG_ON_DEMAND_F,        "Log on Demand" },
    { DIAG_EXT_MSG_F,              "Extended Message Report" },
    { DIAG_ONCRPC_F,               "Open Network Computing Remote Procedure Call (ONC-RPC)" },
    { DIAG_PROTOCOL_LOOPBACK_F,    "DIAG Loopback Test" },
    { DIAG_EXT_BUILD_ID_F,         "Get Extended Build ID" },
    { DIAG_EXT_MSG_CONFIG_F,       "Extended Message Report Config" },
    { DIAG_EXT_MSG_TERSE_F,        "Terse Format Message Config" },
    { DIAG_EXT_MSG_TERSE_XLATE_F,  "Translate Format Message" },
    { DIAG_SUBSYS_CMD_VER_2_F,     "Subsystem Dispatcher Version 2" },
    { DIAG_EVENT_MASK_GET_F,       "Get Event Mask" },
    { DIAG_EVENT_MASK_SET_F,       "Set Event Mask" },
    { DIAG_RESERVED_131_F,         "Reserved" },
    { DIAG_RESERVED_132_F,         "Reserved" },
    { DIAG_RESERVED_133_F,         "Reserved" },
    { DIAG_RESERVED_134_F,         "Reserved" },
    { DIAG_RESERVED_135_F,         "Reserved" },
    { DIAG_RESERVED_136_F,         "Reserved" },
    { DIAG_RESERVED_137_F,         "Reserved" },
    { DIAG_RESERVED_138_F,         "Reserved" },
    { DIAG_RESERVED_139_F,         "Reserved" },
    { DIAG_CHANGE_PORT_SETTINGS,   "Change Port Settings" },
    { DIAG_CNTRY_INFO_F,           "Country Network Information" },
    { DIAG_SUPS_REQ_F,             "Call Supplementary" },
    { DIAG_MMS_ORIG_SMS_REQUEST_F, "MMS Originate SMS" },
    { DIAG_MEAS_MODE_F,            "Measurement Mode" },
    { DIAG_MEAS_REQ_F,             "Measurement Request" },
    { DIAG_QSR_EXT_MSG_TERSE_F,    "Optimized F3 Messages" },
    { DIAG_DCI_CMD_REQ,            "DCI Command" },
    { DIAG_DCI_DELAYED_RSP,        "DCI Delayed" },
    { DIAG_BAD_TRANS_F,            "DCI Error Response" },
    { DIAG_SSM_DISALLOWED_CMD_F,   "SSM Disallowed Command Response" },
    { DIAG_LOG_ON_DEMAND_EXT_F,    "Log On Extended" },
    { DIAG_MULTI_RADIO_CMD_F,      "Multi-SIM Radio Device Command" },
    { DIAG_QSR4_EXT_MSG_TERSE_F,   "Logging Optimized Debugging Messages (QShrink)" },
    { DIAG_DCI_CONTROL_F,          "DCI Control Packet" },
    { DIAG_COMPRESSED_F,           "Compressed Diag Data" },
    { DIAG_MSG_SMALL_F,            "Small Message" },
    { DIAG_QSH_TRACE_PAYLOAD_F,    "QTrace Message" },
    { DIAG_SECURE_LOG_F,           "Log Security" },
    { 0, NULL }
};

value_string_ext qcdiag_cmds_ext = VALUE_STRING_EXT_INIT(qcdiag_cmds);

static const value_string qcdiag_subsys[] = {
    { DIAG_SUBSYS_OEM,                  "OEM" },
    { DIAG_SUBSYS_ZREX,                 "ZREX" },
    { DIAG_SUBSYS_SD,                   "System Determination" },
    { DIAG_SUBSYS_BT,                   "Bluetooth" },
    { DIAG_SUBSYS_WCDMA,                "WCDMA" },
    { DIAG_SUBSYS_HDR,                  "1xEvDO" },
    { DIAG_SUBSYS_DIABLO,               "DIABLO" },
    { DIAG_SUBSYS_TREX,                 "TREX - Off-target testing" },
    { DIAG_SUBSYS_GSM,                  "GSM" },
    { DIAG_SUBSYS_UMTS,                 "UMTS" },
    { DIAG_SUBSYS_HWTC,                 "HWTC" },
    { DIAG_SUBSYS_FTM,                  "Factory Test Mode" },
    { DIAG_SUBSYS_REX,                  "REX" },
    { DIAG_SUBSYS_GPS,                  "GPS" },
    { DIAG_SUBSYS_WMS,                  "Wireless Messaging Service" },
    { DIAG_SUBSYS_CM,                   "Call Manager" },
    { DIAG_SUBSYS_HS,                   "Handset" },
    { DIAG_SUBSYS_AUDIO_SETTINGS,       "Audio Settings" },
    { DIAG_SUBSYS_DIAG_SERV,            "DIAG Services" },
    { DIAG_SUBSYS_FS,                   "EFS2" },
    { DIAG_SUBSYS_PORT_MAP_SETTINGS,    "Port Map Settings" },
    { DIAG_SUBSYS_MEDIAPLAYER,          "QCT Mediaplayer" },
    { DIAG_SUBSYS_QCAMERA,              "QCT QCamera" },
    { DIAG_SUBSYS_MOBIMON,              "QCT MobiMon" },
    { DIAG_SUBSYS_GUNIMON,              "QCT GuniMon" },
    { DIAG_SUBSYS_LSM,                  "Location Services Manager" },
    { DIAG_SUBSYS_QCAMCORDER,           "QCT QCamcorder" },
    { DIAG_SUBSYS_MUX1X,                "Multiplexer (1x)" },
    { DIAG_SUBSYS_DATA1X,               "Data (1x)" },
    { DIAG_SUBSYS_SRCH1X,               "Searcher (1x)" },
    { DIAG_SUBSYS_CALLP1X,              "Call Processor (1x)" },
    { DIAG_SUBSYS_APPS,                 "Applications" },
    { DIAG_SUBSYS_SETTINGS,             "Settings" },
    { DIAG_SUBSYS_GSDI,                 "Generic Sim Driver Interface" },
    { DIAG_SUBSYS_TMC,                  "Task Main Controller" },
    { DIAG_SUBSYS_USB,                  "USB" },
    { DIAG_SUBSYS_PM,                   "Power Management" },
    { DIAG_SUBSYS_DEBUG,                "Debug" },
    { DIAG_SUBSYS_CLKRGM,               "Clock Regime" },
    { DIAG_SUBSYS_WLAN,                 "WLAN" },
    { DIAG_SUBSYS_PS_DATA_LOGGING,      "PS Data Path Logging" },
    { DIAG_SUBSYS_MFLO,                 "MediaFLO" },
    { DIAG_SUBSYS_DTV,                  "Digital TV" },
    { DIAG_SUBSYS_RRC,                  "WCDMA RRC" },
    { DIAG_SUBSYS_PROF,                 "Profiling" },
    { DIAG_SUBSYS_TCXOMGR,              "TXCO Manager" },
    { DIAG_SUBSYS_NV,                   "NV" },
    { DIAG_SUBSYS_PARAMS,               "Parameters" },
    { DIAG_SUBSYS_MDDI,                 "MDDI" },
    { DIAG_SUBSYS_DS_ATCOP,             "Data Services AT Command Processor" },
    { DIAG_SUBSYS_L4LINUX,              "L4/Linux" },
    { DIAG_SUBSYS_MVS,                  "Multimedia Voice Services" },
    { DIAG_SUBSYS_CNV,                  "Compact NV" },
    { DIAG_SUBSYS_APIONE_PROGRAM,       "apiOne" },
    { DIAG_SUBSYS_HIT,                  "Hardware Integration Test" },
    { DIAG_SUBSYS_DRM,                  "Digital Restrictions Management" },
    { DIAG_SUBSYS_DM,                   "Device Management" },
    { DIAG_SUBSYS_FC,                   "Flow Controller" },
    { DIAG_SUBSYS_MEMORY,               "Malloc Manager" },
    { DIAG_SUBSYS_FS_ALTERNATE,         "Alternate Filesystem" },
    { DIAG_SUBSYS_REGRESSION,           "Regression Test Commands" },
    { DIAG_SUBSYS_SENSORS,              "Sensors" },
    { DIAG_SUBSYS_FLUTE,                "File Delivery over Unidirectional Transport (FLUTE)" },
    { DIAG_SUBSYS_ANALOG,               "Analog" },
    { DIAG_SUBSYS_APIONE_PROGRAM_MODEM, "apiOne Program on Modem Processor" },
    { DIAG_SUBSYS_LTE,                  "LTE" },
    { DIAG_SUBSYS_BREW,                 "BREW" },
    { DIAG_SUBSYS_PWRDB,                "Power Debug" },
    { DIAG_SUBSYS_CHORD,                "Chaos Coordinator" },
    { DIAG_SUBSYS_SEC,                  "Security" },
    { DIAG_SUBSYS_TIME,                 "Time" },
    { DIAG_SUBSYS_Q6_CORE,              "Q6 Core" },
    { DIAG_SUBSYS_COREBSP,              "Core BSP" },
    { DIAG_SUBSYS_MFLO2,                "MediaFLO2" },
    { DIAG_SUBSYS_ULOG,                 "ULog Services" },
    { DIAG_SUBSYS_APR,                  "Async Packet Router" },
    { DIAG_SUBSYS_QNP,                  "QNP" },
    { DIAG_SUBSYS_STRIDE,               "STRIDE" },
    { DIAG_SUBSYS_OEMDPP,               "DPP Partition" },
    { DIAG_SUBSYS_Q5_CORE,              "Q5 Core" },
    { DIAG_SUBSYS_USCRIPT,              "Uscript" },
    { DIAG_SUBSYS_NAS,                  "Non Access Stratum" },
    { DIAG_SUBSYS_CMAPI,                "Common Map API (CMAPI)" },
    { DIAG_SUBSYS_SSM,                  "SSM" },
    { DIAG_SUBSYS_TDSCDMA,              "TD-SCDMA" },
    { DIAG_SUBSYS_SSM_TEST,             "SSM Test" },
    { DIAG_SUBSYS_MPOWER,               "mPower" },
    { DIAG_SUBSYS_QDSS,                 "Qualcomm Debug Subsystem (QDSS)" },
    { DIAG_SUBSYS_CXM,                  "CXM" },
    { DIAG_SUBSYS_GNSS_SOC,             "Secondary GNSS" },
    { DIAG_SUBSYS_TTLITE,               "Time Test Lite" },
    { DIAG_SUBSYS_FTM_ANT,              "FTM ANT" },
    { DIAG_SUBSYS_MLOG,                 "MLog" },
    { DIAG_SUBSYS_LIMITSMGR,            "Limits Manager" },
    { DIAG_SUBSYS_EFSMONITOR,           "EFS Monitor" },
    { DIAG_SUBSYS_DISPLAY_CALIBRATION,  "Display Calibration" },
    { DIAG_SUBSYS_VERSION_REPORT,       "Version Report" },
    { DIAG_SUBSYS_DS_IPA,               "Internet Packet Accelerator (IPA)" },
    { DIAG_SUBSYS_SYSTEM_OPERATIONS,    "System Operations" },
    { DIAG_SUBSYS_CNSS_POWER,           "CNSS Power" },
    { DIAG_SUBSYS_LWIP,                 "LwIP" },
    { DIAG_SUBSYS_IMS_QVP_RTP,          "IMS QVP RTP" },
    { 0, NULL }
};

static value_string_ext qcdiag_subsys_ext = VALUE_STRING_EXT_INIT(qcdiag_subsys);

static const value_string qcdiag_logcodes[] = {
    { LOG_CODE_1X_DIAG_REQUEST,     "Diagnostic Request" },
    { LOG_CODE_1X_DIAG_RES_STATUS,  "Diagnostic Response Status" },
    { LOG_CODE_1X_EVENT,            "Event" },
    { LOG_CODE_WCDMA_SIGNALING_MSG, "WCDMA Signaling Messages" },
    { 0, NULL }
};

value_string_ext qcdiag_logcodes_ext = VALUE_STRING_EXT_INIT(qcdiag_logcodes);

enum log_config_op {
    LOG_CONFIG_DISABLE_OP             = 0,
    LOG_CONFIG_RETRIEVE_ID_RANGES_OP  = 1,
    LOG_CONFIG_RETRIEVE_VALID_MASK_OP = 2,
    LOG_CONFIG_SET_MASK_OP            = 3,
    LOG_CONFIG_GET_LOGMASK_OP         = 4,
};

static const value_string qcdiag_logcfg_ops[] = {
    { LOG_CONFIG_DISABLE_OP,             "Disable logging service" },
    { LOG_CONFIG_RETRIEVE_ID_RANGES_OP,  "Retrieve ID ranges" },
    { LOG_CONFIG_RETRIEVE_VALID_MASK_OP, "Retrieve valid mask" },
    { LOG_CONFIG_SET_MASK_OP,            "Set Log Mask" },
    { LOG_CONFIG_GET_LOGMASK_OP,         "Get Log Mask" },
    { 0, NULL }
};

value_string_ext qcdiag_logcfg_ops_ext = VALUE_STRING_EXT_INIT(qcdiag_logcfg_ops);

static const value_string qcdiag_logcfg_status[] = {
    { 0, "Success" },
    { 1, "Invalid Equipment ID" },
    { 2, "Reserved" },
    { 0, NULL }
};

static const value_string qcdiag_logcfg_equipid[] = {
    {  0, "OEM" },
    {  1, "1X" },
    {  2, "Reserved" },
    {  3, "Reserved" },
    {  4, "WCDMA" },
    {  5, "GSM" },
    {  6, "MSP" },
    {  7, "UMTS" },
    {  8, "TDMA" },
    {  9, "BOA" },
    { 10, "DTV" },
    { 11, "APPS" },
    { 12, "DSP" },
    { 13, "TD-SCDMA" },
    { 0, NULL }
};


/* ########################
 * ###   Supplementary  ###
 * ########################
 */

/* XQDM timestamp encoded with upper (48 bits) and lower (16 bits) parts.
 * Upper 48 bits: GPS epoch, incremented by 1 for 1/800s tick
 * Lower 16 bits: time since last tick in 1/32 chip units
 *
 * The GPS epoch is 00:00:00 (midnight) UTC on 1980-01-06.
 *
 *  <--                       48 bits                        --> <--   16 bits    -->
 * +------------------------------------------------------------+--------------------+
 * | 1.25 ms counter                                            | 1/32 chip counter  |
 * +------------------------------------------------------------+--------------------+
 */

nstime_t
qcdiag_parse_timestamp(tvbuff_t *tvb, uint32_t offset)
{
    uint64_t ts;
    double epoch, upper, lower, total;
    nstime_t timestamp;

    ts = tvb_get_uint64(tvb, offset, ENC_LITTLE_ENDIAN);

    upper = (double)(ts >> 16) * (1.0/800 * 1000.0);  // microseconds resolution
    lower = (double)(ts & 0xffff) * (1.0 / 40960.0);

    /* Unix timestamp for 1980-01-06 00:00:00 UTC is 315964800 */
    epoch = 315964800;

    total = ((upper + lower) / 1000.0) + epoch;

    timestamp.secs  = (unsigned)total;
    timestamp.nsecs = (unsigned)((total - (unsigned)total) * 1000000000);

    return timestamp;
}

static void
qcdiag_append_type(proto_tree *tree, packet_info *pinfo, bool request)
{
    proto_item *ti;
    const char *msgtype;

    ti = proto_tree_get_parent(tree);

    /* Request or Response */
    msgtype = tfs_get_string(!request, &tfs_response_request);

    /* Append COL_INFO with Request/Response */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", msgtype);

    /* Append parent item name */
    proto_item_append_text(ti, " %s", msgtype);
}

static uint32_t
qcdiag_add_cmd_hdr(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *tree, uint32_t cmd, uint32_t logcode, int logcode_offset, int ver)
{
    uint32_t length;
    proto_item *generated_item;
    length = tvb_reported_length(tvb);

    /* Log Code */
    generated_item = proto_tree_add_uint(tree, hf_qcdiag_logcode, tvb, offset, logcode_offset, logcode);
    if (logcode_offset == 0)
        proto_item_set_generated(generated_item);
    offset += logcode_offset;

    /* Length */
    generated_item = proto_tree_add_uint(tree, hf_qcdiag_len, tvb, offset, 0, length);
    proto_item_set_generated(generated_item);

    /* Version */
    if (ver > -1)
        proto_tree_add_uint(tree, hf_qcdiag_ver, tvb, offset, 0, ver);

    /* Command Code */
    proto_tree_add_uint(tree, hf_qcdiag_cmd, tvb, offset, 1, cmd);
    offset += 1;

    return offset;
}

static proto_tree*
qcdiag_add_cmd_subtree(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd, bool request)
{
    proto_item *ti;
    proto_tree *subtree;
    uint32_t length;
    const char *text;
    const char *msgtype;

    length = tvb_reported_length(tvb);
    ti = proto_tree_get_parent(tree);

    text = val_to_str_ext(pinfo->pool, cmd, &qcdiag_cmds_ext, "Unknown Command (0x%02x)");
    msgtype = tfs_get_string(!request, &tfs_response_request);

    /* Append parent item name */
    proto_item_append_text(ti, ", %s", text);

    /* Append COL_INFO and parent item name */
    qcdiag_append_type(tree, pinfo, request);

    if (length == offset)
        return NULL;

    subtree = proto_tree_add_subtree_format(tree, tvb, offset, length, /* -1 fails */
                             ett_qcdiag_cmd_subtree, NULL, "%s %s", text, msgtype);

    return subtree;
}


/* Version Information Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (  0 / 0x00) |       1        | Message ID: The CMD_CODE is set to 0    |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Version Information Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (  0 / 0x00) |       1        | Message ID: The CMD_CODE is set to 0    |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | COMP_DATE             |       11       | Compilation date: ASCII characters      |
 * |                       |                | indicating the date of compilation      |
 * |                       |                | for the executable                      |
 * +-----------------------+----------------+-----------------------------------------+
 * | COMP_TIME             |       8        | Compilation time: ASCII characters      |
 * |                       |                | indicating the time of compilation      |
 * |                       |                | for the executable;                     |
 * +-----------------------+----------------+-----------------------------------------+
 * | REL_DATE              |       11       | Release date: ASCII characters          |
 * |                       |                | indicating the date of formal release   |
 * |                       |                | for the executable                      |
 * +-----------------------+----------------+-----------------------------------------+
 * | REL_TIME              |       8        | Release date: ASCII characters          |
 * |                       |                | indicating the time of formal release   |
 * |                       |                | for the executable                      |
 * +-----------------------+----------------+-----------------------------------------+
 * | VER_DIR               |       8        | Version directory: ASCII characters     |
 * |                       |                | giving the name of the directory in     |
 * |                       |                | which the executable was prepared;      |
 * |                       |                | this string is the phone sw version;    |
 * +-----------------------+----------------+-----------------------------------------+
 * | SCM                   |       1        | Station class mark                      |
 * |                       |                |                                         |
 * +-----------------------+----------------+-----------------------------------------+
 * | MOB_CAI_REV           |       1        | Mobile common air interface revision    |
 * |                       |                |                                         |
 * +-----------------------+----------------+-----------------------------------------+
 * | MOB_MODEL             |       1        | Manufacturer’s mobile model             |
 * |                       |                |                                         |
 * +-----------------------+----------------+-----------------------------------------+
 * | MOB_FIRM_REV          |       2        | Manufacturer’s mobile firmware revision |
 * |                       |                | (software version)                      |
 * +-----------------------+----------------+-----------------------------------------+
 * | SLOT_CYCLE_INDEX      |       1        | Slot cycle index                        |
 * |                       |                |                                         |
 * +-----------------------+----------------+-----------------------------------------+
 * | MSM_VER               |       2        | Mobile station modem revision           |
 * |                       |                |                                         |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_verno(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    uint32_t logcode, length;
    uint32_t major, minor;
    bool request;
    char *msm;

    length = tvb_reported_length(tvb);

    request = (length == 1) ? true : false;

    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);

    if (request) return;

    /* COMP_DATE (there is no null-termination) */
    proto_tree_add_item(subtree, hf_qcdiag_verno_comp_date, tvb, offset, 11, ENC_ASCII);
    offset += 11;

    /* COMP_TIME (there is no null-termination) */
    proto_tree_add_item(subtree, hf_qcdiag_verno_comp_time, tvb, offset, 8, ENC_ASCII);
    offset += 8;

    /* REL_DATE (there is no null-termination) */
    proto_tree_add_item(subtree, hf_qcdiag_verno_rel_date, tvb, offset, 11, ENC_ASCII);
    offset += 11;

    /* REL_TIME (there is no null-termination) */
    proto_tree_add_item(subtree, hf_qcdiag_verno_rel_time, tvb, offset, 8, ENC_ASCII);
    offset += 8;

    /* VER_DIR (there is no null-termination) */
    proto_tree_add_item(subtree, hf_qcdiag_verno_ver_dir, tvb, offset, 8, ENC_ASCII);
    offset += 8;

    /* SCM */
    proto_tree_add_item(subtree, hf_qcdiag_verno_scm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* MOB_CAI_REV */
    proto_tree_add_item(subtree, hf_qcdiag_verno_mob_cai_rev, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* MOB_MODEL */
    proto_tree_add_item(subtree, hf_qcdiag_verno_mob_model, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* MOB_FIRM_REV */
    proto_tree_add_item(subtree, hf_qcdiag_verno_mob_firm_rev, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* SLOT_CYCLE_INDEX */
    proto_tree_add_item(subtree, hf_qcdiag_verno_sci, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    major = tvb_get_uint8(tvb, offset);
    minor = tvb_get_uint8(tvb, offset+1);
    msm = wmem_strdup_printf(pinfo->pool, "%d.%02x", major, minor);

    /* MSM_VER */
    proto_tree_add_string(subtree, hf_qcdiag_verno_msm_ver, tvb, offset, 2, msm);
}


/* Mobile Station Electronic Serial Number (ESN) Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (  1 / 0x01) |       1        | Message ID: The CMD_CODE is set to 1    |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Mobile Station Electronic Serial Number (ESN) Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (  1 / 0x01) |       1        | Message ID: The CMD_CODE is set to 1    |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | ESN                   |       4        | Electronic serial number                |
 * |                       |                |                                         |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_esn(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    uint32_t logcode, length;
    bool request;

    length = tvb_reported_length(tvb);

    request = (length == 1) ? true : false;

    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);

    if (request) return;

    /* ESN */
    proto_tree_add_item(subtree, hf_qcdiag_esn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}


/* Bad Command
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 19 / 0x13) |       1        | Message ID: The CMD_CODE is set to 19   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | DATA                  |    Variable    | Unrecognized message                    |
 * |                       |                |                                         |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_bad_cmd(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    int bytes;

    bytes = tvb_captured_length(tvb);

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, LOG_CODE_1X_DIAG_RES_STATUS, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, false);

    /* DATA */
    proto_tree_add_item(subtree, hf_qcdiag_bad_cmd, tvb, offset, bytes-offset, ENC_NA);
}


/* Bad Parameters
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 20 / 0x14) |       1        | Message ID: The CMD_CODE is set to 20   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | DATA                  |    Variable    | Malformed message                       |
 * |                       |                |                                         |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_bad_parm(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    int bytes;

    bytes = tvb_captured_length(tvb);

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, LOG_CODE_1X_DIAG_RES_STATUS, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, false);

    /* DATA */
    proto_tree_add_item(subtree, hf_qcdiag_bad_parm, tvb, offset, bytes-offset, ENC_NA);
}


/* Bad Length
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 21 / 0x15) |       1        | Message ID: The CMD_CODE is set to 21   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | DATA                  |    Variable    | Original message                        |
 * |                       |                |                                         |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_bad_len(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    int bytes;

    bytes = tvb_captured_length(tvb);

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, LOG_CODE_1X_DIAG_RES_STATUS, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, false);

    /* DATA */
    proto_tree_add_item(subtree, hf_qcdiag_bad_len, tvb, offset, bytes-offset, ENC_NA);
}


/* Bad Mode
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 24 / 0x18) |       1        | Message ID: The CMD_CODE is set to 24   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | DATA                  |    Variable    | Original message                        |
 * |                       |                |                                         |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_bad_mode(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    int bytes;

    bytes = tvb_captured_length(tvb);

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, LOG_CODE_1X_DIAG_RES_STATUS, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, false);

    /* DATA */
    proto_tree_add_item(subtree, hf_qcdiag_bad_mode, tvb, offset, bytes-offset, ENC_NA);
}


/* Reset Markov Statistics Request/Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 27 / 0x1B) |       1        | Message ID: The CMD_CODE is set to 27   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_markov_reset(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    uint32_t logcode, length;
    bool request;

    length = tvb_reported_length(tvb);

    /* It is not possible to distinguish between Request and Response */
    request = (length == 0) ? true : false;

    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);
}


/* Diagnostic Protocol Version Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 28 / 0x1C) |       1        | Message ID: The CMD_CODE is set to 28   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Diagnostic Protocol Version Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 28 / 0x1C) |       1        | Message ID: The CMD_CODE is set to 28   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | DIAG_VERSION          |       2        | Version of diagnostic interface         |
 * |                       |                | The version number is 7.                |
 * |                       |                | For streaming capability phones,        |
 * |                       |                | the version number is 8.                |
 * +-----------------------+----------------+-----------------------------------------+
 */

static const value_string qcdiag_diag_ver_vals[] = {
    { 7, "User Equipment without streaming capability" },
    { 8, "User Equipment with streaming capability" },
    { 0, NULL }
};

static void
dissect_qcdiag_diag_ver(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    uint32_t logcode, length;
    bool request;

    length = tvb_reported_length(tvb);

    request = (length == 1) ? true : false;

    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);

    if (request) return;

    /* DIAG_VERSION */
    proto_tree_add_item(subtree, hf_qcdiag_diag_ver, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}


/* Timestamp Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 29 / 0x1D) |       1        | Message ID: The CMD_CODE is set to 29   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Timestamp Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 29 / 0x1D) |       1        | Message ID: The CMD_CODE is set to 29   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | TIME_STAMP            |       8        | Current time read from the system       |
 * |                       |                | time clock                              |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_ts(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    uint32_t logcode, length;
    bool request;
    nstime_t abs_time;
    char *timestamp;

    length = tvb_reported_length(tvb);

    request = (length == 1) ? true : false;

    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);

    if (request) return;

    abs_time = qcdiag_parse_timestamp(tvb, offset);

    /* local time in our time zone, with month and day */
    timestamp = abs_time_to_str(pinfo->pool, &abs_time, ABSOLUTE_TIME_LOCAL, true);

    /* TIME_STAMP */
    proto_tree_add_string(subtree, hf_qcdiag_ts, tvb, offset, 8, timestamp);
}


/* Parameter Set Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 36 / 0x24) |       1        | Message ID: The CMD_CODE is set to 36   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | PARM_ID               |       2        | Parameter ID; the additional special ID |
 * |                       |                | of -1 (0xFFFF) to indicate that all     |
 * |                       |                | settleable parameters are to be reset   |
 * |                       |                | to zero (0)                             |
 * +-----------------------+----------------+-----------------------------------------+
 * | PARM_VALUE            |       4        | Parameter value;                        |
 * |                       |                | the desired new value for the parameter |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Parameter Set Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 36 / 0x24) |       1        | Message ID: The CMD_CODE is set to 36   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | SET_TIME              |       8        | Time the operation was processed;       |
 * |                       |                | the format is the same as 29/0x1D       |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_parm_set(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    uint32_t logcode, length;
    bool request;
    nstime_t abs_time;
    char *timestamp;

    length = tvb_reported_length(tvb);

    request = (length == 1) ? true : false;

    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);

    if (request) {
        /* PARM_ID */
        proto_tree_add_item(subtree, hf_qcdiag_parm_set_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* PARM_VALUE */
        proto_tree_add_item(subtree, hf_qcdiag_parm_set_value, tvb, offset, 4, ENC_LITTLE_ENDIAN);

        return;
    }

    abs_time = qcdiag_parse_timestamp(tvb, offset);

    /* local time in our time zone, with month and day */
    timestamp = abs_time_to_str(pinfo->pool, &abs_time, ABSOLUTE_TIME_LOCAL, true);

    /* SET_TIME */
    proto_tree_add_string(subtree, hf_qcdiag_parm_set_time, tvb, offset, 8, timestamp);
}


/* Mode Change Request/Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 41 / 0x29) |       1        | Message ID: The CMD_CODE is set to 41   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | MODE                  |       2        | Selected operating mode;                |
 * |                       |                | values are in 0-6                       |
 * +-----------------------+----------------+-----------------------------------------+
 */

static const value_string qcdiag_mode_change_mode_vals[] = {
    { 0, "Offline Analog mode" },
    { 1, "Offline Digital mode" },
    { 2, "Reset" },
    { 3, "Offline Factory Test mode" },
    { 4, "Online mode" },
    { 5, "Low Power mode" },
    { 6, "Power Off mode" },
    { 0, NULL }
};

static void
dissect_qcdiag_mode_change(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    uint32_t logcode, length;
    bool request;

    length = tvb_reported_length(tvb);

    /* It is not possible to distinguish between Request and Response */
    request = (length == 0) ? true : false;

    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);

    /* MODE */
    proto_tree_add_item(subtree, hf_qcdiag_mode_change, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}


/* Subsystem Dispatcher Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 75 / 0x4B) |       1        | Message ID: The CMD_CODE is set to 75   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | SUBSYS_ID             |       1        | Subsystem Identifier; this is an        |
 * |                       |                | enumeration of all defined subsystems   |
 * +-----------------------+----------------+-----------------------------------------+
 * | SUBSYS_CMD_CODE       |       2        | Command code for the given subsystem;   |
 * |                       |                | defines the subsystem packet            |
 * +-----------------------+----------------+-----------------------------------------+
 * | REQUEST               |    Variable    | Request packet data for this command;   |
 * |                       |                | defined separately for each command     |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Subsystem Dispatcher Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 75 / 0x4B) |       1        | Message ID: The CMD_CODE is set to 75   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | SUBSYS_ID             |       1        | Subsystem Identifier; this is an        |
 * |                       |                | enumeration of all defined subsystems   |
 * +-----------------------+----------------+-----------------------------------------+
 * | SUBSYS_CMD_CODE       |       2        | Command code for the given subsystem;   |
 * |                       |                | defines the subsystem packet            |
 * +-----------------------+----------------+-----------------------------------------+
 * | RESPONSE              |    Variable    | Response packet data for this command;  |
 * |                       |                | defined separately for each command     |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_subsys_cmd(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_item *ti;
    proto_tree *subtree;
    tvbuff_t *payload_tvb;
    uint32_t length, subsys_id, logcode;
    const char *text;
    bool request;

    ti = proto_tree_get_parent(tree);
    length = tvb_reported_length(tvb);

    request = (length == 4) ? true : false;

    /* SUBSYS_ID value */
    subsys_id = (uint32_t)tvb_get_uint8(tvb, offset+1);

    text = val_to_str_ext(pinfo->pool, subsys_id, &qcdiag_subsys_ext, "Unknown Subsystem (0x%02x)");

    /* Set COL_INFO to Subsystem ID */
    col_set_str(pinfo->cinfo, COL_INFO, "Subsystem");
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", text);

    /* Log Code value */
    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    /* This message type does not include log code so the offset will be increased by 1. */
    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);

    /* Append parent item name */
    proto_item_append_text(ti, ", %s", text);

    /* SUBSYS_ID */
    proto_tree_add_uint(subtree, hf_qcdiag_subsys_id, tvb, offset, 1, subsys_id);
    offset += 1;

    /* SUBSYS_CMD_CODE */
    proto_tree_add_item(subtree, hf_qcdiag_subsys_cmd_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    payload_tvb = tvb_new_subset_length(tvb, offset, length-offset);

    if (!dissector_try_uint(qcdiag_subsys_dissector_table, subsys_id, payload_tvb, pinfo, subtree))
        call_dissector(data_handle, payload_tvb, pinfo, subtree);
}


/* Logging Configuration Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (115 / 0x73) |       1        | Message ID: The CMD_CODE is set to 115  |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | RESERVED              |       3        | Reserved                                |
 * +-----------------------+----------------+-----------------------------------------+
 * | OPERATION             |       4        | Specifies the operation to be performed |
 * |                       |                | values are:                             |
 * |                       |                | 0 - Disable logging service             |
 * |                       |                | 1 - Retrieve ID ranges                  |
 * |                       |                | 2 - Retrieve valid mask                 |
 * |                       |                | 3 - Set log mask                        |
 * |                       |                | 4 - Get log mask                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | OPERATION_DATA        |    Variable    | Response packet data for this command;  |
 * |                       |                | defined separately for each command     |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Logging Configuration Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (115 / 0x73) |       1        | Message ID: The CMD_CODE is set to 115  |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | RESERVED              |       3        | Reserved                                |
 * +-----------------------+----------------+-----------------------------------------+
 * | OPERATION             |       4        | Specifies the operation to be performed |
 * |                       |                | values are:                             |
 * |                       |                | 0 - Disable logging service             |
 * |                       |                | 1 - Retrieve ID ranges                  |
 * |                       |                | 2 - Retrieve valid mask                 |
 * |                       |                | 3 - Set log mask                        |
 * |                       |                | 4 - Get log mask                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | STATUS                |       4        | Specifies the status of the operation;  |
 * |                       |                | values are:                             |
 * |                       |                | 0 - Success                             |
 * |                       |                | 1 - Invalid equipment ID                |
 * |                       |                | 2 - Reserved                            |
 * +-----------------------+----------------+-----------------------------------------+
 * | OPERATION_DATA        |    Variable    | Response packet data for this command;  |
 * |                       |                | defined separately for each command     |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Logging Mask Structure
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | EQUIP_ID              |       4        | Specifies the equipment ID;             |
 * |                       |                | range is 0 to 15;                       |
 * +-----------------------+----------------+-----------------------------------------+
 * | MASK                  |(NUM_ITEMS+7)/8 | Array of (NUM_ITEMS + 7) / 8 bytes      |
 * |                       |                | containing the mask for the specified   |
 * |                       |                | equipment ID                            |
 * +-----------------------+----------------+-----------------------------------------+
 */

/* Each equipment ID is configured separately using Logging Configuration command.
 * A bit-mask is used to denote all items for the specified equipment ID.
 * The mask is an array of bytes in which each bit denotes a log item’s configuration.
 * A bit value of 1 specifies that the item is enabled.
 * A bit value of 0 specifies that the item is disabled.
 */
static void
qcdiag_log_codes_enabled(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *tree, uint32_t equip_id, uint32_t last)
{
    proto_item *pi;
    proto_tree *subtree;
    uint32_t byte, pos, bit, logcode;
    bool first;

    subtree = proto_tree_add_subtree_format(tree, tvb, offset, last,
                   ett_qcdiag_log_codes_enabled, NULL, "Log Codes Enabled");

    equip_id = equip_id << 12;

    for (pos = 0; pos < last; pos++) {
        byte = (uint32_t)tvb_get_uint8(tvb, offset+pos);
        if (byte == 0) continue;

        first = true;
        pi = proto_tree_add_format_text(subtree, tvb, offset+pos, 1);

        for (bit = 0; bit < 8; bit++) {
            if ((byte >> bit) & 1) {
                logcode = equip_id + (pos * 8) + bit;
                if (first) {
	                proto_item_set_text(pi, "0x%04x", logcode);
                    first = false;
                } else {
                    proto_item_append_text(pi, ", 0x%04x", logcode);
                }
            }
        }
    }
}

static uint32_t
dissect_qcdiag_log_config_hdr(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd, bool request)
{
    proto_item *ti;
    uint32_t operation, logcode;
    const char *text;

    ti = proto_tree_get_parent(tree);

    /* Command Code value */
    text = val_to_str_ext(pinfo->pool, cmd, &qcdiag_cmds_ext, "Unknown Command (0x%02x)");

    /* Log Code value */
    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    /* Append parent item name */
    proto_item_append_text(ti, ", %s", text);

    /* Reserved */
    proto_tree_add_item(tree, hf_qcdiag_logcfg_res, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    /* Operation */
    proto_tree_add_item_ret_uint(tree, hf_qcdiag_logcfg_operation, tvb, offset, 4, ENC_LITTLE_ENDIAN, &operation);
    offset += 4;

    text = val_to_str_ext(pinfo->pool, operation, &qcdiag_logcfg_ops_ext, "Unknown Operation (0x%02x)");

    /* Set COL_INFO to Operation */
    col_set_str(pinfo->cinfo, COL_INFO, text);

    /* Append COL_INFO and parent item name */
    qcdiag_append_type(tree, pinfo, request);

    /* Append parent item name */
    proto_item_append_text(ti, ", %s", text);

    return offset;
}

/* Disable Logging Operation Request:
 *   No additional information specified.
 *
 * Disable Logging Operation Response:
 *   No additional information specified.
 */

static void
dissect_qcdiag_log_config_disable_op(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *tree, uint32_t cmd)
{
    uint32_t length;
    bool request;

    length = tvb_reported_length(tvb);

    /* 8 = CMD_CODE (1) + RESERVED (3) + OPERATION (4) */
    request = (length == 8) ? true : false;

    offset = dissect_qcdiag_log_config_hdr(tvb, offset, pinfo, tree, cmd, request);

    if (request) return;

    /* Status */
    proto_tree_add_item(tree, hf_qcdiag_logcfg_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

/* Retrieve Logging ID Ranges Operation Request
 *   No additional information specified.
 *
 * Retrieve Logging ID Ranges Operation Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | RANGES                |     4 * 16     | 16 instances of NUM_ITEMS,              |
 * |                       |                | indexed by equipment ID                 |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_log_config_retreive_id_ranges(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *tree, uint32_t cmd)
{
    proto_item *pi;
    uint32_t length, num_ranges, range;
    bool request;

    length = tvb_reported_length(tvb);

    request = (length == 8) ? true : false;

    offset = dissect_qcdiag_log_config_hdr(tvb, offset, pinfo, tree, cmd, request);

    if (request) return;

    /* Status */
    proto_tree_add_item(tree, hf_qcdiag_logcfg_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    num_ranges = (length - offset) / 4; // num_ranges expected to be 16

    for (uint32_t i=0; i < num_ranges; i++) {
        range = (uint32_t)tvb_get_uint8(tvb, offset+i);
        if (range == 0) continue;

        pi = proto_tree_add_format_text(tree, tvb, offset+(4*i), 1);
	    proto_item_set_text(pi, "%u: %u", i, range);
    }
}

/* Set Logging Mask Request/Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | MASK_STRUCTURE        |    Variable    | Logging mask structure;                 |
 * |                       |                | this is the Logging Mask Structure      |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_log_config_setmask(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *tree, uint32_t cmd)
{
    uint32_t length, equip_id, mask;
    bool request;

    length = tvb_reported_length(tvb);
    request = false;

    /* If Request assumed, there are 12 bytes before MASK */
    /* 12 = CMD_CODE (1) + RESERVED (3) + OPERATION (4) + EQUIP_ID (4) */
    mask = (uint32_t)tvb_get_uint32(tvb, 12, ENC_LITTLE_ENDIAN);
    mask = (mask + 7) / 8;

    if (length == mask + 16)
        request = true;

    /* If Response assumed, there are 16 bytes before MASK */
    /* 16 = CMD_CODE (1) + RESERVED (3) + OPERATION (4) + STATUS (4) + EQUIP_ID (4) */
    //mask = (uint32_t)tvb_get_uint32(tvb, 16, ENC_LITTLE_ENDIAN);
    //mask = (mask + 7) / 8;

    //if (length == mask + 20)
    //    request = false;

    offset = dissect_qcdiag_log_config_hdr(tvb, offset, pinfo, tree, cmd, request);

    if (!request) {
        /* Status */
        proto_tree_add_item(tree, hf_qcdiag_logcfg_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    /* Equipment ID */
    proto_tree_add_item_ret_uint(tree, hf_qcdiag_logcfg_equip_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &equip_id);
    offset += 4;

    /* Last Item */
    proto_tree_add_item_ret_uint(tree, hf_qcdiag_logcfg_last_item, tvb, offset, 4, ENC_LITTLE_ENDIAN, &mask);
    offset += 4;

    mask = (mask + 7) / 8;

    /* Log Codes Enabled */
    qcdiag_log_codes_enabled(tvb, offset, pinfo, tree, equip_id, mask);
}

/* Get Logging Mask Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | EQUIP_ID              |       4        | Specifies the equipment ID;             |
 * |                       |                | range is 0 to 15;                       |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Get Logging Mask Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | MASK_STRUCTURE        |    Variable    | Logging mask structure;                 |
 * |                       |                | this is the Logging Mask Structure      |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_log_config_getlogmask(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *tree, uint32_t cmd)
{
    uint32_t equip_id, mask;
    uint32_t length;
    bool request;

    length = tvb_reported_length(tvb);

    /* 12 = CMD_CODE (1) + RESERVED (3) + OPERATION (4) + EQUIP_ID (4) */
    request = (length == 12) ? true : false;

    offset = dissect_qcdiag_log_config_hdr(tvb, offset, pinfo, tree, cmd, request);

    /* Equipment ID */
    proto_tree_add_item_ret_uint(tree, hf_qcdiag_logcfg_equip_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &equip_id);
    offset += 4;

    if (request) return;

    /* Last Item */
    proto_tree_add_item_ret_uint(tree, hf_qcdiag_logcfg_last_item, tvb, offset, 4, ENC_LITTLE_ENDIAN, &mask);
    offset += 4;

    mask = (mask + 7) / 8;

    /* Log Codes Enabled */
    qcdiag_log_codes_enabled(tvb, offset, pinfo, tree, equip_id, mask);
}

static void
dissect_qcdiag_log_config(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    uint32_t operation;

    /* Operation value */
    operation = (uint32_t)tvb_get_uint8(tvb, offset+4);

    switch (operation) {
    case LOG_CONFIG_DISABLE_OP:
        dissect_qcdiag_log_config_disable_op(tvb, offset, pinfo, tree, cmd);
        break;
    case LOG_CONFIG_RETRIEVE_ID_RANGES_OP:
        dissect_qcdiag_log_config_retreive_id_ranges(tvb, offset, pinfo, tree, cmd);
        break;
    case LOG_CONFIG_RETRIEVE_VALID_MASK_OP:
        break;
    case LOG_CONFIG_SET_MASK_OP:
        dissect_qcdiag_log_config_setmask(tvb, offset, pinfo, tree, cmd);
        break;
    case LOG_CONFIG_GET_LOGMASK_OP:
        dissect_qcdiag_log_config_getlogmask(tvb, offset, pinfo, tree, cmd);
        break;
    default:
        break;
    }
}


/* Log On Demand Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (120 / 0x78) |       1        | Message ID: The CMD_CODE is set to 120  |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | LOG_CODE              |       2        | Log code requested                      |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Log On Demand Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (120 / 0x78) |       1        | Message ID: The CMD_CODE is set to 120  |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | LOG_CODE              |       2        | Log code received                       |
 * +-----------------------+----------------+-----------------------------------------+
 * | STATUS                |       1        | Specifies the status returned by DMSS;  |
 * |                       |                | values are in 0-4                       |
 * +-----------------------+----------------+-----------------------------------------+
 */

static const value_string qcdiag_log_on_demand_status_vals[] = {
    { 0, "Logging request and operation successful" },                       /* LOG_ON_DEMAND_SENT_S */
    { 1, "Logging request acknowledged, success of logging unknown" },       /* LOG_ON_DEMAND_ACKNOWLEDGE_S */
    { 2, "Logging attempted, but log packet was dropped or disabled" },      /* LOG_ON_DEMAND_DROPPED_S */
    { 3, "Request unsuccessful, log code not supported for this service" },  /* LOG_ON_DEMAND_NOT_SUPPORTED_S) */
    { 4, "Unable to log this packet in the present context" },               /* LOG_ON_DEMAND_FAILED_ATTEMPT_S */
    { 0, NULL }
};

static void
dissect_qcdiag_log_on_demand(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    uint32_t logcode, length;
    bool request;

    length = tvb_reported_length(tvb);

    request = (length == 3) ? true : false;

    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);

    /* LOG_CODE */
    proto_tree_add_item(subtree, hf_qcdiag_log_on_demand_logcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (request) return;

    /* STATUS */
    proto_tree_add_item(subtree, hf_qcdiag_log_on_demand_status, tvb, offset, 1, ENC_NA);
}


/* Diagnostic Protocol Loopback Request/Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (123 / 0x7B) |       1        | Message ID: The CMD_CODE is set to 123  |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | PAYLOAD               |       N        | Payload of Loopback message; any size   |
 * |                       |                | is allowed, as long as the service will |
 * |                       |                | accept a packet of that size            |
 * +-----------------------+----------------+-----------------------------------------+
 */

static void
dissect_qcdiag_protocol_loopback(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    uint32_t logcode, length;
    bool request;

    length = tvb_reported_length(tvb);

    /* It is not possible to distinguish between Request and Response */
    request = (length == 0) ? true : false;

    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);

    /* PAYLOAD */
    proto_tree_add_item(subtree, hf_qcdiag_protocol_loopback, tvb, offset, -1, ENC_NA);
}


/* Extended Build ID Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (124 / 0x7C) |       1        | Message ID: The CMD_CODE is set to 124  |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Extended Build ID Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (124 / 0x7C) |       1        | Message ID: The CMD_CODE is set to 124  |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | Version               |       1        | Version of the response; defines the    |
 * |                       |                | value of the MSM Revision field         |
 * +-----------------------+----------------+-----------------------------------------+
 * | Reserved              |       2        | Reserved                                |
 * +-----------------------+----------------+-----------------------------------------+
 * | MSM Revision          |  16, 20 or 32  | An extension of the MSM_VER field from  |
 * |                       |     (bits)     | the version number response packet;     |
 * |                       |                | length and format is dependent on the   |
 * |                       |                | Version field; values are:              |
 * |                       |                | 0 - Length is 16 bits                   |
 * |                       |                | 1 - Length is 20 bits                   |
 * |                       |                | 2 - Length is 32 bits                   |
 * +-----------------------+----------------+-----------------------------------------+
 * | Reserved              |  16, 12 or 0   | Padding to align the MSM Revision field |
 * |                       |     (bits)     | to 4 bytes; length is dependent on the  |
 * |                       |                | Version field; values are:              |
 * |                       |                | 0 - Length is 16 bits                   |
 * |                       |                | 1 - Length is 12 bits                   |
 * |                       |                | 2 - Length is 0 bits                    |
 * +-----------------------+----------------+-----------------------------------------+
 * | Mobile Model Number   |       4        | Manufacturer's mobile model number;     |
 * |                       |                | An extension of MOB_MODEL field from    |
 * |                       |                | the version number response packet      |
 * +-----------------------+----------------+-----------------------------------------+
 * | Mobile Software       |    Variable    | Mobile software revision string;        |
 * | Revision              |                | A NULL-terminated ASCII string;         |
 * |                       |                | if string is nonexistent, a NULL char   |
 * |                       |                | indicates an empty string;              |
 * |                       |                | an extension of the VER_DIR field from  |
 * |                       |                | the version number response packet      |
 * +-----------------------+----------------+-----------------------------------------+
 * | Mobile Model String   |    Variable    | Mobile model string;                    |
 * |                       |                | A NULL-terminated ASCII string;         |
 * |                       |                | if string is nonexistent, a NULL char   |
 * |                       |                | indicates an empty string               |
 * +-----------------------+----------------+-----------------------------------------+
 */

static const value_string qcdiag_ext_build_id_ver[] = {
    { 0, "Older targets with a 16-bit hardware version register" },
    { 1, "Older targets with a 32-bit hardware version register" },
    { 2, "Current AMSS targets with a 32-bit hardware version register" },
    { 0, NULL }
};

static void
dissect_qcdiag_ext_build_id(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, uint32_t cmd)
{
    proto_tree *subtree;
    uint32_t logcode, length;
    int end_offset;
    bool request;

    length = tvb_reported_length(tvb);

    request = (length == 1) ? true : false;

    logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, 0, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, request);

    if (request) return;

    /* Version */
    proto_tree_add_item(subtree, hf_qcdiag_ext_build_id_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Reserved */
    proto_tree_add_item(subtree, hf_qcdiag_ext_build_id_res, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* MSM Revision */
    proto_tree_add_item(subtree, hf_qcdiag_ext_build_id_msm, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Mobile Model Number */
    proto_tree_add_item(subtree, hf_qcdiag_ext_build_id_mob_model, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Returns the offset of the found needle, or -1 if not found */
    end_offset = tvb_find_uint8(tvb, offset, -1, '\0');

	if (end_offset == -1) return;

    /* Mobile Software Revision */
    if (offset == (uint32_t)end_offset)
        proto_tree_add_string(subtree, hf_qcdiag_ext_build_id_sw_rev, tvb, offset, 0, "(empty)");
    else
        proto_tree_add_item(subtree, hf_qcdiag_ext_build_id_sw_rev, tvb, offset, end_offset-offset, ENC_ASCII);
    offset = (uint32_t)end_offset + 1;

    /* Returns the offset of the found needle, or -1 if not found */
    end_offset = tvb_find_uint8(tvb, offset, -1, '\0');

	if (end_offset == -1) return;

    /* Mobile Model String */
    if (offset == (uint32_t)end_offset)
        proto_tree_add_string(subtree, hf_qcdiag_ext_build_id_mob_model_str, tvb, offset, 0, "(empty)");
    else
        proto_tree_add_item(subtree, hf_qcdiag_ext_build_id_mob_model_str, tvb, offset, end_offset-offset, ENC_ASCII);
}


/* Custom Message Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (255 / 0xFF) |       1        | Message ID: The CMD_CODE is set to 255  |
 * | (DIAG_MAX_F)          |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | MSG_TYPE              |       1        | Specifies the message type;             |
 * |                       |                | 0 - Response, 1 - Request               |
 * +-----------------------+----------------+-----------------------------------------+
 * | LOG_CODE              |       2        | Specifies the log code;                 |
 * |                       |                | The value 0 means ignore it             |
 * +-----------------------+----------------+-----------------------------------------+
 * | CMD_CODE (xxx / 0xYY) |       1        | Message ID: The CMD_CODE is set to      |
 * |                       |                | custom CMD_CODE value for this message  |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Custom Message Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE (255 / 0xFF) |       1        | Message ID: The CMD_CODE is set to 255  |
 * | (DIAG_MAX_F)          |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | MSG_TYPE              |       1        | Specifies the message type;             |
 * |                       |                | 0 - Response, 1 - Request               |
 * +-----------------------+----------------+-----------------------------------------+
 * | LOG_CODE              |       2        | Specifies the log code;                 |
 * |                       |                | The value 0 means ignore it             |
 * +-----------------------+----------------+-----------------------------------------+
 * | CMD_CODE (xxx / 0xYY) |       1        | Message ID: The CMD_CODE is set to      |
 * |                       |                | custom CMD_CODE value for this message  |
 * +-----------------------+----------------+-----------------------------------------+
 * | TEXT_DATA             |    Variable    | the custom data in text format;         |
 * |                       |                | "Line-based text data" dissector        |
 * +-----------------------+----------------+-----------------------------------------+
 */

/* Custom Message, for command codes which are not implemented yet.
 * Instead, the packets contain a custom header plus line-based text data.
 */
static void
dissect_qcdiag_custom(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *subtree;
    tvbuff_t *payload_tvb;
    uint32_t length, cmd, request, logcode, logcode_offset;
    const char *text;

    length = tvb_reported_length(tvb);

    /* DIAG_MAX_F */
    offset += 1;

    /* MSG_TYPE */
    request = (uint32_t)tvb_get_uint8(tvb, offset);
    offset += 1;

    /* LOG_CODE */
    logcode = (uint32_t)tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

    /* Determine if Log Code needs offset */
    logcode_offset = (logcode) ? 2 : 0;

    if (logcode == 0)
        logcode = (request) ? LOG_CODE_1X_DIAG_REQUEST : LOG_CODE_1X_DIAG_RES_STATUS;

    cmd = (uint32_t)tvb_get_uint8(tvb, offset+2);

    text = val_to_str_ext(pinfo->pool, cmd, &qcdiag_cmds_ext, "Unknown Command (0x%02x)");

    /* Set COL_INFO to the Command Code Name */
    col_set_str(pinfo->cinfo, COL_INFO, text);

    /* Append COL_INFO with Equipment ID */
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", try_val_to_str(logcode >> 12, qcdiag_logcfg_equipid));

    if (logcode_offset == 0) {
        /* Log Code 0x0000 was in the packet which we need to step over */
        offset += 2;
    }

    offset = qcdiag_add_cmd_hdr(tvb, offset, pinfo, tree, cmd, logcode, logcode_offset, -1);

    subtree = qcdiag_add_cmd_subtree(tvb, offset, pinfo, tree, cmd, (bool)request);

    if (request) return;

    payload_tvb = tvb_new_subset_length(tvb, offset, length-offset);

    call_dissector(text_lines_handle, payload_tvb, pinfo, subtree);
}


/* ################
 * ###   Main   ###
 * ################
 */

static int
dissect_qcdiag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *subtree;
    uint32_t offset = 0;
    uint32_t cmd;
    const char *text;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "QCDIAG");

    ti = proto_tree_add_item(tree, proto_qcdiag, tvb, offset, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_qcdiag);

    cmd = (uint32_t)tvb_get_uint8(tvb, offset);

    text = val_to_str_ext(pinfo->pool, cmd, &qcdiag_cmds_ext, "Unknown Command (0x%02x)");

    /* Set COL_INFO to the Command Code Name */
    col_set_str(pinfo->cinfo, COL_INFO, text);

    switch (cmd) {
    case DIAG_VERNO_F:
        dissect_qcdiag_verno(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_ESN_F:
        dissect_qcdiag_esn(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_BAD_CMD_F:
        dissect_qcdiag_bad_cmd(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_BAD_PARM_F:
        dissect_qcdiag_bad_parm(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_BAD_LEN_F:
        dissect_qcdiag_bad_len(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_BAD_MODE_F:
        dissect_qcdiag_bad_mode(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_MARKOV_RESET_F:
        dissect_qcdiag_markov_reset(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_DIAG_VER_F:
        dissect_qcdiag_diag_ver(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_TS_F:
        dissect_qcdiag_ts(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_PARM_SET_F:
        dissect_qcdiag_parm_set(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_MODE_CHANGE_F:
        dissect_qcdiag_mode_change(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_SUBSYS_CMD_F:
        dissect_qcdiag_subsys_cmd(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_LOG_CONFIG_F:
        dissect_qcdiag_log_config(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_LOG_ON_DEMAND_F:
        dissect_qcdiag_log_on_demand(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_PROTOCOL_LOOPBACK_F:
        dissect_qcdiag_protocol_loopback(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_EXT_BUILD_ID_F:
        dissect_qcdiag_ext_build_id(tvb, offset, pinfo, subtree, cmd);
        break;
    case DIAG_MAX_F:
        dissect_qcdiag_custom(tvb, offset, pinfo, subtree);
        break;
    default:
        return dissector_try_uint(qcdiag_dissector_table, cmd, tvb, pinfo, subtree);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_qcdiag(void)
{
    static hf_register_info hf[] = {
        { &hf_qcdiag_logcode,
          { "Log Code", "qcdiag.logcode",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &qcdiag_logcodes_ext, 0, NULL, HFILL }},
        { &hf_qcdiag_len,
          { "Length", "qcdiag.len",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0, NULL, HFILL }},
        { &hf_qcdiag_ver,
          { "Version", "qcdiag.ver",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_cmd,
          { "Command Code", "qcdiag.cmd",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &qcdiag_cmds_ext, 0, NULL, HFILL }},
        { &hf_qcdiag_verno_comp_date,
          { "Compilation Date", "qcdiag.verno.comp_date",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_verno_comp_time,
          { "Compilation Time", "qcdiag.verno.comp_time",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_verno_rel_date,
          { "Release Date", "qcdiag.verno.rel_date",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_verno_rel_time,
          { "Release Time", "qcdiag.verno.rel_time",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_verno_ver_dir,
          { "Version Directory", "qcdiag.verno.ver_dir",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_verno_scm,
          { "Station Class Mark", "qcdiag.verno.scm",
            FT_UINT8, BASE_DEC, NULL, 0, "SCM", HFILL }},
        { &hf_qcdiag_verno_mob_cai_rev,
          { "Mobile CAI Revision", "qcdiag.verno.mob_cai_rev",
            FT_UINT8, BASE_DEC, NULL, 0, "Mobile common air interface revision", HFILL }},
        { &hf_qcdiag_verno_mob_model,
          { "Mobile Model", "qcdiag.verno.mob_model",
            FT_UINT8, BASE_DEC, NULL, 0, "Manufacturer’s mobile model", HFILL }},
        { &hf_qcdiag_verno_mob_firm_rev,
          { "Mobile Firmware Revision", "qcdiag.verno.mob_firm_rev",
            FT_UINT16, BASE_DEC, NULL, 0, "Manufacturer’s mobile firmware revision", HFILL }},
        { &hf_qcdiag_verno_sci,
          { "Slot Cycle Index", "qcdiag.verno.sci",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_verno_msm_ver,
          { "MSM Revision", "qcdiag.verno.msm_ver",
            FT_STRING, BASE_NONE, NULL, 0, "Mobile station modem revision (Major.Minor)", HFILL }},
        { &hf_qcdiag_esn,
          { "ESN", "qcdiag.esn",
            FT_UINT32, BASE_HEX, NULL, 0, "Electronic Serial Number", HFILL }},
        { &hf_qcdiag_bad_cmd,
          { "Unrecognized Message", "qcdiag.bad_cmd",
            FT_BYTES, BASE_NONE, NULL, 0, "Bad Command", HFILL }},
        { &hf_qcdiag_bad_parm,
          { "Malformed Message", "qcdiag.bad_parm",
            FT_BYTES, BASE_NONE, NULL, 0, "Bad Parameters", HFILL }},
        { &hf_qcdiag_bad_len,
          { "Original Message", "qcdiag.bad_len",
            FT_BYTES, BASE_NONE, NULL, 0, "Bad Length", HFILL }},
        { &hf_qcdiag_bad_mode,
          { "Original Message", "qcdiag.bad_mode",
            FT_BYTES, BASE_NONE, NULL, 0, "Bad Mode", HFILL }},
        { &hf_qcdiag_diag_ver,
          { "Version", "qcdiag.diag_ver",
            FT_UINT16, BASE_DEC, VALS(qcdiag_diag_ver_vals), 0, NULL, HFILL }},
        { &hf_qcdiag_ts,
          { "Timestamp", "qcdiag.ts",
            FT_STRING, BASE_NONE, NULL, 0, "System Time Clock", HFILL }},
        { &hf_qcdiag_parm_set_id,
          { "Parameter ID", "qcdiag.parm_set.parm_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_parm_set_value,
          { "Parameter Value", "qcdiag.parm_set.parm_value",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_parm_set_time,
          { "Processing Time", "qcdiag.parm_set.set_time",
            FT_STRING, BASE_NONE, NULL, 0, "Time the operation was processed", HFILL }},
        { &hf_qcdiag_mode_change,
          { "Selected Operating Mode", "qcdiag.mode_change.mode",
            FT_UINT16, BASE_DEC, VALS(qcdiag_mode_change_mode_vals), 0, NULL, HFILL }},
        { &hf_qcdiag_subsys_id,
          { "Subsystem ID", "qcdiag.subsys_id",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &qcdiag_subsys_ext, 0, NULL, HFILL }},
        { &hf_qcdiag_subsys_cmd_code,
          { "Subsystem Command Code", "qcdiag.subsys_cmd_code",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_qcdiag_logcfg_res,
          { "Reserved", "qcdiag.logcfg.res",
		    FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_logcfg_operation,
          { "Operation", "qcdiag.logcfg.operation",
            FT_UINT32, BASE_DEC, VALS(qcdiag_logcfg_ops), 0, NULL, HFILL }},
        { &hf_qcdiag_logcfg_status,
          { "Status", "qcdiag.logcfg.status",
            FT_UINT32, BASE_DEC, VALS(qcdiag_logcfg_status), 0, NULL, HFILL }},
        { &hf_qcdiag_logcfg_equip_id,
          { "Equipment ID", "qcdiag.logcfg.equip_id",
            FT_UINT32, BASE_DEC, VALS(qcdiag_logcfg_equipid), 0, NULL, HFILL }},
        { &hf_qcdiag_logcfg_last_item,
          { "Last Item", "qcdiag.logcfg.last_item",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_log_on_demand_logcode,
          { "Log Code", "qcdiag.log_on_demand.logcode",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &qcdiag_logcodes_ext, 0, NULL, HFILL }},
        { &hf_qcdiag_log_on_demand_status,
          { "Log Code", "qcdiag.log_on_demand.status",
            FT_UINT8, BASE_DEC, VALS(qcdiag_log_on_demand_status_vals), 0, NULL, HFILL }},
        { &hf_qcdiag_protocol_loopback,
          { "Payload", "qcdiag.protloopb.payload",
            FT_BYTES, BASE_NONE, NULL, 0, "Protocol Loopback Test Payload", HFILL }},
        { &hf_qcdiag_ext_build_id_ver,
          { "Version", "qcdiag.ext_build_id.ver",
            FT_UINT16, BASE_DEC, VALS(qcdiag_ext_build_id_ver), 0, NULL, HFILL }},
		{ &hf_qcdiag_ext_build_id_res,
          { "Reserved", "qcdiag.ext_build_id.res",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_qcdiag_ext_build_id_msm,
          { "MSM Revision Extension", "qcdiag.ext_build_id.msm",
		    FT_UINT32, BASE_HEX, NULL, 0, "Extension of mobile station modem revision", HFILL }},
		{ &hf_qcdiag_ext_build_id_mob_model,
          { "Manufacturer’s Mobile Model Extension", "qcdiag.ext_build_id.mob_model",
		    FT_UINT32, BASE_DEC, NULL, 0, "Extension of manufacturer’s mobile model", HFILL }},
		{ &hf_qcdiag_ext_build_id_sw_rev,
          { "Mobile Software Revision", "qcdiag.ext_build_id.sw_rev",
		    FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_qcdiag_ext_build_id_mob_model_str,
          { "Mobile Model String", "qcdiag.ext_build_id.mob_model_str",
		    FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_qcdiag,
        &ett_qcdiag_cmd_subtree,
        &ett_qcdiag_log_codes_enabled,
    };

    proto_qcdiag = proto_register_protocol("Qualcomm Diagnostic", "QCDIAG", "qcdiag");
    proto_register_field_array(proto_qcdiag, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    qcdiag_dissector_table = register_dissector_table("qcdiag.cmd",
                    "QCDIAG Command", proto_qcdiag, FT_UINT8, BASE_DEC);

    qcdiag_subsys_dissector_table = register_dissector_table("qcdiag.subsys_id",
                    "QCDIAG Subsystem", proto_qcdiag, FT_UINT8, BASE_DEC);

    qcdiag_handle = register_dissector("qcdiag", dissect_qcdiag, proto_qcdiag);
}

void
proto_reg_handoff_qcdiag(void)
{
    dissector_add_uint("gsmtap.type", GSMTAP_TYPE_QC_DIAG, qcdiag_handle);

    data_handle = find_dissector("data");
	text_lines_handle = find_dissector("data-text-lines");
}

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
