/* packet-dlt.c
 * DLT Dissector
 * By Dr. Lars Voelker <lars.voelker@bmw.de> / <lars.voelker@technica-engineering.de>
 * Copyright 2013-2022 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * For further information about the "Diagnostic Log and Trace" (DLT) protocol see:
 * - GENIVI Alliance (https://www.genivi.org and https://github.com/GENIVI/)
 * - AUTOSAR (https://www.autosar.org) -> AUTOSAR_SWS_DiagnosticLogAndTrace.pdf
 */

/* This dissector currently only supports Version 1 of DLT. */

#include <config.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-udp.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/show_exception.h>
#include <epan/etypes.h>
#include <epan/tvbuff.h>

#include <epan/to_str.h>
#include <epan/uat.h>

#include <epan/dissectors/packet-dlt.h>

void proto_register_dlt(void);
void proto_reg_handoff_dlt(void);

void proto_register_dlt_storage_header(void);
void proto_reg_handoff_dlt_storage_header(void);

#define DLT_NAME                                        "DLT"
#define DLT_NAME_LONG                                   "Diagnostic Log and Trace (DLT)"
#define DLT_NAME_FILTER                                 "dlt"

#define DLT_STORAGE_HEADER_NAME                         "DLT Storage Header (short)"
#define DLT_STORAGE_HEADER_NAME_LONG                    "Shortened Diagnostic Log and Trace (DLT) Storage Header"
#define DLT_STORAGE_HEADER_NAME_FILTER                  "dlt.storage"

#define DLT_MIN_SIZE_FOR_PARSING                        4

#define DLT_HDR_TYPE_EXT_HEADER                         0x01
#define DLT_HDR_TYPE_MSB_FIRST                          0x02
#define DLT_HDR_TYPE_WITH_ECU_ID                        0x04
#define DLT_HDR_TYPE_WITH_SESSION_ID                    0x08
#define DLT_HDR_TYPE_WITH_TIMESTAMP                     0x10
#define DLT_HDR_TYPE_VERSION                            0xe0
#define DLT_MSG_INFO_VERBOSE                            0x01
#define DLT_MSG_INFO_MSG_TYPE                           0x0e
#define DLT_MSG_INFO_MSG_TYPE_INFO                      0xf0
#define DLT_MSG_INFO_MSG_TYPE_INFO_COMB                 0xfe

#define DLT_MSG_VERB_PARAM_LENGTH                       0x0000000f
#define DLT_MSG_VERB_PARAM_BOOL                         0x00000010
#define DLT_MSG_VERB_PARAM_SINT                         0x00000020
#define DLT_MSG_VERB_PARAM_UINT                         0x00000040
#define DLT_MSG_VERB_PARAM_FLOA                         0x00000080

#define DLT_MSG_VERB_PARAM_ARAY                         0x00000100
#define DLT_MSG_VERB_PARAM_STRG                         0x00000200
#define DLT_MSG_VERB_PARAM_RAWD                         0x00000400
#define DLT_MSG_VERB_PARAM_VARI                         0x00000800
#define DLT_MSG_VERB_PARAM_FIXP                         0x00001000
#define DLT_MSG_VERB_PARAM_TRAI                         0x00002000
#define DLT_MSG_VERB_PARAM_STRU                         0x00004000

#define DLT_MSG_VERB_PARAM_SCOD                         0x00038000
#define DLT_MSG_VERB_PARAM_SCOD_ASCII                   0x00000000
#define DLT_MSG_VERB_PARAM_SCOD_UTF8                    0x00008000
#define DLT_MSG_VERB_PARAM_SCOD_SHIFT                   15

#define DLT_MSG_VERB_PARAM_RES                          0xfffc0000

#define DLT_SERVICE_ID_SET_LOG_LEVEL                    0x01
#define DLT_SERVICE_ID_SET_TRACE_STATUS                 0x02
#define DLT_SERVICE_ID_GET_LOG_INFO                     0x03
#define DLT_SERVICE_ID_GET_DEFAULT_LOG_LEVEL            0x04
#define DLT_SERVICE_ID_STORE_CONFIGURATION              0x05
#define DLT_SERVICE_ID_RESTORE_TO_FACTORY_DEFAULT       0x06
#define DLT_SERVICE_ID_SET_COM_INTERFACE_STATUS         0x07
#define DLT_SERVICE_ID_SET_COM_INTERFACE_MAX_BANDWIDTH  0x08
#define DLT_SERVICE_ID_SET_VERBOSE_MODE                 0x09
#define DLT_SERVICE_ID_SET_MESSAGE_FILTERING            0x0a
#define DLT_SERVICE_ID_SET_TIMING_PACKETS               0x0b
#define DLT_SERVICE_ID_GET_LOCAL_TIME                   0x0c
#define DLT_SERVICE_ID_USE_ECU_ID                       0x0d
#define DLT_SERVICE_ID_USE_SESSION_ID                   0x0e
#define DLT_SERVICE_ID_USE_TIMESTAMP                    0x0f
#define DLT_SERVICE_ID_USE_EXTENDED_HEADER              0x10
#define DLT_SERVICE_ID_SET_DEFAULT_LOG_LEVEL            0x11
#define DLT_SERVICE_ID_SET_DEFAULT_TRACE_STATUS         0x12
#define DLT_SERVICE_ID_GET_SOFTWARE_VERSION             0x13
#define DLT_SERVICE_ID_MESSAGE_BUFFER_OVERFLOW          0x14
#define DLT_SERVICE_ID_GET_DEFAULT_TRACE_STATUS         0x15
#define DLT_SERVICE_ID_GET_COM_INTERFACE_STATUS         0x16
#define DLT_SERVICE_ID_GET_LOG_CHANNEL_NAMES            0x17
#define DLT_SERVICE_ID_GET_COM_INTERFACE_MAX_BANDWIDTH  0x18
#define DLT_SERVICE_ID_GET_VERBOSE_MODE_STATUS          0x19
#define DLT_SERVICE_ID_GET_MESSAGE_FILTERING_STATUS     0x1a
#define DLT_SERVICE_ID_GET_USE_ECUID                    0x1b
#define DLT_SERVICE_ID_GET_USE_SESSION_ID               0x1c
#define DLT_SERVICE_ID_GET_USE_TIMESTAMP                0x1d
#define DLT_SERVICE_ID_GET_USE_EXTENDED_HEADER          0x1e
#define DLT_SERVICE_ID_GET_TRACE_STATUS                 0x1f
#define DLT_SERVICE_ID_SET_LOG_CHANNEL_ASSIGNMENT       0x20
#define DLT_SERVICE_ID_SET_LOG_CHANNEL_THRESHOLD        0x21
#define DLT_SERVICE_ID_GET_LOG_CHANNEL_THRESHOLD        0x22
#define DLT_SERVICE_ID_BUFFER_OVERFLOW_NOTIFICATION     0x23
/* not found in specification but in github code */
#define DLT_USER_SERVICE_ID                             0xf00
#define DLT_SERVICE_ID_UNREGISTER_CONTEXT               0xf01
#define DLT_SERVICE_ID_CONNECTION_INFO                  0xf02
#define DLT_SERVICE_ID_TIMEZONE                         0xf03
#define DLT_SERVICE_ID_MARKER                           0xf04
#define DLT_SERVICE_ID_OFFLINE_LOGSTORAGE               0xF05
#define DLT_SERVICE_ID_PASSIVE_NODE_CONNECT             0xF06
#define DLT_SERVICE_ID_PASSIVE_NODE_CONNECTION_STATUS   0xF07
#define DLT_SERVICE_ID_SET_ALL_LOG_LEVEL                0xF08
#define DLT_SERVICE_ID_SET_ALL_TRACE_STATUS             0xF09

#define DLT_SERVICE_LOG_LEVEL_DEFAULT                   -1
#define DLT_SERVICE_LOG_LEVEL_NONE                      0
#define DLT_SERVICE_LOG_LEVEL_FATAL                     1
#define DLT_SERVICE_LOG_LEVEL_ERROR                     2
#define DLT_SERVICE_LOG_LEVEL_WARN                      3
#define DLT_SERVICE_LOG_LEVEL_INFO                      4
#define DLT_SERVICE_LOG_LEVEL_DEBUG                     5
#define DLT_SERVICE_LOG_LEVEL_VERBOSE                   6

#define DLT_SERVICE_TRACE_STATUS_DEFAULT                -1
#define DLT_SERVICE_TRACE_STATUS_OFF                    0
#define DLT_SERVICE_TRACE_STATUS_ON                     1

#define DLT_SERVICE_NEW_STATUS_OFF                      0
#define DLT_SERVICE_NEW_STATUS_ON                       1

#define DLT_SERVICE_STATUS_OK                           0x00
#define DLT_SERVICE_STATUS_NOT_SUPPORTED                0x01
#define DLT_SERVICE_STATUS_ERROR                        0x02

#define DLT_SERVICE_STATUS_LOG_LEVEL_NOT_SUPPORTED      1
#define DLT_SERVICE_STATUS_LOG_LEVEL_DLT_ERROR          2
#define DLT_SERVICE_STATUS_LOG_LEVEL_DLT_LOG_TRACE      6
#define DLT_SERVICE_STATUS_LOG_LEVEL_DLT_LOG_TRACE_TEXT 7
#define DLT_SERVICE_STATUS_LOG_LEVEL_DLT_NO_MATCH_CTX   8
#define DLT_SERVICE_STATUS_LOG_LEVEL_DLT_RESP_OVERFLOW  9

#define DLT_SERVICE_OPTIONS_WITH_LOG_TRACE              6
#define DLT_SERVICE_OPTIONS_WITH_LOG_TRACE_TEXT         7

static int proto_dlt = -1;
static int proto_dlt_storage_header = -1;

static dissector_handle_t dlt_handle_udp = NULL;
static dissector_handle_t dlt_handle_tcp = NULL;
static dissector_handle_t dlt_handle_storage = NULL;

/* Subdissectors */
static heur_dissector_list_t heur_subdissector_list;
static heur_dtbl_entry_t *heur_dtbl_entry;

/* header fields */
static int hf_dlt_header_type                           = -1;
static int hf_dlt_ht_ext_header                         = -1;
static int hf_dlt_ht_msb_first                          = -1;
static int hf_dlt_ht_with_ecuid                         = -1;
static int hf_dlt_ht_with_sessionid                     = -1;
static int hf_dlt_ht_with_timestamp                     = -1;
static int hf_dlt_ht_version                            = -1;

static int hf_dlt_msg_ctr                               = -1;
static int hf_dlt_length                                = -1;

static int hf_dlt_ecu_id                                = -1;
static int hf_dlt_session_id                            = -1;
static int hf_dlt_timestamp                             = -1;

static int hf_dlt_ext_hdr                               = -1;
static int hf_dlt_msg_info                              = -1;
static int hf_dlt_mi_verbose                            = -1;
static int hf_dlt_mi_msg_type                           = -1;
static int hf_dlt_mi_msg_type_info                      = -1;
static int hf_dlt_num_of_args                           = -1;
static int hf_dlt_app_id                                = -1;
static int hf_dlt_ctx_id                                = -1;

static int hf_dlt_payload                               = -1;
static int hf_dlt_message_id                            = -1;
static int hf_dlt_payload_data                          = -1;

static int hf_dlt_data_bool                             = -1;
static int hf_dlt_uint8                                 = -1;
static int hf_dlt_uint16                                = -1;
static int hf_dlt_uint32                                = -1;
static int hf_dlt_uint64                                = -1;
static int hf_dlt_int8                                  = -1;
static int hf_dlt_int16                                 = -1;
static int hf_dlt_int32                                 = -1;
static int hf_dlt_int64                                 = -1;
static int hf_dlt_float                                 = -1;
static int hf_dlt_double                                = -1;
static int hf_dlt_rawd                                  = -1;
static int hf_dlt_string                                = -1;

static int hf_dlt_service_options                       = -1;
static int hf_dlt_service_application_id                = -1;
static int hf_dlt_service_context_id                    = -1;
static int hf_dlt_service_log_level                     = -1;
static int hf_dlt_service_new_log_level                 = -1;
static int hf_dlt_service_trace_status                  = -1;
static int hf_dlt_service_new_trace_status              = -1;
static int hf_dlt_service_new_status                    = -1;
static int hf_dlt_service_reserved                      = -1;
static int hf_dlt_service_status                        = -1;
static int hf_dlt_service_length                        = -1;
static int hf_dlt_service_swVersion                     = -1;
static int hf_dlt_service_status_log_info               = -1;
static int hf_dlt_service_log_levels                    = -1;
static int hf_dlt_service_count                         = -1;
static int hf_dlt_service_app_desc                      = -1;
static int hf_dlt_service_ctx_desc                      = -1;

static int hf_dlt_storage_tstamp_s                      = -1;
static int hf_dlt_storage_tstamp_us                     = -1;
static int hf_dlt_storage_ecu_name                      = -1;
static int hf_dlt_storage_reserved                      = -1;

/* subtrees */
static gint ett_dlt                                     = -1;
static gint ett_dlt_hdr_type                            = -1;
static gint ett_dlt_ext_hdr                             = -1;
static gint ett_dlt_msg_info                            = -1;
static gint ett_dlt_payload                             = -1;
static gint ett_dlt_service_app_ids                     = -1;
static gint ett_dlt_service_app_id                      = -1;
static gint ett_dlt_service_ctx_id                      = -1;

static gint ett_dlt_storage                             = -1;

/***************************
 ****** String Tables ******
 ***************************/

/* DLT Message Types */
static const value_string dlt_msg_type[] = {
    {DLT_MSG_TYPE_LOG_MSG,                              "DLT Log Message"},
    {DLT_MSG_TYPE_TRACE_MSG,                            "DLT Trace Message"},
    {DLT_MSG_TYPE_NETWORK_MSG,                          "DLT Network Message"},
    {DLT_MSG_TYPE_CTRL_MSG,                             "DLT Control Message"},
    {0, NULL}
};

/* DLT Message Types Infos - this is not context free and uses bits of dlt_msg_type too! */
static const value_string dlt_msg_type_info[] = {
    {DLT_MSG_TYPE_INFO_LOG_FATAL,                       "Fatal"},
    {DLT_MSG_TYPE_INFO_LOG_ERROR,                       "Error"},
    {DLT_MSG_TYPE_INFO_LOG_WARN,                        "Warn"},
    {DLT_MSG_TYPE_INFO_LOG_INFO,                        "Info"},
    {DLT_MSG_TYPE_INFO_LOG_DEBUG,                       "Debug"},
    {DLT_MSG_TYPE_INFO_LOG_VERBOSE,                     "Verbose"},
    {DLT_MSG_TYPE_INFO_TRACE_VAR,                       "Variable"},
    {DLT_MSG_TYPE_INFO_TRACE_FUNC_IN,                   "Function In"},
    {DLT_MSG_TYPE_INFO_TRACE_FUNC_OUT,                  "Function Out"},
    {DLT_MSG_TYPE_INFO_TRACE_STATE,                     "State"},
    {DLT_MSG_TYPE_INFO_TRACE_VFB,                       "VFB"},
    {DLT_MSG_TYPE_INFO_NET_IPC,                         "IPC"},
    {DLT_MSG_TYPE_INFO_NET_CAN,                         "CAN"},
    {DLT_MSG_TYPE_INFO_NET_FLEXRAY,                     "FlexRay"},
    {DLT_MSG_TYPE_INFO_NET_MOST,                        "MOST"},
    {DLT_MSG_TYPE_INFO_CTRL_REQ,                        "Request"},
    {DLT_MSG_TYPE_INFO_CTRL_RES,                        "Response"},
    {DLT_MSG_TYPE_INFO_CTRL_TIME,                       "Time"},
    {0, NULL}
};

static const value_string dlt_service[] = {
    {DLT_SERVICE_ID_SET_LOG_LEVEL,                      "Set Log Level"},
    {DLT_SERVICE_ID_SET_TRACE_STATUS,                   "Set Trace Status"},
    {DLT_SERVICE_ID_GET_LOG_INFO,                       "Get Log Info"},
    {DLT_SERVICE_ID_GET_DEFAULT_LOG_LEVEL,              "Get Default Log Level"},
    {DLT_SERVICE_ID_STORE_CONFIGURATION,                "Store Configuration"},
    {DLT_SERVICE_ID_RESTORE_TO_FACTORY_DEFAULT,         "Restore Factory Default"},
    {DLT_SERVICE_ID_SET_COM_INTERFACE_STATUS,           "Set Com Interface Status (Deprecated!)"},
    {DLT_SERVICE_ID_SET_COM_INTERFACE_MAX_BANDWIDTH,    "Set Com Interface Max Bandwidth (Deprecated!)"},
    {DLT_SERVICE_ID_SET_VERBOSE_MODE,                   "Set Verbose Mode (Deprecated!)"},
    {DLT_SERVICE_ID_SET_MESSAGE_FILTERING,              "Set Message Filtering"},
    {DLT_SERVICE_ID_SET_TIMING_PACKETS,                 "Set Timing Packets (Deprecated!)"},
    {DLT_SERVICE_ID_GET_LOCAL_TIME,                     "Get Local Time (Deprecated!)"},
    {DLT_SERVICE_ID_USE_ECU_ID,                         "Use ECU ID (Deprecated!)"},
    {DLT_SERVICE_ID_USE_SESSION_ID,                     "Use Session ID (Deprecated!)"},
    {DLT_SERVICE_ID_USE_TIMESTAMP,                      "Use Timestamp (Deprecated!)"},
    {DLT_SERVICE_ID_USE_EXTENDED_HEADER,                "Use Extended Header (Deprecated!)"},
    {DLT_SERVICE_ID_SET_DEFAULT_LOG_LEVEL,              "Set Default Log Level"},
    {DLT_SERVICE_ID_SET_DEFAULT_TRACE_STATUS,           "Set Default Trace Status"},
    {DLT_SERVICE_ID_GET_SOFTWARE_VERSION,               "Get Software Version"},
    {DLT_SERVICE_ID_MESSAGE_BUFFER_OVERFLOW,            "Message Buffer Overflow (Deprecated!)"},
    {DLT_SERVICE_ID_GET_DEFAULT_TRACE_STATUS,           "Get Default trace Status"},
    {DLT_SERVICE_ID_GET_COM_INTERFACE_STATUS,           "Get Com Interface Status (Deprecated!)"},
    {DLT_SERVICE_ID_GET_LOG_CHANNEL_NAMES,              "Get Log Channel Names"},
    {DLT_SERVICE_ID_GET_COM_INTERFACE_MAX_BANDWIDTH,    "Get Com Interface Max Bandwidth (Deprecated!)"},
    {DLT_SERVICE_ID_GET_VERBOSE_MODE_STATUS,            "Get Verbose Mode Status (Deprecated!)"},
    {DLT_SERVICE_ID_GET_MESSAGE_FILTERING_STATUS,       "Get Message Filtering Status (Deprecated!)"},
    {DLT_SERVICE_ID_GET_USE_ECUID,                      "Get Use ECUID (Deprecated!)"},
    {DLT_SERVICE_ID_GET_USE_SESSION_ID,                 "Get Use Session ID (Deprecated!)"},
    {DLT_SERVICE_ID_GET_USE_TIMESTAMP,                  "Get Use Timestamp (Deprecated!)"},
    {DLT_SERVICE_ID_GET_USE_EXTENDED_HEADER,            "Get Use Extended Header (Deprecated!)"},
    {DLT_SERVICE_ID_GET_TRACE_STATUS,                   "Get Trace Status"},
    {DLT_SERVICE_ID_SET_LOG_CHANNEL_ASSIGNMENT,         "Set Log Channel Assignment"},
    {DLT_SERVICE_ID_SET_LOG_CHANNEL_THRESHOLD,          "Set Log Channel Threshold"},
    {DLT_SERVICE_ID_GET_LOG_CHANNEL_THRESHOLD,          "Get log Channel Threshold"},
    {DLT_SERVICE_ID_BUFFER_OVERFLOW_NOTIFICATION,       "Buffer Overflow Notification"},
    {DLT_USER_SERVICE_ID,                               "User Service"},
    {DLT_SERVICE_ID_UNREGISTER_CONTEXT,                 "Unregister Context (undefined)"},
    {DLT_SERVICE_ID_CONNECTION_INFO,                    "Connection Info (undefined)"},
    {DLT_SERVICE_ID_TIMEZONE,                           "Timezone (undefined)"},
    {DLT_SERVICE_ID_MARKER,                             "Marker (undefined)"},
    {DLT_SERVICE_ID_OFFLINE_LOGSTORAGE,                 "Offline Log Storage (undefined)"},
    {DLT_SERVICE_ID_PASSIVE_NODE_CONNECT,               "Passive Mode Connect (undefined)"},
    {DLT_SERVICE_ID_PASSIVE_NODE_CONNECTION_STATUS,     "Passive Mode Connection Status (undefined)"},
    {DLT_SERVICE_ID_SET_ALL_LOG_LEVEL,                  "Set All Log Level (undefined)"},
    {DLT_SERVICE_ID_SET_ALL_TRACE_STATUS,               "Set All Trace Status (undefined)"},
    {0, NULL}
};

static const value_string dlt_service_log_level[] = {
    {DLT_SERVICE_LOG_LEVEL_DEFAULT,                     "Default Log Level"},
    {DLT_SERVICE_LOG_LEVEL_NONE,                        "No Messages"},
    {DLT_SERVICE_LOG_LEVEL_FATAL,                       "Fatal"},
    {DLT_SERVICE_LOG_LEVEL_ERROR,                       "Error"},
    {DLT_SERVICE_LOG_LEVEL_WARN,                        "Warn"},
    {DLT_SERVICE_LOG_LEVEL_INFO,                        "Info"},
    {DLT_SERVICE_LOG_LEVEL_DEBUG,                       "Debug"},
    {DLT_SERVICE_LOG_LEVEL_VERBOSE,                     "Verbose"},
    {0, NULL}
};

static const value_string dlt_service_trace_status[] = {
    {DLT_SERVICE_TRACE_STATUS_DEFAULT,                  "Default Trace Status"},
    {DLT_SERVICE_TRACE_STATUS_OFF,                      "Off"},
    {DLT_SERVICE_TRACE_STATUS_ON,                       "On"},
    {0, NULL}
};

static const value_string dlt_service_new_status[] = {
    {DLT_SERVICE_NEW_STATUS_OFF,                        "Off"},
    {DLT_SERVICE_NEW_STATUS_ON,                         "On"},
    {0, NULL}
};

static const value_string dlt_service_status[] = {
    {DLT_SERVICE_STATUS_OK,                             "OK"},
    {DLT_SERVICE_STATUS_NOT_SUPPORTED,                  "Not supported"},
    {DLT_SERVICE_STATUS_ERROR,                          "Error"},
    {0, NULL}
};

static const value_string dlt_service_options[] = {
    {DLT_SERVICE_OPTIONS_WITH_LOG_TRACE,                "Loglevel and Trace status"},
    {DLT_SERVICE_OPTIONS_WITH_LOG_TRACE_TEXT,           "Loglevel, Trace status, and Textual"},
    {0, NULL}
};

#define DLT_SERVICE_OPTIONS_WITH_LOG_TRACE              6
#define DLT_SERVICE_OPTIONS_WITH_LOG_TRACE_TEXT         7

/*************************
 ****** Expert Info ******
 *************************/

static expert_field ef_dlt_unsupported_datatype = EI_INIT;
static expert_field ef_dlt_unsupported_length_datatype = EI_INIT;
static expert_field ef_dlt_unsupported_string_coding = EI_INIT;
static expert_field ef_dlt_unsupported_non_verbose_msg_type = EI_INIT;
static expert_field ef_dlt_buffer_too_short = EI_INIT;
static expert_field ef_dlt_parsing_error = EI_INIT;

static void
expert_dlt_unsupported_parameter(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, gint length) {
    if (tvb!=NULL) {
        proto_tree_add_expert(tree, pinfo, &ef_dlt_unsupported_datatype, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Unsupported Data Type!]");
}

static void
expert_dlt_unsupported_length_datatype(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ef_dlt_unsupported_length_datatype, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Unsupported Length of Datatype!]");
}

static void
expert_dlt_unsupported_string_coding(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ef_dlt_unsupported_string_coding, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Unsupported String Coding!]");
}

static void
expert_dlt_unsupported_non_verbose_msg_type(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ef_dlt_unsupported_non_verbose_msg_type, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Unsupported Non-Verbose Message Type!]");
}

static void
expert_dlt_buffer_too_short(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ef_dlt_buffer_too_short, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Buffer too short!]");
}

static void
expert_dlt_parsing_error(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ef_dlt_parsing_error, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Parsing Error!]");
}


/*****************************
 ****** Helper routines ******
 *****************************/

gint32
dlt_ecu_id_to_gint32(const gchar *ecu_id) {
    if (ecu_id == NULL) {
        return 0;
    }

    gint32 ret = 0;
    gint i;
    guint shift = 32;

    /* DLT allows only up to 4 ASCII chars! Unused is 0x00 */
    for (i = 0; i < (gint)strlen(ecu_id) && i < 4; i++) {
        shift -= 8;
        ret |= (gint32)ecu_id[i] << shift;
    }

    return ret;
}

/**********************************
 ****** The dissector itself ******
 **********************************/

static void
sanitize_buffer(guint8 *buf, gint length, guint32 encoding) {
    gint i = 0;

    for (i=0; i<length; i++) {
        /* UTF-8 uses the ASCII chars. So between 0x00 and 0x7f, we can treat it as ASCII. :) */
        if ((encoding==DLT_MSG_VERB_PARAM_SCOD_UTF8 || encoding==DLT_MSG_VERB_PARAM_SCOD_ASCII) && buf[i]!=0x00 && buf[i]<0x20) {
            /* write space for special chars */
            buf[i]=0x20;
        }
    }
}

static guint32
dissect_dlt_verbose_parameter_bool(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le _U_, guint32 type_info _U_, gint length) {
    guint8 value = 0;

    if (length != 1 || tvb_captured_length_remaining(tvb, offset) < length) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return 0;
    }

    value = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_dlt_data_bool, tvb, offset, 1, ENC_NA);

    if (value==0x00) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " false");
    } else if (value==0x01) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " true");
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " undefined");
    }

    return length;
}

static guint32
dissect_dlt_verbose_parameter_int(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint32 type_info _U_, gint length) {
    gint64 value = 0;

    if (tvb_captured_length_remaining(tvb, offset) < length) {
        return 0;
    }

    if (payload_le) {
        switch (length) {
        case 1:
            proto_tree_add_item(tree, hf_dlt_int8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            value = (gint8)tvb_get_guint8(tvb, offset);
            break;
        case 2:
            proto_tree_add_item(tree, hf_dlt_int16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            value = (gint16)tvb_get_letohs(tvb, offset);
            break;
        case 4:
            proto_tree_add_item(tree, hf_dlt_int32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            value = (gint32)tvb_get_letohl(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_int64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            value = (gint64)tvb_get_letoh64(tvb, offset);
            break;
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    } else {
        switch (length) {
        case 1:
            proto_tree_add_item(tree, hf_dlt_int8, tvb, offset, 1, ENC_BIG_ENDIAN);
            value = (gint8)tvb_get_guint8(tvb, offset);
            break;
        case 2:
            proto_tree_add_item(tree, hf_dlt_int16, tvb, offset, 2, ENC_BIG_ENDIAN);
            value = (gint16)tvb_get_ntohs(tvb, offset);
            break;
        case 4:
            proto_tree_add_item(tree, hf_dlt_int32, tvb, offset, 4, ENC_BIG_ENDIAN);
            value = (gint32)tvb_get_ntohl(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_int64, tvb, offset, 8, ENC_BIG_ENDIAN);
            value = (gint64)tvb_get_ntoh64(tvb, offset);
            break;
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " %" PRId64, value);
    return length;
}

static guint32
dissect_dlt_verbose_parameter_uint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint32 type_info _U_, gint length) {
    guint64 value = 0;

    if (tvb_captured_length_remaining(tvb, offset) < length) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return 0;
    }

    if (payload_le) {
        switch (length) {
        case 1:
            proto_tree_add_item(tree, hf_dlt_uint8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            value = tvb_get_guint8(tvb, offset);
            break;
        case 2:
            proto_tree_add_item(tree, hf_dlt_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            value = tvb_get_letohs(tvb, offset);
            break;
        case 4:
            proto_tree_add_item(tree, hf_dlt_uint32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            value = tvb_get_letohl(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_uint64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            value = tvb_get_letoh64(tvb, offset);
            break;
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    } else {
        switch (length) {
        case 1:
            proto_tree_add_item(tree, hf_dlt_uint8, tvb, offset, 1, ENC_BIG_ENDIAN);
            value = tvb_get_guint8(tvb, offset);
            break;
        case 2:
            proto_tree_add_item(tree, hf_dlt_uint16, tvb, offset, 2, ENC_BIG_ENDIAN);
            value = tvb_get_ntohs(tvb, offset);
            break;
        case 4:
            proto_tree_add_item(tree, hf_dlt_uint32, tvb, offset, 4, ENC_BIG_ENDIAN);
            value = tvb_get_ntohl(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_uint64, tvb, offset, 8, ENC_BIG_ENDIAN);
            value = tvb_get_ntoh64(tvb, offset);
            break;
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " %" PRIu64, value);
    return length;
}

static guint32
dissect_dlt_verbose_parameter_float(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint32 type_info _U_, gint length) {
    gdouble value = 0.0;

    if (tvb_captured_length_remaining(tvb, offset) < length) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return 0;
    }

    if (payload_le) {
        switch (length) {
        case 4:
            proto_tree_add_item(tree, hf_dlt_float, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            value = (gdouble)tvb_get_letohieee_float(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            value = tvb_get_letohieee_double(tvb, offset);
            break;
        case 2:
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    } else {
        switch (length) {
        case 4:
            proto_tree_add_item(tree, hf_dlt_float, tvb, offset, 4, ENC_BIG_ENDIAN);
            value = (gdouble)tvb_get_ntohieee_float(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_double, tvb, offset, 8, ENC_BIG_ENDIAN);
            value = tvb_get_ntohieee_double(tvb, offset);
            break;
        case 2:
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " %f", value);
    return length;
}

static guint32
dissect_dlt_verbose_parameter_raw_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint32 type_info _U_, gint length _U_) {
    guint16     len = 0;
    guint8     *buf = NULL;
    guint32     i = 0;
    guint32     offset_orig = offset;

    if (tvb_captured_length_remaining(tvb, offset) < 2) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return offset - offset_orig;
    }

    if (payload_le) {
        len = tvb_get_letohs(tvb, offset);
    } else {
        len = tvb_get_ntohs(tvb, offset);
    }
    offset += 2;

    if (tvb_captured_length_remaining(tvb, offset) < len) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return offset - offset_orig;
    }

    proto_tree_add_item(tree, hf_dlt_rawd, tvb, offset, len, ENC_NA);

    buf = (guint8 *) tvb_memdup(pinfo->pool, tvb, offset, len);
    offset += len;

    for (i=0; i<len; i++) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%02x", buf[i]);
    }

    return offset - offset_orig;
}

static guint32
dissect_dlt_verbose_parameter_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint32 type_info _U_, gint length _U_) {
    guint16     str_len = 0;
    guint32     encoding = 0;
    guint8     *buf = NULL;
    guint32     offset_orig = offset;
    gint        tmp_length = 0;
    tvbuff_t   *subtvb = NULL;

    if (tvb_captured_length_remaining(tvb, offset) < 2) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return offset - offset_orig;
    }

    if (payload_le) {
        str_len = tvb_get_letohs(tvb, offset);
    } else {
        str_len = tvb_get_ntohs(tvb, offset);
    }
    offset += 2;

    if (tvb_captured_length_remaining(tvb, offset) < str_len) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return offset - offset_orig;
    }

    encoding = (type_info & DLT_MSG_VERB_PARAM_SCOD);

    if (encoding!=DLT_MSG_VERB_PARAM_SCOD_ASCII && encoding!=DLT_MSG_VERB_PARAM_SCOD_UTF8) {
        expert_dlt_unsupported_string_coding(tree, pinfo, tvb, offset, str_len);
        return -1;
    }

    subtvb = tvb_new_subset_length_caplen(tvb, offset, str_len, str_len);

    if (encoding == DLT_MSG_VERB_PARAM_SCOD_ASCII) {
        buf = tvb_get_stringz_enc(pinfo->pool, subtvb, 0, &tmp_length, ENC_ASCII);
    }
    else {
        buf = tvb_get_stringz_enc(pinfo->pool, subtvb, 0, &tmp_length, ENC_UTF_8);
    }

    if ( buf != NULL && tmp_length > 0) {
        sanitize_buffer(buf, tmp_length, encoding);
        proto_tree_add_item(tree, hf_dlt_string, tvb, offset, str_len, ENC_ASCII | ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", buf);
    } else {
        expert_dlt_parsing_error(tree, pinfo, tvb, offset, str_len);
    }

    offset += str_len;
    return offset - offset_orig;
}

static guint32
dissect_dlt_verbose_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le) {
    guint32     type_info = 0;
    guint8      length_field = 0;
    gint        length = 0;
    guint32     offset_orig = offset;

    /* we need at least the uint32 type info to decide on how much more bytes we need */
    if (tvb_captured_length_remaining(tvb, offset) < 4) {
        expert_dlt_parsing_error(tree, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset));
        return -1;
    }

    if (payload_le) {
        type_info = tvb_get_letohl(tvb, offset);
    } else {
        type_info = tvb_get_ntohl(tvb, offset);
    }
    offset +=4;

    length_field = type_info & DLT_MSG_VERB_PARAM_LENGTH;

    length=0;
    switch (length_field) {
    case 0x01:
        length=1;
        break;
    case 0x02:
        length=2;
        break;
    case 0x03:
        length=4;
        break;
    case 0x04:
        length=8;
        break;
    case 0x05:
        length=16;
        break;
    }

    if (length > 0 && tvb_captured_length_remaining(tvb, offset) < length) {
        return -1;
    }

    switch (type_info & (~ (DLT_MSG_VERB_PARAM_LENGTH | DLT_MSG_VERB_PARAM_SCOD))) {
    case DLT_MSG_VERB_PARAM_BOOL:
        offset += dissect_dlt_verbose_parameter_bool(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    case DLT_MSG_VERB_PARAM_SINT:
        offset += dissect_dlt_verbose_parameter_int(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    case DLT_MSG_VERB_PARAM_UINT:
        offset += dissect_dlt_verbose_parameter_uint(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    case DLT_MSG_VERB_PARAM_FLOA:
        offset += dissect_dlt_verbose_parameter_float(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    case DLT_MSG_VERB_PARAM_STRG:
        offset += dissect_dlt_verbose_parameter_string(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    case DLT_MSG_VERB_PARAM_RAWD:
        offset += dissect_dlt_verbose_parameter_raw_data(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    default:
        expert_dlt_unsupported_parameter(tree, pinfo, tvb, offset, 0);
    }

    if ( (offset-offset_orig) <= 4) {
        return 0;
    } else {
        return offset - offset_orig;
    }
}

static guint32
dissect_dlt_verbose_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint8 num_of_args) {
    guint32     i = 0;
    guint32     offset_orig = offset;
    guint32     len_parsed = 5;

    while (len_parsed>4 && i<num_of_args) {
        len_parsed = dissect_dlt_verbose_parameter(tvb, pinfo, tree, offset, payload_le);
        offset += len_parsed;
        i++;
    }

    return offset - offset_orig;
}

static int
dissect_dlt_non_verbose_payload_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, gboolean payload_le, guint8 msg_type _U_,
                                        guint8 msg_type_info_comb, guint32 message_id) {
    proto_item     *ti = NULL;
    proto_tree     *subtree;
    proto_tree     *subtree2;
    proto_tree     *subtree3;
    int             ret = 0;
    gint            len;
    guint32         offset_orig;
    guint           tmp_length = 0;
    guint           encoding = ENC_BIG_ENDIAN;
    guint           status;
    guint           appid_count;
    guint           ctxid_count;
    guint           i;
    guint           j;

    offset_orig = offset;

    if (payload_le) {
        encoding = ENC_LITTLE_ENDIAN;
    }

    len = tvb_captured_length_remaining(tvb, offset);
    if (len == 0) {
        return 0;
    }

    if (msg_type_info_comb == DLT_MSG_TYPE_INFO_CTRL_REQ) {
        switch (message_id) {
        case DLT_SERVICE_ID_SET_LOG_LEVEL:
            proto_tree_add_item(tree, hf_dlt_service_application_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_context_id, tvb, offset + 4, 4, ENC_ASCII | ENC_NA );
            proto_tree_add_item(tree, hf_dlt_service_new_log_level, tvb, offset + 8, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset + 9, 4, ENC_NA);
            ret = 13;
            break;
        case DLT_SERVICE_ID_SET_TRACE_STATUS:
            proto_tree_add_item(tree, hf_dlt_service_application_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_context_id, tvb, offset + 4, 4, ENC_ASCII | ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_new_trace_status, tvb, offset + 8, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset + 9, 4, ENC_NA);
            ret = 13;
            break;
        case DLT_SERVICE_ID_GET_LOG_INFO:
            proto_tree_add_item(tree, hf_dlt_service_options, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_application_id, tvb, offset + 1, 4, ENC_ASCII | ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_context_id, tvb, offset + 5, 4, ENC_ASCII | ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset + 9, 4, ENC_NA);
            break;
        case DLT_SERVICE_ID_SET_MESSAGE_FILTERING:
            proto_tree_add_item(tree, hf_dlt_service_new_status, tvb, offset, 1, ENC_NA);
            ret = 1;
            break;
        case DLT_SERVICE_ID_SET_DEFAULT_LOG_LEVEL:
            proto_tree_add_item(tree, hf_dlt_service_new_log_level, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset + 1, 4, ENC_NA);
            ret = 5;
            break;
        case DLT_SERVICE_ID_SET_DEFAULT_TRACE_STATUS:
            proto_tree_add_item(tree, hf_dlt_service_new_trace_status, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset + 1, 4, ENC_NA);
            ret = 5;
            break;
        }
    } else if (msg_type_info_comb == DLT_MSG_TYPE_INFO_CTRL_RES) {
        switch (message_id) {
        case DLT_SERVICE_ID_SET_LOG_LEVEL:
        case DLT_SERVICE_ID_SET_TRACE_STATUS:
        case DLT_SERVICE_ID_STORE_CONFIGURATION:
        case DLT_SERVICE_ID_RESTORE_TO_FACTORY_DEFAULT:
        case DLT_SERVICE_ID_SET_VERBOSE_MODE:
        case DLT_SERVICE_ID_SET_MESSAGE_FILTERING:
        case DLT_SERVICE_ID_SET_TIMING_PACKETS:
        case DLT_SERVICE_ID_SET_DEFAULT_LOG_LEVEL:
        case DLT_SERVICE_ID_SET_DEFAULT_TRACE_STATUS:
        case DLT_SERVICE_ID_SET_LOG_CHANNEL_ASSIGNMENT:
            proto_tree_add_item(tree, hf_dlt_service_status, tvb, offset, 1, ENC_NA);
            ret = 1;
            break;
        case DLT_SERVICE_ID_GET_LOG_INFO:
            proto_tree_add_item_ret_uint(tree, hf_dlt_service_status_log_info, tvb, offset, 1, ENC_NA, &status);
            offset += 1;
            ti = proto_tree_add_item(tree, hf_dlt_service_log_levels, tvb, offset, len - 4, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_dlt_service_app_ids);

            proto_tree_add_item_ret_uint(subtree, hf_dlt_service_count, tvb, offset, 2, encoding, &appid_count);
            offset += 2;
            /* loop over all app id entries */
            for (i=0; i<appid_count; i++) {
                ti = proto_tree_add_item(subtree, hf_dlt_service_application_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
                offset += 4;
                subtree2 = proto_item_add_subtree(ti, ett_dlt_service_app_id);

                proto_tree_add_item_ret_uint(subtree2, hf_dlt_service_count, tvb, offset, 2, encoding, &ctxid_count);
                offset += 2;
                /* loop over all ctx id entries */
                for (j = 0; j < ctxid_count; j++) {
                    ti = proto_tree_add_item(subtree2, hf_dlt_service_context_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
                    subtree3 = proto_item_add_subtree(ti, ett_dlt_service_ctx_id);
                    offset += 4;

                    proto_tree_add_item(subtree3, hf_dlt_service_log_level, tvb, offset, 1, encoding);
                    offset += 1;
                    proto_tree_add_item(subtree3, hf_dlt_service_trace_status, tvb, offset, 1, encoding);
                    offset += 1;

                    if (status == DLT_SERVICE_STATUS_LOG_LEVEL_DLT_LOG_TRACE_TEXT) {
                        proto_tree_add_item_ret_uint(subtree2, hf_dlt_service_count, tvb, offset, 2, encoding, &tmp_length);
                        offset += 2;
                        proto_tree_add_item(subtree2, hf_dlt_service_ctx_desc, tvb, offset, tmp_length, ENC_ASCII | ENC_NA);
                        offset += tmp_length;
                    }
                }
                if (status == DLT_SERVICE_STATUS_LOG_LEVEL_DLT_LOG_TRACE_TEXT) {
                    proto_tree_add_item_ret_uint(subtree, hf_dlt_service_count, tvb, offset, 2, encoding, &tmp_length);
                    offset += 2;
                    proto_tree_add_item(subtree, hf_dlt_service_app_desc, tvb, offset, tmp_length, ENC_ASCII | ENC_NA);
                    offset += tmp_length;
                }
            }

            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset_orig + len - 4, 4, ENC_NA);
            ret = len;
            break;
        case DLT_SERVICE_ID_GET_DEFAULT_LOG_LEVEL:
            proto_tree_add_item(tree, hf_dlt_service_status, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_log_level, tvb, offset+1, 1, ENC_NA);
            ret = 2;
            break;
        case DLT_SERVICE_ID_GET_SOFTWARE_VERSION:
            proto_tree_add_item(tree, hf_dlt_service_status, tvb, offset, 1, ENC_NA);
            proto_tree_add_item_ret_uint(tree, hf_dlt_service_length, tvb, offset + 1, 4, encoding, &tmp_length);
            if ((guint)len >= 5 + tmp_length) {
                proto_tree_add_item(tree, hf_dlt_service_swVersion, tvb, offset + 5, tmp_length, ENC_ASCII | ENC_NA);
            } else {
                expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, len);
            }
            ret = 5 + tmp_length;
            break;
        }
    }
    if (ret==0 && len>0) {
        proto_tree_add_item(tree, hf_dlt_payload_data, tvb, offset, len, encoding);
        ret = len;
    }
    return ret;
}

static int
dissect_dlt_non_verbose_payload_message_handoff(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean payload_le,
                                                guint8 msg_type, guint8 msg_type_info_comb, guint32 message_id, const guint8 *ecu_id) {

    dlt_info_t dlt_info;

    dlt_info.message_id = message_id;
    dlt_info.little_endian = payload_le;
    dlt_info.message_type = msg_type;
    dlt_info.message_type_info_comb = msg_type_info_comb;
    dlt_info.ecu_id = (const gchar *)ecu_id;

    return dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, &dlt_info);
}

static int
dissect_dlt_non_verbose_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root_tree, proto_tree *tree, guint32 offset, gboolean payload_le,
                                guint8 msg_type, guint8 msg_type_info_comb, const guint8 *ecu_id) {
    guint32         message_id = 0;
    tvbuff_t       *subtvb = NULL;
    guint32         offset_orig = offset;
    const gchar    *message_id_name = NULL;
    proto_item     *ti;

    if (payload_le) {
        ti = proto_tree_add_item(tree, hf_dlt_message_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        message_id = tvb_get_letohl(tvb, offset);
    } else {
        ti = proto_tree_add_item(tree, hf_dlt_message_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        message_id = tvb_get_ntohl(tvb, offset);
    }
    offset += 4;

    if (msg_type==DLT_MSG_TYPE_CTRL_MSG && (msg_type_info_comb==DLT_MSG_TYPE_INFO_CTRL_REQ || msg_type_info_comb==DLT_MSG_TYPE_INFO_CTRL_RES)) {
        if (tvb_captured_length_remaining(tvb, offset) == 0) {
            return offset - offset_orig;
        }

        message_id_name = try_val_to_str(message_id, dlt_service);

        if (message_id_name == NULL) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Unknown Non-Verbose Message (ID: 0x%02x)", message_id);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s (ID: 0x%02x)", message_id_name, message_id);
            proto_item_append_text(ti, " (%s)", message_id_name);
        }

        subtvb = tvb_new_subset_length_caplen(tvb, offset, tvb_captured_length_remaining(tvb, offset), tvb_captured_length_remaining(tvb, offset));
        dissect_dlt_non_verbose_payload_message(subtvb, pinfo, tree, 0, payload_le, msg_type, msg_type_info_comb, message_id);
    } else if(msg_type == DLT_MSG_TYPE_LOG_MSG) {
        subtvb = tvb_new_subset_length_caplen(tvb, offset, tvb_captured_length_remaining(tvb, offset), tvb_captured_length_remaining(tvb, offset));
        if (dissect_dlt_non_verbose_payload_message_handoff(subtvb, pinfo, root_tree, payload_le, msg_type, msg_type_info_comb, message_id, ecu_id) <= 0) {
            proto_tree_add_item(tree, hf_dlt_payload_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), payload_le);
        }
    } else {
        expert_dlt_unsupported_non_verbose_msg_type(tree, pinfo, tvb, offset, 0);
    }

    return offset - offset_orig;
}

static int
dissect_dlt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint32 offset_orig) {
    proto_item     *ti;
    proto_tree     *dlt_tree = NULL;
    proto_tree     *ext_hdr_tree = NULL;
    proto_tree     *subtree = NULL;
    guint32         offset = offset_orig;

    guint8          header_type = 0;
    gboolean        ext_header = FALSE;
    gboolean        payload_le = FALSE;
    guint16         length = 0;

    guint8          msg_info = 0;
    gboolean        verbose = FALSE;
    guint8          msg_type = 0;
    guint8          msg_type_info = 0;
    guint8          msg_type_info_comb = 0;

    guint8          num_of_args = 0;
    gdouble         timestamp = 0.0;

    gint            captured_length = tvb_captured_length_remaining(tvb, offset);

    const guint8   *ecu_id = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, DLT_NAME);
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", DLT_NAME);

    if (captured_length < DLT_MIN_SIZE_FOR_PARSING) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, captured_length);
        return captured_length;
    }

    header_type = tvb_get_guint8(tvb, offset);
    ext_header = ((header_type & DLT_HDR_TYPE_EXT_HEADER) == DLT_HDR_TYPE_EXT_HEADER);
    payload_le = ((header_type & DLT_HDR_TYPE_MSB_FIRST) != DLT_HDR_TYPE_MSB_FIRST);

    ti = proto_tree_add_item(tree, proto_dlt, tvb, offset, -1, ENC_NA);
    dlt_tree = proto_item_add_subtree(ti, ett_dlt);

    ti = proto_tree_add_item(dlt_tree, hf_dlt_header_type, tvb, offset, 1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_dlt_hdr_type);

    proto_tree_add_item(subtree, hf_dlt_ht_ext_header, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlt_ht_msb_first, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlt_ht_with_ecuid, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlt_ht_with_sessionid, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlt_ht_with_timestamp, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlt_ht_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(dlt_tree, hf_dlt_msg_ctr, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(dlt_tree, hf_dlt_length, tvb, offset, 2, ENC_NA);
    offset += 2;

    if ((header_type & DLT_HDR_TYPE_WITH_ECU_ID) == DLT_HDR_TYPE_WITH_ECU_ID) {
        proto_tree_add_item_ret_string(dlt_tree, hf_dlt_ecu_id, tvb, offset, 4, ENC_ASCII | ENC_NA, pinfo->pool, &ecu_id);
        offset += 4;
    }

    if ((header_type & DLT_HDR_TYPE_WITH_SESSION_ID) == DLT_HDR_TYPE_WITH_SESSION_ID) {
        proto_tree_add_item(dlt_tree, hf_dlt_session_id, tvb, offset, 4, ENC_NA);
        offset += 4;
    }

    if ((header_type & DLT_HDR_TYPE_WITH_TIMESTAMP) == DLT_HDR_TYPE_WITH_TIMESTAMP) {
        timestamp = (tvb_get_ntohl(tvb, offset)/10000.0);
        proto_tree_add_double_format_value(dlt_tree, hf_dlt_timestamp, tvb, offset, 4, timestamp, "%.4f s", timestamp);
        offset += 4;
    }

    if ((header_type & DLT_HDR_TYPE_EXT_HEADER) == DLT_HDR_TYPE_EXT_HEADER) {
        ti = proto_tree_add_item(dlt_tree, hf_dlt_ext_hdr, tvb, offset, 10, ENC_NA);
        ext_hdr_tree = proto_item_add_subtree(ti, ett_dlt_ext_hdr);

        ti = proto_tree_add_item(ext_hdr_tree, hf_dlt_msg_info, tvb, offset, 1, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_dlt_msg_info);

        proto_tree_add_item(subtree, hf_dlt_mi_verbose, tvb, offset, 1, ENC_NA);

        msg_info = tvb_get_guint8(tvb, offset);
        verbose = (msg_info & DLT_MSG_INFO_VERBOSE) == DLT_MSG_INFO_VERBOSE;
        msg_type_info_comb = msg_info & DLT_MSG_INFO_MSG_TYPE_INFO_COMB;
        msg_type = (msg_type_info_comb & DLT_MSG_INFO_MSG_TYPE) >> 1;
        msg_type_info = (msg_type_info_comb & DLT_MSG_INFO_MSG_TYPE_INFO) >> 4;

        proto_tree_add_item(subtree, hf_dlt_mi_msg_type, tvb, offset, 1, ENC_NA);
        proto_tree_add_uint_format_value(subtree, hf_dlt_mi_msg_type_info, tvb, offset, 1, msg_info, "%s (%d)",
            val_to_str(msg_type_info_comb, dlt_msg_type_info, "Unknown Message Type Info"), msg_type_info);
        offset += 1;

        num_of_args = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(ext_hdr_tree, hf_dlt_num_of_args, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(ext_hdr_tree, hf_dlt_app_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
        offset += 4;

        proto_tree_add_item(ext_hdr_tree, hf_dlt_ctx_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
        offset += 4;
    }

    ti = proto_tree_add_item(dlt_tree, hf_dlt_payload, tvb, offset, length - offset, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_dlt_payload);

    col_append_fstr(pinfo->cinfo, COL_INFO, ":");

    if (!ext_header || !verbose) {
        offset += dissect_dlt_non_verbose_payload(tvb, pinfo, tree, subtree, offset, payload_le, msg_type, msg_type_info_comb, ecu_id);
    } else {
        offset += dissect_dlt_verbose_payload(tvb, pinfo, subtree, offset, payload_le, num_of_args);
    }

    col_set_fence(pinfo->cinfo, COL_INFO);
    return offset - offset_orig;
}

static int
dissect_dlt_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_dlt(tvb, pinfo, tree, data, 0);
}

static guint
get_dlt_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void* data _U_) {
    return tvb_get_ntohs(tvb, offset + 2);
}

static int
dissect_dlt_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, DLT_MIN_SIZE_FOR_PARSING, get_dlt_message_len, dissect_dlt_msg, data);
    return tvb_reported_length(tvb);
}

static int
dissect_dlt_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return udp_dissect_pdus(tvb, pinfo, tree, DLT_MIN_SIZE_FOR_PARSING, NULL, get_dlt_message_len, dissect_dlt_msg, data);
}

static int
dissect_dlt_storage_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    proto_tree *dlt_storage_tree;
    proto_item *ti;

    guint32     offset = 0;

    ti = proto_tree_add_item(tree, proto_dlt_storage_header, tvb, offset, 16, ENC_NA);
    dlt_storage_tree = proto_item_add_subtree(ti, ett_dlt_storage);

    proto_tree_add_item(dlt_storage_tree, hf_dlt_storage_tstamp_s, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(dlt_storage_tree, hf_dlt_storage_tstamp_us, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* setting source to ECU Name of the encapsulation header */
    set_address_tvb(&(pinfo->src), AT_STRINGZ, 4, tvb, offset);
    proto_tree_add_item(dlt_storage_tree, hf_dlt_storage_ecu_name, tvb, offset, 5, ENC_ASCII);
    offset += 5;

    proto_tree_add_item(dlt_storage_tree, hf_dlt_storage_reserved, tvb, offset, 3, ENC_NA);
    return 16 + dissect_dlt(tvb, pinfo, tree, data, 16);
}

void proto_register_dlt(void) {
    expert_module_t    *expert_module_DLT;

    static hf_register_info hf_dlt[] = {
        { &hf_dlt_header_type, {
            "Header Type", "dlt.header_type",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dlt_ht_ext_header, {
            "Extended Header", "dlt.header_type.ext_header",
            FT_BOOLEAN, 8, NULL, DLT_HDR_TYPE_EXT_HEADER, NULL, HFILL }},
        { &hf_dlt_ht_msb_first, {
            "MSB First", "dlt.header_type.msb_first",
            FT_BOOLEAN, 8, NULL, DLT_HDR_TYPE_MSB_FIRST, NULL, HFILL }},
        { &hf_dlt_ht_with_ecuid, {
            "With ECU ID", "dlt.header_type.with_ecu_id",
            FT_BOOLEAN, 8, NULL, DLT_HDR_TYPE_WITH_ECU_ID, NULL, HFILL }},
        { &hf_dlt_ht_with_sessionid, {
            "With Session ID", "dlt.header_type.with_session_id",
            FT_BOOLEAN, 8, NULL, DLT_HDR_TYPE_WITH_SESSION_ID, NULL, HFILL }},
        { &hf_dlt_ht_with_timestamp, {
            "With Timestamp", "dlt.header_type.with_timestamp",
            FT_BOOLEAN, 8, NULL, DLT_HDR_TYPE_WITH_TIMESTAMP, NULL, HFILL }},
        { &hf_dlt_ht_version, {
            "Version", "dlt.header_type.version",
            FT_UINT8, BASE_DEC, NULL, DLT_HDR_TYPE_VERSION, NULL, HFILL }},

        { &hf_dlt_msg_ctr, {
            "Message Counter", "dlt.msg_counter",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_length, {
            "Length", "dlt.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_ecu_id, {
            "ECU ID", "dlt.ecu_id",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_session_id, {
            "Session ID", "dlt.session_id",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_timestamp, {
            "Timestamp", "dlt.timestamp",
            FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dlt_ext_hdr, {
            "Extended Header", "dlt.ext_header",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_msg_info, {
            "Message Info", "dlt.msg_info",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_mi_verbose, {
            "Verbose", "dlt.msg_info.verbose",
            FT_BOOLEAN, 8, NULL, DLT_MSG_INFO_VERBOSE, NULL, HFILL }},
        { &hf_dlt_mi_msg_type, {
            "Message Type", "dlt.msg_info.msg_type",
            FT_UINT8, BASE_DEC, VALS(dlt_msg_type), DLT_MSG_INFO_MSG_TYPE, NULL, HFILL }},
        { &hf_dlt_mi_msg_type_info, {
            "Message Type Info", "dlt.msg_info.msg_type_info",
            FT_UINT8, BASE_DEC, NULL, DLT_MSG_INFO_MSG_TYPE_INFO, NULL, HFILL }},
        { &hf_dlt_num_of_args, {
            "Number of Arguments", "dlt.num_of_args",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_app_id, {
            "Application ID", "dlt.application_id",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_ctx_id, {
            "Context ID", "dlt.context_id",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dlt_payload, {
            "Payload", "dlt.payload",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_message_id, {
            "Message ID", "dlt.message_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_payload_data, {
            "Payload Data", "dlt.payload.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dlt_data_bool, {
            "(bool)", "dlt.data.bool",
            FT_BOOLEAN, 1, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_uint8, {
            "(uint8)", "dlt.data.uint8",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_uint16, {
            "(uint16)", "dlt.data.uint16",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_uint32, {
            "(uint32)", "dlt.data.uint32",
           FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_uint64, {
            "(uint64)", "dlt.data.uint64",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_int8, {
            "(int8)", "dlt.data.int8",
            FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_int16, {
            "(int16)", "dlt.data.int16",
            FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_int32, {
            "(int32)", "dlt.data.int32",
            FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_int64, {
            "(int64)", "dlt.data.int64",
            FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_float, {
            "(float)", "dlt.data.float",
            FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_double, {
            "(double)", "dlt.data.double",
            FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_rawd, {
            "(rawd)", "dlt.data.rawd",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_dlt_string, {
            "(string)", "dlt.data.string",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_dlt_service_options, {
            "Options", "dlt.service.options",
            FT_UINT8, BASE_DEC, VALS(dlt_service_options), 0x0, NULL, HFILL } },
        { &hf_dlt_service_application_id, {
            "Application ID", "dlt.service.application_id",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_context_id, {
            "Context ID", "dlt.service.context_id",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_log_level, {
            "Log Level", "dlt.service.log_level",
            FT_INT8, BASE_DEC, VALS(dlt_service_log_level), 0x0, NULL, HFILL } },
        { &hf_dlt_service_new_log_level, {
            "New Log Level", "dlt.service.new_log_level",
            FT_INT8, BASE_DEC, VALS(dlt_service_log_level), 0x0, NULL, HFILL } },
        { &hf_dlt_service_trace_status, {
            "Trace Status", "dlt.service.trace_status",
            FT_INT8, BASE_DEC, VALS(dlt_service_trace_status), 0x0, NULL, HFILL } },
        { &hf_dlt_service_new_trace_status, {
            "New Trace Status", "dlt.service.new_trace_status",
            FT_INT8, BASE_DEC, VALS(dlt_service_trace_status), 0x0, NULL, HFILL } },
        { &hf_dlt_service_new_status, {
            "New  Status", "dlt.service.new_status",
            FT_INT8, BASE_DEC, VALS(dlt_service_new_status), 0x0, NULL, HFILL } },
        { &hf_dlt_service_reserved, {
            "Reserved", "dlt.service.res",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_status, {
            "Status", "dlt.service.status",
            FT_UINT8, BASE_DEC, VALS(dlt_service_status), 0x0, NULL, HFILL } },
        { &hf_dlt_service_length, {
            "Length", "dlt.service.length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_swVersion, {
            "SW-Version", "dlt.service.sw_version",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_status_log_info, {
            "Status", "dlt.service.status",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_log_levels, {
            "Log Levels", "dlt.service.appid_log_levels",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_count, {
            "Count", "dlt.service.count",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_app_desc, {
            "Application Description", "dlt.service.app_description",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_ctx_desc, {
            "Context Description", "dlt.service.ctx_description",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_dlt,
        &ett_dlt_hdr_type,
        &ett_dlt_ext_hdr,
        &ett_dlt_msg_info,
        &ett_dlt_payload,
        &ett_dlt_service_app_ids,
        &ett_dlt_service_app_id,
        &ett_dlt_service_ctx_id,
    };

    static ei_register_info ei[] = {
        { &ef_dlt_unsupported_datatype, {
            "dlt.unsupported_datatype", PI_MALFORMED, PI_ERROR,
            "DLT: Unsupported Data Type!", EXPFILL } },
        { &ef_dlt_unsupported_length_datatype, {
            "dlt.unsupported_length_datatype", PI_MALFORMED, PI_ERROR,
            "DLT: Unsupported Length of Datatype!", EXPFILL } },
        { &ef_dlt_unsupported_string_coding, {
            "dlt.unsupported_string_coding", PI_MALFORMED, PI_ERROR,
            "DLT: Unsupported String Coding!", EXPFILL } },
        { &ef_dlt_unsupported_non_verbose_msg_type, {
            "dlt.unsupported_non_verbose_message_type", PI_MALFORMED, PI_ERROR,
            "DLT: Unsupported Non-Verbose Message Type!", EXPFILL } },
        { &ef_dlt_buffer_too_short, {
            "dlt.buffer_too_short", PI_MALFORMED, PI_ERROR,
            "DLT: Buffer too short!", EXPFILL } },
        { &ef_dlt_parsing_error, {
            "dlt.parsing_error", PI_MALFORMED, PI_ERROR,
            "DLT: Parsing Error!", EXPFILL } },
    };

    /* Register the protocol name and description */
    proto_dlt = proto_register_protocol(DLT_NAME_LONG, DLT_NAME, DLT_NAME_FILTER);
    dlt_handle_tcp = register_dissector("dlt_tcp", dissect_dlt_tcp, proto_dlt);
    dlt_handle_udp = register_dissector("dlt_udp", dissect_dlt_udp, proto_dlt);
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_dlt, hf_dlt, array_length(hf_dlt));

    /* Register Expert Info */
    expert_module_DLT = expert_register_protocol(proto_dlt);
    expert_register_field_array(expert_module_DLT, ei, array_length(ei));

    heur_subdissector_list = register_heur_dissector_list("dlt", proto_dlt);
}

void proto_reg_handoff_dlt(void) {
    dissector_add_uint_with_preference("udp.port", 0, dlt_handle_udp);
    dissector_add_uint_with_preference("tcp.port", 0, dlt_handle_tcp);
}

void proto_register_dlt_storage_header(void) {
    static hf_register_info hfs[] = {
        { &hf_dlt_storage_tstamp_s, {
            "Timestamp s", "dlt.storage.timestamp_s",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_storage_tstamp_us, {
            "Timestamp us", "dlt.storage.timestamp_us",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_storage_ecu_name, {
            "ECU Name", "dlt.storage.ecu_name",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_storage_reserved, {
            "Reserved", "dlt.storage.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    };

    static gint *ett[] = {
        &ett_dlt_storage,
    };

    /* Register the protocol name and description */
    proto_dlt_storage_header = proto_register_protocol(DLT_STORAGE_HEADER_NAME_LONG, DLT_STORAGE_HEADER_NAME, DLT_STORAGE_HEADER_NAME_FILTER);
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_dlt, hfs, array_length(hfs));
}

void proto_reg_handoff_dlt_storage_header(void) {
    dlt_handle_storage = create_dissector_handle(dissect_dlt_storage_header, proto_dlt_storage_header);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_AUTOSAR_DLT, dlt_handle_storage);
}
/*
 * Editor modelines
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
