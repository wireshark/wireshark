/* packet-uds.c
 * Routines for uds protocol packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wsutil/bits_ctz.h>

void proto_register_uds(void);
void proto_reg_handoff_uds(void);

#define UDS_SERVICES_DSC     0x10
#define UDS_SERVICES_ER      0x11
#define UDS_SERVICES_CDTCI   0x14
#define UDS_SERVICES_RDTCI   0x19
#define UDS_SERVICES_RDBI    0x22
#define UDS_SERVICES_RMBA    0x23
#define UDS_SERVICES_RSDBI   0x24
#define UDS_SERVICES_SA      0x27
#define UDS_SERVICES_CC      0x28
#define UDS_SERVICES_RDBPI   0x2A
#define UDS_SERVICES_DDDI    0x2C
#define UDS_SERVICES_WDBI    0x2E
#define UDS_SERVICES_IOCBI   0x2F
#define UDS_SERVICES_RC      0x31
#define UDS_SERVICES_RD      0x34
#define UDS_SERVICES_RU      0x35
#define UDS_SERVICES_TD      0x36
#define UDS_SERVICES_RTE     0x37
#define UDS_SERVICES_RFT     0x38
#define UDS_SERVICES_WMBA    0x3D
#define UDS_SERVICES_TP      0x3E
#define UDS_SERVICES_ERR     0x3F
#define UDS_SERVICES_CDTCS   0x85

#define UDS_RESPONSE_CODES_GR       0x10
#define UDS_RESPONSE_CODES_SNS      0x11
#define UDS_RESPONSE_CODES_SFNS     0x12
#define UDS_RESPONSE_CODES_IMLOIF   0x13
#define UDS_RESPONSE_CODES_RTL      0x14
#define UDS_RESPONSE_CODES_BRR      0x21
#define UDS_RESPONSE_CODES_CNC      0x22
#define UDS_RESPONSE_CODES_RSE      0x24
#define UDS_RESPONSE_CODES_NRFSC    0x25
#define UDS_RESPONSE_CODES_FPEORA   0x26
#define UDS_RESPONSE_CODES_ROOR     0x31
#define UDS_RESPONSE_CODES_SAD      0x33
#define UDS_RESPONSE_CODES_IK       0x35
#define UDS_RESPONSE_CODES_ENOA     0x36
#define UDS_RESPONSE_CODES_RTDNE    0x37
#define UDS_RESPONSE_CODES_UDNA     0x70
#define UDS_RESPONSE_CODES_TDS      0x71
#define UDS_RESPONSE_CODES_GPF      0x72
#define UDS_RESPONSE_CODES_WBSC     0x73
#define UDS_RESPONSE_CODES_RCRRP    0x78
#define UDS_RESPONSE_CODES_SFNSIAS  0x7E
#define UDS_RESPONSE_CODES_SNSIAS   0x7F


#define UDS_SID_MASK    0xBF
#define UDS_REPLY_MASK  0x40
#define UDS_SID_OFFSET  0
#define UDS_SID_LEN     1
#define UDS_DATA_OFFSET 1

#define UDS_DSC_TYPE_OFFSET      (UDS_DATA_OFFSET + 0)
#define UDS_DSC_TYPE_LEN         1
#define UDS_DSC_PARAMETER_RECORD_OFFSET  (UDS_DSC_TYPE_OFFSET + UDS_DSC_TYPE_LEN)

#define UDS_DSC_TYPES_DEFAULT_SESSION                   1
#define UDS_DSC_TYPES_PROGRAMMING_SESSION               2
#define UDS_DSC_TYPES_EXTENDED_DIAGNOSTIC_SESSION       3
#define UDS_DSC_TYPES_SAFETY_SYSTEM_DIAGNOSTIC_SESSION  4

#define UDS_ER_TYPE_OFFSET   (UDS_DATA_OFFSET + 0)
#define UDS_ER_TYPE_LEN      1

#define UDS_ER_TYPES_HARD_RESET                   1
#define UDS_ER_TYPES_KEY_ON_OFF_RESET             2
#define UDS_ER_TYPES_SOFT_RESET                   3
#define UDS_ER_TYPES_ENABLE_RAPID_POWER_SHUTDOWN  4
#define UDS_ER_TYPES_DISABLE_RAPID_POWER_SHUTDOWN 5

#define UDS_RDTCI_TYPE_OFFSET   (UDS_DATA_OFFSET + 0)
#define UDS_RDTCI_TYPE_LEN      1
#define UDS_RDTCI_RECORD_OFFSET (UDS_RDTCI_TYPE_OFFSET + UDS_RDTCI_TYPE_LEN)

#define UDS_RDTCI_TYPES_NUMBER_BY_STATUS_MASK     0x1
#define UDS_RDTCI_TYPES_BY_STATUS_MASK            0x2
#define UDS_RDTCI_TYPES_SNAPSHOT_IDENTIFICATION   0x3
#define UDS_RDTCI_TYPES_SNAPSHOT_RECORD_BY_DTC    0x4
#define UDS_RDTCI_TYPES_SNAPSHOT_RECORD_BY_RECORD 0x5
#define UDS_RDTCI_TYPES_EXTENDED_RECARD_BY_DTC    0x6
#define UDS_RDTCI_TYPES_SUPPORTED_DTC             0xA

#define UDS_RDBI_DATA_IDENTIFIER_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_RDBI_DATA_IDENTIFIER_LEN    2
#define UDS_RDBI_DATA_RECORD_OFFSET     (UDS_RDBI_DATA_IDENTIFIER_OFFSET + UDS_RDBI_DATA_IDENTIFIER_LEN)

#define UDS_SA_TYPE_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_SA_TYPE_LEN    1
#define UDS_SA_KEY_OFFSET  (UDS_SA_TYPE_OFFSET + UDS_SA_TYPE_LEN)
#define UDS_SA_SEED_OFFSET (UDS_SA_TYPE_OFFSET + UDS_SA_TYPE_LEN)

#define UDS_SA_TYPES_SEED   1
#define UDS_SA_TYPES_KEY    2
#define UDS_SA_TYPES_SEED_2 3
#define UDS_SA_TYPES_KEY_2  4

#define UDS_WDBI_DATA_IDENTIFIER_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_WDBI_DATA_IDENTIFIER_LEN    2
#define UDS_WDBI_DATA_RECORD_OFFSET     (UDS_WDBI_DATA_IDENTIFIER_OFFSET + UDS_WDBI_DATA_IDENTIFIER_LEN)

#define UDS_IOCBI_DATA_IDENTIFIER_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_IOCBI_DATA_IDENTIFIER_LEN    2
#define UDS_IOCBI_PARAMETER_OFFSET       (UDS_IOCBI_DATA_IDENTIFIER_OFFSET + UDS_IOCBI_DATA_IDENTIFIER_LEN)
#define UDS_IOCBI_PARAMETER_LEN          1
#define UDS_IOCBI_STATE_OFFSET           (UDS_IOCBI_PARAMETER_OFFSET + UDS_IOCBI_PARAMETER_LEN)

#define UDS_IOCBI_PARAMETERS_RETURN_CONTROL_TO_ECU 0
#define UDS_IOCBI_PARAMETERS_RESET_TO_DEFAULT      1
#define UDS_IOCBI_PARAMETERS_FREEZE_CURRENT_STATE  2
#define UDS_IOCBI_PARAMETERS_SHORT_TERM_ADJUSTMENT 3

#define UDS_RC_TYPE_OFFSET          (UDS_DATA_OFFSET + 0)
#define UDS_RC_TYPE_LEN             1
#define UDS_RC_ROUTINE_OFFSET       (UDS_RC_TYPE_OFFSET + UDS_RC_TYPE_LEN)
#define UDS_RC_ROUTINE_LEN          2
#define UDS_RC_OPTION_RECORD_OFFSET (UDS_RC_ROUTINE_OFFSET + UDS_RC_ROUTINE_LEN)
#define UDS_RC_INFO_OFFSET          (UDS_RC_ROUTINE_OFFSET + UDS_RC_ROUTINE_LEN)
#define UDS_RC_INFO_LEN             1
#define UDS_RC_STATUS_RECORD_OFFSET (UDS_RC_INFO_OFFSET + UDS_RC_INFO_LEN)

#define UDS_RC_TYPES_START   1
#define UDS_RC_TYPES_STOP    2
#define UDS_RC_TYPES_REQUEST 3

#define UDS_RD_DATA_FORMAT_IDENTIFIER_OFFSET               (UDS_DATA_OFFSET + 0)
#define UDS_RD_DATA_FORMAT_IDENTIFIER_LEN                  1
#define UDS_RD_COMPRESSION_METHOD_MASK                     0xF0
#define UDS_RD_ENCRYPTING_METHOD_MASK                      0x0F
#define UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_OFFSET (UDS_RD_DATA_FORMAT_IDENTIFIER_OFFSET + UDS_RD_DATA_FORMAT_IDENTIFIER_LEN)
#define UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_LEN    1
#define UDS_RD_MEMORY_SIZE_LENGTH_MASK                     0xF0
#define UDS_RD_MEMORY_ADDRESS_LENGTH_MASK                  0x0F
#define UDS_RD_MEMORY_ADDRESS_OFFSET                       (UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_OFFSET + UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_LEN)
#define UDS_RD_LENGTH_FORMAT_IDENTIFIER_OFFSET             (UDS_DATA_OFFSET + 0)
#define UDS_RD_LENGTH_FORMAT_IDENTIFIER_LEN                1
#define UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_LENGTH_MASK      0xF0
#define UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_OFFSET           (UDS_RD_LENGTH_FORMAT_IDENTIFIER_OFFSET + UDS_RD_LENGTH_FORMAT_IDENTIFIER_LEN)

#define UDS_TD_SEQUENCE_COUNTER_OFFSET                (UDS_DATA_OFFSET + 0)
#define UDS_TD_SEQUENCE_COUNTER_LEN                   1

#define UDS_TP_SUB_FUNCTION_OFFSET                    (UDS_DATA_OFFSET + 0)
#define UDS_TP_SUB_FUNCTION_LEN                       1
#define UDS_TP_SUB_FUNCTION_MASK                      0x7f
#define UDS_TP_SUPPRESS_POS_RSP_MSG_INDIFICATION_MASK 0x80

#define UDS_ERR_SID_OFFSET   (UDS_DATA_OFFSET + 0)
#define UDS_ERR_SID_LEN      1
#define UDS_ERR_CODE_OFFSET  (UDS_ERR_SID_OFFSET + UDS_ERR_SID_LEN)
#define UDS_ERR_CODE_LEN     1

#define UDS_CDTCS_TYPE_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_CDTCS_TYPE_LEN    1

#define UDS_CDTCS_ACTIONS_ON  1
#define UDS_CDTCS_ACTIONS_OFF 2

/*
 * Enums
 */

/* Services */
static const value_string uds_services[]= {
        {UDS_SERVICES_DSC,   "Diagnostic Session Control"},
        {UDS_SERVICES_ER,    "ECU Reset"},
        {UDS_SERVICES_CDTCI, "Clear Diagnostic Information"},
        {UDS_SERVICES_RDTCI, "Read DTC Information"},
        {UDS_SERVICES_RDBI,  "Read Data By Identifier"},
        {UDS_SERVICES_RMBA,  "Read Memory By Address"},
        {UDS_SERVICES_RSDBI, "Read Scaling Data By Identifier"},
        {UDS_SERVICES_SA,    "Security Access"},
        {UDS_SERVICES_CC,    "Communication Control"},
        {UDS_SERVICES_RDBPI, "Read Data By Periodic Identifier"},
        {UDS_SERVICES_DDDI,  "Dynamically Define Data Identifier"},
        {UDS_SERVICES_WDBI,  "Write Data By Identifier"},
        {UDS_SERVICES_IOCBI, "Input Output Control By Identifier"},
        {UDS_SERVICES_RC,    "Routine Control"},
        {UDS_SERVICES_RD,    "Request Download"},
        {UDS_SERVICES_RU,    "Request Upload"},
        {UDS_SERVICES_TD,    "Transfer Data"},
        {UDS_SERVICES_RTE,   "Request Transfer Exit"},
        {UDS_SERVICES_RFT,   "Request File Transfer"},
        {UDS_SERVICES_WMBA,  "Write Memory By Address"},
        {UDS_SERVICES_TP,    "Tester Present"},
        {UDS_SERVICES_ERR,   "Error"},
        {UDS_SERVICES_CDTCS, "Control DTC Setting"},
        {0, NULL}
};
/* Response code */
static const value_string uds_response_codes[]= {
        {UDS_RESPONSE_CODES_GR,      "General reject"},
        {UDS_RESPONSE_CODES_SNS,     "Service not supported"},
        {UDS_RESPONSE_CODES_SFNS,    "Sub-Function Not Supported"},
        {UDS_RESPONSE_CODES_IMLOIF,  "Incorrect Message Length or Invalid Format"},
        {UDS_RESPONSE_CODES_RTL,     "Response too long"},
        {UDS_RESPONSE_CODES_BRR,     "Busy repeat request"},
        {UDS_RESPONSE_CODES_CNC,     "Conditions Not Correct"},
        {UDS_RESPONSE_CODES_RSE,     "Request Sequence Error"},
        {UDS_RESPONSE_CODES_NRFSC,   "No response from sub-net component"},
        {UDS_RESPONSE_CODES_FPEORA,  "Failure prevents execution of requested action"},
        {UDS_RESPONSE_CODES_ROOR,    "Request Out of Range"},
        {UDS_RESPONSE_CODES_SAD,     "Security Access Denied"},
        {UDS_RESPONSE_CODES_IK,      "Invalid Key"},
        {UDS_RESPONSE_CODES_ENOA,    "Exceeded Number Of Attempts"},
        {UDS_RESPONSE_CODES_RTDNE,   "Required Time Delay Not Expired"},
        {UDS_RESPONSE_CODES_UDNA,    "Upload/Download not accepted"},
        {UDS_RESPONSE_CODES_TDS,     "Transfer data suspended"},
        {UDS_RESPONSE_CODES_GPF,     "General Programming Failure"},
        {UDS_RESPONSE_CODES_WBSC,    "Wrong Block Sequence Counter"},
        {UDS_RESPONSE_CODES_RCRRP,   "Request correctly received, but response is pending"},
        {UDS_RESPONSE_CODES_SFNSIAS, "Sub-Function not supported in active session"},
        {UDS_RESPONSE_CODES_SNSIAS,  "Service not supported in active session"},
        {0, NULL}
};

/* DSC */
static const value_string uds_dsc_types[] = {
        {0,                                             "Reserved"},
        {UDS_DSC_TYPES_DEFAULT_SESSION,                 "Default Session"},
        {UDS_DSC_TYPES_PROGRAMMING_SESSION,             "Programming Session"},
        {UDS_DSC_TYPES_EXTENDED_DIAGNOSTIC_SESSION,     "Extended Diagnostic Session"},
        {UDS_DSC_TYPES_SAFETY_SYSTEM_DIAGNOSTIC_SESSION, "Safety System Diagnostic Session"},
        {0, NULL}
};

/* ER */
static const value_string uds_er_types[] = {
        {0,                                         "Reserved"},
        {UDS_ER_TYPES_HARD_RESET,                   "Hard Reset"},
        {UDS_ER_TYPES_KEY_ON_OFF_RESET,             "Key On Off Reset"},
        {UDS_ER_TYPES_SOFT_RESET,                   "Soft Reset"},
        {UDS_ER_TYPES_ENABLE_RAPID_POWER_SHUTDOWN,  "Enable Rapid Power Shutdown"},
        {UDS_ER_TYPES_DISABLE_RAPID_POWER_SHUTDOWN, "Disable Rapid Power Shutdown"},
        {0, NULL}
};

/* SA */
static const value_string uds_sa_types[] = {
        {UDS_SA_TYPES_SEED,   "Request Seed"},
        {UDS_SA_TYPES_KEY,    "Send Key"},
        {UDS_SA_TYPES_SEED_2, "Request Seed"},
        {UDS_SA_TYPES_KEY_2,  "Send Key"},
        {0, NULL}
};

/* RDTCI */
static const value_string uds_rdtci_types[] = {
        {UDS_RDTCI_TYPES_NUMBER_BY_STATUS_MASK,     "Report Number of DTC by Status Mask"},
        {UDS_RDTCI_TYPES_BY_STATUS_MASK,            "Report DTC by Status Mask"},
        {UDS_RDTCI_TYPES_SNAPSHOT_IDENTIFICATION,   "Report DTC Snapshot Identification"},
        {UDS_RDTCI_TYPES_SNAPSHOT_RECORD_BY_DTC,    "Report DTC Snapshot Record by DTC Number"},
        {UDS_RDTCI_TYPES_SNAPSHOT_RECORD_BY_RECORD, "Report DTC Snapshot Record by Record Number"},
        {UDS_RDTCI_TYPES_EXTENDED_RECARD_BY_DTC,    "Report DTC Extended Data Record by DTC Number"},
        {UDS_RDTCI_TYPES_SUPPORTED_DTC,             "Report Supported DTC"},
        {0, NULL}
};

/* IOCBI */
static const value_string uds_iocbi_parameters[] = {
        {UDS_IOCBI_PARAMETERS_RETURN_CONTROL_TO_ECU, "Return Control To ECU"},
        {UDS_IOCBI_PARAMETERS_RESET_TO_DEFAULT,      "Reset To Default"},
        {UDS_IOCBI_PARAMETERS_FREEZE_CURRENT_STATE,  "Freeze Current State"},
        {UDS_IOCBI_PARAMETERS_SHORT_TERM_ADJUSTMENT, "Short Term Adjustment"},
        {0, NULL}
};

/* RC */
static const value_string uds_rc_types[] = {
        {0,                    "Reserved"},
        {UDS_RC_TYPES_START,   "Start routine"},
        {UDS_RC_TYPES_STOP,    "Stop routine"},
        {UDS_RC_TYPES_REQUEST, "Request routine result"},
        {0, NULL}
};

/* CDTCS */
static const value_string uds_cdtcs_types[] = {
        {0,                     "Reserved"},
        {UDS_CDTCS_ACTIONS_ON,  "On"},
        {UDS_CDTCS_ACTIONS_OFF, "Off"},
        {0, NULL}
};

/*
 * Fields
 */
static int hf_uds_service = -1;
static int hf_uds_reply = -1;

static int hf_uds_dsc_type = -1;
static int hf_uds_dsc_parameter_record = -1;

static int hf_uds_er_type = -1;

static int hf_uds_rdtci_type = -1;
static int hf_uds_rdtci_record = -1;

static int hf_uds_rdbi_data_identifier = -1;
static int hf_uds_rdbi_data_record = -1;

static int hf_uds_sa_type = -1;
static int hf_uds_sa_key = -1;
static int hf_uds_sa_seed = -1;

static int hf_uds_wdbi_data_identifier = -1;
static int hf_uds_wdbi_data_record = -1;

static int hf_uds_iocbi_data_identifier = -1;
static int hf_uds_iocbi_parameter = -1;
static int hf_uds_iocbi_state = -1;

static int hf_uds_rc_type = -1;
static int hf_uds_rc_identifier = -1;
static int hf_uds_rc_option_record = -1;
static int hf_uds_rc_info = -1;
static int hf_uds_rc_status_record = -1;

static int hf_uds_rd_compression_method = -1;
static int hf_uds_rd_encrypting_method = -1;
static int hf_uds_rd_memory_size_length = -1;
static int hf_uds_rd_memory_address_length = -1;
static int hf_uds_rd_memory_address = -1;
static int hf_uds_rd_memory_size = -1;
static int hf_uds_rd_max_number_of_block_length_length = -1;
static int hf_uds_rd_max_number_of_block_length = -1;

static int hf_uds_td_sequence_counter = -1;

static int hf_uds_tp_sub_function = -1;
static int hf_uds_tp_suppress_pos_rsp_msg_indification = -1;

static int hf_uds_err_sid = -1;
static int hf_uds_err_code = -1;

static int hf_uds_cdtcs_type = -1;

/*
 * Trees
 */
static gint ett_uds = -1;
static gint ett_uds_dsc = -1;
static gint ett_uds_er = -1;
static gint ett_uds_rdtci = -1;
static gint ett_uds_rdbi = -1;
static gint ett_uds_sa = -1;
static gint ett_uds_wdbi = -1;
static gint ett_uds_iocbi = -1;
static gint ett_uds_rc = -1;
static gint ett_uds_rd = -1;
static gint ett_uds_td = -1;
static gint ett_uds_tp = -1;
static gint ett_uds_err = -1;
static gint ett_uds_cdtcs = -1;

static int proto_uds = -1;

static dissector_handle_t uds_handle;

static
guint8 masked_guint8_value(const guint8 value, const guint8 mask)
{
    return (value & mask) >> ws_ctz(mask);
}

static guint64
tvb_get_guintX(tvbuff_t *tvb, const gint offset, const gint size, const guint encoding) {
    switch (size) {
        case 1:
            return tvb_get_guint8(tvb, offset);
        case 2:
            return tvb_get_guint16(tvb, offset, encoding);
        case 3:
            return tvb_get_guint24(tvb, offset, encoding);
        case 4:
            return tvb_get_guint32(tvb, offset, encoding);
        case 5:
            return tvb_get_guint40(tvb, offset, encoding);
        case 6:
            return tvb_get_guint48(tvb, offset, encoding);
        case 7:
            return tvb_get_guint56(tvb, offset, encoding);
        case 8:
            return tvb_get_guint64(tvb, offset, encoding);
    }

    return 0;
}

static int
dissect_uds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void* data _U_)
{
    proto_tree *uds_tree, *subtree;
    proto_item *ti;
    guint8      sid, service;
    guint32     enum_val;
    const char *service_name;
    guint32 data_length = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDS");
    col_clear(pinfo->cinfo,COL_INFO);

    sid = tvb_get_guint8(tvb, UDS_SID_OFFSET);
    service = sid & UDS_SID_MASK;
    service_name = val_to_str(service, uds_services, "Unknown (0x%02x)");

    col_add_fstr(pinfo->cinfo, COL_INFO, "%-7s   %-36s", (sid & UDS_REPLY_MASK)? "Reply": "Request", service_name);

    ti = proto_tree_add_item(tree, proto_uds, tvb, 0, -1, ENC_NA);
    uds_tree = proto_item_add_subtree(ti, ett_uds);
    proto_tree_add_item(uds_tree, hf_uds_service, tvb, UDS_SID_OFFSET, UDS_SID_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(uds_tree, hf_uds_reply, tvb, UDS_SID_OFFSET, UDS_SID_LEN, ENC_BIG_ENDIAN);

    switch (service) {
        case UDS_SERVICES_DSC:
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_dsc, NULL, service_name);
            proto_tree_add_item_ret_uint(subtree, hf_uds_dsc_type, tvb, UDS_DSC_TYPE_OFFSET, UDS_DSC_TYPE_LEN,
                                ENC_BIG_ENDIAN, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_dsc_types, "Unknown (0x%02x)"));

            if (sid & UDS_REPLY_MASK) {
                guint32 parameter_record_length = data_length - UDS_DSC_PARAMETER_RECORD_OFFSET;
                proto_tree_add_item(subtree, hf_uds_dsc_parameter_record, tvb,
                                    UDS_DSC_PARAMETER_RECORD_OFFSET, parameter_record_length, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_DSC_PARAMETER_RECORD_OFFSET,
                                                       parameter_record_length, ' '));
            }
            break;

        case UDS_SERVICES_ER:
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_er, NULL, service_name);
            proto_tree_add_item_ret_uint(subtree, hf_uds_er_type, tvb, UDS_ER_TYPE_OFFSET, UDS_ER_TYPE_LEN, ENC_BIG_ENDIAN, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_er_types, "Unknown (0x%02x)"));
            break;

        case UDS_SERVICES_RDTCI: {
            guint32 record_length = data_length - UDS_RDTCI_RECORD_OFFSET;

            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rdtci, NULL, service_name);
            proto_tree_add_item_ret_uint(subtree, hf_uds_rdtci_type, tvb, UDS_RDTCI_TYPE_OFFSET,
                                UDS_RDTCI_TYPE_LEN, ENC_BIG_ENDIAN, &enum_val);
            proto_tree_add_item(subtree, hf_uds_rdtci_record, tvb,
                                UDS_RDTCI_RECORD_OFFSET, record_length, ENC_NA);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s    %s", val_to_str(enum_val, uds_rdtci_types, "Unknown (0x%02x)"),
                            tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_RDTCI_RECORD_OFFSET, record_length, ' '));
            break;
        }
        case UDS_SERVICES_RDBI:
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rdbi, NULL, service_name);
            if (sid & UDS_REPLY_MASK) {
                /* Can't know the size of the data for each identifier, Decode like if there is only one idenfifier */
                guint32 record_length = data_length - UDS_RDBI_DATA_RECORD_OFFSET;
                guint32 data_identifier;
                proto_tree_add_item_ret_uint(subtree, hf_uds_rdbi_data_identifier, tvb, UDS_RDBI_DATA_IDENTIFIER_OFFSET,
                                    UDS_RDBI_DATA_IDENTIFIER_LEN, ENC_BIG_ENDIAN, &data_identifier);
                proto_tree_add_item(subtree, hf_uds_rdbi_data_record, tvb, UDS_RDBI_DATA_RECORD_OFFSET,
                                    record_length, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x   %s", data_identifier,
                                tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_RDBI_DATA_RECORD_OFFSET,
                                                       record_length, ' '));
            } else {
                guint32 identifier_length = data_length - UDS_RDBI_DATA_IDENTIFIER_OFFSET;
                guint32 offset = UDS_RDBI_DATA_IDENTIFIER_OFFSET;
                while (identifier_length > 0) {
                    guint32 data_identifier;
                    proto_tree_add_item_ret_uint(subtree, hf_uds_rdbi_data_identifier, tvb, offset,
                                        UDS_RDBI_DATA_IDENTIFIER_LEN, ENC_BIG_ENDIAN, &data_identifier);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
                    offset += UDS_RDBI_DATA_IDENTIFIER_LEN;
                    identifier_length -= UDS_RDBI_DATA_IDENTIFIER_LEN;
                }
            }
            break;

        case UDS_SERVICES_SA:
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_sa, NULL, service_name);
            proto_tree_add_item_ret_uint(subtree, hf_uds_sa_type, tvb, UDS_SA_TYPE_OFFSET,
                                UDS_SA_TYPE_LEN, ENC_BIG_ENDIAN, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                            val_to_str(enum_val, uds_sa_types, "Unknown (0x%02x)"));

            if (sid & UDS_REPLY_MASK) {
                guint32 seed_length = data_length - UDS_SA_SEED_OFFSET;
                if (seed_length > 0) {
                    proto_tree_add_item(subtree, hf_uds_sa_seed, tvb, UDS_SA_SEED_OFFSET, seed_length, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                    tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_SA_SEED_OFFSET, seed_length,
                                                           ' '));
                }
            } else {
                guint32 key_length = data_length - UDS_SA_KEY_OFFSET;
                if (key_length > 0) {
                    proto_tree_add_item(subtree, hf_uds_sa_key, tvb, UDS_SA_KEY_OFFSET, key_length, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                    tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_SA_KEY_OFFSET, key_length,
                                                           ' '));
                }
            }
            break;

        case UDS_SERVICES_WDBI:
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_wdbi, NULL, service_name);
            proto_tree_add_item_ret_uint(subtree, hf_uds_wdbi_data_identifier, tvb, UDS_WDBI_DATA_IDENTIFIER_OFFSET,
                                UDS_WDBI_DATA_IDENTIFIER_LEN, ENC_BIG_ENDIAN, &enum_val);
            if (sid & UDS_REPLY_MASK) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", enum_val);
            } else {
                guint32 record_length = data_length - UDS_WDBI_DATA_RECORD_OFFSET;
                proto_tree_add_item(subtree, hf_uds_wdbi_data_record, tvb, UDS_WDBI_DATA_RECORD_OFFSET,
                                    record_length, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x   %s", enum_val,
                                tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_WDBI_DATA_RECORD_OFFSET,
                                                       record_length, ' '));
            }
            break;

        case UDS_SERVICES_IOCBI: {
            guint32 data_identifier;
            guint32 state_length = data_length - UDS_IOCBI_STATE_OFFSET;

            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_iocbi, NULL, service_name);
            proto_tree_add_item_ret_uint(subtree, hf_uds_iocbi_data_identifier, tvb, UDS_IOCBI_DATA_IDENTIFIER_OFFSET,
                                UDS_IOCBI_DATA_IDENTIFIER_LEN, ENC_BIG_ENDIAN, &data_identifier);

            proto_tree_add_item_ret_uint(subtree, hf_uds_iocbi_parameter, tvb, UDS_IOCBI_PARAMETER_OFFSET,
                                UDS_IOCBI_PARAMETER_LEN, ENC_BIG_ENDIAN, &enum_val);

            proto_tree_add_item(subtree, hf_uds_iocbi_state, tvb, UDS_IOCBI_STATE_OFFSET,
                                state_length, ENC_NA);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x  %s %s", data_identifier,
                            val_to_str(enum_val, uds_iocbi_parameters, "Unknown (0x%02x)"),
                            tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_IOCBI_STATE_OFFSET,
                                                   state_length, ' '));
            break;
        }
        case UDS_SERVICES_RC: {
            guint32 identifier;

            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rc, NULL, service_name);
            proto_tree_add_item_ret_uint(subtree, hf_uds_rc_type, tvb, UDS_RC_TYPE_OFFSET,
                                UDS_RC_TYPE_LEN, ENC_BIG_ENDIAN, &enum_val);

            proto_tree_add_item_ret_uint(subtree, hf_uds_rc_identifier, tvb, UDS_RC_ROUTINE_OFFSET,
                                UDS_RC_ROUTINE_LEN, ENC_BIG_ENDIAN, &identifier);

            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s 0x%04x",
                            val_to_str(enum_val, uds_rc_types, "Unknown (0x%02x)"), identifier);
            if (sid & UDS_REPLY_MASK) {
                guint32 rc_data_len = data_length - UDS_RC_INFO_OFFSET;
                if (rc_data_len > 0) {
                    guint8 info = tvb_get_guint8(tvb, UDS_RC_INFO_OFFSET);
                    proto_tree_add_item(subtree, hf_uds_rc_info, tvb,
                                        UDS_RC_INFO_OFFSET, UDS_RC_INFO_LEN, ENC_BIG_ENDIAN);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%x", info);
                    if (rc_data_len > 1) {
                        guint32 status_record_len = data_length - UDS_RC_STATUS_RECORD_OFFSET;
                        proto_tree_add_item(subtree, hf_uds_rc_status_record, tvb,
                                            UDS_RC_STATUS_RECORD_OFFSET, status_record_len, ENC_NA);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                        tvb_bytes_to_str_punct(wmem_packet_scope(), tvb,
                                                               UDS_RC_STATUS_RECORD_OFFSET, status_record_len, ' '));
                    }
                }
            } else {
                guint32 option_record_len = data_length - UDS_RC_OPTION_RECORD_OFFSET;
                if (option_record_len > 0) {
                    proto_tree_add_item(subtree, hf_uds_rc_option_record, tvb,
                                        UDS_RC_OPTION_RECORD_OFFSET, option_record_len, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                    tvb_bytes_to_str_punct(wmem_packet_scope(), tvb,
                                                           UDS_RC_OPTION_RECORD_OFFSET, option_record_len, ' '));
                }
            }
            break;
        }
        case UDS_SERVICES_RD:
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rd, NULL, service_name);
            if (sid & UDS_REPLY_MASK) {
                guint8 length_format_identifier, max_number_of_block_length_length;
                guint64 max_number_of_block_length;

                length_format_identifier = tvb_get_guint8(tvb, UDS_RD_LENGTH_FORMAT_IDENTIFIER_OFFSET);
                max_number_of_block_length_length = masked_guint8_value(length_format_identifier,
                                                                        UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_LENGTH_MASK);
                proto_tree_add_item(subtree, hf_uds_rd_max_number_of_block_length_length, tvb,
                                    UDS_RD_LENGTH_FORMAT_IDENTIFIER_OFFSET,
                                    UDS_RD_LENGTH_FORMAT_IDENTIFIER_LEN, ENC_BIG_ENDIAN);

                max_number_of_block_length = tvb_get_guintX(tvb, UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_OFFSET,
                                                            max_number_of_block_length_length, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_uds_rd_max_number_of_block_length, tvb,
                                    UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_OFFSET,
                                    max_number_of_block_length_length, ENC_BIG_ENDIAN);

                col_append_fstr(pinfo->cinfo, COL_INFO, "   Max Number Of Block Length 0x%" G_GINT64_MODIFIER "x",
                                max_number_of_block_length);
            } else {
                guint8 data_format_identifier, compression, encryting;
                guint8 address_and_length_format_idenfifier, memory_size_length, memory_address_length;
                guint64 memory_size, memory_address;

                data_format_identifier = tvb_get_guint8(tvb, UDS_RD_DATA_FORMAT_IDENTIFIER_OFFSET);

                compression = masked_guint8_value(data_format_identifier, UDS_RD_COMPRESSION_METHOD_MASK);
                proto_tree_add_item(subtree, hf_uds_rd_compression_method, tvb,
                                    UDS_RD_DATA_FORMAT_IDENTIFIER_OFFSET,
                                    UDS_RD_DATA_FORMAT_IDENTIFIER_LEN, ENC_BIG_ENDIAN);

                encryting = masked_guint8_value(data_format_identifier, UDS_RD_ENCRYPTING_METHOD_MASK);
                proto_tree_add_item(subtree, hf_uds_rd_encrypting_method, tvb, UDS_RD_DATA_FORMAT_IDENTIFIER_OFFSET,
                                    UDS_RD_DATA_FORMAT_IDENTIFIER_LEN, ENC_BIG_ENDIAN);

                address_and_length_format_idenfifier = tvb_get_guint8(tvb, UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_OFFSET);

                memory_size_length = masked_guint8_value(address_and_length_format_idenfifier,
                                                         UDS_RD_COMPRESSION_METHOD_MASK);
                proto_tree_add_item(subtree, hf_uds_rd_memory_size_length, tvb,
                                    UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_OFFSET,
                                    UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_LEN, ENC_BIG_ENDIAN);

                memory_address_length = masked_guint8_value(address_and_length_format_idenfifier,
                                                            UDS_RD_ENCRYPTING_METHOD_MASK);
                proto_tree_add_item(subtree, hf_uds_rd_memory_address_length, tvb,
                                    UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_OFFSET,
                                    UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_LEN, ENC_BIG_ENDIAN);

                memory_address = tvb_get_guintX(tvb, UDS_RD_MEMORY_ADDRESS_OFFSET, memory_address_length,
                                                ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_uds_rd_memory_address, tvb, UDS_RD_MEMORY_ADDRESS_OFFSET,
                                    memory_address_length, ENC_BIG_ENDIAN);
                memory_size = tvb_get_guintX(tvb, UDS_RD_MEMORY_ADDRESS_OFFSET + memory_address_length,
                                             memory_size_length, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_uds_rd_memory_size, tvb,
                                    UDS_RD_MEMORY_ADDRESS_OFFSET + memory_address_length,
                                    memory_size_length, ENC_BIG_ENDIAN);

                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%" G_GINT64_MODIFIER "x bytes at 0x%" G_GINT64_MODIFIER "x", memory_size, memory_address);

                col_append_fstr(pinfo->cinfo, COL_INFO, "   (Compression:0x%x Encrypting:0x%x)", compression,
                                encryting);
            }
            break;

        case UDS_SERVICES_TD: {
            guint32 sequence_no;
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_td, NULL, service_name);

            proto_tree_add_item_ret_uint(subtree, hf_uds_td_sequence_counter, tvb,
                                     UDS_TD_SEQUENCE_COUNTER_OFFSET, UDS_TD_SEQUENCE_COUNTER_LEN, ENC_NA, &sequence_no);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   Block Sequence Counter %d", sequence_no);
            break;
        }
        case UDS_SERVICES_TP: {
            guint8 sub_function_a, sub_function;
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_tp, NULL, service_name);

            sub_function_a = tvb_get_guint8(tvb, UDS_TP_SUB_FUNCTION_OFFSET);
            sub_function = masked_guint8_value(sub_function_a, UDS_TP_SUB_FUNCTION_MASK);
            proto_tree_add_item(subtree, hf_uds_tp_sub_function, tvb,
                                UDS_TP_SUB_FUNCTION_OFFSET, UDS_TP_SUB_FUNCTION_LEN, ENC_BIG_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "   Sub-function %x", sub_function);

            if (!(sid & UDS_REPLY_MASK)) {
                guint8 suppress = masked_guint8_value(sub_function_a, UDS_TP_SUPPRESS_POS_RSP_MSG_INDIFICATION_MASK);

                proto_tree_add_item(subtree, hf_uds_tp_suppress_pos_rsp_msg_indification, tvb,
                                    UDS_TP_SUB_FUNCTION_OFFSET, UDS_TP_SUB_FUNCTION_LEN, ENC_BIG_ENDIAN);

                if (suppress) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   (Reply suppressed)");
                }
            }
            break;
        }
        case UDS_SERVICES_ERR: {
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_err, NULL, service_name);

            proto_tree_add_item_ret_uint(subtree, hf_uds_err_sid, tvb, UDS_ERR_SID_OFFSET, UDS_ERR_SID_LEN, ENC_BIG_ENDIAN, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_services, "Unknown (0x%02x)"));
            proto_tree_add_item_ret_uint(subtree, hf_uds_err_code, tvb, UDS_ERR_CODE_OFFSET, UDS_ERR_CODE_LEN,
                                ENC_BIG_ENDIAN, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (SID: %s)", val_to_str(enum_val, uds_response_codes, "Unknown (0x%02x)"));
            break;
        }
        case UDS_SERVICES_CDTCS: {
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_cdtcs, NULL, service_name);
            proto_tree_add_item_ret_uint(subtree, hf_uds_cdtcs_type, tvb,
                                UDS_CDTCS_TYPE_OFFSET, UDS_CDTCS_TYPE_LEN, ENC_BIG_ENDIAN, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                            val_to_str(enum_val, uds_cdtcs_types, "Unknown (0x%02x)"));
            break;
        }
    }

    return tvb_captured_length(tvb);
}

void
proto_register_uds(void)
{
    static hf_register_info hf[] = {
            {
                    &hf_uds_service,
                    {
                            "Service Identifier",    "uds.sid",
                            FT_UINT8,  BASE_HEX,
                            VALS(uds_services), UDS_SID_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_reply,
                    {
                            "Reply Flag", "uds.reply",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_REPLY_MASK,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_dsc_type,
                    {
                            "Type", "uds.dsc.type",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_dsc_types), 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_dsc_parameter_record,
                    {
                            "Parameter Record", "uds.dsc.paramter_record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_er_type,
                    {
                            "Type", "uds.er.type",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_er_types), 0x0,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_rdtci_type,
                    {
                            "Type", "uds.rdtci.type",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_rdtci_types), 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rdtci_record,
                    {
                            "Record", "uds.rdtci.record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_rdbi_data_identifier,
                    {
                            "Data Identifier", "uds.rdbi.data_identifier",
                            FT_UINT16, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rdbi_data_record,
                    {
                            "Data Record", "uds.rdbi.data_record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_sa_type,
                    {
                            "Type", "uds.sa.type",
                            FT_UINT8, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_sa_key,
                    {
                            "Key", "uds.sa.key",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_sa_seed,
                    {
                            "Seed", "uds.sa.seed",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_wdbi_data_identifier,
                    {
                            "Data Identifier", "uds.wdbi.data_identifier",
                            FT_UINT8, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_wdbi_data_record,
                    {
                            "Data Record", "uds.wdbi.data_record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_iocbi_data_identifier,
                    {
                            "Data Identifier", "uds.iocbi.data_identifier",
                            FT_UINT8, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_iocbi_parameter,
                    {
                            "Parameter", "uds.iocbi.parameter",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_iocbi_parameters), 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_iocbi_state,
                    {
                            "State", "uds.iocbi.state",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_rc_type,
                    {
                            "Type", "uds.rc.type",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_rc_types), 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rc_identifier,
                    {
                            "Identifier", "uds.rc.identifier",
                            FT_UINT16, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rc_option_record,
                    {
                            "Option record", "uds.rc.option_record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rc_info,
                    {
                            "Info", "uds.rc.info",
                            FT_UINT8, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rc_status_record,
                    {
                            "Status Record", "uds.rc.status_record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_rd_compression_method,
                    {
                            "Compression Method", "uds.rd.compression_method",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_RD_COMPRESSION_METHOD_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_encrypting_method,
                    {
                            "Encrypting Method", "uds.rd.encrypting_method",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_RD_ENCRYPTING_METHOD_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_memory_size_length,
                    {
                            "Memory size length", "uds.rd.memory_size_length",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_RD_MEMORY_SIZE_LENGTH_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_memory_address_length,
                    {
                            "Memory address length", "uds.rd.memory_address_length",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_RD_MEMORY_ADDRESS_LENGTH_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_memory_address,
                    {
                            "Memory Address", "uds.rd.memory_address",
                            FT_UINT64, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_memory_size,
                    {
                            "Memory Size", "uds.rd.memory_size",
                            FT_UINT64, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_max_number_of_block_length_length,
                    {
                            "Memory address length", "uds.rd.max_number_of_block_length_length",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_LENGTH_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_max_number_of_block_length,
                    {
                            "Memory Size", "uds.rd.max_number_of_block_length",
                            FT_UINT64, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_td_sequence_counter,
                    {
                            "Block Sequence Counter", "uds.td.block_sequence_counter",
                            FT_UINT8, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_tp_sub_function,
                    {
                            "Suppress reply", "uds.tp.suppress_reply",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_TP_SUB_FUNCTION_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_tp_suppress_pos_rsp_msg_indification,
                    {
                            "Suppress reply", "uds.tp.suppress_reply.indification",
                            FT_BOOLEAN, 8,
                            NULL, UDS_TP_SUPPRESS_POS_RSP_MSG_INDIFICATION_MASK,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_err_sid,
                    {
                            "Service Identifier", "uds.err.sid",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_services), 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_err_code,
                    {
                            "Code", "uds.err.code",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_response_codes), 0x0,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_cdtcs_type,
                    {
                            "Type", "uds.cdtcs.type",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_cdtcs_types), 0x0,
                            NULL, HFILL
                    }
            },
    };

    /* Setup protocol subtree array */
    static gint *ett[] =
            {
                    &ett_uds,
                    &ett_uds_dsc,
                    &ett_uds_er,
                    &ett_uds_rdtci,
                    &ett_uds_rdbi,
                    &ett_uds_sa,
                    &ett_uds_wdbi,
                    &ett_uds_iocbi,
                    &ett_uds_rc,
                    &ett_uds_rd,
                    &ett_uds_td,
                    &ett_uds_tp,
                    &ett_uds_err,
                    &ett_uds_cdtcs,
            };

    proto_uds = proto_register_protocol (
            "Unified Diagnostic Services", /* name       */
            "UDS",          /* short name */
            "uds"           /* abbrev     */
    );

    proto_register_field_array(proto_uds, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    uds_handle = register_dissector("uds", dissect_uds, proto_uds);
}

void
proto_reg_handoff_uds(void)
{
    dissector_add_for_decode_as("iso15765.subdissector", uds_handle);
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
