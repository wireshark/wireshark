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
#include <epan/uat.h>
#include <wsutil/bits_ctz.h>
#include <epan/dissectors/packet-uds.h>
#include <epan/dissectors/packet-doip.h>
#include <epan/dissectors/packet-iso10681.h>
#include <epan/dissectors/packet-iso15765.h>

void proto_register_uds(void);
void proto_reg_handoff_uds(void);

#define DATAFILE_UDS_ROUTINE_IDS "UDS_routine_identifiers"
#define DATAFILE_UDS_DATA_IDS    "UDS_data_identifiers"
#define DATAFILE_UDS_ADDRESSES   "UDS_diagnostic_addresses"

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
#define UDS_RESPONSE_CODES_AR       0x34
#define UDS_RESPONSE_CODES_IK       0x35
#define UDS_RESPONSE_CODES_ENOA     0x36
#define UDS_RESPONSE_CODES_RTDNE    0x37
#define UDS_RESPONSE_CODES_SDTR     0x38
#define UDS_RESPONSE_CODES_SDTNA    0x39
#define UDS_RESPONSE_CODES_SDTF     0x3A
#define UDS_RESPONSE_CODES_CVFITP   0x50
#define UDS_RESPONSE_CODES_CVFIS    0x51
#define UDS_RESPONSE_CODES_CVFICOT  0x52
#define UDS_RESPONSE_CODES_CVFIT    0x53
#define UDS_RESPONSE_CODES_CVFIF    0x54
#define UDS_RESPONSE_CODES_CVFIC    0x55
#define UDS_RESPONSE_CODES_CVFISD   0x56
#define UDS_RESPONSE_CODES_CVFICR   0x57
#define UDS_RESPONSE_CODES_OVF      0x58
#define UDS_RESPONSE_CODES_CCF      0x59
#define UDS_RESPONSE_CODES_SARF     0x5A
#define UDS_RESPONSE_CODES_SKCDF    0x5B
#define UDS_RESPONSE_CODES_CDUF     0x5C
#define UDS_RESPONSE_CODES_DAF      0x5D
#define UDS_RESPONSE_CODES_UDNA     0x70
#define UDS_RESPONSE_CODES_TDS      0x71
#define UDS_RESPONSE_CODES_GPF      0x72
#define UDS_RESPONSE_CODES_WBSC     0x73
#define UDS_RESPONSE_CODES_RCRRP    0x78
#define UDS_RESPONSE_CODES_SFNSIAS  0x7E
#define UDS_RESPONSE_CODES_SNSIAS   0x7F
#define UDS_RESPONSE_CODES_RPMTH    0x81
#define UDS_RESPONSE_CODES_RPMTL    0x82
#define UDS_RESPONSE_CODES_EIR      0x83
#define UDS_RESPONSE_CODES_EINR     0x84
#define UDS_RESPONSE_CODES_ERTTL    0x85
#define UDS_RESPONSE_CODES_TEMPTH   0x86
#define UDS_RESPONSE_CODES_TEMPTL   0x87
#define UDS_RESPONSE_CODES_VSTH     0x88
#define UDS_RESPONSE_CODES_VSTL     0x89
#define UDS_RESPONSE_CODES_TPTH     0x8a
#define UDS_RESPONSE_CODES_TPTL     0x8b
#define UDS_RESPONSE_CODES_TRNIN    0x8c
#define UDS_RESPONSE_CODES_TRNIG    0x8d
#define UDS_RESPONSE_CODES_BSNC     0x8f
#define UDS_RESPONSE_CODES_SLNIP    0x90
#define UDS_RESPONSE_CODES_TCCL     0x91
#define UDS_RESPONSE_CODES_VTH      0x92
#define UDS_RESPONSE_CODES_VTL      0x93
#define UDS_RESPONSE_CODES_RTNA     0x94

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
#define UDS_RDTCI_TYPES_EXTENDED_RECORD_BY_DTC    0x6
#define UDS_RDTCI_TYPES_NUM_DTC_BY_SEVERITY_MASK  0x7
#define UDS_RDTCI_TYPES_BY_SEVERITY_MASK          0x8
#define UDS_RDTCI_TYPES_SEVERITY_INFO_OF_DTC      0x9
#define UDS_RDTCI_TYPES_SUPPORTED_DTC             0xA
#define UDS_RDTCI_TYPES_MOST_RECENT_TEST_FAILED   0xB
#define UDS_RDTCI_TYPES_MOST_RECENT_CONFIRMED_DTC 0xC
#define UDS_RDTCI_TYPES_DTC_FAULT_DETECT_CTR      0x14
#define UDS_RDTCI_TYPES_DTC_WITH_PERM_STATUS      0x15
#define UDS_RDTCI_TYPES_DTC_EXT_DATA_REC_BY_NUM   0x16
#define UDS_RDTCI_TYPES_USER_MEM_DTC_BY_STATUS_M  0x17
#define UDS_RDTCI_TYPES_USER_MEM_DTC_REC_BY_DTC_N 0x18
#define UDS_RDTCI_TYPES_USER_MEM_DTC_EXT_REC_BY_N 0x19
#define UDS_RDTCI_TYPES_SUP_DTC_EXT_RECORD        0x1A
#define UDS_RDTCI_TYPES_WWH_OBD_DTC_BY_MASK_REC   0x42
#define UDS_RDTCI_TYPES_WWH_OBD_DTC_PERM_STATUS   0x55
#define UDS_RDTCI_TYPES_WWH_OBD_BY_GROUP_READY    0x56

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
        {UDS_SERVICES_ARS,   "Authentication"},
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
        {UDS_SERVICES_SDT,   "Sercure Data Transmission"},
        {UDS_SERVICES_CDTCS, "Control DTC Setting"},
        {UDS_SERVICES_ROE,   "Response On Event"},
        {UDS_SERVICES_LC,    "Link Control"},
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
        {UDS_RESPONSE_CODES_AR,      "Authentication Required"},
        {UDS_RESPONSE_CODES_IK,      "Invalid Key"},
        {UDS_RESPONSE_CODES_ENOA,    "Exceeded Number Of Attempts"},
        {UDS_RESPONSE_CODES_RTDNE,   "Required Time Delay Not Expired"},
        {UDS_RESPONSE_CODES_SDTR,    "Secure Data Transmission Required"},
        {UDS_RESPONSE_CODES_SDTNA,   "Secure Data Transmission Not Allowed"},
        {UDS_RESPONSE_CODES_SDTF,    "Secure Data Verification Failed"},
        {UDS_RESPONSE_CODES_CVFITP,  "Certificate Verification Failed: Invalid Time Period"},
        {UDS_RESPONSE_CODES_CVFIS,   "Certificate Verification Failed: Invalid Signature"},
        {UDS_RESPONSE_CODES_CVFICOT, "Certificate Verification Failed: Invalid Chain of Trust"},
        {UDS_RESPONSE_CODES_CVFIT,   "Certificate Verification Failed: Invalid Type"},
        {UDS_RESPONSE_CODES_CVFIF,   "Certificate Verification Failed: Invalid Format"},
        {UDS_RESPONSE_CODES_CVFIC,   "Certificate Verification Failed: Invalid Content"},
        {UDS_RESPONSE_CODES_CVFISD,  "Certificate Verification Failed: Invalid Scope"},
        {UDS_RESPONSE_CODES_CVFICR,  "Certificate Verification Failed: Invalid Certificate (revoked)"},
        {UDS_RESPONSE_CODES_OVF,     "Ownership Verification Failed"},
        {UDS_RESPONSE_CODES_CCF,     "Challenge Calculation Failed"},
        {UDS_RESPONSE_CODES_SARF,    "Setting Access Rights Failed"},
        {UDS_RESPONSE_CODES_SKCDF,   "Session Key Creation/Derivation Failed"},
        {UDS_RESPONSE_CODES_CDUF,    "Configuration Data Usage Failed"},
        {UDS_RESPONSE_CODES_DAF,     "DeAuthentication Failed"},
        {UDS_RESPONSE_CODES_UDNA,    "Upload/Download not accepted"},
        {UDS_RESPONSE_CODES_TDS,     "Transfer data suspended"},
        {UDS_RESPONSE_CODES_GPF,     "General Programming Failure"},
        {UDS_RESPONSE_CODES_WBSC,    "Wrong Block Sequence Counter"},
        {UDS_RESPONSE_CODES_RCRRP,   "Request correctly received, but response is pending"},
        {UDS_RESPONSE_CODES_SFNSIAS, "Sub-Function not supported in active session"},
        {UDS_RESPONSE_CODES_SNSIAS,  "Service not supported in active session"},
        {UDS_RESPONSE_CODES_RPMTH,   "RPM Too High"},
        {UDS_RESPONSE_CODES_RPMTL,   "RPM Too Low"},
        {UDS_RESPONSE_CODES_EIR,     "Engine Is Running"},
        {UDS_RESPONSE_CODES_EINR,    "Engine Is Not Running"},
        {UDS_RESPONSE_CODES_ERTTL,   "Run Time Too Low"},
        {UDS_RESPONSE_CODES_TEMPTH,  "Temperature Too High"},
        {UDS_RESPONSE_CODES_TEMPTL,  "Temperature Too Low"},
        {UDS_RESPONSE_CODES_VSTH,    "Vehicle Speed Too High"},
        {UDS_RESPONSE_CODES_VSTL,    "Vehicle Speed Too Low"},
        {UDS_RESPONSE_CODES_TPTH,    "Throttle/Pedal Too High"},
        {UDS_RESPONSE_CODES_TPTL,    "Throttle/Pedal Too Low"},
        {UDS_RESPONSE_CODES_TRNIN,   "Transmission Range Not In Neutral"},
        {UDS_RESPONSE_CODES_TRNIG,   "Transmission Range Not In Gear"},
        {UDS_RESPONSE_CODES_BSNC,    "Brake Switch(es) Not Closed"},
        {UDS_RESPONSE_CODES_SLNIP,   "Shifter/Lever Not in Park"},
        {UDS_RESPONSE_CODES_TCCL,    "Torque Converter Clutch Locked"},
        {UDS_RESPONSE_CODES_VTH,     "Voltage Too High"},
        {UDS_RESPONSE_CODES_VTL,     "Voltage Too Low"},
        {UDS_RESPONSE_CODES_RTNA,    "Resource Temporarily Not Available"},
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
        {UDS_RDTCI_TYPES_EXTENDED_RECORD_BY_DTC,    "Report DTC Extended Data Record by DTC Number"},
        {UDS_RDTCI_TYPES_NUM_DTC_BY_SEVERITY_MASK,  "Report Number of DTC By Severity Mask"},
        {UDS_RDTCI_TYPES_BY_SEVERITY_MASK,          "Report DTC by Severity Mask"},
        {UDS_RDTCI_TYPES_SEVERITY_INFO_OF_DTC,      "Report Severity Information of DTC"},
        {UDS_RDTCI_TYPES_SUPPORTED_DTC,             "Report Supported DTC"},
        {UDS_RDTCI_TYPES_MOST_RECENT_TEST_FAILED,   "Report Most Recent Test Failed DTC"},
        {UDS_RDTCI_TYPES_MOST_RECENT_CONFIRMED_DTC, "Report Most Recent Confirmed DTC"},
        {UDS_RDTCI_TYPES_DTC_FAULT_DETECT_CTR,      "Report DTC Fault Detection Counter"},
        {UDS_RDTCI_TYPES_DTC_WITH_PERM_STATUS,      "Report DTC with Permanent Status"},
        {UDS_RDTCI_TYPES_DTC_EXT_DATA_REC_BY_NUM,   "Report DTC Extended Data Record by Record Number"},
        {UDS_RDTCI_TYPES_USER_MEM_DTC_BY_STATUS_M,  "Report User Defined Memory DTC By Status Mask"},
        {UDS_RDTCI_TYPES_USER_MEM_DTC_REC_BY_DTC_N, "Report User Defined Memory DTC Snapshot Record By DTC Number"},
        {UDS_RDTCI_TYPES_USER_MEM_DTC_EXT_REC_BY_N, "Report User Defined Memory DTC Extended Data Record by DTC Number"},
        {UDS_RDTCI_TYPES_SUP_DTC_EXT_RECORD,        "Report List of DTCs Supporting Specific Extended Data Record"},
        {UDS_RDTCI_TYPES_WWH_OBD_DTC_BY_MASK_REC,   "Report WWH-OBD DTC By Mask Record"},
        {UDS_RDTCI_TYPES_WWH_OBD_DTC_PERM_STATUS,   "Report WWH-OBD DTC With Permanent Status"},
        {UDS_RDTCI_TYPES_WWH_OBD_BY_GROUP_READY,    "Report WWH-OBD DTC By Readiness Group Identifier"},
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

static int hf_uds_diag_addr = -1;
static int hf_uds_diag_addr_name = -1;
static int hf_uds_diag_source_addr = -1;
static int hf_uds_diag_source_addr_name = -1;
static int hf_uds_diag_target_addr = -1;
static int hf_uds_diag_target_addr_name = -1;

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
static dissector_handle_t uds_handle_doip;
static dissector_handle_t uds_handle_iso10681;
static dissector_handle_t uds_handle_iso15765;

/*** Subdissectors ***/
static heur_dissector_list_t heur_subdissector_list;
static heur_dtbl_entry_t *heur_dtbl_entry;

/*** Configuration ***/
typedef struct _address_string {
    guint    address;
    gchar   *name;
} address_string_t;

static void *
copy_address_string_cb(void *n, const void *o, size_t size _U_) {
    address_string_t *new_rec = (address_string_t *)n;
    const address_string_t *old_rec = (const address_string_t *)o;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->address = old_rec->address;
    return new_rec;
}

static gboolean
update_address_string_cb(void *r, char **err) {
    address_string_t *rec = (address_string_t *)r;

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return FALSE;
    }

    return TRUE;
}

static void
free_address_string_cb(void *r) {
    address_string_t *rec = (address_string_t *)r;

    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static void
post_update_address_string_cb(address_string_t *data, guint data_num, GHashTable *ht) {
    guint   i;
    gint64 *key = NULL;

    if (ht == NULL) {
        return;
    }

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), gint64);
        *key = data[i].address;

        g_hash_table_insert(ht, key, g_strdup(data[i].name));
    }
}


typedef struct _generic_addr_id_string {
    guint32  address;
    guint    id;
    gchar   *name;
} generic_addr_id_string_t;

static void *
copy_generic_one_id_string_cb(void *n, const void *o, size_t size _U_) {
    generic_addr_id_string_t *new_rec = (generic_addr_id_string_t *)n;
    const generic_addr_id_string_t *old_rec = (const generic_addr_id_string_t *)o;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->id = old_rec->id;
    new_rec->address = old_rec->address;
    return new_rec;
}

static gboolean
update_generic_addr_id_16bit(void *r, char **err) {
    generic_addr_id_string_t *rec = (generic_addr_id_string_t *)r;

    if (rec->id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit identifiers (Addr: %x ID: %i  Name: %s)", rec->address, rec->id, rec->name);
        return FALSE;
    }

    if (rec->address > 0xffff && rec->address != G_MAXUINT32) {
        *err = ws_strdup_printf("We currently only support 16 bit addresses with 0xffffffff = \"don't care\" (Addr: %x  ID: %i  Name: %s)",
                                rec->address, rec->id, rec->name);
        return FALSE;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return FALSE;
    }

    return TRUE;
}

static void
free_generic_one_id_string_cb(void *r) {
    generic_addr_id_string_t *rec = (generic_addr_id_string_t *)r;

    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static gint64
calc_key(guint32 addr, guint16 id) {
    return ((gint64)id << 32) | (gint64)addr;
}

static void
post_update_one_id_string_template_cb(generic_addr_id_string_t *data, guint data_num, GHashTable *ht) {
    guint   i;
    gint64 *key = NULL;

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), gint64);
        *key = calc_key(data[i].address, data[i].id);

        g_hash_table_insert(ht, key, g_strdup(data[i].name));
    }
}

static char *
generic_lookup_addr_id(guint32 addr, guint16 id, GHashTable *ht) {
    char *ret = NULL;

    /* we only currently allow 16bit + MAXUINT32 as any */
    if (addr > G_MAXUINT16 && addr != G_MAXUINT32) {
        addr = G_MAXUINT32;
    }

    guint64 tmp = calc_key(addr, id);

    if (ht == NULL) {
        return NULL;
    }

    ret = (char *)g_hash_table_lookup(ht, &tmp);
    if (ret == NULL) {
        tmp = calc_key(G_MAXUINT32, id);
        return (char *)g_hash_table_lookup(ht, &tmp);
    }

    return ret;
}

static void
simple_free_key(gpointer key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
simple_free(gpointer data) {
    /* we need to free because of the g_strdup in post_update*/
    g_free(data);
}


/* Routine IDs */
static generic_addr_id_string_t *uds_uat_routine_ids = NULL;
static guint uds_uat_routine_id_num = 0;
static GHashTable *uds_ht_routine_ids = NULL;

UAT_HEX_CB_DEF(uds_uat_routine_ids, address, generic_addr_id_string_t)
UAT_HEX_CB_DEF(uds_uat_routine_ids, id, generic_addr_id_string_t)
UAT_CSTRING_CB_DEF(uds_uat_routine_ids, name, generic_addr_id_string_t)

static void
post_update_uds_routine_cb(void) {
    /* destroy old hash table, if it exists */
    if (uds_ht_routine_ids) {
        g_hash_table_destroy(uds_ht_routine_ids);
    }

    /* create new hash table */
    uds_ht_routine_ids = g_hash_table_new_full(g_int64_hash, g_int64_equal, &simple_free_key, &simple_free);
    post_update_one_id_string_template_cb(uds_uat_routine_ids, uds_uat_routine_id_num, uds_ht_routine_ids);
}

static char *
uds_lookup_routine_name(guint32 addr, guint16 id) {
    return generic_lookup_addr_id(addr, id, uds_ht_routine_ids);
}

static void
protoitem_append_routine_name(proto_item *ti, guint32 addr, guint16 data_identifier) {
    gchar *routine_name = uds_lookup_routine_name(addr, data_identifier);
    if (routine_name != NULL) {
        proto_item_append_text(ti, " (%s)", routine_name);
    }
}

static void
infocol_append_routine_name(packet_info *pinfo, guint32 addr, guint16 routine_identifier) {
    gchar *routine_name = uds_lookup_routine_name(addr, routine_identifier);
    if (routine_name != NULL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", routine_name);
    }
}


/* Data IDs */
static generic_addr_id_string_t *uds_uat_data_ids = NULL;
static guint uds_uat_data_id_num = 0;
static GHashTable *uds_ht_data_ids = NULL;

UAT_HEX_CB_DEF(uds_uat_data_ids, address, generic_addr_id_string_t)
UAT_HEX_CB_DEF(uds_uat_data_ids, id, generic_addr_id_string_t)
UAT_CSTRING_CB_DEF(uds_uat_data_ids, name, generic_addr_id_string_t)

static void
post_update_uds_data_cb(void) {
    /* destroy old hash table, if it exists */
    if (uds_ht_data_ids) {
        g_hash_table_destroy(uds_ht_data_ids);
    }

    /* create new hash table */
    uds_ht_data_ids = g_hash_table_new_full(g_int64_hash, g_int64_equal, &simple_free_key, &simple_free);
    post_update_one_id_string_template_cb(uds_uat_data_ids, uds_uat_data_id_num, uds_ht_data_ids);
}

static char *
uds_lookup_data_name(guint32 addr, guint16 id) {
    return generic_lookup_addr_id(addr, id, uds_ht_data_ids);
}

static void
protoitem_append_data_name(proto_item *ti, guint32 addr, guint16 data_identifier) {
    gchar *data_name = uds_lookup_data_name(addr, data_identifier);
    if (data_name != NULL) {
        proto_item_append_text(ti, " (%s)", data_name);
    }
}

static void
infocol_append_data_name(packet_info *pinfo, guint32 addr, guint16 data_identifier) {
    gchar *data_name = uds_lookup_data_name(addr, data_identifier);
    if (data_name != NULL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", data_name);
    }
}


/* Addresses */
static address_string_t *uds_uat_addresses = NULL;
static guint uds_uat_addresses_num = 0;
static GHashTable *uds_ht_addresses = NULL;

UAT_HEX_CB_DEF(uds_uat_addresses, address, address_string_t)
UAT_CSTRING_CB_DEF(uds_uat_addresses, name, address_string_t)

static void
post_update_uds_address_cb(void) {
    /* destroy old hash table, if it exists */
    if (uds_ht_addresses) {
        g_hash_table_destroy(uds_ht_addresses);
    }

    /* create new hash table */
    uds_ht_addresses = g_hash_table_new_full(g_int64_hash, g_int64_equal, &simple_free_key, &simple_free);
    post_update_address_string_cb(uds_uat_addresses, uds_uat_addresses_num, uds_ht_addresses);
}

static char *
uds_lookup_address_name(guint32 addr) {

    char *ret = NULL;
    gint64 tmp = (gint64)addr;

    if (uds_ht_addresses == NULL) {
        return NULL;
    }

    ret = (char *)g_hash_table_lookup(uds_ht_addresses, &tmp);

    return ret;
}

static void
uds_proto_item_append_address_name(proto_item *ti, guint32 addr) {
    gchar *address_name = uds_lookup_address_name(addr);
    if (address_name != NULL) {
        proto_item_append_text(ti, " (%s)", address_name);
    }
}

static proto_item *
uds_proto_tree_add_address_item(proto_tree *tree, int hf, tvbuff_t *tvb, const gint offset, const gint size, guint addr, gboolean generated, gboolean hidden) {
    proto_item *ti;

    ti = proto_tree_add_uint(tree, hf, tvb, offset, size, addr);
    uds_proto_item_append_address_name(ti, addr);

    if (generated) {
        proto_item_set_generated(ti);
    }

    if (hidden) {
        proto_item_set_hidden(ti);
    }

    return ti;
}

static proto_item *
uds_proto_tree_add_address_name(proto_tree *tree, int hf, tvbuff_t *tvb, const gint offset, const gint size, guint addr) {
    proto_item *ti;
    gchar *address_name = uds_lookup_address_name(addr);

    if (address_name != NULL) {
        ti = proto_tree_add_string(tree, hf, tvb, offset, size, address_name);
    } else {
        address_name = g_strdup_printf("%d", addr);
        ti = proto_tree_add_string(tree, hf, tvb, offset, size, address_name);
    }

    proto_item_set_generated(ti);
    proto_item_set_hidden(ti);

    return ti;
}

/*** Configuration End ***/


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

static gboolean
call_heur_subdissector_uds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 service, gboolean reply, guint32 id, guint32 uds_address)
{
    uds_info_t uds_info;

    uds_info.id = id;
    uds_info.uds_address = uds_address;
    uds_info.reply = reply;
    uds_info.service = service;

    return dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, &uds_info);
}

static int
dissect_uds_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 source_address, guint32 target_address, guint8 number_of_addresses_valid)
{
    proto_tree *uds_tree, *subtree;
    proto_item *ti;
    guint8      sid, service;
    guint32     enum_val;
    const char *service_name;
    guint32     ecu_address;
    guint32     data_length = tvb_reported_length(tvb);
    tvbuff_t   *payload_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDS");
    col_clear(pinfo->cinfo,COL_INFO);

    sid = tvb_get_guint8(tvb, UDS_SID_OFFSET);
    service = sid & UDS_SID_MASK;
    service_name = val_to_str(service, uds_services, "Unknown (0x%02x)");

    col_add_fstr(pinfo->cinfo, COL_INFO, "%-7s   %-36s", (sid & UDS_REPLY_MASK)? "Reply": "Request", service_name);

    ti = proto_tree_add_item(tree, proto_uds, tvb, 0, -1, ENC_NA);
    uds_tree = proto_item_add_subtree(ti, ett_uds);

    if (sid & UDS_REPLY_MASK) {
        ecu_address = source_address;
    } else {
        ecu_address = target_address;
    }

    switch (number_of_addresses_valid) {
    case 0:
        ecu_address = G_MAXUINT32;
        break;
    case 1:
        proto_item_append_text(ti, ", Address: 0x%04x", source_address);
        uds_proto_item_append_address_name(ti, source_address);

        uds_proto_tree_add_address_item(uds_tree, hf_uds_diag_addr, tvb, 0, 0, source_address, false, false);
        uds_proto_tree_add_address_name(uds_tree, hf_uds_diag_addr_name, tvb, 0, 0, source_address);
        break;
    case 2:
        proto_item_append_text(ti, ", Source: 0x%04x", source_address);
        uds_proto_item_append_address_name(ti, source_address);
        proto_item_append_text(ti, ", Target: 0x%04x", target_address);
        uds_proto_item_append_address_name(ti, target_address);

        uds_proto_tree_add_address_item(uds_tree, hf_uds_diag_source_addr, tvb, 0, 0, source_address, false, false);
        uds_proto_tree_add_address_name(uds_tree, hf_uds_diag_source_addr_name, tvb, 0, 0, source_address);

        uds_proto_tree_add_address_item(uds_tree, hf_uds_diag_addr, tvb, 0, 0, source_address, true, true);
        uds_proto_tree_add_address_name(uds_tree, hf_uds_diag_addr_name, tvb, 0, 0, source_address);

        uds_proto_tree_add_address_item(uds_tree, hf_uds_diag_target_addr, tvb, 0, 0, target_address, false, false);
        uds_proto_tree_add_address_name(uds_tree, hf_uds_diag_target_addr_name, tvb, 0, 0, target_address);

        uds_proto_tree_add_address_item(uds_tree, hf_uds_diag_addr, tvb, 0, 0, target_address, true, true);
        uds_proto_tree_add_address_name(uds_tree, hf_uds_diag_addr_name, tvb, 0, 0, target_address);
        break;
    }

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
                if (parameter_record_length != 0) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                    tvb_bytes_to_str_punct(pinfo->pool, tvb, UDS_DSC_PARAMETER_RECORD_OFFSET,
                                                           parameter_record_length, ' '));
                }

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
                            tvb_bytes_to_str_punct(pinfo->pool, tvb, UDS_RDTCI_RECORD_OFFSET, record_length, ' '));
            break;
        }
        case UDS_SERVICES_RDBI:
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rdbi, NULL, service_name);
            if (sid & UDS_REPLY_MASK) {
                /* Can't know the size of the data for each identifier, Decode like if there is only one idenfifier */
                guint32 record_length = data_length - UDS_RDBI_DATA_RECORD_OFFSET;
                guint32 data_identifier;
                ti = proto_tree_add_item_ret_uint(subtree, hf_uds_rdbi_data_identifier, tvb,
                                                  UDS_RDBI_DATA_IDENTIFIER_OFFSET, UDS_RDBI_DATA_IDENTIFIER_LEN,
                                                  ENC_BIG_ENDIAN, &data_identifier);
                protoitem_append_data_name(ti, ecu_address, (guint16)data_identifier);

                proto_tree_add_item(subtree, hf_uds_rdbi_data_record, tvb, UDS_RDBI_DATA_RECORD_OFFSET,
                                    record_length, ENC_NA);

                payload_tvb = tvb_new_subset_length(tvb, UDS_RDBI_DATA_RECORD_OFFSET, record_length);
                call_heur_subdissector_uds(payload_tvb, pinfo, tree, service, TRUE, data_identifier, ecu_address);

                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
                infocol_append_data_name(pinfo, ecu_address, data_identifier);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                tvb_bytes_to_str_punct(pinfo->pool, tvb, UDS_RDBI_DATA_RECORD_OFFSET,
                                                       record_length, ' '));
            } else {
                guint32 identifier_length = data_length - UDS_RDBI_DATA_IDENTIFIER_OFFSET;
                guint32 offset = UDS_RDBI_DATA_IDENTIFIER_OFFSET;
                while (identifier_length > 0) {
                    guint32 data_identifier;
                    ti = proto_tree_add_item_ret_uint(subtree, hf_uds_rdbi_data_identifier, tvb, offset,
                                                      UDS_RDBI_DATA_IDENTIFIER_LEN, ENC_BIG_ENDIAN, &data_identifier);
                    protoitem_append_data_name(ti, ecu_address, (guint16)data_identifier);

                    col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
                    infocol_append_data_name(pinfo, ecu_address, data_identifier);
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
                                    tvb_bytes_to_str_punct(pinfo->pool, tvb, UDS_SA_SEED_OFFSET, seed_length,
                                                           ' '));
                }
            } else {
                guint32 key_length = data_length - UDS_SA_KEY_OFFSET;
                if (key_length > 0) {
                    proto_tree_add_item(subtree, hf_uds_sa_key, tvb, UDS_SA_KEY_OFFSET, key_length, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                    tvb_bytes_to_str_punct(pinfo->pool, tvb, UDS_SA_KEY_OFFSET, key_length,
                                                           ' '));
                }
            }
            break;

        case UDS_SERVICES_WDBI:
            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_wdbi, NULL, service_name);
            ti = proto_tree_add_item_ret_uint(subtree, hf_uds_wdbi_data_identifier, tvb,
                                              UDS_WDBI_DATA_IDENTIFIER_OFFSET, UDS_WDBI_DATA_IDENTIFIER_LEN,
                                              ENC_BIG_ENDIAN, &enum_val);
            protoitem_append_data_name(ti, ecu_address, (guint16)enum_val);
            if (sid & UDS_REPLY_MASK) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", enum_val);
                infocol_append_data_name(pinfo, ecu_address, enum_val);
            } else {
                guint32 record_length = data_length - UDS_WDBI_DATA_RECORD_OFFSET;
                proto_tree_add_item(subtree, hf_uds_wdbi_data_record, tvb, UDS_WDBI_DATA_RECORD_OFFSET,
                                    record_length, ENC_NA);

                payload_tvb = tvb_new_subset_length(tvb, UDS_WDBI_DATA_RECORD_OFFSET, record_length);
                call_heur_subdissector_uds(payload_tvb, pinfo, tree, service, FALSE, enum_val, ecu_address);

                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", enum_val);
                infocol_append_data_name(pinfo, ecu_address, enum_val);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                tvb_bytes_to_str_punct(pinfo->pool, tvb, UDS_WDBI_DATA_RECORD_OFFSET,
                                                       record_length, ' '));
            }
            break;

        case UDS_SERVICES_IOCBI: {
            guint32 data_identifier;
            guint32 state_length = data_length - UDS_IOCBI_STATE_OFFSET;

            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_iocbi, NULL, service_name);
            ti = proto_tree_add_item_ret_uint(subtree, hf_uds_iocbi_data_identifier, tvb,
                                              UDS_IOCBI_DATA_IDENTIFIER_OFFSET, UDS_IOCBI_DATA_IDENTIFIER_LEN,
                                              ENC_BIG_ENDIAN, &data_identifier);
            protoitem_append_data_name(ti, ecu_address, (guint16)data_identifier);

            proto_tree_add_item_ret_uint(subtree, hf_uds_iocbi_parameter, tvb, UDS_IOCBI_PARAMETER_OFFSET,
                                         UDS_IOCBI_PARAMETER_LEN, ENC_BIG_ENDIAN, &enum_val);

            proto_tree_add_item(subtree, hf_uds_iocbi_state, tvb, UDS_IOCBI_STATE_OFFSET,
                                state_length, ENC_NA);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
            infocol_append_data_name(pinfo, ecu_address, data_identifier);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  %s %s",
                            val_to_str(enum_val, uds_iocbi_parameters, "Unknown (0x%02x)"),
                            tvb_bytes_to_str_punct(pinfo->pool, tvb, UDS_IOCBI_STATE_OFFSET,
                                                   state_length, ' '));
            break;
        }
        case UDS_SERVICES_RC: {
            guint32 identifier;

            subtree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rc, NULL, service_name);
            proto_tree_add_item_ret_uint(subtree, hf_uds_rc_type, tvb, UDS_RC_TYPE_OFFSET,
                                UDS_RC_TYPE_LEN, ENC_BIG_ENDIAN, &enum_val);

            ti = proto_tree_add_item_ret_uint(subtree, hf_uds_rc_identifier, tvb, UDS_RC_ROUTINE_OFFSET,
                                UDS_RC_ROUTINE_LEN, ENC_BIG_ENDIAN, &identifier);
            protoitem_append_routine_name(ti, ecu_address, identifier);

            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s 0x%04x",
                            val_to_str(enum_val, uds_rc_types, "Unknown (0x%02x)"), identifier);
            infocol_append_routine_name(pinfo, ecu_address, identifier);
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
                                        tvb_bytes_to_str_punct(pinfo->pool, tvb,
                                                               UDS_RC_STATUS_RECORD_OFFSET, status_record_len, ' '));

                        payload_tvb = tvb_new_subset_length(tvb, UDS_RC_STATUS_RECORD_OFFSET, status_record_len);
                        call_heur_subdissector_uds(payload_tvb, pinfo, tree, service, TRUE, identifier, ecu_address);
                    }
                }
            } else {
                guint32 option_record_len = data_length - UDS_RC_OPTION_RECORD_OFFSET;
                if (option_record_len > 0) {
                    proto_tree_add_item(subtree, hf_uds_rc_option_record, tvb,
                                        UDS_RC_OPTION_RECORD_OFFSET, option_record_len, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                    tvb_bytes_to_str_punct(pinfo->pool, tvb,
                                                           UDS_RC_OPTION_RECORD_OFFSET, option_record_len, ' '));

                    payload_tvb = tvb_new_subset_length(tvb, UDS_RC_OPTION_RECORD_OFFSET, option_record_len);
                    call_heur_subdissector_uds(payload_tvb, pinfo, tree, service, FALSE, identifier, ecu_address);
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

                col_append_fstr(pinfo->cinfo, COL_INFO, "   Max Number Of Block Length 0x%" PRIx64,
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

                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%" PRIx64 " bytes at 0x%" PRIx64, memory_size, memory_address);

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

static int
dissect_uds_no_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    return dissect_uds_internal(tvb, pinfo, tree, 0, 0, 0);
}

static int
dissect_uds_doip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data) {
    DISSECTOR_ASSERT(data);

    doip_info_t *doip_info = (doip_info_t *)data;
    return dissect_uds_internal(tvb, pinfo, tree, doip_info->source_address, doip_info->target_address, 2);
}

static int
dissect_uds_iso15765(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data) {
    DISSECTOR_ASSERT(data);

    iso15765_info_t *info = (iso15765_info_t *)data;
    return dissect_uds_internal(tvb, pinfo, tree, info->source_address, info->target_address, info->number_of_addresses_valid);
}

static int
dissect_uds_iso10681(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data) {
    DISSECTOR_ASSERT(data);

    iso10681_info_t *info = (iso10681_info_t *)data;
    return dissect_uds_internal(tvb, pinfo, tree, info->source_address, info->target_address, 2);
}

static void
pref_update_uds(void) {
    if (uds_ht_routine_ids && uds_uat_routine_id_num == 0) {
        g_hash_table_destroy(uds_ht_routine_ids);
        uds_ht_routine_ids = NULL;
    }

    if (uds_ht_data_ids && uds_uat_data_id_num == 0) {
        g_hash_table_destroy(uds_ht_data_ids);
        uds_ht_data_ids = NULL;
    }
}

void
proto_register_uds(void)
{
    module_t* uds_module;
    static hf_register_info hf[] = {
            {
                    &hf_uds_diag_addr,
                    {
                            "Diagnostic Address", "uds.diag_addr",
                            FT_UINT16,  BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_diag_addr_name,
                    {
                            "Diagnostic Address Name", "uds.diag_addr_name",
                            FT_STRING,  BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_diag_source_addr,
                    {
                            "Diagnostic Source Address", "uds.diag_addr_source",
                            FT_UINT16,  BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_diag_source_addr_name,
                    {
                            "Diagnostic Source Address Name", "uds.diag_addr_source_name",
                            FT_STRING,  BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_diag_target_addr,
                    {
                            "Diagnostic Target Address", "uds.diag_addr_target",
                            FT_UINT16,  BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_diag_target_addr_name,
                    {
                            "Diagnostic Target Address Name", "uds.diag_addr_target_name",
                            FT_STRING,  BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
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
                            "Parameter Record", "uds.dsc.parameter_record",
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

    uat_t* uds_routine_ids_uat;
    uat_t* uds_data_ids_uat;
    uat_t* uds_address_uat;

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

    uds_handle = register_dissector("uds", dissect_uds_no_data, proto_uds);
    uds_handle_doip = register_dissector("uds_over_doip", dissect_uds_doip, proto_uds);
    uds_handle_iso10681 = register_dissector("uds_over_iso10681", dissect_uds_iso10681, proto_uds);
    uds_handle_iso15765 = register_dissector("uds_over_iso15765", dissect_uds_iso15765, proto_uds);

    /* Register preferences */
    uds_module = prefs_register_protocol(proto_uds, &pref_update_uds);

    /* UATs for user_data fields */
    static uat_field_t uds_routine_id_uat_fields[] = {
        UAT_FLD_HEX(uds_uat_routine_ids, address, "Address", "Address (16bit hex without leading 0x, 0xffffffff for 'any')"),
        UAT_FLD_HEX(uds_uat_routine_ids, id, "Routine ID", "Routine Identifier (16bit hex without leading 0x)"),
        UAT_FLD_CSTRING(uds_uat_routine_ids, name, "Routine Name", "Name of the Routine ID (string)"),
        UAT_END_FIELDS
    };

    /* UATs */
    uds_routine_ids_uat = uat_new("UDS Routine Identifier List",
        sizeof(generic_addr_id_string_t),           /* record size           */
        DATAFILE_UDS_ROUTINE_IDS,                   /* filename              */
        TRUE,                                       /* from profile          */
        (void**)&uds_uat_routine_ids,               /* data_ptr              */
        &uds_uat_routine_id_num,                    /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_generic_one_id_string_cb,              /* copy callback         */
        update_generic_addr_id_16bit,               /* update callback       */
        free_generic_one_id_string_cb,              /* free callback         */
        post_update_uds_routine_cb,                 /* post update callback  */
        NULL,                                       /* reset callback        */
        uds_routine_id_uat_fields                   /* UAT field definitions */
    );

    prefs_register_uat_preference(uds_module, "_uds_routine_id_list", "UDS Routine Identifier List",
        "A table to define names of UDS Routines", uds_routine_ids_uat);

    static uat_field_t uds_data_id_uat_fields[] = {
        UAT_FLD_HEX(uds_uat_data_ids, address, "Address", "Address (16bit hex without leading 0x, 0xffffffff for 'any')"),
        UAT_FLD_HEX(uds_uat_data_ids, id, "Data ID", "Data Identifier (16bit hex without leading 0x)"),
        UAT_FLD_CSTRING(uds_uat_data_ids, name, "Data Name", "Name of the Data ID (string)"),
        UAT_END_FIELDS
    };

    uds_data_ids_uat = uat_new("UDS Data Identifier List",
        sizeof(generic_addr_id_string_t),           /* record size           */
        DATAFILE_UDS_DATA_IDS,                      /* filename              */
        TRUE,                                       /* from profile          */
        (void**)&uds_uat_data_ids,                  /* data_ptr              */
        &uds_uat_data_id_num,                       /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_generic_one_id_string_cb,              /* copy callback         */
        update_generic_addr_id_16bit,               /* update callback       */
        free_generic_one_id_string_cb,              /* free callback         */
        post_update_uds_data_cb,                    /* post update callback  */
        NULL,                                       /* reset callback        */
        uds_data_id_uat_fields                      /* UAT field definitions */
    );

    prefs_register_uat_preference(uds_module, "_uds_data_id_list", "UDS Data Identifier List",
        "A table to define names of UDS Data Identifier", uds_data_ids_uat);

    static uat_field_t uds_address_name_uat_fields[] = {
        UAT_FLD_HEX(uds_uat_addresses, address, "Address", "Address (32bit hex without leading 0x)"),
        UAT_FLD_CSTRING(uds_uat_addresses, name, "Name", "Name of the Address (string)"),
        UAT_END_FIELDS
    };

    uds_address_uat = uat_new("UDS Addresses",
        sizeof(address_string_t),                   /* record size           */
        DATAFILE_UDS_ADDRESSES,                     /* filename              */
        TRUE,                                       /* from profile          */
        (void**)&uds_uat_addresses,                 /* data_ptr              */
        &uds_uat_addresses_num,                     /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_address_string_cb,                     /* copy callback         */
        update_address_string_cb,                   /* update callback       */
        free_address_string_cb,                     /* free callback         */
        post_update_uds_address_cb,                 /* post update callback  */
        NULL,                                       /* reset callback        */
        uds_address_name_uat_fields                 /* UAT field definitions */
    );

    prefs_register_uat_preference(uds_module, "_uds_address_list", "UDS Address List",
        "A table to define names of UDS Addresses", uds_address_uat);

    heur_subdissector_list = register_heur_dissector_list("uds", proto_uds);
}

void
proto_reg_handoff_uds(void)
{
    dissector_add_for_decode_as("iso10681.subdissector", uds_handle_iso10681);
    dissector_add_for_decode_as("iso15765.subdissector", uds_handle_iso15765);
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
