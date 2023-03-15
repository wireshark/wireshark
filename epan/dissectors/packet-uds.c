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

#define UDS_DSC_TYPES_DEFAULT_SESSION                   1
#define UDS_DSC_TYPES_PROGRAMMING_SESSION               2
#define UDS_DSC_TYPES_EXTENDED_DIAGNOSTIC_SESSION       3
#define UDS_DSC_TYPES_SAFETY_SYSTEM_DIAGNOSTIC_SESSION  4

#define UDS_ER_TYPES_HARD_RESET                   1
#define UDS_ER_TYPES_KEY_OFF_ON_RESET             2
#define UDS_ER_TYPES_SOFT_RESET                   3
#define UDS_ER_TYPES_ENABLE_RAPID_POWER_SHUTDOWN  4
#define UDS_ER_TYPES_DISABLE_RAPID_POWER_SHUTDOWN 5

#define UDS_ER_TYPE_ENABLE_RAPID_POWER_SHUTDOWN_INVALID 0xFF

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
#define UDS_RDTCI_TYPES_FIRST_TEST_FAILED_DTC     0xB
#define UDS_RDTCI_TYPES_FIRST_CONFIRMED_DTC       0xC
#define UDS_RDTCI_TYPES_MOST_RECENT_TEST_FAILED   0xD
#define UDS_RDTCI_TYPES_MOST_RECENT_CONFIRMED_DTC 0xE
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

#define UDS_SA_TYPES_RESERVED                     0x00
#define UDS_SA_TYPES_REQUEST_SEED                 0x01
#define UDS_SA_TYPES_SEND_KEY                     0x02
#define UDS_SA_TYPES_REQUEST_SEED_ISO26021        0x03
#define UDS_SA_TYPES_SEND_KEY_ISO26021            0x04
#define UDS_SA_TYPES_SUPPLIER                     0xFE
#define UDS_SA_TYPES_UNCLEAR                      0xFF

#define UDS_IOCBI_PARAMETERS_RETURN_CONTROL_TO_ECU 0
#define UDS_IOCBI_PARAMETERS_RESET_TO_DEFAULT      1
#define UDS_IOCBI_PARAMETERS_FREEZE_CURRENT_STATE  2
#define UDS_IOCBI_PARAMETERS_SHORT_TERM_ADJUSTMENT 3

#define UDS_RC_TYPES_START   1
#define UDS_RC_TYPES_STOP    2
#define UDS_RC_TYPES_REQUEST 3

#define UDS_RD_COMPRESSION_METHOD_MASK          0xF0
#define UDS_RD_ENCRYPTING_METHOD_MASK           0x0F
#define UDS_RD_MEMORY_SIZE_LENGTH_MASK          0xF0
#define UDS_RD_MEMORY_ADDRESS_LENGTH_MASK       0x0F
#define UDS_RD_MAX_BLOCK_LEN_LEN_MASK           0xF0

#define UDS_TP_SUBFUNCTION_MASK                 0x7f
#define UDS_TP_SUPPRESS_POS_RSP_MSG_IND_MASK    0x80

#define UDS_CDTCS_ACTIONS_ON  1
#define UDS_CDTCS_ACTIONS_OFF 2

#define UDS_DID_BSIDID          0xF180
#define UDS_DID_ASIDID          0xF181
#define UDS_DID_ADIDID          0xF182
#define UDS_DID_BSFPDID         0xF183
#define UDS_DID_ASFPDID         0xF184
#define UDS_DID_ADFPDID         0xF185
#define UDS_DID_ADSDID          0xF186
#define UDS_DID_VMSPNDID        0xF187
#define UDS_DID_VMECUSNDID      0xF188
#define UDS_DID_VMECUSVNDID     0xF189
#define UDS_DID_SSIDDID         0xF18A
#define UDS_DID_ECUMDDID        0xF18B
#define UDS_DID_ECUSNDID        0xF18C
#define UDS_DID_SFUDID          0xF18D
#define UDS_DID_VMKAPNDID       0xF18E
#define UDS_DID_RXSWIN          0xF18F
#define UDS_DID_VINDID          0xF190
#define UDS_DID_VMECUHNDID      0xF191
#define UDS_DID_SSECUHWNDID     0xF192
#define UDS_DID_SSECUHWVNDID    0xF193
#define UDS_DID_SSECUSWNDID     0xF194
#define UDS_DID_SSECUSWVNDID    0xF195
#define UDS_DID_EROTANDID       0xF196
#define UDS_DID_SNOETDID        0xF197
#define UDS_DID_RSCOTSNDID      0xF198
#define UDS_DID_PDDID           0xF199
#define UDS_DID_CRSCOCESNDID    0xF19A
#define UDS_DID_CDDID           0xF19B
#define UDS_DID_CESWNDID        0xF19D
#define UDS_DID_EIDDID          0xF19D
#define UDS_DID_ODXFDID         0xF19E
#define UDS_DID_EDID            0xF19F
#define UDS_DID_ADDID_FA00      0xFA00
#define UDS_DID_ADDID_FA01      0xFA01
#define UDS_DID_ADDID_FA02      0xFA02
#define UDS_DID_ADDID_FA03      0xFA03
#define UDS_DID_ADDID_FA04      0xFA04
#define UDS_DID_ADDID_FA05      0xFA05
#define UDS_DID_ADDID_FA06      0xFA06
#define UDS_DID_ADDID_FA07      0xFA07
#define UDS_DID_ADDID_FA08      0xFA08
#define UDS_DID_ADDID_FA09      0xFA09
#define UDS_DID_ADDID_FA0A      0xFA0A
#define UDS_DID_ADDID_FA0B      0xFA0B
#define UDS_DID_ADDID_FA0C      0xFA0C
#define UDS_DID_ADDID_FA0D      0xFA0D
#define UDS_DID_ADDID_FA0E      0xFA0E
#define UDS_DID_ADDID_FA0F      0xFA0F
#define UDS_DID_NOEDRD          0xFA10
#define UDS_DID_EDRI            0xFA11
#define UDS_DID_EDRDAI          0xFA12
#define UDS_DID_UDSVDID         0xFF00
#define UDS_DID_RESRVDCPADLC    0xFF01

#define UDS_RID_EXSPLRI_        0xE200
#define UDS_RID_DLRI_           0xE201
#define UDS_RID_EM_             0xFF00
#define UDS_RID_CPD_            0xFF01
#define UDS_RID_FF02            0xFF02

/*
 * Enums
 */

/* Services */
static const value_string uds_services[]= {
        {OBD_SERVICES_0x01,  "OBD - Request Current Powertrain Diagnostic Data"},
        {OBD_SERVICES_0x02,  "OBD - Request Powertrain Freeze Frame Data"},
        {OBD_SERVICES_0x03,  "OBD - Request Emission-Related Diagnostic Trouble Codes"},
        {OBD_SERVICES_0x04,  "OBD - Clear/Reset Emission-Related Diagnostic Information"},
        {OBD_SERVICES_0x05,  "OBD - Request Oxygen Sensor Monitoring Test Results"},
        {OBD_SERVICES_0x06,  "OBD - Request On-Board Monitoring Test Results for Specific Monitored Systems"},
        {OBD_SERVICES_0x07,  "OBD - Request Emission-Related Diagnostic Trouble Codes Detected During Current or Last Completed Driving Cycle"},
        {OBD_SERVICES_0x08,  "OBD - Request Control of On-Board System, Test or Component"},
        {OBD_SERVICES_0x09,  "OBD - Request Vehicle Information"},
        {OBD_SERVICES_0x0A,  "OBD - Request Emission-Related Diagnostic Trouble Codes with Permanent Status"},
        {OBD_SERVICES_0x0B,  "OBD - Unknown Service"},
        {OBD_SERVICES_0x0C,  "OBD - Unknown Service"},
        {OBD_SERVICES_0x0D,  "OBD - Unknown Service"},
        {OBD_SERVICES_0x0E,  "OBD - Unknown Service"},
        {OBD_SERVICES_0x0F,  "OBD - Unknown Service"},

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
        {UDS_SERVICES_SDT,   "Secured Data Transmission"},
        {UDS_SERVICES_CDTCS, "Control DTC Setting"},
        {UDS_SERVICES_ROE,   "Response On Event"},
        {UDS_SERVICES_LC,    "Link Control"},
        {0, NULL}
};
/* Response code */
static const value_string uds_response_codes[]= {
        {UDS_RESPONSE_CODES_GR,      "General reject"},
        {UDS_RESPONSE_CODES_SNS,     "Service not supported"},
        {UDS_RESPONSE_CODES_SFNS,    "SubFunction Not Supported"},
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
        {UDS_RESPONSE_CODES_SFNSIAS, "Subfunction not supported in active session"},
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
        {UDS_ER_TYPES_KEY_OFF_ON_RESET,             "Key Off On Reset"},
        {UDS_ER_TYPES_SOFT_RESET,                   "Soft Reset"},
        {UDS_ER_TYPES_ENABLE_RAPID_POWER_SHUTDOWN,  "Enable Rapid Power Shutdown"},
        {UDS_ER_TYPES_DISABLE_RAPID_POWER_SHUTDOWN, "Disable Rapid Power Shutdown"},
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
        {UDS_RDTCI_TYPES_FIRST_TEST_FAILED_DTC,     "Report First Test Failed DTC"},
        {UDS_RDTCI_TYPES_FIRST_CONFIRMED_DTC,       "Report First Confirmed DTC"},
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

/* DIDS */
static const value_string uds_standard_did_types[] = {
        {UDS_DID_BSIDID,        "BootSoftwareIdentificationDataIdentifier"},
        {UDS_DID_ASIDID,        "applicationSoftwareIdentificationDataIdentifier"},
        {UDS_DID_ADIDID,        "applicationDataIdentificationDataIdentifier"},
        {UDS_DID_BSFPDID,       "bootSoftwareFingerprintDataIdentifier"},
        {UDS_DID_ASFPDID,       "applicationSoftwareFingerprintDataIdentifier"},
        {UDS_DID_ADFPDID,       "applicationDataFingerprintDataIdentifier"},
        {UDS_DID_ADSDID,        "ActiveDiagnosticSessionDataIdentifier"},
        {UDS_DID_VMSPNDID,      "vehicleManufacturerSparePartNumberDataIdentifier"},
        {UDS_DID_VMECUSNDID,    "vehicleManufacturerECUSoftwareNumberDataIdentifier"},
        {UDS_DID_VMECUSVNDID,   "vehicleManufacturerECUSoftwareVersionNumberDataIdentifier"},
        {UDS_DID_SSIDDID,       "systemSupplierIdentifierDataIdentifier"},
        {UDS_DID_ECUMDDID,      "ECUManufacturingDateDataIdentifier (year/month/day)"},
        {UDS_DID_ECUSNDID,      "ECUSerialNumberDataIdentifier"},
        {UDS_DID_SFUDID,        "supportedFunctionalUnitsDataIdentifier"},
        {UDS_DID_VMKAPNDID,     "VehicleManufacturerKitAssemblyPartNumberDataIdentifier"},
        {UDS_DID_RXSWIN,        "RegulationXSoftwareIdentificationNumbers (RxSWIN)"},
        {UDS_DID_VINDID,        "VINDataIdentifier"},
        {UDS_DID_VMECUHNDID,    "vehicleManufacturerECUHardwareNumberDataIdentifier"},
        {UDS_DID_SSECUHWNDID,   "systemSupplierECUHardwareNumberDataIdentifier"},
        {UDS_DID_SSECUHWVNDID,  "systemSupplierECUHardwareVersionNumberDataIdentifier"},
        {UDS_DID_SSECUSWNDID,   "systemSupplierECUSoftwareNumberDataIdentifier"},
        {UDS_DID_SSECUSWVNDID,  "systemSupplierECUSoftwareVersionNumberDataIdentifier"},
        {UDS_DID_EROTANDID,     "exhaustRegulationOrTypeApprovalNumberDataIdentifier"},
        {UDS_DID_SNOETDID,      "systemNameOrEngineTypeDataIdentifier"},
        {UDS_DID_RSCOTSNDID,    "repairShopCodeOrTesterSerialNumberDataIdentifier"},
        {UDS_DID_PDDID,         "programmingDateDataIdentifier (year/month/day)"},
        {UDS_DID_CRSCOCESNDID,  "calibrationRepairShopCodeOrCalibrationEquipmentSerialNumberDataIdentifier"},
        {UDS_DID_CDDID,         "calibrationDateDataIdentifier (year/month/day)"},
        {UDS_DID_CESWNDID,      "calibrationEquipmentSoftwareNumberDataIdentifier"},
        {UDS_DID_EIDDID,        "ECUInstallationDateDataIdentifier (year/month/day)"},
        {UDS_DID_ODXFDID,       "ODXFileDataIdentifier"},
        {UDS_DID_EDID,          "EntityDataIdentifier"},
        {UDS_DID_ADDID_FA00,    "AirbagDeployment: Number of PCUs (ISO 26021-2)"},
        {UDS_DID_ADDID_FA01,    "AirbagDeployment: Deployment Method Version (ISO 26021-2)"},
        {UDS_DID_ADDID_FA02,    "AirbagDeployment: Address Information of PCU (ISO 26021-2)"},
        {UDS_DID_ADDID_FA03,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_ADDID_FA04,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_ADDID_FA05,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_ADDID_FA06,    "AirbagDeployment: Deployment Loop Table of PCU (ISO 26021-2)"},
        {UDS_DID_ADDID_FA07,    "AirbagDeployment: Dismantler Info (ISO 26021-2)"},
        {UDS_DID_ADDID_FA08,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_ADDID_FA09,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_ADDID_FA0A,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_ADDID_FA0B,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_ADDID_FA0C,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_ADDID_FA0D,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_ADDID_FA0E,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_ADDID_FA0F,    "AirbagDeployment (ISO 26021-2)"},
        {UDS_DID_NOEDRD,        "NumberOfEDRDevices"},
        {UDS_DID_EDRI,          "EDRIdentification"},
        {UDS_DID_EDRDAI,        "EDRDeviceAddressInformation"},
        {UDS_DID_UDSVDID,       "EDRDAI"},
        {UDS_DID_RESRVDCPADLC,  "ReservedForISO15765-5 (CAN, CAN-FD, CAN+CAN-FD, ...)"},
        {0, NULL}
};

/* RIDS */
static const value_string uds_standard_rid_types[] = {
        {UDS_RID_EXSPLRI_,      "Execute SPL"},
        {UDS_RID_DLRI_,         "DeployLoopRoutineID"},
        {UDS_RID_EM_,           "eraseMemory"},
        {UDS_RID_CPD_,          "checkProgrammingDependencies"},
        {UDS_RID_FF02,          "eraseMirrorMemoryDTCs (deprecated)"},
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

static int hf_uds_dsc_subfunction = -1;
static int hf_uds_dsc_parameter_record = -1;
static int hf_uds_dsc_default_p2_server_timer = -1;
static int hf_uds_dsc_enhanced_p2_server_timer = -1;

static int hf_uds_er_subfunction = -1;
static int hf_uds_er_power_down_time = -1;

static int hf_uds_rdtci_subfunction = -1;
static int hf_uds_rdtci_record = -1;

static int hf_uds_rdbi_data_identifier = -1;
static int hf_uds_rdbi_data_record = -1;

static int hf_uds_sa_subfunction = -1;
static int hf_uds_sa_key = -1;
static int hf_uds_sa_data_record = -1;
static int hf_uds_sa_seed = -1;

static int hf_uds_wdbi_data_identifier = -1;
static int hf_uds_wdbi_data_record = -1;

static int hf_uds_iocbi_data_identifier = -1;
static int hf_uds_iocbi_parameter = -1;
static int hf_uds_iocbi_state = -1;

static int hf_uds_rc_subfunction = -1;
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
static int hf_uds_rd_max_block_len_len = -1;
static int hf_uds_rd_max_block_len = -1;

static int hf_uds_td_sequence_counter = -1;
static int hf_uds_td_record_data = -1;

static int hf_uds_tp_subfunction = -1;
static int hf_uds_tp_subfunction_no_suppress = -1;
static int hf_uds_tp_suppress_pos_rsp_msg_ind = -1;

static int hf_uds_err_sid = -1;
static int hf_uds_err_code = -1;

static int hf_uds_cdtcs_subfunction = -1;
static int hf_uds_cdtcs_option_record = -1;
static int hf_uds_cdtcs_type = -1;

static int hf_uds_unparsed_bytes = -1;

/*
 * Trees
 */
static gint ett_uds = -1;
static gint ett_uds_subfunction = -1;
static gint ett_uds_dsc_parameter_record = -1;

static int proto_uds = -1;

static dissector_handle_t uds_handle;
static dissector_handle_t uds_handle_doip;
static dissector_handle_t uds_handle_iso10681;
static dissector_handle_t uds_handle_iso15765;
static dissector_handle_t obd_ii_handle;

/*** Subdissectors ***/
static heur_dissector_list_t heur_subdissector_list;
static heur_dtbl_entry_t *heur_dtbl_entry;

/*** Configuration ***/
static gboolean uds_dissect_small_sids_with_obd_ii = TRUE;

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

static const char *
uds_lookup_routine_name(guint32 addr, guint16 id) {
    const char *tmp = generic_lookup_addr_id(addr, id, uds_ht_routine_ids);

    if (tmp == NULL) {
        tmp = try_val_to_str(id, uds_standard_rid_types);
    }

    return tmp;
}

static void
protoitem_append_routine_name(proto_item *ti, guint32 addr, guint16 data_identifier) {
    const gchar *routine_name = uds_lookup_routine_name(addr, data_identifier);
    if (routine_name != NULL) {
        proto_item_append_text(ti, " (%s)", routine_name);
    }
}

static void
infocol_append_routine_name(packet_info *pinfo, guint32 addr, guint16 routine_identifier) {
    const gchar *routine_name = uds_lookup_routine_name(addr, routine_identifier);
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

static const char *
uds_lookup_data_name(guint32 addr, guint16 id) {
    const char *tmp = generic_lookup_addr_id(addr, id, uds_ht_data_ids);

    if (tmp == NULL) {
        tmp = try_val_to_str(id, uds_standard_did_types);
    }

    return tmp;
}

static void
protoitem_append_data_name(proto_item *ti, guint32 addr, guint16 data_identifier) {
    const gchar *data_name = uds_lookup_data_name(addr, data_identifier);
    if (data_name != NULL) {
        proto_item_append_text(ti, " (%s)", data_name);
    }
}

static void
infocol_append_data_name(packet_info *pinfo, guint32 addr, guint16 data_identifier) {
    const gchar *data_name = uds_lookup_data_name(addr, data_identifier);
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
        address_name = wmem_strdup_printf(wmem_packet_scope(), "%d", addr);
        ti = proto_tree_add_string(tree, hf, tvb, offset, size, address_name);
    }

    proto_item_set_generated(ti);
    proto_item_set_hidden(ti);

    return ti;
}

/*** Configuration End ***/

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

static guint
uds_sa_subfunction_to_type(guint8 subf) {
    subf = subf & 0x7f;

    if (subf == 0x00 || ((0x43 <= subf) && (subf <= 0x5e)) || (subf == 0x7f)) {
        return UDS_SA_TYPES_RESERVED;
    }

    if (subf == 0x5f) {
        return UDS_SA_TYPES_REQUEST_SEED_ISO26021;
    }

    if (subf == 0x60) {
        return UDS_SA_TYPES_SEND_KEY_ISO26021;
    }

    if ((0x61 <= subf) && (subf <= 0x7e)) {
        return UDS_SA_TYPES_SUPPLIER;
    }

    if ((subf & 0x01) == 0x01) {
        return UDS_SA_TYPES_REQUEST_SEED;
    }

    if ((subf & 0x01) == 0x00) {
        return UDS_SA_TYPES_SEND_KEY;
    }

    return UDS_SA_TYPES_UNCLEAR;
}

static gchar *
uds_sa_subfunction_to_string(guint8 subf) {
    switch (uds_sa_subfunction_to_type(subf)) {
    case UDS_SA_TYPES_RESERVED:
        return "Reserved";
        break;
    case UDS_SA_TYPES_SUPPLIER:
        return "System Supplier Specific";
        break;
    case UDS_SA_TYPES_REQUEST_SEED:
        return "Request Seed";
        break;
    case UDS_SA_TYPES_SEND_KEY:
        return "Send Key";
        break;
    case UDS_SA_TYPES_REQUEST_SEED_ISO26021:
        return "Request Seed ISO26021";
        break;
    case UDS_SA_TYPES_SEND_KEY_ISO26021:
        return "Send Key ISO26021";
        break;
    }

    return "Unknown";
}

static void
uds_sa_subfunction_format(gchar *ret, guint32 value) {
    if (uds_sa_subfunction_to_type(value) == UDS_SA_TYPES_UNCLEAR) {
        snprintf(ret, ITEM_LABEL_LENGTH, "0x%02x", value);
        return;
    }

    snprintf(ret, ITEM_LABEL_LENGTH, "%s (0x%02x)", uds_sa_subfunction_to_string(value), value);
}

static int
dissect_uds_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 source_address, guint32 target_address, guint8 number_of_addresses_valid)
{
    proto_tree *uds_tree;
    proto_item *ti;
    guint8      sid, service;
    guint32     enum_val;
    const char *service_name;
    guint32     ecu_address;
    guint32     data_length = tvb_reported_length(tvb);
    tvbuff_t   *payload_tvb;

    guint32     offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDS");
    col_clear(pinfo->cinfo,COL_INFO);

    sid = tvb_get_guint8(tvb, offset);
    service = sid & UDS_SID_MASK;

    if (service < UDS_SERVICES_MIN && uds_dissect_small_sids_with_obd_ii && (obd_ii_handle != NULL)) {
        return call_dissector(obd_ii_handle, tvb_new_subset_length_caplen(tvb, offset, -1, -1), pinfo, tree);
    }

    service_name = val_to_str(service, uds_services, "Unknown (0x%02x)");

    col_add_fstr(pinfo->cinfo, COL_INFO, "%-7s   %-36s", (sid & UDS_REPLY_MASK)? "Reply": "Request", service_name);

    ti = proto_tree_add_item(tree, proto_uds, tvb, offset, -1, ENC_NA);
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

    proto_tree_add_item(uds_tree, hf_uds_service, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(uds_tree, hf_uds_reply, tvb, offset, 1, ENC_NA);
    offset += 1;

    switch (service) {
        case UDS_SERVICES_DSC:
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_dsc_subfunction, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_dsc_types, "Unknown (0x%02x)"));
            offset += 1;

            if (sid & UDS_REPLY_MASK) {
                ti = proto_tree_add_item(uds_tree, hf_uds_dsc_parameter_record, tvb, offset, data_length - offset, ENC_NA);
                proto_tree *param_tree = proto_item_add_subtree(ti, ett_uds_dsc_parameter_record);

                guint32 default_p2;
                proto_tree_add_item_ret_uint(param_tree, hf_uds_dsc_default_p2_server_timer, tvb, offset, 2, ENC_BIG_ENDIAN, &default_p2);
                offset += 2;

                guint32 enhanced_p2 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) * 10;
                proto_tree_add_uint(param_tree, hf_uds_dsc_enhanced_p2_server_timer, tvb, offset, 2, enhanced_p2);
                offset += 2;

                col_append_fstr(pinfo->cinfo, COL_INFO, "   P2-default:%5dms  P2-enhanced:%6dms", default_p2, enhanced_p2);
            }
            break;

        case UDS_SERVICES_ER:
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_er_subfunction, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_er_types, "Unknown (0x%02x)"));
            offset += 1;

            if ((sid & UDS_REPLY_MASK) && (enum_val == UDS_ER_TYPES_ENABLE_RAPID_POWER_SHUTDOWN)) {
                guint32 tmp;
                ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_er_power_down_time, tvb, offset, 1, ENC_NA, &tmp);
                if (tmp == UDS_ER_TYPE_ENABLE_RAPID_POWER_SHUTDOWN_INVALID) {
                    proto_item_append_text(ti, " (Failure or time not available!)");
                }
                offset += 1;
            }
            break;

        case UDS_SERVICES_RDTCI: {
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_subfunction, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_rdtci_types, "Unknown (0x%02x)"));
            offset += 1;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_record, tvb, offset, data_length - offset, ENC_NA);
            if (data_length > offset) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "    %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                offset = data_length;
            }
            break;
        }

        case UDS_SERVICES_RDBI:
            if (sid & UDS_REPLY_MASK) {
                /* Can't know the size of the data for each identifier, Decode like if there is only one idenfifier */
                guint32 data_identifier;
                ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdbi_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &data_identifier);
                protoitem_append_data_name(ti, ecu_address, (guint16)data_identifier);
                offset += 2;

                /* ISO14229: at least one byte for data record. Just make sure, we show an error, if less than 1 byte left! */
                proto_tree_add_item(uds_tree, hf_uds_rdbi_data_record, tvb, offset, MAX(1, data_length - offset), ENC_NA);

                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
                infocol_append_data_name(pinfo, ecu_address, data_identifier);

                if (data_length > offset) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));

                    payload_tvb = tvb_new_subset_length(tvb, offset, data_length - offset);
                    call_heur_subdissector_uds(payload_tvb, pinfo, tree, service, TRUE, data_identifier, ecu_address);

                    offset = data_length;
                }
            } else {
                /* ISO14229: data identifiers are 2 bytes and at least one has to be present. */
                do {
                    guint32 data_identifier;
                    ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdbi_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &data_identifier);
                    protoitem_append_data_name(ti, ecu_address, (guint16)data_identifier);

                    col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
                    infocol_append_data_name(pinfo, ecu_address, data_identifier);
                    offset += 2;
                } while (data_length >= offset + 2);
            }
            break;

        case UDS_SERVICES_SA:
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_sa_subfunction, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s (0x%02x)", uds_sa_subfunction_to_string(enum_val), enum_val);
            offset += 1;

            if (data_length > offset) {
                if (sid & UDS_REPLY_MASK) {
                    switch (uds_sa_subfunction_to_type(enum_val)) {
                    case UDS_SA_TYPES_SEND_KEY: /* fall through */
                    case UDS_SA_TYPES_SEND_KEY_ISO26021:
                        /* do nothing */
                        break;
                    case UDS_SA_TYPES_REQUEST_SEED: /* fall through */
                    case UDS_SA_TYPES_REQUEST_SEED_ISO26021:
                        proto_tree_add_item(uds_tree, hf_uds_sa_seed, tvb, offset, data_length - offset, ENC_NA);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                        break;
                    default:
                        proto_tree_add_item(uds_tree, hf_uds_sa_data_record, tvb, offset, data_length - offset, ENC_NA);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                    }
                } else {
                    switch (uds_sa_subfunction_to_type(enum_val)) {
                    case UDS_SA_TYPES_SEND_KEY: /* fall through */
                    case UDS_SA_TYPES_SEND_KEY_ISO26021:
                        proto_tree_add_item(uds_tree, hf_uds_sa_key, tvb, offset, data_length - offset, ENC_NA);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                        break;
                    case UDS_SA_TYPES_REQUEST_SEED: /* fall through */
                    case UDS_SA_TYPES_REQUEST_SEED_ISO26021:
                    default:
                        proto_tree_add_item(uds_tree, hf_uds_sa_data_record, tvb, offset, data_length - offset, ENC_NA);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                    }
                }
                offset = data_length;
            }
            break;

        case UDS_SERVICES_WDBI:
            ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_wdbi_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &enum_val);
            protoitem_append_data_name(ti, ecu_address, (guint16)enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", enum_val);
            infocol_append_data_name(pinfo, ecu_address, enum_val);
            offset += 2;

            if (!(sid & UDS_REPLY_MASK)) {
                /* This needs to be at least one byte says the standard */
                proto_tree_add_item(uds_tree, hf_uds_wdbi_data_record, tvb, offset, MAX(1, data_length - offset), ENC_NA);

                if (data_length > offset) {
                    payload_tvb = tvb_new_subset_length(tvb, offset, data_length - offset);
                    call_heur_subdissector_uds(payload_tvb, pinfo, tree, service, FALSE, enum_val, ecu_address);

                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                }

                offset = data_length;
            }
            break;

        case UDS_SERVICES_IOCBI: {
            guint32 data_identifier;
            ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_iocbi_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &data_identifier);
            protoitem_append_data_name(ti, ecu_address, (guint16)data_identifier);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
            infocol_append_data_name(pinfo, ecu_address, data_identifier);
            offset += 2;

            proto_tree_add_item_ret_uint(uds_tree, hf_uds_iocbi_parameter, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", val_to_str(enum_val, uds_iocbi_parameters, "Unknown (0x%02x)"));
            offset += 1;

            /* The exact format depends on vehicle manufacturer and config. Not much we can do here. */
            if (data_length > offset) {
                proto_tree_add_item(uds_tree, hf_uds_iocbi_state, tvb, offset, data_length - offset, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
            }
            offset = data_length;
            break;
        }

        case UDS_SERVICES_RC: {
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rc_subfunction, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_rc_types, "Unknown (0x%02x)"));
            offset += 1;

            guint32 identifier;
            ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_rc_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &identifier);
            protoitem_append_routine_name(ti, ecu_address, identifier);
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x", identifier);
            infocol_append_routine_name(pinfo, ecu_address, identifier);
            offset += 2;

            if (sid & UDS_REPLY_MASK) {
                if (data_length > offset) {
                    guint32 info;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_rc_info, tvb, offset, 1, ENC_NA, &info);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%x", info);
                    offset += 1;

                    if (data_length > offset) {
                        proto_tree_add_item(uds_tree, hf_uds_rc_status_record, tvb, offset, data_length - offset, ENC_NA);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));

                        payload_tvb = tvb_new_subset_length(tvb, offset, data_length - offset);
                        call_heur_subdissector_uds(payload_tvb, pinfo, tree, service, TRUE, identifier, ecu_address);
                        offset = data_length;
                    }
                }
            } else {
                if (data_length > offset) {
                    proto_tree_add_item(uds_tree, hf_uds_rc_option_record, tvb, offset, data_length - offset, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));

                    payload_tvb = tvb_new_subset_length(tvb, offset, data_length - offset);
                    call_heur_subdissector_uds(payload_tvb, pinfo, tree, service, FALSE, identifier, ecu_address);
                    offset = data_length;
                }
            }
            break;
        }

        case UDS_SERVICES_RD:
            if (sid & UDS_REPLY_MASK) {
                guint32 max_block_length_length;
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_rd_max_block_len_len, tvb, offset, 1, ENC_NA, &max_block_length_length);
                offset += 1;

                guint64 max_block_length;
                proto_tree_add_item_ret_uint64(uds_tree, hf_uds_rd_max_block_len, tvb, offset, max_block_length_length, ENC_BIG_ENDIAN, &max_block_length);
                offset += max_block_length_length;

                col_append_fstr(pinfo->cinfo, COL_INFO, "   Max Block Length 0x%" PRIx64, max_block_length);
            } else {
                guint32 compression, encrypting;
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_rd_compression_method, tvb, offset, 1, ENC_NA, &compression);
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_rd_encrypting_method, tvb, offset, 1, ENC_NA, &encrypting);
                offset += 1;

                guint32 memory_size_length, memory_address_length;
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_rd_memory_size_length, tvb, offset, 1, ENC_NA, &memory_size_length);
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_rd_memory_address_length, tvb, offset, 1, ENC_NA, &memory_address_length);
                offset += 1;

                guint64 memory_address;
                proto_tree_add_item_ret_uint64(uds_tree, hf_uds_rd_memory_address, tvb, offset, memory_address_length, ENC_BIG_ENDIAN, &memory_address);
                offset += memory_address_length;

                guint64 memory_size;
                proto_tree_add_item_ret_uint64(uds_tree, hf_uds_rd_memory_size, tvb, offset, memory_size_length, ENC_BIG_ENDIAN, &memory_size);
                offset += memory_size_length;

                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%" PRIx64 " bytes at 0x%" PRIx64, memory_size, memory_address);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   (Compression:0x%x Encrypting:0x%x)", compression, encrypting);
            }
            break;

        case UDS_SERVICES_TD: {
            guint32 sequence_no;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_td_sequence_counter, tvb, offset, 1, ENC_NA, &sequence_no);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   Block Sequence Counter %d", sequence_no);
            offset += 1;

            if (data_length > offset) {
                proto_tree_add_item(uds_tree, hf_uds_td_record_data, tvb, offset, data_length - offset, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                offset = data_length;
            }
            break;
        }

        case UDS_SERVICES_TP: {
            guint32 subfunction;
            ti = proto_tree_add_item(uds_tree, hf_uds_tp_subfunction, tvb, offset, 1, ENC_NA);
            /* do not increase offset, since reply uses the same byte with different mask! */

            proto_tree *subfunction_tree = proto_item_add_subtree(ti, ett_uds_subfunction);
            proto_tree_add_item_ret_uint(subfunction_tree, hf_uds_tp_subfunction_no_suppress, tvb, offset, 1, ENC_NA, &subfunction);

            col_append_fstr(pinfo->cinfo, COL_INFO, "   SubFunction %x", subfunction);

            if (!(sid & UDS_REPLY_MASK)) {
                gboolean suppress;
                proto_tree_add_item_ret_boolean(subfunction_tree, hf_uds_tp_suppress_pos_rsp_msg_ind, tvb, offset, 1, ENC_NA, &suppress);

                if (suppress) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   (Reply suppressed)");
                }
            }
            offset += 1;
            break;
        }

        case UDS_SERVICES_ERR:
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_err_sid, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_services, "Unknown (0x%02x)"));
            offset += 1;

            proto_tree_add_item_ret_uint(uds_tree, hf_uds_err_code, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (NRC: %s)", val_to_str(enum_val, uds_response_codes, "Unknown (0x%02x)"));
            offset += 1;
            break;

        case UDS_SERVICES_CDTCS:
            if ((sid & UDS_REPLY_MASK)) {
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_cdtcs_type, tvb, offset, 1, ENC_NA, &enum_val);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_cdtcs_types, "Unknown (0x%02x)"));
                offset += 1;
            } else {
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_cdtcs_subfunction, tvb, offset, 1, ENC_NA, &enum_val);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_cdtcs_types, "Unknown (0x%02x)"));
                offset += 1;

                if (data_length - offset > 0) {
                    proto_tree_add_item(uds_tree, hf_uds_cdtcs_option_record, tvb, offset, data_length - offset, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                    offset = data_length;
                }
            }
            break;
    }

    if (data_length - offset > 0) {
        proto_tree_add_item(uds_tree, hf_uds_unparsed_bytes, tvb, offset, data_length - offset, ENC_NA);
    }

    return data_length;
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
        { &hf_uds_diag_addr, {
            "Diagnostic Address", "uds.diag_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_diag_addr_name, {
            "Diagnostic Address Name", "uds.diag_addr_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_diag_source_addr, {
            "Diagnostic Source Address", "uds.diag_addr_source", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_diag_source_addr_name, {
            "Diagnostic Source Address Name", "uds.diag_addr_source_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_diag_target_addr, {
            "Diagnostic Target Address", "uds.diag_addr_target", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_diag_target_addr_name, {
            "Diagnostic Target Address Name", "uds.diag_addr_target_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_service, {
            "Service Identifier", "uds.sid", FT_UINT8,  BASE_HEX, VALS(uds_services), UDS_SID_MASK, NULL, HFILL } },
        { &hf_uds_reply, {
            "Reply Flag", "uds.reply", FT_UINT8, BASE_HEX, NULL, UDS_REPLY_MASK, NULL, HFILL } },

        { &hf_uds_dsc_subfunction, {
            "SubFunction", "uds.dsc.subfunction", FT_UINT8, BASE_HEX, VALS(uds_dsc_types), 0x0, NULL, HFILL } },
        { &hf_uds_dsc_parameter_record, {
            "Parameter Record", "uds.dsc.parameter_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_dsc_default_p2_server_timer, {
            "Default P2 Server Timer", "uds.dsc.p2_server_time_default", FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL } },
        /* Header field is actually only 16bit but has to be scaled up by 10x. */
        { &hf_uds_dsc_enhanced_p2_server_timer, {
            "Enhanced P2 Server Timer", "uds.dsc.p2_server_time_enhanced", FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL } },

        { &hf_uds_er_subfunction, {
            "SubFunction", "uds.er.subfunction", FT_UINT8, BASE_HEX, VALS(uds_er_types), 0x0, NULL, HFILL } },
        { &hf_uds_er_power_down_time, {
            "Power Down Time", "uds.er.power_down_time", FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL } },

        { &hf_uds_rdtci_subfunction, {
            "SubFunction", "uds.rdtci.subfunction", FT_UINT8, BASE_HEX, VALS(uds_rdtci_types), 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_record, {
            "Record", "uds.rdtci.record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_rdbi_data_identifier, {
            "Data Identifier", "uds.rdbi.data_identifier", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdbi_data_record, {
            "Data Record", "uds.rdbi.data_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_sa_subfunction, {
            "SubFunction", "uds.sa.subfunction", FT_UINT8, BASE_CUSTOM, CF_FUNC(uds_sa_subfunction_format), 0x0, NULL, HFILL } },
        { &hf_uds_sa_key, {
            "Key", "uds.sa.key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_sa_data_record, {
            "Data Record", "uds.sa.data_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_sa_seed, {
            "Seed", "uds.sa.seed", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_wdbi_data_identifier, {
            "Data Identifier", "uds.wdbi.data_identifier", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_wdbi_data_record, {
            "Data Record", "uds.wdbi.data_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_iocbi_data_identifier, {
            "Data Identifier", "uds.iocbi.data_identifier", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_iocbi_parameter, {
            "Parameter", "uds.iocbi.parameter", FT_UINT8, BASE_HEX, VALS(uds_iocbi_parameters), 0x0, NULL, HFILL } },
        { &hf_uds_iocbi_state, {
            "State", "uds.iocbi.state", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_rc_subfunction, {
            "SubFunction", "uds.rc.subfunction", FT_UINT8, BASE_HEX, VALS(uds_rc_types), 0x0, NULL, HFILL } },
        { &hf_uds_rc_identifier, {
            "Identifier", "uds.rc.identifier", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rc_option_record, {
            "Option record", "uds.rc.option_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rc_info, {
            "Info", "uds.rc.info", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rc_status_record, {
            "Status Record", "uds.rc.status_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_rd_compression_method, {
            "Compression Method", "uds.rd.compression_method", FT_UINT8, BASE_HEX, NULL, UDS_RD_COMPRESSION_METHOD_MASK, NULL, HFILL } },
        { &hf_uds_rd_encrypting_method, {
            "Encrypting Method", "uds.rd.encrypting_method", FT_UINT8, BASE_HEX, NULL, UDS_RD_ENCRYPTING_METHOD_MASK, NULL, HFILL } },
        { &hf_uds_rd_memory_size_length, {
            "Memory size length", "uds.rd.memory_size_length", FT_UINT8, BASE_HEX, NULL, UDS_RD_MEMORY_SIZE_LENGTH_MASK, NULL, HFILL } },
        { &hf_uds_rd_memory_address_length, {
            "Memory address length", "uds.rd.memory_address_length", FT_UINT8, BASE_HEX, NULL, UDS_RD_MEMORY_ADDRESS_LENGTH_MASK, NULL, HFILL } },
        { &hf_uds_rd_memory_address, {
            "Memory Address", "uds.rd.memory_address", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rd_memory_size, {
            "Memory Size", "uds.rd.memory_size", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rd_max_block_len_len, {
            "Length of Max Block Length", "uds.rd.max_block_length_length", FT_UINT8, BASE_HEX, NULL, UDS_RD_MAX_BLOCK_LEN_LEN_MASK, NULL, HFILL } },
        { &hf_uds_rd_max_block_len, {
            "Max Block Length", "uds.rd.max_block_length", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_td_sequence_counter, {
            "Block Sequence Counter", "uds.td.block_sequence_counter", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_td_record_data, {
            "Parameter Record", "uds.td.parameter_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_tp_subfunction, {
            "SubFunction", "uds.tp.subfunction", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_tp_subfunction_no_suppress, {
            "SubFunction (without Suppress)", "uds.tp.subfunction_without_suppress", FT_UINT8, BASE_HEX, NULL, UDS_TP_SUBFUNCTION_MASK, NULL, HFILL } },

        { &hf_uds_tp_suppress_pos_rsp_msg_ind, {
            "Suppress reply", "uds.tp.suppress_reply.indication", FT_BOOLEAN, 8, NULL, UDS_TP_SUPPRESS_POS_RSP_MSG_IND_MASK, NULL, HFILL } },

        { &hf_uds_err_sid,  {
            "Service Identifier", "uds.err.sid", FT_UINT8, BASE_HEX, VALS(uds_services), 0x0, NULL, HFILL } },
        { &hf_uds_err_code, {
            "Code", "uds.err.code",  FT_UINT8, BASE_HEX, VALS(uds_response_codes), 0x0, NULL, HFILL }  },

        { &hf_uds_cdtcs_subfunction, {
            "SubFunction", "uds.cdtcs.subfunction", FT_UINT8, BASE_HEX, VALS(uds_cdtcs_types), 0x0, NULL, HFILL } },
        { &hf_uds_cdtcs_option_record, {
            "Option Record", "uds.cdtcs.option_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_cdtcs_type, {
            "DTC Setting Type", "uds.cdtcs.dtc_setting_type", FT_UINT8, BASE_HEX, VALS(uds_cdtcs_types), 0x0, NULL, HFILL } },

        { &hf_uds_unparsed_bytes, {
            "Unparsed Bytes", "uds.unparsed_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    uat_t* uds_routine_ids_uat;
    uat_t* uds_data_ids_uat;
    uat_t* uds_address_uat;

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_uds,
        &ett_uds_subfunction,
        &ett_uds_dsc_parameter_record,
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

    prefs_register_bool_preference(uds_module, "dissect_small_sids_with_obd_ii",
        "Dissect Service Identifiers smaller 0x10 with OBD II Dissector?",
        "Dissect Service Identifiers smaller 0x10 with OBD II Dissector?",
        &uds_dissect_small_sids_with_obd_ii);

    heur_subdissector_list = register_heur_dissector_list("uds", proto_uds);
}

void
proto_reg_handoff_uds(void)
{
    dissector_add_for_decode_as("iso10681.subdissector", uds_handle_iso10681);
    dissector_add_for_decode_as("iso15765.subdissector", uds_handle_iso15765);
    obd_ii_handle = find_dissector("obd-ii-uds");
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
