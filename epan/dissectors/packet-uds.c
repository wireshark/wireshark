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
#include "packet-uds.h"
#include "packet-doip.h"
#include "packet-hsfz.h"
#include "packet-iso10681.h"
#include "packet-iso15765.h"
#include "packet-ber.h"
#include "packet-x509af.h"
#include <wsutil/utf8_entities.h>

void proto_register_uds(void);
void proto_reg_handoff_uds(void);

#define DATAFILE_UDS_ROUTINE_IDS "UDS_routine_identifiers"
#define DATAFILE_UDS_DATA_IDS    "UDS_data_identifiers"
#define DATAFILE_UDS_DTC_IDS     "UDS_dtc_identifiers"
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

#define UDS_SUBFUNCTION_MASK                    0x7f
#define UDS_SUPPRESS_POS_RSP_MSG_IND_MASK       0x80

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
#define UDS_RDTCI_TYPES_OUTDATED_RMMDTCBSM        0xF
#define UDS_RDTCI_TYPES_OUTDATED_RMMDEDRBDN       0x10
#define UDS_RDTCI_TYPES_OUTDATED_RNOMMDTCBSM      0x11
#define UDS_RDTCI_TYPES_OUTDATED_RNOOEOBDDTCBSM   0x12
#define UDS_RDTCI_TYPES_OUTDATED_ROBDDTCBSM       0x13
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

#define UDS_RDTCI_DTC_STATUS_TEST_FAILED                      0x01
#define UDS_RDTCI_DTC_STATUS_TEST_FAILED_THIS_OPER_CYCLE      0x02
#define UDS_RDTCI_DTC_STATUS_PENDING_DTC                      0x04
#define UDS_RDTCI_DTC_STATUS_CONFIRMED_DTC                    0x08
#define UDS_RDTCI_DTC_STATUS_TEST_NOT_COMPL_SINCE_LAST_CLEAR  0x10
#define UDS_RDTCI_DTC_STATUS_TEST_FAILED_SINCE_LAST_CLEAR     0x20
#define UDS_RDTCI_DTC_STATUS_TEST_NOT_COMPL_THIS_OPER_CYCLE   0x40
#define UDS_RDTCI_DTC_STATUS_WARNING_INDICATOR_REQUESTED      0x80

#define UDS_RSDBI_DATA_TYPE_UNSIGNED_NUM                    0x00
#define UDS_RSDBI_DATA_TYPE_SIGNED_NUM                      0x01
#define UDS_RSDBI_DATA_TYPE_BITMAPPED_REPORTED_WO_MAP       0x02
#define UDS_RSDBI_DATA_TYPE_BITMAPPED_REPORTED_WITH_MAP     0x03
#define UDS_RSDBI_DATA_TYPE_BINARY_CODED_DECIMAL            0x04
#define UDS_RSDBI_DATA_TYPE_STATE_ENCODED_VARIABLE          0x05
#define UDS_RSDBI_DATA_TYPE_ASCII                           0x06
#define UDS_RSDBI_DATA_TYPE_SIGNED_FLOAT                    0x07
#define UDS_RSDBI_DATA_TYPE_PACKET                          0x08
#define UDS_RSDBI_DATA_TYPE_FORMULA                         0x09
#define UDS_RSDBI_DATA_TYPE_UNIT_FORMAT                     0x0a
#define UDS_RSDBI_DATA_TYPE_STATE_AND_CONNECTION_TYPE       0x0b

#define UDS_SA_TYPES_RESERVED                     0x00
#define UDS_SA_TYPES_REQUEST_SEED                 0x01
#define UDS_SA_TYPES_SEND_KEY                     0x02
#define UDS_SA_TYPES_REQUEST_SEED_ISO26021        0x03
#define UDS_SA_TYPES_SEND_KEY_ISO26021            0x04
#define UDS_SA_TYPES_SUPPLIER                     0xFE
#define UDS_SA_TYPES_UNCLEAR                      0xFF

#define UDS_CC_TYPES_ENABLE_RX_AND_TX                            0
#define UDS_CC_TYPES_ENABLE_RX_AND_DISABLE_TX                    1
#define UDS_CC_TYPES_DISABLE_RX_AND_ENABLE_TX                    2
#define UDS_CC_TYPES_DISABLE_RX_AND_TX                           3
#define UDS_CC_TYPES_ENABLE_RX_AND_DISABLE_TX_WITH_ENH_ADDR_INFO 4
#define UDS_CC_TYPES_ENABLE_RX_AND_TX_WITH_ENH_ADDR_INFO         5

#define UDS_CC_COMM_TYPE_COMM_TYPE_MASK             0x03
#define UDS_CC_COMM_TYPE_SUBNET_NUMBER_MASK         0xF0

#define UDS_ARS_TYPES_DEAUTHENTICATE                0x00
#define UDS_ARS_TYPES_VERIFY_CERT_UNIDIRECTIONAL    0x01
#define UDS_ARS_TYPES_VERIFY_CERT_BIDIRECTIONAL     0x02
#define UDS_ARS_TYPES_PROOF_OF_OWNERSHIP            0x03
#define UDS_ARS_TYPES_TRANSMIT_CERTIFICATE          0x04
#define UDS_ARS_TYPES_REQUEST_CHALLENGE_FOR_AUTH    0x05
#define UDS_ARS_TYPES_VERIFY_PROOF_OF_OWN_UNIDIR    0x06
#define UDS_ARS_TYPES_VERIFY_PROOF_OF_OWN_BIDIR     0x07
#define UDS_ARS_TYPES_AUTH_CONFIGURATION            0x08

#define UDS_ARS_AUTH_RET_REQUEST_ACCEPTED           0x00
#define UDS_ARS_AUTH_RET_GENERAL_REJECT             0x01
#define UDS_ARS_AUTH_RET_AUTH_CONFIG_APCE           0x02
#define UDS_ARS_AUTH_RET_AUTH_CONFIG_ACR_SYM        0x03
#define UDS_ARS_AUTH_RET_AUTH_CONFIG_ACR_ASYM       0x04
#define UDS_ARS_AUTH_RET_DEAUTH_SUCCESS             0x10
#define UDS_ARS_AUTH_RET_CERT_VER_OWN_VER_NEC       0x11
#define UDS_ARS_AUTH_RET_OWN_VER_AUTH_COMPL         0x12
#define UDS_ARS_AUTH_RET_CERT_VERIFIED              0x13

#define UDS_DDDI_TYPES_DEFINE_BY_IDENTIFIER         0x01
#define UDS_DDDI_TYPES_DEFINE_BY_MEM_ADDRESS        0x02
#define UDS_DDDI_TYPES_CLEAR_DYN_DEF_DATA_ID        0x03

#define UDS_IOCBI_PARAMETERS_RETURN_CONTROL_TO_ECU  0
#define UDS_IOCBI_PARAMETERS_RESET_TO_DEFAULT       1
#define UDS_IOCBI_PARAMETERS_FREEZE_CURRENT_STATE   2
#define UDS_IOCBI_PARAMETERS_SHORT_TERM_ADJUSTMENT  3

#define UDS_RC_TYPES_START   1
#define UDS_RC_TYPES_STOP    2
#define UDS_RC_TYPES_REQUEST 3

#define UDS_RD_COMPRESSION_METHOD_MASK          0xF0
#define UDS_RD_ENCRYPTING_METHOD_MASK           0x0F
#define UDS_RD_MEMORY_SIZE_LENGTH_MASK          0xF0
#define UDS_RD_MEMORY_ADDRESS_LENGTH_MASK       0x0F
#define UDS_RD_MAX_BLOCK_LEN_LEN_MASK           0xF0

#define UDS_RFT_MODE_ADD_FILE                   0x01
#define UDS_RFT_MODE_DELETE_FILE                0x02
#define UDS_RFT_MODE_REPLACE_FILE               0x03
#define UDS_RFT_MODE_READ_FILE                  0x04
#define UDS_RFT_MODE_READ_DIR                   0x05
#define UDS_RFT_MODE_RESUME_FILE                0x06

#define UDS_SDT_ADMIN_PARAM_REQ                 0x0001
#define UDS_SDT_ADMIN_PARAM_PRE_ESTABL_KEY      0x0008
#define UDS_SDT_ADMIN_PARAM_ENCRYPTED           0x0010
#define UDS_SDT_ADMIN_PARAM_SIGNED              0x0020
#define UDS_SDT_ADMIN_PARAM_SIGN_ON_RESP_REQ    0x0040

#define UDS_CDTCS_ACTIONS_ON  1
#define UDS_CDTCS_ACTIONS_OFF 2

#define UDS_LC_TYPES_VMTWFP 1
#define UDS_LC_TYPES_VMTWSP 2
#define UDS_LC_TYPES_TM     3

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
static const value_string _uds_services[]= {
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
static value_string_ext uds_services_ext = VALUE_STRING_EXT_INIT(_uds_services);

/* Response code */
static const value_string _uds_response_codes[]= {
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
static value_string_ext uds_response_codes_ext = VALUE_STRING_EXT_INIT(_uds_response_codes);

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

/* CDTCI */
static const value_string uds_cdtci_group_of_dtc[] = {
        {0xffff33, "Emissions-system group"},
        {0xffffd0, "Safety-system group"},
        {0xfffffe, "VOBD system"},
        {0xffffff, "All Groups (all DTCs)"},
        {0, NULL}
};

/* RDTCI */
static const value_string _uds_rdtci_types[] = {
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
    {UDS_RDTCI_TYPES_OUTDATED_RMMDTCBSM,        "Report Mirror Memory DTC By Status Mask (outdated 2013 revision)"},
    {UDS_RDTCI_TYPES_OUTDATED_RMMDEDRBDN,       "Report Mirror Memory DTC Ext Data Record by DTC Number (outdated 2013 revision)"},
    {UDS_RDTCI_TYPES_OUTDATED_RNOMMDTCBSM,      "Report Number of Mirror Memory DTC by Status Mask (outdated 2013 revision)"},
    {UDS_RDTCI_TYPES_OUTDATED_RNOOEOBDDTCBSM,   "Report Number of Emissions OBD DTC by Status Mask (outdated 2013 revision)"},
    {UDS_RDTCI_TYPES_OUTDATED_ROBDDTCBSM,       "Report Emissions OBD DTC By Status Mask (outdated 2013 revision)"},
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
static value_string_ext uds_rdtci_types_ext = VALUE_STRING_EXT_INIT(_uds_rdtci_types);

static const value_string uds_rdtci_format_id_types[] = {
    {0x00, "SAE J2012-DA DTC Format 00"},
    {0x01, "ISO 14229-1 DTC Format"},
    {0x02, "SAE J1939-73 DTC Format"},
    {0x03, "ISO 11992-4 DTC Format"},
    {0x04, "SAE J2012-DA DTC Format 04"},
    {0, NULL}
};

/* RSDBI */
static const value_string uds_rsdbi_data_types[] = {
    {UDS_RSDBI_DATA_TYPE_UNSIGNED_NUM,                  "Unsigned Numeric"},
    {UDS_RSDBI_DATA_TYPE_SIGNED_NUM,                    "Signed Numeric"},
    {UDS_RSDBI_DATA_TYPE_BITMAPPED_REPORTED_WO_MAP,     "Bit Mapped Reported Without Mask"},
    {UDS_RSDBI_DATA_TYPE_BITMAPPED_REPORTED_WITH_MAP,   "Bit Mapped Reported With Mask"},
    {UDS_RSDBI_DATA_TYPE_BINARY_CODED_DECIMAL,          "Binary Coded Decimal"},
    {UDS_RSDBI_DATA_TYPE_STATE_ENCODED_VARIABLE,        "State Encoded Variable"},
    {UDS_RSDBI_DATA_TYPE_ASCII,                         "ASCII"},
    {UDS_RSDBI_DATA_TYPE_SIGNED_FLOAT,                  "Signed Floating Point"},
    {UDS_RSDBI_DATA_TYPE_PACKET,                        "Packet"},
    {UDS_RSDBI_DATA_TYPE_FORMULA,                       "Formula"},
    {UDS_RSDBI_DATA_TYPE_UNIT_FORMAT,                   "Unit/Format"},
    {UDS_RSDBI_DATA_TYPE_STATE_AND_CONNECTION_TYPE,     "State And Connection Type"},
    {0, NULL}
};

static const value_string uds_rsdbi_formulas[] = {
    {0, "y = C0 * x + C1"},
    {1, "y = C0 * (x + C1)"},
    {2, "y = C0 / (x + C1) + C2"},
    {3, "y = x / C0 + C1"},
    {4, "y = (x + C0) / C1"},
    {5, "y = (x + C0) / C1 + C2"},
    {6, "y = C0 * x"},
    {7, "y = x / C0"},
    {8, "y = x + C0"},
    {9, "y = x * C0 / C1"},
    {0, NULL}
};

static const value_string _uds_rsdbi_units[] = {
    {0x00, "No unit, no prefix"},
    {0x01, "Metre [m]"},
    {0x02, "Foot [ft]"},
    {0x03, "Inch [in]"},
    {0x04, "Yard [yd]"},
    {0x05, "Mile (English) [mi]"},
    {0x06, "Gram [g]"},
    {0x07, "Ton (metric) [t]"},
    {0x08, "Second [s]"},
    {0x09, "Minute [m]"},
    {0x0a, "Hour [h]"},
    {0x0b, "Day [d]"},
    {0x0c, "Year [y]"},
    {0x0d, "Ampere [A]"},
    {0x0e, "Volt [V]"},
    {0x0f, "Coulomb [C]"},

    {0x10, "Ohm [W]"}, /* sic! */
    {0x11, "Farad [F]"},
    {0x12, "Henry [H]"},
    {0x13, "Siemens [S]"},
    {0x14, "Weber [Wb]"},
    {0x15, "Telsa [T]"},
    {0x16, "Kelvin [K]"},
    {0x17, "Celsius [" UTF8_DEGREE_SIGN "C]"},
    {0x18, "Fahrenheit [" UTF8_DEGREE_SIGN "F]"},
    {0x19, "Candela [cd]"},
    {0x1a, "Radian [rad]"},
    {0x1b, "Degree [" UTF8_DEGREE_SIGN "]"},
    {0x1c, "Hertz [Hz]"},
    {0x1d, "Joule [J]"},
    {0x1e, "Newton [N]"},
    {0x1f, "Kilopond [kp]"},

    {0x20, "Pound force [lbf]"},
    {0x21, "Watt [W]"},
    {0x22, "Horse power (metric) [hk]"},
    {0x23, "Horse power (UK and US) [hp]"},
    {0x24, "Pascal [Pa]"},
    {0x25, "Bar [bar]"},
    {0x26, "Atmosphere [atm]"},
    {0x27, "Pound force per square inch [psi]"},
    {0x28, "Becqerel [Bq]"},
    {0x29, "Lumen [lm]"},
    {0x2a, "Lux [lx]"},
    {0x2b, "Litre [l]"},
    {0x2c, "Gallon (British)"},
    {0x2d, "Gallon (US liq)"},
    {0x2e, "Cubic inch [cu in]"},
    {0x2f, "Meter per second [m/s]"},

    {0x30, "Kilometer per hour [km/h]"},
    {0x31, "Mile per hour [mph]"},
    {0x32, "Revolutions per second [rps]"},
    {0x33, "Revolutions per minute [rpm]"},
    {0x34, "Counts"},
    {0x35, "Percent"},
    {0x36, "Milligram per stroke [mg/stroke]"},
    {0x37, "Meter per square second [m/s" UTF8_SUPERSCRIPT_TWO "]"},
    {0x38, "Newton meter [Nm]"},
    {0x39, "Litre per minute [l/min]"},
    {0x3a, "Watt per square meter [w/m" UTF8_SUPERSCRIPT_TWO "]"},
    {0x3b, "Bar per second [bar/s]"},
    {0x3c, "Radians per second [rad/s]"},
    {0x3d, "Radians per square second [rad/s" UTF8_SUPERSCRIPT_TWO "]"},
    {0x3e, "Kilogram per square meter [kg/m" UTF8_SUPERSCRIPT_TWO "]"},
    {0x3f, "*reserved*"},

    {0x40, "Exa (prefix) [E]"},
    {0x41, "Peta (prefix) [P]"},
    {0x42, "Tera (prefix) [T]"},
    {0x43, "Giga (prefix) [G]"},
    {0x44, "Mega (prefix) [M]"},
    {0x45, "Kilo (prefix) [k]"},
    {0x46, "Hecto (prefix) [h]"},
    {0x47, "Deca (prefix) [da]"},
    {0x48, "Deci (prefix)  [d]"},
    {0x49, "Centi (prefix) [c]"},
    {0x4a, "Milli (prefix) [m]"},
    {0x4b, "Micro (prefix) [m]"}, /* SIC! */
    {0x4c, "Nano (prefix) [n]"},
    {0x4d, "Pico (prefix) [p]"},
    {0x4e, "Femto (prefix) [f]"},
    {0x4f, "Atto (prefix) [a]"},

    {0x50, "Date1 (Year-Month-Day)"},
    {0x51, "Date2 (Day/Month/Year)"},
    {0x52, "Date3 (Month/Day/Year)"},
    {0x53, "Week (calender week)"},
    {0x54, "Time1 (UTC Hour/Minute/Second)"},
    {0x55, "Time2 (Hour/Minute/Second)"},
    {0x56, "DateAndTime1 (Second/Minute/Hour/Day/Month/Year)"},
    {0x57, "DateAndTime2 (Second/Minute/Hour/Day/Month/Year/Local minute offset/Local hour offset)"},
    {0x58, "DateAndTime3 (Second/Minute/Hour/Month/Day/Year)"},
    {0x59, "DateAndTime4 (Second/Minute/Hour/Month/Day/Year/Local minute offset/Local hour offset)"},
    {0, NULL}
};
static value_string_ext uds_rsdbi_units_ext = VALUE_STRING_EXT_INIT(_uds_rsdbi_units);

/* CC */
static const value_string uds_cc_types[] = {
    {UDS_CC_TYPES_ENABLE_RX_AND_TX,                             "Enable RX and TX"},
    {UDS_CC_TYPES_ENABLE_RX_AND_DISABLE_TX,                     "Enable RX and Disable TX"},
    {UDS_CC_TYPES_DISABLE_RX_AND_ENABLE_TX,                     "Disable RX and Enable TX"},
    {UDS_CC_TYPES_DISABLE_RX_AND_TX,                            "Disable RX and TX"},
    {UDS_CC_TYPES_ENABLE_RX_AND_DISABLE_TX_WITH_ENH_ADDR_INFO,  "Enable RX and Disable TX with Enhanced Address Information"},
    {UDS_CC_TYPES_ENABLE_RX_AND_TX_WITH_ENH_ADDR_INFO,          "Enable RX and TX with Enhanced Address Information"},
    {0, NULL}
};

static const value_string uds_cc_comm_types[] = {
    {0, "Reserved"},
    {1, "Normal Communication Messages"},
    {2, "Network Management Communication Messages"},
    {3, "Network Management and Normal Communication Messages"},
    {0, NULL}
};

static const value_string uds_cc_subnet_number_types[] = {
    {0x0, "Disable/Enable specified Communication Type "},
    /* 0x1 .. 0xe specific subnets numbers */
    {0xf, "Disable/Enable network which request is received on"},
    {0, NULL}
};

/* ARS */
static const value_string uds_ars_types[] = {
    {UDS_ARS_TYPES_DEAUTHENTICATE,              "DeAuthenticate"},
    {UDS_ARS_TYPES_VERIFY_CERT_UNIDIRECTIONAL,  "Verify Certificate Unidirectional"},
    {UDS_ARS_TYPES_VERIFY_CERT_BIDIRECTIONAL,   "Verify Certificate Bidirectional"},
    {UDS_ARS_TYPES_PROOF_OF_OWNERSHIP,          "Proof of Ownership"},
    {UDS_ARS_TYPES_TRANSMIT_CERTIFICATE,        "Transmit Certificate"},
    {UDS_ARS_TYPES_REQUEST_CHALLENGE_FOR_AUTH,  "Request Challenge for Authentication"},
    {UDS_ARS_TYPES_VERIFY_PROOF_OF_OWN_UNIDIR,  "Verify Proof of Ownership Unidirectional"},
    {UDS_ARS_TYPES_VERIFY_PROOF_OF_OWN_BIDIR,   "Verify Proof of Ownership Bidirectional"},
    {UDS_ARS_TYPES_AUTH_CONFIGURATION,          "Authentication Configuration"},
    {0, NULL}
};

static const value_string uds_ars_auth_ret_types[] = {
    {UDS_ARS_AUTH_RET_REQUEST_ACCEPTED,         "Request Accepted"},
    {UDS_ARS_AUTH_RET_GENERAL_REJECT,           "General Reject"},
    {UDS_ARS_AUTH_RET_AUTH_CONFIG_APCE,         "Authentication Configuration APCE"},
    {UDS_ARS_AUTH_RET_AUTH_CONFIG_ACR_SYM,      "Authentication Configuration ACR with asymmetric cryptography"},
    {UDS_ARS_AUTH_RET_AUTH_CONFIG_ACR_ASYM,     "Authentication Configuration ACR with symmetric cryptography"},
    {UDS_ARS_AUTH_RET_DEAUTH_SUCCESS,           "DeAuthentication successful "},
    {UDS_ARS_AUTH_RET_CERT_VER_OWN_VER_NEC,     "Certificate Verified, Ownership Verification Necessary"},
    {UDS_ARS_AUTH_RET_OWN_VER_AUTH_COMPL,       "Ownership Verified, Authentication Complete "},
    {UDS_ARS_AUTH_RET_CERT_VERIFIED,            "Certificate Verified"},
    {0, NULL}
};

/* RDBPI */
static const value_string uds_rdbpi_transmission_mode[] = {
    {0, "Reserved"},
    {1, "Send at Slow Rate"},
    {2, "Send at Medium Rate"},
    {3, "Send at Fast Rate"},
    {4, "Stop Sending"},
    {0, NULL}
};

/* DDDI */
static const value_string uds_dddi_types[] = {
    {UDS_DDDI_TYPES_DEFINE_BY_IDENTIFIER,   "Define by Identifier"},
    {UDS_DDDI_TYPES_DEFINE_BY_MEM_ADDRESS,  "Define by Memory Address"},
    {UDS_DDDI_TYPES_CLEAR_DYN_DEF_DATA_ID,  "Clear Dynamically Defined Data Identifier"},
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

/* RFT */
static const value_string uds_rft_mode_types[] = {
    {0,                             "Reserved"},
    {UDS_RFT_MODE_ADD_FILE,         "Add File"},
    {UDS_RFT_MODE_DELETE_FILE,      "Delete File"},
    {UDS_RFT_MODE_REPLACE_FILE,     "Replace File"},
    {UDS_RFT_MODE_READ_FILE,        "Read File"},
    {UDS_RFT_MODE_READ_DIR,         "Read Dir"},
    {UDS_RFT_MODE_RESUME_FILE,      "Resume File"},
    {0, NULL}
};

/* CDTCS */
static const value_string uds_cdtcs_types[] = {
    {0,                     "Reserved"},
    {UDS_CDTCS_ACTIONS_ON,  "On"},
    {UDS_CDTCS_ACTIONS_OFF, "Off"},
    {0, NULL}
};

/* LC */
static const value_string uds_lc_types[] = {
    {0x00,                  "Reserved"},
    {UDS_LC_TYPES_VMTWFP,   "Verify Mode Transition with fixed Parameter"},
    {UDS_LC_TYPES_VMTWSP,   "Verify Mode Transition with specific Parameter"},
    {UDS_LC_TYPES_TM,       "Transition Mode"},
    {0, NULL}
};

static const value_string uds_lc_lcmi_types[] = {
    {0x00,  "Reserved"},
    {0x01,  "PC9600Baud"},
    {0x02,  "PC19200Baud"},
    {0x03,  "PC38400Baud"},
    {0x04,  "PC57600Baud"},
    {0x05,  "PC115200Baud"},
    {0x10,  "CAN125000Baud"},
    {0x11,  "CAN250000Baud"},
    {0x12,  "CAN500000Baud"},
    {0x13,  "CAN1000000Baud"},
    {0x20,  "ProgrammingSetup"},
    {0, NULL}
};

/* DIDS */
static const value_string _uds_standard_did_types[] = {
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
    {UDS_DID_UDSVDID,       "UDSVersionDataIdentifier"},
    {UDS_DID_RESRVDCPADLC,  "ReservedForISO15765-5 (CAN, CAN-FD, CAN+CAN-FD, ...)"},
    {0, NULL}
};
static value_string_ext uds_standard_did_types_ext = VALUE_STRING_EXT_INIT(_uds_standard_did_types);

/* ReservedForISO15765 */
static const value_string uds_did_resrvdcpadlc_types[] = {
    {0, "CAN Classic Only"},
    {1, "CAN FD only"},
    {2, "CAN Classic and CAN FD"},
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

/* DTCS */
static const value_string uds_standard_dtc_types[] = {
    /* TODO: Add DTCs! */
    {0, NULL}
};


/*
 * Fields
 */

static int hf_uds_diag_addr;
static int hf_uds_diag_addr_name;
static int hf_uds_diag_source_addr;
static int hf_uds_diag_source_addr_name;
static int hf_uds_diag_target_addr;
static int hf_uds_diag_target_addr_name;

static int hf_uds_service;
static int hf_uds_reply;

static int hf_uds_subfunction;
static int hf_uds_suppress_pos_rsp_msg_ind;
static int hf_uds_data_record;

static int hf_uds_compression_method;
static int hf_uds_encrypting_method;
static int hf_uds_memory_size_length;
static int hf_uds_memory_address_length;
static int hf_uds_memory_address;
static int hf_uds_memory_size;
static int hf_uds_max_block_len_len;
static int hf_uds_max_block_len;

static int hf_uds_dsc_subfunction;
static int hf_uds_dsc_suppress_pos_rsp_msg_ind;
static int hf_uds_dsc_parameter_record;
static int hf_uds_dsc_default_p2_server_timer;
static int hf_uds_dsc_enhanced_p2_server_timer;

static int hf_uds_er_subfunction;
static int hf_uds_er_power_down_time;

static int hf_uds_cdtci_group_of_dtc;
static int hf_uds_cdtci_memory_selection;

static int hf_uds_rdtci_subfunction;
static int hf_uds_rdtci_dtc_status_mask;
static int hf_uds_rdtci_dtc_status_mask_tf;
static int hf_uds_rdtci_dtc_status_mask_tftoc;
static int hf_uds_rdtci_dtc_status_mask_pdtc;
static int hf_uds_rdtci_dtc_status_mask_cdtc;
static int hf_uds_rdtci_dtc_status_mask_tncslc;
static int hf_uds_rdtci_dtc_status_mask_tfslc;
static int hf_uds_rdtci_dtc_status_mask_tnctoc;
static int hf_uds_rdtci_dtc_status_mask_wir;
static int hf_uds_rdtci_dtc_mask_record;
static int hf_uds_rdtci_dtc_snapshot_rec_no;
static int hf_uds_rdtci_dtc_stored_data_rec_no;
static int hf_uds_rdtci_dtc_ext_data_rec_no;
static int hf_uds_rdtci_memory_selection;
static int hf_uds_rdtci_user_def_dtc_snapshot_rec_no;
static int hf_uds_rdtci_dtc_severity_mask;
static int hf_uds_rdtci_functional_group_id;
static int hf_uds_rdtci_dtc_readiness_group_id;
static int hf_uds_rdtci_dtc_status_avail;
static int hf_uds_rdtci_dtc_status_avail_tf;
static int hf_uds_rdtci_dtc_status_avail_tftoc;
static int hf_uds_rdtci_dtc_status_avail_pdtc;
static int hf_uds_rdtci_dtc_status_avail_cdtc;
static int hf_uds_rdtci_dtc_status_avail_tncslc;
static int hf_uds_rdtci_dtc_status_avail_tfslc;
static int hf_uds_rdtci_dtc_status_avail_tnctoc;
static int hf_uds_rdtci_dtc_status_avail_wir;
static int hf_uds_rdtci_dtc_id;
static int hf_uds_rdtci_dtc_status;
static int hf_uds_rdtci_dtc_status_tf;
static int hf_uds_rdtci_dtc_status_tftoc;
static int hf_uds_rdtci_dtc_status_pdtc;
static int hf_uds_rdtci_dtc_status_cdtc;
static int hf_uds_rdtci_dtc_status_tncslc;
static int hf_uds_rdtci_dtc_status_tfslc;
static int hf_uds_rdtci_dtc_status_tnctoc;
static int hf_uds_rdtci_dtc_status_wir;
static int hf_uds_rdtci_dtc_format_id;
static int hf_uds_rdtci_dtc_count;
static int hf_uds_rdtci_dtc_snapshot_record_number_of_ids;
static int hf_uds_rdtci_dtc_stored_data_record_number_of_ids;
static int hf_uds_rdtci_dtc_severity;
static int hf_uds_rdtci_dtc_functional_unit;
static int hf_uds_rdtci_dtc_fault_detect_counter;
static int hf_uds_rdtci_dtc_severity_avail;
static int hf_uds_rdtci_record;
static int hf_uds_rdtci_record_unparsed;

static int hf_uds_rdbi_data_identifier;

static int hf_uds_rsdbi_data_identifier;
static int hf_uds_rsdbi_scaling_byte;
static int hf_uds_rsdbi_scaling_byte_data_type;
static int hf_uds_rsdbi_scaling_byte_num_of_bytes;
static int hf_uds_rsdbi_validity_mask;
static int hf_uds_rsdbi_formula_identifier;
static int hf_uds_rsdbi_formula_constant;
static int hf_uds_rsdbi_formula_constant_exp;
static int hf_uds_rsdbi_formula_constant_mantissa;
static int hf_uds_rsdbi_unit;

static int hf_uds_sa_subfunction;
static int hf_uds_sa_key;
static int hf_uds_sa_seed;

static int hf_uds_cc_subfunction_no_suppress;
static int hf_uds_cc_comm_type_and_subnet_number;
static int hf_uds_cc_communication_type;
static int hf_uds_cc_subnet_number;
static int hf_uds_cc_node_identifier_number;

static int hf_uds_ars_subfunction_no_suppress;
static int hf_uds_ars_comm_config;
static int hf_uds_ars_length_of_cert_client;
static int hf_uds_ars_cert_client;
static int hf_uds_ars_length_of_cert_server;
static int hf_uds_ars_cert_server;
static int hf_uds_ars_length_of_challenge_client;
static int hf_uds_ars_challenge_client;
static int hf_uds_ars_length_of_challenge_server;
static int hf_uds_ars_challenge_server;
static int hf_uds_ars_length_of_proof_of_ownership_client;
static int hf_uds_ars_proof_of_ownership_client;
static int hf_uds_ars_length_of_proof_of_ownership_server;
static int hf_uds_ars_proof_of_ownership_server;
static int hf_uds_ars_length_of_ephemeral_public_key_client;
static int hf_uds_ars_ephemeral_public_key_client;
static int hf_uds_ars_length_of_ephemeral_public_key_server;
static int hf_uds_ars_ephemeral_public_key_server;
static int hf_uds_ars_cert_eval_id;
static int hf_uds_ars_length_of_cert_data;
static int hf_uds_ars_cert_data;
static int hf_uds_ars_algo_indicator;
static int hf_uds_ars_length_of_additional_parameter;
static int hf_uds_ars_additional_parameter;
static int hf_uds_ars_length_of_needed_additional_parameter;
static int hf_uds_ars_needed_additional_parameter;
static int hf_uds_ars_auth_ret_param;
static int hf_uds_ars_length_of_session_key_info;
static int hf_uds_ars_session_key_info;

static int hf_uds_signedCertificate;

static int hf_uds_rdbpi_transmission_mode;
static int hf_uds_rdbpi_periodic_data_identifier;

static int hf_uds_dddi_subfunction_no_suppress;
static int hf_uds_dddi_dyn_defined_data_identifier;
static int hf_uds_dddi_source_data_identifier;
static int hf_uds_dddi_position_in_source_data_record;
static int hf_uds_dddi_memory_size;

static int hf_uds_wdbi_data_identifier;

static int hf_uds_iocbi_data_identifier;
static int hf_uds_iocbi_parameter;
static int hf_uds_iocbi_state;

static int hf_uds_rc_subfunction;
static int hf_uds_rc_identifier;
static int hf_uds_rc_option_record;
static int hf_uds_rc_info;
static int hf_uds_rc_status_record;

static int hf_uds_td_sequence_counter;
static int hf_uds_td_record_data;

static int hf_uds_rte_record_data;

static int hf_uds_rft_mode_of_operation;
static int hf_uds_rft_length_of_file_path_and_name;
static int hf_uds_rft_file_path_and_name;
static int hf_uds_rft_file_size_param_length;
static int hf_uds_rft_file_size_uncompressed;
static int hf_uds_rft_file_size_compressed;
static int hf_uds_rft_length_format_identifier;
static int hf_uds_rft_max_num_of_block_length;
static int hf_uds_rft_file_size_or_dir_info_param_length;
static int hf_uds_rft_file_size_uncompressed_or_dir_info_length;
static int hf_uds_rft_file_position;

static int hf_uds_tp_subfunction_no_suppress;

static int hf_uds_err_sid;
static int hf_uds_err_code;

static int hf_uds_sdt_administrative_param;
static int hf_uds_sdt_administrative_param_req;
static int hf_uds_sdt_administrative_param_pre_estab_key;
static int hf_uds_sdt_administrative_param_encrypted;
static int hf_uds_sdt_administrative_param_signed;
static int hf_uds_sdt_administrative_param_resp_sign_req;
static int hf_uds_sdt_signature_encryption_calculation;
static int hf_uds_sdt_signature_length;
static int hf_uds_sdt_anti_replay_counter;
static int hf_uds_sdt_encapsulated_message;
static int hf_uds_sdt_encapsulated_message_sid;
static int hf_uds_sdt_encapsulated_message_sid_reply;
static int hf_uds_sdt_signature_mac;

static int hf_uds_cdtcs_subfunction;
static int hf_uds_cdtcs_subfunction_no_suppress;
static int hf_uds_cdtcs_subfunction_pos_rsp_msg_ind;
static int hf_uds_cdtcs_option_record;
static int hf_uds_cdtcs_type;

static int hf_uds_lc_subfunction;
static int hf_uds_lc_subfunction_no_suppress;
static int hf_uds_lc_subfunction_pos_rsp_msg_ind;
static int hf_uds_lc_control_mode_id;
static int hf_uds_lc_link_record;

static int hf_uds_did_reply_f186_diag_session;
static int hf_uds_did_reply_f190_vin;
static int hf_uds_did_reply_ff00_version;
static int hf_uds_did_reply_ff01_dlc_support;

static int hf_uds_unparsed_bytes;

/*
 * Trees
 */
static int ett_uds;
static int ett_uds_subfunction;
static int ett_uds_dtc_status_entry;
static int ett_uds_dtc_status_bits;
static int ett_uds_dtc_snapshot_entry;
static int ett_uds_dtc_counter_entry;
static int ett_uds_dsc_parameter_record;
static int ett_uds_rsdbi_scaling_byte;
static int ett_uds_rsdbi_formula_constant;
static int ett_uds_cc_communication_type;
static int ett_uds_ars_certificate;
static int ett_uds_ars_algo_indicator;
static int ett_uds_dddi_entry;
static int ett_uds_sdt_admin_param;
static int ett_uds_sdt_encap_message;

static int proto_uds;

static dissector_handle_t uds_handle;
static dissector_handle_t uds_handle_doip;
static dissector_handle_t uds_handle_hsfz;
static dissector_handle_t uds_handle_iso10681;
static dissector_handle_t uds_handle_iso15765;
static dissector_handle_t obd_ii_handle;

/*** Subdissectors ***/
static heur_dissector_list_t heur_subdissector_list;
static heur_dtbl_entry_t *heur_dtbl_entry;

/*** Configuration ***/
enum certificate_decoding_strategies {
    cert_parsing_off = -1,
    ber_cert_single_false = 0,
    ber_cert_single_true  = 1,
    ber_cert_multi_false  = 2,
    ber_cert_multi_true   = 3,
};

static const enum_val_t certificate_decoding_vals[] = {
    {"0", "BER Certificate w/o implicit tag", ber_cert_single_false},
    {"1", "BER Certificate w implicit tag", ber_cert_single_true},
    {"2", "BER Certificates w/o implicit tag", ber_cert_multi_false},
    {"3", "BER Certificates w implicit tag", ber_cert_multi_true},
    {"off", "Do not parse", cert_parsing_off},
    {NULL, NULL, -1}
};

static int uds_certificate_decoding_config = (int)cert_parsing_off;

static bool uds_dissect_small_sids_with_obd_ii = true;

typedef struct _address_string {
    unsigned address;
    char    *name;
} address_string_t;

static void *
copy_address_string_cb(void *n, const void *o, size_t size _U_) {
    address_string_t *new_rec = (address_string_t *)n;
    const address_string_t *old_rec = (const address_string_t *)o;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->address = old_rec->address;
    return new_rec;
}

static bool
update_address_string_cb(void *r, char **err) {
    address_string_t *rec = (address_string_t *)r;

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    return true;
}

static void
free_address_string_cb(void *r) {
    address_string_t *rec = (address_string_t *)r;

    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static void
post_update_address_string_cb(address_string_t *data, unsigned data_num, GHashTable *ht) {
    unsigned   i;
    int64_t *key = NULL;

    if (ht == NULL) {
        return;
    }

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int64_t);
        *key = data[i].address;

        g_hash_table_insert(ht, key, g_strdup(data[i].name));
    }
}


typedef struct _generic_addr_id_string {
    uint32_t address;
    uint32_t id;
    char    *name;
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

static bool
update_generic_addr_16bit_id_var(void *r, char **err, uint32_t limit) {
    generic_addr_id_string_t *rec = (generic_addr_id_string_t *)r;

    if (rec->id > limit) {
        *err = ws_strdup_printf("We currently only support identifiers <= %x (Addr: %x ID: %i  Name: %s)", limit, rec->address, rec->id, rec->name);
        return false;
    }

    if (rec->address > 0xffff && rec->address != UINT32_MAX) {
        *err = ws_strdup_printf("We currently only support 16 bit addresses with 0xffffffff = \"don't care\" (Addr: %x  ID: %i  Name: %s)",
                                rec->address, rec->id, rec->name);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    return true;
}

static bool
update_generic_addr_16bit_id_16bit(void *r, char **err) {
    return update_generic_addr_16bit_id_var(r, err, 0xffff);
}

static bool
update_generic_addr_16bit_id_24bit(void *r, char **err) {
    return update_generic_addr_16bit_id_var(r, err, 0xffffff);
}

static void
free_generic_one_id_string_cb(void *r) {
    generic_addr_id_string_t *rec = (generic_addr_id_string_t *)r;

    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static int64_t
calc_key(uint32_t addr, uint32_t id) {
    return ((int64_t)id << 32) | (int64_t)addr;
}

static void
post_update_one_id_string_template_cb(generic_addr_id_string_t *data, unsigned data_num, GHashTable *ht) {
    unsigned   i;
    int64_t *key = NULL;

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int64_t);
        *key = calc_key(data[i].address, data[i].id);

        g_hash_table_insert(ht, key, g_strdup(data[i].name));
    }
}

static char *
generic_lookup_addr_id(uint32_t addr, uint32_t id, GHashTable *ht) {
    char *ret = NULL;

    uint64_t tmp = calc_key(addr, id);

    if (ht == NULL) {
        return NULL;
    }

    ret = (char *)g_hash_table_lookup(ht, &tmp);
    if (ret == NULL) {
        tmp = calc_key(UINT32_MAX, id);
        return (char *)g_hash_table_lookup(ht, &tmp);
    }

    return ret;
}

static void
simple_free_key(void *key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
simple_free(void *data) {
    /* we need to free because of the g_strdup in post_update*/
    g_free(data);
}


/* Routine IDs */
static generic_addr_id_string_t *uds_uat_routine_ids;
static unsigned uds_uat_routine_id_num;
static GHashTable *uds_ht_routine_ids;

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
uds_lookup_routine_name(uint32_t addr, uint16_t id) {
    const char *tmp = generic_lookup_addr_id(addr, id, uds_ht_routine_ids);

    if (tmp == NULL) {
        tmp = try_val_to_str(id, uds_standard_rid_types);
    }

    return tmp;
}

static void
protoitem_append_routine_name(proto_item *ti, uint32_t addr, uint16_t data_identifier) {
    const char *routine_name = uds_lookup_routine_name(addr, data_identifier);
    if (routine_name != NULL) {
        proto_item_append_text(ti, " (%s)", routine_name);
    }
}

static void
infocol_append_routine_name(packet_info *pinfo, uint32_t addr, uint16_t routine_identifier) {
    const char *routine_name = uds_lookup_routine_name(addr, routine_identifier);
    if (routine_name != NULL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", routine_name);
    }
}


/* Data IDs */
static generic_addr_id_string_t *uds_uat_data_ids;
static unsigned uds_uat_data_id_num;
static GHashTable *uds_ht_data_ids;

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
uds_lookup_data_name(uint32_t addr, uint16_t id) {
    const char *tmp = generic_lookup_addr_id(addr, id, uds_ht_data_ids);

    if (tmp == NULL) {
        tmp = try_val_to_str_ext(id, &uds_standard_did_types_ext);
    }

    return tmp;
}

static void
protoitem_append_data_name(proto_item *ti, uint32_t addr, uint16_t data_identifier) {
    const char *data_name = uds_lookup_data_name(addr, data_identifier);
    if (data_name != NULL) {
        proto_item_append_text(ti, " (%s)", data_name);
    }
}

static void
infocol_append_data_name(packet_info *pinfo, uint32_t addr, uint16_t data_identifier) {
    const char *data_name = uds_lookup_data_name(addr, data_identifier);
    if (data_name != NULL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", data_name);
    }
}


/* DTC IDs */
static generic_addr_id_string_t *uds_uat_dtc_ids;
static unsigned uds_uat_dtc_id_num;
static GHashTable *uds_ht_dtc_ids;

UAT_HEX_CB_DEF(uds_uat_dtc_ids, address, generic_addr_id_string_t)
UAT_HEX_CB_DEF(uds_uat_dtc_ids, id, generic_addr_id_string_t)
UAT_CSTRING_CB_DEF(uds_uat_dtc_ids, name, generic_addr_id_string_t)

static void
post_update_uds_dtc_cb(void) {
    /* destroy old hash table, if it exists */
    if (uds_ht_dtc_ids) {
        g_hash_table_destroy(uds_ht_dtc_ids);
    }

    /* create new hash table */
    uds_ht_dtc_ids = g_hash_table_new_full(g_int64_hash, g_int64_equal, &simple_free_key, &simple_free);
    post_update_one_id_string_template_cb(uds_uat_dtc_ids, uds_uat_dtc_id_num, uds_ht_dtc_ids);
}

static const char *
uds_lookup_dtc_name(uint32_t addr, uint32_t id) {
    const char *tmp = generic_lookup_addr_id(addr, id, uds_ht_dtc_ids);

    if (tmp == NULL) {
        tmp = try_val_to_str(id, uds_standard_dtc_types);
    }

    return tmp;
}

static void
protoitem_append_dtc_name(proto_item *ti, uint32_t addr, uint32_t dtc_id) {
    const char *dtc_name = uds_lookup_dtc_name(addr, dtc_id);
    if (dtc_name != NULL) {
        proto_item_append_text(ti, " (%s)", dtc_name);
    }
}


/* Addresses */
static address_string_t *uds_uat_addresses;
static unsigned uds_uat_addresses_num;
static GHashTable *uds_ht_addresses;

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
uds_lookup_address_name(uint32_t addr) {

    char *ret = NULL;
    int64_t tmp = (int64_t)addr;

    if (uds_ht_addresses == NULL) {
        return NULL;
    }

    ret = (char *)g_hash_table_lookup(uds_ht_addresses, &tmp);

    return ret;
}

static void
uds_proto_item_append_address_name(proto_item *ti, uint32_t addr) {
    char *address_name = uds_lookup_address_name(addr);
    if (address_name != NULL) {
        proto_item_append_text(ti, " (%s)", address_name);
    }
}

static proto_item *
uds_proto_tree_add_address_item(proto_tree *tree, int hf, tvbuff_t *tvb, const int offset, const int size, unsigned addr, bool generated, bool hidden) {
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
uds_proto_tree_add_address_name(proto_tree *tree, int hf, tvbuff_t *tvb, const int offset, const int size, unsigned addr) {
    proto_item *ti;
    char *address_name = uds_lookup_address_name(addr);

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

static void
uds_proto_item_append_address_text(proto_item *ti, uint8_t address_length, const char *name, uint32_t value) {
    if (ti == NULL) {
        return;
    }

    switch (address_length) {
    case 1:
        proto_item_append_text(ti, ", %s: 0x%02x", name, value);
        break;
    case 2:
        proto_item_append_text(ti, ", %s: 0x%04x", name, value);
        break;
    }
}

/*** Configuration End ***/

static bool
call_heur_subdissector_uds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *uds_tree, uint8_t service, bool reply, uint32_t id, uint32_t uds_address)
{
    uds_info_t uds_info;

    uds_info.id = id;
    uds_info.uds_address = uds_address;
    uds_info.reply = reply;
    uds_info.service = service;

    bool ret = dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, &uds_info);

    if (!ret) {
        if (service == UDS_SERVICES_RDBI && reply && id == UDS_DID_ADSDID) {
            proto_tree_add_item(uds_tree, hf_uds_did_reply_f186_diag_session, tvb, 0, 1, ENC_NA);
            return true;
        }

        if (service == UDS_SERVICES_RDBI && reply && id == UDS_DID_VINDID) {
            proto_tree_add_item(uds_tree, hf_uds_did_reply_f190_vin, tvb, 0, 17, ENC_ASCII);
            return true;
        }

        if (service == UDS_SERVICES_RDBI && reply && id == UDS_DID_UDSVDID) {
            uint32_t tmp = tvb_get_uint32(tvb, 0, ENC_BIG_ENDIAN);
            proto_tree_add_uint_format(uds_tree, hf_uds_did_reply_ff00_version, tvb, 0, 4, tmp, "UDS Version: %d.%d.%d.%d",
                                       (tmp & 0xff000000) >> 24, (tmp & 0x00ff0000) >> 16, (tmp & 0x0000ff00) >> 8, tmp & 0x000000ff);
            return true;
        }

        if (service == UDS_SERVICES_RDBI && reply && id == UDS_DID_RESRVDCPADLC) {
            proto_tree_add_item(uds_tree, hf_uds_did_reply_ff01_dlc_support, tvb, 0, 1, ENC_NA);
            return true;
        }
    }

    return ret;
}

static unsigned
uds_sa_subfunction_to_type(uint8_t subf) {
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

static char *
uds_sa_subfunction_to_string(uint8_t subf) {
    switch (uds_sa_subfunction_to_type(subf)) {
    case UDS_SA_TYPES_RESERVED:
        return "Reserved";
    case UDS_SA_TYPES_SUPPLIER:
        return "System Supplier Specific";
    case UDS_SA_TYPES_REQUEST_SEED:
        return "Request Seed";
    case UDS_SA_TYPES_SEND_KEY:
        return "Send Key";
    case UDS_SA_TYPES_REQUEST_SEED_ISO26021:
        return "Request Seed ISO26021";
    case UDS_SA_TYPES_SEND_KEY_ISO26021:
        return "Send Key ISO26021";
    }

    return "Unknown";
}

static void
uds_sa_subfunction_format(char *ret, uint32_t value) {
    if (uds_sa_subfunction_to_type(value) == UDS_SA_TYPES_UNCLEAR) {
        snprintf(ret, ITEM_LABEL_LENGTH, "0x%02x", value);
        return;
    }

    snprintf(ret, ITEM_LABEL_LENGTH, "%s (0x%02x)", uds_sa_subfunction_to_string(value), value);
}

static int
dissect_uds_dtc_and_status_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *uds_tree, uint32_t offset, uint32_t ecu_address, bool severity_present, bool func_unit_present) {
    static int * const dtc_status_flags[] = {
     &hf_uds_rdtci_dtc_status_wir,
     &hf_uds_rdtci_dtc_status_tnctoc,
     &hf_uds_rdtci_dtc_status_tfslc,
     &hf_uds_rdtci_dtc_status_tncslc,
     &hf_uds_rdtci_dtc_status_cdtc,
     &hf_uds_rdtci_dtc_status_pdtc,
     &hf_uds_rdtci_dtc_status_tftoc,
     &hf_uds_rdtci_dtc_status_tf,
     NULL
    };

    proto_item *ti_status_record, *ti;
    proto_tree *entry_tree;

    if (severity_present) {
        entry_tree = proto_tree_add_subtree(uds_tree, tvb, offset, 4, ett_uds_dtc_status_entry, &ti_status_record, "DTC and Severity Record");

        unsigned severity;
        proto_tree_add_item_ret_uint(entry_tree, hf_uds_rdtci_dtc_severity, tvb, offset, 1, ENC_NA, &severity);
        offset += 1;

        if (func_unit_present) {
            unsigned functional_unit;
            proto_tree_add_item_ret_uint(entry_tree, hf_uds_rdtci_dtc_functional_unit, tvb, offset, 1, ENC_NA, &functional_unit);
            offset += 1;

            proto_item_append_text(ti_status_record, ", Severity:0x%02x, Functional Unit:0x%02x", severity, functional_unit);
        } else {
            proto_item_append_text(ti_status_record, ", Severity:0x%02x", severity);
        }
    } else {
        entry_tree = proto_tree_add_subtree(uds_tree, tvb, offset, 4, ett_uds_dtc_status_entry, &ti_status_record, "DTC and Status Record");
    }

    unsigned dtc_id;
    ti = proto_tree_add_item_ret_uint(entry_tree, hf_uds_rdtci_dtc_id, tvb, offset, 3, ENC_BIG_ENDIAN, &dtc_id);
    protoitem_append_dtc_name(ti, ecu_address, dtc_id);
    offset += 3;

    uint64_t dtc_status;
    proto_tree_add_bitmask_with_flags_ret_uint64(entry_tree, tvb, offset, hf_uds_rdtci_dtc_status, ett_uds_dtc_status_bits, dtc_status_flags, ENC_NA, BMT_NO_APPEND, &dtc_status);
    offset += 1;

    const char *dtc_name = uds_lookup_dtc_name(ecu_address, dtc_id);
    if (dtc_name == NULL) {
        proto_item_append_text(ti_status_record, ", DTC:0x%06x, Status:0x%02x", dtc_id, (uint32_t)dtc_status);
    } else {
        proto_item_append_text(ti_status_record, ", DTC:0x%06x (%s), Status:0x%02x", dtc_id, dtc_name, (uint32_t)dtc_status);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%06x:0x%02x", dtc_id, (uint32_t)dtc_status);

    return offset;
}

static int
dissect_uds_dtc_and_fault_detection_counter_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *uds_tree, uint32_t offset, uint32_t ecu_address) {
    proto_item *ti_status_record, *ti;
    proto_tree *entry_tree;

    entry_tree = proto_tree_add_subtree(uds_tree, tvb, offset, 4, ett_uds_dtc_counter_entry, &ti_status_record, "DTC and Fault Detection Counter Record");

    unsigned dtc_id;
    ti = proto_tree_add_item_ret_uint(entry_tree, hf_uds_rdtci_dtc_id, tvb, offset, 3, ENC_BIG_ENDIAN, &dtc_id);
    protoitem_append_dtc_name(ti, ecu_address, dtc_id);
    offset += 3;

    unsigned counter;
    proto_tree_add_item_ret_uint(entry_tree, hf_uds_rdtci_dtc_fault_detect_counter, tvb, offset, 1, ENC_NA, &counter);
    offset += 1;

    const char *dtc_name = uds_lookup_dtc_name(ecu_address, dtc_id);
    if (dtc_name == NULL) {
        proto_item_append_text(ti_status_record, ", DTC:0x%06x, Counter:%04d", dtc_id, counter);
    } else {
        proto_item_append_text(ti_status_record, ", DTC:0x%06x (%s), Counter:%04d", dtc_id, dtc_name, counter);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%06x:%04d", dtc_id, counter);

    return offset;
}

static uint32_t
dissect_uds_subfunction(tvbuff_t *tvb, packet_info *pinfo, proto_tree *uds_tree, uint32_t offset, uint32_t *subfunc_value, int hf, const value_string *vs, bool suppress_bit) {
    proto_item *ti = proto_tree_add_item(uds_tree, hf_uds_subfunction, tvb, offset, 1, ENC_NA);
    proto_tree *subfunction_tree = proto_item_add_subtree(ti, ett_uds_subfunction);
    proto_tree_add_item_ret_uint(subfunction_tree, hf, tvb, offset, 1, ENC_NA, subfunc_value);

    if (vs != NULL) {
        proto_item_append_text(ti, " (%s)", val_to_str(*subfunc_value, vs, "Unknown (0x%02x)"));
        col_append_fstr(pinfo->cinfo, COL_INFO, "   SubFunction: %s", val_to_str(*subfunc_value, vs, "Unknown (0x%02x)"));
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "   SubFunction: 0x%02x", *subfunc_value);
    }

    if (suppress_bit) {
        bool suppress;

        proto_tree_add_item_ret_boolean(subfunction_tree, hf_uds_suppress_pos_rsp_msg_ind, tvb, offset, 1, ENC_NA, &suppress);

        if (suppress) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "   (Reply suppressed)");
        }
    }
    offset += 1;

    return offset;
}

static int
dissect_uds_rdtci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *uds_tree, uint32_t ecu_address, uint8_t sid, uint32_t offset, uint32_t data_length) {
    uint32_t    enum_val;

    proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_subfunction, tvb, offset, 1, ENC_NA, &enum_val);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str_ext(enum_val, &uds_rdtci_types_ext, "Unknown (0x%02x)"));
    offset += 1;

    if (sid & UDS_REPLY_MASK) {
        static int * const dtc_status_avail_mask_flags[] = {
             &hf_uds_rdtci_dtc_status_avail_wir,
             &hf_uds_rdtci_dtc_status_avail_tnctoc,
             &hf_uds_rdtci_dtc_status_avail_tfslc,
             &hf_uds_rdtci_dtc_status_avail_tncslc,
             &hf_uds_rdtci_dtc_status_avail_cdtc,
             &hf_uds_rdtci_dtc_status_avail_pdtc,
             &hf_uds_rdtci_dtc_status_avail_tftoc,
             &hf_uds_rdtci_dtc_status_avail_tf,
             NULL
        };

        switch (enum_val) {
        case UDS_RDTCI_TYPES_NUMBER_BY_STATUS_MASK:
        case UDS_RDTCI_TYPES_NUM_DTC_BY_SEVERITY_MASK:
        case UDS_RDTCI_TYPES_OUTDATED_RNOMMDTCBSM:
        case UDS_RDTCI_TYPES_OUTDATED_RNOOEOBDDTCBSM: {
            uint64_t dtc_status_avail_mask;
            proto_tree_add_bitmask_with_flags_ret_uint64(uds_tree, tvb, offset, hf_uds_rdtci_dtc_status_avail, ett_uds_dtc_status_bits, dtc_status_avail_mask_flags, ENC_NA, BMT_NO_APPEND, &dtc_status_avail_mask);
            col_append_fstr(pinfo->cinfo, COL_INFO, "    0x%02x", (uint32_t)dtc_status_avail_mask);
            offset += 1;

            uint32_t dtc_format;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_format_id, tvb, offset, 1, ENC_NA, &dtc_format);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", val_to_str(dtc_format, uds_rdtci_format_id_types, "Unknown Format (0x%02x)"));
            offset += 1;

            uint32_t dtc_count;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_count, tvb, offset, 2, ENC_BIG_ENDIAN, &dtc_count);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  %d DTCs", dtc_count);
            offset += 2;
            break;
        }

        case UDS_RDTCI_TYPES_BY_STATUS_MASK:
        case UDS_RDTCI_TYPES_SUPPORTED_DTC:
        case UDS_RDTCI_TYPES_FIRST_TEST_FAILED_DTC:
        case UDS_RDTCI_TYPES_FIRST_CONFIRMED_DTC:
        case UDS_RDTCI_TYPES_MOST_RECENT_TEST_FAILED:
        case UDS_RDTCI_TYPES_MOST_RECENT_CONFIRMED_DTC:
        case UDS_RDTCI_TYPES_OUTDATED_RMMDTCBSM:
        case UDS_RDTCI_TYPES_OUTDATED_ROBDDTCBSM:
        case UDS_RDTCI_TYPES_DTC_WITH_PERM_STATUS: {
            uint64_t dtc_status_avail_mask;
            proto_tree_add_bitmask_with_flags_ret_uint64(uds_tree, tvb, offset, hf_uds_rdtci_dtc_status_avail, ett_uds_dtc_status_bits, dtc_status_avail_mask_flags, ENC_NA, BMT_NO_APPEND, &dtc_status_avail_mask);
            col_append_fstr(pinfo->cinfo, COL_INFO, "    0x%02x", (uint32_t)dtc_status_avail_mask);
            offset += 1;

            while (offset + 4 <= data_length) {
                offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);
            }
        }
            break;

        case UDS_RDTCI_TYPES_SNAPSHOT_IDENTIFICATION:
            while (offset + 4 <= data_length) {
                offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);
            }
            break;

        case UDS_RDTCI_TYPES_SNAPSHOT_RECORD_BY_DTC: {
            /* this cannot fully be parsed without configuration data (length of DID data) */

            offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);

            if (offset < data_length) {
                proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_snapshot_rec_no, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            if (offset < data_length) {
                proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_snapshot_record_number_of_ids, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            if (offset < data_length) {
                proto_tree_add_item(uds_tree, hf_uds_rdtci_record_unparsed, tvb, offset, data_length - offset, ENC_NA);
                offset = data_length;
            }
        }
            break;

        case UDS_RDTCI_TYPES_SNAPSHOT_RECORD_BY_RECORD: {
            /* this cannot fully be parsed without configuration data (length of DID data) */

            uint32_t count;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_stored_data_rec_no, tvb, offset, 1, ENC_NA, &count);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, "  %d Stored Data Records:  ", count);

            if (count > 0) {
                offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);

                proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_stored_data_record_number_of_ids, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (offset < data_length) {
                    proto_tree_add_item(uds_tree, hf_uds_rdtci_record_unparsed, tvb, offset, data_length - offset, ENC_NA);
                    offset = data_length;
                }
            }
        }
            break;

        case UDS_RDTCI_TYPES_EXTENDED_RECORD_BY_DTC:
            /* this cannot fully be parsed without configuration data (length of DID data) */

            offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);

            if (offset < data_length) {
                proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_ext_data_rec_no, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            if (offset < data_length) {
                proto_tree_add_item(uds_tree, hf_uds_rdtci_record_unparsed, tvb, offset, data_length - offset, ENC_NA);
                offset = data_length;
            }
            break;

        case UDS_RDTCI_TYPES_BY_SEVERITY_MASK:
            offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, true, true);
            break;

        case UDS_RDTCI_TYPES_SEVERITY_INFO_OF_DTC:
            offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, true, true);

            while (offset + 6 <= data_length) {
                offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, true, true);
            }
            break;

        case UDS_RDTCI_TYPES_DTC_FAULT_DETECT_CTR:
            while (offset + 4 <= data_length) {
                offset = dissect_uds_dtc_and_fault_detection_counter_record(tvb, pinfo, uds_tree, offset, ecu_address);
            }
            break;

        case UDS_RDTCI_TYPES_DTC_EXT_DATA_REC_BY_NUM:
            /* this cannot fully be parsed without configuration data (length of data records) */
            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_ext_data_rec_no, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (offset < data_length) {
                proto_tree_add_item(uds_tree, hf_uds_rdtci_record_unparsed, tvb, offset, data_length - offset, ENC_NA);
                offset = data_length;
            }
            break;

        case UDS_RDTCI_TYPES_USER_MEM_DTC_BY_STATUS_M:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_memory_selection, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_status_avail, tvb, offset, 1, ENC_NA);
            offset += 1;

            while (offset + 4 <= data_length) {
                offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);
            }
            break;

        case UDS_RDTCI_TYPES_USER_MEM_DTC_REC_BY_DTC_N:
            /* this cannot fully be parsed without configuration data (length of DID data) */
            proto_tree_add_item(uds_tree, hf_uds_rdtci_memory_selection, tvb, offset, 1, ENC_NA);
            offset += 1;

            offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);

            if (offset < data_length) {
                proto_tree_add_item(uds_tree, hf_uds_rdtci_record_unparsed, tvb, offset, data_length - offset, ENC_NA);
                offset = data_length;
            }
            break;

        case UDS_RDTCI_TYPES_USER_MEM_DTC_EXT_REC_BY_N:
            /* this cannot fully be parsed without configuration data (length of extended data) */
            proto_tree_add_item(uds_tree, hf_uds_rdtci_memory_selection, tvb, offset, 1, ENC_NA);
            offset += 1;

            offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);

            if (offset < data_length) {
                proto_tree_add_item(uds_tree, hf_uds_rdtci_record_unparsed, tvb, offset, data_length - offset, ENC_NA);
                offset = data_length;
            }
            break;

        case UDS_RDTCI_TYPES_SUP_DTC_EXT_RECORD: {
            unsigned status;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_status_avail, tvb, offset, 1, ENC_NA, &status);
            offset += 1;

            unsigned rec_no;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_ext_data_rec_no, tvb, offset, 1, ENC_NA, &rec_no);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x 0x%02x", status, rec_no);

            while (offset + 4 <= data_length) {
                offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);
            }
        }
            break;

        case UDS_RDTCI_TYPES_WWH_OBD_DTC_BY_MASK_REC: {
            unsigned func_group;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_functional_group_id, tvb, offset, 1, ENC_NA, &func_group);
            offset += 1;

            unsigned status;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_status_avail, tvb, offset, 1, ENC_NA, &status);
            offset += 1;

            unsigned severity;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_severity_avail, tvb, offset, 1, ENC_NA, &severity);
            offset += 1;

            unsigned format;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_format_id, tvb, offset, 1, ENC_NA, &format);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x 0x%02x 0x%02x 0x%02x", func_group, status, severity, format);

            while (offset + 5 <= data_length) {
                offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, true, false);
            }
        }
            break;

        case UDS_RDTCI_TYPES_WWH_OBD_DTC_PERM_STATUS: {
            unsigned func_group;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_functional_group_id, tvb, offset, 1, ENC_NA, &func_group);
            offset += 1;

            unsigned status;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_status_avail, tvb, offset, 1, ENC_NA, &status);
            offset += 1;

            unsigned format;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_format_id, tvb, offset, 1, ENC_NA, &format);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x 0x%02x 0x%02x", func_group, status, format);

            while (offset + 4 <= data_length) {
                offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);
            }
        }
            break;

        case UDS_RDTCI_TYPES_WWH_OBD_BY_GROUP_READY: {
            unsigned func_group;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_functional_group_id, tvb, offset, 1, ENC_NA, &func_group);
            offset += 1;

            unsigned status;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_status_avail, tvb, offset, 1, ENC_NA, &status);
            offset += 1;

            unsigned format;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_format_id, tvb, offset, 1, ENC_NA, &format);
            offset += 1;

            unsigned readiness;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdtci_dtc_readiness_group_id, tvb, offset, 1, ENC_NA, &readiness);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x 0x%02x 0x%02x 0x%02x", func_group, status, format, readiness);

            while (offset + 4 <= data_length) {
                offset = dissect_uds_dtc_and_status_record(tvb, pinfo, uds_tree, offset, ecu_address, false, false);
            }
        }
            break;

        default:
            if (offset < data_length) {
                proto_tree_add_item(uds_tree, hf_uds_rdtci_record, tvb, offset, data_length - offset, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, "    %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                offset = data_length;
            }
        }
    } else {
        static int * const dtc_status_mask_flags[] = {
            &hf_uds_rdtci_dtc_status_mask_wir,
            &hf_uds_rdtci_dtc_status_mask_tnctoc,
            &hf_uds_rdtci_dtc_status_mask_tfslc,
            &hf_uds_rdtci_dtc_status_mask_tncslc,
            &hf_uds_rdtci_dtc_status_mask_cdtc,
            &hf_uds_rdtci_dtc_status_mask_pdtc,
            &hf_uds_rdtci_dtc_status_mask_tftoc,
            &hf_uds_rdtci_dtc_status_mask_tf,
            NULL
        };

        switch (enum_val) {
        case UDS_RDTCI_TYPES_NUMBER_BY_STATUS_MASK:
        case UDS_RDTCI_TYPES_BY_STATUS_MASK:
        case UDS_RDTCI_TYPES_OUTDATED_RMMDTCBSM:
        case UDS_RDTCI_TYPES_OUTDATED_RNOMMDTCBSM:
        case UDS_RDTCI_TYPES_OUTDATED_RNOOEOBDDTCBSM:
        case UDS_RDTCI_TYPES_OUTDATED_ROBDDTCBSM: {
            uint64_t status_mask;
            proto_tree_add_bitmask_with_flags_ret_uint64(uds_tree, tvb, offset, hf_uds_rdtci_dtc_status_mask, ett_uds_dtc_status_bits, dtc_status_mask_flags, ENC_NA, BMT_NO_APPEND, &status_mask);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, "    0x%02x", (uint32_t)status_mask);
        }
            break;

        case UDS_RDTCI_TYPES_SNAPSHOT_IDENTIFICATION:
            /* no additional params */
            break;

        case UDS_RDTCI_TYPES_SNAPSHOT_RECORD_BY_DTC:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_mask_record, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_snapshot_rec_no, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_SNAPSHOT_RECORD_BY_RECORD:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_stored_data_rec_no, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_EXTENDED_RECORD_BY_DTC:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_mask_record, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_ext_data_rec_no, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_NUM_DTC_BY_SEVERITY_MASK:
        case UDS_RDTCI_TYPES_BY_SEVERITY_MASK:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_severity_mask, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(uds_tree, tvb, offset, hf_uds_rdtci_dtc_status_mask, ett_uds_dtc_status_bits, dtc_status_mask_flags, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_SEVERITY_INFO_OF_DTC:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_mask_record, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
            break;

        case UDS_RDTCI_TYPES_SUPPORTED_DTC:
        case UDS_RDTCI_TYPES_FIRST_TEST_FAILED_DTC:
        case UDS_RDTCI_TYPES_FIRST_CONFIRMED_DTC:
        case UDS_RDTCI_TYPES_MOST_RECENT_TEST_FAILED:
        case UDS_RDTCI_TYPES_MOST_RECENT_CONFIRMED_DTC:
        case UDS_RDTCI_TYPES_DTC_FAULT_DETECT_CTR:
        case UDS_RDTCI_TYPES_DTC_WITH_PERM_STATUS:
            /* no additional params */
            break;

        case UDS_RDTCI_TYPES_DTC_EXT_DATA_REC_BY_NUM:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_ext_data_rec_no, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_USER_MEM_DTC_BY_STATUS_M:
            proto_tree_add_bitmask(uds_tree, tvb, offset, hf_uds_rdtci_dtc_status_mask, ett_uds_dtc_status_bits, dtc_status_mask_flags, ENC_NA);
            offset += 1;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_memory_selection, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_USER_MEM_DTC_REC_BY_DTC_N:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_mask_record, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_user_def_dtc_snapshot_rec_no, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_memory_selection, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_USER_MEM_DTC_EXT_REC_BY_N:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_mask_record, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_ext_data_rec_no, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_memory_selection, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_SUP_DTC_EXT_RECORD:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_ext_data_rec_no, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_WWH_OBD_DTC_BY_MASK_REC:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_functional_group_id, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(uds_tree, tvb, offset, hf_uds_rdtci_dtc_status_mask, ett_uds_dtc_status_bits, dtc_status_mask_flags, ENC_NA);
            offset += 1;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_severity_mask, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_WWH_OBD_DTC_PERM_STATUS:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_functional_group_id, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case UDS_RDTCI_TYPES_WWH_OBD_BY_GROUP_READY:
            proto_tree_add_item(uds_tree, hf_uds_rdtci_functional_group_id, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(uds_tree, hf_uds_rdtci_dtc_readiness_group_id, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        default:
            if (offset < data_length) {
                proto_tree_add_item(uds_tree, hf_uds_rdtci_record, tvb, offset, data_length - offset, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, "    %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                offset = data_length;
            }
        }
    }

    return offset;
}

static int
dissect_uds_memory_addr_size(tvbuff_t *tvb, packet_info *pinfo, proto_tree *uds_tree, uint32_t offset, bool withDataFormatIdentifier) {
    uint32_t compression, encrypting;

    if (withDataFormatIdentifier) {
        proto_tree_add_item_ret_uint(uds_tree, hf_uds_compression_method, tvb, offset, 1, ENC_NA, &compression);
        proto_tree_add_item_ret_uint(uds_tree, hf_uds_encrypting_method, tvb, offset, 1, ENC_NA, &encrypting);
        offset += 1;
    }

    uint32_t memory_size_length, memory_address_length;
    proto_tree_add_item_ret_uint(uds_tree, hf_uds_memory_size_length, tvb, offset, 1, ENC_NA, &memory_size_length);
    proto_tree_add_item_ret_uint(uds_tree, hf_uds_memory_address_length, tvb, offset, 1, ENC_NA, &memory_address_length);
    offset += 1;

    uint64_t memory_address;
    proto_tree_add_item_ret_uint64(uds_tree, hf_uds_memory_address, tvb, offset, memory_address_length, ENC_BIG_ENDIAN, &memory_address);
    offset += memory_address_length;

    uint64_t memory_size;
    proto_tree_add_item_ret_uint64(uds_tree, hf_uds_memory_size, tvb, offset, memory_size_length, ENC_BIG_ENDIAN, &memory_size);
    offset += memory_size_length;

    col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%" PRIx64 " bytes at 0x%" PRIx64, memory_size, memory_address);

    if (withDataFormatIdentifier) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "   (Compression:0x%x Encrypting:0x%x)", compression, encrypting);
    }

    return offset;
}

static int
dissect_uds_certificates_into_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti, uint32_t offset, unsigned length) {
    asn1_ctx_t  asn1_ctx;

    if (!tree || !tvb || !ti || length == 0 || uds_certificate_decoding_config == cert_parsing_off) {
        return 0;
    }

    tvbuff_t *sub_tvb = tvb_new_subset_length(tvb, offset, length);

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
    proto_tree *cert_tree = proto_item_add_subtree(ti, ett_uds_ars_certificate);

    switch (uds_certificate_decoding_config) {
    case ber_cert_single_false:
        return dissect_x509af_Certificate(false, sub_tvb, 0, &asn1_ctx, cert_tree, hf_uds_signedCertificate);

    case ber_cert_single_true:
        return dissect_x509af_Certificate(true, sub_tvb, 0, &asn1_ctx, cert_tree, hf_uds_signedCertificate);

    case ber_cert_multi_false:
        return dissect_x509af_Certificates(false, sub_tvb, 0, &asn1_ctx, cert_tree, hf_uds_signedCertificate);

    case ber_cert_multi_true:
        return dissect_x509af_Certificates(true, sub_tvb, 0, &asn1_ctx, cert_tree, hf_uds_signedCertificate);
    }

    return 0;
}

static int
dissect_uds_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint16_t source_address, uint16_t target_address, uint8_t number_of_addresses_valid, uint8_t address_size) {
    proto_tree *uds_tree;
    proto_tree *subfunction_tree;
    proto_item *ti;
    uint8_t     sid, service;
    uint32_t    enum_val;
    const char *service_name;
    uint32_t    ecu_address;
    uint32_t    data_length = tvb_reported_length(tvb);
    tvbuff_t   *payload_tvb;

    uint32_t    offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDS");
    col_clear(pinfo->cinfo,COL_INFO);

    sid = tvb_get_uint8(tvb, offset);
    service = sid & UDS_SID_MASK;

    if (service < UDS_SERVICES_MIN && uds_dissect_small_sids_with_obd_ii && (obd_ii_handle != NULL)) {
        return call_dissector(obd_ii_handle, tvb_new_subset_length_caplen(tvb, offset, -1, -1), pinfo, tree);
    }

    service_name = val_to_str_ext(service, &uds_services_ext, "Unknown (0x%02x)");

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
        ecu_address = UINT32_MAX;
        break;
    case 1:
        uds_proto_item_append_address_text(ti, address_size, "Address", source_address);
        uds_proto_item_append_address_name(ti, source_address);

        uds_proto_tree_add_address_item(uds_tree, hf_uds_diag_addr, tvb, 0, 0, source_address, true, false);
        uds_proto_tree_add_address_name(uds_tree, hf_uds_diag_addr_name, tvb, 0, 0, source_address);
        break;
    case 2:
        uds_proto_item_append_address_text(ti, address_size, "Source", source_address);
        uds_proto_item_append_address_name(ti, source_address);
        uds_proto_item_append_address_text(ti, address_size, "Target", target_address);
        uds_proto_item_append_address_name(ti, target_address);

        uds_proto_tree_add_address_item(uds_tree, hf_uds_diag_source_addr, tvb, 0, 0, source_address, true, false);
        uds_proto_tree_add_address_name(uds_tree, hf_uds_diag_source_addr_name, tvb, 0, 0, source_address);

        uds_proto_tree_add_address_item(uds_tree, hf_uds_diag_addr, tvb, 0, 0, source_address, true, true);
        uds_proto_tree_add_address_name(uds_tree, hf_uds_diag_addr_name, tvb, 0, 0, source_address);

        uds_proto_tree_add_address_item(uds_tree, hf_uds_diag_target_addr, tvb, 0, 0, target_address, true, false);
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
        {
            bool suppress;
            proto_tree_add_item_ret_boolean(uds_tree, hf_uds_dsc_suppress_pos_rsp_msg_ind, tvb, offset, 1, ENC_NA, &suppress);
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_dsc_subfunction, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_dsc_types, "Unknown (0x%02x)"));
            if (suppress) {
                col_append_str(pinfo->cinfo, COL_INFO, "   (Reply suppressed)");
            }
        }
            offset += 1;

            if (sid & UDS_REPLY_MASK) {
                ti = proto_tree_add_item(uds_tree, hf_uds_dsc_parameter_record, tvb, offset, data_length - offset, ENC_NA);
                proto_tree *param_tree = proto_item_add_subtree(ti, ett_uds_dsc_parameter_record);

                uint32_t default_p2;
                proto_tree_add_item_ret_uint(param_tree, hf_uds_dsc_default_p2_server_timer, tvb, offset, 2, ENC_BIG_ENDIAN, &default_p2);
                offset += 2;

                uint32_t enhanced_p2 = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) * 10;
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
                uint32_t tmp;
                ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_er_power_down_time, tvb, offset, 1, ENC_NA, &tmp);
                if (tmp == UDS_ER_TYPE_ENABLE_RAPID_POWER_SHUTDOWN_INVALID) {
                    proto_item_append_text(ti, " (Failure or time not available!)");
                }
                offset += 1;
            }
            break;

        case UDS_SERVICES_CDTCI:
            if (sid & UDS_REPLY_MASK) {
                /* do nothing */
            } else {
                proto_tree_add_item(uds_tree, hf_uds_cdtci_group_of_dtc, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;

                if (offset + 1 <= data_length) {
                    proto_tree_add_item(uds_tree, hf_uds_cdtci_memory_selection, tvb, offset, 1, ENC_NA);
                }
            }
            break;

        case UDS_SERVICES_RDTCI:
            offset = dissect_uds_rdtci(tvb, pinfo, uds_tree, ecu_address, sid, offset, data_length);
            break;

        case UDS_SERVICES_RDBI:
            if (sid & UDS_REPLY_MASK) {
                /* Can't know the size of the data for each identifier, Decode like if there is only one identifier */
                uint32_t data_identifier;
                ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdbi_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &data_identifier);
                protoitem_append_data_name(ti, ecu_address, (uint16_t)data_identifier);
                offset += 2;

                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
                infocol_append_data_name(pinfo, ecu_address, data_identifier);

                bool dissection_ok = false;
                if (data_length > offset) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));

                    payload_tvb = tvb_new_subset_length(tvb, offset, data_length - offset);
                    dissection_ok = call_heur_subdissector_uds(payload_tvb, pinfo, tree, uds_tree, service, true, data_identifier, ecu_address);
                }

                if (!dissection_ok) {
                    /* ISO14229: at least one byte for data record. Just make sure, we show an error, if less than 1 byte left! */
                    proto_tree_add_item(uds_tree, hf_uds_data_record, tvb, offset, MAX(1, data_length - offset), ENC_NA);
                }

                offset = data_length;


            } else {
                /* ISO14229: data identifiers are 2 bytes and at least one has to be present. */
                do {
                    uint32_t data_identifier;
                    ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdbi_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &data_identifier);
                    protoitem_append_data_name(ti, ecu_address, (uint16_t)data_identifier);

                    col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
                    infocol_append_data_name(pinfo, ecu_address, data_identifier);
                    offset += 2;
                } while (data_length >= offset + 2);
            }
            break;

        case UDS_SERVICES_RMBA:
            if (sid & UDS_REPLY_MASK) {
                if (offset < data_length) {
                    proto_tree_add_item(uds_tree, hf_uds_data_record, tvb, offset, data_length - offset, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                    offset = data_length;
                }
            } else {
                offset = dissect_uds_memory_addr_size(tvb, pinfo, uds_tree, offset, false);
            }
            break;

        case UDS_SERVICES_RSDBI:
            proto_tree_add_item(uds_tree, hf_uds_rsdbi_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            if (sid & UDS_REPLY_MASK) {
                do {
                    proto_tree *tmp_tree;
                    ti = proto_tree_add_item(uds_tree, hf_uds_rsdbi_scaling_byte, tvb, offset, 1, ENC_NA);
                    tmp_tree = proto_item_add_subtree(ti, ett_uds_rsdbi_scaling_byte);
                    unsigned data_type, num_of_bytes;
                    proto_tree_add_item_ret_uint(tmp_tree, hf_uds_rsdbi_scaling_byte_data_type, tvb, offset, 1, ENC_NA, &data_type);
                    proto_tree_add_item_ret_uint(tmp_tree, hf_uds_rsdbi_scaling_byte_num_of_bytes, tvb, offset, 1, ENC_NA, &num_of_bytes);
                    proto_item_append_text(ti, ", %s, %d", val_to_str(data_type, uds_rsdbi_data_types, "Unknown (0x%x)"), num_of_bytes);
                    offset += 1;

                    /* lets parse the extension, if needed... */
                    unsigned next_pos;
                    switch (data_type) {
                    case UDS_RSDBI_DATA_TYPE_BITMAPPED_REPORTED_WO_MAP:
                        proto_tree_add_item(uds_tree, hf_uds_rsdbi_validity_mask, tvb, offset, num_of_bytes, ENC_NA);
                        offset += num_of_bytes;
                        break;
                    case UDS_RSDBI_DATA_TYPE_FORMULA:
                        proto_tree_add_item(uds_tree, hf_uds_rsdbi_formula_identifier, tvb, offset, 1, ENC_NA);
                        next_pos = offset + num_of_bytes;
                        while (offset + 2 <= next_pos) {
                            ti = proto_tree_add_item(uds_tree, hf_uds_rsdbi_formula_constant, tvb, offset, 2, ENC_NA);
                            proto_tree *const_tree = proto_item_add_subtree(ti, ett_uds_rsdbi_formula_constant);
                            proto_tree_add_item(const_tree, hf_uds_rsdbi_formula_constant_exp, tvb, offset, 2, ENC_BIG_ENDIAN);
                            proto_tree_add_item(const_tree, hf_uds_rsdbi_formula_constant_mantissa, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                        }
                        break;
                    case  UDS_RSDBI_DATA_TYPE_UNIT_FORMAT:
                        proto_tree_add_item(uds_tree, hf_uds_rsdbi_unit, tvb, offset, 1, ENC_NA);
                        offset += num_of_bytes;
                        break;
                    }
                } while (offset < data_length);

            }
            break;

        case UDS_SERVICES_SA:
            ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_sa_subfunction, tvb, offset, 1, ENC_NA, &enum_val);
            proto_item_append_text(ti, " (%s)", uds_sa_subfunction_to_string(enum_val));
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
                        proto_tree_add_item(uds_tree, hf_uds_data_record, tvb, offset, data_length - offset, ENC_NA);
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
                        proto_tree_add_item(uds_tree, hf_uds_data_record, tvb, offset, data_length - offset, ENC_NA);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                    }
                }
                offset = data_length;
            }
            break;

        case UDS_SERVICES_CC:
            if (sid & UDS_REPLY_MASK) {
                offset = dissect_uds_subfunction(tvb, pinfo, uds_tree, offset, &enum_val, hf_uds_cc_subfunction_no_suppress, uds_cc_types, false);
            } else {
                offset = dissect_uds_subfunction(tvb, pinfo, uds_tree, offset, &enum_val, hf_uds_cc_subfunction_no_suppress, uds_cc_types, true);

                proto_tree *comm_type_tree;
                ti = proto_tree_add_item(uds_tree, hf_uds_cc_comm_type_and_subnet_number, tvb, offset, 1, ENC_NA);
                comm_type_tree = proto_item_add_subtree(ti, ett_uds_cc_communication_type);
                proto_tree_add_item(comm_type_tree, hf_uds_cc_communication_type, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(comm_type_tree, hf_uds_cc_subnet_number, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (enum_val == UDS_CC_TYPES_ENABLE_RX_AND_DISABLE_TX_WITH_ENH_ADDR_INFO || enum_val == UDS_CC_TYPES_ENABLE_RX_AND_TX_WITH_ENH_ADDR_INFO) {
                    proto_tree_add_item(uds_tree, hf_uds_cc_node_identifier_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                }
            }
            break;

        case UDS_SERVICES_ARS:
            if (sid & UDS_REPLY_MASK) {
                unsigned length_field;
                proto_tree *algo_tree;

                offset = dissect_uds_subfunction(tvb, pinfo, uds_tree, offset, &enum_val, hf_uds_ars_subfunction_no_suppress, uds_ars_types, false);

                switch (enum_val) {
                case UDS_ARS_TYPES_DEAUTHENTICATE: /* fall through */
                case UDS_ARS_TYPES_TRANSMIT_CERTIFICATE: /* fall through */
                case UDS_ARS_TYPES_AUTH_CONFIGURATION:
                    proto_tree_add_item(uds_tree, hf_uds_ars_auth_ret_param, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    break;

                case UDS_ARS_TYPES_VERIFY_CERT_UNIDIRECTIONAL:
                    proto_tree_add_item(uds_tree, hf_uds_ars_auth_ret_param, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_challenge_server, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    proto_tree_add_item(uds_tree, hf_uds_ars_challenge_server, tvb, offset, length_field, ENC_NA);
                    offset += length_field;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_ephemeral_public_key_server, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    if (length_field > 0) {
                        proto_tree_add_item(uds_tree, hf_uds_ars_ephemeral_public_key_server, tvb, offset, length_field, ENC_NA);
                        offset += length_field;
                    }
                    break;

                case UDS_ARS_TYPES_VERIFY_CERT_BIDIRECTIONAL:
                    proto_tree_add_item(uds_tree, hf_uds_ars_auth_ret_param, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_challenge_server, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    proto_tree_add_item(uds_tree, hf_uds_ars_challenge_server, tvb, offset, length_field, ENC_NA);
                    offset += length_field;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_cert_server, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    ti = proto_tree_add_item(uds_tree, hf_uds_ars_cert_server, tvb, offset, length_field, ENC_NA);
                    dissect_uds_certificates_into_tree(tvb, pinfo, uds_tree, ti, offset, length_field);
                    offset += length_field;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_proof_of_ownership_server, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    proto_tree_add_item(uds_tree, hf_uds_ars_proof_of_ownership_server, tvb, offset, length_field, ENC_NA);
                    offset += length_field;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_ephemeral_public_key_server, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    if (length_field > 0) {
                        proto_tree_add_item(uds_tree, hf_uds_ars_ephemeral_public_key_server, tvb, offset, length_field, ENC_NA);
                        offset += length_field;
                    }
                    break;

                case UDS_ARS_TYPES_PROOF_OF_OWNERSHIP:
                    proto_tree_add_item(uds_tree, hf_uds_ars_auth_ret_param, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_session_key_info, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    if (length_field > 0) {
                        proto_tree_add_item(uds_tree, hf_uds_ars_session_key_info, tvb, offset, length_field, ENC_NA);
                        offset += length_field;
                    }
                    break;

                case UDS_ARS_TYPES_REQUEST_CHALLENGE_FOR_AUTH:
                    proto_tree_add_item(uds_tree, hf_uds_ars_auth_ret_param, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    ti = proto_tree_add_item(uds_tree, hf_uds_ars_algo_indicator, tvb, offset, 16, ENC_NA);
                    algo_tree = proto_item_add_subtree(ti, ett_uds_ars_algo_indicator);
                    dissect_unknown_ber(pinfo, tvb, offset, algo_tree);
                    offset += 16;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_challenge_server, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    proto_tree_add_item(uds_tree, hf_uds_ars_challenge_server, tvb, offset, length_field, ENC_NA);
                    offset += length_field;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_needed_additional_parameter, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    if (length_field > 0) {
                        proto_tree_add_item(uds_tree, hf_uds_ars_needed_additional_parameter, tvb, offset, length_field, ENC_NA);
                        offset += length_field;
                    }
                    break;

                case UDS_ARS_TYPES_VERIFY_PROOF_OF_OWN_UNIDIR:
                    proto_tree_add_item(uds_tree, hf_uds_ars_auth_ret_param, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    ti = proto_tree_add_item(uds_tree, hf_uds_ars_algo_indicator, tvb, offset, 16, ENC_NA);
                    algo_tree = proto_item_add_subtree(ti, ett_uds_ars_algo_indicator);
                    dissect_unknown_ber(pinfo, tvb, offset, algo_tree);
                    offset += 16;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_session_key_info, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    if (length_field > 0) {
                        proto_tree_add_item(uds_tree, hf_uds_ars_session_key_info, tvb, offset, length_field, ENC_NA);
                        offset += length_field;
                    }
                    break;

                case UDS_ARS_TYPES_VERIFY_PROOF_OF_OWN_BIDIR:
                    proto_tree_add_item(uds_tree, hf_uds_ars_auth_ret_param, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    ti = proto_tree_add_item(uds_tree, hf_uds_ars_algo_indicator, tvb, offset, 16, ENC_NA);
                    algo_tree = proto_item_add_subtree(ti, ett_uds_ars_algo_indicator);
                    dissect_unknown_ber(pinfo, tvb, offset, algo_tree);
                    offset += 16;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_proof_of_ownership_server, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    proto_tree_add_item(uds_tree, hf_uds_ars_proof_of_ownership_server, tvb, offset, length_field, ENC_NA);
                    offset += length_field;

                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_session_key_info, tvb, offset, 2, ENC_NA, &length_field);
                    offset += 2;

                    if (length_field > 0) {
                        proto_tree_add_item(uds_tree, hf_uds_ars_session_key_info, tvb, offset, length_field, ENC_NA);
                        offset += length_field;
                    }

                    break;
                }
            } else {
                proto_tree *algo_tree;
                offset = dissect_uds_subfunction(tvb, pinfo, uds_tree, offset, &enum_val, hf_uds_ars_subfunction_no_suppress, uds_ars_types, true);

                switch (enum_val) {
                case UDS_ARS_TYPES_DEAUTHENTICATE: /* fall through */
                case UDS_ARS_TYPES_AUTH_CONFIGURATION:
                    /* do nothing */
                    break;

                case UDS_ARS_TYPES_VERIFY_CERT_UNIDIRECTIONAL: /* fall through */
                case UDS_ARS_TYPES_VERIFY_CERT_BIDIRECTIONAL: {
                    proto_tree_add_item(uds_tree, hf_uds_ars_comm_config, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    unsigned length_cert_client;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_cert_client, tvb, offset, 2, ENC_NA, &length_cert_client);
                    offset += 2;

                    ti = proto_tree_add_item(uds_tree, hf_uds_ars_cert_client, tvb, offset, length_cert_client, ENC_NA);
                    dissect_uds_certificates_into_tree(tvb, pinfo, uds_tree, ti, offset, length_cert_client);
                    offset += length_cert_client;

                    unsigned length_challenge_client;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_challenge_client, tvb, offset, 2, ENC_NA, &length_challenge_client);
                    offset += 2;

                    if (length_challenge_client > 0 || enum_val == UDS_ARS_TYPES_VERIFY_CERT_BIDIRECTIONAL) {
                        proto_tree_add_item(uds_tree, hf_uds_ars_challenge_client, tvb, offset, length_challenge_client, ENC_NA);
                        offset += length_challenge_client;
                    }
                }
                    break;

                case UDS_ARS_TYPES_PROOF_OF_OWNERSHIP: {
                    unsigned length_proof_of_ownership_client;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_proof_of_ownership_client, tvb, offset, 2, ENC_NA, &length_proof_of_ownership_client);
                    offset += 2;

                    proto_tree_add_item(uds_tree, hf_uds_ars_proof_of_ownership_client, tvb, offset, length_proof_of_ownership_client, ENC_NA);
                    offset += length_proof_of_ownership_client;

                    unsigned length_ephemeral_public_key_client;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_ephemeral_public_key_client, tvb, offset, 2, ENC_NA, &length_ephemeral_public_key_client);
                    offset += 2;

                    if (length_ephemeral_public_key_client > 0) {
                        proto_tree_add_item(uds_tree, hf_uds_ars_ephemeral_public_key_client, tvb, offset, length_ephemeral_public_key_client, ENC_NA);
                        offset += length_ephemeral_public_key_client;
                    }
                }
                    break;


                case UDS_ARS_TYPES_TRANSMIT_CERTIFICATE: {
                    proto_tree_add_item(uds_tree, hf_uds_ars_cert_eval_id, tvb, offset, 2, ENC_NA);
                    offset += 2;

                    unsigned length_cert_data;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_cert_data, tvb, offset, 2, ENC_NA, &length_cert_data);
                    offset += 2;

                    proto_tree_add_item(uds_tree, hf_uds_ars_cert_data, tvb, offset, length_cert_data, ENC_NA);
                    offset += length_cert_data;
                }
                    break;

                case UDS_ARS_TYPES_REQUEST_CHALLENGE_FOR_AUTH: {
                    proto_tree_add_item(uds_tree, hf_uds_ars_comm_config, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    ti = proto_tree_add_item(uds_tree, hf_uds_ars_algo_indicator, tvb, offset, 16, ENC_NA);
                    algo_tree = proto_item_add_subtree(ti, ett_uds_ars_algo_indicator);
                    dissect_unknown_ber(pinfo, tvb, offset, algo_tree);
                    offset += 16;
                }
                    break;

                case UDS_ARS_TYPES_VERIFY_PROOF_OF_OWN_UNIDIR: /* fall through */
                case UDS_ARS_TYPES_VERIFY_PROOF_OF_OWN_BIDIR: {
                    ti = proto_tree_add_item(uds_tree, hf_uds_ars_algo_indicator, tvb, offset, 16, ENC_NA);
                    algo_tree = proto_item_add_subtree(ti, ett_uds_ars_algo_indicator);
                    dissect_unknown_ber(pinfo, tvb, offset, algo_tree);
                    offset += 16;

                    unsigned length_proof_of_ownership_client;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_proof_of_ownership_client, tvb, offset, 2, ENC_NA, &length_proof_of_ownership_client);
                    offset += 2;

                    proto_tree_add_item(uds_tree, hf_uds_ars_proof_of_ownership_client, tvb, offset, length_proof_of_ownership_client, ENC_NA);
                    offset += length_proof_of_ownership_client;

                    unsigned length_challenge_client;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_challenge_client, tvb, offset, 2, ENC_NA, &length_challenge_client);
                    offset += 2;

                    if (length_challenge_client > 0 || enum_val == UDS_ARS_TYPES_VERIFY_PROOF_OF_OWN_BIDIR) {
                        proto_tree_add_item(uds_tree, hf_uds_ars_challenge_client, tvb, offset, length_challenge_client, ENC_NA);
                        offset += length_challenge_client;
                    }

                    unsigned length_additional_parameter;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_ars_length_of_additional_parameter, tvb, offset, 2, ENC_NA, &length_additional_parameter);
                    offset += 2;

                    if (length_additional_parameter > 0) {
                        proto_tree_add_item(uds_tree, hf_uds_ars_additional_parameter, tvb, offset, length_additional_parameter, ENC_NA);
                        offset += length_additional_parameter;
                    }
                }
                    break;
                }
            }
            break;

        case UDS_SERVICES_RDBPI:
            if (sid & UDS_REPLY_MASK) {
                proto_tree_add_item(uds_tree, hf_uds_rdbpi_periodic_data_identifier, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(uds_tree, hf_uds_data_record, tvb, offset, data_length - offset, ENC_NA);
                offset = data_length;
            } else {
                unsigned transmission_mode;
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_rdbpi_transmission_mode, tvb, offset, 1, ENC_NA, &transmission_mode);
                offset += 1;

                /* For transmission mode 1 (send at slow rate), mode 2 (medium rate), and mode 3 (fast rate), require at least 1 pdid! */
                if (1 <= transmission_mode && transmission_mode <= 3) {
                    proto_tree_add_item(uds_tree, hf_uds_rdbpi_periodic_data_identifier, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                while (offset < data_length) {
                    proto_tree_add_item(uds_tree, hf_uds_rdbpi_periodic_data_identifier, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
            }
            break;

        case UDS_SERVICES_DDDI:
            if (sid & UDS_REPLY_MASK) {
                offset = dissect_uds_subfunction(tvb, pinfo, uds_tree, offset, &enum_val, hf_uds_dddi_subfunction_no_suppress, uds_dddi_types, false);

                if (offset + 2 <= data_length) {
                    proto_tree_add_item(uds_tree, hf_uds_dddi_dyn_defined_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                }
            } else {
                offset = dissect_uds_subfunction(tvb, pinfo, uds_tree, offset, &enum_val, hf_uds_dddi_subfunction_no_suppress, uds_dddi_types, true);

                switch (enum_val) {
                case UDS_DDDI_TYPES_DEFINE_BY_IDENTIFIER:
                    proto_tree_add_item(uds_tree, hf_uds_dddi_dyn_defined_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    do {
                        proto_tree *tmp_tree;
                        tmp_tree = proto_tree_add_subtree(uds_tree, tvb, offset, 4, ett_uds_dddi_entry, &ti, "Element");

                        unsigned source_data_id;
                        proto_tree_add_item_ret_uint(tmp_tree, hf_uds_dddi_source_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &source_data_id);
                        offset += 2;

                        unsigned position;
                        proto_tree_add_item_ret_uint(tmp_tree, hf_uds_dddi_position_in_source_data_record, tvb, offset, 1, ENC_NA, &position);
                        offset += 1;

                        unsigned mem_size;
                        proto_tree_add_item_ret_uint(tmp_tree, hf_uds_dddi_memory_size, tvb, offset, 1, ENC_NA, &mem_size);
                        offset += 1;

                        proto_item_append_text(ti, " %d with Source ID 0x%04x and %d byte(s)", position, source_data_id, mem_size);
                    } while (offset + 4 <= data_length);

                    break;

                case UDS_DDDI_TYPES_DEFINE_BY_MEM_ADDRESS:
                    proto_tree_add_item(uds_tree, hf_uds_dddi_dyn_defined_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    uint32_t memory_size_length, memory_address_length;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_memory_size_length, tvb, offset, 1, ENC_NA, &memory_size_length);
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_memory_address_length, tvb, offset, 1, ENC_NA, &memory_address_length);
                    offset += 1;

                    do {
                        uint64_t memory_address;
                        proto_tree_add_item_ret_uint64(uds_tree, hf_uds_memory_address, tvb, offset, memory_address_length, ENC_BIG_ENDIAN, &memory_address);
                        offset += memory_address_length;

                        uint64_t memory_size;
                        proto_tree_add_item_ret_uint64(uds_tree, hf_uds_memory_size, tvb, offset, memory_size_length, ENC_BIG_ENDIAN, &memory_size);
                        offset += memory_size_length;
                    } while (offset + memory_address_length + memory_size_length <= data_length);
                    break;

                case UDS_DDDI_TYPES_CLEAR_DYN_DEF_DATA_ID:
                    if (offset + 2 <= data_length) {
                        proto_tree_add_item(uds_tree, hf_uds_dddi_dyn_defined_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                    }
                    break;
                }
            }
            break;

        case UDS_SERVICES_WDBI:
            ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_wdbi_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &enum_val);
            protoitem_append_data_name(ti, ecu_address, (uint16_t)enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", enum_val);
            infocol_append_data_name(pinfo, ecu_address, enum_val);
            offset += 2;

            if (!(sid & UDS_REPLY_MASK)) {
                bool dissection_ok = false;
                if (data_length > offset) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));

                    payload_tvb = tvb_new_subset_length(tvb, offset, data_length - offset);
                    dissection_ok = call_heur_subdissector_uds(payload_tvb, pinfo, tree, uds_tree, service, false, enum_val, ecu_address);
                }

                if (!dissection_ok) {
                    /* ISO14229: at least one byte for data record. Just make sure, we show an error, if less than 1 byte left! */
                    proto_tree_add_item(uds_tree, hf_uds_data_record, tvb, offset, MAX(1, data_length - offset), ENC_NA);
                }

                offset = data_length;
            }
            break;

        case UDS_SERVICES_IOCBI: {
            uint32_t data_identifier;
            ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_iocbi_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &data_identifier);
            protoitem_append_data_name(ti, ecu_address, (uint16_t)data_identifier);
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

            uint32_t identifier;
            ti = proto_tree_add_item_ret_uint(uds_tree, hf_uds_rc_identifier, tvb, offset, 2, ENC_BIG_ENDIAN, &identifier);
            protoitem_append_routine_name(ti, ecu_address, identifier);
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x", identifier);
            infocol_append_routine_name(pinfo, ecu_address, identifier);
            offset += 2;

            if (sid & UDS_REPLY_MASK) {
                if (data_length > offset) {
                    uint32_t info;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_rc_info, tvb, offset, 1, ENC_NA, &info);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%x", info);
                    offset += 1;

                    if (data_length > offset) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));

                        payload_tvb = tvb_new_subset_length(tvb, offset, data_length - offset);
                        if (!call_heur_subdissector_uds(payload_tvb, pinfo, tree, uds_tree, service, true, identifier, ecu_address)) {
                            proto_tree_add_item(uds_tree, hf_uds_rc_status_record, tvb, offset, data_length - offset, ENC_NA);
                        }

                        offset = data_length;
                    }
                }
            } else {
                if (data_length > offset) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));

                    payload_tvb = tvb_new_subset_length(tvb, offset, data_length - offset);
                    if (!call_heur_subdissector_uds(payload_tvb, pinfo, tree, uds_tree, service, false, identifier, ecu_address)) {
                        proto_tree_add_item(uds_tree, hf_uds_rc_option_record, tvb, offset, data_length - offset, ENC_NA);
                    }

                    offset = data_length;
                }
            }
            break;
        }

        case UDS_SERVICES_RD: /* fall through */
        case UDS_SERVICES_RU:
            if (sid & UDS_REPLY_MASK) {
                uint32_t max_block_length_length;
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_max_block_len_len, tvb, offset, 1, ENC_NA, &max_block_length_length);
                offset += 1;

                uint64_t max_block_length;
                proto_tree_add_item_ret_uint64(uds_tree, hf_uds_max_block_len, tvb, offset, max_block_length_length, ENC_BIG_ENDIAN, &max_block_length);
                offset += max_block_length_length;

                col_append_fstr(pinfo->cinfo, COL_INFO, "   Max Block Length 0x%" PRIx64, max_block_length);
            } else {
                offset = dissect_uds_memory_addr_size(tvb, pinfo, uds_tree, offset, true);
            }
            break;

        case UDS_SERVICES_TD: {
            uint32_t sequence_no;
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

        case UDS_SERVICES_RTE:
            if (data_length > offset) {
                proto_tree_add_item(uds_tree, hf_uds_rte_record_data, tvb, offset, data_length - offset, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                offset = data_length;
            }
            break;

        case UDS_SERVICES_RFT: {
            unsigned mode_of_op;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_rft_mode_of_operation, tvb, offset, 1, ENC_NA, &mode_of_op);
            offset += 1;

            if (sid & UDS_REPLY_MASK) {
                if (mode_of_op != UDS_RFT_MODE_DELETE_FILE) {
                    uint32_t length_max_num_block_len;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_rft_length_format_identifier, tvb, offset, 1, ENC_NA, &length_max_num_block_len);
                    offset += 1;

                    proto_tree_add_item(uds_tree, hf_uds_rft_max_num_of_block_length, tvb, offset, length_max_num_block_len, ENC_BIG_ENDIAN);
                    offset += length_max_num_block_len;
                }

                if (mode_of_op != UDS_RFT_MODE_DELETE_FILE) {
                    proto_tree_add_item(uds_tree, hf_uds_compression_method, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(uds_tree, hf_uds_encrypting_method, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                if (mode_of_op != UDS_RFT_MODE_ADD_FILE && mode_of_op != UDS_RFT_MODE_DELETE_FILE && mode_of_op != UDS_RFT_MODE_REPLACE_FILE && mode_of_op != UDS_RFT_MODE_RESUME_FILE) {
                    unsigned length_field;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_rft_file_size_or_dir_info_param_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length_field);
                    offset += 2;

                    proto_tree_add_item(uds_tree, hf_uds_rft_file_size_uncompressed_or_dir_info_length, tvb, offset, length_field, ENC_BIG_ENDIAN);
                    offset += length_field;

                    if (mode_of_op != UDS_RFT_MODE_READ_DIR) {
                        proto_tree_add_item(uds_tree, hf_uds_rft_file_size_compressed, tvb, offset, length_field, ENC_BIG_ENDIAN);
                        offset += length_field;
                    }
                }

                if (mode_of_op != UDS_RFT_MODE_ADD_FILE && mode_of_op != UDS_RFT_MODE_DELETE_FILE && mode_of_op != UDS_RFT_MODE_REPLACE_FILE && mode_of_op != UDS_RFT_MODE_READ_FILE
                    && mode_of_op != UDS_RFT_MODE_READ_DIR) {
                    proto_tree_add_item(uds_tree, hf_uds_rft_file_position, tvb, offset, 8, ENC_BIG_ENDIAN);
                    offset += 8;
                }
            } else {
                unsigned length_field;
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_rft_length_of_file_path_and_name, tvb, offset, 2, ENC_BIG_ENDIAN, &length_field);
                offset += 2;

                proto_tree_add_item(uds_tree, hf_uds_rft_file_path_and_name, tvb, offset, length_field, ENC_ASCII);
                offset += length_field;

                if (mode_of_op != UDS_RFT_MODE_DELETE_FILE && mode_of_op != UDS_RFT_MODE_READ_DIR) {
                    proto_tree_add_item(uds_tree, hf_uds_compression_method, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(uds_tree, hf_uds_encrypting_method, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                if (mode_of_op != UDS_RFT_MODE_DELETE_FILE && mode_of_op != UDS_RFT_MODE_READ_FILE && mode_of_op != UDS_RFT_MODE_READ_DIR) {
                    uint32_t fileSizeParameterLength;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_rft_file_size_param_length, tvb, offset, 1, ENC_NA, &fileSizeParameterLength);
                    offset += 1;

                    uint64_t filesize_uncompressed, filesize_compressed;
                    proto_tree_add_item_ret_uint64(uds_tree, hf_uds_rft_file_size_uncompressed, tvb, offset, fileSizeParameterLength, ENC_BIG_ENDIAN, &filesize_uncompressed);
                    offset += fileSizeParameterLength;

                    proto_tree_add_item_ret_uint64(uds_tree, hf_uds_rft_file_size_compressed, tvb, offset, fileSizeParameterLength, ENC_BIG_ENDIAN, &filesize_compressed);
                    offset += fileSizeParameterLength;
                }

            }
        }
            break;

        case UDS_SERVICES_WMBA:
            offset = dissect_uds_memory_addr_size(tvb, pinfo, uds_tree, offset, false);

            if (sid & UDS_REPLY_MASK) {
                /* do nothing */
            } else {
                if (offset < data_length) {
                    proto_tree_add_item(uds_tree, hf_uds_data_record, tvb, offset, data_length - offset, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                    offset = data_length;
                }
            }
            break;

        case UDS_SERVICES_TP:
            offset = dissect_uds_subfunction(tvb, pinfo, uds_tree, offset, &enum_val, hf_uds_tp_subfunction_no_suppress, NULL, !(sid & UDS_REPLY_MASK));
            break;

        case UDS_SERVICES_ERR:
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_err_sid, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str_ext(enum_val, &uds_services_ext, "Unknown (0x%02x)"));
            offset += 1;

            proto_tree_add_item_ret_uint(uds_tree, hf_uds_err_code, tvb, offset, 1, ENC_NA, &enum_val);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (NRC: %s)", val_to_str_ext(enum_val, &uds_response_codes_ext, "Unknown (0x%02x)"));
            offset += 1;
            break;

        case UDS_SERVICES_SDT: {
            static int * const admin_param_flags[] = {
                &hf_uds_sdt_administrative_param_resp_sign_req,
                &hf_uds_sdt_administrative_param_signed,
                &hf_uds_sdt_administrative_param_encrypted,
                &hf_uds_sdt_administrative_param_pre_estab_key,
                &hf_uds_sdt_administrative_param_req,
                NULL
            };

            uint64_t addmin_param;
            proto_tree_add_bitmask_with_flags_ret_uint64(uds_tree, tvb, offset, hf_uds_sdt_administrative_param, ett_uds_sdt_admin_param, admin_param_flags, ENC_NA, BMT_NO_APPEND, &addmin_param);
            offset += 2;

            proto_tree_add_item(uds_tree, hf_uds_sdt_signature_encryption_calculation, tvb, offset, 1, ENC_NA);
            offset += 1;

            uint32_t sig_length;
            proto_tree_add_item_ret_uint(uds_tree, hf_uds_sdt_signature_length, tvb, offset, 2, ENC_BIG_ENDIAN, &sig_length);
            offset += 2;

            proto_tree_add_item(uds_tree, hf_uds_sdt_anti_replay_counter, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            if (offset + sig_length < data_length) {
                uint32_t encap_length = data_length - offset - sig_length;
                ti = proto_tree_add_item(uds_tree, hf_uds_sdt_encapsulated_message, tvb, offset, encap_length, ENC_NA);

                if ((addmin_param & UDS_SDT_ADMIN_PARAM_ENCRYPTED) == 0) {
                    proto_tree *encap_tree = proto_item_add_subtree(ti, ett_uds_sdt_encap_message);
                    proto_tree_add_item(encap_tree, hf_uds_sdt_encapsulated_message_sid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(encap_tree, hf_uds_sdt_encapsulated_message_sid_reply, tvb, offset, 1, ENC_NA);
                }
                offset += encap_length;
            }

            proto_tree_add_item(uds_tree, hf_uds_sdt_signature_mac, tvb, offset, sig_length, ENC_NA);
            offset += sig_length;

        }
            break;

        case UDS_SERVICES_CDTCS:
            if ((sid & UDS_REPLY_MASK)) {
                proto_tree_add_item_ret_uint(uds_tree, hf_uds_cdtcs_type, tvb, offset, 1, ENC_NA, &enum_val);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_cdtcs_types, "Unknown (0x%02x)"));
                offset += 1;
            } else {
                ti = proto_tree_add_item(uds_tree, hf_uds_cdtcs_subfunction, tvb, offset, 1, ENC_NA);
                subfunction_tree = proto_item_add_subtree(ti, ett_uds_subfunction);
                proto_tree_add_item_ret_uint(subfunction_tree, hf_uds_cdtcs_subfunction_no_suppress, tvb, offset, 1, ENC_NA, &enum_val);
                proto_tree_add_item(subfunction_tree, hf_uds_cdtcs_subfunction_pos_rsp_msg_ind, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_cdtcs_types, "Unknown (0x%02x)"));
                offset += 1;

                if (data_length - offset > 0) {
                    proto_tree_add_item(uds_tree, hf_uds_cdtcs_option_record, tvb, offset, data_length - offset, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length - offset, ' '));
                    offset = data_length;
                }
            }
            break;

        case UDS_SERVICES_ROE:
            /* TODO UDS_SERVICES_ROE 0x86*/
            break;

        case UDS_SERVICES_LC:
            ti = proto_tree_add_item(uds_tree, hf_uds_lc_subfunction, tvb, offset, 1, ENC_NA);
            /* do not increase offset, since reply uses the same byte with different mask! */

            subfunction_tree = proto_item_add_subtree(ti, ett_uds_subfunction);
            proto_tree_add_item_ret_uint(subfunction_tree, hf_uds_lc_subfunction_no_suppress, tvb, offset, 1, ENC_NA, &enum_val);

            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(enum_val, uds_lc_types, "Unknown (0x%02x)"));

            if (sid & UDS_REPLY_MASK) {
                offset += 1;
            } else {
                proto_tree_add_item(subfunction_tree, hf_uds_lc_subfunction_pos_rsp_msg_ind, tvb, offset, 1, ENC_NA);
                offset += 1;

                switch (enum_val) {
                case UDS_LC_TYPES_VMTWFP: {
                    unsigned control_mode_id;
                    proto_tree_add_item_ret_uint(uds_tree, hf_uds_lc_control_mode_id, tvb, offset, 1, ENC_NA, &control_mode_id);
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(control_mode_id, uds_lc_lcmi_types, "Unknown (0x%02x)"));
                    offset += 1;
                }
                    break;

                case UDS_LC_TYPES_VMTWSP:
                    proto_tree_add_item(uds_tree, hf_uds_lc_link_record, tvb, offset, 3, ENC_BIG_ENDIAN);
                    offset += 3;
                    break;

                case UDS_LC_TYPES_TM:
                    /* do nothing */
                    break;
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
dissect_uds_no_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    return dissect_uds_internal(tvb, pinfo, tree, 0, 0, 0, 0);
}

static int
dissect_uds_doip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    DISSECTOR_ASSERT(data);

    doip_info_t *doip_info = (doip_info_t *)data;
    return dissect_uds_internal(tvb, pinfo, tree, doip_info->source_address, doip_info->target_address, 2, 2);
}

static int
dissect_uds_hsfz(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    DISSECTOR_ASSERT(data);

    hsfz_info_t *hsfz_info = (hsfz_info_t *)data;
    return dissect_uds_internal(tvb, pinfo, tree, hsfz_info->source_address, hsfz_info->target_address, 2, 1);
}

static int
dissect_uds_iso15765(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    DISSECTOR_ASSERT(data);

    iso15765_info_t *info = (iso15765_info_t *)data;
    return dissect_uds_internal(tvb, pinfo, tree, info->source_address, info->target_address, info->number_of_addresses_valid, info->address_length);
}

static int
dissect_uds_iso10681(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    DISSECTOR_ASSERT(data);

    iso10681_info_t *info = (iso10681_info_t *)data;
    return dissect_uds_internal(tvb, pinfo, tree, info->source_address, info->target_address, 2, 2);
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

    if (uds_ht_dtc_ids && uds_uat_dtc_id_num == 0) {
        g_hash_table_destroy(uds_ht_dtc_ids);
        uds_ht_dtc_ids = NULL;
    }

}

void
proto_register_uds(void) {
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
            "Service Identifier", "uds.sid", FT_UINT8,  BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&uds_services_ext), UDS_SID_MASK, NULL, HFILL } },
        { &hf_uds_reply, {
            "Reply Flag", "uds.reply", FT_UINT8, BASE_HEX, NULL, UDS_REPLY_MASK, NULL, HFILL } },

        { &hf_uds_subfunction, {
            "SubFunction", "uds.subfunction", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_suppress_pos_rsp_msg_ind, {
            "Suppress reply", "uds.suppress_reply.indication", FT_BOOLEAN, 8, NULL, UDS_SUPPRESS_POS_RSP_MSG_IND_MASK, NULL, HFILL } },
        { &hf_uds_data_record, {
            "Data Record", "uds.data_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_compression_method, {
            "Compression Method", "uds.compression_method", FT_UINT8, BASE_HEX, NULL, UDS_RD_COMPRESSION_METHOD_MASK, NULL, HFILL } },
        { &hf_uds_encrypting_method, {
            "Encrypting Method", "uds.encrypting_method", FT_UINT8, BASE_HEX, NULL, UDS_RD_ENCRYPTING_METHOD_MASK, NULL, HFILL } },
        { &hf_uds_memory_size_length, {
            "Memory size length", "uds.memory_size_length", FT_UINT8, BASE_HEX, NULL, UDS_RD_MEMORY_SIZE_LENGTH_MASK, NULL, HFILL } },
        { &hf_uds_memory_address_length, {
            "Memory address length", "uds.memory_address_length", FT_UINT8, BASE_HEX, NULL, UDS_RD_MEMORY_ADDRESS_LENGTH_MASK, NULL, HFILL } },
        { &hf_uds_memory_address, {
            "Memory Address", "uds.memory_address", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_memory_size, {
            "Memory Size", "uds.memory_size", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_max_block_len_len, {
            "Length of Max Block Length", "uds.max_block_length_length", FT_UINT8, BASE_HEX, NULL, UDS_RD_MAX_BLOCK_LEN_LEN_MASK, NULL, HFILL } },
        { &hf_uds_max_block_len, {
            "Max Block Length", "uds.max_block_length", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_dsc_subfunction, {
            "SubFunction", "uds.dsc.subfunction", FT_UINT8, BASE_HEX, VALS(uds_dsc_types), UDS_SUBFUNCTION_MASK, NULL, HFILL } },
        { &hf_uds_dsc_suppress_pos_rsp_msg_ind, {
            "Suppress reply", "uds.dsc.suppress_reply.indication", FT_BOOLEAN, 8, NULL, UDS_SUPPRESS_POS_RSP_MSG_IND_MASK, NULL, HFILL } },
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

        { &hf_uds_cdtci_group_of_dtc, {
            "Group of DTC", "uds.cdtci.group_of_dtc", FT_UINT24, BASE_HEX, VALS(uds_cdtci_group_of_dtc), 0x0, NULL, HFILL } },
        { &hf_uds_cdtci_memory_selection, {
            "Memory Selection", "uds.cdtci.memory_selection", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_rdtci_subfunction, {
            "SubFunction", "uds.rdtci.subfunction", FT_UINT8, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&uds_rdtci_types_ext), 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_mask, {
            "DTC Status Mask", "uds.rdtci.dtc_status_mask", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_mask_tf, {
            "(Last) Test Failed", "uds.rdtci.dtc_status_mask.tf", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_FAILED, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_mask_tftoc, {
            "Test Failed This Operation Cycle", "uds.rdtci.dtc_status_mask.tftoc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_FAILED_THIS_OPER_CYCLE, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_mask_pdtc, {
            "Pending DTC", "uds.rdtci.dtc_status_mask.pdtc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_PENDING_DTC, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_mask_cdtc, {
            "Confirmed DTC", "uds.rdtci.dtc_status_mask.ctdc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_CONFIRMED_DTC, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_mask_tncslc, {
            "Test Not Completed Since Last Clear", "uds.rdtci.dtc_status_mask.tncslc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_NOT_COMPL_SINCE_LAST_CLEAR, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_mask_tfslc, {
            "Test Failed Since Last Clear", "uds.rdtci.dtc_status_mask.tfslc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_FAILED_SINCE_LAST_CLEAR, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_mask_tnctoc, {
            "Test Not Completed This Operation Cycle", "uds.rdtci.dtc_status_mask.tnctoc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_NOT_COMPL_THIS_OPER_CYCLE, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_mask_wir, {
            "Warning Indicator Requested", "uds.rdtci.dtc_status_mask.wir", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_WARNING_INDICATOR_REQUESTED, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_mask_record, {
            "DTC Mask Record", "uds.rdtci.dtc_mask_record", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_snapshot_rec_no, {
            "DTC Snapshot Record Number", "uds.rdtci.dtc_snapshot_record_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_stored_data_rec_no, {
            "DTC Stored Data Record Number", "uds.rdtci.dtc_stored_data_record_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_ext_data_rec_no, {
            "DTC Extended Data Record Number", "uds.rdtci.dtc_extended_data_record_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_severity_mask, {
            "DTC Severity Mask", "uds.rdtci.dtc_severity_mask", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_memory_selection, {
            "Memory Selection", "uds.rdtci.memory_selection", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_user_def_dtc_snapshot_rec_no, {
            "User Defined DTC Snapshot Record Number", "uds.rdtci.user_def_dtc_snapshot_record_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_functional_group_id, {
            "Functional Group Identifier", "uds.rdtci.functional_group_id", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_readiness_group_id, {
            "DTC Readiness Group Identifier", "uds.rdtci.dtc_readiness_group_id", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_avail, {
            "DTC Status Availability Mask", "uds.rdtci.dtc_status_availability_mask", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_avail_tf, {
            "Test Failed", "uds.rdtci.dtc_status_avail_mask.tf", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_FAILED, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_avail_tftoc, {
            "Test Failed This Operation Cycle", "uds.rdtci.dtc_status_avail_mask.tftoc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_FAILED_THIS_OPER_CYCLE, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_avail_pdtc, {
            "Pending DTC", "uds.rdtci.dtc_status_avail_mask.pdtc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_PENDING_DTC, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_avail_cdtc, {
            "Confirmed DTC", "uds.rdtci.dtc_status_avail_mask.ctdc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_CONFIRMED_DTC, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_avail_tncslc,{
            "Test Not Completed Since Last Clear", "uds.rdtci.dtc_status_avail_mask.tncslc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_NOT_COMPL_SINCE_LAST_CLEAR, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_avail_tfslc, {
            "Test Failed Since Last Clear", "uds.rdtci.dtc_status_avail_mask.tfslc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_FAILED_SINCE_LAST_CLEAR, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_avail_tnctoc, {
            "Test Not Completed This Operation Cycle", "uds.rdtci.dtc_status_avail_mask.tnctoc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_NOT_COMPL_THIS_OPER_CYCLE, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_avail_wir, {
            "Warning Indicator Requested", "uds.rdtci.dtc_status_avail_mask.wir", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_WARNING_INDICATOR_REQUESTED, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_id, {
            "DTC Identifier", "uds.rdtci.dtc_id", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status, {
            "DTC Status", "uds.rdtci.dtc_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_tf, {
            "Test Failed", "uds.rdtci.dtc_status.tf", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_FAILED, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_tftoc, {
            "Test Failed This Operation Cycle", "uds.rdtci.dtc_status.tftoc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_FAILED_THIS_OPER_CYCLE, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_pdtc, {
            "Pending DTC", "uds.rdtci.dtc_status.pdtc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_PENDING_DTC, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_cdtc, {
            "Confirmed DTC", "uds.rdtci.dtc_status.ctdc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_CONFIRMED_DTC, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_tncslc, {
            "Test Not Completed Since Last Clear", "uds.rdtci.dtc_status.tncslc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_NOT_COMPL_SINCE_LAST_CLEAR, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_tfslc, {
            "Test Failed Since Last Clear", "uds.rdtci.dtc_status.tfslc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_FAILED_SINCE_LAST_CLEAR, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_tnctoc, {
            "Test Not Completed This Operation Cycle", "uds.rdtci.dtc_status.tnctoc", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_TEST_NOT_COMPL_THIS_OPER_CYCLE, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_status_wir, {
            "Warning Indicator Requested", "uds.rdtci.dtc_status.wir", FT_BOOLEAN, 8, NULL, UDS_RDTCI_DTC_STATUS_WARNING_INDICATOR_REQUESTED, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_format_id, {
            "DTC Format Identifier", "uds.rdtci.dtc_format_id", FT_UINT8, BASE_HEX_DEC, VALS(uds_rdtci_format_id_types), 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_count, {
            "DTC Count", "uds.rdtci.dtc_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_snapshot_record_number_of_ids, {
            "DTC Snapshot Record Number of IDs", "uds.rdtci.dtc_snapshot_record_number_of_ids", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_stored_data_record_number_of_ids, {
            "DTC Stored Data Record Number of IDs", "uds.rdtci.dtc_stored_data_record_number_of_ids", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_severity, {
            "DTC Severity", "uds.rdtci.dtc_severity", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_functional_unit, {
            "DTC Functional Unit", "uds.rdtci.dtc_functional_unit", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_fault_detect_counter, {
            "DTC Fault Detection Counter", "uds.rdtci.dtc_fault_detection_counter", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_dtc_severity_avail, {
            "DTC Severity Availability Mask", "uds.rdtci.dtc_severity_availability_mask", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_record, {
            "Record", "uds.rdtci.record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rdtci_record_unparsed, {
            "Unparsed Record", "uds.rdtci.record_unparsed", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_rdbi_data_identifier, {
            "Data Identifier", "uds.rdbi.data_identifier", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_rsdbi_data_identifier, {
            "Data Identifier", "uds.rsdbi.data_identifier", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rsdbi_scaling_byte, {
            "Scaling Byte", "uds.rsdbi.scaling_byte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rsdbi_scaling_byte_data_type, {
            "Data Type", "uds.rsdbi.scaling_byte.data_type", FT_UINT8, BASE_HEX, VALS(uds_rsdbi_data_types), 0xF0, NULL, HFILL } },
        { &hf_uds_rsdbi_scaling_byte_num_of_bytes, {
            "Number of Bytes", "uds.rsdbi.scaling_byte.number_of_Bytes", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL } },
        { &hf_uds_rsdbi_validity_mask, {
            "Validity Mask", "uds.rsdbi.scaling_byte_ext.validity_mask", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rsdbi_formula_identifier, {
            "Formula Identifier", "uds.rsdbi.scaling_byte_ext.formula_identifier", FT_UINT8, BASE_HEX, VALS(uds_rsdbi_formulas), 0x0, NULL, HFILL } },
        { &hf_uds_rsdbi_formula_constant, {
            "Constant", "uds.rsdbi.scaling_byte_ext.formula_constant", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rsdbi_formula_constant_exp, {
            "Exponent", "uds.rsdbi.scaling_byte_ext.formulat_constant_exp", FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL } },
        { &hf_uds_rsdbi_formula_constant_mantissa, {
            "Constant", "uds.rsdbi.scaling_byte_ext.formulat_constant", FT_UINT16, BASE_HEX, NULL, 0x0FFF, NULL, HFILL } },
        { &hf_uds_rsdbi_unit, {
            "Unit Identifier", "uds.rsdbi.scaling_byte_ext.unit", FT_UINT8, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&uds_rsdbi_units_ext), 0x0, NULL, HFILL } },

        { &hf_uds_sa_subfunction, {
            "SubFunction", "uds.sa.subfunction", FT_UINT8, BASE_CUSTOM, CF_FUNC(uds_sa_subfunction_format), 0x0, NULL, HFILL } },
        { &hf_uds_sa_key, {
            "Key", "uds.sa.key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_sa_seed, {
            "Seed", "uds.sa.seed", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_cc_subfunction_no_suppress, {
            "SubFunction (without Suppress)", "uds.cc.subfunction_without_suppress", FT_UINT8, BASE_HEX, VALS(uds_cc_types), UDS_SUBFUNCTION_MASK, NULL, HFILL } },
        { &hf_uds_cc_comm_type_and_subnet_number, {
            "Communication Type/Subnet Number", "uds.cc.comm_type_and_subnet_number", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_cc_communication_type, {
            "Communication Type", "uds.cc.communication_type", FT_UINT8, BASE_HEX, VALS(uds_cc_comm_types), UDS_CC_COMM_TYPE_COMM_TYPE_MASK, NULL, HFILL } },
        { &hf_uds_cc_subnet_number, {
            "Subnet Number", "uds.cc.subnet_number", FT_UINT8, BASE_HEX, VALS(uds_cc_subnet_number_types), UDS_CC_COMM_TYPE_SUBNET_NUMBER_MASK, NULL, HFILL } },
        { &hf_uds_cc_node_identifier_number, {
            "Node Identifier Number", "uds.cc.node_identifier_number", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_ars_subfunction_no_suppress, {
            "SubFunction (without Suppress)", "uds.ars.subfunction_without_suppress", FT_UINT8, BASE_HEX, VALS(uds_ars_types), UDS_SUBFUNCTION_MASK, NULL, HFILL } },
        { &hf_uds_ars_comm_config, {
            "Communication Configuration", "uds.ars.communication_configuration", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_cert_client, {
            "Length of Certificate Client", "uds.ars.length_of_certificate_client", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_cert_client, {
            "Certificate Client", "uds.ars.certificate_client", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_cert_server, {
            "Length of Certificate Server", "uds.ars.length_of_certificate_server", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_cert_server, {
            "Certificate Server", "uds.ars.certificate_server", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_challenge_client, {
            "Length of Challenge Client", "uds.ars.length_of_challenge_client", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_challenge_client, {
            "Challenge Client", "uds.ars.challenge_client", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_challenge_server, {
            "Length of Challenge Server", "uds.ars.length_of_challenge_server", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_challenge_server, {
            "Challenge Server", "uds.ars.challenge_server", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_proof_of_ownership_client, {
            "Length of Proof of Ownership Client", "uds.ars.length_of_proof_of_ownership_client", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_proof_of_ownership_client, {
            "Proof of Ownership Client", "uds.ars.proof_of_ownership_client", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_proof_of_ownership_server, {
            "Length of Proof of Ownership Server", "uds.ars.length_of_proof_of_ownership_server", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_proof_of_ownership_server, {
            "Proof of Ownership Server", "uds.ars.proof_of_ownership_server", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_ephemeral_public_key_client, {
            "Length of Ephemeral Public Key Client", "uds.ars.length_of_ephemeral_public_key_client", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_ephemeral_public_key_client, {
            "Ephemeral Public Key Client", "uds.ars.ephemeral_public_key_client", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_ephemeral_public_key_server, {
            "Length of Ephemeral Public Key Server", "uds.ars.length_of_ephemeral_public_key_server", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_ephemeral_public_key_server, {
            "Ephemeral Public Key Server", "uds.ars.ephemeral_public_key_server", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_cert_eval_id, {
            "Certificate Evaluation ID", "uds.ars.certificate_evaluation_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_cert_data, {
            "Length of Certificate Data", "uds.ars.length_of_certificate_data", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_cert_data, {
            "Certificate Data", "uds.ars.certificate_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_algo_indicator, {
            "Algorithm Indicator", "uds.ars.algorithm_indicator", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_additional_parameter, {
            "Length of Additional Parameter", "uds.ars.length_of_additional_parameter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_additional_parameter, {
            "Additional Parameter", "uds.ars.additional_parameter", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_needed_additional_parameter, {
            "Length of Needed Additional Parameter", "uds.ars.length_of_needed_additional_parameter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_needed_additional_parameter, {
            "Needed Additional Parameter", "uds.ars.needed_additional_parameter", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_auth_ret_param, {
            "Authentication Return Parameter", "uds.ars.authentication_return_parameter", FT_UINT8, BASE_HEX, VALS(uds_ars_auth_ret_types), 0x0, NULL, HFILL } },
        { &hf_uds_ars_length_of_session_key_info, {
            "Length of Session Key Info", "uds.ars.length_of_session_key_info", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_ars_session_key_info, {
            "Session Key Info", "uds.ars.session_key_info", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_signedCertificate, {
            "signedCertificate", "uds.signedCertificate_element", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_uds_rdbpi_transmission_mode, {
            "Transmission Mode", "uds.rdbpi.transmission_mode", FT_UINT8, BASE_HEX, VALS(uds_rdbpi_transmission_mode), 0x0, NULL, HFILL } },
        { &hf_uds_rdbpi_periodic_data_identifier, {
            "Periodic Data Identifier", "uds.rdbpi.periodic_data_identifier", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_dddi_subfunction_no_suppress, {
            "SubFunction (without Suppress)", "uds.dddi.subfunction_without_suppress", FT_UINT8, BASE_HEX, VALS(uds_dddi_types), UDS_SUBFUNCTION_MASK, NULL, HFILL } },
        { &hf_uds_dddi_dyn_defined_data_identifier, {
            "Dynamically Defined Data Identifier", "uds.dddi.dynamically_defined_data_identifier", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_dddi_source_data_identifier, {
            "Source Data Identifier", "uds.dddi.source_data_identifier", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_dddi_position_in_source_data_record, {
            "Position in Source Data Record", "uds.dddi.position_in_source_data_record", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_dddi_memory_size, {
            "Memory Size", "uds.dddi.memory_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_wdbi_data_identifier, {
            "Data Identifier", "uds.wdbi.data_identifier", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_iocbi_data_identifier, {
            "Data Identifier", "uds.iocbi.data_identifier", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
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

        { &hf_uds_td_sequence_counter, {
            "Block Sequence Counter", "uds.td.block_sequence_counter", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_td_record_data, {
            "Parameter Record", "uds.td.parameter_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_rte_record_data, {
            "Parameter Record", "uds.rte.parameter_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_rft_mode_of_operation, {
            "Mode of Operation", "uds.rft.mode_of_operation", FT_UINT8, BASE_HEX, VALS(uds_rft_mode_types), 0x0, NULL, HFILL } },
        { &hf_uds_rft_length_of_file_path_and_name, {
            "Length of File Path and Name", "uds.rft.length_of_file_path_and_name", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rft_file_path_and_name, {
            "File Path and Name", "uds.rft.file_path_and_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rft_file_size_param_length, {
            "File Size Parameter Length", "uds.rft.file_size_parameter_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rft_file_size_uncompressed, {
            "File Size Uncompressed", "uds.rft.file_size_uncompressed", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rft_file_size_compressed, {
            "File Size Compressed", "uds.rft.file_size_compressed", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rft_length_format_identifier, {
            "Length Format Identifier", "uds.rft.length_format_identifier", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rft_max_num_of_block_length, {
            "Max Number of Block Length", "uds.rft.max_number_of_block_length", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rft_file_size_or_dir_info_param_length, {
            "File Size or Dir Info Parameter Length", "uds.rft.file_size_or_dir_info_parameter_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rft_file_size_uncompressed_or_dir_info_length, {
            "File Size Uncompressed or Dir Info Length", "uds.rft.file_size_uncompressed_or_dir_info_length", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_rft_file_position, {
            "File Position", "uds.rft.file_position", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_tp_subfunction_no_suppress, {
            "SubFunction (without Suppress)", "uds.tp.subfunction_without_suppress", FT_UINT8, BASE_HEX, NULL, UDS_SUBFUNCTION_MASK, NULL, HFILL } },

        { &hf_uds_err_sid,  {
            "Service Identifier", "uds.err.sid", FT_UINT8, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&uds_services_ext), 0x0, NULL, HFILL } },
        { &hf_uds_err_code, {
            "Code", "uds.err.code",  FT_UINT8, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&uds_response_codes_ext), 0x0, NULL, HFILL }  },

        { &hf_uds_sdt_administrative_param, {
            "Administrative Parameter", "uds.sdt.admin_param",  FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_sdt_administrative_param_req, {
            "Request message", "uds.sdt.admin_param.request", FT_BOOLEAN, 16, NULL, UDS_SDT_ADMIN_PARAM_REQ, NULL, HFILL } },
        { &hf_uds_sdt_administrative_param_pre_estab_key, {
            "Pre-established key is used", "uds.sdt.admin_param.pre_estab_key", FT_BOOLEAN, 16, NULL, UDS_SDT_ADMIN_PARAM_PRE_ESTABL_KEY, NULL, HFILL } },
        { &hf_uds_sdt_administrative_param_encrypted, {
            "Message is encrypted", "uds.sdt.admin_param.encrypted", FT_BOOLEAN, 16, NULL, UDS_SDT_ADMIN_PARAM_ENCRYPTED, NULL, HFILL } },
        { &hf_uds_sdt_administrative_param_signed, {
            "Message is signed", "uds.sdt.admin_param.signed", FT_BOOLEAN, 16, NULL, UDS_SDT_ADMIN_PARAM_SIGNED, NULL, HFILL } },
        { &hf_uds_sdt_administrative_param_resp_sign_req, {
            "Signature on the response is requested", "uds.sdt.admin_param.resp_sign_req", FT_BOOLEAN, 16, NULL, UDS_SDT_ADMIN_PARAM_SIGN_ON_RESP_REQ, NULL, HFILL } },
        { &hf_uds_sdt_signature_encryption_calculation, {
            "Signature/Encryption Calculation", "uds.sdt.signature_encryption_calculation",  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_sdt_signature_length, {
            "Signature/MAC Length", "uds.sdt.signature_length",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_sdt_anti_replay_counter, {
            "Anti-replay Counter", "uds.sdt.anti_replay_counter",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_sdt_encapsulated_message, {
            "Encapsulated Message", "uds.sdt.encapsulated_message",  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_sdt_encapsulated_message_sid, {
            "Service Identifier", "uds.sdt.encapsulated_message.sid",  FT_UINT8, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&uds_services_ext), UDS_SID_MASK, NULL, HFILL } },
        { &hf_uds_sdt_encapsulated_message_sid_reply, {
            "Reply Flag", "uds.sdt.encapsulated_message.reply", FT_UINT8, BASE_HEX, NULL, UDS_REPLY_MASK, NULL, HFILL } },
        { &hf_uds_sdt_signature_mac, {
            "Signature/MAC", "uds.sdt.signature_mac",  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_cdtcs_subfunction, {
            "SubFunction", "uds.cdtcs.subfunction", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_cdtcs_subfunction_no_suppress, {
            "DTC Setting Type", "uds.cdtcs.subfunction_without_suppress", FT_UINT8, BASE_HEX, VALS(uds_cdtcs_types), UDS_SUBFUNCTION_MASK, NULL, HFILL } },
        { &hf_uds_cdtcs_subfunction_pos_rsp_msg_ind, {
            "Suppress reply", "uds.cdtcs.suppress_reply", FT_BOOLEAN, 8, NULL, UDS_SUPPRESS_POS_RSP_MSG_IND_MASK, NULL, HFILL } },
        { &hf_uds_cdtcs_option_record, {
            "Option Record", "uds.cdtcs.option_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_cdtcs_type, {
            "DTC Setting Type", "uds.cdtcs.dtc_setting_type", FT_UINT8, BASE_HEX, VALS(uds_cdtcs_types), 0x0, NULL, HFILL } },

        { &hf_uds_lc_subfunction, {
            "SubFunction", "uds.lc.subfunction", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_lc_subfunction_no_suppress, {
            "SubFunction (without Suppress)", "uds.lc.subfunction_without_suppress", FT_UINT8, BASE_HEX, VALS(uds_lc_types), UDS_SUBFUNCTION_MASK, NULL, HFILL } },
        { &hf_uds_lc_subfunction_pos_rsp_msg_ind, {
            "Suppress reply", "uds.lc.suppress_reply", FT_BOOLEAN, 8, NULL, UDS_SUPPRESS_POS_RSP_MSG_IND_MASK, NULL, HFILL } },
        { &hf_uds_lc_control_mode_id, {
            "Link Control Mode Identifier", "uds.lc.link_control_mode_identifier", FT_UINT8, BASE_HEX, VALS(uds_lc_lcmi_types), 0x0, NULL, HFILL } },
        { &hf_uds_lc_link_record, {
            "Link Record", "uds.lc.link_record", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_uds_did_reply_f186_diag_session, {
            "Diagnostic Session", "uds.did_f186.diagnostic_session", FT_UINT8, BASE_HEX, VALS(uds_dsc_types), 0x0, NULL, HFILL } },
        { &hf_uds_did_reply_f190_vin, {
            "VIN", "uds.did_f190.vin", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_did_reply_ff00_version, {
            "Version", "uds.did_ff00.version", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_uds_did_reply_ff01_dlc_support, {
            "DLC Supports", "uds.did_ff01.dlc_supports", FT_UINT8, BASE_HEX, VALS(uds_did_resrvdcpadlc_types), 0x0, NULL, HFILL } },

        { &hf_uds_unparsed_bytes, {
            "Unparsed Bytes", "uds.unparsed_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    uat_t* uds_routine_ids_uat;
    uat_t* uds_data_ids_uat;
    uat_t* uds_dtc_ids_uat;
    uat_t* uds_address_uat;

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_uds,
        &ett_uds_subfunction,
        &ett_uds_dtc_status_entry,
        &ett_uds_dtc_status_bits,
        &ett_uds_dtc_snapshot_entry,
        &ett_uds_dtc_counter_entry,
        &ett_uds_dsc_parameter_record,
        &ett_uds_rsdbi_scaling_byte,
        &ett_uds_rsdbi_formula_constant,
        &ett_uds_cc_communication_type,
        &ett_uds_ars_certificate,
        &ett_uds_ars_algo_indicator,
        &ett_uds_dddi_entry,
        &ett_uds_sdt_admin_param,
        &ett_uds_sdt_encap_message,
    };

    proto_uds = proto_register_protocol (
        "Unified Diagnostic Services",  /* name       */
        "UDS",                          /* short name */
        "uds"                           /* abbrev     */
    );

    proto_register_field_array(proto_uds, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    uds_handle = register_dissector("uds", dissect_uds_no_data, proto_uds);
    uds_handle_doip = register_dissector("uds_over_doip", dissect_uds_doip, proto_uds);
    uds_handle_hsfz = register_dissector("uds_over_hsfz", dissect_uds_hsfz, proto_uds);
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

    uds_routine_ids_uat = uat_new("UDS Routine Identifier List",
        sizeof(generic_addr_id_string_t),           /* record size           */
        DATAFILE_UDS_ROUTINE_IDS,                   /* filename              */
        true,                                       /* from profile          */
        (void**)&uds_uat_routine_ids,               /* data_ptr              */
        &uds_uat_routine_id_num,                    /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_generic_one_id_string_cb,              /* copy callback         */
        update_generic_addr_16bit_id_16bit,         /* update callback       */
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
        true,                                       /* from profile          */
        (void**)&uds_uat_data_ids,                  /* data_ptr              */
        &uds_uat_data_id_num,                       /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_generic_one_id_string_cb,              /* copy callback         */
        update_generic_addr_16bit_id_16bit,         /* update callback       */
        free_generic_one_id_string_cb,              /* free callback         */
        post_update_uds_data_cb,                    /* post update callback  */
        NULL,                                       /* reset callback        */
        uds_data_id_uat_fields                      /* UAT field definitions */
    );

    prefs_register_uat_preference(uds_module, "_uds_data_id_list", "UDS Data Identifier List",
        "A table to define names of UDS Data Identifier", uds_data_ids_uat);


    static uat_field_t uds_dtc_id_uat_fields[] = {
        UAT_FLD_HEX(uds_uat_dtc_ids, address, "Address", "Address (16bit hex without leading 0x, 0xffffffff for 'any')"),
        UAT_FLD_HEX(uds_uat_dtc_ids, id, "DTC ID", "Data Identifier (24bit hex without leading 0x)"),
        UAT_FLD_CSTRING(uds_uat_dtc_ids, name, "DTC Name", "Name of the Data ID (string)"),
        UAT_END_FIELDS
    };

    uds_dtc_ids_uat = uat_new("UDS DTC Identifier List",
        sizeof(generic_addr_id_string_t),           /* record size           */
        DATAFILE_UDS_DTC_IDS,                       /* filename              */
        true,                                       /* from profile          */
        (void**)&uds_uat_dtc_ids,                   /* data_ptr              */
        &uds_uat_dtc_id_num,                        /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_generic_one_id_string_cb,              /* copy callback         */
        update_generic_addr_16bit_id_24bit,         /* update callback       */
        free_generic_one_id_string_cb,              /* free callback         */
        post_update_uds_dtc_cb,                     /* post update callback  */
        NULL,                                       /* reset callback        */
        uds_dtc_id_uat_fields                       /* UAT field definitions */
    );

    prefs_register_uat_preference(uds_module, "_uds_dtc_id_list", "UDS DTC Identifier List",
        "A table to define names of UDS DTC Identifier", uds_dtc_ids_uat);


    static uat_field_t uds_address_name_uat_fields[] = {
        UAT_FLD_HEX(uds_uat_addresses, address, "Address", "Address (32bit hex without leading 0x)"),
        UAT_FLD_CSTRING(uds_uat_addresses, name, "Name", "Name of the Address (string)"),
        UAT_END_FIELDS
    };

    uds_address_uat = uat_new("UDS Addresses",
        sizeof(address_string_t),                   /* record size           */
        DATAFILE_UDS_ADDRESSES,                     /* filename              */
        true,                                       /* from profile          */
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

    prefs_register_enum_preference(uds_module, "cert_decode_strategy",
        "Certificate Decoding Strategy",
        "Decide how the certificate bytes are decoded",
        &uds_certificate_decoding_config, certificate_decoding_vals, false);

    heur_subdissector_list = register_heur_dissector_list_with_description("uds", "UDS RDBI data", proto_uds);
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
