/* packet-f1ap.c
 * Routines for E-UTRAN F1 Application Protocol (F1AP) packet dissection
 * Copyright 2018-2024, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 38.473 V18.2.0 (2024-06)
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>
#include <epan/stats_tree.h>

#include "packet-per.h"
#include "packet-f1ap.h"
#include "packet-x2ap.h"
#include "packet-nr-rrc.h"
#include "packet-e212.h"
#include "packet-pdcp-nr.h"
#include "packet-lte-rrc.h"
#include "packet-nrppa.h"
#include "packet-lpp.h"

#define PNAME  "F1 Application Protocol"
#define PSNAME "F1AP"
#define PFNAME "f1ap"

#define SCTP_PORT_F1AP 38472

void proto_register_f1ap(void);
void proto_reg_handoff_f1ap(void);

#include "packet-f1ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_f1ap;

static int hf_f1ap_transportLayerAddressIPv4;
static int hf_f1ap_transportLayerAddressIPv6;
static int hf_f1ap_IABTNLAddressIPv4;
static int hf_f1ap_IABTNLAddressIPv6;
static int hf_f1ap_IABTNLAddressIPv6Prefix;
static int hf_f1ap_interfacesToTrace_NG_C;
static int hf_f1ap_interfacesToTrace_Xn_C;
static int hf_f1ap_interfacesToTrace_Uu;
static int hf_f1ap_interfacesToTrace_F1_C;
static int hf_f1ap_interfacesToTrace_E1;
static int hf_f1ap_interfacesToTrace_Reserved;
static int hf_f1ap_MeasurementsToActivate_Reserved1;
static int hf_f1ap_MeasurementsToActivate_M2;
static int hf_f1ap_MeasurementsToActivate_Reserved2;
static int hf_f1ap_MeasurementsToActivate_M5;
static int hf_f1ap_MeasurementsToActivate_Reserved3;
static int hf_f1ap_MeasurementsToActivate_M6;
static int hf_f1ap_MeasurementsToActivate_M7;
static int hf_f1ap_ReportCharacteristics_PRBPeriodic;
static int hf_f1ap_ReportCharacteristics_TNLCapacityIndPeriodic;
static int hf_f1ap_ReportCharacteristics_CompositeAvailableCapacityPeriodic;
static int hf_f1ap_ReportCharacteristics_HWLoadIndPeriodic;
static int hf_f1ap_ReportCharacteristics_NumberOfActiveUEs;
static int hf_f1ap_ReportCharacteristics_Reserved;
#include "packet-f1ap-hf.c"

/* Initialize the subtree pointers */
static int ett_f1ap;
static int ett_f1ap_ResourceCoordinationTransferContainer;
static int ett_f1ap_PLMN_Identity;
static int ett_f1ap_MIB_message;
static int ett_f1ap_SIB1_message;
static int ett_f1ap_CG_ConfigInfo;
static int ett_f1ap_CellGroupConfig;
static int ett_f1ap_TransportLayerAddress;
static int ett_f1ap_UE_CapabilityRAT_ContainerList;
static int ett_f1ap_measurementTimingConfiguration;
static int ett_f1ap_DUtoCURRCContainer;
static int ett_f1ap_requestedP_MaxFR1;
static int ett_f1ap_HandoverPreparationInformation;
static int ett_f1ap_MeasConfig;
static int ett_f1ap_MeasGapConfig;
static int ett_f1ap_MeasGapSharingConfig;
static int ett_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container;
static int ett_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container;
static int ett_f1ap_ProtectedEUTRAResourceIndication;
static int ett_f1ap_RRCContainer;
static int ett_f1ap_RRCContainer_RRCSetupComplete;
static int ett_f1ap_sIBmessage;
static int ett_f1ap_UplinkTxDirectCurrentListInformation;
static int ett_f1ap_DRX_Config;
static int ett_f1ap_Ph_InfoSCG;
static int ett_f1ap_RequestedBandCombinationIndex;
static int ett_f1ap_RequestedFeatureSetEntryIndex;
static int ett_f1ap_RequestedP_MaxFR2;
static int ett_f1ap_UEAssistanceInformation;
static int ett_f1ap_CG_Config;
static int ett_f1ap_Ph_InfoMCG;
static int ett_f1ap_BurstArrivalTime;
static int ett_f1ap_cSI_RS_Configuration;
static int ett_f1ap_sR_Configuration;
static int ett_f1ap_pDCCH_ConfigSIB1;
static int ett_f1ap_sCS_Common;
static int ett_f1ap_IABTNLAddressIPv4Address;
static int ett_f1ap_IABTNLAddressIPv6Address;
static int ett_f1ap_IABTNLAddressIPv6Prefix;
static int ett_f1ap_InterfacesToTrace;
static int ett_f1ap_MeasurementsToActivate;
static int ett_f1ap_NRUERLFReportContainer;
static int ett_f1ap_RACH_Config_Common;
static int ett_f1ap_RACH_Config_Common_IAB;
static int ett_f1ap_RAReportContainer;
static int ett_f1ap_ReferenceTime;
static int ett_f1ap_ReportCharacteristics;
static int ett_f1ap_SIB10_message;
static int ett_f1ap_SIB12_message;
static int ett_f1ap_SIB13_message;
static int ett_f1ap_SIB14_message;
static int ett_f1ap_SIB15_message;
static int ett_f1ap_SIB17_message;
static int ett_f1ap_SIB20_message;
static int ett_f1ap_SIB22_message;
static int ett_f1ap_SIB23_message;
static int ett_f1ap_SIB24_message;
static int ett_f1ap_SL_PHY_MAC_RLC_Config;
static int ett_f1ap_SL_PHY_MAC_RLC_ConfigExt;
static int ett_f1ap_SL_RLC_ChannelToAddModList;
static int ett_f1ap_SL_ConfigDedicatedEUTRA_Info;
static int ett_f1ap_TDD_UL_DLConfigCommonNR;
static int ett_f1ap_UEAssistanceInformationEUTRA;
static int ett_f1ap_PosAssistance_Information;
static int ett_f1ap_LocationMeasurementInformation;
static int ett_f1ap_MUSIM_GapConfig;
static int ett_f1ap_SDT_MAC_PHY_CG_Config;
static int ett_f1ap_SDTRLCBearerConfiguration;
static int ett_f1ap_MBSInterestIndication;
static int ett_f1ap_NeedForGapsInfoNR;
static int ett_f1ap_NeedForGapNCSGInfoNR;
static int ett_f1ap_NeedForGapNCSGInfoEUTRA;
static int ett_f1ap_MBS_Broadcast_NeighbourCellList;
static int ett_f1ap_mRB_PDCP_Config_Broadcast;
static int ett_f1ap_posMeasGapPreConfigToAddModList;
static int ett_f1ap_posMeasGapPreConfigToReleaseList;
static int ett_f1ap_SidelinkConfigurationContainer;
static int ett_f1ap_SRSPosRRCInactiveConfig;
static int ett_f1ap_successfulHOReportContainer;
static int ett_f1ap_UL_GapFR2_Config;
static int ett_f1ap_ConfigRestrictInfoDAPS;
static int ett_f1ap_UplinkTxDirectCurrentTwoCarrierListInfo;
static int ett_f1ap_Ncd_SSB_RedCapInitialBWP_SDT;
static int ett_f1ap_JointorDLTCIStateID;
static int ett_f1ap_ULTCIStateID;
static int ett_f1ap_ReferenceConfigurationInformation;
static int ett_f1ap_LTMCFRAResourceConfig;
static int ett_f1ap_location_Information;
static int ett_f1ap_velocity_Information;
static int ett_f1ap_successfulPSCellChangeReportContainer;
static int ett_f1ap_cSIResourceConfigToAddModList;
static int ett_f1ap_cSIResourceConfigToReleaseList;
static int ett_f1ap_mbs_NeighbourCellList;
static int ett_f1ap_mtch_NeighbourCellprovided;
static int ett_f1ap_thresholdMBSList;
static int ett_f1ap_mBSMulticastConfiguration;
static int ett_f1ap_MusimCandidateBandList;
static int ett_f1ap_NeedForInterruptionInfoNR;
static int ett_f1ap_RACHConfiguration;
static int ett_f1ap_SRSPosRRCInactiveValidityAreaConfig;
static int ett_f1ap_TCIStatesConfigurationsList;
#include "packet-f1ap-ett.c"

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

/* F1AP stats - Tap interface */

static void set_stats_message_type(packet_info *pinfo, int type);

static const uint8_t *st_str_packets        = "Total Packets";
static const uint8_t *st_str_packet_types   = "F1AP Packet Types";

static int st_node_packets = -1;
static int st_node_packet_types = -1;
static int f1ap_tap;

struct f1ap_tap_t {
    int f1ap_mtype;
};

#define MTYPE_RESET                                        1
#define MTYPE_RESET_ACK                                    2
#define MTYPE_F1_SETUP_REQUEST                             3
#define MTYPE_F1_SETUP_RESPONSE                            4
#define MTYPE_F1_SETUP_FAILURE                             5
#define MTYPE_GNB_DU_CONFIGURATION_UPDATE                  6
#define MTYPE_GNB_DU_CONFIGURATION_UPDATE_ACKNOWLEDGE      7
#define MTYPE_GNB_DU_CONFIGURATION_UPDATE_FAILURE          8
#define MTYPE_GNB_CU_CONFIGURATION_UPDATE                  9
#define MTYPE_GNB_CU_CONFIGURATION_UPDATE_ACKNOWLEDGE      10
#define MTYPE_GNB_CU_CONFIGURATION_UPDATE_FAILURE          11
#define MTYPE_UE_CONTEXT_SETUP_REQUEST                     12
#define MTYPE_UE_CONTEXT_SETUP_RESPONSE                    13
#define MTYPE_UE_CONTEXT_SETUP_FAILURE                     14
#define MTYPE_UE_CONTEXT_RELEASE_COMMAND                   15
#define MTYPE_UE_CONTEXT_RELEASE_COMPLETE                  16
#define MTYPE_UE_CONTEXT_MODIFICATION_REQUEST              17
#define MTYPE_UE_CONTEXT_MODIFICATION_RESPONSE             18
#define MTYPE_UE_CONTEXT_MODIFICATION_FAILURE              19
#define MTYPE_UE_CONTEXT_MODIFICATION_REQUIRED             20
#define MTYPE_UE_CONTEXT_MODIFICATION_CONFIRM              21
#define MTYPE_UE_CONTEXT_MODIFICATION_REFUSE               22
#define MTYPE_WRITE_REPLACE_WARNING_REQUEST                23
#define MTYPE_WRITE_REPLACE_WARNING_RESPONSE               24
#define MTYPE_PWS_CANCEL_REQUEST                           25
#define MTYPE_PWS_CANCEL_RESPONSE                          26
#define MTYPE_ERROR_INDICATION                             27
#define MTYPE_UE_CONTEXT_RELEASE_REQUEST                   28
#define MTYPE_INITIAL_UL_RRC_MESSAGE_TRANSFER              29
#define MTYPE_DL_RRC_MESSAGE_TRANSFER                      30
#define MTYPE_UL_RRC_MESSAGE_TRANSFER                      31
#define MTYPE_UE_INACTIVITY_NOTIFICATION                   32
#define MTYPE_GNB_DU_RESOURCE_COORDINATION_REQUEST         33
#define MTYPE_GNB_DU_RESOURCE_COORDINATION_RESPONSE        34
#define MTYPE_PRIVATE_MESSAGE                              35
#define MTYPE_SYSTEM_INFORMATION_DELIVERY_COMMAND          36
#define MTYPE_PAGING                                       37
#define MTYPE_NOTIFY                                       38
#define MTYPE_NETWORK_ACCESS_RATE_REDUCTION                39
#define MTYPE_PWS_RESTART_INDICATION                       40
#define MTYPE_PWS_FAILURE_INDICATION                       41
#define MTYPE_GNB_DU_STATUS_INDICATION                     42
#define MTYPE_RRC_DELIVERY_REPORT                          43
#define MTYPE_F1_REMOVAL_REQUEST                           44
#define MTYPE_F1_REMOVAL_RESPONSE                          45
#define MTYPE_F1_REMOVAL_FAILURE                           46
#define MTYPE_TRACE_START                                  47
#define MTYPE_DEACTIVATE_TRACE                             48
#define MTYPE_DU_CU_RADIO_INFORMATION_TRANSFER             49
#define MTYPE_CU_DU_RADIO_INFORMATION_TRANSFER             50
#define MTYPE_BAP_MAPPING_CONFIGURATION                    51
#define MTYPE_BAP_MAPPING_CONFIGURATION_ACKNOWLEDGE        52
#define MTYPE_BAP_MAPPING_CONFIGURATION_FAILURE            53
#define MTYPE_GNB_DU_RESOURCE_CONFIGURATION                54
#define MTYPE_GNB_DU_RESOURCE_CONFIGURATION_ACKNOWLEDGE    55
#define MTYPE_GNB_DU_RESOURCE_CONFIGURATION_FAILURE        56
#define MTYPE_IAB_TNL_ADDRESS_REQUEST                      57
#define MTYPE_IAB_TNL_ADDRESS_RESPONSE                     58
#define MTYPE_IAB_TNL_ADDRESS_FAILURE                      59
#define MTYPE_IAB_UP_CONFIGURATION_UPDATE_REQUEST          60
#define MTYPE_IAB_UP_CONFIGURATION_UPDATE_RESPONSE         61
#define MTYPE_IAB_UP_CONFIGURATION_UPDATE_FAILURE          62
#define MTYPE_RESOURCE_STATUS_REQUEST                      63
#define MTYPE_RESOURCE_STATUS_RESPONSE                     64
#define MTYPE_RESOURCE_STATUS_FAILURE                      65
#define MTYPE_RESOURCE_STATUS_UPDATE                       66
#define MTYPE_ACCESS_AND_MOBILITY_INDICATION               67
#define MTYPE_REFERENCE_TIME_INFORMATION_REPORTING_CONTROL 68
#define MTYPE_REFERENCE_TIME_INFORMATION_REPORT            69
#define MTYPE_ACCESS_SUCCESS                               70
#define MTYPE_CELL_TRAFFIC_TRACE                           71
#define MTYPE_POSITIONING_ASSISTANCE_INFORMATION_CONTROL   72
#define MTYPE_POSITIONING_ASSISTANCE_INFORMATION_FEEDBACK  73
#define MTYPE_POSITIONING_MEASUREMENT_REQUEST              74
#define MTYPE_POSITIONING_MEASUREMENT_RESPONSE             75
#define MTYPE_POSITIONING_MEASUREMENT_FAILURE              76
#define MTYPE_POSITIONING_MEASUREMENT_REPORT               77
#define MTYPE_POSITIONING_MEASUREMENT_ABORT                78
#define MTYPE_POSITIONING_MEASUREMENT_FAILURE_INDICATION   79
#define MTYPE_POSITIONING_MEASUREMENT_UPDATE               80
#define MTYPE_TRP_INFORMATION_REQUEST                      81
#define MTYPE_TRP_INFORMATION_RESPONSE                     82
#define MTYPE_TRP_INFORMATION_FAILURE                      83
#define MTYPE_POSITIONING_INFORMATION_REQUEST              84
#define MTYPE_POSITIONING_INFORMATION_RESPONSE             85
#define MTYPE_POSITIONING_INFORMATION_FAILURE              86
#define MTYPE_POSITIONING_ACTIVATION_REQUEST               87
#define MTYPE_POSITIONING_ACTIVATION_RESPONSE              88
#define MTYPE_POSITIONING_ACTIVATION_FAILURE               89
#define MTYPE_POSITIONING_DEACTIVATION                     90
#define MTYPE_E_CID_MEASUREMENT_INITIATION_REQUEST         91
#define MTYPE_E_CID_MEASUREMENT_INITIATION_RESPONSE        92
#define MTYPE_E_CID_MEASUREMENT_INITIATION_FAILURE         93
#define MTYPE_E_CID_MEASUREMENT_FAILURE_INDICATION         94
#define MTYPE_E_CID_MEASUREMENT_REPORT                     95
#define MTYPE_E_CID_MEASUREMENT_TERMINATION_COMMAND        96
#define MTYPE_POSITIONING_INFORMATION_UPDATE               97
#define MTYPE_BROADCAST_CONTEXT_SETUP_REQUEST              98
#define MTYPE_BROADCAST_CONTEXT_SETUP_RESPONSE             99
#define MTYPE_BROADCAST_CONTEXT_SETUP_FAILURE              100
#define MTYPE_BROADCAST_CONTEXT_RELEASE_COMMAND            101
#define MTYPE_BROADCAST_CONTEXT_RELEASE_COMPLETE           102
#define MTYPE_BROADCAST_CONTEXT_RELEASE_REQUEST            103
#define MTYPE_BROADCAST_CONTEXT_MODIFICATION_REQUEST       104
#define MTYPE_BROADCAST_CONTEXT_MODIFICATION_RESPONSE      105
#define MTYPE_BROADCAST_CONTEXT_MODIFICATION_FAILURE       106
#define MTYPE_MULTICAST_GROUP_PAGING                       107
#define MTYPE_MULTICAST_CONTEXT_SETUP_REQUEST              108
#define MTYPE_MULTICAST_CONTEXT_SETUP_RESPONSE             109
#define MTYPE_MULTICAST_CONTEXT_SETUP_FAILURE              110
#define MTYPE_MULTICAST_CONTEXT_RELEASE_COMMAND            111
#define MTYPE_MULTICAST_CONTEXT_RELEASE_COMPLETE           112
#define MTYPE_MULTICAST_CONTEXT_RELEASE_REQUEST            113
#define MTYPE_MULTICAST_CONTEXT_MODIFICATION_REQUEST       114
#define MTYPE_MULTICAST_CONTEXT_MODIFICATION_RESPONSE      115
#define MTYPE_MULTICAST_CONTEXT_MODIFICATION_FAILURE       116
#define MTYPE_MULTICAST_DISTRIBUTION_SETUP_REQUEST         117
#define MTYPE_MULTICAST_DISTRIBUTION_SETUP_RESPONSE        118
#define MTYPE_MULTICAST_DISTRIBUTION_SETUP_FAILURE         119
#define MTYPE_MULTICAST_DISTRIBUTION_RELEASE_COMMAND       120
#define MTYPE_MULTICAST_DISTRIBUTION_RELEASE_COMPLETE      121
#define MTYPE_PDCP_MEASUREMENT_INITIATION_REQUEST          122
#define MTYPE_PDCP_MEASUREMENT_INITIATION_RESPONSE         123
#define MTYPE_PDCP_MEASUREMENT_INITIATION_FAILURE          124
#define MTYPE_PDCP_MEASUREMENT_REPORT                      125
#define MTYPE_PDCP_MEASUREMENT_TERMINATION_COMMAND         126
#define MTYPE_PDCP_MEASUREMENT_FAILURE_INDICATION          127
#define MTYPE_PRS_CONFIGURATION_REQUEST                    128
#define MTYPE_PRS_CONFIGURATION_RESPONSE                   129
#define MTYPE_PRS_CONFIGURATION_FAILURE                    130
#define MTYPE_MEASUREMENT_PRECONFIGURATION_REQUIRED        131
#define MTYPE_MEASUREMENT_PRECONFIGURATION_CONFIRM         132
#define MTYPE_MEASUREMENT_PRECONFIGURATION_REFUSE          133
#define MTYPE_MEASUREMENT_ACTIVATION                       134
#define MTYPE_QOE_INFORMATION_TRANSFER                     135
#define MTYPE_POS_SYSTEM_INFORMATION_DELIVERY_COMMAND      136
#define MTYPE_DU_CU_CELL_SWITCH_NOTIFICATION               137
#define MTYPE_CU_DU_CELL_SWITCH_NOTIFICATION               138
#define MTYPE_DU_CU_TA_INFORMATION_TRANSFER                139
#define MTYPE_CU_DU_TA_INFORMATION_TRANSFER                140
#define MTYPE_QOE_INFORMATION_TRANSFER_CONTROL             141
#define MTYPE_RACH_INDICATION                              142
#define MTYPE_TIMING_SYNCHRONISATION_STATUS_REQUEST        143
#define MTYPE_TIMING_SYNCHRONISATION_STATUS_RESPONSE       144
#define MTYPE_TIMING_SYNCHRONISATION_STATUS_FAILURE        145
#define MTYPE_TIMING_SYNCHRONISATION_STATUS_REPORT         146
#define MTYPE_MIAB_F1_SETUP_TRIGGERING                     147
#define MTYPE_MIAB_F1_SETUP_OUTCOME_NOTIFICATION           148
#define MTYPE_MULTICAST_CONTEXT_NOTIFICATION_INDICATION    149
#define MTYPE_MULTICAST_CONTEXT_NOTIFICATION_CONFIRM       150
#define MTYPE_MULTICAST_CONTEXT_NOTIFICATION_REFUSE        151
#define MTYPE_MULTICAST_COMMON_CONFIGURATION_REQUEST       152
#define MTYPE_MULTICAST_COMMON_CONFIGURATION_RESPONSE      153
#define MTYPE_MULTICAST_COMMON_CONFIGURATION_REFUSE        154
#define MTYPE_BROADCAST_TRANSPORT_RESOURCE_REQUEST         155
#define MTYPE_DU_CU_ACCESS_AND_MOBILITY_INDICATION         156
#define MTYPE_SRS_INFORMATION_RESERVATION_NOTIFICATION     157

static const value_string mtype_names[] = {
    { MTYPE_RESET,     "Reset" },
    { MTYPE_RESET_ACK, "ResetAcknowledge" },
    { MTYPE_F1_SETUP_REQUEST,  "F1SetupRequest" },
    { MTYPE_F1_SETUP_RESPONSE, "F1SetupResponse" },
    { MTYPE_F1_SETUP_FAILURE,  "F1SetupFailure" },
    { MTYPE_GNB_DU_CONFIGURATION_UPDATE,             "GNBDUConfigurationUpdate" },
    { MTYPE_GNB_DU_CONFIGURATION_UPDATE_ACKNOWLEDGE, "GNBDUConfigurationUpdateAcknowledge" },
    { MTYPE_GNB_DU_CONFIGURATION_UPDATE_FAILURE,     "GNBDUConfigurationUpdateFailure" },
    { MTYPE_GNB_CU_CONFIGURATION_UPDATE,             "GNBCUConfigurationUpdate" },
    { MTYPE_GNB_CU_CONFIGURATION_UPDATE_ACKNOWLEDGE, "GNBCUConfigurationUpdateAcknowledge" },
    { MTYPE_GNB_CU_CONFIGURATION_UPDATE_FAILURE,     "GNBCUConfigurationUpdateFailure" },
    { MTYPE_UE_CONTEXT_SETUP_REQUEST,    "UEContextSetupRequest" },
    { MTYPE_UE_CONTEXT_SETUP_RESPONSE,   "UEContextSetupResponse" },
    { MTYPE_UE_CONTEXT_SETUP_FAILURE,    "UEContextSetupFailure" },
    { MTYPE_UE_CONTEXT_RELEASE_COMMAND,      "UEContextReleaseCommand"},
    { MTYPE_UE_CONTEXT_RELEASE_COMPLETE,     "UEContextReleaseComplete"},
    { MTYPE_UE_CONTEXT_MODIFICATION_REQUEST,   "UEContextModificationRequest" },
    { MTYPE_UE_CONTEXT_MODIFICATION_RESPONSE,  "UEContextModificationResponse" },
    { MTYPE_UE_CONTEXT_MODIFICATION_FAILURE,   "UEContextModificationFailure" },
    { MTYPE_UE_CONTEXT_MODIFICATION_REQUIRED,  "UEContextModificationRequired" },
    { MTYPE_UE_CONTEXT_MODIFICATION_CONFIRM,   "UEContextModificationConfirm" },
    { MTYPE_UE_CONTEXT_MODIFICATION_REFUSE,   "UEContextModificationRefuse" },
    { MTYPE_WRITE_REPLACE_WARNING_REQUEST,  "WriteReplaceWarningRequest" },
    { MTYPE_WRITE_REPLACE_WARNING_RESPONSE, "WriteReplaceWarningResponse" },
    { MTYPE_PWS_CANCEL_REQUEST,   "PWSCancelRequest" },
    { MTYPE_PWS_CANCEL_RESPONSE,  "PWSCancelResponse" },
    { MTYPE_ERROR_INDICATION, "ErrorIndication" },
    { MTYPE_UE_CONTEXT_RELEASE_REQUEST, "UEContextReleaseRequest" },
    { MTYPE_INITIAL_UL_RRC_MESSAGE_TRANSFER, "InitialULRRCMessageTransfer" },
    { MTYPE_DL_RRC_MESSAGE_TRANSFER,  "DLRRCMessageTransfer" },
    { MTYPE_UL_RRC_MESSAGE_TRANSFER,  "ULRRCMessageTransfer" },
    { MTYPE_UE_INACTIVITY_NOTIFICATION, "UEInactivityNotification" },
    { MTYPE_GNB_DU_RESOURCE_COORDINATION_REQUEST,  "GNBDUResourceCoordinationRequest" },
    { MTYPE_GNB_DU_RESOURCE_COORDINATION_RESPONSE, "GNBDUResourceCoordinationResponse" },
    { MTYPE_PRIVATE_MESSAGE, "PrivateMessage" },
    { MTYPE_SYSTEM_INFORMATION_DELIVERY_COMMAND, "SystemInformationDeliveryCommand" },
    { MTYPE_PAGING, "Paging" },
    { MTYPE_NOTIFY, "Notify" },
    { MTYPE_NETWORK_ACCESS_RATE_REDUCTION, "NetworkAccessRateReduction" },
    { MTYPE_PWS_RESTART_INDICATION, "PWSRestartIndication" },
    { MTYPE_PWS_FAILURE_INDICATION, "PWSFailureIndication" },
    { MTYPE_GNB_DU_STATUS_INDICATION, "GNBDUStatusIndication" },
    { MTYPE_RRC_DELIVERY_REPORT, "RRCDeliveryReport" },
    { MTYPE_F1_REMOVAL_REQUEST,  "F1RemovalRequest" },
    { MTYPE_F1_REMOVAL_RESPONSE, "F1RemovalResponse" },
    { MTYPE_F1_REMOVAL_FAILURE,  "F1RemovalFailure" },
    { MTYPE_TRACE_START, "TraceStart" },
    { MTYPE_DEACTIVATE_TRACE, "DeactivateTrace" },
    { MTYPE_DU_CU_RADIO_INFORMATION_TRANSFER, "DUCURadioInformationTransfer" },
    { MTYPE_CU_DU_RADIO_INFORMATION_TRANSFER, "CUDURadioInformationTransfer" },
    { MTYPE_BAP_MAPPING_CONFIGURATION,             "BAPMappingConfiguration" },
    { MTYPE_BAP_MAPPING_CONFIGURATION_ACKNOWLEDGE, "BAPMappingConfigurationAcknowledge" },
    { MTYPE_BAP_MAPPING_CONFIGURATION_FAILURE,     "BAPMappingConfigurationFailure" },
    { MTYPE_GNB_DU_RESOURCE_CONFIGURATION,             "GNBDUResourceConfiguration" },
    { MTYPE_GNB_DU_RESOURCE_CONFIGURATION_ACKNOWLEDGE, "GNBDUResourceConfigurationAcknowledge" },
    { MTYPE_GNB_DU_RESOURCE_CONFIGURATION_FAILURE,     "GNBDUResourceConfigurationFailure" },
    { MTYPE_IAB_TNL_ADDRESS_REQUEST,  "IABTNLAddressRequest" },
    { MTYPE_IAB_TNL_ADDRESS_RESPONSE, "IABTNLAddressResponse" },
    { MTYPE_IAB_TNL_ADDRESS_FAILURE,  "IABTNLAddressFailure" },
    { MTYPE_IAB_UP_CONFIGURATION_UPDATE_REQUEST,  "IABUPConfigurationUpdateRequest" },
    { MTYPE_IAB_UP_CONFIGURATION_UPDATE_RESPONSE, "IABUPConfigurationUpdateResponse" },
    { MTYPE_IAB_UP_CONFIGURATION_UPDATE_FAILURE,  "IABUPConfigurationUpdateFailure" },
    { MTYPE_RESOURCE_STATUS_REQUEST,   "ResourceStatusRequest" },
    { MTYPE_RESOURCE_STATUS_RESPONSE,  "ResourceStatusResponse" },
    { MTYPE_RESOURCE_STATUS_FAILURE,   "ResourceStatusFailure" },
    { MTYPE_RESOURCE_STATUS_UPDATE,    "ResourceStatusUpdate" },
    { MTYPE_ACCESS_AND_MOBILITY_INDICATION, "AccessAndMobilityIndication" },
    { MTYPE_REFERENCE_TIME_INFORMATION_REPORTING_CONTROL, "ReferenceTimeInformationReportingControl" },
    { MTYPE_REFERENCE_TIME_INFORMATION_REPORT,            "ReferenceTimeInformationReport" },
    { MTYPE_ACCESS_SUCCESS, "AccessSuccess" },
    { MTYPE_CELL_TRAFFIC_TRACE, "CellTrafficTrace" },
    { MTYPE_POSITIONING_ASSISTANCE_INFORMATION_CONTROL,  "PositioningAssistanceInformationControl" },
    { MTYPE_POSITIONING_ASSISTANCE_INFORMATION_FEEDBACK, "PositioningAssistanceInformationFeedback" },
    { MTYPE_POSITIONING_MEASUREMENT_REQUEST,            "PositioningMeasurementRequest" },
    { MTYPE_POSITIONING_MEASUREMENT_RESPONSE,           "PositioningMeasurementResponse" },
    { MTYPE_POSITIONING_MEASUREMENT_FAILURE,            "PositioningMeasurementFailure" },
    { MTYPE_POSITIONING_MEASUREMENT_REPORT,             "PositioningMeasurementReport" },
    { MTYPE_POSITIONING_MEASUREMENT_ABORT,              "PositioningMeasurementAbort" },
    { MTYPE_POSITIONING_MEASUREMENT_FAILURE_INDICATION, "PositioningMeasurementFailureIndication" },
    { MTYPE_POSITIONING_MEASUREMENT_UPDATE,             "PositioningMeasurementUpdate" },
    { MTYPE_TRP_INFORMATION_REQUEST,  "TRPInformationRequest" },
    { MTYPE_TRP_INFORMATION_RESPONSE, "TRPInformationResponse" },
    { MTYPE_TRP_INFORMATION_FAILURE,  "TRPInformationFailure" },
    { MTYPE_POSITIONING_INFORMATION_REQUEST,  "PositioningInformationRequest" },
    { MTYPE_POSITIONING_INFORMATION_RESPONSE, "PositioningInformationResponse" },
    { MTYPE_POSITIONING_INFORMATION_FAILURE,  "PositioningInformationFailure" },
    { MTYPE_POSITIONING_ACTIVATION_REQUEST,   "PositioningActivationRequest" },
    { MTYPE_POSITIONING_ACTIVATION_RESPONSE,  "PositioningActivationResponse" },
    { MTYPE_POSITIONING_ACTIVATION_FAILURE,   "PositioningActivationFailure" },
    { MTYPE_POSITIONING_DEACTIVATION, "PositioningDeactivation" },
    { MTYPE_E_CID_MEASUREMENT_INITIATION_REQUEST,  "E-CIDMeasurementInitiationRequest" },
    { MTYPE_E_CID_MEASUREMENT_INITIATION_RESPONSE, "E-CIDMeasurementInitiationResponse" },
    { MTYPE_E_CID_MEASUREMENT_INITIATION_FAILURE,  "E-CIDMeasurementInitiationFailure" },
    { MTYPE_E_CID_MEASUREMENT_FAILURE_INDICATION,  "E-CIDMeasurementFailureIndication" },
    { MTYPE_E_CID_MEASUREMENT_REPORT,              "E-CIDMeasurementReport" },
    { MTYPE_E_CID_MEASUREMENT_TERMINATION_COMMAND, "E-CIDMeasurementTerminationCommand" },
    { MTYPE_POSITIONING_INFORMATION_UPDATE, "PositioningInformationUpdate" },
    { MTYPE_BROADCAST_CONTEXT_SETUP_REQUEST, "BroadcastContextSetupRequest" },
    { MTYPE_BROADCAST_CONTEXT_SETUP_RESPONSE, "BroadcastContextSetupResponse" },
    { MTYPE_BROADCAST_CONTEXT_SETUP_FAILURE, "BroadcastContextSetupFailure" },
    { MTYPE_BROADCAST_CONTEXT_RELEASE_COMMAND, "BroadcastContextReleaseCommand" },
    { MTYPE_BROADCAST_CONTEXT_RELEASE_COMPLETE, "BroadcastContextReleaseComplete" },
    { MTYPE_BROADCAST_CONTEXT_RELEASE_REQUEST, "BroadcastContextReleaseRequest" },
    { MTYPE_BROADCAST_CONTEXT_MODIFICATION_REQUEST, "BroadcastContextModificationRequest" },
    { MTYPE_BROADCAST_CONTEXT_MODIFICATION_RESPONSE, "BroadcastContextModificationResponse" },
    { MTYPE_BROADCAST_CONTEXT_MODIFICATION_FAILURE, "BroadcastContextModificationFailure" },
    { MTYPE_MULTICAST_GROUP_PAGING, "MulticastGroupPaging" },
    { MTYPE_MULTICAST_CONTEXT_SETUP_REQUEST, "MulticastContextSetupRequest" },
    { MTYPE_MULTICAST_CONTEXT_SETUP_RESPONSE, "MulticastContextSetupResponse" },
    { MTYPE_MULTICAST_CONTEXT_SETUP_FAILURE, "MulticastContextSetupFailure" },
    { MTYPE_MULTICAST_CONTEXT_RELEASE_COMMAND, "MulticastContextReleaseCommand" },
    { MTYPE_MULTICAST_CONTEXT_RELEASE_COMPLETE, "MulticastContextReleaseComplete" },
    { MTYPE_MULTICAST_CONTEXT_RELEASE_REQUEST, "MulticastContextReleaseRequest" },
    { MTYPE_MULTICAST_CONTEXT_MODIFICATION_REQUEST, "MulticastContextModificationRequest" },
    { MTYPE_MULTICAST_CONTEXT_MODIFICATION_RESPONSE, "MulticastContextModificationResponse" },
    { MTYPE_MULTICAST_CONTEXT_MODIFICATION_FAILURE, "MulticastContextModificationFailure" },
    { MTYPE_MULTICAST_DISTRIBUTION_SETUP_REQUEST, "MulticastDistributionSetupRequest" },
    { MTYPE_MULTICAST_DISTRIBUTION_SETUP_RESPONSE, "MulticastDistributionSetupResponse" },
    { MTYPE_MULTICAST_DISTRIBUTION_SETUP_FAILURE, "MulticastDistributionSetupFailure" },
    { MTYPE_MULTICAST_DISTRIBUTION_RELEASE_COMMAND, "MulticastDistributionReleaseCommand" },
    { MTYPE_MULTICAST_DISTRIBUTION_RELEASE_COMPLETE, "MulticastDistributionReleaseComplete" },
    { MTYPE_PDCP_MEASUREMENT_INITIATION_REQUEST, "PDCMeasurementInitiationRequest" },
    { MTYPE_PDCP_MEASUREMENT_INITIATION_RESPONSE, "PDCMeasurementInitiationResponse" },
    { MTYPE_PDCP_MEASUREMENT_INITIATION_FAILURE, "PDCMeasurementInitiationFailure" },
    { MTYPE_PDCP_MEASUREMENT_REPORT, "PDCMeasurementReport" },
    { MTYPE_PDCP_MEASUREMENT_TERMINATION_COMMAND, "PDCMeasurementTerminationCommand" },
    { MTYPE_PDCP_MEASUREMENT_FAILURE_INDICATION, "PDCMeasurementFailureIndication" },
    { MTYPE_PRS_CONFIGURATION_REQUEST, "PRSConfigurationRequest" },
    { MTYPE_PRS_CONFIGURATION_RESPONSE, "PRSConfigurationResponse" },
    { MTYPE_PRS_CONFIGURATION_FAILURE, "PRSConfigurationFailure" },
    { MTYPE_MEASUREMENT_PRECONFIGURATION_REQUIRED, "MeasurementPreconfigurationRequired" },
    { MTYPE_MEASUREMENT_PRECONFIGURATION_CONFIRM, "MeasurementPreconfigurationConfirm" },
    { MTYPE_MEASUREMENT_PRECONFIGURATION_REFUSE, "MeasurementPreconfigurationRefuse" },
    { MTYPE_MEASUREMENT_ACTIVATION, "MeasurementActivation" },
    { MTYPE_QOE_INFORMATION_TRANSFER, "QoEInformationTransfer" },
    { MTYPE_POS_SYSTEM_INFORMATION_DELIVERY_COMMAND, "PosSystemInformationDeliveryCommand" },
    { MTYPE_DU_CU_CELL_SWITCH_NOTIFICATION, "DUCUCellSwitchNotification" },
    { MTYPE_CU_DU_CELL_SWITCH_NOTIFICATION, "CUDUCellSwitchNotification" },
    { MTYPE_DU_CU_TA_INFORMATION_TRANSFER, "DUCUTAInformationTransfer" },
    { MTYPE_CU_DU_TA_INFORMATION_TRANSFER, "CUDUTAInformationTransfer" },
    { MTYPE_QOE_INFORMATION_TRANSFER_CONTROL, "QoEInformationTransferControl" },
    { MTYPE_RACH_INDICATION, "RachIndication" },
    { MTYPE_TIMING_SYNCHRONISATION_STATUS_REQUEST, "TimingSynchronisationStatusRequest" },
    { MTYPE_TIMING_SYNCHRONISATION_STATUS_RESPONSE, "TimingSynchronisationStatusResponse" },
    { MTYPE_TIMING_SYNCHRONISATION_STATUS_FAILURE, "TimingSynchronisationStatusFailure" },
    { MTYPE_TIMING_SYNCHRONISATION_STATUS_REPORT, "TimingSynchronisationStatusReport" },
    { MTYPE_MIAB_F1_SETUP_TRIGGERING, "MIABF1SetupTriggering" },
    { MTYPE_MIAB_F1_SETUP_OUTCOME_NOTIFICATION, "MIABF1SetupOutcomeNotification" },
    { MTYPE_MULTICAST_CONTEXT_NOTIFICATION_INDICATION, "MulticastContextNotificationIndication" },
    { MTYPE_MULTICAST_CONTEXT_NOTIFICATION_CONFIRM, "MulticastContextNotificationConfirm" },
    { MTYPE_MULTICAST_CONTEXT_NOTIFICATION_REFUSE, "MulticastContextNotificationRefuse" },
    { MTYPE_MULTICAST_COMMON_CONFIGURATION_REQUEST, "MulticastCommonConfigurationRequest" },
    { MTYPE_MULTICAST_COMMON_CONFIGURATION_RESPONSE, "MulticastCommonConfigurationResponse" },
    { MTYPE_MULTICAST_COMMON_CONFIGURATION_REFUSE, "MulticastCommonConfigurationRefuse" },
    { MTYPE_BROADCAST_TRANSPORT_RESOURCE_REQUEST, "BroadcastTransportResourceRequest" },
    { MTYPE_DU_CU_ACCESS_AND_MOBILITY_INDICATION, "DUCUAccessAndMobilityIndication" },
    { MTYPE_SRS_INFORMATION_RESERVATION_NOTIFICATION, "SRSInformationReservationNotification" },
    { 0,  NULL }
};
static value_string_ext mtype_names_ext = VALUE_STRING_EXT_INIT(mtype_names);


typedef struct {
  uint32_t message_type;
  uint32_t procedure_code;
  uint32_t protocol_ie_id;
  uint32_t protocol_extension_id;
  const char *obj_id;
  uint32_t sib_type;
  uint32_t srb_id;
  uint32_t gdb_cu_ue_f1ap_id;
  e212_number_type_t number_type;
  struct f1ap_tap_t  *stats_tap;
} f1ap_private_data_t;

typedef struct {
  uint32_t message_type;
  uint32_t ProcedureCode;
  uint32_t ProtocolIE_ID;
  uint32_t ProtocolExtensionID;
} f1ap_ctx_t;

/* Global variables */
static dissector_handle_t f1ap_handle;
static dissector_handle_t nr_rrc_ul_ccch_handle;
static dissector_handle_t nr_rrc_dl_ccch_handle;
static dissector_handle_t nr_rrc_ul_dcch_handle;
static dissector_handle_t nr_pdcp_handle;
static dissector_handle_t lte_rrc_conn_reconf_handle;

/* Dissector tables */
static dissector_table_t f1ap_ies_dissector_table;
static dissector_table_t f1ap_extension_dissector_table;
static dissector_table_t f1ap_proc_imsg_dissector_table;
static dissector_table_t f1ap_proc_sout_dissector_table;
static dissector_table_t f1ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


static proto_tree *top_tree;

static void set_message_label(asn1_ctx_t *actx, int type)
{
  const char *label = val_to_str_ext_const(type, &mtype_names_ext, "Unknown");
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, label);
  /* N.B. would like to be able to use actx->subTree.top_tree, but not easy to set.. */
  proto_item_append_text(top_tree, " (%s)", label);
}



static void
f1ap_MaxPacketLossRate_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
f1ap_PacketDelayBudget_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static void
f1ap_ExtendedPacketDelayBudget_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fms (%u)", (float)v/100, v);
}

static void
f1ap_N6Jitter_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%d)", (float)v/2, (int32_t)v);
}

static f1ap_private_data_t*
f1ap_get_private_data(packet_info *pinfo)
{
  f1ap_private_data_t *f1ap_data = (f1ap_private_data_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_f1ap, 0);
  if (!f1ap_data) {
    f1ap_data = wmem_new0(wmem_file_scope(), f1ap_private_data_t);
    f1ap_data->srb_id = -1;
    f1ap_data->gdb_cu_ue_f1ap_id = 1;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_f1ap, 0, f1ap_data);
  }
  return f1ap_data;
}

static void
add_nr_pdcp_meta_data(packet_info *pinfo, uint8_t direction, uint8_t srb_id)
{
  pdcp_nr_info *p_pdcp_nr_info;

  /* Only need to set info once per session. */
  if (get_pdcp_nr_proto_data(pinfo)) {
      return;
  }

  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);
  p_pdcp_nr_info->direction = direction;
  p_pdcp_nr_info->ueid = f1ap_data->gdb_cu_ue_f1ap_id;
  p_pdcp_nr_info->bearerType = Bearer_DCCH;
  p_pdcp_nr_info->bearerId = srb_id;
  p_pdcp_nr_info->plane = NR_SIGNALING_PLANE;
  p_pdcp_nr_info->seqnum_length = PDCP_NR_SN_LENGTH_12_BITS;
  p_pdcp_nr_info->maci_present = true;
  set_pdcp_nr_proto_data(pinfo, p_pdcp_nr_info);
}

#include "packet-f1ap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  f1ap_ctx_t f1ap_ctx;
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  f1ap_ctx.message_type        = f1ap_data->message_type;
  f1ap_ctx.ProcedureCode       = f1ap_data->procedure_code;
  f1ap_ctx.ProtocolIE_ID       = f1ap_data->protocol_ie_id;
  f1ap_ctx.ProtocolExtensionID = f1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(f1ap_ies_dissector_table, f1ap_data->protocol_ie_id, tvb, pinfo, tree, false, &f1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  f1ap_ctx_t f1ap_ctx;
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  f1ap_ctx.message_type        = f1ap_data->message_type;
  f1ap_ctx.ProcedureCode       = f1ap_data->procedure_code;
  f1ap_ctx.ProtocolIE_ID       = f1ap_data->protocol_ie_id;
  f1ap_ctx.ProtocolExtensionID = f1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(f1ap_extension_dissector_table, f1ap_data->protocol_extension_id, tvb, pinfo, tree, false, &f1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_imsg_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, false, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_sout_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, false, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_uout_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, false, data)) ? tvb_captured_length(tvb) : 0;
}


static void
f1ap_stats_tree_init(stats_tree *st)
{
    st_node_packets = stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, true);
    st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
}

static tap_packet_status
f1ap_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
                       epan_dissect_t* edt _U_ , const void* p, tap_flags_t flags _U_)
{
    const struct f1ap_tap_t *pi = (const struct f1ap_tap_t *) p;

    tick_stat_node(st, st_str_packets, 0, false);
    stats_tree_tick_pivot(st, st_node_packet_types,
                          val_to_str_ext(pi->f1ap_mtype, &mtype_names_ext,
                                         "Unknown packet type (%d)"));
    return TAP_PACKET_REDRAW;
}

static void set_stats_message_type(packet_info *pinfo, int type)
{
    f1ap_private_data_t* priv_data = f1ap_get_private_data(pinfo);
    priv_data->stats_tap->f1ap_mtype = type;
}

static int
dissect_f1ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *f1ap_item = NULL;
  proto_tree *f1ap_tree = NULL;

  struct f1ap_tap_t *f1ap_info;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "F1AP");
  col_clear(pinfo->cinfo, COL_INFO);

  f1ap_info = wmem_new(pinfo->pool, struct f1ap_tap_t);
  f1ap_info->f1ap_mtype   = 0;  /* unknown/invalid */

  /* create the f1ap protocol tree */
  f1ap_item = proto_tree_add_item(tree, proto_f1ap, tvb, 0, -1, ENC_NA);
  f1ap_tree = proto_item_add_subtree(f1ap_item, ett_f1ap);

  /* Store top-level tree */
  top_tree = f1ap_tree;

  /* Add stats tap to private struct */
  f1ap_private_data_t *priv_data = f1ap_get_private_data(pinfo);
  priv_data->stats_tap = f1ap_info;


  dissect_F1AP_PDU_PDU(tvb, pinfo, f1ap_tree, NULL);

  tap_queue_packet(f1ap_tap, pinfo, f1ap_info);
  return tvb_captured_length(tvb);
}

void proto_register_f1ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_f1ap_transportLayerAddressIPv4,
      { "IPv4 transportLayerAddress", "f1ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_transportLayerAddressIPv6,
      { "IPv6 transportLayerAddress", "f1ap.transportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_IABTNLAddressIPv4,
      { "IPv4 IABTNLAddress", "f1ap.IABTNLAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_IABTNLAddressIPv6,
      { "IPv6 IABTNLAddress", "f1ap.IABTNLAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_IABTNLAddressIPv6Prefix,
      { "IPv6 Prefix IABTNLAddress", "f1ap.IABTNLAddressIPv6Prefix",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_NG_C,
      { "NG-C", "f1ap.interfacesToTrace.NG_C",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x80,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_Xn_C,
      { "Xn-C", "f1ap.interfacesToTrace.Xn_C",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x40,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_Uu,
      { "Uu", "f1ap.interfacesToTrace.Uu",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x20,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_F1_C,
      { "F1-C", "f1ap.interfacesToTrace.F1_C",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x10,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_E1,
      { "E1", "f1ap.interfacesToTrace.E1",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x08,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_Reserved,
      { "Reserved", "f1ap.interfacesToTrace.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_Reserved1,
      { "Reserved", "f1ap.MeasurementsToActivate.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x80,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_M2,
      { "M2", "f1ap.MeasurementsToActivate.M2",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x40,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_Reserved2,
      { "Reserved", "f1ap.MeasurementsToActivate.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x30,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_M5,
      { "M5", "f1ap.MeasurementsToActivate.M5",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x08,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_Reserved3,
      { "Reserved", "f1ap.MeasurementsToActivate.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x04,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_M6,
      { "M6", "f1ap.MeasurementsToActivate.M6",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x02,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_M7,
      { "M7", "f1ap.MeasurementsToActivate.M7",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x01,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_PRBPeriodic,
      { "PRBPeriodic", "f1ap.ReportCharacteristics.PRBPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x80000000,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_TNLCapacityIndPeriodic,
      { "TNLCapacityIndPeriodic", "f1ap.ReportCharacteristics.TNLCapacityIndPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x40000000,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_CompositeAvailableCapacityPeriodic,
      { "CompositeAvailableCapacityPeriodic", "f1ap.ReportCharacteristics.CompositeAvailableCapacityPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x20000000,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_HWLoadIndPeriodic,
      { "HWLoadIndPeriodic", "f1ap.ReportCharacteristics.HWLoadIndPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x10000000,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_NumberOfActiveUEs,
      { "NumberOfActiveUEs", "f1ap.ReportCharacteristics.NumberOfActiveUEs",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x08000000,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_Reserved,
      { "Reserved", "f1ap.ReportCharacteristics.Reserved",
        FT_UINT32, BASE_HEX, NULL, 0x07ffffff,
        NULL, HFILL }},
#include "packet-f1ap-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_f1ap,
    &ett_f1ap_ResourceCoordinationTransferContainer,
    &ett_f1ap_PLMN_Identity,
    &ett_f1ap_MIB_message,
    &ett_f1ap_SIB1_message,
    &ett_f1ap_CG_ConfigInfo,
    &ett_f1ap_CellGroupConfig,
    &ett_f1ap_TransportLayerAddress,
    &ett_f1ap_UE_CapabilityRAT_ContainerList,
    &ett_f1ap_measurementTimingConfiguration,
    &ett_f1ap_DUtoCURRCContainer,
    &ett_f1ap_requestedP_MaxFR1,
    &ett_f1ap_HandoverPreparationInformation,
    &ett_f1ap_MeasConfig,
    &ett_f1ap_MeasGapConfig,
    &ett_f1ap_MeasGapSharingConfig,
    &ett_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container,
    &ett_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container,
    &ett_f1ap_ProtectedEUTRAResourceIndication,
    &ett_f1ap_RRCContainer,
    &ett_f1ap_RRCContainer_RRCSetupComplete,
    &ett_f1ap_sIBmessage,
    &ett_f1ap_UplinkTxDirectCurrentListInformation,
    &ett_f1ap_DRX_Config,
    &ett_f1ap_Ph_InfoSCG,
    &ett_f1ap_RequestedBandCombinationIndex,
    &ett_f1ap_RequestedFeatureSetEntryIndex,
    &ett_f1ap_RequestedP_MaxFR2,
    &ett_f1ap_UEAssistanceInformation,
    &ett_f1ap_CG_Config,
    &ett_f1ap_Ph_InfoMCG,
    &ett_f1ap_BurstArrivalTime,
    &ett_f1ap_cSI_RS_Configuration,
    &ett_f1ap_sR_Configuration,
    &ett_f1ap_pDCCH_ConfigSIB1,
    &ett_f1ap_sCS_Common,
    &ett_f1ap_IABTNLAddressIPv4Address,
    &ett_f1ap_IABTNLAddressIPv6Address,
    &ett_f1ap_IABTNLAddressIPv6Prefix,
    &ett_f1ap_InterfacesToTrace,
    &ett_f1ap_MeasurementsToActivate,
    &ett_f1ap_NRUERLFReportContainer,
    &ett_f1ap_RACH_Config_Common,
    &ett_f1ap_RACH_Config_Common_IAB,
    &ett_f1ap_RAReportContainer,
    &ett_f1ap_ReferenceTime,
    &ett_f1ap_ReportCharacteristics,
    &ett_f1ap_SIB10_message,
    &ett_f1ap_SIB12_message,
    &ett_f1ap_SIB13_message,
    &ett_f1ap_SIB14_message,
    &ett_f1ap_SIB15_message,
    &ett_f1ap_SIB17_message,
    &ett_f1ap_SIB20_message,
    &ett_f1ap_SIB22_message,
    &ett_f1ap_SIB23_message,
    &ett_f1ap_SIB24_message,
    &ett_f1ap_SL_PHY_MAC_RLC_Config,
    &ett_f1ap_SL_PHY_MAC_RLC_ConfigExt,
    &ett_f1ap_SL_RLC_ChannelToAddModList,
    &ett_f1ap_SL_ConfigDedicatedEUTRA_Info,
    &ett_f1ap_TDD_UL_DLConfigCommonNR,
    &ett_f1ap_UEAssistanceInformationEUTRA,
    &ett_f1ap_PosAssistance_Information,
    &ett_f1ap_LocationMeasurementInformation,
    &ett_f1ap_MUSIM_GapConfig,
    &ett_f1ap_SDT_MAC_PHY_CG_Config,
    &ett_f1ap_SDTRLCBearerConfiguration,
    &ett_f1ap_MBSInterestIndication,
    &ett_f1ap_NeedForGapsInfoNR,
    &ett_f1ap_NeedForGapNCSGInfoNR,
    &ett_f1ap_NeedForGapNCSGInfoEUTRA,
    &ett_f1ap_MBS_Broadcast_NeighbourCellList,
    &ett_f1ap_mRB_PDCP_Config_Broadcast,
    &ett_f1ap_posMeasGapPreConfigToAddModList,
    &ett_f1ap_posMeasGapPreConfigToReleaseList,
    &ett_f1ap_SidelinkConfigurationContainer,
    &ett_f1ap_SRSPosRRCInactiveConfig,
    &ett_f1ap_successfulHOReportContainer,
    &ett_f1ap_UL_GapFR2_Config,
    &ett_f1ap_ConfigRestrictInfoDAPS,
    &ett_f1ap_UplinkTxDirectCurrentTwoCarrierListInfo,
    &ett_f1ap_Ncd_SSB_RedCapInitialBWP_SDT,
    &ett_f1ap_JointorDLTCIStateID,
    &ett_f1ap_ULTCIStateID,
    &ett_f1ap_ReferenceConfigurationInformation,
    &ett_f1ap_LTMCFRAResourceConfig,
    &ett_f1ap_location_Information,
    &ett_f1ap_velocity_Information,
    &ett_f1ap_successfulPSCellChangeReportContainer,
    &ett_f1ap_cSIResourceConfigToAddModList,
    &ett_f1ap_cSIResourceConfigToReleaseList,
    &ett_f1ap_mbs_NeighbourCellList,
    &ett_f1ap_mtch_NeighbourCellprovided,
    &ett_f1ap_thresholdMBSList,
    &ett_f1ap_mBSMulticastConfiguration,
    &ett_f1ap_MusimCandidateBandList,
    &ett_f1ap_NeedForInterruptionInfoNR,
    &ett_f1ap_RACHConfiguration,
    &ett_f1ap_SRSPosRRCInactiveValidityAreaConfig,
    &ett_f1ap_TCIStatesConfigurationsList,
#include "packet-f1ap-ettarr.c"
  };

  /* Register protocol */
  proto_f1ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_f1ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  f1ap_handle = register_dissector("f1ap", dissect_f1ap, proto_f1ap);

  /* Register dissector tables */
  f1ap_ies_dissector_table = register_dissector_table("f1ap.ies", "F1AP-PROTOCOL-IES", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_extension_dissector_table = register_dissector_table("f1ap.extension", "F1AP-PROTOCOL-EXTENSION", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_imsg_dissector_table = register_dissector_table("f1ap.proc.imsg", "F1AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_sout_dissector_table = register_dissector_table("f1ap.proc.sout", "F1AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_uout_dissector_table = register_dissector_table("f1ap.proc.uout", "F1AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_f1ap, FT_UINT32, BASE_DEC);

  f1ap_tap = register_tap("f1ap");
}

void
proto_reg_handoff_f1ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_F1AP, f1ap_handle);
  dissector_add_uint("sctp.ppi", F1AP_PROTOCOL_ID, f1ap_handle);
  nr_rrc_ul_ccch_handle = find_dissector_add_dependency("nr-rrc.ul.ccch", proto_f1ap);
  nr_rrc_dl_ccch_handle = find_dissector_add_dependency("nr-rrc.dl.ccch", proto_f1ap);
  nr_rrc_ul_dcch_handle = find_dissector_add_dependency("nr-rrc.ul.dcch", proto_f1ap);
  nr_pdcp_handle = find_dissector_add_dependency("pdcp-nr", proto_f1ap);
  lte_rrc_conn_reconf_handle = find_dissector_add_dependency("lte-rrc.rrc_conn_reconf", proto_f1ap);

  stats_tree_register("f1ap", "f1ap", "F1AP", 0,
                       f1ap_stats_tree_packet, f1ap_stats_tree_init, NULL);

#include "packet-f1ap-dis-tab.c"
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
