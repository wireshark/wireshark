/* packet-f1ap.c
 * Routines for E-UTRAN F1 Application Protocol (F1AP) packet dissection
 * Copyright 2018-2022, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 38.473 V16.9.0 (2022-04)
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

#define PNAME  "F1 Application Protocol"
#define PSNAME "F1AP"
#define PFNAME "f1ap"

#define SCTP_PORT_F1AP 38472

void proto_register_f1ap(void);
void proto_reg_handoff_f1ap(void);

#include "packet-f1ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_f1ap = -1;

static int hf_f1ap_transportLayerAddressIPv4 = -1;
static int hf_f1ap_transportLayerAddressIPv6 = -1;
static int hf_f1ap_IABTNLAddressIPv4 = -1;
static int hf_f1ap_IABTNLAddressIPv6 = -1;
static int hf_f1ap_IABTNLAddressIPv6Prefix = -1;
static int hf_f1ap_interfacesToTrace_NG_C = -1;
static int hf_f1ap_interfacesToTrace_Xn_C = -1;
static int hf_f1ap_interfacesToTrace_Uu = -1;
static int hf_f1ap_interfacesToTrace_F1_C = -1;
static int hf_f1ap_interfacesToTrace_E1 = -1;
static int hf_f1ap_interfacesToTrace_Reserved = -1;
static int hf_f1ap_MeasurementsToActivate_Reserved1 = -1;
static int hf_f1ap_MeasurementsToActivate_M2 = -1;
static int hf_f1ap_MeasurementsToActivate_Reserved2 = -1;
static int hf_f1ap_MeasurementsToActivate_M5 = -1;
static int hf_f1ap_MeasurementsToActivate_Reserved3 = -1;
static int hf_f1ap_MeasurementsToActivate_M6 = -1;
static int hf_f1ap_MeasurementsToActivate_M7 = -1;
static int hf_f1ap_ReportCharacteristics_PRBPeriodic = -1;
static int hf_f1ap_ReportCharacteristics_TNLCapacityIndPeriodic = -1;
static int hf_f1ap_ReportCharacteristics_CompositeAvailableCapacityPeriodic = -1;
static int hf_f1ap_ReportCharacteristics_HWLoadIndPeriodic = -1;
static int hf_f1ap_ReportCharacteristics_NumberOfActiveUEs = -1;
static int hf_f1ap_ReportCharacteristics_Reserved = -1;
#include "packet-f1ap-hf.c"

/* Initialize the subtree pointers */
static gint ett_f1ap = -1;
static gint ett_f1ap_ResourceCoordinationTransferContainer = -1;
static gint ett_f1ap_PLMN_Identity = -1;
static gint ett_f1ap_MIB_message = -1;
static gint ett_f1ap_SIB1_message = -1;
static gint ett_f1ap_CG_ConfigInfo = -1;
static gint ett_f1ap_CellGroupConfig = -1;
static gint ett_f1ap_TransportLayerAddress = -1;
static gint ett_f1ap_UE_CapabilityRAT_ContainerList = -1;
static gint ett_f1ap_measurementTimingConfiguration = -1;
static gint ett_f1ap_DUtoCURRCContainer = -1;
static gint ett_f1ap_requestedP_MaxFR1 = -1;
static gint ett_f1ap_HandoverPreparationInformation = -1;
static gint ett_f1ap_MeasConfig = -1;
static gint ett_f1ap_MeasGapConfig = -1;
static gint ett_f1ap_MeasGapSharingConfig = -1;
static gint ett_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container = -1;
static gint ett_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container = -1;
static gint ett_f1ap_ProtectedEUTRAResourceIndication = -1;
static gint ett_f1ap_RRCContainer = -1;
static gint ett_f1ap_RRCContainer_RRCSetupComplete = -1;
static gint ett_f1ap_sIBmessage = -1;
static gint ett_f1ap_UplinkTxDirectCurrentListInformation = -1;
static gint ett_f1ap_DRX_Config = -1;
static gint ett_f1ap_Ph_InfoSCG = -1;
static gint ett_f1ap_RequestedBandCombinationIndex = -1;
static gint ett_f1ap_RequestedFeatureSetEntryIndex = -1;
static gint ett_f1ap_RequestedP_MaxFR2 = -1;
static gint ett_f1ap_UEAssistanceInformation = -1;
static gint ett_f1ap_CG_Config = -1;
static gint ett_f1ap_Ph_InfoMCG = -1;
static gint ett_f1ap_BurstArrivalTime = -1;
static gint ett_f1ap_cSI_RS_Configuration = -1;
static gint ett_f1ap_sR_Configuration = -1;
static gint ett_f1ap_pDCCH_ConfigSIB1 = -1;
static gint ett_f1ap_sCS_Common = -1;
static gint ett_f1ap_IABTNLAddressIPv4Address = -1;
static gint ett_f1ap_IABTNLAddressIPv6Address = -1;
static gint ett_f1ap_IABTNLAddressIPv6Prefix = -1;
static gint ett_f1ap_InterfacesToTrace = -1;
static gint ett_f1ap_MeasurementsToActivate = -1;
static gint ett_f1ap_NRUERLFReportContainer = -1;
static gint ett_f1ap_RACH_Config_Common = -1;
static gint ett_f1ap_RACH_Config_Common_IAB = -1;
static gint ett_f1ap_RACHReportContainer = -1;
static gint ett_f1ap_ReferenceTime = -1;
static gint ett_f1ap_ReportCharacteristics = -1;
static gint ett_f1ap_SIB10_message = -1;
static gint ett_f1ap_SIB12_message = -1;
static gint ett_f1ap_SIB13_message = -1;
static gint ett_f1ap_SIB14_message = -1;
static gint ett_f1ap_SL_PHY_MAC_RLC_Config = -1;
static gint ett_f1ap_SL_ConfigDedicatedEUTRA_Info = -1;
static gint ett_f1ap_TDD_UL_DLConfigCommonNR = -1;
static gint ett_f1ap_UEAssistanceInformationEUTRA = -1;
static gint ett_f1ap_PosAssistance_Information = -1;
static gint ett_f1ap_LocationMeasurementInformation = -1;
#include "packet-f1ap-ett.c"

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

/* F1AP stats - Tap interface */

static void set_stats_message_type(packet_info *pinfo, int type);

static const guint8 *st_str_packets        = "Total Packets";
static const guint8 *st_str_packet_types   = "F1AP Packet Types";

static int st_node_packets = -1;
static int st_node_packet_types = -1;
static int f1ap_tap = -1;

struct f1ap_tap_t {
    gint f1ap_mtype;
};

#define MTYPE_RESET                                       1
#define MTYPE_RESET_ACK                                   2
#define MTYPE_F1_SETUP_REQUEST                            3
#define MTYPE_F1_SETUP_RESPONSE                           4
#define MTYPE_F1_SETUP_FAILURE                            5
#define MTYPE_GNB_DU_CONFIGURATION_UPDATE                 6
#define MTYPE_GNB_DU_CONFIGURATION_UPDATE_ACKNOWLEDGE     7
#define MTYPE_GNB_DU_CONFIGURATION_UPDATE_FAILURE         8
#define MTYPE_GNB_CU_CONFIGURATION_UPDATE                 9
#define MTYPE_GNB_CU_CONFIGURATION_UPDATE_ACKNOWLEDGE     10
#define MTYPE_GNB_CU_CONFIGURATION_UPDATE_FAILURE         11
#define MTYPE_UE_CONTEXT_SETUP_REQUEST                    12
#define MTYPE_UE_CONTEXT_SETUP_RESPONSE                   13
#define MTYPE_UE_CONTEXT_SETUP_FAILURE                    14
#define MTYPE_UE_CONTEXT_RELEASE_COMMAND                  15
#define MTYPE_UE_CONTEXT_RELEASE_COMPLETE                 16
#define MTYPE_UE_CONTEXT_MODIFICATION_REQUEST             17
#define MTYPE_UE_CONTEXT_MODIFICATION_RESPONSE            18
#define MTYPE_UE_CONTEXT_MODIFICATION_FAILURE             19
#define MTYPE_UE_CONTEXT_MODIFICATION_REQUIRED            20
#define MTYPE_UE_CONTEXT_MODIFICATION_CONFIRM             21
#define MTYPE_UE_CONTEXT_MODIFICATION_REFUSE              22
#define MTYPE_WRITE_REPLACE_WARNING_REQUEST               23
#define MTYPE_WRITE_REPLACE_WARNING_RESPONSE              24
#define MTYPE_PWS_CANCEL_REQUEST                          25
#define MTYPE_PWS_CANCEL_RESPONSE                         25
#define MTYPE_ERROR_INDICATION                            26
#define MTYPE_UE_CONTEXT_RELEASE_REQUEST                  27
#define MTYPE_INITIAL_UL_RRC_MESSAGE_TRANSFER             28
#define MTYPE_DL_RRC_MESSAGE_TRANSFER                     29
#define MTYPE_UL_RRC_MESSAGE_TRANSFER                     30
#define MTYPE_UE_INACTIVITY_NOTIFICATION                  31
#define MTYPE_GNB_DU_RESOURCE_COORDINATION_REQUEST        32
#define MTYPE_GNB_DU_RESOURCE_COORDINATION_RESPONSE       33
#define MTYPE_PRIVATE_MESSAGE                             34
#define MTYPE_SYSTEM_INFORMATION_DELIVERY_COMMAND         35
#define MTYPE_PAGING                                      36
#define MTYPE_NOTIFY                                      37
#define MTYPE_NETWORK_ACCESS_RATE_REDUCTION               38
#define MTYPE_PWS_RESTART_INDICATION                      39
#define MTYPE_PWS_FAILURE_INDICATION                      40
#define MTYPE_GNB_DU_STATUS_INDICATION                    41
#define MTYPE_RRC_DELIVERY_REPORT                         42
#define MTYPE_F1_REMOVAL_REQUEST                          43
#define MTYPE_F1_REMOVAL_RESPONSE                         44
#define MTYPE_F1_REMOVAL_FAILURE                          45
#define MTYPE_TRACE_START                                 46
#define MTYPE_DEACTIVATE_TRACE                            47
#define MTYPE_DU_CU_RADIO_INFORMATION_TRANSFER            48
#define MTYPE_CU_DU_RADIO_INFORMATION_TRANSFER            49
#define MTYPE_BAP_MAPPING_CONFIGURATION                   50
#define MTYPE_BAP_MAPPING_CONFIGURATION_ACKNOWLEDGE       51
#define MTYPE_BAP_MAPPING_CONFIGURATION_FAILURE           52
#define MTYPE_GNB_DU_RESOURCE_CONFIGURATION               53
#define MTYPE_GNB_DU_RESOURCE_CONFIGURATION_ACKNOWLEDGE   54
#define MTYPE_GNB_DU_RESOURCE_CONFIGURATION_FAILURE       55
#define MTYPE_IAB_TNL_ADDRESS_REQUEST                     56
#define MTYPE_IAB_TNL_ADDRESS_RESPONSE                    57
#define MTYPE_IAB_TNL_ADDRESS_FAILURE                     58
#define MTYPE_IAB_UP_CONFIGURATION_UPDATE_REQUEST         59
#define MTYPE_IAB_UP_CONFIGURATION_UPDATE_RESPONSE        60
#define MTYPE_IAB_UP_CONFIGURATION_UPDATE_FAILURE         61
#define MTYPE_RESOURCE_STATUS_REQUEST                     62
#define MTYPE_RESOURCE_STATUS_RESPONSE                    63
#define MTYPE_RESOURCE_STATUS_FAILURE                     64
#define MTYPE_RESOURCE_STATUS_UPDATE                      65
#define MTYPE_ACCESS_AND_MOBILITY_INDICATION              66
#define MTYPE_REFERENCE_TIME_INFORMATION_REPORTING_CONTROL 67
#define MTYPE_REFERENCE_TIME_INFORMATION_REPORT           68
#define MTYPE_ACCESS_SUCCESS                              69
#define MTYPE_CELL_TRAFFIC_TRACE                          70
#define MTYPE_POSITIONING_ASSISTANCE_INFORMATION_CONTROL  71
#define MTYPE_POSITIONING_ASSISTANCE_INFORMATION_FEEDBACK 72
#define MTYPE_POSITIONING_MEASUREMENT_REQUEST             73
#define MTYPE_POSITIONING_MEASUREMENT_RESPONSE            74
#define MTYPE_POSITIONING_MEASUREMENT_FAILURE             75
#define MTYPE_POSITIONING_MEASUREMENT_REPORT              76
#define MTYPE_POSITIONING_MEASUREMENT_ABORT               77
#define MTYPE_POSITIONING_MEASUREMENT_FAILURE_INDICATION  78
#define MTYPE_POSITIONING_MEASUREMENT_UPDATE              79
#define MTYPE_TRP_INFORMATION_REQUEST                     80
#define MTYPE_TRP_INFORMATION_RESPONSE                    81
#define MTYPE_TRP_INFORMATION_FAILURE                     82
#define MTYPE_POSITIONING_INFORMATION_REQUEST             83
#define MTYPE_POSITIONING_INFORMATION_RESPONSE            84
#define MTYPE_POSITIONING_INFORMATION_FAILURE             85
#define MTYPE_POSITIONING_ACTIVATION_REQUEST              86
#define MTYPE_POSITIONING_ACTIVATION_RESPONSE             87
#define MTYPE_POSITIONING_ACTIVATION_FAILURE              88
#define MTYPE_POSITIONING_DEACTIVATION                    89
#define MTYPE_E_CID_MEASUREMENT_INITIATION_REQUEST        90
#define MTYPE_E_CID_MEASUREMENT_INITIATION_RESPONSE       91
#define MTYPE_E_CID_MEASUREMENT_INITIATION_FAILURE        92
#define MTYPE_E_CID_MEASUREMENT_FAILURE_INDICATION        93
#define MTYPE_E_CID_MEASUREMENT_REPORT                    94
#define MTYPE_E_CID_MEASUREMENT_TERMINATION_COMMAND       95
#define MTYPE_POSITIONING_INFORMATION_UPDATE              96



/* Value Strings. TODO: ext? */
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
    { 0,  NULL }
};



typedef struct {
  guint32 message_type;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  const char *obj_id;
  guint32 sib_type;
  guint32 srb_id;
  e212_number_type_t number_type;
  struct f1ap_tap_t  *stats_tap;
} f1ap_private_data_t;

typedef struct {
  guint32 message_type;
  guint32 ProcedureCode;
  guint32 ProtocolIE_ID;
  guint32 ProtocolExtensionID;
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

static const true_false_string f1ap_tfs_interfacesToTrace = {
  "Should be traced",
  "Should not be traced"
};


static proto_tree *top_tree = NULL;

static void set_message_label(asn1_ctx_t *actx, int type)
{
  const char *label = val_to_str_const(type, mtype_names, "Unknown");
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, label);
  /* N.B. would like to be able to use actx->subTree.top_tree, but not easy to set.. */
  proto_item_append_text(top_tree, " (%s)", label);
}



static void
f1ap_MaxPacketLossRate_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
f1ap_PacketDelayBudget_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static void
f1ap_ExtendedPacketDelayBudget_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fms (%u)", (float)v/100, v);
}

static f1ap_private_data_t*
f1ap_get_private_data(packet_info *pinfo)
{
  f1ap_private_data_t *f1ap_data = (f1ap_private_data_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_f1ap, 0);
  if (!f1ap_data) {
    f1ap_data = wmem_new0(wmem_file_scope(), f1ap_private_data_t);
    f1ap_data->srb_id = -1;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_f1ap, 0, f1ap_data);
  }
  return f1ap_data;
}

static void
add_nr_pdcp_meta_data(packet_info *pinfo, guint8 direction, guint8 srb_id)
{
  pdcp_nr_info *p_pdcp_nr_info;

  /* Only need to set info once per session. */
  if (get_pdcp_nr_proto_data(pinfo)) {
      return;
  }

  p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);
  p_pdcp_nr_info->direction = direction;
  p_pdcp_nr_info->bearerType = Bearer_DCCH;
  p_pdcp_nr_info->bearerId = srb_id;
  p_pdcp_nr_info->plane = NR_SIGNALING_PLANE;
  p_pdcp_nr_info->seqnum_length = PDCP_NR_SN_LENGTH_12_BITS;
  p_pdcp_nr_info->maci_present = TRUE;
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

  return (dissector_try_uint_new(f1ap_ies_dissector_table, f1ap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &f1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  f1ap_ctx_t f1ap_ctx;
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  f1ap_ctx.message_type        = f1ap_data->message_type;
  f1ap_ctx.ProcedureCode       = f1ap_data->procedure_code;
  f1ap_ctx.ProtocolIE_ID       = f1ap_data->protocol_ie_id;
  f1ap_ctx.ProtocolExtensionID = f1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(f1ap_extension_dissector_table, f1ap_data->protocol_extension_id, tvb, pinfo, tree, FALSE, &f1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_imsg_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_sout_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_uout_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}


static void
f1ap_stats_tree_init(stats_tree *st)
{
    st_node_packets = stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, TRUE);
    st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
}

static tap_packet_status
f1ap_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
                       epan_dissect_t* edt _U_ , const void* p, tap_flags_t flags _U_)
{
    const struct f1ap_tap_t *pi = (const struct f1ap_tap_t *) p;

    tick_stat_node(st, st_str_packets, 0, FALSE);
    stats_tree_tick_pivot(st, st_node_packet_types,
                          val_to_str(pi->f1ap_mtype, mtype_names,
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
        FT_BOOLEAN, 8, TFS(&f1ap_tfs_interfacesToTrace), 0x80,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_Xn_C,
      { "Xn-C", "f1ap.interfacesToTrace.Xn_C",
        FT_BOOLEAN, 8, TFS(&f1ap_tfs_interfacesToTrace), 0x40,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_Uu,
      { "Uu", "f1ap.interfacesToTrace.Uu",
        FT_BOOLEAN, 8, TFS(&f1ap_tfs_interfacesToTrace), 0x20,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_F1_C,
      { "F1-C", "f1ap.interfacesToTrace.F1_C",
        FT_BOOLEAN, 8, TFS(&f1ap_tfs_interfacesToTrace), 0x10,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_E1,
      { "E1", "f1ap.interfacesToTrace.E1",
        FT_BOOLEAN, 8, TFS(&f1ap_tfs_interfacesToTrace), 0x08,
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
  static gint *ett[] = {
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
    &ett_f1ap_RACHReportContainer,
    &ett_f1ap_ReferenceTime,
    &ett_f1ap_ReportCharacteristics,
    &ett_f1ap_SIB10_message,
    &ett_f1ap_SIB12_message,
    &ett_f1ap_SIB13_message,
    &ett_f1ap_SIB14_message,
    &ett_f1ap_SL_PHY_MAC_RLC_Config,
    &ett_f1ap_SL_ConfigDedicatedEUTRA_Info,
    &ett_f1ap_TDD_UL_DLConfigCommonNR,
    &ett_f1ap_UEAssistanceInformationEUTRA,
    &ett_f1ap_PosAssistance_Information,
    &ett_f1ap_LocationMeasurementInformation,
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
