/* packet-ngap.c
 * Routines for NG-RAN NG Application Protocol (NGAP) packet dissection
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2018-2022, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 38.413 v17.1.1 (2022-06)
 */

#include "config.h"
#include <stdio.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>
#include <wsutil/wsjson.h>

#include "packet-ngap.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-s1ap.h"
#include "packet-ranap.h"
#include "packet-rrc.h"
#include "packet-lte-rrc.h"
#include "packet-nr-rrc.h"
#include "packet-gsm_map.h"
#include "packet-cell_broadcast.h"
#include "packet-ntp.h"
#include "packet-gsm_a_common.h"
#include "packet-http.h"

#define PNAME  "NG Application Protocol"
#define PSNAME "NGAP"
#define PFNAME "ngap"

/* Dissector will use SCTP PPID 18 or SCTP port. IANA assigned port = 36412 */
#define SCTP_PORT_NGAP 38412

void proto_register_ngap(void);
void proto_reg_handoff_ngap(void);

static dissector_handle_t ngap_handle;
static dissector_handle_t ngap_media_type_handle;
static dissector_handle_t nas_5gs_handle;
static dissector_handle_t nr_rrc_ue_radio_paging_info_handle;
static dissector_handle_t nr_rrc_ue_radio_access_cap_info_handle;
static dissector_handle_t lte_rrc_ue_radio_paging_info_handle;
static dissector_handle_t lte_rrc_ue_radio_access_cap_info_handle;
static dissector_handle_t lte_rrc_ue_radio_paging_info_nb_handle;
static dissector_handle_t lte_rrc_ue_radio_access_cap_info_nb_handle;
static dissector_handle_t nrppa_handle;

static int proto_json = -1;

#include "packet-ngap-val.h"

/* Initialize the protocol and registered fields */
static int proto_ngap = -1;
static int hf_ngap_transportLayerAddressIPv4 = -1;
static int hf_ngap_transportLayerAddressIPv6 = -1;
static int hf_ngap_SerialNumber_gs = -1;
static int hf_ngap_SerialNumber_msg_code = -1;
static int hf_ngap_SerialNumber_upd_nb = -1;
static int hf_ngap_WarningType_value = -1;
static int hf_ngap_WarningType_emergency_user_alert = -1;
static int hf_ngap_WarningType_popup = -1;
static int hf_ngap_WarningMessageContents_nb_pages = -1;
static int hf_ngap_WarningMessageContents_decoded_page = -1;
static int hf_ngap_NGRANTraceID_TraceID = -1;
static int hf_ngap_NGRANTraceID_TraceRecordingSessionReference = -1;
static int hf_ngap_InterfacesToTrace_NG_C = -1;
static int hf_ngap_InterfacesToTrace_Xn_C = -1;
static int hf_ngap_InterfacesToTrace_Uu = -1;
static int hf_ngap_InterfacesToTrace_F1_C = -1;
static int hf_ngap_InterfacesToTrace_E1 = -1;
static int hf_ngap_InterfacesToTrace_reserved = -1;
static int hf_ngap_RATRestrictionInformation_e_UTRA = -1;
static int hf_ngap_RATRestrictionInformation_nR = -1;
static int hf_ngap_RATRestrictionInformation_nR_unlicensed = -1;
static int hf_ngap_RATRestrictionInformation_reserved = -1;
static int hf_ngap_primaryRATRestriction_e_UTRA = -1;
static int hf_ngap_primaryRATRestriction_nR = -1;
static int hf_ngap_primaryRATRestriction_nR_unlicensed = -1;
static int hf_ngap_primaryRATRestriction_nR_LEO = -1;
static int hf_ngap_primaryRATRestriction_nR_MEO = -1;
static int hf_ngap_primaryRATRestriction_nR_GEO = -1;
static int hf_ngap_primaryRATRestriction_nR_OTHERSAT = -1;
static int hf_ngap_primaryRATRestriction_reserved = -1;
static int hf_ngap_secondaryRATRestriction_e_UTRA = -1;
static int hf_ngap_secondaryRATRestriction_nR = -1;
static int hf_ngap_secondaryRATRestriction_e_UTRA_unlicensed = -1;
static int hf_ngap_secondaryRATRestriction_nR_unlicensed = -1;
static int hf_ngap_secondaryRATRestriction_reserved = -1;
static int hf_ngap_NrencryptionAlgorithms_nea1 = -1;
static int hf_ngap_NrencryptionAlgorithms_nea2 = -1;
static int hf_ngap_NrencryptionAlgorithms_nea3 = -1;
static int hf_ngap_NrencryptionAlgorithms_reserved = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_nia1 = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_nia2 = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_nia3 = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_reserved = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_eea1 = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_eea2 = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_eea3 = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_reserved = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_eia1 = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_eia2 = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_eia3 = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_reserved = -1;
static int hf_ngap_MeasurementsToActivate_M1 = -1;
static int hf_ngap_MeasurementsToActivate_M2 = -1;
static int hf_ngap_MeasurementsToActivate_M4 = -1;
static int hf_ngap_MeasurementsToActivate_M5 = -1;
static int hf_ngap_MeasurementsToActivate_M6 = -1;
static int hf_ngap_MeasurementsToActivate_M7 = -1;
static int hf_ngap_MeasurementsToActivate_M1_from_event = -1;
static int hf_ngap_MeasurementsToActivate_reserved = -1;
static int hf_ngap_MDT_Location_Information_GNSS = -1;
static int hf_ngap_MDT_Location_Information_reserved = -1;
static int hf_ngap_GlobalCable_ID_str = -1;
static int hf_ngap_UpdateFeedback_CN_PDB_DL = -1;
static int hf_ngap_UpdateFeedback_CN_PDB_UL = -1;
static int hf_ngap_UpdateFeedback_reserved = -1;
#include "packet-ngap-hf.c"

/* Initialize the subtree pointers */
static gint ett_ngap = -1;
static gint ett_ngap_TransportLayerAddress = -1;
static gint ett_ngap_DataCodingScheme = -1;
static gint ett_ngap_SerialNumber = -1;
static gint ett_ngap_WarningType = -1;
static gint ett_ngap_WarningMessageContents = -1;
static gint ett_ngap_PLMNIdentity = -1;
static gint ett_ngap_NGAP_Message = -1;
static gint ett_ngap_NGRANTraceID = -1;
static gint ett_ngap_InterfacesToTrace = -1;
static gint ett_ngap_SourceToTarget_TransparentContainer = -1;
static gint ett_ngap_TargetToSource_TransparentContainer = -1;
static gint ett_ngap_RRCContainer = -1;
static gint ett_ngap_RATRestrictionInformation = -1;
static gint ett_ngap_primaryRATRestriction = -1;
static gint ett_ngap_secondaryRATRestriction = -1;
static gint ett_ngap_NrencryptionAlgorithms = -1;
static gint ett_ngap_NrintegrityProtectionAlgorithms = -1;
static gint ett_ngap_EUTRAencryptionAlgorithms = -1;
static gint ett_ngap_EUTRAintegrityProtectionAlgorithms = -1;
static gint ett_ngap_UERadioCapabilityForPagingOfNR = -1;
static gint ett_ngap_UERadioCapabilityForPagingOfEUTRA = -1;
static gint ett_ngap_UERadioCapability = -1;
static gint ett_ngap_LastVisitedEUTRANCellInformation = -1;
static gint ett_ngap_LastVisitedUTRANCellInformation = -1;
static gint ett_ngap_LastVisitedGERANCellInformation = -1;
static gint ett_ngap_NASSecurityParametersFromNGRAN = -1;
static gint ett_ngap_NASC = -1;
static gint ett_ngap_NAS_PDU = -1;
static gint ett_ngap_EN_DCSONConfigurationTransfer = -1;
static gint ett_ngap_BurstArrivalTime = -1;
static gint ett_ngap_CoverageEnhancementLevel = -1;
static gint ett_ngap_MDTModeEutra = -1;
static gint ett_ngap_MeasurementsToActivate = -1;
static gint ett_ngap_MDT_Location_Information = -1;
static gint ett_ngap_NRMobilityHistoryReport = -1;
static gint ett_ngap_LTEUERLFReportContainer = -1;
static gint ett_ngap_NRUERLFReportContainer = -1;
static gint ett_ngap_TargettoSource_Failure_TransparentContainer = -1;
static gint ett_ngap_UERadioCapabilityForPagingOfNB_IoT = -1;
static gint ett_ngap_GlobalCable_ID = -1;
static gint ett_ngap_UpdateFeedback = -1;
static gint ett_ngap_successfulHOReportContainer = -1;
#include "packet-ngap-ett.c"

static expert_field ei_ngap_number_pages_le15 = EI_INIT;

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

/* NGAP stats - Tap interface */

static void set_stats_message_type(packet_info *pinfo, int type);

static const guint8 *st_str_packets        = "Total Packets";
static const guint8 *st_str_packet_types   = "NGAP Packet Types";

static int st_node_packets = -1;
static int st_node_packet_types = -1;
static int ngap_tap = -1;

struct ngap_tap_t {
    gint ngap_mtype;
};

#define MTYPE_AMF_CONFIGURATION_UPDATE                    1
#define MTYPE_AMF_CONFIGURATION_UPDATE_ACK                2
#define MTYPE_AMF_CONFIGURATION_UPDATE_FAILURE            3
#define MTYPE_AMF_CP_RELOCATION_IND                       4
#define MTYPE_AMF_STATUS_IND                              5
#define MTYPE_BROADCAST_SESSION_MODIFICATION_REQUEST      6
#define MTYPE_BROADCAST_SESSION_MODIFICATION_RESPONSE     7
#define MTYPE_BROADCAST_SESSION_MODIFICATION_FAILURE      8
#define MTYPE_BROADCAST_SESSION_RELEASE_REQUEST           9
#define MTYPE_BROADCAST_SESSION_RELEASE_RESPONSE          10
#define MTYPE_BROADCAST_SESSION_RELEASE_REQUIRED          11
#define MTYPE_BROADCAST_SESSION_SETUP_REQUEST             12
#define MTYPE_BROADCAST_SESSION_SETUP_RESPONSE            13
#define MTYPE_BROADCAST_SESSION_SETUP_FAILURE             14
#define MTYPE_CELL_TRAFFIC_TRACE                          15
#define MTYPE_CONNECTION_ESTAB_IND                        16
#define MTYPE_DEACTIVATE_TRACE                            17
#define MTYPE_DISTRIBUTION_SETUP_REQUEST                  18
#define MTYPE_DISTRIBUTION_SETUP_RESPONSE                 19
#define MTYPE_DISTRIBUTION_SETUP_FAILURE                  20
#define MTYPE_DISTRIBUTION_RELEASE_REQUEST                21
#define MTYPE_DISTRIBUTION_RELEASE_RESPONSE               22
#define MTYPE_DOWNLINK_NAS_TRANSPORT                      23
#define MTYPE_DOWNLINK_NON_UE_ASSOCIATED_NR_PPA_TRANSPORT 24
#define MTYPE_DOWNLINK_RAN_CONFIGURATION_TRANSFER         25
#define MTYPE_DOWNLINK_RAN_EARLY_STATUS_TRANSFER          26
#define MTYPE_DOWNLINK_RAN_STATUS_TRANSFER                27
#define MTYPE_DOWNLINK_UE_ASSOCIATED_NR_PPA_TRANSPORT     28
#define MTYPE_ERROR_INDICATION                            29
#define MTYPE_HANDOVER_CANCEL                             30
#define MTYPE_HANDOVER_CANCEL_ACK                         31
#define MTYPE_HANDOVER_NOTIFY                             32
#define MTYPE_HANDOVER_REQUIRED                           33
#define MTYPE_HANDOVER_COMMAND                            34
#define MTYPE_HANDOVER_PREPARATION_FAILURE                35
#define MTYPE_HANDOVER_REQUEST                            36
#define MTYPE_HANDOVER_REQUEST_ACK                        37
#define MTYPE_HANDOVER_FAILURE                            38
#define MTYPE_HANDOVER_SUCCESS                            39
#define MTYPE_INITIAL_CONTEXT_SETUP_REQUEST               40
#define MTYPE_INITIAL_CONTEXT_SETUP_RESPONSE              41
#define MTYPE_INITIAL_CONTEXT_SETUP_FAILURE               42
#define MTYPE_INITIAL_UE_MESSAGE                          43
#define MTYPE_LOCATION_REPORT                             44
#define MTYPE_LOCATION_REPORTING_CONTROL                  45
#define MTYPE_LOCATION_REPORTING_FAILURE_IND              46
#define MTYPE_MULTICAST_SESSION_ACTIVATION_REQUEST        47
#define MTYPE_MULTICAST_SESSION_ACTIVATION_RESPONSE       48
#define MTYPE_MULTICAST_SESSION_ACTIVATION_FAILURE        49
#define MTYPE_MULTICAST_SESSION_DEACTIVATION_REQUEST      50
#define MTYPE_MULTICAST_SESSION_DEACTIVATION_RESPONSE     51
#define MTYPE_MULTICAST_SESSION_UPDATE_REQUEST            52
#define MTYPE_MULTICAST_SESSION_UPDATE_RESPONSE           53
#define MTYPE_MULTICAST_SESSION_UPDATE_FAILURE            54
#define MTYPE_MULTICAST_GROUP_PAGING                      55
#define MTYPE_NAS_NON_DELIVERY_IND                        56
#define MTYPE_NG_RESET                                    57
#define MTYPE_NG_RESET_ACK                                58
#define MTYPE_NG_SETUP_REQUEST                            59
#define MTYPE_NG_SETUP_RESPONSE                           60
#define MTYPE_NG_SETUP_FAILURE                            61
#define MTYPE_OVERLOAD_START                              62
#define MTYPE_OVERLOAD_STOP                               63
#define MTYPE_PAGING                                      64
#define MTYPE_PATH_SWITCH_REQUEST                         65
#define MTYPE_PATH_SWITCH_REQUEST_ACK                     66
#define MTYPE_PATH_SWITCH_REQUEST_FAILURE                 67
#define MTYPE_PDU_SESSION_RESOURCE_MODIFY_REQUEST         68
#define MTYPE_PDU_SESSION_RESOURCE_MODIFY_RESPONSE        69
#define MTYPE_PDU_SESSION_RESOURCE_MODIFY_IND             70
#define MTYPE_PDU_SESSION_RESOURCE_MODIFY_CONFIRM         71
#define MTYPE_PDU_SESSION_RESOURCE_NOTIFY                 72
#define MTYPE_PDU_SESSION_RESOURCE_RELEASE_COMMAND        73
#define MTYPE_PDU_SESSION_RESOURCE_RELEASE_RESPONSE       74
#define MTYPE_PDU_SESSION_RESOURCE_SETUP_REQUEST          75
#define MTYPE_PDU_SESSION_RESOURCE_SETUP_RESPONSE         76
#define MTYPE_PRIVATE_MESSAGE                             77
#define MTYPE_PWS_CANCEL_REQUEST                          78
#define MTYPE_PWS_CANCEL_RESPONSE                         79
#define MTYPE_PWS_FAILURE_INDICATION                      80
#define MTYPE_PWS_RESTART_INDICATION                      81
#define MTYPE_RAN_CONFIGURATION_UPDATE                    82
#define MTYPE_RAN_CONFIGURATION_UPDATE_ACK                83
#define MTYPE_RAN_CONFIGURATION_UPDATE_FAILURE            84
#define MTYPE_RAN_CP_RELOCATION_IND                       85
#define MTYPE_REROUTE_NAS_REQUEST                         86
#define MTYPE_RETRIEVE_UE_INFORMATION                     87
#define MTYPE_RRC_INACTIVE_TRANSITION_REPORT              88
#define MTYPE_SECONDARY_RAT_DATA_USAGE_REPORT             89
#define MTYPE_TRACE_FAILURE_IND                           90
#define MTYPE_TRACE_START                                 91
#define MTYPE_UE_CONTEXT_MODIFICATION_REQUEST             92
#define MTYPE_UE_CONTEXT_MODIFICATION_RESPONSE            93
#define MTYPE_UE_CONTEXT_MODIFICATION_FAILURE             94
#define MTYPE_UE_CONTEXT_RELEASE_COMMAND                  95
#define MTYPE_UE_CONTEXT_RELEASE_COMPLETE                 96
#define MTYPE_UE_CONTEXT_RELEASE_REQUEST                  97
#define MTYPE_UE_CONTEXT_RESUME_REQUEST                   98
#define MTYPE_UE_CONTEXT_RESUME_RESPONSE                  99
#define MTYPE_UE_CONTEXT_RESUME_FAILURE                   100
#define MTYPE_UE_CONTEXT_SUSPEND_REQUEST                  101
#define MTYPE_UE_CONTEXT_SUSPEND_RESPONSE                 102
#define MTYPE_UE_CONTEXT_SUSPEND_FAILURE                  103
#define MTYPE_UE_INFORMATION_TRANSFER                     104
#define MTYPE_UE_RADIO_CAPABILITY_CHECK_REQUEST           105
#define MTYPE_UE_RADIO_CAPABILITY_CHECK_RESPONSE          106
#define MTYPE_UE_RADIO_CAPABILITY_ID_MAPPING_REQUEST      107
#define MTYPE_UE_RADIO_CAPABILITY_ID_MAPPING_RESPONSE     108
#define MTYPE_UE_RADIO_CAPABILITY_INFO_IND                109
#define MTYPE_UE_TN_LAB_BINDING_RELEASE_REQUEST           110
#define MTYPE_UPLINK_NAS_TRANSPORT                        111
#define MTYPE_UPLINK_NON_UE_ASSOCIATED_NR_PPA_TRANSPORT   112
#define MTYPE_UPLINK_RAN_CONFIGURATION_TRANSFER           113
#define MTYPE_UPLINK_RAN_EARLY_STATUS_TRANSFER            114
#define MTYPE_UPLINK_RAN_STATUS_TRANSFER                  115
#define MTYPE_UPLINK_UE_ASSOCIATED_NR_PPA_TRANSPORT       116
#define MTYPE_WRITE_REPLACE_WARNING_REQUEST               117
#define MTYPE_WRITE_REPLACE_WARNING_RESPONSE              118
#define MTYPE_UPLINK_RIM_INFORMATION_TRANSFER             119
#define MTYPE_DOWNLINK_RIM_INFORMATION_TRANSFER           120


/* Value Strings. TODO: ext? */
static const value_string mtype_names[] = {
    { MTYPE_AMF_CONFIGURATION_UPDATE,                    "AMFConfigurationUpdate" },
    { MTYPE_AMF_CONFIGURATION_UPDATE_ACK,                "AMFConfigurationUpdateAcknowledge" },
    { MTYPE_AMF_CONFIGURATION_UPDATE_FAILURE,            "AMFConfigurationUpdateFailure" },
    { MTYPE_AMF_CP_RELOCATION_IND,                       "AMFCPRelocationIndication" },
    { MTYPE_AMF_STATUS_IND,                              "AMFStatusIndication" },
    { MTYPE_BROADCAST_SESSION_MODIFICATION_REQUEST,      "BroadcastSessionModificationRequest" },
    { MTYPE_BROADCAST_SESSION_MODIFICATION_RESPONSE,     "BroadcastSessionModificationResponse" },
    { MTYPE_BROADCAST_SESSION_MODIFICATION_FAILURE,      "BroadcastSessionModificationFailure" },
    { MTYPE_BROADCAST_SESSION_RELEASE_REQUEST,           "BroadcastSessionReleaseRequest" },
    { MTYPE_BROADCAST_SESSION_RELEASE_RESPONSE,          "BroadcastSessionReleaseResponse" },
    { MTYPE_BROADCAST_SESSION_RELEASE_REQUIRED,          "BroadcastSessionReleaseRequired" },
    { MTYPE_BROADCAST_SESSION_SETUP_REQUEST,             "BroadcastSessionSetupRequest" },
    { MTYPE_BROADCAST_SESSION_SETUP_RESPONSE,            "BroadcastSessionSetupResponse" },
    { MTYPE_BROADCAST_SESSION_SETUP_FAILURE,             "BroadcastSessionSetupFailure" },
    { MTYPE_CELL_TRAFFIC_TRACE,                          "CellTrafficTrace" },
    { MTYPE_CONNECTION_ESTAB_IND,                        "ConnectionEstablishmentIndication" },
    { MTYPE_DEACTIVATE_TRACE,                            "DeactivateTrace" },
    { MTYPE_DISTRIBUTION_SETUP_REQUEST,                  "DistributionSetupRequest" },
    { MTYPE_DISTRIBUTION_SETUP_RESPONSE,                 "DistributionSetupResponse" },
    { MTYPE_DISTRIBUTION_SETUP_FAILURE,                  "DistributionSetupFailure" },
    { MTYPE_DISTRIBUTION_RELEASE_REQUEST,                "DistributionReleaseRequest" },
    { MTYPE_DISTRIBUTION_RELEASE_RESPONSE,               "DistributionReleaseResponse" },
    { MTYPE_DOWNLINK_NAS_TRANSPORT,                      "DownlinkNASTransport" },
    { MTYPE_DOWNLINK_NON_UE_ASSOCIATED_NR_PPA_TRANSPORT, "DownlinkNonUEAssociatedNRPPaTransport" },
    { MTYPE_DOWNLINK_RAN_CONFIGURATION_TRANSFER,         "DownlinkRANConfigurationTransfer" },
    { MTYPE_DOWNLINK_RAN_EARLY_STATUS_TRANSFER,          "DownlinkRANEarlyStatusTransfer" },
    { MTYPE_DOWNLINK_RAN_STATUS_TRANSFER,                "DownlinkRANStatusTransfer" },
    { MTYPE_DOWNLINK_UE_ASSOCIATED_NR_PPA_TRANSPORT,     "DownlinkUEAssociatedNRPPaTransport" },
    { MTYPE_ERROR_INDICATION,                            "ErrorIndication" },
    { MTYPE_HANDOVER_CANCEL,                             "HandoverCancel" },
    { MTYPE_HANDOVER_CANCEL_ACK,                         "HandoverCancelAcknowledge" },
    { MTYPE_HANDOVER_NOTIFY,                             "HandoverNotify" },
    { MTYPE_HANDOVER_REQUIRED,                           "HandoverRequired" },
    { MTYPE_HANDOVER_COMMAND,                            "HandoverCommand" },
    { MTYPE_HANDOVER_PREPARATION_FAILURE,                "HandoverPreparationFailure" },
    { MTYPE_HANDOVER_REQUEST,                            "HandoverRequest" },
    { MTYPE_HANDOVER_REQUEST_ACK,                        "HandoverRequestAcknowledge" },
    { MTYPE_HANDOVER_FAILURE,                            "HandoverFailure" },
    { MTYPE_HANDOVER_SUCCESS,                            "HandoverSuccess" },
    { MTYPE_INITIAL_CONTEXT_SETUP_REQUEST,               "InitialContextSetupRequest" },
    { MTYPE_INITIAL_CONTEXT_SETUP_RESPONSE,              "InitialContextSetupResponse" },
    { MTYPE_INITIAL_CONTEXT_SETUP_FAILURE,               "InitialContextSetupFailure" },
    { MTYPE_INITIAL_CONTEXT_SETUP_FAILURE,               "InitialContextSetupFailure" },
    { MTYPE_INITIAL_UE_MESSAGE,                          "InitialUEMessage" },
    { MTYPE_LOCATION_REPORT,                             "LocationReport" },
    { MTYPE_LOCATION_REPORTING_CONTROL,                  "LocationReportingControl" },
    { MTYPE_LOCATION_REPORTING_FAILURE_IND,              "LocationReportingFailureIndication" },
    { MTYPE_MULTICAST_SESSION_ACTIVATION_REQUEST,        "MulticastSessionActivationRequest" },
    { MTYPE_MULTICAST_SESSION_ACTIVATION_RESPONSE,       "MulticastSessionActivationResponse" },
    { MTYPE_MULTICAST_SESSION_ACTIVATION_FAILURE,        "MulticastSessionActivationFailure" },
    { MTYPE_MULTICAST_SESSION_DEACTIVATION_REQUEST,      "MulticastSessionDeactivationRequest" },
    { MTYPE_MULTICAST_SESSION_DEACTIVATION_RESPONSE,     "MulticastSessionDeactivationResponse" },
    { MTYPE_MULTICAST_SESSION_UPDATE_REQUEST,            "MulticastSessionUpdateRequest" },
    { MTYPE_MULTICAST_SESSION_UPDATE_RESPONSE,           "MulticastSessionUpdateResponse" },
    { MTYPE_MULTICAST_SESSION_UPDATE_FAILURE,            "MulticastSessionUpdateFailure" },
    { MTYPE_MULTICAST_GROUP_PAGING,                      "MulticastGroupPaging" },
    { MTYPE_NAS_NON_DELIVERY_IND,                        "NASNonDeliveryIndication" },
    { MTYPE_NG_RESET,                                    "NGReset" },
    { MTYPE_NG_RESET_ACK,                                "NGResetAcknowledge" },
    { MTYPE_NG_SETUP_REQUEST,                            "NGSetupRequest" },
    { MTYPE_NG_SETUP_RESPONSE,                           "NGSetupResponse" },
    { MTYPE_NG_SETUP_FAILURE,                            "NGSetupFailure" },
    { MTYPE_OVERLOAD_START,                              "OverloadStart" },
    { MTYPE_OVERLOAD_STOP,                               "OverloadStop" },
    { MTYPE_PAGING,                                      "Paging" },
    { MTYPE_PATH_SWITCH_REQUEST,                         "PathSwitchRequest" },
    { MTYPE_PATH_SWITCH_REQUEST_ACK,                     "PathSwitchRequestAcknowledge" },
    { MTYPE_PATH_SWITCH_REQUEST_FAILURE,                 "PathSwitchRequestFailure" },
    { MTYPE_PDU_SESSION_RESOURCE_MODIFY_REQUEST,         "PDUSessionResourceModifyRequest" },
    { MTYPE_PDU_SESSION_RESOURCE_MODIFY_RESPONSE,        "PDUSessionResourceModifyResponse" },
    { MTYPE_PDU_SESSION_RESOURCE_MODIFY_IND,             "PDUSessionResourceModifyIndication" },
    { MTYPE_PDU_SESSION_RESOURCE_MODIFY_CONFIRM,         "PDUSessionResourceModifyConfirm" },
    { MTYPE_PDU_SESSION_RESOURCE_NOTIFY,                 "PDUSessionResourceNotify" },
    { MTYPE_PDU_SESSION_RESOURCE_RELEASE_COMMAND,        "PDUSessionResourceReleaseCommand" },
    { MTYPE_PDU_SESSION_RESOURCE_RELEASE_RESPONSE,       "PDUSessionResourceReleaseResponse" },
    { MTYPE_PDU_SESSION_RESOURCE_SETUP_REQUEST,          "PDUSessionResourceSetupRequest" },
    { MTYPE_PDU_SESSION_RESOURCE_SETUP_RESPONSE,         "PDUSessionResourceSetupResponse" },
    { MTYPE_PRIVATE_MESSAGE,                             "PrivateMessage" },
    { MTYPE_PWS_CANCEL_REQUEST,                          "PWSCancelRequest" },
    { MTYPE_PWS_CANCEL_RESPONSE,                         "PWSCancelResponse" },
    { MTYPE_PWS_FAILURE_INDICATION,                      "PWSFailureIndication" },
    { MTYPE_PWS_RESTART_INDICATION,                      "PWSRestartIndication" },
    { MTYPE_RAN_CONFIGURATION_UPDATE,                    "RANConfigurationUpdate" },
    { MTYPE_RAN_CONFIGURATION_UPDATE_ACK,                "RANConfigurationUpdateAcknowledge" },
    { MTYPE_RAN_CONFIGURATION_UPDATE_FAILURE,            "RANConfigurationUpdateFailure" },
    { MTYPE_RAN_CP_RELOCATION_IND,                       "RANCPRelocationIndication" },
    { MTYPE_REROUTE_NAS_REQUEST,                         "RerouteNASRequest" },
    { MTYPE_RETRIEVE_UE_INFORMATION,                     "RetrieveUEInformation" },
    { MTYPE_RRC_INACTIVE_TRANSITION_REPORT,              "RRCInactiveTransitionReport" },
    { MTYPE_SECONDARY_RAT_DATA_USAGE_REPORT,             "SecondaryRATDataUsageReport" },
    { MTYPE_TRACE_FAILURE_IND,                           "TraceFailureIndication" },
    { MTYPE_TRACE_START,                                 "TraceStart" },
    { MTYPE_UE_CONTEXT_MODIFICATION_REQUEST,             "UEContextModificationRequest" },
    { MTYPE_UE_CONTEXT_MODIFICATION_RESPONSE,            "UEContextModificationResponse" },
    { MTYPE_UE_CONTEXT_MODIFICATION_FAILURE,             "UEContextModificationFailure" },
    { MTYPE_UE_CONTEXT_RELEASE_COMMAND,                  "UEContextReleaseCommand" },
    { MTYPE_UE_CONTEXT_RELEASE_COMPLETE,                 "UEContextReleaseComplete" },
    { MTYPE_UE_CONTEXT_RELEASE_REQUEST,                  "UEContextReleaseRequest" },
    { MTYPE_UE_CONTEXT_RESUME_REQUEST,                   "UEContextResumeRequest" },
    { MTYPE_UE_CONTEXT_RESUME_RESPONSE,                  "UEContextResumeResponse" },
    { MTYPE_UE_CONTEXT_RESUME_FAILURE,                   "UEContextResumeFailure" },
    { MTYPE_UE_CONTEXT_SUSPEND_REQUEST,                  "UEContextSuspendRequest" },
    { MTYPE_UE_CONTEXT_SUSPEND_RESPONSE,                 "UEContextSuspendResponse" },
    { MTYPE_UE_CONTEXT_SUSPEND_FAILURE,                  "UEContextSuspendFailure" },
    { MTYPE_UE_INFORMATION_TRANSFER,                     "UEInformationTransfer" },
    { MTYPE_UE_RADIO_CAPABILITY_CHECK_REQUEST,           "UERadioCapabilityCheckRequest" },
    { MTYPE_UE_RADIO_CAPABILITY_CHECK_RESPONSE,          "UERadioCapabilityCheckResponse" },
    { MTYPE_UE_RADIO_CAPABILITY_ID_MAPPING_REQUEST,      "UERadioCapabilityIDMappingRequest" },
    { MTYPE_UE_RADIO_CAPABILITY_ID_MAPPING_RESPONSE,     "UERadioCapabilityIDMappingResponse" },
    { MTYPE_UE_RADIO_CAPABILITY_INFO_IND,                "UERadioCapabilityInfoIndication" },
    { MTYPE_UE_TN_LAB_BINDING_RELEASE_REQUEST,           "UETNLABindingReleaseRequest" },
    { MTYPE_UPLINK_NAS_TRANSPORT,                        "UplinkNASTransport" },
    { MTYPE_UPLINK_NON_UE_ASSOCIATED_NR_PPA_TRANSPORT,   "UplinkNonUEAssociatedNRPPaTransport" },
    { MTYPE_UPLINK_RAN_CONFIGURATION_TRANSFER,           "UplinkRANConfigurationTransfer" },
    { MTYPE_UPLINK_RAN_EARLY_STATUS_TRANSFER,            "UplinkRANEarlyStatusTransfer" },
    { MTYPE_UPLINK_RAN_STATUS_TRANSFER,                  "UplinkRANStatusTransfer" },
    { MTYPE_UPLINK_UE_ASSOCIATED_NR_PPA_TRANSPORT,       "UplinkUEAssociatedNRPPaTransport" },
    { MTYPE_WRITE_REPLACE_WARNING_REQUEST,               "WriteReplaceWarningRequest" },
    { MTYPE_WRITE_REPLACE_WARNING_RESPONSE,              "WriteReplaceWarningResponse" },
    { MTYPE_UPLINK_RIM_INFORMATION_TRANSFER,             "UplinkRIMInformationTransfer" },
    { MTYPE_DOWNLINK_RIM_INFORMATION_TRANSFER,           "DownlinkRIMInformationTransfer" },
    { 0,  NULL }
};


typedef struct _ngap_ctx_t {
    guint32 message_type;
    guint32 ProcedureCode;
    guint32 ProtocolIE_ID;
    guint32 ProtocolExtensionID;
} ngap_ctx_t;

struct ngap_conv_info {
  address addr_a;
  guint32 port_a;
  GlobalRANNodeID_enum ranmode_id_a;
  address addr_b;
  guint32 port_b;
  GlobalRANNodeID_enum ranmode_id_b;
  wmem_map_t *nbiot_ta;
  wmem_tree_t *nbiot_ran_ue_ngap_id;
};

enum {
  SOURCE_TO_TARGET_TRANSPARENT_CONTAINER = 1,
  TARGET_TO_SOURCE_TRANSPARENT_CONTAINER
};

struct ngap_supported_ta {
  guint32 tac;
  wmem_array_t *plmn;
};

struct ngap_tai {
  guint32 plmn;
  guint32 tac;
};

struct ngap_private_data {
  struct ngap_conv_info *ngap_conv;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  guint32 message_type;
  guint32 handover_type_value;
  guint8 data_coding_scheme;
  guint8 transparent_container_type;
  gboolean is_qos_flow_notify;
  struct ngap_supported_ta *supported_ta;
  struct ngap_tai *tai;
  guint32 ran_ue_ngap_id;
  e212_number_type_t number_type;
  struct ngap_tap_t *stats_tap;
};

enum {
  NGAP_NG_RAN_CONTAINER_AUTOMATIC,
  NGAP_NG_RAN_CONTAINER_GNB,
  NGAP_NG_RAN_CONTAINER_NG_ENB
};

static const enum_val_t ngap_target_ng_ran_container_vals[] = {
  {"automatic", "automatic", NGAP_NG_RAN_CONTAINER_AUTOMATIC},
  {"gnb", "gNB", NGAP_NG_RAN_CONTAINER_GNB},
  {"ng-enb","ng-eNB", NGAP_NG_RAN_CONTAINER_NG_ENB},
  {NULL, NULL, -1}
};

enum {
  NGAP_LTE_CONTAINER_AUTOMATIC,
  NGAP_LTE_CONTAINER_LEGACY,
  NGAP_LTE_CONTAINER_NBIOT
};

static const enum_val_t ngap_lte_container_vals[] = {
  {"automatic", "Automatic", NGAP_LTE_CONTAINER_AUTOMATIC},
  {"legacy", "Legacy LTE", NGAP_LTE_CONTAINER_LEGACY},
  {"nb-iot","NB-IoT", NGAP_LTE_CONTAINER_NBIOT},
  {NULL, NULL, -1}
};

/* Global variables */
static range_t *gbl_ngapSctpRange = NULL;
static gboolean ngap_dissect_container = TRUE;
static gint ngap_dissect_target_ng_ran_container_as = NGAP_NG_RAN_CONTAINER_AUTOMATIC;
static gint ngap_dissect_lte_container_as = NGAP_LTE_CONTAINER_AUTOMATIC;

/* Dissector tables */
static dissector_table_t ngap_ies_dissector_table;
static dissector_table_t ngap_ies_p1_dissector_table;
static dissector_table_t ngap_ies_p2_dissector_table;
static dissector_table_t ngap_extension_dissector_table;
static dissector_table_t ngap_proc_imsg_dissector_table;
static dissector_table_t ngap_proc_sout_dissector_table;
static dissector_table_t ngap_proc_uout_dissector_table;
static dissector_table_t ngap_n2_ie_type_dissector_table;

static proto_tree *top_tree = NULL;

static void set_message_label(asn1_ctx_t *actx, int type)
{
  const char *label = val_to_str_const(type, mtype_names, "Unknown");
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, label);
  /* N.B. would like to be able to use actx->subTree.top_tree, but not easy to set.. */
  proto_item_append_text(top_tree, " (%s)", label);
}


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
*/
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static int dissect_InitialUEMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data);
static int dissect_PDUSessionResourceReleaseResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverRequestAcknowledgeTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceSetupUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverResourceAllocationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestSetupFailedTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverCommandTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverRequiredTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyConfirmTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyIndicationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceNotifyTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceNotifyReleasedTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceSetupRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceSetupResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestAcknowledgeTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverPreparationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceReleaseCommandTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_TargetNGRANNode_ToSourceNGRANNode_FailureTransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_SecondaryRATDataUsageReportTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyIndicationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_ngap_AlternativeQoSParaSetNotifyIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

const value_string ngap_serialNumber_gs_vals[] = {
  { 0, "Display mode immediate, cell wide"},
  { 1, "Display mode normal, PLMN wide"},
  { 2, "Display mode normal, tracking area wide"},
  { 3, "Display mode normal, cell wide"},
  { 0, NULL},
};

const value_string ngap_warningType_vals[] = {
  { 0, "Earthquake"},
  { 1, "Tsunami"},
  { 2, "Earthquake and Tsunami"},
  { 3, "Test"},
  { 4, "Other"},
  { 0, NULL},
};

static void
dissect_ngap_warningMessageContents(tvbuff_t *warning_msg_tvb, proto_tree *tree, packet_info *pinfo, guint8 dcs, int hf_nb_pages, int hf_decoded_page)
{
  guint32 offset;
  guint8 nb_of_pages, length, *str;
  proto_item *ti;
  tvbuff_t *cb_data_page_tvb, *cb_data_tvb;
  int i;

  nb_of_pages = tvb_get_guint8(warning_msg_tvb, 0);
  ti = proto_tree_add_uint(tree, hf_nb_pages, warning_msg_tvb, 0, 1, nb_of_pages);
  if (nb_of_pages > 15) {
    expert_add_info_format(pinfo, ti, &ei_ngap_number_pages_le15,
                           "Number of pages should be <=15 (found %u)", nb_of_pages);
    nb_of_pages = 15;
  }
  for (i = 0, offset = 1; i < nb_of_pages; i++) {
    length = tvb_get_guint8(warning_msg_tvb, offset+82);
    cb_data_page_tvb = tvb_new_subset_length(warning_msg_tvb, offset, length);
    cb_data_tvb = dissect_cbs_data(dcs, cb_data_page_tvb, tree, pinfo, 0);
    if (cb_data_tvb) {
      str = tvb_get_string_enc(pinfo->pool, cb_data_tvb, 0, tvb_reported_length(cb_data_tvb), ENC_UTF_8|ENC_NA);
      proto_tree_add_string_format(tree, hf_decoded_page, warning_msg_tvb, offset, 83,
                                   str, "Decoded Page %u: %s", i+1, str);
    }
    offset += 83;
  }
}

static void
ngap_PacketLossRate_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
ngap_PacketDelayBudget_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static void
ngap_TimeUEStayedInCellEnhancedGranularity_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fs", ((float)v)/10);
}

static void
ngap_PeriodicRegistrationUpdateTimer_fmt(gchar *s, guint32 v)
{
  guint32 val = v & 0x1f;

  switch (v>>5) {
    case 0:
      snprintf(s, ITEM_LABEL_LENGTH, "%u min (%u)", val * 10, v);
      break;
    case 1:
    default:
      snprintf(s, ITEM_LABEL_LENGTH, "%u hr (%u)", val, v);
      break;
    case 2:
      snprintf(s, ITEM_LABEL_LENGTH, "%u hr (%u)", val * 10, v);
      break;
    case 3:
      snprintf(s, ITEM_LABEL_LENGTH, "%u sec (%u)", val * 2, v);
      break;
    case 4:
      snprintf(s, ITEM_LABEL_LENGTH, "%u sec (%u)", val * 30, v);
      break;
    case 5:
      snprintf(s, ITEM_LABEL_LENGTH, "%u min (%u)", val, v);
      break;
    case 7:
      snprintf(s, ITEM_LABEL_LENGTH, "deactivated (%u)", v);
      break;
  }
}

static void
ngap_ExtendedPacketDelayBudget_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fms (%u)", (float)v/100, v);
}

static void
ngap_Threshold_RSRP_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%u)", (gint32)v-156, v);
}

static void
ngap_Threshold_RSRQ_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-43, v);
}

static void
ngap_Threshold_SINR_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-23, v);
}

static struct ngap_private_data*
ngap_get_private_data(packet_info *pinfo)
{
  struct ngap_private_data *ngap_data = (struct ngap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_ngap, 0);
  if (!ngap_data) {
    ngap_data = wmem_new0(pinfo->pool, struct ngap_private_data);
    ngap_data->handover_type_value = -1;
    p_add_proto_data(pinfo->pool, pinfo, proto_ngap, 0, ngap_data);
  }
  return ngap_data;
}

static GlobalRANNodeID_enum
ngap_get_ranmode_id(address *addr, guint32 port, packet_info *pinfo)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);
  GlobalRANNodeID_enum ranmode_id = (GlobalRANNodeID_enum)-1;

  if (ngap_data->ngap_conv) {
    if (addresses_equal(addr, &ngap_data->ngap_conv->addr_a) && port == ngap_data->ngap_conv->port_a) {
      ranmode_id = ngap_data->ngap_conv->ranmode_id_a;
    } else if (addresses_equal(addr, &ngap_data->ngap_conv->addr_b) && port == ngap_data->ngap_conv->port_b) {
      ranmode_id = ngap_data->ngap_conv->ranmode_id_b;
    }
  }
  return ranmode_id;
}

static gboolean
ngap_is_nbiot_ue(packet_info *pinfo)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  if (ngap_data->ngap_conv) {
    wmem_tree_key_t tree_key[3];
    guint32 *id;

    tree_key[0].length = 1;
    tree_key[0].key = &ngap_data->ran_ue_ngap_id;
    tree_key[1].length = 1;
    tree_key[1].key = &pinfo->num;
    tree_key[2].length = 0;
    tree_key[2].key = NULL;
    id = (guint32*)wmem_tree_lookup32_array_le(ngap_data->ngap_conv->nbiot_ran_ue_ngap_id, tree_key);
    if (id && (*id == ngap_data->ran_ue_ngap_id)) {
      return TRUE;
    }
  }
  return FALSE;
}

const true_false_string ngap_not_updated_updated = {
    "Not updated",
    "Updated"
};

#include "packet-ngap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  ngap_ctx_t ngap_ctx;
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  ngap_ctx.message_type        = ngap_data->message_type;
  ngap_ctx.ProcedureCode       = ngap_data->procedure_code;
  ngap_ctx.ProtocolIE_ID       = ngap_data->protocol_ie_id;
  ngap_ctx.ProtocolExtensionID = ngap_data->protocol_extension_id;

  return (dissector_try_uint_new(ngap_ies_dissector_table, ngap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &ngap_ctx)) ? tvb_captured_length(tvb) : 0;
}
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint(ngap_ies_p1_dissector_table, ngap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint(ngap_ies_p2_dissector_table, ngap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
*/

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  ngap_ctx_t ngap_ctx;
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  ngap_ctx.message_type        = ngap_data->message_type;
  ngap_ctx.ProcedureCode       = ngap_data->procedure_code;
  ngap_ctx.ProtocolIE_ID       = ngap_data->protocol_ie_id;
  ngap_ctx.ProtocolExtensionID = ngap_data->protocol_extension_id;

  return (dissector_try_uint_new(ngap_extension_dissector_table, ngap_data->protocol_extension_id, tvb, pinfo, tree, TRUE, &ngap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint_new(ngap_proc_imsg_dissector_table, ngap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint_new(ngap_proc_sout_dissector_table, ngap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint_new(ngap_proc_uout_dissector_table, ngap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}


static void
ngap_stats_tree_init(stats_tree *st)
{
    st_node_packets = stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, TRUE);
    st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
}

static tap_packet_status
ngap_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
                       epan_dissect_t* edt _U_ , const void* p, tap_flags_t flags _U_)
{
    const struct ngap_tap_t *pi = (const struct ngap_tap_t *) p;

    tick_stat_node(st, st_str_packets, 0, FALSE);
    stats_tree_tick_pivot(st, st_node_packet_types,
                          val_to_str(pi->ngap_mtype, mtype_names,
                                     "Unknown packet type (%d)"));
    return TAP_PACKET_REDRAW;
}

static void set_stats_message_type(packet_info *pinfo, int type)
{
    struct ngap_private_data* priv_data = ngap_get_private_data(pinfo);
    priv_data->stats_tap->ngap_mtype = type;
}


static int
dissect_ngap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ngap_item = NULL;
  proto_tree *ngap_tree = NULL;
  conversation_t *conversation;
  struct ngap_private_data *ngap_data;
  struct ngap_tap_t *ngap_info;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NGAP");
  col_clear(pinfo->cinfo, COL_INFO);

  ngap_info = wmem_new(pinfo->pool, struct ngap_tap_t);
  ngap_info->ngap_mtype = 0; /* unknown/invalid */

  /* create the ngap protocol tree */
  ngap_item = proto_tree_add_item(tree, proto_ngap, tvb, 0, -1, ENC_NA);
  ngap_tree = proto_item_add_subtree(ngap_item, ett_ngap);

  /* Store top-level tree */
  top_tree = ngap_tree;

  /* Add stats tap to private struct */
  struct ngap_private_data *priv_data = ngap_get_private_data(pinfo);
  priv_data->stats_tap = ngap_info;

  ngap_data = ngap_get_private_data(pinfo);
  conversation = find_or_create_conversation(pinfo);
  ngap_data->ngap_conv = (struct ngap_conv_info *)conversation_get_proto_data(conversation, proto_ngap);
  if (!ngap_data->ngap_conv) {
    ngap_data->ngap_conv = wmem_new0(wmem_file_scope(), struct ngap_conv_info);
    copy_address_wmem(wmem_file_scope(), &ngap_data->ngap_conv->addr_a, &pinfo->src);
    ngap_data->ngap_conv->port_a = pinfo->srcport;
    ngap_data->ngap_conv->ranmode_id_a = (GlobalRANNodeID_enum)-1;
    copy_address_wmem(wmem_file_scope(), &ngap_data->ngap_conv->addr_b, &pinfo->dst);
    ngap_data->ngap_conv->port_b = pinfo->destport;
    ngap_data->ngap_conv->ranmode_id_b = (GlobalRANNodeID_enum)-1;
    ngap_data->ngap_conv->nbiot_ta = wmem_map_new(wmem_file_scope(), wmem_int64_hash, g_int64_equal);
    ngap_data->ngap_conv->nbiot_ran_ue_ngap_id = wmem_tree_new(wmem_file_scope());
    conversation_add_proto_data(conversation, proto_ngap, ngap_data->ngap_conv);
  }

  dissect_NGAP_PDU_PDU(tvb, pinfo, ngap_tree, NULL);

  tap_queue_packet(ngap_tap, pinfo, ngap_info);
  return tvb_captured_length(tvb);
}

static gboolean
find_n2_info_content(char *json_data, jsmntok_t *token, const char *n2_info_content,
                     const char *content_id, dissector_handle_t *subdissector)
{
  jsmntok_t *n2_info_content_token, *ngap_data_token;
  char *str;
  gdouble ngap_msg_type;

  n2_info_content_token = json_get_object(json_data, token, n2_info_content);
  if (!n2_info_content_token)
    return FALSE;
  ngap_data_token = json_get_object(json_data, n2_info_content_token, "ngapData");
  if (!ngap_data_token)
    return FALSE;
  str = json_get_string(json_data, ngap_data_token, "contentId");
  if (!str || strcmp(str, content_id))
    return FALSE;
  str = json_get_string(json_data, n2_info_content_token, "ngapIeType");
  if (str)
    *subdissector = dissector_get_string_handle(ngap_n2_ie_type_dissector_table, str);
  else if (json_get_double(json_data, n2_info_content_token, "ngapMessageType", &ngap_msg_type))
    *subdissector = ngap_handle;
  else
    *subdissector = NULL;
  return TRUE;
}

/* 3GPP TS 29.502 chapter 6.1.6.4.3 and 29.518 chapter 6.1.6.4.3 */
static int
dissect_ngap_media_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  int ret;
  char *json_data;
  const char *n2_info_class;
  jsmntok_t *tokens, *cur_tok;
  dissector_handle_t subdissector = NULL;
  tvbuff_t* json_tvb = (tvbuff_t*)p_get_proto_data(pinfo->pool, pinfo, proto_json, 0);
  http_message_info_t *message_info = (http_message_info_t *)data;

  if (!json_tvb || !message_info || !message_info->content_id)
    return 0;

  json_data = tvb_get_string_enc(pinfo->pool, json_tvb, 0, tvb_reported_length(json_tvb), ENC_UTF_8|ENC_NA);
  ret = json_parse(json_data, NULL, 0);
  if (ret <= 0)
    return 0;
  tokens = wmem_alloc_array(pinfo->pool, jsmntok_t, ret);
  if (json_parse(json_data, tokens, ret) <= 0)
    return 0;
  cur_tok = json_get_object(json_data, tokens, "n2InfoContainer");
  if (!cur_tok) {
      /* look for n2Information too*/
      cur_tok = json_get_object(json_data, tokens, "n2Information");
  }
  if (cur_tok) {
    n2_info_class = json_get_string(json_data, cur_tok, "n2InformationClass");
    if (n2_info_class) {
      if (!strcmp(n2_info_class, "SM")) {
        cur_tok = json_get_object(json_data, cur_tok, "smInfo");
        if (cur_tok && find_n2_info_content(json_data, cur_tok, "n2InfoContent",
                                            message_info->content_id, &subdissector))
          goto found;
      }
      if (!strcmp(n2_info_class, "RAN")) {
        cur_tok = json_get_object(json_data, cur_tok, "ranInfo");
        if (cur_tok && find_n2_info_content(json_data, cur_tok, "n2InfoContent",
                                            message_info->content_id, &subdissector))
          goto found;
      }
      if (!strcmp(n2_info_class, "NRPPa")) {
        cur_tok = json_get_object(json_data, cur_tok, "nrppaInfo");
        if (cur_tok && find_n2_info_content(json_data, cur_tok, "nrppaPdu",
                                            message_info->content_id, &subdissector))
          goto found;
      }
      if (!strcmp(n2_info_class, "PWS") ||
          !strcmp(n2_info_class, "PWS-BCAL") ||
          !strcmp(n2_info_class, "PWS-RF")) {
        cur_tok = json_get_object(json_data, cur_tok, "pwsInfo");
        if (cur_tok && find_n2_info_content(json_data, cur_tok, "pwsContainer",
                                            message_info->content_id, &subdissector))
          goto found;
      }
    }
  }
  cur_tok = json_get_object(json_data, tokens, "n2SmInfo");
  if (cur_tok) {
    const char *content_id_str = json_get_string(json_data, cur_tok, "contentId");
    if (content_id_str && !strcmp(content_id_str, message_info->content_id)) {
      const char *str = json_get_string(json_data, tokens, "n2SmInfoType");
      if (str)
        subdissector = dissector_get_string_handle(ngap_n2_ie_type_dissector_table, str);
      else
        subdissector = NULL;
      goto found;
    }
  }
  cur_tok = json_get_array(json_data, tokens, "pduSessionList");
  if (cur_tok) {
    int i, count;
    count = json_get_array_len(cur_tok);
    for (i = 0; i < count; i++) {
      jsmntok_t *array_tok = json_get_array_index(cur_tok, i);
      if (find_n2_info_content(json_data, array_tok, "n2InfoContent",
                               message_info->content_id, &subdissector))
        goto found;
    }
  }
  if (find_n2_info_content(json_data, tokens, "sourceToTargetData",
                           message_info->content_id, &subdissector))
    goto found;
  if (find_n2_info_content(json_data, tokens, "targetToSourceData",
                           message_info->content_id, &subdissector))
    goto found;
  if (find_n2_info_content(json_data, tokens, "targetToSourceFailureData",
                           message_info->content_id, &subdissector))
    goto found;
  if (find_n2_info_content(json_data, tokens, "ueRadioCapability",
                           message_info->content_id, &subdissector))
    goto found;

found:
  if (subdissector) {
    proto_item *ngap_item;
    proto_tree *ngap_tree;
    gboolean save_writable;

    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "NGAP");
    if (subdissector != ngap_handle) {
        ngap_item = proto_tree_add_item(tree, proto_ngap, tvb, 0, -1, ENC_NA);
        ngap_tree = proto_item_add_subtree(ngap_item, ett_ngap);
    } else {
        ngap_tree = tree;
    }
    save_writable = col_get_writable(pinfo->cinfo, COL_PROTOCOL);
    col_set_writable(pinfo->cinfo, COL_PROTOCOL, FALSE);
    call_dissector_with_data(subdissector, tvb, pinfo, ngap_tree, NULL);
    col_set_writable(pinfo->cinfo, COL_PROTOCOL, save_writable);
    return tvb_captured_length(tvb);
  } else {
    return 0;
  }
}

void
apply_ngap_prefs(void)
{
  gbl_ngapSctpRange = prefs_get_range_value("ngap", "sctp.port");
}

/*--- proto_reg_handoff_ngap ---------------------------------------*/
void
proto_reg_handoff_ngap(void)
{
  nas_5gs_handle = find_dissector_add_dependency("nas-5gs", proto_ngap);
  nr_rrc_ue_radio_paging_info_handle = find_dissector_add_dependency("nr-rrc.ue_radio_paging_info", proto_ngap);
  nr_rrc_ue_radio_access_cap_info_handle = find_dissector_add_dependency("nr-rrc.ue_radio_access_cap_info", proto_ngap);
  lte_rrc_ue_radio_paging_info_handle = find_dissector_add_dependency("lte-rrc.ue_radio_paging_info", proto_ngap);
  lte_rrc_ue_radio_access_cap_info_handle = find_dissector_add_dependency("lte-rrc.ue_radio_access_cap_info", proto_ngap);
  lte_rrc_ue_radio_paging_info_nb_handle = find_dissector_add_dependency("lte-rrc.ue_radio_paging_info.nb", proto_ngap);
  lte_rrc_ue_radio_access_cap_info_nb_handle = find_dissector_add_dependency("lte-rrc.ue_radio_access_cap_info.nb", proto_ngap);
  dissector_add_uint("sctp.ppi", NGAP_PROTOCOL_ID,   ngap_handle);
#include "packet-ngap-dis-tab.c"

  dissector_add_string("media_type", "application/vnd.3gpp.ngap", ngap_media_type_handle);

  nrppa_handle = find_dissector_add_dependency("nrppa", proto_ngap);
  proto_json = proto_get_id_by_filter_name("json");

  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_NGAP, ngap_handle);

  stats_tree_register("ngap", "ngap", "NGAP", 0,
                      ngap_stats_tree_packet, ngap_stats_tree_init, NULL);
  apply_ngap_prefs();
}

/*--- proto_register_ngap -------------------------------------------*/
void proto_register_ngap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_ngap_transportLayerAddressIPv4,
      { "TransportLayerAddress (IPv4)", "ngap.TransportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_transportLayerAddressIPv6,
      { "TransportLayerAddress (IPv6)", "ngap.TransportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WarningMessageContents_nb_pages,
      { "Number of Pages", "ngap.WarningMessageContents.nb_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SerialNumber_gs,
      { "Geographical Scope", "ngap.SerialNumber.gs",
        FT_UINT16, BASE_DEC, VALS(ngap_serialNumber_gs_vals), 0xc000,
        NULL, HFILL }},
    { &hf_ngap_SerialNumber_msg_code,
      { "Message Code", "ngap.SerialNumber.msg_code",
        FT_UINT16, BASE_DEC, NULL, 0x3ff0,
        NULL, HFILL }},
    { &hf_ngap_SerialNumber_upd_nb,
      { "Update Number", "ngap.SerialNumber.upd_nb",
        FT_UINT16, BASE_DEC, NULL, 0x000f,
        NULL, HFILL }},
    { &hf_ngap_WarningType_value,
      { "Warning Type Value", "ngap.WarningType.value",
        FT_UINT16, BASE_DEC, VALS(ngap_warningType_vals), 0xfe00,
        NULL, HFILL }},
    { &hf_ngap_WarningType_emergency_user_alert,
      { "Emergency User Alert", "ngap.WarningType.emergency_user_alert",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
        NULL, HFILL }},
    { &hf_ngap_WarningType_popup,
      { "Popup", "ngap.WarningType.popup",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
        NULL, HFILL }},
    { &hf_ngap_WarningMessageContents_decoded_page,
      { "Decoded Page", "ngap.WarningMessageContents.decoded_page",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGRANTraceID_TraceID,
      { "TraceID", "ngap.NGRANTraceID.TraceID",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGRANTraceID_TraceRecordingSessionReference,
      { "TraceRecordingSessionReference", "ngap.NGRANTraceID.TraceRecordingSessionReference",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_NG_C,
      { "NG-C", "ngap.InterfacesToTrace.NG_C",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_Xn_C,
      { "Xn-C", "ngap.InterfacesToTrace.Xn_C",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_Uu,
      { "Uu", "ngap.InterfacesToTrace.Uu",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_F1_C,
      { "F1-C", "ngap.InterfacesToTrace.F1_C",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_E1,
      { "E1", "ngap.InterfacesToTrace.E1",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_reserved,
      { "Reserved", "ngap.InterfacesToTrace.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictionInformation_e_UTRA,
      { "e-UTRA", "ngap.RATRestrictionInformation.e_UTRA",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictionInformation_nR,
      { "nR", "ngap.RATRestrictionInformation.nR",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictionInformation_nR_unlicensed,
      { "nR-unlicensed", "ngap.RATRestrictionInformation.nR_unlicensed",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x20,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictionInformation_reserved,
      { "reserved", "ngap.RATRestrictionInformation.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x1f,
        NULL, HFILL }},
    { &hf_ngap_primaryRATRestriction_e_UTRA,
      { "e-UTRA", "ngap.primaryRATRestriction.e_UTRA",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
        NULL, HFILL }},
    { &hf_ngap_primaryRATRestriction_nR,
      { "nR", "ngap.primaryRATRestriction.nR",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
        NULL, HFILL }},
    { &hf_ngap_primaryRATRestriction_nR_unlicensed,
      { "nR-unlicensed", "ngap.primaryRATRestriction.nR_unlicensed",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x20,
        NULL, HFILL }},
    { &hf_ngap_primaryRATRestriction_nR_LEO,
      { "nR-LEO", "ngap.primaryRATRestriction.nR_LEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x10,
        NULL, HFILL }},
    { &hf_ngap_primaryRATRestriction_nR_MEO,
      { "nR-MEO", "ngap.primaryRATRestriction.nR_MEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x08,
        NULL, HFILL }},
    { &hf_ngap_primaryRATRestriction_nR_GEO,
      { "nR-GEO", "ngap.primaryRATRestriction.nR_GEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x04,
        NULL, HFILL }},
    { &hf_ngap_primaryRATRestriction_nR_OTHERSAT,
      { "nR-OTHERSAT", "ngap.primaryRATRestriction.nR_OTHERSAT",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x02,
        NULL, HFILL }},
    { &hf_ngap_primaryRATRestriction_reserved,
      { "reserved", "ngap.primaryRATRestriction.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ngap_secondaryRATRestriction_e_UTRA,
      { "e-UTRA", "ngap.secondaryRATRestriction.e_UTRA",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
        NULL, HFILL }},
    { &hf_ngap_secondaryRATRestriction_nR,
      { "nR", "ngap.secondaryRATRestriction.nR",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
        NULL, HFILL }},
    { &hf_ngap_secondaryRATRestriction_e_UTRA_unlicensed,
      { "e-UTRA-unlicensed", "ngap.secondaryRATRestriction.e_UTRA_unlicensed",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x20,
        NULL, HFILL }},
    { &hf_ngap_secondaryRATRestriction_nR_unlicensed,
      { "nR-unlicensed", "ngap.secondaryRATRestriction.nR_unlicensed",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x10,
        NULL, HFILL }},
    { &hf_ngap_secondaryRATRestriction_reserved,
      { "reserved", "ngap.secondaryRATRestriction.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x0f,
        NULL, HFILL }},
	{ &hf_ngap_NrencryptionAlgorithms_nea1,
	  { "128-NEA1", "ngap.NrencryptionAlgorithms.nea1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
	{ &hf_ngap_NrencryptionAlgorithms_nea2,
	  { "128-NEA2", "ngap.NrencryptionAlgorithms.nea2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
	{ &hf_ngap_NrencryptionAlgorithms_nea3,
	  { "128-NEA3", "ngap.NrencryptionAlgorithms.nea3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
	{ &hf_ngap_NrencryptionAlgorithms_reserved,
	  { "Reserved", "ngap.NrencryptionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_nia1,
      { "128-NIA1", "ngap.NrintegrityProtectionAlgorithms.nia1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_nia2,
      { "128-NIA2", "ngap.NrintegrityProtectionAlgorithms.nia2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_nia3,
      { "128-NIA3", "ngap.NrintegrityProtectionAlgorithms.nia3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_reserved,
      { "Reserved", "ngap.NrintegrityProtectionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_eea1,
      { "128-EEA1", "ngap.EUTRAencryptionAlgorithms.eea1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_eea2,
      { "128-EEA2", "ngap.EUTRAencryptionAlgorithms.eea2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_eea3,
      { "128-EEA3", "ngap.EUTRAencryptionAlgorithms.eea3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_reserved,
      { "Reserved", "ngap.EUTRAencryptionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia1,
      { "128-EIA1", "ngap.EUTRAintegrityProtectionAlgorithms.eia1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia2,
      { "128-EIA2", "ngap.EUTRAintegrityProtectionAlgorithms.eia2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia3,
      { "128-EIA3", "ngap.EUTRAintegrityProtectionAlgorithms.eia3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_reserved,
      { "Reserved", "ngap.EUTRAintegrityProtectionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_ngap_MeasurementsToActivate_M1,
      { "M1", "ngap.MeasurementsToActivate.M1",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x80,
        NULL, HFILL }},
    { &hf_ngap_MeasurementsToActivate_M2,
      { "M2", "ngap.MeasurementsToActivate.M2",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x40,
        NULL, HFILL }},
    { &hf_ngap_MeasurementsToActivate_M4,
      { "M4", "ngap.MeasurementsToActivate.M4",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x20,
        NULL, HFILL }},
    { &hf_ngap_MeasurementsToActivate_M5,
      { "M5", "ngap.MeasurementsToActivate.M5",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x10,
        NULL, HFILL }},
    { &hf_ngap_MeasurementsToActivate_M6,
      { "M6", "ngap.MeasurementsToActivate.M6",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x08,
        NULL, HFILL }},
    { &hf_ngap_MeasurementsToActivate_M7,
      { "M7", "ngap.MeasurementsToActivate.M7",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x04,
        NULL, HFILL }},
    { &hf_ngap_MeasurementsToActivate_M1_from_event,
      { "M1 from event", "ngap.MeasurementsToActivate.M1_from_event",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x02,
        NULL, HFILL }},
    { &hf_ngap_MeasurementsToActivate_reserved,
      { "Reserved", "ngap.MeasurementsToActivate.reserved",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ngap_MDT_Location_Information_GNSS,
      { "GNSS", "ngap.MDT_Location_Information.GNSS",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x80,
        NULL, HFILL }},
    { &hf_ngap_MDT_Location_Information_reserved,
      { "Reserved", "ngap.MDT_Location_Information.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x7f,
        NULL, HFILL }},
    { &hf_ngap_GlobalCable_ID_str,
      { "GlobalCable-ID", "ngap.GlobalCable_ID.str",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UpdateFeedback_CN_PDB_DL,
      { "CN PDB DL", "ngap.UpdateFeedback.CN_PDB_DL",
        FT_BOOLEAN, 8, TFS(&ngap_not_updated_updated), 0x80,
        NULL, HFILL }},
    { &hf_ngap_UpdateFeedback_CN_PDB_UL,
      { "CN PDB UL", "ngap.UpdateFeedback.CN_PDB_UL",
        FT_BOOLEAN, 8, TFS(&ngap_not_updated_updated), 0x40,
        NULL, HFILL }},
    { &hf_ngap_UpdateFeedback_reserved,
      { "Reserved", "ngap.UpdateFeedback.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x3f,
        NULL, HFILL }},
#include "packet-ngap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ngap,
    &ett_ngap_TransportLayerAddress,
    &ett_ngap_DataCodingScheme,
    &ett_ngap_SerialNumber,
    &ett_ngap_WarningType,
    &ett_ngap_WarningMessageContents,
    &ett_ngap_PLMNIdentity,
    &ett_ngap_NGAP_Message,
    &ett_ngap_NGRANTraceID,
    &ett_ngap_InterfacesToTrace,
    &ett_ngap_SourceToTarget_TransparentContainer,
    &ett_ngap_TargetToSource_TransparentContainer,
    &ett_ngap_RRCContainer,
    &ett_ngap_RATRestrictionInformation,
    &ett_ngap_primaryRATRestriction,
    &ett_ngap_secondaryRATRestriction,
    &ett_ngap_NrencryptionAlgorithms,
    &ett_ngap_NrintegrityProtectionAlgorithms,
    &ett_ngap_EUTRAencryptionAlgorithms,
    &ett_ngap_EUTRAintegrityProtectionAlgorithms,
    &ett_ngap_UERadioCapabilityForPagingOfNR,
    &ett_ngap_UERadioCapabilityForPagingOfEUTRA,
    &ett_ngap_UERadioCapability,
    &ett_ngap_LastVisitedEUTRANCellInformation,
    &ett_ngap_LastVisitedUTRANCellInformation,
    &ett_ngap_LastVisitedGERANCellInformation,
    &ett_ngap_NASSecurityParametersFromNGRAN,
    &ett_ngap_NASC,
    &ett_ngap_NAS_PDU,
    &ett_ngap_EN_DCSONConfigurationTransfer,
    &ett_ngap_BurstArrivalTime,
    &ett_ngap_CoverageEnhancementLevel,
    &ett_ngap_MDTModeEutra,
    &ett_ngap_MeasurementsToActivate,
    &ett_ngap_MDT_Location_Information,
    &ett_ngap_NRMobilityHistoryReport,
    &ett_ngap_LTEUERLFReportContainer,
    &ett_ngap_NRUERLFReportContainer,
    &ett_ngap_TargettoSource_Failure_TransparentContainer,
    &ett_ngap_UERadioCapabilityForPagingOfNB_IoT,
    &ett_ngap_GlobalCable_ID,
    &ett_ngap_UpdateFeedback,
    &ett_ngap_successfulHOReportContainer,
#include "packet-ngap-ettarr.c"
  };

  static ei_register_info ei[] = {
    { &ei_ngap_number_pages_le15, { "ngap.number_pages_le15", PI_MALFORMED, PI_ERROR, "Number of pages should be <=15", EXPFILL }}
  };

  module_t *ngap_module;
  expert_module_t* expert_ngap;

  /* Register protocol */
  proto_ngap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ngap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_ngap = expert_register_protocol(proto_ngap);
  expert_register_field_array(expert_ngap, ei, array_length(ei));

  /* Register dissector */
  ngap_handle = register_dissector("ngap", dissect_ngap, proto_ngap);
  ngap_media_type_handle = register_dissector("ngap_media_type", dissect_ngap_media_type, proto_ngap);

  /* Register dissector tables */
  ngap_ies_dissector_table = register_dissector_table("ngap.ies", "NGAP-PROTOCOL-IES", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_ies_p1_dissector_table = register_dissector_table("ngap.ies.pair.first", "NGAP-PROTOCOL-IES-PAIR FirstValue", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_ies_p2_dissector_table = register_dissector_table("ngap.ies.pair.second", "NGAP-PROTOCOL-IES-PAIR SecondValue", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_extension_dissector_table = register_dissector_table("ngap.extension", "NGAP-PROTOCOL-EXTENSION", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_imsg_dissector_table = register_dissector_table("ngap.proc.imsg", "NGAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_sout_dissector_table = register_dissector_table("ngap.proc.sout", "NGAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_uout_dissector_table = register_dissector_table("ngap.proc.uout", "NGAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_n2_ie_type_dissector_table = register_dissector_table("ngap.n2_ie_type", "NGAP N2 IE Type", proto_ngap, FT_STRING, FALSE);

  /* Register configuration options for ports */
  ngap_module = prefs_register_protocol(proto_ngap, apply_ngap_prefs);

  prefs_register_bool_preference(ngap_module, "dissect_container",
                                 "Dissect TransparentContainer",
                                 "Dissect TransparentContainers that are opaque to NGAP",
                                 &ngap_dissect_container);
  prefs_register_enum_preference(ngap_module, "dissect_target_ng_ran_container_as",
                                 "Dissect target NG-RAN container as",
                                 "Select whether target NG-RAN container should be decoded automatically"
                                 " (based on NG Setup procedure) or manually",
                                 &ngap_dissect_target_ng_ran_container_as, ngap_target_ng_ran_container_vals, FALSE);
  prefs_register_enum_preference(ngap_module, "dissect_lte_container_as", "Dissect LTE container as",
                                 "Select whether LTE container should be dissected as NB-IOT or legacy LTE",
                                 &ngap_dissect_lte_container_as, ngap_lte_container_vals, FALSE);

  ngap_tap = register_tap("ngap");
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
