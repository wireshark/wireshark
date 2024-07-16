/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-inap.c                                                              */
/* asn2wrs.py -b -q -L -p inap -c ./inap.cnf -s ./packet-inap-template -D . -O ../.. IN-common-classes.asn IN-SSF-SCF-Classes.asn IN-SCF-SRF-Classes.asn IN-operationcodes.asn IN-object-identifiers.asn IN-common-datatypes.asn IN-SSF-SCF-datatypes.asn IN-SSF-SCF-ops-args.asn IN-SCF-SRF-datatypes.asn IN-SCF-SRF-ops-args.asn IN-errorcodes.asn IN-errortypes.asn ../ros/Remote-Operations-Information-Objects.asn ../ros/Remote-Operations-Generic-ROS-PDUs.asn */

/* packet-inap-template.c
 * Routines for INAP
 * Copyright 2004, Tim Endean <endeant@hotmail.com>
 * Built from the gsm-map dissector Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References: ETSI 300 374
 * ITU Q.1218
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/expert.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-inap.h"
#include "packet-q931.h"
#include "packet-e164.h"
#include "packet-isup.h"
#include "packet-tcap.h"
#include "packet-dap.h"
#include "packet-dsp.h"

#define PNAME  "Intelligent Network Application Protocol"
#define PSNAME "INAP"
#define PFNAME "inap"

void proto_register_inap(void);
void proto_reg_handoff_inap(void);


/* Initialize the protocol and registered fields */
static int proto_inap;

/* include constants */
#define opcode_initialDP               0
#define opcode_originationAttemptAuthorized 1
#define opcode_collectedInformation    2
#define opcode_analysedInformation     3
#define opcode_routeSelectFailure      4
#define opcode_oCalledPartyBusy        5
#define opcode_oNoAnswer               6
#define opcode_oAnswer                 7
#define opcode_oDisconnect             8
#define opcode_termAttemptAuthorized   9
#define opcode_tBusy                   10
#define opcode_tNoAnswer               11
#define opcode_tAnswer                 12
#define opcode_tDisconnect             13
#define opcode_facilitySelectedAndAvailable 80
#define opcode_originationAttempt      81
#define opcode_terminationAttempt      82
#define opcode_oAbandon                83
#define opcode_oMidCall                14
#define opcode_tMidCall                15
#define opcode_oSuspended              84
#define opcode_tSuspended              85
#define opcode_assistRequestInstructions 16
#define opcode_establishTemporaryConnection 17
#define opcode_disconnectForwardConnection 18
#define opcode_dFCWithArgument         86
#define opcode_connectToResource       19
#define opcode_connect                 20
#define opcode_holdCallInNetwork       21
#define opcode_releaseCall             22
#define opcode_requestReportBCSMEvent  23
#define opcode_eventReportBCSM         24
#define opcode_requestNotificationChargingEvent 25
#define opcode_eventNotificationCharging 26
#define opcode_collectInformation      27
#define opcode_analyseInformation      28
#define opcode_selectRoute             29
#define opcode_selectFacility          30
#define opcode_continue                31
#define opcode_authorizeTermination    87
#define opcode_initiateCallAttempt     32
#define opcode_resetTimer              33
#define opcode_furnishChargingInformation 34
#define opcode_applyCharging           35
#define opcode_applyChargingReport     36
#define opcode_requestCurrentStatusReport 37
#define opcode_requestEveryStatusChangeReport 38
#define opcode_requestFirstStatusMatchReport 39
#define opcode_statusReport            40
#define opcode_callGap                 41
#define opcode_callFiltering           145
#define opcode_activateServiceFiltering 42
#define opcode_serviceFilteringResponse 43
#define opcode_callInformationReport   44
#define opcode_callInformationRequest  45
#define opcode_sendChargingInformation 46
#define opcode_playAnnouncement        47
#define opcode_promptAndCollectUserInformation 48
#define opcode_specializedResourceReport 49
#define opcode_cancel                  53
#define opcode_cancelStatusReportRequest 54
#define opcode_activityTest            55
#define opcode_continueWithArgument    88
#define opcode_createCallSegmentAssociation 89
#define opcode_disconnectLeg           90
#define opcode_mergeCallSegments       91
#define opcode_moveCallSegments        92
#define opcode_moveLeg                 93
#define opcode_reconnect               94
#define opcode_splitLeg                95
#define opcode_entityReleased          96
#define opcode_manageTriggerData       97
#define opcode_createOrRemoveTriggerData 135
#define opcode_setServiceProfile       136
#define opcode_requestReportUTSI       98
#define opcode_sendSTUI                100
#define opcode_reportUTSI              101
#define opcode_sendFacilityInformation 102
#define opcode_requestReportFacilityEvent 103
#define opcode_eventReportFacility     104
#define opcode_monitorRouteRequest     146
#define opcode_monitorRouteReport      147
#define opcode_promptAndReceiveMessage 107
#define opcode_scriptInformation       108
#define opcode_scriptEvent             109
#define opcode_scriptRun               110
#define opcode_scriptClose             111
#define opcode_srfCallGap              139
#define opcode_establishChargingRecord 112
#define opcode_handlingInformationRequest 113
#define opcode_handlingInformationResult 114
#define opcode_networkCapability       115
#define opcode_notificationProvided    116
#define opcode_confirmedNotificationProvided 117
#define opcode_provideUserInformation  118
#define opcode_confirmedReportChargingInformation 119
#define opcode_reportChargingInformation 120
#define opcode_requestNotification     121
#define opcode_runUserScript           140
#define opcode_transferSTSI            141
#define opcode_announcementCompletionReport 142
#define opcode_initiateCallRequest     143
#define opcode_provideAnnouncementRequest 144
#define opcode_execute                 10
#define opcode_trafficFlowControl      138
#define opcode_activationReceivedAndAuthorized 122
#define opcode_initiateAssociation     123
#define opcode_associationReleaseRequested 124
#define opcode_componentReceived       125
#define opcode_releaseAssociation      126
#define opcode_requestReportBCUSMEvent 127
#define opcode_sendComponent           130
#define opcode_connectAssociation      132
#define opcode_continueAssociation     133
#define opcode_eventReportBCUSM        134
#define opcode_initialAssociationDP    131
#define tc_Messages                    "0.0.17.773.2.1.3"
#define tc_NotationExtensions          "0.0.17.775.2.4.1"
#define ros_InformationObjects         "2.4.5.0"
#define ros_genericPDUs                "2.4.6.0"
#define ros_UsefulDefinitions          "2.4.7.0"
#define sese_APDUs                     "2.20.1.6"
#define guls_Notation                  "2.20.1.1"
#define guls_SecurityTransformations   "2.20.1.3"
#define guls_DirectoryProtectionMappings "2.20.1.4"
#define ds_UsefulDefinitions           "2.5.1.0.3"
#define spkmGssTokens                  "1.3.6.1.5.5.1.10"
#define contexts                       "0.0.17.1218.0.8.1.1"
#define id                             "0.0.17.1248"
#define modules                        id".1"
#define id_ac                          id".3"
#define id_at                          id".4"
#define id_as                          id".5"
#define id_oc                          id".6"
#define id_mt                          id".7"
#define id_sf                          id".11"
#define id_soa                         id".21"
#define id_aca                         id".24"
#define id_rosObject                   id".25"
#define id_contract                    id".26"
#define id_package                     id".27"
#define id_avc                         id".29"
#define object_identifiers             modules".0.0"
#define common_datatypes               modules".1.0"
#define errortypes                     modules".2.0"
#define operationcodes                 modules".3.0"
#define errorcodes                     modules".4.0"
#define common_classes                 modules".5.0"
#define ssf_scf_datatypes              modules".6.0"
#define ssf_scf_classes                modules".7.0"
#define ssf_scf_Operations             modules".8.0"
#define ssf_scf_Protocol               modules".9.0"
#define scf_srf_datatypes              modules".10.0"
#define scf_srf_classes                modules".11.0"
#define scf_srf_Operations             modules".12.0"
#define scf_srf_Protocol               modules".13.0"
#define scf_sdf_datatypes              modules".14.0"
#define scf_sdf_classes                modules".15.0"
#define scf_sdf_Operations             modules".16.0"
#define scf_sdf_Protocol               modules".17.0"
#define sdf_sdf_Operations             modules".18.0"
#define sdf_sdf_Protocol               modules".19.0"
#define scf_scf_datatypes              modules".20.0"
#define scf_scf_classes                modules".21.0"
#define scf_scf_Operations             modules".22.0"
#define scf_scf_Protocol               modules".23.0"
#define scf_cusf_datatypes             modules".24.0"
#define scf_cusf_classes               modules".25.0"
#define scf_cusf_Operations            modules".26.0"
#define scf_cusf_Protocol              modules".27.0"
#define scf_sdf_Additional_Definitions modules".28.0"
#define id_ac_ssf_scfGenericAC         id_ac".4.0"
#define id_ac_ssf_scfDPSpecificAC      id_ac".5.0"
#define id_ac_ssf_scfAssistHandoffAC   id_ac".6.0"
#define id_ac_ssf_scfServiceManagementAC id_ac".7.0"
#define id_ac_scf_ssfGenericAC         id_ac".8.0"
#define id_ac_scf_ssfDPSpecificAC      id_ac".9.0"
#define id_ac_scf_ssfINTrafficManagementAC id_ac".10.0"
#define id_ac_scf_ssfServiceManagementAC id_ac".11.0"
#define id_ac_scf_ssfStatusReportingAC id_ac".12.0"
#define id_ac_scf_ssfTriggerManagementAC id_ac".13.0"
#define id_ac_scf_ssfRouteMonitoringAC id_ac".33.0"
#define id_ac_ssf_scfRouteMonitoringAC id_ac".34.0"
#define id_ac_scf_ssfTrafficManagementAC id_ac".35.0"
#define id_ac_srf_scfAC                id_ac".14.0"
#define id_ac_indirectoryAccessAC      id_ac".1.0"
#define id_ac_indirectoryAccessWith3seAC id_ac".2.0"
#define id_ac_inExtendedDirectoryAccessAC id_ac".3.0"
#define id_ac_inExtendedDirectoryAccessWith3seAC id_ac".27.0"
#define id_ac_trafficFlowControlAC     id_ac".28.0"
#define id_ac_indirectorySystemAC      id_ac".15.0"
#define id_ac_inShadowSupplierInitiatedAC id_ac".16.0"
#define id_ac_inShadowConsumerInitiatedAC id_ac".17.0"
#define id_ac_indirectorySystemWith3seAC id_ac".18.0"
#define id_ac_inShadowSupplierInitiatedWith3seAC id_ac".19.0"
#define id_ac_inShadowConsumerInitiatedWith3seAC id_ac".20.0"
#define id_ac_scfc_scfsOperationsAC    id_ac".21.0"
#define id_ac_distributedSCFSystemAC   id_ac".22.0"
#define id_ac_scfc_scfsOperationsWith3seAC id_ac".23.0"
#define id_ac_distributedSCFSystemWith3seAC id_ac".24.0"
#define id_ac_scfs_scfcOperationsAC    id_ac".31.0"
#define id_ac_scfs_scfcOperationsWith3seAC id_ac".32.0"
#define id_acscfcusfDPSpecific         id_ac".25.0"
#define id_accusfscfDPSpecific         id_ac".26.0"
#define id_acscfcusfGeneric            id_ac".29.0"
#define id_accusfscfGeneric            id_ac".30.0"
#define id_at_securityFacilityId       id_at".1"
#define id_at_secretKey                id_at".2"
#define id_at_identifierList           id_at".3"
#define id_at_bindLevelIfOK            id_at".4"
#define id_at_lockSession              id_at".5"
#define id_at_failureCounter           id_at".6"
#define id_at_maxAttempts              id_at".7"
#define id_at_currentList              id_at".8"
#define id_at_stockId                  id_at".9"
#define id_at_source                   id_at".10"
#define id_at_sizeOfRestocking         id_at".11"
#define id_at_challengeResponse        id_at".12"
#define id_as_ssf_scfGenericAS         id_as".4"
#define id_as_ssf_scfDpSpecificAS      id_as".5"
#define id_as_assistHandoff_ssf_scfAS  id_as".6"
#define id_as_scf_ssfGenericAS         id_as".7"
#define id_as_scf_ssfDpSpecificAS      id_as".8"
#define id_as_scf_ssfINTrafficManagementAS id_as".9"
#define id_as_scf_ssfServiceManagementAS id_as".10"
#define id_as_ssf_scfServiceManagementAS id_as".11"
#define id_as_scf_ssfStatusReportingAS id_as".12"
#define id_as_scf_ssfTriggerManagementAS id_as".13"
#define id_as_scf_ssfRouteMonitoringAS id_as".31"
#define id_as_ssf_scfRouteMonitoringAS id_as".32"
#define id_as_scf_ssfTrafficManagementAS id_as".33"
#define id_as_basic_srf_scf            id_as".14"
#define id_as_basic_scf_srf            id_as".15"
#define id_as_indirectoryOperationsAS  id_as".1"
#define id_as_indirectoryBindingAS     id_as".2"
#define id_as_inExtendedDirectoryOperationsAS id_as".3"
#define id_as_inSESEAS                 id_as".25"
#define id_as_tfcOperationsAS          id_as".26"
#define id_as_tfcBindingAS             id_as".27"
#define id_as_indirectorySystemAS      id_as".16"
#define id_as_indirectoryDSABindingAS  id_as".17"
#define id_as_indirectoryShadowAS      id_as".18"
#define id_as_indsaShadowBindingAS     id_as".19"
#define id_as_scfc_scfsOperationsAS    id_as".20"
#define id_as_distributedSCFSystemAS   id_as".21"
#define id_as_scf_scfBindingAS         id_as".22"
#define id_as_scfs_scfcOperationsAS    id_as".30"
#define id_asscfcusfDPSpecific         id_as".23"
#define id_ascusfscfDPSpecific         id_as".24"
#define id_asscfcusfGeneric            id_as".28"
#define id_ascusfscfGeneric            id_as".29"
#define id_oc_securityUserInfo         id_oc".1"
#define id_oc_tokensStock              id_oc".2"
#define id_mt_verifyCredentials        id_mt".1"
#define id_mt_conformCredentials       id_mt".2"
#define id_mt_provideTokens            id_mt".3"
#define id_mt_fillSecurityTokens       id_mt".4"
#define id_sf_pwd                      id_sf".1"
#define id_sf_challengeResponse        id_sf".2"
#define id_sf_onAirSubscription        id_sf".3"
#define id_soa_methodRuleUse           id_soa".1"
#define id_aca_prescriptiveACI         id_aca".4"
#define id_aca_entryACI                id_aca".5"
#define id_aca_subentryACI             id_aca".6"
#define id_rosObject_scf               id_rosObject".1"
#define id_rosObject_ssf               id_rosObject".2"
#define id_rosObject_srf               id_rosObject".3"
#define id_rosObject_sdf               id_rosObject".4"
#define id_rosObject_cusf              id_rosObject".5"
#define id_inSsfToScfGeneric           id_contract".3"
#define id_inSsfToScfDpSpecific        id_contract".4"
#define id_inAssistHandoffSsfToScf     id_contract".5"
#define id_inScfToSsfGeneric           id_contract".6"
#define id_inScfToSsfDpSpecific        id_contract".7"
#define id_inScfToSsfINTrafficManagement id_contract".8"
#define id_inScfToSsfServiceManagement id_contract".9"
#define id_inSsfToScfServiceManagement id_contract".10"
#define id_inScfToSsfStatusReporting   id_contract".11"
#define id_inScfToSsfTriggerManagement id_contract".12"
#define id_inScfToSsfRouteMonitoring   id_contract".26"
#define id_inSsfToScfRouteMonitoring   id_contract".27"
#define id_inScfToSsfTrafficManagement id_contract".28"
#define id_contract_srf_scf            id_contract".13"
#define id_contract_dap                id_contract".1"
#define id_contract_dapExecute         id_contract".2"
#define id_contract_tfc                id_contract".22"
#define id_contract_indsp              id_contract".14"
#define id_contract_shadowConsumer     id_contract".15"
#define id_contract_shadowSupplier     id_contract".17"
#define id_contract_scfc_scfs          id_contract".18"
#define id_contract_dssp               id_contract".19"
#define id_contract_scfs_scfc          id_contract".25"
#define id_contract_scfcusfDPSpecific  id_contract".20"
#define id_contract_cusfscfDPSpecific  id_contract".21"
#define id_contract_scfcusfGeneric     id_contract".23"
#define id_contract_cusfscfGeneric     id_contract".24"
#define id_package_emptyConnection     id_package".60"
#define id_package_scfActivation       id_package".11"
#define id_package_basicBCPDP          id_package".12"
#define id_package_advancedBCPDP       id_package".14"
#define id_package_srf_scfActivationOfAssist id_package".15"
#define id_package_assistConnectionEstablishment id_package".16"
#define id_package_genericDisconnectResource id_package".17"
#define id_package_nonAssistedConnectionEstablishment id_package".18"
#define id_package_connect             id_package".19"
#define id_package_callHandling        id_package".20"
#define id_package_bcsmEventHandling   id_package".21"
#define id_package_dpSpecificEventHandling id_package".22"
#define id_package_chargingEventHandling id_package".23"
#define id_package_ssfCallProcessing   id_package".24"
#define id_package_scfCallInitiation   id_package".25"
#define id_package_timer               id_package".26"
#define id_package_billing             id_package".27"
#define id_package_charging            id_package".28"
#define id_package_iNTrafficManagement id_package".29"
#define id_package_serviceManagementActivate id_package".30"
#define id_package_serviceManagementResponse id_package".31"
#define id_package_callReport          id_package".32"
#define id_package_signallingControl   id_package".33"
#define id_package_activityTest        id_package".34"
#define id_package_statusReporting     id_package".35"
#define id_package_cancel              id_package".36"
#define id_package_cphResponse         id_package".37"
#define id_package_entityReleased      id_package".38"
#define id_package_triggerManagement   id_package".39"
#define id_package_uSIHandling         id_package".40"
#define id_package_facilityIEHandling  id_package".41"
#define id_package_triggerCallManagement id_package".63"
#define id_package_monitorRoute        id_package".77"
#define id_package_trafficManagement   id_package".78"
#define id_package_specializedResourceControl id_package".42"
#define id_package_srf_scfCancel       id_package".43"
#define id_package_messageControl      id_package".44"
#define id_package_scriptControl       id_package".45"
#define id_package_srfManagement       id_package".66"
#define id_package_search              id_package".2"
#define id_package_modify              id_package".3"
#define id_package_dapConnection       id_package".10"
#define id_package_execute             id_package".4"
#define id_package_tfcOperations       id_package".64"
#define id_package_tfcConnection       id_package".65"
#define id_package_dspConnection       id_package".47"
#define id_package_inchainedModify     id_package".48"
#define id_package_inchainedSearch     id_package".49"
#define id_package_chainedExecute      id_package".50"
#define id_package_dispConnection      id_package".51"
#define id_package_shadowConsumer      id_package".52"
#define id_package_shadowSupplier      id_package".53"
#define id_package_scf_scfConnection   id_package".46"
#define id_package_dsspConnection      id_package".74"
#define id_package_handlingInformation id_package".54"
#define id_package_notification        id_package".55"
#define id_package_chargingInformation id_package".56"
#define id_package_userInformation     id_package".57"
#define id_package_networkCapability   id_package".58"
#define id_package_chainedSCFOperations id_package".59"
#define id_package_transferStsi        id_package".75"
#define id_package_initiateCall        id_package".76"
#define id_package_cusfTDPSpecificInvocation id_package".61"
#define id_package_cusfTDPGenericInvocation id_package".62"
#define id_package_cusfDPSpecificEventHandling id_package".67"
#define id_package_cusfGenericEventHandling id_package".68"
#define id_package_cusfComponentHandling id_package".69"
#define id_package_cusfSCFInitiation   id_package".70"
#define id_package_cusfContinue        id_package".71"
#define id_package_cusfConnect         id_package".72"
#define id_package_cusfRelease         id_package".73"
#define id_avc_assignment              id_avc".1"
#define id_avc_basicService            id_avc".2"
#define id_avc_lineIdentity            id_avc".3"
#define initialCallSegment             1
#define leg1                           0x01
#define leg2                           0x02
#define errcode_canceled               0
#define errcode_cancelFailed           1
#define errcode_eTCFailed              3
#define errcode_improperCallerResponse 4
#define errcode_missingCustomerRecord  6
#define errcode_missingParameter       7
#define errcode_parameterOutOfRange    8
#define errcode_requestedInfoError     10
#define errcode_systemFailure          11
#define errcode_taskRefused            12
#define errcode_unavailableResource    13
#define errcode_unexpectedComponentSequence 14
#define errcode_unexpectedDataValue    15
#define errcode_unexpectedParameter    16
#define errcode_unknownLegID           17
#define errcode_unknownResource        18
#define errcode_scfReferral            21
#define errcode_scfTaskRefused         22
#define errcode_chainingRefused        23
#define noInvokeId                     NULL

static int hf_inap_ActivateServiceFilteringArg_PDU;  /* ActivateServiceFilteringArg */
static int hf_inap_AnalysedInformationArg_PDU;    /* AnalysedInformationArg */
static int hf_inap_AnalyseInformationArg_PDU;     /* AnalyseInformationArg */
static int hf_inap_ApplyChargingArg_PDU;          /* ApplyChargingArg */
static int hf_inap_ApplyChargingReportArg_PDU;    /* ApplyChargingReportArg */
static int hf_inap_AssistRequestInstructionsArg_PDU;  /* AssistRequestInstructionsArg */
static int hf_inap_AuthorizeTerminationArg_PDU;   /* AuthorizeTerminationArg */
static int hf_inap_CallFilteringArg_PDU;          /* CallFilteringArg */
static int hf_inap_CallGapArg_PDU;                /* CallGapArg */
static int hf_inap_CallInformationReportArg_PDU;  /* CallInformationReportArg */
static int hf_inap_CallInformationRequestArg_PDU;  /* CallInformationRequestArg */
static int hf_inap_CancelArg_PDU;                 /* CancelArg */
static int hf_inap_CancelStatusReportRequestArg_PDU;  /* CancelStatusReportRequestArg */
static int hf_inap_CollectedInformationArg_PDU;   /* CollectedInformationArg */
static int hf_inap_CollectInformationArg_PDU;     /* CollectInformationArg */
static int hf_inap_ConnectArg_PDU;                /* ConnectArg */
static int hf_inap_ConnectToResourceArg_PDU;      /* ConnectToResourceArg */
static int hf_inap_ContinueWithArgumentArg_PDU;   /* ContinueWithArgumentArg */
static int hf_inap_CreateCallSegmentAssociationArg_PDU;  /* CreateCallSegmentAssociationArg */
static int hf_inap_CreateCallSegmentAssociationResultArg_PDU;  /* CreateCallSegmentAssociationResultArg */
static int hf_inap_CreateOrRemoveTriggerDataArg_PDU;  /* CreateOrRemoveTriggerDataArg */
static int hf_inap_CreateOrRemoveTriggerDataResultArg_PDU;  /* CreateOrRemoveTriggerDataResultArg */
static int hf_inap_DisconnectForwardConnectionWithArgumentArg_PDU;  /* DisconnectForwardConnectionWithArgumentArg */
static int hf_inap_DisconnectLegArg_PDU;          /* DisconnectLegArg */
static int hf_inap_EntityReleasedArg_PDU;         /* EntityReleasedArg */
static int hf_inap_EstablishTemporaryConnectionArg_PDU;  /* EstablishTemporaryConnectionArg */
static int hf_inap_EventNotificationChargingArg_PDU;  /* EventNotificationChargingArg */
static int hf_inap_EventReportBCSMArg_PDU;        /* EventReportBCSMArg */
static int hf_inap_EventReportFacilityArg_PDU;    /* EventReportFacilityArg */
static int hf_inap_FacilitySelectedAndAvailableArg_PDU;  /* FacilitySelectedAndAvailableArg */
static int hf_inap_FurnishChargingInformationArg_PDU;  /* FurnishChargingInformationArg */
static int hf_inap_HoldCallInNetworkArg_PDU;      /* HoldCallInNetworkArg */
static int hf_inap_InitialDPArg_PDU;              /* InitialDPArg */
static int hf_inap_InitiateCallAttemptArg_PDU;    /* InitiateCallAttemptArg */
static int hf_inap_ManageTriggerDataArg_PDU;      /* ManageTriggerDataArg */
static int hf_inap_ManageTriggerDataResultArg_PDU;  /* ManageTriggerDataResultArg */
static int hf_inap_MergeCallSegmentsArg_PDU;      /* MergeCallSegmentsArg */
static int hf_inap_MonitorRouteReportArg_PDU;     /* MonitorRouteReportArg */
static int hf_inap_MonitorRouteRequestArg_PDU;    /* MonitorRouteRequestArg */
static int hf_inap_MoveCallSegmentsArg_PDU;       /* MoveCallSegmentsArg */
static int hf_inap_MoveLegArg_PDU;                /* MoveLegArg */
static int hf_inap_OAbandonArg_PDU;               /* OAbandonArg */
static int hf_inap_OAnswerArg_PDU;                /* OAnswerArg */
static int hf_inap_OCalledPartyBusyArg_PDU;       /* OCalledPartyBusyArg */
static int hf_inap_ODisconnectArg_PDU;            /* ODisconnectArg */
static int hf_inap_MidCallArg_PDU;                /* MidCallArg */
static int hf_inap_ONoAnswerArg_PDU;              /* ONoAnswerArg */
static int hf_inap_OriginationAttemptArg_PDU;     /* OriginationAttemptArg */
static int hf_inap_OriginationAttemptAuthorizedArg_PDU;  /* OriginationAttemptAuthorizedArg */
static int hf_inap_OSuspendedArg_PDU;             /* OSuspendedArg */
static int hf_inap_ReconnectArg_PDU;              /* ReconnectArg */
static int hf_inap_ReleaseCallArg_PDU;            /* ReleaseCallArg */
static int hf_inap_ReportUTSIArg_PDU;             /* ReportUTSIArg */
static int hf_inap_RequestCurrentStatusReportArg_PDU;  /* RequestCurrentStatusReportArg */
static int hf_inap_RequestCurrentStatusReportResultArg_PDU;  /* RequestCurrentStatusReportResultArg */
static int hf_inap_RequestEveryStatusChangeReportArg_PDU;  /* RequestEveryStatusChangeReportArg */
static int hf_inap_RequestFirstStatusMatchReportArg_PDU;  /* RequestFirstStatusMatchReportArg */
static int hf_inap_RequestNotificationChargingEventArg_PDU;  /* RequestNotificationChargingEventArg */
static int hf_inap_RequestReportBCSMEventArg_PDU;  /* RequestReportBCSMEventArg */
static int hf_inap_RequestReportFacilityEventArg_PDU;  /* RequestReportFacilityEventArg */
static int hf_inap_RequestReportUTSIArg_PDU;      /* RequestReportUTSIArg */
static int hf_inap_ResetTimerArg_PDU;             /* ResetTimerArg */
static int hf_inap_RouteSelectFailureArg_PDU;     /* RouteSelectFailureArg */
static int hf_inap_SelectFacilityArg_PDU;         /* SelectFacilityArg */
static int hf_inap_SelectRouteArg_PDU;            /* SelectRouteArg */
static int hf_inap_SendChargingInformationArg_PDU;  /* SendChargingInformationArg */
static int hf_inap_SendFacilityInformationArg_PDU;  /* SendFacilityInformationArg */
static int hf_inap_SendSTUIArg_PDU;               /* SendSTUIArg */
static int hf_inap_ServiceFilteringResponseArg_PDU;  /* ServiceFilteringResponseArg */
static int hf_inap_SetServiceProfileArg_PDU;      /* SetServiceProfileArg */
static int hf_inap_SplitLegArg_PDU;               /* SplitLegArg */
static int hf_inap_StatusReportArg_PDU;           /* StatusReportArg */
static int hf_inap_TAnswerArg_PDU;                /* TAnswerArg */
static int hf_inap_TBusyArg_PDU;                  /* TBusyArg */
static int hf_inap_TDisconnectArg_PDU;            /* TDisconnectArg */
static int hf_inap_TermAttemptAuthorizedArg_PDU;  /* TermAttemptAuthorizedArg */
static int hf_inap_TerminationAttemptArg_PDU;     /* TerminationAttemptArg */
static int hf_inap_TNoAnswerArg_PDU;              /* TNoAnswerArg */
static int hf_inap_TSuspendedArg_PDU;             /* TSuspendedArg */
static int hf_inap_PlayAnnouncementArg_PDU;       /* PlayAnnouncementArg */
static int hf_inap_PromptAndCollectUserInformationArg_PDU;  /* PromptAndCollectUserInformationArg */
static int hf_inap_ReceivedInformationArg_PDU;    /* ReceivedInformationArg */
static int hf_inap_PromptAndReceiveMessageArg_PDU;  /* PromptAndReceiveMessageArg */
static int hf_inap_MessageReceivedArg_PDU;        /* MessageReceivedArg */
static int hf_inap_ScriptCloseArg_PDU;            /* ScriptCloseArg */
static int hf_inap_ScriptEventArg_PDU;            /* ScriptEventArg */
static int hf_inap_ScriptInformationArg_PDU;      /* ScriptInformationArg */
static int hf_inap_ScriptRunArg_PDU;              /* ScriptRunArg */
static int hf_inap_SpecializedResourceReportArg_PDU;  /* SpecializedResourceReportArg */
static int hf_inap_SRFCallGapArg_PDU;             /* SRFCallGapArg */
static int hf_inap_PAR_cancelFailed_PDU;          /* PAR_cancelFailed */
static int hf_inap_PAR_requestedInfoError_PDU;    /* PAR_requestedInfoError */
static int hf_inap_ScfTaskRefusedParameter_PDU;   /* ScfTaskRefusedParameter */
static int hf_inap_ReferralParameter_PDU;         /* ReferralParameter */
static int hf_inap_UnavailableNetworkResource_PDU;  /* UnavailableNetworkResource */
static int hf_inap_PAR_taskRefused_PDU;           /* PAR_taskRefused */
static int hf_inap_Extensions_item;               /* ExtensionField */
static int hf_inap_type;                          /* Code */
static int hf_inap_criticality;                   /* CriticalityType */
static int hf_inap_value;                         /* T_value */
static int hf_inap_AlternativeIdentities_item;    /* AlternativeIdentity */
static int hf_inap_url;                           /* IA5String_SIZE_1_512 */
static int hf_inap_conferenceTreatmentIndicator;  /* OCTET_STRING_SIZE_1 */
static int hf_inap_callCompletionTreatmentIndicator;  /* OCTET_STRING_SIZE_1 */
static int hf_inap_holdTreatmentIndicator;        /* OCTET_STRING_SIZE_1 */
static int hf_inap_ectTreatmentIndicator;         /* OCTET_STRING_SIZE_1 */
static int hf_inap_calledAddressValue;            /* Digits */
static int hf_inap_gapOnService;                  /* GapOnService */
static int hf_inap_gapAllInTraffic;               /* NULL */
static int hf_inap_calledAddressAndService;       /* T_calledAddressAndService */
static int hf_inap_serviceKey;                    /* ServiceKey */
static int hf_inap_callingAddressAndService;      /* T_callingAddressAndService */
static int hf_inap_callingAddressValue;           /* Digits */
static int hf_inap_locationNumber;                /* LocationNumber */
static int hf_inap_eventTypeBCSM;                 /* EventTypeBCSM */
static int hf_inap_monitorMode;                   /* MonitorMode */
static int hf_inap_legID;                         /* LegID */
static int hf_inap_dpSpecificCriteria;            /* DpSpecificCriteria */
static int hf_inap_bearerCap;                     /* T_bearerCap */
static int hf_inap_tmr;                           /* OCTET_STRING_SIZE_1 */
static int hf_inap_broadbandBearerCap;            /* OCTET_STRING_SIZE_minBroadbandBearerCapabilityLength_maxBroadbandBearerCapabilityLength */
static int hf_inap_aALParameters;                 /* AALParameters */
static int hf_inap_additionalATMCellRate;         /* AdditionalATMCellRate */
static int hf_inap_aESACalledParty;               /* AESACalledParty */
static int hf_inap_aESACallingParty;              /* AESACallingParty */
static int hf_inap_alternativeATMTrafficDescriptor;  /* AlternativeATMTrafficDescriptor */
static int hf_inap_aTMCellRate;                   /* ATMCellRate */
static int hf_inap_cDVTDescriptor;                /* CDVTDescriptor */
static int hf_inap_cumulativeTransitDelay;        /* CumulativeTransitDelay */
static int hf_inap_endToEndTransitDelay;          /* EndToEndTransitDelay */
static int hf_inap_minAcceptableATMTrafficDescriptor;  /* MinAcceptableATMTrafficDescriptor */
static int hf_inap_eventTypeCharging;             /* EventTypeCharging */
static int hf_inap_componentInfo;                 /* OCTET_STRING_SIZE_1_118 */
static int hf_inap_relayedComponent;              /* EMBEDDED_PDV */
static int hf_inap_basicGapCriteria;              /* BasicGapCriteria */
static int hf_inap_scfID;                         /* ScfID */
static int hf_inap_counterID;                     /* CounterID */
static int hf_inap_counterValue;                  /* Integer4 */
static int hf_inap_CountersValue_item;            /* CounterAndValue */
static int hf_inap_action;                        /* T_action */
static int hf_inap_treatment;                     /* GapTreatment */
static int hf_inap_DestinationRoutingAddress_item;  /* CalledPartyNumber */
static int hf_inap_serviceAddressInformation;     /* ServiceAddressInformation */
static int hf_inap_bearerCapability;              /* BearerCapability */
static int hf_inap_calledPartyNumber;             /* CalledPartyNumber */
static int hf_inap_callingPartyNumber;            /* CallingPartyNumber */
static int hf_inap_callingPartysCategory;         /* CallingPartysCategory */
static int hf_inap_iPSSPCapabilities;             /* IPSSPCapabilities */
static int hf_inap_iPAvailable;                   /* IPAvailable */
static int hf_inap_iSDNAccessRelatedInformation;  /* ISDNAccessRelatedInformation */
static int hf_inap_cGEncountered;                 /* CGEncountered */
static int hf_inap_serviceProfileIdentifier;      /* ServiceProfileIdentifier */
static int hf_inap_terminalType;                  /* TerminalType */
static int hf_inap_extensions;                    /* Extensions */
static int hf_inap_chargeNumber;                  /* ChargeNumber */
static int hf_inap_servingAreaID;                 /* ServingAreaID */
static int hf_inap_serviceInteractionIndicators;  /* ServiceInteractionIndicators */
static int hf_inap_iNServiceCompatibilityIndication;  /* INServiceCompatibilityIndication */
static int hf_inap_serviceInteractionIndicatorsTwo;  /* ServiceInteractionIndicatorsTwo */
static int hf_inap_uSIServiceIndicator;           /* USIServiceIndicator */
static int hf_inap_uSIInformation;                /* USIInformation */
static int hf_inap_forwardGVNS;                   /* ForwardGVNS */
static int hf_inap_createdCallSegmentAssociation;  /* CSAID */
static int hf_inap_ipRelatedInformation;          /* IPRelatedInformation */
static int hf_inap_numberOfDigits;                /* NumberOfDigits */
static int hf_inap_applicationTimer;              /* ApplicationTimer */
static int hf_inap_midCallControlInfo;            /* MidCallControlInfo */
static int hf_inap_numberOfDigitsTwo;             /* T_numberOfDigitsTwo */
static int hf_inap_requestedNumberOfDigits;       /* NumberOfDigits */
static int hf_inap_minNumberOfDigits;             /* NumberOfDigits */
static int hf_inap_agreements;                    /* OBJECT_IDENTIFIER */
static int hf_inap_networkSpecific;               /* Integer4 */
static int hf_inap_collectedInfoSpecificInfo;     /* T_collectedInfoSpecificInfo */
static int hf_inap_calledPartynumber;             /* CalledPartyNumber */
static int hf_inap_analysedInfoSpecificInfo;      /* T_analysedInfoSpecificInfo */
static int hf_inap_routeSelectFailureSpecificInfo;  /* T_routeSelectFailureSpecificInfo */
static int hf_inap_failureCause;                  /* Cause */
static int hf_inap_oCalledPartyBusySpecificInfo;  /* T_oCalledPartyBusySpecificInfo */
static int hf_inap_busyCause;                     /* Cause */
static int hf_inap_oNoAnswerSpecificInfo;         /* T_oNoAnswerSpecificInfo */
static int hf_inap_cause;                         /* Cause */
static int hf_inap_oAnswerSpecificInfo;           /* T_oAnswerSpecificInfo */
static int hf_inap_backwardGVNS;                  /* BackwardGVNS */
static int hf_inap_oMidCallSpecificInfo;          /* T_oMidCallSpecificInfo */
static int hf_inap_connectTime;                   /* Integer4 */
static int hf_inap_oMidCallInfo;                  /* MidCallInfo */
static int hf_inap_oDisconnectSpecificInfo;       /* T_oDisconnectSpecificInfo */
static int hf_inap_releaseCause;                  /* Cause */
static int hf_inap_tBusySpecificInfo;             /* T_tBusySpecificInfo */
static int hf_inap_tNoAnswerSpecificInfo;         /* T_tNoAnswerSpecificInfo */
static int hf_inap_tAnswerSpecificInfo;           /* T_tAnswerSpecificInfo */
static int hf_inap_tMidCallSpecificInfo;          /* T_tMidCallSpecificInfo */
static int hf_inap_tMidCallInfo;                  /* MidCallInfo */
static int hf_inap_tDisconnectSpecificInfo;       /* T_tDisconnectSpecificInfo */
static int hf_inap_oTermSeizedSpecificInfo;       /* T_oTermSeizedSpecificInfo */
static int hf_inap_oSuspend;                      /* T_oSuspend */
static int hf_inap_tSuspend;                      /* T_tSuspend */
static int hf_inap_origAttemptAuthorized;         /* T_origAttemptAuthorized */
static int hf_inap_oReAnswer;                     /* T_oReAnswer */
static int hf_inap_tReAnswer;                     /* T_tReAnswer */
static int hf_inap_facilitySelectedAndAvailable;  /* T_facilitySelectedAndAvailable */
static int hf_inap_callAccepted;                  /* T_callAccepted */
static int hf_inap_oAbandon;                      /* T_oAbandon */
static int hf_inap_abandonCause;                  /* Cause */
static int hf_inap_tAbandon;                      /* T_tAbandon */
static int hf_inap_authorizeRouteFailure;         /* T_authorizeRouteFailure */
static int hf_inap_authoriseRouteFailureCause;    /* Cause */
static int hf_inap_terminationAttemptAuthorized;  /* T_terminationAttemptAuthorized */
static int hf_inap_originationAttemptDenied;      /* T_originationAttemptDenied */
static int hf_inap_originationDeniedCause;        /* Cause */
static int hf_inap_terminationAttemptDenied;      /* T_terminationAttemptDenied */
static int hf_inap_terminationDeniedCause;        /* Cause */
static int hf_inap_oModifyRequestSpecificInfo;    /* T_oModifyRequestSpecificInfo */
static int hf_inap_oModifyResultSpecificInfo;     /* T_oModifyResultSpecificInfo */
static int hf_inap_modifyResultType;              /* ModifyResultType */
static int hf_inap_tModifyRequestSpecificInfo;    /* T_tModifyRequestSpecificInfo */
static int hf_inap_tModifyResultSpecificInfo;     /* T_tModifyResultSpecificInfo */
static int hf_inap_trunkGroupID;                  /* INTEGER */
static int hf_inap_privateFacilityID;             /* INTEGER */
static int hf_inap_huntGroup;                     /* OCTET_STRING */
static int hf_inap_routeIndex;                    /* OCTET_STRING */
static int hf_inap_sFBillingChargingCharacteristics;  /* SFBillingChargingCharacteristics */
static int hf_inap_informationToSend;             /* InformationToSend */
static int hf_inap_maximumNumberOfCounters;       /* MaximumNumberOfCounters */
static int hf_inap_filteringCharacteristics_interval;  /* INTEGER_M1_32000 */
static int hf_inap_numberOfCalls;                 /* Integer4 */
static int hf_inap_dialledNumber;                 /* Digits */
static int hf_inap_callingLineID;                 /* Digits */
static int hf_inap_addressAndService;             /* T_addressAndService */
static int hf_inap_duration;                      /* Duration */
static int hf_inap_stopTime;                      /* DateAndTime */
static int hf_inap_callDiversionTreatmentIndicator;  /* OCTET_STRING_SIZE_1 */
static int hf_inap_callOfferingTreatmentIndicator;  /* OCTET_STRING_SIZE_1 */
static int hf_inap_callWaitingTreatmentIndicator;  /* OCTET_STRING_SIZE_1 */
static int hf_inap_compoundCapCriteria;           /* CompoundCriteria */
static int hf_inap_dpCriteria;                    /* EventTypeBCSM */
static int hf_inap_gapInterval;                   /* Interval */
static int hf_inap_both;                          /* T_both */
static int hf_inap_GenericNumbers_item;           /* GenericNumber */
static int hf_inap_actionOnProfile;               /* ActionOnProfile */
static int hf_inap_tDPIdentifier;                 /* TDPIdentifier */
static int hf_inap_dPName;                        /* EventTypeBCSM */
static int hf_inap_INServiceCompatibilityIndication_item;  /* Entry */
static int hf_inap_alternativeCalledPartyIds;     /* AlternativeIdentities */
static int hf_inap_alternativeOriginatingPartyIds;  /* AlternativeIdentities */
static int hf_inap_alternativeOriginalCalledPartyIds;  /* AlternativeIdentities */
static int hf_inap_alternativeRedirectingPartyIds;  /* AlternativeIdentities */
static int hf_inap_sendingSideID;                 /* LegType */
static int hf_inap_receivingSideID;               /* LegType */
static int hf_inap_MidCallControlInfo_item;       /* MidCallControlInfo_item */
static int hf_inap_midCallInfoType;               /* MidCallInfoType */
static int hf_inap_midCallReportType;             /* T_midCallReportType */
static int hf_inap_iNServiceControlCode;          /* Digits */
static int hf_inap_iNServiceControlCodeLow;       /* Digits */
static int hf_inap_iNServiceControlCodeHigh;      /* Digits */
static int hf_inap_messageType;                   /* T_messageType */
static int hf_inap_dpAssignment;                  /* T_dpAssignment */
static int hf_inap_threshold;                     /* Integer4 */
static int hf_inap_interval;                      /* Interval */
static int hf_inap_access;                        /* CalledPartyNumber */
static int hf_inap_group;                         /* FacilityGroup */
static int hf_inap_RequestedInformationList_item;  /* RequestedInformation */
static int hf_inap_RequestedInformationTypeList_item;  /* RequestedInformationType */
static int hf_inap_requestedInformationType;      /* RequestedInformationType */
static int hf_inap_requestedInformationValue;     /* RequestedInformationValue */
static int hf_inap_callAttemptElapsedTimeValue;   /* INTEGER_0_255 */
static int hf_inap_callStopTimeValue;             /* DateAndTime */
static int hf_inap_callConnectedElapsedTimeValue;  /* Integer4 */
static int hf_inap_releaseCauseValue;             /* Cause */
static int hf_inap_uSImonitorMode;                /* USIMonitorMode */
static int hf_inap_RequestedUTSIList_item;        /* RequestedUTSI */
static int hf_inap_lineID;                        /* Digits */
static int hf_inap_facilityGroupID;               /* FacilityGroup */
static int hf_inap_facilityGroupMemberID;         /* INTEGER */
static int hf_inap_RouteCountersValue_item;       /* RouteCountersAndValue */
static int hf_inap_route;                         /* Route */
static int hf_inap_RouteList_item;                /* Route */
static int hf_inap_miscCallInfo;                  /* MiscCallInfo */
static int hf_inap_triggerType;                   /* TriggerType */
static int hf_inap_forwardServiceInteractionInd;  /* ForwardServiceInteractionInd */
static int hf_inap_backwardServiceInteractionInd;  /* BackwardServiceInteractionInd */
static int hf_inap_bothwayThroughConnectionInd;   /* BothwayThroughConnectionInd */
static int hf_inap_suspendTimer;                  /* SuspendTimer */
static int hf_inap_connectedNumberTreatmentInd;   /* ConnectedNumberTreatmentInd */
static int hf_inap_suppressCallDiversionNotification;  /* BOOLEAN */
static int hf_inap_suppressCallTransferNotification;  /* BOOLEAN */
static int hf_inap_allowCdINNoPresentationInd;    /* BOOLEAN */
static int hf_inap_userDialogueDurationInd;       /* BOOLEAN */
static int hf_inap_overrideLineRestrictions;      /* BOOLEAN */
static int hf_inap_suppressVPNAPP;                /* BOOLEAN */
static int hf_inap_calledINNumberOverriding;      /* BOOLEAN */
static int hf_inap_redirectServiceTreatmentInd;   /* T_redirectServiceTreatmentInd */
static int hf_inap_redirectReason;                /* RedirectReason */
static int hf_inap_nonCUGCall;                    /* NULL */
static int hf_inap_oneTrigger;                    /* INTEGER */
static int hf_inap_triggers;                      /* Triggers */
static int hf_inap_triggerId;                     /* T_triggerId */
static int hf_inap_triggerPar;                    /* T_triggerPar */
static int hf_inap_triggerID;                     /* EventTypeBCSM */
static int hf_inap_profile;                       /* ProfileIdentifier */
static int hf_inap_TriggerResults_item;           /* TriggerResult */
static int hf_inap_tDPIdentifer;                  /* INTEGER */
static int hf_inap_actionPerformed;               /* ActionPerformed */
static int hf_inap_Triggers_item;                 /* Trigger */
static int hf_inap_trigger_tDPIdentifier;         /* INTEGER */
static int hf_inap_dpName;                        /* EventTypeBCSM */
static int hf_inap_global;                        /* OBJECT_IDENTIFIER */
static int hf_inap_local;                         /* OCTET_STRING_SIZE_minUSIServiceIndicatorLength_maxUSIServiceIndicatorLength */
static int hf_inap_filteredCallTreatment;         /* FilteredCallTreatment */
static int hf_inap_filteringCharacteristics;      /* FilteringCharacteristics */
static int hf_inap_filteringTimeOut;              /* FilteringTimeOut */
static int hf_inap_filteringCriteria;             /* FilteringCriteria */
static int hf_inap_startTime;                     /* DateAndTime */
static int hf_inap_dpSpecificCommonParameters;    /* DpSpecificCommonParameters */
static int hf_inap_dialledDigits;                 /* CalledPartyNumber */
static int hf_inap_callingPartyBusinessGroupID;   /* CallingPartyBusinessGroupID */
static int hf_inap_callingPartySubaddress;        /* CallingPartySubaddress */
static int hf_inap_callingFacilityGroup;          /* FacilityGroup */
static int hf_inap_callingFacilityGroupMember;    /* FacilityGroupMember */
static int hf_inap_originalCalledPartyID;         /* OriginalCalledPartyID */
static int hf_inap_prefix;                        /* Digits */
static int hf_inap_redirectingPartyID;            /* RedirectingPartyID */
static int hf_inap_redirectionInformation;        /* RedirectionInformation */
static int hf_inap_routeList;                     /* RouteList */
static int hf_inap_travellingClassMark;           /* TravellingClassMark */
static int hf_inap_featureCode;                   /* FeatureCode */
static int hf_inap_accessCode;                    /* AccessCode */
static int hf_inap_carrier;                       /* Carrier */
static int hf_inap_componentType;                 /* ComponentType */
static int hf_inap_component;                     /* Component */
static int hf_inap_componentCorrelationID;        /* ComponentCorrelationID */
static int hf_inap_destinationRoutingAddress;     /* DestinationRoutingAddress */
static int hf_inap_alertingPattern;               /* AlertingPattern */
static int hf_inap_iNServiceCompatibilityResponse;  /* INServiceCompatibilityResponse */
static int hf_inap_correlationID;                 /* CorrelationID */
static int hf_inap_callSegmentID;                 /* CallSegmentID */
static int hf_inap_legToBeCreated;                /* LegID */
static int hf_inap_aChBillingChargingCharacteristics;  /* AChBillingChargingCharacteristics */
static int hf_inap_partyToCharge;                 /* LegID */
static int hf_inap_releaseIndication;             /* BOOLEAN */
static int hf_inap_destinationNumberRoutingAddress;  /* CalledPartyNumber */
static int hf_inap_displayInformation;            /* DisplayInformation */
static int hf_inap_destinationIndex;              /* DestinationIndex */
static int hf_inap_gapIndicators;                 /* GapIndicators */
static int hf_inap_registratorIdentifier;         /* RegistratorIdentifier */
static int hf_inap_gapCriteria;                   /* GapCriteria */
static int hf_inap_controlType;                   /* ControlType */
static int hf_inap_gapTreatment;                  /* GapTreatment */
static int hf_inap_requestedInformationList;      /* RequestedInformationList */
static int hf_inap_lastEventIndicator;            /* BOOLEAN */
static int hf_inap_requestedInformationTypeList;  /* RequestedInformationTypeList */
static int hf_inap_invokeID;                      /* InvokeID */
static int hf_inap_allRequests;                   /* NULL */
static int hf_inap_callSegmentToCancel;           /* T_callSegmentToCancel */
static int hf_inap_allRequestsForCallSegment;     /* CallSegmentID */
static int hf_inap_resourceID;                    /* ResourceID */
static int hf_inap_numberingPlan;                 /* NumberingPlan */
static int hf_inap_cutAndPaste;                   /* CutAndPaste */
static int hf_inap_forwardingCondition;           /* ForwardingCondition */
static int hf_inap_forwardCallIndicators;         /* ForwardCallIndicators */
static int hf_inap_genericNumbers;                /* GenericNumbers */
static int hf_inap_sDSSinformation;               /* SDSSinformation */
static int hf_inap_calledDirectoryNumber;         /* CalledDirectoryNumber */
static int hf_inap_calledPartySubaddress;         /* CalledPartySubaddress */
static int hf_inap_connectionIdentifier;          /* ConnectionIdentifier */
static int hf_inap_genericIdentifier;             /* GenericIdentifier */
static int hf_inap_qOSParameter;                  /* QoSParameter */
static int hf_inap_bISDNParameters;               /* BISDNParameters */
static int hf_inap_cug_Interlock;                 /* CUG_Interlock */
static int hf_inap_cug_OutgoingAccess;            /* NULL */
static int hf_inap_resourceAddress;               /* T_resourceAddress */
static int hf_inap_ipRoutingAddress;              /* IPRoutingAddress */
static int hf_inap_ipAddressAndLegID;             /* T_ipAddressAndLegID */
static int hf_inap_none;                          /* NULL */
static int hf_inap_ipAddressAndCallSegment;       /* T_ipAddressAndCallSegment */
static int hf_inap_legorCSID;                     /* T_legorCSID */
static int hf_inap_csID;                          /* CallSegmentID */
static int hf_inap_genericName;                   /* GenericName */
static int hf_inap_ipRelationInformation;         /* IPRelatedInformation */
static int hf_inap_newCallSegmentAssociation;     /* CSAID */
static int hf_inap_createOrRemove;                /* CreateOrRemoveIndicator */
static int hf_inap_triggerDPType;                 /* TriggerDPType */
static int hf_inap_triggerData;                   /* TriggerData */
static int hf_inap_defaultFaultHandling;          /* DefaultFaultHandling */
static int hf_inap_triggerStatus;                 /* TriggerStatus */
static int hf_inap_partyToDisconnect;             /* T_partyToDisconnect */
static int hf_inap_legToBeReleased;               /* LegID */
static int hf_inap_cSFailure;                     /* T_cSFailure */
static int hf_inap_reason;                        /* Reason */
static int hf_inap_bCSMFailure;                   /* T_bCSMFailure */
static int hf_inap_assistingSSPIPRoutingAddress;  /* AssistingSSPIPRoutingAddress */
static int hf_inap_partyToConnect;                /* T_partyToConnect */
static int hf_inap_eventSpecificInformationCharging;  /* EventSpecificInformationCharging */
static int hf_inap_bcsmEventCorrelationID;        /* CorrelationID */
static int hf_inap_eventSpecificInformationBCSM;  /* EventSpecificInformationBCSM */
static int hf_inap_calledPartyBusinessGroupID;    /* CalledPartyBusinessGroupID */
static int hf_inap_holdcause;                     /* HoldCause */
static int hf_inap_empty;                         /* NULL */
static int hf_inap_highLayerCompatibility;        /* HighLayerCompatibility */
static int hf_inap_additionalCallingPartyNumber;  /* AdditionalCallingPartyNumber */
static int hf_inap_cCSS;                          /* CCSS */
static int hf_inap_vPNIndicator;                  /* VPNIndicator */
static int hf_inap_cNInfo;                        /* CNInfo */
static int hf_inap_callReference;                 /* CallReference */
static int hf_inap_routeingNumber;                /* RouteingNumber */
static int hf_inap_callingGeodeticLocation;       /* CallingGeodeticLocation */
static int hf_inap_globalCallReference;           /* GlobalCallReference */
static int hf_inap_cug_Index;                     /* CUG_Index */
static int hf_inap_newCallSegment;                /* CallSegmentID */
static int hf_inap_incomingSignallingBufferCopy;  /* BOOLEAN */
static int hf_inap_actionIndicator;               /* ActionIndicator */
static int hf_inap_triggerDataIdentifier;         /* T_triggerDataIdentifier */
static int hf_inap_profileAndDP;                  /* TriggerDataIdentifier */
static int hf_inap_oneTriggerResult;              /* T_oneTriggerResult */
static int hf_inap_severalTriggerResult;          /* T_severalTriggerResult */
static int hf_inap_results;                       /* TriggerResults */
static int hf_inap_sourceCallSegment;             /* CallSegmentID */
static int hf_inap_targetCallSegment;             /* CallSegmentID */
static int hf_inap_mergeSignallingPaths;          /* NULL */
static int hf_inap_routeCounters;                 /* RouteCountersValue */
static int hf_inap_monitoringCriteria;            /* MonitoringCriteria */
static int hf_inap_monitoringTimeout;             /* MonitoringTimeOut */
static int hf_inap_targetCallSegmentAssociation;  /* CSAID */
static int hf_inap_callSegments;                  /* T_callSegments */
static int hf_inap_callSegments_item;             /* T_callSegments_item */
static int hf_inap_legs;                          /* T_legs */
static int hf_inap_legs_item;                     /* T_legs_item */
static int hf_inap_sourceLeg;                     /* LegID */
static int hf_inap_newLeg;                        /* LegID */
static int hf_inap_legIDToMove;                   /* LegID */
static int hf_inap_detachSignallingPath;          /* NULL */
static int hf_inap_exportSignallingPath;          /* NULL */
static int hf_inap_featureRequestIndicator;       /* FeatureRequestIndicator */
static int hf_inap_componenttCorrelationID;       /* ComponentCorrelationID */
static int hf_inap_notificationDuration;          /* ApplicationTimer */
static int hf_inap_initialCallSegment;            /* Cause */
static int hf_inap_callSegmentToRelease;          /* T_callSegmentToRelease */
static int hf_inap_callSegment;                   /* INTEGER_1_numOfCSs */
static int hf_inap_forcedRelease;                 /* BOOLEAN */
static int hf_inap_allCallSegments;               /* T_allCallSegments */
static int hf_inap_timeToRelease;                 /* TimerValue */
static int hf_inap_resourceStatus;                /* ResourceStatus */
static int hf_inap_monitorDuration;               /* Duration */
static int hf_inap_RequestNotificationChargingEventArg_item;  /* ChargingEvent */
static int hf_inap_bcsmEvents;                    /* SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent */
static int hf_inap_bcsmEvents_item;               /* BCSMEvent */
static int hf_inap_componentTypes;                /* SEQUENCE_SIZE_1_3_OF_ComponentType */
static int hf_inap_componentTypes_item;           /* ComponentType */
static int hf_inap_requestedUTSIList;             /* RequestedUTSIList */
static int hf_inap_timerID;                       /* TimerID */
static int hf_inap_timervalue;                    /* TimerValue */
static int hf_inap_calledFacilityGroup;           /* FacilityGroup */
static int hf_inap_calledFacilityGroupMember;     /* FacilityGroupMember */
static int hf_inap_sCIBillingChargingCharacteristics;  /* SCIBillingChargingCharacteristics */
static int hf_inap_nocharge;                      /* BOOLEAN */
static int hf_inap_callProcessingOperation;       /* CallProcessingOperation */
static int hf_inap_countersValue;                 /* CountersValue */
static int hf_inap_responseCondition;             /* ResponseCondition */
static int hf_inap_iNprofiles;                    /* SEQUENCE_SIZE_1_numOfINProfile_OF_INprofile */
static int hf_inap_iNprofiles_item;               /* INprofile */
static int hf_inap_legToBeSplit;                  /* LegID */
static int hf_inap_newCallSegment_01;             /* INTEGER_2_numOfCSs */
static int hf_inap_reportCondition;               /* ReportCondition */
static int hf_inap_minimumNbOfDigits;             /* INTEGER_1_127 */
static int hf_inap_maximumNbOfDigits;             /* INTEGER_1_127 */
static int hf_inap_endOfReplyDigit;               /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_cancelDigit;                   /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_startDigit;                    /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_firstDigitTimeOut;             /* INTEGER_1_127 */
static int hf_inap_interDigitTimeOut;             /* INTEGER_1_127 */
static int hf_inap_errorTreatment;                /* ErrorTreatment */
static int hf_inap_interruptableAnnInd;           /* BOOLEAN */
static int hf_inap_voiceInformation;              /* BOOLEAN */
static int hf_inap_voiceBack;                     /* BOOLEAN */
static int hf_inap_detectModem;                   /* BOOLEAN */
static int hf_inap_collectedDigits;               /* CollectedDigits */
static int hf_inap_iA5Information;                /* BOOLEAN */
static int hf_inap_messageID;                     /* MessageID */
static int hf_inap_numberOfRepetitions;           /* INTEGER_1_127 */
static int hf_inap_inbandInfo_duration;           /* INTEGER_0_32767 */
static int hf_inap_inbandInfo_interval;           /* INTEGER_0_32767 */
static int hf_inap_preferredLanguage;             /* Language */
static int hf_inap_messageID_01;                  /* ElementaryMessageID */
static int hf_inap_messageDeletionTimeOut;        /* INTEGER_1_3600 */
static int hf_inap_timeToRecord;                  /* INTEGER_0_b3__maxRecordingTime */
static int hf_inap_controlDigits;                 /* T_controlDigits */
static int hf_inap_endOfRecordingDigit;           /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_replayDigit;                   /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_restartRecordingDigit;         /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_restartAllowed;                /* BOOLEAN */
static int hf_inap_replayAllowed;                 /* BOOLEAN */
static int hf_inap_inbandInfo;                    /* InbandInfo */
static int hf_inap_tone;                          /* Tone */
static int hf_inap_elementaryMessageID;           /* Integer4 */
static int hf_inap_text;                          /* T_text */
static int hf_inap_messageContent;                /* IA5String_SIZE_b3__minMessageContentLength_b3__maxMessageContentLength */
static int hf_inap_attributes;                    /* OCTET_STRING_SIZE_b3__minAttributesLength_b3__maxAttributesLength */
static int hf_inap_elementaryMessageIDs;          /* SEQUENCE_SIZE_1_b3__numOfMessageIDs_OF_Integer4 */
static int hf_inap_elementaryMessageIDs_item;     /* Integer4 */
static int hf_inap_variableMessage;               /* T_variableMessage */
static int hf_inap_variableParts;                 /* SEQUENCE_SIZE_1_b3__maxVariableParts_OF_VariablePart */
static int hf_inap_variableParts_item;            /* VariablePart */
static int hf_inap_iPAddressValue;                /* Digits */
static int hf_inap_gapOnResource;                 /* GapOnResource */
static int hf_inap_iPAddressAndresource;          /* T_iPAddressAndresource */
static int hf_inap_toneID;                        /* Integer4 */
static int hf_inap_tone_duration;                 /* Integer4 */
static int hf_inap_integer;                       /* Integer4 */
static int hf_inap_number;                        /* Digits */
static int hf_inap_time;                          /* OCTET_STRING_SIZE_2 */
static int hf_inap_date;                          /* OCTET_STRING_SIZE_3 */
static int hf_inap_price;                         /* OCTET_STRING_SIZE_4 */
static int hf_inap_disconnectFromIPForbidden;     /* BOOLEAN */
static int hf_inap_requestAnnouncementComplete;   /* BOOLEAN */
static int hf_inap_connectedParty;                /* T_connectedParty */
static int hf_inap_collectedInfo;                 /* CollectedInfo */
static int hf_inap_digitsResponse;                /* Digits */
static int hf_inap_iA5Response;                   /* IA5String */
static int hf_inap_modemdetected;                 /* BOOLEAN */
static int hf_inap_subscriberID;                  /* GenericNumber */
static int hf_inap_mailBoxID;                     /* MailBoxID */
static int hf_inap_informationToRecord;           /* InformationToRecord */
static int hf_inap_media;                         /* Media */
static int hf_inap_receivedStatus;                /* ReceivedStatus */
static int hf_inap_recordedMessageID;             /* RecordedMessageID */
static int hf_inap_recordedMessageUnits;          /* INTEGER_1_b3__maxRecordedMessageUnits */
static int hf_inap_uIScriptId;                    /* Code */
static int hf_inap_uIScriptSpecificInfo;          /* T_uIScriptSpecificInfo */
static int hf_inap_uIScriptResult;                /* T_uIScriptResult */
static int hf_inap_uIScriptSpecificInfo_01;       /* T_uIScriptSpecificInfo_01 */
static int hf_inap_uIScriptSpecificInfo_02;       /* T_uIScriptSpecificInfo_02 */
static int hf_inap_sRFgapCriteria;                /* SRFGapCriteria */
static int hf_inap_problem;                       /* T_problem */
static int hf_inap_operation;                     /* InvokeID */
static int hf_inap_scfTaskRefusedParameter_reason;  /* T_scfTaskRefusedParameter_reason */
static int hf_inap_securityParameters;            /* SecurityParameters */
static int hf_inap_tryhere;                       /* AccessPointInformation */
static int hf_inap_code_local;                    /* T_code_local */
static int hf_inap_global_01;                     /* T_global */
static int hf_inap_invoke;                        /* Invoke */
static int hf_inap_returnResult;                  /* ReturnResult */
static int hf_inap_returnError;                   /* ReturnError */
static int hf_inap_reject;                        /* Reject */
static int hf_inap_invokeId;                      /* InvokeId */
static int hf_inap_linkedId;                      /* T_linkedId */
static int hf_inap_inkedIdPresent;                /* T_inkedIdPresent */
static int hf_inap_absent;                        /* NULL */
static int hf_inap_opcode;                        /* Code */
static int hf_inap_argument;                      /* T_argument */
static int hf_inap_result;                        /* T_result */
static int hf_inap_resultArgument;                /* ResultArgument */
static int hf_inap_errcode;                       /* Code */
static int hf_inap_parameter;                     /* T_parameter */
static int hf_inap_problem_01;                    /* T_problem_01 */
static int hf_inap_general;                       /* GeneralProblem */
static int hf_inap_invokeProblem;                 /* InvokeProblem */
static int hf_inap_problemReturnResult;           /* ReturnResultProblem */
static int hf_inap_returnErrorProblem;            /* ReturnErrorProblem */
static int hf_inap_present;                       /* INTEGER */
static int hf_inap_InvokeId_present;              /* InvokeId_present */

#define MAX_SSN 254
static range_t *global_ssn_range;

static dissector_handle_t	inap_handle;

/* Global variables */
static uint32_t opcode=0;
static uint32_t errorCode=0;
static const char *obj_id;
static bool is_ExtensionField;

static int inap_opcode_type;
#define INAP_OPCODE_INVOKE        1
#define INAP_OPCODE_RETURN_RESULT 2
#define INAP_OPCODE_RETURN_ERROR  3
#define INAP_OPCODE_REJECT        4

static int hf_inap_cause_indicator;

/* Initialize the subtree pointers */
static int ett_inap;
static int ett_inapisup_parameter;
static int ett_inap_RedirectionInformation;
static int ett_inap_HighLayerCompatibility;
static int ett_inap_extension_data;
static int ett_inap_cause;
static int ett_inap_calledAddressValue;
static int ett_inap_callingAddressValue;
static int ett_inap_additionalCallingPartyNumber;
static int ett_inap_assistingSSPIPRoutingAddress;
static int ett_inap_correlationID;
static int ett_inap_number;
static int ett_inap_dialledNumber;
static int ett_inap_callingLineID;
static int ett_inap_iNServiceControlCode;
static int ett_inap_iNServiceControlCodeLow;
static int ett_inap_iNServiceControlCodeHigh;
static int ett_inap_lineID;
static int ett_inap_prefix;
static int ett_inap_iPAddressValue;
static int ett_inap_digitsResponse;

static int ett_inap_Extensions;
static int ett_inap_ExtensionField;
static int ett_inap_AlternativeIdentities;
static int ett_inap_AlternativeIdentity;
static int ett_inap_BackwardServiceInteractionInd;
static int ett_inap_BasicGapCriteria;
static int ett_inap_T_calledAddressAndService;
static int ett_inap_T_callingAddressAndService;
static int ett_inap_BCSMEvent;
static int ett_inap_BearerCapability;
static int ett_inap_BISDNParameters;
static int ett_inap_ChargingEvent;
static int ett_inap_Component;
static int ett_inap_CompoundCriteria;
static int ett_inap_CounterAndValue;
static int ett_inap_CountersValue;
static int ett_inap_DefaultFaultHandling;
static int ett_inap_DestinationRoutingAddress;
static int ett_inap_DpSpecificCommonParameters;
static int ett_inap_DpSpecificCriteria;
static int ett_inap_T_numberOfDigitsTwo;
static int ett_inap_Entry;
static int ett_inap_EventSpecificInformationBCSM;
static int ett_inap_T_collectedInfoSpecificInfo;
static int ett_inap_T_analysedInfoSpecificInfo;
static int ett_inap_T_routeSelectFailureSpecificInfo;
static int ett_inap_T_oCalledPartyBusySpecificInfo;
static int ett_inap_T_oNoAnswerSpecificInfo;
static int ett_inap_T_oAnswerSpecificInfo;
static int ett_inap_T_oMidCallSpecificInfo;
static int ett_inap_T_oDisconnectSpecificInfo;
static int ett_inap_T_tBusySpecificInfo;
static int ett_inap_T_tNoAnswerSpecificInfo;
static int ett_inap_T_tAnswerSpecificInfo;
static int ett_inap_T_tMidCallSpecificInfo;
static int ett_inap_T_tDisconnectSpecificInfo;
static int ett_inap_T_oTermSeizedSpecificInfo;
static int ett_inap_T_oSuspend;
static int ett_inap_T_tSuspend;
static int ett_inap_T_origAttemptAuthorized;
static int ett_inap_T_oReAnswer;
static int ett_inap_T_tReAnswer;
static int ett_inap_T_facilitySelectedAndAvailable;
static int ett_inap_T_callAccepted;
static int ett_inap_T_oAbandon;
static int ett_inap_T_tAbandon;
static int ett_inap_T_authorizeRouteFailure;
static int ett_inap_T_terminationAttemptAuthorized;
static int ett_inap_T_originationAttemptDenied;
static int ett_inap_T_terminationAttemptDenied;
static int ett_inap_T_oModifyRequestSpecificInfo;
static int ett_inap_T_oModifyResultSpecificInfo;
static int ett_inap_T_tModifyRequestSpecificInfo;
static int ett_inap_T_tModifyResultSpecificInfo;
static int ett_inap_FacilityGroup;
static int ett_inap_FilteredCallTreatment;
static int ett_inap_FilteringCharacteristics;
static int ett_inap_FilteringCriteria;
static int ett_inap_T_addressAndService;
static int ett_inap_FilteringTimeOut;
static int ett_inap_ForwardServiceInteractionInd;
static int ett_inap_GapCriteria;
static int ett_inap_GapOnService;
static int ett_inap_GapIndicators;
static int ett_inap_GapTreatment;
static int ett_inap_T_both;
static int ett_inap_GenericNumbers;
static int ett_inap_INprofile;
static int ett_inap_INServiceCompatibilityIndication;
static int ett_inap_IPRelatedInformation;
static int ett_inap_LegID;
static int ett_inap_MidCallControlInfo;
static int ett_inap_MidCallControlInfo_item;
static int ett_inap_MidCallInfo;
static int ett_inap_MidCallInfoType;
static int ett_inap_MiscCallInfo;
static int ett_inap_MonitoringCriteria;
static int ett_inap_MonitoringTimeOut;
static int ett_inap_ProfileIdentifier;
static int ett_inap_RequestedInformationList;
static int ett_inap_RequestedInformationTypeList;
static int ett_inap_RequestedInformation;
static int ett_inap_RequestedInformationValue;
static int ett_inap_RequestedUTSI;
static int ett_inap_RequestedUTSIList;
static int ett_inap_ResourceID;
static int ett_inap_RouteCountersValue;
static int ett_inap_RouteCountersAndValue;
static int ett_inap_RouteList;
static int ett_inap_ServiceAddressInformation;
static int ett_inap_ServiceInteractionIndicatorsTwo;
static int ett_inap_T_redirectServiceTreatmentInd;
static int ett_inap_TDPIdentifier;
static int ett_inap_TriggerData;
static int ett_inap_TriggerDataIdentifier;
static int ett_inap_TriggerResults;
static int ett_inap_TriggerResult;
static int ett_inap_Triggers;
static int ett_inap_Trigger;
static int ett_inap_USIServiceIndicator;
static int ett_inap_ActivateServiceFilteringArg;
static int ett_inap_AnalysedInformationArg;
static int ett_inap_AnalyseInformationArg;
static int ett_inap_ApplyChargingArg;
static int ett_inap_AssistRequestInstructionsArg;
static int ett_inap_AuthorizeTerminationArg;
static int ett_inap_CallFilteringArg;
static int ett_inap_CallGapArg;
static int ett_inap_CallInformationReportArg;
static int ett_inap_CallInformationRequestArg;
static int ett_inap_CancelArg;
static int ett_inap_T_callSegmentToCancel;
static int ett_inap_CancelStatusReportRequestArg;
static int ett_inap_CollectedInformationArg;
static int ett_inap_CollectInformationArg;
static int ett_inap_ConnectArg;
static int ett_inap_ConnectToResourceArg;
static int ett_inap_T_resourceAddress;
static int ett_inap_T_ipAddressAndLegID;
static int ett_inap_T_ipAddressAndCallSegment;
static int ett_inap_ContinueWithArgumentArg;
static int ett_inap_T_legorCSID;
static int ett_inap_CreateCallSegmentAssociationArg;
static int ett_inap_CreateCallSegmentAssociationResultArg;
static int ett_inap_CreateOrRemoveTriggerDataArg;
static int ett_inap_CreateOrRemoveTriggerDataResultArg;
static int ett_inap_DisconnectForwardConnectionWithArgumentArg;
static int ett_inap_T_partyToDisconnect;
static int ett_inap_DisconnectLegArg;
static int ett_inap_EntityReleasedArg;
static int ett_inap_T_cSFailure;
static int ett_inap_T_bCSMFailure;
static int ett_inap_EstablishTemporaryConnectionArg;
static int ett_inap_T_partyToConnect;
static int ett_inap_EventNotificationChargingArg;
static int ett_inap_EventReportBCSMArg;
static int ett_inap_EventReportFacilityArg;
static int ett_inap_FacilitySelectedAndAvailableArg;
static int ett_inap_HoldCallInNetworkArg;
static int ett_inap_InitialDPArg;
static int ett_inap_InitiateCallAttemptArg;
static int ett_inap_ManageTriggerDataArg;
static int ett_inap_T_triggerDataIdentifier;
static int ett_inap_ManageTriggerDataResultArg;
static int ett_inap_T_oneTriggerResult;
static int ett_inap_T_severalTriggerResult;
static int ett_inap_MergeCallSegmentsArg;
static int ett_inap_MonitorRouteReportArg;
static int ett_inap_MonitorRouteRequestArg;
static int ett_inap_MoveCallSegmentsArg;
static int ett_inap_T_callSegments;
static int ett_inap_T_callSegments_item;
static int ett_inap_T_legs;
static int ett_inap_T_legs_item;
static int ett_inap_MoveLegArg;
static int ett_inap_OAbandonArg;
static int ett_inap_OAnswerArg;
static int ett_inap_OCalledPartyBusyArg;
static int ett_inap_ODisconnectArg;
static int ett_inap_MidCallArg;
static int ett_inap_ONoAnswerArg;
static int ett_inap_OriginationAttemptArg;
static int ett_inap_OriginationAttemptAuthorizedArg;
static int ett_inap_OSuspendedArg;
static int ett_inap_ReconnectArg;
static int ett_inap_ReleaseCallArg;
static int ett_inap_T_callSegmentToRelease;
static int ett_inap_T_allCallSegments;
static int ett_inap_ReportUTSIArg;
static int ett_inap_RequestCurrentStatusReportResultArg;
static int ett_inap_RequestEveryStatusChangeReportArg;
static int ett_inap_RequestFirstStatusMatchReportArg;
static int ett_inap_RequestNotificationChargingEventArg;
static int ett_inap_RequestReportBCSMEventArg;
static int ett_inap_SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent;
static int ett_inap_RequestReportFacilityEventArg;
static int ett_inap_SEQUENCE_SIZE_1_3_OF_ComponentType;
static int ett_inap_RequestReportUTSIArg;
static int ett_inap_ResetTimerArg;
static int ett_inap_RouteSelectFailureArg;
static int ett_inap_SelectFacilityArg;
static int ett_inap_SelectRouteArg;
static int ett_inap_SendChargingInformationArg;
static int ett_inap_SendFacilityInformationArg;
static int ett_inap_SendSTUIArg;
static int ett_inap_ServiceFilteringResponseArg;
static int ett_inap_SetServiceProfileArg;
static int ett_inap_SEQUENCE_SIZE_1_numOfINProfile_OF_INprofile;
static int ett_inap_SplitLegArg;
static int ett_inap_StatusReportArg;
static int ett_inap_TAnswerArg;
static int ett_inap_TBusyArg;
static int ett_inap_TDisconnectArg;
static int ett_inap_TermAttemptAuthorizedArg;
static int ett_inap_TerminationAttemptArg;
static int ett_inap_TNoAnswerArg;
static int ett_inap_TSuspendedArg;
static int ett_inap_CollectedDigits;
static int ett_inap_CollectedInfo;
static int ett_inap_InbandInfo;
static int ett_inap_InformationToRecord;
static int ett_inap_T_controlDigits;
static int ett_inap_InformationToSend;
static int ett_inap_MessageID;
static int ett_inap_T_text;
static int ett_inap_SEQUENCE_SIZE_1_b3__numOfMessageIDs_OF_Integer4;
static int ett_inap_T_variableMessage;
static int ett_inap_SEQUENCE_SIZE_1_b3__maxVariableParts_OF_VariablePart;
static int ett_inap_SRFGapCriteria;
static int ett_inap_T_iPAddressAndresource;
static int ett_inap_Tone;
static int ett_inap_VariablePart;
static int ett_inap_PlayAnnouncementArg;
static int ett_inap_T_connectedParty;
static int ett_inap_PromptAndCollectUserInformationArg;
static int ett_inap_ReceivedInformationArg;
static int ett_inap_PromptAndReceiveMessageArg;
static int ett_inap_MessageReceivedArg;
static int ett_inap_ScriptCloseArg;
static int ett_inap_ScriptEventArg;
static int ett_inap_ScriptInformationArg;
static int ett_inap_ScriptRunArg;
static int ett_inap_SRFCallGapArg;
static int ett_inap_PAR_cancelFailed;
static int ett_inap_ScfTaskRefusedParameter;
static int ett_inap_ReferralParameter;
static int ett_inap_Code;
static int ett_inap_ROS;
static int ett_inap_Invoke;
static int ett_inap_T_linkedId;
static int ett_inap_ReturnResult;
static int ett_inap_T_result;
static int ett_inap_ReturnError;
static int ett_inap_Reject;
static int ett_inap_T_problem_01;
static int ett_inap_InvokeId;

static expert_field ei_inap_unknown_invokeData;
static expert_field ei_inap_unknown_returnResultData;
static expert_field ei_inap_unknown_returnErrorData;


/* INAP OPERATIONS */
const value_string inap_opr_code_strings[] = {
  { opcode_activateServiceFiltering         , "activateServiceFiltering" },
  { opcode_activityTest                     , "activityTest" },
  { opcode_analysedInformation              , "analysedInformation" },
  { opcode_analyseInformation               , "analyseInformation" },
  { opcode_applyCharging                    , "applyCharging" },
  { opcode_applyChargingReport              , "applyChargingReport" },
  { opcode_assistRequestInstructions        , "assistRequestInstructions" },
  { opcode_authorizeTermination             , "authorizeTermination" },
  { opcode_callFiltering                    , "callFiltering" },
  { opcode_callGap                          , "callGap" },
  { opcode_callInformationReport            , "callInformationReport" },
  { opcode_callInformationRequest           , "callInformationRequest" },
  { opcode_cancel                           , "cancel" },
  { opcode_cancelStatusReportRequest        , "cancelStatusReportRequest" },
  { opcode_collectedInformation             , "collectedInformation" },
  { opcode_collectInformation               , "collectInformation" },
  { opcode_connect                          , "connect" },
  { opcode_connectToResource                , "connectToResource" },
  { opcode_continue                         , "continue" },
  { opcode_continueWithArgument             , "continueWithArgument" },
  { opcode_createCallSegmentAssociation     , "createCallSegmentAssociation" },
  { opcode_createOrRemoveTriggerData        , "createOrRemoveTriggerData" },
  { opcode_disconnectForwardConnection      , "disconnectForwardConnection" },
  { opcode_dFCWithArgument                  , "disconnectForwardConnectionWithArgument" },
  { opcode_disconnectLeg                    , "disconnectLeg" },
  { opcode_entityReleased                   , "entityReleased" },
  { opcode_establishTemporaryConnection     , "establishTemporaryConnection" },
  { opcode_eventNotificationCharging        , "eventNotificationCharging" },
  { opcode_eventReportBCSM                  , "eventReportBCSM" },
  { opcode_eventReportFacility              , "eventReportFacility" },
  { opcode_facilitySelectedAndAvailable     , "facilitySelectedAndAvailable" },
  { opcode_furnishChargingInformation       , "furnishChargingInformation" },
  { opcode_holdCallInNetwork                , "holdCallInNetwork" },
  { opcode_initialDP                        , "initialDP" },
  { opcode_initiateCallAttempt              , "initiateCallAttempt" },
  { opcode_manageTriggerData                , "manageTriggerData" },
  { opcode_mergeCallSegments                , "mergeCallSegments" },
  { opcode_monitorRouteReport               , "monitorRouteReport" },
  { opcode_monitorRouteRequest              , "monitorRouteRequest" },
  { opcode_moveCallSegments                 , "moveCallSegments" },
  { opcode_moveLeg                          , "moveLeg" },
  { opcode_oAbandon                         , "oAbandon" },
  { opcode_oAnswer                          , "oAnswer" },
  { opcode_oCalledPartyBusy                 , "oCalledPartyBusy" },
  { opcode_oDisconnect                      , "oDisconnect" },
  { opcode_oMidCall                         , "oMidCall" },
  { opcode_oNoAnswer                        , "oNoAnswer" },
  { opcode_originationAttempt               , "originationAttempt" },
  { opcode_originationAttemptAuthorized     , "originationAttemptAuthorized" },
  { opcode_oSuspended                       , "oSuspended" },
  { opcode_reconnect                        , "reconnect" },
  { opcode_releaseCall                      , "releaseCall" },
  { opcode_reportUTSI                       , "reportUTSI" },
  { opcode_requestCurrentStatusReport       , "requestCurrentStatusReport" },
  { opcode_requestEveryStatusChangeReport   , "requestEveryStatusChangeReport" },
  { opcode_requestFirstStatusMatchReport    , "requestFirstStatusMatchReport" },
  { opcode_requestNotificationChargingEvent , "requestNotificationChargingEvent" },
  { opcode_requestReportBCSMEvent           , "requestReportBCSMEvent" },
  { opcode_requestReportFacilityEvent       , "requestReportFacilityEvent" },
  { opcode_requestReportUTSI                , "requestReportUTSI" },
  { opcode_resetTimer                       , "resetTimer" },
  { opcode_routeSelectFailure               , "routeSelectFailure" },
  { opcode_selectFacility                   , "selectFacility" },
  { opcode_selectRoute                      , "selectRoute" },
  { opcode_sendChargingInformation          , "sendChargingInformation" },
  { opcode_sendFacilityInformation          , "sendFacilityInformation" },
  { opcode_sendSTUI                         , "sendSTUI" },
  { opcode_serviceFilteringResponse         , "serviceFilteringResponse" },
  { opcode_setServiceProfile                , "setServiceProfile" },
  { opcode_splitLeg                         , "splitLeg" },
  { opcode_statusReport                     , "statusReport" },
  { opcode_tAnswer                          , "tAnswer" },
  { opcode_tBusy                            , "tBusy" },
  { opcode_tDisconnect                      , "tDisconnect" },
  { opcode_termAttemptAuthorized            , "termAttemptAuthorized" },
  { opcode_terminationAttempt               , "terminationAttempt" },
  { opcode_tMidCall                         , "tMidCall" },
  { opcode_tNoAnswer                        , "tNoAnswer" },
  { opcode_tSuspended                       , "tSuspended" },
  { opcode_playAnnouncement                 , "playAnnouncement" },
  { opcode_promptAndCollectUserInformation  , "promptAndCollectUserInformation" },
  { opcode_promptAndReceiveMessage          , "promptAndReceiveMessage" },
  { opcode_scriptClose                      , "scriptClose" },
  { opcode_scriptEvent                      , "scriptEvent" },
  { opcode_scriptInformation                , "scriptInformation" },
  { opcode_scriptRun                        , "scriptRun" },
  { opcode_specializedResourceReport        , "specializedResourceReport" },
  { opcode_srfCallGap                       , "sRFCallGap" },
  { 0, NULL }
};


/* INAP ERRORS */
static const value_string inap_err_code_string_vals[] = {
  { errcode_canceled                        , "canceled" },
  { errcode_cancelFailed                    , "cancelFailed" },
  { errcode_chainingRefused                 , "chainingRefused" },
  { errcode_eTCFailed                       , "eTCFailed" },
  { errcode_improperCallerResponse          , "improperCallerResponse" },
  { errcode_missingCustomerRecord           , "missingCustomerRecord" },
  { errcode_missingParameter                , "missingParameter" },
  { errcode_parameterOutOfRange             , "parameterOutOfRange" },
  { errcode_requestedInfoError              , "requestedInfoError" },
  { errcode_scfTaskRefused                  , "scfTaskRefused" },
  { errcode_scfReferral                     , "scfReferral" },
  { errcode_systemFailure                   , "systemFailure" },
  { errcode_taskRefused                     , "taskRefused" },
  { errcode_unavailableResource             , "unavailableResource" },
  { errcode_unexpectedComponentSequence     , "unexpectedComponentSequence" },
  { errcode_unexpectedDataValue             , "unexpectedDataValue" },
  { errcode_unexpectedParameter             , "unexpectedParameter" },
  { errcode_unknownLegID                    , "unknownLegID" },
  { errcode_unknownResource                 , "unknownResource" },
  { 0, NULL }
};


#if 0
static const value_string inap_general_problem_strings[] = {
  {0,"General Problem Unrecognized Component"},
  {1,"General Problem Mistyped Component"},
  {3,"General Problem Badly Structured Component"},
  {0, NULL}
};
#endif

/* Forward declarations */
static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx);


const value_string inap_CriticalityType_vals[] = {
  {   0, "ignore" },
  {   1, "abort" },
  { 0, NULL }
};


int
dissect_inap_CriticalityType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_T_code_local(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &opcode);

  if (is_ExtensionField == false){
    if (inap_opcode_type == INAP_OPCODE_RETURN_ERROR){
      errorCode = opcode;
      col_append_str(actx->pinfo->cinfo, COL_INFO, val_to_str(errorCode, inap_err_code_string_vals, "Unknown INAP error (%u)"));
      col_append_str(actx->pinfo->cinfo, COL_INFO, " ");
      col_set_fence(actx->pinfo->cinfo, COL_INFO);
    }else{
      col_append_str(actx->pinfo->cinfo, COL_INFO, val_to_str(opcode, inap_opr_code_strings, "Unknown INAP (%u)"));
      col_append_str(actx->pinfo->cinfo, COL_INFO, " ");
      col_set_fence(actx->pinfo->cinfo, COL_INFO);
    }
 }


  return offset;
}



static int
dissect_inap_T_global(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &obj_id);

  return offset;
}


static const value_string inap_Code_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const ber_choice_t Code_choice[] = {
  {   0, &hf_inap_code_local     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_inap_T_code_local },
  {   1, &hf_inap_global_01      , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_inap_T_global },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_Code(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Code_choice, hf_index, ett_inap_Code,
                                 NULL);

  return offset;
}



static int
dissect_inap_T_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_tree *ext_tree;
  ext_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_inap_extension_data, NULL, "Extension Data");
  if (obj_id){
    offset=call_ber_oid_callback(obj_id, tvb, offset, actx->pinfo, ext_tree, NULL);
  }else{
    call_data_dissector(tvb, actx->pinfo, ext_tree);
    offset = tvb_reported_length_remaining(tvb,offset);
  }
  is_ExtensionField = false;




  return offset;
}


static const ber_sequence_t ExtensionField_sequence[] = {
  { &hf_inap_type           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Code },
  { &hf_inap_criticality    , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_inap_CriticalityType },
  { &hf_inap_value          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_T_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ExtensionField(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  obj_id = NULL;
  is_ExtensionField =true;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtensionField_sequence, hf_index, ett_inap_ExtensionField);

  return offset;
}


static const ber_sequence_t Extensions_sequence_of[1] = {
  { &hf_inap_Extensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_ExtensionField },
};

static int
dissect_inap_Extensions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Extensions_sequence_of, hf_index, ett_inap_Extensions);

  return offset;
}



int
dissect_inap_Integer4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_InvokeID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string inap_UnavailableNetworkResource_vals[] = {
  {   0, "unavailableResources" },
  {   1, "componentFailure" },
  {   2, "basicCallProcessingException" },
  {   3, "resourceStatusFailure" },
  {   4, "endUserFailure" },
  {   5, "screening" },
  { 0, NULL }
};


static int
dissect_inap_UnavailableNetworkResource(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_AALParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_LocationNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_AccessCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_AChBillingChargingCharacteristics(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_ActionIndicator_vals[] = {
  {   1, "activate" },
  {   2, "deactivate" },
  {   3, "retrieve" },
  { 0, NULL }
};


static int
dissect_inap_ActionIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_ActionOnProfile_vals[] = {
  {   0, "activate" },
  {   1, "deactivate" },
  { 0, NULL }
};


static int
dissect_inap_ActionOnProfile(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_ActionPerformed_vals[] = {
  {   1, "activated" },
  {   2, "deactivated" },
  {   3, "alreadyActive" },
  {   4, "alreadyInactive" },
  {   5, "isActive" },
  {   6, "isInactive" },
  {   7, "tDPunknown" },
  { 0, NULL }
};


static int
dissect_inap_ActionPerformed(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_AdditionalATMCellRate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_Digits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  /*
   *-- Indicates the address signalling digits. Refer to the Q.763 Generic Number and Generic Digits parameter
   *-- for encoding. The coding of the subfield's 'NumberQualifier' in Generic Number and 'TypeOfDigits' in
   *-- Generic Digits are irrelevant to the INAP, the ASN.1 tags are sufficient to identify the parameter.
   *-- The ISUP format does not allow to exclude these subfields, therefore the value is network operator specific.
   *-- The following parameters should use Generic Number
   *-- Additional Calling Number, CorrelationID for AssistRequestInstructions, AssistingSSPIPRoutingAddress
   *--  for EstablishTemporaryConnection
   *-- calledAddressValue for all occurrences,callingAddressValue for all occurrences
   *-- The following parameters should use Generic Digits: prefix, all
   *-- other CorrelationID occurrences, dialledNumber filtering criteria, callingLineID filtering criteria, lineID for
   *-- ResourceID type, digitResponse for ReceivedInformationArg, iNServiceControlLow / iNServiceControlHigh for
   *--MidCallInfoType,, iNServiceControlCode for MidCallInfo.
   */
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;
  int ett = -1;
  bool digits = false;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  if (hf_index == hf_inap_additionalCallingPartyNumber) {
    ett = ett_inap_additionalCallingPartyNumber;
  } else if (hf_index == hf_inap_assistingSSPIPRoutingAddress) {
    ett = ett_inap_assistingSSPIPRoutingAddress;
  } else if (hf_index == hf_inap_correlationID) {
    ett = ett_inap_correlationID;
    digits = (opcode != opcode_assistRequestInstructions) ? true : false;
  } else if (hf_index == hf_inap_calledAddressValue) {
    ett = ett_inap_calledAddressValue;
  } else if (hf_index == hf_inap_callingAddressValue) {
    ett = ett_inap_callingAddressValue;
  } else if (hf_index == hf_inap_number) {
    ett = ett_inap_number;
  } else if (hf_index == hf_inap_dialledNumber) {
    ett = ett_inap_dialledNumber;
    digits = true;
  } else if (hf_index == hf_inap_callingLineID) {
    ett = ett_inap_callingLineID;
    digits = true;
  } else if (hf_index == hf_inap_iNServiceControlCode) {
    ett = ett_inap_iNServiceControlCode;
    digits = true;
  } else if (hf_index == hf_inap_iNServiceControlCodeLow) {
    ett = ett_inap_iNServiceControlCodeLow;
    digits = true;
  } else if (hf_index == hf_inap_iNServiceControlCodeHigh) {
    ett = ett_inap_iNServiceControlCodeHigh;
    digits = true;
  } else if (hf_index == hf_inap_lineID) {
    ett = ett_inap_lineID;
    digits = true;
  } else if (hf_index == hf_inap_prefix) {
    ett = ett_inap_prefix;
    digits = true;
  } else if (hf_index == hf_inap_iPAddressValue) {
    ett = ett_inap_iPAddressValue;
  } else if (hf_index == hf_inap_digitsResponse) {
    ett = ett_inap_digitsResponse;
    digits = true;
  }

  subtree = proto_item_add_subtree(actx->created_item, ett);
  if (digits) {
    dissect_isup_generic_digits_parameter(parameter_tvb, subtree, NULL);
  } else {
    dissect_isup_generic_number_parameter(parameter_tvb, actx->pinfo, subtree, NULL);
  }

  return offset;
}



static int
dissect_inap_AdditionalCallingPartyNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Digits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_AESACalledParty(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_AESACallingParty(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_AlertingPattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_IA5String_SIZE_1_512(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string inap_AlternativeIdentity_vals[] = {
  {   0, "url" },
  { 0, NULL }
};

static const ber_choice_t AlternativeIdentity_choice[] = {
  {   0, &hf_inap_url            , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_IA5String_SIZE_1_512 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_AlternativeIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AlternativeIdentity_choice, hf_index, ett_inap_AlternativeIdentity,
                                 NULL);

  return offset;
}


static const ber_sequence_t AlternativeIdentities_sequence_of[1] = {
  { &hf_inap_AlternativeIdentities_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_AlternativeIdentity },
};

static int
dissect_inap_AlternativeIdentities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AlternativeIdentities_sequence_of, hf_index, ett_inap_AlternativeIdentities);

  return offset;
}



static int
dissect_inap_AlternativeATMTrafficDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_ApplicationTimer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_AssistingSSPIPRoutingAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Digits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_ATMCellRate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_BackwardGVNS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t BackwardServiceInteractionInd_sequence[] = {
  { &hf_inap_conferenceTreatmentIndicator, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  { &hf_inap_callCompletionTreatmentIndicator, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  { &hf_inap_holdTreatmentIndicator, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  { &hf_inap_ectTreatmentIndicator, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_BackwardServiceInteractionInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BackwardServiceInteractionInd_sequence, hf_index, ett_inap_BackwardServiceInteractionInd);

  return offset;
}



int
dissect_inap_ServiceKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Integer4(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string inap_EventTypeBCSM_vals[] = {
  {   1, "origAttemptAuthorized" },
  {   2, "collectedInfo" },
  {   3, "analysedInformation" },
  {   4, "routeSelectFailure" },
  {   5, "oCalledPartyBusy" },
  {   6, "oNoAnswer" },
  {   7, "oAnswer" },
  {   8, "oMidCall" },
  {   9, "oDisconnect" },
  {  10, "oAbandon" },
  {  12, "termAttemptAuthorized" },
  {  13, "tBusy" },
  {  14, "tNoAnswer" },
  {  15, "tAnswer" },
  {  16, "tMidCall" },
  {  17, "tDisconnect" },
  {  18, "tAbandon" },
  {  19, "oTermSeized" },
  {  20, "oSuspend" },
  {  21, "tSuspend" },
  {  22, "origAttempt" },
  {  23, "termAttempt" },
  {  24, "oReAnswer" },
  {  25, "tReAnswer" },
  {  26, "facilitySelectedAndAvailable" },
  {  27, "callAccepted" },
  {  28, "authorizeRouteFailure" },
  {  29, "originationAttemptDenied" },
  {  30, "terminationAttemptDenied" },
  { 100, "oModifyRequest" },
  { 101, "oModifyResult" },
  { 102, "tModifyRequest" },
  { 103, "tModifyResult" },
  { 0, NULL }
};


static int
dissect_inap_EventTypeBCSM(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t GapOnService_sequence[] = {
  { &hf_inap_serviceKey     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_ServiceKey },
  { &hf_inap_dpCriteria     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_EventTypeBCSM },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_GapOnService(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GapOnService_sequence, hf_index, ett_inap_GapOnService);

  return offset;
}



static int
dissect_inap_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_calledAddressAndService_sequence[] = {
  { &hf_inap_calledAddressValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_serviceKey     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_ServiceKey },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_calledAddressAndService(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_calledAddressAndService_sequence, hf_index, ett_inap_T_calledAddressAndService);

  return offset;
}


static const ber_sequence_t T_callingAddressAndService_sequence[] = {
  { &hf_inap_callingAddressValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_serviceKey     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_ServiceKey },
  { &hf_inap_locationNumber , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_LocationNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_callingAddressAndService(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_callingAddressAndService_sequence, hf_index, ett_inap_T_callingAddressAndService);

  return offset;
}


static const value_string inap_BasicGapCriteria_vals[] = {
  {   0, "calledAddressValue" },
  {   2, "gapOnService" },
  {   3, "gapAllInTraffic" },
  {  29, "calledAddressAndService" },
  {  30, "callingAddressAndService" },
  { 0, NULL }
};

static const ber_choice_t BasicGapCriteria_choice[] = {
  {   0, &hf_inap_calledAddressValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  {   2, &hf_inap_gapOnService   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_GapOnService },
  {   3, &hf_inap_gapAllInTraffic, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  {  29, &hf_inap_calledAddressAndService, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_inap_T_calledAddressAndService },
  {  30, &hf_inap_callingAddressAndService, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_inap_T_callingAddressAndService },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_BasicGapCriteria(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 BasicGapCriteria_choice, hf_index, ett_inap_BasicGapCriteria,
                                 NULL);

  return offset;
}


static const value_string inap_MonitorMode_vals[] = {
  {   0, "interrupted" },
  {   1, "notifyAndContinue" },
  {   2, "transparent" },
  { 0, NULL }
};


static int
dissect_inap_MonitorMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_LegType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


const value_string inap_LegID_vals[] = {
  {   0, "sendingSideID" },
  {   1, "receivingSideID" },
  { 0, NULL }
};

static const ber_choice_t LegID_choice[] = {
  {   0, &hf_inap_sendingSideID  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_LegType },
  {   1, &hf_inap_receivingSideID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_LegType },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_inap_LegID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LegID_choice, hf_index, ett_inap_LegID,
                                 NULL);

  return offset;
}



static int
dissect_inap_NumberOfDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t MidCallInfoType_sequence[] = {
  { &hf_inap_iNServiceControlCodeLow, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_iNServiceControlCodeHigh, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MidCallInfoType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MidCallInfoType_sequence, hf_index, ett_inap_MidCallInfoType);

  return offset;
}


static const value_string inap_T_midCallReportType_vals[] = {
  {   0, "inMonitoringState" },
  {   1, "inAnyState" },
  { 0, NULL }
};


static int
dissect_inap_T_midCallReportType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MidCallControlInfo_item_sequence[] = {
  { &hf_inap_midCallInfoType, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_MidCallInfoType },
  { &hf_inap_midCallReportType, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_T_midCallReportType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MidCallControlInfo_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MidCallControlInfo_item_sequence, hf_index, ett_inap_MidCallControlInfo_item);

  return offset;
}


static const ber_sequence_t MidCallControlInfo_sequence_of[1] = {
  { &hf_inap_MidCallControlInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_MidCallControlInfo_item },
};

static int
dissect_inap_MidCallControlInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      MidCallControlInfo_sequence_of, hf_index, ett_inap_MidCallControlInfo);

  return offset;
}


static const ber_sequence_t T_numberOfDigitsTwo_sequence[] = {
  { &hf_inap_requestedNumberOfDigits, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_NumberOfDigits },
  { &hf_inap_minNumberOfDigits, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NumberOfDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_numberOfDigitsTwo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_numberOfDigitsTwo_sequence, hf_index, ett_inap_T_numberOfDigitsTwo);

  return offset;
}


static const value_string inap_DpSpecificCriteria_vals[] = {
  {   0, "numberOfDigits" },
  {   1, "applicationTimer" },
  {   2, "midCallControlInfo" },
  {   3, "numberOfDigitsTwo" },
  { 0, NULL }
};

static const ber_choice_t DpSpecificCriteria_choice[] = {
  {   0, &hf_inap_numberOfDigits , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_NumberOfDigits },
  {   1, &hf_inap_applicationTimer, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_ApplicationTimer },
  {   2, &hf_inap_midCallControlInfo, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_MidCallControlInfo },
  {   3, &hf_inap_numberOfDigitsTwo, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_T_numberOfDigitsTwo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_DpSpecificCriteria(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DpSpecificCriteria_choice, hf_index, ett_inap_DpSpecificCriteria,
                                 NULL);

  return offset;
}


static const ber_sequence_t BCSMEvent_sequence[] = {
  { &hf_inap_eventTypeBCSM  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_EventTypeBCSM },
  { &hf_inap_monitorMode    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_MonitorMode },
  { &hf_inap_legID          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_dpSpecificCriteria, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_DpSpecificCriteria },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_BCSMEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BCSMEvent_sequence, hf_index, ett_inap_BCSMEvent);

  return offset;
}



static int
dissect_inap_T_bearerCap(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  tvbuff_t *parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  dissect_q931_bearer_capability_ie(parameter_tvb, 0, tvb_reported_length_remaining(parameter_tvb,0), tree);


  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_minBroadbandBearerCapabilityLength_maxBroadbandBearerCapabilityLength(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_BearerCapability_vals[] = {
  {   0, "bearerCap" },
  {   1, "tmr" },
  {   2, "broadbandBearerCap" },
  { 0, NULL }
};

static const ber_choice_t BearerCapability_choice[] = {
  {   0, &hf_inap_bearerCap      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_T_bearerCap },
  {   1, &hf_inap_tmr            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  {   2, &hf_inap_broadbandBearerCap, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_minBroadbandBearerCapabilityLength_maxBroadbandBearerCapabilityLength },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_BearerCapability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 BearerCapability_choice, hf_index, ett_inap_BearerCapability,
                                 NULL);

  return offset;
}



static int
dissect_inap_CDVTDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_CumulativeTransitDelay(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_EndToEndTransitDelay(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_MinAcceptableATMTrafficDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t BISDNParameters_sequence[] = {
  { &hf_inap_aALParameters  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AALParameters },
  { &hf_inap_additionalATMCellRate, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AdditionalATMCellRate },
  { &hf_inap_aESACalledParty, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AESACalledParty },
  { &hf_inap_aESACallingParty, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AESACallingParty },
  { &hf_inap_alternativeATMTrafficDescriptor, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlternativeATMTrafficDescriptor },
  { &hf_inap_aTMCellRate    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ATMCellRate },
  { &hf_inap_cDVTDescriptor , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CDVTDescriptor },
  { &hf_inap_cumulativeTransitDelay, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CumulativeTransitDelay },
  { &hf_inap_endToEndTransitDelay, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_EndToEndTransitDelay },
  { &hf_inap_minAcceptableATMTrafficDescriptor, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_MinAcceptableATMTrafficDescriptor },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_BISDNParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BISDNParameters_sequence, hf_index, ett_inap_BISDNParameters);

  return offset;
}


const value_string inap_BothwayThroughConnectionInd_vals[] = {
  {   0, "bothwayPathRequired" },
  {   1, "bothwayPathNotRequired" },
  { 0, NULL }
};


int
dissect_inap_BothwayThroughConnectionInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_CalledDirectoryNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_CalledPartyBusinessGroupID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_CalledPartyNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
  return offset;

dissect_isup_called_party_number_parameter(parameter_tvb, actx->pinfo, tree, NULL);


  return offset;
}



static int
dissect_inap_CalledPartySubaddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_CallingGeodeticLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_CallingPartyBusinessGroupID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_CallingPartyNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  dissect_isup_calling_party_number_parameter(parameter_tvb, actx->pinfo, tree, NULL);



  return offset;
}



static int
dissect_inap_CallingPartySubaddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



int
dissect_inap_CallingPartysCategory(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_CallProcessingOperation_vals[] = {
  {   1, "aLERTing" },
  {   5, "sETUP" },
  {   7, "cONNect" },
  {  69, "dISConnect" },
  {  77, "rELease" },
  {  90, "rELeaseCOMPlete" },
  {  98, "fACility" },
  { 0, NULL }
};


static int
dissect_inap_CallProcessingOperation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_CallReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_CallResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_CallSegmentID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_Carrier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_Cause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  /*
   * -- Indicates the cause for interface related information. Refer to the Q.763 Cause  parameter for encoding
   * -- For the use of cause and location values refer to Q.850.
   */
  tvbuff_t *parameter_tvb;
  uint8_t Cause_value;
  proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_inap_cause);

  dissect_q931_cause_ie(parameter_tvb, 0, tvb_reported_length_remaining(parameter_tvb,0), subtree, hf_inap_cause_indicator, &Cause_value, isup_parameter_type_value);


  return offset;
}



static int
dissect_inap_CCSS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string inap_CGEncountered_vals[] = {
  {   0, "noCGencountered" },
  {   1, "manualCGencountered" },
  {   2, "sCPOverload" },
  { 0, NULL }
};


static int
dissect_inap_CGEncountered(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_ChargeNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_EventTypeCharging(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ChargingEvent_sequence[] = {
  { &hf_inap_eventTypeCharging, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_EventTypeCharging },
  { &hf_inap_monitorMode    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_MonitorMode },
  { &hf_inap_legID          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ChargingEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChargingEvent_sequence, hf_index, ett_inap_ChargingEvent);

  return offset;
}



static int
dissect_inap_CNInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_1_118(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_EMBEDDED_PDV(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_EmbeddedPDV_Type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const value_string inap_Component_vals[] = {
  {   0, "componentInfo" },
  {   1, "relayedComponent" },
  { 0, NULL }
};

static const ber_choice_t Component_choice[] = {
  {   0, &hf_inap_componentInfo  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1_118 },
  {   1, &hf_inap_relayedComponent, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_EMBEDDED_PDV },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_Component(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Component_choice, hf_index, ett_inap_Component,
                                 NULL);

  return offset;
}



static int
dissect_inap_ComponentCorrelationID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string inap_ComponentType_vals[] = {
  {   0, "any" },
  {   1, "invoke" },
  {   2, "rResult" },
  {   3, "rError" },
  {   4, "rReject" },
  { 0, NULL }
};


static int
dissect_inap_ComponentType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_ScfID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t CompoundCriteria_sequence[] = {
  { &hf_inap_basicGapCriteria, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_BasicGapCriteria },
  { &hf_inap_scfID          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ScfID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CompoundCriteria(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompoundCriteria_sequence, hf_index, ett_inap_CompoundCriteria);

  return offset;
}


static const value_string inap_ConnectedNumberTreatmentInd_vals[] = {
  {   0, "noINImpact" },
  {   1, "presentationRestricted" },
  {   2, "presentCalledINNumber" },
  {   3, "presentCalledINNumberRestricted" },
  { 0, NULL }
};


static int
dissect_inap_ConnectedNumberTreatmentInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_ConnectionIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_ControlType_vals[] = {
  {   0, "sCPOverloaded" },
  {   1, "manuallyInitiated" },
  {   2, "destinationOverload" },
  { 0, NULL }
};


static int
dissect_inap_ControlType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_CorrelationID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Digits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_CounterID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CounterAndValue_sequence[] = {
  { &hf_inap_counterID      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CounterID },
  { &hf_inap_counterValue   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CounterAndValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CounterAndValue_sequence, hf_index, ett_inap_CounterAndValue);

  return offset;
}


static const ber_sequence_t CountersValue_sequence_of[1] = {
  { &hf_inap_CountersValue_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_CounterAndValue },
};

static int
dissect_inap_CountersValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CountersValue_sequence_of, hf_index, ett_inap_CountersValue);

  return offset;
}


static const value_string inap_CreateOrRemoveIndicator_vals[] = {
  {   0, "create" },
  {   1, "remove" },
  { 0, NULL }
};


static int
dissect_inap_CreateOrRemoveIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_CSAID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_CUG_Interlock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_CUG_Index(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_inap_CutAndPaste(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_DateAndTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_T_action_vals[] = {
  {   0, "resumeCallProcessing" },
  {   1, "releaseCall" },
  { 0, NULL }
};


static int
dissect_inap_T_action(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_IA5String_SIZE_b3__minMessageContentLength_b3__maxMessageContentLength(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_b3__minAttributesLength_b3__maxAttributesLength(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_text_sequence[] = {
  { &hf_inap_messageContent , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_IA5String_SIZE_b3__minMessageContentLength_b3__maxMessageContentLength },
  { &hf_inap_attributes     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_b3__minAttributesLength_b3__maxAttributesLength },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_text(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_text_sequence, hf_index, ett_inap_T_text);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_b3__numOfMessageIDs_OF_Integer4_sequence_of[1] = {
  { &hf_inap_elementaryMessageIDs_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_inap_Integer4 },
};

static int
dissect_inap_SEQUENCE_SIZE_1_b3__numOfMessageIDs_OF_Integer4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_b3__numOfMessageIDs_OF_Integer4_sequence_of, hf_index, ett_inap_SEQUENCE_SIZE_1_b3__numOfMessageIDs_OF_Integer4);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_VariablePart_vals[] = {
  {   0, "integer" },
  {   1, "number" },
  {   2, "time" },
  {   3, "date" },
  {   4, "price" },
  { 0, NULL }
};

static const ber_choice_t VariablePart_choice[] = {
  {   0, &hf_inap_integer        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  {   1, &hf_inap_number         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  {   2, &hf_inap_time           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_2 },
  {   3, &hf_inap_date           , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_3 },
  {   4, &hf_inap_price          , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_4 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_VariablePart(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 VariablePart_choice, hf_index, ett_inap_VariablePart,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_b3__maxVariableParts_OF_VariablePart_sequence_of[1] = {
  { &hf_inap_variableParts_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_VariablePart },
};

static int
dissect_inap_SEQUENCE_SIZE_1_b3__maxVariableParts_OF_VariablePart(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_b3__maxVariableParts_OF_VariablePart_sequence_of, hf_index, ett_inap_SEQUENCE_SIZE_1_b3__maxVariableParts_OF_VariablePart);

  return offset;
}


static const ber_sequence_t T_variableMessage_sequence[] = {
  { &hf_inap_elementaryMessageID, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { &hf_inap_variableParts  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_SEQUENCE_SIZE_1_b3__maxVariableParts_OF_VariablePart },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_variableMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_variableMessage_sequence, hf_index, ett_inap_T_variableMessage);

  return offset;
}


static const value_string inap_MessageID_vals[] = {
  {   0, "elementaryMessageID" },
  {   1, "text" },
  {  29, "elementaryMessageIDs" },
  {  30, "variableMessage" },
  { 0, NULL }
};

static const ber_choice_t MessageID_choice[] = {
  {   0, &hf_inap_elementaryMessageID, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  {   1, &hf_inap_text           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_T_text },
  {  29, &hf_inap_elementaryMessageIDs, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_inap_SEQUENCE_SIZE_1_b3__numOfMessageIDs_OF_Integer4 },
  {  30, &hf_inap_variableMessage, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_inap_T_variableMessage },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MessageID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MessageID_choice, hf_index, ett_inap_MessageID,
                                 NULL);

  return offset;
}



static int
dissect_inap_INTEGER_1_127(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_INTEGER_0_32767(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_Language(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t InbandInfo_sequence[] = {
  { &hf_inap_messageID      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_MessageID },
  { &hf_inap_numberOfRepetitions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_1_127 },
  { &hf_inap_inbandInfo_duration, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_0_32767 },
  { &hf_inap_inbandInfo_interval, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_0_32767 },
  { &hf_inap_preferredLanguage, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Language },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_InbandInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InbandInfo_sequence, hf_index, ett_inap_InbandInfo);

  return offset;
}


static const ber_sequence_t Tone_sequence[] = {
  { &hf_inap_toneID         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { &hf_inap_tone_duration  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_Tone(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Tone_sequence, hf_index, ett_inap_Tone);

  return offset;
}



static int
dissect_inap_DisplayInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_inap_SDSSinformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_InformationToSend_vals[] = {
  {   0, "inbandInfo" },
  {   1, "tone" },
  {   2, "displayInformation" },
  {   3, "sDSSinformation" },
  { 0, NULL }
};

static const ber_choice_t InformationToSend_choice[] = {
  {   0, &hf_inap_inbandInfo     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_InbandInfo },
  {   1, &hf_inap_tone           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Tone },
  {   2, &hf_inap_displayInformation, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_DisplayInformation },
  {   3, &hf_inap_sDSSinformation, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_SDSSinformation },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_InformationToSend(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InformationToSend_choice, hf_index, ett_inap_InformationToSend,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_both_sequence[] = {
  { &hf_inap_informationToSend, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_InformationToSend },
  { &hf_inap_releaseCause   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_both(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_both_sequence, hf_index, ett_inap_T_both);

  return offset;
}


static const value_string inap_GapTreatment_vals[] = {
  {   0, "informationToSend" },
  {   1, "releaseCause" },
  {   2, "both" },
  { 0, NULL }
};

static const ber_choice_t GapTreatment_choice[] = {
  {   0, &hf_inap_informationToSend, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_InformationToSend },
  {   1, &hf_inap_releaseCause   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  {   2, &hf_inap_both           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_T_both },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_GapTreatment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GapTreatment_choice, hf_index, ett_inap_GapTreatment,
                                 NULL);

  return offset;
}


static const ber_sequence_t DefaultFaultHandling_sequence[] = {
  { &hf_inap_action         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_T_action },
  { &hf_inap_treatment      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_GapTreatment },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_DefaultFaultHandling(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefaultFaultHandling_sequence, hf_index, ett_inap_DefaultFaultHandling);

  return offset;
}



static int
dissect_inap_DestinationIndex(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t DestinationRoutingAddress_sequence_of[1] = {
  { &hf_inap_DestinationRoutingAddress_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_inap_CalledPartyNumber },
};

static int
dissect_inap_DestinationRoutingAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      DestinationRoutingAddress_sequence_of, hf_index, ett_inap_DestinationRoutingAddress);

  return offset;
}


static const value_string inap_T_messageType_vals[] = {
  {   0, "request" },
  {   1, "notification" },
  { 0, NULL }
};


static int
dissect_inap_T_messageType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_T_dpAssignment_vals[] = {
  {   0, "individualBased" },
  {   1, "groupBased" },
  {   2, "switchBased" },
  { 0, NULL }
};


static int
dissect_inap_T_dpAssignment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MiscCallInfo_sequence[] = {
  { &hf_inap_messageType    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_T_messageType },
  { &hf_inap_dpAssignment   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_T_dpAssignment },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_inap_MiscCallInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MiscCallInfo_sequence, hf_index, ett_inap_MiscCallInfo);

  return offset;
}


static const value_string inap_TriggerType_vals[] = {
  {   0, "featureActivation" },
  {   1, "verticalServiceCode" },
  {   2, "customizedAccess" },
  {   3, "customizedIntercom" },
  {  12, "emergencyService" },
  {  13, "aFR" },
  {  14, "sharedIOTrunk" },
  {  17, "offHookDelay" },
  {  18, "channelSetupPRI" },
  {  25, "tNoAnswer" },
  {  26, "tBusy" },
  {  27, "oCalledPartyBusy" },
  {  29, "oNoAnswer" },
  {  30, "originationAttemptAuthorized" },
  {  31, "oAnswer" },
  {  32, "oDisconnect" },
  {  33, "termAttemptAuthorized" },
  {  34, "tAnswer" },
  {  35, "tDisconnect" },
  { 100, "oModifyRequest" },
  { 101, "tModifyRequest" },
  { 0, NULL }
};


static int
dissect_inap_TriggerType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ServiceAddressInformation_sequence[] = {
  { &hf_inap_serviceKey     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceKey },
  { &hf_inap_miscCallInfo   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_MiscCallInfo },
  { &hf_inap_triggerType    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TriggerType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ServiceAddressInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceAddressInformation_sequence, hf_index, ett_inap_ServiceAddressInformation);

  return offset;
}



static int
dissect_inap_IPSSPCapabilities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_IPAvailable(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_ISDNAccessRelatedInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_ServiceProfileIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_TerminalType_vals[] = {
  {   0, "unknown" },
  {   1, "dialPulse" },
  {   2, "dtmf" },
  {   3, "isdn" },
  {   4, "isdnNoDtmf" },
  {  16, "spare" },
  { 0, NULL }
};


static int
dissect_inap_TerminalType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_ServingAreaID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_ServiceInteractionIndicators(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string inap_Entry_vals[] = {
  {   0, "agreements" },
  {   1, "networkSpecific" },
  { 0, NULL }
};

static const ber_choice_t Entry_choice[] = {
  {   0, &hf_inap_agreements     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_OBJECT_IDENTIFIER },
  {   1, &hf_inap_networkSpecific, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_Entry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Entry_choice, hf_index, ett_inap_Entry,
                                 NULL);

  return offset;
}


static const ber_sequence_t INServiceCompatibilityIndication_sequence_of[1] = {
  { &hf_inap_INServiceCompatibilityIndication_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Entry },
};

static int
dissect_inap_INServiceCompatibilityIndication(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      INServiceCompatibilityIndication_sequence_of, hf_index, ett_inap_INServiceCompatibilityIndication);

  return offset;
}


static const ber_sequence_t ForwardServiceInteractionInd_sequence[] = {
  { &hf_inap_conferenceTreatmentIndicator, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  { &hf_inap_callDiversionTreatmentIndicator, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  { &hf_inap_callOfferingTreatmentIndicator, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  { &hf_inap_callWaitingTreatmentIndicator, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  { &hf_inap_holdTreatmentIndicator, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  { &hf_inap_ectTreatmentIndicator, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ForwardServiceInteractionInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ForwardServiceInteractionInd_sequence, hf_index, ett_inap_ForwardServiceInteractionInd);

  return offset;
}



static int
dissect_inap_SuspendTimer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_inap_RedirectReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_redirectServiceTreatmentInd_sequence[] = {
  { &hf_inap_redirectReason , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_redirectServiceTreatmentInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_redirectServiceTreatmentInd_sequence, hf_index, ett_inap_T_redirectServiceTreatmentInd);

  return offset;
}


static const ber_sequence_t ServiceInteractionIndicatorsTwo_sequence[] = {
  { &hf_inap_forwardServiceInteractionInd, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardServiceInteractionInd },
  { &hf_inap_backwardServiceInteractionInd, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BackwardServiceInteractionInd },
  { &hf_inap_bothwayThroughConnectionInd, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BothwayThroughConnectionInd },
  { &hf_inap_suspendTimer   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_SuspendTimer },
  { &hf_inap_connectedNumberTreatmentInd, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ConnectedNumberTreatmentInd },
  { &hf_inap_suppressCallDiversionNotification, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_suppressCallTransferNotification, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_allowCdINNoPresentationInd, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_userDialogueDurationInd, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_overrideLineRestrictions, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_suppressVPNAPP , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_calledINNumberOverriding, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_redirectServiceTreatmentInd, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_T_redirectServiceTreatmentInd },
  { &hf_inap_nonCUGCall     , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ServiceInteractionIndicatorsTwo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceInteractionIndicatorsTwo_sequence, hf_index, ett_inap_ServiceInteractionIndicatorsTwo);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_minUSIServiceIndicatorLength_maxUSIServiceIndicatorLength(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_USIServiceIndicator_vals[] = {
  {   0, "global" },
  {   1, "local" },
  { 0, NULL }
};

static const ber_choice_t USIServiceIndicator_choice[] = {
  {   0, &hf_inap_global         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_inap_OBJECT_IDENTIFIER },
  {   1, &hf_inap_local          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_inap_OCTET_STRING_SIZE_minUSIServiceIndicatorLength_maxUSIServiceIndicatorLength },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_USIServiceIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 USIServiceIndicator_choice, hf_index, ett_inap_USIServiceIndicator,
                                 NULL);

  return offset;
}



static int
dissect_inap_USIInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_ForwardGVNS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t IPRelatedInformation_sequence[] = {
  { &hf_inap_alternativeCalledPartyIds, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlternativeIdentities },
  { &hf_inap_alternativeOriginatingPartyIds, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlternativeIdentities },
  { &hf_inap_alternativeOriginalCalledPartyIds, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlternativeIdentities },
  { &hf_inap_alternativeRedirectingPartyIds, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlternativeIdentities },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_IPRelatedInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPRelatedInformation_sequence, hf_index, ett_inap_IPRelatedInformation);

  return offset;
}


static const ber_sequence_t DpSpecificCommonParameters_sequence[] = {
  { &hf_inap_serviceAddressInformation, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_ServiceAddressInformation },
  { &hf_inap_bearerCapability, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_BearerCapability },
  { &hf_inap_calledPartyNumber, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_callingPartyNumber, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyNumber },
  { &hf_inap_callingPartysCategory, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartysCategory },
  { &hf_inap_iPSSPCapabilities, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPSSPCapabilities },
  { &hf_inap_iPAvailable    , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPAvailable },
  { &hf_inap_iSDNAccessRelatedInformation, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ISDNAccessRelatedInformation },
  { &hf_inap_cGEncountered  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CGEncountered },
  { &hf_inap_locationNumber , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_LocationNumber },
  { &hf_inap_serviceProfileIdentifier, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceProfileIdentifier },
  { &hf_inap_terminalType   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TerminalType },
  { &hf_inap_extensions     , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_chargeNumber   , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ChargeNumber },
  { &hf_inap_servingAreaID  , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServingAreaID },
  { &hf_inap_serviceInteractionIndicators, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicators },
  { &hf_inap_iNServiceCompatibilityIndication, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INServiceCompatibilityIndication },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_uSIServiceIndicator, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_USIServiceIndicator },
  { &hf_inap_uSIInformation , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_USIInformation },
  { &hf_inap_forwardGVNS    , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardGVNS },
  { &hf_inap_createdCallSegmentAssociation, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CSAID },
  { &hf_inap_ipRelatedInformation, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPRelatedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_DpSpecificCommonParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DpSpecificCommonParameters_sequence, hf_index, ett_inap_DpSpecificCommonParameters);

  return offset;
}



int
dissect_inap_Duration(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_collectedInfoSpecificInfo_sequence[] = {
  { &hf_inap_calledPartynumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_collectedInfoSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_collectedInfoSpecificInfo_sequence, hf_index, ett_inap_T_collectedInfoSpecificInfo);

  return offset;
}


static const ber_sequence_t T_analysedInfoSpecificInfo_sequence[] = {
  { &hf_inap_calledPartynumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_analysedInfoSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_analysedInfoSpecificInfo_sequence, hf_index, ett_inap_T_analysedInfoSpecificInfo);

  return offset;
}


static const ber_sequence_t T_routeSelectFailureSpecificInfo_sequence[] = {
  { &hf_inap_failureCause   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_routeSelectFailureSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_routeSelectFailureSpecificInfo_sequence, hf_index, ett_inap_T_routeSelectFailureSpecificInfo);

  return offset;
}


static const ber_sequence_t T_oCalledPartyBusySpecificInfo_sequence[] = {
  { &hf_inap_busyCause      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oCalledPartyBusySpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oCalledPartyBusySpecificInfo_sequence, hf_index, ett_inap_T_oCalledPartyBusySpecificInfo);

  return offset;
}


static const ber_sequence_t T_oNoAnswerSpecificInfo_sequence[] = {
  { &hf_inap_cause          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oNoAnswerSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oNoAnswerSpecificInfo_sequence, hf_index, ett_inap_T_oNoAnswerSpecificInfo);

  return offset;
}


static const ber_sequence_t T_oAnswerSpecificInfo_sequence[] = {
  { &hf_inap_backwardGVNS   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BackwardGVNS },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oAnswerSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oAnswerSpecificInfo_sequence, hf_index, ett_inap_T_oAnswerSpecificInfo);

  return offset;
}


static const ber_sequence_t MidCallInfo_sequence[] = {
  { &hf_inap_iNServiceControlCode, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MidCallInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MidCallInfo_sequence, hf_index, ett_inap_MidCallInfo);

  return offset;
}


static const ber_sequence_t T_oMidCallSpecificInfo_sequence[] = {
  { &hf_inap_connectTime    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { &hf_inap_oMidCallInfo   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_MidCallInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oMidCallSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oMidCallSpecificInfo_sequence, hf_index, ett_inap_T_oMidCallSpecificInfo);

  return offset;
}


static const ber_sequence_t T_oDisconnectSpecificInfo_sequence[] = {
  { &hf_inap_releaseCause   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_connectTime    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oDisconnectSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oDisconnectSpecificInfo_sequence, hf_index, ett_inap_T_oDisconnectSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tBusySpecificInfo_sequence[] = {
  { &hf_inap_busyCause      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_tBusySpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tBusySpecificInfo_sequence, hf_index, ett_inap_T_tBusySpecificInfo);

  return offset;
}


static const ber_sequence_t T_tNoAnswerSpecificInfo_sequence[] = {
  { &hf_inap_cause          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_tNoAnswerSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tNoAnswerSpecificInfo_sequence, hf_index, ett_inap_T_tNoAnswerSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tAnswerSpecificInfo_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_tAnswerSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tAnswerSpecificInfo_sequence, hf_index, ett_inap_T_tAnswerSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tMidCallSpecificInfo_sequence[] = {
  { &hf_inap_connectTime    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { &hf_inap_tMidCallInfo   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_MidCallInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_tMidCallSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tMidCallSpecificInfo_sequence, hf_index, ett_inap_T_tMidCallSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tDisconnectSpecificInfo_sequence[] = {
  { &hf_inap_releaseCause   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_connectTime    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_tDisconnectSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tDisconnectSpecificInfo_sequence, hf_index, ett_inap_T_tDisconnectSpecificInfo);

  return offset;
}


static const ber_sequence_t T_oTermSeizedSpecificInfo_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oTermSeizedSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oTermSeizedSpecificInfo_sequence, hf_index, ett_inap_T_oTermSeizedSpecificInfo);

  return offset;
}


static const ber_sequence_t T_oSuspend_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oSuspend(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oSuspend_sequence, hf_index, ett_inap_T_oSuspend);

  return offset;
}


static const ber_sequence_t T_tSuspend_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_tSuspend(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tSuspend_sequence, hf_index, ett_inap_T_tSuspend);

  return offset;
}


static const ber_sequence_t T_origAttemptAuthorized_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_origAttemptAuthorized(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_origAttemptAuthorized_sequence, hf_index, ett_inap_T_origAttemptAuthorized);

  return offset;
}


static const ber_sequence_t T_oReAnswer_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oReAnswer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oReAnswer_sequence, hf_index, ett_inap_T_oReAnswer);

  return offset;
}


static const ber_sequence_t T_tReAnswer_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_tReAnswer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tReAnswer_sequence, hf_index, ett_inap_T_tReAnswer);

  return offset;
}


static const ber_sequence_t T_facilitySelectedAndAvailable_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_facilitySelectedAndAvailable(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_facilitySelectedAndAvailable_sequence, hf_index, ett_inap_T_facilitySelectedAndAvailable);

  return offset;
}


static const ber_sequence_t T_callAccepted_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_callAccepted(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_callAccepted_sequence, hf_index, ett_inap_T_callAccepted);

  return offset;
}


static const ber_sequence_t T_oAbandon_sequence[] = {
  { &hf_inap_abandonCause   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oAbandon(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oAbandon_sequence, hf_index, ett_inap_T_oAbandon);

  return offset;
}


static const ber_sequence_t T_tAbandon_sequence[] = {
  { &hf_inap_abandonCause   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_tAbandon(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tAbandon_sequence, hf_index, ett_inap_T_tAbandon);

  return offset;
}


static const ber_sequence_t T_authorizeRouteFailure_sequence[] = {
  { &hf_inap_authoriseRouteFailureCause, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_authorizeRouteFailure(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_authorizeRouteFailure_sequence, hf_index, ett_inap_T_authorizeRouteFailure);

  return offset;
}


static const ber_sequence_t T_terminationAttemptAuthorized_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_terminationAttemptAuthorized(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_terminationAttemptAuthorized_sequence, hf_index, ett_inap_T_terminationAttemptAuthorized);

  return offset;
}


static const ber_sequence_t T_originationAttemptDenied_sequence[] = {
  { &hf_inap_originationDeniedCause, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_originationAttemptDenied(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_originationAttemptDenied_sequence, hf_index, ett_inap_T_originationAttemptDenied);

  return offset;
}


static const ber_sequence_t T_terminationAttemptDenied_sequence[] = {
  { &hf_inap_terminationDeniedCause, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_terminationAttemptDenied(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_terminationAttemptDenied_sequence, hf_index, ett_inap_T_terminationAttemptDenied);

  return offset;
}


static const ber_sequence_t T_oModifyRequestSpecificInfo_sequence[] = {
  { &hf_inap_aTMCellRate    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ATMCellRate },
  { &hf_inap_additionalATMCellRate, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AdditionalATMCellRate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oModifyRequestSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oModifyRequestSpecificInfo_sequence, hf_index, ett_inap_T_oModifyRequestSpecificInfo);

  return offset;
}


static const value_string inap_ModifyResultType_vals[] = {
  {   0, "modifyAcknowledge" },
  {   1, "modifyReject" },
  { 0, NULL }
};


static int
dissect_inap_ModifyResultType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_oModifyResultSpecificInfo_sequence[] = {
  { &hf_inap_modifyResultType, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ModifyResultType },
  { &hf_inap_aTMCellRate    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ATMCellRate },
  { &hf_inap_additionalATMCellRate, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AdditionalATMCellRate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oModifyResultSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oModifyResultSpecificInfo_sequence, hf_index, ett_inap_T_oModifyResultSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tModifyRequestSpecificInfo_sequence[] = {
  { &hf_inap_aTMCellRate    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ATMCellRate },
  { &hf_inap_additionalATMCellRate, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AdditionalATMCellRate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_tModifyRequestSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tModifyRequestSpecificInfo_sequence, hf_index, ett_inap_T_tModifyRequestSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tModifyResultSpecificInfo_sequence[] = {
  { &hf_inap_modifyResultType, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ModifyResultType },
  { &hf_inap_aTMCellRate    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ATMCellRate },
  { &hf_inap_additionalATMCellRate, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AdditionalATMCellRate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_tModifyResultSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tModifyResultSpecificInfo_sequence, hf_index, ett_inap_T_tModifyResultSpecificInfo);

  return offset;
}


static const value_string inap_EventSpecificInformationBCSM_vals[] = {
  {   0, "collectedInfoSpecificInfo" },
  {   1, "analysedInfoSpecificInfo" },
  {   2, "routeSelectFailureSpecificInfo" },
  {   3, "oCalledPartyBusySpecificInfo" },
  {   4, "oNoAnswerSpecificInfo" },
  {   5, "oAnswerSpecificInfo" },
  {   6, "oMidCallSpecificInfo" },
  {   7, "oDisconnectSpecificInfo" },
  {   8, "tBusySpecificInfo" },
  {   9, "tNoAnswerSpecificInfo" },
  {  10, "tAnswerSpecificInfo" },
  {  11, "tMidCallSpecificInfo" },
  {  12, "tDisconnectSpecificInfo" },
  {  13, "oTermSeizedSpecificInfo" },
  {  14, "oSuspend" },
  {  15, "tSuspend" },
  {  16, "origAttemptAuthorized" },
  {  17, "oReAnswer" },
  {  18, "tReAnswer" },
  {  19, "facilitySelectedAndAvailable" },
  {  20, "callAccepted" },
  {  21, "oAbandon" },
  {  22, "tAbandon" },
  {  23, "authorizeRouteFailure" },
  {  24, "terminationAttemptAuthorized" },
  {  25, "originationAttemptDenied" },
  {  26, "terminationAttemptDenied" },
  {  40, "oModifyRequestSpecificInfo" },
  {  41, "oModifyResultSpecificInfo" },
  {  42, "tModifyRequestSpecificInfo" },
  {  43, "tModifyResultSpecificInfo" },
  { 0, NULL }
};

static const ber_choice_t EventSpecificInformationBCSM_choice[] = {
  {   0, &hf_inap_collectedInfoSpecificInfo, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_T_collectedInfoSpecificInfo },
  {   1, &hf_inap_analysedInfoSpecificInfo, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_T_analysedInfoSpecificInfo },
  {   2, &hf_inap_routeSelectFailureSpecificInfo, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_T_routeSelectFailureSpecificInfo },
  {   3, &hf_inap_oCalledPartyBusySpecificInfo, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_T_oCalledPartyBusySpecificInfo },
  {   4, &hf_inap_oNoAnswerSpecificInfo, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_inap_T_oNoAnswerSpecificInfo },
  {   5, &hf_inap_oAnswerSpecificInfo, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_inap_T_oAnswerSpecificInfo },
  {   6, &hf_inap_oMidCallSpecificInfo, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_inap_T_oMidCallSpecificInfo },
  {   7, &hf_inap_oDisconnectSpecificInfo, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_inap_T_oDisconnectSpecificInfo },
  {   8, &hf_inap_tBusySpecificInfo, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_inap_T_tBusySpecificInfo },
  {   9, &hf_inap_tNoAnswerSpecificInfo, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_inap_T_tNoAnswerSpecificInfo },
  {  10, &hf_inap_tAnswerSpecificInfo, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_inap_T_tAnswerSpecificInfo },
  {  11, &hf_inap_tMidCallSpecificInfo, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_inap_T_tMidCallSpecificInfo },
  {  12, &hf_inap_tDisconnectSpecificInfo, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_inap_T_tDisconnectSpecificInfo },
  {  13, &hf_inap_oTermSeizedSpecificInfo, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_inap_T_oTermSeizedSpecificInfo },
  {  14, &hf_inap_oSuspend       , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_inap_T_oSuspend },
  {  15, &hf_inap_tSuspend       , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_inap_T_tSuspend },
  {  16, &hf_inap_origAttemptAuthorized, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_inap_T_origAttemptAuthorized },
  {  17, &hf_inap_oReAnswer      , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_inap_T_oReAnswer },
  {  18, &hf_inap_tReAnswer      , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_inap_T_tReAnswer },
  {  19, &hf_inap_facilitySelectedAndAvailable, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_inap_T_facilitySelectedAndAvailable },
  {  20, &hf_inap_callAccepted   , BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_inap_T_callAccepted },
  {  21, &hf_inap_oAbandon       , BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_inap_T_oAbandon },
  {  22, &hf_inap_tAbandon       , BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_inap_T_tAbandon },
  {  23, &hf_inap_authorizeRouteFailure, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_inap_T_authorizeRouteFailure },
  {  24, &hf_inap_terminationAttemptAuthorized, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_inap_T_terminationAttemptAuthorized },
  {  25, &hf_inap_originationAttemptDenied, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_inap_T_originationAttemptDenied },
  {  26, &hf_inap_terminationAttemptDenied, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_inap_T_terminationAttemptDenied },
  {  40, &hf_inap_oModifyRequestSpecificInfo, BER_CLASS_CON, 40, BER_FLAGS_IMPLTAG, dissect_inap_T_oModifyRequestSpecificInfo },
  {  41, &hf_inap_oModifyResultSpecificInfo, BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_inap_T_oModifyResultSpecificInfo },
  {  42, &hf_inap_tModifyRequestSpecificInfo, BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_inap_T_tModifyRequestSpecificInfo },
  {  43, &hf_inap_tModifyResultSpecificInfo, BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_inap_T_tModifyResultSpecificInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_EventSpecificInformationBCSM(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EventSpecificInformationBCSM_choice, hf_index, ett_inap_EventSpecificInformationBCSM,
                                 NULL);

  return offset;
}



static int
dissect_inap_EventSpecificInformationCharging(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_FacilityGroup_vals[] = {
  {   0, "trunkGroupID" },
  {   1, "privateFacilityID" },
  {   2, "huntGroup" },
  {   3, "routeIndex" },
  { 0, NULL }
};

static const ber_choice_t FacilityGroup_choice[] = {
  {   0, &hf_inap_trunkGroupID   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER },
  {   1, &hf_inap_privateFacilityID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER },
  {   2, &hf_inap_huntGroup      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING },
  {   3, &hf_inap_routeIndex     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_FacilityGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FacilityGroup_choice, hf_index, ett_inap_FacilityGroup,
                                 NULL);

  return offset;
}



static int
dissect_inap_FacilityGroupMember(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_FCIBillingChargingCharacteristics(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_FeatureCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string inap_FeatureRequestIndicator_vals[] = {
  {   0, "hold" },
  {   1, "retrieve" },
  {   2, "featureActivation" },
  {   3, "spare1" },
  { 127, "sparen" },
  { 0, NULL }
};


static int
dissect_inap_FeatureRequestIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_SFBillingChargingCharacteristics(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_MaximumNumberOfCounters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t FilteredCallTreatment_sequence[] = {
  { &hf_inap_sFBillingChargingCharacteristics, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_SFBillingChargingCharacteristics },
  { &hf_inap_informationToSend, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_InformationToSend },
  { &hf_inap_maximumNumberOfCounters, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_MaximumNumberOfCounters },
  { &hf_inap_releaseCause   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_FilteredCallTreatment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FilteredCallTreatment_sequence, hf_index, ett_inap_FilteredCallTreatment);

  return offset;
}



static int
dissect_inap_INTEGER_M1_32000(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string inap_FilteringCharacteristics_vals[] = {
  {   0, "interval" },
  {   1, "numberOfCalls" },
  { 0, NULL }
};

static const ber_choice_t FilteringCharacteristics_choice[] = {
  {   0, &hf_inap_filteringCharacteristics_interval, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_M1_32000 },
  {   1, &hf_inap_numberOfCalls  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_FilteringCharacteristics(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FilteringCharacteristics_choice, hf_index, ett_inap_FilteringCharacteristics,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_addressAndService_sequence[] = {
  { &hf_inap_calledAddressValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_serviceKey     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_ServiceKey },
  { &hf_inap_callingAddressValue, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_locationNumber , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_LocationNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_addressAndService(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_addressAndService_sequence, hf_index, ett_inap_T_addressAndService);

  return offset;
}


static const value_string inap_FilteringCriteria_vals[] = {
  {   0, "dialledNumber" },
  {   1, "callingLineID" },
  {   2, "serviceKey" },
  {  30, "addressAndService" },
  { 0, NULL }
};

static const ber_choice_t FilteringCriteria_choice[] = {
  {   0, &hf_inap_dialledNumber  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  {   1, &hf_inap_callingLineID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  {   2, &hf_inap_serviceKey     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_ServiceKey },
  {  30, &hf_inap_addressAndService, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_inap_T_addressAndService },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_FilteringCriteria(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FilteringCriteria_choice, hf_index, ett_inap_FilteringCriteria,
                                 NULL);

  return offset;
}


static const value_string inap_FilteringTimeOut_vals[] = {
  {   0, "duration" },
  {   1, "stopTime" },
  { 0, NULL }
};

static const ber_choice_t FilteringTimeOut_choice[] = {
  {   0, &hf_inap_duration       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Duration },
  {   1, &hf_inap_stopTime       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_DateAndTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_FilteringTimeOut(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FilteringTimeOut_choice, hf_index, ett_inap_FilteringTimeOut,
                                 NULL);

  return offset;
}



static int
dissect_inap_ForwardCallIndicators(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_ForwardingCondition_vals[] = {
  {   0, "busy" },
  {   1, "noanswer" },
  {   2, "any" },
  { 0, NULL }
};


static int
dissect_inap_ForwardingCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_GapCriteria_vals[] = {
  {   0, "basicGapCriteria" },
  {   1, "compoundCapCriteria" },
  { 0, NULL }
};

static const ber_choice_t GapCriteria_choice[] = {
  {   0, &hf_inap_basicGapCriteria, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_inap_BasicGapCriteria },
  {   1, &hf_inap_compoundCapCriteria, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_CompoundCriteria },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_GapCriteria(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GapCriteria_choice, hf_index, ett_inap_GapCriteria,
                                 NULL);

  return offset;
}



int
dissect_inap_Interval(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t GapIndicators_sequence[] = {
  { &hf_inap_duration       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Duration },
  { &hf_inap_gapInterval    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Interval },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_GapIndicators(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GapIndicators_sequence, hf_index, ett_inap_GapIndicators);

  return offset;
}



static int
dissect_inap_GenericIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_GenericName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_GenericNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t GenericNumbers_set_of[1] = {
  { &hf_inap_GenericNumbers_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_inap_GenericNumber },
};

static int
dissect_inap_GenericNumbers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 GenericNumbers_set_of, hf_index, ett_inap_GenericNumbers);

  return offset;
}



static int
dissect_inap_GlobalCallReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



int
dissect_inap_HighLayerCompatibility(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/*
 * -- Indicates the teleservice. For encoding, DSS1 (Q.931) is used.
 */
 tvbuff_t       *parameter_tvb;
 proto_tree     *subtree;
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_inap_HighLayerCompatibility);
  dissect_q931_high_layer_compat_ie(parameter_tvb, 0, tvb_reported_length_remaining(parameter_tvb,0), subtree);


  return offset;
}



static int
dissect_inap_HoldCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t Trigger_sequence[] = {
  { &hf_inap_trigger_tDPIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER },
  { &hf_inap_dpName         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_EventTypeBCSM },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_Trigger(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Trigger_sequence, hf_index, ett_inap_Trigger);

  return offset;
}


static const ber_sequence_t Triggers_sequence_of[1] = {
  { &hf_inap_Triggers_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_Trigger },
};

static int
dissect_inap_Triggers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Triggers_sequence_of, hf_index, ett_inap_Triggers);

  return offset;
}


static const value_string inap_TDPIdentifier_vals[] = {
  {   0, "oneTrigger" },
  {   1, "triggers" },
  { 0, NULL }
};

static const ber_choice_t TDPIdentifier_choice[] = {
  {   0, &hf_inap_oneTrigger     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_inap_INTEGER },
  {   1, &hf_inap_triggers       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Triggers },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TDPIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TDPIdentifier_choice, hf_index, ett_inap_TDPIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t INprofile_sequence[] = {
  { &hf_inap_actionOnProfile, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_ActionOnProfile },
  { &hf_inap_tDPIdentifier  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_TDPIdentifier },
  { &hf_inap_dPName         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_EventTypeBCSM },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_INprofile(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   INprofile_sequence, hf_index, ett_inap_INprofile);

  return offset;
}



static int
dissect_inap_INServiceCompatibilityResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Entry(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_IPRoutingAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_CalledPartyNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string inap_MonitoringCriteria_vals[] = {
  {   0, "threshold" },
  {   1, "interval" },
  { 0, NULL }
};

static const ber_choice_t MonitoringCriteria_choice[] = {
  {   0, &hf_inap_threshold      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  {   1, &hf_inap_interval       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Interval },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MonitoringCriteria(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MonitoringCriteria_choice, hf_index, ett_inap_MonitoringCriteria,
                                 NULL);

  return offset;
}


static const value_string inap_MonitoringTimeOut_vals[] = {
  {   0, "duration" },
  {   1, "stopTime" },
  { 0, NULL }
};

static const ber_choice_t MonitoringTimeOut_choice[] = {
  {   0, &hf_inap_duration       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Duration },
  {   1, &hf_inap_stopTime       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_DateAndTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MonitoringTimeOut(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MonitoringTimeOut_choice, hf_index, ett_inap_MonitoringTimeOut,
                                 NULL);

  return offset;
}



static int
dissect_inap_NumberingPlan(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_OriginalCalledPartyID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  tvbuff_t *parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  dissect_isup_original_called_number_parameter(parameter_tvb, actx->pinfo, tree, NULL);


  return offset;
}


static const value_string inap_ProfileIdentifier_vals[] = {
  {   0, "access" },
  {   1, "group" },
  { 0, NULL }
};

static const ber_choice_t ProfileIdentifier_choice[] = {
  {   0, &hf_inap_access         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  {   1, &hf_inap_group          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroup },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ProfileIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProfileIdentifier_choice, hf_index, ett_inap_ProfileIdentifier,
                                 NULL);

  return offset;
}



static int
dissect_inap_QoSParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_Reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_RedirectingPartyID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  tvbuff_t *parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

   dissect_isup_redirecting_number_parameter(parameter_tvb, actx->pinfo, tree, NULL);


  return offset;
}



int
dissect_inap_RedirectionInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

 subtree = proto_item_add_subtree(actx->created_item, ett_inap_RedirectionInformation);
 dissect_isup_redirection_information_parameter(parameter_tvb, subtree, NULL);


  return offset;
}



static int
dissect_inap_RegistratorIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_ReportCondition_vals[] = {
  {   0, "statusReport" },
  {   1, "timerExpired" },
  {   2, "canceled" },
  { 0, NULL }
};


static int
dissect_inap_ReportCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_RequestedInformationType_vals[] = {
  {   0, "callAttemptElapsedTime" },
  {   1, "callStopTime" },
  {   2, "callConnectedElapsedTime" },
  {   3, "calledAddress" },
  {  30, "releaseCause" },
  { 0, NULL }
};


static int
dissect_inap_RequestedInformationType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_INTEGER_0_255(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string inap_RequestedInformationValue_vals[] = {
  {   0, "callAttemptElapsedTimeValue" },
  {   1, "callStopTimeValue" },
  {   2, "callConnectedElapsedTimeValue" },
  {   3, "calledAddressValue" },
  {  30, "releaseCauseValue" },
  { 0, NULL }
};

static const ber_choice_t RequestedInformationValue_choice[] = {
  {   0, &hf_inap_callAttemptElapsedTimeValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_0_255 },
  {   1, &hf_inap_callStopTimeValue, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_DateAndTime },
  {   2, &hf_inap_callConnectedElapsedTimeValue, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  {   3, &hf_inap_calledAddressValue, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  {  30, &hf_inap_releaseCauseValue, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestedInformationValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RequestedInformationValue_choice, hf_index, ett_inap_RequestedInformationValue,
                                 NULL);

  return offset;
}


static const ber_sequence_t RequestedInformation_sequence[] = {
  { &hf_inap_requestedInformationType, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_RequestedInformationType },
  { &hf_inap_requestedInformationValue, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_RequestedInformationValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestedInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestedInformation_sequence, hf_index, ett_inap_RequestedInformation);

  return offset;
}


static const ber_sequence_t RequestedInformationList_sequence_of[1] = {
  { &hf_inap_RequestedInformationList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_RequestedInformation },
};

static int
dissect_inap_RequestedInformationList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RequestedInformationList_sequence_of, hf_index, ett_inap_RequestedInformationList);

  return offset;
}


static const ber_sequence_t RequestedInformationTypeList_sequence_of[1] = {
  { &hf_inap_RequestedInformationTypeList_item, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_inap_RequestedInformationType },
};

static int
dissect_inap_RequestedInformationTypeList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RequestedInformationTypeList_sequence_of, hf_index, ett_inap_RequestedInformationTypeList);

  return offset;
}


static const value_string inap_USIMonitorMode_vals[] = {
  {   0, "monitoringActive" },
  {   1, "monitoringInactive" },
  { 0, NULL }
};


static int
dissect_inap_USIMonitorMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t RequestedUTSI_sequence[] = {
  { &hf_inap_uSIServiceIndicator, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_USIServiceIndicator },
  { &hf_inap_uSImonitorMode , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_USIMonitorMode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestedUTSI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestedUTSI_sequence, hf_index, ett_inap_RequestedUTSI);

  return offset;
}


static const ber_sequence_t RequestedUTSIList_sequence_of[1] = {
  { &hf_inap_RequestedUTSIList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_RequestedUTSI },
};

static int
dissect_inap_RequestedUTSIList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RequestedUTSIList_sequence_of, hf_index, ett_inap_RequestedUTSIList);

  return offset;
}


static const value_string inap_ResourceID_vals[] = {
  {   0, "lineID" },
  {   1, "facilityGroupID" },
  {   2, "facilityGroupMemberID" },
  {   3, "trunkGroupID" },
  { 0, NULL }
};

static const ber_choice_t ResourceID_choice[] = {
  {   0, &hf_inap_lineID         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  {   1, &hf_inap_facilityGroupID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroup },
  {   2, &hf_inap_facilityGroupMemberID, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER },
  {   3, &hf_inap_trunkGroupID   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ResourceID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ResourceID_choice, hf_index, ett_inap_ResourceID,
                                 NULL);

  return offset;
}


static const value_string inap_ResourceStatus_vals[] = {
  {   0, "busy" },
  {   1, "idle" },
  { 0, NULL }
};


static int
dissect_inap_ResourceStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_ResponseCondition_vals[] = {
  {   0, "intermediateResponse" },
  {   1, "lastResponse" },
  { 0, NULL }
};


static int
dissect_inap_ResponseCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_Route(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t RouteCountersAndValue_sequence[] = {
  { &hf_inap_route          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Route },
  { &hf_inap_counterID      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_CounterID },
  { &hf_inap_counterValue   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RouteCountersAndValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RouteCountersAndValue_sequence, hf_index, ett_inap_RouteCountersAndValue);

  return offset;
}


static const ber_sequence_t RouteCountersValue_sequence_of[1] = {
  { &hf_inap_RouteCountersValue_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_RouteCountersAndValue },
};

static int
dissect_inap_RouteCountersValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RouteCountersValue_sequence_of, hf_index, ett_inap_RouteCountersValue);

  return offset;
}


static const ber_sequence_t RouteList_sequence_of[1] = {
  { &hf_inap_RouteList_item , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_inap_Route },
};

static int
dissect_inap_RouteList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RouteList_sequence_of, hf_index, ett_inap_RouteList);

  return offset;
}



static int
dissect_inap_RouteingNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_SCIBillingChargingCharacteristics(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_TimerID_vals[] = {
  {   0, "tssf" },
  { 0, NULL }
};


static int
dissect_inap_TimerID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_TimerValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Integer4(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_TravellingClassMark(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_T_triggerId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_T_triggerPar(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* FIX ME */


  return offset;
}


static const ber_sequence_t TriggerData_sequence[] = {
  { &hf_inap_triggerId      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_T_triggerId },
  { &hf_inap_triggerPar     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_T_triggerPar },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TriggerData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TriggerData_sequence, hf_index, ett_inap_TriggerData);

  return offset;
}


static const ber_sequence_t TriggerDataIdentifier_sequence[] = {
  { &hf_inap_triggerID      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_EventTypeBCSM },
  { &hf_inap_profile        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_ProfileIdentifier },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TriggerDataIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TriggerDataIdentifier_sequence, hf_index, ett_inap_TriggerDataIdentifier);

  return offset;
}


static const value_string inap_TriggerDPType_vals[] = {
  {   0, "tdp-r" },
  {   1, "tdp-n" },
  { 0, NULL }
};


static int
dissect_inap_TriggerDPType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t TriggerResult_sequence[] = {
  { &hf_inap_tDPIdentifer   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER },
  { &hf_inap_actionPerformed, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_ActionPerformed },
  { &hf_inap_dPName         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_EventTypeBCSM },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TriggerResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TriggerResult_sequence, hf_index, ett_inap_TriggerResult);

  return offset;
}


static const ber_sequence_t TriggerResults_sequence_of[1] = {
  { &hf_inap_TriggerResults_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_TriggerResult },
};

static int
dissect_inap_TriggerResults(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TriggerResults_sequence_of, hf_index, ett_inap_TriggerResults);

  return offset;
}


static const value_string inap_TriggerStatus_vals[] = {
  {   0, "created" },
  {   1, "alreadyExist" },
  {   2, "deleted" },
  {   3, "unknownTrigger" },
  { 0, NULL }
};


static int
dissect_inap_TriggerStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_VPNIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ActivateServiceFilteringArg_sequence[] = {
  { &hf_inap_filteredCallTreatment, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_FilteredCallTreatment },
  { &hf_inap_filteringCharacteristics, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FilteringCharacteristics },
  { &hf_inap_filteringTimeOut, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FilteringTimeOut },
  { &hf_inap_filteringCriteria, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FilteringCriteria },
  { &hf_inap_startTime      , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_DateAndTime },
  { &hf_inap_extensions     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ActivateServiceFilteringArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActivateServiceFilteringArg_sequence, hf_index, ett_inap_ActivateServiceFilteringArg);

  return offset;
}


static const ber_sequence_t AnalysedInformationArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_dialledDigits  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_callingFacilityGroup, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_callingFacilityGroupMember, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_prefix         , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_routeList      , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_featureCode    , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FeatureCode },
  { &hf_inap_accessCode     , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AccessCode },
  { &hf_inap_carrier        , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_componentType  , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_AnalysedInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AnalysedInformationArg_sequence, hf_index, ett_inap_AnalysedInformationArg);

  return offset;
}


static const ber_sequence_t AnalyseInformationArg_sequence[] = {
  { &hf_inap_destinationRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DestinationRoutingAddress },
  { &hf_inap_alertingPattern, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlertingPattern },
  { &hf_inap_iSDNAccessRelatedInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ISDNAccessRelatedInformation },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_extensions     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_callingPartyNumber, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyNumber },
  { &hf_inap_callingPartysCategory, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartysCategory },
  { &hf_inap_calledPartyNumber, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_chargeNumber   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ChargeNumber },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_carrier        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_serviceInteractionIndicators, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicators },
  { &hf_inap_iNServiceCompatibilityResponse, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_INServiceCompatibilityResponse },
  { &hf_inap_forwardGVNS    , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardGVNS },
  { &hf_inap_backwardGVNS   , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BackwardGVNS },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_correlationID  , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_scfID          , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ScfID },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_legToBeCreated , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_AnalyseInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AnalyseInformationArg_sequence, hf_index, ett_inap_AnalyseInformationArg);

  return offset;
}


static const ber_sequence_t ApplyChargingArg_sequence[] = {
  { &hf_inap_aChBillingChargingCharacteristics, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_AChBillingChargingCharacteristics },
  { &hf_inap_partyToCharge  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_releaseIndication, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_releaseCause   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ApplyChargingArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ApplyChargingArg_sequence, hf_index, ett_inap_ApplyChargingArg);

  return offset;
}



static int
dissect_inap_ApplyChargingReportArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_CallResult(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AssistRequestInstructionsArg_sequence[] = {
  { &hf_inap_correlationID  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_iPAvailable    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPAvailable },
  { &hf_inap_iPSSPCapabilities, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPSSPCapabilities },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_AssistRequestInstructionsArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AssistRequestInstructionsArg_sequence, hf_index, ett_inap_AssistRequestInstructionsArg);

  return offset;
}


static const ber_sequence_t AuthorizeTerminationArg_sequence[] = {
  { &hf_inap_alertingPattern, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlertingPattern },
  { &hf_inap_callingPartyNumber, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyNumber },
  { &hf_inap_destinationNumberRoutingAddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_displayInformation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_DisplayInformation },
  { &hf_inap_iSDNAccessRelatedInformation, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ISDNAccessRelatedInformation },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_iNServiceCompatibilityResponse, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_INServiceCompatibilityResponse },
  { &hf_inap_forwardGVNS    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardGVNS },
  { &hf_inap_backwardGVNS   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BackwardGVNS },
  { &hf_inap_legID          , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_scfID          , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ScfID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_AuthorizeTerminationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthorizeTerminationArg_sequence, hf_index, ett_inap_AuthorizeTerminationArg);

  return offset;
}


static const ber_sequence_t CallFilteringArg_sequence[] = {
  { &hf_inap_destinationIndex, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DestinationIndex },
  { &hf_inap_gapIndicators  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_GapIndicators },
  { &hf_inap_registratorIdentifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RegistratorIdentifier },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CallFilteringArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallFilteringArg_sequence, hf_index, ett_inap_CallFilteringArg);

  return offset;
}


static const ber_sequence_t CallGapArg_sequence[] = {
  { &hf_inap_gapCriteria    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_GapCriteria },
  { &hf_inap_gapIndicators  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_GapIndicators },
  { &hf_inap_controlType    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ControlType },
  { &hf_inap_gapTreatment   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_GapTreatment },
  { &hf_inap_extensions     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CallGapArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallGapArg_sequence, hf_index, ett_inap_CallGapArg);

  return offset;
}


static const ber_sequence_t CallInformationReportArg_sequence[] = {
  { &hf_inap_requestedInformationList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_RequestedInformationList },
  { &hf_inap_correlationID  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_legID          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_lastEventIndicator, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CallInformationReportArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallInformationReportArg_sequence, hf_index, ett_inap_CallInformationReportArg);

  return offset;
}


static const ber_sequence_t CallInformationRequestArg_sequence[] = {
  { &hf_inap_requestedInformationTypeList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_RequestedInformationTypeList },
  { &hf_inap_correlationID  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_legID          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CallInformationRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallInformationRequestArg_sequence, hf_index, ett_inap_CallInformationRequestArg);

  return offset;
}


static const ber_sequence_t T_callSegmentToCancel_sequence[] = {
  { &hf_inap_invokeID       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_InvokeID },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_callSegmentToCancel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_callSegmentToCancel_sequence, hf_index, ett_inap_T_callSegmentToCancel);

  return offset;
}


static const value_string inap_CancelArg_vals[] = {
  {   0, "invokeID" },
  {   1, "allRequests" },
  {   2, "callSegmentToCancel" },
  {   3, "allRequestsForCallSegment" },
  { 0, NULL }
};

static const ber_choice_t CancelArg_choice[] = {
  {   0, &hf_inap_invokeID       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_InvokeID },
  {   1, &hf_inap_allRequests    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  {   2, &hf_inap_callSegmentToCancel, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_T_callSegmentToCancel },
  {   3, &hf_inap_allRequestsForCallSegment, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CancelArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CancelArg_choice, hf_index, ett_inap_CancelArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t CancelStatusReportRequestArg_sequence[] = {
  { &hf_inap_resourceID     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_ResourceID },
  { &hf_inap_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CancelStatusReportRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelStatusReportRequestArg_sequence, hf_index, ett_inap_CancelStatusReportRequestArg);

  return offset;
}


static const ber_sequence_t CollectedInformationArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_dialledDigits  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_callingFacilityGroup, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_callingFacilityGroupMember, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_prefix         , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_featureCode    , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FeatureCode },
  { &hf_inap_accessCode     , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AccessCode },
  { &hf_inap_carrier        , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_componentType  , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CollectedInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CollectedInformationArg_sequence, hf_index, ett_inap_CollectedInformationArg);

  return offset;
}


static const ber_sequence_t CollectInformationArg_sequence[] = {
  { &hf_inap_alertingPattern, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlertingPattern },
  { &hf_inap_numberingPlan  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NumberingPlan },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_callingPartyNumber, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyNumber },
  { &hf_inap_dialledDigits  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_serviceInteractionIndicators, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicators },
  { &hf_inap_iNServiceCompatibilityResponse, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_INServiceCompatibilityResponse },
  { &hf_inap_forwardGVNS    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardGVNS },
  { &hf_inap_backwardGVNS   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BackwardGVNS },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_legToBeCreated , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CollectInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CollectInformationArg_sequence, hf_index, ett_inap_CollectInformationArg);

  return offset;
}


static const ber_sequence_t ConnectArg_sequence[] = {
  { &hf_inap_destinationRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DestinationRoutingAddress },
  { &hf_inap_alertingPattern, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlertingPattern },
  { &hf_inap_correlationID  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_cutAndPaste    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CutAndPaste },
  { &hf_inap_forwardingCondition, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardingCondition },
  { &hf_inap_iSDNAccessRelatedInformation, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ISDNAccessRelatedInformation },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_routeList      , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_scfID          , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ScfID },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_carrier        , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_serviceInteractionIndicators, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicators },
  { &hf_inap_callingPartyNumber, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyNumber },
  { &hf_inap_callingPartysCategory, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartysCategory },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_displayInformation, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_DisplayInformation },
  { &hf_inap_forwardCallIndicators, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardCallIndicators },
  { &hf_inap_genericNumbers , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GenericNumbers },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_iNServiceCompatibilityResponse, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_INServiceCompatibilityResponse },
  { &hf_inap_forwardGVNS    , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardGVNS },
  { &hf_inap_backwardGVNS   , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BackwardGVNS },
  { &hf_inap_chargeNumber   , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ChargeNumber },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_legToBeCreated , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_sDSSinformation, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_SDSSinformation },
  { &hf_inap_calledDirectoryNumber, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledDirectoryNumber },
  { &hf_inap_bearerCapability, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_BearerCapability },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_connectionIdentifier, BER_CLASS_CON, 61, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ConnectionIdentifier },
  { &hf_inap_genericIdentifier, BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GenericIdentifier },
  { &hf_inap_qOSParameter   , BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_QoSParameter },
  { &hf_inap_bISDNParameters, BER_CLASS_CON, 64, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BISDNParameters },
  { &hf_inap_cug_Interlock  , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CUG_Interlock },
  { &hf_inap_cug_OutgoingAccess, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { &hf_inap_ipRelatedInformation, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPRelatedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ConnectArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConnectArg_sequence, hf_index, ett_inap_ConnectArg);

  return offset;
}


static const ber_sequence_t T_ipAddressAndLegID_sequence[] = {
  { &hf_inap_ipRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_IPRoutingAddress },
  { &hf_inap_legID          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_ipAddressAndLegID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_ipAddressAndLegID_sequence, hf_index, ett_inap_T_ipAddressAndLegID);

  return offset;
}


static const ber_sequence_t T_ipAddressAndCallSegment_sequence[] = {
  { &hf_inap_ipRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_IPRoutingAddress },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_ipAddressAndCallSegment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_ipAddressAndCallSegment_sequence, hf_index, ett_inap_T_ipAddressAndCallSegment);

  return offset;
}


static const value_string inap_T_resourceAddress_vals[] = {
  {   0, "ipRoutingAddress" },
  {   1, "legID" },
  {   2, "ipAddressAndLegID" },
  {   3, "none" },
  {   5, "callSegmentID" },
  {   6, "ipAddressAndCallSegment" },
  { 0, NULL }
};

static const ber_choice_t T_resourceAddress_choice[] = {
  {   0, &hf_inap_ipRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_IPRoutingAddress },
  {   1, &hf_inap_legID          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_LegID },
  {   2, &hf_inap_ipAddressAndLegID, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_T_ipAddressAndLegID },
  {   3, &hf_inap_none           , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  {   5, &hf_inap_callSegmentID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  {   6, &hf_inap_ipAddressAndCallSegment, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_inap_T_ipAddressAndCallSegment },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_resourceAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_resourceAddress_choice, hf_index, ett_inap_T_resourceAddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t ConnectToResourceArg_sequence[] = {
  { &hf_inap_resourceAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_T_resourceAddress },
  { &hf_inap_extensions     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_serviceInteractionIndicators, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicators },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_uSIServiceIndicator, BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_USIServiceIndicator },
  { &hf_inap_uSIInformation , BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_USIInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ConnectToResourceArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConnectToResourceArg_sequence, hf_index, ett_inap_ConnectToResourceArg);

  return offset;
}


static const value_string inap_T_legorCSID_vals[] = {
  {   0, "legID" },
  {   9, "csID" },
  { 0, NULL }
};

static const ber_choice_t T_legorCSID_choice[] = {
  {   0, &hf_inap_legID          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_LegID },
  {   9, &hf_inap_csID           , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_legorCSID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_legorCSID_choice, hf_index, ett_inap_T_legorCSID,
                                 NULL);

  return offset;
}


static const ber_sequence_t ContinueWithArgumentArg_sequence[] = {
  { &hf_inap_legorCSID      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_T_legorCSID },
  { &hf_inap_alertingPattern, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlertingPattern },
  { &hf_inap_genericName    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GenericName },
  { &hf_inap_iNServiceCompatibilityResponse, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_INServiceCompatibilityResponse },
  { &hf_inap_forwardGVNS    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardGVNS },
  { &hf_inap_backwardGVNS   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BackwardGVNS },
  { &hf_inap_extensions     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_sDSSinformation, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_SDSSinformation },
  { &hf_inap_connectionIdentifier, BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ConnectionIdentifier },
  { &hf_inap_iSDNAccessRelatedInformation, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ISDNAccessRelatedInformation },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_callingPartyNumber, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyNumber },
  { &hf_inap_callingPartysCategory, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartysCategory },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_forwardCallIndicators, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardCallIndicators },
  { &hf_inap_genericNumbers , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GenericNumbers },
  { &hf_inap_cug_Interlock  , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CUG_Interlock },
  { &hf_inap_cug_OutgoingAccess, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { &hf_inap_ipRelationInformation, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPRelatedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ContinueWithArgumentArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContinueWithArgumentArg_sequence, hf_index, ett_inap_ContinueWithArgumentArg);

  return offset;
}


static const ber_sequence_t CreateCallSegmentAssociationArg_sequence[] = {
  { &hf_inap_extensions     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CreateCallSegmentAssociationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateCallSegmentAssociationArg_sequence, hf_index, ett_inap_CreateCallSegmentAssociationArg);

  return offset;
}


static const ber_sequence_t CreateCallSegmentAssociationResultArg_sequence[] = {
  { &hf_inap_newCallSegmentAssociation, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CSAID },
  { &hf_inap_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CreateCallSegmentAssociationResultArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateCallSegmentAssociationResultArg_sequence, hf_index, ett_inap_CreateCallSegmentAssociationResultArg);

  return offset;
}


static const ber_sequence_t CreateOrRemoveTriggerDataArg_sequence[] = {
  { &hf_inap_createOrRemove , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CreateOrRemoveIndicator },
  { &hf_inap_dPName         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_EventTypeBCSM },
  { &hf_inap_triggerDPType  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TriggerDPType },
  { &hf_inap_serviceKey     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceKey },
  { &hf_inap_profile        , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_ProfileIdentifier },
  { &hf_inap_triggerData    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TriggerData },
  { &hf_inap_defaultFaultHandling, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_DefaultFaultHandling },
  { &hf_inap_tDPIdentifier  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_TDPIdentifier },
  { &hf_inap_extensions     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CreateOrRemoveTriggerDataArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateOrRemoveTriggerDataArg_sequence, hf_index, ett_inap_CreateOrRemoveTriggerDataArg);

  return offset;
}


static const ber_sequence_t CreateOrRemoveTriggerDataResultArg_sequence[] = {
  { &hf_inap_triggerStatus  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_TriggerStatus },
  { &hf_inap_tDPIdentifier  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_TDPIdentifier },
  { &hf_inap_registratorIdentifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RegistratorIdentifier },
  { &hf_inap_extensions     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CreateOrRemoveTriggerDataResultArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateOrRemoveTriggerDataResultArg_sequence, hf_index, ett_inap_CreateOrRemoveTriggerDataResultArg);

  return offset;
}


static const value_string inap_T_partyToDisconnect_vals[] = {
  {   0, "legID" },
  {   1, "callSegmentID" },
  { 0, NULL }
};

static const ber_choice_t T_partyToDisconnect_choice[] = {
  {   0, &hf_inap_legID          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_LegID },
  {   1, &hf_inap_callSegmentID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_partyToDisconnect(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_partyToDisconnect_choice, hf_index, ett_inap_T_partyToDisconnect,
                                 NULL);

  return offset;
}


static const ber_sequence_t DisconnectForwardConnectionWithArgumentArg_sequence[] = {
  { &hf_inap_partyToDisconnect, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_T_partyToDisconnect },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_uSIServiceIndicator, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_USIServiceIndicator },
  { &hf_inap_uSIInformation , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_USIInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_DisconnectForwardConnectionWithArgumentArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisconnectForwardConnectionWithArgumentArg_sequence, hf_index, ett_inap_DisconnectForwardConnectionWithArgumentArg);

  return offset;
}


static const ber_sequence_t DisconnectLegArg_sequence[] = {
  { &hf_inap_legToBeReleased, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_releaseCause   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_DisconnectLegArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisconnectLegArg_sequence, hf_index, ett_inap_DisconnectLegArg);

  return offset;
}


static const ber_sequence_t T_cSFailure_sequence[] = {
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_reason         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Reason },
  { &hf_inap_cause          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_cSFailure(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_cSFailure_sequence, hf_index, ett_inap_T_cSFailure);

  return offset;
}


static const ber_sequence_t T_bCSMFailure_sequence[] = {
  { &hf_inap_legID          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_reason         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Reason },
  { &hf_inap_cause          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_bCSMFailure(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_bCSMFailure_sequence, hf_index, ett_inap_T_bCSMFailure);

  return offset;
}


static const value_string inap_EntityReleasedArg_vals[] = {
  {   0, "cSFailure" },
  {   1, "bCSMFailure" },
  { 0, NULL }
};

static const ber_choice_t EntityReleasedArg_choice[] = {
  {   0, &hf_inap_cSFailure      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_T_cSFailure },
  {   1, &hf_inap_bCSMFailure    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_T_bCSMFailure },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_EntityReleasedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EntityReleasedArg_choice, hf_index, ett_inap_EntityReleasedArg,
                                 NULL);

  return offset;
}


static const value_string inap_T_partyToConnect_vals[] = {
  {   2, "legID" },
  {   7, "callSegmentID" },
  { 0, NULL }
};

static const ber_choice_t T_partyToConnect_choice[] = {
  {   2, &hf_inap_legID          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_LegID },
  {   7, &hf_inap_callSegmentID  , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_partyToConnect(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_partyToConnect_choice, hf_index, ett_inap_T_partyToConnect,
                                 NULL);

  return offset;
}


static const ber_sequence_t EstablishTemporaryConnectionArg_sequence[] = {
  { &hf_inap_assistingSSPIPRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_AssistingSSPIPRoutingAddress },
  { &hf_inap_correlationID  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_partyToConnect , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_T_partyToConnect },
  { &hf_inap_scfID          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ScfID },
  { &hf_inap_extensions     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_carrier        , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_serviceInteractionIndicators, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicators },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_EstablishTemporaryConnectionArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EstablishTemporaryConnectionArg_sequence, hf_index, ett_inap_EstablishTemporaryConnectionArg);

  return offset;
}


static const ber_sequence_t EventNotificationChargingArg_sequence[] = {
  { &hf_inap_eventTypeCharging, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_EventTypeCharging },
  { &hf_inap_eventSpecificInformationCharging, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_EventSpecificInformationCharging },
  { &hf_inap_legID          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_monitorMode    , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_MonitorMode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_EventNotificationChargingArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventNotificationChargingArg_sequence, hf_index, ett_inap_EventNotificationChargingArg);

  return offset;
}


static const ber_sequence_t EventReportBCSMArg_sequence[] = {
  { &hf_inap_eventTypeBCSM  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_EventTypeBCSM },
  { &hf_inap_bcsmEventCorrelationID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_eventSpecificInformationBCSM, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_EventSpecificInformationBCSM },
  { &hf_inap_legID          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_miscCallInfo   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_MiscCallInfo },
  { &hf_inap_extensions     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_componentType  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_EventReportBCSMArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventReportBCSMArg_sequence, hf_index, ett_inap_EventReportBCSMArg);

  return offset;
}


static const ber_sequence_t EventReportFacilityArg_sequence[] = {
  { &hf_inap_componentType  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_legID          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { &hf_inap_extensions     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_EventReportFacilityArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventReportFacilityArg_sequence, hf_index, ett_inap_EventReportFacilityArg);

  return offset;
}


static const ber_sequence_t FacilitySelectedAndAvailableArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_calledPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyBusinessGroupID },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartyNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyNumber },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_routeList      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_componentType  , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_FacilitySelectedAndAvailableArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FacilitySelectedAndAvailableArg_sequence, hf_index, ett_inap_FacilitySelectedAndAvailableArg);

  return offset;
}



static int
dissect_inap_FurnishChargingInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_FCIBillingChargingCharacteristics(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string inap_HoldCallInNetworkArg_vals[] = {
  {   0, "holdcause" },
  {   1, "empty" },
  { 0, NULL }
};

static const ber_choice_t HoldCallInNetworkArg_choice[] = {
  {   0, &hf_inap_holdcause      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_HoldCause },
  {   1, &hf_inap_empty          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_HoldCallInNetworkArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 HoldCallInNetworkArg_choice, hf_index, ett_inap_HoldCallInNetworkArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t InitialDPArg_sequence[] = {
  { &hf_inap_serviceKey     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceKey },
  { &hf_inap_dialledDigits  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_calledPartyNumber, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_callingPartyNumber, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyNumber },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartysCategory, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartysCategory },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_cGEncountered  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CGEncountered },
  { &hf_inap_iPSSPCapabilities, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPSSPCapabilities },
  { &hf_inap_iPAvailable    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPAvailable },
  { &hf_inap_locationNumber , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_LocationNumber },
  { &hf_inap_miscCallInfo   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_MiscCallInfo },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_serviceProfileIdentifier, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceProfileIdentifier },
  { &hf_inap_terminalType   , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TerminalType },
  { &hf_inap_extensions     , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_triggerType    , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TriggerType },
  { &hf_inap_highLayerCompatibility, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_HighLayerCompatibility },
  { &hf_inap_serviceInteractionIndicators, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicators },
  { &hf_inap_additionalCallingPartyNumber, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AdditionalCallingPartyNumber },
  { &hf_inap_forwardCallIndicators, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardCallIndicators },
  { &hf_inap_bearerCapability, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_BearerCapability },
  { &hf_inap_eventTypeBCSM  , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_EventTypeBCSM },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_cause          , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_componentType  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { &hf_inap_iSDNAccessRelatedInformation, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ISDNAccessRelatedInformation },
  { &hf_inap_iNServiceCompatibilityIndication, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INServiceCompatibilityIndication },
  { &hf_inap_genericNumbers , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GenericNumbers },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_forwardGVNS    , BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardGVNS },
  { &hf_inap_createdCallSegmentAssociation, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CSAID },
  { &hf_inap_uSIServiceIndicator, BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_USIServiceIndicator },
  { &hf_inap_uSIInformation , BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_USIInformation },
  { &hf_inap_carrier        , BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_cCSS           , BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CCSS },
  { &hf_inap_vPNIndicator   , BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_VPNIndicator },
  { &hf_inap_cNInfo         , BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CNInfo },
  { &hf_inap_callReference  , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallReference },
  { &hf_inap_routeingNumber , BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteingNumber },
  { &hf_inap_callingGeodeticLocation, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingGeodeticLocation },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_connectionIdentifier, BER_CLASS_CON, 61, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ConnectionIdentifier },
  { &hf_inap_genericIdentifier, BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GenericIdentifier },
  { &hf_inap_qOSParameter   , BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_QoSParameter },
  { &hf_inap_bISDNParameters, BER_CLASS_CON, 64, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BISDNParameters },
  { &hf_inap_globalCallReference, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GlobalCallReference },
  { &hf_inap_cug_Index      , BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CUG_Index },
  { &hf_inap_cug_Interlock  , BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CUG_Interlock },
  { &hf_inap_cug_OutgoingAccess, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { &hf_inap_ipRelatedInformation, BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPRelatedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_InitialDPArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitialDPArg_sequence, hf_index, ett_inap_InitialDPArg);

  return offset;
}


static const ber_sequence_t InitiateCallAttemptArg_sequence[] = {
  { &hf_inap_destinationRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DestinationRoutingAddress },
  { &hf_inap_alertingPattern, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlertingPattern },
  { &hf_inap_iSDNAccessRelatedInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ISDNAccessRelatedInformation },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_serviceInteractionIndicators, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicators },
  { &hf_inap_callingPartyNumber, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyNumber },
  { &hf_inap_legToBeCreated , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_newCallSegment , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_iNServiceCompatibilityResponse, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_INServiceCompatibilityResponse },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_carrier        , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_correlationID  , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_scfID          , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ScfID },
  { &hf_inap_callReference  , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallReference },
  { &hf_inap_calledDirectoryNumber, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledDirectoryNumber },
  { &hf_inap_bearerCapability, BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_BearerCapability },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 61, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_connectionIdentifier, BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ConnectionIdentifier },
  { &hf_inap_genericIdentifier, BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GenericIdentifier },
  { &hf_inap_qOSParameter   , BER_CLASS_CON, 64, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_QoSParameter },
  { &hf_inap_bISDNParameters, BER_CLASS_CON, 65, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BISDNParameters },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_callingPartysCategory, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartysCategory },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_displayInformation, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_DisplayInformation },
  { &hf_inap_forwardCallIndicators, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardCallIndicators },
  { &hf_inap_genericNumbers , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GenericNumbers },
  { &hf_inap_forwardGVNS    , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardGVNS },
  { &hf_inap_globalCallReference, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GlobalCallReference },
  { &hf_inap_cug_Interlock  , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CUG_Interlock },
  { &hf_inap_cug_OutgoingAccess, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { &hf_inap_incomingSignallingBufferCopy, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_ipRelatedInformation, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPRelatedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_InitiateCallAttemptArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitiateCallAttemptArg_sequence, hf_index, ett_inap_InitiateCallAttemptArg);

  return offset;
}


static const value_string inap_T_triggerDataIdentifier_vals[] = {
  {   1, "profileAndDP" },
  {   5, "profile" },
  { 0, NULL }
};

static const ber_choice_t T_triggerDataIdentifier_choice[] = {
  {   1, &hf_inap_profileAndDP   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_TriggerDataIdentifier },
  {   5, &hf_inap_profile        , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_inap_ProfileIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_triggerDataIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_triggerDataIdentifier_choice, hf_index, ett_inap_T_triggerDataIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t ManageTriggerDataArg_sequence[] = {
  { &hf_inap_actionIndicator, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_ActionIndicator },
  { &hf_inap_triggerDataIdentifier, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_T_triggerDataIdentifier },
  { &hf_inap_registratorIdentifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RegistratorIdentifier },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_tDPIdentifier  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_TDPIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ManageTriggerDataArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ManageTriggerDataArg_sequence, hf_index, ett_inap_ManageTriggerDataArg);

  return offset;
}


static const ber_sequence_t T_oneTriggerResult_sequence[] = {
  { &hf_inap_actionPerformed, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_ActionPerformed },
  { &hf_inap_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_oneTriggerResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oneTriggerResult_sequence, hf_index, ett_inap_T_oneTriggerResult);

  return offset;
}


static const ber_sequence_t T_severalTriggerResult_sequence[] = {
  { &hf_inap_results        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_TriggerResults },
  { &hf_inap_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_severalTriggerResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_severalTriggerResult_sequence, hf_index, ett_inap_T_severalTriggerResult);

  return offset;
}


static const value_string inap_ManageTriggerDataResultArg_vals[] = {
  {   0, "oneTriggerResult" },
  {   1, "severalTriggerResult" },
  { 0, NULL }
};

static const ber_choice_t ManageTriggerDataResultArg_choice[] = {
  {   0, &hf_inap_oneTriggerResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_T_oneTriggerResult },
  {   1, &hf_inap_severalTriggerResult, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_T_severalTriggerResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ManageTriggerDataResultArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ManageTriggerDataResultArg_choice, hf_index, ett_inap_ManageTriggerDataResultArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t MergeCallSegmentsArg_sequence[] = {
  { &hf_inap_sourceCallSegment, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_targetCallSegment, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_mergeSignallingPaths, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MergeCallSegmentsArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MergeCallSegmentsArg_sequence, hf_index, ett_inap_MergeCallSegmentsArg);

  return offset;
}


static const ber_sequence_t MonitorRouteReportArg_sequence[] = {
  { &hf_inap_routeCounters  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_RouteCountersValue },
  { &hf_inap_correlationID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MonitorRouteReportArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MonitorRouteReportArg_sequence, hf_index, ett_inap_MonitorRouteReportArg);

  return offset;
}


static const ber_sequence_t MonitorRouteRequestArg_sequence[] = {
  { &hf_inap_routeList      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_correlationID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_monitoringCriteria, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_MonitoringCriteria },
  { &hf_inap_monitoringTimeout, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_MonitoringTimeOut },
  { &hf_inap_startTime      , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_DateAndTime },
  { &hf_inap_extensions     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MonitorRouteRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MonitorRouteRequestArg_sequence, hf_index, ett_inap_MonitorRouteRequestArg);

  return offset;
}


static const ber_sequence_t T_callSegments_item_sequence[] = {
  { &hf_inap_sourceCallSegment, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_newCallSegment , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_callSegments_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_callSegments_item_sequence, hf_index, ett_inap_T_callSegments_item);

  return offset;
}


static const ber_sequence_t T_callSegments_sequence_of[1] = {
  { &hf_inap_callSegments_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_T_callSegments_item },
};

static int
dissect_inap_T_callSegments(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_callSegments_sequence_of, hf_index, ett_inap_T_callSegments);

  return offset;
}


static const ber_sequence_t T_legs_item_sequence[] = {
  { &hf_inap_sourceLeg      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_newLeg         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_legs_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_legs_item_sequence, hf_index, ett_inap_T_legs_item);

  return offset;
}


static const ber_sequence_t T_legs_sequence_of[1] = {
  { &hf_inap_legs_item      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_T_legs_item },
};

static int
dissect_inap_T_legs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_legs_sequence_of, hf_index, ett_inap_T_legs);

  return offset;
}


static const ber_sequence_t MoveCallSegmentsArg_sequence[] = {
  { &hf_inap_targetCallSegmentAssociation, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CSAID },
  { &hf_inap_callSegments   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_T_callSegments },
  { &hf_inap_legs           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_T_legs },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MoveCallSegmentsArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MoveCallSegmentsArg_sequence, hf_index, ett_inap_MoveCallSegmentsArg);

  return offset;
}


static const ber_sequence_t MoveLegArg_sequence[] = {
  { &hf_inap_legIDToMove    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_targetCallSegment, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_detachSignallingPath, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { &hf_inap_exportSignallingPath, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MoveLegArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MoveLegArg_sequence, hf_index, ett_inap_MoveLegArg);

  return offset;
}


static const ber_sequence_t OAbandonArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_releaseCause   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_OAbandonArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OAbandonArg_sequence, hf_index, ett_inap_OAbandonArg);

  return offset;
}


static const ber_sequence_t OAnswerArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_callingFacilityGroup, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_callingFacilityGroupMember, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_routeList      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_OAnswerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OAnswerArg_sequence, hf_index, ett_inap_OAnswerArg);

  return offset;
}


static const ber_sequence_t OCalledPartyBusyArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_busyCause      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_callingFacilityGroup, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_callingFacilityGroupMember, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_prefix         , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_routeList      , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_carrier        , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_OCalledPartyBusyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OCalledPartyBusyArg_sequence, hf_index, ett_inap_OCalledPartyBusyArg);

  return offset;
}


static const ber_sequence_t ODisconnectArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_callingFacilityGroup, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_callingFacilityGroupMember, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_releaseCause   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_routeList      , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_extensions     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_carrier        , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_connectTime    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { &hf_inap_componentType  , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ODisconnectArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ODisconnectArg_sequence, hf_index, ett_inap_ODisconnectArg);

  return offset;
}


static const ber_sequence_t MidCallArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_calledPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyBusinessGroupID },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_featureRequestIndicator, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FeatureRequestIndicator },
  { &hf_inap_extensions     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_carrier        , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_componentType  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MidCallArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MidCallArg_sequence, hf_index, ett_inap_MidCallArg);

  return offset;
}


static const ber_sequence_t ONoAnswerArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_callingFacilityGroup, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_callingFacilityGroupMember, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_prefix         , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_routeList      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_carrier        , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ONoAnswerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ONoAnswerArg_sequence, hf_index, ett_inap_ONoAnswerArg);

  return offset;
}


static const ber_sequence_t OriginationAttemptArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_callingFacilityGroup, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_callingFacilityGroupMember, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_carrier        , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_componentType  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componenttCorrelationID, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_OriginationAttemptArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OriginationAttemptArg_sequence, hf_index, ett_inap_OriginationAttemptArg);

  return offset;
}


static const ber_sequence_t OriginationAttemptAuthorizedArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_dialledDigits  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_callingFacilityGroup, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_callingFacilityGroupMember, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_carrier        , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_componentType  , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_OriginationAttemptAuthorizedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OriginationAttemptAuthorizedArg_sequence, hf_index, ett_inap_OriginationAttemptAuthorizedArg);

  return offset;
}


static const ber_sequence_t OSuspendedArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_legID          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_OSuspendedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OSuspendedArg_sequence, hf_index, ett_inap_OSuspendedArg);

  return offset;
}


static const ber_sequence_t ReconnectArg_sequence[] = {
  { &hf_inap_notificationDuration, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ApplicationTimer },
  { &hf_inap_alertingPattern, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlertingPattern },
  { &hf_inap_displayInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_DisplayInformation },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ReconnectArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReconnectArg_sequence, hf_index, ett_inap_ReconnectArg);

  return offset;
}



static int
dissect_inap_INTEGER_1_numOfCSs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_callSegmentToRelease_sequence[] = {
  { &hf_inap_callSegment    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_1_numOfCSs },
  { &hf_inap_releaseCause   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_forcedRelease  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_callSegmentToRelease(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_callSegmentToRelease_sequence, hf_index, ett_inap_T_callSegmentToRelease);

  return offset;
}


static const ber_sequence_t T_allCallSegments_sequence[] = {
  { &hf_inap_releaseCause   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_timeToRelease  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TimerValue },
  { &hf_inap_forcedRelease  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_allCallSegments(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_allCallSegments_sequence, hf_index, ett_inap_T_allCallSegments);

  return offset;
}


static const value_string inap_ReleaseCallArg_vals[] = {
  {   0, "initialCallSegment" },
  {   1, "callSegmentToRelease" },
  {   2, "allCallSegments" },
  { 0, NULL }
};

static const ber_choice_t ReleaseCallArg_choice[] = {
  {   0, &hf_inap_initialCallSegment, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_inap_Cause },
  {   1, &hf_inap_callSegmentToRelease, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_T_callSegmentToRelease },
  {   2, &hf_inap_allCallSegments, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_T_allCallSegments },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ReleaseCallArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ReleaseCallArg_choice, hf_index, ett_inap_ReleaseCallArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t ReportUTSIArg_sequence[] = {
  { &hf_inap_uSIServiceIndicator, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_USIServiceIndicator },
  { &hf_inap_legID          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_uSIInformation , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_USIInformation },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ReportUTSIArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportUTSIArg_sequence, hf_index, ett_inap_ReportUTSIArg);

  return offset;
}



static int
dissect_inap_RequestCurrentStatusReportArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_ResourceID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t RequestCurrentStatusReportResultArg_sequence[] = {
  { &hf_inap_resourceStatus , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_ResourceStatus },
  { &hf_inap_resourceID     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_ResourceID },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestCurrentStatusReportResultArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestCurrentStatusReportResultArg_sequence, hf_index, ett_inap_RequestCurrentStatusReportResultArg);

  return offset;
}


static const ber_sequence_t RequestEveryStatusChangeReportArg_sequence[] = {
  { &hf_inap_resourceID     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_ResourceID },
  { &hf_inap_correlationID  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_monitorDuration, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Duration },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestEveryStatusChangeReportArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestEveryStatusChangeReportArg_sequence, hf_index, ett_inap_RequestEveryStatusChangeReportArg);

  return offset;
}


static const ber_sequence_t RequestFirstStatusMatchReportArg_sequence[] = {
  { &hf_inap_resourceID     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_ResourceID },
  { &hf_inap_resourceStatus , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ResourceStatus },
  { &hf_inap_correlationID  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_monitorDuration, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Duration },
  { &hf_inap_extensions     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_bearerCapability, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_BearerCapability },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestFirstStatusMatchReportArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestFirstStatusMatchReportArg_sequence, hf_index, ett_inap_RequestFirstStatusMatchReportArg);

  return offset;
}


static const ber_sequence_t RequestNotificationChargingEventArg_sequence_of[1] = {
  { &hf_inap_RequestNotificationChargingEventArg_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_ChargingEvent },
};

static int
dissect_inap_RequestNotificationChargingEventArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RequestNotificationChargingEventArg_sequence_of, hf_index, ett_inap_RequestNotificationChargingEventArg);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent_sequence_of[1] = {
  { &hf_inap_bcsmEvents_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_BCSMEvent },
};

static int
dissect_inap_SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent_sequence_of, hf_index, ett_inap_SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent);

  return offset;
}


static const ber_sequence_t RequestReportBCSMEventArg_sequence[] = {
  { &hf_inap_bcsmEvents     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent },
  { &hf_inap_bcsmEventCorrelationID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestReportBCSMEventArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestReportBCSMEventArg_sequence, hf_index, ett_inap_RequestReportBCSMEventArg);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_3_OF_ComponentType_sequence_of[1] = {
  { &hf_inap_componentTypes_item, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_inap_ComponentType },
};

static int
dissect_inap_SEQUENCE_SIZE_1_3_OF_ComponentType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_3_OF_ComponentType_sequence_of, hf_index, ett_inap_SEQUENCE_SIZE_1_3_OF_ComponentType);

  return offset;
}


static const ber_sequence_t RequestReportFacilityEventArg_sequence[] = {
  { &hf_inap_componentTypes , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_SEQUENCE_SIZE_1_3_OF_ComponentType },
  { &hf_inap_legID          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { &hf_inap_monitorDuration, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_Duration },
  { &hf_inap_extensions     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestReportFacilityEventArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestReportFacilityEventArg_sequence, hf_index, ett_inap_RequestReportFacilityEventArg);

  return offset;
}


static const ber_sequence_t RequestReportUTSIArg_sequence[] = {
  { &hf_inap_requestedUTSIList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_RequestedUTSIList },
  { &hf_inap_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_legID          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestReportUTSIArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestReportUTSIArg_sequence, hf_index, ett_inap_RequestReportUTSIArg);

  return offset;
}


static const ber_sequence_t ResetTimerArg_sequence[] = {
  { &hf_inap_timerID        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TimerID },
  { &hf_inap_timervalue     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_TimerValue },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ResetTimerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResetTimerArg_sequence, hf_index, ett_inap_ResetTimerArg);

  return offset;
}


static const ber_sequence_t RouteSelectFailureArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_dialledDigits  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_callingFacilityGroup, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_callingFacilityGroupMember, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_failureCause   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_prefix         , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_routeList      , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_carrier        , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_RouteSelectFailureArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RouteSelectFailureArg_sequence, hf_index, ett_inap_RouteSelectFailureArg);

  return offset;
}


static const ber_sequence_t SelectFacilityArg_sequence[] = {
  { &hf_inap_alertingPattern, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlertingPattern },
  { &hf_inap_destinationNumberRoutingAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyNumber },
  { &hf_inap_iSDNAccessRelatedInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ISDNAccessRelatedInformation },
  { &hf_inap_calledFacilityGroup, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_calledFacilityGroupMember, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_extensions     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_displayInformation, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_DisplayInformation },
  { &hf_inap_serviceInteractionIndicators, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicators },
  { &hf_inap_iNServiceCompatibilityResponse, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_INServiceCompatibilityResponse },
  { &hf_inap_forwardGVNS    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardGVNS },
  { &hf_inap_backwardGVNS   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BackwardGVNS },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_correlationID  , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_scfID          , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ScfID },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_legToBeCreated , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_ipRelatedInformation, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPRelatedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_SelectFacilityArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SelectFacilityArg_sequence, hf_index, ett_inap_SelectFacilityArg);

  return offset;
}


static const ber_sequence_t SelectRouteArg_sequence[] = {
  { &hf_inap_destinationRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DestinationRoutingAddress },
  { &hf_inap_alertingPattern, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_AlertingPattern },
  { &hf_inap_correlationID  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_iSDNAccessRelatedInformation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ISDNAccessRelatedInformation },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_routeList      , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_scfID          , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ScfID },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_carrier        , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Carrier },
  { &hf_inap_serviceInteractionIndicators, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicators },
  { &hf_inap_iNServiceCompatibilityResponse, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_INServiceCompatibilityResponse },
  { &hf_inap_forwardGVNS    , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ForwardGVNS },
  { &hf_inap_backwardGVNS   , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BackwardGVNS },
  { &hf_inap_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ServiceInteractionIndicatorsTwo },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_legToBeCreated , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_ipRelatedInformation, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_IPRelatedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_SelectRouteArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SelectRouteArg_sequence, hf_index, ett_inap_SelectRouteArg);

  return offset;
}


static const ber_sequence_t SendChargingInformationArg_sequence[] = {
  { &hf_inap_sCIBillingChargingCharacteristics, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_SCIBillingChargingCharacteristics },
  { &hf_inap_partyToCharge  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_nocharge       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_SendChargingInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SendChargingInformationArg_sequence, hf_index, ett_inap_SendChargingInformationArg);

  return offset;
}


static const ber_sequence_t SendFacilityInformationArg_sequence[] = {
  { &hf_inap_componentType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_legID          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { &hf_inap_component      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_callProcessingOperation, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallProcessingOperation },
  { &hf_inap_extensions     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_SendFacilityInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SendFacilityInformationArg_sequence, hf_index, ett_inap_SendFacilityInformationArg);

  return offset;
}


static const ber_sequence_t SendSTUIArg_sequence[] = {
  { &hf_inap_uSIServiceIndicator, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_USIServiceIndicator },
  { &hf_inap_legID          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_uSIInformation , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_USIInformation },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_SendSTUIArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SendSTUIArg_sequence, hf_index, ett_inap_SendSTUIArg);

  return offset;
}


static const ber_sequence_t ServiceFilteringResponseArg_sequence[] = {
  { &hf_inap_countersValue  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CountersValue },
  { &hf_inap_filteringCriteria, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FilteringCriteria },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_responseCondition, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ResponseCondition },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ServiceFilteringResponseArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceFilteringResponseArg_sequence, hf_index, ett_inap_ServiceFilteringResponseArg);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_numOfINProfile_OF_INprofile_sequence_of[1] = {
  { &hf_inap_iNprofiles_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inap_INprofile },
};

static int
dissect_inap_SEQUENCE_SIZE_1_numOfINProfile_OF_INprofile(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_numOfINProfile_OF_INprofile_sequence_of, hf_index, ett_inap_SEQUENCE_SIZE_1_numOfINProfile_OF_INprofile);

  return offset;
}


static const ber_sequence_t SetServiceProfileArg_sequence[] = {
  { &hf_inap_iNprofiles     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_SEQUENCE_SIZE_1_numOfINProfile_OF_INprofile },
  { &hf_inap_extensions     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_SetServiceProfileArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetServiceProfileArg_sequence, hf_index, ett_inap_SetServiceProfileArg);

  return offset;
}



static int
dissect_inap_INTEGER_2_numOfCSs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SplitLegArg_sequence[] = {
  { &hf_inap_legToBeSplit   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_newCallSegment_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_2_numOfCSs },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_detachSignallingPath, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_SplitLegArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SplitLegArg_sequence, hf_index, ett_inap_SplitLegArg);

  return offset;
}


static const ber_sequence_t StatusReportArg_sequence[] = {
  { &hf_inap_resourceStatus , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ResourceStatus },
  { &hf_inap_correlationID  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CorrelationID },
  { &hf_inap_resourceID     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_ResourceID },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_reportCondition, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ReportCondition },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_StatusReportArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StatusReportArg_sequence, hf_index, ett_inap_StatusReportArg);

  return offset;
}


static const ber_sequence_t TAnswerArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_calledPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyBusinessGroupID },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_calledFacilityGroup, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_calledFacilityGroupMember, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_extensions     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_componentType  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TAnswerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TAnswerArg_sequence, hf_index, ett_inap_TAnswerArg);

  return offset;
}


static const ber_sequence_t TBusyArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_busyCause      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_calledPartyBusinessGroupID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyBusinessGroupID },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_routeList      , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TBusyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TBusyArg_sequence, hf_index, ett_inap_TBusyArg);

  return offset;
}


static const ber_sequence_t TDisconnectArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_calledPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyBusinessGroupID },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_calledFacilityGroup, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_calledFacilityGroupMember, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_releaseCause   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Cause },
  { &hf_inap_extensions     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_connectTime    , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Integer4 },
  { &hf_inap_componentType  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TDisconnectArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TDisconnectArg_sequence, hf_index, ett_inap_TDisconnectArg);

  return offset;
}


static const ber_sequence_t TermAttemptAuthorizedArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_calledPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyBusinessGroupID },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_routeList      , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TermAttemptAuthorizedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TermAttemptAuthorizedArg_sequence, hf_index, ett_inap_TermAttemptAuthorizedArg);

  return offset;
}


static const ber_sequence_t TerminationAttemptArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_calledPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyBusinessGroupID },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_callingPartyBusinessGroupID, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartyBusinessGroupID },
  { &hf_inap_callingPartySubaddress, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallingPartySubaddress },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_routeList      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RouteList },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TerminationAttemptArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminationAttemptArg_sequence, hf_index, ett_inap_TerminationAttemptArg);

  return offset;
}


static const ber_sequence_t TNoAnswerArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_calledPartyBusinessGroupID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartyBusinessGroupID },
  { &hf_inap_calledPartySubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CalledPartySubaddress },
  { &hf_inap_calledFacilityGroup, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_FacilityGroup },
  { &hf_inap_calledFacilityGroupMember, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_FacilityGroupMember },
  { &hf_inap_originalCalledPartyID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OriginalCalledPartyID },
  { &hf_inap_redirectingPartyID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectingPartyID },
  { &hf_inap_redirectionInformation, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RedirectionInformation },
  { &hf_inap_travellingClassMark, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_TravellingClassMark },
  { &hf_inap_extensions     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_componentType  , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentType },
  { &hf_inap_component      , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Component },
  { &hf_inap_componentCorrelationID, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ComponentCorrelationID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TNoAnswerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TNoAnswerArg_sequence, hf_index, ett_inap_TNoAnswerArg);

  return offset;
}


static const ber_sequence_t TSuspendedArg_sequence[] = {
  { &hf_inap_dpSpecificCommonParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_DpSpecificCommonParameters },
  { &hf_inap_legID          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_LegID },
  { &hf_inap_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_TSuspendedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TSuspendedArg_sequence, hf_index, ett_inap_TSuspendedArg);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_1_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_ErrorTreatment_vals[] = {
  {   0, "reportErrorToScf" },
  {   1, "help" },
  {   2, "repeatPrompt" },
  { 0, NULL }
};


static int
dissect_inap_ErrorTreatment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CollectedDigits_sequence[] = {
  { &hf_inap_minimumNbOfDigits, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_1_127 },
  { &hf_inap_maximumNbOfDigits, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_1_127 },
  { &hf_inap_endOfReplyDigit, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1_2 },
  { &hf_inap_cancelDigit    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1_2 },
  { &hf_inap_startDigit     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1_2 },
  { &hf_inap_firstDigitTimeOut, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_1_127 },
  { &hf_inap_interDigitTimeOut, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_1_127 },
  { &hf_inap_errorTreatment , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ErrorTreatment },
  { &hf_inap_interruptableAnnInd, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_voiceInformation, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_voiceBack      , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_detectModem    , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CollectedDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CollectedDigits_sequence, hf_index, ett_inap_CollectedDigits);

  return offset;
}


static const value_string inap_CollectedInfo_vals[] = {
  {   0, "collectedDigits" },
  {   1, "iA5Information" },
  {   2, "detectModem" },
  { 0, NULL }
};

static const ber_choice_t CollectedInfo_choice[] = {
  {   0, &hf_inap_collectedDigits, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_CollectedDigits },
  {   1, &hf_inap_iA5Information , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  {   2, &hf_inap_detectModem    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_CollectedInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CollectedInfo_choice, hf_index, ett_inap_CollectedInfo,
                                 NULL);

  return offset;
}



static int
dissect_inap_ElementaryMessageID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Integer4(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_GapOnResource(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Code(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_INTEGER_1_3600(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_INTEGER_0_b3__maxRecordingTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_controlDigits_sequence[] = {
  { &hf_inap_endOfRecordingDigit, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1_2 },
  { &hf_inap_cancelDigit    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1_2 },
  { &hf_inap_replayDigit    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1_2 },
  { &hf_inap_restartRecordingDigit, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_OCTET_STRING_SIZE_1_2 },
  { &hf_inap_restartAllowed , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_replayAllowed  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_controlDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_controlDigits_sequence, hf_index, ett_inap_T_controlDigits);

  return offset;
}


static const ber_sequence_t InformationToRecord_sequence[] = {
  { &hf_inap_messageID_01   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ElementaryMessageID },
  { &hf_inap_messageDeletionTimeOut, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_1_3600 },
  { &hf_inap_timeToRecord   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_0_b3__maxRecordingTime },
  { &hf_inap_controlDigits  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_inap_T_controlDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_InformationToRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InformationToRecord_sequence, hf_index, ett_inap_InformationToRecord);

  return offset;
}



static int
dissect_inap_MailBoxID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_Media_vals[] = {
  {   0, "voiceMail" },
  {   1, "faxGroup3" },
  {   2, "faxGroup4" },
  { 0, NULL }
};


static int
dissect_inap_Media(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_ReceivedStatus_vals[] = {
  {   0, "messageComplete" },
  {   1, "messageInterrupted" },
  {   2, "messageTimeOut" },
  { 0, NULL }
};


static int
dissect_inap_ReceivedStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_RecordedMessageID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Integer4(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_iPAddressAndresource_sequence[] = {
  { &hf_inap_iPAddressValue , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  { &hf_inap_gapOnResource  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_GapOnResource },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_iPAddressAndresource(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_iPAddressAndresource_sequence, hf_index, ett_inap_T_iPAddressAndresource);

  return offset;
}


static const value_string inap_SRFGapCriteria_vals[] = {
  {   1, "iPAddressValue" },
  {   2, "gapOnResource" },
  {   3, "iPAddressAndresource" },
  { 0, NULL }
};

static const ber_choice_t SRFGapCriteria_choice[] = {
  {   1, &hf_inap_iPAddressValue , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  {   2, &hf_inap_gapOnResource  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_GapOnResource },
  {   3, &hf_inap_iPAddressAndresource, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_T_iPAddressAndresource },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_SRFGapCriteria(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SRFGapCriteria_choice, hf_index, ett_inap_SRFGapCriteria,
                                 NULL);

  return offset;
}


static const value_string inap_T_connectedParty_vals[] = {
  {   4, "legID" },
  {   5, "callSegmentID" },
  { 0, NULL }
};

static const ber_choice_t T_connectedParty_choice[] = {
  {   4, &hf_inap_legID          , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_inap_LegID },
  {   5, &hf_inap_callSegmentID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_connectedParty(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_connectedParty_choice, hf_index, ett_inap_T_connectedParty,
                                 NULL);

  return offset;
}


static const ber_sequence_t PlayAnnouncementArg_sequence[] = {
  { &hf_inap_informationToSend, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_InformationToSend },
  { &hf_inap_disconnectFromIPForbidden, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_requestAnnouncementComplete, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_connectedParty , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_T_connectedParty },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_PlayAnnouncementArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PlayAnnouncementArg_sequence, hf_index, ett_inap_PlayAnnouncementArg);

  return offset;
}


static const ber_sequence_t PromptAndCollectUserInformationArg_sequence[] = {
  { &hf_inap_collectedInfo  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_CollectedInfo },
  { &hf_inap_disconnectFromIPForbidden, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_informationToSend, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_InformationToSend },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_PromptAndCollectUserInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PromptAndCollectUserInformationArg_sequence, hf_index, ett_inap_PromptAndCollectUserInformationArg);

  return offset;
}



static int
dissect_inap_IA5String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string inap_ReceivedInformationArg_vals[] = {
  {   0, "digitsResponse" },
  {   1, "iA5Response" },
  {   2, "modemdetected" },
  { 0, NULL }
};

static const ber_choice_t ReceivedInformationArg_choice[] = {
  {   0, &hf_inap_digitsResponse , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_Digits },
  {   1, &hf_inap_iA5Response    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_IA5String },
  {   2, &hf_inap_modemdetected  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ReceivedInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ReceivedInformationArg_choice, hf_index, ett_inap_ReceivedInformationArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t PromptAndReceiveMessageArg_sequence[] = {
  { &hf_inap_disconnectFromIPForbidden, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_informationToSend, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_InformationToSend },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_subscriberID   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_GenericNumber },
  { &hf_inap_mailBoxID      , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_MailBoxID },
  { &hf_inap_informationToRecord, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_inap_InformationToRecord },
  { &hf_inap_media          , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Media },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_PromptAndReceiveMessageArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PromptAndReceiveMessageArg_sequence, hf_index, ett_inap_PromptAndReceiveMessageArg);

  return offset;
}



static int
dissect_inap_INTEGER_1_b3__maxRecordedMessageUnits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t MessageReceivedArg_sequence[] = {
  { &hf_inap_receivedStatus , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_ReceivedStatus },
  { &hf_inap_recordedMessageID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_RecordedMessageID },
  { &hf_inap_recordedMessageUnits, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_INTEGER_1_b3__maxRecordedMessageUnits },
  { &hf_inap_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_MessageReceivedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageReceivedArg_sequence, hf_index, ett_inap_MessageReceivedArg);

  return offset;
}



static int
dissect_inap_T_uIScriptSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* FIX ME */


  return offset;
}


static const ber_sequence_t ScriptCloseArg_sequence[] = {
  { &hf_inap_uIScriptId     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Code },
  { &hf_inap_uIScriptSpecificInfo, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_T_uIScriptSpecificInfo },
  { &hf_inap_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ScriptCloseArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScriptCloseArg_sequence, hf_index, ett_inap_ScriptCloseArg);

  return offset;
}



static int
dissect_inap_T_uIScriptResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* FIX ME */


  return offset;
}


static const ber_sequence_t ScriptEventArg_sequence[] = {
  { &hf_inap_uIScriptId     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Code },
  { &hf_inap_uIScriptResult , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_T_uIScriptResult },
  { &hf_inap_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { &hf_inap_lastEventIndicator, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ScriptEventArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScriptEventArg_sequence, hf_index, ett_inap_ScriptEventArg);

  return offset;
}



static int
dissect_inap_T_uIScriptSpecificInfo_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* FIX ME */

  return offset;
}


static const ber_sequence_t ScriptInformationArg_sequence[] = {
  { &hf_inap_uIScriptId     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Code },
  { &hf_inap_uIScriptSpecificInfo_01, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_T_uIScriptSpecificInfo_01 },
  { &hf_inap_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ScriptInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScriptInformationArg_sequence, hf_index, ett_inap_ScriptInformationArg);

  return offset;
}



static int
dissect_inap_T_uIScriptSpecificInfo_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* FIX ME */


  return offset;
}


static const ber_sequence_t ScriptRunArg_sequence[] = {
  { &hf_inap_uIScriptId     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Code },
  { &hf_inap_uIScriptSpecificInfo_02, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_T_uIScriptSpecificInfo_02 },
  { &hf_inap_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { &hf_inap_disconnectFromIPForbidden, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_BOOLEAN },
  { &hf_inap_callSegmentID  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ScriptRunArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScriptRunArg_sequence, hf_index, ett_inap_ScriptRunArg);

  return offset;
}



static int
dissect_inap_SpecializedResourceReportArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t SRFCallGapArg_sequence[] = {
  { &hf_inap_sRFgapCriteria , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_SRFGapCriteria },
  { &hf_inap_gapIndicators  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_GapIndicators },
  { &hf_inap_controlType    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_ControlType },
  { &hf_inap_extensions     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inap_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_SRFCallGapArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SRFCallGapArg_sequence, hf_index, ett_inap_SRFCallGapArg);

  return offset;
}


static const value_string inap_T_problem_vals[] = {
  {   0, "unknownOperation" },
  {   1, "tooLate" },
  {   2, "operationNotCancellable" },
  { 0, NULL }
};


static int
dissect_inap_T_problem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PAR_cancelFailed_sequence[] = {
  { &hf_inap_problem        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_T_problem },
  { &hf_inap_operation      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_InvokeID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_PAR_cancelFailed(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PAR_cancelFailed_sequence, hf_index, ett_inap_PAR_cancelFailed);

  return offset;
}


static const value_string inap_PAR_requestedInfoError_vals[] = {
  {   1, "unknownRequestedInfo" },
  {   2, "requestedInfoNotAvailable" },
  { 0, NULL }
};


static int
dissect_inap_PAR_requestedInfoError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_T_scfTaskRefusedParameter_reason_vals[] = {
  {   0, "generic" },
  {   1, "unobtainable" },
  {   2, "congestion" },
  { 0, NULL }
};


static int
dissect_inap_T_scfTaskRefusedParameter_reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ScfTaskRefusedParameter_sequence[] = {
  { &hf_inap_scfTaskRefusedParameter_reason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_inap_T_scfTaskRefusedParameter_reason },
  { &hf_inap_securityParameters, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dap_SecurityParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ScfTaskRefusedParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScfTaskRefusedParameter_sequence, hf_index, ett_inap_ScfTaskRefusedParameter);

  return offset;
}


static const ber_sequence_t ReferralParameter_sequence[] = {
  { &hf_inap_tryhere        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dsp_AccessPointInformation },
  { &hf_inap_securityParameters, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dap_SecurityParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ReferralParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReferralParameter_sequence, hf_index, ett_inap_ReferralParameter);

  return offset;
}


static const value_string inap_PAR_taskRefused_vals[] = {
  {   0, "generic" },
  {   1, "unobtainable" },
  {   2, "congestion" },
  { 0, NULL }
};


static int
dissect_inap_PAR_taskRefused(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_InvokeId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t InvokeId_choice[] = {
  {   0, &hf_inap_present        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_inap_INTEGER },
  {   1, &hf_inap_absent         , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_inap_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_InvokeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InvokeId_choice, hf_index, ett_inap_InvokeId,
                                 NULL);

  return offset;
}



static int
dissect_inap_InvokeId_present(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_inap_T_inkedIdPresent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_InvokeId_present(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string inap_T_linkedId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t T_linkedId_choice[] = {
  {   0, &hf_inap_inkedIdPresent , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_T_inkedIdPresent },
  {   1, &hf_inap_absent         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_linkedId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_linkedId_choice, hf_index, ett_inap_T_linkedId,
                                 NULL);

  return offset;
}



static int
dissect_inap_T_argument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_invokeData(tree, tvb, offset, actx);


  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { &hf_inap_invokeId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_InvokeId },
  { &hf_inap_linkedId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_T_linkedId },
  { &hf_inap_opcode         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Code },
  { &hf_inap_argument       , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_inap_T_argument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_Invoke(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  inap_opcode_type=INAP_OPCODE_INVOKE;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_inap_Invoke);

  return offset;
}



static int
dissect_inap_ResultArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_returnResultData(tree, tvb, offset, actx);


  return offset;
}


static const ber_sequence_t T_result_sequence[] = {
  { &hf_inap_opcode         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Code },
  { &hf_inap_resultArgument , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_inap_ResultArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_result_sequence, hf_index, ett_inap_T_result);

  return offset;
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { &hf_inap_invokeId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_InvokeId },
  { &hf_inap_result         , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_inap_T_result },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ReturnResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  inap_opcode_type=INAP_OPCODE_RETURN_RESULT;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_inap_ReturnResult);

  return offset;
}



static int
dissect_inap_T_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_returnErrorData(tree, tvb, offset, actx);




  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_inap_invokeId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_InvokeId },
  { &hf_inap_errcode        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_Code },
  { &hf_inap_parameter      , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_inap_T_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ReturnError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  inap_opcode_type=INAP_OPCODE_RETURN_ERROR;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_inap_ReturnError);

  return offset;
}


static const value_string inap_GeneralProblem_vals[] = {
  {   0, "unrecognizedPDU" },
  {   1, "mistypedPDU" },
  {   2, "badlyStructuredPDU" },
  { 0, NULL }
};


static int
dissect_inap_GeneralProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string inap_InvokeProblem_vals[] = {
  {   0, "duplicateInvocation" },
  {   1, "unrecognizedOperation" },
  {   2, "mistypedArgument" },
  {   3, "resourceLimitation" },
  {   4, "releaseInProgress" },
  {   5, "unrecognizedLinkedId" },
  {   6, "linkedResponseUnexpected" },
  {   7, "unexpectedLinkedOperation" },
  { 0, NULL }
};


static int
dissect_inap_InvokeProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string inap_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "resultResponseUnexpected" },
  {   2, "mistypedResult" },
  { 0, NULL }
};


static int
dissect_inap_ReturnResultProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string inap_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "errorResponseUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_inap_ReturnErrorProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string inap_T_problem_01_vals[] = {
  {   0, "general" },
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  { 0, NULL }
};

static const ber_choice_t T_problem_01_choice[] = {
  {   0, &hf_inap_general        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inap_GeneralProblem },
  {   1, &hf_inap_invokeProblem  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_InvokeProblem },
  {   2, &hf_inap_problemReturnResult, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_ReturnResultProblem },
  {   3, &hf_inap_returnErrorProblem, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_ReturnErrorProblem },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_T_problem_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_problem_01_choice, hf_index, ett_inap_T_problem_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t Reject_sequence[] = {
  { &hf_inap_invokeId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_InvokeId },
  { &hf_inap_problem_01     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_inap_T_problem_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_Reject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  inap_opcode_type=INAP_OPCODE_REJECT;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_inap_Reject);

  return offset;
}


static const ber_choice_t ROS_choice[] = {
  {   1, &hf_inap_invoke         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inap_Invoke },
  {   2, &hf_inap_returnResult   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_inap_ReturnResult },
  {   3, &hf_inap_returnError    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_inap_ReturnError },
  {   4, &hf_inap_reject         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_inap_Reject },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_inap_ROS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ROS_choice, hf_index, ett_inap_ROS,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ActivateServiceFilteringArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ActivateServiceFilteringArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ActivateServiceFilteringArg_PDU);
  return offset;
}
static int dissect_AnalysedInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_AnalysedInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_AnalysedInformationArg_PDU);
  return offset;
}
static int dissect_AnalyseInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_AnalyseInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_AnalyseInformationArg_PDU);
  return offset;
}
static int dissect_ApplyChargingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ApplyChargingArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ApplyChargingArg_PDU);
  return offset;
}
static int dissect_ApplyChargingReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ApplyChargingReportArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ApplyChargingReportArg_PDU);
  return offset;
}
static int dissect_AssistRequestInstructionsArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_AssistRequestInstructionsArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_AssistRequestInstructionsArg_PDU);
  return offset;
}
static int dissect_AuthorizeTerminationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_AuthorizeTerminationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_AuthorizeTerminationArg_PDU);
  return offset;
}
static int dissect_CallFilteringArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CallFilteringArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CallFilteringArg_PDU);
  return offset;
}
static int dissect_CallGapArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CallGapArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CallGapArg_PDU);
  return offset;
}
static int dissect_CallInformationReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CallInformationReportArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CallInformationReportArg_PDU);
  return offset;
}
static int dissect_CallInformationRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CallInformationRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CallInformationRequestArg_PDU);
  return offset;
}
static int dissect_CancelArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CancelArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CancelArg_PDU);
  return offset;
}
static int dissect_CancelStatusReportRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CancelStatusReportRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CancelStatusReportRequestArg_PDU);
  return offset;
}
static int dissect_CollectedInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CollectedInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CollectedInformationArg_PDU);
  return offset;
}
static int dissect_CollectInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CollectInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CollectInformationArg_PDU);
  return offset;
}
static int dissect_ConnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ConnectArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ConnectArg_PDU);
  return offset;
}
static int dissect_ConnectToResourceArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ConnectToResourceArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ConnectToResourceArg_PDU);
  return offset;
}
static int dissect_ContinueWithArgumentArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ContinueWithArgumentArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ContinueWithArgumentArg_PDU);
  return offset;
}
static int dissect_CreateCallSegmentAssociationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CreateCallSegmentAssociationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CreateCallSegmentAssociationArg_PDU);
  return offset;
}
static int dissect_CreateCallSegmentAssociationResultArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CreateCallSegmentAssociationResultArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CreateCallSegmentAssociationResultArg_PDU);
  return offset;
}
static int dissect_CreateOrRemoveTriggerDataArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CreateOrRemoveTriggerDataArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CreateOrRemoveTriggerDataArg_PDU);
  return offset;
}
static int dissect_CreateOrRemoveTriggerDataResultArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_CreateOrRemoveTriggerDataResultArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_CreateOrRemoveTriggerDataResultArg_PDU);
  return offset;
}
static int dissect_DisconnectForwardConnectionWithArgumentArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_DisconnectForwardConnectionWithArgumentArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_DisconnectForwardConnectionWithArgumentArg_PDU);
  return offset;
}
static int dissect_DisconnectLegArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_DisconnectLegArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_DisconnectLegArg_PDU);
  return offset;
}
static int dissect_EntityReleasedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_EntityReleasedArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_EntityReleasedArg_PDU);
  return offset;
}
static int dissect_EstablishTemporaryConnectionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_EstablishTemporaryConnectionArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_EstablishTemporaryConnectionArg_PDU);
  return offset;
}
static int dissect_EventNotificationChargingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_EventNotificationChargingArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_EventNotificationChargingArg_PDU);
  return offset;
}
static int dissect_EventReportBCSMArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_EventReportBCSMArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_EventReportBCSMArg_PDU);
  return offset;
}
static int dissect_EventReportFacilityArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_EventReportFacilityArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_EventReportFacilityArg_PDU);
  return offset;
}
static int dissect_FacilitySelectedAndAvailableArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_FacilitySelectedAndAvailableArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_FacilitySelectedAndAvailableArg_PDU);
  return offset;
}
static int dissect_FurnishChargingInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_FurnishChargingInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_FurnishChargingInformationArg_PDU);
  return offset;
}
static int dissect_HoldCallInNetworkArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_HoldCallInNetworkArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_HoldCallInNetworkArg_PDU);
  return offset;
}
static int dissect_InitialDPArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_InitialDPArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_InitialDPArg_PDU);
  return offset;
}
static int dissect_InitiateCallAttemptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_InitiateCallAttemptArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_InitiateCallAttemptArg_PDU);
  return offset;
}
static int dissect_ManageTriggerDataArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ManageTriggerDataArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ManageTriggerDataArg_PDU);
  return offset;
}
static int dissect_ManageTriggerDataResultArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ManageTriggerDataResultArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ManageTriggerDataResultArg_PDU);
  return offset;
}
static int dissect_MergeCallSegmentsArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_MergeCallSegmentsArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_MergeCallSegmentsArg_PDU);
  return offset;
}
static int dissect_MonitorRouteReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_MonitorRouteReportArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_MonitorRouteReportArg_PDU);
  return offset;
}
static int dissect_MonitorRouteRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_MonitorRouteRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_MonitorRouteRequestArg_PDU);
  return offset;
}
static int dissect_MoveCallSegmentsArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_MoveCallSegmentsArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_MoveCallSegmentsArg_PDU);
  return offset;
}
static int dissect_MoveLegArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_MoveLegArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_MoveLegArg_PDU);
  return offset;
}
static int dissect_OAbandonArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_OAbandonArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_OAbandonArg_PDU);
  return offset;
}
static int dissect_OAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_OAnswerArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_OAnswerArg_PDU);
  return offset;
}
static int dissect_OCalledPartyBusyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_OCalledPartyBusyArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_OCalledPartyBusyArg_PDU);
  return offset;
}
static int dissect_ODisconnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ODisconnectArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ODisconnectArg_PDU);
  return offset;
}
static int dissect_MidCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_MidCallArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_MidCallArg_PDU);
  return offset;
}
static int dissect_ONoAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ONoAnswerArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ONoAnswerArg_PDU);
  return offset;
}
static int dissect_OriginationAttemptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_OriginationAttemptArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_OriginationAttemptArg_PDU);
  return offset;
}
static int dissect_OriginationAttemptAuthorizedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_OriginationAttemptAuthorizedArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_OriginationAttemptAuthorizedArg_PDU);
  return offset;
}
static int dissect_OSuspendedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_OSuspendedArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_OSuspendedArg_PDU);
  return offset;
}
static int dissect_ReconnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ReconnectArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ReconnectArg_PDU);
  return offset;
}
static int dissect_ReleaseCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ReleaseCallArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ReleaseCallArg_PDU);
  return offset;
}
static int dissect_ReportUTSIArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ReportUTSIArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ReportUTSIArg_PDU);
  return offset;
}
static int dissect_RequestCurrentStatusReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_RequestCurrentStatusReportArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_RequestCurrentStatusReportArg_PDU);
  return offset;
}
static int dissect_RequestCurrentStatusReportResultArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_RequestCurrentStatusReportResultArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_RequestCurrentStatusReportResultArg_PDU);
  return offset;
}
static int dissect_RequestEveryStatusChangeReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_RequestEveryStatusChangeReportArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_RequestEveryStatusChangeReportArg_PDU);
  return offset;
}
static int dissect_RequestFirstStatusMatchReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_RequestFirstStatusMatchReportArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_RequestFirstStatusMatchReportArg_PDU);
  return offset;
}
static int dissect_RequestNotificationChargingEventArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_RequestNotificationChargingEventArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_RequestNotificationChargingEventArg_PDU);
  return offset;
}
static int dissect_RequestReportBCSMEventArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_RequestReportBCSMEventArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_RequestReportBCSMEventArg_PDU);
  return offset;
}
static int dissect_RequestReportFacilityEventArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_RequestReportFacilityEventArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_RequestReportFacilityEventArg_PDU);
  return offset;
}
static int dissect_RequestReportUTSIArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_RequestReportUTSIArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_RequestReportUTSIArg_PDU);
  return offset;
}
static int dissect_ResetTimerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ResetTimerArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ResetTimerArg_PDU);
  return offset;
}
static int dissect_RouteSelectFailureArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_RouteSelectFailureArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_RouteSelectFailureArg_PDU);
  return offset;
}
static int dissect_SelectFacilityArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_SelectFacilityArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_SelectFacilityArg_PDU);
  return offset;
}
static int dissect_SelectRouteArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_SelectRouteArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_SelectRouteArg_PDU);
  return offset;
}
static int dissect_SendChargingInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_SendChargingInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_SendChargingInformationArg_PDU);
  return offset;
}
static int dissect_SendFacilityInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_SendFacilityInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_SendFacilityInformationArg_PDU);
  return offset;
}
static int dissect_SendSTUIArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_SendSTUIArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_SendSTUIArg_PDU);
  return offset;
}
static int dissect_ServiceFilteringResponseArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ServiceFilteringResponseArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ServiceFilteringResponseArg_PDU);
  return offset;
}
static int dissect_SetServiceProfileArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_SetServiceProfileArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_SetServiceProfileArg_PDU);
  return offset;
}
static int dissect_SplitLegArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_SplitLegArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_SplitLegArg_PDU);
  return offset;
}
static int dissect_StatusReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_StatusReportArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_StatusReportArg_PDU);
  return offset;
}
static int dissect_TAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_TAnswerArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_TAnswerArg_PDU);
  return offset;
}
static int dissect_TBusyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_TBusyArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_TBusyArg_PDU);
  return offset;
}
static int dissect_TDisconnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_TDisconnectArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_TDisconnectArg_PDU);
  return offset;
}
static int dissect_TermAttemptAuthorizedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_TermAttemptAuthorizedArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_TermAttemptAuthorizedArg_PDU);
  return offset;
}
static int dissect_TerminationAttemptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_TerminationAttemptArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_TerminationAttemptArg_PDU);
  return offset;
}
static int dissect_TNoAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_TNoAnswerArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_TNoAnswerArg_PDU);
  return offset;
}
static int dissect_TSuspendedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_TSuspendedArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_TSuspendedArg_PDU);
  return offset;
}
static int dissect_PlayAnnouncementArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_PlayAnnouncementArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_PlayAnnouncementArg_PDU);
  return offset;
}
static int dissect_PromptAndCollectUserInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_PromptAndCollectUserInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_PromptAndCollectUserInformationArg_PDU);
  return offset;
}
static int dissect_ReceivedInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ReceivedInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ReceivedInformationArg_PDU);
  return offset;
}
static int dissect_PromptAndReceiveMessageArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_PromptAndReceiveMessageArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_PromptAndReceiveMessageArg_PDU);
  return offset;
}
static int dissect_MessageReceivedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_MessageReceivedArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_MessageReceivedArg_PDU);
  return offset;
}
static int dissect_ScriptCloseArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ScriptCloseArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ScriptCloseArg_PDU);
  return offset;
}
static int dissect_ScriptEventArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ScriptEventArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ScriptEventArg_PDU);
  return offset;
}
static int dissect_ScriptInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ScriptInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ScriptInformationArg_PDU);
  return offset;
}
static int dissect_ScriptRunArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ScriptRunArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_ScriptRunArg_PDU);
  return offset;
}
static int dissect_SpecializedResourceReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_SpecializedResourceReportArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_SpecializedResourceReportArg_PDU);
  return offset;
}
static int dissect_SRFCallGapArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_SRFCallGapArg(false, tvb, offset, &asn1_ctx, tree, hf_inap_SRFCallGapArg_PDU);
  return offset;
}
static int dissect_PAR_cancelFailed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_PAR_cancelFailed(false, tvb, offset, &asn1_ctx, tree, hf_inap_PAR_cancelFailed_PDU);
  return offset;
}
static int dissect_PAR_requestedInfoError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_PAR_requestedInfoError(false, tvb, offset, &asn1_ctx, tree, hf_inap_PAR_requestedInfoError_PDU);
  return offset;
}
static int dissect_ScfTaskRefusedParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ScfTaskRefusedParameter(false, tvb, offset, &asn1_ctx, tree, hf_inap_ScfTaskRefusedParameter_PDU);
  return offset;
}
static int dissect_ReferralParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_ReferralParameter(false, tvb, offset, &asn1_ctx, tree, hf_inap_ReferralParameter_PDU);
  return offset;
}
static int dissect_UnavailableNetworkResource_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_UnavailableNetworkResource(false, tvb, offset, &asn1_ctx, tree, hf_inap_UnavailableNetworkResource_PDU);
  return offset;
}
static int dissect_PAR_taskRefused_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_inap_PAR_taskRefused(false, tvb, offset, &asn1_ctx, tree, hf_inap_PAR_taskRefused_PDU);
  return offset;
}

/*
TC-Invokable OPERATION ::=
  {activateServiceFiltering | activityTest | analysedInformation |
   analyseInformation | applyCharging | applyChargingReport |
   assistRequestInstructions | callGap | callInformationReport |
   callInformationRequest | cancel | cancelStatusReportRequest |
   collectedInformation | collectInformation | connect | connectToResource |
   continue | disconnectForwardConnection | establishTemporaryConnection |
   eventNotificationCharging | eventReportBCSM | furnishChargingInformation |
   holdCallInNetwork | initialDP | initiateCallAttempt | oAnswer |
   oCalledPartyBusy | oDisconnect | oMidCall | oNoAnswer |
   originationAttemptAuthorized | releaseCall | requestCurrentStatusReport |
   requestEveryStatusChangeReport | requestFirstStatusMatchReport |
   requestNotificationChargingEvent | requestReportBCSMEvent | resetTimer |
   routeSelectFailure | selectFacility | selectRoute | sendChargingInformation
   | serviceFilteringResponse | statusReport | tAnswer | tBusy | tDisconnect |
   termAttemptAuthorized | tMidCall | tNoAnswer | playAnnouncement |
   promptAndCollectUserInformation}
*/


static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx) {

  switch(opcode){
    case opcode_activateServiceFiltering:  /* activateServiceFiltering */
      offset= dissect_ActivateServiceFilteringArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_analysedInformation:  /* analysedInformation */
      offset= dissect_AnalysedInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_analyseInformation:  /* analyseInformation */
      offset= dissect_AnalyseInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_applyCharging:  /* applyCharging */
      offset= dissect_ApplyChargingArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_applyChargingReport:  /* applyChargingReport */
      offset= dissect_ApplyChargingReportArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_assistRequestInstructions:  /* assistRequestInstructions */
      offset= dissect_AssistRequestInstructionsArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_authorizeTermination:  /* authorizeTermination */
      offset= dissect_AuthorizeTerminationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_callFiltering:  /* callFiltering */
      offset= dissect_CallFilteringArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_callGap:  /* callGap */
      offset= dissect_CallGapArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_callInformationReport:  /* callInformationReport */
      offset= dissect_CallInformationReportArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_callInformationRequest:  /* callInformationRequest */
      offset= dissect_CallInformationRequestArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_cancel:  /* cancel */
      offset= dissect_CancelArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_cancelStatusReportRequest:  /* cancelStatusReportRequest */
      offset= dissect_CancelStatusReportRequestArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_collectedInformation:  /* collectedInformation */
      offset= dissect_CollectedInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_collectInformation:  /* collectInformation */
      offset= dissect_CollectInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_connect:  /* connect */
      offset= dissect_ConnectArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_connectToResource:  /* connectToResource */
      offset= dissect_ConnectToResourceArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_continueWithArgument:  /* continueWithArgument */
      offset= dissect_ContinueWithArgumentArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_createCallSegmentAssociation:  /* createCallSegmentAssociation */
      offset= dissect_CreateCallSegmentAssociationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_createOrRemoveTriggerData:  /* createOrRemoveTriggerData */
      offset= dissect_CreateOrRemoveTriggerDataArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_dFCWithArgument:  /* disconnectForwardConnectionWithArgument */
      offset= dissect_DisconnectForwardConnectionWithArgumentArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_disconnectLeg:  /* disconnectLeg */
      offset= dissect_DisconnectLegArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_entityReleased:  /* entityReleased */
      offset= dissect_EntityReleasedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_establishTemporaryConnection:  /* establishTemporaryConnection */
      offset= dissect_EstablishTemporaryConnectionArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_eventNotificationCharging:  /* eventNotificationCharging */
      offset= dissect_EventNotificationChargingArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_eventReportBCSM:  /* eventReportBCSM */
      offset= dissect_EventReportBCSMArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_eventReportFacility:  /* eventReportFacility */
      offset= dissect_EventReportFacilityArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_facilitySelectedAndAvailable:  /* facilitySelectedAndAvailable */
      offset= dissect_FacilitySelectedAndAvailableArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_furnishChargingInformation:  /* furnishChargingInformation */
      offset= dissect_FurnishChargingInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_holdCallInNetwork:  /* holdCallInNetwork */
      offset= dissect_HoldCallInNetworkArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_initialDP:  /* initialDP */
      offset= dissect_InitialDPArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_initiateCallAttempt:  /* initiateCallAttempt */
      offset= dissect_InitiateCallAttemptArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_manageTriggerData:  /* manageTriggerData */
      offset= dissect_ManageTriggerDataArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_mergeCallSegments:  /* mergeCallSegments */
      offset= dissect_MergeCallSegmentsArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_monitorRouteReport:  /* monitorRouteReport */
      offset= dissect_MonitorRouteReportArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_monitorRouteRequest:  /* monitorRouteRequest */
      offset= dissect_MonitorRouteRequestArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_moveCallSegments:  /* moveCallSegments */
      offset= dissect_MoveCallSegmentsArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_moveLeg:  /* moveLeg */
      offset= dissect_MoveLegArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_oAbandon:  /* oAbandon */
      offset= dissect_OAbandonArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_oAnswer:  /* oAnswer */
      offset= dissect_OAnswerArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_oCalledPartyBusy:  /* oCalledPartyBusy */
      offset= dissect_OCalledPartyBusyArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_oDisconnect:  /* oDisconnect */
      offset= dissect_ODisconnectArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_oMidCall:  /* oMidCall */
      offset= dissect_MidCallArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_oNoAnswer:  /* oNoAnswer */
      offset= dissect_ONoAnswerArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_originationAttempt:  /* originationAttempt */
      offset= dissect_OriginationAttemptArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_originationAttemptAuthorized:  /* originationAttemptAuthorized */
      offset= dissect_OriginationAttemptAuthorizedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_oSuspended:  /* oSuspended */
      offset= dissect_OSuspendedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_reconnect:  /* reconnect */
      offset= dissect_ReconnectArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_releaseCall:  /* releaseCall */
      offset= dissect_ReleaseCallArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_reportUTSI:  /* reportUTSI */
      offset= dissect_ReportUTSIArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_requestCurrentStatusReport:  /* requestCurrentStatusReport */
      offset= dissect_RequestCurrentStatusReportArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_requestEveryStatusChangeReport:  /* requestEveryStatusChangeReport */
      offset= dissect_RequestEveryStatusChangeReportArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_requestFirstStatusMatchReport:  /* requestFirstStatusMatchReport */
      offset= dissect_RequestFirstStatusMatchReportArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_requestNotificationChargingEvent:  /* requestNotificationChargingEvent */
      offset= dissect_RequestNotificationChargingEventArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_requestReportBCSMEvent:  /* requestReportBCSMEvent */
      offset= dissect_RequestReportBCSMEventArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_requestReportFacilityEvent:  /* requestReportFacilityEvent */
      offset= dissect_RequestReportFacilityEventArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_requestReportUTSI:  /* requestReportUTSI */
      offset= dissect_RequestReportUTSIArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_resetTimer:  /* resetTimer */
      offset= dissect_ResetTimerArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_routeSelectFailure:  /* routeSelectFailure */
      offset= dissect_RouteSelectFailureArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_selectFacility:  /* selectFacility */
      offset= dissect_SelectFacilityArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_selectRoute:  /* selectRoute */
      offset= dissect_SelectRouteArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_sendChargingInformation:  /* sendChargingInformation */
      offset= dissect_SendChargingInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_sendFacilityInformation:  /* sendFacilityInformation */
      offset= dissect_SendFacilityInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_sendSTUI:  /* sendSTUI */
      offset= dissect_SendSTUIArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_serviceFilteringResponse:  /* serviceFilteringResponse */
      offset= dissect_ServiceFilteringResponseArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_setServiceProfile:  /* setServiceProfile */
      offset= dissect_SetServiceProfileArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_splitLeg:  /* splitLeg */
      offset= dissect_SplitLegArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_statusReport:  /* statusReport */
      offset= dissect_StatusReportArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_tAnswer:  /* tAnswer */
      offset= dissect_TAnswerArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_tBusy:  /* tBusy */
      offset= dissect_TBusyArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_tDisconnect:  /* tDisconnect */
      offset= dissect_TDisconnectArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_termAttemptAuthorized:  /* termAttemptAuthorized */
      offset= dissect_TermAttemptAuthorizedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_terminationAttempt:  /* terminationAttempt */
      offset= dissect_TerminationAttemptArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_tMidCall:  /* tMidCall */
      offset= dissect_MidCallArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_tNoAnswer:  /* tNoAnswer */
      offset= dissect_TNoAnswerArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_tSuspended:  /* tSuspended */
      offset= dissect_TSuspendedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_playAnnouncement:  /* playAnnouncement */
      offset= dissect_PlayAnnouncementArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_promptAndCollectUserInformation:  /* promptAndCollectUserInformation */
      offset= dissect_PromptAndCollectUserInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_promptAndReceiveMessage:  /* promptAndReceiveMessage */
      offset= dissect_PromptAndReceiveMessageArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_scriptClose:  /* scriptClose */
      offset= dissect_ScriptCloseArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_scriptEvent:  /* scriptEvent */
      offset= dissect_ScriptEventArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_scriptInformation:  /* scriptInformation */
      offset= dissect_ScriptInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_scriptRun:  /* scriptRun */
      offset= dissect_ScriptRunArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_specializedResourceReport:  /* specializedResourceReport */
      offset= dissect_SpecializedResourceReportArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_srfCallGap:  /* sRFCallGap */
      offset= dissect_SRFCallGapArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    default:
      proto_tree_add_expert_format(tree, actx->pinfo, &ei_inap_unknown_invokeData,
                                   tvb, offset, -1, "Unknown invokeData %d", opcode);
      /* todo call the asn.1 dissector */
      break;
  }
  return offset;
}


static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx) {
  switch(opcode){
    case opcode_createCallSegmentAssociation:  /* createCallSegmentAssociation */
      offset= dissect_CreateCallSegmentAssociationResultArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_createOrRemoveTriggerData:  /* createOrRemoveTriggerData */
      offset= dissect_CreateOrRemoveTriggerDataResultArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_manageTriggerData:  /* manageTriggerData */
      offset= dissect_ManageTriggerDataResultArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_requestCurrentStatusReport:  /* requestCurrentStatusReport */
      offset= dissect_RequestCurrentStatusReportResultArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_promptAndCollectUserInformation:  /* promptAndCollectUserInformation */
      offset= dissect_ReceivedInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case opcode_promptAndReceiveMessage:  /* promptAndReceiveMessage */
      offset= dissect_MessageReceivedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
  default:
    proto_tree_add_expert_format(tree, actx->pinfo, &ei_inap_unknown_returnResultData,
                                 tvb, offset, -1, "Unknown returnResultData %d", opcode);
  }
  return offset;
}


static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx) {
  switch(errorCode) {
    case errcode_cancelFailed:  /* cancelFailed */
      offset= dissect_PAR_cancelFailed_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case errcode_requestedInfoError:  /* requestedInfoError */
      offset= dissect_PAR_requestedInfoError_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case errcode_scfTaskRefused:  /* scfTaskRefused */
      offset= dissect_ScfTaskRefusedParameter_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case errcode_scfReferral:  /* scfReferral */
      offset= dissect_ReferralParameter_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case errcode_systemFailure:  /* systemFailure */
      offset= dissect_UnavailableNetworkResource_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case errcode_taskRefused:  /* taskRefused */
      offset= dissect_PAR_taskRefused_PDU(tvb, actx->pinfo , tree , NULL);
      break;
  default:
    proto_tree_add_expert_format(tree, actx->pinfo, &ei_inap_unknown_returnErrorData,
                                 tvb, offset, -1, "Unknown returnErrorData %d", opcode);
  }
  return offset;
}



static uint8_t inap_pdu_type;
static uint8_t inap_pdu_size;


static int
dissect_inap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
  proto_item		*item=NULL;
  proto_tree		*tree=NULL;
  int				offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "INAP");

  /* create display subtree for the protocol */
  if(parent_tree){
    item = proto_tree_add_item(parent_tree, proto_inap, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_inap);
  }
  inap_pdu_type = tvb_get_uint8(tvb, offset)&0x0f;
  /* Get the length and add 2 */
  inap_pdu_size = tvb_get_uint8(tvb, offset+1)+2;
  opcode = 0;
  is_ExtensionField =false;
  dissect_inap_ROS(true, tvb, offset, &asn1_ctx, tree, -1);

  return inap_pdu_size;
}

/*--- proto_reg_handoff_inap ---------------------------------------*/
static void range_delete_callback(uint32_t ssn, void *ptr _U_)
{
  if (ssn) {
    delete_itu_tcap_subdissector(ssn, inap_handle);
  }
}

static void range_add_callback(uint32_t ssn, void *ptr _U_)
{
  if (ssn) {
  add_itu_tcap_subdissector(ssn, inap_handle);
  }
}

void proto_reg_handoff_inap(void) {

  static bool inap_prefs_initialized = false;
  static range_t *ssn_range;

  if (!inap_prefs_initialized) {
    inap_prefs_initialized = true;
    oid_add_from_string("Core-INAP-CS1-Codes","0.4.0.1.1.0.3.0");
    oid_add_from_string("iso(1) identified-organization(3) icd-ecma(12) member-company(2) 1107 oen(3) inap(3) extensions(2)","1.3.12.2.1107.3.3.2");
    oid_add_from_string("alcatel(1006)","1.3.12.2.1006.64");
    oid_add_from_string("Siemens (1107)","1.3.12.2.1107");
    oid_add_from_string("iso(1) member-body(2) gb(826) national(0) ericsson(1249) inDomain(51) inNetwork(1) inNetworkcapabilitySet1plus(1) ","1.2.826.0.1249.51.1.1");
  }
  else {
    range_foreach(ssn_range, range_delete_callback, NULL);
    wmem_free(wmem_epan_scope(), ssn_range);
  }

  ssn_range = range_copy(wmem_epan_scope(), global_ssn_range);

  range_foreach(ssn_range, range_add_callback, NULL);

}


void proto_register_inap(void) {
  module_t *inap_module;
  /* List of fields */
  static hf_register_info hf[] = {


    { &hf_inap_cause_indicator, /* Currently not enabled */
    { "Cause indicator", "inap.cause_indicator",
    FT_UINT8, BASE_DEC | BASE_EXT_STRING, &q850_cause_code_vals_ext, 0x7f,
    NULL, HFILL } },

    { &hf_inap_ActivateServiceFilteringArg_PDU,
      { "ActivateServiceFilteringArg", "inap.ActivateServiceFilteringArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_AnalysedInformationArg_PDU,
      { "AnalysedInformationArg", "inap.AnalysedInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_AnalyseInformationArg_PDU,
      { "AnalyseInformationArg", "inap.AnalyseInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ApplyChargingArg_PDU,
      { "ApplyChargingArg", "inap.ApplyChargingArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ApplyChargingReportArg_PDU,
      { "ApplyChargingReportArg", "inap.ApplyChargingReportArg",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_AssistRequestInstructionsArg_PDU,
      { "AssistRequestInstructionsArg", "inap.AssistRequestInstructionsArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_AuthorizeTerminationArg_PDU,
      { "AuthorizeTerminationArg", "inap.AuthorizeTerminationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CallFilteringArg_PDU,
      { "CallFilteringArg", "inap.CallFilteringArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CallGapArg_PDU,
      { "CallGapArg", "inap.CallGapArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CallInformationReportArg_PDU,
      { "CallInformationReportArg", "inap.CallInformationReportArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CallInformationRequestArg_PDU,
      { "CallInformationRequestArg", "inap.CallInformationRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CancelArg_PDU,
      { "CancelArg", "inap.CancelArg",
        FT_UINT32, BASE_DEC, VALS(inap_CancelArg_vals), 0,
        NULL, HFILL }},
    { &hf_inap_CancelStatusReportRequestArg_PDU,
      { "CancelStatusReportRequestArg", "inap.CancelStatusReportRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CollectedInformationArg_PDU,
      { "CollectedInformationArg", "inap.CollectedInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CollectInformationArg_PDU,
      { "CollectInformationArg", "inap.CollectInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ConnectArg_PDU,
      { "ConnectArg", "inap.ConnectArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ConnectToResourceArg_PDU,
      { "ConnectToResourceArg", "inap.ConnectToResourceArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ContinueWithArgumentArg_PDU,
      { "ContinueWithArgumentArg", "inap.ContinueWithArgumentArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CreateCallSegmentAssociationArg_PDU,
      { "CreateCallSegmentAssociationArg", "inap.CreateCallSegmentAssociationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CreateCallSegmentAssociationResultArg_PDU,
      { "CreateCallSegmentAssociationResultArg", "inap.CreateCallSegmentAssociationResultArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CreateOrRemoveTriggerDataArg_PDU,
      { "CreateOrRemoveTriggerDataArg", "inap.CreateOrRemoveTriggerDataArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_CreateOrRemoveTriggerDataResultArg_PDU,
      { "CreateOrRemoveTriggerDataResultArg", "inap.CreateOrRemoveTriggerDataResultArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_DisconnectForwardConnectionWithArgumentArg_PDU,
      { "DisconnectForwardConnectionWithArgumentArg", "inap.DisconnectForwardConnectionWithArgumentArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_DisconnectLegArg_PDU,
      { "DisconnectLegArg", "inap.DisconnectLegArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_EntityReleasedArg_PDU,
      { "EntityReleasedArg", "inap.EntityReleasedArg",
        FT_UINT32, BASE_DEC, VALS(inap_EntityReleasedArg_vals), 0,
        NULL, HFILL }},
    { &hf_inap_EstablishTemporaryConnectionArg_PDU,
      { "EstablishTemporaryConnectionArg", "inap.EstablishTemporaryConnectionArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_EventNotificationChargingArg_PDU,
      { "EventNotificationChargingArg", "inap.EventNotificationChargingArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_EventReportBCSMArg_PDU,
      { "EventReportBCSMArg", "inap.EventReportBCSMArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_EventReportFacilityArg_PDU,
      { "EventReportFacilityArg", "inap.EventReportFacilityArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_FacilitySelectedAndAvailableArg_PDU,
      { "FacilitySelectedAndAvailableArg", "inap.FacilitySelectedAndAvailableArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_FurnishChargingInformationArg_PDU,
      { "FurnishChargingInformationArg", "inap.FurnishChargingInformationArg",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_HoldCallInNetworkArg_PDU,
      { "HoldCallInNetworkArg", "inap.HoldCallInNetworkArg",
        FT_UINT32, BASE_DEC, VALS(inap_HoldCallInNetworkArg_vals), 0,
        NULL, HFILL }},
    { &hf_inap_InitialDPArg_PDU,
      { "InitialDPArg", "inap.InitialDPArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_InitiateCallAttemptArg_PDU,
      { "InitiateCallAttemptArg", "inap.InitiateCallAttemptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ManageTriggerDataArg_PDU,
      { "ManageTriggerDataArg", "inap.ManageTriggerDataArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ManageTriggerDataResultArg_PDU,
      { "ManageTriggerDataResultArg", "inap.ManageTriggerDataResultArg",
        FT_UINT32, BASE_DEC, VALS(inap_ManageTriggerDataResultArg_vals), 0,
        NULL, HFILL }},
    { &hf_inap_MergeCallSegmentsArg_PDU,
      { "MergeCallSegmentsArg", "inap.MergeCallSegmentsArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_MonitorRouteReportArg_PDU,
      { "MonitorRouteReportArg", "inap.MonitorRouteReportArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_MonitorRouteRequestArg_PDU,
      { "MonitorRouteRequestArg", "inap.MonitorRouteRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_MoveCallSegmentsArg_PDU,
      { "MoveCallSegmentsArg", "inap.MoveCallSegmentsArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_MoveLegArg_PDU,
      { "MoveLegArg", "inap.MoveLegArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_OAbandonArg_PDU,
      { "OAbandonArg", "inap.OAbandonArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_OAnswerArg_PDU,
      { "OAnswerArg", "inap.OAnswerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_OCalledPartyBusyArg_PDU,
      { "OCalledPartyBusyArg", "inap.OCalledPartyBusyArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ODisconnectArg_PDU,
      { "ODisconnectArg", "inap.ODisconnectArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_MidCallArg_PDU,
      { "MidCallArg", "inap.MidCallArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ONoAnswerArg_PDU,
      { "ONoAnswerArg", "inap.ONoAnswerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_OriginationAttemptArg_PDU,
      { "OriginationAttemptArg", "inap.OriginationAttemptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_OriginationAttemptAuthorizedArg_PDU,
      { "OriginationAttemptAuthorizedArg", "inap.OriginationAttemptAuthorizedArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_OSuspendedArg_PDU,
      { "OSuspendedArg", "inap.OSuspendedArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ReconnectArg_PDU,
      { "ReconnectArg", "inap.ReconnectArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ReleaseCallArg_PDU,
      { "ReleaseCallArg", "inap.ReleaseCallArg",
        FT_UINT32, BASE_DEC, VALS(inap_ReleaseCallArg_vals), 0,
        NULL, HFILL }},
    { &hf_inap_ReportUTSIArg_PDU,
      { "ReportUTSIArg", "inap.ReportUTSIArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_RequestCurrentStatusReportArg_PDU,
      { "RequestCurrentStatusReportArg", "inap.RequestCurrentStatusReportArg",
        FT_UINT32, BASE_DEC, VALS(inap_ResourceID_vals), 0,
        NULL, HFILL }},
    { &hf_inap_RequestCurrentStatusReportResultArg_PDU,
      { "RequestCurrentStatusReportResultArg", "inap.RequestCurrentStatusReportResultArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_RequestEveryStatusChangeReportArg_PDU,
      { "RequestEveryStatusChangeReportArg", "inap.RequestEveryStatusChangeReportArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_RequestFirstStatusMatchReportArg_PDU,
      { "RequestFirstStatusMatchReportArg", "inap.RequestFirstStatusMatchReportArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_RequestNotificationChargingEventArg_PDU,
      { "RequestNotificationChargingEventArg", "inap.RequestNotificationChargingEventArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_RequestReportBCSMEventArg_PDU,
      { "RequestReportBCSMEventArg", "inap.RequestReportBCSMEventArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_RequestReportFacilityEventArg_PDU,
      { "RequestReportFacilityEventArg", "inap.RequestReportFacilityEventArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_RequestReportUTSIArg_PDU,
      { "RequestReportUTSIArg", "inap.RequestReportUTSIArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ResetTimerArg_PDU,
      { "ResetTimerArg", "inap.ResetTimerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_RouteSelectFailureArg_PDU,
      { "RouteSelectFailureArg", "inap.RouteSelectFailureArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_SelectFacilityArg_PDU,
      { "SelectFacilityArg", "inap.SelectFacilityArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_SelectRouteArg_PDU,
      { "SelectRouteArg", "inap.SelectRouteArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_SendChargingInformationArg_PDU,
      { "SendChargingInformationArg", "inap.SendChargingInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_SendFacilityInformationArg_PDU,
      { "SendFacilityInformationArg", "inap.SendFacilityInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_SendSTUIArg_PDU,
      { "SendSTUIArg", "inap.SendSTUIArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ServiceFilteringResponseArg_PDU,
      { "ServiceFilteringResponseArg", "inap.ServiceFilteringResponseArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_SetServiceProfileArg_PDU,
      { "SetServiceProfileArg", "inap.SetServiceProfileArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_SplitLegArg_PDU,
      { "SplitLegArg", "inap.SplitLegArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_StatusReportArg_PDU,
      { "StatusReportArg", "inap.StatusReportArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_TAnswerArg_PDU,
      { "TAnswerArg", "inap.TAnswerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_TBusyArg_PDU,
      { "TBusyArg", "inap.TBusyArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_TDisconnectArg_PDU,
      { "TDisconnectArg", "inap.TDisconnectArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_TermAttemptAuthorizedArg_PDU,
      { "TermAttemptAuthorizedArg", "inap.TermAttemptAuthorizedArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_TerminationAttemptArg_PDU,
      { "TerminationAttemptArg", "inap.TerminationAttemptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_TNoAnswerArg_PDU,
      { "TNoAnswerArg", "inap.TNoAnswerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_TSuspendedArg_PDU,
      { "TSuspendedArg", "inap.TSuspendedArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_PlayAnnouncementArg_PDU,
      { "PlayAnnouncementArg", "inap.PlayAnnouncementArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_PromptAndCollectUserInformationArg_PDU,
      { "PromptAndCollectUserInformationArg", "inap.PromptAndCollectUserInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ReceivedInformationArg_PDU,
      { "ReceivedInformationArg", "inap.ReceivedInformationArg",
        FT_UINT32, BASE_DEC, VALS(inap_ReceivedInformationArg_vals), 0,
        NULL, HFILL }},
    { &hf_inap_PromptAndReceiveMessageArg_PDU,
      { "PromptAndReceiveMessageArg", "inap.PromptAndReceiveMessageArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_MessageReceivedArg_PDU,
      { "MessageReceivedArg", "inap.MessageReceivedArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ScriptCloseArg_PDU,
      { "ScriptCloseArg", "inap.ScriptCloseArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ScriptEventArg_PDU,
      { "ScriptEventArg", "inap.ScriptEventArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ScriptInformationArg_PDU,
      { "ScriptInformationArg", "inap.ScriptInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ScriptRunArg_PDU,
      { "ScriptRunArg", "inap.ScriptRunArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_SpecializedResourceReportArg_PDU,
      { "SpecializedResourceReportArg", "inap.SpecializedResourceReportArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_SRFCallGapArg_PDU,
      { "SRFCallGapArg", "inap.SRFCallGapArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_PAR_cancelFailed_PDU,
      { "PAR-cancelFailed", "inap.PAR_cancelFailed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_PAR_requestedInfoError_PDU,
      { "PAR-requestedInfoError", "inap.PAR_requestedInfoError",
        FT_UINT32, BASE_DEC, VALS(inap_PAR_requestedInfoError_vals), 0,
        NULL, HFILL }},
    { &hf_inap_ScfTaskRefusedParameter_PDU,
      { "ScfTaskRefusedParameter", "inap.ScfTaskRefusedParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ReferralParameter_PDU,
      { "ReferralParameter", "inap.ReferralParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_UnavailableNetworkResource_PDU,
      { "UnavailableNetworkResource", "inap.UnavailableNetworkResource",
        FT_UINT32, BASE_DEC, VALS(inap_UnavailableNetworkResource_vals), 0,
        NULL, HFILL }},
    { &hf_inap_PAR_taskRefused_PDU,
      { "PAR-taskRefused", "inap.PAR_taskRefused",
        FT_UINT32, BASE_DEC, VALS(inap_PAR_taskRefused_vals), 0,
        NULL, HFILL }},
    { &hf_inap_Extensions_item,
      { "ExtensionField", "inap.ExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_type,
      { "type", "inap.type",
        FT_UINT32, BASE_DEC, VALS(inap_Code_vals), 0,
        "Code", HFILL }},
    { &hf_inap_criticality,
      { "criticality", "inap.criticality",
        FT_UINT32, BASE_DEC, VALS(inap_CriticalityType_vals), 0,
        "CriticalityType", HFILL }},
    { &hf_inap_value,
      { "value", "inap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_AlternativeIdentities_item,
      { "AlternativeIdentity", "inap.AlternativeIdentity",
        FT_UINT32, BASE_DEC, VALS(inap_AlternativeIdentity_vals), 0,
        NULL, HFILL }},
    { &hf_inap_url,
      { "url", "inap.url",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_512", HFILL }},
    { &hf_inap_conferenceTreatmentIndicator,
      { "conferenceTreatmentIndicator", "inap.conferenceTreatmentIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_inap_callCompletionTreatmentIndicator,
      { "callCompletionTreatmentIndicator", "inap.callCompletionTreatmentIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_inap_holdTreatmentIndicator,
      { "holdTreatmentIndicator", "inap.holdTreatmentIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_inap_ectTreatmentIndicator,
      { "ectTreatmentIndicator", "inap.ectTreatmentIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_inap_calledAddressValue,
      { "calledAddressValue", "inap.calledAddressValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_gapOnService,
      { "gapOnService", "inap.gapOnService_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_gapAllInTraffic,
      { "gapAllInTraffic", "inap.gapAllInTraffic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_calledAddressAndService,
      { "calledAddressAndService", "inap.calledAddressAndService_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_serviceKey,
      { "serviceKey", "inap.serviceKey",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callingAddressAndService,
      { "callingAddressAndService", "inap.callingAddressAndService_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callingAddressValue,
      { "callingAddressValue", "inap.callingAddressValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_locationNumber,
      { "locationNumber", "inap.locationNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_eventTypeBCSM,
      { "eventTypeBCSM", "inap.eventTypeBCSM",
        FT_UINT32, BASE_DEC, VALS(inap_EventTypeBCSM_vals), 0,
        NULL, HFILL }},
    { &hf_inap_monitorMode,
      { "monitorMode", "inap.monitorMode",
        FT_UINT32, BASE_DEC, VALS(inap_MonitorMode_vals), 0,
        NULL, HFILL }},
    { &hf_inap_legID,
      { "legID", "inap.legID",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        NULL, HFILL }},
    { &hf_inap_dpSpecificCriteria,
      { "dpSpecificCriteria", "inap.dpSpecificCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_DpSpecificCriteria_vals), 0,
        NULL, HFILL }},
    { &hf_inap_bearerCap,
      { "bearerCap", "inap.bearerCap",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tmr,
      { "tmr", "inap.tmr",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_inap_broadbandBearerCap,
      { "broadbandBearerCap", "inap.broadbandBearerCap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_minBroadbandBearerCapabilityLength_maxBroadbandBearerCapabilityLength", HFILL }},
    { &hf_inap_aALParameters,
      { "aALParameters", "inap.aALParameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_additionalATMCellRate,
      { "additionalATMCellRate", "inap.additionalATMCellRate",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_aESACalledParty,
      { "aESACalledParty", "inap.aESACalledParty",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_aESACallingParty,
      { "aESACallingParty", "inap.aESACallingParty",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_alternativeATMTrafficDescriptor,
      { "alternativeATMTrafficDescriptor", "inap.alternativeATMTrafficDescriptor",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_aTMCellRate,
      { "aTMCellRate", "inap.aTMCellRate",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_cDVTDescriptor,
      { "cDVTDescriptor", "inap.cDVTDescriptor",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_cumulativeTransitDelay,
      { "cumulativeTransitDelay", "inap.cumulativeTransitDelay",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_endToEndTransitDelay,
      { "endToEndTransitDelay", "inap.endToEndTransitDelay",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_minAcceptableATMTrafficDescriptor,
      { "minAcceptableATMTrafficDescriptor", "inap.minAcceptableATMTrafficDescriptor",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_eventTypeCharging,
      { "eventTypeCharging", "inap.eventTypeCharging",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_componentInfo,
      { "componentInfo", "inap.componentInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_118", HFILL }},
    { &hf_inap_relayedComponent,
      { "relayedComponent", "inap.relayedComponent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EMBEDDED_PDV", HFILL }},
    { &hf_inap_basicGapCriteria,
      { "basicGapCriteria", "inap.basicGapCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_BasicGapCriteria_vals), 0,
        NULL, HFILL }},
    { &hf_inap_scfID,
      { "scfID", "inap.scfID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_counterID,
      { "counterID", "inap.counterID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_counterValue,
      { "counterValue", "inap.counterValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Integer4", HFILL }},
    { &hf_inap_CountersValue_item,
      { "CounterAndValue", "inap.CounterAndValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_action,
      { "action", "inap.action",
        FT_UINT32, BASE_DEC, VALS(inap_T_action_vals), 0,
        NULL, HFILL }},
    { &hf_inap_treatment,
      { "treatment", "inap.treatment",
        FT_UINT32, BASE_DEC, VALS(inap_GapTreatment_vals), 0,
        "GapTreatment", HFILL }},
    { &hf_inap_DestinationRoutingAddress_item,
      { "CalledPartyNumber", "inap.CalledPartyNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_serviceAddressInformation,
      { "serviceAddressInformation", "inap.serviceAddressInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_bearerCapability,
      { "bearerCapability", "inap.bearerCapability",
        FT_UINT32, BASE_DEC, VALS(inap_BearerCapability_vals), 0,
        NULL, HFILL }},
    { &hf_inap_calledPartyNumber,
      { "calledPartyNumber", "inap.calledPartyNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callingPartyNumber,
      { "callingPartyNumber", "inap.callingPartyNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callingPartysCategory,
      { "callingPartysCategory", "inap.callingPartysCategory",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &isup_calling_partys_category_value_ext, 0,
        NULL, HFILL }},
    { &hf_inap_iPSSPCapabilities,
      { "iPSSPCapabilities", "inap.iPSSPCapabilities",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_iPAvailable,
      { "iPAvailable", "inap.iPAvailable",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_iSDNAccessRelatedInformation,
      { "iSDNAccessRelatedInformation", "inap.iSDNAccessRelatedInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_cGEncountered,
      { "cGEncountered", "inap.cGEncountered",
        FT_UINT32, BASE_DEC, VALS(inap_CGEncountered_vals), 0,
        NULL, HFILL }},
    { &hf_inap_serviceProfileIdentifier,
      { "serviceProfileIdentifier", "inap.serviceProfileIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_terminalType,
      { "terminalType", "inap.terminalType",
        FT_UINT32, BASE_DEC, VALS(inap_TerminalType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_extensions,
      { "extensions", "inap.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_chargeNumber,
      { "chargeNumber", "inap.chargeNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_servingAreaID,
      { "servingAreaID", "inap.servingAreaID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_serviceInteractionIndicators,
      { "serviceInteractionIndicators", "inap.serviceInteractionIndicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_iNServiceCompatibilityIndication,
      { "iNServiceCompatibilityIndication", "inap.iNServiceCompatibilityIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_serviceInteractionIndicatorsTwo,
      { "serviceInteractionIndicatorsTwo", "inap.serviceInteractionIndicatorsTwo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_uSIServiceIndicator,
      { "uSIServiceIndicator", "inap.uSIServiceIndicator",
        FT_UINT32, BASE_DEC, VALS(inap_USIServiceIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_inap_uSIInformation,
      { "uSIInformation", "inap.uSIInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_forwardGVNS,
      { "forwardGVNS", "inap.forwardGVNS",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_createdCallSegmentAssociation,
      { "createdCallSegmentAssociation", "inap.createdCallSegmentAssociation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CSAID", HFILL }},
    { &hf_inap_ipRelatedInformation,
      { "ipRelatedInformation", "inap.ipRelatedInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_numberOfDigits,
      { "numberOfDigits", "inap.numberOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_applicationTimer,
      { "applicationTimer", "inap.applicationTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_midCallControlInfo,
      { "midCallControlInfo", "inap.midCallControlInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_numberOfDigitsTwo,
      { "numberOfDigitsTwo", "inap.numberOfDigitsTwo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_requestedNumberOfDigits,
      { "requestedNumberOfDigits", "inap.requestedNumberOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NumberOfDigits", HFILL }},
    { &hf_inap_minNumberOfDigits,
      { "minNumberOfDigits", "inap.minNumberOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NumberOfDigits", HFILL }},
    { &hf_inap_agreements,
      { "agreements", "inap.agreements",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_inap_networkSpecific,
      { "networkSpecific", "inap.networkSpecific",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Integer4", HFILL }},
    { &hf_inap_collectedInfoSpecificInfo,
      { "collectedInfoSpecificInfo", "inap.collectedInfoSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_calledPartynumber,
      { "calledPartynumber", "inap.calledPartynumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_analysedInfoSpecificInfo,
      { "analysedInfoSpecificInfo", "inap.analysedInfoSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_routeSelectFailureSpecificInfo,
      { "routeSelectFailureSpecificInfo", "inap.routeSelectFailureSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_failureCause,
      { "failureCause", "inap.failureCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Cause", HFILL }},
    { &hf_inap_oCalledPartyBusySpecificInfo,
      { "oCalledPartyBusySpecificInfo", "inap.oCalledPartyBusySpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_busyCause,
      { "busyCause", "inap.busyCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Cause", HFILL }},
    { &hf_inap_oNoAnswerSpecificInfo,
      { "oNoAnswerSpecificInfo", "inap.oNoAnswerSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_cause,
      { "cause", "inap.cause",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_oAnswerSpecificInfo,
      { "oAnswerSpecificInfo", "inap.oAnswerSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_backwardGVNS,
      { "backwardGVNS", "inap.backwardGVNS",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_oMidCallSpecificInfo,
      { "oMidCallSpecificInfo", "inap.oMidCallSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_connectTime,
      { "connectTime", "inap.connectTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Integer4", HFILL }},
    { &hf_inap_oMidCallInfo,
      { "oMidCallInfo", "inap.oMidCallInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MidCallInfo", HFILL }},
    { &hf_inap_oDisconnectSpecificInfo,
      { "oDisconnectSpecificInfo", "inap.oDisconnectSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_releaseCause,
      { "releaseCause", "inap.releaseCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Cause", HFILL }},
    { &hf_inap_tBusySpecificInfo,
      { "tBusySpecificInfo", "inap.tBusySpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tNoAnswerSpecificInfo,
      { "tNoAnswerSpecificInfo", "inap.tNoAnswerSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tAnswerSpecificInfo,
      { "tAnswerSpecificInfo", "inap.tAnswerSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tMidCallSpecificInfo,
      { "tMidCallSpecificInfo", "inap.tMidCallSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tMidCallInfo,
      { "tMidCallInfo", "inap.tMidCallInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MidCallInfo", HFILL }},
    { &hf_inap_tDisconnectSpecificInfo,
      { "tDisconnectSpecificInfo", "inap.tDisconnectSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_oTermSeizedSpecificInfo,
      { "oTermSeizedSpecificInfo", "inap.oTermSeizedSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_oSuspend,
      { "oSuspend", "inap.oSuspend_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tSuspend,
      { "tSuspend", "inap.tSuspend_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_origAttemptAuthorized,
      { "origAttemptAuthorized", "inap.origAttemptAuthorized_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_oReAnswer,
      { "oReAnswer", "inap.oReAnswer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tReAnswer,
      { "tReAnswer", "inap.tReAnswer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_facilitySelectedAndAvailable,
      { "facilitySelectedAndAvailable", "inap.facilitySelectedAndAvailable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callAccepted,
      { "callAccepted", "inap.callAccepted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_oAbandon,
      { "oAbandon", "inap.oAbandon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_abandonCause,
      { "abandonCause", "inap.abandonCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Cause", HFILL }},
    { &hf_inap_tAbandon,
      { "tAbandon", "inap.tAbandon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_authorizeRouteFailure,
      { "authorizeRouteFailure", "inap.authorizeRouteFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_authoriseRouteFailureCause,
      { "authoriseRouteFailureCause", "inap.authoriseRouteFailureCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Cause", HFILL }},
    { &hf_inap_terminationAttemptAuthorized,
      { "terminationAttemptAuthorized", "inap.terminationAttemptAuthorized_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_originationAttemptDenied,
      { "originationAttemptDenied", "inap.originationAttemptDenied_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_originationDeniedCause,
      { "originationDeniedCause", "inap.originationDeniedCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Cause", HFILL }},
    { &hf_inap_terminationAttemptDenied,
      { "terminationAttemptDenied", "inap.terminationAttemptDenied_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_terminationDeniedCause,
      { "terminationDeniedCause", "inap.terminationDeniedCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Cause", HFILL }},
    { &hf_inap_oModifyRequestSpecificInfo,
      { "oModifyRequestSpecificInfo", "inap.oModifyRequestSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_oModifyResultSpecificInfo,
      { "oModifyResultSpecificInfo", "inap.oModifyResultSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_modifyResultType,
      { "modifyResultType", "inap.modifyResultType",
        FT_UINT32, BASE_DEC, VALS(inap_ModifyResultType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_tModifyRequestSpecificInfo,
      { "tModifyRequestSpecificInfo", "inap.tModifyRequestSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tModifyResultSpecificInfo,
      { "tModifyResultSpecificInfo", "inap.tModifyResultSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_trunkGroupID,
      { "trunkGroupID", "inap.trunkGroupID",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_inap_privateFacilityID,
      { "privateFacilityID", "inap.privateFacilityID",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_inap_huntGroup,
      { "huntGroup", "inap.huntGroup",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_inap_routeIndex,
      { "routeIndex", "inap.routeIndex",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_inap_sFBillingChargingCharacteristics,
      { "sFBillingChargingCharacteristics", "inap.sFBillingChargingCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_informationToSend,
      { "informationToSend", "inap.informationToSend",
        FT_UINT32, BASE_DEC, VALS(inap_InformationToSend_vals), 0,
        NULL, HFILL }},
    { &hf_inap_maximumNumberOfCounters,
      { "maximumNumberOfCounters", "inap.maximumNumberOfCounters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_filteringCharacteristics_interval,
      { "interval", "inap.filteringCharacteristics.interval",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1_32000", HFILL }},
    { &hf_inap_numberOfCalls,
      { "numberOfCalls", "inap.numberOfCalls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Integer4", HFILL }},
    { &hf_inap_dialledNumber,
      { "dialledNumber", "inap.dialledNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_callingLineID,
      { "callingLineID", "inap.callingLineID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_addressAndService,
      { "addressAndService", "inap.addressAndService_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_duration,
      { "duration", "inap.duration",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_stopTime,
      { "stopTime", "inap.stopTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DateAndTime", HFILL }},
    { &hf_inap_callDiversionTreatmentIndicator,
      { "callDiversionTreatmentIndicator", "inap.callDiversionTreatmentIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_inap_callOfferingTreatmentIndicator,
      { "callOfferingTreatmentIndicator", "inap.callOfferingTreatmentIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_inap_callWaitingTreatmentIndicator,
      { "callWaitingTreatmentIndicator", "inap.callWaitingTreatmentIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_inap_compoundCapCriteria,
      { "compoundCapCriteria", "inap.compoundCapCriteria_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompoundCriteria", HFILL }},
    { &hf_inap_dpCriteria,
      { "dpCriteria", "inap.dpCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_EventTypeBCSM_vals), 0,
        "EventTypeBCSM", HFILL }},
    { &hf_inap_gapInterval,
      { "gapInterval", "inap.gapInterval",
        FT_INT32, BASE_DEC, NULL, 0,
        "Interval", HFILL }},
    { &hf_inap_both,
      { "both", "inap.both_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_GenericNumbers_item,
      { "GenericNumber", "inap.GenericNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_actionOnProfile,
      { "actionOnProfile", "inap.actionOnProfile",
        FT_UINT32, BASE_DEC, VALS(inap_ActionOnProfile_vals), 0,
        NULL, HFILL }},
    { &hf_inap_tDPIdentifier,
      { "tDPIdentifier", "inap.tDPIdentifier",
        FT_UINT32, BASE_DEC, VALS(inap_TDPIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_inap_dPName,
      { "dPName", "inap.dPName",
        FT_UINT32, BASE_DEC, VALS(inap_EventTypeBCSM_vals), 0,
        "EventTypeBCSM", HFILL }},
    { &hf_inap_INServiceCompatibilityIndication_item,
      { "Entry", "inap.Entry",
        FT_UINT32, BASE_DEC, VALS(inap_Entry_vals), 0,
        NULL, HFILL }},
    { &hf_inap_alternativeCalledPartyIds,
      { "alternativeCalledPartyIds", "inap.alternativeCalledPartyIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlternativeIdentities", HFILL }},
    { &hf_inap_alternativeOriginatingPartyIds,
      { "alternativeOriginatingPartyIds", "inap.alternativeOriginatingPartyIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlternativeIdentities", HFILL }},
    { &hf_inap_alternativeOriginalCalledPartyIds,
      { "alternativeOriginalCalledPartyIds", "inap.alternativeOriginalCalledPartyIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlternativeIdentities", HFILL }},
    { &hf_inap_alternativeRedirectingPartyIds,
      { "alternativeRedirectingPartyIds", "inap.alternativeRedirectingPartyIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlternativeIdentities", HFILL }},
    { &hf_inap_sendingSideID,
      { "sendingSideID", "inap.sendingSideID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LegType", HFILL }},
    { &hf_inap_receivingSideID,
      { "receivingSideID", "inap.receivingSideID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LegType", HFILL }},
    { &hf_inap_MidCallControlInfo_item,
      { "MidCallControlInfo item", "inap.MidCallControlInfo_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_midCallInfoType,
      { "midCallInfoType", "inap.midCallInfoType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_midCallReportType,
      { "midCallReportType", "inap.midCallReportType",
        FT_UINT32, BASE_DEC, VALS(inap_T_midCallReportType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_iNServiceControlCode,
      { "iNServiceControlCode", "inap.iNServiceControlCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_iNServiceControlCodeLow,
      { "iNServiceControlCodeLow", "inap.iNServiceControlCodeLow",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_iNServiceControlCodeHigh,
      { "iNServiceControlCodeHigh", "inap.iNServiceControlCodeHigh",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_messageType,
      { "messageType", "inap.messageType",
        FT_UINT32, BASE_DEC, VALS(inap_T_messageType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_dpAssignment,
      { "dpAssignment", "inap.dpAssignment",
        FT_UINT32, BASE_DEC, VALS(inap_T_dpAssignment_vals), 0,
        NULL, HFILL }},
    { &hf_inap_threshold,
      { "threshold", "inap.threshold",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Integer4", HFILL }},
    { &hf_inap_interval,
      { "interval", "inap.interval",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_access,
      { "access", "inap.access",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CalledPartyNumber", HFILL }},
    { &hf_inap_group,
      { "group", "inap.group",
        FT_UINT32, BASE_DEC, VALS(inap_FacilityGroup_vals), 0,
        "FacilityGroup", HFILL }},
    { &hf_inap_RequestedInformationList_item,
      { "RequestedInformation", "inap.RequestedInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_RequestedInformationTypeList_item,
      { "RequestedInformationType", "inap.RequestedInformationType",
        FT_UINT32, BASE_DEC, VALS(inap_RequestedInformationType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_requestedInformationType,
      { "requestedInformationType", "inap.requestedInformationType",
        FT_UINT32, BASE_DEC, VALS(inap_RequestedInformationType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_requestedInformationValue,
      { "requestedInformationValue", "inap.requestedInformationValue",
        FT_UINT32, BASE_DEC, VALS(inap_RequestedInformationValue_vals), 0,
        NULL, HFILL }},
    { &hf_inap_callAttemptElapsedTimeValue,
      { "callAttemptElapsedTimeValue", "inap.callAttemptElapsedTimeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_inap_callStopTimeValue,
      { "callStopTimeValue", "inap.callStopTimeValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DateAndTime", HFILL }},
    { &hf_inap_callConnectedElapsedTimeValue,
      { "callConnectedElapsedTimeValue", "inap.callConnectedElapsedTimeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Integer4", HFILL }},
    { &hf_inap_releaseCauseValue,
      { "releaseCauseValue", "inap.releaseCauseValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Cause", HFILL }},
    { &hf_inap_uSImonitorMode,
      { "uSImonitorMode", "inap.uSImonitorMode",
        FT_UINT32, BASE_DEC, VALS(inap_USIMonitorMode_vals), 0,
        NULL, HFILL }},
    { &hf_inap_RequestedUTSIList_item,
      { "RequestedUTSI", "inap.RequestedUTSI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_lineID,
      { "lineID", "inap.lineID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_facilityGroupID,
      { "facilityGroupID", "inap.facilityGroupID",
        FT_UINT32, BASE_DEC, VALS(inap_FacilityGroup_vals), 0,
        "FacilityGroup", HFILL }},
    { &hf_inap_facilityGroupMemberID,
      { "facilityGroupMemberID", "inap.facilityGroupMemberID",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_inap_RouteCountersValue_item,
      { "RouteCountersAndValue", "inap.RouteCountersAndValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_route,
      { "route", "inap.route",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_RouteList_item,
      { "Route", "inap.Route",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_miscCallInfo,
      { "miscCallInfo", "inap.miscCallInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_triggerType,
      { "triggerType", "inap.triggerType",
        FT_UINT32, BASE_DEC, VALS(inap_TriggerType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_forwardServiceInteractionInd,
      { "forwardServiceInteractionInd", "inap.forwardServiceInteractionInd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_backwardServiceInteractionInd,
      { "backwardServiceInteractionInd", "inap.backwardServiceInteractionInd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_bothwayThroughConnectionInd,
      { "bothwayThroughConnectionInd", "inap.bothwayThroughConnectionInd",
        FT_UINT32, BASE_DEC, VALS(inap_BothwayThroughConnectionInd_vals), 0,
        NULL, HFILL }},
    { &hf_inap_suspendTimer,
      { "suspendTimer", "inap.suspendTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_connectedNumberTreatmentInd,
      { "connectedNumberTreatmentInd", "inap.connectedNumberTreatmentInd",
        FT_UINT32, BASE_DEC, VALS(inap_ConnectedNumberTreatmentInd_vals), 0,
        NULL, HFILL }},
    { &hf_inap_suppressCallDiversionNotification,
      { "suppressCallDiversionNotification", "inap.suppressCallDiversionNotification",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_suppressCallTransferNotification,
      { "suppressCallTransferNotification", "inap.suppressCallTransferNotification",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_allowCdINNoPresentationInd,
      { "allowCdINNoPresentationInd", "inap.allowCdINNoPresentationInd",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_userDialogueDurationInd,
      { "userDialogueDurationInd", "inap.userDialogueDurationInd",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_overrideLineRestrictions,
      { "overrideLineRestrictions", "inap.overrideLineRestrictions",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_suppressVPNAPP,
      { "suppressVPNAPP", "inap.suppressVPNAPP",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_calledINNumberOverriding,
      { "calledINNumberOverriding", "inap.calledINNumberOverriding",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_redirectServiceTreatmentInd,
      { "redirectServiceTreatmentInd", "inap.redirectServiceTreatmentInd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_redirectReason,
      { "redirectReason", "inap.redirectReason",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_nonCUGCall,
      { "nonCUGCall", "inap.nonCUGCall_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_oneTrigger,
      { "oneTrigger", "inap.oneTrigger",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_inap_triggers,
      { "triggers", "inap.triggers",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_triggerId,
      { "triggerId", "inap.triggerId",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_triggerPar,
      { "triggerPar", "inap.triggerPar_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_triggerID,
      { "triggerID", "inap.triggerID",
        FT_UINT32, BASE_DEC, VALS(inap_EventTypeBCSM_vals), 0,
        "EventTypeBCSM", HFILL }},
    { &hf_inap_profile,
      { "profile", "inap.profile",
        FT_UINT32, BASE_DEC, VALS(inap_ProfileIdentifier_vals), 0,
        "ProfileIdentifier", HFILL }},
    { &hf_inap_TriggerResults_item,
      { "TriggerResult", "inap.TriggerResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tDPIdentifer,
      { "tDPIdentifer", "inap.tDPIdentifer",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_inap_actionPerformed,
      { "actionPerformed", "inap.actionPerformed",
        FT_UINT32, BASE_DEC, VALS(inap_ActionPerformed_vals), 0,
        NULL, HFILL }},
    { &hf_inap_Triggers_item,
      { "Trigger", "inap.Trigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_trigger_tDPIdentifier,
      { "tDPIdentifier", "inap.trigger.tdpidentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_inap_dpName,
      { "dpName", "inap.dpName",
        FT_UINT32, BASE_DEC, VALS(inap_EventTypeBCSM_vals), 0,
        "EventTypeBCSM", HFILL }},
    { &hf_inap_global,
      { "global", "inap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_inap_local,
      { "local", "inap.local",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_minUSIServiceIndicatorLength_maxUSIServiceIndicatorLength", HFILL }},
    { &hf_inap_filteredCallTreatment,
      { "filteredCallTreatment", "inap.filteredCallTreatment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_filteringCharacteristics,
      { "filteringCharacteristics", "inap.filteringCharacteristics",
        FT_UINT32, BASE_DEC, VALS(inap_FilteringCharacteristics_vals), 0,
        NULL, HFILL }},
    { &hf_inap_filteringTimeOut,
      { "filteringTimeOut", "inap.filteringTimeOut",
        FT_UINT32, BASE_DEC, VALS(inap_FilteringTimeOut_vals), 0,
        NULL, HFILL }},
    { &hf_inap_filteringCriteria,
      { "filteringCriteria", "inap.filteringCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_FilteringCriteria_vals), 0,
        NULL, HFILL }},
    { &hf_inap_startTime,
      { "startTime", "inap.startTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DateAndTime", HFILL }},
    { &hf_inap_dpSpecificCommonParameters,
      { "dpSpecificCommonParameters", "inap.dpSpecificCommonParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_dialledDigits,
      { "dialledDigits", "inap.dialledDigits",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CalledPartyNumber", HFILL }},
    { &hf_inap_callingPartyBusinessGroupID,
      { "callingPartyBusinessGroupID", "inap.callingPartyBusinessGroupID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callingPartySubaddress,
      { "callingPartySubaddress", "inap.callingPartySubaddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callingFacilityGroup,
      { "callingFacilityGroup", "inap.callingFacilityGroup",
        FT_UINT32, BASE_DEC, VALS(inap_FacilityGroup_vals), 0,
        "FacilityGroup", HFILL }},
    { &hf_inap_callingFacilityGroupMember,
      { "callingFacilityGroupMember", "inap.callingFacilityGroupMember",
        FT_INT32, BASE_DEC, NULL, 0,
        "FacilityGroupMember", HFILL }},
    { &hf_inap_originalCalledPartyID,
      { "originalCalledPartyID", "inap.originalCalledPartyID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_prefix,
      { "prefix", "inap.prefix",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_redirectingPartyID,
      { "redirectingPartyID", "inap.redirectingPartyID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_redirectionInformation,
      { "redirectionInformation", "inap.redirectionInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_routeList,
      { "routeList", "inap.routeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_travellingClassMark,
      { "travellingClassMark", "inap.travellingClassMark",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_featureCode,
      { "featureCode", "inap.featureCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_accessCode,
      { "accessCode", "inap.accessCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_carrier,
      { "carrier", "inap.carrier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_componentType,
      { "componentType", "inap.componentType",
        FT_UINT32, BASE_DEC, VALS(inap_ComponentType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_component,
      { "component", "inap.component",
        FT_UINT32, BASE_DEC, VALS(inap_Component_vals), 0,
        NULL, HFILL }},
    { &hf_inap_componentCorrelationID,
      { "componentCorrelationID", "inap.componentCorrelationID",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_destinationRoutingAddress,
      { "destinationRoutingAddress", "inap.destinationRoutingAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_alertingPattern,
      { "alertingPattern", "inap.alertingPattern",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_iNServiceCompatibilityResponse,
      { "iNServiceCompatibilityResponse", "inap.iNServiceCompatibilityResponse",
        FT_UINT32, BASE_DEC, VALS(inap_Entry_vals), 0,
        NULL, HFILL }},
    { &hf_inap_correlationID,
      { "correlationID", "inap.correlationID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callSegmentID,
      { "callSegmentID", "inap.callSegmentID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_legToBeCreated,
      { "legToBeCreated", "inap.legToBeCreated",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "LegID", HFILL }},
    { &hf_inap_aChBillingChargingCharacteristics,
      { "aChBillingChargingCharacteristics", "inap.aChBillingChargingCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_partyToCharge,
      { "partyToCharge", "inap.partyToCharge",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "LegID", HFILL }},
    { &hf_inap_releaseIndication,
      { "releaseIndication", "inap.releaseIndication",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_destinationNumberRoutingAddress,
      { "destinationNumberRoutingAddress", "inap.destinationNumberRoutingAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CalledPartyNumber", HFILL }},
    { &hf_inap_displayInformation,
      { "displayInformation", "inap.displayInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_destinationIndex,
      { "destinationIndex", "inap.destinationIndex",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_gapIndicators,
      { "gapIndicators", "inap.gapIndicators_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_registratorIdentifier,
      { "registratorIdentifier", "inap.registratorIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_gapCriteria,
      { "gapCriteria", "inap.gapCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_GapCriteria_vals), 0,
        NULL, HFILL }},
    { &hf_inap_controlType,
      { "controlType", "inap.controlType",
        FT_UINT32, BASE_DEC, VALS(inap_ControlType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_gapTreatment,
      { "gapTreatment", "inap.gapTreatment",
        FT_UINT32, BASE_DEC, VALS(inap_GapTreatment_vals), 0,
        NULL, HFILL }},
    { &hf_inap_requestedInformationList,
      { "requestedInformationList", "inap.requestedInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_lastEventIndicator,
      { "lastEventIndicator", "inap.lastEventIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_requestedInformationTypeList,
      { "requestedInformationTypeList", "inap.requestedInformationTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_invokeID,
      { "invokeID", "inap.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_allRequests,
      { "allRequests", "inap.allRequests_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callSegmentToCancel,
      { "callSegmentToCancel", "inap.callSegmentToCancel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_allRequestsForCallSegment,
      { "allRequestsForCallSegment", "inap.allRequestsForCallSegment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallSegmentID", HFILL }},
    { &hf_inap_resourceID,
      { "resourceID", "inap.resourceID",
        FT_UINT32, BASE_DEC, VALS(inap_ResourceID_vals), 0,
        NULL, HFILL }},
    { &hf_inap_numberingPlan,
      { "numberingPlan", "inap.numberingPlan",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_cutAndPaste,
      { "cutAndPaste", "inap.cutAndPaste",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_forwardingCondition,
      { "forwardingCondition", "inap.forwardingCondition",
        FT_UINT32, BASE_DEC, VALS(inap_ForwardingCondition_vals), 0,
        NULL, HFILL }},
    { &hf_inap_forwardCallIndicators,
      { "forwardCallIndicators", "inap.forwardCallIndicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_genericNumbers,
      { "genericNumbers", "inap.genericNumbers",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_sDSSinformation,
      { "sDSSinformation", "inap.sDSSinformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_calledDirectoryNumber,
      { "calledDirectoryNumber", "inap.calledDirectoryNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_calledPartySubaddress,
      { "calledPartySubaddress", "inap.calledPartySubaddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_connectionIdentifier,
      { "connectionIdentifier", "inap.connectionIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_genericIdentifier,
      { "genericIdentifier", "inap.genericIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_qOSParameter,
      { "qOSParameter", "inap.qOSParameter",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_bISDNParameters,
      { "bISDNParameters", "inap.bISDNParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_cug_Interlock,
      { "cug-Interlock", "inap.cug_Interlock",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_cug_OutgoingAccess,
      { "cug-OutgoingAccess", "inap.cug_OutgoingAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_resourceAddress,
      { "resourceAddress", "inap.resourceAddress",
        FT_UINT32, BASE_DEC, VALS(inap_T_resourceAddress_vals), 0,
        NULL, HFILL }},
    { &hf_inap_ipRoutingAddress,
      { "ipRoutingAddress", "inap.ipRoutingAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ipAddressAndLegID,
      { "ipAddressAndLegID", "inap.ipAddressAndLegID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_none,
      { "none", "inap.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ipAddressAndCallSegment,
      { "ipAddressAndCallSegment", "inap.ipAddressAndCallSegment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_legorCSID,
      { "legorCSID", "inap.legorCSID",
        FT_UINT32, BASE_DEC, VALS(inap_T_legorCSID_vals), 0,
        NULL, HFILL }},
    { &hf_inap_csID,
      { "csID", "inap.csID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallSegmentID", HFILL }},
    { &hf_inap_genericName,
      { "genericName", "inap.genericName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_ipRelationInformation,
      { "ipRelationInformation", "inap.ipRelationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPRelatedInformation", HFILL }},
    { &hf_inap_newCallSegmentAssociation,
      { "newCallSegmentAssociation", "inap.newCallSegmentAssociation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CSAID", HFILL }},
    { &hf_inap_createOrRemove,
      { "createOrRemove", "inap.createOrRemove",
        FT_UINT32, BASE_DEC, VALS(inap_CreateOrRemoveIndicator_vals), 0,
        "CreateOrRemoveIndicator", HFILL }},
    { &hf_inap_triggerDPType,
      { "triggerDPType", "inap.triggerDPType",
        FT_UINT32, BASE_DEC, VALS(inap_TriggerDPType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_triggerData,
      { "triggerData", "inap.triggerData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_defaultFaultHandling,
      { "defaultFaultHandling", "inap.defaultFaultHandling_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_triggerStatus,
      { "triggerStatus", "inap.triggerStatus",
        FT_UINT32, BASE_DEC, VALS(inap_TriggerStatus_vals), 0,
        NULL, HFILL }},
    { &hf_inap_partyToDisconnect,
      { "partyToDisconnect", "inap.partyToDisconnect",
        FT_UINT32, BASE_DEC, VALS(inap_T_partyToDisconnect_vals), 0,
        NULL, HFILL }},
    { &hf_inap_legToBeReleased,
      { "legToBeReleased", "inap.legToBeReleased",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "LegID", HFILL }},
    { &hf_inap_cSFailure,
      { "cSFailure", "inap.cSFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_reason,
      { "reason", "inap.reason",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_bCSMFailure,
      { "bCSMFailure", "inap.bCSMFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_assistingSSPIPRoutingAddress,
      { "assistingSSPIPRoutingAddress", "inap.assistingSSPIPRoutingAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_partyToConnect,
      { "partyToConnect", "inap.partyToConnect",
        FT_UINT32, BASE_DEC, VALS(inap_T_partyToConnect_vals), 0,
        NULL, HFILL }},
    { &hf_inap_eventSpecificInformationCharging,
      { "eventSpecificInformationCharging", "inap.eventSpecificInformationCharging",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_bcsmEventCorrelationID,
      { "bcsmEventCorrelationID", "inap.bcsmEventCorrelationID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CorrelationID", HFILL }},
    { &hf_inap_eventSpecificInformationBCSM,
      { "eventSpecificInformationBCSM", "inap.eventSpecificInformationBCSM",
        FT_UINT32, BASE_DEC, VALS(inap_EventSpecificInformationBCSM_vals), 0,
        NULL, HFILL }},
    { &hf_inap_calledPartyBusinessGroupID,
      { "calledPartyBusinessGroupID", "inap.calledPartyBusinessGroupID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_holdcause,
      { "holdcause", "inap.holdcause",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_empty,
      { "empty", "inap.empty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_highLayerCompatibility,
      { "highLayerCompatibility", "inap.highLayerCompatibility",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_additionalCallingPartyNumber,
      { "additionalCallingPartyNumber", "inap.additionalCallingPartyNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_cCSS,
      { "cCSS", "inap.cCSS",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_vPNIndicator,
      { "vPNIndicator", "inap.vPNIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_cNInfo,
      { "cNInfo", "inap.cNInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callReference,
      { "callReference", "inap.callReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_routeingNumber,
      { "routeingNumber", "inap.routeingNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callingGeodeticLocation,
      { "callingGeodeticLocation", "inap.callingGeodeticLocation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_globalCallReference,
      { "globalCallReference", "inap.globalCallReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_cug_Index,
      { "cug-Index", "inap.cug_Index",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_newCallSegment,
      { "newCallSegment", "inap.newCallSegment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallSegmentID", HFILL }},
    { &hf_inap_incomingSignallingBufferCopy,
      { "incomingSignallingBufferCopy", "inap.incomingSignallingBufferCopy",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_actionIndicator,
      { "actionIndicator", "inap.actionIndicator",
        FT_UINT32, BASE_DEC, VALS(inap_ActionIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_inap_triggerDataIdentifier,
      { "triggerDataIdentifier", "inap.triggerDataIdentifier",
        FT_UINT32, BASE_DEC, VALS(inap_T_triggerDataIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_inap_profileAndDP,
      { "profileAndDP", "inap.profileAndDP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TriggerDataIdentifier", HFILL }},
    { &hf_inap_oneTriggerResult,
      { "oneTriggerResult", "inap.oneTriggerResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_severalTriggerResult,
      { "severalTriggerResult", "inap.severalTriggerResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_results,
      { "results", "inap.results",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TriggerResults", HFILL }},
    { &hf_inap_sourceCallSegment,
      { "sourceCallSegment", "inap.sourceCallSegment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallSegmentID", HFILL }},
    { &hf_inap_targetCallSegment,
      { "targetCallSegment", "inap.targetCallSegment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallSegmentID", HFILL }},
    { &hf_inap_mergeSignallingPaths,
      { "mergeSignallingPaths", "inap.mergeSignallingPaths_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_routeCounters,
      { "routeCounters", "inap.routeCounters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RouteCountersValue", HFILL }},
    { &hf_inap_monitoringCriteria,
      { "monitoringCriteria", "inap.monitoringCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_MonitoringCriteria_vals), 0,
        NULL, HFILL }},
    { &hf_inap_monitoringTimeout,
      { "monitoringTimeout", "inap.monitoringTimeout",
        FT_UINT32, BASE_DEC, VALS(inap_MonitoringTimeOut_vals), 0,
        NULL, HFILL }},
    { &hf_inap_targetCallSegmentAssociation,
      { "targetCallSegmentAssociation", "inap.targetCallSegmentAssociation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CSAID", HFILL }},
    { &hf_inap_callSegments,
      { "callSegments", "inap.callSegments",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callSegments_item,
      { "callSegments item", "inap.callSegments_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_legs,
      { "legs", "inap.legs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_legs_item,
      { "legs item", "inap.legs_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_sourceLeg,
      { "sourceLeg", "inap.sourceLeg",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "LegID", HFILL }},
    { &hf_inap_newLeg,
      { "newLeg", "inap.newLeg",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "LegID", HFILL }},
    { &hf_inap_legIDToMove,
      { "legIDToMove", "inap.legIDToMove",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "LegID", HFILL }},
    { &hf_inap_detachSignallingPath,
      { "detachSignallingPath", "inap.detachSignallingPath_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_exportSignallingPath,
      { "exportSignallingPath", "inap.exportSignallingPath_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_featureRequestIndicator,
      { "featureRequestIndicator", "inap.featureRequestIndicator",
        FT_UINT32, BASE_DEC, VALS(inap_FeatureRequestIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_inap_componenttCorrelationID,
      { "componenttCorrelationID", "inap.componenttCorrelationID",
        FT_INT32, BASE_DEC, NULL, 0,
        "ComponentCorrelationID", HFILL }},
    { &hf_inap_notificationDuration,
      { "notificationDuration", "inap.notificationDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ApplicationTimer", HFILL }},
    { &hf_inap_initialCallSegment,
      { "initialCallSegment", "inap.initialCallSegment",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Cause", HFILL }},
    { &hf_inap_callSegmentToRelease,
      { "callSegmentToRelease", "inap.callSegmentToRelease_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_callSegment,
      { "callSegment", "inap.callSegment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_numOfCSs", HFILL }},
    { &hf_inap_forcedRelease,
      { "forcedRelease", "inap.forcedRelease",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_allCallSegments,
      { "allCallSegments", "inap.allCallSegments_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_timeToRelease,
      { "timeToRelease", "inap.timeToRelease",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimerValue", HFILL }},
    { &hf_inap_resourceStatus,
      { "resourceStatus", "inap.resourceStatus",
        FT_UINT32, BASE_DEC, VALS(inap_ResourceStatus_vals), 0,
        NULL, HFILL }},
    { &hf_inap_monitorDuration,
      { "monitorDuration", "inap.monitorDuration",
        FT_INT32, BASE_DEC, NULL, 0,
        "Duration", HFILL }},
    { &hf_inap_RequestNotificationChargingEventArg_item,
      { "ChargingEvent", "inap.ChargingEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_bcsmEvents,
      { "bcsmEvents", "inap.bcsmEvents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent", HFILL }},
    { &hf_inap_bcsmEvents_item,
      { "BCSMEvent", "inap.BCSMEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_componentTypes,
      { "componentTypes", "inap.componentTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_3_OF_ComponentType", HFILL }},
    { &hf_inap_componentTypes_item,
      { "ComponentType", "inap.ComponentType",
        FT_UINT32, BASE_DEC, VALS(inap_ComponentType_vals), 0,
        NULL, HFILL }},
    { &hf_inap_requestedUTSIList,
      { "requestedUTSIList", "inap.requestedUTSIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_timerID,
      { "timerID", "inap.timerID",
        FT_UINT32, BASE_DEC, VALS(inap_TimerID_vals), 0,
        NULL, HFILL }},
    { &hf_inap_timervalue,
      { "timervalue", "inap.timervalue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_calledFacilityGroup,
      { "calledFacilityGroup", "inap.calledFacilityGroup",
        FT_UINT32, BASE_DEC, VALS(inap_FacilityGroup_vals), 0,
        "FacilityGroup", HFILL }},
    { &hf_inap_calledFacilityGroupMember,
      { "calledFacilityGroupMember", "inap.calledFacilityGroupMember",
        FT_INT32, BASE_DEC, NULL, 0,
        "FacilityGroupMember", HFILL }},
    { &hf_inap_sCIBillingChargingCharacteristics,
      { "sCIBillingChargingCharacteristics", "inap.sCIBillingChargingCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_nocharge,
      { "nocharge", "inap.nocharge",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_callProcessingOperation,
      { "callProcessingOperation", "inap.callProcessingOperation",
        FT_UINT32, BASE_DEC, VALS(inap_CallProcessingOperation_vals), 0,
        NULL, HFILL }},
    { &hf_inap_countersValue,
      { "countersValue", "inap.countersValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_responseCondition,
      { "responseCondition", "inap.responseCondition",
        FT_UINT32, BASE_DEC, VALS(inap_ResponseCondition_vals), 0,
        NULL, HFILL }},
    { &hf_inap_iNprofiles,
      { "iNprofiles", "inap.iNprofiles",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_numOfINProfile_OF_INprofile", HFILL }},
    { &hf_inap_iNprofiles_item,
      { "INprofile", "inap.INprofile_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_legToBeSplit,
      { "legToBeSplit", "inap.legToBeSplit",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "LegID", HFILL }},
    { &hf_inap_newCallSegment_01,
      { "newCallSegment", "inap.newCallSegment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_numOfCSs", HFILL }},
    { &hf_inap_reportCondition,
      { "reportCondition", "inap.reportCondition",
        FT_UINT32, BASE_DEC, VALS(inap_ReportCondition_vals), 0,
        NULL, HFILL }},
    { &hf_inap_minimumNbOfDigits,
      { "minimumNbOfDigits", "inap.minimumNbOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_inap_maximumNbOfDigits,
      { "maximumNbOfDigits", "inap.maximumNbOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_inap_endOfReplyDigit,
      { "endOfReplyDigit", "inap.endOfReplyDigit",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_inap_cancelDigit,
      { "cancelDigit", "inap.cancelDigit",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_inap_startDigit,
      { "startDigit", "inap.startDigit",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_inap_firstDigitTimeOut,
      { "firstDigitTimeOut", "inap.firstDigitTimeOut",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_inap_interDigitTimeOut,
      { "interDigitTimeOut", "inap.interDigitTimeOut",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_inap_errorTreatment,
      { "errorTreatment", "inap.errorTreatment",
        FT_UINT32, BASE_DEC, VALS(inap_ErrorTreatment_vals), 0,
        NULL, HFILL }},
    { &hf_inap_interruptableAnnInd,
      { "interruptableAnnInd", "inap.interruptableAnnInd",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_voiceInformation,
      { "voiceInformation", "inap.voiceInformation",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_voiceBack,
      { "voiceBack", "inap.voiceBack",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_detectModem,
      { "detectModem", "inap.detectModem",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_collectedDigits,
      { "collectedDigits", "inap.collectedDigits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_iA5Information,
      { "iA5Information", "inap.iA5Information",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_messageID,
      { "messageID", "inap.messageID",
        FT_UINT32, BASE_DEC, VALS(inap_MessageID_vals), 0,
        NULL, HFILL }},
    { &hf_inap_numberOfRepetitions,
      { "numberOfRepetitions", "inap.numberOfRepetitions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_inap_inbandInfo_duration,
      { "duration", "inap.inbandInfo.duration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_inap_inbandInfo_interval,
      { "interval", "inap.inbandInfo.interval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_inap_preferredLanguage,
      { "preferredLanguage", "inap.preferredLanguage",
        FT_STRING, BASE_NONE, NULL, 0,
        "Language", HFILL }},
    { &hf_inap_messageID_01,
      { "messageID", "inap.messageID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ElementaryMessageID", HFILL }},
    { &hf_inap_messageDeletionTimeOut,
      { "messageDeletionTimeOut", "inap.messageDeletionTimeOut",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_3600", HFILL }},
    { &hf_inap_timeToRecord,
      { "timeToRecord", "inap.timeToRecord",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_b3__maxRecordingTime", HFILL }},
    { &hf_inap_controlDigits,
      { "controlDigits", "inap.controlDigits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_endOfRecordingDigit,
      { "endOfRecordingDigit", "inap.endOfRecordingDigit",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_inap_replayDigit,
      { "replayDigit", "inap.replayDigit",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_inap_restartRecordingDigit,
      { "restartRecordingDigit", "inap.restartRecordingDigit",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_inap_restartAllowed,
      { "restartAllowed", "inap.restartAllowed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_replayAllowed,
      { "replayAllowed", "inap.replayAllowed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_inbandInfo,
      { "inbandInfo", "inap.inbandInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tone,
      { "tone", "inap.tone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_elementaryMessageID,
      { "elementaryMessageID", "inap.elementaryMessageID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Integer4", HFILL }},
    { &hf_inap_text,
      { "text", "inap.text_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_messageContent,
      { "messageContent", "inap.messageContent",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_b3__minMessageContentLength_b3__maxMessageContentLength", HFILL }},
    { &hf_inap_attributes,
      { "attributes", "inap.attributes",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_b3__minAttributesLength_b3__maxAttributesLength", HFILL }},
    { &hf_inap_elementaryMessageIDs,
      { "elementaryMessageIDs", "inap.elementaryMessageIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_b3__numOfMessageIDs_OF_Integer4", HFILL }},
    { &hf_inap_elementaryMessageIDs_item,
      { "Integer4", "inap.Integer4",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_variableMessage,
      { "variableMessage", "inap.variableMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_variableParts,
      { "variableParts", "inap.variableParts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_b3__maxVariableParts_OF_VariablePart", HFILL }},
    { &hf_inap_variableParts_item,
      { "VariablePart", "inap.VariablePart",
        FT_UINT32, BASE_DEC, VALS(inap_VariablePart_vals), 0,
        NULL, HFILL }},
    { &hf_inap_iPAddressValue,
      { "iPAddressValue", "inap.iPAddressValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_gapOnResource,
      { "gapOnResource", "inap.gapOnResource",
        FT_UINT32, BASE_DEC, VALS(inap_Code_vals), 0,
        NULL, HFILL }},
    { &hf_inap_iPAddressAndresource,
      { "iPAddressAndresource", "inap.iPAddressAndresource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_toneID,
      { "toneID", "inap.toneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Integer4", HFILL }},
    { &hf_inap_tone_duration,
      { "duration", "inap.tone.duration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Integer4", HFILL }},
    { &hf_inap_integer,
      { "integer", "inap.integer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Integer4", HFILL }},
    { &hf_inap_number,
      { "number", "inap.number",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_time,
      { "time", "inap.time",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_inap_date,
      { "date", "inap.date",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_inap_price,
      { "price", "inap.price",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_inap_disconnectFromIPForbidden,
      { "disconnectFromIPForbidden", "inap.disconnectFromIPForbidden",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_requestAnnouncementComplete,
      { "requestAnnouncementComplete", "inap.requestAnnouncementComplete",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_connectedParty,
      { "connectedParty", "inap.connectedParty",
        FT_UINT32, BASE_DEC, VALS(inap_T_connectedParty_vals), 0,
        NULL, HFILL }},
    { &hf_inap_collectedInfo,
      { "collectedInfo", "inap.collectedInfo",
        FT_UINT32, BASE_DEC, VALS(inap_CollectedInfo_vals), 0,
        NULL, HFILL }},
    { &hf_inap_digitsResponse,
      { "digitsResponse", "inap.digitsResponse",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_inap_iA5Response,
      { "iA5Response", "inap.iA5Response",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_inap_modemdetected,
      { "modemdetected", "inap.modemdetected",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_inap_subscriberID,
      { "subscriberID", "inap.subscriberID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GenericNumber", HFILL }},
    { &hf_inap_mailBoxID,
      { "mailBoxID", "inap.mailBoxID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_informationToRecord,
      { "informationToRecord", "inap.informationToRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_media,
      { "media", "inap.media",
        FT_UINT32, BASE_DEC, VALS(inap_Media_vals), 0,
        NULL, HFILL }},
    { &hf_inap_receivedStatus,
      { "receivedStatus", "inap.receivedStatus",
        FT_UINT32, BASE_DEC, VALS(inap_ReceivedStatus_vals), 0,
        NULL, HFILL }},
    { &hf_inap_recordedMessageID,
      { "recordedMessageID", "inap.recordedMessageID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_recordedMessageUnits,
      { "recordedMessageUnits", "inap.recordedMessageUnits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_b3__maxRecordedMessageUnits", HFILL }},
    { &hf_inap_uIScriptId,
      { "uIScriptId", "inap.uIScriptId",
        FT_UINT32, BASE_DEC, VALS(inap_Code_vals), 0,
        "Code", HFILL }},
    { &hf_inap_uIScriptSpecificInfo,
      { "uIScriptSpecificInfo", "inap.uIScriptSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_uIScriptResult,
      { "uIScriptResult", "inap.uIScriptResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_uIScriptSpecificInfo_01,
      { "uIScriptSpecificInfo", "inap.uIScriptSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_uIScriptSpecificInfo_01", HFILL }},
    { &hf_inap_uIScriptSpecificInfo_02,
      { "uIScriptSpecificInfo", "inap.uIScriptSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_uIScriptSpecificInfo_02", HFILL }},
    { &hf_inap_sRFgapCriteria,
      { "sRFgapCriteria", "inap.sRFgapCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_SRFGapCriteria_vals), 0,
        NULL, HFILL }},
    { &hf_inap_problem,
      { "problem", "inap.problem",
        FT_UINT32, BASE_DEC, VALS(inap_T_problem_vals), 0,
        NULL, HFILL }},
    { &hf_inap_operation,
      { "operation", "inap.operation",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeID", HFILL }},
    { &hf_inap_scfTaskRefusedParameter_reason,
      { "reason", "inap.scfTaskRefusedParameter.reason",
        FT_UINT32, BASE_DEC, VALS(inap_T_scfTaskRefusedParameter_reason_vals), 0,
        "T_scfTaskRefusedParameter_reason", HFILL }},
    { &hf_inap_securityParameters,
      { "securityParameters", "inap.securityParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_tryhere,
      { "tryhere", "inap.tryhere_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccessPointInformation", HFILL }},
    { &hf_inap_code_local,
      { "local", "inap.code.local",
        FT_INT32, BASE_DEC, NULL, 0,
        "T_code_local", HFILL }},
    { &hf_inap_global_01,
      { "global", "inap.global",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_invoke,
      { "invoke", "inap.invoke_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_returnResult,
      { "returnResult", "inap.returnResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_returnError,
      { "returnError", "inap.returnError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_reject,
      { "reject", "inap.reject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_invokeId,
      { "invokeId", "inap.invokeId",
        FT_UINT32, BASE_DEC, VALS(inap_InvokeId_vals), 0,
        NULL, HFILL }},
    { &hf_inap_linkedId,
      { "linkedId", "inap.linkedId",
        FT_UINT32, BASE_DEC, VALS(inap_T_linkedId_vals), 0,
        NULL, HFILL }},
    { &hf_inap_inkedIdPresent,
      { "present", "inap.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "T_inkedIdPresent", HFILL }},
    { &hf_inap_absent,
      { "absent", "inap.absent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_opcode,
      { "opcode", "inap.opcode",
        FT_UINT32, BASE_DEC, VALS(inap_Code_vals), 0,
        "Code", HFILL }},
    { &hf_inap_argument,
      { "argument", "inap.argument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_result,
      { "result", "inap.result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_resultArgument,
      { "result", "inap.result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResultArgument", HFILL }},
    { &hf_inap_errcode,
      { "errcode", "inap.errcode",
        FT_UINT32, BASE_DEC, VALS(inap_Code_vals), 0,
        "Code", HFILL }},
    { &hf_inap_parameter,
      { "parameter", "inap.parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_inap_problem_01,
      { "problem", "inap.problem",
        FT_UINT32, BASE_DEC, VALS(inap_T_problem_01_vals), 0,
        "T_problem_01", HFILL }},
    { &hf_inap_general,
      { "general", "inap.general",
        FT_INT32, BASE_DEC, VALS(inap_GeneralProblem_vals), 0,
        "GeneralProblem", HFILL }},
    { &hf_inap_invokeProblem,
      { "invoke", "inap.invoke",
        FT_INT32, BASE_DEC, VALS(inap_InvokeProblem_vals), 0,
        "InvokeProblem", HFILL }},
    { &hf_inap_problemReturnResult,
      { "returnResult", "inap.returnResult",
        FT_INT32, BASE_DEC, VALS(inap_ReturnResultProblem_vals), 0,
        "ReturnResultProblem", HFILL }},
    { &hf_inap_returnErrorProblem,
      { "returnError", "inap.returnError",
        FT_INT32, BASE_DEC, VALS(inap_ReturnErrorProblem_vals), 0,
        "ReturnErrorProblem", HFILL }},
    { &hf_inap_present,
      { "present", "inap.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_inap_InvokeId_present,
      { "InvokeId.present", "inap.InvokeId_present",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeId_present", HFILL }},
  };






  /* List of subtrees */
  static int *ett[] = {
    &ett_inap,
    &ett_inapisup_parameter,
    &ett_inap_RedirectionInformation,
    &ett_inap_HighLayerCompatibility,
    &ett_inap_extension_data,
    &ett_inap_cause,
    &ett_inap_calledAddressValue,
    &ett_inap_callingAddressValue,
    &ett_inap_additionalCallingPartyNumber,
    &ett_inap_assistingSSPIPRoutingAddress,
    &ett_inap_correlationID,
    &ett_inap_number,
    &ett_inap_dialledNumber,
    &ett_inap_callingLineID,
    &ett_inap_iNServiceControlCode,
    &ett_inap_iNServiceControlCodeLow,
    &ett_inap_iNServiceControlCodeHigh,
    &ett_inap_lineID,
    &ett_inap_prefix,
    &ett_inap_iPAddressValue,
    &ett_inap_digitsResponse,
    &ett_inap_Extensions,
    &ett_inap_ExtensionField,
    &ett_inap_AlternativeIdentities,
    &ett_inap_AlternativeIdentity,
    &ett_inap_BackwardServiceInteractionInd,
    &ett_inap_BasicGapCriteria,
    &ett_inap_T_calledAddressAndService,
    &ett_inap_T_callingAddressAndService,
    &ett_inap_BCSMEvent,
    &ett_inap_BearerCapability,
    &ett_inap_BISDNParameters,
    &ett_inap_ChargingEvent,
    &ett_inap_Component,
    &ett_inap_CompoundCriteria,
    &ett_inap_CounterAndValue,
    &ett_inap_CountersValue,
    &ett_inap_DefaultFaultHandling,
    &ett_inap_DestinationRoutingAddress,
    &ett_inap_DpSpecificCommonParameters,
    &ett_inap_DpSpecificCriteria,
    &ett_inap_T_numberOfDigitsTwo,
    &ett_inap_Entry,
    &ett_inap_EventSpecificInformationBCSM,
    &ett_inap_T_collectedInfoSpecificInfo,
    &ett_inap_T_analysedInfoSpecificInfo,
    &ett_inap_T_routeSelectFailureSpecificInfo,
    &ett_inap_T_oCalledPartyBusySpecificInfo,
    &ett_inap_T_oNoAnswerSpecificInfo,
    &ett_inap_T_oAnswerSpecificInfo,
    &ett_inap_T_oMidCallSpecificInfo,
    &ett_inap_T_oDisconnectSpecificInfo,
    &ett_inap_T_tBusySpecificInfo,
    &ett_inap_T_tNoAnswerSpecificInfo,
    &ett_inap_T_tAnswerSpecificInfo,
    &ett_inap_T_tMidCallSpecificInfo,
    &ett_inap_T_tDisconnectSpecificInfo,
    &ett_inap_T_oTermSeizedSpecificInfo,
    &ett_inap_T_oSuspend,
    &ett_inap_T_tSuspend,
    &ett_inap_T_origAttemptAuthorized,
    &ett_inap_T_oReAnswer,
    &ett_inap_T_tReAnswer,
    &ett_inap_T_facilitySelectedAndAvailable,
    &ett_inap_T_callAccepted,
    &ett_inap_T_oAbandon,
    &ett_inap_T_tAbandon,
    &ett_inap_T_authorizeRouteFailure,
    &ett_inap_T_terminationAttemptAuthorized,
    &ett_inap_T_originationAttemptDenied,
    &ett_inap_T_terminationAttemptDenied,
    &ett_inap_T_oModifyRequestSpecificInfo,
    &ett_inap_T_oModifyResultSpecificInfo,
    &ett_inap_T_tModifyRequestSpecificInfo,
    &ett_inap_T_tModifyResultSpecificInfo,
    &ett_inap_FacilityGroup,
    &ett_inap_FilteredCallTreatment,
    &ett_inap_FilteringCharacteristics,
    &ett_inap_FilteringCriteria,
    &ett_inap_T_addressAndService,
    &ett_inap_FilteringTimeOut,
    &ett_inap_ForwardServiceInteractionInd,
    &ett_inap_GapCriteria,
    &ett_inap_GapOnService,
    &ett_inap_GapIndicators,
    &ett_inap_GapTreatment,
    &ett_inap_T_both,
    &ett_inap_GenericNumbers,
    &ett_inap_INprofile,
    &ett_inap_INServiceCompatibilityIndication,
    &ett_inap_IPRelatedInformation,
    &ett_inap_LegID,
    &ett_inap_MidCallControlInfo,
    &ett_inap_MidCallControlInfo_item,
    &ett_inap_MidCallInfo,
    &ett_inap_MidCallInfoType,
    &ett_inap_MiscCallInfo,
    &ett_inap_MonitoringCriteria,
    &ett_inap_MonitoringTimeOut,
    &ett_inap_ProfileIdentifier,
    &ett_inap_RequestedInformationList,
    &ett_inap_RequestedInformationTypeList,
    &ett_inap_RequestedInformation,
    &ett_inap_RequestedInformationValue,
    &ett_inap_RequestedUTSI,
    &ett_inap_RequestedUTSIList,
    &ett_inap_ResourceID,
    &ett_inap_RouteCountersValue,
    &ett_inap_RouteCountersAndValue,
    &ett_inap_RouteList,
    &ett_inap_ServiceAddressInformation,
    &ett_inap_ServiceInteractionIndicatorsTwo,
    &ett_inap_T_redirectServiceTreatmentInd,
    &ett_inap_TDPIdentifier,
    &ett_inap_TriggerData,
    &ett_inap_TriggerDataIdentifier,
    &ett_inap_TriggerResults,
    &ett_inap_TriggerResult,
    &ett_inap_Triggers,
    &ett_inap_Trigger,
    &ett_inap_USIServiceIndicator,
    &ett_inap_ActivateServiceFilteringArg,
    &ett_inap_AnalysedInformationArg,
    &ett_inap_AnalyseInformationArg,
    &ett_inap_ApplyChargingArg,
    &ett_inap_AssistRequestInstructionsArg,
    &ett_inap_AuthorizeTerminationArg,
    &ett_inap_CallFilteringArg,
    &ett_inap_CallGapArg,
    &ett_inap_CallInformationReportArg,
    &ett_inap_CallInformationRequestArg,
    &ett_inap_CancelArg,
    &ett_inap_T_callSegmentToCancel,
    &ett_inap_CancelStatusReportRequestArg,
    &ett_inap_CollectedInformationArg,
    &ett_inap_CollectInformationArg,
    &ett_inap_ConnectArg,
    &ett_inap_ConnectToResourceArg,
    &ett_inap_T_resourceAddress,
    &ett_inap_T_ipAddressAndLegID,
    &ett_inap_T_ipAddressAndCallSegment,
    &ett_inap_ContinueWithArgumentArg,
    &ett_inap_T_legorCSID,
    &ett_inap_CreateCallSegmentAssociationArg,
    &ett_inap_CreateCallSegmentAssociationResultArg,
    &ett_inap_CreateOrRemoveTriggerDataArg,
    &ett_inap_CreateOrRemoveTriggerDataResultArg,
    &ett_inap_DisconnectForwardConnectionWithArgumentArg,
    &ett_inap_T_partyToDisconnect,
    &ett_inap_DisconnectLegArg,
    &ett_inap_EntityReleasedArg,
    &ett_inap_T_cSFailure,
    &ett_inap_T_bCSMFailure,
    &ett_inap_EstablishTemporaryConnectionArg,
    &ett_inap_T_partyToConnect,
    &ett_inap_EventNotificationChargingArg,
    &ett_inap_EventReportBCSMArg,
    &ett_inap_EventReportFacilityArg,
    &ett_inap_FacilitySelectedAndAvailableArg,
    &ett_inap_HoldCallInNetworkArg,
    &ett_inap_InitialDPArg,
    &ett_inap_InitiateCallAttemptArg,
    &ett_inap_ManageTriggerDataArg,
    &ett_inap_T_triggerDataIdentifier,
    &ett_inap_ManageTriggerDataResultArg,
    &ett_inap_T_oneTriggerResult,
    &ett_inap_T_severalTriggerResult,
    &ett_inap_MergeCallSegmentsArg,
    &ett_inap_MonitorRouteReportArg,
    &ett_inap_MonitorRouteRequestArg,
    &ett_inap_MoveCallSegmentsArg,
    &ett_inap_T_callSegments,
    &ett_inap_T_callSegments_item,
    &ett_inap_T_legs,
    &ett_inap_T_legs_item,
    &ett_inap_MoveLegArg,
    &ett_inap_OAbandonArg,
    &ett_inap_OAnswerArg,
    &ett_inap_OCalledPartyBusyArg,
    &ett_inap_ODisconnectArg,
    &ett_inap_MidCallArg,
    &ett_inap_ONoAnswerArg,
    &ett_inap_OriginationAttemptArg,
    &ett_inap_OriginationAttemptAuthorizedArg,
    &ett_inap_OSuspendedArg,
    &ett_inap_ReconnectArg,
    &ett_inap_ReleaseCallArg,
    &ett_inap_T_callSegmentToRelease,
    &ett_inap_T_allCallSegments,
    &ett_inap_ReportUTSIArg,
    &ett_inap_RequestCurrentStatusReportResultArg,
    &ett_inap_RequestEveryStatusChangeReportArg,
    &ett_inap_RequestFirstStatusMatchReportArg,
    &ett_inap_RequestNotificationChargingEventArg,
    &ett_inap_RequestReportBCSMEventArg,
    &ett_inap_SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent,
    &ett_inap_RequestReportFacilityEventArg,
    &ett_inap_SEQUENCE_SIZE_1_3_OF_ComponentType,
    &ett_inap_RequestReportUTSIArg,
    &ett_inap_ResetTimerArg,
    &ett_inap_RouteSelectFailureArg,
    &ett_inap_SelectFacilityArg,
    &ett_inap_SelectRouteArg,
    &ett_inap_SendChargingInformationArg,
    &ett_inap_SendFacilityInformationArg,
    &ett_inap_SendSTUIArg,
    &ett_inap_ServiceFilteringResponseArg,
    &ett_inap_SetServiceProfileArg,
    &ett_inap_SEQUENCE_SIZE_1_numOfINProfile_OF_INprofile,
    &ett_inap_SplitLegArg,
    &ett_inap_StatusReportArg,
    &ett_inap_TAnswerArg,
    &ett_inap_TBusyArg,
    &ett_inap_TDisconnectArg,
    &ett_inap_TermAttemptAuthorizedArg,
    &ett_inap_TerminationAttemptArg,
    &ett_inap_TNoAnswerArg,
    &ett_inap_TSuspendedArg,
    &ett_inap_CollectedDigits,
    &ett_inap_CollectedInfo,
    &ett_inap_InbandInfo,
    &ett_inap_InformationToRecord,
    &ett_inap_T_controlDigits,
    &ett_inap_InformationToSend,
    &ett_inap_MessageID,
    &ett_inap_T_text,
    &ett_inap_SEQUENCE_SIZE_1_b3__numOfMessageIDs_OF_Integer4,
    &ett_inap_T_variableMessage,
    &ett_inap_SEQUENCE_SIZE_1_b3__maxVariableParts_OF_VariablePart,
    &ett_inap_SRFGapCriteria,
    &ett_inap_T_iPAddressAndresource,
    &ett_inap_Tone,
    &ett_inap_VariablePart,
    &ett_inap_PlayAnnouncementArg,
    &ett_inap_T_connectedParty,
    &ett_inap_PromptAndCollectUserInformationArg,
    &ett_inap_ReceivedInformationArg,
    &ett_inap_PromptAndReceiveMessageArg,
    &ett_inap_MessageReceivedArg,
    &ett_inap_ScriptCloseArg,
    &ett_inap_ScriptEventArg,
    &ett_inap_ScriptInformationArg,
    &ett_inap_ScriptRunArg,
    &ett_inap_SRFCallGapArg,
    &ett_inap_PAR_cancelFailed,
    &ett_inap_ScfTaskRefusedParameter,
    &ett_inap_ReferralParameter,
    &ett_inap_Code,
    &ett_inap_ROS,
    &ett_inap_Invoke,
    &ett_inap_T_linkedId,
    &ett_inap_ReturnResult,
    &ett_inap_T_result,
    &ett_inap_ReturnError,
    &ett_inap_Reject,
    &ett_inap_T_problem_01,
    &ett_inap_InvokeId,
  };

  static ei_register_info ei[] = {
   { &ei_inap_unknown_invokeData, { "inap.unknown.invokeData", PI_MALFORMED, PI_WARN, "Unknown invokeData", EXPFILL }},
   { &ei_inap_unknown_returnResultData, { "inap.unknown.returnResultData", PI_MALFORMED, PI_WARN, "Unknown returnResultData", EXPFILL }},
   { &ei_inap_unknown_returnErrorData, { "inap.unknown.returnErrorData", PI_MALFORMED, PI_WARN, "Unknown returnResultData", EXPFILL }},
  };

  expert_module_t* expert_inap;

  /* Register protocol */
  proto_inap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  inap_handle = register_dissector("inap", dissect_inap, proto_inap);
  /* Register fields and subtrees */
  proto_register_field_array(proto_inap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_inap = expert_register_protocol(proto_inap);
  expert_register_field_array(expert_inap, ei, array_length(ei));

  register_ber_oid_dissector("0.4.0.1.1.1.0.0", dissect_inap, proto_inap, "cs1-ssp-to-scp");

  /* Set default SSNs */
  range_convert_str(wmem_epan_scope(), &global_ssn_range, "106,241", MAX_SSN);

  inap_module = prefs_register_protocol(proto_inap, proto_reg_handoff_inap);

  prefs_register_obsolete_preference(inap_module, "tcap.itu_ssn");

  prefs_register_obsolete_preference(inap_module, "tcap.itu_ssn1");

  prefs_register_range_preference(inap_module, "ssn", "TCAP SSNs",
                 "TCAP Subsystem numbers used for INAP",
                 &global_ssn_range, MAX_SSN);
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
