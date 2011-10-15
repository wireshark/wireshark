/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-h460.c                                                              */
/* ../../tools/asn2wrs.py -c ./h460.cnf -s ./packet-h460-template -D . -O ../../epan/dissectors NUMBER-PORTABILITY.asn CIRCUIT-STATUS-MAP.asn CALL-PRIORITY.asn QOS-MONITORING-REPORT.asn QOS-MONITORING-EXTENDED-VOIP-REPORT.asn CALL-PARTY-CATEGORY.asn MLPP.asn SIGNALLING-CHANNEL-SUSPEND-REDIRECT.asn SIGNALLING-TRAVERSAL.asn MEDIA-TRAVERSAL.asn MESSAGE-BROADCAST.asn */

/* Input file: packet-h460-template.c */

#line 1 "../../asn1/h460/packet-h460-template.c"
/* packet-h460.c
 * Routines for H.460.x packet dissection
 * 2007  Tomas Kukosa
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include <string.h>

#include "packet-per.h"
#include "packet-h225.h"
#include "packet-h235.h"
#include "packet-h245.h"

#define PNAME  "H.460 Supplementary Services"
#define PSNAME "H.460"
#define PFNAME "h460"

/* Initialize the protocol and registered fields */
static int proto_h460 = -1;

/*--- Included file: packet-h460-hf.c ---*/
#line 1 "../../asn1/h460/packet-h460-hf.c"

/* --- Module NUMBER-PORTABILITY --- --- ---                                  */

static int hf_h460_2_h460_2_NumberPortabilityInfo_PDU = -1;  /* NumberPortabilityInfo */
static int hf_h460_2_numberPortabilityRejectReason = -1;  /* NumberPortabilityRejectReason */
static int hf_h460_2_nUMBERPORTABILITYDATA = -1;  /* T_nUMBERPORTABILITYDATA */
static int hf_h460_2_addressTranslated = -1;      /* NULL */
static int hf_h460_2_portedAddress = -1;          /* PortabilityAddress */
static int hf_h460_2_routingAddress = -1;         /* PortabilityAddress */
static int hf_h460_2_regionalParams = -1;         /* RegionalParameters */
static int hf_h460_2_unspecified = -1;            /* NULL */
static int hf_h460_2_qorPortedNumber = -1;        /* NULL */
static int hf_h460_2_aliasAddress = -1;           /* AliasAddress */
static int hf_h460_2_typeOfAddress = -1;          /* NumberPortabilityTypeOfNumber */
static int hf_h460_2_publicTypeOfNumber = -1;     /* PublicTypeOfNumber */
static int hf_h460_2_privateTypeOfNumber = -1;    /* PrivateTypeOfNumber */
static int hf_h460_2_portabilityTypeOfNumber = -1;  /* PortabilityTypeOfNumber */
static int hf_h460_2_portedNumber = -1;           /* NULL */
static int hf_h460_2_routingNumber = -1;          /* NULL */
static int hf_h460_2_concatenatedNumber = -1;     /* NULL */
static int hf_h460_2_t35CountryCode = -1;         /* INTEGER_0_255 */
static int hf_h460_2_t35Extension = -1;           /* INTEGER_0_255 */
static int hf_h460_2_variantIdentifier = -1;      /* INTEGER_1_255 */
static int hf_h460_2_regionalData = -1;           /* OCTET_STRING */

/* --- Module CIRCUIT-STATUS-MAP --- --- ---                                  */

static int hf_h460_3_h460_3_CircuitStatus_PDU = -1;  /* CircuitStatus */
static int hf_h460_3_circuitStatusMap = -1;       /* SEQUENCE_OF_CircuitStatusMap */
static int hf_h460_3_circuitStatusMap_item = -1;  /* CircuitStatusMap */
static int hf_h460_3_statusType = -1;             /* CircuitStatusType */
static int hf_h460_3_baseCircuitID = -1;          /* CircuitIdentifier */
static int hf_h460_3_range = -1;                  /* INTEGER_0_4095 */
static int hf_h460_3_status = -1;                 /* OCTET_STRING */
static int hf_h460_3_serviceStatus = -1;          /* NULL */
static int hf_h460_3_busyStatus = -1;             /* NULL */

/* --- Module CALL-PRIORITY --- --- ---                                       */

static int hf_h460_4_h460_4_CallPriorityInfo_PDU = -1;  /* CallPriorityInfo */
static int hf_h460_4_h460_4_CountryInternationalNetworkCallOriginationIdentification_PDU = -1;  /* CountryInternationalNetworkCallOriginationIdentification */
static int hf_h460_4_priorityValue = -1;          /* T_priorityValue */
static int hf_h460_4_emergencyAuthorized = -1;    /* NULL */
static int hf_h460_4_emergencyPublic = -1;        /* NULL */
static int hf_h460_4_high = -1;                   /* NULL */
static int hf_h460_4_normal = -1;                 /* NULL */
static int hf_h460_4_priorityExtension = -1;      /* INTEGER_0_255 */
static int hf_h460_4_tokens = -1;                 /* SEQUENCE_OF_ClearToken */
static int hf_h460_4_tokens_item = -1;            /* ClearToken */
static int hf_h460_4_cryptoTokens = -1;           /* SEQUENCE_OF_CryptoToken */
static int hf_h460_4_cryptoTokens_item = -1;      /* CryptoToken */
static int hf_h460_4_rejectReason = -1;           /* T_rejectReason */
static int hf_h460_4_priorityUnavailable = -1;    /* NULL */
static int hf_h460_4_priorityUnauthorized = -1;   /* NULL */
static int hf_h460_4_priorityValueUnknown = -1;   /* NULL */
static int hf_h460_4_numberingPlan = -1;          /* T_numberingPlan */
static int hf_h460_4_x121 = -1;                   /* T_x121 */
static int hf_h460_4_x121CountryCode = -1;        /* X121CountryCode */
static int hf_h460_4_e164 = -1;                   /* T_e164 */
static int hf_h460_4_e164CountryCode = -1;        /* E164CountryCode */
static int hf_h460_4_identificationCode = -1;     /* T_identificationCode */

/* --- Modules QOS-MONITORING-REPORT QOS-MONITORING-EXTENDED-VOIP-REPORT --- --- --- */

static int hf_h460_9_h460_9_QosMonitoringReportData_PDU = -1;  /* QosMonitoringReportData */
static int hf_h460_9_h460_9_ExtendedRTPMetrics_PDU = -1;  /* ExtendedRTPMetrics */
static int hf_h460_9_extensionId = -1;            /* GenericIdentifier */
static int hf_h460_9_extensionContent = -1;       /* OCTET_STRING */
static int hf_h460_9_rtpAddress = -1;             /* TransportChannelInfo */
static int hf_h460_9_rtcpAddress = -1;            /* TransportChannelInfo */
static int hf_h460_9_sessionId = -1;              /* INTEGER_1_255 */
static int hf_h460_9_nonStandardData = -1;        /* NonStandardParameter */
static int hf_h460_9_mediaSenderMeasures = -1;    /* T_mediaSenderMeasures */
static int hf_h460_9_worstEstimatedEnd2EndDelay = -1;  /* EstimatedEnd2EndDelay */
static int hf_h460_9_meanEstimatedEnd2EndDelay = -1;  /* EstimatedEnd2EndDelay */
static int hf_h460_9_mediaReceiverMeasures = -1;  /* T_mediaReceiverMeasures */
static int hf_h460_9_cumulativeNumberOfPacketsLost = -1;  /* INTEGER_0_4294967295 */
static int hf_h460_9_packetLostRate = -1;         /* INTEGER_0_65535 */
static int hf_h460_9_worstJitter = -1;            /* CalculatedJitter */
static int hf_h460_9_estimatedThroughput = -1;    /* BandWidth */
static int hf_h460_9_fractionLostRate = -1;       /* INTEGER_0_65535 */
static int hf_h460_9_meanJitter = -1;             /* CalculatedJitter */
static int hf_h460_9_extensions = -1;             /* SEQUENCE_OF_Extension */
static int hf_h460_9_extensions_item = -1;        /* Extension */
static int hf_h460_9_callReferenceValue = -1;     /* CallReferenceValue */
static int hf_h460_9_conferenceID = -1;           /* ConferenceIdentifier */
static int hf_h460_9_callIdentifier = -1;         /* CallIdentifier */
static int hf_h460_9_mediaChannelsQoS = -1;       /* SEQUENCE_OF_RTCPMeasures */
static int hf_h460_9_mediaChannelsQoS_item = -1;  /* RTCPMeasures */
static int hf_h460_9_periodic = -1;               /* PeriodicQoSMonReport */
static int hf_h460_9_final = -1;                  /* FinalQosMonReport */
static int hf_h460_9_interGK = -1;                /* InterGKQosMonReport */
static int hf_h460_9_perCallInfo = -1;            /* SEQUENCE_OF_PerCallQoSReport */
static int hf_h460_9_perCallInfo_item = -1;       /* PerCallQoSReport */
static int hf_h460_9_mediaInfo = -1;              /* SEQUENCE_OF_RTCPMeasures */
static int hf_h460_9_mediaInfo_item = -1;         /* RTCPMeasures */
static int hf_h460_9_networkPacketLossRate = -1;  /* INTEGER_0_255 */
static int hf_h460_9_jitterBufferDiscardRate = -1;  /* INTEGER_0_255 */
static int hf_h460_9_burstMetrics = -1;           /* BurstMetrics */
static int hf_h460_9_rtcpRoundTripDelay = -1;     /* INTEGER_0_65535 */
static int hf_h460_9_endSystemDelay = -1;         /* INTEGER_0_65535 */
static int hf_h460_9_signalLevel = -1;            /* INTEGER_M127_10 */
static int hf_h460_9_noiseLevel = -1;             /* INTEGER_M127_0 */
static int hf_h460_9_residualEchoReturnLoss = -1;  /* INTEGER_0_127 */
static int hf_h460_9_rFactor = -1;                /* INTEGER_0_100 */
static int hf_h460_9_extRFactor = -1;             /* INTEGER_0_100 */
static int hf_h460_9_estimatedMOSLQ = -1;         /* INTEGER_10_50 */
static int hf_h460_9_estimatedMOSCQ = -1;         /* INTEGER_10_50 */
static int hf_h460_9_plcType = -1;                /* PLCtypes */
static int hf_h460_9_jitterBufferParms = -1;      /* JitterBufferParms */
static int hf_h460_9_gmin = -1;                   /* INTEGER_0_255 */
static int hf_h460_9_burstLossDensity = -1;       /* INTEGER_0_255 */
static int hf_h460_9_gapLossDensity = -1;         /* INTEGER_0_255 */
static int hf_h460_9_burstDuration = -1;          /* INTEGER_0_65535 */
static int hf_h460_9_gapDuration = -1;            /* INTEGER_0_65535 */
static int hf_h460_9_unspecified = -1;            /* NULL */
static int hf_h460_9_disabled = -1;               /* NULL */
static int hf_h460_9_enhanced = -1;               /* NULL */
static int hf_h460_9_standard = -1;               /* NULL */
static int hf_h460_9_jitterBufferType = -1;       /* JitterBufferTypes */
static int hf_h460_9_jitterBufferAdaptRate = -1;  /* INTEGER_0_15 */
static int hf_h460_9_jitterBufferNominalSize = -1;  /* INTEGER_0_65535 */
static int hf_h460_9_jitterBufferMaxSize = -1;    /* INTEGER_0_65535 */
static int hf_h460_9_jitterBufferAbsoluteMax = -1;  /* INTEGER_0_65535 */
static int hf_h460_9_unknown = -1;                /* NULL */
static int hf_h460_9_reserved = -1;               /* NULL */
static int hf_h460_9_nonadaptive = -1;            /* NULL */
static int hf_h460_9_adaptive = -1;               /* NULL */

/* --- Module CALL-PARTY-CATEGORY --- --- ---                                 */

static int hf_h460_10_h460_10_CallPartyCategoryInfo_PDU = -1;  /* CallPartyCategoryInfo */
static int hf_h460_10_callPartyCategory = -1;     /* CallPartyCategory */
static int hf_h460_10_originatingLineInfo = -1;   /* OriginatingLineInfo */

/* --- Module MLPP --- --- ---                                                */

static int hf_h460_14_h460_14_MLPPInfo_PDU = -1;  /* MLPPInfo */
static int hf_h460_14_precedence = -1;            /* MlppPrecedence */
static int hf_h460_14_mlppReason = -1;            /* MlppReason */
static int hf_h460_14_mlppNotification = -1;      /* MlppNotification */
static int hf_h460_14_alternateParty = -1;        /* AlternateParty */
static int hf_h460_14_releaseCall = -1;           /* ReleaseCall */
static int hf_h460_14_preemptionPending = -1;     /* NULL */
static int hf_h460_14_preemptionInProgress = -1;  /* NULL */
static int hf_h460_14_preemptionEnd = -1;         /* NULL */
static int hf_h460_14_preemptionComplete = -1;    /* NULL */
static int hf_h460_14_altID = -1;                 /* AliasAddress */
static int hf_h460_14_altTimer = -1;              /* INTEGER_0_255 */
static int hf_h460_14_preemptCallID = -1;         /* CallIdentifier */
static int hf_h460_14_releaseReason = -1;         /* MlppReason */
static int hf_h460_14_releaseDelay = -1;          /* INTEGER_0_255 */

/* --- Module SIGNALLING-CHANNEL-SUSPEND-REDIRECT --- --- ---                 */

static int hf_h460_15_h460_15_SignallingChannelData_PDU = -1;  /* SignallingChannelData */
static int hf_h460_15_signallingChannelData = -1;  /* T_signallingChannelData */
static int hf_h460_15_channelSuspendRequest = -1;  /* ChannelSuspendRequest */
static int hf_h460_15_channelSuspendResponse = -1;  /* ChannelSuspendResponse */
static int hf_h460_15_channelSuspendConfirm = -1;  /* ChannelSuspendConfirm */
static int hf_h460_15_channelSuspendCancel = -1;  /* ChannelSuspendCancel */
static int hf_h460_15_channelResumeRequest = -1;  /* ChannelResumeRequest */
static int hf_h460_15_channelResumeResponse = -1;  /* ChannelResumeResponse */
static int hf_h460_15_channelResumeAddress = -1;  /* SEQUENCE_OF_TransportAddress */
static int hf_h460_15_channelResumeAddress_item = -1;  /* TransportAddress */
static int hf_h460_15_immediateResume = -1;       /* BOOLEAN */
static int hf_h460_15_resetH245 = -1;             /* NULL */
static int hf_h460_15_okToSuspend = -1;           /* BOOLEAN */
static int hf_h460_15_randomNumber = -1;          /* INTEGER_0_4294967295 */

/* --- Module SIGNALLING-TRAVERSAL --- --- ---                                */

static int hf_h460_18_h460_18_IncomingCallIndication_PDU = -1;  /* IncomingCallIndication */
static int hf_h460_18_h460_18_LRQKeepAliveData_PDU = -1;  /* LRQKeepAliveData */
static int hf_h460_18_callSignallingAddress = -1;  /* TransportAddress */
static int hf_h460_18_callID = -1;                /* CallIdentifier */
static int hf_h460_18_lrqKeepAliveInterval = -1;  /* TimeToLive */

/* --- Module MEDIA-TRAVERSAL --- --- ---                                     */

static int hf_h460_19_h460_19_TraversalParameters_PDU = -1;  /* TraversalParameters */
static int hf_h460_19_multiplexedMediaChannel = -1;  /* TransportAddress */
static int hf_h460_19_multiplexedMediaControlChannel = -1;  /* TransportAddress */
static int hf_h460_19_multiplexID = -1;           /* INTEGER_0_4294967295 */
static int hf_h460_19_keepAliveChannel = -1;      /* TransportAddress */
static int hf_h460_19_keepAlivePayloadType = -1;  /* INTEGER_0_127 */
static int hf_h460_19_keepAliveInterval = -1;     /* TimeToLive */

/* --- Module MESSAGE-BROADCAST --- --- ---                                   */

static int hf_h460_21_h460_21_CapabilityAdvertisement_PDU = -1;  /* CapabilityAdvertisement */
static int hf_h460_21_receiveCapabilities = -1;   /* ReceiveCapabilities */
static int hf_h460_21_transmitCapabilities = -1;  /* SEQUENCE_SIZE_1_256_OF_TransmitCapabilities */
static int hf_h460_21_transmitCapabilities_item = -1;  /* TransmitCapabilities */
static int hf_h460_21_capabilities = -1;          /* SEQUENCE_SIZE_1_256_OF_Capability */
static int hf_h460_21_capabilities_item = -1;     /* Capability */
static int hf_h460_21_maxGroups = -1;             /* INTEGER_1_65535 */
static int hf_h460_21_groupIdentifer = -1;        /* GloballyUniqueID */
static int hf_h460_21_capability = -1;            /* Capability */
static int hf_h460_21_sourceAddress = -1;         /* UnicastAddress */

/*--- End of included file: packet-h460-hf.c ---*/
#line 49 "../../asn1/h460/packet-h460-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-h460-ett.c ---*/
#line 1 "../../asn1/h460/packet-h460-ett.c"

/* --- Module NUMBER-PORTABILITY --- --- ---                                  */

static gint ett_h460_2_NumberPortabilityInfo = -1;
static gint ett_h460_2_T_nUMBERPORTABILITYDATA = -1;
static gint ett_h460_2_NumberPortabilityRejectReason = -1;
static gint ett_h460_2_PortabilityAddress = -1;
static gint ett_h460_2_NumberPortabilityTypeOfNumber = -1;
static gint ett_h460_2_PortabilityTypeOfNumber = -1;
static gint ett_h460_2_RegionalParameters = -1;

/* --- Module CIRCUIT-STATUS-MAP --- --- ---                                  */

static gint ett_h460_3_CircuitStatus = -1;
static gint ett_h460_3_SEQUENCE_OF_CircuitStatusMap = -1;
static gint ett_h460_3_CircuitStatusMap = -1;
static gint ett_h460_3_CircuitStatusType = -1;

/* --- Module CALL-PRIORITY --- --- ---                                       */

static gint ett_h460_4_CallPriorityInfo = -1;
static gint ett_h460_4_T_priorityValue = -1;
static gint ett_h460_4_SEQUENCE_OF_ClearToken = -1;
static gint ett_h460_4_SEQUENCE_OF_CryptoToken = -1;
static gint ett_h460_4_T_rejectReason = -1;
static gint ett_h460_4_CountryInternationalNetworkCallOriginationIdentification = -1;
static gint ett_h460_4_T_numberingPlan = -1;
static gint ett_h460_4_T_x121 = -1;
static gint ett_h460_4_T_e164 = -1;

/* --- Modules QOS-MONITORING-REPORT QOS-MONITORING-EXTENDED-VOIP-REPORT --- --- --- */

static gint ett_h460_9_Extension = -1;
static gint ett_h460_9_RTCPMeasures = -1;
static gint ett_h460_9_T_mediaSenderMeasures = -1;
static gint ett_h460_9_T_mediaReceiverMeasures = -1;
static gint ett_h460_9_SEQUENCE_OF_Extension = -1;
static gint ett_h460_9_PerCallQoSReport = -1;
static gint ett_h460_9_SEQUENCE_OF_RTCPMeasures = -1;
static gint ett_h460_9_QosMonitoringReportData = -1;
static gint ett_h460_9_PeriodicQoSMonReport = -1;
static gint ett_h460_9_SEQUENCE_OF_PerCallQoSReport = -1;
static gint ett_h460_9_FinalQosMonReport = -1;
static gint ett_h460_9_InterGKQosMonReport = -1;
static gint ett_h460_9_ExtendedRTPMetrics = -1;
static gint ett_h460_9_BurstMetrics = -1;
static gint ett_h460_9_PLCtypes = -1;
static gint ett_h460_9_JitterBufferParms = -1;
static gint ett_h460_9_JitterBufferTypes = -1;

/* --- Module CALL-PARTY-CATEGORY --- --- ---                                 */

static gint ett_h460_10_CallPartyCategoryInfo = -1;

/* --- Module MLPP --- --- ---                                                */

static gint ett_h460_14_MLPPInfo = -1;
static gint ett_h460_14_MlppNotification = -1;
static gint ett_h460_14_AlternateParty = -1;
static gint ett_h460_14_ReleaseCall = -1;

/* --- Module SIGNALLING-CHANNEL-SUSPEND-REDIRECT --- --- ---                 */

static gint ett_h460_15_SignallingChannelData = -1;
static gint ett_h460_15_T_signallingChannelData = -1;
static gint ett_h460_15_ChannelSuspendRequest = -1;
static gint ett_h460_15_SEQUENCE_OF_TransportAddress = -1;
static gint ett_h460_15_ChannelSuspendResponse = -1;
static gint ett_h460_15_ChannelSuspendConfirm = -1;
static gint ett_h460_15_ChannelSuspendCancel = -1;
static gint ett_h460_15_ChannelResumeRequest = -1;
static gint ett_h460_15_ChannelResumeResponse = -1;

/* --- Module SIGNALLING-TRAVERSAL --- --- ---                                */

static gint ett_h460_18_IncomingCallIndication = -1;
static gint ett_h460_18_LRQKeepAliveData = -1;

/* --- Module MEDIA-TRAVERSAL --- --- ---                                     */

static gint ett_h460_19_TraversalParameters = -1;

/* --- Module MESSAGE-BROADCAST --- --- ---                                   */

static gint ett_h460_21_CapabilityAdvertisement = -1;
static gint ett_h460_21_SEQUENCE_SIZE_1_256_OF_TransmitCapabilities = -1;
static gint ett_h460_21_ReceiveCapabilities = -1;
static gint ett_h460_21_SEQUENCE_SIZE_1_256_OF_Capability = -1;
static gint ett_h460_21_TransmitCapabilities = -1;

/*--- End of included file: packet-h460-ett.c ---*/
#line 52 "../../asn1/h460/packet-h460-template.c"

/* Subdissectors */
static dissector_handle_t q931_ie_handle = NULL; 
static dissector_handle_t h225_ras_handle = NULL; 


/*--- Included file: packet-h460-fn.c ---*/
#line 1 "../../asn1/h460/packet-h460-fn.c"

/* --- Module NUMBER-PORTABILITY --- --- ---                                  */



static int
dissect_h460_2_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h460_2_NumberPortabilityRejectReason_vals[] = {
  {   0, "unspecified" },
  {   1, "qorPortedNumber" },
  { 0, NULL }
};

static const per_choice_t h460_2_NumberPortabilityRejectReason_choice[] = {
  {   0, &hf_h460_2_unspecified  , ASN1_EXTENSION_ROOT    , dissect_h460_2_NULL },
  {   1, &hf_h460_2_qorPortedNumber, ASN1_EXTENSION_ROOT    , dissect_h460_2_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_2_NumberPortabilityRejectReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_2_NumberPortabilityRejectReason, h460_2_NumberPortabilityRejectReason_choice,
                                 NULL);

  return offset;
}


static const value_string h460_2_PortabilityTypeOfNumber_vals[] = {
  {   0, "portedNumber" },
  {   1, "routingNumber" },
  {   2, "concatenatedNumber" },
  { 0, NULL }
};

static const per_choice_t h460_2_PortabilityTypeOfNumber_choice[] = {
  {   0, &hf_h460_2_portedNumber , ASN1_EXTENSION_ROOT    , dissect_h460_2_NULL },
  {   1, &hf_h460_2_routingNumber, ASN1_EXTENSION_ROOT    , dissect_h460_2_NULL },
  {   2, &hf_h460_2_concatenatedNumber, ASN1_EXTENSION_ROOT    , dissect_h460_2_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_2_PortabilityTypeOfNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_2_PortabilityTypeOfNumber, h460_2_PortabilityTypeOfNumber_choice,
                                 NULL);

  return offset;
}


static const value_string h460_2_NumberPortabilityTypeOfNumber_vals[] = {
  {   0, "publicTypeOfNumber" },
  {   1, "privateTypeOfNumber" },
  {   2, "portabilityTypeOfNumber" },
  { 0, NULL }
};

static const per_choice_t h460_2_NumberPortabilityTypeOfNumber_choice[] = {
  {   0, &hf_h460_2_publicTypeOfNumber, ASN1_EXTENSION_ROOT    , dissect_h225_PublicTypeOfNumber },
  {   1, &hf_h460_2_privateTypeOfNumber, ASN1_EXTENSION_ROOT    , dissect_h225_PrivateTypeOfNumber },
  {   2, &hf_h460_2_portabilityTypeOfNumber, ASN1_EXTENSION_ROOT    , dissect_h460_2_PortabilityTypeOfNumber },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_2_NumberPortabilityTypeOfNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_2_NumberPortabilityTypeOfNumber, h460_2_NumberPortabilityTypeOfNumber_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h460_2_PortabilityAddress_sequence[] = {
  { &hf_h460_2_aliasAddress , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_AliasAddress },
  { &hf_h460_2_typeOfAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_2_NumberPortabilityTypeOfNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_2_PortabilityAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_2_PortabilityAddress, h460_2_PortabilityAddress_sequence);

  return offset;
}



static int
dissect_h460_2_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_2_INTEGER_1_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_2_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t h460_2_RegionalParameters_sequence[] = {
  { &hf_h460_2_t35CountryCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_2_INTEGER_0_255 },
  { &hf_h460_2_t35Extension , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_2_INTEGER_0_255 },
  { &hf_h460_2_variantIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_2_INTEGER_1_255 },
  { &hf_h460_2_regionalData , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_2_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_2_RegionalParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_2_RegionalParameters, h460_2_RegionalParameters_sequence);

  return offset;
}


static const per_sequence_t h460_2_T_nUMBERPORTABILITYDATA_sequence[] = {
  { &hf_h460_2_addressTranslated, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_2_NULL },
  { &hf_h460_2_portedAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_2_PortabilityAddress },
  { &hf_h460_2_routingAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_2_PortabilityAddress },
  { &hf_h460_2_regionalParams, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_2_RegionalParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_2_T_nUMBERPORTABILITYDATA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_2_T_nUMBERPORTABILITYDATA, h460_2_T_nUMBERPORTABILITYDATA_sequence);

  return offset;
}


static const value_string h460_2_NumberPortabilityInfo_vals[] = {
  {   0, "numberPortabilityRejectReason" },
  {   1, "nUMBERPORTABILITYDATA" },
  { 0, NULL }
};

static const per_choice_t h460_2_NumberPortabilityInfo_choice[] = {
  {   0, &hf_h460_2_numberPortabilityRejectReason, ASN1_EXTENSION_ROOT    , dissect_h460_2_NumberPortabilityRejectReason },
  {   1, &hf_h460_2_nUMBERPORTABILITYDATA, ASN1_EXTENSION_ROOT    , dissect_h460_2_T_nUMBERPORTABILITYDATA },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_2_NumberPortabilityInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_2_NumberPortabilityInfo, h460_2_NumberPortabilityInfo_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h460_2_NumberPortabilityInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_2_NumberPortabilityInfo(tvb, offset, &asn1_ctx, tree, hf_h460_2_h460_2_NumberPortabilityInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module CIRCUIT-STATUS-MAP --- --- ---                                  */



static int
dissect_h460_3_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h460_3_CircuitStatusType_vals[] = {
  {   0, "serviceStatus" },
  {   1, "busyStatus" },
  { 0, NULL }
};

static const per_choice_t h460_3_CircuitStatusType_choice[] = {
  {   0, &hf_h460_3_serviceStatus, ASN1_EXTENSION_ROOT    , dissect_h460_3_NULL },
  {   1, &hf_h460_3_busyStatus   , ASN1_EXTENSION_ROOT    , dissect_h460_3_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_3_CircuitStatusType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_3_CircuitStatusType, h460_3_CircuitStatusType_choice,
                                 NULL);

  return offset;
}



static int
dissect_h460_3_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_3_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t h460_3_CircuitStatusMap_sequence[] = {
  { &hf_h460_3_statusType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_3_CircuitStatusType },
  { &hf_h460_3_baseCircuitID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CircuitIdentifier },
  { &hf_h460_3_range        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_3_INTEGER_0_4095 },
  { &hf_h460_3_status       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_3_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_3_CircuitStatusMap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_3_CircuitStatusMap, h460_3_CircuitStatusMap_sequence);

  return offset;
}


static const per_sequence_t h460_3_SEQUENCE_OF_CircuitStatusMap_sequence_of[1] = {
  { &hf_h460_3_circuitStatusMap_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h460_3_CircuitStatusMap },
};

static int
dissect_h460_3_SEQUENCE_OF_CircuitStatusMap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h460_3_SEQUENCE_OF_CircuitStatusMap, h460_3_SEQUENCE_OF_CircuitStatusMap_sequence_of);

  return offset;
}


static const per_sequence_t h460_3_CircuitStatus_sequence[] = {
  { &hf_h460_3_circuitStatusMap, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_3_SEQUENCE_OF_CircuitStatusMap },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_3_CircuitStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_3_CircuitStatus, h460_3_CircuitStatus_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h460_3_CircuitStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_3_CircuitStatus(tvb, offset, &asn1_ctx, tree, hf_h460_3_h460_3_CircuitStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module CALL-PRIORITY --- --- ---                                       */



static int
dissect_h460_4_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h460_4_T_priorityValue_vals[] = {
  {   0, "emergencyAuthorized" },
  {   1, "emergencyPublic" },
  {   2, "high" },
  {   3, "normal" },
  { 0, NULL }
};

static const per_choice_t h460_4_T_priorityValue_choice[] = {
  {   0, &hf_h460_4_emergencyAuthorized, ASN1_EXTENSION_ROOT    , dissect_h460_4_NULL },
  {   1, &hf_h460_4_emergencyPublic, ASN1_EXTENSION_ROOT    , dissect_h460_4_NULL },
  {   2, &hf_h460_4_high         , ASN1_EXTENSION_ROOT    , dissect_h460_4_NULL },
  {   3, &hf_h460_4_normal       , ASN1_EXTENSION_ROOT    , dissect_h460_4_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_4_T_priorityValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_4_T_priorityValue, h460_4_T_priorityValue_choice,
                                 NULL);

  return offset;
}



static int
dissect_h460_4_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h460_4_SEQUENCE_OF_ClearToken_sequence_of[1] = {
  { &hf_h460_4_tokens_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_ClearToken },
};

static int
dissect_h460_4_SEQUENCE_OF_ClearToken(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h460_4_SEQUENCE_OF_ClearToken, h460_4_SEQUENCE_OF_ClearToken_sequence_of);

  return offset;
}


static const per_sequence_t h460_4_SEQUENCE_OF_CryptoToken_sequence_of[1] = {
  { &hf_h460_4_cryptoTokens_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_CryptoToken },
};

static int
dissect_h460_4_SEQUENCE_OF_CryptoToken(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h460_4_SEQUENCE_OF_CryptoToken, h460_4_SEQUENCE_OF_CryptoToken_sequence_of);

  return offset;
}


static const value_string h460_4_T_rejectReason_vals[] = {
  {   0, "priorityUnavailable" },
  {   1, "priorityUnauthorized" },
  {   2, "priorityValueUnknown" },
  { 0, NULL }
};

static const per_choice_t h460_4_T_rejectReason_choice[] = {
  {   0, &hf_h460_4_priorityUnavailable, ASN1_EXTENSION_ROOT    , dissect_h460_4_NULL },
  {   1, &hf_h460_4_priorityUnauthorized, ASN1_EXTENSION_ROOT    , dissect_h460_4_NULL },
  {   2, &hf_h460_4_priorityValueUnknown, ASN1_EXTENSION_ROOT    , dissect_h460_4_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_4_T_rejectReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_4_T_rejectReason, h460_4_T_rejectReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h460_4_CallPriorityInfo_sequence[] = {
  { &hf_h460_4_priorityValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_4_T_priorityValue },
  { &hf_h460_4_priorityExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_4_INTEGER_0_255 },
  { &hf_h460_4_tokens       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_4_SEQUENCE_OF_ClearToken },
  { &hf_h460_4_cryptoTokens , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_4_SEQUENCE_OF_CryptoToken },
  { &hf_h460_4_rejectReason , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_4_T_rejectReason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_4_CallPriorityInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_4_CallPriorityInfo, h460_4_CallPriorityInfo_sequence);

  return offset;
}



static int
dissect_h460_4_X121CountryCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      3, 3, FALSE, "0123456789", 10,
                                                      NULL);

  return offset;
}


static const per_sequence_t h460_4_T_x121_sequence[] = {
  { &hf_h460_4_x121CountryCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_4_X121CountryCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_4_T_x121(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_4_T_x121, h460_4_T_x121_sequence);

  return offset;
}



static int
dissect_h460_4_E164CountryCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      3, 3, FALSE, "0123456789", 10,
                                                      NULL);

  return offset;
}



static int
dissect_h460_4_T_identificationCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 4, FALSE, "0123456789", 10,
                                                      NULL);

  return offset;
}


static const per_sequence_t h460_4_T_e164_sequence[] = {
  { &hf_h460_4_e164CountryCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_4_E164CountryCode },
  { &hf_h460_4_identificationCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_4_T_identificationCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_4_T_e164(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_4_T_e164, h460_4_T_e164_sequence);

  return offset;
}


static const value_string h460_4_T_numberingPlan_vals[] = {
  {   0, "x121" },
  {   1, "e164" },
  { 0, NULL }
};

static const per_choice_t h460_4_T_numberingPlan_choice[] = {
  {   0, &hf_h460_4_x121         , ASN1_EXTENSION_ROOT    , dissect_h460_4_T_x121 },
  {   1, &hf_h460_4_e164         , ASN1_EXTENSION_ROOT    , dissect_h460_4_T_e164 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_4_T_numberingPlan(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_4_T_numberingPlan, h460_4_T_numberingPlan_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h460_4_CountryInternationalNetworkCallOriginationIdentification_sequence[] = {
  { &hf_h460_4_numberingPlan, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_4_T_numberingPlan },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_4_CountryInternationalNetworkCallOriginationIdentification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_4_CountryInternationalNetworkCallOriginationIdentification, h460_4_CountryInternationalNetworkCallOriginationIdentification_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h460_4_CallPriorityInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_4_CallPriorityInfo(tvb, offset, &asn1_ctx, tree, hf_h460_4_h460_4_CallPriorityInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h460_4_CountryInternationalNetworkCallOriginationIdentification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_4_CountryInternationalNetworkCallOriginationIdentification(tvb, offset, &asn1_ctx, tree, hf_h460_4_h460_4_CountryInternationalNetworkCallOriginationIdentification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Modules QOS-MONITORING-REPORT QOS-MONITORING-EXTENDED-VOIP-REPORT --- --- --- */



static int
dissect_h460_9_EstimatedEnd2EndDelay(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_9_CalculatedJitter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_9_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t h460_9_Extension_sequence[] = {
  { &hf_h460_9_extensionId  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_GenericIdentifier },
  { &hf_h460_9_extensionContent, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_Extension, h460_9_Extension_sequence);

  return offset;
}



static int
dissect_h460_9_INTEGER_1_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h460_9_T_mediaSenderMeasures_sequence[] = {
  { &hf_h460_9_worstEstimatedEnd2EndDelay, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_EstimatedEnd2EndDelay },
  { &hf_h460_9_meanEstimatedEnd2EndDelay, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_EstimatedEnd2EndDelay },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_T_mediaSenderMeasures(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_T_mediaSenderMeasures, h460_9_T_mediaSenderMeasures_sequence);

  return offset;
}



static int
dissect_h460_9_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_9_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h460_9_T_mediaReceiverMeasures_sequence[] = {
  { &hf_h460_9_cumulativeNumberOfPacketsLost, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_4294967295 },
  { &hf_h460_9_packetLostRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_65535 },
  { &hf_h460_9_worstJitter  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_CalculatedJitter },
  { &hf_h460_9_estimatedThroughput, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_BandWidth },
  { &hf_h460_9_fractionLostRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_65535 },
  { &hf_h460_9_meanJitter   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_CalculatedJitter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_T_mediaReceiverMeasures(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_T_mediaReceiverMeasures, h460_9_T_mediaReceiverMeasures_sequence);

  return offset;
}


static const per_sequence_t h460_9_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_h460_9_extensions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h460_9_Extension },
};

static int
dissect_h460_9_SEQUENCE_OF_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h460_9_SEQUENCE_OF_Extension, h460_9_SEQUENCE_OF_Extension_sequence_of);

  return offset;
}


static const per_sequence_t h460_9_RTCPMeasures_sequence[] = {
  { &hf_h460_9_rtpAddress   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_TransportChannelInfo },
  { &hf_h460_9_rtcpAddress  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_TransportChannelInfo },
  { &hf_h460_9_sessionId    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_9_INTEGER_1_255 },
  { &hf_h460_9_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_NonStandardParameter },
  { &hf_h460_9_mediaSenderMeasures, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_T_mediaSenderMeasures },
  { &hf_h460_9_mediaReceiverMeasures, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_T_mediaReceiverMeasures },
  { &hf_h460_9_extensions   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_SEQUENCE_OF_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_RTCPMeasures(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_RTCPMeasures, h460_9_RTCPMeasures_sequence);

  return offset;
}


static const per_sequence_t h460_9_SEQUENCE_OF_RTCPMeasures_sequence_of[1] = {
  { &hf_h460_9_mediaChannelsQoS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h460_9_RTCPMeasures },
};

static int
dissect_h460_9_SEQUENCE_OF_RTCPMeasures(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h460_9_SEQUENCE_OF_RTCPMeasures, h460_9_SEQUENCE_OF_RTCPMeasures_sequence_of);

  return offset;
}


static const per_sequence_t h460_9_PerCallQoSReport_sequence[] = {
  { &hf_h460_9_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_NonStandardParameter },
  { &hf_h460_9_callReferenceValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CallReferenceValue },
  { &hf_h460_9_conferenceID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_ConferenceIdentifier },
  { &hf_h460_9_callIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CallIdentifier },
  { &hf_h460_9_mediaChannelsQoS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_SEQUENCE_OF_RTCPMeasures },
  { &hf_h460_9_extensions   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_SEQUENCE_OF_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_PerCallQoSReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_PerCallQoSReport, h460_9_PerCallQoSReport_sequence);

  return offset;
}


static const per_sequence_t h460_9_SEQUENCE_OF_PerCallQoSReport_sequence_of[1] = {
  { &hf_h460_9_perCallInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h460_9_PerCallQoSReport },
};

static int
dissect_h460_9_SEQUENCE_OF_PerCallQoSReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h460_9_SEQUENCE_OF_PerCallQoSReport, h460_9_SEQUENCE_OF_PerCallQoSReport_sequence_of);

  return offset;
}


static const per_sequence_t h460_9_PeriodicQoSMonReport_sequence[] = {
  { &hf_h460_9_perCallInfo  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_9_SEQUENCE_OF_PerCallQoSReport },
  { &hf_h460_9_extensions   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_SEQUENCE_OF_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_PeriodicQoSMonReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_PeriodicQoSMonReport, h460_9_PeriodicQoSMonReport_sequence);

  return offset;
}


static const per_sequence_t h460_9_FinalQosMonReport_sequence[] = {
  { &hf_h460_9_mediaInfo    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_9_SEQUENCE_OF_RTCPMeasures },
  { &hf_h460_9_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_NonStandardParameter },
  { &hf_h460_9_extensions   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_SEQUENCE_OF_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_FinalQosMonReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_FinalQosMonReport, h460_9_FinalQosMonReport_sequence);

  return offset;
}


static const per_sequence_t h460_9_InterGKQosMonReport_sequence[] = {
  { &hf_h460_9_mediaInfo    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_9_SEQUENCE_OF_RTCPMeasures },
  { &hf_h460_9_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_NonStandardParameter },
  { &hf_h460_9_extensions   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_SEQUENCE_OF_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_InterGKQosMonReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_InterGKQosMonReport, h460_9_InterGKQosMonReport_sequence);

  return offset;
}


static const value_string h460_9_QosMonitoringReportData_vals[] = {
  {   0, "periodic" },
  {   1, "final" },
  {   2, "interGK" },
  { 0, NULL }
};

static const per_choice_t h460_9_QosMonitoringReportData_choice[] = {
  {   0, &hf_h460_9_periodic     , ASN1_EXTENSION_ROOT    , dissect_h460_9_PeriodicQoSMonReport },
  {   1, &hf_h460_9_final        , ASN1_EXTENSION_ROOT    , dissect_h460_9_FinalQosMonReport },
  {   2, &hf_h460_9_interGK      , ASN1_EXTENSION_ROOT    , dissect_h460_9_InterGKQosMonReport },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_9_QosMonitoringReportData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_9_QosMonitoringReportData, h460_9_QosMonitoringReportData_choice,
                                 NULL);

  return offset;
}



static int
dissect_h460_9_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h460_9_BurstMetrics_sequence[] = {
  { &hf_h460_9_gmin         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_255 },
  { &hf_h460_9_burstLossDensity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_255 },
  { &hf_h460_9_gapLossDensity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_255 },
  { &hf_h460_9_burstDuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_65535 },
  { &hf_h460_9_gapDuration  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_BurstMetrics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_BurstMetrics, h460_9_BurstMetrics_sequence);

  return offset;
}



static int
dissect_h460_9_INTEGER_M127_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 10U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_9_INTEGER_M127_0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 0U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_9_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_9_INTEGER_0_100(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_9_INTEGER_10_50(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            10U, 50U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_9_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h460_9_PLCtypes_vals[] = {
  {   0, "unspecified" },
  {   1, "disabled" },
  {   2, "enhanced" },
  {   3, "standard" },
  { 0, NULL }
};

static const per_choice_t h460_9_PLCtypes_choice[] = {
  {   0, &hf_h460_9_unspecified  , ASN1_EXTENSION_ROOT    , dissect_h460_9_NULL },
  {   1, &hf_h460_9_disabled     , ASN1_EXTENSION_ROOT    , dissect_h460_9_NULL },
  {   2, &hf_h460_9_enhanced     , ASN1_EXTENSION_ROOT    , dissect_h460_9_NULL },
  {   3, &hf_h460_9_standard     , ASN1_EXTENSION_ROOT    , dissect_h460_9_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_9_PLCtypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_9_PLCtypes, h460_9_PLCtypes_choice,
                                 NULL);

  return offset;
}


static const value_string h460_9_JitterBufferTypes_vals[] = {
  {   0, "unknown" },
  {   1, "reserved" },
  {   2, "nonadaptive" },
  {   3, "adaptive" },
  { 0, NULL }
};

static const per_choice_t h460_9_JitterBufferTypes_choice[] = {
  {   0, &hf_h460_9_unknown      , ASN1_EXTENSION_ROOT    , dissect_h460_9_NULL },
  {   1, &hf_h460_9_reserved     , ASN1_EXTENSION_ROOT    , dissect_h460_9_NULL },
  {   2, &hf_h460_9_nonadaptive  , ASN1_EXTENSION_ROOT    , dissect_h460_9_NULL },
  {   3, &hf_h460_9_adaptive     , ASN1_EXTENSION_ROOT    , dissect_h460_9_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_9_JitterBufferTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_9_JitterBufferTypes, h460_9_JitterBufferTypes_choice,
                                 NULL);

  return offset;
}



static int
dissect_h460_9_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h460_9_JitterBufferParms_sequence[] = {
  { &hf_h460_9_jitterBufferType, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_JitterBufferTypes },
  { &hf_h460_9_jitterBufferAdaptRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_15 },
  { &hf_h460_9_jitterBufferNominalSize, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_65535 },
  { &hf_h460_9_jitterBufferMaxSize, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_65535 },
  { &hf_h460_9_jitterBufferAbsoluteMax, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_JitterBufferParms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_JitterBufferParms, h460_9_JitterBufferParms_sequence);

  return offset;
}


static const per_sequence_t h460_9_ExtendedRTPMetrics_sequence[] = {
  { &hf_h460_9_networkPacketLossRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_255 },
  { &hf_h460_9_jitterBufferDiscardRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_255 },
  { &hf_h460_9_burstMetrics , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_BurstMetrics },
  { &hf_h460_9_rtcpRoundTripDelay, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_65535 },
  { &hf_h460_9_endSystemDelay, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_65535 },
  { &hf_h460_9_signalLevel  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_M127_10 },
  { &hf_h460_9_noiseLevel   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_M127_0 },
  { &hf_h460_9_residualEchoReturnLoss, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_127 },
  { &hf_h460_9_rFactor      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_100 },
  { &hf_h460_9_extRFactor   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_0_100 },
  { &hf_h460_9_estimatedMOSLQ, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_10_50 },
  { &hf_h460_9_estimatedMOSCQ, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_INTEGER_10_50 },
  { &hf_h460_9_plcType      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_PLCtypes },
  { &hf_h460_9_jitterBufferParms, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_9_JitterBufferParms },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_9_ExtendedRTPMetrics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_9_ExtendedRTPMetrics, h460_9_ExtendedRTPMetrics_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h460_9_QosMonitoringReportData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_9_QosMonitoringReportData(tvb, offset, &asn1_ctx, tree, hf_h460_9_h460_9_QosMonitoringReportData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h460_9_ExtendedRTPMetrics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_9_ExtendedRTPMetrics(tvb, offset, &asn1_ctx, tree, hf_h460_9_h460_9_ExtendedRTPMetrics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module CALL-PARTY-CATEGORY --- --- ---                                 */



static int
dissect_h460_10_CallPartyCategory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_10_OriginatingLineInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h460_10_CallPartyCategoryInfo_sequence[] = {
  { &hf_h460_10_callPartyCategory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_10_CallPartyCategory },
  { &hf_h460_10_originatingLineInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_10_OriginatingLineInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_10_CallPartyCategoryInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_10_CallPartyCategoryInfo, h460_10_CallPartyCategoryInfo_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h460_10_CallPartyCategoryInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_10_CallPartyCategoryInfo(tvb, offset, &asn1_ctx, tree, hf_h460_10_h460_10_CallPartyCategoryInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module MLPP --- --- ---                                                */


static const value_string h460_14_MlppPrecedence_vals[] = {
  {   0, "flashOveride" },
  {   1, "flash" },
  {   2, "immediate" },
  {   3, "priority" },
  {   4, "routine" },
  { 0, NULL }
};


static int
dissect_h460_14_MlppPrecedence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string h460_14_MlppReason_vals[] = {
  {   8, "preemptionNoReservation" },
  {   9, "preemptionReservation" },
  {  46, "callBlocked" },
  { 0, NULL }
};

static guint32 h460_14_MlppReason_value_map[3+0] = {8, 9, 46};

static int
dissect_h460_14_MlppReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, h460_14_MlppReason_value_map);

  return offset;
}



static int
dissect_h460_14_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h460_14_MlppNotification_vals[] = {
  {   0, "preemptionPending" },
  {   1, "preemptionInProgress" },
  {   2, "preemptionEnd" },
  {   3, "preemptionComplete" },
  { 0, NULL }
};

static const per_choice_t h460_14_MlppNotification_choice[] = {
  {   0, &hf_h460_14_preemptionPending, ASN1_EXTENSION_ROOT    , dissect_h460_14_NULL },
  {   1, &hf_h460_14_preemptionInProgress, ASN1_EXTENSION_ROOT    , dissect_h460_14_NULL },
  {   2, &hf_h460_14_preemptionEnd, ASN1_EXTENSION_ROOT    , dissect_h460_14_NULL },
  {   3, &hf_h460_14_preemptionComplete, ASN1_EXTENSION_ROOT    , dissect_h460_14_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_14_MlppNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_14_MlppNotification, h460_14_MlppNotification_choice,
                                 NULL);

  return offset;
}



static int
dissect_h460_14_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h460_14_AlternateParty_sequence[] = {
  { &hf_h460_14_altID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_AliasAddress },
  { &hf_h460_14_altTimer    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_14_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_14_AlternateParty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_14_AlternateParty, h460_14_AlternateParty_sequence);

  return offset;
}


static const per_sequence_t h460_14_ReleaseCall_sequence[] = {
  { &hf_h460_14_preemptCallID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CallIdentifier },
  { &hf_h460_14_releaseReason, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_14_MlppReason },
  { &hf_h460_14_releaseDelay, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_14_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_14_ReleaseCall(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_14_ReleaseCall, h460_14_ReleaseCall_sequence);

  return offset;
}


static const per_sequence_t h460_14_MLPPInfo_sequence[] = {
  { &hf_h460_14_precedence  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_14_MlppPrecedence },
  { &hf_h460_14_mlppReason  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_14_MlppReason },
  { &hf_h460_14_mlppNotification, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_14_MlppNotification },
  { &hf_h460_14_alternateParty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_14_AlternateParty },
  { &hf_h460_14_releaseCall , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_14_ReleaseCall },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_14_MLPPInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_14_MLPPInfo, h460_14_MLPPInfo_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h460_14_MLPPInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_14_MLPPInfo(tvb, offset, &asn1_ctx, tree, hf_h460_14_h460_14_MLPPInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module SIGNALLING-CHANNEL-SUSPEND-REDIRECT --- --- ---                 */


static const per_sequence_t h460_15_SEQUENCE_OF_TransportAddress_sequence_of[1] = {
  { &hf_h460_15_channelResumeAddress_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_TransportAddress },
};

static int
dissect_h460_15_SEQUENCE_OF_TransportAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h460_15_SEQUENCE_OF_TransportAddress, h460_15_SEQUENCE_OF_TransportAddress_sequence_of);

  return offset;
}



static int
dissect_h460_15_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_h460_15_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t h460_15_ChannelSuspendRequest_sequence[] = {
  { &hf_h460_15_channelResumeAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_15_SEQUENCE_OF_TransportAddress },
  { &hf_h460_15_immediateResume, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_15_BOOLEAN },
  { &hf_h460_15_resetH245   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_15_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_15_ChannelSuspendRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_15_ChannelSuspendRequest, h460_15_ChannelSuspendRequest_sequence);

  return offset;
}


static const per_sequence_t h460_15_ChannelSuspendResponse_sequence[] = {
  { &hf_h460_15_okToSuspend , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_15_BOOLEAN },
  { &hf_h460_15_channelResumeAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_15_SEQUENCE_OF_TransportAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_15_ChannelSuspendResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_15_ChannelSuspendResponse, h460_15_ChannelSuspendResponse_sequence);

  return offset;
}


static const per_sequence_t h460_15_ChannelSuspendConfirm_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h460_15_ChannelSuspendConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_15_ChannelSuspendConfirm, h460_15_ChannelSuspendConfirm_sequence);

  return offset;
}


static const per_sequence_t h460_15_ChannelSuspendCancel_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h460_15_ChannelSuspendCancel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_15_ChannelSuspendCancel, h460_15_ChannelSuspendCancel_sequence);

  return offset;
}



static int
dissect_h460_15_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h460_15_ChannelResumeRequest_sequence[] = {
  { &hf_h460_15_randomNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_15_INTEGER_0_4294967295 },
  { &hf_h460_15_resetH245   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_15_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_15_ChannelResumeRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_15_ChannelResumeRequest, h460_15_ChannelResumeRequest_sequence);

  return offset;
}


static const per_sequence_t h460_15_ChannelResumeResponse_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h460_15_ChannelResumeResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_15_ChannelResumeResponse, h460_15_ChannelResumeResponse_sequence);

  return offset;
}


static const value_string h460_15_T_signallingChannelData_vals[] = {
  {   0, "channelSuspendRequest" },
  {   1, "channelSuspendResponse" },
  {   2, "channelSuspendConfirm" },
  {   3, "channelSuspendCancel" },
  {   4, "channelResumeRequest" },
  {   5, "channelResumeResponse" },
  { 0, NULL }
};

static const per_choice_t h460_15_T_signallingChannelData_choice[] = {
  {   0, &hf_h460_15_channelSuspendRequest, ASN1_EXTENSION_ROOT    , dissect_h460_15_ChannelSuspendRequest },
  {   1, &hf_h460_15_channelSuspendResponse, ASN1_EXTENSION_ROOT    , dissect_h460_15_ChannelSuspendResponse },
  {   2, &hf_h460_15_channelSuspendConfirm, ASN1_EXTENSION_ROOT    , dissect_h460_15_ChannelSuspendConfirm },
  {   3, &hf_h460_15_channelSuspendCancel, ASN1_EXTENSION_ROOT    , dissect_h460_15_ChannelSuspendCancel },
  {   4, &hf_h460_15_channelResumeRequest, ASN1_EXTENSION_ROOT    , dissect_h460_15_ChannelResumeRequest },
  {   5, &hf_h460_15_channelResumeResponse, ASN1_EXTENSION_ROOT    , dissect_h460_15_ChannelResumeResponse },
  { 0, NULL, 0, NULL }
};

static int
dissect_h460_15_T_signallingChannelData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h460_15_T_signallingChannelData, h460_15_T_signallingChannelData_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h460_15_SignallingChannelData_sequence[] = {
  { &hf_h460_15_signallingChannelData, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_15_T_signallingChannelData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_15_SignallingChannelData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_15_SignallingChannelData, h460_15_SignallingChannelData_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h460_15_SignallingChannelData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_15_SignallingChannelData(tvb, offset, &asn1_ctx, tree, hf_h460_15_h460_15_SignallingChannelData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module SIGNALLING-TRAVERSAL --- --- ---                                */


static const per_sequence_t h460_18_IncomingCallIndication_sequence[] = {
  { &hf_h460_18_callSignallingAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_TransportAddress },
  { &hf_h460_18_callID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CallIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_18_IncomingCallIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_18_IncomingCallIndication, h460_18_IncomingCallIndication_sequence);

  return offset;
}


static const per_sequence_t h460_18_LRQKeepAliveData_sequence[] = {
  { &hf_h460_18_lrqKeepAliveInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_TimeToLive },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_18_LRQKeepAliveData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_18_LRQKeepAliveData, h460_18_LRQKeepAliveData_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h460_18_IncomingCallIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_18_IncomingCallIndication(tvb, offset, &asn1_ctx, tree, hf_h460_18_h460_18_IncomingCallIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h460_18_LRQKeepAliveData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_18_LRQKeepAliveData(tvb, offset, &asn1_ctx, tree, hf_h460_18_h460_18_LRQKeepAliveData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module MEDIA-TRAVERSAL --- --- ---                                     */



static int
dissect_h460_19_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_h460_19_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h460_19_TraversalParameters_sequence[] = {
  { &hf_h460_19_multiplexedMediaChannel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_TransportAddress },
  { &hf_h460_19_multiplexedMediaControlChannel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_TransportAddress },
  { &hf_h460_19_multiplexID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_19_INTEGER_0_4294967295 },
  { &hf_h460_19_keepAliveChannel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_TransportAddress },
  { &hf_h460_19_keepAlivePayloadType, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_19_INTEGER_0_127 },
  { &hf_h460_19_keepAliveInterval, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_TimeToLive },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_19_TraversalParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_19_TraversalParameters, h460_19_TraversalParameters_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h460_19_TraversalParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_19_TraversalParameters(tvb, offset, &asn1_ctx, tree, hf_h460_19_h460_19_TraversalParameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module MESSAGE-BROADCAST --- --- ---                                   */


static const per_sequence_t h460_21_SEQUENCE_SIZE_1_256_OF_Capability_sequence_of[1] = {
  { &hf_h460_21_capabilities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_Capability },
};

static int
dissect_h460_21_SEQUENCE_SIZE_1_256_OF_Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h460_21_SEQUENCE_SIZE_1_256_OF_Capability, h460_21_SEQUENCE_SIZE_1_256_OF_Capability_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}



static int
dissect_h460_21_INTEGER_1_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h460_21_ReceiveCapabilities_sequence[] = {
  { &hf_h460_21_capabilities, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_21_SEQUENCE_SIZE_1_256_OF_Capability },
  { &hf_h460_21_maxGroups   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_21_INTEGER_1_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_21_ReceiveCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_21_ReceiveCapabilities, h460_21_ReceiveCapabilities_sequence);

  return offset;
}



static int
dissect_h460_21_GloballyUniqueID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, FALSE, NULL);

  return offset;
}


static const per_sequence_t h460_21_TransmitCapabilities_sequence[] = {
  { &hf_h460_21_groupIdentifer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h460_21_GloballyUniqueID },
  { &hf_h460_21_capability  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Capability },
  { &hf_h460_21_sourceAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_UnicastAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_21_TransmitCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_21_TransmitCapabilities, h460_21_TransmitCapabilities_sequence);

  return offset;
}


static const per_sequence_t h460_21_SEQUENCE_SIZE_1_256_OF_TransmitCapabilities_sequence_of[1] = {
  { &hf_h460_21_transmitCapabilities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h460_21_TransmitCapabilities },
};

static int
dissect_h460_21_SEQUENCE_SIZE_1_256_OF_TransmitCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h460_21_SEQUENCE_SIZE_1_256_OF_TransmitCapabilities, h460_21_SEQUENCE_SIZE_1_256_OF_TransmitCapabilities_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t h460_21_CapabilityAdvertisement_sequence[] = {
  { &hf_h460_21_receiveCapabilities, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_21_ReceiveCapabilities },
  { &hf_h460_21_transmitCapabilities, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h460_21_SEQUENCE_SIZE_1_256_OF_TransmitCapabilities },
  { NULL, 0, 0, NULL }
};

static int
dissect_h460_21_CapabilityAdvertisement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h460_21_CapabilityAdvertisement, h460_21_CapabilityAdvertisement_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h460_21_CapabilityAdvertisement_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h460_21_CapabilityAdvertisement(tvb, offset, &asn1_ctx, tree, hf_h460_21_h460_21_CapabilityAdvertisement_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-h460-fn.c ---*/
#line 58 "../../asn1/h460/packet-h460-template.c"

static int 
dissect_ies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  int offset = 0;

  if (q931_ie_handle) {
    call_dissector(q931_ie_handle, tvb, pinfo, tree);
    offset += tvb_length_remaining(tvb, offset);
  }
  return offset;
}

static int 
dissect_ras(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  int offset = 0;

  if (h225_ras_handle) {
    call_dissector(h225_ras_handle, tvb, pinfo, tree);
    offset += tvb_length_remaining(tvb, offset);
  }
  return offset;
}

typedef struct _h460_feature_t {
  guint32 opt;
  const gchar *id;
  const gchar *name;
  new_dissector_t content_pdu;
  /*---*/
  const gchar *key_gd;
  const gchar *key_fd;
  const gchar *key_gm;
  const gchar *key_gi;
  dissector_handle_t content_hnd;
} h460_feature_t;

/* Fill in the items after content_pdu */
#define FFILL	NULL, NULL, NULL, NULL, NULL

/* options */
#define GD 0x01  /* present in H.225 GenericData */
#define FD 0x02  /* present in H.225 FeatureDescriptor */
#define GM 0x04  /* present in H.245 GenericMessage */
#define GI 0x08  /* present in H.245 GenericInformation */

static h460_feature_t h460_feature_tab[] = {
  /* H.460.3 */
  { GD|FD,  "2",   "Number Portability", NULL, FFILL },
  { GD|FD,  "2/1", "NumberPortabilityData", dissect_h460_2_NumberPortabilityInfo_PDU, FFILL },
  /* H.460.3 */
  { GD|FD,  "3",   "Circuit Status", NULL, FFILL },
  { GD|FD,  "3/1", "Circuit Status Map", dissect_h460_3_CircuitStatus_PDU, FFILL },
  /* H.460.4 */
  { GD|FD,  "4",   "CallPriorityDesignation", NULL, FFILL },
  { GD|FD,  "4/1", "CallPriorityRequest", dissect_h460_4_CallPriorityInfo_PDU, FFILL },
  { GD|FD,  "4/2", "CallPriorityConfirm", dissect_h460_4_CallPriorityInfo_PDU, FFILL },
  { GD|FD,  "4/3", "Country/InternationalNetworkCallOriginationRequest", dissect_h460_4_CountryInternationalNetworkCallOriginationIdentification_PDU, FFILL },
  { GD|FD,  "4/4", "Country/InternationalNetworkCallOriginationConfirm", dissect_h460_4_CountryInternationalNetworkCallOriginationIdentification_PDU, FFILL },
  /* H.460.5 */
  { GD|FD,  "5",   "DuplicateIEs", NULL, FFILL },
  { GD|FD,  "5/1", "IEsString", dissect_ies, FFILL },
  /* H.460.6 */
  { GD|FD,  "6",   "Extended Fast Connect", NULL, FFILL },
  { GD|FD,  "6/1", "EFC Proposal", NULL, FFILL },
  { GD|FD,  "6/2", "EFC Close All Media Channels", NULL, FFILL },
  { GD|FD,  "6/3", "EFC Request New Proposals", NULL, FFILL },
  { GD|FD,  "6/4", "EFC Require Symmetric Operation", NULL, FFILL },
  /* H.460.7 */
  { GD|FD,  "7",   "Digit Maps", NULL, FFILL },
  {    FD,  "7/1", "Digit Maps Length", NULL, FFILL },
  {    FD,  "7/2", "Digit Map Length for Overlapped Sending", NULL, FFILL },
  {    FD,  "7/3", "HTTP Digit Maps Download Capability", NULL, FFILL },
  { GD   ,  "7/1", "Start Timer", NULL, FFILL },
  { GD   ,  "7/2", "Short Timer", NULL, FFILL },
  { GD   ,  "7/3", "Long Timer", NULL, FFILL },
  { GD   ,  "7/4", "Digit Map String", NULL, FFILL },
  { GD   ,  "7/5",   "ToN Associated Digit Map", NULL, FFILL },
  { GD   ,  "7/5/1", "Type of Number", NULL, FFILL },
  { GD   ,  "7/5/2", "Digit Map Strings for ToN", NULL, FFILL },
  { GD   ,  "7/6", "Digit Map URL", NULL, FFILL },
  /* H.460.8 */
  { GD|FD,  "8",   "Querying for Alternate Routes", NULL, FFILL },
  { GD|FD,  "8/1", "Query Count", NULL, FFILL },
  { GD|FD,  "8/2", "Call Termination Cause", NULL, FFILL },
  /* H.460.9 */
  { GD|FD,  "9",   "QoS-monitoring Reporting", NULL, FFILL },
  { GD|FD,  "9/1", "qosMonitoringFinalOnly", NULL, FFILL },
  { GD|FD,  "9/2", "qosMonitoringReportData", dissect_h460_9_QosMonitoringReportData_PDU, FFILL },
  { GD|FD,  "9/3", "qosMonitoringExtendedRTPMetrics", dissect_h460_9_ExtendedRTPMetrics_PDU, FFILL },
  /* H.460.10 */
  { GD|FD, "10",   "Call Party Category", NULL, FFILL },
  { GD|FD, "10/1", "Call party category info", dissect_h460_10_CallPartyCategoryInfo_PDU, FFILL },
  /* H.460.11 */
  { GD|FD, "11",   "Delayed Call Establishment", NULL, FFILL },
  { GD|FD, "11/1", "Delay Point Indicator", NULL, FFILL },
  { GD|FD, "11/2", "Implicit DCE Release", NULL, FFILL },
  { GD|FD, "11/3", "Delay Point Reached", NULL, FFILL },
  { GD|FD, "11/4", "DCE Release", NULL, FFILL },
  /* H.460.12 */
  { GD|FD, "12",   "Glare Control Indicator", NULL, FFILL },
  { GD|FD, "12/1", "Glare Control Indicator Parameter", NULL, FFILL },
  /* H.460.13 */
  { GD|FD, "13",   "Called User Release Control", NULL, FFILL },
  { GD|FD, "13/1", "Called User Release Control", NULL, FFILL },
  /* H.460.14 */
  { GD|FD, "14",   "Multi-Level Precedence and Preemption", NULL, FFILL },
  { GD|FD, "14/1", "MLPP Information", dissect_h460_14_MLPPInfo_PDU, FFILL },
  /* H.460.15 */
  { GD|FD, "15",   "Call signalling transport channel suspension and redirection", NULL, FFILL },
  { GD|FD, "15/1", "Signalling channel suspend and redirect", dissect_h460_15_SignallingChannelData_PDU, FFILL },
  /* H.460.16 */
  { GD|FD, "16",   "Multiple-message Release Sequence", NULL, FFILL },
  { GD|FD, "16/1", "MMRS use required", NULL, FFILL },
  { GD|FD, "16/2", "MMRS procedure", NULL, FFILL },
  { GD|FD, "16/3", "MMRS additional IEs", dissect_ies, FFILL },
  /* H.460.17 */
  { GD|FD, "17",   "RAS over H.225.0", NULL, FFILL },
  { GD|FD, "17/1", "RAS message", dissect_ras, FFILL },
  /* H.460.18 */
  { GD|FD|GM, "18",   "Signalling Traversal", NULL, FFILL },
  { GD|FD   , "18/1", "IncomingCallIndication", dissect_h460_18_IncomingCallIndication_PDU, FFILL },
  { GD|FD   , "18/2", "LRQKeepAliveData", dissect_h460_18_LRQKeepAliveData_PDU, FFILL },
  {       GM, "18-1",   "connectionCorrelation", NULL, FFILL },
  {       GM, "18-1/1", "callIdentifier", NULL, FFILL },
  {       GM, "18-1/2", "answerCall", NULL, FFILL },
  /* H.460.19 */
  { GD|FD|GI, "19", "mediaNATFWTraversal", NULL, FFILL },
  { GD|FD   , "19/1", "supportTransmitMultiplexedMedia", NULL, FFILL },
  { GD|FD   , "19/2", "mediaTraversalServer", NULL, FFILL },
  {       GI, "19/1", "Traversal Parameters", dissect_h460_19_TraversalParameters_PDU, FFILL },
  /* H.460.20 */
  { GD|FD, "20",   "LocationSourceAddress", NULL, FFILL },
  { GD|FD, "20/1", "LocationSourceAddress", dissect_h225_ExtendedAliasAddress_PDU, FFILL },
  /* H.460.21 */
  { GD|FD, "21",   "Message Broadcast", NULL, FFILL },
  { GD|FD, "21/1", "MessageBroadcastParameter", dissect_h460_21_CapabilityAdvertisement_PDU, FFILL },
  /* H.460.22 */
  { GD|FD, "22",     "securityProtocolNegotiation", NULL, FFILL },
  { GD|FD, "22/1",   "tlsSecurityProtocol", NULL, FFILL },
  { GD|FD, "22/1/1", "priority", NULL, FFILL },
  { GD|FD, "22/1/2", "connectionAddress", NULL, FFILL },
  { GD|FD, "22/2",   "ipsecSecurityProtocol", NULL, FFILL },
  { GD|FD, "22/2/1", "priority", NULL, FFILL },
  { 0, NULL, NULL, NULL, FFILL },
};                                 

static h460_feature_t *find_ftr(const gchar *key) {
  h460_feature_t *ftr = NULL;
  h460_feature_t *f;

  for (f=h460_feature_tab; f->id; f++) {
    if (f->key_gd && !strcmp(key, f->key_gd)) { ftr = f; break; }
    if (f->key_fd && !strcmp(key, f->key_fd)) { ftr = f; break; }
    if (f->key_gm && !strcmp(key, f->key_gm)) { ftr = f; break; }
    if (f->key_gi && !strcmp(key, f->key_gi)) { ftr = f; break; }
  }
  return ftr;
}

/*--- dissect_h460_name -------------------------------------------*/
static int
dissect_h460_name(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree) {
  int offset = 0;
  asn1_ctx_t *actx;
  h460_feature_t *ftr;

  actx = get_asn1_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(actx);
  if (tree) {
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, 0, 0, "*** DEBUG dissect_h460_name: %s", pinfo->match_string);*/
    ftr = find_ftr(pinfo->match_string);
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, 0, 0, "*** DEBUG dissect_h460_name: ftr %s", (ftr)?ftr->name:"-none-");*/
    if (ftr) {
      proto_item_append_text(actx->created_item, " - %s", ftr->name);
      proto_item_append_text(proto_item_get_parent(proto_tree_get_parent(tree)), ": %s", ftr->name);
    } else {
      proto_item_append_text(actx->created_item, " - unknown(%s)", pinfo->match_string);
    }
  }

  return offset;
}

/*--- proto_register_h460 ----------------------------------------------*/
void proto_register_h460(void) {
  h460_feature_t *ftr;

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-h460-hfarr.c ---*/
#line 1 "../../asn1/h460/packet-h460-hfarr.c"

/* --- Module NUMBER-PORTABILITY --- --- ---                                  */

    { &hf_h460_2_h460_2_NumberPortabilityInfo_PDU,
      { "NumberPortabilityInfo", "h460.2.NumberPortabilityInfo",
        FT_UINT32, BASE_DEC, VALS(h460_2_NumberPortabilityInfo_vals), 0,
        NULL, HFILL }},
    { &hf_h460_2_numberPortabilityRejectReason,
      { "numberPortabilityRejectReason", "h460.2.numberPortabilityRejectReason",
        FT_UINT32, BASE_DEC, VALS(h460_2_NumberPortabilityRejectReason_vals), 0,
        NULL, HFILL }},
    { &hf_h460_2_nUMBERPORTABILITYDATA,
      { "nUMBERPORTABILITYDATA", "h460.2.nUMBERPORTABILITYDATA",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_2_addressTranslated,
      { "addressTranslated", "h460.2.addressTranslated",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_2_portedAddress,
      { "portedAddress", "h460.2.portedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PortabilityAddress", HFILL }},
    { &hf_h460_2_routingAddress,
      { "routingAddress", "h460.2.routingAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PortabilityAddress", HFILL }},
    { &hf_h460_2_regionalParams,
      { "regionalParams", "h460.2.regionalParams",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegionalParameters", HFILL }},
    { &hf_h460_2_unspecified,
      { "unspecified", "h460.2.unspecified",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_2_qorPortedNumber,
      { "qorPortedNumber", "h460.2.qorPortedNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_2_aliasAddress,
      { "aliasAddress", "h460.2.aliasAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h460_2_typeOfAddress,
      { "typeOfAddress", "h460.2.typeOfAddress",
        FT_UINT32, BASE_DEC, VALS(h460_2_NumberPortabilityTypeOfNumber_vals), 0,
        "NumberPortabilityTypeOfNumber", HFILL }},
    { &hf_h460_2_publicTypeOfNumber,
      { "publicTypeOfNumber", "h460.2.publicTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(h225_PublicTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_h460_2_privateTypeOfNumber,
      { "privateTypeOfNumber", "h460.2.privateTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(h225_PrivateTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_h460_2_portabilityTypeOfNumber,
      { "portabilityTypeOfNumber", "h460.2.portabilityTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(h460_2_PortabilityTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_h460_2_portedNumber,
      { "portedNumber", "h460.2.portedNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_2_routingNumber,
      { "routingNumber", "h460.2.routingNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_2_concatenatedNumber,
      { "concatenatedNumber", "h460.2.concatenatedNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_2_t35CountryCode,
      { "t35CountryCode", "h460.2.t35CountryCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h460_2_t35Extension,
      { "t35Extension", "h460.2.t35Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h460_2_variantIdentifier,
      { "variantIdentifier", "h460.2.variantIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h460_2_regionalData,
      { "regionalData", "h460.2.regionalData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},

/* --- Module CIRCUIT-STATUS-MAP --- --- ---                                  */

    { &hf_h460_3_h460_3_CircuitStatus_PDU,
      { "CircuitStatus", "h460.3.CircuitStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_3_circuitStatusMap,
      { "circuitStatusMap", "h460.3.circuitStatusMap",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CircuitStatusMap", HFILL }},
    { &hf_h460_3_circuitStatusMap_item,
      { "CircuitStatusMap", "h460.3.CircuitStatusMap",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_3_statusType,
      { "statusType", "h460.3.statusType",
        FT_UINT32, BASE_DEC, VALS(h460_3_CircuitStatusType_vals), 0,
        "CircuitStatusType", HFILL }},
    { &hf_h460_3_baseCircuitID,
      { "baseCircuitID", "h460.3.baseCircuitID",
        FT_NONE, BASE_NONE, NULL, 0,
        "CircuitIdentifier", HFILL }},
    { &hf_h460_3_range,
      { "range", "h460.3.range",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_h460_3_status,
      { "status", "h460.3.status",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h460_3_serviceStatus,
      { "serviceStatus", "h460.3.serviceStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_3_busyStatus,
      { "busyStatus", "h460.3.busyStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module CALL-PRIORITY --- --- ---                                       */

    { &hf_h460_4_h460_4_CallPriorityInfo_PDU,
      { "CallPriorityInfo", "h460.4.CallPriorityInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_h460_4_CountryInternationalNetworkCallOriginationIdentification_PDU,
      { "CountryInternationalNetworkCallOriginationIdentification", "h460.4.CountryInternationalNetworkCallOriginationIdentification",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_priorityValue,
      { "priorityValue", "h460.4.priorityValue",
        FT_UINT32, BASE_DEC, VALS(h460_4_T_priorityValue_vals), 0,
        NULL, HFILL }},
    { &hf_h460_4_emergencyAuthorized,
      { "emergencyAuthorized", "h460.4.emergencyAuthorized",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_emergencyPublic,
      { "emergencyPublic", "h460.4.emergencyPublic",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_high,
      { "high", "h460.4.high",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_normal,
      { "normal", "h460.4.normal",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_priorityExtension,
      { "priorityExtension", "h460.4.priorityExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h460_4_tokens,
      { "tokens", "h460.4.tokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ClearToken", HFILL }},
    { &hf_h460_4_tokens_item,
      { "ClearToken", "h460.4.ClearToken",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_cryptoTokens,
      { "cryptoTokens", "h460.4.cryptoTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CryptoToken", HFILL }},
    { &hf_h460_4_cryptoTokens_item,
      { "CryptoToken", "h460.4.CryptoToken",
        FT_UINT32, BASE_DEC, VALS(h235_CryptoToken_vals), 0,
        NULL, HFILL }},
    { &hf_h460_4_rejectReason,
      { "rejectReason", "h460.4.rejectReason",
        FT_UINT32, BASE_DEC, VALS(h460_4_T_rejectReason_vals), 0,
        NULL, HFILL }},
    { &hf_h460_4_priorityUnavailable,
      { "priorityUnavailable", "h460.4.priorityUnavailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_priorityUnauthorized,
      { "priorityUnauthorized", "h460.4.priorityUnauthorized",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_priorityValueUnknown,
      { "priorityValueUnknown", "h460.4.priorityValueUnknown",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_numberingPlan,
      { "numberingPlan", "h460.4.numberingPlan",
        FT_UINT32, BASE_DEC, VALS(h460_4_T_numberingPlan_vals), 0,
        NULL, HFILL }},
    { &hf_h460_4_x121,
      { "x121", "h460.4.x121",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_x121CountryCode,
      { "countryCode", "h460.4.countryCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "X121CountryCode", HFILL }},
    { &hf_h460_4_e164,
      { "e164", "h460.4.e164",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_4_e164CountryCode,
      { "countryCode", "h460.4.countryCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "E164CountryCode", HFILL }},
    { &hf_h460_4_identificationCode,
      { "identificationCode", "h460.4.identificationCode",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Modules QOS-MONITORING-REPORT QOS-MONITORING-EXTENDED-VOIP-REPORT --- --- --- */

    { &hf_h460_9_h460_9_QosMonitoringReportData_PDU,
      { "QosMonitoringReportData", "h460.9.QosMonitoringReportData",
        FT_UINT32, BASE_DEC, VALS(h460_9_QosMonitoringReportData_vals), 0,
        NULL, HFILL }},
    { &hf_h460_9_h460_9_ExtendedRTPMetrics_PDU,
      { "ExtendedRTPMetrics", "h460.9.ExtendedRTPMetrics",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_extensionId,
      { "extensionId", "h460.9.extensionId",
        FT_UINT32, BASE_DEC, VALS(h225_GenericIdentifier_vals), 0,
        "GenericIdentifier", HFILL }},
    { &hf_h460_9_extensionContent,
      { "extensionContent", "h460.9.extensionContent",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h460_9_rtpAddress,
      { "rtpAddress", "h460.9.rtpAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportChannelInfo", HFILL }},
    { &hf_h460_9_rtcpAddress,
      { "rtcpAddress", "h460.9.rtcpAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportChannelInfo", HFILL }},
    { &hf_h460_9_sessionId,
      { "sessionId", "h460.9.sessionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h460_9_nonStandardData,
      { "nonStandardData", "h460.9.nonStandardData",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h460_9_mediaSenderMeasures,
      { "mediaSenderMeasures", "h460.9.mediaSenderMeasures",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_worstEstimatedEnd2EndDelay,
      { "worstEstimatedEnd2EndDelay", "h460.9.worstEstimatedEnd2EndDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EstimatedEnd2EndDelay", HFILL }},
    { &hf_h460_9_meanEstimatedEnd2EndDelay,
      { "meanEstimatedEnd2EndDelay", "h460.9.meanEstimatedEnd2EndDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EstimatedEnd2EndDelay", HFILL }},
    { &hf_h460_9_mediaReceiverMeasures,
      { "mediaReceiverMeasures", "h460.9.mediaReceiverMeasures",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_cumulativeNumberOfPacketsLost,
      { "cumulativeNumberOfPacketsLost", "h460.9.cumulativeNumberOfPacketsLost",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h460_9_packetLostRate,
      { "packetLostRate", "h460.9.packetLostRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h460_9_worstJitter,
      { "worstJitter", "h460.9.worstJitter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CalculatedJitter", HFILL }},
    { &hf_h460_9_estimatedThroughput,
      { "estimatedThroughput", "h460.9.estimatedThroughput",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BandWidth", HFILL }},
    { &hf_h460_9_fractionLostRate,
      { "fractionLostRate", "h460.9.fractionLostRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h460_9_meanJitter,
      { "meanJitter", "h460.9.meanJitter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CalculatedJitter", HFILL }},
    { &hf_h460_9_extensions,
      { "extensions", "h460.9.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_h460_9_extensions_item,
      { "Extension", "h460.9.Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_callReferenceValue,
      { "callReferenceValue", "h460.9.callReferenceValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_conferenceID,
      { "conferenceID", "h460.9.conferenceID",
        FT_GUID, BASE_NONE, NULL, 0,
        "ConferenceIdentifier", HFILL }},
    { &hf_h460_9_callIdentifier,
      { "callIdentifier", "h460.9.callIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_mediaChannelsQoS,
      { "mediaChannelsQoS", "h460.9.mediaChannelsQoS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_RTCPMeasures", HFILL }},
    { &hf_h460_9_mediaChannelsQoS_item,
      { "RTCPMeasures", "h460.9.RTCPMeasures",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_periodic,
      { "periodic", "h460.9.periodic",
        FT_NONE, BASE_NONE, NULL, 0,
        "PeriodicQoSMonReport", HFILL }},
    { &hf_h460_9_final,
      { "final", "h460.9.final",
        FT_NONE, BASE_NONE, NULL, 0,
        "FinalQosMonReport", HFILL }},
    { &hf_h460_9_interGK,
      { "interGK", "h460.9.interGK",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterGKQosMonReport", HFILL }},
    { &hf_h460_9_perCallInfo,
      { "perCallInfo", "h460.9.perCallInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PerCallQoSReport", HFILL }},
    { &hf_h460_9_perCallInfo_item,
      { "PerCallQoSReport", "h460.9.PerCallQoSReport",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_mediaInfo,
      { "mediaInfo", "h460.9.mediaInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_RTCPMeasures", HFILL }},
    { &hf_h460_9_mediaInfo_item,
      { "RTCPMeasures", "h460.9.RTCPMeasures",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_networkPacketLossRate,
      { "networkPacketLossRate", "h460.9.networkPacketLossRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h460_9_jitterBufferDiscardRate,
      { "jitterBufferDiscardRate", "h460.9.jitterBufferDiscardRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h460_9_burstMetrics,
      { "burstMetrics", "h460.9.burstMetrics",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_rtcpRoundTripDelay,
      { "rtcpRoundTripDelay", "h460.9.rtcpRoundTripDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h460_9_endSystemDelay,
      { "endSystemDelay", "h460.9.endSystemDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h460_9_signalLevel,
      { "signalLevel", "h460.9.signalLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_10", HFILL }},
    { &hf_h460_9_noiseLevel,
      { "noiseLevel", "h460.9.noiseLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_0", HFILL }},
    { &hf_h460_9_residualEchoReturnLoss,
      { "residualEchoReturnLoss", "h460.9.residualEchoReturnLoss",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_h460_9_rFactor,
      { "rFactor", "h460.9.rFactor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_h460_9_extRFactor,
      { "extRFactor", "h460.9.extRFactor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_h460_9_estimatedMOSLQ,
      { "estimatedMOSLQ", "h460.9.estimatedMOSLQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_10_50", HFILL }},
    { &hf_h460_9_estimatedMOSCQ,
      { "estimatedMOSCQ", "h460.9.estimatedMOSCQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_10_50", HFILL }},
    { &hf_h460_9_plcType,
      { "plcType", "h460.9.plcType",
        FT_UINT32, BASE_DEC, VALS(h460_9_PLCtypes_vals), 0,
        "PLCtypes", HFILL }},
    { &hf_h460_9_jitterBufferParms,
      { "jitterBufferParms", "h460.9.jitterBufferParms",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_gmin,
      { "gmin", "h460.9.gmin",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h460_9_burstLossDensity,
      { "burstLossDensity", "h460.9.burstLossDensity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h460_9_gapLossDensity,
      { "gapLossDensity", "h460.9.gapLossDensity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h460_9_burstDuration,
      { "burstDuration", "h460.9.burstDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h460_9_gapDuration,
      { "gapDuration", "h460.9.gapDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h460_9_unspecified,
      { "unspecified", "h460.9.unspecified",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_disabled,
      { "disabled", "h460.9.disabled",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_enhanced,
      { "enhanced", "h460.9.enhanced",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_standard,
      { "standard", "h460.9.standard",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_jitterBufferType,
      { "jitterBufferType", "h460.9.jitterBufferType",
        FT_UINT32, BASE_DEC, VALS(h460_9_JitterBufferTypes_vals), 0,
        "JitterBufferTypes", HFILL }},
    { &hf_h460_9_jitterBufferAdaptRate,
      { "jitterBufferAdaptRate", "h460.9.jitterBufferAdaptRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_h460_9_jitterBufferNominalSize,
      { "jitterBufferNominalSize", "h460.9.jitterBufferNominalSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h460_9_jitterBufferMaxSize,
      { "jitterBufferMaxSize", "h460.9.jitterBufferMaxSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h460_9_jitterBufferAbsoluteMax,
      { "jitterBufferAbsoluteMax", "h460.9.jitterBufferAbsoluteMax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h460_9_unknown,
      { "unknown", "h460.9.unknown",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_reserved,
      { "reserved", "h460.9.reserved",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_nonadaptive,
      { "nonadaptive", "h460.9.nonadaptive",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_9_adaptive,
      { "adaptive", "h460.9.adaptive",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module CALL-PARTY-CATEGORY --- --- ---                                 */

    { &hf_h460_10_h460_10_CallPartyCategoryInfo_PDU,
      { "CallPartyCategoryInfo", "h460.10.CallPartyCategoryInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_10_callPartyCategory,
      { "callPartyCategory", "h460.10.callPartyCategory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_10_originatingLineInfo,
      { "originatingLineInfo", "h460.10.originatingLineInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},

/* --- Module MLPP --- --- ---                                                */

    { &hf_h460_14_h460_14_MLPPInfo_PDU,
      { "MLPPInfo", "h460.14.MLPPInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_14_precedence,
      { "precedence", "h460.14.precedence",
        FT_UINT32, BASE_DEC, VALS(h460_14_MlppPrecedence_vals), 0,
        "MlppPrecedence", HFILL }},
    { &hf_h460_14_mlppReason,
      { "mlppReason", "h460.14.mlppReason",
        FT_UINT32, BASE_DEC, VALS(h460_14_MlppReason_vals), 0,
        NULL, HFILL }},
    { &hf_h460_14_mlppNotification,
      { "mlppNotification", "h460.14.mlppNotification",
        FT_UINT32, BASE_DEC, VALS(h460_14_MlppNotification_vals), 0,
        NULL, HFILL }},
    { &hf_h460_14_alternateParty,
      { "alternateParty", "h460.14.alternateParty",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_14_releaseCall,
      { "releaseCall", "h460.14.releaseCall",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_14_preemptionPending,
      { "preemptionPending", "h460.14.preemptionPending",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_14_preemptionInProgress,
      { "preemptionInProgress", "h460.14.preemptionInProgress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_14_preemptionEnd,
      { "preemptionEnd", "h460.14.preemptionEnd",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_14_preemptionComplete,
      { "preemptionComplete", "h460.14.preemptionComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_14_altID,
      { "altID", "h460.14.altID",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AliasAddress", HFILL }},
    { &hf_h460_14_altTimer,
      { "altTimer", "h460.14.altTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h460_14_preemptCallID,
      { "preemptCallID", "h460.14.preemptCallID",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallIdentifier", HFILL }},
    { &hf_h460_14_releaseReason,
      { "releaseReason", "h460.14.releaseReason",
        FT_UINT32, BASE_DEC, VALS(h460_14_MlppReason_vals), 0,
        "MlppReason", HFILL }},
    { &hf_h460_14_releaseDelay,
      { "releaseDelay", "h460.14.releaseDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},

/* --- Module SIGNALLING-CHANNEL-SUSPEND-REDIRECT --- --- ---                 */

    { &hf_h460_15_h460_15_SignallingChannelData_PDU,
      { "SignallingChannelData", "h460.15.SignallingChannelData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_15_signallingChannelData,
      { "signallingChannelData", "h460.15.signallingChannelData",
        FT_UINT32, BASE_DEC, VALS(h460_15_T_signallingChannelData_vals), 0,
        NULL, HFILL }},
    { &hf_h460_15_channelSuspendRequest,
      { "channelSuspendRequest", "h460.15.channelSuspendRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_15_channelSuspendResponse,
      { "channelSuspendResponse", "h460.15.channelSuspendResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_15_channelSuspendConfirm,
      { "channelSuspendConfirm", "h460.15.channelSuspendConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_15_channelSuspendCancel,
      { "channelSuspendCancel", "h460.15.channelSuspendCancel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_15_channelResumeRequest,
      { "channelResumeRequest", "h460.15.channelResumeRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_15_channelResumeResponse,
      { "channelResumeResponse", "h460.15.channelResumeResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_15_channelResumeAddress,
      { "channelResumeAddress", "h460.15.channelResumeAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TransportAddress", HFILL }},
    { &hf_h460_15_channelResumeAddress_item,
      { "TransportAddress", "h460.15.TransportAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h460_15_immediateResume,
      { "immediateResume", "h460.15.immediateResume",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h460_15_resetH245,
      { "resetH245", "h460.15.resetH245",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_15_okToSuspend,
      { "okToSuspend", "h460.15.okToSuspend",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h460_15_randomNumber,
      { "randomNumber", "h460.15.randomNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},

/* --- Module SIGNALLING-TRAVERSAL --- --- ---                                */

    { &hf_h460_18_h460_18_IncomingCallIndication_PDU,
      { "IncomingCallIndication", "h460.18.IncomingCallIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_18_h460_18_LRQKeepAliveData_PDU,
      { "LRQKeepAliveData", "h460.18.LRQKeepAliveData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_18_callSignallingAddress,
      { "callSignallingAddress", "h460.18.callSignallingAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "TransportAddress", HFILL }},
    { &hf_h460_18_callID,
      { "callID", "h460.18.callID",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallIdentifier", HFILL }},
    { &hf_h460_18_lrqKeepAliveInterval,
      { "lrqKeepAliveInterval", "h460.18.lrqKeepAliveInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeToLive", HFILL }},

/* --- Module MEDIA-TRAVERSAL --- --- ---                                     */

    { &hf_h460_19_h460_19_TraversalParameters_PDU,
      { "TraversalParameters", "h460.19.TraversalParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_19_multiplexedMediaChannel,
      { "multiplexedMediaChannel", "h460.19.multiplexedMediaChannel",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        "TransportAddress", HFILL }},
    { &hf_h460_19_multiplexedMediaControlChannel,
      { "multiplexedMediaControlChannel", "h460.19.multiplexedMediaControlChannel",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        "TransportAddress", HFILL }},
    { &hf_h460_19_multiplexID,
      { "multiplexID", "h460.19.multiplexID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h460_19_keepAliveChannel,
      { "keepAliveChannel", "h460.19.keepAliveChannel",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        "TransportAddress", HFILL }},
    { &hf_h460_19_keepAlivePayloadType,
      { "keepAlivePayloadType", "h460.19.keepAlivePayloadType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_h460_19_keepAliveInterval,
      { "keepAliveInterval", "h460.19.keepAliveInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeToLive", HFILL }},

/* --- Module MESSAGE-BROADCAST --- --- ---                                   */

    { &hf_h460_21_h460_21_CapabilityAdvertisement_PDU,
      { "CapabilityAdvertisement", "h460.21.CapabilityAdvertisement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_21_receiveCapabilities,
      { "receiveCapabilities", "h460.21.receiveCapabilities",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_21_transmitCapabilities,
      { "transmitCapabilities", "h460.21.transmitCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_TransmitCapabilities", HFILL }},
    { &hf_h460_21_transmitCapabilities_item,
      { "TransmitCapabilities", "h460.21.TransmitCapabilities",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h460_21_capabilities,
      { "capabilities", "h460.21.capabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_Capability", HFILL }},
    { &hf_h460_21_capabilities_item,
      { "Capability", "h460.21.Capability",
        FT_UINT32, BASE_DEC, VALS(h245_Capability_vals), 0,
        NULL, HFILL }},
    { &hf_h460_21_maxGroups,
      { "maxGroups", "h460.21.maxGroups",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h460_21_groupIdentifer,
      { "groupIdentifer", "h460.21.groupIdentifer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GloballyUniqueID", HFILL }},
    { &hf_h460_21_capability,
      { "capability", "h460.21.capability",
        FT_UINT32, BASE_DEC, VALS(h245_Capability_vals), 0,
        NULL, HFILL }},
    { &hf_h460_21_sourceAddress,
      { "sourceAddress", "h460.21.sourceAddress",
        FT_UINT32, BASE_DEC, VALS(h245_UnicastAddress_vals), 0,
        "UnicastAddress", HFILL }},

/*--- End of included file: packet-h460-hfarr.c ---*/
#line 248 "../../asn1/h460/packet-h460-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-h460-ettarr.c ---*/
#line 1 "../../asn1/h460/packet-h460-ettarr.c"

/* --- Module NUMBER-PORTABILITY --- --- ---                                  */

    &ett_h460_2_NumberPortabilityInfo,
    &ett_h460_2_T_nUMBERPORTABILITYDATA,
    &ett_h460_2_NumberPortabilityRejectReason,
    &ett_h460_2_PortabilityAddress,
    &ett_h460_2_NumberPortabilityTypeOfNumber,
    &ett_h460_2_PortabilityTypeOfNumber,
    &ett_h460_2_RegionalParameters,

/* --- Module CIRCUIT-STATUS-MAP --- --- ---                                  */

    &ett_h460_3_CircuitStatus,
    &ett_h460_3_SEQUENCE_OF_CircuitStatusMap,
    &ett_h460_3_CircuitStatusMap,
    &ett_h460_3_CircuitStatusType,

/* --- Module CALL-PRIORITY --- --- ---                                       */

    &ett_h460_4_CallPriorityInfo,
    &ett_h460_4_T_priorityValue,
    &ett_h460_4_SEQUENCE_OF_ClearToken,
    &ett_h460_4_SEQUENCE_OF_CryptoToken,
    &ett_h460_4_T_rejectReason,
    &ett_h460_4_CountryInternationalNetworkCallOriginationIdentification,
    &ett_h460_4_T_numberingPlan,
    &ett_h460_4_T_x121,
    &ett_h460_4_T_e164,

/* --- Modules QOS-MONITORING-REPORT QOS-MONITORING-EXTENDED-VOIP-REPORT --- --- --- */

    &ett_h460_9_Extension,
    &ett_h460_9_RTCPMeasures,
    &ett_h460_9_T_mediaSenderMeasures,
    &ett_h460_9_T_mediaReceiverMeasures,
    &ett_h460_9_SEQUENCE_OF_Extension,
    &ett_h460_9_PerCallQoSReport,
    &ett_h460_9_SEQUENCE_OF_RTCPMeasures,
    &ett_h460_9_QosMonitoringReportData,
    &ett_h460_9_PeriodicQoSMonReport,
    &ett_h460_9_SEQUENCE_OF_PerCallQoSReport,
    &ett_h460_9_FinalQosMonReport,
    &ett_h460_9_InterGKQosMonReport,
    &ett_h460_9_ExtendedRTPMetrics,
    &ett_h460_9_BurstMetrics,
    &ett_h460_9_PLCtypes,
    &ett_h460_9_JitterBufferParms,
    &ett_h460_9_JitterBufferTypes,

/* --- Module CALL-PARTY-CATEGORY --- --- ---                                 */

    &ett_h460_10_CallPartyCategoryInfo,

/* --- Module MLPP --- --- ---                                                */

    &ett_h460_14_MLPPInfo,
    &ett_h460_14_MlppNotification,
    &ett_h460_14_AlternateParty,
    &ett_h460_14_ReleaseCall,

/* --- Module SIGNALLING-CHANNEL-SUSPEND-REDIRECT --- --- ---                 */

    &ett_h460_15_SignallingChannelData,
    &ett_h460_15_T_signallingChannelData,
    &ett_h460_15_ChannelSuspendRequest,
    &ett_h460_15_SEQUENCE_OF_TransportAddress,
    &ett_h460_15_ChannelSuspendResponse,
    &ett_h460_15_ChannelSuspendConfirm,
    &ett_h460_15_ChannelSuspendCancel,
    &ett_h460_15_ChannelResumeRequest,
    &ett_h460_15_ChannelResumeResponse,

/* --- Module SIGNALLING-TRAVERSAL --- --- ---                                */

    &ett_h460_18_IncomingCallIndication,
    &ett_h460_18_LRQKeepAliveData,

/* --- Module MEDIA-TRAVERSAL --- --- ---                                     */

    &ett_h460_19_TraversalParameters,

/* --- Module MESSAGE-BROADCAST --- --- ---                                   */

    &ett_h460_21_CapabilityAdvertisement,
    &ett_h460_21_SEQUENCE_SIZE_1_256_OF_TransmitCapabilities,
    &ett_h460_21_ReceiveCapabilities,
    &ett_h460_21_SEQUENCE_SIZE_1_256_OF_Capability,
    &ett_h460_21_TransmitCapabilities,

/*--- End of included file: packet-h460-ettarr.c ---*/
#line 253 "../../asn1/h460/packet-h460-template.c"
  };

  /* Register protocol */
  proto_h460 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h460, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  for (ftr=h460_feature_tab; ftr->id; ftr++) {
    if (ftr->opt & GD) ftr->key_gd = g_strdup_printf("GenericData/%s", ftr->id);
    if (ftr->opt & FD) ftr->key_fd = g_strdup_printf("FeatureDescriptor/%s", ftr->id);
    if (ftr->opt & GM) ftr->key_gm = g_strdup_printf("GenericMessage/%s", ftr->id);
    if (ftr->opt & GI) ftr->key_gi = g_strdup_printf("GenericInformation/%s", ftr->id);
    if (ftr->content_pdu) ftr->content_hnd = new_create_dissector_handle(ftr->content_pdu, proto_h460);
  }
}

/*--- proto_reg_handoff_h460 -------------------------------------------*/
void proto_reg_handoff_h460(void) 
{
  h460_feature_t *ftr;
  dissector_handle_t h460_name_handle;

  q931_ie_handle = find_dissector("q931.ie");
  h225_ras_handle = find_dissector("h225.ras");

  h460_name_handle = new_create_dissector_handle(dissect_h460_name, proto_h460);
  for (ftr=h460_feature_tab; ftr->id; ftr++) {
    if (ftr->key_gd) dissector_add_string("h225.gef.name", ftr->key_gd, h460_name_handle);
    if (ftr->key_fd) dissector_add_string("h225.gef.name", ftr->key_fd, h460_name_handle);
    if (ftr->key_gm) dissector_add_string("h245.gef.name", ftr->key_gm, h460_name_handle);
    if (ftr->key_gi) dissector_add_string("h245.gef.name", ftr->key_gi, h460_name_handle);
    if (ftr->content_hnd) {
      if (ftr->key_gd) dissector_add_string("h225.gef.content", ftr->key_gd, ftr->content_hnd);
      if (ftr->key_fd) dissector_add_string("h225.gef.content", ftr->key_fd, ftr->content_hnd);
      if (ftr->key_gm) dissector_add_string("h245.gef.content", ftr->key_gm, ftr->content_hnd);
      if (ftr->key_gi) dissector_add_string("h245.gef.content", ftr->key_gi, ftr->content_hnd);
    }
  }

}
