/* packet-h225.c
 * Routines for H.225 packet dissection
 * 2003  Ronnie Sahlberg
 *
 * $Id: packet-h225.c,v 1.2 2003/08/01 09:16:46 sahlberg Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <stdio.h>
#include <string.h>

#include "prefs.h"
#include "packet-tpkt.h"
#include "packet-per.h"
#include "packet-h245.h"

#define UDP_PORT_RAS1 1718
#define UDP_PORT_RAS2 1719
#define TCP_PORT_CS   1720

static dissector_handle_t h225ras_handle;
static dissector_handle_t H323UserInformation_handle;

static int proto_h225 = -1;
static int hf_h225_cname = -1;
static int hf_h225_route = -1;
static int hf_h225_nonStandardUsageTypes = -1;
static int hf_h225_PresentationIndicator = -1;
static int hf_h225_conferenceGoal = -1;
static int hf_h225_ScnConnectionType = -1;
static int hf_h225_ScnConnectionAggregation = -1;
static int hf_h225_FacilityReason = -1;
static int hf_h225_PublicTypeOfNumber = -1;
static int hf_h225_PrivateTypeOfNumber = -1;
static int hf_h225_UseSpecifiedTransport = -1;
static int hf_h225_SecurityErrors = -1;
static int hf_h225_SecurityErrors2 = -1;
static int hf_h225_ServiceControlSession_reason = -1;
static int hf_h225_billingMode = -1;
static int hf_h225_CCSCcallStartingPoint = -1;
static int hf_h225_GatekeeperRejectReason = -1;
static int hf_h225_UnregRequestReason = -1;
static int hf_h225_UnregRejectReason = -1;
static int hf_h225_CallType = -1;
static int hf_h225_CallModel = -1;
static int hf_h225_TransportQOS = -1;
static int hf_h225_BandRejectReason = -1;
static int hf_h225_DisengageReason = -1;
static int hf_h225_DisengageRejectReason = -1;
static int hf_h225_InfoRequestNakReason = -1;
static int hf_h225_SCRresult = -1;
static int hf_h225_GatekeeperInfo = -1;
static int hf_h225_SecurityServiceMode_encryption = -1;
static int hf_h225_SecurityServiceMode_authentication = -1;
static int hf_h225_SecurityServiceMode_integrity = -1;
static int hf_h225_SecurityCapabilities_tls = -1;
static int hf_h225_SecurityCapabilities_ipsec = -1;
static int hf_h225_H245Security = -1;
static int hf_h225_RasUsageInfoTypes = -1;
static int hf_h225_usageReportingCapability = -1;
static int hf_h225_BandWidth = -1;
static int hf_h225_channelRate = -1;
static int hf_h225_totalBandwidthRestriction = -1;
static int hf_h225_allowedBandWidth = -1;
static int hf_h225_channelMultiplier = -1;
static int hf_h225_DataRate = -1;
static int hf_h225_gatewayDataRate = -1;
static int hf_h225_dataRatesSupported = -1;
static int hf_h225_TerminalInfo = -1;
static int hf_h225_h248Message = -1;
static int hf_h225_StimulusControl = -1;
static int hf_h225_conferenceID = -1;
static int hf_h225_Generic_nonStandard = -1;
static int hf_h225_guid = -1;
static int hf_h225_replaceWithConferenceInvite = -1;
static int hf_h225_ReleaseCompleteReason = -1;
static int hf_h225_numberOfScnConnections = -1;
static int hf_h225_connectionParameters = -1;
static int hf_h225_RequestSeqNum = -1;
static int hf_h225_RasUsageSpecification_when = -1;
static int hf_h225_RasUsageSpecification_callStartingPoint = -1;
static int hf_h225_RasUsageSpecification = -1;
static int hf_h225_ipAddress_ip = -1;
static int hf_h225_ipAddress_port = -1;
static int hf_h225_ipAddress = -1;
static int hf_h225_routing = -1;
static int hf_h225_ipSourceRoute = -1;
static int hf_h225_ipxNode = -1;
static int hf_h225_ipxNetnum = -1;
static int hf_h225_ipxPort = -1;
static int hf_h225_ipxAddress = -1;
static int hf_h225_ipv6Address_ip = -1;
static int hf_h225_ipv6Address_port = -1;
static int hf_h225_ip6Address = -1;
static int hf_h225_netBios = -1;
static int hf_h225_nsap = -1;
static int hf_h225_TransportAddress = -1;
static int hf_h225_replyAddress = -1;
static int hf_h225_rasAddress = -1;
static int hf_h225_h245Address = -1;
static int hf_h225_destCallSignalAddress = -1;
static int hf_h225_sourceCallSignalAddress = -1;
static int hf_h225_CallSignalAddress2 = -1;
static int hf_h225_alternativeAddress = -1;
static int hf_h225_transportID = -1;
static int hf_h225_sendAddress = -1;
static int hf_h225_recvAddress = -1;
static int hf_h225_rtpAddress = -1;
static int hf_h225_rtcpAddress = -1;
static int hf_h225_h245 = -1;
static int hf_h225_callSignaling = -1;
static int hf_h225_carrierName = -1;
static int hf_h225_carrierIdentificationCode = -1;
static int hf_h225_CarrierInfo = -1;
static int hf_h225_segment = -1;
static int hf_h225_InfoRequestResponseStatus = -1;
static int hf_h225_CallIdentifier = -1;
static int hf_h225_globalCallId = -1;
static int hf_h225_threadId = -1;
static int hf_h225_CallLinkage = -1;
static int hf_h225_tokens = -1;
static int hf_h225_needToRegister = -1;
static int hf_h225_priority = -1;
static int hf_h225_AlternateGK = -1;
static int hf_h225_alternateGatekeeper = -1;
static int hf_h225_altGKisPermanent = -1;
static int hf_h225_AltGKInfo = -1;
static int hf_h225_annexE = -1;
static int hf_h225_sctp = -1;
static int hf_h225_AlternateTransportAddress = -1;
static int hf_h225_setup_bool = -1;
static int hf_h225_callProceeding_bool = -1;
static int hf_h225_connect_bool = -1;
static int hf_h225_alerting_bool = -1;
static int hf_h225_information_bool = -1;
static int hf_h225_releaseComplete_bool = -1;
static int hf_h225_facility_bool = -1;
static int hf_h225_progress_bool = -1;
static int hf_h225_empty_bool = -1;
static int hf_h225_status_bool = -1;
static int hf_h225_statusInquiry_bool = -1;
static int hf_h225_setupAcknowledge_bool = -1;
static int hf_h225_notify_bool = -1;
static int hf_h225_UUIEsRequested = -1;
static int hf_h225_conferenceCalling = -1;
static int hf_h225_threePartyService = -1;
static int hf_h225_Q954Details = -1;
static int hf_h225_q932Full = -1;
static int hf_h225_q951Full = -1;
static int hf_h225_q952Full = -1;
static int hf_h225_q953Full = -1;
static int hf_h225_q955Full = -1;
static int hf_h225_q956Full = -1;
static int hf_h225_q957Full = -1;
static int hf_h225_QseriesOptions = -1;
static int hf_h225_ssrc = -1;
static int hf_h225_RTPsessionId = -1;
static int hf_h225_associatedSessionIds = -1;
static int hf_h225_RTPSession = -1;
static int hf_h225_cryptoTokens = -1;
static int hf_h225_ProtocolIdentifier = -1;
static int hf_h225_isoAlgorithm = -1;
static int hf_h225_iso9797 = -1;
static int hf_h225_algorithmOID = -1;
static int hf_h225_hMAC_iso10118_3 = -1;
static int hf_h225_enterpriseNumber = -1;
static int hf_h225_Generic_oid = -1;
static int hf_h225_tunnelledProtocolObjectID = -1;
static int hf_h225_StatusUUIE = -1;
static int hf_h225_StatusInquiryUUIE = -1;
static int hf_h225_SetupAcknowledgeUUIE = -1;
static int hf_h225_NotifyUUIE = -1;
static int hf_h225_imsi = -1;
static int hf_h225_tmsi = -1;
static int hf_h225_msisdn = -1;
static int hf_h225_imei = -1;
static int hf_h225_hplmn = -1;
static int hf_h225_vplmn = -1;
static int hf_h225_GSMUIM = -1;
static int hf_h225_sid = -1;
static int hf_h225_mid = -1;
static int hf_h225_systemid = -1;
static int hf_h225_min = -1;
static int hf_h225_mdn = -1;
static int hf_h225_esn = -1;
static int hf_h225_mscid = -1;
static int hf_h225_systemMyTypeCode = -1;
static int hf_h225_systemAccessType = -1;
static int hf_h225_qualificationInformationCode = -1;
static int hf_h225_sesn = -1;
static int hf_h225_soc = -1;
static int hf_h225_ANSI41UIM = -1;
static int hf_h225_MobileUIM = -1;
static int hf_h225_dataPartyNumber = -1;
static int hf_h225_telexPartyNumber = -1;
static int hf_h225_nationalStandardPartyNumber = -1;
static int hf_h225_publicNumberDigits = -1;
static int hf_h225_privateNumberDigits = -1;
static int hf_h225_e164Number = -1;
static int hf_h225_privateNumber = -1;
static int hf_h225_PartyNumber = -1;
static int hf_h225_startOfRange = -1;
static int hf_h225_endOfRange = -1;
static int hf_h225_protocolType = -1;
static int hf_h225_protocolVariant = -1;
static int hf_h225_TunnelledProtocolAlternateIdentifier = -1;
static int hf_h225_dialedDigits = -1;
static int hf_h225_urlId = -1;
static int hf_h225_h323ID = -1;
static int hf_h225_unicode = -1;
static int hf_h225_GatekeeperIdentifier = -1;
static int hf_h225_EndpointIdentifier = -1;
static int hf_h225_emailId = -1;
static int hf_h225_AliasAddress = -1;
static int hf_h225_featureServerAlias = -1;
static int hf_h225_RemoteExtensionAddress = -1;
static int hf_h225_conferenceAlias = -1;
static int hf_h225_wildcard = -1;
static int hf_h225_prefix = -1;
static int hf_h225_SupportedPrefix = -1;
static int hf_h225_SupportedPrefixes = -1;
static int hf_h225_H310Caps = -1;
static int hf_h225_H320Caps = -1;
static int hf_h225_H321Caps = -1;
static int hf_h225_H322Caps = -1;
static int hf_h225_H323Caps = -1;
static int hf_h225_H324Caps = -1;
static int hf_h225_VoiceCaps = -1;
static int hf_h225_T120OnlyCaps = -1;
static int hf_h225_NonStandardProtocol = -1;
static int hf_h225_SIPCaps = -1;
static int hf_h225_AddressPattern_range = -1;
static int hf_h225_AddressPattern = -1;
static int hf_h225_ConferenceList = -1;
static int hf_h225_conferences = -1;
static int hf_h225_T38FaxAnnexbOnlyCaps = -1;
static int hf_h225_SupportedProtocols = -1;
static int hf_h225_protocol = -1;
static int hf_h225_GatewayInfo = -1;
static int hf_h225_McuInfo = -1;
static int hf_h225_TunnelledProtocol_id = -1;
static int hf_h225_TunnelledProtocol_subIdentifier = -1;
static int hf_h225_TunnelledProtocol = -1;
static int hf_h225_desiredTunnelledProtocol = -1;
static int hf_h225_CicInfo_cic_item = -1;
static int hf_h225_CicInfo_pointCode = -1;
static int hf_h225_CicInfo_cic = -1;
static int hf_h225_CicInfo = -1;
static int hf_h225_GroupID_member_item = -1;
static int hf_h225_GroupID_member = -1;
static int hf_h225_GroupID_group = -1;
static int hf_h225_GroupID = -1;
static int hf_h225_sourceCircuitID = -1;
static int hf_h225_destinationCircuitID = -1;
static int hf_h225_Generic_standard = -1;
static int hf_h225_GenericIdentifier = -1;
static int hf_h225_EnumeratedParameter = -1;
static int hf_h225_parameters = -1;
static int hf_h225_GenericData = -1;
static int hf_h225_FeatureDescriptor = -1;
static int hf_h225_Content_raw = -1;
static int hf_h225_Content_text = -1;
static int hf_h225_Content = -1;
static int hf_h225_Content_bool = -1;
static int hf_h225_Content_number8 = -1;
static int hf_h225_number16 = -1;
static int hf_h225_Content_number32 = -1;
static int hf_h225_Content_compound = -1;
static int hf_h225_Content_nested = -1;
static int hf_h225_replacementFeatureSet = -1;
static int hf_h225_neededFeatures = -1;
static int hf_h225_desiredFeatures = -1;
static int hf_h225_supportedFeatures = -1;
static int hf_h225_FeatureSet = -1;
static int hf_h225_CallsAvailable_calls = -1;
static int hf_h225_CallsAvailable_group = -1;
static int hf_h225_CallsAvailable = -1;
static int hf_h225_voiceGwCallsAvailable = -1;
static int hf_h225_h310GwCallsAvailable = -1;
static int hf_h225_h320GwCallsAvailable = -1;
static int hf_h225_h321GwCallsAvailable = -1;
static int hf_h225_h322GwCallsAvailable = -1;
static int hf_h225_h323GwCallsAvailable = -1;
static int hf_h225_h324GwCallsAvailable = -1;
static int hf_h225_t120OnlyGwCallsAvailable = -1;
static int hf_h225_t38FaxAnnexbOnlyGwCallsAvailable = -1;
static int hf_h225_terminalCallsAvailable = -1;
static int hf_h225_mcuCallsAvailable = -1;
static int hf_h225_sipGwCallsAvailable = -1;
static int hf_h225_maximumCallCapacity = -1;
static int hf_h225_currentCallCapacity = -1;
static int hf_h225_CallCapacity = -1;
static int hf_h225_productID = -1;
static int hf_h225_versionID = -1;
static int hf_h225_VendorIdentifier = -1;
static int hf_h225_canReportCallCapacity = -1;
static int hf_h225_CapacityReportingCapability = -1;
static int hf_h225_canDisplayAmountString = -1;
static int hf_h225_canEnforceDurationLimit = -1;
static int hf_h225_CallCreditCapability = -1;
static int hf_h225_BandwidthDetails_sender = -1;
static int hf_h225_BandwidthDetails_multicast = -1;
static int hf_h225_BandwidthDetails = -1;
static int hf_h225_releaseCompleteCauseIE = -1;
static int hf_h225_CallTerminationCause = -1;
static int hf_h225_CircuitInfo = -1;
static int hf_h225_genericData = -1;
static int hf_h225_fastStart_item = -1;
static int hf_h225_fastStart = -1;
static int hf_h225_fastConnectRefused = -1;
static int hf_h225_InformationUUIE = -1;
static int hf_h225_routeCallToSCN = -1;
static int hf_h225_AdmissionRejectReason = -1;
static int hf_h225_hMAC_iso10118_2_s = -1;
static int hf_h225_hMAC_iso10118_2_l = -1;
static int hf_h225_NonIsoIntegrityMechanism = -1;
static int hf_h225_IntegrityMechanism = -1;
static int hf_h225_LocationRejectReason = -1;
static int hf_h225_mc = -1;
static int hf_h225_undefinedNode = -1;
static int hf_h225_EndPointType = -1;
static int hf_h225_terminalType = -1;
static int hf_h225_sourceInfo = -1;
static int hf_h225_destinationInfo = -1;
static int hf_h225_multipleCalls = -1;
static int hf_h225_maintainConnection = -1;
static int hf_h225_CallProceedingUUIE = -1;
static int hf_h225_CapacityReportingSpecification_when = -1;
static int hf_h225_CapacityReportingSpecification = -1;
static int hf_h225_ProgressUUIE = -1;
static int hf_h225_EndPoint = -1;
static int hf_h225_destinationType = -1;
static int hf_h225_destExtraCallInfo = -1;
static int hf_h225_remoteExtensionAddress = -1;
static int hf_h225_rasAddress_sequence = -1;
static int hf_h225_callSignalAddress = -1;
static int hf_h225_ICV = -1;
static int hf_h225_BandwidthConfirm = -1;
static int hf_h225_UnregistrationConfirm = -1;
static int hf_h225_NonStandardMessage = -1;
static int hf_h225_InfoRequestAck = -1;
static int hf_h225_InfoRequestNak = -1;
static int hf_h225_ResourcesAvailableConfirm = -1;
static int hf_h225_GatekeeperRequest = -1;
static int hf_h225_integrity = -1;
static int hf_h225_algorithmOIDs = -1;
static int hf_h225_alternateEndpoints = -1;
static int hf_h225_endpointAlias = -1;
static int hf_h225_ServiceControlResponse = -1;
static int hf_h225_DisengageReject = -1;
static int hf_h225_BandwidthReject = -1;
static int hf_h225_UnregistrationReject = -1;
static int hf_h225_UnregistrationRequest = -1;
static int hf_h225_endpointAliasPattern = -1;
static int hf_h225_RegistrationReject = -1;
static int hf_h225_invalidTerminalAliases = -1;
static int hf_h225_terminalAlias = -1;
static int hf_h225_terminalAliasPattern = -1;
static int hf_h225_RegistrationRejectReason = -1;
static int hf_h225_duplicateAlias = -1;
static int hf_h225_GatekeeperReject = -1;
static int hf_h225_almostOutOfResources = -1;
static int hf_h225_ResourcesAvailableIndicate = -1;
static int hf_h225_protocols = -1;
static int hf_h225_callDurationLimit = -1;
static int hf_h225_enforceCallDurationLimit = -1;
static int hf_h225_CallCreditServiceControl = -1;
static int hf_h225_ScreeningIndicator = -1;
static int hf_h225_ExtendedAliasAddress = -1;
static int hf_h225_messageNotUnderstood = -1;
static int hf_h225_UnknownMessageResponse = -1;
static int hf_h225_CallReferenceValue = -1;
static int hf_h225_AdmissionRequest = -1;
static int hf_h225_canMapSrcAlias = -1;
static int hf_h225_desiredProtocols = -1;
static int hf_h225_willSupplyUUIEs = -1;
static int hf_h225_destAlternatives = -1;
static int hf_h225_srcAlternatives = -1;
static int hf_h225_canMapAlias = -1;
static int hf_h225_activeMC = -1;
static int hf_h225_srcInfo = -1;
static int hf_h225_DestinationInfo = -1;
static int hf_h225_InfoRequest = -1;
static int hf_h225_nextSegmentRequested = -1;
static int hf_h225_delay = -1;
static int hf_h225_RequestInProgress = -1;
static int hf_h225_H248SignalsDescriptor = -1;
static int hf_h225_url = -1;
static int hf_h225_ServiceControlDescriptor = -1;
static int hf_h225_ServiceControlSession = -1;
static int hf_h225_sessionId = -1;
static int hf_h225_AlertingUUIE = -1;
static int hf_h225_serviceControl = -1;
static int hf_h225_alertingAddress = -1;
static int hf_h225_ReleaseCompleteUUIE = -1;
static int hf_h225_busyAddress = -1;
static int hf_h225_FacilityUUIE = -1;
static int hf_h225_alternativeAliasAddress = -1;
static int hf_h225_AdmissionReject = -1;
static int hf_h225_hopCount = -1;
static int hf_h225_parallelH245Control_item = -1;
static int hf_h225_parallelH245Control = -1;
static int hf_h225_language = -1;
static int hf_h225_languages = -1;
static int hf_h225_mediaWaitForConnect = -1;
static int hf_h225_canOverlapSend = -1;
static int hf_h225_SetupUUIE = -1;
static int hf_h225_sourceAddress = -1;
static int hf_h225_destinationAddress = -1;
static int hf_h225_destExtraCRV = -1;
static int hf_h225_h245SecurityCapability = -1;
static int hf_h225_additionalSourceAddresses = -1;
static int hf_h225_ConnectUUIE = -1;
static int hf_h225_connectedAddress = -1;
static int hf_h225_h323_message_body = -1;
static int hf_h225_LocationConfirm = -1;
static int hf_h225_supportedProtocols = -1;
static int hf_h225_modifiedSrcInfo = -1;
static int hf_h225_LocationReject = -1;
static int hf_h225_callSpecific = -1;
static int hf_h225_answeredCall = -1;
static int hf_h225_ServiceControlIndication = -1;
static int hf_h225_RasUsageInformation = -1;
static int hf_h225_nonStandardUsageFields = -1;
static int hf_h225_TimeToLive = -1;
static int hf_h225_GatekeeperConfirm = -1;
static int hf_h225_RegistrationRequest = -1;
static int hf_h225_discoveryComplete = -1;
static int hf_h225_keepAlive = -1;
static int hf_h225_H248PackagesDescriptor = -1;
static int hf_h225_supportedH248Packages = -1;
static int hf_h225_DisengageConfirm = -1;
static int hf_h225_AdmissionConfirm = -1;
static int hf_h225_irrFrequency = -1;
static int hf_h225_willRespondToIRR = -1;
static int hf_h225_usageSpec = -1;
static int hf_h225_DisengageRequest = -1;
static int hf_h225_LocationRequest = -1;
static int hf_h225_SourceInfo = -1;
static int hf_h225_hopCount255 = -1;
static int hf_h225_sourceEndpointInfo = -1;
static int hf_h225_BandwidthRequest = -1;
static int hf_h225_bandwidthDetails = -1;
static int hf_h225_admissionConfirmSequence = -1;
static int hf_h225_tunnelledSignallingMessage = -1;
static int hf_h225_messageContent_item = -1;
static int hf_h225_messageContent = -1;
static int hf_h225_H323_UU_PDU = -1;
static int hf_h225_h4501SupplementaryService_item = -1;
static int hf_h225_h4501SupplementaryService = -1;
static int hf_h225_h245Tunneling = -1;
static int hf_h225_h245Control_item = -1;
static int hf_h225_h245Control = -1;
static int hf_h225_nonStandardControl = -1;
static int hf_h225_preGrantedARQ = -1;
static int hf_h225_makeCall = -1;
static int hf_h225_useGKCallSignalAddressToMakeCall = -1;
static int hf_h225_answerCall = -1;
static int hf_h225_useGKCallSignalAddressToAnswer = -1;
static int hf_h225_RegistrationConfirm = -1;
static int hf_h225_pdu_item = -1;
static int hf_h225_sent = -1;
static int hf_h225_pdu = -1;
static int hf_h225_perCallInfo_item = -1;
static int hf_h225_originator = -1;
static int hf_h225_audio = -1;
static int hf_h225_video = -1;
static int hf_h225_data = -1;
static int hf_h225_substituteConfIDs = -1;
static int hf_h225_perCallInfo = -1;
static int hf_h225_InfoRequestResponse = -1;
static int hf_h225_needResponse = -1;
static int hf_h225_unsolicited = -1;
static int hf_h225_RasMessage = -1;
static int hf_h225_H323_UserInformation = -1;
static int hf_h225_user_data = -1;
static int hf_h225_protocol_discriminator = -1;
static int hf_h225_user_information = -1;
/*aaa*/

static gint ett_h225 = -1;
static gint ett_h225_nonStandardUsageTypes = -1;
static gint ett_h225_PresentationIndicator = -1;
static gint ett_h225_conferenceGoal = -1;
static gint ett_h225_ScnConnectionType = -1;
static gint ett_h225_ScnConnectionAggregation = -1;
static gint ett_h225_FacilityReason = -1;
static gint ett_h225_PublicTypeOfNumber = -1;
static gint ett_h225_PrivateTypeOfNumber = -1;
static gint ett_h225_UseSpecifiedTransport = -1;
static gint ett_h225_SecurityErrors = -1;
static gint ett_h225_SecurityErrors2 = -1;
static gint ett_h225_ServiceControlSession_reason = -1;
static gint ett_h225_billingMode = -1;
static gint ett_h225_CCSCcallStartingPoint = -1;
static gint ett_h225_GatekeeperRejectReason = -1;
static gint ett_h225_UnregRequestReason = -1;
static gint ett_h225_UnregRejectReason = -1;
static gint ett_h225_CallType = -1;
static gint ett_h225_CallModel = -1;
static gint ett_h225_TransportQOS = -1;
static gint ett_h225_BandRejectReason = -1;
static gint ett_h225_DisengageReason = -1;
static gint ett_h225_DisengageRejectReason = -1;
static gint ett_h225_InfoRequestNakReason = -1;
static gint ett_h225_SCRresult = -1;
static gint ett_h225_GatekeeperInfo = -1;
static gint ett_h225_SecurityServiceMode_encryption = -1;
static gint ett_h225_SecurityServiceMode_authentication = -1;
static gint ett_h225_SecurityServiceMode_integrity = -1;
static gint ett_h225_SecurityCapabilities_tls = -1;
static gint ett_h225_SecurityCapabilities_ipsec = -1;
static gint ett_h225_H245Security = -1;
static gint ett_h225_RasUsageInfoTypes = -1;
static gint ett_h225_DataRate = -1;
static gint ett_h225_dataRatesSupported = -1;
static gint ett_h225_TerminalInfo = -1;
static gint ett_h225_StimulusControl = -1;
static gint ett_h225_ReleaseCompleteReason = -1;
static gint ett_h225_connectionParameters = -1;
static gint ett_h225_RasUsageSpecification_when = -1;
static gint ett_h225_RasUsageSpecification_callStartingPoint = -1;
static gint ett_h225_RasUsageSpecification = -1;
static gint ett_h225_ipAddress = -1;
static gint ett_h225_routing = -1;
static gint ett_h225_route = -1;
static gint ett_h225_ipSourceRoute = -1;
static gint ett_h225_ipxAddress = -1;
static gint ett_h225_ip6Address = -1;
static gint ett_h225_TransportAddress = -1;
static gint ett_h225_TransportChannelInfo = -1;
static gint ett_h225_CarrierInfo = -1;
static gint ett_h225_InfoRequestResponseStatus = -1;
static gint ett_h225_CallIdentifier = -1;
static gint ett_h225_CallLinkage = -1;
static gint ett_h225_tokens = -1;
static gint ett_h225_AlternateGK = -1;
static gint ett_h225_alternateGatekeeper = -1;
static gint ett_h225_AltGKInfo = -1;
static gint ett_h225_annexE = -1;
static gint ett_h225_sctp = -1;
static gint ett_h225_AlternateTransportAddress = -1;
static gint ett_h225_UUIEsRequested = -1;
static gint ett_h225_Q954Details = -1;
static gint ett_h225_QseriesOptions = -1;
static gint ett_h225_associatedSessionIds = -1;
static gint ett_h225_RTPSession = -1;
static gint ett_h225_cryptoTokens = -1;
static gint ett_h225_StatusUUIE = -1;
static gint ett_h225_StatusInquiryUUIE = -1;
static gint ett_h225_SetupAcknowledgeUUIE = -1;
static gint ett_h225_NotifyUUIE = -1;
static gint ett_h225_GSMUIM = -1;
static gint ett_h225_systemid = -1;
static gint ett_h225_ANSI41UIM = -1;
static gint ett_h225_MobileUIM = -1;
static gint ett_h225_e164Number = -1;
static gint ett_h225_privateNumber = -1;
static gint ett_h225_PartyNumber = -1;
static gint ett_h225_TunnelledProtocolAlternateIdentifier = -1;
static gint ett_h225_AliasAddress = -1;
static gint ett_h225_SupportedPrefix = -1;
static gint ett_h225_SupportedPrefixes = -1;
static gint ett_h225_H310Caps = -1;
static gint ett_h225_H320Caps = -1;
static gint ett_h225_H321Caps = -1;
static gint ett_h225_H322Caps = -1;
static gint ett_h225_H323Caps = -1;
static gint ett_h225_H324Caps = -1;
static gint ett_h225_VoiceCaps = -1;
static gint ett_h225_T120OnlyCaps = -1;
static gint ett_h225_NonStandardProtocol = -1;
static gint ett_h225_SIPCaps = -1;
static gint ett_h225_AddressPattern_range = -1;
static gint ett_h225_AddressPattern = -1;
static gint ett_h225_ConferenceList = -1;
static gint ett_h225_conferences = -1;
static gint ett_h225_T38FaxAnnexbOnlyCaps = -1;
static gint ett_h225_SupportedProtocols = -1;
static gint ett_h225_protocol = -1;
static gint ett_h225_GatewayInfo = -1;
static gint ett_h225_McuInfo = -1;
static gint ett_h225_TunnelledProtocol_id = -1;
static gint ett_h225_TunnelledProtocol = -1;
static gint ett_h225_CicInfo_cic = -1;
static gint ett_h225_CicInfo = -1;
static gint ett_h225_GroupID_member = -1;
static gint ett_h225_GroupID = -1;
static gint ett_h225_CircuitIdentifier = -1;
static gint ett_h225_GenericIdentifier = -1;
static gint ett_h225_EnumeratedParameter = -1;
static gint ett_h225_parameters = -1;
static gint ett_h225_GenericData = -1;
static gint ett_h225_Content = -1;
static gint ett_h225_Content_compound = -1;
static gint ett_h225_Content_nested = -1;
static gint ett_h225_neededFeatures = -1;
static gint ett_h225_desiredFeatures = -1;
static gint ett_h225_supportedFeatures = -1;
static gint ett_h225_FeatureSet = -1;
static gint ett_h225_CallsAvailable = -1;
static gint ett_h225_voiceGwCallsAvailable = -1;
static gint ett_h225_h310GwCallsAvailable = -1;
static gint ett_h225_h320GwCallsAvailable = -1;
static gint ett_h225_h321GwCallsAvailable = -1;
static gint ett_h225_h322GwCallsAvailable = -1;
static gint ett_h225_h323GwCallsAvailable = -1;
static gint ett_h225_h324GwCallsAvailable = -1;
static gint ett_h225_t120OnlyGwCallsAvailable = -1;
static gint ett_h225_t38FaxAnnexbOnlyGwCallsAvailable = -1;
static gint ett_h225_terminalCallsAvailable = -1;
static gint ett_h225_mcuCallsAvailable = -1;
static gint ett_h225_sipGwCallsAvailable = -1;
static gint ett_h225_CallCapacityInfo = -1;
static gint ett_h225_CallCapacity = -1;
static gint ett_h225_VendorIdentifier = -1;
static gint ett_h225_CapacityReportingCapability = -1;
static gint ett_h225_CallCreditCapability = -1;
static gint ett_h225_BandwidthDetails = -1;
static gint ett_h225_CallTerminationCause = -1;
static gint ett_h225_CircuitInfo = -1;
static gint ett_h225_genericData = -1;
static gint ett_h225_fastStart = -1;
static gint ett_h225_InformationUUIE = -1;
static gint ett_h225_routeCallToSCN = -1;
static gint ett_h225_AdmissionRejectReason = -1;
static gint ett_h225_EncryptIntAlg = -1;
static gint ett_h225_NonIsoIntegrityMechanism = -1;
static gint ett_h225_IntegrityMechanism = -1;
static gint ett_h225_LocationRejectReason = -1;
static gint ett_h225_EndPointType = -1;
static gint ett_h225_CallProceedingUUIE = -1;
static gint ett_h225_CapacityReportingSpecification_when = -1;
static gint ett_h225_CapacityReportingSpecification = -1;
static gint ett_h225_ProgressUUIE = -1;
static gint ett_h225_EndPoint = -1;
static gint ett_h225_destExtraCallInfo = -1;
static gint ett_h225_remoteExtensionAddress = -1;
static gint ett_h225_rasAddress_sequence = -1;
static gint ett_h225_callSignalAddress = -1;
static gint ett_h225_ICV = -1;
static gint ett_h225_BandwidthConfirm = -1;
static gint ett_h225_UnregistrationConfirm = -1;
static gint ett_h225_NonStandardMessage = -1;
static gint ett_h225_InfoRequestAck = -1;
static gint ett_h225_InfoRequestNak = -1;
static gint ett_h225_ResourcesAvailableConfirm = -1;
static gint ett_h225_GatekeeperRequest = -1;
static gint ett_h225_integrity = -1;
static gint ett_h225_algorithmOIDs = -1;
static gint ett_h225_alternateEndpoints = -1;
static gint ett_h225_endpointAlias = -1;
static gint ett_h225_ServiceControlResponse = -1;
static gint ett_h225_DisengageReject = -1;
static gint ett_h225_BandwidthReject = -1;
static gint ett_h225_UnregistrationReject = -1;
static gint ett_h225_UnregistrationRequest = -1;
static gint ett_h225_endpointAliasPattern = -1;
static gint ett_h225_RegistrationReject = -1;
static gint ett_h225_invalidTerminalAliases = -1;
static gint ett_h225_terminalAlias = -1;
static gint ett_h225_terminalAliasPattern = -1;
static gint ett_h225_RegistrationRejectReason = -1;
static gint ett_h225_duplicateAlias = -1;
static gint ett_h225_GatekeeperReject = -1;
static gint ett_h225_ResourcesAvailableIndicate = -1;
static gint ett_h225_protocols = -1;
static gint ett_h225_CallCreditServiceControl = -1;
static gint ett_h225_ExtendedAliasAddress = -1;
static gint ett_h225_UnknownMessageResponse = -1;
static gint ett_h225_AdmissionRequest = -1;
static gint ett_h225_desiredProtocols = -1;
static gint ett_h225_destAlternatives = -1;
static gint ett_h225_srcAlternatives = -1;
static gint ett_h225_srcInfo = -1;
static gint ett_h225_DestinationInfo = -1;
static gint ett_h225_InfoRequest = -1;
static gint ett_h225_RequestInProgress = -1;
static gint ett_h225_ServiceControlDescriptor = -1;
static gint ett_h225_ServiceControlSession = -1;
static gint ett_h225_AlertingUUIE = -1;
static gint ett_h225_serviceControl = -1;
static gint ett_h225_alertingAddress = -1;
static gint ett_h225_ReleaseCompleteUUIE = -1;
static gint ett_h225_busyAddress = -1;
static gint ett_h225_FacilityUUIE = -1;
static gint ett_h225_alternativeAliasAddress = -1;
static gint ett_h225_AdmissionReject = -1;
static gint ett_h225_parallelH245Control = -1;
static gint ett_h225_languages = -1;
static gint ett_h225_SetupUUIE = -1;
static gint ett_h225_sourceAddress = -1;
static gint ett_h225_destinationAddress = -1;
static gint ett_h225_destExtraCRV = -1;
static gint ett_h225_h245SecurityCapability = -1;
static gint ett_h225_additionalSourceAddresses = -1;
static gint ett_h225_ConnectUUIE = -1;
static gint ett_h225_connectedAddress = -1;
static gint ett_h225_h323_message_body = -1;
static gint ett_h225_LocationConfirm = -1;
static gint ett_h225_supportedProtocols = -1;
static gint ett_h225_modifiedSrcInfo = -1;
static gint ett_h225_LocationReject = -1;
static gint ett_h225_callSpecific = -1;
static gint ett_h225_ServiceControlIndication = -1;
static gint ett_h225_RasUsageInformation = -1;
static gint ett_h225_nonStandardUsageFields = -1;
static gint ett_h225_GatekeeperConfirm = -1;
static gint ett_h225_RegistrationRequest = -1;
static gint ett_h225_supportedH248Packages = -1;
static gint ett_h225_DisengageConfirm = -1;
static gint ett_h225_AdmissionConfirm = -1;
static gint ett_h225_usageSpec = -1;
static gint ett_h225_DisengageRequest = -1;
static gint ett_h225_LocationRequest = -1;
static gint ett_h225_SourceInfo = -1;
static gint ett_h225_sourceEndpointInfo = -1;
static gint ett_h225_BandwidthRequest = -1;
static gint ett_h225_bandwidthDetails = -1;
static gint ett_h225_admissionConfirmSequence = -1;
static gint ett_h225_tunnelledSignallingMessage = -1;
static gint ett_h225_messageContent = -1;
static gint ett_h225_H323_UU_PDU = -1;
static gint ett_h225_h4501SupplementaryService = -1;
static gint ett_h225_h245Control = -1;
static gint ett_h225_nonStandardControl = -1;
static gint ett_h225_preGrantedARQ = -1;
static gint ett_h225_RegistrationConfirm = -1;
static gint ett_h225_pdu_item = -1;
static gint ett_h225_pdu = -1;
static gint ett_h225_perCallInfo_item = -1;
static gint ett_h225_audio = -1;
static gint ett_h225_video = -1;
static gint ett_h225_data = -1;
static gint ett_h225_substituteConfIDs = -1;
static gint ett_h225_perCallInfo = -1;
static gint ett_h225_InfoRequestResponse = -1;
static gint ett_h225_RasMessage = -1;
static gint ett_h225_H323_UserInformation = -1;
static gint ett_h225_user_data = -1;
/*bbb*/

static const true_false_string tfs_unsolicited_bit = {
	"unsolicited bit is SET",
	"unsolicited bit is NOT set"
};

static const true_false_string tfs_needResponse_bit = {
	"needResponse bit is SET",
	"needResponse bit is NOT set"
};

static const true_false_string tfs_originator_bit = {
	"originator bit is SET",
	"originator bit is NOT set"
};

static const true_false_string tfs_sent_bit = {
	"sent bit is SET",
	"sent bit is NOT set"
};

static const true_false_string tfs_useGKCallSignalAddressToAnswer_bit = {
	"useGKCallSignalAddressToAnswer bit is SET",
	"useGKCallSignalAddressToAnswer bit is NOT set"
};

static const true_false_string tfs_answerCall_bit = {
	"answerCall bit is SET",
	"answerCall bit is NOT set"
};

static const true_false_string tfs_useGKCallSignalAddressToMakeCall_bit = {
	"useGKCallSignalAddressToMakeCall bit is SET",
	"useGKCallSignalAddressToMakeCall bit is NOT set"
};

static const true_false_string tfs_makeCall_bit = {
	"makeCall bit is SET",
	"makeCall bit is NOT set"
};

static const true_false_string tfs_h245Tunneling_bit = {
	"h245Tunneling bit is SET",
	"h245Tunneling bit is NOT set"
};

static const true_false_string tfs_willRespondToIRR_bit = {
	"willRespondToIRR bit is SET",
	"willRespondToIRR bit is NOT set"
};

static const true_false_string tfs_keepAlive_bit = {
	"keepAlive bit is SET",
	"keepAlive bit is NOT set"
};

static const true_false_string tfs_discoveryComplete_bit = {
	"discoveryComplete bit is SET",
	"discoveryComplete bit is NOT set"
};

static const true_false_string tfs_answeredCall_bit = {
	"answeredCall bit is SET",
	"answeredCall bit is NOT set"
};

static const true_false_string tfs_canOverlapSend_bit = {
	"canOverlapSend bit is SET",
	"canOverlapSend bit is NOT set"
};

static const true_false_string tfs_mediaWaitForConnect_bit = {
	"mediaWaitForConnect bit is SET",
	"mediaWaitForConnect bit is NOT set"
};

static const true_false_string tfs_activeMC_bit = {
	"activeMC bit is SET",
	"activeMC bit is NOT set"
};

static const true_false_string tfs_canMapAlias_bit = {
	"canMapAlias bit is SET",
	"canMapAlias bit is NOT set"
};

static const true_false_string tfs_willSupplyUUIEs_bit = {
	"willSupplyUUIEs bit is SET",
	"willSupplyUUIEs bit is NOT set"
};

static const true_false_string tfs_canMapSrcAlias_bit = {
	"canMapSrcAlias bit is SET",
	"canMapSrcAlias bit is NOT set"
};

static const true_false_string tfs_enforceCallDurationLimit_bit = {
	"enforceCallDurationLimit bit is SET",
	"enforceCallDurationLimit bit is NOT set"
};

static const true_false_string tfs_almostOutOfResources_bit = {
	"almostOutOfResources bit is SET",
	"almostOutOfResources bit is NOT set"
};

static const true_false_string tfs_maintainConnection_bit = {
	"maintainConnection bit is SET",
	"maintainConnection bit is NOT set"
};

static const true_false_string tfs_multipleCalls_bit = {
	"multipleCalls bit is SET",
	"multipleCalls bit is NOT set"
};

static const true_false_string tfs_undefinedNode_bit = {
	"undefinedNode bit is SET",
	"undefinedNode bit is NOT set"
};

static const true_false_string tfs_mc_bit = {
	"mc bit is SET",
	"mc bit is NOT set"
};


static const true_false_string tfs_fastConnectRefused_bit = {
	"fastConnectRefused bit is SET",
	"fastConnectRefused bit is NOT set"
};

static const true_false_string tfs_BandwidthDetails_multicast_bit = {
	"BandwidthDetails_multicast bit is SET",
	"BandwidthDetails_multicast bit is NOT set"
};

static const true_false_string tfs_BandwidthDetails_sender_bit = {
	"BandwidthDetails_sender bit is SET",
	"BandwidthDetails_sender bit is NOT set"
};

static const true_false_string tfs_canEnforceDurationLimit_bit = {
	"canEnforceDurationLimit bit is SET",
	"canEnforceDurationLimit bit is NOT set"
};

static const true_false_string tfs_canDisplayAmountString_bit = {
	"canDisplayAmountString bit is SET",
	"canDisplayAmountString bit is NOT set"
};

static const true_false_string tfs_canReportCallCapacity_bit = {
	"canReportCallCapacity bit is SET",
	"canReportCallCapacity bit is NOT set"
};

static const true_false_string tfs_replacementFeatureSet_bit = {
	"replacementFeatureSet bit is SET",
	"replacementFeatureSet bit is NOT set"
};

static const true_false_string tfs_Content_bool_bit = {
	"Content_bool bit is SET",
	"Content_bool bit is NOT set"
};

static const true_false_string tfs_q957Full_bit = {
	"q957Full bit is SET",
	"q957Full bit is NOT set"
};

static const true_false_string tfs_q956Full_bit = {
	"q956Full bit is SET",
	"q956Full bit is NOT set"
};

static const true_false_string tfs_q955Full_bit = {
	"q955Full bit is SET",
	"q955Full bit is NOT set"
};

static const true_false_string tfs_q953Full_bit = {
	"q953Full bit is SET",
	"q953Full bit is NOT set"
};

static const true_false_string tfs_q952Full_bit = {
	"q952Full bit is SET",
	"q952Full bit is NOT set"
};

static const true_false_string tfs_q951Full_bit = {
	"q951Full bit is SET",
	"q951Full bit is NOT set"
};

static const true_false_string tfs_q932Full_bit = {
	"q932Full bit is SET",
	"q932Full bit is NOT set"
};

static const true_false_string tfs_threePartyService_bit = {
	"threePartyService bit is SET",
	"threePartyService bit is NOT set"
};

static const true_false_string tfs_conferenceCalling_bit = {
	"conferenceCalling bit is SET",
	"conferenceCalling bit is NOT set"
};

static const true_false_string tfs_notify_bool_bit = {
	"notify_bool bit is SET",
	"notify_bool bit is NOT set"
};

static const true_false_string tfs_setupAcknowledge_bool_bit = {
	"setupAcknowledge_bool bit is SET",
	"setupAcknowledge_bool bit is NOT set"
};

static const true_false_string tfs_statusInquiry_bool_bit = {
	"statusInquiry_bool bit is SET",
	"statusInquiry_bool bit is NOT set"
};

static const true_false_string tfs_status_bool_bit = {
	"status_bool bit is SET",
	"status_bool bit is NOT set"
};

static const true_false_string tfs_empty_bool_bit = {
	"empty_bool bit is SET",
	"empty_bool bit is NOT set"
};

static const true_false_string tfs_progress_bool_bit = {
	"progress_bool bit is SET",
	"progress_bool bit is NOT set"
};

static const true_false_string tfs_facility_bool_bit = {
	"facility_bool bit is SET",
	"facility_bool bit is NOT set"
};

static const true_false_string tfs_releaseComplete_bool_bit = {
	"releaseComplete_bool bit is SET",
	"releaseComplete_bool bit is NOT set"
};

static const true_false_string tfs_information_bool_bit = {
	"information_bool bit is SET",
	"information_bool bit is NOT set"
};

static const true_false_string tfs_alerting_bool_bit = {
	"alerting_bool bit is SET",
	"alerting_bool bit is NOT set"
};

static const true_false_string tfs_connect_bool_bit = {
	"connect_bool bit is SET",
	"connect_bool bit is NOT set"
};

static const true_false_string tfs_callProceeding_bool_bit = {
	"callProceeding_bool bit is SET",
	"callProceeding_bool bit is NOT set"
};

static const true_false_string tfs_setup_bool_bit = {
	"setup_bool bit is SET",
	"setup_bool bit is NOT set"
};

static const true_false_string tfs_altGKisPermanent_bit = {
	"altGKisPermanent bit is SET",
	"altGKisPermanent bit is NOT set"
};

static const true_false_string tfs_needToRegister_bit = {
	"needToRegister bit is SET",
	"needToRegister bit is NOT set"
};



static gboolean h225_reassembly = TRUE;



static int
dissect_h225_NULL(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	return offset;
}

static const value_string PresentationIndicator_vals[] = {
	{ 0, "presentationAllowed" },
	{ 1, "presentationRestricted" },
	{ 2, "addressNotAvailable" },
	{ 0, NULL}
};
static per_choice_t PresentationIndicator_choice[] = {
	{ 0, "presentationAllowed", EXTENSION_ROOT,
		dissect_h225_NULL},
	{ 1, "presentationRestricted", EXTENSION_ROOT,
		dissect_h225_NULL},
	{ 2, "addressNotAvailable", EXTENSION_ROOT,
		dissect_h225_NULL},
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_PresentationIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_PresentationIndicator, ett_h225_PresentationIndicator, PresentationIndicator_choice, "PresentationIndicator", NULL);
	return offset;
}


static const value_string conferenceGoal_vals[] = {
	{ 0, "create" },
	{ 1, "join" },
	{ 2, "invite" },
	{ 3, "capability-negotiation" },
	{ 4, "callIndependentSupplementaryService" },
	{ 0, NULL}
};
static per_choice_t conferenceGoal_choice[] = {
	{ 0, "create", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 1, "join", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 2, "invite", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 3, "capability-negotiation", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 4, "callIndependentSupplementaryService", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_conferenceGoal(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_conferenceGoal, ett_h225_conferenceGoal, conferenceGoal_choice, "conferenceGoal", NULL);
	return offset;
}


static const value_string ScnConnectionType_vals[] = {
	{ 0, "unknown" },
	{ 1, "bChannel" },
	{ 2, "hybrid2x64" },
	{ 3, "hybrid384" },
	{ 4, "hybrid1536" },
	{ 5, "hybrid1920" },
	{ 6, "multirate" },
	{ 0, NULL}
};
static per_choice_t ScnConnectionType_choice[] = {
	{ 0, "unknown", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "bChannel", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "hybrid2x64", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "hybrid384", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "hybrid1536", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "hybrid1920", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 6, "multirate", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_ScnConnectionType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_ScnConnectionType, ett_h225_ScnConnectionType, ScnConnectionType_choice, "ScnConnectionType", NULL);
	return offset;
}


static const value_string ScnConnectionAggregation_vals[] = {
	{ 0, "auto" },
	{ 1, "none" },
	{ 2, "h221" },
	{ 3, "bonded-mode1" },
	{ 4, "bonded-mode2" },
	{ 5, "bonded-mode3" },
	{ 0, NULL}
};
static per_choice_t ScnConnectionAggregation_choice[] = {
	{ 0, "auto", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "none", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "h221", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "bonded-mode1", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "bonded-mode2", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "bonded-mode3", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_ScnConnectionAggregation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_ScnConnectionAggregation, ett_h225_ScnConnectionAggregation, ScnConnectionAggregation_choice, "ScnConnectionAggregation", NULL);
	return offset;
}


static const value_string FacilityReason_vals[] = {
	{ 0, "routeCallToGatekeeper" },
	{ 1, "callForwarded" },
	{ 2, "routeCallToMC" },
	{ 3, "undefinedReason" },
	{ 4, "conferenceListChoice" },
	{ 5, "startH245" },
	{ 6, "noH245" },
	{ 7, "newTokens" },
	{ 8, "featureSetUpdate" },
	{ 9, "forwardedElements" },
	{ 10, "transportedInformation" },
	{ 0, NULL}
};
static per_choice_t FacilityReason_choice[] = {
	{ 0, "routeCallToGatekeeper", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "callForwarded", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "routeCallToMC", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "undefinedReason", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "conferenceListChoice", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "startH245", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 6, "noH245", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 7, "newTokens", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 8, "featureSetUpdate", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 9, "forwardedElements", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 10, "transportedInformation", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_FacilityReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_FacilityReason, ett_h225_FacilityReason, FacilityReason_choice, "FacilityReason", NULL);
	return offset;
}



static const value_string PublicTypeOfNumber_vals[] = {
	{ 0, "unknown" },
	{ 1, "internationalNumber" },
	{ 2, "nationalNumber" },
	{ 3, "networkSpecificNumber" },
	{ 4, "subscriberNumber" },
	{ 5, "abbreviatedNumber" },
	{ 0, NULL}
};
static per_choice_t PublicTypeOfNumber_choice[] = {
	{ 0, "unknown", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "internationalNumber", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "nationalNumber", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "networkSpecificNumber", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "subscriberNumber", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "abbreviatedNumber", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_PublicTypeOfNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_PublicTypeOfNumber, ett_h225_PublicTypeOfNumber, PublicTypeOfNumber_choice, "PublicTypeOfNumber", NULL);
	return offset;
}



static const value_string PrivateTypeOfNumber_vals[] = {
	{ 0, "unknown" },
	{ 1, "level2RegionalNumber" },
	{ 2, "level1RegionalNumber" },
	{ 3, "pISNSpecificNumber" },
	{ 4, "localNumber" },
	{ 5, "abbreviatedNumber" },
	{ 0, NULL}
};
static per_choice_t PrivateTypeOfNumber_choice[] = {
	{ 0, "unknown", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "level2RegionalNumber", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "level1RegionalNumber", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "pISNSpecificNumber", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "localNumber", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "abbreviatedNumber", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_PrivateTypeOfNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_PrivateTypeOfNumber, ett_h225_PrivateTypeOfNumber, PrivateTypeOfNumber_choice, "PrivateTypeOfNumber", NULL);
	return offset;
}


static const value_string UseSpecifiedTransport_vals[] = {
	{ 0, "tcp" },
	{ 1, "annexE" },
	{ 2, "sctp" },
	{ 0, NULL}
};
static per_choice_t UseSpecifiedTransport_choice[] = {
	{ 0, "tcp", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "annexE", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "sctp", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_UseSpecifiedTransport(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_UseSpecifiedTransport, ett_h225_UseSpecifiedTransport, UseSpecifiedTransport_choice, "UseSpecifiedTransport", NULL);
	return offset;
}



static const value_string SecurityErrors_vals[] = {
	{ 0, "securityWrongSyncTime" },
	{ 1, "securityReplay" },
	{ 2, "securityWrongGeneralID" },
	{ 3, "securityWrongSendersID" },
	{ 4, "securityIntegrityFailed" },
	{ 5, "securityWrongOID" },
	{ 6, "securityDHmismatch" },
	{ 7, "securityCertificateExpired" },
	{ 8, "securityCertificateDateInvalid" },
	{ 9, "securityCertificateRevoked" },
	{ 10, "securityCertificateNotReadable" },
	{ 11, "securityCertificateSignatureInvalid" },
	{ 12, "securityCertificateMissing" },
	{ 13, "securityCertificateIncomplete" },
	{ 14, "securityUnsupportedCertificateAlgOID" },
	{ 15, "securityUnknownCA" },
	{ 0, NULL}
};
static per_choice_t SecurityErrors_choice[] = {
	{ 0, "securityWrongSyncTime", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "securityReplay", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "securityWrongGeneralID", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "securityWrongSendersID", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "securityIntegrityFailed", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "securityWrongOID", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 6, "securityDHmismatch", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 7, "securityCertificateExpired", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 8, "securityCertificateDateInvalid", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 9, "securityCertificateRevoked", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 10, "securityCertificateNotReadable", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 11, "securityCertificateSignatureInvalid", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 12, "securityCertificateMissing", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 13, "securityCertificateIncomplete", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 14, "securityUnsupportedCertificateAlgOID", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 15, "securityUnknownCA", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_SecurityErrors(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_SecurityErrors, ett_h225_SecurityErrors, SecurityErrors_choice, "SecurityErrors", NULL);
	return offset;
}



static const value_string SecurityErrors2_vals[] = {
	{ 0, "securityWrongSyncTime" },
	{ 1, "securityReplay" },
	{ 2, "securityWrongGeneralID" },
	{ 3, "securityWrongSendersID" },
	{ 4, "securityIntegrityFailed" },
	{ 5, "securityWrongOID" },
	{ 0, NULL}
};
static per_choice_t SecurityErrors2_choice[] = {
	{ 0, "securityWrongSyncTime", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "securityReplay", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "securityWrongGeneralID", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "securityWrongSendersID", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "securityIntegrityFailed", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "securityWrongOID", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_SecurityErrors2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_SecurityErrors2, ett_h225_SecurityErrors2, SecurityErrors2_choice, "SecurityErrors2", NULL);
	return offset;
}


static const value_string ServiceControlSession_reason_vals[] = {
	{ 0, "open" },
	{ 1, "refresh" },
	{ 2, "close" },
	{ 0, NULL}
};
static per_choice_t ServiceControlSession_reason_choice[] = {
	{ 0, "open", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "refresh", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "close", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_ServiceControlSession_reason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_ServiceControlSession_reason, ett_h225_ServiceControlSession_reason, ServiceControlSession_reason_choice, "ServiceControlSession_reason", NULL);
	return offset;
}



static const value_string billingMode_vals[] = {
	{ 0, "credit" },
	{ 1, "debit" },
	{ 0, NULL}
};
static per_choice_t billingMode_choice[] = {
	{ 0, "credit", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "debit", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_billingMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_billingMode, ett_h225_billingMode, billingMode_choice, "billingMode", NULL);
	return offset;
}



static const value_string CCSCcallStartingPoint_vals[] = {
	{ 0, "alerting" },
	{ 1, "connect" },
	{ 0, NULL}
};
static per_choice_t CCSCcallStartingPoint_choice[] = {
	{ 0, "alerting", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "connect", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_CCSCcallStartingPoint(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_CCSCcallStartingPoint, ett_h225_CCSCcallStartingPoint, CCSCcallStartingPoint_choice, "CCSCcallStartingPoint", NULL);
	return offset;
}



static const value_string GatekeeperRejectReason_vals[] = {
	{ 0, "resourceUnavailable" },
	{ 1, "terminalExcluded" },
	{ 2, "invalidRevision" },
	{ 3, "undefinedReason" },
	{ 4, "securityDenial" },
	{ 5, "genericDataReason" },
	{ 6, "neededFeatureNotSupported" },
	{ 7, "securityError" },
	{ 0, NULL}
};
static per_choice_t GatekeeperRejectReason_choice[] = {
	{ 0, "resourceUnavailable", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "terminalExcluded", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "invalidRevision", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "undefinedReason", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "securityDenial", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "genericDataReason", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 6, "neededFeatureNotSupported", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 7, "securityError", NOT_EXTENSION_ROOT,
		dissect_h225_SecurityErrors },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_GatekeeperRejectReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_GatekeeperRejectReason, ett_h225_GatekeeperRejectReason, GatekeeperRejectReason_choice, "GatekeeperRejectReason", NULL);
	return offset;
}



static const value_string UnregRequestReason_vals[] = {
	{ 0, "reregistrationRequired" },
	{ 1, "ttlExpired" },
	{ 2, "securityDenial" },
	{ 3, "undefinedReason" },
	{ 4, "maintenance" },
	{ 5, "securityError" },
	{ 0, NULL}
};
static per_choice_t UnregRequestReason_choice[] = {
	{ 0, "reregistrationRequired", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "ttlExpired", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "securityDenial", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "undefinedReason", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "maintenance", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "securityError", NOT_EXTENSION_ROOT,
		dissect_h225_SecurityErrors2 },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_UnregRequestReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_UnregRequestReason, ett_h225_UnregRequestReason, UnregRequestReason_choice, "UnregRequestReason", NULL);
	return offset;
}



static const value_string UnregRejectReason_vals[] = {
	{ 0, "notCurrentlyRegistered" },
	{ 1, "callInProgress" },
	{ 2, "undefinedReason" },
	{ 3, "permissionDenied" },
	{ 4, "securityDenial" },
	{ 5, "securityError" },
	{ 0, NULL}
};
static per_choice_t UnregRejectReason_choice[] = {
	{ 0, "notCurrentlyRegistered", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "callInProgress", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "undefinedReason", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "permissionDenied", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "securityDenial", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "securityError", NOT_EXTENSION_ROOT,
		dissect_h225_SecurityErrors2 },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_UnregRejectReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_UnregRejectReason, ett_h225_UnregRejectReason, UnregRejectReason_choice, "UnregRejectReason", NULL);
	return offset;
}



static const value_string CallType_vals[] = {
	{ 0, "pointToPoint" },
	{ 1, "oneToN" },
	{ 2, "nToOne" },
	{ 3, "nToN" },
	{ 0, NULL}
};
static per_choice_t CallType_choice[] = {
	{ 0, "pointToPoint", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "oneToN", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "nToOne", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "nToN", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_CallType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_CallType, ett_h225_CallType, CallType_choice, "CallType", NULL);
	return offset;
}


static const value_string CallModel_vals[] = {
	{ 0, "direct" },
	{ 1, "gatekeeperRouted" },
	{ 0, NULL}
};
static per_choice_t CallModel_choice[] = {
	{ 0, "direct", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "gatekeeperRouted", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_CallModel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_CallModel, ett_h225_CallModel, CallModel_choice, "CallModel", NULL);
	return offset;
}



static const value_string TransportQOS_vals[] = {
	{ 0, "endpointControlled" },
	{ 1, "gatekeeperControlled" },
	{ 2, "noControl" },
	{ 0, NULL}
};
static per_choice_t TransportQOS_choice[] = {
	{ 0, "endpointControlled", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "gatekeeperControlled", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "noControl", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_TransportQOS(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_TransportQOS, ett_h225_TransportQOS, TransportQOS_choice, "TransportQOS", NULL);
	return offset;
}


static const value_string BandRejectReason_vals[] = {
	{ 0, "notBound" },
	{ 1, "invalidConferenceID" },
	{ 2, "invalidPermission" },
	{ 3, "insufficientResources" },
	{ 4, "invalidRevision" },
	{ 5, "undefinedReason" },
	{ 6, "securityDenial" },
	{ 7, "securityError" },
	{ 0, NULL}
};
static per_choice_t BandRejectReason_choice[] = {
	{ 0, "notBound", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "invalidConferenceID", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "invalidPermission", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "insufficientResources", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "invalidRevision", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "undefinedReason", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 6, "securityDenial", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 7, "securityError", NOT_EXTENSION_ROOT,
		dissect_h225_SecurityErrors2 },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_BandRejectReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_BandRejectReason, ett_h225_BandRejectReason, BandRejectReason_choice, "BandRejectReason", NULL);
	return offset;
}



static const value_string DisengageReason_vals[] = {
	{ 0, "forcedDrop" },
	{ 1, "normalDrop" },
	{ 2, "undefinedReason" },
	{ 0, NULL}
};
static per_choice_t DisengageReason_choice[] = {
	{ 0, "forcedDrop", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "normalDrop", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "undefinedReason", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_DisengageReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_DisengageReason, ett_h225_DisengageReason, DisengageReason_choice, "DisengageReason", NULL);
	return offset;
}



static const value_string DisengageRejectReason_vals[] = {
	{ 0, "notRegistered" },
	{ 1, "requestToDropOther" },
	{ 2, "securityDenial" },
	{ 3, "securityError" },
	{ 0, NULL}
};
static per_choice_t DisengageRejectReason_choice[] = {
	{ 0, "notRegistered", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "requestToDropOther", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "securityDenial", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "securityError", NOT_EXTENSION_ROOT,
		dissect_h225_SecurityErrors2 },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_DisengageRejectReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_DisengageRejectReason, ett_h225_DisengageRejectReason, DisengageRejectReason_choice, "DisengageRejectReason", NULL);
	return offset;
}




static const value_string InfoRequestNakReason_vals[] = {
	{ 0, "notRegistered" },
	{ 1, "securityDenial" },
	{ 2, "undefinedReason" },
	{ 3, "securityError" },
	{ 0, NULL}
};
static per_choice_t InfoRequestNakReason_choice[] = {
	{ 0, "notRegistered", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "securityDenial", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "undefinedReason", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "securityError", NOT_EXTENSION_ROOT,
		dissect_h225_SecurityErrors2 },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_InfoRequestNakReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_InfoRequestNakReason, ett_h225_InfoRequestNakReason, InfoRequestNakReason_choice, "InfoRequestNakReason", NULL);
	return offset;
}



static const value_string SCRresult_vals[] = {
	{ 0, "started" },
	{ 1, "failed" },
	{ 2, "stopped" },
	{ 3, "notAvailable" },
	{ 4, "neededFeatureNotSupported" },
	{ 0, NULL}
};
static per_choice_t SCRresult_choice[] = {
	{ 0, "started", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "failed", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "stopped", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "notAvailable", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "neededFeatureNotSupported", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_SCRresult(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_SCRresult, ett_h225_SCRresult, SCRresult_choice, "SCRresult", NULL);
	return offset;
}



static per_sequence_t GatekeeperInfo_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_GatekeeperInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_GatekeeperInfo, ett_h225_GatekeeperInfo, GatekeeperInfo_sequence);
	return offset;
}



static const value_string SecurityServiceMode_vals[] = {
	{ 0, "nonStandard" },
	{ 1, "none" },
	{ 2, "default" },
	{ 0, NULL}
};
static per_choice_t SecurityServiceMode_choice[] = {
	{ 0, "nonStandard", EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{ 1, "none", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "default", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_SecurityServiceMode_encryption(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_SecurityServiceMode_encryption, ett_h225_SecurityServiceMode_encryption, SecurityServiceMode_choice, "Encryption", NULL);
	return offset;
}
static int
dissect_h225_SecurityServiceMode_authentication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_SecurityServiceMode_authentication, ett_h225_SecurityServiceMode_authentication, SecurityServiceMode_choice, "Authentication", NULL);
	return offset;
}
static int
dissect_h225_SecurityServiceMode_integrity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_SecurityServiceMode_integrity, ett_h225_SecurityServiceMode_integrity, SecurityServiceMode_choice, "Integrity", NULL);
	return offset;
}



static per_sequence_t SecurityCapabilities_sequence[] = {
	{ "nonStandard", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "encryption", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SecurityServiceMode_encryption },
	{ "authenticaton", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SecurityServiceMode_authentication },
	{ "integrity", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SecurityServiceMode_integrity },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_SecurityCapabilities_tls(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_SecurityCapabilities_tls, ett_h225_SecurityCapabilities_tls, SecurityCapabilities_sequence);
	return offset;
}
static int 
dissect_h225_SecurityCapabilities_ipsec(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_SecurityCapabilities_ipsec, ett_h225_SecurityCapabilities_ipsec, SecurityCapabilities_sequence);
	return offset;
}




static const value_string H245Security_vals[] = {
	{ 0, "nonStandard" },
	{ 1, "noSecurity" },
	{ 2, "tls" },
	{ 3, "ipsec" },
	{ 0, NULL}
};
static per_choice_t H245Security_choice[] = {
	{ 0, "nonStandard", EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{ 1, "noSecurity", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "tls", EXTENSION_ROOT,
		dissect_h225_SecurityCapabilities_tls },
	{ 3, "ipsec", EXTENSION_ROOT,
		dissect_h225_SecurityCapabilities_ipsec },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_H245Security(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_H245Security, ett_h225_H245Security, H245Security_choice, "H245Security", NULL);
	return offset;
}

static int
dissect_h225_nonStandardUsageTypes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_nonStandardUsageTypes, ett_h225_nonStandardUsageTypes, dissect_h245_NonStandardParameter);
	return offset;
}


static per_sequence_t RasUsageInfoTypes_sequence[] = {
	{ "nonStandardUsageTypes", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_nonStandardUsageTypes },
	{ "startTime", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "endTime", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "terminationCause", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_RasUsageInfoTypes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_RasUsageInfoTypes, ett_h225_RasUsageInfoTypes, RasUsageInfoTypes_sequence);
	return offset;
}
static int 
dissect_h225_usageReportingCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_usageReportingCapability, ett_h225_RasUsageInfoTypes, RasUsageInfoTypes_sequence);
	return offset;
}



static int
dissect_h225_BandWidth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_BandWidth, 0, 4294967295UL,
		NULL, NULL, FALSE);
	return offset;
}



static int
dissect_h225_channelRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_channelRate, 0, 4294967295UL,
		NULL, NULL, FALSE);
	return offset;
}



static int
dissect_h225_totalBandwidthRestriction(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_totalBandwidthRestriction, 0, 4294967295UL,
		NULL, NULL, FALSE);
	return offset;
}


static int
dissect_h225_allowedBandWidth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_allowedBandWidth, 0, 4294967295UL,
		NULL, NULL, FALSE);
	return offset;
}



static int
dissect_h225_channelMultiplier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_channelMultiplier, 1, 256,
		NULL, NULL, FALSE);
	return offset;
}


static per_sequence_t DataRate_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL, 
		dissect_h245_NonStandardParameter },
	{ "channelRate", EXTENSION_ROOT, NOT_OPTIONAL, 
		dissect_h225_channelRate },
	{ "channelMultiplier", EXTENSION_ROOT, OPTIONAL, 
		dissect_h225_channelMultiplier },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_DataRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_DataRate, ett_h225_DataRate, DataRate_sequence);
	return offset;
}
static int 
dissect_h225_gatewayDataRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_gatewayDataRate, ett_h225_DataRate, DataRate_sequence);
	return offset;
}


static int
dissect_h225_dataRatesSupported(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_dataRatesSupported, ett_h225_dataRatesSupported, dissect_h225_DataRate );
	return offset;
}


static per_sequence_t TerminalInfo_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL, 
		dissect_h245_NonStandardParameter },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_TerminalInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_TerminalInfo, ett_h225_TerminalInfo, TerminalInfo_sequence);
	return offset;
}


static int
dissect_h225_h248Message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_h248Message, -1, -1);
	return offset;
}


static per_sequence_t StimulusControl_sequence[] = {
	{ "nonStandard", EXTENSION_ROOT, OPTIONAL, 
		dissect_h245_NonStandardParameter },
	{ "isText", EXTENSION_ROOT, OPTIONAL, 
		dissect_h225_NULL },
	{ "h248Message", EXTENSION_ROOT, OPTIONAL, 
		dissect_h225_h248Message},
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_StimulusControl(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_StimulusControl, ett_h225_StimulusControl, StimulusControl_sequence);
	return offset;
}




static int
dissect_h225_conferenceID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_conferenceID, 16, 16);
	return offset;
}



static int
dissect_h225_replaceWithConferenceInvite(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_replaceWithConferenceInvite, 16, 16);
	return offset;
}


static const value_string ReleaseCompleteReason_vals[] = {
	{ 0, "noBandwidth" },
	{ 1, "gatekeeperResources" },
	{ 2, "unreachableDestination" },
	{ 3, "destinationRejection" },
	{ 4, "invalidRevision" },
	{ 5, "noPermission" },
	{ 6, "unreachableGatekeeper" },
	{ 7, "gatewayResources" },
	{ 8, "badFormatAddress" },
	{ 9, "adaptiveBusy" },
	{ 10, "inConf" },
	{ 11, "undefinedReason" },
	{ 12, "facilityCallDeflection" },
	{ 13, "securityDenied" },
	{ 14, "calledPartyNotRegistered" },
	{ 15, "callerNotRegistered" },
	{ 16, "newConnectionNeeded" },
	{ 17, "nonStandardReason" },
	{ 18, "replaceWithConferenceInvite" },
	{ 19, "genericDataReason" },
	{ 20, "neededFeatureNotSupported" },
	{ 21, "tunnelledSignallingRejected" },
	{ 22, "invalidCID" },
	{ 23, "invalidCID" },
	{ 24, "securityError" },
	{ 25, "hopCountExceeded" },
	{ 0, NULL}
};
static per_choice_t ReleaseCompleteReason_choice[] = {
	{ 0, "noBandwidth", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 1, "gatekeeperResources", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 2, "unreachableDestination", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 3, "destinationRejection", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 4, "invalidRevision", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 5, "noPermission", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 6, "unreachableGatekeeper", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 7, "gatewayResources", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 8, "badFormatAddress", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 9, "adaptiveBusy", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 10, "inConf", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 11, "undefinedReason", EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 12, "facilityCallDeflection", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 13, "securityDenied", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 14, "calledPartyNotRegistered", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 15, "callerNotRegistered", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 16, "newConnectionNeeded", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 17, "nonStandardReason", NOT_EXTENSION_ROOT, 
		dissect_h245_NonStandardParameter },
	{ 18, "replaceWithConferenceInvite", NOT_EXTENSION_ROOT, 
		dissect_h225_replaceWithConferenceInvite },
	{ 19, "genericDataReason", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 20, "neededFeatureNotSupported", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 21, "tunnelledSignallingRejected", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 22, "invalidCID", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 23, "invalidCID", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 24, "securityError", NOT_EXTENSION_ROOT, 
		dissect_h225_SecurityErrors },
	{ 25, "hopCountExceeded", NOT_EXTENSION_ROOT, 
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_ReleaseCompleteReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_ReleaseCompleteReason, ett_h225_ReleaseCompleteReason, ReleaseCompleteReason_choice, "ReleaseCompleteReason", NULL);
	return offset;
}



static int
dissect_h225_numberOfScnConnections(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_numberOfScnConnections, 0, 65535,
		NULL, NULL, FALSE);
	return offset;
}

static per_sequence_t connectionParameters_sequence[] = {
	{ "connectionType", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ScnConnectionType },
	{ "numberOfScnConnections", EXTENSION_ROOT, NOT_OPTIONAL, 
		dissect_h225_numberOfScnConnections },
	{ "connectionAggregation", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ScnConnectionAggregation },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_connectionParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_connectionParameters, ett_h225_connectionParameters, connectionParameters_sequence);
	return offset;
}




static int
dissect_h225_RequestSeqNum(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_RequestSeqNum, 1, 65535,
		NULL, NULL, FALSE);
	return offset;
}

static per_sequence_t RasUsageSpecification_when_sequence[] = {
	{ "start", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "end", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "inIrr", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_RasUsageSpecification_when(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_RasUsageSpecification_when, ett_h225_RasUsageSpecification_when, RasUsageSpecification_when_sequence);
	return offset;
}



static per_sequence_t RasUsageSpecification_callStartingPoint_sequence[] = {
	{ "alerting", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "connect", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_RasUsageSpecification_callStartingPoint(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_RasUsageSpecification_callStartingPoint, ett_h225_RasUsageSpecification_callStartingPoint, RasUsageSpecification_callStartingPoint_sequence);
	return offset;
}




static per_sequence_t RasUsageSpecification_sequence[] = {
	{ "when", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RasUsageSpecification_when },
	{ "callStartingPoint", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_RasUsageSpecification_callStartingPoint },
	{ "required", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RasUsageInfoTypes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_RasUsageSpecification(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_RasUsageSpecification, ett_h225_RasUsageSpecification, RasUsageSpecification_sequence);
	return offset;
}




static int
dissect_h225_ipAddress_ip(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 ip;

	/* byte aligned */
	if(offset&0x07){
		offset=(offset&0xfffffff8)+8;
	}
	ip=tvb_get_letohl(tvb, offset>>3);
	proto_tree_add_ipv4(tree, hf_h225_ipAddress_ip, tvb, offset>>3, 4, ip);
	
	offset+=32;
	return offset;
}



static int
dissect_h225_ipAddress_port(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_ipAddress_port, 0, 65535,
		NULL, NULL, FALSE);
	return offset;
}



static per_sequence_t ipAddress_sequence[] = {
	{ "ip", NO_EXTENSIONS, NOT_OPTIONAL, 
		dissect_h225_ipAddress_ip },
	{ "port", NO_EXTENSIONS, NOT_OPTIONAL, 
		dissect_h225_ipAddress_port },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ipAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ipAddress, ett_h225_ipAddress, ipAddress_sequence);
	return offset;
}



static const value_string routing_vals[] = {
	{ 0, "strict" },
	{ 1, "loose" },
	{ 0, NULL}
};
static per_choice_t routing_choice[] = {
	{ 0, "strict", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "loose", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_routing(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_routing, ett_h225_routing, routing_choice, "routing", NULL);
	return offset;
}




static int
dissect_h225_route(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_route, ett_h225_route, dissect_h225_ipAddress_ip );
	return offset;
}

static per_sequence_t ipSourceRoute_sequence[] = {
	{ "ip", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ipAddress_ip },
	{ "port", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ipAddress_port },
	{ "route", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_route },
	{ "routing", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_routing },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ipSourceRoute(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ipSourceRoute, ett_h225_ipSourceRoute, ipSourceRoute_sequence);
	return offset;
}




static int
dissect_h225_ipxNode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_ipxNode, 6, 6);
	return offset;
}



static int
dissect_h225_ipxNetnum(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_ipxNetnum, 4, 4);
	return offset;
}


static int
dissect_h225_ipxPort(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_ipxPort, 2, 2);
	return offset;
}

static per_sequence_t ipxAddress_sequence[] = {
	{ "node", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_ipxNode },
	{ "netnum", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_ipxNetnum },
	{ "port", NO_EXTENSIONS, NOT_OPTIONAL, 
		dissect_h225_ipxPort },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ipxAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ipxAddress, ett_h225_ipxAddress, ipxAddress_sequence);
	return offset;
}


static int
dissect_h225_ipv6Address_ip(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_ipv6Address_ip, 16, 16);
	return offset;
}

static int
dissect_h225_ipv6Address_port(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_ipv6Address_port, 0, 65535,
		NULL, NULL, FALSE);
	return offset;
}



static per_sequence_t ip6Address_sequence[] = {
	{ "ip", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ipv6Address_ip },
	{ "port", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ipv6Address_port },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ip6Address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ip6Address, ett_h225_ip6Address, ip6Address_sequence);
	return offset;
}




static int
dissect_h225_netBios(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_netBios, 16, 16);
	return offset;
}




static int
dissect_h225_nsap(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_nsap, 1, 20);
	return offset;
}



static const value_string TransportAddress_vals[] = {
	{ 0, "ipAddress" },
	{ 1, "ipSourceRoute" },
	{ 2, "ipxAddress" },
	{ 3, "ip6Address" },
	{ 4, "netBios" },
	{ 5, "nsap" },
	{ 6, "nonStandardAddress" },
	{ 0, NULL}
};
static per_choice_t TransportAddress_choice[] = {
	{ 0, "ipAddress", EXTENSION_ROOT,
		dissect_h225_ipAddress },
	{ 1, "ipSourceRoute", EXTENSION_ROOT,
		dissect_h225_ipSourceRoute },
	{ 2, "ipxAddress", EXTENSION_ROOT,
		dissect_h225_ipxAddress },
	{ 3, "ip6Address", EXTENSION_ROOT,
		dissect_h225_ip6Address },
	{ 4, "netBios", EXTENSION_ROOT,
		dissect_h225_netBios },
	{ 5, "nsap", EXTENSION_ROOT,
		dissect_h225_nsap },
	{ 6, "nonStandardAddress", EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_transportID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_transportID, ett_h225_TransportAddress, TransportAddress_choice, "transportID", NULL);
	return offset;
}
static int
dissect_h225_alternativeAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_alternativeAddress, ett_h225_TransportAddress, TransportAddress_choice, "alternativeAddress", NULL);
	return offset;
}
static int
dissect_h225_sourceCallSignalAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_sourceCallSignalAddress, ett_h225_TransportAddress, TransportAddress_choice, "sourceCallSignalAddress", NULL);
	return offset;
}
static int
dissect_h225_CallSignalAddress2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_CallSignalAddress2, ett_h225_TransportAddress, TransportAddress_choice, "CallSignalAddress2", NULL);
	return offset;
}
static int
dissect_h225_destCallSignalAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_destCallSignalAddress, ett_h225_TransportAddress, TransportAddress_choice, "destCallSignalAddress", NULL);
	return offset;
}
static int
dissect_h225_h245Address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_h245Address, ett_h225_TransportAddress, TransportAddress_choice, "h245Address", NULL);
	return offset;
}
static int
dissect_h225_sendAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_sendAddress, ett_h225_TransportAddress, TransportAddress_choice, "sendAddress", NULL);
	return offset;
}
static int
dissect_h225_recvAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_recvAddress, ett_h225_TransportAddress, TransportAddress_choice, "recvAddress", NULL);
	return offset;
}
static int
dissect_h225_rasAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_rasAddress, ett_h225_TransportAddress, TransportAddress_choice, "rasAddress", NULL);
	return offset;
}
static int
dissect_h225_replyAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_replyAddress, ett_h225_TransportAddress, TransportAddress_choice, "replyAddress", NULL);
	return offset;
}
static int
dissect_h225_TransportAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_TransportAddress, ett_h225_TransportAddress, TransportAddress_choice, "TransportAddress", NULL);
	return offset;
}


static per_sequence_t TransportChannelInfo_sequence[] = {
	{ "sendAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_sendAddress },
	{ "recvAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_recvAddress },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_rtpAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_rtpAddress, ett_h225_TransportChannelInfo, TransportChannelInfo_sequence);
	return offset;
}
static int 
dissect_h225_rtcpAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_rtcpAddress, ett_h225_TransportChannelInfo, TransportChannelInfo_sequence);
	return offset;
}
static int 
dissect_h225_h245(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_h245, ett_h225_TransportChannelInfo, TransportChannelInfo_sequence);
	return offset;
}
static int 
dissect_h225_callSignaling(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_callSignaling, ett_h225_TransportChannelInfo, TransportChannelInfo_sequence);
	return offset;
}

static int
dissect_h225_carrierName(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_carrierName, 1, 128);
	return offset;
}



static int
dissect_h225_carrierIdentificationCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_carrierIdentificationCode, 3, 4);
	return offset;
}

static per_sequence_t CarrierInfo_sequence[] = {
	{ "carrierIdentificationCode", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_carrierIdentificationCode },
	{ "carrierName", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_carrierName },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CarrierInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CarrierInfo, ett_h225_CarrierInfo, CarrierInfo_sequence);
	return offset;
}

static int
dissect_h225_segment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_segment, 0, 65535,
		NULL, NULL, FALSE);
	return offset;
}


static const value_string InfoRequestResponseStatus_vals[] = {
	{ 0, "complete" },
	{ 1, "incomplete" },
	{ 2, "segment" },
	{ 3, "invalidCall" },
	{ 0, NULL}
};
static per_choice_t InfoRequestResponseStatus_choice[] = {
	{ 0, "complete", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "incomplete", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "segment", EXTENSION_ROOT,
		dissect_h225_segment },
	{ 3, "invalidCall", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_InfoRequestResponseStatus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_InfoRequestResponseStatus, ett_h225_InfoRequestResponseStatus, InfoRequestResponseStatus_choice, "InfoRequestResponseStatus", NULL);
	return offset;
}




static int
dissect_h225_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_guid, 16, 16);
	return offset;
}

static per_sequence_t CallIdentifier_sequence[] = {
	{ "guid", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_guid },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CallIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CallIdentifier, ett_h225_CallIdentifier, CallIdentifier_sequence);
	return offset;
}


static int
dissect_h225_globalCallId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_globalCallId, 16, 16);
	return offset;
}


static int
dissect_h225_threadId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_threadId, 16, 16);
	return offset;
}


static per_sequence_t CallLinkage_sequence[] = {
	{ "globalCallId", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_globalCallId },
	{ "threadId", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_threadId },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CallLinkage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CallLinkage, ett_h225_CallLinkage, CallLinkage_sequence);
	return offset;
}



static int 
dissect_h225_ClearToken(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_)
{
NOT_DECODED_YET("ClearToken");
	return offset;
}

static int
dissect_h225_tokens(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_tokens, ett_h225_tokens, dissect_h225_ClearToken);
	return offset;
}


static int
dissect_h225_needToRegister(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_needToRegister, NULL, NULL);
	return offset;
}

static int
dissect_h225_priority(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_priority, 0, 127,
		NULL, NULL, FALSE);
	return offset;
}



static int
dissect_h225_GatekeeperIdentifier(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	offset=dissect_per_BMPString(tvb, offset, pinfo, tree, hf_h225_GatekeeperIdentifier, 1, 128);
	return offset;
}

static per_sequence_t AlternateGK_sequence[] = {
	{ "rasAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_rasAddress },
	{ "gatekeeperIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "needToRegister", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_needToRegister },
	{ "priority", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_priority },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_AlternateGK(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_AlternateGK, ett_h225_AlternateGK, AlternateGK_sequence);
	return offset;
}

static int
dissect_h225_alternateGatekeeper(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_alternateGatekeeper, ett_h225_alternateGatekeeper, dissect_h225_AlternateGK);
	return offset;
}

static int
dissect_h225_altGKisPermanent(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_altGKisPermanent, NULL, NULL);
	return offset;
}

static per_sequence_t AltGKInfo_sequence[] = {
	{ "alternateGatekeeper", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_alternateGatekeeper },
	{ "altGKisPermanent", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_altGKisPermanent },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_AltGKInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_AltGKInfo, ett_h225_AltGKInfo, AltGKInfo_sequence);
	return offset;
}

static int
dissect_h225_annexE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_annexE, ett_h225_annexE, dissect_h225_TransportAddress);
	return offset;
}

static int
dissect_h225_sctp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_sctp, ett_h225_sctp, dissect_h225_TransportAddress);
	return offset;
}
static per_sequence_t AlternateTransportAddress_sequence[] = {
	{ "annexE", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_annexE },
	{ "sctp", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_sctp },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_AlternateTransportAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_AlternateTransportAddress, ett_h225_AlternateTransportAddress, AlternateTransportAddress_sequence);
	return offset;
}

static int
dissect_h225_callProceeding_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_callProceeding_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_setup_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_setup_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_connect_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_connect_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_alerting_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_alerting_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_information_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_information_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_releaseComplete_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_releaseComplete_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_facility_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_facility_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_progress_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_progress_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_empty_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_empty_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_status_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_status_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_statusInquiry_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_statusInquiry_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_setupAcknowledge_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_setupAcknowledge_bool, NULL, NULL);
	return offset;
}
static int
dissect_h225_notify_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_notify_bool, NULL, NULL);
	return offset;
}


static per_sequence_t UUIEsRequested_sequence[] = {
	{ "setup", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_setup_bool },
	{ "callProceeding", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_callProceeding_bool },
	{ "connect", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_connect_bool },
	{ "alerting", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_alerting_bool },
	{ "information", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_information_bool },
	{ "releaseComplete", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_releaseComplete_bool },
	{ "facility", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_facility_bool },
	{ "progress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_progress_bool },
	{ "empty", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_empty_bool },
	{ "status", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_status_bool },
	{ "statusInquiry", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_statusInquiry_bool },
	{ "setupAcknowledge", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_setupAcknowledge_bool },
	{ "notify", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_notify_bool },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_UUIEsRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_UUIEsRequested, ett_h225_UUIEsRequested, UUIEsRequested_sequence);
	return offset;
}

static int
dissect_h225_conferenceCalling(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_conferenceCalling, NULL, NULL);
	return offset;
}



static int
dissect_h225_threePartyService(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_threePartyService, NULL, NULL);
	return offset;
}


static per_sequence_t Q954Details_sequence[] = {
	{ "conferenceCalling", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_conferenceCalling },
	{ "threePartyService", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_threePartyService },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_Q954Info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_Q954Details, ett_h225_Q954Details, Q954Details_sequence);
	return offset;
}

static int
dissect_h225_q932Full(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_q932Full, NULL, NULL);
	return offset;
}


static int
dissect_h225_q951Full(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_q951Full, NULL, NULL);
	return offset;
}

static int
dissect_h225_q952Full(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_q952Full, NULL, NULL);
	return offset;
}

static int
dissect_h225_q953Full(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_q953Full, NULL, NULL);
	return offset;
}

static int
dissect_h225_q955Full(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_q955Full, NULL, NULL);
	return offset;
}

static int
dissect_h225_q956Full(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_q956Full, NULL, NULL);
	return offset;
}


static int
dissect_h225_q957Full(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_q957Full, NULL, NULL);
	return offset;
}

static per_sequence_t QseriesOptions_sequence[] = {
	{ "q932Full", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_q932Full },
	{ "q951Full", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_q951Full },
	{ "q952Full", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_q952Full },
	{ "q953Full", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_q953Full },
	{ "q955Full", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_q955Full },
	{ "q956Full", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_q956Full },
	{ "q957Full", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_q957Full },
	{ "q954Info", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_Q954Info },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_callServices(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_QseriesOptions, ett_h225_QseriesOptions, QseriesOptions_sequence);
	return offset;
}

static int
dissect_h225_cname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_PrintableString(tvb, offset, pinfo, tree, hf_h225_cname, -1, -1);
	return offset;
}


static int
dissect_h225_ssrc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_ssrc, 1, 4294967295UL,
		NULL, NULL, FALSE);
	return offset;
}


static int
dissect_h225_RTPsessionId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_RTPsessionId, 1, 255,
		NULL, NULL, FALSE);
	return offset;
}

static int
dissect_h225_associatedSessionIds(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_associatedSessionIds, ett_h225_associatedSessionIds, dissect_h225_RTPsessionId);
	return offset;
}
static per_sequence_t RTPSession_sequence[] = {
	{ "rtpAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_rtpAddress },
	{ "rtcpAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_rtcpAddress },
	{ "cname", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_cname },
	{ "ssrc", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ssrc },
	{ "sessionId", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RTPsessionId },
	{ "associatedSessionIds", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_associatedSessionIds },
	{ "multicast", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "bandwidth", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_BandWidth },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_RTPSession(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_RTPSession, ett_h225_RTPSession, RTPSession_sequence);
	return offset;
}

static int 
dissect_h225_CryptoH323Token(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
NOT_DECODED_YET("CryptoH323Token");
	return offset;
}


static int
dissect_h225_cryptoTokens(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_cryptoTokens, ett_h225_cryptoTokens, dissect_h225_CryptoH323Token);
	return offset;
}


static int
dissect_h225_ProtocolIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h225_ProtocolIdentifier);
	return offset;
}

static per_sequence_t StatusUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "callIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_StatusUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_StatusUUIE, ett_h225_StatusUUIE, StatusUUIE_sequence);
	return offset;
}
static per_sequence_t StatusInquiryUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "callIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_StatusInquiryUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_StatusInquiryUUIE, ett_h225_StatusInquiryUUIE, StatusInquiryUUIE_sequence);
	return offset;
}
static per_sequence_t SetupAcknowledgeUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "callIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_SetupAcknowledgeUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_SetupAcknowledgeUUIE, ett_h225_SetupAcknowledgeUUIE, SetupAcknowledgeUUIE_sequence);
	return offset;
}
static per_sequence_t NotifyUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "callIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_NotifyUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_NotifyUUIE, ett_h225_NotifyUUIE, NotifyUUIE_sequence);
	return offset;
}

static int
dissect_h225_imsi(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_imsi, 3, 16, "#*0123456789ABC", 15);

	return offset;
}


static int
dissect_h225_tmsi(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_tmsi, 1, 4);
	return offset;
}


static int
dissect_h225_msisdn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_msisdn, 3, 16, "#*0123456789ABC", 15);

	return offset;
}


static int
dissect_h225_imei(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_imei, 15, 16, "#*0123456789ABC", 15);

	return offset;
}

static int
dissect_h225_hplmn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_hplmn, 1, 4, "#*0123456789ABC", 15);

	return offset;
}

static int
dissect_h225_vplmn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_vplmn, 1, 4, "#*0123456789ABC", 15);
	return offset;
}


static per_sequence_t GSMUIM_sequence[] = {
	{ "imsi", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_imsi },
	{ "tmsi", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tmsi },
	{ "msisdn", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_msisdn },
	{ "imei", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_imei },
	{ "hplmn", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_hplmn },
	{ "vplmn", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_vplmn },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_GSMUIM(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_GSMUIM, ett_h225_GSMUIM, GSMUIM_sequence);
	return offset;
}

static int
dissect_h225_sid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_sid, 1, 4, "#*0123456789ABC", 15);
	return offset;
}


static int
dissect_h225_mid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_mid, 1, 4, "#*0123456789ABC", 15);
	return offset;
}

static const value_string systemid_vals[] = {
	{ 0, "sid" },
	{ 1, "mid" },
	{ 0, NULL}
};
static per_choice_t systemid_choice[] = {
	{ 0, "sid", EXTENSION_ROOT,
		dissect_h225_sid },
	{ 1, "mid", EXTENSION_ROOT,
		dissect_h225_mid },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_systemid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_systemid, ett_h225_systemid, systemid_choice, "systemid", NULL);
	return offset;
}



static int
dissect_h225_min(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_mid, 3, 16, "#*0123456789ABC", 15);
	return offset;
}


static int
dissect_h225_mdn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_mdn, 3, 16, "#*0123456789ABC", 15);
	return offset;
}

static int
dissect_h225_esn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_esn, 16, 16, "#*0123456789ABC", 15);

	return offset;
}

static int
dissect_h225_mscid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_mscid, 3, 16, "#*0123456789ABC", 15);

	return offset;
}


static int
dissect_h225_systemMyTypeCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_systemMyTypeCode, 1, 1);
	return offset;
}

static int
dissect_h225_systemAccessType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_systemAccessType, 1, 1);
	return offset;
}

static int
dissect_h225_qualificationInformationCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_qualificationInformationCode, 1, 1);
	return offset;
}

static int
dissect_h225_sesn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_sesn, 16, 16, "#*0123456789ABC", 15);
	return offset;
}


static int
dissect_h225_soc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_soc, 3, 16, "#*0123456789ABC", 15);

	return offset;
}

static per_sequence_t ANSI41UIM_sequence[] = {
	{ "imsi", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_imsi },
	{ "min", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_min },
	{ "mdn", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_mdn },
	{ "msisdn", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_msisdn },
	{ "esn", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_esn },
	{ "mscid", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_mscid },
	{ "systemid", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_systemid },
	{ "systemMyTypeCode", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_systemMyTypeCode },
	{ "systemAccessType", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_systemAccessType },
	{ "qualificationInformationCode", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_qualificationInformationCode },
	{ "sesn", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_sesn },
	{ "soc", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_soc },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ANSI41UIM(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ANSI41UIM, ett_h225_ANSI41UIM, ANSI41UIM_sequence);
	return offset;
}


static const value_string MobileUIM_vals[] = {
	{ 0, "ansi41uim" },
	{ 1, "gsmuim" },
	{ 0, NULL}
};
static per_choice_t MobileUIM_choice[] = {
	{ 0, "ansi41uim", EXTENSION_ROOT,
		dissect_h225_ANSI41UIM },
	{ 1, "gsmuim", EXTENSION_ROOT,
		dissect_h225_GSMUIM },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_MobileUIM(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_MobileUIM, ett_h225_MobileUIM, MobileUIM_choice, "MobileUIM", NULL);
	return offset;
}


static int
dissect_h225_dataPartyNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_dataPartyNumber, 1, 128, "#*,0123456789", 13);

	return offset;
}

static int
dissect_h225_telexPartyNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_telexPartyNumber, 1, 128, "#*,0123456789", 13);
	return offset;
}



static int
dissect_h225_nationalStandardPartyNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_nationalStandardPartyNumber, 1, 128, "#*,0123456789", 13);
	return offset;
}

static int
dissect_h225_publicNumberDigits(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_publicNumberDigits, 1, 128, "#*,0123456789", 13);
	return offset;
}


static int
dissect_h225_privateNumberDigits(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_privateNumberDigits, 1, 128, "#*,0123456789", 13);
	return offset;
}


static per_sequence_t e164Number_sequence[] = {
	{ "publicTypeOfNumber", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_PublicTypeOfNumber },
	{ "publicNumberDigits", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_publicNumberDigits },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_e164Number(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_e164Number, ett_h225_e164Number, e164Number_sequence);
	return offset;
}
static per_sequence_t privateNumber_sequence[] = {
	{ "privateTypeOfNumber", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_PrivateTypeOfNumber },
	{ "privateNumberDigits", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_privateNumberDigits },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_privateNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_privateNumber, ett_h225_privateNumber, privateNumber_sequence);
	return offset;
}

static const value_string PartyNumber_vals[] = {
	{ 0, "e164Number" },
	{ 1, "dataPartyNumber" },
	{ 2, "telexPartyNumber" },
	{ 3, "privateNumber" },
	{ 4, "nationalStandardPartyNumber" },
	{ 0, NULL}
};
static per_choice_t PartyNumber_choice[] = {
	{ 0, "e164Number", EXTENSION_ROOT,
		dissect_h225_e164Number },
	{ 1, "dataPartyNumber", EXTENSION_ROOT,
		dissect_h225_dataPartyNumber },
	{ 2, "telexPartyNumber", EXTENSION_ROOT,
		dissect_h225_telexPartyNumber },
	{ 3, "privateNumber", EXTENSION_ROOT,
		dissect_h225_privateNumber },
	{ 4, "nationalStandardPartyNumber", EXTENSION_ROOT,
		dissect_h225_nationalStandardPartyNumber },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_PartyNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_PartyNumber, ett_h225_PartyNumber, PartyNumber_choice, "PartyNumber", NULL);
	return offset;
}
static int
dissect_h225_startOfRange(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_startOfRange, ett_h225_PartyNumber, PartyNumber_choice, "startOfRange", NULL);
	return offset;
}
static int
dissect_h225_endOfRange(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_endOfRange, ett_h225_PartyNumber, PartyNumber_choice, "endOfRange", NULL);
	return offset;
}

static int
dissect_h225_protocolType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_protocolType, 1, 64);
	return offset;
}

static int
dissect_h225_protocolVariant(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_protocolVariant, 1, 64);
	return offset;
}
static per_sequence_t TunnelledProtocolAlternateIdentifier_sequence[] = {
	{ "protocolType", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_protocolType },
	{ "protocolVariant", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_protocolVariant },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_TunnelledProtocolAlternateIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_TunnelledProtocolAlternateIdentifier, ett_h225_TunnelledProtocolAlternateIdentifier, TunnelledProtocolAlternateIdentifier_sequence);
	return offset;
}

static int
dissect_h225_dialedDigits(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h225_privateNumberDigits, 1, 128, "#,*0123456789", 13);

	return offset;
}

static int
dissect_h225_h323Id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_BMPString(tvb, offset, pinfo, tree, hf_h225_h323ID, 1, 256);
	return offset;
}

static int
dissect_h225_urlId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_urlId, 1, 512);
	return offset;
}


static int
dissect_h225_emailId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_emailId, 1, 512);
	return offset;
}


static const value_string AliasAddress_vals[] = {
	{ 0, "dialedDigits" },
	{ 1, "h323ID" },
	{ 2, "urlID" },
	{ 3, "transportID" },
	{ 4, "emailID" },
	{ 5, "partyNumber" },
	{ 6, "mobileUIM" },
	{ 0, NULL}
};
static per_choice_t AliasAddress_choice[] = {
	{ 0, "dialedDigits", EXTENSION_ROOT,
		dissect_h225_dialedDigits },
	{ 1, "h323ID", EXTENSION_ROOT,
		dissect_h225_h323Id },
	{ 2, "urlID", NOT_EXTENSION_ROOT,
		dissect_h225_urlId },
	{ 3, "transportID", NOT_EXTENSION_ROOT,
		dissect_h225_transportID },
	{ 4, "emailID", NOT_EXTENSION_ROOT,
		dissect_h225_emailId },
	{ 5, "partyNumber", NOT_EXTENSION_ROOT,
		dissect_h225_PartyNumber },
	{ 6, "mobileUIM", NOT_EXTENSION_ROOT,
		dissect_h225_MobileUIM },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_AliasAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_AliasAddress, ett_h225_AliasAddress, AliasAddress_choice, "AliasAddress", NULL);
	return offset;
}
static int
dissect_h225_featureServerAlias(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_featureServerAlias, ett_h225_AliasAddress, AliasAddress_choice, "featureServerAlias", NULL);
	return offset;
}
static int
dissect_h225_RemoteExtensionAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_RemoteExtensionAddress, ett_h225_AliasAddress, AliasAddress_choice, "RemoteExtensionAddress", NULL);
	return offset;
}
static int
dissect_h225_conferenceAlias(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_conferenceAlias, ett_h225_AliasAddress, AliasAddress_choice, "conferenceAlias", NULL);
	return offset;
}
static int
dissect_h225_wildcard(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_wildcard, ett_h225_AliasAddress, AliasAddress_choice, "wildcard", NULL);
	return offset;
}
static int
dissect_h225_prefix(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_prefix, ett_h225_AliasAddress, AliasAddress_choice, "prefix", NULL);
	return offset;
}

static per_sequence_t SupportedPrefix_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "prefix", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_prefix },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_SupportedPrefix(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_SupportedPrefix, ett_h225_SupportedPrefix, SupportedPrefix_sequence);
	return offset;
}

static int
dissect_h225_SupportedPrefixes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_SupportedPrefixes, ett_h225_SupportedPrefixes, dissect_h225_SupportedPrefix);
	return offset;
}


static per_sequence_t H310Caps_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_H310Caps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_H310Caps, ett_h225_H310Caps, H310Caps_sequence);
	return offset;
}


static per_sequence_t H320Caps_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_H320Caps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_H320Caps, ett_h225_H320Caps, H320Caps_sequence);
	return offset;
}


static per_sequence_t H321Caps_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_H321Caps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_H321Caps, ett_h225_H321Caps, H321Caps_sequence);
	return offset;
}


static per_sequence_t H322Caps_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_H322Caps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_H322Caps, ett_h225_H322Caps, H322Caps_sequence);
	return offset;
}


static per_sequence_t H323Caps_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_H323Caps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_H323Caps, ett_h225_H323Caps, H323Caps_sequence);
	return offset;
}


static per_sequence_t H324Caps_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_H324Caps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_H324Caps, ett_h225_H324Caps, H324Caps_sequence);
	return offset;
}


static per_sequence_t VoiceCaps_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_VoiceCaps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_VoiceCaps, ett_h225_VoiceCaps, VoiceCaps_sequence);
	return offset;
}


static per_sequence_t T120OnlyCaps_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_T120OnlyCaps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_T120OnlyCaps, ett_h225_T120OnlyCaps, T120OnlyCaps_sequence);
	return offset;
}

static per_sequence_t NonStandardProtocol_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_NonStandardProtocol(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_NonStandardProtocol, ett_h225_NonStandardProtocol, NonStandardProtocol_sequence);
	return offset;
}


static per_sequence_t SIPCaps_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_SIPCaps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_SIPCaps, ett_h225_SIPCaps, SIPCaps_sequence);
	return offset;
}

static per_sequence_t AddressPattern_range_sequence[] = {
	{ "startOfRange", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_startOfRange },
	{ "endOfRange", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_endOfRange },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_AddressPattern_range(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_AddressPattern_range, ett_h225_AddressPattern_range, AddressPattern_range_sequence);
	return offset;
}


static const value_string AddressPattern_vals[] = {
	{ 0, "wildcard" },
	{ 1, "range" },
	{ 0, NULL}
};
static per_choice_t AddressPattern_choice[] = {
	{ 0, "wildcard", EXTENSION_ROOT,
		dissect_h225_wildcard },
	{ 0, "range", EXTENSION_ROOT,
		dissect_h225_AddressPattern_range },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_AddressPattern(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_AddressPattern, ett_h225_AddressPattern, AddressPattern_choice, "AddressPattern", NULL);
	return offset;
}
static per_sequence_t ConferenceList_sequence[] = {
	{ "conferenceID", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_conferenceID },
	{ "conferenceAlias", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_conferenceAlias },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ConferenceList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ConferenceList, ett_h225_ConferenceList, ConferenceList_sequence);
	return offset;
}

static int
dissect_h225_conferences(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_conferences, ett_h225_conferences, dissect_h225_ConferenceList);
	return offset;
}
static per_sequence_t T38FaxAnnexbOnlyCaps_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "dataRatesSupported", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_dataRatesSupported },
	{ "supportedPrefixes", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ "t38FaxProtocol", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h245_DataProtocolCapability },
	{ "t38FaxProfile", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h245_T38FaxProfile },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_T38FaxAnnexbOnlyCaps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_T38FaxAnnexbOnlyCaps, ett_h225_T38FaxAnnexbOnlyCaps, T38FaxAnnexbOnlyCaps_sequence);
	return offset;
}


static const value_string SupportedProtocols_vals[] = {
	{ 0, "nonStandardData" },
	{ 1, "h310" },
	{ 2, "h320" },
	{ 3, "h321" },
	{ 4, "h322" },
	{ 5, "h323" },
	{ 6, "h324" },
	{ 7, "voice" },
	{ 8, "t120-only" },
	{ 9, "nonStandardProtocol" },
	{ 10, "t38FaxAnnexbOnly" },
	{ 11, "sip" },
	{ 0, NULL}
};
static per_choice_t SupportedProtocols_choice[] = {
	{ 0, "nonStandardData", EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{ 1, "h310", EXTENSION_ROOT,
		dissect_h225_H310Caps },
	{ 2, "h320", EXTENSION_ROOT,
		dissect_h225_H320Caps },
	{ 3, "h321", EXTENSION_ROOT,
		dissect_h225_H321Caps },
	{ 4, "h322", EXTENSION_ROOT,
		dissect_h225_H322Caps },
	{ 5, "h323", EXTENSION_ROOT,
		dissect_h225_H323Caps },
	{ 6, "h324", EXTENSION_ROOT,
		dissect_h225_H324Caps },
	{ 7, "voice", EXTENSION_ROOT,
		dissect_h225_VoiceCaps },
	{ 8, "t120-only", EXTENSION_ROOT,
		dissect_h225_T120OnlyCaps },
	{ 9, "nonStandardProtocol", NOT_EXTENSION_ROOT,
		dissect_h225_NonStandardProtocol },
	{ 10, "t38FaxAnnexbOnly", NOT_EXTENSION_ROOT,
		dissect_h225_T38FaxAnnexbOnlyCaps },
	{ 11, "sip", NOT_EXTENSION_ROOT,
		dissect_h225_SIPCaps },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_SupportedProtocols(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_SupportedProtocols, ett_h225_SupportedProtocols, SupportedProtocols_choice, "SupportedProtocols", NULL);
	return offset;
}

static int
dissect_h225_protocol(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_protocol, ett_h225_protocol, dissect_h225_SupportedProtocols);
	return offset;
}



static per_sequence_t GatewayInfo_sequence[] = {
	{ "protocol", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_protocol },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_gateway(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_GatewayInfo, ett_h225_GatewayInfo, GatewayInfo_sequence);
	return offset;
}
static per_sequence_t McuInfo_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "protocol", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_protocol },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_mcu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_McuInfo, ett_h225_McuInfo, McuInfo_sequence);
	return offset;
}


static int
dissect_h225_tunnelledProtocolObjectID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h225_tunnelledProtocolObjectID);
	return offset;
}


static per_sequence_t TunnelledProtocol_id_sequence[] = {
	{ "tunnelledProtocolObjectID", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_tunnelledProtocolObjectID },
	{ "tunnelledProtocolAlternateID", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_TunnelledProtocolAlternateIdentifier },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_TunnelledProtocol_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_TunnelledProtocol_id, ett_h225_TunnelledProtocol_id, TunnelledProtocol_id_sequence);
	return offset;
}

static int
dissect_h225_TunnelledProtocol_subIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_TunnelledProtocol_subIdentifier, 1, 64);
	return offset;
}
static per_sequence_t TunnelledProtocol_sequence[] = {
	{ "id", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_TunnelledProtocol_id },
	{ "subIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_TunnelledProtocol_subIdentifier },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_TunnelledProtocol(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_TunnelledProtocol, ett_h225_TunnelledProtocol, TunnelledProtocol_sequence);
	return offset;
}
static int 
dissect_h225_desiredTunnelledProtocol(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_desiredTunnelledProtocol, ett_h225_TunnelledProtocol, TunnelledProtocol_sequence);
	return offset;
}


static int
dissect_h225_CicInfo_cic_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_CicInfo_cic_item, 2, 4);
	return offset;
}

static int
dissect_h225_CicInfo_pointCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_CicInfo_pointCode, 2, 5);
	return offset;
}

static int
dissect_h225_CicInfo_cic(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_CicInfo_cic, ett_h225_CicInfo_cic, dissect_h225_CicInfo_cic_item);
	return offset;
}

static per_sequence_t CicInfo_sequence[] = {
	{ "cic", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CicInfo_cic },
	{ "pointCode", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CicInfo_pointCode },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CicInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CicInfo, ett_h225_CicInfo, CicInfo_sequence);
	return offset;
}

static int
dissect_h225_GroupID_member_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_GroupID_member_item, 0, 65535,
		NULL, NULL, FALSE);
	return offset;
}

static int
dissect_h225_GroupID_member(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_GroupID_member, ett_h225_GroupID_member, dissect_h225_GroupID_member_item);
	return offset;
}

static int
dissect_h225_GroupID_group(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_GroupID_group, 1, 128);
	return offset;
}

static per_sequence_t GroupID_sequence[] = {
	{ "member", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GroupID_member },
	{ "group", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_GroupID_group },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_GroupID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_GroupID, ett_h225_GroupID, GroupID_sequence);
	return offset;
}

static per_sequence_t CircuitIdentifier_sequence[] = {
	{ "cic", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CicInfo },
	{ "group", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GroupID },
	{ "carrier", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CarrierInfo },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_sourceCircuitID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_sourceCircuitID, ett_h225_CircuitIdentifier, CircuitIdentifier_sequence);
	return offset;
}
static int 
dissect_h225_destinationCircuitID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_destinationCircuitID, ett_h225_CircuitIdentifier, CircuitIdentifier_sequence);
	return offset;
}

static int
dissect_h225_Generic_standard(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_Generic_standard, 0, 16383,
		NULL, NULL, TRUE);
	return offset;
}


static int
dissect_h225_Generic_oid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h225_Generic_oid);
	return offset;
}


static int
dissect_h225_Generic_nonStandard(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_Generic_nonStandard, 16, 16);
	return offset;
}


static const value_string GenericIdentifier_vals[] = {
	{ 0, "standard" },
	{ 1, "oid" },
	{ 2, "nonStandard" },
	{ 0, NULL}
};
static per_choice_t GenericIdentifier_choice[] = {
	{ 0, "standard", EXTENSION_ROOT,
		dissect_h225_Generic_standard },
	{ 1, "oid", EXTENSION_ROOT,
		dissect_h225_Generic_oid },
	{ 2, "nonStandard", EXTENSION_ROOT,
		dissect_h225_Generic_nonStandard },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_GenericIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_GenericIdentifier, ett_h225_GenericIdentifier, GenericIdentifier_choice, "GenericIdentifier", NULL);
	return offset;
}

static int dissect_h225_Content(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static per_sequence_t EnumeratedParameter_sequence[] = {
	{ "id", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_GenericIdentifier },
	{ "content", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_Content },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_EnumeratedParameter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_EnumeratedParameter, ett_h225_EnumeratedParameter, EnumeratedParameter_sequence);
	return offset;
}


static int
dissect_h225_parameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h225_parameters, ett_h225_parameters, dissect_h225_EnumeratedParameter, 1, 512);
	return offset;
}

static per_sequence_t GenericData_sequence[] = {
	{ "id", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_GenericIdentifier },
	{ "parameters", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_parameters },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_GenericData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_GenericData, ett_h225_GenericData, GenericData_sequence);
	return offset;
}
static int
dissect_h225_genericData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_genericData, ett_h225_genericData, dissect_h225_GenericData);
	return offset;
}
static int 
dissect_h225_FeatureDescriptor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_FeatureDescriptor, ett_h225_GenericData, GenericData_sequence);
	return offset;
}

static int
dissect_h225_Content_raw(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_Content_raw, -1, -1);
	return offset;
}


static int
dissect_h225_Content_text(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_Content_text, -1, -1);
	return offset;
}




static int
dissect_h225_Content_unicode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_BMPString(tvb, offset, pinfo, tree, hf_h225_unicode, -1, -1);
	return offset;
}



static int
dissect_h225_Content_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_Content_bool, NULL, NULL);
	return offset;
}



static int
dissect_h225_Content_number8(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_Content_number8, 0, 255,
		NULL, NULL, FALSE);
	return offset;
}

static int
dissect_h225_number16(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_number16, 0, 65535,
		NULL, NULL, FALSE);
	return offset;
}

static int
dissect_h225_Content_number32(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_Content_number32, 0, 4294967295UL,
		NULL, NULL, FALSE);
	return offset;
}

static int
dissect_h225_Content_compound(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h225_Content_compound, ett_h225_Content_compound, dissect_h225_EnumeratedParameter, 1, 512);
	return offset;
}

static int
dissect_h225_Content_nested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h225_Content_nested, ett_h225_Content_nested, dissect_h225_GenericData, 1, 16);
	return offset;
}





static const value_string Content_vals[] = {
	{ 0, "raw" },
	{ 1, "text" },
	{ 2, "unicode" },
	{ 3, "bool" },
	{ 4, "number8" },
	{ 5, "number16" },
	{ 6, "number32" },
	{ 7, "id" },
	{ 8, "alias" },
	{ 9, "transport" },
	{ 10, "compound" },
	{ 11, "nested" },
	{ 0, NULL}
};
static per_choice_t Content_choice[] = {
	{ 0, "raw", EXTENSION_ROOT,
		dissect_h225_Content_raw },
	{ 1, "text", EXTENSION_ROOT,
		dissect_h225_Content_text },
	{ 2, "unicode", EXTENSION_ROOT,
		dissect_h225_Content_unicode },
	{ 3, "bool", EXTENSION_ROOT,
		dissect_h225_Content_bool },
	{ 4, "number8", EXTENSION_ROOT,
		dissect_h225_Content_number8 },
	{ 5, "number16", EXTENSION_ROOT,
		dissect_h225_number16 },
	{ 6, "number32", EXTENSION_ROOT,
		dissect_h225_Content_number32 },
	{ 7, "id", EXTENSION_ROOT,
		dissect_h225_GenericIdentifier },
	{ 8, "alias", EXTENSION_ROOT,
		dissect_h225_AliasAddress },
	{ 9, "transport", EXTENSION_ROOT,
		dissect_h225_TransportAddress },
	{ 10, "compound", EXTENSION_ROOT,
		dissect_h225_Content_compound },
	{ 11, "nested", EXTENSION_ROOT,
		dissect_h225_Content_nested },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_Content(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_Content, ett_h225_Content, Content_choice, "Content", NULL);
	return offset;
}


static int
dissect_h225_replacementFeatureSet(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_replacementFeatureSet, NULL, NULL);
	return offset;
}

static int
dissect_h225_neededFeatures(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_neededFeatures, ett_h225_neededFeatures, dissect_h225_FeatureDescriptor);
	return offset;
}

static int
dissect_h225_desiredFeatures(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_desiredFeatures, ett_h225_desiredFeatures, dissect_h225_FeatureDescriptor);
	return offset;
}

static int
dissect_h225_supportedFeatures(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_supportedFeatures, ett_h225_supportedFeatures, dissect_h225_FeatureDescriptor);
	return offset;
}

static per_sequence_t FeatureSet_sequence[] = {
	{ "replacementFeatureSet", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_replacementFeatureSet },
	{ "neededFeatures", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_neededFeatures },
	{ "desiredFeatures", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_desiredFeatures },
	{ "supportedFeatures", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_supportedFeatures },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_FeatureSet(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_FeatureSet, ett_h225_FeatureSet, FeatureSet_sequence);
	return offset;
}

static int
dissect_h225_CallsAvailable_calls(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_CallsAvailable_calls, 0, 4294967295UL,
		NULL, NULL, FALSE);
	return offset;
}


static int
dissect_h225_CallsAvailable_group(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_CallsAvailable_group, 1, 128);
	return offset;
}

static per_sequence_t CallsAvailable_sequence[] = {
	{ "calls", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallsAvailable_calls },
	{ "group", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallsAvailable_group },
	{ "carrier", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CarrierInfo },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CallsAvailable, ett_h225_CallsAvailable, CallsAvailable_sequence);
	return offset;
}

static int
dissect_h225_voiceGwCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_voiceGwCallsAvailable, ett_h225_voiceGwCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_h310GwCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_h310GwCallsAvailable, ett_h225_h310GwCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_h320GwCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_h320GwCallsAvailable, ett_h225_h320GwCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_h321GwCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_h321GwCallsAvailable, ett_h225_h321GwCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_h322GwCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_h322GwCallsAvailable, ett_h225_h322GwCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_h323GwCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_h323GwCallsAvailable, ett_h225_h323GwCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_h324GwCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_h324GwCallsAvailable, ett_h225_h324GwCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_t120OnlyGwCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_t120OnlyGwCallsAvailable, ett_h225_t120OnlyGwCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_t38FaxAnnexbOnlyGwCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_t38FaxAnnexbOnlyGwCallsAvailable, ett_h225_t38FaxAnnexbOnlyGwCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_terminalCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_terminalCallsAvailable, ett_h225_terminalCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_mcuCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_mcuCallsAvailable, ett_h225_mcuCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}

static int
dissect_h225_sipGwCallsAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_sipGwCallsAvailable, ett_h225_sipGwCallsAvailable, dissect_h225_CallsAvailable);
	return offset;
}
static per_sequence_t CallCapacityInfo_sequence[] = {
	{ "voiceGwCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_voiceGwCallsAvailable },
	{ "h310GwCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h310GwCallsAvailable },
	{ "h320GwCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h320GwCallsAvailable },
	{ "h321GwCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h321GwCallsAvailable },
	{ "h322GwCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h322GwCallsAvailable },
	{ "h323GwCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h323GwCallsAvailable },
	{ "h324GwCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h324GwCallsAvailable },
	{ "t120OnlyGwCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_t120OnlyGwCallsAvailable },
	{ "t38FaxAnnexbOnlyGwCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_t38FaxAnnexbOnlyGwCallsAvailable },
	{ "terminalCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_terminalCallsAvailable },
	{ "mcuCallsAvailable", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_mcuCallsAvailable },
	{ "sipGwCallsAvailable", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_sipGwCallsAvailable },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_maximumCallCapacity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_maximumCallCapacity, ett_h225_CallCapacityInfo, CallCapacityInfo_sequence);
	return offset;
}
static int 
dissect_h225_currentCallCapacity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_currentCallCapacity, ett_h225_CallCapacityInfo, CallCapacityInfo_sequence);
	return offset;
}

static per_sequence_t CallCapacity_sequence[] = {
	{ "maximumCallCapacity", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_maximumCallCapacity },
	{ "currentCallCapacity", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_currentCallCapacity },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CallCapacity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CallCapacity, ett_h225_CallCapacity, CallCapacity_sequence);
	return offset;
}

static int
dissect_h225_productID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_productID, 1, 256);
	return offset;
}

static int
dissect_h225_versionID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_versionID, 1, 256);
	return offset;
}

static int
dissect_h225_enterpriseNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h225_enterpriseNumber);
	return offset;
}

static per_sequence_t VendorIdentifier_sequence[] = {
	{ "vendor", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h245_h221NonStandard },
	{ "productId", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_productID },
	{ "versionId", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_versionID },
	{ "enterpriseNumber", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_enterpriseNumber },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_VendorIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_VendorIdentifier, ett_h225_VendorIdentifier, VendorIdentifier_sequence);
	return offset;
}


static int
dissect_h225_canReportCallCapacity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_canReportCallCapacity, NULL, NULL);
	return offset;
}

static per_sequence_t CapacityReportingCapability_sequence[] = {
	{ "canReportCallCapacity", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_canReportCallCapacity },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CapacityReportingCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CapacityReportingCapability, ett_h225_CapacityReportingCapability, CapacityReportingCapability_sequence);
	return offset;
}

static int
dissect_h225_canDisplayAmountString(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_canDisplayAmountString, NULL, NULL);
	return offset;
}

static int
dissect_h225_canEnforceDurationLimit(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_canEnforceDurationLimit, NULL, NULL);
	return offset;
}

static per_sequence_t CallCreditCapability_sequence[] = {
	{ "canDisplayAmountString", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_canDisplayAmountString },
	{ "canEnforceDurationLimit", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_canEnforceDurationLimit },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CallCreditCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CallCreditCapability, ett_h225_CallCreditCapability, CallCreditCapability_sequence);
	return offset;
}

static int
dissect_h225_BandwidthDetails_sender(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_BandwidthDetails_sender, NULL, NULL);
	return offset;
}

static int
dissect_h225_BandwidthDetails_multicast(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_BandwidthDetails_multicast, NULL, NULL);
	return offset;
}

static per_sequence_t BandwidthDetails_sequence[] = {
	{ "sender", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_BandwidthDetails_sender },
	{ "multicast", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_BandwidthDetails_multicast },
	{ "bandwidth", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_BandWidth },
	{ "rtcpAddresses", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_rtcpAddress },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_BandwidthDetails(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_BandwidthDetails, ett_h225_BandwidthDetails, BandwidthDetails_sequence);
	return offset;
}

static int
dissect_h225_releaseCompleteCauseIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_releaseCompleteCauseIE, 2, 32);
	return offset;
}

static const value_string CallTerminationCause_vals[] = {
	{ 0, "releaseCompleteReason" },
	{ 1, "releaseCompleteCauseIE" },
	{ 0, NULL}
};
static per_choice_t CallTerminationCause_choice[] = {
	{ 0, "releaseCompleteReason", EXTENSION_ROOT,
		dissect_h225_ReleaseCompleteReason },
	{ 1, "releaseCompleteCauseIE", EXTENSION_ROOT,
		dissect_h225_releaseCompleteCauseIE },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_CallTerminationCause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_CallTerminationCause, ett_h225_CallTerminationCause, CallTerminationCause_choice, "CallTerminationCause", NULL);
	return offset;
}

static per_sequence_t CircuitInfo_sequence[] = {
	{ "sourceCircuitID", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_sourceCircuitID },
	{ "destinationCircuitID", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destinationCircuitID },
	{ "genericData", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CircuitInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CircuitInfo, ett_h225_CircuitInfo, CircuitInfo_sequence);
	return offset;
}

static int
dissect_h225_fastStart_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_fastStart_item, -1, -1);
	return offset;
}

static int
dissect_h225_fastStart(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_fastStart, ett_h225_fastStart, dissect_h225_fastStart_item);
	return offset;
}

static int
dissect_h225_fastConnectRefused(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_fastConnectRefused, NULL, NULL);
	return offset;
}

static per_sequence_t InformationUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "fastStart", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_fastStart },
	{ "fastConnectRefused", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_fastConnectRefused },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_InformationUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_InformationUUIE, ett_h225_InformationUUIE, InformationUUIE_sequence);
	return offset;
}

static int
dissect_h225_routeCallToSCN(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_routeCallToSCN, ett_h225_routeCallToSCN, dissect_h225_PartyNumber);
	return offset;
}

static const value_string AdmissionRejectReason_vals[] = {
	{ 0, "calledPartyNotRegistered" },
	{ 1, "invalidPermission" },
	{ 2, "requestDenied" },
	{ 3, "undefinedReason" },
	{ 4, "callerNotRegistered" },
	{ 5, "routeCallToGatekeeper" },
	{ 6, "invalidEndpointIdentifier" },
	{ 7, "resourceUnavailable" },
	{ 8, "securityDenial" },
	{ 9, "qosControlNotSupported" },
	{ 10, "incompleteAddress" },
	{ 11, "aliasesInconsistent" },
	{ 12, "routeCallToSCN" },
	{ 13, "exceedsCallCapacity" },
	{ 14, "collectDestination" },
	{ 15, "collectPIN" },
	{ 16, "genericDataReason" },
	{ 17, "neededFeatureNotSupported" },
	{ 18, "securityErrors" },
	{ 19, "securityDHmismatch" },
	{ 20, "noRouteToDestination" },
	{ 21, "unallocatedNumber" },
	{ 0, NULL}
};
static per_choice_t AdmissionRejectReason_choice[] = {
	{ 0, "calledPartyNotRegistered", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "invalidPermission", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "requestDenied", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "undefinedReason", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "callerNotRegistered", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "routeCallToGatekeeper", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 6, "invalidEndpointIdentifier", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 7, "resourceUnavailable", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 8, "securityDenial", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 9, "qosControlNotSupported", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 10, "incompleteAddress", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 11, "aliasesInconsistent", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 12, "routeCallToSCN", NOT_EXTENSION_ROOT,
		dissect_h225_routeCallToSCN },
	{ 13, "exceedsCallCapacity", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 14, "collectDestination", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 15, "collectPIN", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 16, "genericDataReason", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 17, "neededFeatureNotSupported", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 18, "securityErrors", NOT_EXTENSION_ROOT,
		dissect_h225_SecurityErrors2 },
	{ 19, "securityDHmismatch", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 20, "noRouteToDestination", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 21, "unallocatedNumber", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_AdmissionRejectReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_AdmissionRejectReason, ett_h225_AdmissionRejectReason, AdmissionRejectReason_choice, "AdmissionRejectReason", NULL);
	return offset;
}

static int
dissect_h225_isoAlgorithm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h225_isoAlgorithm);
	return offset;
}

static const value_string EncryptIntAlg_vals[] = {
	{ 0, "nonStandard" },
	{ 1, "isoAlgorithm" },
	{ 0, NULL}
};
static per_choice_t EncryptIntAlg_choice[] = {
	{ 0, "nonStandard", EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{ 1, "isoAlgorithm", EXTENSION_ROOT,
		dissect_h225_isoAlgorithm },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_hMAC_iso10118_2_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_hMAC_iso10118_2_s, ett_h225_EncryptIntAlg, EncryptIntAlg_choice, "hMAC_iso10118_2_s", NULL);
	return offset;
}
static int
dissect_h225_hMAC_iso10118_2_l(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_hMAC_iso10118_2_l, ett_h225_EncryptIntAlg, EncryptIntAlg_choice, "hMAC_iso10118_2_l", NULL);
	return offset;
}

static int
dissect_h225_hMAC_iso10118_3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h225_hMAC_iso10118_3);
	return offset;
}


static const value_string NonIsoIntegrityMechanism_vals[] = {
	{ 0, "hMAC-MD5" },
	{ 1, "hMAC_iso10118_2_s" },
	{ 2, "hMAC_iso10118_2_l" },
	{ 3, "hMAC_iso10118_3" },
	{ 0, NULL}
};
static per_choice_t NonIsoIntegrityMechanism_choice[] = {
	{ 0, "hMAC-MD5", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "hMAC_iso10118_2_s", EXTENSION_ROOT,
		dissect_h225_hMAC_iso10118_2_s },
	{ 2, "hMAC_iso10118_2_l", EXTENSION_ROOT,
		dissect_h225_hMAC_iso10118_2_l },
	{ 3, "hMAC_iso10118_3", EXTENSION_ROOT,
		dissect_h225_hMAC_iso10118_3 },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_NonIsoIntegrityMechanism(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_NonIsoIntegrityMechanism, ett_h225_NonIsoIntegrityMechanism, NonIsoIntegrityMechanism_choice, "NonIsoIntegrityMechanism", NULL);
	return offset;
}

static int
dissect_h225_iso9797(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h225_iso9797);
	return offset;
}

static const value_string IntegrityMechanism_vals[] = {
	{ 0, "nonStandard" },
	{ 1, "digSig" },
	{ 2, "iso9797" },
	{ 3, "nonIsoIM" },
	{ 0, NULL}
};
static per_choice_t IntegrityMechanism_choice[] = {
	{ 0, "nonStandard", EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{ 1, "digSig", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "iso9797", EXTENSION_ROOT,
		dissect_h225_iso9797 },
	{ 3, "nonIsoIM", EXTENSION_ROOT,
		dissect_h225_NonIsoIntegrityMechanism },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_IntegrityMechanism(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_IntegrityMechanism, ett_h225_IntegrityMechanism, IntegrityMechanism_choice, "IntegrityMechanism", NULL);
	return offset;
}

static const value_string LocationRejectReason_vals[] = {
	{ 0, "notRegistered" },
	{ 1, "invalidPermission" },
	{ 2, "requestDenied" },
	{ 3, "undefinedReason" },
	{ 4, "securityDenial" },
	{ 5, "aliasesInconsistent" },
	{ 6, "routeCalltoSCN" },
	{ 7, "resourceUnavailable" },
	{ 8, "genericDataReason" },
	{ 9, "neededFeatureNotSupported" },
	{10, "hopCountExceeded" },
	{11, "incompleteAddress" },
	{12, "securityError" },
	{13, "securityDHmismatch" },
	{14, "noRouteToDestination" },
	{15, "unallocatedNumber" },
	{ 0, NULL}
};
static per_choice_t LocationRejectReason_choice[] = {
	{ 0, "notRegistered", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "invalidPermission", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "requestDenied", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "undefinedReason", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "securityDenial", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 5, "aliasesInconsistent", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 6, "routeCalltoSCN", NOT_EXTENSION_ROOT,
		dissect_h225_routeCallToSCN },
	{ 7, "resourceUnavailable", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 8, "genericDataReason", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 9, "neededFeatureNotSupported", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{10, "hopCountExceeded", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{11, "incompleteAddress", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{12, "securityError", NOT_EXTENSION_ROOT,
		dissect_h225_SecurityErrors2 },
	{13, "securityDHmismatch", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{14, "noRouteToDestination", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{15, "unallocatedNumber", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_LocationRejectReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_LocationRejectReason, ett_h225_LocationRejectReason, LocationRejectReason_choice, "LocationRejectReason", NULL);
	return offset;
}


static int
dissect_h225_EndpointType_set(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
NOT_DECODED_YET("EndpointType_set");
	return offset;
}

static int
dissect_h225_mc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_mc, NULL, NULL);
	return offset;
}

static int
dissect_h225_undefinedNode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_undefinedNode, NULL, NULL);
	return offset;
}


static per_sequence_t EndPointType_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "vendor", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_VendorIdentifier },
	{ "gatekeeper", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperInfo },
	{ "gateway", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_gateway },
	{ "mcu", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_mcu },
	{ "terminal", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_TerminalInfo },
	{ "mc", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_mc },
	{ "undefinedNode", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_undefinedNode },
	{ "set", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_EndpointType_set },
	{ "supportedTunnelledProtocols", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_TunnelledProtocol },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_EndPointType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_EndPointType, ett_h225_EndPointType, EndPointType_sequence);
	return offset;
}
static int 
dissect_h225_terminalType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_terminalType, ett_h225_EndPointType, EndPointType_sequence);
	return offset;
}
static int 
dissect_h225_sourceInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_sourceInfo, ett_h225_EndPointType, EndPointType_sequence);
	return offset;
}
static int 
dissect_h225_destinationInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_destinationInfo, ett_h225_EndPointType, EndPointType_sequence);
	return offset;
}

static int
dissect_h225_multipleCalls(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_multipleCalls, NULL, NULL);
	return offset;
}

static int
dissect_h225_maintainConnection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_maintainConnection, NULL, NULL);
	return offset;
}
static per_sequence_t CallProceedingUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "destinationInfo", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_destinationInfo },
	{ "h245Address", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h245Address },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "h245SecurityMode", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_H245Security },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "fastStart", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_fastStart },
	{ "multipleCalls", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_multipleCalls },
	{ "maintainConnection", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_maintainConnection },
	{ "fastConnectRefused", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CallProceedingUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CallProceedingUUIE, ett_h225_CallProceedingUUIE, CallProceedingUUIE_sequence);
	return offset;
}

static per_sequence_t CapacityReportingSpecification_when_sequence[] = {
	{ "callStart", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_NULL },
	{ "callEnd", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CapacityReportingSpecification_when(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CapacityReportingSpecification_when, ett_h225_CapacityReportingSpecification_when, CapacityReportingSpecification_when_sequence);
	return offset;
}

static per_sequence_t CapacityReportingSpecification_sequence[] = {
	{ "when", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CapacityReportingSpecification_when },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CapacityReportingSpecification(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CapacityReportingSpecification, ett_h225_CapacityReportingSpecification, CapacityReportingSpecification_sequence);
	return offset;
}
static per_sequence_t ProgressUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "destinationInfo", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_destinationInfo },
	{ "h245Address", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h245Address },
	{ "callIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "h245SecurityMode", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_H245Security },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "fastStart", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_fastStart },
	{ "multipleCalls", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_multipleCalls },
	{ "maintainConnection", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_maintainConnection },
	{ "fastConnectRefused", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ProgressUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ProgressUUIE, ett_h225_ProgressUUIE, ProgressUUIE_sequence);
	return offset;
}


static int
dissect_h225_destExtraCallInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_destExtraCallInfo, ett_h225_destExtraCallInfo, dissect_h225_AliasAddress);
	return offset;
}

static int
dissect_h225_remoteExtensionAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_remoteExtensionAddress, ett_h225_remoteExtensionAddress, dissect_h225_AliasAddress);
	return offset;
}

static int
dissect_h225_rasAddress_sequence(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_rasAddress_sequence, ett_h225_rasAddress_sequence, dissect_h225_TransportAddress);
	return offset;
}

static int
dissect_h225_callSignalAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_callSignalAddress, ett_h225_callSignalAddress, dissect_h225_TransportAddress);
	return offset;
}


static per_sequence_t EndPoint_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "aliasAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AliasAddress },
	{ "callSignalAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_callSignalAddress },
	{ "rasAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_rasAddress_sequence },
	{ "endpointType", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_EndPointType },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "priority", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_priority },
	{ "remoteExtensionAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_remoteExtensionAddress },
	{ "destExtraCallInfo", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destExtraCallInfo },
	{ "alternateTransportAddresses", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AlternateTransportAddress },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_EndPoint(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_EndPoint, ett_h225_EndPoint, EndPoint_sequence);
	return offset;
}
static int 
dissect_h225_destinationType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_destinationType, ett_h225_EndPoint, EndPoint_sequence);
	return offset;
}


static int 
dissect_h225_icv(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
NOT_DECODED_YET("icv");
	return offset;
}

static int
dissect_h225_algorithmOID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h225_algorithmOID);
	return offset;
}

static per_sequence_t ICV_sequence[] = {
	{ "algorithmOID", NO_EXTENSIONS, OPTIONAL,
		dissect_h225_algorithmOID },
	{ "icv", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_icv },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ICV(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ICV, ett_h225_ICV, ICV_sequence);
	return offset;
}

static per_sequence_t BandwidthConfirm_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "bandWidth", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_BandWidth },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_BandwidthConfirm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_BandwidthConfirm, ett_h225_BandwidthConfirm, BandwidthConfirm_sequence);
	return offset;
}


static per_sequence_t UnregistrationConfirm_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_UnregistrationConfirm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_UnregistrationConfirm, ett_h225_UnregistrationConfirm, UnregistrationConfirm_sequence);
	return offset;
}
static per_sequence_t NonStandardMessage_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_NonStandardMessage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_NonStandardMessage, ett_h225_NonStandardMessage, NonStandardMessage_sequence);
	return offset;
}


static per_sequence_t InfoRequestAck_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_InfoRequestAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_InfoRequestAck, ett_h225_InfoRequestAck, InfoRequestAck_sequence);
	return offset;
}
static per_sequence_t InfoRequestNak_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "nakReason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_InfoRequestNakReason },
	{ "altGKInfo", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AltGKInfo },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_InfoRequestNak(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_InfoRequestNak, ett_h225_InfoRequestNak, InfoRequestNak_sequence);
	return offset;
}

static per_sequence_t ResourcesAvailableConfirm_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "genericData", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ResourcesAvailableConfirm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ResourcesAvailableConfirm, ett_h225_ResourcesAvailableConfirm, ResourcesAvailableConfirm_sequence);
	return offset;
}



static int
dissect_h225_integrity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_integrity, ett_h225_integrity, dissect_h225_IntegrityMechanism);
	return offset;
}


static int
dissect_h225_algorithmOIDs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_algorithmOIDs, ett_h225_algorithmOIDs, dissect_h225_algorithmOID);
	return offset;
}


static int
dissect_h225_alternateEndpoints(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_alternateEndpoints, ett_h225_alternateEndpoints, dissect_h225_EndPoint);
	return offset;
}



static int
dissect_h225_endpointAlias(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_endpointAlias, ett_h225_endpointAlias, dissect_h225_AliasAddress);
	return offset;
}


static per_sequence_t GatekeeperRequest_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "rasAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_rasAddress },
	{ "endpointType", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_EndPointType },
	{ "gatekeeperIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "callServices", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_callServices },
	{ "endpointAlias", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_endpointAlias },
	{ "alternateEndpoints", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alternateEndpoints },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
/*XXX from h235 AuthenticationMechanism */
	{ "authenticationCapability", NOT_EXTENSION_ROOT, OPTIONAL, NULL },
	{ "algorithmOIDs", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_algorithmOIDs },
	{ "integrity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_integrity },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "supportsAltGK", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_GatekeeperRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_GatekeeperRequest, ett_h225_GatekeeperRequest, GatekeeperRequest_sequence);
	return offset;
}

static per_sequence_t ServiceControlResponse_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "result", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_SCRresult },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "featureSet", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ServiceControlResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ServiceControlResponse, ett_h225_ServiceControlResponse, ServiceControlResponse_sequence);
	return offset;
}



static per_sequence_t DisengageReject_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "rejectReason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_DisengageRejectReason },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "altGKInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AltGKInfo },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_DisengageReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_DisengageReject, ett_h225_DisengageReject, DisengageReject_sequence);
	return offset;
}



static per_sequence_t BandwidthReject_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "rejectReason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_BandRejectReason },
	{ "allowedBandWidth", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_allowedBandWidth },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "altGKInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AltGKInfo },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_BandwidthReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_BandwidthReject, ett_h225_BandwidthReject, BandwidthReject_sequence);
	return offset;
}



static per_sequence_t UnregistrationReject_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "rejectReason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_UnregRejectReason },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "altGKInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AltGKInfo },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_UnregistrationReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_UnregistrationReject, ett_h225_UnregistrationReject, UnregistrationReject_sequence);
	return offset;
}


static int
dissect_h225_endpointAliasPattern(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_endpointAliasPattern, ett_h225_endpointAliasPattern, dissect_h225_AddressPattern);
	return offset;
}

static int
dissect_h225_EndpointIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_BMPString(tvb, offset, pinfo, tree, hf_h225_EndpointIdentifier, 1, 128);
	return offset;
}

static per_sequence_t UnregistrationRequest_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "callSignalAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_callSignalAddress },
	{ "endpointAlias", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_endpointAlias },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "endpointIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "alternateEndpoints", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alternateEndpoints },
	{ "gatekeeperIdentifier", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "reason", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_UnregRequestReason },
	{ "endpointAliasPattern", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_endpointAliasPattern },
	{ "supportedPrefixes", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ "alternateGatekeeper", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alternateGatekeeper },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_UnregistrationRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_UnregistrationRequest, ett_h225_UnregistrationRequest, UnregistrationRequest_sequence);
	return offset;
}


static int
dissect_h225_terminalAlias(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_terminalAlias, ett_h225_terminalAlias, dissect_h225_AliasAddress);
	return offset;
}



static int
dissect_h225_terminalAliasPattern(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_terminalAliasPattern, ett_h225_terminalAliasPattern, dissect_h225_AddressPattern);
	return offset;
}


static per_sequence_t invalidTerminalAliases_sequence[] = {
	{ "terminalAlias", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_terminalAlias },
	{ "terminalAliasPattern", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_terminalAliasPattern },
	{ "supportedPrefixes", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_invalidTerminalAliases(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_invalidTerminalAliases, ett_h225_invalidTerminalAliases, invalidTerminalAliases_sequence);
	return offset;
}






static int
dissect_h225_duplicateAlias(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_duplicateAlias, ett_h225_duplicateAlias, dissect_h225_AliasAddress);
	return offset;
}





static const value_string RegistrationRejectReason_vals[] = {
	{ 0, "discoveryRequired" },
	{ 1, "invalidRevision" },
	{ 2, "invalidCallSignalAddress" },
	{ 3, "invalidRASAddress" },
	{ 4, "duplicateAlias" },
	{ 5, "invalidTerminalType" },
	{ 6, "undefinedReason" },
	{ 7, "transportNotSupported" },
	{ 8, "transportQOSNotSupported" },
	{ 9, "resourceUnavailable" },
	{ 10, "invalidAlias" },
	{ 11, "securityDenial" },
	{ 12, "fullRegistrationRequired" },
	{ 13, "additiveRegistrationNotSupported" },
	{ 14, "invalidTerminalAliases" },
	{ 15, "genericDataReason" },
	{ 16, "neededFeatureNotSupported" },
	{ 17, "securityError" },
	{ 0, NULL}
};
static per_choice_t RegistrationRejectReason_choice[] = {
	{ 0, "discoveryRequired", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 1, "invalidRevision", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 2, "invalidCallSignalAddress", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 3, "invalidRASAddress", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 4, "duplicateAlias", EXTENSION_ROOT,
		dissect_h225_duplicateAlias },
	{ 5, "invalidTerminalType", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 6, "undefinedReason", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 7, "transportNotSupported", EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 8, "transportQOSNotSupported", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 9, "resourceUnavailable", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 10, "invalidAlias", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 11, "securityDenial", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 12, "fullRegistrationRequired", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 13, "additiveRegistrationNotSupported", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 14, "invalidTerminalAliases", NOT_EXTENSION_ROOT,
		dissect_h225_invalidTerminalAliases },
	{ 15, "genericDataReason", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 16, "neededFeatureNotSupported", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 17, "securityError", NOT_EXTENSION_ROOT,
		dissect_h225_SecurityErrors },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_RegistrationRejectReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_RegistrationRejectReason, ett_h225_RegistrationRejectReason, RegistrationRejectReason_choice, "RegistrationRejectReason", NULL);
	return offset;
}






static per_sequence_t RegistrationReject_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "rejectReason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RegistrationRejectReason },
	{ "gatekeeperIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "altGKInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AltGKInfo },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_RegistrationReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_RegistrationReject, ett_h225_RegistrationReject, RegistrationReject_sequence);
	return offset;
}


static per_sequence_t GatekeeperReject_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "gatekeeperIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "rejectReason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_GatekeeperRejectReason },
	{ "altGKInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AltGKInfo },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_GatekeeperReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_GatekeeperReject, ett_h225_GatekeeperReject, GatekeeperReject_sequence);
	return offset;
}



static int
dissect_h225_almostOutOfResources(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_almostOutOfResources, NULL, NULL);
	return offset;
}


static int
dissect_h225_protocols(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_protocols, ett_h225_protocols, dissect_h225_SupportedProtocols);
	return offset;
}

static per_sequence_t ResourcesAvailableIndicate_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "endpointIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "protocols", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_protocols },
	{ "almostOutOfResources", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_almostOutOfResources },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ResourcesAvailableIndicate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ResourcesAvailableIndicate, ett_h225_ResourcesAvailableIndicate, ResourcesAvailableIndicate_sequence);
	return offset;
}


static int 
dissect_h225_amountString(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
NOT_DECODED_YET("amountString");
	return offset;
}



static int
dissect_h225_callDurationLimit(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_callDurationLimit, 1, 4294967295UL,
		NULL, NULL, FALSE);
	return offset;
}


static int
dissect_h225_enforceCallDurationLimit(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_enforceCallDurationLimit, NULL, NULL);
	return offset;
}


static per_sequence_t CallCreditServiceControl_sequence[] = {
	{ "amountString", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_amountString },
	{ "billingMode", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_billingMode },
	{ "callDurationLimit", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_callDurationLimit },
	{ "enforceCallDurationLimit", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_enforceCallDurationLimit },
	{ "callStartingPoint", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CCSCcallStartingPoint },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_CallCreditServiceControl(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_CallCreditServiceControl, ett_h225_CallCreditServiceControl, CallCreditServiceControl_sequence);
	return offset;
}



static const value_string ScreeningIndicator_vals[] = {
	{ 0, "userProvidedNotScreened" },
	{ 1, "userProvidedVerifiedAndPassed" },
	{ 2, "userProvidedVerifiedAndFailed" },
	{ 3, "networkProvided" },
	{ 0, NULL },
};

static int
dissect_h225_ScreeningIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_ScreeningIndicator, 0, 3,
		NULL, NULL, TRUE);
	return offset;
}

static per_sequence_t ExtendedAliasAddress_sequence[] = {
	{ "address", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_AliasAddress },
	{ "presentationIndicator", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_PresentationIndicator },
	{ "screeningIndicator", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ScreeningIndicator },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ExtendedAliasAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ExtendedAliasAddress, ett_h225_ExtendedAliasAddress, ExtendedAliasAddress_sequence);
	return offset;
}




static int
dissect_h225_messageNotUnderstood(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_messageNotUnderstood, -1, -1);
	return offset;
}

static per_sequence_t UnknownMessageResponse_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "messageNotUnderstood", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_messageNotUnderstood },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_UnknownMessageResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_UnknownMessageResponse, ett_h225_UnknownMessageResponse, UnknownMessageResponse_sequence);
	return offset;
}

static int
dissect_h225_CallReferenceValue(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_CallReferenceValue, 0, 65535,
		NULL, NULL, FALSE);
	return offset;
}




static int
dissect_h225_canMapSrcAlias(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_canMapSrcAlias, NULL, NULL);
	return offset;
}

static int
dissect_h225_desiredProtocols(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_desiredProtocols, ett_h225_desiredProtocols, dissect_h225_SupportedProtocols);
	return offset;
}

static int
dissect_h225_willSupplyUUIEs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_willSupplyUUIEs, NULL, NULL);
	return offset;
}


static int
dissect_h225_destAlternatives(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_destAlternatives, ett_h225_destAlternatives, dissect_h225_EndPoint);
	return offset;
}

static int
dissect_h225_srcAlternatives(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_srcAlternatives, ett_h225_srcAlternatives, dissect_h225_EndPoint);
	return offset;
}

static int
dissect_h225_canMapAlias(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_canMapAlias, NULL, NULL);
	return offset;
}


static int
dissect_h225_answerCall(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_answerCall, NULL, NULL);
	return offset;
}


static int
dissect_h225_activeMC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_activeMC, NULL, NULL);
	return offset;
}


static int
dissect_h225_srcInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_srcInfo, ett_h225_srcInfo, dissect_h225_AliasAddress);
	return offset;
}

static int
dissect_h225_DestinationInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_DestinationInfo, ett_h225_DestinationInfo, dissect_h225_AliasAddress);
	return offset;
}






static per_sequence_t AdmissionRequest_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "callType", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallType },
	{ "callModel", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallModel },
	{ "endpointIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "DestinationInfo", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_DestinationInfo },
	{ "destCallSignalAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destCallSignalAddress },
	{ "destExtraCallInfo", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destExtraCallInfo },
	{ "srcInfo", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_srcInfo },
	{ "sourceCallSignalAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_sourceCallSignalAddress },
	{ "bandWidth", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_BandWidth },
	{ "callReferenceValue", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallReferenceValue },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "callServices", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_callServices },
	{ "conferenceID", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_conferenceID },
	{ "activeMC", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_activeMC },
	{ "answerCall", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_answerCall },
	{ "canMapAlias", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_canMapAlias },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "srcAlternatives", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_srcAlternatives },
	{ "destAlternatives", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destAlternatives },
	{ "gatekeeperIdentifier", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "transportQOS", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_TransportQOS },
	{ "willSupplyUUIEs", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_willSupplyUUIEs },
	{ "callLinkage", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallLinkage },
	{ "gatewayDataRate", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_gatewayDataRate },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ "desiredProtocols", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_desiredProtocols },
	{ "desiredTunnelledProtocol", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_desiredTunnelledProtocol },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ "canMapSrcAlias", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_canMapSrcAlias },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_AdmissionRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_AdmissionRequest, ett_h225_AdmissionRequest, AdmissionRequest_sequence);
	return offset;
}



static int
dissect_h225_nextSegmentRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_nextSegmentRequested, 0, 65535,
		NULL, NULL, FALSE);
	return offset;
}

static per_sequence_t InfoRequest_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "callReferenceValue", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallReferenceValue },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "replyAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_replyAddress },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "uuiesRequested", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_UUIEsRequested },
	{ "callLinkage", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallLinkage },
	{ "usageInfoRequested", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_RasUsageInfoTypes },
	{ "segmentedResponseSupported", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "nextSegmentRequested", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_nextSegmentRequested },
	{ "capacityInfoRequested", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_InfoRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_InfoRequest, ett_h225_InfoRequest, InfoRequest_sequence);
	return offset;
}


static int
dissect_h225_delay(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_delay, 1, 65535,
		NULL, NULL, FALSE);
	return offset;
}

static per_sequence_t RequestInProgress_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "delay", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_delay },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_RequestInProgress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_RequestInProgress, ett_h225_RequestInProgress, RequestInProgress_sequence);
	return offset;
}

static int
dissect_h225_H248SignalsDescriptor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_H248SignalsDescriptor, -1, -1);
	return offset;
}


static int
dissect_h225_url(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_url, 0, 512);
	return offset;
}


static const value_string ServiceControlDescriptor_vals[] = {
	{ 0, "url" },
	{ 1, "signal" },
	{ 2, "nonStandard" },
	{ 3, "callCreditServiceControl" },
	{ 0, NULL}
};
static per_choice_t ServiceControlDescriptor_choice[] = {
	{ 0, "url", EXTENSION_ROOT,
		dissect_h225_url },
	{ 1, "signal", EXTENSION_ROOT,
		dissect_h225_H248SignalsDescriptor },
	{ 2, "nonStandard", EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{ 3, "callCreditServiceControl", EXTENSION_ROOT,
		dissect_h225_CallCreditServiceControl },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_ServiceControlDescriptor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_ServiceControlDescriptor, ett_h225_ServiceControlDescriptor, ServiceControlDescriptor_choice, "ServiceControlDescriptor", NULL);
	return offset;
}



static int
dissect_h225_sessionId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_sessionId, 0, 255,
		NULL, NULL, FALSE);
	return offset;
}

static per_sequence_t ServiceControlSession_sequence[] = {
	{ "sessionId", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_sessionId },
	{ "contents", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ServiceControlDescriptor },
	{ "reason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ServiceControlSession_reason },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ServiceControlSession(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ServiceControlSession, ett_h225_ServiceControlSession, ServiceControlSession_sequence);
	return offset;
}



static int
dissect_h225_serviceControl(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_serviceControl, ett_h225_serviceControl, dissect_h225_ServiceControlSession);
	return offset;
}


static int
dissect_h225_alertingAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_alertingAddress, ett_h225_alertingAddress, dissect_h225_AliasAddress);
	return offset;
}


static per_sequence_t AlertingUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "destinationInfo", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_destinationInfo },
	{ "h245Address", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h245Address },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "h245SecurityMode", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_H245Security },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "fastStart", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_fastStart },
	{ "multipleCalls", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_multipleCalls },
	{ "maintainConnection", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_maintainConnection },
	{ "alertingAddress", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alertingAddress },
	{ "presentationIndicator", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_PresentationIndicator },
	{ "screeningIndicator", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ScreeningIndicator },
	{ "fastConnectRefused", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_AlertingUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_AlertingUUIE, ett_h225_AlertingUUIE, AlertingUUIE_sequence);
	return offset;
}

static int
dissect_h225_busyAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_busyAddress, ett_h225_busyAddress, dissect_h225_AliasAddress);
	return offset;
}


static per_sequence_t ReleaseCompleteUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "reason", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ReleaseCompleteReason },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "busyAddress", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_busyAddress },
	{ "presentationIndicator", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_PresentationIndicator },
	{ "screeningIndicator", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ScreeningIndicator },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ReleaseCompleteUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ReleaseCompleteUUIE, ett_h225_ReleaseCompleteUUIE, ReleaseCompleteUUIE_sequence);
	return offset;
}

static int
dissect_h225_alternativeAliasAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_alternativeAliasAddress, ett_h225_alternativeAliasAddress, dissect_h225_AliasAddress);
	return offset;
}

static per_sequence_t FacilityUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "alternativeAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alternativeAddress },
	{ "alternativeAliasAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alternativeAliasAddress },
	{ "conferenceID", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_conferenceID },
	{ "reason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_FacilityReason },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "destExtraCallInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destExtraCallInfo },
	{ "remoteExtensionAddress", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_RemoteExtensionAddress },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "conferences", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_conferences },
	{ "h245Address", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h245Address },
	{ "fastStart", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_fastStart },
	{ "multipleCalls", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_multipleCalls },
	{ "maintainConnection", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_maintainConnection },
	{ "fastConnectRefused", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "destinationInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destinationInfo },
	{ "h245SecurityMode", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_H245Security },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_FacilityUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_FacilityUUIE, ett_h225_FacilityUUIE, FacilityUUIE_sequence);
	return offset;
}

static per_sequence_t AdmissionReject_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "rejectReason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_AdmissionRejectReason },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "altGKInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AltGKInfo },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "callSignalAddress", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_callSignalAddress },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_AdmissionReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_AdmissionReject, ett_h225_AdmissionReject, AdmissionReject_sequence);
	return offset;
}

static int
dissect_h225_hopCount(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_hopCount, 1, 31,
		NULL, NULL, FALSE);
	return offset;
}


static int
dissect_h225_parallelH245Control_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_parallelH245Control_item, -1, -1);
	return offset;
}

static int
dissect_h225_parallelH245Control(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_parallelH245Control, ett_h225_parallelH245Control, dissect_h225_parallelH245Control_item);
	return offset;
}

static int
dissect_h225_language(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h225_language, 1, 32);
	return offset;
}

static int
dissect_h225_languages(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_languages, ett_h225_languages, dissect_h225_language);
	return offset;
}

static int
dissect_h225_mediaWaitForConnect(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_mediaWaitForConnect, NULL, NULL);
	return offset;
}

static int
dissect_h225_canOverlapSend(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_canOverlapSend, NULL, NULL);
	return offset;
}

static int
dissect_h225_sourceAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_sourceAddress, ett_h225_sourceAddress, dissect_h225_AliasAddress);
	return offset;
}

static int
dissect_h225_destinationAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_destinationAddress, ett_h225_destinationAddress, dissect_h225_AliasAddress);
	return offset;
}


static int
dissect_h225_destExtraCRV(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_destExtraCRV, ett_h225_destExtraCRV, dissect_h225_CallReferenceValue);
	return offset;
}

static int
dissect_h225_h245SecurityCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_h245SecurityCapability, ett_h225_h245SecurityCapability, dissect_h225_H245Security);
	return offset;
}

static int
dissect_h225_additionalSourceAddresses(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_additionalSourceAddresses, ett_h225_additionalSourceAddresses, dissect_h225_ExtendedAliasAddress);
	return offset;
}



static per_sequence_t SetupUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "h245Address", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h245Address },
	{ "sourceAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_sourceAddress },
	{ "sourceInfo", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_sourceInfo },
	{ "destinationAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destinationAddress },
	{ "destCallSignalAddress", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destCallSignalAddress },
	{ "destExtraCallInfo", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destExtraCallInfo },
	{ "destExtraCRV", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destExtraCRV },
	{ "activeMC", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_activeMC },
	{ "conferenceID", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_conferenceID },
	{ "conferenceGoal", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_conferenceGoal },
	{ "callServices", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_callServices },
	{ "callType", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallType },
	{ "sourceCallSignalAddress", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_sourceCallSignalAddress },
	{ "RemoteExtensionAddress", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_RemoteExtensionAddress },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "h245SecurityCapability", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h245SecurityCapability },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "fastStart", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_fastStart },
	{ "mediaWaitForConnect", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_mediaWaitForConnect },
	{ "canOverlapSend", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_canOverlapSend },
	{ "endpointIdentifier", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "multipleCalls", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_multipleCalls },
	{ "maintainConnection", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_maintainConnection },
	{ "connectionParameters", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_connectionParameters },
	{ "languages", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_languages },
	{ "presentationIndicator", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_PresentationIndicator },
	{ "screeningIndicator", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ScreeningIndicator },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ "symmetricOperationRequired", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ "desiredProtocols", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_desiredProtocols },
	{ "neededFeatures", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_neededFeatures },
	{ "desiredFeatures", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_desiredFeatures },
	{ "supportedFeatures", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_supportedFeatures },
	{ "parallelH245Control", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_parallelH245Control },
	{ "additionalSourceAddresses", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_additionalSourceAddresses },
	{ "hopCount", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_hopCount },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_SetupUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_SetupUUIE, ett_h225_SetupUUIE, SetupUUIE_sequence);
	return offset;
}


static int
dissect_h225_connectedAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_connectedAddress, ett_h225_connectedAddress, dissect_h225_AliasAddress);
	return offset;
}

static per_sequence_t ConnectUUIE_sequence[] = {
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "h245Address", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h245Address },
	{ "destinationInfo", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_destinationInfo },
	{ "conferenceID", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_conferenceID },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "h245SecurityMode", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_H245Security },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "fastStart", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_fastStart },
	{ "multipleCalls", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_multipleCalls },
	{ "maintainConnection", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_maintainConnection },
	{ "languages", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_languages },
	{ "connectedAddress", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_connectedAddress },
	{ "presentationIndicator", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_PresentationIndicator },
	{ "screeningIndicator", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ScreeningIndicator },
	{ "fastConnectRefused", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ConnectUUIE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ConnectUUIE, ett_h225_ConnectUUIE, ConnectUUIE_sequence);
	return offset;
}


static const value_string h323_message_body_vals[] = {
	{ 0, "setup" },
	{ 1, "callProceeding" },
	{ 2, "connect" },
	{ 3, "alerting" },
	{ 4, "information" },
	{ 5, "releaseComplete" },
	{ 6, "facility" },
	{ 7, "progress" },
	{ 8, "empty" },
	{ 9, "status" },
	{ 10, "statusInquiry" },
	{ 11, "setupAcknowledge" },
	{ 12, "notify" },
	{ 0, NULL}
};
static per_choice_t h323_message_body_choice[] = {
	{ 0, "setup", EXTENSION_ROOT,
		dissect_h225_SetupUUIE },
	{ 1, "callProceeding", EXTENSION_ROOT,
		dissect_h225_CallProceedingUUIE },
	{ 2, "connect", EXTENSION_ROOT,
		dissect_h225_ConnectUUIE },
	{ 3, "alerting", EXTENSION_ROOT,
		dissect_h225_AlertingUUIE },
	{ 4, "information", EXTENSION_ROOT,
		dissect_h225_InformationUUIE },
	{ 5, "releaseComplete", EXTENSION_ROOT,
		dissect_h225_ReleaseCompleteUUIE },
	{ 6, "facility", EXTENSION_ROOT,
		dissect_h225_FacilityUUIE },
	{ 7, "progress", NOT_EXTENSION_ROOT,
		dissect_h225_ProgressUUIE },
	{ 8, "empty", NOT_EXTENSION_ROOT,
		dissect_h225_NULL },
	{ 9, "status", NOT_EXTENSION_ROOT,
		dissect_h225_StatusUUIE },
	{ 10, "statusInquiry", NOT_EXTENSION_ROOT,
		dissect_h225_StatusInquiryUUIE },
	{ 11, "setupAcknowledge", NOT_EXTENSION_ROOT,
		dissect_h225_SetupAcknowledgeUUIE },
	{ 12, "notify", NOT_EXTENSION_ROOT,
		dissect_h225_NotifyUUIE },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h225_h323_message_body(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h225_h323_message_body, ett_h225_h323_message_body, h323_message_body_choice, "h323_message_body", NULL);
	return offset;
}

static int
dissect_h225_supportedProtocols(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_supportedProtocols, ett_h225_supportedProtocols, dissect_h225_SupportedProtocols);
	return offset;
}

static int
dissect_h225_modifiedSrcInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_modifiedSrcInfo, ett_h225_modifiedSrcInfo, dissect_h225_AliasAddress);
	return offset;
}


static per_sequence_t LocationConfirm_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "callSignalAddress2", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallSignalAddress2 },
	{ "rasAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_rasAddress },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "DestinationInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_DestinationInfo },
	{ "destExtraCallInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destExtraCallInfo },
	{ "destinationType", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destinationType },
	{ "remoteExtensionAddress", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_remoteExtensionAddress },
	{ "alternateEndpoints", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alternateEndpoints },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "alternateTransportAddresses", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AlternateTransportAddress },
	{ "supportedProtocols", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_supportedProtocols },
	{ "multipleCalls", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_multipleCalls },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ "modifiedSrcInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_modifiedSrcInfo },
	{ "bandWidth", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_BandWidth },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_LocationConfirm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_LocationConfirm, ett_h225_LocationConfirm, LocationConfirm_sequence);
	return offset;
}

static per_sequence_t LocationReject_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "rejectReason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_LocationRejectReason },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "altGKInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AltGKInfo },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_LocationReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_LocationReject, ett_h225_LocationReject, LocationReject_sequence);
	return offset;
}


static int
dissect_h225_answeredCall(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_answeredCall, NULL, NULL);
	return offset;
}

static per_sequence_t callSpecific_sequence[] = {
	{ "callIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "conferenceID", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_conferenceID },
	{ "answeredCall", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_answeredCall },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_callSpecific(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_callSpecific, ett_h225_callSpecific, callSpecific_sequence);
	return offset;
}

static per_sequence_t ServiceControlIndication_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		 dissect_h225_RequestSeqNum },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "serviceControl", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_serviceControl },
	{ "endpointIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "callSpecific", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_callSpecific },
	{ "tokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "featureSet", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_ServiceControlIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_ServiceControlIndication, ett_h225_ServiceControlIndication, ServiceControlIndication_sequence);
	return offset;
}

static int 
dissect_h225_alertingTime(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
NOT_DECODED_YET("alertingTime");
	return offset;
}
static int 
dissect_h225_connectTime(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
NOT_DECODED_YET("connectTime");
	return offset;
}
static int 
dissect_h225_endTime(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
NOT_DECODED_YET("endTime");
	return offset;
}

static int
dissect_h225_nonStandardUsageFields(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_nonStandardUsageFields, ett_h225_nonStandardUsageFields, dissect_h245_NonStandardParameter);
	return offset;
}


static per_sequence_t RasUsageInformation_sequence[] = {
	{ "nonStandardUsageFields", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_nonStandardUsageFields },
	{ "alertingTime", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alertingTime },
	{ "connectTime", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_connectTime },
	{ "endTime", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_endTime },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_RasUsageInformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_RasUsageInformation, ett_h225_RasUsageInformation, RasUsageInformation_sequence);
	return offset;
}



static int
dissect_h225_TimeToLive(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_TimeToLive, 1, 4294967295UL,
		NULL, NULL, FALSE);
	return offset;
}

static per_sequence_t GatekeeperConfirm_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "gatekeeperIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "rasAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_rasAddress },
	{ "alternateGatekeeper", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alternateGatekeeper },
/*XXX from h235 AuthenticationMechanism */
	{ "authenticationMode", NOT_EXTENSION_ROOT, OPTIONAL, NULL },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "algorithmOID", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_algorithmOID },
	{ "integrity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_integrity },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_GatekeeperConfirm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_GatekeeperConfirm, ett_h225_GatekeeperConfirm, GatekeeperConfirm_sequence);
	return offset;
}



static int
dissect_h225_discoveryComplete(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_discoveryComplete, NULL, NULL);
	return offset;
}


static int
dissect_h225_keepAlive(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_keepAlive, NULL, NULL);
	return offset;
}


static int
dissect_h225_H248PackagesDescriptor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_H248PackagesDescriptor, -1, -1);
	return offset;
}

static int
dissect_h225_supportedH248Packages(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_supportedH248Packages, ett_h225_supportedH248Packages, dissect_h225_H248PackagesDescriptor);
	return offset;
}


static per_sequence_t RegistrationRequest_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "discoveryComplete", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_discoveryComplete },
	{ "callSignalAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_callSignalAddress },
	{ "rasAddress_sequence", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_rasAddress_sequence },
	{ "terminalType", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_terminalType },
	{ "terminalAlias", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_terminalAlias },
	{ "gatekeeperIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "endpointVendor", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_VendorIdentifier },
	{ "alternateEndpoints", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alternateEndpoints },
	{ "timeToLive", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_TimeToLive },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "keepAlive", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_keepAlive },
	{ "endpointIdentifier", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "willSupplyUUIEs", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_willSupplyUUIEs },
	{ "maintainConnection", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_maintainConnection },
	{ "alternateTransportAddresses", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AlternateTransportAddress },
	{ "additiveRegistration", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "terminalAliasPattern", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_terminalAliasPattern },
	{ "supportsAltGK", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "usageReportingCapability", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_usageReportingCapability },
	{ "multipleCalls", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_multipleCalls },
	{ "supportedH248Packages", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_supportedH248Packages },
	{ "callCreditCapability", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCreditCapability },
	{ "capacityReportingCapability", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CapacityReportingCapability },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ "restart", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "supportsACFSequences", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_RegistrationRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_RegistrationRequest, ett_h225_RegistrationRequest, RegistrationRequest_sequence);
	return offset;
}


static per_sequence_t DisengageConfirm_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ "usageInformation", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_RasUsageInformation },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_DisengageConfirm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_DisengageConfirm, ett_h225_DisengageConfirm, DisengageConfirm_sequence);
	return offset;
}


static int
dissect_h225_irrFrequency(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_irrFrequency, 1, 65535,
		NULL, NULL, FALSE);
	return offset;
}

static int
dissect_h225_willRespondToIRR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_willRespondToIRR, NULL, NULL);
	return offset;
}


static int
dissect_h225_usageSpec(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_usageSpec, ett_h225_usageSpec, dissect_h225_RasUsageSpecification);
	return offset;
}

static per_sequence_t AdmissionConfirm_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "bandWidth", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_BandWidth },
	{ "callModel", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallModel },
	{ "destCallSignalAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_destCallSignalAddress },
	{ "irrFrequency", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_irrFrequency },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "DestinationInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_DestinationInfo },
	{ "destExtraCallInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destExtraCallInfo },
	{ "destinationType", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_destinationType },
	{ "remoteExtensionAddress", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_remoteExtensionAddress },
	{ "alternateEndpoints", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alternateEndpoints },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "transportQOS", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_TransportQOS },
	{ "willRespondToIRR", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_willRespondToIRR },
	{ "uuiesRequested", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_UUIEsRequested },
	{ "languages", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_languages },
	{ "alternateTransportAddresses", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AlternateTransportAddress },
	{ "useSpecifiedTransport", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_UseSpecifiedTransport },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ "usageSpec", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_usageSpec },
	{ "supportedProtocols", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_supportedProtocols },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ "multipleCalls", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_multipleCalls },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ "modifiedSrcInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_modifiedSrcInfo },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_AdmissionConfirm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_AdmissionConfirm, ett_h225_AdmissionConfirm, AdmissionConfirm_sequence);
	return offset;
}


static per_sequence_t DisengageRequest_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "endpointIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "conferenceID", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_conferenceID },
	{ "callReferenceValue", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallReferenceValue },
	{ "disengageReason", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_DisengageReason },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "gatekeeperIdentifier", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "answeredCall", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_answeredCall },
	{ "callLinkage", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallLinkage },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ "usageInformation", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_RasUsageInformation },
	{ "terminationCause", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallTerminationCause },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_DisengageRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_DisengageRequest, ett_h225_DisengageRequest, DisengageRequest_sequence);
	return offset;
}


static int
dissect_h225_SourceInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_SourceInfo, ett_h225_SourceInfo, dissect_h225_AliasAddress);
	return offset;
}

static int
dissect_h225_hopCount255(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_hopCount255, 1, 255,
		NULL, NULL, FALSE);
	return offset;
}

static int
dissect_h225_sourceEndpointInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_sourceEndpointInfo, ett_h225_sourceEndpointInfo, dissect_h225_AliasAddress);
	return offset;
}

static per_sequence_t LocationRequest_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "endpointIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "DestinationInfo", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_DestinationInfo },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "replyAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_replyAddress },
	{ "SourceInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_SourceInfo },
	{ "canMapAlias", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_canMapAlias },
	{ "gatekeeperIdentifier", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "desiredProtocols", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_desiredProtocols },
	{ "desiredTunnelledProtocol", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_desiredTunnelledProtocol },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ "hopCount255", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_hopCount255 },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ "callIdentifier", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "bandWidth", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_BandWidth },
	{ "sourceEndpointInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_sourceEndpointInfo },
	{ "canMapSrcAlias", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_canMapSrcAlias },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_LocationRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_LocationRequest, ett_h225_LocationRequest, LocationRequest_sequence);
	return offset;
}

static int
dissect_h225_bandwidthDetails(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_bandwidthDetails, ett_h225_bandwidthDetails, dissect_h225_BandwidthDetails);
	return offset;
}

static per_sequence_t BandwidthRequest_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "endpointIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "conferenceID", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_conferenceID },
	{ "callReferenceValue", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallReferenceValue },
	{ "callType", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallType },
	{ "bandWidth", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_BandWidth },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "gatekeeperIdentifier", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "answeredCall", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_answeredCall },
	{ "callLinkage", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallLinkage },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "usageInformation", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_RasUsageInformation },
	{ "bandwidthDetails", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_bandwidthDetails },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_BandwidthRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_BandwidthRequest, ett_h225_BandwidthRequest, BandwidthRequest_sequence);
	return offset;
}


static int
dissect_h225_admissionConfirmSequence(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_admissionConfirmSequence, ett_h225_admissionConfirmSequence, dissect_h225_AdmissionConfirm);
	return offset;
}


static int
dissect_h225_messageContent_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_messageContent_item, -1, -1);
	return offset;
}


static int
dissect_h225_messageContent(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_messageContent, ett_h225_messageContent, dissect_h225_messageContent_item);
	return offset;
}


static per_sequence_t tunnelledSignallingMessage_sequence[] = {
	{ "tunnelledProtocolID", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_TunnelledProtocol },
	{ "messageContent", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_messageContent },
	{ "tunnellingRequired", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_tunnelledSignallingMessage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_tunnelledSignallingMessage, ett_h225_tunnelledSignallingMessage, tunnelledSignallingMessage_sequence);
	return offset;
}



static int
dissect_h225_h4501SupplementaryService_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_h4501SupplementaryService_item, -1, -1);
	return offset;
}

static int
dissect_h225_h4501SupplementaryService(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_h4501SupplementaryService, ett_h225_h4501SupplementaryService, dissect_h225_h4501SupplementaryService_item);
	return offset;
}


static int
dissect_h225_h245Tunneling(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_h245Tunneling, NULL, NULL);
	return offset;
}


static int
dissect_h225_h245Control_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_h245Control_item, -1, -1);
	return offset;
}


static int
dissect_h225_h245Control(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_h245Control, ett_h225_h245Control, dissect_h225_h245Control_item);
	return offset;
}


static int
dissect_h225_nonStandardControl(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_nonStandardControl, ett_h225_nonStandardControl, dissect_h245_NonStandardParameter);
	return offset;
}


static per_sequence_t H323_UU_PDU_sequence[] = {
	{ "h323_message_body", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_h323_message_body },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "h4501SupplementaryService", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h4501SupplementaryService },
	{ "h245Tunneling", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_h245Tunneling },
	{ "h245Control", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_h245Control },
	{ "nonStandardControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_nonStandardControl },
	{ "callLinkage", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallLinkage },
	{ "tunnelledSignallingMessage", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tunnelledSignallingMessage },
	{ "provisionalRespToH245Tunneling", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "stimulusControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_StimulusControl },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_H323_UU_PDU(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_H323_UU_PDU, ett_h225_H323_UU_PDU, H323_UU_PDU_sequence);
	return offset;
}


static int
dissect_h225_makeCall(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_makeCall, NULL, NULL);
	return offset;
}

static int
dissect_h225_useGKCallSignalAddressToMakeCall(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_useGKCallSignalAddressToMakeCall, NULL, NULL);
	return offset;
}


static int
dissect_h225_useGKCallSignalAddressToAnswer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_useGKCallSignalAddressToAnswer, NULL, NULL);
	return offset;
}

static per_sequence_t preGrantedARQ_sequence[] = {
	{ "makeCall", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_makeCall },
	{ "useGKCallSignalAddressToMakeCall", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_useGKCallSignalAddressToMakeCall },
	{ "answerCall", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_answerCall },
	{ "useGKCallSignalAddressToAnswer", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_useGKCallSignalAddressToAnswer },
	{ "irrFrequencyInCall", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_irrFrequency },
	{ "totalBandwidthRestriction", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_totalBandwidthRestriction },
	{ "alternateTransportAddresses", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_AlternateTransportAddress },
	{ "useSpecifiedTransport", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_UseSpecifiedTransport },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_preGrantedARQ(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_preGrantedARQ, ett_h225_preGrantedARQ, preGrantedARQ_sequence);
	return offset;
}



static per_sequence_t RegistrationConfirm_sequence[] = {
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "protocolIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_ProtocolIdentifier },
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "callSignalAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_callSignalAddress },
	{ "terminalAlias", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_terminalAlias },
	{ "gatekeeperIdentifier", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_GatekeeperIdentifier },
	{ "endpointIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "alternateGatekeeper", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_alternateGatekeeper },
	{ "timeToLive", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_TimeToLive },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "willRespondToIRR", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_willRespondToIRR },
	{ "preGrantedARQ", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_preGrantedARQ },
	{ "maintainConnection", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_maintainConnection },
	{ "serviceControl", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_serviceControl },
	{ "supportsAdditiveRegistration", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_NULL },
	{ "terminalAliasPattern", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_terminalAliasPattern },
	{ "supportedPrefixes", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_SupportedPrefixes },
	{ "usageSpec", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_usageSpec },
	{ "featureServerAlias", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_featureServerAlias },
	{ "capacityReportingSpec", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CapacityReportingSpecification },
	{ "featureSet", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_FeatureSet },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_RegistrationConfirm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_RegistrationConfirm, ett_h225_RegistrationConfirm, RegistrationConfirm_sequence);
	return offset;
}


static int
dissect_h225_sent(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_sent, NULL, NULL);
	return offset;
}

static per_sequence_t pdu_item_sequence[] = {
	{ "h323pdu", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_H323_UU_PDU },
	{ "sent", NO_EXTENSIONS, NOT_OPTIONAL,
		dissect_h225_sent },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_pdu_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_pdu_item, ett_h225_pdu_item, pdu_item_sequence);
	return offset;
}


static int
dissect_h225_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_pdu, ett_h225_pdu, dissect_h225_pdu_item);
	return offset;
}



static int
dissect_h225_originator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_originator, NULL, NULL);
	return offset;
}

static int
dissect_h225_audio(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_audio, ett_h225_audio, dissect_h225_RTPSession);
	return offset;
}

static int
dissect_h225_video(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_video, ett_h225_video, dissect_h225_RTPSession);
	return offset;
}

static int
dissect_h225_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_data, ett_h225_data, dissect_h225_RTPSession);
	return offset;
}


static int
dissect_h225_substituteConfIDs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_substituteConfIDs, ett_h225_substituteConfIDs, dissect_h225_conferenceID);
	return offset;
}


static per_sequence_t perCallInfo_item_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "callReferenceValue", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallReferenceValue },
	{ "conferenceID", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_conferenceID },
	{ "originator", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_originator },
	{ "audio", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_audio },
	{ "video", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_video },
	{ "data", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_data },
	{ "h245", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_h245 },
	{ "callSignaling", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_callSignaling },
	{ "callType", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallType },
	{ "bandWidth", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_BandWidth },
	{ "callModel", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallModel },
	{ "callIdentifier", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_CallIdentifier },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "substituteConfIDs", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_substituteConfIDs },
	{ "pdu", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_pdu },
	{ "callLinkage", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallLinkage },
	{ "usageInformation", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_RasUsageInformation },
	{ "circuitInfo", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CircuitInfo },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_perCallInfo_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_perCallInfo_item, ett_h225_perCallInfo_item, perCallInfo_item_sequence);
	return offset;
}




static int
dissect_h225_perCallInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h225_perCallInfo, ett_h225_perCallInfo, dissect_h225_perCallInfo_item);
	return offset;
}



static int
dissect_h225_needResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_needResponse, NULL, NULL);
	return offset;
}


static int
dissect_h225_unsolicited(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h225_unsolicited, NULL, NULL);
	return offset;
}

static per_sequence_t InfoRequestResponse_sequence[] = {
	{ "nonStandardData", EXTENSION_ROOT, OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "requestSeqNum", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_RequestSeqNum },
	{ "endpointType", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_EndPointType },
	{ "endpointIdentifier", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_EndpointIdentifier },
	{ "rasAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_rasAddress },
	{ "callSignalAddress", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_callSignalAddress },
	{ "endpointAlias", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_endpointAlias },
	{ "perCallInfo", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_perCallInfo },
	{ "tokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_tokens },
	{ "cryptoTokens", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_cryptoTokens },
	{ "integrityCheckValue", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_ICV },
	{ "needResponse", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_needResponse },
	{ "capacity", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_CallCapacity },
	{ "irrStatus", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_InfoRequestResponseStatus },
	{ "unsolicited", NOT_EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_unsolicited },
	{ "genericData", NOT_EXTENSION_ROOT, OPTIONAL,
		dissect_h225_genericData },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_InfoRequestResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_InfoRequestResponse, ett_h225_InfoRequestResponse, InfoRequestResponse_sequence);
	return offset;
}



static int
dissect_h225_protocol_discriminator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h225_protocol_discriminator, 0, 255,
		NULL, NULL, FALSE);
	return offset;
}

static int
dissect_h225_user_information(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h225_user_information, 1, 131);
	return offset;
}

static per_sequence_t user_data_sequence[] = {
	{ "protocol-discriminator", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_protocol_discriminator },
	{ "user-information", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_user_information },
	{ NULL, 0, 0, NULL }
};
static int 
dissect_h225_user_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h225_user_data, ett_h225_user_data, user_data_sequence);
	return offset;
}




static const value_string RasMessage_vals[] = {
	{ 0, "gatekeeperRequest" },
	{ 1, "gatekeeperConfirm" },
	{ 2, "gatekeeperReject" },
	{ 3, "registrationRequest" },
	{ 4, "registrationConfirm" },
	{ 5, "registrationReject" },
	{ 6, "unregistrationRequest" },
	{ 7, "unregistrationConfirm" },
	{ 8, "unregistrationReject" },
	{ 9, "admissionRequest" },
	{10, "admissionConfirm" },
	{11, "admissionReject" },
	{12, "bandwidthRequest" },
	{13, "bandwidthConfirm" },
	{14, "bandwidthReject" },
	{15, "disengageRequest" },
	{16, "disengageConfirm" },
	{17, "disengageReject" },
	{18, "locationRequest" },
	{19, "locationConfirm" },
	{20, "locationReject" },
	{21, "infoRequest" },
	{22, "infoRequestResponse" },
	{23, "nonStandardMessage" },
	{24, "unknownMessageResponse" },
	{25, "requestInProgress" },
	{26, "resourcesAvailableIndicate" },
	{27, "resourcesAvailableConfirm" },
	{28, "infoRequestAck" },
	{29, "infoRequestNak" },
	{30, "serviceControlIndication" },
	{31, "serviceControlResponse" },
	{32, "admissionConfirmSequence" },
	{ 0, NULL}
};
static per_choice_t RasMessage_choice[] = {
	{ 0, "gatekeeperRequest", EXTENSION_ROOT,
		dissect_h225_GatekeeperRequest },
	{ 1, "gatekeeperConfirm", EXTENSION_ROOT,
		dissect_h225_GatekeeperConfirm },
	{ 2, "gatekeeperReject", EXTENSION_ROOT,
		dissect_h225_GatekeeperReject },
	{ 3, "registrationRequest", EXTENSION_ROOT,
		dissect_h225_RegistrationRequest },
	{ 4, "registrationConfirm", EXTENSION_ROOT,
		dissect_h225_RegistrationConfirm },
	{ 5, "registrationReject", EXTENSION_ROOT,
		dissect_h225_RegistrationReject },
	{ 6, "unregistrationRequest", EXTENSION_ROOT,
		dissect_h225_UnregistrationRequest },
	{ 7, "unregistrationConfirm", EXTENSION_ROOT,
		dissect_h225_UnregistrationConfirm },
	{ 8, "unregistrationReject", EXTENSION_ROOT,
		dissect_h225_UnregistrationReject },
	{ 9, "admissionRequest", EXTENSION_ROOT,
		dissect_h225_AdmissionRequest },
	{10, "admissionConfirm", EXTENSION_ROOT,
		dissect_h225_AdmissionConfirm },
	{11, "admissionReject", EXTENSION_ROOT,
		dissect_h225_AdmissionReject },
	{12, "bandwidthRequest", EXTENSION_ROOT,
		dissect_h225_BandwidthRequest },
	{13, "bandwidthConfirm", EXTENSION_ROOT,
		dissect_h225_BandwidthConfirm },
	{14, "bandwidthReject", EXTENSION_ROOT,
		dissect_h225_BandwidthReject },
	{15, "disengageRequest", EXTENSION_ROOT,
		dissect_h225_DisengageRequest },
	{16, "disengageConfirm", EXTENSION_ROOT,
		dissect_h225_DisengageConfirm },
	{17, "disengageReject", EXTENSION_ROOT,
		dissect_h225_DisengageReject },
	{18, "locationRequest", EXTENSION_ROOT,
		dissect_h225_LocationRequest },
	{19, "locationConfirm", EXTENSION_ROOT,
		dissect_h225_LocationConfirm },
	{20, "locationReject", EXTENSION_ROOT,
		dissect_h225_LocationReject },
	{21, "infoRequest", EXTENSION_ROOT,
		dissect_h225_InfoRequest },
	{22, "infoRequestResponse", EXTENSION_ROOT,
		dissect_h225_InfoRequestResponse },
	{23, "nonStandardMessage", EXTENSION_ROOT,
		dissect_h225_NonStandardMessage },
	{24, "unknownMessageResponse", EXTENSION_ROOT,
		dissect_h225_UnknownMessageResponse },
	{25, "requestInProgress", NOT_EXTENSION_ROOT,
		dissect_h225_RequestInProgress },
	{26, "resourcesAvailableIndicate", NOT_EXTENSION_ROOT,
		dissect_h225_ResourcesAvailableIndicate },
	{27, "resourcesAvailableConfirm", NOT_EXTENSION_ROOT,
		dissect_h225_ResourcesAvailableConfirm },
	{28, "infoRequestAck", NOT_EXTENSION_ROOT,
		dissect_h225_InfoRequestAck },
	{29, "infoRequestNak", NOT_EXTENSION_ROOT,
		dissect_h225_InfoRequestNak },
	{30, "serviceControlIndication", NOT_EXTENSION_ROOT,
		dissect_h225_ServiceControlIndication },
	{31, "serviceControlResponse", NOT_EXTENSION_ROOT,
		dissect_h225_ServiceControlResponse },
	{32, "admissionConfirmSequence", NOT_EXTENSION_ROOT,
		dissect_h225_admissionConfirmSequence },
	{ 0, NULL, 0, NULL }
};
static void
dissect_h225_RasMessage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;
	guint32 value;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "H.225.0 RAS");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	it=proto_tree_add_protocol_format(tree, proto_h225, tvb, 0, tvb_length(tvb), "H.225.0 RAS");
	tr=proto_item_add_subtree(it, ett_h225);

	offset=dissect_per_choice(tvb, offset, pinfo, tr, hf_h225_RasMessage, ett_h225_RasMessage, RasMessage_choice, "RasMessage", &value);

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(value, RasMessage_vals, "<unknown>"));
	}
}






static per_sequence_t H323_UserInformation_sequence[] = {
	{ "h323_uu_pdu", EXTENSION_ROOT, NOT_OPTIONAL,
		dissect_h225_H323_UU_PDU },
	{ "user_data", EXTENSION_ROOT, OPTIONAL,
		dissect_h225_user_data },
	{ NULL, 0, 0, NULL }
};
static void
dissect_h225_H323UserInformation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;
	guint32 value;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "H.323 UserInformation");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	it=proto_tree_add_protocol_format(tree, proto_h225, tvb, 0, tvb_length(tvb), "H.225");
	tr=proto_item_add_subtree(it, ett_h225);

	offset=dissect_per_sequence(tvb, offset, pinfo, tr, hf_h225_H323_UserInformation, ett_h225_H323_UserInformation, H323_UserInformation_sequence);

#ifdef REMOVED
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(value, H323UserInformation_vals, "<unknown>"));
	}
#endif

}



void
dissect_h225ras(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_tpkt_encap(tvb, pinfo, tree, h225_reassembly, h225ras_handle);
}



void
proto_register_h225(void)
{
	static hf_register_info hf[] =
	{
	{ &hf_h225_PresentationIndicator,
		{ "PresentationIndicator", "h225.PresentationIndicator", FT_UINT32, BASE_DEC,
		VALS(PresentationIndicator_vals), 0, "PresentationIndicator choice", HFILL }},
	{ &hf_h225_conferenceGoal,
		{ "conferenceGoal", "h225.conferenceGoal", FT_UINT32, BASE_DEC,
		VALS(conferenceGoal_vals), 0, "conferenceGoal choice", HFILL }},
	{ &hf_h225_ScnConnectionType,
		{ "ScnConnectionType", "h225.ScnConnectionType", FT_UINT32, BASE_DEC,
		VALS(ScnConnectionType_vals), 0, "ScnConnectionType choice", HFILL }},
	{ &hf_h225_ScnConnectionAggregation,
		{ "ScnConnectionAggregation", "h225.ScnConnectionAggregation", FT_UINT32, BASE_DEC,
		VALS(ScnConnectionAggregation_vals), 0, "ScnConnectionAggregation choice", HFILL }},
	{ &hf_h225_FacilityReason,
		{ "FacilityReason", "h225.FacilityReason", FT_UINT32, BASE_DEC,
		VALS(FacilityReason_vals), 0, "FacilityReason choice", HFILL }},
	{ &hf_h225_PublicTypeOfNumber,
		{ "PublicTypeOfNumber", "h225.PublicTypeOfNumber", FT_UINT32, BASE_DEC,
		VALS(PublicTypeOfNumber_vals), 0, "PublicTypeOfNumber choice", HFILL }},
	{ &hf_h225_PrivateTypeOfNumber,
		{ "PrivateTypeOfNumber", "h225.PrivateTypeOfNumber", FT_UINT32, BASE_DEC,
		VALS(PrivateTypeOfNumber_vals), 0, "PrivateTypeOfNumber choice", HFILL }},
	{ &hf_h225_UseSpecifiedTransport,
		{ "UseSpecifiedTransport", "h225.UseSpecifiedTransport", FT_UINT32, BASE_DEC,
		VALS(UseSpecifiedTransport_vals), 0, "UseSpecifiedTransport choice", HFILL }},
	{ &hf_h225_SecurityErrors,
		{ "SecurityErrors", "h225.SecurityErrors", FT_UINT32, BASE_DEC,
		VALS(SecurityErrors_vals), 0, "SecurityErrors choice", HFILL }},
	{ &hf_h225_SecurityErrors2,
		{ "SecurityErrors2", "h225.SecurityErrors2", FT_UINT32, BASE_DEC,
		VALS(SecurityErrors2_vals), 0, "SecurityErrors2 choice", HFILL }},
	{ &hf_h225_ServiceControlSession_reason,
		{ "ServiceControlSession_reason", "h225.ServiceControlSession_reason", FT_UINT32, BASE_DEC,
		VALS(ServiceControlSession_reason_vals), 0, "ServiceControlSession_reason choice", HFILL }},
	{ &hf_h225_billingMode,
		{ "billingMode", "h225.billingMode", FT_UINT32, BASE_DEC,
		VALS(billingMode_vals), 0, "billingMode choice", HFILL }},
	{ &hf_h225_CCSCcallStartingPoint,
		{ "CCSCcallStartingPoint", "h225.CCSCcallStartingPoint", FT_UINT32, BASE_DEC,
		VALS(CCSCcallStartingPoint_vals), 0, "CCSCcallStartingPoint choice", HFILL }},
	{ &hf_h225_GatekeeperRejectReason,
		{ "GatekeeperRejectReason", "h225.GatekeeperRejectReason", FT_UINT32, BASE_DEC,
		VALS(GatekeeperRejectReason_vals), 0, "GatekeeperRejectReason choice", HFILL }},
	{ &hf_h225_UnregRequestReason,
		{ "UnregRequestReason", "h225.UnregRequestReason", FT_UINT32, BASE_DEC,
		VALS(UnregRequestReason_vals), 0, "UnregRequestReason choice", HFILL }},
	{ &hf_h225_UnregRejectReason,
		{ "UnregRejectReason", "h225.UnregRejectReason", FT_UINT32, BASE_DEC,
		VALS(UnregRejectReason_vals), 0, "UnregRejectReason choice", HFILL }},
	{ &hf_h225_CallType,
		{ "CallType", "h225.CallType", FT_UINT32, BASE_DEC,
		VALS(CallType_vals), 0, "CallType choice", HFILL }},
	{ &hf_h225_CallModel,
		{ "CallModel", "h225.CallModel", FT_UINT32, BASE_DEC,
		VALS(CallModel_vals), 0, "CallModel choice", HFILL }},
	{ &hf_h225_TransportQOS,
		{ "TransportQOS", "h225.TransportQOS", FT_UINT32, BASE_DEC,
		VALS(TransportQOS_vals), 0, "TransportQOS choice", HFILL }},
	{ &hf_h225_BandRejectReason,
		{ "BandRejectReason", "h225.BandRejectReason", FT_UINT32, BASE_DEC,
		VALS(BandRejectReason_vals), 0, "BandRejectReason choice", HFILL }},
	{ &hf_h225_DisengageReason,
		{ "DisengageReason", "h225.DisengageReason", FT_UINT32, BASE_DEC,
		VALS(DisengageReason_vals), 0, "DisengageReason choice", HFILL }},
	{ &hf_h225_DisengageRejectReason,
		{ "DisengageRejectReason", "h225.DisengageRejectReason", FT_UINT32, BASE_DEC,
		VALS(DisengageRejectReason_vals), 0, "DisengageRejectReason choice", HFILL }},
	{ &hf_h225_InfoRequestNakReason,
		{ "InfoRequestNakReason", "h225.InfoRequestNakReason", FT_UINT32, BASE_DEC,
		VALS(InfoRequestNakReason_vals), 0, "InfoRequestNakReason choice", HFILL }},
	{ &hf_h225_SCRresult,
		{ "SCRresult", "h225.SCRresult", FT_UINT32, BASE_DEC,
		VALS(SCRresult_vals), 0, "SCRresult choice", HFILL }},
	{ &hf_h225_GatekeeperInfo,
		{ "GatekeeperInfo", "h225.GatekeeperInfo", FT_NONE, BASE_NONE,
		NULL, 0, "GatekeeperInfo sequence", HFILL }},
	{ &hf_h225_SecurityServiceMode_encryption,
		{ "Encryption", "h225.SecurityServiceMode_encryption", FT_UINT32, BASE_DEC,
		VALS(SecurityServiceMode_vals), 0, "Encryption SecurityServiceMode choice", HFILL }},
	{ &hf_h225_SecurityServiceMode_authentication,
		{ "Authentication", "h225.SecurityServiceMode_authentication", FT_UINT32, BASE_DEC,
		VALS(SecurityServiceMode_vals), 0, "Authentication SecurityServiceMode choice", HFILL }},
	{ &hf_h225_SecurityServiceMode_integrity,
		{ "Integrity", "h225.SecurityServiceMode_integrity", FT_UINT32, BASE_DEC,
		VALS(SecurityServiceMode_vals), 0, "Integrity SecurityServiceMode choice", HFILL }},
	{ &hf_h225_SecurityCapabilities_tls,
		{ "TLS", "h225.SecurityCapabilities.tls", FT_NONE, BASE_NONE,
		NULL, 0, "TLS SecurityCapabilities sequence", HFILL }},
	{ &hf_h225_SecurityCapabilities_ipsec,
		{ "IPSec", "h225.SecurityCapabilities.ipsec", FT_NONE, BASE_NONE,
		NULL, 0, "IPSec SecurityCapabilities sequence", HFILL }},
	{ &hf_h225_H245Security,
		{ "H245Security", "h225.H245Security", FT_UINT32, BASE_DEC,
		VALS(H245Security_vals), 0, "H245Security choice", HFILL }},
	{ &hf_h225_nonStandardUsageTypes,
		{ "nonStandardUsageTypes", "h225.nonStandardUsageTypes", FT_NONE, BASE_NONE,
		NULL, 0, "nonStandardUsageTypes sequence of", HFILL }},
	{ &hf_h225_route,
		{ "route", "h225.route", FT_NONE, BASE_NONE,
		NULL, 0, "Source Routing route", HFILL }},
	{ &hf_h225_RasUsageInfoTypes,
		{ "RasUsageInfoTypes", "h225.RasUsageInfoTypes", FT_NONE, BASE_NONE,
		NULL, 0, "RasUsageInfoTypes sequence", HFILL }},
	{ &hf_h225_usageReportingCapability,
		{ "usageReportingCapability", "h225.usageReportingCapability", FT_NONE, BASE_NONE,
		NULL, 0, "usageReportingCapability sequence", HFILL }},
	{ &hf_h225_BandWidth,
		{ "BandWidth", "h225.BandWidth", FT_UINT32, BASE_DEC,
		NULL, 0, "BandWidth in units of 100bits", HFILL }},
	{ &hf_h225_channelRate,
		{ "channelRate", "h225.channelRate", FT_UINT32, BASE_DEC,
		NULL, 0, "channelRate in units of 100bits", HFILL }},
	{ &hf_h225_totalBandwidthRestriction,
		{ "totalBandwidthRestriction", "h225.totalBandwidthRestriction", FT_UINT32, BASE_DEC,
		NULL, 0, "totalBandwidthRestriction in units of 100bits", HFILL }},
	{ &hf_h225_allowedBandWidth,
		{ "allowedBandWidth", "h225.allowedBandWidth", FT_UINT32, BASE_DEC,
		NULL, 0, "allowedBandWidth in units of 100bits", HFILL }},
	{ &hf_h225_channelMultiplier,
		{ "channelMultiplier", "h225.channelMultiplier", FT_UINT32, BASE_DEC,
		NULL, 0, "channelMultiplier", HFILL }},
	{ &hf_h225_DataRate,
		{ "DataRate", "h225.DataRate", FT_NONE, BASE_NONE,
		NULL, 0, "DataRate sequence", HFILL }},
	{ &hf_h225_gatewayDataRate,
		{ "gatewayDataRate", "h225.gatewayDataRate", FT_NONE, BASE_NONE,
		NULL, 0, "gatewayDataRate sequence", HFILL }},
	{ &hf_h225_dataRatesSupported,
		{ "dataRatesSupported", "h225.dataRatesSupported", FT_NONE, BASE_NONE,
		NULL, 0, "dataRatesSupported sequence of", HFILL }},
	{ &hf_h225_TerminalInfo,
		{ "TerminalInfo", "h225.TerminalInfo", FT_NONE, BASE_NONE,
		NULL, 0, "TerminalInfo sequence", HFILL }},
	{ &hf_h225_cname,
		{ "cname", "h225.cname", FT_STRING, BASE_NONE,
		NULL, 0, "cname", HFILL }},
	{ &hf_h225_h248Message,
		{ "h248Message", "h225.h248Message", FT_STRING, BASE_NONE,
		NULL, 0, "h248Message", HFILL }},
	{ &hf_h225_conferenceID,
		{ "conferenceID", "h225.conferenceID", FT_BYTES, BASE_HEX,
		NULL, 0, "conferenceID", HFILL }},
	{ &hf_h225_Generic_nonStandard,
		{ "nonStandard", "h225.Generic_nonStandard", FT_BYTES, BASE_HEX,
		NULL, 0, "Generic_nonStandard", HFILL }},
	{ &hf_h225_guid,
		{ "guid", "h225.guid", FT_BYTES, BASE_HEX,
		NULL, 0, "guid", HFILL }},
	{ &hf_h225_replaceWithConferenceInvite,
		{ "replaceWithConferenceInvite", "h225.replaceWithConferenceInvite", FT_BYTES, BASE_HEX,
		NULL, 0, "replaceWithConferenceInvite", HFILL }},
	{ &hf_h225_StimulusControl,
		{ "StimulusControl", "h225.StimulusControl", FT_NONE, BASE_NONE,
		NULL, 0, "StimulusControl sequence", HFILL }},
	{ &hf_h225_ReleaseCompleteReason,
		{ "ReleaseCompleteReason", "h225.ReleaseCompleteReason", FT_UINT32, BASE_DEC,
		VALS(ReleaseCompleteReason_vals), 0, "ReleaseCompleteReason choice", HFILL }},
	{ &hf_h225_numberOfScnConnections,
		{ "numberOfScnConnections", "h225.numberOfScnConnections", FT_UINT32, BASE_DEC,
		NULL, 0, "numberOfScnConnections", HFILL }},
	{ &hf_h225_connectionParameters,
		{ "connectionParameters", "h225.connectionParameters", FT_NONE, BASE_NONE,
		NULL, 0, "connectionParameters sequence", HFILL }},
	{ &hf_h225_RequestSeqNum,
		{ "RequestSeqNum", "h225.RequestSeqNum", FT_UINT32, BASE_DEC,
		NULL, 0, "RequestSeqNum", HFILL }},
	{ &hf_h225_RasUsageSpecification_when,
		{ "RasUsageSpecification_when", "h225.RasUsageSpecification_when", FT_NONE, BASE_NONE,
		NULL, 0, "RasUsageSpecification_when sequence", HFILL }},
	{ &hf_h225_RasUsageSpecification_callStartingPoint,
		{ "RasUsageSpecification_callStartingPoint", "h225.RasUsageSpecification_callStartingPoint", FT_NONE, BASE_NONE,
		NULL, 0, "RasUsageSpecification_callStartingPoint sequence", HFILL }},
	{ &hf_h225_RasUsageSpecification,
		{ "RasUsageSpecification", "h225.RasUsageSpecification", FT_NONE, BASE_NONE,
		NULL, 0, "RasUsageSpecification sequence", HFILL }},
	{ &hf_h225_ipAddress_ip,
		{ "IP", "h245.ipAddress.ip", FT_IPv4, BASE_NONE,
		NULL, 0, "IPv4 Address", HFILL }},
	{ &hf_h225_ipAddress_port,
		{ "Port", "h225.ipAddress.port", FT_UINT16, BASE_DEC,
		NULL, 0, "Port number", HFILL }},
	{ &hf_h225_ipAddress,
		{ "ipAddress", "h225.ipAddress", FT_NONE, BASE_NONE,
		NULL, 0, "ipAddress sequence", HFILL }},
	{ &hf_h225_routing,
		{ "routing", "h225.routing", FT_UINT32, BASE_DEC,
		VALS(routing_vals), 0, "routing choice", HFILL }},
	{ &hf_h225_ipSourceRoute,
		{ "ipSourceRoute", "h225.ipSourceRoute", FT_NONE, BASE_NONE,
		NULL, 0, "ipSourceRoute sequence", HFILL }},
	{ &hf_h225_ipxNode,
		{ "Node", "h225.ipx.node", FT_BYTES, BASE_HEX,
		NULL, 0, "ipx node", HFILL }},
	{ &hf_h225_ipxNetnum,
		{ "Netnum", "h225.ipx.netnum", FT_BYTES, BASE_HEX,
		NULL, 0, "ipx netnum", HFILL }},
	{ &hf_h225_ipxPort,
		{ "Port", "h225.ipx.port", FT_BYTES, BASE_HEX,
		NULL, 0, "ipx port number", HFILL }},
	{ &hf_h225_ipxAddress,
		{ "ipxAddress", "h225.ipxAddress", FT_NONE, BASE_NONE,
		NULL, 0, "ipxAddress sequence", HFILL }},
	{ &hf_h225_ipv6Address_ip,
		{ "IP", "h225.ipv6Address.ip", FT_BYTES, BASE_HEX,
		NULL, 0, "ipv6 address", HFILL }},
	{ &hf_h225_ipv6Address_port,
		{ "Port", "h225.ipv6Address.port", FT_UINT16, BASE_DEC,
		NULL, 0, "Port number", HFILL }},
	{ &hf_h225_ip6Address,
		{ "ip6Address", "h225.ip6Address", FT_NONE, BASE_NONE,
		NULL, 0, "ip6Address sequence", HFILL }},
	{ &hf_h225_netBios,
		{ "netBios", "h225.netBios", FT_BYTES, BASE_HEX,
		NULL, 0, "netBios octet string", HFILL }},
	{ &hf_h225_nsap,
		{ "nsap", "h225.nsap", FT_BYTES, BASE_HEX,
		NULL, 0, "nsap octet string", HFILL }},
	{ &hf_h225_rasAddress,
		{ "rasAddress", "h225.rasAddress", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "rasAddress choice", HFILL }},
	{ &hf_h225_TransportAddress,
		{ "TransportAddress", "h225.TransportAddress", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "TransportAddress choice", HFILL }},
	{ &hf_h225_replyAddress,
		{ "replyAddress", "h225.replyAddress", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "replyAddress choice", HFILL }},
	{ &hf_h225_h245Address,
		{ "h245Address", "h225.h245Address", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "h245Address choice", HFILL }},
	{ &hf_h225_destCallSignalAddress,
		{ "destCallSignalAddress", "h225.destCallSignalAddress", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "destCallSignalAddress choice", HFILL }},
	{ &hf_h225_sourceCallSignalAddress,
		{ "sourceCallSignalAddress", "h225.sourceCallSignalAddress", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "sourceCallSignalAddress choice", HFILL }},
	{ &hf_h225_CallSignalAddress2,
		{ "CallSignalAddress2", "h225.CallSignalAddress2", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "CallSignalAddress2 choice", HFILL }},
	{ &hf_h225_alternativeAddress,
		{ "alternativeAddress", "h225.alternativeAddress", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "alternativeAddress choice", HFILL }},
	{ &hf_h225_transportID,
		{ "transportID", "h225.transportID", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "transportID choice", HFILL }},
	{ &hf_h225_sendAddress,
		{ "sendAddress", "h225.sendAddress", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "sendAddress choice", HFILL }},
	{ &hf_h225_recvAddress,
		{ "recvAddress", "h225.recvAddress", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "recvAddress choice", HFILL }},
	{ &hf_h225_rtpAddress,
		{ "rtpAddress", "h225.rtpAddress", FT_NONE, BASE_NONE,
		NULL, 0, "rtpAddress sequence", HFILL }},
	{ &hf_h225_rtcpAddress,
		{ "rtcpAddress", "h225.rtcpAddress", FT_NONE, BASE_NONE,
		NULL, 0, "rtcpAddress sequence", HFILL }},
	{ &hf_h225_h245,
		{ "h245", "h225.h245", FT_NONE, BASE_NONE,
		NULL, 0, "h245 sequence", HFILL }},
	{ &hf_h225_callSignaling,
		{ "callSignaling", "h225.callSignaling", FT_NONE, BASE_NONE,
		NULL, 0, "callSignaling sequence", HFILL }},
	{ &hf_h225_carrierName,
		{ "carrierName", "h225.carrierName", FT_BYTES, BASE_HEX,
		NULL, 0, "carrierName IA5String", HFILL }},
	{ &hf_h225_carrierIdentificationCode,
		{ "carrierIdentificationCode", "h225.carrierIdentificationCode", FT_BYTES, BASE_HEX,
		NULL, 0, "carrierIdentificationCode octet string", HFILL }},
	{ &hf_h225_CarrierInfo,
		{ "CarrierInfo", "h225.CarrierInfo", FT_NONE, BASE_NONE,
		NULL, 0, "CarrierInfo sequence", HFILL }},
	{ &hf_h225_segment,
		{ "segment", "h225.segment", FT_UINT32, BASE_DEC,
		NULL, 0, "segment", HFILL }},
	{ &hf_h225_InfoRequestResponseStatus,
		{ "InfoRequestResponseStatus", "h225.InfoRequestResponseStatus", FT_UINT32, BASE_DEC,
		VALS(InfoRequestResponseStatus_vals), 0, "InfoRequestResponseStatus choice", HFILL }},
	{ &hf_h225_CallIdentifier,
		{ "CallIdentifier", "h225.CallIdentifier", FT_NONE, BASE_NONE,
		NULL, 0, "CallIdentifier sequence", HFILL }},
	{ &hf_h225_globalCallId,
		{ "globalCallId", "h225.globalCallId", FT_BYTES, BASE_HEX,
		NULL, 0, "globalCallId octet string", HFILL }},
	{ &hf_h225_threadId,
		{ "threadId", "h225.threadId", FT_BYTES, BASE_HEX,
		NULL, 0, "threadId octet string", HFILL }},
	{ &hf_h225_CallLinkage,
		{ "CallLinkage", "h225.CallLinkage", FT_NONE, BASE_NONE,
		NULL, 0, "CallLinkage sequence", HFILL }},
	{ &hf_h225_tokens,
		{ "tokens", "h225.tokens", FT_NONE, BASE_NONE,
		NULL, 0, "tokens sequence of", HFILL }},
	{ &hf_h225_needToRegister,
		{ "needToRegister", "h225.needToRegister", FT_BOOLEAN, 8,
		TFS(&tfs_needToRegister_bit), 0x01, "needToRegister boolean", HFILL }},
	{ &hf_h225_priority,
		{ "priority", "h225.priority", FT_UINT32, BASE_DEC,
		NULL, 0, "priority", HFILL }},
	{ &hf_h225_AlternateGK,
		{ "AlternateGK", "h225.AlternateGK", FT_NONE, BASE_NONE,
		NULL, 0, "AlternateGK sequence", HFILL }},
	{ &hf_h225_alternateGatekeeper,
		{ "alternateGatekeeper", "h225.alternateGatekeeper", FT_NONE, BASE_NONE,
		NULL, 0, "alternateGatekeeper sequence of", HFILL }},
	{ &hf_h225_altGKisPermanent,
		{ "altGKisPermanent", "h225.altGKisPermanent", FT_BOOLEAN, 8,
		TFS(&tfs_altGKisPermanent_bit), 0x01, "altGKisPermanent boolean", HFILL }},
	{ &hf_h225_AltGKInfo,
		{ "AltGKInfo", "h225.AltGKInfo", FT_NONE, BASE_NONE,
		NULL, 0, "AltGKInfo sequence", HFILL }},
	{ &hf_h225_annexE,
		{ "annexE", "h225.annexE", FT_NONE, BASE_NONE,
		NULL, 0, "annexE sequence of", HFILL }},
	{ &hf_h225_sctp,
		{ "sctp", "h225.sctp", FT_NONE, BASE_NONE,
		NULL, 0, "sctp sequence of", HFILL }},
	{ &hf_h225_AlternateTransportAddress,
		{ "AlternateTransportAddress", "h225.AlternateTransportAddress", FT_NONE, BASE_NONE,
		NULL, 0, "AlternateTransportAddress sequence", HFILL }},
	{ &hf_h225_setup_bool,
		{ "setup_bool", "h225.setup_bool", FT_BOOLEAN, 8,
		TFS(&tfs_setup_bool_bit), 0x01, "setup_bool boolean", HFILL }},
	{ &hf_h225_callProceeding_bool,
		{ "callProceeding_bool", "h225.callProceeding_bool", FT_BOOLEAN, 8,
		TFS(&tfs_callProceeding_bool_bit), 0x01, "callProceeding_bool boolean", HFILL }},
	{ &hf_h225_connect_bool,
		{ "connect_bool", "h225.connect_bool", FT_BOOLEAN, 8,
		TFS(&tfs_connect_bool_bit), 0x01, "connect_bool boolean", HFILL }},
	{ &hf_h225_alerting_bool,
		{ "alerting_bool", "h225.alerting_bool", FT_BOOLEAN, 8,
		TFS(&tfs_alerting_bool_bit), 0x01, "alerting_bool boolean", HFILL }},
	{ &hf_h225_information_bool,
		{ "information_bool", "h225.information_bool", FT_BOOLEAN, 8,
		TFS(&tfs_information_bool_bit), 0x01, "information_bool boolean", HFILL }},
	{ &hf_h225_releaseComplete_bool,
		{ "releaseComplete_bool", "h225.releaseComplete_bool", FT_BOOLEAN, 8,
		TFS(&tfs_releaseComplete_bool_bit), 0x01, "releaseComplete_bool boolean", HFILL }},
	{ &hf_h225_facility_bool,
		{ "facility_bool", "h225.facility_bool", FT_BOOLEAN, 8,
		TFS(&tfs_facility_bool_bit), 0x01, "facility_bool boolean", HFILL }},
	{ &hf_h225_progress_bool,
		{ "progress_bool", "h225.progress_bool", FT_BOOLEAN, 8,
		TFS(&tfs_progress_bool_bit), 0x01, "progress_bool boolean", HFILL }},
	{ &hf_h225_empty_bool,
		{ "empty_bool", "h225.empty_bool", FT_BOOLEAN, 8,
		TFS(&tfs_empty_bool_bit), 0x01, "empty_bool boolean", HFILL }},
	{ &hf_h225_status_bool,
		{ "status_bool", "h225.status_bool", FT_BOOLEAN, 8,
		TFS(&tfs_status_bool_bit), 0x01, "status_bool boolean", HFILL }},
	{ &hf_h225_statusInquiry_bool,
		{ "statusInquiry_bool", "h225.statusInquiry_bool", FT_BOOLEAN, 8,
		TFS(&tfs_statusInquiry_bool_bit), 0x01, "statusInquiry_bool boolean", HFILL }},
	{ &hf_h225_setupAcknowledge_bool,
		{ "setupAcknowledge_bool", "h225.setupAcknowledge_bool", FT_BOOLEAN, 8,
		TFS(&tfs_setupAcknowledge_bool_bit), 0x01, "setupAcknowledge_bool boolean", HFILL }},
	{ &hf_h225_notify_bool,
		{ "notify_bool", "h225.notify_bool", FT_BOOLEAN, 8,
		TFS(&tfs_notify_bool_bit), 0x01, "notify_bool boolean", HFILL }},
	{ &hf_h225_UUIEsRequested,
		{ "UUIEsRequested", "h225.UUIEsRequested", FT_NONE, BASE_NONE,
		NULL, 0, "UUIEsRequested sequence", HFILL }},
	{ &hf_h225_conferenceCalling,
		{ "conferenceCalling", "h225.conferenceCalling", FT_BOOLEAN, 8,
		TFS(&tfs_conferenceCalling_bit), 0x01, "conferenceCalling boolean", HFILL }},
	{ &hf_h225_threePartyService,
		{ "threePartyService", "h225.threePartyService", FT_BOOLEAN, 8,
		TFS(&tfs_threePartyService_bit), 0x01, "threePartyService boolean", HFILL }},
	{ &hf_h225_Q954Details,
		{ "Q954Details", "h225.Q954Details", FT_NONE, BASE_NONE,
		NULL, 0, "Q954Details sequence", HFILL }},
	{ &hf_h225_q932Full,
		{ "q932Full", "h225.q932Full", FT_BOOLEAN, 8,
		TFS(&tfs_q932Full_bit), 0x01, "q932Full boolean", HFILL }},
	{ &hf_h225_q951Full,
		{ "q951Full", "h225.q951Full", FT_BOOLEAN, 8,
		TFS(&tfs_q951Full_bit), 0x01, "q951Full boolean", HFILL }},
	{ &hf_h225_q952Full,
		{ "q952Full", "h225.q952Full", FT_BOOLEAN, 8,
		TFS(&tfs_q952Full_bit), 0x01, "q952Full boolean", HFILL }},
	{ &hf_h225_q953Full,
		{ "q953Full", "h225.q953Full", FT_BOOLEAN, 8,
		TFS(&tfs_q953Full_bit), 0x01, "q953Full boolean", HFILL }},
	{ &hf_h225_q955Full,
		{ "q955Full", "h225.q955Full", FT_BOOLEAN, 8,
		TFS(&tfs_q955Full_bit), 0x01, "q955Full boolean", HFILL }},
	{ &hf_h225_q956Full,
		{ "q956Full", "h225.q956Full", FT_BOOLEAN, 8,
		TFS(&tfs_q956Full_bit), 0x01, "q956Full boolean", HFILL }},
	{ &hf_h225_q957Full,
		{ "q957Full", "h225.q957Full", FT_BOOLEAN, 8,
		TFS(&tfs_q957Full_bit), 0x01, "q957Full boolean", HFILL }},
	{ &hf_h225_QseriesOptions,
		{ "callServices", "h225.callServices", FT_NONE, BASE_NONE,
		NULL, 0, "QseriesOptions sequence", HFILL }},
	{ &hf_h225_ssrc,
		{ "ssrc", "h225.ssrc", FT_UINT32, BASE_DEC,
		NULL, 0, "ssrc", HFILL }},
	{ &hf_h225_RTPsessionId,
		{ "RTPsessionId", "h225.RTPsessionId", FT_UINT32, BASE_DEC,
		NULL, 0, "RTPsessionId", HFILL }},
	{ &hf_h225_associatedSessionIds,
		{ "associatedSessionIds", "h225.associatedSessionIds", FT_NONE, BASE_NONE,
		NULL, 0, "associatedSessionIds sequence of", HFILL }},
	{ &hf_h225_RTPSession,
		{ "RTPSession", "h225.RTPSession", FT_NONE, BASE_NONE,
		NULL, 0, "RTPSession sequence", HFILL }},
	{ &hf_h225_cryptoTokens,
		{ "cryptoTokens", "h225.cryptoTokens", FT_NONE, BASE_NONE,
		NULL, 0, "cryptoTokens sequence of", HFILL }},
	{ &hf_h225_tunnelledProtocolObjectID,
		{ "tunnelledProtocolObjectID", "h225.tunnelledProtocolObjectID", FT_STRING, BASE_NONE,
		NULL, 0, "tunnelledProtocolObjectID object", HFILL }},
	{ &hf_h225_ProtocolIdentifier,
		{ "ProtocolIdentifier", "h225.ProtocolIdentifier", FT_STRING, BASE_NONE,
		NULL, 0, "ProtocolIdentifier object", HFILL }},
	{ &hf_h225_isoAlgorithm,
		{ "isoAlgorithm", "h225.isoAlgorithm", FT_STRING, BASE_NONE,
		NULL, 0, "isoAlgorithm object", HFILL }},
	{ &hf_h225_algorithmOID,
		{ "algorithmOID", "h225.algorithmOID", FT_STRING, BASE_NONE,
		NULL, 0, "algorithmOID object", HFILL }},
	{ &hf_h225_iso9797,
		{ "iso9797", "h225.iso9797", FT_STRING, BASE_NONE,
		NULL, 0, "iso9797 object", HFILL }},
	{ &hf_h225_hMAC_iso10118_3,
		{ "hMAC_iso10118_3", "h225.hMAC_iso10118_3", FT_STRING, BASE_NONE,
		NULL, 0, "hMAC_iso10118_3 object", HFILL }},
	{ &hf_h225_enterpriseNumber,
		{ "enterpriseNumber", "h225.enterpriseNumber", FT_STRING, BASE_NONE,
		NULL, 0, "enterpriseNumber object", HFILL }},
	{ &hf_h225_Generic_oid,
		{ "OID", "h225.Generic_oid", FT_STRING, BASE_NONE,
		NULL, 0, "Generic OID object", HFILL }},
	{ &hf_h225_StatusUUIE,
		{ "StatusUUIE", "h225.StatusUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "StatusUUIE sequence", HFILL }},
	{ &hf_h225_StatusInquiryUUIE,
		{ "StatusInquiryUUIE", "h225.StatusInquiryUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "StatusInquiryUUIE sequence", HFILL }},
	{ &hf_h225_SetupAcknowledgeUUIE,
		{ "SetupAcknowledgeUUIE", "h225.SetupAcknowledgeUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "SetupAcknowledgeUUIE sequence", HFILL }},
	{ &hf_h225_NotifyUUIE,
		{ "NotifyUUIE", "h225.NotifyUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "NotifyUUIE sequence", HFILL }},
	{ &hf_h225_imsi,
		{ "imsi", "h225.imsi", FT_STRING, BASE_HEX,
		NULL, 0, "imsi string", HFILL }},
	{ &hf_h225_tmsi,
		{ "tmsi", "h225.tmsi", FT_BYTES, BASE_HEX,
		NULL, 0, "tmsi octet string", HFILL }},
	{ &hf_h225_msisdn,
		{ "msisdn", "h225.msisdn", FT_STRING, BASE_HEX,
		NULL, 0, "msisdn string", HFILL }},
	{ &hf_h225_imei,
		{ "imei", "h225.imei", FT_STRING, BASE_HEX,
		NULL, 0, "imei string", HFILL }},
	{ &hf_h225_hplmn,
		{ "hplmn", "h225.hplmn", FT_STRING, BASE_HEX,
		NULL, 0, "hplmn string", HFILL }},
	{ &hf_h225_vplmn,
		{ "vplmn", "h225.vplmn", FT_STRING, BASE_HEX,
		NULL, 0, "vplmn string", HFILL }},
	{ &hf_h225_GSMUIM,
		{ "GSMUIM", "h225.GSMUIM", FT_NONE, BASE_NONE,
		NULL, 0, "GSMUIM sequence", HFILL }},
	{ &hf_h225_sid,
		{ "sid", "h225.sid", FT_STRING, BASE_HEX,
		NULL, 0, "sid string", HFILL }},
	{ &hf_h225_mid,
		{ "mid", "h225.mid", FT_STRING, BASE_HEX,
		NULL, 0, "mid string", HFILL }},
	{ &hf_h225_systemid,
		{ "systemid", "h225.sustemid", FT_UINT32, BASE_DEC,
		VALS(systemid_vals), 0, "systemid choice", HFILL }},
	{ &hf_h225_min,
		{ "min", "h225.min", FT_STRING, BASE_HEX,
		NULL, 0, "min string", HFILL }},
	{ &hf_h225_mdn,
		{ "mdn", "h225.mdn", FT_STRING, BASE_HEX,
		NULL, 0, "mdn string", HFILL }},
	{ &hf_h225_esn,
		{ "esn", "h225.esn", FT_STRING, BASE_HEX,
		NULL, 0, "esn string", HFILL }},
	{ &hf_h225_mscid,
		{ "mscid", "h225.mscid", FT_STRING, BASE_HEX,
		NULL, 0, "mscid string", HFILL }},
	{ &hf_h225_systemMyTypeCode,
		{ "systemMyTypeCode", "h225.systemMyTypeCode", FT_BYTES, BASE_HEX,
		NULL, 0, "systemMyTypeCode octet string", HFILL }},
	{ &hf_h225_systemAccessType,
		{ "systemAccessType", "h225.systemAccessType", FT_BYTES, BASE_HEX,
		NULL, 0, "systemAccessType octet string", HFILL }},
	{ &hf_h225_qualificationInformationCode,
		{ "qualificationInformationCode", "h225.qualificationInformationCode", FT_BYTES, BASE_HEX,
		NULL, 0, "qualificationInformationCode octet string", HFILL }},
	{ &hf_h225_sesn,
		{ "sesn", "h225.sesn", FT_STRING, BASE_HEX,
		NULL, 0, "sesn string", HFILL }},
	{ &hf_h225_soc,
		{ "soc", "h225.soc", FT_STRING, BASE_HEX,
		NULL, 0, "soc string", HFILL }},
	{ &hf_h225_ANSI41UIM,
		{ "ANSI41UIM", "h225.ANSI41UIM", FT_NONE, BASE_NONE,
		NULL, 0, "ANSI41UIM sequence", HFILL }},
	{ &hf_h225_MobileUIM,
		{ "MobileUIM", "h225.MobileUIM", FT_UINT32, BASE_DEC,
		VALS(MobileUIM_vals), 0, "MobileUIM choice", HFILL }},
	{ &hf_h225_dataPartyNumber,
		{ "dataPartyNumber", "h225.dataPartyNumber", FT_STRING, BASE_HEX,
		NULL, 0, "dataPartyNumber string", HFILL }},
	{ &hf_h225_telexPartyNumber,
		{ "telexPartyNumber", "h225.telexPartyNumber", FT_STRING, BASE_HEX,
		NULL, 0, "telexPartyNumber string", HFILL }},
	{ &hf_h225_nationalStandardPartyNumber,
		{ "nationalStandardPartyNumber", "h225.nationalStandardPartyNumber", FT_STRING, BASE_HEX,
		NULL, 0, "nationalStandardPartyNumber string", HFILL }},
	{ &hf_h225_publicNumberDigits,
		{ "publicNumberDigits", "h225.publicNumberDigits", FT_STRING, BASE_HEX,
		NULL, 0, "publicNumberDigits string", HFILL }},
	{ &hf_h225_privateNumberDigits,
		{ "privateNumberDigits", "h225.privateNumberDigits", FT_STRING, BASE_HEX,
		NULL, 0, "privateNumberDigits string", HFILL }},
	{ &hf_h225_e164Number,
		{ "e164Number", "h225.e164Number", FT_NONE, BASE_NONE,
		NULL, 0, "e164Number sequence", HFILL }},
	{ &hf_h225_privateNumber,
		{ "privateNumber", "h225.privateNumber", FT_NONE, BASE_NONE,
		NULL, 0, "privateNumber sequence", HFILL }},
	{ &hf_h225_startOfRange,
		{ "startOfRange", "h225.startOfRange", FT_UINT32, BASE_DEC,
		VALS(PartyNumber_vals), 0, "startOfRange choice", HFILL }},
	{ &hf_h225_endOfRange,
		{ "endOfRange", "h225.endOfRange", FT_UINT32, BASE_DEC,
		VALS(PartyNumber_vals), 0, "endOfRange choice", HFILL }},
	{ &hf_h225_PartyNumber,
		{ "PartyNumber", "h225.PartyNumber", FT_UINT32, BASE_DEC,
		VALS(PartyNumber_vals), 0, "PartyNumber choice", HFILL }},
	{ &hf_h225_protocolType,
		{ "protocolType", "h225.protocolType", FT_BYTES, BASE_HEX,
		NULL, 0, "protocolType IA5String", HFILL }},
	{ &hf_h225_protocolVariant,
		{ "protocolVariant", "h225.protocolVariant", FT_BYTES, BASE_HEX,
		NULL, 0, "protocolVariant IA5String", HFILL }},
	{ &hf_h225_TunnelledProtocolAlternateIdentifier,
		{ "TunnelledProtocolAlternateIdentifier", "h225.TunnelledProtocolAlternateIdentifier", FT_NONE, BASE_NONE,
		NULL, 0, "TunnelledProtocolAlternateIdentifier sequence", HFILL }},
	{ &hf_h225_dialedDigits,
		{ "dialedDigits", "h225.dialedDigits", FT_BYTES, BASE_HEX,
		NULL, 0, "dialedDigits IA5String", HFILL }},
	{ &hf_h225_urlId,
		{ "urlId", "h225.urlId", FT_BYTES, BASE_HEX,
		NULL, 0, "urlId IA5String", HFILL }},
	{ &hf_h225_h323ID,
		{ "h323ID", "h225.h323ID", FT_STRING, BASE_HEX,
		NULL, 0, "h323ID BMPString", HFILL }},
	{ &hf_h225_GatekeeperIdentifier,
		{ "GatekeeperIdentifier", "h225.GatekeeperIdentifier", FT_STRING, BASE_HEX,
		NULL, 0, "GatekeeperIdentifier BMPString", HFILL }},
	{ &hf_h225_unicode,
		{ "unicode", "h225.unicode", FT_STRING, BASE_HEX,
		NULL, 0, "unicode BMPString", HFILL }},
	{ &hf_h225_EndpointIdentifier,
		{ "EndpointIdentifier", "h225.EndpointIdentifier", FT_STRING, BASE_HEX,
		NULL, 0, "EndpointIdentifier BMPString", HFILL }},
	{ &hf_h225_emailId,
		{ "emailId", "h225.emailId", FT_BYTES, BASE_HEX,
		NULL, 0, "emailId IA5String", HFILL }},
	{ &hf_h225_conferenceAlias,
		{ "conferenceAlias", "h225.conferenceAlias", FT_UINT32, BASE_DEC,
		VALS(AliasAddress_vals), 0, "conferenceAlias choice", HFILL }},
	{ &hf_h225_AliasAddress,
		{ "AliasAddress", "h225.AliasAddress", FT_UINT32, BASE_DEC,
		VALS(AliasAddress_vals), 0, "AliasAddress choice", HFILL }},
	{ &hf_h225_RemoteExtensionAddress,
		{ "RemoteExtensionAddress", "h225.RemoteExtensionAddress", FT_UINT32, BASE_DEC,
		VALS(AliasAddress_vals), 0, "RemoteExtensionAddress choice", HFILL }},
	{ &hf_h225_wildcard,
		{ "wildcard", "h225.wildcard", FT_UINT32, BASE_DEC,
		VALS(AliasAddress_vals), 0, "wildcard choice", HFILL }},
	{ &hf_h225_prefix,
		{ "prefix", "h225.prefix", FT_UINT32, BASE_DEC,
		VALS(AliasAddress_vals), 0, "prefix choice", HFILL }},
	{ &hf_h225_SupportedPrefix,
		{ "SupportedPrefix", "h225.SupportedPrefix", FT_NONE, BASE_NONE,
		NULL, 0, "SupportedPrefix sequence", HFILL }},
	{ &hf_h225_SupportedPrefixes,
		{ "SupportedPrefixes", "h225.SupportedPrefixes", FT_NONE, BASE_NONE,
		NULL, 0, "SupportedPrefixes sequence of", HFILL }},
	{ &hf_h225_H310Caps,
		{ "H310Caps", "h225.H310Caps", FT_NONE, BASE_NONE,
		NULL, 0, "H310Caps sequence", HFILL }},
	{ &hf_h225_H320Caps,
		{ "H320Caps", "h225.H320Caps", FT_NONE, BASE_NONE,
		NULL, 0, "H320Caps sequence", HFILL }},
	{ &hf_h225_H321Caps,
		{ "H321Caps", "h225.H321Caps", FT_NONE, BASE_NONE,
		NULL, 0, "H321Caps sequence", HFILL }},
	{ &hf_h225_H322Caps,
		{ "H322Caps", "h225.H322Caps", FT_NONE, BASE_NONE,
		NULL, 0, "H322Caps sequence", HFILL }},
	{ &hf_h225_H323Caps,
		{ "H323Caps", "h225.H323Caps", FT_NONE, BASE_NONE,
		NULL, 0, "H323Caps sequence", HFILL }},
	{ &hf_h225_H324Caps,
		{ "H324Caps", "h225.H324Caps", FT_NONE, BASE_NONE,
		NULL, 0, "H324Caps sequence", HFILL }},
	{ &hf_h225_VoiceCaps,
		{ "VoiceCaps", "h225.VoiceCaps", FT_NONE, BASE_NONE,
		NULL, 0, "VoiceCaps sequence", HFILL }},
	{ &hf_h225_T120OnlyCaps,
		{ "T120OnlyCaps", "h225.T120OnlyCaps", FT_NONE, BASE_NONE,
		NULL, 0, "T120OnlyCaps sequence", HFILL }},
	{ &hf_h225_NonStandardProtocol,
		{ "NonStandardProtocol", "h225.NonStandardProtocol", FT_NONE, BASE_NONE,
		NULL, 0, "NonStandardProtocol sequence", HFILL }},
	{ &hf_h225_SIPCaps,
		{ "SIPCaps", "h225.SIPCaps", FT_NONE, BASE_NONE,
		NULL, 0, "SIPCaps sequence", HFILL }},
	{ &hf_h225_AddressPattern_range,
		{ "AddressPattern_range", "h225.AddressPattern_range", FT_NONE, BASE_NONE,
		NULL, 0, "AddressPattern_range sequence", HFILL }},
	{ &hf_h225_AddressPattern,
		{ "AddressPattern", "h225.AddressPattern", FT_UINT32, BASE_DEC,
		VALS(AddressPattern_vals), 0, "AddressPattern choice", HFILL }},
	{ &hf_h225_ConferenceList,
		{ "ConferenceList", "h225.ConferenceList", FT_NONE, BASE_NONE,
		NULL, 0, "ConferenceList sequence", HFILL }},
	{ &hf_h225_conferences,
		{ "conferences", "h225.conferences", FT_NONE, BASE_NONE,
		NULL, 0, "conferences sequence of", HFILL }},
	{ &hf_h225_T38FaxAnnexbOnlyCaps,
		{ "T38FaxAnnexbOnlyCaps", "h225.T38FaxAnnexbOnlyCaps", FT_NONE, BASE_NONE,
		NULL, 0, "T38FaxAnnexbOnlyCaps sequence", HFILL }},
	{ &hf_h225_SupportedProtocols,
		{ "SupportedProtocols", "h225.SupportedProtocols", FT_UINT32, BASE_DEC,
		VALS(SupportedProtocols_vals), 0, "SupportedProtocols choice", HFILL }},
	{ &hf_h225_protocol,
		{ "protocol", "h225.protocol", FT_NONE, BASE_NONE,
		NULL, 0, "protocol sequence of", HFILL }},
	{ &hf_h225_GatewayInfo,
		{ "GatewayInfo", "h225.GatewayInfo", FT_NONE, BASE_NONE,
		NULL, 0, "GatewayInfo sequence", HFILL }},
	{ &hf_h225_McuInfo,
		{ "McuInfo", "h225.McuInfo", FT_NONE, BASE_NONE,
		NULL, 0, "McuInfo sequence", HFILL }},
	{ &hf_h225_TunnelledProtocol_id,
		{ "id", "h225.TunnelledProtocol_id", FT_NONE, BASE_NONE,
		NULL, 0, "TunnelledProtocol_id sequence", HFILL }},
	{ &hf_h225_TunnelledProtocol_subIdentifier,
		{ "subIdentifier", "h225.TunnelledProtocol_subIdentifier", FT_BYTES, BASE_HEX,
		NULL, 0, "TunnelledProtocol_subIdentifier IA5String", HFILL }},
	{ &hf_h225_TunnelledProtocol,
		{ "TunnelledProtocol", "h225.TunnelledProtocol", FT_NONE, BASE_NONE,
		NULL, 0, "TunnelledProtocol sequence", HFILL }},
	{ &hf_h225_desiredTunnelledProtocol,
		{ "desiredTunnelledProtocol", "h225.desiredTunnelledProtocol", FT_NONE, BASE_NONE,
		NULL, 0, "desiredTunnelledProtocol sequence", HFILL }},
	{ &hf_h225_CicInfo_cic_item,
		{ "item", "h225.CicInfo_cic_item", FT_BYTES, BASE_HEX,
		NULL, 0, "CicInfo_cic_item octet string", HFILL }},
	{ &hf_h225_CicInfo_pointCode,
		{ "pointCode", "h225.CicInfo_pointCode", FT_BYTES, BASE_HEX,
		NULL, 0, "CicInfo_pointCode octet string", HFILL }},
	{ &hf_h225_CicInfo_cic,
		{ "cic", "h225.CicInfo_cic", FT_NONE, BASE_NONE,
		NULL, 0, "CicInfo_cic sequence of", HFILL }},
	{ &hf_h225_CicInfo,
		{ "CicInfo", "h225.CicInfo", FT_NONE, BASE_NONE,
		NULL, 0, "CicInfo sequence", HFILL }},
	{ &hf_h225_GroupID_member_item,
		{ "item", "h225.GroupID_member_item", FT_UINT32, BASE_DEC,
		NULL, 0, "GroupID_member_item", HFILL }},
	{ &hf_h225_GroupID_member,
		{ "member", "h225.GroupID_member", FT_NONE, BASE_NONE,
		NULL, 0, "GroupID_member sequence of", HFILL }},
	{ &hf_h225_GroupID_group,
		{ "group", "h225.GroupID_group", FT_BYTES, BASE_HEX,
		NULL, 0, "GroupID_group IA5String", HFILL }},
	{ &hf_h225_GroupID,
		{ "GroupID", "h225.GroupID", FT_NONE, BASE_NONE,
		NULL, 0, "GroupID sequence", HFILL }},
	{ &hf_h225_sourceCircuitID,
		{ "sourceCircuitID", "h225.sourceCircuitID", FT_NONE, BASE_NONE,
		NULL, 0, "sourceCircuitID sequence", HFILL }},
	{ &hf_h225_destinationCircuitID,
		{ "destinationCircuitID", "h225.destinationCircuitID", FT_NONE, BASE_NONE,
		NULL, 0, "destinationCircuitID sequence", HFILL }},
	{ &hf_h225_Generic_standard,
		{ "standard", "h225.Generic_standard", FT_UINT32, BASE_DEC,
		NULL, 0, "Generic_standard", HFILL }},
	{ &hf_h225_GenericIdentifier,
		{ "GenericIdentifier", "h225.GenericIdentifier", FT_UINT32, BASE_DEC,
		VALS(GenericIdentifier_vals), 0, "GenericIdentifier choice", HFILL }},
	{ &hf_h225_EnumeratedParameter,
		{ "EnumeratedParameter", "h225.EnumeratedParameter", FT_NONE, BASE_NONE,
		NULL, 0, "EnumeratedParameter sequence", HFILL }},
	{ &hf_h225_parameters,
		{ "parameters", "h225.parameters", FT_NONE, BASE_NONE,
		NULL, 0, "parameters sequence of", HFILL }},
	{ &hf_h225_GenericData,
		{ "GenericData", "h225.GenericData", FT_NONE, BASE_NONE,
		NULL, 0, "GenericData sequence", HFILL }},
	{ &hf_h225_FeatureDescriptor,
		{ "FeatureDescriptor", "h225.FeatureDescriptor", FT_NONE, BASE_NONE,
		NULL, 0, "FeatureDescriptor sequence", HFILL }},
	{ &hf_h225_Content_raw,
		{ "Content_raw", "h225.Content_raw", FT_BYTES, BASE_HEX,
		NULL, 0, "Content_raw octet string", HFILL }},
	{ &hf_h225_Content_text,
		{ "Content_text", "h225.Content_text", FT_BYTES, BASE_HEX,
		NULL, 0, "Content_text IA5String", HFILL }},
	{ &hf_h225_Content,
		{ "Content", "h225.Content", FT_UINT32, BASE_DEC,
		VALS(Content_vals), 0, "Content choice", HFILL }},
	{ &hf_h225_Content_bool,
		{ "Content_bool", "h225.Content_bool", FT_BOOLEAN, 8,
		TFS(&tfs_Content_bool_bit), 0x01, "Content_bool boolean", HFILL }},
	{ &hf_h225_Content_number8,
		{ "Content_number8", "h225.Content_number8", FT_UINT32, BASE_DEC,
		NULL, 0, "Content_number8", HFILL }},
	{ &hf_h225_number16,
		{ "number16", "h225.number16", FT_UINT32, BASE_DEC,
		NULL, 0, "number16", HFILL }},
	{ &hf_h225_Content_number32,
		{ "Content_number32", "h225.Content_number32", FT_UINT32, BASE_DEC,
		NULL, 0, "Content_number32", HFILL }},
	{ &hf_h225_Content_compound,
		{ "Content_compound", "h225.Content_compound", FT_NONE, BASE_NONE,
		NULL, 0, "Content_compound sequence of", HFILL }},
	{ &hf_h225_Content_nested,
		{ "Content_nested", "h225.Content_nested", FT_NONE, BASE_NONE,
		NULL, 0, "Content_nested sequence of", HFILL }},
	{ &hf_h225_replacementFeatureSet,
		{ "replacementFeatureSet", "h225.replacementFeatureSet", FT_BOOLEAN, 8,
		TFS(&tfs_replacementFeatureSet_bit), 0x01, "replacementFeatureSet boolean", HFILL }},
	{ &hf_h225_neededFeatures,
		{ "neededFeatures", "h225.neededFeatures", FT_NONE, BASE_NONE,
		NULL, 0, "neededFeatures sequence of", HFILL }},
	{ &hf_h225_desiredFeatures,
		{ "desiredFeatures", "h225.desiredFeatures", FT_NONE, BASE_NONE,
		NULL, 0, "desiredFeatures sequence of", HFILL }},
	{ &hf_h225_supportedFeatures,
		{ "supportedFeatures", "h225.supportedFeatures", FT_NONE, BASE_NONE,
		NULL, 0, "supportedFeatures sequence of", HFILL }},
	{ &hf_h225_FeatureSet,
		{ "FeatureSet", "h225.FeatureSet", FT_NONE, BASE_NONE,
		NULL, 0, "FeatureSet sequence", HFILL }},
	{ &hf_h225_CallsAvailable_calls,
		{ "CallsAvailable_calls", "h225.CallsAvailable_calls", FT_UINT32, BASE_DEC,
		NULL, 0, "CallsAvailable_calls", HFILL }},
	{ &hf_h225_CallsAvailable_group,
		{ "CallsAvailable_group", "h225.CallsAvailable_group", FT_BYTES, BASE_HEX,
		NULL, 0, "CallsAvailable_group IA5String", HFILL }},
	{ &hf_h225_CallsAvailable,
		{ "CallsAvailable", "h225.CallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "CallsAvailable sequence", HFILL }},
	{ &hf_h225_voiceGwCallsAvailable,
		{ "voiceGwCallsAvailable", "h225.voiceGwCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "voiceGwCallsAvailable sequence of", HFILL }},
	{ &hf_h225_h310GwCallsAvailable,
		{ "h310GwCallsAvailable", "h225.h310GwCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "h310GwCallsAvailable sequence of", HFILL }},
	{ &hf_h225_h320GwCallsAvailable,
		{ "h320GwCallsAvailable", "h225.h320GwCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "h320GwCallsAvailable sequence of", HFILL }},
	{ &hf_h225_h321GwCallsAvailable,
		{ "h321GwCallsAvailable", "h225.h321GwCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "h321GwCallsAvailable sequence of", HFILL }},
	{ &hf_h225_h322GwCallsAvailable,
		{ "h322GwCallsAvailable", "h225.h322GwCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "h322GwCallsAvailable sequence of", HFILL }},
	{ &hf_h225_h323GwCallsAvailable,
		{ "h323GwCallsAvailable", "h225.h323GwCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "h323GwCallsAvailable sequence of", HFILL }},
	{ &hf_h225_h324GwCallsAvailable,
		{ "h324GwCallsAvailable", "h225.h324GwCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "h324GwCallsAvailable sequence of", HFILL }},
	{ &hf_h225_t120OnlyGwCallsAvailable,
		{ "t120OnlyGwCallsAvailable", "h225.t120OnlyGwCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "t120OnlyGwCallsAvailable sequence of", HFILL }},
	{ &hf_h225_t38FaxAnnexbOnlyGwCallsAvailable,
		{ "t38FaxAnnexbOnlyGwCallsAvailable", "h225.t38FaxAnnexbOnlyGwCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "t38FaxAnnexbOnlyGwCallsAvailable sequence of", HFILL }},
	{ &hf_h225_terminalCallsAvailable,
		{ "terminalCallsAvailable", "h225.terminalCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "terminalCallsAvailable sequence of", HFILL }},
	{ &hf_h225_mcuCallsAvailable,
		{ "mcuCallsAvailable", "h225.mcuCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "mcuCallsAvailable sequence of", HFILL }},
	{ &hf_h225_sipGwCallsAvailable,
		{ "sipGwCallsAvailable", "h225.sipGwCallsAvailable", FT_NONE, BASE_NONE,
		NULL, 0, "sipGwCallsAvailable sequence of", HFILL }},
	{ &hf_h225_maximumCallCapacity,
		{ "maximumCallCapacity", "h225.maximumCallCapacity", FT_NONE, BASE_NONE,
		NULL, 0, "maximumCallCapacity sequence", HFILL }},
	{ &hf_h225_currentCallCapacity,
		{ "currentCallCapacity", "h225.currentCallCapacity", FT_NONE, BASE_NONE,
		NULL, 0, "currentCallCapacity sequence", HFILL }},
	{ &hf_h225_CallCapacity,
		{ "CallCapacity", "h225.CallCapacity", FT_NONE, BASE_NONE,
		NULL, 0, "CallCapacity sequence", HFILL }},
	{ &hf_h225_productID,
		{ "productID", "h225.productID", FT_STRING, BASE_HEX,
		NULL, 0, "productID octet string", HFILL }},
	{ &hf_h225_versionID,
		{ "versionID", "h225.versionID", FT_STRING, BASE_HEX,
		NULL, 0, "versionID octet string", HFILL }},
	{ &hf_h225_VendorIdentifier,
		{ "VendorIdentifier", "h225.VendorIdentifier", FT_NONE, BASE_NONE,
		NULL, 0, "VendorIdentifier sequence", HFILL }},
	{ &hf_h225_canReportCallCapacity,
		{ "canReportCallCapacity", "h225.canReportCallCapacity", FT_BOOLEAN, 8,
		TFS(&tfs_canReportCallCapacity_bit), 0x01, "canReportCallCapacity boolean", HFILL }},
	{ &hf_h225_CapacityReportingCapability,
		{ "CapacityReportingCapability", "h225.CapacityReportingCapability", FT_NONE, BASE_NONE,
		NULL, 0, "CapacityReportingCapability sequence", HFILL }},
	{ &hf_h225_canDisplayAmountString,
		{ "canDisplayAmountString", "h225.canDisplayAmountString", FT_BOOLEAN, 8,
		TFS(&tfs_canDisplayAmountString_bit), 0x01, "canDisplayAmountString boolean", HFILL }},
	{ &hf_h225_canEnforceDurationLimit,
		{ "canEnforceDurationLimit", "h225.canEnforceDurationLimit", FT_BOOLEAN, 8,
		TFS(&tfs_canEnforceDurationLimit_bit), 0x01, "canEnforceDurationLimit boolean", HFILL }},
	{ &hf_h225_CallCreditCapability,
		{ "CallCreditCapability", "h225.CallCreditCapability", FT_NONE, BASE_NONE,
		NULL, 0, "CallCreditCapability sequence", HFILL }},
	{ &hf_h225_BandwidthDetails_sender,
		{ "BandwidthDetails_sender", "h225.BandwidthDetails_sender", FT_BOOLEAN, 8,
		TFS(&tfs_BandwidthDetails_sender_bit), 0x01, "BandwidthDetails_sender boolean", HFILL }},
	{ &hf_h225_BandwidthDetails_multicast,
		{ "BandwidthDetails_multicast", "h225.BandwidthDetails_multicast", FT_BOOLEAN, 8,
		TFS(&tfs_BandwidthDetails_multicast_bit), 0x01, "BandwidthDetails_multicast boolean", HFILL }},
	{ &hf_h225_BandwidthDetails,
		{ "BandwidthDetails", "h225.BandwidthDetails", FT_NONE, BASE_NONE,
		NULL, 0, "BandwidthDetails sequence", HFILL }},
	{ &hf_h225_releaseCompleteCauseIE,
		{ "releaseCompleteCauseIE", "h225.releaseCompleteCauseIE", FT_BYTES, BASE_HEX,
		NULL, 0, "releaseCompleteCauseIE octet string", HFILL }},
	{ &hf_h225_CallTerminationCause,
		{ "CallTerminationCause", "h225.CallTerminationCause", FT_UINT32, BASE_DEC,
		VALS(CallTerminationCause_vals), 0, "CallTerminationCause choice", HFILL }},
	{ &hf_h225_CircuitInfo,
		{ "CircuitInfo", "h225.CircuitInfo", FT_NONE, BASE_NONE,
		NULL, 0, "CircuitInfo sequence", HFILL }},
	{ &hf_h225_genericData,
		{ "genericData", "h225.genericData", FT_NONE, BASE_NONE,
		NULL, 0, "genericData sequence of", HFILL }},
	{ &hf_h225_fastStart_item,
		{ "fastStart_item", "h225.fastStart_item", FT_BYTES, BASE_HEX,
		NULL, 0, "fastStart_item octet string", HFILL }},
	{ &hf_h225_fastStart,
		{ "fastStart", "h225.fastStart", FT_NONE, BASE_NONE,
		NULL, 0, "fastStart sequence of", HFILL }},
	{ &hf_h225_fastConnectRefused,
		{ "fastConnectRefused", "h225.fastConnectRefused", FT_BOOLEAN, 8,
		TFS(&tfs_fastConnectRefused_bit), 0x01, "fastConnectRefused boolean", HFILL }},
	{ &hf_h225_InformationUUIE,
		{ "InformationUUIE", "h225.InformationUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "InformationUUIE sequence", HFILL }},
	{ &hf_h225_routeCallToSCN,
		{ "routeCallToSCN", "h225.routeCallToSCN", FT_NONE, BASE_NONE,
		NULL, 0, "routeCallToSCN sequence of", HFILL }},
	{ &hf_h225_AdmissionRejectReason,
		{ "AdmissionRejectReason", "h225.AdmissionRejectReason", FT_UINT32, BASE_DEC,
		VALS(AdmissionRejectReason_vals), 0, "AdmissionRejectReason choice", HFILL }},
	{ &hf_h225_hMAC_iso10118_2_s,
		{ "hMAC_iso10118_2_s", "h225.hMAC_iso10118_2_s", FT_UINT32, BASE_DEC,
		VALS(EncryptIntAlg_vals), 0, "hMAC_iso10118_2_s choice", HFILL }},
	{ &hf_h225_hMAC_iso10118_2_l,
		{ "hMAC_iso10118_2_l", "h225.hMAC_iso10118_2_l", FT_UINT32, BASE_DEC,
		VALS(EncryptIntAlg_vals), 0, "hMAC_iso10118_2_l choice", HFILL }},
	{ &hf_h225_NonIsoIntegrityMechanism,
		{ "NonIsoIntegrityMechanism", "h225.NonIsoIntegrityMechanism", FT_UINT32, BASE_DEC,
		VALS(NonIsoIntegrityMechanism_vals), 0, "NonIsoIntegrityMechanism choice", HFILL }},
	{ &hf_h225_IntegrityMechanism,
		{ "IntegrityMechanism", "h225.IntegrityMechanism", FT_UINT32, BASE_DEC,
		VALS(IntegrityMechanism_vals), 0, "IntegrityMechanism choice", HFILL }},
	{ &hf_h225_LocationRejectReason,
		{ "LocationRejectReason", "h225.LocationRejectReason", FT_UINT32, BASE_DEC,
		VALS(LocationRejectReason_vals), 0, "LocationRejectReason choice", HFILL }},
	{ &hf_h225_mc,
		{ "mc", "h225.mc", FT_BOOLEAN, 8,
		TFS(&tfs_mc_bit), 0x01, "mc boolean", HFILL }},
	{ &hf_h225_undefinedNode,
		{ "undefinedNode", "h225.undefinedNode", FT_BOOLEAN, 8,
		TFS(&tfs_undefinedNode_bit), 0x01, "undefinedNode boolean", HFILL }},
	{ &hf_h225_destinationInfo,
		{ "destinationInfo", "h225.destinationInfo", FT_NONE, BASE_NONE,
		NULL, 0, "destinationInfo sequence", HFILL }},
	{ &hf_h225_EndPointType,
		{ "EndPointType", "h225.EndPointType", FT_NONE, BASE_NONE,
		NULL, 0, "EndPointType sequence", HFILL }},
	{ &hf_h225_terminalType,
		{ "terminalType", "h225.terminalType", FT_NONE, BASE_NONE,
		NULL, 0, "terminalType sequence", HFILL }},
	{ &hf_h225_sourceInfo,
		{ "sourceInfo", "h225.sourceInfo", FT_NONE, BASE_NONE,
		NULL, 0, "sourceInfo sequence", HFILL }},
	{ &hf_h225_multipleCalls,
		{ "multipleCalls", "h225.multipleCalls", FT_BOOLEAN, 8,
		TFS(&tfs_multipleCalls_bit), 0x01, "multipleCalls boolean", HFILL }},
	{ &hf_h225_maintainConnection,
		{ "maintainConnection", "h225.maintainConnection", FT_BOOLEAN, 8,
		TFS(&tfs_maintainConnection_bit), 0x01, "maintainConnection boolean", HFILL }},
	{ &hf_h225_CallProceedingUUIE,
		{ "CallProceedingUUIE", "h225.CallProceedingUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "CallProceedingUUIE sequence", HFILL }},
	{ &hf_h225_CapacityReportingSpecification_when,
		{ "CapacityReportingSpecification_when", "h225.CapacityReportingSpecification_when", FT_NONE, BASE_NONE,
		NULL, 0, "CapacityReportingSpecification_when sequence", HFILL }},
	{ &hf_h225_CapacityReportingSpecification,
		{ "CapacityReportingSpecification", "h225.CapacityReportingSpecification", FT_NONE, BASE_NONE,
		NULL, 0, "CapacityReportingSpecification sequence", HFILL }},
	{ &hf_h225_ProgressUUIE,
		{ "ProgressUUIE", "h225.ProgressUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "ProgressUUIE sequence", HFILL }},
	{ &hf_h225_EndPoint,
		{ "EndPoint", "h225.EndPoint", FT_NONE, BASE_NONE,
		NULL, 0, "EndPoint sequence", HFILL }},
	{ &hf_h225_destinationType,
		{ "destinationType", "h225.destinationType", FT_NONE, BASE_NONE,
		NULL, 0, "destinationType sequence", HFILL }},
	{ &hf_h225_destExtraCallInfo,
		{ "destExtraCallInfo", "h225.destExtraCallInfo", FT_NONE, BASE_NONE,
		NULL, 0, "destExtraCallInfo sequence of", HFILL }},
	{ &hf_h225_remoteExtensionAddress,
		{ "remoteExtensionAddress", "h225.remoteExtensionAddress", FT_NONE, BASE_NONE,
		NULL, 0, "remoteExtensionAddress sequence of", HFILL }},
	{ &hf_h225_rasAddress_sequence,
		{ "rasAddress_sequence", "h225.rasAddress_sequence", FT_NONE, BASE_NONE,
		NULL, 0, "rasAddress_sequence sequence of", HFILL }},
	{ &hf_h225_callSignalAddress,
		{ "callSignalAddress", "h225.callSignalAddress", FT_NONE, BASE_NONE,
		NULL, 0, "callSignalAddress sequence of", HFILL }},
	{ &hf_h225_ICV,
		{ "ICV", "h225.ICV", FT_NONE, BASE_NONE,
		NULL, 0, "ICV sequence", HFILL }},
	{ &hf_h225_BandwidthConfirm,
		{ "BandwidthConfirm", "h225.BandwidthConfirm", FT_NONE, BASE_NONE,
		NULL, 0, "BandwidthConfirm sequence", HFILL }},
	{ &hf_h225_UnregistrationConfirm,
		{ "UnregistrationConfirm", "h225.UnregistrationConfirm", FT_NONE, BASE_NONE,
		NULL, 0, "UnregistrationConfirm sequence", HFILL }},
	{ &hf_h225_NonStandardMessage,
		{ "NonStandardMessage", "h225.NonStandardMessage", FT_NONE, BASE_NONE,
		NULL, 0, "NonStandardMessage sequence", HFILL }},
	{ &hf_h225_InfoRequestAck,
		{ "InfoRequestAck", "h225.InfoRequestAck", FT_NONE, BASE_NONE,
		NULL, 0, "InfoRequestAck sequence", HFILL }},
	{ &hf_h225_InfoRequestNak,
		{ "InfoRequestNak", "h225.InfoRequestNak", FT_NONE, BASE_NONE,
		NULL, 0, "InfoRequestNak sequence", HFILL }},
	{ &hf_h225_ResourcesAvailableConfirm,
		{ "ResourcesAvailableConfirm", "h225.ResourcesAvailableConfirm", FT_NONE, BASE_NONE,
		NULL, 0, "ResourcesAvailableConfirm sequence", HFILL }},
	{ &hf_h225_GatekeeperRequest,
		{ "GatekeeperRequest", "h225.GatekeeperRequest", FT_NONE, BASE_NONE,
		NULL, 0, "GatekeeperRequest sequence", HFILL }},
	{ &hf_h225_integrity,
		{ "integrity", "h225.integrity", FT_NONE, BASE_NONE,
		NULL, 0, "integrity sequence of", HFILL }},
	{ &hf_h225_algorithmOIDs,
		{ "algorithmOIDs", "h225.algorithmOIDs", FT_NONE, BASE_NONE,
		NULL, 0, "algorithmOIDs sequence of", HFILL }},
	{ &hf_h225_alternateEndpoints,
		{ "alternateEndpoints", "h225.alternateEndpoints", FT_NONE, BASE_NONE,
		NULL, 0, "alternateEndpoints sequence of", HFILL }},
	{ &hf_h225_endpointAlias,
		{ "endpointAlias", "h225.endpointAlias", FT_NONE, BASE_NONE,
		NULL, 0, "endpointAlias sequence of", HFILL }},
	{ &hf_h225_ServiceControlResponse,
		{ "ServiceControlResponse", "h225.ServiceControlResponse", FT_NONE, BASE_NONE,
		NULL, 0, "ServiceControlResponse sequence", HFILL }},
	{ &hf_h225_DisengageReject,
		{ "DisengageReject", "h225.DisengageReject", FT_NONE, BASE_NONE,
		NULL, 0, "DisengageReject sequence", HFILL }},
	{ &hf_h225_BandwidthReject,
		{ "BandwidthReject", "h225.BandwidthReject", FT_NONE, BASE_NONE,
		NULL, 0, "BandwidthReject sequence", HFILL }},
	{ &hf_h225_UnregistrationReject,
		{ "UnregistrationReject", "h225.UnregistrationReject", FT_NONE, BASE_NONE,
		NULL, 0, "UnregistrationReject sequence", HFILL }},
	{ &hf_h225_UnregistrationRequest,
		{ "UnregistrationRequest", "h225.UnregistrationRequest", FT_NONE, BASE_NONE,
		NULL, 0, "UnregistrationRequest sequence", HFILL }},
	{ &hf_h225_endpointAliasPattern,
		{ "endpointAliasPattern", "h225.endpointAliasPattern", FT_NONE, BASE_NONE,
		NULL, 0, "endpointAliasPattern sequence of", HFILL }},
	{ &hf_h225_RegistrationReject,
		{ "RegistrationReject", "h225.RegistrationReject", FT_NONE, BASE_NONE,
		NULL, 0, "RegistrationReject sequence", HFILL }},
	{ &hf_h225_invalidTerminalAliases,
		{ "invalidTerminalAliases", "h225.invalidTerminalAliases", FT_NONE, BASE_NONE,
		NULL, 0, "invalidTerminalAliases sequence", HFILL }},
	{ &hf_h225_terminalAlias,
		{ "terminalAlias", "h225.terminalAlias", FT_NONE, BASE_NONE,
		NULL, 0, "terminalAlias sequence of", HFILL }},
	{ &hf_h225_terminalAliasPattern,
		{ "terminalAliasPattern", "h225.terminalAliasPattern", FT_NONE, BASE_NONE,
		NULL, 0, "terminalAliasPattern sequence of", HFILL }},
	{ &hf_h225_RegistrationRejectReason,
		{ "RegistrationRejectReason", "h225.RegistrationRejectReason", FT_UINT32, BASE_DEC,
		VALS(RegistrationRejectReason_vals), 0, "RegistrationRejectReason choice", HFILL }},
	{ &hf_h225_duplicateAlias,
		{ "duplicateAlias", "h225.duplicateAlias", FT_NONE, BASE_NONE,
		NULL, 0, "duplicateAlias sequence of", HFILL }},
	{ &hf_h225_GatekeeperReject,
		{ "GatekeeperReject", "h225.GatekeeperReject", FT_NONE, BASE_NONE,
		NULL, 0, "GatekeeperReject sequence", HFILL }},
	{ &hf_h225_almostOutOfResources,
		{ "almostOutOfResources", "h225.almostOutOfResources", FT_BOOLEAN, 8,
		TFS(&tfs_almostOutOfResources_bit), 0x01, "almostOutOfResources boolean", HFILL }},
	{ &hf_h225_ResourcesAvailableIndicate,
		{ "ResourcesAvailableIndicate", "h225.ResourcesAvailableIndicate", FT_NONE, BASE_NONE,
		NULL, 0, "ResourcesAvailableIndicate sequence", HFILL }},
	{ &hf_h225_protocols,
		{ "protocols", "h225.protocols", FT_NONE, BASE_NONE,
		NULL, 0, "protocols sequence of", HFILL }},
	{ &hf_h225_callDurationLimit,
		{ "callDurationLimit", "h225.callDurationLimit", FT_UINT32, BASE_DEC,
		NULL, 0, "callDurationLimit", HFILL }},
	{ &hf_h225_enforceCallDurationLimit,
		{ "enforceCallDurationLimit", "h225.enforceCallDurationLimit", FT_BOOLEAN, 8,
		TFS(&tfs_enforceCallDurationLimit_bit), 0x01, "enforceCallDurationLimit boolean", HFILL }},
	{ &hf_h225_CallCreditServiceControl,
		{ "CallCreditServiceControl", "h225.CallCreditServiceControl", FT_NONE, BASE_NONE,
		NULL, 0, "CallCreditServiceControl sequence", HFILL }},
	{ &hf_h225_ScreeningIndicator,
		{ "ScreeningIndicator", "h225.ScreeningIndicator", FT_UINT32, BASE_DEC,
		VALS(ScreeningIndicator_vals), 0, "ScreeningIndicator", HFILL }},
	{ &hf_h225_ExtendedAliasAddress,
		{ "ExtendedAliasAddress", "h225.ExtendedAliasAddress", FT_NONE, BASE_NONE,
		NULL, 0, "ExtendedAliasAddress sequence", HFILL }},
	{ &hf_h225_messageNotUnderstood,
		{ "messageNotUnderstood", "h225.messageNotUnderstood", FT_BYTES, BASE_HEX,
		NULL, 0, "messageNotUnderstood octet string", HFILL }},
	{ &hf_h225_UnknownMessageResponse,
		{ "UnknownMessageResponse", "h225.UnknownMessageResponse", FT_NONE, BASE_NONE,
		NULL, 0, "UnknownMessageResponse sequence", HFILL }},
	{ &hf_h225_CallReferenceValue,
		{ "CallReferenceValue", "h225.CallReferenceValue", FT_UINT32, BASE_DEC,
		NULL, 0, "CallReferenceValue", HFILL }},
	{ &hf_h225_AdmissionRequest,
		{ "AdmissionRequest", "h225.AdmissionRequest", FT_NONE, BASE_NONE,
		NULL, 0, "AdmissionRequest sequence", HFILL }},
	{ &hf_h225_canMapSrcAlias,
		{ "canMapSrcAlias", "h225.canMapSrcAlias", FT_BOOLEAN, 8,
		TFS(&tfs_canMapSrcAlias_bit), 0x01, "canMapSrcAlias boolean", HFILL }},
	{ &hf_h225_desiredProtocols,
		{ "desiredProtocols", "h225.desiredProtocols", FT_NONE, BASE_NONE,
		NULL, 0, "desiredProtocols sequence of", HFILL }},
	{ &hf_h225_willSupplyUUIEs,
		{ "willSupplyUUIEs", "h225.willSupplyUUIEs", FT_BOOLEAN, 8,
		TFS(&tfs_willSupplyUUIEs_bit), 0x01, "willSupplyUUIEs boolean", HFILL }},
	{ &hf_h225_destAlternatives,
		{ "destAlternatives", "h225.destAlternatives", FT_NONE, BASE_NONE,
		NULL, 0, "destAlternatives sequence of", HFILL }},
	{ &hf_h225_srcAlternatives,
		{ "srcAlternatives", "h225.srcAlternatives", FT_NONE, BASE_NONE,
		NULL, 0, "srcAlternatives sequence of", HFILL }},
	{ &hf_h225_canMapAlias,
		{ "canMapAlias", "h225.canMapAlias", FT_BOOLEAN, 8,
		TFS(&tfs_canMapAlias_bit), 0x01, "canMapAlias boolean", HFILL }},
	{ &hf_h225_activeMC,
		{ "activeMC", "h225.activeMC", FT_BOOLEAN, 8,
		TFS(&tfs_activeMC_bit), 0x01, "activeMC boolean", HFILL }},
	{ &hf_h225_srcInfo,
		{ "srcInfo", "h225.srcInfo", FT_NONE, BASE_NONE,
		NULL, 0, "srcInfo sequence of", HFILL }},
	{ &hf_h225_DestinationInfo,
		{ "DestinationInfo", "h225.DestinationInfo", FT_NONE, BASE_NONE,
		NULL, 0, "DestinationInfo sequence of", HFILL }},
	{ &hf_h225_InfoRequest,
		{ "InfoRequest", "h225.InfoRequest", FT_NONE, BASE_NONE,
		NULL, 0, "InfoRequest sequence", HFILL }},
	{ &hf_h225_nextSegmentRequested,
		{ "nextSegmentRequested", "h225.nextSegmentRequested", FT_UINT32, BASE_DEC,
		NULL, 0, "nextSegmentRequested", HFILL }},
	{ &hf_h225_delay,
		{ "delay", "h225.delay", FT_UINT32, BASE_DEC,
		NULL, 0, "delay", HFILL }},
	{ &hf_h225_RequestInProgress,
		{ "RequestInProgress", "h225.RequestInProgress", FT_NONE, BASE_NONE,
		NULL, 0, "RequestInProgress sequence", HFILL }},
	{ &hf_h225_H248SignalsDescriptor,
		{ "H248SignalsDescriptor", "h225.H248SignalsDescriptor", FT_BYTES, BASE_HEX,
		NULL, 0, "H248SignalsDescriptor octet string", HFILL }},
	{ &hf_h225_url,
		{ "url", "h225.url", FT_BYTES, BASE_HEX,
		NULL, 0, "url IA5String", HFILL }},
	{ &hf_h225_ServiceControlDescriptor,
		{ "ServiceControlDescriptor", "h225.ServiceControlDescriptor", FT_UINT32, BASE_DEC,
		VALS(ServiceControlDescriptor_vals), 0, "ServiceControlDescriptor choice", HFILL }},
	{ &hf_h225_ServiceControlSession,
		{ "ServiceControlSession", "h225.ServiceControlSession", FT_NONE, BASE_NONE,
		NULL, 0, "ServiceControlSession sequence", HFILL }},
	{ &hf_h225_sessionId,
		{ "sessionId", "h225.sessionId", FT_UINT32, BASE_DEC,
		NULL, 0, "sessionId", HFILL }},
	{ &hf_h225_AlertingUUIE,
		{ "AlertingUUIE", "h225.AlertingUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "AlertingUUIE sequence", HFILL }},
	{ &hf_h225_serviceControl,
		{ "serviceControl", "h225.serviceControl", FT_NONE, BASE_NONE,
		NULL, 0, "serviceControl sequence of", HFILL }},
	{ &hf_h225_alertingAddress,
		{ "alertingAddress", "h225.alertingAddress", FT_NONE, BASE_NONE,
		NULL, 0, "alertingAddress sequence of", HFILL }},
	{ &hf_h225_ReleaseCompleteUUIE,
		{ "ReleaseCompleteUUIE", "h225.ReleaseCompleteUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "ReleaseCompleteUUIE sequence", HFILL }},
	{ &hf_h225_busyAddress,
		{ "busyAddress", "h225.busyAddress", FT_NONE, BASE_NONE,
		NULL, 0, "busyAddress sequence of", HFILL }},
	{ &hf_h225_FacilityUUIE,
		{ "FacilityUUIE", "h225.FacilityUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "FacilityUUIE sequence", HFILL }},
	{ &hf_h225_alternativeAliasAddress,
		{ "alternativeAliasAddress", "h225.alternativeAliasAddress", FT_NONE, BASE_NONE,
		NULL, 0, "alternativeAliasAddress sequence of", HFILL }},
	{ &hf_h225_AdmissionReject,
		{ "AdmissionReject", "h225.AdmissionReject", FT_NONE, BASE_NONE,
		NULL, 0, "AdmissionReject sequence", HFILL }},
	{ &hf_h225_hopCount,
		{ "hopCount", "h225.hopCount", FT_UINT32, BASE_DEC,
		NULL, 0, "hopCount", HFILL }},
	{ &hf_h225_parallelH245Control_item,
		{ "parallelH245Control_item", "h225.parallelH245Control_item", FT_BYTES, BASE_HEX,
		NULL, 0, "parallelH245Control_item octet string", HFILL }},
	{ &hf_h225_parallelH245Control,
		{ "parallelH245Control", "h225.parallelH245Control", FT_NONE, BASE_NONE,
		NULL, 0, "parallelH245Control sequence of", HFILL }},
	{ &hf_h225_language,
		{ "language", "h225.language", FT_BYTES, BASE_HEX,
		NULL, 0, "language IA5String", HFILL }},
	{ &hf_h225_languages,
		{ "languages", "h225.languages", FT_NONE, BASE_NONE,
		NULL, 0, "languages sequence of", HFILL }},
	{ &hf_h225_mediaWaitForConnect,
		{ "mediaWaitForConnect", "h225.mediaWaitForConnect", FT_BOOLEAN, 8,
		TFS(&tfs_mediaWaitForConnect_bit), 0x01, "mediaWaitForConnect boolean", HFILL }},
	{ &hf_h225_canOverlapSend,
		{ "canOverlapSend", "h225.canOverlapSend", FT_BOOLEAN, 8,
		TFS(&tfs_canOverlapSend_bit), 0x01, "canOverlapSend boolean", HFILL }},
	{ &hf_h225_SetupUUIE,
		{ "SetupUUIE", "h225.SetupUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "SetupUUIE sequence", HFILL }},
	{ &hf_h225_sourceAddress,
		{ "sourceAddress", "h225.sourceAddress", FT_NONE, BASE_NONE,
		NULL, 0, "sourceAddress sequence of", HFILL }},
	{ &hf_h225_destinationAddress,
		{ "destinationAddress", "h225.destinationAddress", FT_NONE, BASE_NONE,
		NULL, 0, "destinationAddress sequence of", HFILL }},
	{ &hf_h225_destExtraCRV,
		{ "destExtraCRV", "h225.destExtraCRV", FT_NONE, BASE_NONE,
		NULL, 0, "destExtraCRV sequence of", HFILL }},
	{ &hf_h225_h245SecurityCapability,
		{ "h245SecurityCapability", "h225.h245SecurityCapability", FT_NONE, BASE_NONE,
		NULL, 0, "h245SecurityCapability sequence of", HFILL }},
	{ &hf_h225_additionalSourceAddresses,
		{ "additionalSourceAddresses", "h225.additionalSourceAddresses", FT_NONE, BASE_NONE,
		NULL, 0, "additionalSourceAddresses sequence of", HFILL }},
	{ &hf_h225_ConnectUUIE,
		{ "ConnectUUIE", "h225.ConnectUUIE", FT_NONE, BASE_NONE,
		NULL, 0, "ConnectUUIE sequence", HFILL }},
	{ &hf_h225_connectedAddress,
		{ "connectedAddress", "h225.connectedAddress", FT_NONE, BASE_NONE,
		NULL, 0, "connectedAddress sequence of", HFILL }},
	{ &hf_h225_h323_message_body,
		{ "h323_message_body", "h225.h323_message_body", FT_UINT32, BASE_DEC,
		VALS(h323_message_body_vals), 0, "h323_message_body choice", HFILL }},
	{ &hf_h225_LocationConfirm,
		{ "LocationConfirm", "h225.LocationConfirm", FT_NONE, BASE_NONE,
		NULL, 0, "LocationConfirm sequence", HFILL }},
	{ &hf_h225_supportedProtocols,
		{ "supportedProtocols", "h225.supportedProtocols", FT_NONE, BASE_NONE,
		NULL, 0, "supportedProtocols sequence of", HFILL }},
	{ &hf_h225_modifiedSrcInfo,
		{ "modifiedSrcInfo", "h225.modifiedSrcInfo", FT_NONE, BASE_NONE,
		NULL, 0, "modifiedSrcInfo sequence of", HFILL }},
	{ &hf_h225_LocationReject,
		{ "LocationReject", "h225.LocationReject", FT_NONE, BASE_NONE,
		NULL, 0, "LocationReject sequence", HFILL }},
	{ &hf_h225_callSpecific,
		{ "callSpecific", "h225.callSpecific", FT_NONE, BASE_NONE,
		NULL, 0, "callSpecific sequence", HFILL }},
	{ &hf_h225_answeredCall,
		{ "answeredCall", "h225.answeredCall", FT_BOOLEAN, 8,
		TFS(&tfs_answeredCall_bit), 0x01, "answeredCall boolean", HFILL }},
	{ &hf_h225_ServiceControlIndication,
		{ "ServiceControlIndication", "h225.ServiceControlIndication", FT_NONE, BASE_NONE,
		NULL, 0, "ServiceControlIndication sequence", HFILL }},
	{ &hf_h225_RasUsageInformation,
		{ "RasUsageInformation", "h225.RasUsageInformation", FT_NONE, BASE_NONE,
		NULL, 0, "RasUsageInformation sequence", HFILL }},
	{ &hf_h225_nonStandardUsageFields,
		{ "nonStandardUsageFields", "h225.nonStandardUsageFields", FT_NONE, BASE_NONE,
		NULL, 0, "nonStandardUsageFields sequence of", HFILL }},
	{ &hf_h225_TimeToLive,
		{ "TimeToLive", "h225.TimeToLive", FT_UINT32, BASE_DEC,
		NULL, 0, "TimeToLive in seconds", HFILL }},
	{ &hf_h225_GatekeeperConfirm,
		{ "GatekeeperConfirm", "h225.GatekeeperConfirm", FT_NONE, BASE_NONE,
		NULL, 0, "GatekeeperConfirm sequence", HFILL }},
	{ &hf_h225_RegistrationRequest,
		{ "RegistrationRequest", "h225.RegistrationRequest", FT_NONE, BASE_NONE,
		NULL, 0, "RegistrationRequest sequence", HFILL }},
	{ &hf_h225_discoveryComplete,
		{ "discoveryComplete", "h225.discoveryComplete", FT_BOOLEAN, 8,
		TFS(&tfs_discoveryComplete_bit), 0x01, "discoveryComplete boolean", HFILL }},
	{ &hf_h225_keepAlive,
		{ "keepAlive", "h225.keepAlive", FT_BOOLEAN, 8,
		TFS(&tfs_keepAlive_bit), 0x01, "keepAlive boolean", HFILL }},
	{ &hf_h225_H248PackagesDescriptor,
		{ "H248PackagesDescriptor", "h225.H248PackagesDescriptor", FT_BYTES, BASE_HEX,
		NULL, 0, "H248PackagesDescriptor octet string", HFILL }},
	{ &hf_h225_supportedH248Packages,
		{ "supportedH248Packages", "h225.supportedH248Packages", FT_NONE, BASE_NONE,
		NULL, 0, "supportedH248Packages sequence of", HFILL }},
	{ &hf_h225_DisengageConfirm,
		{ "DisengageConfirm", "h225.DisengageConfirm", FT_NONE, BASE_NONE,
		NULL, 0, "DisengageConfirm sequence", HFILL }},
	{ &hf_h225_AdmissionConfirm,
		{ "AdmissionConfirm", "h225.AdmissionConfirm", FT_NONE, BASE_NONE,
		NULL, 0, "AdmissionConfirm sequence", HFILL }},
	{ &hf_h225_irrFrequency,
		{ "irrFrequency", "h225.irrFrequency", FT_UINT32, BASE_DEC,
		NULL, 0, "irrFrequency", HFILL }},
	{ &hf_h225_willRespondToIRR,
		{ "willRespondToIRR", "h225.willRespondToIRR", FT_BOOLEAN, 8,
		TFS(&tfs_willRespondToIRR_bit), 0x01, "willRespondToIRR boolean", HFILL }},
	{ &hf_h225_usageSpec,
		{ "usageSpec", "h225.usageSpec", FT_NONE, BASE_NONE,
		NULL, 0, "usageSpec sequence of", HFILL }},
	{ &hf_h225_DisengageRequest,
		{ "DisengageRequest", "h225.DisengageRequest", FT_NONE, BASE_NONE,
		NULL, 0, "DisengageRequest sequence", HFILL }},
	{ &hf_h225_LocationRequest,
		{ "LocationRequest", "h225.LocationRequest", FT_NONE, BASE_NONE,
		NULL, 0, "LocationRequest sequence", HFILL }},
	{ &hf_h225_SourceInfo,
		{ "SourceInfo", "h225.SourceInfo", FT_NONE, BASE_NONE,
		NULL, 0, "SourceInfo sequence of", HFILL }},
	{ &hf_h225_hopCount255,
		{ "hopCount255", "h225.hopCount255", FT_UINT32, BASE_DEC,
		NULL, 0, "hopCount255", HFILL }},
	{ &hf_h225_sourceEndpointInfo,
		{ "sourceEndpointInfo", "h225.sourceEndpointInfo", FT_NONE, BASE_NONE,
		NULL, 0, "sourceEndpointInfo sequence of", HFILL }},
	{ &hf_h225_BandwidthRequest,
		{ "BandwidthRequest", "h225.BandwidthRequest", FT_NONE, BASE_NONE,
		NULL, 0, "BandwidthRequest sequence", HFILL }},
	{ &hf_h225_bandwidthDetails,
		{ "bandwidthDetails", "h225.bandwidthDetails", FT_NONE, BASE_NONE,
		NULL, 0, "bandwidthDetails sequence of", HFILL }},
	{ &hf_h225_admissionConfirmSequence,
		{ "admissionConfirmSequence", "h225.admissionConfirmSequence", FT_NONE, BASE_NONE,
		NULL, 0, "admissionConfirmSequence sequence of", HFILL }},
	{ &hf_h225_tunnelledSignallingMessage,
		{ "tunnelledSignallingMessage", "h225.tunnelledSignallingMessage", FT_NONE, BASE_NONE,
		NULL, 0, "tunnelledSignallingMessage sequence", HFILL }},
	{ &hf_h225_messageContent_item,
		{ "messageContent_item", "h225.messageContent_item", FT_BYTES, BASE_HEX,
		NULL, 0, "messageContent_item octet string", HFILL }},
	{ &hf_h225_messageContent,
		{ "messageContent", "h225.messageContent", FT_NONE, BASE_NONE,
		NULL, 0, "messageContent sequence of", HFILL }},
	{ &hf_h225_H323_UU_PDU,
		{ "H323_UU_PDU", "h225.H323_UU_PDU", FT_NONE, BASE_NONE,
		NULL, 0, "H323_UU_PDU sequence", HFILL }},
	{ &hf_h225_h4501SupplementaryService_item,
		{ "h4501SupplementaryService_item", "h225.h4501SupplementaryService_item", FT_BYTES, BASE_HEX,
		NULL, 0, "h4501SupplementaryService_item octet string", HFILL }},
	{ &hf_h225_h4501SupplementaryService,
		{ "h4501SupplementaryService", "h225.h4501SupplementaryService", FT_NONE, BASE_NONE,
		NULL, 0, "h4501SupplementaryService sequence of", HFILL }},
	{ &hf_h225_h245Tunneling,
		{ "h245Tunneling", "h225.h245Tunneling", FT_BOOLEAN, 8,
		TFS(&tfs_h245Tunneling_bit), 0x01, "h245Tunneling boolean", HFILL }},
	{ &hf_h225_h245Control_item,
		{ "h245Control_item", "h225.h245Control_item", FT_BYTES, BASE_HEX,
		NULL, 0, "h245Control_item octet string", HFILL }},
	{ &hf_h225_h245Control,
		{ "h245Control", "h225.h245Control", FT_NONE, BASE_NONE,
		NULL, 0, "h245Control sequence of", HFILL }},
	{ &hf_h225_nonStandardControl,
		{ "nonStandardControl", "h225.nonStandardControl", FT_NONE, BASE_NONE,
		NULL, 0, "nonStandardControl sequence of", HFILL }},
	{ &hf_h225_preGrantedARQ,
		{ "preGrantedARQ", "h225.preGrantedARQ", FT_NONE, BASE_NONE,
		NULL, 0, "preGrantedARQ sequence", HFILL }},
	{ &hf_h225_makeCall,
		{ "makeCall", "h225.makeCall", FT_BOOLEAN, 8,
		TFS(&tfs_makeCall_bit), 0x01, "makeCall boolean", HFILL }},
	{ &hf_h225_useGKCallSignalAddressToMakeCall,
		{ "useGKCallSignalAddressToMakeCall", "h225.useGKCallSignalAddressToMakeCall", FT_BOOLEAN, 8,
		TFS(&tfs_useGKCallSignalAddressToMakeCall_bit), 0x01, "useGKCallSignalAddressToMakeCall boolean", HFILL }},
	{ &hf_h225_answerCall,
		{ "answerCall", "h225.answerCall", FT_BOOLEAN, 8,
		TFS(&tfs_answerCall_bit), 0x01, "answerCall boolean", HFILL }},
	{ &hf_h225_useGKCallSignalAddressToAnswer,
		{ "useGKCallSignalAddressToAnswer", "h225.useGKCallSignalAddressToAnswer", FT_BOOLEAN, 8,
		TFS(&tfs_useGKCallSignalAddressToAnswer_bit), 0x01, "useGKCallSignalAddressToAnswer boolean", HFILL }},
	{ &hf_h225_RegistrationConfirm,
		{ "RegistrationConfirm", "h225.RegistrationConfirm", FT_NONE, BASE_NONE,
		NULL, 0, "RegistrationConfirm sequence", HFILL }},
	{ &hf_h225_pdu_item,
		{ "pdu_item", "h225.pdu_item", FT_NONE, BASE_NONE,
		NULL, 0, "pdu_item sequence", HFILL }},
	{ &hf_h225_sent,
		{ "sent", "h225.sent", FT_BOOLEAN, 8,
		TFS(&tfs_sent_bit), 0x01, "sent boolean", HFILL }},
	{ &hf_h225_pdu,
		{ "pdu", "h225.pdu", FT_NONE, BASE_NONE,
		NULL, 0, "pdu sequence of", HFILL }},
	{ &hf_h225_perCallInfo_item,
		{ "perCallInfo_item", "h225.perCallInfo_item", FT_NONE, BASE_NONE,
		NULL, 0, "perCallInfo_item sequence", HFILL }},
	{ &hf_h225_originator,
		{ "originator", "h225.originator", FT_BOOLEAN, 8,
		TFS(&tfs_originator_bit), 0x01, "originator boolean", HFILL }},
	{ &hf_h225_audio,
		{ "audio", "h225.audio", FT_NONE, BASE_NONE,
		NULL, 0, "audio sequence of", HFILL }},
	{ &hf_h225_video,
		{ "video", "h225.video", FT_NONE, BASE_NONE,
		NULL, 0, "video sequence of", HFILL }},
	{ &hf_h225_data,
		{ "data", "h225.data", FT_NONE, BASE_NONE,
		NULL, 0, "data sequence of", HFILL }},
	{ &hf_h225_substituteConfIDs,
		{ "substituteConfIDs", "h225.substituteConfIDs", FT_NONE, BASE_NONE,
		NULL, 0, "substituteConfIDs sequence of", HFILL }},
	{ &hf_h225_perCallInfo,
		{ "perCallInfo", "h225.perCallInfo", FT_NONE, BASE_NONE,
		NULL, 0, "perCallInfo sequence of", HFILL }},
	{ &hf_h225_InfoRequestResponse,
		{ "InfoRequestResponse", "h225.InfoRequestResponse", FT_NONE, BASE_NONE,
		NULL, 0, "InfoRequestResponse sequence", HFILL }},
	{ &hf_h225_needResponse,
		{ "needResponse", "h225.needResponse", FT_BOOLEAN, 8,
		TFS(&tfs_needResponse_bit), 0x01, "needResponse boolean", HFILL }},
	{ &hf_h225_unsolicited,
		{ "unsolicited", "h225.unsolicited", FT_BOOLEAN, 8,
		TFS(&tfs_unsolicited_bit), 0x01, "unsolicited boolean", HFILL }},
	{ &hf_h225_RasMessage,
		{ "RasMessage", "h225.RasMessage", FT_UINT32, BASE_DEC,
		VALS(RasMessage_vals), 0, "RasMessage choice", HFILL }},
	{ &hf_h225_H323_UserInformation,
		{ "H323_UserInformation", "h225.H323_UserInformation", FT_NONE, BASE_NONE,
		NULL, 0, "H323_UserInformation sequence", HFILL }},
	{ &hf_h225_user_data,
		{ "user_data", "h225.user_data", FT_NONE, BASE_NONE,
		NULL, 0, "user_data sequence", HFILL }},
	{ &hf_h225_protocol_discriminator,
		{ "protocol_discriminator", "h225.protocol_discriminator", FT_UINT32, BASE_DEC,
		NULL, 0, "protocol_discriminator", HFILL }},
	{ &hf_h225_user_information,
		{ "user_information", "h225.user_information", FT_BYTES, BASE_HEX,
		NULL, 0, "user_information octet string", HFILL }},
/*ddd*/
	};

	static gint *ett[] =
	{
		&ett_h225,
		&ett_h225_SecurityServiceMode_encryption,
		&ett_h225_SecurityServiceMode_authentication,
		&ett_h225_SecurityServiceMode_integrity,
		&ett_h225_H245Security,
		&ett_h225_ReleaseCompleteReason,
		&ett_h225_routing,
		&ett_h225_TransportAddress,
		&ett_h225_InfoRequestResponseStatus,
		&ett_h225_systemid,
		&ett_h225_MobileUIM,
		&ett_h225_PartyNumber,
		&ett_h225_AliasAddress,
		&ett_h225_AddressPattern,
		&ett_h225_SupportedProtocols,
		&ett_h225_GenericIdentifier,
		&ett_h225_Content,
		&ett_h225_CallTerminationCause,
		&ett_h225_AdmissionRejectReason,
		&ett_h225_EncryptIntAlg,
		&ett_h225_NonIsoIntegrityMechanism,
		&ett_h225_IntegrityMechanism,
		&ett_h225_LocationRejectReason,
		&ett_h225_RegistrationRejectReason,
		&ett_h225_ServiceControlDescriptor,
		&ett_h225_h323_message_body,
		&ett_h225_RasMessage,
		&ett_h225_GatekeeperRejectReason,
		&ett_h225_PresentationIndicator,
		&ett_h225_conferenceGoal,
		&ett_h225_ScnConnectionType,
		&ett_h225_ScnConnectionAggregation,
		&ett_h225_FacilityReason,
		&ett_h225_PublicTypeOfNumber,
		&ett_h225_PrivateTypeOfNumber,
		&ett_h225_UseSpecifiedTransport,
		&ett_h225_SecurityErrors,
		&ett_h225_SecurityErrors2,
		&ett_h225_ServiceControlSession_reason,
		&ett_h225_billingMode,
		&ett_h225_CCSCcallStartingPoint,
		&ett_h225_UnregRequestReason,
		&ett_h225_UnregRejectReason,
		&ett_h225_CallType,
		&ett_h225_CallModel,
		&ett_h225_TransportQOS,
		&ett_h225_BandRejectReason,
		&ett_h225_DisengageReason,
		&ett_h225_DisengageRejectReason,
		&ett_h225_InfoRequestNakReason,
		&ett_h225_SCRresult,
		&ett_h225_GatekeeperInfo,
		&ett_h225_SecurityCapabilities_tls,
		&ett_h225_SecurityCapabilities_ipsec,
		&ett_h225_RasUsageInfoTypes,
		&ett_h225_nonStandardUsageTypes,
		&ett_h225_DataRate,
		&ett_h225_dataRatesSupported,
		&ett_h225_TerminalInfo,
		&ett_h225_StimulusControl,
		&ett_h225_connectionParameters,
		&ett_h225_RasUsageSpecification_when,
		&ett_h225_RasUsageSpecification_callStartingPoint,
		&ett_h225_RasUsageSpecification,
		&ett_h225_ipAddress,
		&ett_h225_route,
		&ett_h225_ipSourceRoute,
		&ett_h225_ipxAddress,
		&ett_h225_ip6Address,
		&ett_h225_TransportChannelInfo,
		&ett_h225_CarrierInfo,
		&ett_h225_CallIdentifier,
		&ett_h225_CallLinkage,
		&ett_h225_tokens,
		&ett_h225_AlternateGK,
		&ett_h225_alternateGatekeeper,
		&ett_h225_AltGKInfo,
		&ett_h225_annexE,
		&ett_h225_sctp,
		&ett_h225_AlternateTransportAddress,
		&ett_h225_UUIEsRequested,
		&ett_h225_Q954Details,
		&ett_h225_QseriesOptions,
		&ett_h225_associatedSessionIds,
		&ett_h225_RTPSession,
		&ett_h225_cryptoTokens,
		&ett_h225_StatusUUIE,
		&ett_h225_StatusInquiryUUIE,
		&ett_h225_SetupAcknowledgeUUIE,
		&ett_h225_NotifyUUIE,
		&ett_h225_GSMUIM,
		&ett_h225_ANSI41UIM,
		&ett_h225_e164Number,
		&ett_h225_privateNumber,
		&ett_h225_TunnelledProtocolAlternateIdentifier,
		&ett_h225_SupportedPrefix,
		&ett_h225_SupportedPrefixes,
		&ett_h225_H310Caps,
		&ett_h225_H320Caps,
		&ett_h225_H321Caps,
		&ett_h225_H322Caps,
		&ett_h225_H323Caps,
		&ett_h225_H324Caps,
		&ett_h225_VoiceCaps,
		&ett_h225_T120OnlyCaps,
		&ett_h225_NonStandardProtocol,
		&ett_h225_SIPCaps,
		&ett_h225_AddressPattern_range,
		&ett_h225_ConferenceList,
		&ett_h225_conferences,
		&ett_h225_T38FaxAnnexbOnlyCaps,
		&ett_h225_protocol,
		&ett_h225_GatewayInfo,
		&ett_h225_McuInfo,
		&ett_h225_TunnelledProtocol_id,
		&ett_h225_TunnelledProtocol,
		&ett_h225_CicInfo_cic,
		&ett_h225_CicInfo,
		&ett_h225_GroupID_member,
		&ett_h225_GroupID,
		&ett_h225_CircuitIdentifier,
		&ett_h225_EnumeratedParameter,
		&ett_h225_parameters,
		&ett_h225_GenericData,
		&ett_h225_Content_compound,
		&ett_h225_Content_nested,
		&ett_h225_neededFeatures,
		&ett_h225_desiredFeatures,
		&ett_h225_supportedFeatures,
		&ett_h225_FeatureSet,
		&ett_h225_CallsAvailable,
		&ett_h225_voiceGwCallsAvailable,
		&ett_h225_h310GwCallsAvailable,
		&ett_h225_h320GwCallsAvailable,
		&ett_h225_h321GwCallsAvailable,
		&ett_h225_h322GwCallsAvailable,
		&ett_h225_h323GwCallsAvailable,
		&ett_h225_h324GwCallsAvailable,
		&ett_h225_t120OnlyGwCallsAvailable,
		&ett_h225_t38FaxAnnexbOnlyGwCallsAvailable,
		&ett_h225_terminalCallsAvailable,
		&ett_h225_mcuCallsAvailable,
		&ett_h225_sipGwCallsAvailable,
		&ett_h225_CallCapacityInfo,
		&ett_h225_CallCapacity,
		&ett_h225_VendorIdentifier,
		&ett_h225_CapacityReportingCapability,
		&ett_h225_CallCreditCapability,
		&ett_h225_BandwidthDetails,
		&ett_h225_CircuitInfo,
		&ett_h225_genericData,
		&ett_h225_fastStart,
		&ett_h225_InformationUUIE,
		&ett_h225_routeCallToSCN,
		&ett_h225_EndPointType,
		&ett_h225_CallProceedingUUIE,
		&ett_h225_CapacityReportingSpecification_when,
		&ett_h225_CapacityReportingSpecification,
		&ett_h225_ProgressUUIE,
		&ett_h225_EndPoint,
		&ett_h225_destExtraCallInfo,
		&ett_h225_remoteExtensionAddress,
		&ett_h225_rasAddress_sequence,
		&ett_h225_callSignalAddress,
		&ett_h225_ICV,
		&ett_h225_BandwidthConfirm,
		&ett_h225_UnregistrationConfirm,
		&ett_h225_NonStandardMessage,
		&ett_h225_InfoRequestAck,
		&ett_h225_InfoRequestNak,
		&ett_h225_ResourcesAvailableConfirm,
		&ett_h225_GatekeeperRequest,
		&ett_h225_integrity,
		&ett_h225_algorithmOIDs,
		&ett_h225_alternateEndpoints,
		&ett_h225_endpointAlias,
		&ett_h225_ServiceControlResponse,
		&ett_h225_DisengageReject,
		&ett_h225_BandwidthReject,
		&ett_h225_UnregistrationReject,
		&ett_h225_UnregistrationRequest,
		&ett_h225_endpointAliasPattern,
		&ett_h225_RegistrationReject,
		&ett_h225_invalidTerminalAliases,
		&ett_h225_terminalAlias,
		&ett_h225_terminalAliasPattern,
		&ett_h225_duplicateAlias,
		&ett_h225_GatekeeperReject,
		&ett_h225_ResourcesAvailableIndicate,
		&ett_h225_protocols,
		&ett_h225_CallCreditServiceControl,
		&ett_h225_ExtendedAliasAddress,
		&ett_h225_UnknownMessageResponse,
		&ett_h225_AdmissionRequest,
		&ett_h225_desiredProtocols,
		&ett_h225_destAlternatives,
		&ett_h225_srcAlternatives,
		&ett_h225_srcInfo,
		&ett_h225_DestinationInfo,
		&ett_h225_InfoRequest,
		&ett_h225_RequestInProgress,
		&ett_h225_ServiceControlSession,
		&ett_h225_AlertingUUIE,
		&ett_h225_serviceControl,
		&ett_h225_alertingAddress,
		&ett_h225_ReleaseCompleteUUIE,
		&ett_h225_busyAddress,
		&ett_h225_FacilityUUIE,
		&ett_h225_alternativeAliasAddress,
		&ett_h225_AdmissionReject,
		&ett_h225_parallelH245Control,
		&ett_h225_languages,
		&ett_h225_SetupUUIE,
		&ett_h225_sourceAddress,
		&ett_h225_destinationAddress,
		&ett_h225_destExtraCRV,
		&ett_h225_h245SecurityCapability,
		&ett_h225_additionalSourceAddresses,
		&ett_h225_ConnectUUIE,
		&ett_h225_connectedAddress,
		&ett_h225_LocationConfirm,
		&ett_h225_supportedProtocols,
		&ett_h225_modifiedSrcInfo,
		&ett_h225_LocationReject,
		&ett_h225_callSpecific,
		&ett_h225_ServiceControlIndication,
		&ett_h225_RasUsageInformation,
		&ett_h225_nonStandardUsageFields,
		&ett_h225_GatekeeperConfirm,
		&ett_h225_RegistrationRequest,
		&ett_h225_supportedH248Packages,
		&ett_h225_DisengageConfirm,
		&ett_h225_AdmissionConfirm,
		&ett_h225_usageSpec,
		&ett_h225_DisengageRequest,
		&ett_h225_LocationRequest,
		&ett_h225_SourceInfo,
		&ett_h225_sourceEndpointInfo,
		&ett_h225_BandwidthRequest,
		&ett_h225_bandwidthDetails,
		&ett_h225_admissionConfirmSequence,
		&ett_h225_tunnelledSignallingMessage,
		&ett_h225_messageContent,
		&ett_h225_H323_UU_PDU,
		&ett_h225_h4501SupplementaryService,
		&ett_h225_h245Control,
		&ett_h225_nonStandardControl,
		&ett_h225_preGrantedARQ,
		&ett_h225_RegistrationConfirm,
		&ett_h225_pdu_item,
		&ett_h225_pdu,
		&ett_h225_perCallInfo_item,
		&ett_h225_audio,
		&ett_h225_video,
		&ett_h225_data,
		&ett_h225_substituteConfIDs,
		&ett_h225_perCallInfo,
		&ett_h225_InfoRequestResponse,
		&ett_h225_H323_UserInformation,
		&ett_h225_user_data,
/*eee*/
	};
	module_t *h225_module;

	proto_h225 = proto_register_protocol("H225", "H225", "h225");
	proto_register_field_array(proto_h225, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	h225_module = prefs_register_protocol(proto_h225, NULL);
	prefs_register_bool_preference(h225_module, "reassembly",
		"Reassemble H.225 over TCP",
		"Whether the dissector should reassemble H.225 PDUs spanning multiple TCP segments",
		&h225_reassembly);
	register_dissector("h225", dissect_h225_H323UserInformation, proto_h225);
}

void
proto_reg_handoff_h225(void)
{
	h225ras_handle=create_dissector_handle(dissect_h225_RasMessage, proto_h225);
	H323UserInformation_handle=create_dissector_handle(dissect_h225_H323UserInformation, proto_h225);


	dissector_add("udp.port", UDP_PORT_RAS1, h225ras_handle);
	dissector_add("udp.port", UDP_PORT_RAS2, h225ras_handle);
}
