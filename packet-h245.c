/* packet-h245.c
 * Routines for H.245 packet dissection
 * 2003  Ronnie Sahlberg
 *       with great support with testing and providing capturefiles
 *       from Martin Regner
 *
 *
 * Maintained by Andreas Sikkema (andreas.sikkema@philips.com)
 *
 * $Id: packet-h245.c,v 1.43 2004/01/09 00:56:03 guy Exp $
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "prefs.h"
#include "packet-tpkt.h"
#include "packet-per.h"
#include "t35.h"

static dissector_handle_t rtp_handle=NULL;
static dissector_handle_t rtcp_handle=NULL;

static dissector_handle_t h245_handle;
static dissector_handle_t MultimediaSystemControlMessage_handle;

static int proto_h245 = -1;		/* h245 over tpkt */
static int hf_h245_rfc_number = -1;
static int hf_h245_pdu_type = -1;
static int hf_h245_DialingInformationNumber_networkAddress = -1;
static int hf_h245_signalType = -1;
static int hf_h245_e164Address = -1;
static int hf_h245_subAddress = -1;
static int hf_h245_domainBased = -1;
static int hf_h245_internationalNumber = -1;
static int hf_h245_IndicationMessage_type = -1;
static int hf_h245_RequestMessage_type = -1;
static int hf_h245_ResponseMessage_type = -1;
static int hf_h245_CommandMessage_type = -1;
static int hf_h245_PixelAspectCode = -1;
static int hf_h245_LogicalChannelNumber = -1;
static int hf_h245_SequenceNumber = -1;
static int hf_h245_EndSessionCommand_type = -1;
static int hf_h245_MobileMultilinkReconfigurationIndication = -1;
static int hf_h245_FlowControlIndication = -1;
static int hf_h245_UserInputIndication_extendedAlphanumeric = -1;
static int hf_h245_UserInputIndication_signalUpdate_rtp = -1;
static int hf_h245_UserInputIndication_signalUpdate = -1;
static int hf_h245_UserInputIndication_signal_rtp = -1;
static int hf_h245_UserInputIndication_signal = -1;
static int hf_h245_NewATMVCIndication_reverseParameters = -1;
static int hf_h245_NewATMVCIndication_aal_aal5 = -1;
static int hf_h245_NewATMVCIndication_aal_aal1 = -1;
static int hf_h245_NewATMVCIndication_aal = -1;
static int hf_h245_NewATMVCIndication = -1;
static int hf_h245_VendorIdentification = -1;
static int hf_h245_MCLocationIndication = -1;
static int hf_h245_H2250MaximumSkewIndication = -1;
static int hf_h245_H223SkewIndication = -1;
static int hf_h245_JitterIndication = -1;
static int hf_h245_MiscellaneousIndication_type_videoNotDecodedMBs = -1;
static int hf_h245_MiscellaneousIndication = -1;
static int hf_h245_VideoIndicateCompose = -1;
static int hf_h245_TerminalYouAreSeeingInSubPictureNumber = -1;
static int hf_h245_FunctionNotSupported = -1;
static int hf_h245_MobileMultilinkReconfigurationCommand = -1;
static int hf_h245_NewATMVCCommand_reverseParameters = -1;
static int hf_h245_NewATMVCCommand = -1;
static int hf_h245_NewATMVCCommand_aal_aal5 = -1;
static int hf_h245_NewATMVCCommand_aal_aal1 = -1;
static int hf_h245_EncryptionUpdateRequest = -1;
static int hf_h245_KeyProtectionMethod = -1;
static int hf_h245_MiscellaneousCommand_type_lostPartialPicture = -1;
static int hf_h245_MiscellaneousCommand_type_videoBadMBs = -1;
static int hf_h245_MiscellaneousCommand_type_progressiveRefinementStart = -1;
static int hf_h245_MiscellaneousCommand_type_videoFastUpdateMB = -1;
static int hf_h245_MiscellaneousCommand_type_videoFastUpdateGOB = -1;
static int hf_h245_MiscellaneousCommand = -1;
static int hf_h245_SubstituteConferenceIDCommand = -1;
static int hf_h245_FlowControlCommand = -1;
static int hf_h245_EncryptionCommand_encryptionAlgorithmID = -1;
static int hf_h245_SendTerminalCapabilitySet_specificRequest = -1;
static int hf_h245_LogicalChannelRateRelease = -1;
static int hf_h245_LogicalChannelRateReject = -1;
static int hf_h245_LogicalChannelRateAck = -1;
static int hf_h245_LogicalChannelRateRequest = -1;
static int hf_h245_ConnectionIdentifier = -1;
static int hf_h245_DialingInformationNumber = -1;
static int hf_h245_MultilinkIndication_excessiveError = -1;
static int hf_h245_MultilinkIndication_crcDesired = -1;
static int hf_h245_MultilinkResponse_maximumHeaderInterval = -1;
static int hf_h245_MultilinkResponse_removeConnection = -1;
static int hf_h245_MultilinkResponse_addConnection = -1;
static int hf_h245_MultilinkResponse_callInformation = -1;
static int hf_h245_MultilinkRequest_maximumHeaderInterval = -1;
static int hf_h245_MultilinkRequest_removeConnection = -1;
static int hf_h245_MultilinkRequest_addConnection = -1;
static int hf_h245_MultilinkRequest_callInformation = -1;
static int hf_h245_TerminalInformation = -1;
static int hf_h245_RequestAllTerminalIDsResponse = -1;
static int hf_h245_ConferenceResponse_terminalCertificateResponse = -1;
static int hf_h245_ConferenceResponse_chairTokenOwnerResponse = -1;
static int hf_h245_ConferenceResponse_extensionAddressResponse = -1;
static int hf_h245_ConferenceResponse_passwordResponse = -1;
static int hf_h245_ConferenceResponse_conferenceIDResponse = -1;
static int hf_h245_ConferenceResponse_terminalIDResponse = -1;
static int hf_h245_ConferenceResponse_mCterminalIDResponse = -1;
static int hf_h245_TerminalLabel = -1;
static int hf_h245_Criteria = -1;
static int hf_h245_ConferenceRequest_requestTerminalCertificate = -1;
static int hf_h245_CommunicationModeTableEntry = -1;
static int hf_h245_CommunicationModeRequest = -1;
static int hf_h245_CommunicationModeCommand = -1;
static int hf_h245_MaintenanceLoopOffCommand = -1;
static int hf_h245_MaintenanceLoopReject = -1;
static int hf_h245_MaintenanceLoopAck = -1;
static int hf_h245_MaintenanceLoopRequest = -1;
static int hf_h245_RoundTripDelayResponse = -1;
static int hf_h245_RoundTripDelayRequest = -1;
static int hf_h245_DataMode_application_t38fax = -1;
static int hf_h245_DataMode_application_nlpid = -1;
static int hf_h245_DataMode = -1;
static int hf_h245_VBDMode = -1;
static int hf_h245_G7231AnnexCMode_g723AnnexCAudioMode = -1;
static int hf_h245_G7231AnnexCMode = -1;
static int hf_h245_IS13818AudioMode = -1;
static int hf_h245_IS11172AudioMode = -1;
static int hf_h245_IS11172VideoMode = -1;
static int hf_h245_H263VideoMode = -1;
static int hf_h245_H262VideoMode = -1;
static int hf_h245_H261VideoMode = -1;
static int hf_h245_RedundancyEncodingMode = -1;
static int hf_h245_H2250ModeParameters = -1;
static int hf_h245_H223ModeParameters_adaptationLayerType_al3 = -1;
static int hf_h245_H223ModeParameters = -1;
static int hf_h245_FECMode_rfc2733Mode_mode_separateStream_samePort = -1;
static int hf_h245_FECMode_rfc2733Mode_mode_separateStream_differentPort = -1;
static int hf_h245_FECMode_rfc2733Mode = -1;
static int hf_h245_MultiplePayloadStreamElementMode = -1;
static int hf_h245_MultiplePayloadStreamMode = -1;
static int hf_h245_RedundancyEncodingDTModeElement = -1;
static int hf_h245_RedundancyEncodingDTMode = -1;
static int hf_h245_MultiplexedStreamModeParameters = -1;
static int hf_h245_H235Mode = -1;
static int hf_h245_ModeElement = -1;
static int hf_h245_RequestModeRelease = -1;
static int hf_h245_RequestModeReject = -1;
static int hf_h245_RequestModeAck = -1;
static int hf_h245_RequestMode = -1;
static int hf_h245_RequestMultiplexEntryRelease = -1;
static int hf_h245_RequestMultiplexEntryRejectionDescriptions = -1;
static int hf_h245_RequestMultiplexEntryReject = -1;
static int hf_h245_RequestMultiplexEntryAck = -1;
static int hf_h245_RequestMultiplexEntry = -1;
static int hf_h245_MultiplexEntrySendRelease = -1;
static int hf_h245_MultiplexEntryRejectionDescriptions = -1;
static int hf_h245_MultiplexEntrySendReject = -1;
static int hf_h245_MultiplexEntrySendAck = -1;
static int hf_h245_MultiplexElement = -1;
static int hf_h245_MultiplexEntryDescriptor = -1;
static int hf_h245_MultiplexEntrySend = -1;
static int hf_h245_RequestChannelCloseRelease = -1;
static int hf_h245_RequestChannelCloseReject = -1;
static int hf_h245_RequestChannelCloseAck = -1;
static int hf_h245_RequestChannelClose = -1;
static int hf_h245_CloseLogicalChannelAck = -1;
static int hf_h245_CloseLogicalChannel = -1;
static int hf_h245_H2250LogicalChannelAckParameters = -1;
static int hf_h245_OpenLogicalChannelConfirm = -1;
static int hf_h245_OpenLogicalChannelReject = -1;
static int hf_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters = -1;
static int hf_h245_OpenLogicalChannelAck = -1;
static int hf_h245_EscrowData = -1;
static int hf_h245_EncryptionSync = -1;
static int hf_h245_MulticastAddress_iP6Address = -1;
static int hf_h245_MulticastAddress_iPAddress = -1;
static int hf_h245_UnicastAddress_iPSourceRouteAddress = -1;
static int hf_h245_UnicastAddress_iP6Address = -1;
static int hf_h245_UnicastAddress_iPXAddress = -1;
static int hf_h245_UnicastAddress_iPAddress = -1;
static int hf_h245_FECData_rfc2733_mode_separateStream_samePort = -1;
static int hf_h245_FECData_rfc2733_mode_separateStream_differentPort = -1;
static int hf_h245_FECData_rfc2733 = -1;
static int hf_h245_MultiplePayloadStreamElement = -1;
static int hf_h245_MultiplePayloadStream = -1;
static int hf_h245_RedundancyEncodingElement = -1;
static int hf_h245_RedundancyEncoding_rtpRedundancyEncoding = -1;
static int hf_h245_RedundancyEncoding = -1;
static int hf_h245_RTPPayloadType = -1;
static int hf_h245_H2250LogicalChannelParameters = -1;
static int hf_h245_V76HDLCParameters = -1;
static int hf_h245_V76LogicalChannelParameters_mode_eRM = -1;
static int hf_h245_V76LogicalChannelParameters = -1;
static int hf_h245_H223AnnexCArqParameters = -1;
static int hf_h245_H223AL3MParameters = -1;
static int hf_h245_H223AL2MParameters = -1;
static int hf_h245_H223AL1MParameters = -1;
static int hf_h245_H223LogicalChannelParameters_adaptionLayerType_al3 = -1;
static int hf_h245_H223LogicalChannelParameters = -1;
static int hf_h245_H222LogicalChannelParameters = -1;
static int hf_h245_MultiplexedStreamParameter = -1;
static int hf_h245_H235Media = -1;
static int hf_h245_V75Parameters = -1;
static int hf_h245_Q2931Address = -1;
static int hf_h245_NetworkAccessParameters = -1;
static int hf_h245_reverseLogicalChannelParameters = -1;
static int hf_h245_forwardLogicalChannelParameters = -1;
static int hf_h245_OpenLogicalChannel = -1;
static int hf_h245_FECCapability_rfc2733_separateStream = -1;
static int hf_h245_FECCapability_rfc2733 = -1;
static int hf_h245_MultiplePayloadStreamCapability = -1;
static int hf_h245_NoPTAudioToneCapability = -1;
static int hf_h245_NoPTAudioTelephonyEventCapability = -1;
static int hf_h245_AudioToneCapability = -1;
static int hf_h245_AudioTelephonyEventCapability = -1;
static int hf_h245_MultiplexedStreamCapability = -1;
static int hf_h245_GenericParameter = -1;
static int hf_h245_GenericCapability = -1;
static int hf_h245_ConferenceCapability = -1;
static int hf_h245_IntegrityCapability = -1;
static int hf_h245_AuthenticationCapability = -1;
static int hf_h245_EncryptionAuthenticationAndIntegrity = -1;
static int hf_h245_T38FaxTcpOptions = -1;
static int hf_h245_T38FaxUdpOptions = -1;
static int hf_h245_T38FaxProfile = -1;
static int hf_h245_T84Profile_t84Restricted = -1;
static int hf_h245_V42bis = -1;
static int hf_h245_DataApplicationCapability_application_t38fax = -1;
static int hf_h245_DataApplicationCapability_application_nlpid = -1;
static int hf_h245_DataApplicationCapability_application_t84 = -1;
static int hf_h245_DataApplicationCapability = -1;
static int hf_h245_VBDCapability = -1;
static int hf_h245_GSMAudioCapability = -1;
static int hf_h245_IS13818AudioCapability = -1;
static int hf_h245_IS11172AudioCapability = -1;
static int hf_h245_G7231AnnexCCapability_g723AnnexCAudioMode = -1;
static int hf_h245_G7231AnnexCCapability = -1;
static int hf_h245_G729Extensions = -1;
static int hf_h245_AudioCapability_g7231 = -1;
static int hf_h245_IS11172VideoCapability = -1;
static int hf_h245_H263Version3Options = -1;
static int hf_h245_H263ModeComboFlags = -1;
static int hf_h245_H263VideoModeCombos = -1;
static int hf_h245_CustomPictureFormat_pixelAspectInformation_extendedPAR = -1;
static int hf_h245_CustomPictureFormat_mPI_customPCF = -1;
static int hf_h245_CustomPictureFormat_mPI = -1;
static int hf_h245_CustomPictureFormat = -1;
static int hf_h245_CustomPictureClockFrequency = -1;
static int hf_h245_RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters = -1;
static int hf_h245_RefPictureSelection_enhancedReferencePicSelect = -1;
static int hf_h245_RefPictureSelection_additionalPictureMemory = -1;
static int hf_h245_RefPictureSelection = -1;
static int hf_h245_TransperencyParameters = -1;
static int hf_h245_H263Options = -1;
static int hf_h245_EnhancementOptions = -1;
static int hf_h245_BEnhancementParameters = -1;
static int hf_h245_EnhancementLayerInfo = -1;
static int hf_h245_H263VideoCapability = -1;
static int hf_h245_H262VideoCapability = -1;
static int hf_h245_H261VideoCapability = -1;
static int hf_h245_MediaDistributionCapability = -1;
static int hf_h245_MultipointCapability = -1;
static int hf_h245_receiveMultipointCapability = -1;
static int hf_h245_transmitMultipointCapability = -1;
static int hf_h245_receiveAndTransmitMultipointCapability = -1;
static int hf_h245_RTPH263VideoRedundancyFrameMapping = -1;
static int hf_h245_RTPH263VideoRedundancyEncoding = -1;
static int hf_h245_RedundancyEncodingCapability = -1;
static int hf_h245_TransportCapability = -1;
static int hf_h245_MediaChannelCapability = -1;
static int hf_h245_MediaTransportType_AtmAAL5Compressed = -1;
static int hf_h245_QOSCapability = -1;
static int hf_h245_ATMParameters = -1;
static int hf_h245_RSVPParameters = -1;
static int hf_h245_MediaPacketizationCapability = -1;
static int hf_h245_H2250Capability_mcCapability = -1;
static int hf_h245_H2250Capability = -1;
static int hf_h245_V75Capability = -1;
static int hf_h245_V76Capability = -1;
static int hf_h245_H223AnnexCCapability = -1;
static int hf_h245_H223Capability_mobileMultilinkFrameCapability = -1;
static int hf_h245_H223Capability_mobileOperationTransmitCapability = -1;
static int hf_h245_H223Capability_h223MultiplexTableCapability_enhanced = -1;
static int hf_h245_H223Capability = -1;
static int hf_h245_VCCapability_aal1ViaGateway = -1;
static int hf_h245_VCCapability_availableBitRates_rangeOfBitRates = -1;
static int hf_h245_VCCapability_availableBitRates = -1;
static int hf_h245_VCCapability_aal5 = -1;
static int hf_h245_VCCapability_aal1 = -1;
static int hf_h245_VCCapability = -1;
static int hf_h245_H222Capability = -1;
static int hf_h245_H235SecurityCapability = -1;
static int hf_h245_Capability_h233EncryptionReceiveCapability = -1;
static int hf_h245_TerminalCapabilitySetRelease = -1;
static int hf_h245_TerminalCapabilitySetReject = -1;
static int hf_h245_TerminalCapabilitySetAck = -1;
static int hf_h245_CapabilityDescriptor = -1;
static int hf_h245_CapabilityTableEntry = -1;
static int hf_h245_TerminalCapabilitySet = -1;
static int hf_h245_MasterSlaveDeterminationRelease = -1;
static int hf_h245_MasterSlaveDeterminationReject = -1;
static int hf_h245_MasterSlaveDeterminationAck = -1;
static int hf_h245_MasterSlaveDetermination = -1;
static int hf_h245_h221NonStandard = -1;
static int hf_h245_NonStandardParameter = -1;
static int hf_h245_NonStandardMessage = -1;
static int hf_h245_FlowControlIndication_restriction = -1;
static int hf_h245_FlowControlIndication_scope = -1;
static int hf_h245_UserInputIndication_userInputSupportIndication = -1;
static int hf_h245_UserInputIndication = -1;
static int hf_h245_NewATMVCIndication_reverseParameters_multiplex = -1;
static int hf_h245_NewATMVCIndication_multiplex = -1;
static int hf_h245_NewATMVCIndication_aal_aal1_errorCorrection = -1;
static int hf_h245_NewATMVCIndication_aal_aal1_clockRecovery = -1;
static int hf_h245_JitterIndication_scope = -1;
static int hf_h245_MiscellaneousIndication_type = -1;
static int hf_h245_ConferenceIndication = -1;
static int hf_h245_FunctionNotSupported_cause = -1;
static int hf_h245_FunctionNotUnderstood = -1;
static int hf_h245_MobileMultilinkReconfigurationCommand_status = -1;
static int hf_h245_NewATMVCCommand_reverseParameters_multiplex = -1;
static int hf_h245_NewATMVCCommand_multiplex = -1;
static int hf_h245_NewATMVCCommand_aal_aal1_errorCorrection = -1;
static int hf_h245_NewATMVCCommand_aal_aal1_clockRecovery = -1;
static int hf_h245_NewATMVCCommand_aal = -1;
static int hf_h245_H223MultiplexReconfiguration_h223AnnexADoubleFlag = -1;
static int hf_h245_H223MultiplexReconfiguration_h223ModeChange = -1;
static int hf_h245_H223MultiplexReconfiguration = -1;
static int hf_h245_PictureReference = -1;
static int hf_h245_MiscellaneousCommand_type_progressiveRefinementStart_repeatCount = -1;
static int hf_h245_MiscellaneousCommand_type = -1;
static int hf_h245_ConferenceCommand = -1;
static int hf_h245_EndSessionCommand_gstnOptions = -1;
static int hf_h245_EndSessionCommand_isdnOptions = -1;
static int hf_h245_FlowControlCommand_restriction = -1;
static int hf_h245_FlowControlCommand_scope = -1;
static int hf_h245_EncryptionCommand = -1;
static int hf_h245_SendTerminalCapabilitySet = -1;
static int hf_h245_LogicalChannelRateRejectReason = -1;
static int hf_h245_DialingInformationNetworkType = -1;
static int hf_h245_DialingInformation = -1;
static int hf_h245_MultilinkIndication = -1;
static int hf_h245_MultilinkResponse_addConnection_responseCode_rejected = -1;
static int hf_h245_MultilinkResponse_addConnection_responseCode = -1;
static int hf_h245_MultilinkResponse = -1;
static int hf_h245_MultilinkRequest_maximumHeaderInterval_requestType = -1;
static int hf_h245_MultilinkRequest = -1;
static int hf_h245_RemoteMCResponse_reject = -1;
static int hf_h245_RemoteMCResponse = -1;
static int hf_h245_RemoteMCRequest = -1;
static int hf_h245_ConferenceResponse_sendThisSourceResponse = -1;
static int hf_h245_ConferenceResponse_makeTerminalBroadcasterResponse = -1;
static int hf_h245_ConferenceResponse_broadcastMyLogicalChannelResponse = -1;
static int hf_h245_ConferenceResponse_makeMeChairResponse = -1;
static int hf_h245_ConferenceResponse = -1;
static int hf_h245_ConferenceRequest = -1;
static int hf_h245_CommunicationModeTableEntry_dataType = -1;
static int hf_h245_CommunicationModeResponse = -1;
static int hf_h245_MaintenanceLoopReject_cause = -1;
static int hf_h245_MaintenanceLoopReject_type = -1;
static int hf_h245_MaintenanceLoopAck_type = -1;
static int hf_h245_MaintenanceLoopRequest_type = -1;
static int hf_h245_EncryptionMode = -1;
static int hf_h245_DataMode_application = -1;
static int hf_h245_IS13818AudioMode_multiChannelType = -1;
static int hf_h245_IS13818AudioMode_audioSampling = -1;
static int hf_h245_IS13818AudioMode_audioLayer = -1;
static int hf_h245_IS11172AudioMode_multichannelType = -1;
static int hf_h245_IS11172AudioMode_audioSampling = -1;
static int hf_h245_IS11172AudioMode_audioLayer = -1;
static int hf_h245_AudioMode_g7231 = -1;
static int hf_h245_AudioMode = -1;
static int hf_h245_H263VideoMode_resolution = -1;
static int hf_h245_H262VideoMode_profileAndLevel = -1;
static int hf_h245_H261VideoMode_resolution = -1;
static int hf_h245_VideoMode = -1;
static int hf_h245_RedundancyEncodingMode_secondaryEncoding = -1;
static int hf_h245_V76ModeParameters = -1;
static int hf_h245_H223ModeParameters_adaptationLayerType = -1;
static int hf_h245_FECMode_rfc2733Mode_mode_separateStream = -1;
static int hf_h245_FECMode_rfc2733Mode_mode = -1;
static int hf_h245_FECMode = -1;
static int hf_h245_RedundancyEncodingDTModeElement_type = -1;
static int hf_h245_H235Mode_mediaMode = -1;
static int hf_h245_ModeElementType = -1;
static int hf_h245_RequestModeReject_cause = -1;
static int hf_h245_RequestMultiplexEntryRejectionDescriptions_cause = -1;
static int hf_h245_MultiplexEntryRejectionDescriptions_cause = -1;
static int hf_h245_MultiplexElement_repeatCount = -1;
static int hf_h245_MultiplexElement_type = -1;
static int hf_h245_RequestChannelCloseReject_cause = -1;
static int hf_h245_RequestChannelClose_reason = -1;
static int hf_h245_CloseLogicalChannel_reason = -1;
static int hf_h245_CloseLogicalChannel_source = -1;
static int hf_h245_OpenLogicalChannelReject_cause = -1;
static int hf_h245_forwardMultiplexAckParameters = -1;
static int hf_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters = -1;
static int hf_h245_MulticastAddress = -1;
static int hf_h245_UnicastAddress_iPSourceRouteAddress_routing = -1;
static int hf_h245_UnicastAddress = -1;
static int hf_h245_mediaControlChannel = -1;
static int hf_h245_localAreaAddress = -1;
static int hf_h245_mediaChannel = -1;
static int hf_h245_signalAddress = -1;
static int hf_h245_FECData_rfc2733_mode_separateStream = -1;
static int hf_h245_FECData_rfc2733_mode = -1;
static int hf_h245_FECData = -1;
static int hf_h245_RTPPayloadType_payloadDescriptor = -1;
static int hf_h245_H2250LogicalChannelParameters_mediaPacketization = -1;
static int hf_h245_CRCLength = -1;
static int hf_h245_V76LogicalChannelParameters_mode_eRM_recovery = -1;
static int hf_h245_V76LogicalChannelParameters_mode = -1;
static int hf_h245_V76LogicalChannelParameters_suspendResume = -1;
static int hf_h245_H223AnnexCArqParameters_numberOfRetransmissions = -1;
static int hf_h245_H223AL3MParameters_arqType = -1;
static int hf_h245_H223AL3MParameters_crcLength = -1;
static int hf_h245_H223AL3MParameters_headerFormat = -1;
static int hf_h245_H223AL2MParameters_headerFEC = -1;
static int hf_h245_H223AL1MParameters_arqType = -1;
static int hf_h245_H223AL1MParameters_crcLength = -1;
static int hf_h245_H223AL1MParameters_headerFEC = -1;
static int hf_h245_H223AL1MParameters_transferMode = -1;
static int hf_h245_H223LogicalChannelParameters_adaptationLayerType = -1;
static int hf_h245_H235Media_mediaType = -1;
static int hf_h245_DataType = -1;
static int hf_h245_Q2931Address_address = -1;
static int hf_h245_NetworkAccessParameters_t120SetupProcedure = -1;
static int hf_h245_NetworkAccessParameters_networkAddress = -1;
static int hf_h245_NetworkAccessParameters_distribution = -1;
static int hf_h245_reverseLogicalChannelParameters_multiplexParameters = -1;
static int hf_h245_forwardLogicalChannelParameters_multiplexParameters = -1;
static int hf_h245_FECCapability = -1;
static int hf_h245_MultiplexFormat = -1;
static int hf_h245_ParameterValue = -1;
static int hf_h245_ParameterIdentifier = -1;
static int hf_h245_CapabilityIdentifier = -1;
static int hf_h245_UserInputCapability = -1;
static int hf_h245_MediaEncryptionAlgorithm = -1;
static int hf_h245_T38FaxUdpOptions_t38FaxUdpEC = -1;
static int hf_h245_T38FaxRateManagement = -1;
static int hf_h245_T84Profile = -1;
static int hf_h245_CompressionType = -1;
static int hf_h245_DataProtocolCapability_v76wCompression = -1;
static int hf_h245_DataProtocolCapability = -1;
static int hf_h245_DataApplicationCapability_application = -1;
static int hf_h245_AudioCapability = -1;
static int hf_h245_CustomPictureFormat_pixelAspectInformation = -1;
static int hf_h245_RefPictureSelection_videoBackChannelSend = -1;
static int hf_h245_VideoCapability = -1;
static int hf_h245_RTPH263VideoRedundancyEncoding_frameToThreadMapping = -1;
static int hf_h245_RedundancyEncodingMethod = -1;
static int hf_h245_MediaTransportType = -1;
static int hf_h245_QOSMode = -1;
static int hf_h245_H223Capability_h223MultiplexTableCapability = -1;
static int hf_h245_VCCapability_availableBitRates_type = -1;
static int hf_h245_MultiplexCapability = -1;
static int hf_h245_Capability = -1;
static int hf_h245_TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded = -1;
static int hf_h245_TerminalCapabilitySetReject_cause = -1;
static int hf_h245_MasterSlaveDeterminationReject_cause = -1;
static int hf_h245_MasterSlaveDeterminationAck_decision = -1;
static int hf_h245_RequestModeAck_response_decision = -1;
static int hf_h245_NonStandardIdentifier = -1;
static int hf_h245_h233EncryptionTransmitCapability = -1;
static int hf_h245_nullClockRecovery = -1;
static int hf_h245_srtsClockRecovery = -1;
static int hf_h245_adaptiveClockRecovery = -1;
static int hf_h245_nullErrorCorrection = -1;
static int hf_h245_longInterleaver = -1;
static int hf_h245_shortInterleaver = -1;
static int hf_h245_errorCorrectionOnly = -1;
static int hf_h245_structuredDataTransfer = -1;
static int hf_h245_partiallyFilledCells = -1;
static int hf_h245_transportStream = -1;
static int hf_h245_programStream = -1;
static int hf_h245_transportWithIframes = -1;
static int hf_h245_videoWithAL1 = -1;
static int hf_h245_videoWithAL2 = -1;
static int hf_h245_videoWithAL3 = -1;
static int hf_h245_audioWithAL1 = -1;
static int hf_h245_audioWithAL2 = -1;
static int hf_h245_audioWithAL3 = -1;
static int hf_h245_dataWithAL1 = -1;
static int hf_h245_dataWithAL2 = -1;
static int hf_h245_dataWithAL3 = -1;
static int hf_h245_maxMUXPDUSizeCapability = -1;
static int hf_h245_nsrpSupport = -1;
static int hf_h245_modeChangeCapability = -1;
static int hf_h245_h223AnnexA = -1;
static int hf_h245_h223AnnexADoubleFlag_bool = -1;
static int hf_h245_h223AnnexB = -1;
static int hf_h245_h223AnnexBwithHeader = -1;
static int hf_h245_videoWithAL1M = -1;
static int hf_h245_videoWithAL2M = -1;
static int hf_h245_videoWithAL3M = -1;
static int hf_h245_audioWithAL1M = -1;
static int hf_h245_audioWithAL2M = -1;
static int hf_h245_audioWithAL3M = -1;
static int hf_h245_dataWithAL1M = -1;
static int hf_h245_dataWithAL2M = -1;
static int hf_h245_dataWithAL3M = -1;
static int hf_h245_alpduInterleaving = -1;
static int hf_h245_rsCodeCapability = -1;
static int hf_h245_suspendResumeCapabilitywAddress = -1;
static int hf_h245_suspendResumeCapabilitywoAddress = -1;
static int hf_h245_rejCapability = -1;
static int hf_h245_sREJCapability = -1;
static int hf_h245_mREJCapability = -1;
static int hf_h245_crc8bitCapability = -1;
static int hf_h245_crc16bitCapability = -1;
static int hf_h245_crc32bitCapability = -1;
static int hf_h245_uihCapability = -1;
static int hf_h245_twoOctetAddressFieldCapability = -1;
static int hf_h245_loopBackTestCapability = -1;
static int hf_h245_audioHeader = -1;
static int hf_h245_centralizedConferenceMC = -1;
static int hf_h245_decentralizedConferenceMC = -1;
static int hf_h245_rtcpVideoControlCapability = -1;
static int hf_h245_logicalChannelSwitchingCapability = -1;
static int hf_h245_t120DynamicPortCapability = -1;
static int hf_h245_h261aVideoPacketization = -1;
static int hf_h245_atmUBR = -1;
static int hf_h245_atmrtVBR = -1;
static int hf_h245_atmnrtVBR = -1;
static int hf_h245_atmABR = -1;
static int hf_h245_atmCBR = -1;
static int hf_h245_variableDelta = -1;
static int hf_h245_multicastCapability = -1;
static int hf_h245_multiUniCastConference = -1;
static int hf_h245_centralizedControl = -1;
static int hf_h245_distributedControl = -1;
static int hf_h245_centralizedAudio = -1;
static int hf_h245_distributedAudio = -1;
static int hf_h245_centralizedVideo = -1;
static int hf_h245_distributedVideo = -1;
static int hf_h245_temporalSpatialTradeOffCapability = -1;
static int hf_h245_stillImageTransmission = -1;
static int hf_h245_videoBadMBsCap = -1;
static int hf_h245_profileAndLevelSPatML = -1;
static int hf_h245_profileAndLevelMPatLL = -1;
static int hf_h245_profileAndLevelMPatML = -1;
static int hf_h245_profileAndLevelMPatH14 = -1;
static int hf_h245_profileAndLevelMPatHL = -1;
static int hf_h245_profileAndLevelSNRatLL = -1;
static int hf_h245_profileAndLevelSNRatML = -1;
static int hf_h245_profileAndLevelSpatialatH14 = -1;
static int hf_h245_profileAndLevelHPatML = -1;
static int hf_h245_profileAndLevelHPatH14 = -1;
static int hf_h245_profileAndLevelHPatHL = -1;
static int hf_h245_unrestrictedVector = -1;
static int hf_h245_arithmeticCoding = -1;
static int hf_h245_advancedPrediction = -1;
static int hf_h245_pbFrames = -1;
static int hf_h245_errorCompensation = -1;
static int hf_h245_baseBitRateConstrained = -1;
static int hf_h245_advancedIntraCodingMode = -1;
static int hf_h245_deblockingFilterMode = -1;
static int hf_h245_improvedPBFramesMode = -1;
static int hf_h245_unlimitedMotionVectors = -1;
static int hf_h245_fullPictureFreeze = -1;
static int hf_h245_partialPictureFreezeAndRelease = -1;
static int hf_h245_resizingPartPicFreezeAndRelease = -1;
static int hf_h245_fullPictureSnapshot = -1;
static int hf_h245_partialPictureSnapshot = -1;
static int hf_h245_videoSegmentTagging = -1;
static int hf_h245_progressiveRefinement = -1;
static int hf_h245_dynamicPictureResizingByFour = -1;
static int hf_h245_dynamicPictureResizingSixteenthPel = -1;
static int hf_h245_dynamicWarpingHalfPel = -1;
static int hf_h245_dynamicWarpingSixteenthPel = -1;
static int hf_h245_independentSegmentDecoding = -1;
static int hf_h245_slicesInOrderNonRect = -1;
static int hf_h245_slicesInOrderRect = -1;
static int hf_h245_slicesNoOrderNonRect = -1;
static int hf_h245_slicesNoOrderRect = -1;
static int hf_h245_alternateInterVLCMode = -1;
static int hf_h245_modifiedQuantizationMode = -1;
static int hf_h245_reducedResolutionUpdate = -1;
static int hf_h245_separateVideoBackChannel = -1;
static int hf_h245_videoMux = -1;
static int hf_h245_anyPixelAspectRatio = -1;
static int hf_h245_referencePicSelect = -1;
static int hf_h245_enhancedReferencePicSelect_bool = -1;
static int hf_h245_dataPartitionedSlices = -1;
static int hf_h245_fixedPointIDCT0 = -1;
static int hf_h245_interlacedFields = -1;
static int hf_h245_currentPictureHeaderRepetition = -1;
static int hf_h245_previousPictureHeaderRepetition = -1;
static int hf_h245_nextPictureHeaderRepetition = -1;
static int hf_h245_pictureNumber_bool = -1;
static int hf_h245_spareReferencePictures = -1;
static int hf_h245_constrainedBitstream = -1;
static int hf_h245_silenceSuppression = -1;
static int hf_h245_annexA = -1;
static int hf_h245_annexB = -1;
static int hf_h245_annexD = -1;
static int hf_h245_annexE = -1;
static int hf_h245_annexF = -1;
static int hf_h245_annexG = -1;
static int hf_h245_annexH = -1;
static int hf_h245_audioLayer1 = -1;
static int hf_h245_audioLayer2 = -1;
static int hf_h245_audioLayer3 = -1;
static int hf_h245_audioSampling32k = -1;
static int hf_h245_audioSampling44k1 = -1;
static int hf_h245_audioSampling48k = -1;
static int hf_h245_singleChannel = -1;
static int hf_h245_twoChannels = -1;
static int hf_h245_audioSampling16k = -1;
static int hf_h245_audioSampling22k05 = -1;
static int hf_h245_audioSampling24k = -1;
static int hf_h245_threeChannels21 = -1;
static int hf_h245_threeChannels30 = -1;
static int hf_h245_fourChannels2020 = -1;
static int hf_h245_fourChannels22 = -1;
static int hf_h245_fourChannels31 = -1;
static int hf_h245_fiveChannels3020 = -1;
static int hf_h245_fiveChannels32 = -1;
static int hf_h245_lowFrequencyEnhancement = -1;
static int hf_h245_multilingual = -1;
static int hf_h245_comfortNoise = -1;
static int hf_h245_scrambled = -1;
static int hf_h245_qcif_bool = -1;
static int hf_h245_cif_bool = -1;
static int hf_h245_ccir601Seq = -1;
static int hf_h245_ccir601Prog = -1;
static int hf_h245_hdtvSeq = -1;
static int hf_h245_hdtvProg = -1;
static int hf_h245_g3FacsMH200x100 = -1;
static int hf_h245_g3FacsMH200x200 = -1;
static int hf_h245_g4FacsMMR200x100 = -1;
static int hf_h245_g4FacsMMR200x200 = -1;
static int hf_h245_jbig200x200Seq = -1;
static int hf_h245_jbig200x200Prog = -1;
static int hf_h245_jbig300x300Seq = -1;
static int hf_h245_jbig300x300Prog = -1;
static int hf_h245_digPhotoLow = -1;
static int hf_h245_digPhotoMedSeq = -1;
static int hf_h245_digPhotoMedProg = -1;
static int hf_h245_digPhotoHighSeq = -1;
static int hf_h245_digPhotoHighProg = -1;
static int hf_h245_fillBitRemoval = -1;
static int hf_h245_transcodingJBIG = -1;
static int hf_h245_transcodingMMR = -1;
static int hf_h245_t38TCPBidirectionalMode = -1;
static int hf_h245_chairControlCapability = -1;
static int hf_h245_videoIndicateMixingCapability = -1;
static int hf_h245_multipointVisualizationCapability = -1;
static int hf_h245_controlOnMuxStream = -1;
static int hf_h245_redundancyEncoding_bool = -1;
static int hf_h245_separatePort = -1;
static int hf_h245_samePort_bool = -1;
static int hf_h245_associateConference = -1;
static int hf_h245_audioHeaderPresent = -1;
static int hf_h245_segmentableFlag = -1;
static int hf_h245_alsduSplitting = -1;
static int hf_h245_uIH = -1;
static int hf_h245_loopbackTestProcedure = -1;
static int hf_h245_mediaGuaranteedDelivery = -1;
static int hf_h245_mediaControlGuaranteedDelivery = -1;
static int hf_h245_flowControlToZero = -1;
static int hf_h245_multiplexCapability_bool = -1;
static int hf_h245_secureChannel = -1;
static int hf_h245_sharedSecret = -1;
static int hf_h245_certProtectedKey = -1;
static int hf_h245_bitRateLockedToPCRClock = -1;
static int hf_h245_bitRateLockedToNetworkClock = -1;
static int hf_h245_IS11172_BitRate = -1;
static int hf_h245_IS13818_BitRate = -1;
static int hf_h245_ATM_BitRate = -1;
static int hf_h245_t35CountryCode = -1;
static int hf_h245_t35Extension = -1;
static int hf_h245_manufacturerCode = -1;
static int hf_h245_terminalType = -1;
static int hf_h245_statusDeterminationNumber = -1;
static int hf_h245_CapabilityTableEntryNumber = -1;
static int hf_h245_CapabilityDescriptorNumber = -1;
static int hf_h245_h233IVResponseTime = -1;
static int hf_h245_maxPendingReplacementFor = -1;
static int hf_h245_numberOfVCs = -1;
static int hf_h245_forwardMaximumSDUSize = -1;
static int hf_h245_backwardMaximumSDUSize = -1;
static int hf_h245_singleBitRate = -1;
static int hf_h245_lowerBitRate = -1;
static int hf_h245_higherBitRate = -1;
static int hf_h245_maximumAl2SDUSize = -1;
static int hf_h245_maximumAl3SDUSize = -1;
static int hf_h245_maximumDelayJitter = -1;
static int hf_h245_maximumNestingDepth = -1;
static int hf_h245_maximumElementListSize = -1;
static int hf_h245_maximumSubElementListSize = -1;
static int hf_h245_h223bitRate = -1;
static int hf_h245_maximumSampleSize = -1;
static int hf_h245_maximumPayloadLength = -1;
static int hf_h245_maximumAL1MPDUSize = -1;
static int hf_h245_maximumAL2MSDUSize = -1;
static int hf_h245_maximumAL3MSDUSize = -1;
static int hf_h245_numOfDLCS = -1;
static int hf_h245_n401Capability = -1;
static int hf_h245_maxWindowSizeCapability = -1;
static int hf_h245_maximumAudioDelayJitter = -1;
static int hf_h245_tokenRate = -1;
static int hf_h245_bucketSize = -1;
static int hf_h245_peakRate = -1;
static int hf_h245_minPoliced = -1;
static int hf_h245_maxPktSize = -1;
static int hf_h245_maxNTUSize = -1;
static int hf_h245_numberOfThreads = -1;
static int hf_h245_framesBetweenSyncPoints = -1;
static int hf_h245_threadNumber = -1;
static int hf_h245_qcifMPI_1_4 = -1;
static int hf_h245_qcifMPI_1_32 = -1;
static int hf_h245_qcifMPI_1_2048 = -1;
static int hf_h245_cifMPI_1_4 = -1;
static int hf_h245_cifMPI_1_32 = -1;
static int hf_h245_cifMPI_1_2048 = -1;
static int hf_h245_videoBitRate = -1;
static int hf_h245_vbvBufferSize = -1;
static int hf_h245_samplesPerLine = -1;
static int hf_h245_linesPerFrame = -1;
static int hf_h245_framesPerSecond = -1;
static int hf_h245_luminanceSampleRate = -1;
static int hf_h245_sqcifMPI_1_32 = -1;
static int hf_h245_sqcifMPI_1_2048 = -1;
static int hf_h245_cif4MPI_1_32 = -1;
static int hf_h245_cif4MPI_1_2048 = -1;
static int hf_h245_cif16MPI_1_32 = -1;
static int hf_h245_cif16MPI_1_2048 = -1;
static int hf_h245_maxBitRate_192400 = -1;
static int hf_h245_hrd_B = -1;
static int hf_h245_bppMaxKb = -1;
static int hf_h245_slowSqcifMPI = -1;
static int hf_h245_slowQcifMPI = -1;
static int hf_h245_slowCifMPI = -1;
static int hf_h245_slowCif4MPI = -1;
static int hf_h245_slowCif16MPI = -1;
static int hf_h245_numberOfBPictures = -1;
static int hf_h245_presentationOrder = -1;
static int hf_h245_offset_x = -1;
static int hf_h245_offset_y = -1;
static int hf_h245_scale_x = -1;
static int hf_h245_scale_y = -1;
static int hf_h245_sqcifAdditionalPictureMemory = -1;
static int hf_h245_qcifAdditionalPictureMemory = -1;
static int hf_h245_cifAdditionalPictureMemory = -1;
static int hf_h245_cif4AdditionalPictureMemory = -1;
static int hf_h245_cif16AdditionalPictureMemory = -1;
static int hf_h245_bigCpfAdditionalPictureMemory = -1;
static int hf_h245_mpuHorizMBs = -1;
static int hf_h245_mpuVertMBs = -1;
static int hf_h245_mpuTotalNumber = -1;
static int hf_h245_clockConversionCode = -1;
static int hf_h245_clockDivisor = -1;
static int hf_h245_maxCustomPictureWidth = -1;
static int hf_h245_minCustomPictureWidth = -1;
static int hf_h245_minCustomPictureHeight = -1;
static int hf_h245_maxCustomPictureHeight = -1;
static int hf_h245_standardMPI = -1;
static int hf_h245_customMPI = -1;
static int hf_h245_width = -1;
static int hf_h245_height = -1;
static int hf_h245_pictureRate = -1;
static int hf_h245_g711Alaw64k = -1;
static int hf_h245_g711Alaw56k = -1;
static int hf_h245_g711Ulaw64k = -1;
static int hf_h245_g711Ulaw56k = -1;
static int hf_h245_g722_64k = -1;
static int hf_h245_g722_56k = -1;
static int hf_h245_g722_48k = -1;
static int hf_h245_maxAl_sduAudioFrames = -1;
static int hf_h245_g728 = -1;
static int hf_h245_g729 = -1;
static int hf_h245_g729AnnexA = -1;
static int hf_h245_g729wAnnexB = -1;
static int hf_h245_g729AnnexAwAnnexB = -1;
static int hf_h245_audioUnit = -1;
static int hf_h245_highRateMode0 = -1;
static int hf_h245_highRateMode1 = -1;
static int hf_h245_lowRateMode0 = -1;
static int hf_h245_lowRateMode1 = -1;
static int hf_h245_sidMode0 = -1;
static int hf_h245_sidMode1 = -1;
static int hf_h245_audioUnitSize = -1;
static int hf_h245_maxBitRate_4294967295UL = -1;
static int hf_h245_numberOfCodewords = -1;
static int hf_h245_maximumStringLength = -1;
static int hf_h245_version = -1;
static int hf_h245_standard_0_127 = -1;
static int hf_h245_booleanArray = -1;
static int hf_h245_unsignedMin = -1;
static int hf_h245_unsignedMax = -1;
static int hf_h245_unsigned32Min = -1;
static int hf_h245_unsigned32Max = -1;
static int hf_h245_dynamicRTPPayloadType = -1;
static int hf_h245_portNumber = -1;
static int hf_h245_resourceID = -1;
static int hf_h245_subChannelID = -1;
static int hf_h245_pcr_pid = -1;
static int hf_h245_controlFieldOctets = -1;
static int hf_h245_sendBufferSize = -1;
static int hf_h245_rcpcCodeRate = -1;
static int hf_h245_rsCodeCorrection = -1;
static int hf_h245_finite_0_16 = -1;
static int hf_h245_windowSize = -1;
static int hf_h245_n401 = -1;
static int hf_h245_sessionID_0_255 = -1;
static int hf_h245_sessionID_1_255 = -1;
static int hf_h245_associatedSessionID = -1;
static int hf_h245_payloadType = -1;
static int hf_h245_protectedSessionID = -1;
static int hf_h245_protectedPayloadType = -1;
static int hf_h245_tsapIdentifier = -1;
static int hf_h245_synchFlag = -1;
static int hf_h245_finite_1_65535 = -1;
static int hf_h245_MultiplexTableEntryNumber = -1;
static int hf_h245_dataModeBitRate = -1;
static int hf_h245_sessionDependency = -1;
static int hf_h245_sRandom = -1;
static int hf_h245_McuNumber = -1;
static int hf_h245_TerminalNumber = -1;
static int hf_h245_maxNumberOfAdditionalConnections = -1;
static int hf_h245_requestedInterval = -1;
static int hf_h245_callAssociationNumber = -1;
static int hf_h245_currentInterval = -1;
static int hf_h245_infoNotAvailable = -1;
static int hf_h245_channelTag = -1;
static int hf_h245_ConnectionIDsequenceNumber = -1;
static int hf_h245_MaximumBitRate = -1;
static int hf_h245_maximumBitRate_0_16777215 = -1;
static int hf_h245_firstGOB_0_17 = -1;
static int hf_h245_numberOfGOBs = -1;
static int hf_h245_videoTemporalSpatialTradeOff = -1;
static int hf_h245_firstGOB_0_255 = -1;
static int hf_h245_firstMB_1_8192 = -1;
static int hf_h245_firstMB_1_9216 = -1;
static int hf_h245_numberOfMBs_1_8192 = -1;
static int hf_h245_numberOfMBs_1_9216 = -1;
static int hf_h245_maxH223MUXPDUsize = -1;
static int hf_h245_temporalReference_0_1023 = -1;
static int hf_h245_temporalReference_0_255 = -1;
static int hf_h245_pictureNumber = -1;
static int hf_h245_longTermPictureIndex = -1;
static int hf_h245_sampleSize = -1;
static int hf_h245_samplesPerFrame = -1;
static int hf_h245_sbeNumber = -1;
static int hf_h245_subPictureNumber = -1;
static int hf_h245_compositionNumber = -1;
static int hf_h245_estimatedReceivedJitterMantissa = -1;
static int hf_h245_estimatedReceivedJitterExponent = -1;
static int hf_h245_skippedFrameCount = -1;
static int hf_h245_additionalDecoderBuffer = -1;
static int hf_h245_skew = -1;
static int hf_h245_maximumSkew = -1;
static int hf_h245_duration = -1;
static int hf_h245_timestamp = -1;
static int hf_h245_frame = -1;
static int hf_h245_containedThread = -1;
static int hf_h245_t38FaxMaxBuffer = -1;
static int hf_h245_t38FaxMaxDatagram = -1;
static int hf_h245_expirationTime = -1;
static int hf_h245_object = -1;
static int hf_h245_protocolIdentifier = -1;
static int hf_h245_algorithm = -1;
static int hf_h245_antiSpamAlgorithm = -1;
static int hf_h245_standard_object = -1;
static int hf_h245_oid = -1;
static int hf_h245_escrowID = -1;
static int hf_h245_field = -1;
static int hf_h245_NonStandardParameterData = -1;
static int hf_h245_nlpidData = -1;
static int hf_h245_nonCollapsingRaw = -1;
static int hf_h245_uuid = -1;
static int hf_h245_octetString = -1;
static int hf_h245_externalReference = -1;
static int hf_h245_nsapAddress = -1;
static int hf_h245_subaddress_1_20 = -1;
static int hf_h245_programDescriptors = -1;
static int hf_h245_streamDescriptors = -1;
static int hf_h245_ipv4network = -1;
static int hf_h245_ipxNode = -1;
static int hf_h245_ipxNetnum = -1;
static int hf_h245_ipv6network = -1;
static int hf_h245_netBios = -1;
static int hf_h245_nsap = -1;
static int hf_h245_h235Key = -1;
static int hf_h245_value = -1;
static int hf_h245_certificateResponse = -1;
static int hf_h245_TerminalID = -1;
static int hf_h245_ConferenceID = -1;
static int hf_h245_Password = -1;
static int hf_h245_encryptionSE = -1;
static int hf_h245_conferenceIdentifier = -1;
static int hf_h245_returnedFunction = -1;
static int hf_h245_productNumber = -1;
static int hf_h245_versionNumber = -1;
static int hf_h245_mediaDistributionCapability = -1;
static int hf_h245_AlternativeCapabilitySet = -1;
static int hf_h245_frameToThreadMapping_custom = -1;
static int hf_h245_RedundancyEncodingCapability_sequence_of = -1;
static int hf_h245_frameSequence = -1;
static int hf_h245_EncryptionCapability = -1;
static int hf_h245_escrowentry = -1;
static int hf_h245_elementList = -1;
static int hf_h245_subElementList = -1;
static int hf_h245_requestedModes = -1;
static int hf_h245_CertSelectionCriteria = -1;
static int hf_h245_capabilityTable = -1;
static int hf_h245_capabilityDescriptors = -1;
static int hf_h245_simultaneousCapabilities = -1;
static int hf_h245_gatewayAddress = -1;
static int hf_h245_snrEnhancement = -1;
static int hf_h245_spatialEnhancement = -1;
static int hf_h245_bPictureEnhancement = -1;
static int hf_h245_customPictureClockFrequency = -1;
static int hf_h245_customPictureFormat = -1;
static int hf_h245_modeCombos = -1;
static int hf_h245_customPCF = -1;
static int hf_h245_pixelAspectCode = -1;
static int hf_h245_extendedPAR = -1;
static int hf_h245_h263VideoCoupledModes = -1;
static int hf_h245_capabilityOnMuxStream = -1;
static int hf_h245_capabilities = -1;
static int hf_h245_multiplexEntryDescriptors = -1;
static int hf_h245_multiplexTableEntryNumber_set_of = -1;
static int hf_h245_VCCapability_set_of = -1;
static int hf_h245_rejectionDescriptions = -1;
static int hf_h245_entryNumbers = -1;
static int hf_h245_ModeDescription = -1;
static int hf_h245_communicationModeTable = -1;
static int hf_h245_terminalListResponse = -1;
static int hf_h245_differential = -1;
static int hf_h245_networkType = -1;
static int hf_h245_capabilityTableEntryNumbers = -1;
static int hf_h245_capabilityDescriptorNumbers = -1;
static int hf_h245_qOSCapabilities = -1;
static int hf_h245_containedThreads = -1;
static int hf_h245_CapabilityTableEntryNumber_sequence_of = -1;
static int hf_h245_mediaChannelCapabilities = -1;
static int hf_h245_rtpPayloadType_sequence_of = -1;
static int hf_h245_centralizedData = -1;
static int hf_h245_distributedData = -1;
static int hf_h245_nonStandardData = -1;
static int hf_h245_collapsing = -1;
static int hf_h245_nonCollapsing = -1;
static int hf_h245_supersedes = -1;
static int hf_h245_genericParameter = -1;
static int hf_h245_secondary_REE = -1;
static int hf_h245_elements_MPSE = -1;
static int hf_h245_secondary_REDTME = -1;
static int hf_h245_elements_MPSEM = -1;
static int hf_h245_TerminalInformationSO = -1;
static int hf_h245_lostPicture = -1;
static int hf_h245_recoveryReferencePicture = -1;
static int hf_h245_iPSourceRouteAddress_route = -1;
static int hf_h245_audioTelephoneEvent = -1;
static int hf_h245_alphanumeric = -1;
static int hf_h245_h221Manufacturer = -1;


static gint ett_h245 = -1;
static gint ett_h245_VCCapability_set_of = -1;
static gint ett_h245_MultimediaSystemControlMessage = -1;
static gint ett_h245_RequestMessage = -1;
static gint ett_h245_ResponseMessage = -1;
static gint ett_h245_IndicationMessage = -1;
static gint ett_h245_CommandMessage = -1;
static gint ett_h245_EndSessionCommand = -1;
static gint ett_h245_MobileMultilinkReconfigurationIndication = -1;
static gint ett_h245_FlowControlIndication = -1;
static gint ett_h245_UserInputIndication_extendedAlphanumeric = -1;
static gint ett_h245_UserInputIndication_signalUpdate_rtp = -1;
static gint ett_h245_UserInputIndication_signalUpdate = -1;
static gint ett_h245_UserInputIndication_signal_rtp = -1;
static gint ett_h245_UserInputIndication_signal = -1;
static gint ett_h245_NewATMVCIndication_reverseParameters = -1;
static gint ett_h245_NewATMVCIndication_aal_aal5 = -1;
static gint ett_h245_NewATMVCIndication_aal_aal1 = -1;
static gint ett_h245_NewATMVCIndication_aal = -1;
static gint ett_h245_NewATMVCIndication = -1;
static gint ett_h245_VendorIdentification = -1;
static gint ett_h245_MCLocationIndication = -1;
static gint ett_h245_H2250MaximumSkewIndication = -1;
static gint ett_h245_H223SkewIndication = -1;
static gint ett_h245_JitterIndication = -1;
static gint ett_h245_AlternativeCapabilitySet = -1;
static gint ett_h245_MiscellaneousIndication_type_videoNotDecodedMBs = -1;
static gint ett_h245_MiscellaneousIndication = -1;
static gint ett_h245_VideoIndicateCompose = -1;
static gint ett_h245_TerminalYouAreSeeingInSubPictureNumber = -1;
static gint ett_h245_FunctionNotSupported = -1;
static gint ett_h245_MobileMultilinkReconfigurationCommand = -1;
static gint ett_h245_NewATMVCCommand_reverseParameters = -1;
static gint ett_h245_NewATMVCCommand = -1;
static gint ett_h245_NewATMVCCommand_aal_aal5 = -1;
static gint ett_h245_NewATMVCCommand_aal_aal1 = -1;
static gint ett_h245_EncryptionUpdateRequest = -1;
static gint ett_h245_KeyProtectionMethod = -1;
static gint ett_h245_MiscellaneousCommand_type_lostPartialPicture = -1;
static gint ett_h245_MiscellaneousCommand_type_videoBadMBs = -1;
static gint ett_h245_MiscellaneousCommand_type_progressiveRefinementStart = -1;
static gint ett_h245_MiscellaneousCommand_type_videoFastUpdateMB = -1;
static gint ett_h245_MiscellaneousCommand_type_videoFastUpdateGOB = -1;
static gint ett_h245_MiscellaneousCommand = -1;
static gint ett_h245_SubstituteConferenceIDCommand = -1;
static gint ett_h245_FlowControlCommand = -1;
static gint ett_h245_EncryptionCommand_encryptionAlgorithmID = -1;
static gint ett_h245_SendTerminalCapabilitySet_specificRequest = -1;
static gint ett_h245_LogicalChannelRateRelease = -1;
static gint ett_h245_LogicalChannelRateReject = -1;
static gint ett_h245_LogicalChannelRateAck = -1;
static gint ett_h245_LogicalChannelRateRequest = -1;
static gint ett_h245_ConnectionIdentifier = -1;
static gint ett_h245_DialingInformationNumber = -1;
static gint ett_h245_MultilinkIndication_excessiveError = -1;
static gint ett_h245_MultilinkIndication_crcDesired = -1;
static gint ett_h245_MultilinkResponse_maximumHeaderInterval = -1;
static gint ett_h245_MultilinkResponse_removeConnection = -1;
static gint ett_h245_MultilinkResponse_addConnection = -1;
static gint ett_h245_MultilinkResponse_callInformation = -1;
static gint ett_h245_MultilinkRequest_maximumHeaderInterval = -1;
static gint ett_h245_MultilinkRequest_removeConnection = -1;
static gint ett_h245_MultilinkRequest_addConnection = -1;
static gint ett_h245_MultilinkRequest_callInformation = -1;
static gint ett_h245_TerminalInformation = -1;
static gint ett_h245_RequestAllTerminalIDsResponse = -1;
static gint ett_h245_ConferenceResponse_terminalCertificateResponse = -1;
static gint ett_h245_ConferenceResponse_chairTokenOwnerResponse = -1;
static gint ett_h245_ConferenceResponse_extensionAddressResponse = -1;
static gint ett_h245_ConferenceResponse_passwordResponse = -1;
static gint ett_h245_ConferenceResponse_conferenceIDResponse = -1;
static gint ett_h245_ConferenceResponse_terminalIDResponse = -1;
static gint ett_h245_ConferenceResponse_mCterminalIDResponse = -1;
static gint ett_h245_TerminalLabel = -1;
static gint ett_h245_Criteria = -1;
static gint ett_h245_ConferenceRequest_requestTerminalCertificate = -1;
static gint ett_h245_CommunicationModeTableEntry = -1;
static gint ett_h245_CommunicationModeRequest = -1;
static gint ett_h245_CommunicationModeCommand = -1;
static gint ett_h245_MaintenanceLoopOffCommand = -1;
static gint ett_h245_MaintenanceLoopReject = -1;
static gint ett_h245_MaintenanceLoopAck = -1;
static gint ett_h245_MaintenanceLoopRequest = -1;
static gint ett_h245_RoundTripDelayResponse = -1;
static gint ett_h245_RoundTripDelayRequest = -1;
static gint ett_h245_DataMode_application_t38fax = -1;
static gint ett_h245_DataMode_application_nlpid = -1;
static gint ett_h245_DataMode = -1;
static gint ett_h245_VBDMode = -1;
static gint ett_h245_G7231AnnexCMode_g723AnnexCAudioMode = -1;
static gint ett_h245_G7231AnnexCMode = -1;
static gint ett_h245_IS13818AudioMode = -1;
static gint ett_h245_IS11172AudioMode = -1;
static gint ett_h245_IS11172VideoMode = -1;
static gint ett_h245_H263VideoMode = -1;
static gint ett_h245_H262VideoMode = -1;
static gint ett_h245_H261VideoMode = -1;
static gint ett_h245_RedundancyEncodingMode = -1;
static gint ett_h245_H2250ModeParameters = -1;
static gint ett_h245_H223ModeParameters_adaptationLayerType_al3 = -1;
static gint ett_h245_H223ModeParameters = -1;
static gint ett_h245_FECMode_rfc2733Mode_mode_separateStream_samePort = -1;
static gint ett_h245_FECMode_rfc2733Mode_mode_separateStream_differentPort = -1;
static gint ett_h245_FECMode_rfc2733Mode = -1;
static gint ett_h245_MultiplePayloadStreamElementMode = -1;
static gint ett_h245_MultiplePayloadStreamMode = -1;
static gint ett_h245_RedundancyEncodingDTModeElement = -1;
static gint ett_h245_RedundancyEncodingDTMode = -1;
static gint ett_h245_MultiplexedStreamModeParameters = -1;
static gint ett_h245_H235Mode = -1;
static gint ett_h245_ModeElement = -1;
static gint ett_h245_RequestModeRelease = -1;
static gint ett_h245_RequestModeReject = -1;
static gint ett_h245_RequestModeAck = -1;
static gint ett_h245_RequestMode = -1;
static gint ett_h245_RequestMultiplexEntryRelease = -1;
static gint ett_h245_RequestMultiplexEntryRejectionDescriptions = -1;
static gint ett_h245_RequestMultiplexEntryReject = -1;
static gint ett_h245_RequestMultiplexEntryAck = -1;
static gint ett_h245_RequestMultiplexEntry = -1;
static gint ett_h245_MultiplexEntrySendRelease = -1;
static gint ett_h245_MultiplexEntryRejectionDescriptions = -1;
static gint ett_h245_MultiplexEntrySendReject = -1;
static gint ett_h245_MultiplexEntrySendAck = -1;
static gint ett_h245_MultiplexElement = -1;
static gint ett_h245_MultiplexEntryDescriptor = -1;
static gint ett_h245_MultiplexEntrySend = -1;
static gint ett_h245_RequestChannelCloseRelease = -1;
static gint ett_h245_RequestChannelCloseReject = -1;
static gint ett_h245_RequestChannelCloseAck = -1;
static gint ett_h245_RequestChannelClose = -1;
static gint ett_h245_CloseLogicalChannelAck = -1;
static gint ett_h245_CloseLogicalChannel = -1;
static gint ett_h245_H2250LogicalChannelAckParameters = -1;
static gint ett_h245_OpenLogicalChannelConfirm = -1;
static gint ett_h245_OpenLogicalChannelReject = -1;
static gint ett_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters = -1;
static gint ett_h245_OpenLogicalChannelAck = -1;
static gint ett_h245_EscrowData = -1;
static gint ett_h245_EncryptionSync = -1;
static gint ett_h245_MulticastAddress_iP6Address = -1;
static gint ett_h245_MulticastAddress_iPAddress = -1;
static gint ett_h245_UnicastAddress_iPSourceRouteAddress = -1;
static gint ett_h245_UnicastAddress_iP6Address = -1;
static gint ett_h245_UnicastAddress_iPXAddress = -1;
static gint ett_h245_UnicastAddress_iPAddress = -1;
static gint ett_h245_FECData_rfc2733_mode_separateStream_samePort = -1;
static gint ett_h245_FECData_rfc2733_mode_separateStream_differentPort = -1;
static gint ett_h245_FECData_rfc2733 = -1;
static gint ett_h245_MultiplePayloadStreamElement = -1;
static gint ett_h245_MultiplePayloadStream = -1;
static gint ett_h245_RedundancyEncodingElement = -1;
static gint ett_h245_RedundancyEncoding_rtpRedundancyEncoding = -1;
static gint ett_h245_RedundancyEncoding = -1;
static gint ett_h245_RTPPayloadType = -1;
static gint ett_h245_H2250LogicalChannelParameters = -1;
static gint ett_h245_V76HDLCParameters = -1;
static gint ett_h245_V76LogicalChannelParameters_mode_eRM = -1;
static gint ett_h245_V76LogicalChannelParameters = -1;
static gint ett_h245_H223AnnexCArqParameters = -1;
static gint ett_h245_H223AL3MParameters = -1;
static gint ett_h245_H223AL2MParameters = -1;
static gint ett_h245_H223AL1MParameters = -1;
static gint ett_h245_H223LogicalChannelParameters_adaptionLayerType_al3 = -1;
static gint ett_h245_H223LogicalChannelParameters = -1;
static gint ett_h245_H222LogicalChannelParameters = -1;
static gint ett_h245_MultiplexedStreamParameter = -1;
static gint ett_h245_H235Media = -1;
static gint ett_h245_V75Parameters = -1;
static gint ett_h245_Q2931Address = -1;
static gint ett_h245_NetworkAccessParameters = -1;
static gint ett_h245_reverseLogicalChannelParameters = -1;
static gint ett_h245_forwardLogicalChannelParameters = -1;
static gint ett_h245_OpenLogicalChannel = -1;
static gint ett_h245_FECCapability_rfc2733_separateStream = -1;
static gint ett_h245_FECCapability_rfc2733 = -1;
static gint ett_h245_MultiplePayloadStreamCapability = -1;
static gint ett_h245_NoPTAudioToneCapability = -1;
static gint ett_h245_NoPTAudioTelephonyEventCapability = -1;
static gint ett_h245_AudioToneCapability = -1;
static gint ett_h245_AudioTelephonyEventCapability = -1;
static gint ett_h245_MultiplexedStreamCapability = -1;
static gint ett_h245_GenericParameter = -1;
static gint ett_h245_GenericCapability = -1;
static gint ett_h245_ConferenceCapability = -1;
static gint ett_h245_IntegrityCapability = -1;
static gint ett_h245_AuthenticationCapability = -1;
static gint ett_h245_EncryptionAuthenticationAndIntegrity = -1;
static gint ett_h245_T38FaxTcpOptions = -1;
static gint ett_h245_T38FaxUdpOptions = -1;
static gint ett_h245_T38FaxProfile = -1;
static gint ett_h245_T84Profile_t84Restricted = -1;
static gint ett_h245_V42bis = -1;
static gint ett_h245_DataApplicationCapability_application_t38fax = -1;
static gint ett_h245_DataApplicationCapability_application_nlpid = -1;
static gint ett_h245_DataApplicationCapability_application_t84 = -1;
static gint ett_h245_DataApplicationCapability = -1;
static gint ett_h245_VBDCapability = -1;
static gint ett_h245_GSMAudioCapability = -1;
static gint ett_h245_IS13818AudioCapability = -1;
static gint ett_h245_IS11172AudioCapability = -1;
static gint ett_h245_G7231AnnexCCapability_g723AnnexCAudioMode = -1;
static gint ett_h245_G7231AnnexCCapability = -1;
static gint ett_h245_G729Extensions = -1;
static gint ett_h245_AudioCapability_g7231 = -1;
static gint ett_h245_IS11172VideoCapability = -1;
static gint ett_h245_H263Version3Options = -1;
static gint ett_h245_H263ModeComboFlags = -1;
static gint ett_h245_H263VideoModeCombos = -1;
static gint ett_h245_CustomPictureFormat_pixelAspectInformation_extendedPAR = -1;
static gint ett_h245_CustomPictureFormat_mPI_customPCF = -1;
static gint ett_h245_CustomPictureFormat_mPI = -1;
static gint ett_h245_CustomPictureFormat = -1;
static gint ett_h245_CustomPictureClockFrequency = -1;
static gint ett_h245_RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters = -1;
static gint ett_h245_RefPictureSelection_enhancedReferencePicSelect = -1;
static gint ett_h245_RefPictureSelection_additionalPictureMemory = -1;
static gint ett_h245_RefPictureSelection = -1;
static gint ett_h245_TransperencyParameters = -1;
static gint ett_h245_H263Options = -1;
static gint ett_h245_EnhancementOptions = -1;
static gint ett_h245_BEnhancementParameters = -1;
static gint ett_h245_EnhancementLayerInfo = -1;
static gint ett_h245_H263VideoCapability = -1;
static gint ett_h245_H262VideoCapability = -1;
static gint ett_h245_H261VideoCapability = -1;
static gint ett_h245_MediaDistributionCapability = -1;
static gint ett_h245_MultipointCapability = -1;
static gint ett_h245_RTPH263VideoRedundancyFrameMapping = -1;
static gint ett_h245_RTPH263VideoRedundancyEncoding = -1;
static gint ett_h245_RedundancyEncodingCapability = -1;
static gint ett_h245_TransportCapability = -1;
static gint ett_h245_MediaChannelCapability = -1;
static gint ett_h245_MediaTransportType_AtmAAL5Compressed = -1;
static gint ett_h245_QOSCapability = -1;
static gint ett_h245_ATMParameters = -1;
static gint ett_h245_RSVPParameters = -1;
static gint ett_h245_MediaPacketizationCapability = -1;
static gint ett_h245_H2250Capability_mcCapability = -1;
static gint ett_h245_H2250Capability = -1;
static gint ett_h245_V75Capability = -1;
static gint ett_h245_V76Capability = -1;
static gint ett_h245_H223AnnexCCapability = -1;
static gint ett_h245_H223Capability_mobileMultilinkFrameCapability = -1;
static gint ett_h245_H223Capability_mobileOperationTransmitCapability = -1;
static gint ett_h245_H223Capability_h223MultiplexTableCapability_enhanced = -1;
static gint ett_h245_H223Capability = -1;
static gint ett_h245_VCCapability_aal1ViaGateway = -1;
static gint ett_h245_VCCapability_availableBitRates_rangeOfBitRates = -1;
static gint ett_h245_VCCapability_availableBitRates = -1;
static gint ett_h245_VCCapability_aal5 = -1;
static gint ett_h245_VCCapability_aal1 = -1;
static gint ett_h245_VCCapability = -1;
static gint ett_h245_H222Capability = -1;
static gint ett_h245_H235SecurityCapability = -1;
static gint ett_h245_Capability_h233EncryptionReceiveCapability = -1;
static gint ett_h245_TerminalCapabilitySetRelease = -1;
static gint ett_h245_TerminalCapabilitySetReject = -1;
static gint ett_h245_TerminalCapabilitySetAck = -1;
static gint ett_h245_CapabilityDescriptor = -1;
static gint ett_h245_CapabilityTableEntry = -1;
static gint ett_h245_TerminalCapabilitySet = -1;
static gint ett_h245_MasterSlaveDeterminationRelease = -1;
static gint ett_h245_MasterSlaveDeterminationReject = -1;
static gint ett_h245_MasterSlaveDeterminationAck = -1;
static gint ett_h245_MasterSlaveDetermination = -1;
static gint ett_h245_h221NonStandard = -1;
static gint ett_h245_NonStandardParameter = -1;
static gint ett_h245_NonStandardMessage = -1;
static gint ett_h245_FlowControlIndication_restriction = -1;
static gint ett_h245_FlowControlIndication_scope = -1;
static gint ett_h245_UserInputIndication_userInputSupportIndication = -1;
static gint ett_h245_UserInputIndication = -1;
static gint ett_h245_NewATMVCIndication_reverseParameters_multiplex = -1;
static gint ett_h245_NewATMVCIndication_multiplex = -1;
static gint ett_h245_NewATMVCIndication_aal_aal1_errorCorrection = -1;
static gint ett_h245_NewATMVCIndication_aal_aal1_clockRecovery = -1;
static gint ett_h245_JitterIndication_scope = -1;
static gint ett_h245_MiscellaneousIndication_type = -1;
static gint ett_h245_ConferenceIndication = -1;
static gint ett_h245_FunctionNotSupported_cause = -1;
static gint ett_h245_FunctionNotUnderstood = -1;
static gint ett_h245_MobileMultilinkReconfigurationCommand_status = -1;
static gint ett_h245_NewATMVCCommand_reverseParameters_multiplex = -1;
static gint ett_h245_NewATMVCCommand_multiplex = -1;
static gint ett_h245_NewATMVCCommand_aal_aal1_errorCorrection = -1;
static gint ett_h245_NewATMVCCommand_aal_aal1_clockRecovery = -1;
static gint ett_h245_NewATMVCCommand_aal = -1;
static gint ett_h245_H223MultiplexReconfiguration_h223AnnexADoubleFlag = -1;
static gint ett_h245_H223MultiplexReconfiguration_h223ModeChange = -1;
static gint ett_h245_H223MultiplexReconfiguration = -1;
static gint ett_h245_PictureReference = -1;
static gint ett_h245_MiscellaneousCommand_type_progressiveRefinementStart_repeatCount = -1;
static gint ett_h245_MiscellaneousCommand_type = -1;
static gint ett_h245_ConferenceCommand = -1;
static gint ett_h245_EndSessionCommand_gstnOptions = -1;
static gint ett_h245_EndSessionCommand_isdnOptions = -1;
static gint ett_h245_FlowControlCommand_restriction = -1;
static gint ett_h245_FlowControlCommand_scope = -1;
static gint ett_h245_EncryptionCommand = -1;
static gint ett_h245_SendTerminalCapabilitySet = -1;
static gint ett_h245_LogicalChannelRateRejectReason = -1;
static gint ett_h245_DialingInformationNetworkType = -1;
static gint ett_h245_DialingInformation = -1;
static gint ett_h245_MultilinkIndication = -1;
static gint ett_h245_MultilinkResponse_addConnection_responseCode_rejected = -1;
static gint ett_h245_MultilinkResponse_addConnection_responseCode = -1;
static gint ett_h245_MultilinkResponse = -1;
static gint ett_h245_MultilinkRequest_maximumHeaderInterval_requestType = -1;
static gint ett_h245_MultilinkRequest = -1;
static gint ett_h245_RemoteMCResponse_reject = -1;
static gint ett_h245_RemoteMCResponse = -1;
static gint ett_h245_RemoteMCRequest = -1;
static gint ett_h245_ConferenceResponse_sendThisSourceResponse = -1;
static gint ett_h245_ConferenceResponse_makeTerminalBroadcasterResponse = -1;
static gint ett_h245_ConferenceResponse_broadcastMyLogicalChannelResponse = -1;
static gint ett_h245_ConferenceResponse_makeMeChairResponse = -1;
static gint ett_h245_ConferenceResponse = -1;
static gint ett_h245_ConferenceRequest = -1;
static gint ett_h245_CommunicationModeTableEntry_dataType = -1;
static gint ett_h245_CommunicationModeResponse = -1;
static gint ett_h245_MaintenanceLoopReject_cause = -1;
static gint ett_h245_MaintenanceLoopReject_type = -1;
static gint ett_h245_MaintenanceLoopAck_type = -1;
static gint ett_h245_MaintenanceLoopRequest_type = -1;
static gint ett_h245_EncryptionMode = -1;
static gint ett_h245_DataMode_application = -1;
static gint ett_h245_IS13818AudioMode_multiChannelType = -1;
static gint ett_h245_IS13818AudioMode_audioSampling = -1;
static gint ett_h245_IS13818AudioMode_audioLayer = -1;
static gint ett_h245_IS11172AudioMode_multichannelType = -1;
static gint ett_h245_IS11172AudioMode_audioSampling = -1;
static gint ett_h245_IS11172AudioMode_audioLayer = -1;
static gint ett_h245_AudioMode_g7231 = -1;
static gint ett_h245_AudioMode = -1;
static gint ett_h245_H263VideoMode_resolution = -1;
static gint ett_h245_H262VideoMode_profileAndLevel = -1;
static gint ett_h245_H261VideoMode_resolution = -1;
static gint ett_h245_VideoMode = -1;
static gint ett_h245_RedundancyEncodingMode_secondaryEncoding = -1;
static gint ett_h245_V76ModeParameters = -1;
static gint ett_h245_H223ModeParameters_adaptationLayerType = -1;
static gint ett_h245_FECMode_rfc2733Mode_mode_separateStream = -1;
static gint ett_h245_FECMode_rfc2733Mode_mode = -1;
static gint ett_h245_FECMode = -1;
static gint ett_h245_RedundancyEncodingDTModeElement_type = -1;
static gint ett_h245_H235Mode_mediaMode = -1;
static gint ett_h245_ModeElementType = -1;
static gint ett_h245_RequestModeReject_cause = -1;
static gint ett_h245_RequestMultiplexEntryRejectionDescriptions_cause = -1;
static gint ett_h245_MultiplexEntryRejectionDescriptions_cause = -1;
static gint ett_h245_MultiplexElement_repeatCount = -1;
static gint ett_h245_MultiplexElement_type = -1;
static gint ett_h245_RequestChannelCloseReject_cause = -1;
static gint ett_h245_RequestChannelClose_reason = -1;
static gint ett_h245_CloseLogicalChannel_reason = -1;
static gint ett_h245_CloseLogicalChannel_source = -1;
static gint ett_h245_OpenLogicalChannelReject_cause = -1;
static gint ett_h245_forwardMultiplexAckParameters = -1;
static gint ett_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters = -1;
static gint ett_h245_MulticastAddress = -1;
static gint ett_h245_UnicastAddress_iPSourceRouteAddress_routing = -1;
static gint ett_h245_UnicastAddress = -1;
static gint ett_h245_TransportAddress = -1;
static gint ett_h245_FECData_rfc2733_mode_separateStream = -1;
static gint ett_h245_FECData_rfc2733_mode = -1;
static gint ett_h245_FECData = -1;
static gint ett_h245_RTPPayloadType_payloadDescriptor = -1;
static gint ett_h245_H2250LogicalChannelParameters_mediaPacketization = -1;
static gint ett_h245_CRCLength = -1;
static gint ett_h245_V76LogicalChannelParameters_mode_eRM_recovery = -1;
static gint ett_h245_V76LogicalChannelParameters_mode = -1;
static gint ett_h245_V76LogicalChannelParameters_suspendResume = -1;
static gint ett_h245_H223AnnexCArqParameters_numberOfRetransmissions = -1;
static gint ett_h245_H223AL3MParameters_arqType = -1;
static gint ett_h245_H223AL3MParameters_crcLength = -1;
static gint ett_h245_H223AL3MParameters_headerFormat = -1;
static gint ett_h245_H223AL2MParameters_headerFEC = -1;
static gint ett_h245_H223AL1MParameters_arqType = -1;
static gint ett_h245_H223AL1MParameters_crcLength = -1;
static gint ett_h245_H223AL1MParameters_headerFEC = -1;
static gint ett_h245_H223AL1MParameters_transferMode = -1;
static gint ett_h245_H223LogicalChannelParameters_adaptationLayerType = -1;
static gint ett_h245_H235Media_mediaType = -1;
static gint ett_h245_DataType = -1;
static gint ett_h245_Q2931Address_address = -1;
static gint ett_h245_NetworkAccessParameters_t120SetupProcedure = -1;
static gint ett_h245_NetworkAccessParameters_networkAddress = -1;
static gint ett_h245_NetworkAccessParameters_distribution = -1;
static gint ett_h245_reverseLogicalChannelParameters_multiplexParameters = -1;
static gint ett_h245_forwardLogicalChannelParameters_multiplexParameters = -1;
static gint ett_h245_FECCapability = -1;
static gint ett_h245_MultiplexFormat = -1;
static gint ett_h245_ParameterValue = -1;
static gint ett_h245_ParameterIdentifier = -1;
static gint ett_h245_CapabilityIdentifier = -1;
static gint ett_h245_UserInputCapability = -1;
static gint ett_h245_MediaEncryptionAlgorithm = -1;
static gint ett_h245_T38FaxUdpOptions_t38FaxUdpEC = -1;
static gint ett_h245_T38FaxRateManagement = -1;
static gint ett_h245_T84Profile = -1;
static gint ett_h245_CompressionType = -1;
static gint ett_h245_DataProtocolCapability_v76wCompression = -1;
static gint ett_h245_DataProtocolCapability = -1;
static gint ett_h245_DataApplicationCapability_application = -1;
static gint ett_h245_AudioCapability = -1;
static gint ett_h245_CustomPictureFormat_pixelAspectInformation = -1;
static gint ett_h245_RefPictureSelection_videoBackChannelSend = -1;
static gint ett_h245_VideoCapability = -1;
static gint ett_h245_RTPH263VideoRedundancyEncoding_frameToThreadMapping = -1;
static gint ett_h245_RedundancyEncodingMethod = -1;
static gint ett_h245_MediaTransportType = -1;
static gint ett_h245_QOSMode = -1;
static gint ett_h245_H223Capability_h223MultiplexTableCapability = -1;
static gint ett_h245_VCCapability_availableBitRates_type = -1;
static gint ett_h245_MultiplexCapability = -1;
static gint ett_h245_Capability = -1;
static gint ett_h245_TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded = -1;
static gint ett_h245_TerminalCapabilitySetReject_cause = -1;
static gint ett_h245_MasterSlaveDeterminationReject_cause = -1;
static gint ett_h245_MasterSlaveDeterminationAck_decision = -1;
static gint ett_h245_RequestModeAck_response_decision = -1;
static gint ett_h245_NonStandardIdentifier = -1;
static gint ett_h245_mediaDistributionCapability = -1;
static gint ett_h245_frameToThreadMapping_custom = -1;
static gint ett_h245_RedundancyEncodingCapability_sequence_of = -1;
static gint ett_h245_frameSequence = -1;
static gint ett_h245_EncryptionCapability = -1;
static gint ett_h245_escrowentry = -1;
static gint ett_h245_elementList = -1;
static gint ett_h245_requestedModes = -1;
static gint ett_h245_CertSelectionCriteria = -1;
static gint ett_h245_capabilityTable = -1;
static gint ett_h245_capabilityDescriptors = -1;
static gint ett_h245_simultaneousCapabilities = -1;
static gint ett_h245_gatewayAddress = -1;
static gint ett_h245_snrEnhancement = -1;
static gint ett_h245_spatialEnhancement = -1;
static gint ett_h245_bPictureEnhancement = -1;
static gint ett_h245_customPictureClockFrequency = -1;
static gint ett_h245_customPictureFormat = -1;
static gint ett_h245_modeCombos = -1;
static gint ett_h245_customPCF = -1;
static gint ett_h245_pixelAspectCode = -1;
static gint ett_h245_extendedPAR = -1;
static gint ett_h245_h263VideoCoupledModes = -1;
static gint ett_h245_capabilityOnMuxStream = -1;
static gint ett_h245_capabilities = -1;
static gint ett_h245_multiplexEntryDescriptors = -1;
static gint ett_h245_multiplexTableEntryNumber_set_of = -1;
static gint ett_h245_rejectionDescriptions = -1;
static gint ett_h245_entryNumbers = -1;
static gint ett_h245_ModeDescription = -1;
static gint ett_h245_communicationModeTable = -1;
static gint ett_h245_terminalListResponse = -1;
static gint ett_h245_differential = -1;
static gint ett_h245_networkType = -1;
static gint ett_h245_capabilityTableEntryNumbers = -1;
static gint ett_h245_capabilityDescriptorNumbers = -1;
static gint ett_h245_qOSCapabilities = -1;
static gint ett_h245_subElementList = -1;
static gint ett_h245_containedThreads = -1;
static gint ett_h245_CapabilityTableEntryNumber_sequence_of = -1;
static gint ett_h245_mediaChannelCapabilities = -1;
static gint ett_h245_rtpPayloadType_sequence_of = -1;
static gint ett_h245_centralizedData = -1;
static gint ett_h245_distributedData = -1;
static gint ett_h245_nonStandardData = -1;
static gint ett_h245_collapsing = -1;
static gint ett_h245_nonCollapsing = -1;
static gint ett_h245_supersedes = -1;
static gint ett_h245_genericParameter = -1;
static gint ett_h245_secondary_REE = -1;
static gint ett_h245_elements_MPSE = -1;
static gint ett_h245_secondary_REDTME = -1;
static gint ett_h245_elements_MPSEM = -1;
static gint ett_h245_TerminalInformationSO = -1;
static gint ett_h245_lostPicture = -1;
static gint ett_h245_recoveryReferencePicture = -1;
static gint ett_h245_iPSourceRouteAddress_route = -1;

static dissector_table_t nsp_object_dissector_table;
static dissector_table_t nsp_h221_dissector_table;

static dissector_handle_t nsp_handle;

static guint32 ipv4_address;
static guint32 ipv4_port;
static char object[256];
static guint32 t35CountryCode;
static guint32 t35Extension;
static guint32 manufacturerCode;
static guint32 h221NonStandard;

static gboolean h245_reassembly = TRUE;
static gboolean h245_shorttypes = FALSE;
/* To put the codec type only in COL_INFO when
   an OLC is read */
char* codec_type = NULL;

static int
dissect_h245_NULL(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	return offset;
}








static const value_string MasterSlaveDeterminationAck_decision_vals[] = {
	{  0, "master" },
	{  1, "slave" },
	{  0, NULL }
};
static per_choice_t MasterSlaveDeterminationAck_decision_choice[] = {
	{  0, "master", ASN1_NO_EXTENSIONS,
		dissect_h245_NULL },
	{  1, "slave", ASN1_NO_EXTENSIONS,
		dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MasterSlaveDeterminationAck_decision(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MasterSlaveDeterminationAck_decision, ett_h245_MasterSlaveDeterminationAck_decision, MasterSlaveDeterminationAck_decision_choice, "Decision", NULL);

	return offset;
}



static per_sequence_t MasterSlaveDeterminationAck_sequence[] = {
	{ "decision", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MasterSlaveDeterminationAck_decision },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MasterSlaveDeterminationAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MasterSlaveDeterminationAck, ett_h245_MasterSlaveDeterminationAck, MasterSlaveDeterminationAck_sequence);

	return offset;
}


static const value_string MasterSlaveDeterminationReject_cause_vals[] = {
	{  0, "identicalNumbers" },
	{  0, NULL }
};
static per_choice_t MasterSlaveDeterminationReject_cause_choice[] = {
	{  0, "identicalNumbers", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MasterSlaveDeterminationReject_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MasterSlaveDeterminationReject_cause, ett_h245_MasterSlaveDeterminationReject_cause, MasterSlaveDeterminationReject_cause_choice, "Cause", NULL);

	return offset;
}



static per_sequence_t MasterSlaveDeterminationReject_sequence[] = {
	{ "cause", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MasterSlaveDeterminationReject_cause },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MasterSlaveDeterminationReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MasterSlaveDeterminationReject, ett_h245_MasterSlaveDeterminationReject, MasterSlaveDeterminationReject_sequence);

	return offset;
}



static const value_string QOSMode_vals[] = {
	{  0, "guaranteedQOS" },
	{  1, "controlledLoad" },
	{  0, NULL }
};
static per_choice_t QOSMode_choice[] = {
	{  0, "guaranteedQOS", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "controlledLoad", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_QOSMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_QOSMode, ett_h245_QOSMode, QOSMode_choice, "QOSMode", NULL);

	return offset;
}



static const value_string RefPictureSelection_videoBackChannelSend_vals[] = {
	{  0, "none" },
	{  1, "ackMessageOnly" },
	{  2, "nackMessageOnly" },
	{  3, "ackOrNackMessageOnly" },
	{  4, "ackAndNackMessage" },
	{  0, NULL }
};
static per_choice_t RefPictureSelection_videoBackChannelSend_choice[] = {
	{  0, "none", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "ackMessageOnly", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "nackMessageOnly", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "ackOrNackMessageOnly", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "ackAndNackMessage", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RefPictureSelection_videoBackChannelSend(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RefPictureSelection_videoBackChannelSend, ett_h245_RefPictureSelection_videoBackChannelSend, RefPictureSelection_videoBackChannelSend_choice, "videoBackChannelSend", NULL);

	return offset;
}



static const value_string T38FaxRateManagement_vals[] = {
	{  0, "localTCF" },
	{  1, "transferredTCF" },
	{  0, NULL }
};
static per_choice_t T38FaxRateManagement_choice[] = {
	{  0, "localTCF", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "transferredTCF", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_T38FaxRateManagement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_T38FaxRateManagement, ett_h245_T38FaxRateManagement, T38FaxRateManagement_choice, "T38FaxRateManagement", NULL);

	return offset;
}



static const value_string T38FaxUdpOptions_t38FaxUdpEC_vals[] = {
	{  0, "t38UDPFEC" },
	{  1, "t38UDPRedundancy" },
	{  0, NULL }
};
static per_choice_t T38FaxUdpOptions_t38FaxUdpEC_choice[] = {
	{  0, "t38UDPFEC", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "t38UDPRedundancy", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_T38FaxUdpOptions_t38FaxUdpEC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_T38FaxUdpOptions_t38FaxUdpEC, ett_h245_T38FaxUdpOptions_t38FaxUdpEC, T38FaxUdpOptions_t38FaxUdpEC_choice, "t38FaxUdpEC", NULL);

	return offset;
}



static const value_string NetworkAccessParameters_distribution_vals[] = {
	{  0, "unicast" },
	{  1, "multicast" },
	{  0, NULL }
};
static per_choice_t NetworkAccessParameters_distribution_choice[] = {
	{  0, "unicast", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "multicast", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NetworkAccessParameters_distribution(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NetworkAccessParameters_distribution, ett_h245_NetworkAccessParameters_distribution, NetworkAccessParameters_distribution_choice, "Distribution", NULL);

	return offset;
}



static const value_string NetworkAccessParameters_t120SetupProcedure_vals[] = {
	{  0, "originateCall" },
	{  1, "waitForCall" },
	{  2, "issueQuery" },
	{  0, NULL }
};
static per_choice_t NetworkAccessParameters_t120SetupProcedure_choice[] = {
	{  0, "originateCall", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "waitForCall", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "issueQuery", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NetworkAccessParameters_t120SetupProcedure(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NetworkAccessParameters_t120SetupProcedure, ett_h245_NetworkAccessParameters_t120SetupProcedure, NetworkAccessParameters_t120SetupProcedure_choice, "t120SetupProcedure", NULL);

	return offset;
}



static const value_string H223AL1MParameters_transferMode_vals[] = {
	{  0, "framed" },
	{  1, "unframed" },
	{  0, NULL }
};
static per_choice_t H223AL1MParameters_transferMode_choice[] = {
	{  0, "framed", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "unframed", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223AL1MParameters_transferMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223AL1MParameters_transferMode, ett_h245_H223AL1MParameters_transferMode, H223AL1MParameters_transferMode_choice, "transferMode", NULL);

	return offset;
}



static const value_string H223AL1MParameters_headerFEC_vals[] = {
	{  0, "sebch16-7" },
	{  1, "golay24-12" },
	{  0, NULL }
};
static per_choice_t H223AL1MParameters_headerFEC_choice[] = {
	{  0, "sebch16-7", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "golay24-12", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223AL1MParameters_headerFEC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223AL1MParameters_headerFEC, ett_h245_H223AL1MParameters_headerFEC, H223AL1MParameters_headerFEC_choice, "headerFEC", NULL);

	return offset;
}



static const value_string H223AL1MParameters_crcLength_vals[] = {
	{  0, "crc4bit" },
	{  1, "crc12bit" },
	{  2, "crc20bit" },
	{  3, "crc28bit" },
	{  4, "crc8bit" },
	{  5, "crc16bit" },
	{  6, "crc32bit" },
	{  7, "crcNotUsed" },
	{  0, NULL }
};
static per_choice_t H223AL1MParameters_crcLength_choice[] = {
	{  0, "crc4bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "crc12bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "crc20bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "crc28bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "crc8bit", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "crc16bit", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  6, "crc32bit", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  7, "crcNotUsed", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223AL1MParameters_crcLength(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223AL1MParameters_crcLength, ett_h245_H223AL1MParameters_crcLength, H223AL1MParameters_crcLength_choice, "crcLength", NULL);

	return offset;
}



static const value_string H223AL2MParameters_headerFEC_vals[] = {
	{  0, "sebch16-5" },
	{  1, "golay24-12" },
	{  0, NULL }
};
static per_choice_t H223AL2MParameters_headerFEC_choice[] = {
	{  0, "sebch16-5", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "golay24-12", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223AL2MParameters_headerFEC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223AL2MParameters_headerFEC, ett_h245_H223AL2MParameters_headerFEC, H223AL2MParameters_headerFEC_choice, "headerFEC", NULL);

	return offset;
}




static const value_string H223AL3MParameters_headerFormat_vals[] = {
	{  0, "sebch16-7" },
	{  1, "golay24-12" },
	{  0, NULL }
};
static per_choice_t H223AL3MParameters_headerFormat_choice[] = {
	{  0, "sebch16-7", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "golay24-12", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223AL3MParameters_headerFormat(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223AL3MParameters_headerFormat, ett_h245_H223AL3MParameters_headerFormat, H223AL3MParameters_headerFormat_choice, "headerFormat", NULL);

	return offset;
}




static const value_string H223AL3MParameters_crcLength_vals[] = {
	{  0, "crc4bit" },
	{  1, "crc12bit" },
	{  2, "crc20bit" },
	{  3, "crc28bit" },
	{  4, "crc8bit" },
	{  5, "crc16bit" },
	{  6, "crc32bit" },
	{  7, "crcNotUsed" },
	{  0, NULL }
};
static per_choice_t H223AL3MParameters_crcLength_choice[] = {
	{  0, "crc4bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "crc12bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "crc20bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "crc28bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "crc8bit", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "crc16bit", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  6, "crc32bit", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  7, "crcNotUsed", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223AL3MParameters_crcLength(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223AL3MParameters_crcLength, ett_h245_H223AL3MParameters_crcLength, H223AL3MParameters_crcLength_choice, "crcLength", NULL);

	return offset;
}




static const value_string V76LogicalChannelParameters_suspendResume_vals[] = {
	{  0, "noSuspendResume" },
	{  1, "suspendResumewAddress" },
	{  2, "suspendResumewoAddress" },
	{  0, NULL }
};
static per_choice_t V76LogicalChannelParameters_suspendResume_choice[] = {
	{  0, "noSuspendResume", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "suspendResumewAddress", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "suspendResumewoAddress", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_V76LogicalChannelParameters_suspendResume(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_V76LogicalChannelParameters_suspendResume, ett_h245_V76LogicalChannelParameters_suspendResume, V76LogicalChannelParameters_suspendResume_choice, "suspendResume", NULL);

	return offset;
}




static const value_string V76LogicalChannelParameters_mode_eRM_recovery_vals[] = {
	{  0, "rej" },
	{  1, "sREJ" },
	{  2, "mSREJ" },
	{  0, NULL }
};
static per_choice_t V76LogicalChannelParameters_mode_eRM_recovery_choice[] = {
	{  0, "rej", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "sREJ", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "mSREJ", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_V76LogicalChannelParameters_mode_eRM_recovery(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_V76LogicalChannelParameters_mode_eRM_recovery, ett_h245_V76LogicalChannelParameters_mode_eRM_recovery, V76LogicalChannelParameters_mode_eRM_recovery_choice, "recovery", NULL);

	return offset;
}




static const value_string CRCLength_vals[] = {
	{  0, "crc8bit" },
	{  1, "crc16bit" },
	{  2, "crc32bit" },
	{  0, NULL }
};
static per_choice_t CRCLength_choice[] = {
	{  0, "crc8bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "crc16bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "crc32bit", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_CRCLength(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_CRCLength, ett_h245_CRCLength, CRCLength_choice, "CRCLength", NULL);

	return offset;
}




static const value_string UnicastAddress_iPSourceRouteAddress_routing_vals[] = {
	{  0, "strict" },
	{  1, "loose" },
	{  0, NULL }
};
static per_choice_t UnicastAddress_iPSourceRouteAddress_routing_choice[] = {
	{  0, "strict", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "loose", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_UnicastAddress_iPSourceRouteAddress_routing(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_UnicastAddress_iPSourceRouteAddress_routing, ett_h245_UnicastAddress_iPSourceRouteAddress_routing, UnicastAddress_iPSourceRouteAddress_routing_choice, "routing", NULL);

	return offset;
}




static const value_string OpenLogicalChannelReject_cause_vals[] = {
	{  0, "unspecified" },
	{  1, "unsuitableReverseParameters" },
	{  2, "dataTypeNotSupported" },
	{  3, "dataTypeNotAvailable" },
	{  4, "unknownDataType" },
	{  5, "dataTypeALCombinationNotSupported" },
	{  6, "multicastChannelNotAllowed" },
	{  7, "insufficientBandwidth" },
	{  8, "separateStackEstablishmentFailed" },
	{  9, "invalidSessionID" },
	{ 10, "masterSlaveConflict" },
	{ 11, "waitForCommunicationMode" },
	{ 12, "invalidDependentChannel" },
	{ 13, "replacementForRejected" },
	{  0, NULL }
};
static per_choice_t OpenLogicalChannelReject_cause_choice[] = {
	{  0, "unspecified", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "unsuitableReverseParameters", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "dataTypeNotSupported", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "dataTypeNotAvailable", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "unknownDataType", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "dataTypeALCombinationNotSupported", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  6, "multicastChannelNotAllowed", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  7, "insufficientBandwidth", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  8, "separateStackEstablishmentFailed", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  9, "invalidSessionID", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{ 10, "masterSlaveConflict", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{ 11, "waitForCommunicationMode", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{ 12, "invalidDependentChannel", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{ 13, "replacementForRejected", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_OpenLogicalChannelReject_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_OpenLogicalChannelReject_cause, ett_h245_OpenLogicalChannelReject_cause, OpenLogicalChannelReject_cause_choice, "cause", NULL);

	return offset;
}



static const value_string CloseLogicalChannel_source_vals[] = {
	{  0, "user" },
	{  1, "lcse" },
	{  0, NULL }
};
static per_choice_t CloseLogicalChannel_source_choice[] = {
	{  0, "user", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "lcse", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_CloseLogicalChannel_source(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_CloseLogicalChannel_source, ett_h245_CloseLogicalChannel_source, CloseLogicalChannel_source_choice, "source", NULL);

	return offset;
}


static const value_string CloseLogicalChannel_reason_vals[] = {
	{  0, "unknown" },
	{  1, "reopen" },
	{  2, "reservationFailure" },
	{  0, NULL }
};
static per_choice_t CloseLogicalChannel_reason_choice[] = {
	{  0, "unknown", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "reopen", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "reservationFailure", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_CloseLogicalChannel_reason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_CloseLogicalChannel_reason, ett_h245_CloseLogicalChannel_reason, CloseLogicalChannel_reason_choice, "reason", NULL);

	return offset;
}



static const value_string RequestChannelClose_reason_vals[] = {
	{  0, "unknown" },
	{  1, "normal" },
	{  2, "reopen" },
	{  3, "reservationFailure" },
	{  0, NULL }
};
static per_choice_t RequestChannelClose_reason_choice[] = {
	{  0, "unknown", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "normal", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "reopen", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "reservationFailure", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RequestChannelClose_reason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RequestChannelClose_reason, ett_h245_RequestChannelClose_reason, RequestChannelClose_reason_choice, "reason", NULL);

	return offset;
}



static const value_string RequestChannelCloseReject_cause_vals[] = {
	{  0, "unspecified" },
	{  0, NULL }
};
static per_choice_t RequestChannelCloseReject_cause_choice[] = {
	{  0, "unspecified", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RequestChannelCloseReject_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RequestChannelCloseReject_cause, ett_h245_RequestChannelCloseReject_cause, RequestChannelCloseReject_cause_choice, "cause", NULL);

	return offset;
}




static const value_string MultiplexEntryRejectionDescriptions_cause_vals[] = {
	{  0, "unspecifiedCause" },
	{  1, "descriptorTooComplex" },
	{  0, NULL }
};
static per_choice_t MultiplexEntryRejectionDescriptions_cause_choice[] = {
	{  0, "unspecifiedCause", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "descriptorTooComplex", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultiplexEntryRejectionDescriptions_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultiplexEntryRejectionDescriptions_cause, ett_h245_MultiplexEntryRejectionDescriptions_cause, MultiplexEntryRejectionDescriptions_cause_choice, "cause", NULL);

	return offset;
}



static const value_string RequestMultiplexEntryRejectionDescriptions_cause_vals[] = {
	{  0, "unspecifiedCause" },
	{  0, NULL }
};
static per_choice_t RequestMultiplexEntryRejectionDescriptions_cause_choice[] = {
	{  0, "unspecifiedCause", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RequestMultiplexEntryRejectionDescriptions_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RequestMultiplexEntryRejectionDescriptions_cause, ett_h245_RequestMultiplexEntryRejectionDescriptions_cause, RequestMultiplexEntryRejectionDescriptions_cause_choice, "cause", NULL);

	return offset;
}



static const value_string RequestModeReject_cause_vals[] = {
	{  0, "modeUnavailable" },
	{  1, "multipointConstraint" },
	{  2, "requestDenied" },
	{  0, NULL }
};
static per_choice_t RequestModeReject_cause_choice[] = {
	{  0, "modeUnavailable", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "multipointConstraint", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "requestDenied", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RequestModeReject_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RequestModeReject_cause, ett_h245_RequestModeReject_cause, RequestModeReject_cause_choice, "cause", NULL);

	return offset;
}




static const value_string V76ModeParameters_vals[] = {
	{  0, "suspendResumewAddress" },
	{  1, "suspendResumewoAddress" },
	{  0, NULL }
};
static per_choice_t V76ModeParameters_choice[] = {
	{  0, "suspendResumewAddress", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "suspendResumewoAddress", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_V76ModeParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_V76ModeParameters, ett_h245_V76ModeParameters, V76ModeParameters_choice, "V76ModeParameters", NULL);

	return offset;
}



static const value_string H262VideoMode_profileAndLevel_vals[] = {
	{  0, "profileAndLevel-SPatML" },
	{  1, "profileAndLevel-MPatLL" },
	{  2, "profileAndLevel-MPatML" },
	{  3, "profileAndLevel-MPatH-14" },
	{  4, "profileAndLevel-MPatHL" },
	{  5, "profileAndLevel-SNRatLL" },
	{  6, "profileAndLevel-SNRatML" },
	{  7, "profileAndLevel-SpatialH-14" },
	{  8, "profileAndLevel-HPatML" },
	{  9, "profileAndLevel-HPatH-14" },
	{ 10, "profileAndLevel-HPatHL" },
	{  0, NULL }
};
static per_choice_t H262VideoMode_profileAndLevel_choice[] = {
	{  0, "profileAndLevel-SPatML", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "profileAndLevel-MPatLL", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "profileAndLevel-MPatML", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "profileAndLevel-MPatH-14", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "profileAndLevel-MPatHL", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "profileAndLevel-SNRatLL", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  6, "profileAndLevel-SNRatML", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  7, "profileAndLevel-SpatialH-14", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  8, "profileAndLevel-HPatML", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  9, "profileAndLevel-HPatH-14", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{ 10, "profileAndLevel-HPatHL", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H262VideoMode_profileAndLevel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H262VideoMode_profileAndLevel, ett_h245_H262VideoMode_profileAndLevel, H262VideoMode_profileAndLevel_choice, "profileAndLevel", NULL);

	return offset;
}




static const value_string H263VideoMode_resolution_vals[] = {
	{  0, "sqcif" },
	{  1, "qcif" },
	{  2, "cif" },
	{  3, "cif4" },
	{  4, "cif16" },
	{  5, "custom" },
	{  0, NULL }
};
static per_choice_t H263VideoMode_resolution_choice[] = {
	{  0, "sqcif", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "qcif", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "cif", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "cif4", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "cif16", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "custom", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H263VideoMode_resolution(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H263VideoMode_resolution, ett_h245_H263VideoMode_resolution, H263VideoMode_resolution_choice, "resolution", NULL);

	return offset;
}


static const value_string AudioMode_g7231_vals[] = {
	{  0, "noSilenceSuppressionLowRate" },
	{  1, "noSilenceSuppressionHighRate" },
	{  2, "silenceSuppressionLowRate" },
	{  3, "silenceSuppressionHighRate" },
	{  0, NULL }
};
static per_choice_t AudioMode_g7231_choice[] = {
	{  0, "noSilenceSuppressionLowRate", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "noSilenceSuppressionHighRate", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  2, "silenceSuppressionLowRate", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  3, "silenceSuppressionHighRate", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_AudioMode_g7231(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_AudioMode_g7231, ett_h245_AudioMode_g7231, AudioMode_g7231_choice, "g7231", NULL);

	return offset;
}



static const value_string IS11172AudioMode_audioLayer_vals[] = {
	{  0, "audioLayer1" },
	{  1, "audioLayer2" },
	{  2, "audioLayer3" },
	{  0, NULL }
};
static per_choice_t IS11172AudioMode_audioLayer_choice[] = {
	{  0, "audioLayer1", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "audioLayer2", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  2, "audioLayer3", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_IS11172AudioMode_audioLayer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_IS11172AudioMode_audioLayer, ett_h245_IS11172AudioMode_audioLayer, IS11172AudioMode_audioLayer_choice, "audioLayer", NULL);

	return offset;
}



static const value_string IS11172AudioMode_audioSampling_vals[] = {
	{  0, "audioSampling32k" },
	{  1, "audioSampling44k1" },
	{  2, "audioSampling48k" },
	{  0, NULL }
};
static per_choice_t IS11172AudioMode_audioSampling_choice[] = {
	{  0, "audioSampling32k", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "audioSampling44k1", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  2, "audioSampling48k", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_IS11172AudioMode_audioSampling(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_IS11172AudioMode_audioSampling, ett_h245_IS11172AudioMode_audioSampling, IS11172AudioMode_audioSampling_choice, "audioSampling", NULL);

	return offset;
}



static const value_string IS11172AudioMode_multichannelType_vals[] = {
	{  0, "singleChannel" },
	{  1, "twoChannelStereo" },
	{  2, "twoChannelDual" },
	{  0, NULL }
};
static per_choice_t IS11172AudioMode_multichannelType_choice[] = {
	{  0, "singleChannel", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "twoChannelStereo", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  2, "twoChannelDual", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_IS11172AudioMode_multichannelType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_IS11172AudioMode_multichannelType, ett_h245_IS11172AudioMode_multichannelType, IS11172AudioMode_multichannelType_choice, "multichannelType", NULL);

	return offset;
}




static const value_string IS13818AudioMode_audioLayer_vals[] = {
	{  0, "audioLayer1" },
	{  1, "audioLayer2" },
	{  2, "audioLayer3" },
	{  0, NULL }
};
static per_choice_t IS13818AudioMode_audioLayer_choice[] = {
	{  0, "audioLayer1", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "audioLayer2", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  2, "audioLayer3", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_IS13818AudioMode_audioLayer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_IS13818AudioMode_audioLayer, ett_h245_IS13818AudioMode_audioLayer, IS13818AudioMode_audioLayer_choice, "audioLayer", NULL);

	return offset;
}




static const value_string IS13818AudioMode_audioSampling_vals[] = {
	{  0, "audioSampling16k" },
	{  1, "audioSampling22k05" },
	{  2, "audioSampling24k" },
	{  3, "audioSampling32k" },
	{  4, "audioSampling44k1" },
	{  5, "audioSampling48k" },
	{  0, NULL }
};
static per_choice_t IS13818AudioMode_audioSampling_choice[] = {
	{  0, "audioSampling16k", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "audioSampling22k05", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  2, "audioSampling24k", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  3, "audioSampling32k", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  4, "audioSampling44k1", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  5, "audioSampling48k", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_IS13818AudioMode_audioSampling(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_IS13818AudioMode_audioSampling, ett_h245_IS13818AudioMode_audioSampling, IS13818AudioMode_audioSampling_choice, "audioSampling", NULL);

	return offset;
}




static const value_string IS13818AudioMode_multiChannelType_vals[] = {
	{  0, "singleChannel" },
	{  1, "twoChannelStereo" },
	{  2, "twoChannelDual" },
	{  3, "threeChannels2-1" },
	{  4, "threeChannels3-0" },
	{  5, "fourChannels2-0-2-0" },
	{  6, "fourChannels2-2" },
	{  7, "fourChannels3-1" },
	{  8, "fiveChannels3-0-2-0" },
	{  9, "fiveChannels3-2" },
	{  0, NULL }
};
static per_choice_t IS13818AudioMode_multiChannelType_choice[] = {
	{  0, "singleChannel", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "twoChannelStereo", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  2, "twoChannelDual", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  3, "threeChannels2-1", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  4, "threeChannels3-0", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  5, "fourChannels2-0-2-0", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  6, "fourChannels2-2", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  7, "fourChannels3-1", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  8, "fiveChannels3-0-2-0", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  9, "fiveChannels3-2", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_IS13818AudioMode_multiChannelType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_IS13818AudioMode_multiChannelType, ett_h245_IS13818AudioMode_multiChannelType, IS13818AudioMode_multiChannelType_choice, "multiChannelType", NULL);

	return offset;
}




static const value_string MaintenanceLoopReject_cause_vals[] = {
	{  0, "canNotPerformLoop" },
	{  0, NULL }
};
static per_choice_t MaintenanceLoopReject_cause_choice[] = {
	{  0, "canNotPerformLoop", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MaintenanceLoopReject_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MaintenanceLoopReject_cause, ett_h245_MaintenanceLoopReject_cause, MaintenanceLoopReject_cause_choice, "cause", NULL);

	return offset;
}




static const value_string ConferenceResponse_makeMeChairResponse_vals[] = {
	{  0, "grantedChairToken" },
	{  1, "deniedChairToken" },
	{  0, NULL }
};
static per_choice_t ConferenceResponse_makeMeChairResponse_choice[] = {
	{  0, "grantedChairToken", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "deniedChairToken", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_makeMeChairResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_makeMeChairResponse, ett_h245_ConferenceResponse_makeMeChairResponse, ConferenceResponse_makeMeChairResponse_choice, "makeMeChairResponse", NULL);

	return offset;
}




static const value_string ConferenceResponse_broadcastMyLogicalChannelResponse_vals[] = {
	{  0, "grantedBroadcastMyLogicalChannel" },
	{  1, "deniedBroadcastMyLogicalChannel" },
	{  0, NULL }
};
static per_choice_t ConferenceResponse_broadcastMyLogicalChannelResponse_choice[] = {
	{  0, "grantedBroadcastMyLogicalChannel", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "deniedBroadcastMyLogicalChannel", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_broadcastMyLogicalChannelResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_broadcastMyLogicalChannelResponse, ett_h245_ConferenceResponse_broadcastMyLogicalChannelResponse, ConferenceResponse_broadcastMyLogicalChannelResponse_choice, "broadcastMyLogicalChannelResponse", NULL);

	return offset;
}



static const value_string ConferenceResponse_makeTerminalBroadcasterResponse_vals[] = {
	{  0, "grantedMakeTerminalBroadcaster" },
	{  1, "deniedMakeTerminalBroadcaster" },
	{  0, NULL }
};
static per_choice_t ConferenceResponse_makeTerminalBroadcasterResponse_choice[] = {
	{  0, "grantedMakeTerminalBroadcaster", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "deniedMakeTerminalBroadcaster", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_makeTerminalBroadcasterResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_makeTerminalBroadcasterResponse, ett_h245_ConferenceResponse_makeTerminalBroadcasterResponse, ConferenceResponse_makeTerminalBroadcasterResponse_choice, "makeTerminalBroadcasterResponse", NULL);

	return offset;
}




static const value_string ConferenceResponse_sendThisSourceResponse_vals[] = {
	{  0, "grantedSendThisSource" },
	{  1, "deniedSendThisSource" },
	{  0, NULL }
};
static per_choice_t ConferenceResponse_sendThisSourceResponse_choice[] = {
	{  0, "grantedSendThisSource", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "deniedSendThisSource", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_sendThisSourceResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_sendThisSourceResponse, ett_h245_ConferenceResponse_sendThisSourceResponse, ConferenceResponse_sendThisSourceResponse_choice, "sendThisSourceResponse", NULL);

	return offset;
}



static const value_string RemoteMCRequest_vals[] = {
	{  0, "masterActivate" },
	{  1, "slaveActivate" },
	{  2, "deActivate" },
	{  0, NULL }
};
static per_choice_t RemoteMCRequest_choice[] = {
	{  0, "masterActivate", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "slaveActivate", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "deActivate", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RemoteMCRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RemoteMCRequest, ett_h245_RemoteMCRequest, RemoteMCRequest_choice, "RemoteMCRequest", NULL);

	return offset;
}




static const value_string RemoteMCResponse_reject_vals[] = {
	{  0, "unspecified" },
	{  1, "functionNotSupported" },
	{  0, NULL }
};
static per_choice_t RemoteMCResponse_reject_choice[] = {
	{  0, "unspecified", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "functionNotSupported", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RemoteMCResponse_reject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RemoteMCResponse_reject, ett_h245_RemoteMCResponse_reject, RemoteMCResponse_reject_choice, "reject", NULL);

	return offset;
}




static const value_string RemoteMCResponse_vals[] = {
	{  0, "accept" },
	{  1, "reject" },
	{  0, NULL }
};
static per_choice_t RemoteMCResponse_choice[] = {
	{  0, "accept", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "reject", ASN1_EXTENSION_ROOT,
			dissect_h245_RemoteMCResponse_reject },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RemoteMCResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RemoteMCResponse, ett_h245_RemoteMCResponse, RemoteMCResponse_choice, "RemoteMCResponse", NULL);

	return offset;
}




static const value_string MultilinkResponse_addConnection_responseCode_rejected_vals[] = {
	{  0, "connectionNotAvailable" },
	{  1, "userRejected" },
	{  0, NULL }
};
static per_choice_t MultilinkResponse_addConnection_responseCode_rejected_choice[] = {
	{  0, "connectionNotAvailable", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "userRejected", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultilinkResponse_addConnection_responseCode_rejected(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultilinkResponse_addConnection_responseCode_rejected, ett_h245_MultilinkResponse_addConnection_responseCode_rejected, MultilinkResponse_addConnection_responseCode_rejected_choice, "rejected", NULL);

	return offset;
}



static const value_string MultilinkResponse_addConnection_responseCode_vals[] = {
	{  0, "accepted" },
	{  1, "rejected" },
	{  0, NULL }
};
static per_choice_t MultilinkResponse_addConnection_responseCode_choice[] = {
	{  0, "accepted", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "rejected", ASN1_EXTENSION_ROOT,
			dissect_h245_MultilinkResponse_addConnection_responseCode_rejected },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultilinkResponse_addConnection_responseCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultilinkResponse_addConnection_responseCode, ett_h245_MultilinkResponse_addConnection_responseCode, MultilinkResponse_addConnection_responseCode_choice, "responseCode", NULL);

	return offset;
}



static const value_string LogicalChannelRateRejectReason_vals[] = {
	{  0, "undefinedReason" },
	{  1, "insufficientResources" },
	{  0, NULL }
};
static per_choice_t LogicalChannelRateRejectReason_choice[] = {
	{  0, "undefinedReason", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "insufficientResources", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_LogicalChannelRateRejectReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_LogicalChannelRateRejectReason, ett_h245_LogicalChannelRateRejectReason, LogicalChannelRateRejectReason_choice, "LogicalChannelRateRejectReason", NULL);

	return offset;
}




static const value_string EndSessionCommand_gstnOptions_vals[] = {
	{  0, "telephonyMode" },
	{  1, "v8bis" },
	{  2, "v34DSVD" },
	{  3, "v34DuplexFax" },
	{  4, "v34H324" },
	{  0, NULL }
};
static per_choice_t EndSessionCommand_gstnOptions_choice[] = {
	{  0, "telephonyMode", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "v8bis", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "v34DSVD", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "v34DuplexFax", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "v34H324", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_EndSessionCommand_gstnOptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_EndSessionCommand_gstnOptions, ett_h245_EndSessionCommand_gstnOptions, EndSessionCommand_gstnOptions_choice, "gstnOptions", NULL);

	return offset;
}




static const value_string EndSessionCommand_isdnOptions_vals[] = {
	{  0, "telephonyMode" },
	{  1, "v140" },
	{  2, "terminalOnHold" },
	{  0, NULL }
};
static per_choice_t EndSessionCommand_isdnOptions_choice[] = {
	{  0, "telephonyMode", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "v140", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "terminalOnHold", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_EndSessionCommand_isdnOptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_EndSessionCommand_isdnOptions, ett_h245_EndSessionCommand_isdnOptions, EndSessionCommand_isdnOptions_choice, "isdnOptions", NULL);

	return offset;
}




static const value_string MiscellaneousCommand_type_progressiveRefinementStart_repeatCount_vals[] = {
	{  0, "doOneProgression" },
	{  1, "doContinousProgressions" },
	{  2, "doOneIndependentProgression" },
	{  3, "doContinousIndependentProgressions" },
	{  0, NULL }
};
static per_choice_t MiscellaneousCommand_type_progressiveRefinementStart_repeatCount_choice[] = {
	{  0, "doOneProgression", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "doContinousProgressions", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "doOneIndependentProgression", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "doContinousIndependentProgressions", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MiscellaneousCommand_type_progressiveRefinementStart_repeatCount(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MiscellaneousCommand_type_progressiveRefinementStart_repeatCount, ett_h245_MiscellaneousCommand_type_progressiveRefinementStart_repeatCount, MiscellaneousCommand_type_progressiveRefinementStart_repeatCount_choice, "repeatCount", NULL);

	return offset;
}



static per_sequence_t MiscellaneousCommand_type_progressiveRefinementStart_sequence[] = {
	{ "repeatCount", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MiscellaneousCommand_type_progressiveRefinementStart_repeatCount },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MiscellaneousCommand_type_progressiveRefinementStart(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MiscellaneousCommand_type_progressiveRefinementStart, ett_h245_MiscellaneousCommand_type_progressiveRefinementStart, MiscellaneousCommand_type_progressiveRefinementStart_sequence);

	return offset;
}




static const value_string H223MultiplexReconfiguration_h223ModeChange_vals[] = {
	{  0, "toLevel0" },
	{  1, "toLevel1" },
	{  2, "toLevel2" },
	{  3, "toLevel2WithOptionalHeader" },
	{  0, NULL }
};
static per_choice_t H223MultiplexReconfiguration_h223ModeChange_choice[] = {
	{  0, "toLevel0", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "toLevel1", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "toLevel2", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "toLevel2WithOptionalHeader", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223MultiplexReconfiguration_h223ModeChange(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223MultiplexReconfiguration_h223ModeChange, ett_h245_H223MultiplexReconfiguration_h223ModeChange, H223MultiplexReconfiguration_h223ModeChange_choice, "h223ModeChange", NULL);

	return offset;
}




static const value_string H223MultiplexReconfiguration_h223AnnexADoubleFlag_vals[] = {
	{  0, "start" },
	{  1, "stop" },
	{  0, NULL }
};
static per_choice_t H223MultiplexReconfiguration_h223AnnexADoubleFlag_choice[] = {
	{  0, "start", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "stop", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223MultiplexReconfiguration_h223AnnexADoubleFlag(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223MultiplexReconfiguration_h223AnnexADoubleFlag, ett_h245_H223MultiplexReconfiguration_h223AnnexADoubleFlag, H223MultiplexReconfiguration_h223AnnexADoubleFlag_choice, "h223AnnexADoubleFlag", NULL);

	return offset;
}




static const value_string H223MultiplexReconfiguration_vals[] = {
	{  0, "h233ModeChange" },
	{  1, "h223AnnexADoubleFlag" },
	{  0, NULL }
};
static per_choice_t H223MultiplexReconfiguration_choice[] = {
	{  0, "h233ModeChange", ASN1_EXTENSION_ROOT,
			dissect_h245_H223MultiplexReconfiguration_h223ModeChange },
	{  1, "h223AnnexADoubleFlag", ASN1_EXTENSION_ROOT,
			dissect_h245_H223MultiplexReconfiguration_h223AnnexADoubleFlag },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223MultiplexReconfiguration(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223MultiplexReconfiguration, ett_h245_H223MultiplexReconfiguration, H223MultiplexReconfiguration_choice, "H223MultiplexReconfiguration", NULL);

	return offset;
}




static const value_string NewATMVCCommand_aal_aal1_clockRecovery_vals[] = {
	{  0, "nullClockRecovery" },
	{  1, "srtsClockRecovery" },
	{  2, "adaptiveClockRecovery" },
	{  0, NULL }
};
static per_choice_t NewATMVCCommand_aal_aal1_clockRecovery_choice[] = {
	{  0, "nullClockRecovery", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "srtsClockRecovery", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "adaptiveClockRecovery", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NewATMVCCommand_aal_aal1_clockRecovery(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NewATMVCCommand_aal_aal1_clockRecovery, ett_h245_NewATMVCCommand_aal_aal1_clockRecovery, NewATMVCCommand_aal_aal1_clockRecovery_choice, "clockRecovery", NULL);

	return offset;
}





static const value_string NewATMVCCommand_aal_aal1_errorCorrection_vals[] = {
	{  0, "nullErrorCorrection" },
	{  1, "longInterleaver" },
	{  2, "shortInterleaver" },
	{  3, "errorCorrectionOnly" },
	{  0, NULL }
};
static per_choice_t NewATMVCCommand_aal_aal1_errorCorrection_choice[] = {
	{  0, "nullErrorCorrection", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "longInterleaver", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "shortInterleaver", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "errorCorrectionOnly", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NewATMVCCommand_aal_aal1_errorCorrection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NewATMVCCommand_aal_aal1_errorCorrection, ett_h245_NewATMVCCommand_aal_aal1_errorCorrection, NewATMVCCommand_aal_aal1_errorCorrection_choice, "errorCorrection", NULL);

	return offset;
}




static const value_string NewATMVCCommand_multiplex_vals[] = {
	{  0, "noMultiplex" },
	{  1, "transportStream" },
	{  2, "programStream" },
	{  0, NULL }
};
static per_choice_t NewATMVCCommand_multiplex_choice[] = {
	{  0, "noMultiplex", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "transportStream", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "programStream", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NewATMVCCommand_multiplex(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NewATMVCCommand_multiplex, ett_h245_NewATMVCCommand_multiplex, NewATMVCCommand_multiplex_choice, "multiplex", NULL);

	return offset;
}




static const value_string NewATMVCCommand_reverseParameters_multiplex_vals[] = {
	{  0, "noMultiplex" },
	{  1, "transportStream" },
	{  2, "programStream" },
	{  0, NULL }
};
static per_choice_t NewATMVCCommand_reverseParameters_multiplex_choice[] = {
	{  0, "noMultiplex", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "transportStream", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "programStream", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NewATMVCCommand_reverseParameters_multiplex(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NewATMVCCommand_reverseParameters_multiplex, ett_h245_NewATMVCCommand_reverseParameters_multiplex, NewATMVCCommand_reverseParameters_multiplex_choice, "multiplex", NULL);

	return offset;
}



static const value_string MobileMultilinkReconfigurationCommand_status_vals[] = {
	{  0, "synchronized" },
	{  1, "reconfiguration" },
	{  0, NULL }
};
static per_choice_t MobileMultilinkReconfigurationCommand_status_choice[] = {
	{  0, "synchronized", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "reconfiguration", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MobileMultilinkReconfigurationCommand_status(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MobileMultilinkReconfigurationCommand_status, ett_h245_MobileMultilinkReconfigurationCommand_status, MobileMultilinkReconfigurationCommand_status_choice, "status", NULL);

	return offset;
}




static const value_string FunctionNotSupported_cause_vals[] = {
	{  0, "syntaxError" },
	{  1, "semanticError" },
	{  2, "unknownFunction" },
	{  0, NULL }
};
static per_choice_t FunctionNotSupported_cause_choice[] = {
	{  0, "syntaxError", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "semanticError", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "unknownFunction", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FunctionNotSupported_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FunctionNotSupported_cause, ett_h245_FunctionNotSupported_cause, FunctionNotSupported_cause_choice, "cause", NULL);

	return offset;
}




static const value_string NewATMVCIndication_aal_aal1_clockRecovery_vals[] = {
	{  0, "nullClockRecovery" },
	{  1, "srtsClockRecovery" },
	{  2, "adaptiveClockRecovery" },
	{  0, NULL }
};
static per_choice_t NewATMVCIndication_aal_aal1_clockRecovery_choice[] = {
	{  0, "nullClockRecovery", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "srtsClockRecovery", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "adaptiveClockRecovery", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NewATMVCIndication_aal_aal1_clockRecovery(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NewATMVCIndication_aal_aal1_clockRecovery, ett_h245_NewATMVCIndication_aal_aal1_clockRecovery, NewATMVCIndication_aal_aal1_clockRecovery_choice, "clockRecovery", NULL);

	return offset;
}



static const value_string NewATMVCIndication_aal_aal1_errorCorrection_vals[] = {
	{  0, "nullErrorCorrection" },
	{  1, "longInterleaver" },
	{  2, "shortInterleaver" },
	{  3, "errorCorrectionOnly" },
	{  0, NULL }
};
static per_choice_t NewATMVCIndication_aal_aal1_errorCorrection_choice[] = {
	{  0, "nullErrorCorrection", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "longInterleaver", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "shortInterleaver", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "errorCorrectionOnly", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NewATMVCIndication_aal_aal1_errorCorrection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NewATMVCIndication_aal_aal1_errorCorrection, ett_h245_NewATMVCIndication_aal_aal1_errorCorrection, NewATMVCIndication_aal_aal1_errorCorrection_choice, "errorCorrection", NULL);

	return offset;
}




static const value_string NewATMVCIndication_multiplex_vals[] = {
	{  0, "noMultiplex" },
	{  1, "transportStream" },
	{  2, "programStream" },
	{  0, NULL }
};
static per_choice_t NewATMVCIndication_multiplex_choice[] = {
	{  0, "noMultiplex", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "transportStream", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "programStream", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NewATMVCIndication_multiplex(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NewATMVCIndication_multiplex, ett_h245_NewATMVCIndication_multiplex, NewATMVCIndication_multiplex_choice, "multiplex", NULL);

	return offset;
}




static const value_string NewATMVCIndication_reverseParameters_multiplex_vals[] = {
	{  0, "noMultiplex" },
	{  1, "transportStream" },
	{  2, "programStream" },
	{  0, NULL }
};
static per_choice_t NewATMVCIndication_reverseParameters_multiplex_choice[] = {
	{  0, "noMultiplex", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "transportStream", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "programStream", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NewATMVCIndication_reverseParameters_multiplex(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NewATMVCIndication_reverseParameters_multiplex, ett_h245_NewATMVCIndication_reverseParameters_multiplex, NewATMVCIndication_reverseParameters_multiplex_choice, "multiplex", NULL);

	return offset;
}



static int
dissect_h245_LogicalChannelNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_LogicalChannelNumber, 1, 65535,
		NULL, NULL, FALSE);
	return offset;
}

static int
dissect_h245_logicalChannelNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_LogicalChannelNumber, 0, 65535,
		NULL, NULL, FALSE);
	return offset;
}


static int
dissect_h245_SequenceNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_SequenceNumber, 0, 255,
		NULL, NULL, FALSE);
	return offset;
}




static const value_string MaintenanceLoopRequest_type_vals[] = {
	{  0, "systemLoop" },
	{  1, "mediaLoop" },
	{  2, "logicalChannelLoop" },
	{  0, NULL }
};
static per_choice_t MaintenanceLoopRequest_type_choice[] = {
	{  0, "systemLoop", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "mediaLoop", ASN1_EXTENSION_ROOT,
			dissect_h245_LogicalChannelNumber },
	{  2, "logicalChannelLoop", ASN1_EXTENSION_ROOT,
			dissect_h245_LogicalChannelNumber },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MaintenanceLoopRequest_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MaintenanceLoopRequest_type, ett_h245_MaintenanceLoopRequest_type, MaintenanceLoopRequest_type_choice, "type", NULL);

	return offset;
}




static const value_string MaintenanceLoopAck_type_vals[] = {
	{  0, "systemLoop" },
	{  1, "mediaLoop" },
	{  2, "logicalChannelLoop" },
	{  0, NULL }
};
static per_choice_t MaintenanceLoopAck_type_choice[] = {
	{  0, "systemLoop", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "mediaLoop", ASN1_EXTENSION_ROOT,
			dissect_h245_LogicalChannelNumber },
	{  2, "logicalChannelLoop", ASN1_EXTENSION_ROOT,
			dissect_h245_LogicalChannelNumber },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MaintenanceLoopAck_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MaintenanceLoopAck_type, ett_h245_MaintenanceLoopAck_type, MaintenanceLoopAck_type_choice, "type", NULL);

	return offset;
}




static const value_string MaintenanceLoopReject_type_vals[] = {
	{  0, "systemLoop" },
	{  1, "mediaLoop" },
	{  2, "logicalChannelLoop" },
	{  0, NULL }
};
static per_choice_t MaintenanceLoopReject_type_choice[] = {
	{  0, "systemLoop", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "mediaLoop", ASN1_EXTENSION_ROOT,
			dissect_h245_LogicalChannelNumber },
	{  2, "logicalChannelLoop", ASN1_EXTENSION_ROOT,
			dissect_h245_LogicalChannelNumber },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MaintenanceLoopReject_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MaintenanceLoopReject_type, ett_h245_MaintenanceLoopReject_type, MaintenanceLoopReject_type_choice, "type", NULL);

	return offset;
}




static per_sequence_t OpenLogicalChannelReject_sequence[] = {
	{ "forwardLogicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "cause", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_OpenLogicalChannelReject_cause },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_OpenLogicalChannelReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_OpenLogicalChannelReject, ett_h245_OpenLogicalChannelReject, OpenLogicalChannelReject_sequence);

	return offset;
}




static per_sequence_t CloseLogicalChannel_sequence[] = {
	{ "forwardLogicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "source", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_CloseLogicalChannel_source },
	{ "reason", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_CloseLogicalChannel_reason },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CloseLogicalChannel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CloseLogicalChannel, ett_h245_CloseLogicalChannel, CloseLogicalChannel_sequence);

	return offset;
}




static per_sequence_t CloseLogicalChannelAck_sequence[] = {
	{ "forwardLogicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CloseLogicalChannelAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CloseLogicalChannelAck, ett_h245_CloseLogicalChannelAck, CloseLogicalChannelAck_sequence);

	return offset;
}




static per_sequence_t RequestChannelCloseAck_sequence[] = {
	{ "forwardLogiclChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestChannelCloseAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestChannelCloseAck, ett_h245_RequestChannelCloseAck, RequestChannelCloseAck_sequence);

	return offset;
}




static per_sequence_t RequestChannelCloseReject_sequence[] = {
	{ "forwardLogicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "cause", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RequestChannelCloseReject_cause },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestChannelCloseReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestChannelCloseReject, ett_h245_RequestChannelCloseReject, RequestChannelCloseReject_sequence);

	return offset;
}




static per_sequence_t RequestChannelCloseRelease_sequence[] = {
	{ "forwardLogicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestChannelCloseRelease(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestChannelCloseRelease, ett_h245_RequestChannelCloseRelease, RequestChannelCloseRelease_sequence);

	return offset;
}





static per_sequence_t MultiplexedStreamModeParameters_sequence[] = {
	{ "logicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplexedStreamModeParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplexedStreamModeParameters, ett_h245_MultiplexedStreamModeParameters, MultiplexedStreamModeParameters_sequence);

	return offset;
}




static per_sequence_t MaintenanceLoopRequest_sequence[] = {
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MaintenanceLoopRequest_type },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MaintenanceLoopRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MaintenanceLoopRequest, ett_h245_MaintenanceLoopRequest, MaintenanceLoopRequest_sequence);

	return offset;
}




static per_sequence_t MaintenanceLoopAck_sequence[] = {
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MaintenanceLoopAck_type },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MaintenanceLoopAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MaintenanceLoopAck, ett_h245_MaintenanceLoopAck, MaintenanceLoopAck_sequence);

	return offset;
}



static per_sequence_t MaintenanceLoopReject_sequence[] = {
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_MaintenanceLoopReject_type },
	{ "cause", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_MaintenanceLoopReject_cause },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MaintenanceLoopReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MaintenanceLoopReject, ett_h245_MaintenanceLoopReject, MaintenanceLoopReject_sequence);

	return offset;
}



static per_sequence_t UserInputIndication_signalUpdate_rtp_sequence[] = {
	{ "logicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_LogicalChannelNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_UserInputIndication_signalUpdate_rtp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_UserInputIndication_signalUpdate_rtp, ett_h245_UserInputIndication_signalUpdate_rtp, UserInputIndication_signalUpdate_rtp_sequence);

	return offset;
}



static per_sequence_t OpenLogicalChannelConfirm_sequence[] = {
	{ "forwardLogicalChannelNumber",	ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_LogicalChannelNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_OpenLogicalChannelConfirm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_OpenLogicalChannelConfirm, ett_h245_OpenLogicalChannelConfirm, OpenLogicalChannelConfirm_sequence);

	return offset;
}



static per_sequence_t TerminalCapabilitySetAck_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_TerminalCapabilitySetAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_TerminalCapabilitySetAck, ett_h245_TerminalCapabilitySetAck, TerminalCapabilitySetAck_sequence);

	return offset;
}



static per_sequence_t RequestModeReject_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "cause", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RequestModeReject_cause },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestModeReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestModeReject, ett_h245_RequestModeReject, RequestModeReject_sequence);

	return offset;
}




static per_sequence_t RoundTripDelayRequest_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RoundTripDelayRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RoundTripDelayRequest, ett_h245_RoundTripDelayRequest, RoundTripDelayRequest_sequence);

	return offset;
}




static per_sequence_t RoundTripDelayResponse_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RoundTripDelayResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RoundTripDelayResponse, ett_h245_RoundTripDelayResponse, RoundTripDelayResponse_sequence);

	return offset;
}



static per_sequence_t MultilinkResponse_addConnection_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "responseCode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MultilinkResponse_addConnection_responseCode },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultilinkResponse_addConnection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultilinkResponse_addConnection, ett_h245_MultilinkResponse_addConnection, MultilinkResponse_addConnection_sequence);

	return offset;
}




static const true_false_string tfs_h233EncryptionTransmitCapability_bit = {
	"h233EncryptionTransmitCapability bit is SET",
	"h233EncryptionTransmitCapability bit is CLEAR"
};
static int
dissect_h245_h233EncryptionTransmitCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_h233EncryptionTransmitCapability, NULL, NULL);

	return offset;
}


static const true_false_string tfs_nullClockRecovery_bit = {
	"nullClockRecovery bit is SET",
	"nullClockRecovery bit is CLEAR"
};
static int
dissect_h245_nullClockRecovery(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_nullClockRecovery, NULL, NULL);

	return offset;
}


static const true_false_string tfs_srtsClockRecovery_bit = {
	"srtsClockRecovery bit is SET",
	"srtsClockRecovery bit is CLEAR"
};
static int
dissect_h245_srtsClockRecovery(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_srtsClockRecovery, NULL, NULL);

	return offset;
}



static const true_false_string tfs_adaptiveClockRecovery_bit = {
	"adaptiveClockRecovery bit is SET",
	"adaptiveClockRecovery bit is CLEAR"
};
static int
dissect_h245_adaptiveClockRecovery(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_adaptiveClockRecovery, NULL, NULL);

	return offset;
}




static const true_false_string tfs_nullErrorCorrection_bit = {
	"nullErrorCorrection bit is SET",
	"nullErrorCorrection bit is CLEAR"
};
static int
dissect_h245_nullErrorCorrection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_nullErrorCorrection, NULL, NULL);

	return offset;
}



static const true_false_string tfs_longInterleaver_bit = {
	"longInterleaver bit is SET",
	"longInterleaver bit is CLEAR"
};
static int
dissect_h245_longInterleaver(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_longInterleaver, NULL, NULL);

	return offset;
}



static const true_false_string tfs_shortInterleaver_bit = {
	"shortInterleaver bit is SET",
	"shortInterleaver bit is CLEAR"
};
static int
dissect_h245_shortInterleaver(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_shortInterleaver, NULL, NULL);

	return offset;
}



static const true_false_string tfs_errorCorrectionOnly_bit = {
	"errorCorrectionOnly bit is SET",
	"errorCorrectionOnly bit is CLEAR"
};
static int
dissect_h245_errorCorrectionOnly(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_errorCorrectionOnly, NULL, NULL);

	return offset;
}





static const true_false_string tfs_structuredDataTransfer_bit = {
	"structuredDataTransfer bit is SET",
	"structuredDataTransfer bit is CLEAR"
};
static int
dissect_h245_structuredDataTransfer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_structuredDataTransfer, NULL, NULL);

	return offset;
}





static const true_false_string tfs_partiallyFilledCells_bit = {
	"partiallyFilledCells bit is SET",
	"partiallyFilledCells bit is CLEAR"
};
static int
dissect_h245_partiallyFilledCells(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_partiallyFilledCells, NULL, NULL);

	return offset;
}




static per_sequence_t VCCapability_aal1_sequence[] = {
	{ "nullClockRecovery", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_nullClockRecovery },
	{ "srtsClockRecovery", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_srtsClockRecovery },
	{ "adaptiveClockRecovery", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_adaptiveClockRecovery },
	{ "nullErrorCorrection", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_nullErrorCorrection },
	{ "longInterleaver", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_longInterleaver },
	{ "shortInterleaver", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_shortInterleaver },
	{ "errorCorrectionOnly", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_errorCorrectionOnly },
	{ "structuredDataTransfer", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_structuredDataTransfer },
	{ "partiallyFilledCells", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_partiallyFilledCells },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_VCCapability_aal1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_VCCapability_aal1, ett_h245_VCCapability_aal1, VCCapability_aal1_sequence);

	return offset;
}





static per_sequence_t NewATMVCCommand_aal_aal1_sequence[] = {
	{ "clockRecovery", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCCommand_aal_aal1_clockRecovery },
	{ "errorCorrection", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCCommand_aal_aal1_errorCorrection },
	{ "structuredDataTransfer", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_structuredDataTransfer },
	{ "partiallyFilledCells", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_partiallyFilledCells },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NewATMVCCommand_aal_aal1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NewATMVCCommand_aal_aal1, ett_h245_NewATMVCCommand_aal_aal1, NewATMVCCommand_aal_aal1_sequence);

	return offset;
}



static per_sequence_t NewATMVCIndication_aal_aal1_sequence[] = {
	{ "clockRecovery", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCIndication_aal_aal1_clockRecovery },
	{ "errorCorrection", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCIndication_aal_aal1_errorCorrection },
	{ "structuredDataTransfer", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_structuredDataTransfer },
	{ "partiallyFilledCells", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_partiallyFilledCells },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NewATMVCIndication_aal_aal1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NewATMVCIndication_aal_aal1, ett_h245_NewATMVCIndication_aal_aal1, NewATMVCIndication_aal_aal1_sequence);

	return offset;
}





static const true_false_string tfs_transportStream_bit = {
	"transportStream bit is SET",
	"transportStream bit is CLEAR"
};
static int
dissect_h245_transportStream(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_transportStream, NULL, NULL);

	return offset;
}





static const true_false_string tfs_programStream_bit = {
	"programStream bit is SET",
	"programStream bit is CLEAR"
};
static int
dissect_h245_programStream(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_programStream, NULL, NULL);

	return offset;
}





static const true_false_string tfs_videoWithAL1_bit = {
	"videoWithAL1 bit is SET",
	"videoWithAL1 bit is CLEAR"
};
static int
dissect_h245_videoWithAL1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_videoWithAL1, NULL, NULL);

	return offset;
}





static const true_false_string tfs_videoWithAL2_bit = {
	"videoWithAL2 bit is SET",
	"videoWithAL2 bit is CLEAR"
};
static int
dissect_h245_videoWithAL2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_videoWithAL2, NULL, NULL);

	return offset;
}





static const true_false_string tfs_videoWithAL3_bit = {
	"videoWithAL3 bit is SET",
	"videoWithAL3 bit is CLEAR"
};
static int
dissect_h245_videoWithAL3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_videoWithAL3, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioWithAL1_bit = {
	"audioWithAL1 bit is SET",
	"audioWithAL1 bit is CLEAR"
};
static int
dissect_h245_audioWithAL1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioWithAL1, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioWithAL2_bit = {
	"audioWithAL2 bit is SET",
	"audioWithAL2 bit is CLEAR"
};
static int
dissect_h245_audioWithAL2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioWithAL2, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioWithAL3_bit = {
	"audioWithAL3 bit is SET",
	"audioWithAL3 bit is CLEAR"
};
static int
dissect_h245_audioWithAL3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioWithAL3, NULL, NULL);

	return offset;
}





static const true_false_string tfs_dataWithAL1_bit = {
	"dataWithAL1 bit is SET",
	"dataWithAL1 bit is CLEAR"
};
static int
dissect_h245_dataWithAL1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dataWithAL1, NULL, NULL);

	return offset;
}





static const true_false_string tfs_dataWithAL2_bit = {
	"dataWithAL2 bit is SET",
	"dataWithAL2 bit is CLEAR"
};
static int
dissect_h245_dataWithAL2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dataWithAL2, NULL, NULL);

	return offset;
}





static const true_false_string tfs_dataWithAL3_bit = {
	"dataWithAL3 bit is SET",
	"dataWithAL3 bit is CLEAR"
};
static int
dissect_h245_dataWithAL3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dataWithAL3, NULL, NULL);

	return offset;
}



static const true_false_string tfs_maxMUXPDUSizeCapability_bit = {
	"maxMUXPDUSizeCapability bit is SET",
	"maxMUXPDUSizeCapability bit is CLEAR"
};
static int
dissect_h245_maxMUXPDUSizeCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_maxMUXPDUSizeCapability, NULL, NULL);

	return offset;
}






static const true_false_string tfs_nsrpSupport_bit = {
	"nsrpSupport bit is SET",
	"nsrpSupport bit is CLEAR"
};
static int
dissect_h245_nsrpSupport(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_nsrpSupport, NULL, NULL);

	return offset;
}





static const true_false_string tfs_modeChangeCapability_bit = {
	"modeChangeCapability bit is SET",
	"modeChangeCapability bit is CLEAR"
};
static int
dissect_h245_modeChangeCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_modeChangeCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_h223AnnexA_bit = {
	"h223AnnexA bit is SET",
	"h223AnnexA bit is CLEAR"
};
static int
dissect_h245_h223AnnexA(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_h223AnnexA, NULL, NULL);

	return offset;
}






static const true_false_string tfs_h223AnnexADoubleFlag_bool_bit = {
	"h223AnnexADoubleFlag_bool bit is SET",
	"h223AnnexADoubleFlag_bool bit is CLEAR"
};
static int
dissect_h245_h223AnnexADoubleFlag_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_h223AnnexADoubleFlag_bool, NULL, NULL);

	return offset;
}





static const true_false_string tfs_h223AnnexB_bit = {
	"h223AnnexB bit is SET",
	"h223AnnexB bit is CLEAR"
};
static int
dissect_h245_h223AnnexB(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_h223AnnexB, NULL, NULL);

	return offset;
}





static const true_false_string tfs_h223AnnexBwithHeader_bit = {
	"h223AnnexBwithHeader bit is SET",
	"h223AnnexBwithHeader bit is CLEAR"
};
static int
dissect_h245_h223AnnexBwithHeader(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_h223AnnexBwithHeader, NULL, NULL);

	return offset;
}



static per_sequence_t H223Capability_mobileOperationTransmitCapability_sequence[] = {
	{ "modeChangeCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_modeChangeCapability },
	{ "h223AnnexA", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_h223AnnexA },
	{ "h223AnnexADoubleFlag", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_h223AnnexADoubleFlag_bool },
	{ "h223AnnexB", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_h223AnnexB },
	{ "h223AnnexBwithHeader", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_h223AnnexBwithHeader },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223Capability_mobileOperationTransmitCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223Capability_mobileOperationTransmitCapability, ett_h245_H223Capability_mobileOperationTransmitCapability, H223Capability_mobileOperationTransmitCapability_sequence);

	return offset;
}





static const true_false_string tfs_videoWithAL1M_bit = {
	"videoWithAL1M bit is SET",
	"videoWithAL1M bit is CLEAR"
};
static int
dissect_h245_videoWithAL1M(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_videoWithAL1M, NULL, NULL);

	return offset;
}




static const true_false_string tfs_videoWithAL2M_bit = {
	"videoWithAL2M bit is SET",
	"videoWithAL2M bit is CLEAR"
};
static int
dissect_h245_videoWithAL2M(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_videoWithAL2M, NULL, NULL);

	return offset;
}





static const true_false_string tfs_videoWithAL3M_bit = {
	"videoWithAL3M bit is SET",
	"videoWithAL3M bit is CLEAR"
};
static int
dissect_h245_videoWithAL3M(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_videoWithAL3M, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioWithAL1M_bit = {
	"audioWithAL1M bit is SET",
	"audioWithAL1M bit is CLEAR"
};
static int
dissect_h245_audioWithAL1M(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioWithAL1M, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioWithAL2M_bit = {
	"audioWithAL2M bit is SET",
	"audioWithAL2M bit is CLEAR"
};
static int
dissect_h245_audioWithAL2M(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioWithAL2M, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioWithAL3M_bit = {
	"audioWithAL3M bit is SET",
	"audioWithAL3M bit is CLEAR"
};
static int
dissect_h245_audioWithAL3M(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioWithAL3M, NULL, NULL);

	return offset;
}





static const true_false_string tfs_dataWithAL1M_bit = {
	"dataWithAL1M bit is SET",
	"dataWithAL1M bit is CLEAR"
};
static int
dissect_h245_dataWithAL1M(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dataWithAL1M, NULL, NULL);

	return offset;
}





static const true_false_string tfs_dataWithAL2M_bit = {
	"dataWithAL2M bit is SET",
	"dataWithAL2M bit is CLEAR"
};
static int
dissect_h245_dataWithAL2M(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dataWithAL2M, NULL, NULL);

	return offset;
}





static const true_false_string tfs_dataWithAL3M_bit = {
	"dataWithAL3M bit is SET",
	"dataWithAL3M bit is CLEAR"
};
static int
dissect_h245_dataWithAL3M(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dataWithAL3M, NULL, NULL);

	return offset;
}





static const true_false_string tfs_alpduInterleaving_bit = {
	"alpduInterleaving bit is SET",
	"alpduInterleaving bit is CLEAR"
};
static int
dissect_h245_alpduInterleaving(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_alpduInterleaving, NULL, NULL);

	return offset;
}



static per_sequence_t H223AL2MParameters_sequence[] = {
	{ "headerFEC", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223AL2MParameters_headerFEC },
	{ "alpduInterleaving", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_alpduInterleaving },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223AL2MParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223AL2MParameters, ett_h245_H223AL2MParameters, H223AL2MParameters_sequence);

	return offset;
}





static const true_false_string tfs_rsCodeCapability_bit = {
	"rsCodeCapability bit is SET",
	"rsCodeCapability bit is CLEAR"
};
static int
dissect_h245_rsCodeCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_rsCodeCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_suspendResumeCapabilitywAddress_bit = {
	"suspendResumeCapabilitywAddress bit is SET",
	"suspendResumeCapabilitywAddress bit is CLEAR"
};
static int
dissect_h245_suspendResumeCapabilitywAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_suspendResumeCapabilitywAddress, NULL, NULL);

	return offset;
}





static const true_false_string tfs_suspendResumeCapabilitywoAddress_bit = {
	"suspendResumeCapabilitywoAddress bit is SET",
	"suspendResumeCapabilitywoAddress bit is CLEAR"
};
static int
dissect_h245_suspendResumeCapabilitywoAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_suspendResumeCapabilitywoAddress, NULL, NULL);

	return offset;
}





static const true_false_string tfs_rejCapability_bit = {
	"rejCapability bit is SET",
	"rejCapability bit is CLEAR"
};
static int
dissect_h245_rejCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_rejCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_sREJCapability_bit = {
	"sREJCapability bit is SET",
	"sREJCapability bit is CLEAR"
};
static int
dissect_h245_sREJCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_sREJCapability, NULL, NULL);

	return offset;
}






static const true_false_string tfs_mREJCapability_bit = {
	"mREJCapability bit is SET",
	"mREJCapability bit is CLEAR"
};
static int
dissect_h245_mREJCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_mREJCapability, NULL, NULL);

	return offset;
}






static const true_false_string tfs_crc8bitCapability_bit = {
	"crc8bitCapability bit is SET",
	"crc8bitCapability bit is CLEAR"
};
static int
dissect_h245_crc8bitCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_crc8bitCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_crc16bitCapability_bit = {
	"crc16bitCapability bit is SET",
	"crc16bitCapability bit is CLEAR"
};
static int
dissect_h245_crc16bitCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_crc16bitCapability, NULL, NULL);

	return offset;
}






static const true_false_string tfs_crc32bitCapability_bit = {
	"crc32bitCapability bit is SET",
	"crc32bitCapability bit is CLEAR"
};
static int
dissect_h245_crc32bitCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_crc32bitCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_uihCapability_bit = {
	"uihCapability bit is SET",
	"uihCapability bit is CLEAR"
};
static int
dissect_h245_uihCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_uihCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_twoOctetAddressFieldCapability_bit = {
	"twoOctetAddressFieldCapability bit is SET",
	"twoOctetAddressFieldCapability bit is CLEAR"
};
static int
dissect_h245_twoOctetAddressFieldCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_twoOctetAddressFieldCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_loopBackTestCapability_bit = {
	"loopBackTestCapability bit is SET",
	"loopBackTestCapability bit is CLEAR"
};
static int
dissect_h245_loopBackTestCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_loopBackTestCapability, NULL, NULL);

	return offset;
}






static const true_false_string tfs_audioHeader_bit = {
	"audioHeader bit is SET",
	"audioHeader bit is CLEAR"
};
static int
dissect_h245_audioHeader(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioHeader, NULL, NULL);

	return offset;
}



static per_sequence_t V75Capability_sequence[] = {
	{ "audioHeader", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioHeader },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_V75Capability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_V75Capability, ett_h245_V75Capability, V75Capability_sequence);

	return offset;
}





static const true_false_string tfs_centralizedConferenceMC_bit = {
	"centralizedConferenceMC bit is SET",
	"centralizedConferenceMC bit is CLEAR"
};
static int
dissect_h245_centralizedConferenceMC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_centralizedConferenceMC, NULL, NULL);

	return offset;
}





static const true_false_string tfs_decentralizedConferenceMC_bit = {
	"decentralizedConferenceMC bit is SET",
	"decentralizedConferenceMC bit is CLEAR"
};
static int
dissect_h245_decentralizedConferenceMC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_decentralizedConferenceMC, NULL, NULL);

	return offset;
}




static per_sequence_t H2250Capability_mcCapability_sequence[] = {
	{ "centralizedConferenceMC", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_centralizedConferenceMC },
	{ "decentralizedConferenceMC", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_decentralizedConferenceMC },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H2250Capability_mcCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H2250Capability_mcCapability, ett_h245_H2250Capability_mcCapability, H2250Capability_mcCapability_sequence);

	return offset;
}





static const true_false_string tfs_rtcpVideoControlCapability_bit = {
	"rtcpVideoControlCapability bit is SET",
	"rtcpVideoControlCapability bit is CLEAR"
};
static int
dissect_h245_rtcpVideoControlCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_rtcpVideoControlCapability, NULL, NULL);

	return offset;
}






static const true_false_string tfs_logicalChannelSwitchingCapability_bit = {
	"logicalChannelSwitchingCapability bit is SET",
	"logicalChannelSwitchingCapability bit is CLEAR"
};
static int
dissect_h245_logicalChannelSwitchingCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_logicalChannelSwitchingCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_t120DynamicPortCapability_bit = {
	"t120DynamicPortCapability bit is SET",
	"t120DynamicPortCapability bit is CLEAR"
};
static int
dissect_h245_t120DynamicPortCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_t120DynamicPortCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_h261aVideoPacketization_bit = {
	"h261aVideoPacketization bit is SET",
	"h261aVideoPacketization bit is CLEAR"
};
static int
dissect_h245_h261aVideoPacketization(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_h261aVideoPacketization, NULL, NULL);

	return offset;
}





static const true_false_string tfs_atmUBR_bit = {
	"atmUBR bit is SET",
	"atmUBR bit is CLEAR"
};
static int
dissect_h245_atmUBR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_atmUBR, NULL, NULL);

	return offset;
}




static const true_false_string tfs_atmrtVBR_bit = {
	"atmrtVBR bit is SET",
	"atmrtVBR bit is CLEAR"
};
static int
dissect_h245_atmrtVBR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_atmrtVBR, NULL, NULL);

	return offset;
}





static const true_false_string tfs_atmnrtVBR_bit = {
	"atmnrtVBR bit is SET",
	"atmnrtVBR bit is CLEAR"
};
static int
dissect_h245_atmnrtVBR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_atmnrtVBR, NULL, NULL);

	return offset;
}





static const true_false_string tfs_atmABR_bit = {
	"atmABR bit is SET",
	"atmABR bit is CLEAR"
};
static int
dissect_h245_atmABR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_atmABR, NULL, NULL);

	return offset;
}






static const true_false_string tfs_atmCBR_bit = {
	"atmCBR bit is SET",
	"atmCBR bit is CLEAR"
};
static int
dissect_h245_atmCBR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_atmCBR, NULL, NULL);

	return offset;
}





static const true_false_string tfs_variableDelta_bit = {
	"variableDelta bit is SET",
	"variableDelta bit is CLEAR"
};
static int
dissect_h245_variableDelta(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_variableDelta, NULL, NULL);

	return offset;
}



static per_sequence_t MediaTransportType_AtmAAL5Compressed_sequence[] = {
	{ "variable-delta", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_variableDelta },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MediaTransportType_AtmAAL5Compressed(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MediaTransportType_AtmAAL5Compressed, ett_h245_MediaTransportType_AtmAAL5Compressed, MediaTransportType_AtmAAL5Compressed_sequence);

	return offset;
}




static const value_string MediaTransportType_vals[] = {
	{  0, "ip-UDP" },
	{  1, "ip-TCP" },
	{  2, "atm-AAL5-UNIDIR" },
	{  3, "atm-AAL5-BIDIR" },
	{  4, "atm-AAL5-compressed" },
	{  0, NULL }
};
static per_choice_t MediaTransportType_choice[] = {
	{  0, "ip-UDP", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "ip-TCP", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "atm-AAL5-UNIDIR", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "atm-AAL5-BIDIR", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "atm-AAL5-compressed", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_MediaTransportType_AtmAAL5Compressed },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MediaTransportType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MediaTransportType, ett_h245_MediaTransportType, MediaTransportType_choice, "MediaTransportType", NULL);

	return offset;
}



static per_sequence_t MediaChannelCapability_sequence[] = {
	{ "mediaTransport", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_MediaTransportType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MediaChannelCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MediaChannelCapability, ett_h245_MediaChannelCapability, MediaChannelCapability_sequence);

	return offset;
}





static const true_false_string tfs_multicastCapability_bit = {
	"multicastCapability bit is SET",
	"multicastCapability bit is CLEAR"
};
static int
dissect_h245_multicastCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_multicastCapability, NULL, NULL);

	return offset;
}






static const true_false_string tfs_multiUniCastConference_bit = {
	"multiUniCastConference bit is SET",
	"multiUniCastConference bit is CLEAR"
};
static int
dissect_h245_multiUniCastConference(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_multiUniCastConference, NULL, NULL);

	return offset;
}





static const true_false_string tfs_centralizedControl_bit = {
	"centralizedControl bit is SET",
	"centralizedControl bit is CLEAR"
};
static int
dissect_h245_centralizedControl(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_centralizedControl, NULL, NULL);

	return offset;
}





static const true_false_string tfs_distributedControl_bit = {
	"distributedControl bit is SET",
	"distributedControl bit is CLEAR"
};
static int
dissect_h245_distributedControl(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_distributedControl, NULL, NULL);

	return offset;
}





static const true_false_string tfs_centralizedAudio_bit = {
	"centralizedAudio bit is SET",
	"centralizedAudio bit is CLEAR"
};
static int
dissect_h245_centralizedAudio(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_centralizedAudio, NULL, NULL);

	return offset;
}





static const true_false_string tfs_distributedAudio_bit = {
	"distributedAudio bit is SET",
	"distributedAudio bit is CLEAR"
};
static int
dissect_h245_distributedAudio(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_distributedAudio, NULL, NULL);

	return offset;
}





static const true_false_string tfs_centralizedVideo_bit = {
	"centralizedVideo bit is SET",
	"centralizedVideo bit is CLEAR"
};
static int
dissect_h245_centralizedVideo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_centralizedVideo, NULL, NULL);

	return offset;
}




static const true_false_string tfs_distributedVideo_bit = {
	"distributedVideo bit is SET",
	"distributedVideo bit is CLEAR"
};
static int
dissect_h245_distributedVideo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_distributedVideo, NULL, NULL);

	return offset;
}






static const true_false_string tfs_temporalSpatialTradeOffCapability_bit = {
	"temporalSpatialTradeOffCapability bit is SET",
	"temporalSpatialTradeOffCapability bit is CLEAR"
};
static int
dissect_h245_temporalSpatialTradeOffCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_temporalSpatialTradeOffCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_stillImageTransmission_bit = {
	"stillImageTransmission bit is SET",
	"stillImageTransmission bit is CLEAR"
};
static int
dissect_h245_stillImageTransmission(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_stillImageTransmission, NULL, NULL);

	return offset;
}





static const true_false_string tfs_videoBadMBsCap_bit = {
	"videoBadMBsCap bit is SET",
	"videoBadMBsCap bit is CLEAR"
};
static int
dissect_h245_videoBadMBsCap(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_videoBadMBsCap, NULL, NULL);

	return offset;
}





static const true_false_string tfs_profileAndLevelSPatML_bit = {
	"profileAndLevelSPatML bit is SET",
	"profileAndLevelSPatML bit is CLEAR"
};
static int
dissect_h245_profileAndLevelSPatML(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelSPatML, NULL, NULL);

	return offset;
}





static const true_false_string tfs_profileAndLevelMPatLL_bit = {
	"profileAndLevelMPatLL bit is SET",
	"profileAndLevelMPatLL bit is CLEAR"
};
static int
dissect_h245_profileAndLevelMPatLL(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelMPatLL, NULL, NULL);

	return offset;
}





static const true_false_string tfs_profileAndLevelMPatML_bit = {
	"profileAndLevelMPatML bit is SET",
	"profileAndLevelMPatML bit is CLEAR"
};
static int
dissect_h245_profileAndLevelMPatML(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelMPatML, NULL, NULL);

	return offset;
}





static const true_false_string tfs_profileAndLevelMPatH14_bit = {
	"profileAndLevelMPatH14 bit is SET",
	"profileAndLevelMPatH14 bit is CLEAR"
};
static int
dissect_h245_profileAndLevelMPatH14(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelMPatH14, NULL, NULL);

	return offset;
}





static const true_false_string tfs_profileAndLevelMPatHL_bit = {
	"profileAndLevelMPatHL bit is SET",
	"profileAndLevelMPatHL bit is CLEAR"
};
static int
dissect_h245_profileAndLevelMPatHL(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelMPatHL, NULL, NULL);

	return offset;
}





static const true_false_string tfs_profileAndLevelSNRatLL_bit = {
	"profileAndLevelSNRatLL bit is SET",
	"profileAndLevelSNRatLL bit is CLEAR"
};
static int
dissect_h245_profileAndLevelSNRatLL(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelSNRatLL, NULL, NULL);

	return offset;
}





static const true_false_string tfs_profileAndLevelSNRatML_bit = {
	"profileAndLevelSNRatML bit is SET",
	"profileAndLevelSNRatML bit is CLEAR"
};
static int
dissect_h245_profileAndLevelSNRatML(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelSNRatML, NULL, NULL);

	return offset;
}





static const true_false_string tfs_profileAndLevelSpatialatH14_bit = {
	"profileAndLevelSpatialatH14 bit is SET",
	"profileAndLevelSpatialatH14 bit is CLEAR"
};
static int
dissect_h245_profileAndLevelSpatialatH14(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelSpatialatH14, NULL, NULL);

	return offset;
}





static const true_false_string tfs_profileAndLevelHPatML_bit = {
	"profileAndLevelHPatML bit is SET",
	"profileAndLevelHPatML bit is CLEAR"
};
static int
dissect_h245_profileAndLevelHPatML(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelHPatML, NULL, NULL);

	return offset;
}




static const true_false_string tfs_profileAndLevelHPatH14_bit = {
	"profileAndLevelHPatH14 bit is SET",
	"profileAndLevelHPatH14 bit is CLEAR"
};
static int
dissect_h245_profileAndLevelHPatH14(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelHPatH14, NULL, NULL);

	return offset;
}





static const true_false_string tfs_profileAndLevelHPatHL_bit = {
	"profileAndLevelHPatHL bit is SET",
	"profileAndLevelHPatHL bit is CLEAR"
};
static int
dissect_h245_profileAndLevelHPatHL(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_profileAndLevelHPatHL, NULL, NULL);

	return offset;
}





static const true_false_string tfs_unrestrictedVector_bit = {
	"unrestrictedVector bit is SET",
	"unrestrictedVector bit is CLEAR"
};
static int
dissect_h245_unrestrictedVector(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_unrestrictedVector, NULL, NULL);

	return offset;
}





static const true_false_string tfs_arithmeticCoding_bit = {
	"arithmeticCoding bit is SET",
	"arithmeticCoding bit is CLEAR"
};
static int
dissect_h245_arithmeticCoding(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_arithmeticCoding, NULL, NULL);

	return offset;
}





static const true_false_string tfs_advancedPrediction_bit = {
	"advancedPrediction bit is SET",
	"advancedPrediction bit is CLEAR"
};
static int
dissect_h245_advancedPrediction(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_advancedPrediction, NULL, NULL);

	return offset;
}





static const true_false_string tfs_pbFrames_bit = {
	"pbFrames bit is SET",
	"pbFrames bit is CLEAR"
};
static int
dissect_h245_pbFrames(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_pbFrames, NULL, NULL);

	return offset;
}





static const true_false_string tfs_errorCompensation_bit = {
	"errorCompensation bit is SET",
	"errorCompensation bit is CLEAR"
};
static int
dissect_h245_errorCompensation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_errorCompensation, NULL, NULL);

	return offset;
}






static const true_false_string tfs_baseBitRateConstrained_bit = {
	"baseBitRateConstrained bit is SET",
	"baseBitRateConstrained bit is CLEAR"
};
static int
dissect_h245_baseBitRateConstrained(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_baseBitRateConstrained, NULL, NULL);

	return offset;
}





static const true_false_string tfs_advancedIntraCodingMode_bit = {
	"advancedIntraCodingMode bit is SET",
	"advancedIntraCodingMode bit is CLEAR"
};
static int
dissect_h245_advancedIntraCodingMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_advancedIntraCodingMode, NULL, NULL);

	return offset;
}




static const true_false_string tfs_deblockingFilterMode_bit = {
	"deblockingFilterMode bit is SET",
	"deblockingFilterMode bit is CLEAR"
};
static int
dissect_h245_deblockingFilterMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_deblockingFilterMode, NULL, NULL);

	return offset;
}





static const true_false_string tfs_improvedPBFramesMode_bit = {
	"improvedPBFramesMode bit is SET",
	"improvedPBFramesMode bit is CLEAR"
};
static int
dissect_h245_improvedPBFramesMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_improvedPBFramesMode, NULL, NULL);

	return offset;
}




static const true_false_string tfs_unlimitedMotionVectors_bit = {
	"unlimitedMotionVectors bit is SET",
	"unlimitedMotionVectors bit is CLEAR"
};
static int
dissect_h245_unlimitedMotionVectors(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_unlimitedMotionVectors, NULL, NULL);

	return offset;
}





static const true_false_string tfs_fullPictureFreeze_bit = {
	"fullPictureFreeze bit is SET",
	"fullPictureFreeze bit is CLEAR"
};
static int
dissect_h245_fullPictureFreeze(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_fullPictureFreeze, NULL, NULL);

	return offset;
}





static const true_false_string tfs_partialPictureFreezeAndRelease_bit = {
	"partialPictureFreezeAndRelease bit is SET",
	"partialPictureFreezeAndRelease bit is CLEAR"
};
static int
dissect_h245_partialPictureFreezeAndRelease(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_partialPictureFreezeAndRelease, NULL, NULL);

	return offset;
}




static const true_false_string tfs_resizingPartPicFreezeAndRelease_bit = {
	"resizingPartPicFreezeAndRelease bit is SET",
	"resizingPartPicFreezeAndRelease bit is CLEAR"
};
static int
dissect_h245_resizingPartPicFreezeAndRelease(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_resizingPartPicFreezeAndRelease, NULL, NULL);

	return offset;
}




static const true_false_string tfs_fullPictureSnapshot_bit = {
	"fullPictureSnapshot bit is SET",
	"fullPictureSnapshot bit is CLEAR"
};
static int
dissect_h245_fullPictureSnapshot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_fullPictureSnapshot, NULL, NULL);

	return offset;
}





static const true_false_string tfs_partialPictureSnapshot_bit = {
	"partialPictureSnapshot bit is SET",
	"partialPictureSnapshot bit is CLEAR"
};
static int
dissect_h245_partialPictureSnapshot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_partialPictureSnapshot, NULL, NULL);

	return offset;
}




static const true_false_string tfs_videoSegmentTagging_bit = {
	"videoSegmentTagging bit is SET",
	"videoSegmentTagging bit is CLEAR"
};
static int
dissect_h245_videoSegmentTagging(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_videoSegmentTagging, NULL, NULL);

	return offset;
}





static const true_false_string tfs_progressiveRefinement_bit = {
	"progressiveRefinement bit is SET",
	"progressiveRefinement bit is CLEAR"
};
static int
dissect_h245_progressiveRefinement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_progressiveRefinement, NULL, NULL);

	return offset;
}





static const true_false_string tfs_dynamicPictureResizingByFour_bit = {
	"dynamicPictureResizingByFour bit is SET",
	"dynamicPictureResizingByFour bit is CLEAR"
};
static int
dissect_h245_dynamicPictureResizingByFour(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dynamicPictureResizingByFour, NULL, NULL);

	return offset;
}




static const true_false_string tfs_dynamicPictureResizingSixteenthPel_bit = {
	"dynamicPictureResizingSixteenthPel bit is SET",
	"dynamicPictureResizingSixteenthPel bit is CLEAR"
};
static int
dissect_h245_dynamicPictureResizingSixteenthPel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dynamicPictureResizingSixteenthPel, NULL, NULL);

	return offset;
}





static const true_false_string tfs_dynamicWarpingHalfPel_bit = {
	"dynamicWarpingHalfPel bit is SET",
	"dynamicWarpingHalfPel bit is CLEAR"
};
static int
dissect_h245_dynamicWarpingHalfPel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dynamicWarpingHalfPel, NULL, NULL);

	return offset;
}





static const true_false_string tfs_dynamicWarpingSixteenthPel_bit = {
	"dynamicWarpingSixteenthPel bit is SET",
	"dynamicWarpingSixteenthPel bit is CLEAR"
};
static int
dissect_h245_dynamicWarpingSixteenthPel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dynamicWarpingSixteenthPel, NULL, NULL);

	return offset;
}





static const true_false_string tfs_independentSegmentDecoding_bit = {
	"independentSegmentDecoding bit is SET",
	"independentSegmentDecoding bit is CLEAR"
};
static int
dissect_h245_independentSegmentDecoding(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_independentSegmentDecoding, NULL, NULL);

	return offset;
}





static const true_false_string tfs_slicesInOrderNonRect_bit = {
	"slicesInOrderNonRect bit is SET",
	"slicesInOrderNonRect bit is CLEAR"
};
static int
dissect_h245_slicesInOrderNonRect(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_slicesInOrderNonRect, NULL, NULL);

	return offset;
}





static const true_false_string tfs_slicesInOrderRect_bit = {
	"slicesInOrderRect bit is SET",
	"slicesInOrderRect bit is CLEAR"
};
static int
dissect_h245_slicesInOrderRect(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_slicesInOrderRect, NULL, NULL);

	return offset;
}





static const true_false_string tfs_slicesNoOrderNonRect_bit = {
	"slicesNoOrderNonRect bit is SET",
	"slicesNoOrderNonRect bit is CLEAR"
};
static int
dissect_h245_slicesNoOrderNonRect(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_slicesNoOrderNonRect, NULL, NULL);

	return offset;
}





static const true_false_string tfs_slicesNoOrderRect_bit = {
	"slicesNoOrderRect bit is SET",
	"slicesNoOrderRect bit is CLEAR"
};
static int
dissect_h245_slicesNoOrderRect(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_slicesNoOrderRect, NULL, NULL);

	return offset;
}





static const true_false_string tfs_alternateInterVLCMode_bit = {
	"alternateInterVLCMode bit is SET",
	"alternateInterVLCMode bit is CLEAR"
};
static int
dissect_h245_alternateInterVLCMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_alternateInterVLCMode, NULL, NULL);

	return offset;
}





static const true_false_string tfs_modifiedQuantizationMode_bit = {
	"modifiedQuantizationMode bit is SET",
	"modifiedQuantizationMode bit is CLEAR"
};
static int
dissect_h245_modifiedQuantizationMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_modifiedQuantizationMode, NULL, NULL);

	return offset;
}





static const true_false_string tfs_reducedResolutionUpdate_bit = {
	"reducedResolutionUpdate bit is SET",
	"reducedResolutionUpdate bit is CLEAR"
};
static int
dissect_h245_reducedResolutionUpdate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_reducedResolutionUpdate, NULL, NULL);

	return offset;
}





static const true_false_string tfs_separateVideoBackChannel_bit = {
	"separateVideoBackChannel bit is SET",
	"separateVideoBackChannel bit is CLEAR"
};
static int
dissect_h245_separateVideoBackChannel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_separateVideoBackChannel, NULL, NULL);

	return offset;
}





static const true_false_string tfs_videoMux_bit = {
	"videoMux bit is SET",
	"videoMux bit is CLEAR"
};
static int
dissect_h245_videoMux(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_videoMux, NULL, NULL);

	return offset;
}





static const true_false_string tfs_anyPixelAspectRatio_bit = {
	"anyPixelAspectRatio bit is SET",
	"anyPixelAspectRatio bit is CLEAR"
};
static int
dissect_h245_anyPixelAspectRatio(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_anyPixelAspectRatio, NULL, NULL);

	return offset;
}





static const true_false_string tfs_referencePicSelect_bit = {
	"referencePicSelect bit is SET",
	"referencePicSelect bit is CLEAR"
};
static int
dissect_h245_referencePicSelect(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_referencePicSelect, NULL, NULL);

	return offset;
}





static const true_false_string tfs_enhancedReferencePicSelect_bool_bit = {
	"enhancedReferencePicSelect_bool bit is SET",
	"enhancedReferencePicSelect_bool bit is CLEAR"
};
static int
dissect_h245_enhancedReferencePicSelect_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_enhancedReferencePicSelect_bool, NULL, NULL);

	return offset;
}





static const true_false_string tfs_dataPartitionedSlices_bit = {
	"dataPartitionedSlices bit is SET",
	"dataPartitionedSlices bit is CLEAR"
};
static int
dissect_h245_dataPartitionedSlices(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_dataPartitionedSlices, NULL, NULL);

	return offset;
}





static const true_false_string tfs_fixedPointIDCT0_bit = {
	"fixedPointIDCT0 bit is SET",
	"fixedPointIDCT0 bit is CLEAR"
};
static int
dissect_h245_fixedPointIDCT0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_fixedPointIDCT0, NULL, NULL);

	return offset;
}





static const true_false_string tfs_interlacedFields_bit = {
	"interlacedFields bit is SET",
	"interlacedFields bit is CLEAR"
};
static int
dissect_h245_interlacedFields(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_interlacedFields, NULL, NULL);

	return offset;
}





static const true_false_string tfs_currentPictureHeaderRepetition_bit = {
	"currentPictureHeaderRepetition bit is SET",
	"currentPictureHeaderRepetition bit is CLEAR"
};
static int
dissect_h245_currentPictureHeaderRepetition(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_currentPictureHeaderRepetition, NULL, NULL);

	return offset;
}





static const true_false_string tfs_previousPictureHeaderRepetition_bit = {
	"previousPictureHeaderRepetition bit is SET",
	"previousPictureHeaderRepetition bit is CLEAR"
};
static int
dissect_h245_previousPictureHeaderRepetition(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_previousPictureHeaderRepetition, NULL, NULL);

	return offset;
}





static const true_false_string tfs_nextPictureHeaderRepetition_bit = {
	"nextPictureHeaderRepetition bit is SET",
	"nextPictureHeaderRepetition bit is CLEAR"
};
static int
dissect_h245_nextPictureHeaderRepetition(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_nextPictureHeaderRepetition, NULL, NULL);

	return offset;
}





static const true_false_string tfs_pictureNumber_bool_bit = {
	"pictureNumber_bool bit is SET",
	"pictureNumber_bool bit is CLEAR"
};
static int
dissect_h245_pictureNumber_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_pictureNumber_bool, NULL, NULL);

	return offset;
}





static const true_false_string tfs_spareReferencePictures_bit = {
	"spareReferencePictures bit is SET",
	"spareReferencePictures bit is CLEAR"
};
static int
dissect_h245_spareReferencePictures(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_spareReferencePictures, NULL, NULL);

	return offset;
}



static per_sequence_t H263Version3Options_sequence[] = {
	{ "dataPartitionedSlices", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dataPartitionedSlices },
	{ "fixedPointIDCTO", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_fixedPointIDCT0 },
	{ "interlacedFields", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_interlacedFields},
	{ "currentPictureHeaderRepetition", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_currentPictureHeaderRepetition },
	{ "previousPictureHeaderRepetition", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_previousPictureHeaderRepetition },
	{ "nextPictureHeaderRepetition", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_nextPictureHeaderRepetition },
	{ "pictureNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_pictureNumber_bool },
	{ "spareReferencePictures", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_spareReferencePictures },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H263Version3Options(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H263Version3Options, ett_h245_H263Version3Options, H263Version3Options_sequence);

	return offset;
}





static per_sequence_t H263ModeComboFlags_sequence[] = {
	{ "unrestrictedVector", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_unrestrictedVector },
	{ "arithmeticCoding", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_arithmeticCoding },
	{ "advancedPrediction", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_advancedPrediction },
	{ "pbFrames", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_pbFrames },
	{ "advancedIntraCodingMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_advancedIntraCodingMode },
	{ "deblockingFilterMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_deblockingFilterMode },
	{ "unlimitedMotionVectors", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_unlimitedMotionVectors },
	{ "slicesInOrder-NonRect", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_slicesInOrderNonRect },
	{ "slicesInOrder-Rect", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_slicesInOrderRect },
	{ "slicesNoOrder-NonRect", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_slicesNoOrderNonRect },
	{ "slicesNoOrder-Rect", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_slicesNoOrderRect },
	{ "improvedPBFramesMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_improvedPBFramesMode },
	{ "referencePicSelect", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_referencePicSelect },
	{ "dynamicPictureResizingByFour", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dynamicPictureResizingByFour },
	{ "dynamicPictureResizingSixteenthPel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dynamicPictureResizingSixteenthPel },
	{ "dynamicWarpingHalfPel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dynamicWarpingHalfPel },
	{ "dynamicWarpingSixteenthPel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dynamicWarpingSixteenthPel },
	{ "reducedResolutionUpdate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_reducedResolutionUpdate },
	{ "independentSegmentDecoding", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_independentSegmentDecoding },
	{ "alternateInterVLCMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_alternateInterVLCMode },
	{ "modifiedQuantizationMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_modifiedQuantizationMode },
	{ "enhancedReferencePicSelect", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_enhancedReferencePicSelect_bool },
	{ "h263Version3Options", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H263Version3Options },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H263ModeComboFlags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H263ModeComboFlags, ett_h245_H263ModeComboFlags, H263ModeComboFlags_sequence);

	return offset;
}





static const true_false_string tfs_constrainedBitstream_bit = {
	"constrainedBitstream bit is SET",
	"constrainedBitstream bit is CLEAR"
};
static int
dissect_h245_constrainedBitstream(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_constrainedBitstream, NULL, NULL);

	return offset;
}





static const true_false_string tfs_silenceSuppression_bit = {
	"silenceSuppression bit is SET",
	"silenceSuppression bit is CLEAR"
};
static int
dissect_h245_silenceSuppression(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_silenceSuppression, NULL, NULL);

	return offset;
}





static const true_false_string tfs_annexA_bit = {
	"annexA bit is SET",
	"annexA bit is CLEAR"
};
static int
dissect_h245_annexA(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_annexA, NULL, NULL);

	return offset;
}





static const true_false_string tfs_annexB_bit = {
	"annexB bit is SET",
	"annexB bit is CLEAR"
};
static int
dissect_h245_annexB(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_annexB, NULL, NULL);

	return offset;
}





static const true_false_string tfs_annexD_bit = {
	"annexD bit is SET",
	"annexD bit is CLEAR"
};
static int
dissect_h245_annexD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_annexD, NULL, NULL);

	return offset;
}





static const true_false_string tfs_annexE_bit = {
	"annexE bit is SET",
	"annexE bit is CLEAR"
};
static int
dissect_h245_annexE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_annexE, NULL, NULL);

	return offset;
}





static const true_false_string tfs_annexF_bit = {
	"annexF bit is SET",
	"annexF bit is CLEAR"
};
static int
dissect_h245_annexF(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_annexF, NULL, NULL);

	return offset;
}





static const true_false_string tfs_annexG_bit = {
	"annexG bit is SET",
	"annexG bit is CLEAR"
};
static int
dissect_h245_annexG(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_annexG, NULL, NULL);

	return offset;
}





static const true_false_string tfs_annexH_bit = {
	"annexH bit is SET",
	"annexH bit is CLEAR"
};
static int
dissect_h245_annexH(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_annexH, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioLayer1_bit = {
	"audioLayer1 bit is SET",
	"audioLayer1 bit is CLEAR"
};
static int
dissect_h245_audioLayer1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioLayer1, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioLayer2_bit = {
	"audioLayer2 bit is SET",
	"audioLayer2 bit is CLEAR"
};
static int
dissect_h245_audioLayer2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioLayer2, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioLayer3_bit = {
	"audioLayer3 bit is SET",
	"audioLayer3 bit is CLEAR"
};
static int
dissect_h245_audioLayer3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioLayer3, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioSampling32k_bit = {
	"audioSampling32k bit is SET",
	"audioSampling32k bit is CLEAR"
};
static int
dissect_h245_audioSampling32k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioSampling32k, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioSampling44k1_bit = {
	"audioSampling44k1 bit is SET",
	"audioSampling44k1 bit is CLEAR"
};
static int
dissect_h245_audioSampling44k1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioSampling44k1, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioSampling48k_bit = {
	"audioSampling48k bit is SET",
	"audioSampling48k bit is CLEAR"
};
static int
dissect_h245_audioSampling48k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioSampling48k, NULL, NULL);

	return offset;
}





static const true_false_string tfs_singleChannel_bit = {
	"singleChannel bit is SET",
	"singleChannel bit is CLEAR"
};
static int
dissect_h245_singleChannel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_singleChannel, NULL, NULL);

	return offset;
}





static const true_false_string tfs_twoChannels_bit = {
	"twoChannels bit is SET",
	"twoChannels bit is CLEAR"
};
static int
dissect_h245_twoChannels(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_twoChannels, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioSampling16k_bit = {
	"audioSampling16k bit is SET",
	"audioSampling16k bit is CLEAR"
};
static int
dissect_h245_audioSampling16k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioSampling16k, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioSampling22k05_bit = {
	"audioSampling22k05 bit is SET",
	"audioSampling22k05 bit is CLEAR"
};
static int
dissect_h245_audioSampling22k05(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioSampling22k05, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioSampling24k_bit = {
	"audioSampling24k bit is SET",
	"audioSampling24k bit is CLEAR"
};
static int
dissect_h245_audioSampling24k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioSampling24k, NULL, NULL);

	return offset;
}





static const true_false_string tfs_threeChannels21_bit = {
	"threeChannels21 bit is SET",
	"threeChannels21 bit is CLEAR"
};
static int
dissect_h245_threeChannels21(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_threeChannels21, NULL, NULL);

	return offset;
}





static const true_false_string tfs_threeChannels30_bit = {
	"threeChannels30 bit is SET",
	"threeChannels30 bit is CLEAR"
};
static int
dissect_h245_threeChannels30(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_threeChannels30, NULL, NULL);

	return offset;
}





static const true_false_string tfs_fourChannels2020_bit = {
	"fourChannels2020 bit is SET",
	"fourChannels2020 bit is CLEAR"
};
static int
dissect_h245_fourChannels2020(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_fourChannels2020, NULL, NULL);

	return offset;
}





static const true_false_string tfs_fourChannels22_bit = {
	"fourChannels22 bit is SET",
	"fourChannels22 bit is CLEAR"
};
static int
dissect_h245_fourChannels22(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_fourChannels22, NULL, NULL);

	return offset;
}





static const true_false_string tfs_fourChannels31_bit = {
	"fourChannels31 bit is SET",
	"fourChannels31 bit is CLEAR"
};
static int
dissect_h245_fourChannels31(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_fourChannels31, NULL, NULL);

	return offset;
}





static const true_false_string tfs_fiveChannels3020_bit = {
	"fiveChannels3020 bit is SET",
	"fiveChannels3020 bit is CLEAR"
};
static int
dissect_h245_fiveChannels3020(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_fiveChannels3020, NULL, NULL);

	return offset;
}





static const true_false_string tfs_fiveChannels32_bit = {
	"fiveChannels32 bit is SET",
	"fiveChannels32 bit is CLEAR"
};
static int
dissect_h245_fiveChannels32(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_fiveChannels32, NULL, NULL);

	return offset;
}





static const true_false_string tfs_lowFrequencyEnhancement_bit = {
	"lowFrequencyEnhancement bit is SET",
	"lowFrequencyEnhancement bit is CLEAR"
};
static int
dissect_h245_lowFrequencyEnhancement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_lowFrequencyEnhancement, NULL, NULL);

	return offset;
}





static const true_false_string tfs_multilingual_bit = {
	"multilingual bit is SET",
	"multilingual bit is CLEAR"
};
static int
dissect_h245_multilingual(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_multilingual, NULL, NULL);

	return offset;
}





static const true_false_string tfs_comfortNoise_bit = {
	"comfortNoise bit is SET",
	"comfortNoise bit is CLEAR"
};
static int
dissect_h245_comfortNoise(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_comfortNoise, NULL, NULL);

	return offset;
}




static const true_false_string tfs_scrambled_bit = {
	"scrambled bit is SET",
	"scrambled bit is CLEAR"
};
static int
dissect_h245_scrambled(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_scrambled, NULL, NULL);

	return offset;
}





static const true_false_string tfs_qcif_bool_bit = {
	"qcif_bool bit is SET",
	"qcif_bool bit is CLEAR"
};
static int
dissect_h245_qcif_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_qcif_bool, NULL, NULL);

	return offset;
}





static const true_false_string tfs_cif_bool_bit = {
	"cif_bool bit is SET",
	"cif_bool bit is CLEAR"
};
static int
dissect_h245_cif_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_cif_bool, NULL, NULL);

	return offset;
}





static const true_false_string tfs_ccir601Seq_bit = {
	"ccir601Seq bit is SET",
	"ccir601Seq bit is CLEAR"
};
static int
dissect_h245_ccir601Seq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_ccir601Seq, NULL, NULL);

	return offset;
}





static const true_false_string tfs_ccir601Prog_bit = {
	"ccir601Prog bit is SET",
	"ccir601Prog bit is CLEAR"
};
static int
dissect_h245_ccir601Prog(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_ccir601Prog, NULL, NULL);

	return offset;
}





static const true_false_string tfs_hdtvSeq_bit = {
	"hdtvSeq bit is SET",
	"hdtvSeq bit is CLEAR"
};
static int
dissect_h245_hdtvSeq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_hdtvSeq, NULL, NULL);

	return offset;
}





static const true_false_string tfs_hdtvProg_bit = {
	"hdtvProg bit is SET",
	"hdtvProg bit is CLEAR"
};
static int
dissect_h245_hdtvProg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_hdtvProg, NULL, NULL);

	return offset;
}





static const true_false_string tfs_g3FacsMH200x100_bit = {
	"g3FacsMH200x100 bit is SET",
	"g3FacsMH200x100 bit is CLEAR"
};
static int
dissect_h245_g3FacsMH200x100(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_g3FacsMH200x100, NULL, NULL);

	return offset;
}






static const true_false_string tfs_g3FacsMH200x200_bit = {
	"g3FacsMH200x200 bit is SET",
	"g3FacsMH200x200 bit is CLEAR"
};
static int
dissect_h245_g3FacsMH200x200(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_g3FacsMH200x200, NULL, NULL);

	return offset;
}





static const true_false_string tfs_g4FacsMMR200x100_bit = {
	"g4FacsMMR200x100 bit is SET",
	"g4FacsMMR200x100 bit is CLEAR"
};
static int
dissect_h245_g4FacsMMR200x100(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_g4FacsMMR200x100, NULL, NULL);

	return offset;
}





static const true_false_string tfs_g4FacsMMR200x200_bit = {
	"g4FacsMMR200x200 bit is SET",
	"g4FacsMMR200x200 bit is CLEAR"
};
static int
dissect_h245_g4FacsMMR200x200(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_g4FacsMMR200x200, NULL, NULL);

	return offset;
}







static const true_false_string tfs_jbig200x200Seq_bit = {
	"jbig200x200Seq bit is SET",
	"jbig200x200Seq bit is CLEAR"
};
static int
dissect_h245_jbig200x200Seq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_jbig200x200Seq, NULL, NULL);

	return offset;
}





static const true_false_string tfs_jbig200x200Prog_bit = {
	"jbig200x200Prog bit is SET",
	"jbig200x200Prog bit is CLEAR"
};
static int
dissect_h245_jbig200x200Prog(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_jbig200x200Prog, NULL, NULL);

	return offset;
}





static const true_false_string tfs_jbig300x300Seq_bit = {
	"jbig300x300Seq bit is SET",
	"jbig300x300Seq bit is CLEAR"
};
static int
dissect_h245_jbig300x300Seq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_jbig300x300Seq, NULL, NULL);

	return offset;
}





static const true_false_string tfs_jbig300x300Prog_bit = {
	"jbig300x300Prog bit is SET",
	"jbig300x300Prog bit is CLEAR"
};
static int
dissect_h245_jbig300x300Prog(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_jbig300x300Prog, NULL, NULL);

	return offset;
}





static const true_false_string tfs_digPhotoLow_bit = {
	"digPhotoLow bit is SET",
	"digPhotoLow bit is CLEAR"
};
static int
dissect_h245_digPhotoLow(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_digPhotoLow, NULL, NULL);

	return offset;
}





static const true_false_string tfs_digPhotoMedSeq_bit = {
	"digPhotoMedSeq bit is SET",
	"digPhotoMedSeq bit is CLEAR"
};
static int
dissect_h245_digPhotoMedSeq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_digPhotoMedSeq, NULL, NULL);

	return offset;
}





static const true_false_string tfs_digPhotoMedProg_bit = {
	"digPhotoMedProg bit is SET",
	"digPhotoMedProg bit is CLEAR"
};
static int
dissect_h245_digPhotoMedProg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_digPhotoMedProg, NULL, NULL);

	return offset;
}





static const true_false_string tfs_digPhotoHighSeq_bit = {
	"digPhotoHighSeq bit is SET",
	"digPhotoHighSeq bit is CLEAR"
};
static int
dissect_h245_digPhotoHighSeq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_digPhotoHighSeq, NULL, NULL);

	return offset;
}





static const true_false_string tfs_digPhotoHighProg_bit = {
	"digPhotoHighProg bit is SET",
	"digPhotoHighProg bit is CLEAR"
};
static int
dissect_h245_digPhotoHighProg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_digPhotoHighProg, NULL, NULL);

	return offset;
}




static per_sequence_t T84Profile_t84Restricted_sequence[] = {
	{ "qcif", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_qcif_bool },
	{ "cif", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_cif_bool },
	{ "ccir601Seq", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ccir601Seq },
	{ "ccir601Prog", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ccir601Prog },
	{ "hdtvSeq", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_hdtvSeq },
	{ "hdtvProg", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_hdtvProg },
	{ "g3FacsMH200x100", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_g3FacsMH200x100 },
	{ "g3FacsMH200x200", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_g3FacsMH200x200 },
	{ "g4FacsMMR200x100", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_g4FacsMMR200x100 },
	{ "g4FacsMMR200x200", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_g4FacsMMR200x200 },
	{ "jbig200x200Seq", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_jbig200x200Seq },
	{ "jbig200x200Prog", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_jbig200x200Prog },
	{ "jbig300x300Seq", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_jbig300x300Seq },
	{ "jbig300x300Prog", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_jbig300x300Prog },
	{ "digPhotoLow", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_digPhotoLow },
	{ "digPhotoMedSeq", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_digPhotoMedSeq },
	{ "digPhotoMedProg", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_digPhotoMedProg },
	{ "digPhotoHighSeq", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_digPhotoHighSeq },
	{ "digPhotoHighProg", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_digPhotoHighProg },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_T84Profile_t84Restricted(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_T84Profile_t84Restricted, ett_h245_T84Profile_t84Restricted, T84Profile_t84Restricted_sequence);

	return offset;
}




static const value_string T84Profile_vals[] = {
	{  0, "t84Unrestricted" },
	{  1, "t84Restricted" },
	{  0, NULL }
};
static per_choice_t T84Profile_choice[] = {
	{  0, "t84Unrestricted", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "t84Restricted", ASN1_NO_EXTENSIONS,
			dissect_h245_T84Profile_t84Restricted },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_T84Profile(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_T84Profile, ett_h245_T84Profile, T84Profile_choice, "T84Profile", NULL);

	return offset;
}





static const true_false_string tfs_fillBitRemoval_bit = {
	"fillBitRemoval bit is SET",
	"fillBitRemoval bit is CLEAR"
};
static int
dissect_h245_fillBitRemoval(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_fillBitRemoval, NULL, NULL);

	return offset;
}





static const true_false_string tfs_transcodingJBIG_bit = {
	"transcodingJBIG bit is SET",
	"transcodingJBIG bit is CLEAR"
};
static int
dissect_h245_transcodingJBIG(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_transcodingJBIG, NULL, NULL);

	return offset;
}





static const true_false_string tfs_transcodingMMR_bit = {
	"transcodingMMR bit is SET",
	"transcodingMMR bit is CLEAR"
};
static int
dissect_h245_transcodingMMR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_transcodingMMR, NULL, NULL);

	return offset;
}





static const true_false_string tfs_t38TCPBidirectionalMode_bit = {
	"t38TCPBidirectionalMode bit is SET",
	"t38TCPBidirectionalMode bit is CLEAR"
};
static int
dissect_h245_t38TCPBidirectionalMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_t38TCPBidirectionalMode, NULL, NULL);

	return offset;
}



static per_sequence_t T38FaxTcpOptions_sequence[] = {
	{ "t38TCPBidirectionalMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_t38TCPBidirectionalMode },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_T38FaxTcpOptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_T38FaxTcpOptions, ett_h245_T38FaxTcpOptions, T38FaxTcpOptions_sequence);

	return offset;
}





static const true_false_string tfs_chairControlCapability_bit = {
	"chairControlCapability bit is SET",
	"chairControlCapability bit is CLEAR"
};
static int
dissect_h245_chairControlCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_chairControlCapability, NULL, NULL);

	return offset;
}






static const true_false_string tfs_videoIndicateMixingCapability_bit = {
	"videoIndicateMixingCapability bit is SET",
	"videoIndicateMixingCapability bit is CLEAR"
};
static int
dissect_h245_videoIndicateMixingCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_videoIndicateMixingCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_multipointVisualizationCapability_bit = {
	"multipointVisualizationCapability bit is SET",
	"multipointVisualizationCapability bit is CLEAR"
};
static int
dissect_h245_multipointVisualizationCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_multipointVisualizationCapability, NULL, NULL);

	return offset;
}





static const true_false_string tfs_controlOnMuxStream_bit = {
	"controlOnMuxStream bit is SET",
	"controlOnMuxStream bit is CLEAR"
};
static int
dissect_h245_controlOnMuxStream(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_controlOnMuxStream, NULL, NULL);

	return offset;
}





static const true_false_string tfs_redundancyEncoding_bool_bit = {
	"redundancyEncoding_bool bit is SET",
	"redundancyEncoding_bool bit is CLEAR"
};
static int
dissect_h245_redundancyEncoding_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_redundancyEncoding_bool, NULL, NULL);

	return offset;
}





static const true_false_string tfs_separatePort_bit = {
	"separatePort bit is SET",
	"separatePort bit is CLEAR"
};
static int
dissect_h245_separatePort(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_separatePort, NULL, NULL);

	return offset;
}





static const true_false_string tfs_samePort_bool_bit = {
	"samePort_bool bit is SET",
	"samePort_bool bit is CLEAR"
};
static int
dissect_h245_samePort_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_samePort_bool, NULL, NULL);

	return offset;
}




static per_sequence_t FECCapability_rfc2733_separateStream_sequence[] = {
	{ "separatePort", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_separatePort },
	{ "samePort", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_samePort_bool },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FECCapability_rfc2733_separateStream(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FECCapability_rfc2733_separateStream, ett_h245_FECCapability_rfc2733_separateStream, FECCapability_rfc2733_separateStream_sequence);

	return offset;
}



static per_sequence_t FECCapability_rfc2733_sequence[] = {
	{ "redundancyEncoding", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_redundancyEncoding_bool },
	{ "separateStream", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_FECCapability_rfc2733_separateStream },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FECCapability_rfc2733(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FECCapability_rfc2733, ett_h245_FECCapability_rfc2733, FECCapability_rfc2733_sequence);

	return offset;
}




static const value_string FECCapability_vals[] = {
	{  0, "rfc2733" },
	{  0, NULL }
};
static per_choice_t FECCapability_choice[] = {
	{  0, "rfc2733", ASN1_EXTENSION_ROOT,
		dissect_h245_FECCapability_rfc2733 },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FECCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FECCapability, ett_h245_FECCapability, FECCapability_choice, "FECCapability", NULL);

	return offset;
}




static const true_false_string tfs_associateConference_bit = {
	"associateConference bit is SET",
	"associateConference bit is CLEAR"
};
static int
dissect_h245_associateConference(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_associateConference, NULL, NULL);

	return offset;
}





static const true_false_string tfs_audioHeaderPresent_bit = {
	"audioHeaderPresent bit is SET",
	"audioHeaderPresent bit is CLEAR"
};
static int
dissect_h245_audioHeaderPresent(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_audioHeaderPresent, NULL, NULL);

	return offset;
}




static per_sequence_t V75Parameters_sequence[] = {
	{ "audioHeaderPresent", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioHeaderPresent },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_V75Parameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_V75Parameters, ett_h245_V75Parameters, V75Parameters_sequence);

	return offset;
}






static const true_false_string tfs_segmentableFlag_bit = {
	"segmentableFlag bit is SET",
	"segmentableFlag bit is CLEAR"
};
static int
dissect_h245_segmentableFlag(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_segmentableFlag, NULL, NULL);

	return offset;
}





static const true_false_string tfs_alsduSplitting_bit = {
	"alsduSplitting bit is SET",
	"alsduSplitting bit is CLEAR"
};
static int
dissect_h245_alsduSplitting(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_alsduSplitting, NULL, NULL);

	return offset;
}





static const true_false_string tfs_uIH_bit = {
	"uIH bit is SET",
	"uIH bit is CLEAR"
};
static int
dissect_h245_uIH(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_uIH, NULL, NULL);

	return offset;
}






static const true_false_string tfs_loopbackTestProcedure_bit = {
	"loopbackTestProcedure bit is SET",
	"loopbackTestProcedure bit is CLEAR"
};
static int
dissect_h245_loopbackTestProcedure(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_loopbackTestProcedure, NULL, NULL);

	return offset;
}






static const true_false_string tfs_mediaGuaranteedDelivery_bit = {
	"mediaGuaranteedDelivery bit is SET",
	"mediaGuaranteedDelivery bit is CLEAR"
};
static int
dissect_h245_mediaGuaranteedDelivery(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_mediaGuaranteedDelivery, NULL, NULL);

	return offset;
}






static const true_false_string tfs_mediaControlGuaranteedDelivery_bit = {
	"mediaControlGuaranteedDelivery bit is SET",
	"mediaControlGuaranteedDelivery bit is CLEAR"
};
static int
dissect_h245_mediaControlGuaranteedDelivery(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_mediaControlGuaranteedDelivery, NULL, NULL);

	return offset;
}






static const true_false_string tfs_flowControlToZero_bit = {
	"flowControlToZero bit is SET",
	"flowControlToZero bit is CLEAR"
};
static int
dissect_h245_flowControlToZero(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_flowControlToZero, NULL, NULL);

	return offset;
}






static const true_false_string tfs_multiplexCapability_bool_bit = {
	"multiplexCapability_bool bit is SET",
	"multiplexCapability_bool bit is CLEAR"
};
static int
dissect_h245_multiplexCapability_bool(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_multiplexCapability_bool, NULL, NULL);

	return offset;
}





static const true_false_string tfs_secureChannel_bit = {
	"secureChannel bit is SET",
	"secureChannel bit is CLEAR"
};
static int
dissect_h245_secureChannel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_secureChannel, NULL, NULL);

	return offset;
}





static const true_false_string tfs_sharedSecret_bit = {
	"sharedSecret bit is SET",
	"sharedSecret bit is CLEAR"
};
static int
dissect_h245_sharedSecret(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_sharedSecret, NULL, NULL);

	return offset;
}





static const true_false_string tfs_certProtectedKey_bit = {
	"certProtectedKey bit is SET",
	"certProtectedKey bit is CLEAR"
};
static int
dissect_h245_certProtectedKey(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_certProtectedKey, NULL, NULL);

	return offset;
}



static per_sequence_t KeyProtectionMethod_sequence[] = {
	{ "secureChannel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_secureChannel },
	{ "sharedSecret", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_sharedSecret },
	{ "certProtectedKey", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_certProtectedKey },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_KeyProtectionMethod(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_KeyProtectionMethod, ett_h245_KeyProtectionMethod, KeyProtectionMethod_sequence);

	return offset;
}



static per_sequence_t EncryptionUpdateRequest_sequence[] = {
	{ "keyProtectionMethod", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_KeyProtectionMethod },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_EncryptionUpdateRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_EncryptionUpdateRequest, ett_h245_EncryptionUpdateRequest, EncryptionUpdateRequest_sequence);

	return offset;
}





static const true_false_string tfs_bitRateLockedToPCRClock_bit = {
	"bitRateLockedToPCRClock bit is SET",
	"bitRateLockedToPCRClock bit is CLEAR"
};
static int
dissect_h245_bitRateLockedToPCRClock(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_bitRateLockedToPCRClock, NULL, NULL);

	return offset;
}






static const true_false_string tfs_bitRateLockedToNetworkClock_bit = {
	"bitRateLockedToNetworkClock bit is SET",
	"bitRateLockedToNetworkClock bit is CLEAR"
};
static int
dissect_h245_bitRateLockedToNetworkClock(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_bitRateLockedToNetworkClock, NULL, NULL);

	return offset;
}



static int
dissect_h245_IS11172_BitRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_IS11172_BitRate, 1, 448,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_IS13818_BitRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_IS13818_BitRate, 1, 1130,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t IS11172AudioCapability_sequence[] = {
	{ "audioLayer1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioLayer1 },
	{ "audioLayer2", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioLayer2 },
	{ "audioLayer3", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioLayer3 },
	{ "audioSampling32k", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioSampling32k },
	{ "audioSampling44k1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioSampling44k1 },
	{ "audioSampling48k", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioSampling48k },
	{ "singleChannel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_singleChannel },
	{ "twoChannels", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_twoChannels },
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_IS11172_BitRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_IS11172AudioCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_IS11172AudioCapability, ett_h245_IS11172AudioCapability, IS11172AudioCapability_sequence);

	return offset;
}



static per_sequence_t IS11172AudioMode_sequence[] = {
	{ "audioLayer", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_IS11172AudioMode_audioLayer },
	{ "audioSampling", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_IS11172AudioMode_audioSampling },
	{ "multichannelType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_IS11172AudioMode_multichannelType },
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_IS11172_BitRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_IS11172AudioMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_IS11172AudioMode, ett_h245_IS11172AudioMode, IS11172AudioMode_sequence);

	return offset;
}



static per_sequence_t IS13818AudioMode_sequence[] = {
	{ "audioLayer", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_IS13818AudioMode_audioLayer },
	{ "audioSampling", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_IS13818AudioMode_audioSampling },
	{ "multiChannelType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_IS13818AudioMode_multiChannelType },
	{ "lowFrequencyEnhancement", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_lowFrequencyEnhancement },
	{ "multilingual", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_multilingual },
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_IS13818_BitRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_IS13818AudioMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_IS13818AudioMode, ett_h245_IS13818AudioMode, IS13818AudioMode_sequence);

	return offset;
}




static per_sequence_t IS13818AudioCapability_sequence[] = {
	{ "audioLayer1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioLayer1 },
	{ "audioLayer2", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioLayer2 },
	{ "audioLayer3", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioLayer3 },
	{ "audioSampling16k", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioSampling16k },
	{ "audioSampling22k05", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioSampling22k05 },
	{ "audioSampling24k", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioSampling24k },
	{ "audioSampling32k", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioSampling32k },
	{ "audioSampling44k1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioSampling44k1 },
	{ "audioSampling48k", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioSampling48k },
	{ "singleChannel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_singleChannel },
	{ "twoChannels", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_twoChannels },
	{ "threeChannels2-1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_threeChannels21 },
	{ "threeChannels3-0", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_threeChannels30 },
	{ "fourChannels2-0-2-0", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_fourChannels2020 },
	{ "fourChannels2-2", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_fourChannels22 },
	{ "fourChannels3-1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_fourChannels31 },
	{ "fiveChannels3-0-2-0", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_fiveChannels3020 },
	{ "fiveChannels3-2", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_fiveChannels32 },
	{ "lowFrequencyEnhancement", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_lowFrequencyEnhancement },
	{ "multilingual", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_multilingual },
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_IS13818_BitRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_IS13818AudioCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_IS13818AudioCapability, ett_h245_IS13818AudioCapability, IS13818AudioCapability_sequence);

	return offset;
}




static int
dissect_h245_ATM_BitRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_ATM_BitRate, 1, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t NewATMVCIndication_reverseParameters_sequence[] = {
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ATM_BitRate },
	{ "bitRateLockedToPCRClock", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_bitRateLockedToPCRClock },
	{ "bitRateLockedToNetworkClock", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_bitRateLockedToNetworkClock },
	{ "multiplex", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCIndication_reverseParameters_multiplex },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NewATMVCIndication_reverseParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NewATMVCIndication_reverseParameters, ett_h245_NewATMVCIndication_reverseParameters, NewATMVCIndication_reverseParameters_sequence);

	return offset;
}



static per_sequence_t NewATMVCCommand_reverseParameters_sequence[] = {
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ATM_BitRate },
	{ "bitRateLockedToPCRClock", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_bitRateLockedToPCRClock },
	{ "bitRateLockedToNetworkClock", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_bitRateLockedToNetworkClock },
	{ "multiplex", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCCommand_reverseParameters_multiplex },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NewATMVCCommand_reverseParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NewATMVCCommand_reverseParameters, ett_h245_NewATMVCCommand_reverseParameters, NewATMVCCommand_reverseParameters_sequence);

	return offset;
}

static int
dissect_h245_t35CountryCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_t35CountryCode, 0, 255,
		&t35CountryCode, NULL, FALSE);

	return offset;
}


static int
dissect_h245_t35Extension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_t35Extension, 0, 255,
		&t35Extension, NULL, FALSE);

	return offset;
}



static int
dissect_h245_manufacturerCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_manufacturerCode, 0, 65535,
		&manufacturerCode, NULL, FALSE);

	return offset;
}


/* dissect_h245_h221NonStandard is used for H.245 */

static per_sequence_t h221NonStandard_sequence[] = {
	{ "t35CountryCode", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_t35CountryCode },
	{ "t35Extension", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_t35Extension },
	{ "manufacturerCode", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_manufacturerCode },
	{ NULL, 0, 0, NULL }
};
int
dissect_h245_h221NonStandard(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	t35CountryCode = 0;
	t35Extension = 0;
	manufacturerCode = 0;

	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_h221NonStandard, ett_h245_h221NonStandard, h221NonStandard_sequence);

	h221NonStandard = ((t35CountryCode * 256) + t35Extension) * 65536 + manufacturerCode;

	proto_tree_add_uint(tree, hf_h245_h221Manufacturer, tvb, (offset-3)>>3,4,h221NonStandard);

	return offset;
}

static int
dissect_h245_terminalType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_terminalType, 0, 255,
		NULL, NULL, FALSE);

	return offset;
}

static int
dissect_h245_statusDeterminationNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_statusDeterminationNumber, 0, 16777215,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t MasterSlaveDetermination_sequence[] = {
	{ "terminalType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_terminalType },
	{ "statusDeterminationNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_statusDeterminationNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MasterSlaveDetermination(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MasterSlaveDetermination, ett_h245_MasterSlaveDetermination, MasterSlaveDetermination_sequence);

	return offset;
}




static int
dissect_h245_CapabilityTableEntryNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_CapabilityTableEntryNumber, 1, 65535,
		NULL, NULL, FALSE);

	return offset;
}



static const value_string TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded_vals[] = {
	{  0, "highestEntryNumberProcessed" },
	{  1, "noneProcessed" },
	{  0, NULL }
};
static per_choice_t TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded_choice[] = {
	{  0, "highestEntryNumberProcessed", ASN1_NO_EXTENSIONS,
			dissect_h245_CapabilityTableEntryNumber },
	{  1, "noneProcessed", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded, ett_h245_TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded, TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded_choice, "tableEntryCapacityExceeded", NULL);

	return offset;
}





static const value_string TerminalCapabilitySetReject_cause_vals[] = {
	{  0, "unspecified" },
	{  1, "undefinedTableEntryUsed" },
	{  2, "descriptorCapacityExceeded" },
	{  3, "tableEntryCapacityExceeded" },
	{  0, NULL }
};
static per_choice_t TerminalCapabilitySetReject_cause_choice[] = {
	{  0, "unspecified", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "undefinedTableEntryUsed", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "descriptorCapacityExceeded", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "tableEntryCapacityExceeded", ASN1_EXTENSION_ROOT,
			dissect_h245_TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_TerminalCapabilitySetReject_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_TerminalCapabilitySetReject_cause, ett_h245_TerminalCapabilitySetReject_cause, TerminalCapabilitySetReject_cause_choice, "cause", NULL);

	return offset;
}



static per_sequence_t TerminalCapabilitySetReject_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_SequenceNumber },
	{ "cause", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_TerminalCapabilitySetReject_cause },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_TerminalCapabilitySetReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_TerminalCapabilitySetReject, ett_h245_TerminalCapabilitySetReject, TerminalCapabilitySetReject_sequence);

	return offset;
}





static int
dissect_h245_CapabilityDescriptorNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_CapabilityDescriptorNumber, 0, 255,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_h233IVResponseTime(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_h233IVResponseTime, 0, 255,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t Capability_h233EncryptionReceiveCapability_sequence[] = {
	{ "h233IVResponseTime", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_h233IVResponseTime },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_Capability_h233EncryptionReceiveCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_Capability_h233EncryptionReceiveCapability, ett_h245_Capability_h233EncryptionReceiveCapability, Capability_h233EncryptionReceiveCapability_sequence);

	return offset;
}





static int
dissect_h245_maxPendingReplacementFor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maxPendingReplacementFor, 0, 255,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_numberOfVCs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_numberOfVCs, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_forwardMaximumSDUSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_forwardMaximumSDUSize, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_backwardMaximumSDUSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_backwardMaximumSDUSize, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}





static per_sequence_t VCCapability_aal5_sequence[] = {
	{ "forwardMaximumSDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_forwardMaximumSDUSize },
	{ "backwardMaximumSDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_backwardMaximumSDUSize },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_VCCapability_aal5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_VCCapability_aal5, ett_h245_VCCapability_aal5, VCCapability_aal5_sequence);

	return offset;
}



static per_sequence_t NewATMVCCommand_aal_aal5_sequence[] = {
	{ "forwardMaximumSDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_forwardMaximumSDUSize},
	{ "backwardMaximumSDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_backwardMaximumSDUSize },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NewATMVCCommand_aal_aal5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NewATMVCCommand_aal_aal5, ett_h245_NewATMVCCommand_aal_aal5, NewATMVCCommand_aal_aal5_sequence);

	return offset;
}





static const value_string NewATMVCCommand_aal_vals[] = {
	{  0, "aal1" },
	{  1, "aal5" },
	{  0, NULL }
};
static per_choice_t NewATMVCCommand_aal_choice[] = {
	{  0, "aal1", ASN1_EXTENSION_ROOT,
		dissect_h245_NewATMVCCommand_aal_aal1 },
	{  1, "aal5", ASN1_EXTENSION_ROOT,
		dissect_h245_NewATMVCCommand_aal_aal5 },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NewATMVCCommand_aal(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NewATMVCCommand_aal, ett_h245_NewATMVCCommand_aal, NewATMVCCommand_aal_choice, "aal", NULL);

	return offset;
}




static per_sequence_t NewATMVCIndication_aal_aal5_sequence[] = {
	{ "forwardMaximumSDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_forwardMaximumSDUSize },
	{ "backwardMaximumSDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_backwardMaximumSDUSize },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NewATMVCIndication_aal_aal5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NewATMVCIndication_aal_aal5, ett_h245_NewATMVCIndication_aal_aal5, NewATMVCIndication_aal_aal5_sequence);

	return offset;
}




static const value_string NewATMVCIndication_aal_vals[] = {
	{  0, "aal1" },
	{  1, "aal5" },
	{  0, NULL }
};
static per_choice_t NewATMVCIndication_aal_choice[] = {
	{  0, "aal1", ASN1_EXTENSION_ROOT,
		dissect_h245_NewATMVCIndication_aal_aal1 },
	{  1, "aal5", ASN1_EXTENSION_ROOT,
		dissect_h245_NewATMVCIndication_aal_aal5 },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NewATMVCIndication_aal(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NewATMVCIndication_aal, ett_h245_NewATMVCIndication_aal, NewATMVCIndication_aal_choice, "aal", NULL);

	return offset;
}




static int
dissect_h245_singleBitRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_singleBitRate, 1, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_lowerBitRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_lowerBitRate, 1, 65535,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_higherBitRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_higherBitRate, 1, 65535,
		NULL, NULL, FALSE);

	return offset;
}





static per_sequence_t VCCapability_availableBitRates_rangeOfBitRates_sequence[] = {
	{ "lowerBitRate", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
			dissect_h245_lowerBitRate },
	{ "higherBitRate", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
			dissect_h245_higherBitRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_VCCapability_availableBitRates_rangeOfBitRates(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_VCCapability_availableBitRates_rangeOfBitRates, ett_h245_VCCapability_availableBitRates_rangeOfBitRates, VCCapability_availableBitRates_rangeOfBitRates_sequence);

	return offset;
}




static const value_string VCCapability_availableBitRates_type_vals[] = {
	{  0, "singleBitRate" },
	{  1, "rangeOfBitRates" },
	{  0, NULL }
};
static per_choice_t VCCapability_availableBitRates_type_choice[] = {
	{  0, "singleBitRate", ASN1_NO_EXTENSIONS,
			dissect_h245_singleBitRate },
	{  1, "rangeOfBitRates", ASN1_NO_EXTENSIONS,
			dissect_h245_VCCapability_availableBitRates_rangeOfBitRates },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_VCCapability_availableBitRates_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_VCCapability_availableBitRates_type, ett_h245_VCCapability_availableBitRates_type, VCCapability_availableBitRates_type_choice, "type", NULL);

	return offset;
}



static int
dissect_h245_maximumAl2SDUSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumAl2SDUSize, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_maximumAl3SDUSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumAl3SDUSize, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_maximumDelayJitter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumDelayJitter, 0, 1023,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_maximumNestingDepth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumNestingDepth, 1, 15,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_maximumElementListSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumElementListSize, 2, 255,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_maximumSubElementListSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumSubElementListSize, 2, 255,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t H223Capability_h223MultiplexTableCapability_enhanced_sequence[] = {
	{ "maximumNestingDepth", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_maximumNestingDepth },
	{ "maximumElementListSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_maximumElementListSize },
	{ "maximumSubElementListSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_maximumSubElementListSize },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223Capability_h223MultiplexTableCapability_enhanced(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223Capability_h223MultiplexTableCapability_enhanced, ett_h245_H223Capability_h223MultiplexTableCapability_enhanced, H223Capability_h223MultiplexTableCapability_enhanced_sequence);

	return offset;
}




static const value_string H223Capability_h223MultiplexTableCapability_vals[] = {
	{  0, "basic" },
	{  1, "enhanced" },
	{  0, NULL }
};
static per_choice_t H223Capability_h223MultiplexTableCapability_choice[] = {
	{  0, "basic", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  1, "enhanced", ASN1_NO_EXTENSIONS,
			dissect_h245_H223Capability_h223MultiplexTableCapability_enhanced },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223Capability_h223MultiplexTableCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223Capability_h223MultiplexTableCapability, ett_h245_H223Capability_h223MultiplexTableCapability, H223Capability_h223MultiplexTableCapability_choice, "h223MultiplexTableCapability", NULL);

	return offset;
}




static int
dissect_h245_h223bitRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_h223bitRate, 1, 19200,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_maximumSampleSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumSampleSize, 1, 255,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_maximumPayloadLength(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumPayloadLength, 1, 65025,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t H223Capability_mobileMultilinkFrameCapability_sequence[] = {
	{ "maximumSampleSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_maximumSampleSize },
	{ "maximumPayloadLength", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_maximumPayloadLength },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223Capability_mobileMultilinkFrameCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223Capability_mobileMultilinkFrameCapability, ett_h245_H223Capability_mobileMultilinkFrameCapability, H223Capability_mobileMultilinkFrameCapability_sequence);

	return offset;
}




static int
dissect_h245_maximumAL1MPDUSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumAL1MPDUSize, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_maximumAL2MSDUSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumAL2MSDUSize, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_maximumAL3MSDUSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumAL3MSDUSize, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}





static per_sequence_t H223AnnexCCapability_sequence[] = {
	{ "videoWithAL1M", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoWithAL1M },
	{ "videoWithAL2M", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoWithAL2M },
	{ "videoWithAL3M", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoWithAL3M },
	{ "audioWithAL1M", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioWithAL1M },
	{ "audioWithAL2M", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioWithAL2M },
	{ "audioWithAL3M", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioWithAL3M },
	{ "dataWithAL1M", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dataWithAL1M },
	{ "dataWithAL2M", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dataWithAL2M },
	{ "dataWithAL3M", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dataWithAL3M },
	{ "alpduInterleaving", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_alpduInterleaving },
	{ "maximumAL1MPDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maximumAL1MPDUSize },
	{ "maximumAL2MSDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maximumAL2MSDUSize },
	{ "maximumAL3MSDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maximumAL3MSDUSize },
	{ "rsCodeCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_rsCodeCapability },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223AnnexCCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223AnnexCCapability, ett_h245_H223AnnexCCapability, H223AnnexCCapability_sequence);

	return offset;
}



static const true_false_string tfs_transportWithIframes_bit = {
	"transportWithIframes bit is SET",
	"transportWithIframes bit is CLEAR"
};
static int
dissect_h245_transportWithIframes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h245_transportWithIframes, NULL, NULL);

	return offset;
}


static per_sequence_t H223Capability_sequence[] = {
	{ "transportWithIframes", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_transportWithIframes },
	{ "videoWithAL1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoWithAL1 },
	{ "videoWithAL2", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoWithAL2 },
	{ "videoWithAL3", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoWithAL3 },
	{ "audioWithAL1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioWithAL1 },
	{ "audioWithAL2", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioWithAL2 },
	{ "audioWithAL3", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioWithAL3 },
	{ "dataWithAL1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dataWithAL1 },
	{ "dataWithAL2", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dataWithAL2 },
	{ "dataWithAL3", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dataWithAL3 },
	{ "maximumAL2SDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maximumAl2SDUSize },
	{ "maximumAL3SDUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maximumAl3SDUSize },
	{ "maximumDelayJitter", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maximumDelayJitter },
	{ "h223MultiplexTableCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223Capability_h223MultiplexTableCapability },
	{ "maxMUXPDUSizeCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxMUXPDUSizeCapability },
	{ "nsrpSupport", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_nsrpSupport },
	{ "mobileOperationTransmitCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_H223Capability_mobileOperationTransmitCapability },
	{ "h223AnnexCCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_H223AnnexCCapability },
	{ "bitRate", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_h223bitRate },
	{ "mobileMultilinkFrameCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_H223Capability_mobileMultilinkFrameCapability },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223Capability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223Capability, ett_h245_H223Capability, H223Capability_sequence);

	return offset;
}




static int
dissect_h245_numOfDLCS(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_numOfDLCS, 2, 8191,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_n401Capability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_n401Capability, 1, 4095,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_maxWindowSizeCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maxWindowSizeCapability, 1, 127,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t V76Capability_sequence[] = {
	{ "suspendResumeCapabilitywAddress", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_suspendResumeCapabilitywAddress },
	{ "suspendResumeCapabilitywoAddress", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_suspendResumeCapabilitywoAddress },
	{ "rejCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_rejCapability },
	{ "sREJCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_sREJCapability },
	{ "mREJCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_mREJCapability },
	{ "crc8bitCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_crc8bitCapability },
	{ "crc16bitCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_crc16bitCapability },
	{ "crc32bitCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_crc32bitCapability },
	{ "uihCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_uihCapability },
	{ "numOfDLCS", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_numOfDLCS },
	{ "twoOctetAddressFieldCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_twoOctetAddressFieldCapability },
	{ "loopBackTestCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_loopBackTestCapability },
	{ "n401Capability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_n401Capability },
	{ "maxWindowSizeCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxWindowSizeCapability },
	{ "v75Capability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_V75Capability },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_V76Capability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_V76Capability, ett_h245_V76Capability, V76Capability_sequence);

	return offset;
}




static int
dissect_h245_maximumAudioDelayJitter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumAudioDelayJitter, 0, 1023,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_tokenRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_tokenRate, 1, 4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_bucketSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_bucketSize, 1, 4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_peakRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_peakRate, 1, 4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_minPoliced(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_minPoliced, 1, 4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_maxPktSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maxPktSize, 1, 4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t RSVPParameters_sequence[] = {
	{ "qosMode", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
			dissect_h245_QOSMode },
	{ "tokenRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
			dissect_h245_tokenRate },
	{ "bucketSize", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
			dissect_h245_bucketSize },
	{ "peakRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
			dissect_h245_peakRate },
	{ "minPoliced", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
			dissect_h245_minPoliced },
	{ "maxPktSize", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
			dissect_h245_maxPktSize },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RSVPParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RSVPParameters, ett_h245_RSVPParameters, RSVPParameters_sequence);

	return offset;
}




static int
dissect_h245_maxNTUSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maxNTUSize, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t ATMParameters_sequence[] = {
	{ "maxNTUSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxNTUSize },
	{ "atmUBR", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_atmUBR },
	{ "atmrtVBR", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_atmrtVBR },
	{ "atmnrtVBR", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_atmnrtVBR },
	{ "atmABR", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_atmABR },
	{ "atmCBR", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_atmCBR },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ATMParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ATMParameters, ett_h245_ATMParameters, ATMParameters_sequence);

	return offset;
}




static int
dissect_h245_numberOfThreads(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_numberOfThreads, 1, 16,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_framesBetweenSyncPoints(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_framesBetweenSyncPoints, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_threadNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_threadNumber, 0, 15,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_qcifMPI_1_4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_qcifMPI_1_4, 1, 4,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_qcifMPI_1_32(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_qcifMPI_1_32, 1, 32,
		NULL, NULL, FALSE);

	return offset;
}






static int
dissect_h245_qcifMPI_1_2048(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_qcifMPI_1_2048, 1, 2048,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_cifMPI_1_4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_cifMPI_1_4, 1, 4,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_cifMPI_1_32(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_cifMPI_1_32, 1, 32,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_cifMPI_1_2048(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_cifMPI_1_2048, 1, 2048,
		NULL, NULL, FALSE);

	return offset;
}





static per_sequence_t H261VideoCapability_sequence[] = {
	{ "qcifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_qcifMPI_1_4 },
	{ "cifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cifMPI_1_4 },
	{ "temporalSpatialTradeOffCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_temporalSpatialTradeOffCapability },
	{ "maxBitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_h223bitRate },
	{ "stillImageTransmission", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_stillImageTransmission },
	{ "videoBadMBsCap", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoBadMBsCap },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H261VideoCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H261VideoCapability, ett_h245_H261VideoCapability, H261VideoCapability_sequence);

	return offset;
}




static int
dissect_h245_videoBitRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_videoBitRate, 0, 1073741823,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_vbvBufferSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_vbvBufferSize, 0, 262143,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_samplesPerLine(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_samplesPerLine, 0, 16383,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_linesPerFrame(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_linesPerFrame, 0, 16383,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_framesPerSecond(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_framesPerSecond, 0, 15,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_luminanceSampleRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_luminanceSampleRate, 0, 4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t H262VideoCapability_sequence[] = {
	{ "profileAndLevel-SPatML", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelSPatML },
	{ "profileAndLevel-MPatLL", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelMPatLL },
	{ "profileAndLevel-MPatML", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelMPatML },
	{ "profileAndLevel-MPatH-14", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelMPatH14 },
	{ "profileAndLevel-MPatHL", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelMPatHL },
	{ "profileAndLevel-SNRatLL", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelSNRatLL },
	{ "profileAndLevel-SNRatML", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelSNRatML },
	{ "profileAndLevel-SpatialatH-14", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelSpatialatH14 },
	{ "profileAndLevel-HPatML", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelHPatML },
	{ "profileAndLevel-HPatH-14", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelHPatH14 },
	{ "profileAndLevel-HPatHL", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_profileAndLevelHPatHL },
	{ "videoBitRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_videoBitRate },
	{ "vbvBufferSize", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_vbvBufferSize },
	{ "samplesPerLine", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_samplesPerLine },
	{ "linesPerFrame", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_linesPerFrame },
	{ "framesPerSecond", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_framesPerSecond },
	{ "luminanceSampleRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_luminanceSampleRate },
	{ "videoBadMBsCap", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoBadMBsCap },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H262VideoCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H262VideoCapability, ett_h245_H262VideoCapability, H262VideoCapability_sequence);

	return offset;
}





static per_sequence_t H262VideoMode_sequence[] = {
	{ "profileAndLevel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H262VideoMode_profileAndLevel },
	{ "videoBitRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_videoBitRate },
	{ "vbvBufferSize", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_vbvBufferSize },
	{ "samplesPerLine", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_samplesPerLine },
	{ "linesPerFrame", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_linesPerFrame },
	{ "framesPerSecond", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_framesPerSecond },
	{ "luminanceSampleRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_luminanceSampleRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H262VideoMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H262VideoMode, ett_h245_H262VideoMode, H262VideoMode_sequence);

	return offset;
}




static int
dissect_h245_sqcifMPI_1_32(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_sqcifMPI_1_32, 1, 32,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_sqcifMPI_1_2048(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_sqcifMPI_1_2048, 1, 2048,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_cif4MPI_1_32(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_cif4MPI_1_32, 1, 32,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_cif4MPI_1_2048(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_cif4MPI_1_2048, 1, 2048,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_cif16MPI_1_32(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_cif16MPI_1_32, 1, 32,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_cif16MPI_1_2048(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_cif16MPI_1_2048, 1, 2048,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_maxBitRate_192400(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maxBitRate_192400, 1, 192400,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_hrd_B(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_hrd_B, 0, 524287,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_bppMaxKb(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_bppMaxKb, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_slowSqcifMPI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_slowSqcifMPI, 1, 3600,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_slowQcifMPI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_slowQcifMPI, 1, 3600,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_slowCifMPI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_slowCifMPI, 1, 3600,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_slowCif4MPI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_slowCif4MPI, 1, 3600,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_slowCif16MPI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_slowCif16MPI, 1, 3600,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_numberOfBPictures(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_numberOfBPictures, 1, 64,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_presentationOrder(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_presentationOrder, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_offset_x(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_offset_x, -262144, 262143,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_offset_y(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_offset_y, -262144, 262143,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_scale_x(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_scale_x, 1, 255,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_scale_y(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_scale_y, 1, 255,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t TransperencyParameters_sequence[] = {
	{ "presentationOrder", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_presentationOrder },
	{ "offset-x", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_offset_x },
	{ "offset-y", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_offset_y },
	{ "scale-x", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_scale_x },
	{ "scale-y", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_scale_y },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_TransperencyParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_TransperencyParameters, ett_h245_TransperencyParameters, TransperencyParameters_sequence);

	return offset;
}




static int
dissect_h245_sqcifAdditionalPictureMemory(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_sqcifAdditionalPictureMemory, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_qcifAdditionalPictureMemory(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_qcifAdditionalPictureMemory, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_cifAdditionalPictureMemory(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_cifAdditionalPictureMemory, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_cif4AdditionalPictureMemory(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_cif4AdditionalPictureMemory, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_cif16AdditionalPictureMemory(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_cif16AdditionalPictureMemory, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_bigCpfAdditionalPictureMemory(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_bigCpfAdditionalPictureMemory, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t RefPictureSelection_additionalPictureMemory_sequence[] = {
	{ "sqcifAdditionalPictureMemory", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_sqcifAdditionalPictureMemory },
	{ "qcifAdditionalPictureMemory", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_qcifAdditionalPictureMemory },
	{ "cifAdditionalPictureMemory", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cifAdditionalPictureMemory },
	{ "cif4AdditionalPictureMemory", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cif4AdditionalPictureMemory },
	{ "cif16AdditionalPictureMemory", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cif16AdditionalPictureMemory },
	{ "bigCpfAdditionalPictureMemory", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_bigCpfAdditionalPictureMemory},
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RefPictureSelection_additionalPictureMemory(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RefPictureSelection_additionalPictureMemory, ett_h245_RefPictureSelection_additionalPictureMemory, RefPictureSelection_additionalPictureMemory_sequence);

	return offset;
}




static int
dissect_h245_mpuHorizMBs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_mpuHorizMBs, 1, 128,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_mpuVertMBs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_mpuVertMBs, 1, 72,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_mpuTotalNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_mpuTotalNumber, 1, 65536,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters_sequence[] = {
	{ "mpuHorizMBs", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_mpuHorizMBs },
	{ "mpuVertMBs", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_mpuVertMBs},
	{ "mpuTotalNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_mpuTotalNumber},
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters, ett_h245_RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters, RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters_sequence);

	return offset;
}






static per_sequence_t RefPictureSelection_enhancedReferencePicSelect_sequence[] = {
	{ "subPictureRemovalParameters", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RefPictureSelection_enhancedReferencePicSelect(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RefPictureSelection_enhancedReferencePicSelect, ett_h245_RefPictureSelection_enhancedReferencePicSelect, RefPictureSelection_enhancedReferencePicSelect_sequence);

	return offset;
}





static per_sequence_t RefPictureSelection_sequence[] = {
	{ "additionalPictureMemory", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RefPictureSelection_additionalPictureMemory },
	{ "videoMux", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoMux },
	{ "videoBackChannelSend", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RefPictureSelection_videoBackChannelSend },
	{ "enhancedReferencePicSelect", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RefPictureSelection_enhancedReferencePicSelect },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RefPictureSelection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RefPictureSelection, ett_h245_RefPictureSelection, RefPictureSelection_sequence);

	return offset;
}



static int
dissect_h245_clockConversionCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_clockConversionCode, 1000, 1001,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_clockDivisor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_clockDivisor, 1, 127,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t CustomPictureClockFrequency_sequence[] = {
	{ "clockConversionCode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_clockConversionCode },
	{ "clockDivisor", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_clockDivisor },
	{ "sqcifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_sqcifMPI_1_2048 },
	{ "qcifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_qcifMPI_1_2048 },
	{ "cifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cifMPI_1_2048 },
	{ "cif4MPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cif4MPI_1_2048 },
	{ "cif16MPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cif16MPI_1_2048 },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CustomPictureClockFrequency(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CustomPictureClockFrequency, ett_h245_CustomPictureClockFrequency, CustomPictureClockFrequency_sequence);

	return offset;
}




static int
dissect_h245_maxCustomPictureWidth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maxCustomPictureWidth, 1, 2048,
		NULL, NULL, FALSE);

	return offset;
}


static int
dissect_h245_minCustomPictureWidth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_minCustomPictureWidth, 1, 2048,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_minCustomPictureHeight(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_minCustomPictureHeight, 1, 2048,
		NULL, NULL, FALSE);

	return offset;
}


static int
dissect_h245_maxCustomPictureHeight(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maxCustomPictureHeight, 1, 2048,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_standardMPI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_standardMPI, 1, 31,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_customMPI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_customMPI, 1, 2048,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t CustomPictureFormat_mPI_customPCF_sequence[] = {
	{ "clockConversionCode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_clockConversionCode },
	{ "clockDivisor", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_clockDivisor },
	{ "customMPI", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_customMPI },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CustomPictureFormat_mPI_customPCF(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CustomPictureFormat_mPI_customPCF, ett_h245_CustomPictureFormat_mPI_customPCF, CustomPictureFormat_mPI_customPCF_sequence);

	return offset;
}



static int dissect_h245_customPCF(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static per_sequence_t CustomPictureFormat_mPI_sequence[] = {
	{ "standardMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_standardMPI},
	{ "customPCF", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_customPCF },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CustomPictureFormat_mPI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CustomPictureFormat_mPI, ett_h245_CustomPictureFormat_mPI, CustomPictureFormat_mPI_sequence);

	return offset;
}




static int
dissect_h245_width(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_width, 1, 255,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_height(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_height, 1, 255,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t CustomPictureFormat_pixelAspectInformation_extendedPAR_sequence[] = {
	{ "width", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_width },
	{ "height", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_height},
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CustomPictureFormat_pixelAspectInformation_extendedPAR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CustomPictureFormat_pixelAspectInformation_extendedPAR, ett_h245_CustomPictureFormat_pixelAspectInformation_extendedPAR, CustomPictureFormat_pixelAspectInformation_extendedPAR_sequence);

	return offset;
}




static int
dissect_h245_pictureRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_pictureRate, 0, 15,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t IS11172VideoMode_sequence[] = {
	{ "constrainedBitstream", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_constrainedBitstream },
	{ "videoBitRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_videoBitRate },
	{ "vbvBufferSize", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_vbvBufferSize },
	{ "samplesPerLine", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_samplesPerLine },
	{ "linesPerFrame", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_linesPerFrame },
	{ "pictureRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_pictureRate},
	{ "luminanceSampleRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_luminanceSampleRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_IS11172VideoMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_IS11172VideoMode, ett_h245_IS11172VideoMode, IS11172VideoMode_sequence);

	return offset;
}



static per_sequence_t IS11172VideoCapability_sequence[] = {
	{ "constrainedBitstream", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_constrainedBitstream },
	{ "videoBitRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_videoBitRate },
	{ "vbvBufferSize", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_vbvBufferSize },
	{ "samplesPerLine", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_samplesPerLine },
	{ "linesPerFrame", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_linesPerFrame },
	{ "pictureRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_pictureRate },
	{ "luminanceSampleRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_luminanceSampleRate },
	{ "videoBadMBsCap", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoBadMBsCap },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_IS11172VideoCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_IS11172VideoCapability, ett_h245_IS11172VideoCapability, IS11172VideoCapability_sequence);

	return offset;
}




static int
dissect_h245_g711Alaw64k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g711Alaw64k, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_g711Alaw56k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g711Alaw56k, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_g711Ulaw64k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g711Ulaw64k, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_g711Ulaw56k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g711Ulaw56k, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_g722_64k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g722_64k, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_g722_56k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g722_56k, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_g722_48k(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g722_48k, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_maxAl_sduAudioFrames(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maxAl_sduAudioFrames, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t AudioCapability_g7231_sequence[] = {
	{ "maxAl-sduAudioFrames", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_maxAl_sduAudioFrames },
	{ "silenceSuppression", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_silenceSuppression },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_AudioCapability_g7231(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_AudioCapability_g7231, ett_h245_AudioCapability_g7231, AudioCapability_g7231_sequence);

	return offset;
}




static int
dissect_h245_g728(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g728, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_g729(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g729, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_g729AnnexA(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g729AnnexA, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_g729wAnnexB(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g729wAnnexB, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_g729AnnexAwAnnexB(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_g729AnnexAwAnnexB, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_audioUnit(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_audioUnit, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t G729Extensions_sequence[] = {
	{ "audioUnit", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_audioUnit },
	{ "annexA", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_annexA },
	{ "annexB", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_annexB },
	{ "annexD", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_annexD },
	{ "annexE", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_annexE },
	{ "annexF", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_annexF },
	{ "annexG", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_annexG },
	{ "annexH", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_annexH },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_G729Extensions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_G729Extensions, ett_h245_G729Extensions, G729Extensions_sequence);

	return offset;
}




static int
dissect_h245_highRateMode0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_highRateMode0, 27, 78,
		NULL, NULL, FALSE);

	return offset;
}


static int
dissect_h245_highRateMode1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_highRateMode1, 27, 78,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_lowRateMode0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_lowRateMode0, 23, 66,
		NULL, NULL, FALSE);

	return offset;
}


static int
dissect_h245_lowRateMode1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_lowRateMode1, 23, 66,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_sidMode0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_sidMode0, 6, 17,
		NULL, NULL, FALSE);

	return offset;
}


static int
dissect_h245_sidMode1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_sidMode1, 6, 17,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t G7231AnnexCCapability_g723AnnexCAudioMode_sequence[] = {
	{ "highRateMode0", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_highRateMode0 },
	{ "highRateMode1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_highRateMode1 },
	{ "lowRateMode0", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_lowRateMode0 },
	{ "lowRateMode1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_lowRateMode1 },
	{ "sidMode0", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_sidMode0 },
	{ "sidMode1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_sidMode1 },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_G7231AnnexCCapability_g723AnnexCAudioMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_G7231AnnexCCapability_g723AnnexCAudioMode, ett_h245_G7231AnnexCCapability_g723AnnexCAudioMode, G7231AnnexCCapability_g723AnnexCAudioMode_sequence);

	return offset;
}




static per_sequence_t G7231AnnexCCapability_sequence[] = {
	{ "maxAl-sduAudioFrames", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxAl_sduAudioFrames },
	{ "silenceSuppression", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_silenceSuppression },
	{ "g723AnnexCAudioMode", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_G7231AnnexCCapability_g723AnnexCAudioMode },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_G7231AnnexCCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_G7231AnnexCCapability, ett_h245_G7231AnnexCCapability, G7231AnnexCCapability_sequence);

	return offset;
}



static per_sequence_t G7231AnnexCMode_g723AnnexCAudioMode_sequence[] = {
	{ "highRateMode0", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_highRateMode0 },
	{ "highRateMode1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_highRateMode1 },
	{ "lowRateMode0", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_lowRateMode0 },
	{ "lowRateMode1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_lowRateMode0 },
	{ "sidMode0", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_sidMode0 },
	{ "sidMode1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_sidMode1 },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_G7231AnnexCMode_g723AnnexCAudioMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_G7231AnnexCMode_g723AnnexCAudioMode, ett_h245_G7231AnnexCMode_g723AnnexCAudioMode, G7231AnnexCMode_g723AnnexCAudioMode_sequence);

	return offset;
}




static per_sequence_t G7231AnnexCMode_sequence[] = {
	{ "maxAl-sduAudioFrames", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxAl_sduAudioFrames },
	{ "silenceSupression", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_silenceSuppression },
	{ "g723AnnexCAudioMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_G7231AnnexCMode_g723AnnexCAudioMode },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_G7231AnnexCMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_G7231AnnexCMode, ett_h245_G7231AnnexCMode, G7231AnnexCMode_sequence);

	return offset;
}




static int
dissect_h245_audioUnitSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_audioUnitSize, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}





static per_sequence_t GSMAudioCapability_sequence[] = {
	{ "audioUnitSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioUnitSize },
	{ "comfortNoice", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_comfortNoise },
	{ "scrambled", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_scrambled },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_GSMAudioCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_GSMAudioCapability, ett_h245_GSMAudioCapability, GSMAudioCapability_sequence);

	return offset;
}





static int
dissect_h245_maxBitRate_4294967295UL(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* XXX unit is 100bit/s */
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maxBitRate_4294967295UL, 0, 4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}





static int
dissect_h245_numberOfCodewords(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_numberOfCodewords, 1, 65536,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_maximumStringLength(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_maximumStringLength, 1, 256,
		NULL, NULL, FALSE);

	return offset;
}





static per_sequence_t V42bis_sequence[] = {
	{ "numberOfCodewords", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_numberOfCodewords },
	{ "maximumStringLength", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maximumStringLength },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_V42bis(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_V42bis, ett_h245_V42bis, V42bis_sequence);

	return offset;
}



static const value_string CompressionType_vals[] = {
	{  0, "v42bis" },
	{  0, NULL }
};
static per_choice_t CompressionType_choice[] = {
	{  0, "v42bis", ASN1_EXTENSION_ROOT,
		dissect_h245_V42bis },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_CompressionType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_CompressionType, ett_h245_CompressionType, CompressionType_choice, "CompressionType", NULL);

	return offset;
}





static const value_string DataProtocolCapability_v76wCompression_vals[] = {
	{  0, "transmitCompression" },
	{  1, "receiveCompression" },
	{  2, "transmitAndReceiveCompression" },
	{  0, NULL }
};
static per_choice_t DataProtocolCapability_v76wCompression_choice[] = {
	{  0, "transmitCompression", ASN1_EXTENSION_ROOT,
		dissect_h245_CompressionType },
	{  1, "receiveCompression", ASN1_EXTENSION_ROOT,
		dissect_h245_CompressionType },
	{  2, "transmitAndReceiveCompression", ASN1_EXTENSION_ROOT,
		dissect_h245_CompressionType },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_DataProtocolCapability_v76wCompression(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_DataProtocolCapability_v76wCompression, ett_h245_DataProtocolCapability_v76wCompression, DataProtocolCapability_v76wCompression_choice, "v76wCompression", NULL);

	return offset;
}





static int
dissect_h245_version(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_version, 0, 255,
		NULL, NULL, FALSE);

	return offset;
}



static int dissect_h245_T38FaxUdpOptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static per_sequence_t T38FaxProfile_sequence[] = {
	{ "fillBitRemoval", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_fillBitRemoval },
	{ "transcodingJBIG", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_transcodingJBIG },
	{ "transcodingMMR", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_transcodingMMR },
	{ "version", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_version },
	{ "t38FaxRateManagement", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_T38FaxRateManagement },
	{ "t38FaxUdpOptions", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_T38FaxUdpOptions },
	{ "t38FaxTcpOptions", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_T38FaxTcpOptions },
	{ NULL, 0, 0, NULL }
};
int
dissect_h245_T38FaxProfile(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_T38FaxProfile, ett_h245_T38FaxProfile, T38FaxProfile_sequence);

	return offset;
}




static int
dissect_h245_standard_0_127(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_standard_0_127, 0, 127,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_booleanArray(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_booleanArray, 0, 255,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_unsignedMin(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_unsignedMin, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}


static int
dissect_h245_unsignedMax(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_unsignedMax, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_unsigned32Min(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_unsigned32Min, 0, 4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}


static int
dissect_h245_unsigned32Max(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_unsigned32Max, 0, 4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_dynamicRTPPayloadType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_dynamicRTPPayloadType, 96, 127,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t AudioToneCapability_sequence[] = {
	{ "dynamicRTPPayloadType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dynamicRTPPayloadType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_AudioToneCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_AudioToneCapability, ett_h245_AudioToneCapability, AudioToneCapability_sequence);

	return offset;
}




static per_sequence_t NoPTAudioToneCapability_sequence[] = {
	{ NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};
static int
dissect_h245_NoPTAudioToneCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NoPTAudioToneCapability, ett_h245_NoPTAudioToneCapability, NoPTAudioToneCapability_sequence);

	return offset;
}





static int
dissect_h245_portNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_portNumber, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_resourceID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_resourceID, 0, 65535,
		NULL, NULL, FALSE);

	return offset;
}




static const value_string FlowControlCommand_scope_vals[] = {
	{  0, "logicalChannelNumber" },
	{  1, "resourceID" },
	{  2, "wholeMultiplex" },
	{  0, NULL }
};
static per_choice_t FlowControlCommand_scope_choice[] = {
	{  0, "logicalChannelNumber", ASN1_NO_EXTENSIONS,
			dissect_h245_LogicalChannelNumber },
	{  1, "resourceID", ASN1_NO_EXTENSIONS,
			dissect_h245_resourceID },
	{  2, "wholeMultiplex", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FlowControlCommand_scope(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FlowControlCommand_scope, ett_h245_FlowControlCommand_scope, FlowControlCommand_scope_choice, "scope", NULL);

	return offset;
}






static const value_string JitterIndication_scope_vals[] = {
	{  0, "logicalChannelNumber" },
	{  1, "resourceID" },
	{  2, "wholeMultiplex" },
	{  0, NULL }
};
static per_choice_t JitterIndication_scope_choice[] = {
	{  0, "logicalChannelNumber", ASN1_NO_EXTENSIONS,
			dissect_h245_LogicalChannelNumber },
	{  1, "resourceID", ASN1_NO_EXTENSIONS,
			dissect_h245_resourceID },
	{  2, "wholeMultiplex", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_JitterIndication_scope(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_JitterIndication_scope, ett_h245_JitterIndication_scope, JitterIndication_scope_choice, "scope", NULL);

	return offset;
}





static const value_string FlowControlIndication_scope_vals[] = {
	{  0, "logicalChannelNumber" },
	{  1, "resouceID" },
	{  2, "wholeMultiplex" },
	{  0, NULL }
};
static per_choice_t FlowControlIndication_scope_choice[] = {
	{  0, "logicalChannelNumber", ASN1_NO_EXTENSIONS,
			dissect_h245_LogicalChannelNumber },
	{  1, "resourceID", ASN1_NO_EXTENSIONS,
			dissect_h245_resourceID },
	{  2, "wholeMultiplex", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FlowControlIndication_scope(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FlowControlIndication_scope, ett_h245_FlowControlIndication_scope, FlowControlIndication_scope_choice, "scope", NULL);

	return offset;
}




static per_sequence_t NewATMVCIndication_sequence[] = {
	{ "resourceID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_resourceID },
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ATM_BitRate },
	{ "bitRateLockedToPCRClock", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_bitRateLockedToPCRClock },
	{ "bitRateLockedToNetworkClock", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_bitRateLockedToNetworkClock },
	{ "aal", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCIndication_aal },
	{ "multiplex", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCIndication_multiplex },
	{ "reverseParameters", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCIndication_reverseParameters },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NewATMVCIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NewATMVCIndication, ett_h245_NewATMVCIndication, NewATMVCIndication_sequence);

	return offset;
}




static int
dissect_h245_subChannelID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_subChannelID, 0, 8191,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_pcr_pid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_pcr_pid, 0, 8191,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_controlFieldOctets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_controlFieldOctets, 0, 2,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_sendBufferSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_sendBufferSize, 0, 16777215,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t H223LogicalChannelParameters_adaptionLayerType_al3_sequence[] = {
	{ "controlFieldOctets", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_controlFieldOctets },
	{ "sendBufferSize", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_sendBufferSize },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223LogicalChannelParameters_adaptionLayerType_al3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223LogicalChannelParameters_adaptionLayerType_al3, ett_h245_H223LogicalChannelParameters_adaptionLayerType_al3, H223LogicalChannelParameters_adaptionLayerType_al3_sequence);

	return offset;
}



static per_sequence_t H223ModeParameters_adaptationLayerType_al3_sequence[] = {
	{ "controlFieldOctets", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_controlFieldOctets },
	{ "sendBufferSize", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_sendBufferSize },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223ModeParameters_adaptationLayerType_al3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223ModeParameters_adaptationLayerType_al3, ett_h245_H223ModeParameters_adaptationLayerType_al3, H223ModeParameters_adaptationLayerType_al3_sequence);

	return offset;
}




static int
dissect_h245_rcpcCodeRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_rcpcCodeRate, 8, 32,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_rsCodeCorrection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_rsCodeCorrection, 0, 127,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_finite_0_16(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_finite_0_16, 0, 16,
		NULL, NULL, FALSE);

	return offset;
}





static const value_string H223AnnexCArqParameters_numberOfRetransmissions_vals[] = {
	{  0, "finite" },
	{  1, "infinite" },
	{  0, NULL }
};
static per_choice_t H223AnnexCArqParameters_numberOfRetransmissions_choice[] = {
	{  0, "finite", ASN1_EXTENSION_ROOT,
			dissect_h245_finite_0_16 },
	{  1, "infinite", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223AnnexCArqParameters_numberOfRetransmissions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223AnnexCArqParameters_numberOfRetransmissions, ett_h245_H223AnnexCArqParameters_numberOfRetransmissions, H223AnnexCArqParameters_numberOfRetransmissions_choice, "numberOfRetransmissions", NULL);

	return offset;
}




static per_sequence_t H223AnnexCArqParameters_sequence[] = {
	{ "numberOfRetransmissions", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223AnnexCArqParameters_numberOfRetransmissions },
	{ "sendBufferSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_sendBufferSize },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223AnnexCArqParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223AnnexCArqParameters, ett_h245_H223AnnexCArqParameters, H223AnnexCArqParameters_sequence);

	return offset;
}





static const value_string H223AL1MParameters_arqType_vals[] = {
	{  0, "noArq" },
	{  1, "typeIArq" },
	{  2, "typeIIArq" },
	{  0, NULL }
};
static per_choice_t H223AL1MParameters_arqType_choice[] = {
	{  0, "noArq", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "typeIArq", ASN1_EXTENSION_ROOT,
			dissect_h245_H223AnnexCArqParameters },
	{  2, "typeIIArq", ASN1_EXTENSION_ROOT,
			dissect_h245_H223AnnexCArqParameters },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223AL1MParameters_arqType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223AL1MParameters_arqType, ett_h245_H223AL1MParameters_arqType, H223AL1MParameters_arqType_choice, "arqType", NULL);

	return offset;
}




static const value_string H223AL3MParameters_arqType_vals[] = {
	{  0, "noArq" },
	{  1, "typeIArq" },
	{  2, "typeIIArq" },
	{  0, NULL }
};
static per_choice_t H223AL3MParameters_arqType_choice[] = {
	{  0, "noArq", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "typeIArq", ASN1_EXTENSION_ROOT,
			dissect_h245_H223AnnexCArqParameters },
	{  2, "typeIIArq", ASN1_EXTENSION_ROOT,
			dissect_h245_H223AnnexCArqParameters },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223AL3MParameters_arqType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223AL3MParameters_arqType, ett_h245_H223AL3MParameters_arqType, H223AL3MParameters_arqType_choice, "arqType", NULL);

	return offset;
}





static per_sequence_t H223AL1MParameters_sequence[] = {
	{ "transferMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223AL1MParameters_transferMode },
	{ "headerFEC", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223AL1MParameters_headerFEC },
	{ "crcLength", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223AL1MParameters_crcLength },
	{ "rcpcCodeRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_rcpcCodeRate },
	{ "arqType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223AL1MParameters_arqType },
	{ "alpduInterleaving", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_alpduInterleaving },
	{ "alsduSplitting", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_alsduSplitting },
	{ "rsCodeCorrection", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_rsCodeCorrection },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223AL1MParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223AL1MParameters, ett_h245_H223AL1MParameters, H223AL1MParameters_sequence);

	return offset;
}




static per_sequence_t H223AL3MParameters_sequence[] = {
	{ "headerFormat", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223AL3MParameters_headerFormat },
	{ "crcLength", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223AL3MParameters_crcLength },
	{ "rcpcCodeRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_rcpcCodeRate },
	{ "arqType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223AL3MParameters_arqType },
	{ "alpduInterleaving", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_alpduInterleaving },
	{ "rsCodeCorrection", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_rsCodeCorrection },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223AL3MParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223AL3MParameters, ett_h245_H223AL3MParameters, H223AL3MParameters_sequence);

	return offset;
}





static int
dissect_h245_windowSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_windowSize, 1, 127,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t V76LogicalChannelParameters_mode_eRM_sequence[] = {
	{ "windowSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_windowSize },
	{ "recovery", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_V76LogicalChannelParameters_mode_eRM_recovery },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_V76LogicalChannelParameters_mode_eRM(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_V76LogicalChannelParameters_mode_eRM, ett_h245_V76LogicalChannelParameters_mode_eRM, V76LogicalChannelParameters_mode_eRM_sequence);

	return offset;
}



static const value_string V76LogicalChannelParameters_mode_vals[] = {
	{  0, "eRM" },
	{  1, "uNERM" },
	{  0, NULL }
};
static per_choice_t V76LogicalChannelParameters_mode_choice[] = {
	{  0, "eRM", ASN1_EXTENSION_ROOT,
			dissect_h245_V76LogicalChannelParameters_mode_eRM },
	{  1, "uNERM", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_V76LogicalChannelParameters_mode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_V76LogicalChannelParameters_mode, ett_h245_V76LogicalChannelParameters_mode, V76LogicalChannelParameters_mode_choice, "mode", NULL);

	return offset;
}




static int
dissect_h245_n401(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_n401, 1, 4095,
		NULL, NULL, FALSE);

	return offset;
}





static per_sequence_t V76HDLCParameters_sequence[] = {
	{ "crcLength", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_CRCLength },
	{ "n401", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_n401 },
	{ "loopbackTestProcedure", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_loopbackTestProcedure },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_V76HDLCParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_V76HDLCParameters, ett_h245_V76HDLCParameters, V76HDLCParameters_sequence);

	return offset;
}




static per_sequence_t V76LogicalChannelParameters_sequence[] = {
	{ "hdlcParameters", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_V76HDLCParameters },
	{ "suspendResume", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_V76LogicalChannelParameters_suspendResume },
	{ "uIH", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_uIH },
	{ "mode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_V76LogicalChannelParameters_mode },
	{ "v75Parameters", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_V75Parameters },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_V76LogicalChannelParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_V76LogicalChannelParameters, ett_h245_V76LogicalChannelParameters, V76LogicalChannelParameters_sequence);

	return offset;
}



static int
dissect_h245_sessionID_0_255(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_sessionID_0_255, 0, 255,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_sessionID_1_255(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_sessionID_1_255, 1, 255,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_associatedSessionID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_associatedSessionID, 1, 255,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_payloadType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_payloadType,  0,  127,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_protectedSessionID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_protectedSessionID,  1,  255,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_protectedPayloadType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_protectedPayloadType,  0,  127,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t FECData_rfc2733_mode_separateStream_differentPort_sequence[] = {
	{ "protectedSessionID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_protectedSessionID },
	{ "protectedPayloadType", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_protectedPayloadType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FECData_rfc2733_mode_separateStream_differentPort(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FECData_rfc2733_mode_separateStream_differentPort, ett_h245_FECData_rfc2733_mode_separateStream_differentPort, FECData_rfc2733_mode_separateStream_differentPort_sequence);

	return offset;
}




static per_sequence_t FECData_rfc2733_mode_separateStream_samePort_sequence[] = {
	{ "protectedPayloadType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_protectedPayloadType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FECData_rfc2733_mode_separateStream_samePort(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FECData_rfc2733_mode_separateStream_samePort, ett_h245_FECData_rfc2733_mode_separateStream_samePort, FECData_rfc2733_mode_separateStream_samePort_sequence);

	return offset;
}



static const value_string FECData_rfc2733_mode_separateStream_vals[] = {
	{  0, "differentPort" },
	{  1, "samePort" },
	{  0, NULL }
};
static per_choice_t FECData_rfc2733_mode_separateStream_choice[] = {
	{  0, "differentPort", ASN1_EXTENSION_ROOT,
		dissect_h245_FECData_rfc2733_mode_separateStream_differentPort },
	{  1, "samePort", ASN1_EXTENSION_ROOT,
		dissect_h245_FECData_rfc2733_mode_separateStream_samePort },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FECData_rfc2733_mode_separateStream(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FECData_rfc2733_mode_separateStream, ett_h245_FECData_rfc2733_mode_separateStream, FECData_rfc2733_mode_separateStream_choice, "separateStream", NULL);

	return offset;
}




static const value_string FECData_rfc2733_mode_vals[] = {
	{  0, "redundancyEncoding" },
	{  1, "separateStream" },
	{  0, NULL }
};
static per_choice_t FECData_rfc2733_mode_choice[] = {
	{  0, "redundancyEncoding", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "separateStream", ASN1_EXTENSION_ROOT,
			dissect_h245_FECData_rfc2733_mode_separateStream },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FECData_rfc2733_mode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FECData_rfc2733_mode, ett_h245_FECData_rfc2733_mode, FECData_rfc2733_mode_choice, "mode", NULL);

	return offset;
}




static per_sequence_t FECData_rfc2733_sequence[] = {
	{ "mode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_FECData_rfc2733_mode },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FECData_rfc2733(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FECData_rfc2733, ett_h245_FECData_rfc2733, FECData_rfc2733_sequence);

	return offset;
}




static const value_string FECData_vals[] = {
	{  0, "rfc2733" },
	{  0, NULL }
};
static per_choice_t FECData_choice[] = {
	{  0, "rfc2733", ASN1_NO_EXTENSIONS,
		dissect_h245_FECData_rfc2733 },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FECData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FECData, ett_h245_FECData, FECData_choice, "FECData", NULL);

	return offset;
}




static per_sequence_t FECMode_rfc2733Mode_mode_separateStream_differentPort_sequence[] = {
	{ "protectedSessionID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_protectedSessionID },
	{ "protectedPayloadType", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_protectedPayloadType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FECMode_rfc2733Mode_mode_separateStream_differentPort(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FECMode_rfc2733Mode_mode_separateStream_differentPort, ett_h245_FECMode_rfc2733Mode_mode_separateStream_differentPort, FECMode_rfc2733Mode_mode_separateStream_differentPort_sequence);

	return offset;
}




static int
dissect_h245_tsapIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_tsapIdentifier,  0,  65535,
		&ipv4_port, NULL, FALSE);

	return offset;
}



static int
dissect_h245_synchFlag(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_synchFlag,  0,  255,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_finite_1_65535(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_finite_1_65535,  1,  65535,
		NULL, NULL, FALSE);

	return offset;
}




static const value_string MultiplexElement_repeatCount_vals[] = {
	{  0, "finite" },
	{  1, "untilClosingFlag" },
	{  0, NULL }
};
static per_choice_t MultiplexElement_repeatCount_choice[] = {
	{  0, "finite", ASN1_NO_EXTENSIONS,
			dissect_h245_finite_1_65535 },
	{  1, "untilClosingFlag", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultiplexElement_repeatCount(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultiplexElement_repeatCount, ett_h245_MultiplexElement_repeatCount, MultiplexElement_repeatCount_choice, "repeatCount", NULL);

	return offset;
}




static int
dissect_h245_MultiplexTableEntryNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_MultiplexTableEntryNumber,  1,  15,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t MultiplexEntryRejectionDescriptions_sequence[] = {
	{ "multiplexTableEntryNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MultiplexTableEntryNumber },
	{ "cause", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MultiplexEntryRejectionDescriptions_cause },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplexEntryRejectionDescriptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplexEntryRejectionDescriptions, ett_h245_MultiplexEntryRejectionDescriptions, MultiplexEntryRejectionDescriptions_sequence);

	return offset;
}




static per_sequence_t RequestMultiplexEntryRejectionDescriptions_sequence[] = {
	{ "multiplexTableEntryNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MultiplexTableEntryNumber },
	{ "cause", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RequestMultiplexEntryRejectionDescriptions_cause},
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestMultiplexEntryRejectionDescriptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestMultiplexEntryRejectionDescriptions, ett_h245_RequestMultiplexEntryRejectionDescriptions, RequestMultiplexEntryRejectionDescriptions_sequence);

	return offset;
}




static int
dissect_h245_dataModeBitRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_dataModeBitRate,  0,  4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_sessionDependency(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_sessionDependency,  1,  255,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_sRandom(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_sRandom,  1,  4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_McuNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_McuNumber,  0,  192,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_TerminalNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_TerminalNumber,  0,  192,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t TerminalLabel_sequence[] = {
	{ "mcuNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_McuNumber },
	{ "terminalNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_TerminalLabel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_TerminalLabel, ett_h245_TerminalLabel, TerminalLabel_sequence);

	return offset;
}





static int
dissect_h245_maxNumberOfAdditionalConnections(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_maxNumberOfAdditionalConnections,  1,  65535,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t MultilinkRequest_callInformation_sequence[] = {
	{ "maxNumberOfAdditionalConnections", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxNumberOfAdditionalConnections },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultilinkRequest_callInformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultilinkRequest_callInformation, ett_h245_MultilinkRequest_callInformation, MultilinkRequest_callInformation_sequence);

	return offset;
}





static int
dissect_h245_requestedInterval(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_requestedInterval,  0,  65535,
		NULL, NULL, FALSE);

	return offset;
}




static const value_string MultilinkRequest_maximumHeaderInterval_requestType_vals[] = {
	{  0, "currentIntervalInformation" },
	{  1, "requestedInterval" },
	{  0, NULL }
};
static per_choice_t MultilinkRequest_maximumHeaderInterval_requestType_choice[] = {
	{  0, "currentIntervalInformation", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "requestedInterval", ASN1_EXTENSION_ROOT,
			dissect_h245_requestedInterval },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultilinkRequest_maximumHeaderInterval_requestType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultilinkRequest_maximumHeaderInterval_requestType, ett_h245_MultilinkRequest_maximumHeaderInterval_requestType, MultilinkRequest_maximumHeaderInterval_requestType_choice, "requestType", NULL);

	return offset;
}




static per_sequence_t MultilinkRequest_maximumHeaderInterval_sequence[] = {
	{ "requestType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MultilinkRequest_maximumHeaderInterval_requestType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultilinkRequest_maximumHeaderInterval(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultilinkRequest_maximumHeaderInterval, ett_h245_MultilinkRequest_maximumHeaderInterval, MultilinkRequest_maximumHeaderInterval_sequence);

	return offset;
}




static int
dissect_h245_callAssociationNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_callAssociationNumber,  0,  4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_currentInterval(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_currentInterval,  0,  65535,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t MultilinkResponse_maximumHeaderInterval_sequence[] = {
	{ "currentInterval", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_currentInterval },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultilinkResponse_maximumHeaderInterval(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultilinkResponse_maximumHeaderInterval, ett_h245_MultilinkResponse_maximumHeaderInterval, MultilinkResponse_maximumHeaderInterval_sequence);

	return offset;
}




static int
dissect_h245_infoNotAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_infoNotAvailable,  1,  65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_channelTag(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_channelTag,  0,  4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_ConnectionIDsequenceNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_ConnectionIDsequenceNumber,  0,  4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}





static per_sequence_t ConnectionIdentifier_sequence[] = {
	{ "channelTag", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_channelTag },
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ConnectionIDsequenceNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ConnectionIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ConnectionIdentifier, ett_h245_ConnectionIdentifier, ConnectionIdentifier_sequence);

	return offset;
}




static per_sequence_t MultilinkRequest_removeConnection_sequence[] = {
	{ "connectionIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ConnectionIdentifier },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultilinkRequest_removeConnection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultilinkRequest_removeConnection, ett_h245_MultilinkRequest_removeConnection, MultilinkRequest_removeConnection_sequence);

	return offset;
}




static per_sequence_t MultilinkResponse_removeConnection_sequence[] = {
	{ "connectionIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ConnectionIdentifier },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultilinkResponse_removeConnection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultilinkResponse_removeConnection, ett_h245_MultilinkResponse_removeConnection, MultilinkResponse_removeConnection_sequence);

	return offset;
}




static per_sequence_t MultilinkIndication_excessiveError_sequence[] = {
	{ "connectionIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ConnectionIdentifier },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultilinkIndication_excessiveError(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultilinkIndication_excessiveError, ett_h245_MultilinkIndication_excessiveError, MultilinkIndication_excessiveError_sequence);

	return offset;
}




static int
dissect_h245_MaximumBitRate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_MaximumBitRate,  0,  4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t LogicalChannelRateRequest_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "logicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "maximumBitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MaximumBitRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_LogicalChannelRateRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_LogicalChannelRateRequest, ett_h245_LogicalChannelRateRequest, LogicalChannelRateRequest_sequence);

	return offset;
}



static per_sequence_t LogicalChannelRateAck_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "logicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "maximumBitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MaximumBitRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_LogicalChannelRateAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_LogicalChannelRateAck, ett_h245_LogicalChannelRateAck, LogicalChannelRateAck_sequence);

	return offset;
}




static per_sequence_t LogicalChannelRateReject_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_SequenceNumber },
	{ "logicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_LogicalChannelNumber },
	{ "rejectReason", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_LogicalChannelRateRejectReason },
	{ "currentMaximumBitRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
			dissect_h245_MaximumBitRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_LogicalChannelRateReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_LogicalChannelRateReject, ett_h245_LogicalChannelRateReject, LogicalChannelRateReject_sequence);

	return offset;
}





static per_sequence_t LogicalChannelRateRelease_sequence[] = {
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_LogicalChannelRateRelease(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_LogicalChannelRateRelease, ett_h245_LogicalChannelRateRelease, LogicalChannelRateRelease_sequence);

	return offset;
}




static int
dissect_h245_maximumBitRate_0_16777215(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_maximumBitRate_0_16777215,  0,  16777215,
		NULL, NULL, FALSE);

	return offset;
}



static const value_string FlowControlCommand_restriction_vals[] = {
	{  0, "maximumBitRate" },
	{  1, "noRestriction" },
	{  0, NULL }
};
static per_choice_t FlowControlCommand_restriction_choice[] = {
	{  0, "maximumBitRate", ASN1_NO_EXTENSIONS,
			dissect_h245_maximumBitRate_0_16777215 },
	{  1, "noRestriction", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FlowControlCommand_restriction(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FlowControlCommand_restriction, ett_h245_FlowControlCommand_restriction, FlowControlCommand_restriction_choice, "restriction", NULL);

	return offset;
}




static const value_string FlowControlIndication_restriction_vals[] = {
	{  0, "maximumBitRate" },
	{  1, "noRestriction" },
	{  0, NULL }
};
static per_choice_t FlowControlIndication_restriction_choice[] = {
	{  0, "maximumBitRate", ASN1_NO_EXTENSIONS,
			dissect_h245_maximumBitRate_0_16777215 },
	{  1, "noRestrictions", ASN1_NO_EXTENSIONS,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FlowControlIndication_restriction(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FlowControlIndication_restriction, ett_h245_FlowControlIndication_restriction, FlowControlIndication_restriction_choice, "restriction", NULL);

	return offset;
}




static per_sequence_t FlowControlCommand_sequence[] = {
	{ "scope", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_FlowControlCommand_scope },
	{ "restriction", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_FlowControlCommand_restriction },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FlowControlCommand(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FlowControlCommand, ett_h245_FlowControlCommand, FlowControlCommand_sequence);

	return offset;
}



static per_sequence_t FlowControlIndication_sequence[] = {
	{ "scope", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_FlowControlIndication_scope },
	{ "restriction", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_FlowControlIndication_restriction },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FlowControlIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FlowControlIndication, ett_h245_FlowControlIndication, FlowControlIndication_sequence);

	return offset;
}




static int
dissect_h245_firstGOB_0_17(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_firstGOB_0_17,  0,  17,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_numberOfGOBs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_numberOfGOBs,  1,  18,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t MiscellaneousCommand_type_videoFastUpdateGOB_sequence[] = {
	{ "firstGOB", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_firstGOB_0_17 },
	{ "numberOfGOBs", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_numberOfGOBs },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MiscellaneousCommand_type_videoFastUpdateGOB(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MiscellaneousCommand_type_videoFastUpdateGOB, ett_h245_MiscellaneousCommand_type_videoFastUpdateGOB, MiscellaneousCommand_type_videoFastUpdateGOB_sequence);

	return offset;
}




static int
dissect_h245_videoTemporalSpatialTradeOff(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_videoTemporalSpatialTradeOff,  0,  31,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_firstGOB_0_255(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_firstGOB_0_255,  0,  255,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_firstMB_1_8192(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_firstMB_1_8192,  1,  8192,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_firstMB_1_9216(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_firstMB_1_9216,  1,  9216,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_numberOfMBs_1_8192(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_numberOfMBs_1_8192,  1,  8192,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_numberOfMBs_1_9216(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_numberOfMBs_1_9216,  1,  9216,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t MiscellaneousCommand_type_videoFastUpdateMB_sequence[] = {
	{ "firstGOB", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_firstGOB_0_255 },
	{ "firstMB", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_firstMB_1_8192 },
	{ "numberOfMBs", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_numberOfMBs_1_8192 },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MiscellaneousCommand_type_videoFastUpdateMB(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MiscellaneousCommand_type_videoFastUpdateMB, ett_h245_MiscellaneousCommand_type_videoFastUpdateMB, MiscellaneousCommand_type_videoFastUpdateMB_sequence);

	return offset;
}




static int
dissect_h245_maxH223MUXPDUsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_maxH223MUXPDUsize,  1,  65535,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_temporalReference_0_1023(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_temporalReference_0_1023,  0,  1023,
		NULL, NULL, FALSE);

	return offset;
}






static int
dissect_h245_temporalReference_0_255(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_temporalReference_0_255,  0,  255,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t MiscellaneousIndication_type_videoNotDecodedMBs_sequence[] = {
	{ "firstMB", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_firstMB_1_8192 },
	{ "numberOfMBs", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_numberOfMBs_1_8192 },
	{ "temporalReference", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_temporalReference_0_255 },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MiscellaneousIndication_type_videoNotDecodedMBs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MiscellaneousIndication_type_videoNotDecodedMBs, ett_h245_MiscellaneousIndication_type_videoNotDecodedMBs, MiscellaneousIndication_type_videoNotDecodedMBs_sequence);

	return offset;
}





static per_sequence_t MiscellaneousCommand_type_videoBadMBs_sequence[] = {
	{ "firstMB", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_firstMB_1_9216 },
	{ "numberOfMBs", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_numberOfMBs_1_9216 },
	{ "temporalReference", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_temporalReference_0_1023 },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MiscellaneousCommand_type_videoBadMBs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MiscellaneousCommand_type_videoBadMBs, ett_h245_MiscellaneousCommand_type_videoBadMBs, MiscellaneousCommand_type_videoBadMBs_sequence);

	return offset;
}




static int
dissect_h245_pictureNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_pictureNumber,  0,  1023,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_longTermPictureIndex(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_longTermPictureIndex,  0,  255,
		NULL, NULL, FALSE);

	return offset;
}




static const value_string PictureReference_vals[] = {
	{  0, "pictureNumber" },
	{  1, "longTermPictureIndex" },
	{  0, NULL }
};
static per_choice_t PictureReference_choice[] = {
	{  0, "pictureNumber", ASN1_EXTENSION_ROOT,
		dissect_h245_pictureNumber },
	{  1, "longTermPictureIndex", ASN1_EXTENSION_ROOT,
		dissect_h245_longTermPictureIndex },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_PictureReference(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_PictureReference, ett_h245_PictureReference, PictureReference_choice, "PictureReference", NULL);

	return offset;
}




static per_sequence_t MiscellaneousCommand_type_lostPartialPicture_sequence[] = {
	{ "pictureReference", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_PictureReference },
	{ "firstMB", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_firstMB_1_9216 },
	{ "numberOfMBs", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_numberOfMBs_1_9216 },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MiscellaneousCommand_type_lostPartialPicture(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MiscellaneousCommand_type_lostPartialPicture, ett_h245_MiscellaneousCommand_type_lostPartialPicture, MiscellaneousCommand_type_lostPartialPicture_sequence);

	return offset;
}




static int
dissect_h245_sampleSize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_sampleSize,  1,  255,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_samplesPerFrame(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_samplesPerFrame,  1,  255,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t MobileMultilinkReconfigurationIndication_sequence[] = {
	{ "sampleSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_sampleSize },
	{ "samplesPerFrame", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_samplesPerFrame },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MobileMultilinkReconfigurationIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MobileMultilinkReconfigurationIndication, ett_h245_MobileMultilinkReconfigurationIndication, MobileMultilinkReconfigurationIndication_sequence);

	return offset;
}




static per_sequence_t MobileMultilinkReconfigurationCommand_sequence[] = {
	{ "sampleSize", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_sampleSize },
	{ "samplesPerFrame", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_samplesPerFrame },
	{ "status", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MobileMultilinkReconfigurationCommand_status },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MobileMultilinkReconfigurationCommand(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MobileMultilinkReconfigurationCommand, ett_h245_MobileMultilinkReconfigurationCommand, MobileMultilinkReconfigurationCommand_sequence);

	return offset;
}




static int
dissect_h245_sbeNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_sbeNumber,  0,  9,
		NULL, NULL, FALSE);

	return offset;
}







static int
dissect_h245_subPictureNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_subPictureNumber,  0,  255,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t TerminalYouAreSeeingInSubPictureNumber_sequence[] = {
	{ "terminalNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalNumber },
	{ "subPictureNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_subPictureNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_TerminalYouAreSeeingInSubPictureNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_TerminalYouAreSeeingInSubPictureNumber, ett_h245_TerminalYouAreSeeingInSubPictureNumber, TerminalYouAreSeeingInSubPictureNumber_sequence);

	return offset;
}



static int
dissect_h245_compositionNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_compositionNumber,  0,  255,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t VideoIndicateCompose_sequence[] = {
	{ "compositionNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_compositionNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_VideoIndicateCompose(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_VideoIndicateCompose, ett_h245_VideoIndicateCompose, VideoIndicateCompose_sequence);

	return offset;
}




static const value_string ConferenceIndication_vals[] = {
	{  0, "sbeNumber" },
	{  1, "terminalNumberAssign" },
	{  2, "terminalJoinedConference" },
	{  3, "terminalLeftConference" },
	{  4, "seenByAtLeastOneOther" },
	{  5, "cancelSeenByAtLeastOneOther" },
	{  6, "seenByAll" },
	{  7, "cancelSeenByAll" },
	{  8, "terminalAreYouSeeing" },
	{  9, "requestForFloor" },
	{ 10, "withdrawChairToken" },
	{ 11, "floorRequested" },
	{ 12, "terminalAreYouSeeingInSubPictureNumber" },
	{ 13, "videoIndicateCompose" },
	{  0, NULL }
};
static per_choice_t ConferenceIndication_choice[] = {
	{  0, "sbeNumber", ASN1_EXTENSION_ROOT,
			dissect_h245_sbeNumber },
	{  1, "terminalNumberAssign", ASN1_EXTENSION_ROOT,
			dissect_h245_TerminalLabel },
	{  2, "terminalJoinedConference", ASN1_EXTENSION_ROOT,
			dissect_h245_TerminalLabel },
	{  3, "terminalLeftConference", ASN1_EXTENSION_ROOT,
			dissect_h245_TerminalLabel },
	{  4, "seenByAtLeastOneOther", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "cancelSeenByAtLeastOneOther", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  6, "seenByAll", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  7, "cancelSeenByAll", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  8, "terminalAreYouSeeing", ASN1_EXTENSION_ROOT,
			dissect_h245_TerminalLabel },
	{  9, "requestForFloor", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{ 10, "withdrawChairToken", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{ 11, "floorRequested", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_TerminalLabel },
	{ 12, "terminalAreYouSeeingInSubPictureNumber", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_TerminalYouAreSeeingInSubPictureNumber },
	{ 13, "videoIndicateCompose", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_VideoIndicateCompose },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ConferenceIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ConferenceIndication, ett_h245_ConferenceIndication, ConferenceIndication_choice, "ConferenceIndication", NULL);

	return offset;
}




static int
dissect_h245_estimatedReceivedJitterMantissa(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_estimatedReceivedJitterMantissa,  0,  3,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_estimatedReceivedJitterExponent(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_estimatedReceivedJitterExponent,  0,  7,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_skippedFrameCount(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_skippedFrameCount,  0,  15,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_additionalDecoderBuffer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_additionalDecoderBuffer,  0,  262143,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t JitterIndication_sequence[] = {
	{ "scope", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_JitterIndication_scope },
	{ "estimatedReceivedJitterMantissa", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_estimatedReceivedJitterMantissa },
	{ "estimatedReceivedJitterExponent", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_estimatedReceivedJitterExponent },
	{ "skippedFrameCount", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_skippedFrameCount },
	{ "additionalDecoderBuffer", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_additionalDecoderBuffer },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_JitterIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_JitterIndication, ett_h245_JitterIndication, JitterIndication_sequence);

	return offset;
}




static int
dissect_h245_skew(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_skew,  0,  4095,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t H223SkewIndication_sequence[] = {
	{ "logicalChannelNumber1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_LogicalChannelNumber },
	{ "logicalChannelNumber2", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_LogicalChannelNumber },
	{ "skew", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_skew },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223SkewIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223SkewIndication, ett_h245_H223SkewIndication, H223SkewIndication_sequence);

	return offset;
}




static int
dissect_h245_maximumSkew(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_maximumSkew,  0,  4095,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t H2250MaximumSkewIndication_sequence[] = {
	{ "logicalChannelNumber1", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_LogicalChannelNumber },
	{ "logicalChannelNumber2", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_LogicalChannelNumber },
	{ "maximumSkew", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
			dissect_h245_maximumSkew },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H2250MaximumSkewIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H2250MaximumSkewIndication, ett_h245_H2250MaximumSkewIndication, H2250MaximumSkewIndication_sequence);

	return offset;
}




static int
dissect_h245_duration(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_duration,  1,  65535,
		NULL, NULL, FALSE);

	return offset;
}



static per_sequence_t UserInputIndication_signalUpdate_sequence[] = {
	{ "duration", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_duration },
	{ "rtp", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_UserInputIndication_signalUpdate_rtp },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_UserInputIndication_signalUpdate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_UserInputIndication_signalUpdate, ett_h245_UserInputIndication_signalUpdate, UserInputIndication_signalUpdate_sequence);

	return offset;
}




static int
dissect_h245_timestamp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_timestamp,  0,  4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_expirationTime(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_expirationTime,  0,  4294967295UL,
		NULL, NULL, FALSE);

	return offset;
}




static per_sequence_t UserInputIndication_signal_rtp_sequence[] = {
	{ "timestamp", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_timestamp },
	{ "expirationTime", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_expirationTime },
	{ "logicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_UserInputIndication_signal_rtp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_UserInputIndication_signal_rtp, ett_h245_UserInputIndication_signal_rtp, UserInputIndication_signal_rtp_sequence);

	return offset;
}






static per_sequence_t MasterSlaveDeterminationRelease_sequence[] = {
	{ NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};
static int
dissect_h245_MasterSlaveDeterminationRelease(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MasterSlaveDeterminationRelease, ett_h245_MasterSlaveDeterminationRelease, MasterSlaveDeterminationRelease_sequence);

	return offset;
}





static per_sequence_t MultilinkIndication_crcDesired_sequence[] = {
	{ NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};
static int
dissect_h245_MultilinkIndication_crcDesired(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultilinkIndication_crcDesired, ett_h245_MultilinkIndication_crcDesired, MultilinkIndication_crcDesired_sequence);

	return offset;
}





static int
dissect_h245_object(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h245_object, object);
	return offset;
}



static int
dissect_h245_protocolIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h245_protocolIdentifier, NULL);
	return offset;
}




static int
dissect_h245_algorithm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h245_algorithm, NULL);
	return offset;
}




static int
dissect_h245_antiSpamAlgorithm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h245_antiSpamAlgorithm, NULL);
	return offset;
}




static int
dissect_h245_standard_object(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h245_standard_object, NULL);
	return offset;
}



static int
dissect_h245_oid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h245_oid, NULL);
	return offset;
}




static int
dissect_h245_escrowID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h245_escrowID, NULL);
	return offset;
}




static int
dissect_h245_field(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h245_field, NULL);
	return offset;
}




/* dissect_h245_NonStandardIdentifier is used for H.245 */

static const value_string NonStandardIdentifier_vals[] = {
	{ 0,	"object" },
	{ 1,	"h221NonStandard" },
	{ 0, NULL }
};
static per_choice_t NonStandardIdentifier_choice[] = {
	{ 0,	"object", ASN1_NO_EXTENSIONS,
		dissect_h245_object },
	{ 1,	"h221NonStandard", ASN1_NO_EXTENSIONS,
		dissect_h245_h221NonStandard },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h245_NonStandardIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 value;

	*object = '\0';
	h221NonStandard = 0;

	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NonStandardIdentifier, ett_h245_NonStandardIdentifier, NonStandardIdentifier_choice, "NonStandardIdentifier", &value);

	switch (value) {
		case 0 :  /* object */
			nsp_handle = dissector_get_string_handle(nsp_object_dissector_table, object);
			break;
		case 1 :  /* h221NonStandard */
			nsp_handle = dissector_get_port_handle(nsp_h221_dissector_table, h221NonStandard);
			break;
		default :
			nsp_handle = NULL;
    }

	return offset;
}

static int
dissect_h245_NonStandardParameterData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 value_offset, value_len;
	tvbuff_t *next_tvb;

	if (nsp_handle) {
		offset=dissect_per_octet_string(tvb, offset, pinfo, tree, -1, -1, -1, &value_offset, &value_len);
		next_tvb = tvb_new_subset(tvb, value_offset, value_len, value_len);
		call_dissector(nsp_handle, next_tvb, pinfo, tree);
	} else {
		offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_NonStandardParameterData, -1, -1, NULL, NULL);
	}
	return offset;
}




static int
dissect_h245_nlpidData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_nlpidData, -1, -1, NULL, NULL);
	return offset;
}




static int
dissect_h245_nonCollapsingRaw(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_nonCollapsingRaw, -1, -1, NULL, NULL);
	return offset;
}



static int
dissect_h245_uuid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_uuid, 16, 16, NULL, NULL);
	return offset;
}




static int
dissect_h245_octetString(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_octetString, -1, -1, NULL, NULL);
	return offset;
}




static int
dissect_h245_externalReference(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_externalReference, 1, 255, NULL, NULL);
	return offset;
}




static int
dissect_h245_nsapAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_nsapAddress, 1, 20, NULL, NULL);
	return offset;
}




static int
dissect_h245_subaddress_1_20(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_subaddress_1_20, 1, 20, NULL, NULL);
	return offset;
}




static int
dissect_h245_programDescriptors(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_programDescriptors, -1, -1, NULL, NULL);
	return offset;
}



static int
dissect_h245_streamDescriptors(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_streamDescriptors, -1, -1, NULL, NULL);
	return offset;
}




static int
dissect_h245_ipv4network(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	/* byte aligned */
	if(offset&0x07){
		offset=(offset&0xfffffff8)+8;
	}
	tvb_memcpy(tvb, (char *)&ipv4_address, offset>>3, 4);
	proto_tree_add_ipv4(tree, hf_h245_ipv4network, tvb, offset>>3, 4, ipv4_address);

	offset+=32;
	return offset;
}



static int
dissect_h245_ipxNode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_ipxNode, 6, 6, NULL, NULL);
	return offset;
}



static int
dissect_h245_ipxNetnum(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_ipxNetnum, 4, 4, NULL, NULL);
	return offset;
}




static int
dissect_h245_ipv6network(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_ipv6network, 16, 16, NULL, NULL);
	return offset;
}



static int
dissect_h245_netBios(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_netBios, 16, 16, NULL, NULL);
	return offset;
}




static int
dissect_h245_nsap(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_nsap, 1, 20, NULL, NULL);
	return offset;
}




static int
dissect_h245_h235Key(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_h235Key, 1, 65535, NULL, NULL);
	return offset;
}



static int
dissect_h245_value(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_value, 1, 65535, NULL, NULL);
	return offset;
}




static int
dissect_h245_certificateResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_certificateResponse, 1, 65535, NULL, NULL);
	return offset;
}




static int
dissect_h245_TerminalID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_TerminalID, 1, 128, NULL, NULL);
	return offset;
}



static int
dissect_h245_ConferenceID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_ConferenceID, 1, 32, NULL, NULL);
	return offset;
}



static int
dissect_h245_Password(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_Password, 1, 32, NULL, NULL);
	return offset;
}




static int
dissect_h245_encryptionSE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_encryptionSE, -1, -1, NULL, NULL);
	return offset;
}



static int
dissect_h245_conferenceIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_conferenceIdentifier, 1, 16, NULL, NULL);
	return offset;
}




static int
dissect_h245_returnedFunction(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_returnedFunction, -1, -1, NULL, NULL);
	return offset;
}




static int
dissect_h245_productNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_productNumber, 1, 256, NULL, NULL);
	return offset;
}




static int
dissect_h245_versionNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h245_versionNumber, 1, 256, NULL, NULL);
	return offset;
}





static per_sequence_t H222LogicalChannelParameters_sequence[] = {
	{ "resourceID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_resourceID },
	{ "subChannelID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_subChannelID },
	{ "pcr-pid", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_pcr_pid },
	{ "programDescriptors", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_programDescriptors },
	{ "streamDescriptors", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_streamDescriptors },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H222LogicalChannelParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H222LogicalChannelParameters, ett_h245_H222LogicalChannelParameters, H222LogicalChannelParameters_sequence);

	return offset;
}





static per_sequence_t UnicastAddress_iPAddress_sequence[] = {
	{ "network", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ipv4network },
	{ "tsapIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_tsapIdentifier },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_UnicastAddress_iPAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_UnicastAddress_iPAddress, ett_h245_UnicastAddress_iPAddress, UnicastAddress_iPAddress_sequence);

	return offset;
}



static per_sequence_t UnicastAddress_iPXAddress_sequence[] = {
	{ "node", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ipxNode },
	{ "netnum", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ipxNetnum },
	{ "tsapIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_tsapIdentifier },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_UnicastAddress_iPXAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_UnicastAddress_iPXAddress, ett_h245_UnicastAddress_iPXAddress, UnicastAddress_iPXAddress_sequence);

	return offset;
}




static per_sequence_t UnicastAddress_iP6Address_sequence[] = {
	{ "network", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ipv6network },
	{ "tsapIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_tsapIdentifier },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_UnicastAddress_iP6Address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_UnicastAddress_iP6Address, ett_h245_UnicastAddress_iP6Address, UnicastAddress_iP6Address_sequence);

	return offset;
}





static per_sequence_t VendorIdentification_sequence[] = {
	{ "vendor", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NonStandardIdentifier },
	{ "productNumber", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_productNumber },
	{ "versionNumber", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_versionNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_VendorIdentification(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_VendorIdentification, ett_h245_VendorIdentification, VendorIdentification_sequence);

	return offset;
}




static per_sequence_t MulticastAddress_iPAddress_sequence[] = {
	{ "network", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ipv4network },
	{ "tsapIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_tsapIdentifier },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MulticastAddress_iPAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MulticastAddress_iPAddress, ett_h245_MulticastAddress_iPAddress, MulticastAddress_iPAddress_sequence);

	return offset;
}




static per_sequence_t MulticastAddress_iP6Address_sequence[] = {
	{ "network", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ipv6network },
	{ "tsapIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_tsapIdentifier },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MulticastAddress_iP6Address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MulticastAddress_iP6Address, ett_h245_MulticastAddress_iP6Address, MulticastAddress_iP6Address_sequence);

	return offset;
}





static per_sequence_t Criteria_sequence[] = {
	{ "field", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_field },
	{ "value", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_value },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_Criteria(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_Criteria, ett_h245_Criteria, Criteria_sequence);

	return offset;
}




static per_sequence_t ConferenceResponse_mCterminalIDResponse_sequence[] = {
	{ "terminalLabel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ "terminalID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalID },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_mCterminalIDResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_mCterminalIDResponse, ett_h245_ConferenceResponse_mCterminalIDResponse, ConferenceResponse_mCterminalIDResponse_sequence);

	return offset;
}




static per_sequence_t ConferenceResponse_conferenceIDResponse_sequence[] = {
	{ "terminalLabel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ "conferenceID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ConferenceID },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_conferenceIDResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_conferenceIDResponse, ett_h245_ConferenceResponse_conferenceIDResponse, ConferenceResponse_conferenceIDResponse_sequence);

	return offset;
}




static per_sequence_t ConferenceResponse_passwordResponse_sequence[] = {
	{ "terminalLabel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ "password", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_Password },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_passwordResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_passwordResponse, ett_h245_ConferenceResponse_passwordResponse, ConferenceResponse_passwordResponse_sequence);

	return offset;
}





static per_sequence_t ConferenceResponse_extensionAddressResponse_sequence[] = {
	{ "extensionAddress", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalID },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_extensionAddressResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_extensionAddressResponse, ett_h245_ConferenceResponse_extensionAddressResponse, ConferenceResponse_extensionAddressResponse_sequence);

	return offset;
}




static per_sequence_t ConferenceResponse_chairTokenOwnerResponse_sequence[] = {
	{ "terminalLabel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ "terminalID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalID },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_chairTokenOwnerResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_chairTokenOwnerResponse, ett_h245_ConferenceResponse_chairTokenOwnerResponse, ConferenceResponse_chairTokenOwnerResponse_sequence);

	return offset;
}




static per_sequence_t ConferenceResponse_terminalCertificateResponse_sequence[] = {
	{ "terminalLabel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ "certificateResponse", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_certificateResponse },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_terminalCertificateResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_terminalCertificateResponse, ett_h245_ConferenceResponse_terminalCertificateResponse, ConferenceResponse_terminalCertificateResponse_sequence);

	return offset;
}




static per_sequence_t TerminalInformation_sequence[] = {
	{ "terminalLabel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ "terminalID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalID },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_TerminalInformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_TerminalInformation, ett_h245_TerminalInformation, TerminalInformation_sequence);

	return offset;
}



static per_sequence_t SubstituteConferenceIDCommand_sequence[] = {
	{ "conferenceIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_conferenceIdentifier },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_SubstituteConferenceIDCommand(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_SubstituteConferenceIDCommand, ett_h245_SubstituteConferenceIDCommand, SubstituteConferenceIDCommand_sequence);

	return offset;
}




static const value_string ConferenceCommand_vals[] = {
	{  0, "broadcastMyLogicalChannel" },
	{  1, "cancelBroadcastMyLogicalChannel" },
	{  2, "makeTerminalBroadcaster" },
	{  3, "cancelMakeTerminalBroadcaster" },
	{  4, "sendThisSource" },
	{  5, "cancelSendThisSource" },
	{  6, "dropConference" },
	{  7, "substituteConferenceIDCommand" },
	{  0, NULL }
};
static per_choice_t ConferenceCommand_choice[] = {
	{  0, "broadcastMyLogicalChannel", ASN1_EXTENSION_ROOT,
		dissect_h245_LogicalChannelNumber },
	{  1, "cancelBroadcastMyLogicalChannel", ASN1_EXTENSION_ROOT,
		dissect_h245_LogicalChannelNumber },
	{  2, "makeTerminalBroadcaster", ASN1_EXTENSION_ROOT,
		dissect_h245_TerminalLabel },
	{  3, "cancelMakeTerminalBroadcaster", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  4, "sendThisSource", ASN1_EXTENSION_ROOT,
		dissect_h245_TerminalLabel },
	{  5, "cancelSendThisSource", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  6, "dropConference", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  7, "substituteConferenceIDCommand", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_SubstituteConferenceIDCommand },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ConferenceCommand(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ConferenceCommand, ett_h245_ConferenceCommand, ConferenceCommand_choice, "ConferenceCommand", NULL);

	return offset;
}




static per_sequence_t FunctionNotSupported_sequence[] = {
	{ "cause", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_FunctionNotSupported_cause },
	{ "returnedFunction", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_returnedFunction },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FunctionNotSupported(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FunctionNotSupported, ett_h245_FunctionNotSupported, FunctionNotSupported_sequence);

	return offset;
}




/* dissect_h245_NonStandardParameter is used for H.245 */

static per_sequence_t NonStandardParameter_sequence[] = {
	{ "nonStandardIdentifier", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_NonStandardIdentifier },
	{ "data", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_NonStandardParameterData },
	{ NULL, 0, 0, NULL }
};
int
dissect_h245_NonStandardParameter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	nsp_handle = NULL;

	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NonStandardParameter, ett_h245_NonStandardParameter, NonStandardParameter_sequence);

	return offset;
}

static const value_string DataProtocolCapability_vals[] = {
	{  0, "nonStandard" },
	{  1, "v14buffered" },
	{  2, "v42lapm" },
	{  3, "hdlcFrameTunnelling" },
	{  4, "h310SeparateVCStack" },
	{  5, "h310SingleVCStack" },
	{  6, "transparent" },
	{  7, "segmentationAndReassembly" },
	{  8, "hdlcFrameTunnelingwSAR" },
	{  9, "v120" },
	{ 10, "separateLANStack" },
	{ 11, "v76wCompression" },
	{ 12, "tcp" },
	{ 13, "udp" },
	{  0, NULL }
};
static per_choice_t DataProtocolCapability_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
			dissect_h245_NonStandardParameter },
	{  1, "v14buffered", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "v42lapm", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "hdlcFrameTunnelling", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "h310SeparateVCStack", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "h310SingleVCStack", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  6, "transparent", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  7, "segmentationAndReassembly", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  8, "hdlcFrameTunnelingwSAR", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  9, "v120", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{ 10, "separateLANStack", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{ 11, "v76wCompression", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_DataProtocolCapability_v76wCompression },
	{ 12, "tcp", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{ 13, "udp", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
int
dissect_h245_DataProtocolCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_DataProtocolCapability, ett_h245_DataProtocolCapability, DataProtocolCapability_choice, "DataProtocolCapability", NULL);

	return offset;
}




static const value_string MediaEncryptionAlgorithm_vals[] = {
	{  0, "nonStandard" },
	{  1, "algorithm" },
	{  0, NULL }
};
static per_choice_t MediaEncryptionAlgorithm_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "algorithm", ASN1_EXTENSION_ROOT,
		dissect_h245_algorithm },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MediaEncryptionAlgorithm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MediaEncryptionAlgorithm, ett_h245_MediaEncryptionAlgorithm, MediaEncryptionAlgorithm_choice, "MediaEncryptionAlgorithm", NULL);

	return offset;
}




static const value_string UserInputCapability_vals[] = {
	{  0, "nonStandard" },
	{  1, "basicString" },
	{  2, "iA5String" },
	{  3, "generalString" },
	{  4, "dtmf" },
	{  5, "hookflash" },
	{  6, "extendedAlphanumeric" },
	{  0, NULL }
};
static per_choice_t UserInputCapability_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
			dissect_h245_NonStandardParameter },
	{  1, "basicString", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "iA5String", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "generalString", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "dtmf", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "hookflash", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  6, "extendedAlphanumeric", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_UserInputCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_UserInputCapability, ett_h245_UserInputCapability, UserInputCapability_choice, "UserInputCapability", NULL);

	return offset;
}



static int
dissect_h245_domainBased(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h245_domainBased, 1, 64);

	return offset;
}




static const value_string CapabilityIdentifier_vals[] = {
	{  0, "standard" },
	{  1, "h221NonStandard" },
	{  2, "uuid" },
	{  3, "domainBased" },
	{  0, NULL }
};
static per_choice_t CapabilityIdentifier_choice[] = {
	{  0, "standard", ASN1_EXTENSION_ROOT,
		dissect_h245_standard_object },
	{  1, "h221NonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  2, "uuid", ASN1_EXTENSION_ROOT,
		dissect_h245_uuid },
	{  3, "domainBased", ASN1_EXTENSION_ROOT,
		dissect_h245_domainBased },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_CapabilityIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_CapabilityIdentifier, ett_h245_CapabilityIdentifier, CapabilityIdentifier_choice, "CapabilityIdentifier", NULL);

	return offset;
}




static const value_string ParameterIdentifier_vals[] = {
	{  0, "standard" },
	{  1, "h221NonStandard" },
	{  2, "uuid" },
	{  3, "domainBased" },
	{  0, NULL }
};
static per_choice_t ParameterIdentifier_choice[] = {
	{  0, "standard", ASN1_EXTENSION_ROOT,
		dissect_h245_standard_0_127 },
	{  1, "h221NonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  2, "uuid", ASN1_EXTENSION_ROOT,
		dissect_h245_uuid },
	{  3, "domainBased", ASN1_EXTENSION_ROOT,
		dissect_h245_domainBased },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ParameterIdentifier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ParameterIdentifier, ett_h245_ParameterIdentifier, ParameterIdentifier_choice, "ParameterIdentifier", NULL);

	return offset;
}


static const value_string H223LogicalChannelParameters_adaptationLayerType_vals[] = {
	{  0, "nonStandard" },
	{  1, "al1Framed" },
	{  2, "al1NotFramed" },
	{  3, "al2WithoutSequenceNumbers" },
	{  4, "al2WithSequenceNumbers" },
	{  5, "al3" },
	{  6, "al1M" },
	{  7, "al2M" },
	{  8, "al3M" },
	{  0, NULL }
};
static per_choice_t H223LogicalChannelParameters_adaptationLayerType_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
			dissect_h245_NonStandardParameter },
	{  1, "al1Framed", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "al1NotFramed", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "al2WithoutSequenceNumbers", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "al2WithSequenceNumbers", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "al3", ASN1_EXTENSION_ROOT,
			dissect_h245_H223LogicalChannelParameters_adaptionLayerType_al3 },
	{  6, "al1M", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_H223AL1MParameters },
	{  7, "al2M", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_H223AL2MParameters },
	{  8, "al3M", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_H223AL3MParameters },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223LogicalChannelParameters_adaptationLayerType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223LogicalChannelParameters_adaptationLayerType, ett_h245_H223LogicalChannelParameters_adaptationLayerType, H223LogicalChannelParameters_adaptationLayerType_choice, "adaptationLayerType", NULL);

	return offset;
}





static const value_string MulticastAddress_vals[] = {
	{  0, "iPAddress" },
	{  1, "iP6Address" },
	{  2, "nsap" },
	{  3, "nonStandardAddress" },
	{  0, NULL }
};
static per_choice_t MulticastAddress_choice[] = {
	{  0, "iPAddress", ASN1_EXTENSION_ROOT,
		dissect_h245_MulticastAddress_iPAddress },
	{  1, "iP6Address", ASN1_EXTENSION_ROOT,
		dissect_h245_MulticastAddress_iP6Address },
	{  2, "nsap", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_nsap },
	{  3, "nonStandardAddress", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MulticastAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MulticastAddress, ett_h245_MulticastAddress, MulticastAddress_choice, "MulticastAddress", NULL);

	return offset;
}




static const value_string H223ModeParameters_adaptationLayerType_vals[] = {
	{  0, "nonStandard" },
	{  1, "al1Framed" },
	{  2, "al1NotFramed" },
	{  3, "al2WithoutSequenceNumbers" },
	{  4, "al2WithSequenceNumbers" },
	{  5, "al3" },
	{  6, "al1M" },
	{  7, "al2M" },
	{  8, "al3M" },
	{  0, NULL }
};
static per_choice_t H223ModeParameters_adaptationLayerType_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
			dissect_h245_NonStandardParameter },
	{  1, "al1Framed", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "al1NotFramed", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "al2WithoutSequenceNumbers", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "al2WithSequenceNumbers", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "al3", ASN1_EXTENSION_ROOT,
			dissect_h245_H223ModeParameters_adaptationLayerType_al3 },
	{  6, "al1M", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_H223AL1MParameters },
	{  7, "al2M", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_H223AL2MParameters },
	{  8, "al3M", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_H223AL3MParameters },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H223ModeParameters_adaptationLayerType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H223ModeParameters_adaptationLayerType, ett_h245_H223ModeParameters_adaptationLayerType, H223ModeParameters_adaptationLayerType_choice, "Type", NULL);

	return offset;
}




static const value_string EncryptionMode_vals[] = {
	{  0, "nonStandard" },
	{  1, "h233Encryption" },
	{  0, NULL }
};
static per_choice_t EncryptionMode_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "h233Encryption", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_EncryptionMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_EncryptionMode, ett_h245_EncryptionMode, EncryptionMode_choice, "EncryptionMode", NULL);

	return offset;
}




static per_sequence_t NonStandardMessage_sequence[] = {
	{ "nonStandardData", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NonStandardMessage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NonStandardMessage, ett_h245_NonStandardMessage, NonStandardMessage_sequence);

	return offset;
}





static const value_string MultilinkIndication_vals[] = {
	{  0, "nonStandard" },
	{  1, "crcDesired" },
	{  2, "excessiveError" },
	{  0, NULL }
};
static per_choice_t MultilinkIndication_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardMessage },
	{  1, "crcDesired", ASN1_EXTENSION_ROOT,
		dissect_h245_MultilinkIndication_crcDesired },
	{  2, "excessiveError", ASN1_EXTENSION_ROOT,
		dissect_h245_MultilinkIndication_excessiveError },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultilinkIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultilinkIndication, ett_h245_MultilinkIndication, MultilinkIndication_choice, "MultilinkIndication", NULL);

	return offset;
}




static const value_string DialingInformationNetworkType_vals[] = {
	{  0, "nonStandard" },
	{  1, "n-isdn" },
	{  2, "gstn" },
	{  3, "mobile" },
	{  0, NULL }
};
static per_choice_t DialingInformationNetworkType_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardMessage },
	{  1, "n-isdn", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  2, "gstn", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  3, "mobile", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_DialingInformationNetworkType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_DialingInformationNetworkType, ett_h245_DialingInformationNetworkType, DialingInformationNetworkType_choice, "DialingInformationNetworkType", NULL);

	return offset;
}




static per_sequence_t QOSCapability_sequence[] = {
	{ "nonStandardData", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "rsvpParameters", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RSVPParameters },
	{ "atmParameters", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_ATMParameters },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_QOSCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_QOSCapability, ett_h245_QOSCapability, QOSCapability_sequence);

	return offset;
}




static per_sequence_t DataApplicationCapability_application_t84_sequence[] = {
	{ "t84Protocol", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_DataProtocolCapability },
	{ "t84Profile", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_T84Profile },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_DataApplicationCapability_application_t84(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_DataApplicationCapability_application_t84, ett_h245_DataApplicationCapability_application_t84, DataApplicationCapability_application_t84_sequence);

	return offset;
}





static per_sequence_t DataApplicationCapability_application_nlpid_sequence[] = {
	{ "nlpidProtocol", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_DataProtocolCapability },
	{ "nlpidData", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_nlpidData },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_DataApplicationCapability_application_nlpid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_DataApplicationCapability_application_nlpid, ett_h245_DataApplicationCapability_application_nlpid, DataApplicationCapability_application_nlpid_sequence);

	return offset;
}




static per_sequence_t DataApplicationCapability_application_t38fax_sequence[] = {
	{ "t38FaxProtocol", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_DataProtocolCapability },
	{ "t38FaxProfile", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_T38FaxProfile },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_DataApplicationCapability_application_t38fax(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_DataApplicationCapability_application_t38fax, ett_h245_DataApplicationCapability_application_t38fax, DataApplicationCapability_application_t38fax_sequence);

	return offset;
}




static per_sequence_t AuthenticationCapability_sequence[] = {
	{ "nonStandard", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "antiSpamAlgorithm", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_antiSpamAlgorithm },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_AuthenticationCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_AuthenticationCapability, ett_h245_AuthenticationCapability, AuthenticationCapability_sequence);

	return offset;
}



static per_sequence_t IntegrityCapability_sequence[] = {
	{ "nonStandard", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_IntegrityCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_IntegrityCapability, ett_h245_IntegrityCapability, IntegrityCapability_sequence);

	return offset;
}




static per_sequence_t H223LogicalChannelParameters_sequence[] = {
	{ "adaptationLayerType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223LogicalChannelParameters_adaptationLayerType },
	{ "segmentableFlag", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_segmentableFlag },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223LogicalChannelParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223LogicalChannelParameters, ett_h245_H223LogicalChannelParameters, H223LogicalChannelParameters_sequence);

	return offset;
}




static per_sequence_t RequestChannelClose_sequence[] = {
	{ "forwardLogicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "qosCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_QOSCapability },
	{ "reason", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RequestChannelClose_reason },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestChannelClose(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestChannelClose, ett_h245_RequestChannelClose, RequestChannelClose_sequence);

	return offset;
}




static per_sequence_t DataMode_application_nlpid_sequence[] = {
	{ "nlpidProtocol", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_DataProtocolCapability },
	{ "nlpidData", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_nlpidData },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_DataMode_application_nlpid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_DataMode_application_nlpid, ett_h245_DataMode_application_nlpid, DataMode_application_nlpid_sequence);

	return offset;
}





static per_sequence_t DataMode_application_t38fax_sequence[] = {
	{ "t38FaxProtocol", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_DataProtocolCapability },
	{ "t38FaxProfile", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_T38FaxProfile },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_DataMode_application_t38fax(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_DataMode_application_t38fax, ett_h245_DataMode_application_t38fax, DataMode_application_t38fax_sequence);

	return offset;
}




static per_sequence_t EncryptionCommand_encryptionAlgorithmID_sequence[] = {
	{ "h233AlgorithmIdentifier", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "associatedAlgorithm", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_EncryptionCommand_encryptionAlgorithmID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_EncryptionCommand_encryptionAlgorithmID, ett_h245_EncryptionCommand_encryptionAlgorithmID, EncryptionCommand_encryptionAlgorithmID_sequence);

	return offset;
}





static const value_string EncryptionCommand_vals[] = {
	{  0, "encryptionSE" },
	{  1, "encryptionIVRequest" },
	{  2, "encryptionAlgorithmID" },
	{  0, NULL }
};
static per_choice_t EncryptionCommand_choice[] = {
	{  0, "encryptionSE", ASN1_EXTENSION_ROOT,
		dissect_h245_encryptionSE },
	{  1, "encryptionIVRequest", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  2, "encryptionAlgorithmID", ASN1_EXTENSION_ROOT,
		dissect_h245_EncryptionCommand_encryptionAlgorithmID },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_EncryptionCommand(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_EncryptionCommand, ett_h245_EncryptionCommand, EncryptionCommand_choice, "EncryptionCommand", NULL);

	return offset;
}




static const value_string EndSessionCommand_vals[] = {
	{  0,	"nonStandard" },
	{  1,	"disconnect" },
	{  2,	"gstnOptions" },
	{  3,	"isdnOptions" },
	{  0, NULL }
};
static per_choice_t EndSessionCommand_choice[] = {
	{  0,	"nonStandard",			ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1,	"disconnect",			ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  2,	"gstnOptions",			ASN1_EXTENSION_ROOT,
		dissect_h245_EndSessionCommand_gstnOptions },
	{  3,	"isdnOptions",			ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_EndSessionCommand_isdnOptions },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_EndSessionCommand(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_EndSessionCommand_type, ett_h245_EndSessionCommand, EndSessionCommand_choice, "EndSessionCommand", NULL);

	return offset;
}






static int
dissect_h245_AudioCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static per_sequence_t VBDCapability_sequence[] = {
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_AudioCapability },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_VBDCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_VBDCapability, ett_h245_VBDCapability, VBDCapability_sequence);

	return offset;
}








static int
dissect_h245_nonStandardData_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_nonStandardData, ett_h245_nonStandardData, dissect_h245_NonStandardParameter);
	return offset;
}





static int
dissect_h245_supersedes_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_supersedes, ett_h245_supersedes, dissect_h245_ParameterIdentifier );
	return offset;
}




static const value_string ParameterValue_vals[] = {
	{  0, "logical" },
	{  1, "booleanArray" },
	{  2, "unsignedMin" },
	{  3, "unsignedMax" },
	{  4, "unsigned32Min" },
	{  5, "unsigned32Max" },
	{  6, "octetString" },
	{  7, "genericParameter" },
	{  0, NULL }
};
static int dissect_h245_genericParameter_sequence_of(tvbuff_t *, int, packet_info *, proto_tree *);
static per_choice_t ParameterValue_choice[] = {
	{  0, "logical", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "booleanArray", ASN1_EXTENSION_ROOT,
			dissect_h245_booleanArray },
	{  2, "unsignedMin", ASN1_EXTENSION_ROOT,
			dissect_h245_unsignedMin },
	{  3, "unsignedMax", ASN1_EXTENSION_ROOT,
			dissect_h245_unsignedMax },
	{  4, "unsigned32Min", ASN1_EXTENSION_ROOT,
			dissect_h245_unsigned32Min },
	{  5, "unsigned32Max", ASN1_EXTENSION_ROOT,
			dissect_h245_unsigned32Max },
	{  6, "octetString", ASN1_EXTENSION_ROOT,
			dissect_h245_octetString },
	{  7, "genericParameter", ASN1_EXTENSION_ROOT,
			dissect_h245_genericParameter_sequence_of },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ParameterValue(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ParameterValue, ett_h245_ParameterValue, ParameterValue_choice, "ParameterValue", NULL);

	return offset;
}



static per_sequence_t GenericParameter_sequence[] = {
	{ "parameterIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ParameterIdentifier },
	{ "parameterValue", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ParameterValue },
	{ "supersedes", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_supersedes_sequence_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_GenericParameter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_GenericParameter, ett_h245_GenericParameter, GenericParameter_sequence);

	return offset;
}





static int
dissect_h245_genericParameter_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_genericParameter, ett_h245_genericParameter, dissect_h245_GenericParameter );
	return offset;
}



static int
dissect_h245_collapsing_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_collapsing, ett_h245_collapsing, dissect_h245_GenericParameter );
	return offset;
}


static int
dissect_h245_nonCollapsing_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_nonCollapsing, ett_h245_nonCollapsing, dissect_h245_GenericParameter );
	return offset;
}


static int
dissect_h245_secondary_REE_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
/* XXX */
static int dissect_h245_RedundancyEncodingElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_secondary_REE, ett_h245_secondary_REE, dissect_h245_RedundancyEncodingElement );
	return offset;
}




static int
dissect_h245_elements_MPSE_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
/* XXX */
static int dissect_h245_MultiplePayloadStreamElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_elements_MPSE, ett_h245_elements_MPSE, dissect_h245_MultiplePayloadStreamElement );
	return offset;
}




static int
dissect_h245_secondary_REDTME_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
/* XXX */
static int dissect_h245_RedundancyEncodingDTModeElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_secondary_REDTME, ett_h245_secondary_REDTME, dissect_h245_RedundancyEncodingDTModeElement );
	return offset;
}




static int
dissect_h245_elements_MPSEM_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
/* XXX*/
static int dissect_h245_MultiplePayloadStreamElementMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_elements_MPSEM, ett_h245_elements_MPSEM, dissect_h245_MultiplePayloadStreamElementMode );
	return offset;
}




static int
dissect_h245_TerminalInformationSO_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_TerminalInformationSO, ett_h245_TerminalInformationSO, dissect_h245_TerminalInformation );
	return offset;
}




static int
dissect_h245_lostPicture_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_lostPicture, ett_h245_lostPicture, dissect_h245_PictureReference );
	return offset;
}




static int
dissect_h245_recoveryReferencePicture_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_recoveryReferencePicture, ett_h245_recoveryReferencePicture, dissect_h245_PictureReference );
	return offset;
}







static per_sequence_t ConferenceCapability_sequence[] = {
	{ "nonStandardData", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_nonStandardData_sequence_of },
	{ "chairControlCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_chairControlCapability },
	{ "videoIndicateMixingCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoIndicateMixingCapability },
	{ "multipointVisualizationCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_multipointVisualizationCapability },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ConferenceCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ConferenceCapability, ett_h245_ConferenceCapability, ConferenceCapability_sequence);

	return offset;
}




static per_sequence_t GenericCapability_sequence[] = {
	{ "capabilityIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_CapabilityIdentifier },
	{ "maxBitRate", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_maxBitRate_4294967295UL },
	{ "collapsing", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_collapsing_sequence_of },
	{ "nonCollapsing", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_nonCollapsing_sequence_of },
	{ "nonCollapsingRaw", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_nonCollapsingRaw },
	{ "transport", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_DataProtocolCapability },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_GenericCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_GenericCapability, ett_h245_GenericCapability, GenericCapability_sequence);

	return offset;
}





static const value_string DataApplicationCapability_application_vals[] = {
	{  0, "nonStandard" },
	{  1, "t120" },
	{  2, "dsm-cc" },
	{  3, "userData" },
	{  4, "t84" },
	{  5, "t434" },
	{  6, "h224" },
	{  7, "nlpid" },
	{  8, "dsvdControl" },
	{  9, "h222DataPartitioning" },
	{ 10, "t30fax" },
	{ 11, "t140" },
	{ 12, "t38fax" },
	{ 13, "genericDataCapability" },
	{  0, NULL }
};
static per_choice_t DataApplicationCapability_application_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "t120", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  2, "dsm-cc", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  3, "userData", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  4, "t84", ASN1_EXTENSION_ROOT,
		dissect_h245_DataApplicationCapability_application_t84 },
	{  5, "t434", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  6, "h224", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  7, "nlpid", ASN1_EXTENSION_ROOT,
		dissect_h245_DataApplicationCapability_application_nlpid },
	{  8, "dsvdControl", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  9, "h222DataPartitioning", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{ 10, "t30fax", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{ 11, "t140", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{ 12, "t38fax", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_DataApplicationCapability_application_t38fax },
	{ 13, "genericDataCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GenericCapability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_DataApplicationCapability_application(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
        guint32 value;

	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_DataApplicationCapability_application, ett_h245_DataApplicationCapability_application, DataApplicationCapability_application_choice, "application", &value);

        codec_type = val_to_str(value, DataApplicationCapability_application_vals, "<unknown>");

	return offset;
}




static const value_string DataMode_application_vals[] = {
	{  0, "nonStandard" },
	{  1, "t120" },
	{  2, "dsm-cc" },
	{  3, "userData" },
	{  4, "t84" },
	{  5, "t434" },
	{  6, "h224" },
	{  7, "nlpid" },
	{  8, "dsvdControl" },
	{  9, "h222DataPartitioning" },
	{ 10, "t30fax" },
	{ 11, "t140" },
	{ 12, "t38fax" },
	{ 13, "genericDataMode" },
	{  0, NULL }
};
static per_choice_t DataMode_application_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "t120", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  2, "dsm-cc", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  3, "userData", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  4, "t84", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  5, "t434", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  6, "h224", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{  7, "nlpid", ASN1_EXTENSION_ROOT,
		dissect_h245_DataMode_application_nlpid },
	{  8, "dsvdControl", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  9, "h222DataPartitioning", ASN1_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{ 10, "t30fax", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{ 11, "t140", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_DataProtocolCapability },
	{ 12, "t38fax", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_DataMode_application_t38fax },
	{ 13, "genericDataMode", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GenericCapability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_DataMode_application(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_DataMode_application, ett_h245_DataMode_application, DataMode_application_choice, "application", NULL);

	return offset;
}





static per_sequence_t MultiplePayloadStream_sequence[] = {
	{ "elements", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_elements_MPSE_sequence_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplePayloadStream(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplePayloadStream, ett_h245_MultiplePayloadStream, MultiplePayloadStream_sequence);

	return offset;
}





static per_sequence_t MultiplePayloadStreamMode_sequence[] = {
	{ "elements", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_elements_MPSEM_sequence_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplePayloadStreamMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplePayloadStreamMode, ett_h245_MultiplePayloadStreamMode, MultiplePayloadStreamMode_sequence);

	return offset;
}





static per_sequence_t DataMode_sequence[] = {
	{ "application", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_DataMode_application },
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dataModeBitRate },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_DataMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_DataMode, ett_h245_DataMode, DataMode_sequence);

	return offset;
}





static per_sequence_t RequestAllTerminalIDsResponse_sequence[] = {
	{ "terminalInformation", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalInformationSO_sequence_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestAllTerminalIDsResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestAllTerminalIDsResponse, ett_h245_RequestAllTerminalIDsResponse, RequestAllTerminalIDsResponse_sequence);

	return offset;
}





static per_sequence_t DataApplicationCapability_sequence[] = {
	{ "application", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_DataApplicationCapability_application },
	{ "maxBitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxBitRate_4294967295UL },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_DataApplicationCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_DataApplicationCapability, ett_h245_DataApplicationCapability, DataApplicationCapability_sequence);

	return offset;
}


static int
dissect_h245_iPSourceRouteAddress_route(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_, proto_tree *tree _U_)
{
NOT_DECODED_YET("iPSourceRouteAddress");
/* XXX
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_iPSourceRouteAddress_route, ett_h245_iPSourceRouteAddress_route, dissect_h245_ );
*/
	return offset;
}



static per_sequence_t UnicastAddress_iPSourceRouteAddress_sequence[] = {
	{ "routing", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_UnicastAddress_iPSourceRouteAddress_routing },
	{ "network", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ipv4network },
	{ "tsapIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_tsapIdentifier },
	{ "route", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_iPSourceRouteAddress_route },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_UnicastAddress_iPSourceRouteAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_UnicastAddress_iPSourceRouteAddress, ett_h245_UnicastAddress_iPSourceRouteAddress, UnicastAddress_iPSourceRouteAddress_sequence);

	return offset;
}



static const value_string UnicastAddress_vals[] = {
	{  0, "iPAddress" },
	{  1, "iPXAddress" },
	{  2, "iP6Address" },
	{  3, "netBios" },
	{  4, "iPSourceRouteAddress" },
	{  5, "nsap" },
	{  6, "nonStandardAddress" },
	{  0, NULL }
};
static per_choice_t UnicastAddress_choice[] = {
	{  0, "iPAddress", ASN1_EXTENSION_ROOT,
		dissect_h245_UnicastAddress_iPAddress },
	{  1, "iPXAddress", ASN1_EXTENSION_ROOT,
		dissect_h245_UnicastAddress_iPXAddress },
	{  2, "iP6Address", ASN1_EXTENSION_ROOT,
		dissect_h245_UnicastAddress_iP6Address },
	{  3, "netBios", ASN1_EXTENSION_ROOT,
		dissect_h245_netBios },
	{  4, "iPSourceRouteAddress", ASN1_EXTENSION_ROOT,
		dissect_h245_UnicastAddress_iPSourceRouteAddress },
	{  5, "nsap", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_nsap },
	{  6, "nonStandardAddress", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_UnicastAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_UnicastAddress, ett_h245_UnicastAddress, UnicastAddress_choice, "UnicastAddress", NULL);

	return offset;
}




static const value_string TransportAddress_vals[] = {
	{  0, "unicastAddress" },
	{  1, "multicastAddress" },
	{  0, NULL }
};
static per_choice_t TransportAddress_choice[] = {
	{  0, "unicastAddress", ASN1_EXTENSION_ROOT,
		dissect_h245_UnicastAddress },
	{  1, "multicastAddress", ASN1_EXTENSION_ROOT,
		dissect_h245_MulticastAddress },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_localAreaAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_localAreaAddress, ett_h245_TransportAddress, TransportAddress_choice, "localAreaAddress", NULL);

	return offset;
}
static int
dissect_h245_mediaChannel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	ipv4_address=0;
	ipv4_port=0;

	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_mediaChannel, ett_h245_TransportAddress, TransportAddress_choice, "mediaChannel", NULL);

	if((!pinfo->fd->flags.visited) && ipv4_address!=0 && ipv4_port!=0 && rtp_handle){
		address src_addr;
		conversation_t *conv=NULL;

		src_addr.type=AT_IPv4;
		src_addr.len=4;
		src_addr.data=(char *)&ipv4_address;

		conv=find_conversation(&src_addr, &src_addr, PT_UDP, ipv4_port, ipv4_port, NO_ADDR_B|NO_PORT_B);
		if(!conv){
			conv=conversation_new(&src_addr, &src_addr, PT_UDP, ipv4_port, ipv4_port, NO_ADDR2|NO_PORT2);
			conversation_set_dissector(conv, rtp_handle);
		}
	}
	return offset;
}
static int
dissect_h245_mediaControlChannel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	ipv4_address=0;
	ipv4_port=0;

	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_mediaControlChannel, ett_h245_TransportAddress, TransportAddress_choice, "mediaControlChannel", NULL);

	if((!pinfo->fd->flags.visited) && ipv4_address!=0 && ipv4_port!=0 && rtcp_handle){
		address src_addr;
		conversation_t *conv=NULL;

		src_addr.type=AT_IPv4;
		src_addr.len=4;
		src_addr.data=(char *)&ipv4_address;

		conv=find_conversation(&src_addr, &src_addr, PT_UDP, ipv4_port, ipv4_port, NO_ADDR_B|NO_PORT_B);
		if(!conv){
			conv=conversation_new(&src_addr, &src_addr, PT_UDP, ipv4_port, ipv4_port, NO_ADDR2|NO_PORT2);
			conversation_set_dissector(conv, rtcp_handle);
		}
	}
	return offset;
}
static int
dissect_h245_signalAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_signalAddress, ett_h245_TransportAddress, TransportAddress_choice, "signalAddress", NULL);

	return offset;
}



static per_sequence_t MCLocationIndication_sequence[] = {
	{ "signalAddress", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_signalAddress },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MCLocationIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MCLocationIndication, ett_h245_MCLocationIndication, MCLocationIndication_sequence);

	return offset;
}



static per_sequence_t H2250LogicalChannelAckParameters_sequence[] = {
	{ "nonStandard", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_nonStandardData_sequence_of },
	{ "sessionID", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_sessionID_1_255 },
	{ "mediaChannel", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaChannel },
	{ "mediaControlChannel", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaControlChannel },
	{ "dynamicRTPPayloadType", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_dynamicRTPPayloadType },
	{ "flowControlToZero", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_flowControlToZero },
	{ "portNumber", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_portNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H2250LogicalChannelAckParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H2250LogicalChannelAckParameters, ett_h245_H2250LogicalChannelAckParameters, H2250LogicalChannelAckParameters_sequence);

	return offset;
}




static const value_string forwardMultiplexAckParameters_vals[] = {
	{  0, "h2250LogicalChannelAckParameters" },
	{  0, NULL }
};
static per_choice_t forwardMultiplexAckParameters_choice[] = {
	{  0, "h2250LogicalChannelAckParameters", ASN1_EXTENSION_ROOT,
		dissect_h245_H2250LogicalChannelAckParameters },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_forwardMultiplexAckParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_forwardMultiplexAckParameters, ett_h245_forwardMultiplexAckParameters, forwardMultiplexAckParameters_choice, "forwardMultiplexAckParameters", NULL);

	return offset;
}





static int
dissect_h245_AlternativeCapabilitySet(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_AlternativeCapabilitySet, ett_h245_AlternativeCapabilitySet, dissect_h245_CapabilityTableEntryNumber, 1, 256 );
	return offset;
}




static int dissect_h245_rtpPayloadType_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static per_sequence_t MediaPacketizationCapability_sequence[] = {
	{ "h261aVideoPacketization", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_h261aVideoPacketization },
	{ "rtpPayloadType", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_rtpPayloadType_sequence_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MediaPacketizationCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MediaPacketizationCapability, ett_h245_MediaPacketizationCapability, MediaPacketizationCapability_sequence);

	return offset;
}




static int
dissect_h245_qOSCapabilities(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_qOSCapabilities, ett_h245_qOSCapabilities, dissect_h245_QOSCapability, 1, 256 );
	return offset;
}



static int
dissect_h245_mediaChannelCapabilities(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_mediaChannelCapabilities, ett_h245_mediaChannelCapabilities, dissect_h245_MediaChannelCapability, 1, 256 );
	return offset;
}


static per_sequence_t TransportCapability_sequence[] = {
	{ "nonStandard", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "qOSCapabilities", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_qOSCapabilities },
	{ "mediaChannelCapabilities", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaChannelCapabilities },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_TransportCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_TransportCapability, ett_h245_TransportCapability, TransportCapability_sequence);

	return offset;
}





static const value_string MiscellaneousIndication_type_vals[] = {
	{  0, "logicalChannelActive" },
	{  1, "logicalChannelInactive" },
	{  2, "multiportConference" },
	{  3, "cancelMultiportConference" },
	{  4, "multipointZeroComm" },
	{  5, "cancelMultipointZeroComm" },
	{  6, "multipointSecondryStatus" },
	{  7, "cancelMultipointSecondryStatus" },
	{  8, "videoIndicateReadyToActivate" },
	{  9, "videoTemporalSpatialTradeOff" },
	{ 10, "videoNotDecodedMBs" },
	{ 11, "transportCapability" },
	{  0, NULL }
};
static per_choice_t MiscellaneousIndication_type_choice[] = {
	{  0, "logicalChannelActive", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  1, "logicalChannelInactive", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  2, "multiportConference", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  3, "cancelMultiportConference", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  4, "multipointZeroComm", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  5, "cancelMultipointZeroComm", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  6, "multipointSecondryStatus", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  7, "cancelMultipointSecondryStatus", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  8, "videoIndicateReadyToActivate", ASN1_EXTENSION_ROOT,
			dissect_h245_NULL },
	{  9, "videoTemporalSpatialTradeOff", ASN1_EXTENSION_ROOT,
			dissect_h245_videoTemporalSpatialTradeOff },
	{ 10, "videoNotDecodedMBs", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_MiscellaneousIndication_type_videoNotDecodedMBs },
	{ 11, "transportCapability", ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_TransportCapability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MiscellaneousIndication_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MiscellaneousIndication_type, ett_h245_MiscellaneousIndication_type, MiscellaneousIndication_type_choice, "type", NULL);

	return offset;
}





static per_sequence_t MiscellaneousIndication_sequence[] = {
	{ "logicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MiscellaneousIndication_type },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MiscellaneousIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MiscellaneousIndication, ett_h245_MiscellaneousIndication, MiscellaneousIndication_sequence);

	return offset;
}





static int
dissect_h245_CapabilityTableEntryNumber_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_CapabilityTableEntryNumber_sequence_of, ett_h245_CapabilityTableEntryNumber_sequence_of, dissect_h245_CapabilityTableEntryNumber, 1, 256 );
	return offset;
}




static int dissect_h245_RTPH263VideoRedundancyFrameMapping(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_frameToThreadMapping_custom(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_frameToThreadMapping_custom, ett_h245_frameToThreadMapping_custom, dissect_h245_RTPH263VideoRedundancyFrameMapping, 1, 256 );
	return offset;
}




static const value_string RTPH263VideoRedundancyEncoding_frameToThreadMapping_vals[] = {
	{  0, "roundrobin" },
	{  1, "custom" },
	{  0, NULL }
};
static per_choice_t RTPH263VideoRedundancyEncoding_frameToThreadMapping_choice[] = {
	{  0, "roundrobin", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  1, "custom", ASN1_EXTENSION_ROOT,
		dissect_h245_frameToThreadMapping_custom },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RTPH263VideoRedundancyEncoding_frameToThreadMapping(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RTPH263VideoRedundancyEncoding_frameToThreadMapping, ett_h245_RTPH263VideoRedundancyEncoding_frameToThreadMapping, RTPH263VideoRedundancyEncoding_frameToThreadMapping_choice, "frameToThreadMapping", NULL);

	return offset;
}




static int
dissect_h245_containedThread(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_containedThread,  0,  15,
		NULL, NULL, FALSE);

	return offset;
}




static int
dissect_h245_containedThreads(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_containedThreads, ett_h245_containedThreads, dissect_h245_containedThread, 1, 256 );
	return offset;
}





static per_sequence_t RTPH263VideoRedundancyEncoding_sequence[] = {
	{ "numberOfThreads", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_numberOfThreads },
	{ "framesBetweenSyncPoints", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_framesBetweenSyncPoints },
	{ "frameToThreadMapping", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RTPH263VideoRedundancyEncoding_frameToThreadMapping },
	{ "containedThreads", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_containedThreads },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RTPH263VideoRedundancyEncoding(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RTPH263VideoRedundancyEncoding, ett_h245_RTPH263VideoRedundancyEncoding, RTPH263VideoRedundancyEncoding_sequence);

	return offset;
}




static const value_string RedundancyEncodingMethod_vals[] = {
	{  0, "nonStandard" },
	{  1, "rtpAudioRedundancyEncoding" },
	{  2, "rtpH263VideoRedundancyEncoding" },
	{  0, NULL }
};
static per_choice_t RedundancyEncodingMethod_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "rtpAudioRedundancyEncoding", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  2, "rtpH263VideoRedundancyEncoding", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_RTPH263VideoRedundancyEncoding },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RedundancyEncodingMethod(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RedundancyEncodingMethod, ett_h245_RedundancyEncodingMethod, RedundancyEncodingMethod_choice, "RedundancyEncodingMethod", NULL);

	return offset;
}




static per_sequence_t RedundancyEncodingCapability_sequence[] = {
	{ "redundancyEncodingMethod", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RedundancyEncodingMethod },
	{ "primaryEncoding", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_CapabilityTableEntryNumber },
	{ "secondaryEncoding", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_CapabilityTableEntryNumber_sequence_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RedundancyEncodingCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RedundancyEncodingCapability, ett_h245_RedundancyEncodingCapability, RedundancyEncodingCapability_sequence);

	return offset;
}



static int
dissect_h245_RedundancyEncodingCapability_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_RedundancyEncodingCapability_sequence_of, ett_h245_RedundancyEncodingCapability_sequence_of, dissect_h245_RedundancyEncodingCapability, 1, 256 );
	return offset;
}




static int
dissect_h245_frame(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree,
		hf_h245_frame,  0,  255,
		NULL, NULL, FALSE);

	return offset;
}



static int
dissect_h245_frameSequence(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_frameSequence, ett_h245_frameSequence, dissect_h245_frame, 1, 256 );
	return offset;
}




static per_sequence_t RTPH263VideoRedundancyFrameMapping_sequence[] = {
	{ "threadNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_threadNumber },
	{ "frameSequence", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_frameSequence },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RTPH263VideoRedundancyFrameMapping(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RTPH263VideoRedundancyFrameMapping, ett_h245_RTPH263VideoRedundancyFrameMapping, RTPH263VideoRedundancyFrameMapping_sequence);

	return offset;
}





static int
dissect_h245_EncryptionCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_EncryptionCapability, ett_h245_EncryptionCapability, dissect_h245_MediaEncryptionAlgorithm, 1, 256 );
	return offset;
}




static per_sequence_t EncryptionAuthenticationAndIntegrity_sequence[] = {
	{ "encryptionCapability", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_EncryptionCapability },
	{ "authenticationCapability", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_AuthenticationCapability },
	{ "integrityCapability", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_IntegrityCapability },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_EncryptionAuthenticationAndIntegrity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_EncryptionAuthenticationAndIntegrity, ett_h245_EncryptionAuthenticationAndIntegrity, EncryptionAuthenticationAndIntegrity_sequence);

	return offset;
}



static per_sequence_t H235SecurityCapability_sequence[] = {
	{ "encryptionAuthenticationAndIntegrity", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_EncryptionAuthenticationAndIntegrity },
	{ "mediaCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_CapabilityTableEntryNumber},
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H235SecurityCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H235SecurityCapability, ett_h245_H235SecurityCapability, H235SecurityCapability_sequence);

	return offset;
}


static int dissect_h245_EscrowData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_escrowentry(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_escrowentry, ett_h245_escrowentry, dissect_h245_EscrowData, 1, 256 );
	return offset;
}




static per_sequence_t EncryptionSync_sequence[] = {
	{ "nonStandard", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NonStandardParameter },
	{ "synchFlag", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_synchFlag },
	{ "h235Key", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_h235Key },
	{ "escrowentry", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_escrowentry },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_EncryptionSync(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_EncryptionSync, ett_h245_EncryptionSync, EncryptionSync_sequence);

	return offset;
}



static const value_string MiscellaneousCommand_type_vals[] = {
	{  0, "equalizeDelay" },
	{  1, "zeroDelay" },
	{  2, "multipointModeCommand" },
	{  3, "cancelMultipointModeCommand" },
	{  4, "videoFreezePicture" },
	{  5, "videoFastUpdatePicture" },
	{  6, "videoFastUpdateGOB" },
	{  7, "videoTemporalSpatialTradeOff" },
	{  8, "videoSendSyncEveryGOB" },
	{  9, "videoSendSyncEveryGOBCancel" },
	{ 10, "videoFastUpdateMB" },
	{ 11, "maxH223MUXPDUSize" },
	{ 12, "encryptionUpdate" },
	{ 13, "encryptionUpdateRequest" },
	{ 14, "switchReceiveMediaOff" },
	{ 15, "switchReceiveMediaOn" },
	{ 16, "progressiveRefinementStart" },
	{ 17, "progressiveRefinementAbortOne" },
	{ 18, "progressiveRefinementAbortContinous" },
	{ 19, "videoBadMBs" },
	{ 20, "lostPicture" },
	{ 21, "lostPartialPicture" },
	{ 22, "recoveryReferencePicture" },
	{  0, NULL }
};
static per_choice_t MiscellaneousCommand_type_choice[] = {
	{  0, "equalizeDelay", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  1, "zeroDelay", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  2, "multipointModeCommand", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  3, "cancelMultipointModeCommand", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  4, "videoFreezePicture", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  5, "videoFastUpdatePicture", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  6, "videoFastUpdateGOB", ASN1_EXTENSION_ROOT,
		dissect_h245_MiscellaneousCommand_type_videoFastUpdateGOB },
	{  7, "videoTemporalSpatialTradeOff", ASN1_EXTENSION_ROOT,
		dissect_h245_videoTemporalSpatialTradeOff },
	{  8, "videoSendSyncEveryGOB", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  9, "videoSendSyncEveryGOBCancel", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{ 10, "videoFastUpdateMB", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MiscellaneousCommand_type_videoFastUpdateMB },
	{ 11, "maxH223MUXPDUSize", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_maxH223MUXPDUsize },
	{ 12, "encryptionUpdate", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_EncryptionSync },
	{ 13, "encryptionUpdateRequest", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_EncryptionUpdateRequest },
	{ 14, "switchReceiveMediaOff", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NULL },
	{ 15, "switchReceiveMediaOn", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NULL },
	{ 16, "progressiveRefinementStart", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MiscellaneousCommand_type_progressiveRefinementStart },
	{ 17, "progressiveRefinementAbortOne", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NULL },
	{ 18, "progressiveRefinementAbortContinous", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NULL },
	{ 19, "videoBadMBs", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MiscellaneousCommand_type_videoBadMBs },
	{ 20, "lostPicture", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_lostPicture_sequence_of },
	{ 21, "lostPartialPicture", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MiscellaneousCommand_type_lostPartialPicture},
	{ 22, "recoveryReferencePicture", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_recoveryReferencePicture_sequence_of },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MiscellaneousCommand_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MiscellaneousCommand_type, ett_h245_MiscellaneousCommand_type, MiscellaneousCommand_type_choice, "type", NULL);

	return offset;
}




static per_sequence_t MiscellaneousCommand_sequence[] = {
	{ "logicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MiscellaneousCommand_type },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MiscellaneousCommand(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MiscellaneousCommand, ett_h245_MiscellaneousCommand, MiscellaneousCommand_sequence);

	return offset;
}



static int dissect_h245_MultiplexElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_elementList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_elementList, ett_h245_elementList, dissect_h245_MultiplexElement, 1, 256 );
	return offset;
}



static per_sequence_t MultiplexEntryDescriptor_sequence[] = {
	{ "multiplexTableEntryNumber", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_MultiplexTableEntryNumber },
	{ "elementList", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h245_elementList },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplexEntryDescriptor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplexEntryDescriptor, ett_h245_MultiplexEntryDescriptor, MultiplexEntryDescriptor_sequence);

	return offset;
}



static int
dissect_h245_subElementList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_subElementList, ett_h245_subElementList, dissect_h245_MultiplexElement, 2, 255 );
	return offset;
}



static const value_string MultiplexElement_type_vals[] = {
	{  0, "logicalChannelNumber" },
	{  1, "subElementList" },
	{  0, NULL }
};
static per_choice_t MultiplexElement_type_choice[] = {
	{  0, "logicalChannelNumber", ASN1_NO_EXTENSIONS,
		dissect_h245_logicalChannelNumber },
	{  1, "subElementList", ASN1_NO_EXTENSIONS,
		dissect_h245_subElementList },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultiplexElement_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultiplexElement_type, ett_h245_MultiplexElement_type, MultiplexElement_type_choice, "type", NULL);

	return offset;
}




static per_sequence_t MultiplexElement_sequence[] = {
	{ "type", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_MultiplexElement_type },
	{ "repeatCount", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_MultiplexElement_repeatCount },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplexElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplexElement, ett_h245_MultiplexElement, MultiplexElement_sequence);

	return offset;
}




static int dissect_h245_ModeDescription(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_requestedModes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_requestedModes, ett_h245_requestedModes, dissect_h245_ModeDescription, 1, 256 );
	return offset;
}




static per_sequence_t RequestMode_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "requestedModes", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_requestedModes },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestMode, ett_h245_RequestMode, RequestMode_sequence);

	return offset;
}



static int
dissect_h245_CertSelectionCriteria(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_CertSelectionCriteria, ett_h245_CertSelectionCriteria, dissect_h245_Criteria, 1, 16 );
	return offset;
}



static per_sequence_t ConferenceRequest_requestTerminalCertificate_sequence[] = {
	{ "terminalLabel", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ "certSelectionCriteria", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_CertSelectionCriteria },
	{ "sRandom", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_sRandom },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ConferenceRequest_requestTerminalCertificate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ConferenceRequest_requestTerminalCertificate, ett_h245_ConferenceRequest_requestTerminalCertificate, ConferenceRequest_requestTerminalCertificate_sequence);

	return offset;
}




static const value_string ConferenceRequest_vals[] = {
	{  0, "terminalListRequest" },
	{  1, "makeMeChair" },
	{  2, "cancelMakeMeChair" },
	{  3, "dropTerminal" },
	{  4, "requestTerminalID" },
	{  5, "enterH243Password" },
	{  6, "enterH243TerminalID" },
	{  7, "enterH243ConferenceID" },
	{  8, "enterExtensionAddress" },
	{  9, "requestChairTokenOwner" },
	{ 10, "requestTerminalCertificate" },
	{ 11, "broadcastMyLogicalChannel" },
	{ 12, "makeTerminalBroadcaster" },
	{ 13, "sendThisSource" },
	{ 14, "requestAllTerminalIDs" },
	{ 15, "remoteMCRequest" },
	{  0, NULL }
};
static per_choice_t ConferenceRequest_choice[] = {
	{  0, "terminalListRequest", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  1, "makeMeChair", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  2, "cancelMakeMeChair", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  3, "dropTerminal", ASN1_EXTENSION_ROOT,
		dissect_h245_TerminalLabel },
	{  4, "requestTerminalID", ASN1_EXTENSION_ROOT,
		dissect_h245_TerminalLabel },
	{  5, "enterH243Password", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  6, "enterH243TerminalID", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  7, "enterH243ConferenceID", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  8, "enterExtensionAddress", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  9, "requestChairTokenOwner", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NULL },
	{ 10, "requestTerminalCertificate", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_ConferenceRequest_requestTerminalCertificate },
	{ 11, "broadcastMyLogicalChannel", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_LogicalChannelNumber },
	{ 12, "makeTerminalBroadcaster", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_TerminalLabel },
	{ 13, "sendThisSource", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_TerminalLabel },
	{ 14, "requestAllTerminalIDs", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NULL },
	{ 15, "remoteMCRequest", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_RemoteMCRequest },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ConferenceRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ConferenceRequest, ett_h245_ConferenceRequest, ConferenceRequest_choice, "ConferenceRequest", NULL);

	return offset;
}

static int dissect_h245_CapabilityTableEntry(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_capabilityTable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_capabilityTable, ett_h245_capabilityTable, dissect_h245_CapabilityTableEntry, 1, 256);
	return offset;
}





static int
dissect_h245_simultaneousCapabilities(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_simultaneousCapabilities, ett_h245_simultaneousCapabilities, dissect_h245_AlternativeCapabilitySet, 1, 256);
	return offset;
}




static per_sequence_t CapabilityDescriptor_sequence[] = {
	{ "capabilityDescriptorNumber", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_CapabilityDescriptorNumber },
	{ "simultaneousCapabilities", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h245_simultaneousCapabilities },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CapabilityDescriptor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CapabilityDescriptor, ett_h245_CapabilityDescriptor, CapabilityDescriptor_sequence);

	return offset;
}



static int
dissect_h245_capabilityDescriptors(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_capabilityDescriptors, ett_h245_capabilityDescriptors, dissect_h245_CapabilityDescriptor, 1, 256);
	return offset;
}




static int dissect_h245_Q2931Address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_gatewayAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_gatewayAddress, ett_h245_gatewayAddress, dissect_h245_Q2931Address, 1, 256);
	return offset;
}



static per_sequence_t VCCapability_aal1ViaGateway_sequence[] = {
	{ "gatewayAddress", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_gatewayAddress },
	{ "nullClockRecovery", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_nullClockRecovery },
	{ "srtsClockRecovery", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_srtsClockRecovery },
	{ "adaptiveClockRecovery", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_adaptiveClockRecovery },
	{ "nullErrorCorrection", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_nullErrorCorrection },
	{ "longInterleaver", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_longInterleaver },
	{ "shortInterleaver", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_shortInterleaver },
	{ "errorCorrectionOnly", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_errorCorrectionOnly },
	{ "structuredDataTransfer", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_structuredDataTransfer },
	{ "partiallyFilledCells", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_partiallyFilledCells },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_VCCapability_aal1ViaGateway(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_VCCapability_aal1ViaGateway, ett_h245_VCCapability_aal1ViaGateway, VCCapability_aal1ViaGateway_sequence);

	return offset;
}



static per_sequence_t VCCapability_availableBitRates_sequence[] = {
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_VCCapability_availableBitRates_type },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_VCCapability_availableBitRates(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_VCCapability_availableBitRates, ett_h245_VCCapability_availableBitRates, VCCapability_availableBitRates_sequence);

	return offset;
}





static per_sequence_t VCCapability_sequence[] = {
	{ "aal1", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_VCCapability_aal1 },
	{ "aal5", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_VCCapability_aal5 },
	{ "transportStream", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_transportStream },
	{ "programStream", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_programStream },
	{ "availableBitRates", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_VCCapability_availableBitRates },
	{ "aal1ViaGateway", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_VCCapability_aal1ViaGateway },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_VCCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_VCCapability, ett_h245_VCCapability, VCCapability_sequence);

	return offset;
}





static int dissect_h245_EnhancementOptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_snrEnhancement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_snrEnhancement, ett_h245_snrEnhancement, dissect_h245_EnhancementOptions, 1, 14);
	return offset;
}




static int
dissect_h245_spatialEnhancement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_spatialEnhancement, ett_h245_spatialEnhancement, dissect_h245_EnhancementOptions, 1, 14);
	return offset;
}




static int dissect_h245_BEnhancementParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_bPictureEnhancement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_bPictureEnhancement, ett_h245_bPictureEnhancement, dissect_h245_BEnhancementParameters, 1, 14);
	return offset;
}




static per_sequence_t EnhancementLayerInfo_sequence[] = {
	{ "baseBitRateConstrained", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_baseBitRateConstrained },
	{ "snrEnhancement", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_snrEnhancement },
	{ "spatialEnhancement", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_spatialEnhancement },
	{ "bPictureEnhancement", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_bPictureEnhancement },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_EnhancementLayerInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_EnhancementLayerInfo, ett_h245_EnhancementLayerInfo, EnhancementLayerInfo_sequence);

	return offset;
}




static int
dissect_h245_customPictureClockFrequency(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_customPictureClockFrequency, ett_h245_customPictureClockFrequency, dissect_h245_CustomPictureClockFrequency, 1, 16);
	return offset;
}




static int dissect_h245_CustomPictureFormat(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);


static int
dissect_h245_customPictureFormat(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_customPictureFormat, ett_h245_customPictureFormat, dissect_h245_CustomPictureFormat, 1, 16);
	return offset;
}



static int dissect_h245_H263VideoModeCombos(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_modeCombos(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_modeCombos, ett_h245_modeCombos, dissect_h245_H263VideoModeCombos, 1, 16);
	return offset;
}





static per_sequence_t H263Options_sequence[] = {
	{ "advancedIntraCodingMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_advancedIntraCodingMode },
	{ "deblockingFilterMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_deblockingFilterMode },
	{ "improvedPBFramesMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_improvedPBFramesMode },
	{ "unlimitedMotionVectors", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_unlimitedMotionVectors },
	{ "fullPictureFreeze", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_fullPictureFreeze },
	{ "partialPictureFreezeAndRelease", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_partialPictureFreezeAndRelease },
	{ "resizingPartPicFreezeAndRelease", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_resizingPartPicFreezeAndRelease },
	{ "fullPictureSnapshot", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_fullPictureSnapshot },
	{ "partialPictureSnapshot", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_partialPictureSnapshot },
	{ "videoSegmentTagging", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoSegmentTagging },
	{ "progressiveRefinement", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_progressiveRefinement },
	{ "dynamicPictureResizingByFour", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dynamicPictureResizingByFour },
	{ "dynamicPictureResizingSixteenthPel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dynamicPictureResizingSixteenthPel },
	{ "dynamicWarpingHalfPel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dynamicWarpingHalfPel },
	{ "dynamicWarpingSixteenthPel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dynamicWarpingSixteenthPel },
	{ "independentSegmentDecoding", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_independentSegmentDecoding },
	{ "slicesInOrder-NonRect", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_slicesInOrderNonRect },
	{ "slicesInOrder-Rect", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_slicesInOrderRect },
	{ "slicesNoOrder-NonRect", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_slicesNoOrderNonRect },
	{ "slicesNoOrder-Rect", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_slicesNoOrderRect },
	{ "alternateInterVLCMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_alternateInterVLCMode },
	{ "modifiedQuantizationMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_modifiedQuantizationMode },
	{ "reducedResolutionUpdate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_reducedResolutionUpdate },
	{ "transparencyParameters", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_TransperencyParameters },
	{ "separateVideoBackChannel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_separateVideoBackChannel },
	{ "refPictureSelection", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RefPictureSelection },
	{ "customPictureClockFrequence", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_customPictureClockFrequency },
	{ "customPictureFormat", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_customPictureFormat },
	{ "modeCombos", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_modeCombos },
	{ "videoBadMBsCap", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_videoBadMBsCap },
	{ "h263Version3Options", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H263Version3Options },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H263Options(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H263Options, ett_h245_H263Options, H263Options_sequence);

	return offset;
}




static per_sequence_t H263VideoMode_sequence[] = {
	{ "resolution", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H263VideoMode_resolution },
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_h223bitRate },
	{ "unrestrictedVector", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_unrestrictedVector },
	{ "arithmeticCoding", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_arithmeticCoding },
	{ "advancedPrediction", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_advancedPrediction },
	{ "pbFrames", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_pbFrames },
	{ "errorCompensation", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_errorCompensation },
	{ "enhancementLayerInfo", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_EnhancementLayerInfo },
	{ "h263Options", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_H263Options },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H263VideoMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H263VideoMode, ett_h245_H263VideoMode, H263VideoMode_sequence);

	return offset;
}





static per_sequence_t H263VideoCapability_sequence[] = {
	{ "sqcifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_sqcifMPI_1_32 },
	{ "qcifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_qcifMPI_1_32 },
	{ "cifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cifMPI_1_32 },
	{ "cif4MPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cif4MPI_1_32 },
	{ "cif16MPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cif16MPI_1_32 },
	{ "maxBitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxBitRate_192400 },
	{ "unrestrictedVector", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_unrestrictedVector },
	{ "arithmeticCoding", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_arithmeticCoding },
	{ "advancedPrediction", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_advancedPrediction },
	{ "pbFrames", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_pbFrames },
	{ "temporalSpatialTradeOffCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_temporalSpatialTradeOffCapability },
	{ "hrd-B", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_hrd_B },
	{ "bppMaxKb", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_bppMaxKb },
	{ "slowSqcifMPI", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_slowSqcifMPI },
	{ "slowQcifMPI", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_slowQcifMPI },
	{ "slowCifMPI", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_slowCifMPI },
	{ "slowCif4MPI", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_slowCif4MPI },
	{ "slowCif16MPI", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_slowCif16MPI },
	{ "errorCompensation", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_errorCompensation },
	{ "enhancementLayerInfo", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_EnhancementLayerInfo },
	{ "h263Options", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_H263Options },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H263VideoCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H263VideoCapability, ett_h245_H263VideoCapability, H263VideoCapability_sequence);

	return offset;
}





static const value_string VideoCapability_vals[] = {
	{  0, "nonStandard" },
	{  1, "h261VideoCapability" },
	{  2, "h262VideoCapability" },
	{  3, "h263VideoCapability" },
	{  4, "is11172VideoCapability" },
	{  5, "genericVideoCapability" },
	{  0, NULL }
};
static per_choice_t VideoCapability_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "h261VideoCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_H261VideoCapability },
	{  2, "h262VideoCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_H262VideoCapability },
	{  3, "h263VideoCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_H263VideoCapability },
	{  4, "is11172VideoCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_IS11172VideoCapability},
	{  5, "genericVideoCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GenericCapability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_VideoCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
 	guint32 value;

	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_VideoCapability, ett_h245_VideoCapability, VideoCapability_choice, "VideoCapability", &value );

        codec_type = val_to_str(value, VideoCapability_vals, "<unknown>");

	return offset;
}





static per_sequence_t EnhancementOptions_sequence[] = {
	{ "sqcifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_sqcifMPI_1_32 },
	{ "qcifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_qcifMPI_1_32 },
	{ "cifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cifMPI_1_32 },
	{ "cif4MPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cif4MPI_1_32 },
	{ "cif16MPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_cif16MPI_1_32 },
	{ "maxBitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxBitRate_192400 },
	{ "unrestrictedVector", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_unrestrictedVector },
	{ "arithmeticCoding", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_arithmeticCoding },
	{ "temporalSpatialTradeOffCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_temporalSpatialTradeOffCapability },
	{ "slowSqcifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_slowSqcifMPI },
	{ "slowQcifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_slowQcifMPI },
	{ "slowCifMPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_slowCifMPI },
	{ "slowCif4MPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_slowCif4MPI },
	{ "slowCif16MPI", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_slowCif16MPI },
	{ "errorCompensation", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_errorCompensation },
	{ "h263Options", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_H263Options },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_EnhancementOptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_EnhancementOptions, ett_h245_EnhancementOptions, EnhancementOptions_sequence);

	return offset;
}




static per_sequence_t BEnhancementParameters_sequence[] = {
	{ "enhancementOptions", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_EnhancementOptions },
	{ "numberOfBPictures", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_numberOfBPictures },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_BEnhancementParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_BEnhancementParameters, ett_h245_BEnhancementParameters, BEnhancementParameters_sequence);

	return offset;
}



static int
dissect_h245_customPCF(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_customPCF, ett_h245_customPCF, dissect_h245_CustomPictureFormat_mPI_customPCF, 1, 16);
	return offset;
}




static int
dissect_h245_PixelAspectCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_PixelAspectCode, 1, 14,
		NULL, NULL, FALSE);

	return offset;
}

static int
dissect_h245_pixelAspectCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_pixelAspectCode, ett_h245_pixelAspectCode, dissect_h245_PixelAspectCode, 1, 14);
	return offset;
}



static int dissect_h245_extendedPAR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static const value_string CustomPictureFormat_pixelAspectInformation_vals[] = {
	{  0, "anyPixelAspectRatio" },
	{  1, "pixelAspectCode" },
	{  2, "extendedPAR" },
	{  0, NULL }
};
static per_choice_t CustomPictureFormat_pixelAspectInformation_choice[] = {
	{  0, "anyPixelAspectRatio", ASN1_EXTENSION_ROOT,
		dissect_h245_anyPixelAspectRatio },
	{  1, "pixelAspectCode", ASN1_EXTENSION_ROOT,
		dissect_h245_pixelAspectCode },
	{  2, "extendedPAR", ASN1_EXTENSION_ROOT,
		dissect_h245_extendedPAR },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_CustomPictureFormat_pixelAspectInformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_CustomPictureFormat_pixelAspectInformation, ett_h245_CustomPictureFormat_pixelAspectInformation, CustomPictureFormat_pixelAspectInformation_choice, "pixelAspectInformation", NULL);

	return offset;
}





static per_sequence_t CustomPictureFormat_sequence[] = {
	{ "maxCustomPictureWidth", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxCustomPictureWidth },
	{ "maxCustomPictureHeight", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maxCustomPictureHeight},
	{ "minCustomPictureWidth", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_minCustomPictureWidth },
	{ "minCustomPictureHeight", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_minCustomPictureHeight },
	{ "mPI", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_CustomPictureFormat_mPI },
	{ "pixelAspectInformation", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_CustomPictureFormat_pixelAspectInformation },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CustomPictureFormat(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CustomPictureFormat, ett_h245_CustomPictureFormat, CustomPictureFormat_sequence);

	return offset;
}




static int
dissect_h245_extendedPAR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_extendedPAR, ett_h245_extendedPAR, dissect_h245_CustomPictureFormat_pixelAspectInformation_extendedPAR, 1, 256);
	return offset;
}




static int
dissect_h245_h263VideoCoupledModes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_h263VideoCoupledModes, ett_h245_h263VideoCoupledModes, dissect_h245_H263ModeComboFlags, 1, 16);
	return offset;
}





static per_sequence_t H263VideoModeCombos_sequence[] = {
	{ "h263VideoUncoupledModes", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H263ModeComboFlags },
	{ "h263VideoCoupledModes", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_h263VideoCoupledModes },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H263VideoModeCombos(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H263VideoModeCombos, ett_h245_H263VideoModeCombos, H263VideoModeCombos_sequence);

	return offset;
}



static int
dissect_h245_capabilityOnMuxStream(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_capabilityOnMuxStream, ett_h245_capabilityOnMuxStream, dissect_h245_AlternativeCapabilitySet, 1, 256);
	return offset;
}




static int
dissect_h245_capabilities(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_capabilities, ett_h245_capabilities, dissect_h245_AlternativeCapabilitySet, 1, 256);
	return offset;
}



static per_sequence_t MultiplePayloadStreamCapability_sequence[] = {
	{ "capabilities", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_capabilities },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplePayloadStreamCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplePayloadStreamCapability, ett_h245_MultiplePayloadStreamCapability, MultiplePayloadStreamCapability_sequence);

	return offset;
}





static int
dissect_h245_multiplexEntryDescriptors(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_multiplexEntryDescriptors, ett_h245_multiplexEntryDescriptors, dissect_h245_MultiplexEntryDescriptor, 1, 15);
	return offset;
}



static per_sequence_t MultiplexEntrySend_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "multiplexEntryDescriptors", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_multiplexEntryDescriptors },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplexEntrySend(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplexEntrySend, ett_h245_MultiplexEntrySend, MultiplexEntrySend_sequence);

	return offset;
}




static int
dissect_h245_multiplexTableEntryNumber_set_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_multiplexTableEntryNumber_set_of, ett_h245_multiplexTableEntryNumber_set_of, dissect_h245_MultiplexTableEntryNumber, 1, 15);
	return offset;
}



static per_sequence_t MultiplexEntrySendRelease_sequence[] = {
	{ "multiplexTableEntryNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_multiplexTableEntryNumber_set_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplexEntrySendRelease(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplexEntrySendRelease, ett_h245_MultiplexEntrySendRelease, MultiplexEntrySendRelease_sequence);

	return offset;
}




static per_sequence_t MultiplexEntrySendAck_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "multiplexTableEntryNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_multiplexTableEntryNumber_set_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplexEntrySendAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplexEntrySendAck, ett_h245_MultiplexEntrySendAck, MultiplexEntrySendAck_sequence);

	return offset;
}





static int
dissect_h245_RMErejectionDescriptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_rejectionDescriptions, ett_h245_rejectionDescriptions, dissect_h245_RequestMultiplexEntryRejectionDescriptions, 1, 15);
	return offset;
}


static int
dissect_h245_rejectionDescriptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_rejectionDescriptions, ett_h245_rejectionDescriptions, dissect_h245_MultiplexEntryRejectionDescriptions, 1, 15);
	return offset;
}






static per_sequence_t MultiplexEntrySendReject_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "rejectionDescriptions", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_rejectionDescriptions },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplexEntrySendReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplexEntrySendReject, ett_h245_MultiplexEntrySendReject, MultiplexEntrySendReject_sequence);

	return offset;
}




static int
dissect_h245_entryNumbers(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_entryNumbers, ett_h245_entryNumbers, dissect_h245_MultiplexTableEntryNumber, 1, 15);
	return offset;
}




static per_sequence_t RequestMultiplexEntry_sequence[] = {
	{ "entryNumbers", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_entryNumbers },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestMultiplexEntry(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestMultiplexEntry, ett_h245_RequestMultiplexEntry, RequestMultiplexEntry_sequence);

	return offset;
}



static per_sequence_t RequestMultiplexEntryAck_sequence[] = {
	{ "entryNumbers", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_entryNumbers },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestMultiplexEntryAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestMultiplexEntryAck, ett_h245_RequestMultiplexEntryAck, RequestMultiplexEntryAck_sequence);

	return offset;
}




static per_sequence_t RequestMultiplexEntryReject_sequence[] = {
	{ "entryNumbers", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_entryNumbers },
	{ "rejectionDescriptions", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RMErejectionDescriptions },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestMultiplexEntryReject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestMultiplexEntryReject, ett_h245_RequestMultiplexEntryReject, RequestMultiplexEntryReject_sequence);

	return offset;
}





static per_sequence_t RequestMultiplexEntryRelease_sequence[] = {
	{ "entryNumbers", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_entryNumbers },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestMultiplexEntryRelease(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestMultiplexEntryRelease, ett_h245_RequestMultiplexEntryRelease, RequestMultiplexEntryRelease_sequence);

	return offset;
}



static int dissect_h245_ModeElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_ModeDescription(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_ModeDescription, ett_h245_ModeDescription, dissect_h245_ModeElement, 1, 256);
	return offset;
}




static int dissect_h245_CommunicationModeTableEntry(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_communicationModeTable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_communicationModeTable, ett_h245_communicationModeTable, dissect_h245_CommunicationModeTableEntry, 1, 256);
	return offset;
}





static per_sequence_t CommunicationModeCommand_sequence[] = {
	{ "communicationModeTable", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_communicationModeTable },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CommunicationModeCommand(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CommunicationModeCommand, ett_h245_CommunicationModeCommand, CommunicationModeCommand_sequence);

	return offset;
}





static const value_string CommunicationModeResponse_vals[] = {
	{  0, "communicationModeTable" },
	{  0, NULL }
};
static per_choice_t CommunicationModeResponse_choice[] = {
	{  0, "communicationModeTable", ASN1_EXTENSION_ROOT,
		dissect_h245_communicationModeTable },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_CommunicationModeResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_CommunicationModeResponse, ett_h245_CommunicationModeResponse, CommunicationModeResponse_choice, "CommunicationModeResponse", NULL);

	return offset;
}





static int
dissect_h245_terminalListResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_terminalListResponse, ett_h245_terminalListResponse, dissect_h245_TerminalLabel, 1, 256);
	return offset;
}




static int dissect_h245_DialingInformationNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int
dissect_h245_differential(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_differential, ett_h245_differential, dissect_h245_DialingInformationNumber, 1, 65535);
	return offset;
}





static const value_string DialingInformation_vals[] = {
	{  0, "nonStandard" },
	{  1, "differential" },
	{  2, "infoNotAvailable" },
	{  0, NULL }
};
static per_choice_t DialingInformation_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardMessage },
	{  1, "differential", ASN1_EXTENSION_ROOT,
		dissect_h245_differential },
	{  2, "infoNotAvailable", ASN1_EXTENSION_ROOT,
		dissect_h245_infoNotAvailable },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_DialingInformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_DialingInformation, ett_h245_DialingInformation, DialingInformation_choice, "DialingInformation", NULL);

	return offset;
}





static per_sequence_t MultilinkResponse_callInformation_sequence[] = {
	{ "dialingInformation", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_DialingInformation },
	{ "callAssociationNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_callAssociationNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultilinkResponse_callInformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultilinkResponse_callInformation, ett_h245_MultilinkResponse_callInformation, MultilinkResponse_callInformation_sequence);

	return offset;
}






static const value_string MultilinkResponse_vals[] = {
	{  0, "nonStandard" },
	{  1, "callInformation" },
	{  2, "addConnection" },
	{  3, "removeConnection" },
	{  4, "maximumHeaderInterval" },
	{  0, NULL }
};
static per_choice_t MultilinkResponse_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardMessage },
	{  1, "callInformation", ASN1_EXTENSION_ROOT,
		dissect_h245_MultilinkResponse_callInformation },
	{  2, "addConnection", ASN1_EXTENSION_ROOT,
		dissect_h245_MultilinkResponse_addConnection },
	{  3, "removeConnection", ASN1_EXTENSION_ROOT,
		dissect_h245_MultilinkResponse_removeConnection },
	{  4, "maximumHeaderInterval", ASN1_EXTENSION_ROOT,
		dissect_h245_MultilinkResponse_maximumHeaderInterval },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultilinkResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultilinkResponse, ett_h245_MultilinkResponse, MultilinkResponse_choice, "MultilinkResponse", NULL);

	return offset;
}




static per_sequence_t MultilinkRequest_addConnection_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "dialingInformation", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_DialingInformation },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultilinkRequest_addConnection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultilinkRequest_addConnection, ett_h245_MultilinkRequest_addConnection, MultilinkRequest_addConnection_sequence);

	return offset;
}





static const value_string MultilinkRequest_vals[] = {
	{  0, "nonStandard" },
	{  1, "callInformation" },
	{  2, "addConnection" },
	{  3, "removeConnection" },
	{  4, "maximumHeaderInterval" },
	{  0, NULL }
};
static per_choice_t MultilinkRequest_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardMessage },
	{  1, "callInformation", ASN1_EXTENSION_ROOT,
		dissect_h245_MultilinkRequest_callInformation },
	{  2, "addConnection", ASN1_EXTENSION_ROOT,
		dissect_h245_MultilinkRequest_addConnection },
	{  3, "removeConnection", ASN1_EXTENSION_ROOT,
		dissect_h245_MultilinkRequest_removeConnection },
	{  4, "maximumHeaderInterval", ASN1_EXTENSION_ROOT,
		dissect_h245_MultilinkRequest_maximumHeaderInterval },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultilinkRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultilinkRequest, ett_h245_MultilinkRequest, MultilinkRequest_choice, "MultilinkRequest", NULL);

	return offset;
}





static int
dissect_h245_networkType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_networkType, ett_h245_networkType, dissect_h245_DialingInformationNetworkType, 1, 255);
	return offset;
}





static int
dissect_h245_capabilityTableEntryNumbers(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_capabilityTableEntryNumbers, ett_h245_capabilityTableEntryNumbers, dissect_h245_CapabilityTableEntryNumber, 1, 65535);
	return offset;
}




static int
dissect_h245_capabilityDescriptorNumbers(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_set_of(tvb, offset, pinfo, tree, hf_h245_capabilityDescriptorNumbers, ett_h245_capabilityDescriptorNumbers, dissect_h245_CapabilityDescriptorNumber, 1, 256);
	return offset;
}




static per_sequence_t SendTerminalCapabilitySet_specificRequest_sequence[] = {
	{ "multiplexCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_multiplexCapability_bool },
	{ "capabilityTableEntryNumbers", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_capabilityTableEntryNumbers },
	{ "capabilityDescriptorNumbers", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_capabilityDescriptorNumbers },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_SendTerminalCapabilitySet_specificRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_SendTerminalCapabilitySet_specificRequest, ett_h245_SendTerminalCapabilitySet_specificRequest, SendTerminalCapabilitySet_specificRequest_sequence);

	return offset;
}





static const value_string SendTerminalCapabilitySet_vals[] = {
	{  0, "specificRequest" },
	{  1, "genericRequest" },
	{  0, NULL }
};
static per_choice_t SendTerminalCapabilitySet_choice[] = {
	{  0, "specificRequest", ASN1_EXTENSION_ROOT,
		dissect_h245_SendTerminalCapabilitySet_specificRequest },
	{  1, "genericRequest", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_SendTerminalCapabilitySet(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_SendTerminalCapabilitySet, ett_h245_SendTerminalCapabilitySet, SendTerminalCapabilitySet_choice, "SendTerminalCapabilitySet", NULL);

	return offset;
}






static int
dissect_h245_audioTelephoneEvent(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_GeneralString(tvb, offset, pinfo, tree, hf_h245_audioTelephoneEvent);
	return offset;
}





static per_sequence_t AudioTelephonyEventCapability_sequence[] = {
	{ "dynamicRTPPayloadType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_dynamicRTPPayloadType },
	{ "audioTelephoneEvent", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioTelephoneEvent },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_AudioTelephonyEventCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_AudioTelephonyEventCapability, ett_h245_AudioTelephonyEventCapability, AudioTelephonyEventCapability_sequence);

	return offset;
}






static per_sequence_t NoPTAudioTelephonyEventCapability_sequence[] = {
	{ "audioTelephoneEvent", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_audioTelephoneEvent },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NoPTAudioTelephonyEventCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NoPTAudioTelephonyEventCapability, ett_h245_NoPTAudioTelephonyEventCapability, NoPTAudioTelephonyEventCapability_sequence);

	return offset;
}




static const value_string AudioCapability_vals[] = {
	{  0, "nonStandard" },
	{  1, "g711Alaw64k" },
	{  2, "g711Alaw56k" },
	{  3, "g711Ulaw64k" },
	{  4, "g711Ulaw56k" },
	{  5, "g722-64k" },
	{  6, "g722-56k" },
	{  7, "g722-48k" },
	{  8, "g7231" },
	{  9, "g728" },
	{ 10, "g729" },
	{ 11, "g729AnnexA" },
	{ 12, "is11172AudioCapability" },
	{ 13, "is13818AudioCapability" },
	{ 14, "g729wAnnexB" },
	{ 15, "g729AnnexAwAnnexB" },
	{ 16, "g7231AnnexCCapability" },
	{ 17, "gsmFullRate" },
	{ 18, "gsmHalfRate" },
	{ 19, "gsmEnhancedFullRate" },
	{ 20, "genericAudioCapability" },
	{ 21, "g729Extensions" },
	{ 22, "vbd" },
	{ 23, "audioTelephonyEvent" },
	{ 24, "audioTone" },
	{  0, NULL }
};
static per_choice_t AudioCapability_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "g711Alaw64k", ASN1_EXTENSION_ROOT,
		dissect_h245_g711Alaw64k },
	{  2, "g711Alaw56k", ASN1_EXTENSION_ROOT,
		dissect_h245_g711Alaw56k },
	{  3, "g711Ulaw64k", ASN1_EXTENSION_ROOT,
		dissect_h245_g711Ulaw64k },
	{  4, "g711Ulaw56k", ASN1_EXTENSION_ROOT,
		dissect_h245_g711Ulaw56k },
	{  5, "g722-64k", ASN1_EXTENSION_ROOT,
		dissect_h245_g722_64k },
	{  6, "g722-56k", ASN1_EXTENSION_ROOT,
		dissect_h245_g722_56k },
	{  7, "g722-48k", ASN1_EXTENSION_ROOT,
		dissect_h245_g722_48k },
	{  8, "g7231", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioCapability_g7231 },
	{  9, "g728", ASN1_EXTENSION_ROOT,
		dissect_h245_g728 },
	{ 10, "g729", ASN1_EXTENSION_ROOT,
		dissect_h245_g729 },
	{ 11, "g729AnnexA", ASN1_EXTENSION_ROOT,
		dissect_h245_g729AnnexA },
	{ 12, "is11172AudioCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_IS11172AudioCapability },
	{ 13, "is13818AudioCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_IS13818AudioCapability },
	{ 14, "g729wAnnexB", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_g729wAnnexB },
	{ 15, "g729AnnexAwAnnexB", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_g729AnnexAwAnnexB },
	{ 16, "g7231AnnexCCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_G7231AnnexCCapability },
	{ 17, "gsmFullRate", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GSMAudioCapability },
	{ 18, "gsmHalfRate", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GSMAudioCapability },
	{ 19, "gsmEnhancedFullRate", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GSMAudioCapability },
	{ 20, "genericAudioCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GenericCapability },
	{ 21, "g729Extensions", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_G729Extensions },
	{ 22, "vbd", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_VBDCapability },
	{ 23, "audioTelephonyEvent", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NoPTAudioTelephonyEventCapability },
	{ 24, "audioTone", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NoPTAudioToneCapability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_AudioCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
        guint32 value;

	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_AudioCapability, ett_h245_AudioCapability, AudioCapability_choice, "AudioCapability", &value);

        codec_type = val_to_str(value, AudioCapability_vals, "<unknown>");

	return offset;
}





static const value_string H235Media_mediaType_vals[] = {
	{  0, "nonStandard" },
	{  1, "videoData" },
	{  2, "audioData" },
	{  3, "data" },
	{  0, NULL }
};
static per_choice_t H235Media_mediaType_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "videoData", ASN1_EXTENSION_ROOT,
		dissect_h245_VideoCapability },
	{  2, "audioData", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioCapability },
	{  3, "data", ASN1_EXTENSION_ROOT,
		dissect_h245_DataApplicationCapability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H235Media_mediaType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H235Media_mediaType, ett_h245_H235Media_mediaType, H235Media_mediaType_choice, "mediaType", NULL);

	return offset;
}






static const value_string CommunicationModeTableEntry_dataType_vals[] = {
	{  0, "videoData" },
	{  1, "audioData" },
	{  2, "data" },
	{  0, NULL }
};
static per_choice_t CommunicationModeTableEntry_dataType_choice[] = {
	{  0, "videoData", ASN1_EXTENSION_ROOT,
		dissect_h245_VideoCapability },
	{  1, "audioData", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioCapability },
	{  2, "data", ASN1_EXTENSION_ROOT,
		dissect_h245_DataApplicationCapability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_CommunicationModeTableEntry_dataType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_CommunicationModeTableEntry_dataType, ett_h245_CommunicationModeTableEntry_dataType, CommunicationModeTableEntry_dataType_choice, "dataType", NULL);

	return offset;
}





static per_sequence_t H235Media_sequence[] = {
	{ "encryptionAuthenticationAndIntegrity", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_EncryptionAuthenticationAndIntegrity },
	{ "mediaType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H235Media_mediaType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H235Media(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H235Media, ett_h245_H235Media, H235Media_sequence);

	return offset;
}





static int
dissect_h245_alphanumeric(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_GeneralString(tvb, offset, pinfo, tree, hf_h245_alphanumeric);
	return offset;
}






static const value_string UserInputIndication_userInputSupportIndication_vals[] = {
	{  0, "nonStandard" },
	{  1, "basicString" },
	{  2, "iA5String" },
	{  3, "generalString" },
	{  0, NULL }
};
static per_choice_t UserInputIndication_userInputSupportIndication_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "basicString", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  2, "iA5String", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  3, "generalString", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_UserInputIndication_userInputSupportIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_UserInputIndication_userInputSupportIndication, ett_h245_UserInputIndication_userInputSupportIndication, UserInputIndication_userInputSupportIndication_choice, "userInputSupportIndication", NULL);

	return offset;
}




static per_sequence_t UserInputIndication_extendedAlphanumeric_sequence[] = {
	{ "alphanumeric", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_alphanumeric },
	{ "rtpPayloadIndication", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NULL },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_UserInputIndication_extendedAlphanumeric(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_UserInputIndication_extendedAlphanumeric, ett_h245_UserInputIndication_extendedAlphanumeric, UserInputIndication_extendedAlphanumeric_sequence);

	return offset;
}


static int
dissect_h245_rfcnumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_h245_rfc_number, 1, 32768,
		NULL, NULL, TRUE);
	return offset;
}




static const value_string RTPPayloadType_payloadDescriptor_vals[] = {
	{  0, "nonStandardIdentifier" },
	{  1, "rfc-number" },
	{  2, "oid" },
	{  0, NULL }
};
static per_choice_t RTPPayloadType_payloadDescriptor_choice[] = {
	{  0, "nonStandardIdentifier", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "rfc-number", ASN1_EXTENSION_ROOT,
		dissect_h245_rfcnumber },
	{  2, "oid", ASN1_EXTENSION_ROOT,
		dissect_h245_oid },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RTPPayloadType_payloadDescriptor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RTPPayloadType_payloadDescriptor, ett_h245_RTPPayloadType_payloadDescriptor, RTPPayloadType_payloadDescriptor_choice, "payloadDescriptor", NULL);

	return offset;
}





static per_sequence_t RTPPayloadType_sequence[] = {
	{ "payloadDescriptor", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RTPPayloadType_payloadDescriptor },
	{ "payloadType", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_payloadType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RTPPayloadType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RTPPayloadType, ett_h245_RTPPayloadType, RTPPayloadType_sequence);

	return offset;
}






static const value_string H2250LogicalChannelParameters_mediaPacketization_vals[] = {
	{  0, "h261aVideoPacketization" },
	{  1, "rtpPayloadType" },
	{  0, NULL }
};
static per_choice_t H2250LogicalChannelParameters_mediaPacketization_choice[] = {
	{  0, "h261aVideoPacketization", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  1, "rtpPayloadType", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_RTPPayloadType },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H2250LogicalChannelParameters_mediaPacketization(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H2250LogicalChannelParameters_mediaPacketization, ett_h245_H2250LogicalChannelParameters_mediaPacketization, H2250LogicalChannelParameters_mediaPacketization_choice, "mediaPacketization", NULL);

	return offset;
}





static int dissect_h245_mediaDistributionCapability_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static per_sequence_t MultipointCapability_sequence[] = {
	{ "multicastCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_multicastCapability },
	{ "multiUniCastConference", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_multiUniCastConference },
	{ "mediaDistributionCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_mediaDistributionCapability_sequence_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_receiveMultipointCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_receiveMultipointCapability, ett_h245_MultipointCapability, MultipointCapability_sequence);

	return offset;
}
static int
dissect_h245_transmitMultipointCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_transmitMultipointCapability, ett_h245_MultipointCapability, MultipointCapability_sequence);

	return offset;
}
static int
dissect_h245_receiveAndTransmitMultipointCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_receiveAndTransmitMultipointCapability, ett_h245_MultipointCapability, MultipointCapability_sequence);

	return offset;
}




static per_sequence_t H2250Capability_sequence[] = {
	{ "maximumAudioDelayJitter", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_maximumAudioDelayJitter },
	{ "receiveMultipointCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_receiveMultipointCapability },
	{ "transmitMultipointCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_transmitMultipointCapability },
	{ "receiveAndTransmitMultipointCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_receiveAndTransmitMultipointCapability },
	{ "mcCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H2250Capability_mcCapability },
	{ "rtcpVideoControlCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_rtcpVideoControlCapability },
	{ "mediaPacketizationCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MediaPacketizationCapability },
	{ "transportCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_TransportCapability },
	{ "redundancyEncodingCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RedundancyEncodingCapability_sequence_of },
	{ "logicalChannelSwitchingCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_logicalChannelSwitchingCapability },
	{ "t120DynamicPortCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_t120DynamicPortCapability },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H2250Capability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H2250Capability, ett_h245_H2250Capability, H2250Capability_sequence);

	return offset;
}






static int dissect_h245_DataType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static per_sequence_t RedundancyEncodingElement_sequence[] = {
	{ "dataType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_DataType },
	{ "payloadType", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_payloadType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RedundancyEncodingElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RedundancyEncodingElement, ett_h245_RedundancyEncodingElement, RedundancyEncodingElement_sequence);

	return offset;
}





static per_sequence_t RedundancyEncoding_rtpRedundancyEncoding_sequence[] = {
	{ "primary", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RedundancyEncodingElement },
	{ "secondary", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_secondary_REE_sequence_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RedundancyEncoding_rtpRedundancyEncoding(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RedundancyEncoding_rtpRedundancyEncoding, ett_h245_RedundancyEncoding_rtpRedundancyEncoding, RedundancyEncoding_rtpRedundancyEncoding_sequence);

	return offset;
}





static per_sequence_t RedundancyEncoding_sequence[] = {
	{ "redundancyEncodingMethod", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RedundancyEncodingMethod },
	{ "secondaryEncoding", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_DataType },
	{ "rtpRedundancyEncoding", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RedundancyEncoding_rtpRedundancyEncoding },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RedundancyEncoding(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RedundancyEncoding, ett_h245_RedundancyEncoding, RedundancyEncoding_sequence);

	return offset;
}




static per_sequence_t H2250LogicalChannelParameters_sequence[] = {
	{ "nonStandard", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_nonStandardData_sequence_of },
	{ "sessionID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_sessionID_0_255 },
	{ "associatedSessionID", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_associatedSessionID },
	{ "mediaChannel", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaChannel },
	{ "mediaGuaranteedDelivery", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaGuaranteedDelivery },
	{ "mediaControlChannel", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaControlChannel },
	{ "mediaControlGuaranteedDelivery", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaControlGuaranteedDelivery },
	{ "silenceSuppression", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_silenceSuppression },
	{ "destination", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ "dynamicRTPPayloadType", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_dynamicRTPPayloadType },
	{ "mediaPacketization", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_H2250LogicalChannelParameters_mediaPacketization },
	{ "transportCapability", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_TransportCapability },
	{ "redundancyEncoding", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RedundancyEncoding },
	{ "source", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H2250LogicalChannelParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H2250LogicalChannelParameters, ett_h245_H2250LogicalChannelParameters, H2250LogicalChannelParameters_sequence);

	return offset;
}




static const value_string forwardLogicalChannelParameters_multiplexParameters_vals[] = {
	{  0, "h222LogicalChannelParameters" },
	{  1, "h223LogicalChannelParameters" },
	{  2, "v76LogicalChannelParameters" },
	{  3, "h2250LogicalChannelParameters" },
	{  4, "none" },
	{  0, NULL }
};
static per_choice_t forwardLogicalChannelParameters_multiplexParameters_choice[] = {
	{  0, "h222LogicalChannelParameters", ASN1_EXTENSION_ROOT,
		dissect_h245_H222LogicalChannelParameters },
	{  1, "h223LogicalChannelParameters", ASN1_EXTENSION_ROOT,
		dissect_h245_H223LogicalChannelParameters },
	{  2, "v76LogicalChannelParameters", ASN1_EXTENSION_ROOT,
		dissect_h245_V76LogicalChannelParameters },
	{  3, "h2250LogicalChannelParameters", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_H2250LogicalChannelParameters },
	{  4, "none", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_forwardLogicalChannelParameters_multiplexParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_forwardLogicalChannelParameters_multiplexParameters, ett_h245_forwardLogicalChannelParameters_multiplexParameters, forwardLogicalChannelParameters_multiplexParameters_choice, "multiplexParameters", NULL);

	return offset;
}





static per_sequence_t MultiplePayloadStreamElement_sequence[] = {
	{ "dataType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_DataType },
	{ "payloadType", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_payloadType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplePayloadStreamElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplePayloadStreamElement, ett_h245_MultiplePayloadStreamElement, MultiplePayloadStreamElement_sequence);

	return offset;
}



static const value_string reverseLogicalChannelParameters_multiplexParameters_vals[] = {
	{  0, "h223LogicalChannelParameters" },
	{  1, "v76LogicalChannelParameters" },
	{  2, "h2250LogicalChannelParameters" },
	{  0, NULL }
};
static per_choice_t reverseLogicalChannelParameters_multiplexParameters_choice[] = {
	{  0, "h223LogicalChannelParameters", ASN1_EXTENSION_ROOT,
		dissect_h245_H223LogicalChannelParameters },
	{  1, "v76LogicalChannelParameters", ASN1_EXTENSION_ROOT,
		dissect_h245_V76LogicalChannelParameters },
	{  2, "h2250LogicalChannelParameters", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_H2250LogicalChannelParameters },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_reverseLogicalChannelParameters_multiplexParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_reverseLogicalChannelParameters_multiplexParameters, ett_h245_reverseLogicalChannelParameters_multiplexParameters, reverseLogicalChannelParameters_multiplexParameters_choice, "multiplexParameters", NULL);

	return offset;
}




static const value_string OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters_vals[] = {
	{  0, "h222LogicalChannelParameters" },
	{  1, "h2250LogicalChannelParameters" },
	{  0, NULL }
};
static per_choice_t OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters_choice[] = {
	{  0, "h222LogicalChannelParameters", ASN1_EXTENSION_ROOT,
		dissect_h245_H222LogicalChannelParameters },
	{  1, "h2250LogicalChannelParameters", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_H2250LogicalChannelParameters },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters, ett_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters, OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters_choice, "multiplexParameters", NULL);

	return offset;
}





static per_sequence_t forwardLogicalChannelParameters_sequence[] = {
	{ "portNumber", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_portNumber },
	{ "dataType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_DataType },
	{ "multiplexParameters", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_forwardLogicalChannelParameters_multiplexParameters },
	{ "forwardLogicalChannelDependency", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "replacementFor", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_forwardLogicalChannelParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_forwardLogicalChannelParameters, ett_h245_forwardLogicalChannelParameters, forwardLogicalChannelParameters_sequence);

	return offset;
}




static per_sequence_t reverseLogicalChannelParameters_sequence[] = {
	{ "dataType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_DataType },
	{ "multiplexParameters", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_reverseLogicalChannelParameters_multiplexParameters },
	{ "reverseLogicalChannelDependency", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "replacementFor", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_reverseLogicalChannelParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_reverseLogicalChannelParameters, ett_h245_reverseLogicalChannelParameters, reverseLogicalChannelParameters_sequence);

	return offset;
}





static per_sequence_t OpenLogicalChannelAck_reverseLogicalChannelParameters_sequence[] = {
	{ "reverseLogicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "portNumber", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_portNumber },
	{ "multiplexParameters", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters },
	{ "replacementFor", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters, ett_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters, OpenLogicalChannelAck_reverseLogicalChannelParameters_sequence);

	return offset;
}




static int
dissect_h245_VCCapability_set_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_set_of(tvb, offset, pinfo, tree, hf_h245_VCCapability_set_of, ett_h245_VCCapability_set_of, dissect_h245_VCCapability);
	return offset;
}




static per_sequence_t H222Capability_sequence[] = {
	{ "numberOfVCs", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_numberOfVCs },
	{ "vcCapability", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_VCCapability_set_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H222Capability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H222Capability, ett_h245_H222Capability, H222Capability_sequence);

	return offset;
}




static const value_string MultiplexFormat_vals[] = {
	{  0, "nonStandard" },
	{  1, "h222Capability" },
	{  2, "h223Capability" },
	{  0, NULL }
};
static per_choice_t MultiplexFormat_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "h222Capability", ASN1_EXTENSION_ROOT,
		dissect_h245_H222Capability },
	{  2, "h223Capability", ASN1_EXTENSION_ROOT,
		dissect_h245_H223Capability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultiplexFormat(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultiplexFormat, ett_h245_MultiplexFormat, MultiplexFormat_choice, "MultiplexFormat", NULL);

	return offset;
}




static per_sequence_t MultiplexedStreamCapability_sequence[] = {
	{ "multiplexFormat", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MultiplexFormat },
	{ "controlOnMuxStream", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_controlOnMuxStream },
	{ "capabilityOnMuxStream", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_capabilityOnMuxStream },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplexedStreamCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplexedStreamCapability, ett_h245_MultiplexedStreamCapability, MultiplexedStreamCapability_sequence);

	return offset;
}





static const value_string Capability_vals[] = {
	{  0, "nonStandard" },
	{  1, "receiveVideoCapability" },
	{  2, "transmitVideoCapability" },
	{  3, "receiveAndTransmitVideoCapability" },
	{  4, "receiveAudioCapability" },
	{  5, "transmitAudioCapability" },
	{  6, "receiveAndTransmitAudioCapability" },
	{  7, "receiveDataApplicationCapability" },
	{  8, "transmitDataApplicationCapability" },
	{  9, "receiveAndTransmitDataApplicationCapability" },
	{ 10, "h233EncryptionTransmitCapability" },
	{ 11, "h233EncryptionReceiveCapability" },
	{ 12, "conferenceCapability" },
	{ 13, "h235SecurityCapability" },
	{ 14, "maxPendingReplacementFor" },
	{ 15, "receiveUserInputCapability" },
	{ 16, "transmitUserInputCapability" },
	{ 17, "receiveAndTransmitUserInputCapability" },
	{ 18, "genericControlCapability" },
	{ 19, "receiveMultiplexedStreamCapability" },
	{ 20, "transmitMultiplexedStreamCapability" },
	{ 21, "receiveAndTransmitMultiplexedStreamCapability" },
	{ 22, "receiveRTPAudioTelephonyEventCapability" },
	{ 23, "receiveRTPAudioToneCapability" },
	{ 24, "fecCapability" },
	{ 25, "multiplePayloadStreamCapability" },
	{  0, NULL }
};
static per_choice_t Capability_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "receiveVideoCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_VideoCapability },
	{  2, "transmitVideoCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_VideoCapability },
	{  3, "receiveAndTransmitVideoCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_VideoCapability },
	{  4, "receiveAudioCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioCapability },
	{  5, "transmitAudioCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioCapability },
	{  6, "receiveAndTransmitAudioCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioCapability },
	{  7, "receiveDataApplicationCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_DataApplicationCapability },
	{  8, "transmitDataApplicationCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_DataApplicationCapability },
	{  9, "receiveAndTransmitDataApplicationCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_DataApplicationCapability },
	{ 10, "h233EncryptionTransmitCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_h233EncryptionTransmitCapability },
	{ 11, "h233EncryptionReceiveCapability", ASN1_EXTENSION_ROOT,
		dissect_h245_Capability_h233EncryptionReceiveCapability },
	{ 12, "conferenceCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_ConferenceCapability },
	{ 13, "h235SecurityCapability" , ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_H235SecurityCapability },
	{ 14, "maxPendingReplacementFor", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_maxPendingReplacementFor },
	{ 15, "receiveUserInputCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_UserInputCapability },
	{ 16, "transmitUserInputCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_UserInputCapability },
	{ 17, "receiveAndTransmitUserInputCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_UserInputCapability },
	{ 18, "genericControlCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GenericCapability },
	{ 19, "receiveMultiplexedStreamCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MultiplexedStreamCapability },
	{ 20, "transmitMultiplexedStreamCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MultiplexedStreamCapability },
	{ 21, "receiveAndTransmitMultiplexedStreamCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MultiplexedStreamCapability },
	{ 22, "receiveRTPAudioTelephonyEventCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_AudioTelephonyEventCapability },
	{ 23, "receiveRTPAudioToneCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_AudioToneCapability },
	{ 24, "fecCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_FECCapability },
	{ 25, "multiplePayloadStreamCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MultiplePayloadStreamCapability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_Capability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_Capability, ett_h245_Capability, Capability_choice, "Capability", NULL);

	return offset;
}



static per_sequence_t CapabilityTableEntry_sequence[] = {
	{ "capabilityTableEntryNumber", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_CapabilityTableEntryNumber },
	{ "capability", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h245_Capability },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CapabilityTableEntry(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CapabilityTableEntry, ett_h245_CapabilityTableEntry, CapabilityTableEntry_sequence);

	return offset;
}




static per_sequence_t MultiplexedStreamParameter_sequence[] = {
	{ "multiplexFormat", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_MultiplexFormat },
	{ "controlOnMuxStream", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_controlOnMuxStream },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplexedStreamParameter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplexedStreamParameter, ett_h245_MultiplexedStreamParameter, MultiplexedStreamParameter_sequence);

	return offset;
}





static const value_string DataType_vals[] = {
	{  0, "nonStandard" },
	{  1, "nullData" },
	{  2, "videoData" },
	{  3, "audioData" },
	{  4, "data" },
	{  5, "encryptionData" },
	{  6, "h235Control" },
	{  7, "h235Media" },
	{  8, "multiplexedStream" },
	{  9, "redundancyEncoding" },
	{ 10, "multiplePayloadStream" },
	{ 11, "fec" },
	{  0, NULL }
};
static per_choice_t DataType_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "nullData", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  2, "videoData", ASN1_EXTENSION_ROOT,
		dissect_h245_VideoCapability },
	{  3, "audioData", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioCapability },
	{  4, "data", ASN1_EXTENSION_ROOT,
		dissect_h245_DataApplicationCapability },
	{  5, "encryptionData", ASN1_EXTENSION_ROOT,
		dissect_h245_EncryptionMode },
	{  6, "h235Control", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  7, "h235Media", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_H235Media },
	{  8, "multiplexedStream", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MultiplexedStreamParameter },
	{  9, "redundancyEncoding", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_RedundancyEncoding },
	{ 10, "multiplePayloadStream", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MultiplePayloadStream },
	{ 11, "fec", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_FECData },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_DataType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_DataType, ett_h245_DataType, DataType_choice, "DataType", NULL);

	return offset;
}




static int dissect_h245_VBDMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static const value_string AudioMode_vals[] = {
	{  0, "nonStandard" },
	{  1, "g711Alaw64k" },
	{  2, "g711Alaw56k" },
	{  3, "g711Ulaw64k" },
	{  4, "g711Ulaw56k" },
	{  5, "g722-64k" },
	{  6, "g722-56k" },
	{  7, "g722-48k" },
	{  8, "g728" },
	{  9, "g729" },
	{ 10, "g729AnnexA" },
	{ 11, "g7231" },
	{ 12, "is11172AudioMode" },
	{ 13, "is13818AudioMode" },
	{ 14, "g729wAnnexB" },
	{ 15, "g729AnnexAwAnnexB" },
	{ 16, "g7231AnnexCMode" },
	{ 17, "gsmFullRate" },
	{ 18, "gsmHalfRate" },
	{ 19, "gsmEnhancedFullRate" },
	{ 20, "genericAudioMode" },
	{ 21, "g729Extensions" },
	{ 22, "vbd" },
	{  0, NULL }
};
static per_choice_t AudioMode_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "g711Alaw64k", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  2, "g711Alaw56k", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  3, "g711Ulaw64k", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  4, "g711Ulaw56k", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  5, "g722-64k", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  6, "g722-56k", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  7, "g722-48k", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  8, "g728", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  9, "g729", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{ 10, "g729AnnexA", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{ 11, "g7231", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioMode_g7231 },
	{ 12, "is11172AudioMode", ASN1_EXTENSION_ROOT,
		dissect_h245_IS11172AudioMode },
	{ 13, "is13818AudioMode", ASN1_EXTENSION_ROOT,
		dissect_h245_IS13818AudioMode },
	{ 14, "g729wAnnexB", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_g729wAnnexB },
	{ 15, "g729AnnexAwAnnexB", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_g729AnnexAwAnnexB },
	{ 16, "g7231AnnexCMode", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_G7231AnnexCMode },
	{ 17, "gsmFullRate", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GSMAudioCapability },
	{ 18, "gsmHalfRate", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GSMAudioCapability },
	{ 19, "gsmEnhancedFullRate", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GSMAudioCapability },
	{ 20, "genericAudioMode", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GenericCapability },
	{ 21, "g729Extensions", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_G729Extensions },
	{ 22, "vbd", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_VBDMode },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_AudioMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_AudioMode, ett_h245_AudioMode, AudioMode_choice, "AudioMode", NULL);

	return offset;
}




static const value_string RedundancyEncodingMode_secondaryEncoding_vals[] = {
	{  0, "nonStandard" },
	{  1, "audioData" },
	{  0, NULL }
};
static per_choice_t RedundancyEncodingMode_secondaryEncoding_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "audioData", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioMode },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RedundancyEncodingMode_secondaryEncoding(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RedundancyEncodingMode_secondaryEncoding, ett_h245_RedundancyEncodingMode_secondaryEncoding, RedundancyEncodingMode_secondaryEncoding_choice, "secondaryEncoding", NULL);

	return offset;
}



static per_sequence_t RedundancyEncodingMode_sequence[] = {
	{ "redundancyEncodingMethod", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RedundancyEncodingMethod },
	{ "secondaryEncoding", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RedundancyEncodingMode_secondaryEncoding },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RedundancyEncodingMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RedundancyEncodingMode, ett_h245_RedundancyEncodingMode, RedundancyEncodingMode_sequence);

	return offset;
}



static per_sequence_t H2250ModeParameters_sequence[] = {
	{ "redundancyEncodingMode", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RedundancyEncodingMode },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H2250ModeParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H2250ModeParameters, ett_h245_H2250ModeParameters, H2250ModeParameters_sequence);

	return offset;
}





static per_sequence_t VBDMode_sequence[] = {
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_AudioMode },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_VBDMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_VBDMode, ett_h245_VBDMode, VBDMode_sequence);

	return offset;
}



static const value_string MultiplexCapability_vals[] = {
	{  0, "nonStandard" },
	{  1, "h222Capability" },
	{  2, "h223Capability" },
	{  3, "v76Capability" },
	{  4, "h2250Capability" },
	{  5, "genericMultiplexCapability" },
	{  0, NULL }
};
static per_choice_t MultiplexCapability_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "h222Capability", ASN1_EXTENSION_ROOT,
		dissect_h245_H222Capability },
	{  2, "h223Capability", ASN1_EXTENSION_ROOT,
		dissect_h245_H223Capability },
	{  3, "v76Capability", ASN1_EXTENSION_ROOT,
		dissect_h245_V76Capability },
	{  4, "h2250Capability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_H2250Capability },
	{  5, "genericMultiplexCapability", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GenericCapability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_MultiplexCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_MultiplexCapability, ett_h245_MultiplexCapability, MultiplexCapability_choice, "MultiplexCapability", NULL);

	return offset;
}





static per_sequence_t TerminalCapabilitySet_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "protocolIdentifier", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_protocolIdentifier },
	{ "multiplexCapability", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_MultiplexCapability },
	{ "capabilityTable", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_capabilityTable },
	{ "capabilityDescriptors", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_capabilityDescriptors },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_TerminalCapabilitySet(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_TerminalCapabilitySet, ett_h245_TerminalCapabilitySet, TerminalCapabilitySet_sequence);

	return offset;
}






static per_sequence_t ConferenceResponse_terminalIDResponse_sequence[] = {
	{ "terminalLabel", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ "terminalID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_TerminalID },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ConferenceResponse_terminalIDResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse_terminalIDResponse, ett_h245_ConferenceResponse_terminalIDResponse, ConferenceResponse_terminalIDResponse_sequence);

	return offset;
}





static const value_string ConferenceResponse_vals[] = {
	{  0, "mCTerminalIDResponse" },
	{  1, "terminalIDResponse" },
	{  2, "conferenceIDResponse" },
	{  3, "passwordResponse" },
	{  4, "terminalListResponse" },
	{  5, "videoCommandReject" },
	{  6, "terminalDropReject" },
	{  7, "makeMeChairResponse" },
	{  8, "extensionAddressResponse" },
	{  9, "chairTokenOwnerResponse" },
	{ 10, "terminalCertificateResponse" },
	{ 11, "broadcastMyLogicalChannelResponse" },
	{ 12, "makeTerminalBroadcasterResponse" },
	{ 13, "sendThisSourceResponse" },
	{ 14, "requestAllTerminalIDsResponse" },
	{ 15, "remoteMCResponse" },
	{  0, NULL }
};
static per_choice_t ConferenceResponse_choice[] = {
	{  0, "mCTerminalIDResponse", ASN1_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_mCterminalIDResponse },
	{  1, "terminalIDResponse", ASN1_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_terminalIDResponse },
	{  2, "conferenceIDResponse", ASN1_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_conferenceIDResponse },
	{  3, "passwordResponse", ASN1_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_passwordResponse },
	{  4, "terminalListResponse", ASN1_EXTENSION_ROOT,
		dissect_h245_terminalListResponse },
	{  5, "videoCommandReject", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  6, "terminalDropReject", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  7, "makeMeChairResponse", ASN1_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_makeMeChairResponse },
	{  8, "extensionAddressResponse", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_extensionAddressResponse },
	{  9, "chairTokenOwnerResponse", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_chairTokenOwnerResponse },
	{ 10, "terminalCertificateResponse", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_terminalCertificateResponse },
	{ 11, "broadcastMyLogicalChannelResponse", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_broadcastMyLogicalChannelResponse },
	{ 12, "makeTerminalBroadcasterResponse", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_makeTerminalBroadcasterResponse },
	{ 13, "sendThisSourceResponse", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_ConferenceResponse_sendThisSourceResponse },
	{ 14, "requestAllTerminalIDsResponse", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_RequestAllTerminalIDsResponse },
	{ 15, "remoteMCResponse", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_RemoteMCResponse },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ConferenceResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ConferenceResponse, ett_h245_ConferenceResponse, ConferenceResponse_choice, "ConferenceResponse", NULL);

	return offset;
}





static const value_string H261VideoMode_resolution_vals[] = {
	{  0, "qcif" },
	{  1, "cif" },
	{  0, NULL }
};
static per_choice_t H261VideoMode_resolution_choice[] = {
	{  0, "qcif", ASN1_NO_EXTENSIONS,
		dissect_h245_NULL },
	{  1, "cif", ASN1_NO_EXTENSIONS,
		dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H261VideoMode_resolution(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H261VideoMode_resolution, ett_h245_H261VideoMode_resolution, H261VideoMode_resolution_choice, "resolution", NULL);

	return offset;
}




static per_sequence_t H261VideoMode_sequence[] = {
	{ "resolution", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H261VideoMode_resolution },
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_h223bitRate },
	{ "stillImageTransmission", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_stillImageTransmission },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H261VideoMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H261VideoMode, ett_h245_H261VideoMode, H261VideoMode_sequence);

	return offset;
}




static const value_string VideoMode_vals[] = {
	{  0, "nonStandard" },
	{  1, "h261VideoMode" },
	{  2, "h262VideoMode" },
	{  3, "h263VideoMode" },
	{  4, "is11172VideoMode" },
	{  5, "genericVideoMode" },
	{  0, NULL }
};
static per_choice_t VideoMode_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "h261VideoMode", ASN1_EXTENSION_ROOT,
		dissect_h245_H261VideoMode },
	{  2, "h262VideoMode", ASN1_EXTENSION_ROOT,
		dissect_h245_H262VideoMode },
	{  3, "h263VideoMode", ASN1_EXTENSION_ROOT,
		dissect_h245_H263VideoMode },
	{  4, "is11172VideoMode", ASN1_EXTENSION_ROOT,
		dissect_h245_IS11172VideoMode},
	{  5, "genericVideoMode", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_GenericCapability },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_VideoMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_VideoMode, ett_h245_VideoMode, VideoMode_choice, "VideoMode", NULL);

	return offset;
}




static const value_string H235Mode_mediaMode_vals[] = {
	{  0, "nonStandard" },
	{  1, "videoMode" },
	{  2, "audioMode" },
	{  3, "dataMode" },
	{  0, NULL }
};
static per_choice_t H235Mode_mediaMode_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "videoMode", ASN1_EXTENSION_ROOT,
		dissect_h245_VideoMode },
	{  2, "audioMode", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioMode },
	{  3, "dataMode", ASN1_EXTENSION_ROOT,
		dissect_h245_DataMode },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_H235Mode_mediaMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_H235Mode_mediaMode, ett_h245_H235Mode_mediaMode, H235Mode_mediaMode_choice, "mediaMode", NULL);

	return offset;
}




static per_sequence_t H235Mode_sequence[] = {
	{ "encryptionAuthenticationAndIntegrity", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_EncryptionAuthenticationAndIntegrity },
	{ "mediaMode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H235Mode_mediaMode },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H235Mode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H235Mode, ett_h245_H235Mode, H235Mode_sequence);

	return offset;
}





static const value_string RedundancyEncodingDTModeElement_type_vals[] = {
	{  0, "nonStandard" },
	{  1, "videoMode" },
	{  2, "audioMode" },
	{  3, "dataMode" },
	{  4, "encryptionMode" },
	{  5, "h235Mode" },
	{  0, NULL }
};
static per_choice_t RedundancyEncodingDTModeElement_type_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "videoMode", ASN1_EXTENSION_ROOT,
		dissect_h245_VideoMode },
	{  2, "audioMode", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioMode },
	{  3, "dataMode", ASN1_EXTENSION_ROOT,
		dissect_h245_DataMode },
	{  4, "encryptionMode", ASN1_EXTENSION_ROOT,
		dissect_h245_EncryptionMode },
	{  5, "h235Mode", ASN1_EXTENSION_ROOT,
		dissect_h245_H235Mode },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RedundancyEncodingDTModeElement_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RedundancyEncodingDTModeElement_type, ett_h245_RedundancyEncodingDTModeElement_type, RedundancyEncodingDTModeElement_type_choice, "type", NULL);

	return offset;
}




static per_sequence_t RedundancyEncodingDTModeElement_sequence[] = {
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RedundancyEncodingDTModeElement_type },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RedundancyEncodingDTModeElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RedundancyEncodingDTModeElement, ett_h245_RedundancyEncodingDTModeElement, RedundancyEncodingDTModeElement_sequence);

	return offset;
}





static per_sequence_t RedundancyEncodingDTMode_sequence[] = {
	{ "redundancyEncodingMethod", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RedundancyEncodingMethod },
	{ "primary", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RedundancyEncodingDTModeElement },
	{ "secondary", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_secondary_REDTME_sequence_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RedundancyEncodingDTMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RedundancyEncodingDTMode, ett_h245_RedundancyEncodingDTMode, RedundancyEncodingDTMode_sequence);

	return offset;
}




static int dissect_h245_FECMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static const value_string ModeElementType_vals[] = {
	{  0, "nonStandard" },
	{  1, "videoMode" },
	{  2, "audioMode" },
	{  3, "dataMode" },
	{  4, "encryptionMode" },
	{  5, "h235Mode" },
	{  6, "multiplexedStreamMode" },
	{  7, "redundancyEncodingDTMode" },
	{  8, "multiplePayloadStreamMode" },
	{  9, "fecMode" },
	{  0, NULL }
};
static per_choice_t ModeElementType_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "videoMode", ASN1_EXTENSION_ROOT,
		dissect_h245_VideoMode },
	{  2, "audioMode", ASN1_EXTENSION_ROOT,
		dissect_h245_AudioMode },
	{  3, "dataMode", ASN1_EXTENSION_ROOT,
		dissect_h245_DataMode },
	{  4, "encryptionMode", ASN1_EXTENSION_ROOT,
		dissect_h245_EncryptionMode },
	{  5, "h235Mode", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_H235Mode },
	{  6, "multiplexedStreamMode", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MultiplexedStreamParameter },
	{  7, "redundancyEncodingDTMode", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_RedundancyEncodingDTMode },
	{  8, "multiplePayloadStreamMode", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MultiplePayloadStreamMode },
	{  9, "fecMode", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_FECMode },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ModeElementType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ModeElementType, ett_h245_ModeElementType, ModeElementType_choice, "ModeElementType", NULL);

	return offset;
}




static per_sequence_t MultiplePayloadStreamElementMode_sequence[] = {
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ModeElementType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MultiplePayloadStreamElementMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MultiplePayloadStreamElementMode, ett_h245_MultiplePayloadStreamElementMode, MultiplePayloadStreamElementMode_sequence);

	return offset;
}





static per_sequence_t FECMode_rfc2733Mode_mode_separateStream_samePort_sequence[] = {
	{ "protectedType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ModeElementType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FECMode_rfc2733Mode_mode_separateStream_samePort(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FECMode_rfc2733Mode_mode_separateStream_samePort, ett_h245_FECMode_rfc2733Mode_mode_separateStream_samePort, FECMode_rfc2733Mode_mode_separateStream_samePort_sequence);

	return offset;
}



static const value_string FECMode_rfc2733Mode_mode_separateStream_vals[] = {
	{  0, "differentPort" },
	{  1, "samePort" },
	{  0, NULL }
};
static per_choice_t FECMode_rfc2733Mode_mode_separateStream_choice[] = {
	{  0, "differentPort", ASN1_EXTENSION_ROOT,
		dissect_h245_FECMode_rfc2733Mode_mode_separateStream_differentPort },
	{  1, "samePort", ASN1_EXTENSION_ROOT,
		dissect_h245_FECMode_rfc2733Mode_mode_separateStream_samePort },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FECMode_rfc2733Mode_mode_separateStream(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FECMode_rfc2733Mode_mode_separateStream, ett_h245_FECMode_rfc2733Mode_mode_separateStream, FECMode_rfc2733Mode_mode_separateStream_choice, "separateStream", NULL);

	return offset;
}





static const value_string FECMode_rfc2733Mode_mode_vals[] = {
	{  0, "redundancyEncoding" },
	{  1, "separateStream" },
	{  0, NULL }
};
static per_choice_t FECMode_rfc2733Mode_mode_choice[] = {
	{  0, "redundancyEncoding", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  1, "separateStream", ASN1_EXTENSION_ROOT,
		dissect_h245_FECMode_rfc2733Mode_mode_separateStream },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FECMode_rfc2733Mode_mode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FECMode_rfc2733Mode_mode, ett_h245_FECMode_rfc2733Mode_mode, FECMode_rfc2733Mode_mode_choice, "mode", NULL);

	return offset;
}



static per_sequence_t FECMode_rfc2733Mode_sequence[] = {
	{ "mode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_FECMode_rfc2733Mode_mode },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_FECMode_rfc2733Mode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_FECMode_rfc2733Mode, ett_h245_FECMode_rfc2733Mode, FECMode_rfc2733Mode_sequence);

	return offset;
}




static const value_string FECMode_vals[] = {
	{  0, "rfc2733Mode" },
	{  0, NULL }
};
static per_choice_t FECMode_choice[] = {
	{  0, "rfc2733Mode", ASN1_EXTENSION_ROOT,
		dissect_h245_FECMode_rfc2733Mode },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FECMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FECMode, ett_h245_FECMode, FECMode_choice, "FECMode", NULL);

	return offset;
}




static int dissect_h245_RequestMessage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_h245_ResponseMessage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_h245_CommandMessage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static const value_string FunctionNotUnderstood_vals[] = {
	{  0, "request" },
	{  1, "response" },
	{  2, "command" },
	{  0, NULL }
};
static per_choice_t FunctionNotUnderstood_choice[] = {
	{  0, "request", ASN1_NO_EXTENSIONS,
		dissect_h245_RequestMessage },
	{  1, "response", ASN1_NO_EXTENSIONS,
		dissect_h245_ResponseMessage },
	{  2, "command", ASN1_NO_EXTENSIONS,
		dissect_h245_CommandMessage },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_FunctionNotUnderstood(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_FunctionNotUnderstood, ett_h245_FunctionNotUnderstood, FunctionNotUnderstood_choice, "FunctionNotUnderstood", NULL);

	return offset;
}



static int
dissect_h245_signalType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* XXX this is just wrong.
         * the definition in the ASN.1 file is :
	 *   signalType	IA5String (SIZE (1) ^ FROM ("0123456789#*ABCD!"))
	 * which means the 17 characters are encoded as 8-bit values 
	 * between 0x00 and 0x10
         *
	 * however, captures from real world applications show that
	 * the field is encoded instead as :
	 *   signalType	IA5String (SIZE (1))
	 * ie a single character ascii value from 0x00 to 0xff.
	 *
	 * the code is changed under protest.
	 * i still think it is the one commented out that is the correct one
	 */
         /*offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h245_signalType, 1, 1, "!#*0123456789ABCD", 17);*/

         offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h245_signalType, 1, 1);


	return offset;
}







static per_sequence_t UserInputIndication_signal_sequence[] = {
	{ "signalType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_signalType },
	{ "duration", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_duration },
	{ "rtp", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_UserInputIndication_signal_rtp },
	{ "rtpPayloadIndication", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NULL },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_UserInputIndication_signal(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_UserInputIndication_signal, ett_h245_UserInputIndication_signal, UserInputIndication_signal_sequence);

	return offset;
}




static const value_string UserInputIndication_vals[] = {
	{  0, "nonStandard" },
	{  1, "alphanumeric" },
	{  2, "userInputSupportIndication" },
	{  3, "signal" },
	{  4, "signalUpdate" },
	{  5, "extendedAlphanumeric" },
	{  0, NULL }
};
static per_choice_t UserInputIndication_choice[] = {
	{  0, "nonStandard", ASN1_EXTENSION_ROOT,
		dissect_h245_NonStandardParameter },
	{  1, "alphanumeric", ASN1_EXTENSION_ROOT,
		dissect_h245_alphanumeric },
	{  2, "userInputSupportIndication", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_UserInputIndication_userInputSupportIndication },
	{  3, "signal", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_UserInputIndication_signal },
	{  4, "signalUpdate", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_UserInputIndication_signalUpdate },
	{  5, "extendedAlphanumeric", ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_UserInputIndication_extendedAlphanumeric },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_UserInputIndication(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_UserInputIndication, ett_h245_UserInputIndication, UserInputIndication_choice, "UserInputIndication", NULL);

	return offset;
}





static per_sequence_t TerminalCapabilitySetRelease_sequence[] = {
	{ NULL, ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, NULL }
};
static int
dissect_h245_TerminalCapabilitySetRelease(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_TerminalCapabilitySetRelease, ett_h245_TerminalCapabilitySetRelease, TerminalCapabilitySetRelease_sequence);

	return offset;
}



static int
dissect_h245_internationalNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_NumericString(tvb, offset, pinfo, tree, hf_h245_internationalNumber, 1, 16);
	return offset;
}





static const value_string Q2931Address_address_vals[] = {
	{  0, "internationalNumber" },
	{  1, "nsapAddress" },
	{  0, NULL }
};
static per_choice_t Q2931Address_address_choice[] = {
	{  0, "internationalNumber", ASN1_EXTENSION_ROOT,
		dissect_h245_internationalNumber },
	{  1, "nsapAddress", ASN1_EXTENSION_ROOT,
		dissect_h245_nsapAddress},
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_Q2931Address_address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_Q2931Address_address, ett_h245_Q2931Address_address, Q2931Address_address_choice, "address", NULL);

	return offset;
}





static per_sequence_t Q2931Address_sequence[] = {
	{ "address", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_Q2931Address_address },
	{ "subaddress", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_subaddress_1_20 },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_Q2931Address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_Q2931Address, ett_h245_Q2931Address, Q2931Address_sequence);

	return offset;
}




static int
dissect_h245_e164Address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_restricted_character_string(tvb, offset, pinfo, tree, hf_h245_e164Address, 1, 128, "#*,0123456789", 13);

	return offset;
}




static const value_string NetworkAccessParameters_networkAddress_vals[] = {
	{  0, "q2931Address" },
	{  1, "e164Address" },
	{  2, "localAreaAddress" },
	{  0, NULL }
};
static per_choice_t NetworkAccessParameters_networkAddress_choice[] = {
	{  0, "q2931Address", ASN1_EXTENSION_ROOT,
		dissect_h245_Q2931Address },
	{  1, "e164Address", ASN1_EXTENSION_ROOT,
		dissect_h245_e164Address },
	{  2, "localAreaAddress", ASN1_EXTENSION_ROOT,
		dissect_h245_localAreaAddress },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_NetworkAccessParameters_networkAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_NetworkAccessParameters_networkAddress, ett_h245_NetworkAccessParameters_networkAddress, NetworkAccessParameters_networkAddress_choice, "networkAddress", NULL);

	return offset;
}





static per_sequence_t NetworkAccessParameters_sequence[] = {
	{ "distribution", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NetworkAccessParameters_distribution },
	{ "networkAddress", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NetworkAccessParameters_networkAddress },
	{ "associateConference", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_associateConference},
	{ "externalReference", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_externalReference },
	{ "t120SetupProcedure", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NetworkAccessParameters_t120SetupProcedure },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NetworkAccessParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NetworkAccessParameters, ett_h245_NetworkAccessParameters, NetworkAccessParameters_sequence);

	return offset;
}





static per_sequence_t OpenLogicalChannel_sequence[] = {
	{ "forwardLogicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "forwardLogicalChannelParameters", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_forwardLogicalChannelParameters },
	{ "reverseLogicalChannelParameters", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_reverseLogicalChannelParameters },
	{ "separateStack", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NetworkAccessParameters },
	{ "encryptionSync", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_EncryptionSync },
	{ NULL, 0, 0, NULL }
};
int
dissect_h245_OpenLogicalChannel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_OpenLogicalChannel, ett_h245_OpenLogicalChannel, OpenLogicalChannel_sequence);

	return offset;
}




static per_sequence_t OpenLogicalChannelAck_sequence[] = {
	{ "forwardLogicalChannelNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_LogicalChannelNumber },
	{ "reverseLogicalChannelParameters", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters },
	{ "separateStack", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_NetworkAccessParameters },
	{ "forwardMultiplexAckParameters", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_forwardMultiplexAckParameters},
	{ "encryptionSync", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_EncryptionSync},
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_OpenLogicalChannelAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_OpenLogicalChannelAck, ett_h245_OpenLogicalChannelAck, OpenLogicalChannelAck_sequence);

	return offset;
}




static int
dissect_h245_escrowValue(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
NOT_DECODED_YET("escrowValue");
	return offset;
}





static per_sequence_t EscrowData_sequence[] = {
	{ "escrowID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_escrowID },
	{ "escrowValue", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_escrowValue },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_EscrowData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_EscrowData, ett_h245_EscrowData, EscrowData_sequence);

	return offset;
}









static const value_string RequestModeAck_response_decision_vals[] = {
	{  0, "willTransmitMostPreferredMode" },
	{  1, "willTransmitLessPreferredMode" },
	{  0, NULL }
};
static per_choice_t RequestModeAck_response_decision_choice[] = {
	{  0, "willTransmitMostPreferredMode", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  1, "willTransmitLessPreferredMode", ASN1_EXTENSION_ROOT,
		dissect_h245_NULL },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RequestModeAck_response_decision(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RequestModeAck_response_decision, ett_h245_RequestModeAck_response_decision, RequestModeAck_response_decision_choice, "decision", NULL);

	return offset;
}





static per_sequence_t RequestModeAck_sequence[] = {
	{ "sequenceNumber", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_SequenceNumber },
	{ "response", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_RequestModeAck_response_decision },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_RequestModeAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestModeAck, ett_h245_RequestModeAck, RequestModeAck_sequence);

	return offset;
}




static per_sequence_t RequestModeRelease_sequence[] = {
	{ NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};
static int
dissect_h245_RequestModeRelease(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_RequestModeRelease, ett_h245_RequestModeRelease, RequestModeRelease_sequence);

	return offset;
}



static per_sequence_t MaintenanceLoopOffCommand_sequence[] = {
	{ NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};
static int
dissect_h245_MaintenanceLoopOffCommand(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MaintenanceLoopOffCommand, ett_h245_MaintenanceLoopOffCommand, MaintenanceLoopOffCommand_sequence);

	return offset;
}




static per_sequence_t CommunicationModeRequest_sequence[] = {
	{ NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};
static int
dissect_h245_CommunicationModeRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CommunicationModeRequest, ett_h245_CommunicationModeRequest, CommunicationModeRequest_sequence);

	return offset;
}




static const value_string IndicationMessage_short_vals[] = {
	{  0,	"NSM" },
	{  1,	"FNU" },
	{  2,	"MSDRelease" },
	{  3,	"TCSRelease" },
	{  4,	"OLCConfirm" },
	{  5,	"RCCRelease" },
	{  6,	"MESRelease" },
	{  7,	"RMERelease" },
	{  8,	"RMRelease" },
	{  9,	"MI" },
	{ 10,	"JI" },
	{ 11,	"H223SI" },
	{ 12,	"NATMVCI" },
	{ 13,	"UII" },
	{ 14,	"H2250MSI" },
	{ 15,	"MCLI" },
	{ 16,	"CI" },
	{ 17,	"VI" },
	{ 18,	"FNS" },
	{ 19,	"MultilinkIndication" },
	{ 20,	"LCRRelease" },
	{ 21,	"FCIndication" },
	{ 22,	"MMRI" },
	{  0, NULL }
};


static const value_string IndicationMessage_vals[] = {
	{  0,	"NonStandardMessage" },
	{  1,	"FunctionNotUnderstood" },
	{  2,	"MasterSlaveDeterminationRelease" },
	{  3,	"TerminalCapabilitySetRelease" },
	{  4,	"OpenLogicalChannelConfirm" },
	{  5,	"RequestChannelCloseRelease" },
	{  6,	"MultiplexEntrySendRelease" },
	{  7,	"RequestMultiplexEntryRelease" },
	{  8,	"RequestModeRelease" },
	{  9,	"MiscellaneousIndication" },
	{ 10,	"JitterIndication" },
	{ 11,	"H223SkewIndication" },
	{ 12,	"NewATMVCIndication" },
	{ 13,	"UserInputIndication" },
	{ 14,	"H2250MaximumSkewIndication" },
	{ 15,	"MCLocationIndication" },
	{ 16,	"ConferenceIndication" },
	{ 17,	"VendorIdentification" },
	{ 18,	"FunctionNotSupported" },
	{ 19,	"MultilinkIndication" },
	{ 20,	"LogicalChannelRateRelease" },
	{ 21,	"FlowControlIndication" },
	{ 22,	"MobileMultilinkReconfigurationIndication" },
	{  0, NULL }
};
static per_choice_t IndicationMessage_choice[] = {
	{  0,	"NonStandardMessage",			ASN1_EXTENSION_ROOT,
			dissect_h245_NonStandardMessage },
	{  1,	"FunctionNotUnderstood",		ASN1_EXTENSION_ROOT,
			dissect_h245_FunctionNotUnderstood },
	{  2,	"MasterSlaveDeterminationRelease",	ASN1_EXTENSION_ROOT,
			dissect_h245_MasterSlaveDeterminationRelease },
	{  3,	"TerminalCapabilitySetRelease",		ASN1_EXTENSION_ROOT,
			dissect_h245_TerminalCapabilitySetRelease },
	{  4,	"OpenLogicalChannelConfirm",		ASN1_EXTENSION_ROOT,
			dissect_h245_OpenLogicalChannelConfirm },
	{  5,	"RequestChannelCloseRelease",		ASN1_EXTENSION_ROOT,
			dissect_h245_RequestChannelCloseRelease },
	{  6,	"MultiplexEntrySendRelease",		ASN1_EXTENSION_ROOT,
			dissect_h245_MultiplexEntrySendRelease },
	{  7,	"RequestMultiplexEntryRelease",		ASN1_EXTENSION_ROOT,
			dissect_h245_RequestMultiplexEntryRelease },
	{  8,	"RequestModeRelease",			ASN1_EXTENSION_ROOT,
			dissect_h245_RequestModeRelease },
	{  9,	"MiscellaneousIndication",		ASN1_EXTENSION_ROOT,
			dissect_h245_MiscellaneousIndication },
	{ 10,	"JitterIndication",			ASN1_EXTENSION_ROOT,
			dissect_h245_JitterIndication },
	{ 11,	"H223SkewIndication",			ASN1_EXTENSION_ROOT,
			dissect_h245_H223SkewIndication },
	{ 12,	"NewATMVCIndication",			ASN1_EXTENSION_ROOT,
			dissect_h245_NewATMVCIndication },
	{ 13,	"UserInputIndication",			ASN1_EXTENSION_ROOT,
			dissect_h245_UserInputIndication },
	{ 14,	"H2250MaximumSkewIndication",		ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_H2250MaximumSkewIndication },
	{ 15,	"MCLocationIndication",			ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_MCLocationIndication },
	{ 16,	"ConferenceIndication",			ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_ConferenceIndication },
	{ 17,	"VendorIdentification",			ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_VendorIdentification },
	{ 18,	"FunctionNotSupported",			ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_FunctionNotSupported },
	{ 19,	"MultilinkIndication",			ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MultilinkIndication },
	{ 20,	"LogicalChannelRateRelease",		ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_LogicalChannelRateRelease },
	{ 21,	"FlowControlIndication",		ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_FlowControlIndication },
	{ 22,	"MobileMultilinkReconfigurationIndication",ASN1_NOT_EXTENSION_ROOT,
		dissect_h245_MobileMultilinkReconfigurationIndication },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_IndicationMessage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 value;

	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_IndicationMessage_type, ett_h245_IndicationMessage, IndicationMessage_choice, "IndicationMessage", &value);

	if (check_col(pinfo->cinfo, COL_INFO)){
	        if ( h245_shorttypes == TRUE )
	        {
	        	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, IndicationMessage_short_vals, "<unknown>"));
		}
		else
		{
	        	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, IndicationMessage_vals, "<unknown>"));
		}
	}

	col_set_fence(pinfo->cinfo,COL_INFO);

	return offset;
}



static const value_string RequestMessage_short_vals[] = {
	{  0,	"NSM" },
	{  1,	"MSD" },
	{  2,	"TCS" },
	{  3,	"OLC" },
	{  4,	"CLC" },
	{  5,	"RCC" },
	{  6,	"MES" },
	{  7,	"RME" },
	{  8,	"RM" },
	{  9,	"RTDR" },
	{ 10,	"MLR" },
	{ 11,	"CMR" },
	{ 12,	"CR" },
	{ 13,	"MR" },
	{ 14,	"LCRR" },
	{  0, NULL }
};


static const value_string RequestMessage_vals[] = {
	{  0,	"NonStandardMessage" },
	{  1,	"MasterSlaveDetermination" },
	{  2,	"TerminalCapabilitySet" },
	{  3,	"OpenLogicalChannel" },
	{  4,	"CloseLogicalChannel" },
	{  5,	"RequestChannelClose" },
	{  6,	"MultiplexEntrySend" },
	{  7,	"RequestMultiplexEntry" },
	{  8,	"RequestMode" },
	{  9,	"RoundTripDelayRequest" },
	{ 10,	"MaintenanceLoopRequest" },
	{ 11,	"CommunicationModeRequest" },
	{ 12,	"ConferenceRequest" },
	{ 13,	"MultilinkRequest" },
	{ 14,	"LogicalChannelRateRequest" },
	{  0, NULL }
};
static per_choice_t RequestMessage_choice[] = {
	{  0,	"NonStandardMessage",		ASN1_EXTENSION_ROOT,
			dissect_h245_NonStandardMessage },
	{  1,	"MasterSlaveDetermination",	ASN1_EXTENSION_ROOT,
			dissect_h245_MasterSlaveDetermination },
	{  2,	"TerminalCapabilitySet",	ASN1_EXTENSION_ROOT,
			dissect_h245_TerminalCapabilitySet },
	{  3,	"OpenLogicalChannel",		ASN1_EXTENSION_ROOT,
			dissect_h245_OpenLogicalChannel },
	{  4,	"CloseLogicalChannel",		ASN1_EXTENSION_ROOT,
			dissect_h245_CloseLogicalChannel },
	{  5,	"RequestChannelClose",		ASN1_EXTENSION_ROOT,
			dissect_h245_RequestChannelClose },
	{  6,	"MultiplexEntrySend",		ASN1_EXTENSION_ROOT,
			dissect_h245_MultiplexEntrySend },
	{  7,	"RequestMultiplexEntry",	ASN1_EXTENSION_ROOT,
			dissect_h245_RequestMultiplexEntry },
	{  8,	"RequestMode",			ASN1_EXTENSION_ROOT,
			dissect_h245_RequestMode },
	{  9,	"RoundTripDelayRequest",	ASN1_EXTENSION_ROOT,
			dissect_h245_RoundTripDelayRequest },
	{ 10,	"MaintenanceLoopRequest",	ASN1_EXTENSION_ROOT,
			dissect_h245_MaintenanceLoopRequest },
	{ 11,	"CommunicationModeRequest",	ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_CommunicationModeRequest },
	{ 12,	"ConferenceRequest",		ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_ConferenceRequest },
	{ 13,	"MultilinkRequest",		ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_MultilinkRequest },
	{ 14,	"LogicalChannelRateRequest",	ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_LogicalChannelRateRequest },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_RequestMessage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 value;

	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_RequestMessage_type, ett_h245_RequestMessage, RequestMessage_choice, "RequestMessage", &value);

	if (check_col(pinfo->cinfo, COL_INFO)){
	        if ( h245_shorttypes == TRUE )
	        {
	        	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, RequestMessage_short_vals, "<unknown>"));
		}
		else
		{
	        	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, RequestMessage_vals, "<unknown>"));
		}
	}

	if (( check_col(pinfo->cinfo, COL_INFO)) && ( codec_type != NULL ) && ( value == 3) ){
		col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ", codec_type );
	}

        col_set_fence(pinfo->cinfo,COL_INFO);

	return offset;
}





static int
dissect_h245_centralizedData_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_centralizedData, ett_h245_centralizedData, dissect_h245_DataApplicationCapability );
	return offset;
}




static int
dissect_h245_distributedData_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_distributedData, ett_h245_distributedData, dissect_h245_DataApplicationCapability );
	return offset;
}



static per_sequence_t MediaDistributionCapability_sequence[] = {
	{ "centralizedControl", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_centralizedControl },
	{ "distributedControl", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_distributedControl },
	{ "centralizedAudio", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_centralizedAudio },
	{ "distributedAudio", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_distributedAudio },
	{ "centralizedVideo", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_centralizedVideo },
	{ "distributedVideo", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_distributedVideo },
	{ "centralizedData", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_centralizedData_sequence_of },
	{ "distributedData", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_distributedData_sequence_of },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_MediaDistributionCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_MediaDistributionCapability, ett_h245_MediaDistributionCapability, MediaDistributionCapability_sequence);

	return offset;
}


static int
dissect_h245_mediaDistributionCapability_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h245_mediaDistributionCapability, ett_h245_mediaDistributionCapability, dissect_h245_MediaDistributionCapability );
	return offset;
}





static int
dissect_h245_rtpPayloadType_sequence_of(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_h245_rtpPayloadType_sequence_of, ett_h245_rtpPayloadType_sequence_of, dissect_h245_RTPPayloadType, 1, 256 );
	return offset;
}





static per_sequence_t H223ModeParameters_sequence[] = {
	{ "adaptationLayerType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_H223ModeParameters_adaptationLayerType },
	{ "segmentableFlag", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_segmentableFlag },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_H223ModeParameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_H223ModeParameters, ett_h245_H223ModeParameters, H223ModeParameters_sequence);

	return offset;
}





static per_sequence_t ModeElement_sequence[] = {
	{ "type", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ModeElementType },
	{ "h223ModeParameters", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_H223ModeParameters },
	{ "v76ModeParameters", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_V76ModeParameters },
	{ "h2250ModeParameters", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_H2250ModeParameters },
	{ "genericModeParameters", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_GenericCapability },
	{ "multiplexedStreamModeParameters", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_MultiplexedStreamModeParameters },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_ModeElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_ModeElement, ett_h245_ModeElement, ModeElement_sequence);

	return offset;
}





static int
dissect_h245_t38FaxMaxBuffer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_integer(tvb, offset, pinfo, tree,
		hf_h245_t38FaxMaxBuffer,
		NULL, NULL);

	return offset;
}



static int
dissect_h245_t38FaxMaxDatagram(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_integer(tvb, offset, pinfo, tree,
		hf_h245_t38FaxMaxDatagram,
		NULL, NULL);

	return offset;
}





static per_sequence_t T38FaxUdpOptions_sequence[] = {
	{ "t38FaxMaxBuffer", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h245_t38FaxMaxBuffer },
	{ "t38FaxMaxDatagram", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h245_t38FaxMaxDatagram },
	{ "t38FaxUdpEC", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h245_T38FaxUdpOptions_t38FaxUdpEC },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_T38FaxUdpOptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_T38FaxUdpOptions, ett_h245_T38FaxUdpOptions, T38FaxUdpOptions_sequence);

	return offset;
}






static int
dissect_h245_sessionDescription(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
NOT_DECODED_YET("sessionDescription");
	return offset;
}



static per_sequence_t CommunicationModeTableEntry_sequence[] = {
	{ "nonStandard", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_nonStandardData_sequence_of },
	{ "sessionID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_sessionID_1_255 },
	{ "associatedSessionID", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_associatedSessionID },
	{ "terminalLabel", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ "sessionDescription", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_sessionDescription },
	{ "dataType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_CommunicationModeTableEntry_dataType },
	{ "mediaChannel", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaChannel },
	{ "mediaGuaranteedDelivery", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaGuaranteedDelivery },
	{ "mediaControlChannel", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaControlChannel },
	{ "mediaControlGuaranteedDelivery", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_mediaControlGuaranteedDelivery },
	{ "redundancyEncoding", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_RedundancyEncoding },
	{ "sessionDependency", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_sessionDependency },
	{ "destination", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_TerminalLabel },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_CommunicationModeTableEntry(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_CommunicationModeTableEntry, ett_h245_CommunicationModeTableEntry, CommunicationModeTableEntry_sequence);

	return offset;
}




static per_sequence_t NewATMVCCommand_sequence[] = {
	{ "resouceID", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_resourceID },
	{ "bitRate", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_ATM_BitRate },
	{ "bitRateLockedToPCRClock", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_bitRateLockedToPCRClock },
	{ "bitRateLockedToNetworkClock", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_bitRateLockedToNetworkClock },
	{ "aal", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCCommand_aal },
	{ "multiplex", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCCommand_multiplex },
	{ "reverseParameters", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_NewATMVCCommand_reverseParameters },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_NewATMVCCommand(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_NewATMVCCommand, ett_h245_NewATMVCCommand, NewATMVCCommand_sequence);

	return offset;
}

static const value_string CommandMessage_short_vals[] = {
	{  0,	"NSM" },
	{  1,	"MLOC" },
	{  2,	"STCS" },
	{  3,	"EC" },
	{  4,	"FCC" },
	{  5,	"ESC" },
	{  6,	"MC" },
	{  7,	"CMC" },
	{  8,	"CC" },
	{  9,	"H223MR" },
	{ 10,	"NATMVCC" },
	{ 11,	"MMRC" },
	{  0, NULL }
};



static const value_string CommandMessage_vals[] = {
	{  0,	"NonStandardMessage" },
	{  1,	"MaintenanceLoopOffCommand" },
	{  2,	"SendTerminalCapabilitySet" },
	{  3,	"EncryptionCommand" },
	{  4,	"FlowControlCommand" },
	{  5,	"EndSessionCommand" },
	{  6,	"MiscellaneousCommand" },
	{  7,	"CommunicationModeCommand" },
	{  8,	"ConferenceCommand" },
	{  9,	"H223MultiplexReconfiguration" },
	{ 10,	"NewATMVCCommand" },
	{ 11,	"MobileMultilinkReconfigurationCommand" },
	{  0, NULL }
};
static per_choice_t CommandMessage_choice[] = {
	{  0,	"NonStandardMessage",		ASN1_EXTENSION_ROOT,
			dissect_h245_NonStandardMessage },
	{  1,	"MaintenanceLoopOffCommand",	ASN1_EXTENSION_ROOT,
			dissect_h245_MaintenanceLoopOffCommand },
	{  2,	"SendTerminalCapabilitySet",	ASN1_EXTENSION_ROOT,
			dissect_h245_SendTerminalCapabilitySet },
	{  3,	"EncryptionCommand",		ASN1_EXTENSION_ROOT,
			dissect_h245_EncryptionCommand },
	{  4,	"FlowControlCommand",		ASN1_EXTENSION_ROOT,
			dissect_h245_FlowControlCommand },
	{  5,	"EndSessionCommand",		ASN1_EXTENSION_ROOT,
			dissect_h245_EndSessionCommand },
	{  6,	"MiscellaneousCommand",		ASN1_EXTENSION_ROOT,
			dissect_h245_MiscellaneousCommand },
	{  7,	"CommunicationModeCommand",	ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_CommunicationModeCommand },
	{  8,	"ConferenceCommand",		ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_ConferenceCommand },
	{  9,	"H223MultiplexReconfiguration",	ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_H223MultiplexReconfiguration },
	{ 10,	"NewATMVCCommand",		ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_NewATMVCCommand },
	{ 11,	"MobileMultilinkReconfigurationCommand",ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_MobileMultilinkReconfigurationCommand },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_CommandMessage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 value;

	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_CommandMessage_type, ett_h245_CommandMessage, CommandMessage_choice, "CommandMessage", &value);

	if (check_col(pinfo->cinfo, COL_INFO)){
	        if ( h245_shorttypes == TRUE )
	        {
	        	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, CommandMessage_short_vals, "<unknown>"));
		}
		else
		{
	        	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, CommandMessage_vals, "<unknown>"));
		}
	}

	col_set_fence(pinfo->cinfo,COL_INFO);

	return offset;
}




static const value_string ResponseMessage_short_vals[] = {
	{  0,	"NSM" },
	{  1,	"MSDAck" },
	{  2,	"MSDReject" },
	{  3,	"TCSAck" },
	{  4,	"TCSReject" },
	{  5,	"OLCAck" },
	{  6,	"OLCReject" },
	{  7,	"CLCAck" },
	{  8,	"RCCAck" },
	{  9,	"RCCReject" },
	{ 10,	"MESAck" },
	{ 11,	"MESReject" },
	{ 12,	"RMEAck" },
	{ 13,	"RMEReject" },
	{ 14,	"RMAck" },
	{ 15,	"RMReject" },
	{ 16,	"RTDResponse" },
	{ 17,	"MLAck" },
	{ 18,	"MLReject" },
	{ 19,	"CMResponse" },
	{ 20,	"CResponse" },
	{ 21,	"MResponse" },
	{ 22,	"LCRAck" },
	{ 23,	"LCRReject" },
	{  0, NULL }
};


static const value_string ResponseMessage_vals[] = {
	{  0,	"NonStandardMessage" },
	{  1,	"MasterSlaveDeterminationAck" },
	{  2,	"MasterSlaveDeterminationReject" },
	{  3,	"TerminalCapabilitySetAck" },
	{  4,	"TerminalCapabilitySetReject" },
	{  5,	"OpenLogicalChannelAck" },
	{  6,	"OpenLogicalChannelReject" },
	{  7,	"CloseLogicalChannelAck" },
	{  8,	"RequestChannelCloseAck" },
	{  9,	"RequestChannelCloseReject" },
	{ 10,	"MultiplexEntrySendAck" },
	{ 11,	"MultiplexEntrySendReject" },
	{ 12,	"RequestMultiplexEntryAck" },
	{ 13,	"RequestMultiplexEntryReject" },
	{ 14,	"RequestModeAck" },
	{ 15,	"RequestModeReject" },
	{ 16,	"RoundTripDelayResponse" },
	{ 17,	"MaintenanceLoopAck" },
	{ 18,	"MaintenanceLoopReject" },
	{ 19,	"CommunicationModeResponse" },
	{ 20,	"ConferenceResponse" },
	{ 21,	"MultilinkResponse" },
	{ 22,	"LogicalChannelRateAck" },
	{ 23,	"LogicalChannelRateReject" },
	{  0, NULL }
};
static per_choice_t ResponseMessage_choice[] = {
	{  0,	"NonStandardMessage",		ASN1_EXTENSION_ROOT,
			dissect_h245_NonStandardMessage },
	{  1,	"MasterSlaveDeterminationAck",	ASN1_EXTENSION_ROOT,
			dissect_h245_MasterSlaveDeterminationAck },
	{  2,	"MasterSlaveDeterminationReject",ASN1_EXTENSION_ROOT,
			dissect_h245_MasterSlaveDeterminationReject },
	{  3,	"TerminalCapabilitySetAck", 	ASN1_EXTENSION_ROOT,
			dissect_h245_TerminalCapabilitySetAck },
	{  4,	"TerminalCapabilitySetReject", 	ASN1_EXTENSION_ROOT,
			dissect_h245_TerminalCapabilitySetReject },
	{  5,	"OpenLogicalChannelAck", 	ASN1_EXTENSION_ROOT,
			dissect_h245_OpenLogicalChannelAck },
	{  6,	"OpenLogicalChannelReject", 	ASN1_EXTENSION_ROOT,
			dissect_h245_OpenLogicalChannelReject },
	{  7,	"CloseLogicalChannelAck", 	ASN1_EXTENSION_ROOT,
			dissect_h245_CloseLogicalChannelAck },
	{  8,	"RequestChannelCloseAck", 	ASN1_EXTENSION_ROOT,
			dissect_h245_RequestChannelCloseAck },
	{  9,	"RequestChannelCloseReject", 	ASN1_EXTENSION_ROOT,
			dissect_h245_RequestChannelCloseReject },
	{ 10,	"MultiplexEntrySendAck", 	ASN1_EXTENSION_ROOT,
			dissect_h245_MultiplexEntrySendAck },
	{ 11,	"MultiplexEntrySendReject", 	ASN1_EXTENSION_ROOT,
			dissect_h245_MultiplexEntrySendReject },
	{ 12,	"RequestMultiplexEntryAck", 	ASN1_EXTENSION_ROOT,
			dissect_h245_RequestMultiplexEntryAck },
	{ 13,	"RequestMultiplexEntryReject", 	ASN1_EXTENSION_ROOT,
			dissect_h245_RequestMultiplexEntryReject },
	{ 14,	"RequestModeAck", 		ASN1_EXTENSION_ROOT,
			dissect_h245_RequestModeAck },
	{ 15,	"RequestModeReject", 		ASN1_EXTENSION_ROOT,
			dissect_h245_RequestModeReject },
	{ 16,	"RoundTripDelayResponse", 	ASN1_EXTENSION_ROOT,
			dissect_h245_RoundTripDelayResponse },
	{ 17,	"MaintenanceLoopAck", 		ASN1_EXTENSION_ROOT,
			dissect_h245_MaintenanceLoopAck },
	{ 18,	"MaintenanceLoopReject", 	ASN1_EXTENSION_ROOT,
			dissect_h245_MaintenanceLoopReject },
	{ 19,	"CommunicationModeResponse", 	ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_CommunicationModeResponse },
	{ 20,	"ConferenceResponse", 		ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_ConferenceResponse },
	{ 21,	"MultilinkResponse", 		ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_MultilinkResponse },
	{ 22,	"LogicalChannelRateAck", 	ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_LogicalChannelRateAck },
	{ 23,	"LogicalChannelRateReject", 	ASN1_NOT_EXTENSION_ROOT,
			dissect_h245_LogicalChannelRateReject },
	{  0, NULL, 0, NULL }
};
static int
dissect_h245_ResponseMessage(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 value;

	offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h245_ResponseMessage_type, ett_h245_ResponseMessage, ResponseMessage_choice, "ResponseMessage", &value);

	if (check_col(pinfo->cinfo, COL_INFO)){
	        if ( h245_shorttypes == TRUE )
	        {
	        	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, ResponseMessage_short_vals, "<unknown>"));
		}
		else
		{
	        	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, ResponseMessage_vals, "<unknown>"));
		}
	}

	col_set_fence(pinfo->cinfo,COL_INFO);

	return offset;
}






static int
dissect_h245_DialingInformationNumber_networkAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_NumericString(tvb, offset, pinfo, tree, hf_h245_DialingInformationNumber_networkAddress, 0, 40);

	return offset;
}




static int
dissect_h245_DialingInformationNumber_subAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_IA5String(tvb, offset, pinfo, tree, hf_h245_subAddress, 0, 40);

	return offset;
}



static per_sequence_t DialingInformationNumber_sequence[] = {
	{ "networkAddress", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_DialingInformationNumber_networkAddress },
	{ "subAddress", ASN1_EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h245_DialingInformationNumber_subAddress },
	{ "networkType", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h245_networkType },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h245_DialingInformationNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h245_DialingInformationNumber, ett_h245_DialingInformationNumber, DialingInformationNumber_sequence);

	return offset;
}


static const value_string MultimediaSystemControlMessage_vals[] = {
	{ 0,	"Request" },
	{ 1,	"Response" },
	{ 2,	"Command" },
	{ 3,	"Indication" },
	{ 0, NULL }
};
static per_choice_t MultimediaSystemControlMessage_choice[] = {
	{ 0,	"Request",	ASN1_EXTENSION_ROOT,
			dissect_h245_RequestMessage },
	{ 1,	"Response",	ASN1_EXTENSION_ROOT,
			dissect_h245_ResponseMessage },
	{ 2,	"Command",	ASN1_EXTENSION_ROOT,
			dissect_h245_CommandMessage },
	{ 3,	"Indication",	ASN1_EXTENSION_ROOT,
			dissect_h245_IndicationMessage },
	{ 0, NULL, 0, NULL }
};
void
dissect_h245_MultimediaSystemControlMessage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;
	guint32 value;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "H.245");
	}

	it=proto_tree_add_protocol_format(tree, proto_h245, tvb, 0, tvb_length(tvb), "H.245");
	tr=proto_item_add_subtree(it, ett_h245);

	/* this code is called from at least TPKT (over TCP) and
	   MEGACO.  Over MEGACO there is no framing so we just have to assume
	   that as long as we havent run out of TVB data, there is more
	   MSCM PDUsa to decode.
	*/
	while(tvb_length_remaining(tvb, offset>>3)>0){
		offset=dissect_per_choice(tvb, offset, pinfo, tr, hf_h245_pdu_type, ett_h245_MultimediaSystemControlMessage, MultimediaSystemControlMessage_choice, "MultimediaSystemControlMessage", &value);
		/* align next PDU to octet boundary */
		if(offset&0x07){
			offset=(offset&0xfffffff8)+8;
		}
	}
}






void
dissect_h245(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_tpkt_encap(tvb, pinfo, tree, h245_reassembly, MultimediaSystemControlMessage_handle);
}

void
proto_register_h245(void)
{
	static hf_register_info hf[] =
	{
	{ &hf_h245_pdu_type,
		{ "PDU Type", "h245.pdu_type", FT_UINT32, BASE_DEC,
		VALS(MultimediaSystemControlMessage_vals), 0, "Type of H.245 PDU", HFILL }},
	{ &hf_h245_IndicationMessage_type,
		{ "Indication Type", "h245.indication_type", FT_UINT32, BASE_DEC,
		VALS(IndicationMessage_vals), 0, "Type of Indication", HFILL }},
	{ &hf_h245_RequestMessage_type,
		{ "Request Type", "h245.request_type", FT_UINT32, BASE_DEC,
		VALS(RequestMessage_vals), 0, "Type of Request", HFILL }},
	{ &hf_h245_ResponseMessage_type,
		{ "Response Type", "h245.response_type", FT_UINT32, BASE_DEC,
		VALS(ResponseMessage_vals), 0, "Type of Response", HFILL }},
	{ &hf_h245_CommandMessage_type,
		{ "Command Type", "h245.command_type", FT_UINT32, BASE_DEC,
		VALS(CommandMessage_vals), 0, "Type of Command", HFILL }},
	{ &hf_h245_EndSessionCommand_type,
		{ "EndSessionCommand type", "h245.endsessioncommand_type", FT_UINT32, BASE_DEC,
		VALS(EndSessionCommand_vals), 0, "Type of EndSessionCommand", HFILL }},
	{ &hf_h245_PixelAspectCode,
		{ "PixelAspectCode", "h245.PixelAspectCode", FT_UINT32, BASE_DEC,
		NULL, 0, "PixelAspectCode", HFILL }},
	{ &hf_h245_LogicalChannelNumber,
		{ "LogicalChannelNumber", "h245.logicalchannelnumber", FT_UINT32, BASE_DEC,
		NULL, 0, "LogicalChannelNumber", HFILL }},
	{ &hf_h245_SequenceNumber,
		{ "SequenceNumber", "h245.sequencenumber", FT_UINT32, BASE_DEC,
		NULL, 0, "SequenceNumber", HFILL }},
	{ &hf_h245_OpenLogicalChannelConfirm,
		{ "OpenLogicalChannelConfirm", "h245.openlogicalchannelconfirm", FT_NONE, BASE_NONE,
		NULL, 0, "OpenLogicalChannelConfirm sequence", HFILL }},
	{ &hf_h245_MobileMultilinkReconfigurationIndication,
		{ "MobileMultilinkReconfigurationIndication", "h245.MobileMultilinkReconfigurationIndication", FT_NONE, BASE_NONE,
		NULL, 0, "MobileMultilinkReconfigurationIndication sequence", HFILL }},
	{ &hf_h245_FlowControlIndication,
		{ "FlowControlIndication", "h245.FlowControlIndication", FT_NONE, BASE_NONE,
		NULL, 0, "FlowControlIndication sequence", HFILL }},
	{ &hf_h245_UserInputIndication_extendedAlphanumeric,
		{ "UserInputIndication_extendedAlphanumeric", "h245.UserInputIndication_extendedAlphanumeric", FT_NONE, BASE_NONE,
		NULL, 0, "UserInputIndication_extendedAlphanumeric sequence", HFILL }},
	{ &hf_h245_UserInputIndication_signalUpdate_rtp,
		{ "UserInputIndication_signalUpdate_rtp", "h245.UserInputIndication_signalUpdate_rtp", FT_NONE, BASE_NONE,
		NULL, 0, "UserInputIndication_signalUpdate_rtp sequence", HFILL }},
	{ &hf_h245_UserInputIndication_signalUpdate,
		{ "UserInputIndication_signalUpdate", "h245.UserInputIndication_signalUpdate", FT_NONE, BASE_NONE,
		NULL, 0, "UserInputIndication_signalUpdate sequence", HFILL }},
	{ &hf_h245_UserInputIndication_signal_rtp,
		{ "UserInputIndication_signal_rtp", "h245.UserInputIndication_signal_rtp", FT_NONE, BASE_NONE,
		NULL, 0, "UserInputIndication_signal_rtp sequence", HFILL }},
	{ &hf_h245_UserInputIndication_signal,
		{ "UserInputIndication_signal", "h245.UserInputIndication_signal", FT_NONE, BASE_NONE,
		NULL, 0, "UserInputIndication_signal sequence", HFILL }},
	{ &hf_h245_NewATMVCIndication_reverseParameters,
		{ "NewATMVCIndication_reverseParameters", "h245.NewATMVCIndication_reverseParameters", FT_NONE, BASE_NONE,
		NULL, 0, "NewATMVCIndication_reverseParameters sequence", HFILL }},
	{ &hf_h245_NewATMVCIndication_aal_aal5,
		{ "NewATMVCIndication_aal_aal5", "h245.NewATMVCIndication_aal_aal5", FT_NONE, BASE_NONE,
		NULL, 0, "NewATMVCIndication_aal_aal5 sequence", HFILL }},
	{ &hf_h245_NewATMVCIndication_aal_aal1,
		{ "NewATMVCIndication_aal_aal1", "h245.NewATMVCIndication_aal_aal1", FT_NONE, BASE_NONE,
		NULL, 0, "NewATMVCIndication_aal_aal1 sequence", HFILL }},
	{ &hf_h245_NewATMVCIndication,
		{ "NewATMVCIndication", "h245.NewATMVCIndication", FT_NONE, BASE_NONE,
		NULL, 0, "NewATMVCIndication sequence", HFILL }},
	{ &hf_h245_VendorIdentification,
		{ "VendorIdentification", "h245.VendorIdentification", FT_NONE, BASE_NONE,
		NULL, 0, "VendorIdentification sequence", HFILL }},
	{ &hf_h245_MCLocationIndication,
		{ "MCLocationIndication", "h245.MCLocationIndication", FT_NONE, BASE_NONE,
		NULL, 0, "MCLocationIndication sequence", HFILL }},
	{ &hf_h245_H2250MaximumSkewIndication,
		{ "H2250MaximumSkewIndication", "h245.H2250MaximumSkewIndication", FT_NONE, BASE_NONE,
		NULL, 0, "H2250MaximumSkewIndication sequence", HFILL }},
	{ &hf_h245_H223SkewIndication,
		{ "H223SkewIndication", "h245.H223SkewIndication", FT_NONE, BASE_NONE,
		NULL, 0, "H223SkewIndication sequence", HFILL }},
	{ &hf_h245_JitterIndication,
		{ "JitterIndication", "h245.JitterIndication", FT_NONE, BASE_NONE,
		NULL, 0, "JitterIndication sequence", HFILL }},
	{ &hf_h245_MiscellaneousIndication_type_videoNotDecodedMBs,
		{ "MiscellaneousIndication_type_videoNotDecodedMBs", "h245.MiscellaneousIndication_type_videoNotDecodedMBs", FT_NONE, BASE_NONE,
		NULL, 0, "MiscellaneousIndication_type_videoNotDecodedMBs sequence", HFILL }},
	{ &hf_h245_MiscellaneousIndication,
		{ "MiscellaneousIndication", "h245.MiscellaneousIndication", FT_NONE, BASE_NONE,
		NULL, 0, "MiscellaneousIndication sequence", HFILL }},
	{ &hf_h245_VideoIndicateCompose,
		{ "VideoIndicateCompose", "h245.VideoIndicateCompose", FT_NONE, BASE_NONE,
		NULL, 0, "VideoIndicateCompose sequence", HFILL }},
	{ &hf_h245_TerminalYouAreSeeingInSubPictureNumber,
		{ "TerminalYouAreSeeingInSubPictureNumber", "h245.TerminalYouAreSeeingInSubPictureNumber", FT_NONE, BASE_NONE,
		NULL, 0, "TerminalYouAreSeeingInSubPictureNumber sequence", HFILL }},
	{ &hf_h245_FunctionNotSupported,
		{ "FunctionNotSupported", "h245.FunctionNotSupported", FT_NONE, BASE_NONE,
		NULL, 0, "FunctionNotSupported sequence", HFILL }},
	{ &hf_h245_MobileMultilinkReconfigurationCommand,
		{ "MobileMultilinkReconfigurationCommand", "h245.MobileMultilinkReconfigurationCommand", FT_NONE, BASE_NONE,
		NULL, 0, "MobileMultilinkReconfigurationCommand sequence", HFILL }},
	{ &hf_h245_NewATMVCCommand_reverseParameters,
		{ "NewATMVCCommand_reverseParameters", "h245.NewATMVCCommand_reverseParameters", FT_NONE, BASE_NONE,
		NULL, 0, "NewATMVCCommand_reverseParameters sequence", HFILL }},
	{ &hf_h245_NewATMVCCommand,
		{ "NewATMVCCommand", "h245.NewATMVCCommand", FT_NONE, BASE_NONE,
		NULL, 0, "NewATMVCCommand sequence", HFILL }},
	{ &hf_h245_NewATMVCCommand_aal_aal5,
		{ "NewATMVCCommand_aal_aal5", "h245.NewATMVCCommand_aal_aal5", FT_NONE, BASE_NONE,
		NULL, 0, "NewATMVCCommand_aal_aal5 sequence", HFILL }},
	{ &hf_h245_NewATMVCCommand_aal_aal1,
		{ "NewATMVCCommand_aal_aal1", "h245.NewATMVCCommand_aal_aal1", FT_NONE, BASE_NONE,
		NULL, 0, "NewATMVCCommand_aal_aal1 sequence", HFILL }},
	{ &hf_h245_EncryptionUpdateRequest,
		{ "EncryptionUpdateRequest", "h245.EncryptionUpdateRequest", FT_NONE, BASE_NONE,
		NULL, 0, "EncryptionUpdateRequest sequence", HFILL }},
	{ &hf_h245_KeyProtectionMethod,
		{ "KeyProtectionMethod", "h245.KeyProtectionMethod", FT_NONE, BASE_NONE,
		NULL, 0, "KeyProtectionMethod sequence", HFILL }},
	{ &hf_h245_MiscellaneousCommand_type_lostPartialPicture,
		{ "MiscellaneousCommand_type_lostPartialPicture", "h245.MiscellaneousCommand_type_lostPartialPicture", FT_NONE, BASE_NONE,
		NULL, 0, "MiscellaneousCommand_type_lostPartialPicture sequence", HFILL }},
	{ &hf_h245_MiscellaneousCommand_type_videoBadMBs,
		{ "MiscellaneousCommand_type_videoBadMBs", "h245.MiscellaneousCommand_type_videoBadMBs", FT_NONE, BASE_NONE,
		NULL, 0, "MiscellaneousCommand_type_videoBadMBs sequence", HFILL }},
	{ &hf_h245_MiscellaneousCommand_type_progressiveRefinementStart,
		{ "MiscellaneousCommand_type_progressiveRefinementStart", "h245.MiscellaneousCommand_type_progressiveRefinementStart", FT_NONE, BASE_NONE,
		NULL, 0, "MiscellaneousCommand_type_progressiveRefinementStart sequence", HFILL }},
	{ &hf_h245_MiscellaneousCommand_type_videoFastUpdateMB,
		{ "MiscellaneousCommand_type_videoFastUpdateMB", "h245.MiscellaneousCommand_type_videoFastUpdateMB", FT_NONE, BASE_NONE,
		NULL, 0, "MiscellaneousCommand_type_videoFastUpdateMB sequence", HFILL }},
	{ &hf_h245_MiscellaneousCommand_type_videoFastUpdateGOB,
		{ "MiscellaneousCommand_type_videoFastUpdateGOB", "h245.MiscellaneousCommand_type_videoFastUpdateGOB", FT_NONE, BASE_NONE,
		NULL, 0, "MiscellaneousCommand_type_videoFastUpdateGOB sequence", HFILL }},
	{ &hf_h245_MiscellaneousCommand,
		{ "MiscellaneousCommand", "h245.MiscellaneousCommand", FT_NONE, BASE_NONE,
		NULL, 0, "MiscellaneousCommand sequence", HFILL }},
	{ &hf_h245_SubstituteConferenceIDCommand,
		{ "SubstituteConferenceIDCommand", "h245.SubstituteConferenceIDCommand", FT_NONE, BASE_NONE,
		NULL, 0, "SubstituteConferenceIDCommand sequence", HFILL }},
	{ &hf_h245_FlowControlCommand,
		{ "FlowControlCommand", "h245.FlowControlCommand", FT_NONE, BASE_NONE,
		NULL, 0, "FlowControlCommand sequence", HFILL }},
	{ &hf_h245_EncryptionCommand_encryptionAlgorithmID,
		{ "EncryptionCommand_encryptionAlgorithmID", "h245.EncryptionCommand_encryptionAlgorithmID", FT_NONE, BASE_NONE,
		NULL, 0, "EncryptionCommand_encryptionAlgorithmID sequence", HFILL }},
	{ &hf_h245_SendTerminalCapabilitySet_specificRequest,
		{ "SendTerminalCapabilitySet_specificRequest", "h245.SendTerminalCapabilitySet_specificRequest", FT_NONE, BASE_NONE,
		NULL, 0, "SendTerminalCapabilitySet_specificRequest sequence", HFILL }},
	{ &hf_h245_LogicalChannelRateRelease,
		{ "LogicalChannelRateRelease", "h245.LogicalChannelRateRelease", FT_NONE, BASE_NONE,
		NULL, 0, "LogicalChannelRateRelease sequence", HFILL }},
	{ &hf_h245_LogicalChannelRateReject,
		{ "LogicalChannelRateReject", "h245.LogicalChannelRateReject", FT_NONE, BASE_NONE,
		NULL, 0, "LogicalChannelRateReject sequence", HFILL }},
	{ &hf_h245_LogicalChannelRateAck,
		{ "LogicalChannelRateAck", "h245.LogicalChannelRateAck", FT_NONE, BASE_NONE,
		NULL, 0, "LogicalChannelRateAck sequence", HFILL }},
	{ &hf_h245_LogicalChannelRateRequest,
		{ "LogicalChannelRateRequest", "h245.LogicalChannelRateRequest", FT_NONE, BASE_NONE,
		NULL, 0, "LogicalChannelRateRequest sequence", HFILL }},
	{ &hf_h245_ConnectionIdentifier,
		{ "ConnectionIdentifier", "h245.ConnectionIdentifier", FT_NONE, BASE_NONE,
		NULL, 0, "ConnectionIdentifier sequence", HFILL }},
	{ &hf_h245_DialingInformationNumber,
		{ "DialingInformationNumber", "h245.DialingInformationNumber", FT_NONE, BASE_NONE,
		NULL, 0, "DialingInformationNumber sequence", HFILL }},
	{ &hf_h245_MultilinkIndication_excessiveError,
		{ "MultilinkIndication_excessiveError", "h245.MultilinkIndication_excessiveError", FT_NONE, BASE_NONE,
		NULL, 0, "MultilinkIndication_excessiveError sequence", HFILL }},
	{ &hf_h245_MultilinkIndication_crcDesired,
		{ "MultilinkIndication_crcDesired", "h245.MultilinkIndication_crcDesired", FT_NONE, BASE_NONE,
		NULL, 0, "MultilinkIndication_crcDesired sequence", HFILL }},
	{ &hf_h245_MultilinkResponse_maximumHeaderInterval,
		{ "MultilinkResponse_maximumHeaderInterval", "h245.MultilinkResponse_maximumHeaderInterval", FT_NONE, BASE_NONE,
		NULL, 0, "MultilinkResponse_maximumHeaderInterval sequence", HFILL }},
	{ &hf_h245_MultilinkResponse_removeConnection,
		{ "MultilinkResponse_removeConnection", "h245.MultilinkResponse_removeConnection", FT_NONE, BASE_NONE,
		NULL, 0, "MultilinkResponse_removeConnection sequence", HFILL }},
	{ &hf_h245_MultilinkResponse_addConnection,
		{ "MultilinkResponse_addConnection", "h245.MultilinkResponse_addConnection", FT_NONE, BASE_NONE,
		NULL, 0, "MultilinkResponse_addConnection sequence", HFILL }},
	{ &hf_h245_MultilinkResponse_callInformation,
		{ "MultilinkResponse_callInformation", "h245.MultilinkResponse_callInformation", FT_NONE, BASE_NONE,
		NULL, 0, "MultilinkResponse_callInformation sequence", HFILL }},
	{ &hf_h245_MultilinkRequest_maximumHeaderInterval,
		{ "MultilinkRequest_maximumHeaderInterval", "h245.MultilinkRequest_maximumHeaderInterval", FT_NONE, BASE_NONE,
		NULL, 0, "MultilinkRequest_maximumHeaderInterval sequence", HFILL }},
	{ &hf_h245_MultilinkRequest_removeConnection,
		{ "MultilinkRequest_removeConnection", "h245.MultilinkRequest_removeConnection", FT_NONE, BASE_NONE,
		NULL, 0, "MultilinkRequest_removeConnection sequence", HFILL }},
	{ &hf_h245_MultilinkRequest_addConnection,
		{ "MultilinkRequest_addConnection", "h245.MultilinkRequest_addConnection", FT_NONE, BASE_NONE,
		NULL, 0, "MultilinkRequest_addConnection sequence", HFILL }},
	{ &hf_h245_MultilinkRequest_callInformation,
		{ "MultilinkRequest_callInformation", "h245.MultilinkRequest_callInformation", FT_NONE, BASE_NONE,
		NULL, 0, "MultilinkRequest_callInformation sequence", HFILL }},
	{ &hf_h245_TerminalInformation,
		{ "TerminalInformation", "h245.TerminalInformation", FT_NONE, BASE_NONE,
		NULL, 0, "TerminalInformation sequence", HFILL }},
	{ &hf_h245_RequestAllTerminalIDsResponse,
		{ "RequestAllTerminalIDsResponse", "h245.RequestAllTerminalIDsResponse", FT_NONE, BASE_NONE,
		NULL, 0, "RequestAllTerminalIDsResponse sequence", HFILL }},
	{ &hf_h245_ConferenceResponse_terminalCertificateResponse,
		{ "ConferenceResponse_terminalCertificateResponse", "h245.ConferenceResponse_terminalCertificateResponse", FT_NONE, BASE_NONE,
		NULL, 0, "ConferenceResponse_terminalCertificateResponse sequence", HFILL }},
	{ &hf_h245_ConferenceResponse_chairTokenOwnerResponse,
		{ "ConferenceResponse_chairTokenOwnerResponse", "h245.ConferenceResponse_chairTokenOwnerResponse", FT_NONE, BASE_NONE,
		NULL, 0, "ConferenceResponse_chairTokenOwnerResponse sequence", HFILL }},
	{ &hf_h245_ConferenceResponse_extensionAddressResponse,
		{ "ConferenceResponse_extensionAddressResponse", "h245.ConferenceResponse_extensionAddressResponse", FT_NONE, BASE_NONE,
		NULL, 0, "ConferenceResponse_extensionAddressResponse sequence", HFILL }},
	{ &hf_h245_ConferenceResponse_passwordResponse,
		{ "ConferenceResponse_passwordResponse", "h245.ConferenceResponse_passwordResponse", FT_NONE, BASE_NONE,
		NULL, 0, "ConferenceResponse_passwordResponse sequence", HFILL }},
	{ &hf_h245_ConferenceResponse_conferenceIDResponse,
		{ "ConferenceResponse_conferenceIDResponse", "h245.ConferenceResponse_conferenceIDResponse", FT_NONE, BASE_NONE,
		NULL, 0, "ConferenceResponse_conferenceIDResponse sequence", HFILL }},
	{ &hf_h245_ConferenceResponse_terminalIDResponse,
		{ "ConferenceResponse_terminalIDResponse", "h245.ConferenceResponse_terminalIDResponse", FT_NONE, BASE_NONE,
		NULL, 0, "ConferenceResponse_terminalIDResponse sequence", HFILL }},
	{ &hf_h245_ConferenceResponse_mCterminalIDResponse,
		{ "ConferenceResponse_mCterminalIDResponse", "h245.ConferenceResponse_mCterminalIDResponse", FT_NONE, BASE_NONE,
		NULL, 0, "ConferenceResponse_mCterminalIDResponse sequence", HFILL }},
	{ &hf_h245_TerminalLabel,
		{ "TerminalLabel", "h245.TerminalLabel", FT_NONE, BASE_NONE,
		NULL, 0, "TerminalLabel sequence", HFILL }},
	{ &hf_h245_Criteria,
		{ "Criteria", "h245.Criteria", FT_NONE, BASE_NONE,
		NULL, 0, "Criteria sequence", HFILL }},
	{ &hf_h245_ConferenceRequest_requestTerminalCertificate,
		{ "ConferenceRequest_requestTerminalCertificate", "h245.ConferenceRequest_requestTerminalCertificate", FT_NONE, BASE_NONE,
		NULL, 0, "ConferenceRequest_requestTerminalCertificate sequence", HFILL }},
	{ &hf_h245_CommunicationModeTableEntry,
		{ "CommunicationModeTableEntry", "h245.CommunicationModeTableEntry", FT_NONE, BASE_NONE,
		NULL, 0, "CommunicationModeTableEntry sequence", HFILL }},
	{ &hf_h245_CommunicationModeRequest,
		{ "CommunicationModeRequest", "h245.CommunicationModeRequest", FT_NONE, BASE_NONE,
		NULL, 0, "CommunicationModeRequest sequence", HFILL }},
	{ &hf_h245_CommunicationModeCommand,
		{ "CommunicationModeCommand", "h245.CommunicationModeCommand", FT_NONE, BASE_NONE,
		NULL, 0, "CommunicationModeCommand sequence", HFILL }},
	{ &hf_h245_MaintenanceLoopOffCommand,
		{ "MaintenanceLoopOffCommand", "h245.MaintenanceLoopOffCommand", FT_NONE, BASE_NONE,
		NULL, 0, "MaintenanceLoopOffCommand sequence", HFILL }},
	{ &hf_h245_MaintenanceLoopReject,
		{ "MaintenanceLoopReject", "h245.MaintenanceLoopReject", FT_NONE, BASE_NONE,
		NULL, 0, "MaintenanceLoopReject sequence", HFILL }},
	{ &hf_h245_MaintenanceLoopAck,
		{ "MaintenanceLoopAck", "h245.MaintenanceLoopAck", FT_NONE, BASE_NONE,
		NULL, 0, "MaintenanceLoopAck sequence", HFILL }},
	{ &hf_h245_MaintenanceLoopRequest,
		{ "MaintenanceLoopRequest", "h245.MaintenanceLoopRequest", FT_NONE, BASE_NONE,
		NULL, 0, "MaintenanceLoopRequest sequence", HFILL }},
	{ &hf_h245_RoundTripDelayResponse,
		{ "RoundTripDelayResponse", "h245.RoundTripDelayResponse", FT_NONE, BASE_NONE,
		NULL, 0, "RoundTripDelayResponse sequence", HFILL }},
	{ &hf_h245_RoundTripDelayRequest,
		{ "RoundTripDelayRequest", "h245.RoundTripDelayRequest", FT_NONE, BASE_NONE,
		NULL, 0, "RoundTripDelayRequest sequence", HFILL }},
	{ &hf_h245_DataMode_application_t38fax,
		{ "DataMode_application_t38fax", "h245.DataMode_application_t38fax", FT_NONE, BASE_NONE,
		NULL, 0, "DataMode_application_t38fax sequence", HFILL }},
	{ &hf_h245_DataMode_application_nlpid,
		{ "DataMode_application_nlpid", "h245.DataMode_application_nlpid", FT_NONE, BASE_NONE,
		NULL, 0, "DataMode_application_nlpid sequence", HFILL }},
	{ &hf_h245_DataMode,
		{ "DataMode", "h245.DataMode", FT_NONE, BASE_NONE,
		NULL, 0, "DataMode sequence", HFILL }},
	{ &hf_h245_VBDMode,
		{ "VBDMode", "h245.VBDMode", FT_NONE, BASE_NONE,
		NULL, 0, "VBDMode sequence", HFILL }},
	{ &hf_h245_G7231AnnexCMode_g723AnnexCAudioMode,
		{ "G7231AnnexCMode_g723AnnexCAudioMode", "h245.G7231AnnexCMode_g723AnnexCAudioMode", FT_NONE, BASE_NONE,
		NULL, 0, "G7231AnnexCMode_g723AnnexCAudioMode sequence", HFILL }},
	{ &hf_h245_G7231AnnexCMode,
		{ "G7231AnnexCMode", "h245.G7231AnnexCMode", FT_NONE, BASE_NONE,
		NULL, 0, "G7231AnnexCMode sequence", HFILL }},
	{ &hf_h245_IS13818AudioMode,
		{ "IS13818AudioMode", "h245.IS13818AudioMode", FT_NONE, BASE_NONE,
		NULL, 0, "IS13818AudioMode sequence", HFILL }},
	{ &hf_h245_IS11172AudioMode,
		{ "IS11172AudioMode", "h245.IS11172AudioMode", FT_NONE, BASE_NONE,
		NULL, 0, "IS11172AudioMode sequence", HFILL }},
	{ &hf_h245_IS11172VideoMode,
		{ "IS11172VideoMode", "h245.IS11172VideoMode", FT_NONE, BASE_NONE,
		NULL, 0, "IS11172VideoMode sequence", HFILL }},
	{ &hf_h245_H263VideoMode,
		{ "H263VideoMode", "h245.H263VideoMode", FT_NONE, BASE_NONE,
		NULL, 0, "H263VideoMode sequence", HFILL }},
	{ &hf_h245_H262VideoMode,
		{ "H262VideoMode", "h245.H262VideoMode", FT_NONE, BASE_NONE,
		NULL, 0, "H262VideoMode sequence", HFILL }},
	{ &hf_h245_H261VideoMode,
		{ "H261VideoMode", "h245.H261VideoMode", FT_NONE, BASE_NONE,
		NULL, 0, "H261VideoMode sequence", HFILL }},
	{ &hf_h245_RedundancyEncodingMode,
		{ "RedundancyEncodingMode", "h245.RedundancyEncodingMode", FT_NONE, BASE_NONE,
		NULL, 0, "RedundancyEncodingMode sequence", HFILL }},
	{ &hf_h245_H2250ModeParameters,
		{ "H2250ModeParameters", "h245.H2250ModeParameters", FT_NONE, BASE_NONE,
		NULL, 0, "H2250ModeParameters sequence", HFILL }},
	{ &hf_h245_H223ModeParameters_adaptationLayerType_al3,
		{ "H223ModeParameters_adaptationLayerType_al3", "h245.H223ModeParameters_adaptationLayerType_al3", FT_NONE, BASE_NONE,
		NULL, 0, "H223ModeParameters_adaptationLayerType_al3 sequence", HFILL }},
	{ &hf_h245_H223ModeParameters,
		{ "H223ModeParameters", "h245.H223ModeParameters", FT_NONE, BASE_NONE,
		NULL, 0, "H223ModeParameters sequence", HFILL }},
	{ &hf_h245_FECMode_rfc2733Mode_mode_separateStream_samePort,
		{ "FECMode_rfc2733Mode_mode_separateStream_samePort", "h245.FECMode_rfc2733Mode_mode_separateStream_samePort", FT_NONE, BASE_NONE,
		NULL, 0, "FECMode_rfc2733Mode_mode_separateStream_samePort sequence", HFILL }},
	{ &hf_h245_FECMode_rfc2733Mode_mode_separateStream_differentPort,
		{ "FECMode_rfc2733Mode_mode_separateStream_differentPort", "h245.FECMode_rfc2733Mode_mode_separateStream_differentPort", FT_NONE, BASE_NONE,
		NULL, 0, "FECMode_rfc2733Mode_mode_separateStream_differentPort sequence", HFILL }},
	{ &hf_h245_FECMode_rfc2733Mode,
		{ "FECMode_rfc2733Mode", "h245.FECMode_rfc2733Mode", FT_NONE, BASE_NONE,
		NULL, 0, "FECMode_rfc2733Mode sequence", HFILL }},
	{ &hf_h245_MultiplePayloadStreamElementMode,
		{ "MultiplePayloadStreamElementMode", "h245.MultiplePayloadStreamElementMode", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplePayloadStreamElementMode sequence", HFILL }},
	{ &hf_h245_MultiplePayloadStreamMode,
		{ "MultiplePayloadStreamMode", "h245.MultiplePayloadStreamMode", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplePayloadStreamMode sequence", HFILL }},
	{ &hf_h245_RedundancyEncodingDTModeElement,
		{ "RedundancyEncodingDTModeElement", "h245.RedundancyEncodingDTModeElement", FT_NONE, BASE_NONE,
		NULL, 0, "RedundancyEncodingDTModeElement sequence", HFILL }},
	{ &hf_h245_RedundancyEncodingDTMode,
		{ "RedundancyEncodingDTMode", "h245.RedundancyEncodingDTMode", FT_NONE, BASE_NONE,
		NULL, 0, "RedundancyEncodingDTMode sequence", HFILL }},
	{ &hf_h245_MultiplexedStreamModeParameters,
		{ "MultiplexedStreamModeParameters", "h245.MultiplexedStreamModeParameters", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplexedStreamModeParameters sequence", HFILL }},
	{ &hf_h245_H235Mode,
		{ "H235Mode", "h245.H235Mode", FT_NONE, BASE_NONE,
		NULL, 0, "H235Mode sequence", HFILL }},
	{ &hf_h245_ModeElement,
		{ "ModeElement", "h245.ModeElement", FT_NONE, BASE_NONE,
		NULL, 0, "ModeElement sequence", HFILL }},
	{ &hf_h245_RequestModeRelease,
		{ "RequestModeRelease", "h245.RequestModeRelease", FT_NONE, BASE_NONE,
		NULL, 0, "RequestModeRelease sequence", HFILL }},
	{ &hf_h245_RequestModeReject,
		{ "RequestModeReject", "h245.RequestModeReject", FT_NONE, BASE_NONE,
		NULL, 0, "RequestModeReject sequence", HFILL }},
	{ &hf_h245_RequestModeAck,
		{ "RequestModeAck", "h245.RequestModeAck", FT_NONE, BASE_NONE,
		NULL, 0, "RequestModeAck sequence", HFILL }},
	{ &hf_h245_RequestMode,
		{ "RequestMode", "h245.RequestMode", FT_NONE, BASE_NONE,
		NULL, 0, "RequestMode sequence", HFILL }},
	{ &hf_h245_RequestMultiplexEntryRelease,
		{ "RequestMultiplexEntryRelease", "h245.RequestMultiplexEntryRelease", FT_NONE, BASE_NONE,
		NULL, 0, "RequestMultiplexEntryRelease sequence", HFILL }},
	{ &hf_h245_RequestMultiplexEntryRejectionDescriptions,
		{ "RequestMultiplexEntryRejectionDescriptions", "h245.RequestMultiplexEntryRejectionDescriptions", FT_NONE, BASE_NONE,
		NULL, 0, "RequestMultiplexEntryRejectionDescriptions sequence", HFILL }},
	{ &hf_h245_RequestMultiplexEntryReject,
		{ "RequestMultiplexEntryReject", "h245.RequestMultiplexEntryReject", FT_NONE, BASE_NONE,
		NULL, 0, "RequestMultiplexEntryReject sequence", HFILL }},
	{ &hf_h245_RequestMultiplexEntryAck,
		{ "RequestMultiplexEntryAck", "h245.RequestMultiplexEntryAck", FT_NONE, BASE_NONE,
		NULL, 0, "RequestMultiplexEntryAck sequence", HFILL }},
	{ &hf_h245_RequestMultiplexEntry,
		{ "RequestMultiplexEntry", "h245.RequestMultiplexEntry", FT_NONE, BASE_NONE,
		NULL, 0, "RequestMultiplexEntry sequence", HFILL }},
	{ &hf_h245_MultiplexEntrySendRelease,
		{ "MultiplexEntrySendRelease", "h245.MultiplexEntrySendRelease", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplexEntrySendRelease sequence", HFILL }},
	{ &hf_h245_MultiplexEntryRejectionDescriptions,
		{ "MultiplexEntryRejectionDescriptions", "h245.MultiplexEntryRejectionDescriptions", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplexEntryRejectionDescriptions sequence", HFILL }},
	{ &hf_h245_MultiplexEntrySendReject,
		{ "MultiplexEntrySendReject", "h245.MultiplexEntrySendReject", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplexEntrySendReject sequence", HFILL }},
	{ &hf_h245_MultiplexEntrySendAck,
		{ "MultiplexEntrySendAck", "h245.MultiplexEntrySendAck", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplexEntrySendAck sequence", HFILL }},
	{ &hf_h245_MultiplexElement,
		{ "MultiplexElement", "h245.MultiplexElement", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplexElement sequence", HFILL }},
	{ &hf_h245_MultiplexEntryDescriptor,
		{ "MultiplexEntryDescriptor", "h245.MultiplexEntryDescriptor", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplexEntryDescriptor sequence", HFILL }},
	{ &hf_h245_MultiplexEntrySend,
		{ "MultiplexEntrySend", "h245.MultiplexEntrySend", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplexEntrySend sequence", HFILL }},
	{ &hf_h245_RequestChannelCloseRelease,
		{ "RequestChannelCloseRelease", "h245.RequestChannelCloseRelease", FT_NONE, BASE_NONE,
		NULL, 0, "RequestChannelCloseRelease sequence", HFILL }},
	{ &hf_h245_RequestChannelCloseReject,
		{ "RequestChannelCloseReject", "h245.RequestChannelCloseReject", FT_NONE, BASE_NONE,
		NULL, 0, "RequestChannelCloseReject sequence", HFILL }},
	{ &hf_h245_RequestChannelCloseAck,
		{ "RequestChannelCloseAck", "h245.RequestChannelCloseAck", FT_NONE, BASE_NONE,
		NULL, 0, "RequestChannelCloseAck sequence", HFILL }},
	{ &hf_h245_RequestChannelClose,
		{ "RequestChannelClose", "h245.RequestChannelClose", FT_NONE, BASE_NONE,
		NULL, 0, "RequestChannelClose sequence", HFILL }},
	{ &hf_h245_CloseLogicalChannelAck,
		{ "CloseLogicalChannelAck", "h245.CloseLogicalChannelAck", FT_NONE, BASE_NONE,
		NULL, 0, "CloseLogicalChannelAck sequence", HFILL }},
	{ &hf_h245_CloseLogicalChannel,
		{ "CloseLogicalChannel", "h245.CloseLogicalChannel", FT_NONE, BASE_NONE,
		NULL, 0, "CloseLogicalChannel sequence", HFILL }},
	{ &hf_h245_H2250LogicalChannelAckParameters,
		{ "H2250LogicalChannelAckParameters", "h245.H2250LogicalChannelAckParameters", FT_NONE, BASE_NONE,
		NULL, 0, "H2250LogicalChannelAckParameters sequence", HFILL }},
	{ &hf_h245_OpenLogicalChannelReject,
		{ "OpenLogicalChannelReject", "h245.OpenLogicalChannelReject", FT_NONE, BASE_NONE,
		NULL, 0, "OpenLogicalChannelReject sequence", HFILL }},
	{ &hf_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters,
		{ "OpenLogicalChannelAck_reverseLogicalChannelParameters", "h245.OpenLogicalChannelAck_reverseLogicalChannelParameters", FT_NONE, BASE_NONE,
		NULL, 0, "OpenLogicalChannelAck_reverseLogicalChannelParameters sequence", HFILL }},
	{ &hf_h245_OpenLogicalChannelAck,
		{ "OpenLogicalChannelAck", "h245.OpenLogicalChannelAck", FT_NONE, BASE_NONE,
		NULL, 0, "OpenLogicalChannelAck sequence", HFILL }},
	{ &hf_h245_EscrowData,
		{ "EscrowData", "h245.EscrowData", FT_NONE, BASE_NONE,
		NULL, 0, "EscrowData sequence", HFILL }},
	{ &hf_h245_EncryptionSync,
		{ "EncryptionSync", "h245.EncryptionSync", FT_NONE, BASE_NONE,
		NULL, 0, "EncryptionSync sequence", HFILL }},
	{ &hf_h245_MulticastAddress_iP6Address,
		{ "MulticastAddress_iP6Address", "h245.MulticastAddress_iP6Address", FT_NONE, BASE_NONE,
		NULL, 0, "MulticastAddress_iP6Address sequence", HFILL }},
	{ &hf_h245_MulticastAddress_iPAddress,
		{ "MulticastAddress_iPAddress", "h245.MulticastAddress_iPAddress", FT_NONE, BASE_NONE,
		NULL, 0, "MulticastAddress_iPAddress sequence", HFILL }},
	{ &hf_h245_UnicastAddress_iPSourceRouteAddress,
		{ "UnicastAddress_iPSourceRouteAddress", "h245.UnicastAddress_iPSourceRouteAddress", FT_NONE, BASE_NONE,
		NULL, 0, "UnicastAddress_iPSourceRouteAddress sequence", HFILL }},
	{ &hf_h245_UnicastAddress_iP6Address,
		{ "UnicastAddress_iP6Address", "h245.UnicastAddress_iP6Address", FT_NONE, BASE_NONE,
		NULL, 0, "UnicastAddress_iP6Address sequence", HFILL }},
	{ &hf_h245_UnicastAddress_iPXAddress,
		{ "UnicastAddress_iPXAddress", "h245.UnicastAddress_iPXAddress", FT_NONE, BASE_NONE,
		NULL, 0, "UnicastAddress_iPXAddress sequence", HFILL }},
	{ &hf_h245_UnicastAddress_iPAddress,
		{ "UnicastAddress_iPAddress", "h245.UnicastAddress_iPAddress", FT_NONE, BASE_NONE,
		NULL, 0, "UnicastAddress_iPAddress sequence", HFILL }},
	{ &hf_h245_FECData_rfc2733_mode_separateStream_samePort,
		{ "FECData_rfc2733_mode_separateStream_samePort", "h245.FECData_rfc2733_mode_separateStream_samePort", FT_NONE, BASE_NONE,
		NULL, 0, "FECData_rfc2733_mode_separateStream_samePort sequence", HFILL }},
	{ &hf_h245_FECData_rfc2733_mode_separateStream_differentPort,
		{ "FECData_rfc2733_mode_separateStream_differentPort", "h245.FECData_rfc2733_mode_separateStream_differentPort", FT_NONE, BASE_NONE,
		NULL, 0, "FECData_rfc2733_mode_separateStream_differentPort sequence", HFILL }},
	{ &hf_h245_FECData_rfc2733,
		{ "FECData_rfc2733", "h245.FECData_rfc2733", FT_NONE, BASE_NONE,
		NULL, 0, "FECData_rfc2733 sequence", HFILL }},
	{ &hf_h245_MultiplePayloadStreamElement,
		{ "MultiplePayloadStreamElement", "h245.MultiplePayloadStreamElement", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplePayloadStreamElement sequence", HFILL }},
	{ &hf_h245_MultiplePayloadStream,
		{ "MultiplePayloadStream", "h245.MultiplePayloadStream", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplePayloadStream sequence", HFILL }},
	{ &hf_h245_RedundancyEncodingElement,
		{ "RedundancyEncodingElement", "h245.RedundancyEncodingElement", FT_NONE, BASE_NONE,
		NULL, 0, "RedundancyEncodingElement sequence", HFILL }},
	{ &hf_h245_RedundancyEncoding_rtpRedundancyEncoding,
		{ "RedundancyEncoding_rtpRedundancyEncoding", "h245.RedundancyEncoding_rtpRedundancyEncoding", FT_NONE, BASE_NONE,
		NULL, 0, "RedundancyEncoding_rtpRedundancyEncoding sequence", HFILL }},
	{ &hf_h245_RedundancyEncoding,
		{ "RedundancyEncoding", "h245.RedundancyEncoding", FT_NONE, BASE_NONE,
		NULL, 0, "RedundancyEncoding sequence", HFILL }},
	{ &hf_h245_RTPPayloadType,
		{ "RTPPayloadType", "h245.RTPPayloadType", FT_NONE, BASE_NONE,
		NULL, 0, "RTPPayloadType sequence", HFILL }},
	{ &hf_h245_H2250LogicalChannelParameters,
		{ "H2250LogicalChannelParameters", "h245.H2250LogicalChannelParameters", FT_NONE, BASE_NONE,
		NULL, 0, "H2250LogicalChannelParameters sequence", HFILL }},
	{ &hf_h245_V76HDLCParameters,
		{ "V76HDLCParameters", "h245.V76HDLCParameters", FT_NONE, BASE_NONE,
		NULL, 0, "V76HDLCParameters sequence", HFILL }},
	{ &hf_h245_V76LogicalChannelParameters_mode_eRM,
		{ "V76LogicalChannelParameters_mode_eRM", "h245.V76LogicalChannelParameters_mode_eRM", FT_NONE, BASE_NONE,
		NULL, 0, "V76LogicalChannelParameters_mode_eRM sequence", HFILL }},
	{ &hf_h245_V76LogicalChannelParameters,
		{ "V76LogicalChannelParameters", "h245.V76LogicalChannelParameters", FT_NONE, BASE_NONE,
		NULL, 0, "V76LogicalChannelParameters sequence", HFILL }},
	{ &hf_h245_H223AnnexCArqParameters,
		{ "H223AnnexCArqParameters", "h245.H223AnnexCArqParameters", FT_NONE, BASE_NONE,
		NULL, 0, "H223AnnexCArqParameters sequence", HFILL }},
	{ &hf_h245_H223AL3MParameters,
		{ "H223AL3MParameters", "h245.H223AL3MParameters", FT_NONE, BASE_NONE,
		NULL, 0, "H223AL3MParameters sequence", HFILL }},
	{ &hf_h245_H223AL2MParameters,
		{ "H223AL2MParameters", "h245.H223AL2MParameters", FT_NONE, BASE_NONE,
		NULL, 0, "H223AL2MParameters sequence", HFILL }},
	{ &hf_h245_H223AL1MParameters,
		{ "H223AL1MParameters", "h245.H223AL1MParameters", FT_NONE, BASE_NONE,
		NULL, 0, "H223AL1MParameters sequence", HFILL }},
	{ &hf_h245_H223LogicalChannelParameters_adaptionLayerType_al3,
		{ "H223LogicalChannelParameters_adaptionLayerType_al3", "h245.H223LogicalChannelParameters_adaptionLayerType_al3", FT_NONE, BASE_NONE,
		NULL, 0, "H223LogicalChannelParameters_adaptionLayerType_al3 sequence", HFILL }},
	{ &hf_h245_H223LogicalChannelParameters,
		{ "H223LogicalChannelParameters", "h245.H223LogicalChannelParameters", FT_NONE, BASE_NONE,
		NULL, 0, "H223LogicalChannelParameters sequence", HFILL }},
	{ &hf_h245_H222LogicalChannelParameters,
		{ "H222LogicalChannelParameters", "h245.H222LogicalChannelParameters", FT_NONE, BASE_NONE,
		NULL, 0, "H222LogicalChannelParameters sequence", HFILL }},
	{ &hf_h245_MultiplexedStreamParameter,
		{ "MultiplexedStreamParameter", "h245.MultiplexedStreamParameter", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplexedStreamParameter sequence", HFILL }},
	{ &hf_h245_H235Media,
		{ "H235Media", "h245.H235Media", FT_NONE, BASE_NONE,
		NULL, 0, "H235Media sequence", HFILL }},
	{ &hf_h245_V75Parameters,
		{ "V75Parameters", "h245.V75Parameters", FT_NONE, BASE_NONE,
		NULL, 0, "V75Parameters sequence", HFILL }},
	{ &hf_h245_Q2931Address,
		{ "Q2931Address", "h245.Q2931Address", FT_NONE, BASE_NONE,
		NULL, 0, "Q2931Address sequence", HFILL }},
	{ &hf_h245_NetworkAccessParameters,
		{ "NetworkAccessParameters", "h245.NetworkAccessParameters", FT_NONE, BASE_NONE,
		NULL, 0, "NetworkAccessParameters sequence", HFILL }},
	{ &hf_h245_reverseLogicalChannelParameters,
		{ "reverseLogicalChannelParameters", "h245.reverseLogicalChannelParameters", FT_NONE, BASE_NONE,
		NULL, 0, "reverseLogicalChannelParameters sequence", HFILL }},
	{ &hf_h245_forwardLogicalChannelParameters,
		{ "forwardLogicalChannelParameters", "h245.forwardLogicalChannelParameters", FT_NONE, BASE_NONE,
		NULL, 0, "forwardLogicalChannelParameters sequence", HFILL }},
	{ &hf_h245_OpenLogicalChannel,
		{ "OpenLogicalChannel", "h245.OpenLogicalChannel", FT_NONE, BASE_NONE,
		NULL, 0, "OpenLogicalChannel sequence", HFILL }},
	{ &hf_h245_FECCapability_rfc2733_separateStream,
		{ "FECCapability_rfc2733_separateStream", "h245.FECCapability_rfc2733_separateStream", FT_NONE, BASE_NONE,
		NULL, 0, "FECCapability_rfc2733_separateStream sequence", HFILL }},
	{ &hf_h245_FECCapability_rfc2733,
		{ "FECCapability_rfc2733", "h245.FECCapability_rfc2733", FT_NONE, BASE_NONE,
		NULL, 0, "FECCapability_rfc2733 sequence", HFILL }},
	{ &hf_h245_MultiplePayloadStreamCapability,
		{ "MultiplePayloadStreamCapability", "h245.MultiplePayloadStreamCapability", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplePayloadStreamCapability sequence", HFILL }},
	{ &hf_h245_NoPTAudioToneCapability,
		{ "NoPTAudioToneCapability", "h245.NoPTAudioToneCapability", FT_NONE, BASE_NONE,
		NULL, 0, "NoPTAudioToneCapability sequence", HFILL }},
	{ &hf_h245_NoPTAudioTelephonyEventCapability,
		{ "NoPTAudioTelephonyEventCapability", "h245.NoPTAudioTelephonyEventCapability", FT_NONE, BASE_NONE,
		NULL, 0, "NoPTAudioTelephonyEventCapability sequence", HFILL }},
	{ &hf_h245_AudioToneCapability,
		{ "AudioToneCapability", "h245.AudioToneCapability", FT_NONE, BASE_NONE,
		NULL, 0, "AudioToneCapability sequence", HFILL }},
	{ &hf_h245_AudioTelephonyEventCapability,
		{ "AudioTelephonyEventCapability", "h245.AudioTelephonyEventCapability", FT_NONE, BASE_NONE,
		NULL, 0, "AudioTelephonyEventCapability sequence", HFILL }},
	{ &hf_h245_MultiplexedStreamCapability,
		{ "MultiplexedStreamCapability", "h245.MultiplexedStreamCapability", FT_NONE, BASE_NONE,
		NULL, 0, "MultiplexedStreamCapability sequence", HFILL }},
	{ &hf_h245_GenericParameter,
		{ "GenericParameter", "h245.GenericParameter", FT_NONE, BASE_NONE,
		NULL, 0, "GenericParameter sequence", HFILL }},
	{ &hf_h245_GenericCapability,
		{ "GenericCapability", "h245.GenericCapability", FT_NONE, BASE_NONE,
		NULL, 0, "GenericCapability sequence", HFILL }},
	{ &hf_h245_ConferenceCapability,
		{ "ConferenceCapability", "h245.ConferenceCapability", FT_NONE, BASE_NONE,
		NULL, 0, "ConferenceCapability sequence", HFILL }},
	{ &hf_h245_IntegrityCapability,
		{ "IntegrityCapability", "h245.IntegrityCapability", FT_NONE, BASE_NONE,
		NULL, 0, "IntegrityCapability sequence", HFILL }},
	{ &hf_h245_AuthenticationCapability,
		{ "AuthenticationCapability", "h245.AuthenticationCapability", FT_NONE, BASE_NONE,
		NULL, 0, "AuthenticationCapability sequence", HFILL }},
	{ &hf_h245_EncryptionAuthenticationAndIntegrity,
		{ "EncryptionAuthenticationAndIntegrity", "h245.EncryptionAuthenticationAndIntegrity", FT_NONE, BASE_NONE,
		NULL, 0, "EncryptionAuthenticationAndIntegrity sequence", HFILL }},
	{ &hf_h245_T38FaxTcpOptions,
		{ "T38FaxTcpOptions", "h245.T38FaxTcpOptions", FT_NONE, BASE_NONE,
		NULL, 0, "T38FaxTcpOptions sequence", HFILL }},
	{ &hf_h245_T38FaxUdpOptions,
		{ "T38FaxUdpOptions", "h245.T38FaxUdpOptions", FT_NONE, BASE_NONE,
		NULL, 0, "T38FaxUdpOptions sequence", HFILL }},
	{ &hf_h245_T38FaxProfile,
		{ "T38FaxProfile", "h245.T38FaxProfile", FT_NONE, BASE_NONE,
		NULL, 0, "T38FaxProfile sequence", HFILL }},
	{ &hf_h245_T84Profile_t84Restricted,
		{ "T84Profile_t84Restricted", "h245.T84Profile_t84Restricted", FT_NONE, BASE_NONE,
		NULL, 0, "T84Profile_t84Restricted sequence", HFILL }},
	{ &hf_h245_V42bis,
		{ "V42bis", "h245.V42bis", FT_NONE, BASE_NONE,
		NULL, 0, "V42bis sequence", HFILL }},
	{ &hf_h245_DataApplicationCapability_application_t38fax,
		{ "DataApplicationCapability_application_t38fax", "h245.DataApplicationCapability_application_t38fax", FT_NONE, BASE_NONE,
		NULL, 0, "DataApplicationCapability_application_t38fax sequence", HFILL }},
	{ &hf_h245_DataApplicationCapability_application_nlpid,
		{ "DataApplicationCapability_application_nlpid", "h245.DataApplicationCapability_application_nlpid", FT_NONE, BASE_NONE,
		NULL, 0, "DataApplicationCapability_application_nlpid sequence", HFILL }},
	{ &hf_h245_DataApplicationCapability_application_t84,
		{ "DataApplicationCapability_application_t84", "h245.DataApplicationCapability_application_t84", FT_NONE, BASE_NONE,
		NULL, 0, "DataApplicationCapability_application_t84 sequence", HFILL }},
	{ &hf_h245_DataApplicationCapability,
		{ "DataApplicationCapability", "h245.DataApplicationCapability", FT_NONE, BASE_NONE,
		NULL, 0, "DataApplicationCapability sequence", HFILL }},
	{ &hf_h245_VBDCapability,
		{ "VBDCapability", "h245.VBDCapability", FT_NONE, BASE_NONE,
		NULL, 0, "VBDCapability sequence", HFILL }},
	{ &hf_h245_GSMAudioCapability,
		{ "GSMAudioCapability", "h245.GSMAudioCapability", FT_NONE, BASE_NONE,
		NULL, 0, "GSMAudioCapability sequence", HFILL }},
	{ &hf_h245_IS13818AudioCapability,
		{ "IS13818AudioCapability", "h245.IS13818AudioCapability", FT_NONE, BASE_NONE,
		NULL, 0, "IS13818AudioCapability sequence", HFILL }},
	{ &hf_h245_IS11172AudioCapability,
		{ "IS11172AudioCapability", "h245.IS11172AudioCapability", FT_NONE, BASE_NONE,
		NULL, 0, "IS11172AudioCapability sequence", HFILL }},
	{ &hf_h245_G7231AnnexCCapability_g723AnnexCAudioMode,
		{ "G7231AnnexCCapability_g723AnnexCAudioMode", "h245.G7231AnnexCCapability_g723AnnexCAudioMode", FT_NONE, BASE_NONE,
		NULL, 0, "G7231AnnexCCapability_g723AnnexCAudioMode sequence", HFILL }},
	{ &hf_h245_G7231AnnexCCapability,
		{ "G7231AnnexCCapability", "h245.G7231AnnexCCapability", FT_NONE, BASE_NONE,
		NULL, 0, "G7231AnnexCCapability sequence", HFILL }},
	{ &hf_h245_G729Extensions,
		{ "G729Extensions", "h245.G729Extensions", FT_NONE, BASE_NONE,
		NULL, 0, "G729Extensions sequence", HFILL }},
	{ &hf_h245_AudioCapability_g7231,
		{ "AudioCapability_g7231", "h245.AudioCapability_g7231", FT_NONE, BASE_NONE,
		NULL, 0, "AudioCapability_g7231 sequence", HFILL }},
	{ &hf_h245_IS11172VideoCapability,
		{ "IS11172VideoCapability", "h245.IS11172VideoCapability", FT_NONE, BASE_NONE,
		NULL, 0, "IS11172VideoCapability sequence", HFILL }},
	{ &hf_h245_H263Version3Options,
		{ "H263Version3Options", "h245.H263Version3Options", FT_NONE, BASE_NONE,
		NULL, 0, "H263Version3Options sequence", HFILL }},
	{ &hf_h245_H263ModeComboFlags,
		{ "H263ModeComboFlags", "h245.H263ModeComboFlags", FT_NONE, BASE_NONE,
		NULL, 0, "H263ModeComboFlags sequence", HFILL }},
	{ &hf_h245_H263VideoModeCombos,
		{ "H263VideoModeCombos", "h245.H263VideoModeCombos", FT_NONE, BASE_NONE,
		NULL, 0, "H263VideoModeCombos sequence", HFILL }},
	{ &hf_h245_CustomPictureFormat_pixelAspectInformation_extendedPAR,
		{ "CustomPictureFormat_pixelAspectInformation_extendedPAR", "h245.CustomPictureFormat_pixelAspectInformation_extendedPAR", FT_NONE, BASE_NONE,
		NULL, 0, "CustomPictureFormat_pixelAspectInformation_extendedPAR sequence", HFILL }},
	{ &hf_h245_CustomPictureFormat_mPI_customPCF,
		{ "CustomPictureFormat_mPI_customPCF", "h245.CustomPictureFormat_mPI_customPCF", FT_NONE, BASE_NONE,
		NULL, 0, "CustomPictureFormat_mPI_customPCF sequence", HFILL }},
	{ &hf_h245_CustomPictureFormat_mPI,
		{ "CustomPictureFormat_mPI", "h245.CustomPictureFormat_mPI", FT_NONE, BASE_NONE,
		NULL, 0, "CustomPictureFormat_mPI sequence", HFILL }},
	{ &hf_h245_CustomPictureFormat,
		{ "CustomPictureFormat", "h245.CustomPictureFormat", FT_NONE, BASE_NONE,
		NULL, 0, "CustomPictureFormat sequence", HFILL }},
	{ &hf_h245_CustomPictureClockFrequency,
		{ "CustomPictureClockFrequency", "h245.CustomPictureClockFrequency", FT_NONE, BASE_NONE,
		NULL, 0, "CustomPictureClockFrequency sequence", HFILL }},
	{ &hf_h245_RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters,
		{ "RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters", "h245.RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters", FT_NONE, BASE_NONE,
		NULL, 0, "RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters sequence", HFILL }},
	{ &hf_h245_RefPictureSelection_enhancedReferencePicSelect,
		{ "RefPictureSelection_enhancedReferencePicSelect", "h245.RefPictureSelection_enhancedReferencePicSelect", FT_NONE, BASE_NONE,
		NULL, 0, "RefPictureSelection_enhancedReferencePicSelect sequence", HFILL }},
	{ &hf_h245_RefPictureSelection_additionalPictureMemory,
		{ "RefPictureSelection_additionalPictureMemory", "h245.RefPictureSelection_additionalPictureMemory", FT_NONE, BASE_NONE,
		NULL, 0, "RefPictureSelection_additionalPictureMemory sequence", HFILL }},
	{ &hf_h245_RefPictureSelection,
		{ "RefPictureSelection", "h245.RefPictureSelection", FT_NONE, BASE_NONE,
		NULL, 0, "RefPictureSelection sequence", HFILL }},
	{ &hf_h245_TransperencyParameters,
		{ "TransperencyParameters", "h245.TransperencyParameters", FT_NONE, BASE_NONE,
		NULL, 0, "TransperencyParameters sequence", HFILL }},
	{ &hf_h245_H263Options,
		{ "H263Options", "h245.H263Options", FT_NONE, BASE_NONE,
		NULL, 0, "H263Options sequence", HFILL }},
	{ &hf_h245_EnhancementOptions,
		{ "EnhancementOptions", "h245.EnhancementOptions", FT_NONE, BASE_NONE,
		NULL, 0, "EnhancementOptions sequence", HFILL }},
	{ &hf_h245_BEnhancementParameters,
		{ "BEnhancementParameters", "h245.BEnhancementParameters", FT_NONE, BASE_NONE,
		NULL, 0, "BEnhancementParameters sequence", HFILL }},
	{ &hf_h245_EnhancementLayerInfo,
		{ "EnhancementLayerInfo", "h245.EnhancementLayerInfo", FT_NONE, BASE_NONE,
		NULL, 0, "EnhancementLayerInfo sequence", HFILL }},
	{ &hf_h245_H263VideoCapability,
		{ "H263VideoCapability", "h245.H263VideoCapability", FT_NONE, BASE_NONE,
		NULL, 0, "H263VideoCapability sequence", HFILL }},
	{ &hf_h245_H262VideoCapability,
		{ "H262VideoCapability", "h245.H262VideoCapability", FT_NONE, BASE_NONE,
		NULL, 0, "H262VideoCapability sequence", HFILL }},
	{ &hf_h245_H261VideoCapability,
		{ "H261VideoCapability", "h245.H261VideoCapability", FT_NONE, BASE_NONE,
		NULL, 0, "H261VideoCapability sequence", HFILL }},
	{ &hf_h245_MediaDistributionCapability,
		{ "MediaDistributionCapability", "h245.MediaDistributionCapability", FT_NONE, BASE_NONE,
		NULL, 0, "MediaDistributionCapability sequence", HFILL }},
	{ &hf_h245_MultipointCapability,
		{ "MultipointCapability", "h245.MultipointCapability", FT_NONE, BASE_NONE,
		NULL, 0, "MultipointCapability sequence", HFILL }},
	{ &hf_h245_receiveMultipointCapability,
		{ "receiveMultipointCapability", "h245.receiveMultipointCapability", FT_NONE, BASE_NONE,
		NULL, 0, "Receive MultipointCapability sequence", HFILL }},
	{ &hf_h245_transmitMultipointCapability,
		{ "transmitMultipointCapability", "h245.transmitMultipointCapability", FT_NONE, BASE_NONE,
		NULL, 0, "Transmit MultipointCapability sequence", HFILL }},
	{ &hf_h245_receiveAndTransmitMultipointCapability,
		{ "receiveAndTransmitMultipointCapability", "h245.receiveAndTransmitMultipointCapability", FT_NONE, BASE_NONE,
		NULL, 0, "Receive And Transmit MultipointCapability sequence", HFILL }},
	{ &hf_h245_RTPH263VideoRedundancyFrameMapping,
		{ "RTPH263VideoRedundancyFrameMapping", "h245.RTPH263VideoRedundancyFrameMapping", FT_NONE, BASE_NONE,
		NULL, 0, "RTPH263VideoRedundancyFrameMapping sequence", HFILL }},
	{ &hf_h245_RTPH263VideoRedundancyEncoding,
		{ "RTPH263VideoRedundancyEncoding", "h245.RTPH263VideoRedundancyEncoding", FT_NONE, BASE_NONE,
		NULL, 0, "RTPH263VideoRedundancyEncoding sequence", HFILL }},
	{ &hf_h245_RedundancyEncodingCapability,
		{ "RedundancyEncodingCapability", "h245.RedundancyEncodingCapability", FT_NONE, BASE_NONE,
		NULL, 0, "RedundancyEncodingCapability sequence", HFILL }},
	{ &hf_h245_TransportCapability,
		{ "TransportCapability", "h245.TransportCapability", FT_NONE, BASE_NONE,
		NULL, 0, "TransportCapability sequence", HFILL }},
	{ &hf_h245_MediaChannelCapability,
		{ "MediaChannelCapability", "h245.MediaChannelCapability", FT_NONE, BASE_NONE,
		NULL, 0, "MediaChannelCapability sequence", HFILL }},
	{ &hf_h245_MediaTransportType_AtmAAL5Compressed,
		{ "MediaTransportType_AtmAAL5Compressed", "h245.MediaTransportType_AtmAAL5Compressed", FT_NONE, BASE_NONE,
		NULL, 0, "MediaTransportType_AtmAAL5Compressed sequence", HFILL }},
	{ &hf_h245_QOSCapability,
		{ "QOSCapability", "h245.QOSCapability", FT_NONE, BASE_NONE,
		NULL, 0, "QOSCapability sequence", HFILL }},
	{ &hf_h245_ATMParameters,
		{ "ATMParameters", "h245.ATMParameters", FT_NONE, BASE_NONE,
		NULL, 0, "ATMParameters sequence", HFILL }},
	{ &hf_h245_RSVPParameters,
		{ "RSVPParameters", "h245.RSVPParameters", FT_NONE, BASE_NONE,
		NULL, 0, "RSVPParameters sequence", HFILL }},
	{ &hf_h245_MediaPacketizationCapability,
		{ "MediaPacketizationCapability", "h245.MediaPacketizationCapability", FT_NONE, BASE_NONE,
		NULL, 0, "MediaPacketizationCapability sequence", HFILL }},
	{ &hf_h245_H2250Capability_mcCapability,
		{ "H2250Capability_mcCapability", "h245.H2250Capability_mcCapability", FT_NONE, BASE_NONE,
		NULL, 0, "H2250Capability_mcCapability sequence", HFILL }},
	{ &hf_h245_H2250Capability,
		{ "H2250Capability", "h245.H2250Capability", FT_NONE, BASE_NONE,
		NULL, 0, "H2250Capability sequence", HFILL }},
	{ &hf_h245_V75Capability,
		{ "V75Capability", "h245.V75Capability", FT_NONE, BASE_NONE,
		NULL, 0, "V75Capability sequence", HFILL }},
	{ &hf_h245_V76Capability,
		{ "V76Capability", "h245.V76Capability", FT_NONE, BASE_NONE,
		NULL, 0, "V76Capability sequence", HFILL }},
	{ &hf_h245_H223AnnexCCapability,
		{ "H223AnnexCCapability", "h245.H223AnnexCCapability", FT_NONE, BASE_NONE,
		NULL, 0, "H223AnnexCCapability sequence", HFILL }},
	{ &hf_h245_H223Capability_mobileMultilinkFrameCapability,
		{ "H223Capability_mobileMultilinkFrameCapability", "h245.H223Capability_mobileMultilinkFrameCapability", FT_NONE, BASE_NONE,
		NULL, 0, "H223Capability_mobileMultilinkFrameCapability sequence", HFILL }},
	{ &hf_h245_H223Capability_mobileOperationTransmitCapability,
		{ "H223Capability_mobileOperationTransmitCapability", "h245.H223Capability_mobileOperationTransmitCapability", FT_NONE, BASE_NONE,
		NULL, 0, "H223Capability_mobileOperationTransmitCapability sequence", HFILL }},
	{ &hf_h245_H223Capability_h223MultiplexTableCapability_enhanced,
		{ "H223Capability_h223MultiplexTableCapability_enhanced", "h245.H223Capability_h223MultiplexTableCapability_enhanced", FT_NONE, BASE_NONE,
		NULL, 0, "H223Capability_h223MultiplexTableCapability_enhanced sequence", HFILL }},
	{ &hf_h245_H223Capability,
		{ "H223Capability", "h245.H223Capability", FT_NONE, BASE_NONE,
		NULL, 0, "H223Capability sequence", HFILL }},
	{ &hf_h245_VCCapability_aal1ViaGateway,
		{ "VCCapability_aal1ViaGateway", "h245.VCCapability_aal1ViaGateway", FT_NONE, BASE_NONE,
		NULL, 0, "VCCapability_aal1ViaGateway sequence", HFILL }},
	{ &hf_h245_VCCapability_availableBitRates_rangeOfBitRates,
		{ "VCCapability_availableBitRates_rangeOfBitRates", "h245.VCCapability_availableBitRates_rangeOfBitRates", FT_NONE, BASE_NONE,
		NULL, 0, "VCCapability_availableBitRates_rangeOfBitRates sequence", HFILL }},
	{ &hf_h245_VCCapability_availableBitRates,
		{ "VCCapability_availableBitRates", "h245.VCCapability_availableBitRates", FT_NONE, BASE_NONE,
		NULL, 0, "VCCapability_availableBitRates sequence", HFILL }},
	{ &hf_h245_VCCapability_aal5,
		{ "VCCapability_aal5", "h245.VCCapability_aal5", FT_NONE, BASE_NONE,
		NULL, 0, "VCCapability_aal5 sequence", HFILL }},
	{ &hf_h245_VCCapability_aal1,
		{ "VCCapability_aal1", "h245.VCCapability_aal1", FT_NONE, BASE_NONE,
		NULL, 0, "VCCapability_aal1 sequence", HFILL }},
	{ &hf_h245_VCCapability,
		{ "VCCapability", "h245.VCCapability", FT_NONE, BASE_NONE,
		NULL, 0, "VCCapability sequence", HFILL }},
	{ &hf_h245_H222Capability,
		{ "H222Capability", "h245.H222Capability", FT_NONE, BASE_NONE,
		NULL, 0, "H222Capability sequence", HFILL }},
	{ &hf_h245_H235SecurityCapability,
		{ "H235SecurityCapability", "h245.H235SecurityCapability", FT_NONE, BASE_NONE,
		NULL, 0, "H235SecurityCapability sequence", HFILL }},
	{ &hf_h245_Capability_h233EncryptionReceiveCapability,
		{ "Capability_h233EncryptionReceiveCapability", "h245.Capability_h233EncryptionReceiveCapability", FT_NONE, BASE_NONE,
		NULL, 0, "Capability_h233EncryptionReceiveCapability sequence", HFILL }},
	{ &hf_h245_TerminalCapabilitySetRelease,
		{ "TerminalCapabilitySetRelease", "h245.TerminalCapabilitySetRelease", FT_NONE, BASE_NONE,
		NULL, 0, "TerminalCapabilitySetRelease sequence", HFILL }},
	{ &hf_h245_TerminalCapabilitySetReject,
		{ "TerminalCapabilitySetReject", "h245.TerminalCapabilitySetReject", FT_NONE, BASE_NONE,
		NULL, 0, "TerminalCapabilitySetReject sequence", HFILL }},
	{ &hf_h245_TerminalCapabilitySetAck,
		{ "TerminalCapabilitySetAck", "h245.TerminalCapabilitySetAck", FT_NONE, BASE_NONE,
		NULL, 0, "TerminalCapabilitySetAck sequence", HFILL }},
	{ &hf_h245_CapabilityDescriptor,
		{ "CapabilityDescriptor", "h245.CapabilityDescriptor", FT_NONE, BASE_NONE,
		NULL, 0, "CapabilityDescriptor sequence", HFILL }},
	{ &hf_h245_CapabilityTableEntry,
		{ "CapabilityTableEntry", "h245.CapabilityTableEntry", FT_NONE, BASE_NONE,
		NULL, 0, "CapabilityTableEntry sequence", HFILL }},
	{ &hf_h245_TerminalCapabilitySet,
		{ "TerminalCapabilitySet", "h245.TerminalCapabilitySet", FT_NONE, BASE_NONE,
		NULL, 0, "TerminalCapabilitySet sequence", HFILL }},
	{ &hf_h245_MasterSlaveDeterminationRelease,
		{ "MasterSlaveDeterminationRelease", "h245.MasterSlaveDeterminationRelease", FT_NONE, BASE_NONE,
		NULL, 0, "MasterSlaveDeterminationRelease sequence", HFILL }},
	{ &hf_h245_MasterSlaveDeterminationReject,
		{ "MasterSlaveDeterminationReject", "h245.MasterSlaveDeterminationReject", FT_NONE, BASE_NONE,
		NULL, 0, "MasterSlaveDeterminationReject sequence", HFILL }},
	{ &hf_h245_MasterSlaveDeterminationAck,
		{ "MasterSlaveDeterminationAck", "h245.MasterSlaveDeterminationAck", FT_NONE, BASE_NONE,
		NULL, 0, "MasterSlaveDeterminationAck sequence", HFILL }},
	{ &hf_h245_MasterSlaveDetermination,
		{ "MasterSlaveDetermination", "h245.MasterSlaveDetermination", FT_NONE, BASE_NONE,
		NULL, 0, "MasterSlaveDetermination sequence", HFILL }},
	{ &hf_h245_h221NonStandard,
		{ "h221NonStandard", "h245.h221NonStandard", FT_NONE, BASE_NONE,
		NULL, 0, "h221NonStandard sequence", HFILL }},
	{ &hf_h245_NonStandardParameter,
		{ "NonStandardParameter", "h245.NonStandardParameter", FT_NONE, BASE_NONE,
		NULL, 0, "NonStandardParameter sequence", HFILL }},
	{ &hf_h245_NonStandardMessage,
		{ "NonStandardMessage", "h245.NonStandardMessage", FT_NONE, BASE_NONE,
		NULL, 0, "NonStandardMessage sequence", HFILL }},
	{ &hf_h245_FlowControlIndication_restriction,
		{ "FlowControlIndication_restriction", "h245.FlowControlIndication_restriction_type", FT_UINT32, BASE_DEC,
		VALS(FlowControlIndication_restriction_vals), 0, "FlowControlIndication_restriction choice", HFILL }},
	{ &hf_h245_FlowControlIndication_scope,
		{ "FlowControlIndication_scope", "h245.FlowControlIndication_scope_type", FT_UINT32, BASE_DEC,
		VALS(FlowControlIndication_scope_vals), 0, "FlowControlIndication_scope choice", HFILL }},
	{ &hf_h245_UserInputIndication_userInputSupportIndication,
		{ "UserInputIndication_userInputSupportIndication type", "h245.UserInputIndication_userInputSupportIndication_type", FT_UINT32, BASE_DEC,
		VALS(UserInputIndication_userInputSupportIndication_vals), 0, "Type of UserInputIndication_userInputSupportIndication choice", HFILL }},
	{ &hf_h245_UserInputIndication,
		{ "UserInputIndication type", "h245.UserInputIndication_type", FT_UINT32, BASE_DEC,
		VALS(UserInputIndication_vals), 0, "Type of UserInputIndication choice", HFILL }},
	{ &hf_h245_NewATMVCIndication_reverseParameters_multiplex,
		{ "NewATMVCIndication_reverseParameters_multiplex type", "h245.NewATMVCIndication_reverseParameters_multiplex_type", FT_UINT32, BASE_DEC,
		VALS(NewATMVCIndication_reverseParameters_multiplex_vals), 0, "Type of NewATMVCIndication_reverseParameters_multiplex choice", HFILL }},
	{ &hf_h245_NewATMVCIndication_multiplex,
		{ "NewATMVCIndication_multiplex type", "h245.NewATMVCIndication_multiplex_type", FT_UINT32, BASE_DEC,
		VALS(NewATMVCIndication_multiplex_vals), 0, "Type of NewATMVCIndication_multiplex choice", HFILL }},
	{ &hf_h245_NewATMVCIndication_aal_aal1_errorCorrection,
		{ "NewATMVCIndication_aal_aal1_errorCorrection type", "h245.NewATMVCIndication_aal_aal1_errorCorrection_type", FT_UINT32, BASE_DEC,
		VALS(NewATMVCIndication_aal_aal1_errorCorrection_vals), 0, "Type of NewATMVCIndication_aal_aal1_errorCorrection choice", HFILL }},
	{ &hf_h245_NewATMVCIndication_aal_aal1_clockRecovery,
		{ "NewATMVCIndication_aal_aal1_clockRecovery type", "h245.NewATMVCIndication_aal_aal1_clockRecovery_type", FT_UINT32, BASE_DEC,
		VALS(NewATMVCIndication_aal_aal1_clockRecovery_vals), 0, "Type of NewATMVCIndication_aal_aal1_clockRecovery choice", HFILL }},
	{ &hf_h245_NewATMVCIndication_aal,
		{ "NewATMVCIndication_aal type", "h245.NewATMVCIndication_aal_type", FT_UINT32, BASE_DEC,
		VALS(NewATMVCIndication_aal_vals), 0, "Type of NewATMVCIndication_aal choice", HFILL }},
	{ &hf_h245_JitterIndication_scope,
		{ "JitterIndication_scope type", "h245.JitterIndication_scope_type", FT_UINT32, BASE_DEC,
		VALS(JitterIndication_scope_vals), 0, "Type of JitterIndication_scope choice", HFILL }},
	{ &hf_h245_MiscellaneousIndication_type,
		{ "MiscellaneousIndication_type type", "h245.MiscellaneousIndication_type_type", FT_UINT32, BASE_DEC,
		VALS(MiscellaneousIndication_type_vals), 0, "Type of MiscellaneousIndication_type choice", HFILL }},
	{ &hf_h245_ConferenceIndication,
		{ "ConferenceIndication type", "h245.ConferenceIndication_type", FT_UINT32, BASE_DEC,
		VALS(ConferenceIndication_vals), 0, "Type of ConferenceIndication choice", HFILL }},
	{ &hf_h245_FunctionNotSupported_cause,
		{ "FunctionNotSupported_cause type", "h245.FunctionNotSupported_cause_type", FT_UINT32, BASE_DEC,
		VALS(FunctionNotSupported_cause_vals), 0, "Type of FunctionNotSupported_cause choice", HFILL }},
	{ &hf_h245_FunctionNotUnderstood,
		{ "FunctionNotUnderstood type", "h245.FunctionNotUnderstood_type", FT_UINT32, BASE_DEC,
		VALS(FunctionNotUnderstood_vals), 0, "Type of FunctionNotUnderstood choice", HFILL }},
	{ &hf_h245_MobileMultilinkReconfigurationCommand_status,
		{ "MobileMultilinkReconfigurationCommand_status type", "h245.MobileMultilinkReconfigurationCommand_status_type", FT_UINT32, BASE_DEC,
		VALS(MobileMultilinkReconfigurationCommand_status_vals), 0, "Type of MobileMultilinkReconfigurationCommand_status choice", HFILL }},
	{ &hf_h245_NewATMVCCommand_reverseParameters_multiplex,
		{ "NewATMVCCommand_reverseParameters_multiplex type", "h245.NewATMVCCommand_reverseParameters_multiplex_type", FT_UINT32, BASE_DEC,
		VALS(NewATMVCCommand_reverseParameters_multiplex_vals), 0, "Type of NewATMVCCommand_reverseParameters_multiplex choice", HFILL }},
	{ &hf_h245_NewATMVCCommand_multiplex,
		{ "NewATMVCCommand_multiplex type", "h245.NewATMVCCommand_multiplex_type", FT_UINT32, BASE_DEC,
		VALS(NewATMVCCommand_multiplex_vals), 0, "Type of NewATMVCCommand_multiplex choice", HFILL }},
	{ &hf_h245_NewATMVCCommand_aal_aal1_errorCorrection,
		{ "NewATMVCCommand_aal_aal1_errorCorrection type", "h245.NewATMVCCommand_aal_aal1_errorCorrection_type", FT_UINT32, BASE_DEC,
		VALS(NewATMVCCommand_aal_aal1_errorCorrection_vals), 0, "Type of NewATMVCCommand_aal_aal1_errorCorrection choice", HFILL }},
	{ &hf_h245_NewATMVCCommand_aal_aal1_clockRecovery,
		{ "NewATMVCCommand_aal_aal1_clockRecovery type", "h245.NewATMVCCommand_aal_aal1_clockRecovery_type", FT_UINT32, BASE_DEC,
		VALS(NewATMVCCommand_aal_aal1_clockRecovery_vals), 0, "Type of NewATMVCCommand_aal_aal1_clockRecovery choice", HFILL }},
	{ &hf_h245_NewATMVCCommand_aal,
		{ "NewATMVCCommand_aal type", "h245.NewATMVCCommand_aal_type", FT_UINT32, BASE_DEC,
		VALS(NewATMVCCommand_aal_vals), 0, "Type of NewATMVCCommand_aal choice", HFILL }},
	{ &hf_h245_H223MultiplexReconfiguration_h223AnnexADoubleFlag,
		{ "H223MultiplexReconfiguration_h223AnnexADoubleFlag type", "h245.H223MultiplexReconfiguration_h223AnnexADoubleFlag_type", FT_UINT32, BASE_DEC,
		VALS(H223MultiplexReconfiguration_h223AnnexADoubleFlag_vals), 0, "Type of H223MultiplexReconfiguration_h223AnnexADoubleFlag choice", HFILL }},
	{ &hf_h245_H223MultiplexReconfiguration_h223ModeChange,
		{ "H223MultiplexReconfiguration_h223ModeChange type", "h245.H223MultiplexReconfiguration_h223ModeChange_type", FT_UINT32, BASE_DEC,
		VALS(H223MultiplexReconfiguration_h223ModeChange_vals), 0, "Type of H223MultiplexReconfiguration_h223ModeChange choice", HFILL }},
	{ &hf_h245_H223MultiplexReconfiguration,
		{ "H223MultiplexReconfiguration type", "h245.H223MultiplexReconfiguration_type", FT_UINT32, BASE_DEC,
		VALS(H223MultiplexReconfiguration_vals), 0, "Type of H223MultiplexReconfiguration choice", HFILL }},
	{ &hf_h245_PictureReference,
		{ "PictureReference type", "h245.PictureReference_type", FT_UINT32, BASE_DEC,
		VALS(PictureReference_vals), 0, "Type of PictureReference choice", HFILL }},
	{ &hf_h245_MiscellaneousCommand_type_progressiveRefinementStart_repeatCount,
		{ "MiscellaneousCommand_type_progressiveRefinementStart_repeatCount type", "h245.MiscellaneousCommand_type_progressiveRefinementStart_repeatCount_type", FT_UINT32, BASE_DEC,
		VALS(MiscellaneousCommand_type_progressiveRefinementStart_repeatCount_vals), 0, "Type of MiscellaneousCommand_type_progressiveRefinementStart_repeatCount choice", HFILL }},
	{ &hf_h245_MiscellaneousCommand_type,
		{ "MiscellaneousCommand_type type", "h245.MiscellaneousCommand_type_type", FT_UINT32, BASE_DEC,
		VALS(MiscellaneousCommand_type_vals), 0, "Type of MiscellaneousCommand_type choice", HFILL }},
	{ &hf_h245_ConferenceCommand,
		{ "ConferenceCommand type", "h245.ConferenceCommand_type", FT_UINT32, BASE_DEC,
		VALS(ConferenceCommand_vals), 0, "Type of ConferenceCommand choice", HFILL }},
	{ &hf_h245_EndSessionCommand_gstnOptions,
		{ "EndSessionCommand_gstnOptions type", "h245.EndSessionCommand_gstnOptions_type", FT_UINT32, BASE_DEC,
		VALS(EndSessionCommand_gstnOptions_vals), 0, "Type of EndSessionCommand_gstnOptions choice", HFILL }},
	{ &hf_h245_EndSessionCommand_isdnOptions,
		{ "EndSessionCommand_isdnOptions type", "h245.EndSessionCommand_isdnOptions_type", FT_UINT32, BASE_DEC,
		VALS(EndSessionCommand_isdnOptions_vals), 0, "Type of EndSessionCommand_isdnOptions choice", HFILL }},
	{ &hf_h245_FlowControlCommand_restriction,
		{ "FlowControlCommand_restriction type", "h245.FlowControlCommand_restriction_type", FT_UINT32, BASE_DEC,
		VALS(FlowControlCommand_restriction_vals), 0, "Type of FlowControlCommand_restriction choice", HFILL }},
	{ &hf_h245_FlowControlCommand_scope,
		{ "FlowControlCommand_scope type", "h245.FlowControlCommand_scope_type", FT_UINT32, BASE_DEC,
		VALS(FlowControlCommand_scope_vals), 0, "Type of FlowControlCommand_scope choice", HFILL }},
	{ &hf_h245_EncryptionCommand,
		{ "EncryptionCommand type", "h245.EncryptionCommand_type", FT_UINT32, BASE_DEC,
		VALS(EncryptionCommand_vals), 0, "Type of EncryptionCommand choice", HFILL }},
	{ &hf_h245_SendTerminalCapabilitySet,
		{ "SendTerminalCapabilitySet type", "h245.SendTerminalCapabilitySet_type", FT_UINT32, BASE_DEC,
		VALS(SendTerminalCapabilitySet_vals), 0, "Type of SendTerminalCapabilitySet choice", HFILL }},
	{ &hf_h245_LogicalChannelRateRejectReason,
		{ "LogicalChannelRateRejectReason type", "h245.LogicalChannelRateRejectReason_type", FT_UINT32, BASE_DEC,
		VALS(LogicalChannelRateRejectReason_vals), 0, "Type of LogicalChannelRateRejectReason choice", HFILL }},
	{ &hf_h245_DialingInformationNetworkType,
		{ "DialingInformationNetworkType type", "h245.DialingInformationNetworkType_type", FT_UINT32, BASE_DEC,
		VALS(DialingInformationNetworkType_vals), 0, "Type of DialingInformationNetworkType choice", HFILL }},
	{ &hf_h245_DialingInformation,
		{ "DialingInformation type", "h245.DialingInformation_type", FT_UINT32, BASE_DEC,
		VALS(DialingInformation_vals), 0, "Type of DialingInformation choice", HFILL }},
	{ &hf_h245_MultilinkIndication,
		{ "MultilinkIndication type", "h245.MultilinkIndication_type", FT_UINT32, BASE_DEC,
		VALS(MultilinkIndication_vals), 0, "Type of MultilinkIndication choice", HFILL }},
	{ &hf_h245_MultilinkResponse_addConnection_responseCode_rejected,
		{ "MultilinkResponse_addConnection_responseCode_rejected type", "h245.MultilinkResponse_addConnection_responseCode_rejected_type", FT_UINT32, BASE_DEC,
		VALS(MultilinkResponse_addConnection_responseCode_rejected_vals), 0, "Type of MultilinkResponse_addConnection_responseCode_rejected choice", HFILL }},
	{ &hf_h245_MultilinkResponse_addConnection_responseCode,
		{ "MultilinkResponse_addConnection_responseCode type", "h245.MultilinkResponse_addConnection_responseCode_type", FT_UINT32, BASE_DEC,
		VALS(MultilinkResponse_addConnection_responseCode_vals), 0, "Type of MultilinkResponse_addConnection_responseCode choice", HFILL }},
	{ &hf_h245_MultilinkResponse,
		{ "MultilinkResponse type", "h245.MultilinkResponse_type", FT_UINT32, BASE_DEC,
		VALS(MultilinkResponse_vals), 0, "Type of MultilinkResponse choice", HFILL }},
	{ &hf_h245_MultilinkRequest_maximumHeaderInterval_requestType,
		{ "MultilinkRequest_maximumHeaderInterval_requestType type", "h245.MultilinkRequest_maximumHeaderInterval_requestType_type", FT_UINT32, BASE_DEC,
		VALS(MultilinkRequest_maximumHeaderInterval_requestType_vals), 0, "Type of MultilinkRequest_maximumHeaderInterval_requestType choice", HFILL }},
	{ &hf_h245_MultilinkRequest,
		{ "MultilinkRequest type", "h245.MultilinkRequest_type", FT_UINT32, BASE_DEC,
		VALS(MultilinkRequest_vals), 0, "Type of MultilinkRequest choice", HFILL }},
	{ &hf_h245_RemoteMCResponse_reject,
		{ "RemoteMCResponse_reject type", "h245.RemoteMCResponse_reject_type", FT_UINT32, BASE_DEC,
		VALS(RemoteMCResponse_reject_vals), 0, "Type of RemoteMCResponse_reject choice", HFILL }},
	{ &hf_h245_RemoteMCResponse,
		{ "RemoteMCResponse type", "h245.RemoteMCResponse_type", FT_UINT32, BASE_DEC,
		VALS(RemoteMCResponse_vals), 0, "Type of RemoteMCResponse choice", HFILL }},
	{ &hf_h245_RemoteMCRequest,
		{ "RemoteMCRequest type", "h245.RemoteMCRequest_type", FT_UINT32, BASE_DEC,
		VALS(RemoteMCRequest_vals), 0, "Type of RemoteMCRequest choice", HFILL }},
	{ &hf_h245_ConferenceResponse_sendThisSourceResponse,
		{ "ConferenceResponse_sendThisSourceResponse type", "h245.ConferenceResponse_sendThisSourceResponse_type", FT_UINT32, BASE_DEC,
		VALS(ConferenceResponse_sendThisSourceResponse_vals), 0, "Type of ConferenceResponse_sendThisSourceResponse choice", HFILL }},
	{ &hf_h245_ConferenceResponse_makeTerminalBroadcasterResponse,
		{ "ConferenceResponse_makeTerminalBroadcasterResponse type", "h245.ConferenceResponse_makeTerminalBroadcasterResponse_type", FT_UINT32, BASE_DEC,
		VALS(ConferenceResponse_makeTerminalBroadcasterResponse_vals), 0, "Type of ConferenceResponse_makeTerminalBroadcasterResponse choice", HFILL }},
	{ &hf_h245_ConferenceResponse_broadcastMyLogicalChannelResponse,
		{ "ConferenceResponse_broadcastMyLogicalChannelResponse type", "h245.ConferenceResponse_broadcastMyLogicalChannelResponse_type", FT_UINT32, BASE_DEC,
		VALS(ConferenceResponse_broadcastMyLogicalChannelResponse_vals), 0, "Type of ConferenceResponse_broadcastMyLogicalChannelResponse choice", HFILL }},
	{ &hf_h245_ConferenceResponse_makeMeChairResponse,
		{ "ConferenceResponse_makeMeChairResponse type", "h245.ConferenceResponse_makeMeChairResponse_type", FT_UINT32, BASE_DEC,
		VALS(ConferenceResponse_makeMeChairResponse_vals), 0, "Type of ConferenceResponse_makeMeChairResponse choice", HFILL }},
	{ &hf_h245_ConferenceResponse,
		{ "ConferenceResponse type", "h245.ConferenceResponse_type", FT_UINT32, BASE_DEC,
		VALS(ConferenceResponse_vals), 0, "Type of ConferenceResponse choice", HFILL }},
	{ &hf_h245_ConferenceRequest,
		{ "ConferenceRequest type", "h245.ConferenceRequest_type", FT_UINT32, BASE_DEC,
		VALS(ConferenceRequest_vals), 0, "Type of ConferenceRequest choice", HFILL }},
	{ &hf_h245_CommunicationModeTableEntry_dataType,
		{ "CommunicationModeTableEntry_dataType type", "h245.CommunicationModeTableEntry_dataType_type", FT_UINT32, BASE_DEC,
		VALS(CommunicationModeTableEntry_dataType_vals), 0, "Type of CommunicationModeTableEntry_dataType choice", HFILL }},
	{ &hf_h245_CommunicationModeResponse,
		{ "CommunicationModeResponse type", "h245.CommunicationModeResponse_type", FT_UINT32, BASE_DEC,
		VALS(CommunicationModeResponse_vals), 0, "Type of CommunicationModeResponse choice", HFILL }},
	{ &hf_h245_MaintenanceLoopReject_cause,
		{ "MaintenanceLoopReject_cause type", "h245.MaintenanceLoopReject_cause_type", FT_UINT32, BASE_DEC,
		VALS(MaintenanceLoopReject_cause_vals), 0, "Type of MaintenanceLoopReject_cause choice", HFILL }},
	{ &hf_h245_MaintenanceLoopReject_type,
		{ "MaintenanceLoopReject_type type", "h245.MaintenanceLoopReject_type_type", FT_UINT32, BASE_DEC,
		VALS(MaintenanceLoopReject_type_vals), 0, "Type of MaintenanceLoopReject_type choice", HFILL }},
	{ &hf_h245_MaintenanceLoopAck_type,
		{ "MaintenanceLoopAck_type type", "h245.MaintenanceLoopAck_type_type", FT_UINT32, BASE_DEC,
		VALS(MaintenanceLoopAck_type_vals), 0, "Type of MaintenanceLoopAck_type choice", HFILL }},
	{ &hf_h245_MaintenanceLoopRequest_type,
		{ "MaintenanceLoopRequest_type type", "h245.MaintenanceLoopRequest_type_type", FT_UINT32, BASE_DEC,
		VALS(MaintenanceLoopRequest_type_vals), 0, "Type of MaintenanceLoopRequest_type choice", HFILL }},
	{ &hf_h245_EncryptionMode,
		{ "EncryptionMode type", "h245.EncryptionMode_type", FT_UINT32, BASE_DEC,
		VALS(EncryptionMode_vals), 0, "Type of EncryptionMode choice", HFILL }},
	{ &hf_h245_DataMode_application,
		{ "DataMode_application type", "h245.DataMode_application_type", FT_UINT32, BASE_DEC,
		VALS(DataMode_application_vals), 0, "Type of DataMode_application choice", HFILL }},
	{ &hf_h245_IS13818AudioMode_multiChannelType,
		{ "IS13818AudioMode_multiChannelType type", "h245.IS13818AudioMode_multiChannelType_type", FT_UINT32, BASE_DEC,
		VALS(IS13818AudioMode_multiChannelType_vals), 0, "Type of IS13818AudioMode_multiChannelType choice", HFILL }},
	{ &hf_h245_IS13818AudioMode_audioSampling,
		{ "IS13818AudioMode_audioSampling type", "h245.IS13818AudioMode_audioSampling_type", FT_UINT32, BASE_DEC,
		VALS(IS13818AudioMode_audioSampling_vals), 0, "Type of IS13818AudioMode_audioSampling choice", HFILL }},
	{ &hf_h245_IS13818AudioMode_audioLayer,
		{ "IS13818AudioMode_audioLayer type", "h245.IS13818AudioMode_audioLayer_type", FT_UINT32, BASE_DEC,
		VALS(IS13818AudioMode_audioLayer_vals), 0, "Type of IS13818AudioMode_audioLayer choice", HFILL }},
	{ &hf_h245_IS11172AudioMode_multichannelType,
		{ "IS11172AudioMode_multichannelType type", "h245.IS11172AudioMode_multichannelType_type", FT_UINT32, BASE_DEC,
		VALS(IS11172AudioMode_multichannelType_vals), 0, "Type of IS11172AudioMode_multichannelType choice", HFILL }},
	{ &hf_h245_IS11172AudioMode_audioSampling,
		{ "IS11172AudioMode_audioSampling type", "h245.IS11172AudioMode_audioSampling_type", FT_UINT32, BASE_DEC,
		VALS(IS11172AudioMode_audioSampling_vals), 0, "Type of IS11172AudioMode_audioSampling choice", HFILL }},
	{ &hf_h245_IS11172AudioMode_audioLayer,
		{ "IS11172AudioMode_audioLayer type", "h245.IS11172AudioMode_audioLayer_type", FT_UINT32, BASE_DEC,
		VALS(IS11172AudioMode_audioLayer_vals), 0, "Type of IS11172AudioMode_audioLayer choice", HFILL }},
	{ &hf_h245_AudioMode_g7231,
		{ "AudioMode_g7231 type", "h245.AudioMode_g7231_type", FT_UINT32, BASE_DEC,
		VALS(AudioMode_g7231_vals), 0, "Type of AudioMode_g7231 choice", HFILL }},
	{ &hf_h245_AudioMode,
		{ "AudioMode type", "h245.AudioMode_type", FT_UINT32, BASE_DEC,
		VALS(AudioMode_vals), 0, "Type of AudioMode choice", HFILL }},
	{ &hf_h245_H263VideoMode_resolution,
		{ "H263VideoMode_resolution type", "h245.H263VideoMode_resolution_type", FT_UINT32, BASE_DEC,
		VALS(H263VideoMode_resolution_vals), 0, "Type of H263VideoMode_resolution choice", HFILL }},
	{ &hf_h245_H262VideoMode_profileAndLevel,
		{ "H262VideoMode_profileAndLevel type", "h245.H262VideoMode_profileAndLevel_type", FT_UINT32, BASE_DEC,
		VALS(H262VideoMode_profileAndLevel_vals), 0, "Type of H262VideoMode_profileAndLevel choice", HFILL }},
	{ &hf_h245_H261VideoMode_resolution,
		{ "H261VideoMode_resolution type", "h245.H261VideoMode_resolution_type", FT_UINT32, BASE_DEC,
		VALS(H261VideoMode_resolution_vals), 0, "Type of H261VideoMode_resolution choice", HFILL }},
	{ &hf_h245_VideoMode,
		{ "VideoMode type", "h245.VideoMode_type", FT_UINT32, BASE_DEC,
		VALS(VideoMode_vals), 0, "Type of VideoMode choice", HFILL }},
	{ &hf_h245_RedundancyEncodingMode_secondaryEncoding,
		{ "RedundancyEncodingMode_secondaryEncoding type", "h245.RedundancyEncodingMode_secondaryEncoding_type", FT_UINT32, BASE_DEC,
		VALS(RedundancyEncodingMode_secondaryEncoding_vals), 0, "Type of RedundancyEncodingMode_secondaryEncoding choice", HFILL }},
	{ &hf_h245_V76ModeParameters,
		{ "V76ModeParameters type", "h245.V76ModeParameters_type", FT_UINT32, BASE_DEC,
		VALS(V76ModeParameters_vals), 0, "Type of V76ModeParameters choice", HFILL }},
	{ &hf_h245_H223ModeParameters_adaptationLayerType,
		{ "H223ModeParameters_adaptationLayerType type", "h245.H223ModeParameters_adaptationLayerType_type", FT_UINT32, BASE_DEC,
		VALS(H223ModeParameters_adaptationLayerType_vals), 0, "Type of H223ModeParameters_adaptationLayerType choice", HFILL }},
	{ &hf_h245_FECMode_rfc2733Mode_mode_separateStream,
		{ "FECMode_rfc2733Mode_mode_separateStream type", "h245.FECMode_rfc2733Mode_mode_separateStream_type", FT_UINT32, BASE_DEC,
		VALS(FECMode_rfc2733Mode_mode_separateStream_vals), 0, "Type of FECMode_rfc2733Mode_mode_separateStream choice", HFILL }},
	{ &hf_h245_FECMode_rfc2733Mode_mode,
		{ "FECMode_rfc2733Mode_mode type", "h245.FECMode_rfc2733Mode_mode_type", FT_UINT32, BASE_DEC,
		VALS(FECMode_rfc2733Mode_mode_vals), 0, "Type of FECMode_rfc2733Mode_mode choice", HFILL }},
	{ &hf_h245_FECMode,
		{ "FECMode type", "h245.FECMode_type", FT_UINT32, BASE_DEC,
		VALS(FECMode_vals), 0, "Type of FECMode choice", HFILL }},
	{ &hf_h245_RedundancyEncodingDTModeElement_type,
		{ "RedundancyEncodingDTModeElement_type type", "h245.RedundancyEncodingDTModeElement_type_type", FT_UINT32, BASE_DEC,
		VALS(RedundancyEncodingDTModeElement_type_vals), 0, "Type of RedundancyEncodingDTModeElement_type choice", HFILL }},
	{ &hf_h245_H235Mode_mediaMode,
		{ "H235Mode_mediaMode type", "h245.H235Mode_mediaMode_type", FT_UINT32, BASE_DEC,
		VALS(H235Mode_mediaMode_vals), 0, "Type of H235Mode_mediaMode choice", HFILL }},
	{ &hf_h245_ModeElementType,
		{ "ModeElementType type", "h245.ModeElementType_type", FT_UINT32, BASE_DEC,
		VALS(ModeElementType_vals), 0, "Type of ModeElementType choice", HFILL }},
	{ &hf_h245_RequestModeReject_cause,
		{ "RequestModeReject_cause type", "h245.RequestModeReject_cause_type", FT_UINT32, BASE_DEC,
		VALS(RequestModeReject_cause_vals), 0, "Type of RequestModeReject_cause choice", HFILL }},
	{ &hf_h245_RequestMultiplexEntryRejectionDescriptions_cause,
		{ "RequestMultiplexEntryRejectionDescriptions_cause type", "h245.RequestMultiplexEntryRejectionDescriptions_cause_type", FT_UINT32, BASE_DEC,
		VALS(RequestMultiplexEntryRejectionDescriptions_cause_vals), 0, "Type of RequestMultiplexEntryRejectionDescriptions_cause choice", HFILL }},
	{ &hf_h245_MultiplexEntryRejectionDescriptions_cause,
		{ "MultiplexEntryRejectionDescriptions_cause type", "h245.MultiplexEntryRejectionDescriptions_cause_type", FT_UINT32, BASE_DEC,
		VALS(MultiplexEntryRejectionDescriptions_cause_vals), 0, "Type of MultiplexEntryRejectionDescriptions_cause choice", HFILL }},
	{ &hf_h245_MultiplexElement_repeatCount,
		{ "MultiplexElement_repeatCount type", "h245.MultiplexElement_repeatCount_type", FT_UINT32, BASE_DEC,
		VALS(MultiplexElement_repeatCount_vals), 0, "Type of MultiplexElement_repeatCount choice", HFILL }},
	{ &hf_h245_MultiplexElement_type,
		{ "MultiplexElement_type type", "h245.MultiplexElement_type_type", FT_UINT32, BASE_DEC,
		VALS(MultiplexElement_type_vals), 0, "Type of MultiplexElement_type choice", HFILL }},
	{ &hf_h245_RequestChannelCloseReject_cause,
		{ "RequestChannelCloseReject_cause type", "h245.RequestChannelCloseReject_cause_type", FT_UINT32, BASE_DEC,
		VALS(RequestChannelCloseReject_cause_vals), 0, "Type of RequestChannelCloseReject_cause choice", HFILL }},
	{ &hf_h245_RequestChannelClose_reason,
		{ "RequestChannelClose_reason type", "h245.RequestChannelClose_reason_type", FT_UINT32, BASE_DEC,
		VALS(RequestChannelClose_reason_vals), 0, "Type of RequestChannelClose_reason choice", HFILL }},
	{ &hf_h245_CloseLogicalChannel_reason,
		{ "CloseLogicalChannel_reason type", "h245.CloseLogicalChannel_reason_type", FT_UINT32, BASE_DEC,
		VALS(CloseLogicalChannel_reason_vals), 0, "Type of CloseLogicalChannel_reason choice", HFILL }},
	{ &hf_h245_CloseLogicalChannel_source,
		{ "CloseLogicalChannel_source type", "h245.CloseLogicalChannel_source_type", FT_UINT32, BASE_DEC,
		VALS(CloseLogicalChannel_source_vals), 0, "Type of CloseLogicalChannel_source choice", HFILL }},
	{ &hf_h245_OpenLogicalChannelReject_cause,
		{ "OpenLogicalChannelReject_cause type", "h245.OpenLogicalChannelReject_cause_type", FT_UINT32, BASE_DEC,
		VALS(OpenLogicalChannelReject_cause_vals), 0, "Type of OpenLogicalChannelReject_cause choice", HFILL }},
	{ &hf_h245_forwardMultiplexAckParameters,
		{ "forwardMultiplexAckParameters type", "h245.forwardMultiplexAckParameters_type", FT_UINT32, BASE_DEC,
		VALS(forwardMultiplexAckParameters_vals), 0, "Type of forwardMultiplexAckParameters choice", HFILL }},
	{ &hf_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters,
		{ "OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters type", "h245.OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters_type", FT_UINT32, BASE_DEC,
		VALS(OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters_vals), 0, "Type of OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters choice", HFILL }},
	{ &hf_h245_MulticastAddress,
		{ "MulticastAddress type", "h245.MulticastAddress_type", FT_UINT32, BASE_DEC,
		VALS(MulticastAddress_vals), 0, "Type of MulticastAddress choice", HFILL }},
	{ &hf_h245_UnicastAddress_iPSourceRouteAddress_routing,
		{ "UnicastAddress_iPSourceRouteAddress_routing type", "h245.UnicastAddress_iPSourceRouteAddress_routing_type", FT_UINT32, BASE_DEC,
		VALS(UnicastAddress_iPSourceRouteAddress_routing_vals), 0, "Type of UnicastAddress_iPSourceRouteAddress_routing choice", HFILL }},
	{ &hf_h245_UnicastAddress,
		{ "UnicastAddress type", "h245.UnicastAddress_type", FT_UINT32, BASE_DEC,
		VALS(UnicastAddress_vals), 0, "Type of UnicastAddress choice", HFILL }},
	{ &hf_h245_mediaControlChannel,
		{ "mediaControlChannel type", "h245.mediaControlChannel_type", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "Type of mediaControlChannel choice", HFILL }},
	{ &hf_h245_mediaChannel,
		{ "mediaChannel type", "h245.mediaChannel_type", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "Type of mediaChannel choice", HFILL }},
	{ &hf_h245_localAreaAddress,
		{ "localAreaAddress type", "h245.localAreaAddress_type", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "Type of localAreaAddress choice", HFILL }},
	{ &hf_h245_signalAddress,
		{ "signalAddress type", "h245.signalAddress_type", FT_UINT32, BASE_DEC,
		VALS(TransportAddress_vals), 0, "Type of signalAddress choice", HFILL }},
	{ &hf_h245_FECData_rfc2733_mode_separateStream,
		{ "FECData_rfc2733_mode_separateStream type", "h245.FECData_rfc2733_mode_separateStream_type", FT_UINT32, BASE_DEC,
		VALS(FECData_rfc2733_mode_separateStream_vals), 0, "Type of FECData_rfc2733_mode_separateStream choice", HFILL }},
	{ &hf_h245_FECData_rfc2733_mode,
		{ "FECData_rfc2733_mode type", "h245.FECData_rfc2733_mode_type", FT_UINT32, BASE_DEC,
		VALS(FECData_rfc2733_mode_vals), 0, "Type of FECData_rfc2733_mode choice", HFILL }},
	{ &hf_h245_FECData,
		{ "FECData type", "h245.FECData_type", FT_UINT32, BASE_DEC,
		VALS(FECData_vals), 0, "Type of FECData choice", HFILL }},
	{ &hf_h245_RTPPayloadType_payloadDescriptor,
		{ "RTPPayloadType_payloadDescriptor type", "h245.RTPPayloadType_payloadDescriptor_type", FT_UINT32, BASE_DEC,
		VALS(RTPPayloadType_payloadDescriptor_vals), 0, "Type of RTPPayloadType_payloadDescriptor choice", HFILL }},
	{ &hf_h245_H2250LogicalChannelParameters_mediaPacketization,
		{ "H2250LogicalChannelParameters_mediaPacketization type", "h245.H2250LogicalChannelParameters_mediaPacketization_type", FT_UINT32, BASE_DEC,
		VALS(H2250LogicalChannelParameters_mediaPacketization_vals), 0, "Type of H2250LogicalChannelParameters_mediaPacketization choice", HFILL }},
	{ &hf_h245_CRCLength,
		{ "CRCLength type", "h245.CRCLength_type", FT_UINT32, BASE_DEC,
		VALS(CRCLength_vals), 0, "Type of CRCLength choice", HFILL }},
	{ &hf_h245_V76LogicalChannelParameters_mode_eRM_recovery,
		{ "V76LogicalChannelParameters_mode_eRM_recovery type", "h245.V76LogicalChannelParameters_mode_eRM_recovery_type", FT_UINT32, BASE_DEC,
		VALS(V76LogicalChannelParameters_mode_eRM_recovery_vals), 0, "Type of V76LogicalChannelParameters_mode_eRM_recovery choice", HFILL }},
	{ &hf_h245_V76LogicalChannelParameters_mode,
		{ "V76LogicalChannelParameters_mode type", "h245.V76LogicalChannelParameters_mode_type", FT_UINT32, BASE_DEC,
		VALS(V76LogicalChannelParameters_mode_vals), 0, "Type of V76LogicalChannelParameters_mode choice", HFILL }},
	{ &hf_h245_V76LogicalChannelParameters_suspendResume,
		{ "V76LogicalChannelParameters_suspendResume type", "h245.V76LogicalChannelParameters_suspendResume_type", FT_UINT32, BASE_DEC,
		VALS(V76LogicalChannelParameters_suspendResume_vals), 0, "Type of V76LogicalChannelParameters_suspendResume choice", HFILL }},
	{ &hf_h245_H223AnnexCArqParameters_numberOfRetransmissions,
		{ "H223AnnexCArqParameters_numberOfRetransmissions type", "h245.H223AnnexCArqParameters_numberOfRetransmissions_type", FT_UINT32, BASE_DEC,
		VALS(H223AnnexCArqParameters_numberOfRetransmissions_vals), 0, "Type of H223AnnexCArqParameters_numberOfRetransmissions choice", HFILL }},
	{ &hf_h245_H223AL3MParameters_arqType,
		{ "H223AL3MParameters_arqType type", "h245.H223AL3MParameters_arqType_type", FT_UINT32, BASE_DEC,
		VALS(H223AL3MParameters_arqType_vals), 0, "Type of H223AL3MParameters_arqType choice", HFILL }},
	{ &hf_h245_H223AL3MParameters_crcLength,
		{ "H223AL3MParameters_crcLength type", "h245.H223AL3MParameters_crcLength_type", FT_UINT32, BASE_DEC,
		VALS(H223AL3MParameters_crcLength_vals), 0, "Type of H223AL3MParameters_crcLength choice", HFILL }},
	{ &hf_h245_H223AL3MParameters_headerFormat,
		{ "H223AL3MParameters_headerFormat type", "h245.H223AL3MParameters_headerFormat_type", FT_UINT32, BASE_DEC,
		VALS(H223AL3MParameters_headerFormat_vals), 0, "Type of H223AL3MParameters_headerFormat choice", HFILL }},
	{ &hf_h245_H223AL2MParameters_headerFEC,
		{ "H223AL2MParameters_headerFEC type", "h245.H223AL2MParameters_headerFEC_type", FT_UINT32, BASE_DEC,
		VALS(H223AL2MParameters_headerFEC_vals), 0, "Type of H223AL2MParameters_headerFEC choice", HFILL }},
	{ &hf_h245_H223AL1MParameters_arqType,
		{ "H223AL1MParameters_arqType type", "h245.H223AL1MParameters_arqType_type", FT_UINT32, BASE_DEC,
		VALS(H223AL1MParameters_arqType_vals), 0, "Type of H223AL1MParameters_arqType choice", HFILL }},
	{ &hf_h245_H223AL1MParameters_crcLength,
		{ "H223AL1MParameters_crcLength type", "h245.H223AL1MParameters_crcLength_type", FT_UINT32, BASE_DEC,
		VALS(H223AL1MParameters_crcLength_vals), 0, "Type of H223AL1MParameters_crcLength choice", HFILL }},
	{ &hf_h245_H223AL1MParameters_headerFEC,
		{ "H223AL1MParameters_headerFEC type", "h245.H223AL1MParameters_headerFEC_type", FT_UINT32, BASE_DEC,
		VALS(H223AL1MParameters_headerFEC_vals), 0, "Type of H223AL1MParameters_headerFEC choice", HFILL }},
	{ &hf_h245_H223AL1MParameters_transferMode,
		{ "H223AL1MParameters_transferMode type", "h245.H223AL1MParameters_transferMode_type", FT_UINT32, BASE_DEC,
		VALS(H223AL1MParameters_transferMode_vals), 0, "Type of H223AL1MParameters_transferMode choice", HFILL }},
	{ &hf_h245_H223LogicalChannelParameters_adaptationLayerType,
		{ "H223LogicalChannelParameters_adaptationLayerType type", "h245.H223LogicalChannelParameters_adaptationLayerType_type", FT_UINT32, BASE_DEC,
		VALS(H223LogicalChannelParameters_adaptationLayerType_vals), 0, "Type of H223LogicalChannelParameters_adaptationLayerType choice", HFILL }},
	{ &hf_h245_H235Media_mediaType,
		{ "H235Media_mediaType type", "h245.H235Media_mediaType_type", FT_UINT32, BASE_DEC,
		VALS(H235Media_mediaType_vals), 0, "Type of H235Media_mediaType choice", HFILL }},
	{ &hf_h245_DataType,
		{ "DataType type", "h245.DataType_type", FT_UINT32, BASE_DEC,
		VALS(DataType_vals), 0, "Type of DataType choice", HFILL }},
	{ &hf_h245_Q2931Address_address,
		{ "Q2931Address_address type", "h245.Q2931Address_address_type", FT_UINT32, BASE_DEC,
		VALS(Q2931Address_address_vals), 0, "Type of Q2931Address_address choice", HFILL }},
	{ &hf_h245_NetworkAccessParameters_t120SetupProcedure,
		{ "NetworkAccessParameters_t120SetupProcedure type", "h245.NetworkAccessParameters_t120SetupProcedure_type", FT_UINT32, BASE_DEC,
		VALS(NetworkAccessParameters_t120SetupProcedure_vals), 0, "Type of NetworkAccessParameters_t120SetupProcedure choice", HFILL }},
	{ &hf_h245_NetworkAccessParameters_networkAddress,
		{ "NetworkAccessParameters_networkAddress type", "h245.NetworkAccessParameters_networkAddress_type", FT_UINT32, BASE_DEC,
		VALS(NetworkAccessParameters_networkAddress_vals), 0, "Type of NetworkAccessParameters_networkAddress choice", HFILL }},
	{ &hf_h245_NetworkAccessParameters_distribution,
		{ "NetworkAccessParameters_distribution type", "h245.NetworkAccessParameters_distribution_type", FT_UINT32, BASE_DEC,
		VALS(NetworkAccessParameters_distribution_vals), 0, "Type of NetworkAccessParameters_distribution choice", HFILL }},
	{ &hf_h245_reverseLogicalChannelParameters_multiplexParameters,
		{ "reverseLogicalChannelParameters_multiplexParameters type", "h245.reverseLogicalChannelParameters_multiplexParameters_type", FT_UINT32, BASE_DEC,
		VALS(reverseLogicalChannelParameters_multiplexParameters_vals), 0, "Type of reverseLogicalChannelParameters_multiplexParameters choice", HFILL }},
	{ &hf_h245_forwardLogicalChannelParameters_multiplexParameters,
		{ "forwardLogicalChannelParameters_multiplexParameters type", "h245.forwardLogicalChannelParameters_multiplexParameters_type", FT_UINT32, BASE_DEC,
		VALS(forwardLogicalChannelParameters_multiplexParameters_vals), 0, "Type of forwardLogicalChannelParameters_multiplexParameters choice", HFILL }},
	{ &hf_h245_FECCapability,
		{ "FECCapability type", "h245.FECCapability_type", FT_UINT32, BASE_DEC,
		VALS(FECCapability_vals), 0, "Type of FECCapability choice", HFILL }},
	{ &hf_h245_MultiplexFormat,
		{ "MultiplexFormat type", "h245.MultiplexFormat_type", FT_UINT32, BASE_DEC,
		VALS(MultiplexFormat_vals), 0, "Type of MultiplexFormat choice", HFILL }},
	{ &hf_h245_ParameterValue,
		{ "ParameterValue type", "h245.ParameterValue_type", FT_UINT32, BASE_DEC,
		VALS(ParameterValue_vals), 0, "Type of ParameterValue choice", HFILL }},
	{ &hf_h245_ParameterIdentifier,
		{ "ParameterIdentifier type", "h245.ParameterIdentifier_type", FT_UINT32, BASE_DEC,
		VALS(ParameterIdentifier_vals), 0, "Type of ParameterIdentifier choice", HFILL }},
	{ &hf_h245_CapabilityIdentifier,
		{ "CapabilityIdentifier type", "h245.CapabilityIdentifier_type", FT_UINT32, BASE_DEC,
		VALS(CapabilityIdentifier_vals), 0, "Type of CapabilityIdentifier choice", HFILL }},
	{ &hf_h245_UserInputCapability,
		{ "UserInputCapability type", "h245.UserInputCapability_type", FT_UINT32, BASE_DEC,
		VALS(UserInputCapability_vals), 0, "Type of UserInputCapability choice", HFILL }},
	{ &hf_h245_MediaEncryptionAlgorithm,
		{ "MediaEncryptionAlgorithm type", "h245.MediaEncryptionAlgorithm_type", FT_UINT32, BASE_DEC,
		VALS(MediaEncryptionAlgorithm_vals), 0, "Type of MediaEncryptionAlgorithm choice", HFILL }},
	{ &hf_h245_T38FaxUdpOptions_t38FaxUdpEC,
		{ "T38FaxUdpOptions_t38FaxUdpEC type", "h245.T38FaxUdpOptions_t38FaxUdpEC_type", FT_UINT32, BASE_DEC,
		VALS(T38FaxUdpOptions_t38FaxUdpEC_vals), 0, "Type of T38FaxUdpOptions_t38FaxUdpEC choice", HFILL }},
	{ &hf_h245_T38FaxRateManagement,
		{ "T38FaxRateManagement type", "h245.T38FaxRateManagement_type", FT_UINT32, BASE_DEC,
		VALS(T38FaxRateManagement_vals), 0, "Type of T38FaxRateManagement choice", HFILL }},
	{ &hf_h245_T84Profile,
		{ "T84Profile type", "h245.T84Profile_type", FT_UINT32, BASE_DEC,
		VALS(T84Profile_vals), 0, "Type of T84Profile choice", HFILL }},
	{ &hf_h245_CompressionType,
		{ "CompressionType type", "h245.CompressionType_type", FT_UINT32, BASE_DEC,
		VALS(CompressionType_vals), 0, "Type of CompressionType choice", HFILL }},
	{ &hf_h245_DataProtocolCapability_v76wCompression,
		{ "DataProtocolCapability_v76wCompression type", "h245.DataProtocolCapability_v76wCompression_type", FT_UINT32, BASE_DEC,
		VALS(DataProtocolCapability_v76wCompression_vals), 0, "Type of DataProtocolCapability_v76wCompression choice", HFILL }},
	{ &hf_h245_DataProtocolCapability,
		{ "DataProtocolCapability type", "h245.DataProtocolCapability_type", FT_UINT32, BASE_DEC,
		VALS(DataProtocolCapability_vals), 0, "Type of DataProtocolCapability choice", HFILL }},
	{ &hf_h245_DataApplicationCapability_application,
		{ "DataApplicationCapability_application type", "h245.DataApplicationCapability_application_type", FT_UINT32, BASE_DEC,
		VALS(DataApplicationCapability_application_vals), 0, "Type of DataApplicationCapability_application choice", HFILL }},
	{ &hf_h245_AudioCapability,
		{ "AudioCapability type", "h245.AudioCapability_type", FT_UINT32, BASE_DEC,
		VALS(AudioCapability_vals), 0, "Type of AudioCapability choice", HFILL }},
	{ &hf_h245_CustomPictureFormat_pixelAspectInformation,
		{ "CustomPictureFormat_pixelAspectInformation type", "h245.CustomPictureFormat_pixelAspectInformation_type", FT_UINT32, BASE_DEC,
		VALS(CustomPictureFormat_pixelAspectInformation_vals), 0, "Type of CustomPictureFormat_pixelAspectInformation choice", HFILL }},
	{ &hf_h245_RefPictureSelection_videoBackChannelSend,
		{ "RefPictureSelection_videoBackChannelSend type", "h245.RefPictureSelection_videoBackChannelSend_type", FT_UINT32, BASE_DEC,
		VALS(RefPictureSelection_videoBackChannelSend_vals), 0, "Type of RefPictureSelection_videoBackChannelSend choice", HFILL }},
	{ &hf_h245_VideoCapability,
		{ "VideoCapability type", "h245.VideoCapability_type", FT_UINT32, BASE_DEC,
		VALS(VideoCapability_vals), 0, "Type of VideoCapability choice", HFILL }},
	{ &hf_h245_RTPH263VideoRedundancyEncoding_frameToThreadMapping,
		{ "RTPH263VideoRedundancyEncoding_frameToThreadMapping type", "h245.RTPH263VideoRedundancyEncoding_frameToThreadMapping_type", FT_UINT32, BASE_DEC,
		VALS(RTPH263VideoRedundancyEncoding_frameToThreadMapping_vals), 0, "Type of RTPH263VideoRedundancyEncoding_frameToThreadMapping choice", HFILL }},
	{ &hf_h245_RedundancyEncodingMethod,
		{ "RedundancyEncodingMethod type", "h245.RedundancyEncodingMethod_type", FT_UINT32, BASE_DEC,
		VALS(RedundancyEncodingMethod_vals), 0, "Type of RedundancyEncodingMethod choice", HFILL }},
	{ &hf_h245_MediaTransportType,
		{ "MediaTransportType type", "h245.MediaTransportType_type", FT_UINT32, BASE_DEC,
		VALS(MediaTransportType_vals), 0, "Type of MediaTransportType choice", HFILL }},
	{ &hf_h245_QOSMode,
		{ "QOSMode type", "h245.QOSMode_type", FT_UINT32, BASE_DEC,
		VALS(QOSMode_vals), 0, "Type of QOSMode choice", HFILL }},
	{ &hf_h245_H223Capability_h223MultiplexTableCapability,
		{ "H223Capability_h223MultiplexTableCapability type", "h245.H223Capability_h223MultiplexTableCapability_type", FT_UINT32, BASE_DEC,
		VALS(H223Capability_h223MultiplexTableCapability_vals), 0, "Type of H223Capability_h223MultiplexTableCapability choice", HFILL }},
	{ &hf_h245_VCCapability_availableBitRates_type,
		{ "VCCapability_availableBitRates_type type", "h245.VCCapability_availableBitRates_type_type", FT_UINT32, BASE_DEC,
		VALS(VCCapability_availableBitRates_type_vals), 0, "Type of VCCapability_availableBitRates_type choice", HFILL }},
	{ &hf_h245_MultiplexCapability,
		{ "MultiplexCapability type", "h245.MultiplexCapability_type", FT_UINT32, BASE_DEC,
		VALS(MultiplexCapability_vals), 0, "Type of MultiplexCapability choice", HFILL }},
	{ &hf_h245_Capability,
		{ "Capability type", "h245.Capability_type", FT_UINT32, BASE_DEC,
		VALS(Capability_vals), 0, "Type of Capability choice", HFILL }},
	{ &hf_h245_TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded,
		{ "TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded type", "h245.TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded_type", FT_UINT32, BASE_DEC,
		VALS(TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded_vals), 0, "Type of TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded choice", HFILL }},
	{ &hf_h245_TerminalCapabilitySetReject_cause,
		{ "TerminalCapabilitySetReject_cause type", "h245.TerminalCapabilitySetReject_cause_type", FT_UINT32, BASE_DEC,
		VALS(TerminalCapabilitySetReject_cause_vals), 0, "Type of TerminalCapabilitySetReject_cause choice", HFILL }},
	{ &hf_h245_MasterSlaveDeterminationReject_cause,
		{ "MasterSlaveDeterminationReject_cause type", "h245.MasterSlaveDeterminationReject_cause_type", FT_UINT32, BASE_DEC,
		VALS(MasterSlaveDeterminationReject_cause_vals), 0, "Type of MasterSlaveDeterminationReject_cause choice", HFILL }},
	{ &hf_h245_MasterSlaveDeterminationAck_decision,
		{ "MasterSlaveDeterminationAck_decision type", "h245.MasterSlaveDeterminationAck_decision_type", FT_UINT32, BASE_DEC,
		VALS(MasterSlaveDeterminationAck_decision_vals), 0, "Type of MasterSlaveDeterminationAck_decision choice", HFILL }},
	{ &hf_h245_RequestModeAck_response_decision,
		{ "RequestModeAck_response_decision type", "h245.RequestModeAck_response_decision_type", FT_UINT32, BASE_DEC,
		VALS(RequestModeAck_response_decision_vals), 0, "Type of RequestModeAck_response_decision choice", HFILL }},
	{ &hf_h245_NonStandardIdentifier,
		{ "NonStandardIdentifier type", "h245.NonStandardIdentifier_type", FT_UINT32, BASE_DEC,
		VALS(NonStandardIdentifier_vals), 0, "Type of NonStandardIdentifier choice", HFILL }},
	{ &hf_h245_h233EncryptionTransmitCapability,
		{ "h233EncryptionTransmitCapability", "h245.h233EncryptionTransmitCapability", FT_BOOLEAN, 8,
		TFS(&tfs_h233EncryptionTransmitCapability_bit), 0x01, "The h233EncryptionTransmitCapability bit", HFILL }},
	{ &hf_h245_nullClockRecovery,
		{ "nullClockRecovery", "h245.nullClockRecovery", FT_BOOLEAN, 8,
		TFS(&tfs_nullClockRecovery_bit), 0x01, "The nullClockRecovery bit", HFILL }},
	{ &hf_h245_srtsClockRecovery,
		{ "srtsClockRecovery", "h245.srtsClockRecovery", FT_BOOLEAN, 8,
		TFS(&tfs_srtsClockRecovery_bit), 0x01, "The srtsClockRecovery bit", HFILL }},
	{ &hf_h245_adaptiveClockRecovery,
		{ "adaptiveClockRecovery", "h245.adaptiveClockRecovery", FT_BOOLEAN, 8,
		TFS(&tfs_adaptiveClockRecovery_bit), 0x01, "The adaptiveClockRecovery bit", HFILL }},
	{ &hf_h245_nullErrorCorrection,
		{ "nullErrorCorrection", "h245.nullErrorCorrection", FT_BOOLEAN, 8,
		TFS(&tfs_nullErrorCorrection_bit), 0x01, "The nullErrorCorrection bit", HFILL }},
	{ &hf_h245_longInterleaver,
		{ "longInterleaver", "h245.longInterleaver", FT_BOOLEAN, 8,
		TFS(&tfs_longInterleaver_bit), 0x01, "The longInterleaver bit", HFILL }},
	{ &hf_h245_shortInterleaver,
		{ "shortInterleaver", "h245.shortInterleaver", FT_BOOLEAN, 8,
		TFS(&tfs_shortInterleaver_bit), 0x01, "The shortInterleaver bit", HFILL }},
	{ &hf_h245_errorCorrectionOnly,
		{ "errorCorrectionOnly", "h245.errorCorrectionOnly", FT_BOOLEAN, 8,
		TFS(&tfs_errorCorrectionOnly_bit), 0x01, "The errorCorrectionOnly bit", HFILL }},
	{ &hf_h245_structuredDataTransfer,
		{ "structuredDataTransfer", "h245.structuredDataTransfer", FT_BOOLEAN, 8,
		TFS(&tfs_structuredDataTransfer_bit), 0x01, "The structuredDataTransfer bit", HFILL }},
	{ &hf_h245_partiallyFilledCells,
		{ "partiallyFilledCells", "h245.partiallyFilledCells", FT_BOOLEAN, 8,
		TFS(&tfs_partiallyFilledCells_bit), 0x01, "The partiallyFilledCells bit", HFILL }},
	{ &hf_h245_transportStream,
		{ "transportStream", "h245.transportStream", FT_BOOLEAN, 8,
		TFS(&tfs_transportStream_bit), 0x01, "The transportStream bit", HFILL }},
	{ &hf_h245_programStream,
		{ "programStream", "h245.programStream", FT_BOOLEAN, 8,
		TFS(&tfs_programStream_bit), 0x01, "The programStream bit", HFILL }},
	{ &hf_h245_transportWithIframes,
		{ "transportWithIframes", "h245.transportWithIframes", FT_BOOLEAN, 8,
		TFS(&tfs_transportWithIframes_bit), 0x01, "The transportWithIframes bit", HFILL }},
	{ &hf_h245_videoWithAL1,
		{ "videoWithAL1", "h245.videoWithAL1", FT_BOOLEAN, 8,
		TFS(&tfs_videoWithAL1_bit), 0x01, "The videoWithAL1 bit", HFILL }},
	{ &hf_h245_videoWithAL2,
		{ "videoWithAL2", "h245.videoWithAL2", FT_BOOLEAN, 8,
		TFS(&tfs_videoWithAL2_bit), 0x01, "The videoWithAL2 bit", HFILL }},
	{ &hf_h245_videoWithAL3,
		{ "videoWithAL3", "h245.videoWithAL3", FT_BOOLEAN, 8,
		TFS(&tfs_videoWithAL3_bit), 0x01, "The videoWithAL3 bit", HFILL }},
	{ &hf_h245_audioWithAL1,
		{ "audioWithAL1", "h245.audioWithAL1", FT_BOOLEAN, 8,
		TFS(&tfs_audioWithAL1_bit), 0x01, "The audioWithAL1 bit", HFILL }},
	{ &hf_h245_audioWithAL2,
		{ "audioWithAL2", "h245.audioWithAL2", FT_BOOLEAN, 8,
		TFS(&tfs_audioWithAL2_bit), 0x01, "The audioWithAL2 bit", HFILL }},
	{ &hf_h245_audioWithAL3,
		{ "audioWithAL3", "h245.audioWithAL3", FT_BOOLEAN, 8,
		TFS(&tfs_audioWithAL3_bit), 0x01, "The audioWithAL3 bit", HFILL }},
	{ &hf_h245_dataWithAL1,
		{ "dataWithAL1", "h245.dataWithAL1", FT_BOOLEAN, 8,
		TFS(&tfs_dataWithAL1_bit), 0x01, "The dataWithAL1 bit", HFILL }},
	{ &hf_h245_dataWithAL2,
		{ "dataWithAL2", "h245.dataWithAL2", FT_BOOLEAN, 8,
		TFS(&tfs_dataWithAL2_bit), 0x01, "The dataWithAL2 bit", HFILL }},
	{ &hf_h245_dataWithAL3,
		{ "dataWithAL3", "h245.dataWithAL3", FT_BOOLEAN, 8,
		TFS(&tfs_dataWithAL3_bit), 0x01, "The dataWithAL3 bit", HFILL }},
	{ &hf_h245_maxMUXPDUSizeCapability,
		{ "maxMUXPDUSizeCapability", "h245.maxMUXPDUSizeCapability", FT_BOOLEAN, 8,
		TFS(&tfs_maxMUXPDUSizeCapability_bit), 0x01, "The maxMUXPDUSizeCapability bit", HFILL }},
	{ &hf_h245_nsrpSupport,
		{ "nsrpSupport", "h245.nsrpSupport", FT_BOOLEAN, 8,
		TFS(&tfs_nsrpSupport_bit), 0x01, "The nsrpSupport bit", HFILL }},
	{ &hf_h245_modeChangeCapability,
		{ "modeChangeCapability", "h245.modeChangeCapability", FT_BOOLEAN, 8,
		TFS(&tfs_modeChangeCapability_bit), 0x01, "The modeChangeCapability bit", HFILL }},
	{ &hf_h245_h223AnnexA,
		{ "h223AnnexA", "h245.h223AnnexA", FT_BOOLEAN, 8,
		TFS(&tfs_h223AnnexA_bit), 0x01, "The h223AnnexA bit", HFILL }},
	{ &hf_h245_h223AnnexADoubleFlag_bool,
		{ "h223AnnexADoubleFlag_bool", "h245.h223AnnexADoubleFlag_bool", FT_BOOLEAN, 8,
		TFS(&tfs_h223AnnexADoubleFlag_bool_bit), 0x01, "The h223AnnexADoubleFlag_bool bit", HFILL }},
	{ &hf_h245_h223AnnexB,
		{ "h223AnnexB", "h245.h223AnnexB", FT_BOOLEAN, 8,
		TFS(&tfs_h223AnnexB_bit), 0x01, "The h223AnnexB bit", HFILL }},
	{ &hf_h245_h223AnnexBwithHeader,
		{ "h223AnnexBwithHeader", "h245.h223AnnexBwithHeader", FT_BOOLEAN, 8,
		TFS(&tfs_h223AnnexBwithHeader_bit), 0x01, "The h223AnnexBwithHeader bit", HFILL }},
	{ &hf_h245_videoWithAL1M,
		{ "videoWithAL1M", "h245.videoWithAL1M", FT_BOOLEAN, 8,
		TFS(&tfs_videoWithAL1M_bit), 0x01, "The videoWithAL1M bit", HFILL }},
	{ &hf_h245_videoWithAL2M,
		{ "videoWithAL2M", "h245.videoWithAL2M", FT_BOOLEAN, 8,
		TFS(&tfs_videoWithAL2M_bit), 0x01, "The videoWithAL2M bit", HFILL }},
	{ &hf_h245_videoWithAL3M,
		{ "videoWithAL3M", "h245.videoWithAL3M", FT_BOOLEAN, 8,
		TFS(&tfs_videoWithAL3M_bit), 0x01, "The videoWithAL3M bit", HFILL }},
	{ &hf_h245_audioWithAL1M,
		{ "audioWithAL1M", "h245.audioWithAL1M", FT_BOOLEAN, 8,
		TFS(&tfs_audioWithAL1M_bit), 0x01, "The audioWithAL1M bit", HFILL }},
	{ &hf_h245_audioWithAL2M,
		{ "audioWithAL2M", "h245.audioWithAL2M", FT_BOOLEAN, 8,
		TFS(&tfs_audioWithAL2M_bit), 0x01, "The audioWithAL2M bit", HFILL }},
	{ &hf_h245_audioWithAL3M,
		{ "audioWithAL3M", "h245.audioWithAL3M", FT_BOOLEAN, 8,
		TFS(&tfs_audioWithAL3M_bit), 0x01, "The audioWithAL3M bit", HFILL }},
	{ &hf_h245_dataWithAL1M,
		{ "dataWithAL1M", "h245.dataWithAL1M", FT_BOOLEAN, 8,
		TFS(&tfs_dataWithAL1M_bit), 0x01, "The dataWithAL1M bit", HFILL }},
	{ &hf_h245_dataWithAL2M,
		{ "dataWithAL2M", "h245.dataWithAL2M", FT_BOOLEAN, 8,
		TFS(&tfs_dataWithAL2M_bit), 0x01, "The dataWithAL2M bit", HFILL }},
	{ &hf_h245_dataWithAL3M,
		{ "dataWithAL3M", "h245.dataWithAL3M", FT_BOOLEAN, 8,
		TFS(&tfs_dataWithAL3M_bit), 0x01, "The dataWithAL3M bit", HFILL }},
	{ &hf_h245_alpduInterleaving,
		{ "alpduInterleaving", "h245.alpduInterleaving", FT_BOOLEAN, 8,
		TFS(&tfs_alpduInterleaving_bit), 0x01, "The alpduInterleaving bit", HFILL }},
	{ &hf_h245_rsCodeCapability,
		{ "rsCodeCapability", "h245.rsCodeCapability", FT_BOOLEAN, 8,
		TFS(&tfs_rsCodeCapability_bit), 0x01, "The rsCodeCapability bit", HFILL }},
	{ &hf_h245_suspendResumeCapabilitywAddress,
		{ "suspendResumeCapabilitywAddress", "h245.suspendResumeCapabilitywAddress", FT_BOOLEAN, 8,
		TFS(&tfs_suspendResumeCapabilitywAddress_bit), 0x01, "The suspendResumeCapabilitywAddress bit", HFILL }},
	{ &hf_h245_suspendResumeCapabilitywoAddress,
		{ "suspendResumeCapabilitywoAddress", "h245.suspendResumeCapabilitywoAddress", FT_BOOLEAN, 8,
		TFS(&tfs_suspendResumeCapabilitywoAddress_bit), 0x01, "The suspendResumeCapabilitywoAddress bit", HFILL }},
	{ &hf_h245_rejCapability,
		{ "rejCapability", "h245.rejCapability", FT_BOOLEAN, 8,
		TFS(&tfs_rejCapability_bit), 0x01, "The rejCapability bit", HFILL }},
	{ &hf_h245_sREJCapability,
		{ "sREJCapability", "h245.sREJCapability", FT_BOOLEAN, 8,
		TFS(&tfs_sREJCapability_bit), 0x01, "The sREJCapability bit", HFILL }},
	{ &hf_h245_mREJCapability,
		{ "mREJCapability", "h245.mREJCapability", FT_BOOLEAN, 8,
		TFS(&tfs_mREJCapability_bit), 0x01, "The mREJCapability bit", HFILL }},
	{ &hf_h245_crc8bitCapability,
		{ "crc8bitCapability", "h245.crc8bitCapability", FT_BOOLEAN, 8,
		TFS(&tfs_crc8bitCapability_bit), 0x01, "The crc8bitCapability bit", HFILL }},
	{ &hf_h245_crc16bitCapability,
		{ "crc16bitCapability", "h245.crc16bitCapability", FT_BOOLEAN, 8,
		TFS(&tfs_crc16bitCapability_bit), 0x01, "The crc16bitCapability bit", HFILL }},
	{ &hf_h245_crc32bitCapability,
		{ "crc32bitCapability", "h245.crc32bitCapability", FT_BOOLEAN, 8,
		TFS(&tfs_crc32bitCapability_bit), 0x01, "The crc32bitCapability bit", HFILL }},
	{ &hf_h245_uihCapability,
		{ "uihCapability", "h245.uihCapability", FT_BOOLEAN, 8,
		TFS(&tfs_uihCapability_bit), 0x01, "The uihCapability bit", HFILL }},
	{ &hf_h245_twoOctetAddressFieldCapability,
		{ "twoOctetAddressFieldCapability", "h245.twoOctetAddressFieldCapability", FT_BOOLEAN, 8,
		TFS(&tfs_twoOctetAddressFieldCapability_bit), 0x01, "The twoOctetAddressFieldCapability bit", HFILL }},
	{ &hf_h245_loopBackTestCapability,
		{ "loopBackTestCapability", "h245.loopBackTestCapability", FT_BOOLEAN, 8,
		TFS(&tfs_loopBackTestCapability_bit), 0x01, "The loopBackTestCapability bit", HFILL }},
	{ &hf_h245_audioHeader,
		{ "audioHeader", "h245.audioHeader", FT_BOOLEAN, 8,
		TFS(&tfs_audioHeader_bit), 0x01, "The audioHeader bit", HFILL }},
	{ &hf_h245_centralizedConferenceMC,
		{ "centralizedConferenceMC", "h245.centralizedConferenceMC", FT_BOOLEAN, 8,
		TFS(&tfs_centralizedConferenceMC_bit), 0x01, "The centralizedConferenceMC bit", HFILL }},
	{ &hf_h245_decentralizedConferenceMC,
		{ "decentralizedConferenceMC", "h245.decentralizedConferenceMC", FT_BOOLEAN, 8,
		TFS(&tfs_decentralizedConferenceMC_bit), 0x01, "The decentralizedConferenceMC bit", HFILL }},
	{ &hf_h245_rtcpVideoControlCapability,
		{ "rtcpVideoControlCapability", "h245.rtcpVideoControlCapability", FT_BOOLEAN, 8,
		TFS(&tfs_rtcpVideoControlCapability_bit), 0x01, "The rtcpVideoControlCapability bit", HFILL }},
	{ &hf_h245_logicalChannelSwitchingCapability,
		{ "logicalChannelSwitchingCapability", "h245.logicalChannelSwitchingCapability", FT_BOOLEAN, 8,
		TFS(&tfs_logicalChannelSwitchingCapability_bit), 0x01, "The logicalChannelSwitchingCapability bit", HFILL }},
	{ &hf_h245_t120DynamicPortCapability,
		{ "t120DynamicPortCapability", "h245.t120DynamicPortCapability", FT_BOOLEAN, 8,
		TFS(&tfs_t120DynamicPortCapability_bit), 0x01, "The t120DynamicPortCapability bit", HFILL }},
	{ &hf_h245_h261aVideoPacketization,
		{ "h261aVideoPacketization", "h245.h261aVideoPacketization", FT_BOOLEAN, 8,
		TFS(&tfs_h261aVideoPacketization_bit), 0x01, "The h261aVideoPacketization bit", HFILL }},
	{ &hf_h245_atmUBR,
		{ "atmUBR", "h245.atmUBR", FT_BOOLEAN, 8,
		TFS(&tfs_atmUBR_bit), 0x01, "The atmUBR bit", HFILL }},
	{ &hf_h245_atmrtVBR,
		{ "atmrtVBR", "h245.atmrtVBR", FT_BOOLEAN, 8,
		TFS(&tfs_atmrtVBR_bit), 0x01, "The atmrtVBR bit", HFILL }},
	{ &hf_h245_atmnrtVBR,
		{ "atmnrtVBR", "h245.atmnrtVBR", FT_BOOLEAN, 8,
		TFS(&tfs_atmnrtVBR_bit), 0x01, "The atmnrtVBR bit", HFILL }},
	{ &hf_h245_atmABR,
		{ "atmABR", "h245.atmABR", FT_BOOLEAN, 8,
		TFS(&tfs_atmABR_bit), 0x01, "The atmABR bit", HFILL }},
	{ &hf_h245_atmCBR,
		{ "atmCBR", "h245.atmCBR", FT_BOOLEAN, 8,
		TFS(&tfs_atmCBR_bit), 0x01, "The atmCBR bit", HFILL }},
	{ &hf_h245_variableDelta,
		{ "variableDelta", "h245.variableDelta", FT_BOOLEAN, 8,
		TFS(&tfs_variableDelta_bit), 0x01, "The variableDelta bit", HFILL }},
	{ &hf_h245_multicastCapability,
		{ "multicastCapability", "h245.multicastCapability", FT_BOOLEAN, 8,
		TFS(&tfs_multicastCapability_bit), 0x01, "The multicastCapability bit", HFILL }},
	{ &hf_h245_multiUniCastConference,
		{ "multiUniCastConference", "h245.multiUniCastConference", FT_BOOLEAN, 8,
		TFS(&tfs_multiUniCastConference_bit), 0x01, "The multiUniCastConference bit", HFILL }},
	{ &hf_h245_centralizedControl,
		{ "centralizedControl", "h245.centralizedControl", FT_BOOLEAN, 8,
		TFS(&tfs_centralizedControl_bit), 0x01, "The centralizedControl bit", HFILL }},
	{ &hf_h245_distributedControl,
		{ "distributedControl", "h245.distributedControl", FT_BOOLEAN, 8,
		TFS(&tfs_distributedControl_bit), 0x01, "The distributedControl bit", HFILL }},
	{ &hf_h245_centralizedAudio,
		{ "centralizedAudio", "h245.centralizedAudio", FT_BOOLEAN, 8,
		TFS(&tfs_centralizedAudio_bit), 0x01, "The centralizedAudio bit", HFILL }},
	{ &hf_h245_distributedAudio,
		{ "distributedAudio", "h245.distributedAudio", FT_BOOLEAN, 8,
		TFS(&tfs_distributedAudio_bit), 0x01, "The distributedAudio bit", HFILL }},
	{ &hf_h245_centralizedVideo,
		{ "centralizedVideo", "h245.centralizedVideo", FT_BOOLEAN, 8,
		TFS(&tfs_centralizedVideo_bit), 0x01, "The centralizedVideo bit", HFILL }},
	{ &hf_h245_distributedVideo,
		{ "distributedVideo", "h245.distributedVideo", FT_BOOLEAN, 8,
		TFS(&tfs_distributedVideo_bit), 0x01, "The distributedVideo bit", HFILL }},
	{ &hf_h245_temporalSpatialTradeOffCapability,
		{ "temporalSpatialTradeOffCapability", "h245.temporalSpatialTradeOffCapability", FT_BOOLEAN, 8,
		TFS(&tfs_temporalSpatialTradeOffCapability_bit), 0x01, "The temporalSpatialTradeOffCapability bit", HFILL }},
	{ &hf_h245_stillImageTransmission,
		{ "stillImageTransmission", "h245.stillImageTransmission", FT_BOOLEAN, 8,
		TFS(&tfs_stillImageTransmission_bit), 0x01, "The stillImageTransmission bit", HFILL }},
	{ &hf_h245_videoBadMBsCap,
		{ "videoBadMBsCap", "h245.videoBadMBsCap", FT_BOOLEAN, 8,
		TFS(&tfs_videoBadMBsCap_bit), 0x01, "The videoBadMBsCap bit", HFILL }},
	{ &hf_h245_profileAndLevelSPatML,
		{ "profileAndLevelSPatML", "h245.profileAndLevelSPatML", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelSPatML_bit), 0x01, "The profileAndLevelSPatML bit", HFILL }},
	{ &hf_h245_profileAndLevelMPatLL,
		{ "profileAndLevelMPatLL", "h245.profileAndLevelMPatLL", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelMPatLL_bit), 0x01, "The profileAndLevelMPatLL bit", HFILL }},
	{ &hf_h245_profileAndLevelMPatML,
		{ "profileAndLevelMPatML", "h245.profileAndLevelMPatML", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelMPatML_bit), 0x01, "The profileAndLevelMPatML bit", HFILL }},
	{ &hf_h245_profileAndLevelMPatH14,
		{ "profileAndLevelMPatH14", "h245.profileAndLevelMPatH14", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelMPatH14_bit), 0x01, "The profileAndLevelMPatH14 bit", HFILL }},
	{ &hf_h245_profileAndLevelMPatHL,
		{ "profileAndLevelMPatHL", "h245.profileAndLevelMPatHL", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelMPatHL_bit), 0x01, "The profileAndLevelMPatHL bit", HFILL }},
	{ &hf_h245_profileAndLevelSNRatLL,
		{ "profileAndLevelSNRatLL", "h245.profileAndLevelSNRatLL", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelSNRatLL_bit), 0x01, "The profileAndLevelSNRatLL bit", HFILL }},
	{ &hf_h245_profileAndLevelSNRatML,
		{ "profileAndLevelSNRatML", "h245.profileAndLevelSNRatML", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelSNRatML_bit), 0x01, "The profileAndLevelSNRatML bit", HFILL }},
	{ &hf_h245_profileAndLevelSpatialatH14,
		{ "profileAndLevelSpatialatH14", "h245.profileAndLevelSpatialatH14", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelSpatialatH14_bit), 0x01, "The profileAndLevelSpatialatH14 bit", HFILL }},
	{ &hf_h245_profileAndLevelHPatML,
		{ "profileAndLevelHPatML", "h245.profileAndLevelHPatML", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelHPatML_bit), 0x01, "The profileAndLevelHPatML bit", HFILL }},
	{ &hf_h245_profileAndLevelHPatH14,
		{ "profileAndLevelHPatH14", "h245.profileAndLevelHPatH14", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelHPatH14_bit), 0x01, "The profileAndLevelHPatH14 bit", HFILL }},
	{ &hf_h245_profileAndLevelHPatHL,
		{ "profileAndLevelHPatHL", "h245.profileAndLevelHPatHL", FT_BOOLEAN, 8,
		TFS(&tfs_profileAndLevelHPatHL_bit), 0x01, "The profileAndLevelHPatHL bit", HFILL }},
	{ &hf_h245_unrestrictedVector,
		{ "unrestrictedVector", "h245.unrestrictedVector", FT_BOOLEAN, 8,
		TFS(&tfs_unrestrictedVector_bit), 0x01, "The unrestrictedVector bit", HFILL }},
	{ &hf_h245_arithmeticCoding,
		{ "arithmeticCoding", "h245.arithmeticCoding", FT_BOOLEAN, 8,
		TFS(&tfs_arithmeticCoding_bit), 0x01, "The arithmeticCoding bit", HFILL }},
	{ &hf_h245_advancedPrediction,
		{ "advancedPrediction", "h245.advancedPrediction", FT_BOOLEAN, 8,
		TFS(&tfs_advancedPrediction_bit), 0x01, "The advancedPrediction bit", HFILL }},
	{ &hf_h245_pbFrames,
		{ "pbFrames", "h245.pbFrames", FT_BOOLEAN, 8,
		TFS(&tfs_pbFrames_bit), 0x01, "The pbFrames bit", HFILL }},
	{ &hf_h245_errorCompensation,
		{ "errorCompensation", "h245.errorCompensation", FT_BOOLEAN, 8,
		TFS(&tfs_errorCompensation_bit), 0x01, "The errorCompensation bit", HFILL }},
	{ &hf_h245_baseBitRateConstrained,
		{ "baseBitRateConstrained", "h245.baseBitRateConstrained", FT_BOOLEAN, 8,
		TFS(&tfs_baseBitRateConstrained_bit), 0x01, "The baseBitRateConstrained bit", HFILL }},
	{ &hf_h245_advancedIntraCodingMode,
		{ "advancedIntraCodingMode", "h245.advancedIntraCodingMode", FT_BOOLEAN, 8,
		TFS(&tfs_advancedIntraCodingMode_bit), 0x01, "The advancedIntraCodingMode bit", HFILL }},
	{ &hf_h245_deblockingFilterMode,
		{ "deblockingFilterMode", "h245.deblockingFilterMode", FT_BOOLEAN, 8,
		TFS(&tfs_deblockingFilterMode_bit), 0x01, "The deblockingFilterMode bit", HFILL }},
	{ &hf_h245_improvedPBFramesMode,
		{ "improvedPBFramesMode", "h245.improvedPBFramesMode", FT_BOOLEAN, 8,
		TFS(&tfs_improvedPBFramesMode_bit), 0x01, "The improvedPBFramesMode bit", HFILL }},
	{ &hf_h245_unlimitedMotionVectors,
		{ "unlimitedMotionVectors", "h245.unlimitedMotionVectors", FT_BOOLEAN, 8,
		TFS(&tfs_unlimitedMotionVectors_bit), 0x01, "The unlimitedMotionVectors bit", HFILL }},
	{ &hf_h245_fullPictureFreeze,
		{ "fullPictureFreeze", "h245.fullPictureFreeze", FT_BOOLEAN, 8,
		TFS(&tfs_fullPictureFreeze_bit), 0x01, "The fullPictureFreeze bit", HFILL }},
	{ &hf_h245_partialPictureFreezeAndRelease,
		{ "partialPictureFreezeAndRelease", "h245.partialPictureFreezeAndRelease", FT_BOOLEAN, 8,
		TFS(&tfs_partialPictureFreezeAndRelease_bit), 0x01, "The partialPictureFreezeAndRelease bit", HFILL }},
	{ &hf_h245_resizingPartPicFreezeAndRelease,
		{ "resizingPartPicFreezeAndRelease", "h245.resizingPartPicFreezeAndRelease", FT_BOOLEAN, 8,
		TFS(&tfs_resizingPartPicFreezeAndRelease_bit), 0x01, "The resizingPartPicFreezeAndRelease bit", HFILL }},
	{ &hf_h245_fullPictureSnapshot,
		{ "fullPictureSnapshot", "h245.fullPictureSnapshot", FT_BOOLEAN, 8,
		TFS(&tfs_fullPictureSnapshot_bit), 0x01, "The fullPictureSnapshot bit", HFILL }},
	{ &hf_h245_partialPictureSnapshot,
		{ "partialPictureSnapshot", "h245.partialPictureSnapshot", FT_BOOLEAN, 8,
		TFS(&tfs_partialPictureSnapshot_bit), 0x01, "The partialPictureSnapshot bit", HFILL }},
	{ &hf_h245_videoSegmentTagging,
		{ "videoSegmentTagging", "h245.videoSegmentTagging", FT_BOOLEAN, 8,
		TFS(&tfs_videoSegmentTagging_bit), 0x01, "The videoSegmentTagging bit", HFILL }},
	{ &hf_h245_progressiveRefinement,
		{ "progressiveRefinement", "h245.progressiveRefinement", FT_BOOLEAN, 8,
		TFS(&tfs_progressiveRefinement_bit), 0x01, "The progressiveRefinement bit", HFILL }},
	{ &hf_h245_dynamicPictureResizingByFour,
		{ "dynamicPictureResizingByFour", "h245.dynamicPictureResizingByFour", FT_BOOLEAN, 8,
		TFS(&tfs_dynamicPictureResizingByFour_bit), 0x01, "The dynamicPictureResizingByFour bit", HFILL }},
	{ &hf_h245_dynamicPictureResizingSixteenthPel,
		{ "dynamicPictureResizingSixteenthPel", "h245.dynamicPictureResizingSixteenthPel", FT_BOOLEAN, 8,
		TFS(&tfs_dynamicPictureResizingSixteenthPel_bit), 0x01, "The dynamicPictureResizingSixteenthPel bit", HFILL }},
	{ &hf_h245_dynamicWarpingHalfPel,
		{ "dynamicWarpingHalfPel", "h245.dynamicWarpingHalfPel", FT_BOOLEAN, 8,
		TFS(&tfs_dynamicWarpingHalfPel_bit), 0x01, "The dynamicWarpingHalfPel bit", HFILL }},
	{ &hf_h245_dynamicWarpingSixteenthPel,
		{ "dynamicWarpingSixteenthPel", "h245.dynamicWarpingSixteenthPel", FT_BOOLEAN, 8,
		TFS(&tfs_dynamicWarpingSixteenthPel_bit), 0x01, "The dynamicWarpingSixteenthPel bit", HFILL }},
	{ &hf_h245_independentSegmentDecoding,
		{ "independentSegmentDecoding", "h245.independentSegmentDecoding", FT_BOOLEAN, 8,
		TFS(&tfs_independentSegmentDecoding_bit), 0x01, "The independentSegmentDecoding bit", HFILL }},
	{ &hf_h245_slicesInOrderNonRect,
		{ "slicesInOrderNonRect", "h245.slicesInOrderNonRect", FT_BOOLEAN, 8,
		TFS(&tfs_slicesInOrderNonRect_bit), 0x01, "The slicesInOrderNonRect bit", HFILL }},
	{ &hf_h245_slicesInOrderRect,
		{ "slicesInOrderRect", "h245.slicesInOrderRect", FT_BOOLEAN, 8,
		TFS(&tfs_slicesInOrderRect_bit), 0x01, "The slicesInOrderRect bit", HFILL }},
	{ &hf_h245_slicesNoOrderNonRect,
		{ "slicesNoOrderNonRect", "h245.slicesNoOrderNonRect", FT_BOOLEAN, 8,
		TFS(&tfs_slicesNoOrderNonRect_bit), 0x01, "The slicesNoOrderNonRect bit", HFILL }},
	{ &hf_h245_slicesNoOrderRect,
		{ "slicesNoOrderRect", "h245.slicesNoOrderRect", FT_BOOLEAN, 8,
		TFS(&tfs_slicesNoOrderRect_bit), 0x01, "The slicesNoOrderRect bit", HFILL }},
	{ &hf_h245_alternateInterVLCMode,
		{ "alternateInterVLCMode", "h245.alternateInterVLCMode", FT_BOOLEAN, 8,
		TFS(&tfs_alternateInterVLCMode_bit), 0x01, "The alternateInterVLCMode bit", HFILL }},
	{ &hf_h245_modifiedQuantizationMode,
		{ "modifiedQuantizationMode", "h245.modifiedQuantizationMode", FT_BOOLEAN, 8,
		TFS(&tfs_modifiedQuantizationMode_bit), 0x01, "The modifiedQuantizationMode bit", HFILL }},
	{ &hf_h245_reducedResolutionUpdate,
		{ "reducedResolutionUpdate", "h245.reducedResolutionUpdate", FT_BOOLEAN, 8,
		TFS(&tfs_reducedResolutionUpdate_bit), 0x01, "The reducedResolutionUpdate bit", HFILL }},
	{ &hf_h245_separateVideoBackChannel,
		{ "separateVideoBackChannel", "h245.separateVideoBackChannel", FT_BOOLEAN, 8,
		TFS(&tfs_separateVideoBackChannel_bit), 0x01, "The separateVideoBackChannel bit", HFILL }},
	{ &hf_h245_videoMux,
		{ "videoMux", "h245.videoMux", FT_BOOLEAN, 8,
		TFS(&tfs_videoMux_bit), 0x01, "The videoMux bit", HFILL }},
	{ &hf_h245_anyPixelAspectRatio,
		{ "anyPixelAspectRatio", "h245.anyPixelAspectRatio", FT_BOOLEAN, 8,
		TFS(&tfs_anyPixelAspectRatio_bit), 0x01, "The anyPixelAspectRatio bit", HFILL }},
	{ &hf_h245_referencePicSelect,
		{ "referencePicSelect", "h245.referencePicSelect", FT_BOOLEAN, 8,
		TFS(&tfs_referencePicSelect_bit), 0x01, "The referencePicSelect bit", HFILL }},
	{ &hf_h245_enhancedReferencePicSelect_bool,
		{ "enhancedReferencePicSelect_bool", "h245.enhancedReferencePicSelect_bool", FT_BOOLEAN, 8,
		TFS(&tfs_enhancedReferencePicSelect_bool_bit), 0x01, "The enhancedReferencePicSelect_bool bit", HFILL }},
	{ &hf_h245_dataPartitionedSlices,
		{ "dataPartitionedSlices", "h245.dataPartitionedSlices", FT_BOOLEAN, 8,
		TFS(&tfs_dataPartitionedSlices_bit), 0x01, "The dataPartitionedSlices bit", HFILL }},
	{ &hf_h245_fixedPointIDCT0,
		{ "fixedPointIDCT0", "h245.fixedPointIDCT0", FT_BOOLEAN, 8,
		TFS(&tfs_fixedPointIDCT0_bit), 0x01, "The fixedPointIDCT0 bit", HFILL }},
	{ &hf_h245_interlacedFields,
		{ "interlacedFields", "h245.interlacedFields", FT_BOOLEAN, 8,
		TFS(&tfs_interlacedFields_bit), 0x01, "The interlacedFields bit", HFILL }},
	{ &hf_h245_currentPictureHeaderRepetition,
		{ "currentPictureHeaderRepetition", "h245.currentPictureHeaderRepetition", FT_BOOLEAN, 8,
		TFS(&tfs_currentPictureHeaderRepetition_bit), 0x01, "The currentPictureHeaderRepetition bit", HFILL }},
	{ &hf_h245_previousPictureHeaderRepetition,
		{ "previousPictureHeaderRepetition", "h245.previousPictureHeaderRepetition", FT_BOOLEAN, 8,
		TFS(&tfs_previousPictureHeaderRepetition_bit), 0x01, "The previousPictureHeaderRepetition bit", HFILL }},
	{ &hf_h245_nextPictureHeaderRepetition,
		{ "nextPictureHeaderRepetition", "h245.nextPictureHeaderRepetition", FT_BOOLEAN, 8,
		TFS(&tfs_nextPictureHeaderRepetition_bit), 0x01, "The nextPictureHeaderRepetition bit", HFILL }},
	{ &hf_h245_pictureNumber_bool,
		{ "pictureNumber_bool", "h245.pictureNumber_bool", FT_BOOLEAN, 8,
		TFS(&tfs_pictureNumber_bool_bit), 0x01, "The pictureNumber_bool bit", HFILL }},
	{ &hf_h245_spareReferencePictures,
		{ "spareReferencePictures", "h245.spareReferencePictures", FT_BOOLEAN, 8,
		TFS(&tfs_spareReferencePictures_bit), 0x01, "The spareReferencePictures bit", HFILL }},
	{ &hf_h245_constrainedBitstream,
		{ "constrainedBitstream", "h245.constrainedBitstream", FT_BOOLEAN, 8,
		TFS(&tfs_constrainedBitstream_bit), 0x01, "The constrainedBitstream bit", HFILL }},
	{ &hf_h245_silenceSuppression,
		{ "silenceSuppression", "h245.silenceSuppression", FT_BOOLEAN, 8,
		TFS(&tfs_silenceSuppression_bit), 0x01, "The silenceSuppression bit", HFILL }},
	{ &hf_h245_annexA,
		{ "annexA", "h245.annexA", FT_BOOLEAN, 8,
		TFS(&tfs_annexA_bit), 0x01, "The annexA bit", HFILL }},
	{ &hf_h245_annexB,
		{ "annexB", "h245.annexB", FT_BOOLEAN, 8,
		TFS(&tfs_annexB_bit), 0x01, "The annexB bit", HFILL }},
	{ &hf_h245_annexD,
		{ "annexD", "h245.annexD", FT_BOOLEAN, 8,
		TFS(&tfs_annexD_bit), 0x01, "The annexD bit", HFILL }},
	{ &hf_h245_annexE,
		{ "annexE", "h245.annexE", FT_BOOLEAN, 8,
		TFS(&tfs_annexE_bit), 0x01, "The annexE bit", HFILL }},
	{ &hf_h245_annexF,
		{ "annexF", "h245.annexF", FT_BOOLEAN, 8,
		TFS(&tfs_annexF_bit), 0x01, "The annexF bit", HFILL }},
	{ &hf_h245_annexG,
		{ "annexG", "h245.annexG", FT_BOOLEAN, 8,
		TFS(&tfs_annexG_bit), 0x01, "The annexG bit", HFILL }},
	{ &hf_h245_annexH,
		{ "annexH", "h245.annexH", FT_BOOLEAN, 8,
		TFS(&tfs_annexH_bit), 0x01, "The annexH bit", HFILL }},
	{ &hf_h245_audioLayer1,
		{ "audioLayer1", "h245.audioLayer1", FT_BOOLEAN, 8,
		TFS(&tfs_audioLayer1_bit), 0x01, "The audioLayer1 bit", HFILL }},
	{ &hf_h245_audioLayer2,
		{ "audioLayer2", "h245.audioLayer2", FT_BOOLEAN, 8,
		TFS(&tfs_audioLayer2_bit), 0x01, "The audioLayer2 bit", HFILL }},
	{ &hf_h245_audioLayer3,
		{ "audioLayer3", "h245.audioLayer3", FT_BOOLEAN, 8,
		TFS(&tfs_audioLayer3_bit), 0x01, "The audioLayer3 bit", HFILL }},
	{ &hf_h245_audioSampling32k,
		{ "audioSampling32k", "h245.audioSampling32k", FT_BOOLEAN, 8,
		TFS(&tfs_audioSampling32k_bit), 0x01, "The audioSampling32k bit", HFILL }},
	{ &hf_h245_audioSampling44k1,
		{ "audioSampling44k1", "h245.audioSampling44k1", FT_BOOLEAN, 8,
		TFS(&tfs_audioSampling44k1_bit), 0x01, "The audioSampling44k1 bit", HFILL }},
	{ &hf_h245_audioSampling48k,
		{ "audioSampling48k", "h245.audioSampling48k", FT_BOOLEAN, 8,
		TFS(&tfs_audioSampling48k_bit), 0x01, "The audioSampling48k bit", HFILL }},
	{ &hf_h245_singleChannel,
		{ "singleChannel", "h245.singleChannel", FT_BOOLEAN, 8,
		TFS(&tfs_singleChannel_bit), 0x01, "The singleChannel bit", HFILL }},
	{ &hf_h245_twoChannels,
		{ "twoChannels", "h245.twoChannels", FT_BOOLEAN, 8,
		TFS(&tfs_twoChannels_bit), 0x01, "The twoChannels bit", HFILL }},
	{ &hf_h245_audioSampling16k,
		{ "audioSampling16k", "h245.audioSampling16k", FT_BOOLEAN, 8,
		TFS(&tfs_audioSampling16k_bit), 0x01, "The audioSampling16k bit", HFILL }},
	{ &hf_h245_audioSampling22k05,
		{ "audioSampling22k05", "h245.audioSampling22k05", FT_BOOLEAN, 8,
		TFS(&tfs_audioSampling22k05_bit), 0x01, "The audioSampling22k05 bit", HFILL }},
	{ &hf_h245_audioSampling24k,
		{ "audioSampling24k", "h245.audioSampling24k", FT_BOOLEAN, 8,
		TFS(&tfs_audioSampling24k_bit), 0x01, "The audioSampling24k bit", HFILL }},
	{ &hf_h245_threeChannels21,
		{ "threeChannels21", "h245.threeChannels21", FT_BOOLEAN, 8,
		TFS(&tfs_threeChannels21_bit), 0x01, "The threeChannels21 bit", HFILL }},
	{ &hf_h245_threeChannels30,
		{ "threeChannels30", "h245.threeChannels30", FT_BOOLEAN, 8,
		TFS(&tfs_threeChannels30_bit), 0x01, "The threeChannels30 bit", HFILL }},
	{ &hf_h245_fourChannels2020,
		{ "fourChannels2020", "h245.fourChannels2020", FT_BOOLEAN, 8,
		TFS(&tfs_fourChannels2020_bit), 0x01, "The fourChannels2020 bit", HFILL }},
	{ &hf_h245_fourChannels22,
		{ "fourChannels22", "h245.fourChannels22", FT_BOOLEAN, 8,
		TFS(&tfs_fourChannels22_bit), 0x01, "The fourChannels22 bit", HFILL }},
	{ &hf_h245_fourChannels31,
		{ "fourChannels31", "h245.fourChannels31", FT_BOOLEAN, 8,
		TFS(&tfs_fourChannels31_bit), 0x01, "The fourChannels31 bit", HFILL }},
	{ &hf_h245_fiveChannels3020,
		{ "fiveChannels3020", "h245.fiveChannels3020", FT_BOOLEAN, 8,
		TFS(&tfs_fiveChannels3020_bit), 0x01, "The fiveChannels3020 bit", HFILL }},
	{ &hf_h245_fiveChannels32,
		{ "fiveChannels32", "h245.fiveChannels32", FT_BOOLEAN, 8,
		TFS(&tfs_fiveChannels32_bit), 0x01, "The fiveChannels32 bit", HFILL }},
	{ &hf_h245_lowFrequencyEnhancement,
		{ "lowFrequencyEnhancement", "h245.lowFrequencyEnhancement", FT_BOOLEAN, 8,
		TFS(&tfs_lowFrequencyEnhancement_bit), 0x01, "The lowFrequencyEnhancement bit", HFILL }},
	{ &hf_h245_multilingual,
		{ "multilingual", "h245.multilingual", FT_BOOLEAN, 8,
		TFS(&tfs_multilingual_bit), 0x01, "The multilingual bit", HFILL }},
	{ &hf_h245_comfortNoise,
		{ "comfortNoise", "h245.comfortNoise", FT_BOOLEAN, 8,
		TFS(&tfs_comfortNoise_bit), 0x01, "The comfortNoise bit", HFILL }},
	{ &hf_h245_scrambled,
		{ "scrambled", "h245.scrambled", FT_BOOLEAN, 8,
		TFS(&tfs_scrambled_bit), 0x01, "The scrambled bit", HFILL }},
	{ &hf_h245_qcif_bool,
		{ "qcif_bool", "h245.qcif_bool", FT_BOOLEAN, 8,
		TFS(&tfs_qcif_bool_bit), 0x01, "The qcif_bool bit", HFILL }},
	{ &hf_h245_cif_bool,
		{ "cif_bool", "h245.cif_bool", FT_BOOLEAN, 8,
		TFS(&tfs_cif_bool_bit), 0x01, "The cif_bool bit", HFILL }},
	{ &hf_h245_ccir601Seq,
		{ "ccir601Seq", "h245.ccir601Seq", FT_BOOLEAN, 8,
		TFS(&tfs_ccir601Seq_bit), 0x01, "The ccir601Seq bit", HFILL }},
	{ &hf_h245_ccir601Prog,
		{ "ccir601Prog", "h245.ccir601Prog", FT_BOOLEAN, 8,
		TFS(&tfs_ccir601Prog_bit), 0x01, "The ccir601Prog bit", HFILL }},
	{ &hf_h245_hdtvSeq,
		{ "hdtvSeq", "h245.hdtvSeq", FT_BOOLEAN, 8,
		TFS(&tfs_hdtvSeq_bit), 0x01, "The hdtvSeq bit", HFILL }},
	{ &hf_h245_hdtvProg,
		{ "hdtvProg", "h245.hdtvProg", FT_BOOLEAN, 8,
		TFS(&tfs_hdtvProg_bit), 0x01, "The hdtvProg bit", HFILL }},
	{ &hf_h245_g3FacsMH200x100,
		{ "g3FacsMH200x100", "h245.g3FacsMH200x100", FT_BOOLEAN, 8,
		TFS(&tfs_g3FacsMH200x100_bit), 0x01, "The g3FacsMH200x100 bit", HFILL }},
	{ &hf_h245_g3FacsMH200x200,
		{ "g3FacsMH200x200", "h245.g3FacsMH200x200", FT_BOOLEAN, 8,
		TFS(&tfs_g3FacsMH200x200_bit), 0x01, "The g3FacsMH200x200 bit", HFILL }},
	{ &hf_h245_g4FacsMMR200x100,
		{ "g4FacsMMR200x100", "h245.g4FacsMMR200x100", FT_BOOLEAN, 8,
		TFS(&tfs_g4FacsMMR200x100_bit), 0x01, "The g4FacsMMR200x100 bit", HFILL }},
	{ &hf_h245_g4FacsMMR200x200,
		{ "g4FacsMMR200x200", "h245.g4FacsMMR200x200", FT_BOOLEAN, 8,
		TFS(&tfs_g4FacsMMR200x200_bit), 0x01, "The g4FacsMMR200x200 bit", HFILL }},
	{ &hf_h245_jbig200x200Seq,
		{ "jbig200x200Seq", "h245.jbig200x200Seq", FT_BOOLEAN, 8,
		TFS(&tfs_jbig200x200Seq_bit), 0x01, "The jbig200x200Seq bit", HFILL }},
	{ &hf_h245_jbig200x200Prog,
		{ "jbig200x200Prog", "h245.jbig200x200Prog", FT_BOOLEAN, 8,
		TFS(&tfs_jbig200x200Prog_bit), 0x01, "The jbig200x200Prog bit", HFILL }},
	{ &hf_h245_jbig300x300Seq,
		{ "jbig300x300Seq", "h245.jbig300x300Seq", FT_BOOLEAN, 8,
		TFS(&tfs_jbig300x300Seq_bit), 0x01, "The jbig300x300Seq bit", HFILL }},
	{ &hf_h245_jbig300x300Prog,
		{ "jbig300x300Prog", "h245.jbig300x300Prog", FT_BOOLEAN, 8,
		TFS(&tfs_jbig300x300Prog_bit), 0x01, "The jbig300x300Prog bit", HFILL }},
	{ &hf_h245_digPhotoLow,
		{ "digPhotoLow", "h245.digPhotoLow", FT_BOOLEAN, 8,
		TFS(&tfs_digPhotoLow_bit), 0x01, "The digPhotoLow bit", HFILL }},
	{ &hf_h245_digPhotoMedSeq,
		{ "digPhotoMedSeq", "h245.digPhotoMedSeq", FT_BOOLEAN, 8,
		TFS(&tfs_digPhotoMedSeq_bit), 0x01, "The digPhotoMedSeq bit", HFILL }},
	{ &hf_h245_digPhotoMedProg,
		{ "digPhotoMedProg", "h245.digPhotoMedProg", FT_BOOLEAN, 8,
		TFS(&tfs_digPhotoMedProg_bit), 0x01, "The digPhotoMedProg bit", HFILL }},
	{ &hf_h245_digPhotoHighSeq,
		{ "digPhotoHighSeq", "h245.digPhotoHighSeq", FT_BOOLEAN, 8,
		TFS(&tfs_digPhotoHighSeq_bit), 0x01, "The digPhotoHighSeq bit", HFILL }},
	{ &hf_h245_digPhotoHighProg,
		{ "digPhotoHighProg", "h245.digPhotoHighProg", FT_BOOLEAN, 8,
		TFS(&tfs_digPhotoHighProg_bit), 0x01, "The digPhotoHighProg bit", HFILL }},
	{ &hf_h245_fillBitRemoval,
		{ "fillBitRemoval", "h245.fillBitRemoval", FT_BOOLEAN, 8,
		TFS(&tfs_fillBitRemoval_bit), 0x01, "The fillBitRemoval bit", HFILL }},
	{ &hf_h245_transcodingJBIG,
		{ "transcodingJBIG", "h245.transcodingJBIG", FT_BOOLEAN, 8,
		TFS(&tfs_transcodingJBIG_bit), 0x01, "The transcodingJBIG bit", HFILL }},
	{ &hf_h245_transcodingMMR,
		{ "transcodingMMR", "h245.transcodingMMR", FT_BOOLEAN, 8,
		TFS(&tfs_transcodingMMR_bit), 0x01, "The transcodingMMR bit", HFILL }},
	{ &hf_h245_t38TCPBidirectionalMode,
		{ "t38TCPBidirectionalMode", "h245.t38TCPBidirectionalMode", FT_BOOLEAN, 8,
		TFS(&tfs_t38TCPBidirectionalMode_bit), 0x01, "The t38TCPBidirectionalMode bit", HFILL }},
	{ &hf_h245_chairControlCapability,
		{ "chairControlCapability", "h245.chairControlCapability", FT_BOOLEAN, 8,
		TFS(&tfs_chairControlCapability_bit), 0x01, "The chairControlCapability bit", HFILL }},
	{ &hf_h245_videoIndicateMixingCapability,
		{ "videoIndicateMixingCapability", "h245.videoIndicateMixingCapability", FT_BOOLEAN, 8,
		TFS(&tfs_videoIndicateMixingCapability_bit), 0x01, "The videoIndicateMixingCapability bit", HFILL }},
	{ &hf_h245_multipointVisualizationCapability,
		{ "multipointVisualizationCapability", "h245.multipointVisualizationCapability", FT_BOOLEAN, 8,
		TFS(&tfs_multipointVisualizationCapability_bit), 0x01, "The multipointVisualizationCapability bit", HFILL }},
	{ &hf_h245_controlOnMuxStream,
		{ "controlOnMuxStream", "h245.controlOnMuxStream", FT_BOOLEAN, 8,
		TFS(&tfs_controlOnMuxStream_bit), 0x01, "The controlOnMuxStream bit", HFILL }},
	{ &hf_h245_redundancyEncoding_bool,
		{ "redundancyEncoding_bool", "h245.redundancyEncoding_bool", FT_BOOLEAN, 8,
		TFS(&tfs_redundancyEncoding_bool_bit), 0x01, "The redundancyEncoding_bool bit", HFILL }},
	{ &hf_h245_separatePort,
		{ "separatePort", "h245.separatePort", FT_BOOLEAN, 8,
		TFS(&tfs_separatePort_bit), 0x01, "The separatePort bit", HFILL }},
	{ &hf_h245_samePort_bool,
		{ "samePort_bool", "h245.samePort_bool", FT_BOOLEAN, 8,
		TFS(&tfs_samePort_bool_bit), 0x01, "The samePort_bool bit", HFILL }},
	{ &hf_h245_associateConference,
		{ "associateConference", "h245.associateConference", FT_BOOLEAN, 8,
		TFS(&tfs_associateConference_bit), 0x01, "The associateConference bit", HFILL }},
	{ &hf_h245_audioHeaderPresent,
		{ "audioHeaderPresent", "h245.audioHeaderPresent", FT_BOOLEAN, 8,
		TFS(&tfs_audioHeaderPresent_bit), 0x01, "The audioHeaderPresent bit", HFILL }},
	{ &hf_h245_segmentableFlag,
		{ "segmentableFlag", "h245.segmentableFlag", FT_BOOLEAN, 8,
		TFS(&tfs_segmentableFlag_bit), 0x01, "The segmentableFlag bit", HFILL }},
	{ &hf_h245_alsduSplitting,
		{ "alsduSplitting", "h245.alsduSplitting", FT_BOOLEAN, 8,
		TFS(&tfs_alsduSplitting_bit), 0x01, "The alsduSplitting bit", HFILL }},
	{ &hf_h245_uIH,
		{ "uIH", "h245.uIH", FT_BOOLEAN, 8,
		TFS(&tfs_uIH_bit), 0x01, "The uIH bit", HFILL }},
	{ &hf_h245_loopbackTestProcedure,
		{ "loopbackTestProcedure", "h245.loopbackTestProcedure", FT_BOOLEAN, 8,
		TFS(&tfs_loopbackTestProcedure_bit), 0x01, "The loopbackTestProcedure bit", HFILL }},
	{ &hf_h245_mediaGuaranteedDelivery,
		{ "mediaGuaranteedDelivery", "h245.mediaGuaranteedDelivery", FT_BOOLEAN, 8,
		TFS(&tfs_mediaGuaranteedDelivery_bit), 0x01, "The mediaGuaranteedDelivery bit", HFILL }},
	{ &hf_h245_mediaControlGuaranteedDelivery,
		{ "mediaControlGuaranteedDelivery", "h245.mediaControlGuaranteedDelivery", FT_BOOLEAN, 8,
		TFS(&tfs_mediaControlGuaranteedDelivery_bit), 0x01, "The mediaControlGuaranteedDelivery bit", HFILL }},
	{ &hf_h245_flowControlToZero,
		{ "flowControlToZero", "h245.flowControlToZero", FT_BOOLEAN, 8,
		TFS(&tfs_flowControlToZero_bit), 0x01, "The flowControlToZero bit", HFILL }},
	{ &hf_h245_multiplexCapability_bool,
		{ "multiplexCapability_bool", "h245.multiplexCapability_bool", FT_BOOLEAN, 8,
		TFS(&tfs_multiplexCapability_bool_bit), 0x01, "The multiplexCapability_bool bit", HFILL }},
	{ &hf_h245_secureChannel,
		{ "secureChannel", "h245.secureChannel", FT_BOOLEAN, 8,
		TFS(&tfs_secureChannel_bit), 0x01, "The secureChannel bit", HFILL }},
	{ &hf_h245_sharedSecret,
		{ "sharedSecret", "h245.sharedSecret", FT_BOOLEAN, 8,
		TFS(&tfs_sharedSecret_bit), 0x01, "The sharedSecret bit", HFILL }},
	{ &hf_h245_certProtectedKey,
		{ "certProtectedKey", "h245.certProtectedKey", FT_BOOLEAN, 8,
		TFS(&tfs_certProtectedKey_bit), 0x01, "The certProtectedKey bit", HFILL }},
	{ &hf_h245_bitRateLockedToPCRClock,
		{ "bitRateLockedToPCRClock", "h245.bitRateLockedToPCRClock", FT_BOOLEAN, 8,
		TFS(&tfs_bitRateLockedToPCRClock_bit), 0x01, "The bitRateLockedToPCRClock bit", HFILL }},
	{ &hf_h245_bitRateLockedToNetworkClock,
		{ "bitRateLockedToNetworkClock", "h245.bitRateLockedToNetworkClock", FT_BOOLEAN, 8,
		TFS(&tfs_bitRateLockedToNetworkClock_bit), 0x01, "The bitRateLockedToNetworkClock bit", HFILL }},
	{ &hf_h245_IS11172_BitRate,
		{ "BitRate", "h245.IS11172_BitRate", FT_UINT32, BASE_DEC,
		NULL, 0, "IS11172 BitRate in kbit/s", HFILL }},
	{ &hf_h245_IS13818_BitRate,
		{ "BitRate", "h245.IS13818_BitRate", FT_UINT32, BASE_DEC,
		NULL, 0, "IS13818 BitRate in kbit/s", HFILL }},
	{ &hf_h245_ATM_BitRate,
		{ "BitRate", "h245.ATM_BitRate", FT_UINT32, BASE_DEC,
		NULL, 0, "ATM BitRate in 64kbit/s units", HFILL }},
	{ &hf_h245_t35CountryCode,
		{ "t35CountryCode", "h245.t35CountryCode", FT_UINT32, BASE_DEC,
		VALS(T35CountryCode_vals), 0, "t35CountryCode value", HFILL }},
	{ &hf_h245_t35Extension,
		{ "t35Extension", "h245.t35Extension", FT_UINT32, BASE_DEC,
		NULL, 0, "t35Extension value", HFILL }},
	{ &hf_h245_manufacturerCode,
		{ "manufacturerCode", "h245.manufacturerCode", FT_UINT32, BASE_DEC,
		NULL, 0, "manufacturerCode value", HFILL }},
	{ &hf_h245_terminalType,
		{ "terminalType", "h245.terminalType", FT_UINT32, BASE_DEC,
		NULL, 0, "terminalType value", HFILL }},
	{ &hf_h245_statusDeterminationNumber,
		{ "statusDeterminationNumber", "h245.statusDeterminationNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "statusDeterminationNumber value", HFILL }},
	{ &hf_h245_CapabilityTableEntryNumber,
		{ "CapabilityTableEntryNumber", "h245.CapabilityTableEntryNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "CapabilityTableEntryNumber value", HFILL }},
	{ &hf_h245_CapabilityDescriptorNumber,
		{ "CapabilityDescriptorNumber", "h245.CapabilityDescriptorNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "CapabilityDescriptorNumber value", HFILL }},
	{ &hf_h245_h233IVResponseTime,
		{ "h233IVResponseTime", "h245.h233IVResponseTime", FT_UINT32, BASE_DEC,
		NULL, 0, "h233IVResponseTime value", HFILL }},
	{ &hf_h245_maxPendingReplacementFor,
		{ "maxPendingReplacementFor", "h245.maxPendingReplacementFor", FT_UINT32, BASE_DEC,
		NULL, 0, "maxPendingReplacementFor value", HFILL }},
	{ &hf_h245_numberOfVCs,
		{ "numberOfVCs", "h245.numberOfVCs", FT_UINT32, BASE_DEC,
		NULL, 0, "numberOfVCs value", HFILL }},
	{ &hf_h245_forwardMaximumSDUSize,
		{ "forwardMaximumSDUSize", "h245.forwardMaximumSDUSize", FT_UINT32, BASE_DEC,
		NULL, 0, "forwardMaximumSDUSize value", HFILL }},
	{ &hf_h245_backwardMaximumSDUSize,
		{ "backwardMaximumSDUSize", "h245.backwardMaximumSDUSize", FT_UINT32, BASE_DEC,
		NULL, 0, "backwardMaximumSDUSize value", HFILL }},
	{ &hf_h245_singleBitRate,
		{ "singleBitRate", "h245.singleBitRate", FT_UINT32, BASE_DEC,
		NULL, 0, "singleBitRate value", HFILL }},
	{ &hf_h245_lowerBitRate,
		{ "lowerBitRate", "h245.lowerBitRate", FT_UINT32, BASE_DEC,
		NULL, 0, "lowerBitRate value", HFILL }},
	{ &hf_h245_higherBitRate,
		{ "higherBitRate", "h245.higherBitRate", FT_UINT32, BASE_DEC,
		NULL, 0, "higherBitRate value", HFILL }},
	{ &hf_h245_maximumAl2SDUSize,
		{ "maximumAl2SDUSize", "h245.maximumAl2SDUSize", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumAl2SDUSize value", HFILL }},
	{ &hf_h245_maximumAl3SDUSize,
		{ "maximumAl3SDUSize", "h245.maximumAl3SDUSize", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumAl3SDUSize value", HFILL }},
	{ &hf_h245_maximumDelayJitter,
		{ "maximumDelayJitter", "h245.maximumDelayJitter", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumDelayJitter value", HFILL }},
	{ &hf_h245_maximumNestingDepth,
		{ "maximumNestingDepth", "h245.maximumNestingDepth", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumNestingDepth value", HFILL }},
	{ &hf_h245_maximumElementListSize,
		{ "maximumElementListSize", "h245.maximumElementListSize", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumElementListSize value", HFILL }},
	{ &hf_h245_maximumSubElementListSize,
		{ "maximumSubElementListSize", "h245.maximumSubElementListSize", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumSubElementListSize value", HFILL }},
	{ &hf_h245_h223bitRate,
		{ "h223bitRate", "h245.h223bitRate", FT_UINT32, BASE_DEC,
		NULL, 0, "h223bitRate value", HFILL }},
	{ &hf_h245_maximumSampleSize,
		{ "maximumSampleSize", "h245.maximumSampleSize", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumSampleSize value", HFILL }},
	{ &hf_h245_maximumPayloadLength,
		{ "maximumPayloadLength", "h245.maximumPayloadLength", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumPayloadLength value", HFILL }},
	{ &hf_h245_maximumAL1MPDUSize,
		{ "maximumAL1MPDUSize", "h245.maximumAL1MPDUSize", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumAL1MPDUSize value", HFILL }},
	{ &hf_h245_maximumAL2MSDUSize,
		{ "maximumAL2MSDUSize", "h245.maximumAL2MSDUSize", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumAL2MSDUSize value", HFILL }},
	{ &hf_h245_maximumAL3MSDUSize,
		{ "maximumAL3MSDUSize", "h245.maximumAL3MSDUSize", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumAL3MSDUSize value", HFILL }},
	{ &hf_h245_numOfDLCS,
		{ "numOfDLCS", "h245.numOfDLCS", FT_UINT32, BASE_DEC,
		NULL, 0, "numOfDLCS value", HFILL }},
	{ &hf_h245_n401Capability,
		{ "n401Capability", "h245.n401Capability", FT_UINT32, BASE_DEC,
		NULL, 0, "n401Capability value", HFILL }},
	{ &hf_h245_maxWindowSizeCapability,
		{ "maxWindowSizeCapability", "h245.maxWindowSizeCapability", FT_UINT32, BASE_DEC,
		NULL, 0, "maxWindowSizeCapability value", HFILL }},
	{ &hf_h245_maximumAudioDelayJitter,
		{ "maximumAudioDelayJitter", "h245.maximumAudioDelayJitter", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumAudioDelayJitter value", HFILL }},
	{ &hf_h245_tokenRate,
		{ "tokenRate", "h245.tokenRate", FT_UINT32, BASE_DEC,
		NULL, 0, "tokenRate value", HFILL }},
	{ &hf_h245_bucketSize,
		{ "bucketSize", "h245.bucketSize", FT_UINT32, BASE_DEC,
		NULL, 0, "bucketSize value", HFILL }},
	{ &hf_h245_peakRate,
		{ "peakRate", "h245.peakRate", FT_UINT32, BASE_DEC,
		NULL, 0, "peakRate value", HFILL }},
	{ &hf_h245_minPoliced,
		{ "minPoliced", "h245.minPoliced", FT_UINT32, BASE_DEC,
		NULL, 0, "minPoliced value", HFILL }},
	{ &hf_h245_maxPktSize,
		{ "maxPktSize", "h245.maxPktSize", FT_UINT32, BASE_DEC,
		NULL, 0, "maxPktSize value", HFILL }},
	{ &hf_h245_maxNTUSize,
		{ "maxNTUSize", "h245.maxNTUSize", FT_UINT32, BASE_DEC,
		NULL, 0, "maxNTUSize value", HFILL }},
	{ &hf_h245_numberOfThreads,
		{ "numberOfThreads", "h245.numberOfThreads", FT_UINT32, BASE_DEC,
		NULL, 0, "numberOfThreads value", HFILL }},
	{ &hf_h245_framesBetweenSyncPoints,
		{ "framesBetweenSyncPoints", "h245.framesBetweenSyncPoints", FT_UINT32, BASE_DEC,
		NULL, 0, "framesBetweenSyncPoints value", HFILL }},
	{ &hf_h245_threadNumber,
		{ "threadNumber", "h245.threadNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "threadNumber value", HFILL }},
	{ &hf_h245_qcifMPI_1_4,
		{ "qcifMPI_1_4", "h245.qcifMPI_1_4", FT_UINT32, BASE_DEC,
		NULL, 0, "qcifMPI_1_4 value", HFILL }},
	{ &hf_h245_qcifMPI_1_32,
		{ "qcifMPI_1_32", "h245.qcifMPI_1_32", FT_UINT32, BASE_DEC,
		NULL, 0, "qcifMPI_1_32 value", HFILL }},
	{ &hf_h245_qcifMPI_1_2048,
		{ "qcifMPI_1_2048", "h245.qcifMPI_1_2048", FT_UINT32, BASE_DEC,
		NULL, 0, "qcifMPI_1_2048 value", HFILL }},
	{ &hf_h245_cifMPI_1_4,
		{ "cifMPI_1_4", "h245.cifMPI_1_4", FT_UINT32, BASE_DEC,
		NULL, 0, "cifMPI_1_4 value", HFILL }},
	{ &hf_h245_cifMPI_1_32,
		{ "cifMPI_1_32", "h245.cifMPI_1_32", FT_UINT32, BASE_DEC,
		NULL, 0, "cifMPI_1_32 value", HFILL }},
	{ &hf_h245_cifMPI_1_2048,
		{ "cifMPI_1_2048", "h245.cifMPI_1_2048", FT_UINT32, BASE_DEC,
		NULL, 0, "cifMPI_1_2048 value", HFILL }},
	{ &hf_h245_videoBitRate,
		{ "videoBitRate", "h245.videoBitRate", FT_UINT32, BASE_DEC,
		NULL, 0, "videoBitRate value  (units 400 bit/s)", HFILL }},
	{ &hf_h245_vbvBufferSize,
		{ "vbvBufferSize", "h245.vbvBufferSize", FT_UINT32, BASE_DEC,
		NULL, 0, "vbvBufferSize value  (units 16384 bits)", HFILL }},
	{ &hf_h245_samplesPerLine,
		{ "samplesPerLine", "h245.samplesPerLine", FT_UINT32, BASE_DEC,
		NULL, 0, "samplesPerLine value", HFILL }},
	{ &hf_h245_linesPerFrame,
		{ "linesPerFrame", "h245.linesPerFrame", FT_UINT32, BASE_DEC,
		NULL, 0, "linesPerFrame value", HFILL }},
	{ &hf_h245_framesPerSecond,
		{ "framesPerSecond", "h245.framesPerSecond", FT_UINT32, BASE_DEC,
		NULL, 0, "framesPerSecond value", HFILL }},
	{ &hf_h245_luminanceSampleRate,
		{ "luminanceSampleRate", "h245.luminanceSampleRate", FT_UINT32, BASE_DEC,
		NULL, 0, "luminanceSampleRate value", HFILL }},
	{ &hf_h245_sqcifMPI_1_32,
		{ "sqcifMPI_1_32", "h245.sqcifMPI_1_32", FT_UINT32, BASE_DEC,
		NULL, 0, "sqcifMPI_1_32 value", HFILL }},
	{ &hf_h245_sqcifMPI_1_2048,
		{ "sqcifMPI_1_2048", "h245.sqcifMPI_1_2048", FT_UINT32, BASE_DEC,
		NULL, 0, "sqcifMPI_1_2048 value", HFILL }},
	{ &hf_h245_cif4MPI_1_32,
		{ "cif4MPI_1_32", "h245.cif4MPI_1_32", FT_UINT32, BASE_DEC,
		NULL, 0, "cif4MPI_1_32 value", HFILL }},
	{ &hf_h245_cif4MPI_1_2048,
		{ "cif4MPI_1_2048", "h245.cif4MPI_1_2048", FT_UINT32, BASE_DEC,
		NULL, 0, "cif4MPI_1_2048 value", HFILL }},
	{ &hf_h245_cif16MPI_1_32,
		{ "cif16MPI_1_32", "h245.cif16MPI_1_32", FT_UINT32, BASE_DEC,
		NULL, 0, "cif16MPI_1_32 value", HFILL }},
	{ &hf_h245_cif16MPI_1_2048,
		{ "cif16MPI_1_2048", "h245.cif16MPI_1_2048", FT_UINT32, BASE_DEC,
		NULL, 0, "cif16MPI_1_2048 value", HFILL }},
	{ &hf_h245_maxBitRate_192400,
		{ "maxBitRate_192400", "h245.maxBitRate_192400", FT_UINT32, BASE_DEC,
		NULL, 0, "maxBitRate_192400 value", HFILL }},
	{ &hf_h245_hrd_B,
		{ "hrd_B", "h245.hrd_B", FT_UINT32, BASE_DEC,
		NULL, 0, "hrd_B value", HFILL }},
	{ &hf_h245_bppMaxKb,
		{ "bppMaxKb", "h245.bppMaxKb", FT_UINT32, BASE_DEC,
		NULL, 0, "bppMaxKb value", HFILL }},
	{ &hf_h245_slowSqcifMPI,
		{ "slowSqcifMPI", "h245.slowSqcifMPI", FT_UINT32, BASE_DEC,
		NULL, 0, "slowSqcifMPI value", HFILL }},
	{ &hf_h245_slowQcifMPI,
		{ "slowQcifMPI", "h245.slowQcifMPI", FT_UINT32, BASE_DEC,
		NULL, 0, "slowQcifMPI value", HFILL }},
	{ &hf_h245_slowCifMPI,
		{ "slowCifMPI", "h245.slowCifMPI", FT_UINT32, BASE_DEC,
		NULL, 0, "slowCifMPI value", HFILL }},
	{ &hf_h245_slowCif4MPI,
		{ "slowCif4MPI", "h245.slowCif4MPI", FT_UINT32, BASE_DEC,
		NULL, 0, "slowCif4MPI value", HFILL }},
	{ &hf_h245_slowCif16MPI,
		{ "slowCif16MPI", "h245.slowCif16MPI", FT_UINT32, BASE_DEC,
		NULL, 0, "slowCif16MPI value", HFILL }},
	{ &hf_h245_numberOfBPictures,
		{ "numberOfBPictures", "h245.numberOfBPictures", FT_UINT32, BASE_DEC,
		NULL, 0, "numberOfBPictures value", HFILL }},
	{ &hf_h245_presentationOrder,
		{ "presentationOrder", "h245.presentationOrder", FT_UINT32, BASE_DEC,
		NULL, 0, "presentationOrder value", HFILL }},
	{ &hf_h245_offset_x,
		{ "offset_x", "h245.offset_x", FT_UINT32, BASE_DEC,
		NULL, 0, "offset_x value", HFILL }},
	{ &hf_h245_offset_y,
		{ "offset_y", "h245.offset_y", FT_UINT32, BASE_DEC,
		NULL, 0, "offset_y value", HFILL }},
	{ &hf_h245_scale_x,
		{ "scale_x", "h245.scale_x", FT_UINT32, BASE_DEC,
		NULL, 0, "scale_x value", HFILL }},
	{ &hf_h245_scale_y,
		{ "scale_y", "h245.scale_y", FT_UINT32, BASE_DEC,
		NULL, 0, "scale_y value", HFILL }},
	{ &hf_h245_sqcifAdditionalPictureMemory,
		{ "sqcifAdditionalPictureMemory", "h245.sqcifAdditionalPictureMemory", FT_UINT32, BASE_DEC,
		NULL, 0, "sqcifAdditionalPictureMemory value", HFILL }},
	{ &hf_h245_qcifAdditionalPictureMemory,
		{ "qcifAdditionalPictureMemory", "h245.qcifAdditionalPictureMemory", FT_UINT32, BASE_DEC,
		NULL, 0, "qcifAdditionalPictureMemory value", HFILL }},
	{ &hf_h245_cifAdditionalPictureMemory,
		{ "cifAdditionalPictureMemory", "h245.cifAdditionalPictureMemory", FT_UINT32, BASE_DEC,
		NULL, 0, "cifAdditionalPictureMemory value", HFILL }},
	{ &hf_h245_cif4AdditionalPictureMemory,
		{ "cif4AdditionalPictureMemory", "h245.cif4AdditionalPictureMemory", FT_UINT32, BASE_DEC,
		NULL, 0, "cif4AdditionalPictureMemory value", HFILL }},
	{ &hf_h245_cif16AdditionalPictureMemory,
		{ "cif16AdditionalPictureMemory", "h245.cif16AdditionalPictureMemory", FT_UINT32, BASE_DEC,
		NULL, 0, "cif16AdditionalPictureMemory value", HFILL }},
	{ &hf_h245_bigCpfAdditionalPictureMemory,
		{ "bigCpfAdditionalPictureMemory", "h245.bigCpfAdditionalPictureMemory", FT_UINT32, BASE_DEC,
		NULL, 0, "bigCpfAdditionalPictureMemory value", HFILL }},
	{ &hf_h245_mpuHorizMBs,
		{ "mpuHorizMBs", "h245.mpuHorizMBs", FT_UINT32, BASE_DEC,
		NULL, 0, "mpuHorizMBs value", HFILL }},
	{ &hf_h245_mpuVertMBs,
		{ "mpuVertMBs", "h245.mpuVertMBs", FT_UINT32, BASE_DEC,
		NULL, 0, "mpuVertMBs value", HFILL }},
	{ &hf_h245_mpuTotalNumber,
		{ "mpuTotalNumber", "h245.mpuTotalNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "mpuTotalNumber value", HFILL }},
	{ &hf_h245_clockConversionCode,
		{ "clockConversionCode", "h245.clockConversionCode", FT_UINT32, BASE_DEC,
		NULL, 0, "clockConversionCode value", HFILL }},
	{ &hf_h245_clockDivisor,
		{ "clockDivisor", "h245.clockDivisor", FT_UINT32, BASE_DEC,
		NULL, 0, "clockDivisor value", HFILL }},
	{ &hf_h245_maxCustomPictureWidth,
		{ "maxCustomPictureWidth", "h245.maxCustomPictureWidth", FT_UINT32, BASE_DEC,
		NULL, 0, "maxCustomPictureWidth value", HFILL }},
	{ &hf_h245_minCustomPictureWidth,
		{ "minCustomPictureWidth", "h245.minCustomPictureWidth", FT_UINT32, BASE_DEC,
		NULL, 0, "minCustomPictureWidth value", HFILL }},
	{ &hf_h245_minCustomPictureHeight,
		{ "minCustomPictureHeight", "h245.minCustomPictureHeight", FT_UINT32, BASE_DEC,
		NULL, 0, "minCustomPictureHeight value", HFILL }},
	{ &hf_h245_maxCustomPictureHeight,
		{ "maxCustomPictureHeight", "h245.maxCustomPictureHeight", FT_UINT32, BASE_DEC,
		NULL, 0, "maxCustomPictureHeight value", HFILL }},
	{ &hf_h245_standardMPI,
		{ "standardMPI", "h245.standardMPI", FT_UINT32, BASE_DEC,
		NULL, 0, "standardMPI value", HFILL }},
	{ &hf_h245_customMPI,
		{ "customMPI", "h245.customMPI", FT_UINT32, BASE_DEC,
		NULL, 0, "customMPI value", HFILL }},
	{ &hf_h245_width,
		{ "width", "h245.width", FT_UINT32, BASE_DEC,
		NULL, 0, "width value", HFILL }},
	{ &hf_h245_height,
		{ "height", "h245.height", FT_UINT32, BASE_DEC,
		NULL, 0, "height value", HFILL }},
	{ &hf_h245_pictureRate,
		{ "pictureRate", "h245.pictureRate", FT_UINT32, BASE_DEC,
		NULL, 0, "pictureRate value", HFILL }},
	{ &hf_h245_g711Alaw64k,
		{ "g711Alaw64k", "h245.g711Alaw64k", FT_UINT32, BASE_DEC,
		NULL, 0, "g711Alaw64k value", HFILL }},
	{ &hf_h245_g711Alaw56k,
		{ "g711Alaw56k", "h245.g711Alaw56k", FT_UINT32, BASE_DEC,
		NULL, 0, "g711Alaw56k value", HFILL }},
	{ &hf_h245_g711Ulaw64k,
		{ "g711Ulaw64k", "h245.g711Ulaw64k", FT_UINT32, BASE_DEC,
		NULL, 0, "g711Ulaw64k value", HFILL }},
	{ &hf_h245_g711Ulaw56k,
		{ "g711Ulaw56k", "h245.g711Ulaw56k", FT_UINT32, BASE_DEC,
		NULL, 0, "g711Ulaw56k value", HFILL }},
	{ &hf_h245_g722_64k,
		{ "g722_64k", "h245.g722_64k", FT_UINT32, BASE_DEC,
		NULL, 0, "g722_64k value", HFILL }},
	{ &hf_h245_g722_56k,
		{ "g722_56k", "h245.g722_56k", FT_UINT32, BASE_DEC,
		NULL, 0, "g722_56k value", HFILL }},
	{ &hf_h245_g722_48k,
		{ "g722_48k", "h245.g722_48k", FT_UINT32, BASE_DEC,
		NULL, 0, "g722_48k value", HFILL }},
	{ &hf_h245_maxAl_sduAudioFrames,
		{ "maxAl_sduAudioFrames", "h245.maxAl_sduAudioFrames", FT_UINT32, BASE_DEC,
		NULL, 0, "maxAl_sduAudioFrames value", HFILL }},
	{ &hf_h245_g728,
		{ "g728", "h245.g728", FT_UINT32, BASE_DEC,
		NULL, 0, "g728 value", HFILL }},
	{ &hf_h245_g729,
		{ "g729", "h245.g729", FT_UINT32, BASE_DEC,
		NULL, 0, "g729 value", HFILL }},
	{ &hf_h245_g729AnnexA,
		{ "g729AnnexA", "h245.g729AnnexA", FT_UINT32, BASE_DEC,
		NULL, 0, "g729AnnexA value", HFILL }},
	{ &hf_h245_g729wAnnexB,
		{ "g729wAnnexB", "h245.g729wAnnexB", FT_UINT32, BASE_DEC,
		NULL, 0, "g729wAnnexB value", HFILL }},
	{ &hf_h245_g729AnnexAwAnnexB,
		{ "g729AnnexAwAnnexB", "h245.g729AnnexAwAnnexB", FT_UINT32, BASE_DEC,
		NULL, 0, "g729AnnexAwAnnexB value", HFILL }},
	{ &hf_h245_audioUnit,
		{ "audioUnit", "h245.audioUnit", FT_UINT32, BASE_DEC,
		NULL, 0, "audioUnit value", HFILL }},
	{ &hf_h245_highRateMode0,
		{ "highRateMode0", "h245.highRateMode0", FT_UINT32, BASE_DEC,
		NULL, 0, "highRateMode0 value", HFILL }},
	{ &hf_h245_highRateMode1,
		{ "highRateMode1", "h245.highRateMode1", FT_UINT32, BASE_DEC,
		NULL, 0, "highRateMode1 value", HFILL }},
	{ &hf_h245_lowRateMode0,
		{ "lowRateMode0", "h245.lowRateMode0", FT_UINT32, BASE_DEC,
		NULL, 0, "lowRateMode0 value", HFILL }},
	{ &hf_h245_lowRateMode1,
		{ "lowRateMode1", "h245.lowRateMode1", FT_UINT32, BASE_DEC,
		NULL, 0, "lowRateMode1 value", HFILL }},
	{ &hf_h245_sidMode0,
		{ "sidMode0", "h245.sidMode0", FT_UINT32, BASE_DEC,
		NULL, 0, "sidMode0 value", HFILL }},
	{ &hf_h245_sidMode1,
		{ "sidMode1", "h245.sidMode1", FT_UINT32, BASE_DEC,
		NULL, 0, "sidMode1 value", HFILL }},
	{ &hf_h245_audioUnitSize,
		{ "audioUnitSize", "h245.audioUnitSize", FT_UINT32, BASE_DEC,
		NULL, 0, "audioUnitSize value", HFILL }},
	{ &hf_h245_maxBitRate_4294967295UL,
		{ "maxBitRate_4294967295UL", "h245.maxBitRate_4294967295UL", FT_UINT32, BASE_DEC,
		NULL, 0, "maxBitRate value in units of 100bits/s", HFILL }},
	{ &hf_h245_numberOfCodewords,
		{ "numberOfCodewords", "h245.numberOfCodewords", FT_UINT32, BASE_DEC,
		NULL, 0, "numberOfCodewords value", HFILL }},
	{ &hf_h245_maximumStringLength,
		{ "maximumStringLength", "h245.maximumStringLength", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumStringLength value", HFILL }},
	{ &hf_h245_version,
		{ "version", "h245.version", FT_UINT32, BASE_DEC,
		NULL, 0, "version value", HFILL }},
	{ &hf_h245_standard_0_127,
		{ "standard_0_127", "h245.standard_0_127", FT_UINT32, BASE_DEC,
		NULL, 0, "standard_0_127 value", HFILL }},
	{ &hf_h245_booleanArray,
		{ "booleanArray", "h245.booleanArray", FT_UINT32, BASE_DEC,
		NULL, 0, "booleanArray value", HFILL }},
	{ &hf_h245_unsignedMin,
		{ "unsignedMin", "h245.unsignedMin", FT_UINT32, BASE_DEC,
		NULL, 0, "unsignedMin value", HFILL }},
	{ &hf_h245_unsignedMax,
		{ "unsignedMax", "h245.unsignedMax", FT_UINT32, BASE_DEC,
		NULL, 0, "unsignedMax value", HFILL }},
	{ &hf_h245_unsigned32Min,
		{ "unsigned32Min", "h245.unsigned32Min", FT_UINT32, BASE_DEC,
		NULL, 0, "unsigned32Min value", HFILL }},
	{ &hf_h245_unsigned32Max,
		{ "unsigned32Max", "h245.unsigned32Max", FT_UINT32, BASE_DEC,
		NULL, 0, "unsigned32Max value", HFILL }},
	{ &hf_h245_dynamicRTPPayloadType,
		{ "dynamicRTPPayloadType", "h245.dynamicRTPPayloadType", FT_UINT32, BASE_DEC,
		NULL, 0, "dynamicRTPPayloadType value", HFILL }},
	{ &hf_h245_portNumber,
		{ "portNumber", "h245.portNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "portNumber value", HFILL }},
	{ &hf_h245_resourceID,
		{ "resourceID", "h245.resourceID", FT_UINT32, BASE_DEC,
		NULL, 0, "resourceID value", HFILL }},
	{ &hf_h245_subChannelID,
		{ "subChannelID", "h245.subChannelID", FT_UINT32, BASE_DEC,
		NULL, 0, "subChannelID value", HFILL }},
	{ &hf_h245_pcr_pid,
		{ "pcr_pid", "h245.pcr_pid", FT_UINT32, BASE_DEC,
		NULL, 0, "pcr_pid value", HFILL }},
	{ &hf_h245_controlFieldOctets,
		{ "controlFieldOctets", "h245.controlFieldOctets", FT_UINT32, BASE_DEC,
		NULL, 0, "controlFieldOctets value", HFILL }},
	{ &hf_h245_sendBufferSize,
		{ "sendBufferSize", "h245.sendBufferSize", FT_UINT32, BASE_DEC,
		NULL, 0, "sendBufferSize value", HFILL }},
	{ &hf_h245_rcpcCodeRate,
		{ "rcpcCodeRate", "h245.rcpcCodeRate", FT_UINT32, BASE_DEC,
		NULL, 0, "rcpcCodeRate value", HFILL }},
	{ &hf_h245_rsCodeCorrection,
		{ "rsCodeCorrection", "h245.rsCodeCorrection", FT_UINT32, BASE_DEC,
		NULL, 0, "rsCodeCorrection value", HFILL }},
	{ &hf_h245_finite_0_16,
		{ "finite_0_16", "h245.finite_0_16", FT_UINT32, BASE_DEC,
		NULL, 0, "finite_0_16 value", HFILL }},
	{ &hf_h245_windowSize,
		{ "windowSize", "h245.windowSize", FT_UINT32, BASE_DEC,
		NULL, 0, "windowSize value", HFILL }},
	{ &hf_h245_n401,
		{ "n401", "h245.n401", FT_UINT32, BASE_DEC,
		NULL, 0, "n401 value", HFILL }},
	{ &hf_h245_sessionID_0_255,
		{ "sessionID_0_255", "h245.sessionID_0_255", FT_UINT32, BASE_DEC,
		NULL, 0, "sessionID_0_255 value", HFILL }},
	{ &hf_h245_sessionID_1_255,
		{ "sessionID_1_255", "h245.sessionID_1_255", FT_UINT32, BASE_DEC,
		NULL, 0, "sessionID_1_255 value", HFILL }},
	{ &hf_h245_associatedSessionID,
		{ "associatedSessionID", "h245.associatedSessionID", FT_UINT32, BASE_DEC,
		NULL, 0, "associatedSessionID value", HFILL }},
	{ &hf_h245_payloadType,
		{ "payloadType", "h245.payloadType", FT_UINT32, BASE_DEC,
		NULL, 0, "payloadType value", HFILL }},
	{ &hf_h245_protectedSessionID,
		{ "protectedSessionID", "h245.protectedSessionID", FT_UINT32, BASE_DEC,
		NULL, 0, "protectedSessionID value", HFILL }},
	{ &hf_h245_protectedPayloadType,
		{ "protectedPayloadType", "h245.protectedPayloadType", FT_UINT32, BASE_DEC,
		NULL, 0, "protectedPayloadType value", HFILL }},
	{ &hf_h245_tsapIdentifier,
		{ "tsapIdentifier", "h245.tsapIdentifier", FT_UINT32, BASE_DEC,
		NULL, 0, "tsapIdentifier value", HFILL }},
	{ &hf_h245_synchFlag,
		{ "synchFlag", "h245.synchFlag", FT_UINT32, BASE_DEC,
		NULL, 0, "synchFlag value", HFILL }},
	{ &hf_h245_finite_1_65535,
		{ "finite_1_65535", "h245.finite_1_65535", FT_UINT32, BASE_DEC,
		NULL, 0, "finite_1_65535 value", HFILL }},
	{ &hf_h245_MultiplexTableEntryNumber,
		{ "MultiplexTableEntryNumber", "h245.MultiplexTableEntryNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "MultiplexTableEntryNumber value", HFILL }},
	{ &hf_h245_dataModeBitRate,
		{ "dataModeBitRate", "h245.dataModeBitRate", FT_UINT32, BASE_DEC,
		NULL, 0, "dataModeBitRate value", HFILL }},
	{ &hf_h245_sessionDependency,
		{ "sessionDependency", "h245.sessionDependency", FT_UINT32, BASE_DEC,
		NULL, 0, "sessionDependency value", HFILL }},
	{ &hf_h245_sRandom,
		{ "sRandom", "h245.sRandom", FT_UINT32, BASE_DEC,
		NULL, 0, "sRandom value", HFILL }},
	{ &hf_h245_McuNumber,
		{ "McuNumber", "h245.McuNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "McuNumber value", HFILL }},
	{ &hf_h245_TerminalNumber,
		{ "TerminalNumber", "h245.TerminalNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "TerminalNumber value", HFILL }},
	{ &hf_h245_maxNumberOfAdditionalConnections,
		{ "maxNumberOfAdditionalConnections", "h245.maxNumberOfAdditionalConnections", FT_UINT32, BASE_DEC,
		NULL, 0, "maxNumberOfAdditionalConnections value", HFILL }},
	{ &hf_h245_requestedInterval,
		{ "requestedInterval", "h245.requestedInterval", FT_UINT32, BASE_DEC,
		NULL, 0, "requestedInterval value", HFILL }},
	{ &hf_h245_callAssociationNumber,
		{ "callAssociationNumber", "h245.callAssociationNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "callAssociationNumber value", HFILL }},
	{ &hf_h245_currentInterval,
		{ "currentInterval", "h245.currentInterval", FT_UINT32, BASE_DEC,
		NULL, 0, "currentInterval value", HFILL }},
	{ &hf_h245_infoNotAvailable,
		{ "infoNotAvailable", "h245.infoNotAvailable", FT_UINT32, BASE_DEC,
		NULL, 0, "infoNotAvailable value", HFILL }},
	{ &hf_h245_channelTag,
		{ "channelTag", "h245.channelTag", FT_UINT32, BASE_DEC,
		NULL, 0, "channelTag value", HFILL }},
	{ &hf_h245_ConnectionIDsequenceNumber,
		{ "ConnectionIDsequenceNumber", "h245.ConnectionIDsequenceNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "ConnectionIDsequenceNumber value", HFILL }},
	{ &hf_h245_MaximumBitRate,
		{ "MaximumBitRate", "h245.MaximumBitRate", FT_UINT32, BASE_DEC,
		NULL, 0, "MaximumBitRate value", HFILL }},
	{ &hf_h245_maximumBitRate_0_16777215,
		{ "maximumBitRate_0_16777215", "h245.maximumBitRate_0_16777215", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumBitRate_0_16777215 value", HFILL }},
	{ &hf_h245_firstGOB_0_17,
		{ "firstGOB_0_17", "h245.firstGOB_0_17", FT_UINT32, BASE_DEC,
		NULL, 0, "firstGOB_0_17 value", HFILL }},
	{ &hf_h245_numberOfGOBs,
		{ "numberOfGOBs", "h245.numberOfGOBs", FT_UINT32, BASE_DEC,
		NULL, 0, "numberOfGOBs value", HFILL }},
	{ &hf_h245_videoTemporalSpatialTradeOff,
		{ "videoTemporalSpatialTradeOff", "h245.videoTemporalSpatialTradeOff", FT_UINT32, BASE_DEC,
		NULL, 0, "videoTemporalSpatialTradeOff value", HFILL }},
	{ &hf_h245_firstGOB_0_255,
		{ "firstGOB_0_255", "h245.firstGOB_0_255", FT_UINT32, BASE_DEC,
		NULL, 0, "firstGOB_0_255 value", HFILL }},
	{ &hf_h245_firstMB_1_8192,
		{ "firstMB_1_8192", "h245.firstMB_1_8192", FT_UINT32, BASE_DEC,
		NULL, 0, "firstMB_1_8192 value", HFILL }},
	{ &hf_h245_firstMB_1_9216,
		{ "firstMB_1_9216", "h245.firstMB_1_9216", FT_UINT32, BASE_DEC,
		NULL, 0, "firstMB_1_9216 value", HFILL }},
	{ &hf_h245_numberOfMBs_1_8192,
		{ "numberOfMBs_1_8192", "h245.numberOfMBs_1_8192", FT_UINT32, BASE_DEC,
		NULL, 0, "numberOfMBs_1_8192 value", HFILL }},
	{ &hf_h245_numberOfMBs_1_9216,
		{ "numberOfMBs_1_9216", "h245.numberOfMBs_1_9216", FT_UINT32, BASE_DEC,
		NULL, 0, "numberOfMBs_1_9216 value", HFILL }},
	{ &hf_h245_maxH223MUXPDUsize,
		{ "maxH223MUXPDUsize", "h245.maxH223MUXPDUsize", FT_UINT32, BASE_DEC,
		NULL, 0, "maxH223MUXPDUsize value", HFILL }},
	{ &hf_h245_temporalReference_0_1023,
		{ "temporalReference_0_1023", "h245.temporalReference_0_1023", FT_UINT32, BASE_DEC,
		NULL, 0, "temporalReference_0_1023 value", HFILL }},
	{ &hf_h245_temporalReference_0_255,
		{ "temporalReference_0_255", "h245.temporalReference_0_255", FT_UINT32, BASE_DEC,
		NULL, 0, "temporalReference_0_255 value", HFILL }},
	{ &hf_h245_pictureNumber,
		{ "pictureNumber", "h245.pictureNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "pictureNumber value", HFILL }},
	{ &hf_h245_longTermPictureIndex,
		{ "longTermPictureIndex", "h245.longTermPictureIndex", FT_UINT32, BASE_DEC,
		NULL, 0, "longTermPictureIndex value", HFILL }},
	{ &hf_h245_sampleSize,
		{ "sampleSize", "h245.sampleSize", FT_UINT32, BASE_DEC,
		NULL, 0, "sampleSize value", HFILL }},
	{ &hf_h245_samplesPerFrame,
		{ "samplesPerFrame", "h245.samplesPerFrame", FT_UINT32, BASE_DEC,
		NULL, 0, "samplesPerFrame value", HFILL }},
	{ &hf_h245_sbeNumber,
		{ "sbeNumber", "h245.sbeNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "sbeNumber value", HFILL }},
	{ &hf_h245_subPictureNumber,
		{ "subPictureNumber", "h245.subPictureNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "subPictureNumber value", HFILL }},
	{ &hf_h245_compositionNumber,
		{ "compositionNumber", "h245.compositionNumber", FT_UINT32, BASE_DEC,
		NULL, 0, "compositionNumber value", HFILL }},
	{ &hf_h245_estimatedReceivedJitterMantissa,
		{ "estimatedReceivedJitterMantissa", "h245.estimatedReceivedJitterMantissa", FT_UINT32, BASE_DEC,
		NULL, 0, "estimatedReceivedJitterMantissa value", HFILL }},
	{ &hf_h245_estimatedReceivedJitterExponent,
		{ "estimatedReceivedJitterExponent", "h245.estimatedReceivedJitterExponent", FT_UINT32, BASE_DEC,
		NULL, 0, "estimatedReceivedJitterExponent value", HFILL }},
	{ &hf_h245_skippedFrameCount,
		{ "skippedFrameCount", "h245.skippedFrameCount", FT_UINT32, BASE_DEC,
		NULL, 0, "skippedFrameCount value", HFILL }},
	{ &hf_h245_additionalDecoderBuffer,
		{ "additionalDecoderBuffer", "h245.additionalDecoderBuffer", FT_UINT32, BASE_DEC,
		NULL, 0, "additionalDecoderBuffer value", HFILL }},
	{ &hf_h245_skew,
		{ "skew", "h245.skew", FT_UINT32, BASE_DEC,
		NULL, 0, "skew value", HFILL }},
	{ &hf_h245_maximumSkew,
		{ "maximumSkew", "h245.maximumSkew", FT_UINT32, BASE_DEC,
		NULL, 0, "maximumSkew value", HFILL }},
	{ &hf_h245_duration,
		{ "duration", "h245.duration", FT_UINT32, BASE_DEC,
		NULL, 0, "duration value", HFILL }},
	{ &hf_h245_timestamp,
		{ "timestamp", "h245.timestamp", FT_UINT32, BASE_DEC,
		NULL, 0, "timestamp value", HFILL }},
	{ &hf_h245_frame,
		{ "frame", "h245.frame", FT_UINT32, BASE_DEC,
		NULL, 0, "frame", HFILL }},
	{ &hf_h245_containedThread,
		{ "containedThread", "h245.containedThread", FT_UINT32, BASE_DEC,
		NULL, 0, "containedThread value", HFILL }},
	{ &hf_h245_t38FaxMaxDatagram,
		{ "t38FaxMaxDatagram", "h245.t38FaxMaxDatagram", FT_INT32, BASE_DEC,
		NULL, 0, "t38FaxMaxDatagram value", HFILL }},
	{ &hf_h245_t38FaxMaxBuffer,
		{ "t38FaxMaxBuffer", "h245.t38FaxMaxBuffer", FT_INT32, BASE_DEC,
		NULL, 0, "t38FaxMaxBuffer value", HFILL }},
	{ &hf_h245_expirationTime,
		{ "expirationTime", "h245.expirationTime", FT_UINT32, BASE_DEC,
		NULL, 0, "expirationTime value", HFILL }},
	{ &hf_h245_rfc_number,
		{ "RFC", "h245.rfc_number", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of the RFC where this can be found", HFILL }},
	{ &hf_h245_object,
		{ "Object", "h245.object", FT_STRING, BASE_NONE,
		NULL, 0, "Object Identifier", HFILL }},
	{ &hf_h245_protocolIdentifier,
		{ "protocolIdentifier", "h245.protocolIdentifier", FT_STRING, BASE_NONE,
		NULL, 0, "protocolIdentifier object", HFILL }},
	{ &hf_h245_algorithm,
		{ "algorithm", "h245.algorithm", FT_STRING, BASE_NONE,
		NULL, 0, "algorithm object", HFILL }},
	{ &hf_h245_antiSpamAlgorithm,
		{ "antiSpamAlgorithm", "h245.antiSpamAlgorithm", FT_STRING, BASE_NONE,
		NULL, 0, "antiSpamAlgorithm object", HFILL }},
	{ &hf_h245_standard_object,
		{ "standard_object", "h245.standard_object", FT_STRING, BASE_NONE,
		NULL, 0, "standard_object object", HFILL }},
	{ &hf_h245_oid,
		{ "oid", "h245.oid", FT_STRING, BASE_NONE,
		NULL, 0, "oid object", HFILL }},
	{ &hf_h245_escrowID,
		{ "escrowID", "h245.escrowID", FT_STRING, BASE_NONE,
		NULL, 0, "escrowID object", HFILL }},
	{ &hf_h245_field,
		{ "field", "h245.field", FT_STRING, BASE_NONE,
		NULL, 0, "field object", HFILL }},
	{ &hf_h245_NonStandardParameterData,
		{ "data", "h245.NonStandardParameterData", FT_BYTES, BASE_HEX,
		NULL, 0, "NonStandardParameterData", HFILL }},
	{ &hf_h245_nlpidData,
		{ "nlpidData", "h245.nlpidData", FT_BYTES, BASE_HEX,
		NULL, 0, "nlpidData octet string", HFILL }},
	{ &hf_h245_nonCollapsingRaw,
		{ "nonCollapsingRaw", "h245.nonCollapsingRaw", FT_BYTES, BASE_HEX,
		NULL, 0, "nonCollapsingRaw octet string", HFILL }},
	{ &hf_h245_uuid,
		{ "uuid", "h245.uuid", FT_BYTES, BASE_HEX,
		NULL, 0, "uuid octet string", HFILL }},
	{ &hf_h245_octetString,
		{ "octetString", "h245.octetString", FT_BYTES, BASE_HEX,
		NULL, 0, "octetString octet string", HFILL }},
	{ &hf_h245_externalReference,
		{ "externalReference", "h245.externalReference", FT_BYTES, BASE_HEX,
		NULL, 0, "externalReference octet string", HFILL }},
	{ &hf_h245_nsapAddress,
		{ "nsapAddress", "h245.nsapAddress", FT_BYTES, BASE_HEX,
		NULL, 0, "nsapAddress octet string", HFILL }},
	{ &hf_h245_subaddress_1_20,
		{ "subaddress_1_20", "h245.subaddress_1_20", FT_BYTES, BASE_HEX,
		NULL, 0, "subaddress_1_20 octet string", HFILL }},
	{ &hf_h245_programDescriptors,
		{ "programDescriptors", "h245.programDescriptors", FT_BYTES, BASE_HEX,
		NULL, 0, "programDescriptors octet string", HFILL }},
	{ &hf_h245_streamDescriptors,
		{ "streamDescriptors", "h245.streamDescriptors", FT_BYTES, BASE_HEX,
		NULL, 0, "streamDescriptors octet string", HFILL }},
	{ &hf_h245_ipv4network,
		{ "ipv4network", "h245.ipv4network", FT_IPv4, BASE_NONE,
		NULL, 0, "IPv4 Address", HFILL }},
	{ &hf_h245_ipxNode,
		{ "ipxNode", "h245.ipxNode", FT_BYTES, BASE_HEX,
		NULL, 0, "ipxNode octet string", HFILL }},
	{ &hf_h245_ipxNetnum,
		{ "ipxNetnum", "h245.ipxNetnum", FT_BYTES, BASE_HEX,
		NULL, 0, "ipxNetnum octet string", HFILL }},
	{ &hf_h245_ipv6network,
		{ "ipv6network", "h245.ipv6network", FT_BYTES, BASE_HEX,
		NULL, 0, "ipv6network octet string", HFILL }},
	{ &hf_h245_netBios,
		{ "netBios", "h245.netBios", FT_BYTES, BASE_HEX,
		NULL, 0, "netBios octet string", HFILL }},
	{ &hf_h245_nsap,
		{ "nsap", "h245.nsap", FT_BYTES, BASE_HEX,
		NULL, 0, "nsap octet string", HFILL }},
	{ &hf_h245_h235Key,
		{ "h235Key", "h245.h235Key", FT_BYTES, BASE_HEX,
		NULL, 0, "h235Key octet string", HFILL }},
	{ &hf_h245_value,
		{ "value", "h245.value", FT_BYTES, BASE_HEX,
		NULL, 0, "value octet string", HFILL }},
	{ &hf_h245_certificateResponse,
		{ "certificateResponse", "h245.certificateResponse", FT_BYTES, BASE_HEX,
		NULL, 0, "certificateResponse octet string", HFILL }},
	{ &hf_h245_TerminalID,
		{ "TerminalID", "h245.TerminalID", FT_BYTES, BASE_HEX,
		NULL, 0, "TerminalID octet string", HFILL }},
	{ &hf_h245_ConferenceID,
		{ "ConferenceID", "h245.ConferenceID", FT_BYTES, BASE_HEX,
		NULL, 0, "ConferenceID octet string", HFILL }},
	{ &hf_h245_Password,
		{ "Password", "h245.Password", FT_BYTES, BASE_HEX,
		NULL, 0, "Password octet string", HFILL }},
	{ &hf_h245_encryptionSE,
		{ "encryptionSE", "h245.encryptionSE", FT_BYTES, BASE_HEX,
		NULL, 0, "encryptionSE octet string", HFILL }},
	{ &hf_h245_conferenceIdentifier,
		{ "conferenceIdentifier", "h245.conferenceIdentifier", FT_BYTES, BASE_HEX,
		NULL, 0, "conferenceIdentifier octet string", HFILL }},
	{ &hf_h245_returnedFunction,
		{ "returnedFunction", "h245.returnedFunction", FT_BYTES, BASE_HEX,
		NULL, 0, "returnedFunction octet string", HFILL }},
	{ &hf_h245_productNumber,
		{ "productNumber", "h245.productNumber", FT_BYTES, BASE_HEX,
		NULL, 0, "productNumber octet string", HFILL }},
	{ &hf_h245_versionNumber,
		{ "versionNumber", "h245.versionNumber", FT_BYTES, BASE_HEX,
		NULL, 0, "versionNumber octet string", HFILL }},
	{ &hf_h245_mediaDistributionCapability,
		{ "mediaDistributionCapability", "h245.mediaDistributionCapability_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "mediaDistributionCapability sequence of", HFILL }},
	{ &hf_h245_AlternativeCapabilitySet,
		{ "AlternativeCapabilitySet", "h245.AlternativeCapabilitySet", FT_NONE, BASE_NONE,
		NULL, 0 , "AlternativeCapabilitySet sequence of", HFILL }},
	{ &hf_h245_CapabilityTableEntryNumber_sequence_of,
		{ "CapabilityTableEntryNumber_sequence_of", "h245.CapabilityTableEntryNumber_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "CapabilityTableEntryNumber_sequence_of sequence of", HFILL }},
	{ &hf_h245_frameToThreadMapping_custom,
		{ "frameToThreadMapping_custom", "h245.frameToThreadMapping_custom", FT_NONE, BASE_NONE,
		NULL, 0 , "frameToThreadMapping_custom sequence of", HFILL }},
	{ &hf_h245_RedundancyEncodingCapability_sequence_of,
		{ "RedundancyEncodingCapability_sequence_of", "h245.RedundancyEncodingCapability_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "RedundancyEncodingCapability_sequence_of sequence of", HFILL }},
	{ &hf_h245_frameSequence,
		{ "frameSequence", "h245.frameSequence", FT_NONE, BASE_NONE,
		NULL, 0 , "sequence of frames", HFILL }},
	{ &hf_h245_escrowentry,
		{ "escrowentry", "h245.escrowentry", FT_NONE, BASE_NONE,
		NULL, 0 , "escrowentry sequence of", HFILL }},
	{ &hf_h245_elementList,
		{ "elementList", "h245.elementList", FT_NONE, BASE_NONE,
		NULL, 0 , "elementList sequence of", HFILL }},
	{ &hf_h245_subElementList,
		{ "subElementList", "h245.subElementList", FT_NONE, BASE_NONE,
		NULL, 0 , "subElementList sequence of", HFILL }},
	{ &hf_h245_requestedModes,
		{ "requestedModes", "h245.requestedModes", FT_NONE, BASE_NONE,
		NULL, 0 , "requestedModes sequence of", HFILL }},
	{ &hf_h245_CertSelectionCriteria,
		{ "CertSelectionCriteria", "h245.CertSelectionCriteria", FT_NONE, BASE_NONE,
		NULL, 0 , "CertSelectionCriteria sequence of", HFILL }},
	{ &hf_h245_capabilityTable,
		{ "capabilityTable", "h245.capabilityTable", FT_NONE, BASE_NONE,
		NULL, 0, "capabilityTable set of", HFILL }},
	{ &hf_h245_capabilityDescriptors,
		{ "capabilityDescriptors", "h245.capabilityDescriptors", FT_NONE, BASE_NONE,
		NULL, 0, "capabilityDescriptors set of", HFILL }},
	{ &hf_h245_simultaneousCapabilities,
		{ "simultaneousCapabilities", "h245.simultaneousCapabilities", FT_NONE, BASE_NONE,
		NULL, 0, "simultaneousCapabilities set of", HFILL }},
	{ &hf_h245_gatewayAddress,
		{ "gatewayAddress", "h245.gatewayAddress", FT_NONE, BASE_NONE,
		NULL, 0, "gatewayAddress set of", HFILL }},
	{ &hf_h245_snrEnhancement,
		{ "snrEnhancement", "h245.snrEnhancement", FT_NONE, BASE_NONE,
		NULL, 0, "snrEnhancement set of", HFILL }},
	{ &hf_h245_spatialEnhancement,
		{ "spatialEnhancement", "h245.spatialEnhancement", FT_NONE, BASE_NONE,
		NULL, 0, "spatialEnhancement set of", HFILL }},
	{ &hf_h245_bPictureEnhancement,
		{ "bPictureEnhancement", "h245.bPictureEnhancement", FT_NONE, BASE_NONE,
		NULL, 0, "bPictureEnhancement set of", HFILL }},
	{ &hf_h245_customPictureClockFrequency,
		{ "customPictureClockFrequency", "h245.customPictureClockFrequency", FT_NONE, BASE_NONE,
		NULL, 0, "customPictureClockFrequency set of", HFILL }},
	{ &hf_h245_customPictureFormat,
		{ "customPictureFormat", "h245.customPictureFormat", FT_NONE, BASE_NONE,
		NULL, 0, "customPictureFormat set of", HFILL }},
	{ &hf_h245_modeCombos,
		{ "modeCombos", "h245.modeCombos", FT_NONE, BASE_NONE,
		NULL, 0, "modeCombos set of", HFILL }},
	{ &hf_h245_customPCF,
		{ "customPCF", "h245.customPCF", FT_NONE, BASE_NONE,
		NULL, 0, "customPCF set of", HFILL }},
	{ &hf_h245_pixelAspectCode,
		{ "pixelAspectCode", "h245.pixelAspectCode", FT_NONE, BASE_NONE,
		NULL, 0, "pixelAspectCode set of", HFILL }},
	{ &hf_h245_extendedPAR,
		{ "extendedPAR", "h245.extendedPAR", FT_NONE, BASE_NONE,
		NULL, 0, "extendedPAR set of", HFILL }},
	{ &hf_h245_h263VideoCoupledModes,
		{ "h263VideoCoupledModes", "h245.h263VideoCoupledModes", FT_NONE, BASE_NONE,
		NULL, 0, "h263VideoCoupledModes set of", HFILL }},
	{ &hf_h245_capabilityOnMuxStream,
		{ "capabilityOnMuxStream", "h245.capabilityOnMuxStream", FT_NONE, BASE_NONE,
		NULL, 0, "capabilityOnMuxStream set of", HFILL }},
	{ &hf_h245_capabilities,
		{ "capabilities", "h245.capabilities", FT_NONE, BASE_NONE,
		NULL, 0, "capabilities set of", HFILL }},
	{ &hf_h245_multiplexEntryDescriptors,
		{ "multiplexEntryDescriptors", "h245.multiplexEntryDescriptors", FT_NONE, BASE_NONE,
		NULL, 0, "multiplexEntryDescriptors set of", HFILL }},
	{ &hf_h245_multiplexTableEntryNumber_set_of,
		{ "multiplexTableEntryNumber_set_of", "h245.multiplexTableEntryNumber_set_of", FT_NONE, BASE_NONE,
		NULL, 0, "multiplexTableEntryNumber_set_of set of", HFILL }},
	{ &hf_h245_VCCapability_set_of,
		{ "VCCapability_set_of", "h245.VCCapability_set_of", FT_NONE, BASE_NONE,
		NULL, 0, "VCCapability_set_of set of", HFILL }},
	{ &hf_h245_rejectionDescriptions,
		{ "rejectionDescriptions", "h245.rejectionDescriptions", FT_NONE, BASE_NONE,
		NULL, 0, "rejectionDescriptions set of", HFILL }},
	{ &hf_h245_entryNumbers,
		{ "entryNumbers", "h245.entryNumbers", FT_NONE, BASE_NONE,
		NULL, 0, "entryNumbers set of", HFILL }},
	{ &hf_h245_ModeDescription,
		{ "ModeDescription", "h245.ModeDescription", FT_NONE, BASE_NONE,
		NULL, 0, "ModeDescription set of", HFILL }},
	{ &hf_h245_communicationModeTable,
		{ "communicationModeTable", "h245.communicationModeTable", FT_NONE, BASE_NONE,
		NULL, 0, "communicationModeTable set of", HFILL }},
	{ &hf_h245_terminalListResponse,
		{ "terminalListResponse", "h245.terminalListResponse", FT_NONE, BASE_NONE,
		NULL, 0, "terminalListResponse set of", HFILL }},
	{ &hf_h245_differential,
		{ "differential", "h245.differential", FT_NONE, BASE_NONE,
		NULL, 0, "differential set of", HFILL }},
	{ &hf_h245_networkType,
		{ "networkType", "h245.networkType", FT_NONE, BASE_NONE,
		NULL, 0, "networkType set of", HFILL }},
	{ &hf_h245_capabilityTableEntryNumbers,
		{ "capabilityTableEntryNumbers", "h245.capabilityTableEntryNumbers", FT_NONE, BASE_NONE,
		NULL, 0, "capabilityTableEntryNumbers set of", HFILL }},
	{ &hf_h245_capabilityDescriptorNumbers,
		{ "capabilityDescriptorNumbers", "h245.capabilityDescriptorNumbers", FT_NONE, BASE_NONE,
		NULL, 0, "capabilityDescriptorNumbers set of", HFILL }},
	{ &hf_h245_qOSCapabilities,
		{ "qOSCapabilities", "h245.qOSCapabilities", FT_NONE, BASE_NONE,
		NULL, 0 , "qOSCapabilities sequence of", HFILL }},
	{ &hf_h245_EncryptionCapability,
		{ "EncryptionCapability", "h245.EncryptionCapability", FT_NONE, BASE_NONE,
		NULL, 0 , "EncryptionCapability sequence of", HFILL }},
	{ &hf_h245_containedThreads,
		{ "containedThreads", "h245.containedThreads", FT_NONE, BASE_NONE,
		NULL, 0 , "containedThreads sequence of", HFILL }},
	{ &hf_h245_mediaChannelCapabilities,
		{ "mediaChannelCapabilities", "h245.mediaChannelCapabilities", FT_NONE, BASE_NONE,
		NULL, 0 , "mediaChannelCapabilities sequence of", HFILL }},
	{ &hf_h245_rtpPayloadType_sequence_of,
		{ "rtpPayloadType_sequence_of", "h245.rtpPayloadType_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "rtpPayloadType sequence of", HFILL }},
	{ &hf_h245_centralizedData,
		{ "centralizedData", "h245.centralizedData_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "centralizedData sequence of", HFILL }},
	{ &hf_h245_distributedData,
		{ "distributedData", "h245.distributedData_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "distributedData sequence of", HFILL }},
	{ &hf_h245_nonStandardData,
		{ "nonStandardData", "h245.nonStandardData_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "nonStandardData sequence of", HFILL }},
	{ &hf_h245_collapsing,
		{ "collapsing", "h245.collapsing_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "collapsing sequence of", HFILL }},
	{ &hf_h245_nonCollapsing,
		{ "nonCollapsing", "h245.nonCollapsing_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "nonCollapsing sequence of", HFILL }},
	{ &hf_h245_supersedes,
		{ "supersedes", "h245.supersedes_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "supersedes sequence of", HFILL }},
	{ &hf_h245_genericParameter,
		{ "genericParameter", "h245.genericParameter_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "genericParameter sequence of", HFILL }},
	{ &hf_h245_secondary_REE,
		{ "secondary_REE", "h245.secondary_REE_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "secondary_REE sequence of", HFILL }},
	{ &hf_h245_elements_MPSE,
		{ "elements_MPSE", "h245.elements_MPSE_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "elements_MPSE sequence of", HFILL }},
	{ &hf_h245_secondary_REDTME,
		{ "secondary_REDTME", "h245.secondary_REDTME_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "secondary_REDTME sequence of", HFILL }},
	{ &hf_h245_elements_MPSEM,
		{ "elements_MPSEM", "h245.elements_MPSEM_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "elements_MPSEM sequence of", HFILL }},
	{ &hf_h245_TerminalInformationSO,
		{ "TerminalInformationSO", "h245.TerminalInformationSO_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "TerminalInformationSO sequence of", HFILL }},
	{ &hf_h245_lostPicture,
		{ "lostPicture", "h245.lostPicture_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "lostPicture sequence of", HFILL }},
	{ &hf_h245_recoveryReferencePicture,
		{ "recoveryReferencePicture", "h245.recoveryReferencePicture_sequence_of", FT_NONE, BASE_NONE,
		NULL, 0 , "recoveryReferencePicture sequence of", HFILL }},
	{ &hf_h245_iPSourceRouteAddress_route,
		{ "iPSourceRouteAddress_route", "h245.iPSourceRouteAddress_route", FT_NONE, BASE_NONE,
		NULL, 0, "iPSourceRouteAddress_route sequence of", HFILL }},
	{ &hf_h245_audioTelephoneEvent,
		{ "audioTelephoneEvent", "h245.audioTelephoneEvent", FT_STRING, FT_NONE,
		NULL, 0, "audioTelephoneEvent string", HFILL }},
	{ &hf_h245_alphanumeric,
		{ "alphanumeric", "h245.alphanumeric", FT_STRING, FT_NONE,
		NULL, 0, "alphanumeric string", HFILL }},
	{ &hf_h245_domainBased,
		{ "domainBased", "h245.domainBased", FT_STRING, FT_NONE,
		NULL, 0, "String for domainBased", HFILL }},
	{ &hf_h245_subAddress,
		{ "subAddress", "h245.subAddress", FT_STRING, FT_NONE,
		NULL, 0, "String for subAddress", HFILL }},
	{ &hf_h245_e164Address,
		{ "e164Address", "h245.e164Address", FT_STRING, FT_NONE,
		NULL, 0, "String for e164Address", HFILL }},
	{ &hf_h245_signalType,
		{ "signalType", "h245.signalType", FT_STRING, FT_NONE,
		NULL, 0, "String for signalType", HFILL }},
	{ &hf_h245_DialingInformationNumber_networkAddress,
		{ "networkAddress", "h245.DialingInformationNumber_networkAddress", FT_STRING, FT_NONE,
		NULL, 0, "String for DialingInformationNumber_networkAddress", HFILL }},
	{ &hf_h245_internationalNumber,
		{ "internationalNumber", "h245.internationalNumber", FT_STRING, FT_NONE,
		NULL, 0, "String for internationalNumber", HFILL }},
	{ &hf_h245_h221Manufacturer,
		{ "H.221 Manufacturer", "h245.h221Manufacturer", FT_UINT32, BASE_HEX,
		VALS(H221ManufacturerCode_vals), 0, "H.221 Manufacturer", HFILL }},
	};

	static gint *ett[] =
	{
		&ett_h245,
		&ett_h245_MultimediaSystemControlMessage,
		&ett_h245_RequestMessage,
		&ett_h245_ResponseMessage,
		&ett_h245_IndicationMessage,
		&ett_h245_CommandMessage,
		&ett_h245_OpenLogicalChannelConfirm,
		&ett_h245_EndSessionCommand,
		&ett_h245_MobileMultilinkReconfigurationIndication,
		&ett_h245_FlowControlIndication,
		&ett_h245_UserInputIndication_extendedAlphanumeric,
		&ett_h245_UserInputIndication_signalUpdate_rtp,
		&ett_h245_UserInputIndication_signalUpdate,
		&ett_h245_UserInputIndication_signal_rtp,
		&ett_h245_UserInputIndication_signal,
		&ett_h245_NewATMVCIndication_reverseParameters,
		&ett_h245_NewATMVCIndication_aal_aal5,
		&ett_h245_NewATMVCIndication_aal_aal1,
		&ett_h245_NewATMVCIndication_aal,
		&ett_h245_NewATMVCIndication,
		&ett_h245_VendorIdentification,
		&ett_h245_MCLocationIndication,
		&ett_h245_H2250MaximumSkewIndication,
		&ett_h245_H223SkewIndication,
		&ett_h245_JitterIndication,
		&ett_h245_MiscellaneousIndication_type_videoNotDecodedMBs,
		&ett_h245_MiscellaneousIndication,
		&ett_h245_VideoIndicateCompose,
		&ett_h245_TerminalYouAreSeeingInSubPictureNumber,
		&ett_h245_FunctionNotSupported,
		&ett_h245_MobileMultilinkReconfigurationCommand,
		&ett_h245_NewATMVCCommand_reverseParameters,
		&ett_h245_NewATMVCCommand,
		&ett_h245_NewATMVCCommand_aal_aal5,
		&ett_h245_NewATMVCCommand_aal_aal1,
		&ett_h245_EncryptionUpdateRequest,
		&ett_h245_KeyProtectionMethod,
		&ett_h245_MiscellaneousCommand_type_lostPartialPicture,
		&ett_h245_MiscellaneousCommand_type_videoBadMBs,
		&ett_h245_MiscellaneousCommand_type_progressiveRefinementStart,
		&ett_h245_MiscellaneousCommand_type_videoFastUpdateMB,
		&ett_h245_MiscellaneousCommand_type_videoFastUpdateGOB,
		&ett_h245_MiscellaneousCommand,
		&ett_h245_SubstituteConferenceIDCommand,
		&ett_h245_FlowControlCommand,
		&ett_h245_EncryptionCommand_encryptionAlgorithmID,
		&ett_h245_SendTerminalCapabilitySet_specificRequest,
		&ett_h245_LogicalChannelRateRelease,
		&ett_h245_LogicalChannelRateReject,
		&ett_h245_LogicalChannelRateAck,
		&ett_h245_LogicalChannelRateRequest,
		&ett_h245_ConnectionIdentifier,
		&ett_h245_DialingInformationNumber,
		&ett_h245_MultilinkIndication_excessiveError,
		&ett_h245_MultilinkIndication_crcDesired,
		&ett_h245_MultilinkResponse_maximumHeaderInterval,
		&ett_h245_MultilinkResponse_removeConnection,
		&ett_h245_MultilinkResponse_addConnection,
		&ett_h245_MultilinkResponse_callInformation,
		&ett_h245_MultilinkRequest_maximumHeaderInterval,
		&ett_h245_MultilinkRequest_removeConnection,
		&ett_h245_MultilinkRequest_addConnection,
		&ett_h245_MultilinkRequest_callInformation,
		&ett_h245_TerminalInformation,
		&ett_h245_RequestAllTerminalIDsResponse,
		&ett_h245_ConferenceResponse_terminalCertificateResponse,
		&ett_h245_ConferenceResponse_chairTokenOwnerResponse,
		&ett_h245_ConferenceResponse_extensionAddressResponse,
		&ett_h245_ConferenceResponse_passwordResponse,
		&ett_h245_ConferenceResponse_conferenceIDResponse,
		&ett_h245_ConferenceResponse_terminalIDResponse,
		&ett_h245_ConferenceResponse_mCterminalIDResponse,
		&ett_h245_TerminalLabel,
		&ett_h245_Criteria,
		&ett_h245_ConferenceRequest_requestTerminalCertificate,
		&ett_h245_CommunicationModeTableEntry,
		&ett_h245_CommunicationModeRequest,
		&ett_h245_CommunicationModeCommand,
		&ett_h245_MaintenanceLoopOffCommand,
		&ett_h245_MaintenanceLoopReject,
		&ett_h245_MaintenanceLoopAck,
		&ett_h245_MaintenanceLoopRequest,
		&ett_h245_RoundTripDelayResponse,
		&ett_h245_RoundTripDelayRequest,
		&ett_h245_DataMode_application_t38fax,
		&ett_h245_DataMode_application_nlpid,
		&ett_h245_DataMode,
		&ett_h245_VBDMode,
		&ett_h245_G7231AnnexCMode_g723AnnexCAudioMode,
		&ett_h245_G7231AnnexCMode,
		&ett_h245_IS13818AudioMode,
		&ett_h245_IS11172AudioMode,
		&ett_h245_IS11172VideoMode,
		&ett_h245_H263VideoMode,
		&ett_h245_H262VideoMode,
		&ett_h245_H261VideoMode,
		&ett_h245_RedundancyEncodingMode,
		&ett_h245_H2250ModeParameters,
		&ett_h245_H223ModeParameters_adaptationLayerType_al3,
		&ett_h245_H223ModeParameters,
		&ett_h245_FECMode_rfc2733Mode_mode_separateStream_samePort,
		&ett_h245_FECMode_rfc2733Mode_mode_separateStream_differentPort,
		&ett_h245_FECMode_rfc2733Mode,
		&ett_h245_MultiplePayloadStreamElementMode,
		&ett_h245_MultiplePayloadStreamMode,
		&ett_h245_RedundancyEncodingDTModeElement,
		&ett_h245_RedundancyEncodingDTMode,
		&ett_h245_MultiplexedStreamModeParameters,
		&ett_h245_H235Mode,
		&ett_h245_ModeElement,
		&ett_h245_RequestModeRelease,
		&ett_h245_RequestModeReject,
		&ett_h245_RequestModeAck,
		&ett_h245_RequestMode,
		&ett_h245_RequestMultiplexEntryRelease,
		&ett_h245_RequestMultiplexEntryRejectionDescriptions,
		&ett_h245_RequestMultiplexEntryReject,
		&ett_h245_RequestMultiplexEntryAck,
		&ett_h245_RequestMultiplexEntry,
		&ett_h245_MultiplexEntrySendRelease,
		&ett_h245_MultiplexEntryRejectionDescriptions,
		&ett_h245_MultiplexEntrySendReject,
		&ett_h245_MultiplexEntrySendAck,
		&ett_h245_MultiplexElement,
		&ett_h245_MultiplexEntryDescriptor,
		&ett_h245_MultiplexEntrySend,
		&ett_h245_RequestChannelCloseRelease,
		&ett_h245_RequestChannelCloseReject,
		&ett_h245_RequestChannelCloseAck,
		&ett_h245_RequestChannelClose,
		&ett_h245_CloseLogicalChannelAck,
		&ett_h245_CloseLogicalChannel,
		&ett_h245_H2250LogicalChannelAckParameters,
		&ett_h245_OpenLogicalChannelReject,
		&ett_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters,
		&ett_h245_OpenLogicalChannelAck,
		&ett_h245_EscrowData,
		&ett_h245_EncryptionSync,
		&ett_h245_MulticastAddress_iP6Address,
		&ett_h245_MulticastAddress_iPAddress,
		&ett_h245_UnicastAddress_iPSourceRouteAddress,
		&ett_h245_UnicastAddress_iP6Address,
		&ett_h245_UnicastAddress_iPXAddress,
		&ett_h245_UnicastAddress_iPAddress,
		&ett_h245_FECData_rfc2733_mode_separateStream_samePort,
		&ett_h245_FECData_rfc2733_mode_separateStream_differentPort,
		&ett_h245_FECData_rfc2733,
		&ett_h245_MultiplePayloadStreamElement,
		&ett_h245_MultiplePayloadStream,
		&ett_h245_RedundancyEncodingElement,
		&ett_h245_RedundancyEncoding_rtpRedundancyEncoding,
		&ett_h245_RedundancyEncoding,
		&ett_h245_RTPPayloadType,
		&ett_h245_H2250LogicalChannelParameters,
		&ett_h245_V76HDLCParameters,
		&ett_h245_V76LogicalChannelParameters_mode_eRM,
		&ett_h245_V76LogicalChannelParameters,
		&ett_h245_H223AnnexCArqParameters,
		&ett_h245_H223AL3MParameters,
		&ett_h245_H223AL2MParameters,
		&ett_h245_H223AL1MParameters,
		&ett_h245_H223LogicalChannelParameters_adaptionLayerType_al3,
		&ett_h245_H223LogicalChannelParameters,
		&ett_h245_H222LogicalChannelParameters,
		&ett_h245_MultiplexedStreamParameter,
		&ett_h245_H235Media,
		&ett_h245_V75Parameters,
		&ett_h245_Q2931Address,
		&ett_h245_NetworkAccessParameters,
		&ett_h245_reverseLogicalChannelParameters,
		&ett_h245_forwardLogicalChannelParameters,
		&ett_h245_OpenLogicalChannel,
		&ett_h245_FECCapability_rfc2733_separateStream,
		&ett_h245_FECCapability_rfc2733,
		&ett_h245_MultiplePayloadStreamCapability,
		&ett_h245_NoPTAudioToneCapability,
		&ett_h245_NoPTAudioTelephonyEventCapability,
		&ett_h245_AudioToneCapability,
		&ett_h245_AudioTelephonyEventCapability,
		&ett_h245_MultiplexedStreamCapability,
		&ett_h245_GenericParameter,
		&ett_h245_GenericCapability,
		&ett_h245_ConferenceCapability,
		&ett_h245_IntegrityCapability,
		&ett_h245_AuthenticationCapability,
		&ett_h245_EncryptionAuthenticationAndIntegrity,
		&ett_h245_T38FaxTcpOptions,
		&ett_h245_T38FaxUdpOptions,
		&ett_h245_T38FaxProfile,
		&ett_h245_T84Profile_t84Restricted,
		&ett_h245_V42bis,
		&ett_h245_DataApplicationCapability_application_t38fax,
		&ett_h245_DataApplicationCapability_application_nlpid,
		&ett_h245_DataApplicationCapability_application_t84,
		&ett_h245_DataApplicationCapability,
		&ett_h245_VBDCapability,
		&ett_h245_GSMAudioCapability,
		&ett_h245_IS13818AudioCapability,
		&ett_h245_IS11172AudioCapability,
		&ett_h245_G7231AnnexCCapability_g723AnnexCAudioMode,
		&ett_h245_G7231AnnexCCapability,
		&ett_h245_G729Extensions,
		&ett_h245_AudioCapability_g7231,
		&ett_h245_IS11172VideoCapability,
		&ett_h245_H263Version3Options,
		&ett_h245_H263ModeComboFlags,
		&ett_h245_H263VideoModeCombos,
		&ett_h245_CustomPictureFormat_pixelAspectInformation_extendedPAR,
		&ett_h245_CustomPictureFormat_mPI_customPCF,
		&ett_h245_CustomPictureFormat_mPI,
		&ett_h245_CustomPictureFormat,
		&ett_h245_CustomPictureClockFrequency,
		&ett_h245_RefPictureSelection_enhancedReferencePicSelect_subPictureRemovalParameters,
		&ett_h245_RefPictureSelection_enhancedReferencePicSelect,
		&ett_h245_RefPictureSelection_additionalPictureMemory,
		&ett_h245_RefPictureSelection,
		&ett_h245_TransperencyParameters,
		&ett_h245_H263Options,
		&ett_h245_EnhancementOptions,
		&ett_h245_BEnhancementParameters,
		&ett_h245_EnhancementLayerInfo,
		&ett_h245_H263VideoCapability,
		&ett_h245_H262VideoCapability,
		&ett_h245_H261VideoCapability,
		&ett_h245_MediaDistributionCapability,
		&ett_h245_MultipointCapability,
		&ett_h245_RTPH263VideoRedundancyFrameMapping,
		&ett_h245_RTPH263VideoRedundancyEncoding,
		&ett_h245_RedundancyEncodingCapability,
		&ett_h245_TransportCapability,
		&ett_h245_MediaChannelCapability,
		&ett_h245_MediaTransportType_AtmAAL5Compressed,
		&ett_h245_QOSCapability,
		&ett_h245_ATMParameters,
		&ett_h245_RSVPParameters,
		&ett_h245_MediaPacketizationCapability,
		&ett_h245_H2250Capability_mcCapability,
		&ett_h245_H2250Capability,
		&ett_h245_V75Capability,
		&ett_h245_V76Capability,
		&ett_h245_H223AnnexCCapability,
		&ett_h245_H223Capability_mobileMultilinkFrameCapability,
		&ett_h245_H223Capability_mobileOperationTransmitCapability,
		&ett_h245_H223Capability_h223MultiplexTableCapability_enhanced,
		&ett_h245_H223Capability,
		&ett_h245_VCCapability_aal1ViaGateway,
		&ett_h245_VCCapability_availableBitRates_rangeOfBitRates,
		&ett_h245_VCCapability_availableBitRates,
		&ett_h245_VCCapability_aal5,
		&ett_h245_VCCapability_aal1,
		&ett_h245_VCCapability,
		&ett_h245_H222Capability,
		&ett_h245_H235SecurityCapability,
		&ett_h245_Capability_h233EncryptionReceiveCapability,
		&ett_h245_TerminalCapabilitySetRelease,
		&ett_h245_TerminalCapabilitySetReject,
		&ett_h245_TerminalCapabilitySetAck,
		&ett_h245_CapabilityDescriptor,
		&ett_h245_CapabilityTableEntry,
		&ett_h245_TerminalCapabilitySet,
		&ett_h245_MasterSlaveDeterminationRelease,
		&ett_h245_MasterSlaveDeterminationReject,
		&ett_h245_MasterSlaveDeterminationAck,
		&ett_h245_MasterSlaveDetermination,
		&ett_h245_h221NonStandard,
		&ett_h245_NonStandardParameter,
		&ett_h245_NonStandardMessage,
		&ett_h245_FlowControlIndication_restriction,
		&ett_h245_FlowControlIndication_scope,
		&ett_h245_UserInputIndication_userInputSupportIndication,
		&ett_h245_UserInputIndication,
		&ett_h245_NewATMVCIndication_reverseParameters_multiplex,
		&ett_h245_NewATMVCIndication_multiplex,
		&ett_h245_NewATMVCIndication_aal_aal1_errorCorrection,
		&ett_h245_NewATMVCIndication_aal_aal1_clockRecovery,
		&ett_h245_JitterIndication_scope,
		&ett_h245_MiscellaneousIndication_type,
		&ett_h245_ConferenceIndication,
		&ett_h245_FunctionNotSupported_cause,
		&ett_h245_FunctionNotUnderstood,
		&ett_h245_MobileMultilinkReconfigurationCommand_status,
		&ett_h245_NewATMVCCommand_reverseParameters_multiplex,
		&ett_h245_NewATMVCCommand_multiplex,
		&ett_h245_NewATMVCCommand_aal_aal1_errorCorrection,
		&ett_h245_NewATMVCCommand_aal_aal1_clockRecovery,
		&ett_h245_NewATMVCCommand_aal,
		&ett_h245_H223MultiplexReconfiguration_h223AnnexADoubleFlag,
		&ett_h245_H223MultiplexReconfiguration_h223ModeChange,
		&ett_h245_H223MultiplexReconfiguration,
		&ett_h245_PictureReference,
		&ett_h245_MiscellaneousCommand_type_progressiveRefinementStart_repeatCount,
		&ett_h245_MiscellaneousCommand_type,
		&ett_h245_ConferenceCommand,
		&ett_h245_EndSessionCommand_gstnOptions,
		&ett_h245_EndSessionCommand_isdnOptions,
		&ett_h245_FlowControlCommand_restriction,
		&ett_h245_FlowControlCommand_scope,
		&ett_h245_EncryptionCommand,
		&ett_h245_SendTerminalCapabilitySet,
		&ett_h245_LogicalChannelRateRejectReason,
		&ett_h245_DialingInformationNetworkType,
		&ett_h245_DialingInformation,
		&ett_h245_MultilinkIndication,
		&ett_h245_MultilinkResponse_addConnection_responseCode_rejected,
		&ett_h245_MultilinkResponse_addConnection_responseCode,
		&ett_h245_MultilinkResponse,
		&ett_h245_MultilinkRequest_maximumHeaderInterval_requestType,
		&ett_h245_MultilinkRequest,
		&ett_h245_RemoteMCResponse_reject,
		&ett_h245_RemoteMCResponse,
		&ett_h245_RemoteMCRequest,
		&ett_h245_ConferenceResponse_sendThisSourceResponse,
		&ett_h245_ConferenceResponse_makeTerminalBroadcasterResponse,
		&ett_h245_ConferenceResponse_broadcastMyLogicalChannelResponse,
		&ett_h245_ConferenceResponse_makeMeChairResponse,
		&ett_h245_ConferenceResponse,
		&ett_h245_ConferenceRequest,
		&ett_h245_CommunicationModeTableEntry_dataType,
		&ett_h245_CommunicationModeResponse,
		&ett_h245_MaintenanceLoopReject_cause,
		&ett_h245_MaintenanceLoopReject_type,
		&ett_h245_MaintenanceLoopAck_type,
		&ett_h245_MaintenanceLoopRequest_type,
		&ett_h245_EncryptionMode,
		&ett_h245_DataMode_application,
		&ett_h245_IS13818AudioMode_multiChannelType,
		&ett_h245_IS13818AudioMode_audioSampling,
		&ett_h245_IS13818AudioMode_audioLayer,
		&ett_h245_IS11172AudioMode_multichannelType,
		&ett_h245_IS11172AudioMode_audioSampling,
		&ett_h245_IS11172AudioMode_audioLayer,
		&ett_h245_AudioMode_g7231,
		&ett_h245_AudioMode,
		&ett_h245_H263VideoMode_resolution,
		&ett_h245_H262VideoMode_profileAndLevel,
		&ett_h245_H261VideoMode_resolution,
		&ett_h245_VideoMode,
		&ett_h245_RedundancyEncodingMode_secondaryEncoding,
		&ett_h245_V76ModeParameters,
		&ett_h245_H223ModeParameters_adaptationLayerType,
		&ett_h245_FECMode_rfc2733Mode_mode_separateStream,
		&ett_h245_FECMode_rfc2733Mode_mode,
		&ett_h245_FECMode,
		&ett_h245_RedundancyEncodingDTModeElement_type,
		&ett_h245_H235Mode_mediaMode,
		&ett_h245_ModeElementType,
		&ett_h245_RequestModeReject_cause,
		&ett_h245_RequestMultiplexEntryRejectionDescriptions_cause,
		&ett_h245_MultiplexEntryRejectionDescriptions_cause,
		&ett_h245_MultiplexElement_repeatCount,
		&ett_h245_MultiplexElement_type,
		&ett_h245_RequestChannelCloseReject_cause,
		&ett_h245_RequestChannelClose_reason,
		&ett_h245_CloseLogicalChannel_reason,
		&ett_h245_CloseLogicalChannel_source,
		&ett_h245_OpenLogicalChannelReject_cause,
		&ett_h245_forwardMultiplexAckParameters,
		&ett_h245_OpenLogicalChannelAck_reverseLogicalChannelParameters_multiplexParameters,
		&ett_h245_MulticastAddress,
		&ett_h245_UnicastAddress_iPSourceRouteAddress_routing,
		&ett_h245_UnicastAddress,
		&ett_h245_TransportAddress,
		&ett_h245_FECData_rfc2733_mode_separateStream,
		&ett_h245_FECData_rfc2733_mode,
		&ett_h245_FECData,
		&ett_h245_RTPPayloadType_payloadDescriptor,
		&ett_h245_H2250LogicalChannelParameters_mediaPacketization,
		&ett_h245_CRCLength,
		&ett_h245_V76LogicalChannelParameters_mode_eRM_recovery,
		&ett_h245_V76LogicalChannelParameters_mode,
		&ett_h245_V76LogicalChannelParameters_suspendResume,
		&ett_h245_H223AnnexCArqParameters_numberOfRetransmissions,
		&ett_h245_H223AL3MParameters_arqType,
		&ett_h245_H223AL3MParameters_crcLength,
		&ett_h245_H223AL3MParameters_headerFormat,
		&ett_h245_H223AL2MParameters_headerFEC,
		&ett_h245_H223AL1MParameters_arqType,
		&ett_h245_H223AL1MParameters_crcLength,
		&ett_h245_H223AL1MParameters_headerFEC,
		&ett_h245_H223AL1MParameters_transferMode,
		&ett_h245_H223LogicalChannelParameters_adaptationLayerType,
		&ett_h245_H235Media_mediaType,
		&ett_h245_DataType,
		&ett_h245_Q2931Address_address,
		&ett_h245_NetworkAccessParameters_t120SetupProcedure,
		&ett_h245_NetworkAccessParameters_networkAddress,
		&ett_h245_NetworkAccessParameters_distribution,
		&ett_h245_reverseLogicalChannelParameters_multiplexParameters,
		&ett_h245_forwardLogicalChannelParameters_multiplexParameters,
		&ett_h245_FECCapability,
		&ett_h245_MultiplexFormat,
		&ett_h245_ParameterValue,
		&ett_h245_ParameterIdentifier,
		&ett_h245_CapabilityIdentifier,
		&ett_h245_UserInputCapability,
		&ett_h245_MediaEncryptionAlgorithm,
		&ett_h245_T38FaxUdpOptions_t38FaxUdpEC,
		&ett_h245_T38FaxRateManagement,
		&ett_h245_T84Profile,
		&ett_h245_CompressionType,
		&ett_h245_DataProtocolCapability_v76wCompression,
		&ett_h245_DataProtocolCapability,
		&ett_h245_DataApplicationCapability_application,
		&ett_h245_AudioCapability,
		&ett_h245_CustomPictureFormat_pixelAspectInformation,
		&ett_h245_RefPictureSelection_videoBackChannelSend,
		&ett_h245_VideoCapability,
		&ett_h245_RTPH263VideoRedundancyEncoding_frameToThreadMapping,
		&ett_h245_RedundancyEncodingMethod,
		&ett_h245_MediaTransportType,
		&ett_h245_QOSMode,
		&ett_h245_H223Capability_h223MultiplexTableCapability,
		&ett_h245_VCCapability_availableBitRates_type,
		&ett_h245_MultiplexCapability,
		&ett_h245_Capability,
		&ett_h245_TerminalCapabilitySetReject_cause_tableEntryCapacityExceeded,
		&ett_h245_TerminalCapabilitySetReject_cause,
		&ett_h245_MasterSlaveDeterminationReject_cause,
		&ett_h245_MasterSlaveDeterminationAck_decision,
		&ett_h245_RequestModeAck_response_decision,
		&ett_h245_NonStandardIdentifier,
		&ett_h245_mediaDistributionCapability,
		&ett_h245_AlternativeCapabilitySet,
		&ett_h245_CapabilityTableEntryNumber_sequence_of,
		&ett_h245_frameToThreadMapping_custom,
		&ett_h245_RedundancyEncodingCapability_sequence_of,
		&ett_h245_frameSequence,
		&ett_h245_EncryptionCapability,
		&ett_h245_escrowentry,
		&ett_h245_elementList,
		&ett_h245_requestedModes,
		&ett_h245_CertSelectionCriteria,
		&ett_h245_capabilityTable,
		&ett_h245_capabilityDescriptors,
		&ett_h245_simultaneousCapabilities,
		&ett_h245_gatewayAddress,
		&ett_h245_snrEnhancement,
		&ett_h245_spatialEnhancement,
		&ett_h245_bPictureEnhancement,
		&ett_h245_customPictureClockFrequency,
		&ett_h245_customPictureFormat,
		&ett_h245_modeCombos,
		&ett_h245_customPCF,
		&ett_h245_pixelAspectCode,
		&ett_h245_extendedPAR,
		&ett_h245_h263VideoCoupledModes,
		&ett_h245_capabilityOnMuxStream,
		&ett_h245_capabilities,
		&ett_h245_multiplexEntryDescriptors,
		&ett_h245_multiplexTableEntryNumber_set_of,
		&ett_h245_VCCapability_set_of,
		&ett_h245_rejectionDescriptions,
		&ett_h245_entryNumbers,
		&ett_h245_ModeDescription,
		&ett_h245_communicationModeTable,
		&ett_h245_terminalListResponse,
		&ett_h245_differential,
		&ett_h245_networkType,
		&ett_h245_capabilityTableEntryNumbers,
		&ett_h245_capabilityDescriptorNumbers,
		&ett_h245_qOSCapabilities,
		&ett_h245_subElementList,
		&ett_h245_containedThreads,
		&ett_h245_mediaChannelCapabilities,
		&ett_h245_rtpPayloadType_sequence_of,
		&ett_h245_centralizedData,
		&ett_h245_distributedData,
		&ett_h245_nonStandardData,
		&ett_h245_collapsing,
		&ett_h245_nonCollapsing,
		&ett_h245_supersedes,
		&ett_h245_genericParameter,
		&ett_h245_secondary_REE,
		&ett_h245_elements_MPSE,
		&ett_h245_secondary_REDTME,
		&ett_h245_elements_MPSEM,
		&ett_h245_TerminalInformationSO,
		&ett_h245_lostPicture,
		&ett_h245_recoveryReferencePicture,
		&ett_h245_iPSourceRouteAddress_route,
	};
	module_t *h245_module;

	proto_h245 = proto_register_protocol("H245", "H245", "h245");
	proto_register_field_array(proto_h245, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	h245_module = prefs_register_protocol(proto_h245, NULL);
	prefs_register_bool_preference(h245_module, "reassembly",
		"Reassemble H.245 over TCP",
		"Whether the dissector should reassemble H.245 PDUs spanning multiple TCP segments",
		&h245_reassembly);
	prefs_register_bool_preference(h245_module, "shorttypes",
		"Show short message types",
		"Whether the dissector should show short names or the long names from the standard",
		&h245_shorttypes);
	register_dissector("h245dg", dissect_h245_MultimediaSystemControlMessage, proto_h245);
	register_dissector("h245", dissect_h245, proto_h245);

	nsp_object_dissector_table = register_dissector_table("h245.nsp.object", "H.245 NonStandardParameter (object)", FT_STRING, BASE_NONE);
	nsp_h221_dissector_table = register_dissector_table("h245.nsp.h221", "H.245 NonStandardParameter (h221)", FT_UINT32, BASE_HEX);
}

void
proto_reg_handoff_h245(void)
{
	rtp_handle = find_dissector("rtp");
	rtcp_handle = find_dissector("rtcp");

	h245_handle=create_dissector_handle(dissect_h245, proto_h245);
	dissector_add_handle("tcp.port", h245_handle);
	MultimediaSystemControlMessage_handle=create_dissector_handle(dissect_h245_MultimediaSystemControlMessage, proto_h245);
	dissector_add_handle("udp.port", MultimediaSystemControlMessage_handle);
}
