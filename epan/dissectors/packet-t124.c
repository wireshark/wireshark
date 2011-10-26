/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-t124.c                                                              */
/* ../../tools/asn2wrs.py -p t124 -c ./t124.cnf -s ./packet-t124-template -D . -O ../../epan/dissectors GCC-PROTOCOL.asn MCS-PROTOCOL.asn */

/* Input file: packet-t124-template.c */

#line 1 "../../asn1/t124/packet-t124-template.c"
/* packet-t124.c
 * Routines for t124 packet dissection
 * Copyright 2010, Graeme Lunt
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <epan/asn1.h>
#include "packet-per.h"
#include "packet-ber.h"
#include "packet-t124.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "GENERIC-CONFERENCE-CONTROL T.124"
#define PSNAME "T.124"
#define PFNAME "t124"

/* Initialize the protocol and registered fields */
static int proto_t124 = -1;
static proto_tree *top_tree = NULL;


/*--- Included file: packet-t124-hf.c ---*/
#line 1 "../../asn1/t124/packet-t124-hf.c"
static int hf_t124_object = -1;                   /* T_object */
static int hf_t124_h221NonStandard = -1;          /* H221NonStandardIdentifier */
static int hf_t124_key = -1;                      /* Key */
static int hf_t124_data = -1;                     /* OCTET_STRING */
static int hf_t124_UserData_item = -1;            /* UserData_item */
static int hf_t124_value = -1;                    /* T_value */
static int hf_t124_numeric = -1;                  /* SimpleNumericString */
static int hf_t124_text = -1;                     /* SimpleTextString */
static int hf_t124_unicodeText = -1;              /* TextString */
static int hf_t124_passwordString = -1;           /* PasswordSelector */
static int hf_t124_responseData = -1;             /* UserData */
static int hf_t124_passwordInTheClear = -1;       /* NULL */
static int hf_t124_nonStandardAlgorithm = -1;     /* NonStandardParameter */
static int hf_t124_responseAlgorithm = -1;        /* ChallengeResponseAlgorithm */
static int hf_t124_challengeData = -1;            /* UserData */
static int hf_t124_challengeTag = -1;             /* INTEGER */
static int hf_t124_challengeSet = -1;             /* SET_OF_ChallengeItem */
static int hf_t124_challengeSet_item = -1;        /* ChallengeItem */
static int hf_t124_responseItem = -1;             /* ChallengeResponseItem */
static int hf_t124_passwordInTheClear_01 = -1;    /* PasswordSelector */
static int hf_t124_challengeRequestResponse = -1;  /* T_challengeRequestResponse */
static int hf_t124_challengeRequest = -1;         /* ChallengeRequest */
static int hf_t124_challengeResponse = -1;        /* ChallengeResponse */
static int hf_t124_nonStandardScheme = -1;        /* NonStandardParameter */
static int hf_t124_priority = -1;                 /* INTEGER_0_65535 */
static int hf_t124_scheme = -1;                   /* ConferencePriorityScheme */
static int hf_t124_conventional = -1;             /* NULL */
static int hf_t124_counted = -1;                  /* NULL */
static int hf_t124_anonymous = -1;                /* NULL */
static int hf_t124_nonStandardCategory = -1;      /* NonStandardParameter */
static int hf_t124_conventional_only = -1;        /* NULL */
static int hf_t124_counted_only = -1;             /* NULL */
static int hf_t124_anonymous_only = -1;           /* NULL */
static int hf_t124_conventional_control = -1;     /* NULL */
static int hf_t124_unrestricted_mode = -1;        /* NULL */
static int hf_t124_non_standard_mode = -1;        /* NonStandardParameter */
static int hf_t124_NetworkAddress_item = -1;      /* NetworkAddress_item */
static int hf_t124_aggregatedChannel = -1;        /* T_aggregatedChannel */
static int hf_t124_transferModes = -1;            /* T_transferModes */
static int hf_t124_speech = -1;                   /* BOOLEAN */
static int hf_t124_voice_band = -1;               /* BOOLEAN */
static int hf_t124_digital_56k = -1;              /* BOOLEAN */
static int hf_t124_digital_64k = -1;              /* BOOLEAN */
static int hf_t124_digital_128k = -1;             /* BOOLEAN */
static int hf_t124_digital_192k = -1;             /* BOOLEAN */
static int hf_t124_digital_256k = -1;             /* BOOLEAN */
static int hf_t124_digital_320k = -1;             /* BOOLEAN */
static int hf_t124_digital_384k = -1;             /* BOOLEAN */
static int hf_t124_digital_512k = -1;             /* BOOLEAN */
static int hf_t124_digital_768k = -1;             /* BOOLEAN */
static int hf_t124_digital_1152k = -1;            /* BOOLEAN */
static int hf_t124_digital_1472k = -1;            /* BOOLEAN */
static int hf_t124_digital_1536k = -1;            /* BOOLEAN */
static int hf_t124_digital_1920k = -1;            /* BOOLEAN */
static int hf_t124_packet_mode = -1;              /* BOOLEAN */
static int hf_t124_frame_mode = -1;               /* BOOLEAN */
static int hf_t124_atm = -1;                      /* BOOLEAN */
static int hf_t124_internationalNumber = -1;      /* DiallingString */
static int hf_t124_subAddress = -1;               /* SubAddressString */
static int hf_t124_extraDialling = -1;            /* ExtraDiallingString */
static int hf_t124_highLayerCompatibility = -1;   /* T_highLayerCompatibility */
static int hf_t124_telephony3kHz = -1;            /* BOOLEAN */
static int hf_t124_telephony7kHz = -1;            /* BOOLEAN */
static int hf_t124_videotelephony = -1;           /* BOOLEAN */
static int hf_t124_videoconference = -1;          /* BOOLEAN */
static int hf_t124_audiographic = -1;             /* BOOLEAN */
static int hf_t124_audiovisual = -1;              /* BOOLEAN */
static int hf_t124_multimedia = -1;               /* BOOLEAN */
static int hf_t124_transportConnection = -1;      /* T_transportConnection */
static int hf_t124_nsapAddress = -1;              /* OCTET_STRING_SIZE_1_20 */
static int hf_t124_transportSelector = -1;        /* OCTET_STRING */
static int hf_t124_nonStandard = -1;              /* NonStandardParameter */
static int hf_t124_audio = -1;                    /* BOOLEAN */
static int hf_t124_video = -1;                    /* BOOLEAN */
static int hf_t124_data_01 = -1;                  /* BOOLEAN */
static int hf_t124_h221 = -1;                     /* NULL */
static int hf_t124_h244 = -1;                     /* NULL */
static int hf_t124_iso_iec_13871 = -1;            /* NULL */
static int hf_t124_simpleProfile = -1;            /* T_simpleProfile */
static int hf_t124_speech_01 = -1;                /* NULL */
static int hf_t124_telephony_3kHz = -1;           /* NULL */
static int hf_t124_telephony_7kHz = -1;           /* NULL */
static int hf_t124_voice_band_01 = -1;            /* NULL */
static int hf_t124_frameRelay = -1;               /* NULL */
static int hf_t124_t123_pstn_basic = -1;          /* NULL */
static int hf_t124_t123_psdn_basic = -1;          /* NULL */
static int hf_t124_t123_b_isdn_basic = -1;        /* NULL */
static int hf_t124_multimediaProfile = -1;        /* T_multimediaProfile */
static int hf_t124_profile = -1;                  /* T_profile */
static int hf_t124_h310 = -1;                     /* NULL */
static int hf_t124_h320 = -1;                     /* NULL */
static int hf_t124_h321 = -1;                     /* NULL */
static int hf_t124_h322 = -1;                     /* NULL */
static int hf_t124_h323 = -1;                     /* NULL */
static int hf_t124_h324 = -1;                     /* NULL */
static int hf_t124_h324m = -1;                    /* NULL */
static int hf_t124_asvd = -1;                     /* NULL */
static int hf_t124_dsvd = -1;                     /* NULL */
static int hf_t124_t120Data = -1;                 /* BOOLEAN */
static int hf_t124_dsmccDownloadProfile = -1;     /* NULL */
static int hf_t124_networkAddress = -1;           /* ExtendedE164NetworkAddress */
static int hf_t124_iSDNCircuitTypes = -1;         /* ISDNCircuitTypes */
static int hf_t124_iSDNCircuitTypes_item = -1;    /* ISDNCircuitTypes_item */
static int hf_t124_digital_64k_01 = -1;           /* NULL */
static int hf_t124_digital_2x64k = -1;            /* NULL */
static int hf_t124_digital_384k_01 = -1;          /* NULL */
static int hf_t124_digital_1536 = -1;             /* NULL */
static int hf_t124_digital_1920k_01 = -1;         /* NULL */
static int hf_t124_multirate_base_64k = -1;       /* INTEGER_1_30 */
static int hf_t124_iSDNHighLayerCompatibility = -1;  /* ISDNHighLayerCompatibility */
static int hf_t124_circuitTypes = -1;             /* T_circuitTypes */
static int hf_t124_circuitTypes_item = -1;        /* T_circuitTypes_item */
static int hf_t124_digital_56k_01 = -1;           /* NULL */
static int hf_t124_pSDNNetworkAddress = -1;       /* PSDNNetworkAddress */
static int hf_t124_extendedE164NetworkAddress = -1;  /* ExtendedE164NetworkAddress */
static int hf_t124_transportAddress = -1;         /* TransportAddress */
static int hf_t124_networkAddress_01 = -1;        /* T_networkAddress */
static int hf_t124_extendedE164 = -1;             /* ExtendedE164NetworkAddress */
static int hf_t124_nsapAddress_01 = -1;           /* TransportAddress */
static int hf_t124_maxTransferRate = -1;          /* INTEGER_0_MAX */
static int hf_t124_gstnConnection = -1;           /* GSTNConnection */
static int hf_t124_isdnConnection = -1;           /* ISDNConnection */
static int hf_t124_csdnConnection = -1;           /* CSDNConnection */
static int hf_t124_psdnConnection = -1;           /* PSDNConnection */
static int hf_t124_atmConnection = -1;            /* ATMConnection */
static int hf_t124_NetworkAddressV2_item = -1;    /* NetworkAddressV2_item */
static int hf_t124_networkConnection = -1;        /* T_networkConnection */
static int hf_t124_singleConnection = -1;         /* NetworkConnection */
static int hf_t124_aggregatedConnections = -1;    /* T_aggregatedConnections */
static int hf_t124_connectionList = -1;           /* T_connectionList */
static int hf_t124_connectionList_item = -1;      /* T_connectionList_item */
static int hf_t124_aggregationMethods = -1;       /* SET_OF_ChannelAggregationMethod */
static int hf_t124_aggregationMethods_item = -1;  /* ChannelAggregationMethod */
static int hf_t124_profiles = -1;                 /* SET_OF_Profile */
static int hf_t124_profiles_item = -1;            /* Profile */
static int hf_t124_mediaConcerned = -1;           /* MediaList */
static int hf_t124_managementDevice = -1;         /* BOOLEAN */
static int hf_t124_peripheralDevice = -1;         /* BOOLEAN */
static int hf_t124_callingNode = -1;              /* NULL */
static int hf_t124_calledNode = -1;               /* NULL */
static int hf_t124_unknown = -1;                  /* INTEGER_0_4294967295 */
static int hf_t124_h243NodeID = -1;               /* OCTET_STRING_SIZE_2 */
static int hf_t124_conferenceName = -1;           /* ConferenceName */
static int hf_t124_conferenceNameModifier = -1;   /* ConferenceNameModifier */
static int hf_t124_conferenceDescription = -1;    /* TextString */
static int hf_t124_lockedConference = -1;         /* BOOLEAN */
static int hf_t124_passwordInTheClearRequired = -1;  /* BOOLEAN */
static int hf_t124_networkAddress_02 = -1;        /* NetworkAddress */
static int hf_t124_defaultConferenceFlag = -1;    /* BOOLEAN */
static int hf_t124_conferenceMode = -1;           /* ConferenceMode */
static int hf_t124_superiorNode = -1;             /* UserID */
static int hf_t124_nodeType = -1;                 /* NodeType */
static int hf_t124_nodeProperties = -1;           /* NodeProperties */
static int hf_t124_nodeName = -1;                 /* TextString */
static int hf_t124_participantsList = -1;         /* SEQUENCE_OF_TextString */
static int hf_t124_participantsList_item = -1;    /* TextString */
static int hf_t124_siteInformation = -1;          /* TextString */
static int hf_t124_alternativeNodeID = -1;        /* AlternativeNodeID */
static int hf_t124_userData = -1;                 /* UserData */
static int hf_t124_nodeCategory = -1;             /* NodeCategory */
static int hf_t124_networkAddressV2 = -1;         /* NetworkAddressV2 */
static int hf_t124_applicationProtocolKey = -1;   /* Key */
static int hf_t124_sessionID = -1;                /* ChannelID */
static int hf_t124_applicationActive = -1;        /* BOOLEAN */
static int hf_t124_conductingOperationCapable = -1;  /* BOOLEAN */
static int hf_t124_startupChannel = -1;           /* ChannelType */
static int hf_t124_applicationUserID = -1;        /* UserID */
static int hf_t124_nonCollapsingCapabilities = -1;  /* T_nonCollapsingCapabilities */
static int hf_t124_nonCollapsingCapabilities_item = -1;  /* T_nonCollapsingCapabilities_item */
static int hf_t124_capabilityID = -1;             /* CapabilityID */
static int hf_t124_applicationData = -1;          /* OCTET_STRING */
static int hf_t124_standard = -1;                 /* INTEGER_0_65535 */
static int hf_t124_nonStandard_01 = -1;           /* Key */
static int hf_t124_logical = -1;                  /* NULL */
static int hf_t124_unsignedMin = -1;              /* INTEGER_0_MAX */
static int hf_t124_unsignedMax = -1;              /* INTEGER_0_MAX */
static int hf_t124_sessionKey = -1;               /* SessionKey */
static int hf_t124_expectedCapabilitySet = -1;    /* T_expectedCapabilitySet */
static int hf_t124_expectedCapabilitySet_item = -1;  /* T_expectedCapabilitySet_item */
static int hf_t124_capabilityClass = -1;          /* CapabilityClass */
static int hf_t124_mandatoryFlag = -1;            /* BOOLEAN */
static int hf_t124_resourceID = -1;               /* OCTET_STRING_SIZE_0_64 */
static int hf_t124_channelID = -1;                /* DynamicChannelID */
static int hf_t124_tokenID = -1;                  /* DynamicTokenID */
static int hf_t124_parameter = -1;                /* OCTET_STRING_SIZE_0_64 */
static int hf_t124_vacant = -1;                   /* NULL */
static int hf_t124_owned = -1;                    /* T_owned */
static int hf_t124_nodeID = -1;                   /* UserID */
static int hf_t124_entityID = -1;                 /* EntityID */
static int hf_t124_notOwned = -1;                 /* NULL */
static int hf_t124_convenerPassword = -1;         /* Password */
static int hf_t124_password = -1;                 /* Password */
static int hf_t124_listedConference = -1;         /* BOOLEAN */
static int hf_t124_conductibleConference = -1;    /* BOOLEAN */
static int hf_t124_terminationMethod = -1;        /* TerminationMethod */
static int hf_t124_conductorPrivileges = -1;      /* SET_OF_Privilege */
static int hf_t124_conductorPrivileges_item = -1;  /* Privilege */
static int hf_t124_conductedPrivileges = -1;      /* SET_OF_Privilege */
static int hf_t124_conductedPrivileges_item = -1;  /* Privilege */
static int hf_t124_nonConductedPrivileges = -1;   /* SET_OF_Privilege */
static int hf_t124_nonConductedPrivileges_item = -1;  /* Privilege */
static int hf_t124_callerIdentifier = -1;         /* TextString */
static int hf_t124_conferencePriority = -1;       /* ConferencePriority */
static int hf_t124_tag = -1;                      /* INTEGER */
static int hf_t124_result = -1;                   /* T_result */
static int hf_t124_asymmetryIndicator = -1;       /* AsymmetryIndicator */
static int hf_t124_conferenceList = -1;           /* SET_OF_ConferenceDescriptor */
static int hf_t124_conferenceList_item = -1;      /* ConferenceDescriptor */
static int hf_t124_queryResponseResult = -1;      /* QueryResponseResult */
static int hf_t124_waitForInvitationFlag = -1;    /* BOOLEAN */
static int hf_t124_noUnlistedConferenceFlag = -1;  /* BOOLEAN */
static int hf_t124_conferenceName_01 = -1;        /* ConferenceNameSelector */
static int hf_t124_password_01 = -1;              /* PasswordChallengeRequestResponse */
static int hf_t124_convenerPassword_01 = -1;      /* PasswordSelector */
static int hf_t124_topNodeID = -1;                /* UserID */
static int hf_t124_conferenceNameAlias = -1;      /* ConferenceNameSelector */
static int hf_t124_joinResponseResult = -1;       /* JoinResponseResult */
static int hf_t124_inviteResponseResult = -1;     /* InviteResponseResult */
static int hf_t124_requestingNode = -1;           /* UserID */
static int hf_t124_addingMCU = -1;                /* UserID */
static int hf_t124_terminateRequestReason = -1;   /* TerminateRequestReason */
static int hf_t124_nodeToEject = -1;              /* UserID */
static int hf_t124_ejectUserRequestReason = -1;   /* EjectUserRequestReason */
static int hf_t124_transferringNodes = -1;        /* SET_SIZE_1_65536_OF_UserID */
static int hf_t124_transferringNodes_item = -1;   /* UserID */
static int hf_t124_password_02 = -1;              /* PasswordSelector */
static int hf_t124_key_01 = -1;                   /* RegistryKey */
static int hf_t124_modificationRights = -1;       /* RegistryModificationRights */
static int hf_t124_numberOfHandles = -1;          /* INTEGER_1_1024 */
static int hf_t124_data_02 = -1;                  /* NonStandardParameter */
static int hf_t124_t124Identifier = -1;           /* Key */
static int hf_t124_connectPDU = -1;               /* T_connectPDU */
static int hf_t124_conferenceCreateRequest = -1;  /* ConferenceCreateRequest */
static int hf_t124_conferenceCreateResponse = -1;  /* ConferenceCreateResponse */
static int hf_t124_conferenceQueryRequest = -1;   /* ConferenceQueryRequest */
static int hf_t124_conferenceQueryResponse = -1;  /* ConferenceQueryResponse */
static int hf_t124_conferenceJoinRequest = -1;    /* ConferenceJoinRequest */
static int hf_t124_conferenceJoinResponse = -1;   /* ConferenceJoinResponse */
static int hf_t124_conferenceInviteRequest = -1;  /* ConferenceInviteRequest */
static int hf_t124_conferenceInviteResponse = -1;  /* ConferenceInviteResponse */
static int hf_t124_conferenceAddRequest = -1;     /* ConferenceAddRequest */
static int hf_t124_conferenceLockRequest = -1;    /* ConferenceLockRequest */
static int hf_t124_conferenceUnlockRequest = -1;  /* ConferenceUnlockRequest */
static int hf_t124_conferenceTerminateRequest = -1;  /* ConferenceTerminateRequest */
static int hf_t124_conferenceEjectUserRequest = -1;  /* ConferenceEjectUserRequest */
static int hf_t124_conferenceTransferRequest = -1;  /* ConferenceTransferRequest */
static int hf_t124_registryRegisterChannelRequest = -1;  /* RegistryRegisterChannelRequest */
static int hf_t124_registryAssignTokenRequest = -1;  /* RegistryAssignTokenRequest */
static int hf_t124_registrySetParameterRequest = -1;  /* RegistrySetParameterRequest */
static int hf_t124_registryRetrieveEntryRequest = -1;  /* RegistryRetrieveEntryRequest */
static int hf_t124_registryDeleteEntryRequest = -1;  /* RegistryDeleteEntryRequest */
static int hf_t124_registryMonitorEntryRequest = -1;  /* RegistryMonitorEntryRequest */
static int hf_t124_registryAllocateHandleRequest = -1;  /* RegistryAllocateHandleRequest */
static int hf_t124_nonStandardRequest = -1;       /* NonStandardPDU */
static int hf_t124_maxChannelIds = -1;            /* INTEGER_0_MAX */
static int hf_t124_maxUserIds = -1;               /* INTEGER_0_MAX */
static int hf_t124_maxTokenIds = -1;              /* INTEGER_0_MAX */
static int hf_t124_numPriorities = -1;            /* INTEGER_0_MAX */
static int hf_t124_minThroughput = -1;            /* INTEGER_0_MAX */
static int hf_t124_maxHeight = -1;                /* INTEGER_0_MAX */
static int hf_t124_maxMCSPDUsize = -1;            /* INTEGER_0_MAX */
static int hf_t124_protocolVersion = -1;          /* INTEGER_0_MAX */
static int hf_t124_heightLimit = -1;              /* INTEGER_0_MAX */
static int hf_t124_subHeight = -1;                /* INTEGER_0_MAX */
static int hf_t124_subInterval = -1;              /* INTEGER_0_MAX */
static int hf_t124_static = -1;                   /* T_static */
static int hf_t124_channelId = -1;                /* StaticChannelId */
static int hf_t124_userId = -1;                   /* T_userId */
static int hf_t124_joined = -1;                   /* BOOLEAN */
static int hf_t124_userId_01 = -1;                /* UserId */
static int hf_t124_private = -1;                  /* T_private */
static int hf_t124_channelId_01 = -1;             /* PrivateChannelId */
static int hf_t124_manager = -1;                  /* UserId */
static int hf_t124_admitted = -1;                 /* SET_OF_UserId */
static int hf_t124_admitted_item = -1;            /* UserId */
static int hf_t124_assigned = -1;                 /* T_assigned */
static int hf_t124_channelId_02 = -1;             /* AssignedChannelId */
static int hf_t124_mergeChannels = -1;            /* SET_OF_ChannelAttributes */
static int hf_t124_mergeChannels_item = -1;       /* ChannelAttributes */
static int hf_t124_purgeChannelIds = -1;          /* SET_OF_ChannelId */
static int hf_t124_purgeChannelIds_item = -1;     /* ChannelId */
static int hf_t124_detachUserIds = -1;            /* SET_OF_UserId */
static int hf_t124_detachUserIds_item = -1;       /* UserId */
static int hf_t124_grabbed = -1;                  /* T_grabbed */
static int hf_t124_tokenId = -1;                  /* TokenId */
static int hf_t124_grabber = -1;                  /* UserId */
static int hf_t124_inhibited = -1;                /* T_inhibited */
static int hf_t124_inhibitors = -1;               /* SET_OF_UserId */
static int hf_t124_inhibitors_item = -1;          /* UserId */
static int hf_t124_giving = -1;                   /* T_giving */
static int hf_t124_recipient = -1;                /* UserId */
static int hf_t124_ungivable = -1;                /* T_ungivable */
static int hf_t124_given = -1;                    /* T_given */
static int hf_t124_mergeTokens = -1;              /* SET_OF_TokenAttributes */
static int hf_t124_mergeTokens_item = -1;         /* TokenAttributes */
static int hf_t124_purgeTokenIds = -1;            /* SET_OF_TokenId */
static int hf_t124_purgeTokenIds_item = -1;       /* TokenId */
static int hf_t124_reason = -1;                   /* Reason */
static int hf_t124_diagnostic = -1;               /* Diagnostic */
static int hf_t124_initialOctets = -1;            /* OCTET_STRING */
static int hf_t124_result_01 = -1;                /* Result */
static int hf_t124_initiator = -1;                /* UserId */
static int hf_t124_userIds = -1;                  /* SET_OF_UserId */
static int hf_t124_userIds_item = -1;             /* UserId */
static int hf_t124_channelId_03 = -1;             /* ChannelId */
static int hf_t124_requested = -1;                /* ChannelId */
static int hf_t124_channelIds = -1;               /* SET_OF_ChannelId */
static int hf_t124_channelIds_item = -1;          /* ChannelId */
static int hf_t124_dataPriority = -1;             /* DataPriority */
static int hf_t124_segmentation = -1;             /* Segmentation */
static int hf_t124_userData_01 = -1;              /* T_userData */
static int hf_t124_userData_02 = -1;              /* T_userData_01 */
static int hf_t124_userData_03 = -1;              /* OCTET_STRING */
static int hf_t124_tokenStatus = -1;              /* TokenStatus */
static int hf_t124_plumbDomainIndication = -1;    /* PlumbDomainIndication */
static int hf_t124_erectDomainRequest = -1;       /* ErectDomainRequest */
static int hf_t124_mergeChannelsRequest = -1;     /* MergeChannelsRequest */
static int hf_t124_mergeChannelsConfirm = -1;     /* MergeChannelsConfirm */
static int hf_t124_purgeChannelsIndication = -1;  /* PurgeChannelsIndication */
static int hf_t124_mergeTokensRequest = -1;       /* MergeTokensRequest */
static int hf_t124_mergeTokensConfirm = -1;       /* MergeTokensConfirm */
static int hf_t124_purgeTokensIndication = -1;    /* PurgeTokensIndication */
static int hf_t124_disconnectProviderUltimatum = -1;  /* DisconnectProviderUltimatum */
static int hf_t124_rejectMCSPDUUltimatum = -1;    /* RejectMCSPDUUltimatum */
static int hf_t124_attachUserRequest = -1;        /* AttachUserRequest */
static int hf_t124_attachUserConfirm = -1;        /* AttachUserConfirm */
static int hf_t124_detachUserRequest = -1;        /* DetachUserRequest */
static int hf_t124_detachUserIndication = -1;     /* DetachUserIndication */
static int hf_t124_channelJoinRequest = -1;       /* ChannelJoinRequest */
static int hf_t124_channelJoinConfirm = -1;       /* ChannelJoinConfirm */
static int hf_t124_channelLeaveRequest = -1;      /* ChannelLeaveRequest */
static int hf_t124_channelConveneRequest = -1;    /* ChannelConveneRequest */
static int hf_t124_channelConveneConfirm = -1;    /* ChannelConveneConfirm */
static int hf_t124_channelDisbandRequest = -1;    /* ChannelDisbandRequest */
static int hf_t124_channelDisbandIndication = -1;  /* ChannelDisbandIndication */
static int hf_t124_channelAdmitRequest = -1;      /* ChannelAdmitRequest */
static int hf_t124_channelAdmitIndication = -1;   /* ChannelAdmitIndication */
static int hf_t124_channelExpelRequest = -1;      /* ChannelExpelRequest */
static int hf_t124_channelExpelIndication = -1;   /* ChannelExpelIndication */
static int hf_t124_sendDataRequest = -1;          /* SendDataRequest */
static int hf_t124_sendDataIndication = -1;       /* SendDataIndication */
static int hf_t124_uniformSendDataRequest = -1;   /* UniformSendDataRequest */
static int hf_t124_uniformSendDataIndication = -1;  /* UniformSendDataIndication */
static int hf_t124_tokenGrabRequest = -1;         /* TokenGrabRequest */
static int hf_t124_tokenGrabConfirm = -1;         /* TokenGrabConfirm */
static int hf_t124_tokenInhibitRequest = -1;      /* TokenInhibitRequest */
static int hf_t124_tokenInhibitConfirm = -1;      /* TokenInhibitConfirm */
static int hf_t124_tokenGiveRequest = -1;         /* TokenGiveRequest */
static int hf_t124_tokenGiveIndication = -1;      /* TokenGiveIndication */
static int hf_t124_tokenGiveResponse = -1;        /* TokenGiveResponse */
static int hf_t124_tokenGiveConfirm = -1;         /* TokenGiveConfirm */
static int hf_t124_tokenPleaseRequest = -1;       /* TokenPleaseRequest */
static int hf_t124_tokenPleaseIndication = -1;    /* TokenPleaseIndication */
static int hf_t124_tokenReleaseRequest = -1;      /* TokenReleaseRequest */
static int hf_t124_tokenReleaseConfirm = -1;      /* TokenReleaseConfirm */
static int hf_t124_tokenTestRequest = -1;         /* TokenTestRequest */
static int hf_t124_tokenTestConfirm = -1;         /* TokenTestConfirm */
/* named bits */
static int hf_t124_Segmentation_begin = -1;
static int hf_t124_Segmentation_end = -1;

/*--- End of included file: packet-t124-hf.c ---*/
#line 54 "../../asn1/t124/packet-t124-template.c"

/* Initialize the subtree pointers */
static int ett_t124 = -1;
static int ett_t124_connectGCCPDU = -1;

static int hf_t124_ConnectData = -1;
static int hf_t124_connectGCCPDU = -1;
static int hf_t124_DomainMCSPDU_PDU = -1;

static guint32 channelId = -1;

static const char *t124Identifier = NULL; /* extensions identifier */
static tvbuff_t *t124NSIdentifier = NULL; /* extensions non-standard identifier */
static dissector_table_t t124_ns_dissector_table=NULL;
static dissector_table_t t124_sd_dissector_table=NULL;


/*--- Included file: packet-t124-ett.c ---*/
#line 1 "../../asn1/t124/packet-t124-ett.c"
static gint ett_t124_Key = -1;
static gint ett_t124_NonStandardParameter = -1;
static gint ett_t124_UserData = -1;
static gint ett_t124_UserData_item = -1;
static gint ett_t124_Password = -1;
static gint ett_t124_PasswordSelector = -1;
static gint ett_t124_ChallengeResponseItem = -1;
static gint ett_t124_ChallengeResponseAlgorithm = -1;
static gint ett_t124_ChallengeItem = -1;
static gint ett_t124_ChallengeRequest = -1;
static gint ett_t124_SET_OF_ChallengeItem = -1;
static gint ett_t124_ChallengeResponse = -1;
static gint ett_t124_PasswordChallengeRequestResponse = -1;
static gint ett_t124_T_challengeRequestResponse = -1;
static gint ett_t124_ConferenceName = -1;
static gint ett_t124_ConferenceNameSelector = -1;
static gint ett_t124_ConferencePriorityScheme = -1;
static gint ett_t124_ConferencePriority = -1;
static gint ett_t124_NodeCategory = -1;
static gint ett_t124_ConferenceMode = -1;
static gint ett_t124_NetworkAddress = -1;
static gint ett_t124_NetworkAddress_item = -1;
static gint ett_t124_T_aggregatedChannel = -1;
static gint ett_t124_T_transferModes = -1;
static gint ett_t124_T_highLayerCompatibility = -1;
static gint ett_t124_T_transportConnection = -1;
static gint ett_t124_MediaList = -1;
static gint ett_t124_ChannelAggregationMethod = -1;
static gint ett_t124_Profile = -1;
static gint ett_t124_T_simpleProfile = -1;
static gint ett_t124_T_multimediaProfile = -1;
static gint ett_t124_T_profile = -1;
static gint ett_t124_ExtendedE164NetworkAddress = -1;
static gint ett_t124_TransportAddress = -1;
static gint ett_t124_GSTNConnection = -1;
static gint ett_t124_ISDNConnection = -1;
static gint ett_t124_ISDNCircuitTypes = -1;
static gint ett_t124_ISDNCircuitTypes_item = -1;
static gint ett_t124_ISDNHighLayerCompatibility = -1;
static gint ett_t124_CSDNConnection = -1;
static gint ett_t124_T_circuitTypes = -1;
static gint ett_t124_T_circuitTypes_item = -1;
static gint ett_t124_PSDNConnection = -1;
static gint ett_t124_PSDNNetworkAddress = -1;
static gint ett_t124_ATMConnection = -1;
static gint ett_t124_T_networkAddress = -1;
static gint ett_t124_NetworkConnection = -1;
static gint ett_t124_NetworkAddressV2 = -1;
static gint ett_t124_NetworkAddressV2_item = -1;
static gint ett_t124_T_networkConnection = -1;
static gint ett_t124_T_aggregatedConnections = -1;
static gint ett_t124_T_connectionList = -1;
static gint ett_t124_T_connectionList_item = -1;
static gint ett_t124_SET_OF_ChannelAggregationMethod = -1;
static gint ett_t124_SET_OF_Profile = -1;
static gint ett_t124_NodeProperties = -1;
static gint ett_t124_AsymmetryIndicator = -1;
static gint ett_t124_AlternativeNodeID = -1;
static gint ett_t124_ConferenceDescriptor = -1;
static gint ett_t124_NodeRecord = -1;
static gint ett_t124_SEQUENCE_OF_TextString = -1;
static gint ett_t124_SessionKey = -1;
static gint ett_t124_ApplicationRecord = -1;
static gint ett_t124_T_nonCollapsingCapabilities = -1;
static gint ett_t124_T_nonCollapsingCapabilities_item = -1;
static gint ett_t124_CapabilityID = -1;
static gint ett_t124_CapabilityClass = -1;
static gint ett_t124_ApplicationInvokeSpecifier = -1;
static gint ett_t124_T_expectedCapabilitySet = -1;
static gint ett_t124_T_expectedCapabilitySet_item = -1;
static gint ett_t124_RegistryKey = -1;
static gint ett_t124_RegistryItem = -1;
static gint ett_t124_RegistryEntryOwner = -1;
static gint ett_t124_T_owned = -1;
static gint ett_t124_ConferenceCreateRequest = -1;
static gint ett_t124_SET_OF_Privilege = -1;
static gint ett_t124_ConferenceCreateResponse = -1;
static gint ett_t124_ConferenceQueryRequest = -1;
static gint ett_t124_ConferenceQueryResponse = -1;
static gint ett_t124_SET_OF_ConferenceDescriptor = -1;
static gint ett_t124_ConferenceJoinRequest = -1;
static gint ett_t124_ConferenceJoinResponse = -1;
static gint ett_t124_ConferenceInviteRequest = -1;
static gint ett_t124_ConferenceInviteResponse = -1;
static gint ett_t124_ConferenceAddRequest = -1;
static gint ett_t124_ConferenceLockRequest = -1;
static gint ett_t124_ConferenceUnlockRequest = -1;
static gint ett_t124_ConferenceTerminateRequest = -1;
static gint ett_t124_ConferenceEjectUserRequest = -1;
static gint ett_t124_ConferenceTransferRequest = -1;
static gint ett_t124_SET_SIZE_1_65536_OF_UserID = -1;
static gint ett_t124_RegistryRegisterChannelRequest = -1;
static gint ett_t124_RegistryAssignTokenRequest = -1;
static gint ett_t124_RegistrySetParameterRequest = -1;
static gint ett_t124_RegistryRetrieveEntryRequest = -1;
static gint ett_t124_RegistryDeleteEntryRequest = -1;
static gint ett_t124_RegistryMonitorEntryRequest = -1;
static gint ett_t124_RegistryAllocateHandleRequest = -1;
static gint ett_t124_NonStandardPDU = -1;
static gint ett_t124_ConnectData = -1;
static gint ett_t124_ConnectGCCPDU = -1;
static gint ett_t124_RequestPDU = -1;
static gint ett_t124_Segmentation = -1;
static gint ett_t124_DomainParameters = -1;
static gint ett_t124_PlumbDomainIndication = -1;
static gint ett_t124_ErectDomainRequest = -1;
static gint ett_t124_ChannelAttributes = -1;
static gint ett_t124_T_static = -1;
static gint ett_t124_T_userId = -1;
static gint ett_t124_T_private = -1;
static gint ett_t124_SET_OF_UserId = -1;
static gint ett_t124_T_assigned = -1;
static gint ett_t124_MergeChannelsRequest = -1;
static gint ett_t124_SET_OF_ChannelAttributes = -1;
static gint ett_t124_SET_OF_ChannelId = -1;
static gint ett_t124_MergeChannelsConfirm = -1;
static gint ett_t124_PurgeChannelsIndication = -1;
static gint ett_t124_TokenAttributes = -1;
static gint ett_t124_T_grabbed = -1;
static gint ett_t124_T_inhibited = -1;
static gint ett_t124_T_giving = -1;
static gint ett_t124_T_ungivable = -1;
static gint ett_t124_T_given = -1;
static gint ett_t124_MergeTokensRequest = -1;
static gint ett_t124_SET_OF_TokenAttributes = -1;
static gint ett_t124_SET_OF_TokenId = -1;
static gint ett_t124_MergeTokensConfirm = -1;
static gint ett_t124_PurgeTokensIndication = -1;
static gint ett_t124_DisconnectProviderUltimatum = -1;
static gint ett_t124_RejectMCSPDUUltimatum = -1;
static gint ett_t124_AttachUserRequest = -1;
static gint ett_t124_AttachUserConfirm = -1;
static gint ett_t124_DetachUserRequest = -1;
static gint ett_t124_DetachUserIndication = -1;
static gint ett_t124_ChannelJoinRequest = -1;
static gint ett_t124_ChannelJoinConfirm = -1;
static gint ett_t124_ChannelLeaveRequest = -1;
static gint ett_t124_ChannelConveneRequest = -1;
static gint ett_t124_ChannelConveneConfirm = -1;
static gint ett_t124_ChannelDisbandRequest = -1;
static gint ett_t124_ChannelDisbandIndication = -1;
static gint ett_t124_ChannelAdmitRequest = -1;
static gint ett_t124_ChannelAdmitIndication = -1;
static gint ett_t124_ChannelExpelRequest = -1;
static gint ett_t124_ChannelExpelIndication = -1;
static gint ett_t124_SendDataRequest = -1;
static gint ett_t124_SendDataIndication = -1;
static gint ett_t124_UniformSendDataRequest = -1;
static gint ett_t124_UniformSendDataIndication = -1;
static gint ett_t124_TokenGrabRequest = -1;
static gint ett_t124_TokenGrabConfirm = -1;
static gint ett_t124_TokenInhibitRequest = -1;
static gint ett_t124_TokenInhibitConfirm = -1;
static gint ett_t124_TokenGiveRequest = -1;
static gint ett_t124_TokenGiveIndication = -1;
static gint ett_t124_TokenGiveResponse = -1;
static gint ett_t124_TokenGiveConfirm = -1;
static gint ett_t124_TokenPleaseRequest = -1;
static gint ett_t124_TokenPleaseIndication = -1;
static gint ett_t124_TokenReleaseRequest = -1;
static gint ett_t124_TokenReleaseConfirm = -1;
static gint ett_t124_TokenTestRequest = -1;
static gint ett_t124_TokenTestConfirm = -1;
static gint ett_t124_DomainMCSPDU = -1;

/*--- End of included file: packet-t124-ett.c ---*/
#line 71 "../../asn1/t124/packet-t124-template.c"


/*--- Included file: packet-t124-fn.c ---*/
#line 1 "../../asn1/t124/packet-t124-fn.c"


static int
dissect_t124_ChannelID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_t124_DynamicChannelID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1001U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_t124_UserID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_DynamicChannelID(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t124_DynamicTokenID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            16384U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_t124_Time(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2147483648, 2147483647U, NULL, FALSE);

  return offset;
}



static int
dissect_t124_Handle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_t124_H221NonStandardIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 174 "../../asn1/t124/t124.cnf"

      offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 255, FALSE, &t124NSIdentifier);




  return offset;
}



static int
dissect_t124_T_object(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &t124Identifier);

  return offset;
}


static const value_string t124_Key_vals[] = {
  {   0, "object" },
  {   1, "h221NonStandard" },
  { 0, NULL }
};

static const per_choice_t Key_choice[] = {
  {   0, &hf_t124_object         , ASN1_NO_EXTENSIONS     , dissect_t124_T_object },
  {   1, &hf_t124_h221NonStandard, ASN1_NO_EXTENSIONS     , dissect_t124_H221NonStandardIdentifier },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_Key(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_Key, Key_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t NonStandardParameter_sequence[] = {
  { &hf_t124_key            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Key },
  { &hf_t124_data           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_NonStandardParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_NonStandardParameter, NonStandardParameter_sequence);

  return offset;
}



static int
dissect_t124_TextString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          0, 255, FALSE);

  return offset;
}



static int
dissect_t124_SimpleTextString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          0, 255, FALSE);

  return offset;
}



static int
dissect_t124_SimpleNumericString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 255, FALSE, "0123456789", 10,
                                                      NULL);

  return offset;
}



static int
dissect_t124_DiallingString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 16, FALSE, "0123456789", 10,
                                                      NULL);

  return offset;
}



static int
dissect_t124_SubAddressString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 40, FALSE, "0123456789", 10,
                                                      NULL);

  return offset;
}



static int
dissect_t124_ExtraDiallingString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_size_constrained_type(tvb, offset, actx, tree, hf_index, dissect_t124_TextString,
                                                "TextString", 1, 255, FALSE);

  return offset;
}



static int
dissect_t124_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 106 "../../asn1/t124/t124.cnf"
    tvbuff_t	*next_tvb = NULL;
    guint8      *ns = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &next_tvb);


	if(next_tvb) {

	ns = tvb_get_string(t124NSIdentifier, 0, tvb_length(t124NSIdentifier));
	if(ns != NULL) {
		dissector_try_string(t124_ns_dissector_table, ns, next_tvb, actx->pinfo, top_tree);
		g_free(ns);
	}
	}



  return offset;
}


static const per_sequence_t UserData_item_sequence[] = {
  { &hf_t124_key            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Key },
  { &hf_t124_value          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_UserData_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_UserData_item, UserData_item_sequence);

  return offset;
}


static const per_sequence_t UserData_set_of[1] = {
  { &hf_t124_UserData_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserData_item },
};

static int
dissect_t124_UserData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_UserData, UserData_set_of);

  return offset;
}


static const per_sequence_t Password_sequence[] = {
  { &hf_t124_numeric        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_SimpleNumericString },
  { &hf_t124_text           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SimpleTextString },
  { &hf_t124_unicodeText    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_TextString },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_Password(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_Password, Password_sequence);

  return offset;
}


static const value_string t124_PasswordSelector_vals[] = {
  {   0, "numeric" },
  {   1, "text" },
  {   2, "unicodeText" },
  { 0, NULL }
};

static const per_choice_t PasswordSelector_choice[] = {
  {   0, &hf_t124_numeric        , ASN1_EXTENSION_ROOT    , dissect_t124_SimpleNumericString },
  {   1, &hf_t124_text           , ASN1_EXTENSION_ROOT    , dissect_t124_SimpleTextString },
  {   2, &hf_t124_unicodeText    , ASN1_NOT_EXTENSION_ROOT, dissect_t124_TextString },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_PasswordSelector(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_PasswordSelector, PasswordSelector_choice,
                                 NULL);

  return offset;
}


static const value_string t124_ChallengeResponseItem_vals[] = {
  {   0, "passwordString" },
  {   1, "responseData" },
  { 0, NULL }
};

static const per_choice_t ChallengeResponseItem_choice[] = {
  {   0, &hf_t124_passwordString , ASN1_EXTENSION_ROOT    , dissect_t124_PasswordSelector },
  {   1, &hf_t124_responseData   , ASN1_EXTENSION_ROOT    , dissect_t124_UserData },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ChallengeResponseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ChallengeResponseItem, ChallengeResponseItem_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string t124_ChallengeResponseAlgorithm_vals[] = {
  {   0, "passwordInTheClear" },
  {   1, "nonStandardAlgorithm" },
  { 0, NULL }
};

static const per_choice_t ChallengeResponseAlgorithm_choice[] = {
  {   0, &hf_t124_passwordInTheClear, ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   1, &hf_t124_nonStandardAlgorithm, ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ChallengeResponseAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ChallengeResponseAlgorithm, ChallengeResponseAlgorithm_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ChallengeItem_sequence[] = {
  { &hf_t124_responseAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ChallengeResponseAlgorithm },
  { &hf_t124_challengeData  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserData },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChallengeItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChallengeItem, ChallengeItem_sequence);

  return offset;
}



static int
dissect_t124_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t SET_OF_ChallengeItem_set_of[1] = {
  { &hf_t124_challengeSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChallengeItem },
};

static int
dissect_t124_SET_OF_ChallengeItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_ChallengeItem, SET_OF_ChallengeItem_set_of);

  return offset;
}


static const per_sequence_t ChallengeRequest_sequence[] = {
  { &hf_t124_challengeTag   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_challengeSet   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChallengeItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChallengeRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChallengeRequest, ChallengeRequest_sequence);

  return offset;
}


static const per_sequence_t ChallengeResponse_sequence[] = {
  { &hf_t124_challengeTag   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_responseAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ChallengeResponseAlgorithm },
  { &hf_t124_responseItem   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ChallengeResponseItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChallengeResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChallengeResponse, ChallengeResponse_sequence);

  return offset;
}


static const per_sequence_t T_challengeRequestResponse_sequence[] = {
  { &hf_t124_challengeRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ChallengeRequest },
  { &hf_t124_challengeResponse, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ChallengeResponse },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_challengeRequestResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_challengeRequestResponse, T_challengeRequestResponse_sequence);

  return offset;
}


static const value_string t124_PasswordChallengeRequestResponse_vals[] = {
  {   0, "passwordInTheClear" },
  {   1, "challengeRequestResponse" },
  { 0, NULL }
};

static const per_choice_t PasswordChallengeRequestResponse_choice[] = {
  {   0, &hf_t124_passwordInTheClear_01, ASN1_EXTENSION_ROOT    , dissect_t124_PasswordSelector },
  {   1, &hf_t124_challengeRequestResponse, ASN1_EXTENSION_ROOT    , dissect_t124_T_challengeRequestResponse },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_PasswordChallengeRequestResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_PasswordChallengeRequestResponse, PasswordChallengeRequestResponse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ConferenceName_sequence[] = {
  { &hf_t124_numeric        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_SimpleNumericString },
  { &hf_t124_text           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SimpleTextString },
  { &hf_t124_unicodeText    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_TextString },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceName, ConferenceName_sequence);

  return offset;
}


static const value_string t124_ConferenceNameSelector_vals[] = {
  {   0, "numeric" },
  {   1, "text" },
  {   2, "unicodeText" },
  { 0, NULL }
};

static const per_choice_t ConferenceNameSelector_choice[] = {
  {   0, &hf_t124_numeric        , ASN1_EXTENSION_ROOT    , dissect_t124_SimpleNumericString },
  {   1, &hf_t124_text           , ASN1_EXTENSION_ROOT    , dissect_t124_SimpleTextString },
  {   2, &hf_t124_unicodeText    , ASN1_NOT_EXTENSION_ROOT, dissect_t124_TextString },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ConferenceNameSelector(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ConferenceNameSelector, ConferenceNameSelector_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_ConferenceNameModifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_SimpleNumericString(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string t124_Privilege_vals[] = {
  {   0, "terminate" },
  {   1, "ejectUser" },
  {   2, "add" },
  {   3, "lockUnlock" },
  {   4, "transfer" },
  { 0, NULL }
};


static int
dissect_t124_Privilege(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string t124_TerminationMethod_vals[] = {
  {   0, "automatic" },
  {   1, "manual" },
  { 0, NULL }
};


static int
dissect_t124_TerminationMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string t124_ConferencePriorityScheme_vals[] = {
  {   0, "nonStandardScheme" },
  { 0, NULL }
};

static const per_choice_t ConferencePriorityScheme_choice[] = {
  {   0, &hf_t124_nonStandardScheme, ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ConferencePriorityScheme(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ConferencePriorityScheme, ConferencePriorityScheme_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ConferencePriority_sequence[] = {
  { &hf_t124_priority       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_65535 },
  { &hf_t124_scheme         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ConferencePriorityScheme },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferencePriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferencePriority, ConferencePriority_sequence);

  return offset;
}


static const value_string t124_NodeCategory_vals[] = {
  {   0, "conventional" },
  {   1, "counted" },
  {   2, "anonymous" },
  {   3, "nonStandardCategory" },
  { 0, NULL }
};

static const per_choice_t NodeCategory_choice[] = {
  {   0, &hf_t124_conventional   , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   1, &hf_t124_counted        , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   2, &hf_t124_anonymous      , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   3, &hf_t124_nonStandardCategory, ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_NodeCategory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_NodeCategory, NodeCategory_choice,
                                 NULL);

  return offset;
}


static const value_string t124_ConferenceMode_vals[] = {
  {   0, "conventional-only" },
  {   1, "counted-only" },
  {   2, "anonymous-only" },
  {   3, "conventional-control" },
  {   4, "unrestricted-mode" },
  {   5, "non-standard-mode" },
  { 0, NULL }
};

static const per_choice_t ConferenceMode_choice[] = {
  {   0, &hf_t124_conventional_only, ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   1, &hf_t124_counted_only   , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   2, &hf_t124_anonymous_only , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   3, &hf_t124_conventional_control, ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   4, &hf_t124_unrestricted_mode, ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   5, &hf_t124_non_standard_mode, ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ConferenceMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ConferenceMode, ConferenceMode_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t T_transferModes_sequence[] = {
  { &hf_t124_speech         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_voice_band     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_56k    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_64k    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_128k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_192k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_256k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_320k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_384k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_512k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_768k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_1152k  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_1472k  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_1536k  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_1920k  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_packet_mode    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_frame_mode     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_atm            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_transferModes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_transferModes, T_transferModes_sequence);

  return offset;
}


static const per_sequence_t T_highLayerCompatibility_sequence[] = {
  { &hf_t124_telephony3kHz  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_telephony7kHz  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_videotelephony , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_videoconference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_audiographic   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_audiovisual    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_multimedia     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_highLayerCompatibility(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_highLayerCompatibility, T_highLayerCompatibility_sequence);

  return offset;
}


static const per_sequence_t T_aggregatedChannel_sequence[] = {
  { &hf_t124_transferModes  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_T_transferModes },
  { &hf_t124_internationalNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_DiallingString },
  { &hf_t124_subAddress     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SubAddressString },
  { &hf_t124_extraDialling  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ExtraDiallingString },
  { &hf_t124_highLayerCompatibility, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_T_highLayerCompatibility },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_aggregatedChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_aggregatedChannel, T_aggregatedChannel_sequence);

  return offset;
}



static int
dissect_t124_OCTET_STRING_SIZE_1_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_transportConnection_sequence[] = {
  { &hf_t124_nsapAddress    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING_SIZE_1_20 },
  { &hf_t124_transportSelector, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_transportConnection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_transportConnection, T_transportConnection_sequence);

  return offset;
}


static const value_string t124_NetworkAddress_item_vals[] = {
  {   0, "aggregatedChannel" },
  {   1, "transportConnection" },
  {   2, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t NetworkAddress_item_choice[] = {
  {   0, &hf_t124_aggregatedChannel, ASN1_EXTENSION_ROOT    , dissect_t124_T_aggregatedChannel },
  {   1, &hf_t124_transportConnection, ASN1_EXTENSION_ROOT    , dissect_t124_T_transportConnection },
  {   2, &hf_t124_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_NetworkAddress_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_NetworkAddress_item, NetworkAddress_item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NetworkAddress_sequence_of[1] = {
  { &hf_t124_NetworkAddress_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_NetworkAddress_item },
};

static int
dissect_t124_NetworkAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_t124_NetworkAddress, NetworkAddress_sequence_of,
                                                  1, 64, FALSE);

  return offset;
}


static const per_sequence_t MediaList_sequence[] = {
  { &hf_t124_audio          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_video          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_data_01        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_MediaList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_MediaList, MediaList_sequence);

  return offset;
}


static const value_string t124_ChannelAggregationMethod_vals[] = {
  {   0, "h221" },
  {   1, "h244" },
  {   2, "iso-iec-13871" },
  {   3, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t ChannelAggregationMethod_choice[] = {
  {   0, &hf_t124_h221           , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   1, &hf_t124_h244           , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   2, &hf_t124_iso_iec_13871  , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   3, &hf_t124_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ChannelAggregationMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ChannelAggregationMethod, ChannelAggregationMethod_choice,
                                 NULL);

  return offset;
}


static const value_string t124_T_simpleProfile_vals[] = {
  {   0, "speech" },
  {   1, "telephony-3kHz" },
  {   2, "telephony-7kHz" },
  {   3, "voice-band" },
  {   4, "frameRelay" },
  {   5, "t123-pstn-basic" },
  {   6, "t123-psdn-basic" },
  {   7, "t123-b-isdn-basic" },
  { 0, NULL }
};

static const per_choice_t T_simpleProfile_choice[] = {
  {   0, &hf_t124_speech_01      , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   1, &hf_t124_telephony_3kHz , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   2, &hf_t124_telephony_7kHz , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   3, &hf_t124_voice_band_01  , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   4, &hf_t124_frameRelay     , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   5, &hf_t124_t123_pstn_basic, ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   6, &hf_t124_t123_psdn_basic, ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   7, &hf_t124_t123_b_isdn_basic, ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_T_simpleProfile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_T_simpleProfile, T_simpleProfile_choice,
                                 NULL);

  return offset;
}


static const value_string t124_T_profile_vals[] = {
  {   0, "h310" },
  {   1, "h320" },
  {   2, "h321" },
  {   3, "h322" },
  {   4, "h323" },
  {   5, "h324" },
  {   6, "h324m" },
  {   7, "asvd" },
  {   8, "dsvd" },
  { 0, NULL }
};

static const per_choice_t T_profile_choice[] = {
  {   0, &hf_t124_h310           , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   1, &hf_t124_h320           , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   2, &hf_t124_h321           , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   3, &hf_t124_h322           , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   4, &hf_t124_h323           , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   5, &hf_t124_h324           , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   6, &hf_t124_h324m          , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   7, &hf_t124_asvd           , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   8, &hf_t124_dsvd           , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_T_profile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_T_profile, T_profile_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_multimediaProfile_sequence[] = {
  { &hf_t124_profile        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_profile },
  { &hf_t124_t120Data       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_multimediaProfile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_multimediaProfile, T_multimediaProfile_sequence);

  return offset;
}


static const value_string t124_Profile_vals[] = {
  {   0, "simpleProfile" },
  {   1, "multimediaProfile" },
  {   2, "dsmccDownloadProfile" },
  {   3, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t Profile_choice[] = {
  {   0, &hf_t124_simpleProfile  , ASN1_EXTENSION_ROOT    , dissect_t124_T_simpleProfile },
  {   1, &hf_t124_multimediaProfile, ASN1_EXTENSION_ROOT    , dissect_t124_T_multimediaProfile },
  {   2, &hf_t124_dsmccDownloadProfile, ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   3, &hf_t124_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_Profile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_Profile, Profile_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ExtendedE164NetworkAddress_sequence[] = {
  { &hf_t124_internationalNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_DiallingString },
  { &hf_t124_subAddress     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SubAddressString },
  { &hf_t124_extraDialling  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ExtraDiallingString },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ExtendedE164NetworkAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ExtendedE164NetworkAddress, ExtendedE164NetworkAddress_sequence);

  return offset;
}


static const per_sequence_t TransportAddress_sequence[] = {
  { &hf_t124_nsapAddress    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING_SIZE_1_20 },
  { &hf_t124_transportSelector, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TransportAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TransportAddress, TransportAddress_sequence);

  return offset;
}


static const per_sequence_t GSTNConnection_sequence[] = {
  { &hf_t124_networkAddress , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ExtendedE164NetworkAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_GSTNConnection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_GSTNConnection, GSTNConnection_sequence);

  return offset;
}



static int
dissect_t124_INTEGER_1_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 30U, NULL, FALSE);

  return offset;
}


static const value_string t124_ISDNCircuitTypes_item_vals[] = {
  {   0, "digital-64k" },
  {   1, "digital-2x64k" },
  {   2, "digital-384k" },
  {   3, "digital-1536" },
  {   4, "digital-1920k" },
  {   5, "multirate-base-64k" },
  { 0, NULL }
};

static const per_choice_t ISDNCircuitTypes_item_choice[] = {
  {   0, &hf_t124_digital_64k_01 , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   1, &hf_t124_digital_2x64k  , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   2, &hf_t124_digital_384k_01, ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   3, &hf_t124_digital_1536   , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   4, &hf_t124_digital_1920k_01, ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   5, &hf_t124_multirate_base_64k, ASN1_NO_EXTENSIONS     , dissect_t124_INTEGER_1_30 },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ISDNCircuitTypes_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ISDNCircuitTypes_item, ISDNCircuitTypes_item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ISDNCircuitTypes_set_of[1] = {
  { &hf_t124_iSDNCircuitTypes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ISDNCircuitTypes_item },
};

static int
dissect_t124_ISDNCircuitTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ISDNCircuitTypes, ISDNCircuitTypes_set_of);

  return offset;
}


static const per_sequence_t ISDNHighLayerCompatibility_sequence[] = {
  { &hf_t124_telephony3kHz  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_telephony7kHz  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_videotelephony , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_videoconference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_audiographic   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_audiovisual    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_multimedia     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ISDNHighLayerCompatibility(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ISDNHighLayerCompatibility, ISDNHighLayerCompatibility_sequence);

  return offset;
}


static const per_sequence_t ISDNConnection_sequence[] = {
  { &hf_t124_iSDNCircuitTypes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ISDNCircuitTypes },
  { &hf_t124_networkAddress , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ExtendedE164NetworkAddress },
  { &hf_t124_iSDNHighLayerCompatibility, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ISDNHighLayerCompatibility },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ISDNConnection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ISDNConnection, ISDNConnection_sequence);

  return offset;
}


static const value_string t124_T_circuitTypes_item_vals[] = {
  {   0, "digital-56k" },
  {   1, "digital-64k" },
  { 0, NULL }
};

static const per_choice_t T_circuitTypes_item_choice[] = {
  {   0, &hf_t124_digital_56k_01 , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   1, &hf_t124_digital_64k_01 , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_T_circuitTypes_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_T_circuitTypes_item, T_circuitTypes_item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_circuitTypes_set_of[1] = {
  { &hf_t124_circuitTypes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_circuitTypes_item },
};

static int
dissect_t124_T_circuitTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_T_circuitTypes, T_circuitTypes_set_of);

  return offset;
}


static const per_sequence_t CSDNConnection_sequence[] = {
  { &hf_t124_circuitTypes   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_T_circuitTypes },
  { &hf_t124_networkAddress , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ExtendedE164NetworkAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_CSDNConnection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_CSDNConnection, CSDNConnection_sequence);

  return offset;
}


static const value_string t124_PSDNNetworkAddress_vals[] = {
  {   0, "extendedE164NetworkAddress" },
  {   1, "transportAddress" },
  {   2, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t PSDNNetworkAddress_choice[] = {
  {   0, &hf_t124_extendedE164NetworkAddress, ASN1_NO_EXTENSIONS     , dissect_t124_ExtendedE164NetworkAddress },
  {   1, &hf_t124_transportAddress, ASN1_NO_EXTENSIONS     , dissect_t124_TransportAddress },
  {   2, &hf_t124_nonStandard    , ASN1_NO_EXTENSIONS     , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_PSDNNetworkAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_PSDNNetworkAddress, PSDNNetworkAddress_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PSDNConnection_sequence[] = {
  { &hf_t124_pSDNNetworkAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_PSDNNetworkAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_PSDNConnection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_PSDNConnection, PSDNConnection_sequence);

  return offset;
}


static const value_string t124_T_networkAddress_vals[] = {
  {   0, "extendedE164" },
  {   1, "nsapAddress" },
  {   2, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t T_networkAddress_choice[] = {
  {   0, &hf_t124_extendedE164   , ASN1_NO_EXTENSIONS     , dissect_t124_ExtendedE164NetworkAddress },
  {   1, &hf_t124_nsapAddress_01 , ASN1_NO_EXTENSIONS     , dissect_t124_TransportAddress },
  {   2, &hf_t124_nonStandard    , ASN1_NO_EXTENSIONS     , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_T_networkAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_T_networkAddress, T_networkAddress_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_INTEGER_0_MAX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, NO_BOUND, NULL, FALSE);

  return offset;
}


static const per_sequence_t ATMConnection_sequence[] = {
  { &hf_t124_networkAddress_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_T_networkAddress },
  { &hf_t124_maxTransferRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_INTEGER_0_MAX },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ATMConnection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ATMConnection, ATMConnection_sequence);

  return offset;
}


static const value_string t124_NetworkConnection_vals[] = {
  {   0, "gstnConnection" },
  {   1, "isdnConnection" },
  {   2, "csdnConnection" },
  {   3, "psdnConnection" },
  {   4, "atmConnection" },
  {   5, "extendedE164NetworkAddress" },
  {   6, "transportAddress" },
  {   7, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t NetworkConnection_choice[] = {
  {   0, &hf_t124_gstnConnection , ASN1_EXTENSION_ROOT    , dissect_t124_GSTNConnection },
  {   1, &hf_t124_isdnConnection , ASN1_EXTENSION_ROOT    , dissect_t124_ISDNConnection },
  {   2, &hf_t124_csdnConnection , ASN1_EXTENSION_ROOT    , dissect_t124_CSDNConnection },
  {   3, &hf_t124_psdnConnection , ASN1_EXTENSION_ROOT    , dissect_t124_PSDNConnection },
  {   4, &hf_t124_atmConnection  , ASN1_EXTENSION_ROOT    , dissect_t124_ATMConnection },
  {   5, &hf_t124_extendedE164NetworkAddress, ASN1_EXTENSION_ROOT    , dissect_t124_ExtendedE164NetworkAddress },
  {   6, &hf_t124_transportAddress, ASN1_EXTENSION_ROOT    , dissect_t124_TransportAddress },
  {   7, &hf_t124_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_NetworkConnection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_NetworkConnection, NetworkConnection_choice,
                                 NULL);

  return offset;
}


static const value_string t124_T_connectionList_item_vals[] = {
  {   0, "isdnConnection" },
  {   1, "csdnConnection" },
  { 0, NULL }
};

static const per_choice_t T_connectionList_item_choice[] = {
  {   0, &hf_t124_isdnConnection , ASN1_EXTENSION_ROOT    , dissect_t124_ISDNConnection },
  {   1, &hf_t124_csdnConnection , ASN1_EXTENSION_ROOT    , dissect_t124_CSDNConnection },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_T_connectionList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_T_connectionList_item, T_connectionList_item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_connectionList_set_of[1] = {
  { &hf_t124_connectionList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_connectionList_item },
};

static int
dissect_t124_T_connectionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_t124_T_connectionList, T_connectionList_set_of,
                                             1, 30, FALSE);

  return offset;
}


static const per_sequence_t SET_OF_ChannelAggregationMethod_set_of[1] = {
  { &hf_t124_aggregationMethods_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelAggregationMethod },
};

static int
dissect_t124_SET_OF_ChannelAggregationMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_ChannelAggregationMethod, SET_OF_ChannelAggregationMethod_set_of);

  return offset;
}


static const per_sequence_t T_aggregatedConnections_sequence[] = {
  { &hf_t124_connectionList , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_T_connectionList },
  { &hf_t124_aggregationMethods, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_ChannelAggregationMethod },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_aggregatedConnections(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_aggregatedConnections, T_aggregatedConnections_sequence);

  return offset;
}


static const value_string t124_T_networkConnection_vals[] = {
  {   0, "singleConnection" },
  {   1, "aggregatedConnections" },
  { 0, NULL }
};

static const per_choice_t T_networkConnection_choice[] = {
  {   0, &hf_t124_singleConnection, ASN1_NO_EXTENSIONS     , dissect_t124_NetworkConnection },
  {   1, &hf_t124_aggregatedConnections, ASN1_NO_EXTENSIONS     , dissect_t124_T_aggregatedConnections },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_T_networkConnection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_T_networkConnection, T_networkConnection_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SET_OF_Profile_set_of[1] = {
  { &hf_t124_profiles_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Profile },
};

static int
dissect_t124_SET_OF_Profile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_Profile, SET_OF_Profile_set_of);

  return offset;
}


static const per_sequence_t NetworkAddressV2_item_sequence[] = {
  { &hf_t124_networkConnection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_T_networkConnection },
  { &hf_t124_profiles       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Profile },
  { &hf_t124_mediaConcerned , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_MediaList },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_NetworkAddressV2_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_NetworkAddressV2_item, NetworkAddressV2_item_sequence);

  return offset;
}


static const per_sequence_t NetworkAddressV2_set_of[1] = {
  { &hf_t124_NetworkAddressV2_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_NetworkAddressV2_item },
};

static int
dissect_t124_NetworkAddressV2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_NetworkAddressV2, NetworkAddressV2_set_of);

  return offset;
}


static const value_string t124_NodeType_vals[] = {
  {   0, "terminal" },
  {   1, "multiportTerminal" },
  {   2, "mcu" },
  { 0, NULL }
};


static int
dissect_t124_NodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t NodeProperties_sequence[] = {
  { &hf_t124_managementDevice, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_peripheralDevice, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_NodeProperties(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_NodeProperties, NodeProperties_sequence);

  return offset;
}



static int
dissect_t124_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const value_string t124_AsymmetryIndicator_vals[] = {
  {   0, "callingNode" },
  {   1, "calledNode" },
  {   2, "unknown" },
  { 0, NULL }
};

static const per_choice_t AsymmetryIndicator_choice[] = {
  {   0, &hf_t124_callingNode    , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   1, &hf_t124_calledNode     , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   2, &hf_t124_unknown        , ASN1_NO_EXTENSIONS     , dissect_t124_INTEGER_0_4294967295 },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_AsymmetryIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_AsymmetryIndicator, AsymmetryIndicator_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_OCTET_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const value_string t124_AlternativeNodeID_vals[] = {
  {   0, "h243NodeID" },
  { 0, NULL }
};

static const per_choice_t AlternativeNodeID_choice[] = {
  {   0, &hf_t124_h243NodeID     , ASN1_EXTENSION_ROOT    , dissect_t124_OCTET_STRING_SIZE_2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_AlternativeNodeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_AlternativeNodeID, AlternativeNodeID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ConferenceDescriptor_sequence[] = {
  { &hf_t124_conferenceName , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ConferenceName },
  { &hf_t124_conferenceNameModifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ConferenceNameModifier },
  { &hf_t124_conferenceDescription, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_lockedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_passwordInTheClearRequired, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_networkAddress_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_NetworkAddress },
  { &hf_t124_defaultConferenceFlag, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_conferenceMode , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_t124_ConferenceMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceDescriptor, ConferenceDescriptor_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_TextString_sequence_of[1] = {
  { &hf_t124_participantsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TextString },
};

static int
dissect_t124_SEQUENCE_OF_TextString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_t124_SEQUENCE_OF_TextString, SEQUENCE_OF_TextString_sequence_of);

  return offset;
}


static const per_sequence_t NodeRecord_sequence[] = {
  { &hf_t124_superiorNode   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserID },
  { &hf_t124_nodeType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_NodeType },
  { &hf_t124_nodeProperties , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_NodeProperties },
  { &hf_t124_nodeName       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_participantsList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SEQUENCE_OF_TextString },
  { &hf_t124_siteInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_networkAddress_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_NetworkAddress },
  { &hf_t124_alternativeNodeID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_AlternativeNodeID },
  { &hf_t124_userData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_nodeCategory   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_NodeCategory },
  { &hf_t124_networkAddressV2, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_NetworkAddressV2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_NodeRecord(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_NodeRecord, NodeRecord_sequence);

  return offset;
}


static const per_sequence_t SessionKey_sequence[] = {
  { &hf_t124_applicationProtocolKey, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Key },
  { &hf_t124_sessionID      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_ChannelID },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_SessionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_SessionKey, SessionKey_sequence);

  return offset;
}


static const value_string t124_ChannelType_vals[] = {
  {   0, "static" },
  {   1, "dynamicMulticast" },
  {   2, "dynamicPrivate" },
  {   3, "dynamicUserId" },
  { 0, NULL }
};


static int
dissect_t124_ChannelType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string t124_CapabilityID_vals[] = {
  {   0, "standard" },
  {   1, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t CapabilityID_choice[] = {
  {   0, &hf_t124_standard       , ASN1_NO_EXTENSIONS     , dissect_t124_INTEGER_0_65535 },
  {   1, &hf_t124_nonStandard_01 , ASN1_NO_EXTENSIONS     , dissect_t124_Key },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_CapabilityID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_CapabilityID, CapabilityID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_nonCollapsingCapabilities_item_sequence[] = {
  { &hf_t124_capabilityID   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_CapabilityID },
  { &hf_t124_applicationData, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_nonCollapsingCapabilities_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_nonCollapsingCapabilities_item, T_nonCollapsingCapabilities_item_sequence);

  return offset;
}


static const per_sequence_t T_nonCollapsingCapabilities_set_of[1] = {
  { &hf_t124_nonCollapsingCapabilities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_nonCollapsingCapabilities_item },
};

static int
dissect_t124_T_nonCollapsingCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_T_nonCollapsingCapabilities, T_nonCollapsingCapabilities_set_of);

  return offset;
}


static const per_sequence_t ApplicationRecord_sequence[] = {
  { &hf_t124_applicationActive, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_conductingOperationCapable, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_startupChannel , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ChannelType },
  { &hf_t124_applicationUserID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserID },
  { &hf_t124_nonCollapsingCapabilities, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_T_nonCollapsingCapabilities },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ApplicationRecord(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ApplicationRecord, ApplicationRecord_sequence);

  return offset;
}


static const value_string t124_CapabilityClass_vals[] = {
  {   0, "logical" },
  {   1, "unsignedMin" },
  {   2, "unsignedMax" },
  { 0, NULL }
};

static const per_choice_t CapabilityClass_choice[] = {
  {   0, &hf_t124_logical        , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   1, &hf_t124_unsignedMin    , ASN1_EXTENSION_ROOT    , dissect_t124_INTEGER_0_MAX },
  {   2, &hf_t124_unsignedMax    , ASN1_EXTENSION_ROOT    , dissect_t124_INTEGER_0_MAX },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_CapabilityClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_CapabilityClass, CapabilityClass_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_EntityID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_expectedCapabilitySet_item_sequence[] = {
  { &hf_t124_capabilityID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_CapabilityID },
  { &hf_t124_capabilityClass, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_CapabilityClass },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_expectedCapabilitySet_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_expectedCapabilitySet_item, T_expectedCapabilitySet_item_sequence);

  return offset;
}


static const per_sequence_t T_expectedCapabilitySet_set_of[1] = {
  { &hf_t124_expectedCapabilitySet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_expectedCapabilitySet_item },
};

static int
dissect_t124_T_expectedCapabilitySet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_T_expectedCapabilitySet, T_expectedCapabilitySet_set_of);

  return offset;
}


static const per_sequence_t ApplicationInvokeSpecifier_sequence[] = {
  { &hf_t124_sessionKey     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_SessionKey },
  { &hf_t124_expectedCapabilitySet, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_T_expectedCapabilitySet },
  { &hf_t124_startupChannel , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ChannelType },
  { &hf_t124_mandatoryFlag  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ApplicationInvokeSpecifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ApplicationInvokeSpecifier, ApplicationInvokeSpecifier_sequence);

  return offset;
}



static int
dissect_t124_OCTET_STRING_SIZE_0_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       0, 64, FALSE, NULL);

  return offset;
}


static const per_sequence_t RegistryKey_sequence[] = {
  { &hf_t124_sessionKey     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SessionKey },
  { &hf_t124_resourceID     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING_SIZE_0_64 },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_RegistryKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_RegistryKey, RegistryKey_sequence);

  return offset;
}


static const value_string t124_RegistryItem_vals[] = {
  {   0, "channelID" },
  {   1, "tokenID" },
  {   2, "parameter" },
  {   3, "vacant" },
  { 0, NULL }
};

static const per_choice_t RegistryItem_choice[] = {
  {   0, &hf_t124_channelID      , ASN1_EXTENSION_ROOT    , dissect_t124_DynamicChannelID },
  {   1, &hf_t124_tokenID        , ASN1_EXTENSION_ROOT    , dissect_t124_DynamicTokenID },
  {   2, &hf_t124_parameter      , ASN1_EXTENSION_ROOT    , dissect_t124_OCTET_STRING_SIZE_0_64 },
  {   3, &hf_t124_vacant         , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_RegistryItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_RegistryItem, RegistryItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_owned_sequence[] = {
  { &hf_t124_nodeID         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_entityID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_EntityID },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_owned(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_owned, T_owned_sequence);

  return offset;
}


static const value_string t124_RegistryEntryOwner_vals[] = {
  {   0, "owned" },
  {   1, "notOwned" },
  { 0, NULL }
};

static const per_choice_t RegistryEntryOwner_choice[] = {
  {   0, &hf_t124_owned          , ASN1_NO_EXTENSIONS     , dissect_t124_T_owned },
  {   1, &hf_t124_notOwned       , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_RegistryEntryOwner(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_RegistryEntryOwner, RegistryEntryOwner_choice,
                                 NULL);

  return offset;
}


static const value_string t124_RegistryModificationRights_vals[] = {
  {   0, "owner" },
  {   1, "session" },
  {   2, "public" },
  { 0, NULL }
};


static int
dissect_t124_RegistryModificationRights(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t SET_OF_Privilege_set_of[1] = {
  { &hf_t124_conductorPrivileges_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Privilege },
};

static int
dissect_t124_SET_OF_Privilege(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_Privilege, SET_OF_Privilege_set_of);

  return offset;
}


static const per_sequence_t ConferenceCreateRequest_sequence[] = {
  { &hf_t124_conferenceName , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ConferenceName },
  { &hf_t124_convenerPassword, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_Password },
  { &hf_t124_password       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_Password },
  { &hf_t124_lockedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_listedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_conductibleConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_terminationMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_TerminationMethod },
  { &hf_t124_conductorPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_nonConductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conferenceDescription, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_callerIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_userData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_conferencePriority, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_ConferencePriority },
  { &hf_t124_conferenceMode , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_ConferenceMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceCreateRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceCreateRequest, ConferenceCreateRequest_sequence);

  return offset;
}


static const value_string t124_T_result_vals[] = {
  {   0, "success" },
  {   1, "userRejected" },
  {   2, "resourcesNotAvailable" },
  {   3, "rejectedForSymmetryBreaking" },
  {   4, "lockedConferenceNotSupported" },
  { 0, NULL }
};


static int
dissect_t124_T_result(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ConferenceCreateResponse_sequence[] = {
  { &hf_t124_nodeID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_tag            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_result         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_T_result },
  { &hf_t124_userData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceCreateResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceCreateResponse, ConferenceCreateResponse_sequence);

  return offset;
}


static const per_sequence_t ConferenceQueryRequest_sequence[] = {
  { &hf_t124_nodeType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_NodeType },
  { &hf_t124_asymmetryIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_AsymmetryIndicator },
  { &hf_t124_userData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceQueryRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceQueryRequest, ConferenceQueryRequest_sequence);

  return offset;
}


static const per_sequence_t SET_OF_ConferenceDescriptor_set_of[1] = {
  { &hf_t124_conferenceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ConferenceDescriptor },
};

static int
dissect_t124_SET_OF_ConferenceDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_ConferenceDescriptor, SET_OF_ConferenceDescriptor_set_of);

  return offset;
}


static const value_string t124_QueryResponseResult_vals[] = {
  {   0, "success" },
  {   1, "userRejected" },
  { 0, NULL }
};


static int
dissect_t124_QueryResponseResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ConferenceQueryResponse_sequence[] = {
  { &hf_t124_nodeType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_NodeType },
  { &hf_t124_asymmetryIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_AsymmetryIndicator },
  { &hf_t124_conferenceList , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ConferenceDescriptor },
  { &hf_t124_queryResponseResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_QueryResponseResult },
  { &hf_t124_userData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_waitForInvitationFlag, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_BOOLEAN },
  { &hf_t124_noUnlistedConferenceFlag, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceQueryResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceQueryResponse, ConferenceQueryResponse_sequence);

  return offset;
}


static const per_sequence_t ConferenceJoinRequest_sequence[] = {
  { &hf_t124_conferenceName_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ConferenceNameSelector },
  { &hf_t124_conferenceNameModifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ConferenceNameModifier },
  { &hf_t124_tag            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_INTEGER },
  { &hf_t124_password_01    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_PasswordChallengeRequestResponse },
  { &hf_t124_convenerPassword_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_PasswordSelector },
  { &hf_t124_callerIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_userData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_nodeCategory   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_NodeCategory },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceJoinRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceJoinRequest, ConferenceJoinRequest_sequence);

  return offset;
}


static const value_string t124_JoinResponseResult_vals[] = {
  {   0, "success" },
  {   1, "userRejected" },
  {   2, "invalidConference" },
  {   3, "invalidPassword" },
  {   4, "invalidConvenerPassword" },
  {   5, "challengeResponseRequired" },
  {   6, "invalidChallengeResponse" },
  { 0, NULL }
};


static int
dissect_t124_JoinResponseResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ConferenceJoinResponse_sequence[] = {
  { &hf_t124_nodeID         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserID },
  { &hf_t124_topNodeID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_tag            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_conferenceNameAlias, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ConferenceNameSelector },
  { &hf_t124_passwordInTheClearRequired, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_lockedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_listedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_conductibleConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_terminationMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_TerminationMethod },
  { &hf_t124_conductorPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_nonConductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conferenceDescription, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_password_01    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_PasswordChallengeRequestResponse },
  { &hf_t124_joinResponseResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_JoinResponseResult },
  { &hf_t124_userData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_nodeCategory   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_NodeCategory },
  { &hf_t124_conferenceMode , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_ConferenceMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceJoinResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceJoinResponse, ConferenceJoinResponse_sequence);

  return offset;
}


static const per_sequence_t ConferenceInviteRequest_sequence[] = {
  { &hf_t124_conferenceName , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ConferenceName },
  { &hf_t124_nodeID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_topNodeID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_tag            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_passwordInTheClearRequired, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_lockedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_listedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_conductibleConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_terminationMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_TerminationMethod },
  { &hf_t124_conductorPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_nonConductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conferenceDescription, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_callerIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_userData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_conferencePriority, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_ConferencePriority },
  { &hf_t124_nodeCategory   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_NodeCategory },
  { &hf_t124_conferenceMode , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_ConferenceMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceInviteRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceInviteRequest, ConferenceInviteRequest_sequence);

  return offset;
}


static const value_string t124_InviteResponseResult_vals[] = {
  {   0, "success" },
  {   1, "userRejected" },
  { 0, NULL }
};


static int
dissect_t124_InviteResponseResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ConferenceInviteResponse_sequence[] = {
  { &hf_t124_inviteResponseResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_InviteResponseResult },
  { &hf_t124_userData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceInviteResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceInviteResponse, ConferenceInviteResponse_sequence);

  return offset;
}


static const per_sequence_t ConferenceAddRequest_sequence[] = {
  { &hf_t124_networkAddress_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_NetworkAddress },
  { &hf_t124_requestingNode , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_tag            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_addingMCU      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserID },
  { &hf_t124_userData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_nodeCategory   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_NodeCategory },
  { &hf_t124_networkAddressV2, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_t124_NetworkAddressV2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceAddRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceAddRequest, ConferenceAddRequest_sequence);

  return offset;
}


static const per_sequence_t ConferenceLockRequest_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_t124_ConferenceLockRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceLockRequest, ConferenceLockRequest_sequence);

  return offset;
}


static const per_sequence_t ConferenceUnlockRequest_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_t124_ConferenceUnlockRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceUnlockRequest, ConferenceUnlockRequest_sequence);

  return offset;
}


static const value_string t124_TerminateRequestReason_vals[] = {
  {   0, "userInitiated" },
  {   1, "timedConferenceTermination" },
  { 0, NULL }
};


static int
dissect_t124_TerminateRequestReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ConferenceTerminateRequest_sequence[] = {
  { &hf_t124_terminateRequestReason, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_TerminateRequestReason },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceTerminateRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceTerminateRequest, ConferenceTerminateRequest_sequence);

  return offset;
}


static const value_string t124_EjectUserRequestReason_vals[] = {
  {   0, "userInitiated" },
  { 0, NULL }
};


static int
dissect_t124_EjectUserRequestReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ConferenceEjectUserRequest_sequence[] = {
  { &hf_t124_nodeToEject    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_ejectUserRequestReason, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_EjectUserRequestReason },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceEjectUserRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceEjectUserRequest, ConferenceEjectUserRequest_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_65536_OF_UserID_set_of[1] = {
  { &hf_t124_transferringNodes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
};

static int
dissect_t124_SET_SIZE_1_65536_OF_UserID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_t124_SET_SIZE_1_65536_OF_UserID, SET_SIZE_1_65536_OF_UserID_set_of,
                                             1, 65536, FALSE);

  return offset;
}


static const per_sequence_t ConferenceTransferRequest_sequence[] = {
  { &hf_t124_conferenceName_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ConferenceNameSelector },
  { &hf_t124_conferenceNameModifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ConferenceNameModifier },
  { &hf_t124_networkAddress_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_NetworkAddress },
  { &hf_t124_transferringNodes, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_SIZE_1_65536_OF_UserID },
  { &hf_t124_password_02    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_PasswordSelector },
  { &hf_t124_networkAddressV2, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_NetworkAddressV2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceTransferRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceTransferRequest, ConferenceTransferRequest_sequence);

  return offset;
}


static const per_sequence_t RegistryRegisterChannelRequest_sequence[] = {
  { &hf_t124_entityID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_EntityID },
  { &hf_t124_key_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_RegistryKey },
  { &hf_t124_channelID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_DynamicChannelID },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_RegistryRegisterChannelRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_RegistryRegisterChannelRequest, RegistryRegisterChannelRequest_sequence);

  return offset;
}


static const per_sequence_t RegistryAssignTokenRequest_sequence[] = {
  { &hf_t124_entityID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_EntityID },
  { &hf_t124_key_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_RegistryKey },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_RegistryAssignTokenRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_RegistryAssignTokenRequest, RegistryAssignTokenRequest_sequence);

  return offset;
}


static const per_sequence_t RegistrySetParameterRequest_sequence[] = {
  { &hf_t124_entityID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_EntityID },
  { &hf_t124_key_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_RegistryKey },
  { &hf_t124_parameter      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING_SIZE_0_64 },
  { &hf_t124_modificationRights, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_RegistryModificationRights },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_RegistrySetParameterRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_RegistrySetParameterRequest, RegistrySetParameterRequest_sequence);

  return offset;
}


static const per_sequence_t RegistryRetrieveEntryRequest_sequence[] = {
  { &hf_t124_entityID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_EntityID },
  { &hf_t124_key_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_RegistryKey },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_RegistryRetrieveEntryRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_RegistryRetrieveEntryRequest, RegistryRetrieveEntryRequest_sequence);

  return offset;
}


static const per_sequence_t RegistryDeleteEntryRequest_sequence[] = {
  { &hf_t124_entityID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_EntityID },
  { &hf_t124_key_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_RegistryKey },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_RegistryDeleteEntryRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_RegistryDeleteEntryRequest, RegistryDeleteEntryRequest_sequence);

  return offset;
}


static const per_sequence_t RegistryMonitorEntryRequest_sequence[] = {
  { &hf_t124_entityID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_EntityID },
  { &hf_t124_key_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_RegistryKey },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_RegistryMonitorEntryRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_RegistryMonitorEntryRequest, RegistryMonitorEntryRequest_sequence);

  return offset;
}



static int
dissect_t124_INTEGER_1_1024(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RegistryAllocateHandleRequest_sequence[] = {
  { &hf_t124_entityID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_EntityID },
  { &hf_t124_numberOfHandles, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_1_1024 },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_RegistryAllocateHandleRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_RegistryAllocateHandleRequest, RegistryAllocateHandleRequest_sequence);

  return offset;
}


static const per_sequence_t NonStandardPDU_sequence[] = {
  { &hf_t124_data_02        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_NonStandardParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_NonStandardPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_NonStandardPDU, NonStandardPDU_sequence);

  return offset;
}



static int
dissect_t124_T_connectPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 80 "../../asn1/t124/t124.cnf"
    tvbuff_t	*next_tvb = NULL;
    proto_tree	*next_tree = NULL;
    int		old_offset = 0;

    old_offset = offset;
      offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &next_tvb);

    if(next_tvb) {
      /* "2a -> ConnectData::connectPDU length = 42 bytes */
      /* This length MUST be ignored by the client." */

      /* Not sure why - but lets ignore the length. */
      /* We assume the OCTET STRING is all of the remaining bytes */	 

      if(tvb_length(next_tvb) == 42) {
         /* this is perhaps a naive ... */
	 next_tvb = tvb_new_subset_remaining(tvb, (old_offset>>3)+1);
      }

	 next_tree = proto_item_add_subtree(actx->created_item, ett_t124_connectGCCPDU);

       dissect_t124_ConnectGCCPDU(next_tvb, 0, actx, next_tree, hf_t124_connectGCCPDU);

    }


  return offset;
}


static const per_sequence_t ConnectData_sequence[] = {
  { &hf_t124_t124Identifier , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Key },
  { &hf_t124_connectPDU     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_connectPDU },
  { NULL, 0, 0, NULL }
};

int
dissect_t124_ConnectData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConnectData, ConnectData_sequence);

  return offset;
}


const value_string t124_ConnectGCCPDU_vals[] = {
  {   0, "conferenceCreateRequest" },
  {   1, "conferenceCreateResponse" },
  {   2, "conferenceQueryRequest" },
  {   3, "conferenceQueryResponse" },
  {   4, "conferenceJoinRequest" },
  {   5, "conferenceJoinResponse" },
  {   6, "conferenceInviteRequest" },
  {   7, "conferenceInviteResponse" },
  { 0, NULL }
};

static const per_choice_t ConnectGCCPDU_choice[] = {
  {   0, &hf_t124_conferenceCreateRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceCreateRequest },
  {   1, &hf_t124_conferenceCreateResponse, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceCreateResponse },
  {   2, &hf_t124_conferenceQueryRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceQueryRequest },
  {   3, &hf_t124_conferenceQueryResponse, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceQueryResponse },
  {   4, &hf_t124_conferenceJoinRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceJoinRequest },
  {   5, &hf_t124_conferenceJoinResponse, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceJoinResponse },
  {   6, &hf_t124_conferenceInviteRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceInviteRequest },
  {   7, &hf_t124_conferenceInviteResponse, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceInviteResponse },
  { 0, NULL, 0, NULL }
};

int
dissect_t124_ConnectGCCPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ConnectGCCPDU, ConnectGCCPDU_choice,
                                 NULL);

  return offset;
}


static const value_string t124_RequestPDU_vals[] = {
  {   0, "conferenceJoinRequest" },
  {   1, "conferenceAddRequest" },
  {   2, "conferenceLockRequest" },
  {   3, "conferenceUnlockRequest" },
  {   4, "conferenceTerminateRequest" },
  {   5, "conferenceEjectUserRequest" },
  {   6, "conferenceTransferRequest" },
  {   7, "registryRegisterChannelRequest" },
  {   8, "registryAssignTokenRequest" },
  {   9, "registrySetParameterRequest" },
  {  10, "registryRetrieveEntryRequest" },
  {  11, "registryDeleteEntryRequest" },
  {  12, "registryMonitorEntryRequest" },
  {  13, "registryAllocateHandleRequest" },
  {  14, "nonStandardRequest" },
  { 0, NULL }
};

static const per_choice_t RequestPDU_choice[] = {
  {   0, &hf_t124_conferenceJoinRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceJoinRequest },
  {   1, &hf_t124_conferenceAddRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceAddRequest },
  {   2, &hf_t124_conferenceLockRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceLockRequest },
  {   3, &hf_t124_conferenceUnlockRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceUnlockRequest },
  {   4, &hf_t124_conferenceTerminateRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceTerminateRequest },
  {   5, &hf_t124_conferenceEjectUserRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceEjectUserRequest },
  {   6, &hf_t124_conferenceTransferRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceTransferRequest },
  {   7, &hf_t124_registryRegisterChannelRequest, ASN1_EXTENSION_ROOT    , dissect_t124_RegistryRegisterChannelRequest },
  {   8, &hf_t124_registryAssignTokenRequest, ASN1_EXTENSION_ROOT    , dissect_t124_RegistryAssignTokenRequest },
  {   9, &hf_t124_registrySetParameterRequest, ASN1_EXTENSION_ROOT    , dissect_t124_RegistrySetParameterRequest },
  {  10, &hf_t124_registryRetrieveEntryRequest, ASN1_EXTENSION_ROOT    , dissect_t124_RegistryRetrieveEntryRequest },
  {  11, &hf_t124_registryDeleteEntryRequest, ASN1_EXTENSION_ROOT    , dissect_t124_RegistryDeleteEntryRequest },
  {  12, &hf_t124_registryMonitorEntryRequest, ASN1_EXTENSION_ROOT    , dissect_t124_RegistryMonitorEntryRequest },
  {  13, &hf_t124_registryAllocateHandleRequest, ASN1_EXTENSION_ROOT    , dissect_t124_RegistryAllocateHandleRequest },
  {  14, &hf_t124_nonStandardRequest, ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardPDU },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_RequestPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_RequestPDU, RequestPDU_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_ChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 180 "../../asn1/t124/t124.cnf"

      offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &channelId, FALSE);


    if(hf_index == hf_t124_channelId_03) 
        col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%d", channelId);
    	



  return offset;
}



static int
dissect_t124_StaticChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_ChannelId(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t124_DynamicChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_ChannelId(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t124_UserId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_DynamicChannelId(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t124_PrivateChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_DynamicChannelId(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t124_AssignedChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_DynamicChannelId(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t124_TokenId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string t124_TokenStatus_vals[] = {
  {   0, "notInUse" },
  {   1, "selfGrabbed" },
  {   2, "otherGrabbed" },
  {   3, "selfInhibited" },
  {   4, "otherInhibited" },
  {   5, "selfRecipient" },
  {   6, "selfGiving" },
  {   7, "otherGiving" },
  { 0, NULL }
};


static int
dissect_t124_TokenStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string t124_DataPriority_vals[] = {
  {   0, "top" },
  {   1, "high" },
  {   2, "medium" },
  {   3, "low" },
  { 0, NULL }
};


static int
dissect_t124_DataPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_t124_Segmentation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t DomainParameters_sequence[] = {
  { &hf_t124_maxChannelIds  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { &hf_t124_maxUserIds     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { &hf_t124_maxTokenIds    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { &hf_t124_numPriorities  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { &hf_t124_minThroughput  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { &hf_t124_maxHeight      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { &hf_t124_maxMCSPDUsize  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { &hf_t124_protocolVersion, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_DomainParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_DomainParameters, DomainParameters_sequence);

  return offset;
}


static const per_sequence_t PlumbDomainIndication_sequence[] = {
  { &hf_t124_heightLimit    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_PlumbDomainIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_PlumbDomainIndication, PlumbDomainIndication_sequence);

  return offset;
}


static const per_sequence_t ErectDomainRequest_sequence[] = {
  { &hf_t124_subHeight      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { &hf_t124_subInterval    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ErectDomainRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ErectDomainRequest, ErectDomainRequest_sequence);

  return offset;
}


static const per_sequence_t T_static_sequence[] = {
  { &hf_t124_channelId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_StaticChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_static(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_static, T_static_sequence);

  return offset;
}


static const per_sequence_t T_userId_sequence[] = {
  { &hf_t124_joined         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_userId_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_userId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_userId, T_userId_sequence);

  return offset;
}


static const per_sequence_t SET_OF_UserId_set_of[1] = {
  { &hf_t124_admitted_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
};

static int
dissect_t124_SET_OF_UserId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_UserId, SET_OF_UserId_set_of);

  return offset;
}


static const per_sequence_t T_private_sequence[] = {
  { &hf_t124_joined         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { &hf_t124_manager        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_admitted       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_private(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_private, T_private_sequence);

  return offset;
}


static const per_sequence_t T_assigned_sequence[] = {
  { &hf_t124_channelId_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_AssignedChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_assigned(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_assigned, T_assigned_sequence);

  return offset;
}


static const value_string t124_ChannelAttributes_vals[] = {
  {   0, "static" },
  {   1, "userId" },
  {   2, "private" },
  {   3, "assigned" },
  { 0, NULL }
};

static const per_choice_t ChannelAttributes_choice[] = {
  {   0, &hf_t124_static         , ASN1_NO_EXTENSIONS     , dissect_t124_T_static },
  {   1, &hf_t124_userId         , ASN1_NO_EXTENSIONS     , dissect_t124_T_userId },
  {   2, &hf_t124_private        , ASN1_NO_EXTENSIONS     , dissect_t124_T_private },
  {   3, &hf_t124_assigned       , ASN1_NO_EXTENSIONS     , dissect_t124_T_assigned },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ChannelAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ChannelAttributes, ChannelAttributes_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SET_OF_ChannelAttributes_set_of[1] = {
  { &hf_t124_mergeChannels_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelAttributes },
};

static int
dissect_t124_SET_OF_ChannelAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_ChannelAttributes, SET_OF_ChannelAttributes_set_of);

  return offset;
}


static const per_sequence_t SET_OF_ChannelId_set_of[1] = {
  { &hf_t124_purgeChannelIds_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
};

static int
dissect_t124_SET_OF_ChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_ChannelId, SET_OF_ChannelId_set_of);

  return offset;
}


static const per_sequence_t MergeChannelsRequest_sequence[] = {
  { &hf_t124_mergeChannels  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelAttributes },
  { &hf_t124_purgeChannelIds, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_MergeChannelsRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_MergeChannelsRequest, MergeChannelsRequest_sequence);

  return offset;
}


static const per_sequence_t MergeChannelsConfirm_sequence[] = {
  { &hf_t124_mergeChannels  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelAttributes },
  { &hf_t124_purgeChannelIds, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_MergeChannelsConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_MergeChannelsConfirm, MergeChannelsConfirm_sequence);

  return offset;
}


static const per_sequence_t PurgeChannelsIndication_sequence[] = {
  { &hf_t124_detachUserIds  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { &hf_t124_purgeChannelIds, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_PurgeChannelsIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_PurgeChannelsIndication, PurgeChannelsIndication_sequence);

  return offset;
}


static const per_sequence_t T_grabbed_sequence[] = {
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_grabber        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_grabbed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_grabbed, T_grabbed_sequence);

  return offset;
}


static const per_sequence_t T_inhibited_sequence[] = {
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_inhibitors     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_inhibited(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_inhibited, T_inhibited_sequence);

  return offset;
}


static const per_sequence_t T_giving_sequence[] = {
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_grabber        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_recipient      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_giving(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_giving, T_giving_sequence);

  return offset;
}


static const per_sequence_t T_ungivable_sequence[] = {
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_grabber        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_ungivable(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_ungivable, T_ungivable_sequence);

  return offset;
}


static const per_sequence_t T_given_sequence[] = {
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_recipient      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_given(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_given, T_given_sequence);

  return offset;
}


static const value_string t124_TokenAttributes_vals[] = {
  {   0, "grabbed" },
  {   1, "inhibited" },
  {   2, "giving" },
  {   3, "ungivable" },
  {   4, "given" },
  { 0, NULL }
};

static const per_choice_t TokenAttributes_choice[] = {
  {   0, &hf_t124_grabbed        , ASN1_NO_EXTENSIONS     , dissect_t124_T_grabbed },
  {   1, &hf_t124_inhibited      , ASN1_NO_EXTENSIONS     , dissect_t124_T_inhibited },
  {   2, &hf_t124_giving         , ASN1_NO_EXTENSIONS     , dissect_t124_T_giving },
  {   3, &hf_t124_ungivable      , ASN1_NO_EXTENSIONS     , dissect_t124_T_ungivable },
  {   4, &hf_t124_given          , ASN1_NO_EXTENSIONS     , dissect_t124_T_given },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_TokenAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_TokenAttributes, TokenAttributes_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SET_OF_TokenAttributes_set_of[1] = {
  { &hf_t124_mergeTokens_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenAttributes },
};

static int
dissect_t124_SET_OF_TokenAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_TokenAttributes, SET_OF_TokenAttributes_set_of);

  return offset;
}


static const per_sequence_t SET_OF_TokenId_set_of[1] = {
  { &hf_t124_purgeTokenIds_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
};

static int
dissect_t124_SET_OF_TokenId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_TokenId, SET_OF_TokenId_set_of);

  return offset;
}


static const per_sequence_t MergeTokensRequest_sequence[] = {
  { &hf_t124_mergeTokens    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_TokenAttributes },
  { &hf_t124_purgeTokenIds  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_MergeTokensRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_MergeTokensRequest, MergeTokensRequest_sequence);

  return offset;
}


static const per_sequence_t MergeTokensConfirm_sequence[] = {
  { &hf_t124_mergeTokens    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_TokenAttributes },
  { &hf_t124_purgeTokenIds  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_MergeTokensConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_MergeTokensConfirm, MergeTokensConfirm_sequence);

  return offset;
}


static const per_sequence_t PurgeTokensIndication_sequence[] = {
  { &hf_t124_purgeTokenIds  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_PurgeTokensIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_PurgeTokensIndication, PurgeTokensIndication_sequence);

  return offset;
}


static const value_string t124_Reason_vals[] = {
  {   0, "rn-domain-disconnected" },
  {   1, "rn-provider-initiated" },
  {   2, "rn-token-purged" },
  {   3, "rn-user-requested" },
  {   4, "rn-channel-purged" },
  { 0, NULL }
};


static int
dissect_t124_Reason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t DisconnectProviderUltimatum_sequence[] = {
  { &hf_t124_reason         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Reason },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_DisconnectProviderUltimatum(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_DisconnectProviderUltimatum, DisconnectProviderUltimatum_sequence);

  return offset;
}


static const value_string t124_Diagnostic_vals[] = {
  {   0, "dc-inconsistent-merge" },
  {   1, "dc-forbidden-PDU-downward" },
  {   2, "dc-forbidden-PDU-upward" },
  {   3, "dc-invalid-BER-encoding" },
  {   4, "dc-invalid-PER-encoding" },
  {   5, "dc-misrouted-user" },
  {   6, "dc-unrequested-confirm" },
  {   7, "dc-wrong-transport-priority" },
  {   8, "dc-channel-id-conflict" },
  {   9, "dc-token-id-conflict" },
  {  10, "dc-not-user-id-channel" },
  {  11, "dc-too-many-channels" },
  {  12, "dc-too-many-tokens" },
  {  13, "dc-too-many-users" },
  { 0, NULL }
};


static int
dissect_t124_Diagnostic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t RejectMCSPDUUltimatum_sequence[] = {
  { &hf_t124_diagnostic     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Diagnostic },
  { &hf_t124_initialOctets  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_RejectMCSPDUUltimatum(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_RejectMCSPDUUltimatum, RejectMCSPDUUltimatum_sequence);

  return offset;
}


static const per_sequence_t AttachUserRequest_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_AttachUserRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_AttachUserRequest, AttachUserRequest_sequence);

  return offset;
}


static const value_string t124_Result_vals[] = {
  {   0, "rt-successful" },
  {   1, "rt-domain-merging" },
  {   2, "rt-domain-not-hierarchical" },
  {   3, "rt-no-such-channel" },
  {   4, "rt-no-such-domain" },
  {   5, "rt-no-such-user" },
  {   6, "rt-not-admitted" },
  {   7, "rt-other-user-id" },
  {   8, "rt-parameters-unacceptable" },
  {   9, "rt-token-not-available" },
  {  10, "rt-token-not-possessed" },
  {  11, "rt-too-many-channels" },
  {  12, "rt-too-many-tokens" },
  {  13, "rt-too-many-users" },
  {  14, "rt-unspecified-failure" },
  {  15, "rt-user-rejected" },
  { 0, NULL }
};


static int
dissect_t124_Result(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AttachUserConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_AttachUserConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_AttachUserConfirm, AttachUserConfirm_sequence);

  return offset;
}


static const per_sequence_t DetachUserRequest_sequence[] = {
  { &hf_t124_reason         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Reason },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_DetachUserRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_DetachUserRequest, DetachUserRequest_sequence);

  return offset;
}


static const per_sequence_t DetachUserIndication_sequence[] = {
  { &hf_t124_reason         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Reason },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_DetachUserIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_DetachUserIndication, DetachUserIndication_sequence);

  return offset;
}


static const per_sequence_t ChannelJoinRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelJoinRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelJoinRequest, ChannelJoinRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelJoinConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_requested      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelJoinConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelJoinConfirm, ChannelJoinConfirm_sequence);

  return offset;
}


static const per_sequence_t ChannelLeaveRequest_sequence[] = {
  { &hf_t124_channelIds     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelLeaveRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelLeaveRequest, ChannelLeaveRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelConveneRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelConveneRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelConveneRequest, ChannelConveneRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelConveneConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_PrivateChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelConveneConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelConveneConfirm, ChannelConveneConfirm_sequence);

  return offset;
}


static const per_sequence_t ChannelDisbandRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelDisbandRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelDisbandRequest, ChannelDisbandRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelDisbandIndication_sequence[] = {
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelDisbandIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelDisbandIndication, ChannelDisbandIndication_sequence);

  return offset;
}


static const per_sequence_t ChannelAdmitRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelAdmitRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelAdmitRequest, ChannelAdmitRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelAdmitIndication_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelAdmitIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelAdmitIndication, ChannelAdmitIndication_sequence);

  return offset;
}


static const per_sequence_t ChannelExpelRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelExpelRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelExpelRequest, ChannelExpelRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelExpelIndication_sequence[] = {
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelExpelIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelExpelIndication, ChannelExpelIndication_sequence);

  return offset;
}



static int
dissect_t124_T_userData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 123 "../../asn1/t124/t124.cnf"
    tvbuff_t	*next_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &next_tvb);


	if(next_tvb) {

	     dissector_try_uint(t124_sd_dissector_table, channelId, next_tvb, actx->pinfo, top_tree);

	}



  return offset;
}


static const per_sequence_t SendDataRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { &hf_t124_dataPriority   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_DataPriority },
  { &hf_t124_segmentation   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Segmentation },
  { &hf_t124_userData_01    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_userData },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_SendDataRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_SendDataRequest, SendDataRequest_sequence);

  return offset;
}



static int
dissect_t124_T_userData_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 136 "../../asn1/t124/t124.cnf"
    tvbuff_t	*next_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &next_tvb);


	if(next_tvb) {

	     dissector_try_uint(t124_sd_dissector_table, channelId, next_tvb, actx->pinfo, top_tree);

	}



  return offset;
}


static const per_sequence_t SendDataIndication_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { &hf_t124_dataPriority   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_DataPriority },
  { &hf_t124_segmentation   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Segmentation },
  { &hf_t124_userData_02    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_userData_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_SendDataIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_SendDataIndication, SendDataIndication_sequence);

  return offset;
}


static const per_sequence_t UniformSendDataRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { &hf_t124_dataPriority   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_DataPriority },
  { &hf_t124_segmentation   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Segmentation },
  { &hf_t124_userData_03    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_UniformSendDataRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_UniformSendDataRequest, UniformSendDataRequest_sequence);

  return offset;
}


static const per_sequence_t UniformSendDataIndication_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { &hf_t124_dataPriority   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_DataPriority },
  { &hf_t124_segmentation   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Segmentation },
  { &hf_t124_userData_03    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_UniformSendDataIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_UniformSendDataIndication, UniformSendDataIndication_sequence);

  return offset;
}


static const per_sequence_t TokenGrabRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGrabRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGrabRequest, TokenGrabRequest_sequence);

  return offset;
}


static const per_sequence_t TokenGrabConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_tokenStatus    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGrabConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGrabConfirm, TokenGrabConfirm_sequence);

  return offset;
}


static const per_sequence_t TokenInhibitRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenInhibitRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenInhibitRequest, TokenInhibitRequest_sequence);

  return offset;
}


static const per_sequence_t TokenInhibitConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_tokenStatus    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenInhibitConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenInhibitConfirm, TokenInhibitConfirm_sequence);

  return offset;
}


static const per_sequence_t TokenGiveRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_recipient      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGiveRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGiveRequest, TokenGiveRequest_sequence);

  return offset;
}


static const per_sequence_t TokenGiveIndication_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_recipient      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGiveIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGiveIndication, TokenGiveIndication_sequence);

  return offset;
}


static const per_sequence_t TokenGiveResponse_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_recipient      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGiveResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGiveResponse, TokenGiveResponse_sequence);

  return offset;
}


static const per_sequence_t TokenGiveConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_tokenStatus    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGiveConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGiveConfirm, TokenGiveConfirm_sequence);

  return offset;
}


static const per_sequence_t TokenPleaseRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenPleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenPleaseRequest, TokenPleaseRequest_sequence);

  return offset;
}


static const per_sequence_t TokenPleaseIndication_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenPleaseIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenPleaseIndication, TokenPleaseIndication_sequence);

  return offset;
}


static const per_sequence_t TokenReleaseRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenReleaseRequest, TokenReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t TokenReleaseConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_tokenStatus    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenReleaseConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenReleaseConfirm, TokenReleaseConfirm_sequence);

  return offset;
}


static const per_sequence_t TokenTestRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenTestRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenTestRequest, TokenTestRequest_sequence);

  return offset;
}


static const per_sequence_t TokenTestConfirm_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_tokenStatus    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenTestConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenTestConfirm, TokenTestConfirm_sequence);

  return offset;
}


static const value_string t124_DomainMCSPDU_vals[] = {
  {   0, "plumbDomainIndication" },
  {   1, "erectDomainRequest" },
  {   2, "mergeChannelsRequest" },
  {   3, "mergeChannelsConfirm" },
  {   4, "purgeChannelsIndication" },
  {   5, "mergeTokensRequest" },
  {   6, "mergeTokensConfirm" },
  {   7, "purgeTokensIndication" },
  {   8, "disconnectProviderUltimatum" },
  {   9, "rejectMCSPDUUltimatum" },
  {  10, "attachUserRequest" },
  {  11, "attachUserConfirm" },
  {  12, "detachUserRequest" },
  {  13, "detachUserIndication" },
  {  14, "channelJoinRequest" },
  {  15, "channelJoinConfirm" },
  {  16, "channelLeaveRequest" },
  {  17, "channelConveneRequest" },
  {  18, "channelConveneConfirm" },
  {  19, "channelDisbandRequest" },
  {  20, "channelDisbandIndication" },
  {  21, "channelAdmitRequest" },
  {  22, "channelAdmitIndication" },
  {  23, "channelExpelRequest" },
  {  24, "channelExpelIndication" },
  {  25, "sendDataRequest" },
  {  26, "sendDataIndication" },
  {  27, "uniformSendDataRequest" },
  {  28, "uniformSendDataIndication" },
  {  29, "tokenGrabRequest" },
  {  30, "tokenGrabConfirm" },
  {  31, "tokenInhibitRequest" },
  {  32, "tokenInhibitConfirm" },
  {  33, "tokenGiveRequest" },
  {  34, "tokenGiveIndication" },
  {  35, "tokenGiveResponse" },
  {  36, "tokenGiveConfirm" },
  {  37, "tokenPleaseRequest" },
  {  38, "tokenPleaseIndication" },
  {  39, "tokenReleaseRequest" },
  {  40, "tokenReleaseConfirm" },
  {  41, "tokenTestRequest" },
  {  42, "tokenTestConfirm" },
  { 0, NULL }
};

static const per_choice_t DomainMCSPDU_choice[] = {
  {   0, &hf_t124_plumbDomainIndication, ASN1_NO_EXTENSIONS     , dissect_t124_PlumbDomainIndication },
  {   1, &hf_t124_erectDomainRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ErectDomainRequest },
  {   2, &hf_t124_mergeChannelsRequest, ASN1_NO_EXTENSIONS     , dissect_t124_MergeChannelsRequest },
  {   3, &hf_t124_mergeChannelsConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_MergeChannelsConfirm },
  {   4, &hf_t124_purgeChannelsIndication, ASN1_NO_EXTENSIONS     , dissect_t124_PurgeChannelsIndication },
  {   5, &hf_t124_mergeTokensRequest, ASN1_NO_EXTENSIONS     , dissect_t124_MergeTokensRequest },
  {   6, &hf_t124_mergeTokensConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_MergeTokensConfirm },
  {   7, &hf_t124_purgeTokensIndication, ASN1_NO_EXTENSIONS     , dissect_t124_PurgeTokensIndication },
  {   8, &hf_t124_disconnectProviderUltimatum, ASN1_NO_EXTENSIONS     , dissect_t124_DisconnectProviderUltimatum },
  {   9, &hf_t124_rejectMCSPDUUltimatum, ASN1_NO_EXTENSIONS     , dissect_t124_RejectMCSPDUUltimatum },
  {  10, &hf_t124_attachUserRequest, ASN1_NO_EXTENSIONS     , dissect_t124_AttachUserRequest },
  {  11, &hf_t124_attachUserConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_AttachUserConfirm },
  {  12, &hf_t124_detachUserRequest, ASN1_NO_EXTENSIONS     , dissect_t124_DetachUserRequest },
  {  13, &hf_t124_detachUserIndication, ASN1_NO_EXTENSIONS     , dissect_t124_DetachUserIndication },
  {  14, &hf_t124_channelJoinRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelJoinRequest },
  {  15, &hf_t124_channelJoinConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelJoinConfirm },
  {  16, &hf_t124_channelLeaveRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelLeaveRequest },
  {  17, &hf_t124_channelConveneRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelConveneRequest },
  {  18, &hf_t124_channelConveneConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelConveneConfirm },
  {  19, &hf_t124_channelDisbandRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelDisbandRequest },
  {  20, &hf_t124_channelDisbandIndication, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelDisbandIndication },
  {  21, &hf_t124_channelAdmitRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelAdmitRequest },
  {  22, &hf_t124_channelAdmitIndication, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelAdmitIndication },
  {  23, &hf_t124_channelExpelRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelExpelRequest },
  {  24, &hf_t124_channelExpelIndication, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelExpelIndication },
  {  25, &hf_t124_sendDataRequest, ASN1_NO_EXTENSIONS     , dissect_t124_SendDataRequest },
  {  26, &hf_t124_sendDataIndication, ASN1_NO_EXTENSIONS     , dissect_t124_SendDataIndication },
  {  27, &hf_t124_uniformSendDataRequest, ASN1_NO_EXTENSIONS     , dissect_t124_UniformSendDataRequest },
  {  28, &hf_t124_uniformSendDataIndication, ASN1_NO_EXTENSIONS     , dissect_t124_UniformSendDataIndication },
  {  29, &hf_t124_tokenGrabRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGrabRequest },
  {  30, &hf_t124_tokenGrabConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGrabConfirm },
  {  31, &hf_t124_tokenInhibitRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenInhibitRequest },
  {  32, &hf_t124_tokenInhibitConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_TokenInhibitConfirm },
  {  33, &hf_t124_tokenGiveRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGiveRequest },
  {  34, &hf_t124_tokenGiveIndication, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGiveIndication },
  {  35, &hf_t124_tokenGiveResponse, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGiveResponse },
  {  36, &hf_t124_tokenGiveConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGiveConfirm },
  {  37, &hf_t124_tokenPleaseRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenPleaseRequest },
  {  38, &hf_t124_tokenPleaseIndication, ASN1_NO_EXTENSIONS     , dissect_t124_TokenPleaseIndication },
  {  39, &hf_t124_tokenReleaseRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenReleaseRequest },
  {  40, &hf_t124_tokenReleaseConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_TokenReleaseConfirm },
  {  41, &hf_t124_tokenTestRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenTestRequest },
  {  42, &hf_t124_tokenTestConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_TokenTestConfirm },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_DomainMCSPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 150 "../../asn1/t124/t124.cnf"
  	gint domainmcs_value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_DomainMCSPDU, DomainMCSPDU_choice,
                                 &domainmcs_value);

	switch(domainmcs_value) {
	case 25: /* sendDataRequest */
	case 26: /* sendDataIndication */
	case 27: /* uniformSendDataRequest */
	case 28: /* uniformSendDataIndication */
		/* Do nothing */
		break;
	default:
		col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", val_to_str(domainmcs_value, t124_DomainMCSPDU_vals, "Unknown"));
		break;
	}



  return offset;
}


/*--- End of included file: packet-t124-fn.c ---*/
#line 73 "../../asn1/t124/packet-t124-template.c"

static const per_sequence_t t124Heur_sequence[] = {
  { &hf_t124_t124Identifier , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Key },
  { NULL, 0, 0, NULL }
};

void
register_t124_ns_dissector(const char *nsKey, dissector_t dissector, int proto)
{
  dissector_handle_t dissector_handle;

  dissector_handle=create_dissector_handle(dissector, proto);
  dissector_add_string("t124.ns", nsKey, dissector_handle);
}

void register_t124_sd_dissector(packet_info *pinfo _U_, guint32 channelId, dissector_t dissector, int proto)
{
  /* XXX: we should keep the sub-dissectors list per conversation
     as the same channels may be used.
     While we are just using RDP over T.124, then we can get away with it.
  */

  dissector_handle_t dissector_handle;

  dissector_handle=create_dissector_handle(dissector, proto);
  dissector_add_uint("t124.sd", channelId, dissector_handle);

}

guint32 t124_get_last_channelId(void)
{
  return channelId;
}

void t124_set_top_tree(proto_tree *tree)
{
  top_tree = tree;
}

int dissect_DomainMCSPDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

  offset = dissect_t124_DomainMCSPDU(tvb, offset, &asn1_ctx, tree, hf_t124_DomainMCSPDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}

static int
dissect_t124_new(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  asn1_ctx_t asn1_ctx;

  top_tree = parent_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.125");
  col_clear(pinfo->cinfo, COL_INFO);

  item = proto_tree_add_item(parent_tree, proto_t124, tvb, 0, tvb_length(tvb), ENC_NA);
  tree = proto_item_add_subtree(item, ett_t124);

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  dissect_t124_ConnectData(tvb, 0, &asn1_ctx, tree, hf_t124_ConnectData);

  return tvb_length(tvb);
}

static void
dissect_t124(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  dissect_t124_new(tvb, pinfo, parent_tree);
}

static gboolean
dissect_t124_heur(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  asn1_ctx_t asn1_ctx;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

  t124Identifier = NULL;

  (void) dissect_per_sequence(tvb, 0, &asn1_ctx, NULL, -1, -1, t124Heur_sequence);

  if((t124Identifier != NULL) &&
     (strcmp(t124Identifier, "0.0.20.124.0.1") == 0)) {

    dissect_t124(tvb, pinfo, parent_tree);

  }

  return FALSE;
}

/*--- proto_register_t124 -------------------------------------------*/
void proto_register_t124(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_t124_ConnectData,
      { "ConnectData", "t124.ConnectData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_connectGCCPDU,
      { "connectGCCPDU", "t124.connectGCCPDU",
        FT_UINT32, BASE_DEC, VALS(t124_ConnectGCCPDU_vals), 0,
        NULL, HFILL }},
    { &hf_t124_DomainMCSPDU_PDU,
      { "DomainMCSPDU", "t124.DomainMCSPDU",
        FT_UINT32, BASE_DEC, VALS(t124_DomainMCSPDU_vals), 0,
        NULL, HFILL }},

/*--- Included file: packet-t124-hfarr.c ---*/
#line 1 "../../asn1/t124/packet-t124-hfarr.c"
    { &hf_t124_object,
      { "object", "t124.object",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_h221NonStandard,
      { "h221NonStandard", "t124.h221NonStandard",
        FT_BYTES, BASE_NONE, NULL, 0,
        "H221NonStandardIdentifier", HFILL }},
    { &hf_t124_key,
      { "key", "t124.key",
        FT_UINT32, BASE_DEC, VALS(t124_Key_vals), 0,
        NULL, HFILL }},
    { &hf_t124_data,
      { "data", "t124.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t124_UserData_item,
      { "UserData item", "t124.UserData_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_value,
      { "value", "t124.value",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_numeric,
      { "numeric", "t124.numeric",
        FT_STRING, BASE_NONE, NULL, 0,
        "SimpleNumericString", HFILL }},
    { &hf_t124_text,
      { "text", "t124.text",
        FT_STRING, BASE_NONE, NULL, 0,
        "SimpleTextString", HFILL }},
    { &hf_t124_unicodeText,
      { "unicodeText", "t124.unicodeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "TextString", HFILL }},
    { &hf_t124_passwordString,
      { "passwordString", "t124.passwordString",
        FT_UINT32, BASE_DEC, VALS(t124_PasswordSelector_vals), 0,
        "PasswordSelector", HFILL }},
    { &hf_t124_responseData,
      { "responseData", "t124.responseData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserData", HFILL }},
    { &hf_t124_passwordInTheClear,
      { "passwordInTheClear", "t124.passwordInTheClear",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nonStandardAlgorithm,
      { "nonStandardAlgorithm", "t124.nonStandardAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_responseAlgorithm,
      { "responseAlgorithm", "t124.responseAlgorithm",
        FT_UINT32, BASE_DEC, VALS(t124_ChallengeResponseAlgorithm_vals), 0,
        "ChallengeResponseAlgorithm", HFILL }},
    { &hf_t124_challengeData,
      { "challengeData", "t124.challengeData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserData", HFILL }},
    { &hf_t124_challengeTag,
      { "challengeTag", "t124.challengeTag",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_t124_challengeSet,
      { "challengeSet", "t124.challengeSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChallengeItem", HFILL }},
    { &hf_t124_challengeSet_item,
      { "ChallengeItem", "t124.ChallengeItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_responseItem,
      { "responseItem", "t124.responseItem",
        FT_UINT32, BASE_DEC, VALS(t124_ChallengeResponseItem_vals), 0,
        "ChallengeResponseItem", HFILL }},
    { &hf_t124_passwordInTheClear_01,
      { "passwordInTheClear", "t124.passwordInTheClear",
        FT_UINT32, BASE_DEC, VALS(t124_PasswordSelector_vals), 0,
        "PasswordSelector", HFILL }},
    { &hf_t124_challengeRequestResponse,
      { "challengeRequestResponse", "t124.challengeRequestResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_challengeRequest,
      { "challengeRequest", "t124.challengeRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_challengeResponse,
      { "challengeResponse", "t124.challengeResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nonStandardScheme,
      { "nonStandardScheme", "t124.nonStandardScheme",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_priority,
      { "priority", "t124.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_t124_scheme,
      { "scheme", "t124.scheme",
        FT_UINT32, BASE_DEC, VALS(t124_ConferencePriorityScheme_vals), 0,
        "ConferencePriorityScheme", HFILL }},
    { &hf_t124_conventional,
      { "conventional", "t124.conventional",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_counted,
      { "counted", "t124.counted",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_anonymous,
      { "anonymous", "t124.anonymous",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nonStandardCategory,
      { "nonStandardCategory", "t124.nonStandardCategory",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_conventional_only,
      { "conventional-only", "t124.conventional_only",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_counted_only,
      { "counted-only", "t124.counted_only",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_anonymous_only,
      { "anonymous-only", "t124.anonymous_only",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conventional_control,
      { "conventional-control", "t124.conventional_control",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_unrestricted_mode,
      { "unrestricted-mode", "t124.unrestricted_mode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_non_standard_mode,
      { "non-standard-mode", "t124.non_standard_mode",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_NetworkAddress_item,
      { "NetworkAddress item", "t124.NetworkAddress_item",
        FT_UINT32, BASE_DEC, VALS(t124_NetworkAddress_item_vals), 0,
        NULL, HFILL }},
    { &hf_t124_aggregatedChannel,
      { "aggregatedChannel", "t124.aggregatedChannel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_transferModes,
      { "transferModes", "t124.transferModes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_speech,
      { "speech", "t124.speech",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_voice_band,
      { "voice-band", "t124.voice_band",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_56k,
      { "digital-56k", "t124.digital_56k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_64k,
      { "digital-64k", "t124.digital_64k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_128k,
      { "digital-128k", "t124.digital_128k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_192k,
      { "digital-192k", "t124.digital_192k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_256k,
      { "digital-256k", "t124.digital_256k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_320k,
      { "digital-320k", "t124.digital_320k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_384k,
      { "digital-384k", "t124.digital_384k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_512k,
      { "digital-512k", "t124.digital_512k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_768k,
      { "digital-768k", "t124.digital_768k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_1152k,
      { "digital-1152k", "t124.digital_1152k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_1472k,
      { "digital-1472k", "t124.digital_1472k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_1536k,
      { "digital-1536k", "t124.digital_1536k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_1920k,
      { "digital-1920k", "t124.digital_1920k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_packet_mode,
      { "packet-mode", "t124.packet_mode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_frame_mode,
      { "frame-mode", "t124.frame_mode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_atm,
      { "atm", "t124.atm",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_internationalNumber,
      { "internationalNumber", "t124.internationalNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "DiallingString", HFILL }},
    { &hf_t124_subAddress,
      { "subAddress", "t124.subAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "SubAddressString", HFILL }},
    { &hf_t124_extraDialling,
      { "extraDialling", "t124.extraDialling",
        FT_STRING, BASE_NONE, NULL, 0,
        "ExtraDiallingString", HFILL }},
    { &hf_t124_highLayerCompatibility,
      { "highLayerCompatibility", "t124.highLayerCompatibility",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_telephony3kHz,
      { "telephony3kHz", "t124.telephony3kHz",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_telephony7kHz,
      { "telephony7kHz", "t124.telephony7kHz",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_videotelephony,
      { "videotelephony", "t124.videotelephony",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_videoconference,
      { "videoconference", "t124.videoconference",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_audiographic,
      { "audiographic", "t124.audiographic",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_audiovisual,
      { "audiovisual", "t124.audiovisual",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_multimedia,
      { "multimedia", "t124.multimedia",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_transportConnection,
      { "transportConnection", "t124.transportConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nsapAddress,
      { "nsapAddress", "t124.nsapAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_t124_transportSelector,
      { "transportSelector", "t124.transportSelector",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t124_nonStandard,
      { "nonStandard", "t124.nonStandard",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_audio,
      { "audio", "t124.audio",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_video,
      { "video", "t124.video",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_data_01,
      { "data", "t124.data",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_h221,
      { "h221", "t124.h221",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_h244,
      { "h244", "t124.h244",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_iso_iec_13871,
      { "iso-iec-13871", "t124.iso_iec_13871",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_simpleProfile,
      { "simpleProfile", "t124.simpleProfile",
        FT_UINT32, BASE_DEC, VALS(t124_T_simpleProfile_vals), 0,
        NULL, HFILL }},
    { &hf_t124_speech_01,
      { "speech", "t124.speech",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_telephony_3kHz,
      { "telephony-3kHz", "t124.telephony_3kHz",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_telephony_7kHz,
      { "telephony-7kHz", "t124.telephony_7kHz",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_voice_band_01,
      { "voice-band", "t124.voice_band",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_frameRelay,
      { "frameRelay", "t124.frameRelay",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_t123_pstn_basic,
      { "t123-pstn-basic", "t124.t123_pstn_basic",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_t123_psdn_basic,
      { "t123-psdn-basic", "t124.t123_psdn_basic",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_t123_b_isdn_basic,
      { "t123-b-isdn-basic", "t124.t123_b_isdn_basic",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_multimediaProfile,
      { "multimediaProfile", "t124.multimediaProfile",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_profile,
      { "profile", "t124.profile",
        FT_UINT32, BASE_DEC, VALS(t124_T_profile_vals), 0,
        NULL, HFILL }},
    { &hf_t124_h310,
      { "h310", "t124.h310",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_h320,
      { "h320", "t124.h320",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_h321,
      { "h321", "t124.h321",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_h322,
      { "h322", "t124.h322",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_h323,
      { "h323", "t124.h323",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_h324,
      { "h324", "t124.h324",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_h324m,
      { "h324m", "t124.h324m",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_asvd,
      { "asvd", "t124.asvd",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_dsvd,
      { "dsvd", "t124.dsvd",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_t120Data,
      { "t120Data", "t124.t120Data",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_dsmccDownloadProfile,
      { "dsmccDownloadProfile", "t124.dsmccDownloadProfile",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_networkAddress,
      { "networkAddress", "t124.networkAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedE164NetworkAddress", HFILL }},
    { &hf_t124_iSDNCircuitTypes,
      { "circuitTypes", "t124.circuitTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ISDNCircuitTypes", HFILL }},
    { &hf_t124_iSDNCircuitTypes_item,
      { "circuitTypes item", "t124.circuitTypes_item",
        FT_UINT32, BASE_DEC, VALS(t124_ISDNCircuitTypes_item_vals), 0,
        "ISDNCircuitTypes_item", HFILL }},
    { &hf_t124_digital_64k_01,
      { "digital-64k", "t124.digital_64k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_digital_2x64k,
      { "digital-2x64k", "t124.digital_2x64k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_digital_384k_01,
      { "digital-384k", "t124.digital_384k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_digital_1536,
      { "digital-1536", "t124.digital_1536",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_digital_1920k_01,
      { "digital-1920k", "t124.digital_1920k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_multirate_base_64k,
      { "multirate-base-64k", "t124.multirate_base_64k",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_30", HFILL }},
    { &hf_t124_iSDNHighLayerCompatibility,
      { "highLayerCompatibility", "t124.highLayerCompatibility",
        FT_NONE, BASE_NONE, NULL, 0,
        "ISDNHighLayerCompatibility", HFILL }},
    { &hf_t124_circuitTypes,
      { "circuitTypes", "t124.circuitTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_circuitTypes_item,
      { "circuitTypes item", "t124.circuitTypes_item",
        FT_UINT32, BASE_DEC, VALS(t124_T_circuitTypes_item_vals), 0,
        NULL, HFILL }},
    { &hf_t124_digital_56k_01,
      { "digital-56k", "t124.digital_56k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_pSDNNetworkAddress,
      { "networkAddress", "t124.networkAddress",
        FT_UINT32, BASE_DEC, VALS(t124_PSDNNetworkAddress_vals), 0,
        "PSDNNetworkAddress", HFILL }},
    { &hf_t124_extendedE164NetworkAddress,
      { "extendedE164NetworkAddress", "t124.extendedE164NetworkAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_transportAddress,
      { "transportAddress", "t124.transportAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_networkAddress_01,
      { "networkAddress", "t124.networkAddress",
        FT_UINT32, BASE_DEC, VALS(t124_T_networkAddress_vals), 0,
        NULL, HFILL }},
    { &hf_t124_extendedE164,
      { "extendedE164", "t124.extendedE164",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedE164NetworkAddress", HFILL }},
    { &hf_t124_nsapAddress_01,
      { "nsapAddress", "t124.nsapAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportAddress", HFILL }},
    { &hf_t124_maxTransferRate,
      { "maxTransferRate", "t124.maxTransferRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_gstnConnection,
      { "gstnConnection", "t124.gstnConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_isdnConnection,
      { "isdnConnection", "t124.isdnConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_csdnConnection,
      { "csdnConnection", "t124.csdnConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_psdnConnection,
      { "psdnConnection", "t124.psdnConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_atmConnection,
      { "atmConnection", "t124.atmConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_NetworkAddressV2_item,
      { "NetworkAddressV2 item", "t124.NetworkAddressV2_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_networkConnection,
      { "networkConnection", "t124.networkConnection",
        FT_UINT32, BASE_DEC, VALS(t124_T_networkConnection_vals), 0,
        NULL, HFILL }},
    { &hf_t124_singleConnection,
      { "singleConnection", "t124.singleConnection",
        FT_UINT32, BASE_DEC, VALS(t124_NetworkConnection_vals), 0,
        "NetworkConnection", HFILL }},
    { &hf_t124_aggregatedConnections,
      { "aggregatedConnections", "t124.aggregatedConnections",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_connectionList,
      { "connectionList", "t124.connectionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_connectionList_item,
      { "connectionList item", "t124.connectionList_item",
        FT_UINT32, BASE_DEC, VALS(t124_T_connectionList_item_vals), 0,
        "T_connectionList_item", HFILL }},
    { &hf_t124_aggregationMethods,
      { "aggregationMethods", "t124.aggregationMethods",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChannelAggregationMethod", HFILL }},
    { &hf_t124_aggregationMethods_item,
      { "ChannelAggregationMethod", "t124.ChannelAggregationMethod",
        FT_UINT32, BASE_DEC, VALS(t124_ChannelAggregationMethod_vals), 0,
        NULL, HFILL }},
    { &hf_t124_profiles,
      { "profiles", "t124.profiles",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Profile", HFILL }},
    { &hf_t124_profiles_item,
      { "Profile", "t124.Profile",
        FT_UINT32, BASE_DEC, VALS(t124_Profile_vals), 0,
        NULL, HFILL }},
    { &hf_t124_mediaConcerned,
      { "mediaConcerned", "t124.mediaConcerned",
        FT_NONE, BASE_NONE, NULL, 0,
        "MediaList", HFILL }},
    { &hf_t124_managementDevice,
      { "managementDevice", "t124.managementDevice",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_peripheralDevice,
      { "peripheralDevice", "t124.peripheralDevice",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_callingNode,
      { "callingNode", "t124.callingNode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_calledNode,
      { "calledNode", "t124.calledNode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_unknown,
      { "unknown", "t124.unknown",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_t124_h243NodeID,
      { "h243NodeID", "t124.h243NodeID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_t124_conferenceName,
      { "conferenceName", "t124.conferenceName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceNameModifier,
      { "conferenceNameModifier", "t124.conferenceNameModifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceDescription,
      { "conferenceDescription", "t124.conferenceDescription",
        FT_STRING, BASE_NONE, NULL, 0,
        "TextString", HFILL }},
    { &hf_t124_lockedConference,
      { "lockedConference", "t124.lockedConference",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_passwordInTheClearRequired,
      { "passwordInTheClearRequired", "t124.passwordInTheClearRequired",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_networkAddress_02,
      { "networkAddress", "t124.networkAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_defaultConferenceFlag,
      { "defaultConferenceFlag", "t124.defaultConferenceFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_conferenceMode,
      { "conferenceMode", "t124.conferenceMode",
        FT_UINT32, BASE_DEC, VALS(t124_ConferenceMode_vals), 0,
        NULL, HFILL }},
    { &hf_t124_superiorNode,
      { "superiorNode", "t124.superiorNode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserID", HFILL }},
    { &hf_t124_nodeType,
      { "nodeType", "t124.nodeType",
        FT_UINT32, BASE_DEC, VALS(t124_NodeType_vals), 0,
        NULL, HFILL }},
    { &hf_t124_nodeProperties,
      { "nodeProperties", "t124.nodeProperties",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nodeName,
      { "nodeName", "t124.nodeName",
        FT_STRING, BASE_NONE, NULL, 0,
        "TextString", HFILL }},
    { &hf_t124_participantsList,
      { "participantsList", "t124.participantsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TextString", HFILL }},
    { &hf_t124_participantsList_item,
      { "TextString", "t124.TextString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_siteInformation,
      { "siteInformation", "t124.siteInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "TextString", HFILL }},
    { &hf_t124_alternativeNodeID,
      { "alternativeNodeID", "t124.alternativeNodeID",
        FT_UINT32, BASE_DEC, VALS(t124_AlternativeNodeID_vals), 0,
        NULL, HFILL }},
    { &hf_t124_userData,
      { "userData", "t124.userData",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nodeCategory,
      { "nodeCategory", "t124.nodeCategory",
        FT_UINT32, BASE_DEC, VALS(t124_NodeCategory_vals), 0,
        NULL, HFILL }},
    { &hf_t124_networkAddressV2,
      { "networkAddressV2", "t124.networkAddressV2",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_applicationProtocolKey,
      { "applicationProtocolKey", "t124.applicationProtocolKey",
        FT_UINT32, BASE_DEC, VALS(t124_Key_vals), 0,
        "Key", HFILL }},
    { &hf_t124_sessionID,
      { "sessionID", "t124.sessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChannelID", HFILL }},
    { &hf_t124_applicationActive,
      { "applicationActive", "t124.applicationActive",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_conductingOperationCapable,
      { "conductingOperationCapable", "t124.conductingOperationCapable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_startupChannel,
      { "startupChannel", "t124.startupChannel",
        FT_UINT32, BASE_DEC, VALS(t124_ChannelType_vals), 0,
        "ChannelType", HFILL }},
    { &hf_t124_applicationUserID,
      { "applicationUserID", "t124.applicationUserID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserID", HFILL }},
    { &hf_t124_nonCollapsingCapabilities,
      { "nonCollapsingCapabilities", "t124.nonCollapsingCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nonCollapsingCapabilities_item,
      { "nonCollapsingCapabilities item", "t124.nonCollapsingCapabilities_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_capabilityID,
      { "capabilityID", "t124.capabilityID",
        FT_UINT32, BASE_DEC, VALS(t124_CapabilityID_vals), 0,
        NULL, HFILL }},
    { &hf_t124_applicationData,
      { "applicationData", "t124.applicationData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t124_standard,
      { "standard", "t124.standard",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_t124_nonStandard_01,
      { "nonStandard", "t124.nonStandard",
        FT_UINT32, BASE_DEC, VALS(t124_Key_vals), 0,
        "Key", HFILL }},
    { &hf_t124_logical,
      { "logical", "t124.logical",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_unsignedMin,
      { "unsignedMin", "t124.unsignedMin",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_unsignedMax,
      { "unsignedMax", "t124.unsignedMax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_sessionKey,
      { "sessionKey", "t124.sessionKey",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_expectedCapabilitySet,
      { "expectedCapabilitySet", "t124.expectedCapabilitySet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_expectedCapabilitySet_item,
      { "expectedCapabilitySet item", "t124.expectedCapabilitySet_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_expectedCapabilitySet_item", HFILL }},
    { &hf_t124_capabilityClass,
      { "capabilityClass", "t124.capabilityClass",
        FT_UINT32, BASE_DEC, VALS(t124_CapabilityClass_vals), 0,
        NULL, HFILL }},
    { &hf_t124_mandatoryFlag,
      { "mandatoryFlag", "t124.mandatoryFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_resourceID,
      { "resourceID", "t124.resourceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_64", HFILL }},
    { &hf_t124_channelID,
      { "channelID", "t124.channelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DynamicChannelID", HFILL }},
    { &hf_t124_tokenID,
      { "tokenID", "t124.tokenID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DynamicTokenID", HFILL }},
    { &hf_t124_parameter,
      { "parameter", "t124.parameter",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_64", HFILL }},
    { &hf_t124_vacant,
      { "vacant", "t124.vacant",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_owned,
      { "owned", "t124.owned",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nodeID,
      { "nodeID", "t124.nodeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserID", HFILL }},
    { &hf_t124_entityID,
      { "entityID", "t124.entityID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_notOwned,
      { "notOwned", "t124.notOwned",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_convenerPassword,
      { "convenerPassword", "t124.convenerPassword",
        FT_NONE, BASE_NONE, NULL, 0,
        "Password", HFILL }},
    { &hf_t124_password,
      { "password", "t124.password",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_listedConference,
      { "listedConference", "t124.listedConference",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_conductibleConference,
      { "conductibleConference", "t124.conductibleConference",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_terminationMethod,
      { "terminationMethod", "t124.terminationMethod",
        FT_UINT32, BASE_DEC, VALS(t124_TerminationMethod_vals), 0,
        NULL, HFILL }},
    { &hf_t124_conductorPrivileges,
      { "conductorPrivileges", "t124.conductorPrivileges",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Privilege", HFILL }},
    { &hf_t124_conductorPrivileges_item,
      { "Privilege", "t124.Privilege",
        FT_UINT32, BASE_DEC, VALS(t124_Privilege_vals), 0,
        NULL, HFILL }},
    { &hf_t124_conductedPrivileges,
      { "conductedPrivileges", "t124.conductedPrivileges",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Privilege", HFILL }},
    { &hf_t124_conductedPrivileges_item,
      { "Privilege", "t124.Privilege",
        FT_UINT32, BASE_DEC, VALS(t124_Privilege_vals), 0,
        NULL, HFILL }},
    { &hf_t124_nonConductedPrivileges,
      { "nonConductedPrivileges", "t124.nonConductedPrivileges",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Privilege", HFILL }},
    { &hf_t124_nonConductedPrivileges_item,
      { "Privilege", "t124.Privilege",
        FT_UINT32, BASE_DEC, VALS(t124_Privilege_vals), 0,
        NULL, HFILL }},
    { &hf_t124_callerIdentifier,
      { "callerIdentifier", "t124.callerIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "TextString", HFILL }},
    { &hf_t124_conferencePriority,
      { "conferencePriority", "t124.conferencePriority",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tag,
      { "tag", "t124.tag",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_t124_result,
      { "result", "t124.result",
        FT_UINT32, BASE_DEC, VALS(t124_T_result_vals), 0,
        NULL, HFILL }},
    { &hf_t124_asymmetryIndicator,
      { "asymmetryIndicator", "t124.asymmetryIndicator",
        FT_UINT32, BASE_DEC, VALS(t124_AsymmetryIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_t124_conferenceList,
      { "conferenceList", "t124.conferenceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ConferenceDescriptor", HFILL }},
    { &hf_t124_conferenceList_item,
      { "ConferenceDescriptor", "t124.ConferenceDescriptor",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_queryResponseResult,
      { "result", "t124.result",
        FT_UINT32, BASE_DEC, VALS(t124_QueryResponseResult_vals), 0,
        "QueryResponseResult", HFILL }},
    { &hf_t124_waitForInvitationFlag,
      { "waitForInvitationFlag", "t124.waitForInvitationFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_noUnlistedConferenceFlag,
      { "noUnlistedConferenceFlag", "t124.noUnlistedConferenceFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_conferenceName_01,
      { "conferenceName", "t124.conferenceName",
        FT_UINT32, BASE_DEC, VALS(t124_ConferenceNameSelector_vals), 0,
        "ConferenceNameSelector", HFILL }},
    { &hf_t124_password_01,
      { "password", "t124.password",
        FT_UINT32, BASE_DEC, VALS(t124_PasswordChallengeRequestResponse_vals), 0,
        "PasswordChallengeRequestResponse", HFILL }},
    { &hf_t124_convenerPassword_01,
      { "convenerPassword", "t124.convenerPassword",
        FT_UINT32, BASE_DEC, VALS(t124_PasswordSelector_vals), 0,
        "PasswordSelector", HFILL }},
    { &hf_t124_topNodeID,
      { "topNodeID", "t124.topNodeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserID", HFILL }},
    { &hf_t124_conferenceNameAlias,
      { "conferenceNameAlias", "t124.conferenceNameAlias",
        FT_UINT32, BASE_DEC, VALS(t124_ConferenceNameSelector_vals), 0,
        "ConferenceNameSelector", HFILL }},
    { &hf_t124_joinResponseResult,
      { "result", "t124.result",
        FT_UINT32, BASE_DEC, VALS(t124_JoinResponseResult_vals), 0,
        "JoinResponseResult", HFILL }},
    { &hf_t124_inviteResponseResult,
      { "result", "t124.result",
        FT_UINT32, BASE_DEC, VALS(t124_InviteResponseResult_vals), 0,
        "InviteResponseResult", HFILL }},
    { &hf_t124_requestingNode,
      { "requestingNode", "t124.requestingNode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserID", HFILL }},
    { &hf_t124_addingMCU,
      { "addingMCU", "t124.addingMCU",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserID", HFILL }},
    { &hf_t124_terminateRequestReason,
      { "reason", "t124.reason",
        FT_UINT32, BASE_DEC, VALS(t124_TerminateRequestReason_vals), 0,
        "TerminateRequestReason", HFILL }},
    { &hf_t124_nodeToEject,
      { "nodeToEject", "t124.nodeToEject",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserID", HFILL }},
    { &hf_t124_ejectUserRequestReason,
      { "reason", "t124.reason",
        FT_UINT32, BASE_DEC, VALS(t124_EjectUserRequestReason_vals), 0,
        "EjectUserRequestReason", HFILL }},
    { &hf_t124_transferringNodes,
      { "transferringNodes", "t124.transferringNodes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_65536_OF_UserID", HFILL }},
    { &hf_t124_transferringNodes_item,
      { "UserID", "t124.UserID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_password_02,
      { "password", "t124.password",
        FT_UINT32, BASE_DEC, VALS(t124_PasswordSelector_vals), 0,
        "PasswordSelector", HFILL }},
    { &hf_t124_key_01,
      { "key", "t124.key",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistryKey", HFILL }},
    { &hf_t124_modificationRights,
      { "modificationRights", "t124.modificationRights",
        FT_UINT32, BASE_DEC, VALS(t124_RegistryModificationRights_vals), 0,
        "RegistryModificationRights", HFILL }},
    { &hf_t124_numberOfHandles,
      { "numberOfHandles", "t124.numberOfHandles",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1024", HFILL }},
    { &hf_t124_data_02,
      { "data", "t124.data",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_t124Identifier,
      { "t124Identifier", "t124.t124Identifier",
        FT_UINT32, BASE_DEC, VALS(t124_Key_vals), 0,
        "Key", HFILL }},
    { &hf_t124_connectPDU,
      { "connectPDU", "t124.connectPDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceCreateRequest,
      { "conferenceCreateRequest", "t124.conferenceCreateRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceCreateResponse,
      { "conferenceCreateResponse", "t124.conferenceCreateResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceQueryRequest,
      { "conferenceQueryRequest", "t124.conferenceQueryRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceQueryResponse,
      { "conferenceQueryResponse", "t124.conferenceQueryResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceJoinRequest,
      { "conferenceJoinRequest", "t124.conferenceJoinRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceJoinResponse,
      { "conferenceJoinResponse", "t124.conferenceJoinResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceInviteRequest,
      { "conferenceInviteRequest", "t124.conferenceInviteRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceInviteResponse,
      { "conferenceInviteResponse", "t124.conferenceInviteResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceAddRequest,
      { "conferenceAddRequest", "t124.conferenceAddRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceLockRequest,
      { "conferenceLockRequest", "t124.conferenceLockRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceUnlockRequest,
      { "conferenceUnlockRequest", "t124.conferenceUnlockRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceTerminateRequest,
      { "conferenceTerminateRequest", "t124.conferenceTerminateRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceEjectUserRequest,
      { "conferenceEjectUserRequest", "t124.conferenceEjectUserRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceTransferRequest,
      { "conferenceTransferRequest", "t124.conferenceTransferRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_registryRegisterChannelRequest,
      { "registryRegisterChannelRequest", "t124.registryRegisterChannelRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_registryAssignTokenRequest,
      { "registryAssignTokenRequest", "t124.registryAssignTokenRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_registrySetParameterRequest,
      { "registrySetParameterRequest", "t124.registrySetParameterRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_registryRetrieveEntryRequest,
      { "registryRetrieveEntryRequest", "t124.registryRetrieveEntryRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_registryDeleteEntryRequest,
      { "registryDeleteEntryRequest", "t124.registryDeleteEntryRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_registryMonitorEntryRequest,
      { "registryMonitorEntryRequest", "t124.registryMonitorEntryRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_registryAllocateHandleRequest,
      { "registryAllocateHandleRequest", "t124.registryAllocateHandleRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nonStandardRequest,
      { "nonStandardRequest", "t124.nonStandardRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardPDU", HFILL }},
    { &hf_t124_maxChannelIds,
      { "maxChannelIds", "t124.maxChannelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_maxUserIds,
      { "maxUserIds", "t124.maxUserIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_maxTokenIds,
      { "maxTokenIds", "t124.maxTokenIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_numPriorities,
      { "numPriorities", "t124.numPriorities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_minThroughput,
      { "minThroughput", "t124.minThroughput",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_maxHeight,
      { "maxHeight", "t124.maxHeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_maxMCSPDUsize,
      { "maxMCSPDUsize", "t124.maxMCSPDUsize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_protocolVersion,
      { "protocolVersion", "t124.protocolVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_heightLimit,
      { "heightLimit", "t124.heightLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_subHeight,
      { "subHeight", "t124.subHeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_subInterval,
      { "subInterval", "t124.subInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_static,
      { "static", "t124.static",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelId,
      { "channelId", "t124.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StaticChannelId", HFILL }},
    { &hf_t124_userId,
      { "userId", "t124.userId",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_joined,
      { "joined", "t124.joined",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_userId_01,
      { "userId", "t124.userId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_private,
      { "private", "t124.private",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelId_01,
      { "channelId", "t124.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateChannelId", HFILL }},
    { &hf_t124_manager,
      { "manager", "t124.manager",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t124_admitted,
      { "admitted", "t124.admitted",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t124_admitted_item,
      { "UserId", "t124.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_assigned,
      { "assigned", "t124.assigned",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelId_02,
      { "channelId", "t124.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AssignedChannelId", HFILL }},
    { &hf_t124_mergeChannels,
      { "mergeChannels", "t124.mergeChannels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChannelAttributes", HFILL }},
    { &hf_t124_mergeChannels_item,
      { "ChannelAttributes", "t124.ChannelAttributes",
        FT_UINT32, BASE_DEC, VALS(t124_ChannelAttributes_vals), 0,
        NULL, HFILL }},
    { &hf_t124_purgeChannelIds,
      { "purgeChannelIds", "t124.purgeChannelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChannelId", HFILL }},
    { &hf_t124_purgeChannelIds_item,
      { "ChannelId", "t124.ChannelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_detachUserIds,
      { "detachUserIds", "t124.detachUserIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t124_detachUserIds_item,
      { "UserId", "t124.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_grabbed,
      { "grabbed", "t124.grabbed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenId,
      { "tokenId", "t124.tokenId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_grabber,
      { "grabber", "t124.grabber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t124_inhibited,
      { "inhibited", "t124.inhibited",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_inhibitors,
      { "inhibitors", "t124.inhibitors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t124_inhibitors_item,
      { "UserId", "t124.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_giving,
      { "giving", "t124.giving",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_recipient,
      { "recipient", "t124.recipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t124_ungivable,
      { "ungivable", "t124.ungivable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_given,
      { "given", "t124.given",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_mergeTokens,
      { "mergeTokens", "t124.mergeTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_TokenAttributes", HFILL }},
    { &hf_t124_mergeTokens_item,
      { "TokenAttributes", "t124.TokenAttributes",
        FT_UINT32, BASE_DEC, VALS(t124_TokenAttributes_vals), 0,
        NULL, HFILL }},
    { &hf_t124_purgeTokenIds,
      { "purgeTokenIds", "t124.purgeTokenIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_TokenId", HFILL }},
    { &hf_t124_purgeTokenIds_item,
      { "TokenId", "t124.TokenId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_reason,
      { "reason", "t124.reason",
        FT_UINT32, BASE_DEC, VALS(t124_Reason_vals), 0,
        NULL, HFILL }},
    { &hf_t124_diagnostic,
      { "diagnostic", "t124.diagnostic",
        FT_UINT32, BASE_DEC, VALS(t124_Diagnostic_vals), 0,
        NULL, HFILL }},
    { &hf_t124_initialOctets,
      { "initialOctets", "t124.initialOctets",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t124_result_01,
      { "result", "t124.result",
        FT_UINT32, BASE_DEC, VALS(t124_Result_vals), 0,
        NULL, HFILL }},
    { &hf_t124_initiator,
      { "initiator", "t124.initiator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t124_userIds,
      { "userIds", "t124.userIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t124_userIds_item,
      { "UserId", "t124.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelId_03,
      { "channelId", "t124.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_requested,
      { "requested", "t124.requested",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChannelId", HFILL }},
    { &hf_t124_channelIds,
      { "channelIds", "t124.channelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChannelId", HFILL }},
    { &hf_t124_channelIds_item,
      { "ChannelId", "t124.ChannelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_dataPriority,
      { "dataPriority", "t124.dataPriority",
        FT_UINT32, BASE_DEC, VALS(t124_DataPriority_vals), 0,
        NULL, HFILL }},
    { &hf_t124_segmentation,
      { "segmentation", "t124.segmentation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_userData_01,
      { "userData", "t124.userData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_userData_02,
      { "userData", "t124.userData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userData_01", HFILL }},
    { &hf_t124_userData_03,
      { "userData", "t124.userData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t124_tokenStatus,
      { "tokenStatus", "t124.tokenStatus",
        FT_UINT32, BASE_DEC, VALS(t124_TokenStatus_vals), 0,
        NULL, HFILL }},
    { &hf_t124_plumbDomainIndication,
      { "plumbDomainIndication", "t124.plumbDomainIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_erectDomainRequest,
      { "erectDomainRequest", "t124.erectDomainRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_mergeChannelsRequest,
      { "mergeChannelsRequest", "t124.mergeChannelsRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_mergeChannelsConfirm,
      { "mergeChannelsConfirm", "t124.mergeChannelsConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_purgeChannelsIndication,
      { "purgeChannelsIndication", "t124.purgeChannelsIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_mergeTokensRequest,
      { "mergeTokensRequest", "t124.mergeTokensRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_mergeTokensConfirm,
      { "mergeTokensConfirm", "t124.mergeTokensConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_purgeTokensIndication,
      { "purgeTokensIndication", "t124.purgeTokensIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_disconnectProviderUltimatum,
      { "disconnectProviderUltimatum", "t124.disconnectProviderUltimatum",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_rejectMCSPDUUltimatum,
      { "rejectMCSPDUUltimatum", "t124.rejectMCSPDUUltimatum",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_attachUserRequest,
      { "attachUserRequest", "t124.attachUserRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_attachUserConfirm,
      { "attachUserConfirm", "t124.attachUserConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_detachUserRequest,
      { "detachUserRequest", "t124.detachUserRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_detachUserIndication,
      { "detachUserIndication", "t124.detachUserIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelJoinRequest,
      { "channelJoinRequest", "t124.channelJoinRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelJoinConfirm,
      { "channelJoinConfirm", "t124.channelJoinConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelLeaveRequest,
      { "channelLeaveRequest", "t124.channelLeaveRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelConveneRequest,
      { "channelConveneRequest", "t124.channelConveneRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelConveneConfirm,
      { "channelConveneConfirm", "t124.channelConveneConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelDisbandRequest,
      { "channelDisbandRequest", "t124.channelDisbandRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelDisbandIndication,
      { "channelDisbandIndication", "t124.channelDisbandIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelAdmitRequest,
      { "channelAdmitRequest", "t124.channelAdmitRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelAdmitIndication,
      { "channelAdmitIndication", "t124.channelAdmitIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelExpelRequest,
      { "channelExpelRequest", "t124.channelExpelRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelExpelIndication,
      { "channelExpelIndication", "t124.channelExpelIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_sendDataRequest,
      { "sendDataRequest", "t124.sendDataRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_sendDataIndication,
      { "sendDataIndication", "t124.sendDataIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_uniformSendDataRequest,
      { "uniformSendDataRequest", "t124.uniformSendDataRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_uniformSendDataIndication,
      { "uniformSendDataIndication", "t124.uniformSendDataIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGrabRequest,
      { "tokenGrabRequest", "t124.tokenGrabRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGrabConfirm,
      { "tokenGrabConfirm", "t124.tokenGrabConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenInhibitRequest,
      { "tokenInhibitRequest", "t124.tokenInhibitRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenInhibitConfirm,
      { "tokenInhibitConfirm", "t124.tokenInhibitConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGiveRequest,
      { "tokenGiveRequest", "t124.tokenGiveRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGiveIndication,
      { "tokenGiveIndication", "t124.tokenGiveIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGiveResponse,
      { "tokenGiveResponse", "t124.tokenGiveResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGiveConfirm,
      { "tokenGiveConfirm", "t124.tokenGiveConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenPleaseRequest,
      { "tokenPleaseRequest", "t124.tokenPleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenPleaseIndication,
      { "tokenPleaseIndication", "t124.tokenPleaseIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenReleaseRequest,
      { "tokenReleaseRequest", "t124.tokenReleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenReleaseConfirm,
      { "tokenReleaseConfirm", "t124.tokenReleaseConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenTestRequest,
      { "tokenTestRequest", "t124.tokenTestRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenTestConfirm,
      { "tokenTestConfirm", "t124.tokenTestConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_Segmentation_begin,
      { "begin", "t124.begin",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_t124_Segmentation_end,
      { "end", "t124.end",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

/*--- End of included file: packet-t124-hfarr.c ---*/
#line 188 "../../asn1/t124/packet-t124-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_t124,
	  &ett_t124_connectGCCPDU,

/*--- Included file: packet-t124-ettarr.c ---*/
#line 1 "../../asn1/t124/packet-t124-ettarr.c"
    &ett_t124_Key,
    &ett_t124_NonStandardParameter,
    &ett_t124_UserData,
    &ett_t124_UserData_item,
    &ett_t124_Password,
    &ett_t124_PasswordSelector,
    &ett_t124_ChallengeResponseItem,
    &ett_t124_ChallengeResponseAlgorithm,
    &ett_t124_ChallengeItem,
    &ett_t124_ChallengeRequest,
    &ett_t124_SET_OF_ChallengeItem,
    &ett_t124_ChallengeResponse,
    &ett_t124_PasswordChallengeRequestResponse,
    &ett_t124_T_challengeRequestResponse,
    &ett_t124_ConferenceName,
    &ett_t124_ConferenceNameSelector,
    &ett_t124_ConferencePriorityScheme,
    &ett_t124_ConferencePriority,
    &ett_t124_NodeCategory,
    &ett_t124_ConferenceMode,
    &ett_t124_NetworkAddress,
    &ett_t124_NetworkAddress_item,
    &ett_t124_T_aggregatedChannel,
    &ett_t124_T_transferModes,
    &ett_t124_T_highLayerCompatibility,
    &ett_t124_T_transportConnection,
    &ett_t124_MediaList,
    &ett_t124_ChannelAggregationMethod,
    &ett_t124_Profile,
    &ett_t124_T_simpleProfile,
    &ett_t124_T_multimediaProfile,
    &ett_t124_T_profile,
    &ett_t124_ExtendedE164NetworkAddress,
    &ett_t124_TransportAddress,
    &ett_t124_GSTNConnection,
    &ett_t124_ISDNConnection,
    &ett_t124_ISDNCircuitTypes,
    &ett_t124_ISDNCircuitTypes_item,
    &ett_t124_ISDNHighLayerCompatibility,
    &ett_t124_CSDNConnection,
    &ett_t124_T_circuitTypes,
    &ett_t124_T_circuitTypes_item,
    &ett_t124_PSDNConnection,
    &ett_t124_PSDNNetworkAddress,
    &ett_t124_ATMConnection,
    &ett_t124_T_networkAddress,
    &ett_t124_NetworkConnection,
    &ett_t124_NetworkAddressV2,
    &ett_t124_NetworkAddressV2_item,
    &ett_t124_T_networkConnection,
    &ett_t124_T_aggregatedConnections,
    &ett_t124_T_connectionList,
    &ett_t124_T_connectionList_item,
    &ett_t124_SET_OF_ChannelAggregationMethod,
    &ett_t124_SET_OF_Profile,
    &ett_t124_NodeProperties,
    &ett_t124_AsymmetryIndicator,
    &ett_t124_AlternativeNodeID,
    &ett_t124_ConferenceDescriptor,
    &ett_t124_NodeRecord,
    &ett_t124_SEQUENCE_OF_TextString,
    &ett_t124_SessionKey,
    &ett_t124_ApplicationRecord,
    &ett_t124_T_nonCollapsingCapabilities,
    &ett_t124_T_nonCollapsingCapabilities_item,
    &ett_t124_CapabilityID,
    &ett_t124_CapabilityClass,
    &ett_t124_ApplicationInvokeSpecifier,
    &ett_t124_T_expectedCapabilitySet,
    &ett_t124_T_expectedCapabilitySet_item,
    &ett_t124_RegistryKey,
    &ett_t124_RegistryItem,
    &ett_t124_RegistryEntryOwner,
    &ett_t124_T_owned,
    &ett_t124_ConferenceCreateRequest,
    &ett_t124_SET_OF_Privilege,
    &ett_t124_ConferenceCreateResponse,
    &ett_t124_ConferenceQueryRequest,
    &ett_t124_ConferenceQueryResponse,
    &ett_t124_SET_OF_ConferenceDescriptor,
    &ett_t124_ConferenceJoinRequest,
    &ett_t124_ConferenceJoinResponse,
    &ett_t124_ConferenceInviteRequest,
    &ett_t124_ConferenceInviteResponse,
    &ett_t124_ConferenceAddRequest,
    &ett_t124_ConferenceLockRequest,
    &ett_t124_ConferenceUnlockRequest,
    &ett_t124_ConferenceTerminateRequest,
    &ett_t124_ConferenceEjectUserRequest,
    &ett_t124_ConferenceTransferRequest,
    &ett_t124_SET_SIZE_1_65536_OF_UserID,
    &ett_t124_RegistryRegisterChannelRequest,
    &ett_t124_RegistryAssignTokenRequest,
    &ett_t124_RegistrySetParameterRequest,
    &ett_t124_RegistryRetrieveEntryRequest,
    &ett_t124_RegistryDeleteEntryRequest,
    &ett_t124_RegistryMonitorEntryRequest,
    &ett_t124_RegistryAllocateHandleRequest,
    &ett_t124_NonStandardPDU,
    &ett_t124_ConnectData,
    &ett_t124_ConnectGCCPDU,
    &ett_t124_RequestPDU,
    &ett_t124_Segmentation,
    &ett_t124_DomainParameters,
    &ett_t124_PlumbDomainIndication,
    &ett_t124_ErectDomainRequest,
    &ett_t124_ChannelAttributes,
    &ett_t124_T_static,
    &ett_t124_T_userId,
    &ett_t124_T_private,
    &ett_t124_SET_OF_UserId,
    &ett_t124_T_assigned,
    &ett_t124_MergeChannelsRequest,
    &ett_t124_SET_OF_ChannelAttributes,
    &ett_t124_SET_OF_ChannelId,
    &ett_t124_MergeChannelsConfirm,
    &ett_t124_PurgeChannelsIndication,
    &ett_t124_TokenAttributes,
    &ett_t124_T_grabbed,
    &ett_t124_T_inhibited,
    &ett_t124_T_giving,
    &ett_t124_T_ungivable,
    &ett_t124_T_given,
    &ett_t124_MergeTokensRequest,
    &ett_t124_SET_OF_TokenAttributes,
    &ett_t124_SET_OF_TokenId,
    &ett_t124_MergeTokensConfirm,
    &ett_t124_PurgeTokensIndication,
    &ett_t124_DisconnectProviderUltimatum,
    &ett_t124_RejectMCSPDUUltimatum,
    &ett_t124_AttachUserRequest,
    &ett_t124_AttachUserConfirm,
    &ett_t124_DetachUserRequest,
    &ett_t124_DetachUserIndication,
    &ett_t124_ChannelJoinRequest,
    &ett_t124_ChannelJoinConfirm,
    &ett_t124_ChannelLeaveRequest,
    &ett_t124_ChannelConveneRequest,
    &ett_t124_ChannelConveneConfirm,
    &ett_t124_ChannelDisbandRequest,
    &ett_t124_ChannelDisbandIndication,
    &ett_t124_ChannelAdmitRequest,
    &ett_t124_ChannelAdmitIndication,
    &ett_t124_ChannelExpelRequest,
    &ett_t124_ChannelExpelIndication,
    &ett_t124_SendDataRequest,
    &ett_t124_SendDataIndication,
    &ett_t124_UniformSendDataRequest,
    &ett_t124_UniformSendDataIndication,
    &ett_t124_TokenGrabRequest,
    &ett_t124_TokenGrabConfirm,
    &ett_t124_TokenInhibitRequest,
    &ett_t124_TokenInhibitConfirm,
    &ett_t124_TokenGiveRequest,
    &ett_t124_TokenGiveIndication,
    &ett_t124_TokenGiveResponse,
    &ett_t124_TokenGiveConfirm,
    &ett_t124_TokenPleaseRequest,
    &ett_t124_TokenPleaseIndication,
    &ett_t124_TokenReleaseRequest,
    &ett_t124_TokenReleaseConfirm,
    &ett_t124_TokenTestRequest,
    &ett_t124_TokenTestConfirm,
    &ett_t124_DomainMCSPDU,

/*--- End of included file: packet-t124-ettarr.c ---*/
#line 195 "../../asn1/t124/packet-t124-template.c"
  };
  
  /* Register protocol */
  proto_t124 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_t124, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  t124_ns_dissector_table = register_dissector_table("t124.ns", "T.124 H.221 Non Standard Dissectors", FT_STRING, BASE_NONE);
  t124_sd_dissector_table = register_dissector_table("t124.sd", "T.124 H.221 Send Data Dissectors", FT_UINT32, BASE_NONE);

  new_register_dissector("t124", dissect_t124_new, proto_t124);

}

void
proto_reg_handoff_t124(void) {

  register_ber_oid_dissector("0.0.20.124.0.1", dissect_t124, proto_t124, "Generic Conference Control");

  heur_dissector_add("t125", dissect_t124_heur, proto_t124);

}
