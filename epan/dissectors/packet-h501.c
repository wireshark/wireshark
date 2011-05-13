/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-h501.c                                                              */
/* ../../tools/asn2wrs.py -p h501 -c ./h501.cnf -s ./packet-h501-template -D . H501-MESSAGES.asn */

/* Input file: packet-h501-template.c */

#line 1 "../../asn1/h501/packet-h501-template.c"
/* packet-h501.c
 * Routines for H.501 packet dissection
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
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-tpkt.h"
#include "packet-per.h"
#include "packet-h225.h"
#include "packet-h235.h"

#define PNAME  "H.501 Mobility"
#define PSNAME "H.501"
#define PFNAME "h501"

/* Initialize the protocol and registered fields */
static int proto_h501 = -1;

/*--- Included file: packet-h501-hf.c ---*/
#line 1 "../../asn1/h501/packet-h501-hf.c"
static int hf_h501_Message_PDU = -1;              /* Message */
static int hf_h501_body = -1;                     /* MessageBody */
static int hf_h501_common = -1;                   /* MessageCommonInfo */
static int hf_h501_serviceRequest = -1;           /* ServiceRequest */
static int hf_h501_serviceConfirmation = -1;      /* ServiceConfirmation */
static int hf_h501_serviceRejection = -1;         /* ServiceRejection */
static int hf_h501_serviceRelease = -1;           /* ServiceRelease */
static int hf_h501_descriptorRequest = -1;        /* DescriptorRequest */
static int hf_h501_descriptorConfirmation = -1;   /* DescriptorConfirmation */
static int hf_h501_descriptorRejection = -1;      /* DescriptorRejection */
static int hf_h501_descriptorIDRequest = -1;      /* DescriptorIDRequest */
static int hf_h501_descriptorIDConfirmation = -1;  /* DescriptorIDConfirmation */
static int hf_h501_descriptorIDRejection = -1;    /* DescriptorIDRejection */
static int hf_h501_descriptorUpdate = -1;         /* DescriptorUpdate */
static int hf_h501_descriptorUpdateAck = -1;      /* DescriptorUpdateAck */
static int hf_h501_accessRequest = -1;            /* AccessRequest */
static int hf_h501_accessConfirmation = -1;       /* AccessConfirmation */
static int hf_h501_accessRejection = -1;          /* AccessRejection */
static int hf_h501_requestInProgress = -1;        /* RequestInProgress */
static int hf_h501_nonStandardRequest = -1;       /* NonStandardRequest */
static int hf_h501_nonStandardConfirmation = -1;  /* NonStandardConfirmation */
static int hf_h501_nonStandardRejection = -1;     /* NonStandardRejection */
static int hf_h501_unknownMessageResponse = -1;   /* UnknownMessageResponse */
static int hf_h501_usageRequest = -1;             /* UsageRequest */
static int hf_h501_usageConfirmation = -1;        /* UsageConfirmation */
static int hf_h501_usageIndication = -1;          /* UsageIndication */
static int hf_h501_usageIndicationConfirmation = -1;  /* UsageIndicationConfirmation */
static int hf_h501_usageIndicationRejection = -1;  /* UsageIndicationRejection */
static int hf_h501_usageRejection = -1;           /* UsageRejection */
static int hf_h501_validationRequest = -1;        /* ValidationRequest */
static int hf_h501_validationConfirmation = -1;   /* ValidationConfirmation */
static int hf_h501_validationRejection = -1;      /* ValidationRejection */
static int hf_h501_authenticationRequest = -1;    /* AuthenticationRequest */
static int hf_h501_authenticationConfirmation = -1;  /* AuthenticationConfirmation */
static int hf_h501_authenticationRejection = -1;  /* AuthenticationRejection */
static int hf_h501_sequenceNumber = -1;           /* INTEGER_0_65535 */
static int hf_h501_annexGversion = -1;            /* ProtocolVersion */
static int hf_h501_hopCount = -1;                 /* INTEGER_1_255 */
static int hf_h501_replyAddress = -1;             /* SEQUENCE_OF_TransportAddress */
static int hf_h501_replyAddress_item = -1;        /* TransportAddress */
static int hf_h501_integrityCheckValue = -1;      /* ICV */
static int hf_h501_tokens = -1;                   /* SEQUENCE_OF_ClearToken */
static int hf_h501_tokens_item = -1;              /* ClearToken */
static int hf_h501_cryptoTokens = -1;             /* SEQUENCE_OF_CryptoH323Token */
static int hf_h501_cryptoTokens_item = -1;        /* CryptoH323Token */
static int hf_h501_nonStandard = -1;              /* SEQUENCE_OF_NonStandardParameter */
static int hf_h501_nonStandard_item = -1;         /* NonStandardParameter */
static int hf_h501_serviceID = -1;                /* ServiceID */
static int hf_h501_genericData = -1;              /* SEQUENCE_OF_GenericData */
static int hf_h501_genericData_item = -1;         /* GenericData */
static int hf_h501_featureSet = -1;               /* FeatureSet */
static int hf_h501_version = -1;                  /* ProtocolVersion */
static int hf_h501_elementIdentifier = -1;        /* ElementIdentifier */
static int hf_h501_domainIdentifier = -1;         /* AliasAddress */
static int hf_h501_securityMode = -1;             /* SEQUENCE_OF_SecurityMode */
static int hf_h501_securityMode_item = -1;        /* SecurityMode */
static int hf_h501_timeToLive = -1;               /* INTEGER_1_4294967295 */
static int hf_h501_usageSpec = -1;                /* UsageSpecification */
static int hf_h501_authentication = -1;           /* AuthenticationMechanism */
static int hf_h501_integrity = -1;                /* IntegrityMechanism */
static int hf_h501_algorithmOIDs = -1;            /* T_algorithmOIDs */
static int hf_h501_algorithmOIDs_item = -1;       /* OBJECT_IDENTIFIER */
static int hf_h501_alternates = -1;               /* AlternatePEInfo */
static int hf_h501_securityMode_01 = -1;          /* SecurityMode */
static int hf_h501_reason = -1;                   /* ServiceRejectionReason */
static int hf_h501_serviceUnavailable = -1;       /* NULL */
static int hf_h501_serviceRedirected = -1;        /* NULL */
static int hf_h501_security = -1;                 /* NULL */
static int hf_h501_continue = -1;                 /* NULL */
static int hf_h501_undefined = -1;                /* NULL */
static int hf_h501_unknownServiceID = -1;         /* NULL */
static int hf_h501_cannotSupportUsageSpec = -1;   /* NULL */
static int hf_h501_neededFeature = -1;            /* NULL */
static int hf_h501_genericDataReason = -1;        /* NULL */
static int hf_h501_usageUnavailable = -1;         /* NULL */
static int hf_h501_unknownUsageSendTo = -1;       /* NULL */
static int hf_h501_reason_01 = -1;                /* ServiceReleaseReason */
static int hf_h501_outOfService = -1;             /* NULL */
static int hf_h501_maintenance = -1;              /* NULL */
static int hf_h501_terminated = -1;               /* NULL */
static int hf_h501_expired = -1;                  /* NULL */
static int hf_h501_descriptorID = -1;             /* SEQUENCE_OF_DescriptorID */
static int hf_h501_descriptorID_item = -1;        /* DescriptorID */
static int hf_h501_descriptor = -1;               /* SEQUENCE_OF_Descriptor */
static int hf_h501_descriptor_item = -1;          /* Descriptor */
static int hf_h501_reason_02 = -1;                /* DescriptorRejectionReason */
static int hf_h501_descriptorID_01 = -1;          /* DescriptorID */
static int hf_h501_packetSizeExceeded = -1;       /* NULL */
static int hf_h501_illegalID = -1;                /* NULL */
static int hf_h501_hopCountExceeded = -1;         /* NULL */
static int hf_h501_noServiceRelationship = -1;    /* NULL */
static int hf_h501_descriptorInfo = -1;           /* SEQUENCE_OF_DescriptorInfo */
static int hf_h501_descriptorInfo_item = -1;      /* DescriptorInfo */
static int hf_h501_reason_03 = -1;                /* DescriptorIDRejectionReason */
static int hf_h501_noDescriptors = -1;            /* NULL */
static int hf_h501_sender = -1;                   /* AliasAddress */
static int hf_h501_updateInfo = -1;               /* SEQUENCE_OF_UpdateInformation */
static int hf_h501_updateInfo_item = -1;          /* UpdateInformation */
static int hf_h501_descriptorInfo_01 = -1;        /* T_descriptorInfo */
static int hf_h501_descriptor_01 = -1;            /* Descriptor */
static int hf_h501_updateType = -1;               /* T_updateType */
static int hf_h501_added = -1;                    /* NULL */
static int hf_h501_deleted = -1;                  /* NULL */
static int hf_h501_changed = -1;                  /* NULL */
static int hf_h501_destinationInfo = -1;          /* PartyInformation */
static int hf_h501_sourceInfo = -1;               /* PartyInformation */
static int hf_h501_callInfo = -1;                 /* CallInformation */
static int hf_h501_desiredProtocols = -1;         /* SEQUENCE_OF_SupportedProtocols */
static int hf_h501_desiredProtocols_item = -1;    /* SupportedProtocols */
static int hf_h501_templates = -1;                /* SEQUENCE_OF_AddressTemplate */
static int hf_h501_templates_item = -1;           /* AddressTemplate */
static int hf_h501_partialResponse = -1;          /* BOOLEAN */
static int hf_h501_supportedProtocols = -1;       /* SEQUENCE_OF_SupportedProtocols */
static int hf_h501_supportedProtocols_item = -1;  /* SupportedProtocols */
static int hf_h501_serviceControl = -1;           /* SEQUENCE_OF_ServiceControlSession */
static int hf_h501_serviceControl_item = -1;      /* ServiceControlSession */
static int hf_h501_reason_04 = -1;                /* AccessRejectionReason */
static int hf_h501_noMatch = -1;                  /* NULL */
static int hf_h501_needCallInformation = -1;      /* NULL */
static int hf_h501_destinationUnavailable = -1;   /* NULL */
static int hf_h501_aliasesInconsistent = -1;      /* NULL */
static int hf_h501_resourceUnavailable = -1;      /* NULL */
static int hf_h501_incompleteAddress = -1;        /* NULL */
static int hf_h501_reason_05 = -1;                /* UsageRejectReason */
static int hf_h501_accessTokens = -1;             /* SEQUENCE_OF_AccessToken */
static int hf_h501_accessTokens_item = -1;        /* AccessToken */
static int hf_h501_senderRole = -1;               /* Role */
static int hf_h501_usageCallStatus = -1;          /* UsageCallStatus */
static int hf_h501_srcInfo = -1;                  /* PartyInformation */
static int hf_h501_destAddress = -1;              /* PartyInformation */
static int hf_h501_startTime = -1;                /* TimeStamp */
static int hf_h501_endTime = -1;                  /* TimeStamp */
static int hf_h501_terminationCause = -1;         /* TerminationCause */
static int hf_h501_usageFields = -1;              /* SEQUENCE_OF_UsageField */
static int hf_h501_usageFields_item = -1;         /* UsageField */
static int hf_h501_id = -1;                       /* OBJECT_IDENTIFIER */
static int hf_h501_value = -1;                    /* OCTET_STRING */
static int hf_h501_invalidCall = -1;              /* NULL */
static int hf_h501_unavailable = -1;              /* NULL */
static int hf_h501_reason_06 = -1;                /* UsageIndicationRejectionReason */
static int hf_h501_unknownCall = -1;              /* NULL */
static int hf_h501_incomplete = -1;               /* NULL */
static int hf_h501_accessToken = -1;              /* SEQUENCE_OF_AccessToken */
static int hf_h501_accessToken_item = -1;         /* AccessToken */
static int hf_h501_reason_07 = -1;                /* ValidationRejectionReason */
static int hf_h501_tokenNotValid = -1;            /* NULL */
static int hf_h501_missingSourceInfo = -1;        /* NULL */
static int hf_h501_missingDestInfo = -1;          /* NULL */
static int hf_h501_delay = -1;                    /* INTEGER_1_65535 */
static int hf_h501_reason_08 = -1;                /* NonStandardRejectionReason */
static int hf_h501_notSupported = -1;             /* NULL */
static int hf_h501_unknownMessage = -1;           /* OCTET_STRING */
static int hf_h501_reason_09 = -1;                /* UnknownMessageReason */
static int hf_h501_notUnderstood = -1;            /* NULL */
static int hf_h501_applicationMessage = -1;       /* ApplicationMessage */
static int hf_h501_reason_10 = -1;                /* AuthenticationRejectionReason */
static int hf_h501_securityWrongSyncTime = -1;    /* NULL */
static int hf_h501_securityReplay = -1;           /* NULL */
static int hf_h501_securityWrongGeneralID = -1;   /* NULL */
static int hf_h501_securityWrongSendersID = -1;   /* NULL */
static int hf_h501_securityIntegrityFailed = -1;  /* NULL */
static int hf_h501_securityWrongOID = -1;         /* NULL */
static int hf_h501_pattern = -1;                  /* SEQUENCE_OF_Pattern */
static int hf_h501_pattern_item = -1;             /* Pattern */
static int hf_h501_routeInfo = -1;                /* SEQUENCE_OF_RouteInformation */
static int hf_h501_routeInfo_item = -1;           /* RouteInformation */
static int hf_h501_specific = -1;                 /* AliasAddress */
static int hf_h501_wildcard = -1;                 /* AliasAddress */
static int hf_h501_range = -1;                    /* T_range */
static int hf_h501_startOfRange = -1;             /* PartyNumber */
static int hf_h501_endOfRange = -1;               /* PartyNumber */
static int hf_h501_messageType = -1;              /* T_messageType */
static int hf_h501_sendAccessRequest = -1;        /* NULL */
static int hf_h501_sendSetup = -1;                /* NULL */
static int hf_h501_nonExistent = -1;              /* NULL */
static int hf_h501_callSpecific = -1;             /* BOOLEAN */
static int hf_h501_priceInfo = -1;                /* SEQUENCE_OF_PriceInfoSpec */
static int hf_h501_priceInfo_item = -1;           /* PriceInfoSpec */
static int hf_h501_contacts = -1;                 /* SEQUENCE_OF_ContactInformation */
static int hf_h501_contacts_item = -1;            /* ContactInformation */
static int hf_h501_type = -1;                     /* EndpointType */
static int hf_h501_circuitID = -1;                /* CircuitInfo */
static int hf_h501_supportedCircuits = -1;        /* SEQUENCE_OF_CircuitIdentifier */
static int hf_h501_supportedCircuits_item = -1;   /* CircuitIdentifier */
static int hf_h501_transportAddress = -1;         /* AliasAddress */
static int hf_h501_priority = -1;                 /* INTEGER_0_127 */
static int hf_h501_transportQoS = -1;             /* TransportQOS */
static int hf_h501_security_01 = -1;              /* SEQUENCE_OF_SecurityMode */
static int hf_h501_security_item = -1;            /* SecurityMode */
static int hf_h501_multipleCalls = -1;            /* BOOLEAN */
static int hf_h501_currency = -1;                 /* IA5String_SIZE_3 */
static int hf_h501_currencyScale = -1;            /* INTEGER_M127_127 */
static int hf_h501_validFrom = -1;                /* GlobalTimeStamp */
static int hf_h501_validUntil = -1;               /* GlobalTimeStamp */
static int hf_h501_hoursFrom = -1;                /* IA5String_SIZE_6 */
static int hf_h501_hoursUntil = -1;               /* IA5String_SIZE_6 */
static int hf_h501_priceElement = -1;             /* SEQUENCE_OF_PriceElement */
static int hf_h501_priceElement_item = -1;        /* PriceElement */
static int hf_h501_priceFormula = -1;             /* IA5String_SIZE_1_2048 */
static int hf_h501_amount = -1;                   /* INTEGER_0_4294967295 */
static int hf_h501_quantum = -1;                  /* INTEGER_0_4294967295 */
static int hf_h501_units = -1;                    /* T_units */
static int hf_h501_seconds = -1;                  /* NULL */
static int hf_h501_packets = -1;                  /* NULL */
static int hf_h501_bytes = -1;                    /* NULL */
static int hf_h501_initial = -1;                  /* NULL */
static int hf_h501_minimum = -1;                  /* NULL */
static int hf_h501_maximum = -1;                  /* NULL */
static int hf_h501_descriptorInfo_02 = -1;        /* DescriptorInfo */
static int hf_h501_gatekeeperID = -1;             /* GatekeeperIdentifier */
static int hf_h501_lastChanged = -1;              /* GlobalTimeStamp */
static int hf_h501_alternatePE = -1;              /* SEQUENCE_OF_AlternatePE */
static int hf_h501_alternatePE_item = -1;         /* AlternatePE */
static int hf_h501_alternateIsPermanent = -1;     /* BOOLEAN */
static int hf_h501_contactAddress = -1;           /* AliasAddress */
static int hf_h501_priority_01 = -1;              /* INTEGER_1_127 */
static int hf_h501_token = -1;                    /* ClearToken */
static int hf_h501_cryptoToken = -1;              /* CryptoH323Token */
static int hf_h501_genericData_01 = -1;           /* GenericData */
static int hf_h501_callIdentifier = -1;           /* CallIdentifier */
static int hf_h501_conferenceID = -1;             /* ConferenceIdentifier */
static int hf_h501_preConnect = -1;               /* NULL */
static int hf_h501_callInProgress = -1;           /* NULL */
static int hf_h501_callEnded = -1;                /* NULL */
static int hf_h501_registrationLost = -1;         /* NULL */
static int hf_h501_userIdentifier = -1;           /* AliasAddress */
static int hf_h501_userAuthenticator = -1;        /* SEQUENCE_OF_CryptoH323Token */
static int hf_h501_userAuthenticator_item = -1;   /* CryptoH323Token */
static int hf_h501_sendTo = -1;                   /* ElementIdentifier */
static int hf_h501_when = -1;                     /* T_when */
static int hf_h501_never = -1;                    /* NULL */
static int hf_h501_start = -1;                    /* NULL */
static int hf_h501_end = -1;                      /* NULL */
static int hf_h501_period = -1;                   /* INTEGER_1_65535 */
static int hf_h501_failures = -1;                 /* NULL */
static int hf_h501_required = -1;                 /* T_required */
static int hf_h501_required_item = -1;            /* OBJECT_IDENTIFIER */
static int hf_h501_preferred = -1;                /* T_preferred */
static int hf_h501_preferred_item = -1;           /* OBJECT_IDENTIFIER */
static int hf_h501_sendToPEAddress = -1;          /* AliasAddress */
static int hf_h501_logicalAddresses = -1;         /* SEQUENCE_OF_AliasAddress */
static int hf_h501_logicalAddresses_item = -1;    /* AliasAddress */
static int hf_h501_endpointType = -1;             /* EndpointType */
static int hf_h501_userInfo = -1;                 /* UserInformation */
static int hf_h501_timeZone = -1;                 /* TimeZone */
static int hf_h501_originator = -1;               /* NULL */
static int hf_h501_destination = -1;              /* NULL */
static int hf_h501_nonStandardData = -1;          /* NonStandardParameter */
static int hf_h501_releaseCompleteReason = -1;    /* ReleaseCompleteReason */
static int hf_h501_causeIE = -1;                  /* INTEGER_1_65535 */

/*--- End of included file: packet-h501-hf.c ---*/
#line 48 "../../asn1/h501/packet-h501-template.c"

/* Initialize the subtree pointers */
static int ett_h501 = -1;

/*--- Included file: packet-h501-ett.c ---*/
#line 1 "../../asn1/h501/packet-h501-ett.c"
static gint ett_h501_Message = -1;
static gint ett_h501_MessageBody = -1;
static gint ett_h501_MessageCommonInfo = -1;
static gint ett_h501_SEQUENCE_OF_TransportAddress = -1;
static gint ett_h501_SEQUENCE_OF_ClearToken = -1;
static gint ett_h501_SEQUENCE_OF_CryptoH323Token = -1;
static gint ett_h501_SEQUENCE_OF_NonStandardParameter = -1;
static gint ett_h501_SEQUENCE_OF_GenericData = -1;
static gint ett_h501_ServiceRequest = -1;
static gint ett_h501_SEQUENCE_OF_SecurityMode = -1;
static gint ett_h501_SecurityMode = -1;
static gint ett_h501_T_algorithmOIDs = -1;
static gint ett_h501_ServiceConfirmation = -1;
static gint ett_h501_ServiceRejection = -1;
static gint ett_h501_ServiceRejectionReason = -1;
static gint ett_h501_ServiceRelease = -1;
static gint ett_h501_ServiceReleaseReason = -1;
static gint ett_h501_DescriptorRequest = -1;
static gint ett_h501_SEQUENCE_OF_DescriptorID = -1;
static gint ett_h501_DescriptorConfirmation = -1;
static gint ett_h501_SEQUENCE_OF_Descriptor = -1;
static gint ett_h501_DescriptorRejection = -1;
static gint ett_h501_DescriptorRejectionReason = -1;
static gint ett_h501_DescriptorIDRequest = -1;
static gint ett_h501_DescriptorIDConfirmation = -1;
static gint ett_h501_SEQUENCE_OF_DescriptorInfo = -1;
static gint ett_h501_DescriptorIDRejection = -1;
static gint ett_h501_DescriptorIDRejectionReason = -1;
static gint ett_h501_DescriptorUpdate = -1;
static gint ett_h501_SEQUENCE_OF_UpdateInformation = -1;
static gint ett_h501_UpdateInformation = -1;
static gint ett_h501_T_descriptorInfo = -1;
static gint ett_h501_T_updateType = -1;
static gint ett_h501_DescriptorUpdateAck = -1;
static gint ett_h501_AccessRequest = -1;
static gint ett_h501_SEQUENCE_OF_SupportedProtocols = -1;
static gint ett_h501_AccessConfirmation = -1;
static gint ett_h501_SEQUENCE_OF_AddressTemplate = -1;
static gint ett_h501_SEQUENCE_OF_ServiceControlSession = -1;
static gint ett_h501_AccessRejection = -1;
static gint ett_h501_AccessRejectionReason = -1;
static gint ett_h501_UsageRequest = -1;
static gint ett_h501_UsageConfirmation = -1;
static gint ett_h501_UsageRejection = -1;
static gint ett_h501_UsageIndication = -1;
static gint ett_h501_SEQUENCE_OF_AccessToken = -1;
static gint ett_h501_SEQUENCE_OF_UsageField = -1;
static gint ett_h501_UsageField = -1;
static gint ett_h501_UsageRejectReason = -1;
static gint ett_h501_UsageIndicationConfirmation = -1;
static gint ett_h501_UsageIndicationRejection = -1;
static gint ett_h501_UsageIndicationRejectionReason = -1;
static gint ett_h501_ValidationRequest = -1;
static gint ett_h501_ValidationConfirmation = -1;
static gint ett_h501_ValidationRejection = -1;
static gint ett_h501_ValidationRejectionReason = -1;
static gint ett_h501_RequestInProgress = -1;
static gint ett_h501_NonStandardRequest = -1;
static gint ett_h501_NonStandardConfirmation = -1;
static gint ett_h501_NonStandardRejection = -1;
static gint ett_h501_NonStandardRejectionReason = -1;
static gint ett_h501_UnknownMessageResponse = -1;
static gint ett_h501_UnknownMessageReason = -1;
static gint ett_h501_AuthenticationRequest = -1;
static gint ett_h501_AuthenticationConfirmation = -1;
static gint ett_h501_AuthenticationRejection = -1;
static gint ett_h501_AuthenticationRejectionReason = -1;
static gint ett_h501_AddressTemplate = -1;
static gint ett_h501_SEQUENCE_OF_Pattern = -1;
static gint ett_h501_SEQUENCE_OF_RouteInformation = -1;
static gint ett_h501_Pattern = -1;
static gint ett_h501_T_range = -1;
static gint ett_h501_RouteInformation = -1;
static gint ett_h501_T_messageType = -1;
static gint ett_h501_SEQUENCE_OF_PriceInfoSpec = -1;
static gint ett_h501_SEQUENCE_OF_ContactInformation = -1;
static gint ett_h501_SEQUENCE_OF_CircuitIdentifier = -1;
static gint ett_h501_ContactInformation = -1;
static gint ett_h501_PriceInfoSpec = -1;
static gint ett_h501_SEQUENCE_OF_PriceElement = -1;
static gint ett_h501_PriceElement = -1;
static gint ett_h501_T_units = -1;
static gint ett_h501_Descriptor = -1;
static gint ett_h501_DescriptorInfo = -1;
static gint ett_h501_AlternatePEInfo = -1;
static gint ett_h501_SEQUENCE_OF_AlternatePE = -1;
static gint ett_h501_AlternatePE = -1;
static gint ett_h501_AccessToken = -1;
static gint ett_h501_CallInformation = -1;
static gint ett_h501_UsageCallStatus = -1;
static gint ett_h501_UserInformation = -1;
static gint ett_h501_UsageSpecification = -1;
static gint ett_h501_T_when = -1;
static gint ett_h501_T_required = -1;
static gint ett_h501_T_preferred = -1;
static gint ett_h501_PartyInformation = -1;
static gint ett_h501_SEQUENCE_OF_AliasAddress = -1;
static gint ett_h501_Role = -1;
static gint ett_h501_TerminationCause = -1;

/*--- End of included file: packet-h501-ett.c ---*/
#line 52 "../../asn1/h501/packet-h501-template.c"

/* Dissectors */
static dissector_handle_t h501_pdu_handle;

/* Preferences */
static guint h501_udp_port = 2099;
static guint h501_tcp_port = 2099;
static gboolean h501_desegment_tcp = TRUE;

void proto_reg_handoff_h501(void);


/*--- Included file: packet-h501-fn.c ---*/
#line 1 "../../asn1/h501/packet-h501-fn.c"


static int
dissect_h501_ElementIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 128, FALSE);

  return offset;
}



static int
dissect_h501_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t T_algorithmOIDs_sequence_of[1] = {
  { &hf_h501_algorithmOIDs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_OBJECT_IDENTIFIER },
};

static int
dissect_h501_T_algorithmOIDs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_T_algorithmOIDs, T_algorithmOIDs_sequence_of);

  return offset;
}


static const per_sequence_t SecurityMode_sequence[] = {
  { &hf_h501_authentication , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_AuthenticationMechanism },
  { &hf_h501_integrity      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_IntegrityMechanism },
  { &hf_h501_algorithmOIDs  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_T_algorithmOIDs },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_SecurityMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_SecurityMode, SecurityMode_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_SecurityMode_sequence_of[1] = {
  { &hf_h501_securityMode_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_SecurityMode },
};

static int
dissect_h501_SEQUENCE_OF_SecurityMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_SecurityMode, SEQUENCE_OF_SecurityMode_sequence_of);

  return offset;
}



static int
dissect_h501_INTEGER_1_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_h501_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h501_INTEGER_1_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_when_sequence[] = {
  { &hf_h501_never          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_NULL },
  { &hf_h501_start          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_NULL },
  { &hf_h501_end            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_NULL },
  { &hf_h501_period         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_INTEGER_1_65535 },
  { &hf_h501_failures       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_T_when(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_T_when, T_when_sequence);

  return offset;
}


static const per_sequence_t T_required_sequence_of[1] = {
  { &hf_h501_required_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_OBJECT_IDENTIFIER },
};

static int
dissect_h501_T_required(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_T_required, T_required_sequence_of);

  return offset;
}


static const per_sequence_t T_preferred_sequence_of[1] = {
  { &hf_h501_preferred_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_OBJECT_IDENTIFIER },
};

static int
dissect_h501_T_preferred(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_T_preferred, T_preferred_sequence_of);

  return offset;
}


static const per_sequence_t UsageSpecification_sequence[] = {
  { &hf_h501_sendTo         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_ElementIdentifier },
  { &hf_h501_when           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_T_when },
  { &hf_h501_required       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_T_required },
  { &hf_h501_preferred      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_T_preferred },
  { &hf_h501_sendToPEAddress, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_AliasAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_UsageSpecification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UsageSpecification, UsageSpecification_sequence);

  return offset;
}


static const per_sequence_t ServiceRequest_sequence[] = {
  { &hf_h501_elementIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_ElementIdentifier },
  { &hf_h501_domainIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_AliasAddress },
  { &hf_h501_securityMode   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_SecurityMode },
  { &hf_h501_timeToLive     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_INTEGER_1_4294967295 },
  { &hf_h501_usageSpec      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_UsageSpecification },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_ServiceRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_ServiceRequest, ServiceRequest_sequence);

  return offset;
}



static int
dissect_h501_INTEGER_1_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AlternatePE_sequence[] = {
  { &hf_h501_contactAddress , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_AliasAddress },
  { &hf_h501_priority_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_INTEGER_1_127 },
  { &hf_h501_elementIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_ElementIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_AlternatePE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_AlternatePE, AlternatePE_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_AlternatePE_sequence_of[1] = {
  { &hf_h501_alternatePE_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_AlternatePE },
};

static int
dissect_h501_SEQUENCE_OF_AlternatePE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_AlternatePE, SEQUENCE_OF_AlternatePE_sequence_of);

  return offset;
}



static int
dissect_h501_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t AlternatePEInfo_sequence[] = {
  { &hf_h501_alternatePE    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_AlternatePE },
  { &hf_h501_alternateIsPermanent, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_AlternatePEInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_AlternatePEInfo, AlternatePEInfo_sequence);

  return offset;
}


static const per_sequence_t ServiceConfirmation_sequence[] = {
  { &hf_h501_elementIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_ElementIdentifier },
  { &hf_h501_domainIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_AliasAddress },
  { &hf_h501_alternates     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_AlternatePEInfo },
  { &hf_h501_securityMode_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SecurityMode },
  { &hf_h501_timeToLive     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_INTEGER_1_4294967295 },
  { &hf_h501_usageSpec      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_UsageSpecification },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_ServiceConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_ServiceConfirmation, ServiceConfirmation_sequence);

  return offset;
}


static const value_string h501_ServiceRejectionReason_vals[] = {
  {   0, "serviceUnavailable" },
  {   1, "serviceRedirected" },
  {   2, "security" },
  {   3, "continue" },
  {   4, "undefined" },
  {   5, "unknownServiceID" },
  {   6, "cannotSupportUsageSpec" },
  {   7, "neededFeature" },
  {   8, "genericDataReason" },
  {   9, "usageUnavailable" },
  {  10, "unknownUsageSendTo" },
  { 0, NULL }
};

static const per_choice_t ServiceRejectionReason_choice[] = {
  {   0, &hf_h501_serviceUnavailable, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_serviceRedirected, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_security       , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_continue       , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   4, &hf_h501_undefined      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   5, &hf_h501_unknownServiceID, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   6, &hf_h501_cannotSupportUsageSpec, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   7, &hf_h501_neededFeature  , ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   8, &hf_h501_genericDataReason, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   9, &hf_h501_usageUnavailable, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {  10, &hf_h501_unknownUsageSendTo, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_ServiceRejectionReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_ServiceRejectionReason, ServiceRejectionReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ServiceRejection_sequence[] = {
  { &hf_h501_reason         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_ServiceRejectionReason },
  { &hf_h501_alternates     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_AlternatePEInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_ServiceRejection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_ServiceRejection, ServiceRejection_sequence);

  return offset;
}


static const value_string h501_ServiceReleaseReason_vals[] = {
  {   0, "outOfService" },
  {   1, "maintenance" },
  {   2, "terminated" },
  {   3, "expired" },
  { 0, NULL }
};

static const per_choice_t ServiceReleaseReason_choice[] = {
  {   0, &hf_h501_outOfService   , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_maintenance    , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_terminated     , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_expired        , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_ServiceReleaseReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_ServiceReleaseReason, ServiceReleaseReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ServiceRelease_sequence[] = {
  { &hf_h501_reason_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_ServiceReleaseReason },
  { &hf_h501_alternates     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_AlternatePEInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_ServiceRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_ServiceRelease, ServiceRelease_sequence);

  return offset;
}



static int
dissect_h501_DescriptorID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h225_GloballyUniqueID(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_DescriptorID_sequence_of[1] = {
  { &hf_h501_descriptorID_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_DescriptorID },
};

static int
dissect_h501_SEQUENCE_OF_DescriptorID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_DescriptorID, SEQUENCE_OF_DescriptorID_sequence_of);

  return offset;
}


static const per_sequence_t DescriptorRequest_sequence[] = {
  { &hf_h501_descriptorID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_DescriptorID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_DescriptorRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_DescriptorRequest, DescriptorRequest_sequence);

  return offset;
}



static int
dissect_h501_GlobalTimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          14, 14, FALSE);

  return offset;
}


static const per_sequence_t DescriptorInfo_sequence[] = {
  { &hf_h501_descriptorID_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_DescriptorID },
  { &hf_h501_lastChanged    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_GlobalTimeStamp },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_DescriptorInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_DescriptorInfo, DescriptorInfo_sequence);

  return offset;
}


static const per_sequence_t T_range_sequence[] = {
  { &hf_h501_startOfRange   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_PartyNumber },
  { &hf_h501_endOfRange     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_PartyNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_T_range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_T_range, T_range_sequence);

  return offset;
}


static const value_string h501_Pattern_vals[] = {
  {   0, "specific" },
  {   1, "wildcard" },
  {   2, "range" },
  { 0, NULL }
};

static const per_choice_t Pattern_choice[] = {
  {   0, &hf_h501_specific       , ASN1_EXTENSION_ROOT    , dissect_h225_AliasAddress },
  {   1, &hf_h501_wildcard       , ASN1_EXTENSION_ROOT    , dissect_h225_AliasAddress },
  {   2, &hf_h501_range          , ASN1_EXTENSION_ROOT    , dissect_h501_T_range },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_Pattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_Pattern, Pattern_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_Pattern_sequence_of[1] = {
  { &hf_h501_pattern_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_Pattern },
};

static int
dissect_h501_SEQUENCE_OF_Pattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_Pattern, SEQUENCE_OF_Pattern_sequence_of);

  return offset;
}


static const value_string h501_T_messageType_vals[] = {
  {   0, "sendAccessRequest" },
  {   1, "sendSetup" },
  {   2, "nonExistent" },
  { 0, NULL }
};

static const per_choice_t T_messageType_choice[] = {
  {   0, &hf_h501_sendAccessRequest, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_sendSetup      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_nonExistent    , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_T_messageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_T_messageType, T_messageType_choice,
                                 NULL);

  return offset;
}



static int
dissect_h501_IA5String_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          3, 3, FALSE);

  return offset;
}



static int
dissect_h501_INTEGER_M127_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_h501_IA5String_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          6, 6, FALSE);

  return offset;
}



static int
dissect_h501_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const value_string h501_T_units_vals[] = {
  {   0, "seconds" },
  {   1, "packets" },
  {   2, "bytes" },
  {   3, "initial" },
  {   4, "minimum" },
  {   5, "maximum" },
  { 0, NULL }
};

static const per_choice_t T_units_choice[] = {
  {   0, &hf_h501_seconds        , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_packets        , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_bytes          , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_initial        , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   4, &hf_h501_minimum        , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   5, &hf_h501_maximum        , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_T_units(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_T_units, T_units_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PriceElement_sequence[] = {
  { &hf_h501_amount         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_INTEGER_0_4294967295 },
  { &hf_h501_quantum        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_INTEGER_0_4294967295 },
  { &hf_h501_units          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_T_units },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_PriceElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_PriceElement, PriceElement_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_PriceElement_sequence_of[1] = {
  { &hf_h501_priceElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_PriceElement },
};

static int
dissect_h501_SEQUENCE_OF_PriceElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_PriceElement, SEQUENCE_OF_PriceElement_sequence_of);

  return offset;
}



static int
dissect_h501_IA5String_SIZE_1_2048(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 2048, FALSE);

  return offset;
}


static const per_sequence_t PriceInfoSpec_sequence[] = {
  { &hf_h501_currency       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_IA5String_SIZE_3 },
  { &hf_h501_currencyScale  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_INTEGER_M127_127 },
  { &hf_h501_validFrom      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_GlobalTimeStamp },
  { &hf_h501_validUntil     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_GlobalTimeStamp },
  { &hf_h501_hoursFrom      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_IA5String_SIZE_6 },
  { &hf_h501_hoursUntil     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_IA5String_SIZE_6 },
  { &hf_h501_priceElement   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_PriceElement },
  { &hf_h501_priceFormula   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_IA5String_SIZE_1_2048 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_PriceInfoSpec(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_PriceInfoSpec, PriceInfoSpec_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_PriceInfoSpec_sequence_of[1] = {
  { &hf_h501_priceInfo_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_PriceInfoSpec },
};

static int
dissect_h501_SEQUENCE_OF_PriceInfoSpec(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_PriceInfoSpec, SEQUENCE_OF_PriceInfoSpec_sequence_of);

  return offset;
}



static int
dissect_h501_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const value_string h501_AccessToken_vals[] = {
  {   0, "token" },
  {   1, "cryptoToken" },
  {   2, "genericData" },
  { 0, NULL }
};

static const per_choice_t AccessToken_choice[] = {
  {   0, &hf_h501_token          , ASN1_EXTENSION_ROOT    , dissect_h235_ClearToken },
  {   1, &hf_h501_cryptoToken    , ASN1_EXTENSION_ROOT    , dissect_h225_CryptoH323Token },
  {   2, &hf_h501_genericData_01 , ASN1_NOT_EXTENSION_ROOT, dissect_h225_GenericData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_AccessToken(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_AccessToken, AccessToken_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_AccessToken_sequence_of[1] = {
  { &hf_h501_accessTokens_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_AccessToken },
};

static int
dissect_h501_SEQUENCE_OF_AccessToken(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_AccessToken, SEQUENCE_OF_AccessToken_sequence_of);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_CircuitIdentifier_sequence_of[1] = {
  { &hf_h501_supportedCircuits_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_CircuitIdentifier },
};

static int
dissect_h501_SEQUENCE_OF_CircuitIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_CircuitIdentifier, SEQUENCE_OF_CircuitIdentifier_sequence_of);

  return offset;
}


static const per_sequence_t ContactInformation_sequence[] = {
  { &hf_h501_transportAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_AliasAddress },
  { &hf_h501_priority       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_INTEGER_0_127 },
  { &hf_h501_transportQoS   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_TransportQOS },
  { &hf_h501_security_01    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_SecurityMode },
  { &hf_h501_accessTokens   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_AccessToken },
  { &hf_h501_multipleCalls  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_BOOLEAN },
  { &hf_h501_featureSet     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_FeatureSet },
  { &hf_h501_circuitID      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_CircuitInfo },
  { &hf_h501_supportedCircuits, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_CircuitIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_ContactInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_ContactInformation, ContactInformation_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_ContactInformation_sequence_of[1] = {
  { &hf_h501_contacts_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_ContactInformation },
};

static int
dissect_h501_SEQUENCE_OF_ContactInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_ContactInformation, SEQUENCE_OF_ContactInformation_sequence_of);

  return offset;
}


static const per_sequence_t RouteInformation_sequence[] = {
  { &hf_h501_messageType    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_T_messageType },
  { &hf_h501_callSpecific   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_BOOLEAN },
  { &hf_h501_usageSpec      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_UsageSpecification },
  { &hf_h501_priceInfo      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_PriceInfoSpec },
  { &hf_h501_contacts       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_ContactInformation },
  { &hf_h501_type           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_EndpointType },
  { &hf_h501_featureSet     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_FeatureSet },
  { &hf_h501_circuitID      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_CircuitInfo },
  { &hf_h501_supportedCircuits, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_CircuitIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_RouteInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_RouteInformation, RouteInformation_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_RouteInformation_sequence_of[1] = {
  { &hf_h501_routeInfo_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_RouteInformation },
};

static int
dissect_h501_SEQUENCE_OF_RouteInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_RouteInformation, SEQUENCE_OF_RouteInformation_sequence_of);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_SupportedProtocols_sequence_of[1] = {
  { &hf_h501_desiredProtocols_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_SupportedProtocols },
};

static int
dissect_h501_SEQUENCE_OF_SupportedProtocols(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_SupportedProtocols, SEQUENCE_OF_SupportedProtocols_sequence_of);

  return offset;
}


static const per_sequence_t AddressTemplate_sequence[] = {
  { &hf_h501_pattern        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_Pattern },
  { &hf_h501_routeInfo      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_RouteInformation },
  { &hf_h501_timeToLive     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_INTEGER_1_4294967295 },
  { &hf_h501_supportedProtocols, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_SupportedProtocols },
  { &hf_h501_featureSet     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_FeatureSet },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_AddressTemplate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_AddressTemplate, AddressTemplate_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_AddressTemplate_sequence_of[1] = {
  { &hf_h501_templates_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_AddressTemplate },
};

static int
dissect_h501_SEQUENCE_OF_AddressTemplate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_AddressTemplate, SEQUENCE_OF_AddressTemplate_sequence_of);

  return offset;
}


static const per_sequence_t Descriptor_sequence[] = {
  { &hf_h501_descriptorInfo_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_DescriptorInfo },
  { &hf_h501_templates      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_AddressTemplate },
  { &hf_h501_gatekeeperID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_GatekeeperIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_Descriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_Descriptor, Descriptor_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_Descriptor_sequence_of[1] = {
  { &hf_h501_descriptor_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_Descriptor },
};

static int
dissect_h501_SEQUENCE_OF_Descriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_Descriptor, SEQUENCE_OF_Descriptor_sequence_of);

  return offset;
}


static const per_sequence_t DescriptorConfirmation_sequence[] = {
  { &hf_h501_descriptor     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_Descriptor },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_DescriptorConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_DescriptorConfirmation, DescriptorConfirmation_sequence);

  return offset;
}


static const value_string h501_DescriptorRejectionReason_vals[] = {
  {   0, "packetSizeExceeded" },
  {   1, "illegalID" },
  {   2, "security" },
  {   3, "hopCountExceeded" },
  {   4, "noServiceRelationship" },
  {   5, "undefined" },
  {   6, "neededFeature" },
  {   7, "genericDataReason" },
  {   8, "unknownServiceID" },
  { 0, NULL }
};

static const per_choice_t DescriptorRejectionReason_choice[] = {
  {   0, &hf_h501_packetSizeExceeded, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_illegalID      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_security       , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_hopCountExceeded, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   4, &hf_h501_noServiceRelationship, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   5, &hf_h501_undefined      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   6, &hf_h501_neededFeature  , ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   7, &hf_h501_genericDataReason, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   8, &hf_h501_unknownServiceID, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_DescriptorRejectionReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_DescriptorRejectionReason, DescriptorRejectionReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DescriptorRejection_sequence[] = {
  { &hf_h501_reason_02      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_DescriptorRejectionReason },
  { &hf_h501_descriptorID_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_DescriptorID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_DescriptorRejection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_DescriptorRejection, DescriptorRejection_sequence);

  return offset;
}


static const per_sequence_t DescriptorIDRequest_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h501_DescriptorIDRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_DescriptorIDRequest, DescriptorIDRequest_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_DescriptorInfo_sequence_of[1] = {
  { &hf_h501_descriptorInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_DescriptorInfo },
};

static int
dissect_h501_SEQUENCE_OF_DescriptorInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_DescriptorInfo, SEQUENCE_OF_DescriptorInfo_sequence_of);

  return offset;
}


static const per_sequence_t DescriptorIDConfirmation_sequence[] = {
  { &hf_h501_descriptorInfo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_DescriptorInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_DescriptorIDConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_DescriptorIDConfirmation, DescriptorIDConfirmation_sequence);

  return offset;
}


static const value_string h501_DescriptorIDRejectionReason_vals[] = {
  {   0, "noDescriptors" },
  {   1, "security" },
  {   2, "hopCountExceeded" },
  {   3, "noServiceRelationship" },
  {   4, "undefined" },
  {   5, "neededFeature" },
  {   6, "genericDataReason" },
  {   7, "unknownServiceID" },
  { 0, NULL }
};

static const per_choice_t DescriptorIDRejectionReason_choice[] = {
  {   0, &hf_h501_noDescriptors  , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_security       , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_hopCountExceeded, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_noServiceRelationship, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   4, &hf_h501_undefined      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   5, &hf_h501_neededFeature  , ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   6, &hf_h501_genericDataReason, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   7, &hf_h501_unknownServiceID, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_DescriptorIDRejectionReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_DescriptorIDRejectionReason, DescriptorIDRejectionReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DescriptorIDRejection_sequence[] = {
  { &hf_h501_reason_03      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_DescriptorIDRejectionReason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_DescriptorIDRejection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_DescriptorIDRejection, DescriptorIDRejection_sequence);

  return offset;
}


static const value_string h501_T_descriptorInfo_vals[] = {
  {   0, "descriptorID" },
  {   1, "descriptor" },
  { 0, NULL }
};

static const per_choice_t T_descriptorInfo_choice[] = {
  {   0, &hf_h501_descriptorID_01, ASN1_EXTENSION_ROOT    , dissect_h501_DescriptorID },
  {   1, &hf_h501_descriptor_01  , ASN1_EXTENSION_ROOT    , dissect_h501_Descriptor },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_T_descriptorInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_T_descriptorInfo, T_descriptorInfo_choice,
                                 NULL);

  return offset;
}


static const value_string h501_T_updateType_vals[] = {
  {   0, "added" },
  {   1, "deleted" },
  {   2, "changed" },
  { 0, NULL }
};

static const per_choice_t T_updateType_choice[] = {
  {   0, &hf_h501_added          , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_deleted        , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_changed        , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_T_updateType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_T_updateType, T_updateType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UpdateInformation_sequence[] = {
  { &hf_h501_descriptorInfo_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_T_descriptorInfo },
  { &hf_h501_updateType     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_T_updateType },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_UpdateInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UpdateInformation, UpdateInformation_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_UpdateInformation_sequence_of[1] = {
  { &hf_h501_updateInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_UpdateInformation },
};

static int
dissect_h501_SEQUENCE_OF_UpdateInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_UpdateInformation, SEQUENCE_OF_UpdateInformation_sequence_of);

  return offset;
}


static const per_sequence_t DescriptorUpdate_sequence[] = {
  { &hf_h501_sender         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_AliasAddress },
  { &hf_h501_updateInfo     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_UpdateInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_DescriptorUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_DescriptorUpdate, DescriptorUpdate_sequence);

  return offset;
}


static const per_sequence_t DescriptorUpdateAck_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h501_DescriptorUpdateAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_DescriptorUpdateAck, DescriptorUpdateAck_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_AliasAddress_sequence_of[1] = {
  { &hf_h501_logicalAddresses_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_AliasAddress },
};

static int
dissect_h501_SEQUENCE_OF_AliasAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_AliasAddress, SEQUENCE_OF_AliasAddress_sequence_of);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_CryptoH323Token_sequence_of[1] = {
  { &hf_h501_cryptoTokens_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_CryptoH323Token },
};

static int
dissect_h501_SEQUENCE_OF_CryptoH323Token(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_CryptoH323Token, SEQUENCE_OF_CryptoH323Token_sequence_of);

  return offset;
}


static const per_sequence_t UserInformation_sequence[] = {
  { &hf_h501_userIdentifier , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_AliasAddress },
  { &hf_h501_userAuthenticator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_CryptoH323Token },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_UserInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UserInformation, UserInformation_sequence);

  return offset;
}



static int
dissect_h501_TimeZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -43200, 43200U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PartyInformation_sequence[] = {
  { &hf_h501_logicalAddresses, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_AliasAddress },
  { &hf_h501_domainIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_AliasAddress },
  { &hf_h501_transportAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_AliasAddress },
  { &hf_h501_endpointType   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_EndpointType },
  { &hf_h501_userInfo       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_UserInformation },
  { &hf_h501_timeZone       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_TimeZone },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_PartyInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_PartyInformation, PartyInformation_sequence);

  return offset;
}


static const per_sequence_t CallInformation_sequence[] = {
  { &hf_h501_callIdentifier , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CallIdentifier },
  { &hf_h501_conferenceID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_ConferenceIdentifier },
  { &hf_h501_circuitID      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_CircuitInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_CallInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_CallInformation, CallInformation_sequence);

  return offset;
}


static const per_sequence_t AccessRequest_sequence[] = {
  { &hf_h501_destinationInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_PartyInformation },
  { &hf_h501_sourceInfo     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_PartyInformation },
  { &hf_h501_callInfo       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_CallInformation },
  { &hf_h501_usageSpec      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_UsageSpecification },
  { &hf_h501_desiredProtocols, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_SupportedProtocols },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_AccessRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_AccessRequest, AccessRequest_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_ServiceControlSession_sequence_of[1] = {
  { &hf_h501_serviceControl_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_ServiceControlSession },
};

static int
dissect_h501_SEQUENCE_OF_ServiceControlSession(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_ServiceControlSession, SEQUENCE_OF_ServiceControlSession_sequence_of);

  return offset;
}


static const per_sequence_t AccessConfirmation_sequence[] = {
  { &hf_h501_templates      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_AddressTemplate },
  { &hf_h501_partialResponse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_BOOLEAN },
  { &hf_h501_supportedProtocols, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_SupportedProtocols },
  { &hf_h501_serviceControl , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_ServiceControlSession },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_AccessConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_AccessConfirmation, AccessConfirmation_sequence);

  return offset;
}


static const value_string h501_AccessRejectionReason_vals[] = {
  {   0, "noMatch" },
  {   1, "packetSizeExceeded" },
  {   2, "security" },
  {   3, "hopCountExceeded" },
  {   4, "needCallInformation" },
  {   5, "noServiceRelationship" },
  {   6, "undefined" },
  {   7, "neededFeature" },
  {   8, "genericDataReason" },
  {   9, "destinationUnavailable" },
  {  10, "aliasesInconsistent" },
  {  11, "resourceUnavailable" },
  {  12, "incompleteAddress" },
  {  13, "unknownServiceID" },
  {  14, "usageUnavailable" },
  {  15, "cannotSupportUsageSpec" },
  {  16, "unknownUsageSendTo" },
  { 0, NULL }
};

static const per_choice_t AccessRejectionReason_choice[] = {
  {   0, &hf_h501_noMatch        , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_packetSizeExceeded, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_security       , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_hopCountExceeded, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   4, &hf_h501_needCallInformation, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   5, &hf_h501_noServiceRelationship, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   6, &hf_h501_undefined      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   7, &hf_h501_neededFeature  , ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   8, &hf_h501_genericDataReason, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   9, &hf_h501_destinationUnavailable, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {  10, &hf_h501_aliasesInconsistent, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {  11, &hf_h501_resourceUnavailable, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {  12, &hf_h501_incompleteAddress, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {  13, &hf_h501_unknownServiceID, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {  14, &hf_h501_usageUnavailable, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {  15, &hf_h501_cannotSupportUsageSpec, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {  16, &hf_h501_unknownUsageSendTo, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_AccessRejectionReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_AccessRejectionReason, AccessRejectionReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AccessRejection_sequence[] = {
  { &hf_h501_reason_04      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_AccessRejectionReason },
  { &hf_h501_serviceControl , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_ServiceControlSession },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_AccessRejection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_AccessRejection, AccessRejection_sequence);

  return offset;
}


static const per_sequence_t RequestInProgress_sequence[] = {
  { &hf_h501_delay          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_INTEGER_1_65535 },
  { &hf_h501_serviceControl , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_ServiceControlSession },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_RequestInProgress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_RequestInProgress, RequestInProgress_sequence);

  return offset;
}


static const per_sequence_t NonStandardRequest_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h501_NonStandardRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_NonStandardRequest, NonStandardRequest_sequence);

  return offset;
}


static const per_sequence_t NonStandardConfirmation_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h501_NonStandardConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_NonStandardConfirmation, NonStandardConfirmation_sequence);

  return offset;
}


static const value_string h501_NonStandardRejectionReason_vals[] = {
  {   0, "notSupported" },
  {   1, "noServiceRelationship" },
  {   2, "undefined" },
  {   3, "neededFeature" },
  {   4, "genericDataReason" },
  {   5, "unknownServiceID" },
  { 0, NULL }
};

static const per_choice_t NonStandardRejectionReason_choice[] = {
  {   0, &hf_h501_notSupported   , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_noServiceRelationship, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_undefined      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_neededFeature  , ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   4, &hf_h501_genericDataReason, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   5, &hf_h501_unknownServiceID, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_NonStandardRejectionReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_NonStandardRejectionReason, NonStandardRejectionReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NonStandardRejection_sequence[] = {
  { &hf_h501_reason_08      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_NonStandardRejectionReason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_NonStandardRejection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_NonStandardRejection, NonStandardRejection_sequence);

  return offset;
}



static int
dissect_h501_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const value_string h501_UnknownMessageReason_vals[] = {
  {   0, "notUnderstood" },
  {   1, "undefined" },
  { 0, NULL }
};

static const per_choice_t UnknownMessageReason_choice[] = {
  {   0, &hf_h501_notUnderstood  , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_undefined      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_UnknownMessageReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_UnknownMessageReason, UnknownMessageReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UnknownMessageResponse_sequence[] = {
  { &hf_h501_unknownMessage , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_OCTET_STRING },
  { &hf_h501_reason_09      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_UnknownMessageReason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_UnknownMessageResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UnknownMessageResponse, UnknownMessageResponse_sequence);

  return offset;
}


static const per_sequence_t UsageRequest_sequence[] = {
  { &hf_h501_callInfo       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_CallInformation },
  { &hf_h501_usageSpec      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_UsageSpecification },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_UsageRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UsageRequest, UsageRequest_sequence);

  return offset;
}


static const per_sequence_t UsageConfirmation_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h501_UsageConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UsageConfirmation, UsageConfirmation_sequence);

  return offset;
}


static const value_string h501_Role_vals[] = {
  {   0, "originator" },
  {   1, "destination" },
  {   2, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t Role_choice[] = {
  {   0, &hf_h501_originator     , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_destination    , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_nonStandardData, ASN1_EXTENSION_ROOT    , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_Role(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_Role, Role_choice,
                                 NULL);

  return offset;
}


static const value_string h501_UsageCallStatus_vals[] = {
  {   0, "preConnect" },
  {   1, "callInProgress" },
  {   2, "callEnded" },
  {   3, "registrationLost" },
  { 0, NULL }
};

static const per_choice_t UsageCallStatus_choice[] = {
  {   0, &hf_h501_preConnect     , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_callInProgress , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_callEnded      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_registrationLost, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_UsageCallStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_UsageCallStatus, UsageCallStatus_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TerminationCause_sequence[] = {
  { &hf_h501_releaseCompleteReason, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_ReleaseCompleteReason },
  { &hf_h501_causeIE        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_INTEGER_1_65535 },
  { &hf_h501_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_NonStandardParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_TerminationCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_TerminationCause, TerminationCause_sequence);

  return offset;
}


static const per_sequence_t UsageField_sequence[] = {
  { &hf_h501_id             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_OBJECT_IDENTIFIER },
  { &hf_h501_value          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_UsageField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UsageField, UsageField_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_UsageField_sequence_of[1] = {
  { &hf_h501_usageFields_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h501_UsageField },
};

static int
dissect_h501_SEQUENCE_OF_UsageField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_UsageField, SEQUENCE_OF_UsageField_sequence_of);

  return offset;
}


static const per_sequence_t UsageIndication_sequence[] = {
  { &hf_h501_callInfo       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_CallInformation },
  { &hf_h501_accessTokens   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_AccessToken },
  { &hf_h501_senderRole     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_Role },
  { &hf_h501_usageCallStatus, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_UsageCallStatus },
  { &hf_h501_srcInfo        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_PartyInformation },
  { &hf_h501_destAddress    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_PartyInformation },
  { &hf_h501_startTime      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_TimeStamp },
  { &hf_h501_endTime        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_TimeStamp },
  { &hf_h501_terminationCause, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_TerminationCause },
  { &hf_h501_usageFields    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_SEQUENCE_OF_UsageField },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_UsageIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UsageIndication, UsageIndication_sequence);

  return offset;
}


static const per_sequence_t UsageIndicationConfirmation_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h501_UsageIndicationConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UsageIndicationConfirmation, UsageIndicationConfirmation_sequence);

  return offset;
}


static const value_string h501_UsageIndicationRejectionReason_vals[] = {
  {   0, "unknownCall" },
  {   1, "incomplete" },
  {   2, "security" },
  {   3, "noServiceRelationship" },
  {   4, "undefined" },
  {   5, "neededFeature" },
  {   6, "genericDataReason" },
  {   7, "unknownServiceID" },
  { 0, NULL }
};

static const per_choice_t UsageIndicationRejectionReason_choice[] = {
  {   0, &hf_h501_unknownCall    , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_incomplete     , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_security       , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_noServiceRelationship, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   4, &hf_h501_undefined      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   5, &hf_h501_neededFeature  , ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   6, &hf_h501_genericDataReason, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   7, &hf_h501_unknownServiceID, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_UsageIndicationRejectionReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_UsageIndicationRejectionReason, UsageIndicationRejectionReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UsageIndicationRejection_sequence[] = {
  { &hf_h501_reason_06      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_UsageIndicationRejectionReason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_UsageIndicationRejection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UsageIndicationRejection, UsageIndicationRejection_sequence);

  return offset;
}


static const value_string h501_UsageRejectReason_vals[] = {
  {   0, "invalidCall" },
  {   1, "unavailable" },
  {   2, "security" },
  {   3, "noServiceRelationship" },
  {   4, "undefined" },
  {   5, "neededFeature" },
  {   6, "genericDataReason" },
  {   7, "unknownServiceID" },
  { 0, NULL }
};

static const per_choice_t UsageRejectReason_choice[] = {
  {   0, &hf_h501_invalidCall    , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_unavailable    , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_security       , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_noServiceRelationship, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   4, &hf_h501_undefined      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   5, &hf_h501_neededFeature  , ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   6, &hf_h501_genericDataReason, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   7, &hf_h501_unknownServiceID, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_UsageRejectReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_UsageRejectReason, UsageRejectReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UsageRejection_sequence[] = {
  { &hf_h501_reason_05      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_UsageRejectReason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_UsageRejection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_UsageRejection, UsageRejection_sequence);

  return offset;
}


static const per_sequence_t ValidationRequest_sequence[] = {
  { &hf_h501_accessToken    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_AccessToken },
  { &hf_h501_destinationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_PartyInformation },
  { &hf_h501_sourceInfo     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_PartyInformation },
  { &hf_h501_callInfo       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_CallInformation },
  { &hf_h501_usageSpec      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_UsageSpecification },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_ValidationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_ValidationRequest, ValidationRequest_sequence);

  return offset;
}


static const per_sequence_t ValidationConfirmation_sequence[] = {
  { &hf_h501_destinationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_PartyInformation },
  { &hf_h501_usageSpec      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_UsageSpecification },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_ValidationConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_ValidationConfirmation, ValidationConfirmation_sequence);

  return offset;
}


static const value_string h501_ValidationRejectionReason_vals[] = {
  {   0, "tokenNotValid" },
  {   1, "security" },
  {   2, "hopCountExceeded" },
  {   3, "missingSourceInfo" },
  {   4, "missingDestInfo" },
  {   5, "noServiceRelationship" },
  {   6, "undefined" },
  {   7, "neededFeature" },
  {   8, "genericDataReason" },
  {   9, "unknownServiceID" },
  { 0, NULL }
};

static const per_choice_t ValidationRejectionReason_choice[] = {
  {   0, &hf_h501_tokenNotValid  , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_security       , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_hopCountExceeded, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_missingSourceInfo, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   4, &hf_h501_missingDestInfo, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   5, &hf_h501_noServiceRelationship, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   6, &hf_h501_undefined      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   7, &hf_h501_neededFeature  , ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   8, &hf_h501_genericDataReason, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  {   9, &hf_h501_unknownServiceID, ASN1_NOT_EXTENSION_ROOT, dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_ValidationRejectionReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_ValidationRejectionReason, ValidationRejectionReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ValidationRejection_sequence[] = {
  { &hf_h501_reason_07      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_ValidationRejectionReason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_ValidationRejection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_ValidationRejection, ValidationRejection_sequence);

  return offset;
}



static int
dissect_h501_ApplicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t AuthenticationRequest_sequence[] = {
  { &hf_h501_applicationMessage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_ApplicationMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_AuthenticationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_AuthenticationRequest, AuthenticationRequest_sequence);

  return offset;
}


static const per_sequence_t AuthenticationConfirmation_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h501_AuthenticationConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_AuthenticationConfirmation, AuthenticationConfirmation_sequence);

  return offset;
}


static const value_string h501_AuthenticationRejectionReason_vals[] = {
  {   0, "security" },
  {   1, "hopCountExceeded" },
  {   2, "noServiceRelationship" },
  {   3, "undefined" },
  {   4, "neededFeature" },
  {   5, "genericDataReason" },
  {   6, "unknownServiceID" },
  {   7, "securityWrongSyncTime" },
  {   8, "securityReplay" },
  {   9, "securityWrongGeneralID" },
  {  10, "securityWrongSendersID" },
  {  11, "securityIntegrityFailed" },
  {  12, "securityWrongOID" },
  { 0, NULL }
};

static const per_choice_t AuthenticationRejectionReason_choice[] = {
  {   0, &hf_h501_security       , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   1, &hf_h501_hopCountExceeded, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   2, &hf_h501_noServiceRelationship, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   3, &hf_h501_undefined      , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   4, &hf_h501_neededFeature  , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   5, &hf_h501_genericDataReason, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   6, &hf_h501_unknownServiceID, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   7, &hf_h501_securityWrongSyncTime, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   8, &hf_h501_securityReplay , ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {   9, &hf_h501_securityWrongGeneralID, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {  10, &hf_h501_securityWrongSendersID, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {  11, &hf_h501_securityIntegrityFailed, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  {  12, &hf_h501_securityWrongOID, ASN1_EXTENSION_ROOT    , dissect_h501_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_AuthenticationRejectionReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_AuthenticationRejectionReason, AuthenticationRejectionReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AuthenticationRejection_sequence[] = {
  { &hf_h501_reason_10      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_AuthenticationRejectionReason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_AuthenticationRejection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_AuthenticationRejection, AuthenticationRejection_sequence);

  return offset;
}


static const value_string h501_MessageBody_vals[] = {
  {   0, "serviceRequest" },
  {   1, "serviceConfirmation" },
  {   2, "serviceRejection" },
  {   3, "serviceRelease" },
  {   4, "descriptorRequest" },
  {   5, "descriptorConfirmation" },
  {   6, "descriptorRejection" },
  {   7, "descriptorIDRequest" },
  {   8, "descriptorIDConfirmation" },
  {   9, "descriptorIDRejection" },
  {  10, "descriptorUpdate" },
  {  11, "descriptorUpdateAck" },
  {  12, "accessRequest" },
  {  13, "accessConfirmation" },
  {  14, "accessRejection" },
  {  15, "requestInProgress" },
  {  16, "nonStandardRequest" },
  {  17, "nonStandardConfirmation" },
  {  18, "nonStandardRejection" },
  {  19, "unknownMessageResponse" },
  {  20, "usageRequest" },
  {  21, "usageConfirmation" },
  {  22, "usageIndication" },
  {  23, "usageIndicationConfirmation" },
  {  24, "usageIndicationRejection" },
  {  25, "usageRejection" },
  {  26, "validationRequest" },
  {  27, "validationConfirmation" },
  {  28, "validationRejection" },
  {  29, "authenticationRequest" },
  {  30, "authenticationConfirmation" },
  {  31, "authenticationRejection" },
  { 0, NULL }
};

static const per_choice_t MessageBody_choice[] = {
  {   0, &hf_h501_serviceRequest , ASN1_EXTENSION_ROOT    , dissect_h501_ServiceRequest },
  {   1, &hf_h501_serviceConfirmation, ASN1_EXTENSION_ROOT    , dissect_h501_ServiceConfirmation },
  {   2, &hf_h501_serviceRejection, ASN1_EXTENSION_ROOT    , dissect_h501_ServiceRejection },
  {   3, &hf_h501_serviceRelease , ASN1_EXTENSION_ROOT    , dissect_h501_ServiceRelease },
  {   4, &hf_h501_descriptorRequest, ASN1_EXTENSION_ROOT    , dissect_h501_DescriptorRequest },
  {   5, &hf_h501_descriptorConfirmation, ASN1_EXTENSION_ROOT    , dissect_h501_DescriptorConfirmation },
  {   6, &hf_h501_descriptorRejection, ASN1_EXTENSION_ROOT    , dissect_h501_DescriptorRejection },
  {   7, &hf_h501_descriptorIDRequest, ASN1_EXTENSION_ROOT    , dissect_h501_DescriptorIDRequest },
  {   8, &hf_h501_descriptorIDConfirmation, ASN1_EXTENSION_ROOT    , dissect_h501_DescriptorIDConfirmation },
  {   9, &hf_h501_descriptorIDRejection, ASN1_EXTENSION_ROOT    , dissect_h501_DescriptorIDRejection },
  {  10, &hf_h501_descriptorUpdate, ASN1_EXTENSION_ROOT    , dissect_h501_DescriptorUpdate },
  {  11, &hf_h501_descriptorUpdateAck, ASN1_EXTENSION_ROOT    , dissect_h501_DescriptorUpdateAck },
  {  12, &hf_h501_accessRequest  , ASN1_EXTENSION_ROOT    , dissect_h501_AccessRequest },
  {  13, &hf_h501_accessConfirmation, ASN1_EXTENSION_ROOT    , dissect_h501_AccessConfirmation },
  {  14, &hf_h501_accessRejection, ASN1_EXTENSION_ROOT    , dissect_h501_AccessRejection },
  {  15, &hf_h501_requestInProgress, ASN1_EXTENSION_ROOT    , dissect_h501_RequestInProgress },
  {  16, &hf_h501_nonStandardRequest, ASN1_EXTENSION_ROOT    , dissect_h501_NonStandardRequest },
  {  17, &hf_h501_nonStandardConfirmation, ASN1_EXTENSION_ROOT    , dissect_h501_NonStandardConfirmation },
  {  18, &hf_h501_nonStandardRejection, ASN1_EXTENSION_ROOT    , dissect_h501_NonStandardRejection },
  {  19, &hf_h501_unknownMessageResponse, ASN1_EXTENSION_ROOT    , dissect_h501_UnknownMessageResponse },
  {  20, &hf_h501_usageRequest   , ASN1_EXTENSION_ROOT    , dissect_h501_UsageRequest },
  {  21, &hf_h501_usageConfirmation, ASN1_EXTENSION_ROOT    , dissect_h501_UsageConfirmation },
  {  22, &hf_h501_usageIndication, ASN1_EXTENSION_ROOT    , dissect_h501_UsageIndication },
  {  23, &hf_h501_usageIndicationConfirmation, ASN1_EXTENSION_ROOT    , dissect_h501_UsageIndicationConfirmation },
  {  24, &hf_h501_usageIndicationRejection, ASN1_EXTENSION_ROOT    , dissect_h501_UsageIndicationRejection },
  {  25, &hf_h501_usageRejection , ASN1_EXTENSION_ROOT    , dissect_h501_UsageRejection },
  {  26, &hf_h501_validationRequest, ASN1_EXTENSION_ROOT    , dissect_h501_ValidationRequest },
  {  27, &hf_h501_validationConfirmation, ASN1_EXTENSION_ROOT    , dissect_h501_ValidationConfirmation },
  {  28, &hf_h501_validationRejection, ASN1_EXTENSION_ROOT    , dissect_h501_ValidationRejection },
  {  29, &hf_h501_authenticationRequest, ASN1_NOT_EXTENSION_ROOT, dissect_h501_AuthenticationRequest },
  {  30, &hf_h501_authenticationConfirmation, ASN1_NOT_EXTENSION_ROOT, dissect_h501_AuthenticationConfirmation },
  {  31, &hf_h501_authenticationRejection, ASN1_NOT_EXTENSION_ROOT, dissect_h501_AuthenticationRejection },
  { 0, NULL, 0, NULL }
};

static int
dissect_h501_MessageBody(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 22 "../../asn1/h501/h501.cnf"
  gint32 msg_type = -1;
  const gchar *p = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h501_MessageBody, MessageBody_choice,
                                 &msg_type);

#line 25 "../../asn1/h501/h501.cnf"
  p = match_strval(msg_type, VALS(h501_MessageBody_vals));
  if (p )
    col_set_str(actx->pinfo->cinfo, COL_INFO, p);

  return offset;
}



static int
dissect_h501_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_h501_ProtocolVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_h501_INTEGER_1_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_TransportAddress_sequence_of[1] = {
  { &hf_h501_replyAddress_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_TransportAddress },
};

static int
dissect_h501_SEQUENCE_OF_TransportAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_TransportAddress, SEQUENCE_OF_TransportAddress_sequence_of);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_ClearToken_sequence_of[1] = {
  { &hf_h501_tokens_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_ClearToken },
};

static int
dissect_h501_SEQUENCE_OF_ClearToken(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_ClearToken, SEQUENCE_OF_ClearToken_sequence_of);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_NonStandardParameter_sequence_of[1] = {
  { &hf_h501_nonStandard_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_NonStandardParameter },
};

static int
dissect_h501_SEQUENCE_OF_NonStandardParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_NonStandardParameter, SEQUENCE_OF_NonStandardParameter_sequence_of);

  return offset;
}



static int
dissect_h501_ServiceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h225_GloballyUniqueID(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_GenericData_sequence_of[1] = {
  { &hf_h501_genericData_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_GenericData },
};

static int
dissect_h501_SEQUENCE_OF_GenericData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h501_SEQUENCE_OF_GenericData, SEQUENCE_OF_GenericData_sequence_of);

  return offset;
}


static const per_sequence_t MessageCommonInfo_sequence[] = {
  { &hf_h501_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_INTEGER_0_65535 },
  { &hf_h501_annexGversion  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_ProtocolVersion },
  { &hf_h501_hopCount       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_INTEGER_1_255 },
  { &hf_h501_replyAddress   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_TransportAddress },
  { &hf_h501_integrityCheckValue, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_ICV },
  { &hf_h501_tokens         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_ClearToken },
  { &hf_h501_cryptoTokens   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_CryptoH323Token },
  { &hf_h501_nonStandard    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_NonStandardParameter },
  { &hf_h501_serviceID      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_ServiceID },
  { &hf_h501_genericData    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h501_SEQUENCE_OF_GenericData },
  { &hf_h501_featureSet     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_FeatureSet },
  { &hf_h501_version        , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h501_ProtocolVersion },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_MessageCommonInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_MessageCommonInfo, MessageCommonInfo_sequence);

  return offset;
}


static const per_sequence_t Message_sequence[] = {
  { &hf_h501_body           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_MessageBody },
  { &hf_h501_common         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h501_MessageCommonInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_h501_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h501_Message, Message_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h501_Message(tvb, offset, &asn1_ctx, tree, hf_h501_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-h501-fn.c ---*/
#line 64 "../../asn1/h501/packet-h501-template.c"

static int
dissect_h501_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item  *ti = NULL;
  proto_tree  *h501_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  ti = proto_tree_add_item(tree, proto_h501, tvb, 0, -1, FALSE);
  h501_tree = proto_item_add_subtree(ti, ett_h501);

  return dissect_Message_PDU(tvb, pinfo, h501_tree);
}

static int
dissect_h501_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_tpkt_encap(tvb, pinfo, tree, FALSE, h501_pdu_handle);
  return tvb_length(tvb);
}

static int
dissect_h501_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_tpkt_encap(tvb, pinfo, tree, h501_desegment_tcp, h501_pdu_handle);
  return tvb_length(tvb);
}

/*--- proto_register_h501 ----------------------------------------------*/
void proto_register_h501(void) {
  module_t *h501_module;

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-h501-hfarr.c ---*/
#line 1 "../../asn1/h501/packet-h501-hfarr.c"
    { &hf_h501_Message_PDU,
      { "Message", "h501.Message",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_body,
      { "body", "h501.body",
        FT_UINT32, BASE_DEC, VALS(h501_MessageBody_vals), 0,
        "MessageBody", HFILL }},
    { &hf_h501_common,
      { "common", "h501.common",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageCommonInfo", HFILL }},
    { &hf_h501_serviceRequest,
      { "serviceRequest", "h501.serviceRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_serviceConfirmation,
      { "serviceConfirmation", "h501.serviceConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_serviceRejection,
      { "serviceRejection", "h501.serviceRejection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_serviceRelease,
      { "serviceRelease", "h501.serviceRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorRequest,
      { "descriptorRequest", "h501.descriptorRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorConfirmation,
      { "descriptorConfirmation", "h501.descriptorConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorRejection,
      { "descriptorRejection", "h501.descriptorRejection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorIDRequest,
      { "descriptorIDRequest", "h501.descriptorIDRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorIDConfirmation,
      { "descriptorIDConfirmation", "h501.descriptorIDConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorIDRejection,
      { "descriptorIDRejection", "h501.descriptorIDRejection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorUpdate,
      { "descriptorUpdate", "h501.descriptorUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorUpdateAck,
      { "descriptorUpdateAck", "h501.descriptorUpdateAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_accessRequest,
      { "accessRequest", "h501.accessRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_accessConfirmation,
      { "accessConfirmation", "h501.accessConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_accessRejection,
      { "accessRejection", "h501.accessRejection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_requestInProgress,
      { "requestInProgress", "h501.requestInProgress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_nonStandardRequest,
      { "nonStandardRequest", "h501.nonStandardRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_nonStandardConfirmation,
      { "nonStandardConfirmation", "h501.nonStandardConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_nonStandardRejection,
      { "nonStandardRejection", "h501.nonStandardRejection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_unknownMessageResponse,
      { "unknownMessageResponse", "h501.unknownMessageResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_usageRequest,
      { "usageRequest", "h501.usageRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_usageConfirmation,
      { "usageConfirmation", "h501.usageConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_usageIndication,
      { "usageIndication", "h501.usageIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_usageIndicationConfirmation,
      { "usageIndicationConfirmation", "h501.usageIndicationConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_usageIndicationRejection,
      { "usageIndicationRejection", "h501.usageIndicationRejection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_usageRejection,
      { "usageRejection", "h501.usageRejection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_validationRequest,
      { "validationRequest", "h501.validationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_validationConfirmation,
      { "validationConfirmation", "h501.validationConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_validationRejection,
      { "validationRejection", "h501.validationRejection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_authenticationRequest,
      { "authenticationRequest", "h501.authenticationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_authenticationConfirmation,
      { "authenticationConfirmation", "h501.authenticationConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_authenticationRejection,
      { "authenticationRejection", "h501.authenticationRejection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_sequenceNumber,
      { "sequenceNumber", "h501.sequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h501_annexGversion,
      { "annexGversion", "h501.annexGversion",
        FT_OID, BASE_NONE, NULL, 0,
        "ProtocolVersion", HFILL }},
    { &hf_h501_hopCount,
      { "hopCount", "h501.hopCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h501_replyAddress,
      { "replyAddress", "h501.replyAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TransportAddress", HFILL }},
    { &hf_h501_replyAddress_item,
      { "TransportAddress", "h501.TransportAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h501_integrityCheckValue,
      { "integrityCheckValue", "h501.integrityCheckValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "ICV", HFILL }},
    { &hf_h501_tokens,
      { "tokens", "h501.tokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ClearToken", HFILL }},
    { &hf_h501_tokens_item,
      { "ClearToken", "h501.ClearToken",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_cryptoTokens,
      { "cryptoTokens", "h501.cryptoTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CryptoH323Token", HFILL }},
    { &hf_h501_cryptoTokens_item,
      { "CryptoH323Token", "h501.CryptoH323Token",
        FT_UINT32, BASE_DEC, VALS(h225_CryptoH323Token_vals), 0,
        NULL, HFILL }},
    { &hf_h501_nonStandard,
      { "nonStandard", "h501.nonStandard",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_NonStandardParameter", HFILL }},
    { &hf_h501_nonStandard_item,
      { "NonStandardParameter", "h501.NonStandardParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_serviceID,
      { "serviceID", "h501.serviceID",
        FT_GUID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_genericData,
      { "genericData", "h501.genericData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GenericData", HFILL }},
    { &hf_h501_genericData_item,
      { "GenericData", "h501.GenericData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_featureSet,
      { "featureSet", "h501.featureSet",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_version,
      { "version", "h501.version",
        FT_OID, BASE_NONE, NULL, 0,
        "ProtocolVersion", HFILL }},
    { &hf_h501_elementIdentifier,
      { "elementIdentifier", "h501.elementIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_domainIdentifier,
      { "domainIdentifier", "h501.domainIdentifier",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AliasAddress", HFILL }},
    { &hf_h501_securityMode,
      { "securityMode", "h501.securityMode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SecurityMode", HFILL }},
    { &hf_h501_securityMode_item,
      { "SecurityMode", "h501.SecurityMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_timeToLive,
      { "timeToLive", "h501.timeToLive",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_h501_usageSpec,
      { "usageSpec", "h501.usageSpec",
        FT_NONE, BASE_NONE, NULL, 0,
        "UsageSpecification", HFILL }},
    { &hf_h501_authentication,
      { "authentication", "h501.authentication",
        FT_UINT32, BASE_DEC, VALS(h235_AuthenticationMechanism_vals), 0,
        "AuthenticationMechanism", HFILL }},
    { &hf_h501_integrity,
      { "integrity", "h501.integrity",
        FT_UINT32, BASE_DEC, VALS(h225_IntegrityMechanism_vals), 0,
        "IntegrityMechanism", HFILL }},
    { &hf_h501_algorithmOIDs,
      { "algorithmOIDs", "h501.algorithmOIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_algorithmOIDs_item,
      { "algorithmOIDs item", "h501.algorithmOIDs_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h501_alternates,
      { "alternates", "h501.alternates",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlternatePEInfo", HFILL }},
    { &hf_h501_securityMode_01,
      { "securityMode", "h501.securityMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_reason,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_ServiceRejectionReason_vals), 0,
        "ServiceRejectionReason", HFILL }},
    { &hf_h501_serviceUnavailable,
      { "serviceUnavailable", "h501.serviceUnavailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_serviceRedirected,
      { "serviceRedirected", "h501.serviceRedirected",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_security,
      { "security", "h501.security",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_continue,
      { "continue", "h501.continue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_undefined,
      { "undefined", "h501.undefined",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_unknownServiceID,
      { "unknownServiceID", "h501.unknownServiceID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_cannotSupportUsageSpec,
      { "cannotSupportUsageSpec", "h501.cannotSupportUsageSpec",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_neededFeature,
      { "neededFeature", "h501.neededFeature",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_genericDataReason,
      { "genericDataReason", "h501.genericDataReason",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_usageUnavailable,
      { "usageUnavailable", "h501.usageUnavailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_unknownUsageSendTo,
      { "unknownUsageSendTo", "h501.unknownUsageSendTo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_reason_01,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_ServiceReleaseReason_vals), 0,
        "ServiceReleaseReason", HFILL }},
    { &hf_h501_outOfService,
      { "outOfService", "h501.outOfService",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_maintenance,
      { "maintenance", "h501.maintenance",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_terminated,
      { "terminated", "h501.terminated",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_expired,
      { "expired", "h501.expired",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorID,
      { "descriptorID", "h501.descriptorID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DescriptorID", HFILL }},
    { &hf_h501_descriptorID_item,
      { "DescriptorID", "h501.DescriptorID",
        FT_GUID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptor,
      { "descriptor", "h501.descriptor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Descriptor", HFILL }},
    { &hf_h501_descriptor_item,
      { "Descriptor", "h501.Descriptor",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_reason_02,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_DescriptorRejectionReason_vals), 0,
        "DescriptorRejectionReason", HFILL }},
    { &hf_h501_descriptorID_01,
      { "descriptorID", "h501.descriptorID",
        FT_GUID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_packetSizeExceeded,
      { "packetSizeExceeded", "h501.packetSizeExceeded",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_illegalID,
      { "illegalID", "h501.illegalID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_hopCountExceeded,
      { "hopCountExceeded", "h501.hopCountExceeded",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_noServiceRelationship,
      { "noServiceRelationship", "h501.noServiceRelationship",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorInfo,
      { "descriptorInfo", "h501.descriptorInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DescriptorInfo", HFILL }},
    { &hf_h501_descriptorInfo_item,
      { "DescriptorInfo", "h501.DescriptorInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_reason_03,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_DescriptorIDRejectionReason_vals), 0,
        "DescriptorIDRejectionReason", HFILL }},
    { &hf_h501_noDescriptors,
      { "noDescriptors", "h501.noDescriptors",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_sender,
      { "sender", "h501.sender",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AliasAddress", HFILL }},
    { &hf_h501_updateInfo,
      { "updateInfo", "h501.updateInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_UpdateInformation", HFILL }},
    { &hf_h501_updateInfo_item,
      { "UpdateInformation", "h501.UpdateInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorInfo_01,
      { "descriptorInfo", "h501.descriptorInfo",
        FT_UINT32, BASE_DEC, VALS(h501_T_descriptorInfo_vals), 0,
        NULL, HFILL }},
    { &hf_h501_descriptor_01,
      { "descriptor", "h501.descriptor",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_updateType,
      { "updateType", "h501.updateType",
        FT_UINT32, BASE_DEC, VALS(h501_T_updateType_vals), 0,
        NULL, HFILL }},
    { &hf_h501_added,
      { "added", "h501.added",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_deleted,
      { "deleted", "h501.deleted",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_changed,
      { "changed", "h501.changed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_destinationInfo,
      { "destinationInfo", "h501.destinationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_h501_sourceInfo,
      { "sourceInfo", "h501.sourceInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_h501_callInfo,
      { "callInfo", "h501.callInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallInformation", HFILL }},
    { &hf_h501_desiredProtocols,
      { "desiredProtocols", "h501.desiredProtocols",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SupportedProtocols", HFILL }},
    { &hf_h501_desiredProtocols_item,
      { "SupportedProtocols", "h501.SupportedProtocols",
        FT_UINT32, BASE_DEC, VALS(h225_SupportedProtocols_vals), 0,
        NULL, HFILL }},
    { &hf_h501_templates,
      { "templates", "h501.templates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AddressTemplate", HFILL }},
    { &hf_h501_templates_item,
      { "AddressTemplate", "h501.AddressTemplate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_partialResponse,
      { "partialResponse", "h501.partialResponse",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h501_supportedProtocols,
      { "supportedProtocols", "h501.supportedProtocols",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SupportedProtocols", HFILL }},
    { &hf_h501_supportedProtocols_item,
      { "SupportedProtocols", "h501.SupportedProtocols",
        FT_UINT32, BASE_DEC, VALS(h225_SupportedProtocols_vals), 0,
        NULL, HFILL }},
    { &hf_h501_serviceControl,
      { "serviceControl", "h501.serviceControl",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ServiceControlSession", HFILL }},
    { &hf_h501_serviceControl_item,
      { "ServiceControlSession", "h501.ServiceControlSession",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_reason_04,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_AccessRejectionReason_vals), 0,
        "AccessRejectionReason", HFILL }},
    { &hf_h501_noMatch,
      { "noMatch", "h501.noMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_needCallInformation,
      { "needCallInformation", "h501.needCallInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_destinationUnavailable,
      { "destinationUnavailable", "h501.destinationUnavailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_aliasesInconsistent,
      { "aliasesInconsistent", "h501.aliasesInconsistent",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_resourceUnavailable,
      { "resourceUnavailable", "h501.resourceUnavailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_incompleteAddress,
      { "incompleteAddress", "h501.incompleteAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_reason_05,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_UsageRejectReason_vals), 0,
        "UsageRejectReason", HFILL }},
    { &hf_h501_accessTokens,
      { "accessTokens", "h501.accessTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AccessToken", HFILL }},
    { &hf_h501_accessTokens_item,
      { "AccessToken", "h501.AccessToken",
        FT_UINT32, BASE_DEC, VALS(h501_AccessToken_vals), 0,
        NULL, HFILL }},
    { &hf_h501_senderRole,
      { "senderRole", "h501.senderRole",
        FT_UINT32, BASE_DEC, VALS(h501_Role_vals), 0,
        "Role", HFILL }},
    { &hf_h501_usageCallStatus,
      { "usageCallStatus", "h501.usageCallStatus",
        FT_UINT32, BASE_DEC, VALS(h501_UsageCallStatus_vals), 0,
        NULL, HFILL }},
    { &hf_h501_srcInfo,
      { "srcInfo", "h501.srcInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_h501_destAddress,
      { "destAddress", "h501.destAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_h501_startTime,
      { "startTime", "h501.startTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_h501_endTime,
      { "endTime", "h501.endTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_h501_terminationCause,
      { "terminationCause", "h501.terminationCause",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_usageFields,
      { "usageFields", "h501.usageFields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_UsageField", HFILL }},
    { &hf_h501_usageFields_item,
      { "UsageField", "h501.UsageField",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_id,
      { "id", "h501.id",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h501_value,
      { "value", "h501.value",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h501_invalidCall,
      { "invalidCall", "h501.invalidCall",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_unavailable,
      { "unavailable", "h501.unavailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_reason_06,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_UsageIndicationRejectionReason_vals), 0,
        "UsageIndicationRejectionReason", HFILL }},
    { &hf_h501_unknownCall,
      { "unknownCall", "h501.unknownCall",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_incomplete,
      { "incomplete", "h501.incomplete",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_accessToken,
      { "accessToken", "h501.accessToken",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AccessToken", HFILL }},
    { &hf_h501_accessToken_item,
      { "AccessToken", "h501.AccessToken",
        FT_UINT32, BASE_DEC, VALS(h501_AccessToken_vals), 0,
        NULL, HFILL }},
    { &hf_h501_reason_07,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_ValidationRejectionReason_vals), 0,
        "ValidationRejectionReason", HFILL }},
    { &hf_h501_tokenNotValid,
      { "tokenNotValid", "h501.tokenNotValid",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_missingSourceInfo,
      { "missingSourceInfo", "h501.missingSourceInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_missingDestInfo,
      { "missingDestInfo", "h501.missingDestInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_delay,
      { "delay", "h501.delay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h501_reason_08,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_NonStandardRejectionReason_vals), 0,
        "NonStandardRejectionReason", HFILL }},
    { &hf_h501_notSupported,
      { "notSupported", "h501.notSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_unknownMessage,
      { "unknownMessage", "h501.unknownMessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h501_reason_09,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_UnknownMessageReason_vals), 0,
        "UnknownMessageReason", HFILL }},
    { &hf_h501_notUnderstood,
      { "notUnderstood", "h501.notUnderstood",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_applicationMessage,
      { "applicationMessage", "h501.applicationMessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_reason_10,
      { "reason", "h501.reason",
        FT_UINT32, BASE_DEC, VALS(h501_AuthenticationRejectionReason_vals), 0,
        "AuthenticationRejectionReason", HFILL }},
    { &hf_h501_securityWrongSyncTime,
      { "securityWrongSyncTime", "h501.securityWrongSyncTime",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_securityReplay,
      { "securityReplay", "h501.securityReplay",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_securityWrongGeneralID,
      { "securityWrongGeneralID", "h501.securityWrongGeneralID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_securityWrongSendersID,
      { "securityWrongSendersID", "h501.securityWrongSendersID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_securityIntegrityFailed,
      { "securityIntegrityFailed", "h501.securityIntegrityFailed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_securityWrongOID,
      { "securityWrongOID", "h501.securityWrongOID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_pattern,
      { "pattern", "h501.pattern",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Pattern", HFILL }},
    { &hf_h501_pattern_item,
      { "Pattern", "h501.Pattern",
        FT_UINT32, BASE_DEC, VALS(h501_Pattern_vals), 0,
        NULL, HFILL }},
    { &hf_h501_routeInfo,
      { "routeInfo", "h501.routeInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_RouteInformation", HFILL }},
    { &hf_h501_routeInfo_item,
      { "RouteInformation", "h501.RouteInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_specific,
      { "specific", "h501.specific",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AliasAddress", HFILL }},
    { &hf_h501_wildcard,
      { "wildcard", "h501.wildcard",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AliasAddress", HFILL }},
    { &hf_h501_range,
      { "range", "h501.range",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_startOfRange,
      { "startOfRange", "h501.startOfRange",
        FT_UINT32, BASE_DEC, VALS(h225_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_h501_endOfRange,
      { "endOfRange", "h501.endOfRange",
        FT_UINT32, BASE_DEC, VALS(h225_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_h501_messageType,
      { "messageType", "h501.messageType",
        FT_UINT32, BASE_DEC, VALS(h501_T_messageType_vals), 0,
        NULL, HFILL }},
    { &hf_h501_sendAccessRequest,
      { "sendAccessRequest", "h501.sendAccessRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_sendSetup,
      { "sendSetup", "h501.sendSetup",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_nonExistent,
      { "nonExistent", "h501.nonExistent",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_callSpecific,
      { "callSpecific", "h501.callSpecific",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h501_priceInfo,
      { "priceInfo", "h501.priceInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PriceInfoSpec", HFILL }},
    { &hf_h501_priceInfo_item,
      { "PriceInfoSpec", "h501.PriceInfoSpec",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_contacts,
      { "contacts", "h501.contacts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ContactInformation", HFILL }},
    { &hf_h501_contacts_item,
      { "ContactInformation", "h501.ContactInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_type,
      { "type", "h501.type",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointType", HFILL }},
    { &hf_h501_circuitID,
      { "circuitID", "h501.circuitID",
        FT_NONE, BASE_NONE, NULL, 0,
        "CircuitInfo", HFILL }},
    { &hf_h501_supportedCircuits,
      { "supportedCircuits", "h501.supportedCircuits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CircuitIdentifier", HFILL }},
    { &hf_h501_supportedCircuits_item,
      { "CircuitIdentifier", "h501.CircuitIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_transportAddress,
      { "transportAddress", "h501.transportAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AliasAddress", HFILL }},
    { &hf_h501_priority,
      { "priority", "h501.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_h501_transportQoS,
      { "transportQoS", "h501.transportQoS",
        FT_UINT32, BASE_DEC, VALS(h225_TransportQOS_vals), 0,
        NULL, HFILL }},
    { &hf_h501_security_01,
      { "security", "h501.security",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SecurityMode", HFILL }},
    { &hf_h501_security_item,
      { "SecurityMode", "h501.SecurityMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_multipleCalls,
      { "multipleCalls", "h501.multipleCalls",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h501_currency,
      { "currency", "h501.currency",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_3", HFILL }},
    { &hf_h501_currencyScale,
      { "currencyScale", "h501.currencyScale",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_127", HFILL }},
    { &hf_h501_validFrom,
      { "validFrom", "h501.validFrom",
        FT_STRING, BASE_NONE, NULL, 0,
        "GlobalTimeStamp", HFILL }},
    { &hf_h501_validUntil,
      { "validUntil", "h501.validUntil",
        FT_STRING, BASE_NONE, NULL, 0,
        "GlobalTimeStamp", HFILL }},
    { &hf_h501_hoursFrom,
      { "hoursFrom", "h501.hoursFrom",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_6", HFILL }},
    { &hf_h501_hoursUntil,
      { "hoursUntil", "h501.hoursUntil",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_6", HFILL }},
    { &hf_h501_priceElement,
      { "priceElement", "h501.priceElement",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PriceElement", HFILL }},
    { &hf_h501_priceElement_item,
      { "PriceElement", "h501.PriceElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_priceFormula,
      { "priceFormula", "h501.priceFormula",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_2048", HFILL }},
    { &hf_h501_amount,
      { "amount", "h501.amount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h501_quantum,
      { "quantum", "h501.quantum",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h501_units,
      { "units", "h501.units",
        FT_UINT32, BASE_DEC, VALS(h501_T_units_vals), 0,
        NULL, HFILL }},
    { &hf_h501_seconds,
      { "seconds", "h501.seconds",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_packets,
      { "packets", "h501.packets",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_bytes,
      { "bytes", "h501.bytes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_initial,
      { "initial", "h501.initial",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_minimum,
      { "minimum", "h501.minimum",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_maximum,
      { "maximum", "h501.maximum",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_descriptorInfo_02,
      { "descriptorInfo", "h501.descriptorInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_gatekeeperID,
      { "gatekeeperID", "h501.gatekeeperID",
        FT_STRING, BASE_NONE, NULL, 0,
        "GatekeeperIdentifier", HFILL }},
    { &hf_h501_lastChanged,
      { "lastChanged", "h501.lastChanged",
        FT_STRING, BASE_NONE, NULL, 0,
        "GlobalTimeStamp", HFILL }},
    { &hf_h501_alternatePE,
      { "alternatePE", "h501.alternatePE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AlternatePE", HFILL }},
    { &hf_h501_alternatePE_item,
      { "AlternatePE", "h501.AlternatePE",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_alternateIsPermanent,
      { "alternateIsPermanent", "h501.alternateIsPermanent",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h501_contactAddress,
      { "contactAddress", "h501.contactAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AliasAddress", HFILL }},
    { &hf_h501_priority_01,
      { "priority", "h501.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_h501_token,
      { "token", "h501.token",
        FT_NONE, BASE_NONE, NULL, 0,
        "ClearToken", HFILL }},
    { &hf_h501_cryptoToken,
      { "cryptoToken", "h501.cryptoToken",
        FT_UINT32, BASE_DEC, VALS(h225_CryptoH323Token_vals), 0,
        "CryptoH323Token", HFILL }},
    { &hf_h501_genericData_01,
      { "genericData", "h501.genericData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_callIdentifier,
      { "callIdentifier", "h501.callIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_conferenceID,
      { "conferenceID", "h501.conferenceID",
        FT_GUID, BASE_NONE, NULL, 0,
        "ConferenceIdentifier", HFILL }},
    { &hf_h501_preConnect,
      { "preConnect", "h501.preConnect",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_callInProgress,
      { "callInProgress", "h501.callInProgress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_callEnded,
      { "callEnded", "h501.callEnded",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_registrationLost,
      { "registrationLost", "h501.registrationLost",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_userIdentifier,
      { "userIdentifier", "h501.userIdentifier",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AliasAddress", HFILL }},
    { &hf_h501_userAuthenticator,
      { "userAuthenticator", "h501.userAuthenticator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CryptoH323Token", HFILL }},
    { &hf_h501_userAuthenticator_item,
      { "CryptoH323Token", "h501.CryptoH323Token",
        FT_UINT32, BASE_DEC, VALS(h225_CryptoH323Token_vals), 0,
        NULL, HFILL }},
    { &hf_h501_sendTo,
      { "sendTo", "h501.sendTo",
        FT_STRING, BASE_NONE, NULL, 0,
        "ElementIdentifier", HFILL }},
    { &hf_h501_when,
      { "when", "h501.when",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_never,
      { "never", "h501.never",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_start,
      { "start", "h501.start",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_end,
      { "end", "h501.end",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_period,
      { "period", "h501.period",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h501_failures,
      { "failures", "h501.failures",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_required,
      { "required", "h501.required",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_required_item,
      { "required item", "h501.required_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h501_preferred,
      { "preferred", "h501.preferred",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_preferred_item,
      { "preferred item", "h501.preferred_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h501_sendToPEAddress,
      { "sendToPEAddress", "h501.sendToPEAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AliasAddress", HFILL }},
    { &hf_h501_logicalAddresses,
      { "logicalAddresses", "h501.logicalAddresses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AliasAddress", HFILL }},
    { &hf_h501_logicalAddresses_item,
      { "AliasAddress", "h501.AliasAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h501_endpointType,
      { "endpointType", "h501.endpointType",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_userInfo,
      { "userInfo", "h501.userInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserInformation", HFILL }},
    { &hf_h501_timeZone,
      { "timeZone", "h501.timeZone",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_originator,
      { "originator", "h501.originator",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_destination,
      { "destination", "h501.destination",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h501_nonStandardData,
      { "nonStandardData", "h501.nonStandardData",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h501_releaseCompleteReason,
      { "releaseCompleteReason", "h501.releaseCompleteReason",
        FT_UINT32, BASE_DEC, VALS(h225_ReleaseCompleteReason_vals), 0,
        NULL, HFILL }},
    { &hf_h501_causeIE,
      { "causeIE", "h501.causeIE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},

/*--- End of included file: packet-h501-hfarr.c ---*/
#line 100 "../../asn1/h501/packet-h501-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h501,

/*--- Included file: packet-h501-ettarr.c ---*/
#line 1 "../../asn1/h501/packet-h501-ettarr.c"
    &ett_h501_Message,
    &ett_h501_MessageBody,
    &ett_h501_MessageCommonInfo,
    &ett_h501_SEQUENCE_OF_TransportAddress,
    &ett_h501_SEQUENCE_OF_ClearToken,
    &ett_h501_SEQUENCE_OF_CryptoH323Token,
    &ett_h501_SEQUENCE_OF_NonStandardParameter,
    &ett_h501_SEQUENCE_OF_GenericData,
    &ett_h501_ServiceRequest,
    &ett_h501_SEQUENCE_OF_SecurityMode,
    &ett_h501_SecurityMode,
    &ett_h501_T_algorithmOIDs,
    &ett_h501_ServiceConfirmation,
    &ett_h501_ServiceRejection,
    &ett_h501_ServiceRejectionReason,
    &ett_h501_ServiceRelease,
    &ett_h501_ServiceReleaseReason,
    &ett_h501_DescriptorRequest,
    &ett_h501_SEQUENCE_OF_DescriptorID,
    &ett_h501_DescriptorConfirmation,
    &ett_h501_SEQUENCE_OF_Descriptor,
    &ett_h501_DescriptorRejection,
    &ett_h501_DescriptorRejectionReason,
    &ett_h501_DescriptorIDRequest,
    &ett_h501_DescriptorIDConfirmation,
    &ett_h501_SEQUENCE_OF_DescriptorInfo,
    &ett_h501_DescriptorIDRejection,
    &ett_h501_DescriptorIDRejectionReason,
    &ett_h501_DescriptorUpdate,
    &ett_h501_SEQUENCE_OF_UpdateInformation,
    &ett_h501_UpdateInformation,
    &ett_h501_T_descriptorInfo,
    &ett_h501_T_updateType,
    &ett_h501_DescriptorUpdateAck,
    &ett_h501_AccessRequest,
    &ett_h501_SEQUENCE_OF_SupportedProtocols,
    &ett_h501_AccessConfirmation,
    &ett_h501_SEQUENCE_OF_AddressTemplate,
    &ett_h501_SEQUENCE_OF_ServiceControlSession,
    &ett_h501_AccessRejection,
    &ett_h501_AccessRejectionReason,
    &ett_h501_UsageRequest,
    &ett_h501_UsageConfirmation,
    &ett_h501_UsageRejection,
    &ett_h501_UsageIndication,
    &ett_h501_SEQUENCE_OF_AccessToken,
    &ett_h501_SEQUENCE_OF_UsageField,
    &ett_h501_UsageField,
    &ett_h501_UsageRejectReason,
    &ett_h501_UsageIndicationConfirmation,
    &ett_h501_UsageIndicationRejection,
    &ett_h501_UsageIndicationRejectionReason,
    &ett_h501_ValidationRequest,
    &ett_h501_ValidationConfirmation,
    &ett_h501_ValidationRejection,
    &ett_h501_ValidationRejectionReason,
    &ett_h501_RequestInProgress,
    &ett_h501_NonStandardRequest,
    &ett_h501_NonStandardConfirmation,
    &ett_h501_NonStandardRejection,
    &ett_h501_NonStandardRejectionReason,
    &ett_h501_UnknownMessageResponse,
    &ett_h501_UnknownMessageReason,
    &ett_h501_AuthenticationRequest,
    &ett_h501_AuthenticationConfirmation,
    &ett_h501_AuthenticationRejection,
    &ett_h501_AuthenticationRejectionReason,
    &ett_h501_AddressTemplate,
    &ett_h501_SEQUENCE_OF_Pattern,
    &ett_h501_SEQUENCE_OF_RouteInformation,
    &ett_h501_Pattern,
    &ett_h501_T_range,
    &ett_h501_RouteInformation,
    &ett_h501_T_messageType,
    &ett_h501_SEQUENCE_OF_PriceInfoSpec,
    &ett_h501_SEQUENCE_OF_ContactInformation,
    &ett_h501_SEQUENCE_OF_CircuitIdentifier,
    &ett_h501_ContactInformation,
    &ett_h501_PriceInfoSpec,
    &ett_h501_SEQUENCE_OF_PriceElement,
    &ett_h501_PriceElement,
    &ett_h501_T_units,
    &ett_h501_Descriptor,
    &ett_h501_DescriptorInfo,
    &ett_h501_AlternatePEInfo,
    &ett_h501_SEQUENCE_OF_AlternatePE,
    &ett_h501_AlternatePE,
    &ett_h501_AccessToken,
    &ett_h501_CallInformation,
    &ett_h501_UsageCallStatus,
    &ett_h501_UserInformation,
    &ett_h501_UsageSpecification,
    &ett_h501_T_when,
    &ett_h501_T_required,
    &ett_h501_T_preferred,
    &ett_h501_PartyInformation,
    &ett_h501_SEQUENCE_OF_AliasAddress,
    &ett_h501_Role,
    &ett_h501_TerminationCause,

/*--- End of included file: packet-h501-ettarr.c ---*/
#line 106 "../../asn1/h501/packet-h501-template.c"
  };

  /* Register protocol */
  proto_h501 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h501, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector(PFNAME, dissect_h501_pdu, proto_h501);

  h501_module = prefs_register_protocol(proto_h501, proto_reg_handoff_h501);
  prefs_register_uint_preference(h501_module, "udp.port",
                                 "UDP port",
                                 "Port to be decoded as h501",
                                 10, &h501_udp_port);
  prefs_register_uint_preference(h501_module, "tcp.port",
                                 "TCP port",
                                 "Port to be decoded as h501",
                                 10, &h501_tcp_port);
  prefs_register_bool_preference(h501_module, "desegment",
                                 "Desegment H.501 over TCP",
                                 "Desegment H.501 messages that span more TCP segments",
                                 &h501_desegment_tcp);

}

/*--- proto_reg_handoff_h501 -------------------------------------------*/
void proto_reg_handoff_h501(void) 
{
  static gboolean h501_prefs_initialized = FALSE;
  static dissector_handle_t h501_udp_handle;
  static dissector_handle_t h501_tcp_handle;
  static guint saved_h501_udp_port;
  static guint saved_h501_tcp_port;

  if (!h501_prefs_initialized) {
    h501_pdu_handle = find_dissector(PFNAME);
    h501_udp_handle = new_create_dissector_handle(dissect_h501_udp, proto_h501);
    h501_tcp_handle = new_create_dissector_handle(dissect_h501_tcp, proto_h501);
    h501_prefs_initialized = TRUE;
  } else {
    dissector_delete_uint("udp.port", saved_h501_udp_port, h501_udp_handle);
    dissector_delete_uint("tcp.port", saved_h501_tcp_port, h501_tcp_handle);
  }

  /* Set our port number for future use */
  saved_h501_udp_port = h501_udp_port;
  dissector_add_uint("udp.port", saved_h501_udp_port, h501_udp_handle);
  saved_h501_tcp_port = h501_tcp_port;
  dissector_add_uint("tcp.port", saved_h501_tcp_port, h501_tcp_handle);

}

